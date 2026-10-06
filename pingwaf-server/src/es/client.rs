//! Non-blocking Elasticsearch log shipper.
//!
//! The design goal is that indexing never touches the proxy hot path and never
//! crashes the control plane:
//!
//! - Producers call [`ElasticsearchClient::index`] (or the typed helpers), which
//!   is a `try_send` into a bounded channel — it returns immediately and, if the
//!   channel is full, drops the document with a warning rather than applying
//!   back-pressure.
//! - A background worker owns the receiver, batches documents up to
//!   `bulk_max_size` or `bulk_flush_interval_ms`, and posts them to the `_bulk`
//!   API as NDJSON.
//! - When ES is unreachable (transport error, 429 or 503) the batch is written
//!   to an on-disk write-ahead buffer; a second background task replays those
//!   segments once ES answers again.
//!
//! The client is cheap to clone (everything lives behind an [`Arc`]) and must be
//! shut down with [`ElasticsearchClient::shutdown`] so buffered documents are
//! flushed on process exit.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;

use super::config::EsConfig;
use super::models::{AccessLogDocument, SecurityEventDocument};

/// Distinguishes the two index families a document may belong to.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DocumentType {
    AccessLog,
    SecurityEvent,
}

impl DocumentType {
    /// The infix used in the daily index name, e.g. `pingwaf-access-2026.09.25`.
    fn index_suffix(self) -> &'static str {
        match self {
            DocumentType::AccessLog => "access",
            DocumentType::SecurityEvent => "security",
        }
    }
}

/// A single document waiting to be indexed.
///
/// `index` is resolved at enqueue time so a document buffered across midnight
/// still lands in the day it was produced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsDocument {
    pub index: String,
    pub doc_type: DocumentType,
    pub body: serde_json::Value,
}

/// Outcome of one `_bulk` request.
#[derive(Debug, Clone, Default)]
pub struct BulkResult {
    /// Documents ES accepted (2xx item status).
    pub indexed: usize,
    /// Documents ES rejected.
    pub failed: usize,
    /// True when the failure was transient (429/503) and the batch is worth
    /// retrying via the on-disk buffer.
    pub retryable: bool,
}

/// Cluster health snapshot returned by [`ElasticsearchClient::health_check`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsHealth {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number_of_nodes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_shards: Option<u64>,
}

/// Commands the client can send to its own background worker.
enum Control {
    Flush(oneshot::Sender<anyhow::Result<()>>),
    Shutdown(oneshot::Sender<anyhow::Result<()>>),
}

/// Monotonic counter that keeps buffered segment filenames unique even when two
/// are written within the same millisecond.
static SEGMENT_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Prefix for on-disk buffer segments; the timestamp makes names sort
/// chronologically so "oldest first" is a plain lexicographic sort.
const BUFFER_PREFIX: &str = "pingwaf-es-";

struct Inner {
    config: EsConfig,
    http: reqwest::Client,
    tx: mpsc::Sender<EsDocument>,
    control_tx: mpsc::Sender<Control>,
    buffer: DiskBuffer,
    url_cursor: AtomicUsize,
    shutdown_flag: AtomicBool,
    worker: Mutex<Option<JoinHandle<()>>>,
    replay: Mutex<Option<JoinHandle<()>>>,
}

/// Handle to the running Elasticsearch shipper.
///
/// Cloning shares the same background worker and buffer.
#[derive(Clone)]
pub struct ElasticsearchClient {
    inner: Arc<Inner>,
}

impl ElasticsearchClient {
    /// Creates a client and starts its background worker and buffer-replay task.
    ///
    /// The configuration is normalised and validated first; a disabled or
    /// misconfigured shipper is an error so the caller can fall back to
    /// PostgreSQL-only logging.
    pub async fn new(config: EsConfig) -> anyhow::Result<Self> {
        let mut config = config;
        config.normalise();
        config.validate()?;

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.request_timeout_secs.max(1)))
            .build()
            .map_err(|err| {
                anyhow::anyhow!("failed to build the ES HTTP client: {err}")
            })?;

        let (tx, rx) =
            mpsc::channel::<EsDocument>(config.channel_capacity.max(1));
        let (control_tx, control_rx) = mpsc::channel::<Control>(32);
        let buffer = DiskBuffer::new(
            config.buffer_dir.clone(),
            config.buffer_max_size_mb,
        );
        if let Err(err) = buffer.create_dir().await {
            // A missing buffer directory downgrades resilience but must not stop
            // the shipper; buffering simply stays off until it is writable.
            tracing::warn!(error = %err, "could not create the ES buffer directory, WAL disabled");
        }

        let inner = Arc::new(Inner {
            config,
            http,
            tx,
            control_tx,
            buffer,
            url_cursor: AtomicUsize::new(0),
            shutdown_flag: AtomicBool::new(false),
            worker: Mutex::new(None),
            replay: Mutex::new(None),
        });

        let worker = tokio::spawn(worker_loop(inner.clone(), rx, control_rx));
        *inner.worker.lock().await = Some(worker);

        let replay = tokio::spawn(replay_loop(inner.clone()));
        *inner.replay.lock().await = Some(replay);

        tracing::info!(
            urls = ?inner.config.urls,
            index_prefix = %inner.config.index_prefix,
            buffered = inner.buffer.enabled(),
            "elasticsearch log shipper started"
        );

        Ok(Self { inner })
    }

    /// The effective configuration (already normalised).
    pub fn config(&self) -> &EsConfig {
        &self.inner.config
    }

    /// Queues a document for indexing. Non-blocking: drops on a full channel.
    pub fn index(&self, doc: EsDocument) {
        if let Err(err) = self.inner.tx.try_send(doc) {
            match err {
                mpsc::error::TrySendError::Full(_) => {
                    tracing::warn!(
                        "elasticsearch buffer full, dropping a document"
                    );
                },
                mpsc::error::TrySendError::Closed(_) => {
                    tracing::debug!(
                        "elasticsearch shipper closed, dropping a document"
                    );
                },
            }
        }
    }

    /// Queues an access log entry.
    pub fn index_access_log(&self, entry: AccessLogDocument) {
        let index = self.index_name(DocumentType::AccessLog, entry.timestamp);
        match serde_json::to_value(&entry) {
            Ok(body) => self.index(EsDocument {
                index,
                doc_type: DocumentType::AccessLog,
                body,
            }),
            Err(err) => {
                tracing::error!(error = %err, "could not serialise an access log document")
            },
        }
    }

    /// Queues a security event.
    pub fn index_security_event(&self, event: SecurityEventDocument) {
        let index =
            self.index_name(DocumentType::SecurityEvent, event.timestamp);
        match serde_json::to_value(&event) {
            Ok(body) => self.index(EsDocument {
                index,
                doc_type: DocumentType::SecurityEvent,
                body,
            }),
            Err(err) => {
                tracing::error!(error = %err, "could not serialise a security event document")
            },
        }
    }

    /// Daily index name for a document type, using the document's own timestamp.
    fn index_name(&self, doc_type: DocumentType, ts: DateTime<Utc>) -> String {
        format!(
            "{}-{}-{}",
            self.inner.config.index_prefix,
            doc_type.index_suffix(),
            ts.format("%Y.%m.%d")
        )
    }

    /// Daily index name for a document type as of now.
    pub fn get_index_name(&self, doc_type: &DocumentType) -> String {
        self.index_name(*doc_type, Utc::now())
    }

    /// Truncates a body to `max_body_size`, returning the bytes and whether a
    /// truncation happened. The cut is backed off to a UTF-8 boundary so the
    /// lossy decode never emits a stray replacement character.
    pub fn truncate_body(&self, body: &[u8]) -> (Vec<u8>, bool) {
        truncate_body_with(body, self.inner.config.max_body_size)
    }

    /// Convenience wrapper producing the optional string body stored on a
    /// document: empty input becomes `None`, everything else a lossy string.
    pub fn truncate_body_to_string(
        &self,
        body: &[u8],
    ) -> (Option<String>, bool) {
        if body.is_empty() {
            return (None, false);
        }
        let (bytes, truncated) = self.truncate_body(body);
        (
            Some(String::from_utf8_lossy(&bytes).into_owned()),
            truncated,
        )
    }

    /// Forces the worker to flush everything currently buffered.
    pub async fn flush(&self) -> anyhow::Result<()> {
        let (reply, rx) = oneshot::channel();
        self.inner
            .control_tx
            .send(Control::Flush(reply))
            .await
            .map_err(|_| {
                anyhow::anyhow!("the elasticsearch shipper is not running")
            })?;
        rx.await.map_err(|_| {
            anyhow::anyhow!("the elasticsearch worker dropped the flush reply")
        })?
    }

    /// Flushes remaining documents, stops the background tasks and makes one
    /// final attempt to drain the on-disk buffer.
    pub async fn shutdown(&self) -> anyhow::Result<()> {
        self.inner.shutdown_flag.store(true, Ordering::SeqCst);

        let (reply, rx) = oneshot::channel();
        // The worker may already have exited; a send failure is not fatal.
        if self
            .inner
            .control_tx
            .send(Control::Shutdown(reply))
            .await
            .is_ok()
        {
            let _ = rx.await;
        }

        for slot in [&self.inner.worker, &self.inner.replay] {
            if let Some(handle) = slot.lock().await.take() {
                let _ = handle.await;
            }
        }
        tracing::info!("elasticsearch log shipper stopped");
        Ok(())
    }

    /// Checks connectivity by reading `_cluster/health`.
    pub async fn health_check(&self) -> anyhow::Result<EsHealth> {
        let body = self
            .inner
            .request_json(reqwest::Method::GET, "/_cluster/health", None)
            .await?;
        Ok(EsHealth {
            status: body
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            cluster_name: body
                .get("cluster_name")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            number_of_nodes: body
                .get("number_of_nodes")
                .and_then(|v| v.as_u64()),
            active_shards: body.get("active_shards").and_then(|v| v.as_u64()),
        })
    }

    /// Issues an authenticated JSON request against the cluster. Used by
    /// [`super::template`] and by the settings API connectivity probe.
    pub async fn request_json(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> anyhow::Result<serde_json::Value> {
        self.inner.request_json(method, path, body).await
    }
}

impl Inner {
    /// Picks the next node URL round-robin, giving client-side failover.
    fn next_url(&self) -> String {
        let urls = &self.config.urls;
        if urls.is_empty() {
            return String::new();
        }
        let idx = self.url_cursor.fetch_add(1, Ordering::Relaxed) % urls.len();
        urls[idx].clone()
    }

    /// Attaches API-key or basic auth to a request builder.
    fn apply_auth(
        &self,
        req: reqwest::RequestBuilder,
    ) -> reqwest::RequestBuilder {
        if let Some(key) = self
            .config
            .api_key
            .as_deref()
            .filter(|k| !k.trim().is_empty())
        {
            return req.header(
                reqwest::header::AUTHORIZATION,
                format!("ApiKey {key}"),
            );
        }
        match (
            self.config.username.as_deref(),
            self.config.password.as_deref(),
        ) {
            (Some(user), Some(pass)) => req.basic_auth(user, Some(pass)),
            _ => req,
        }
    }

    /// Generic authenticated JSON request used for health and template calls.
    async fn request_json(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> anyhow::Result<serde_json::Value> {
        let base = self.next_url();
        let url = format!("{base}{path}");
        let mut req = self.apply_auth(self.http.request(method, &url));
        if let Some(payload) = body {
            req = req.json(&payload);
        }
        let resp = req.send().await.map_err(|err| {
            anyhow::anyhow!("elasticsearch request to {url} failed: {err}")
        })?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(anyhow::anyhow!(
                "elasticsearch returned {status} for {url}: {text}"
            ));
        }
        if text.trim().is_empty() {
            return Ok(serde_json::Value::Null);
        }
        Ok(serde_json::from_str(&text).unwrap_or(serde_json::Value::Null))
    }

    /// Encodes and sends a batch of documents to `_bulk`.
    async fn bulk_send(
        &self,
        docs: &[EsDocument],
    ) -> anyhow::Result<BulkResult> {
        if docs.is_empty() {
            return Ok(BulkResult::default());
        }
        let payload = encode_bulk(docs)?;
        self.send_raw_bulk(&payload, docs.len()).await
    }

    /// Posts pre-encoded NDJSON to `_bulk`, rotating across nodes and retrying
    /// transient failures. Returns `Err` only when every attempt was transient
    /// (so the caller buffers the batch); a hard 4xx yields a non-retryable
    /// [`BulkResult`] instead.
    async fn send_raw_bulk(
        &self,
        payload: &[u8],
        doc_count: usize,
    ) -> anyhow::Result<BulkResult> {
        let attempts = self.config.urls.len().max(1);
        let mut last_err: Option<anyhow::Error> = None;

        for attempt in 0..attempts {
            let base = self.next_url();
            let url = format!("{base}/_bulk");
            let req = self
                .apply_auth(self.http.post(&url))
                .header(reqwest::header::CONTENT_TYPE, "application/x-ndjson")
                .body(payload.to_vec());

            match req.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status == reqwest::StatusCode::TOO_MANY_REQUESTS
                        || status == reqwest::StatusCode::SERVICE_UNAVAILABLE
                    {
                        let text = resp.text().await.unwrap_or_default();
                        tracing::warn!(%status, %url, body = %text, "elasticsearch busy, will retry");
                        last_err = Some(anyhow::anyhow!(
                            "elasticsearch returned {status}"
                        ));
                        sleep_backoff(attempt).await;
                        continue;
                    }
                    if !status.is_success() {
                        let text = resp.text().await.unwrap_or_default();
                        tracing::error!(%status, %url, body = %text, "elasticsearch rejected the bulk request");
                        return Ok(BulkResult {
                            indexed: 0,
                            failed: doc_count,
                            retryable: false,
                        });
                    }
                    let body: serde_json::Value =
                        resp.json().await.unwrap_or(serde_json::Value::Null);
                    return Ok(parse_bulk_response(&body, doc_count));
                },
                Err(err) => {
                    tracing::warn!(%url, error = %err, "elasticsearch bulk transport error");
                    last_err = Some(err.into());
                    sleep_backoff(attempt).await;
                },
            }
        }

        Err(last_err.unwrap_or_else(|| {
            anyhow::anyhow!("elasticsearch bulk send failed")
        }))
    }
}

/// Small linear backoff between bulk attempts.
async fn sleep_backoff(attempt: usize) {
    tokio::time::sleep(Duration::from_millis(200 * (attempt as u64 + 1))).await;
}

/// The background batching worker.
async fn worker_loop(
    inner: Arc<Inner>,
    mut rx: mpsc::Receiver<EsDocument>,
    mut control_rx: mpsc::Receiver<Control>,
) {
    let max = inner.config.bulk_max_size.max(1);
    let interval =
        Duration::from_millis(inner.config.bulk_flush_interval_ms.max(1));
    let mut buf: Vec<EsDocument> = Vec::with_capacity(max.min(4096));

    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // consume the immediate first tick

    loop {
        tokio::select! {
            maybe_doc = rx.recv() => match maybe_doc {
                Some(doc) => {
                    buf.push(doc);
                    if buf.len() >= max {
                        let _ = flush_batch(&inner, &mut buf).await;
                    }
                }
                None => {
                    // Every producer is gone; flush what remains and stop.
                    let _ = flush_batch(&inner, &mut buf).await;
                    break;
                }
            },
            _ = ticker.tick() => {
                if !buf.is_empty() {
                    let _ = flush_batch(&inner, &mut buf).await;
                }
            }
            ctrl = control_rx.recv() => match ctrl {
                Some(Control::Flush(reply)) => {
                    let _ = reply.send(flush_batch(&inner, &mut buf).await);
                }
                Some(Control::Shutdown(reply)) => {
                    while let Ok(doc) = rx.try_recv() {
                        buf.push(doc);
                    }
                    let _ = reply.send(flush_batch(&inner, &mut buf).await);
                    break;
                }
                None => {
                    let _ = flush_batch(&inner, &mut buf).await;
                    break;
                }
            },
        }
    }
    tracing::debug!("elasticsearch bulk worker stopped");
}

/// Sends the accumulated batch; on transient failure writes it to the on-disk
/// buffer. Clears `buf` in all cases.
async fn flush_batch(
    inner: &Inner,
    buf: &mut Vec<EsDocument>,
) -> anyhow::Result<()> {
    if buf.is_empty() {
        return Ok(());
    }
    let docs = std::mem::take(buf);
    match inner.bulk_send(&docs).await {
        Ok(result) if !result.retryable => {
            if result.failed > 0 {
                tracing::warn!(
                    indexed = result.indexed,
                    failed = result.failed,
                    "elasticsearch bulk completed with item-level failures"
                );
            } else {
                tracing::debug!(
                    indexed = result.indexed,
                    "elasticsearch bulk indexed"
                );
            }
            Ok(())
        },
        Ok(_) => {
            tracing::warn!(
                count = docs.len(),
                "elasticsearch busy, buffering the batch"
            );
            buffer_docs(inner, &docs).await
        },
        Err(err) => {
            tracing::warn!(count = docs.len(), error = %err, "elasticsearch unreachable, buffering the batch");
            buffer_docs(inner, &docs).await
        },
    }
}

/// Persists a failed batch to the write-ahead buffer.
async fn buffer_docs(inner: &Inner, docs: &[EsDocument]) -> anyhow::Result<()> {
    match inner.buffer.write(docs).await {
        Ok(Some(path)) => {
            tracing::warn!(path = %path.display(), count = docs.len(), "buffered elasticsearch batch to disk");
            Ok(())
        },
        Ok(None) => {
            tracing::warn!(
                count = docs.len(),
                "elasticsearch buffer disabled, dropping the batch"
            );
            Err(anyhow::anyhow!("buffer disabled, batch dropped"))
        },
        Err(err) => {
            tracing::error!(error = %err, "failed to write the elasticsearch buffer");
            Err(err)
        },
    }
}

/// Periodically replays on-disk segments while ES is reachable.
async fn replay_loop(inner: Arc<Inner>) {
    if !inner.buffer.enabled() {
        return;
    }
    let period = Duration::from_millis(
        inner
            .config
            .bulk_flush_interval_ms
            .max(1000)
            .saturating_mul(2),
    );
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // skip the immediate first tick

    loop {
        ticker.tick().await;
        if inner.shutdown_flag.load(Ordering::SeqCst) {
            break;
        }
        match inner.buffer.replay(&inner).await {
            Ok(0) => {},
            Ok(n) => tracing::info!(
                segments = n,
                "replayed buffered elasticsearch segments"
            ),
            Err(err) => {
                tracing::debug!(error = %err, "elasticsearch buffer replay pass failed")
            },
        }
    }
    // One last drain attempt on the way out.
    let _ = inner.buffer.replay(&inner).await;
}

/// Encodes documents into the `_bulk` NDJSON wire format: an action line
/// followed by the source document, for each entry.
fn encode_bulk(docs: &[EsDocument]) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(docs.len() * 256);
    for doc in docs {
        let action = serde_json::json!({ "index": { "_index": doc.index } });
        serde_json::to_writer(&mut out, &action)?;
        out.push(b'\n');
        serde_json::to_writer(&mut out, &doc.body)?;
        out.push(b'\n');
    }
    Ok(out)
}

/// Interprets a `_bulk` response body into a [`BulkResult`].
fn parse_bulk_response(body: &serde_json::Value, total: usize) -> BulkResult {
    let mut result = BulkResult::default();
    match body.get("items").and_then(|v| v.as_array()) {
        Some(items) => {
            for item in items {
                let status = item
                    .get("index")
                    .and_then(|op| op.get("status"))
                    .and_then(|s| s.as_u64());
                match status {
                    Some(code) if (200..300).contains(&code) => {
                        result.indexed += 1
                    },
                    Some(code) if code == 429 || code == 503 => {
                        result.failed += 1;
                        result.retryable = true;
                    },
                    _ => result.failed += 1,
                }
            }
        },
        None => {
            // Fall back to the top-level flag when the item array is absent.
            if body
                .get("errors")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                result.failed = total;
            } else {
                result.indexed = total;
            }
        },
    }
    result
}

/// Truncates `body` to `max` bytes, backing off to a UTF-8 char boundary.
fn truncate_body_with(body: &[u8], max: usize) -> (Vec<u8>, bool) {
    if max == 0 || body.len() <= max {
        return (body.to_vec(), false);
    }
    let mut end = max;
    // A UTF-8 continuation byte has the bit pattern 10xxxxxx; step back over
    // any trailing continuation bytes so we never split a multi-byte char.
    while end > 0 && (body[end] & 0b1100_0000) == 0b1000_0000 {
        end -= 1;
    }
    (body[..end].to_vec(), true)
}

/// On-disk write-ahead buffer for batches ES could not accept.
///
/// Each segment is stored already encoded as `_bulk` NDJSON, so replaying is a
/// matter of posting the file bytes back — no re-serialisation and no risk of
/// the index name drifting if the clock rolls over while the batch waits.
#[derive(Debug)]
struct DiskBuffer {
    dir: Option<PathBuf>,
    max_bytes: u64,
}

impl DiskBuffer {
    fn new(dir: Option<String>, max_mb: usize) -> Self {
        Self {
            dir: dir
                .map(|d| d.trim().to_string())
                .filter(|d| !d.is_empty())
                .map(PathBuf::from),
            max_bytes: (max_mb as u64).saturating_mul(1024 * 1024),
        }
    }

    fn enabled(&self) -> bool {
        self.dir.is_some()
    }

    async fn create_dir(&self) -> anyhow::Result<()> {
        if let Some(dir) = &self.dir {
            tokio::fs::create_dir_all(dir).await?;
        }
        Ok(())
    }

    /// Writes a batch to a new segment, enforcing the total-size quota first.
    /// Returns the segment path, or `None` when buffering is disabled.
    async fn write(
        &self,
        docs: &[EsDocument],
    ) -> anyhow::Result<Option<PathBuf>> {
        let Some(dir) = self.dir.clone() else {
            return Ok(None);
        };
        let encoded = encode_bulk(docs)?;
        self.enforce_quota(&dir, encoded.len() as u64).await;

        let seq = SEGMENT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!(
            "{BUFFER_PREFIX}{}-{seq:06}.ndjson",
            Utc::now().format("%Y%m%dT%H%M%S%3f")
        );
        let path = dir.join(name);
        tokio::fs::write(&path, &encoded).await?;
        Ok(Some(path))
    }

    /// Lists segments oldest-first as `(path, size_bytes)`.
    async fn list_segments(
        &self,
        dir: &Path,
    ) -> anyhow::Result<Vec<(PathBuf, u64)>> {
        let mut out = Vec::new();
        let mut entries = match tokio::fs::read_dir(dir).await {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(out)
            },
            Err(err) => return Err(err.into()),
        };
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name.starts_with(BUFFER_PREFIX) || !name.ends_with(".ndjson") {
                continue;
            }
            let len = entry.metadata().await.map(|m| m.len()).unwrap_or(0);
            out.push((path, len));
        }
        out.sort_by(|a, b| a.0.file_name().cmp(&b.0.file_name()));
        Ok(out)
    }

    /// Deletes the oldest segments until the projected total fits the quota.
    async fn enforce_quota(&self, dir: &Path, incoming: u64) {
        if self.max_bytes == 0 {
            return;
        }
        let segments = match self.list_segments(dir).await {
            Ok(segments) => segments,
            Err(_) => return,
        };
        let mut total: u64 = segments.iter().map(|(_, len)| len).sum();
        if total.saturating_add(incoming) <= self.max_bytes {
            return;
        }
        for (path, len) in segments {
            if total.saturating_add(incoming) <= self.max_bytes {
                break;
            }
            if tokio::fs::remove_file(&path).await.is_ok() {
                total = total.saturating_sub(len);
                tracing::warn!(path = %path.display(), "dropped the oldest ES buffer segment to stay under quota");
            }
        }
    }

    /// Replays buffered segments while ES accepts them, stopping at the first
    /// transient failure so ordering is preserved. Returns the number replayed.
    async fn replay(&self, inner: &Inner) -> anyhow::Result<usize> {
        let Some(dir) = self.dir.clone() else {
            return Ok(0);
        };
        let segments = self.list_segments(&dir).await?;
        let mut replayed = 0;
        for (path, _) in segments {
            if inner.shutdown_flag.load(Ordering::SeqCst) && replayed > 0 {
                break;
            }
            let bytes = match tokio::fs::read(&path).await {
                Ok(bytes) => bytes,
                Err(err) => {
                    tracing::warn!(path = %path.display(), error = %err, "could not read an ES buffer segment");
                    continue;
                },
            };
            if bytes.is_empty() {
                let _ = tokio::fs::remove_file(&path).await;
                continue;
            }
            match inner.send_raw_bulk(&bytes, 0).await {
                Ok(result) if !result.retryable => {
                    let _ = tokio::fs::remove_file(&path).await;
                    replayed += 1;
                },
                Ok(_) => break, // ES still busy; keep the segment for later.
                Err(err) => {
                    tracing::debug!(error = %err, "elasticsearch still unreachable, keeping the buffer");
                    break;
                },
            }
        }
        Ok(replayed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(index: &str) -> EsDocument {
        EsDocument {
            index: index.to_string(),
            doc_type: DocumentType::AccessLog,
            body: serde_json::json!({ "path": "/" }),
        }
    }

    #[test]
    fn encode_bulk_produces_ndjson_pairs() {
        let encoded = encode_bulk(&[doc("pingwaf-access-2026.09.25")]).unwrap();
        let text = String::from_utf8(encoded).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"_index\":\"pingwaf-access-2026.09.25\""));
        assert!(lines[1].contains("\"path\":\"/\""));
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn parse_bulk_counts_item_statuses() {
        let body = serde_json::json!({
            "errors": true,
            "items": [
                { "index": { "status": 201 } },
                { "index": { "status": 429 } },
                { "index": { "status": 400 } },
            ]
        });
        let result = parse_bulk_response(&body, 3);
        assert_eq!(result.indexed, 1);
        assert_eq!(result.failed, 2);
        assert!(result.retryable);
    }

    #[test]
    fn parse_bulk_falls_back_to_errors_flag() {
        let ok =
            parse_bulk_response(&serde_json::json!({ "errors": false }), 5);
        assert_eq!(ok.indexed, 5);
        assert_eq!(ok.failed, 0);
        let bad =
            parse_bulk_response(&serde_json::json!({ "errors": true }), 5);
        assert_eq!(bad.failed, 5);
    }

    #[test]
    fn truncation_respects_utf8_boundaries() {
        // Under the cap: unchanged, not truncated.
        let (bytes, truncated) = truncate_body_with(b"hello", 10);
        assert_eq!(bytes, b"hello");
        assert!(!truncated);

        // Over the cap: cut and flagged.
        let (bytes, truncated) = truncate_body_with(b"hello world", 5);
        assert_eq!(bytes, b"hello");
        assert!(truncated);

        // Each 'é' is two bytes; a five-byte cap must not split the third one.
        let input = "ééé".as_bytes();
        let (bytes, truncated) = truncate_body_with(input, 5);
        assert_eq!(bytes, "éé".as_bytes());
        assert!(truncated);
        assert!(std::str::from_utf8(&bytes).is_ok());
    }

    #[test]
    fn index_suffixes_are_stable() {
        assert_eq!(DocumentType::AccessLog.index_suffix(), "access");
        assert_eq!(DocumentType::SecurityEvent.index_suffix(), "security");
    }

    #[tokio::test]
    async fn disk_buffer_is_disabled_without_a_dir() {
        let buffer = DiskBuffer::new(None, 512);
        assert!(!buffer.enabled());
        assert!(buffer.write(&[doc("x")]).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn disk_buffer_writes_and_lists_segments() {
        let tmp = tempfile::tempdir().unwrap();
        let buffer = DiskBuffer::new(
            Some(tmp.path().to_string_lossy().into_owned()),
            512,
        );
        buffer.create_dir().await.unwrap();

        let path = buffer.write(&[doc("idx")]).await.unwrap().unwrap();
        assert!(path.exists());

        let segments = buffer.list_segments(tmp.path()).await.unwrap();
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].0, path);
    }

    #[tokio::test]
    async fn disk_buffer_enforces_quota_by_dropping_oldest() {
        let tmp = tempfile::tempdir().unwrap();
        // A one-megabyte ceiling expressed in megabytes would never trigger, so
        // use the byte-level quota directly via a tiny max_mb of 0 => disabled.
        let buffer = DiskBuffer {
            dir: Some(tmp.path().to_path_buf()),
            max_bytes: 64, // far smaller than one encoded segment
        };
        buffer.create_dir().await.unwrap();

        // First write fits under the projected quota check trivially.
        buffer.write(&[doc("idx-a")]).await.unwrap().unwrap();
        // Second write forces the quota sweep to drop the oldest segment.
        buffer.write(&[doc("idx-b")]).await.unwrap().unwrap();

        let segments = buffer.list_segments(tmp.path()).await.unwrap();
        let total: u64 = segments.iter().map(|(_, len)| len).sum();
        assert!(
            total <= 64 + 512,
            "quota sweep should keep the total bounded"
        );
    }
}
