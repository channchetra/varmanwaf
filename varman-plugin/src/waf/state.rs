use super::*;

// ─────────────────────────────────────────────────────────────
// Pending access log store
// ─────────────────────────────────────────────────────────────

/// Request facts captured before inspection and held until the response
/// (and, when captured, its body) allows the access log to be emitted.
pub(crate) struct PendingAccess {
    pub(crate) site_id: String,
    pub(crate) client_ip: String,
    pub(crate) method: String,
    pub(crate) scheme: String,
    pub(crate) protocol: String,
    pub(crate) host: String,
    pub(crate) path: String,
    pub(crate) query: String,
    pub(crate) user_agent: String,
    pub(crate) referer: String,
    pub(crate) tls_version: String,
    pub(crate) country_code: String,
    pub(crate) request_headers: Vec<(String, String)>,
    pub(crate) request_body: Option<Vec<u8>>,
    pub(crate) request_body_size: u64,
    pub(crate) request_body_truncated: bool,
    /// Body bytes the log keeps per direction, resolved from the agent
    /// config when the request arrived. 0 disables body capture.
    pub(crate) body_limit: usize,
    /// Response facts, present once `handle_response` held the entry back
    /// for body capture.
    pub(crate) response: Option<ResponseFacts>,
    pub(crate) start: Instant,
}

/// Response facts gathered before the access entry is emitted.
pub(crate) struct ResponseFacts {
    pub(crate) status_code: u32,
    pub(crate) upstream_addr: String,
    pub(crate) upstream_latency_ms: u64,
    pub(crate) headers: Vec<(String, String)>,
    /// Prefix kept for the log; `None` when body capture was skipped.
    pub(crate) body: Option<Vec<u8>>,
    /// Body bytes seen while streaming, or the announced content length when
    /// capture was skipped.
    pub(crate) body_size: u64,
    /// The stream never finished; whatever arrived is all there was to log.
    pub(crate) abandoned: bool,
}

impl ResponseFacts {
    /// Facts for a response the plugin generated itself (block page,
    /// challenge, rate limit); no upstream and no captured body.
    pub(crate) fn generated(status_code: u32) -> Self {
        Self {
            status_code,
            upstream_addr: String::new(),
            upstream_latency_ms: 0,
            headers: Vec::new(),
            body: None,
            body_size: 0,
            abandoned: false,
        }
    }

    /// Facts for a response the plugin answers with, taken from the response
    /// itself: a blocked request is then as replayable in the log as a
    /// proxied one. The body is kept up to `limit` bytes.
    pub(crate) fn from_generated(
        response: &HttpResponse,
        limit: usize,
    ) -> Self {
        let mut facts = Self::generated(response.status.as_u16() as u32);
        facts.headers =
            cap_headers(response.headers.iter().flatten().filter_map(
                |(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| (name.as_str().to_string(), value))
                },
            ));
        facts.absorb(&response.body, limit);
        facts
    }

    /// Absorbs one streamed chunk, keeping at most `limit` bytes.
    pub(crate) fn absorb(&mut self, chunk: &[u8], limit: usize) {
        self.body_size += chunk.len() as u64;
        if limit == 0 {
            return;
        }
        let buf = self
            .body
            .get_or_insert_with(|| Vec::with_capacity(chunk.len().min(limit)));
        if buf.len() < limit {
            let room = limit - buf.len();
            buf.extend_from_slice(&chunk[..chunk.len().min(room)]);
        }
    }

    /// Whether the kept prefix is shorter than the body it came from.
    pub(crate) fn truncated(&self) -> bool {
        self.abandoned
            || self
                .body
                .as_ref()
                .is_some_and(|body| (body.len() as u64) < self.body_size)
    }
}

/// Hard ceiling for the configured per-entry body capture, so a bad value
/// cannot turn the log store into a bandwidth sink.
pub(crate) const MAX_LOG_BODY_LIMIT: usize = 64 * 1024;

/// Upper bounds for the header snapshot kept per access log entry.
pub(crate) const MAX_LOG_HEADERS: usize = 64;
pub(crate) const MAX_LOG_HEADERS_BYTES: usize = 8 * 1024;

/// Caps the header snapshot kept for logging so a pathological exchange
/// cannot bloat the log store: at most [`MAX_LOG_HEADERS`] entries totalling
/// at most [`MAX_LOG_HEADERS_BYTES`] bytes. Values are stored verbatim —
/// including cookies and credentials — because incident response needs to
/// replay traffic (see the security note in `docs/api.md`).
pub(crate) fn cap_headers<'a>(
    headers: impl Iterator<Item = (String, &'a str)>,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut total = 0usize;
    for (name, value) in headers.take(MAX_LOG_HEADERS) {
        total += name.len() + value.len();
        if total > MAX_LOG_HEADERS_BYTES {
            break;
        }
        out.push((name, value.to_string()));
    }
    out
}

/// Accumulates the request-body prefix kept for logging: at most `limit`
/// bytes plus a flag telling whether the kept prefix is shorter than the
/// body the data plane read. The full byte count is tracked regardless of
/// the limit, so the log can report the real size even when truncated.
pub(crate) struct LogBodyPrefix {
    pub(crate) limit: usize,
    pub(crate) body: Option<Vec<u8>>,
    pub(crate) size: u64,
    pub(crate) truncated: bool,
}

impl LogBodyPrefix {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            body: None,
            size: 0,
            truncated: false,
        }
    }

    pub(crate) fn absorb(&mut self, chunk: &[u8]) {
        self.size += chunk.len() as u64;
        if self.limit == 0 {
            return;
        }
        let buf = self.body.get_or_insert_with(|| {
            Vec::with_capacity(chunk.len().min(self.limit))
        });
        // Overshoot is allowed here so a body of exactly `limit` bytes stays
        // untruncated; `finish` trims and flags afterwards.
        if buf.len() <= self.limit {
            buf.extend_from_slice(chunk);
        }
    }

    /// Whether the prefix has everything it will ever keep; the read loop
    /// stops once this holds.
    pub(crate) fn limit_hit(&self) -> bool {
        self.limit > 0
            && self.body.as_ref().is_some_and(|buf| buf.len() > self.limit)
    }

    /// Marks the capture as interrupted (the read loop stopped before the body
    /// signalled completion), so the kept prefix may be shorter than the real
    /// body even though it fits within the limit.
    pub(crate) fn interrupted(&mut self) {
        self.truncated = true;
    }

    pub(crate) fn finish(mut self) -> (Option<Vec<u8>>, u64, bool) {
        if let Some(buf) = self.body.as_mut()
            && buf.len() > self.limit
        {
            buf.truncate(self.limit);
            self.truncated = true;
        }
        (self.body, self.size, self.truncated)
    }
}

/// How long a request may sit between `handle_request` and the end of its
/// response body before the pending entry counts as abandoned.
pub const PENDING_ACCESS_SWEEP_TTL: Duration = Duration::from_secs(45);
/// Orphaned entries (e.g. upstream connect failures that bypass
/// `handle_response`) are evicted once they outlive this window.
pub(crate) const PENDING_ACCESS_TTL: Duration = Duration::from_secs(60);

/// Default edge refusal window after a WAF block verdict: repeat requests
/// from the same client are dropped before the engine runs again.
pub(crate) const WAF_AUTO_BLOCK_SECS: u64 = 600;

/// Only pay for garbage collection above this many outstanding entries.
pub(crate) const PENDING_ACCESS_GC_THRESHOLD: usize = 65536;

pub(crate) static PENDING_ACCESS: LazyLock<DashMap<String, PendingAccess>> =
    LazyLock::new(DashMap::new);

/// Facts about the request that opened a stream, snapshotted when a 101
/// upgrade is seen: the pending access entry is consumed by the access log
/// when the 101 completes, so aborts later in the tunnel still need the
/// request's identity for their security event.
#[derive(Default, Clone)]
pub(crate) struct StreamFacts {
    pub(crate) site_id: String,
    pub(crate) client_ip: String,
    pub(crate) method: String,
    pub(crate) scheme: String,
    pub(crate) protocol: String,
    pub(crate) host: String,
    pub(crate) path: String,
    pub(crate) query: String,
    pub(crate) user_agent: String,
    pub(crate) country_code: String,
}

/// Per-connection stream inspection state for tail and upgraded traffic,
/// keyed by request id. Created lazily by the stream hooks and removed when
/// the stream ends; a bounded purge drops stale entries if a connection dies
/// without an end-of-stream signal.
#[derive(Default)]
pub(crate) struct StreamState {
    /// Sliding tail window for forwarded body chunks.
    pub(crate) tail: TailWindow,
    /// Set once a finding fired; further chunks are ignored while the
    /// connection is being aborted.
    pub(crate) aborted: bool,
    /// Set when the response was a 101 WebSocket upgrade.
    pub(crate) websocket: bool,
    /// Enforcement policy, resolved once per connection from the site
    /// context (at the 101, or on the first tail scan).
    pub(crate) policy: Option<Arc<StreamPolicy>>,
    /// Rules already recorded on this stream. A monitor site sees the same
    /// low-confidence rule on every matching message; one event per rule per
    /// connection is enough, and the old behaviour (one event per message)
    /// flooded the event store.
    pub(crate) reported: HashSet<String>,
    /// Frame decoders for an upgraded connection.
    pub(crate) inspector: StreamInspector,
    /// Request identity for abort events, snapshotted at the 101.
    pub(crate) facts: StreamFacts,
    /// Creation time, for the lazy purge.
    pub(crate) created: Option<Instant>,
}

pub(crate) static STREAMS: LazyLock<DashMap<String, StreamState>> =
    LazyLock::new(DashMap::new);

/// Purge stale stream entries once the map grows past this size.
pub(crate) const STREAM_GC_THRESHOLD: usize = 10_000;
/// Entries older than this are stale (a stream cannot live longer).
pub(crate) const STREAM_TTL: Duration = Duration::from_secs(3600);

/// Run `f` with the stream state for `request_id`, creating it on first use.
/// A bounded purge drops stale entries once the map grows large, so a
/// connection that dies without an end-of-stream signal cannot leak.
pub(crate) fn with_stream<R>(
    request_id: &str,
    f: impl FnOnce(&mut StreamState) -> R,
) -> R {
    if STREAMS.len() > STREAM_GC_THRESHOLD {
        let now = Instant::now();
        STREAMS.retain(|_, state| {
            state
                .created
                .is_none_or(|created| now.duration_since(created) < STREAM_TTL)
        });
    }
    let mut state = STREAMS.entry(request_id.to_string()).or_default();
    if state.created.is_none() {
        state.created = Some(Instant::now());
    }
    f(&mut state)
}

/// Everything the stream inspector needs from the site configuration,
/// resolved once per connection.
#[derive(Debug, Clone, Default)]
pub(crate) struct StreamPolicy {
    /// Findings may close the stream.
    pub(crate) enforce: bool,
    /// Monitor-only categories, applied to every scanned message with the
    /// same helper the request path uses.
    pub(crate) monitored: Vec<String>,
    /// Rule ids excluded for the request path whose exclusion names the
    /// body target.
    pub(crate) excluded_rules: HashSet<String>,
    /// Request path the policy was resolved for (exclusion matching and
    /// debug logging).
    pub(crate) path: String,
}

/// Rules excluded for `path` whose exclusion names the body target.
///
/// A stream payload is body content; an exclusion that only names the path
/// or the query arguments says nothing about what flows through the tunnel.
pub(crate) fn stream_excluded_rules(
    path: &str,
    exclusions: &[CachePathTargetExclusion],
) -> HashSet<String> {
    exclusions
        .iter()
        .filter(|exclusion| {
            exclusion
                .targets
                .iter()
                .any(|target| target.eq_ignore_ascii_case("body"))
        })
        .filter(|exclusion| {
            exclusion.path_prefix.is_empty()
                || path.starts_with(&exclusion.path_prefix)
        })
        .map(|exclusion| exclusion.rule_id.clone())
        .collect()
}

pub(crate) fn register_pending_access(
    request_id: &str,
    pending: PendingAccess,
) {
    if PENDING_ACCESS.len() > PENDING_ACCESS_GC_THRESHOLD {
        PENDING_ACCESS.retain(|_, v| v.start.elapsed() < PENDING_ACCESS_TTL);
    }
    PENDING_ACCESS.insert(request_id.to_string(), pending);
}

/// Ships, or drops, entries whose exchange never completed: a client that
/// vanished mid-body (or an upstream that died before responding) would
/// otherwise leave its entry behind forever. Entries that already hold
/// response facts are logged with what arrived; the rest are dropped. Runs
/// off the data plane's periodic task.
/// Per-request body staging: the remainder of an over-window request body
/// (one the early read could not consume inside the replay window) is
/// withheld from the upstream up to the inspection cap, scanned, and only
/// then forwarded. Upstream's staging model, adapted to our early-read
/// pipeline: past the cap the rest flows untouched (the tail scan covers
/// it) instead of buffering unbounded bytes.
pub(crate) struct DeferredBody {
    /// Bytes withheld from the upstream so far.
    pub(crate) buffer: BytesMut,
    /// Past the cap: later chunks flow without staging.
    pub(crate) passthrough: bool,
    pub(crate) created_at: Instant,
}

/// Entries live only while their request is streaming; answered requests
/// leave one behind until the periodic sweep drops it.
pub(crate) static DEFERRED_BODY: LazyLock<DashMap<String, DeferredBody>> =
    LazyLock::new(DashMap::new);

/// The per-chunk decision [`stage_chunk`] returns.
#[derive(Debug)]
pub(crate) enum StageAction {
    /// Absorbed into the buffer: the caller replaces the outgoing chunk
    /// with an empty one so the upstream stays byte-silent.
    Withhold,
    /// The cap was hit with this chunk: scan the staged bytes once, then
    /// hand them over and let the rest through.
    Flush(Bytes),
    /// Staging is inactive: leave the chunk as it is.
    PassThrough,
}

/// Decides what happens to one streaming body chunk. Pure so the staging
/// state machine is unit-testable without a proxy session.
pub(crate) fn stage_chunk(
    cap: usize,
    passthrough: &mut bool,
    buffer: &mut BytesMut,
    chunk: Option<&[u8]>,
) -> StageAction {
    if *passthrough {
        return StageAction::PassThrough;
    }
    if let Some(chunk) = chunk {
        buffer.extend_from_slice(chunk);
    }
    if buffer.len() > cap {
        *passthrough = true;
        StageAction::Flush(std::mem::take(buffer).freeze())
    } else {
        StageAction::Withhold
    }
}

pub fn sweep_stale_access(ttl: Duration) -> usize {
    let expired: Vec<String> = PENDING_ACCESS
        .iter()
        .filter(|entry| entry.value().start.elapsed() >= ttl)
        .map(|entry| entry.key().clone())
        .collect();
    let agent = VarmanAgent::instance();
    let mut swept = 0;
    for request_id in expired {
        let Some((_, mut pending)) = PENDING_ACCESS.remove(&request_id) else {
            continue;
        };
        swept += 1;
        let Some(agent) = agent.as_ref() else {
            continue;
        };
        if let Some(mut facts) = pending.response.take() {
            facts.abandoned = true;
            emit_access(agent, &request_id, pending, facts);
        }
    }
    // Body-staging entries abandoned mid-exchange - a client that vanished
    // while sending, or a request answered before its body filter ran -
    // hold staged bytes; drop them on the same window.
    let before = DEFERRED_BODY.len();
    DEFERRED_BODY.retain(|_, entry| entry.created_at.elapsed() < ttl);
    swept + (before - DEFERRED_BODY.len())
}

/// Emit an access log entry, either when the response is complete or
/// immediately for plugin-generated responses (which never reach
/// `handle_response`).
pub(crate) fn emit_access(
    agent: &VarmanAgent,
    request_id: &str,
    pending: PendingAccess,
    response: ResponseFacts,
) {
    let total_latency_ms = pending.start.elapsed().as_millis() as u64;
    let response_body_truncated = response.truncated();
    agent.log_access(AccessLogEntry {
        site_id: pending.site_id,
        request_id: request_id.to_string(),
        client_ip: pending.client_ip,
        method: pending.method,
        scheme: pending.scheme,
        host: pending.host,
        path: pending.path,
        query_string: pending.query,
        protocol: pending.protocol,
        status_code: response.status_code,
        response_size: response.body_size,
        upstream_addr: response.upstream_addr,
        upstream_latency_ms: response.upstream_latency_ms,
        total_latency_ms,
        cache_status: String::new(),
        user_agent: pending.user_agent,
        referer: pending.referer,
        tls_version: pending.tls_version,
        country_code: pending.country_code,
        request_headers: pending.request_headers,
        request_body: pending.request_body,
        request_body_size: pending.request_body_size,
        request_body_truncated: pending.request_body_truncated,
        response_headers: response.headers,
        response_body: response.body,
        response_body_size: response.body_size,
        response_body_truncated,
    });
}

/// Emits the access entry for a response the plugin answers with itself. The
/// entry records what the client is about to receive — status, headers and
/// truncated body — so a blocked or challenged request is as replayable in
/// the log as a proxied one.
pub(crate) fn emit_generated_access(
    agent: Option<&Arc<VarmanAgent>>,
    request_id: &str,
    response: &HttpResponse,
) {
    let Some(agent) = agent else {
        return;
    };
    let Some((_, pending)) = PENDING_ACCESS.remove(request_id) else {
        return;
    };
    let limit = pending.body_limit;
    emit_access(
        agent,
        request_id,
        pending,
        ResponseFacts::from_generated(response, limit),
    );
}

/// Content types whose bodies are text-like and thus worth storing.
pub(crate) fn is_textual_content_type(value: &str) -> bool {
    let mime = value
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    mime.starts_with("text/")
        || matches!(
            mime.as_str(),
            "application/json"
                | "application/xml"
                | "application/javascript"
                | "application/x-www-form-urlencoded"
        )
        || mime.ends_with("+json")
        || mime.ends_with("+xml")
}

/// Whether the response body should be captured for the access log. Capture
/// is skipped when the outcome is knowable from the headers alone (HEAD,
/// bodyless statuses) or the bytes would not be replayable text (compressed
/// or binary payloads).
pub(crate) fn should_capture_response_body(
    method: &str,
    status: u16,
    response: &pingora::http::ResponseHeader,
) -> bool {
    if method == "HEAD" || status < 200 || status == 204 || status == 304 {
        return false;
    }
    if let Some(encoding) = response
        .headers
        .get("content-encoding")
        .and_then(|value| value.to_str().ok())
        && !encoding.is_empty()
        && !encoding.eq_ignore_ascii_case("identity")
    {
        return false;
    }
    if let Some(length) = response
        .headers
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        && length == 0
    {
        return false;
    }
    match response
        .headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
    {
        Some(value) => is_textual_content_type(value),
        // Unknown payload: capture, best effort.
        None => true,
    }
}

/// The response's announced body size, used when the body itself was not
/// captured.
pub(crate) fn announced_body_size(
    response: &pingora::http::ResponseHeader,
) -> u64 {
    response
        .headers
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

/// Body bytes kept per access log entry per direction, resolved from the
/// agent config; capped so a misconfiguration cannot bloat the log store.
pub(crate) fn log_body_limit() -> usize {
    VarmanAgent::instance()
        .map(|agent| agent.config.max_body_log_size.min(MAX_LOG_BODY_LIMIT))
        .unwrap_or(0)
}

pub(crate) fn parse_mode(value: &str) -> WafMode {
    match value.to_lowercase().as_str() {
        "off" => WafMode::Off,
        "monitor" => WafMode::Monitor,
        "block" => WafMode::Block,
        _ => WafMode::Block,
    }
}

pub(crate) fn action_str(action: &WafAction) -> &'static str {
    match action {
        WafAction::Pass => "pass",
        WafAction::Monitor => "monitor",
        WafAction::Block => "block",
        WafAction::Challenge => "challenge",
    }
}

/// Parses a site monitor list for attack categories; unknown names are
/// ignored with a warning so a stale control-plane value can never silently
/// re-enable enforcement of a category the operator turned off.
pub(crate) fn parse_monitor_categories(names: &[String]) -> CategorySet {
    let mut set = CategorySet::EMPTY;
    for name in names {
        match CategorySet::parse_name(name) {
            Some(category) => set = set.union(category),
            None => warn!(name = %name, "unknown monitor category; ignoring"),
        }
    }
    set
}

/// Parses a site monitor list for backend stacks. Starts from the empty set
/// (unlike [`StackSet::from_names`], which always includes GENERIC) because
/// language-agnostic detection must not be downgradable via stack switches.
pub(crate) fn parse_monitor_stacks(names: &[String]) -> StackSet {
    let mut set = StackSet::EMPTY;
    for name in names {
        match StackSet::parse_name(name) {
            Some(stack) => set = set.union(stack),
            None => warn!(name = %name, "unknown monitor stack; ignoring"),
        }
    }
    set
}

/// Build a [`WafEngine`] from control-plane site WAF config.
/// Maps a site's enforcement mode (`waf_settings.mode`) onto the engine mode.
pub(crate) fn site_mode(cfg: &CacheWafConfig) -> WafMode {
    match cfg.mode {
        CacheWafMode::Off => WafMode::Off,
        CacheWafMode::Monitor => WafMode::Monitor,
        CacheWafMode::Block => WafMode::Block,
    }
}

/// Applies the site's enforcement mode to the escalated verdict: `monitor`
/// downgrades a Block/Challenge to a Monitor verdict (recorded, never
/// enforced) and `off` enforces nothing. Block leaves the verdict alone.
pub(crate) fn cap_to_site_mode(
    verdict: WafVerdict,
    mode: WafMode,
) -> WafVerdict {
    match mode {
        WafMode::Off => WafVerdict {
            action: WafAction::Pass,
            ..verdict
        },
        WafMode::Monitor => match verdict.action {
            WafAction::Block | WafAction::Challenge => WafVerdict {
                action: WafAction::Monitor,
                ..verdict
            },
            _ => verdict,
        },
        WafMode::Block => verdict,
    }
}

pub(crate) fn build_site_engine(cfg: &CacheWafConfig) -> WafEngine {
    WafEngine::new(&build_site_engine_config(cfg))
}

/// Builds the engine config for one site, inheriting every value the site
/// does not deliberately override from [`WafEngineConfig::default`].
pub(crate) fn build_site_engine_config(
    cfg: &CacheWafConfig,
) -> WafEngineConfig {
    let mode = site_mode(cfg);
    let rules: Vec<CompiledRule> = cfg
        .custom_rules
        .iter()
        // A rule in `off` mode is switched off entirely; `monitor` rules are
        // compiled normally and downgraded through `monitor_custom_rules`.
        .filter(|r| r.enabled && r.mode != CacheWafMode::Off)
        .filter_map(|r| {
            let action = match r.action {
                CacheWafAction::Block => RuleAction::Block,
                CacheWafAction::Log => RuleAction::Log,
                CacheWafAction::Challenge => RuleAction::Challenge,
                CacheWafAction::JsChallenge => RuleAction::JsChallenge,
                CacheWafAction::Allow => RuleAction::Allow,
                // Not a custom-rule action; the control plane never sends
                // one, so the rule is dropped instead of guessed at.
                CacheWafAction::BasicAuth => {
                    warn!(
                        rule = %r.id,
                        "custom rule carries a non-rule action; rule skipped"
                    );
                    return None;
                },
            };
            CompiledRule::compile(
                r.id.clone(),
                r.name.clone(),
                &r.expression,
                action,
                r.severity as u8,
                r.tags.clone(),
            )
            .ok()
        })
        .collect();

    // The engine baseline (level, stacks, threshold, decode layers, managed
    // rules, fast-path blocking, empty tuning sets) is owned by
    // `WafEngineConfig::default`; only the policy-derived values are set here.
    WafEngineConfig {
        mode,
        level: if cfg.advanced_mode {
            WafLevel::Strict
        } else {
            WafEngineConfig::default().level
        },
        monitor_categories: parse_monitor_categories(&cfg.monitor_categories),
        monitor_stacks: parse_monitor_stacks(&cfg.monitor_stacks),
        threshold: if cfg.anomaly_threshold > 0 {
            cfg.anomaly_threshold
        } else {
            WafEngineConfig::default().threshold
        },
        paranoia_level: (cfg.paranoia_level.clamp(1, 4)) as u8,
        rules,
        // Per-rule monitor downgrades from the control plane: managed rule
        // ids arrive on the site's WAF config; a custom rule's own `mode`
        // decides (`monitor` records the hit without enforcing).
        monitor_managed_rules: cfg
            .monitor_managed_rules
            .iter()
            .cloned()
            .collect(),
        monitor_custom_rules: cfg
            .custom_rules
            .iter()
            .filter(|r| r.enabled && r.mode == CacheWafMode::Monitor)
            .map(|r| r.id.clone())
            .collect(),
        // Per-rule tuning from the control plane's policies: disabled rules
        // are skipped entirely, score overrides replace the severity-derived
        // contribution.
        disabled_rules: cfg.disabled_rules.iter().cloned().collect(),
        rule_scores: cfg
            .rule_scores
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect(),
        rule_target_exclusions: cfg
            .rule_target_exclusions
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        path_target_exclusions: cfg
            .path_target_exclusions
            .iter()
            .map(|entry| PathTargetExclusion {
                rule_id: entry.rule_id.clone(),
                targets: entry.targets.clone(),
                path_prefix: entry.path_prefix.clone(),
            })
            .collect(),
        ..Default::default()
    }
}
