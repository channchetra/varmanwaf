use super::request::RequestState;
use super::*;

// ─────────────────────────────────────────────────────────────
// Request body capture
// ─────────────────────────────────────────────────────────────

impl WafPlugin {
    /// Reads the request body once for the access log and the WAF inspection.
    ///
    /// Pingora's retry buffer replays the consumed bytes upstream, so reading
    /// does not interfere with forwarding. A body larger than the replay window
    /// is read exactly one chunk; the remainder is staged for the body filter.
    /// Returns an early response when the read deadline, the replay window or
    /// the configured size policy refuses the request.
    pub(super) async fn capture_body(
        &self,
        session: &mut Session,
        ctx: &Ctx,
        state: &mut RequestState,
    ) -> pingora::Result<Option<RequestPluginResult>> {
        let body_limit = log_body_limit();
        let log_headers = cap_headers(
            state
                .request_data
                .headers
                .iter()
                .map(|(name, value)| (name.clone(), value.as_str())),
        );
        let mut log_body_prefix = LogBodyPrefix::new(body_limit);
        // Set when the early read stopped before the end of the body: the
        // remainder is staged (withheld and scanned) by the body filter.
        let mut stage_remainder = false;
        if (state.agent.is_some() && body_limit > 0 || state.captures_body)
            && !(state.request_data.method == "POST"
                && state.request_data.path == VERIFY_ENDPOINT)
        {
            // Reading the body here consumes it from the downstream stream.
            // Pingora only enables its retry buffer after the request filters
            // have run, so without this call the bytes we read are lost: the
            // proxy replays nothing while the upstream waits for the declared
            // Content-Length and the request stalls. Enabling the buffer
            // first makes every byte we read replayable.
            //
            // The replay buffer is exactly 64 KiB and a single read can return
            // a full 64 KiB, so a second read after any consumed byte can
            // cross the limit, truncate the replay and stall the upstream
            // (observed live as a hang on bodies above 64 KiB). The safe rule:
            // read the whole body only when the declared Content-Length fits
            // the replay window; otherwise read exactly one chunk and let the
            // stream (tail) inspection cover everything after it.
            const REPLAY_LIMIT: usize = 64 * 1024;
            let content_length = state
                .request_data
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, value)| value.trim().parse::<usize>().ok());
            let read_whole =
                content_length.is_some_and(|len| len <= REPLAY_LIMIT);
            session.enable_retry_buffering();
            let mut interrupted = false;
            // Slow-upload defense: the whole read pass must finish within the
            // deadline, so a trickling client cannot stretch it byte by byte.
            let deadline = (self.body_read_timeout_ms > 0).then(|| {
                tokio::time::Instant::now()
                    + Duration::from_millis(self.body_read_timeout_ms)
            });
            loop {
                let read = session.read_request_body();
                let chunk = match deadline {
                    Some(deadline) => {
                        match tokio::time::timeout_at(deadline, read).await {
                            Ok(result) => result?,
                            Err(_) => {
                                tracing::info!(
                                    timeout_ms = self.body_read_timeout_ms,
                                    "request body read deadline exceeded; refused"
                                );
                                let mut response = block_page(
                                    &state.request_id,
                                    &format!(
                                        "request body was not received within {} ms",
                                        self.body_read_timeout_ms
                                    ),
                                );
                                response.status =
                                    http::StatusCode::REQUEST_TIMEOUT;
                                emit_generated_access(
                                    state.agent.as_ref(),
                                    &state.request_id,
                                    &response,
                                );
                                return Ok(Some(RequestPluginResult::Respond(
                                    response,
                                )));
                            },
                        }
                    },
                    None => read.await?,
                };
                let Some(chunk) = chunk else {
                    break;
                };
                let chunk = chunk.as_ref();
                log_body_prefix.absorb(chunk);
                if state.captures_body {
                    state.inspect_buf.put(chunk);
                }
                // Inspection needs the prefix; the log needs its own. Stop
                // once neither can learn anything from more bytes.
                if state.captures_body
                    && state.inspect_buf.len() >= self.max_body_size
                {
                    interrupted = true;
                    state.body_truncated = true;
                    break;
                }
                if !read_whole {
                    // A body larger than the replay window: one chunk is all
                    // we can consume without risking a truncated replay; the
                    // stream (tail) inspection covers the remainder.
                    interrupted = true;
                    state.body_truncated = true;
                    break;
                }
                if !state.captures_body && log_body_prefix.limit_hit() {
                    interrupted = true;
                    break;
                }
            }
            if session.retry_buffer_truncated() {
                // The replay can no longer be trusted (a content-length that
                // under-declared the body, or an unforeseen read path).
                // Refusing explicitly beats stalling the upstream forever.
                tracing::warn!(
                    limit = REPLAY_LIMIT,
                    "request body exceeded the replay window; refused"
                );
                let mut response = block_page(
                    &state.request_id,
                    &format!(
                        "request body exceeds the {} byte replay window",
                        REPLAY_LIMIT
                    ),
                );
                response.status = http::StatusCode::PAYLOAD_TOO_LARGE;
                emit_generated_access(
                    state.agent.as_ref(),
                    &state.request_id,
                    &response,
                );
                return Ok(Some(RequestPluginResult::Respond(response)));
            }
            if interrupted {
                log_body_prefix.interrupted();
                // Explicit size policy: refuse the request rather than
                // inspecting a prefix and forwarding the remainder.
                if self.body_reject {
                    tracing::info!(
                        limit = self.max_body_size,
                        "request body exceeds the inspection limit; rejected"
                    );
                    let mut response = block_page(
                        &state.request_id,
                        &format!(
                            "request body exceeds the {} byte inspection limit",
                            self.max_body_size
                        ),
                    );
                    response.status = http::StatusCode::PAYLOAD_TOO_LARGE;
                    emit_generated_access(
                        state.agent.as_ref(),
                        &state.request_id,
                        &response,
                    );
                    return Ok(Some(RequestPluginResult::Respond(response)));
                }
                // Staging policy: withhold and scan the remainder before
                // any of it reaches the upstream.
                if state.captures_body {
                    stage_remainder = true;
                }
            }
        }
        if stage_remainder && self.tail_inspection {
            DEFERRED_BODY.insert(
                state.request_id.clone(),
                DeferredBody {
                    buffer: BytesMut::new(),
                    passthrough: false,
                    created_at: Instant::now(),
                },
            );
        }
        let (log_body, log_body_size, log_body_truncated) =
            log_body_prefix.finish();

        // Track the request for access logging until the response phase —
        // including WAF-disabled sites, so traffic data stays complete.
        if state.agent.is_some() {
            register_pending_access(
                &state.request_id,
                PendingAccess {
                    site_id: state.site_id.clone(),
                    client_ip: state.request_data.client_ip.clone(),
                    method: state.request_data.method.clone(),
                    scheme: state.request_data.scheme.clone(),
                    protocol: state.request_data.protocol.clone(),
                    host: state.host.clone(),
                    path: state.request_data.path.clone(),
                    query: state.request_data.query.clone(),
                    user_agent: state.user_agent.clone(),
                    referer: std::mem::take(&mut state.referer),
                    tls_version: ctx
                        .conn
                        .tls_version
                        .clone()
                        .unwrap_or_default()
                        .to_string(),
                    country_code: state
                        .request_data
                        .country_code
                        .clone()
                        .unwrap_or_default(),
                    request_headers: log_headers,
                    request_body: log_body,
                    request_body_size: log_body_size,
                    request_body_truncated: log_body_truncated,
                    body_limit,
                    response: None,
                    start: Instant::now(),
                },
            );
        }
        Ok(None)
    }
}
