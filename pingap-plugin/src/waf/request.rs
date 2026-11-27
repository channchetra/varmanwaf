use super::*;

// ─────────────────────────────────────────────────────────────
// Request-path stages
// ─────────────────────────────────────────────────────────────

/// Per-request state shared by the WAF request stages.
///
/// [`WafPlugin::begin_request`] builds it once; every stage below borrows it,
/// so the extracted request facts (headers, body prefix, resolved site rules)
/// are not cloned again per gate.
pub(super) struct RequestState {
    /// Request id shared by the access log, the security events and the
    /// `X-Request-ID` header.
    pub(super) request_id: String,
    pub(super) host: String,
    pub(super) site_id: String,
    pub(super) paused: bool,
    pub(super) choice: EngineChoice,
    pub(super) context: Option<Arc<SiteContext>>,
    /// Observation mode: detections keep running but nothing is enforced.
    pub(super) observe: bool,
    pub(super) agent: Option<Arc<VarmanAgent>>,
    pub(super) client_addr: Option<IpAddr>,
    pub(super) request_data: RequestData,
    pub(super) user_agent: String,
    pub(super) referer: String,
    /// Access-policy outcome, reused by the basic auth gate.
    pub(super) access: PolicyOutcome,
    /// Body inspection was requested by the plugin or the site.
    pub(super) captures_body: bool,
    /// Inspected body prefix, filled by [`WafPlugin::capture_body`].
    pub(super) inspect_buf: BytesMut,
    /// The early read stopped before the end of the body.
    pub(super) body_truncated: bool,
}

/// The URL a challenge is bound to: path plus query when one is present.
pub(super) fn request_url(request_data: &RequestData) -> String {
    if request_data.query.is_empty() {
        request_data.path.clone()
    } else {
        format!("{}?{}", request_data.path, request_data.query)
    }
}

impl WafPlugin {
    /// Extracts the immutable request facts, resolves the site rules and the
    /// request identifier every stage shares.
    pub(super) fn begin_request(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> RequestState {
        let req_header = session.req_header();
        let method = req_header.method.as_str().to_string();
        let path = req_header.uri.path().to_string();
        let query = req_header.uri.query().unwrap_or_default().to_string();
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut user_agent = String::new();
        let mut referer = String::new();
        for (name, value) in req_header.headers.iter() {
            let Ok(v) = value.to_str() else {
                continue;
            };
            match name.as_str() {
                "user-agent" => user_agent = v.to_string(),
                "referer" => referer = v.to_string(),
                _ => {},
            }
            headers.push((name.as_str().to_string(), v.to_string()));
        }
        let host = get_host(req_header).unwrap_or_default().to_string();
        let scheme = if ctx.conn.tls_version.is_some() {
            "https".to_string()
        } else {
            "http".to_string()
        };
        // Matches http::Version's Debug output without the formatting
        // machinery on the hot path.
        let protocol = match req_header.version {
            Version::HTTP_09 => "HTTP/0.9",
            Version::HTTP_10 => "HTTP/1.0",
            Version::HTTP_11 => "HTTP/1.1",
            Version::HTTP_2 => "HTTP/2.0",
            Version::HTTP_3 => "HTTP/3.0",
            _ => "HTTP/1.1",
        }
        .to_string();
        let client_ip = ensure_client_ip(session, ctx).to_string();
        let client_addr: Option<IpAddr> = client_ip.parse().ok();

        // Get or create the request id early so the access log, security
        // events and the X-Request-ID header all share one stable value.
        let request_id = match ctx.state.request_id.clone() {
            Some(id) => id,
            None => {
                let id = generate_request_id();
                ctx.state.request_id = Some(id.clone());
                let _ = session
                    .req_header_mut()
                    .insert_header(&HTTP_HEADER_NAME_X_REQUEST_ID, &id);
                id
            },
        };

        // Resolve the engine and access restrictions for this domain.
        let resolved = self.resolve_site(&host);
        let observe = resolved
            .context
            .as_ref()
            .is_some_and(|site| site.observation_mode);
        // Advanced-mode sites ask for body inspection even when the plugin
        // switch is off; the plugin-level switch stays authoritative for the
        // truncation cap.
        let captures_body = self.inspect_body
            || resolved
                .context
                .as_ref()
                .is_some_and(|site| site.inspect_body);
        // Per-site custom layers may need the body (OpenAPI JSON-body
        // schemas) even when generic body inspection is off.
        let site_wants_body = resolved
            .context
            .as_ref()
            .and_then(|site| site.custom.as_ref())
            .is_some_and(|custom| custom.wants_body());

        // Country of the client: it feeds geo restrictions, the
        // `ip.src.country` rule variable and the flag shown with the access
        // log, so it is only resolved when an agent consumes those facts.
        let agent = VarmanAgent::instance();
        let country = if agent.is_some() {
            client_addr.and_then(lookup_country_addr)
        } else {
            None
        };

        RequestState {
            request_id,
            host,
            site_id: resolved.site_id,
            paused: resolved.paused,
            choice: resolved.choice,
            context: resolved.context,
            observe,
            agent,
            client_addr,
            request_data: RequestData {
                method,
                path,
                query,
                headers,
                body: None,
                client_ip,
                country_code: country,
                scheme,
                protocol,
            },
            user_agent,
            referer,
            access: PolicyOutcome::NoMatch,
            captures_body: captures_body || site_wants_body,
            inspect_buf: BytesMut::new(),
            body_truncated: false,
        }
    }

    /// A client serving out a failed-authentication block is refused before
    /// any further work happens.
    pub(super) fn check_ato(
        &self,
        state: &RequestState,
    ) -> Option<RequestPluginResult> {
        if !self.ato.enabled() || state.site_id.is_empty() {
            return None;
        }
        let key = format!("{}|{}", state.site_id, state.request_data.client_ip);
        if !self.ato.is_blocked(&key) {
            return None;
        }
        let retry = self.ato.retry_after_secs(&key).unwrap_or(0);
        tracing::info!(
            site_id = %state.site_id,
            client_ip = %state.request_data.client_ip,
            "request refused: failed-authentication streak"
        );
        let mut response = block_page(
            &state.request_id,
            "too many failed authentication attempts; try again later",
        );
        if retry > 0 {
            response.headers.get_or_insert_with(Vec::new).push((
                http::header::RETRY_AFTER,
                http::HeaderValue::from_str(&retry.to_string())
                    .unwrap_or(http::HeaderValue::from_static("60")),
            ));
        }
        emit_generated_access(
            state.agent.as_ref(),
            &state.request_id,
            &response,
        );
        Some(RequestPluginResult::Respond(response))
    }

    /// Paused sites answer with a maintenance page before any other rule runs.
    /// TLS termination and the log pipeline stay untouched, so the certificate
    /// keeps serving and the traffic remains visible.
    pub(super) fn check_paused(
        &self,
        state: &RequestState,
    ) -> Option<RequestPluginResult> {
        if !state.paused {
            return None;
        }
        let response = paused_page(&state.request_id);
        emit_generated_access(
            state.agent.as_ref(),
            &state.request_id,
            &response,
        );
        Some(RequestPluginResult::Respond(response))
    }

    /// Dynamic IP blocks: an IP the edge already refused (an auto-block from
    /// an earlier WAF/rate-limit verdict or a server-issued block command) is
    /// rejected before any rule runs. Like the paused-site and mTLS denials
    /// this enforces an existing decision, so observation mode never
    /// downgrades it. Unknown hosts carry no synced site id and therefore can
    /// never match a block.
    pub(super) fn check_ip_block(
        &self,
        state: &RequestState,
    ) -> Option<RequestPluginResult> {
        if state.site_id.is_empty() {
            return None;
        }
        let agent = state.agent.as_ref()?;
        if !agent.is_ip_blocked(&state.site_id, &state.request_data.client_ip) {
            return None;
        }
        let response = block_page(
            &state.request_id,
            "IP temporarily blocked by WAF defense",
        );
        emit_generated_access(
            state.agent.as_ref(),
            &state.request_id,
            &response,
        );
        Some(RequestPluginResult::Respond(response))
    }

    /// mTLS: a site that requires a client certificate refuses the request
    /// before any other rule runs. Revoked certificates and organization
    /// mismatches are refused here too, since the TLS layer only proves the
    /// chain is trusted, not which site it was issued for. The denial is
    /// logged as access only - it is not a WAF verdict.
    pub(super) fn check_mtls(
        &self,
        state: &RequestState,
        ctx: &Ctx,
    ) -> Option<RequestPluginResult> {
        let mtls =
            state.context.as_ref().and_then(|site| site.mtls.as_ref())?;
        let reason = mtls.denial(ctx)?;
        let response = block_page(&state.request_id, reason);
        emit_generated_access(
            state.agent.as_ref(),
            &state.request_id,
            &response,
        );
        Some(RequestPluginResult::Respond(response))
    }

    /// Access restrictions: IP rules and geo stop a request before the WAF
    /// engine runs, and apply whether or not it is enabled. A rule whose
    /// action is `basic_auth` is not an outright denial: it feeds the gate
    /// below so the request continues once authenticated. The outcome is kept
    /// on the state for [`Self::check_basic_auth`].
    pub(super) fn check_access(
        &self,
        state: &mut RequestState,
    ) -> Option<RequestPluginResult> {
        let access = match &state.context {
            Some(site) => site.policy.evaluate(
                &state.request_data.client_ip,
                state.client_addr,
                state.request_data.country_code.as_deref(),
            ),
            None => PolicyOutcome::NoMatch,
        };
        let mut result = None;
        if let Some(denial) =
            access.denial().filter(|denial| !denial.basic_auth)
        {
            if state.observe || denial.monitor {
                // Observation mode downgrades every protection; the geo
                // policy's monitor action downgrades only itself. Both record
                // without enforcing; the monitor action labels the event as
                // such.
                Self::log_observed(
                    &state.site_id,
                    &state.request_id,
                    &state.host,
                    &state.request_data,
                    if denial.monitor {
                        WafAction::Monitor
                    } else if denial.challenge {
                        WafAction::Challenge
                    } else {
                        WafAction::Block
                    },
                    &denial.rule_id,
                    &denial.detail,
                    &denial.rule_name,
                );
            } else {
                let original_url = request_url(&state.request_data);
                result = Some(Self::deny_request(
                    state.agent.as_ref(),
                    &state.site_id,
                    &state.request_id,
                    &state.host,
                    &state.request_data,
                    denial,
                    &original_url,
                    self.pow_difficulty,
                ));
            }
        }
        state.access = access;
        result
    }

    /// Basic authentication: the site-wide gate and any access rule with the
    /// `basic_auth` action share one credential set. It runs before
    /// bot/rate/WAF checks and inside the WAF plugin, which sits ahead of the
    /// cache plugin, so neither a cached response nor a later verdict can skip
    /// it. An `allow` rule is the one exemption: it means the client is
    /// trusted outright.
    pub(super) async fn check_basic_auth(
        &self,
        session: &mut Session,
        state: &mut RequestState,
    ) -> Option<RequestPluginResult> {
        let gate = state
            .context
            .as_ref()
            .and_then(|site| site.basic_auth.as_ref());
        let gate_required = match &state.access {
            PolicyOutcome::Allowed => false,
            PolicyOutcome::Denied(denial) => denial.basic_auth,
            PolicyOutcome::NoMatch => gate.is_some_and(|gate| gate.site_wide),
        };
        if !gate_required {
            return None;
        }
        let authenticated =
            gate.is_some_and(|gate| gate.verify(&state.request_data.headers));
        if !authenticated {
            if let Some(delay) = gate.and_then(|gate| gate.delay) {
                tokio::time::sleep(delay).await;
            }
            let realm = gate
                .map(|gate| gate.realm.as_str())
                .unwrap_or(DEFAULT_BASIC_REALM);
            let reason = state
                .access
                .denial()
                .map(|denial| {
                    format!("{}; authentication required", denial.detail)
                })
                .unwrap_or_else(|| {
                    "site-wide basic authentication".to_string()
                });
            let response = basic_auth_page(&state.request_id, realm, &reason);
            emit_generated_access(
                state.agent.as_ref(),
                &state.request_id,
                &response,
            );
            return Some(RequestPluginResult::Respond(response));
        }
        if let Some(gate) = gate
            && gate.hide_credentials
        {
            session
                .req_header_mut()
                .remove_header(&http::header::AUTHORIZATION);
        }
        None
    }

    /// Bot protection: UA classification runs after IP/geo and before the
    /// engine, applying whether or not the WAF engine is enabled.
    pub(super) async fn check_bot(
        &self,
        session: &Session,
        state: &RequestState,
    ) -> Option<RequestPluginResult> {
        let bot = state.context.as_ref().and_then(|ctx| ctx.bot.as_ref())?;
        let burst = bot.uses_behavioral()
            && !state.request_data.client_ip.is_empty()
            && request_burst(&state.request_data.client_ip);
        match bot
            .evaluate_with_signals(
                state.request_data.client_ip.parse::<IpAddr>().ok(),
                &state.user_agent,
                ClientSignals {
                    browser_hints: browser_header_hints(
                        &state.request_data.headers,
                    ),
                    tls_verified: session
                        .digest()
                        .is_some_and(|d| d.ssl_digest.is_some()),
                    burst,
                },
            )
            .await
        {
            BotDecision::Pass => None,
            BotDecision::Deny(denial) => {
                if state.observe {
                    Self::log_observed(
                        &state.site_id,
                        &state.request_id,
                        &state.host,
                        &state.request_data,
                        if denial.challenge {
                            WafAction::Challenge
                        } else {
                            WafAction::Block
                        },
                        &denial.rule_id,
                        &denial.detail,
                        &denial.rule_name,
                    );
                    None
                } else {
                    let original_url = request_url(&state.request_data);
                    Some(Self::deny_request(
                        state.agent.as_ref(),
                        &state.site_id,
                        &state.request_id,
                        &state.host,
                        &state.request_data,
                        &denial,
                        &original_url,
                        self.pow_difficulty,
                    ))
                }
            },
            BotDecision::LogOnly(denial) => {
                let verdict = WafVerdict {
                    action: WafAction::Monitor,
                    score: 0,
                    matched_rules: vec![denial.rule_id.clone()],
                    details: denial.detail.clone(),
                    breakdown: ScoreBreakdown::clean(),
                };
                Self::log_event(
                    &state.site_id,
                    &state.request_id,
                    &state.host,
                    &state.request_data,
                    &verdict,
                    &denial.rule_name,
                );
                None
            },
        }
    }

    /// Rate limiting: fixed-window counters run after IP/geo/bot and before
    /// the engine, applying whether or not the WAF engine is enabled.
    pub(super) fn check_rate_limit(
        &self,
        state: &RequestState,
    ) -> Option<RequestPluginResult> {
        let rate = state
            .context
            .as_ref()
            .and_then(|c| c.rate_limits.as_ref())?;
        let cleared = rate
            .rules
            .iter()
            .any(|r| r.action == RateAction::Challenge)
            && clearance_valid(clearance_cookie(&state.request_data.headers));
        let outcome = rate.evaluate(
            &self.rate_counters,
            &state.request_data,
            &state.host,
            cleared,
            state.client_addr,
        );
        for tripped in &outcome.logged {
            let verdict = WafVerdict {
                action: WafAction::Monitor,
                score: 0,
                matched_rules: vec![tripped.rule_id.clone()],
                details: tripped.detail.clone(),
                breakdown: ScoreBreakdown::clean(),
            };
            Self::log_event(
                &state.site_id,
                &state.request_id,
                &state.host,
                &state.request_data,
                &verdict,
                &tripped.rule_name,
            );
        }
        let tripped = outcome.deny?;
        if state.observe {
            Self::log_observed(
                &state.site_id,
                &state.request_id,
                &state.host,
                &state.request_data,
                if tripped.challenge {
                    WafAction::Challenge
                } else {
                    WafAction::Block
                },
                &tripped.rule_id,
                &tripped.detail,
                &tripped.rule_name,
            );
            return None;
        }
        let original_url = request_url(&state.request_data);
        let verdict = WafVerdict {
            action: if tripped.challenge {
                WafAction::Challenge
            } else {
                WafAction::Block
            },
            score: 0,
            matched_rules: vec![tripped.rule_id.clone()],
            details: tripped.detail.clone(),
            breakdown: ScoreBreakdown::clean(),
        };
        Self::log_event(
            &state.site_id,
            &state.request_id,
            &state.host,
            &state.request_data,
            &verdict,
            &tripped.rule_name,
        );
        // Defense in depth: refuse the client at the edge for the mitigation
        // window so a repeat offender never reaches the counters (or the
        // origin) again in that time.
        if !tripped.challenge
            && let Some(agent) = &state.agent
        {
            agent.block_ip(
                &state.site_id,
                &state.request_data.client_ip,
                Some(Duration::from_secs(tripped.retry_after)),
                &format!("rate limit: {}", tripped.rule_name),
            );
        }
        let response = if tripped.challenge {
            build_challenge_response(
                &state.request_id,
                &original_url,
                &state.site_id,
                self.pow_difficulty,
                ChallengeKind::Js,
            )
        } else {
            rate_limit_page(
                &state.request_id,
                &tripped.detail,
                tripped.retry_after,
            )
        };
        emit_generated_access(
            state.agent.as_ref(),
            &state.request_id,
            &response,
        );
        Some(RequestPluginResult::Respond(response))
    }

    /// Engine selection: a disabled site, a plugin-level `off` mode and a
    /// site-level `off` mode end the request path before inspection. A
    /// site-level `off` mirrors the plugin-level switch: the site is
    /// configured to enforce nothing, so neither the legacy engine nor the
    /// pipeline runs.
    pub(super) fn select_engine(
        &self,
        state: &RequestState,
    ) -> Option<RequestPluginResult> {
        let disabled = matches!(&state.choice, EngineChoice::Disabled);
        let base_off = matches!(&state.choice, EngineChoice::Base)
            && self.mode == WafMode::Off;
        let site_off = state.context.as_ref().and_then(|site| site.mode)
            == Some(WafMode::Off);
        if !disabled && !base_off && !site_off {
            return None;
        }
        if let Some(agent) = &state.agent {
            agent.record_request(false);
        }
        if disabled {
            Some(RequestPluginResult::Continue)
        } else {
            Some(RequestPluginResult::Skipped)
        }
    }
}
