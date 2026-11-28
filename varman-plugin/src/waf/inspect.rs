use super::request::{RequestState, request_url};
use super::*;

// ─────────────────────────────────────────────────────────────
// Inspection and verdict handling
// ─────────────────────────────────────────────────────────────

impl WafPlugin {
    /// Inspects the request with the selected engine, then lets the Varman
    /// pipeline, the per-site custom layers and the external processor
    /// escalate the verdict. The site's enforcement mode caps every engine
    /// path; access control decided before inspection is never downgraded.
    pub(super) async fn inspect_request(
        &self,
        state: &mut RequestState,
    ) -> WafVerdict {
        // The body (if any) was already read during log capture; when body
        // inspection (or a per-site body schema) is enabled the engine sees
        // the same prefix.
        state.request_data.body =
            if state.captures_body && !state.inspect_buf.is_empty() {
                Some(state.inspect_buf.to_vec())
            } else {
                None
            };
        let verdict = match &state.choice {
            EngineChoice::Site(engine) => engine.inspect(&state.request_data),
            EngineChoice::Base => {
                let guard =
                    self.engine.read().unwrap_or_else(|e| e.into_inner());
                guard.inspect(&state.request_data)
            },
            EngineChoice::Disabled => unreachable!("handled above"),
        };

        // Varman pipeline: shadow comparison, or enforcement when the engine
        // mode is `varman`. The pipeline can only escalate the legacy action,
        // so dashboard-configured custom rules stay effective. The mode comes
        // from the site's `waf_settings.engine_mode` (when it is not
        // `inherit`) and falls back to the process-wide `VARMAN_WAF_ENGINE`.
        let engine = crate::waf_shadow::resolve_mode(
            state
                .context
                .as_ref()
                .map(|site| site.engine_mode.as_str())
                .filter(|mode| !mode.is_empty()),
        );
        let monitored = state
            .context
            .as_ref()
            .map(|site| site.monitor_categories.as_slice())
            .unwrap_or_default();
        // Engine telemetry sink: only meaningful when an agent reports it.
        let metrics = state.agent.as_ref().map(|agent| agent.metrics.as_ref());
        let mut verdict = match crate::waf_shadow::analyze(
            &state.request_data,
            &verdict,
            engine,
            monitored,
            metrics,
        ) {
            Some(pipeline)
                if engine == crate::waf_shadow::EngineMode::Varman =>
            {
                crate::waf_shadow::effective_verdict(&verdict, &pipeline)
            },
            _ => verdict,
        };

        // Per-site custom layers: SecLang virtual patches (block) and
        // OpenAPI validation (monitor). Compiled once per site context; both
        // escalate only, never weaken the native verdict.
        if let Some(custom) =
            state.context.as_ref().and_then(|site| site.custom.as_ref())
        {
            let canonical =
                crate::waf_shadow::canonicalize(&state.request_data);
            if let Some(custom_verdict) =
                custom.evaluate(&canonical, !state.body_truncated)
            {
                verdict = crate::waf_shadow::effective_verdict(
                    &verdict,
                    &custom_verdict,
                );
            }
        }

        // External processor (Phase 9): bounded, policy-resolved and
        // additive. The processor can only escalate the verdict; a failure
        // resolves through its configured policy.
        if crate::waf_processor::is_enabled() {
            let findings =
                crate::waf_processor::evaluate(&state.request_data, metrics)
                    .await
                    .filter(|findings| !findings.is_empty());
            if let Some(findings) = findings {
                let processor_verdict =
                    crate::waf_processor::to_waf_verdict(&findings);
                verdict = crate::waf_shadow::effective_verdict(
                    &verdict,
                    &processor_verdict,
                );
            }
        }

        // The site's enforcement mode caps every engine path, including the
        // escalate-only ones (pipeline, custom layers, external processor):
        // `monitor` records findings without enforcing and `off` (handled
        // above) enforces nothing.
        if let Some(mode) = state.context.as_ref().and_then(|site| site.mode) {
            verdict = cap_to_site_mode(verdict, mode);
        }
        verdict
    }

    /// Turns the verdict into the request outcome: pass, monitor, observation
    /// mode or the block/challenge response. A Respond result never reaches
    /// `handle_response`, so the access entry is emitted here.
    pub(super) fn finalize_response(
        &self,
        state: &RequestState,
        verdict: WafVerdict,
    ) -> RequestPluginResult {
        // Custom rule ids carry no name of their own; the site context maps
        // the one that fired back to its configured name.
        let rule_name_of = |verdict: &WafVerdict| -> String {
            let Some(id) = verdict.matched_rules.first() else {
                return String::new();
            };
            state
                .context
                .as_ref()
                .and_then(|context| context.rule_names.get(id))
                .cloned()
                .unwrap_or_default()
        };

        if verdict.action == WafAction::Pass {
            if let Some(agent) = &state.agent {
                agent.record_request(false);
            }
            return RequestPluginResult::Continue;
        }

        // Monitor: log the event but let the request through.
        if verdict.action == WafAction::Monitor {
            let rule_name = rule_name_of(&verdict);
            Self::log_event(
                &state.site_id,
                &state.request_id,
                &state.host,
                &state.request_data,
                &verdict,
                &rule_name,
            );
            return RequestPluginResult::Continue;
        }

        // Observation mode: a Block/Challenge verdict is recorded as a
        // monitor event — nothing was actually blocked — and the request
        // proceeds.
        if state.observe {
            let rule_name = rule_name_of(&verdict);
            tracing::info!(
                site_id = %state.site_id,
                request_id = %state.request_id,
                path = %state.request_data.path,
                would_have = ?verdict.action,
                score = verdict.score,
                "[observation] WAF verdict recorded without enforcing"
            );
            let observed = WafVerdict {
                action: WafAction::Monitor,
                ..verdict.clone()
            };
            Self::log_event(
                &state.site_id,
                &state.request_id,
                &state.host,
                &state.request_data,
                &observed,
                &rule_name,
            );
            return RequestPluginResult::Continue;
        }

        // Block / Challenge: log the security event, then emit the access
        // entry with the real status.
        let rule_name = rule_name_of(&verdict);
        Self::log_event(
            &state.site_id,
            &state.request_id,
            &state.host,
            &state.request_data,
            &verdict,
            &rule_name,
        );
        let response = if verdict.action == WafAction::Block {
            // Auto-block the client for a grace window: repeat requests are
            // refused at the edge (see the entry check above) instead of
            // running the engine every time.
            if let Some(agent) = &state.agent {
                agent.block_ip(
                    &state.site_id,
                    &state.request_data.client_ip,
                    Some(Duration::from_secs(WAF_AUTO_BLOCK_SECS)),
                    &format!("waf: {rule_name}"),
                );
            }
            block_page(&state.request_id, &verdict.details)
        } else {
            // Challenge verdict — delegate to the challenge subsystem.
            let original_url = request_url(&state.request_data);
            build_challenge_response(
                &state.request_id,
                &original_url,
                &state.site_id,
                self.pow_difficulty,
                ChallengeKind::Js,
            )
        };
        emit_generated_access(
            state.agent.as_ref(),
            &state.request_id,
            &response,
        );
        RequestPluginResult::Respond(response)
    }
}
