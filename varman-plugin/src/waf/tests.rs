use super::*;
use crate::test_support::{install_test_agent, lock_agent};
use pingap_core::PluginStep;
use pingap_plugin::text::contains_ignore_case;
use pingap_util::base64_encode;
use pingora::proxy::Session;
use tokio_test::io::Builder;
use varman_challenge::ClearanceLevel;
use varman_protocol::control_plane as proto;

#[test]
fn test_waf_params() {
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(
            r###"
mode = "block"
paranoia_level = 3
anomaly_threshold = 30
detections = ["sqli", "xss", "rce", "lfi", "ssrf"]
ml_enabled = true
ml_threshold = 0.75
"###,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(WafMode::Block, plugin.mode);
    assert_eq!(PluginStep::EarlyRequest, plugin.plugin_step);
}

#[test]
fn path_scoped_exclusion_reaches_the_site_engine() {
    let mut cfg = cache_waf_config(false, Vec::new(), Vec::new());
    cfg.engine_mode = "varman".into();
    cfg.path_target_exclusions =
        vec![varman_agent::cache::PathTargetExclusion {
            rule_id: "VARMAN-1020".to_string(),
            targets: vec!["path".to_string()],
            path_prefix: "/.git".to_string(),
        }];
    let engine = build_site_engine(&cfg);

    let mut inside = probe("");
    inside.path = "/.git/config".to_string();
    let verdict = engine.inspect(&inside);
    assert_eq!(
        WafAction::Pass,
        verdict.action,
        "details: {}",
        verdict.details
    );

    let mut outside = probe("");
    outside.path = "/.svn/config".to_string();
    let verdict = engine.inspect(&outside);
    assert_eq!(
        WafAction::Block,
        verdict.action,
        "details: {}",
        verdict.details
    );
}

fn cache_waf_config(
    advanced_mode: bool,
    monitor_categories: Vec<String>,
    monitor_stacks: Vec<String>,
) -> CacheWafConfig {
    CacheWafConfig {
        enabled: true,
        mode: CacheWafMode::Block,
        paranoia_level: 2,
        sqli_detection: true,
        xss_detection: true,
        rce_detection: true,
        lfi_detection: true,
        ssrf_detection: true,
        bot_detection: true,
        custom_rules: Vec::new(),
        managed_overrides: Vec::new(),
        ml_enabled: false,
        ml_model_path: String::new(),
        ml_threshold: 0.0,
        anomaly_threshold: 0,
        advanced_mode,
        engine_mode: "inherit".into(),
        virtual_patches: String::new(),
        openapi_spec: String::new(),
        monitor_categories,
        monitor_stacks,
        monitor_managed_rules: Vec::new(),
        disabled_rules: Vec::new(),
        rule_scores: Default::default(),
        rule_target_exclusions: Default::default(),
        path_target_exclusions: Default::default(),
        api_operations: Default::default(),
    }
}

fn probe(query: &str) -> RequestData {
    RequestData {
        method: "GET".into(),
        path: "/page".into(),
        query: query.into(),
        headers: vec![
            ("User-Agent".into(), "Mozilla/5.0".into()),
            ("Host".into(), "bench.example.net".into()),
        ],
        body: None,
        client_ip: "203.0.113.10".into(),
        country_code: None,
        scheme: "https".into(),
        protocol: "HTTP/1.1".into(),
    }
}

#[test]
fn site_engine_advanced_mode_enables_strict_rules() {
    // The freemarker EL probe only fires at the strict level, so a block
    // on it proves the site switch reached the engine level knob.
    let query = r#"tpl=${"freemarker.template.utility.Execute"?new()("id")}"#;
    let plain =
        build_site_engine(&cache_waf_config(false, Vec::new(), Vec::new()));
    let advanced =
        build_site_engine(&cache_waf_config(true, Vec::new(), Vec::new()));
    assert_ne!(
        plain.inspect(&probe(query)).action,
        WafAction::Block,
        "details: {}",
        plain.inspect(&probe(query)).details
    );
    assert_eq!(advanced.inspect(&probe(query)).action, WafAction::Block);
}

#[test]
fn site_engine_monitor_categories_downgrade_to_monitor() {
    let engine = build_site_engine(&cache_waf_config(
        false,
        vec!["sqli".into()],
        Vec::new(),
    ));
    let v = engine.inspect(&probe("id=1' OR 1=1 --"));
    assert_eq!(v.action, WafAction::Monitor, "details: {}", v.details);
}

#[test]
fn site_engine_applies_disabled_rules_and_score_overrides() {
    let mut r = probe("");
    r.headers
        .retain(|(k, _)| !k.eq_ignore_ascii_case("User-Agent"));
    r.headers.push(("User-Agent".into(), "sqlmap/1.7".into()));

    // Baseline: the scanner-UA managed rule blocks.
    let base =
        build_site_engine(&cache_waf_config(false, Vec::new(), Vec::new()));
    assert_eq!(base.inspect(&r).action, WafAction::Block);

    // Disabled: the rule is skipped entirely.
    let mut cfg = cache_waf_config(false, Vec::new(), Vec::new());
    cfg.disabled_rules = vec!["VARMAN-1010".to_string()];
    let disabled = build_site_engine(&cfg);
    let v = disabled.inspect(&r);
    assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
    assert!(!v.matched_rules.contains(&"VARMAN-1010".to_string()));

    // Score override: the rule still enforces, with the override points
    // (severity 4 contributes 4 by default, 1 with the override).
    let base_total = base.inspect(&r).breakdown.total;
    let mut cfg = cache_waf_config(false, Vec::new(), Vec::new());
    cfg.rule_scores = [("VARMAN-1010".to_string(), 1u32)].into_iter().collect();
    let overridden = build_site_engine(&cfg);
    let v = overridden.inspect(&r);
    assert_eq!(v.action, WafAction::Block);
    assert_eq!(v.breakdown.total, base_total - 3);
}

#[test]
fn custom_rule_modes_are_wired_into_the_engine() {
    use varman_agent::cache::WafRule as CacheWafRule;

    let rule = |mode: CacheWafMode| CacheWafRule {
        id: "custom-1".to_string(),
        name: "custom".to_string(),
        description: String::new(),
        expression: "http.request.uri.path eq \"/blocked\"".to_string(),
        action: CacheWafAction::Block,
        severity: 4,
        tags: Vec::new(),
        enabled: true,
        mode,
        priority: 0,
    };
    let mut r = probe("");
    r.path = "/blocked".into();

    // Block mode enforces.
    let mut cfg = cache_waf_config(false, Vec::new(), Vec::new());
    cfg.custom_rules = vec![rule(CacheWafMode::Block)];
    assert_eq!(build_site_engine(&cfg).inspect(&r).action, WafAction::Block);

    // Monitor mode records the hit but never enforces it.
    cfg.custom_rules = vec![rule(CacheWafMode::Monitor)];
    let v = build_site_engine(&cfg).inspect(&r);
    assert_eq!(v.action, WafAction::Monitor, "details: {}", v.details);
    assert!(v.matched_rules.contains(&"custom-1".to_string()));

    // Off mode skips the rule entirely.
    cfg.custom_rules = vec![rule(CacheWafMode::Off)];
    assert_eq!(build_site_engine(&cfg).inspect(&r).action, WafAction::Pass);
}

#[test]
fn site_engine_applies_target_exclusions() {
    let mut r = probe("");
    r.path = "/.git/config".into();

    let mut cfg = cache_waf_config(false, Vec::new(), Vec::new());
    assert_eq!(build_site_engine(&cfg).inspect(&r).action, WafAction::Block);

    // Excluding the path suppresses the path-based managed rule.
    cfg.rule_target_exclusions =
        [("VARMAN-1020".to_string(), vec!["path".to_string()])]
            .into_iter()
            .collect();
    let v = build_site_engine(&cfg).inspect(&r);
    assert_eq!(v.action, WafAction::Pass, "details: {}", v.details);
}

#[test]
fn site_mode_caps_the_escalated_verdict() {
    let block = WafVerdict {
        action: WafAction::Block,
        score: 55,
        matched_rules: vec!["sig.sqli.union_bare".to_string()],
        details: "varman-pipeline: 3 finding(s)".to_string(),
        ..WafVerdict::pass()
    };

    // Monitor records the finding but never enforces.
    let capped = cap_to_site_mode(block.clone(), WafMode::Monitor);
    assert_eq!(capped.action, WafAction::Monitor);
    assert_eq!(capped.score, 55);
    assert_eq!(capped.matched_rules, block.matched_rules);

    // Off enforces nothing.
    assert_eq!(
        cap_to_site_mode(block.clone(), WafMode::Off).action,
        WafAction::Pass
    );

    // Block leaves the verdict alone, and a Monitor verdict stays one.
    assert_eq!(
        cap_to_site_mode(block, WafMode::Block).action,
        WafAction::Block
    );
    let monitor = WafVerdict {
        action: WafAction::Monitor,
        ..WafVerdict::pass()
    };
    assert_eq!(
        cap_to_site_mode(monitor, WafMode::Monitor).action,
        WafAction::Monitor
    );
}

#[test]
fn toml_body_read_timeout_parses() {
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(
            r###"
mode = "block"
body_read_timeout_ms = 2500
"###,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(plugin.body_read_timeout_ms, 2500);

    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();
    assert_eq!(plugin.body_read_timeout_ms, 10_000);
}

#[test]
fn toml_body_policy_reject_parses() {
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(
            r###"
mode = "block"
body_policy = "reject"
max_body_size = 1024
"###,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(plugin.body_reject);
    assert_eq!(plugin.max_body_size, 1024);

    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();
    assert!(!plugin.body_reject, "default stays process_partial");
}

#[test]
fn toml_ato_threshold_parses_and_zero_disables() {
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(
            r###"
mode = "block"
ato_failed_auth_threshold = 7
"###,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(plugin.ato.threshold(), 7);

    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(
            r###"
mode = "block"
ato_failed_auth_threshold = 0
"###,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(!plugin.ato.enabled());
}

#[test]
fn site_engine_toml_monitor_keys_flow_into_the_engine() {
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(
            r###"
mode = "block"
monitor_categories = ["sqli", "bogus"]
monitor_stacks = ["java"]
"###,
        )
        .unwrap(),
    )
    .unwrap();
    let engine = plugin.engine.read().unwrap_or_else(|e| e.into_inner());
    let sqli = engine.inspect(&probe("id=1' OR 1=1 --"));
    assert_eq!(sqli.action, WafAction::Monitor, "details: {}", sqli.details);
}

#[test]
fn toml_detections_limit_blocking_families() {
    // Only SQLi may block; every other family records (monitor).
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(
            r###"
mode = "block"
detections = ["sqli", "bogus-family"]
"###,
        )
        .unwrap(),
    )
    .unwrap();
    let engine = plugin.engine.read().unwrap_or_else(|e| e.into_inner());
    let sqli = engine.inspect(&probe("id=1' OR 1=1 --"));
    assert_eq!(
        sqli.action,
        WafAction::Block,
        "sqli stays blocking, details: {}",
        sqli.details
    );
    let xss = engine.inspect(&probe("q=<script>alert(1)</script>"));
    assert_eq!(
        xss.action,
        WafAction::Monitor,
        "xss must be downgraded by the whitelist, details: {}",
        xss.details
    );
}

#[test]
fn toml_ml_enabled_is_reported_not_silent() {
    // The engine has no ML scorer: the flag must load (with a warning)
    // rather than fail, and must not change detection behaviour.
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(
            r###"
mode = "block"
ml_enabled = true
ml_threshold = 0.9
"###,
        )
        .unwrap(),
    )
    .unwrap();
    let engine = plugin.engine.read().unwrap_or_else(|e| e.into_inner());
    let sqli = engine.inspect(&probe("id=1' OR 1=1 --"));
    assert_eq!(sqli.action, WafAction::Block, "details: {}", sqli.details);
}

#[tokio::test]
async fn toml_advanced_mode_enables_strict_rules_and_body() {
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(
            r###"
mode = "block"
advanced_mode = true
"###,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(plugin.inspect_body, "advanced mode implies body inspection");
    let engine = plugin.engine.read().unwrap_or_else(|e| e.into_inner());
    let tpl = engine.inspect(&probe(
        r#"tpl=${"freemarker.template.utility.Execute"?new()("id")}"#,
    ));
    assert_eq!(
        tpl.action,
        WafAction::Block,
        "strict-only rules must be active, details: {}",
        tpl.details
    );
}

#[tokio::test]
async fn test_blocks_sqli() {
    let _agent_lock = lock_agent().await;
    // Start from no instance: a leftover agent from a sibling test
    // would otherwise observe (and count) this request.
    VarmanAgent::set_agent_instance(None);
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    let input_header = "GET /api/users?id=1'%20OR%201=1%20-- HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mock_io = Builder::new().read(input_header.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(mock_io));
    session.read_request().await.unwrap();

    let result = plugin
        .handle_request(
            PluginStep::EarlyRequest,
            &mut session,
            &mut Ctx::default(),
        )
        .await
        .unwrap();
    let RequestPluginResult::Respond(resp) = result else {
        panic!("expected a block response");
    };
    assert_eq!(http::StatusCode::FORBIDDEN, resp.status);
}

#[tokio::test]
async fn test_passes_clean_request() {
    let _agent_lock = lock_agent().await;
    VarmanAgent::set_agent_instance(None);
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    let input_header =
        "GET /api/users?page=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mock_io = Builder::new().read(input_header.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(mock_io));
    session.read_request().await.unwrap();

    let result = plugin
        .handle_request(
            PluginStep::EarlyRequest,
            &mut session,
            &mut Ctx::default(),
        )
        .await
        .unwrap();
    assert!(result == RequestPluginResult::Continue);
}

#[tokio::test]
async fn test_monitor_mode_does_not_block() {
    let _agent_lock = lock_agent().await;
    VarmanAgent::set_agent_instance(None);
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "monitor""###).unwrap(),
    )
    .unwrap();

    let input_header = "GET /api/users?id=1'%20OR%201=1%20-- HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mock_io = Builder::new().read(input_header.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(mock_io));
    session.read_request().await.unwrap();

    let result = plugin
        .handle_request(
            PluginStep::EarlyRequest,
            &mut session,
            &mut Ctx::default(),
        )
        .await
        .unwrap();
    assert!(result == RequestPluginResult::Continue);
}

#[tokio::test]
async fn test_off_mode_skips() {
    let _agent_lock = lock_agent().await;
    VarmanAgent::set_agent_instance(None);
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "off""###).unwrap(),
    )
    .unwrap();

    let input_header = "GET /api/users?id=1'%20OR%201=1%20-- HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mock_io = Builder::new().read(input_header.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(mock_io));
    session.read_request().await.unwrap();

    let result = plugin
        .handle_request(
            PluginStep::EarlyRequest,
            &mut session,
            &mut Ctx::default(),
        )
        .await
        .unwrap();
    assert!(result == RequestPluginResult::Skipped);
}

/// Pushes site rules to the test agent: a whitelist allow rule above a
/// catch-all block rule for `example.com`.
async fn install_whitelist_agent() -> (
    tokio::sync::MutexGuard<'static, ()>,
    Arc<VarmanAgent>,
    tempfile::TempDir,
) {
    let installed = install_test_agent().await;
    installed
        .1
        .rule_cache
        .update_from_site_config(&proto::SiteConfig {
            sites: vec![proto::Site {
                id: "site-1".to_string(),
                name: "example".to_string(),
                domain: "example.com".to_string(),
                alternate_domains: Vec::new(),
                status: 0,
                rules: Some(proto::RuleBundle {
                    site_id: "site-1".to_string(),
                    config_hash: "hash-1".to_string(),
                    ip_access_rules: vec![
                        proto::IpAccessRule {
                            id: "allow-office".to_string(),
                            name: "office egress".to_string(),
                            ip_ranges: vec!["10.1.1.1".to_string()],
                            action: proto::IpAccessAction::IpAccessAllow as i32,
                            note: String::new(),
                            enabled: true,
                        },
                        proto::IpAccessRule {
                            id: "block-all".to_string(),
                            name: "block everything else".to_string(),
                            ip_ranges: vec!["0.0.0.0/0".to_string()],
                            action: proto::IpAccessAction::IpAccessBlock as i32,
                            note: String::new(),
                            enabled: true,
                        },
                    ],
                    ..Default::default()
                }),
                ..Default::default()
            }],
            config_hash: "hash-1".to_string(),
            updated_at: None,
        })
        .unwrap();
    installed
}

/// Installs an agent whose only site is paused and carries a catch-all
/// block rule, so the pause must win over the restriction.
async fn install_paused_agent() -> (
    tokio::sync::MutexGuard<'static, ()>,
    Arc<VarmanAgent>,
    tempfile::TempDir,
) {
    let installed = install_test_agent().await;
    installed
        .1
        .rule_cache
        .update_from_site_config(&proto::SiteConfig {
            sites: vec![proto::Site {
                id: "site-1".to_string(),
                name: "example".to_string(),
                domain: "example.com".to_string(),
                alternate_domains: Vec::new(),
                status: 1, // SITE_STATUS_PAUSED
                rules: Some(proto::RuleBundle {
                    site_id: "site-1".to_string(),
                    config_hash: "hash-1".to_string(),
                    ip_access_rules: vec![proto::IpAccessRule {
                        id: "block-all".to_string(),
                        name: "block everything".to_string(),
                        ip_ranges: vec!["0.0.0.0/0".to_string()],
                        action: proto::IpAccessAction::IpAccessBlock as i32,
                        note: String::new(),
                        enabled: true,
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            }],
            config_hash: "hash-1".to_string(),
            updated_at: None,
        })
        .unwrap();
    installed
}

/// Builds the one-site config used by the mode-cap test: `example.com`
/// runs the Varman pipeline with the given site mode (1 = monitor,
/// 2 = block). The config hash differs per mode so the plugin's per-site
/// cache cannot serve a stale context between the two phases.
fn monitor_varman_site(mode: i32) -> proto::SiteConfig {
    proto::SiteConfig {
        sites: vec![proto::Site {
            id: "site-1".to_string(),
            name: "example".to_string(),
            domain: "example.com".to_string(),
            alternate_domains: Vec::new(),
            rules: Some(proto::RuleBundle {
                site_id: "site-1".to_string(),
                config_hash: format!("hash-{mode}"),
                waf: Some(proto::WafConfig {
                    enabled: true,
                    mode,
                    engine_mode: "varman".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }],
        config_hash: format!("hash-{mode}"),
        updated_at: None,
    }
}

/// Two sites, where only the second one changes. The first site's bundle
/// hash is what the agent reports globally, so the second site's context
/// must key on its own hash.
fn two_site_varman_config(mode: i32, site_hash: &str) -> proto::SiteConfig {
    proto::SiteConfig {
        sites: vec![
            proto::Site {
                id: "site-a".to_string(),
                name: "first".to_string(),
                domain: "aaa.com".to_string(),
                alternate_domains: Vec::new(),
                rules: Some(proto::RuleBundle {
                    site_id: "site-a".to_string(),
                    config_hash: "hash-first".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            proto::Site {
                id: "site-1".to_string(),
                name: "example".to_string(),
                domain: "example.com".to_string(),
                alternate_domains: Vec::new(),
                rules: Some(proto::RuleBundle {
                    site_id: "site-1".to_string(),
                    config_hash: site_hash.to_string(),
                    waf: Some(proto::WafConfig {
                        enabled: true,
                        mode,
                        engine_mode: "varman".to_string(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ],
        config_hash: format!("full-{site_hash}"),
        updated_at: None,
    }
}

/// Runs the union-select probe through the plugin for `example.com`.
async fn run_query_probe(plugin: &WafPlugin) -> RequestPluginResult {
    run_query_probe_for(plugin, "example.com").await
}

async fn run_query_probe_for(
    plugin: &WafPlugin,
    host: &str,
) -> RequestPluginResult {
    let input_header = format!(
        "GET /?id=1'%20UNION%20SELECT%20username,password%20FROM%20users-- \
         HTTP/1.1\r\nHost: {host}\r\n\r\n"
    );
    let mock_io = Builder::new().read(input_header.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(mock_io));
    session.read_request().await.unwrap();
    let mut ctx = Ctx::default();
    ctx.conn.client_ip = Some("203.0.113.7".to_string());
    plugin
        .handle_request(PluginStep::EarlyRequest, &mut session, &mut ctx)
        .await
        .unwrap()
}

/// A site that runs the Varman pipeline in monitor mode never enforces:
/// the site's `mode` caps every engine path, including the pipeline's
/// escalation to Block.
#[tokio::test]
async fn test_site_monitor_mode_caps_the_pipeline() {
    let (_guard, agent, _dir) = install_test_agent().await;
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    // Control: the same site in block mode enforces the finding, so the
    // monitor assertion below is meaningful.
    agent
        .rule_cache
        .update_from_site_config(&monitor_varman_site(2))
        .unwrap();
    assert!(matches!(
        run_query_probe(&plugin).await,
        RequestPluginResult::Respond(_)
    ));

    // Monitor mode caps it: detected and recorded, never enforced.
    agent
        .rule_cache
        .update_from_site_config(&monitor_varman_site(1))
        .unwrap();
    assert!(run_query_probe(&plugin).await == RequestPluginResult::Continue);
}

/// Changing one site's mode must not leave another site's compiled
/// context pinned to the old mode when the global (first-site) hash is
/// unchanged.
#[tokio::test]
async fn test_site_context_keys_on_its_own_bundle_hash() {
    let (_guard, agent, _dir) = install_test_agent().await;
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    agent
        .rule_cache
        .update_from_site_config(&two_site_varman_config(1, "hash-1"))
        .unwrap();
    assert_eq!(agent.config_hash().as_ref(), "hash-first");
    // Prime example.com's context while it runs monitor.
    assert!(
        run_query_probe_for(&plugin, "example.com").await
            == RequestPluginResult::Continue
    );

    // Only the second site changes. The agent-level hash stays at the
    // first site's bundle, so a global cache key would miss this update.
    agent
        .rule_cache
        .update_from_site_config(&two_site_varman_config(2, "hash-2"))
        .unwrap();
    assert_eq!(agent.config_hash().as_ref(), "hash-first");
    let RequestPluginResult::Respond(resp) =
        run_query_probe_for(&plugin, "example.com").await
    else {
        panic!("expected the mode change to be enforced");
    };
    assert_eq!(http::StatusCode::FORBIDDEN, resp.status);
}

/// Stream inspection is capped by the site mode and the engine: a
/// monitor/legacy site must never close a WebSocket tunnel.
#[tokio::test]
async fn stream_policy_follows_mode_engine_and_site_settings() {
    fn config(
        mode: i32,
        engine_mode: &str,
        enabled: bool,
        observation: bool,
    ) -> proto::SiteConfig {
        // The bundle hash must cover every field the test varies:
        // the cache keys on it, not on the struct contents.
        let hash = format!("hash-{mode}-{engine_mode}-{enabled}-{observation}");
        proto::SiteConfig {
            sites: vec![proto::Site {
                id: "site-1".to_string(),
                name: "example".to_string(),
                domain: "example.com".to_string(),
                alternate_domains: Vec::new(),
                rules: Some(proto::RuleBundle {
                    site_id: "site-1".to_string(),
                    config_hash: hash.clone(),
                    observation_mode: observation,
                    waf: Some(proto::WafConfig {
                        enabled,
                        mode,
                        engine_mode: engine_mode.to_string(),
                        monitor_categories: vec!["rce".to_string()],
                        rule_target_exclusions: vec![
                            proto::RuleTargetExclusions {
                                rule_id: "VARMAN-1001".to_string(),
                                targets: vec!["body".to_string()],
                                path_prefix: "/ws".to_string(),
                            },
                        ],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            config_hash: format!("full-{hash}"),
            updated_at: None,
        }
    }

    let (_guard, agent, _dir) = install_test_agent().await;
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    agent
        .rule_cache
        .update_from_site_config(&config(1, "varman", true, false))
        .unwrap();
    assert!(
        !plugin.stream_policy("example.com", "").enforce,
        "monitor mode must not enforce stream findings"
    );

    agent
        .rule_cache
        .update_from_site_config(&config(2, "legacy", true, false))
        .unwrap();
    assert!(
        !plugin.stream_policy("example.com", "").enforce,
        "legacy engine must not run the Varman stream inspector"
    );

    agent
        .rule_cache
        .update_from_site_config(&config(2, "varman", false, false))
        .unwrap();
    assert!(
        !plugin.stream_policy("example.com", "").enforce,
        "a disabled WAF must not enforce stream findings"
    );

    agent
        .rule_cache
        .update_from_site_config(&config(2, "varman", true, true))
        .unwrap();
    assert!(
        !plugin.stream_policy("example.com", "").enforce,
        "observation mode must not enforce stream findings"
    );

    // `enforce` is a documented alias for `varman`; it must not silently
    // disable stream protection.
    agent
        .rule_cache
        .update_from_site_config(&config(2, "enforce", true, false))
        .unwrap();
    assert!(
        plugin.stream_policy("example.com", "").enforce,
        "the enforce alias must match the request path"
    );

    agent
        .rule_cache
        .update_from_site_config(&config(2, "varman", true, false))
        .unwrap();
    assert!(
        plugin.stream_policy("example.com", "").enforce,
        "block + varman is the only enforcement combination"
    );
    assert!(
        !plugin.stream_policy("missing.example", "").enforce,
        "an unsynced domain must not fall back to the plugin's block mode"
    );

    // The same resolution carries the site's monitor categories and the
    // body-scoped exclusions for the WebSocket request path.
    let policy = plugin.stream_policy("example.com", "/ws");
    assert!(policy.enforce);
    assert_eq!(vec!["rce".to_string()], policy.monitored);
    assert!(policy.excluded_rules.contains("VARMAN-1001"));
    assert!(
        !plugin
            .stream_policy("example.com", "/api")
            .excluded_rules
            .contains("VARMAN-1001"),
        "an exclusion must not leak outside its path prefix"
    );
}

#[test]
fn stream_exclusions_only_apply_to_the_body_target() {
    let exclusions = vec![
        CachePathTargetExclusion {
            rule_id: "VARMAN-1001".to_string(),
            targets: vec!["body".to_string()],
            path_prefix: "/ws".to_string(),
        },
        CachePathTargetExclusion {
            rule_id: "VARMAN-1002".to_string(),
            targets: vec!["path".to_string()],
            path_prefix: "/ws".to_string(),
        },
        CachePathTargetExclusion {
            rule_id: "VARMAN-1003".to_string(),
            targets: vec!["body".to_string()],
            path_prefix: "/api".to_string(),
        },
        CachePathTargetExclusion {
            rule_id: "VARMAN-1004".to_string(),
            targets: vec!["BODY".to_string()],
            path_prefix: String::new(),
        },
    ];
    let excluded = stream_excluded_rules("/ws/socket", &exclusions);
    assert!(excluded.contains("VARMAN-1001"));
    assert!(
        !excluded.contains("VARMAN-1002"),
        "a path-only exclusion says nothing about the tunnel"
    );
    assert!(!excluded.contains("VARMAN-1003"));
    assert!(
        excluded.contains("VARMAN-1004"),
        "an empty prefix is site-wide and targets are case-insensitive"
    );
}

/// A monitor site sees the same low-confidence rule on every matching
/// WebSocket message. Before deduplication one busy connection produced
/// hundreds of rows; now the rule is recorded once per connection.
#[tokio::test]
async fn a_monitor_stream_records_each_rule_once() {
    let (_guard, agent, _dir) = install_test_agent().await;
    while agent.client.pop_log().await.is_some() {}
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    let request_id = "stream-dedupe";
    let finding = StreamFinding::Payload {
        rule_id: "sem.cmd.command_context".to_string(),
        detail: "payload matched".to_string(),
        action: Action::Log,
        score: 5,
    };
    let policy = StreamPolicy::default();
    assert!(!plugin.record_stream_finding(request_id, &finding, &policy));
    assert!(!plugin.record_stream_finding(request_id, &finding, &policy));

    let event = agent.client.pop_log().await.expect("one event");
    assert_eq!("monitor", event.waf_action);
    assert_eq!(5, event.waf_score);
    assert!(
        agent.client.pop_log().await.is_none(),
        "the second finding must not produce another row"
    );
    STREAMS.remove(request_id);
}

/// A paused site answers with a 503 maintenance page (and a Retry-After
/// hint) instead of proxying, while still producing an access log row.
#[tokio::test]
async fn test_paused_site_answers_maintenance_page() {
    let (_guard, agent, _dir) = install_paused_agent().await;
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    let RequestPluginResult::Respond(resp) =
        run_request(&plugin, "203.0.113.7").await
    else {
        panic!("expected the paused site to answer");
    };
    assert_eq!(http::StatusCode::SERVICE_UNAVAILABLE, resp.status);
    let retry_after = resp.headers.as_ref().and_then(|headers| {
        headers
            .iter()
            .find(|(name, _)| name.as_str() == "retry-after")
            .map(|(_, value)| value.to_str().unwrap_or_default().to_string())
    });
    assert_eq!(Some("3600".to_string()), retry_after);

    // The access row ships immediately with the 503; the pause is not a
    // WAF decision, so no security event is queued.
    let entry = agent.client.pop_log().await.unwrap();
    assert_eq!(503, entry.response_status);
    assert_eq!("GET", entry.method);
    // The page the client receives is recorded, headers and body alike.
    assert_eq!(
        Some("text/html; charset=utf-8"),
        entry
            .response_headers
            .get("content-type")
            .map(String::as_str)
    );
    assert_eq!(
        Some("3600"),
        entry
            .response_headers
            .get("retry-after")
            .map(String::as_str)
    );
    let body = entry
        .response_body
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    assert!(body.contains("temporarily paused"), "body: {body}");
    assert_eq!(
        entry.response_body_size,
        body.len() as u64,
        "the recorded size is the body that was sent"
    );
    assert!(!entry.response_body_truncated);
    assert!(agent.client.pop_log().await.is_none());
}

/// A status change carries no bundle-hash change. The cached site context
/// must not keep serving a site the operator just paused.
#[tokio::test]
async fn test_pause_applies_without_a_new_bundle_hash() {
    fn config(status: i32) -> proto::SiteConfig {
        proto::SiteConfig {
            sites: vec![proto::Site {
                id: "site-1".to_string(),
                name: "example".to_string(),
                domain: "example.com".to_string(),
                alternate_domains: Vec::new(),
                status,
                rules: Some(proto::RuleBundle {
                    site_id: "site-1".to_string(),
                    config_hash: "hash-1".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            config_hash: "hash-1".to_string(),
            updated_at: None,
        }
    }

    let (_guard, agent, _dir) = install_test_agent().await;
    agent
        .rule_cache
        .update_from_site_config(&config(0))
        .unwrap();
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    // Prime the per-domain context while the site is active.
    assert!(
        run_request(&plugin, "203.0.113.7").await
            == RequestPluginResult::Continue
    );

    // Same hash, paused status: the context cache stays valid but the
    // live rule cache must win.
    agent
        .rule_cache
        .update_from_site_config(&config(1))
        .unwrap();
    assert_eq!(agent.config_hash().as_ref(), "hash-1");
    let RequestPluginResult::Respond(resp) =
        run_request(&plugin, "203.0.113.7").await
    else {
        panic!("expected the paused site to answer");
    };
    assert_eq!(http::StatusCode::SERVICE_UNAVAILABLE, resp.status);
}

/// A blocked request logs the page the client received, so the dashboard
/// can show what a denial looked like without replaying the request.
#[tokio::test]
async fn test_blocked_response_is_logged_with_its_body() {
    let (_guard, agent, _dir) = install_whitelist_agent().await;
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    let RequestPluginResult::Respond(resp) =
        run_request(&plugin, "203.0.113.7").await
    else {
        panic!("expected the catch-all rule to answer");
    };
    assert_eq!(http::StatusCode::FORBIDDEN, resp.status);

    // The security event ships first; the access entry follows with the
    // page the client received.
    let event = agent.client.pop_log().await.unwrap();
    assert_eq!("block", event.waf_action);
    let entry = agent.client.pop_log().await.unwrap();
    assert_eq!(event.request_id, entry.request_id);
    assert_eq!(403, entry.response_status);
    assert_eq!(
        Some("text/html; charset=utf-8"),
        entry
            .response_headers
            .get("content-type")
            .map(String::as_str)
    );
    let body = entry
        .response_body
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    // The branded block page names the product and the verdict.
    assert!(body.contains("Request Blocked"), "body: {body}");
    assert!(
        body.contains("Protected by <b>VarmanWAF</b>"),
        "body: {body}"
    );
    assert_eq!(entry.response_body_size, body.len() as u64);
    assert!(!entry.response_body_truncated);
}

/// Installs an agent whose only site enforces mTLS, revoking `revoked`
/// and pinning the organization to `organization`.
async fn install_mtls_agent(
    require_client_cert: bool,
    organization: &str,
    revoked: &[&str],
) -> (
    tokio::sync::MutexGuard<'static, ()>,
    Arc<VarmanAgent>,
    tempfile::TempDir,
) {
    let installed = install_test_agent().await;
    // The per-domain context cache is keyed on the agent's config hash:
    // give each posture its own so a test that reinstalls the agent does
    // not reuse the previous context.
    let config_hash = format!(
        "hash-mtls-{require_client_cert}-{organization}-{}",
        revoked.join(",")
    );
    installed
        .1
        .rule_cache
        .update_from_site_config(&proto::SiteConfig {
            sites: vec![proto::Site {
                id: "site-1".to_string(),
                name: "example".to_string(),
                domain: "example.com".to_string(),
                alternate_domains: Vec::new(),
                status: 0,
                rules: Some(proto::RuleBundle {
                    site_id: "site-1".to_string(),
                    config_hash: config_hash.clone(),
                    ssl: Some(proto::SslConfig {
                        enabled: true,
                        mtls_enabled: true,
                        mtls_client_ca: "CA".to_string(),
                        mtls_organization: organization.to_string(),
                        mtls_require_client_cert: require_client_cert,
                        mtls_revoked_fingerprints: revoked
                            .iter()
                            .map(|f| f.to_string())
                            .collect(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            config_hash,
            updated_at: None,
        })
        .unwrap();
    installed
}

/// Builds one request carrying the client certificate facts the TLS layer
/// would have put on the connection.
async fn run_request_with_cert(
    plugin: &WafPlugin,
    digest: Option<&str>,
    organization: Option<&str>,
) -> RequestPluginResult {
    let input_header = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mock_io = Builder::new().read(input_header.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(mock_io));
    session.read_request().await.unwrap();
    let mut ctx = Ctx::default();
    ctx.conn.client_ip = Some("203.0.113.7".to_string());
    ctx.conn.tls_peer_cert_digest = digest.map(str::to_string);
    ctx.conn.tls_peer_organization = organization.map(str::to_string);
    plugin
        .handle_request(PluginStep::EarlyRequest, &mut session, &mut ctx)
        .await
        .unwrap()
}

/// A site that requires client certificates answers 403 without one —
/// and without touching the WAF event stream — while a site that only
/// trusts them still serves the request.
#[tokio::test]
async fn test_mtls_requires_a_client_certificate() {
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    {
        let (_guard, agent, _dir) = install_mtls_agent(true, "", &[]).await;
        let RequestPluginResult::Respond(resp) =
            run_request_with_cert(&plugin, None, None).await
        else {
            panic!("expected the missing certificate to be refused");
        };
        assert_eq!(http::StatusCode::FORBIDDEN, resp.status);
        let entry = agent.client.pop_log().await.unwrap();
        assert_eq!(403, entry.response_status);
        // A denial, not a WAF verdict: nothing is queued as a security
        // event.
        assert!(agent.client.pop_log().await.is_none());
    }

    let (_guard, _agent, _dir) = install_mtls_agent(false, "", &[]).await;
    assert!(
        run_request_with_cert(&plugin, None, None).await
            == RequestPluginResult::Continue
    );
}

/// Revoked certificates and certificates issued for another organization
/// are refused even though their chain verified at the TLS layer.
#[tokio::test]
async fn test_mtls_refuses_revoked_and_foreign_certificates() {
    let revoked = "0a1b2c3d";
    let (_guard, _agent, _dir) =
        install_mtls_agent(true, "Acme", &[revoked]).await;
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    // The certificate this site trusts passes.
    assert!(
        run_request_with_cert(&plugin, Some("00ff"), Some("Acme")).await
            == RequestPluginResult::Continue
    );

    let RequestPluginResult::Respond(resp) =
        run_request_with_cert(&plugin, Some(revoked), Some("Acme")).await
    else {
        panic!("expected the revoked certificate to be refused");
    };
    assert_eq!(http::StatusCode::FORBIDDEN, resp.status);

    let RequestPluginResult::Respond(resp) =
        run_request_with_cert(&plugin, Some("00ff"), Some("Other")).await
    else {
        panic!("expected the foreign certificate to be refused");
    };
    assert_eq!(http::StatusCode::FORBIDDEN, resp.status);

    let RequestPluginResult::Respond(_) =
        run_request_with_cert(&plugin, Some("00ff"), None).await
    else {
        panic!("expected a certificate without an organization to fail");
    };
}

/// Posture of a basic auth test agent.
struct BasicAuthPosture {
    /// The site-wide gate is on: every request must authenticate.
    site_wide: bool,
    /// One enabled IP rule: the matched network and its action
    /// (3 = allow, 4 = basic auth).
    rule: Option<(&'static str, i32)>,
    hide_credentials: bool,
}

/// Installs an agent whose only site carries `credentials` and the given
/// basic auth posture.
async fn install_basic_auth_agent(
    credentials: &[(&str, &str)],
    posture: BasicAuthPosture,
) -> (
    tokio::sync::MutexGuard<'static, ()>,
    Arc<VarmanAgent>,
    tempfile::TempDir,
) {
    let installed = install_test_agent().await;
    let ip_rules: Vec<proto::IpAccessRule> = posture
        .rule
        .iter()
        .map(|(network, action)| proto::IpAccessRule {
            id: "rule-1".to_string(),
            name: "example".to_string(),
            ip_ranges: vec![(*network).to_string()],
            action: *action,
            note: String::new(),
            enabled: true,
        })
        .collect();
    let config_hash = format!(
        "hash-basic-auth-{}-{:?}-{}",
        posture.site_wide, posture.rule, posture.hide_credentials
    );
    installed
        .1
        .rule_cache
        .update_from_site_config(&proto::SiteConfig {
            sites: vec![proto::Site {
                id: "site-1".to_string(),
                name: "example".to_string(),
                domain: "example.com".to_string(),
                alternate_domains: Vec::new(),
                status: 0,
                rules: Some(proto::RuleBundle {
                    site_id: "site-1".to_string(),
                    config_hash: config_hash.clone(),
                    ip_access_rules: ip_rules,
                    basic_auth: Some(proto::BasicAuthConfig {
                        enabled: posture.site_wide,
                        realm: "Restricted".to_string(),
                        credentials: credentials
                            .iter()
                            .map(|(username, password)| {
                                proto::BasicAuthCredential {
                                    username: (*username).to_string(),
                                    authorization: base64_encode(format!(
                                        "{username}:{password}"
                                    )),
                                }
                            })
                            .collect(),
                        delay_seconds: 0,
                        hide_credentials: posture.hide_credentials,
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            config_hash,
            updated_at: None,
        })
        .unwrap();
    installed
}

/// Runs one request carrying an optional `Authorization` header, and
/// reports whether the header was still there when the plugin finished.
async fn run_request_with_auth(
    plugin: &WafPlugin,
    client_ip: &str,
    authorization: Option<&str>,
) -> (RequestPluginResult, bool) {
    let auth_header = authorization
        .map(|value| format!("Authorization: {value}\r\n"))
        .unwrap_or_default();
    let input_header =
        format!("GET / HTTP/1.1\r\nHost: example.com\r\n{auth_header}\r\n");
    let mock_io = Builder::new().read(input_header.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(mock_io));
    session.read_request().await.unwrap();
    let mut ctx = Ctx::default();
    ctx.conn.client_ip = Some(client_ip.to_string());
    let result = plugin
        .handle_request(PluginStep::EarlyRequest, &mut session, &mut ctx)
        .await
        .unwrap();
    let kept = session
        .req_header()
        .headers
        .contains_key(http::header::AUTHORIZATION);
    (result, kept)
}

/// The site-wide gate answers 401 with a challenge until the client
/// presents a stored credential, and the attempt lands in the access log
/// as a response the plugin generated itself.
#[tokio::test]
async fn test_basic_auth_gate_challenges_until_credentials_match() {
    let (_guard, agent, _dir) = install_basic_auth_agent(
        &[("alice", "hunter2")],
        BasicAuthPosture {
            site_wide: true,
            rule: None,
            hide_credentials: false,
        },
    )
    .await;
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    let (result, _) = run_request_with_auth(&plugin, "203.0.113.7", None).await;
    let RequestPluginResult::Respond(resp) = result else {
        panic!("expected the gate to challenge the request");
    };
    assert_eq!(http::StatusCode::UNAUTHORIZED, resp.status);
    let challenge = resp.headers.as_ref().and_then(|headers| {
        headers
            .iter()
            .find(|(name, _)| name == http::header::WWW_AUTHENTICATE)
            .and_then(|(_, value)| value.to_str().ok())
    });
    assert_eq!(Some("Basic realm=\"Restricted\""), challenge);
    let entry = agent.client.pop_log().await.unwrap();
    assert_eq!(401, entry.response_status);
    // A denial, not a WAF verdict: nothing is queued as a security event.
    assert!(agent.client.pop_log().await.is_none());

    let wrong = format!("Basic {}", base64_encode("alice:nope"));
    let (result, _) =
        run_request_with_auth(&plugin, "203.0.113.7", Some(&wrong)).await;
    let RequestPluginResult::Respond(resp) = result else {
        panic!("expected the wrong password to be refused");
    };
    assert_eq!(http::StatusCode::UNAUTHORIZED, resp.status);

    let right = format!("Basic {}", base64_encode("alice:hunter2"));
    let (result, kept) =
        run_request_with_auth(&plugin, "203.0.113.7", Some(&right)).await;
    assert!(result == RequestPluginResult::Continue);
    // The gate keeps the header unless hiding it was configured.
    assert!(kept);
}

/// `hide_credentials` strips the `Authorization` header once the request
/// is authenticated.
#[tokio::test]
async fn test_basic_auth_hide_credentials_strips_the_header() {
    let (_guard, _agent, _dir) = install_basic_auth_agent(
        &[("alice", "hunter2")],
        BasicAuthPosture {
            site_wide: true,
            rule: None,
            hide_credentials: true,
        },
    )
    .await;
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    let right = format!("Basic {}", base64_encode("alice:hunter2"));
    let (result, kept) =
        run_request_with_auth(&plugin, "203.0.113.7", Some(&right)).await;
    assert!(result == RequestPluginResult::Continue);
    assert!(!kept);
}

/// An IP rule whose action is `basic_auth` gates only the clients it
/// matches — the site-wide switch stays off — and lets them continue
/// once authenticated.
#[tokio::test]
async fn test_basic_auth_rule_action_gates_matching_clients() {
    let (_guard, _agent, _dir) = install_basic_auth_agent(
        &[("alice", "hunter2")],
        BasicAuthPosture {
            site_wide: false,
            rule: Some(("10.1.1.0/24", 4)),
            hide_credentials: false,
        },
    )
    .await;
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    // A client the rule does not match passes untouched.
    let (result, _) = run_request_with_auth(&plugin, "203.0.113.7", None).await;
    assert!(result == RequestPluginResult::Continue);

    let (result, _) = run_request_with_auth(&plugin, "10.1.1.1", None).await;
    let RequestPluginResult::Respond(resp) = result else {
        panic!("expected the rule to require authentication");
    };
    assert_eq!(http::StatusCode::UNAUTHORIZED, resp.status);

    let right = format!("Basic {}", base64_encode("alice:hunter2"));
    let (result, _) =
        run_request_with_auth(&plugin, "10.1.1.1", Some(&right)).await;
    assert!(result == RequestPluginResult::Continue);
}

/// A rule that requires authentication while the site stores no
/// credential refuses the matched client outright.
#[tokio::test]
async fn test_basic_auth_rule_without_credentials_refuses() {
    let (_guard, _agent, _dir) = install_basic_auth_agent(
        &[],
        BasicAuthPosture {
            site_wide: false,
            rule: Some(("10.1.1.0/24", 4)),
            hide_credentials: false,
        },
    )
    .await;
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    let (result, _) = run_request_with_auth(&plugin, "10.1.1.1", None).await;
    let RequestPluginResult::Respond(resp) = result else {
        panic!("expected a refusal without credentials to verify");
    };
    assert_eq!(http::StatusCode::UNAUTHORIZED, resp.status);
}

/// An `allow` rule exempts its clients from the site-wide gate, so a
/// monitoring range can keep polling a protected site.
#[tokio::test]
async fn test_ip_allow_rule_exempts_the_site_gate() {
    let (_guard, _agent, _dir) = install_basic_auth_agent(
        &[("alice", "hunter2")],
        BasicAuthPosture {
            site_wide: true,
            rule: Some(("10.1.1.0/24", 3)),
            hide_credentials: false,
        },
    )
    .await;
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    let (result, _) = run_request_with_auth(&plugin, "10.1.1.1", None).await;
    assert!(result == RequestPluginResult::Continue);

    let (result, _) = run_request_with_auth(&plugin, "203.0.113.7", None).await;
    let RequestPluginResult::Respond(resp) = result else {
        panic!("expected the gate to challenge an unlisted client");
    };
    assert_eq!(http::StatusCode::UNAUTHORIZED, resp.status);
}

/// Builds one request against the plugin from `client_ip`.
async fn run_request(
    plugin: &WafPlugin,
    client_ip: &str,
) -> RequestPluginResult {
    let input_header = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mock_io = Builder::new().read(input_header.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(mock_io));
    session.read_request().await.unwrap();
    let mut ctx = Ctx::default();
    ctx.conn.client_ip = Some(client_ip.to_string());
    plugin
        .handle_request(PluginStep::EarlyRequest, &mut session, &mut ctx)
        .await
        .unwrap()
}

/// An allow rule above a catch-all block rule yields a whitelist: the
/// listed IP passes, everything else is answered with 403.
#[tokio::test]
async fn test_ip_access_rules_whitelist() {
    let (_guard, _agent, _dir) = install_whitelist_agent().await;
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    assert!(
        run_request(&plugin, "10.1.1.1").await == RequestPluginResult::Continue
    );

    let RequestPluginResult::Respond(resp) =
        run_request(&plugin, "203.0.113.7").await
    else {
        panic!("expected the catch-all rule to answer");
    };
    assert_eq!(http::StatusCode::FORBIDDEN, resp.status);
}

/// A matching block rule is enforced even when the site has no WAF engine
/// of its own: access restrictions are not gated on the managed rules.
#[tokio::test]
async fn test_ip_access_rule_applies_with_waf_disabled() {
    let (_guard, agent, _dir) = install_test_agent().await;
    agent
        .rule_cache
        .update_from_site_config(&proto::SiteConfig {
            sites: vec![proto::Site {
                id: "site-1".to_string(),
                name: "example".to_string(),
                domain: "example.com".to_string(),
                alternate_domains: Vec::new(),
                status: 0,
                rules: Some(proto::RuleBundle {
                    site_id: "site-1".to_string(),
                    config_hash: "hash-1".to_string(),
                    waf: Some(proto::WafConfig {
                        enabled: false,
                        ..Default::default()
                    }),
                    ip_access_rules: vec![proto::IpAccessRule {
                        id: "block-crawlers".to_string(),
                        name: "block crawlers".to_string(),
                        ip_ranges: vec!["192.0.2.0/24".to_string()],
                        action: proto::IpAccessAction::IpAccessChallenge as i32,
                        note: String::new(),
                        enabled: true,
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            }],
            config_hash: "hash-1".to_string(),
            updated_at: None,
        })
        .unwrap();
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    let RequestPluginResult::Respond(resp) =
        run_request(&plugin, "192.0.2.9").await
    else {
        panic!("expected the challenge rule to answer");
    };
    assert_eq!(http::StatusCode::SERVICE_UNAVAILABLE, resp.status);

    assert!(
        run_request(&plugin, "198.51.100.4").await
            == RequestPluginResult::Continue
    );
}

/// A path-scoped exclusion from a package suppresses its rule under the
/// prefix only, through the whole data plane (bundle -> cache -> engine).
#[tokio::test]
async fn test_exclusion_package_suppresses_under_its_prefix() {
    let (_guard, agent, _dir) = install_test_agent().await;
    agent
        .rule_cache
        .update_from_site_config(&proto::SiteConfig {
            sites: vec![proto::Site {
                id: "site-1".to_string(),
                name: "example".to_string(),
                domain: "example.com".to_string(),
                alternate_domains: Vec::new(),
                status: 0,
                rules: Some(proto::RuleBundle {
                    site_id: "site-1".to_string(),
                    config_hash: "hash-1".to_string(),
                    waf: Some(proto::WafConfig {
                        enabled: true,
                        mode: proto::WafMode::Block as i32,
                        // The native engine enforces; the pipeline
                        // defaults to shadow when no mode is selected.
                        engine_mode: "varman".to_string(),
                        rule_target_exclusions: vec![
                            proto::RuleTargetExclusions {
                                rule_id: "VARMAN-1020".to_string(),
                                targets: vec!["path".to_string()],
                                path_prefix: "/.git".to_string(),
                            },
                        ],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            config_hash: "hash-1".to_string(),
            updated_at: None,
        })
        .unwrap();
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    let probe = |path: &str| {
        let header =
            format!("GET {path} HTTP/1.1\r\nHost: example.com\r\n\r\n");
        let plugin = &plugin;
        async move {
            let mock_io = Builder::new().read(header.as_bytes()).build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            let mut ctx = Ctx::default();
            ctx.conn.client_ip = Some("203.0.113.7".to_string());
            plugin
                .handle_request(
                    PluginStep::EarlyRequest,
                    &mut session,
                    &mut ctx,
                )
                .await
                .unwrap()
        }
    };

    let inside = probe("/.git/config").await;
    eprintln!("inside result: {inside:?}");
    assert_eq!(
        RequestPluginResult::Continue,
        inside,
        "the exclusion must suppress the dotfile rule under /.git"
    );
    let outside = probe("/.svn/config").await;
    eprintln!("outside result: {outside:?}");
    let RequestPluginResult::Respond(resp) = outside else {
        panic!("expected the dotfile rule to answer outside the prefix");
    };
    assert_eq!(http::StatusCode::FORBIDDEN, resp.status);
}

/// A geo policy denies a client inside the synced country ranges, and
/// the denial carries the display country on the emitted security event.
#[tokio::test]
async fn test_geo_rule_blocks_listed_country() {
    pingap_plugin::geo::warm_geoip();
    let country = lookup_country_addr("8.8.8.8".parse().unwrap())
        .expect("embedded db resolves 8.8.8.8 for display");

    let (_guard, agent, _dir) = install_test_agent().await;
    agent
        .rule_cache
        .update_from_site_config(&proto::SiteConfig {
            sites: vec![proto::Site {
                id: "site-1".to_string(),
                name: "example".to_string(),
                domain: "example.com".to_string(),
                alternate_domains: Vec::new(),
                status: 0,
                rules: Some(proto::RuleBundle {
                    site_id: "site-1".to_string(),
                    config_hash: "hash-1".to_string(),
                    geo: Some(proto::GeoConfig {
                        enabled: true,
                        blocked_countries: vec![country.clone()],
                        country_ranges: vec!["8.8.8.0/24".to_string()],
                        action: proto::WafAction::Block as i32,
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            config_hash: "hash-1".to_string(),
            updated_at: None,
        })
        .unwrap();
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    let RequestPluginResult::Respond(resp) =
        run_request(&plugin, "8.8.8.8").await
    else {
        panic!("expected the geo rule to answer");
    };
    assert_eq!(http::StatusCode::FORBIDDEN, resp.status);

    let event = agent.client.pop_log().await.unwrap();
    assert_eq!(country, event.country_code);
    assert_eq!("geo_restriction", event.waf_rule_id);

    // An address outside the synced ranges is not touched.
    assert_eq!(
        RequestPluginResult::Continue,
        run_request(&plugin, "1.1.1.1").await
    );
}

/// The geo policy's monitor action records the decision without
/// enforcing: the request continues and the event carries `monitor`.
#[tokio::test]
async fn test_geo_rule_monitor_action_records_without_blocking() {
    pingap_plugin::geo::warm_geoip();
    let country = lookup_country_addr("8.8.8.8".parse().unwrap())
        .expect("embedded db resolves 8.8.8.8 for display");

    let (_guard, agent, _dir) = install_test_agent().await;
    agent
        .rule_cache
        .update_from_site_config(&proto::SiteConfig {
            sites: vec![proto::Site {
                id: "site-1".to_string(),
                name: "example".to_string(),
                domain: "example.com".to_string(),
                alternate_domains: Vec::new(),
                status: 0,
                rules: Some(proto::RuleBundle {
                    site_id: "site-1".to_string(),
                    config_hash: "hash-1".to_string(),
                    geo: Some(proto::GeoConfig {
                        enabled: true,
                        blocked_countries: vec![country.clone()],
                        country_ranges: vec!["8.8.8.0/24".to_string()],
                        action: proto::WafAction::Log as i32,
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            config_hash: "hash-1".to_string(),
            updated_at: None,
        })
        .unwrap();
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    assert_eq!(
        RequestPluginResult::Continue,
        run_request(&plugin, "8.8.8.8").await
    );

    let event = agent.client.pop_log().await.unwrap();
    assert_eq!(country, event.country_code);
    assert_eq!("geo_restriction", event.waf_rule_id);
    assert_eq!("monitor", event.waf_action);
}

/// Whitelist mode: the synced ranges are the allowed set; everything
/// outside them is denied.
#[tokio::test]
async fn test_geo_allow_list_denies_outside_ranges() {
    let (_guard, agent, _dir) = install_test_agent().await;
    agent
        .rule_cache
        .update_from_site_config(&proto::SiteConfig {
            sites: vec![proto::Site {
                id: "site-1".to_string(),
                name: "example".to_string(),
                domain: "example.com".to_string(),
                alternate_domains: Vec::new(),
                status: 0,
                rules: Some(proto::RuleBundle {
                    site_id: "site-1".to_string(),
                    config_hash: "hash-1".to_string(),
                    geo: Some(proto::GeoConfig {
                        enabled: true,
                        allowed_countries: vec!["US".to_string()],
                        country_ranges: vec!["8.8.8.0/24".to_string()],
                        action: proto::WafAction::Block as i32,
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            config_hash: "hash-1".to_string(),
            updated_at: None,
        })
        .unwrap();
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    assert_eq!(
        RequestPluginResult::Continue,
        run_request(&plugin, "8.8.8.8").await
    );
    let RequestPluginResult::Respond(resp) =
        run_request(&plugin, "1.1.1.1").await
    else {
        panic!("expected the allow list to deny outside its ranges");
    };
    assert_eq!(http::StatusCode::FORBIDDEN, resp.status);
}

/// `block_unknown` with range data means "outside the listed countries":
/// addresses matching no listed country range are denied too.
#[tokio::test]
async fn test_geo_block_unknown_denies_unlisted_addresses() {
    let (_guard, agent, _dir) = install_test_agent().await;
    agent
        .rule_cache
        .update_from_site_config(&proto::SiteConfig {
            sites: vec![proto::Site {
                id: "site-1".to_string(),
                name: "example".to_string(),
                domain: "example.com".to_string(),
                alternate_domains: Vec::new(),
                status: 0,
                rules: Some(proto::RuleBundle {
                    site_id: "site-1".to_string(),
                    config_hash: "hash-1".to_string(),
                    geo: Some(proto::GeoConfig {
                        enabled: true,
                        blocked_countries: vec!["US".to_string()],
                        country_ranges: vec!["8.8.8.0/24".to_string()],
                        block_unknown: true,
                        action: proto::WafAction::Block as i32,
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            config_hash: "hash-1".to_string(),
            updated_at: None,
        })
        .unwrap();
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    for ip in ["1.1.1.1", "8.8.8.8"] {
        let RequestPluginResult::Respond(resp) = run_request(&plugin, ip).await
        else {
            panic!("expected {ip} to be denied");
        };
        assert_eq!(http::StatusCode::FORBIDDEN, resp.status);
    }
}

/// Blocked ASNs are enforced through their synced ranges.
#[tokio::test]
async fn test_geo_asn_ranges_deny() {
    let (_guard, agent, _dir) = install_test_agent().await;
    agent
        .rule_cache
        .update_from_site_config(&proto::SiteConfig {
            sites: vec![proto::Site {
                id: "site-1".to_string(),
                name: "example".to_string(),
                domain: "example.com".to_string(),
                alternate_domains: Vec::new(),
                status: 0,
                rules: Some(proto::RuleBundle {
                    site_id: "site-1".to_string(),
                    config_hash: "hash-1".to_string(),
                    geo: Some(proto::GeoConfig {
                        enabled: true,
                        blocked_asns: vec!["13335".to_string()],
                        asn_ranges: vec!["1.1.1.0/24".to_string()],
                        action: proto::WafAction::Block as i32,
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            config_hash: "hash-1".to_string(),
            updated_at: None,
        })
        .unwrap();
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    let RequestPluginResult::Respond(resp) =
        run_request(&plugin, "1.1.1.1").await
    else {
        panic!("expected the ASN range to deny");
    };
    assert_eq!(http::StatusCode::FORBIDDEN, resp.status);
    assert_eq!(
        RequestPluginResult::Continue,
        run_request(&plugin, "8.8.8.8").await
    );
}

/// A listed key without synced data does not deny anything - it is
/// surfaced by the control plane instead of guessing.
#[test]
fn test_geo_missing_keys_do_not_deny() {
    let rule = GeoRule::build(&CacheGeoConfig {
        enabled: true,
        blocked_countries: vec!["US".to_string()],
        allowed_countries: Vec::new(),
        blocked_asns: Vec::new(),
        block_unknown: false,
        action: CacheWafAction::Block,
        country_ranges: Vec::new(),
        asn_ranges: Vec::new(),
        missing_keys: vec!["US".to_string()],
    });
    // The compiled rule carries no ranges and never matches; the
    // missing key is a control-plane surface, not a denial.
    let addr: std::net::IpAddr = "8.8.8.8".parse().unwrap();
    assert!(rule.enabled);
    assert!(!rule.country_ranges.is_match_addr(&addr));
    assert!(!rule.asn_ranges.is_match_addr(&addr));
}

#[tokio::test]
async fn test_access_log_pipeline() {
    let (_guard, agent, _dir) = install_test_agent().await;
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    // ── Blocked request: security event + immediate access entry ──
    let input_header = "GET /api/users?id=1'%20OR%201=1%20-- HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mock_io = Builder::new().read(input_header.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(mock_io));
    session.read_request().await.unwrap();
    let mut ctx = Ctx::default();
    let result = plugin
        .handle_request(PluginStep::EarlyRequest, &mut session, &mut ctx)
        .await
        .unwrap();
    let RequestPluginResult::Respond(resp) = result else {
        panic!("expected a block response");
    };
    assert_eq!(http::StatusCode::FORBIDDEN, resp.status);
    assert_eq!(1, agent.metrics.requests_total());
    assert_eq!(1, agent.metrics.blocked_requests_total());

    // First shipped entry is the security event with the real scheme,
    // protocol and status (no more hardcoded https/HTTP/1.1/403 trio).
    let event = agent.client.pop_log().await.unwrap();
    assert_eq!("block", event.waf_action);
    assert_eq!(403, event.response_status);
    assert_eq!("http", event.scheme);
    assert_eq!("HTTP/1.1", event.protocol);

    // Second is the access entry, emitted at request time because a
    // Respond result never reaches handle_response.
    let blocked_id = event.request_id.clone();
    let entry = agent.client.pop_log().await.unwrap();
    assert_eq!(blocked_id, entry.request_id);
    assert_eq!(403, entry.response_status);
    assert_eq!("GET", entry.method);
    assert_eq!("/api/users", entry.path);
    assert_eq!("example.com", entry.host);
    assert_eq!("http", entry.scheme);
    assert_eq!("HTTP/1.1", entry.protocol);

    // The pending entry was consumed: handle_response must not re-send.
    let mut resp = ResponseHeader::build(200, None).unwrap();
    plugin
        .handle_response(&mut session, &mut ctx, &mut resp)
        .await
        .unwrap();
    assert!(agent.client.pop_log().await.is_none());

    // ── Passed request: metrics counted, access logged at response ──
    // A distinct client IP: the blocked request above auto-blocked its
    // own client at the edge, and this leg must stay reachable.
    let input_header =
        "GET /api/users?page=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mock_io = Builder::new().read(input_header.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(mock_io));
    session.read_request().await.unwrap();
    let mut ctx = Ctx::default();
    ctx.conn.client_ip = Some("203.0.113.21".to_string());
    let result = plugin
        .handle_request(PluginStep::EarlyRequest, &mut session, &mut ctx)
        .await
        .unwrap();
    assert!(result == RequestPluginResult::Continue);
    assert_eq!(2, agent.metrics.requests_total());
    assert_eq!(1, agent.metrics.blocked_requests_total());

    // Nothing ships until the response arrives.
    assert!(agent.client.pop_log().await.is_none());

    let request_id = ctx.state.request_id.clone().unwrap();
    let mut resp = ResponseHeader::build(200, None).unwrap();
    plugin
        .handle_response(&mut session, &mut ctx, &mut resp)
        .await
        .unwrap();
    // A capturable payload holds the entry back until the body ends.
    assert!(agent.client.pop_log().await.is_none());
    plugin
        .handle_response_body(
            &mut session,
            &mut ctx,
            &mut Some(bytes::Bytes::from_static(b"page one")),
            true,
        )
        .unwrap();
    let entry = agent.client.pop_log().await.unwrap();
    assert_eq!(request_id, entry.request_id);
    assert_eq!(200, entry.response_status);
    assert_eq!("page=1", entry.query_string);
    assert_eq!(Some(b"page one".to_vec()), entry.response_body);
    // Consumed exactly once.
    assert!(agent.client.pop_log().await.is_none());
}

#[test]
fn cap_headers_limits_size_and_count() {
    let headers: Vec<(String, String)> = (0..100)
        .map(|i| (format!("x-header-{i:03}"), format!("value-{i}")))
        .collect();
    let capped =
        cap_headers(headers.iter().map(|(n, v)| (n.clone(), v.as_str())));
    assert_eq!(MAX_LOG_HEADERS, capped.len());

    let huge: Vec<(String, String)> =
        vec![("x-big".to_string(), "a".repeat(MAX_LOG_HEADERS_BYTES))];
    let capped = cap_headers(huge.iter().map(|(n, v)| (n.clone(), v.as_str())));
    assert!(capped.is_empty());

    let mut big = vec![("x-ok".to_string(), "v".to_string())];
    big.push(("x-big".to_string(), "b".repeat(MAX_LOG_HEADERS_BYTES)));
    let capped = cap_headers(big.iter().map(|(n, v)| (n.clone(), v.as_str())));
    assert_eq!(1, capped.len());
}

#[test]
fn cap_headers_keeps_credentials_verbatim() {
    // Cookies and authorization values must survive: incident response
    // replays the captured request, so the log keeps them.
    let headers = [
        ("Authorization".to_string(), "Bearer tok".to_string()),
        ("cookie".to_string(), "sid=secret".to_string()),
        ("Proxy-Authorization".to_string(), "Basic xyz".to_string()),
    ];
    let capped =
        cap_headers(headers.iter().map(|(n, v)| (n.clone(), v.as_str())));
    let value = |name: &str| {
        capped
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .unwrap()
    };
    assert_eq!("Bearer tok", value("Authorization"));
    assert_eq!("sid=secret", value("cookie"));
    assert_eq!("Basic xyz", value("Proxy-Authorization"));
}

#[test]
fn log_body_prefix_keeps_configured_prefix() {
    // A body of exactly the cap arrives complete.
    let mut prefix = LogBodyPrefix::new(1024);
    prefix.absorb(&[b'a'; 1024]);
    let (body, size, truncated) = prefix.finish();
    assert_eq!(1024, body.unwrap().len());
    assert_eq!(1024, size);
    assert!(!truncated);

    // Anything longer is cut to the cap and flagged; the reported size
    // still counts every byte read.
    let mut prefix = LogBodyPrefix::new(1024);
    prefix.absorb(&[b'a'; 1024]);
    prefix.absorb(b"overflow");
    let (body, size, truncated) = prefix.finish();
    assert_eq!(1024, body.unwrap().len());
    assert_eq!(1024 + 8, size);
    assert!(truncated);

    // An interrupted read marks even a small prefix as partial.
    let mut prefix = LogBodyPrefix::new(1024);
    prefix.absorb(b"partial");
    prefix.interrupted();
    let (body, _, truncated) = prefix.finish();
    assert_eq!(b"partial".to_vec(), body.unwrap());
    assert!(truncated);

    // No body at all.
    let (body, size, truncated) = LogBodyPrefix::new(1024).finish();
    assert!(body.is_none());
    assert_eq!(0, size);
    assert!(!truncated);

    // Capture disabled: nothing kept, size still counted when the bytes
    // were read for another reason.
    let mut prefix = LogBodyPrefix::new(0);
    prefix.absorb(b"ignored");
    let (body, size, truncated) = prefix.finish();
    assert!(body.is_none());
    assert_eq!(7, size);
    assert!(!truncated);
}

#[test]
fn response_capture_skips_bodiless_and_binary_payloads() {
    let build = |status: u16, headers: &[(&str, &str)]| {
        let mut response = ResponseHeader::build(status, None).unwrap();
        for (name, value) in headers {
            response.insert_header(name.to_string(), *value).unwrap();
        }
        response
    };

    // Textual payloads are captured.
    assert!(should_capture_response_body(
        "GET",
        200,
        &build(200, &[("content-type", "text/html; charset=utf-8")])
    ));
    // Unknown payload: best effort.
    assert!(should_capture_response_body("GET", 200, &build(200, &[])));

    // HEAD and bodyless statuses never stream a body.
    assert!(!should_capture_response_body(
        "HEAD",
        200,
        &build(200, &[("content-type", "text/html")])
    ));
    assert!(!should_capture_response_body("GET", 204, &build(204, &[])));
    assert!(!should_capture_response_body("GET", 304, &build(304, &[])));

    // Compressed payloads are not replayable text.
    assert!(!should_capture_response_body(
        "GET",
        200,
        &build(200, &[("content-encoding", "gzip")])
    ));
    // Binary payloads are not worth keeping.
    assert!(!should_capture_response_body(
        "GET",
        200,
        &build(200, &[("content-type", "image/png")])
    ));
    assert!(!should_capture_response_body(
        "GET",
        200,
        &build(200, &[("content-type", "application/octet-stream")])
    ));
    // An explicitly empty body needs no capture.
    assert!(!should_capture_response_body(
        "GET",
        200,
        &build(200, &[("content-length", "0")])
    ));
}

#[tokio::test]
async fn test_access_log_captures_request_detail() {
    let (_guard, agent, _dir) = install_test_agent().await;
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    let body = "username=admin&password=secret";
    let input = format!(
        "POST /login HTTP/1.1\r\nHost: example.com\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let mock_io = Builder::new().read(input.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(mock_io));
    session.read_request().await.unwrap();
    let mut ctx = Ctx::default();
    let result = plugin
        .handle_request(PluginStep::EarlyRequest, &mut session, &mut ctx)
        .await
        .unwrap();
    assert!(result == RequestPluginResult::Continue);

    // The access entry only ships once the response arrives.
    assert!(agent.client.pop_log().await.is_none());
    let mut resp = ResponseHeader::build(200, None).unwrap();
    resp.insert_header("content-type", "text/plain; charset=utf-8")
        .unwrap();
    plugin
        .handle_response(&mut session, &mut ctx, &mut resp)
        .await
        .unwrap();
    assert!(agent.client.pop_log().await.is_none());
    plugin
        .handle_response_body(
            &mut session,
            &mut ctx,
            &mut Some(bytes::Bytes::from_static(b"welcome back")),
            true,
        )
        .unwrap();
    let entry = agent.client.pop_log().await.unwrap();

    assert_eq!(
        body.as_bytes(),
        entry.request_body.as_deref().unwrap_or(&[])
    );
    assert!(!entry.request_body_truncated);
    assert_eq!(body.len() as u64, entry.request_body_size);
    assert_eq!(
        Some("example.com"),
        entry.request_headers.get("host").map(String::as_str)
    );
    assert_eq!(
        Some("application/x-www-form-urlencoded"),
        entry
            .request_headers
            .get("content-type")
            .map(String::as_str)
    );
    // The response side is captured alongside the request.
    assert_eq!(Some(b"welcome back".to_vec()), entry.response_body);
    assert_eq!(12, entry.response_body_size);
    assert!(!entry.response_body_truncated);
    assert_eq!(
        Some("text/plain; charset=utf-8"),
        entry
            .response_headers
            .iter()
            .find(|(name, _)| *name == "content-type")
            .map(|(_, value)| value.as_str())
    );
}

/// Builds one request with an explicit user agent header.
async fn run_request_with_ua(
    plugin: &WafPlugin,
    client_ip: &str,
    user_agent: &str,
) -> RequestPluginResult {
    let input_header = format!(
        "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: {user_agent}\r\n\r\n"
    );
    let mock_io = Builder::new().read(input_header.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(mock_io));
    session.read_request().await.unwrap();
    let mut ctx = Ctx::default();
    ctx.conn.client_ip = Some(client_ip.to_string());
    plugin
        .handle_request(PluginStep::EarlyRequest, &mut session, &mut ctx)
        .await
        .unwrap()
}

/// Installs an agent whose site has bot protection enabled with the given
/// action and a `Googlebot` whitelist entry, and no WAF engine.
async fn install_bot_agent(
    action: proto::WafAction,
) -> (
    tokio::sync::MutexGuard<'static, ()>,
    Arc<VarmanAgent>,
    tempfile::TempDir,
) {
    let installed = install_test_agent().await;
    installed
        .1
        .rule_cache
        .update_from_site_config(&proto::SiteConfig {
            sites: vec![proto::Site {
                id: "site-1".to_string(),
                name: "example".to_string(),
                domain: "example.com".to_string(),
                alternate_domains: Vec::new(),
                status: 0,
                rules: Some(proto::RuleBundle {
                    site_id: "site-1".to_string(),
                    config_hash: "hash-1".to_string(),
                    waf: Some(proto::WafConfig {
                        enabled: false,
                        ..Default::default()
                    }),
                    bot_protection: Some(proto::BotProtectionConfig {
                        enabled: true,
                        action: action as i32,
                        known_bots_whitelist: vec!["Googlebot".to_string()],
                        js_detection: false,
                        tls_fingerprint: false,
                        behavioral_analysis: false,
                        ip_verification_enabled: false,
                        dns_verification_enabled: false,
                        verified_bot_ranges: Vec::new(),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            config_hash: "hash-1".to_string(),
            updated_at: None,
        })
        .unwrap();
    installed
}

#[test]
fn bot_js_detection_requires_browser_headers() {
    let policy = BotPolicy::build(&CacheBotProtection {
        enabled: true,
        action: CacheWafAction::Block,
        known_bots_whitelist: vec!["Googlebot".to_string()],
        js_detection: true,
        tls_fingerprint: false,
        behavioral_analysis: false,
        dns_verification_enabled: false,
        verified_bot_ranges: Vec::new(),
    });
    let browser = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36";

    // Browser headers present: a real browser passes.
    assert!(matches!(
        policy.evaluate_with_hints(browser, true),
        BotDecision::Pass
    ));
    // Browser-like UA without browser headers: scripted client.
    assert!(matches!(
        policy.evaluate_with_hints(browser, false),
        BotDecision::Deny(_)
    ));
    // Verified-bot whitelist entries pass regardless of the hints.
    assert!(matches!(
        policy.evaluate_with_hints(
            "Mozilla/5.0 (compatible; Googlebot/2.1)",
            false
        ),
        BotDecision::Pass
    ));
}

#[test]
fn bot_tls_fingerprint_requires_a_tls_session() {
    let policy = BotPolicy::build(&CacheBotProtection {
        enabled: true,
        action: CacheWafAction::Block,
        known_bots_whitelist: vec!["Googlebot".to_string()],
        js_detection: false,
        tls_fingerprint: true,
        behavioral_analysis: false,
        dns_verification_enabled: false,
        verified_bot_ranges: Vec::new(),
    });
    let browser = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36";

    // Browser over TLS: passes even without browser header hints when JS
    // detection is off.
    assert!(matches!(
        policy.classify_with_signals(
            browser,
            ClientSignals {
                browser_hints: false,
                tls_verified: true,
                burst: false,
            },
        ),
        BotDecision::Pass
    ));
    // Browser on a plaintext connection: scripted client.
    assert!(matches!(
        policy.classify_with_signals(
            browser,
            ClientSignals {
                browser_hints: true,
                tls_verified: false,
                burst: false,
            },
        ),
        BotDecision::Deny(_)
    ));
    // Non-browser clients are unaffected by the TLS requirement.
    assert!(matches!(
        policy.classify_with_signals(
            "curl/8.4.0",
            ClientSignals {
                browser_hints: false,
                tls_verified: false,
                burst: false,
            },
        ),
        BotDecision::Deny(_)
    ));
}

#[test]
fn bot_behavioral_analysis_flags_bursts() {
    let policy = BotPolicy::build(&CacheBotProtection {
        enabled: true,
        action: CacheWafAction::Block,
        known_bots_whitelist: vec![],
        js_detection: false,
        tls_fingerprint: false,
        behavioral_analysis: true,
        dns_verification_enabled: false,
        verified_bot_ranges: Vec::new(),
    });
    let browser = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36";
    assert!(matches!(
        policy.classify_with_signals(
            browser,
            ClientSignals {
                browser_hints: true,
                tls_verified: true,
                burst: false,
            },
        ),
        BotDecision::Pass
    ));
    assert!(matches!(
        policy.classify_with_signals(
            browser,
            ClientSignals {
                browser_hints: true,
                tls_verified: true,
                burst: true,
            },
        ),
        BotDecision::Deny(_)
    ));
}

#[test]
fn behavioral_tracker_flags_bursts_within_the_window() {
    let map: dashmap::DashMap<String, (std::time::Instant, u32)> =
        dashmap::DashMap::new();
    let start = std::time::Instant::now();
    let window = std::time::Duration::from_secs(60);
    assert!(!super::request_burst_with(
        &map,
        "203.0.113.9",
        start,
        window,
        2
    ));
    assert!(!super::request_burst_with(
        &map,
        "203.0.113.9",
        start,
        window,
        2
    ));
    assert!(super::request_burst_with(
        &map,
        "203.0.113.9",
        start,
        window,
        2
    ));
    assert!(!super::request_burst_with(
        &map,
        "203.0.113.10",
        start,
        window,
        2
    ));
    let later = start + window;
    assert!(!super::request_burst_with(
        &map,
        "203.0.113.9",
        later,
        window,
        2
    ));
}

/// A client IP inside a configured verified-bot range passes without any
/// user-agent consideration, and the DNS path stays quiet when the
/// feature is off.
#[tokio::test]
async fn bot_verified_range_bypasses_ua_classification() {
    let policy = BotPolicy::build(&CacheBotProtection {
        enabled: true,
        action: CacheWafAction::Block,
        known_bots_whitelist: vec![],
        js_detection: false,
        tls_fingerprint: false,
        behavioral_analysis: false,
        verified_bot_ranges: vec!["203.0.113.0/24".to_string()],
        dns_verification_enabled: false,
    });
    // Inside the range: passes even though the UA is a scripted client.
    assert!(matches!(
        policy
            .evaluate_with_signals(
                Some("203.0.113.44".parse().unwrap()),
                "curl/8.4.0",
                ClientSignals {
                    browser_hints: false,
                    tls_verified: false,
                    burst: false,
                },
            )
            .await,
        BotDecision::Pass
    ));
    // Outside the range the UA classification decides again.
    assert!(matches!(
        policy
            .evaluate_with_signals(
                Some("198.51.100.7".parse().unwrap()),
                "curl/8.4.0",
                ClientSignals {
                    browser_hints: false,
                    tls_verified: false,
                    burst: false,
                },
            )
            .await,
        BotDecision::Deny(_)
    ));
    // A malformed range entry is skipped, not fatal.
    let policy = BotPolicy::build(&CacheBotProtection {
        enabled: true,
        action: CacheWafAction::Block,
        known_bots_whitelist: vec![],
        js_detection: false,
        tls_fingerprint: false,
        behavioral_analysis: false,
        verified_bot_ranges: vec!["not-a-range".to_string()],
        dns_verification_enabled: false,
    });
    assert!(policy.verified_ranges.is_empty());
}

#[test]
fn bot_ua_classification() {
    let policy = BotPolicy::build(&CacheBotProtection {
        enabled: true,
        action: CacheWafAction::Block,
        known_bots_whitelist: vec!["Googlebot".to_string()],
        js_detection: false,
        tls_fingerprint: false,
        behavioral_analysis: false,
        dns_verification_enabled: false,
        verified_bot_ranges: Vec::new(),
    });

    assert!(matches!(
        policy.evaluate(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
        ),
        BotDecision::Pass
    ));
    assert!(matches!(
        policy.evaluate("Mozilla/5.0 (compatible; Googlebot/2.1)"),
        BotDecision::Pass
    ));
    assert!(matches!(
        policy.evaluate("curl/8.4.0"),
        BotDecision::Deny(_)
    ));
    assert!(matches!(policy.evaluate(""), BotDecision::Deny(_)));
    assert!(matches!(
        policy.evaluate("python-requests/2.31.0"),
        BotDecision::Deny(_)
    ));
    // Matching is case-insensitive without lowercasing the agent.
    assert!(matches!(
        policy.evaluate("mOzIlLa/5.0 (compatible; googlEBot/2.1)"),
        BotDecision::Pass
    ));
    assert!(matches!(
        policy.evaluate("MOZILLA/5.0 (X11; Linux) FIREFOX/128.0"),
        BotDecision::Pass
    ));
}

#[test]
fn contains_ignore_case_matches_substrings_only() {
    assert!(contains_ignore_case("curl/8.4.0", "CURL/"));
    assert!(contains_ignore_case("Curl/8.4.0", "curl/"));
    assert!(!contains_ignore_case("curl/8.4.0", "wget/"));
    // Needle longer than haystack, and empty needle, are not matches.
    assert!(!contains_ignore_case("ab", "abc"));
    assert!(!contains_ignore_case("anything", ""));
}

#[test]
fn stage_chunk_withholds_until_the_cap() {
    let mut passthrough = false;
    let mut buffer = BytesMut::new();
    // Below the cap: withheld, nothing forwarded.
    assert!(matches!(
        stage_chunk(8, &mut passthrough, &mut buffer, Some(b"12345")),
        StageAction::Withhold
    ));
    assert!(!passthrough);
    assert_eq!(&buffer[..], b"12345");
    // Exactly at the cap: still withheld (the cap is a ceiling).
    assert!(matches!(
        stage_chunk(8, &mut passthrough, &mut buffer, Some(b"678")),
        StageAction::Withhold
    ));
    assert_eq!(&buffer[..], b"12345678");
    // One byte past: everything staged is flushed once for scanning.
    let StageAction::Flush(staged) =
        stage_chunk(8, &mut passthrough, &mut buffer, Some(b"9"))
    else {
        panic!("the cap must flush");
    };
    assert_eq!(&staged[..], b"123456789");
    assert!(passthrough);
    assert!(buffer.is_empty());
    // Afterwards the stream flows untouched.
    assert!(matches!(
        stage_chunk(8, &mut passthrough, &mut buffer, Some(b"tail")),
        StageAction::PassThrough
    ));
    // An end-of-stream call with no chunk must not flush on its own.
    let mut passthrough = false;
    let mut buffer = BytesMut::new();
    assert!(matches!(
        stage_chunk(8, &mut passthrough, &mut buffer, None),
        StageAction::Withhold
    ));
    assert!(buffer.is_empty());
}

/// A block action answers non-browser agents with 403 even with the WAF
/// engine disabled; whitelisted bots and browsers pass.
#[tokio::test]
async fn test_bot_protection_blocks_non_browser() {
    let (_guard, _agent, _dir) =
        install_bot_agent(proto::WafAction::Block).await;
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    let RequestPluginResult::Respond(resp) =
        run_request_with_ua(&plugin, "203.0.113.7", "curl/8.4.0").await
    else {
        panic!("expected bot protection to answer");
    };
    assert_eq!(http::StatusCode::FORBIDDEN, resp.status);

    assert!(
        run_request_with_ua(
            &plugin,
            "203.0.113.7",
            "Mozilla/5.0 (compatible; Googlebot/2.1)"
        )
        .await
            == RequestPluginResult::Continue
    );
    assert!(
        run_request_with_ua(
            &plugin,
            "203.0.113.7",
            "Mozilla/5.0 (X11; Linux x86_64) Firefox/127.0"
        )
        .await
            == RequestPluginResult::Continue
    );
}

/// The challenge action answers with the JS challenge (503).
#[tokio::test]
async fn test_bot_protection_challenge_action() {
    let (_guard, _agent, _dir) =
        install_bot_agent(proto::WafAction::Challenge).await;
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    let RequestPluginResult::Respond(resp) =
        run_request_with_ua(&plugin, "203.0.113.7", "wget/1.21").await
    else {
        panic!("expected bot protection to answer");
    };
    assert_eq!(http::StatusCode::SERVICE_UNAVAILABLE, resp.status);
}

/// The log action records a security event but lets the request through.
#[tokio::test]
async fn test_bot_protection_log_action() {
    let (_guard, agent, _dir) = install_bot_agent(proto::WafAction::Log).await;
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    assert!(
        run_request_with_ua(&plugin, "203.0.113.7", "python/3.12").await
            == RequestPluginResult::Continue
    );
    let event = agent.client.pop_log().await.unwrap();
    assert_eq!("bot_protection", event.waf_rule_id);
    assert_eq!("monitor", event.waf_action);
}

/// Builds one rate limit rule for the tests.
fn rate_rule(
    id: &str,
    chars: Vec<proto::RateLimitCharacteristics>,
    expression: &str,
    threshold: u32,
    action: proto::WafAction,
    mitigation: u32,
) -> proto::RateLimitRule {
    proto::RateLimitRule {
        id: id.to_string(),
        name: format!("rule-{id}"),
        expression: expression.to_string(),
        characteristics: chars.into_iter().map(|c| c as i32).collect(),
        characteristic_params: Vec::new(),
        period_seconds: 60,
        threshold,
        action: action as i32,
        mitigation_timeout_seconds: mitigation,
        enabled: true,
        priority: 0,
    }
}

/// Installs an agent whose site carries the given rate limit rules and no
/// WAF engine.
async fn install_rate_agent(
    rules: Vec<proto::RateLimitRule>,
) -> (
    tokio::sync::MutexGuard<'static, ()>,
    Arc<VarmanAgent>,
    tempfile::TempDir,
) {
    let installed = install_test_agent().await;
    installed
        .1
        .rule_cache
        .update_from_site_config(&proto::SiteConfig {
            sites: vec![proto::Site {
                id: "site-1".to_string(),
                name: "example".to_string(),
                domain: "example.com".to_string(),
                alternate_domains: Vec::new(),
                status: 0,
                rules: Some(proto::RuleBundle {
                    site_id: "site-1".to_string(),
                    config_hash: "hash-1".to_string(),
                    waf: Some(proto::WafConfig {
                        enabled: false,
                        ..Default::default()
                    }),
                    rate_limit_rules: rules,
                    ..Default::default()
                }),
                ..Default::default()
            }],
            config_hash: "hash-1".to_string(),
            updated_at: None,
        })
        .unwrap();
    installed
}

/// Builds one GET request with an explicit path and optional cookie.
async fn run_rate_request(
    plugin: &WafPlugin,
    client_ip: &str,
    path: &str,
    cookie: Option<&str>,
) -> RequestPluginResult {
    let cookie_line = cookie
        .map(|value| format!("Cookie: {value}\r\n"))
        .unwrap_or_default();
    let input_header = format!(
        "GET {path} HTTP/1.1\r\nHost: example.com\r\n{cookie_line}\r\n"
    );
    let mock_io = Builder::new().read(input_header.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(mock_io));
    session.read_request().await.unwrap();
    let mut ctx = Ctx::default();
    ctx.conn.client_ip = Some(client_ip.to_string());
    plugin
        .handle_request(PluginStep::EarlyRequest, &mut session, &mut ctx)
        .await
        .unwrap()
}

#[test]
fn rate_rule_build_filters_unenforceable_rules() {
    let build = |rule: proto::RateLimitRule| {
        CompiledRateRule::build(&CacheRateLimitRule {
            id: rule.id,
            name: rule.name,
            expression: rule.expression,
            characteristics: rule
                .characteristics
                .iter()
                .map(|c| {
                    format!(
                        "{:?}",
                        proto::RateLimitCharacteristics::try_from(*c)
                            .unwrap_or(
                            proto::RateLimitCharacteristics::RateLimitCharIp
                        )
                    )
                })
                .collect(),
            characteristic_params: Vec::new(),
            period_seconds: rule.period_seconds,
            threshold: rule.threshold,
            action: CacheWafAction::from(rule.action),
            mitigation_timeout_seconds: rule.mitigation_timeout_seconds,
            enabled: rule.enabled,
            priority: rule.priority,
        })
    };

    // Zero threshold or period would never trip (or trip everything).
    assert!(
        build(rate_rule(
            "a",
            vec![proto::RateLimitCharacteristics::RateLimitCharIp],
            "",
            0,
            proto::WafAction::Block,
            60
        ))
        .is_none()
    );
    // Disabled rules are skipped.
    let mut disabled = rate_rule(
        "b",
        vec![proto::RateLimitCharacteristics::RateLimitCharIp],
        "",
        10,
        proto::WafAction::Block,
        0,
    );
    disabled.enabled = false;
    assert!(build(disabled).is_none());
    // Characteristics the edge cannot key on invalidate the whole rule.
    assert!(
        build(rate_rule(
            "c",
            vec![
                proto::RateLimitCharacteristics::RateLimitCharIp,
                proto::RateLimitCharacteristics::RateLimitCharJa3,
            ],
            "",
            10,
            proto::WafAction::Block,
            0
        ))
        .is_none()
    );
    // Allow actions do nothing meaningful on a counter.
    assert!(
        build(rate_rule(
            "d",
            vec![proto::RateLimitCharacteristics::RateLimitCharIp],
            "",
            10,
            proto::WafAction::Allow,
            0
        ))
        .is_none()
    );
    // A parse failure leaves the rule out rather than matching nothing.
    assert!(
        build(rate_rule(
            "e",
            vec![proto::RateLimitCharacteristics::RateLimitCharIp],
            "http.request.uri.path ~~~",
            10,
            proto::WafAction::Block,
            0
        ))
        .is_none()
    );
    // The prost debug name of ip_nat normalises to the plain IP key.
    let nat = build(rate_rule(
        "f",
        vec![proto::RateLimitCharacteristics::RateLimitCharIpNat],
        "",
        10,
        proto::WafAction::Block,
        0,
    ))
    .unwrap();
    assert_eq!(vec![RateChar::Ip], nat.chars);
}

#[test]
fn rate_rule_build_accepts_parameterized_characteristics() {
    let build = |characteristics: &[&str], params: &[&str]| {
        CompiledRateRule::build(&CacheRateLimitRule {
            id: "p".to_string(),
            name: "rule-p".to_string(),
            expression: String::new(),
            characteristics: characteristics
                .iter()
                .map(|s| s.to_string())
                .collect(),
            characteristic_params: params
                .iter()
                .map(|s| s.to_string())
                .collect(),
            period_seconds: 60,
            threshold: 10,
            action: CacheWafAction::Block,
            mitigation_timeout_seconds: 0,
            enabled: true,
            priority: 0,
        })
    };

    // Header names are matched case-insensitively, so the stored name is
    // lowercased; cookie and query names stay as configured.
    let header = build(&["RateLimitCharHeader"], &["X-Api-Key"]).unwrap();
    assert_eq!(
        vec![RateChar::Header("x-api-key".to_string())],
        header.chars
    );
    let cookie_query = build(
        &["RateLimitCharCookie", "RateLimitCharQuery"],
        &["Session", "lang"],
    )
    .unwrap();
    assert_eq!(
        vec![
            RateChar::Cookie("Session".to_string()),
            RateChar::Query("lang".to_string())
        ],
        cookie_query.chars
    );
    // A parameterized kind without a name cannot key a counter.
    assert!(build(&["RateLimitCharHeader"], &[]).is_none());
    assert!(build(&["RateLimitCharQuery"], &["  "]).is_none());
}

#[test]
fn rate_limit_keys_parameterized_characteristics() {
    let rule = CompiledRateRule {
        id: "rl-h".to_string(),
        name: "per-key".to_string(),
        expression: None,
        chars: vec![
            RateChar::Header("X-Api-Key".to_string()),
            RateChar::Cookie("Session".to_string()),
            RateChar::Query("lang".to_string()),
        ],
        period_secs: 60,
        threshold: 1,
        mitigation_secs: 0,
        action: RateAction::Block,
    };
    let request = |headers: Vec<(&str, &str)>, query: &str| RequestData {
        method: "GET".to_string(),
        path: "/".to_string(),
        query: query.to_string(),
        headers: headers
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        body: None,
        client_ip: "1.1.1.1".to_string(),
        country_code: None,
        scheme: "http".to_string(),
        protocol: "HTTP/1.1".to_string(),
    };
    let sep = '\u{1f}';

    let full = request(
        vec![("x-api-key", "v1"), ("Cookie", "a=1; Session=abc; b=2")],
        "lang=en&page=2",
    );
    assert_eq!(
        format!("rl-h{sep}v1{sep}abc{sep}en"),
        rule.counter_key(&full, "s.test", None)
    );

    // Header matching is case-insensitive; a present-but-empty query
    // value keys as "" rather than the missing bucket.
    let mixed = request(vec![("X-API-KEY", "v1")], "lang=");
    assert_eq!(
        format!("rl-h{sep}v1{sep}-{sep}"),
        rule.counter_key(&mixed, "s.test", None)
    );

    // Requests missing every parameterized value share the '-' bucket
    // instead of bypassing the counter.
    let empty = request(Vec::new(), "page=2");
    assert_eq!(
        format!("rl-h{sep}-{sep}-{sep}-"),
        rule.counter_key(&empty, "s.test", None)
    );
}

#[test]
fn rate_policy_counts_per_key_and_expires() {
    let policy = RateLimitPolicy {
        rules: vec![CompiledRateRule {
            id: "rl".to_string(),
            name: "per-ip".to_string(),
            expression: None,
            chars: vec![RateChar::Ip],
            period_secs: 60,
            threshold: 1,
            mitigation_secs: 0,
            action: RateAction::Block,
        }],
    };
    let counters: DashMap<String, RateCounter> = DashMap::new();
    let request = |ip: &str, path: &str| RequestData {
        method: "GET".to_string(),
        path: path.to_string(),
        query: String::new(),
        headers: Vec::new(),
        body: None,
        client_ip: ip.to_string(),
        country_code: None,
        scheme: "http".to_string(),
        protocol: "HTTP/1.1".to_string(),
    };

    assert!(
        policy
            .evaluate(
                &counters,
                &request("1.1.1.1", "/"),
                "s.test",
                false,
                "1.1.1.1".parse().ok(),
            )
            .deny
            .is_none()
    );
    let outcome = policy.evaluate(
        &counters,
        &request("1.1.1.1", "/"),
        "s.test",
        false,
        "1.1.1.1".parse().ok(),
    );
    let deny = outcome.deny.expect("second request must trip");
    assert!(!deny.challenge);
    assert!(deny.retry_after > 0 && deny.retry_after <= 60);

    // A different key (IP or path dimension) keeps its own counter.
    assert!(
        policy
            .evaluate(
                &counters,
                &request("2.2.2.2", "/"),
                "s.test",
                false,
                "2.2.2.2".parse().ok(),
            )
            .deny
            .is_none()
    );
}

/// A block action answers the third request over the threshold with 429
/// while other IPs keep their own counters.
#[tokio::test]
async fn test_rate_limit_blocks_over_threshold() {
    let (_guard, _agent, _dir) = install_rate_agent(vec![rate_rule(
        "rl-block",
        vec![proto::RateLimitCharacteristics::RateLimitCharIp],
        "",
        2,
        proto::WafAction::Block,
        60,
    )])
    .await;
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    assert!(
        run_rate_request(&plugin, "203.0.113.9", "/", None).await
            == RequestPluginResult::Continue
    );
    assert!(
        run_rate_request(&plugin, "203.0.113.9", "/", None).await
            == RequestPluginResult::Continue
    );
    let RequestPluginResult::Respond(resp) =
        run_rate_request(&plugin, "203.0.113.9", "/", None).await
    else {
        panic!("expected the rate limit to answer");
    };
    assert_eq!(http::StatusCode::TOO_MANY_REQUESTS, resp.status);

    // Another client IP is unaffected.
    assert!(
        run_rate_request(&plugin, "203.0.113.10", "/", None).await
            == RequestPluginResult::Continue
    );
}

/// The path characteristic splits counters and the expression restricts
/// which requests a rule counts at all.
#[tokio::test]
async fn test_rate_limit_path_and_expression() {
    let (_guard, _agent, _dir) = install_rate_agent(vec![rate_rule(
        "rl-api",
        vec![
            proto::RateLimitCharacteristics::RateLimitCharIp,
            proto::RateLimitCharacteristics::RateLimitCharPath,
        ],
        r#"http.request.uri.path starts_with "/api/""#,
        1,
        proto::WafAction::Block,
        0,
    )])
    .await;
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    // First hit counts, second trips, a different path keeps its own
    // counter and requests outside /api/ are never counted.
    assert!(
        run_rate_request(&plugin, "203.0.113.11", "/api/list", None).await
            == RequestPluginResult::Continue
    );
    let RequestPluginResult::Respond(resp) =
        run_rate_request(&plugin, "203.0.113.11", "/api/list", None).await
    else {
        panic!("expected the rate limit to answer");
    };
    assert_eq!(http::StatusCode::TOO_MANY_REQUESTS, resp.status);

    // The tripped client is refused at the edge for the retry window:
    // even an uncounted path is answered without reaching the counters.
    let RequestPluginResult::Respond(resp) =
        run_rate_request(&plugin, "203.0.113.11", "/other", None).await
    else {
        panic!("expected the edge block to answer");
    };
    assert_eq!(http::StatusCode::FORBIDDEN, resp.status);

    // A fresh client proves the path characteristic splits counters
    // (/api/detail keeps counting from zero) and the expression keeps
    // non-/api/ requests out of the rule entirely.
    assert!(
        run_rate_request(&plugin, "203.0.113.15", "/api/list", None).await
            == RequestPluginResult::Continue
    );
    assert!(
        run_rate_request(&plugin, "203.0.113.15", "/api/detail", None).await
            == RequestPluginResult::Continue
    );
    assert!(
        run_rate_request(&plugin, "203.0.113.15", "/other", None).await
            == RequestPluginResult::Continue
    );
    assert!(
        run_rate_request(&plugin, "203.0.113.15", "/other", None).await
            == RequestPluginResult::Continue
    );
}

/// The log action ships a security event but lets the request continue.
#[tokio::test]
async fn test_rate_limit_log_action_records_event() {
    let (_guard, agent, _dir) = install_rate_agent(vec![rate_rule(
        "rl-log",
        vec![proto::RateLimitCharacteristics::RateLimitCharIp],
        "",
        1,
        proto::WafAction::Log,
        0,
    )])
    .await;
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    assert!(
        run_rate_request(&plugin, "203.0.113.12", "/", None).await
            == RequestPluginResult::Continue
    );
    assert!(
        run_rate_request(&plugin, "203.0.113.12", "/", None).await
            == RequestPluginResult::Continue
    );
    let event = agent.client.pop_log().await.unwrap();
    assert_eq!("rl-log", event.waf_rule_id);
    assert_eq!("monitor", event.waf_action);
}

/// The challenge action serves the JS challenge; a client holding a valid
/// clearance cookie is exempt and keeps passing.
#[tokio::test]
async fn test_rate_limit_challenge_and_clearance() {
    let (_guard, _agent, _dir) = install_rate_agent(vec![rate_rule(
        "rl-challenge",
        vec![proto::RateLimitCharacteristics::RateLimitCharIp],
        "",
        1,
        proto::WafAction::Challenge,
        60,
    )])
    .await;
    let plugin = WafPlugin::new(
        &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
    )
    .unwrap();

    // The second request trips and receives the challenge page.
    assert!(
        run_rate_request(&plugin, "203.0.113.13", "/", None).await
            == RequestPluginResult::Continue
    );
    let RequestPluginResult::Respond(resp) =
        run_rate_request(&plugin, "203.0.113.13", "/", None).await
    else {
        panic!("expected the challenge to answer");
    };
    assert_eq!(http::StatusCode::SERVICE_UNAVAILABLE, resp.status);

    // A solved clearance exempts the client: the rule neither counts nor
    // stops it, even though the counter is already over the threshold.
    let secret = resolve_cookie_secret("");
    let manager = CookieManager::new(secret.as_bytes(), 3600);
    let cookie = manager.issue_clearance(
        ClearanceLevel::NonInteractive,
        "site-1",
        "fingerprint",
    );
    assert!(
        run_rate_request(
            &plugin,
            "203.0.113.13",
            "/",
            Some(&format!("{CLEARANCE_COOKIE_NAME}={cookie}"))
        )
        .await
            == RequestPluginResult::Continue
    );
}

#[test]
fn site_engine_inherits_the_engine_baseline() {
    let cfg = cache_waf_config(false, Vec::new(), Vec::new());
    let config = super::state::build_site_engine_config(&cfg);
    let baseline = varman_waf::engine::WafEngineConfig::default();
    // Fields the site does not override must come from the one baseline
    // owner, so changing the engine default reaches the edge.
    assert_eq!(config.level, baseline.level);
    assert_eq!(config.stacks, baseline.stacks);
    assert_eq!(config.threshold, baseline.threshold);
    assert_eq!(config.max_decode_layers, baseline.max_decode_layers);
    assert_eq!(config.enable_managed_rules, baseline.enable_managed_rules);
    assert_eq!(
        config.fast_path_block_on_critical,
        baseline.fast_path_block_on_critical
    );
}
