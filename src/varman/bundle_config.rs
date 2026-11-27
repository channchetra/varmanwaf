use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use pingap_config::{
    BasicConf, CertificateConf, LocationConf, PingapConfig, PluginConf,
    ServerConf as PingapServerConf, UpstreamConf,
};
use tracing::warn;
use varman_agent::cache::{
    CachedRules, HealthCheckConfig, RuleCache, SslConfig,
};

use super::acme::acme_certificate_conf;

/// Sanitize a control-plane LB algorithm into a pingap `algo` value.
///
/// pingap accepts `round_robin` (its default), `random`,
/// `least_connections` and `hash:<type>[:<key>]` with type in {ip, url,
/// path, header, cookie, query}; anything else — including legacy enum
/// Debug names such as `lbconsistenthash` — is a hard error at upstream
/// construction, so it must collapse to the default here.
pub(super) fn sanitize_algo(algo: &str) -> Option<String> {
    let algo = algo.trim();
    if algo.is_empty() || algo == "round_robin" {
        return None;
    }
    if matches!(algo, "random" | "least_connections") {
        return Some(algo.to_string());
    }
    let spec = algo.strip_prefix("hash:")?;
    let hash_type = spec.split(':').next().unwrap_or_default();
    if matches!(
        hash_type,
        "ip" | "url" | "path" | "header" | "cookie" | "query"
    ) {
        Some(algo.to_string())
    } else {
        None
    }
}

/// Name under which the WAF plugin is registered and referenced from
/// every generated location.
const WAF_PLUGIN_NAME: &str = "varman:waf";

/// Name under which the edge cache plugin is registered. One process-wide
/// instance serves every site: the plugin resolves each host's cache rules
/// from the agent's rule cache, so wiring it into the locations is all the
/// data plane needs to actually cache.
pub(super) const CACHE_PLUGIN_NAME: &str = "varman:cache";

/// Name under which the CC/challenge plugin is registered. Like the WAF and
/// cache plugins it resolves per-site settings from the agent's rule cache;
/// it also serves the challenge verify endpoint, which every site needs
/// whenever a WAF, IP or geo rule answers with a challenge.
const CHALLENGE_PLUGIN_NAME: &str = "varman:challenge";

/// Name under which the rewrite plugin is registered. It rewrites request
/// and response headers/paths/bodies per the site's rewrite rules, resolved
/// from the agent's rule cache at request time.
const REWRITE_PLUGIN_NAME: &str = "varman:rewrite";

/// Name under which the custom error page plugin is registered. It replaces
/// upstream error responses with the site's configured pages (falling back to
/// the built-in VarmanWAF pages); plugin-generated responses such as WAF blocks
/// answer early and never reach its response phase.
const ERROR_PAGE_PLUGIN_NAME: &str = "varman:error_page";

/// Builds the per-site plugins that enforce TLS postures outside the WAF
/// plugin, and returns their names in the order they should run.
///
/// Both postures are per-site settings, so each site gets its own plugin
/// instance; the instance name carries the site id to keep them apart.
fn site_posture_plugins(
    site_id: &str,
    ssl: Option<&SslConfig>,
    plugins: &mut HashMap<String, PluginConf>,
) -> Vec<String> {
    let mut names = Vec::new();
    let Some(ssl) = ssl.filter(|ssl| ssl.enabled) else {
        return names;
    };

    // `max-age=0` would tell browsers to stop honouring HSTS, which is the
    // opposite of what the switch means — treat it as "not configured".
    if ssl.hsts_enabled && ssl.hsts_max_age > 0 {
        let name = format!("{site_id}_hsts");
        let mut conf = PluginConf::new();
        conf.insert(
            "category".to_string(),
            toml::Value::String("response_headers".to_string()),
        );
        conf.insert(
            "add_headers".to_string(),
            toml::Value::Array(vec![toml::Value::String(format!(
                "Strict-Transport-Security: max-age={}",
                ssl.hsts_max_age
            ))]),
        );
        plugins.insert(name.clone(), conf);
        names.push(name);
    }

    // The redirect plugin compares the request's TLS state against the
    // desired one, so sharing a location between :80 and :443 is safe — only
    // the plaintext listener redirects.
    if ssl.always_use_https {
        let name = format!("{site_id}_https");
        let mut conf = PluginConf::new();
        conf.insert(
            "category".to_string(),
            toml::Value::String("redirect".to_string()),
        );
        conf.insert("http_to_https".to_string(), toml::Value::Boolean(true));
        conf.insert("status".to_string(), toml::Value::Integer(301));
        plugins.insert(name.clone(), conf);
        names.push(name);
    }

    names
}

/// Synthesizes the data-plane health check URL from the control plane's
/// per-pool [`HealthCheckConfig`]. The URL host is the upstream (pool) name —
/// pingap only uses it as the probe request's Host header, nothing resolves
/// it — and the query carries the tunables `pingap-health` understands
/// (`check_frequency`, `connection_timeout`/`read_timeout`, `failure`,
/// `success`). Values are clamped so a corrupt cache entry can never produce
/// a zero-timeout or zero-frequency probe.
pub(super) fn health_check_url(
    upstream_name: &str,
    hc: &HealthCheckConfig,
) -> String {
    let path = if hc.path.is_empty() {
        "/".to_string()
    } else if hc.path.starts_with('/') {
        hc.path.clone()
    } else {
        format!("/{}", hc.path)
    };
    format!(
        "http://{upstream_name}{path}?check_frequency={}s&\
         connection_timeout={}ms&read_timeout={}ms&failure={}&success={}",
        hc.interval_seconds.max(1),
        hc.timeout_ms.max(1),
        hc.timeout_ms.max(1),
        hc.unhealthy_threshold.max(1),
        hc.healthy_threshold.max(1),
    )
}

/// Build a `PingapConfig` from the agent's cached site rules.
///
/// Each origin pool becomes one upstream keyed by its pool id (or the
/// legacy per-site name for caches written before pools existed). The
/// default pool — or the only pool, when no routes exist — receives the
/// site's `/` fallback location, and every enabled route becomes an
/// additional location carrying the pingap path marker for its match
/// type. All sites share a single server listening on ports 80 and 443
/// with TLS enabled via the global certificate store.
pub(super) fn cached_rules_to_pingap_config(
    cached: &CachedRules,
    cache_dir: &Path,
) -> Option<PingapConfig> {
    if cached.sites.is_empty() {
        return None;
    }

    // The cache plugin carries no per-site settings of its own — rules,
    // namespaces and quotas all flow from the agent's rule cache at request
    // time. It only earns a slot in the config when some site actually has
    // cache rules; for the rest it would be dead weight.
    let has_cache_rules = cached
        .sites
        .values()
        .any(|site| site.cache_rules.iter().any(|rule| rule.enabled));

    let mut upstreams: HashMap<String, UpstreamConf> = HashMap::new();
    let mut locations: HashMap<String, LocationConf> = HashMap::new();
    let mut certificates: HashMap<String, CertificateConf> = HashMap::new();
    let mut location_names: Vec<String> = Vec::new();
    // PEM bundle of the CAs every mTLS-enabled site trusts. The listener
    // verifies client certificates as a whole, so the anchor is the union
    // across sites; pinning a certificate to its site is left to the WAF
    // plugin, which sees the request's SNI.
    let mut mtls_ca_bundle = String::new();
    // The WAF plugin is referenced from every location: this is what makes
    // the data plane enforce rules and emit access/security events.
    let mut plugins: HashMap<String, PluginConf> = HashMap::new();
    plugins.insert(
        WAF_PLUGIN_NAME.to_string(),
        toml::from_str::<PluginConf>(r###"category = "waf""###)
            .unwrap_or_default(),
    );
    plugins.insert(
        CHALLENGE_PLUGIN_NAME.to_string(),
        toml::from_str::<PluginConf>(r###"category = "challenge""###)
            .unwrap_or_default(),
    );
    plugins.insert(
        REWRITE_PLUGIN_NAME.to_string(),
        toml::from_str::<PluginConf>(r###"category = "rewrite""###)
            .unwrap_or_default(),
    );
    plugins.insert(
        ERROR_PAGE_PLUGIN_NAME.to_string(),
        toml::from_str::<PluginConf>(r###"category = "error_page""###)
            .unwrap_or_default(),
    );
    // The cache master switch gates everything: with it off the data plane
    // never sees a cache plugin, regardless of the rules any site carries.
    let global_cache = cached.global_cache.clone().unwrap_or_default();
    let cache_enabled = has_cache_rules && global_cache.master_enabled();
    if cache_enabled {
        let mut cache_conf = PluginConf::new();
        cache_conf.insert(
            "category".to_string(),
            toml::Value::String("cache".to_string()),
        );
        // The disk budget rides on the directory URL (`FileCacheParams`
        // parses `?max_size=`): pingora's `ensure_disk_space` then evicts by
        // LRU across every namespace sharing the backend. `0` = unlimited.
        let directory = match global_cache.max_space_mb() {
            0 => cache_dir.to_string_lossy().to_string(),
            space_mb => {
                format!("{}?max_size={space_mb}mb", cache_dir.to_string_lossy())
            },
        };
        cache_conf
            .insert("directory".to_string(), toml::Value::String(directory));
        // pingora's default 1MB ceiling silently refuses to cache anything
        // larger (the response header stage rejects it before the body ever
        // fills). Magento-style merged JS/CSS bundles run several MB and are
        // exactly the assets caching exists for, so the ceiling is raised
        // here. `ByteSize` parses decimal units — the 16 MiB default is
        // 16_000_000 bytes, comfortably above a ~10MB bundle. Actual disk
        // usage stays bounded by each site's `disk_quota_mb` and the LRU
        // eviction manager.
        cache_conf.insert(
            "max_file_size".to_string(),
            toml::Value::String(format!(
                "{}mb",
                global_cache.max_file_size_mb()
            )),
        );
        // A rule without an explicit edge TTL falls back to this floor;
        // `0` (the default) keeps the old behaviour of no fallback at all.
        let default_ttl = global_cache.default_edge_ttl_seconds();
        if default_ttl > 0 {
            cache_conf.insert(
                "max_ttl".to_string(),
                toml::Value::String(format!("{default_ttl}s")),
            );
        }
        plugins.insert(CACHE_PLUGIN_NAME.to_string(), cache_conf);
    }
    let mut location_plugins: Vec<String> = vec![
        WAF_PLUGIN_NAME.to_string(),
        CHALLENGE_PLUGIN_NAME.to_string(),
        REWRITE_PLUGIN_NAME.to_string(),
        ERROR_PAGE_PLUGIN_NAME.to_string(),
    ];
    if cache_enabled {
        location_plugins.push(CACHE_PLUGIN_NAME.to_string());
    }

    for (site_id, site) in &cached.sites {
        if site.domain.is_empty() {
            continue;
        }

        // One upstream per origin pool. Pools without peers are skipped:
        // an address-less upstream cannot be constructed.
        let mut pool_keys: Vec<String> = Vec::new();
        let mut default_key: Option<String> = None;
        for (i, up) in site.upstreams.iter().enumerate() {
            if up.peers.is_empty() {
                continue;
            }
            let name = if up.pool_id.is_empty() {
                if site.upstreams.len() == 1 {
                    format!("{site_id}_upstream")
                } else {
                    format!("{site_id}_upstream_{i}")
                }
            } else {
                up.pool_id.clone()
            };

            let addrs: Vec<String> = up
                .peers
                .iter()
                .map(|p| {
                    let addr = p
                        .address
                        .strip_prefix("https://")
                        .or_else(|| p.address.strip_prefix("http://"))
                        .unwrap_or(&p.address);
                    if p.weight > 1 {
                        format!("{} {}", addr, p.weight)
                    } else {
                        addr.to_string()
                    }
                })
                .collect();

            // Multi-node pools get request-level protection by default:
            // without backend stats the circuit breaker can never observe
            // failures, and the control plane exposes no knobs for either.
            // Single-node pools are left untouched — with no alternative
            // backend an open breaker only short-circuits into 503.
            let multi_peer = up.peers.len() > 1;
            let conf = UpstreamConf {
                addrs,
                algo: sanitize_algo(&up.algo),
                sni: if up.sni.is_empty() {
                    None
                } else {
                    Some(up.sni.clone())
                },
                // Verification is opt-in. Normalize here as well as in the
                // agent's gRPC conversion: a rule cache restored from the
                // persisted snapshot (sites.json) carries `verify_cert: null`
                // and never passes through that conversion, and a `None` left
                // intact means pingora's default - strict verification - so
                // self-signed origins would 502 with InvalidCert.
                verify_cert: Some(up.verify_cert.unwrap_or(false)),
                connection_timeout: if up.connection_timeout_ms > 0 {
                    Some(Duration::from_millis(up.connection_timeout_ms as u64))
                } else {
                    None
                },
                read_timeout: if up.read_timeout_ms > 0 {
                    Some(Duration::from_millis(up.read_timeout_ms as u64))
                } else {
                    None
                },
                write_timeout: if up.write_timeout_ms > 0 {
                    Some(Duration::from_millis(up.write_timeout_ms as u64))
                } else {
                    None
                },
                health_check: up
                    .health_check
                    .as_ref()
                    .filter(|h| h.enabled)
                    .map(|h| health_check_url(&name, h)),
                enable_backend_stats: multi_peer.then_some(true),
                circuit_break_max_consecutive_failures: multi_peer.then_some(5),
                circuit_break_max_failure_percent: multi_peer.then_some(50),
                circuit_break_min_requests_threshold: multi_peer.then_some(10),
                circuit_break_open_duration: multi_peer
                    .then_some(Duration::from_secs(10)),
                // With several origins, a misjudged health check or an
                // all-open breaker should degrade to the least-bad backend
                // instead of failing the site with instant 503s.
                enable_unhealthy_fallback: multi_peer.then_some(true),
                ..Default::default()
            };
            if up.is_default {
                default_key = Some(name.clone());
            }
            pool_keys.push(name.clone());
            upstreams.insert(name, conf);
        }

        // The `/` fallback location points at the default pool. Caches
        // written before pools existed mark nothing default, so the only
        // pool serves when no routes exist.
        let fallback_key = default_key.clone().or_else(|| {
            if site.routes.is_empty() {
                pool_keys.first().cloned()
            } else {
                None
            }
        });

        let host = if site.alternate_domains.is_empty() {
            site.domain.clone()
        } else {
            let mut hosts = vec![site.domain.clone()];
            hosts.extend(site.alternate_domains.clone());
            hosts.join(",")
        };

        let mut site_plugins = location_plugins.clone();
        site_plugins.extend(site_posture_plugins(
            site_id,
            site.ssl_config.as_ref(),
            &mut plugins,
        ));

        if let Some(key) = fallback_key {
            let loc_name = format!("{site_id}_loc");
            locations.insert(
                loc_name.clone(),
                LocationConf {
                    upstream: Some(key),
                    host: Some(host.clone()),
                    path: Some("/".to_string()),
                    plugins: Some(site_plugins.clone()),
                    // The fallback must sort behind every route: with the
                    // auto weight (128) any route whose priority was 127 or
                    // less ranked below this catch-all `/` location and
                    // never matched. Pin it to the floor instead.
                    weight: Some(0),
                    ..Default::default()
                },
            );
            location_names.push(loc_name);
        }

        for route in &site.routes {
            if !route.enabled {
                continue;
            }
            // Route only to pools this site actually built — an empty pool
            // has no upstream to receive traffic. Fall back to the site's
            // default pool instead of silently dropping the route.
            let target = if pool_keys.contains(&route.pool_id) {
                route.pool_id.clone()
            } else {
                match default_key.clone().or_else(|| pool_keys.first().cloned())
                {
                    Some(fallback) => {
                        warn!(
                            site = %site.domain,
                            route = %route.id,
                            pool = %route.pool_id,
                            "route pool has no peers; falling back to the site default pool"
                        );
                        fallback
                    },
                    None => {
                        warn!(
                            site = %site.domain,
                            route = %route.id,
                            "route pool has no peers and the site has no usable upstream; route skipped"
                        );
                        continue;
                    },
                }
            };
            let path = match route.match_type.as_str() {
                "exact" => format!("={}", route.path),
                "regex" => format!("~{}", route.path),
                _ => route.path.clone(),
            };
            let loc_name = format!("{site_id}_route_{}", route.id);
            locations.insert(
                loc_name.clone(),
                LocationConf {
                    upstream: Some(target),
                    host: Some(host.clone()),
                    path: Some(path),
                    weight: route
                        .priority
                        .map(|p| p.clamp(1, u16::MAX as i32) as u16),
                    // A route may be gated on an IP group; the location only
                    // matches clients inside those ranges.
                    match_ip_ranges: (!route.ip_ranges.is_empty())
                        .then(|| route.ip_ranges.clone()),
                    plugins: Some(site_plugins.clone()),
                    ..Default::default()
                },
            );
            location_names.push(loc_name);
        }

        // Convert SSL certificate: an uploaded PEM is served as-is, while a
        // site asking for ACME without one gets a certificate entry the
        // lets-encrypt task issues against — and later fills in — inside
        // this config.
        if let Some(ref ssl) = site.ssl_config
            && ssl.enabled
        {
            // A multi-domain certificate row carries its SAN list explicitly;
            // otherwise keep the historical site-domain fallback.
            let domains = if !ssl.domains.is_empty() {
                ssl.domains.join(",")
            } else if site.alternate_domains.is_empty() {
                site.domain.clone()
            } else {
                let mut d = vec![site.domain.clone()];
                d.extend(site.alternate_domains.clone());
                d.join(",")
            };
            let cert = if !ssl.cert_pem.is_empty() {
                Some(CertificateConf {
                    domains: Some(domains),
                    tls_cert: Some(ssl.cert_pem.clone()),
                    tls_key: Some(ssl.key_pem.clone()),
                    ..Default::default()
                })
            } else if ssl.acme_enabled && !ssl.acme_email.is_empty() {
                acme_certificate_conf(ssl, domains)
            } else {
                None
            };
            if let Some(cert) = cert {
                certificates.insert(format!("{site_id}_cert"), cert);
            }
        }

        // A site that turns mTLS on contributes its trust anchor to the
        // shared listener.
        if let Some(ssl) = site.ssl_config.as_ref()
            && ssl.mtls_enabled
            && !ssl.mtls_client_ca.trim().is_empty()
        {
            mtls_ca_bundle.push_str(ssl.mtls_client_ca.trim());
            mtls_ca_bundle.push('\n');
        }
    }

    // The dashboard's own certificate (Settings -> System TLS -> auto-issue).
    // It is issued by the same ACME task through the same HTTP-01 handler,
    // which answers for any host - so a dashboard *domain* that is not a
    // proxied site works too. The data plane never serves it; it exists so
    // the ACME task can fill it in, and the material is handed back to the
    // control plane after each reload.
    //
    // Seed it with the pair already installed. Without the seed, a rebuilt
    // config starts with an empty pair, the ACME task reads that as "not
    // issued yet", and every restart (or reload) orders a duplicate
    // certificate until the CA's rate limit stops it.
    if let Some(request) = varman_control::management_cert::desired() {
        let seed = varman_control::management_cert::seed();
        certificates.insert(
            varman_control::management_cert::CERT_NAME.to_string(),
            CertificateConf {
                domains: Some(request.identity.clone()),
                acme: Some(format!("http://{}", request.email)),
                tls_cert: seed.as_ref().map(|seed| seed.cert_pem.clone()),
                tls_key: seed.as_ref().map(|seed| seed.key_pem.clone()),
                ..Default::default()
            },
        );
    }

    if location_names.is_empty() {
        return None;
    }

    // TLS is a per-server switch in pingap: `global_certificates` turns it
    // on for every address that server listens on, so 80 and 443 cannot
    // share one server — a merged listener ran plaintext HTTP through TLS
    // handshakes, which also broke ACME HTTP-01 validation on port 80.
    //
    // 443 is bound even before the first certificate exists: the listener
    // comes up with an empty provider and handshakes fail until issuance
    // completes, but the moment a certificate is issued or uploaded the
    // provider serves it — no restart, no listener rebuild. Binding 443
    // only once a certificate existed left fresh deployments with the port
    // closed until the whole process restarted.
    if certificates.is_empty() {
        warn!(
            "data plane: no certificates yet — TLS handshakes on 443 will \
             fail until one is issued or uploaded"
        );
    }
    let mut servers: HashMap<String, PingapServerConf> = HashMap::new();
    servers.insert(
        "varman".to_string(),
        PingapServerConf {
            addr: "0.0.0.0:80".to_string(),
            locations: Some(location_names.clone()),
            global_certificates: Some(false),
            ..Default::default()
        },
    );
    servers.insert(
        "varman_tls".to_string(),
        PingapServerConf {
            addr: "0.0.0.0:443".to_string(),
            locations: Some(location_names),
            global_certificates: Some(true),
            client_ca_pem: (!mtls_ca_bundle.is_empty())
                .then_some(mtls_ca_bundle),
            ..Default::default()
        },
    );

    Some(PingapConfig {
        basic: BasicConf::default(),
        upstreams,
        locations,
        servers,
        certificates,
        plugins,
        ..Default::default()
    })
}

/// Build a `PingapConfig` from the agent's cached rules.
pub(super) fn build_pingap_config(
    rule_cache: &RuleCache,
) -> Option<PingapConfig> {
    cached_rules_to_pingap_config(
        &rule_cache.all_sites(),
        rule_cache.cache_dir(),
    )
}
