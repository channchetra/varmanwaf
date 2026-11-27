use super::*;

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

/// Build a `PingapConfig` from the agent's cached site rules.
///
/// Each origin pool becomes one upstream keyed by its pool id (or the
/// legacy per-site name for caches written before pools existed). The
/// default pool — or the only pool, when no routes exist — receives the
/// site's `/` fallback location, and every enabled route becomes an
/// additional location carrying the pingap path marker for its match
/// type. All sites share a single server listening on ports 80 and 443
/// with TLS enabled via the global certificate store.
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
fn build_pingap_config(rule_cache: &RuleCache) -> Option<PingapConfig> {
    cached_rules_to_pingap_config(
        &rule_cache.all_sites(),
        rule_cache.cache_dir(),
    )
}

/// Build the certificate entry a lets-encrypt issuance is driven by.
///
/// `acme` is only a marker (never parsed); the email keeps the convention
/// legacy pingap used so operators recognize it in a config dump. DNS-01
/// carries the provider plus credentials: the endpoint defaults to the
/// provider's API host and every `acme_dns_config` entry becomes a query
/// pair — the layout pingap's DNS tasks parse.
/// Returns `None` when the order cannot be issued and must be skipped:
/// a wildcard hostname only validates through DNS-01, so an entry that would
/// fall back to HTTP-01 is dropped (with an error log) instead of making the
/// lets-encrypt task retry a doomed order forever. The API refuses the same
/// combination, so this only fires for rows written before that check existed.
pub(super) fn acme_certificate_conf(
    ssl: &SslConfig,
    domains: String,
) -> Option<CertificateConf> {
    let wildcard = domains
        .split(',')
        .any(|domain| domain.trim().starts_with("*."));
    let mut cert = CertificateConf {
        domains: Some(domains.clone()),
        acme: Some(format!("http://{}", ssl.acme_email)),
        ..Default::default()
    };
    if ssl.acme_challenge_type != "AcmeDns01" {
        if wildcard {
            error!(
                domains = %domains,
                "wildcard hostnames need the dns-01 ACME challenge; skipping issuance for the http-01 order"
            );
            return None;
        }
        return Some(cert);
    }
    let provider = match normalize_dns_provider(&ssl.acme_dns_provider) {
        // Unknown provider: stay on HTTP-01 rather than emit an entry the
        // config validation rejects outright.
        Some(provider) => provider,
        None if wildcard => {
            error!(
                domains = %domains,
                "wildcard hostnames need a configured DNS provider for dns-01; skipping issuance"
            );
            return None;
        },
        None => return Some(cert),
    };
    if provider == "manual" {
        // Manual mode renders no dns fields, i.e. the order falls back to
        // HTTP-01, which a wildcard can never pass.
        if wildcard {
            error!(
                domains = %domains,
                "the manual dns-01 provider cannot validate a wildcard automatically; skipping issuance"
            );
            return None;
        }
        return Some(cert);
    }
    cert.dns_challenge = Some(true);
    cert.dns_provider = Some(provider.to_string());
    if let Some(url) = acme_dns_service_url(provider, &ssl.acme_dns_config) {
        cert.dns_service_url = Some(url);
    }
    Some(cert)
}

/// The DNS provider endpoint with credentials appended as query pairs.
///
/// An explicit `endpoint` entry (full URL, or host getting the default
/// scheme) wins; `region` is only used to build the Huawei cloud host.
/// Without either, the provider's documented API host applies — Huawei has
/// per-region hosts and cannot have one. Every other entry becomes
/// `key=value` — names match what the provider task expects, e.g.
/// `access_key_id` / `access_key_secret` / `token`.
fn acme_dns_service_url(
    provider: &str,
    config: &HashMap<String, String>,
) -> Option<String> {
    let base = match config.get("endpoint").filter(|v| !v.is_empty()) {
        Some(v) if v.contains("://") => v.clone(),
        Some(v) => format!("https://{v}"),
        None => {
            if let Some(region) = config.get("region").filter(|r| !r.is_empty())
            {
                format!("https://dns.{region}.myhuaweicloud.com")
            } else if provider == "huawei" {
                warn!(
                    "acme dns-01: huawei needs a region or endpoint, \
                     issuance will need manual DNS"
                );
                return None;
            } else {
                // Providers accepted by acme_certificate_conf all have a
                // documented host; the tasks error out on an empty URL.
                let host = match provider {
                    "ali" => "alidns.aliyuncs.com",
                    "cf" => "api.cloudflare.com",
                    "tencent" => "dnspod.tencentcloudapi.com",
                    _ => {
                        warn!(
                            "acme dns-01: no endpoint configured for \
                             {provider}, issuance will need manual DNS"
                        );
                        return None;
                    },
                };
                format!("https://{host}")
            }
        },
    };
    let mut pairs: Vec<String> = config
        .iter()
        .filter(|(k, _)| !matches!(k.as_str(), "endpoint" | "region"))
        .map(|(k, v)| {
            format!("{}={}", urlencoding::encode(k), urlencoding::encode(v))
        })
        .collect();
    pairs.sort();
    if pairs.is_empty() {
        return Some(base);
    }
    Some(format!("{base}?{}", pairs.join("&")))
}

/// The agent's ACME state file: the memory config manager mirrors every
/// write there, so issued certificates and challenge tokens survive a
/// restart (Let's Encrypt caps duplicate certificates per week, and a
/// stateless restart would burn that quota).
fn acme_state_path(rule_cache: &RuleCache) -> PathBuf {
    rule_cache.cache_dir().join("acme_state.toml")
}

/// Merge a freshly converted config with a previous one, carrying over the
/// state only the lets-encrypt task produces: issued PEMs (filled into
/// certificate entries the new config left empty) and the whole `storages`
/// section — challenge tokens and ACME account credentials. Uploads always
/// win: a new config that carries its own PEM is never overwritten.
pub(super) fn merge_config_state(new_toml: &str, prev_toml: &str) -> String {
    if prev_toml.trim().is_empty() {
        return new_toml.to_string();
    }
    let Ok(mut doc) = new_toml.parse::<toml::Table>() else {
        return new_toml.to_string();
    };
    let Ok(prev) = prev_toml.parse::<toml::Table>() else {
        return new_toml.to_string();
    };

    if let Some(prev_certs) =
        prev.get("certificates").and_then(|v| v.as_table())
    {
        let certs = doc
            .entry("certificates")
            .or_insert(toml::Value::Table(toml::Table::new()));
        if let Some(certs) = certs.as_table_mut() {
            for (name, prev_cert) in prev_certs {
                let pem = prev_cert
                    .get("tls_cert")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                if pem.is_empty() {
                    continue;
                }
                let Some(cert) = certs.get_mut(name) else {
                    continue;
                };
                // A certificate whose identity set changed (e.g. the
                // dashboard request was edited from one domain/IP to
                // another) must not inherit the old PEM: that certificate
                // does not cover the new name and would suppress issuance.
                let prev_domains = prev_cert
                    .get("domains")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let new_domains = cert
                    .get("domains")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                if prev_domains != new_domains {
                    continue;
                }
                let has_pem = cert
                    .get("tls_cert")
                    .and_then(|v| v.as_str())
                    .is_some_and(|v| !v.is_empty());
                if has_pem {
                    continue;
                }
                if let Some(cert) = cert.as_table_mut() {
                    cert.insert(
                        "tls_cert".to_string(),
                        toml::Value::String(pem.to_string()),
                    );
                    if let Some(key) = prev_cert.get("tls_key") {
                        cert.insert("tls_key".to_string(), key.clone());
                    }
                }
            }
        }
    }

    if let Some(storages) = prev.get("storages") {
        doc.insert("storages".to_string(), storages.clone());
    }

    toml::to_string_pretty(&doc).unwrap_or_else(|_| new_toml.to_string())
}

/// Hands the certificate the edge issued for the dashboard to the control
/// plane, which installs it on the 9080 listener and persists it.
///
/// The ACME task fills the `__management` entry; publishing the same material
/// again is harmless (the installer compares fingerprints, so a renewal is
/// installed exactly once and a restart does not re-install).
fn publish_management_certificate(config: &PingapConfig) {
    let Some(cert) = config
        .certificates
        .get(varman_control::management_cert::CERT_NAME)
    else {
        return;
    };
    let (Some(cert_pem), Some(key_pem)) =
        (cert.tls_cert.as_ref(), cert.tls_key.as_ref())
    else {
        return;
    };
    if cert_pem.is_empty() || key_pem.is_empty() {
        return;
    }
    varman_control::management_cert::set_issued(Some(
        varman_control::management_cert::Issued {
            identity: cert.domains.clone().unwrap_or_default(),
            cert_pem: cert_pem.clone(),
            key_pem: key_pem.clone(),
        },
    ));
}

/// Start the Pingora-based data plane proxy from the agent's cached rules.
///
/// Waits for the agent to receive its initial configuration from the
/// control plane, then builds a PingapConfig and starts the reverse proxy
/// on ports 80 and 443.
pub(super) async fn start_data_plane(
    rule_cache: Arc<RuleCache>,
) -> anyhow::Result<()> {
    // Wait for the agent to receive initial config from the control plane
    for i in 0..30 {
        let cached = rule_cache.all_sites();
        if !cached.sites.is_empty() {
            break;
        }
        if i == 0 {
            info!("data plane: waiting for control plane configuration...");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let config = match build_pingap_config(&rule_cache) {
        Some(config) => config,
        None => {
            warn!("data plane: no sites configured, proxy not started");
            // Keep waiting — the agent may receive config later
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                if let Some(config) = build_pingap_config(&rule_cache) {
                    break config;
                }
            }
        },
    };

    let site_count = config
        .servers
        .values()
        .flat_map(|s| s.locations.as_deref().unwrap_or_default())
        .count();
    info!(
        upstreams = config.upstreams.len(),
        locations = config.locations.len(),
        certificates = config.certificates.len(),
        "data plane: starting reverse proxy with {} site(s)",
        site_count,
    );

    // Serialize to TOML and create a memory-backed config manager. The
    // freshly converted config is merged with the ACME state left by the
    // previous run first, so already-issued certificates are served (and
    // not reordered) from the first request on.
    let toml_str = toml::to_string_pretty(&config).map_err(|e| {
        anyhow::anyhow!("failed to serialize proxy config: {}", e)
    })?;
    let acme_state = acme_state_path(&rule_cache);
    let toml_str = merge_config_state(
        &toml_str,
        &std::fs::read_to_string(&acme_state).unwrap_or_default(),
    );
    let config_manager =
        try_init_memory_config_manager(&toml_str, Some(acme_state)).map_err(
            |e| anyhow::anyhow!("failed to init config manager: {}", e),
        )?;

    // The lets-encrypt task scans current_config for certificates to issue,
    // so it must reflect the merged state; validation keeps a malformed
    // merge from taking the proxy down (falls back to the fresh config).
    let config = match PingapTomlConfig::from_toml(&toml_str)
        .and_then(|toml_config| toml_config.to_pingap_config(true))
    {
        Ok(merged) => merged,
        Err(e) => {
            warn!(
                error = %e,
                "data plane: merged config failed validation, using freshly converted config"
            );
            config
        },
    };
    config_manager.set_current_config(config.clone());
    publish_management_certificate(&config);

    // Initialize providers from the (merged) config
    try_init_upstreams(&config.upstreams, crate::webhook::get_webhook_sender())
        .map_err(|e| anyhow::anyhow!("failed to init upstreams: {}", e))?;
    try_init_locations(&config.locations)
        .map_err(|e| anyhow::anyhow!("failed to init locations: {}", e))?;
    try_init_server_locations(&config.servers, &config.locations).map_err(
        |e| anyhow::anyhow!("failed to init server locations: {}", e),
    )?;

    // Activate the WAF plugin: without it the data plane forwards traffic
    // uninspected and no access/security events are ever emitted.
    let (updated_plugins, plugin_errors) = try_init_plugins(&config.plugins);
    if !updated_plugins.is_empty() {
        info!(
            plugins = updated_plugins.join(","),
            "data plane: plugins initialized"
        );
    }
    if !plugin_errors.is_empty() {
        error!(error = plugin_errors, "data plane: plugin init errors");
    }

    // Initialize certificates
    let cert_provider = new_certificate_provider();
    if !config.certificates.is_empty() {
        let (updated, errors) = try_update_certificates(&config.certificates);
        if !updated.is_empty() {
            info!(certs = updated.join(","), "data plane: certificates loaded");
        }
        if !errors.is_empty() {
            error!(error = errors, "data plane: certificate parse errors");
        }
    }

    // Let the agent report certificate state: the ACME task writes issued PEMs
    // into the provider below, and without this the control plane keeps showing
    // the certificate as pending forever. Certificates generated from site
    // config are named `{site_id}_cert`, which is how a status is attributed
    // back to its site.
    {
        let provider = cert_provider.clone();
        varman_agent::cert_status::set_snapshot(Some(Arc::new(move || {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_secs() as i64)
                .unwrap_or_default();
            let mut statuses = HashMap::new();
            for cert in provider.list().values() {
                let Some(site_id) = cert
                    .name
                    .as_deref()
                    .and_then(|name| name.strip_suffix("_cert"))
                else {
                    continue;
                };
                let Some(info) = cert.info.as_ref() else {
                    continue;
                };
                if info.not_after == 0 {
                    continue;
                }
                let remaining = info.not_after - now;
                let status = if remaining <= 0 {
                    "expired"
                } else if remaining <= 2 * 24 * 3600 {
                    "expiring_soon"
                } else {
                    "valid"
                };
                // One certificate is listed under every domain it serves; the
                // entries agree, so the first one wins.
                statuses.entry(site_id.to_string()).or_insert(
                    varman_agent::cert_status::CertStatus {
                        status,
                        expires_at: info.not_after,
                    },
                );
            }
            statuses
        })));
    }

    // Create the Pingora server
    let opt = Opt::default();
    let server_conf = crate::new_server_config_from(false, None, &config);
    let mut my_server =
        server::Server::new_with_opt_and_conf(Some(opt), server_conf);
    let bootstrap_handle = my_server.bootstrap_as_a_service();

    // ACME (Let's Encrypt): issue and renew certificates for sites whose
    // The ACME task must exist even when no certificate is configured at
    // start-up: certificates are created at runtime (the console, the API)
    // and the task re-reads the live config every cycle, so a task that was
    // never registered leaves runtime-created orders unprocessed - the row
    // sits `pending` and the stale sweeper eventually fails it with a
    // generic reason. With no ACME certificates the task is a cheap no-op.
    // PINGAP_DISABLE_ACME opts out entirely.
    let acme_enabled = std::env::var("PINGAP_DISABLE_ACME")
        .unwrap_or_default()
        .is_empty();
    let mut background_tasks = BackgroundTaskService::new(
        "data_plane_background_tasks",
        Duration::from_secs(60),
        vec![],
    );
    background_tasks.set_immediately(true);
    background_tasks.set_initial_delay(Some(Duration::from_secs(3)));
    // A stalled ACME cycle is mirrored onto the `pingap::acme` target, which
    // the agent's certificate-event capture ships to the control plane — so
    // an issuance that hangs shows up in the panel's certificate log instead
    // of only in the data plane's own log file.
    background_tasks.set_on_stalled(Some(Box::new(|name, tasks, elapsed| {
        warn!(
            target: "pingap::acme",
            name,
            tasks,
            elapsed,
            "background tasks still running past the interval"
        );
    })));
    // The same loops the file-configured data plane registers. Without them
    // an agent-hosted plane never notices an expiring certificate, never
    // rotates a stale self-signed pair and never clears old storage.
    background_tasks.add_task(
        "validity_checker",
        pingap_certificate::new_certificate_validity_service(
            cert_provider.clone(),
            crate::webhook::get_webhook_sender(),
        ),
    );
    background_tasks.add_task(
        "self_signed_certificate_stale",
        pingap_certificate::new_self_signed_certificate_validity_service(),
    );
    background_tasks.add_task(
        "performance_metrics",
        pingap_performance::new_performance_metrics_log_service(
            new_location_provider(),
            new_upstream_provider(),
        ),
    );
    if let Some(task) = pingap_cache::new_storage_clear_service() {
        background_tasks.add_task("storage_clear", task);
    }
    if acme_enabled {
        background_tasks.add_task(
            "lets_encrypt",
            new_lets_encrypt_service(
                config_manager.clone(),
                cert_provider.clone(),
                crate::webhook::get_webhook_sender(),
            ),
        );
        info!("data plane: ACME certificate management enabled");
    }
    let background_tasks_name = background_tasks.name().to_string();
    my_server.add_service(background_service(
        &background_tasks_name,
        background_tasks,
    ));

    // Parse server configs and start proxy servers
    let server_conf_list: Vec<ServerConf> = parse_from_conf(config.clone());

    for server_conf in server_conf_list {
        let ctx = AppContext {
            server_locations_provider: new_server_locations_provider(),
            location_provider: new_location_provider(),
            upstream_provider: new_upstream_provider(),
            plugin_provider: new_plugin_provider(),
            certificate_provider: cert_provider.clone(),
            config_manager: config_manager.clone(),
            logger: None,
        };
        let mut ps = ProxyServer::new(&server_conf, ctx)?;
        // The HTTP-01 challenge must be reachable on port 80, so every
        // data-plane server whose address list includes :80 intercepts
        // /.well-known/acme-challenge before proxying.
        if acme_enabled
            && server_conf
                .addr
                .split(',')
                .any(|addr| addr.trim().ends_with(":80"))
        {
            ps.enable_lets_encrypt();
        }
        let services = ps.run(my_server.configuration.clone())?;
        my_server
            .add_service(services.lb)
            .add_dependency(&bootstrap_handle);
    }

    info!(
        addrs = %config
            .servers
            .values()
            .map(|s| s.addr.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        "data plane: proxy server is running"
    );

    // Start the upstream health check background task.
    // This also drives periodic DNS discovery updates — without it,
    // DNS-based backends are never resolved and requests get 503.
    let upstream_health_check_task = new_upstream_health_check_task(
        new_upstream_provider(),
        Duration::from_secs(10),
        None,
    );
    let hc_name = upstream_health_check_task.name().to_string();
    info!(
        service_name = %hc_name,
        "data plane: registering upstream health check background service"
    );
    my_server
        .add_service(background_service(&hc_name, upstream_health_check_task));

    // Run Pingora in a dedicated OS thread. Do NOT join it here —
    // joining would block the tokio worker thread permanently and starve
    // the control-plane REST/gRPC servers (especially on small machines).
    // The thread exits when the process shuts down.
    std::thread::spawn(move || {
        my_server.run_forever();
    });

    // Access log entries are held until the response body completes so the
    // log can carry the response payload. A client that disconnects mid-body
    // never fires the end-of-stream callback, so stale entries are swept
    // periodically: they are still emitted (flagged truncated) so the request
    // never vanishes from the log, and the map cannot grow without bound.
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let swept = pingap_plugin::sweep_stale_access(
                pingap_plugin::PENDING_ACCESS_SWEEP_TTL,
            );
            if swept > 0 {
                info!(
                    count = swept,
                    "data plane: swept stale pending access entries"
                );
            }
        }
    });

    // Hot-reload watcher: poll the rule cache config hash and re-init the
    // ArcSwap providers when the control plane pushes new rules. The proxy
    // reads these providers per request, so no restart is needed. The config
    // manager itself is updated in place: on every reload the freshly
    // converted config is merged with the previous document (preserving
    // issued PEMs and ACME state such as challenge tokens and the account
    // key) and set as current, so the ACME renewal task keeps working.
    let watcher_cache = Arc::clone(&rule_cache);
    let watcher_config_manager = Arc::clone(&config_manager);
    let mut last_hash = watcher_cache.data_plane_hash();
    let mut last_management = varman_control::management_cert::revision();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let hash = watcher_cache.data_plane_hash();
            let management = varman_control::management_cert::revision();
            if hash == last_hash && management == last_management {
                continue;
            }
            info!(
                old = %last_hash,
                new = %hash,
                "data plane: rule change detected, reloading"
            );
            let Some(converted) = build_pingap_config(&watcher_cache) else {
                warn!(
                    "data plane: reload produced no usable config, keeping current"
                );
                last_hash = hash;
                last_management = management;
                continue;
            };
            let Ok(new_toml) = toml::to_string_pretty(&converted) else {
                error!(
                    "data plane: reload config serialization failed, keeping current"
                );
                last_hash = hash;
                last_management = management;
                continue;
            };
            // Fetch-merge-save must be atomic with respect to ACME's own
            // read-modify-write: an issuance completing while the reload was
            // reading a PEM-less snapshot used to be clobbered by the reload
            // save, dropping the certificate from storage (and then from the
            // SNI table on the next provider rebuild).
            let config = match watcher_config_manager
                .update_raw(|prev_toml| {
                    merge_config_state(&new_toml, &prev_toml)
                })
                .await
            {
                Ok(config) => config,
                Err(e) => {
                    warn!(
                        error = %e,
                        "data plane: merged reload config failed, using freshly converted config"
                    );
                    converted
                },
            };
            watcher_config_manager.set_current_config(config.clone());
            publish_management_certificate(&config);
            if let Err(e) = try_init_upstreams(&config.upstreams, None) {
                error!(error = %e, "data plane: reload upstreams failed");
            }
            if let Err(e) = try_init_locations(&config.locations) {
                error!(error = %e, "data plane: reload locations failed");
            }
            if let Err(e) =
                try_init_server_locations(&config.servers, &config.locations)
            {
                error!(error = %e, "data plane: reload server locations failed");
            }
            let (updated, errors) =
                try_update_certificates(&config.certificates);
            if !updated.is_empty() {
                info!(
                    certs = updated.join(","),
                    "data plane: certificates reloaded"
                );
            }
            if !errors.is_empty() {
                error!(error = errors, "data plane: certificate reload errors");
            }
            let (updated_plugins, plugin_errors) =
                try_init_plugins(&config.plugins);
            if !updated_plugins.is_empty() {
                info!(
                    plugins = updated_plugins.join(","),
                    "data plane: plugins reloaded"
                );
            }
            if !plugin_errors.is_empty() {
                error!(
                    error = plugin_errors,
                    "data plane: plugin reload errors"
                );
            }
            last_hash = hash;
            last_management = management;
        }
    });

    // The ACME task fills the `__management` entry in place, without changing
    // the config hash, so the reload hooks above never see the issued material.
    // Publish it on a timer instead: the installer compares fingerprints, so
    // repeating the same certificate is a no-op.
    let management_config = Arc::clone(&config_manager);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            publish_management_certificate(
                &management_config.get_current_config(),
            );
        }
    });

    // Keep the async task alive until the tokio runtime shuts down.
    // The caller (run()) aborts this task on shutdown signal.
    std::future::pending::<()>().await;
    Ok(())
}
