use std::collections::HashMap;
use std::path::PathBuf;

use pingap_config::{CertificateConf, PingapConfig, normalize_dns_provider};
use tracing::{error, warn};
use varman_agent::cache::{RuleCache, SslConfig};

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
pub(super) fn acme_state_path(rule_cache: &RuleCache) -> PathBuf {
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
pub(super) fn publish_management_certificate(config: &PingapConfig) {
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
