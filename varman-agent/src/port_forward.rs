//! Edge-side TCP port forwarding.
//!
//! The control plane owns the rules; this task watches the agent's rule cache
//! and keeps one listener per enabled forward. Each accepted connection is
//! checked against the rule's allowlist before the target is dialled.

use crate::cache::{PortForward, RuleCache};
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tracing::{info, warn};

/// How often the cache is diffed for added/removed/changed rules.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(2);
/// Target connect budget for one accepted client.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// A listen port that is still in use is retried after this delay.
const BIND_RETRY: Duration = Duration::from_secs(5);

struct Active {
    handle: JoinHandle<()>,
    rule: PortForward,
}

/// Starts the manager task. It lives for the process lifetime; on shutdown the
/// listeners disappear with the runtime.
pub fn spawn(cache: Arc<RuleCache>) {
    tokio::spawn(async move {
        let mut active: HashMap<String, Active> = HashMap::new();
        let mut retry_at: HashMap<String, Instant> = HashMap::new();

        loop {
            let desired: HashMap<String, PortForward> = cache
                .port_forwards()
                .into_iter()
                .filter(|rule| rule.enabled)
                .map(|rule| (rule.id.clone(), rule))
                .collect();

            // Stop listeners whose rule was removed or edited. A changed
            // target/allowlist needs a fresh task; an unchanged rule keeps its
            // existing sockets.
            let ids: Vec<String> = active.keys().cloned().collect();
            for id in ids {
                let keep = match (desired.get(&id), active.get(&id)) {
                    (Some(rule), Some(current)) => {
                        same_rule(rule, &current.rule)
                    },
                    _ => false,
                };
                if !keep {
                    if let Some(current) = active.remove(&id) {
                        current.handle.abort();
                        info!(
                            forward = %id,
                            listen_port = current.rule.listen_port,
                            "port forward listener stopped"
                        );
                        // `abort` completes asynchronously; binding the same
                        // port in this iteration races the old socket. Wait
                        // one reconcile cycle before rebinding.
                        retry_at
                            .insert(id, Instant::now() + RECONCILE_INTERVAL);
                    }
                }
            }

            for (id, rule) in desired {
                if active.contains_key(&id) {
                    continue;
                }
                if retry_at.get(&id).is_some_and(|at| *at > Instant::now()) {
                    continue;
                }
                match bind_listener(rule.clone()).await {
                    Ok(handle) => {
                        info!(
                            forward = %id,
                            site = %rule.site_id,
                            listen_port = rule.listen_port,
                            target = %format!("{}:{}", rule.target_host, rule.target_port),
                            allowed = ?rule.allowed_cidrs,
                            "port forward listener started"
                        );
                        retry_at.remove(&id);
                        active.insert(id, Active { handle, rule });
                    },
                    Err(err) => {
                        warn!(
                            forward = %id,
                            listen_port = rule.listen_port,
                            error = %err,
                            "port forward listener could not bind"
                        );
                        retry_at.insert(id, Instant::now() + BIND_RETRY);
                    },
                }
            }

            tokio::time::sleep(RECONCILE_INTERVAL).await;
        }
    });
}

async fn bind_listener(rule: PortForward) -> std::io::Result<JoinHandle<()>> {
    let listener =
        TcpListener::bind(("0.0.0.0", rule.listen_port as u16)).await?;
    let allow = parse_allowed(&rule.allowed_cidrs);
    let target = format!("{}:{}", rule.target_host, rule.target_port);
    let site = rule.site_id.clone();
    let id = rule.id.clone();
    let listen_port = rule.listen_port;

    Ok(tokio::spawn(async move {
        loop {
            let (mut inbound, peer) = match listener.accept().await {
                Ok(value) => value,
                Err(err) => {
                    warn!(
                        forward = %id,
                        listen_port,
                        error = %err,
                        "port forward accept failed"
                    );
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                },
            };

            if !allow.iter().any(|net| net.contains(&peer.ip())) {
                warn!(
                    forward = %id,
                    site = %site,
                    listen_port,
                    client = %peer,
                    "port forward connection denied by allowlist"
                );
                drop(inbound);
                continue;
            }

            let target = target.clone();
            let site = site.clone();
            let id = id.clone();
            tokio::spawn(async move {
                match tokio::time::timeout(
                    CONNECT_TIMEOUT,
                    TcpStream::connect(&target),
                )
                .await
                {
                    Ok(Ok(mut outbound)) => {
                        info!(
                            forward = %id,
                            site = %site,
                            listen_port,
                            client = %peer,
                            target = %target,
                            "port forward connection opened"
                        );
                        let _ = copy_bidirectional(&mut inbound, &mut outbound)
                            .await;
                    },
                    Ok(Err(err)) => {
                        warn!(
                            forward = %id,
                            site = %site,
                            target = %target,
                            error = %err,
                            "port forward target connect failed"
                        );
                    },
                    Err(_) => {
                        warn!(
                            forward = %id,
                            site = %site,
                            target = %target,
                            "port forward target connect timed out"
                        );
                    },
                }
            });
        }
    }))
}

fn parse_allowed(values: &[String]) -> Vec<IpNet> {
    values
        .iter()
        .filter_map(|value| {
            let value = value.trim();
            if let Ok(net) = value.parse::<IpNet>() {
                return Some(net);
            }
            value.parse::<IpAddr>().ok().and_then(|ip| {
                IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 }).ok()
            })
        })
        .collect()
}

fn same_rule(a: &PortForward, b: &PortForward) -> bool {
    a.listen_port == b.listen_port
        && a.target_host == b.target_host
        && a.target_port == b.target_port
        && a.allowed_cidrs == b.allowed_cidrs
        && a.enabled == b.enabled
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlists_accept_cidrs_and_bare_addresses() {
        let rules = parse_allowed(&[
            "10.0.0.0/8".to_string(),
            "203.0.113.7".to_string(),
            "2001:db8::/32".to_string(),
            "not-an-ip".to_string(),
        ]);
        assert_eq!(rules.len(), 3);
        assert!(rules[0].contains(&"10.1.2.3".parse::<IpAddr>().unwrap()));
        assert!(rules[1].contains(&"203.0.113.7".parse::<IpAddr>().unwrap()));
        assert!(rules[2].contains(&"2001:db8::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn rule_change_is_detected() {
        let rule = PortForward {
            id: "f1".to_string(),
            site_id: "s1".to_string(),
            name: "ssh".to_string(),
            listen_port: 10_000,
            target_host: "10.1.18.5".to_string(),
            target_port: 22,
            allowed_cidrs: vec!["203.0.113.7".to_string()],
            enabled: true,
        };
        assert!(same_rule(&rule, &rule));
        let mut changed = rule.clone();
        changed.target_port = 2222;
        assert!(!same_rule(&rule, &changed));
        let mut allow = rule.clone();
        allow.allowed_cidrs = vec!["10.0.0.0/8".to_string()];
        assert!(!same_rule(&rule, &allow));
    }
}
