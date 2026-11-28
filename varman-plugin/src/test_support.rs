//! Fixtures shared by this crate's plugin tests.

use pingora::proxy::Session;
use std::sync::Arc;
use tokio_test::io::Builder;
use varman_agent::VarmanAgent;

/// Serializes tests that install the process-wide agent.
pub(crate) static AGENT_LOCK: tokio::sync::Mutex<()> =
    tokio::sync::Mutex::const_new(());

pub(crate) async fn lock_agent() -> tokio::sync::MutexGuard<'static, ()> {
    AGENT_LOCK.lock().await
}

/// Builds an H1 session preloaded with a single request.
pub(crate) async fn h1_session(
    method: &str,
    target: &str,
    host: &str,
) -> Session {
    let input = format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\n\r\n");
    let mock_io = Builder::new().read(input.as_bytes()).build();
    let mut s = Session::new_h1(Box::new(mock_io));
    s.read_request().await.expect("read_request");
    s
}

/// Installs a never-connecting agent for the duration of one test.
pub(crate) async fn install_test_agent() -> (
    tokio::sync::MutexGuard<'static, ()>,
    Arc<VarmanAgent>,
    tempfile::TempDir,
) {
    use varman_agent::cache::RuleCache;
    use varman_agent::client::ControlPlaneClient;
    use varman_agent::config::AgentConfig;
    use varman_agent::heartbeat::MetricsCollector;

    let lock = lock_agent().await;
    let dir = tempfile::tempdir().expect("test temp dir");
    let config = AgentConfig {
        cache_dir: dir.path().to_string_lossy().to_string(),
        ..Default::default()
    };
    let rule_cache =
        RuleCache::new(dir.path().to_path_buf(), "test-agent".to_string())
            .expect("test rule cache");
    let metrics = Arc::new(MetricsCollector::new());
    let client = Arc::new(ControlPlaneClient::new(
        config.clone(),
        Arc::clone(&rule_cache),
        Arc::clone(&metrics),
    ));
    let agent = Arc::new(VarmanAgent {
        config,
        client,
        rule_cache,
        metrics,
    });
    VarmanAgent::set_agent_instance(Some(Arc::clone(&agent)));
    (lock, agent, dir)
}
