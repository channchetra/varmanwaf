//! Boot smoke tests for the `pingap` binary.
//!
//! These spawn the compiled binary so the argument parsing, config loading
//! and validation wired up in `src/main.rs` are exercised as a whole. No
//! listener is started: `--template` and `--version` return before the server
//! is assembled, and `-t` exits right after validation.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// A minimal HTTP-only configuration: one upstream, one location and one
/// server on a port the kernel can hand out, no TLS and no ACME.
const MINIMAL_CONFIG: &str = r#"
[basic]
name = "boot-smoke"

[upstreams.backend]
addrs = ["127.0.0.1:9"]

[locations.root]
path = "/"
upstream = "backend"

[servers.http]
addr = "127.0.0.1:0"
locations = ["root"]
"#;

/// A server without `addr` cannot listen, so `-t` has to reject it.
const INVALID_CONFIG: &str = r#"
[basic]
name = "boot-smoke-invalid"

[locations.root]
path = "/"

[servers.http]
locations = ["root"]
"#;

/// The same minimal proxy with JSON logs, so the startup line can be checked
/// without parsing the human-readable format.
const ENV_CONFIG: &str = r#"
[basic]
name = "boot-smoke-env"
log_format_json = true

[upstreams.backend]
addrs = ["127.0.0.1:9"]

[locations.root]
path = "/"
upstream = "backend"

[servers.http]
addr = "127.0.0.1:0"
locations = ["root"]
"#;

/// The binary under test, with `PINGAP_*` removed so a developer's own
/// environment cannot change what these cases exercise.
fn pingap() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pingap"));
    for (key, _) in std::env::vars_os() {
        let key = key.to_string_lossy();
        if key.starts_with("PINGAP_") {
            command.env_remove(key.as_ref());
        }
    }
    command
}

fn run(args: &[&str]) -> Output {
    match pingap().args(args).output() {
        Ok(output) => output,
        Err(error) => panic!("failed to run pingap {args:?}: {error}"),
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn write_config(dir: &tempfile::TempDir, name: &str, body: &str) -> PathBuf {
    let path = dir.path().join(name);
    if let Err(error) = std::fs::write(&path, body) {
        panic!("failed to write {}: {error}", path.display());
    }
    path
}

/// Every log file under `dir`, concatenated. The rolling appender suffixes
/// the file name with the date, so the exact path is not predictable.
fn read_logs(dir: &std::path::Path) -> String {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return String::new();
    };
    let mut logs = String::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file()
            && let Ok(body) = std::fs::read_to_string(&path)
        {
            logs.push_str(&body);
        }
    }
    logs
}

#[test]
fn template_prints_a_config_with_a_basic_section() {
    // Arrange & Act
    let output = run(&["--template"]);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    // Assert
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout.contains("[basic]"), "template output: {stdout}");
}

#[test]
fn version_flag_exits_zero() {
    // Arrange & Act
    let output = run(&["--version"]);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    // Assert
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "version output: {stdout}"
    );
}

#[test]
fn test_mode_accepts_a_minimal_http_config() {
    // Arrange
    let dir = match tempfile::TempDir::new() {
        Ok(dir) => dir,
        Err(error) => panic!("failed to create temp dir: {error}"),
    };
    let conf = write_config(&dir, "ok.toml", MINIMAL_CONFIG);
    let conf = conf.to_string_lossy().to_string();

    // Act
    let output = run(&["-t", "-c", &conf]);

    // Assert
    assert!(output.status.success(), "stderr: {}", stderr(&output));
}

#[test]
fn test_mode_rejects_a_server_without_an_addr() {
    // Arrange
    let dir = match tempfile::TempDir::new() {
        Ok(dir) => dir,
        Err(error) => panic!("failed to create temp dir: {error}"),
    };
    let conf = write_config(&dir, "invalid.toml", INVALID_CONFIG);
    let conf = conf.to_string_lossy().to_string();

    // Act
    let output = run(&["-t", "-c", &conf]);

    // Assert
    assert!(
        !output.status.success(),
        "an invalid config must not validate"
    );
    let stderr = stderr(&output);
    assert!(stderr.contains("server(http)"), "stderr: {stderr}");
    assert!(stderr.contains("missing field `addr`"), "stderr: {stderr}");
}

/// The `PINGAP_*` overlay in `parse_arguments` must reach the child process.
/// Every value is set on the child only — `pingap()` strips the developer's
/// own variables first — so nothing has to be restored afterwards.
#[test]
fn environment_overrides_reach_the_binary() {
    // Arrange
    let dir = tempfile::TempDir::new().unwrap();
    let valid = write_config(&dir, "env-ok.toml", ENV_CONFIG);
    let invalid = write_config(&dir, "env-invalid.toml", INVALID_CONFIG);
    let validate_logs = dir.path().join("validate-logs");

    // PINGAP_CONF is the config when no `-c` is passed: the broken document
    // only exists at the environment path, so `-t` must fail on it.
    let output = pingap()
        .env("PINGAP_CONF", &invalid)
        .arg("-t")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "an invalid PINGAP_CONF must fail -t"
    );
    let first_stderr = stderr(&output);
    assert!(
        first_stderr.contains("missing field `addr`"),
        "stderr: {first_stderr}"
    );

    // PINGAP_LOG sends the log to the configured file instead of stderr.
    let output = pingap()
        .env("PINGAP_CONF", &valid)
        .env("PINGAP_LOG", validate_logs.join("validate.log"))
        .arg("-t")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let logs = read_logs(&validate_logs);
    assert!(
        logs.contains("Validate config success"),
        "the log file must carry the validation result: {logs}"
    );

    // PINGAP_AUTORELOAD only takes effect once a server assembles, so start
    // the proxy on an ephemeral port and wait for the startup line that
    // records every parsed flag. The child is killed and reaped here; the
    // parent process environment is never touched.
    let run_logs = dir.path().join("run-logs");
    let mut child = pingap()
        .env("PINGAP_CONF", &valid)
        .env("PINGAP_LOG", run_logs.join("server.log"))
        .env("PINGAP_AUTORELOAD", "1")
        .env("RUST_LOG", "info")
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(30);
    let logs = loop {
        let logs = read_logs(&run_logs);
        if logs.contains("server is running") {
            break logs;
        }
        if let Some(status) = child.try_wait().unwrap() {
            let _ = child.wait();
            panic!("pingap exited before the startup line ({status}): {logs}");
        }
        if Instant::now() >= deadline {
            break logs;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let _ = child.kill();
    let _ = child.wait();

    let startup = logs
        .lines()
        .find(|line| line.contains("server is running"))
        .unwrap_or_default();
    assert!(
        startup.contains("\"auto_reload\":true"),
        "the startup line must record the environment flag: {logs}"
    );
}

/// The assembled proxy actually listens and answers, not only validates.
///
/// The earlier cases stop before `Server::run`; this one starts the binary on
/// a real port, sends a request through the listener and then kills it.
#[test]
fn the_assembled_proxy_answers_on_its_listener() {
    // Arrange: reserve a port, then release it for the child.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config = format!(
        r#"
[basic]
name = "boot-smoke-listener"

[upstreams.backend]
addrs = ["127.0.0.1:9"]

[locations.root]
path = "/"
upstream = "backend"

[servers.http]
addr = "127.0.0.1:{port}"
locations = ["root"]
"#
    );
    let dir = tempfile::TempDir::new().unwrap();
    let path = write_config(&dir, "listener.toml", &config);
    let stderr_path = dir.path().join("stderr.log");
    let stderr_file = std::fs::File::create(&stderr_path).unwrap();

    let mut child = pingap()
        .args(["-c", path.to_str().unwrap()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr_file)
        .spawn()
        .expect("the binary must start");

    // Act: wait for the listener, then send one request.
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut stream = loop {
        match TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(200),
        ) {
            Ok(stream) => break stream,
            Err(_) if Instant::now() < deadline => {
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "the binary exited before it listened: {}",
                    std::fs::read_to_string(&stderr_path).unwrap_or_default()
                );
                std::thread::sleep(Duration::from_millis(100));
            },
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "the listener never answered: {error}; stderr: {}",
                    std::fs::read_to_string(&stderr_path).unwrap_or_default()
                );
            },
        }
    };
    stream
        .write_all(
            b"GET / HTTP/1.1\r\nHost: boot-smoke\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();

    // Assert: the proxy answered (the dead upstream yields a 5xx, which is
    // fine - the point is that the assembled listener served the request).
    assert!(
        response.starts_with("HTTP/1.1 "),
        "unexpected response: {response:?}"
    );
    assert!(
        response.contains("502") || response.contains("503"),
        "the dead upstream must produce an error response: {response:?}"
    );

    let _ = child.kill();
    let _ = child.wait();
}
