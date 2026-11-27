//! Boot smoke tests for the `pingap` binary.
//!
//! These spawn the compiled binary so the argument parsing, config loading
//! and validation wired up in `src/main.rs` are exercised as a whole. No
//! listener is started: `--template` and `--version` return before the server
//! is assembled, and `-t` exits right after validation.

use std::path::PathBuf;
use std::process::{Command, Output};

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
