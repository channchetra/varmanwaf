// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::webhook::send_notification;
use pingap_core::{NotificationData, NotificationLevel};
use std::io;
use std::path::PathBuf;
use std::process;
use std::process::{Command, Stdio};
use std::sync::LazyLock;
use std::sync::OnceLock;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::Duration;
use tracing::{error, info, warn};

#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

static LOG_TARGET: &str = "main::process";

/// Process start time as epoch seconds. Set once by [`init_start_time`];
/// the lazy fallback keeps tests and library users working without it.
static START_TIME: OnceLock<u64> = OnceLock::new();

/// Records the process start time as epoch seconds.
///
/// Call this once at startup, as early as possible: without it
/// [`get_start_time`] falls back to the first read, which reports the first
/// caller rather than the process start. Idempotent; later calls keep the
/// value recorded by the first one.
pub fn init_start_time() {
    let _ = START_TIME.set(pingap_core::now_sec());
}

/// Returns the process start time as epoch seconds (not an uptime).
///
/// Callers that need uptime subtract this from `pingap_core::now_sec()`.
pub fn get_start_time() -> u64 {
    *START_TIME.get_or_init(pingap_core::now_sec)
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct RestartProcessCommand {
    pub exec_path: PathBuf,
    pub log_level: String,
    pub args: Vec<String>,
    /// Unix socket the replacement connects to once it is ready for the
    /// listening sockets; lives next to the upgrade socket.
    pub ready_sock: PathBuf,
    /// How long to wait for that before abandoning the restart.
    pub ready_timeout: Duration,
    /// The pid file both generations share. The replacement's daemon writes
    /// its pid there as soon as it has forked, which lets the wait notice a
    /// daemon that died before it could report.
    pub pid_file: String,
}

impl RestartProcessCommand {
    /// Spawns the replacement process **without waiting** for it to exit.
    ///
    /// The new process is started with `-d` (daemon) and `-u` (upgrade), so it
    /// daemonizes itself and takes over the listening sockets from the current
    /// process. We must NOT use `Command::output()` here: it blocks until the
    /// child exits and reads its stdout/stderr to EOF, which never happens for a
    /// long-running daemon, and it would keep this task blocked while the old
    /// process is being torn down. Return the child handle instead.
    ///
    /// stdout/stderr are **inherited**, not discarded. Pingora only redirects a
    /// daemon's stderr when `basic.error_log` is configured; otherwise it keeps
    /// whatever it was given (`Stdio::keep()`). Handing the child `/dev/null`
    /// here therefore threw away every diagnostic the new process produced
    /// before its own logger was up - which is exactly the window where a
    /// failed hot upgrade dies.
    fn exec(&self) -> io::Result<process::Child> {
        Command::new(&self.exec_path)
            .env("RUST_LOG", &self.log_level)
            .env(READY_SOCK_ENV, &self.ready_sock)
            .args(&self.args)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
    }
}

/// The command `/restart` spawns. The last root to install one owns it; see
/// [`set_restart_process_command`].
static CMD: RwLock<Option<RestartProcessCommand>> = RwLock::new(None);

/// Sets the command configuration used for process restarts.
///
/// A later, different command replaces the stored one instead of being
/// silently discarded: the last caller owns the restart path, and the
/// replacement is logged because it changes what `/restart` spawns.
///
/// # Arguments
/// * `data` - The restart command configuration to store
pub fn set_restart_process_command(data: RestartProcessCommand) {
    let mut slot = CMD.write().unwrap_or_else(|e| e.into_inner());
    if let Some(previous) = slot.as_ref()
        && previous != &data
    {
        warn!(
            target: LOG_TARGET,
            previous_exec_path = %previous.exec_path.display(),
            exec_path = %data.exec_path.display(),
            "restart command replaced by a later one"
        );
    }
    *slot = Some(data);
}

/// The installed restart command, cloned so the lock is never held across the
/// asynchronous restart.
fn restart_command() -> Option<RestartProcessCommand> {
    CMD.read().unwrap_or_else(|e| e.into_inner()).clone()
}

static PROCESS_RESTART_COUNT: LazyLock<AtomicU8> =
    LazyLock::new(|| AtomicU8::new(0));
static PROCESS_RESTARTING: LazyLock<AtomicBool> =
    LazyLock::new(|| AtomicBool::new(false));

/// Environment variable through which a restarting pingap tells its
/// replacement where to report readiness: set on the spawned process by
/// [`restart_now`], read by [`new_ready_notify_service`] in the new one.
pub const READY_SOCK_ENV: &str = "PINGAP_READY_SOCK";

/// Default for `basic.restart_ready_timeout`.
pub const DEFAULT_RESTART_READY_TIMEOUT: Duration = Duration::from_secs(60);

/// How often the wait looks at the spawned process and the pid file.
#[cfg(unix)]
const READY_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Initiates an immediate process restart.
///
/// This function will:
/// 1. Check if a restart is already in progress
/// 2. Send a notification about the restart
/// 3. Bind the readiness socket, then spawn the replacement process (with
///    `-d -u`, so it daemonizes and takes over the listeners) with the
///    socket's path in its environment
/// 4. Wait for the replacement to connect to that socket, which it does right
///    before its bootstrap asks this process for the listening sockets; abort
///    the restart if it exits, its daemon dies, or `restart_ready_timeout`
///    passes first (see [`wait_for_ready`])
/// 5. Send a SIGQUIT signal to the current process so it hands off the listening
///    sockets and exits gracefully
///
/// **Ordering matters.** Pingora's zero-downtime upgrade makes the *new* process
/// the fd receiver (it binds and listens on the upgrade socket, then `accept`s)
/// and the *old* process the fd sender (it `connect`s to that socket on SIGQUIT).
/// Both sides only retry the handshake for ~5s. If we signalled the old process
/// first and spawned the new one afterwards (the previous behaviour), the old
/// process could exhaust its retries and shut down before the new one finished
/// booting and bound the socket — leaving the old process exited and the new one
/// failing its bootstrap. So we start the new process first, then signal.
///
/// Note: pingora's fd transfer is **Linux only**. On other platforms
/// (e.g. macOS) the new `-u` process cannot acquire the listeners and exits;
/// use `--autoreload` (hot reload) for local development instead.
///
/// # Errors
/// Returns an error if:
/// - A restart is already in progress
/// - The restart command is not configured
/// - The restart command fails to spawn
#[cfg(unix)]
pub async fn restart_now() -> io::Result<()> {
    let restarting = PROCESS_RESTARTING.swap(true, Ordering::Relaxed);
    if restarting {
        error!(target: LOG_TARGET, "pingap is restarting now");
        return Err(std::io::Error::new(
            io::ErrorKind::InvalidInput,
            "Pingap is restarting",
        ));
    }
    let Some(cmd) = restart_command() else {
        PROCESS_RESTARTING.store(false, Ordering::Relaxed);
        return Err(std::io::Error::new(
            io::ErrorKind::NotFound,
            "Command not found",
        ));
    };
    info!(target: LOG_TARGET, "pingap will restart");
    send_notification(NotificationData {
        category: "restart".to_string(),
        message: format!("Restart now, pid:{}", std::process::id()),
        ..Default::default()
    })
    .await;

    // Bind the readiness socket before spawning, so the replacement can never
    // report to nobody ...
    let listener = match ReadyListener::bind(&cmd.ready_sock) {
        Ok(listener) => listener,
        Err(e) => {
            PROCESS_RESTARTING.store(false, Ordering::Relaxed);
            error!(
                target: LOG_TARGET,
                path = %cmd.ready_sock.display(), error = %e,
                "unable to bind the readiness socket, not restarting"
            );
            return Err(e);
        },
    };
    // ... then start it, so it can bind the upgrade socket and wait to receive
    // the listening fds ...
    let child = match cmd.exec() {
        Ok(child) => child,
        Err(e) => {
            PROCESS_RESTARTING.store(false, Ordering::Relaxed);
            return Err(e);
        },
    };
    let new_pid = child.id();
    info!(
        target: LOG_TARGET,
        new_pid,
        "new pingap process spawned, sending sockets to it"
    );

    // A successful spawn only means `execve` worked. The signal below is a
    // point of no return: pingora stops accepting once its close timeout
    // elapses and exits when the grace period does, so signalling ourselves
    // next to a replacement that already died takes the whole service down -
    // several minutes later, which makes it look unrelated to the restart.
    if let Err(e) = wait_for_ready(
        listener,
        child,
        new_pid,
        cmd.ready_timeout,
        &cmd.pid_file,
    )
    .await
    {
        PROCESS_RESTARTING.store(false, Ordering::Relaxed);
        error!(
            target: LOG_TARGET,
            new_pid, error = %e,
            "new pingap process is not ready, keeping the current one"
        );
        return Err(e);
    }

    // ... then signal the current process to transfer its sockets and exit.
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(std::process::id() as i32),
        nix::sys::signal::SIGQUIT,
    )?;
    Ok(())
}

/// The listening end of the readiness channel. Bound before the replacement
/// is spawned; the socket file is removed again on drop, whichever way the
/// restart ends.
#[cfg(unix)]
struct ReadyListener {
    path: PathBuf,
    listener: tokio::net::UnixListener,
}

#[cfg(unix)]
impl ReadyListener {
    fn bind(path: &Path) -> io::Result<Self> {
        // A leftover from a restart that never completed would fail the bind.
        if let Err(e) = std::fs::remove_file(path)
            && e.kind() != io::ErrorKind::NotFound
        {
            return Err(e);
        }
        let listener = tokio::net::UnixListener::bind(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            listener,
        })
    }

    /// Waits for the replacement to connect and identify itself by pid.
    async fn accept(&self) -> io::Result<u32> {
        let (mut stream, _) = self.listener.accept().await?;
        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).await?;
        parse_ready_pid(&buf[..n])
    }
}

#[cfg(unix)]
impl Drop for ReadyListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Parses the pid a replacement reports on the readiness socket.
///
/// An empty, non-numeric or zero report is an error: treating it as ready
/// would hand the listening sockets to a process that never identified
/// itself.
#[cfg(unix)]
fn parse_ready_pid(buf: &[u8]) -> io::Result<u32> {
    let text = std::str::from_utf8(buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let pid: u32 = text
        .trim()
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if pid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "readiness report contained pid 0",
        ));
    }
    Ok(pid)
}

/// Waits until the replacement reports that it is ready for the listening
/// sockets, or until it is clear that it never will.
///
/// Three things end the wait. Success: the replacement connects to the
/// readiness socket. Failure: the spawned process exits non-zero, or the
/// daemon it forked - found through the shared pid file - is gone before it
/// reported, or `ready_timeout` passes. Waiting here cannot deadlock the
/// hand-over: the replacement reports *before* its bootstrap asks this process
/// for the sockets, and those only leave on SIGQUIT.
#[cfg(unix)]
async fn wait_for_ready(
    listener: ReadyListener,
    mut child: process::Child,
    new_pid: u32,
    ready_timeout: Duration,
    pid_file: &str,
) -> io::Result<()> {
    let deadline = tokio::time::Instant::now() + ready_timeout;
    let mut poll = tokio::time::interval(READY_POLL_INTERVAL);
    let mut spawned_exited = false;
    // One accept future for the whole wait. `select!` drops the losing
    // branch every round, and a fresh `accept()` per iteration could be
    // dropped by a poll tick between accepting the connection and reading
    // the pid from it, silently losing the report and timing out.
    let accept = listener.accept();
    tokio::pin!(accept);
    loop {
        tokio::select! {
            accepted = &mut accept => {
                let daemon_pid = accepted?;
                info!(
                    target: LOG_TARGET,
                    new_pid, daemon_pid,
                    "new pingap process is ready for the sockets"
                );
                return Ok(());
            },
            _ = poll.tick() => {
                if !spawned_exited {
                    match child.try_wait() {
                        Ok(Some(status)) if !status.success() => {
                            return Err(io::Error::other(format!(
                                "new process({new_pid}) exited with {status} before it was ready"
                            )));
                        },
                        // With `-d` the spawned process leaves as soon as it
                        // has forked the daemon; the pid file tracks it from
                        // here on.
                        Ok(Some(_)) => spawned_exited = true,
                        Ok(None) => {},
                        Err(e) => warn!(
                            target: LOG_TARGET,
                            new_pid, error = %e,
                            "unable to check the new pingap process"
                        ),
                    }
                } else if let Some(pid) = daemon_pid_from(pid_file)
                    && !process_is_running(pid)
                {
                    return Err(io::Error::other(format!(
                        "new daemon({pid}) exited before it was ready"
                    )));
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "new process({new_pid}) did not report readiness within {ready_timeout:?}"
                        ),
                    ));
                }
            },
        }
    }
}

/// The pid the replacement's daemon wrote to the shared pid file, if any and
/// if it is not this process's own (pingora renames the old file away before
/// forking, but be safe).
#[cfg(unix)]
fn daemon_pid_from(pid_file: &str) -> Option<i32> {
    let pid: i32 = std::fs::read_to_string(pid_file)
        .ok()?
        .trim()
        .parse()
        .ok()?;
    (pid != std::process::id() as i32).then_some(pid)
}

#[cfg(unix)]
fn process_is_running(pid: i32) -> bool {
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_ok()
}

/// Reports readiness to the pingap that spawned this one. Runs as a service
/// the bootstrap service depends on, so the report goes out right before this
/// process asks the old one for the listening sockets - which the old one
/// only sends once it has that report.
pub struct ReadyNotifyService {
    path: PathBuf,
}

/// The service to run before bootstrap when this process was started by a
/// restart, `None` for a normal start. The variable is left in place: a
/// restart from this process sets a fresh value on the process it spawns.
pub fn new_ready_notify_service() -> Option<ReadyNotifyService> {
    let path = std::env::var_os(READY_SOCK_ENV)?;
    Some(ReadyNotifyService {
        path: PathBuf::from(path),
    })
}

#[async_trait::async_trait]
impl pingora::services::background::BackgroundService for ReadyNotifyService {
    async fn start_with_ready_notifier(
        &self,
        _shutdown: pingora::server::ShutdownWatch,
        ready_notifier: pingora::services::ServiceReadyNotifier,
    ) {
        match notify_ready(&self.path).await {
            Ok(()) => info!(
                target: LOG_TARGET,
                path = %self.path.display(),
                "reported readiness to the previous pingap process"
            ),
            // Not fatal here: the old process decides what silence means
            // (it abandons the restart and keeps serving), and bootstrap
            // must still run for the failure to surface on this side.
            Err(e) => warn!(
                target: LOG_TARGET,
                path = %self.path.display(), error = %e,
                "unable to report readiness to the previous pingap process"
            ),
        }
        ready_notifier.notify_ready();
    }
}

#[cfg(unix)]
async fn notify_ready(path: &Path) -> io::Result<()> {
    let mut stream = tokio::net::UnixStream::connect(path).await?;
    stream
        .write_all(std::process::id().to_string().as_bytes())
        .await?;
    stream.shutdown().await
}

#[cfg(not(unix))]
async fn notify_ready(_path: &PathBuf) -> io::Result<()> {
    Err(io::Error::other("readiness reporting needs unix sockets"))
}

/// Initiates an immediate process restart (Windows systems - not supported)
#[cfg(windows)]
pub async fn restart_now() -> io::Result<()> {
    return Err(io::Error::new(
        io::ErrorKind::Other,
        "Not support restart".to_string(),
    ));
}

/// Schedules a process restart after a 60-second delay.
///
/// This function will:
/// 1. Increment the restart counter
/// 2. Wait 60 seconds
/// 3. Verify no other restart was requested during the wait
/// 4. Execute the restart if this is still the most recent restart request
///
/// If the restart fails, an error notification will be sent.
/// Restarts after a 60-second debounce window.
///
/// Only the last request in the window restarts, so a burst of configuration
/// changes produces one hand-over. A failed restart is logged, notified and
/// returned so the caller can record it; it is never silently discarded.
pub async fn restart() -> io::Result<()> {
    let count = PROCESS_RESTART_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    tokio::time::sleep(Duration::from_secs(60)).await;
    if count == PROCESS_RESTART_COUNT.load(Ordering::Relaxed)
        && let Err(e) = restart_now().await
    {
        error!(
            target: LOG_TARGET,
            error = %e,
            "restart fail"
        );
        send_notification(NotificationData {
            level: NotificationLevel::Error,
            category: "restart_fail".to_string(),
            message: e.to_string(),
            ..Default::default()
        })
        .await;
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod start_time_tests {
    use super::*;

    #[test]
    fn init_start_time_is_idempotent_and_never_in_the_future() {
        // Act
        init_start_time();
        let first = get_start_time();
        init_start_time();
        let second = get_start_time();

        // Assert: the second call keeps the first value, and it is not later
        // than the current clock.
        assert_eq!(first, second);
        assert!(first <= pingap_core::now_sec(), "{first}");
    }
}

#[cfg(test)]
mod restart_command_tests {
    use super::*;

    #[test]
    fn a_second_restart_command_replaces_the_stale_one() {
        // Arrange: one root installed its command.
        set_restart_process_command(RestartProcessCommand {
            exec_path: PathBuf::from("/first/pingap"),
            ..Default::default()
        });

        // Act: a second root installs a different one.
        set_restart_process_command(RestartProcessCommand {
            exec_path: PathBuf::from("/second/pingap"),
            ..Default::default()
        });

        // Assert: the newest command owns the restart path; the old one is
        // not silently kept.
        let stored = restart_command().expect("a command must be stored");
        assert_eq!(PathBuf::from("/second/pingap"), stored.exec_path);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    /// Short on purpose: AF_UNIX paths are capped at about 100 bytes and a
    /// TMPDIR can eat most of that.
    fn sock_path(tag: &str) -> PathBuf {
        PathBuf::from(format!(
            "/tmp/pingap-ready-{}-{tag}.sock",
            std::process::id()
        ))
    }

    #[tokio::test]
    async fn test_ready_channel_round_trip() {
        let path = sock_path("ok");
        let listener = ReadyListener::bind(&path).unwrap();
        // Stands in for the spawned process: alive for the whole wait.
        let child = Command::new("sleep").arg("5").spawn().unwrap();
        let new_pid = child.id();
        // Report and wait side by side, the way the two processes do.
        let (waited, reported) = tokio::join!(
            wait_for_ready(
                listener,
                child,
                new_pid,
                Duration::from_secs(5),
                "/nonexistent/pingap-test.pid",
            ),
            notify_ready(&path),
        );
        reported.expect("the report must go through");
        waited.expect("the report must end the wait");
        // The socket file does not outlive the wait.
        assert_eq!(false, path.exists());
    }

    #[tokio::test]
    async fn test_ready_wait_notices_an_early_exit() {
        let path = sock_path("exit");
        let listener = ReadyListener::bind(&path).unwrap();
        let child = Command::new("sh").args(["-c", "exit 3"]).spawn().unwrap();
        let new_pid = child.id();
        let err = wait_for_ready(
            listener,
            child,
            new_pid,
            Duration::from_secs(5),
            "/nonexistent/pingap-test.pid",
        )
        .await
        .expect_err("must fail");
        assert_eq!(
            true,
            err.to_string()
                .contains("exited with exit status: 3 before it was ready"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn test_ready_wait_times_out() {
        let path = sock_path("timeout");
        let listener = ReadyListener::bind(&path).unwrap();
        let child = Command::new("sleep").arg("5").spawn().unwrap();
        let new_pid = child.id();
        let err = wait_for_ready(
            listener,
            child,
            new_pid,
            Duration::from_millis(500),
            "/nonexistent/pingap-test.pid",
        )
        .await
        .expect_err("must time out");
        assert_eq!(io::ErrorKind::TimedOut, err.kind());
        assert_eq!(false, path.exists());
    }

    #[tokio::test]
    async fn test_ready_wait_notices_a_daemon_that_died() {
        let path = sock_path("daemon");
        let listener = ReadyListener::bind(&path).unwrap();
        // The spawned process exits successfully, as `-d` does after forking.
        let child = Command::new("sh").args(["-c", "exit 0"]).spawn().unwrap();
        let new_pid = child.id();
        // A pid that is certainly gone: start a process and reap it.
        let mut gone =
            Command::new("sh").args(["-c", "exit 0"]).spawn().unwrap();
        let gone_pid = gone.id();
        gone.wait().unwrap();
        let pid_file = sock_path("daemon.pid");
        std::fs::write(&pid_file, gone_pid.to_string()).unwrap();

        let err = wait_for_ready(
            listener,
            child,
            new_pid,
            Duration::from_secs(5),
            pid_file.to_str().unwrap(),
        )
        .await
        .expect_err("a dead daemon must fail the wait");
        let _ = std::fs::remove_file(&pid_file);

        assert_eq!(
            true,
            err.to_string()
                .contains(&format!("new daemon({gone_pid}) exited")),
            "{err}"
        );
    }

    #[test]
    fn test_daemon_pid_from_ignores_this_process() {
        let pid_file = sock_path("own.pid");
        std::fs::write(&pid_file, std::process::id().to_string()).unwrap();
        assert_eq!(None, daemon_pid_from(pid_file.to_str().unwrap()));
        std::fs::write(&pid_file, "424242").unwrap();
        assert_eq!(Some(424242), daemon_pid_from(pid_file.to_str().unwrap()));
        let _ = std::fs::remove_file(&pid_file);
        assert_eq!(None, daemon_pid_from("/nonexistent/pingap-test.pid"));
    }

    #[tokio::test]
    async fn notify_ready_fails_without_a_listener() {
        let err = notify_ready(&sock_path("absent"))
            .await
            .expect_err("no listener must be an error");
        assert_eq!(io::ErrorKind::NotFound, err.kind(), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn parse_ready_pid_requires_a_real_pid() {
        assert_eq!(1234, parse_ready_pid(b"1234").expect("valid pid"));
        assert_eq!(1234, parse_ready_pid(b" 1234\n").expect("valid pid"));
        assert!(parse_ready_pid(b"").is_err());
        assert!(parse_ready_pid(b"abc").is_err());
        assert!(parse_ready_pid(b"0").is_err());
    }

    #[test]
    fn test_new_ready_notify_service_needs_the_env() {
        // The variable is never set in the test process.
        assert_eq!(true, new_ready_notify_service().is_none());
    }
}
