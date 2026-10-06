//! Built-in pprof-style profiling for PingWAF processes.
//!
//! CPU sampling wraps the `pprof` crate and is exposed by both planes as
//! three endpoints:
//!
//! * `.../pprof/profile` — gzip-compressed pprof protobuf, understood by
//!   `go tool pprof` and speedscope
//! * `.../pprof/flamegraph` — SVG flamegraph rendered by inferno, viewable
//!   directly in a browser
//! * `.../pprof/memory` — JSON snapshot of process RSS and system memory
//!
//! Sampling is process-global: `pprof` installs a single signal handler and
//! one shared collector, so a second concurrent session is rejected with
//! [`ProfileError::AlreadyActive`] rather than corrupting the first.
//!
//! CPU sampling only works on Linux: there the `pprof` signal handler unwinds
//! with its own signal-safe DWARF walker. On other platforms (macOS in
//! particular) unwinding goes through libunwind, which is not async-signal-safe
//! and can abort the process from inside the handler (tikv/pprof-rs#36), so
//! [`start_session`] fails with [`ProfileError::UnsupportedPlatform`] there
//! instead of risking the process. [`memory_snapshot`] works everywhere.
//!
//! Frames are resolved from the binary's symbol table. The default
//! `release` profile strips symbols, so profile a `release-perf` build
//! (`--profile release-perf`, which keeps `debug = 1`) to get readable
//! flame graphs; on a stripped build most frames show up as `Unknown`.

use bytesize::ByteSize;
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(target_os = "linux")]
use std::io::Write;

#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_os = "linux")]
use pprof::ProfilerGuard;

/// Sampling frequency used when the request does not specify one. 99 rather
/// than a round 100 so the sampler does not synchronise with periodically
/// scheduled work.
pub const DEFAULT_FREQUENCY: i32 = 99;
/// Upper bound accepted for the `frequency` query parameter.
pub const MAX_FREQUENCY: i32 = 1000;
/// Default capture window in seconds.
pub const DEFAULT_SECONDS: u64 = 30;
/// Upper bound accepted for the `seconds` query parameter.
pub const MAX_SECONDS: u64 = 120;

/// The profiler is a process-global singleton, so only one sampling session
/// may exist at a time. `pprof` itself would fail the second start anyway;
/// this flag turns that failure into a clean "already active" answer.
#[cfg(target_os = "linux")]
static SESSION_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Failures surfaced to the profiling endpoints.
#[derive(Debug)]
pub enum ProfileError {
    /// Another session is already sampling in this process (HTTP 409).
    AlreadyActive,
    /// CPU sampling is unavailable on this platform (HTTP 501); only Linux
    /// has a signal-safe unwinder for the sampling handler.
    UnsupportedPlatform,
    /// The profiler failed to start (unsupported platform, resource limits).
    Start(String),
    /// Collecting, symbolising or encoding the report failed.
    Report(String),
}

impl std::error::Error for ProfileError {}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProfileError::AlreadyActive => f.write_str(
                "a profiling session is already active in this process",
            ),
            ProfileError::UnsupportedPlatform => f.write_str(
                "CPU sampling is only supported on Linux; the macOS unwinder is not signal-safe",
            ),
            ProfileError::Start(msg) => {
                write!(f, "failed to start profiler: {msg}")
            },
            ProfileError::Report(msg) => {
                write!(f, "failed to build profile report: {msg}")
            },
        }
    }
}

#[cfg(target_os = "linux")]
fn report_err(err: pprof::Error) -> ProfileError {
    ProfileError::Report(err.to_string())
}

/// An in-flight CPU sampling session. Sampling runs until one of the
/// `finish_*` methods consumes the session or it is dropped.
pub struct ProfilingSession {
    #[cfg(target_os = "linux")]
    guard: Option<ProfilerGuard<'static>>,
}

/// Starts CPU sampling at `frequency` Hz (values outside `1..=MAX_FREQUENCY`
/// are clamped).
///
/// The caller decides how long to sample: start the session, wait, then call
/// [`ProfilingSession::finish_pprof`] or
/// [`ProfilingSession::finish_flamegraph`].
#[cfg(target_os = "linux")]
pub fn start_session(frequency: i32) -> Result<ProfilingSession, ProfileError> {
    if SESSION_ACTIVE.swap(true, Ordering::SeqCst) {
        return Err(ProfileError::AlreadyActive);
    }
    // Blocking the unwinder's own libraries avoids deadlocks inside
    // `_Unwind_Backtrace`, and `vdso` carries broken DWARF on some
    // distributions (both per the pprof-rs documentation).
    let started = pprof::ProfilerGuardBuilder::default()
        .frequency(frequency.clamp(1, MAX_FREQUENCY))
        .blocklist(&["libc", "libgcc", "pthread", "vdso"])
        .build();
    match started {
        Ok(guard) => Ok(ProfilingSession { guard: Some(guard) }),
        Err(err) => {
            SESSION_ACTIVE.store(false, Ordering::SeqCst);
            Err(ProfileError::Start(err.to_string()))
        },
    }
}

/// Off-Linux the sampling handler would unwind through libunwind, which can
/// abort the process from inside the signal handler, so captures are refused
/// outright.
#[cfg(not(target_os = "linux"))]
pub fn start_session(
    _frequency: i32,
) -> Result<ProfilingSession, ProfileError> {
    Err(ProfileError::UnsupportedPlatform)
}

impl ProfilingSession {
    /// Stops sampling and returns the samples as a gzip-compressed pprof
    /// protobuf - the same wire format `go tool pprof` accepts.
    #[cfg(target_os = "linux")]
    pub fn finish_pprof(mut self) -> Result<Vec<u8>, ProfileError> {
        let report = self.take_report()?;
        let profile = report.pprof().map_err(report_err)?;
        let raw = pprof::protos::Message::encode_to_vec(&profile);
        let mut encoder = flate2::write::GzEncoder::new(
            Vec::with_capacity(raw.len() / 4 + 256),
            flate2::Compression::default(),
        );
        encoder
            .write_all(&raw)
            .and_then(|_| encoder.finish())
            .map_err(|e| ProfileError::Report(e.to_string()))
    }

    /// Unreachable off-Linux: `start_session` never hands out a session there.
    #[cfg(not(target_os = "linux"))]
    pub fn finish_pprof(self) -> Result<Vec<u8>, ProfileError> {
        Err(ProfileError::UnsupportedPlatform)
    }

    /// Stops sampling and returns the samples as an inferno flamegraph SVG.
    #[cfg(target_os = "linux")]
    pub fn finish_flamegraph(mut self) -> Result<String, ProfileError> {
        let report = self.take_report()?;
        let mut svg = Vec::new();
        report.flamegraph(&mut svg).map_err(report_err)?;
        String::from_utf8(svg).map_err(|e| ProfileError::Report(e.to_string()))
    }

    /// Unreachable off-Linux: `start_session` never hands out a session there.
    #[cfg(not(target_os = "linux"))]
    pub fn finish_flamegraph(self) -> Result<String, ProfileError> {
        Err(ProfileError::UnsupportedPlatform)
    }

    #[cfg(target_os = "linux")]
    fn take_report(&mut self) -> Result<pprof::Report, ProfileError> {
        let Some(guard) = self.guard.as_ref() else {
            return Err(ProfileError::Report(
                "profiling session already finished".to_string(),
            ));
        };
        let report = guard.report().build().map_err(report_err)?;
        // Sampling stops here; symbolising and encoding below is idle time.
        self.guard = None;
        Ok(report)
    }
}

#[cfg(target_os = "linux")]
impl Drop for ProfilingSession {
    fn drop(&mut self) {
        self.guard = None;
        SESSION_ACTIVE.store(false, Ordering::SeqCst);
    }
}

/// Point-in-time memory usage of this process and the machine, for the
/// `.../pprof/memory` endpoint.
#[derive(Debug, Serialize)]
pub struct MemorySnapshot {
    /// Resident set size of this process in bytes.
    pub rss_bytes: u64,
    /// Virtual memory size of this process in bytes.
    pub virtual_bytes: u64,
    /// Total physical RAM of the machine in bytes.
    pub total_memory_bytes: u64,
    /// Physical RAM in use across the machine in bytes.
    pub used_memory_bytes: u64,
    /// `rss_bytes` rendered human-readable, e.g. "120.3 MB".
    pub rss: String,
    /// `total_memory_bytes` rendered human-readable.
    pub total_memory: String,
    /// `used_memory_bytes` rendered human-readable.
    pub used_memory: String,
    /// Unix epoch milliseconds at which the snapshot was taken.
    pub collected_at_ms: u64,
}

/// Collects a [`MemorySnapshot`]. Process memory comes from `memory-stats`,
/// system totals from sysinfo with only RAM refresh enabled.
pub fn memory_snapshot() -> MemorySnapshot {
    let (rss_bytes, virtual_bytes) = match memory_stats::memory_stats() {
        Some(stats) => (stats.physical_mem as u64, stats.virtual_mem as u64),
        None => (0, 0),
    };
    let kind = sysinfo::MemoryRefreshKind::nothing().with_ram();
    let mut sys = sysinfo::System::new_with_specifics(
        sysinfo::RefreshKind::nothing().with_memory(kind),
    );
    sys.refresh_memory();
    let collected_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default();
    MemorySnapshot {
        rss_bytes,
        virtual_bytes,
        total_memory_bytes: sys.total_memory(),
        used_memory_bytes: sys.used_memory(),
        rss: ByteSize(rss_bytes).to_string(),
        total_memory: ByteSize(sys.total_memory()).to_string(),
        used_memory: ByteSize(sys.used_memory()).to_string(),
        collected_at_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    use pretty_assertions::assert_eq;

    /// Burns CPU for `ms` so the sampler has something to catch.
    #[cfg(target_os = "linux")]
    fn burn(ms: u64) {
        let start = std::time::Instant::now();
        let mut acc = 0u64;
        while start.elapsed().as_millis() < ms as u128 {
            acc =
                acc.wrapping_add(std::hint::black_box(acc.count_ones() as u64));
        }
        assert!(acc < u64::MAX);
    }

    // All sampling paths share one process-global profiler, so they must run
    // sequentially inside a single test.
    #[cfg(target_os = "linux")]
    #[test]
    fn sampling_sessions() {
        let session = start_session(DEFAULT_FREQUENCY).expect("first start");
        burn(300);
        let profile = session.finish_pprof().expect("pprof bytes");
        // gzip magic: the output is a valid gzip stream for go tool pprof.
        assert_eq!(profile[0], 0x1f);
        assert_eq!(profile[1], 0x8b);

        let session = start_session(DEFAULT_FREQUENCY).expect("second start");
        assert!(matches!(
            start_session(DEFAULT_FREQUENCY),
            Err(ProfileError::AlreadyActive)
        ));
        burn(200);
        let svg = session.finish_flamegraph().expect("flamegraph svg");
        assert!(svg.contains("<svg"));

        // Dropping a session releases the process-global slot.
        let session = start_session(DEFAULT_FREQUENCY).expect("third start");
        drop(session);
        let session = start_session(DEFAULT_FREQUENCY).expect("fourth start");
        drop(session);
    }

    // Sampling the process via SIGPROF is unsafe off-Linux (see
    // `start_session`); the endpoints must fail cleanly instead of crashing.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn sampling_rejected_off_linux() {
        assert!(matches!(
            start_session(DEFAULT_FREQUENCY),
            Err(ProfileError::UnsupportedPlatform)
        ));
    }

    #[test]
    fn memory_snapshot_is_populated() {
        let snapshot = memory_snapshot();
        assert!(snapshot.rss_bytes > 0);
        assert!(snapshot.total_memory_bytes > 0);
        assert!(snapshot.used_memory_bytes > 0);
        assert!(snapshot.collected_at_ms > 0);
    }
}
