//! Test-only process-wide locks.
//!
//! Provider tests still exercise the compatibility constructors, which share
//! the process-wide registries; serialising them keeps one test's rebuild from
//! racing another's assertions. Production paths use the local `ProviderSet`.

use std::sync::{Mutex, MutexGuard};

static PROVIDER_LOCK: Mutex<()> = Mutex::new(());

/// Serialises tests that mutate the process-wide providers.
pub(crate) fn lock_providers() -> MutexGuard<'static, ()> {
    PROVIDER_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}
