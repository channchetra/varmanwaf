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

use pingap_config::ConfigManager;
use pingap_config::{Error, new_config_manager, new_memory_config_manager};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};

type Result<T> = std::result::Result<T, Error>;

/// Only a successfully built manager is stored here. A failed attempt leaves
/// the cell empty, so the next call retries instead of replaying the error.
static CONFIG_MANAGER: OnceLock<Arc<ConfigManager>> = OnceLock::new();
/// Serialises construction: two concurrent callers must not each build and
/// install a manager, and a retry must not race a concurrent first attempt.
static INIT_LOCK: Mutex<()> = Mutex::new(());

/// Installs a manager into `cell`, retrying after a failed initialization.
///
/// The first caller to acquire the lock builds the manager; a failure is
/// returned without caching it, and the double-checked read makes every later
/// caller reuse the installed instance.
fn try_init_with<F>(
    cell: &OnceLock<Arc<ConfigManager>>,
    new_manager: F,
) -> Result<Arc<ConfigManager>>
where
    F: FnOnce() -> Result<ConfigManager>,
{
    if let Some(manager) = cell.get() {
        return Ok(manager.clone());
    }
    let _guard = INIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Another caller may have installed a manager while this one waited.
    if let Some(manager) = cell.get() {
        return Ok(manager.clone());
    }
    let manager = Arc::new(new_manager().map_err(|e| Error::Invalid {
        message: e.to_string(),
    })?);
    // `set` can only fail when the cell is already filled, which the lock
    // above rules out; the manager is valid either way and is returned.
    let _ = cell.set(manager.clone());
    Ok(manager)
}

fn try_init<F>(new_manager: F) -> Result<Arc<ConfigManager>>
where
    F: FnOnce() -> Result<ConfigManager>,
{
    try_init_with(&CONFIG_MANAGER, new_manager)
}

/// Initializes the process-wide config manager from `value` (a `file://` or
/// `etcd://` URL). A failed attempt is not cached, so a later call retries.
pub fn try_init_config_manager(value: &str) -> Result<Arc<ConfigManager>> {
    try_init(|| new_config_manager(value))
}

/// Initializes the config manager from a config that is already in memory,
/// used by the command line proxy (`--upstream`) where there is no file or
/// etcd backing store to read from. `path` receives the acme state so an issued
/// certificate is not thrown away on restart.
pub fn try_init_memory_config_manager(
    data: &str,
    path: Option<PathBuf>,
) -> Result<Arc<ConfigManager>> {
    try_init(move || Ok(new_memory_config_manager(data, path)))
}

/// The process-wide config manager, when one has been initialized.
pub fn get_config_manager() -> Result<Arc<ConfigManager>> {
    CONFIG_MANAGER.get().cloned().ok_or_else(|| Error::Invalid {
        message: "config manager not initialized".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn failing() -> Result<ConfigManager> {
        Err(Error::Invalid {
            message: "config source is not available".to_string(),
        })
    }

    #[test]
    fn a_failed_initialization_is_not_cached_and_the_next_call_retries() {
        // Arrange: a local cell, so the process-wide manager stays untouched.
        let cell: OnceLock<Arc<ConfigManager>> = OnceLock::new();

        // Act: the first attempt fails ...
        let error = try_init_with(&cell, failing)
            .err()
            .expect("the failing manager must not be installed");

        // Assert: the error is reported and nothing was cached ...
        assert!(matches!(error, Error::Invalid { .. }));
        assert!(cell.get().is_none());

        // ... so the next call retries and succeeds.
        let manager =
            try_init_with(&cell, || Ok(new_memory_config_manager("", None)))
                .expect("the retry must succeed");
        assert!(cell.get().is_some());
        assert!(Arc::ptr_eq(
            &manager,
            &try_init_with(&cell, failing).expect("the cached manager")
        ));
    }

    #[test]
    fn concurrent_initialization_installs_one_manager() {
        // Arrange
        static CELL: OnceLock<Arc<ConfigManager>> = OnceLock::new();
        static BUILDS: AtomicUsize = AtomicUsize::new(0);

        // Act: every caller races to initialize the same cell.
        let handles: Vec<_> = (0..8)
            .map(|_| {
                std::thread::spawn(|| {
                    try_init_with(&CELL, || {
                        BUILDS.fetch_add(1, Ordering::SeqCst);
                        std::thread::yield_now();
                        Ok(new_memory_config_manager("", None))
                    })
                })
            })
            .collect();
        let managers: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("worker must not panic"))
            .collect::<Result<Vec<_>>>()
            .expect("every caller must get the manager");

        // Assert: one construction, one instance handed to every caller.
        assert_eq!(1, BUILDS.load(Ordering::SeqCst));
        let first = &managers[0];
        assert!(managers.iter().all(|manager| Arc::ptr_eq(first, manager)));
        assert!(Arc::ptr_eq(
            first,
            CELL.get().expect("the manager must be installed")
        ));
    }
}
