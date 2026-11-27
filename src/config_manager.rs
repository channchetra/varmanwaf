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

//! Config manager construction for the process roots.
//!
//! Each entry point builds its manager here and hands it to the data plane,
//! which is the manager's only owner. There is deliberately no process-wide
//! slot: nothing can inherit a manager from a different entry point, and no
//! start-up order decides which one the plane gets.

use pingap_config::ConfigManager;
use pingap_config::{Error, new_config_manager, new_memory_config_manager};
use std::path::PathBuf;
use std::sync::Arc;

type Result<T> = std::result::Result<T, Error>;

/// Builds the config manager from `value` (a `file://` or `etcd://` URL).
///
/// Nothing is cached: every call builds a fresh manager, so a failed attempt
/// is retried by calling again, and the caller owns the result.
pub fn try_init_config_manager(value: &str) -> Result<Arc<ConfigManager>> {
    Ok(Arc::new(new_config_manager(value)?))
}

/// Builds the config manager from a config that is already in memory, used by
/// the command line proxy (`--upstream`) and the agent-hosted data plane,
/// where there is no file or etcd backing store to read from. `path` receives
/// the acme state so an issued certificate is not thrown away on restart.
pub fn try_init_memory_config_manager(
    data: &str,
    path: Option<PathBuf>,
) -> Result<Arc<ConfigManager>> {
    Ok(Arc::new(new_memory_config_manager(data, path)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_initialization_reports_the_error_and_the_next_call_succeeds() {
        // Arrange: an etcd URL that names no host, so building it cannot work.
        let invalid_source = "etcd://";

        // Act: the first attempt fails ...
        let error = try_init_config_manager(invalid_source)
            .err()
            .expect("an unparsable source must not produce a manager");

        // Assert: the error is reported ...
        assert!(matches!(error, Error::Invalid { .. }));

        // ... and nothing was cached, so the next call is independent.
        try_init_memory_config_manager("[basic]\n", None)
            .expect("the retry must succeed");
    }

    #[test]
    fn every_call_builds_its_own_manager() {
        // Arrange/Act: two callers ask for the same in-memory source.
        let first = try_init_memory_config_manager("[basic]\n", None)
            .expect("the first manager");
        let second = try_init_memory_config_manager("[basic]\n", None)
            .expect("the second manager");

        // Assert: with no process-wide slot, each call owns the manager it was
        // given instead of inheriting one built by another entry point.
        assert!(!Arc::ptr_eq(&first, &second));
    }
}
