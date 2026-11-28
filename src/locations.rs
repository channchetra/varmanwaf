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

use crate::config_apply::ProviderUpdate;
use ahash::AHashMap;
use arc_swap::ArcSwap;
use pingap_config::Error;
use pingap_config::{Hashable, LocationConf};
use pingap_location::{Location, LocationProvider, LocationStats, Locations};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::LazyLock;

type Result<T> = std::result::Result<T, String>;

/// The construction failure in the wording the callers have always logged
/// (`Error::Invalid`'s display).
fn invalid_error(error: impl std::fmt::Display) -> String {
    Error::Invalid {
        message: error.to_string(),
    }
    .to_string()
}

/// One owner's location registry. Constructed per data plane, never shared.
pub struct Provider {
    locations: ArcSwap<Locations>,
}

impl Provider {
    /// A registry with no locations.
    pub fn new() -> Self {
        Self {
            locations: ArcSwap::from_pointee(AHashMap::new()),
        }
    }

    fn store(&self, data: Locations) {
        self.locations.store(Arc::new(data));
    }

    /// Initializes or updates the locations of this provider.
    /// Returns the names of the locations that were updated
    pub fn init_locations(
        &self,
        location_configs: &HashMap<String, LocationConf>,
    ) -> Result<ProviderUpdate> {
        let mut locations = AHashMap::new();
        let mut updated_locations = vec![];
        for (name, conf) in location_configs.iter() {
            if let Some(found) = self.get(name)
                && found.key == conf.hash_key()
            {
                locations.insert(name.to_string(), found);
                continue;
            }
            // A location that cannot be built aborts the rebuild: storing the
            // partial map would drop the entries that failed.
            let lo = Location::new(name, conf).map_err(invalid_error)?;
            updated_locations.push(name.clone());
            locations.insert(name.to_string(), Arc::new(lo));
        }
        self.store(locations);
        Ok(ProviderUpdate {
            updated: updated_locations,
            errors: String::new(),
        })
    }
}

impl Default for Provider {
    fn default() -> Self {
        Self::new()
    }
}

impl LocationProvider for Provider {
    fn get(&self, name: &str) -> Option<Arc<Location>> {
        if name.is_empty() {
            return None;
        }
        self.locations.load().get(name).cloned()
    }
    fn stats(&self) -> HashMap<String, LocationStats> {
        let mut stats = HashMap::new();
        self.locations.load().iter().for_each(|(k, v)| {
            stats.insert(k.to_string(), v.stats());
        });
        stats
    }
}

// Compatibility layer for the pre-provider-set callers and the test suite.
// Production assembly and reload use the owned `Provider`, so these are dead
// in a non-test build by design.
#[allow(dead_code)]
static LOCATION_PROVIDER: LazyLock<Arc<Provider>> = LazyLock::new(|| {
    Arc::new(Provider {
        locations: ArcSwap::from_pointee(AHashMap::new()),
    })
});
#[allow(dead_code)]
pub fn new_location_provider() -> Arc<dyn LocationProvider> {
    LOCATION_PROVIDER.clone()
}

/// Compatibility wrapper over the process-wide registry.
///
/// Production assembly and reload go through the [`Provider`] owned by their
/// provider set; this is kept for the legacy paths and tests that have not
/// been converted.
#[allow(dead_code)]
pub fn try_init_locations(
    location_configs: &HashMap<String, LocationConf>,
) -> Result<ProviderUpdate> {
    LOCATION_PROVIDER.init_locations(location_configs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(path: Option<&str>) -> HashMap<String, LocationConf> {
        HashMap::from([(
            "provider-update-location".to_string(),
            LocationConf {
                path: path.map(str::to_string),
                ..Default::default()
            },
        )])
    }

    #[test]
    fn a_new_location_is_reported_as_updated() {
        // Act
        let update =
            try_init_locations(&config(Some("/api"))).expect("a valid path");

        // Assert
        assert!(update.is_ok(), "{}", update.errors);
        assert_eq!(
            vec!["provider-update-location".to_string()],
            update.updated
        );
    }

    #[test]
    fn an_unparseable_location_is_a_fatal_error() {
        // Act: a broken regex path cannot be built.
        let error = try_init_locations(&config(Some("~(")))
            .expect_err("an invalid path pattern must fail the rebuild");

        // Assert: the failure is the `Err`, not a per-entry error.
        assert!(error.contains("Invalid error"), "{error}");
    }
}
