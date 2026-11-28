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
use pingap_location::{LocationProvider, ServerLocationRoute};
use pingap_proxy::{ServerLocations, ServerLocationsProvider};
use std::collections::HashMap;
use std::sync::Arc;

type Result<T> = std::result::Result<T, String>;

/// One owner's server->location index. Constructed per data plane.
pub struct Provider {
    server_locations: ArcSwap<ServerLocations>,
}

impl Provider {
    /// An index with no servers.
    pub fn new() -> Self {
        Self {
            server_locations: ArcSwap::from_pointee(AHashMap::new()),
        }
    }

    fn store(&self, data: ServerLocations) {
        self.server_locations.store(Arc::new(data));
    }

    /// Rebuilds the index from `servers`, resolving each location name
    /// through `location_provider`.
    pub fn replace_server_locations(
        &self,
        location_provider: &dyn LocationProvider,
        servers: &HashMap<String, pingap_config::ServerConf>,
        locations: &HashMap<String, pingap_config::LocationConf>,
    ) -> Result<ProviderUpdate> {
        // get the location weight
        let location_weights = locations
            .iter()
            .map(|(name, item)| (name.to_string(), item.get_weight()))
            .collect::<HashMap<_, _>>();
        let ordered = ordered_server_locations(servers, &location_weights);
        let updated_servers =
            changed_server_locations(&ordered, |name| self.get(name));

        let mut server_locations = AHashMap::new();
        for (name, items) in ordered {
            let route = ServerLocationRoute::build(items, |loc_name| {
                location_provider.get(loc_name)
            });
            server_locations.insert(name, Arc::new(route));
        }
        self.store(server_locations);
        Ok(ProviderUpdate {
            updated: updated_servers,
            errors: String::new(),
        })
    }
}

impl Default for Provider {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerLocationsProvider for Provider {
    fn get(&self, name: &str) -> Option<Arc<ServerLocationRoute>> {
        self.server_locations.load().get(name).cloned()
    }
}

/// Sorts a server's configured location names by their weight, highest first,
/// so the first match keeps the priority `LocationConf` declares.
fn ordered_locations(
    items: &[String],
    weights: &HashMap<String, u16>,
) -> Vec<String> {
    let mut items = items.to_vec();
    items.sort_by_key(|item| {
        std::cmp::Reverse(
            weights.get(item.as_str()).copied().unwrap_or_default(),
        )
    });
    items
}

fn ordered_server_locations(
    servers: &HashMap<String, pingap_config::ServerConf>,
    weights: &HashMap<String, u16>,
) -> HashMap<String, Vec<String>> {
    servers
        .iter()
        .filter_map(|(name, server)| {
            server.locations.as_ref().map(|items| {
                (name.to_string(), ordered_locations(items, weights))
            })
        })
        .collect()
}

/// Names of the servers whose new order differs from the route currently
/// published by `current`, i.e. the ones a reload has to report as updated.
fn changed_server_locations(
    ordered: &HashMap<String, Vec<String>>,
    current: impl Fn(&str) -> Option<Arc<ServerLocationRoute>>,
) -> Vec<String> {
    ordered
        .iter()
        .filter(|(name, items)| {
            let unchanged = current(name).is_some_and(|route| {
                route.ordered.as_slice() == items.as_slice()
            });
            !unchanged
        })
        .map(|(name, _)| name.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_config::{LocationConf, ServerConf};
    use pretty_assertions::assert_eq;

    fn names(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    fn weights(pairs: &[(&str, u16)]) -> HashMap<String, u16> {
        pairs
            .iter()
            .map(|(name, weight)| (name.to_string(), *weight))
            .collect()
    }

    fn server(locations: &[&str]) -> ServerConf {
        ServerConf {
            locations: Some(names(locations)),
            ..Default::default()
        }
    }

    #[test]
    fn higher_weight_is_ordered_first() {
        // Arrange
        let weights = weights(&[("api", 10), ("static", 200), ("root", 50)]);

        // Act
        let ordered =
            ordered_locations(&names(&["api", "static", "root"]), &weights);

        // Assert
        assert_eq!(names(&["static", "root", "api"]), ordered);
    }

    #[test]
    fn equal_weight_keeps_the_configured_order() {
        // Arrange
        let weights = weights(&[("first", 10), ("second", 10)]);

        // Act
        let ordered = ordered_locations(&names(&["first", "second"]), &weights);

        // Assert
        assert_eq!(names(&["first", "second"]), ordered);
    }

    #[test]
    fn a_location_without_a_weight_sorts_last() {
        // Arrange
        let weights = weights(&[("weighted", 1)]);

        // Act
        let ordered =
            ordered_locations(&names(&["unweighted", "weighted"]), &weights);

        // Assert
        assert_eq!(names(&["weighted", "unweighted"]), ordered);
    }

    #[test]
    fn only_servers_with_a_location_list_get_an_order() {
        // Arrange
        let servers = HashMap::from([
            ("web".to_string(), server(&["low", "high"])),
            ("admin".to_string(), ServerConf::default()),
        ]);
        let weights = weights(&[("low", 1), ("high", 100)]);

        // Act
        let ordered = ordered_server_locations(&servers, &weights);

        // Assert
        assert_eq!(
            HashMap::from([("web".to_string(), names(&["high", "low"]))]),
            ordered
        );
    }

    #[test]
    fn an_unchanged_order_reports_no_change() {
        // Arrange: the published route is already in weight order, even
        // though the config lists the names in the opposite order.
        let ordered =
            HashMap::from([("web".to_string(), names(&["high", "low"]))]);
        let published = HashMap::from([(
            "web".to_string(),
            Arc::new(ServerLocationRoute::build(
                names(&["high", "low"]),
                |_| None,
            )),
        )]);

        // Act
        let changed = changed_server_locations(&ordered, |name| {
            published.get(name).cloned()
        });

        // Assert
        assert!(changed.is_empty(), "{changed:?}");
    }

    #[test]
    fn a_reordered_route_reports_the_server_as_changed() {
        // Arrange: the published route predates the config's weight change.
        let ordered =
            HashMap::from([("web".to_string(), names(&["high", "low"]))]);
        let published = HashMap::from([(
            "web".to_string(),
            Arc::new(ServerLocationRoute::build(
                names(&["low", "high"]),
                |_| None,
            )),
        )]);

        // Act
        let changed = changed_server_locations(&ordered, |name| {
            published.get(name).cloned()
        });

        // Assert
        assert_eq!(names(&["web"]), changed);
    }

    #[test]
    fn a_server_without_a_published_route_reports_as_changed() {
        // Arrange
        let ordered = HashMap::from([("web".to_string(), names(&["high"]))]);

        // Act
        let changed = changed_server_locations(&ordered, |_| None);

        // Assert
        assert_eq!(names(&["web"]), changed);
    }

    #[test]
    fn initializing_the_same_config_twice_reports_no_change() {
        // Arrange: weights come from `LocationConf::get_weight`, the way the
        // callers' real configs do. The server name is unique to this test so
        // the shared provider cannot be confused with another test's entries.
        let locations = HashMap::from([
            (
                "slow".to_string(),
                LocationConf {
                    weight: Some(1),
                    ..Default::default()
                },
            ),
            (
                "fast".to_string(),
                LocationConf {
                    weight: Some(100),
                    ..Default::default()
                },
            ),
        ]);
        let servers = HashMap::from([(
            "server-locations-order-test".to_string(),
            server(&["slow", "fast"]),
        )]);

        // Act
        let location_provider = crate::locations::Provider::new();
        location_provider
            .replace_locations(&locations)
            .expect("the test locations build");
        let provider = Provider::new();
        let first = provider
            .replace_server_locations(&location_provider, &servers, &locations)
            .expect("a server location index never fails to build")
            .updated;
        let published = provider
            .get("server-locations-order-test")
            .map(|route| route.ordered.as_slice().to_vec());
        let second = provider
            .replace_server_locations(&location_provider, &servers, &locations)
            .expect("a server location index never fails to build");

        // Assert
        assert_eq!(names(&["server-locations-order-test"]), first);
        assert_eq!(Some(names(&["fast", "slow"])), published);
        assert!(second.is_empty(), "{second:?}");
    }
}
