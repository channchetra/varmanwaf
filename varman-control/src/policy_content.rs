//! Built-in policy templates and rule recipes.
//!
//! Templates are complete starter policies (our layer format); recipes are
//! small parameterized custom rules in the rule expression language. Both
//! are compiled in, reviewed with the engine and validated by the same
//! [`crate::policy::validate_layer`] every API write goes through — a
//! template or recipe that stops compiling fails the build's tests.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use crate::policy::{self, PolicyRule, LAYER_CUSTOM_RULES, LAYER_ENGINE};

/// One built-in policy template.
pub struct PolicyTemplate {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    /// `(layer kind, layer payload)` pairs, validated at test time.
    pub layers: &'static [(&'static str, &'static str)],
}

/// Every built-in template, in gallery order.
pub const TEMPLATES: &[PolicyTemplate] = &[
    PolicyTemplate {
        id: "observe",
        name: "Observe first",
        description: "Detect and record everything without enforcing; the \
                      safe starting point before switching to blocking.",
        layers: &[(LAYER_ENGINE, r#"{"mode":"monitor","paranoia_level":2}"#)],
    },
    PolicyTemplate {
        id: "standard",
        name: "Standard",
        description: "Blocking at paranoia level 1: the default posture for \
                      a production site.",
        layers: &[(LAYER_ENGINE, r#"{"mode":"block","paranoia_level":1}"#)],
    },
    PolicyTemplate {
        id: "strict",
        name: "Strict",
        description: "Blocking at paranoia level 2 with deep body \
                      inspection; more detections, more tuning required.",
        layers: &[(
            LAYER_ENGINE,
            r#"{"mode":"block","paranoia_level":2,"advanced_mode":true}"#,
        )],
    },
    PolicyTemplate {
        id: "extra-strict",
        name: "Extra strict",
        description: "Blocking at paranoia level 3 with deep body \
                      inspection; expect to add exclusions for busy sites.",
        layers: &[(
            LAYER_ENGINE,
            r#"{"mode":"block","paranoia_level":3,"advanced_mode":true}"#,
        )],
    },
];

/// Dashboard-facing template view.
#[derive(Debug, Serialize)]
pub struct TemplateView {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    /// Layers as JSON objects, ready to show or seed a create request.
    pub layers: BTreeMap<&'static str, Value>,
}

/// The template gallery with parsed layers.
pub fn templates() -> Vec<TemplateView> {
    TEMPLATES
        .iter()
        .map(|template| TemplateView {
            id: template.id,
            name: template.name,
            description: template.description,
            layers: template
                .layers
                .iter()
                .filter_map(|(kind, raw)| {
                    serde_json::from_str::<Value>(raw)
                        .ok()
                        .map(|value| (*kind, value))
                })
                .collect(),
        })
        .collect()
}

/// Parsed layers of one template, or `None` for an unknown id.
pub fn template_layers(id: &str) -> Option<BTreeMap<String, Value>> {
    let template = TEMPLATES.iter().find(|template| template.id == id)?;
    Some(
        template
            .layers
            .iter()
            .filter_map(|(kind, raw)| {
                serde_json::from_str::<Value>(raw)
                    .ok()
                    .map(|value| (kind.to_string(), value))
            })
            .collect(),
    )
}

/// One parameter of a recipe.
#[derive(Clone, Debug, Serialize)]
pub struct RecipeParam {
    pub name: &'static str,
    pub label: &'static str,
    pub placeholder: &'static str,
    pub required: bool,
}

/// One built-in rule recipe.
#[derive(Debug, Serialize)]
pub struct Recipe {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub params: &'static [RecipeParam],
}

/// Every built-in recipe, in gallery order.
pub const RECIPES: &[Recipe] = &[
    Recipe {
        id: "block-path",
        name: "Block a path",
        description: "Block every request whose path starts with the given \
                      prefix.",
        params: &[RecipeParam {
            name: "path",
            label: "Path prefix",
            placeholder: "/admin",
            required: true,
        }],
    },
    Recipe {
        id: "challenge-path",
        name: "Challenge a path",
        description: "Answer requests under the given path prefix with a \
                      challenge instead of a hard block.",
        params: &[RecipeParam {
            name: "path",
            label: "Path prefix",
            placeholder: "/wp-admin",
            required: true,
        }],
    },
    Recipe {
        id: "block-query-param",
        name: "Block a query parameter",
        description: "Block requests carrying the given query parameter, \
                      whatever its value.",
        params: &[RecipeParam {
            name: "name",
            label: "Parameter name",
            placeholder: "debug",
            required: true,
        }],
    },
    Recipe {
        id: "block-user-agent",
        name: "Block a user-agent token",
        description: "Block requests whose User-Agent contains the given \
                      token (case-insensitive).",
        params: &[RecipeParam {
            name: "token",
            label: "User-agent token",
            placeholder: "internal-scanner",
            required: true,
        }],
    },
];

/// The recipe gallery.
pub fn recipes() -> &'static [Recipe] {
    RECIPES
}

/// Renders a recipe into a custom rule. `params` is the submitted map; a
/// missing or invalid parameter is an error naming the parameter.
pub fn render_recipe(
    id: &str,
    params: &BTreeMap<String, String>,
) -> Result<PolicyRule, String> {
    let recipe = RECIPES
        .iter()
        .find(|recipe| recipe.id == id)
        .ok_or_else(|| format!("unknown recipe '{id}'"))?;
    for param in recipe.params {
        if param.required && params.get(param.name).is_none_or(String::is_empty)
        {
            return Err(format!("'{}' is required", param.name));
        }
    }
    let (name, expression, action, severity, tags) = match recipe.id {
        "block-path" => {
            let path = safe_path(
                params.get("path").map(String::as_str).unwrap_or_default(),
            )?;
            (
                format!("Block path {path}"),
                format!("http.request.uri.path starts_with \"{path}\""),
                "block",
                4,
                vec!["custom", "path"],
            )
        },
        "challenge-path" => {
            let path = safe_path(
                params.get("path").map(String::as_str).unwrap_or_default(),
            )?;
            (
                format!("Challenge path {path}"),
                format!("http.request.uri.path starts_with \"{path}\""),
                "challenge",
                3,
                vec!["custom", "path"],
            )
        },
        "block-query-param" => {
            let name = safe_token(
                "name",
                params.get("name").map(String::as_str).unwrap_or_default(),
            )?;
            (
                format!("Block query parameter {name}"),
                format!("http.request.uri.query contains \"{name}=\""),
                "block",
                4,
                vec!["custom", "query"],
            )
        },
        "block-user-agent" => {
            let token = safe_token(
                "token",
                params.get("token").map(String::as_str).unwrap_or_default(),
            )?;
            (
                format!("Block user-agent {token}"),
                format!("user_agent contains \"{token}\""),
                "block",
                4,
                vec!["custom", "user-agent"],
            )
        },
        other => return Err(format!("unknown recipe '{other}'")),
    };
    let rule = PolicyRule {
        name,
        description: format!("{} (recipe: {})", recipe.name, recipe.id),
        expression,
        action: action.to_string(),
        severity,
        tags: tags.into_iter().map(str::to_string).collect(),
        enabled: true,
        mode: "block".to_string(),
        priority: 0,
    };
    // The rule must survive the same validation a layer write gets.
    policy::validate_layer(
        LAYER_CUSTOM_RULES,
        &serde_json::json!({ "rules": [rule] }),
    )?;
    Ok(rule)
}

/// Path prefixes: must start with `/`, no quotes/whitespace/control bytes.
fn safe_path(value: &str) -> Result<String, String> {
    let value = value.trim();
    if !value.starts_with('/') {
        return Err("'path' must start with '/'".to_string());
    }
    if value.len() > 200 {
        return Err("'path' must be at most 200 characters".to_string());
    }
    if value
        .chars()
        .any(|c| c == '"' || c == '\\' || c.is_whitespace() || c.is_control())
    {
        return Err(
            "'path' must not contain quotes, backslashes or whitespace"
                .to_string(),
        );
    }
    Ok(value.to_string())
}

/// Tokens and parameter names: alphanumerics plus `-`, `_`, `.` and `:`.
fn safe_token(key: &str, value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 200 {
        return Err(format!("'{key}' must be 1-200 characters"));
    }
    if !value.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':')
    }) {
        return Err(format!(
            "'{key}' must contain only letters, digits, '-', '_', '.' or ':'"
        ));
    }
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_template_passes_layer_validation() {
        for template in TEMPLATES {
            for (kind, raw) in template.layers {
                let config: Value = serde_json::from_str(raw)
                    .expect("template layer is valid JSON");
                policy::validate_layer(kind, &config).unwrap_or_else(|err| {
                    panic!("template {} layer {kind}: {err}", template.id)
                });
            }
        }
        assert!(TEMPLATES.iter().any(|t| t.id == "standard"));
        assert!(templates().iter().all(|t| !t.layers.is_empty()));
        assert!(template_layers("nope").is_none());
    }

    #[test]
    fn every_recipe_renders_a_valid_rule() {
        let samples: &[(&str, &[(&str, &str)])] = &[
            ("block-path", &[("path", "/admin")]),
            ("challenge-path", &[("path", "/wp-admin")]),
            ("block-query-param", &[("name", "debug")]),
            ("block-user-agent", &[("token", "internal-scanner")]),
        ];
        for (id, params) in samples {
            let map: BTreeMap<String, String> = params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            let rule = render_recipe(id, &map)
                .unwrap_or_else(|err| panic!("recipe {id}: {err}"));
            assert!(!rule.name.is_empty());
            assert!(!rule.expression.is_empty());
        }
    }

    #[test]
    fn recipe_params_are_validated() {
        let map = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };

        // Missing parameter.
        assert!(render_recipe("block-path", &BTreeMap::new())
            .unwrap_err()
            .contains("'path' is required"));
        // Path must start with a slash.
        assert!(render_recipe("block-path", &map(&[("path", "admin")]))
            .unwrap_err()
            .contains("start with '/'"));
        // No expression injection through parameters.
        assert!(render_recipe(
            "block-path",
            &map(&[("path", "/x\" or true or \"")])
        )
        .is_err());
        assert!(render_recipe(
            "block-user-agent",
            &map(&[("token", "a\" or true")])
        )
        .is_err());
        // Unknown recipe.
        assert!(render_recipe("nope", &BTreeMap::new())
            .unwrap_err()
            .contains("unknown recipe"));
    }
}
