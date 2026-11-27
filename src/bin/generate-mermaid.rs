use glob::glob;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use toml::Value;

#[derive(Serialize, Deserialize, Debug)]
pub struct Cargo {
    package: Package,
    dependencies: HashMap<String, Value>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Package {
    name: String,
}

/// Readable node id for a workspace package.
fn short(name: &str) -> String {
    match name {
        "varman" => "root".to_string(),
        "varman-control" => "control".to_string(),
        "varman-agent" => "agent".to_string(),
        "varman-waf" => "waf".to_string(),
        "varman-challenge" => "challenge".to_string(),
        "varman-protocol" => "protocol".to_string(),
        "varman-pprof" => "pprof".to_string(),
        other => other.strip_prefix("pingap-").unwrap_or(other).to_string(),
    }
}

fn is_workspace_crate(name: &str) -> bool {
    name == "varman"
        || name.starts_with("pingap-")
        || name.starts_with("varman-")
}

/// Rewrites the mermaid block in `docs/modules.md` from every workspace
/// member's Cargo.toml, so the graph cannot drift from the real edges.
#[allow(clippy::unwrap_used)]
fn main() {
    let mut manifests = vec!["Cargo.toml".to_string()];
    for prefix in ["pingap-", "varman-"] {
        for entry in glob(&format!("{prefix}*/Cargo.toml")).unwrap() {
            manifests.push(entry.unwrap().to_string_lossy().to_string());
        }
    }

    let mut deps: HashMap<String, Vec<String>> = HashMap::new();
    for path in manifests {
        let data = fs::read_to_string(&path).unwrap();
        let c = toml::from_str::<Cargo>(&data).unwrap();
        let mut targets: Vec<String> = c
            .dependencies
            .keys()
            .filter(|name| is_workspace_crate(name))
            .map(|name| short(name))
            .collect();
        targets.sort();
        deps.insert(short(&c.package.name), targets);
    }

    let mut all: Vec<String> = deps.keys().cloned().collect();
    for targets in deps.values() {
        all.extend(targets.iter().cloned());
    }
    all.sort();
    all.dedup();

    let mut arr = vec![];
    for name in &all {
        if deps.get(name).is_none_or(|targets| targets.is_empty()) {
            arr.push(format!("    {name}[\"{name}\"]"));
        }
    }
    let mut keys: Vec<&String> = deps.keys().collect();
    keys.sort();
    for name in keys {
        for target in deps.get(name).unwrap() {
            arr.push(format!("    {name} --> {target}"));
        }
        arr.push(String::new());
    }

    let mermaid = format!("```mermaid\ngraph TD\n{}```", arr.join("\n"));
    let re = Regex::new(r#"```mermaid[\s\S]*?```"#).unwrap();
    let file = "docs/modules.md";
    let mut content = fs::read_to_string(file).unwrap();
    content = re.replace(&content, &mermaid).to_string();
    fs::write(file, content).unwrap();
}
