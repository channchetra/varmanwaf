//! MCP prompts: canned instructions for the questions operators ask most —
//! "why is this site failing", "what happened yesterday", "are we under
//! attack". A prompt tells the client's model which tools to run and how to
//! structure the answer; it never touches the database itself.

use serde_json::{json, Value};

/// `prompts/list` payload.
pub fn list() -> Value {
    json!({
        "prompts": [
            {
                "name": "troubleshoot",
                "title": "Troubleshoot a site problem",
                "description": "Investigate an error, latency or reachability problem and propose a fix",
                "arguments": [
                    { "name": "symptom", "description": "What the operator observes, e.g. '504 on /checkout since 09:00'", "required": true },
                    { "name": "site", "description": "Site name or domain, when known", "required": false }
                ]
            },
            {
                "name": "traffic_report",
                "title": "Traffic report",
                "description": "Summarize traffic, cache and error numbers for a window as a short report",
                "arguments": [
                    { "name": "hours", "description": "Look-back window in hours (default 24)", "required": false },
                    { "name": "site", "description": "Site name or domain; omit for the whole platform", "required": false }
                ]
            },
            {
                "name": "security_review",
                "title": "Security review",
                "description": "Review WAF detections and control-plane access for attacks and misconfigurations",
                "arguments": [
                    { "name": "hours", "description": "Look-back window in hours (default 24)", "required": false }
                ]
            }
        ]
    })
}

/// `prompts/get` payload.
pub fn get(name: &str, args: &Value) -> Result<Value, String> {
    let text = match name {
        "troubleshoot" => {
            let symptom = arg(args, "symptom")
                .ok_or_else(|| "'symptom' is required".to_string())?;
            let site = arg(args, "site");
            let site_line = match &site {
                Some(site) => format!(
                    "The operator named the site: {site}. Resolve it with list_sites (search) to get its id."
                ),
                None => "The site was not named; call list_sites first to find it."
                    .to_string(),
            };
            format!(
                "Act as the PingWAF on-call engineer.\n\n\
                 Symptom: {symptom}\n{site_line}\n\n\
                 Investigate before answering:\n\
                 1. list_agents — is the site's agent online and current?\n\
                 2. query_access_logs — filter by the site and the failing status class; note upstream_addr and latencies.\n\
                 3. query_waf_events — could a WAF rule (or observation mode) explain it?\n\
                 4. get_defense_status — is anything globally toggled?\n\n\
                 Then answer with: the likely root cause, the evidence (concrete log lines or counts), the exact fix or next step, and any uncertainty. Answer in the language the symptom was written in."
            )
        },
        "traffic_report" => {
            let hours = arg(args, "hours").unwrap_or_else(|| "24".to_string());
            let site = arg(args, "site");
            let scope = match &site {
                Some(site) => format!(
                    "Scope the report to the site '{site}' (resolve it with list_sites; pass its id to the tools)."
                ),
                None => "Cover the whole platform (omit site_id).".to_string(),
            };
            format!(
                "Produce a concise traffic report for the last {hours} hour(s). {scope}\n\n\
                 Use get_traffic_summary for the numbers and query_access_logs with status_class 5 (and 4) to explain the error share. If security_events is non-zero, add one sentence from query_waf_events.\n\n\
                 Format: a short summary paragraph, then a markdown table (requests, unique IPs, cache hit rate, avg/max latency, 4xx, 5xx, WAF events), then 'Notable findings' with at most three bullets. State the window and scope explicitly. Answer in the language the request was written in."
            )
        },
        "security_review" => {
            let hours = arg(args, "hours").unwrap_or_else(|| "24".to_string());
            format!(
                "Review the platform's security posture for the last {hours} hour(s).\n\n\
                 Run: get_defense_status (posture and toggles), query_waf_events (what fired), query_control_plane_logs (who reached the console, and any allowlist/WAF blocks), and list_ip_groups (shared lists and sync state).\n\n\
                 Report: top attacking IPs or rules with counts, anything that looks like a false positive, whether observation mode or monitor mode is masking enforcement, and 1-3 concrete hardening suggestions. Be explicit when the data is too thin to conclude. Answer in the language the request was written in."
            )
        },
        other => return Err(format!("unknown prompt '{other}'")),
    };

    Ok(json!({
        "description": match name {
            "troubleshoot" => "Troubleshoot a site problem",
            "traffic_report" => "Traffic report",
            _ => "Security review",
        },
        "messages": [
            { "role": "user", "content": { "type": "text", "text": text } }
        ],
    }))
}

fn arg(args: &Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_prompt_is_listed_with_its_arguments() {
        let value = list();
        let prompts = value["prompts"].as_array().unwrap();
        assert_eq!(prompts.len(), 3);
        let names: Vec<&str> = prompts
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"troubleshoot"));
        assert!(names.contains(&"traffic_report"));
        assert!(names.contains(&"security_review"));
    }

    #[test]
    fn troubleshoot_requires_a_symptom() {
        assert!(get("troubleshoot", &json!({})).is_err());
        assert!(get("troubleshoot", &json!({ "symptom": " " })).is_err());
        let value = get(
            "troubleshoot",
            &json!({ "symptom": "504s on /checkout", "site": "shop" }),
        )
        .unwrap();
        let text = value["messages"][0]["content"]["text"].as_str().unwrap();
        assert!(text.contains("504s on /checkout"));
        assert!(text.contains("shop"));
        assert!(text.contains("query_access_logs"));
    }

    #[test]
    fn report_prompts_default_to_a_day_and_reject_unknown_names() {
        let value = get("traffic_report", &json!({})).unwrap();
        let text = value["messages"][0]["content"]["text"].as_str().unwrap();
        assert!(text.contains("last 24 hour(s)"));
        let security =
            get("security_review", &json!({ "hours": "6" })).unwrap();
        assert!(security["messages"][0]["content"]["text"]
            .as_str()
            .unwrap()
            .contains("last 6 hour(s)"));
        assert!(get("no-such-prompt", &json!({})).is_err());
    }
}
