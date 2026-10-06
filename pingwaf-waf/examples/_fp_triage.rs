use std::env;

use pingwaf_waf::{WafEngine, WafEngineConfig, WafLevel, WafMode};

fn main() {
    let mut args = env::args().skip(1);
    let level = args
        .next()
        .and_then(|s| WafLevel::parse(&s))
        .unwrap_or(WafLevel::Normal);
    let force_body = env::args().any(|a| a == "--body");
    let engine = WafEngine::new(&WafEngineConfig {
        level,
        mode: WafMode::Block,
        ..WafEngineConfig::default()
    });
    for path in args.filter(|a| a != "--body") {
        let raw = std::fs::read(&path).expect("read sample");
        let text = String::from_utf8_lossy(&raw).to_string();
        let mut parts = text.splitn(2, "\r\n\r\n");
        let head = parts.next().unwrap_or("");
        let body = parts.next().unwrap_or("").as_bytes().to_vec();
        let mut lines = head.lines();
        let reqline = lines.next().unwrap_or("");
        let mut seg = reqline.split_whitespace();
        let method = seg.next().unwrap_or("GET").to_string();
        let target = seg.next().unwrap_or("/").to_string();
        let (reqpath, query) = match target.split_once('?') {
            Some((p, q)) => (p.to_string(), q.to_string()),
            None => (target.clone(), String::new()),
        };
        let mut headers = Vec::new();
        for l in lines {
            if let Some((k, v)) = l.split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
        let body = if !force_body && (method == "GET" || method == "HEAD") {
            None
        } else {
            Some(body)
        };
        let req = pingwaf_waf::RequestData {
            path: reqpath,
            query,
            headers,
            body,
            ..pingwaf_waf::RequestData::new(method, "/")
        };
        let verdict = engine.inspect(&req);
        println!(
            "{} [{}] -> {:?} score={} rules={} detail={}",
            path,
            level.as_str(),
            verdict.action,
            verdict.score,
            verdict.matched_rules.join(","),
            verdict.details
        );
    }
}
