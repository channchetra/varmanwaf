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

use super::{get_hash_key, get_int_conf, get_str_conf, get_str_slice_conf};
use crate::certificates::new_certificate_provider;
use crate::config_manager::get_config_manager;
use crate::process::{get_start_time, restart_now};
use crate::upstreams::new_upstream_provider;
use async_trait::async_trait;
use bytes::Bytes;
use bytes::{BufMut, BytesMut};
use ctor::ctor;
use flate2::Compression;
use flate2::write::GzEncoder;
use hex::ToHex;
use hex::encode;
use http::Method;
use http::{HeaderValue, StatusCode, header};
use humantime::parse_duration;
use pingap_certificate::validate_servers_tls_for_backend;
use pingap_config::hcl::convert_toml_to_hcl;
use pingap_config::kdl::convert_toml_to_kdl;
use pingap_config::{
    BasicConf, CATEGORY_CERTIFICATE, CATEGORY_STORAGE, Category,
    CertificateConf, ConfigManager, LocationConf, PingapTomlConfig,
    PluginCategory, PluginConf, ServerConf, StorageConf, UpstreamConf,
    Validate, format_category,
};
use pingap_config::{
    CATEGORY_LOCATION, CATEGORY_PLUGIN, CATEGORY_SERVER, CATEGORY_UPSTREAM,
    PingapConfig,
};
use pingap_core::{
    Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult, TtlLruLimit,
};
use pingap_performance::get_process_system_info;
use pingap_performance::get_processing_accepted;
use pingap_plugin::{Error, get_plugin_factory, redacted_params};
use pingap_upstream::UpstreamHealthyStatus;
use pingap_util::base64_decode;
use pingora::http::RequestHeader;
use pingora::proxy::Session;
use rust_embed::EmbeddedFile;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::HashMap;
use std::io::Write;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use substring::Substring;
use tracing::{debug, error, warn};
use urlencoding::decode;

type Result<T> = std::result::Result<T, Error>;

static LOG_TARGET: &str = "main::admin";

#[derive(RustEmbed)]
#[folder = "web/dist/"]
struct AdminAsset;

pub struct EmbeddedStaticFile(pub Option<EmbeddedFile>, pub Duration);

impl From<EmbeddedStaticFile> for HttpResponse {
    fn from(value: EmbeddedStaticFile) -> Self {
        let Some(file) = value.0 else {
            return HttpResponse::not_found("Not Found");
        };
        // generate content hash
        let str = &encode(file.metadata.sha256_hash())[0..8];
        let mime_type = file.metadata.mimetype();
        // cut hash and file length as etag
        let entity_tag = format!(r#""{:x}-{str}""#, file.data.len());
        // html set no-cache
        let max_age = if mime_type.contains("text/html") {
            0
        } else {
            value.1.as_secs()
        };

        let mut headers = vec![];
        if let Ok(value) = HeaderValue::from_str(mime_type) {
            headers.push((header::CONTENT_TYPE, value));
        }
        if let Ok(value) = HeaderValue::from_str(&entity_tag) {
            headers.push((header::ETAG, value));
        }

        let mut gzip_body = None;
        if file.data.len() > 1024 {
            let mut d = GzEncoder::new(vec![], Compression::best());
            let _ = d.write_all(&file.data);
            if let Ok(w) = d.finish() {
                gzip_body = Some(Bytes::copy_from_slice(w.as_ref()));
                if let Ok(value) = HeaderValue::from_str("gzip") {
                    headers.push((header::CONTENT_ENCODING, value));
                }
            }
        }
        let body = if let Some(data) = gzip_body {
            data
        } else {
            Bytes::copy_from_slice(&file.data)
        };

        HttpResponse {
            status: StatusCode::OK,
            body,
            max_age: Some(max_age as u32),
            headers: Some(headers),
            ..Default::default()
        }
    }
}

pub struct AdminServe {
    pub path: String,
    pub authorizations: Vec<(String, String)>,
    pub plugin_step: PluginStep,
    manager: Arc<ConfigManager>,
    max_age: Duration,
    hash_value: String,
    ip_fail_limit: TtlLruLimit,
    allow_unauthenticated: bool,
}

#[derive(Serialize, Deserialize)]
struct ErrorResponse {
    message: String,
}

#[derive(Serialize, Deserialize)]
struct BasicInfo {
    start_time: u64,
    version: String,
    rustc_version: String,
    kernel: String,
    config_hash: String,
    pid: String,
    user: String,
    group: String,
    threads: i64,
    processing: i32,
    accepted: u64,
    memory_mb: usize,
    memory: String,
    arch: String,
    cpus: usize,
    physical_cpus: usize,
    total_memory: String,
    used_memory: String,
    features: Vec<String>,
    fd_count: usize,
    tcp_count: usize,
    tcp6_count: usize,
    supported_plugins: Vec<String>,
    upstream_healthy_status: HashMap<String, UpstreamHealthyStatus>,
    support_history: bool,
    git_hash: String,
    now: u64,
}

#[derive(Serialize, Deserialize)]
struct FullConfigJson {
    pub hcl: String,
    pub kdl: String,
    pub full: String,
    pub original: String,
}

impl TryFrom<&PluginConf> for AdminServe {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let allow_unauthenticated = value
            .get("allow_unauthenticated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let mut authorizations = vec![];
        for (index, item) in get_str_slice_conf(value, "authorizations")
            .iter()
            .enumerate()
        {
            if item.is_empty() {
                // The `--admin host:port` form emits one empty entry when no
                // credentials are given. It used to disable authentication
                // silently; only `allow_unauthenticated` may do that now.
                if allow_unauthenticated {
                    continue;
                }
                return Err(Error::Invalid {
                    category: "admin".to_string(),
                    message: format!(
                        "authorizations[{index}] is empty, expect base64 of user:password"
                    ),
                });
            }
            let data =
                base64_decode(item).map_err(|e| Error::Base64Decode {
                    category: PluginCategory::BasicAuth.to_string(),
                    source: e,
                })?;
            let decoded = std::string::String::from_utf8_lossy(&data);
            let Some((user, pass)) = decoded.split_once(':') else {
                return Err(Error::Invalid {
                    category: "admin".to_string(),
                    message: format!(
                        "authorizations[{index}] must be base64 of user:password"
                    ),
                });
            };
            authorizations.push((user.to_string(), pass.to_string()));
        }
        if authorizations.is_empty() && !allow_unauthenticated {
            return Err(Error::Invalid {
                category: "admin".to_string(),
                message:
                    "authorizations is empty; set allow_unauthenticated = \
                          true to disable authentication"
                        .to_string(),
            });
        }
        if allow_unauthenticated {
            warn!(
                target: LOG_TARGET,
                "admin: authentication is DISABLED (allow_unauthenticated = true); \
                 anyone who can reach this listener can read and change the \
                 configuration"
            );
        }
        let mut ip_fail_limit = get_int_conf(value, "ip_fail_limit");
        if ip_fail_limit <= 0 {
            ip_fail_limit = 10;
        }
        let max_age_value = &get_str_conf(value, "max_age");
        let mut max_age = Duration::from_secs(2 * 24 * 3600);
        if !max_age_value.is_empty() {
            max_age = parse_duration(max_age_value).map_err(|e| {
                Error::ParseDuration {
                    category: "admin".to_string(),
                    source: e,
                }
            })?;
        }
        let mut path = get_str_conf(value, "path");
        if path.len() > 1 && path.ends_with("/") {
            path = path.substring(0, path.len() - 1).to_string();
        }

        let params = AdminServe {
            hash_value,
            max_age,
            plugin_step: PluginStep::Request,
            path,
            ip_fail_limit: TtlLruLimit::new_compact(
                512,
                Duration::from_secs(5 * 60),
                ip_fail_limit as usize,
            ),
            manager: get_config_manager().map_err(|e| Error::Invalid {
                category: "config_manager".to_string(),
                message: e.to_string(),
            })?,
            authorizations,
            allow_unauthenticated,
        };

        Ok(params)
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct AesParams {
    category: String,
    key: String,
    data: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct AesResp {
    value: String,
}

async fn get_request_body(session: &mut Session) -> pingora::Result<BytesMut> {
    let mut buf = BytesMut::with_capacity(4096);
    while let Some(value) = session.read_request_body().await? {
        buf.put(value.as_ref());
    }
    Ok(buf)
}

/// The login UI's own files, which may be served before the visitor has
/// authenticated.
///
/// Only exact paths qualify (plus the Vite bundle under `/assets/`), and only
/// for a read: a suffix such as `.js`, `.css` or `.png` proves nothing, because
/// the route table also accepts bare paths (`/configs/...` as well as
/// `/api/configs/...`). Anything else — every API route, config history,
/// `/basic`, `/pprof`, and any path that merely *looks* static — must
/// authenticate.
fn is_public_asset(method: &Method, path: &str) -> bool {
    if method != Method::GET && method != Method::HEAD {
        return false;
    }
    path.starts_with("/assets/")
        || matches!(path, "/" | "/index.html" | "/favicon.ico" | "/vite.svg")
}

impl AdminServe {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(target: LOG_TARGET, params = redacted_params(params), "new admin server plugin");
        let serve = AdminServe::try_from(params)?;

        Ok(serve)
    }
    fn auth_validate(&self, req_header: &RequestHeader) -> bool {
        if self.allow_unauthenticated {
            return true;
        }
        // Construction rejects an empty list unless `allow_unauthenticated` is
        // set, so this is a belt-and-braces fail-closed default: a malformed
        // config must never turn into an open admin API.
        if self.authorizations.is_empty() {
            error!(
                target: LOG_TARGET,
                "auth validate fail: no authorizations configured"
            );
            return false;
        }
        let path = req_header.uri.path();
        if is_public_asset(&req_header.method, path) {
            return true;
        }
        let value =
            pingap_core::get_req_header_value(req_header, "Authorization")
                .unwrap_or_default();
        if value.is_empty() {
            error!(target: LOG_TARGET, path, "auth validate fail: missing authorization header");
            return false;
        }
        let Some((token, ts)) = value.split_once(':') else {
            error!(target: LOG_TARGET, path, "auth validate fail: malformed authorization, expect token:ts");
            return false;
        };
        let now = pingap_core::now_sec() as i64;
        let parsed_ts = ts.parse::<i64>().unwrap_or_default();
        let offset = now - parsed_ts;
        let max_age = self.max_age.as_secs() as i64;
        if offset.abs() > max_age {
            error!(
                target: LOG_TARGET,
                path,
                ts,
                parsed_ts,
                now,
                offset,
                max_age,
                "auth validate fail: timestamp out of max_age window"
            );
            return false;
        }

        for (user, pass) in self.authorizations.iter() {
            let mut hasher = Sha256::new();
            hasher.update(format!("{user}:{pass}:{ts}").as_bytes());
            let hash256 = hasher.finalize();
            if pingap_core::constant_time_eq(
                hash256.encode_hex::<String>().as_bytes(),
                token.as_bytes(),
            ) {
                return true;
            }
        }
        error!(
            target: LOG_TARGET,
            path,
            ts,
            authorizations = self.authorizations.len(),
            "auth validate fail: token hash mismatch"
        );
        false
    }
    async fn load_config(
        &self,
        replace_include: bool,
    ) -> pingora::Result<PingapConfig> {
        let config = self.manager.load_all().await.map_err(|e| {
            error!(target: LOG_TARGET, "failed to load config: {e}");
            pingap_core::new_internal_error(400, e)
        })?;
        let config = config.to_pingap_config(replace_include).map_err(|e| {
            error!(target: LOG_TARGET, "failed to convert config: {e}");
            pingap_core::new_internal_error(400, e)
        })?;
        Ok(config)
    }
    async fn get_config(
        &self,
        category: &str,
    ) -> pingora::Result<HttpResponse> {
        let conf = self.load_config(false).await?;
        if category == "full" {
            let full_conf = self.load_config(true).await?;
            let mut full_toml = toml::to_string_pretty(&full_conf)
                .map_err(|e| pingap_core::new_internal_error(400, e))?;
            if let Ok(value) = pingap_util::toml_omit_empty_value(&full_toml) {
                full_toml = value;
            };
            let hcl = convert_toml_to_hcl(&full_toml)
                .map_err(|e| pingap_core::new_internal_error(400, e))?;
            let kdl = convert_toml_to_kdl(&full_toml)
                .map_err(|e| pingap_core::new_internal_error(400, e))?;
            let mut original_toml = toml::to_string_pretty(&conf)
                .map_err(|e| pingap_core::new_internal_error(400, e))?;
            if let Ok(value) =
                pingap_util::toml_omit_empty_value(&original_toml)
            {
                original_toml = value;
            };
            return HttpResponse::try_from_json(&FullConfigJson {
                hcl,
                kdl,
                full: full_toml,
                original: original_toml,
            });
        }
        let resp = match category {
            CATEGORY_UPSTREAM => HttpResponse::try_from_json(&conf.upstreams)?,
            CATEGORY_LOCATION => HttpResponse::try_from_json(&conf.locations)?,
            CATEGORY_SERVER => HttpResponse::try_from_json(&conf.servers)?,
            CATEGORY_PLUGIN => HttpResponse::try_from_json(&conf.plugins)?,
            CATEGORY_CERTIFICATE => {
                HttpResponse::try_from_json(&conf.certificates)?
            },
            _ => HttpResponse::try_from_json(&conf)?,
        };
        Ok(resp)
    }

    async fn remove_config(
        &self,
        category: &str,
        name: &str,
    ) -> pingora::Result<HttpResponse> {
        let category = Category::from_str(category)
            .map_err(|e| pingap_core::new_internal_error(400, e))?;
        self.manager.delete(category, name).await.map_err(|e| {
            error!(target: LOG_TARGET, error = e.to_string(), "delete config fail");
            pingap_core::new_internal_error(400, e)
        })?;
        Ok(HttpResponse::no_content())
    }
    async fn handle_update_config<T>(
        &self,
        name: &str,
        buf: &[u8],
        category: Category,
    ) -> pingora::Result<()>
    where
        T: DeserializeOwned + Serialize + Send + Sync + Validate,
    {
        let conf: T = serde_json::from_slice(buf).map_err(|e| {
            error!(
                target: LOG_TARGET,
                error = e.to_string(),
                "parse {} config fail",
                category.to_string()
            );
            pingap_core::new_internal_error(400, e)
        })?;
        conf.validate().map_err(|e| {
            error!(target: LOG_TARGET, error = e.to_string(), "validate config fail");
            pingap_core::new_internal_error(400, e)
        })?;

        self.manager
            .update(category, name, &conf)
            .await
            .map_err(|e| {
                error!(target: LOG_TARGET, error = e.to_string(), "update config fail");
                pingap_core::new_internal_error(400, e)
            })?;

        Ok(())
    }

    async fn update_config(
        &self,
        session: &mut Session,
        category: &str,
        name: &str,
    ) -> pingora::Result<HttpResponse> {
        if name.is_empty() {
            return Err(pingap_core::new_internal_error(
                400,
                "name is empty".to_string(),
            ));
        }
        let buf = get_request_body(session).await?;

        match category {
            CATEGORY_UPSTREAM => {
                self.handle_update_config::<UpstreamConf>(
                    name,
                    &buf,
                    Category::Upstream,
                )
                .await?;
            },
            CATEGORY_LOCATION => {
                self.handle_update_config::<LocationConf>(
                    name,
                    &buf,
                    Category::Location,
                )
                .await?;
            },
            CATEGORY_SERVER => {
                self.handle_update_config::<ServerConf>(
                    name,
                    &buf,
                    Category::Server,
                )
                .await?;
            },
            CATEGORY_PLUGIN => {
                self.handle_update_config::<PluginConf>(
                    name,
                    &buf,
                    Category::Plugin,
                )
                .await?;
            },
            CATEGORY_CERTIFICATE => {
                self.handle_update_config::<CertificateConf>(
                    name,
                    &buf,
                    Category::Certificate,
                )
                .await?;
            },
            CATEGORY_STORAGE => {
                self.handle_update_config::<StorageConf>(
                    name,
                    &buf,
                    Category::Storage,
                )
                .await?;
            },
            _ => {
                self.handle_update_config::<BasicConf>(
                    "",
                    &buf,
                    Category::Basic,
                )
                .await?;
            },
        };

        Ok(HttpResponse::no_content())
    }
    async fn import_config(
        &self,
        session: &mut Session,
    ) -> pingora::Result<HttpResponse> {
        let buf = get_request_body(session).await?;
        let config: PingapTomlConfig = toml::from_slice(&buf).map_err(|e| {
            error!(target: LOG_TARGET, error = e.to_string(), "import config fail");
            pingap_core::new_internal_error(400, e)
        })?;
        // A per-category write validates before it is stored; a wholesale
        // import replaces every category at once, so it must pass the same
        // gate or it can install a config the process would refuse to boot.
        validate_import(&config).map_err(|e| {
            error!(target: LOG_TARGET, error = e, "import config fail");
            pingap_core::new_internal_error(400, e)
        })?;
        self.manager.save_all(&config).await.map_err(|e| {
            error!(target: LOG_TARGET, error = e.to_string(), "import config fail");
            pingap_core::new_internal_error(400, e)
        })?;

        Ok(HttpResponse::no_content())
    }
}

/// Runs the startup validation over an imported configuration, before any of
/// it is written to the backing store.
fn validate_import(
    config: &PingapTomlConfig,
) -> std::result::Result<(), String> {
    let parsed = config.to_pingap_config(true).map_err(|e| e.to_string())?;
    parsed.validate().map_err(|e| e.to_string())?;
    validate_servers_tls_for_backend(&parsed.servers)
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn get_method_path(session: &Session) -> (Method, String) {
    let req_header = session.req_header();
    let method = req_header.method.clone();
    let path = req_header.uri.path();
    (method, path.to_string())
}

/// Query parameters accepted by the profiling endpoints, matching the
/// control plane's `/debug/pprof` contract.
#[derive(Debug, Default)]
struct PprofQuery {
    seconds: Option<u64>,
    frequency: Option<i32>,
}

fn pprof_query(session: &Session) -> PprofQuery {
    let mut query = PprofQuery::default();
    let Some(raw) = session.req_header().uri.query() else {
        return query;
    };
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        match &*key {
            "seconds" => query.seconds = value.parse().ok(),
            "frequency" => query.frequency = value.parse().ok(),
            _ => {},
        };
    }
    query
}

/// Renders a profiling failure like the control plane does: 409 while
/// another capture is running, 501 where sampling cannot run at all, 500
/// otherwise.
fn pprof_error_response(err: varman_pprof::ProfileError) -> HttpResponse {
    error!(target: LOG_TARGET, error = %err, "pprof request fail");
    let status = match err {
        varman_pprof::ProfileError::AlreadyActive => StatusCode::CONFLICT,
        varman_pprof::ProfileError::UnsupportedPlatform => {
            StatusCode::NOT_IMPLEMENTED
        },
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    HttpResponse::try_from_json_status(
        &ErrorResponse {
            message: err.to_string(),
        },
        status,
    )
    .unwrap_or(HttpResponse::unknown_error("Json serde fail"))
}

/// `GET /api/pprof/{profile,flamegraph,memory}` — built-in profiling of this
/// data-plane process, mirroring the control plane's `/debug/pprof` endpoints.
/// Auth is enforced by `auth_validate` before the admin route chain runs.
async fn handle_pprof_request(
    session: &Session,
    path: &str,
    method: &Method,
) -> HttpResponse {
    if method != Method::GET {
        return HttpResponse::bad_request("Only GET is supported");
    }
    let endpoint = path.substring("/pprof/".len(), path.len());
    if endpoint == "memory" {
        return HttpResponse::try_from_json(&varman_pprof::memory_snapshot())
            .unwrap_or(HttpResponse::unknown_error("Json serde fail"));
    }
    if endpoint != "profile" && endpoint != "flamegraph" {
        return HttpResponse::not_found("Unknown pprof endpoint");
    }

    let query = pprof_query(session);
    let profiling = match varman_pprof::start_session(
        query.frequency.unwrap_or_default(),
    ) {
        Ok(profiling) => profiling,
        Err(err) => return pprof_error_response(err),
    };
    let seconds = query
        .seconds
        .unwrap_or(varman_pprof::DEFAULT_SECONDS)
        .clamp(1, varman_pprof::MAX_SECONDS);
    tokio::time::sleep(Duration::from_secs(seconds)).await;

    // Symbolising and encoding the report is CPU-bound work that must not
    // run on the async runtime.
    if endpoint == "profile" {
        match tokio::task::spawn_blocking(move || profiling.finish_pprof())
            .await
        {
            Ok(Ok(bytes)) => HttpResponse::builder(StatusCode::OK)
                .header((
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/octet-stream"),
                ))
                // The body is already gzip; stating it keeps any downstream
                // compressor from encoding it a second time.
                .header((
                    header::CONTENT_ENCODING,
                    HeaderValue::from_static("gzip"),
                ))
                .header((
                    header::CONTENT_DISPOSITION,
                    HeaderValue::from_static(
                        "attachment; filename=\"varman-cpu.pb.gz\"",
                    ),
                ))
                .no_store()
                .body(bytes)
                .finish(),
            Ok(Err(err)) => pprof_error_response(err),
            Err(err) => pprof_error_response(
                varman_pprof::ProfileError::Report(err.to_string()),
            ),
        }
    } else {
        match tokio::task::spawn_blocking(move || profiling.finish_flamegraph())
            .await
        {
            Ok(Ok(svg)) => HttpResponse::builder(StatusCode::OK)
                .header((
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("image/svg+xml"),
                ))
                .no_store()
                .body(svg)
                .finish(),
            Ok(Err(err)) => pprof_error_response(err),
            Err(err) => pprof_error_response(
                varman_pprof::ProfileError::Report(err.to_string()),
            ),
        }
    }
}

async fn handle_request_admin(
    plugin: &AdminServe,
    session: &mut Session,
    ctx: &mut Ctx,
) -> pingora::Result<Option<HttpResponse>> {
    let ip = pingap_core::ensure_client_ip(session, ctx);
    if !plugin.ip_fail_limit.validate(ip) {
        return Ok(Some(HttpResponse {
            status: StatusCode::FORBIDDEN,
            body: Bytes::from_static(b"Forbidden, too many failures"),
            ..Default::default()
        }));
    }

    let header = session.req_header_mut();
    let path = header.uri.path();
    let mut new_path =
        path.substring(plugin.path.len(), path.len()).to_string();
    if plugin.path.len() > 1 && new_path.is_empty() {
        new_path = format!("{path}/");
        if let Some(query) = header.uri.query() {
            new_path = format!("{new_path}?{query}");
        }
        let resp = HttpResponse::redirect(&new_path)?;
        return Ok(Some(resp));
    }
    if let Some(query) = header.uri.query() {
        new_path = format!("{new_path}?{query}");
    }
    // ignore parse error
    if let Ok(uri) = new_path.parse::<http::Uri>() {
        header.set_uri(uri);
    }
    if !plugin.auth_validate(header) {
        plugin.ip_fail_limit.inc(ip);
        return Ok(Some(HttpResponse {
            status: StatusCode::UNAUTHORIZED,
            ..Default::default()
        }));
    }
    let (method, mut path) = get_method_path(session);
    let api_prefix = "/api";
    if path.starts_with(api_prefix) {
        path = path.substring(api_prefix.len(), path.len()).to_string();
    }
    let params: Vec<String> = path
        .split('/')
        .map(|item| decode(item).unwrap_or_default().to_string())
        .collect();
    let mut category = "";
    if params.len() >= 3 {
        category = &params[2];
    }
    let resp = if path.starts_with("/configs") {
        match method {
            Method::POST => {
                if category == "import" {
                    plugin.import_config(session).await
                } else if params.len() < 4 {
                    Err(pingora::Error::new_str("Url is invalid(no name)"))
                } else {
                    plugin.update_config(session, category, &params[3]).await
                }
            },
            Method::DELETE => {
                if params.len() < 4 {
                    Err(pingora::Error::new_str("Url is invalid(no name)"))
                } else {
                    plugin.remove_config(category, &params[3]).await
                }
            },
            _ => plugin.get_config(category).await,
        }
        .unwrap_or_else(|err| {
            HttpResponse::try_from_json_status(
                &ErrorResponse {
                    message: err.to_string(),
                },
                StatusCode::INTERNAL_SERVER_ERROR,
            )
            .unwrap_or(HttpResponse::unknown_error("Json serde fail"))
        })
    } else if path.starts_with("/config-history") {
        let category = Category::from_str(category).map_err(|e| {
            error!(target: LOG_TARGET, error = e.to_string(), "get config category fail");
            pingap_core::new_internal_error(400, e)
        })?;
        // The name segment is optional in the url but not in the code below,
        // so reject a short url instead of indexing past the end of `params`.
        let Some(name) = params.get(3).cloned() else {
            return Err(pingap_core::new_internal_error(
                400,
                "Url is invalid(no name)",
            ));
        };
        let arr = plugin.manager.history(category.clone(), &name).await.map_err(|e| {
            error!(target: LOG_TARGET, error = e.to_string(), "get config history fail");
            pingap_core::new_internal_error(400, e)
        })?.unwrap_or_default();

        let mut history = vec![];
        for item in arr {
            let data:toml::Table = toml::from_str(&item.data).map_err(|e| {
                error!(target: LOG_TARGET, error = e.to_string(), "get config history fail");
                pingap_core::new_internal_error(400, e)
            })?;
            let key = format_category(&category);
            let Some(data) = data.get(key).cloned() else {
                continue;
            };
            let data = if name.is_empty() {
                data
            } else {
                let Some(data) = data.get(&name).cloned() else {
                    continue;
                };
                data
            };
            history.push(json!({
                "created_at": item.created_at,
                "data": data,
            }));
        }
        HttpResponse::try_from_json(&json!({
            "history": history,
        }))
        .unwrap_or(HttpResponse::unknown_error("Json serde fail"))
    } else if path == "/basic" {
        let current_config = plugin.load_config(true).await?;
        let info = get_process_system_info();

        let (processing, accepted) = get_processing_accepted();

        let mut basic_info = BasicInfo {
            start_time: get_start_time(),
            version: pingap_util::get_pkg_version().to_string(),
            rustc_version: pingap_util::get_rustc_version().to_string(),
            config_hash: plugin
                .manager
                .get_current_config()
                .hash()
                .unwrap_or_default(),
            user: current_config.basic.user.clone().unwrap_or_default(),
            group: current_config.basic.group.clone().unwrap_or_default(),
            pid: info.pid.to_string(),
            threads: info.threads,
            accepted,
            processing,
            kernel: info.kernel,
            memory_mb: info.memory_mb,
            memory: info.memory,
            arch: info.arch,
            cpus: info.cpus,
            physical_cpus: info.physical_cpus,
            total_memory: info.total_memory,
            used_memory: info.used_memory,
            features: vec![],
            fd_count: info.fd_count,
            tcp_count: info.tcp_count,
            tcp6_count: info.tcp6_count,
            supported_plugins: get_plugin_factory().supported_plugins(),
            upstream_healthy_status: new_upstream_provider().healthy_status(),
            support_history: plugin.manager.support_history(),
            git_hash: crate::git_hash().to_string(),
            now: pingap_core::now_sec(),
        };
        basic_info.features.push("default".to_string());
        // TLS backend name (`openssl` or `rustls`) so the admin UI can disable
        // settings the active binary cannot honour and show it on the home page.
        basic_info
            .features
            .push(pingap_certificate::TLS_BACKEND.to_string());

        cfg_if::cfg_if! {
            if #[cfg(feature = "tracing")] {
                basic_info.features.push("tracing".to_string());
            }
        }
        cfg_if::cfg_if! {
            if #[cfg(feature = "full")] {
                basic_info.features.push("full".to_string());
            }
        }
        cfg_if::cfg_if! {
            if #[cfg(feature = "pyro")] {
                basic_info.features.push("pyroscope".to_string());
            }
        }

        HttpResponse::try_from_json(&basic_info)
            .unwrap_or(HttpResponse::unknown_error("Json serde fail"))
    } else if path == "/restart" && method == Method::POST {
        if let Err(e) = restart_now().await {
            error!(target: LOG_TARGET, error = e.to_string(), "Restart fail");
            HttpResponse::bad_request(e.to_string())
        } else {
            HttpResponse::no_content()
        }
    } else if path == "/aes" {
        let buf = get_request_body(session).await?;
        let params: AesParams = serde_json::from_slice(buf.as_ref())
            .map_err(|e| pingap_core::new_internal_error(400, e))?;
        let value = if params.category == "encrypt" {
            pingap_util::aes_encrypt(&params.key, &params.data)
        } else {
            pingap_util::aes_decrypt(&params.key, &params.data)
        }
        .map_err(|e| pingap_core::new_internal_error(400, e))?;
        HttpResponse::try_from_json(&AesResp { value })
            .unwrap_or(HttpResponse::unknown_error("Json serde fail"))
    } else if path == "/certificates" {
        let mut infos = HashMap::new();
        for (name, cert) in new_certificate_provider().list().iter() {
            if let Some(info) = &cert.info {
                let key = if let Some(value) = &cert.name {
                    value.clone()
                } else {
                    name.clone()
                };
                infos.insert(key, info.clone());
            }
        }
        HttpResponse::try_from_json(&infos)
            .unwrap_or(HttpResponse::unknown_error("Json serde fail"))
    } else if path.starts_with("/pprof/") {
        handle_pprof_request(session, &path, &method).await
    } else {
        let mut file = path.substring(1, path.len());
        if file.is_empty() {
            file = "index.html";
        }
        EmbeddedStaticFile(
            AdminAsset::get(file),
            Duration::from_secs(365 * 24 * 3600),
        )
        .into()
    };
    Ok(Some(resp))
}

#[async_trait]
impl Plugin for AdminServe {
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if self.plugin_step != step {
            return Ok(RequestPluginResult::Skipped);
        }
        if !session.req_header().uri.path().starts_with(&self.path) {
            return Ok(RequestPluginResult::Skipped);
        }
        let resp = handle_request_admin(self, session, _ctx).await?;
        if let Some(resp) = resp {
            return Ok(RequestPluginResult::Respond(resp));
        }
        Ok(RequestPluginResult::Continue)
    }
}

#[ctor(unsafe)]
fn init() {
    get_plugin_factory()
        .register("admin", |params| Ok(Arc::new(AdminServe::new(params)?)));
}

#[cfg(test)]
mod tests {
    use super::{
        AdminAsset, AdminServe, EmbeddedStaticFile, handle_request_admin,
        is_public_asset, validate_import,
    };
    use crate::config_manager::try_init_config_manager;
    use http::Method;
    use pingap_config::{PingapTomlConfig, PluginConf};
    use pingap_core::{Ctx, HttpResponse};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use std::time::Duration;
    use tokio_test::io::Builder;

    #[test]
    fn test_admin_params() {
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        try_init_config_manager(&file.path().to_string_lossy()).unwrap();
        // spellchecker:off
        let params = AdminServe::try_from(
            &toml::from_str::<PluginConf>(
                r#"
    category = "admin"
    path = "/"
    authorizations = [
        "YWRtaW46MTIzMTIz",
        "cGluZ2FwOjEyMzEyMw=="
    ]
    "#,
            )
            .unwrap(),
        )
        .unwrap();
        // spellchecker:on
        assert_eq!(
            "admin:123123,pingap:123123",
            params
                .authorizations
                .iter()
                .map(|item| format!("{}:{}", item.0, item.1))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!("request", params.plugin_step.to_string());
        assert_eq!("/", params.path);

        let result = AdminServe::try_from(
            &toml::from_str::<PluginConf>(
                r#"
    category = "admin"
    path = "/"
    authorizations = [
        "123",
    ]
    "#,
            )
            .unwrap(),
        );

        assert_eq!(
            "Plugin basic_auth, base64 decode error Invalid padding",
            result.err().unwrap().to_string()
        );
    }

    #[test]
    fn test_embedded_static_file() {
        // `web/dist/` is the same bundle the control plane embeds. A clean
        // checkout has no bundle until `make build-web`; skip gracefully
        // instead of panicking when it isn't present.
        let Some(file) = AdminAsset::get("index.html") else {
            eprintln!(
                "skipping test_embedded_static_file: web/dist/index.html not built (run `make build-web`)"
            );
            return;
        };
        let resp: HttpResponse =
            EmbeddedStaticFile(Some(file), Duration::from_secs(60)).into();
        assert_eq!(true, !resp.body.is_empty());
        assert_eq!(200, resp.status.as_u16());
        assert_eq!(0, resp.max_age.unwrap_or_default());
        assert_eq!(
            r#"("content-type", "text/html")"#,
            format!("{:?}", resp.headers.unwrap_or_default()[0])
        );

        let resp: HttpResponse =
            EmbeddedStaticFile(None, Duration::from_secs(60)).into();
        assert_eq!(404, resp.status.as_u16())
    }

    #[test]
    fn test_auth_validate_skips_only_public_assets() {
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        try_init_config_manager(&file.path().to_string_lossy()).unwrap();
        // spellchecker:off
        let admin = AdminServe::try_from(
            &toml::from_str::<PluginConf>(
                r#"
    category = "admin"
    path = "/"
    authorizations = ["YWRtaW46MTIzMTIz"]
    "#,
            )
            .unwrap(),
        )
        .unwrap();
        // spellchecker:on

        // `auth_validate` runs on the path AFTER the admin prefix is stripped.
        let auth_skipped = |method: Method, path: &str| {
            let req = pingora::http::RequestHeader::build(
                method,
                path.as_bytes(),
                None,
            )
            .unwrap();
            admin.auth_validate(&req)
        };

        // Genuine static assets of the login UI load without auth.
        assert_eq!(true, auth_skipped(Method::GET, "/"));
        assert_eq!(true, auth_skipped(Method::GET, "/index.html"));
        assert_eq!(true, auth_skipped(Method::GET, "/favicon.ico"));
        assert_eq!(true, auth_skipped(Method::GET, "/vite.svg"));
        assert_eq!(true, auth_skipped(Method::GET, "/assets/index-abc.js"));

        // Regression: the bare-path router accepts `/configs` too, so a
        // static-looking suffix must never skip auth.
        assert_eq!(false, auth_skipped(Method::GET, "/configs/full.js"));
        assert_eq!(false, auth_skipped(Method::GET, "/api/configs/full.js"));
        assert_eq!(false, auth_skipped(Method::GET, "/config-history/x.css"));
        assert_eq!(
            false,
            auth_skipped(Method::POST, "/configs/upstream/evil.js")
        );
        assert_eq!(false, auth_skipped(Method::GET, "/api/basic"));
        assert_eq!(false, auth_skipped(Method::GET, "/pingap.png"));
        assert_eq!(false, auth_skipped(Method::POST, "/assets/index.js"));
    }

    #[test]
    fn test_public_asset_requires_exact_path_and_read_method() {
        assert_eq!(true, is_public_asset(&Method::GET, "/"));
        assert_eq!(true, is_public_asset(&Method::HEAD, "/"));
        assert_eq!(true, is_public_asset(&Method::GET, "/assets/index-abc.js"));
        assert_eq!(true, is_public_asset(&Method::HEAD, "/assets/index.css"));

        assert_eq!(false, is_public_asset(&Method::GET, "/configs/full.js"));
        assert_eq!(
            false,
            is_public_asset(&Method::GET, "/api/configs/full.js")
        );
        assert_eq!(
            false,
            is_public_asset(&Method::GET, "/config-history/x.css")
        );
        assert_eq!(false, is_public_asset(&Method::GET, "/basic"));
        assert_eq!(false, is_public_asset(&Method::GET, "/pprof/memory.js"));
        assert_eq!(
            false,
            is_public_asset(&Method::POST, "/configs/upstream/evil.js")
        );
        assert_eq!(false, is_public_asset(&Method::POST, "/assets/index.js"));
        assert_eq!(false, is_public_asset(&Method::POST, "/"));
    }

    #[test]
    fn test_admin_auth_construction_fails_closed() {
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        try_init_config_manager(&file.path().to_string_lossy()).unwrap();
        let build = |conf: &str| {
            AdminServe::try_from(&toml::from_str::<PluginConf>(conf).unwrap())
        };

        // An empty list used to mean "no authentication"; it is now an error.
        let err = build(r#"category = "admin""#).err().unwrap();
        assert!(
            err.to_string().contains("authorizations is empty"),
            "unexpected error: {err}"
        );
        let err = build(
            r#"
category = "admin"
authorizations = []
"#,
        )
        .err()
        .unwrap();
        assert!(
            err.to_string().contains("authorizations is empty"),
            "unexpected error: {err}"
        );

        // A decoded entry without `user:pass` is rejected, naming the index.
        // spellchecker:off
        let err = build(
            r#"
category = "admin"
authorizations = ["YWRtaW46MTIzMTIz", "bm9jb2xvbg=="]
"#,
        )
        .err()
        .unwrap();
        // spellchecker:on
        assert!(
            err.to_string().contains("authorizations[1]"),
            "unexpected error: {err}"
        );

        // An explicitly empty entry (what `--admin host:port` emits) is
        // rejected too: authentication can only be turned off on purpose.
        let err = build(
            r#"
category = "admin"
authorizations = [""]
"#,
        )
        .err()
        .unwrap();
        assert!(
            err.to_string().contains("authorizations[0]"),
            "unexpected error: {err}"
        );

        // One valid entry is enough.
        assert!(
            build(
                r#"
category = "admin"
authorizations = ["YWRtaW46MTIzMTIz"]
"#
            )
            .is_ok()
        );

        // The explicit opt-out still allows an empty list.
        assert!(
            build(
                r#"
category = "admin"
allow_unauthenticated = true
"#
            )
            .is_ok()
        );
    }

    #[test]
    fn test_validate_import_rejects_invalid_config() {
        let valid: PingapTomlConfig = toml::from_str(
            r#"
[basic]
log_level = "info"
"#,
        )
        .unwrap();
        assert_eq!(Ok(()), validate_import(&valid));

        // An upstream without addresses would be stored by `save_all` today
        // and only fail at the next restart.
        let invalid: PingapTomlConfig = toml::from_str(
            r#"
[upstreams.bad]
addrs = []
"#,
        )
        .unwrap();
        let err = validate_import(&invalid).err().unwrap();
        assert!(
            err.contains("upstream addrs is empty"),
            "unexpected error: {err}"
        );
    }

    /// Regression: `/config-history/{category}` without the trailing name used
    /// to index past the end of the split url and panic the request task.
    #[tokio::test]
    async fn test_config_history_without_name() {
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        try_init_config_manager(&file.path().to_string_lossy()).unwrap();
        let admin = AdminServe::try_from(
            &toml::from_str::<PluginConf>(
                r#"
category = "admin"
allow_unauthenticated = true
"#,
            )
            .unwrap(),
        )
        .unwrap();

        let mock_io = Builder::new()
            .read(b"GET /api/config-history/upstream HTTP/1.1\r\n\r\n")
            .build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let err =
            handle_request_admin(&admin, &mut session, &mut Ctx::default())
                .await
                .err()
                .unwrap();
        assert_eq!(
            true,
            err.to_string().contains("Url is invalid(no name)"),
            "unexpected error: {err}"
        );
    }
}
