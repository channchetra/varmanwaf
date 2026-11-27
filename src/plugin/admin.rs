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
use crate::process::{get_start_time, restart_now};
use crate::upstreams::new_upstream_provider;
use async_trait::async_trait;
use bytes::Bytes;
use bytes::{BufMut, BytesMut};
use hex::ToHex;
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
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use substring::Substring;
use tracing::{debug, error, warn};
use urlencoding::decode;

type Result<T> = std::result::Result<T, Error>;

static LOG_TARGET: &str = "main::admin";

pub struct AdminServe {
    pub path: String,
    pub authorizations: Vec<(String, String)>,
    pub plugin_step: PluginStep,
    config_manager: Arc<ConfigManager>,
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

impl AdminServe {
    /// Creates the admin API plugin, reading and writing the configuration
    /// through `config_manager`.
    ///
    /// The manager is a parameter rather than a process-global lookup: the
    /// assembly and reload paths already own one, so construction carries no
    /// start-up ordering requirement and a test can inject a local instance.
    pub fn new(
        value: &PluginConf,
        config_manager: Arc<ConfigManager>,
    ) -> Result<Self> {
        debug!(target: LOG_TARGET, params = redacted_params(value), "new admin server plugin");
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
            config_manager,
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

impl AdminServe {
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
        let config = self.config_manager.load_all().await.map_err(|e| {
            error!(target: LOG_TARGET, "failed to load config: {e}");
            pingap_core::new_internal_error(500, e)
        })?;
        let config = config.to_pingap_config(replace_include).map_err(|e| {
            error!(target: LOG_TARGET, "failed to convert config: {e}");
            pingap_core::new_internal_error(500, e)
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
                .map_err(|e| pingap_core::new_internal_error(500, e))?;
            if let Ok(value) = pingap_util::toml_omit_empty_value(&full_toml) {
                full_toml = value;
            };
            let hcl = convert_toml_to_hcl(&full_toml)
                .map_err(|e| pingap_core::new_internal_error(500, e))?;
            let kdl = convert_toml_to_kdl(&full_toml)
                .map_err(|e| pingap_core::new_internal_error(500, e))?;
            let mut original_toml = toml::to_string_pretty(&conf)
                .map_err(|e| pingap_core::new_internal_error(500, e))?;
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
            .map_err(|e| pingap_core::new_internal_error(500, e))?;
        self.config_manager.delete(category, name).await.map_err(|e| {
            error!(target: LOG_TARGET, error = e.to_string(), "delete config fail");
            pingap_core::new_internal_error(500, e)
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
            pingap_core::new_internal_error(500, e)
        })?;
        conf.validate().map_err(|e| {
            error!(target: LOG_TARGET, error = e.to_string(), "validate config fail");
            pingap_core::new_internal_error(500, e)
        })?;

        self.config_manager
            .update(category, name, &conf)
            .await
            .map_err(|e| {
                error!(target: LOG_TARGET, error = e.to_string(), "update config fail");
                pingap_core::new_internal_error(500, e)
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
            pingap_core::new_internal_error(500, e)
        })?;
        // A per-category write validates before it is stored; a wholesale
        // import replaces every category at once, so it must pass the same
        // gate or it can install a config the process would refuse to boot.
        validate_import(&config).map_err(|e| {
            error!(target: LOG_TARGET, error = e, "import config fail");
            pingap_core::new_internal_error(500, e)
        })?;
        self.config_manager.save_all(&config).await.map_err(|e| {
            error!(target: LOG_TARGET, error = e.to_string(), "import config fail");
            pingap_core::new_internal_error(500, e)
        })?;

        Ok(HttpResponse::no_content())
    }

    /// `GET|POST|DELETE /configs[/{category}[/{name}]]` — read the running
    /// configuration or write a single category entry. Failures are reported
    /// as a 500 with the error message, matching the old inline dispatcher.
    async fn handle_configs(
        &self,
        session: &mut Session,
        method: Method,
        category: &str,
        params: &[String],
    ) -> HttpResponse {
        let result = match method {
            Method::POST => {
                if category == "import" {
                    self.import_config(session).await
                } else if params.len() < 4 {
                    Err(pingora::Error::new_str("Url is invalid(no name)"))
                } else {
                    self.update_config(session, category, &params[3]).await
                }
            },
            Method::DELETE => {
                if params.len() < 4 {
                    Err(pingora::Error::new_str("Url is invalid(no name)"))
                } else {
                    self.remove_config(category, &params[3]).await
                }
            },
            _ => self.get_config(category).await,
        };
        result.unwrap_or_else(|err| {
            HttpResponse::try_from_json_status(
                &ErrorResponse {
                    message: err.to_string(),
                },
                StatusCode::INTERNAL_SERVER_ERROR,
            )
            .unwrap_or(HttpResponse::unknown_error("Json serde fail"))
        })
    }

    /// `GET /config-history/{category}[/{name}]` — stored revisions of a
    /// category, or of one entry inside it.
    async fn handle_config_history(
        &self,
        category: &str,
        params: &[String],
    ) -> pingora::Result<HttpResponse> {
        let category = Category::from_str(category).map_err(|e| {
            error!(target: LOG_TARGET, error = e.to_string(), "get config category fail");
            pingap_core::new_internal_error(500, e)
        })?;
        // The name segment is optional in the url but not in the code below,
        // so reject a short url instead of indexing past the end of `params`.
        let Some(name) = params.get(3).cloned() else {
            return Err(pingap_core::new_internal_error(
                400,
                "Url is invalid(no name)",
            ));
        };
        let history = self.config_history_entries(&category, &name).await?;
        Ok(HttpResponse::try_from_json(&json!({
            "history": history,
        }))
        .unwrap_or(HttpResponse::unknown_error("Json serde fail")))
    }

    /// Loads the stored revisions of one entry and shapes them for the console,
    /// skipping revisions that do not contain the category or the entry.
    async fn config_history_entries(
        &self,
        category: &Category,
        name: &str,
    ) -> pingora::Result<Vec<serde_json::Value>> {
        let arr = self
            .config_manager
            .history(category.clone(), name)
            .await
            .map_err(|e| {
                error!(target: LOG_TARGET, error = e.to_string(), "get config history fail");
                pingap_core::new_internal_error(500, e)
            })?
            .unwrap_or_default();

        let mut history = vec![];
        for item in arr {
            let data: toml::Table = toml::from_str(&item.data).map_err(|e| {
                error!(target: LOG_TARGET, error = e.to_string(), "get config history fail");
                pingap_core::new_internal_error(500, e)
            })?;
            let key = format_category(category);
            let Some(data) = data.get(key).cloned() else {
                continue;
            };
            let data = if name.is_empty() {
                data
            } else {
                let Some(data) = data.get(name).cloned() else {
                    continue;
                };
                data
            };
            history.push(json!({
                "created_at": item.created_at,
                "data": data,
            }));
        }
        Ok(history)
    }

    /// `GET /basic` — process, host and plugin facts for the console.
    async fn handle_basic(&self) -> pingora::Result<HttpResponse> {
        let current_config = self.load_config(true).await?;
        let info = get_process_system_info();

        let (processing, accepted) = get_processing_accepted();

        let basic_info = BasicInfo {
            start_time: get_start_time(),
            version: pingap_util::get_pkg_version().to_string(),
            rustc_version: pingap_util::get_rustc_version().to_string(),
            config_hash: self
                .config_manager
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
            features: feature_flags(),
            fd_count: info.fd_count,
            tcp_count: info.tcp_count,
            tcp6_count: info.tcp6_count,
            supported_plugins: get_plugin_factory().supported_plugins(),
            upstream_healthy_status: new_upstream_provider().healthy_status(),
            support_history: self.config_manager.support_history(),
            git_hash: crate::git_hash().to_string(),
            now: pingap_core::now_sec(),
        };

        Ok(HttpResponse::try_from_json(&basic_info)
            .unwrap_or(HttpResponse::unknown_error("Json serde fail")))
    }

    /// `POST /restart` — graceful restart of the data-plane process.
    async fn handle_restart(&self) -> HttpResponse {
        if let Err(e) = restart_now().await {
            error!(target: LOG_TARGET, error = e.to_string(), "Restart fail");
            HttpResponse::bad_request(e.to_string())
        } else {
            HttpResponse::no_content()
        }
    }

    /// `POST /aes` — encrypt or decrypt a value with the console's AES key.
    async fn handle_aes(
        &self,
        session: &mut Session,
    ) -> pingora::Result<HttpResponse> {
        let buf = get_request_body(session).await?;
        let params: AesParams = serde_json::from_slice(buf.as_ref())
            .map_err(|e| pingap_core::new_internal_error(500, e))?;
        let value = if params.category == "encrypt" {
            pingap_util::aes_encrypt(&params.key, &params.data)
        } else {
            pingap_util::aes_decrypt(&params.key, &params.data)
        }
        .map_err(|e| pingap_core::new_internal_error(500, e))?;
        Ok(HttpResponse::try_from_json(&AesResp { value })
            .unwrap_or(HttpResponse::unknown_error("Json serde fail")))
    }

    /// `GET /certificates` — certificate metadata known to this process.
    fn handle_certificates(&self) -> HttpResponse {
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
    }
}

/// Feature flags reported by `/basic`; the control-plane console uses them to
/// disable settings the running binary cannot honour. The TLS backend is named
/// (`openssl` or `rustls`) alongside the enabled cargo features.
fn feature_flags() -> Vec<String> {
    let mut features = vec![
        "default".to_string(),
        pingap_certificate::TLS_BACKEND.to_string(),
    ];
    cfg_if::cfg_if! {
        if #[cfg(feature = "tracing")] {
            features.push("tracing".to_string());
        }
    }
    cfg_if::cfg_if! {
        if #[cfg(feature = "full")] {
            features.push("full".to_string());
        }
    }
    cfg_if::cfg_if! {
        if #[cfg(feature = "pyro")] {
            features.push("pyroscope".to_string());
        }
    }
    features
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
    // A `/` mount strips the only slash, leaving a relative `basic`. `http::Uri`
    // parses that as an authority with an empty path, so the bare single-segment
    // routes (`/basic`, `/configs`, ...) would fall through to 404. Restore the
    // leading slash before rewriting the request URI.
    if !new_path.is_empty() && !new_path.starts_with('/') {
        new_path = format!("/{new_path}");
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
        plugin
            .handle_configs(session, method, category, &params)
            .await
    } else if path.starts_with("/config-history") {
        plugin.handle_config_history(category, &params).await?
    } else if path == "/basic" {
        plugin.handle_basic().await?
    } else if path == "/restart" && method == Method::POST {
        plugin.handle_restart().await
    } else if path == "/aes" {
        plugin.handle_aes(session).await?
    } else if path == "/certificates" {
        plugin.handle_certificates()
    } else if path.starts_with("/pprof/") {
        handle_pprof_request(session, &path, &method).await
    } else {
        // The data-plane plugin is an API only; the console bundle belongs to
        // `varman-control`, so any path outside the route table is a 404.
        HttpResponse::not_found("Not Found")
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

#[cfg(test)]
mod tests {
    use super::{AdminServe, handle_request_admin, validate_import};
    use hex::ToHex;
    use http::Method;
    use pingap_config::{ConfigManager, PingapTomlConfig, PluginConf};
    use pingap_core::{Ctx, HttpResponse};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use tokio_test::io::Builder;

    /// A local manager per test. Injection is the point of the constructor:
    /// the plugin no longer reads the process-global slot, so a test can hand
    /// it its own instance instead of installing one process-wide first.
    fn new_config_manager() -> Arc<ConfigManager> {
        Arc::new(pingap_config::new_memory_config_manager("[basic]\n", None))
    }

    /// Builds the `token:ts` header the admin API expects.
    fn auth_header(user: &str, pass: &str) -> String {
        auth_header_at(user, pass, pingap_core::now_sec())
    }

    /// Signs `user:pass` for a specific timestamp, so tests can age the token
    /// without changing the secret.
    fn auth_header_at(user: &str, pass: &str, ts: u64) -> String {
        let mut hasher = Sha256::new();
        hasher.update(format!("{user}:{pass}:{ts}").as_bytes());
        format!("{}:{ts}", hasher.finalize().encode_hex::<String>())
    }

    async fn admin_response(admin: &AdminServe, request: &str) -> HttpResponse {
        let mock_io = Builder::new().read(request.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        handle_request_admin(admin, &mut session, &mut Ctx::default())
            .await
            .unwrap()
            .unwrap()
    }

    /// A plugin over a per-test in-memory manager, unauthenticated so the
    /// mutation handlers can be driven without signing every request.
    fn admin_with_config(config: &str) -> (AdminServe, Arc<ConfigManager>) {
        let manager =
            Arc::new(pingap_config::new_memory_config_manager(config, None));
        let admin = AdminServe::new(
            &toml::from_str::<PluginConf>(
                r#"
    category = "admin"
    allow_unauthenticated = true
    "#,
            )
            .unwrap(),
            manager.clone(),
        )
        .unwrap();
        (admin, manager)
    }

    /// Drives the admin router with a request body, which is how the mutation
    /// handlers receive their payload.
    async fn admin_json_response(
        admin: &AdminServe,
        method: &str,
        path: &str,
        body: &str,
    ) -> HttpResponse {
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        admin_response(admin, &request).await
    }

    #[test]
    fn test_admin_params() {
        // spellchecker:off
        let params = AdminServe::new(
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
            new_config_manager(),
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

        let result = AdminServe::new(
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
            new_config_manager(),
        );

        assert_eq!(
            "Plugin basic_auth, base64 decode error Invalid padding",
            result.err().unwrap().to_string()
        );
    }

    #[test]
    fn test_auth_validate_requires_auth_for_every_path() {
        // spellchecker:off
        let admin = AdminServe::new(
            &toml::from_str::<PluginConf>(
                r#"
    category = "admin"
    path = "/"
    authorizations = ["YWRtaW46MTIzMTIz"]
    "#,
            )
            .unwrap(),
            new_config_manager(),
        )
        .unwrap();
        // spellchecker:on

        // `auth_validate` runs on the path AFTER the admin prefix is stripped.
        let request =
            |method: Method, path: &str, authorization: Option<&str>| {
                let mut req = pingora::http::RequestHeader::build(
                    method,
                    path.as_bytes(),
                    None,
                )
                .unwrap();
                if let Some(value) = authorization {
                    req.insert_header("authorization", value).unwrap();
                }
                req
            };

        // Nothing is public any more: the console moved to the control plane,
        // so every path — including the old login-page assets and paths that
        // merely look static — must authenticate.
        for path in [
            "/",
            "/index.html",
            "/favicon.ico",
            "/vite.svg",
            "/assets/index-abc.js",
            "/configs/full.js",
            "/api/configs/full.js",
            "/config-history/x.css",
            "/api/basic",
            "/pingap.png",
        ] {
            assert_eq!(
                false,
                admin.auth_validate(&request(Method::GET, path, None)),
                "{path} must require authentication"
            );
        }
        assert_eq!(
            false,
            admin.auth_validate(&request(
                Method::POST,
                "/configs/upstream/evil.js",
                None
            ))
        );

        // A valid signed token still authenticates any of them.
        let token = auth_header("admin", "123123");
        assert_eq!(
            true,
            admin.auth_validate(&request(
                Method::GET,
                "/configs/full",
                Some(&token)
            ))
        );
        assert_eq!(
            true,
            admin.auth_validate(&request(
                Method::GET,
                "/assets/index-abc.js",
                Some(&token)
            ))
        );

        // A token signed for a different password does not.
        let token = auth_header("admin", "wrong");
        assert_eq!(
            false,
            admin.auth_validate(&request(
                Method::GET,
                "/configs/full",
                Some(&token)
            ))
        );
    }

    #[tokio::test]
    async fn test_configs_full_requires_auth() {
        // spellchecker:off
        let admin = AdminServe::new(
            &toml::from_str::<PluginConf>(
                r#"
    category = "admin"
    path = "/"
    authorizations = ["YWRtaW46MTIzMTIz"]
    "#,
            )
            .unwrap(),
            new_config_manager(),
        )
        .unwrap();
        // spellchecker:on

        let request = |authorization: Option<&str>| {
            let mut value = String::from(
                "GET /configs/full HTTP/1.1\r\nHost: localhost\r\n",
            );
            if let Some(token) = authorization {
                value.push_str(&format!("Authorization: {token}\r\n"));
            }
            value.push_str("\r\n");
            value
        };

        let resp = admin_response(&admin, &request(None)).await;
        assert_eq!(401, resp.status.as_u16());

        let token = auth_header("admin", "123123");
        let resp = admin_response(&admin, &request(Some(&token))).await;
        assert_eq!(200, resp.status.as_u16());
    }

    /// Regression: a `/` mount strips the only slash from a single-segment
    /// route. `http::Uri` parsed the relative `basic` as an authority with an
    /// empty path, so `/basic` and `/configs` fell through to 404.
    #[tokio::test]
    async fn test_bare_single_segment_routes() {
        // spellchecker:off
        let admin = AdminServe::new(
            &toml::from_str::<PluginConf>(
                r#"
    category = "admin"
    path = "/"
    authorizations = ["YWRtaW46MTIzMTIz"]
    "#,
            )
            .unwrap(),
            new_config_manager(),
        )
        .unwrap();
        // spellchecker:on
        let token = auth_header("admin", "123123");

        for path in ["/basic", "/configs"] {
            let request = format!(
                "GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: {token}\r\n\r\n"
            );
            let resp = admin_response(&admin, &request).await;
            assert_eq!(200, resp.status.as_u16(), "{path}");
        }
    }

    /// A configured mount prefix must strip like the default `/` mount:
    /// `/prefix/configs/full` is the `/configs/full` route, the bare mount
    /// redirects to the directory form, and the directory form is the API
    /// root (which has no route, so 404 after authentication).
    #[tokio::test]
    async fn test_prefixed_mount_routes() {
        // spellchecker:off
        let admin = AdminServe::new(
            &toml::from_str::<PluginConf>(
                r#"
    category = "admin"
    path = "/prefix"
    authorizations = ["YWRtaW46MTIzMTIz"]
    "#,
            )
            .unwrap(),
            new_config_manager(),
        )
        .unwrap();
        // spellchecker:on
        let token = auth_header("admin", "123123");

        // `/prefix` -> `/prefix/`, keeping the query string.
        let request = format!(
            "GET /prefix?x=1 HTTP/1.1\r\nHost: localhost\r\nAuthorization: {token}\r\n\r\n"
        );
        let resp = admin_response(&admin, &request).await;
        assert_eq!(307, resp.status.as_u16());
        let location = resp
            .headers
            .iter()
            .flatten()
            .find(|(name, _)| name == http::header::LOCATION)
            .map(|(_, value)| value.to_str().unwrap_or_default().to_string());
        assert_eq!(Some("/prefix/?x=1".to_string()), location);

        // `/prefix/` is the API root: authenticated, then 404 like `/`.
        let request = format!(
            "GET /prefix/ HTTP/1.1\r\nHost: localhost\r\nAuthorization: {token}\r\n\r\n"
        );
        let resp = admin_response(&admin, &request).await;
        assert_eq!(404, resp.status.as_u16());

        // The prefixed routes match their definitions, with or without the
        // optional `/api` prefix.
        for path in ["/prefix/configs/full", "/prefix/api/configs/full"] {
            let request = format!(
                "GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: {token}\r\n\r\n"
            );
            let resp = admin_response(&admin, &request).await;
            assert_eq!(200, resp.status.as_u16(), "{path}");
        }
        // Authentication still runs on the stripped path.
        let request =
            "GET /prefix/basic HTTP/1.1\r\nHost: localhost\r\n\r\n".to_string();
        let resp = admin_response(&admin, &request).await;
        assert_eq!(401, resp.status.as_u16());
    }

    #[tokio::test]
    async fn test_unknown_path_returns_not_found() {
        // spellchecker:off
        let admin = AdminServe::new(
            &toml::from_str::<PluginConf>(
                r#"
    category = "admin"
    path = "/"
    authorizations = ["YWRtaW46MTIzMTIz"]
    "#,
            )
            .unwrap(),
            new_config_manager(),
        )
        .unwrap();
        // spellchecker:on
        let token = auth_header("admin", "123123");

        // `/` used to serve the embedded `index.html`; it is now just another
        // unknown path for this API-only plugin.
        for path in ["/", "/does-not-exist.js"] {
            let request = format!(
                "GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: {token}\r\n\r\n"
            );
            let resp = admin_response(&admin, &request).await;
            assert_eq!(404, resp.status.as_u16(), "{path}");
        }
    }

    #[test]
    fn test_admin_auth_construction_fails_closed() {
        let build = |conf: &str| {
            AdminServe::new(
                &toml::from_str::<PluginConf>(conf).unwrap(),
                new_config_manager(),
            )
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
        let admin = AdminServe::new(
            &toml::from_str::<PluginConf>(
                r#"
category = "admin"
allow_unauthenticated = true
"#,
            )
            .unwrap(),
            new_config_manager(),
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

    /// The constructor takes its manager instead of reading the process-global
    /// slot, so each plugin serves the document of the instance it was given.
    #[tokio::test]
    async fn test_config_reads_use_the_injected_manager() {
        let admin = |log_level: &str| {
            AdminServe::new(
                &toml::from_str::<PluginConf>(
                    r#"
category = "admin"
allow_unauthenticated = true
"#,
                )
                .unwrap(),
                Arc::new(pingap_config::new_memory_config_manager(
                    &format!("[basic]\nlog_level = \"{log_level}\"\n"),
                    None,
                )),
            )
            .unwrap()
        };
        let request = "GET /configs/full HTTP/1.1\r\nHost: localhost\r\n\r\n";

        for log_level in ["warn", "error"] {
            let resp = admin_response(&admin(log_level), request).await;
            assert_eq!(200, resp.status.as_u16(), "{log_level}");
            let body = String::from_utf8_lossy(&resp.body);
            assert!(
                body.contains(&format!("log_level = \\\"{log_level}\\\"")),
                "the injected manager's document must be served: {body}"
            );
        }
    }

    /// A freshly signed token is accepted; ageing it past `max_age`, or
    /// signing it for the wrong password, is not.
    #[test]
    fn test_auth_validate_accepts_a_fresh_token() {
        // spellchecker:off
        let admin = AdminServe::new(
            &toml::from_str::<PluginConf>(
                r#"
    category = "admin"
    path = "/"
    authorizations = ["YWRtaW46MTIzMTIz"]
    "#,
            )
            .unwrap(),
            new_config_manager(),
        )
        .unwrap();
        // spellchecker:on
        let request = |authorization: &str| {
            let mut req = pingora::http::RequestHeader::build(
                Method::GET,
                b"/configs/full",
                None,
            )
            .unwrap();
            req.insert_header("authorization", authorization).unwrap();
            req
        };

        let now = pingap_core::now_sec();
        assert!(
            admin.auth_validate(&request(&auth_header_at(
                "admin", "123123", now
            ))),
            "a fresh token must authenticate"
        );

        // The hash is valid for the stale timestamp, so the only reason to
        // refuse it is the two-day window.
        let stale = now - 3 * 24 * 3600;
        assert!(
            !admin.auth_validate(&request(&auth_header_at(
                "admin", "123123", stale
            ))),
            "a token older than max_age must be refused"
        );

        assert!(
            !admin.auth_validate(&request(&auth_header_at(
                "admin", "wrong", now
            ))),
            "a token signed for the wrong password must be refused"
        );
    }

    #[tokio::test]
    async fn test_update_config_writes_a_valid_entry() {
        let (admin, manager) =
            admin_with_config("[basic]\nname = \"before\"\n");

        let resp = admin_json_response(
            &admin,
            "POST",
            "/configs/upstream/backend",
            r#"{"addrs":["127.0.0.1:8080"]}"#,
        )
        .await;
        assert_eq!(204, resp.status.as_u16());

        let config = manager.load_all().await.unwrap();
        let upstreams = config.upstreams.expect("the upstream section");
        let entry = upstreams
            .get("backend")
            .expect("the update must be persisted");
        assert_eq!(
            Some(&toml::Value::Array(vec![toml::Value::String(
                "127.0.0.1:8080".to_string()
            )])),
            entry.get("addrs")
        );
        // A single entry write is not a whole-document replace: the rest of
        // the document survives.
        assert_eq!(
            Some(&toml::Value::String("before".to_string())),
            config.basic.as_ref().and_then(|basic| basic.get("name"))
        );
    }

    #[tokio::test]
    async fn test_update_config_rejects_an_invalid_entry() {
        let (admin, manager) = admin_with_config(
            "[basic]\nname = \"before\"\n\
             [upstreams.keep]\naddrs = [\"127.0.0.1:8080\"]\n",
        );

        let resp = admin_json_response(
            &admin,
            "POST",
            "/configs/upstream/bad",
            r#"{"addrs":[]}"#,
        )
        .await;
        // `handle_configs` reports handler failures as 500 today; what matters
        // here is that the invalid entry is refused instead of persisted.
        assert_eq!(500, resp.status.as_u16());
        let body = String::from_utf8_lossy(&resp.body);
        assert!(body.contains("upstream addrs is empty"), "body: {body}");

        let config = manager.load_all().await.unwrap();
        let upstreams = config.upstreams.expect("the upstream section");
        assert!(
            !upstreams.contains_key("bad"),
            "an invalid entry must not be stored"
        );
        assert!(
            upstreams.contains_key("keep"),
            "the rejected write must not drop other entries"
        );
    }

    #[tokio::test]
    async fn test_remove_config_deletes_an_existing_entry() {
        let (admin, manager) = admin_with_config(
            "[upstreams.backend]\naddrs = [\"127.0.0.1:8080\"]\n",
        );

        let resp = admin_json_response(
            &admin,
            "DELETE",
            "/configs/upstream/backend",
            "",
        )
        .await;
        assert_eq!(204, resp.status.as_u16());

        let config = manager.load_all().await.unwrap();
        assert!(
            config
                .upstreams
                .is_none_or(|upstreams| !upstreams.contains_key("backend")),
            "the deleted entry must be gone"
        );
    }

    /// In the single-document mode the admin writes through, deleting an
    /// absent name is a no-op rather than an error: the handler answers 204
    /// and every other entry survives.
    #[tokio::test]
    async fn test_removing_a_missing_entry_leaves_the_document_intact() {
        let (admin, manager) = admin_with_config(
            "[basic]\nname = \"before\"\n\
             [upstreams.backend]\naddrs = [\"127.0.0.1:8080\"]\n",
        );

        let resp = admin_json_response(
            &admin,
            "DELETE",
            "/configs/upstream/missing",
            "",
        )
        .await;
        assert_eq!(204, resp.status.as_u16());

        let config = manager.load_all().await.unwrap();
        let upstreams = config.upstreams.expect("the upstream section");
        assert!(
            upstreams.contains_key("backend"),
            "deleting a missing name must not touch the others"
        );
        assert!(!upstreams.contains_key("missing"));
    }

    #[tokio::test]
    async fn test_import_config_replaces_the_whole_document() {
        let (admin, manager) =
            admin_with_config("[basic]\nname = \"before\"\n");

        let resp = admin_json_response(
            &admin,
            "POST",
            "/configs/import",
            "[upstreams.imported]\naddrs = [\"127.0.0.1:9090\"]\n",
        )
        .await;
        assert_eq!(204, resp.status.as_u16());

        let config = manager.load_all().await.unwrap();
        assert!(
            config.basic.is_none(),
            "a whole import replaces the basic section too"
        );
        let upstreams = config.upstreams.expect("the imported section");
        assert!(upstreams.contains_key("imported"));
    }

    #[tokio::test]
    async fn test_import_config_rejects_invalid_documents() {
        let (admin, manager) =
            admin_with_config("[basic]\nname = \"before\"\n");
        let before = manager.load_all_raw().await.unwrap();

        for body in [
            // Not TOML at all.
            "this is not toml = [",
            // Valid TOML that fails startup validation (an upstream without
            // addresses could never serve traffic).
            "[upstreams.bad]\naddrs = []\n",
        ] {
            let resp =
                admin_json_response(&admin, "POST", "/configs/import", body)
                    .await;
            assert_eq!(500, resp.status.as_u16(), "body: {body}");
            assert_eq!(
                before,
                manager.load_all_raw().await.unwrap(),
                "a rejected import must not replace the stored document: {body}"
            );
        }
    }
}
