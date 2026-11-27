//! End-to-end request lifecycle tests for `pingap-proxy`.
//!
//! These tests exercise the path the unit tests in `src/server.rs` cannot:
//! a raw TCP client talks to a real pingora listener, pingora runs the whole
//! `ProxyHttp` lifecycle (`early_request_filter` -> `request_filter` ->
//! `handle_standard_request` -> `proxy_upstream_filter` -> `upstream_peer` ->
//! upstream exchange -> response), and the request is answered by a real
//! origin TCP server. No upstream response is faked.
//!
//! The pingora listener is assembled from the same pieces `Server::run`
//! uses: the public `Server`, `HttpProxy`, and `Service::handle_event` accept
//! path, with a plain `tokio::net::TcpListener` bound to `127.0.0.1:0` so the
//! kernel picks the port. Starting the full `pingora::server::Server` is
//! deliberately avoided: it owns process-wide runtime, daemon, and
//! hot-upgrade machinery that a unit test must not touch. That means the
//! `Server::run` listener configuration itself (TLS setup, h2c/h2 options,
//! configured socket options) is not covered here; it has separate unit
//! coverage in `src/server_conf.rs`/`src/server.rs`.

use ahash::AHashMap;
use pingap_certificate::{
    CertificateProvider, DynamicCertificates, TlsCertificate,
};
use pingap_config::{LocationConf, UpstreamConf, new_memory_config_manager};
use pingap_core::{Plugin, PluginProvider};
use pingap_location::{
    Location, LocationProvider, LocationStats, ServerLocationRoute,
};
use pingap_proxy::{AppContext, Server, ServerLocationsProvider};
use pingap_upstream::{Upstream, UpstreamProvider};
use pingora::apps::HttpServerOptions;
use pingora::protocols::l4::stream::Stream;
use pingora::proxy::HttpProxy;
use pingora::server::ShutdownWatch;
use pingora::services::listening::Service;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

const SERVER_NAME: &str = "lifecycle";
const REQUEST_HOST: &str = "lifecycle.test";
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// One request as the origin saw it on the wire.
#[derive(Debug, Clone)]
struct OriginRequest {
    method: String,
    target: String,
    host: Option<String>,
}

/// A real HTTP/1.1 origin server bound to an ephemeral port.
///
/// It accepts connections until dropped, logs each request, and answers with
/// a deterministic body plus an `x-origin-count` header. Dropping the handle
/// aborts the accept loop so a test never leaks a listener.
struct Origin {
    addr: SocketAddr,
    counter: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<OriginRequest>>>,
    task: JoinHandle<()>,
}

impl Origin {
    async fn spawn(name: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("origin listener should bind an ephemeral port");
        let addr = listener
            .local_addr()
            .expect("origin listener should have a local address");
        let counter = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let task = tokio::spawn({
            let counter = counter.clone();
            let requests = requests.clone();
            async move {
                loop {
                    let Ok((mut socket, _)) = listener.accept().await else {
                        break;
                    };
                    let counter = counter.clone();
                    let requests = requests.clone();
                    tokio::spawn(async move {
                        let Ok(raw) = read_request_head(&mut socket).await
                        else {
                            return;
                        };
                        let request = parse_origin_request(&raw);
                        let count = counter.fetch_add(1, Ordering::SeqCst) + 1;
                        requests
                            .lock()
                            .expect("origin request log should not be poisoned")
                            .push(request);
                        let body = format!("response from {name}");
                        let response = format!(
                            "HTTP/1.1 200 OK\r\n\
                             Content-Type: text/plain\r\n\
                             Content-Length: {}\r\n\
                             x-origin-name: {name}\r\n\
                             x-origin-count: {count}\r\n\
                             Connection: close\r\n\
                             \r\n\
                             {body}",
                            body.len()
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                        let _ = socket.shutdown().await;
                    });
                }
            }
        });
        Self {
            addr,
            counter,
            requests,
            task,
        }
    }

    fn requests(&self) -> Vec<OriginRequest> {
        self.requests
            .lock()
            .expect("origin request log should not be poisoned")
            .clone()
    }

    fn request_count(&self) -> usize {
        self.counter.load(Ordering::SeqCst)
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The proxy listener plus everything needed to keep it alive.
struct ProxyFixture {
    addr: SocketAddr,
    task: JoinHandle<()>,
    shutdown: watch::Sender<bool>,
}

impl Drop for ProxyFixture {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        self.task.abort();
    }
}

struct NoPlugins;

impl PluginProvider for NoPlugins {
    fn get(&self, _name: &str) -> Option<Arc<dyn Plugin>> {
        None
    }
}

struct NoCertificates;

impl CertificateProvider for NoCertificates {
    fn get(&self, _sni: &str) -> Option<Arc<TlsCertificate>> {
        None
    }

    fn list(&self) -> Arc<DynamicCertificates> {
        Arc::new(AHashMap::new())
    }

    fn store(&self, _data: DynamicCertificates) {}
}

struct StaticLocations {
    locations: AHashMap<String, Arc<Location>>,
}

impl LocationProvider for StaticLocations {
    fn get(&self, name: &str) -> Option<Arc<Location>> {
        self.locations.get(name).cloned()
    }

    fn stats(&self) -> HashMap<String, LocationStats> {
        HashMap::new()
    }
}

struct StaticUpstreams {
    upstreams: AHashMap<String, Arc<Upstream>>,
}

impl UpstreamProvider for StaticUpstreams {
    fn get(&self, name: &str) -> Option<Arc<Upstream>> {
        self.upstreams.get(name).cloned()
    }

    fn list(&self) -> Vec<(String, Arc<Upstream>)> {
        self.upstreams
            .iter()
            .map(|(name, upstream)| (name.clone(), upstream.clone()))
            .collect()
    }
}

struct StaticServerLocations {
    server: String,
    route: Arc<ServerLocationRoute>,
}

impl ServerLocationsProvider for StaticServerLocations {
    fn get(&self, name: &str) -> Option<Arc<ServerLocationRoute>> {
        (name == self.server).then(|| self.route.clone())
    }
}

/// Builds the smallest real `Server` and serves it through pingora's public
/// `HttpProxy`/`Service::handle_event` path over an ephemeral TCP port.
async fn spawn_proxy(
    upstream_confs: AHashMap<String, UpstreamConf>,
    location_confs: AHashMap<String, LocationConf>,
) -> ProxyFixture {
    let upstreams = upstream_confs
        .iter()
        .map(|(name, conf)| {
            let upstream = Upstream::new(name, conf, None)
                .expect("test upstream should build");
            (name.clone(), Arc::new(upstream))
        })
        .collect::<AHashMap<_, _>>();
    let upstream_provider = Arc::new(StaticUpstreams { upstreams });

    let locations = location_confs
        .iter()
        .map(|(name, conf)| {
            let location =
                Location::new(name, conf).expect("test location should build");
            (name.clone(), Arc::new(location))
        })
        .collect::<AHashMap<_, _>>();
    let location_provider = Arc::new(StaticLocations { locations });

    let ordered = location_confs.keys().cloned().collect::<Vec<_>>();
    let route = ServerLocationRoute::build(ordered, {
        let location_provider = location_provider.clone();
        move |name| location_provider.get(name)
    });
    let server_locations_provider = Arc::new(StaticServerLocations {
        server: SERVER_NAME.to_string(),
        route: Arc::new(route),
    });

    let server_conf = pingap_proxy::ServerConf {
        name: SERVER_NAME.to_string(),
        ..Default::default()
    };
    let server = Server::new(
        &server_conf,
        AppContext {
            logger: None,
            config_manager: Arc::new(new_memory_config_manager("", None)),
            server_locations_provider,
            location_provider,
            upstream_provider,
            plugin_provider: Arc::new(NoPlugins),
            certificate_provider: Arc::new(NoCertificates),
        },
    )
    .expect("test proxy server should build");

    // Same construction as `Server::run`: `HttpProxy` + module setup. The
    // configured h2c flag is false here, matching a plain HTTP listener.
    let mut proxy = HttpProxy::new(
        server,
        Arc::new(pingora::server::configuration::ServerConf::default()),
    );
    proxy.handle_init_modules();
    let mut options = HttpServerOptions::default();
    options.h2c = false;
    proxy.server_options = Some(options);
    let proxy = Arc::new(proxy);

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("proxy listener should bind an ephemeral port");
    let addr = listener
        .local_addr()
        .expect("proxy listener should have a local address");
    let (shutdown, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            let proxy = proxy.clone();
            let shutdown: ShutdownWatch = shutdown_rx.clone();
            tokio::spawn(async move {
                Service::<HttpProxy<Server>>::handle_event(
                    Box::new(Stream::from(socket)),
                    proxy,
                    shutdown,
                )
                .await;
            });
        }
    });

    ProxyFixture {
        addr,
        task,
        shutdown,
    }
}

/// Sends one raw HTTP/1.1 request and parses the response.
async fn send_request(
    addr: SocketAddr,
    request: &str,
) -> (u16, HashMap<String, String>, String) {
    let exchange = async {
        let mut stream = TcpStream::connect(addr)
            .await
            .expect("client should connect to the proxy");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("client should write the request");
        stream
            .flush()
            .await
            .expect("client should flush the request");
        read_response(&mut stream).await
    };
    tokio::time::timeout(IO_TIMEOUT, exchange)
        .await
        .expect("proxy exchange should finish before the timeout")
}

async fn read_response(
    stream: &mut TcpStream,
) -> (u16, HashMap<String, String>, String) {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(end) = find_header_end(&raw) {
            break end;
        }
        let read = stream
            .read(&mut chunk)
            .await
            .expect("client should read the response header");
        assert!(read > 0, "connection closed before the response header");
        raw.extend_from_slice(&chunk[..read]);
    };

    let head = std::str::from_utf8(&raw[..header_end])
        .expect("response header should be valid UTF-8");
    let mut lines = head.split("\r\n");
    let status_line = lines.next().expect("response should have a status line");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .expect("status line should carry a status code")
        .parse::<u16>()
        .expect("status code should be numeric");
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(
                name.trim().to_ascii_lowercase(),
                value.trim().to_string(),
            );
        }
    }

    let mut body = raw[header_end..].to_vec();
    let content_length = headers
        .get("content-length")
        .expect("origin response should carry content-length")
        .parse::<usize>()
        .expect("content-length should be numeric");
    while body.len() < content_length {
        let read = stream
            .read(&mut chunk)
            .await
            .expect("client should read the response body");
        assert!(read > 0, "connection closed before the response body");
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);

    (
        status,
        headers,
        String::from_utf8(body).expect("response body should be valid UTF-8"),
    )
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|i| i + 4)
}

/// Reads the request line and headers; the tests only send bodyless GETs.
async fn read_request_head(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if find_header_end(&raw).is_some() {
            break;
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..read]);
        if raw.len() > 64 * 1024 {
            return Err(std::io::Error::other("request head too large"));
        }
    }
    Ok(String::from_utf8_lossy(&raw).into_owned())
}

fn parse_origin_request(raw: &str) -> OriginRequest {
    let mut lines = raw.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();
    let mut host = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("host")
        {
            host = Some(value.trim().to_string());
        }
    }
    OriginRequest {
        method,
        target,
        host,
    }
}

fn http_get(path: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {REQUEST_HOST}\r\nConnection: close\r\n\r\n"
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxies_request_to_real_origin_and_preserves_response_headers() {
    // Arrange: one origin, one location matched by host + path, one upstream.
    let origin = Origin::spawn("origin").await;
    let mut upstreams = AHashMap::new();
    upstreams.insert(
        "origin".to_string(),
        UpstreamConf {
            addrs: vec![origin.addr.to_string()],
            ..Default::default()
        },
    );
    let mut locations = AHashMap::new();
    locations.insert(
        "api".to_string(),
        LocationConf {
            upstream: Some("origin".to_string()),
            path: Some("/hello".to_string()),
            host: Some(REQUEST_HOST.to_string()),
            ..Default::default()
        },
    );
    let proxy = spawn_proxy(upstreams, locations).await;

    // Act: one real TCP request through the proxy listener.
    let (status, headers, body) =
        send_request(proxy.addr, &http_get("/hello")).await;

    // Assert: the client sees the origin's status, body and header.
    assert_eq!(200, status);
    assert_eq!("response from origin", body);
    assert_eq!(
        Some("origin"),
        headers.get("x-origin-name").map(String::as_str)
    );
    assert_eq!(Some("1"), headers.get("x-origin-count").map(String::as_str));

    // Assert: exactly one request reached the origin with the expected
    // method, path and forwarded Host.
    assert_eq!(1, origin.request_count());
    let requests = origin.requests();
    assert_eq!(1, requests.len());
    assert_eq!("GET", requests[0].method);
    assert_eq!("/hello", requests[0].target);
    assert_eq!(Some(REQUEST_HOST), requests[0].host.as_deref());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resolves_dollar_variable_upstream_override_from_path_capture() {
    // Arrange: two upstreams and a location whose upstream is `$target`.
    // The named regex capture `target` supplies the real upstream name, so
    // `upstream_peer` has to resolve the variable instead of using a static
    // upstream.
    let origin_a = Origin::spawn("origin-a").await;
    let origin_b = Origin::spawn("origin-b").await;
    let mut upstreams = AHashMap::new();
    for (name, origin) in [("origin-a", &origin_a), ("origin-b", &origin_b)] {
        upstreams.insert(
            name.to_string(),
            UpstreamConf {
                addrs: vec![origin.addr.to_string()],
                ..Default::default()
            },
        );
    }
    let mut locations = AHashMap::new();
    locations.insert(
        "by-variable".to_string(),
        LocationConf {
            upstream: Some("$target".to_string()),
            path: Some(r"~^/(?P<target>[a-z-]+)/".to_string()),
            host: Some(REQUEST_HOST.to_string()),
            ..Default::default()
        },
    );
    let proxy = spawn_proxy(upstreams, locations).await;

    // Act: the path names origin-b, so the variable must select it.
    let (status, headers, body) =
        send_request(proxy.addr, &http_get("/origin-b/hello")).await;

    // Assert: the request was answered by the captured upstream only.
    assert_eq!(200, status);
    assert_eq!("response from origin-b", body);
    assert_eq!(
        Some("origin-b"),
        headers.get("x-origin-name").map(String::as_str)
    );
    assert_eq!(0, origin_a.request_count());
    assert_eq!(1, origin_b.request_count());
    let requests = origin_b.requests();
    assert_eq!(1, requests.len());
    assert_eq!("/origin-b/hello", requests[0].target);
    assert_eq!(Some(REQUEST_HOST), requests[0].host.as_deref());
}
