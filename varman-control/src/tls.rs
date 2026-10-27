//! HTTPS termination for the control plane's HTTP listener.
//!
//! The dashboard has to be reachable over a secure origin — browsers only
//! expose WebAuthn (passkeys) and the other crypto APIs to HTTPS or localhost
//! — so the control plane can terminate TLS itself. The certificate lives in
//! the database and can be replaced from the dashboard; a
//! [`ReloadableResolver`] lets the running listener pick up a replacement
//! without a restart.
//!
//! The listener is *mixed*: it also accepts cleartext on the same port so
//! health probes and an operator typing `http://host:9080` get a real HTTP
//! answer instead of a connection reset. [`ConnInfo`] tells the request
//! middleware which half a connection arrived on, which is what drives the
//! redirect to HTTPS in [`crate::api`].
//!
//! Protocol detection and the TLS handshake run in bounded per-connection
//! tasks, never inline in `accept()`. An idle TCP client must not be able to
//! head-of-line block the console or its health probe.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::extract::connect_info::Connected;
use axum::serve::{IncomingStream, Listener};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio::time::timeout;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use crate::pki::mtls::MtlsError;
use crate::pki::tls::{certified_key, crypto_provider};

/// First byte of a TLS record carrying a handshake (the ClientHello).
const TLS_HANDSHAKE_RECORD: u8 = 0x16;

/// A client must send its first byte this quickly. This is also the
/// slowloris guard: an idle TCP connection must never occupy the listener.
const PROTOCOL_PEEK_TIMEOUT: Duration = Duration::from_secs(5);

/// Bounds a TLS handshake. A client that cannot finish in this window is
/// dropped instead of holding a classification worker forever.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum number of connections being classified or handshaking at once.
/// The accept loop keeps running while these tasks are in flight.
const MAX_CONCURRENT_HANDSHAKES: usize = 64;

/// Holds the certificate the listener presents, swappable at runtime.
///
/// rustls asks the resolver for a certificate on every handshake, so
/// installing a new pair takes effect immediately; connections already
/// established keep the certificate they negotiated.
#[derive(Debug, Default)]
pub struct ReloadableResolver {
    current: RwLock<Option<Arc<CertifiedKey>>>,
}

impl ReloadableResolver {
    /// Installs a certificate, replacing any previous one.
    pub fn install(&self, key: Arc<CertifiedKey>) {
        match self.current.write() {
            Ok(mut current) => *current = Some(key),
            Err(poisoned) => *poisoned.into_inner() = Some(key),
        }
    }

    /// The certificate currently served, if one has been installed.
    pub fn loaded(&self) -> Option<Arc<CertifiedKey>> {
        match self.current.read() {
            Ok(current) => current.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

impl ResolvesServerCert for ReloadableResolver {
    fn resolve(
        &self,
        _client_hello: ClientHello<'_>,
    ) -> Option<Arc<CertifiedKey>> {
        // One certificate for every name: the dashboard is a single-origin
        // service and the operator decides which names it answers on.
        self.loaded()
    }
}

/// The TLS state shared by the HTTP listener and the API that manages it.
pub struct ControlPlaneTls {
    /// `--tls-enabled`: whether this process terminates TLS at all.
    enabled: bool,
    resolver: Arc<ReloadableResolver>,
    acceptor: TlsAcceptor,
}

impl std::fmt::Debug for ControlPlaneTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlPlaneTls")
            .field("enabled", &self.enabled)
            .field("has_certificate", &self.has_certificate())
            .finish_non_exhaustive()
    }
}

impl ControlPlaneTls {
    /// Creates the TLS state. No certificate is required yet: a deployment
    /// that terminates TLS elsewhere never installs one.
    pub fn new(enabled: bool) -> Self {
        let resolver = Arc::new(ReloadableResolver::default());
        let config = rustls::ServerConfig::builder_with_provider(
            crypto_provider().clone(),
        )
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports the default protocol versions")
        .with_no_client_auth()
        .with_cert_resolver(resolver.clone());

        Self {
            enabled,
            resolver,
            acceptor: TlsAcceptor::from(Arc::new(config)),
        }
    }

    /// Whether the HTTP listener terminates TLS.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Whether a certificate has been installed.
    pub fn has_certificate(&self) -> bool {
        self.resolver.loaded().is_some()
    }

    /// Validates and installs a certificate pair, replacing the current one.
    pub fn activate(
        &self,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<(), MtlsError> {
        let key = certified_key(cert_pem, key_pem)?;
        self.resolver.install(key);
        Ok(())
    }

    /// A handle for the listener to accept connections with.
    pub fn acceptor(&self) -> TlsAcceptor {
        self.acceptor.clone()
    }
}

/// A connection accepted by [`MixedListener`], TLS or cleartext.
pub enum MaybeTlsStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for MaybeTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Accepts TLS and cleartext HTTP on a single port.
///
/// The first byte decides: a TLS record starts with `0x16` (handshake), and
/// no HTTP request line does — methods are ASCII letters — so the split is
/// unambiguous for anything a browser, curl or a container probe sends.
pub struct MixedListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    /// Fully classified connections, handed to axum by [`accept`].
    ready: mpsc::Receiver<(MaybeTlsStream, SocketAddr)>,
    /// Clone held by the listener so classification tasks can enqueue.
    ready_tx: mpsc::Sender<(MaybeTlsStream, SocketAddr)>,
    /// Bounds concurrent idle/TLS handshakes. Without this, a burst of slow
    /// clients could exhaust memory even though the accept loop stays live.
    slots: Arc<Semaphore>,
}

impl MixedListener {
    pub fn new(listener: TcpListener, acceptor: TlsAcceptor) -> Self {
        let (ready_tx, ready) = mpsc::channel(MAX_CONCURRENT_HANDSHAKES);
        Self {
            listener,
            acceptor,
            ready,
            ready_tx,
            slots: Arc::new(Semaphore::new(MAX_CONCURRENT_HANDSHAKES)),
        }
    }
}

impl Listener for MixedListener {
    type Io = MaybeTlsStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        // Classify connections concurrently. The previous implementation
        // awaited `peek` and the TLS handshake inline, so one client that
        // connected and sent nothing froze the whole admin listener — a
        // single idle TCP connection could take the dashboard down.
        let Self {
            listener,
            acceptor,
            ready,
            ready_tx,
            slots,
        } = self;
        loop {
            tokio::select! {
                biased;
                Some(classified) = ready.recv() => return classified,
                accepted = TcpListener::accept(listener) => {
                    let (stream, addr) = match accepted {
                        Ok(accepted) => accepted,
                        Err(err) => {
                            tracing::error!(error = %err, "control-plane accept failed");
                            // Mirroring axum: an accept error is usually a
                            // transient resource shortage (e.g. EMFILE), so
                            // pause instead of spinning.
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            continue;
                        },
                    };

                    // Loopback is reserved for the container health probe and
                    // an SSH tunnel. It must survive an external slow-client
                    // flood; external connections are bounded by `slots`.
                    let permit = if addr.ip().is_loopback() {
                        None
                    } else {
                        match slots.clone().try_acquire_owned() {
                            Ok(permit) => Some(permit),
                            Err(_) => {
                                tracing::debug!(
                                    %addr,
                                    "control-plane connection dropped: too many \
                                     pending handshakes"
                                );
                                drop(stream);
                                continue;
                            },
                        }
                    };

                    let acceptor = acceptor.clone();
                    let sender = ready_tx.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        let _ = stream.set_nodelay(true);
                        match classify(stream, acceptor).await {
                            Ok(io) => {
                                if sender.send((io, addr)).await.is_err() {
                                    tracing::debug!(
                                        %addr,
                                        "control-plane listener closed while \
                                         classifying a connection"
                                    );
                                }
                            },
                            Err(err) => tracing::debug!(
                                %addr,
                                error = %err,
                                "control-plane connection setup failed"
                            ),
                        }
                    });
                },
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

/// Classifies and, for TLS clients, completes the handshake before handing
/// the connection to axum. Both waits are bounded so a silent client cannot
/// hold a worker indefinitely.
async fn classify(
    stream: TcpStream,
    acceptor: TlsAcceptor,
) -> io::Result<MaybeTlsStream> {
    let is_tls = timeout(PROTOCOL_PEEK_TIMEOUT, looks_like_tls(&stream))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out waiting for the first byte",
            )
        })??;

    if !is_tls {
        return Ok(MaybeTlsStream::Plain(stream));
    }

    let tls = timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream))
        .await
        .map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out")
        })??;
    Ok(MaybeTlsStream::Tls(Box::new(tls)))
}

/// Peeks the first byte to tell a TLS handshake from a cleartext request.
///
/// `peek` does not consume the byte, so the protocol handler still sees it.
async fn looks_like_tls(stream: &TcpStream) -> io::Result<bool> {
    let mut first = [0u8; 1];
    match stream.peek(&mut first).await? {
        // The peer hung up before saying anything; hand it to the HTTP side,
        // which reports the empty request the same way it always has.
        0 => Ok(false),
        _ => Ok(first[0] == TLS_HANDSHAKE_RECORD),
    }
}

/// Per-connection facts the request middleware reads through `ConnectInfo`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnInfo {
    /// Whether the connection arrived through the TLS half of the listener.
    pub tls: bool,
    /// The TCP peer address, used by the self-protection IP allowlist and the
    /// access log. Forwarding headers are deliberately ignored: only the
    /// socket address cannot be spoofed by the caller.
    pub peer_addr: SocketAddr,
}

impl Connected<IncomingStream<'_, MixedListener>> for ConnInfo {
    fn connect_info(stream: IncomingStream<'_, MixedListener>) -> Self {
        Self {
            tls: matches!(stream.io(), MaybeTlsStream::Tls(_)),
            peer_addr: *stream.remote_addr(),
        }
    }
}

impl Connected<IncomingStream<'_, TcpListener>> for ConnInfo {
    fn connect_info(stream: IncomingStream<'_, TcpListener>) -> Self {
        // A plain `TcpListener` only ever serves cleartext.
        Self {
            tls: false,
            peer_addr: *stream.remote_addr(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::tls::{generate_self_signed, parse_chain};
    use rustls::pki_types::ServerName;
    use rustls::RootCertStore;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::TlsConnector;

    fn test_certificate() -> (String, String) {
        let material =
            generate_self_signed("VarmanWAF", &["localhost".to_string()], 30)
                .unwrap();
        (material.cert_pem, material.key_pem.unwrap())
    }

    #[test]
    fn activate_installs_the_certificate_and_rejects_a_bad_pair() {
        let tls = ControlPlaneTls::new(true);
        assert!(!tls.has_certificate());
        assert!(tls.is_enabled());

        let (cert_pem, key_pem) = test_certificate();
        tls.activate(&cert_pem, &key_pem).unwrap();
        assert!(tls.has_certificate());

        // An unrelated key must not replace a working certificate.
        let other =
            generate_self_signed("Other", &["localhost".to_string()], 30)
                .unwrap();
        assert!(tls
            .activate(&cert_pem, other.key_pem.as_deref().unwrap())
            .is_err());
        assert!(tls.has_certificate());
    }

    #[test]
    fn resolver_serves_the_installed_key_and_nothing_before() {
        let resolver = ReloadableResolver::default();
        assert!(resolver.loaded().is_none());

        let (cert_pem, key_pem) = test_certificate();
        resolver.install(certified_key(&cert_pem, &key_pem).unwrap());
        let loaded = resolver.loaded().unwrap();
        assert_eq!(loaded.cert.len(), 1);
    }

    /// Drives a real TCP connection through both halves of the listener: a
    /// cleartext client and a TLS client trusting the generated certificate.
    #[tokio::test]
    async fn mixed_listener_dispatches_both_protocols() {
        let (cert_pem, key_pem) = test_certificate();
        let tls = ControlPlaneTls::new(true);
        tls.activate(&cert_pem, &key_pem).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut listener = MixedListener::new(listener, tls.acceptor());
        assert_eq!(listener.local_addr().unwrap(), addr);

        let server = tokio::spawn(async move {
            let mut replies = Vec::new();
            for _ in 0..2 {
                let (mut io, _) = listener.accept().await;
                let tls = matches!(io, MaybeTlsStream::Tls(_));
                let mut ping = [0u8; 4];
                io.read_exact(&mut ping).await.unwrap();
                assert_eq!(&ping, b"PING");
                io.write_all(if tls { b"TLS" } else { b"PLAIN" })
                    .await
                    .unwrap();
                io.flush().await.unwrap();
                replies.push(tls);
            }
            replies
        });

        // Cleartext: the first byte is 'P', not a TLS record.
        let mut plain = TcpStream::connect(addr).await.unwrap();
        plain.write_all(b"PING").await.unwrap();
        let mut reply = [0u8; 5];
        plain.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"PLAIN");

        // TLS: the client verifies the self-signed certificate by name.
        let mut roots = RootCertStore::empty();
        roots
            .add(parse_chain(&cert_pem).unwrap().remove(0))
            .unwrap();
        let client_config = rustls::ClientConfig::builder_with_provider(
            crypto_provider().clone(),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let name = ServerName::try_from("localhost").unwrap();
        let mut secure = connector
            .connect(name, TcpStream::connect(addr).await.unwrap())
            .await
            .unwrap();
        secure.write_all(b"PING").await.unwrap();
        let mut reply = [0u8; 3];
        secure.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"TLS");

        let mut handshakes: Vec<bool> = server.await.unwrap();
        handshakes.sort_unstable();
        assert_eq!(handshakes, vec![false, true]);
    }

    /// Regression: a client that connects and sends nothing must not head-of-
    /// line block a valid health probe or dashboard request. Previously the
    /// listener awaited `peek` inline, so one idle TCP connection froze 9080
    /// until the process was restarted.
    #[tokio::test]
    async fn idle_connection_does_not_block_a_valid_client() {
        let (cert_pem, key_pem) = test_certificate();
        let tls = ControlPlaneTls::new(true);
        tls.activate(&cert_pem, &key_pem).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut listener = MixedListener::new(listener, tls.acceptor());

        let server = tokio::spawn(async move {
            let (mut io, _) = listener.accept().await;
            let mut ping = [0u8; 4];
            io.read_exact(&mut ping).await.unwrap();
            assert_eq!(&ping, b"PING");
            io.write_all(b"PLAIN").await.unwrap();
            io.flush().await.unwrap();
        });

        // Hold a connection open without sending a single byte.
        let idle = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // A normal cleartext client must still be accepted and answered.
        let mut plain = TcpStream::connect(addr).await.unwrap();
        plain.write_all(b"PING").await.unwrap();
        let mut reply = [0u8; 5];
        timeout(Duration::from_secs(2), plain.read_exact(&mut reply))
            .await
            .expect("an idle connection blocked a valid client")
            .unwrap();
        assert_eq!(&reply, b"PLAIN");

        drop(idle);
        server.await.unwrap();
    }
}
