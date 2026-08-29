mod ca;
mod service;
mod tls;
mod upstream;

use std::net::SocketAddr;
use std::sync::Arc;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::LazyConfigAcceptor;

use crate::http::HttpRule;
use self::service::AclService;
use self::tls::CertSigner;
use self::upstream::Forwarder;

pub(crate) use self::ca::resolve_ca;
pub(crate) use self::service::OrigDestMap;

/// Handle returned by [`spawn_transparent_proxy`]. Dropping it shuts the proxy down.
pub(crate) struct HttpAclProxyHandle {
    pub(crate) addr: SocketAddr,
    pub(crate) orig_dest: OrigDestMap,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl Drop for HttpAclProxyHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// A TLS record/handshake always begins with content-type 0x16 (handshake).
/// A plaintext HTTP request never does (it starts with an ASCII method letter).
fn is_tls_client_hello(first_byte: u8) -> bool {
    first_byte == 0x16
}

/// Spawn the transparent HTTP/HTTPS ACL proxy. When `ca_cert_pem`/`ca_key_pem`
/// are provided, TLS connections are MITM-terminated with a per-SNI leaf cert
/// minted from that CA; otherwise TLS connections are closed (443 is only
/// redirected here when a CA is configured) and plaintext HTTP is served.
pub(crate) async fn spawn_transparent_proxy(
    allow: Vec<HttpRule>,
    deny: Vec<HttpRule>,
    inject: Arc<Vec<crate::credential::InjectRule>>,
    ca_cert_pem: Option<&str>,
    ca_key_pem: Option<&str>,
    log_fn: Option<Arc<dyn Fn(&str, &str, &str) + Send + Sync>>,
    bind_ip: std::net::IpAddr,
    host_mask: Option<&str>,
) -> std::io::Result<HttpAclProxyHandle> {
    // rustls 0.22 builder() uses the ring provider directly; no provider install needed.
    let orig_dest: OrigDestMap =
        Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
    let forwarder = Forwarder::new()?;
    let svc = AclService::new(
        allow,
        deny,
        inject,
        Arc::clone(&orig_dest),
        forwarder,
        log_fn,
        host_mask.map(str::to_string),
    );

    let signer = match (ca_cert_pem, ca_key_pem) {
        (Some(c), Some(k)) => Some(Arc::new(CertSigner::new(c, k)?)),
        _ => None,
    };

    // In per-sandbox netns mode the proxy must bind the veth gateway address
    // (the sandbox's on-behalf connections route inside the sandbox netns and
    // can only reach the worker through the veth); otherwise host loopback.
    let listener = TcpListener::bind(std::net::SocketAddr::new(bind_ip, 0)).await?;
    let addr = listener.local_addr()?;
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            let accept = tokio::select! {
                _ = &mut shutdown_rx => break,
                r = listener.accept() => r,
            };
            let (stream, peer) = match accept {
                Ok(v) => v,
                Err(_) => continue,
            };
            let svc = svc.clone();
            let signer = signer.clone();
            tokio::spawn(async move {
                let _ = serve_conn(stream, peer, svc, signer).await;
            });
        }
    });

    Ok(HttpAclProxyHandle {
        addr,
        orig_dest,
        shutdown_tx: Some(shutdown_tx),
    })
}

async fn serve_conn(
    stream: TcpStream,
    peer: SocketAddr,
    svc: AclService,
    signer: Option<Arc<CertSigner>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut first = [0u8; 1];
    let n = stream.peek(&mut first).await?;
    if n == 0 {
        return Ok(());
    }

    if is_tls_client_hello(first[0]) {
        let signer = match signer {
            Some(s) => s,
            None => return Ok(()), // no CA: cannot MITM
        };
        // LazyConfigAcceptor reads the ClientHello so we can choose a config by
        // SNI before completing the handshake. First arg is a fresh Acceptor.
        let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
        let start = acceptor.await?;
        let sni = match start.client_hello().server_name() {
            Some(s) => s.to_string(),
            None => return Ok(()), // fail closed: no SNI
        };
        let cfg = signer.server_config_for(&sni)?;
        let tls = start.into_stream(cfg).await?;
        serve_http(TokioIo::new(tls), peer, svc, "https").await
    } else {
        serve_http(TokioIo::new(stream), peer, svc, "http").await
    }
}

async fn serve_http<I>(
    io: I,
    peer: SocketAddr,
    svc: AclService,
    scheme: &'static str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + 'static,
{
    let service = service_fn(move |req| {
        let svc = svc.clone();
        async move { Ok::<_, std::convert::Infallible>(svc.handle(peer, scheme, req).await) }
    });
    http1::Builder::new().serve_connection(io, service).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classifies_tls_vs_plaintext() {
        assert!(is_tls_client_hello(0x16));
        assert!(!is_tls_client_hello(b'G')); // "GET ..."
        assert!(!is_tls_client_hello(b'P')); // "POST ..."
    }

    // Extract the first certificate DER from a PEM string.
    fn first_cert_der(pem: &str) -> rustls::pki_types::CertificateDer<'static> {
        let mut rd = std::io::BufReader::new(pem.as_bytes());
        let der = rustls_pemfile::certs(&mut rd)
            .next()
            .expect("at least one CERTIFICATE block")
            .expect("valid certificate");
        der
    }

    // Hermetic proof of the MITM path, no upstream network:
    //   1. the proxy terminates TLS,
    //   2. a client trusting the generated CA completes the handshake against
    //      the proxy's per-SNI minted leaf,
    //   3. a request that does not match the ACL gets HTTP 403 with the
    //      sandlock body (the deny path never contacts an upstream).
    #[tokio::test]
    async fn https_mitm_denies_disallowed_request() {
        use std::sync::Arc;
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;
        use tokio_rustls::TlsConnector;

        // Ephemeral CA, plus an allow rule that will NOT match our request.
        let ca = resolve_ca(None, None, true)
            .expect("resolve_ca ok")
            .expect("ephemeral CA generated");
        let allow = vec![crate::http::HttpRule::parse("GET allowed.test/*").expect("rule parses")];
        let handle = super::spawn_transparent_proxy(
            allow,
            vec![],
            Arc::new(vec![]),
            Some(&ca.cert_pem),
            Some(&ca.key_pem),
            None,
            std::net::Ipv4Addr::LOCALHOST.into(),
            None,
        )
        .await
        .expect("proxy spawns");
        let addr = handle.addr;

        // rustls client that trusts only the generated CA.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(first_cert_der(&ca.cert_pem)).expect("add CA root");
        let client_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_cfg));

        // Connect and complete the TLS handshake with SNI "denied.test". A
        // successful handshake proves termination plus trust of the minted leaf.
        let tcp = TcpStream::connect(addr).await.expect("tcp connect");
        let server_name = rustls::pki_types::ServerName::try_from("denied.test")
            .expect("valid server name");
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("TLS handshake against minted leaf");

        // A disallowed request: GET denied.test/secret.
        tls.write_all(
            b"GET /secret HTTP/1.1\r\nHost: denied.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("write request");

        let mut buf = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut buf))
            .await
            .expect("response within timeout")
            .expect("read response");
        let resp = String::from_utf8_lossy(&buf);

        assert!(resp.starts_with("HTTP/1.1 403"), "expected 403, got: {resp}");
        assert!(
            resp.contains("Blocked by sandlock HTTP ACL policy"),
            "body: {resp}"
        );
    }

    /// Hermetic proof of the Block B proxy path over plaintext HTTP:
    ///
    ///   1. the proxy forwards the request to a local upstream (no external
    ///      network),
    ///   2. a matching credential rule injects `Authorization: Bearer <secret>`
    ///      inside the proxy — after the ACL check — and the secret never
    ///      reaches the client,
    ///   3. `host_mask` rewrites only the wire `Host` header (the connection
    ///      still goes to the real destination).
    ///
    /// TLS termination itself is covered separately by
    /// [`https_mitm_denies_disallowed_request`]; injection and masking run in
    /// the same per-request handler for both the plaintext and MITM paths.
    #[tokio::test]
    async fn http_injects_credential_and_masks_host() {
        use crate::credential::{AuthShape, InjectRule, OnExistingHeader, SecretString};
        use std::sync::Arc;
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        // 1. Local upstream that captures the raw request and replies 200.
        let upstream = TcpListener::bind("127.0.0.1:0").await.expect("upstream binds");
        let upstream_addr = upstream.local_addr().expect("upstream addr");
        let seen: Arc<std::sync::Mutex<Vec<u8>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen_cap = Arc::clone(&seen);
        tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.expect("upstream accepts");
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            loop {
                let n = sock.read(&mut tmp).await.expect("upstream reads");
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            *seen_cap.lock().unwrap() = buf;
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .expect("upstream responds");
        });

        // 2. Proxy with an allow rule, a bearer inject rule, and a host mask.
        let inject = vec![InjectRule {
            name: "test".to_string(),
            matcher: crate::http::HttpRule::parse("* 127.0.0.1/v1/*").expect("rule parses"),
            auth: AuthShape::Bearer,
            secret: Arc::new(SecretString::new(b"sk-test".to_vec())),
            on_existing: OnExistingHeader::Replace,
        }];
        let handle = super::spawn_transparent_proxy(
            vec![crate::http::HttpRule::parse("* 127.0.0.1/*").expect("allow parses")],
            vec![],
            Arc::new(inject),
            None,
            None,
            None,
            std::net::Ipv4Addr::LOCALHOST.into(),
            Some("internal.test:${PORT}"),
        )
        .await
        .expect("proxy spawns");
        let addr = handle.addr;

        // 3. Plaintext client; the request addresses the real upstream
        //    host:port while the proxy masks the wire Host.
        let mut conn = TcpStream::connect(addr).await.expect("tcp connect");

        let host_line = format!("Host: {upstream_addr}");
        conn.write_all(
            format!("GET /v1/test HTTP/1.1\r\n{host_line}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .expect("write request");

        // The connection may not half-close after the response, so read
        // bounded chunks until the response head + body are complete rather
        // than waiting for EOF.
        let mut resp = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let mut chunk = [0u8; 4096];
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let n = tokio::time::timeout(remaining, conn.read(&mut chunk))
                .await
                .expect("response within timeout")
                .expect("read response");
            if n == 0 {
                break;
            }
            resp.extend_from_slice(&chunk[..n]);
            // Response head + the 2-byte body ("ok") is enough to assert on.
            if let Some(header_end) = resp.windows(4).position(|w| w == b"\r\n\r\n") {
                if resp.len() >= header_end + 4 + 2 {
                    break;
                }
            }
        }
        let resp = String::from_utf8_lossy(&resp);
        assert!(resp.starts_with("HTTP/1.1 200"), "expected 200, got: {resp}");

        // 4. The upstream saw the injected credential AND the masked host.
        let raw = seen.lock().unwrap().clone();
        let raw = String::from_utf8_lossy(&raw);
        assert!(
            raw.to_ascii_lowercase().contains("authorization: bearer sk-test"),
            "upstream request missing injected header: {raw}"
        );
        assert!(
            raw.to_ascii_lowercase()
                .contains(&format!("host: internal.test:{}", upstream_addr.port())),
            "upstream request missing masked host: {raw}"
        );
    }
}
