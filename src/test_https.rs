//! Tests: a local HTTPS server (test CA in `testdata/`, names `*.cimd.test`)
//! for the production CIMD fetcher, and a resolver that sends every
//! `*.cimd.test` name to it. Each route answers after an optional delay;
//! the server counts requests per path and the most connections it held at
//! once.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::{
    self,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};

pub const CA: &str = include_str!("testdata/cimd-test-ca.pem");
const LEAF: &str = include_str!("testdata/cimd-test-leaf.pem");
const KEY: &str = include_str!("testdata/cimd-test-leaf.key");

#[derive(Clone, Default)]
pub struct Route {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub delay: Duration,
    /// Send `content-length` (else the body ends with the connection).
    pub content_length: bool,
}

impl Route {
    pub fn json(body: impl Into<Vec<u8>>) -> Self {
        Route {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.into(),
            delay: Duration::ZERO,
            content_length: true,
        }
    }

    pub fn delayed(mut self, d: Duration) -> Self {
        self.delay = d;
        self
    }
}

#[derive(Default)]
struct State {
    routes: Mutex<HashMap<String, Route>>,
    hits: Mutex<HashMap<String, usize>>,
    active: AtomicUsize,
    max_active: AtomicUsize,
}

#[derive(Clone)]
pub struct Server {
    pub port: u16,
    st: Arc<State>,
}

impl Server {
    pub async fn start() -> Server {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let certs = vec![CertificateDer::from_pem_slice(LEAF.as_bytes()).unwrap()];
        let key = PrivateKeyDer::from_pem_slice(KEY.as_bytes()).unwrap();
        let cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let l = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = l.local_addr().unwrap().port();
        let st = Arc::new(State::default());
        let s2 = st.clone();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = l.accept().await else {
                    continue;
                };
                let (acceptor, st) = (acceptor.clone(), s2.clone());
                tokio::spawn(async move {
                    let n = st.active.fetch_add(1, Ordering::SeqCst) + 1;
                    st.max_active.fetch_max(n, Ordering::SeqCst);
                    let _ = serve(acceptor, tcp, &st).await;
                    st.active.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        Server { port, st }
    }

    pub fn route(&self, path: &str, r: Route) {
        self.st.routes.lock().unwrap().insert(path.into(), r);
    }

    pub fn hits(&self, path: &str) -> usize {
        self.st.hits.lock().unwrap().get(path).copied().unwrap_or(0)
    }

    pub fn total_hits(&self) -> usize {
        self.st.hits.lock().unwrap().values().sum()
    }

    pub fn max_active(&self) -> usize {
        self.st.max_active.load(Ordering::SeqCst)
    }

    /// `https://<host>.cimd.test:<port><path>`.
    pub fn url(&self, host: &str, path: &str) -> String {
        format!("https://{host}.cimd.test:{}{path}", self.port)
    }
}

async fn serve(
    acceptor: tokio_rustls::TlsAcceptor,
    tcp: tokio::net::TcpStream,
    st: &State,
) -> std::io::Result<()> {
    let mut tls = acceptor.accept(tcp).await?;
    let mut req = Vec::new();
    let mut buf = [0u8; 4096];
    while !req.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = tls.read(&mut buf).await?;
        if n == 0 || req.len() > 16384 {
            return Ok(());
        }
        req.extend_from_slice(&buf[..n]);
    }
    let line = String::from_utf8_lossy(&req);
    let path = line.split(' ').nth(1).unwrap_or("").to_string();
    *st.hits.lock().unwrap().entry(path.clone()).or_default() += 1;
    let route = st.routes.lock().unwrap().get(&path).cloned();
    let r = route.unwrap_or(Route {
        status: 404,
        content_length: true,
        ..Default::default()
    });
    tokio::time::sleep(r.delay).await;
    let mut head = format!("HTTP/1.1 {} X\r\nconnection: close\r\n", r.status);
    for (k, v) in &r.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    if r.content_length {
        head.push_str(&format!("content-length: {}\r\n", r.body.len()));
    }
    head.push_str("\r\n");
    tls.write_all(head.as_bytes()).await?;
    tls.write_all(&r.body).await?;
    tls.shutdown().await
}

/// Every `*.cimd.test` name resolves to the local server (the port comes
/// from the URL); anything else fails, so nothing leaves the machine.
pub struct LocalResolver;

impl reqwest::dns::Resolve for LocalResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            if host == "cimd.test" || host.ends_with(".cimd.test") {
                let a = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
                Ok(Box::new(std::iter::once(a)) as reqwest::dns::Addrs)
            } else {
                Err(format!("test resolver: {host} is not a test name").into())
            }
        })
    }
}

pub fn ca() -> reqwest::Certificate {
    reqwest::Certificate::from_pem(CA.as_bytes()).unwrap()
}
