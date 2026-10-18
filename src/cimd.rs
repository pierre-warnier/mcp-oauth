//! Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document,
//! MCP authorization 2025-11-25): a `client_id` that is an https URL names a
//! JSON document with the client's metadata. It is fetched (5 s timeout,
//! 64 KiB max, no redirects, public IP addresses only), validated, and cached
//! in memory for an hour; on a transport error a cached copy up to a day old
//! is still used. Errors and invalid documents are never cached.

use crate::jwt::{self, Jwk};
use crate::oauth::{is_loopback, pattern_matches, uri_parts};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_DOC: usize = 64 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const FRESH: Duration = Duration::from_secs(3600);
const STALE_OK: Duration = Duration::from_secs(86400);
/// Minimum time between two JWKS fetches triggered by an unknown `kid`.
const JWKS_REFETCH: Duration = Duration::from_secs(60);
const MAX_ENTRIES: usize = 256;
const MAX_REDIRECT_URIS: usize = 64;
const MAX_URL: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AuthMethod {
    None,
    PrivateKeyJwt,
}

/// A validated Client ID Metadata Document.
#[derive(Clone, Debug, PartialEq)]
pub struct ClientDoc {
    pub client_id: String,
    pub client_name: Option<String>,
    /// The document's redirect URIs that the redirect patterns allow.
    pub redirect_uris: Vec<String>,
    /// Token endpoint authentication the client may use here.
    pub auth_methods: Vec<AuthMethod>,
    pub jwks: Option<Vec<Jwk>>,
    pub jwks_uri: Option<String>,
}

impl ClientDoc {
    pub fn allows(&self, m: AuthMethod) -> bool {
        self.auth_methods.contains(&m)
    }
}

#[derive(Debug, PartialEq)]
pub enum CimdError {
    /// Network trouble or a server error at the client: try again later.
    Unavailable(String),
    /// The URL or the document is not acceptable.
    Invalid(String),
}

impl std::fmt::Display for CimdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CimdError::Unavailable(s) | CimdError::Invalid(s) => f.write_str(s),
        }
    }
}

/// A client identifier URL (draft section 3): https, a host name (no IP
/// literal, no userinfo), a path, no dot segments, no fragment.
pub fn check_url(u: &str) -> Result<(), String> {
    let bad = |why: &str| Err(format!("client_id URL {u:?}: {why}"));
    if u.len() > MAX_URL {
        return bad("too long");
    }
    let Some(p) = uri_parts(u) else {
        return bad("not an absolute URL without userinfo, fragment or spaces");
    };
    if p.scheme != "https" {
        return bad("must be https");
    }
    let host = p.host.trim_start_matches('[').trim_end_matches(']');
    if host.parse::<IpAddr>().is_ok() || is_loopback(p.host) || !host.contains('.') {
        return bad("host must be a public DNS name");
    }
    if p.port
        .is_some_and(|x| x.is_empty() || x.len() > 5 || !x.bytes().all(|b| b.is_ascii_digit()))
    {
        return bad("bad port");
    }
    if !p.rest.starts_with('/') {
        return bad("needs a path");
    }
    let path = p.rest.split('?').next().unwrap_or("");
    let lower = path.to_ascii_lowercase();
    if path.split('/').any(|s| s == "." || s == "..") || lower.contains("%2e") {
        return bad("no dot segments");
    }
    Ok(())
}

/// RFC 6890 special-purpose addresses are refused (SSRF, draft section 8.6).
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => public_v4(a),
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return public_v4(v4);
            }
            let s = a.segments();
            // Global unicast 2000::/3 only, minus 2001::/23 (IETF protocol
            // assignments, Teredo), 2001:db8::/32 (documentation), 2002::/16 (6to4).
            (s[0] & 0xe000) == 0x2000
                && !(s[0] == 0x2001 && s[1] < 0x0200)
                && !(s[0] == 0x2001 && s[1] == 0x0db8)
                && s[0] != 0x2002
        }
    }
}

fn public_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    !(o[0] == 0
        || o[0] == 10
        || o[0] == 127
        || (o[0] == 100 && (o[1] & 0xc0) == 64)
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 172 && (o[1] & 0xf0) == 16)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 192 && o[1] == 88 && o[2] == 99)
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 198 && (o[1] & 0xfe) == 18)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        || o[0] >= 224)
}

/// DNS resolver that drops special-purpose addresses, so a public name
/// pointing at a private address is not fetched either.
struct PublicOnly;

impl reqwest::dns::Resolve for PublicOnly {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|a| is_public_ip(a.ip()))
                .collect();
            if addrs.is_empty() {
                return Err(format!("{host} has no public address").into());
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

fn sanitize_name(n: &str) -> Option<String> {
    let n: String = n.chars().filter(|c| !c.is_control()).take(100).collect();
    let n = n.trim();
    (!n.is_empty()).then(|| n.to_string())
}

/// Validate a fetched document for `url` (draft sections 4 and 4.1, MCP
/// 2025-11-25): JSON object whose `client_id` is exactly `url`, no client
/// secret, `redirect_uris` filtered by the redirect patterns, token endpoint
/// authentication `none` and/or `private_key_jwt` (the plural
/// `token_endpoint_auth_methods_supported`, else the singular
/// `token_endpoint_auth_method`, else `none`).
pub fn parse_doc(url: &str, body: &[u8], patterns: &[String]) -> Result<ClientDoc, String> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("client metadata is not JSON: {e}"))?;
    let m = v
        .as_object()
        .ok_or("client metadata is not a JSON object")?;
    if m.get("client_id").and_then(|c| c.as_str()) != Some(url) {
        return Err("client metadata client_id differs from its URL".into());
    }
    if m.contains_key("client_secret") || m.contains_key("client_secret_expires_at") {
        return Err("client metadata must not contain a client secret".into());
    }
    let strings = |k: &str| -> Result<Option<Vec<String>>, String> {
        match m.get(k) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::Array(a)) => a
                .iter()
                .map(|x| x.as_str().map(String::from))
                .collect::<Option<Vec<_>>>()
                .map(Some)
                .ok_or(format!("client metadata {k} must be strings")),
            Some(_) => Err(format!("client metadata {k} must be an array")),
        }
    };
    let uris = strings("redirect_uris")?.unwrap_or_default();
    if uris.is_empty() || uris.len() > MAX_REDIRECT_URIS {
        return Err("client metadata needs 1 to 64 redirect_uris".into());
    }
    let redirect_uris: Vec<String> = uris
        .into_iter()
        .filter(|u| u.len() <= MAX_URL && patterns.iter().any(|p| pattern_matches(p, u)))
        .collect();
    if redirect_uris.is_empty() {
        return Err("none of the client's redirect_uris is allowed on this server".into());
    }
    if let Some(g) = strings("grant_types")?
        && !g.iter().any(|g| g == "authorization_code")
    {
        return Err("client metadata grant_types lacks authorization_code".into());
    }
    if let Some(r) = strings("response_types")?
        && !r.iter().any(|r| r == "code")
    {
        return Err("client metadata response_types lacks code".into());
    }
    let shared_secret = |s: &str| s.starts_with("client_secret") || s == "tls_client_auth";
    let single = m.get("token_endpoint_auth_method").and_then(|s| s.as_str());
    if single.is_some_and(|s| s.starts_with("client_secret")) {
        return Err(
            "client metadata must not use a shared-secret token_endpoint_auth_method".into(),
        );
    }
    let declared: Vec<String> = match strings("token_endpoint_auth_methods_supported")? {
        Some(v) if !v.is_empty() => v,
        _ => vec![single.unwrap_or("none").to_string()],
    };
    let jwks = m
        .get("jwks")
        .and_then(jwt::parse_jwks)
        .filter(|k| !k.is_empty());
    let jwks_uri = m
        .get("jwks_uri")
        .and_then(|u| u.as_str())
        .filter(|u| check_url(u).is_ok())
        .map(String::from);
    let mut auth_methods = Vec::new();
    for d in declared.iter().filter(|d| !shared_secret(d)) {
        let am = match d.as_str() {
            "none" => AuthMethod::None,
            "private_key_jwt" if jwks.is_some() || jwks_uri.is_some() => AuthMethod::PrivateKeyJwt,
            _ => continue,
        };
        if !auth_methods.contains(&am) {
            auth_methods.push(am);
        }
    }
    if auth_methods.is_empty() {
        return Err(format!(
            "client metadata offers no usable token_endpoint_auth_method ({}); supported: none, private_key_jwt with jwks or jwks_uri",
            declared.join(", ")
        ));
    }
    Ok(ClientDoc {
        client_id: url.to_string(),
        client_name: m
            .get("client_name")
            .and_then(|n| n.as_str())
            .and_then(sanitize_name),
        redirect_uris,
        auth_methods,
        jwks,
        jwks_uri,
    })
}

enum Fetcher {
    Http(reqwest::Client),
    /// Tests: URL -> (status, body).
    #[cfg(test)]
    Static(Mutex<HashMap<String, (u16, Vec<u8>)>>),
}

impl Fetcher {
    async fn get(&self, url: &str) -> Result<Vec<u8>, CimdError> {
        match self {
            Fetcher::Http(c) => {
                let unavailable = |e: reqwest::Error| {
                    let mut msg = format!("cannot fetch {url}: {e}");
                    let mut src = std::error::Error::source(&e);
                    while let Some(s) = src {
                        msg.push_str(&format!(": {s}"));
                        src = s.source();
                    }
                    CimdError::Unavailable(msg)
                };
                let mut r = c
                    .get(url)
                    .header(reqwest::header::ACCEPT, "application/json")
                    .send()
                    .await
                    .map_err(unavailable)?;
                let st = r.status();
                if st.is_server_error() {
                    return Err(CimdError::Unavailable(format!("{url} answered {st}")));
                }
                if st != reqwest::StatusCode::OK {
                    return Err(CimdError::Invalid(format!("{url} answered {st}, not 200")));
                }
                if r.content_length().is_some_and(|n| n > MAX_DOC as u64) {
                    return Err(CimdError::Invalid(format!("{url} is larger than 64 KiB")));
                }
                let mut body = Vec::new();
                while let Some(chunk) = r.chunk().await.map_err(unavailable)? {
                    if body.len() + chunk.len() > MAX_DOC {
                        return Err(CimdError::Invalid(format!("{url} is larger than 64 KiB")));
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(body)
            }
            #[cfg(test)]
            Fetcher::Static(m) => match m.lock().unwrap().get(url).cloned() {
                Some((200, b)) if b.len() <= MAX_DOC => Ok(b),
                Some((200, _)) => Err(CimdError::Invalid(format!("{url} is larger than 64 KiB"))),
                Some((s, _)) if s >= 500 => {
                    Err(CimdError::Unavailable(format!("{url} answered {s}")))
                }
                Some((s, _)) => Err(CimdError::Invalid(format!("{url} answered {s}, not 200"))),
                None => Err(CimdError::Unavailable(format!("cannot fetch {url}"))),
            },
        }
    }
}

struct Entry {
    doc: Arc<ClientDoc>,
    fetched: Instant,
    /// Keys from `jwks_uri` and when they were fetched.
    keys: Option<(Arc<Vec<Jwk>>, Instant)>,
}

pub struct Cimd {
    fetcher: Fetcher,
    patterns: Vec<String>,
    cache: Mutex<HashMap<String, Entry>>,
}

impl Cimd {
    pub fn new(patterns: Vec<String>) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(FETCH_TIMEOUT)
            .connect_timeout(FETCH_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .no_proxy()
            .dns_resolver(PublicOnly)
            .user_agent(concat!("mcp-oauth/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| format!("CIMD HTTP client: {e}"))?;
        Ok(Self {
            fetcher: Fetcher::Http(client),
            patterns,
            cache: Mutex::new(HashMap::new()),
        })
    }

    #[cfg(test)]
    pub fn new_static(patterns: Vec<String>) -> Self {
        Self {
            fetcher: Fetcher::Static(Mutex::new(HashMap::new())),
            patterns,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Tests: serve `body` with `status` at `url`.
    #[cfg(test)]
    pub fn serve(&self, url: &str, status: u16, body: &[u8]) {
        let Fetcher::Static(m) = &self.fetcher else {
            panic!("not a static fetcher")
        };
        m.lock()
            .unwrap()
            .insert(url.into(), (status, body.to_vec()));
    }

    /// Tests: age every cache entry by `d`.
    #[cfg(test)]
    pub fn age(&self, d: Duration) {
        for e in self.cache.lock().unwrap().values_mut() {
            e.fetched -= d;
            if let Some((_, t)) = &mut e.keys {
                *t -= d;
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.cache.lock().expect("cimd cache lock")
    }

    /// The validated document at `url` (from the cache if fresh).
    pub async fn get(&self, url: &str) -> Result<Arc<ClientDoc>, CimdError> {
        check_url(url).map_err(CimdError::Invalid)?;
        let now = Instant::now();
        let stale = match self.lock().get(url) {
            Some(e) if now.duration_since(e.fetched) < FRESH => return Ok(e.doc.clone()),
            Some(e) if now.duration_since(e.fetched) < STALE_OK => Some(e.doc.clone()),
            _ => None,
        };
        let body = match self.fetcher.get(url).await {
            Ok(b) => b,
            Err(CimdError::Unavailable(e)) => {
                return match stale {
                    Some(d) => {
                        eprintln!("oauth: {e}; using the cached client metadata");
                        Ok(d)
                    }
                    None => Err(CimdError::Unavailable(e)),
                };
            }
            Err(e) => {
                self.lock().remove(url);
                return Err(e);
            }
        };
        match parse_doc(url, &body, &self.patterns) {
            Ok(doc) => {
                let doc = Arc::new(doc);
                let mut c = self.lock();
                let keys = c
                    .remove(url)
                    .filter(|e| e.doc.jwks_uri == doc.jwks_uri)
                    .and_then(|e| e.keys);
                if c.len() >= MAX_ENTRIES
                    && let Some(oldest) = c
                        .iter()
                        .min_by_key(|(_, e)| e.fetched)
                        .map(|(k, _)| k.clone())
                {
                    c.remove(&oldest);
                }
                c.insert(
                    url.to_string(),
                    Entry {
                        doc: doc.clone(),
                        fetched: Instant::now(),
                        keys,
                    },
                );
                Ok(doc)
            }
            Err(e) => {
                self.lock().remove(url);
                Err(CimdError::Invalid(e))
            }
        }
    }

    /// Public keys of `doc`: inline `jwks`, else `jwks_uri` (cached an hour;
    /// `refresh` refetches, at most once a minute, after an unknown `kid`).
    pub async fn keys(&self, doc: &ClientDoc, refresh: bool) -> Result<Arc<Vec<Jwk>>, CimdError> {
        if let Some(k) = &doc.jwks {
            return Ok(Arc::new(k.clone()));
        }
        let Some(uri) = doc.jwks_uri.as_deref() else {
            return Err(CimdError::Invalid(
                "client metadata has no jwks or jwks_uri".into(),
            ));
        };
        let now = Instant::now();
        if let Some((k, t)) = self.lock().get(&doc.client_id).and_then(|e| e.keys.clone()) {
            let age = now.duration_since(t);
            if age < FRESH && (!refresh || age < JWKS_REFETCH) {
                return Ok(k);
            }
        }
        let body = self.fetcher.get(uri).await?;
        let keys = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .as_ref()
            .and_then(jwt::parse_jwks)
            .ok_or_else(|| CimdError::Invalid(format!("{uri} is not a JWK Set")))?;
        let keys = Arc::new(keys);
        if let Some(e) = self.lock().get_mut(&doc.client_id) {
            e.keys = Some((keys.clone(), Instant::now()));
        }
        Ok(keys)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::oauth::DEFAULT_REDIRECT_PATTERNS;

    pub(crate) const CLAUDE: &str = "https://claude.ai/oauth/mcp-oauth-client-metadata";
    pub(crate) const CLAUDE_CODE: &str = "https://claude.ai/oauth/claude-code-client-metadata";
    pub(crate) const CHATGPT: &str = "https://chatgpt.com/oauth/client.json";

    /// The published documents, as fetched on 2026-10-18.
    pub(crate) const CLAUDE_DOC: &str = r#"{"client_id":"https://claude.ai/oauth/mcp-oauth-client-metadata","client_name":"Claude","client_uri":"https://claude.ai","redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"grant_types":["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:jwt-bearer"],"response_types":["code"],"token_endpoint_auth_method":"none"}"#;
    pub(crate) const CLAUDE_CODE_DOC: &str = r#"{"client_id":"https://claude.ai/oauth/claude-code-client-metadata","client_name":"Claude Code","client_uri":"https://claude.ai","redirect_uris":["http://localhost/callback","http://127.0.0.1/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}"#;
    pub(crate) const CHATGPT_DOC: &str = r#"{"client_id":"https://chatgpt.com/oauth/client.json","client_uri":"https://chatgpt.com/","redirect_uris":["https://chatgpt.com/connector_platform_oauth_redirect"],"token_endpoint_auth_method":"private_key_jwt","token_endpoint_auth_methods_supported":["none","private_key_jwt"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"client_name":"ChatGPT","logo_uri":"https://persistent.oaistatic.com/sonic/misc/openai-logo.png","token_endpoint_auth_signing_alg":"RS256","jwks_uri":"https://chatgpt.com/oauth/jwks.json"}"#;

    fn patterns() -> Vec<String> {
        DEFAULT_REDIRECT_PATTERNS
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    #[test]
    fn vendor_documents_validate() {
        let p = patterns();
        let c = parse_doc(CLAUDE, CLAUDE_DOC.as_bytes(), &p).unwrap();
        assert_eq!(c.client_name.as_deref(), Some("Claude"));
        assert_eq!(c.redirect_uris, ["https://claude.ai/api/mcp/auth_callback"]);
        assert_eq!(
            c.auth_methods,
            [AuthMethod::None],
            "extra jwt-bearer grant ignored"
        );
        let cc = parse_doc(CLAUDE_CODE, CLAUDE_CODE_DOC.as_bytes(), &p).unwrap();
        assert_eq!(cc.redirect_uris.len(), 2);
        let g = parse_doc(CHATGPT, CHATGPT_DOC.as_bytes(), &p).unwrap();
        assert_eq!(
            g.auth_methods,
            [AuthMethod::None, AuthMethod::PrivateKeyJwt]
        );
        assert_eq!(
            g.jwks_uri.as_deref(),
            Some("https://chatgpt.com/oauth/jwks.json")
        );
        assert_eq!(
            g.redirect_uris,
            ["https://chatgpt.com/connector_platform_oauth_redirect"]
        );
    }

    #[test]
    fn document_rules() {
        let p = patterns();
        let u = "https://app.example/client.json";
        let doc = |extra: &str| {
            format!(
                r#"{{"client_id":"{u}","client_name":"App","redirect_uris":["https://claude.ai/api/mcp/auth_callback","https://evil.example/cb"]{extra}}}"#
            )
        };
        let ok = parse_doc(u, doc("").as_bytes(), &p).unwrap();
        assert_eq!(
            ok.redirect_uris,
            ["https://claude.ai/api/mcp/auth_callback"],
            "patterns filter"
        );
        assert_eq!(ok.auth_methods, [AuthMethod::None], "default none");
        let err = |extra: &str| parse_doc(u, doc(extra).as_bytes(), &p).unwrap_err();
        assert!(err(r#","client_secret":"s""#).contains("secret"));
        assert!(
            err(r#","token_endpoint_auth_method":"client_secret_basic""#).contains("shared-secret")
        );
        assert!(
            err(r#","token_endpoint_auth_method":"private_key_jwt""#).contains("no usable"),
            "pkjwt without keys"
        );
        assert!(err(r#","token_endpoint_auth_method":"tls_client_auth""#).contains("no usable"));
        assert!(err(r#","grant_types":["client_credentials"]"#).contains("authorization_code"));
        assert!(err(r#","response_types":["token"]"#).contains("code"));
        assert!(err(r#","grant_types":"authorization_code""#).contains("array"));
        let jwks = r#","token_endpoint_auth_method":"private_key_jwt","jwks":{"keys":[{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}]}"#;
        assert_eq!(
            parse_doc(u, doc(jwks).as_bytes(), &p).unwrap().auth_methods,
            [AuthMethod::PrivateKeyJwt]
        );
        let insecure_jwks = r#","token_endpoint_auth_method":"private_key_jwt","jwks_uri":"http://app.example/jwks""#;
        assert!(parse_doc(u, doc(insecure_jwks).as_bytes(), &p).is_err());
        assert!(
            parse_doc("https://app.example/other.json", doc("").as_bytes(), &p)
                .unwrap_err()
                .contains("differs")
        );
        assert!(parse_doc(u, b"[1]", &p).is_err());
        assert!(parse_doc(u, b"nope", &p).is_err());
        let no_allowed =
            format!(r#"{{"client_id":"{u}","redirect_uris":["https://evil.example/cb"]}}"#);
        assert!(
            parse_doc(u, no_allowed.as_bytes(), &p)
                .unwrap_err()
                .contains("redirect_uris")
        );
        let ctrl = format!(
            r#"{{"client_id":"{u}","client_name":"  A\u0007B  ","redirect_uris":["https://claude.ai/api/mcp/auth_callback"]}}"#
        );
        assert_eq!(
            parse_doc(u, ctrl.as_bytes(), &p)
                .unwrap()
                .client_name
                .as_deref(),
            Some("AB")
        );
    }

    #[test]
    fn client_id_urls() {
        for ok in [
            CLAUDE,
            CLAUDE_CODE,
            CHATGPT,
            "https://a.example:8443/c?x=1",
            "https://a.example/",
        ] {
            assert_eq!(check_url(ok), Ok(()), "{ok}");
        }
        for bad in [
            "http://a.example/c",
            "https://a.example",
            "https://u@a.example/c",
            "https://a.example/c#f",
            "https://a.example/./c",
            "https://a.example/x/../c",
            "https://a.example/%2E%2E/c",
            "https://127.0.0.1/c",
            "https://[::1]/c",
            "https://10.0.0.1/c",
            "https://localhost/c",
            "https://intranet/c",
            "https://a.example:x/c",
            "https://a.example/c d",
            "ftp://a.example/c",
            "abc",
        ] {
            assert!(check_url(bad).is_err(), "{bad}");
        }
        assert!(check_url(&format!("https://a.example/{}", "x".repeat(600))).is_err());
    }

    #[test]
    fn special_purpose_addresses() {
        for ip in [
            "0.1.2.3",
            "10.1.1.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.1",
            "192.0.2.1",
            "192.168.0.232",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::a00:1",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "2001::1",
            "2002::1",
            "100::1",
        ] {
            assert!(!is_public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "1.1.1.1",
            "160.79.104.10",
            "20.170.184.1",
            "172.32.0.1",
            "2606:4700::1",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_public_ip(ip.parse().unwrap()), "{ip}");
        }
    }

    #[tokio::test]
    async fn cache_errors_and_stale_copies() {
        let c = Cimd::new_static(patterns());
        c.serve(CLAUDE, 200, CLAUDE_DOC.as_bytes());
        let d = c.get(CLAUDE).await.unwrap();
        assert_eq!(d.client_name.as_deref(), Some("Claude"));
        // Cached: a broken origin does not matter within the hour.
        c.serve(CLAUDE, 500, b"");
        assert_eq!(c.get(CLAUDE).await.unwrap(), d);
        // After an hour, a server error falls back to the cached copy...
        c.age(Duration::from_secs(3700));
        assert_eq!(c.get(CLAUDE).await.unwrap(), d);
        // ...but not after a day.
        c.age(Duration::from_secs(86400));
        assert!(matches!(
            c.get(CLAUDE).await,
            Err(CimdError::Unavailable(_))
        ));
        // An invalid document evicts the entry and is not cached.
        c.serve(CLAUDE, 200, CLAUDE_DOC.as_bytes());
        c.get(CLAUDE).await.unwrap();
        c.age(Duration::from_secs(3700));
        c.serve(CLAUDE, 200, CHATGPT_DOC.as_bytes());
        assert!(matches!(c.get(CLAUDE).await, Err(CimdError::Invalid(_))));
        c.serve(CLAUDE, 503, b"");
        assert!(
            matches!(c.get(CLAUDE).await, Err(CimdError::Unavailable(_))),
            "invalid document left no stale copy"
        );
        c.serve(CLAUDE, 404, b"");
        assert!(matches!(c.get(CLAUDE).await, Err(CimdError::Invalid(_))));
        c.serve(CLAUDE, 200, &vec![b' '; MAX_DOC + 1]);
        assert!(matches!(c.get(CLAUDE).await, Err(CimdError::Invalid(_))));
        assert!(matches!(
            c.get("https://10.0.0.1/c").await,
            Err(CimdError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn jwks_uri_cache_and_refetch() {
        let c = Cimd::new_static(patterns());
        c.serve(CHATGPT, 200, CHATGPT_DOC.as_bytes());
        let d = c.get(CHATGPT).await.unwrap();
        let k1 = r#"{"keys":[{"kty":"RSA","kid":"a","n":"AQAB","e":"AQAB"}]}"#;
        let k2 = r#"{"keys":[{"kty":"RSA","kid":"b","n":"AQAB","e":"AQAB"}]}"#;
        c.serve("https://chatgpt.com/oauth/jwks.json", 200, k1.as_bytes());
        assert_eq!(
            c.keys(&d, false).await.unwrap()[0].kid.as_deref(),
            Some("a")
        );
        c.serve("https://chatgpt.com/oauth/jwks.json", 200, k2.as_bytes());
        assert_eq!(
            c.keys(&d, false).await.unwrap()[0].kid.as_deref(),
            Some("a"),
            "cached"
        );
        assert_eq!(
            c.keys(&d, true).await.unwrap()[0].kid.as_deref(),
            Some("a"),
            "refetch throttled"
        );
        c.age(Duration::from_secs(61));
        assert_eq!(
            c.keys(&d, true).await.unwrap()[0].kid.as_deref(),
            Some("b"),
            "rotated"
        );
        c.serve("https://chatgpt.com/oauth/jwks.json", 200, b"{}");
        c.age(Duration::from_secs(3601));
        assert!(c.keys(&d, false).await.is_err(), "not a JWK set");
    }

    /// Fetches the real vendor documents through the production fetcher
    /// (network): `cargo test -- --ignored live_vendor_documents`.
    #[tokio::test]
    #[ignore]
    async fn live_vendor_documents() {
        let c = Cimd::new(patterns()).unwrap();
        for u in [CLAUDE, CLAUDE_CODE, CHATGPT] {
            let d = c.get(u).await.unwrap_or_else(|e| panic!("{u}: {e}"));
            eprintln!("{u}: {d:?}");
        }
        let g = c.get(CHATGPT).await.unwrap();
        let keys = c.keys(&g, false).await.unwrap();
        assert!(keys.iter().any(|k| k.kty == "RSA"), "{keys:?}");
        // SSRF guard on a public name that resolves to loopback.
        let e = c.get("https://localtest.me/x").await.unwrap_err();
        eprintln!("localtest.me: {e}");
        assert!(
            matches!(&e, CimdError::Unavailable(m) if m.contains("no public address")),
            "{e}"
        );
    }
}
