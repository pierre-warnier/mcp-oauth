//! The authorization server and the bearer guard (see the crate docs).
//!
//! Secrets at rest: only SHA-256 digests of access and refresh tokens are
//! stored (`oauth-tokens.json`); clients registered by DCR (with the SHA-256
//! digest of their client secret, if any) are in `oauth-clients.json`; both
//! are written atomically with mode 600. Codes, login tickets, CIMD documents
//! and assertion `jti`s live in memory.

use crate::cimd::{AuthMethod, Cimd, CimdError};
use crate::guard::AuthFailures;
use crate::jwt;
use crate::password::{DEFAULT_MAX_PASSWORD_CHECKS, OwnerPassword};
use axum::{
    Extension, Router,
    body::Bytes,
    extract::{RawQuery, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

pub const ACCESS_TTL: u64 = 3600;
pub const REFRESH_TTL: u64 = 30 * 86400;
const CODE_TTL: u64 = 300;
const TICKET_TTL: u64 = 600;
const MAX_CLIENTS: usize = 512;
const MAX_FAMILIES: usize = 1024;
const MAX_PENDING: usize = 256;
const MAX_RETIRED: usize = 16;
const MAX_JTIS: usize = 10_000;
const SCOPE: &str = "mcp";
const CLIENTS_FILE: &str = "oauth-clients.json";
const TOKENS_FILE: &str = "oauth-tokens.json";

/// Redirect URIs a client may register (see [`check_pattern`]): scheme and
/// host match exactly; `:*` after the host matches any (or no) port; a
/// trailing `*` matches any rest of the path (prefix match). https only,
/// except http on loopback.
/// Claude (claude.ai web, Desktop, mobile), Claude Code (loopback) and
/// ChatGPT custom connectors (callback path unique per connector).
pub const DEFAULT_REDIRECT_PATTERNS: &[&str] = &[
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
    "http://localhost:*/callback",
    "http://127.0.0.1:*/callback",
    "https://chatgpt.com/connector_platform_oauth_redirect",
    "https://chatgpt.com/connector_platform_oauth_redirect/*",
    "https://chatgpt.com/aip/*",
    "https://chat.openai.com/connector_platform_oauth_redirect",
    "https://chat.openai.com/aip/*",
];

#[derive(Clone, Debug)]
pub struct Config {
    /// Public origin, e.g. `https://mcp.example.net` (no trailing slash). It
    /// is the issuer; the protected resource is `issuer + mcp_path`.
    pub issuer: String,
    /// Path of the bearer-protected MCP route, e.g. `/mcp`.
    pub mcp_path: String,
    /// Argon2id PHC string of the single owner's password.
    pub owner_password_hash: String,
    /// Directory for `oauth-clients.json` and `oauth-tokens.json`.
    pub state_dir: PathBuf,
    /// Redirect URIs a client may use, by DCR or in its Client ID Metadata
    /// Document (see [`DEFAULT_REDIRECT_PATTERNS`]).
    pub redirect_patterns: Vec<String>,
    /// Display name of the protected resource: login and consent pages,
    /// `resource_name` of the protected resource metadata.
    pub resource_name: String,
    /// `None` (default): Dynamic Client Registration is open and any https
    /// `client_id` URL is accepted as a Client ID Metadata Document.
    /// `Some(urls)`: only these `client_id` URLs (exact match) are accepted
    /// via CIMD, and DCR is disabled (the registration endpoint answers 403
    /// and is not advertised). New authorizations need an allowlisted
    /// `client_id`; clients registered by DCR earlier are refused at the
    /// authorization endpoint (see [`OAuth::with_dcr_grace`] for their tokens).
    pub cimd_allowlist: Option<Vec<String>>,
}

/// What a valid bearer token grants; inserted into request extensions.
#[derive(Clone, Debug, PartialEq)]
pub struct Grant {
    pub client_id: String,
    pub scope: String,
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn random_token(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).expect("OS random generator");
    B64.encode(b)
}

fn digest(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// argon2id (v19, default OWASP parameters m=19 MiB, t=2, p=1) PHC string.
pub fn hash_password(password: &str) -> Result<String, String> {
    use argon2::PasswordHasher;
    argon2::Argon2::default()
        .hash_password(password.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------- PKCE

/// RFC 7636: verifier is 43..=128 unreserved characters.
fn valid_pkce_string(s: &str) -> bool {
    (43..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
}

/// S256: BASE64URL(SHA256(verifier)) == challenge, compared in constant time.
pub fn pkce_s256_ok(verifier: &str, challenge: &str) -> bool {
    if !valid_pkce_string(verifier) {
        return false;
    }
    let computed = B64.encode(Sha256::digest(verifier.as_bytes()));
    computed.len() == challenge.len() && bool::from(computed.as_bytes().ct_eq(challenge.as_bytes()))
}

// ---------------------------------------------------------- redirect URIs

/// `scheme://host[:port]rest` of an absolute URI; `rest` is path + query.
pub(crate) struct UriParts<'a> {
    pub(crate) scheme: &'a str,
    pub(crate) host: &'a str,
    pub(crate) port: Option<&'a str>,
    pub(crate) rest: &'a str,
}

/// Split an absolute URI. Refuses what browsers could read differently from
/// us: userinfo (`@`), backslashes, fragments, whitespace and controls.
pub(crate) fn uri_parts(u: &str) -> Option<UriParts<'_>> {
    if u.bytes()
        .any(|b| b <= b' ' || b == 0x7f || b == b'\\' || b == b'#')
    {
        return None;
    }
    let (scheme, after) = u.split_once("://")?;
    let (auth, rest) = after.split_at(after.find(['/', '?']).unwrap_or(after.len()));
    if auth.contains('@') {
        return None;
    }
    let (host, port) = if auth.starts_with('[') {
        let (h, p) = auth.split_at(auth.find(']')? + 1);
        (
            h,
            if p.is_empty() {
                None
            } else {
                Some(p.strip_prefix(':')?)
            },
        )
    } else {
        match auth.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (auth, None),
        }
    };
    if scheme.is_empty() || host.is_empty() {
        return None;
    }
    Some(UriParts {
        scheme,
        host,
        port,
        rest,
    })
}

pub(crate) fn is_loopback(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]")
}

/// https, or http on loopback (RFC 8252 section 7.3).
fn secure_scheme(p: &UriParts) -> bool {
    p.scheme == "https" || (p.scheme == "http" && is_loopback(p.host))
}

fn valid_port(p: &str) -> bool {
    (1..=5).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit())
}

/// What a trailing-`*` pattern may match: no dot segments and no encoded
/// dot, slash or backslash, so the match stays under the pattern's prefix.
fn safe_tail(t: &str) -> bool {
    let l = t.to_ascii_lowercase();
    let path = l.split('?').next().unwrap_or("");
    !["%2e", "%2f", "%5c"].iter().any(|e| l.contains(e))
        && !path.split('/').any(|s| s == "." || s == "..")
}

/// A redirect URI pattern is `https://host[:port|:*]/path[*]` (or `http://`
/// on loopback); `*` is only allowed as the last character.
pub fn check_pattern(pattern: &str) -> Result<(), String> {
    let bad = |why: &str| Err(format!("redirect URI pattern {pattern:?}: {why}"));
    let Some(p) = uri_parts(pattern) else {
        return bad("not an absolute URI without userinfo, fragment or spaces");
    };
    if !secure_scheme(&p) {
        return bad("must be https (http only on localhost, 127.0.0.1, [::1])");
    }
    if p.host.contains('*') {
        return bad("no wildcard in the host");
    }
    if p.port.is_some_and(|x| x != "*" && !valid_port(x)) {
        return bad("port must be digits or *");
    }
    if !p.rest.starts_with('/') {
        return bad("needs a path");
    }
    if p.rest.trim_end_matches('*').contains('*') || p.rest.ends_with("**") {
        return bad("* only as the last character");
    }
    Ok(())
}

pub(crate) fn pattern_matches(pattern: &str, uri: &str) -> bool {
    let (Some(p), Some(u)) = (uri_parts(pattern), uri_parts(uri)) else {
        return false;
    };
    if !secure_scheme(&u) || p.scheme != u.scheme || p.host != u.host {
        return false;
    }
    let port_ok = match (p.port, u.port) {
        (Some("*"), None) => true,
        (Some("*"), Some(x)) => valid_port(x),
        (a, b) => a == b,
    };
    port_ok
        && match p.rest.strip_suffix('*') {
            None => p.rest == u.rest,
            Some(prefix) => u.rest.strip_prefix(prefix).is_some_and(safe_tail),
        }
}

/// `http://<loopback>:<port>/path` -> `http://<loopback>/path`; None if not loopback.
fn loopback_without_port(uri: &str) -> Option<String> {
    let rest = uri.strip_prefix("http://")?;
    let (auth, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let host = if auth.starts_with('[') {
        &auth[..auth.find(']')? + 1]
    } else {
        auth.split(':').next()?
    };
    is_loopback(host).then(|| format!("http://{host}{path}"))
}

/// Exact match against the registered URIs, except loopback where the port
/// is ignored (RFC 8252 section 7.3; Claude Code uses an ephemeral port).
fn redirect_registered(registered: &[String], uri: &str) -> bool {
    if uri.contains('#') {
        return false;
    }
    registered.iter().any(|r| {
        r == uri || matches!((loopback_without_port(r), loopback_without_port(uri)), (Some(a), Some(b)) if a == b)
    })
}

fn redirect_host(uri: &str) -> &str {
    let rest = uri.split_once("://").map_or(uri, |(_, r)| r);
    &rest[..rest.find(['/', '?']).unwrap_or(rest.len())]
}

/// RFC 8707 resource comparison: case-insensitive scheme/host, no trailing slash.
pub(crate) fn canonical_uri(u: &str) -> String {
    let u = u.trim().trim_end_matches('/');
    match u.split_once("://") {
        Some((s, rest)) => {
            let (auth, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
            format!(
                "{}://{}{}",
                s.to_ascii_lowercase(),
                auth.to_ascii_lowercase(),
                path
            )
        }
        None => u.to_string(),
    }
}

// ------------------------------------------------------------- clients

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Client {
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub client_id_issued_at: u64,
    /// SHA-256 hex of the client secret (confidential clients only); never
    /// sent back, the secret itself is returned once at registration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret_sha256: Option<String>,
}

/// Unknown fields (scope, logo_uri, contacts, ...) are ignored.
#[derive(Deserialize, Default)]
struct RegistrationRequest {
    redirect_uris: Option<Vec<String>>,
    client_name: Option<String>,
    grant_types: Option<Vec<String>>,
    response_types: Option<Vec<String>>,
    token_endpoint_auth_method: Option<String>,
}

#[derive(Debug, PartialEq)]
pub struct OAuthError {
    pub status: StatusCode,
    pub error: &'static str,
    pub description: String,
}

fn oerr(status: StatusCode, error: &'static str, description: impl Into<String>) -> OAuthError {
    OAuthError {
        status,
        error,
        description: description.into(),
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let body = json!({"error": self.error, "error_description": self.description});
        (self.status, no_store(), axum::Json(body)).into_response()
    }
}

fn no_store() -> [(header::HeaderName, &'static str); 2] {
    [
        (header::CACHE_CONTROL, "no-store"),
        (header::PRAGMA, "no-cache"),
    ]
}

/// RFC 7591 validation; returns the client and, for confidential clients,
/// the client secret in clear (only its digest is kept). `none` (also when the
/// method is omitted, which Claude Code does) registers a public client;
/// `client_secret_post` / `client_secret_basic` get a secret. PKCE is
/// required for all.
fn validate_registration(
    body: &[u8],
    patterns: &[String],
    now: u64,
) -> Result<(Client, Option<String>), OAuthError> {
    let bad = |what: &'static str, d: String| oerr(StatusCode::BAD_REQUEST, what, d);
    let r: RegistrationRequest = serde_json::from_slice(body)
        .map_err(|e| bad("invalid_client_metadata", format!("bad JSON: {e}")))?;
    let uris = r.redirect_uris.unwrap_or_default();
    if uris.is_empty() || uris.len() > 8 {
        return Err(bad(
            "invalid_redirect_uri",
            "1 to 8 redirect_uris required".into(),
        ));
    }
    for u in &uris {
        if u.len() > 512 || !patterns.iter().any(|p| pattern_matches(p, u)) {
            return Err(bad(
                "invalid_redirect_uri",
                format!("redirect URI not allowed: {u}"),
            ));
        }
    }
    let grant_types = r
        .grant_types
        .unwrap_or_else(|| vec!["authorization_code".into(), "refresh_token".into()]);
    if grant_types.is_empty()
        || grant_types
            .iter()
            .any(|g| g != "authorization_code" && g != "refresh_token")
    {
        return Err(bad(
            "invalid_client_metadata",
            "grant_types: only authorization_code, refresh_token".into(),
        ));
    }
    let response_types = r.response_types.unwrap_or_else(|| vec!["code".into()]);
    if response_types != ["code"] {
        return Err(bad(
            "invalid_client_metadata",
            "response_types: only code".into(),
        ));
    }
    let auth_method = r
        .token_endpoint_auth_method
        .unwrap_or_else(|| "none".into());
    if !matches!(
        auth_method.as_str(),
        "none" | "client_secret_post" | "client_secret_basic"
    ) {
        return Err(bad(
            "invalid_client_metadata",
            format!("unsupported token_endpoint_auth_method {auth_method}"),
        ));
    }
    let secret = (auth_method != "none").then(|| random_token(32));
    let client_name = r
        .client_name
        .map(|n| {
            n.chars()
                .filter(|c| !c.is_control())
                .take(100)
                .collect::<String>()
                .trim()
                .to_string()
        })
        .filter(|n| !n.is_empty());
    let client = Client {
        client_id: random_token(16),
        client_name,
        redirect_uris: uris,
        grant_types,
        response_types,
        token_endpoint_auth_method: auth_method,
        client_id_issued_at: now,
        client_secret_sha256: secret.as_deref().map(digest),
    };
    Ok((client, secret))
}

/// RFC 7591 section 3.2.1 response: the registered metadata, plus
/// `client_secret` (and `client_secret_expires_at: 0`, never) if issued.
fn registration_response(c: &Client, secret: Option<&str>) -> serde_json::Value {
    let mut v = serde_json::to_value(c).expect("serialize client");
    if let Some(m) = v.as_object_mut() {
        m.remove("client_secret_sha256");
        if let Some(s) = secret {
            m.insert("client_secret".into(), json!(s));
            m.insert("client_secret_expires_at".into(), json!(0));
        }
    }
    v
}

/// Constant-time check of a presented client secret against its digest.
fn secret_ok(secret: &str, sha256_hex: &str) -> bool {
    let d = digest(secret);
    d.len() == sha256_hex.len() && bool::from(d.as_bytes().ct_eq(sha256_hex.as_bytes()))
}

// -------------------------------------------------------------- tokens

/// One authorization (code exchange) and all its refresh rotations.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Family {
    id: String,
    client_id: String,
    scope: String,
    resource: String,
    created: u64,
    /// SHA-256 hex of the live access token.
    access: String,
    access_exp: u64,
    /// SHA-256 hex of the live refresh token.
    refresh: String,
    refresh_exp: u64,
    /// SHA-256 hex of rotated-out refresh tokens (reuse detection).
    retired: Vec<String>,
}

#[derive(Debug, PartialEq)]
pub struct Issued {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub scope: String,
    pub family: String,
}

#[derive(Debug, PartialEq)]
pub enum RefreshError {
    Invalid,
    /// A rotated-out refresh token was presented: the whole family is revoked.
    Reused,
}

#[derive(Debug, PartialEq)]
enum Access {
    Valid(Grant),
    /// Issued here but expired or bound to another resource.
    Stale,
    Unknown,
}

#[derive(Default)]
struct TokenStore {
    fams: HashMap<String, Family>,
    by_access: HashMap<String, String>,
    by_refresh: HashMap<String, String>,
    by_retired: HashMap<String, String>,
}

impl TokenStore {
    fn from_families(v: Vec<Family>) -> Self {
        let mut s = Self::default();
        for f in v {
            s.insert(f);
        }
        s
    }

    fn families(&self) -> Vec<Family> {
        let mut v: Vec<Family> = self.fams.values().cloned().collect();
        v.sort_by(|a, b| a.created.cmp(&b.created).then_with(|| a.id.cmp(&b.id)));
        v
    }

    fn insert(&mut self, f: Family) {
        self.by_access.insert(f.access.clone(), f.id.clone());
        self.by_refresh.insert(f.refresh.clone(), f.id.clone());
        for r in &f.retired {
            self.by_retired.insert(r.clone(), f.id.clone());
        }
        self.fams.insert(f.id.clone(), f);
    }

    fn remove(&mut self, id: &str) -> Option<Family> {
        let f = self.fams.remove(id)?;
        self.by_access.remove(&f.access);
        self.by_refresh.remove(&f.refresh);
        for r in &f.retired {
            self.by_retired.remove(r);
        }
        Some(f)
    }

    fn prune(&mut self, now: u64) {
        let dead: Vec<String> = self
            .fams
            .values()
            .filter(|f| f.refresh_exp <= now)
            .map(|f| f.id.clone())
            .collect();
        for id in dead {
            self.remove(&id);
        }
        while self.fams.len() >= MAX_FAMILIES {
            let oldest = self
                .fams
                .values()
                .min_by_key(|f| f.created)
                .map(|f| f.id.clone());
            match oldest {
                Some(id) => self.remove(&id),
                None => break,
            };
        }
    }

    fn issue(&mut self, client_id: &str, scope: &str, resource: &str, now: u64) -> Issued {
        self.prune(now);
        let (access, refresh) = (random_token(32), random_token(32));
        let f = Family {
            id: random_token(12),
            client_id: client_id.into(),
            scope: scope.into(),
            resource: resource.into(),
            created: now,
            access: digest(&access),
            access_exp: now + ACCESS_TTL,
            refresh: digest(&refresh),
            refresh_exp: now + REFRESH_TTL,
            retired: Vec::new(),
        };
        let issued = Issued {
            access_token: access,
            refresh_token: refresh,
            expires_in: ACCESS_TTL,
            scope: scope.into(),
            family: f.id.clone(),
        };
        self.insert(f);
        issued
    }

    /// Grant for a live access token bound to `resource`.
    #[cfg(test)]
    fn access(&self, token: &str, resource: &str, now: u64) -> Option<Grant> {
        match self.lookup(token, resource, now) {
            Access::Valid(g) => Some(g),
            _ => None,
        }
    }

    /// Like [`Self::access`], but tells a token we issued (expired, or for
    /// another resource) from one we never issued.
    fn lookup(&self, token: &str, resource: &str, now: u64) -> Access {
        let Some(f) = self
            .by_access
            .get(&digest(token))
            .and_then(|id| self.fams.get(id))
        else {
            return Access::Unknown;
        };
        if f.access_exp > now && f.resource == resource {
            Access::Valid(Grant {
                client_id: f.client_id.clone(),
                scope: f.scope.clone(),
            })
        } else {
            Access::Stale
        }
    }

    /// Rotate: new access + refresh token, the presented one is retired.
    fn refresh(&mut self, token: &str, client_id: &str, now: u64) -> Result<Issued, RefreshError> {
        let h = digest(token);
        if let Some(id) = self.by_retired.get(&h).cloned() {
            eprintln!("oauth: refresh token reuse, revoking family {id}");
            self.remove(&id);
            return Err(RefreshError::Reused);
        }
        let id = self
            .by_refresh
            .get(&h)
            .cloned()
            .ok_or(RefreshError::Invalid)?;
        let mut f = self.remove(&id).ok_or(RefreshError::Invalid)?;
        if f.refresh_exp <= now || f.client_id != client_id {
            if f.refresh_exp > now {
                self.insert(f);
            }
            return Err(RefreshError::Invalid);
        }
        let (access, refresh) = (random_token(32), random_token(32));
        f.retired
            .push(std::mem::replace(&mut f.refresh, digest(&refresh)));
        if f.retired.len() > MAX_RETIRED {
            f.retired.remove(0);
        }
        f.access = digest(&access);
        f.access_exp = now + ACCESS_TTL;
        f.refresh_exp = now + REFRESH_TTL;
        let issued = Issued {
            access_token: access,
            refresh_token: refresh,
            expires_in: ACCESS_TTL,
            scope: f.scope.clone(),
            family: f.id.clone(),
        };
        self.insert(f);
        Ok(issued)
    }

    /// RFC 7009: revoking any token of a family revokes the family.
    fn revoke(&mut self, token: &str) -> bool {
        let h = digest(token);
        let id = self
            .by_access
            .get(&h)
            .or_else(|| self.by_refresh.get(&h))
            .or_else(|| self.by_retired.get(&h))
            .cloned();
        id.and_then(|id| self.remove(&id)).is_some()
    }

    fn has_client(&self, client_id: &str) -> bool {
        self.fams.values().any(|f| f.client_id == client_id)
    }
}

// ---------------------------------------------------------- persistence

/// Atomic write: temp file (mode 600) + fsync + rename + directory fsync.
fn write_atomic(dir: &Path, name: &str, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = dir.join(format!(".{name}.tmp"));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, dir.join(name))?;
    std::fs::File::open(dir)?.sync_all()
}

fn read_json<T: for<'de> Deserialize<'de> + Default>(dir: &Path, name: &str) -> Result<T, String> {
    match std::fs::read(dir.join(name)) {
        Ok(b) => {
            serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", dir.join(name).display()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(format!("{}: {e}", dir.join(name).display())),
    }
}

#[derive(Serialize, Deserialize, Default)]
struct ClientsFile {
    clients: Vec<Client>,
}

#[derive(Serialize, Deserialize, Default)]
struct TokensFile {
    families: Vec<Family>,
}

// --------------------------------------------------------------- state

#[derive(Clone)]
struct PendingAuth {
    client_id: String,
    redirect_uri: String,
    /// Whether redirect_uri was sent explicitly (then the token request must repeat it).
    redirect_explicit: bool,
    code_challenge: String,
    state: Option<String>,
    scope: String,
    exp: u64,
}

struct Inner {
    cfg: Config,
    resource: String,
    cimd: Cimd,
    password: Arc<OwnerPassword>,
    /// See [`OAuth::with_dcr_grace`].
    dcr_grace: AtomicBool,
    st: Mutex<St>,
}

struct St {
    clients: HashMap<String, Client>,
    tokens: TokenStore,
    /// Login tickets (digest -> request), issued after a correct password.
    tickets: HashMap<String, PendingAuth>,
    /// Authorization codes (digest -> request).
    codes: HashMap<String, PendingAuth>,
    /// Redeemed codes (digest -> (family, expiry)): a replay revokes the family.
    used_codes: HashMap<String, (String, u64)>,
    /// `client_id jti` of accepted client assertions -> expiry (replay guard).
    used_jtis: HashMap<String, u64>,
}

/// The authorization server: cheap to clone (shared state).
#[derive(Clone)]
pub struct OAuth(Arc<Inner>);

impl OAuth {
    /// Validate `cfg`, create the state directory (mode 700) if needed and
    /// load the persisted clients and tokens.
    pub fn new(cfg: Config) -> Result<Self, String> {
        let cimd = Cimd::new(cfg.redirect_patterns.clone())?;
        Self::with_cimd(cfg, cimd)
    }

    pub(crate) fn with_cimd(mut cfg: Config, cimd: Cimd) -> Result<Self, String> {
        cfg.issuer = cfg.issuer.trim_end_matches('/').to_string();
        let local = ["http://localhost", "http://127.0.0.1"]
            .iter()
            .any(|p| cfg.issuer.starts_with(p));
        if !cfg.issuer.starts_with("https://") && !local {
            return Err(format!(
                "OAuth issuer must be an https:// origin, got {}",
                cfg.issuer
            ));
        }
        if cfg
            .issuer
            .split_once("://")
            .is_some_and(|(_, rest)| rest.contains(['/', '?', '#']))
        {
            return Err(format!(
                "OAuth issuer must be an origin without a path, got {}",
                cfg.issuer
            ));
        }
        if !cfg.mcp_path.starts_with('/') {
            return Err(format!("mcp_path must start with /, got {}", cfg.mcp_path));
        }
        let password = Arc::new(OwnerPassword::new(
            &cfg.owner_password_hash,
            DEFAULT_MAX_PASSWORD_CHECKS,
        )?);
        if cfg.redirect_patterns.is_empty() {
            return Err("no redirect URI patterns".into());
        }
        for p in &cfg.redirect_patterns {
            check_pattern(p)?;
        }
        for u in cfg.cimd_allowlist.iter().flatten() {
            crate::cimd::check_url(u)?;
        }

        if !cfg.state_dir.is_dir() {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&cfg.state_dir)
                .map_err(|e| format!("{}: {e}", cfg.state_dir.display()))?;
        }
        let clients: ClientsFile = read_json(&cfg.state_dir, CLIENTS_FILE)?;
        let tokens: TokensFile = read_json(&cfg.state_dir, TOKENS_FILE)?;
        let mut tokens = TokenStore::from_families(tokens.families);
        tokens.prune(unix_now());
        if let Some(l) = &cfg.cimd_allowlist {
            let outside = tokens
                .fams
                .values()
                .filter(|f| !l.contains(&f.client_id))
                .count();
            eprintln!(
                "oauth: dynamic client registration closed ({} allowlisted client_id URLs); \
                 {outside} token families of other clients kept until their refresh \
                 tokens expire, unless dcr_grace is turned off",
                l.len(),
            );
        }
        let resource = format!("{}{}", cfg.issuer, cfg.mcp_path);
        let st = St {
            clients: clients
                .clients
                .into_iter()
                .map(|c| (c.client_id.clone(), c))
                .collect(),
            tokens,
            tickets: HashMap::new(),
            codes: HashMap::new(),
            used_codes: HashMap::new(),
            used_jtis: HashMap::new(),
        };
        Ok(Self(Arc::new(Inner {
            cfg,
            resource,
            cimd,
            password,
            dcr_grace: AtomicBool::new(true),
            st: Mutex::new(st),
        })))
    }

    /// Only matters with a [`Config::cimd_allowlist`]. `true` (the default):
    /// token families issued before the allowlist to clients outside it
    /// (DCR clients) keep working, access tokens validate and refresh tokens
    /// rotate, until their refresh token expires; nothing breaks for
    /// connections that already exist. `false`: those clients are cut off at
    /// once (their access tokens are rejected, refresh is refused). Either
    /// way they cannot start a new authorization.
    pub fn with_dcr_grace(self, grace: bool) -> Self {
        self.0.dcr_grace.store(grace, Ordering::Relaxed);
        if !grace && let Some(l) = &self.0.cfg.cimd_allowlist {
            let outside = self
                .lock()
                .tokens
                .fams
                .values()
                .filter(|f| !l.contains(&f.client_id))
                .count();
            eprintln!(
                "oauth: dcr_grace off: {outside} token families of clients outside the \
                 allowlist are no longer honoured"
            );
        }
        self
    }

    /// See [`Self::with_dcr_grace`].
    pub fn dcr_grace(&self) -> bool {
        self.0.dcr_grace.load(Ordering::Relaxed)
    }

    /// At most `n` owner password checks run at once (default
    /// [`DEFAULT_MAX_PASSWORD_CHECKS`], minimum 1); a sign-in beyond that is
    /// answered at once with 503 and `Retry-After`, without checking the
    /// password. Each check holds one argon2 working buffer (`m` KiB of the
    /// owner password hash, 19 MiB for [`hash_password`]), allocated on first
    /// use and kept for the next check: the password checks never take more
    /// than `n` x `m` KiB.
    pub fn with_max_password_checks(self, n: usize) -> Self {
        self.0.password.set_max(n);
        self
    }

    /// Owner password checks allowed at once (see [`Self::with_max_password_checks`]).
    pub fn max_password_checks(&self) -> usize {
        self.0.password.max()
    }

    /// Tests: an instance whose CIMD documents come from memory.
    #[cfg(test)]
    pub(crate) fn new_for_tests(cfg: Config) -> Result<Self, String> {
        let cimd = Cimd::new_static(cfg.redirect_patterns.clone());
        Self::with_cimd(cfg, cimd)
    }

    #[cfg(test)]
    pub(crate) fn cimd(&self) -> &Cimd {
        &self.0.cimd
    }

    #[cfg(test)]
    pub(crate) fn password_pool(&self) -> &Arc<OwnerPassword> {
        &self.0.password
    }

    /// Whether Dynamic Client Registration is open (no CIMD allowlist).
    pub fn dcr_enabled(&self) -> bool {
        self.0.cfg.cimd_allowlist.is_none()
    }

    fn cimd_allowed(&self, client_id: &str) -> bool {
        match &self.0.cfg.cimd_allowlist {
            None => true,
            Some(l) => l.iter().any(|u| u == client_id),
        }
    }

    /// Whether tokens already issued to `client_id` are honoured (bearer
    /// check and refresh): always without an allowlist or with
    /// [`Self::with_dcr_grace`], otherwise only for allowlisted clients.
    fn tokens_honoured(&self, client_id: &str) -> bool {
        self.dcr_grace() || self.cimd_allowed(client_id)
    }

    /// Bearer lookup, with the allowlist applied to the token's client.
    fn lookup(&self, token: &str) -> Access {
        match self
            .lock()
            .tokens
            .lookup(token, &self.0.resource, unix_now())
        {
            Access::Valid(g) if !self.tokens_honoured(&g.client_id) => Access::Stale,
            a => a,
        }
    }

    /// The protected resource (MCP endpoint URL), e.g. `https://host/mcp`.
    pub fn resource(&self) -> &str {
        &self.0.resource
    }

    pub fn resource_metadata_url(&self) -> String {
        format!("{}/.well-known/oauth-protected-resource", self.0.cfg.issuer)
    }

    /// Grant for a bearer access token, if valid for this resource now.
    pub fn validate(&self, token: &str) -> Option<Grant> {
        match self.lookup(token) {
            Access::Valid(g) => Some(g),
            _ => None,
        }
    }

    /// Layer for the protected route(s): a valid bearer token (issued here,
    /// for this resource, unexpired) puts a [`Grant`] in the request
    /// extensions; otherwise `401` with `WWW-Authenticate: Bearer
    /// resource_metadata="..."` (RFC 9728 section 5.1). A bearer token we
    /// never issued counts as an authentication failure (see
    /// [`crate::protect`]); an expired one does not.
    pub fn bearer_layer(&self) -> BearerLayer {
        BearerLayer(self.clone())
    }

    /// The bearer check of [`BearerLayer`].
    fn authenticate(&self, h: &HeaderMap) -> Result<Grant, BearerRejection> {
        let found = bearer(h).map(|t| self.lookup(t));
        match found {
            Some(Access::Valid(g)) => Ok(g),
            Some(Access::Unknown) => Err(BearerRejection {
                invalid: true,
                count: true,
            }),
            Some(Access::Stale) => Err(BearerRejection {
                invalid: true,
                count: false,
            }),
            None => Err(BearerRejection {
                invalid: false,
                count: false,
            }),
        }
    }

    /// 401 with the RFC 9728 challenge.
    fn unauthorized(&self, invalid: bool) -> Response {
        let meta = self.resource_metadata_url();
        let v = if invalid {
            format!(r#"Bearer error="invalid_token", resource_metadata="{meta}""#)
        } else {
            format!(r#"Bearer resource_metadata="{meta}""#)
        };
        let hv = HeaderValue::from_str(&v).unwrap_or(HeaderValue::from_static("Bearer"));
        (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, hv)],
            "unauthorized",
        )
            .into_response()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, St> {
        self.0.st.lock().expect("oauth state lock")
    }

    fn save_clients(&self, st: &St) {
        let mut clients: Vec<Client> = st.clients.values().cloned().collect();
        clients.sort_by(|a, b| {
            a.client_id_issued_at
                .cmp(&b.client_id_issued_at)
                .then_with(|| a.client_id.cmp(&b.client_id))
        });
        let data = serde_json::to_vec(&ClientsFile { clients }).expect("serialize clients");
        if let Err(e) = write_atomic(&self.0.cfg.state_dir, CLIENTS_FILE, &data) {
            eprintln!("oauth: cannot persist clients: {e}");
        }
    }

    fn save_tokens(&self, st: &St) {
        let data = serde_json::to_vec(&TokensFile {
            families: st.tokens.families(),
        })
        .expect("serialize tokens");
        if let Err(e) = write_atomic(&self.0.cfg.state_dir, TOKENS_FILE, &data) {
            eprintln!("oauth: cannot persist tokens: {e}");
        }
    }

    fn resource_ok(&self, r: Option<&str>) -> bool {
        r.is_none_or(|r| {
            let c = canonical_uri(r);
            c == canonical_uri(&self.0.resource) || c == canonical_uri(&self.0.cfg.issuer)
        })
    }

    /// Axum router: well-known metadata and the `/oauth/*` endpoints.
    pub fn router(&self) -> Router {
        let prm_alias = format!(
            "/.well-known/oauth-protected-resource{}",
            self.0.cfg.mcp_path
        );
        Router::new()
            .route(
                "/.well-known/oauth-protected-resource",
                get(protected_resource_metadata),
            )
            .route(&prm_alias, get(protected_resource_metadata))
            .route(
                "/.well-known/oauth-authorization-server",
                get(authorization_server_metadata),
            )
            .route("/oauth/register", post(register))
            .route("/oauth/authorize", get(authorize_get).post(authorize_post))
            .route("/oauth/token", post(token))
            .route("/oauth/revoke", post(revoke))
            .with_state(self.clone())
    }

    fn prm_json(&self) -> serde_json::Value {
        json!({
            "resource": self.0.resource,
            "authorization_servers": [self.0.cfg.issuer],
            "scopes_supported": [SCOPE],
            "bearer_methods_supported": ["header"],
            "resource_name": self.0.cfg.resource_name,
        })
    }

    fn token_endpoint(&self) -> String {
        format!("{}/oauth/token", self.0.cfg.issuer)
    }

    fn asm_json(&self) -> serde_json::Value {
        let i = &self.0.cfg.issuer;
        let methods: &[&str] = if self.dcr_enabled() {
            &[
                "none",
                "client_secret_post",
                "client_secret_basic",
                "private_key_jwt",
            ]
        } else {
            &["none", "private_key_jwt"]
        };
        let mut m = json!({
            "issuer": i,
            "authorization_endpoint": format!("{i}/oauth/authorize"),
            "token_endpoint": self.token_endpoint(),
            "revocation_endpoint": format!("{i}/oauth/revoke"),
            "scopes_supported": [SCOPE],
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": methods,
            "token_endpoint_auth_signing_alg_values_supported": jwt::ALGS,
            "revocation_endpoint_auth_methods_supported": ["none"],
            "authorization_response_iss_parameter_supported": true,
            "client_id_metadata_document_supported": true,
        });
        if self.dcr_enabled() {
            m["registration_endpoint"] = json!(format!("{i}/oauth/register"));
        }
        m
    }
}

// ------------------------------------------------------ resource guard

/// Why the bearer check failed.
struct BearerRejection {
    /// A token was presented (`error="invalid_token"`).
    invalid: bool,
    /// Count it as an authentication failure (a token we never issued).
    count: bool,
}

/// Tower layer from [`OAuth::bearer_layer`].
#[derive(Clone)]
pub struct BearerLayer(OAuth);

impl<S> tower::Layer<S> for BearerLayer {
    type Service = BearerService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        BearerService {
            oauth: self.0.clone(),
            inner,
        }
    }
}

/// Service of [`BearerLayer`].
#[derive(Clone)]
pub struct BearerService<S> {
    oauth: OAuth,
    inner: S,
}

impl<S, B> tower::Service<Request<B>> for BearerService<S>
where
    S: tower::Service<Request<B>, Response = Response> + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        match self.oauth.authenticate(req.headers()) {
            Ok(grant) => {
                req.extensions_mut().insert(grant);
                Box::pin(self.inner.call(req))
            }
            Err(r) => {
                if r.count
                    && let Some(f) = req.extensions().get::<AuthFailures>()
                {
                    f.record("bearer token");
                }
                let resp = self.oauth.unauthorized(r.invalid);
                Box::pin(async move { Ok(resp) })
            }
        }
    }
}

fn bearer(h: &HeaderMap) -> Option<&str> {
    let v = h.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, tok) = v.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| tok.trim())
        .filter(|t| !t.is_empty())
}

// ----------------------------------------------------------- endpoints

async fn protected_resource_metadata(State(o): State<OAuth>) -> Response {
    axum::Json(o.prm_json()).into_response()
}

async fn authorization_server_metadata(State(o): State<OAuth>) -> Response {
    axum::Json(o.asm_json()).into_response()
}

async fn register(State(o): State<OAuth>, body: Bytes) -> Response {
    if !o.dcr_enabled() {
        return oerr(
            StatusCode::FORBIDDEN,
            "access_denied",
            "dynamic client registration is disabled; use a Client ID Metadata Document",
        )
        .into_response();
    }
    let now = unix_now();
    let (c, secret) = match validate_registration(&body, &o.0.cfg.redirect_patterns, now) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let mut st = o.lock();
    if st.clients.len() >= MAX_CLIENTS {
        // Evict the oldest client that holds no tokens.
        let victim = st
            .clients
            .values()
            .filter(|c| !st.tokens.has_client(&c.client_id))
            .min_by_key(|c| c.client_id_issued_at)
            .map(|c| c.client_id.clone());
        match victim {
            Some(id) => {
                st.clients.remove(&id);
            }
            None => {
                return oerr(
                    StatusCode::BAD_REQUEST,
                    "invalid_client_metadata",
                    "too many registered clients",
                )
                .into_response();
            }
        }
    }
    st.clients.insert(c.client_id.clone(), c.clone());
    o.save_clients(&st);
    drop(st);
    eprintln!(
        "oauth: registered client {} ({}, {}, {})",
        c.client_id,
        c.client_name.as_deref().unwrap_or("unnamed"),
        c.token_endpoint_auth_method,
        c.redirect_uris.join(" ")
    );
    (
        StatusCode::CREATED,
        no_store(),
        axum::Json(registration_response(&c, secret.as_deref())),
    )
        .into_response()
}

#[derive(Deserialize, Default, Clone)]
struct AuthzParams {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    scope: Option<String>,
    resource: Option<String>,
}

#[derive(Deserialize, Default)]
struct AuthzForm {
    #[serde(flatten)]
    p: AuthzParams,
    step: Option<String>,
    password: Option<String>,
    ticket: Option<String>,
    decision: Option<String>,
}

/// Outcome of validating an authorization request.
enum Checked {
    /// Show the error to the user; never redirect to an unverified URI.
    Page(StatusCode, String),
    /// Redirect back to the client with an OAuth error.
    Redirect(Response),
    Ok(PendingAuth, ClientLabel),
}

/// Who asks, for the login and consent pages.
#[derive(Clone, Debug, Default)]
struct ClientLabel {
    name: Option<String>,
    /// Host of the `client_id` URL for CIMD clients (the self-asserted name
    /// alone is not enough to know who asks).
    cimd_host: Option<String>,
}

/// A client as the authorization endpoint sees it (DCR or CIMD).
struct ClientInfo {
    client_id: String,
    redirect_uris: Vec<String>,
    label: ClientLabel,
}

const UNKNOWN_CLIENT: &str = "Unknown client. Remove the connector and add it again.";
const DCR_CLOSED: &str =
    "This client registration is no longer accepted. Remove the connector and add it again.";

impl OAuth {
    /// A registered (DCR) client, or a Client ID Metadata Document when the
    /// `client_id` is an https URL; `Err` is the message for the error page.
    async fn client_info(&self, id: Option<&str>) -> Result<ClientInfo, String> {
        let Some(id) = id else {
            return Err(UNKNOWN_CLIENT.into());
        };
        if let Some(c) = self.lock().clients.get(id) {
            if !self.dcr_enabled() {
                eprintln!(
                    "oauth: client_id {id} was registered by DCR, which is closed; \
                     new authorizations need an allowlisted client_id"
                );
                return Err(DCR_CLOSED.into());
            }
            return Ok(ClientInfo {
                client_id: c.client_id.clone(),
                redirect_uris: c.redirect_uris.clone(),
                label: ClientLabel {
                    name: c.client_name.clone(),
                    cimd_host: None,
                },
            });
        }
        if !id.starts_with("https://") {
            return Err(UNKNOWN_CLIENT.into());
        }
        if !self.cimd_allowed(id) {
            eprintln!("oauth: client_id {id} is not in the CIMD allowlist");
            return Err("This client is not allowed on this server.".into());
        }
        match self.0.cimd.get(id).await {
            Ok(d) => Ok(ClientInfo {
                client_id: d.client_id.clone(),
                redirect_uris: d.redirect_uris.clone(),
                label: ClientLabel {
                    name: d.client_name.clone(),
                    cimd_host: Some(redirect_host(id).to_string()),
                },
            }),
            Err(e) => {
                eprintln!("oauth: client metadata {id}: {e}");
                Err(format!("Cannot use this client's metadata document: {e}"))
            }
        }
    }

    async fn check_authz(&self, p: &AuthzParams, now: u64) -> Checked {
        let c = match self.client_info(p.client_id.as_deref()).await {
            Ok(c) => c,
            Err(m) => return Checked::Page(StatusCode::BAD_REQUEST, m),
        };
        let explicit = p.redirect_uri.is_some();
        let redirect = match p.redirect_uri.as_deref() {
            Some(r) => r.to_string(),
            None if c.redirect_uris.len() == 1 => c.redirect_uris[0].clone(),
            None => return Checked::Page(StatusCode::BAD_REQUEST, "Missing redirect_uri.".into()),
        };
        if !redirect_registered(&c.redirect_uris, &redirect) {
            return Checked::Page(
                StatusCode::BAD_REQUEST,
                "This redirect URI is not registered for the client.".into(),
            );
        }
        let label = c.label;
        let client_id = c.client_id;
        let fail = |error: &str, d: &str| {
            Checked::Redirect(self.redirect(
                &redirect,
                &[("error", error), ("error_description", d)],
                p.state.as_deref(),
            ))
        };
        if p.response_type.as_deref() != Some("code") {
            return fail("unsupported_response_type", "only response_type=code");
        }
        let challenge = p.code_challenge.clone().unwrap_or_default();
        if p.code_challenge_method.as_deref() != Some("S256") || !valid_pkce_string(&challenge) {
            return fail(
                "invalid_request",
                "PKCE with code_challenge_method=S256 is required",
            );
        }
        if !self.resource_ok(p.resource.as_deref()) {
            return fail("invalid_target", "unknown resource");
        }
        let pending = PendingAuth {
            client_id,
            redirect_uri: redirect,
            redirect_explicit: explicit,
            code_challenge: challenge,
            state: p.state.clone(),
            scope: SCOPE.into(),
            exp: now,
        };
        Checked::Ok(pending, label)
    }

    /// 303 to the client's redirect URI with `params`, `state` and `iss` (RFC 9207).
    fn redirect(&self, uri: &str, params: &[(&str, &str)], state: Option<&str>) -> Response {
        let mut q: Vec<(&str, &str)> = params.to_vec();
        if let Some(s) = state {
            q.push(("state", s));
        }
        q.push(("iss", &self.0.cfg.issuer));
        let qs = serde_urlencoded::to_string(&q).unwrap_or_default();
        let sep = if uri.contains('?') { '&' } else { '?' };
        let loc = format!("{uri}{sep}{qs}");
        match HeaderValue::from_str(&loc) {
            Ok(v) => (
                StatusCode::SEE_OTHER,
                [(header::LOCATION, v)],
                [(header::CACHE_CONTROL, "no-store")],
            )
                .into_response(),
            Err(_) => html(
                StatusCode::BAD_REQUEST,
                &page("Error", "<p>Invalid redirect URI.</p>"),
            ),
        }
    }
}

async fn authorize_get(State(o): State<OAuth>, RawQuery(q): RawQuery) -> Response {
    let p: AuthzParams = match serde_urlencoded::from_str(q.as_deref().unwrap_or("")) {
        Ok(p) => p,
        Err(e) => {
            return error_page(
                StatusCode::BAD_REQUEST,
                &format!("Malformed authorization request: {e}"),
            );
        }
    };
    match o.check_authz(&p, unix_now()).await {
        Checked::Page(s, m) => error_page(s, &m),
        Checked::Redirect(r) => r,
        Checked::Ok(pending, label) => {
            html(StatusCode::OK, &login_page(&o, &p, &pending, &label, None))
        }
    }
}

/// Count an authentication failure against the client IP (if the app is
/// wrapped in [`crate::protect`]).
fn record_failure(f: &Option<Extension<AuthFailures>>, what: &str) {
    if let Some(Extension(f)) = f {
        f.record(what);
    }
}

const BUSY: &str = "Too many sign-ins in progress, try again in a few seconds.";
const BUSY_RETRY_AFTER: &str = "2";

async fn authorize_post(
    State(o): State<OAuth>,
    failures: Option<Extension<AuthFailures>>,
    body: Bytes,
) -> Response {
    let f: AuthzForm = match serde_urlencoded::from_bytes(&body) {
        Ok(f) => f,
        Err(e) => return error_page(StatusCode::BAD_REQUEST, &format!("Malformed form: {e}")),
    };
    let now = unix_now();
    match f.step.as_deref() {
        Some("login") => {
            let (mut pending, label) = match o.check_authz(&f.p, now).await {
                Checked::Page(s, m) => return error_page(s, &m),
                Checked::Redirect(r) => return r,
                Checked::Ok(p, n) => (p, n),
            };
            // Bounded: at most max_password_checks argon2 runs (19 MiB each)
            // at once; beyond that answer now, without queueing.
            let Some(slot) = o.0.password.try_slot() else {
                eprintln!("oauth: owner password check refused, all slots busy");
                let mut r = html(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &login_page(&o, &f.p, &pending, &label, Some(BUSY)),
                );
                r.headers_mut().insert(
                    header::RETRY_AFTER,
                    HeaderValue::from_static(BUSY_RETRY_AFTER),
                );
                return r;
            };
            let pw = f.password.unwrap_or_default();
            // The slot moves into the blocking task: it is released when
            // argon2 is done, even if this request is cancelled meanwhile.
            let ok = tokio::task::spawn_blocking(move || slot.verify(&pw))
                .await
                .unwrap_or(false);
            if !ok {
                record_failure(&failures, "oauth password");
                return html(
                    StatusCode::UNAUTHORIZED,
                    &login_page(&o, &f.p, &pending, &label, Some("Wrong password.")),
                );
            }
            pending.exp = now + TICKET_TTL;
            let ticket = random_token(32);
            {
                let mut st = o.lock();
                st.tickets.retain(|_, t| t.exp > now);
                if st.tickets.len() >= MAX_PENDING {
                    return error_page(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Too many pending sign-ins, try again later.",
                    );
                }
                st.tickets.insert(digest(&ticket), pending.clone());
            }
            html(StatusCode::OK, &consent_page(&o, &pending, &label, &ticket))
        }
        Some("consent") => {
            let pending = {
                let mut st = o.lock();
                st.tickets
                    .remove(&digest(f.ticket.as_deref().unwrap_or("")))
            };
            let Some(mut pending) = pending.filter(|p| p.exp > now) else {
                return error_page(
                    StatusCode::BAD_REQUEST,
                    "This sign-in has expired. Start again from the client.",
                );
            };
            if f.decision.as_deref() != Some("allow") {
                return o.redirect(
                    &pending.redirect_uri,
                    &[
                        ("error", "access_denied"),
                        ("error_description", "the owner denied access"),
                    ],
                    pending.state.as_deref(),
                );
            }
            pending.exp = now + CODE_TTL;
            let code = random_token(32);
            {
                let mut st = o.lock();
                st.codes.retain(|_, c| c.exp > now);
                st.used_codes.retain(|_, (_, exp)| *exp > now);
                if st.codes.len() >= MAX_PENDING {
                    return error_page(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Too many pending authorizations, try again later.",
                    );
                }
                st.codes.insert(digest(&code), pending.clone());
            }
            eprintln!("oauth: owner authorized client {}", pending.client_id);
            o.redirect(
                &pending.redirect_uri,
                &[("code", &code)],
                pending.state.as_deref(),
            )
        }
        _ => error_page(StatusCode::BAD_REQUEST, "Malformed form."),
    }
}

#[derive(Deserialize, Default)]
struct TokenRequest {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    resource: Option<String>,
    client_assertion: Option<String>,
    client_assertion_type: Option<String>,
}

/// Why a `private_key_jwt` assertion was not accepted.
enum AssertionError {
    /// The client's metadata or keys cannot be fetched right now.
    Unavailable(String),
    /// The client's metadata or key set is unusable (not counted against the IP).
    Unusable(String),
    /// Bad assertion: counted as an authentication failure.
    Rejected(String),
}

impl OAuth {
    /// Token endpoint authentication of a CIMD client: `none` (PKCE only) or
    /// `private_key_jwt`, whichever its document declares and it uses.
    async fn cimd_client_auth(
        &self,
        client_id: &str,
        r: &TokenRequest,
        failures: &Option<Extension<AuthFailures>>,
        now: u64,
    ) -> Result<(), Box<Response>> {
        let invalid =
            |d: &str| Box::new(oerr(StatusCode::UNAUTHORIZED, "invalid_client", d).into_response());
        let unavailable = |e: &str| {
            eprintln!("oauth: client {client_id}: {e}");
            Box::new(
                oerr(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "the client metadata document cannot be fetched now",
                )
                .into_response(),
            )
        };
        if !self.cimd_allowed(client_id) {
            eprintln!("oauth: client_id {client_id} is not in the CIMD allowlist");
            return Err(invalid("client not allowed"));
        }
        let doc = match self.0.cimd.get(client_id).await {
            Ok(d) => d,
            Err(CimdError::Unavailable(e)) => return Err(unavailable(&e)),
            Err(CimdError::Invalid(e)) => {
                eprintln!("oauth: client metadata {client_id}: {e}");
                return Err(invalid(&format!("client metadata: {e}")));
            }
        };
        let Some(assertion) = r.client_assertion.as_deref() else {
            return if doc.allows(AuthMethod::None) {
                Ok(())
            } else {
                Err(invalid("client authentication required (private_key_jwt)"))
            };
        };
        if r.client_assertion_type.as_deref() != Some(jwt::ASSERTION_TYPE) {
            return Err(Box::new(
                oerr(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    format!("client_assertion_type must be {}", jwt::ASSERTION_TYPE),
                )
                .into_response(),
            ));
        }
        if !doc.allows(AuthMethod::PrivateKeyJwt) {
            return Err(invalid(
                "the client metadata does not declare private_key_jwt",
            ));
        }
        match self.verify_assertion(&doc, assertion, now).await {
            Ok(()) => Ok(()),
            Err(AssertionError::Unavailable(e)) => Err(unavailable(&e)),
            Err(AssertionError::Unusable(e)) => {
                eprintln!("oauth: client {client_id}: {e}");
                Err(invalid(&e))
            }
            Err(AssertionError::Rejected(e)) => {
                eprintln!("oauth: client assertion for {client_id} rejected: {e}");
                record_failure(failures, "oauth client assertion");
                Err(invalid("client authentication failed"))
            }
        }
    }

    /// RFC 7523 checks, signature against the document's keys (refetched
    /// once on an unknown `kid`), then single use of the `jti`.
    async fn verify_assertion(
        &self,
        doc: &crate::cimd::ClientDoc,
        assertion: &str,
        now: u64,
    ) -> Result<(), AssertionError> {
        let rejected = |s: &str| AssertionError::Rejected(s.to_string());
        let key_err = |e: CimdError| match e {
            CimdError::Unavailable(s) => AssertionError::Unavailable(s),
            CimdError::Invalid(s) => AssertionError::Unusable(s),
        };
        let a = jwt::parse(assertion).map_err(rejected)?;
        let token_endpoint = self.token_endpoint();
        a.check_claims(
            &doc.client_id,
            &[self.0.cfg.issuer.as_str(), token_endpoint.as_str()],
            now,
        )
        .map_err(rejected)?;
        let keys = self.0.cimd.keys(doc, false).await.map_err(key_err)?;
        match a.verify_signature(&keys) {
            Ok(()) => {}
            Err(jwt::SigError::Invalid(s)) => return Err(rejected(s)),
            Err(jwt::SigError::UnknownKey) => {
                let keys = self.0.cimd.keys(doc, true).await.map_err(key_err)?;
                a.verify_signature(&keys).map_err(|e| match e {
                    jwt::SigError::UnknownKey => rejected("no key with the assertion's kid"),
                    jwt::SigError::Invalid(s) => rejected(s),
                })?;
            }
        }
        // check_claims requires the jti.
        let j = a.claims.jti.as_deref().unwrap_or_default();
        let key = format!("{} {j}", doc.client_id);
        let exp = a.claims.exp.unwrap_or(0.0).max(0.0) as u64 + 60;
        let mut st = self.lock();
        st.used_jtis.retain(|_, e| *e > now);
        if st.used_jtis.contains_key(&key) {
            return Err(rejected("client assertion replayed (jti already used)"));
        }
        if st.used_jtis.len() >= MAX_JTIS {
            return Err(AssertionError::Unavailable(
                "too many recent client assertions".into(),
            ));
        }
        st.used_jtis.insert(key, exp);
        Ok(())
    }
}

/// application/x-www-form-urlencoded decoding of one value (`+` is a space).
fn form_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let h = b.get(i + 1..i + 3)?;
                if !h.iter().all(u8::is_ascii_hexdigit) {
                    return None;
                }
                out.push(u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok()?);
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8(out).ok()
}

/// (client_id, client_secret) from HTTP Basic; RFC 6749 section 2.3.1: both
/// are form-urlencoded before the base64. Public clients may send any secret.
fn basic_credentials(h: &HeaderMap) -> Option<(String, String)> {
    let v = h.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, b) = v.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let dec = base64::engine::general_purpose::STANDARD
        .decode(b.trim())
        .ok()?;
    let s = String::from_utf8(dec).ok()?;
    let (id, secret) = s.split_once(':')?;
    Some((form_decode(id)?, form_decode(secret)?))
}

fn token_response(i: &Issued) -> Response {
    let body = json!({
        "access_token": i.access_token,
        "token_type": "Bearer",
        "expires_in": i.expires_in,
        "refresh_token": i.refresh_token,
        "scope": i.scope,
    });
    (StatusCode::OK, no_store(), axum::Json(body)).into_response()
}

async fn token(
    State(o): State<OAuth>,
    failures: Option<Extension<AuthFailures>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let r: TokenRequest = match serde_urlencoded::from_bytes(&body) {
        Ok(r) => r,
        Err(e) => {
            return oerr(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                format!("bad form: {e}"),
            )
            .into_response();
        }
    };
    let now = unix_now();
    let grant = |d: &str| oerr(StatusCode::BAD_REQUEST, "invalid_grant", d).into_response();
    let basic = basic_credentials(&headers);
    let client_id = match (r.client_id.as_deref(), basic.as_ref()) {
        (Some(a), Some((b, _))) if a != b => {
            return oerr(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "client_id differs from the Authorization header",
            )
            .into_response();
        }
        (Some(a), _) => a.to_string(),
        (None, Some((b, _))) => b.clone(),
        (None, None) => match r
            .client_assertion
            .as_deref()
            .and_then(jwt::unverified_subject)
        {
            Some(sub) => sub,
            None => {
                return oerr(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "client_id required",
                )
                .into_response();
            }
        },
    };
    let registered = o.lock().clients.contains_key(&client_id);
    if !registered {
        if !client_id.starts_with("https://") {
            return oerr(StatusCode::UNAUTHORIZED, "invalid_client", "unknown client")
                .into_response();
        }
        if let Err(resp) = o.cimd_client_auth(&client_id, &r, &failures, now).await {
            return *resp;
        }
    } else if r.client_assertion.is_some() {
        return oerr(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client assertions are only accepted from Client ID Metadata Document clients",
        )
        .into_response();
    }
    // DCR closed (allowlist): a client registered earlier may only refresh
    // the tokens it holds, and only during the grace.
    if registered && !o.dcr_enabled() {
        let refresh = r.grant_type.as_deref() == Some("refresh_token");
        if !(refresh && o.tokens_honoured(&client_id)) {
            eprintln!(
                "oauth: client_id {client_id} was registered by DCR, which is closed; \
                 {} refused",
                r.grant_type.as_deref().unwrap_or("grant")
            );
            return oerr(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "dynamic client registration is closed; use a Client ID Metadata Document",
            )
            .into_response();
        }
    }
    let mut st = o.lock();
    // Registered client (DCR), unless it was evicted meanwhile.
    let dcr = st.clients.get(&client_id);
    if registered && dcr.is_none() {
        return oerr(StatusCode::UNAUTHORIZED, "invalid_client", "unknown client").into_response();
    }
    // Confidential client: the secret from Basic or from the form body
    // (accepted in either place, whichever method was registered).
    if let Some(want) = dcr.and_then(|c| c.client_secret_sha256.as_deref()) {
        let given = [
            basic.as_ref().map(|(_, s)| s.as_str()),
            r.client_secret.as_deref(),
        ];
        if !given.into_iter().flatten().any(|s| secret_ok(s, want)) {
            drop(st);
            record_failure(&failures, "oauth client secret");
            let mut resp = oerr(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "client authentication failed",
            )
            .into_response();
            if basic.is_some() {
                resp.headers_mut().insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static(r#"Basic realm="oauth""#),
                );
            }
            return resp;
        }
    }
    if !o.resource_ok(r.resource.as_deref()) {
        return oerr(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "unknown resource",
        )
        .into_response();
    }
    match r.grant_type.as_deref() {
        Some("authorization_code") => {
            let h = digest(r.code.as_deref().unwrap_or(""));
            let Some(p) = st.codes.remove(&h) else {
                if let Some((fam, _)) = st.used_codes.remove(&h) {
                    eprintln!("oauth: authorization code replay, revoking family {fam}");
                    st.tokens.remove(&fam);
                    o.save_tokens(&st);
                }
                return grant("unknown, expired or used code");
            };
            if p.exp <= now || p.client_id != client_id {
                return grant("unknown, expired or used code");
            }
            match r.redirect_uri.as_deref() {
                Some(u) if u != p.redirect_uri => return grant("redirect_uri mismatch"),
                None if p.redirect_explicit => return grant("redirect_uri required"),
                _ => {}
            }
            if !pkce_s256_ok(r.code_verifier.as_deref().unwrap_or(""), &p.code_challenge) {
                // A live code of this very client with a wrong verifier: the
                // client that asked for the code holds its verifier, so this
                // is someone else with a stolen code. Counted (the code is
                // burnt). Unknown, expired or used codes and unknown clients
                // are not: real clients retry those after restarts.
                drop(st);
                record_failure(&failures, "oauth PKCE verifier");
                return grant("PKCE verification failed");
            }
            let resource = o.0.resource.clone();
            let issued = st.tokens.issue(&client_id, &p.scope, &resource, now);
            st.used_codes.insert(h, (issued.family.clone(), p.exp));
            o.save_tokens(&st);
            token_response(&issued)
        }
        Some("refresh_token") => {
            let res = st
                .tokens
                .refresh(r.refresh_token.as_deref().unwrap_or(""), &client_id, now);
            match res {
                Ok(issued) => {
                    o.save_tokens(&st);
                    token_response(&issued)
                }
                Err(RefreshError::Reused) => {
                    o.save_tokens(&st);
                    grant("refresh token reused; authorization revoked")
                }
                Err(RefreshError::Invalid) => grant("unknown or expired refresh token"),
            }
        }
        _ => oerr(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "authorization_code or refresh_token",
        )
        .into_response(),
    }
}

#[derive(Deserialize)]
struct RevokeRequest {
    token: Option<String>,
}

async fn revoke(State(o): State<OAuth>, body: Bytes) -> Response {
    let Ok(RevokeRequest { token: Some(t) }) = serde_urlencoded::from_bytes(&body) else {
        return oerr(StatusCode::BAD_REQUEST, "invalid_request", "token required").into_response();
    };
    let mut st = o.lock();
    if st.tokens.revoke(&t) {
        o.save_tokens(&st);
    }
    (StatusCode::OK, no_store()).into_response()
}

// ---------------------------------------------------------------- HTML

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

const CSS: &str = "body{font:16px/1.5 system-ui,sans-serif;background:#f4f4f5;color:#18181b;margin:0;\
display:flex;min-height:100vh;align-items:center;justify-content:center}\
main{background:#fff;border-radius:12px;box-shadow:0 2px 12px #0002;padding:2rem;max-width:26rem;width:90%}\
h1{font-size:1.3rem;margin:0 0 1rem}code{background:#f4f4f5;padding:.1rem .3rem;border-radius:4px}\
label{display:block;margin:1rem 0 .3rem}input[type=password]{width:100%;box-sizing:border-box;padding:.6rem;\
font-size:1rem;border:1px solid #d4d4d8;border-radius:8px}button{margin-top:1rem;padding:.6rem 1.2rem;font-size:1rem;\
border:0;border-radius:8px;background:#18181b;color:#fff;cursor:pointer}button.secondary{background:#e4e4e7;color:#18181b}\
.err{color:#b91c1c}.warn{color:#92400e;background:#fef3c7;padding:.5rem;border-radius:8px}";

fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"data:,\">\
<title>{}</title><style>{CSS}</style></head><body><main>{body}</main></body></html>",
        esc(title)
    )
}

fn html(status: StatusCode, body: &str) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::X_FRAME_OPTIONS, "DENY"),
            (header::REFERRER_POLICY, "no-referrer"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'none'; base-uri 'none'",
            ),
        ],
        body.to_string(),
    )
        .into_response()
}

fn error_page(status: StatusCode, msg: &str) -> Response {
    html(
        status,
        &page(
            "Authorization error",
            &format!(
                "<h1>Authorization error</h1><p class=\"err\">{}</p>",
                esc(msg)
            ),
        ),
    )
}

/// `<b>name</b>`, plus the `client_id` host for CIMD clients.
fn client_label(l: &ClientLabel, client_id: &str) -> String {
    match (l.name.as_deref(), l.cimd_host.as_deref()) {
        (Some(n), None) => format!("<b>{}</b>", esc(n)),
        (None, None) => format!("<b>Unnamed client <code>{}</code></b>", esc(client_id)),
        (Some(n), Some(h)) => format!(
            "<b>{}</b> (client published by <code>{}</code>)",
            esc(n),
            esc(h)
        ),
        (None, Some(h)) => format!("<b>A client published by <code>{}</code></b>", esc(h)),
    }
}

fn hidden(name: &str, v: Option<&str>) -> String {
    v.map(|v| {
        format!(
            "<input type=\"hidden\" name=\"{name}\" value=\"{}\">",
            esc(v)
        )
    })
    .unwrap_or_default()
}

fn redirect_note(uri: &str) -> String {
    let mut s = format!(
        "<p>You will be sent back to <code>{}</code>.</p>",
        esc(redirect_host(uri))
    );
    if loopback_without_port(uri).is_some() {
        s.push_str(
            "<p class=\"warn\">This client runs on this computer (local redirect). Continue only if you just \
started the connection yourself, e.g. from Claude Code.</p>",
        );
    }
    s
}

fn login_page(
    o: &OAuth,
    p: &AuthzParams,
    pending: &PendingAuth,
    label: &ClientLabel,
    err: Option<&str>,
) -> String {
    let fields: String = [
        ("response_type", p.response_type.as_deref()),
        ("client_id", p.client_id.as_deref()),
        ("redirect_uri", p.redirect_uri.as_deref()),
        ("state", p.state.as_deref()),
        ("code_challenge", p.code_challenge.as_deref()),
        ("code_challenge_method", p.code_challenge_method.as_deref()),
        ("scope", p.scope.as_deref()),
        ("resource", p.resource.as_deref()),
    ]
    .iter()
    .map(|(n, v)| hidden(n, *v))
    .collect();
    let svc = esc(&o.0.cfg.resource_name);
    let err = err
        .map(|e| format!("<p class=\"err\">{}</p>", esc(e)))
        .unwrap_or_default();
    page(
        &format!("Sign in to {}", o.0.cfg.resource_name),
        &format!(
            "<h1>Sign in to {svc}</h1><p>{} asks to connect to {svc}.</p>{}{err}\
<form method=\"post\" action=\"/oauth/authorize\">{fields}<input type=\"hidden\" name=\"step\" value=\"login\">\
<label for=\"pw\">Owner password</label><input id=\"pw\" type=\"password\" name=\"password\" \
autocomplete=\"current-password\" required autofocus><button type=\"submit\">Sign in</button></form>",
            client_label(label, &pending.client_id),
            redirect_note(&pending.redirect_uri),
        ),
    )
}

fn consent_page(o: &OAuth, pending: &PendingAuth, label: &ClientLabel, ticket: &str) -> String {
    let svc = esc(&o.0.cfg.resource_name);
    page(
        "Allow access?",
        &format!(
            "<h1>Allow access?</h1><p>{} will be able to use {svc} on your behalf.</p>{}\
<form method=\"post\" action=\"/oauth/authorize\"><input type=\"hidden\" name=\"step\" value=\"consent\">{}\
<button type=\"submit\" name=\"decision\" value=\"allow\">Allow</button> \
<button type=\"submit\" name=\"decision\" value=\"deny\" class=\"secondary\">Deny</button></form>",
            client_label(label, &pending.client_id),
            redirect_note(&pending.redirect_uri),
            hidden("ticket", Some(ticket)),
        ),
    )
}

#[cfg(test)]
impl OAuth {
    /// Tests: issue tokens for `client_id` as if at time `now`.
    pub(crate) fn issue_for_tests(&self, client_id: &str, now: u64) -> (String, String) {
        let mut st = self.lock();
        let resource = self.0.resource.clone();
        let i = st.tokens.issue(client_id, SCOPE, &resource, now);
        (i.access_token, i.refresh_token)
    }
}

// --------------------------------------------------------------- tests

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn tmp_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "ytg-oauth-{tag}-{}-{}",
            std::process::id(),
            random_token(6)
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    pub(crate) fn config(dir: &Path, hash: &str) -> Config {
        Config {
            issuer: "https://ytg.test".into(),
            mcp_path: "/mcp".into(),
            owner_password_hash: hash.into(),
            state_dir: dir.to_path_buf(),
            redirect_patterns: DEFAULT_REDIRECT_PATTERNS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            resource_name: "test-service".into(),
            cimd_allowlist: None,
        }
    }

    pub(crate) fn rand_bytes(n: usize) -> Vec<u8> {
        let mut b = vec![0u8; n];
        getrandom::fill(&mut b).unwrap();
        b
    }

    fn patterns() -> Vec<String> {
        DEFAULT_REDIRECT_PATTERNS
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    #[test]
    fn pkce_rfc7636_appendix_b() {
        let v = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let c = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(pkce_s256_ok(v, c));
        assert!(
            !pkce_s256_ok("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXK", c),
            "one char off"
        );
        assert!(!pkce_s256_ok("short", c), "verifier too short");
        assert!(!pkce_s256_ok(&"a".repeat(129), c), "verifier too long");
        assert!(!pkce_s256_ok(&format!("{v}!"), c), "bad charset");
        assert!(!pkce_s256_ok(v, ""), "empty challenge");
    }

    #[test]
    fn password_hash_roundtrip() {
        let h = hash_password("correct horse battery staple").unwrap();
        assert!(h.starts_with("$argon2id$v=19$"), "{h}");
        let pw = Arc::new(OwnerPassword::new(&h, 1).unwrap());
        assert!(
            pw.try_slot()
                .unwrap()
                .verify("correct horse battery staple")
        );
        assert!(!pw.try_slot().unwrap().verify("correct horse battery stapl"));
        assert!(OwnerPassword::new("$argon2i$v=19$m=16,t=2,p=1$c2FsdHNhbHQ$Zm9v", 1).is_err());
        assert!(OwnerPassword::new("plain", 1).is_err());
    }

    #[test]
    fn token_issue_expiry_and_rotation() {
        let mut s = TokenStore::default();
        let r = "https://ytg.test/mcp";
        let t0 = 1_000_000;
        let a = s.issue("c1", "mcp", r, t0);
        assert_eq!(a.expires_in, 3600);
        assert_eq!(
            B64.decode(&a.access_token).unwrap().len(),
            32,
            "opaque 32 random bytes"
        );
        assert_ne!(a.access_token, a.refresh_token);
        let g = Grant {
            client_id: "c1".into(),
            scope: "mcp".into(),
        };
        assert_eq!(s.access(&a.access_token, r, t0 + 3599), Some(g.clone()));
        assert_eq!(
            s.access(&a.access_token, r, t0 + 3600),
            None,
            "access expires after 1 h"
        );
        assert_eq!(
            s.access(&a.access_token, "https://other/mcp", t0),
            None,
            "audience bound"
        );
        assert_eq!(
            s.access(&a.refresh_token, r, t0),
            None,
            "refresh is not an access token"
        );

        assert_eq!(
            s.refresh(&a.refresh_token, "c2", t0 + 10),
            Err(RefreshError::Invalid),
            "other client"
        );
        let b = s.refresh(&a.refresh_token, "c1", t0 + 4000).unwrap();
        assert_eq!(b.family, a.family);
        assert_ne!(b.refresh_token, a.refresh_token, "rotated");
        assert_eq!(
            s.access(&a.access_token, r, t0 + 4000),
            None,
            "old access token replaced"
        );
        assert_eq!(s.access(&b.access_token, r, t0 + 4000), Some(g));

        // Replaying the retired refresh token revokes the whole family.
        assert_eq!(
            s.refresh(&a.refresh_token, "c1", t0 + 4001),
            Err(RefreshError::Reused)
        );
        assert_eq!(s.access(&b.access_token, r, t0 + 4001), None);
        assert_eq!(
            s.refresh(&b.refresh_token, "c1", t0 + 4001),
            Err(RefreshError::Invalid)
        );

        // Refresh tokens live 30 days from their issue.
        let c = s.issue("c1", "mcp", r, t0);
        assert_eq!(
            s.refresh(&c.refresh_token, "c1", t0 + REFRESH_TTL),
            Err(RefreshError::Invalid)
        );
        let d = s.issue("c1", "mcp", r, t0);
        assert!(
            s.refresh(&d.refresh_token, "c1", t0 + REFRESH_TTL - 1)
                .is_ok()
        );
        assert_eq!(s.refresh("garbage", "c1", t0), Err(RefreshError::Invalid));
    }

    #[test]
    fn revoke_and_prune() {
        let mut s = TokenStore::default();
        let r = "https://ytg.test/mcp";
        let a = s.issue("c1", "mcp", r, 100);
        assert!(s.revoke(&a.refresh_token));
        assert_eq!(s.access(&a.access_token, r, 100), None);
        assert!(!s.revoke(&a.refresh_token));
        s.issue("c1", "mcp", r, 100);
        s.prune(100 + REFRESH_TTL);
        assert!(s.fams.is_empty() && s.by_access.is_empty() && s.by_refresh.is_empty());
    }

    #[test]
    fn dcr_validation() {
        let p = patterns();
        let ok = br#"{"client_name":"Claude","redirect_uris":["https://claude.ai/api/mcp/auth_callback"],
            "grant_types":["authorization_code","refresh_token"],"token_endpoint_auth_method":"none"}"#;
        let (c, secret) = validate_registration(ok, &p, 7).unwrap();
        assert_eq!(c.client_name.as_deref(), Some("Claude"));
        assert_eq!(c.token_endpoint_auth_method, "none");
        assert_eq!((secret, c.client_secret_sha256), (None, None), "public");
        assert_eq!(c.client_id_issued_at, 7);
        assert_eq!(c.response_types, ["code"]);
        assert!(
            validate_registration(
                br#"{"redirect_uris":["https://claude.com/api/mcp/auth_callback"]}"#,
                &p,
                0
            )
            .is_ok()
        );
        let cc =
            br#"{"client_name":"Claude Code","redirect_uris":["http://localhost:51234/callback"]}"#;
        let (c, secret) = validate_registration(cc, &p, 0).unwrap();
        assert_eq!(c.grant_types, ["authorization_code", "refresh_token"]);
        assert_eq!(
            (c.token_endpoint_auth_method.as_str(), secret),
            ("none", None),
            "omitted method stays public"
        );
        assert!(
            validate_registration(br#"{"redirect_uris":["http://127.0.0.1/callback"]}"#, &p, 0)
                .is_ok()
        );

        let err = |b: &[u8]| validate_registration(b, &p, 0).unwrap_err().error;
        assert_eq!(
            err(br#"{"redirect_uris":["https://evil.example/cb"]}"#),
            "invalid_redirect_uri"
        );
        assert_eq!(
            err(br#"{"redirect_uris":["http://localhost:1/other"]}"#),
            "invalid_redirect_uri"
        );
        assert_eq!(
            err(br#"{"redirect_uris":["http://localhost:1x/callback"]}"#),
            "invalid_redirect_uri"
        );
        assert_eq!(
            err(br#"{"redirect_uris":["https://claude.ai/api/mcp/auth_callback#x"]}"#),
            "invalid_redirect_uri"
        );
        assert_eq!(err(br#"{"redirect_uris":[]}"#), "invalid_redirect_uri");
        assert_eq!(err(br#"{}"#), "invalid_redirect_uri");
        assert_eq!(err(b"not json"), "invalid_client_metadata");
        let imp = br#"{"redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"grant_types":["implicit"]}"#;
        assert_eq!(err(imp), "invalid_client_metadata");
        let tok = br#"{"redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"response_types":["token"]}"#;
        assert_eq!(err(tok), "invalid_client_metadata");
        let jwt = br#"{"redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"token_endpoint_auth_method":"private_key_jwt"}"#;
        assert_eq!(err(jwt), "invalid_client_metadata");
        let chatgpt_http =
            br#"{"redirect_uris":["http://chatgpt.com/connector_platform_oauth_redirect"]}"#;
        assert_eq!(err(chatgpt_http), "invalid_redirect_uri");
    }

    /// ChatGPT-style registration: confidential client, scope and unknown
    /// fields ignored, unique callback path.
    #[test]
    fn dcr_confidential_clients() {
        let p = patterns();
        for method in ["client_secret_post", "client_secret_basic"] {
            let body = format!(
                r#"{{"client_name":"ChatGPT","redirect_uris":["https://chatgpt.com/connector_platform_oauth_redirect/abc123"],
                "grant_types":["authorization_code","refresh_token"],"response_types":["code"],
                "token_endpoint_auth_method":"{method}","scope":"mcp openid","logo_uri":"https://x/y.png",
                "contacts":["a@b"],"software_id":"chatgpt","extra":{{"nested":[1,2]}}}}"#
            );
            let (c, secret) = validate_registration(body.as_bytes(), &p, 9).unwrap();
            let secret = secret.expect("secret issued");
            assert_eq!(B64.decode(&secret).unwrap().len(), 32);
            assert_eq!(c.token_endpoint_auth_method, method);
            assert_eq!(
                c.client_secret_sha256.as_deref(),
                Some(digest(&secret).as_str())
            );
            assert!(secret_ok(
                &secret,
                c.client_secret_sha256.as_deref().unwrap()
            ));
            assert!(!secret_ok(
                "wrong",
                c.client_secret_sha256.as_deref().unwrap()
            ));
            assert!(!secret_ok(&secret, ""));
            let v = registration_response(&c, Some(&secret));
            assert_eq!(v["client_secret"], secret.as_str());
            assert_eq!(v["client_secret_expires_at"], 0);
            assert_eq!(v["token_endpoint_auth_method"], method);
            assert_eq!(
                v["redirect_uris"],
                json!(["https://chatgpt.com/connector_platform_oauth_redirect/abc123"])
            );
            assert!(v.get("client_secret_sha256").is_none(), "digest never sent");
        }
        // Only authorization_code is fine too.
        let only_code = br#"{"redirect_uris":["https://chatgpt.com/aip/g-1/oauth/callback"],
            "grant_types":["authorization_code"],"token_endpoint_auth_method":"client_secret_post"}"#;
        let (c, s) = validate_registration(only_code, &p, 0).unwrap();
        assert_eq!(c.grant_types, ["authorization_code"]);
        assert!(s.is_some());
        // Public client response has no secret fields.
        let (c, s) = validate_registration(
            br#"{"redirect_uris":["https://chatgpt.com/connector_platform_oauth_redirect"],"token_endpoint_auth_method":"none"}"#,
            &p,
            0,
        )
        .unwrap();
        let v = registration_response(&c, s.as_deref());
        assert!(v.get("client_secret").is_none() && v.get("client_secret_sha256").is_none());
        // Persisted shape round-trips, old files without the digest still load.
        let back: Client = serde_json::from_value(serde_json::to_value(&c).unwrap()).unwrap();
        assert_eq!(back, c);
        let old: Client = serde_json::from_str(
            r#"{"client_id":"x","redirect_uris":["https://claude.ai/api/mcp/auth_callback"],
            "grant_types":["authorization_code"],"response_types":["code"],
            "token_endpoint_auth_method":"none","client_id_issued_at":1}"#,
        )
        .unwrap();
        assert_eq!(old.client_secret_sha256, None);
    }

    #[test]
    fn redirect_patterns_chatgpt_and_wildcards() {
        let p = patterns();
        let ok = |u: &str| p.iter().any(|pat| pattern_matches(pat, u));
        for u in [
            "https://chatgpt.com/connector_platform_oauth_redirect",
            "https://chatgpt.com/connector_platform_oauth_redirect/abc123",
            "https://chatgpt.com/connector_platform_oauth_redirect/a/b-c_d",
            "https://chatgpt.com/aip/g-123/oauth/callback",
            "https://chatgpt.com/aip/x?y=1",
            "https://chat.openai.com/connector_platform_oauth_redirect",
            "https://chat.openai.com/aip/g-123/oauth/callback",
            // Claude and loopback unchanged.
            "https://claude.ai/api/mcp/auth_callback",
            "https://claude.com/api/mcp/auth_callback",
            "http://localhost:51234/callback",
            "http://localhost/callback",
            "http://127.0.0.1:3118/callback",
        ] {
            assert!(ok(u), "should match: {u}");
        }
        for u in [
            "https://evil.com/connector_platform_oauth_redirect",
            "https://evil.com/connector_platform_oauth_redirect/abc",
            "https://chatgpt.com.evil.net/connector_platform_oauth_redirect",
            "https://chatgpt.com.evil.net/connector_platform_oauth_redirect/abc",
            "https://chatgpt.com.evil.net/aip/x",
            "https://evilchatgpt.com/aip/x",
            "https://chatgpt.com@evil.net/connector_platform_oauth_redirect",
            "https://evil.net\\@chatgpt.com/aip/x",
            "https://evil.net\\.chatgpt.com/aip/x",
            "http://chatgpt.com/connector_platform_oauth_redirect",
            "http://chatgpt.com/connector_platform_oauth_redirect/abc",
            "http://chatgpt.com/aip/x",
            "https://chatgpt.com:8443/aip/x",
            "https://chatgpt.com:/aip/x",
            "https://CHATGPT.com/aip/x",
            "https://chatgpt.com/connector_platform_oauth_redirectX",
            "https://chatgpt.com/connector_platform_oauth_redirect?x=1",
            "https://chatgpt.com/aip",
            "https://chatgpt.com/aipx/y",
            "https://chatgpt.com/other",
            "https://chatgpt.com/aip/../evil",
            "https://chatgpt.com/aip/x/../../evil",
            "https://chatgpt.com/aip/%2e%2e/evil",
            "https://chatgpt.com/aip/x%2Fy",
            "https://chatgpt.com/aip/x#frag",
            "https://chatgpt.com/aip/x y",
            "https://chat.openai.com/connector_platform_oauth_redirect/abc",
            "chatgpt.com/aip/x",
            "https:///aip/x",
            "http://localhost:1x/callback",
            "http://localhost:123456/callback",
            "http://localhost.evil.net:80/callback",
        ] {
            assert!(!ok(u), "should not match: {u}");
        }
        // Pattern syntax.
        for good in [
            "https://x.test/cb",
            "https://x.test/a/*",
            "https://x.test:8443/cb",
            "https://x.test:*/cb",
            "http://localhost:*/callback",
            "http://[::1]:*/callback",
        ] {
            assert_eq!(check_pattern(good), Ok(()), "{good}");
        }
        for bad in [
            "http://chatgpt.com/*",
            "http://x.test/cb",
            "https://x.test",
            "https://x.test/a*b",
            "https://x.test/a/**",
            "https://*.x.test/cb",
            "https://u@x.test/cb",
            "https://x.test/cb#f",
            "https://x.test:ab/cb",
            "x.test/cb",
        ] {
            assert!(check_pattern(bad).is_err(), "{bad}");
        }
        for d in DEFAULT_REDIRECT_PATTERNS {
            assert_eq!(check_pattern(d), Ok(()), "{d}");
        }
        // Custom patterns replace the defaults.
        let custom = vec!["https://app.example/oauth/*".to_string()];
        assert!(pattern_matches(
            &custom[0],
            "https://app.example/oauth/cb/1"
        ));
        assert!(
            validate_registration(
                br#"{"redirect_uris":["https://app.example/oauth/cb"]}"#,
                &custom,
                0
            )
            .is_ok()
        );
        assert!(
            validate_registration(
                br#"{"redirect_uris":["https://claude.ai/api/mcp/auth_callback"]}"#,
                &custom,
                0
            )
            .is_err()
        );
    }

    #[test]
    fn redirect_matching() {
        let reg = vec![
            "http://localhost:4000/callback".to_string(),
            "https://claude.ai/api/mcp/auth_callback".to_string(),
        ];
        assert!(redirect_registered(&reg, "http://localhost:4000/callback"));
        assert!(
            redirect_registered(&reg, "http://localhost:5999/callback"),
            "loopback port ignored"
        );
        assert!(
            !redirect_registered(&reg, "http://127.0.0.1:4000/callback"),
            "host must match"
        );
        assert!(!redirect_registered(&reg, "http://localhost:4000/other"));
        assert!(redirect_registered(
            &reg,
            "https://claude.ai/api/mcp/auth_callback"
        ));
        assert!(!redirect_registered(
            &reg,
            "https://claude.ai/api/mcp/auth_callback/"
        ));
        assert!(
            !redirect_registered(&reg, "https://claude.ai:8443/api/mcp/auth_callback"),
            "non-loopback exact"
        );
        let cimd_style = vec!["http://127.0.0.1/callback".to_string()];
        assert!(redirect_registered(
            &cimd_style,
            "http://127.0.0.1:3118/callback"
        ));
        assert_eq!(
            redirect_host("https://claude.ai/api/mcp/auth_callback"),
            "claude.ai"
        );
        assert_eq!(
            redirect_host("http://localhost:3118/callback"),
            "localhost:3118"
        );
    }

    #[test]
    fn resource_canonicalisation() {
        assert_eq!(
            canonical_uri("HTTPS://YTG.Test/mcp/"),
            "https://ytg.test/mcp"
        );
        assert_eq!(canonical_uri("https://ytg.test"), "https://ytg.test");
        assert_ne!(
            canonical_uri("https://ytg.test/MCP"),
            "https://ytg.test/mcp",
            "path is case-sensitive"
        );
    }

    #[test]
    fn metadata_json() {
        let dir = tmp_dir("meta");
        let h = hash_password("pw-for-metadata-test").unwrap();
        let o = OAuth::new(config(&dir, &h)).unwrap();
        let prm = o.prm_json();
        assert_eq!(prm["resource"], "https://ytg.test/mcp");
        assert_eq!(prm["authorization_servers"], json!(["https://ytg.test"]));
        assert_eq!(prm["bearer_methods_supported"], json!(["header"]));
        let asm = o.asm_json();
        assert_eq!(asm["issuer"], "https://ytg.test");
        assert_eq!(
            asm["authorization_endpoint"],
            "https://ytg.test/oauth/authorize"
        );
        assert_eq!(asm["token_endpoint"], "https://ytg.test/oauth/token");
        assert_eq!(
            asm["registration_endpoint"],
            "https://ytg.test/oauth/register"
        );
        assert_eq!(asm["revocation_endpoint"], "https://ytg.test/oauth/revoke");
        assert_eq!(asm["code_challenge_methods_supported"], json!(["S256"]));
        assert_eq!(
            asm["grant_types_supported"],
            json!(["authorization_code", "refresh_token"])
        );
        assert_eq!(
            asm["token_endpoint_auth_methods_supported"],
            json!([
                "none",
                "client_secret_post",
                "client_secret_basic",
                "private_key_jwt"
            ])
        );
        assert_eq!(
            asm["token_endpoint_auth_signing_alg_values_supported"],
            json!(["RS256", "PS256", "ES256"])
        );
        assert_eq!(asm["authorization_response_iss_parameter_supported"], true);
        assert_eq!(asm["client_id_metadata_document_supported"], true);
        assert!(o.dcr_enabled());
        // With a CIMD allowlist: no DCR, no shared-secret methods.
        let mut c = config(&dir, &h);
        c.cimd_allowlist = Some(vec![crate::cimd::tests::CLAUDE.into()]);
        let o2 = OAuth::new(c).unwrap();
        let asm2 = o2.asm_json();
        assert!(!o2.dcr_enabled() && asm2.get("registration_endpoint").is_none());
        assert_eq!(asm2["client_id_metadata_document_supported"], true);
        assert_eq!(
            asm2["token_endpoint_auth_methods_supported"],
            json!(["none", "private_key_jwt"])
        );
        assert_eq!(
            o.resource_metadata_url(),
            "https://ytg.test/.well-known/oauth-protected-resource"
        );
        assert!(
            o.resource_ok(Some("https://ytg.test/mcp")) && o.resource_ok(Some("https://ytg.test/"))
        );
        assert!(o.resource_ok(None) && !o.resource_ok(Some("https://evil.test/mcp")));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn config_validation() {
        let dir = tmp_dir("cfg");
        let h = hash_password("pw-for-config-test").unwrap();
        let mut c = config(&dir, &h);
        c.issuer = "http://ytg.test".into();
        assert!(OAuth::new(c).is_err(), "plain http issuer");
        let mut c = config(&dir, &h);
        c.issuer = "https://ytg.test/sub".into();
        assert!(OAuth::new(c).is_err(), "issuer with path");
        assert!(OAuth::new(config(&dir, "nope")).is_err(), "bad hash");
        let mut c = config(&dir, &h);
        c.redirect_patterns = vec!["http://chatgpt.com/*".into()];
        assert!(OAuth::new(c).is_err(), "insecure redirect pattern");
        let mut c = config(&dir, &h);
        c.redirect_patterns = vec![];
        assert!(OAuth::new(c).is_err(), "no redirect patterns");
        let mut c = config(&dir, &h);
        c.cimd_allowlist = Some(vec!["http://claude.ai/oauth/x".into()]);
        assert!(OAuth::new(c).is_err(), "allowlist entry not https");
        let mut c = config(&dir, &h);
        c.cimd_allowlist = Some(vec!["https://claude.ai".into()]);
        assert!(OAuth::new(c).is_err(), "allowlist entry without path");
        let mut c = config(&dir, &h);
        c.issuer = "https://ytg.test/".into();
        assert_eq!(
            OAuth::new(c).unwrap().resource(),
            "https://ytg.test/mcp",
            "trailing slash trimmed"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn state_persists_with_mode_600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_dir("persist");
        let h = hash_password("pw-for-persist-test").unwrap();
        let o = OAuth::new(config(&dir, &h)).unwrap();
        let issued = {
            let mut st = o.lock();
            let c = validate_registration(
                br#"{"redirect_uris":["https://claude.ai/api/mcp/auth_callback"]}"#,
                &patterns(),
                unix_now(),
            )
            .unwrap()
            .0;
            st.clients.insert(c.client_id.clone(), c.clone());
            o.save_clients(&st);
            let i = st
                .tokens
                .issue(&c.client_id, "mcp", "https://ytg.test/mcp", unix_now());
            o.save_tokens(&st);
            i
        };
        for f in [CLIENTS_FILE, TOKENS_FILE] {
            let m = std::fs::metadata(dir.join(f)).unwrap().permissions().mode() & 0o777;
            assert_eq!(m, 0o600, "{f}");
        }
        let raw = std::fs::read_to_string(dir.join(TOKENS_FILE)).unwrap();
        assert!(
            !raw.contains(&issued.access_token) && !raw.contains(&issued.refresh_token),
            "only digests at rest"
        );
        drop(o);
        let o2 = OAuth::new(config(&dir, &h)).unwrap();
        assert_eq!(o2.lock().clients.len(), 1);
        assert!(
            o2.validate(&issued.access_token).is_some(),
            "access token survives restart"
        );
        std::fs::write(dir.join(TOKENS_FILE), b"{corrupt").unwrap();
        assert!(
            OAuth::new(config(&dir, &h)).is_err(),
            "corrupt state is loud"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn basic_auth_credentials() {
        let basic = |raw: &str| {
            let mut h = HeaderMap::new();
            let v = format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(raw)
            );
            h.insert(header::AUTHORIZATION, v.parse().unwrap());
            basic_credentials(&h)
        };
        let pair = |a: &str, b: &str| Some((a.to_string(), b.to_string()));
        assert_eq!(basic("abc%2Dd:secret"), pair("abc-d", "secret"));
        assert_eq!(basic("id:se%3Acret+x"), pair("id", "se:cret x"));
        assert_eq!(
            basic("id:a:b"),
            pair("id", "a:b"),
            "split at the first colon"
        );
        assert_eq!(basic("id:"), pair("id", ""), "public client, empty secret");
        assert_eq!(basic("no-colon"), None);
        assert_eq!(basic("id:%zz"), None, "bad escape");
        assert_eq!(basic("id:%4"), None, "truncated escape");
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, "Bearer x".parse().unwrap());
        assert_eq!(basic_credentials(&h), None);
    }
}
