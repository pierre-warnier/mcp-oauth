//! OAuth 2.1 for a single-owner MCP server: the server is its own
//! authorization server and its own protected resource, and one owner
//! password guards the consent screen. Nothing here knows about the tools
//! the server offers. The API:
//!
//! - [`Config`] and [`OAuth::new`] (validates the config, loads persisted
//!   clients and tokens from `state_dir`);
//! - [`OAuth::router`]: the well-known metadata, `/oauth/authorize` (login
//!   and consent pages), `/oauth/token`, `/oauth/register`, `/oauth/revoke`;
//!   merge it into the app;
//! - [`OAuth::bearer_layer`]: protects any route; a valid token puts a
//!   [`Grant`] in the request extensions, anything else gets 401 with
//!   `WWW-Authenticate: Bearer resource_metadata="..."`;
//! - [`hash_password`]: argon2id PHC string for [`Config::owner_password_hash`];
//! - [`protect`] with a [`Guard`]: per-IP rate limit, ban after repeated
//!   authentication failures, body limit, timeout, concurrency cap, 404 for
//!   unknown paths (never counted as failures).
//!
//! Standards: Protected Resource Metadata (RFC 9728), Authorization Server
//! Metadata (RFC 8414), Client ID Metadata Documents
//! (draft-ietf-oauth-client-id-metadata-document, MCP authorization
//! 2025-11-25: public clients, or `private_key_jwt` with RS256/PS256/ES256),
//! Dynamic Client Registration (RFC 7591: public clients, or confidential ones
//! with `client_secret_post` / `client_secret_basic`), authorization code +
//! PKCE S256 for every client (OAuth 2.1, RFC 7636), resource indicators
//! (RFC 8707, tokens bound to the MCP URL), `iss` in authorization responses
//! (RFC 9207), refresh token rotation with reuse detection, token revocation
//! (RFC 7009), loopback redirects matched port-agnostically (RFC 8252
//! section 7.3).
//!
//! ```no_run
//! use axum::{Router, routing::any};
//! use mcp_oauth::{Config, Guard, Limits, OAuth, protect};
//!
//! # fn app() -> Result<Router, String> {
//! let oauth = OAuth::new(Config {
//!     issuer: "https://mcp.example.net".into(),
//!     mcp_path: "/mcp".into(),
//!     owner_password_hash: std::env::var("OWNER_PASSWORD_HASH").map_err(|e| e.to_string())?,
//!     state_dir: "/state".into(),
//!     redirect_patterns: mcp_oauth::DEFAULT_REDIRECT_PATTERNS.iter().map(|s| s.to_string()).collect(),
//!     resource_name: "my-server".into(),
//!     cimd_allowlist: None,
//! })?;
//! let app = Router::new()
//!     .route("/mcp", any(|| async { "MCP here" }).layer(oauth.bearer_layer()))
//!     .merge(oauth.router());
//! Ok(protect(app, Guard::new(Limits::default())))
//! # }
//! ```

mod cimd;
mod guard;
mod jwt;
mod oauth;
mod password;

#[cfg(test)]
mod flow_tests;
#[cfg(test)]
mod test_https;

pub use guard::{AuthFailures, Guard, Limits, Verdict, client_ip, protect};
pub use oauth::{
    ACCESS_TTL, BearerLayer, BearerService, Config, DEFAULT_REDIRECT_PATTERNS, Grant, OAuth,
    REFRESH_TTL, check_pattern, hash_password,
};
pub use password::DEFAULT_MAX_PASSWORD_CHECKS;
