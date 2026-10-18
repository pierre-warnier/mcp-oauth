# mcp-oauth

OAuth 2.1 for a single-owner MCP server written with axum: the server is its
own authorization server and its own protected resource, and one owner
password guards the consent screen. Also the abuse protection that goes with
an internet-facing endpoint. Rust 1.99, edition 2024, axum 0.8, tokio.

Used by [youtube-get](../youtube-get) (path dependency for now; a git
dependency once this repo has a remote).

## API

```rust
use axum::{Extension, Router, routing::any};
use mcp_oauth::{Config, Grant, Guard, Limits, OAuth, protect};

let oauth = OAuth::new(Config {
    issuer: "https://mcp.example.net".into(),          // https origin, no path
    mcp_path: "/mcp".into(),                           // resource = issuer + mcp_path
    owner_password_hash: hash,                         // mcp_oauth::hash_password(..)
    state_dir: "/state".into(),                        // clients + token digests
    redirect_patterns: mcp_oauth::DEFAULT_REDIRECT_PATTERNS
        .iter().map(|s| s.to_string()).collect(),
    resource_name: "my-server".into(),                 // shown on the pages
    cimd_allowlist: None,                              // see below
})?;
let app = Router::new()
    .route("/mcp", any(|Extension(g): Extension<Grant>| async move { g.client_id })
        .layer(oauth.bearer_layer()))
    .merge(oauth.router());
let app = protect(app, Guard::new(Limits::default()));
```

| Item | What it does |
|---|---|
| `Config` | issuer, `mcp_path`, `owner_password_hash` (argon2id PHC), `state_dir`, `redirect_patterns`, `resource_name`, `cimd_allowlist` |
| `OAuth::new(Config) -> Result<OAuth, String>` | validates the config, creates `state_dir` (mode 700), loads `oauth-clients.json` and `oauth-tokens.json` |
| `OAuth::with_dcr_grace(bool) -> OAuth` | with an allowlist, whether tokens already held by clients outside it keep working (default `true`, below) |
| `OAuth::with_max_password_checks(n) -> OAuth` | owner password checks running at once, default `DEFAULT_MAX_PASSWORD_CHECKS` = 2 (below) |
| `OAuth::router()` | `/.well-known/oauth-protected-resource` (also `+ mcp_path`), `/.well-known/oauth-authorization-server`, `/oauth/authorize` (login + consent pages), `/oauth/token`, `/oauth/register`, `/oauth/revoke` |
| `OAuth::bearer_layer()` | tower layer for any route: a valid token puts a `Grant { client_id, scope }` in the request extensions, otherwise `401` with `WWW-Authenticate: Bearer resource_metadata="<issuer>/.well-known/oauth-protected-resource"` (`error="invalid_token"` when a token was sent) |
| `OAuth::validate(token)` | the same check by hand |
| `hash_password(pw)` | argon2id (m=19 MiB, t=2, p=1) PHC string |
| `protect(router, Guard)` | abuse protection around the whole app (below) |
| `AuthFailures` | request extension set by `protect`; `record("what")` counts a failure for the client IP (use it for your own credentials, e.g. a URL path token) |
| `client_ip(headers)` | `CF-Connecting-IP`, else leftmost `X-Forwarded-For`, else `unknown` |

The login and consent pages say "Sign in to `resource_name`", "*client* asks to
connect", "Owner password"; nothing else is shown about the owner.

## Standards

- Protected Resource Metadata (RFC 9728), Authorization Server Metadata (RFC 8414).
- Authorization code + PKCE S256 for every client (OAuth 2.1, RFC 7636);
  `resource` (RFC 8707) checked when present, tokens bound to the MCP URL;
  `iss` in every authorization response (RFC 9207).
- Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document-02,
  MCP authorization 2025-11-25), advertised with
  `client_id_metadata_document_supported: true`. A `client_id` that is an https
  URL (host name, path, no userinfo, fragment or dot segments) is fetched at
  `/oauth/authorize` and at the token endpoint: 5 s timeout, 64 KiB max, no
  redirects, no proxy, only public IP addresses (RFC 6890 special-purpose
  ranges are refused by the resolver, IP literals by the URL check), cached in
  memory 1 h (a copy up to 24 h old is used if a refetch hits a network error;
  errors and invalid documents are never cached). At most 8 fetches run at
  once (documents and `jwks_uri` key sets together; a request waits up to
  5 s for a slot, then gets "unavailable"), concurrent requests for the same
  URL share one fetch and its result, and no idle connection is kept. With an
  allowlist, a `client_id` outside it is refused before anything is fetched,
  at `/oauth/authorize` and at the token endpoint. The document must contain
  `client_id` equal to the URL and `redirect_uris`; it must not contain a
  client secret. Its `redirect_uris` are filtered by the redirect patterns and
  the authorization request must use one of the rest (loopback port ignored).
  Token endpoint authentication: the plural
  `token_endpoint_auth_methods_supported` of the document if present (ChatGPT),
  else `token_endpoint_auth_method`, else `none`; accepted are `none` (PKCE
  only) and `private_key_jwt` (RFC 7523: `iss` = `sub` = client_id, `aud` the
  issuer or the token endpoint, `exp` within an hour, a `jti` (required, as
  in OpenID Connect Core section 9; without it an assertion could be replayed)
  that is single-use;
  RS256, PS256 or ES256 against `jwks` or `jwks_uri`, refetched at most once a
  minute on an unknown `kid`). The consent page shows the document's name and
  the host of the `client_id`. CIMD clients are never written to disk.
- Dynamic Client Registration (RFC 7591): `none` (or omitted) gives a public
  client; `client_secret_post` / `client_secret_basic` a confidential one whose
  secret is returned once and stored as a SHA-256 digest (accepted in the form
  body or HTTP Basic at the token endpoint). `private_key_jwt` is not offered
  through DCR (only through CIMD).
- Refresh tokens rotate on every use, 30 days; access tokens are opaque 32
  random bytes, 1 h. Replaying a used code or a rotated-out refresh token
  revokes the grant. Revocation (RFC 7009).
- Redirect patterns: scheme and host match exactly, `:*` any port, a trailing
  `*` any rest of the path (no `..` or encoded `.` `/` `\`); https only, http
  only on loopback. `DEFAULT_REDIRECT_PATTERNS`: Claude
  (`https://claude.ai/api/mcp/auth_callback`, `https://claude.com/...`),
  Claude Code (`http://localhost:*/callback`, `http://127.0.0.1:*/callback`),
  ChatGPT (`https://chatgpt.com/connector_platform_oauth_redirect` and `/*`,
  `https://chatgpt.com/aip/*`, `https://chat.openai.com/...`).

## CIMD allowlist

`cimd_allowlist: None` (default): Dynamic Client Registration stays open and
any https `client_id` URL is accepted as a metadata document.

`cimd_allowlist: Some(urls)`: only those `client_id` URLs (exact string match)
are accepted through CIMD, Dynamic Client Registration is off
(`/oauth/register` answers 403 and `registration_endpoint` disappears from the
metadata, as do the shared-secret auth methods). Every new authorization
needs an allowlisted `client_id`: a client registered by DCR earlier gets an
error page at `/oauth/authorize` ("Remove the connector and add it again") and
`invalid_client` for an authorization code.

`OAuth::with_dcr_grace(grace)` (only with an allowlist) decides what happens to the tokens such
clients (DCR, or a CIMD URL outside the list) already hold:

- `true` (the default): their access tokens keep validating and a DCR
  client keeps rotating its refresh token (still authenticating with its
  secret if it has one), so existing connections do not break. The grace ends
  when a refresh token expires (`REFRESH_TTL`, 30 days without use) or is
  revoked; the client then has to connect again, through CIMD. A CIMD client
  outside the list cannot refresh (its document is refused), so its access
  token simply runs out (`ACCESS_TTL`).
- `false`: cut off at once. Their access tokens get `401 invalid_token` (not
  counted as an authentication failure) and refresh gets `invalid_client`.
  Nothing is deleted: setting it back to `true` restores them.

At start the server logs `oauth: dynamic client registration closed (N
allowlisted client_id URLs); M token families of other clients kept ...`, and
`with_dcr_grace(false)` logs how many families it cuts off.

Recommended allowlist, the published client_id URLs (checked 2026-10-18; each
document names itself and validates against the default redirect patterns):

| Client | client_id URL | Source |
|---|---|---|
| ChatGPT | `https://chatgpt.com/oauth/client.json` | OpenAI, [Authentication](https://developers.openai.com/plugins/build/auth) ("For authorization servers that meet the issuer identification requirements above, ChatGPT uses the stable `https://chatgpt.com/oauth/client.json`"; this server meets them) |
| Claude Code | `https://claude.ai/oauth/claude-code-client-metadata` | Anthropic, [Authentication for connectors](https://claude.com/docs/connectors/building/authentication) (linked as Claude Code's Client ID Metadata Document) |
| Claude (claude.ai, Desktop, mobile, Cowork) | `https://claude.ai/oauth/mcp-oauth-client-metadata` | Not named in Anthropic's docs. The document is served by claude.ai, names itself (`client_name` "Claude", redirect `https://claude.ai/api/mcp/auth_callback`), and is the URL reported in anthropics/claude-ai-mcp issues [#1148](https://github.com/anthropics/claude-ai-mcp/issues/1148), [#623](https://github.com/anthropics/claude-ai-mcp/issues/623), [#566](https://github.com/anthropics/claude-ai-mcp/issues/566). Confirm it in your server log on the first CIMD connection before relying on it. |

ChatGPT's document declares both `none` and `private_key_jwt` (RS256, keys at
`https://chatgpt.com/oauth/jwks.json`); ChatGPT picks from the intersection
with `token_endpoint_auth_methods_supported`, preferring `private_key_jwt`.
OpenAI's docs also describe a per-connection
`https://chatgpt.com/oauth/{callback_id}/client.json` for servers without RFC
9207 issuer identification; that does not apply here.

## Abuse protection (`protect`)

- Per-IP token bucket on every request except `Limits::exempt_paths`
  (`/healthz`): 120/min sustained, burst 40; 429 with `retry-after: 30`.
- Ban (429) for 1 h after 10 authentication failures in 10 min. Failures are
  a bearer token never issued here (an expired one does not count), a wrong
  owner password, a wrong client secret, a rejected client assertion, a wrong
  PKCE verifier for a live authorization code of that client (the client
  that asked for the code holds its verifier, so this is a stolen code; the
  code is burnt too), and whatever the app reports through `AuthFailures`.
- Not counted, because real clients hit them: an unknown, expired or already
  used authorization code (restarts, retries, races; a reused code still
  revokes its grant), a code presented by another client, an unknown
  `client_id`, and a CIMD `client_id` URL that is not on the allowlist, cannot
  be fetched (timeout, network error, 5xx) or has an invalid document: a
  Claude client whose metadata fetch timed out must not get its (often
  shared) IP banned. Those only cost the rate limit.
- Unknown paths: 404, rate-limited, never counted; logged on stderr as
  `debug: unknown path <METHOD> <path> from <ip>` (path without query).
- Body cap 1 MiB, request timeout 120 s (408), 32 concurrent requests.
- Owner password checks (argon2id, 19 MiB of memory each with
  `hash_password`): at most 2 at once (`OAuth::with_max_password_checks`).
  A sign-in that finds both busy gets the login page again at once with
  `503` and `Retry-After: 2`; its password is not checked and nothing is
  counted. Each slot keeps its argon2 buffer for the next check, so password
  checks never hold more than 2 x 19 MiB, however many requests come in. This
  lives in `OAuth`, not in `protect`, so it holds without the guard too.

Memory of kidctl's release binary (glibc 2.41, 20 cores) for N concurrent
wrong passwords from N distinct IPs (`VmHWM` peak, `VmRSS` 15 s after the
burst; base 13 MiB):

| N concurrent | before: peak | before: kept | after: peak | after: kept | after: answers |
|---|---|---|---|---|---|
| 1 | 31 MiB | 13 MiB | 32 MiB | 32 MiB | 1 x 401 |
| 8 | 164 MiB | 13 MiB | 51 MiB | 51 MiB | 2 x 401, 6 x 503 |
| 60 | 644 MiB | 643 MiB | 53 MiB | 53 MiB | 2 x 401, 58 x 503 |
| 60, 20 bursts | 1165 MiB | 1164 MiB | 59 MiB | 59 MiB | 40 x 401, 1160 x 503 |

Why the buffers are kept: freed one by one, they do not go back to the
system. glibc raises its mmap threshold to the size of the first freed
19 MiB chunk, so later buffers come from the per-thread malloc arenas, whose
free memory is kept. With the two slots but a fresh buffer per check, what
stayed resident still grew with the bursts (62 MiB after 20 bursts of 60,
67 MiB after 60 bursts). With kept buffers it is fixed at 2 x 19 MiB once
the owner has signed in.

All in `Limits`; `Limits::default()` is the above.

## State at rest

`state_dir/oauth-clients.json` (DCR clients, client secret as SHA-256) and
`state_dir/oauth-tokens.json` (SHA-256 of access and refresh tokens), written
atomically with mode 600. Codes, login tickets, CIMD documents and assertion
`jti`s are in memory. Delete `oauth-tokens.json` and restart to log every
client out.

## Tests

`cargo test`: unit tests per module and end-to-end flows (`src/flow_tests.rs`:
DCR, CIMD public and `private_key_jwt`, allowlist and DCR grace, failure
counting, password check bound), with CIMD documents served from memory, and
the production HTTP fetcher against a local HTTPS server (`src/test_https.rs`,
test CA in `src/testdata/`, every `*.cimd.test` name resolved to it, nothing
leaves the machine): size cap, redirects, timeout, shared and bounded
fetches, and the Claude, Claude Code and ChatGPT flows end to end.
`cargo test --release -- --ignored cimd_fetch_memory --nocapture` prints the
memory and fetch counts of 60 concurrent authorize requests with CIMD URLs. `cargo test -- --ignored
live_vendor_documents` fetches the real Claude, Claude Code and ChatGPT
documents and ChatGPT's JWKS through the production fetcher and checks that a
public name resolving to loopback is refused.
