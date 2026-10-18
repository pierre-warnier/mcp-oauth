# mcp-oauth

OAuth 2.1 for a **single-owner MCP server** written with axum: the server is
its own authorization server and its own protected resource, one owner
password guards the consent screen, and an abuse guard sits in front of the
whole app. Nothing here knows about the tools your server offers. Verified
live with the claude.ai and ChatGPT custom connectors (Client ID Metadata
Documents, ChatGPT through `private_key_jwt`); the Claude Code flow is
covered end to end by the local HTTPS tests against its published metadata
document. Rust 1.99, edition 2024, axum 0.8, tokio. MIT.

```toml
[dependencies]
mcp-oauth = { git = "https://github.com/pierre-warnier/mcp-oauth" }
```

- [Features](#features)
- [Quickstart](#quickstart)
- [Configuration](#configuration)
- [CIMD allowlist (recommended)](#cimd-allowlist-recommended)
- [Threat model](#threat-model)
- [Client compatibility notes](#client-compatibility-notes)
- [Protocol details](#protocol-details)
- [Abuse protection (`protect`)](#abuse-protection-protect)
- [State at rest](#state-at-rest)
- [Tests](#tests)

## Features

| Feature | Standard |
|---|---|
| Protected Resource Metadata, `401` with `WWW-Authenticate: Bearer resource_metadata=...` | [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) |
| Authorization Server Metadata | [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) |
| Authorization code + PKCE S256 for every client | [OAuth 2.1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/), [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) |
| Resource indicators: tokens bound to the MCP URL | [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) |
| `iss` in every authorization response | [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207) |
| Client ID Metadata Documents (public clients, or `private_key_jwt` with RS256 / PS256 / ES256) | [draft-ietf-oauth-client-id-metadata-document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/), [MCP authorization 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) |
| `private_key_jwt` client assertions, single-use `jti` | [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523), [OpenID Connect Core §9](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication) |
| Dynamic Client Registration (public, or `client_secret_post` / `client_secret_basic`) | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591) |
| Refresh token rotation with reuse detection | [OAuth 2.1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) |
| Token revocation | [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009) |
| Loopback redirects matched port-agnostically | [RFC 8252 §7.3](https://www.rfc-editor.org/rfc/rfc8252#section-7.3) |
| Owner password: argon2id, at most 2 checks at once | [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) |
| Per-IP rate limit, ban after repeated authentication failures, body cap, timeout, concurrency cap | (this crate) |

## Quickstart

1. Hash the owner password once (argon2id PHC string), and keep the hash
   out of git:

   ```rust
   let hash = mcp_oauth::hash_password(&password)?; // m=19 MiB, t=2, p=1
   ```

2. Mount the authorization server next to your MCP route and wrap the app
   in the guard. This is the crate's doc test (`cargo test --doc` compiles
   it):

   ```rust
   use axum::{Router, routing::any};
   use mcp_oauth::{Config, Guard, Limits, OAuth, protect};

   fn app() -> Result<Router, String> {
   let oauth = OAuth::new(Config {
       issuer: "https://mcp.example.net".into(),
       mcp_path: "/mcp".into(),
       owner_password_hash: std::env::var("OWNER_PASSWORD_HASH").map_err(|e| e.to_string())?,
       state_dir: "/state".into(),
       redirect_patterns: mcp_oauth::DEFAULT_REDIRECT_PATTERNS.iter().map(|s| s.to_string()).collect(),
       resource_name: "my-server".into(),
       cimd_allowlist: None,
   })?;
   let app = Router::new()
       .route("/mcp", any(|| async { "MCP here" }).layer(oauth.bearer_layer()))
       .merge(oauth.router());
   Ok(protect(app, Guard::new(Limits::default())))
   }
   ```

   A handler behind `bearer_layer()` can read who called it:
   `Extension(grant): Extension<mcp_oauth::Grant>` (`grant.client_id`,
   `grant.scope`).

3. Serve it over HTTPS at the issuer origin, then add
   `https://mcp.example.net/mcp` as a custom connector in claude.ai or
   ChatGPT, or `claude mcp add --transport http my-server
   https://mcp.example.net/mcp` in Claude Code. No client ID or secret to
   type: the client discovers the metadata, identifies itself (CIMD or DCR)
   and sends the owner to the login page ("Sign in to `resource_name`",
   owner password, then "Allow").

4. In production, set the [CIMD allowlist](#cimd-allowlist-recommended).

## Configuration

### `Config`

| Field | Meaning |
|---|---|
| `issuer` | Public origin, e.g. `https://mcp.example.net`: https, no path, query or fragment (http only on `localhost` / `127.0.0.1`); one trailing slash is dropped. It is the issuer; the protected resource is `issuer + mcp_path` |
| `mcp_path` | Path of the bearer-protected MCP route, e.g. `/mcp`; must start with `/` |
| `owner_password_hash` | argon2id PHC string of the single owner's password (`hash_password`) |
| `state_dir` | Directory for `oauth-clients.json` and `oauth-tokens.json`; created mode 700 if missing |
| `redirect_patterns` | Redirect URIs a client may use, by DCR or in its metadata document; non-empty; `DEFAULT_REDIRECT_PATTERNS` covers Claude, Claude Code and ChatGPT (see [Protocol details](#protocol-details)) |
| `resource_name` | Display name on the login and consent pages and `resource_name` of the resource metadata |
| `cimd_allowlist` | `None`: DCR open, any https `client_id` URL accepted as a metadata document. `Some(urls)`: only those `client_id` URLs (exact match), DCR off. See below |

`OAuth::new(Config) -> Result<OAuth, String>` validates all of it, creates
`state_dir` and loads the persisted clients and tokens.

### Builders

| Builder | Default | Meaning |
|---|---|---|
| `OAuth::with_dcr_grace(bool)` | `true` | Only with an allowlist: whether tokens already held by clients outside it keep working ([below](#cimd-allowlist-recommended)) |
| `OAuth::with_max_password_checks(n)` | `DEFAULT_MAX_PASSWORD_CHECKS` = 2 (minimum 1) | Owner password checks running at once; beyond that the login page comes back with `503` and `Retry-After: 2` ([below](#abuse-protection-protect)) |

### `Limits` (for `Guard::new`)

| Field | `Limits::default()` |
|---|---|
| `per_ip_per_min` / `per_ip_burst` | 120 / 40 |
| `max_failures` within `fail_window`, then banned for `ban_for` | 10 in 600 s, ban 3600 s |
| `max_body_bytes` | 1 MiB |
| `request_timeout` | 120 s (answered with 408) |
| `max_concurrency` | 32 |
| `exempt_paths` | `["/healthz"]` |

Override with struct update syntax, e.g.
`Limits { max_body_bytes: 256 * 1024, ..Limits::default() }`.

### Environment conventions

The crate reads no environment variable itself. Servers that use it
configure it from a prefixed set of variables, or from a mode-600 TOML file
outside git with the same keys:

| Variable | Maps to |
|---|---|
| `<PREFIX>_OWNER_PASSWORD_HASH` | `owner_password_hash`; its presence turns OAuth on |
| `<PREFIX>_PUBLIC_URL` | `issuer` |
| `<PREFIX>_STATE_DIR` | `state_dir` |
| `<PREFIX>_REDIRECT_PATTERNS` | `redirect_patterns`, comma list; unset = `DEFAULT_REDIRECT_PATTERNS` |
| `<PREFIX>_CIMD_ALLOWLIST` | `cimd_allowlist`, comma list; unset = `None` |

A `hash-password` subcommand that reads the password from stdin (not argv,
so it stays out of shell history and the process list) and prints
`hash_password(..)` is the usual way to produce the hash.

### API at a glance

| Item | What it does |
|---|---|
| `OAuth::router()` | `/.well-known/oauth-protected-resource` (also `+ mcp_path`), `/.well-known/oauth-authorization-server`, `/oauth/authorize` (login + consent pages), `/oauth/token`, `/oauth/register`, `/oauth/revoke` |
| `OAuth::bearer_layer()` | tower layer for any route: a valid token puts a `Grant { client_id, scope }` in the request extensions, otherwise `401` with `WWW-Authenticate: Bearer resource_metadata="<issuer>/.well-known/oauth-protected-resource"` (`error="invalid_token"` when a token was sent) |
| `OAuth::validate(token)` | the same check by hand |
| `OAuth::resource()`, `resource_metadata_url()`, `dcr_enabled()` | the MCP URL, the metadata URL, whether DCR is open |
| `hash_password(pw)` | argon2id (m=19 MiB, t=2, p=1) PHC string |
| `protect(router, Guard)` | abuse protection around the whole app |
| `AuthFailures` | request extension set by `protect`; `record("what")` counts a failure for the client IP (use it for your own credentials, e.g. a URL path token) |
| `client_ip(headers)` | `CF-Connecting-IP`, else leftmost `X-Forwarded-For`, else `unknown` |
| `check_pattern(p)` | validates one redirect pattern |
| `ACCESS_TTL`, `REFRESH_TTL` | 3600 s, 30 days |

The login and consent pages say "Sign in to `resource_name`", "*client* asks
to connect", "Owner password"; nothing else is shown about the owner.

## CIMD allowlist (recommended)

`cimd_allowlist: None` (default): Dynamic Client Registration stays open and
any https `client_id` URL is accepted as a metadata document.

`cimd_allowlist: Some(urls)`: only those `client_id` URLs (exact string match)
are accepted through CIMD, Dynamic Client Registration is off
(`/oauth/register` answers 403 and `registration_endpoint` disappears from the
metadata, as do the shared-secret auth methods). Every new authorization
needs an allowlisted `client_id`: a client registered by DCR earlier gets an
error page at `/oauth/authorize` ("Remove the connector and add it again") and
`invalid_client` for an authorization code.

Recommended allowlist, the published client_id URLs (checked 2026-10-18; each
document names itself and validates against the default redirect patterns):

| Client | client_id URL | Source |
|---|---|---|
| ChatGPT | `https://chatgpt.com/oauth/client.json` | OpenAI, [Authentication](https://developers.openai.com/plugins/build/auth) ("For authorization servers that meet the issuer identification requirements above, ChatGPT uses the stable `https://chatgpt.com/oauth/client.json`"; this server meets them) |
| Claude Code | `https://claude.ai/oauth/claude-code-client-metadata` | Anthropic, [Authentication for connectors](https://claude.com/docs/connectors/building/authentication) (linked as Claude Code's Client ID Metadata Document) |
| Claude (claude.ai, Desktop, mobile, Cowork) | `https://claude.ai/oauth/mcp-oauth-client-metadata` | Not named in Anthropic's docs. The document is served by claude.ai, names itself (`client_name` "Claude", redirect `https://claude.ai/api/mcp/auth_callback`), and is the URL reported in anthropics/claude-ai-mcp issues [#1148](https://github.com/anthropics/claude-ai-mcp/issues/1148), [#623](https://github.com/anthropics/claude-ai-mcp/issues/623), [#566](https://github.com/anthropics/claude-ai-mcp/issues/566). Confirm it in your server log on the first CIMD connection before relying on it. |

```rust
cimd_allowlist: Some(vec![
    "https://claude.ai/oauth/mcp-oauth-client-metadata".into(),   // Claude
    "https://claude.ai/oauth/claude-code-client-metadata".into(), // Claude Code
    "https://chatgpt.com/oauth/client.json".into(),               // ChatGPT
]),
```

`OAuth::with_dcr_grace(grace)` (only with an allowlist) decides what happens
to the tokens such clients (DCR, or a CIMD URL outside the list) already
hold:

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

## Threat model

Assumptions: one owner, one password, an HTTPS front (e.g. a tunnel or a
reverse proxy) that sets `CF-Connecting-IP` or `X-Forwarded-For`, and a host
you trust.

| Threat | What stops it |
|---|---|
| Password brute force | argon2id; 10 authentication failures per IP in 10 min ban that IP for 1 h; per-IP token bucket (120/min, burst 40) |
| Token guessing | opaque 32-byte random tokens; a bearer token never issued here counts as a failure |
| Stolen authorization code | PKCE S256 for every client; a wrong verifier for a live code burns the code and counts as a failure; a reused code revokes its grant |
| Refresh token theft | rotation on every use; replaying a rotated-out refresh token revokes the whole grant |
| Client assertion replay | `jti` required and single-use, `exp` within an hour, `aud` checked |
| Token leakage at rest | only SHA-256 digests of tokens and client secrets are stored, files mode 600, directory mode 700 |
| Open redirect / code interception | redirect URIs must match the configured patterns (https only, http only on loopback, no `..` or encoded separators) |
| SSRF through CIMD `client_id` URLs | https only, host names only (IP literals and userinfo refused), a resolver that drops RFC 6890 special-purpose addresses, no redirects, no proxy, 5 s timeout, 64 KiB cap; with an allowlist nothing outside it is ever fetched |
| Memory exhaustion | argon2 bounded to 2 concurrent checks with reused buffers (2 x 19 MiB); at most 8 outgoing fetches, one per URL shared by concurrent callers, no idle connections; bounded maps: 512 DCR clients, 1024 token families, 256 pending sign-ins and codes, 10 000 recent `jti`s, 256 cached documents; 1 MiB bodies, 32 requests at once, 120 s timeout |
| Banning real clients | unknown paths, discovery probes, expired or reused codes, unknown `client_id`s and CIMD fetch failures never count as failures |

Out of scope: a compromised host or `state_dir` (whoever can write it can
replace the hash or the token store), a leaked owner password, a
compromised client (claude.ai, ChatGPT or the owner's machine holding a
valid token), volumetric DDoS (leave that to the front: the caps here only
bound what reaches the process), and multi-user servers (there is one owner
and one scope, `mcp`). Client IP headers are trusted as sent: spoofing them
only spreads an attacker over buckets they could get with more IPs, and the
global caps still hold.

## Client compatibility notes

Learned on live connections and from the published metadata documents:

- **Discovery probes.** MCP clients (ChatGPT among them) probe URLs this
  server does not serve, such as `/.well-known/openid-configuration` and
  path-suffixed variants, before and after registering. They get 404, are
  rate-limited like everything else, and never count toward a ban: a chatty
  client behind a shared IP must not lock itself out.
- **ChatGPT** offers CIMD when the metadata says
  `client_id_metadata_document_supported: true`. Its document declares
  `token_endpoint_auth_method: private_key_jwt` and
  `token_endpoint_auth_methods_supported: ["none", "private_key_jwt"]`
  (RS256, keys at `https://chatgpt.com/oauth/jwks.json`); it picks from the
  intersection with this server's `token_endpoint_auth_methods_supported`,
  preferring `private_key_jwt`. The plural field is read first for that
  reason. OpenAI's docs also describe a per-connection
  `https://chatgpt.com/oauth/{callback_id}/client.json` for servers without
  RFC 9207 issuer identification; that does not apply here.
- **Claude and Claude Code** documents declare
  `token_endpoint_auth_method: none` (public clients, PKCE only). Claude
  Code redirects to `http://localhost/callback` or
  `http://127.0.0.1/callback` on a random port, hence the `:*` patterns.
- **CIMD fetch failures** (timeout, 5xx) from a vendor's side cost the rate
  limit only, never a ban.

## Protocol details

- Client ID Metadata Documents
  (draft-ietf-oauth-client-id-metadata-document-02, MCP authorization
  2025-11-25), advertised with `client_id_metadata_document_supported: true`.
  A `client_id` that is an https URL (host name, path, no userinfo, fragment
  or dot segments) is fetched at `/oauth/authorize` and at the token
  endpoint: 5 s timeout, 64 KiB max, no redirects, no proxy, only public IP
  addresses (RFC 6890 special-purpose ranges are refused by the resolver, IP
  literals by the URL check), cached in memory 1 h (a copy up to 24 h old is
  used if a refetch hits a network error; errors and invalid documents are
  never cached). At most 8 fetches run at once (documents and `jwks_uri` key
  sets together; a request waits up to 5 s for a slot, then gets
  "unavailable"), concurrent requests for the same URL share one fetch and
  its result, and no idle connection is kept. With an allowlist, a
  `client_id` outside it is refused before anything is fetched, at
  `/oauth/authorize` and at the token endpoint. The document must contain
  `client_id` equal to the URL and `redirect_uris`; it must not contain a
  client secret. Its `redirect_uris` are filtered by the redirect patterns
  and the authorization request must use one of the rest (loopback port
  ignored). Token endpoint authentication: the plural
  `token_endpoint_auth_methods_supported` of the document if present
  (ChatGPT), else `token_endpoint_auth_method`, else `none`; accepted are
  `none` (PKCE only) and `private_key_jwt` (RFC 7523: `iss` = `sub` =
  client_id, `aud` the issuer or the token endpoint, `exp` within an hour, a
  `jti` (required, as in OpenID Connect Core section 9; without it an
  assertion could be replayed) that is single-use; RS256, PS256 or ES256
  against `jwks` or `jwks_uri`, refetched at most once a minute on an
  unknown `kid`). The consent page shows the document's name and the host of
  the `client_id`. CIMD clients are never written to disk.
- Dynamic Client Registration (RFC 7591): `none` (or omitted) gives a public
  client; `client_secret_post` / `client_secret_basic` a confidential one whose
  secret is returned once and stored as a SHA-256 digest (accepted in the form
  body or HTTP Basic at the token endpoint). `private_key_jwt` is not offered
  through DCR (only through CIMD).
- Authorization code + PKCE S256 for every client; `resource` (RFC 8707)
  checked when present, tokens bound to the MCP URL; `iss` in every
  authorization response (RFC 9207).
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

Memory of a release binary on a glibc 2.41, 20-core server for N concurrent
wrong passwords from N distinct IPs (`VmHWM` peak, `VmRSS` 15 s after the
burst; base 13 MiB):

| N concurrent | before: peak | before: kept | after: peak | after: kept | after: answers |
|---|---|---|---|---|---|
| 1 | 31 MiB | 13 MiB | 32 MiB | 32 MiB | 1 x 401 |
| 8 | 164 MiB | 13 MiB | 51 MiB | 51 MiB | 2 x 401, 6 x 503 |
| 60 | 644 MiB | 643 MiB | 53 MiB | 53 MiB | 2 x 401, 58 x 503 |
| 60, 20 bursts | 1165 MiB | 1164 MiB | 61 MiB | 61 MiB | 40 x 401, 1160 x 503 |

The bound on concurrent checks is what removes both the peak and the
retention: unbounded, every concurrent check got its own 19 MiB in its own
malloc arena, and glibc keeps arena memory. Why the buffers are also kept:
a buffer freed after each check does not reliably go back to the system
either (glibc raises its mmap threshold to the size of the first freed
19 MiB chunk, later ones come from the arenas), and how much stays depends
on how many arenas glibc creates (up to 8 per core). Measured over 60 bursts
of 60 (3600 checks): fresh buffers kept 52-53 MiB over base, kept buffers
49-51 MiB, about the same here; but with kept buffers the argon2 share is
exactly 2 x 19 MiB whatever the allocator and the core count, at the price
of holding it from the first sign-in on (32 MiB RSS after one login instead
of 13 MiB). The rest of the growth over many bursts is per-IP guard state
and allocator overhead.

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
`cargo test --doc` compiles the quickstart above.
`cargo test --release -- --ignored cimd_fetch_memory --nocapture` prints the
memory and fetch counts of 60 concurrent authorize requests with CIMD URLs.
`cargo test -- --ignored live_vendor_documents` fetches the real Claude,
Claude Code and ChatGPT documents and ChatGPT's JWKS through the production
fetcher and checks that a public name resolving to loopback is refused.

## Used by

The author's single-owner MCP servers in production, behind a Cloudflare
tunnel, with the CIMD allowlist above.

## License

MIT, see [LICENSE](LICENSE).
