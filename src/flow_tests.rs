//! End-to-end flows through the axum app: DCR, CIMD (public and
//! private_key_jwt), the allowlist, the bearer layer and the guard.

use crate::cimd::tests::{CHATGPT, CHATGPT_DOC, CLAUDE, CLAUDE_CODE, CLAUDE_CODE_DOC, CLAUDE_DOC};
use crate::jwt::tests::{Signer, claims};
use crate::oauth::tests::{config, tmp_dir};
use crate::{Grant, Guard, Limits, OAuth, protect};
use axum::{
    Extension, Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::any,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

const PW: &str = "correct horse battery staple";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const IP: &str = "198.51.100.7";
const JWKS: &str = "https://chatgpt.com/oauth/jwks.json";
const TOKEN_URL: &str = "https://ytg.test/oauth/token";

struct Resp {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: String,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("{e}: {}", self.body))
    }
}

async fn send(app: &Router, req: Request<Body>) -> Resp {
    let r = app.clone().oneshot(req).await.unwrap();
    let status = r.status();
    let headers = r.headers().clone();
    let body = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
    Resp {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

fn form(path: &str, pairs: &[(&str, &str)]) -> Request<Body> {
    Request::post(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("cf-connecting-ip", IP)
        .body(Body::from(serde_urlencoded::to_string(pairs).unwrap()))
        .unwrap()
}

fn get(path: &str) -> Request<Body> {
    Request::get(path)
        .header("cf-connecting-ip", IP)
        .body(Body::empty())
        .unwrap()
}

fn mcp(bearer: Option<&str>) -> Request<Body> {
    let mut b = Request::post("/mcp").header("cf-connecting-ip", IP);
    if let Some(t) = bearer {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::empty()).unwrap()
}

fn hidden_value(html: &str, name: &str) -> String {
    let pat = format!("name=\"{name}\" value=\"");
    let i = html
        .find(&pat)
        .unwrap_or_else(|| panic!("no hidden {name} in {html}"))
        + pat.len();
    html[i..i + html[i..].find('"').unwrap()].to_string()
}

fn query_param(url: &str, k: &str) -> Option<String> {
    let q = url.split_once('?')?.1;
    serde_urlencoded::from_str::<Vec<(String, String)>>(q)
        .ok()?
        .into_iter()
        .find(|(a, _)| a == k)
        .map(|(_, v)| v)
}

fn challenge() -> String {
    B64.encode(Sha256::digest(VERIFIER.as_bytes()))
}

/// `/mcp` echoes the grant's client_id; everything inside `protect`.
fn app_with(o: &OAuth, lim: Limits) -> Router {
    let r = Router::new()
        .route(
            "/mcp",
            any(|Extension(g): Extension<Grant>| async move { g.client_id })
                .layer(o.bearer_layer()),
        )
        .merge(o.router());
    protect(r, Guard::new(lim))
}

fn setup(tag: &str, allowlist: Option<Vec<String>>) -> (std::path::PathBuf, OAuth, Router) {
    let dir = tmp_dir(tag);
    let mut c = config(&dir, &crate::hash_password(PW).unwrap());
    c.cimd_allowlist = allowlist;
    let o = OAuth::new_for_tests(c).unwrap();
    let app = app_with(&o, Limits::default());
    (dir, o, app)
}

/// authorize (GET) -> login -> consent -> code, for `client_id` and `redirect`.
async fn authorize(app: &Router, client_id: &str, redirect: &str, expect: &[&str]) -> String {
    let ch = challenge();
    let params = [
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect),
        ("state", "st-1"),
        ("code_challenge", ch.as_str()),
        ("code_challenge_method", "S256"),
        ("scope", "mcp"),
        ("resource", "https://ytg.test/mcp"),
    ];
    let q = serde_urlencoded::to_string(params).unwrap();
    let r = send(app, get(&format!("/oauth/authorize?{q}"))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    for e in expect {
        assert!(r.body.contains(e), "{e} not in {}", r.body);
    }
    let mut login = params.to_vec();
    login.extend([("step", "login"), ("password", PW)]);
    let r = send(app, form("/oauth/authorize", &login)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let ticket = hidden_value(&r.body, "ticket");
    let consent = [
        ("step", "consent"),
        ("ticket", ticket.as_str()),
        ("decision", "allow"),
    ];
    let r = send(app, form("/oauth/authorize", &consent)).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    let loc = r.headers[header::LOCATION].to_str().unwrap().to_string();
    assert!(loc.starts_with(&format!("{redirect}?")), "{loc}");
    assert_eq!(
        query_param(&loc, "iss").as_deref(),
        Some("https://ytg.test")
    );
    query_param(&loc, "code").unwrap()
}

fn exchange<'a>(
    client_id: &'a str,
    code: &'a str,
    redirect: &'a str,
) -> Vec<(&'static str, &'a str)> {
    vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect),
        ("client_id", client_id),
        ("code_verifier", VERIFIER),
        ("resource", "https://ytg.test/mcp"),
    ]
}

#[tokio::test]
async fn dcr_flow_and_bearer_layer() {
    let (dir, _o, app) = setup("dcr", None);
    let r = send(&app, mcp(None)).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        r.headers[header::WWW_AUTHENTICATE],
        r#"Bearer resource_metadata="https://ytg.test/.well-known/oauth-protected-resource""#
    );
    let cb = "https://claude.ai/api/mcp/auth_callback";
    let reg = Request::post("/oauth/register")
        .body(Body::from(format!(
            r#"{{"client_name":"Claude","redirect_uris":["{cb}"]}}"#
        )))
        .unwrap();
    let r = send(&app, reg).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    let id = r.json()["client_id"].as_str().unwrap().to_string();
    let code = authorize(
        &app,
        &id,
        cb,
        &["<b>Claude</b> asks to connect to test-service"],
    )
    .await;
    let r = send(&app, form("/oauth/token", &exchange(&id, &code, cb))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let access = r.json()["access_token"].as_str().unwrap().to_string();
    let r = send(&app, mcp(Some(&access))).await;
    assert_eq!(
        (r.status, r.body.as_str()),
        (StatusCode::OK, id.as_str()),
        "grant in extensions"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn cimd_public_clients() {
    let (dir, o, app) = setup("cimd-public", None);
    o.cimd().serve(CLAUDE, 200, CLAUDE_DOC.as_bytes());
    o.cimd().serve(CLAUDE_CODE, 200, CLAUDE_CODE_DOC.as_bytes());
    let cb = "https://claude.ai/api/mcp/auth_callback";
    let code = authorize(
        &app,
        CLAUDE,
        cb,
        &[
            "<b>Claude</b> (client published by <code>claude.ai</code>)",
            "<code>claude.ai</code>",
        ],
    )
    .await;
    // Public client: PKCE only, no secret.
    let r = send(&app, form("/oauth/token", &exchange(CLAUDE, &code, cb))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let tok = r.json();
    let access = tok["access_token"].as_str().unwrap();
    let r = send(&app, mcp(Some(access))).await;
    assert_eq!((r.status, r.body.as_str()), (StatusCode::OK, CLAUDE));
    // Refresh with the URL as client_id.
    let rf = [
        ("grant_type", "refresh_token"),
        ("refresh_token", tok["refresh_token"].as_str().unwrap()),
        ("client_id", CLAUDE),
    ];
    let r = send(&app, form("/oauth/token", &rf)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    // Nothing persisted for CIMD clients.
    let clients = std::fs::read_to_string(dir.join("oauth-clients.json")).unwrap_or_default();
    assert!(!clients.contains(CLAUDE), "{clients}");

    // Claude Code: loopback redirect on any port.
    let code = authorize(
        &app,
        CLAUDE_CODE,
        "http://localhost:51234/callback",
        &["local redirect"],
    )
    .await;
    let r = send(
        &app,
        form(
            "/oauth/token",
            &exchange(CLAUDE_CODE, &code, "http://localhost:51234/callback"),
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);

    // A redirect the document does not list: error page, never a redirect.
    let q = serde_urlencoded::to_string([
        ("response_type", "code"),
        ("client_id", CLAUDE),
        ("redirect_uri", "https://claude.com/api/mcp/auth_callback"),
        ("code_challenge", challenge().as_str()),
        ("code_challenge_method", "S256"),
    ])
    .unwrap();
    let r = send(&app, get(&format!("/oauth/authorize?{q}"))).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.headers.get(header::LOCATION).is_none());
    // No redirect_uri: the document's only one is used.
    let q = serde_urlencoded::to_string([
        ("response_type", "code"),
        ("client_id", CLAUDE),
        ("code_challenge", challenge().as_str()),
        ("code_challenge_method", "S256"),
    ])
    .unwrap();
    assert_eq!(
        send(&app, get(&format!("/oauth/authorize?{q}")))
            .await
            .status,
        StatusCode::OK
    );

    // Bad documents and unreachable ones: an error page.
    let evil = "https://evil.example/client.json";
    for (status, body, why) in [
        (200, CLAUDE_DOC.to_string(), "differs"),
        (
            200,
            format!(r#"{{"client_id":"{evil}","redirect_uris":["https://evil.example/cb"]}}"#),
            "redirect_uris",
        ),
        (404, String::new(), "404"),
        (503, String::new(), "503"),
    ] {
        o.cimd().serve(evil, status, body.as_bytes());
        let q =
            serde_urlencoded::to_string([("response_type", "code"), ("client_id", evil)]).unwrap();
        let r = send(&app, get(&format!("/oauth/authorize?{q}"))).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{why}");
        assert!(r.body.contains(why), "{why}: {}", r.body);
    }
    // Not an acceptable client_id URL at all.
    let q = serde_urlencoded::to_string([
        ("response_type", "code"),
        ("client_id", "https://10.0.0.1/c"),
    ])
    .unwrap();
    assert_eq!(
        send(&app, get(&format!("/oauth/authorize?{q}")))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    // Token endpoint: a URL whose document cannot be fetched now is a 503.
    let r = send(&app, form("/oauth/token", &exchange(evil, "x", cb))).await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE, "{}", r.body);
    assert!(r.body.contains("temporarily_unavailable"));
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn cimd_private_key_jwt() {
    let (dir, o, app) = setup("cimd-jwt", None);
    let signer = Signer::rsa("RS256");
    o.cimd().serve(CHATGPT, 200, CHATGPT_DOC.as_bytes());
    o.cimd().serve(
        JWKS,
        200,
        json!({"keys":[signer.jwk("k1")]}).to_string().as_bytes(),
    );
    let cb = "https://chatgpt.com/connector_platform_oauth_redirect";
    let now = crate::oauth::unix_now();
    let assertion = |kid: &str, c: &Value| signer.sign(Some(kid), c);
    let with = |pairs: &[(&'static str, String)]| -> Vec<(&'static str, String)> { pairs.to_vec() };
    let post = |v: &[(&'static str, String)]| {
        let p: Vec<(&str, &str)> = v.iter().map(|(k, x)| (*k, x.as_str())).collect();
        form("/oauth/token", &p)
    };
    let atype = (
        "client_assertion_type",
        crate::jwt::ASSERTION_TYPE.to_string(),
    );

    let code = authorize(
        &app,
        CHATGPT,
        cb,
        &["<b>ChatGPT</b> (client published by <code>chatgpt.com</code>)"],
    )
    .await;
    let base = with(&[
        ("grant_type", "authorization_code".into()),
        ("code", code.clone()),
        ("redirect_uri", cb.into()),
        ("code_verifier", VERIFIER.into()),
    ]);
    // Wrong signature (another key, same kid): 401, counted, code kept.
    let mut v = base.clone();
    v.push(("client_id", CHATGPT.into()));
    v.push(atype.clone());
    v.push((
        "client_assertion",
        Signer::rsa("RS256").sign(Some("k1"), &claims(CHATGPT, TOKEN_URL, now)),
    ));
    let r = send(&app, post(&v)).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
    assert!(r.body.contains("invalid_client"));
    // Wrong audience.
    let mut v = base.clone();
    v.push(atype.clone());
    v.push((
        "client_assertion",
        assertion("k1", &claims(CHATGPT, "https://other.test/token", now)),
    ));
    assert_eq!(send(&app, post(&v)).await.status, StatusCode::UNAUTHORIZED);
    // Wrong assertion type.
    let mut v = base.clone();
    v.push(("client_assertion_type", "urn:x".into()));
    v.push((
        "client_assertion",
        assertion("k1", &claims(CHATGPT, TOKEN_URL, now)),
    ));
    assert_eq!(send(&app, post(&v)).await.status, StatusCode::BAD_REQUEST);
    // Good assertion, client_id taken from its sub (no client_id field).
    let good = claims(CHATGPT, TOKEN_URL, now);
    let mut v = base.clone();
    v.push(atype.clone());
    v.push(("client_assertion", assertion("k1", &good)));
    let r = send(&app, post(&v)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let tok = r.json();
    assert_eq!(
        send(&app, mcp(tok["access_token"].as_str())).await.body,
        CHATGPT
    );
    // Replayed assertion (same jti) on refresh: refused.
    let refresh = tok["refresh_token"].as_str().unwrap().to_string();
    let rf = with(&[
        ("grant_type", "refresh_token".into()),
        ("refresh_token", refresh.clone()),
        ("client_id", CHATGPT.into()),
        atype.clone(),
        ("client_assertion", assertion("k1", &good)),
    ]);
    let r = send(&app, post(&rf)).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
    // Key rotation: unknown kid triggers a JWKS refetch (at most once a minute).
    let signer2 = Signer::es256();
    o.cimd().serve(
        JWKS,
        200,
        json!({"keys":[signer2.jwk("k2")]}).to_string().as_bytes(),
    );
    o.cimd().age(std::time::Duration::from_secs(61));
    let rf = with(&[
        ("grant_type", "refresh_token".into()),
        ("refresh_token", refresh.clone()),
        ("client_id", CHATGPT.into()),
        atype.clone(),
        (
            "client_assertion",
            signer2.sign(Some("k2"), &claims(CHATGPT, "https://ytg.test", now)),
        ),
    ]);
    let r = send(&app, post(&rf)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    // ChatGPT's document also declares `none`: PKCE-only exchange accepted.
    let code = authorize(&app, CHATGPT, cb, &[]).await;
    let r = send(&app, form("/oauth/token", &exchange(CHATGPT, &code, cb))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);

    // A private_key_jwt-only client must authenticate.
    let strict = "https://agent.example/cimd.json";
    let doc = json!({"client_id":strict,"client_name":"Agent","redirect_uris":[cb],
        "token_endpoint_auth_method":"private_key_jwt","jwks":{"keys":[signer.jwk("k1")]}});
    o.cimd().serve(strict, 200, doc.to_string().as_bytes());
    let code = authorize(&app, strict, cb, &["agent.example"]).await;
    let r = send(&app, form("/oauth/token", &exchange(strict, &code, cb))).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
    assert!(r.body.contains("private_key_jwt"));
    let mut v: Vec<(&'static str, String)> = exchange(strict, &code, cb)
        .into_iter()
        .map(|(k, x)| (k, x.to_string()))
        .collect();
    v.push(atype.clone());
    v.push((
        "client_assertion",
        assertion("k1", &claims(strict, TOKEN_URL, now)),
    ));
    let r = send(&app, post(&v)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    // DCR clients cannot use assertions.
    let reg = Request::post("/oauth/register")
        .body(Body::from(format!(r#"{{"redirect_uris":["{cb}"]}}"#)))
        .unwrap();
    let id = send(&app, reg).await.json()["client_id"]
        .as_str()
        .unwrap()
        .to_string();
    let code = authorize(&app, &id, cb, &[]).await;
    let mut v: Vec<(&'static str, String)> = exchange(&id, &code, cb)
        .into_iter()
        .map(|(k, x)| (k, x.to_string()))
        .collect();
    v.push(atype.clone());
    v.push((
        "client_assertion",
        assertion("k1", &claims(&id, TOKEN_URL, now)),
    ));
    assert_eq!(send(&app, post(&v)).await.status, StatusCode::UNAUTHORIZED);
    let _ = std::fs::remove_dir_all(dir);
}

fn refresh_req<'a>(client_id: &'a str, refresh: &'a str) -> Vec<(&'static str, &'a str)> {
    vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh),
        ("client_id", client_id),
    ]
}

/// Register by DCR on `app`; `(client_id, client_secret)`.
async fn register(app: &Router, body: &str) -> (String, Option<String>) {
    let r = send(
        app,
        Request::post("/oauth/register")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    let j = r.json();
    (
        j["client_id"].as_str().unwrap().to_string(),
        j["client_secret"].as_str().map(str::to_string),
    )
}

/// `(access, refresh)` of a token response.
fn tokens(r: &Resp) -> (String, String) {
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let j = r.json();
    (
        j["access_token"].as_str().unwrap().to_string(),
        j["refresh_token"].as_str().unwrap().to_string(),
    )
}

fn allowlisted(dir: &std::path::Path, hash: &str, grace: bool) -> (OAuth, Router) {
    let mut c = config(dir, hash);
    c.cimd_allowlist = Some(vec![CLAUDE.into()]);
    let o = OAuth::new_for_tests(c).unwrap();
    assert!(o.dcr_grace(), "on by default");
    let o = o.with_dcr_grace(grace);
    let app = app_with(&o, Limits::default());
    (o, app)
}

#[tokio::test]
async fn allowlist_disables_dcr() {
    let dir = tmp_dir("allow");
    let hash = crate::hash_password(PW).unwrap();
    let cb = "https://claude.ai/api/mcp/auth_callback";
    let gpt = "https://chatgpt.com/connector_platform_oauth_redirect";
    // Two clients registered by DCR before the allowlist was set (a public
    // one, like Claude's, and a confidential one, like ChatGPT's), each
    // holding a token family...
    let open = OAuth::new_for_tests(config(&dir, &hash)).unwrap();
    let app = app_with(&open, Limits::default());
    let (pub_id, _) = register(&app, &format!(r#"{{"redirect_uris":["{cb}"]}}"#)).await;
    let (conf_id, secret) = register(
        &app,
        &format!(
            r#"{{"redirect_uris":["{gpt}"],"token_endpoint_auth_method":"client_secret_post"}}"#
        ),
    )
    .await;
    let secret = secret.expect("confidential client gets a secret");
    let code = authorize(&app, &pub_id, cb, &[]).await;
    let (pub_access, pub_refresh) =
        tokens(&send(&app, form("/oauth/token", &exchange(&pub_id, &code, cb))).await);
    let code = authorize(&app, &conf_id, gpt, &[]).await;
    let mut ex = exchange(&conf_id, &code, gpt);
    ex.push(("client_secret", &secret));
    let (conf_access, conf_refresh) = tokens(&send(&app, form("/oauth/token", &ex)).await);
    drop((open, app));

    // ...then the server restarts with an allowlist (dcr_grace on).
    let (o, app) = allowlisted(&dir, &hash, true);
    let r = send(&app, get("/.well-known/oauth-authorization-server")).await;
    let asm = r.json();
    assert!(asm.get("registration_endpoint").is_none(), "{asm}");
    assert_eq!(asm["client_id_metadata_document_supported"], true);
    let reg = Request::post("/oauth/register")
        .body(Body::from(format!(r#"{{"redirect_uris":["{cb}"]}}"#)))
        .unwrap();
    let r = send(&app, reg).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.body);
    // Allowlisted CIMD client: fine.
    o.cimd().serve(CLAUDE, 200, CLAUDE_DOC.as_bytes());
    let code = authorize(&app, CLAUDE, cb, &["Claude"]).await;
    let (cimd_access, _) =
        tokens(&send(&app, form("/oauth/token", &exchange(CLAUDE, &code, cb))).await);
    // Other URLs are refused, even with a valid document.
    o.cimd().serve(CHATGPT, 200, CHATGPT_DOC.as_bytes());
    let q =
        serde_urlencoded::to_string([("response_type", "code"), ("client_id", CHATGPT)]).unwrap();
    let r = send(&app, get(&format!("/oauth/authorize?{q}"))).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.body.contains("not allowed"), "{}", r.body);
    let r = send(&app, form("/oauth/token", &exchange(CHATGPT, "x", cb))).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    // Grace: the earlier DCR clients' access tokens still validate...
    for (id, access) in [(&pub_id, &pub_access), (&conf_id, &conf_access)] {
        let r = send(&app, mcp(Some(access))).await;
        assert_eq!((r.status, r.body.as_str()), (StatusCode::OK, id.as_str()));
        assert!(o.validate(access).is_some());
    }
    // ...their refresh tokens rotate (the confidential one still needs its secret)...
    let r = send(
        &app,
        form("/oauth/token", &refresh_req(&pub_id, &pub_refresh)),
    )
    .await;
    let (pub_access, pub_refresh) = tokens(&r);
    let r = send(
        &app,
        form("/oauth/token", &refresh_req(&conf_id, &conf_refresh)),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "no secret: {}", r.body);
    let mut rr = refresh_req(&conf_id, &conf_refresh);
    rr.push(("client_secret", &secret));
    let (conf_access, conf_refresh) = tokens(&send(&app, form("/oauth/token", &rr)).await);
    for (id, access) in [(&pub_id, &pub_access), (&conf_id, &conf_access)] {
        let r = send(&app, mcp(Some(access))).await;
        assert_eq!((r.status, r.body.as_str()), (StatusCode::OK, id.as_str()));
    }
    // ...but they cannot start a new authorization, nor exchange a code.
    for (id, uri) in [(&pub_id, cb), (&conf_id, gpt)] {
        let q = serde_urlencoded::to_string([
            ("response_type", "code"),
            ("client_id", id.as_str()),
            ("redirect_uri", uri),
            ("code_challenge", challenge().as_str()),
            ("code_challenge_method", "S256"),
        ])
        .unwrap();
        let r = send(&app, get(&format!("/oauth/authorize?{q}"))).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.body);
        assert!(r.body.contains("no longer accepted"), "{}", r.body);
    }
    let r = send(&app, form("/oauth/token", &exchange(&pub_id, "x", cb))).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.json()["error"], "invalid_client");
    drop((o, app));

    // Restart with dcr_grace off: the DCR clients are cut off at once,
    // the allowlisted client is not; nothing of this counts as a failure.
    let (o, app) = allowlisted(&dir, &hash, false);
    for access in [&pub_access, &conf_access] {
        let r = send(&app, mcp(Some(access))).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        assert!(
            r.headers[header::WWW_AUTHENTICATE]
                .to_str()
                .unwrap()
                .contains("invalid_token")
        );
        assert!(o.validate(access).is_none());
    }
    let r = send(
        &app,
        form("/oauth/token", &refresh_req(&pub_id, &pub_refresh)),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
    assert_eq!(r.json()["error"], "invalid_client");
    let mut rr = refresh_req(&conf_id, &conf_refresh);
    rr.push(("client_secret", &secret));
    let r = send(&app, form("/oauth/token", &rr)).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
    let r = send(&app, mcp(Some(&cimd_access))).await;
    assert_eq!((r.status, r.body.as_str()), (StatusCode::OK, CLAUDE));
    // The state is untouched: turning the grace back on restores them.
    drop((o, app));
    let (_o, app) = allowlisted(&dir, &hash, true);
    let r = send(&app, mcp(Some(&pub_access))).await;
    assert_eq!(
        (r.status, r.body.as_str()),
        (StatusCode::OK, pub_id.as_str())
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn failures_that_count_and_those_that_do_not() {
    let dir = tmp_dir("count");
    let o = OAuth::new_for_tests(config(&dir, &crate::hash_password(PW).unwrap())).unwrap();
    let app = app_with(
        &o,
        Limits {
            max_failures: 3,
            ..Default::default()
        },
    );
    // Expired tokens we issued, missing tokens and unknown paths: never counted.
    let (expired, _) = o.issue_for_tests("c1", 1000);
    for _ in 0..5 {
        let r = send(&app, mcp(Some(&expired))).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        assert!(
            r.headers[header::WWW_AUTHENTICATE]
                .to_str()
                .unwrap()
                .contains("invalid_token")
        );
        assert_eq!(send(&app, mcp(None)).await.status, StatusCode::UNAUTHORIZED);
        for p in [
            "/foo",
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server/mcp",
        ] {
            assert_eq!(
                send(&app, get(p)).await.status,
                StatusCode::NOT_FOUND,
                "{p}"
            );
        }
    }
    let (live, _) = o.issue_for_tests("c1", crate::oauth::unix_now());
    assert_eq!(
        send(&app, mcp(Some(&live))).await.status,
        StatusCode::OK,
        "not banned"
    );
    // Bearer tokens we never issued: counted, the IP is banned at the 3rd.
    for _ in 0..3 {
        assert_eq!(
            send(&app, mcp(Some("forged-token"))).await.status,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        send(&app, mcp(Some(&live))).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Login form for a DCR client registered on `app` (wrong password unless `pw`).
async fn login_form(app: &Router) -> Vec<(&'static str, String)> {
    let cb = "https://claude.ai/api/mcp/auth_callback";
    let (id, _) = register(app, &format!(r#"{{"redirect_uris":["{cb}"]}}"#)).await;
    vec![
        ("response_type", "code".into()),
        ("client_id", id),
        ("redirect_uri", cb.into()),
        ("state", "st-1".into()),
        ("code_challenge", challenge()),
        ("code_challenge_method", "S256".into()),
        ("step", "login".into()),
    ]
}

fn login_req(f: &[(&'static str, String)], password: &str, ip: &str) -> Request<Body> {
    let mut f: Vec<(&str, &str)> = f.iter().map(|(k, v)| (*k, v.as_str())).collect();
    f.push(("password", password));
    Request::post("/oauth/authorize")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("cf-connecting-ip", ip)
        .body(Body::from(serde_urlencoded::to_string(&f).unwrap()))
        .unwrap()
}

/// All password slots busy: the login is answered at once with 503 and
/// Retry-After, the login page is shown again (form kept), no failure is
/// counted and no password is checked.
#[tokio::test]
async fn password_checks_bounded() {
    let dir = tmp_dir("pwbusy");
    let o = OAuth::new_for_tests(config(&dir, &crate::hash_password(PW).unwrap())).unwrap();
    assert_eq!(o.max_password_checks(), crate::DEFAULT_MAX_PASSWORD_CHECKS);
    assert_eq!(crate::DEFAULT_MAX_PASSWORD_CHECKS, 2);
    let app = app_with(
        &o,
        Limits {
            max_failures: 2,
            ..Default::default()
        },
    );
    let f = login_form(&app).await;
    let pool = o.password_pool().clone();
    let held = [pool.try_slot().unwrap(), pool.try_slot().unwrap()];
    for _ in 0..5 {
        let r = send(&app, login_req(&f, "wrong password", IP)).await;
        assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE, "{}", r.body);
        assert_eq!(r.headers[header::RETRY_AFTER], "2");
        assert!(
            r.body.contains("Too many sign-ins in progress"),
            "{}",
            r.body
        );
        assert!(r.body.contains(r#"name="password""#), "login form kept");
    }
    // Even the right password is refused while busy (it is never looked at).
    let r = send(&app, login_req(&f, PW, IP)).await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(pool.usage(), (2, 0), "nothing allocated by refused logins");
    drop(held);
    // 503s were not failures: one wrong password is not a ban (max 2).
    let r = send(&app, login_req(&f, "wrong password", IP)).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
    let r = send(&app, login_req(&f, PW, IP)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(r.body.contains(r#"name="ticket""#));
    assert_eq!(pool.usage(), (0, 1), "one buffer, reused");
    // Configurable.
    let o = o.with_max_password_checks(1);
    assert_eq!(o.max_password_checks(), 1);
    let _held = pool.try_slot().unwrap();
    let r = send(&app, login_req(&f, PW, IP)).await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    let _ = std::fs::remove_dir_all(dir);
}

/// 16 simultaneous wrong passwords from 16 IPs: never more than
/// DEFAULT_MAX_PASSWORD_CHECKS argon2 buffers; the others get 503 at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_logins_bounded() {
    let dir = tmp_dir("pwconc");
    let o = OAuth::new_for_tests(config(&dir, &crate::hash_password(PW).unwrap())).unwrap();
    let app = app_with(&o, Limits::default());
    let f = login_form(&app).await;
    let start = std::sync::Arc::new(tokio::sync::Barrier::new(16));
    let mut tasks = Vec::new();
    for i in 0..16 {
        let (app, f, start) = (app.clone(), f.clone(), start.clone());
        tasks.push(tokio::spawn(async move {
            start.wait().await;
            let ip = format!("203.0.113.{}", i + 1);
            send(&app, login_req(&f, "wrong password", &ip))
                .await
                .status
        }));
    }
    let mut codes = Vec::new();
    for t in tasks {
        codes.push(t.await.unwrap());
    }
    let wrong = codes
        .iter()
        .filter(|c| **c == StatusCode::UNAUTHORIZED)
        .count();
    let busy = codes
        .iter()
        .filter(|c| **c == StatusCode::SERVICE_UNAVAILABLE)
        .count();
    assert_eq!(wrong + busy, 16, "{codes:?}");
    assert!(wrong >= 1 && busy >= 1, "{codes:?}");
    let (running, buffers) = o.password_pool().usage();
    assert_eq!(running, 0);
    assert!(buffers <= crate::DEFAULT_MAX_PASSWORD_CHECKS, "{buffers}");
    let _ = std::fs::remove_dir_all(dir);
}

/// A wrong PKCE verifier for a live code counts as an authentication
/// failure, the same way for a DCR client and for a CIMD client; unknown,
/// expired or used codes, codes of another client and unknown client_ids do
/// not (a real client hits those after a restart or a race).
#[tokio::test]
async fn pkce_mismatch_counts_for_dcr_and_cimd_clients() {
    const BAD: &str = "xBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let cb = "https://claude.ai/api/mcp/auth_callback";
    for kind in ["dcr", "cimd"] {
        let dir = tmp_dir(&format!("pkce-{kind}"));
        let o = OAuth::new_for_tests(config(&dir, &crate::hash_password(PW).unwrap())).unwrap();
        let app = app_with(
            &o,
            Limits {
                max_failures: 3,
                per_ip_burst: 1000.0,
                ..Default::default()
            },
        );
        let id = if kind == "dcr" {
            register(&app, &format!(r#"{{"redirect_uris":["{cb}"]}}"#))
                .await
                .0
        } else {
            o.cimd().serve(CLAUDE, 200, CLAUDE_DOC.as_bytes());
            CLAUDE.to_string()
        };
        // Not counted, however often: unknown code, unknown client_id, a
        // live code presented by another client, a used code.
        for _ in 0..4 {
            let r = send(&app, form("/oauth/token", &exchange(&id, "nope", cb))).await;
            assert_eq!(r.status, StatusCode::BAD_REQUEST, "{kind}: {}", r.body);
            let r = send(
                &app,
                form("/oauth/token", &exchange("no-such-client", "x", cb)),
            )
            .await;
            assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{kind}: {}", r.body);
        }
        let other = register(&app, &format!(r#"{{"redirect_uris":["{cb}"]}}"#))
            .await
            .0;
        let code = authorize(&app, &id, cb, &[]).await;
        for _ in 0..3 {
            let r = send(&app, form("/oauth/token", &exchange(&other, &code, cb))).await;
            assert_eq!(r.status, StatusCode::BAD_REQUEST, "{kind}: {}", r.body);
        }
        let code = authorize(&app, &id, cb, &[]).await;
        let r = send(&app, form("/oauth/token", &exchange(&id, &code, cb))).await;
        tokens(&r);
        for _ in 0..3 {
            let r = send(&app, form("/oauth/token", &exchange(&id, &code, cb))).await;
            assert_eq!(r.status, StatusCode::BAD_REQUEST, "{kind}: used code");
        }
        let (still, _) = o.issue_for_tests(&id, crate::oauth::unix_now());
        assert_eq!(
            send(&app, mcp(Some(&still))).await.status,
            StatusCode::OK,
            "{kind}: nothing above counted"
        );
        // Wrong verifier on live codes: counted, banned at the 3rd.
        for i in 0..3 {
            let code = authorize(&app, &id, cb, &[]).await;
            let mut ex = exchange(&id, &code, cb);
            ex.retain(|(k, _)| *k != "code_verifier");
            if i != 1 {
                ex.push(("code_verifier", BAD));
            } // i == 1: no verifier at all
            let r = send(&app, form("/oauth/token", &ex)).await;
            assert_eq!(r.status, StatusCode::BAD_REQUEST, "{kind}: {}", r.body);
            assert!(r.body.contains("PKCE verification failed"), "{}", r.body);
            // The code is burnt: the right verifier no longer works.
            let r = send(&app, form("/oauth/token", &exchange(&id, &code, cb))).await;
            if i < 2 {
                assert_eq!(r.status, StatusCode::BAD_REQUEST, "{kind}: burnt");
            }
        }
        let r = send(&app, mcp(Some(&still))).await;
        assert_eq!(
            (r.status, r.body.as_str()),
            (StatusCode::TOO_MANY_REQUESTS, "banned"),
            "{kind}: banned after 3 PKCE mismatches"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// The CIMD flows of the three vendor clients through the production HTTP
/// fetcher against a local HTTPS server (fixtures mimic the published
/// documents; nothing leaves the machine), allowlist on: Claude (public),
/// Claude Code (public, loopback redirect, any port), ChatGPT
/// (private_key_jwt with jwks_uri, assertion replay and missing jti
/// rejected). Documents are fetched once; a URL outside the allowlist is
/// never fetched; fetch failures and discovery probes are not counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cimd_over_https_vendor_clients() {
    use crate::cimd::{
        Cimd,
        tests::{CHATGPT, CLAUDE_CODE},
    };
    use crate::test_https::{LocalResolver, Route, Server, ca};
    let srv = Server::start().await;
    let claude = srv.url("claude", "/oauth/mcp-oauth-client-metadata");
    let code_cli = srv.url("claude", "/oauth/claude-code-client-metadata");
    let gpt = srv.url("chatgpt", "/oauth/client.json");
    let jwks = srv.url("chatgpt", "/oauth/jwks.json");
    let outsider = srv.url("evil", "/evil.json");
    let flaky = srv.url("flaky", "/client.json");
    srv.route(
        "/oauth/mcp-oauth-client-metadata",
        Route::json(CLAUDE_DOC.replace(CLAUDE, &claude)),
    );
    srv.route(
        "/oauth/claude-code-client-metadata",
        Route::json(CLAUDE_CODE_DOC.replace(CLAUDE_CODE, &code_cli)),
    );
    srv.route(
        "/oauth/client.json",
        Route::json(CHATGPT_DOC.replace(CHATGPT, &gpt).replace(JWKS, &jwks)),
    );
    srv.route(
        "/evil.json",
        Route::json(CLAUDE_DOC.replace(CLAUDE, &outsider)),
    );
    let signer = Signer::rsa("RS256");
    srv.route(
        "/oauth/jwks.json",
        Route::json(json!({"keys":[signer.jwk("k1")]}).to_string()),
    );
    srv.route(
        "/client.json",
        Route {
            status: 503,
            content_length: true,
            ..Default::default()
        },
    );

    let dir = tmp_dir("cimd-https");
    let mut c = config(&dir, &crate::hash_password(PW).unwrap());
    c.cimd_allowlist = Some(vec![
        claude.clone(),
        code_cli.clone(),
        gpt.clone(),
        flaky.clone(),
    ]);
    let cimd = Cimd::new_http_for_tests(c.redirect_patterns.clone(), LocalResolver, ca());
    let o = OAuth::with_cimd(c, cimd).unwrap();
    let app = app_with(
        &o,
        Limits {
            max_failures: 3,
            per_ip_burst: 1000.0,
            ..Default::default()
        },
    );

    // Claude.
    let cb = "https://claude.ai/api/mcp/auth_callback";
    let code = authorize(&app, &claude, cb, &["<b>Claude</b>"]).await;
    let (access, _) =
        tokens(&send(&app, form("/oauth/token", &exchange(&claude, &code, cb))).await);
    assert_eq!(send(&app, mcp(Some(&access))).await.body, claude);

    // Claude Code: loopback redirect on an ephemeral port.
    let loopback = "http://127.0.0.1:43117/callback";
    let code = authorize(&app, &code_cli, loopback, &["Claude Code"]).await;
    let (access, _) = tokens(
        &send(
            &app,
            form("/oauth/token", &exchange(&code_cli, &code, loopback)),
        )
        .await,
    );
    assert_eq!(send(&app, mcp(Some(&access))).await.body, code_cli);

    // ChatGPT probes OpenID discovery first: 404, not counted (max 3).
    for _ in 0..5 {
        let r = send(&app, get("/.well-known/openid-configuration")).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND);
    }
    // ChatGPT, private_key_jwt with keys from jwks_uri.
    let gcb = "https://chatgpt.com/connector_platform_oauth_redirect";
    let token_url = "https://ytg.test/oauth/token";
    let now = crate::oauth::unix_now();
    let code = authorize(&app, &gpt, gcb, &["<b>ChatGPT</b>"]).await;
    let good = signer.sign(Some("k1"), &claims(&gpt, token_url, now));
    let mut ex = exchange(&gpt, &code, gcb);
    ex.push(("client_assertion_type", crate::jwt::ASSERTION_TYPE));
    ex.push(("client_assertion", &good));
    let (access, refresh) = tokens(&send(&app, form("/oauth/token", &ex)).await);
    assert_eq!(send(&app, mcp(Some(&access))).await.body, gpt);
    let refresh_with = |assertion: String| {
        let v = [
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", refresh.clone()),
            ("client_id", gpt.clone()),
            (
                "client_assertion_type",
                crate::jwt::ASSERTION_TYPE.to_string(),
            ),
            ("client_assertion", assertion),
        ];
        let p: Vec<(&str, &str)> = v.iter().map(|(k, x)| (*k, x.as_str())).collect();
        form("/oauth/token", &p)
    };
    // Replayed assertion (same jti): refused, counted (1).
    let r = send(&app, refresh_with(good.clone())).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
    // An assertion without jti (replayable): refused, counted (2).
    let mut no_jti = claims(&gpt, token_url, now);
    no_jti.as_object_mut().unwrap().remove("jti");
    let r = send(&app, refresh_with(signer.sign(Some("k1"), &no_jti))).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
    // A fresh assertion still refreshes.
    let fresh = signer.sign(Some("k1"), &claims(&gpt, token_url, now));
    let r = send(&app, refresh_with(fresh)).await;
    let (access, _) = tokens(&r);

    // Outside the allowlist: refused at both endpoints, never fetched.
    let q = serde_urlencoded::to_string([
        ("response_type", "code"),
        ("client_id", outsider.as_str()),
        ("redirect_uri", cb),
        ("code_challenge", challenge().as_str()),
        ("code_challenge_method", "S256"),
    ])
    .unwrap();
    for _ in 0..5 {
        let r = send(&app, get(&format!("/oauth/authorize?{q}"))).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
        let r = send(&app, form("/oauth/token", &exchange(&outsider, "x", cb))).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        // Allowlisted but its server fails: 400 page / 503, not counted.
        let qf = q.replace(
            &serde_urlencoded::to_string([("c", outsider.as_str())]).unwrap()[2..],
            &serde_urlencoded::to_string([("c", flaky.as_str())]).unwrap()[2..],
        );
        let r = send(&app, get(&format!("/oauth/authorize?{qf}"))).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.body);
        let r = send(&app, form("/oauth/token", &exchange(&flaky, "x", cb))).await;
        assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE, "{}", r.body);
    }
    assert_eq!(
        srv.hits("/evil.json"),
        0,
        "outside the allowlist: never fetched"
    );
    assert_eq!(srv.hits("/client.json"), 10, "errors are not cached");
    assert_eq!(srv.hits("/oauth/mcp-oauth-client-metadata"), 1, "cached");
    assert_eq!(srv.hits("/oauth/claude-code-client-metadata"), 1);
    assert_eq!(srv.hits("/oauth/client.json"), 1);
    assert_eq!(srv.hits("/oauth/jwks.json"), 1);
    // Two counted failures (replay, no jti), max 3: not banned.
    assert_eq!(send(&app, mcp(Some(&access))).await.body, gpt);
    let _ = std::fs::remove_dir_all(dir);
}

/// Measurement, not a check: `cargo test --release -- --ignored
/// cimd_fetch_memory --nocapture`. 60 concurrent authorize requests from 60
/// IPs whose client_id URLs are (a) outside the allowlist, (b) one
/// allowlisted document that takes 3 s, (c) 60 distinct documents that take
/// 3 s each (no allowlist). Prints the peak RSS over the run (VmHWM reset
/// before each scenario), fetches and connections at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "measurement"]
async fn cimd_fetch_memory() {
    use crate::cimd::Cimd;
    use crate::test_https::{LocalResolver, Route, Server, ca};
    fn kib(k: &str) -> u64 {
        let s = std::fs::read_to_string("/proc/self/status").unwrap();
        s.lines()
            .find(|l| l.starts_with(k))
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap()
            .parse()
            .unwrap()
    }
    let cb = "https://claude.ai/api/mcp/auth_callback";
    for (name, allow, distinct) in [
        ("(a) 60 URLs outside the allowlist", true, true),
        ("(b) 1 allowlisted slow URL x 60", true, false),
        ("(c) 60 distinct slow URLs, no allowlist", false, true),
    ] {
        let srv = Server::start().await;
        let urls: Vec<String> = (0..60)
            .map(|i| {
                let path = if distinct {
                    format!("/doc/{i}")
                } else {
                    "/doc/0".into()
                };
                srv.url("x", &path)
            })
            .collect();
        for u in &urls {
            let path = &u[u.find("/doc").unwrap()..];
            srv.route(
                path,
                Route::json(CLAUDE_DOC.replace(CLAUDE, u))
                    .delayed(std::time::Duration::from_secs(3)),
            );
        }
        let dir = tmp_dir("cimd-mem");
        let mut c = config(&dir, &crate::hash_password(PW).unwrap());
        c.cimd_allowlist = match (allow, distinct) {
            (true, true) => Some(vec![srv.url("x", "/allowed")]),
            (true, false) => Some(vec![urls[0].clone()]),
            _ => None,
        };
        let cimd = Cimd::new_http_for_tests(c.redirect_patterns.clone(), LocalResolver, ca());
        let o = OAuth::with_cimd(c, cimd).unwrap();
        let app = app_with(
            &o,
            Limits {
                max_concurrency: 64,
                ..Default::default()
            },
        );
        std::fs::write("/proc/self/clear_refs", "5").unwrap();
        let base = kib("VmRSS:");
        let t = std::time::Instant::now();
        let mut tasks = Vec::new();
        for (i, u) in urls.iter().enumerate() {
            let q = serde_urlencoded::to_string([
                ("response_type", "code"),
                ("client_id", u.as_str()),
                ("redirect_uri", cb),
                ("code_challenge", challenge().as_str()),
                ("code_challenge_method", "S256"),
            ])
            .unwrap();
            let app = app.clone();
            tasks.push(tokio::spawn(async move {
                let req = Request::get(format!("/oauth/authorize?{q}"))
                    .header("cf-connecting-ip", format!("203.0.113.{}", i + 1))
                    .body(Body::empty())
                    .unwrap();
                send(&app, req).await.status
            }));
        }
        let mut codes = std::collections::BTreeMap::new();
        for t in tasks {
            *codes.entry(t.await.unwrap().as_u16()).or_insert(0) += 1;
        }
        let took = t.elapsed();
        let peak = kib("VmHWM:");
        let after = kib("VmRSS:");
        println!(
            "{name}: RSS base {base} KiB, peak +{} KiB, after +{} KiB; fetches {}, \
             connections at once {}; answers {codes:?}; {took:.1?}",
            peak.saturating_sub(base),
            after.saturating_sub(base),
            srv.total_hits(),
            srv.max_active(),
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
