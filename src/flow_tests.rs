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

#[tokio::test]
async fn allowlist_disables_dcr() {
    let dir = tmp_dir("allow");
    let hash = crate::hash_password(PW).unwrap();
    let cb = "https://claude.ai/api/mcp/auth_callback";
    // A client registered by DCR before the allowlist was set...
    let open = OAuth::new_for_tests(config(&dir, &hash)).unwrap();
    let reg = Request::post("/oauth/register")
        .body(Body::from(format!(r#"{{"redirect_uris":["{cb}"]}}"#)))
        .unwrap();
    assert_eq!(
        send(&app_with(&open, Limits::default()), reg).await.status,
        StatusCode::CREATED
    );
    drop(open);
    // ...then the server restarts with an allowlist.
    let mut c = config(&dir, &hash);
    c.cimd_allowlist = Some(vec![CLAUDE.into()]);
    let o = OAuth::new_for_tests(c).unwrap();
    let app = app_with(&o, Limits::default());
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
    let r = send(&app, form("/oauth/token", &exchange(CLAUDE, &code, cb))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    // Other URLs are refused, even with a valid document.
    o.cimd().serve(CHATGPT, 200, CHATGPT_DOC.as_bytes());
    let q =
        serde_urlencoded::to_string([("response_type", "code"), ("client_id", CHATGPT)]).unwrap();
    let r = send(&app, get(&format!("/oauth/authorize?{q}"))).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.body.contains("not allowed"), "{}", r.body);
    let r = send(&app, form("/oauth/token", &exchange(CHATGPT, "x", cb))).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // The client registered earlier still authorizes.
    let stored: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("oauth-clients.json")).unwrap())
            .unwrap();
    let id = stored["clients"][0]["client_id"]
        .as_str()
        .unwrap()
        .to_string();
    let code = authorize(&app, &id, cb, &[]).await;
    assert_eq!(
        send(&app, form("/oauth/token", &exchange(&id, &code, cb)))
            .await
            .status,
        StatusCode::OK
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
