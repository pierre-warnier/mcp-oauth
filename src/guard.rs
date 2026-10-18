//! Abuse protection for an internet-facing axum app (built for MCP servers
//! behind a Cloudflare tunnel, whose free plan gives volumetric DDoS
//! mitigation but no spare WAF / rate-limit rules):
//!
//! - per-client-IP token bucket on every request (except [`Limits::exempt_paths`]);
//! - per-IP ban after repeated authentication failures, answered with 429;
//! - body size cap, request timeout, global concurrency cap ([`protect`]).
//!
//! What counts as an authentication failure: a wrong or unknown bearer token,
//! a wrong URL path token, a wrong owner password, a wrong client secret or
//! client assertion. Handlers report them through the [`AuthFailures`]
//! request extension that [`protect`] inserts. Unknown paths do **not** count:
//! MCP clients probe discovery URLs (`/.well-known/openid-configuration`,
//! path-suffixed variants, ...) before and after registering, and a chatty
//! client must not get its (often shared) IP banned. They get a 404, are
//! rate-limited like everything else, and are logged as a `debug:` line.
//!
//! Client IP: `CF-Connecting-IP` (set by Cloudflare; the tunnel is the only
//! ingress), else the leftmost `X-Forwarded-For`, else "unknown". Spoofing the
//! header only lets an attacker spread over buckets they could already get by
//! using more IPs; the global caps still bound the total.

use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Limits {
    /// Sustained requests per minute per IP.
    pub per_ip_per_min: f64,
    /// Burst size per IP.
    pub per_ip_burst: f64,
    /// Auth failures per IP within `fail_window` that trigger a ban.
    pub max_failures: u32,
    pub fail_window: Duration,
    pub ban_for: Duration,
    /// Request body cap in bytes (axum `DefaultBodyLimit`).
    pub max_body_bytes: usize,
    /// Whole-request timeout (answered with 408).
    pub request_timeout: Duration,
    /// Requests served at once, all clients together.
    pub max_concurrency: usize,
    /// Paths exempt from rate limiting and bans (health probes).
    pub exempt_paths: Vec<String>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            per_ip_per_min: 120.0,
            per_ip_burst: 40.0,
            max_failures: 10,
            fail_window: Duration::from_secs(600),
            ban_for: Duration::from_secs(3600),
            max_body_bytes: 1024 * 1024,
            request_timeout: Duration::from_secs(120),
            max_concurrency: 32,
            exempt_paths: vec!["/healthz".into()],
        }
    }
}

#[derive(Debug)]
struct Client {
    tokens: f64,
    last: Instant,
    failures: Vec<Instant>,
    banned_until: Option<Instant>,
}

#[derive(Clone)]
pub struct Guard {
    limits: Limits,
    clients: Arc<Mutex<HashMap<String, Client>>>,
}

pub fn client_ip(h: &HeaderMap) -> String {
    let get = |k: &str| {
        h.get(k)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
    };
    get("cf-connecting-ip")
        .map(String::from)
        .or_else(|| {
            get("x-forwarded-for")
                .and_then(|v| v.split(',').next())
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".into())
}

#[derive(Debug, PartialEq)]
pub enum Verdict {
    Ok,
    Banned,
    RateLimited,
}

impl Guard {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    fn client<'a>(
        &self,
        m: &'a mut HashMap<String, Client>,
        ip: &str,
        now: Instant,
    ) -> &'a mut Client {
        m.entry(ip.to_string()).or_insert(Client {
            tokens: self.limits.per_ip_burst,
            last: now,
            failures: Vec::new(),
            banned_until: None,
        })
    }

    /// Account one request from `ip`.
    pub fn admit(&self, ip: &str, now: Instant) -> Verdict {
        let mut m = self.clients.lock().expect("guard lock");
        // Bound memory under a flood of distinct IPs: drop idle entries.
        if m.len() > 50_000 {
            m.retain(|_, c| {
                now.duration_since(c.last) < Duration::from_secs(600)
                    || c.banned_until.is_some_and(|b| b > now)
            });
        }
        let lim = self.limits.clone();
        let c = self.client(&mut m, ip, now);
        if let Some(b) = c.banned_until {
            if b > now {
                return Verdict::Banned;
            }
            c.banned_until = None;
            c.failures.clear();
        }
        let elapsed = now.duration_since(c.last).as_secs_f64();
        c.tokens = (c.tokens + elapsed * lim.per_ip_per_min / 60.0).min(lim.per_ip_burst);
        c.last = now;
        if c.tokens < 1.0 {
            return Verdict::RateLimited;
        }
        c.tokens -= 1.0;
        Verdict::Ok
    }

    /// Record an authentication failure; returns true if the IP is now banned.
    pub fn auth_failed(&self, ip: &str, what: &str, now: Instant) -> bool {
        let mut m = self.clients.lock().expect("guard lock");
        let lim = self.limits.clone();
        let c = self.client(&mut m, ip, now);
        c.failures
            .retain(|t| now.duration_since(*t) < lim.fail_window);
        c.failures.push(now);
        let n = c.failures.len() as u32;
        eprintln!(
            "auth failure ({what}) from {ip} [{n}/{} in window]",
            lim.max_failures
        );
        if n >= lim.max_failures {
            c.banned_until = Some(now + lim.ban_for);
            eprintln!(
                "banning {ip} for {}s after {n} auth failures",
                lim.ban_for.as_secs()
            );
            return true;
        }
        false
    }
}

/// Request extension inserted by [`protect`]: lets a handler (or a layer
/// such as [`crate::BearerLayer`]) count an authentication failure against
/// the client IP of the current request.
#[derive(Clone)]
pub struct AuthFailures {
    guard: Guard,
    ip: String,
}

impl AuthFailures {
    /// Count one failure (`what` is logged); returns true if the IP is now banned.
    pub fn record(&self, what: &str) -> bool {
        self.guard.auth_failed(&self.ip, what, Instant::now())
    }

    /// Client IP the failure is counted against.
    pub fn ip(&self) -> &str {
        &self.ip
    }
}

/// Rate limit + ban check on every request except the exempt paths; puts
/// [`AuthFailures`] in the request extensions.
async fn guard_layer(State(g): State<Guard>, mut req: Request, next: Next) -> Response {
    let path = req.uri().path();
    if g.limits.exempt_paths.iter().any(|p| p == path) {
        return next.run(req).await;
    }
    let ip = client_ip(req.headers());
    match g.admit(&ip, Instant::now()) {
        Verdict::Ok => {
            req.extensions_mut().insert(AuthFailures { guard: g, ip });
            next.run(req).await
        }
        Verdict::Banned => (StatusCode::TOO_MANY_REQUESTS, "banned").into_response(),
        Verdict::RateLimited => (
            [("retry-after", "30")],
            (StatusCode::TOO_MANY_REQUESTS, "rate limited"),
        )
            .into_response(),
    }
}

/// Unknown path: 404, logged at debug level (method and path, no query),
/// never counted as an authentication failure.
async fn unknown_path(req: Request) -> StatusCode {
    let path: String = req.uri().path().chars().take(200).collect();
    eprintln!(
        "debug: unknown path {} {path} from {}",
        req.method(),
        client_ip(req.headers())
    );
    StatusCode::NOT_FOUND
}

/// Wrap a complete app in the abuse protection layers: unknown paths answer
/// 404 (see [`unknown_path`]); per-IP rate limit and ban; body cap; request
/// timeout (408); global concurrency cap. Replaces any fallback of `router`.
pub fn protect(router: Router, guard: Guard) -> Router {
    let lim = guard.limits.clone();
    router
        .fallback(unknown_path)
        .layer(axum::extract::DefaultBodyLimit::max(lim.max_body_bytes))
        .layer(axum::middleware::from_fn_with_state(guard, guard_layer))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            lim.request_timeout,
        ))
        .layer(tower::limit::GlobalConcurrencyLimitLayer::new(
            lim.max_concurrency,
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, routing::get};
    use tower::ServiceExt;

    fn small() -> Guard {
        Guard::new(Limits {
            per_ip_per_min: 60.0,
            per_ip_burst: 3.0,
            max_failures: 3,
            fail_window: Duration::from_secs(60),
            ban_for: Duration::from_secs(100),
            ..Default::default()
        })
    }

    #[test]
    fn bucket_refills() {
        let g = small();
        let t0 = Instant::now();
        for _ in 0..3 {
            assert!(matches!(g.admit("1.2.3.4", t0), Verdict::Ok));
        }
        assert!(matches!(g.admit("1.2.3.4", t0), Verdict::RateLimited));
        assert!(
            matches!(g.admit("5.6.7.8", t0), Verdict::Ok),
            "other IPs unaffected"
        );
        assert!(
            matches!(g.admit("1.2.3.4", t0 + Duration::from_secs(1)), Verdict::Ok),
            "1 token/s refill"
        );
    }

    #[test]
    fn ban_after_failures_then_expires() {
        let g = small();
        let t0 = Instant::now();
        assert!(!g.auth_failed("9.9.9.9", "t", t0));
        assert!(!g.auth_failed("9.9.9.9", "t", t0));
        assert!(g.auth_failed("9.9.9.9", "t", t0));
        assert!(matches!(
            g.admit("9.9.9.9", t0 + Duration::from_secs(50)),
            Verdict::Banned
        ));
        assert!(matches!(
            g.admit("9.9.9.9", t0 + Duration::from_secs(101)),
            Verdict::Ok
        ));
    }

    #[test]
    fn failures_outside_window_do_not_count() {
        let g = small();
        let t0 = Instant::now();
        g.auth_failed("8.8.8.8", "t", t0);
        g.auth_failed("8.8.8.8", "t", t0);
        assert!(
            !g.auth_failed("8.8.8.8", "t", t0 + Duration::from_secs(61)),
            "old failures expired"
        );
    }

    #[test]
    fn ip_from_headers() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "10.0.0.1, 172.16.0.1".parse().unwrap());
        assert_eq!(client_ip(&h), "10.0.0.1");
        h.insert("cf-connecting-ip", "203.0.113.7".parse().unwrap());
        assert_eq!(client_ip(&h), "203.0.113.7");
        assert_eq!(client_ip(&HeaderMap::new()), "unknown");
    }

    /// `/t/{token}`: "good" is 200, anything else 404 + an auth failure
    /// reported through the extension (like a URL path token).
    fn app(lim: Limits) -> Router {
        let r = Router::new()
            .route("/healthz", get(|| async { "ok" }))
            .route(
                "/t/{token}",
                get(
                    |axum::extract::Path(t): axum::extract::Path<String>,
                     f: Option<axum::Extension<AuthFailures>>| async move {
                        if t == "good" {
                            StatusCode::OK
                        } else {
                            if let Some(axum::Extension(f)) = f {
                                f.record("path token");
                            }
                            StatusCode::NOT_FOUND
                        }
                    },
                ),
            );
        protect(r, Guard::new(lim))
    }

    async fn get_(app: &Router, path: &str, ip: &str) -> StatusCode {
        let req = axum::http::Request::get(path)
            .header("cf-connecting-ip", ip)
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn ban_after_bad_tokens_only() {
        let a = app(Limits {
            max_failures: 3,
            ..Default::default()
        });
        assert_eq!(get_(&a, "/t/good", "1.1.1.1").await, StatusCode::OK);
        // Scanner and discovery probes: 404, never counted.
        for p in [
            "/.env",
            "/wp-login.php",
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server/mcp",
            "/foo?x=1",
        ] {
            assert_eq!(get_(&a, p, "6.6.6.6").await, StatusCode::NOT_FOUND, "{p}");
        }
        assert_eq!(
            get_(&a, "/t/good", "6.6.6.6").await,
            StatusCode::OK,
            "unknown paths do not ban"
        );
        for _ in 0..3 {
            assert_eq!(get_(&a, "/t/bad", "6.6.6.6").await, StatusCode::NOT_FOUND);
        }
        assert_eq!(
            get_(&a, "/t/good", "6.6.6.6").await,
            StatusCode::TOO_MANY_REQUESTS,
            "bad tokens ban"
        );
        assert_eq!(get_(&a, "/t/good", "1.1.1.1").await, StatusCode::OK);
        assert_eq!(
            get_(&a, "/healthz", "6.6.6.6").await,
            StatusCode::OK,
            "probes stay exempt"
        );
    }

    #[tokio::test]
    async fn unknown_paths_are_rate_limited() {
        let a = app(Limits {
            per_ip_burst: 3.0,
            per_ip_per_min: 1.0,
            max_failures: 1,
            ..Default::default()
        });
        for _ in 0..3 {
            assert_eq!(get_(&a, "/nope", "4.4.4.4").await, StatusCode::NOT_FOUND);
        }
        assert_eq!(
            get_(&a, "/nope", "4.4.4.4").await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn rate_limited_per_ip() {
        let a = app(Limits {
            per_ip_burst: 3.0,
            per_ip_per_min: 1.0,
            ..Default::default()
        });
        for _ in 0..3 {
            assert_eq!(get_(&a, "/t/good", "2.2.2.2").await, StatusCode::OK);
        }
        assert_eq!(
            get_(&a, "/t/good", "2.2.2.2").await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(get_(&a, "/t/good", "3.3.3.3").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn body_limit_and_timeout() {
        let r = Router::new()
            .route(
                "/echo",
                axum::routing::post(|b: axum::body::Bytes| async move { b.len().to_string() }),
            )
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    "late"
                }),
            );
        let a = protect(
            r,
            Guard::new(Limits {
                max_body_bytes: 16,
                request_timeout: Duration::from_millis(50),
                ..Default::default()
            }),
        );
        let post = |n: usize| {
            axum::http::Request::post("/echo")
                .body(Body::from(vec![b'x'; n]))
                .unwrap()
        };
        assert_eq!(
            a.clone().oneshot(post(16)).await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(
            a.clone().oneshot(post(17)).await.unwrap().status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            get_(&a, "/slow", "7.7.7.7").await,
            StatusCode::REQUEST_TIMEOUT
        );
    }
}
