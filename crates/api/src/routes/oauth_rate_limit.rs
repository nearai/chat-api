//! Bounded, per-process admission limits for public OAuth initiation.
use axum::{
    extract::{ConnectInfo, Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const WINDOW: Duration = Duration::from_secs(60);
const PER_IP_LIMIT: u32 = 20;
const GLOBAL_LIMIT: u32 = 1000;

#[derive(Clone)]
pub(super) struct OAuthInitiationLimit {
    trusted_proxy_count: usize,
    window: Arc<Mutex<Window>>,
}

struct Window {
    started: Instant,
    requests: u32,
    by_ip: HashMap<String, u32>,
}

impl OAuthInitiationLimit {
    pub(super) fn new(trusted_proxy_count: usize) -> Self {
        Self {
            trusted_proxy_count,
            window: Arc::new(Mutex::new(Window {
                started: Instant::now(),
                requests: 0,
                by_ip: HashMap::new(),
            })),
        }
    }

    fn allow(&self, ip: String, now: Instant) -> bool {
        let mut window = self.window.lock().unwrap();
        if now.duration_since(window.started) >= WINDOW {
            window.started = now;
            window.requests = 0;
            window.by_ip.clear();
        }
        // The global cap also bounds the number of tracked IP addresses.
        if window.requests >= GLOBAL_LIMIT {
            return false;
        }
        let count = window.by_ip.entry(ip).or_default();
        if *count >= PER_IP_LIMIT {
            return false;
        }
        *count += 1;
        window.requests += 1;
        true
    }
}

pub(super) async fn limit_oauth_initiation(
    State(limit): State<OAuthInitiationLimit>,
    request: Request,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|addr| addr.0);
    let ip = super::oauth::extract_client_ip(request.headers(), limit.trusted_proxy_count, peer);
    if !limit.allow(ip, Instant::now()) {
        return (
            http::StatusCode::TOO_MANY_REQUESTS,
            [(http::header::RETRY_AFTER, "60")],
            axum::Json(serde_json::json!({"error": "Too many OAuth login attempts"})),
        )
            .into_response();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_ip_and_global_limits_and_expires_tracking() {
        let limit = OAuthInitiationLimit::new(0);
        let now = Instant::now();
        for _ in 0..PER_IP_LIMIT {
            assert!(limit.allow("one".into(), now));
        }
        assert!(!limit.allow("one".into(), now));
        for i in PER_IP_LIMIT..GLOBAL_LIMIT {
            assert!(limit.allow(i.to_string(), now));
        }
        assert!(!limit.allow("new".into(), now));
        assert_eq!(
            limit.window.lock().unwrap().by_ip.len(),
            (GLOBAL_LIMIT - PER_IP_LIMIT + 1) as usize
        );
        assert!(limit.allow("one".into(), now + WINDOW));
        assert_eq!(limit.window.lock().unwrap().by_ip.len(), 1);
    }

    #[tokio::test]
    async fn spoofed_forwarded_headers_do_not_bypass_peer_limit() {
        use tower::ServiceExt;
        let app = axum::Router::new()
            .route("/google", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                OAuthInitiationLimit::new(0),
                limit_oauth_initiation,
            ));
        for i in 0..=PER_IP_LIMIT {
            let request = http::Request::builder()
                .uri("/google")
                .header("x-forwarded-for", format!("192.0.2.{i}"))
                .extension(ConnectInfo("127.0.0.1:1234".parse::<SocketAddr>().unwrap()))
                .body(axum::body::Body::empty())
                .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), if i < PER_IP_LIMIT { 200 } else { 429 });
        }
    }
    #[tokio::test]
    async fn appending_ingress_does_not_trust_a_forged_xff_prefix() {
        use tower::ServiceExt;
        // Both supported forwarding header forms use the same trusted-hop count.
        for header in ["x-forwarded-for", "forwarded"] {
            let app = axum::Router::new()
                .route("/google", axum::routing::get(|| async { "ok" }))
                .layer(axum::middleware::from_fn_with_state(
                    OAuthInitiationLimit::new(1),
                    limit_oauth_initiation,
                ));
            for i in 0..=PER_IP_LIMIT {
                let value = if header == "forwarded" {
                    format!("for=198.51.100.{i}, for=203.0.113.10")
                } else {
                    format!("198.51.100.{i}, 203.0.113.10")
                };
                let response = app
                    .clone()
                    .oneshot(
                        http::Request::builder()
                            .uri("/google")
                            .header(header, value)
                            .extension(ConnectInfo("10.0.0.1:1234".parse::<SocketAddr>().unwrap()))
                            .body(axum::body::Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), if i < PER_IP_LIMIT { 200 } else { 429 });
            }
        }
    }
}
