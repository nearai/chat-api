#![cfg(feature = "test")]
mod common;

use common::{create_test_server_and_db, mock_login, TestServerConfig};
use database::repositories::browser_session_repository::{
    BrowserCredentials, BrowserSessionRepository,
};
use http::header::{AUTHORIZATION, COOKIE, ORIGIN};
use serde_json::json;
use services::auth::ports::SessionRepository;
use sha2::{Digest, Sha256};

const ORIGIN_VALUE: &str = "https://session-test.near.ai";

async fn fixture(
    kind: &str,
) -> (
    axum_test::TestServer,
    database::Database,
    BrowserCredentials,
) {
    std::env::set_var("SESSION_ENFORCE_SHORT_TOKENS", "true");
    std::env::set_var("AGENT_API_TOKEN", "browser-session-test");
    std::env::set_var("BROWSER_SESSION_USER_ORIGINS", ORIGIN_VALUE);
    std::env::set_var(
        "BROWSER_SESSION_ADMIN_ORIGINS",
        "https://admin-session-test.near.ai",
    );
    let mut gateway = services::agent::ports::MockAgentService::new();
    gateway
        .expect_setup_gateway_session_for_user()
        .returning(|_| Ok(None));
    let (server, db) = create_test_server_and_db(TestServerConfig {
        agent_service: Some(std::sync::Arc::new(gateway)),
        ..Default::default()
    })
    .await;
    let email = format!("browser-{}@example.com", uuid::Uuid::new_v4());
    let token = mock_login(&server, &email).await;
    let mut session = db
        .session_repository()
        .get_session_by_token_hash(hex::encode(Sha256::digest(token.as_bytes())))
        .await
        .unwrap()
        .unwrap();
    session.token = Some(token);
    let issued = BrowserSessionRepository(db.pool().clone())
        .establish(&session, kind, ORIGIN_VALUE)
        .await
        .unwrap();

    (server, db, issued)
}

#[tokio::test]
async fn rotation_preserves_other_tabs_access_and_replay_revokes_family() {
    let (server, db, first) = fixture("user").await;
    let repo = BrowserSessionRepository(db.pool().clone());
    let next = repo
        .refresh(&first.refresh_token, "user", ORIGIN_VALUE, true)
        .await
        .unwrap()
        .unwrap();

    for token in [&first.token, &next.token] {
        server
            .get("/v1/users/status")
            .add_header(
                AUTHORIZATION,
                format!("Bearer {token}")
                    .parse::<http::HeaderValue>()
                    .unwrap(),
            )
            .await
            .assert_status_ok();
    }
    assert!(repo
        .refresh(&first.refresh_token, "user", ORIGIN_VALUE, true)
        .await
        .unwrap()
        .is_none());

    server
        .get("/v1/users/status")
        .add_header(
            AUTHORIZATION,
            format!("Bearer {}", next.token)
                .parse::<http::HeaderValue>()
                .unwrap(),
        )
        .await
        .assert_status_unauthorized();
    assert!(repo
        .refresh(&next.refresh_token, "user", ORIGIN_VALUE, true)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn concurrent_refresh_detects_reuse_and_leaves_no_valid_family() {
    let (_, db, first) = fixture("user").await;
    let repo = BrowserSessionRepository(db.pool().clone());

    let (a, b) = tokio::join!(
        repo.refresh(&first.refresh_token, "user", ORIGIN_VALUE, false),
        repo.refresh(&first.refresh_token, "user", ORIGIN_VALUE, false),
    );
    assert_eq!(
        usize::from(a.unwrap().is_some()) + usize::from(b.unwrap().is_some()),
        1
    );
    assert!(db
        .session_repository()
        .get_session_by_id(first.session_id)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn logout_serializes_with_refresh_and_accepts_consumed_credentials() {
    let (_, db, first) = fixture("user").await;
    let repo = BrowserSessionRepository(db.pool().clone());

    let (refresh, logout) = tokio::join!(
        repo.refresh(&first.refresh_token, "user", ORIGIN_VALUE, false),
        repo.logout(&first.refresh_token, "user", ORIGIN_VALUE),
    );
    refresh.unwrap();
    logout.unwrap();

    assert!(db
        .session_repository()
        .get_session_by_id(first.session_id)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn idle_deadline_is_enforced_without_background_extension() {
    let (_, db, first) = fixture("admin").await;
    let repo = BrowserSessionRepository(db.pool().clone());
    let client = db.pool().get().await.unwrap();
    client.execute("UPDATE browser_sessions SET idle_expires_at = NOW() + INTERVAL '1 minute' WHERE session_id = $1", &[&first.session_id]).await.unwrap();

    let next = repo
        .refresh(&first.refresh_token, "admin", ORIGIN_VALUE, false)
        .await
        .unwrap()
        .unwrap();
    assert!(next.expires_at <= chrono::Utc::now() + chrono::Duration::minutes(1));
    assert_eq!(next.absolute_expires_at, first.absolute_expires_at);

    client
        .execute(
            "UPDATE browser_sessions SET idle_expires_at = NOW() WHERE session_id = $1",
            &[&first.session_id],
        )
        .await
        .unwrap();
    assert!(repo
        .refresh(&next.refresh_token, "admin", ORIGIN_VALUE, true)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn refresh_requires_exact_origin_and_correct_client_and_logout_needs_no_access_token() {
    let (server, db, first) = fixture("user").await;
    let cookie = format!("__Host-nearai_user_refresh={}", first.refresh_token);
    let repo = BrowserSessionRepository(db.pool().clone());

    assert!(repo
        .refresh(&first.refresh_token, "admin", ORIGIN_VALUE, false)
        .await
        .unwrap()
        .is_none());
    assert!(repo
        .refresh(&first.refresh_token, "user", "https://evil.near.ai", false)
        .await
        .unwrap()
        .is_none());
    server
        .post("/v1/auth/session/refresh")
        .add_header(COOKIE, cookie.parse::<http::HeaderValue>().unwrap())
        .add_header(
            http::HeaderName::from_static("x-session-client"),
            "user".parse::<http::HeaderValue>().unwrap(),
        )
        .json(&json!({"active": false}))
        .await
        .assert_status_forbidden();

    let refreshed = server
        .post("/v1/auth/session/refresh")
        .add_header(COOKIE, cookie.parse::<http::HeaderValue>().unwrap())
        .add_header(ORIGIN, ORIGIN_VALUE.parse::<http::HeaderValue>().unwrap())
        .add_header(
            http::HeaderName::from_static("x-session-client"),
            "user".parse::<http::HeaderValue>().unwrap(),
        )
        .json(&json!({"active": false}))
        .await;
    refreshed.assert_status_ok();
    assert!(refreshed
        .json::<serde_json::Value>()
        .get("refresh_token")
        .is_none());
    assert_eq!(refreshed.header("cache-control"), "no-store");

    // Even the consumed cookie revokes the family. No access token is supplied.
    server
        .post("/v1/auth/session/logout")
        .add_header(COOKIE, cookie.parse::<http::HeaderValue>().unwrap())
        .add_header(ORIGIN, ORIGIN_VALUE.parse::<http::HeaderValue>().unwrap())
        .add_header(
            http::HeaderName::from_static("x-session-client"),
            "user".parse::<http::HeaderValue>().unwrap(),
        )
        .await
        .assert_status_no_content();
    assert!(db
        .session_repository()
        .get_session_by_id(first.session_id)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn absolute_expiry_cannot_be_extended_and_revokes_access() {
    let (server, db, first) = fixture("user").await;
    let client = db.pool().get().await.unwrap();
    client
        .execute(
            "UPDATE sessions SET expires_at = NOW() WHERE id = $1",
            &[&first.session_id],
        )
        .await
        .unwrap();

    server
        .get("/v1/users/status")
        .add_header(AUTHORIZATION, format!("Bearer {}", first.token))
        .await
        .assert_status_unauthorized();
    assert!(BrowserSessionRepository(db.pool().clone())
        .refresh(&first.refresh_token, "user", ORIGIN_VALUE, true)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn cutoff_caps_previously_issued_legacy_credentials() {
    let (server, db, _) = fixture("user").await;
    let token = mock_login(&server, "legacy-cutoff@example.com").await;
    let hash = hex::encode(Sha256::digest(token.as_bytes()));
    let client = db.pool().get().await.unwrap();
    client.execute(
        "UPDATE sessions SET created_at = NOW() - INTERVAL '16 minutes', expires_at = NOW() + INTERVAL '30 days' WHERE token_hash = $1",
        &[&hash],
    ).await.unwrap();

    server
        .get("/v1/users/status")
        .add_header(AUTHORIZATION, format!("Bearer {token}"))
        .await
        .assert_status_unauthorized();
}

#[tokio::test]
async fn admin_routes_require_admin_session_even_for_an_allowlisted_user() {
    let (server, db, _) = fixture("user").await;
    let token = mock_login(&server, "admin@admin.org").await;
    server
        .get("/v1/admin/users")
        .add_header(AUTHORIZATION, format!("Bearer {token}"))
        .await
        .assert_status_forbidden();

    let repo = BrowserSessionRepository(db.pool().clone());
    let mut session = db
        .session_repository()
        .get_session_by_token_hash(hex::encode(Sha256::digest(token.as_bytes())))
        .await
        .unwrap()
        .unwrap();
    session.token = Some(token);
    let user_session = repo
        .establish(&session, "user", ORIGIN_VALUE)
        .await
        .unwrap();
    server
        .get("/v1/admin/users")
        .add_header(AUTHORIZATION, format!("Bearer {}", user_session.token))
        .await
        .assert_status_forbidden();

    let token = mock_login(&server, "admin@admin.org").await;
    let mut session = db
        .session_repository()
        .get_session_by_token_hash(hex::encode(Sha256::digest(token.as_bytes())))
        .await
        .unwrap()
        .unwrap();
    session.token = Some(token);
    let admin_session = repo
        .establish(&session, "admin", ORIGIN_VALUE)
        .await
        .unwrap();
    server
        .get("/v1/admin/users")
        .add_header(AUTHORIZATION, format!("Bearer {}", admin_session.token))
        .await
        .assert_status_ok();
}
