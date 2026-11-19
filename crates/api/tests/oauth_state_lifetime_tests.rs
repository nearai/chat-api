#![cfg(feature = "test")]
mod common;

use chrono::{Duration, Utc};
use services::auth::ports::{OAuthRepository, OAuthState};
use services::user::ports::OAuthProvider;
use uuid::Uuid;

fn state(age: Duration) -> OAuthState {
    OAuthState {
        state: Uuid::new_v4().to_string(),
        provider: OAuthProvider::Google,
        redirect_uri: "https://api.example.com/v1/auth/callback".into(),
        frontend_callback: Some("https://app.example.com".into()),
        frontend_code_challenge: "A".repeat(43),
        frontend_state: "B".repeat(43),
        created_at: Utc::now() - age,
        provider_code_verifier: None,
    }
}

#[tokio::test]
#[serial_test::serial]
async fn oauth_state_is_one_time_and_expired_state_is_deleted_but_not_returned() {
    let (_, db) = common::create_test_server_and_db(Default::default()).await;
    let repo = db.oauth_repository();
    let recent = state(Duration::minutes(9));
    repo.store_oauth_state(&recent).await.unwrap();
    assert!(repo
        .consume_oauth_state(&recent.state)
        .await
        .unwrap()
        .is_some());
    assert!(repo
        .consume_oauth_state(&recent.state)
        .await
        .unwrap()
        .is_none());
    for age in [Duration::minutes(10), Duration::days(30)] {
        let expired = state(age);
        repo.store_oauth_state(&expired).await.unwrap();
        assert!(repo
            .consume_oauth_state(&expired.state)
            .await
            .unwrap()
            .is_none());
        let client = db.pool().get().await.unwrap();
        assert_eq!(
            client
                .query_one(
                    "SELECT COUNT(*) FROM oauth_states WHERE state=$1",
                    &[&expired.state]
                )
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
    }
}

#[tokio::test]
#[serial_test::serial]
async fn starting_login_cleans_up_abandoned_expired_states() {
    let (_, db) = common::create_test_server_and_db(Default::default()).await;
    let repo = db.oauth_repository();
    let abandoned = state(Duration::days(1));
    repo.store_oauth_state(&abandoned).await.unwrap();
    let recent = state(Duration::zero());
    repo.store_oauth_state(&recent).await.unwrap();
    let client = db.pool().get().await.unwrap();
    assert_eq!(
        client
            .query_one(
                "SELECT COUNT(*) FROM oauth_states WHERE state=$1",
                &[&abandoned.state]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert!(repo
        .consume_oauth_state(&recent.state)
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
#[serial_test::serial]
async fn oversized_urls_are_rejected_before_state_insertion_for_both_providers() {
    let (server, db) = common::create_test_server_and_db(Default::default()).await;
    let client = db.pool().get().await.unwrap();
    let before: i64 = client
        .query_one("SELECT COUNT(*) FROM oauth_states", &[])
        .await
        .unwrap()
        .get(0);
    for provider in ["google", "github"] {
        for field in ["frontend_callback", "redirect_uri"] {
            let mut query = url::form_urlencoded::Serializer::new(String::new());
            query
                .append_pair("frontend_response_mode", "code")
                .append_pair("code_challenge", &"A".repeat(43))
                .append_pair("code_challenge_method", "S256")
                .append_pair("frontend_state", &"B".repeat(43));
            if field == "redirect_uri" {
                query.append_pair("frontend_callback", "http://localhost:3000");
            }
            query.append_pair(field, &format!("https://example.com/{}", "a".repeat(2048)));
            let response = server
                .get(&format!("/v1/auth/{provider}?{}", query.finish()))
                .await;
            assert_eq!(response.status_code(), 400);
        }
    }
    assert_eq!(
        client
            .query_one("SELECT COUNT(*) FROM oauth_states", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        before
    );
}

#[tokio::test]
#[serial_test::serial]
async fn google_and_github_share_an_initiation_limit() {
    let (server, _) = common::create_test_server_and_db(Default::default()).await;
    // Invalid attempts are also limited and never insert state rows.
    for i in 0..20 {
        let provider = if i % 2 == 0 { "google" } else { "github" };
        assert_eq!(
            server
                .get(&format!(
                    "/v1/auth/{provider}?frontend_callback=http://localhost:3000"
                ))
                .await
                .status_code(),
            400
        );
    }
    let response = server
        .get("/v1/auth/github?frontend_callback=http://localhost:3000")
        .await;
    assert_eq!(response.status_code(), 429);
    assert_eq!(response.header(http::header::RETRY_AFTER), "60");
}

#[tokio::test]
#[serial_test::serial]
async fn cleanup_skips_rows_locked_by_another_request() {
    let (_, db) = common::create_test_server_and_db(Default::default()).await;
    let repo = db.oauth_repository();
    let expired = state(Duration::days(1));
    repo.store_oauth_state(&expired).await.unwrap();
    let mut client = db.pool().get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    tx.query_one(
        "SELECT state FROM oauth_states WHERE state=$1 FOR UPDATE",
        &[&expired.state],
    )
    .await
    .unwrap();
    let recent = state(Duration::zero());
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        repo.store_oauth_state(&recent),
    )
    .await
    .unwrap()
    .unwrap();
    tx.rollback().await.unwrap();
    assert!(repo
        .consume_oauth_state(&expired.state)
        .await
        .unwrap()
        .is_none());
    assert!(repo
        .consume_oauth_state(&recent.state)
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
#[serial_test::serial]
async fn near_login_is_limited_before_parsing_and_shares_oauth_quota() {
    let (server, _) = common::create_test_server_and_db(Default::default()).await;
    for _ in 0..20 {
        // Malformed attempts count too; no signature verification or RPC is needed.
        server
            .post("/v1/auth/near")
            .json(&serde_json::json!({}))
            .await
            .assert_status(http::StatusCode::UNPROCESSABLE_ENTITY);
    }
    let response = server
        .post("/v1/auth/near")
        .json(&serde_json::json!({}))
        .await;
    response.assert_status(http::StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.header("retry-after"), "60");
    for provider in ["google", "github"] {
        server
            .get(&format!(
                "/v1/auth/{provider}?frontend_callback=http://localhost:3000"
            ))
            .await
            .assert_status(http::StatusCode::TOO_MANY_REQUESTS);
    }
    // Exchange is not a new login attempt and must not consume the initiation quota.
    assert_ne!(
        server
            .post("/v1/auth/exchange")
            .json(&serde_json::json!({}))
            .await
            .status_code(),
        http::StatusCode::TOO_MANY_REQUESTS
    );
}
