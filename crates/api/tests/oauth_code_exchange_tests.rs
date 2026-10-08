mod common;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use common::{create_test_server_and_db, TestServerConfig};
use http::header::CACHE_CONTROL;
use serde_json::json;
use services::auth::ports::{
    OAuthCallbackCode, OAuthFrontendResponseMode, OAuthRepository, SessionRepository,
};
use services::user::ports::UserRepository;
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[tokio::test]
async fn callback_code_is_pkce_bound_single_use_and_rotates_the_session_token() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;
    let user = db
        .user_repository()
        .create_user(
            format!("oauth-code-{}@example.com", Uuid::new_v4()),
            Some("OAuth code test".into()),
            None,
        )
        .await
        .expect("create test user");
    let original_session = db
        .session_repository()
        .create_session(user.id)
        .await
        .expect("create initial session");
    let original_token = original_session.token.clone().expect("initial token");

    let code = URL_SAFE_NO_PAD.encode([7_u8; 32]);
    let verifier = "v".repeat(43);
    db.oauth_repository()
        .store_callback_code(
            &sha256_hex(&code),
            &OAuthCallbackCode {
                session_id: original_session.session_id,
                code_challenge: pkce_challenge(&verifier),
                is_new_user: true,
                expires_at: Utc::now() + Duration::minutes(2),
            },
        )
        .await
        .expect("store callback code");

    let wrong_response = server
        .post("/v1/auth/exchange")
        .json(&json!({ "code": code, "code_verifier": "w".repeat(43) }))
        .await;
    assert_eq!(wrong_response.status_code(), 401);
    assert_eq!(wrong_response.header(CACHE_CONTROL), "no-store");

    let response = server
        .post("/v1/auth/exchange")
        .json(&json!({ "code": code, "code_verifier": verifier }))
        .await;
    assert_eq!(response.status_code(), 200);
    assert_eq!(response.header(CACHE_CONTROL), "no-store");
    let body: serde_json::Value = response.json();
    let rotated_token = body["token"].as_str().expect("rotated token");
    assert_ne!(rotated_token, original_token);
    assert_eq!(
        body["session_id"].as_str(),
        Some(original_session.session_id.to_string().as_str())
    );
    assert_eq!(body["is_new_user"], true);

    assert!(db
        .session_repository()
        .get_session_by_token_hash(sha256_hex(&original_token))
        .await
        .expect("look up original token")
        .is_none());
    assert!(db
        .session_repository()
        .get_session_by_token_hash(sha256_hex(rotated_token))
        .await
        .expect("look up rotated token")
        .is_some());

    let replay = server
        .post("/v1/auth/exchange")
        .json(&json!({ "code": code, "code_verifier": verifier }))
        .await;
    assert_eq!(replay.status_code(), 401);
}

#[tokio::test]
async fn concurrent_callback_code_exchanges_have_exactly_one_winner() {
    let (_server, db) = create_test_server_and_db(TestServerConfig::default()).await;
    let user = db
        .user_repository()
        .create_user(
            format!("oauth-code-race-{}@example.com", Uuid::new_v4()),
            None,
            None,
        )
        .await
        .expect("create test user");
    let session = db
        .session_repository()
        .create_session(user.id)
        .await
        .expect("create session");
    let code = URL_SAFE_NO_PAD.encode([8_u8; 32]);
    let verifier = "r".repeat(43);
    let code_hash = sha256_hex(&code);
    let challenge = pkce_challenge(&verifier);
    db.oauth_repository()
        .store_callback_code(
            &code_hash,
            &OAuthCallbackCode {
                session_id: session.session_id,
                code_challenge: challenge.clone(),
                is_new_user: false,
                expires_at: Utc::now() + Duration::minutes(2),
            },
        )
        .await
        .expect("store callback code");

    let first_repo = db.oauth_repository();
    let second_repo = db.oauth_repository();
    let first_hash = code_hash.clone();
    let first_challenge = challenge.clone();
    let (first, second) = tokio::join!(
        first_repo.exchange_callback_code(&first_hash, &first_challenge),
        second_repo.exchange_callback_code(&code_hash, &challenge),
    );
    let winners = [first, second]
        .into_iter()
        .map(|result| result.expect("concurrent exchange query"))
        .filter(Option::is_some)
        .count();
    assert_eq!(winners, 1);
}

#[tokio::test]
async fn expired_callback_code_cannot_be_exchanged_and_is_cleaned_up() {
    let (_server, db) = create_test_server_and_db(TestServerConfig::default()).await;
    let user = db
        .user_repository()
        .create_user(
            format!("oauth-code-expired-{}@example.com", Uuid::new_v4()),
            None,
            None,
        )
        .await
        .expect("create test user");
    let session = db
        .session_repository()
        .create_session(user.id)
        .await
        .expect("create session");
    let code = URL_SAFE_NO_PAD.encode([9_u8; 32]);
    let verifier = "x".repeat(43);
    db.oauth_repository()
        .store_callback_code(
            &sha256_hex(&code),
            &OAuthCallbackCode {
                session_id: session.session_id,
                code_challenge: pkce_challenge(&verifier),
                is_new_user: false,
                expires_at: Utc::now() - Duration::seconds(1),
            },
        )
        .await
        .expect("store expired callback code");

    let exchanged = db
        .oauth_repository()
        .exchange_callback_code(&sha256_hex(&code), &pkce_challenge(&verifier))
        .await
        .expect("exchange query should succeed");
    assert!(exchanged.is_none());

    let client = db.pool().get().await.expect("database client");
    let remaining: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM oauth_callback_codes WHERE code_hash = $1",
            &[&sha256_hex(&code)],
        )
        .await
        .expect("count expired callback codes")
        .get(0);
    assert_eq!(remaining, 0);
}

#[tokio::test]
async fn pre_upgrade_oauth_state_writes_default_to_legacy_token_mode() {
    let (_server, db) = create_test_server_and_db(TestServerConfig::default()).await;
    let state = format!("legacy-state-{}", Uuid::new_v4());
    let client = db.pool().get().await.expect("database client");
    client
        .execute(
            "INSERT INTO oauth_states (
                state, provider, redirect_uri, frontend_callback, created_at
             ) VALUES ($1, 'google', $2, $3, NOW())",
            &[
                &state,
                &"https://api.example.com/v1/auth/callback",
                &Some("https://app.example.com"),
            ],
        )
        .await
        .expect("legacy-shaped oauth state insert");

    let consumed = db
        .oauth_repository()
        .consume_oauth_state(&state)
        .await
        .expect("consume legacy oauth state")
        .expect("stored oauth state");
    assert_eq!(
        consumed.frontend_response_mode,
        OAuthFrontendResponseMode::Token
    );
    assert!(consumed.frontend_code_challenge.is_none());
    assert!(consumed.frontend_state.is_none());
}
