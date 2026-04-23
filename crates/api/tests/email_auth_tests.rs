mod common;

use common::{create_test_server_and_db, TestServerConfig};
use serde_json::json;
use serial_test::serial;
use services::user::ports::UserRepository;
use uuid::Uuid;
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_TURNSTILE_TOKEN: &str = "test-turnstile-token";

fn set_email_auth_env() {
    std::env::set_var("RESEND_API_KEY", "test-resend-key");
    std::env::set_var("EMAIL_FROM", "auth@example.com");
    std::env::set_var("EMAIL_OTP_TURNSTILE_SECRET_KEY", "test-turnstile-secret");
    std::env::set_var(
        "EMAIL_OTP_HMAC_SECRET",
        "test-email-auth-secret-test-email-auth-secret",
    );
    std::env::set_var("EMAIL_OTP_TTL_MINUTES", "10");
    std::env::set_var("EMAIL_OTP_RATE_LIMIT_PER_HOUR", "10");
    std::env::set_var("EMAIL_OTP_MAX_VERIFY_ATTEMPTS", "5");
    std::env::set_var("EMAIL_OTP_VERIFY_FAILURES_PER_HOUR", "20");
    std::env::set_var("EMAIL_OTP_REQUESTS_PER_IP_PER_HOUR", "30");
    std::env::set_var("EMAIL_OTP_VERIFIES_PER_IP_PER_HOUR", "60");
}

fn unique_email(prefix: &str) -> String {
    format!("{prefix}-{}@example.com", Uuid::new_v4())
}

fn unique_ip() -> String {
    let bytes = Uuid::new_v4().into_bytes();
    format!("10.{}.{}.{}", bytes[0], bytes[1], bytes[2])
}

async fn request_email_code(
    server: &axum_test::TestServer,
    email: &str,
    ip: &str,
) -> axum_test::TestResponse {
    request_email_code_with_token(server, email, ip, TEST_TURNSTILE_TOKEN).await
}

async fn request_email_code_with_token(
    server: &axum_test::TestServer,
    email: &str,
    ip: &str,
    turnstile_token: &str,
) -> axum_test::TestResponse {
    server
        .post("/v1/auth/email/request-code")
        .add_header(
            http::HeaderName::from_static("x-real-ip"),
            http::HeaderValue::from_str(ip).expect("valid ip header"),
        )
        .json(&json!({
            "email": email,
            "turnstile_token": turnstile_token,
        }))
        .await
}

async fn mount_turnstile_success(resend: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/turnstile/siteverify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "success": true })))
        .mount(resend)
        .await;
}

async fn mount_turnstile_failure(resend: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/turnstile/siteverify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": false,
            "error-codes": ["invalid-input-response"]
        })))
        .mount(resend)
        .await;
}

async fn verify_email_code(
    server: &axum_test::TestServer,
    email: &str,
    code: &str,
    ip: &str,
) -> axum_test::TestResponse {
    server
        .post("/v1/auth/email/verify-code")
        .add_header(
            http::HeaderName::from_static("x-real-ip"),
            http::HeaderValue::from_str(ip).expect("valid ip header"),
        )
        .json(&json!({
            "email": email,
            "code": code,
        }))
        .await
}

fn compute_code_mac(email: &str, code: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(b"test-email-auth-secret-test-email-auth-secret")
        .expect("valid hmac key");
    mac.update(email.as_bytes());
    mac.update(b"|");
    mac.update(code.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

async fn cleanup_email_auth_state(db: &database::Database, email: &str) {
    let client = db.pool().get().await.expect("get pool client");
    client
        .execute(
            "DELETE FROM email_verification_challenges WHERE email = $1",
            &[&email],
        )
        .await
        .ok();

    if let Some(user) = db
        .user_repository()
        .get_user_by_email(email)
        .await
        .expect("get user by email")
    {
        client
            .execute(
                "UPDATE sessions SET expires_at = NOW() WHERE user_id = $1",
                &[&user.id],
            )
            .await
            .ok();
    }
}

async fn latest_challenge_id(db: &database::Database, email: &str) -> Uuid {
    let client = db.pool().get().await.expect("db client");
    let row = client
        .query_one(
            "SELECT id FROM email_verification_challenges WHERE email = $1 ORDER BY created_at DESC LIMIT 1",
            &[&email],
        )
        .await
        .expect("query latest challenge");
    row.get(0)
}

async fn set_latest_challenge_code(db: &database::Database, email: &str, code: &str) -> Uuid {
    let challenge_id = latest_challenge_id(db, email).await;
    let code_mac = compute_code_mac(email, code);
    let client = db.pool().get().await.expect("db client");
    client
        .execute(
            "UPDATE email_verification_challenges SET code_mac = $2, status = 'sent' WHERE id = $1",
            &[&challenge_id, &code_mac],
        )
        .await
        .expect("update challenge mac");
    challenge_id
}

async fn insert_failed_challenge(db: &database::Database, email: &str, ip: &str) {
    let ip_addr = ip.parse::<std::net::IpAddr>().expect("valid ip");
    let client = db.pool().get().await.expect("db client");
    client
        .execute(
            "INSERT INTO email_verification_challenges
                (id, email, code_mac, ip_address, status, expires_at)
             VALUES ($1, $2, $3, $4, 'failed', NOW() + INTERVAL '10 minutes')",
            &[&Uuid::new_v4(), &email, &"failed-mac", &ip_addr],
        )
        .await
        .expect("insert failed challenge");
}

#[tokio::test]
#[serial]
async fn test_request_email_code_returns_204_and_persists_sent_challenge() {
    let resend = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/emails"))
        .and(header("authorization", "Bearer test-resend-key"))
        .and(body_partial_json(json!({
            "from": "auth@example.com",
            "subject": "Your NEAR AI verification code"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "email_123" })))
        .mount(&resend)
        .await;
    mount_turnstile_success(&resend).await;

    set_email_auth_env();

    let (server, db) = create_test_server_and_db(TestServerConfig {
        email_resend_base_url: Some(resend.uri()),
        email_auth_enabled: Some(true),
        ..Default::default()
    })
    .await;

    let email = unique_email("email-auth-request");
    let ip = unique_ip();
    cleanup_email_auth_state(&db, &email).await;

    let response = request_email_code(&server, &email, &ip).await;

    assert_eq!(response.status_code(), 204);

    let client = db.pool().get().await.expect("db client");
    let row = client
        .query_one(
            "SELECT status, provider_message_id FROM email_verification_challenges WHERE email = $1 ORDER BY created_at DESC LIMIT 1",
            &[&email],
        )
        .await
        .expect("query latest challenge");

    let status: String = row.get(0);
    let provider_message_id: Option<String> = row.get(1);
    assert_eq!(status, "sent");
    assert_eq!(provider_message_id.as_deref(), Some("email_123"));
}

#[tokio::test]
#[serial]
async fn test_request_email_code_requires_turnstile_token() {
    set_email_auth_env();

    let (server, _db) = create_test_server_and_db(TestServerConfig {
        email_auth_enabled: Some(true),
        ..Default::default()
    })
    .await;

    let response = server
        .post("/v1/auth/email/request-code")
        .json(&json!({ "email": unique_email("email-auth-missing-turnstile") }))
        .await;

    assert_eq!(response.status_code(), 422);
}

#[tokio::test]
#[serial]
async fn test_request_email_code_rejects_when_turnstile_verification_fails() {
    let resend = MockServer::start().await;
    mount_turnstile_failure(&resend).await;

    set_email_auth_env();

    let (server, db) = create_test_server_and_db(TestServerConfig {
        email_resend_base_url: Some(resend.uri()),
        email_auth_enabled: Some(true),
        ..Default::default()
    })
    .await;

    let email = unique_email("email-auth-turnstile-failed");
    let ip = unique_ip();
    cleanup_email_auth_state(&db, &email).await;

    let response = request_email_code_with_token(&server, &email, &ip, "invalid-token").await;
    assert_eq!(response.status_code(), 401);

    let client = db.pool().get().await.expect("db client");
    let row = client
        .query_one(
            "SELECT COUNT(*)::bigint FROM email_verification_challenges WHERE email = $1",
            &[&email],
        )
        .await
        .expect("count challenges");
    let challenge_count: i64 = row.get(0);
    assert_eq!(challenge_count, 0);
}

#[tokio::test]
#[serial]
async fn test_verify_email_code_logs_into_existing_user() {
    let resend = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/emails"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "email_456" })))
        .mount(&resend)
        .await;
    mount_turnstile_success(&resend).await;

    set_email_auth_env();

    let (server, db) = create_test_server_and_db(TestServerConfig {
        email_resend_base_url: Some(resend.uri()),
        email_auth_enabled: Some(true),
        ..Default::default()
    })
    .await;

    let email = unique_email("existing-oauth-user");
    let ip = unique_ip();
    cleanup_email_auth_state(&db, &email).await;

    let existing_user = db
        .user_repository()
        .create_user(email.clone(), Some("Existing User".to_string()), None)
        .await
        .expect("create existing user");

    let request_response = request_email_code(&server, &email, &ip).await;
    assert_eq!(request_response.status_code(), 204);

    set_latest_challenge_code(&db, &email, "123456").await;

    let response = verify_email_code(&server, &email, "123456", &ip).await;

    assert_eq!(response.status_code(), 200);
    let body: serde_json::Value = response.json();
    assert_eq!(body["is_new_user"], false);
    assert!(body["token"].as_str().is_some());
    assert!(body["session_id"].as_str().is_some());

    let user = db
        .user_repository()
        .get_user_by_email(&email)
        .await
        .expect("get user by email")
        .expect("user exists");
    assert_eq!(user.id, existing_user.id);
}

#[tokio::test]
#[serial]
async fn test_email_auth_normalizes_email_case_across_request_and_verify() {
    let resend = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/emails"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "email_case" })))
        .mount(&resend)
        .await;
    mount_turnstile_success(&resend).await;

    set_email_auth_env();

    let (server, db) = create_test_server_and_db(TestServerConfig {
        email_resend_base_url: Some(resend.uri()),
        email_auth_enabled: Some(true),
        ..Default::default()
    })
    .await;

    let normalized_email = unique_email("email-auth-case");
    let mixed_case_email = normalized_email.to_uppercase();
    let ip = unique_ip();
    cleanup_email_auth_state(&db, &normalized_email).await;

    let request_response = request_email_code(&server, &mixed_case_email, &ip).await;
    assert_eq!(request_response.status_code(), 204);

    set_latest_challenge_code(&db, &normalized_email, "123456").await;

    let verify_response = verify_email_code(&server, &normalized_email, "123456", &ip).await;
    assert_eq!(verify_response.status_code(), 200);

    let user = db
        .user_repository()
        .get_user_by_email(&normalized_email)
        .await
        .expect("get normalized user")
        .expect("normalized user should exist");
    assert_eq!(user.email, normalized_email);
}

#[tokio::test]
#[serial]
async fn test_request_email_code_invalidates_previous_challenge() {
    let resend = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/emails"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "email_resend" })))
        .mount(&resend)
        .await;
    mount_turnstile_success(&resend).await;

    set_email_auth_env();

    let (server, db) = create_test_server_and_db(TestServerConfig {
        email_resend_base_url: Some(resend.uri()),
        email_auth_enabled: Some(true),
        ..Default::default()
    })
    .await;

    let email = unique_email("email-auth-resend");
    let ip = unique_ip();
    cleanup_email_auth_state(&db, &email).await;

    let first = request_email_code(&server, &email, &ip).await;
    assert_eq!(first.status_code(), 204);

    let second = request_email_code(&server, &email, &ip).await;
    assert_eq!(second.status_code(), 204);

    let client = db.pool().get().await.expect("db client");
    let rows = client
        .query(
            "SELECT id, status FROM email_verification_challenges WHERE email = $1 ORDER BY created_at ASC",
            &[&email],
        )
        .await
        .expect("query challenges");

    assert_eq!(rows.len(), 2);
    let first_id: Uuid = rows[0].get(0);
    let first_status: String = rows[0].get(1);
    let second_id: Uuid = rows[1].get(0);
    let second_status: String = rows[1].get(1);
    assert_eq!(first_status, "invalidated");
    assert_eq!(second_status, "sent");

    let first_mac = compute_code_mac(&email, "111111");
    let second_mac = compute_code_mac(&email, "222222");
    client
        .execute(
            "UPDATE email_verification_challenges SET code_mac = $2 WHERE id = $1",
            &[&first_id, &first_mac],
        )
        .await
        .expect("update first challenge mac");
    client
        .execute(
            "UPDATE email_verification_challenges SET code_mac = $2 WHERE id = $1",
            &[&second_id, &second_mac],
        )
        .await
        .expect("update second challenge mac");

    let old_code_response = verify_email_code(&server, &email, "111111", &ip).await;
    assert_eq!(old_code_response.status_code(), 401);

    let new_code_response = verify_email_code(&server, &email, "222222", &ip).await;
    assert_eq!(new_code_response.status_code(), 200);
}

#[tokio::test]
#[serial]
async fn test_verify_email_code_cannot_be_replayed() {
    let resend = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/emails"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "email_replay" })))
        .mount(&resend)
        .await;
    mount_turnstile_success(&resend).await;

    set_email_auth_env();

    let (server, db) = create_test_server_and_db(TestServerConfig {
        email_resend_base_url: Some(resend.uri()),
        email_auth_enabled: Some(true),
        ..Default::default()
    })
    .await;

    let email = unique_email("email-auth-replay");
    let ip = unique_ip();
    cleanup_email_auth_state(&db, &email).await;

    let request_response = request_email_code(&server, &email, &ip).await;
    assert_eq!(request_response.status_code(), 204);

    let challenge_id = set_latest_challenge_code(&db, &email, "123456").await;

    let first_verify = verify_email_code(&server, &email, "123456", &ip).await;
    assert_eq!(first_verify.status_code(), 200);

    let replay_verify = verify_email_code(&server, &email, "123456", &ip).await;
    assert_eq!(replay_verify.status_code(), 401);

    let client = db.pool().get().await.expect("db client");
    let row = client
        .query_one(
            "SELECT status FROM email_verification_challenges WHERE id = $1",
            &[&challenge_id],
        )
        .await
        .expect("query consumed challenge");
    let status: String = row.get(0);
    assert_eq!(status, "consumed");
}

#[tokio::test]
#[serial]
async fn test_wrong_code_attempts_eventually_invalidate_challenge() {
    let resend = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/emails"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "email_attempts" })))
        .mount(&resend)
        .await;
    mount_turnstile_success(&resend).await;

    set_email_auth_env();
    std::env::set_var("EMAIL_OTP_MAX_VERIFY_ATTEMPTS", "2");

    let (server, db) = create_test_server_and_db(TestServerConfig {
        email_resend_base_url: Some(resend.uri()),
        email_auth_enabled: Some(true),
        ..Default::default()
    })
    .await;

    let email = unique_email("email-auth-attempts");
    let ip = unique_ip();
    cleanup_email_auth_state(&db, &email).await;

    let request_response = request_email_code(&server, &email, &ip).await;
    assert_eq!(request_response.status_code(), 204);

    let challenge_id = set_latest_challenge_code(&db, &email, "123456").await;

    for _ in 0..2 {
        let wrong_response = verify_email_code(&server, &email, "000000", &ip).await;
        assert_eq!(wrong_response.status_code(), 401);
    }

    let client = db.pool().get().await.expect("db client");
    let row = client
        .query_one(
            "SELECT status, attempt_count FROM email_verification_challenges WHERE id = $1",
            &[&challenge_id],
        )
        .await
        .expect("query invalidated challenge");
    let status: String = row.get(0);
    let attempt_count: i32 = row.get(1);
    assert_eq!(status, "invalidated");
    assert_eq!(attempt_count, 2);

    let correct_response = verify_email_code(&server, &email, "123456", &ip).await;
    assert_eq!(correct_response.status_code(), 401);
}

#[tokio::test]
#[serial]
async fn test_expired_challenge_cannot_be_verified() {
    let resend = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/emails"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "email_expired" })))
        .mount(&resend)
        .await;
    mount_turnstile_success(&resend).await;

    set_email_auth_env();

    let (server, db) = create_test_server_and_db(TestServerConfig {
        email_resend_base_url: Some(resend.uri()),
        email_auth_enabled: Some(true),
        ..Default::default()
    })
    .await;

    let email = unique_email("email-auth-expired");
    let ip = unique_ip();
    cleanup_email_auth_state(&db, &email).await;

    let request_response = request_email_code(&server, &email, &ip).await;
    assert_eq!(request_response.status_code(), 204);

    let challenge_id = set_latest_challenge_code(&db, &email, "123456").await;
    let client = db.pool().get().await.expect("db client");
    client
        .execute(
            "UPDATE email_verification_challenges SET expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1",
            &[&challenge_id],
        )
        .await
        .expect("expire challenge");

    let response = verify_email_code(&server, &email, "123456", &ip).await;
    assert_eq!(response.status_code(), 401);
}

#[tokio::test]
#[serial]
async fn test_failed_delivery_marks_challenge_failed_and_non_verifiable() {
    let resend = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/emails"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&resend)
        .await;
    mount_turnstile_success(&resend).await;

    set_email_auth_env();

    let (server, db) = create_test_server_and_db(TestServerConfig {
        email_resend_base_url: Some(resend.uri()),
        email_auth_enabled: Some(true),
        ..Default::default()
    })
    .await;

    let email = unique_email("email-auth-failed-delivery");
    let ip = unique_ip();
    cleanup_email_auth_state(&db, &email).await;

    let request_response = request_email_code(&server, &email, &ip).await;
    assert_eq!(request_response.status_code(), 500);

    let client = db.pool().get().await.expect("db client");
    let row = client
        .query_one(
            "SELECT id, status FROM email_verification_challenges WHERE email = $1 ORDER BY created_at DESC LIMIT 1",
            &[&email],
        )
        .await
        .expect("query failed challenge");
    let challenge_id: Uuid = row.get(0);
    let status: String = row.get(1);
    assert_eq!(status, "failed");

    let code_mac = compute_code_mac(&email, "123456");
    client
        .execute(
            "UPDATE email_verification_challenges SET code_mac = $2 WHERE id = $1",
            &[&challenge_id, &code_mac],
        )
        .await
        .expect("update failed challenge mac");

    let verify_response = verify_email_code(&server, &email, "123456", &ip).await;
    assert_eq!(verify_response.status_code(), 401);
}

#[tokio::test]
#[serial]
async fn test_request_email_code_rate_limit_skips_creating_additional_challenge() {
    let resend = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/emails"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "email_limit" })))
        .mount(&resend)
        .await;
    mount_turnstile_success(&resend).await;

    set_email_auth_env();
    std::env::set_var("EMAIL_OTP_RATE_LIMIT_PER_HOUR", "1");

    let (server, db) = create_test_server_and_db(TestServerConfig {
        email_resend_base_url: Some(resend.uri()),
        email_auth_enabled: Some(true),
        ..Default::default()
    })
    .await;

    let email = unique_email("email-auth-request-limit");
    let ip = unique_ip();
    cleanup_email_auth_state(&db, &email).await;

    let first = request_email_code(&server, &email, &ip).await;
    assert_eq!(first.status_code(), 204);

    let second = request_email_code(&server, &email, &ip).await;
    assert_eq!(second.status_code(), 204);

    let client = db.pool().get().await.expect("db client");
    let row = client
        .query_one(
            "SELECT COUNT(*)::bigint FROM email_verification_challenges WHERE email = $1",
            &[&email],
        )
        .await
        .expect("count challenges");
    let challenge_count: i64 = row.get(0);
    assert_eq!(challenge_count, 1);
}

#[tokio::test]
#[serial]
async fn test_failed_challenge_does_not_consume_request_rate_limit() {
    let resend = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/emails"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "id": "email_after_failure" })),
        )
        .mount(&resend)
        .await;
    mount_turnstile_success(&resend).await;

    set_email_auth_env();
    std::env::set_var("EMAIL_OTP_RATE_LIMIT_PER_HOUR", "1");

    let (server, db) = create_test_server_and_db(TestServerConfig {
        email_resend_base_url: Some(resend.uri()),
        email_auth_enabled: Some(true),
        ..Default::default()
    })
    .await;

    let email = unique_email("email-auth-failed-rate-limit");
    let ip = unique_ip();
    cleanup_email_auth_state(&db, &email).await;
    insert_failed_challenge(&db, &email, &ip).await;

    let response = request_email_code(&server, &email, &ip).await;
    assert_eq!(response.status_code(), 204);

    let client = db.pool().get().await.expect("db client");
    let row = client
        .query_one(
            "SELECT COUNT(*)::bigint,
                    COUNT(*) FILTER (WHERE status = 'sent')::bigint
             FROM email_verification_challenges
             WHERE email = $1",
            &[&email],
        )
        .await
        .expect("count challenges after failed challenge");
    let total_count: i64 = row.get(0);
    let sent_count: i64 = row.get(1);
    assert_eq!(total_count, 2);
    assert_eq!(sent_count, 1);
}

#[tokio::test]
#[serial]
async fn test_verify_email_code_rate_limit_blocks_after_failed_attempt() {
    let resend = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/emails"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "id": "email_verify_limit" })),
        )
        .mount(&resend)
        .await;
    mount_turnstile_success(&resend).await;

    set_email_auth_env();
    std::env::set_var("EMAIL_OTP_VERIFY_FAILURES_PER_HOUR", "1");
    std::env::set_var("EMAIL_OTP_MAX_VERIFY_ATTEMPTS", "5");

    let (server, db) = create_test_server_and_db(TestServerConfig {
        email_resend_base_url: Some(resend.uri()),
        email_auth_enabled: Some(true),
        ..Default::default()
    })
    .await;

    let email = unique_email("email-auth-verify-limit");
    let ip = unique_ip();
    cleanup_email_auth_state(&db, &email).await;

    let request_response = request_email_code(&server, &email, &ip).await;
    assert_eq!(request_response.status_code(), 204);

    let challenge_id = set_latest_challenge_code(&db, &email, "123456").await;

    let wrong_response = verify_email_code(&server, &email, "000000", &ip).await;
    assert_eq!(wrong_response.status_code(), 401);

    let blocked_response = verify_email_code(&server, &email, "123456", &ip).await;
    assert_eq!(blocked_response.status_code(), 401);

    let client = db.pool().get().await.expect("db client");
    let row = client
        .query_one(
            "SELECT status, attempt_count FROM email_verification_challenges WHERE id = $1",
            &[&challenge_id],
        )
        .await
        .expect("query rate-limited challenge");
    let status: String = row.get(0);
    let attempt_count: i32 = row.get(1);
    assert_eq!(status, "sent");
    assert_eq!(attempt_count, 1);
}

#[tokio::test]
#[serial]
async fn test_concurrent_verify_only_allows_one_success() {
    let resend = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/emails"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "email_concurrent" })))
        .mount(&resend)
        .await;
    mount_turnstile_success(&resend).await;

    set_email_auth_env();

    let (server, db) = create_test_server_and_db(TestServerConfig {
        email_resend_base_url: Some(resend.uri()),
        email_auth_enabled: Some(true),
        ..Default::default()
    })
    .await;

    let email = unique_email("email-auth-concurrent");
    let ip = unique_ip();
    cleanup_email_auth_state(&db, &email).await;

    let request_response = request_email_code(&server, &email, &ip).await;
    assert_eq!(request_response.status_code(), 204);

    set_latest_challenge_code(&db, &email, "123456").await;

    let request_one = server
        .post("/v1/auth/email/verify-code")
        .add_header(
            http::HeaderName::from_static("x-real-ip"),
            http::HeaderValue::from_str(&ip).expect("valid ip header"),
        )
        .json(&json!({
            "email": email,
            "code": "123456",
        }));
    let request_two = server
        .post("/v1/auth/email/verify-code")
        .add_header(
            http::HeaderName::from_static("x-real-ip"),
            http::HeaderValue::from_str(&ip).expect("valid ip header"),
        )
        .json(&json!({
            "email": email,
            "code": "123456",
        }));

    let (response_one, response_two) = tokio::join!(request_one, request_two);
    let mut status_codes = vec![
        response_one.status_code().as_u16(),
        response_two.status_code().as_u16(),
    ];
    status_codes.sort_unstable();
    assert_eq!(status_codes, vec![200, 401]);

    let user = db
        .user_repository()
        .get_user_by_email(&email)
        .await
        .expect("get user by email")
        .expect("user exists");
    let client = db.pool().get().await.expect("db client");
    let row = client
        .query_one(
            "SELECT COUNT(*)::bigint FROM sessions WHERE user_id = $1 AND expires_at > NOW()",
            &[&user.id],
        )
        .await
        .expect("count active sessions");
    let session_count: i64 = row.get(0);
    assert_eq!(session_count, 1);
}
