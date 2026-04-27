mod common;

use api::routes::api::USER_BANNED_ERROR_MESSAGE;
use axum_test::TestServer;
use common::{
    clear_subscription_plans, create_test_server_and_db, insert_test_subscription,
    insert_test_subscription_with_price_id, mock_login, set_subscription_plans,
};
use serde_json::json;
use serial_test::serial;
use services::user::ports::UserRepository;
use tokio::time::sleep;

/// Comprehensive cleanup for a user: clear bans, subscriptions, sessions, and oauth links
/// This prevents state from one test leaking into another when reusing the same email.
/// NOTE: Does NOT delete the user itself to avoid affecting other tests that query users.
async fn cleanup_user_completely(db: &database::Database, user_email: &str) {
    let user = match db
        .user_repository()
        .get_user_by_email(user_email)
        .await
        .expect("get user")
    {
        Some(u) => u,
        None => return, // User doesn't exist, nothing to clean
    };

    let client = db.pool().get().await.expect("get pool client");

    // Delete subscriptions
    client
        .execute("DELETE FROM subscriptions WHERE user_id = $1", &[&user.id])
        .await
        .ok();

    // Delete or revoke sessions (set expires_at to now so they're invalid)
    client
        .execute(
            "UPDATE user_sessions SET expires_at = NOW() WHERE user_id = $1",
            &[&user.id],
        )
        .await
        .ok();

    // Revoke user bans
    client
        .execute(
            "UPDATE user_bans SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL",
            &[&user.id],
        )
        .await
        .ok();

    // Delete oauth links
    client
        .execute(
            "DELETE FROM user_oauth_links WHERE user_id = $1",
            &[&user.id],
        )
        .await
        .ok();
}

async fn wait_for_near_balance_ban(
    server: &TestServer,
    token: &str,
    request_body: serde_json::Value,
) -> axum_test::TestResponse {
    let mut last_response = None;

    for _ in 0..10 {
        sleep(std::time::Duration::from_millis(1100)).await;

        let response = server
            .post("/v1/responses")
            .add_header(
                http::HeaderName::from_static("authorization"),
                http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
            )
            .json(&request_body)
            .await;

        if response.status_code() == 403 {
            return response;
        }

        last_response = Some(response);
    }

    let response = last_response.expect("should have attempted at least one follow-up request");
    panic!(
        "expected NEAR balance ban to return 403, got {} after waiting for async check",
        response.status_code()
    );
}

/// When user has no NEAR-linked account, NEAR balance check should be skipped
/// and /v1/responses should not return 403 due to balance.
#[tokio::test]
#[serial(subscription_tests)]
async fn test_near_balance_skipped_when_no_near_linked_account() {
    let (server, db) = create_test_server_and_db(Default::default()).await;
    clear_subscription_plans(&server).await;
    cleanup_user_completely(&db, "no-near@example.com").await;

    // Use mock_login helper which does NOT set oauth_provider, so no NEAR linked account
    let token = mock_login(&server, "no-near@example.com").await;

    let response = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&json!({
            "input": "Hello"
        }))
        .await;

    assert_ne!(
        response.status_code(),
        403,
        "Request without NEAR-linked account should not be blocked by NEAR balance check"
    );
}

/// Integration test that verifies NEAR balance gating for a real NEAR account.
#[tokio::test]
async fn test_near_balance_allows_rich_account() {
    let (server, db) = create_test_server_and_db(Default::default()).await;

    // Real account in mainnet
    let rich_account = "near";
    let user_email = format!("{}@near", rich_account);
    cleanup_user_completely(&db, &user_email).await;

    let login_request = json!({
        "email": user_email.clone(),
        "name": "Rich NEAR User",
        "oauth_provider": "near"
    });

    let response = server
        .post("/v1/auth/mock-login")
        .json(&login_request)
        .await;

    assert_eq!(
        response.status_code(),
        200,
        "Mock login with NEAR provider should succeed"
    );

    let body: serde_json::Value = response.json();
    let token = body
        .get("token")
        .and_then(|v| v.as_str())
        .expect("Auth response should contain token");

    let response = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&json!({
            "input": "Hello"
        }))
        .await;

    assert_ne!(
        response.status_code(),
        403,
        "Rich NEAR account should not be blocked by NEAR balance check"
    );
}

/// Integration test that verifies NEAR balance gating blocks a "poor" NEAR account.
#[tokio::test]
async fn test_near_balance_blocks_poor_account() {
    let (server, db) = create_test_server_and_db(Default::default()).await;

    // Real account in mainnet
    let poor_account = "zero-balance.near";
    let user_email = format!("{}@near", poor_account);
    cleanup_user_completely(&db, &user_email).await;

    let login_request = json!({
        "email": format!("{}@near", poor_account),
        "name": "Poor NEAR User",
        "oauth_provider": "near"
    });

    let response = server
        .post("/v1/auth/mock-login")
        .json(&login_request)
        .await;

    assert_eq!(
        response.status_code(),
        200,
        "Mock login with NEAR provider should succeed for poor account"
    );

    let body: serde_json::Value = response.json();
    let token = body
        .get("token")
        .and_then(|v| v.as_str())
        .expect("Auth response should contain token");

    let first_response = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&json!({
            "input": "Hello"
        }))
        .await;

    // First call should NOT yet be blocked by NEAR balance check, since the check is asynchronous
    assert_ne!(
        first_response.status_code(),
        403,
        "First request from poor NEAR account should not be synchronously blocked"
    );

    let second_response = wait_for_near_balance_ban(
        &server,
        token,
        json!({
            "input": "Hello again"
        }),
    )
    .await;

    assert_eq!(
        second_response.status_code(),
        403,
        "Subsequent requests from poor NEAR account should be blocked by NEAR balance ban"
    );

    let body: serde_json::Value = second_response.json();
    let error = body.get("error").and_then(|v| v.as_str());
    assert_eq!(
        error,
        Some(USER_BANNED_ERROR_MESSAGE),
        "Ban error message should indicate a temporary ban without exposing NEAR balance details"
    );
}

/// Paid user (plan with price > 0) with NEAR account skips NEAR balance check.
#[tokio::test]
#[serial(subscription_tests)]
async fn test_near_balance_skipped_for_paid_subscription() {
    let (server, db) = create_test_server_and_db(Default::default()).await;

    // Plan with price 999 (paid) - matches insert_test_subscription's price_test_basic
    set_subscription_plans(
        &server,
        json!({
            "basic": {
                "providers": { "stripe": { "price_id": "price_test_basic" } },
                "price": 999,
                "monthly_tokens": { "max": 1000000 }
            }
        }),
    )
    .await;

    let user_email = "near@near";
    cleanup_user_completely(&db, user_email).await;

    // Login with NEAR provider (rich account "near" to avoid balance issues)
    let login_request = json!({
        "email": user_email,
        "name": "Paid NEAR User",
        "oauth_provider": "near"
    });
    let login_resp = server
        .post("/v1/auth/mock-login")
        .json(&login_request)
        .await;
    assert_eq!(login_resp.status_code(), 200);
    let body: serde_json::Value = login_resp.json();
    let token = body
        .get("token")
        .and_then(|v| v.as_str())
        .expect("Auth response should contain token");

    insert_test_subscription(&server, &db, user_email, false).await;

    let response = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&json!({
            "input": "Hello"
        }))
        .await;

    assert_ne!(
        response.status_code(),
        403,
        "Paid user with NEAR account should skip NEAR balance check"
    );
}

/// Free plan user (price = 0) with poor NEAR account still gets NEAR balance check and ban.
#[tokio::test]
#[serial(subscription_tests)]
async fn test_near_balance_check_applied_for_free_plan_subscription() {
    let (server, db) = create_test_server_and_db(Default::default()).await;

    set_subscription_plans(
        &server,
        json!({
            "free": {
                "providers": { "stripe": { "price_id": "price_test_free" } },
                "price": 0,
                "monthly_tokens": { "max": 1000000 }
            }
        }),
    )
    .await;

    let poor_account = "zero-balance-3.near";
    let user_email = format!("{}@near", poor_account);
    cleanup_user_completely(&db, &user_email).await;

    let login_request = json!({
        "email": user_email,
        "name": "Free Plan NEAR User",
        "oauth_provider": "near"
    });
    let login_resp = server
        .post("/v1/auth/mock-login")
        .json(&login_request)
        .await;
    assert_eq!(login_resp.status_code(), 200);
    let body: serde_json::Value = login_resp.json();
    let token = body
        .get("token")
        .and_then(|v| v.as_str())
        .expect("Auth response should contain token");

    insert_test_subscription_with_price_id(&server, &db, &user_email, false, "price_test_free")
        .await;

    let first_response = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&json!({
            "input": "Hello"
        }))
        .await;

    assert_ne!(
        first_response.status_code(),
        403,
        "First request from free plan + poor NEAR should not be synchronously blocked"
    );

    let second_response = wait_for_near_balance_ban(
        &server,
        token,
        json!({
            "input": "Hello again"
        }),
    )
    .await;

    assert_eq!(
        second_response.status_code(),
        403,
        "Free plan user with poor NEAR account should be blocked after async balance check"
    );

    let body: serde_json::Value = second_response.json();
    let error = body.get("error").and_then(|v| v.as_str());
    assert_eq!(
        error,
        Some(USER_BANNED_ERROR_MESSAGE),
        "Ban error message should indicate a temporary ban without exposing NEAR balance details"
    );
}

/// Unknown price_id (not in config) is not treated as paid; NEAR balance check applies.
#[tokio::test]
#[serial(subscription_tests)]
async fn test_near_balance_check_applied_for_unknown_price_id() {
    let (server, db) = create_test_server_and_db(Default::default()).await;

    // Config only has "basic" - subscription uses price_unknown which is not in config
    set_subscription_plans(
        &server,
        json!({
            "basic": {
                "providers": { "stripe": { "price_id": "price_test_basic" } },
                "price": 999,
                "monthly_tokens": { "max": 1000000 }
            }
        }),
    )
    .await;

    let poor_account = "zero-balance-4.near";
    let user_email = format!("{}@near", poor_account);
    cleanup_user_completely(&db, &user_email).await;

    let login_request = json!({
        "email": user_email,
        "name": "Unknown Price NEAR User",
        "oauth_provider": "near"
    });
    let login_resp = server
        .post("/v1/auth/mock-login")
        .json(&login_request)
        .await;
    assert_eq!(login_resp.status_code(), 200);
    let body: serde_json::Value = login_resp.json();
    let token = body
        .get("token")
        .and_then(|v| v.as_str())
        .expect("Auth response should contain token");

    insert_test_subscription_with_price_id(&server, &db, &user_email, false, "price_unknown").await;

    let first_response = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&json!({
            "input": "Hello"
        }))
        .await;

    assert_ne!(
        first_response.status_code(),
        403,
        "First request from unknown price_id + poor NEAR should not be synchronously blocked"
    );

    let second_response = wait_for_near_balance_ban(
        &server,
        token,
        json!({
            "input": "Hello again"
        }),
    )
    .await;

    assert_eq!(
        second_response.status_code(),
        403,
        "User with unknown price_id and poor NEAR account should be blocked by NEAR balance check"
    );

    let body: serde_json::Value = second_response.json();
    let error = body.get("error").and_then(|v| v.as_str());
    assert_eq!(
        error,
        Some(USER_BANNED_ERROR_MESSAGE),
        "Ban error message should indicate a temporary ban without exposing NEAR balance details"
    );
}
