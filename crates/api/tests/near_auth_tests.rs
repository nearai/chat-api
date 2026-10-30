mod common;

use common::create_test_server;
use serde_json::json;

#[tokio::test]
async fn near_auth_returns_bad_request_for_over_long_public_key() {
    let server = create_test_server().await;

    let response = server
        .post("/v1/auth/near")
        .json(&json!({
            "signed_message": {
                "accountId": "alice.near",
                "publicKey": format!("ed25519:{}", "1".repeat(65_536)),
                "signature": "",
            },
            "payload": {
                "message": "Sign in",
                "nonce": vec![0u8; 32],
                "recipient": "near.ai",
            },
        }))
        .await;

    assert_eq!(response.status_code(), 400);
    let body: serde_json::Value = response.json();
    assert_eq!(
        body["message"],
        "Invalid public key length: expected at most 3000, got 65544"
    );
}
