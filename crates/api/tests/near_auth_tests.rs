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

#[tokio::test]
async fn sunset_near_login_preserves_existing_users_and_rejects_new_accounts() {
    use common::{create_test_server_and_db, TestServerConfig};
    use near_kit::{signer::SecretKey, standards::nep413};
    use services::{
        auth::{
            near::{NearAuthService, SignedMessage},
            ports::SignupsClosed,
        },
        user::ports::{OAuthProvider, UserRepository},
    };
    use uuid::Uuid;
    use wiremock::{matchers::body_partial_json, Mock, MockServer, ResponseTemplate};

    let rpc = MockServer::start().await;
    Mock::given(body_partial_json(json!({"method":"EXPERIMENTAL_view_access_key"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc":"2.0", "id":1,
            "result":{"block_hash":"11111111111111111111111111111111","block_height":1,"nonce":0,"permission":"FullAccess"}
        })))
        .expect(2)
        .mount(&rpc).await;
    let (_, db) = create_test_server_and_db(TestServerConfig::default()).await;
    let auth = NearAuthService::new(
        db.session_repository(),
        db.user_repository(),
        db.near_nonce_repository(),
        rpc.uri().parse().unwrap(),
    );
    let key = SecretKey::ed25519_from_bytes([37; 32]);
    for existing in [false, true] {
        let account = format!("sunset-{}.testnet", Uuid::new_v4().simple());
        let email = format!("{account}@near");
        let user = if existing {
            let user = db
                .user_repository()
                .create_user(email.clone(), None, None)
                .await
                .unwrap();
            db.user_repository()
                .link_oauth_account(user.id, OAuthProvider::Near, account.clone())
                .await
                .unwrap();
            Some(user)
        } else {
            None
        };
        let payload = nep413::SignMessageParams {
            message: "Sign in to NEAR AI".into(),
            nonce: nep413::generate_nonce(),
            recipient: "private.near.ai".into(),
            callback_url: None,
            state: None,
        };
        let message = SignedMessage {
            account_id: account.parse().unwrap(),
            public_key: key.public_key(),
            signature: key.sign(nep413::serialize_message(&payload).as_bytes()),
            state: None,
        };
        let result = auth.verify_and_authenticate(message, payload).await;
        if let Some(user) = user {
            let (session, is_new) = result.unwrap();
            assert_eq!(session.user_id, user.id);
            assert!(!is_new);
        } else {
            assert!(result.unwrap_err().is::<SignupsClosed>());
            assert!(db
                .user_repository()
                .get_user_by_email(&email)
                .await
                .unwrap()
                .is_none());
        }
    }
}
