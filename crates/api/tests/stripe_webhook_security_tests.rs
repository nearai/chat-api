mod common;

use common::{create_test_server_and_db, TestServerConfig};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;
use uuid::Uuid;

#[tokio::test]
async fn webhook_rejects_incomplete_configuration_without_storing_event() {
    for (api_key, secret) in [("sk_test", ""), ("", "whsec_test"), ("sk_test", "   ")] {
        let (server, db) = create_test_server_and_db(TestServerConfig {
            stripe_config: Some(config::StripeConfig {
                secret_key: api_key.into(),
                webhook_secret: secret.into(),
                test_clock_enabled: false,
                refund_execution_enabled: false,
            }),
            ..Default::default()
        })
        .await;
        let event_id = format!("evt_{}", Uuid::new_v4());
        let body = json!({"id": event_id, "type": "test.unhandled"}).to_string();
        let ts = chrono::Utc::now().timestamp();
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(format!("{ts}.{body}").as_bytes());
        let signature = format!("t={ts},v1={}", hex::encode(mac.finalize().into_bytes()));
        server
            .post("/v1/subscriptions/stripe/webhook")
            .add_header(http::header::CONTENT_TYPE, "application/json")
            .add_header("stripe-signature", signature)
            .text(body)
            .await
            .assert_status(http::StatusCode::SERVICE_UNAVAILABLE);
        let client = db.pool().get().await.unwrap();
        let count: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM payment_webhooks WHERE event_id=$1",
                &[&event_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 0);
    }
}
