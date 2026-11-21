#![allow(unused_variables)]
mod common;
use async_trait::async_trait;
use common::{create_test_server_and_db, mock_login, TestServerConfig};
use serde_json::json;
use services::subscription::ports::*;
use services::subscription::refund_preview::{RefundInvoice, RefundInvoicePage};
use services::user::ports::UserRepository;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use uuid::Uuid;

struct PreviewStripe {
    reads: AtomicUsize,
}
#[async_trait]
impl StripeClientPort for PreviewStripe {
    async fn refund_preview_invoices(
        &self,
        subscription: &str,
        customer: &str,
        cursor: Option<&str>,
    ) -> Result<RefundInvoicePage, SubscriptionError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        assert!(subscription.starts_with("sub_"));
        assert_eq!(customer, "cus_test");
        if cursor == Some("in_error") {
            return Err(SubscriptionError::StripeError(
                "internal provider detail".into(),
            ));
        }
        Ok(RefundInvoicePage {
            has_more: cursor.is_none(),
            invoices: if cursor.is_some() {
                vec![]
            } else {
                vec![RefundInvoice {
                    invoice_id: "in_test".into(),
                    charge_id: Some("ch_test".into()),
                    currency: "usd".into(),
                    amount_paid: 1001,
                    amount_refunded: Some(0),
                    period_start: Some(100),
                    period_end: Some(200),
                    review_reason: None,
                }]
            },
        })
    }
    async fn verify_webhook_signature(
        &self,
        _payload: &[u8],
        _signature: &str,
        _secret: &str,
    ) -> Result<(), SubscriptionError> {
        panic!("Refund preview must not invoke unrelated Stripe operations")
    }
    async fn create_customer(
        &self,
        _email: Option<&str>,
        _name: Option<&str>,
        user_id: &str,
        _test_clock_id: Option<&str>,
    ) -> Result<String, SubscriptionError> {
        panic!("Refund preview must not invoke unrelated Stripe operations")
    }
    async fn retrieve_customer(
        &self,
        customer_id: &str,
    ) -> Result<StripeCustomerRef, SubscriptionError> {
        panic!("Refund preview must not invoke unrelated Stripe operations")
    }
    async fn create_subscription_checkout_session(
        &self,
        _params: StripeCreateSubscriptionCheckoutParams,
    ) -> Result<StripeCheckoutSessionResult, SubscriptionError> {
        panic!("Refund preview must not invoke unrelated Stripe operations")
    }
    async fn create_credits_checkout_session(
        &self,
        params: StripeCreateCreditsCheckoutParams,
    ) -> Result<StripeCheckoutSessionResult, SubscriptionError> {
        panic!("Refund preview must not invoke unrelated Stripe operations")
    }
    async fn retrieve_checkout_session(
        &self,
        _checkout_session_id: &str,
    ) -> Result<StripeCheckoutSessionResult, SubscriptionError> {
        panic!("Refund preview must not invoke unrelated Stripe operations")
    }
    async fn retrieve_subscription(
        &self,
        _subscription_id: &str,
    ) -> Result<StripeSubscriptionSnapshot, SubscriptionError> {
        panic!("Refund preview must not invoke unrelated Stripe operations")
    }
    async fn update_subscription(
        &self,
        _subscription_id: &str,
        _params: StripeUpdateSubscriptionParams,
    ) -> Result<StripeSubscriptionSnapshot, SubscriptionError> {
        panic!("Refund preview must not invoke unrelated Stripe operations")
    }
    async fn create_billing_portal_session(
        &self,
        _customer_id: &str,
        _return_url: &str,
    ) -> Result<StripePortalSessionResult, SubscriptionError> {
        panic!("Refund preview must not invoke unrelated Stripe operations")
    }
}

#[tokio::test]
async fn refund_preview_is_admin_only_read_only_and_scoped() {
    let stripe = Arc::new(PreviewStripe {
        reads: AtomicUsize::new(0),
    });
    let (server, db) = create_test_server_and_db(TestServerConfig {
        stripe_client: Some(stripe.clone()),
        stripe_config: Some(config::StripeConfig {
            secret_key: "sk_test_fixture".into(),
            ..Default::default()
        }),
        ..Default::default()
    })
    .await;
    let email = format!("refund-{}@example.com", Uuid::new_v4());
    let user_token = mock_login(&server, &email).await;
    let admin_token = mock_login(&server, "admin@admin.org").await;
    let user = db
        .user_repository()
        .get_user_by_email(&email)
        .await
        .unwrap()
        .unwrap();
    common::insert_test_subscription(&server, &db, &email, false).await;
    let subscription_id = format!("sub_{}", Uuid::new_v4().simple());
    let conn = db.pool().get().await.unwrap();
    conn.execute(
        "UPDATE subscriptions SET subscription_id=$1 WHERE user_id=$2",
        &[&subscription_id, &user.id],
    )
    .await
    .unwrap();
    let url = format!("/v1/admin/subscriptions/{subscription_id}/refund-preview");
    let body = json!({"user_id":user.id,"effective_at":"1970-01-01T00:02:30Z","method":"unused_seconds_floor"});
    assert_eq!(server.post(&url).json(&body).await.status_code(), 401);
    let auth = |token: &str| http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap();
    assert_eq!(
        server
            .post(&url)
            .add_header(http::header::AUTHORIZATION, auth(&user_token))
            .json(&body)
            .await
            .status_code(),
        403
    );
    assert_eq!(stripe.reads.load(Ordering::SeqCst), 0);
    let response = server
        .post(&url)
        .add_header(http::header::AUTHORIZATION, auth(&admin_token))
        .json(&body)
        .await;
    assert_eq!(response.status_code(), 200);
    let result: serde_json::Value = response.json();
    assert_eq!(result["preview_only"], true);
    assert_eq!(result["rows"][0]["estimated_refund"], 500);
    assert_eq!(result["next_cursor"], "in_test");
    assert!(result["rows"][0].get("customer").is_none());
    let mut next = body.clone();
    next["starting_after"] = "in_test".into();
    let result: serde_json::Value = server
        .post(&url)
        .add_header(http::header::AUTHORIZATION, auth(&admin_token))
        .json(&next)
        .await
        .json();
    assert_eq!(result["rows"], json!([]));
    assert!(result["next_cursor"].is_null());
    next["starting_after"] = "in_error".into();
    let failed = server
        .post(&url)
        .add_header(http::header::AUTHORIZATION, auth(&admin_token))
        .json(&next)
        .await;
    assert_eq!(failed.status_code(), 502);
    assert!(!failed.text().contains("internal provider detail"));
    let reads = stripe.reads.load(Ordering::SeqCst);
    next["starting_after"] = "in_bad/path".into();
    assert_eq!(
        server
            .post(&url)
            .add_header(http::header::AUTHORIZATION, auth(&admin_token))
            .json(&next)
            .await
            .status_code(),
        400
    );
    let mut wrong_user = body.clone();
    wrong_user["user_id"] = json!(Uuid::new_v4());
    assert_eq!(
        server
            .post(&url)
            .add_header(http::header::AUTHORIZATION, auth(&admin_token))
            .json(&wrong_user)
            .await
            .status_code(),
        404
    );
    let mut missing = body.clone();
    missing.as_object_mut().unwrap().remove("method");
    assert_eq!(
        server
            .post(&url)
            .add_header(http::header::AUTHORIZATION, auth(&admin_token))
            .json(&missing)
            .await
            .status_code(),
        422
    );
    let mut fractional = body.clone();
    fractional["effective_at"] = "1970-01-01T00:02:30.5Z".into();
    assert_eq!(
        server
            .post(&url)
            .add_header(http::header::AUTHORIZATION, auth(&admin_token))
            .json(&fractional)
            .await
            .status_code(),
        400
    );
    let sub = conn
        .query_one(
            "SELECT status,cancel_at_period_end FROM subscriptions WHERE subscription_id=$1",
            &[&subscription_id],
        )
        .await
        .unwrap();
    assert_eq!(sub.get::<_, String>(0), "active");
    assert!(!sub.get::<_, bool>(1));
    conn.execute(
        "UPDATE subscriptions SET provider='near' WHERE subscription_id=$1",
        &[&subscription_id],
    )
    .await
    .unwrap();
    assert_eq!(
        server
            .post(&url)
            .add_header(http::header::AUTHORIZATION, auth(&admin_token))
            .json(&body)
            .await
            .status_code(),
        400
    );
    assert_eq!(stripe.reads.load(Ordering::SeqCst), reads);
}
