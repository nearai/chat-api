#![allow(unused_variables)]
mod common;
use async_trait::async_trait;
use common::{create_test_server_and_db, mock_login, TestServerConfig};
use serde_json::{json, Value};
use services::subscription::ports::*;
use services::user::ports::UserRepository;
use std::sync::{Arc, Mutex};
use stripe_client::refunds::{RefundEvidence, StripeRefund};
use uuid::Uuid;

#[derive(Default)]
struct ProviderState {
    refunds: Vec<StripeRefund>,
    keys: Vec<String>,
    mode: u8, // 1: accept then lose response, 2: fail before accepting
    status: String,
    delay: bool,
}
struct RefundStripe {
    state: Mutex<ProviderState>,
    suffix: String,
}
#[async_trait]
impl StripeClientPort for RefundStripe {
    async fn refund_evidence(
        &self,
        invoice: &str,
        sub: &str,
        customer: &str,
    ) -> Result<RefundEvidence, SubscriptionError> {
        assert_eq!(invoice, format!("in_{}", self.suffix));
        assert_eq!(sub, format!("sub_{}", self.suffix));
        assert_eq!(customer, "cus_test");
        let s = self.state.lock().unwrap();
        Ok(RefundEvidence {
            invoice_id: invoice.into(),
            charge_id: format!("ch_{}", self.suffix),
            customer_id: customer.into(),
            currency: "usd".into(),
            amount_paid: 1001,
            amount_refunded: s
                .refunds
                .iter()
                .filter(|r| r.status == "succeeded")
                .map(|r| r.amount)
                .sum(),
            livemode: false,
            refunds: s.refunds.clone(),
        })
    }
    async fn create_sunset_refund(
        &self,
        charge: &str,
        amount: i64,
        op: &str,
        attempt: &str,
    ) -> Result<StripeRefund, SubscriptionError> {
        let delay = self.state.lock().unwrap().delay;
        if delay {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }
        let mut s = self.state.lock().unwrap();
        s.keys.push(attempt.into());
        let mode = s.mode;
        s.mode = 0;
        if mode == 2 {
            return Err(SubscriptionError::StripeError(
                "fixture transport error".into(),
            ));
        }
        if let Some(r) = s
            .refunds
            .iter()
            .find(|r| r.metadata.get("sunset_attempt_id").map(String::as_str) == Some(attempt))
        {
            return Ok(r.clone());
        }
        let r = StripeRefund {
            id: format!("re_{}", Uuid::new_v4().simple()),
            charge: charge.into(),
            amount,
            currency: "usd".into(),
            status: if s.status.is_empty() {
                "pending".into()
            } else {
                s.status.clone()
            },
            metadata: [
                ("sunset_operation_id".into(), op.into()),
                ("sunset_attempt_id".into(), attempt.into()),
            ]
            .into(),
            failure_reason: None,
        };
        s.refunds.push(r.clone());
        if mode == 1 {
            Err(SubscriptionError::StripeError(
                "fixture lost response".into(),
            ))
        } else {
            Ok(r)
        }
    }
    async fn verify_webhook_signature(
        &self,
        _payload: &[u8],
        _signature: &str,
        _secret: &str,
    ) -> Result<(), SubscriptionError> {
        if _signature == "fixture_valid" {
            Ok(())
        } else {
            Err(SubscriptionError::WebhookVerificationFailed(
                "fixture invalid".into(),
            ))
        }
    }
    async fn create_customer(
        &self,
        _email: Option<&str>,
        _name: Option<&str>,
        user_id: &str,
        _test_clock_id: Option<&str>,
    ) -> Result<String, SubscriptionError> {
        panic!("Unexpected Stripe operation")
    }
    async fn retrieve_customer(
        &self,
        customer_id: &str,
    ) -> Result<StripeCustomerRef, SubscriptionError> {
        panic!("Unexpected Stripe operation")
    }
    async fn create_subscription_checkout_session(
        &self,
        _params: StripeCreateSubscriptionCheckoutParams,
    ) -> Result<StripeCheckoutSessionResult, SubscriptionError> {
        panic!("Unexpected Stripe operation")
    }
    async fn create_credits_checkout_session(
        &self,
        params: StripeCreateCreditsCheckoutParams,
    ) -> Result<StripeCheckoutSessionResult, SubscriptionError> {
        panic!("Unexpected Stripe operation")
    }
    async fn retrieve_checkout_session(
        &self,
        _checkout_session_id: &str,
    ) -> Result<StripeCheckoutSessionResult, SubscriptionError> {
        panic!("Unexpected Stripe operation")
    }
    async fn retrieve_subscription(
        &self,
        _subscription_id: &str,
    ) -> Result<StripeSubscriptionSnapshot, SubscriptionError> {
        panic!("Unexpected Stripe operation")
    }
    async fn update_subscription(
        &self,
        _subscription_id: &str,
        _params: StripeUpdateSubscriptionParams,
    ) -> Result<StripeSubscriptionSnapshot, SubscriptionError> {
        panic!("Unexpected Stripe operation")
    }
    async fn create_billing_portal_session(
        &self,
        _customer_id: &str,
        _return_url: &str,
    ) -> Result<StripePortalSessionResult, SubscriptionError> {
        panic!("Unexpected Stripe operation")
    }
}
struct Fixture {
    server: axum_test::TestServer,
    db: database::Database,
    stripe: Arc<RefundStripe>,
    admin: String,
    user: String,
    body: Value,
}
fn config(stripe: Arc<RefundStripe>, enabled: bool) -> TestServerConfig {
    TestServerConfig {
        stripe_client: Some(stripe),
        stripe_config: Some(config::StripeConfig {
            secret_key: "sk_test_fixture".into(),
            webhook_secret: "whsec_fixture".into(),
            refund_execution_enabled: enabled,
            ..Default::default()
        }),
        ..Default::default()
    }
}
impl Fixture {
    async fn new(enabled: bool) -> Self {
        let suffix = Uuid::new_v4().simple().to_string();
        let stripe = Arc::new(RefundStripe {
            state: Mutex::new(ProviderState::default()),
            suffix: suffix.clone(),
        });
        let (server, db) = create_test_server_and_db(config(stripe.clone(), enabled)).await;
        let email = format!("refund-exec-{suffix}@example.com");
        let user = mock_login(&server, &email).await;
        let admin = mock_login(&server, "admin@admin.org").await;
        let owner = db
            .user_repository()
            .get_user_by_email(&email)
            .await
            .unwrap()
            .unwrap();
        common::insert_test_subscription(&server, &db, &email, false).await;
        let sub = format!("sub_{suffix}");
        db.pool()
            .get()
            .await
            .unwrap()
            .execute(
                "UPDATE subscriptions SET subscription_id=$1 WHERE user_id=$2",
                &[&sub, &owner.id],
            )
            .await
            .unwrap();
        let body = json!({"user_id":owner.id,"subscription_id":sub,"invoice_id":format!("in_{suffix}"),"amount":500,"currency":"usd","effective_at":"2026-11-16T00:00:00Z","policy_reference":"policy-337","reconciliation_reference":"recon-337","approved":true});
        Self {
            server,
            db,
            stripe,
            admin,
            user,
            body,
        }
    }
    async fn prepare(&self) -> Value {
        let r = self
            .server
            .post("/v1/admin/refunds")
            .add_header(http::header::AUTHORIZATION, auth(&self.admin))
            .json(&self.body)
            .await;
        assert_eq!(r.status_code(), 200, "{}", r.text());
        r.json()
    }
    async fn action(&self, op: &Value, action: &str) -> axum_test::TestResponse {
        self.server.post(&format!("/v1/admin/refunds/{}/{action}",op["id"].as_str().unwrap())).add_header(http::header::AUTHORIZATION,auth(&self.admin)).json(&json!({"confirmed":true,"expected_attempt_id":op["attempts"].as_array().unwrap().last().unwrap()["id"]})).await
    }
}
fn auth(token: &str) -> http::HeaderValue {
    format!("Bearer {token}").parse().unwrap()
}
fn status(op: &Value) -> &str {
    op["attempts"].as_array().unwrap().last().unwrap()["status"]
        .as_str()
        .unwrap()
}

#[tokio::test]
async fn access_approval_scope_and_disabled_execution() {
    let f = Fixture::new(false).await;
    assert_eq!(
        f.server
            .post("/v1/admin/refunds")
            .json(&f.body)
            .await
            .status_code(),
        401
    );
    for path in [
        "/v1/admin/refunds".to_owned(),
        format!("/v1/admin/refunds/{}/execute", Uuid::new_v4()),
    ] {
        assert_eq!(
            f.server
                .post(&path)
                .add_header(http::header::AUTHORIZATION, auth(&f.user))
                .json(&f.body)
                .await
                .status_code(),
            403
        );
    }
    assert_eq!(
        f.server
            .get("/v1/admin/refunds")
            .add_header(http::header::AUTHORIZATION, auth(&f.user))
            .await
            .status_code(),
        403
    );
    for (field, value, expected) in [
        ("approved", json!(false), 400),
        ("amount", json!(1002), 400),
        ("user_id", json!(Uuid::new_v4()), 404),
        ("policy_reference", json!(""), 400),
    ] {
        let mut b = f.body.clone();
        b[field] = value;
        assert_eq!(
            f.server
                .post("/v1/admin/refunds")
                .add_header(http::header::AUTHORIZATION, auth(&f.admin))
                .json(&b)
                .await
                .status_code(),
            expected
        );
    }
    let op = f.prepare().await;
    assert_eq!(f.prepare().await["id"], op["id"]);
    let mut conflict = f.body.clone();
    conflict["amount"] = json!(499);
    assert_eq!(
        f.server
            .post("/v1/admin/refunds")
            .add_header(http::header::AUTHORIZATION, auth(&f.admin))
            .json(&conflict)
            .await
            .status_code(),
        409
    );
    assert_eq!(f.action(&op, "execute").await.status_code(), 403);
    assert_eq!(f.action(&op, "sync").await.status_code(), 200);
    assert!(f.stripe.state.lock().unwrap().keys.is_empty());
    let list: Value = f
        .server
        .get("/v1/admin/refunds")
        .add_query_param(
            "subscription_id",
            f.body["subscription_id"].as_str().unwrap(),
        )
        .add_header(http::header::AUTHORIZATION, auth(&f.admin))
        .await
        .json();
    assert_eq!(list["execution_enabled"], false);
    assert_eq!(list["total"], 1);
    assert!(list["items"][0].get("customer_id").is_none());
}

#[tokio::test]
async fn concurrent_execution_is_single_and_webhooks_refresh_provider_truth() {
    let f = Fixture::new(true).await;
    let op = f.prepare().await;
    f.stripe.state.lock().unwrap().delay = true;
    let (a, b) = tokio::join!(f.action(&op, "execute"), f.action(&op, "execute"));
    let codes = [a.status_code().as_u16(), b.status_code().as_u16()];
    assert!(codes.contains(&200));
    assert!(codes.contains(&409));
    assert_eq!(f.stripe.state.lock().unwrap().keys.len(), 1);
    assert_eq!(status(&f.action(&op, "execute").await.json()), "pending");
    f.stripe.state.lock().unwrap().refunds[0].status = "succeeded".into();
    let event = json!({"id":format!("evt_{}",Uuid::new_v4().simple()),"type":"refund.updated","data":{"object":{"charge":format!("ch_{}",f.stripe.suffix),"status":"pending"}}});
    let r = f
        .server
        .post("/v1/subscriptions/stripe/webhook")
        .add_header("stripe-signature", "fixture_valid")
        .json(&event)
        .await;
    assert_eq!(r.status_code(), 200, "{}", r.text());
    assert_eq!(status(&f.action(&op, "sync").await.json()), "succeeded");
    assert_eq!(f.stripe.state.lock().unwrap().keys.len(), 1);
}

#[tokio::test]
async fn lost_response_recovers_after_service_restart_without_new_post() {
    let mut f = Fixture::new(true).await;
    let op = f.prepare().await;
    f.stripe.state.lock().unwrap().mode = 1;
    let unknown: Value = f.action(&op, "execute").await.json();
    assert_eq!(status(&unknown), "unknown");
    let (server, _) = create_test_server_and_db(config(f.stripe.clone(), true)).await;
    f.server = server;
    f.admin = mock_login(&f.server, "admin@admin.org").await;
    assert_eq!(status(&f.action(&op, "execute").await.json()), "pending");
    assert_eq!(f.stripe.state.lock().unwrap().keys.len(), 1);
}

#[tokio::test]
async fn uncertain_retry_reuses_key_and_expired_keys_never_resubmit() {
    let f = Fixture::new(true).await;
    let op = f.prepare().await;
    f.stripe.state.lock().unwrap().mode = 2;
    assert_eq!(status(&f.action(&op, "execute").await.json()), "unknown");
    assert_eq!(status(&f.action(&op, "execute").await.json()), "pending");
    {
        let s = f.stripe.state.lock().unwrap();
        assert_eq!(s.keys.len(), 2);
        assert_eq!(s.keys[0], s.keys[1]);
        assert_eq!(s.refunds.len(), 1);
    }
    let f = Fixture::new(true).await;
    let op = f.prepare().await;
    f.stripe.state.lock().unwrap().mode = 2;
    f.action(&op, "execute").await;
    let id: Uuid = op["attempts"][0]["id"].as_str().unwrap().parse().unwrap();
    f.db.pool().get().await.unwrap().execute("UPDATE agent_hosting_refund_attempts SET first_submitted_at=NOW()-INTERVAL '25 hours' WHERE id=$1",&[&id]).await.unwrap();
    let result: Value = f.action(&op, "execute").await.json();
    assert_eq!(result["review_reason"], "idempotency_window_expired");
    assert_eq!(f.stripe.state.lock().unwrap().keys.len(), 1);
}

#[tokio::test]
async fn confirmed_failure_requires_explicit_new_attempt_and_rejects_stale_retry() {
    let f = Fixture::new(true).await;
    let op = f.prepare().await;
    f.stripe.state.lock().unwrap().status = "failed".into();
    assert_eq!(status(&f.action(&op, "execute").await.json()), "failed");
    assert_eq!(f.action(&op, "execute").await.status_code(), 409);
    f.stripe.state.lock().unwrap().status = "pending".into();
    let next: Value = f.action(&op, "retry").await.json();
    assert_eq!(status(&next), "pending");
    assert_eq!(next["attempts"].as_array().unwrap().len(), 2);
    assert_eq!(f.action(&op, "retry").await.status_code(), 409);
    let s = f.stripe.state.lock().unwrap();
    assert_eq!(s.keys.len(), 2);
    assert_ne!(s.keys[0], s.keys[1]);
}

#[tokio::test]
async fn outside_refunds_and_missing_known_refunds_block_execution() {
    let f = Fixture::new(true).await;
    let op = f.prepare().await;
    f.stripe.state.lock().unwrap().refunds.push(StripeRefund {
        id: "re_external".into(),
        charge: format!("ch_{}", f.stripe.suffix),
        amount: 100,
        currency: "usd".into(),
        status: "pending".into(),
        metadata: Default::default(),
        failure_reason: None,
    });
    let result: Value = f.action(&op, "execute").await.json();
    assert_eq!(
        result["review_reason"],
        "external_refund_requires_reconciliation"
    );
    assert!(f.stripe.state.lock().unwrap().keys.is_empty());
    let f = Fixture::new(true).await;
    let op = f.prepare().await;
    f.action(&op, "execute").await;
    f.stripe.state.lock().unwrap().refunds.clear();
    let result: Value = f.action(&op, "execute").await.json();
    assert_eq!(result["review_reason"], "known_refund_missing_from_stripe");
    assert_eq!(f.stripe.state.lock().unwrap().keys.len(), 1);
}

#[tokio::test]
async fn execution_audits_executor_separately_from_approver() {
    let mut f = Fixture::new(true).await;
    let op = f.prepare().await;
    assert!(op["attempts"][0]["initiated_by"].is_null());
    let email = "subs_admin@admin.org".to_owned();
    f.admin = mock_login(&f.server, &email).await;
    let executor =
        f.db.user_repository()
            .get_user_by_email(&email)
            .await
            .unwrap()
            .unwrap();
    let response = f.action(&op, "execute").await;
    assert_eq!(response.status_code(), 200, "{}", response.text());
    let result: Value = response.json();
    assert_eq!(result["approved_by"], op["approved_by"]);
    assert_eq!(result["attempts"][0]["initiated_by"], json!(executor.id));
    assert_ne!(result["approved_by"], result["attempts"][0]["initiated_by"]);
}
