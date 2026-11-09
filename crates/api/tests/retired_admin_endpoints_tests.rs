mod common;

use common::{create_test_server_with_state, mock_login, TestServerConfig};
use http::{header::AUTHORIZATION, HeaderValue, Method, StatusCode};
use serde_json::{json, Value};
use services::agent::ports::{AgentRepository, CreateInstanceParams};
use services::UserId;
use utoipa::OpenApi;
use uuid::Uuid;

async fn tenant_state(db: &database::Database, user_id: UserId) -> Value {
    db.pool()
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT jsonb_build_object(
                'keys', (
                    SELECT COALESCE(jsonb_agg(to_jsonb(k) ORDER BY k.id), '[]'::jsonb)
                    FROM agent_api_keys k WHERE user_id = $1
                ),
                'instances', (
                    SELECT COALESCE(jsonb_agg(to_jsonb(i) ORDER BY i.id), '[]'::jsonb)
                    FROM agent_instances i WHERE user_id = $1
                ),
                'subscriptions', (
                    SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY s.subscription_id), '[]'::jsonb)
                    FROM subscriptions s WHERE user_id = $1
                )
            )",
            &[&user_id],
        )
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
async fn retired_admin_writes_reject_admin_and_preserve_tenant_state() {
    let admin_email = format!("retired-admin-{}@admin.org", Uuid::new_v4());
    let (server, db, state) = create_test_server_with_state(TestServerConfig {
        admin_emails: Some(vec![admin_email.clone()]),
        ..Default::default()
    })
    .await;

    let admin_token = mock_login(&server, &admin_email).await;
    let authorization = HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap();
    let user_id = UserId(Uuid::new_v4());
    let user_email = format!("{user_id}@example.com");
    let subscription_id = format!("sub_retired_admin_{user_id}");
    let period_end = chrono::Utc::now() + chrono::Duration::days(30);

    let client = db.pool().get().await.unwrap();
    client
        .execute(
            "INSERT INTO users (id, email) VALUES ($1, $2)",
            &[&user_id, &user_email],
        )
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO subscriptions (
                subscription_id, user_id, provider, customer_id,
                price_id, status, current_period_end
            ) VALUES ($1, $2, 'stripe', 'cus_fixture', 'price_fixture', 'active', $3)",
            &[&subscription_id, &user_id, &period_end],
        )
        .await
        .unwrap();
    drop(client);

    let instance = db
        .agent_repository()
        .create_instance(CreateInstanceParams {
            user_id,
            instance_id: Uuid::new_v4().to_string(),
            name: "retired-admin-fixture".into(),
            public_ssh_key: None,
            instance_url: None,
            instance_token: None,
            dashboard_url: None,
            agent_api_base_url: None,
            service_type: None,
        })
        .await
        .unwrap();
    let (key, _) = state
        .agent_service
        .create_unbound_api_key(user_id, "unbound-fixture".into(), Some(1_000), None)
        .await
        .unwrap();

    // Confirm this session can still use the retained admin read operations.
    for (operation, path) in [
        ("list instances", "/v1/admin/agents/instances".to_string()),
        (
            "list subscriptions",
            format!("/v1/admin/subscriptions?user_id={user_id}"),
        ),
    ] {
        let response = server
            .get(&path)
            .add_header(AUTHORIZATION, authorization.clone())
            .await;

        assert_eq!(response.status_code(), StatusCode::OK, "{operation}");
    }

    let original_state = tenant_state(&db, user_id).await;
    let requests = [
        (
            "create API key",
            StatusCode::NOT_FOUND,
            Method::POST,
            "/v1/admin/agents/keys".to_string(),
            json!({ "user_id": user_id, "name": "removed-admin-key" }),
        ),
        (
            "bind API key",
            StatusCode::NOT_FOUND,
            Method::POST,
            format!("/v1/admin/agents/keys/{}/bind-instance", key.id),
            json!({ "instance_id": instance.id }),
        ),
        (
            "create instance",
            StatusCode::METHOD_NOT_ALLOWED,
            Method::POST,
            "/v1/admin/agents/instances".to_string(),
            json!({ "user_id": user_id, "name": "removed-admin-instance" }),
        ),
        (
            "create subscription",
            StatusCode::NOT_FOUND,
            Method::POST,
            format!("/v1/admin/users/{user_id}/subscription"),
            json!({
                "provider": "stripe",
                "plan": "pro",
                "current_period_end": period_end,
            }),
        ),
        (
            "delete subscription",
            StatusCode::NOT_FOUND,
            Method::DELETE,
            format!("/v1/admin/users/{user_id}/subscription"),
            Value::Null,
        ),
        (
            "replace subscription",
            StatusCode::NOT_FOUND,
            Method::PUT,
            format!("/v1/admin/subscriptions/{subscription_id}"),
            json!({
                "user_id": user_id,
                "provider": "stripe",
                "customer_id": "cus_replacement",
                "price_id": "price_replacement",
                "status": "canceled",
                "current_period_end": period_end,
                "cancel_at_period_end": true,
                "created_at": chrono::Utc::now(),
            }),
        ),
    ];

    // Removed paths return 404. The retained GET instances route rejects POST
    // with 405, so each assertion distinguishes route removal from method removal.
    for (operation, expected_status, method, path, body) in requests {
        let response = server
            .method(method.clone(), &path)
            .add_header(AUTHORIZATION, authorization.clone())
            .json(&body)
            .await;

        assert_eq!(
            response.status_code(),
            expected_status,
            "Retired endpoint must not be routed: {operation}"
        );

        // Compare every field without printing tenant records on assertion failure.
        let current_state = tenant_state(&db, user_id).await;
        assert!(
            current_state == original_state,
            "Retired endpoint must not mutate tenant state: {operation}"
        );
    }

    // Unbound keys are not covered by instance cleanup and restrict user deletion.
    db.pool()
        .get()
        .await
        .unwrap()
        .execute("DELETE FROM agent_api_keys WHERE id = $1", &[&key.id])
        .await
        .unwrap();

    common::cleanup_user_agent_instances(&db, &user_email).await;
    common::cleanup_user_subscriptions(&db, &user_email).await;
    common::cleanup_user(&db, &user_email).await;
    common::cleanup_user(&db, &admin_email).await;
}

#[test]
fn retired_admin_operations_and_schemas_are_absent_from_openapi() {
    let document = serde_json::to_value(api::ApiDoc::openapi()).unwrap();
    let paths = document["paths"].as_object().unwrap();

    for path in [
        "/v1/admin/agents/keys",
        "/v1/admin/agents/keys/{key_id}/bind-instance",
        "/v1/admin/users/{user_id}/subscription",
        "/v1/admin/subscriptions/{subscription_id}",
    ] {
        assert!(!paths.contains_key(path), "Retired path documented: {path}");
    }

    let instances = paths["/v1/admin/agents/instances"].as_object().unwrap();
    assert!(!instances.contains_key("post"));
    assert!(instances.contains_key("get"));

    let schemas = document["components"]["schemas"].as_object().unwrap();
    for schema in [
        "AdminCreateApiKeyRequest",
        "BindApiKeyRequest",
        "AdminCreateInstanceRequest",
        "AdminSetSubscriptionRequest",
        "AdminReplaceSubscriptionRequest",
    ] {
        assert!(
            !schemas.contains_key(schema),
            "Retired request schema documented: {schema}"
        );
    }
}
