mod common;

use common::{create_test_server_and_db, mock_login, TestServerConfig};
use services::user::ports::UserRepository;
use uuid::Uuid;

fn auth_header(token: &str) -> http::HeaderValue {
    http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap()
}

const AUTH: http::HeaderName = http::HeaderName::from_static("authorization");

async fn server_and_db() -> (axum_test::TestServer, database::Database) {
    create_test_server_and_db(TestServerConfig::default()).await
}

/// Insert test agent instances and usage log data directly into the database.
/// Returns (instance1_id, instance2_id) for the two created instances.
async fn seed_bi_test_data(db: &database::Database, user_id: Uuid) -> (Uuid, Uuid) {
    let client = db.pool().get().await.expect("get pool client");

    let inst1_id = Uuid::new_v4();
    let inst2_id = Uuid::new_v4();
    let inst1_external = format!("bi-test-oc-{}", Uuid::new_v4());
    let inst2_external = format!("bi-test-ic-{}", Uuid::new_v4());

    // Insert two agent instances: one openclaw (active), one ironclaw (stopped)
    client
        .execute(
            "INSERT INTO agent_instances (id, user_id, instance_id, name, type, status)
             VALUES ($1, $2, $3, $4, $5, $6)",
            &[
                &inst1_id,
                &user_id,
                &inst1_external,
                &"BI Test Instance OC",
                &"openclaw",
                &"active",
            ],
        )
        .await
        .expect("insert instance 1");

    client
        .execute(
            "INSERT INTO agent_instances (id, user_id, instance_id, name, type, status)
             VALUES ($1, $2, $3, $4, $5, $6)",
            &[
                &inst2_id,
                &user_id,
                &inst2_external,
                &"BI Test Instance IC",
                &"ironclaw",
                &"stopped",
            ],
        )
        .await
        .expect("insert instance 2");

    // Insert usage events for both instances into user_usage_event
    for i in 0..5 {
        let input_tokens: i64 = 100 + i * 10;
        let output_tokens: i64 = 50 + i * 5;
        let total_tokens: i64 = input_tokens + output_tokens;
        let input_cost: i64 = input_tokens * 1000; // nano-dollars
        let output_cost: i64 = output_tokens * 2000;
        let total_cost: i64 = input_cost + output_cost;

        let details = serde_json::json!({
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "input_cost": input_cost,
            "output_cost": output_cost,
            "request_type": "chat",
        });

        client
            .execute(
                "INSERT INTO user_usage_event
                 (user_id, metric_key, quantity, cost_nano_usd, model_id,
                  instance_id, details)
                 VALUES ($1, 'llm.tokens', $2, $3, $4, $5, $6)",
                &[
                    &user_id,
                    &total_tokens,
                    &total_cost,
                    &"gpt-4",
                    &inst1_id,
                    &details,
                ],
            )
            .await
            .expect("insert usage event for instance 1");
    }

    // Insert usage events for instance 2 with a different model
    for i in 0..3 {
        let input_tokens: i64 = 200 + i * 20;
        let output_tokens: i64 = 100 + i * 10;
        let total_tokens: i64 = input_tokens + output_tokens;
        let input_cost: i64 = input_tokens * 500;
        let output_cost: i64 = output_tokens * 1000;
        let total_cost: i64 = input_cost + output_cost;

        let details = serde_json::json!({
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "input_cost": input_cost,
            "output_cost": output_cost,
            "request_type": "chat",
        });

        client
            .execute(
                "INSERT INTO user_usage_event
                 (user_id, metric_key, quantity, cost_nano_usd, model_id,
                  instance_id, details)
                 VALUES ($1, 'llm.tokens', $2, $3, $4, $5, $6)",
                &[
                    &user_id,
                    &total_tokens,
                    &total_cost,
                    &"claude-3",
                    &inst2_id,
                    &details,
                ],
            )
            .await
            .expect("insert usage event for instance 2");
    }

    (inst1_id, inst2_id)
}

/// Clean up seeded test data. Each test uses unique UUIDs so no cross-test interference.
async fn cleanup(db: &database::Database, inst1_id: Uuid, inst2_id: Uuid) {
    let client = db.pool().get().await.expect("get pool client");
    let _ = client
        .execute(
            "DELETE FROM user_usage_event WHERE instance_id IN ($1, $2)",
            &[&inst1_id, &inst2_id],
        )
        .await;
    let _ = client
        .execute(
            "DELETE FROM agent_instance_status_history WHERE instance_id IN ($1, $2)",
            &[&inst1_id, &inst2_id],
        )
        .await;
    let _ = client
        .execute(
            "DELETE FROM agent_instances WHERE id IN ($1, $2)",
            &[&inst1_id, &inst2_id],
        )
        .await;
}

// =============================================================================
// Auth checks
// =============================================================================

#[tokio::test]
async fn test_bi_deployments_requires_admin() {
    let (server, _db) = server_and_db().await;

    let user_token = mock_login(&server, "regular_bi@no-admin.org").await;

    let response = server
        .get("/v1/admin/bi/deployments")
        .add_header(AUTH, auth_header(&user_token))
        .await;

    assert_eq!(
        response.status_code(),
        403,
        "Non-admin should receive 403 on BI endpoints"
    );
}

#[tokio::test]
async fn test_bi_deployments_unauthenticated() {
    let (server, _db) = server_and_db().await;

    let response = server.get("/v1/admin/bi/deployments").await;

    assert_eq!(
        response.status_code(),
        401,
        "Unauthenticated request should receive 401"
    );
}

// =============================================================================
// Deployment endpoints with seeded data
// =============================================================================

#[tokio::test]
async fn test_bi_list_deployments_with_data() {
    let (server, db) = server_and_db().await;
    let admin_token = mock_login(&server, "bi_admin_list_data@admin.org").await;

    // Get user ID for seeding
    let user = db
        .user_repository()
        .get_user_by_email("bi_admin_list_data@admin.org")
        .await
        .unwrap()
        .unwrap();

    let (inst1_id, inst2_id) = seed_bi_test_data(&db, user.id.0).await;

    let response = server
        .get("/v1/admin/bi/deployments")
        .add_header(AUTH, auth_header(&admin_token))
        .await;

    assert_eq!(response.status_code(), 200);

    let body: serde_json::Value = response.json();
    let deployments = body.get("deployments").unwrap().as_array().unwrap();
    let total = body.get("total").unwrap().as_i64().unwrap();

    // We inserted 2 instances; total should be >= 2 (other tests may have data)
    assert!(total >= 2, "Expected at least 2 deployments, got {total}");
    assert!(
        !deployments.is_empty(),
        "Deployments array should not be empty"
    );

    // Verify response fields are present on each deployment (including user info for admin UI)
    for d in deployments {
        assert!(d.get("id").is_some());
        assert!(d.get("user_id").is_some());
        assert!(
            d.get("user_email").is_some(),
            "deployments should include user_email when available"
        );
        assert!(
            d.get("user_name").is_some(),
            "deployments should include user_name when available"
        );
        assert!(
            d.get("user_avatar_url").is_some(),
            "deployments should include user_avatar_url when available"
        );
        assert!(d.get("instance_id").is_some());
        assert!(d.get("instance_type").is_some());
        assert!(d.get("status").is_some());
        assert!(d.get("created_at").is_some());
        assert!(d.get("updated_at").is_some());
    }

    cleanup(&db, inst1_id, inst2_id).await;
}

#[tokio::test]
async fn test_bi_list_deployments_filter_by_type() {
    let (server, db) = server_and_db().await;
    let admin_token = mock_login(&server, "bi_admin_ftype@admin.org").await;

    let user = db
        .user_repository()
        .get_user_by_email("bi_admin_ftype@admin.org")
        .await
        .unwrap()
        .unwrap();

    let (inst1_id, inst2_id) = seed_bi_test_data(&db, user.id.0).await;

    // Filter by openclaw type
    let response = server
        .get("/v1/admin/bi/deployments?type=openclaw")
        .add_header(AUTH, auth_header(&admin_token))
        .await;

    assert_eq!(response.status_code(), 200);

    let body: serde_json::Value = response.json();
    let deployments = body.get("deployments").unwrap().as_array().unwrap();

    // All returned deployments should be openclaw
    assert!(
        !deployments.is_empty(),
        "Should have at least 1 openclaw deployment"
    );
    for d in deployments {
        assert_eq!(
            d.get("instance_type").unwrap().as_str().unwrap(),
            "openclaw"
        );
    }

    // Filter by ironclaw type
    let response = server
        .get("/v1/admin/bi/deployments?type=ironclaw")
        .add_header(AUTH, auth_header(&admin_token))
        .await;

    let body: serde_json::Value = response.json();
    let deployments = body.get("deployments").unwrap().as_array().unwrap();
    for d in deployments {
        assert_eq!(
            d.get("instance_type").unwrap().as_str().unwrap(),
            "ironclaw"
        );
    }

    cleanup(&db, inst1_id, inst2_id).await;
}

#[tokio::test]
async fn test_bi_list_deployments_filter_by_status() {
    let (server, db) = server_and_db().await;
    let admin_token = mock_login(&server, "bi_admin_fstat@admin.org").await;

    let user = db
        .user_repository()
        .get_user_by_email("bi_admin_fstat@admin.org")
        .await
        .unwrap()
        .unwrap();

    let (inst1_id, inst2_id) = seed_bi_test_data(&db, user.id.0).await;

    // Filter by stopped status — should include our ironclaw instance
    let response = server
        .get("/v1/admin/bi/deployments?status=stopped")
        .add_header(AUTH, auth_header(&admin_token))
        .await;

    assert_eq!(response.status_code(), 200);

    let body: serde_json::Value = response.json();
    let deployments = body.get("deployments").unwrap().as_array().unwrap();
    for d in deployments {
        assert_eq!(d.get("status").unwrap().as_str().unwrap(), "stopped");
    }

    cleanup(&db, inst1_id, inst2_id).await;
}

#[tokio::test]
async fn test_bi_deployment_summary_with_data() {
    let (server, db) = server_and_db().await;
    let admin_token = mock_login(&server, "bi_admin_sumdata@admin.org").await;

    let user = db
        .user_repository()
        .get_user_by_email("bi_admin_sumdata@admin.org")
        .await
        .unwrap()
        .unwrap();

    let (inst1_id, inst2_id) = seed_bi_test_data(&db, user.id.0).await;

    let response = server
        .get("/v1/admin/bi/deployments/summary")
        .add_header(AUTH, auth_header(&admin_token))
        .await;

    assert_eq!(response.status_code(), 200);

    let body: serde_json::Value = response.json();
    let total = body.get("total_deployments").unwrap().as_i64().unwrap();
    assert!(total >= 2, "Expected at least 2 total deployments");

    let counts = body
        .get("counts_by_type_status")
        .unwrap()
        .as_array()
        .unwrap();
    assert!(
        !counts.is_empty(),
        "Should have at least one type/status breakdown"
    );

    // Verify each breakdown entry has expected fields
    for c in counts {
        assert!(c.get("instance_type").is_some());
        assert!(c.get("status").is_some());
        assert!(c.get("count").unwrap().as_i64().unwrap() > 0);
    }

    cleanup(&db, inst1_id, inst2_id).await;
}

#[tokio::test]
async fn test_bi_deployment_summary_with_date_range() {
    let (server, db) = server_and_db().await;
    let admin_token = mock_login(&server, "bi_admin_sumdate@admin.org").await;

    let user = db
        .user_repository()
        .get_user_by_email("bi_admin_sumdate@admin.org")
        .await
        .unwrap()
        .unwrap();

    let (inst1_id, inst2_id) = seed_bi_test_data(&db, user.id.0).await;

    let response = server
        .get("/v1/admin/bi/deployments/summary?start_date=2024-01-01T00:00:00Z&end_date=2030-01-01T00:00:00Z")
        .add_header(AUTH, auth_header(&admin_token))
        .await;

    assert_eq!(response.status_code(), 200);

    let body: serde_json::Value = response.json();
    let new_in_range = body
        .get("new_deployments_in_range")
        .unwrap()
        .as_i64()
        .unwrap();
    assert!(
        new_in_range >= 2,
        "Expected at least 2 new deployments in range"
    );

    cleanup(&db, inst1_id, inst2_id).await;
}

// =============================================================================
// User summary endpoint
// =============================================================================

#[tokio::test]
async fn test_bi_users_summary() {
    let (server, db) = server_and_db().await;
    let admin_token = mock_login(&server, "bi_admin_summary@admin.org").await;

    let user = db
        .user_repository()
        .get_user_by_email("bi_admin_summary@admin.org")
        .await
        .unwrap()
        .unwrap();

    let (inst1_id, inst2_id) = seed_bi_test_data(&db, user.id.0).await;

    let response = server
        .get("/v1/admin/bi/users/summary")
        .add_header(AUTH, auth_header(&admin_token))
        .await;

    assert_eq!(
        response.status_code(),
        200,
        "users/summary should return 200"
    );

    let body: serde_json::Value = response.json();
    let by_plan = body
        .get("by_subscription_plan")
        .expect("response should have by_subscription_plan")
        .as_array()
        .expect("by_subscription_plan should be array");
    let by_agents = body
        .get("by_agent_count")
        .expect("response should have by_agent_count")
        .as_array()
        .expect("by_agent_count should be array");

    for p in by_plan {
        assert!(p.get("plan").is_some(), "each plan count should have plan");
        assert!(
            p.get("user_count").is_some(),
            "each plan count should have user_count"
        );
    }
    for b in by_agents {
        assert!(
            b.get("agent_count").is_some(),
            "each agent bucket should have agent_count"
        );
        assert!(
            b.get("user_count").is_some(),
            "each agent bucket should have user_count"
        );
    }

    // We seeded 2 instances for one user, so there should be at least one bucket with user_count >= 1
    let total_users_with_agents: i64 = by_agents
        .iter()
        .map(|b| b.get("user_count").and_then(|v| v.as_i64()).unwrap_or(0))
        .sum();
    assert!(
        total_users_with_agents >= 1,
        "expected at least one user in by_agent_count (we seeded 2 instances for one user)"
    );

    cleanup(&db, inst1_id, inst2_id).await;
}

// =============================================================================
// Status history endpoint
// =============================================================================

#[tokio::test]
async fn test_bi_status_history_invalid_uuid() {
    let (server, _db) = server_and_db().await;
    let admin_token = mock_login(&server, "bi_admin_hist@admin.org").await;

    let response = server
        .get("/v1/admin/bi/deployments/not-a-uuid/status-history")
        .add_header(AUTH, auth_header(&admin_token))
        .await;

    assert_eq!(
        response.status_code(),
        400,
        "Invalid UUID should return 400"
    );
}

#[tokio::test]
async fn test_bi_status_history_nonexistent() {
    let (server, _db) = server_and_db().await;
    let admin_token = mock_login(&server, "bi_admin_hist2@admin.org").await;

    let response = server
        .get("/v1/admin/bi/deployments/00000000-0000-4000-8000-000000000000/status-history")
        .add_header(AUTH, auth_header(&admin_token))
        .await;

    assert_eq!(response.status_code(), 200);

    let body: serde_json::Value = response.json();
    let history = body.get("history").unwrap().as_array().unwrap();
    assert!(history.is_empty());
}

#[tokio::test]
async fn test_bi_status_history_with_changes() {
    let (server, db) = server_and_db().await;
    let admin_token = mock_login(&server, "bi_admin_histdata@admin.org").await;

    let user = db
        .user_repository()
        .get_user_by_email("bi_admin_histdata@admin.org")
        .await
        .unwrap()
        .unwrap();

    let (inst1_id, inst2_id) = seed_bi_test_data(&db, user.id.0).await;

    // Trigger status changes via UPDATE (the trigger will record them)
    let client = db.pool().get().await.expect("get pool client");
    client
        .execute(
            "UPDATE agent_instances SET status = 'stopped' WHERE id = $1",
            &[&inst1_id],
        )
        .await
        .expect("update status to stopped");
    client
        .execute(
            "UPDATE agent_instances SET status = 'active' WHERE id = $1",
            &[&inst1_id],
        )
        .await
        .expect("update status back to active");

    let response = server
        .get(&format!(
            "/v1/admin/bi/deployments/{}/status-history",
            inst1_id
        ))
        .add_header(AUTH, auth_header(&admin_token))
        .await;

    assert_eq!(response.status_code(), 200);

    let body: serde_json::Value = response.json();
    let history = body.get("history").unwrap().as_array().unwrap();
    assert_eq!(
        history.len(),
        2,
        "Expected 2 status changes (active->stopped, stopped->active)"
    );

    // Most recent change should be stopped->active (ordered by changed_at DESC)
    let latest = &history[0];
    assert_eq!(
        latest.get("old_status").unwrap().as_str().unwrap(),
        "stopped"
    );
    assert_eq!(
        latest.get("new_status").unwrap().as_str().unwrap(),
        "active"
    );

    let earlier = &history[1];
    assert_eq!(
        earlier.get("old_status").unwrap().as_str().unwrap(),
        "active"
    );
    assert_eq!(
        earlier.get("new_status").unwrap().as_str().unwrap(),
        "stopped"
    );

    cleanup(&db, inst1_id, inst2_id).await;
}

// =============================================================================
// Usage endpoints with seeded data
// =============================================================================

#[tokio::test]
async fn test_bi_usage_group_by_day_with_data() {
    let (server, db) = server_and_db().await;
    let admin_token = mock_login(&server, "bi_admin_uday@admin.org").await;

    let user = db
        .user_repository()
        .get_user_by_email("bi_admin_uday@admin.org")
        .await
        .unwrap()
        .unwrap();

    let (inst1_id, inst2_id) = seed_bi_test_data(&db, user.id.0).await;

    let response = server
        .get("/v1/admin/bi/usage?group_by=day")
        .add_header(AUTH, auth_header(&admin_token))
        .await;

    assert_eq!(response.status_code(), 200);

    let body: serde_json::Value = response.json();
    assert_eq!(body.get("group_by").unwrap().as_str().unwrap(), "day");
    let data = body.get("data").unwrap().as_array().unwrap();
    assert!(!data.is_empty(), "Should have usage data grouped by day");

    // Verify aggregation fields
    let row = &data[0];
    assert!(row.get("group_key").is_some());
    assert!(row.get("input_tokens").unwrap().as_i64().unwrap() > 0);
    assert!(row.get("output_tokens").unwrap().as_i64().unwrap() > 0);
    assert!(row.get("total_tokens").unwrap().as_i64().unwrap() > 0);
    assert!(row.get("request_count").unwrap().as_i64().unwrap() > 0);

    // group_by=day includes active_agents_count and active_users_count (usage > 0)
    assert!(
        row.get("active_agents_count").is_some(),
        "usage group_by=day should include active_agents_count"
    );
    assert!(
        row.get("active_users_count").is_some(),
        "usage group_by=day should include active_users_count"
    );
    let active_agents = row
        .get("active_agents_count")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let active_users = row
        .get("active_users_count")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    assert!(
        active_agents > 0,
        "expected active_agents_count > 0 when usage data exists"
    );
    assert!(
        active_users > 0,
        "expected active_users_count > 0 when usage data exists"
    );

    cleanup(&db, inst1_id, inst2_id).await;
}

#[tokio::test]
async fn test_bi_usage_group_by_model_with_data() {
    let (server, db) = server_and_db().await;
    let admin_token = mock_login(&server, "bi_admin_umodel@admin.org").await;

    let user = db
        .user_repository()
        .get_user_by_email("bi_admin_umodel@admin.org")
        .await
        .unwrap()
        .unwrap();

    let (inst1_id, inst2_id) = seed_bi_test_data(&db, user.id.0).await;

    let response = server
        .get("/v1/admin/bi/usage?group_by=model")
        .add_header(AUTH, auth_header(&admin_token))
        .await;

    assert_eq!(response.status_code(), 200);

    let body: serde_json::Value = response.json();
    let data = body.get("data").unwrap().as_array().unwrap();

    // We inserted data for gpt-4 and claude-3, so should have at least 2 model groups
    assert!(
        data.len() >= 2,
        "Expected at least 2 model groups, got {}",
        data.len()
    );

    let model_keys: Vec<&str> = data
        .iter()
        .map(|d| d.get("group_key").unwrap().as_str().unwrap())
        .collect();
    assert!(
        model_keys.contains(&"gpt-4"),
        "Expected gpt-4 in model groups: {:?}",
        model_keys
    );
    assert!(
        model_keys.contains(&"claude-3"),
        "Expected claude-3 in model groups: {:?}",
        model_keys
    );

    cleanup(&db, inst1_id, inst2_id).await;
}

#[tokio::test]
async fn test_bi_usage_group_by_user_with_data() {
    let (server, db) = server_and_db().await;
    let admin_token = mock_login(&server, "bi_admin_uuser@admin.org").await;

    let user = db
        .user_repository()
        .get_user_by_email("bi_admin_uuser@admin.org")
        .await
        .unwrap()
        .unwrap();

    let (inst1_id, inst2_id) = seed_bi_test_data(&db, user.id.0).await;

    let response = server
        .get("/v1/admin/bi/usage?group_by=user")
        .add_header(AUTH, auth_header(&admin_token))
        .await;

    assert_eq!(response.status_code(), 200);

    let body: serde_json::Value = response.json();
    let data = body.get("data").unwrap().as_array().unwrap();
    assert!(!data.is_empty(), "Should have at least one user group");

    // Our user should be in the results with at least 8 requests (5 + 3)
    let our_user_data = data
        .iter()
        .find(|d| d.get("group_key").unwrap().as_str().unwrap() == user.id.0.to_string());
    assert!(
        our_user_data.is_some(),
        "Our test user should appear in user-grouped data"
    );
    let our_data = our_user_data.unwrap();
    let request_count = our_data.get("request_count").unwrap().as_i64().unwrap();
    assert!(
        request_count >= 8,
        "Expected at least 8 requests for our user, got {}",
        request_count
    );

    cleanup(&db, inst1_id, inst2_id).await;
}

#[tokio::test]
async fn test_bi_usage_with_type_filter() {
    let (server, db) = server_and_db().await;
    let admin_token = mock_login(&server, "bi_admin_utfilter@admin.org").await;

    let user = db
        .user_repository()
        .get_user_by_email("bi_admin_utfilter@admin.org")
        .await
        .unwrap()
        .unwrap();

    let (inst1_id, inst2_id) = seed_bi_test_data(&db, user.id.0).await;

    // Filter by openclaw — should only include instance 1's 5 requests
    let response = server
        .get("/v1/admin/bi/usage?type=openclaw&group_by=instance")
        .add_header(AUTH, auth_header(&admin_token))
        .await;

    assert_eq!(response.status_code(), 200);

    let body: serde_json::Value = response.json();
    let data = body.get("data").unwrap().as_array().unwrap();

    // All instance groups returned should be openclaw instances and include user info
    for row in data {
        assert!(
            row.get("user_email").is_some(),
            "usage group_by=instance should include user_email"
        );
        assert!(
            row.get("user_name").is_some(),
            "usage group_by=instance should include user_name"
        );
        assert!(
            row.get("user_avatar_url").is_some(),
            "usage group_by=instance should include user_avatar_url"
        );
        let instance_id = row.get("group_key").unwrap().as_str().unwrap();
        // Our openclaw instance should be present with owner's user_email
        if instance_id == inst1_id.to_string() {
            assert_eq!(row.get("request_count").unwrap().as_i64().unwrap(), 5);
            assert_eq!(
                row.get("user_email").and_then(|v| v.as_str()).unwrap_or(""),
                "bi_admin_utfilter@admin.org",
                "instance row should include owner user_email"
            );
        }
        // inst2_id (ironclaw) should NOT appear
        assert_ne!(
            instance_id,
            inst2_id.to_string(),
            "Ironclaw instance should not appear when filtering by openclaw"
        );
    }

    cleanup(&db, inst1_id, inst2_id).await;
}

// =============================================================================
// Top consumers endpoint with seeded data
// =============================================================================

#[tokio::test]
async fn test_bi_top_consumers_by_tokens_with_data() {
    let (server, db) = server_and_db().await;
    let admin_token = mock_login(&server, "bi_admin_toptok@admin.org").await;

    let user = db
        .user_repository()
        .get_user_by_email("bi_admin_toptok@admin.org")
        .await
        .unwrap()
        .unwrap();

    let (inst1_id, inst2_id) = seed_bi_test_data(&db, user.id.0).await;

    let response = server
        .get("/v1/admin/bi/usage/top?rank_by=tokens&group_by=user&limit=10")
        .add_header(AUTH, auth_header(&admin_token))
        .await;

    assert_eq!(response.status_code(), 200);

    let body: serde_json::Value = response.json();
    assert_eq!(body.get("rank_by").unwrap().as_str().unwrap(), "tokens");
    assert_eq!(body.get("group_by").unwrap().as_str().unwrap(), "user");

    let consumers = body.get("consumers").unwrap().as_array().unwrap();
    assert!(
        !consumers.is_empty(),
        "Should have at least one top consumer"
    );

    // Verify consumers are ordered by total_tokens descending
    let mut prev_tokens = i64::MAX;
    for c in consumers {
        let tokens = c.get("total_tokens").unwrap().as_i64().unwrap();
        assert!(
            tokens <= prev_tokens,
            "Consumers should be sorted by tokens DESC"
        );
        prev_tokens = tokens;
        assert!(c.get("id").is_some());
        assert!(c.get("request_count").unwrap().as_i64().unwrap() > 0);
    }

    cleanup(&db, inst1_id, inst2_id).await;
}

#[tokio::test]
async fn test_bi_top_consumers_by_cost_grouped_by_instance() {
    let (server, db) = server_and_db().await;
    let admin_token = mock_login(&server, "bi_admin_topcost@admin.org").await;

    let user = db
        .user_repository()
        .get_user_by_email("bi_admin_topcost@admin.org")
        .await
        .unwrap()
        .unwrap();

    let (inst1_id, inst2_id) = seed_bi_test_data(&db, user.id.0).await;

    let response = server
        .get("/v1/admin/bi/usage/top?rank_by=cost&group_by=instance&limit=10")
        .add_header(AUTH, auth_header(&admin_token))
        .await;

    assert_eq!(response.status_code(), 200);

    let body: serde_json::Value = response.json();
    assert_eq!(body.get("rank_by").unwrap().as_str().unwrap(), "cost");
    assert_eq!(body.get("group_by").unwrap().as_str().unwrap(), "instance");

    let consumers = body.get("consumers").unwrap().as_array().unwrap();
    assert!(
        !consumers.is_empty(),
        "Should have at least one instance consumer"
    );

    // When grouped by instance, instance_type should be populated
    for c in consumers {
        let inst_type = c.get("instance_type").unwrap().as_str().unwrap();
        assert!(
            inst_type == "openclaw" || inst_type == "ironclaw",
            "instance_type should be openclaw or ironclaw, got: {}",
            inst_type
        );
    }

    // Verify cost ordering is descending
    let mut prev_cost = i64::MAX;
    for c in consumers {
        let cost = c.get("total_cost_nano").unwrap().as_i64().unwrap();
        assert!(cost <= prev_cost, "Consumers should be sorted by cost DESC");
        prev_cost = cost;
    }

    cleanup(&db, inst1_id, inst2_id).await;
}

#[tokio::test]
async fn test_bi_top_consumers_with_type_filter() {
    let (server, db) = server_and_db().await;
    let admin_token = mock_login(&server, "bi_admin_topfilt@admin.org").await;

    let user = db
        .user_repository()
        .get_user_by_email("bi_admin_topfilt@admin.org")
        .await
        .unwrap()
        .unwrap();

    let (inst1_id, inst2_id) = seed_bi_test_data(&db, user.id.0).await;

    // Filter by ironclaw — should only include instance 2
    let response = server
        .get("/v1/admin/bi/usage/top?type=ironclaw&rank_by=cost&group_by=instance&limit=10")
        .add_header(AUTH, auth_header(&admin_token))
        .await;

    assert_eq!(response.status_code(), 200);

    let body: serde_json::Value = response.json();
    let consumers = body.get("consumers").unwrap().as_array().unwrap();

    for c in consumers {
        assert_eq!(
            c.get("instance_type").unwrap().as_str().unwrap(),
            "ironclaw",
            "All consumers should be ironclaw when filtered"
        );
    }

    cleanup(&db, inst1_id, inst2_id).await;
}

// =============================================================================
// Pagination / edge cases
// =============================================================================

#[tokio::test]
async fn test_bi_deployments_limit_clamped() {
    let (server, _db) = server_and_db().await;
    let admin_token = mock_login(&server, "bi_admin_clamp@admin.org").await;

    // limit=999 should be clamped to 100
    let response = server
        .get("/v1/admin/bi/deployments?limit=999")
        .add_header(AUTH, auth_header(&admin_token))
        .await;

    assert_eq!(response.status_code(), 200);

    let body: serde_json::Value = response.json();
    assert_eq!(body.get("limit").unwrap().as_i64().unwrap(), 100);
}

#[tokio::test]
async fn test_bi_deployments_limit_minimum() {
    let (server, _db) = server_and_db().await;
    let admin_token = mock_login(&server, "bi_admin_min@admin.org").await;

    // limit=-5 should be clamped to 1
    let response = server
        .get("/v1/admin/bi/deployments?limit=-5")
        .add_header(AUTH, auth_header(&admin_token))
        .await;

    assert_eq!(response.status_code(), 200);

    let body: serde_json::Value = response.json();
    assert_eq!(body.get("limit").unwrap().as_i64().unwrap(), 1);
}

#[tokio::test]
async fn test_bi_deployments_pagination() {
    let (server, db) = server_and_db().await;
    let admin_token = mock_login(&server, "bi_admin_page@admin.org").await;

    let user = db
        .user_repository()
        .get_user_by_email("bi_admin_page@admin.org")
        .await
        .unwrap()
        .unwrap();

    let (inst1_id, inst2_id) = seed_bi_test_data(&db, user.id.0).await;

    // Fetch page 1 with limit=1
    let response = server
        .get("/v1/admin/bi/deployments?limit=1&offset=0")
        .add_header(AUTH, auth_header(&admin_token))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: serde_json::Value = response.json();
    let page1 = body.get("deployments").unwrap().as_array().unwrap();
    let total = body.get("total").unwrap().as_i64().unwrap();
    assert_eq!(page1.len(), 1, "Page 1 should return exactly 1 item");
    assert!(total >= 2, "Total should be at least 2");

    // Fetch page 2 with limit=1, offset=1
    let response = server
        .get("/v1/admin/bi/deployments?limit=1&offset=1")
        .add_header(AUTH, auth_header(&admin_token))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: serde_json::Value = response.json();
    let page2 = body.get("deployments").unwrap().as_array().unwrap();
    assert_eq!(page2.len(), 1, "Page 2 should return exactly 1 item");

    // Pages should return different items
    let id1 = page1[0].get("id").unwrap().as_str().unwrap();
    let id2 = page2[0].get("id").unwrap().as_str().unwrap();
    assert_ne!(id1, id2, "Pagination should return different items");

    cleanup(&db, inst1_id, inst2_id).await;
}

// =============================================================================
// BI users endpoint - subscription filtering (active/trialing only)
// =============================================================================

#[tokio::test]
async fn test_bi_users_returns_only_active_subscriptions() {
    let (server, db) = server_and_db().await;
    let admin_token = mock_login(&server, "bi_users_admin@admin.org").await;

    // Configure subscription plans so we can filter by plan
    common::set_subscription_plans(
        &server,
        serde_json::json!({
            "basic": { "providers": { "stripe": { "price_id": "price_bi_test_basic" } } }
        }),
    )
    .await;

    // User 1: active subscription - should appear with subscription_status=active
    let _ = mock_login(&server, "bi_user_active@test.org").await;
    common::insert_test_subscription_with_status(
        &server,
        &db,
        "bi_user_active@test.org",
        "active",
        "price_bi_test_basic",
    )
    .await;

    // User 2: no subscription - should appear with subscription_status=none
    let _ = mock_login(&server, "bi_user_none@test.org").await;

    // User 3: canceled subscription only - BI returns only active/trialing, so this user gets null
    let _ = mock_login(&server, "bi_user_canceled@test.org").await;
    common::insert_test_subscription_with_status(
        &server,
        &db,
        "bi_user_canceled@test.org",
        "canceled",
        "price_bi_test_basic",
    )
    .await;

    // Filter by subscription_status=active: should include user 1, exclude user 2 and 3
    let response = server
        .get("/v1/admin/bi/users?filter_by=subscription_status&filter_value=active&limit=100")
        .add_header(AUTH, auth_header(&admin_token))
        .await;
    assert_eq!(response.status_code(), 200);
    let body: serde_json::Value = response.json();
    let users = body.get("users").unwrap().as_array().unwrap();
    let active_emails: Vec<_> = users
        .iter()
        .filter_map(|u| u.get("email").and_then(|e| e.as_str()))
        .collect();
    assert!(
        active_emails.contains(&"bi_user_active@test.org"),
        "User with active subscription should appear: {:?}",
        active_emails
    );
    assert!(
        !active_emails.contains(&"bi_user_canceled@test.org"),
        "User with only canceled subscription should not appear"
    );

    // Filter by subscription_status=none: should include user 2 and 3 (no active sub)
    let response = server
        .get("/v1/admin/bi/users?filter_by=subscription_status&filter_value=none&limit=100")
        .add_header(AUTH, auth_header(&admin_token))
        .await;
    assert_eq!(response.status_code(), 200);
    let body: serde_json::Value = response.json();
    let users = body.get("users").unwrap().as_array().unwrap();
    let none_emails: Vec<_> = users
        .iter()
        .filter_map(|u| u.get("email").and_then(|e| e.as_str()))
        .collect();
    assert!(
        none_emails.contains(&"bi_user_none@test.org"),
        "User with no subscription should appear: {:?}",
        none_emails
    );
    assert!(
        none_emails.contains(&"bi_user_canceled@test.org"),
        "User with only canceled subscription should appear as 'none' (no active sub): {:?}",
        none_emails
    );

    // Filter subscription_status=canceled should return 400 (invalid - only active, trialing, none)
    let response = server
        .get("/v1/admin/bi/users?filter_by=subscription_status&filter_value=canceled")
        .add_header(AUTH, auth_header(&admin_token))
        .await;
    assert_eq!(
        response.status_code(),
        400,
        "filter_value=canceled should be rejected"
    );

    // Cleanup
    common::cleanup_user_subscriptions(&db, "bi_user_active@test.org").await;
    common::cleanup_user_subscriptions(&db, "bi_user_canceled@test.org").await;
}
