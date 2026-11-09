#![cfg(feature = "test")]
mod common;

use common::{create_test_server_with_state, mock_login, TestServerConfig};
use http::{header::AUTHORIZATION, StatusCode};
use serde_json::json;
use services::{
    agent::ports::{AgentRepository, CreateInstanceParams},
    user::ports::UserRepository,
};
use uuid::Uuid;
use wiremock::{matchers::path, Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn agent_reports_require_the_owner_before_any_upstream_request() {
    let cloud = MockServer::start().await;
    let manager = MockServer::start().await;
    let rogue = MockServer::start().await;
    let (server, db, _) = create_test_server_with_state(TestServerConfig {
        proxy_base_url: Some(cloud.uri()),
        agent_managers: Some(vec![config::AgentManager {
            url: manager.uri(),
            token: "test-manager-token".into(),
        }]),
        ..Default::default()
    })
    .await;
    let email = format!("attestation-owner-{}@example.com", Uuid::new_v4());
    let owner_token = mock_login(&server, &email).await;
    let other_token = mock_login(
        &server,
        &format!("attestation-other-{}@example.com", Uuid::new_v4()),
    )
    .await;
    let owner = db
        .user_repository()
        .get_user_by_email(&email)
        .await
        .unwrap()
        .unwrap();
    let instance = db
        .agent_repository()
        .create_instance(CreateInstanceParams {
            user_id: owner.id,
            instance_id: Uuid::new_v4().to_string(),
            name: "attestation-test".into(),
            public_ssh_key: None,
            instance_url: None,
            instance_token: None,
            dashboard_url: None,
            agent_api_base_url: Some(manager.uri()),
            service_type: None,
        })
        .await
        .unwrap();
    // Discard manager discovery performed while constructing the test server.
    manager.reset().await;
    let url = format!("/v1/attestation/report?agent={}", instance.id);
    for credential in [
        None,
        Some("invalid".to_owned()),
        Some(format!("sess_{}", Uuid::new_v4().simple())),
    ] {
        let request = server.get(&url);
        let request = match credential {
            Some(token) => request.add_header(AUTHORIZATION, format!("Bearer {token}")),
            None => request,
        };
        request.await.assert_status(StatusCode::UNAUTHORIZED);
    }
    for id in [instance.id, Uuid::new_v4()] {
        server
            .get(&format!("/v1/attestation/report?agent={id}"))
            .add_header(AUTHORIZATION, format!("Bearer {other_token}"))
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }
    assert!(cloud.received_requests().await.unwrap().is_empty());
    assert!(manager.received_requests().await.unwrap().is_empty());

    Mock::given(path("/attestation/report"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "gateway_attestation": {"intel_quote":"test-quote", "request_nonce":"ab".repeat(32)},
            "model_attestations": []
        })))
        .expect(3)
        .mount(&cloud)
        .await;
    Mock::given(path("/attestation/report"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"quote":"agent-quote"})))
        .expect(1)
        .mount(&manager)
        .await;
    Mock::given(path("/instances/attestation-test/attestation"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name":"attestation-test"})))
        .expect(1)
        .mount(&manager)
        .await;
    let report = server
        .get(&url)
        .add_header(AUTHORIZATION, format!("Bearer {owner_token}"))
        .await;
    report.assert_status_ok();
    assert_eq!(
        report.json::<serde_json::Value>()["agent_attestations"][0]["intel_quote"],
        "agent-quote"
    );
    server
        .get("/v1/attestation/report?model=public-model")
        .await
        .assert_status_ok();

    // Ownership does not replace the manager allowlist for stored URLs.
    db.pool()
        .get()
        .await
        .unwrap()
        .execute(
            "UPDATE agent_instances SET agent_api_base_url=$1 WHERE id=$2",
            &[&rogue.uri(), &instance.id],
        )
        .await
        .unwrap();
    let report = server
        .get(&url)
        .add_header(AUTHORIZATION, format!("Bearer {owner_token}"))
        .await;
    report.assert_status_ok();
    assert!(report.json::<serde_json::Value>()["agent_attestations"].is_null());
    assert!(rogue.received_requests().await.unwrap().is_empty());
    cloud.verify().await;
    manager.verify().await;
}
