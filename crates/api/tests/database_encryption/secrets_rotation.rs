use super::fixture::{ring_config, Fixture, OLD, WRITE};
use database::field_encryption::{self, KeyRing};
use http::HeaderName;
use serde_json::{json, Value};
use services::agent::ports::{AgentRepository, CreateInstanceParams};
use services::auth::ports::{OAuthRepository, OAuthState, PkceCodeVerifier};
use services::user::ports::OAuthProvider;
use services::UserId;
use uuid::Uuid;

#[tokio::test]
async fn rewrap_preserves_oauth_agent_and_passkey_secrets_after_old_key_removal() {
    // Given all secret-bearing tables written using the previous database key.
    let f = Fixture::new().await;
    let mut config = ring_config();
    config.ring = KeyRing::new("db-v1".into(), *OLD, vec![]).unwrap();
    f.db.pool().set_field_encryption(config);
    let agents = f.db.agent_repository();
    let instance = agents
        .create_instance(CreateInstanceParams {
            user_id: UserId(f.user),
            instance_id: Uuid::new_v4().to_string(),
            name: "rotation-agent".into(),
            public_ssh_key: None,
            instance_url: Some("https://instance.rotation.example".into()),
            instance_token: Some("rotation-instance-token".into()),
            dashboard_url: Some("https://dashboard.rotation.example".into()),
            agent_api_base_url: None,
            service_type: None,
        })
        .await
        .unwrap();
    agents
        .upsert_user_passkey_credentials(UserId(f.user), "rotation-auth", "rotation-backup")
        .await
        .unwrap();
    let oauth_state = OAuthState {
        state: Uuid::new_v4().to_string(),
        provider: OAuthProvider::Google,
        redirect_uri: "https://callback.rotation.example".into(),
        frontend_callback: None,
        frontend_code_challenge: "rotation-challenge".into(),
        frontend_state: "rotation-state".into(),
        provider_code_verifier: Some(PkceCodeVerifier::new("rotation-provider-verifier".into())),
        created_at: chrono::Utc::now(),
    };
    f.db.oauth_repository()
        .store_oauth_state(&oauth_state)
        .await
        .unwrap();
    let session = field_encryption::encrypt(
        &OLD,
        "db-v1",
        "agent_instances",
        "auth_session_token",
        instance.id,
        "rotation-session",
    )
    .unwrap();
    let client = f.db.pool().get().await.unwrap();
    client
        .execute(
            "UPDATE agent_instances SET auth_session_token=$2 WHERE id=$1",
            &[&instance.id, &session],
        )
        .await
        .unwrap();
    let oauth_id: Uuid = client
        .query_one(
            "SELECT id FROM oauth_states WHERE state=$1",
            &[&oauth_state.state],
        )
        .await
        .unwrap()
        .get(0);
    drop(client);
    f.db.pool().set_field_encryption(ring_config());
    let fields = [
        (
            "oauth_states",
            "provider_code_verifier",
            oauth_id,
            "rotation-provider-verifier",
        ),
        (
            "agent_instances",
            "auth_session_token",
            instance.id,
            "rotation-session",
        ),
        (
            "agent_instances",
            "instance_url",
            instance.id,
            "https://instance.rotation.example",
        ),
        (
            "agent_instances",
            "dashboard_url",
            instance.id,
            "https://dashboard.rotation.example",
        ),
        (
            "agent_instances",
            "instance_token",
            instance.id,
            "rotation-instance-token",
        ),
        (
            "user_passkey_credentials",
            "auth_secret",
            f.user,
            "rotation-auth",
        ),
        (
            "user_passkey_credentials",
            "backup_passphrase",
            f.user,
            "rotation-backup",
        ),
    ];
    let mut before = Vec::new();
    for (table, column, id, _) in fields {
        let raw = stored(&f, (table, column, id)).await;
        assert_eq!(
            serde_json::from_str::<Value>(&raw).unwrap()["key_id"],
            "db-v1"
        );
        before.push(raw);
    }

    // When a dry run and execute rewrap process the same explicit tables.
    for mode in ["dry_run", "execute"] {
        let response = f.server.post("/v1/admin/database-encryption/jobs")
            .add_header(HeaderName::from_static("authorization"), f.auth.clone())
            .json(&json!({"mode":mode,"scope":{"tables":["oauth_states","agent_instances","user_passkey_credentials"]},"batch_size":10,"actions":["rewrap"]}))
            .await;
        assert_eq!(response.status_code(), 202, "{}", response.text());
        let accepted: Value = response.json();
        let result = f.wait_job(accepted["job_id"].as_str().unwrap()).await;
        assert_eq!(result["progress"]["stale"], 7);
        assert_eq!(result["progress"]["rewrapped"], 7);
        if mode == "dry_run" {
            for (index, (table, column, id, _)) in fields.iter().enumerate() {
                assert_eq!(stored(&f, (table, column, *id)).await, before[index]);
            }
        }
    }

    // Then every secret authenticates and repository reads work with only the new key.
    let mut config = ring_config();
    config.ring = KeyRing::new("rotation-v2".into(), *WRITE, vec![]).unwrap();
    f.db.pool().set_field_encryption(config.clone());
    for (table, column, id, plaintext) in fields {
        let raw = stored(&f, (table, column, id)).await;
        assert_eq!(
            serde_json::from_str::<Value>(&raw).unwrap()["key_id"],
            "rotation-v2"
        );
        assert_eq!(
            field_encryption::decrypt_with_ring(&raw, config.ring(), table, column, id).unwrap(),
            plaintext
        );
    }
    let rotated = agents.get_instance(instance.id).await.unwrap().unwrap();
    assert_eq!(rotated.instance_token, instance.instance_token);
    assert_eq!(rotated.instance_url, instance.instance_url);
    assert_eq!(rotated.dashboard_url, instance.dashboard_url);
    assert_eq!(
        agents
            .get_user_passkey_credentials(UserId(f.user))
            .await
            .unwrap(),
        Some(("rotation-auth".into(), "rotation-backup".into()))
    );
    let state =
        f.db.oauth_repository()
            .consume_oauth_state(&oauth_state.state)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        state.provider_code_verifier.unwrap().secret(),
        "rotation-provider-verifier"
    );
}

async fn stored(f: &Fixture, field: (&str, &str, Uuid)) -> String {
    let (table, column, id) = field;
    let selector = if table == "user_passkey_credentials" {
        "user_id"
    } else {
        "id"
    };
    f.db.pool()
        .get()
        .await
        .unwrap()
        .query_one(
            &format!("SELECT {column} FROM {table} WHERE {selector}=$1"),
            &[&id],
        )
        .await
        .unwrap()
        .get(0)
}
