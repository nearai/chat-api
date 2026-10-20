#![cfg(feature = "test")]

mod common;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use common::{create_test_server_and_db, TestServerConfig};
use http::header::{
    CACHE_CONTROL, LOCATION, REFERRER_POLICY, SET_COOKIE, STRICT_TRANSPORT_SECURITY,
};
use serde_json::json;
use services::agent::ports::MockAgentService;
use services::auth::ports::{OAuthCallbackCode, OAuthRepository, OAuthTokens, SessionRepository};
use services::user::ports::{OAuthProvider, UserRepository};
use services::UserId;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use url::Url;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

const GATEWAY_COOKIE: &str =
    "gateway=test-session; Domain=.near.ai; Path=/; Secure; HttpOnly; SameSite=None";
type GatewayCalls = Arc<Mutex<Vec<UserId>>>;

fn gateway_config(
    expected_calls: usize,
    result: Result<Option<&'static str>, &'static str>,
) -> (TestServerConfig, GatewayCalls) {
    let calls = GatewayCalls::default();
    let recorded = calls.clone();
    let mut gateway = MockAgentService::new();
    gateway
        .expect_setup_gateway_session_for_user()
        .times(expected_calls)
        .returning(move |user_id| {
            recorded.lock().unwrap().push(user_id);
            result
                .map(|cookie| cookie.map(str::to_owned))
                .map_err(anyhow::Error::msg)
        });
    (
        TestServerConfig {
            agent_service: Some(Arc::new(gateway)),
            ..Default::default()
        },
        calls,
    )
}

#[tokio::test]
async fn security_headers_cover_the_complete_production_router() {
    let (server, _db) = create_test_server_and_db(TestServerConfig::default()).await;
    for (path, expected_status) in [
        ("/health", 200),
        ("/docs", 303),
        ("/docs/", 200),
        ("/docs/swagger-ui.css", 200),
        ("/api-docs/openapi.json", 200),
        ("/v1/auth/callback?code=invalid&state=invalid", 401),
    ] {
        let response = server.get(path).await;
        assert_eq!(response.status_code(), expected_status, "{path}");
        assert_eq!(
            response.header(STRICT_TRANSPORT_SECURITY),
            "max-age=31536000; includeSubDomains",
            "{path}"
        );
        assert_eq!(
            response.header(http::header::X_CONTENT_TYPE_OPTIONS),
            "nosniff",
            "{path}"
        );
        let policies: Vec<_> = response
            .headers()
            .get_all(http::header::CONTENT_SECURITY_POLICY)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        assert_eq!(
            policies
                .iter()
                .filter(|p| **p == "frame-ancestors 'none'; script-src-attr 'none'")
                .count(),
            1,
            "{path}"
        );
    }
    let openapi = server.get("/api-docs/openapi.json").await;
    let document: serde_json::Value = openapi.json();
    assert!(document["paths"]["/health"].is_object());
    let preflight = server
        .method(http::Method::OPTIONS, "/v1/auth/google")
        .add_header(http::header::ORIGIN, "https://agent.near.ai")
        .add_header(http::header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
        .await;
    assert_eq!(preflight.status_code(), 200);
    assert_eq!(
        preflight.header(STRICT_TRANSPORT_SECURITY),
        "max-age=31536000; includeSubDomains"
    );
}

#[tokio::test]
async fn code_mode_initiation_accepts_valid_pkce_for_both_providers() {
    let (server, _db) = create_test_server_and_db(TestServerConfig::default()).await;
    let health = server.get("/health").await;
    assert_eq!(health.status_code(), 200);
    assert_eq!(
        health.header(STRICT_TRANSPORT_SECURITY),
        "max-age=31536000; includeSubDomains"
    );
    let challenge = "A".repeat(43);
    let frontend_state = "B".repeat(43);

    for provider in ["google", "github"] {
        let response = server
            .get(&format!(
                "/v1/auth/{provider}?frontend_callback=http%3A%2F%2Flocalhost%3A3000&frontend_response_mode=code&code_challenge={challenge}&code_challenge_method=S256&frontend_state={frontend_state}"
            ))
            .await;

        assert_eq!(response.status_code(), 307);
        let redirect = Url::parse(response.header(LOCATION).to_str().unwrap()).unwrap();
        let query: std::collections::HashMap<_, _> = redirect.query_pairs().collect();
        assert_eq!(
            query.get("code_challenge_method").map(|v| v.as_ref()),
            Some("S256")
        );
        let provider_challenge = query
            .get("code_challenge")
            .expect("provider PKCE challenge");
        assert_eq!(provider_challenge.len(), 43);
        assert_ne!(provider_challenge.as_ref(), challenge);
        assert!(!query.contains_key("code_verifier"));
    }
}

#[tokio::test]
async fn initiation_rejects_legacy_and_invalid_frontend_pkce() {
    let (config, calls) = gateway_config(0, Ok(Some(GATEWAY_COOKIE)));
    let (server, _) = create_test_server_and_db(config).await;
    let challenge = "A".repeat(43);
    let state = "B".repeat(43);
    let pkce =
        format!("&code_challenge={challenge}&code_challenge_method=S256&frontend_state={state}");
    let invalid_queries = [
        String::new(),
        "&frontend_response_mode=token".into(),
        pkce.clone(),
        format!("&frontend_response_mode=token{pkce}"),
        format!("&frontend_response_mode=unknown{pkce}"),
        "&frontend_response_mode=code".into(),
        format!("&frontend_response_mode=code&code_challenge_method=S256&frontend_state={state}"),
        format!("&frontend_response_mode=code&code_challenge={challenge}&frontend_state={state}"),
        format!("&frontend_response_mode=code&code_challenge={challenge}&code_challenge_method=plain&frontend_state={state}"),
        format!("&frontend_response_mode=code&code_challenge={challenge}&code_challenge_method=S256"),
        format!("&frontend_response_mode=code&code_challenge=invalid&code_challenge_method=S256&frontend_state={state}"),
    ];
    for provider in ["google", "github"] {
        for query in &invalid_queries {
            let response = server
                .get(&format!(
                    "/v1/auth/{provider}?frontend_callback=http%3A%2F%2Flocalhost%3A3000{query}"
                ))
                .await;
            assert_eq!(response.status_code(), 400, "{provider}: {query}");
            assert!(!response.headers().contains_key(LOCATION));
            assert!(!response.headers().contains_key(SET_COOKIE));
        }
    }
    assert!(calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn provider_callback_works_with_global_encryption_writes_disabled() {
    let provider = MockServer::start().await;
    let (gateway, gateway_calls) = gateway_config(1, Ok(Some(GATEWAY_COOKIE)));
    let email = format!("oauth-provider-callback-{}@example.com", Uuid::new_v4());
    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": format!("google-{}", Uuid::new_v4()),
            "email": email,
            "verified_email": true,
            "name": "OAuth provider callback test"
        })))
        .mount(&provider)
        .await;

    let (server, db) = create_test_server_and_db(TestServerConfig {
        database_encryption_write_enabled: Some(false),
        google_oauth_token_url: Some(format!("{}/token", provider.uri())),
        google_oauth_user_info_url: Some(format!("{}/userinfo", provider.uri())),
        ..gateway
    })
    .await;
    let verifier = "provider-callback-verifier-abcdefghijklmnopqrstuvwxyz0123456789";
    let challenge = pkce_challenge(verifier);
    let frontend_state = URL_SAFE_NO_PAD.encode(Sha256::digest(b"frontend-state"));

    let initiation = server
        .get(&format!(
            "/v1/auth/google?frontend_callback=http%3A%2F%2Flocalhost%3A3000&frontend_response_mode=code&code_challenge={challenge}&code_challenge_method=S256&frontend_state={frontend_state}"
        ))
        .await;
    assert_eq!(initiation.status_code(), 307);
    let provider_location = initiation.header(LOCATION);
    let provider_redirect = Url::parse(
        provider_location
            .to_str()
            .expect("provider redirect header value"),
    )
    .expect("provider redirect URL");
    let provider_challenge = provider_redirect
        .query_pairs()
        .find_map(|(key, value)| (key == "code_challenge").then(|| value.into_owned()))
        .expect("provider PKCE challenge");
    assert_ne!(provider_challenge, challenge);
    let expected_challenge = provider_challenge.clone();
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(move |request: &wiremock::Request| {
            let form: std::collections::HashMap<_, _> = url::form_urlencoded::parse(&request.body).collect();
            if form.get("code_verifier").is_some_and(|verifier| pkce_challenge(verifier) == expected_challenge) {
                ResponseTemplate::new(200).set_body_json(json!({
                    "access_token": "mock-google-access-token", "token_type": "Bearer", "expires_in": 3600
                }))
            } else {
                ResponseTemplate::new(400).set_body_json(json!({"error": "invalid_grant"}))
            }
        })
        .expect(1)
        .mount(&provider)
        .await;
    let provider_state = provider_redirect
        .query_pairs()
        .find_map(|(name, value)| (name == "state").then(|| value.into_owned()))
        .expect("OAuth provider state");

    let client = db.pool().get().await.expect("database client");
    let stored_state = client
        .query_one(
            "SELECT frontend_response_mode, frontend_code_challenge, frontend_state, provider_code_verifier
             FROM oauth_states WHERE state = $1",
            &[&provider_state],
        )
        .await
        .expect("stored OAuth initiation state");
    assert_eq!(stored_state.get::<_, String>(0), "code");
    assert_eq!(
        stored_state.get::<_, Option<String>>(1).as_deref(),
        Some(challenge.as_str())
    );
    assert_eq!(
        stored_state.get::<_, Option<String>>(2).as_deref(),
        Some(frontend_state.as_str())
    );
    let stored_verifier: String = stored_state.get(3);
    let envelope: serde_json::Value = serde_json::from_str(&stored_verifier).unwrap();
    assert!(database::field_encryption::is_envelope(&envelope));

    let callback = server
        .get(&format!(
            "/v1/auth/callback?code=mock-provider-code&state={provider_state}"
        ))
        .await;
    assert_eq!(callback.status_code(), 302);
    assert!(!callback.headers().contains_key(SET_COOKIE));
    assert!(gateway_calls.lock().unwrap().is_empty());
    assert_eq!(callback.header(CACHE_CONTROL), "no-store");
    assert_eq!(callback.header(REFERRER_POLICY), "no-referrer");
    let frontend_location = callback.header(LOCATION);
    let frontend_redirect = Url::parse(
        frontend_location
            .to_str()
            .expect("frontend callback header value"),
    )
    .expect("frontend callback redirect URL");
    let query: std::collections::HashMap<_, _> = frontend_redirect.query_pairs().collect();
    let callback_code = query
        .get("code")
        .expect("frontend callback code")
        .to_string();
    assert_eq!(
        query.get("state").map(|value| value.as_ref()),
        Some(frontend_state.as_str())
    );
    assert!(!query.contains_key("token"));
    assert!(!query.contains_key("session_id"));

    let exchange = server
        .post("/v1/auth/exchange")
        .json(&json!({ "code": callback_code, "code_verifier": verifier }))
        .await;
    assert_eq!(exchange.status_code(), 200);
    assert_eq!(exchange.header(SET_COOKIE), GATEWAY_COOKIE);
    assert_eq!(gateway_calls.lock().unwrap().len(), 1);
    assert_eq!(exchange.header(CACHE_CONTROL), "no-store");
    let body: serde_json::Value = exchange.json();
    assert!(body["token"]
        .as_str()
        .is_some_and(|token| token.starts_with("sess_")));
    assert!(body["session_id"].as_str().is_some());
    assert_eq!(body["is_new_user"], true);
    assert!(db
        .oauth_repository()
        .consume_oauth_state(&provider_state)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn provider_verifiers_are_encrypted_independently_of_the_write_gate() {
    for write_enabled in [false, true] {
        let (server, db) = create_test_server_and_db(TestServerConfig {
            database_encryption_write_enabled: Some(write_enabled),
            ..Default::default()
        })
        .await;
        let client = db.pool().get().await.unwrap();
        let encryption = db.pool().field_encryption().unwrap();
        assert_eq!(encryption.write_enabled, write_enabled);

        for provider in ["google", "github"] {
            let mode_query = format!(
                    "&frontend_response_mode=code&code_challenge={}&code_challenge_method=S256&frontend_state={}",
                    "A".repeat(43),
                    "B".repeat(43)
                );
            let response = server
                    .get(&format!(
                        "/v1/auth/{provider}?frontend_callback=http%3A%2F%2Flocalhost%3A3000{mode_query}"
                    ))
                    .await;
            assert_eq!(response.status_code(), 307);
            let redirect = Url::parse(response.header(LOCATION).to_str().unwrap()).unwrap();
            let query: std::collections::HashMap<_, _> =
                redirect.query_pairs().into_owned().collect();
            let state = &query["state"];
            let row = client
                .query_one(
                    "SELECT id, provider_code_verifier FROM oauth_states WHERE state = $1",
                    &[state],
                )
                .await
                .unwrap();
            let id: Uuid = row.get(0);
            let stored: String = row.get(1);
            let envelope: serde_json::Value = serde_json::from_str(&stored)
                .expect("provider verifier must never be stored as plaintext");
            assert!(database::field_encryption::is_envelope(&envelope));
            let verifier = database::field_encryption::decrypt(
                &encryption.key,
                &encryption.key_id,
                "oauth_states",
                "provider_code_verifier",
                id,
                &stored,
            )
            .unwrap();
            assert_eq!(pkce_challenge(&verifier), query["code_challenge"]);
            let consumed = db
                .oauth_repository()
                .consume_oauth_state(state)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(consumed.provider_code_verifier.unwrap().secret(), &verifier);
            assert!(db
                .oauth_repository()
                .consume_oauth_state(state)
                .await
                .unwrap()
                .is_none());
        }
        // Existing token fields retain their rollout gate and dual-read behavior.
        let user = db
            .user_repository()
            .create_user(
                format!("oauth-storage-{}@example.com", Uuid::new_v4()),
                None,
                None,
            )
            .await
            .unwrap();
        let tokens = OAuthTokens {
            access_token: "storage-test-access-token".into(),
            refresh_token: Some("storage-test-refresh-token".into()),
            expires_at: None,
        };
        db.oauth_repository()
            .store_oauth_tokens(user.id, OAuthProvider::Google, &tokens)
            .await
            .unwrap();
        let row = client
            .query_one(
                "SELECT access_token, refresh_token FROM oauth_tokens WHERE user_id = $1 AND provider = 'google'",
                &[&user.id],
            )
            .await
            .unwrap();
        for (index, plaintext) in [
            (0, tokens.access_token.as_str()),
            (1, "storage-test-refresh-token"),
        ] {
            let stored: String = row.get(index);
            if write_enabled {
                assert!(database::field_encryption::is_envelope(
                    &serde_json::from_str(&stored).unwrap()
                ));
            } else {
                assert_eq!(stored, plaintext);
            }
        }
        let decoded = db
            .oauth_repository()
            .get_oauth_tokens(user.id, OAuthProvider::Google)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decoded.access_token, tokens.access_token);
        assert_eq!(decoded.refresh_token, tokens.refresh_token);
    }
}

#[tokio::test]
async fn provider_state_storage_fails_closed_without_encryption_configuration() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;
    let response = server
        .get(&format!("/v1/auth/google?frontend_callback=http%3A%2F%2Flocalhost%3A3000&frontend_response_mode=code&code_challenge={}&code_challenge_method=S256&frontend_state={}", "A".repeat(43), "B".repeat(43)))
        .await;
    assert_eq!(response.status_code(), 307);
    let redirect = Url::parse(response.header(LOCATION).to_str().unwrap()).unwrap();
    let state = redirect
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .unwrap();
    let oauth_state = db
        .oauth_repository()
        .consume_oauth_state(&state)
        .await
        .unwrap()
        .unwrap();
    let unconfigured_pool = database::pool::DbPool::new(db.pool().current().unwrap());
    let unconfigured_repository =
        database::repositories::PostgresOAuthRepository::new(unconfigured_pool);
    let error = unconfigured_repository
        .store_oauth_state(&oauth_state)
        .await
        .expect_err("missing key must not fall back to plaintext");
    assert!(error.to_string().contains("field encryption configuration"));
    assert!(db
        .oauth_repository()
        .consume_oauth_state(&state)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn provider_callback_rejects_missing_and_wrong_verifiers() {
    for replacement in [None, Some("w".repeat(43))] {
        let provider = MockServer::start().await;
        // A provider-bound code cannot be exchanged with a different verifier.
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(400).set_body_json(json!({ "error": "invalid_grant" })),
            )
            .expect(if replacement.is_some() { 1 } else { 0 })
            .mount(&provider)
            .await;
        let (server, db) = create_test_server_and_db(TestServerConfig {
            google_oauth_token_url: Some(format!("{}/token", provider.uri())),
            google_oauth_user_info_url: Some(format!("{}/userinfo", provider.uri())),
            ..Default::default()
        })
        .await;
        let initiation = server
            .get(&format!("/v1/auth/google?frontend_callback=http%3A%2F%2Flocalhost%3A3000&frontend_response_mode=code&code_challenge={}&code_challenge_method=S256&frontend_state={}", "A".repeat(43), "B".repeat(43)))
            .await;
        assert_eq!(initiation.status_code(), 307);
        let redirect = Url::parse(initiation.header(LOCATION).to_str().unwrap()).unwrap();
        let state = redirect
            .query_pairs()
            .find_map(|(k, v)| (k == "state").then(|| v.into_owned()))
            .unwrap();
        let client = db.pool().get().await.unwrap();
        client
            .execute(
                "UPDATE oauth_states SET provider_code_verifier = $2 WHERE state = $1",
                &[&state, &replacement],
            )
            .await
            .unwrap();
        let callback = server
            .get(&format!(
                "/v1/auth/callback?code=provider-bound-code&state={state}"
            ))
            .await;
        assert_eq!(callback.status_code(), 401);
        assert!(db
            .oauth_repository()
            .consume_oauth_state(&state)
            .await
            .unwrap()
            .is_none());
        let requests = provider.received_requests().await.unwrap();
        assert!(requests.iter().all(|r| r.url.path() != "/userinfo"));
        if let Some(verifier) = replacement {
            let form: std::collections::HashMap<_, _> =
                url::form_urlencoded::parse(&requests[0].body).collect();
            assert_eq!(
                form.get("code_verifier").map(|v| v.as_ref()),
                Some(verifier.as_str())
            );
        }
    }
}

#[tokio::test]
async fn callback_code_is_pkce_bound_single_use_and_rotates_the_session_token() {
    let (config, calls) = gateway_config(1, Ok(Some(GATEWAY_COOKIE)));
    let (server, db) = create_test_server_and_db(config).await;
    let user = db
        .user_repository()
        .create_user(
            format!("oauth-code-{}@example.com", Uuid::new_v4()),
            Some("OAuth code test".into()),
            None,
        )
        .await
        .expect("create test user");
    let original_session = db
        .session_repository()
        .create_session(user.id)
        .await
        .expect("create initial session");
    let original_token = original_session.token.clone().expect("initial token");

    let code = URL_SAFE_NO_PAD.encode([7_u8; 32]);
    let verifier = "v".repeat(43);
    db.oauth_repository()
        .store_callback_code(
            &sha256_hex(&code),
            &OAuthCallbackCode {
                session_id: original_session.session_id,
                code_challenge: pkce_challenge(&verifier),
                is_new_user: true,
                expires_at: Utc::now() + Duration::minutes(2),
            },
        )
        .await
        .expect("store callback code");

    let wrong_response = server
        .post("/v1/auth/exchange")
        .json(&json!({ "code": code, "code_verifier": "w".repeat(43) }))
        .await;
    assert_eq!(wrong_response.status_code(), 401);
    assert!(!wrong_response.headers().contains_key(SET_COOKIE));
    assert!(calls.lock().unwrap().is_empty());
    assert_eq!(wrong_response.header(CACHE_CONTROL), "no-store");

    let response = server
        .post("/v1/auth/exchange")
        .add_header(http::header::ORIGIN, "https://agent.near.ai")
        .json(&json!({ "code": code, "code_verifier": verifier }))
        .await;
    assert_eq!(response.status_code(), 200);
    assert_eq!(response.header(SET_COOKIE), GATEWAY_COOKIE);
    assert_eq!(
        response.header(http::header::ACCESS_CONTROL_ALLOW_ORIGIN),
        "https://agent.near.ai"
    );
    assert_eq!(
        response.header(http::header::ACCESS_CONTROL_ALLOW_CREDENTIALS),
        "true"
    );
    assert_eq!(*calls.lock().unwrap(), vec![user.id]);
    assert_eq!(response.header(CACHE_CONTROL), "no-store");
    let body: serde_json::Value = response.json();
    let rotated_token = body["token"].as_str().expect("rotated token");
    assert_ne!(rotated_token, original_token);
    assert_eq!(
        body["session_id"].as_str(),
        Some(original_session.session_id.to_string().as_str())
    );
    assert_eq!(body["is_new_user"], true);

    assert!(db
        .session_repository()
        .get_session_by_token_hash(sha256_hex(&original_token))
        .await
        .expect("look up original token")
        .is_none());
    assert!(db
        .session_repository()
        .get_session_by_token_hash(sha256_hex(rotated_token))
        .await
        .expect("look up rotated token")
        .is_some());

    let replay = server
        .post("/v1/auth/exchange")
        .json(&json!({ "code": code, "code_verifier": verifier }))
        .await;
    assert_eq!(replay.status_code(), 401);
    assert!(!replay.headers().contains_key(SET_COOKIE));
    assert_eq!(*calls.lock().unwrap(), vec![user.id]);
}

#[tokio::test]
async fn concurrent_callback_code_exchanges_have_exactly_one_winner() {
    let (config, calls) = gateway_config(1, Ok(Some(GATEWAY_COOKIE)));
    let (server, db) = create_test_server_and_db(config).await;
    let user = db
        .user_repository()
        .create_user(
            format!("oauth-code-race-{}@example.com", Uuid::new_v4()),
            None,
            None,
        )
        .await
        .expect("create test user");
    let session = db
        .session_repository()
        .create_session(user.id)
        .await
        .expect("create session");
    let code = URL_SAFE_NO_PAD.encode([8_u8; 32]);
    let verifier = "r".repeat(43);
    let code_hash = sha256_hex(&code);
    let challenge = pkce_challenge(&verifier);
    db.oauth_repository()
        .store_callback_code(
            &code_hash,
            &OAuthCallbackCode {
                session_id: session.session_id,
                code_challenge: challenge.clone(),
                is_new_user: false,
                expires_at: Utc::now() + Duration::minutes(2),
            },
        )
        .await
        .expect("store callback code");

    let (first, second) = tokio::join!(
        async {
            server
                .post("/v1/auth/exchange")
                .json(&json!({"code": code, "code_verifier": verifier}))
                .await
        },
        async {
            server
                .post("/v1/auth/exchange")
                .json(&json!({"code": code, "code_verifier": verifier}))
                .await
        },
    );
    let mut statuses = [first.status_code().as_u16(), second.status_code().as_u16()];
    statuses.sort();
    assert_eq!(statuses, [200, 401]);
    for response in [first, second] {
        let body: serde_json::Value = response.json();
        if response.status_code() == 200 {
            assert_eq!(response.header(SET_COOKIE), GATEWAY_COOKIE);
            assert!(body["token"].as_str().is_some());
        } else {
            assert!(!response.headers().contains_key(SET_COOKIE));
            assert!(body.get("token").is_none());
        }
    }
    assert_eq!(*calls.lock().unwrap(), vec![user.id]);
}

#[tokio::test]
async fn expired_callback_code_cannot_be_exchanged_and_is_cleaned_up() {
    let (config, calls) = gateway_config(0, Ok(Some(GATEWAY_COOKIE)));
    let (server, db) = create_test_server_and_db(config).await;
    let user = db
        .user_repository()
        .create_user(
            format!("oauth-code-expired-{}@example.com", Uuid::new_v4()),
            None,
            None,
        )
        .await
        .expect("create test user");
    let session = db
        .session_repository()
        .create_session(user.id)
        .await
        .expect("create session");
    let code = URL_SAFE_NO_PAD.encode([9_u8; 32]);
    let verifier = "x".repeat(43);
    db.oauth_repository()
        .store_callback_code(
            &sha256_hex(&code),
            &OAuthCallbackCode {
                session_id: session.session_id,
                code_challenge: pkce_challenge(&verifier),
                is_new_user: false,
                expires_at: Utc::now() - Duration::seconds(1),
            },
        )
        .await
        .expect("store expired callback code");

    let response = server
        .post("/v1/auth/exchange")
        .json(&json!({"code": code, "code_verifier": verifier}))
        .await;
    assert_eq!(response.status_code(), 401);
    assert!(!response.headers().contains_key(SET_COOKIE));
    assert!(calls.lock().unwrap().is_empty());

    let client = db.pool().get().await.expect("database client");
    let remaining: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM oauth_callback_codes WHERE code_hash = $1",
            &[&sha256_hex(&code)],
        )
        .await
        .expect("count expired callback codes")
        .get(0);
    assert_eq!(remaining, 0);
}

#[tokio::test]
async fn expired_session_returns_unauthorized_without_consuming_callback_code() {
    let (config, calls) = gateway_config(0, Ok(Some(GATEWAY_COOKIE)));
    let (server, db) = create_test_server_and_db(config).await;
    let user = db
        .user_repository()
        .create_user(
            format!("oauth-code-expired-session-{}@example.com", Uuid::new_v4()),
            None,
            None,
        )
        .await
        .expect("create test user");
    let session = db
        .session_repository()
        .create_session(user.id)
        .await
        .expect("create session");
    let code = URL_SAFE_NO_PAD.encode(Sha256::digest(Uuid::new_v4().as_bytes()));
    let verifier = "m".repeat(43);
    let code_hash = sha256_hex(&code);
    db.oauth_repository()
        .store_callback_code(
            &code_hash,
            &OAuthCallbackCode {
                session_id: session.session_id,
                code_challenge: pkce_challenge(&verifier),
                is_new_user: false,
                expires_at: Utc::now() + Duration::minutes(2),
            },
        )
        .await
        .expect("store callback code");
    let client = db.pool().get().await.expect("database client");
    client
        .execute(
            "UPDATE sessions SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1",
            &[&session.session_id],
        )
        .await
        .expect("expire session");

    let response = server
        .post("/v1/auth/exchange")
        .json(&json!({ "code": code, "code_verifier": verifier }))
        .await;
    assert_eq!(response.status_code(), 401);
    assert!(!response.headers().contains_key(SET_COOKIE));
    assert!(calls.lock().unwrap().is_empty());
    assert_eq!(response.header(CACHE_CONTROL), "no-store");

    let remaining: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM oauth_callback_codes WHERE code_hash = $1",
            &[&code_hash],
        )
        .await
        .expect("count callback code after failed exchange")
        .get(0);
    assert_eq!(remaining, 1);
}

#[tokio::test]
async fn callback_rejects_legacy_or_incomplete_state_before_provider_exchange() {
    let provider = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&provider)
        .await;
    let (config, calls) = gateway_config(0, Ok(Some(GATEWAY_COOKIE)));
    let (server, db) = create_test_server_and_db(TestServerConfig {
        google_oauth_token_url: Some(format!("{}/token", provider.uri())),
        google_oauth_user_info_url: Some(format!("{}/userinfo", provider.uri())),
        ..config
    })
    .await;
    for (mode, challenge, frontend_state) in [
        ("token", Some("A".repeat(43)), Some("B".repeat(43))),
        ("code", None, Some("B".repeat(43))),
        ("code", Some("A".repeat(43)), None),
    ] {
        let initiation = server.get(&format!(
            "/v1/auth/google?frontend_callback=http%3A%2F%2Flocalhost%3A3000&frontend_response_mode=code&code_challenge={}&code_challenge_method=S256&frontend_state={}",
            "A".repeat(43), "B".repeat(43)
        )).await;
        assert_eq!(initiation.status_code(), 307);
        let redirect = Url::parse(initiation.header(LOCATION).to_str().unwrap()).unwrap();
        let state = redirect
            .query_pairs()
            .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
            .unwrap();
        db.pool().get().await.unwrap().execute(
            "UPDATE oauth_states SET frontend_response_mode = $2, frontend_code_challenge = $3, frontend_state = $4 WHERE state = $1",
            &[&state, &mode, &challenge, &frontend_state]
        ).await.unwrap();
        let response = server
            .get(&format!(
                "/v1/auth/callback?code=provider-code&state={state}"
            ))
            .await;
        assert_eq!(response.status_code(), 401);
        assert!(!response.headers().contains_key(SET_COOKIE));
        assert!(!response.headers().contains_key(LOCATION));
        assert!(db
            .oauth_repository()
            .consume_oauth_state(&state)
            .await
            .unwrap()
            .is_none());
    }
    assert!(calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn malformed_or_missing_exchange_credentials_never_call_gateway() {
    let (config, calls) = gateway_config(0, Ok(Some(GATEWAY_COOKIE)));
    let (server, _) = create_test_server_and_db(config).await;
    let code = URL_SAFE_NO_PAD.encode([9_u8; 32]);
    for (body, status) in [
        (json!({"code": code}), 422),
        (json!({"code_verifier": "v".repeat(43)}), 422),
        (json!({"code": code, "code_verifier": ""}), 400),
        (json!({"code": code, "code_verifier": "invalid"}), 400),
        (
            json!({"code": "invalid", "code_verifier": "v".repeat(43)}),
            400,
        ),
        (
            json!({"code": code, "code_verifier": "v".repeat(42) + "!"}),
            400,
        ),
        (json!({"code": code, "code_verifier": "v".repeat(43)}), 401),
    ] {
        let response = server.post("/v1/auth/exchange").json(&body).await;
        assert_eq!(response.status_code(), status);
        assert_eq!(response.header(CACHE_CONTROL), "no-store");
        assert!(!response.headers().contains_key(SET_COOKIE));
        assert!(!response.text().contains("sess_"));
    }
    assert!(calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn gateway_failure_revokes_session_without_restoring_callback_code() {
    for result in [
        Err("gateway unavailable"),
        Ok(None),
        Ok(Some("")),
        Ok(Some("   ")),
        Ok(Some("invalid\r\nSet-Cookie: injected=value")),
    ] {
        let (config, calls) = gateway_config(1, result);
        let (server, db) = create_test_server_and_db(config).await;
        let user = db
            .user_repository()
            .create_user(
                format!("oauth-gateway-failure-{}@example.com", Uuid::new_v4()),
                None,
                None,
            )
            .await
            .unwrap();
        let session = db
            .session_repository()
            .create_session(user.id)
            .await
            .unwrap();
        let code = URL_SAFE_NO_PAD.encode(Sha256::digest(Uuid::new_v4().as_bytes()));
        let verifier = "v".repeat(43);
        db.oauth_repository()
            .store_callback_code(
                &sha256_hex(&code),
                &OAuthCallbackCode {
                    session_id: session.session_id,
                    code_challenge: pkce_challenge(&verifier),
                    is_new_user: false,
                    expires_at: Utc::now() + Duration::minutes(2),
                },
            )
            .await
            .unwrap();
        let response = server
            .post("/v1/auth/exchange")
            .json(&json!({"code": code, "code_verifier": verifier}))
            .await;
        assert_eq!(response.status_code(), 502);
        assert_eq!(response.header(CACHE_CONTROL), "no-store");
        assert!(!response.headers().contains_key(SET_COOKIE));
        let body: serde_json::Value = response.json();
        assert!(body.get("token").is_none());
        assert!(body["message"]
            .as_str()
            .unwrap()
            .contains("restart sign-in"));
        let remaining: i64 = db
            .pool()
            .get()
            .await
            .unwrap()
            .query_one(
                "SELECT COUNT(*) FROM sessions WHERE id = $1",
                &[&session.session_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(remaining, 0);
        let remaining: i64 = db
            .pool()
            .get()
            .await
            .unwrap()
            .query_one(
                "SELECT COUNT(*) FROM oauth_callback_codes WHERE code_hash = $1",
                &[&sha256_hex(&code)],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(remaining, 0);
        let replay = server
            .post("/v1/auth/exchange")
            .json(&json!({"code": code, "code_verifier": verifier}))
            .await;
        assert_eq!(replay.status_code(), 401);
        assert!(!replay.headers().contains_key(SET_COOKIE));
        assert_eq!(*calls.lock().unwrap(), vec![user.id]);
    }
}
