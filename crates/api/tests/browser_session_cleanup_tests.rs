#![cfg(feature = "test")]
mod common;

use common::{create_test_server_with_state, TestServerConfig};
use database::repositories::browser_session_repository::BrowserSessionRepository;
use services::auth::ports::SessionRepository;
use services::user::ports::UserRepository;

const ORIGIN: &str = "https://cleanup-session-test.near.ai";

#[tokio::test]
async fn cleanup_is_bounded_skips_locked_roots_and_preserves_live_replay_evidence() {
    std::env::set_var("AGENT_API_TOKEN", "session-cleanup-test");
    let (_, db, _) = create_test_server_with_state(TestServerConfig::default()).await;
    let repo = BrowserSessionRepository(db.pool().clone());
    while repo.cleanup_expired(500).await.unwrap() > 0 {}

    let user = db
        .user_repository()
        .create_user(
            format!("cleanup-{}@example.com", uuid::Uuid::new_v4()),
            None,
            None,
        )
        .await
        .unwrap();

    let mut families = Vec::new();
    for _ in 0..4 {
        let session = db
            .session_repository()
            .create_session(user.id)
            .await
            .unwrap();
        families.push(repo.establish(&session, "user", ORIGIN).await.unwrap());
    }

    let live = repo
        .refresh(&families[3].refresh_token, "user", ORIGIN, false)
        .await
        .unwrap()
        .unwrap();
    let legacy = db
        .session_repository()
        .create_session(user.id)
        .await
        .unwrap();
    let client = db.pool().get().await.unwrap();

    // Exercise both expiry predicates and a legacy session that cleanup must ignore.
    for id in [
        families[0].session_id,
        families[2].session_id,
        legacy.session_id,
    ] {
        client
            .execute(
                "UPDATE sessions SET expires_at = NOW() WHERE id = $1",
                &[&id],
            )
            .await
            .unwrap();
    }
    client
        .execute(
            "UPDATE browser_sessions SET idle_expires_at = NOW() WHERE session_id = $1",
            &[&families[1].session_id],
        )
        .await
        .unwrap();

    let mut locked_client = db.pool().get().await.unwrap();
    let locked = locked_client.transaction().await.unwrap();
    locked
        .query_one(
            "SELECT id FROM sessions WHERE id = $1 FOR UPDATE",
            &[&families[2].session_id],
        )
        .await
        .unwrap();

    assert_eq!(repo.cleanup_expired(1).await.unwrap(), 1);
    let deleted =
        tokio::time::timeout(std::time::Duration::from_secs(2), repo.cleanup_expired(500))
            .await
            .expect("cleanup must skip locked roots")
            .unwrap();
    assert_eq!(deleted, 1);
    assert!(db
        .session_repository()
        .get_session_by_id(families[2].session_id)
        .await
        .unwrap()
        .is_some());
    assert!(db
        .session_repository()
        .get_session_by_id(legacy.session_id)
        .await
        .unwrap()
        .is_some());

    for id in [families[0].session_id, families[1].session_id] {
        for table in [
            "browser_sessions",
            "browser_access_tokens",
            "browser_refresh_tokens",
        ] {
            let count: i64 = client
                .query_one(
                    &format!("SELECT COUNT(*) FROM {table} WHERE session_id = $1"),
                    &[&id],
                )
                .await
                .unwrap()
                .get(0);
            assert_eq!(count, 0, "expired family rows must cascade from {table}");
        }
    }

    locked.rollback().await.unwrap();
    assert_eq!(repo.cleanup_expired(500).await.unwrap(), 1);
    let live_records: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM browser_refresh_tokens WHERE session_id = $1",
            &[&live.session_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        live_records, 2,
        "live replay tombstones must survive cleanup"
    );

    // Cleanup must not undermine subsequent replay detection.
    assert!(repo
        .refresh(&families[3].refresh_token, "user", ORIGIN, false)
        .await
        .unwrap()
        .is_none());
    assert!(repo
        .refresh(&live.refresh_token, "user", ORIGIN, false)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn failed_browser_setup_revokes_the_original_login_credential() {
    std::env::set_var("AGENT_API_TOKEN", "session-cleanup-test");
    std::env::set_var("BROWSER_SESSION_USER_ORIGINS", ORIGIN);
    let (_, db, state) = create_test_server_with_state(TestServerConfig::default()).await;
    let user = db
        .user_repository()
        .create_user(
            format!("setup-failure-{}@example.com", uuid::Uuid::new_v4()),
            None,
            None,
        )
        .await
        .unwrap();
    let mut session = db
        .session_repository()
        .create_session(user.id)
        .await
        .unwrap();
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::ORIGIN, ORIGIN.parse().unwrap());
    headers.insert("x-session-client", "user".parse().unwrap());
    let context = api::routes::browser_session::login_context(&headers).unwrap();

    // Force establishment to fail its atomic credential match after login has
    // already created a valid session, without making the database unavailable.
    session.token = Some("wrong-login-token".into());
    let result =
        api::routes::browser_session::establish(&state, context.as_ref(), &mut session).await;

    assert!(result.is_err());
    assert!(session.token.is_none());
    assert!(db
        .session_repository()
        .get_session_by_id(session.session_id)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn missing_roots_are_not_classified_as_live_legacy_sessions() {
    std::env::set_var("AGENT_API_TOKEN", "session-cleanup-test");
    let (_, db, _) = create_test_server_with_state(TestServerConfig::default()).await;
    let user = db
        .user_repository()
        .create_user(
            format!("classification-race-{}@example.com", uuid::Uuid::new_v4()),
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

    assert_eq!(
        db.session_repository()
            .browser_session_client(session.session_id)
            .await
            .unwrap(),
        None
    );

    BrowserSessionRepository(db.pool().clone())
        .establish(&session, "user", ORIGIN)
        .await
        .unwrap();

    assert_eq!(
        db.session_repository()
            .browser_session_client(session.session_id)
            .await
            .unwrap()
            .as_deref(),
        Some("user")
    );

    // Model deletion between access-token authentication and the admin lookup.
    db.session_repository()
        .delete_session(session.session_id)
        .await
        .unwrap();

    assert!(db
        .session_repository()
        .browser_session_client(session.session_id)
        .await
        .is_err());
}
