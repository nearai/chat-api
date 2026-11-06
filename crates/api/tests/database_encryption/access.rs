use super::fixture::Fixture;
use crate::common::mock_login;
use http::{HeaderName, HeaderValue};
use serde_json::json;

#[tokio::test]
async fn execute_rewrap_is_rejected_when_global_writes_are_disabled() {
    // Given an old-key fixture and a disabled global write gate.
    let f = Fixture::new().await;
    let before = f.stored().await;
    let mut config = f.db.pool().field_encryption().unwrap();
    config.write_enabled = false;
    f.db.pool().set_field_encryption(config);

    // When an admin requests an execute rewrap.
    let response = f
        .server
        .post("/v1/admin/database-encryption/jobs")
        .add_header(HeaderName::from_static("authorization"), f.auth.clone())
        .json(&json!({"mode":"execute","scope":{"tables":["files"]},"actions":["rewrap"]}))
        .await;

    // Then no job or encrypted value is changed.
    assert_eq!(response.status_code(), 400);
    assert_eq!(f.stored().await, before);
    let count: i64 =
        f.db.pool()
            .get()
            .await
            .unwrap()
            .query_one("SELECT count(*) FROM database_encryption_jobs", &[])
            .await
            .unwrap()
            .get(0);
    assert_eq!(count, 0);
}

#[tokio::test]
async fn authenticated_non_admin_cannot_inspect_encryption_keys() {
    // Given an authenticated user outside the configured admin domains.
    let f = Fixture::new().await;
    let token = mock_login(&f.server, "reader@rotation.example").await;

    // When that user requests the replica's encryption configuration.
    let response = f
        .server
        .get("/v1/admin/database-encryption/keys")
        .add_header(
            HeaderName::from_static("authorization"),
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .await;

    // Then authorization rejects the authenticated user.
    assert_eq!(response.status_code(), 403);
}
