use super::fixture::Fixture;
use http::HeaderName;
use serde_json::{json, Value};
use std::time::Duration;

#[tokio::test]
async fn duplicate_delay_locations_are_rejected() {
    let f = Fixture::new().await;
    let response = f.server.post("/v1/admin/database-encryption/jobs")
        .add_header(HeaderName::from_static("authorization"), f.auth.clone())
        .json(&json!({"mode":"dry_run","scope":{"tables":["files"],"options":{"batch_delay_ms":0}},"batch_delay_ms":0,"actions":["rewrap"]})).await;
    assert_eq!(response.status_code(), 400);
    f.cleanup().await;
}

#[tokio::test]
async fn large_delay_releases_batch_resources_and_cancels_after_last_row() {
    let f = Fixture::new().await;
    let response = f.server.post("/v1/admin/database-encryption/jobs")
        .add_header(HeaderName::from_static("authorization"), f.auth.clone())
        .json(&json!({"mode":"dry_run","scope":{"tables":["files"]},"batch_size":1,"max_rows":1,"batch_delay_ms":10000,"actions":["rewrap"]})).await;
    assert_eq!(response.status_code(), 202);
    let accepted: Value = response.json();
    let id = accepted["job_id"].as_str().unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let status = f
                .server
                .get(&format!("/v1/admin/database-encryption/jobs/{id}"))
                .add_header(HeaderName::from_static("authorization"), f.auth.clone())
                .await;
            let status: Value = status.json();
            if status["progress"]["processed"] == 1 {
                assert_eq!(status["status"], "running");
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("first batch commits");
    let client = f.db.pool().get().await.unwrap();
    let locked: bool = client
        .query_one(
            "SELECT pg_try_advisory_lock($1)",
            &[&0x4e45415243484154_i64],
        )
        .await
        .unwrap()
        .get(0);
    if locked {
        client
            .query_one("SELECT pg_advisory_unlock($1)", &[&0x4e45415243484154_i64])
            .await
            .unwrap();
    }
    assert!(
        !locked,
        "job ownership must prevent a second worker taking over during the delay"
    );
    let held: i64 = client.query_one("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND state='idle in transaction'", &[]).await.unwrap().get(0);
    assert_eq!(held, 1, "only the job ownership transaction remains open");
    client
        .query_one(
            "SELECT filename FROM files WHERE id=$1 FOR UPDATE NOWAIT",
            &[&f.file],
        )
        .await
        .expect("the batch releases its application row locks during the delay");
    drop(client);
    let pool = f.db.pool().status().unwrap();
    assert_eq!(
        pool.available + 1,
        pool.size,
        "only the job ownership connection remains reserved during the delay"
    );
    let started = tokio::time::Instant::now();
    let response = f
        .server
        .post(&format!("/v1/admin/database-encryption/jobs/{id}/cancel"))
        .add_header(HeaderName::from_static("authorization"), f.auth.clone())
        .await;
    assert_eq!(response.status_code(), 200);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let response = f
                .server
                .get(&format!("/v1/admin/database-encryption/jobs/{id}"))
                .add_header(HeaderName::from_static("authorization"), f.auth.clone())
                .await;
            let status: Value = response.json();
            if status["status"] == "cancelled" {
                assert_eq!(status["progress"]["processed"], 1);
                assert!(!status["completed_at"].is_null());
                break;
            }
            assert_ne!(status["status"], "completed", "{status}");
            assert_ne!(status["status"], "failed", "{status}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("large-delay job cancels within two seconds");
    assert!(started.elapsed() < Duration::from_secs(2));
    f.cleanup().await;
}
