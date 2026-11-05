use super::fixture::Fixture;
use chrono::{DateTime, Utc};
use http::HeaderName;
use serde_json::{json, Value};
use std::time::Duration;
use uuid::Uuid;

#[tokio::test]
async fn concurrently_created_jobs_execute_one_after_the_other() {
    // Given two distinct scopes, each with an old-key row and a visible delay.
    let f = Fixture::new().await;
    let fixture = &f;
    let create = |table| async move {
        fixture
            .server
            .post("/v1/admin/database-encryption/jobs")
            .add_header(
                HeaderName::from_static("authorization"),
                fixture.auth.clone(),
            )
            .json(&json!({"mode":"execute","scope":{"tables":[table]},
                "batch_size":1,"batch_delay_ms":1000,"actions":["rewrap"]}))
            .await
    };

    // When both jobs are submitted concurrently.
    let (left, right) = tokio::join!(create("files"), create("oauth_tokens"));
    assert_eq!(left.status_code(), 202, "{}", left.text());
    assert_eq!(right.status_code(), 202, "{}", right.text());
    let ids = [left.json::<Value>(), right.json::<Value>()]
        .map(|response| Uuid::parse_str(response["job_id"].as_str().unwrap()).unwrap());

    // Then one runs while the other remains unstarted, and their lifetimes do not overlap.
    let first = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let rows = f.db.pool().get().await.unwrap()
                .query("SELECT id,status,started_at,progress FROM database_encryption_jobs WHERE id=ANY($1)", &[&ids.as_slice()])
                .await.unwrap();
            if let Some(running) = rows.iter().find(|row| {
                row.get::<_, String>(1) == "running"
                    && row.get::<_, Value>(3)["processed"] == 1
            }) {
                let running_id: Uuid = running.get(0);
                let queued = rows.iter().find(|row| row.get::<_, Uuid>(0) != running_id).unwrap();
                assert_eq!(queued.get::<_, String>(1), "queued");
                assert_eq!(queued.get::<_, Option<DateTime<Utc>>>(2), None);
                break running_id;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("one submitted job must enter its first-batch delay");
    let first_result = f.wait_job(&first.to_string()).await;
    let second = *ids.iter().find(|id| **id != first).unwrap();
    let second_result = f.wait_job(&second.to_string()).await;
    for result in [first_result, second_result] {
        assert_eq!(result["progress"]["rewrapped"], 1);
    }
    let client = f.db.pool().get().await.unwrap();
    let row = client.query_one(
        "SELECT a.completed_at<=b.started_at FROM database_encryption_jobs a CROSS JOIN database_encryption_jobs b WHERE a.id=$1 AND b.id=$2",
        &[&first, &second],
    ).await.unwrap();
    assert!(
        row.get::<_, bool>(0),
        "second job must start after the first finishes"
    );
}
