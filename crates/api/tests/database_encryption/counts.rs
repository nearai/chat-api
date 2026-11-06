use super::fixture::{Fixture, OLD, WRITE};
use database::field_encryption;
use http::HeaderName;
use serde_json::{json, Value};
use uuid::Uuid;

#[tokio::test]
async fn forged_ids_are_invalid_in_scan_job_progress_and_verify() {
    let f = Fixture::new().await;
    let client = f.db.pool().get().await.unwrap();
    let current = Uuid::new_v4();
    let raw = field_encryption::encrypt(
        &WRITE,
        "rotation-v2",
        "files",
        "filename",
        current,
        "current",
    )
    .unwrap();
    client.execute("INSERT INTO files(id,user_id,bytes,file_created_at,filename,purpose) VALUES($1,$2,1,1,$3,'assistants')", &[&format!("file-{current}"), &f.user, &raw]).await.unwrap();
    for key_id in [
        "rotation-v2".to_owned(),
        "unknown".to_owned(),
        "x".repeat(4096),
    ] {
        let id = Uuid::new_v4();
        let raw =
            field_encryption::encrypt(&OLD, "db-v1", "files", "filename", id, "forged").unwrap();
        let mut envelope: Value = serde_json::from_str(&raw).unwrap();
        envelope["key_id"] = json!(key_id);
        let raw = envelope.to_string();
        client.execute("INSERT INTO files(id,user_id,bytes,file_created_at,filename,purpose) VALUES($1,$2,1,1,$3,'assistants')", &[&format!("file-{id}"), &f.user, &raw]).await.unwrap();
    }
    drop(client);
    let scope = json!({"fields":[{"table":"files","column":"filename"}]});
    let scan = f
        .server
        .post("/v1/admin/database-encryption/scan")
        .add_header(HeaderName::from_static("authorization"), f.auth.clone())
        .json(&json!({"scope":scope}))
        .await;
    assert_eq!(scan.status_code(), 200);
    let scan: Value = scan.json();
    let expected = json!({"db-v1":1,"rotation-v2":1});
    assert_eq!(scan["totals"]["by_key_id"], expected);
    assert_eq!(scan["totals"]["invalid_envelope"], 3);
    for (mode, action) in [("dry_run", "rewrap"), ("verify", "verify")] {
        let response = f
            .server
            .post("/v1/admin/database-encryption/jobs")
            .add_header(HeaderName::from_static("authorization"), f.auth.clone())
            .json(&json!({"mode":mode,"scope":scope,"actions":[action]}))
            .await;
        assert_eq!(response.status_code(), 202);
        let accepted: Value = response.json();
        let result = f.wait_job(accepted["job_id"].as_str().unwrap()).await;
        assert_eq!(result["progress"]["by_key_id"], expected);
        assert_eq!(result["progress"]["invalid_envelopes"], 3);
        assert_eq!(result["progress"]["pass"], false);
    }
    f.cleanup().await;
}
