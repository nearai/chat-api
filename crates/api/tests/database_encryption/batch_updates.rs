use super::fixture::{random_key, Fixture};
use database::field_encryption::{self, KeyRing};
use http::HeaderName;
use serde_json::{json, Value};
use uuid::Uuid;

async fn execute(f: &Fixture, action: &str) -> Value {
    let response = f
        .server
        .post("/v1/admin/database-encryption/jobs")
        .add_header(HeaderName::from_static("authorization"), f.auth.clone())
        .json(&json!({
            "mode":"execute",
            "scope":{"fields":[{"table":"files","column":"filename"}]},
            "actions":[action],
            "batch_size":100
        }))
        .await;
    assert_eq!(response.status_code(), 202, "{}", response.text());
    let accepted: Value = response.json();
    f.wait_job(accepted["job_id"].as_str().unwrap()).await
}

#[tokio::test]
async fn multirow_encrypt_and_tokenless_rewrap_count_updated_rows() {
    let f = Fixture::new().await;
    let ids = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
    let client = f.db.pool().get().await.unwrap();
    for id in ids {
        client.execute(
            "INSERT INTO files(id,user_id,bytes,file_created_at,filename,purpose) VALUES($1,$2,1,1,'batch.txt','assistants')",
            &[&format!("file-{id}"), &f.user],
        ).await.unwrap();
    }
    drop(client);

    let encrypted = execute(&f, "encrypt").await;
    assert_eq!(encrypted["progress"]["encrypted"], 3);
    assert_eq!(execute(&f, "encrypt").await["progress"]["encrypted"], 0);
    let mut config = f.db.pool().field_encryption().unwrap();
    let previous = config
        .ring()
        .keys()
        .map(|(id, key)| (id.to_owned(), *key))
        .collect();
    config.ring = KeyRing::new("batch-v3".into(), random_key(), previous).unwrap();
    f.db.pool().set_field_encryption(config);

    let rewrapped = execute(&f, "rewrap").await;
    assert_eq!(rewrapped["progress"]["rewrapped"], 4);
    assert_eq!(execute(&f, "rewrap").await["progress"]["rewrapped"], 0);
    let config = f.db.pool().field_encryption().unwrap();
    let client = f.db.pool().get().await.unwrap();
    for id in ids {
        let row = client
            .query_one(
                "SELECT filename FROM files WHERE id=$1",
                &[&format!("file-{id}")],
            )
            .await
            .unwrap();
        let raw: String = row.get(0);
        assert_eq!(
            serde_json::from_str::<Value>(&raw).unwrap()["key_id"],
            "batch-v3"
        );
        assert_eq!(
            field_encryption::decrypt_with_ring(&raw, config.ring(), "files", "filename", id)
                .unwrap(),
            "batch.txt"
        );
    }
}
