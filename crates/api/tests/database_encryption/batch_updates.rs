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

#[tokio::test]
async fn encrypt_isolates_database_token_conflicts_and_commits_unrelated_rows() {
    let f = Fixture::new().await;
    let conflict = Uuid::new_v4();
    let unrelated = Uuid::new_v4();
    let recipient_token = field_encryption::search_token(
        f.db.pool().field_encryption().unwrap().ring().write_key(),
        "conversation_share_group_members.member_value",
        &f.email,
    )
    .unwrap();
    let existing_value = field_encryption::encrypt(
        f.db.pool().field_encryption().unwrap().ring().write_key(),
        f.db.pool().field_encryption().unwrap().ring().write_id(),
        "conversation_share_group_members",
        "member_value",
        f.member,
        &f.email,
    )
    .unwrap();
    let client = f.db.pool().get().await.unwrap();
    client.execute(
        "UPDATE conversation_share_group_members SET member_value=$2,member_value_search_token=$3 WHERE id=$1",
        &[&f.member, &existing_value, &recipient_token],
    ).await.unwrap();
    client.execute(
        "INSERT INTO conversation_share_group_members(id,group_id,member_type,member_value) VALUES($1,$2,'email',$3),($4,$2,'email','other@example.com')",
        &[&conflict, &f.group, &f.email, &unrelated],
    ).await.unwrap();
    drop(client);

    let response = f.server.post("/v1/admin/database-encryption/jobs")
        .add_header(HeaderName::from_static("authorization"), f.auth.clone())
        .json(&json!({
            "mode":"execute",
            "scope":{"fields":[{"table":"conversation_share_group_members","column":"member_value"}]},
            "actions":["encrypt"], "batch_size":100
        })).await;
    assert_eq!(response.status_code(), 202, "{}", response.text());
    let accepted: Value = response.json();
    let result = f.wait_job(accepted["job_id"].as_str().unwrap()).await;
    assert_eq!(result["progress"]["token_conflicts"], 1);
    assert_eq!(result["progress"]["encrypted"], 1);

    let client = f.db.pool().get().await.unwrap();
    let encryption = f.db.pool().field_encryption().unwrap();
    let rows = client.query(
        "SELECT id,member_value,member_value_search_token FROM conversation_share_group_members WHERE id=ANY($1)",
        &[&vec![f.member, conflict, unrelated]],
    ).await.unwrap();
    assert_eq!(rows.len(), 3);
    for row in rows {
        let id: Uuid = row.get(0);
        let value: String = row.get(1);
        let token: Option<Vec<u8>> = row.get(2);
        if id == f.member {
            assert_eq!(value, existing_value);
            assert_eq!(token, Some(recipient_token.clone()));
        } else if id == conflict {
            assert_eq!(value, f.email);
            assert_eq!(token, None);
        } else {
            assert_eq!(
                field_encryption::decrypt_with_ring(
                    &value,
                    encryption.ring(),
                    "conversation_share_group_members",
                    "member_value",
                    id,
                )
                .unwrap(),
                "other@example.com"
            );
            assert_eq!(
                token,
                Some(
                    field_encryption::search_token(
                        encryption.ring().write_key(),
                        "conversation_share_group_members.member_value",
                        "other@example.com",
                    )
                    .unwrap()
                )
            );
        }
    }
    assert_eq!(
        client
            .query_one("SELECT 1", &[])
            .await
            .unwrap()
            .get::<_, i32>(0),
        1
    );
    drop(client);
    assert_eq!(verify(&f).await["progress"]["pass"], false);
    f.cleanup().await;
}

async fn verify(f: &Fixture) -> Value {
    let response = f.server.post("/v1/admin/database-encryption/jobs")
        .add_header(HeaderName::from_static("authorization"), f.auth.clone())
        .json(&json!({
            "mode":"verify",
            "scope":{"fields":[{"table":"conversation_share_group_members","column":"member_value"}]},
            "actions":["verify"], "batch_size":100
        })).await;
    assert_eq!(response.status_code(), 202, "{}", response.text());
    let accepted: Value = response.json();
    f.wait_job(accepted["job_id"].as_str().unwrap()).await
}
