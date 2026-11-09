mod common;
mod retired_stateful;

use common::{create_test_server_and_db, mock_login, TestServerConfig};
use services::file::ports::{FileData, FileRepository};
use services::user::ports::UserRepository;
use services::UserId;
use uuid::Uuid;
use wiremock::MockServer;

#[tokio::test]
async fn repository_encrypts_filename_and_dual_reads_it() {
    let (_server, db) = create_test_server_and_db(TestServerConfig::default()).await;
    let config = db.pool().field_encryption().expect("test key configured");
    db.pool()
        .set_field_encryption(services::db_pool::FieldEncryptionConfig {
            write_enabled: true,
            ..config
        });

    let user_id = Uuid::new_v4();
    let file_id = format!("file-{user_id}");
    let client = db.pool().get().await.unwrap();

    client
        .execute(
            "INSERT INTO users(id,email) VALUES($1,$2)",
            &[&user_id, &format!("{user_id}@example.com")],
        )
        .await
        .unwrap();
    drop(client);

    let file = FileData {
        id: file_id.clone(),
        bytes: 7,
        created_at: 1,
        expires_at: None,
        filename: "private-name.txt".into(),
        purpose: "assistants".into(),
    };

    db.file_repository()
        .upsert_file(&file, UserId(user_id))
        .await
        .unwrap();

    let client = db.pool().get().await.unwrap();
    let stored: String = client
        .query_one("SELECT filename FROM files WHERE id=$1", &[&file_id])
        .await
        .unwrap()
        .get(0);

    assert!(stored.contains(database::field_encryption::MARKER));
    assert!(!stored.contains("private-name.txt"));
    drop(client);

    let loaded = db
        .file_repository()
        .get_file(&file_id, UserId(user_id))
        .await
        .unwrap();

    assert_eq!(loaded.filename, "private-name.txt");
}

#[tokio::test]
async fn file_endpoints_are_retired_without_accessing_data() {
    let upstream = MockServer::start().await;
    let (server, db) = create_test_server_and_db(TestServerConfig {
        proxy_base_url: Some(upstream.uri()),
        ..TestServerConfig::default()
    })
    .await;
    let email = format!("retired-file-{}@example.com", Uuid::new_v4());
    let token = mock_login(&server, &email).await;
    let owner = db
        .user_repository()
        .get_user_by_email(&email)
        .await
        .unwrap()
        .unwrap();
    let file = FileData {
        id: format!("file-{}", Uuid::new_v4()),
        bytes: 7,
        created_at: 1,
        expires_at: None,
        filename: "private.txt".into(),
        purpose: "assistants".into(),
    };

    db.file_repository()
        .upsert_file(&file, owner.id)
        .await
        .unwrap();
    let paths = vec![
        "/v1/files".to_string(),
        "/v1/files/".to_string(),
        "/v1/files/missing".to_string(),
        format!("/v1/files/{}", file.id),
        format!("/v1/files/{}/content", file.id),
        format!("/v1/files/{}/unknown/child", file.id),
    ];

    retired_stateful::assert_retired_paths(&server, &paths, &token).await;

    let stored = db
        .file_repository()
        .get_file(&file.id, owner.id)
        .await
        .unwrap();
    assert_eq!(stored.filename, file.filename);
    assert!(upstream.received_requests().await.unwrap().is_empty());
}
