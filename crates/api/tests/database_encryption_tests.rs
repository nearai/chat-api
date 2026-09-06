mod common;

use common::{create_test_server_and_db, TestServerConfig};
use services::conversation::ports::{
    ConversationShareRepository, NewConversationShare, SharePermission, ShareRecipient,
    ShareRecipientKind, ShareType,
};
use services::UserId;
use uuid::Uuid;

#[tokio::test]
async fn encrypted_share_values_remain_queryable_and_readable() {
    let (_server, db) = create_test_server_and_db(TestServerConfig::default()).await;
    let config = db.pool().field_encryption().expect("test key configured");
    db.pool()
        .set_field_encryption(services::db_pool::FieldEncryptionConfig {
            write_enabled: true,
            ..config
        });
    let user_id = Uuid::new_v4();
    let conversation_id = format!("conv-encrypted-{user_id}");
    let member_email = format!("member-{user_id}@example.com");
    let reader_email = format!("reader-{user_id}@example.com");
    let client = db.pool().get().await.unwrap();
    client
        .execute(
            "INSERT INTO users(id,email) VALUES($1,$2)",
            &[&user_id, &format!("{user_id}@example.com")],
        )
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO conversations(id,user_id) VALUES($1,$2)",
            &[&conversation_id, &user_id],
        )
        .await
        .unwrap();
    drop(client);

    let repository = db.conversation_share_repository();
    let group = repository
        .create_group(
            UserId(user_id),
            "Private team",
            &[ShareRecipient {
                kind: ShareRecipientKind::Email,
                value: member_email.clone(),
            }],
        )
        .await
        .unwrap();
    assert_eq!(group.name, "Private team");
    let share = repository
        .create_share(NewConversationShare {
            conversation_id: conversation_id.clone(),
            owner_user_id: UserId(user_id),
            share_type: ShareType::Direct,
            permission: SharePermission::Read,
            recipient: Some(ShareRecipient {
                kind: ShareRecipientKind::Email,
                value: reader_email.clone(),
            }),
            group_id: None,
            org_email_pattern: None,
        })
        .await
        .unwrap();
    assert_eq!(share.recipient.unwrap().value, reader_email.as_str());

    let client = db.pool().get().await.unwrap();
    let (stored_name, name_token): (String, Option<Vec<u8>>) = client
        .query_one(
            "SELECT name,name_search_token FROM conversation_share_groups WHERE id=$1",
            &[&group.id],
        )
        .await
        .map(|row| (row.get(0), row.get(1)))
        .unwrap();
    assert!(!stored_name.contains("Private team"));
    assert!(name_token.is_some());
    drop(client);

    assert_eq!(
        repository
            .get_share_permission_for_user(&conversation_id, &reader_email, &[])
            .await
            .unwrap(),
        Some(SharePermission::Read)
    );
    let groups = repository
        .list_groups_for_member(&[ShareRecipient {
            kind: ShareRecipientKind::Email,
            value: member_email.clone(),
        }])
        .await
        .unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].members[0].value, member_email.as_str());
}

#[tokio::test]
async fn encrypted_share_upsert_migrates_legacy_row_and_downgrades_permission() {
    let (_server, db) = create_test_server_and_db(TestServerConfig::default()).await;
    let user_id = Uuid::new_v4();
    let conversation_id = format!("conv-mixed-{user_id}");
    let recipient = format!("Mixed-{user_id}@example.com");
    let client = db.pool().get().await.unwrap();
    client
        .execute(
            "INSERT INTO users(id,email) VALUES($1,$2)",
            &[&user_id, &format!("{user_id}@example.com")],
        )
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO conversations(id,user_id) VALUES($1,$2)",
            &[&conversation_id, &user_id],
        )
        .await
        .unwrap();
    client.execute(
        "INSERT INTO conversation_shares(id,conversation_id,owner_user_id,share_type,permission,recipient_type,recipient_value) VALUES($1,$2,$3,'direct','write','email',$4)",
        &[&Uuid::new_v4(), &conversation_id, &user_id, &recipient],
    ).await.unwrap();
    drop(client);

    let config = db.pool().field_encryption().expect("test key configured");
    db.pool()
        .set_field_encryption(services::db_pool::FieldEncryptionConfig {
            write_enabled: true,
            ..config
        });
    let repository = db.conversation_share_repository();
    repository
        .create_share(NewConversationShare {
            conversation_id: conversation_id.clone(),
            owner_user_id: UserId(user_id),
            share_type: ShareType::Direct,
            permission: SharePermission::Read,
            recipient: Some(ShareRecipient {
                kind: ShareRecipientKind::Email,
                value: recipient.to_lowercase(),
            }),
            group_id: None,
            org_email_pattern: None,
        })
        .await
        .unwrap();

    let client = db.pool().get().await.unwrap();
    let row = client
        .query_one(
            "SELECT count(*),max(permission),bool_and(recipient_value_search_token IS NOT NULL),bool_and(recipient_value NOT LIKE $2) FROM conversation_shares WHERE conversation_id=$1 AND share_type='direct'",
            &[&conversation_id, &format!("%{recipient}%")],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, String>(1), "read");
    assert!(row.get::<_, bool>(2));
    assert!(row.get::<_, bool>(3));
}

#[tokio::test]
async fn encrypted_group_names_preserve_raw_uniqueness() {
    let (_server, db) = create_test_server_and_db(TestServerConfig::default()).await;
    let config = db.pool().field_encryption().expect("test key configured");
    db.pool()
        .set_field_encryption(services::db_pool::FieldEncryptionConfig {
            write_enabled: true,
            ..config
        });
    let user_id = Uuid::new_v4();
    let client = db.pool().get().await.unwrap();
    client
        .execute(
            "INSERT INTO users(id,email) VALUES($1,$2)",
            &[&user_id, &format!("{user_id}@example.com")],
        )
        .await
        .unwrap();
    drop(client);
    let repository = db.conversation_share_repository();
    repository
        .create_group(UserId(user_id), "Team", &[])
        .await
        .unwrap();
    repository
        .create_group(UserId(user_id), "team", &[])
        .await
        .unwrap();
    repository
        .create_group(UserId(user_id), "Team ", &[])
        .await
        .unwrap();
    assert_eq!(
        repository.list_groups(UserId(user_id)).await.unwrap().len(),
        3
    );
}
