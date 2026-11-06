use super::fixture::{Fixture, OLD, WRITE};
use database::field_encryption;
use services::user::ports::UserRepository;
use services::UserId;
use uuid::Uuid;

#[tokio::test]
async fn rewrap_repairs_current_tokens_and_continues_after_unknown_ids() {
    let f = Fixture::new().await;
    f.job("execute", "rewrap").await;
    let client = f.db.pool().get().await.unwrap();
    let old_token =
        field_encryption::search_token(&OLD, "conversation_shares.recipient_value", &f.email)
            .unwrap();
    client
        .execute(
            "UPDATE conversation_shares SET recipient_value_search_token=$2 WHERE id=$1",
            &[&f.share, &old_token],
        )
        .await
        .unwrap();
    let unknown = Uuid::new_v4();
    let raw = field_encryption::encrypt(
        &OLD,
        "unconfigured",
        "files",
        "filename",
        unknown,
        "unknown.txt",
    )
    .unwrap();
    client.execute("INSERT INTO files(id,user_id,bytes,file_created_at,filename,purpose) VALUES($1,$2,1,1,$3,'assistants')",&[&format!("file-{unknown}"),&f.user,&raw]).await.unwrap();
    drop(client);
    assert_eq!(f.job("verify", "verify").await["progress"]["pass"], false);
    let before = f.stored().await;
    let dry = f.job("dry_run", "rewrap").await;
    assert_eq!(dry["progress"]["tokens_rewritten"], 1);
    assert_eq!(f.stored().await, before);
    let result = f.job("execute", "rewrap").await;
    assert_eq!(result["progress"]["rewrapped"], 0);
    assert_eq!(result["progress"]["tokens_rewritten"], 1);
    assert_eq!(result["progress"]["invalid_envelopes"], 1);
    assert!(result["progress"]
        .to_string()
        .contains(&unknown.to_string()));
    let stored = f.stored().await;
    assert_eq!(
        stored[3].1,
        Some(
            field_encryption::search_token(&WRITE, "conversation_shares.recipient_value", &f.email)
                .unwrap()
        )
    );
    f.cleanup().await;
}

#[tokio::test]
async fn rewrap_token_conflicts_leave_the_row_unchanged_and_keep_processing() {
    let f = Fixture::new().await;
    let duplicate = Uuid::new_v4();
    let raw = field_encryption::encrypt(
        &WRITE,
        "rotation-v2",
        "conversation_share_groups",
        "name",
        duplicate,
        &f.name,
    )
    .unwrap();
    let token =
        field_encryption::search_token(&WRITE, "conversation_share_groups.name", &f.name).unwrap();
    let client = f.db.pool().get().await.unwrap();
    client.execute("INSERT INTO conversation_share_groups(id,owner_user_id,name,name_search_token) VALUES($1,$2,$3,$4)",&[&duplicate,&f.user,&raw,&token]).await.unwrap();
    let plain = Uuid::new_v4();
    client.execute("INSERT INTO files(id,user_id,bytes,file_created_at,filename,purpose) VALUES($1,$2,1,1,'plain.txt','assistants')",&[&format!("file-{plain}"),&f.user]).await.unwrap();
    drop(client);
    let before = f.stored().await;
    let dry = f.job("dry_run", "rewrap").await;
    assert_eq!(dry["progress"]["token_conflicts"], 1);
    assert_eq!(f.stored().await, before);
    let result = f.job("execute", "rewrap").await;
    assert_eq!(result["progress"]["token_conflicts"], 1);
    assert_eq!(result["progress"]["rewrapped"], 4);
    assert!(result["progress"]
        .to_string()
        .contains(&f.group.to_string()));
    let after = f.stored().await;
    assert_eq!(after[1], before[1]);
    let client = f.db.pool().get().await.unwrap();
    let row = client
        .query_one(
            "SELECT filename FROM files WHERE id=$1",
            &[&format!("file-{plain}")],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "plain.txt");
    drop(client);
    assert_eq!(f.job("verify", "verify").await["progress"]["pass"], false);
    f.cleanup().await;
}

#[tokio::test]
async fn account_deletion_removes_previous_key_recipient_tokens() {
    let f = Fixture::new().await;
    let recipient = Uuid::new_v4();
    let client = f.db.pool().get().await.unwrap();
    client
        .execute(
            "INSERT INTO users(id,email) VALUES($1,$2)",
            &[&recipient, &f.email],
        )
        .await
        .unwrap();
    drop(client);
    f.db.user_repository()
        .delete_user_account(UserId(recipient), &[], &[])
        .await
        .unwrap();
    let client = f.db.pool().get().await.unwrap();
    for (table, id) in [
        ("conversation_shares", f.share),
        ("conversation_share_group_members", f.member),
    ] {
        assert_eq!(
            client
                .query_one(&format!("SELECT count(*) FROM {table} WHERE id=$1"), &[&id])
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
    }
    drop(client);
    f.cleanup().await;
}
