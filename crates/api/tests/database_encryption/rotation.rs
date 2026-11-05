use super::fixture::{ring_config, Fixture, WRITE};
use database::field_encryption;
use http::HeaderName;
use serde_json::{json, Value};
use services::auth::ports::OAuthRepository;
use services::conversation::ports::{
    ConversationShareRepository, SharePermission, ShareRecipient, ShareRecipientKind,
};
use services::file::ports::FileRepository;
use services::user::ports::OAuthProvider;
use services::UserId;

async fn assert_reads(f: &Fixture) {
    assert_eq!(
        f.db.file_repository()
            .get_file(&f.file, UserId(f.user))
            .await
            .unwrap()
            .filename,
        "rotation.txt"
    );
    assert_eq!(
        f.db.oauth_repository()
            .get_oauth_tokens(UserId(f.user), OAuthProvider::Google)
            .await
            .unwrap()
            .unwrap()
            .access_token,
        "rotation-access"
    );
    let shares = f.db.conversation_share_repository();
    assert_eq!(
        shares.list_groups(UserId(f.user)).await.unwrap()[0].name,
        f.name
    );
    assert_eq!(
        shares
            .get_share_permission_for_user(&f.conversation, &f.email, &[])
            .await
            .unwrap(),
        Some(SharePermission::Read)
    );
    assert_eq!(
        shares
            .list_groups_for_member(&[ShareRecipient {
                kind: ShareRecipientKind::Email,
                value: f.email.clone()
            }])
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn previous_key_rotation_preserves_reads_tokens_and_verification() {
    let f = Fixture::new().await;
    assert_reads(&f).await;
    let keys = f
        .server
        .get("/v1/admin/database-encryption/keys")
        .add_header(HeaderName::from_static("authorization"), f.auth.clone())
        .await;
    assert_eq!(keys.status_code(), 200);
    let keys: Value = keys.json();
    assert_eq!(keys["write_key_id"], "rotation-v2");
    assert_eq!(keys["read_key_ids"], json!(["db-v1"]));
    assert_eq!(
        f.server
            .get("/v1/admin/database-encryption/keys")
            .await
            .status_code(),
        401
    );
    let scan = f
        .server
        .post("/v1/admin/database-encryption/scan")
        .add_header(HeaderName::from_static("authorization"), f.auth.clone())
        .json(&json!({"scope":{}}))
        .await;
    assert_eq!(scan.status_code(), 200);
    let scan: Value = scan.json();
    assert_eq!(scan["totals"]["stale"], 5);
    assert_eq!(scan["totals"]["by_key_id"]["db-v1"], 5);
    assert_eq!(f.job("verify", "verify").await["progress"]["pass"], false);
    let before = f.stored().await;
    let dry = f.job("dry_run", "rewrap").await;
    assert_eq!(dry["progress"]["stale"], 5);
    assert_eq!(f.stored().await, before);
    let execute = f.job("execute", "rewrap").await;
    assert_eq!(execute["progress"]["rewrapped"], 5);
    assert_eq!(execute["scope"]["options"]["batch_delay_ms"], 1);
    let after = f.stored().await;
    for (value, _) in &after {
        let envelope: Value = serde_json::from_str(value).unwrap();
        assert_eq!(envelope["key_id"], "rotation-v2");
    }
    for (index, domain, value) in [
        (1, "conversation_share_groups.name", f.name.as_str()),
        (
            2,
            "conversation_share_group_members.member_value",
            f.email.as_str(),
        ),
        (3, "conversation_shares.recipient_value", f.email.as_str()),
    ] {
        assert_eq!(
            after[index].1,
            Some(field_encryption::search_token(&WRITE, domain, value).unwrap())
        );
    }
    assert_reads(&f).await;
    assert_eq!(f.job("execute", "rewrap").await["progress"]["rewrapped"], 0);
    assert_eq!(f.job("verify", "verify").await["progress"]["pass"], true);
    let mut config = ring_config();
    config.ring = field_encryption::KeyRing::new("rotation-v2".into(), *WRITE, vec![]).unwrap();
    f.db.pool().set_field_encryption(config);
    assert_reads(&f).await;
    assert_eq!(f.job("verify", "verify").await["progress"]["pass"], true);
    f.cleanup().await;
}
