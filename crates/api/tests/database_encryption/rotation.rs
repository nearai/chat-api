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

#[tokio::test]
async fn previous_key_tokens_remain_valid_for_non_rewrap_jobs() {
    // Given five stale envelopes, including three valid old-key search tokens.
    let f = Fixture::new().await;
    let before = f.stored().await;
    for (mode, action) in [
        ("dry_run", "encrypt"),
        ("execute", "encrypt"),
        ("verify", "verify"),
    ] {
        // When a non-rewrap job inspects the old-key rows.
        let result = f.job(mode, action).await;

        // Then stale rows remain unchanged and are not classified as invalid.
        assert_eq!(f.stored().await, before, "{mode}/{action}");
        let progress = &result["progress"];
        assert_eq!(progress["stale"], 5, "{mode}/{action}");
        assert_eq!(progress["invalid_envelopes"], 0, "{mode}/{action}");
        assert_eq!(progress["invalid_sample_ids"], json!([]), "{mode}/{action}");
        assert_eq!(progress["pass"], mode != "verify", "{mode}/{action}");
    }
    f.cleanup().await;
}

#[tokio::test]
async fn previous_key_token_corruption_is_invalid_for_non_rewrap_jobs() {
    // Given the same five stale envelopes with exactly one corrupted token.
    let f = Fixture::new().await;
    let mut before = f.stored().await;
    let token = before[1].1.as_mut().unwrap();
    token[0] ^= 1;
    let client = f.db.pool().get().await.unwrap();
    assert_eq!(
        client
            .execute(
                "UPDATE conversation_share_groups SET name_search_token=$1 WHERE id=$2",
                &[token, &f.group],
            )
            .await
            .unwrap(),
        1
    );
    drop(client);

    for (mode, action) in [
        ("dry_run", "encrypt"),
        ("execute", "encrypt"),
        ("verify", "verify"),
    ] {
        // When a non-rewrap job validates the tokens.
        let result = f.job(mode, action).await;

        // Then only the corrupted row is invalid; valid stale peers stay valid.
        assert_eq!(f.stored().await, before, "{mode}/{action}");
        let progress = &result["progress"];
        assert_eq!(progress["stale"], 5, "{mode}/{action}");
        assert_eq!(progress["invalid_envelopes"], 1, "{mode}/{action}");
        assert_eq!(
            progress["invalid_sample_ids"],
            json!([f.group.to_string()]),
            "{mode}/{action}"
        );
        assert_eq!(progress["pass"], false, "{mode}/{action}");
    }
    f.cleanup().await;
}

#[tokio::test]
async fn scan_validates_previous_key_tokens_and_preserves_invalid_rows() {
    let f = Fixture::new().await;
    let valid_scan = f
        .server
        .post("/v1/admin/database-encryption/scan")
        .add_header(HeaderName::from_static("authorization"), f.auth.clone())
        .json(&json!({"scope":{"fields":[{"table":"conversation_share_groups","column":"name"}]}}))
        .await;
    assert_eq!(valid_scan.status_code(), 200);
    let valid_scan: Value = valid_scan.json();
    assert_eq!(valid_scan["totals"]["stale"], 1);
    assert_eq!(valid_scan["totals"]["invalid_envelope"], 0);

    let original: Vec<u8> =
        f.db.pool()
            .get()
            .await
            .unwrap()
            .query_one(
                "SELECT name_search_token FROM conversation_share_groups WHERE id=$1",
                &[&f.group],
            )
            .await
            .unwrap()
            .get(0);
    for corrupted in [
        Some({
            let mut token = original.clone();
            token[0] ^= 1;
            token
        }),
        None,
    ] {
        let client = f.db.pool().get().await.unwrap();
        client
            .execute(
                "UPDATE conversation_share_groups SET name_search_token=$1 WHERE id=$2",
                &[&corrupted, &f.group],
            )
            .await
            .unwrap();
        drop(client);

        let scan = f.server.post("/v1/admin/database-encryption/scan")
            .add_header(HeaderName::from_static("authorization"), f.auth.clone())
            .json(&json!({"scope":{"fields":[{"table":"conversation_share_groups","column":"name"}]}}))
            .await;
        assert_eq!(scan.status_code(), 200);
        let scan: Value = scan.json();
        assert_eq!(scan["totals"]["stale"], 1);
        assert_eq!(scan["totals"]["encrypted"], 0);
        assert_eq!(scan["totals"]["invalid_envelope"], 1);

        let stored: Option<Vec<u8>> =
            f.db.pool()
                .get()
                .await
                .unwrap()
                .query_one(
                    "SELECT name_search_token FROM conversation_share_groups WHERE id=$1",
                    &[&f.group],
                )
                .await
                .unwrap()
                .get(0);
        assert_eq!(stored, corrupted);
        let verify = f.job("verify", "verify").await;
        assert_eq!(verify["progress"]["invalid_envelopes"], 1);
        assert_eq!(verify["progress"]["pass"], false);

        let client = f.db.pool().get().await.unwrap();
        client
            .execute(
                "UPDATE conversation_share_groups SET name_search_token=$1 WHERE id=$2",
                &[&Some(original.clone()), &f.group],
            )
            .await
            .unwrap();
        drop(client);
    }
    f.cleanup().await;
}
