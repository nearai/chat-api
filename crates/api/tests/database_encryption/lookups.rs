use super::fixture::Fixture;
use services::conversation::ports::{
    ConversationShareRepository, NewConversationShare, SharePermission, ShareRecipient,
    ShareRecipientKind, ShareType,
};
use services::UserId;

#[tokio::test]
async fn previous_key_lookups_preserve_uniqueness_and_identity_pairs() {
    let f = Fixture::new().await;
    let shares = f.db.conversation_share_repository();
    assert!(shares
        .create_group(UserId(f.user), &f.name, &[])
        .await
        .is_err());
    let second = shares
        .create_group(UserId(f.user), "Different team", &[])
        .await
        .unwrap();
    assert!(shares
        .update_group(UserId(f.user), second.id, Some(&f.name), None)
        .await
        .is_err());
    let upsert = shares
        .create_share(NewConversationShare {
            conversation_id: f.conversation.clone(),
            owner_user_id: UserId(f.user),
            share_type: ShareType::Direct,
            permission: SharePermission::Write,
            recipient: Some(ShareRecipient {
                kind: ShareRecipientKind::Email,
                value: f.email.to_uppercase(),
            }),
            group_id: None,
            org_email_pattern: None,
        })
        .await
        .unwrap();
    assert_eq!(upsert.id, f.share);
    let groups = shares
        .list_groups_for_member(&[
            ShareRecipient {
                kind: ShareRecipientKind::NearAccount,
                value: f.email.clone(),
            },
            ShareRecipient {
                kind: ShareRecipientKind::Email,
                value: "different@example.com".into(),
            },
        ])
        .await
        .unwrap();
    assert!(groups.is_empty());
    assert_eq!(
        shares
            .list_groups_for_member(&[
                ShareRecipient {
                    kind: ShareRecipientKind::Email,
                    value: f.email.clone()
                },
                ShareRecipient {
                    kind: ShareRecipientKind::NearAccount,
                    value: "different.near".into()
                },
            ])
            .await
            .unwrap()
            .len(),
        1
    );
    f.cleanup().await;
}
