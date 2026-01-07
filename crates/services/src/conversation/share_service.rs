use async_trait::async_trait;
use rand::rngs::OsRng;
use rand::TryRngCore;
use std::sync::Arc;

use super::ports::{
    ConversationError, ConversationRepository, ConversationShare, ConversationShareRepository,
    ConversationShareService, NewConversationShare, ShareGroup, SharePermission, ShareRecipient,
    ShareRecipientKind, ShareTarget, ShareType,
};
use crate::user::ports::{OAuthProvider, UserRepository};
use crate::UserId;

const PUBLIC_TOKEN_BYTES: usize = 32;

pub struct ConversationShareServiceImpl {
    conversation_repository: Arc<dyn ConversationRepository>,
    share_repository: Arc<dyn ConversationShareRepository>,
    user_repository: Arc<dyn UserRepository>,
}

impl ConversationShareServiceImpl {
    pub fn new(
        conversation_repository: Arc<dyn ConversationRepository>,
        share_repository: Arc<dyn ConversationShareRepository>,
        user_repository: Arc<dyn UserRepository>,
    ) -> Self {
        Self {
            conversation_repository,
            share_repository,
            user_repository,
        }
    }

    fn normalize_recipient(recipient: ShareRecipient) -> ShareRecipient {
        match recipient.kind {
            ShareRecipientKind::Email => ShareRecipient {
                kind: recipient.kind,
                value: recipient.value.trim().to_lowercase(),
            },
            ShareRecipientKind::NearAccount => ShareRecipient {
                kind: recipient.kind,
                value: recipient.value.trim().to_string(),
            },
        }
    }

    fn normalize_org_pattern(pattern: String) -> String {
        let trimmed = pattern.trim().to_string();
        if trimmed.contains('%') || trimmed.contains('_') || trimmed.contains('@') {
            trimmed
        } else {
            format!("%@{trimmed}")
        }
    }

    fn generate_public_token() -> String {
        let mut bytes = [0u8; PUBLIC_TOKEN_BYTES];
        let mut rng = OsRng;
        rng.try_fill_bytes(&mut bytes)
            .expect("Failed to generate share token");
        hex::encode(bytes)
    }

    fn has_required_permission(
        share_permission: SharePermission,
        required_permission: SharePermission,
    ) -> bool {
        match required_permission {
            SharePermission::Read => true,
            SharePermission::Write => share_permission.allows_write(),
        }
    }
}

#[async_trait]
impl ConversationShareService for ConversationShareServiceImpl {
    async fn ensure_access(
        &self,
        conversation_id: &str,
        user_id: UserId,
        required_permission: SharePermission,
    ) -> Result<(), ConversationError> {
        match self
            .conversation_repository
            .access_conversation(conversation_id, user_id)
            .await
        {
            Ok(()) => return Ok(()),
            Err(ConversationError::NotFound) => {}
            Err(error) => return Err(error),
        }

        let user = self
            .user_repository
            .get_user(user_id)
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?
            .ok_or(ConversationError::AccessDenied)?;

        let linked_accounts = self
            .user_repository
            .get_linked_accounts(user_id)
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let near_accounts: Vec<String> = linked_accounts
            .into_iter()
            .filter(|account| account.provider == OAuthProvider::Near)
            .map(|account| account.provider_user_id)
            .collect();

        let email = user.email.to_lowercase();

        let permission = self
            .share_repository
            .get_share_permission_for_user(conversation_id, &email, &near_accounts)
            .await?;

        match permission {
            Some(permission) if Self::has_required_permission(permission, required_permission) => {
                Ok(())
            }
            _ => Err(ConversationError::AccessDenied),
        }
    }

    async fn get_public_access(
        &self,
        token: &str,
        required_permission: SharePermission,
    ) -> Result<ConversationShare, ConversationError> {
        let share = self
            .share_repository
            .get_public_share_by_token(token)
            .await?
            .ok_or(ConversationError::NotFound)?;

        if !Self::has_required_permission(share.permission, required_permission) {
            return Err(ConversationError::AccessDenied);
        }

        Ok(share)
    }

    async fn create_group(
        &self,
        owner_user_id: UserId,
        name: &str,
        members: Vec<ShareRecipient>,
    ) -> Result<ShareGroup, ConversationError> {
        let members = members
            .into_iter()
            .map(Self::normalize_recipient)
            .collect::<Vec<_>>();

        self.share_repository
            .create_group(owner_user_id, name, &members)
            .await
    }

    async fn list_groups(
        &self,
        owner_user_id: UserId,
    ) -> Result<Vec<ShareGroup>, ConversationError> {
        self.share_repository.list_groups(owner_user_id).await
    }

    async fn update_group(
        &self,
        owner_user_id: UserId,
        group_id: uuid::Uuid,
        name: Option<String>,
        members: Option<Vec<ShareRecipient>>,
    ) -> Result<ShareGroup, ConversationError> {
        let members = members.map(|members| {
            members
                .into_iter()
                .map(Self::normalize_recipient)
                .collect::<Vec<_>>()
        });

        self.share_repository
            .update_group(owner_user_id, group_id, name.as_deref(), members.as_deref())
            .await
    }

    async fn delete_group(
        &self,
        owner_user_id: UserId,
        group_id: uuid::Uuid,
    ) -> Result<(), ConversationError> {
        self.share_repository
            .delete_group(owner_user_id, group_id)
            .await
    }

    async fn create_share(
        &self,
        owner_user_id: UserId,
        conversation_id: &str,
        permission: SharePermission,
        target: ShareTarget,
    ) -> Result<Vec<ConversationShare>, ConversationError> {
        self.conversation_repository
            .access_conversation(conversation_id, owner_user_id)
            .await?;

        let mut shares = Vec::new();

        match target {
            ShareTarget::Direct(recipients) => {
                for recipient in recipients.into_iter().map(Self::normalize_recipient) {
                    let share = self
                        .share_repository
                        .create_share(NewConversationShare {
                            conversation_id: conversation_id.to_string(),
                            owner_user_id,
                            share_type: ShareType::Direct,
                            permission,
                            recipient: Some(recipient),
                            group_id: None,
                            org_email_pattern: None,
                            public_token: None,
                        })
                        .await?;
                    shares.push(share);
                }
            }
            ShareTarget::Group(group_id) => {
                let group = self
                    .share_repository
                    .get_group(owner_user_id, group_id)
                    .await?;

                if group.is_none() {
                    return Err(ConversationError::AccessDenied);
                }

                let share = self
                    .share_repository
                    .create_share(NewConversationShare {
                        conversation_id: conversation_id.to_string(),
                        owner_user_id,
                        share_type: ShareType::Group,
                        permission,
                        recipient: None,
                        group_id: Some(group_id),
                        org_email_pattern: None,
                        public_token: None,
                    })
                    .await?;

                shares.push(share);
            }
            ShareTarget::Organization(pattern) => {
                let normalized = Self::normalize_org_pattern(pattern);
                let share = self
                    .share_repository
                    .create_share(NewConversationShare {
                        conversation_id: conversation_id.to_string(),
                        owner_user_id,
                        share_type: ShareType::Organization,
                        permission,
                        recipient: None,
                        group_id: None,
                        org_email_pattern: Some(normalized),
                        public_token: None,
                    })
                    .await?;

                shares.push(share);
            }
            ShareTarget::Public => {
                let token = Self::generate_public_token();
                let share = self
                    .share_repository
                    .create_share(NewConversationShare {
                        conversation_id: conversation_id.to_string(),
                        owner_user_id,
                        share_type: ShareType::Public,
                        permission,
                        recipient: None,
                        group_id: None,
                        org_email_pattern: None,
                        public_token: Some(token),
                    })
                    .await?;

                shares.push(share);
            }
        }

        Ok(shares)
    }

    async fn list_shares(
        &self,
        owner_user_id: UserId,
        conversation_id: &str,
    ) -> Result<Vec<ConversationShare>, ConversationError> {
        self.share_repository
            .list_shares(owner_user_id, conversation_id)
            .await
    }

    async fn delete_share(
        &self,
        owner_user_id: UserId,
        share_id: uuid::Uuid,
    ) -> Result<(), ConversationError> {
        self.share_repository
            .delete_share(owner_user_id, share_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::ports::{
        ConversationShareRepository, ShareGroup, SharePermission, ShareRecipient,
        ShareRecipientKind, ShareTarget, ShareType,
    };
    use crate::user::ports::{
        LinkedOAuthAccount, OAuthProvider, User, UserRepository, UserService,
    };
    use async_trait::async_trait;
    use chrono::Utc;
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;
    use uuid::Uuid;

    #[derive(Default)]
    struct InMemoryConversationRepo {
        owners: Mutex<HashMap<String, UserId>>,
    }

    impl InMemoryConversationRepo {
        fn insert_owner(&self, conversation_id: &str, user_id: UserId) {
            self.owners
                .lock()
                .expect("lock owners")
                .insert(conversation_id.to_string(), user_id);
        }
    }

    #[async_trait]
    impl ConversationRepository for InMemoryConversationRepo {
        async fn upsert_conversation(
            &self,
            _conversation_id: &str,
            _user_id: UserId,
        ) -> Result<(), ConversationError> {
            Ok(())
        }

        async fn list_conversations(
            &self,
            _user_id: UserId,
        ) -> Result<Vec<String>, ConversationError> {
            Ok(Vec::new())
        }

        async fn access_conversation(
            &self,
            conversation_id: &str,
            user_id: UserId,
        ) -> Result<(), ConversationError> {
            let owners = self.owners.lock().expect("lock owners");
            match owners.get(conversation_id) {
                Some(owner) if *owner == user_id => Ok(()),
                Some(_) => Err(ConversationError::AccessDenied),
                None => Err(ConversationError::NotFound),
            }
        }

        async fn delete_conversation(
            &self,
            _conversation_id: &str,
            _user_id: UserId,
        ) -> Result<(), ConversationError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct InMemoryShareRepo {
        shares: Mutex<Vec<ConversationShare>>,
        groups: Mutex<HashMap<Uuid, ShareGroup>>,
    }

    impl InMemoryShareRepo {
        fn next_share(&self, share: NewConversationShare) -> ConversationShare {
            let now = Utc::now();
            ConversationShare {
                id: Uuid::new_v4(),
                conversation_id: share.conversation_id,
                owner_user_id: share.owner_user_id,
                share_type: share.share_type,
                permission: share.permission,
                recipient: share.recipient,
                group_id: share.group_id,
                org_email_pattern: share.org_email_pattern,
                public_token: share.public_token,
                created_at: now,
                updated_at: now,
            }
        }
    }

    #[async_trait]
    impl ConversationShareRepository for InMemoryShareRepo {
        async fn create_group(
            &self,
            owner_user_id: UserId,
            name: &str,
            members: &[ShareRecipient],
        ) -> Result<ShareGroup, ConversationError> {
            let now = Utc::now();
            let group = ShareGroup {
                id: Uuid::new_v4(),
                owner_user_id,
                name: name.to_string(),
                members: members.to_vec(),
                created_at: now,
                updated_at: now,
            };

            self.groups
                .lock()
                .expect("lock groups")
                .insert(group.id, group.clone());

            Ok(group)
        }

        async fn list_groups(
            &self,
            owner_user_id: UserId,
        ) -> Result<Vec<ShareGroup>, ConversationError> {
            let groups = self
                .groups
                .lock()
                .expect("lock groups")
                .values()
                .filter(|group| group.owner_user_id == owner_user_id)
                .cloned()
                .collect();
            Ok(groups)
        }

        async fn get_group(
            &self,
            owner_user_id: UserId,
            group_id: Uuid,
        ) -> Result<Option<ShareGroup>, ConversationError> {
            let groups = self.groups.lock().expect("lock groups");
            Ok(groups
                .get(&group_id)
                .filter(|group| group.owner_user_id == owner_user_id)
                .cloned())
        }

        async fn update_group(
            &self,
            owner_user_id: UserId,
            group_id: Uuid,
            name: Option<&str>,
            members: Option<&[ShareRecipient]>,
        ) -> Result<ShareGroup, ConversationError> {
            let mut groups = self.groups.lock().expect("lock groups");
            let group = groups
                .get_mut(&group_id)
                .filter(|group| group.owner_user_id == owner_user_id)
                .ok_or(ConversationError::NotFound)?;

            if let Some(name) = name {
                group.name = name.to_string();
            }
            if let Some(members) = members {
                group.members = members.to_vec();
            }
            group.updated_at = Utc::now();
            Ok(group.clone())
        }

        async fn delete_group(
            &self,
            owner_user_id: UserId,
            group_id: Uuid,
        ) -> Result<(), ConversationError> {
            let mut groups = self.groups.lock().expect("lock groups");
            let existing = groups
                .get(&group_id)
                .filter(|group| group.owner_user_id == owner_user_id)
                .cloned();
            match existing {
                Some(_) => {
                    groups.remove(&group_id);
                    Ok(())
                }
                None => Err(ConversationError::NotFound),
            }
        }

        async fn create_share(
            &self,
            share: NewConversationShare,
        ) -> Result<ConversationShare, ConversationError> {
            let share = self.next_share(share);
            self.shares.lock().expect("lock shares").push(share.clone());
            Ok(share)
        }

        async fn list_shares(
            &self,
            owner_user_id: UserId,
            conversation_id: &str,
        ) -> Result<Vec<ConversationShare>, ConversationError> {
            let shares = self
                .shares
                .lock()
                .expect("lock shares")
                .iter()
                .filter(|share| {
                    share.owner_user_id == owner_user_id && share.conversation_id == conversation_id
                })
                .cloned()
                .collect();
            Ok(shares)
        }

        async fn delete_share(
            &self,
            owner_user_id: UserId,
            share_id: Uuid,
        ) -> Result<(), ConversationError> {
            let mut shares = self.shares.lock().expect("lock shares");
            let original_len = shares.len();
            shares.retain(|share| !(share.owner_user_id == owner_user_id && share.id == share_id));
            if shares.len() == original_len {
                return Err(ConversationError::NotFound);
            }
            Ok(())
        }

        async fn get_share_permission_for_user(
            &self,
            conversation_id: &str,
            email: &str,
            near_accounts: &[String],
        ) -> Result<Option<SharePermission>, ConversationError> {
            let shares = self.shares.lock().expect("lock shares");
            let mut permissions = Vec::new();

            for share in shares
                .iter()
                .filter(|share| share.conversation_id == conversation_id)
            {
                match share.share_type {
                    ShareType::Direct => {
                        if let Some(recipient) = &share.recipient {
                            match recipient.kind {
                                ShareRecipientKind::Email if recipient.value == email => {
                                    permissions.push(share.permission);
                                }
                                ShareRecipientKind::NearAccount
                                    if near_accounts.contains(&recipient.value) =>
                                {
                                    permissions.push(share.permission);
                                }
                                _ => {}
                            }
                        }
                    }
                    ShareType::Group => {
                        let groups = self.groups.lock().expect("lock groups");
                        if let Some(group_id) = share.group_id {
                            if let Some(group) = groups.get(&group_id) {
                                let members = group
                                    .members
                                    .iter()
                                    .map(|member| (member.kind, member.value.clone()))
                                    .collect::<HashSet<_>>();
                                if members.contains(&(ShareRecipientKind::Email, email.to_string()))
                                    || near_accounts.iter().any(|account| {
                                        members.contains(&(
                                            ShareRecipientKind::NearAccount,
                                            account.clone(),
                                        ))
                                    })
                                {
                                    permissions.push(share.permission);
                                }
                            }
                        }
                    }
                    ShareType::Organization => {
                        if let Some(pattern) = &share.org_email_pattern {
                            if email.ends_with(pattern.trim_start_matches("%@")) {
                                permissions.push(share.permission);
                            }
                        }
                    }
                    ShareType::Public => {}
                }
            }

            if permissions
                .iter()
                .any(|permission| *permission == SharePermission::Write)
            {
                return Ok(Some(SharePermission::Write));
            }

            if permissions.is_empty() {
                Ok(None)
            } else {
                Ok(Some(SharePermission::Read))
            }
        }

        async fn get_public_share_by_token(
            &self,
            token: &str,
        ) -> Result<Option<ConversationShare>, ConversationError> {
            let shares = self.shares.lock().expect("lock shares");
            Ok(shares
                .iter()
                .find(|share| {
                    share.share_type == ShareType::Public
                        && share.public_token.as_deref() == Some(token)
                })
                .cloned())
        }
    }

    #[derive(Default)]
    struct InMemoryUserRepo {
        users: Mutex<HashMap<UserId, User>>,
        linked_accounts: Mutex<HashMap<UserId, Vec<LinkedOAuthAccount>>>,
    }

    impl InMemoryUserRepo {
        fn insert_user(&self, user: User) {
            self.users.lock().expect("lock users").insert(user.id, user);
        }

        fn insert_linked_account(&self, user_id: UserId, account: LinkedOAuthAccount) {
            self.linked_accounts
                .lock()
                .expect("lock linked accounts")
                .entry(user_id)
                .or_default()
                .push(account);
        }
    }

    #[async_trait]
    impl UserRepository for InMemoryUserRepo {
        async fn get_user(&self, user_id: UserId) -> anyhow::Result<Option<User>> {
            Ok(self
                .users
                .lock()
                .expect("lock users")
                .get(&user_id)
                .cloned())
        }

        async fn get_user_by_email(&self, _email: &str) -> anyhow::Result<Option<User>> {
            Ok(None)
        }

        async fn create_user(
            &self,
            _email: String,
            _name: Option<String>,
            _avatar_url: Option<String>,
        ) -> anyhow::Result<User> {
            unimplemented!("create_user not needed for tests");
        }

        async fn update_user(
            &self,
            _user_id: UserId,
            _name: Option<String>,
            _avatar_url: Option<String>,
        ) -> anyhow::Result<User> {
            unimplemented!("update_user not needed for tests");
        }

        async fn delete_user(&self, _user_id: UserId) -> anyhow::Result<()> {
            Ok(())
        }

        async fn get_linked_accounts(
            &self,
            user_id: UserId,
        ) -> anyhow::Result<Vec<LinkedOAuthAccount>> {
            Ok(self
                .linked_accounts
                .lock()
                .expect("lock linked accounts")
                .get(&user_id)
                .cloned()
                .unwrap_or_default())
        }

        async fn link_oauth_account(
            &self,
            _user_id: UserId,
            _provider: OAuthProvider,
            _provider_user_id: String,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn find_user_by_oauth(
            &self,
            _provider: OAuthProvider,
            _provider_user_id: &str,
        ) -> anyhow::Result<Option<UserId>> {
            Ok(None)
        }

        async fn list_users(&self, _limit: i64, _offset: i64) -> anyhow::Result<(Vec<User>, u64)> {
            Ok((Vec::new(), 0))
        }

        async fn has_active_ban(&self, _user_id: UserId) -> anyhow::Result<bool> {
            Ok(false)
        }

        async fn create_user_ban(
            &self,
            _user_id: UserId,
            _ban_type: crate::user::ports::BanType,
            _reason: Option<String>,
            _expires_at: Option<chrono::DateTime<chrono::Utc>>,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl UserService for InMemoryUserRepo {
        async fn get_user_profile(
            &self,
            _user_id: UserId,
        ) -> anyhow::Result<crate::user::ports::UserProfile> {
            unimplemented!("UserService not needed for tests");
        }

        async fn update_profile(
            &self,
            _user_id: UserId,
            _name: Option<String>,
            _avatar_url: Option<String>,
        ) -> anyhow::Result<User> {
            unimplemented!("UserService not needed for tests");
        }

        async fn delete_account(&self, _user_id: UserId) -> anyhow::Result<()> {
            Ok(())
        }

        async fn list_users(&self, _limit: i64, _offset: i64) -> anyhow::Result<(Vec<User>, u64)> {
            Ok((Vec::new(), 0))
        }

        async fn has_active_ban(&self, _user_id: UserId) -> anyhow::Result<bool> {
            Ok(false)
        }

        async fn ban_user_for_duration(
            &self,
            _user_id: UserId,
            _ban_type: crate::user::ports::BanType,
            _reason: Option<String>,
            _duration: chrono::Duration,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn build_user(email: &str) -> User {
        User {
            id: UserId::new(),
            email: email.to_string(),
            name: None,
            avatar_url: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn ensure_access_allows_owner() {
        let conversation_repo = Arc::new(InMemoryConversationRepo::default());
        let share_repo = Arc::new(InMemoryShareRepo::default());
        let user_repo = Arc::new(InMemoryUserRepo::default());

        let user = build_user("owner@example.com");
        conversation_repo.insert_owner("conv_123", user.id);
        user_repo.insert_user(user.clone());

        let service = ConversationShareServiceImpl::new(conversation_repo, share_repo, user_repo);

        let result = service
            .ensure_access("conv_123", user.id, SharePermission::Read)
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn ensure_access_uses_direct_share_write() {
        let conversation_repo = Arc::new(InMemoryConversationRepo::default());
        let share_repo = Arc::new(InMemoryShareRepo::default());
        let user_repo = Arc::new(InMemoryUserRepo::default());

        let user = build_user("sharee@example.com");
        user_repo.insert_user(user.clone());

        let share = share_repo
            .create_share(NewConversationShare {
                conversation_id: "conv_456".to_string(),
                owner_user_id: UserId::new(),
                share_type: ShareType::Direct,
                permission: SharePermission::Write,
                recipient: Some(ShareRecipient {
                    kind: ShareRecipientKind::Email,
                    value: "sharee@example.com".to_string(),
                }),
                group_id: None,
                org_email_pattern: None,
                public_token: None,
            })
            .await
            .expect("share create");

        assert_eq!(share.permission, SharePermission::Write);

        let service = ConversationShareServiceImpl::new(conversation_repo, share_repo, user_repo);

        let result = service
            .ensure_access("conv_456", user.id, SharePermission::Write)
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn create_public_share_generates_token() {
        let conversation_repo = Arc::new(InMemoryConversationRepo::default());
        let share_repo = Arc::new(InMemoryShareRepo::default());
        let user_repo = Arc::new(InMemoryUserRepo::default());

        let owner = build_user("owner@example.com");
        conversation_repo.insert_owner("conv_public", owner.id);
        user_repo.insert_user(owner.clone());

        let service = ConversationShareServiceImpl::new(conversation_repo, share_repo, user_repo);

        let shares = service
            .create_share(
                owner.id,
                "conv_public",
                SharePermission::Read,
                ShareTarget::Public,
            )
            .await
            .expect("create public share");

        let share = shares.first().expect("share");
        let token = share.public_token.as_deref().expect("token");
        assert_eq!(token.len(), 64);
    }

    #[tokio::test]
    async fn ensure_access_matches_group_members() {
        let conversation_repo = Arc::new(InMemoryConversationRepo::default());
        let share_repo = Arc::new(InMemoryShareRepo::default());
        let user_repo = Arc::new(InMemoryUserRepo::default());

        let owner = build_user("owner@example.com");
        let sharee = build_user("team@example.com");
        user_repo.insert_user(owner.clone());
        user_repo.insert_user(sharee.clone());

        conversation_repo.insert_owner("conv_group", owner.id);

        let group = share_repo
            .create_group(
                owner.id,
                "team",
                &[ShareRecipient {
                    kind: ShareRecipientKind::Email,
                    value: "team@example.com".to_string(),
                }],
            )
            .await
            .expect("create group");

        share_repo
            .create_share(NewConversationShare {
                conversation_id: "conv_group".to_string(),
                owner_user_id: owner.id,
                share_type: ShareType::Group,
                permission: SharePermission::Read,
                recipient: None,
                group_id: Some(group.id),
                org_email_pattern: None,
                public_token: None,
            })
            .await
            .expect("create share");

        let service = ConversationShareServiceImpl::new(conversation_repo, share_repo, user_repo);

        let result = service
            .ensure_access("conv_group", sharee.id, SharePermission::Read)
            .await;

        assert!(result.is_ok());
    }
}
