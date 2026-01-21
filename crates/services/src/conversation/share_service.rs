use async_trait::async_trait;
use std::sync::Arc;

use super::ports::{
    ConversationError, ConversationRepository, ConversationShare, ConversationShareRepository,
    ConversationShareService, NewConversationShare, ShareGroup, SharePermission, ShareRecipient,
    ShareRecipientKind, ShareTarget, ShareType,
};
use crate::user::ports::{OAuthProvider, UserRepository};
use crate::UserId;

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
        // If pattern contains wildcards (% or _), keep as-is
        if trimmed.contains('%') || trimmed.contains('_') {
            trimmed
        } else if trimmed.starts_with('@') {
            // @company.com -> %@company.com
            format!("%{trimmed}")
        } else if trimmed.contains('@') {
            // user@company.com -> keep as-is (specific email match)
            trimmed
        } else {
            // company.com -> %@company.com
            format!("%@{trimmed}")
        }
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
            Err(ConversationError::NotFound) | Err(ConversationError::AccessDenied) => {}
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

    async fn get_public_access_by_conversation_id(
        &self,
        conversation_id: &str,
        required_permission: SharePermission,
    ) -> Result<ConversationShare, ConversationError> {
        let share = self
            .share_repository
            .get_public_share_by_conversation_id(conversation_id)
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

    async fn list_accessible_groups(
        &self,
        owner_user_id: UserId,
        member_identifiers: &[ShareRecipient],
    ) -> Result<Vec<ShareGroup>, ConversationError> {
        // Get groups owned by the user
        let owned_groups = self.share_repository.list_groups(owner_user_id).await?;

        // Get groups where the user is a member
        let member_groups = self
            .share_repository
            .list_groups_for_member(member_identifiers)
            .await?;

        // Combine and deduplicate (owned groups take precedence)
        let owned_ids: std::collections::HashSet<_> = owned_groups.iter().map(|g| g.id).collect();

        let mut all_groups = owned_groups;
        for group in member_groups {
            if !owned_ids.contains(&group.id) {
                all_groups.push(group);
            }
        }

        // Sort by name
        all_groups.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(all_groups)
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
        // First verify the conversation exists
        let owner = self
            .conversation_repository
            .get_conversation_owner(conversation_id)
            .await?;
        if owner.is_none() {
            return Err(ConversationError::NotFound);
        }

        // Allow owners OR users with write permission to create shares
        self.ensure_access(conversation_id, owner_user_id, SharePermission::Write)
            .await?;

        let mut shares = Vec::new();

        match target {
            ShareTarget::Direct(recipients) => {
                // Use batch creation for atomicity - all shares succeed or all fail
                let share_requests: Vec<NewConversationShare> = recipients
                    .into_iter()
                    .map(Self::normalize_recipient)
                    .map(|recipient| NewConversationShare {
                        conversation_id: conversation_id.to_string(),
                        owner_user_id,
                        share_type: ShareType::Direct,
                        permission,
                        recipient: Some(recipient),
                        group_id: None,
                        org_email_pattern: None,
                    })
                    .collect();

                shares = self
                    .share_repository
                    .create_shares_batch(share_requests)
                    .await?;
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
                    })
                    .await?;

                shares.push(share);
            }
            ShareTarget::Public => {
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
        conversation_id: &str,
        share_id: uuid::Uuid,
    ) -> Result<(), ConversationError> {
        self.share_repository
            .delete_share(owner_user_id, conversation_id, share_id)
            .await
    }

    async fn list_shared_with_me(
        &self,
        user_id: UserId,
    ) -> Result<Vec<(String, SharePermission)>, ConversationError> {
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

        self.share_repository
            .list_conversations_shared_with_user(user_id, &email, &near_accounts)
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

        async fn get_conversation_owner(
            &self,
            conversation_id: &str,
        ) -> Result<Option<UserId>, ConversationError> {
            let owners = self.owners.lock().expect("lock owners");
            Ok(owners.get(conversation_id).copied())
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
                created_at: now,
                updated_at: now,
            }
        }

        fn is_duplicate_share(
            existing: &ConversationShare,
            new_share: &NewConversationShare,
        ) -> bool {
            if existing.conversation_id != new_share.conversation_id {
                return false;
            }

            match new_share.share_type {
                ShareType::Direct => {
                    existing.share_type == ShareType::Direct
                        && existing.recipient == new_share.recipient
                }
                ShareType::Group => {
                    existing.share_type == ShareType::Group
                        && existing.group_id == new_share.group_id
                }
                ShareType::Organization => {
                    existing.share_type == ShareType::Organization
                        && existing.org_email_pattern == new_share.org_email_pattern
                }
                ShareType::Public => existing.share_type == ShareType::Public,
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

        async fn list_groups_for_member(
            &self,
            member_identifiers: &[ShareRecipient],
        ) -> Result<Vec<ShareGroup>, ConversationError> {
            let groups = self
                .groups
                .lock()
                .expect("lock groups")
                .values()
                .filter(|group| {
                    group.members.iter().any(|member| {
                        member_identifiers.iter().any(|identifier| {
                            member.kind == identifier.kind
                                && member.value.to_lowercase() == identifier.value.to_lowercase()
                        })
                    })
                })
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
            let shares = self.shares.lock().expect("lock shares");

            // Check if a duplicate share already exists
            let exists = shares
                .iter()
                .any(|existing| Self::is_duplicate_share(existing, &share));

            if exists {
                return Err(ConversationError::ShareAlreadyExists);
            }

            drop(shares);

            let new_share = self.next_share(share);
            self.shares
                .lock()
                .expect("lock shares")
                .push(new_share.clone());
            Ok(new_share)
        }

        async fn create_shares_batch(
            &self,
            shares: Vec<NewConversationShare>,
        ) -> Result<Vec<ConversationShare>, ConversationError> {
            let mut shares_vec = self.shares.lock().expect("lock shares");
            let mut created_shares = Vec::with_capacity(shares.len());

            for share in shares {
                // Check if a duplicate share already exists
                let exists = shares_vec
                    .iter()
                    .any(|existing| Self::is_duplicate_share(existing, &share));

                if exists {
                    return Err(ConversationError::ShareAlreadyExists);
                }

                let new_share = self.next_share(share);
                shares_vec.push(new_share.clone());
                created_shares.push(new_share);
            }

            Ok(created_shares)
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
            conversation_id: &str,
            share_id: Uuid,
        ) -> Result<(), ConversationError> {
            let mut shares = self.shares.lock().expect("lock shares");
            let original_len = shares.len();
            shares.retain(|share| {
                !(share.owner_user_id == owner_user_id
                    && share.conversation_id == conversation_id
                    && share.id == share_id)
            });
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

            if permissions.contains(&SharePermission::Write) {
                return Ok(Some(SharePermission::Write));
            }

            if permissions.is_empty() {
                Ok(None)
            } else {
                Ok(Some(SharePermission::Read))
            }
        }

        async fn get_public_share_by_conversation_id(
            &self,
            conversation_id: &str,
        ) -> Result<Option<ConversationShare>, ConversationError> {
            let shares = self.shares.lock().expect("lock shares");
            Ok(shares
                .iter()
                .find(|share| {
                    share.share_type == ShareType::Public
                        && share.conversation_id == conversation_id
                })
                .cloned())
        }

        async fn list_conversations_shared_with_user(
            &self,
            user_id: UserId,
            email: &str,
            near_accounts: &[String],
        ) -> Result<Vec<(String, SharePermission)>, ConversationError> {
            let shares = self.shares.lock().expect("lock shares");
            let groups = self.groups.lock().expect("lock groups");
            let mut result: std::collections::HashMap<String, SharePermission> =
                std::collections::HashMap::new();

            for share in shares.iter() {
                // Exclude own conversations
                if share.owner_user_id == user_id {
                    continue;
                }

                let matches = match share.share_type {
                    ShareType::Direct => {
                        if let Some(recipient) = &share.recipient {
                            match recipient.kind {
                                ShareRecipientKind::Email => recipient.value == email,
                                ShareRecipientKind::NearAccount => {
                                    near_accounts.contains(&recipient.value)
                                }
                            }
                        } else {
                            false
                        }
                    }
                    ShareType::Group => {
                        if let Some(group_id) = share.group_id {
                            if let Some(group) = groups.get(&group_id) {
                                group.members.iter().any(|member| match member.kind {
                                    ShareRecipientKind::Email => member.value == email,
                                    ShareRecipientKind::NearAccount => {
                                        near_accounts.contains(&member.value)
                                    }
                                })
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    }
                    ShareType::Organization => {
                        if let Some(pattern) = &share.org_email_pattern {
                            email.ends_with(pattern.trim_start_matches("%@"))
                        } else {
                            false
                        }
                    }
                    ShareType::Public => false,
                };

                if matches {
                    let entry = result
                        .entry(share.conversation_id.clone())
                        .or_insert(SharePermission::Read);
                    if share.permission == SharePermission::Write {
                        *entry = SharePermission::Write;
                    }
                }
            }

            Ok(result.into_iter().collect())
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

    fn setup_service_with_owner(
        conversation_id: &str,
        owner_email: &str,
    ) -> (
        ConversationShareServiceImpl,
        Arc<InMemoryConversationRepo>,
        Arc<InMemoryShareRepo>,
        Arc<InMemoryUserRepo>,
        User,
    ) {
        let conversation_repo = Arc::new(InMemoryConversationRepo::default());
        let share_repo = Arc::new(InMemoryShareRepo::default());
        let user_repo = Arc::new(InMemoryUserRepo::default());
        let owner = build_user(owner_email);
        conversation_repo.insert_owner(conversation_id, owner.id);
        user_repo.insert_user(owner.clone());

        (
            ConversationShareServiceImpl::new(
                conversation_repo.clone(),
                share_repo.clone(),
                user_repo.clone(),
            ),
            conversation_repo,
            share_repo,
            user_repo,
            owner,
        )
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
    async fn create_public_share() {
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
        assert_eq!(share.share_type, ShareType::Public);
        assert_eq!(share.permission, SharePermission::Read);
    }

    #[tokio::test]
    async fn create_share_requires_existing_conversation() {
        let conversation_repo = Arc::new(InMemoryConversationRepo::default());
        let share_repo = Arc::new(InMemoryShareRepo::default());
        let user_repo = Arc::new(InMemoryUserRepo::default());

        let owner = build_user("owner@example.com");
        user_repo.insert_user(owner.clone());

        let service = ConversationShareServiceImpl::new(conversation_repo, share_repo, user_repo);

        let err = service
            .create_share(
                owner.id,
                "missing_conv",
                SharePermission::Read,
                ShareTarget::Public,
            )
            .await
            .expect_err("should fail when conversation missing");
        assert!(matches!(err, ConversationError::NotFound));
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
            })
            .await
            .expect("create share");

        let service = ConversationShareServiceImpl::new(conversation_repo, share_repo, user_repo);

        let result = service
            .ensure_access("conv_group", sharee.id, SharePermission::Read)
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn create_group_share_requires_owners_group() {
        let (service, _conversation_repo, share_repo, _user_repo, owner) =
            setup_service_with_owner("conv_group_owner", "owner@example.com");

        let outsider = build_user("outsider@example.com");

        let outsider_group = share_repo
            .create_group(
                outsider.id,
                "outsiders",
                &[ShareRecipient {
                    kind: ShareRecipientKind::Email,
                    value: "outsider@example.com".to_string(),
                }],
            )
            .await
            .expect("outsider group");

        let err = service
            .create_share(
                owner.id,
                "conv_group_owner",
                SharePermission::Read,
                ShareTarget::Group(outsider_group.id),
            )
            .await
            .expect_err("should reject group owned by someone else");
        assert!(matches!(err, ConversationError::AccessDenied));
    }

    #[tokio::test]
    async fn ensure_access_denies_group_non_member() {
        let (service, _conversation_repo, share_repo, user_repo, owner) =
            setup_service_with_owner("conv_group_access", "owner@example.com");

        let sharee = build_user("someone@example.com");
        user_repo.insert_user(sharee.clone());

        let group = share_repo
            .create_group(
                owner.id,
                "team",
                &[ShareRecipient {
                    kind: ShareRecipientKind::Email,
                    value: "member@example.com".to_string(),
                }],
            )
            .await
            .expect("create group");

        share_repo
            .create_share(NewConversationShare {
                conversation_id: "conv_group_access".to_string(),
                owner_user_id: owner.id,
                share_type: ShareType::Group,
                permission: SharePermission::Read,
                recipient: None,
                group_id: Some(group.id),
                org_email_pattern: None,
            })
            .await
            .expect("create share");

        let err = service
            .ensure_access("conv_group_access", sharee.id, SharePermission::Read)
            .await
            .expect_err("non member should not access");
        assert!(matches!(err, ConversationError::AccessDenied));
    }

    #[tokio::test]
    async fn ensure_access_prefers_write_when_multiple_shares() {
        let conversation_repo = Arc::new(InMemoryConversationRepo::default());
        let share_repo = Arc::new(InMemoryShareRepo::default());
        let user_repo = Arc::new(InMemoryUserRepo::default());
        let owner = build_user("owner@example.com");
        let sharee = build_user("writer@example.com");
        conversation_repo.insert_owner("conv_write", owner.id);
        user_repo.insert_user(owner.clone());
        user_repo.insert_user(sharee.clone());

        let service = ConversationShareServiceImpl::new(
            conversation_repo.clone(),
            share_repo.clone(),
            user_repo.clone(),
        );

        share_repo
            .create_share(NewConversationShare {
                conversation_id: "conv_write".to_string(),
                owner_user_id: owner.id,
                share_type: ShareType::Direct,
                permission: SharePermission::Read,
                recipient: Some(ShareRecipient {
                    kind: ShareRecipientKind::Email,
                    value: "writer@example.com".to_string(),
                }),
                group_id: None,
                org_email_pattern: None,
            })
            .await
            .expect("create read share");

        share_repo
            .create_share(NewConversationShare {
                conversation_id: "conv_write".to_string(),
                owner_user_id: owner.id,
                share_type: ShareType::Direct,
                permission: SharePermission::Write,
                recipient: Some(ShareRecipient {
                    kind: ShareRecipientKind::NearAccount,
                    value: "writer.near".to_string(),
                }),
                group_id: None,
                org_email_pattern: None,
            })
            .await
            .expect("create write share");

        user_repo.insert_linked_account(
            sharee.id,
            LinkedOAuthAccount {
                provider: OAuthProvider::Near,
                provider_user_id: "writer.near".to_string(),
                linked_at: Utc::now(),
            },
        );

        service
            .ensure_access("conv_write", sharee.id, SharePermission::Write)
            .await
            .expect("should allow write with matching share");
    }

    #[tokio::test]
    async fn ensure_access_denies_write_when_only_read_share() {
        let conversation_repo = Arc::new(InMemoryConversationRepo::default());
        let share_repo = Arc::new(InMemoryShareRepo::default());
        let user_repo = Arc::new(InMemoryUserRepo::default());

        let user = build_user("reader@example.com");
        user_repo.insert_user(user.clone());

        share_repo
            .create_share(NewConversationShare {
                conversation_id: "conv_read".to_string(),
                owner_user_id: UserId::new(),
                share_type: ShareType::Direct,
                permission: SharePermission::Read,
                recipient: Some(ShareRecipient {
                    kind: ShareRecipientKind::Email,
                    value: "reader@example.com".to_string(),
                }),
                group_id: None,
                org_email_pattern: None,
            })
            .await
            .expect("share create");

        let service = ConversationShareServiceImpl::new(conversation_repo, share_repo, user_repo);

        let result = service
            .ensure_access("conv_read", user.id, SharePermission::Write)
            .await;

        assert!(matches!(result, Err(ConversationError::AccessDenied)));
    }

    #[tokio::test]
    async fn ensure_access_respects_near_account_recipients() {
        let conversation_repo = Arc::new(InMemoryConversationRepo::default());
        let share_repo = Arc::new(InMemoryShareRepo::default());
        let user_repo = Arc::new(InMemoryUserRepo::default());

        let user = build_user("linked@example.com");
        user_repo.insert_user(user.clone());
        user_repo.insert_linked_account(
            user.id,
            LinkedOAuthAccount {
                provider: OAuthProvider::Near,
                provider_user_id: "alice.near".to_string(),
                linked_at: Utc::now(),
            },
        );

        share_repo
            .create_share(NewConversationShare {
                conversation_id: "conv_near".to_string(),
                owner_user_id: UserId::new(),
                share_type: ShareType::Direct,
                permission: SharePermission::Read,
                recipient: Some(ShareRecipient {
                    kind: ShareRecipientKind::NearAccount,
                    value: "alice.near".to_string(),
                }),
                group_id: None,
                org_email_pattern: None,
            })
            .await
            .expect("share create");

        let service = ConversationShareServiceImpl::new(conversation_repo, share_repo, user_repo);

        service
            .ensure_access("conv_near", user.id, SharePermission::Read)
            .await
            .expect("near access");
    }

    #[tokio::test]
    async fn ensure_access_respects_org_shares() {
        let conversation_repo = Arc::new(InMemoryConversationRepo::default());
        let share_repo = Arc::new(InMemoryShareRepo::default());
        let user_repo = Arc::new(InMemoryUserRepo::default());

        let user = build_user("someone@team.example.com");
        user_repo.insert_user(user.clone());

        share_repo
            .create_share(NewConversationShare {
                conversation_id: "conv_org".to_string(),
                owner_user_id: UserId::new(),
                share_type: ShareType::Organization,
                permission: SharePermission::Read,
                recipient: None,
                group_id: None,
                org_email_pattern: Some("%@example.com".to_string()),
            })
            .await
            .expect("share create");

        let service = ConversationShareServiceImpl::new(conversation_repo, share_repo, user_repo);

        service
            .ensure_access("conv_org", user.id, SharePermission::Read)
            .await
            .expect("org access");
    }

    #[tokio::test]
    async fn create_share_normalizes_recipients_and_patterns() {
        let (service, _conversation_repo, _share_repo, _user_repo, owner) =
            setup_service_with_owner("conv_norm", "owner@example.com");

        let shares = service
            .create_share(
                owner.id,
                "conv_norm",
                SharePermission::Read,
                ShareTarget::Direct(vec![
                    ShareRecipient {
                        kind: ShareRecipientKind::Email,
                        value: " MixedCase@Example.COM  ".to_string(),
                    },
                    ShareRecipient {
                        kind: ShareRecipientKind::NearAccount,
                        value: "   alice.near  ".to_string(),
                    },
                ]),
            )
            .await
            .expect("create direct shares");

        assert_eq!(shares.len(), 2);
        assert_eq!(
            shares[0].recipient.as_ref().expect("email recipient").value,
            "mixedcase@example.com"
        );
        assert_eq!(
            shares[1].recipient.as_ref().expect("near recipient").value,
            "alice.near"
        );

        service
            .create_share(
                owner.id,
                "conv_norm",
                SharePermission::Read,
                ShareTarget::Organization("example.com".to_string()),
            )
            .await
            .expect("create org share");

        let stored = service
            .list_shares(owner.id, "conv_norm")
            .await
            .expect("list shares");
        let org_share = stored
            .iter()
            .find(|share| share.share_type == ShareType::Organization)
            .expect("org share missing");
        assert_eq!(
            org_share.org_email_pattern.as_deref(),
            Some("%@example.com")
        );
    }

    #[tokio::test]
    async fn organization_patterns_preserve_existing_wildcards() {
        let (service, _conversation_repo, _share_repo, _user_repo, owner) =
            setup_service_with_owner("conv_org_norm", "owner@example.com");

        service
            .create_share(
                owner.id,
                "conv_org_norm",
                SharePermission::Read,
                ShareTarget::Organization("%@partner.example.com".to_string()),
            )
            .await
            .expect("create org share");

        let stored = service
            .list_shares(owner.id, "conv_org_norm")
            .await
            .expect("list shares");
        let org_share = stored
            .iter()
            .find(|share| share.share_type == ShareType::Organization)
            .expect("org share missing");
        assert_eq!(
            org_share.org_email_pattern.as_deref(),
            Some("%@partner.example.com")
        );
    }

    #[tokio::test]
    async fn organization_patterns_normalize_at_prefix() {
        let (service, _conversation_repo, _share_repo, _user_repo, owner) =
            setup_service_with_owner("conv_org_at", "owner@example.com");

        // @company.com should be normalized to %@company.com
        service
            .create_share(
                owner.id,
                "conv_org_at",
                SharePermission::Read,
                ShareTarget::Organization("@acme.com".to_string()),
            )
            .await
            .expect("create org share");

        let stored = service
            .list_shares(owner.id, "conv_org_at")
            .await
            .expect("list shares");
        let org_share = stored
            .iter()
            .find(|share| share.share_type == ShareType::Organization)
            .expect("org share missing");
        assert_eq!(org_share.org_email_pattern.as_deref(), Some("%@acme.com"));
    }

    #[tokio::test]
    async fn share_group_lifecycle_normalizes_members() {
        let (service, _conversation_repo, _share_repo, _user_repo, owner) =
            setup_service_with_owner("conv_groups", "owner@example.com");

        let group = service
            .create_group(
                owner.id,
                " Team ",
                vec![ShareRecipient {
                    kind: ShareRecipientKind::Email,
                    value: " TEAM@Example.Com  ".to_string(),
                }],
            )
            .await
            .expect("create group");

        assert_eq!(group.name, " Team ");
        assert_eq!(group.members.len(), 1);
        assert_eq!(group.members[0].value, "team@example.com");

        let groups = service.list_groups(owner.id).await.expect("list groups");
        assert_eq!(groups.len(), 1);

        let updated = service
            .update_group(
                owner.id,
                group.id,
                Some("Renamed Group".to_string()),
                Some(vec![ShareRecipient {
                    kind: ShareRecipientKind::NearAccount,
                    value: "  alice.near ".to_string(),
                }]),
            )
            .await
            .expect("update group");

        assert_eq!(updated.name, "Renamed Group");
        assert_eq!(updated.members[0].value, "alice.near");

        service
            .delete_group(owner.id, group.id)
            .await
            .expect("delete group");

        let remaining = service.list_groups(owner.id).await.expect("list groups");
        assert!(remaining.is_empty());
    }

    #[tokio::test]
    async fn list_accessible_groups_includes_member_groups() {
        let (service, _conversation_repo, share_repo, user_repo, owner) =
            setup_service_with_owner("conv_accessible", "owner@example.com");

        // Create a group owned by the owner with another member
        let group1 = service
            .create_group(
                owner.id,
                "Owner's Group",
                vec![ShareRecipient {
                    kind: ShareRecipientKind::Email,
                    value: "member@example.com".to_string(),
                }],
            )
            .await
            .expect("create group 1");

        // Create another user who owns a different group that includes the owner
        let other_owner = build_user("other@example.com");
        user_repo.insert_user(other_owner.clone());

        let group2 = share_repo
            .create_group(
                other_owner.id,
                "Other's Group",
                &[ShareRecipient {
                    kind: ShareRecipientKind::Email,
                    value: "owner@example.com".to_string(),
                }],
            )
            .await
            .expect("create group 2");

        // The owner should see both groups when listing accessible groups
        let member_identifiers = vec![ShareRecipient {
            kind: ShareRecipientKind::Email,
            value: "owner@example.com".to_string(),
        }];

        let accessible = service
            .list_accessible_groups(owner.id, &member_identifiers)
            .await
            .expect("list accessible groups");

        assert_eq!(accessible.len(), 2);
        let group_ids: Vec<_> = accessible.iter().map(|g| g.id).collect();
        assert!(group_ids.contains(&group1.id));
        assert!(group_ids.contains(&group2.id));

        // The other owner should only see their owned group (and not member groups of owner)
        let other_member_identifiers = vec![ShareRecipient {
            kind: ShareRecipientKind::Email,
            value: "other@example.com".to_string(),
        }];

        let other_accessible = service
            .list_accessible_groups(other_owner.id, &other_member_identifiers)
            .await
            .expect("list accessible groups for other");

        assert_eq!(other_accessible.len(), 1);
        assert_eq!(other_accessible[0].id, group2.id);
    }

    #[tokio::test]
    async fn delete_share_requires_matching_conversation() {
        let (service, _conversation_repo, _share_repo, _user_repo, owner) =
            setup_service_with_owner("conv_consistent", "owner@example.com");

        let share = service
            .create_share(
                owner.id,
                "conv_consistent",
                SharePermission::Read,
                ShareTarget::Public,
            )
            .await
            .expect("create share")
            .into_iter()
            .next()
            .expect("share");

        let err = service
            .delete_share(owner.id, "other_conversation", share.id)
            .await
            .expect_err("should fail mismatch");
        assert!(matches!(err, ConversationError::NotFound));

        let shares = service
            .list_shares(owner.id, "conv_consistent")
            .await
            .expect("list shares");
        assert_eq!(shares.len(), 1, "share should remain untouched");
    }

    #[tokio::test]
    async fn delete_share_requires_owner() {
        let (service, _conversation_repo, share_repo, user_repo, owner) =
            setup_service_with_owner("conv_protected", "owner@example.com");

        let other_user = build_user("intruder@example.com");
        user_repo.insert_user(other_user.clone());

        let share = service
            .create_share(
                owner.id,
                "conv_protected",
                SharePermission::Read,
                ShareTarget::Public,
            )
            .await
            .expect("create share")
            .into_iter()
            .next()
            .expect("share");

        let err = service
            .delete_share(other_user.id, "conv_protected", share.id)
            .await
            .expect_err("should fail for non-owner");
        assert!(matches!(err, ConversationError::NotFound));

        // Avoid warnings about unused repos
        drop((share_repo, user_repo));
    }

    #[tokio::test]
    async fn delete_share_removes_share_for_owner() {
        let (service, _conversation_repo, _share_repo, user_repo, owner) =
            setup_service_with_owner("conv_delete_success", "owner@example.com");

        let sharee = build_user("reader@example.com");
        user_repo.insert_user(sharee.clone());

        let share = service
            .create_share(
                owner.id,
                "conv_delete_success",
                SharePermission::Read,
                ShareTarget::Direct(vec![ShareRecipient {
                    kind: ShareRecipientKind::Email,
                    value: sharee.email.clone(),
                }]),
            )
            .await
            .expect("create share")
            .into_iter()
            .next()
            .expect("share");

        service
            .delete_share(owner.id, "conv_delete_success", share.id)
            .await
            .expect("owner should delete share");

        let shares = service
            .list_shares(owner.id, "conv_delete_success")
            .await
            .expect("list shares");
        assert!(shares.is_empty(), "share should be removed after deletion");
    }

    #[tokio::test]
    async fn delete_share_revokes_recipient_access() {
        let (service, _conversation_repo, _share_repo, user_repo, owner) =
            setup_service_with_owner("conv_revoke_access", "owner@example.com");

        let sharee = build_user("reader@example.com");
        user_repo.insert_user(sharee.clone());

        let share = service
            .create_share(
                owner.id,
                "conv_revoke_access",
                SharePermission::Read,
                ShareTarget::Direct(vec![ShareRecipient {
                    kind: ShareRecipientKind::Email,
                    value: sharee.email.clone(),
                }]),
            )
            .await
            .expect("create share")
            .into_iter()
            .next()
            .expect("share");

        service
            .ensure_access("conv_revoke_access", sharee.id, SharePermission::Read)
            .await
            .expect("recipient should have access");

        service
            .delete_share(owner.id, "conv_revoke_access", share.id)
            .await
            .expect("owner should delete share");

        let err = service
            .ensure_access("conv_revoke_access", sharee.id, SharePermission::Read)
            .await
            .expect_err("access should be revoked");
        assert!(matches!(err, ConversationError::AccessDenied));
    }

    #[tokio::test]
    async fn ensure_access_denies_missing_user_record() {
        let (service, _conversation_repo, _share_repo, _user_repo, owner) =
            setup_service_with_owner("conv_missing_user", "owner@example.com");

        let ghost_user = build_user("ghost@example.com");

        service
            .create_share(
                owner.id,
                "conv_missing_user",
                SharePermission::Read,
                ShareTarget::Direct(vec![ShareRecipient {
                    kind: ShareRecipientKind::Email,
                    value: ghost_user.email.clone(),
                }]),
            )
            .await
            .expect("create share");

        let err = service
            .ensure_access("conv_missing_user", ghost_user.id, SharePermission::Read)
            .await
            .expect_err("missing user should be denied");
        assert!(matches!(err, ConversationError::AccessDenied));
    }

    #[tokio::test]
    async fn public_access_by_conversation_id_allows_read_when_public() {
        let (service, _conversation_repo, _share_repo, _user_repo, owner) =
            setup_service_with_owner("conv_public_read", "owner@example.com");

        // Create a public share with read permission
        service
            .create_share(
                owner.id,
                "conv_public_read",
                SharePermission::Read,
                ShareTarget::Public,
            )
            .await
            .expect("create public share");

        // Public access by conversation ID should work for read
        let share = service
            .get_public_access_by_conversation_id("conv_public_read", SharePermission::Read)
            .await
            .expect("public read access should succeed");

        assert_eq!(share.conversation_id, "conv_public_read");
        assert_eq!(share.permission, SharePermission::Read);
    }

    #[tokio::test]
    async fn public_access_by_conversation_id_denied_when_not_public() {
        let (service, _conversation_repo, _share_repo, _user_repo, _owner) =
            setup_service_with_owner("conv_private", "owner@example.com");

        // No public share created - should be denied
        let err = service
            .get_public_access_by_conversation_id("conv_private", SharePermission::Read)
            .await
            .expect_err("should be denied for private conversation");

        assert!(matches!(err, ConversationError::NotFound));
    }

    #[tokio::test]
    async fn public_access_by_conversation_id_denied_for_nonexistent() {
        let (service, _conversation_repo, _share_repo, _user_repo, _owner) =
            setup_service_with_owner("conv_exists", "owner@example.com");

        // Non-existent conversation should return NotFound
        let err = service
            .get_public_access_by_conversation_id("conv_nonexistent", SharePermission::Read)
            .await
            .expect_err("should be denied for nonexistent conversation");

        assert!(matches!(err, ConversationError::NotFound));
    }

    #[tokio::test]
    async fn public_access_enforces_write_permission() {
        let (service, _conversation_repo, _share_repo, _user_repo, owner) =
            setup_service_with_owner("conv_public_write", "owner@example.com");

        // Create a public share with write permission
        service
            .create_share(
                owner.id,
                "conv_public_write",
                SharePermission::Write,
                ShareTarget::Public,
            )
            .await
            .expect("create public share");

        // Both read and write access should work
        service
            .get_public_access_by_conversation_id("conv_public_write", SharePermission::Read)
            .await
            .expect("public read access should succeed");

        service
            .get_public_access_by_conversation_id("conv_public_write", SharePermission::Write)
            .await
            .expect("public write access should succeed");
    }

    #[tokio::test]
    async fn public_access_denies_write_when_only_read() {
        let (service, _conversation_repo, _share_repo, _user_repo, owner) =
            setup_service_with_owner("conv_public_readonly", "owner@example.com");

        // Create a public share with read-only permission
        service
            .create_share(
                owner.id,
                "conv_public_readonly",
                SharePermission::Read,
                ShareTarget::Public,
            )
            .await
            .expect("create public share");

        // Read should work
        service
            .get_public_access_by_conversation_id("conv_public_readonly", SharePermission::Read)
            .await
            .expect("public read access should succeed");

        // Write should be denied
        let err = service
            .get_public_access_by_conversation_id("conv_public_readonly", SharePermission::Write)
            .await
            .expect_err("write access should be denied");

        assert!(matches!(err, ConversationError::AccessDenied));
    }

    #[tokio::test]
    async fn duplicate_public_share_returns_error() {
        let (service, _conversation_repo, _share_repo, _user_repo, owner) =
            setup_service_with_owner("conv_dup_public", "owner@example.com");

        // Create initial public share
        service
            .create_share(
                owner.id,
                "conv_dup_public",
                SharePermission::Read,
                ShareTarget::Public,
            )
            .await
            .expect("create public share");

        // Try to create duplicate public share - should fail
        let err = service
            .create_share(
                owner.id,
                "conv_dup_public",
                SharePermission::Write,
                ShareTarget::Public,
            )
            .await
            .expect_err("duplicate public share should fail");

        assert!(matches!(err, ConversationError::ShareAlreadyExists));
    }

    #[tokio::test]
    async fn duplicate_direct_share_returns_error() {
        let (service, _conversation_repo, _share_repo, _user_repo, owner) =
            setup_service_with_owner("conv_dup_direct", "owner@example.com");

        let recipient = vec![ShareRecipient {
            kind: ShareRecipientKind::Email,
            value: "user@example.com".to_string(),
        }];

        // Create initial direct share
        service
            .create_share(
                owner.id,
                "conv_dup_direct",
                SharePermission::Read,
                ShareTarget::Direct(recipient.clone()),
            )
            .await
            .expect("create direct share");

        // Try to create duplicate direct share - should fail
        let err = service
            .create_share(
                owner.id,
                "conv_dup_direct",
                SharePermission::Write,
                ShareTarget::Direct(recipient),
            )
            .await
            .expect_err("duplicate direct share should fail");

        assert!(matches!(err, ConversationError::ShareAlreadyExists));
    }

    #[tokio::test]
    async fn duplicate_group_share_returns_error() {
        let (service, _conversation_repo, _share_repo, _user_repo, owner) =
            setup_service_with_owner("conv_dup_group", "owner@example.com");

        let group = service
            .create_group(
                owner.id,
                "Test Group",
                vec![ShareRecipient {
                    kind: ShareRecipientKind::Email,
                    value: "member@example.com".to_string(),
                }],
            )
            .await
            .expect("create group");

        // Create initial group share
        service
            .create_share(
                owner.id,
                "conv_dup_group",
                SharePermission::Read,
                ShareTarget::Group(group.id),
            )
            .await
            .expect("create group share");

        // Try to create duplicate group share - should fail
        let err = service
            .create_share(
                owner.id,
                "conv_dup_group",
                SharePermission::Write,
                ShareTarget::Group(group.id),
            )
            .await
            .expect_err("duplicate group share should fail");

        assert!(matches!(err, ConversationError::ShareAlreadyExists));
    }

    #[tokio::test]
    async fn duplicate_organization_share_returns_error() {
        let (service, _conversation_repo, _share_repo, _user_repo, owner) =
            setup_service_with_owner("conv_dup_org", "owner@example.com");

        // Create initial organization share
        service
            .create_share(
                owner.id,
                "conv_dup_org",
                SharePermission::Read,
                ShareTarget::Organization("@example.com".to_string()),
            )
            .await
            .expect("create org share");

        // Try to create duplicate organization share - should fail
        let err = service
            .create_share(
                owner.id,
                "conv_dup_org",
                SharePermission::Write,
                ShareTarget::Organization("@example.com".to_string()),
            )
            .await
            .expect_err("duplicate org share should fail");

        assert!(matches!(err, ConversationError::ShareAlreadyExists));
    }
}
