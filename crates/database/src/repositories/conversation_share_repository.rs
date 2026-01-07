use crate::pool::DbPool;
use async_trait::async_trait;
use services::conversation::ports::{
    ConversationError, ConversationShare, ConversationShareRepository, NewConversationShare,
    ShareGroup, SharePermission, ShareRecipient, ShareRecipientKind, ShareType,
};
use services::UserId;
use std::collections::HashMap;
use uuid::Uuid;

pub struct PostgresConversationShareRepository {
    pool: DbPool,
}

impl PostgresConversationShareRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    fn map_permission(value: &str) -> Result<SharePermission, ConversationError> {
        match value {
            "read" => Ok(SharePermission::Read),
            "write" => Ok(SharePermission::Write),
            _ => Err(ConversationError::DatabaseError(format!(
                "Unknown share permission: {value}"
            ))),
        }
    }

    fn map_share_type(value: &str) -> Result<ShareType, ConversationError> {
        match value {
            "direct" => Ok(ShareType::Direct),
            "group" => Ok(ShareType::Group),
            "organization" => Ok(ShareType::Organization),
            "public" => Ok(ShareType::Public),
            _ => Err(ConversationError::DatabaseError(format!(
                "Unknown share type: {value}"
            ))),
        }
    }

    fn map_recipient_kind(value: &str) -> Result<ShareRecipientKind, ConversationError> {
        match value {
            "email" => Ok(ShareRecipientKind::Email),
            "near" => Ok(ShareRecipientKind::NearAccount),
            _ => Err(ConversationError::DatabaseError(format!(
                "Unknown share recipient kind: {value}"
            ))),
        }
    }

    fn map_share_row(row: &tokio_postgres::Row) -> Result<ConversationShare, ConversationError> {
        let recipient_kind: Option<String> = row.get("recipient_type");
        let recipient_value: Option<String> = row.get("recipient_value");
        let recipient = match (recipient_kind, recipient_value) {
            (Some(kind), Some(value)) => Some(ShareRecipient {
                kind: Self::map_recipient_kind(&kind)?,
                value,
            }),
            _ => None,
        };

        Ok(ConversationShare {
            id: row.get("id"),
            conversation_id: row.get("conversation_id"),
            owner_user_id: row.get("owner_user_id"),
            share_type: Self::map_share_type(row.get("share_type"))?,
            permission: Self::map_permission(row.get("permission"))?,
            recipient,
            group_id: row.get("group_id"),
            org_email_pattern: row.get("org_email_pattern"),
            public_token: row.get("public_token"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    async fn load_group_members(
        &self,
        group_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Vec<ShareRecipient>>, ConversationError> {
        if group_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let client = self
            .pool
            .get()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let rows = client
            .query(
                "SELECT group_id, member_type, member_value
                 FROM conversation_share_group_members
                 WHERE group_id = ANY($1)",
                &[&group_ids],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let mut members: HashMap<Uuid, Vec<ShareRecipient>> = HashMap::new();

        for row in rows {
            let group_id: Uuid = row.get("group_id");
            let kind = Self::map_recipient_kind(row.get("member_type"))?;
            let value: String = row.get("member_value");
            members
                .entry(group_id)
                .or_default()
                .push(ShareRecipient { kind, value });
        }

        Ok(members)
    }

    fn to_share_group(row: &tokio_postgres::Row, members: Vec<ShareRecipient>) -> ShareGroup {
        ShareGroup {
            id: row.get("id"),
            owner_user_id: row.get("owner_user_id"),
            name: row.get("name"),
            members,
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }
    }
}

#[async_trait]
impl ConversationShareRepository for PostgresConversationShareRepository {
    async fn create_group(
        &self,
        owner_user_id: UserId,
        name: &str,
        members: &[ShareRecipient],
    ) -> Result<ShareGroup, ConversationError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let transaction = client
            .transaction()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let row = transaction
            .query_one(
                "INSERT INTO conversation_share_groups (owner_user_id, name)
                 VALUES ($1, $2)
                 RETURNING id, owner_user_id, name, created_at, updated_at",
                &[&owner_user_id.0, &name],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let group_id: Uuid = row.get("id");

        for member in members {
            transaction
                .execute(
                    "INSERT INTO conversation_share_group_members (group_id, member_type, member_value)
                     VALUES ($1, $2, $3)
                     ON CONFLICT (group_id, member_type, member_value) DO NOTHING",
                    &[&group_id, &member.kind.as_str(), &member.value],
                )
                .await
                .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;
        }

        transaction
            .commit()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        Ok(Self::to_share_group(&row, members.to_vec()))
    }

    async fn list_groups(
        &self,
        owner_user_id: UserId,
    ) -> Result<Vec<ShareGroup>, ConversationError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let rows = client
            .query(
                "SELECT id, owner_user_id, name, created_at, updated_at
                 FROM conversation_share_groups
                 WHERE owner_user_id = $1
                 ORDER BY name",
                &[&owner_user_id.0],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let group_ids: Vec<Uuid> = rows.iter().map(|row| row.get("id")).collect();
        let members = self.load_group_members(&group_ids).await?;

        let groups = rows
            .iter()
            .map(|row| {
                let id: Uuid = row.get("id");
                Self::to_share_group(row, members.get(&id).cloned().unwrap_or_default())
            })
            .collect();

        Ok(groups)
    }

    async fn get_group(
        &self,
        owner_user_id: UserId,
        group_id: Uuid,
    ) -> Result<Option<ShareGroup>, ConversationError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let row = client
            .query_opt(
                "SELECT id, owner_user_id, name, created_at, updated_at
                 FROM conversation_share_groups
                 WHERE owner_user_id = $1 AND id = $2",
                &[&owner_user_id.0, &group_id],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let Some(row) = row else {
            return Ok(None);
        };

        let members = self.load_group_members(&[group_id]).await?;
        let group = Self::to_share_group(&row, members.get(&group_id).cloned().unwrap_or_default());
        Ok(Some(group))
    }

    async fn update_group(
        &self,
        owner_user_id: UserId,
        group_id: Uuid,
        name: Option<&str>,
        members: Option<&[ShareRecipient]>,
    ) -> Result<ShareGroup, ConversationError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let transaction = client
            .transaction()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let row = transaction
            .query_opt(
                "UPDATE conversation_share_groups
                 SET name = COALESCE($1, name), updated_at = NOW()
                 WHERE owner_user_id = $2 AND id = $3
                 RETURNING id, owner_user_id, name, created_at, updated_at",
                &[&name, &owner_user_id.0, &group_id],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let Some(row) = row else {
            return Err(ConversationError::NotFound);
        };

        if let Some(members) = members {
            transaction
                .execute(
                    "DELETE FROM conversation_share_group_members WHERE group_id = $1",
                    &[&group_id],
                )
                .await
                .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

            for member in members {
                transaction
                    .execute(
                        "INSERT INTO conversation_share_group_members (group_id, member_type, member_value)
                         VALUES ($1, $2, $3)
                         ON CONFLICT (group_id, member_type, member_value) DO NOTHING",
                        &[&group_id, &member.kind.as_str(), &member.value],
                    )
                    .await
                    .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;
            }
        }

        transaction
            .commit()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let members = if let Some(members) = members {
            members.to_vec()
        } else {
            let members_map = self.load_group_members(&[group_id]).await?;
            members_map.get(&group_id).cloned().unwrap_or_default()
        };

        Ok(Self::to_share_group(&row, members))
    }

    async fn delete_group(
        &self,
        owner_user_id: UserId,
        group_id: Uuid,
    ) -> Result<(), ConversationError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let deleted = client
            .execute(
                "DELETE FROM conversation_share_groups WHERE owner_user_id = $1 AND id = $2",
                &[&owner_user_id.0, &group_id],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        if deleted == 0 {
            return Err(ConversationError::NotFound);
        }

        Ok(())
    }

    async fn create_share(
        &self,
        share: NewConversationShare,
    ) -> Result<ConversationShare, ConversationError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let row = client
            .query_one(
                "INSERT INTO conversation_shares (
                     conversation_id,
                     owner_user_id,
                     share_type,
                     permission,
                     recipient_type,
                     recipient_value,
                     group_id,
                     org_email_pattern,
                     public_token
                 )
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                 RETURNING id, conversation_id, owner_user_id, share_type, permission,
                           recipient_type, recipient_value, group_id, org_email_pattern,
                           public_token, created_at, updated_at",
                &[
                    &share.conversation_id,
                    &share.owner_user_id.0,
                    &share.share_type.as_str(),
                    &share.permission.as_str(),
                    &share
                        .recipient
                        .as_ref()
                        .map(|recipient| recipient.kind.as_str()),
                    &share
                        .recipient
                        .as_ref()
                        .map(|recipient| recipient.value.as_str()),
                    &share.group_id,
                    &share.org_email_pattern,
                    &share.public_token,
                ],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        Self::map_share_row(&row)
    }

    async fn list_shares(
        &self,
        owner_user_id: UserId,
        conversation_id: &str,
    ) -> Result<Vec<ConversationShare>, ConversationError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let rows = client
            .query(
                "SELECT id, conversation_id, owner_user_id, share_type, permission,
                        recipient_type, recipient_value, group_id, org_email_pattern,
                        public_token, created_at, updated_at
                 FROM conversation_shares
                 WHERE owner_user_id = $1 AND conversation_id = $2
                 ORDER BY created_at",
                &[&owner_user_id.0, &conversation_id],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        rows.iter()
            .map(Self::map_share_row)
            .collect::<Result<Vec<_>, _>>()
    }

    async fn delete_share(
        &self,
        owner_user_id: UserId,
        share_id: Uuid,
    ) -> Result<(), ConversationError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let deleted = client
            .execute(
                "DELETE FROM conversation_shares WHERE owner_user_id = $1 AND id = $2",
                &[&owner_user_id.0, &share_id],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        if deleted == 0 {
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
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let mut permissions: Vec<SharePermission> = Vec::new();

        let direct_rows = client
            .query(
                "SELECT permission
                 FROM conversation_shares
                 WHERE conversation_id = $1
                   AND share_type = 'direct'
                   AND (
                        (recipient_type = 'email' AND recipient_value = $2)
                        OR
                        (recipient_type = 'near' AND recipient_value = ANY($3))
                   )",
                &[&conversation_id, &email, &near_accounts],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        for row in direct_rows {
            let permission: String = row.get("permission");
            permissions.push(Self::map_permission(&permission)?);
        }

        let group_rows = client
            .query(
                "SELECT DISTINCT cs.permission
                 FROM conversation_shares cs
                 JOIN conversation_share_group_members cgm
                   ON cs.group_id = cgm.group_id
                 WHERE cs.conversation_id = $1
                   AND cs.share_type = 'group'
                   AND (
                        (cgm.member_type = 'email' AND cgm.member_value = $2)
                        OR
                        (cgm.member_type = 'near' AND cgm.member_value = ANY($3))
                   )",
                &[&conversation_id, &email, &near_accounts],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        for row in group_rows {
            let permission: String = row.get("permission");
            permissions.push(Self::map_permission(&permission)?);
        }

        let org_rows = client
            .query(
                "SELECT permission
                 FROM conversation_shares
                 WHERE conversation_id = $1
                   AND share_type = 'organization'
                   AND $2 ILIKE org_email_pattern",
                &[&conversation_id, &email],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        for row in org_rows {
            let permission: String = row.get("permission");
            permissions.push(Self::map_permission(&permission)?);
        }

        let has_write = permissions
            .iter()
            .any(|permission| *permission == SharePermission::Write);
        if has_write {
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
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let row = client
            .query_opt(
                "SELECT id, conversation_id, owner_user_id, share_type, permission,
                        recipient_type, recipient_value, group_id, org_email_pattern,
                        public_token, created_at, updated_at
                 FROM conversation_shares
                 WHERE share_type = 'public' AND public_token = $1",
                &[&token],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => Ok(Some(Self::map_share_row(&row)?)),
            None => Ok(None),
        }
    }
}
