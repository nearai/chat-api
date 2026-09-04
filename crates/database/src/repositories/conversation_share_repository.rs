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

    fn encode(
        &self,
        table: &str,
        column: &str,
        id: Uuid,
        value: &str,
    ) -> Result<String, ConversationError> {
        match self.pool.field_encryption() {
            Some(config) if config.write_enabled => crate::field_encryption::encrypt(
                &config.key,
                &config.key_id,
                table,
                column,
                id,
                value,
            )
            .map_err(|e| ConversationError::DatabaseError(e.to_string())),
            _ => Ok(value.to_string()),
        }
    }

    fn decode(
        &self,
        table: &str,
        column: &str,
        id: Uuid,
        value: String,
    ) -> Result<String, ConversationError> {
        match self.pool.field_encryption() {
            Some(config) => crate::field_encryption::decrypt_if_encrypted(
                &config.key,
                &config.key_id,
                table,
                column,
                id,
                value,
            )
            .map_err(|e| ConversationError::DatabaseError(e.to_string())),
            None => Ok(value),
        }
    }

    fn token(&self, domain: &str, value: &str) -> Result<Option<Vec<u8>>, ConversationError> {
        self.pool
            .field_encryption()
            .map(|config| {
                crate::field_encryption::search_token(
                    &config.key,
                    domain,
                    &value.trim().to_lowercase(),
                )
                .map_err(|e| ConversationError::DatabaseError(e.to_string()))
            })
            .transpose()
    }

    fn org_domain(value: &str) -> String {
        value
            .trim()
            .trim_start_matches('%')
            .trim_start_matches('@')
            .to_lowercase()
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

    fn map_share_row(
        &self,
        row: &tokio_postgres::Row,
    ) -> Result<ConversationShare, ConversationError> {
        let id: Uuid = row.get("id");
        let recipient_kind: Option<String> = row.get("recipient_type");
        let recipient_value: Option<String> = row.get("recipient_value");
        let recipient = match (recipient_kind, recipient_value) {
            (Some(kind), Some(value)) => Some(ShareRecipient {
                kind: Self::map_recipient_kind(&kind)?,
                value: self.decode("conversation_shares", "recipient_value", id, value)?,
            }),
            _ => None,
        };

        Ok(ConversationShare {
            id,
            conversation_id: row.get("conversation_id"),
            owner_user_id: row.get("owner_user_id"),
            share_type: Self::map_share_type(row.get("share_type"))?,
            permission: Self::map_permission(row.get("permission"))?,
            recipient,
            group_id: row.get("group_id"),
            org_email_pattern: row
                .get::<_, Option<String>>("org_email_pattern")
                .map(|value| self.decode("conversation_shares", "org_email_pattern", id, value))
                .transpose()?,
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
                "SELECT id, group_id, member_type, member_value
                 FROM conversation_share_group_members
                 WHERE group_id = ANY($1)",
                &[&group_ids],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let mut members: HashMap<Uuid, Vec<ShareRecipient>> = HashMap::new();

        for row in rows {
            let id: Uuid = row.get("id");
            let group_id: Uuid = row.get("group_id");
            let kind = Self::map_recipient_kind(row.get("member_type"))?;
            let value = self.decode(
                "conversation_share_group_members",
                "member_value",
                id,
                row.get("member_value"),
            )?;
            members
                .entry(group_id)
                .or_default()
                .push(ShareRecipient { kind, value });
        }

        Ok(members)
    }

    fn to_share_group(
        &self,
        row: &tokio_postgres::Row,
        members: Vec<ShareRecipient>,
    ) -> Result<ShareGroup, ConversationError> {
        let id: Uuid = row.get("id");
        Ok(ShareGroup {
            id,
            owner_user_id: row.get("owner_user_id"),
            name: self.decode("conversation_share_groups", "name", id, row.get("name"))?,
            members,
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
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
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let transaction = client
            .transaction()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let group_id = Uuid::new_v4();
        let stored_name = self.encode("conversation_share_groups", "name", group_id, name)?;
        let name_token = self.token("conversation_share_groups.name", name)?;
        let row = transaction
            .query_one(
                "INSERT INTO conversation_share_groups (id, owner_user_id, name, name_search_token)
                 VALUES ($1, $2, $3, $4)
                 RETURNING id, owner_user_id, name, created_at, updated_at",
                &[&group_id, &owner_user_id.0, &stored_name, &name_token],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        for member in members {
            let member_id = Uuid::new_v4();
            let stored_value = self.encode(
                "conversation_share_group_members",
                "member_value",
                member_id,
                &member.value,
            )?;
            let value_token = self.token(
                "conversation_share_group_members.member_value",
                &member.value,
            )?;
            transaction
                .execute(
                    "INSERT INTO conversation_share_group_members (id, group_id, member_type, member_value, member_value_search_token)
                     VALUES ($1, $2, $3, $4, $5)
                     ON CONFLICT (group_id, member_type, member_value_search_token) WHERE member_value_search_token IS NOT NULL DO NOTHING",
                    &[&member_id, &group_id, &member.kind.as_str(), &stored_value, &value_token],
                )
                .await
                .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;
        }

        transaction
            .commit()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        self.to_share_group(&row, members.to_vec())
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
                 ORDER BY created_at, id",
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
                self.to_share_group(row, members.get(&id).cloned().unwrap_or_default())
            })
            .collect::<Result<_, _>>()?;

        Ok(groups)
    }

    async fn list_groups_for_member(
        &self,
        member_identifiers: &[ShareRecipient],
    ) -> Result<Vec<ShareGroup>, ConversationError> {
        if member_identifiers.is_empty() {
            return Ok(Vec::new());
        }

        let client = self
            .pool
            .get()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        // Use UNNEST to create pairs of (type, value) from arrays
        // This is safer than dynamic SQL construction and maintains correct pair matching
        // UNNEST with multiple arrays creates rows where elements at the same position are paired
        let member_types: Vec<String> = member_identifiers
            .iter()
            .map(|m| m.kind.as_str().to_string())
            .collect();
        let member_values_lower: Vec<String> = member_identifiers
            .iter()
            .map(|m| m.value.to_lowercase())
            .collect();
        let member_tokens: Vec<Option<Vec<u8>>> = member_identifiers
            .iter()
            .map(|member| {
                self.token(
                    "conversation_share_group_members.member_value",
                    &member.value,
                )
            })
            .collect::<Result<_, _>>()?;

        // Use parameterized query with UNNEST to safely match (type, value) pairs
        // This avoids dynamic SQL construction while maintaining correct pairing semantics
        let rows = client
            .query(
                "SELECT DISTINCT g.id, g.owner_user_id, g.name, g.created_at, g.updated_at
                 FROM conversation_share_groups g
                 JOIN conversation_share_group_members m ON g.id = m.group_id
                 JOIN UNNEST($1::text[], $2::text[], $3::bytea[]) AS search(member_type, member_value, member_token)
                   ON m.member_type = search.member_type
                   AND (m.member_value_search_token = search.member_token OR
                        (m.member_value_search_token IS NULL AND LOWER(m.member_value) = search.member_value))
                 ORDER BY g.created_at, g.id",
                &[&member_types, &member_values_lower, &member_tokens],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let group_ids: Vec<Uuid> = rows.iter().map(|row| row.get("id")).collect();
        let members = self.load_group_members(&group_ids).await?;

        let groups = rows
            .iter()
            .map(|row| {
                let id: Uuid = row.get("id");
                self.to_share_group(row, members.get(&id).cloned().unwrap_or_default())
            })
            .collect::<Result<_, _>>()?;

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
        let group =
            self.to_share_group(&row, members.get(&group_id).cloned().unwrap_or_default())?;
        Ok(Some(group))
    }

    async fn update_group(
        &self,
        owner_user_id: UserId,
        group_id: Uuid,
        name: Option<&str>,
        members: Option<&[ShareRecipient]>,
    ) -> Result<ShareGroup, ConversationError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let transaction = client
            .transaction()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let stored_name = name
            .map(|value| self.encode("conversation_share_groups", "name", group_id, value))
            .transpose()?;
        let name_token = name
            .map(|value| self.token("conversation_share_groups.name", value))
            .transpose()?
            .flatten();
        let row = transaction
            .query_opt(
                "UPDATE conversation_share_groups
                 SET name = COALESCE($1, name), name_search_token = COALESCE($2, name_search_token), updated_at = NOW()
                 WHERE owner_user_id = $3 AND id = $4
                 RETURNING id, owner_user_id, name, created_at, updated_at",
                &[&stored_name, &name_token, &owner_user_id.0, &group_id],
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
                let member_id = Uuid::new_v4();
                let stored_value = self.encode(
                    "conversation_share_group_members",
                    "member_value",
                    member_id,
                    &member.value,
                )?;
                let value_token = self.token(
                    "conversation_share_group_members.member_value",
                    &member.value,
                )?;
                transaction
                    .execute(
                        "INSERT INTO conversation_share_group_members (id, group_id, member_type, member_value, member_value_search_token)
                         VALUES ($1, $2, $3, $4, $5)
                         ON CONFLICT (group_id, member_type, member_value_search_token) WHERE member_value_search_token IS NOT NULL DO NOTHING",
                        &[&member_id, &group_id, &member.kind.as_str(), &stored_value, &value_token],
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

        self.to_share_group(&row, members)
    }

    async fn delete_group(
        &self,
        owner_user_id: UserId,
        group_id: Uuid,
    ) -> Result<(), ConversationError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let tx = client
            .transaction()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let group_exists = tx
            .query_opt(
                "SELECT 1 FROM conversation_share_groups WHERE owner_user_id = $1 AND id = $2 FOR UPDATE",
                &[&owner_user_id.0, &group_id],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?
            .is_some();
        if !group_exists {
            return Err(ConversationError::NotFound);
        }

        tx.execute(
            "DELETE FROM conversation_shares WHERE group_id = $1",
            &[&group_id],
        )
        .await
        .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        tx.execute(
            "DELETE FROM conversation_share_group_members WHERE group_id = $1",
            &[&group_id],
        )
        .await
        .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        tx.execute(
            "DELETE FROM conversation_share_groups WHERE owner_user_id = $1 AND id = $2",
            &[&owner_user_id.0, &group_id],
        )
        .await
        .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

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

        let share_id = Uuid::new_v4();
        let recipient_value = share
            .recipient
            .as_ref()
            .map(|recipient| {
                self.encode(
                    "conversation_shares",
                    "recipient_value",
                    share_id,
                    &recipient.value,
                )
            })
            .transpose()?;
        let recipient_token = share
            .recipient
            .as_ref()
            .map(|recipient| self.token("conversation_shares.recipient_value", &recipient.value))
            .transpose()?
            .flatten();
        let org_email_pattern = share
            .org_email_pattern
            .as_ref()
            .map(|pattern| {
                self.encode(
                    "conversation_shares",
                    "org_email_pattern",
                    share_id,
                    pattern,
                )
            })
            .transpose()?;
        let org_domain_token = share
            .org_email_pattern
            .as_ref()
            .map(|pattern| self.token("conversation_shares.org_domain", &Self::org_domain(pattern)))
            .transpose()?
            .flatten();
        // Use ON CONFLICT to update existing shares based on share type
        let query = match share.share_type {
            ShareType::Direct => {
                "INSERT INTO conversation_shares (
                     conversation_id,
                     owner_user_id,
                     share_type,
                     permission,
                     recipient_type,
                     recipient_value,
                     group_id,
                     org_email_pattern, id, recipient_value_search_token, org_domain_search_token
                 )
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                 ON CONFLICT (conversation_id, recipient_type, recipient_value_search_token)
                     WHERE share_type = 'direct' AND recipient_value_search_token IS NOT NULL
                 DO UPDATE SET
                     permission = EXCLUDED.permission,
                     updated_at = NOW()
                 RETURNING id, conversation_id, owner_user_id, share_type, permission,
                           recipient_type, recipient_value, group_id, org_email_pattern,
                           created_at, updated_at"
            }
            ShareType::Group => {
                "INSERT INTO conversation_shares (
                     conversation_id,
                     owner_user_id,
                     share_type,
                     permission,
                     recipient_type,
                     recipient_value,
                     group_id,
                     org_email_pattern, id, recipient_value_search_token, org_domain_search_token
                 )
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                 ON CONFLICT (conversation_id, group_id)
                     WHERE share_type = 'group'
                 DO UPDATE SET
                     permission = EXCLUDED.permission,
                     updated_at = NOW()
                 RETURNING id, conversation_id, owner_user_id, share_type, permission,
                           recipient_type, recipient_value, group_id, org_email_pattern,
                           created_at, updated_at"
            }
            ShareType::Organization => {
                "INSERT INTO conversation_shares (
                     conversation_id,
                     owner_user_id,
                     share_type,
                     permission,
                     recipient_type,
                     recipient_value,
                     group_id,
                     org_email_pattern, id, recipient_value_search_token, org_domain_search_token
                 )
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                 ON CONFLICT (conversation_id, org_domain_search_token)
                     WHERE share_type = 'organization' AND org_domain_search_token IS NOT NULL
                 DO UPDATE SET
                     permission = EXCLUDED.permission,
                     updated_at = NOW()
                 RETURNING id, conversation_id, owner_user_id, share_type, permission,
                           recipient_type, recipient_value, group_id, org_email_pattern,
                           created_at, updated_at"
            }
            ShareType::Public => {
                "INSERT INTO conversation_shares (
                     conversation_id,
                     owner_user_id,
                     share_type,
                     permission,
                     recipient_type,
                     recipient_value,
                     group_id,
                     org_email_pattern, id, recipient_value_search_token, org_domain_search_token
                 )
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                 ON CONFLICT (conversation_id)
                     WHERE share_type = 'public'
                 DO UPDATE SET
                     permission = EXCLUDED.permission,
                     updated_at = NOW()
                 RETURNING id, conversation_id, owner_user_id, share_type, permission,
                           recipient_type, recipient_value, group_id, org_email_pattern,
                           created_at, updated_at"
            }
        };

        let row = client
            .query_one(
                query,
                &[
                    &share.conversation_id,
                    &share.owner_user_id.0,
                    &share.share_type.as_str(),
                    &share.permission.as_str(),
                    &share
                        .recipient
                        .as_ref()
                        .map(|recipient| recipient.kind.as_str()),
                    &recipient_value,
                    &share.group_id,
                    &org_email_pattern,
                    &share_id,
                    &recipient_token,
                    &org_domain_token,
                ],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        self.map_share_row(&row)
    }

    /// Create multiple shares atomically (all succeed or all fail).
    /// If a share already exists, updates the permission instead of failing.
    async fn create_shares_batch(
        &self,
        shares: Vec<NewConversationShare>,
    ) -> Result<Vec<ConversationShare>, ConversationError> {
        if shares.is_empty() {
            return Ok(vec![]);
        }

        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let transaction = client
            .transaction()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let mut results = Vec::with_capacity(shares.len());

        for share in shares {
            let share_id = Uuid::new_v4();
            let recipient_value = share
                .recipient
                .as_ref()
                .map(|recipient| {
                    self.encode(
                        "conversation_shares",
                        "recipient_value",
                        share_id,
                        &recipient.value,
                    )
                })
                .transpose()?;
            let recipient_token = share
                .recipient
                .as_ref()
                .map(|recipient| {
                    self.token("conversation_shares.recipient_value", &recipient.value)
                })
                .transpose()?
                .flatten();
            let org_email_pattern = share
                .org_email_pattern
                .as_ref()
                .map(|pattern| {
                    self.encode(
                        "conversation_shares",
                        "org_email_pattern",
                        share_id,
                        pattern,
                    )
                })
                .transpose()?;
            let org_domain_token = share
                .org_email_pattern
                .as_ref()
                .map(|pattern| {
                    self.token("conversation_shares.org_domain", &Self::org_domain(pattern))
                })
                .transpose()?
                .flatten();
            // Use ON CONFLICT to update existing shares based on share type
            let query = match share.share_type {
                ShareType::Direct => {
                    "INSERT INTO conversation_shares (
                         conversation_id,
                         owner_user_id,
                         share_type,
                         permission,
                         recipient_type,
                         recipient_value,
                         group_id,
                         org_email_pattern, id, recipient_value_search_token, org_domain_search_token
                     )
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                     ON CONFLICT (conversation_id, recipient_type, recipient_value_search_token)
                         WHERE share_type = 'direct' AND recipient_value_search_token IS NOT NULL
                     DO UPDATE SET
                         permission = EXCLUDED.permission,
                         updated_at = NOW()
                     RETURNING id, conversation_id, owner_user_id, share_type, permission,
                               recipient_type, recipient_value, group_id, org_email_pattern,
                               created_at, updated_at"
                }
                ShareType::Group => {
                    "INSERT INTO conversation_shares (
                         conversation_id,
                         owner_user_id,
                         share_type,
                         permission,
                         recipient_type,
                         recipient_value,
                         group_id,
                         org_email_pattern, id, recipient_value_search_token, org_domain_search_token
                     )
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                     ON CONFLICT (conversation_id, group_id)
                         WHERE share_type = 'group'
                     DO UPDATE SET
                         permission = EXCLUDED.permission,
                         updated_at = NOW()
                     RETURNING id, conversation_id, owner_user_id, share_type, permission,
                               recipient_type, recipient_value, group_id, org_email_pattern,
                               created_at, updated_at"
                }
                ShareType::Organization => {
                    "INSERT INTO conversation_shares (
                         conversation_id,
                         owner_user_id,
                         share_type,
                         permission,
                         recipient_type,
                         recipient_value,
                         group_id,
                         org_email_pattern, id, recipient_value_search_token, org_domain_search_token
                     )
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                     ON CONFLICT (conversation_id, org_domain_search_token)
                         WHERE share_type = 'organization' AND org_domain_search_token IS NOT NULL
                     DO UPDATE SET
                         permission = EXCLUDED.permission,
                         updated_at = NOW()
                     RETURNING id, conversation_id, owner_user_id, share_type, permission,
                               recipient_type, recipient_value, group_id, org_email_pattern,
                               created_at, updated_at"
                }
                ShareType::Public => {
                    "INSERT INTO conversation_shares (
                         conversation_id,
                         owner_user_id,
                         share_type,
                         permission,
                         recipient_type,
                         recipient_value,
                         group_id,
                         org_email_pattern, id, recipient_value_search_token, org_domain_search_token
                     )
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                     ON CONFLICT (conversation_id)
                         WHERE share_type = 'public'
                     DO UPDATE SET
                         permission = EXCLUDED.permission,
                         updated_at = NOW()
                     RETURNING id, conversation_id, owner_user_id, share_type, permission,
                               recipient_type, recipient_value, group_id, org_email_pattern,
                               created_at, updated_at"
                }
            };

            let row = transaction
                .query_one(
                    query,
                    &[
                        &share.conversation_id,
                        &share.owner_user_id.0,
                        &share.share_type.as_str(),
                        &share.permission.as_str(),
                        &share
                            .recipient
                            .as_ref()
                            .map(|recipient| recipient.kind.as_str()),
                        &recipient_value,
                        &share.group_id,
                        &org_email_pattern,
                        &share_id,
                        &recipient_token,
                        &org_domain_token,
                    ],
                )
                .await
                .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

            results.push(self.map_share_row(&row)?);
        }

        transaction
            .commit()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        Ok(results)
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
                        created_at, updated_at
                 FROM conversation_shares
                 WHERE owner_user_id = $1 AND conversation_id = $2
                 ORDER BY created_at",
                &[&owner_user_id.0, &conversation_id],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        rows.iter()
            .map(|row| self.map_share_row(row))
            .collect::<Result<Vec<_>, _>>()
    }

    async fn delete_share(
        &self,
        owner_user_id: UserId,
        conversation_id: &str,
        share_id: Uuid,
    ) -> Result<(), ConversationError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let deleted = client
            .execute(
                "DELETE FROM conversation_shares
                 WHERE owner_user_id = $1 AND conversation_id = $2 AND id = $3",
                &[&owner_user_id.0, &conversation_id, &share_id],
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

        let email_token = self.token("conversation_shares.recipient_value", email)?;
        let group_email_token =
            self.token("conversation_share_group_members.member_value", email)?;
        let near_tokens: Vec<Option<Vec<u8>>> = near_accounts
            .iter()
            .map(|value| self.token("conversation_shares.recipient_value", value))
            .collect::<Result<_, _>>()?;
        let group_near_tokens: Vec<Option<Vec<u8>>> = near_accounts
            .iter()
            .map(|value| self.token("conversation_share_group_members.member_value", value))
            .collect::<Result<_, _>>()?;
        let org_token = email
            .split_once('@')
            .map(|(_, domain)| self.token("conversation_shares.org_domain", domain))
            .transpose()?
            .flatten();
        let row = client
            .query_opt(
                "SELECT permission FROM (
                     SELECT permission
                     FROM conversation_shares
                     WHERE conversation_id = $1
                       AND share_type = 'direct'
                       AND (
                            (recipient_type = 'email' AND (recipient_value_search_token = $4 OR (recipient_value_search_token IS NULL AND LOWER(recipient_value) = LOWER($2))))
                            OR
                            (recipient_type = 'near' AND (recipient_value_search_token = ANY($5) OR (recipient_value_search_token IS NULL AND recipient_value = ANY($3))))
                       )
                     UNION ALL
                     SELECT cs.permission
                     FROM conversation_shares cs
                     JOIN conversation_share_group_members cgm
                       ON cs.group_id = cgm.group_id
                     WHERE cs.conversation_id = $1
                       AND cs.share_type = 'group'
                       AND (
                            (cgm.member_type = 'email' AND (cgm.member_value_search_token = $6 OR (cgm.member_value_search_token IS NULL AND LOWER(cgm.member_value) = LOWER($2))))
                            OR
                            (cgm.member_type = 'near' AND (cgm.member_value_search_token = ANY($7) OR (cgm.member_value_search_token IS NULL AND cgm.member_value = ANY($3))))
                       )
                     UNION ALL
                     SELECT permission
                     FROM conversation_shares
                     WHERE conversation_id = $1
                       AND share_type = 'organization'
                       AND (org_domain_search_token = $8 OR (org_domain_search_token IS NULL AND $2 ILIKE org_email_pattern))
                 ) perms
                 ORDER BY CASE WHEN permission = 'write' THEN 0 ELSE 1 END
                 LIMIT 1",
                &[&conversation_id, &email, &near_accounts, &email_token, &near_tokens, &group_email_token, &group_near_tokens, &org_token],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => {
                let permission: String = row.get("permission");
                let permission = Self::map_permission(&permission)?;
                Ok(Some(permission))
            }
            None => Ok(None),
        }
    }

    async fn get_public_share_by_conversation_id(
        &self,
        conversation_id: &str,
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
                        created_at, updated_at
                 FROM conversation_shares
                 WHERE share_type = 'public' AND conversation_id = $1",
                &[&conversation_id],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => Ok(Some(self.map_share_row(&row)?)),
            None => Ok(None),
        }
    }

    async fn list_conversations_shared_with_user(
        &self,
        user_id: UserId,
        email: &str,
        near_accounts: &[String],
    ) -> Result<Vec<(String, SharePermission)>, ConversationError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let email_token = self.token("conversation_shares.recipient_value", email)?;
        let group_email_token =
            self.token("conversation_share_group_members.member_value", email)?;
        let near_tokens: Vec<Option<Vec<u8>>> = near_accounts
            .iter()
            .map(|value| self.token("conversation_shares.recipient_value", value))
            .collect::<Result<_, _>>()?;
        let group_near_tokens: Vec<Option<Vec<u8>>> = near_accounts
            .iter()
            .map(|value| self.token("conversation_share_group_members.member_value", value))
            .collect::<Result<_, _>>()?;
        let org_token = email
            .split_once('@')
            .map(|(_, domain)| self.token("conversation_shares.org_domain", domain))
            .transpose()?
            .flatten();
        // Query to find all conversations shared with the user via direct shares,
        // group memberships, or organization patterns. We take the highest permission
        // (write > read) for each conversation. Excludes conversations owned by the user.
        let rows = client
            .query(
                "SELECT conversation_id, MAX(CASE WHEN permission = 'write' THEN 1 ELSE 0 END) as has_write
                 FROM (
                     -- Direct shares by email or NEAR account (exclude own)
                     SELECT conversation_id, permission
                     FROM conversation_shares
                     WHERE share_type = 'direct'
                       AND owner_user_id != $3
                       AND (
                            (recipient_type = 'email' AND (recipient_value_search_token = $4 OR (recipient_value_search_token IS NULL AND LOWER(recipient_value) = LOWER($1))))
                            OR
                            (recipient_type = 'near' AND (recipient_value_search_token = ANY($5) OR (recipient_value_search_token IS NULL AND recipient_value = ANY($2))))
                       )
                     UNION ALL
                     -- Group shares where user is a member (exclude own)
                     SELECT cs.conversation_id, cs.permission
                     FROM conversation_shares cs
                     JOIN conversation_share_group_members cgm
                       ON cs.group_id = cgm.group_id
                     WHERE cs.share_type = 'group'
                       AND cs.owner_user_id != $3
                       AND (
                            (cgm.member_type = 'email' AND (cgm.member_value_search_token = $6 OR (cgm.member_value_search_token IS NULL AND LOWER(cgm.member_value) = LOWER($1))))
                            OR
                            (cgm.member_type = 'near' AND (cgm.member_value_search_token = ANY($7) OR (cgm.member_value_search_token IS NULL AND cgm.member_value = ANY($2))))
                       )
                     UNION ALL
                     -- Organization shares matching email pattern (exclude own)
                     SELECT conversation_id, permission
                     FROM conversation_shares
                     WHERE share_type = 'organization'
                       AND owner_user_id != $3
                       AND (org_domain_search_token = $8 OR (org_domain_search_token IS NULL AND $1 ILIKE org_email_pattern))
                 ) shares
                 GROUP BY conversation_id
                 ORDER BY conversation_id",
                &[&email, &near_accounts, &user_id.0, &email_token, &near_tokens, &group_email_token, &group_near_tokens, &org_token],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let result = rows
            .iter()
            .map(|row| {
                let conversation_id: String = row.get("conversation_id");
                let has_write: i32 = row.get("has_write");
                let permission = if has_write == 1 {
                    SharePermission::Write
                } else {
                    SharePermission::Read
                };
                (conversation_id, permission)
            })
            .collect();

        Ok(result)
    }
}
