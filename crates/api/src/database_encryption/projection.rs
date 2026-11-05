use super::*;
use std::collections::{HashMap, HashSet};

const MAX_PROJECTED_ROWS: usize = 100_000;
type FieldKey = (&'static str, &'static str);

#[derive(Default)]
struct ProjectedField {
    rows: HashSet<Uuid>,
    tokens: HashMap<[u8; 32], Vec<Uuid>>,
}

/// Job-local dry-run state contains only field names, UUIDs and HMAC tokens.
/// Tracking at most 100,000 successful rows bounds memory; overflow discards
/// tracking and makes conflict counts estimates for the remainder of the job.
#[derive(Default)]
pub(super) struct Projection {
    fields: HashMap<FieldKey, ProjectedField>,
    tracked_rows: usize,
    estimated: bool,
}

impl Projection {
    pub(super) fn clear_field(&mut self) {
        self.fields.clear();
        self.tracked_rows = 0;
    }

    pub(super) const fn estimated(&self) -> bool {
        self.estimated
    }

    fn projected_ids(&self, field: FieldKey, token: &[u8; 32]) -> &[Uuid] {
        self.fields
            .get(&field)
            .and_then(|field| field.tokens.get(token))
            .map_or(&[], Vec::as_slice)
    }

    fn try_record(
        &mut self,
        field: FieldKey,
        id: Uuid,
        token: [u8; 32],
        stored_matches: &[Uuid],
        projected_conflict: bool,
    ) -> bool {
        let projected = self.fields.get(&field);
        let stored_conflict = stored_matches
            .iter()
            .any(|id| projected.is_none_or(|field| !field.rows.contains(id)));
        if stored_conflict || projected_conflict {
            return false;
        }
        if self.estimated {
            return true;
        }
        if self.tracked_rows == MAX_PROJECTED_ROWS {
            self.clear_field();
            self.estimated = true;
            return true;
        }
        let projected = self.fields.entry(field).or_default();
        if projected.rows.insert(id) {
            projected.tokens.entry(token).or_default().push(id);
            self.tracked_rows += 1;
        }
        true
    }

    /// Match V39's unique indexes against stored and successfully projected rows.
    pub(super) async fn try_rewrite(
        &mut self,
        batch: &batch::Batch<'_, '_>,
        rewrite: &writes::RowRewrite,
    ) -> anyhow::Result<bool> {
        let Some(token) = rewrite.token.as_deref() else {
            return Ok(true);
        };
        let field = batch.field;
        let Some((column, _)) = field.token else {
            return Ok(true);
        };
        let token: [u8; 32] = token
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid search token length"))?;
        let constraint = match field.table {
            "conversation_share_groups" => "other.owner_user_id=target.owner_user_id",
            "conversation_share_group_members" => "other.group_id=target.group_id AND other.member_type=target.member_type",
            "conversation_shares" => "other.conversation_id=target.conversation_id AND other.recipient_type=target.recipient_type AND other.share_type='direct' AND target.share_type='direct'",
            _ => anyhow::bail!("unregistered token constraint"),
        };
        let sql = format!(
            "SELECT other.id FROM {table} target JOIN {table} other ON {constraint}
             WHERE target.id=$1 AND other.id<>$1 AND other.{column}=$2",
            table = field.table,
        );
        let stored_matches = batch
            .tx
            .query(&sql, &[&rewrite.id, &token.as_slice()])
            .await?
            .iter()
            .map(|row| row.get(0))
            .collect::<Vec<Uuid>>();
        let key = (field.table, field.column);
        let candidates = self.projected_ids(key, &token);
        let projected_conflict = if candidates.is_empty() {
            false
        } else {
            let sql = format!(
                "SELECT EXISTS (
                    SELECT 1 FROM {table} target JOIN {table} other ON {constraint}
                    WHERE target.id=$1 AND other.id<>$1 AND other.id=ANY($2::uuid[])
                )",
                table = field.table,
            );
            batch
                .tx
                .query_one(&sql, &[&rewrite.id, &candidates])
                .await?
                .get(0)
        };
        Ok(self.try_record(key, rewrite.id, token, &stored_matches, projected_conflict))
    }
}

#[cfg(test)]
#[path = "projection_tests.rs"]
mod tests;
