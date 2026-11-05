use super::*;

/// Only row ids and HMAC tokens are stored, scoped to a job rather than a pooled
/// session so connections can be returned between committed batches.
pub(super) async fn clear(
    client: &impl deadpool_postgres::GenericClient,
    job_id: Uuid,
) -> anyhow::Result<()> {
    client
        .execute(
            "DELETE FROM database_encryption_projection WHERE job_id=$1",
            &[&job_id],
        )
        .await?;
    Ok(())
}

/// Match V39's partial unique indexes against the simulated state at this row.
/// Unvisited/conflicting rows retain their stored token; successful earlier rows
/// contribute only their projected token, including releasing their old token.
pub(super) async fn try_rewrite(
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
    let constraint = match field.table {
        "conversation_share_groups" => "other.owner_user_id=target.owner_user_id",
        "conversation_share_group_members" => "other.group_id=target.group_id AND other.member_type=target.member_type",
        "conversation_shares" => "other.conversation_id=target.conversation_id AND other.recipient_type=target.recipient_type AND other.share_type='direct' AND target.share_type='direct'",
        _ => anyhow::bail!("unregistered token constraint"),
    };
    let sql = format!(
        "SELECT EXISTS (
            SELECT 1 FROM {table} target JOIN {table} other ON {constraint}
            WHERE target.id=$1 AND other.id<>$1 AND other.{column}=$2
                AND NOT EXISTS (SELECT 1 FROM database_encryption_projection projected
                                WHERE projected.job_id=$3 AND projected.row_id=other.id)
            UNION ALL
            SELECT 1 FROM {table} target
            JOIN database_encryption_projection projected ON projected.job_id=$3 AND projected.token=$2
            JOIN {table} other ON other.id=projected.row_id AND {constraint}
            WHERE target.id=$1 AND other.id<>$1
        )",
        table = field.table,
    );
    let conflicts: bool = batch
        .tx
        .query_one(&sql, &[&rewrite.id, &token, &batch.job_id])
        .await?
        .get(0);
    if conflicts {
        return Ok(false);
    }
    batch
        .tx
        .execute(
            "INSERT INTO database_encryption_projection(row_id,token,job_id) VALUES($1,$2,$3)",
            &[&rewrite.id, &token, &batch.job_id],
        )
        .await?;
    Ok(true)
}
