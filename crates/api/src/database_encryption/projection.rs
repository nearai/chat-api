use super::*;

/// Temporary, session-local simulation; only row ids and HMAC tokens are stored.
/// PostgreSQL spills growing temporary relations to disk instead of retaining a
/// field's entire projection in application memory. Batch commits preserve it.
pub(super) async fn initialize(client: &deadpool_postgres::Object) -> anyhow::Result<()> {
    clear_session(client).await?;
    client
        .batch_execute(
            "CREATE TEMPORARY TABLE near_db_encryption_projection (
            row_id UUID PRIMARY KEY,
            token BYTEA NOT NULL
         ) ON COMMIT PRESERVE ROWS;
         CREATE INDEX near_db_encryption_projection_token
            ON near_db_encryption_projection(token)",
        )
        .await?;
    Ok(())
}

pub(super) async fn clear_session(client: &deadpool_postgres::Object) -> anyhow::Result<()> {
    // Inspecting the current session's namespace does not create one or require
    // TEMP privilege. Ordinary encrypt/verify jobs issue no temporary DDL.
    let exists: bool = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM pg_class
         WHERE relnamespace=pg_my_temp_schema() AND relname='near_db_encryption_projection')",
            &[],
        )
        .await?
        .get(0);
    if !exists {
        return Ok(());
    }
    client
        .batch_execute("DROP TABLE pg_temp.near_db_encryption_projection")
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
                AND NOT EXISTS (SELECT 1 FROM pg_temp.near_db_encryption_projection projected
                                WHERE projected.row_id=other.id)
            UNION ALL
            SELECT 1 FROM {table} target
            JOIN pg_temp.near_db_encryption_projection projected ON projected.token=$2
            JOIN {table} other ON other.id=projected.row_id AND {constraint}
            WHERE target.id=$1 AND other.id<>$1
        )",
        table = field.table,
    );
    let conflicts: bool = batch
        .tx
        .query_one(&sql, &[&rewrite.id, &token])
        .await?
        .get(0);
    if conflicts {
        return Ok(false);
    }
    batch
        .tx
        .execute(
            "INSERT INTO pg_temp.near_db_encryption_projection(row_id,token) VALUES($1,$2)",
            &[&rewrite.id, &token],
        )
        .await?;
    Ok(true)
}
