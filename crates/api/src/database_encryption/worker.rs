use super::*;

pub(super) async fn run_job(state: &AppState, id: Uuid) -> anyhow::Result<()> {
    let mut client = state.db_pool.get().await?;
    client
        .query_one("SELECT pg_advisory_lock($1)", &[&WORKER_LOCK])
        .await?;
    let result = run_locked_job(state, id, &mut client).await;
    // Clean temporary simulation state on both normal completion and errors.
    // A disconnected/crashed session drops its temporary relation automatically.
    let cleanup = projection::clear_session(&client).await;
    let unlock = client
        .query_one("SELECT pg_advisory_unlock($1)", &[&WORKER_LOCK])
        .await;
    result?;
    cleanup?;
    unlock?;
    Ok(())
}

async fn run_locked_job(
    state: &AppState,
    id: Uuid,
    client: &mut deadpool_postgres::Object,
) -> anyhow::Result<()> {
    let config = state
        .db_pool
        .field_encryption()
        .ok_or_else(|| anyhow::anyhow!("database encryption is not configured"))?;
    let ring = config.ring()?;
    let Some(job) = client.query_opt("UPDATE database_encryption_jobs SET status='running',started_at=COALESCE(started_at,NOW()) WHERE id=$1 AND status IN ('queued','running') RETURNING mode,scope,batch_size,max_rows,cursor,progress,actions", &[&id]).await? else { return Ok(()) };
    let mode: String = job.get(0);
    let scope: Scope = serde_json::from_value(job.get(1))?;
    if !scope.tables.is_empty() || scope.fields.is_empty() {
        mark_job_failed(
            state,
            id,
            "scope_requires_confirmation",
            "Legacy job scope is not pinned; review the fields and create a new job",
        )
        .await?;
        return Ok(());
    }
    let batch: i64 = job.get(2);
    let max: Option<i64> = job.get(3);
    let cursor: Value = job.get(4);
    let actions: Vec<String> = serde_json::from_value(job.get(6))?;
    let request_mode: Mode = serde_json::from_value(json!(mode))?;
    requests::validate_actions(&request_mode, &actions)
        .map_err(|_| anyhow::anyhow!("invalid stored job action"))?;
    let action = actions
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing job action"))?;
    let replay_projection = mode == "dry_run" && action == "rewrap";
    let checkpoint = checkpoint::Checkpoint::restore(replay_projection, cursor, job.get(5))?;
    let mut progress = checkpoint.progress;
    let fields = selected(&scope).map_err(|_| anyhow::anyhow!("invalid scope"))?;
    let mut field_index = checkpoint.field_index;
    let mut after = checkpoint.after;
    if replay_projection {
        // Publish the replay reset before processing, even if no rows remain.
        client
            .execute(
                "UPDATE database_encryption_jobs SET cursor=$2,progress=$3 WHERE id=$1",
                &[
                    &id,
                    &json!({"field_index":field_index,"after_id":after}),
                    &serde_json::to_value(&progress)?,
                ],
            )
            .await?;
        projection::initialize(client).await?;
    }
    while field_index < fields.len() && max.is_none_or(|limit| progress.totals.processed < limit) {
        if write_gate_blocks(&mode, execute_writes_enabled(state, &fields)) {
            fail_write_disabled_job(state, id).await?;
            return Ok(());
        }
        let field = fields[field_index];
        let cap = max
            .map(|limit| (limit - progress.totals.processed).min(batch))
            .unwrap_or(batch);
        let tx = client.transaction().await?;
        tx.batch_execute("SET LOCAL statement_timeout='30s'")
            .await?;
        if tx.query_one("SELECT cancel_requested_at IS NOT NULL FROM database_encryption_jobs WHERE id=$1 FOR UPDATE", &[&id]).await?.get::<_,bool>(0) {
            tx.execute("UPDATE database_encryption_jobs SET status='cancelled',completed_at=NOW() WHERE id=$1", &[&id]).await?;
            tx.commit().await?;
            return Ok(());
        }
        let row_id = row_id_expression(field, None);
        let token = field
            .token
            .map(|(column, _)| column)
            .unwrap_or("NULL::bytea");
        let query = format!("WITH candidates AS (SELECT {row_id} AS row_id,{column}::text value,{token} search_token FROM {table} WHERE {row_id}>$1 AND {column} IS NOT NULL ORDER BY row_id LIMIT $2 FOR UPDATE), sized AS (SELECT *,sum(octet_length(value)) OVER(ORDER BY row_id) bytes,row_number() OVER(ORDER BY row_id) row_no FROM candidates) SELECT row_id,value,search_token FROM sized WHERE bytes<=$3 OR row_no=1 ORDER BY row_id", column=field.column,table=field.table);
        let rows = tx.query(&query, &[&after, &cap, &MAX_BATCH_BYTES]).await?;
        if rows.is_empty() {
            field_index += 1;
            after = Uuid::nil();
            if replay_projection {
                tx.batch_execute("TRUNCATE pg_temp.near_db_encryption_projection")
                    .await?;
            }
            tx.commit().await?;
            continue;
        }
        let processor = batch::Batch {
            tx: &tx,
            field,
            config: &config,
            ring: &ring,
            mode: &mode,
            action,
        };
        for row in &rows {
            after = row.get(0);
            processor.process(row, &mut progress).await?;
        }
        let progress_value = serde_json::to_value(&progress)?;
        tx.execute(
            "UPDATE database_encryption_jobs SET progress=$2,cursor=$3 WHERE id=$1",
            &[
                &id,
                &progress_value,
                &json!({"field_index":field_index,"after_id":after}),
            ],
        )
        .await?;
        tx.commit().await?;
        // Release every row and job lock before applying the operator's throttle.
        tokio::time::sleep(std::time::Duration::from_millis(
            scope.options.batch_delay_ms,
        ))
        .await;
    }
    let inventory = if mode == "verify" {
        inventory_with_client(client).await?
    } else {
        Inventory::default()
    };
    let mut missing_encryption_contexts = 0i64;
    for field in &fields {
        let row_id = row_id_expression(field, None);
        let query = format!(
            "SELECT count(*) FROM {table} WHERE {column} IS NOT NULL AND {row_id} IS NULL",
            table = field.table,
            column = field.column
        );
        missing_encryption_contexts += client.query_one(&query, &[]).await?.get::<_, i64>(0);
    }
    let totals = &progress.totals;
    let pass = totals.invalid_envelopes == 0
        && totals.token_conflicts == 0
        && (mode != "verify"
            || totals.plaintext == 0
                && totals.legacy_encrypted == 0
                && totals.stale == 0
                && missing_encryption_contexts == 0
                && inventory.unclassified.is_empty()
                && inventory.legacy_confidential.is_empty());
    client.execute("UPDATE database_encryption_jobs SET status='completed',completed_at=NOW(),progress=progress||$2 WHERE id=$1", &[&id, &json!({"pass":pass,"missing_encryption_contexts":missing_encryption_contexts,"legacy_confidential":inventory.legacy_confidential,"unclassified":inventory.unclassified})]).await?;
    Ok(())
}
