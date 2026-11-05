use super::*;

pub(super) async fn run_job(state: &AppState, id: Uuid) -> anyhow::Result<()> {
    // A separate transaction holds whole-job ownership across batch commits and
    // throttle waits. Disconnect/abort rolls it back and releases ownership.
    let mut owner = state.db_pool.get().await?;
    let ownership = owner.transaction().await?;
    let locked: bool = ownership
        .query_one("SELECT pg_try_advisory_xact_lock($1)", &[&WORKER_LOCK])
        .await?
        .get(0);
    if !locked {
        return Ok(());
    }
    let running = ownership.query_opt(
        "SELECT id FROM database_encryption_jobs WHERE status='running' ORDER BY created_at,id LIMIT 1",
        &[],
    ).await?;
    if running.is_some_and(|row| row.get::<_, Uuid>(0) != id) {
        return Ok(());
    }
    let result = run_owned_job(state, id).await;
    if result.is_err() {
        mark_job_failed(state, id, "batch_failed", "batch_failed").await?;
    }
    ownership.rollback().await?;
    result
}

async fn run_owned_job(state: &AppState, id: Uuid) -> anyhow::Result<()> {
    let mut first = true;
    // Task-local state survives returning pooled connections between batches.
    // A recovered dry run starts over because this state is never persisted.
    let mut projection = projection::Projection::default();
    loop {
        // run_batch commits and returns its connection before any delay.
        let Some(delay) = run_batch(state, id, first, &mut projection).await? else {
            return Ok(());
        };
        first = false;
        if throttle::wait(std::time::Duration::from_millis(delay), || async {
            let client = state.db_pool.get().await?;
            let cancelled = client.execute("UPDATE database_encryption_jobs SET status='cancelled',completed_at=NOW() WHERE id=$1 AND status IN ('queued','running') AND cancel_requested_at IS NOT NULL", &[&id]).await? > 0;
            Ok(cancelled)
        }).await? { return Ok(()) }
    }
}

async fn run_batch(
    state: &AppState,
    id: Uuid,
    first: bool,
    projection: &mut projection::Projection,
) -> anyhow::Result<Option<u64>> {
    let config = state
        .db_pool
        .field_encryption()
        .ok_or_else(|| anyhow::anyhow!("database encryption is not configured"))?;
    let ring = config.ring();
    let mut client = state.db_pool.get().await?;
    let tx = client.transaction().await?;
    tx.batch_execute("SET LOCAL statement_timeout='30s'")
        .await?;
    let Some(job) = tx.query_opt("UPDATE database_encryption_jobs SET status='running',started_at=COALESCE(started_at,NOW()) WHERE id=$1 AND status IN ('queued','running') RETURNING mode,scope,batch_size,max_rows,cursor,progress,actions,cancel_requested_at IS NOT NULL", &[&id]).await? else { return Ok(None) };
    if job.get::<_, bool>(7) {
        tx.execute(
            "UPDATE database_encryption_jobs SET status='cancelled',completed_at=NOW() WHERE id=$1 AND status='running'",
            &[&id],
        )
        .await?;
        tx.commit().await?;
        return Ok(None);
    }
    let mode: String = job.get(0);
    let scope: Scope = serde_json::from_value(job.get(1))?;
    if !scope.tables.is_empty() || scope.fields.is_empty() {
        tx.execute("UPDATE database_encryption_jobs SET status=CASE WHEN cancel_requested_at IS NULL THEN 'failed' ELSE 'cancelled' END,completed_at=NOW(),last_error_class=CASE WHEN cancel_requested_at IS NULL THEN 'scope_requires_confirmation' END,last_error_message=CASE WHEN cancel_requested_at IS NULL THEN 'Legacy job scope is not pinned; review the fields and create a new job' END WHERE id=$1 AND status='running'", &[&id]).await?;
        tx.commit().await?;
        return Ok(None);
    }
    let batch: i64 = job.get(2);
    let max: Option<i64> = job.get(3);
    let actions: Vec<String> = serde_json::from_value(job.get(6))?;
    let request_mode: Mode = serde_json::from_value(json!(mode))?;
    requests::validate_actions(&request_mode, &actions)
        .map_err(|_| anyhow::anyhow!("invalid stored job action"))?;
    let action = actions
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing job action"))?;
    let replay = mode == "dry_run";
    let mut checkpoint = checkpoint::Checkpoint::restore(first && replay, job.get(4), job.get(5))?;
    let fields = selected(&scope).map_err(|_| anyhow::anyhow!("invalid scope"))?;
    if write_gate_blocks(&mode, execute_writes_enabled(state, &fields)) {
        tx.execute("UPDATE database_encryption_jobs SET status=CASE WHEN cancel_requested_at IS NULL THEN 'failed' ELSE 'cancelled' END,completed_at=NOW(),last_error_class=CASE WHEN cancel_requested_at IS NULL THEN 'write_disabled' END,last_error_message=CASE WHEN cancel_requested_at IS NULL THEN 'Database encryption writes are disabled for the selected scope' END WHERE id=$1 AND status='running'", &[&id]).await?;
        tx.commit().await?;
        return Ok(None);
    }
    if checkpoint.field_index >= fields.len()
        || max.is_some_and(|limit| checkpoint.progress.totals.processed >= limit)
    {
        super::completion::finish(&tx, id, &mode, &fields, &checkpoint.progress).await?;
        tx.commit().await?;
        return Ok(None);
    }
    let field = fields[checkpoint.field_index];
    let cap = max
        .map(|limit| (limit - checkpoint.progress.totals.processed).min(batch))
        .unwrap_or(batch);
    let row_id = row_id_expression(field, None);
    let token = field
        .token
        .map(|(column, _)| column)
        .unwrap_or("NULL::bytea");
    let query = format!("WITH candidates AS (SELECT {row_id} AS row_id,{column}::text value,{token} search_token FROM {table} WHERE {row_id}>$1 AND {column} IS NOT NULL ORDER BY row_id LIMIT $2 FOR UPDATE), sized AS (SELECT *,sum(octet_length(value)) OVER(ORDER BY row_id) bytes,row_number() OVER(ORDER BY row_id) row_no FROM candidates) SELECT row_id,value,search_token FROM sized WHERE bytes<=$3 OR row_no=1 ORDER BY row_id", column=field.column,table=field.table);
    let rows = tx
        .query(&query, &[&checkpoint.after, &cap, &MAX_BATCH_BYTES])
        .await?;
    let delay = if rows.is_empty() {
        checkpoint.field_index += 1;
        checkpoint.after = Uuid::nil();
        projection.clear_field();
        0
    } else {
        let processor = batch::Batch {
            tx: &tx,
            field,
            ring,
            mode: &mode,
            action,
        };
        let mut rewrites = Vec::with_capacity(rows.len());
        for row in &rows {
            checkpoint.after = row.get(0);
            processor
                .process(row, &mut checkpoint.progress, projection, &mut rewrites)
                .await?;
        }
        let updated = writes::write_batch(&processor, &rewrites).await? as i64;
        checkpoint.progress.record(field, |counts| {
            if action == "encrypt" {
                counts.encrypted += updated;
            } else if action == "rewrap" {
                counts.rewrapped += updated;
            }
        });
        checkpoint.progress.token_conflicts_estimated = projection.estimated();
        scope.options.batch_delay_ms.unwrap_or_default()
    };
    tx.execute(
        "UPDATE database_encryption_jobs SET progress=$2,cursor=$3 WHERE id=$1",
        &[
            &id,
            &serde_json::to_value(&checkpoint.progress)?,
            &json!({"field_index":checkpoint.field_index,"after_id":checkpoint.after}),
        ],
    )
    .await?;
    tx.commit().await?;
    Ok(Some(delay))
}
