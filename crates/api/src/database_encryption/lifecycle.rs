use super::*;
use std::time::Duration;

#[path = "recovery_scheduler.rs"]
mod scheduler;
pub(super) fn execute_writes_enabled(state: &AppState, fields: &[&Field]) -> bool {
    state.db_pool.field_encryption().is_some_and(|config| {
        config.write_enabled
            && (config.app_config_write_enabled
                || !fields.iter().any(|field| field.table == "app_config"))
            && (config.agent_secrets_write_enabled
                || !fields
                    .iter()
                    .any(|field| matches!(field.kind, Kind::AgentSecret)))
    })
}

pub(super) fn write_gate_blocks(mode: &str, write_enabled: bool) -> bool {
    mode == "execute" && !write_enabled
}

pub(super) async fn mark_job_failed(
    state: &AppState,
    id: Uuid,
    error_class: &str,
    error_message: &str,
) -> anyhow::Result<()> {
    let client = state.db_pool.get().await?;
    client
        .execute(
            "UPDATE database_encryption_jobs
             SET status=CASE WHEN cancel_requested_at IS NULL THEN 'failed' ELSE 'cancelled' END,
                 last_error_class=CASE WHEN cancel_requested_at IS NULL THEN $2 END,
                 last_error_message=CASE WHEN cancel_requested_at IS NULL THEN $3 END,
                 completed_at=NOW()
             WHERE id=$1 AND status IN ('queued','running')",
            &[&id, &error_class, &error_message],
        )
        .await?;
    Ok(())
}

pub async fn recover_jobs(state: AppState) {
    let Ok(_permit) = state.database_encryption_worker.semaphore.try_acquire() else {
        return;
    };
    let Ok(client) = state.db_pool.get().await else {
        return;
    };
    let Ok(Some(row)) = client
        .query_opt(
            "SELECT id FROM database_encryption_jobs
             WHERE status IN ('queued','running')
             ORDER BY (status='running') DESC,created_at,id LIMIT 1",
            &[],
        )
        .await
    else {
        return;
    };
    let id = row.get::<_, Uuid>(0);
    drop(client);
    if let Err(_error) = run_job(&state, id).await {
        tracing::error!(job_id=%id,error_class="database_encryption_recovered_job_failed","Recovered database encryption job failed");
        let _ = mark_job_failed(&state, id, "batch_failed", "batch_failed").await;
    }
}

pub async fn recover_jobs_periodically(state: AppState, interval: Duration) {
    scheduler::run(scheduler::ticks(interval), || recover_jobs(state.clone())).await;
}
