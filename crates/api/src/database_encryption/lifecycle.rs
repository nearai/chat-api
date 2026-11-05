use super::*;
pub(super) fn execute_writes_enabled(state: &AppState, fields: &[&Field]) -> bool {
    state.db_pool.field_encryption().is_some_and(|config| {
        config.write_enabled
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
             SET status='failed',
                 last_error_class=$2,
                 last_error_message=$3,
                 completed_at=NOW()
             WHERE id=$1 AND status IN ('queued','running')",
            &[&id, &error_class, &error_message],
        )
        .await?;
    Ok(())
}

pub async fn recover_jobs(state: AppState) {
    let Ok(client) = state.db_pool.get().await else {
        return;
    };
    let Ok(rows) = client.query("UPDATE database_encryption_jobs SET status='queued' WHERE status='running' RETURNING id", &[]).await else { return };
    let mut ids = rows
        .into_iter()
        .map(|row| row.get::<_, Uuid>(0))
        .collect::<Vec<_>>();
    if let Ok(rows) = client
        .query(
            "SELECT id FROM database_encryption_jobs WHERE status='queued' ORDER BY created_at",
            &[],
        )
        .await
    {
        ids.extend(rows.into_iter().map(|row| row.get::<_, Uuid>(0)));
    }
    ids.sort();
    ids.dedup();
    drop(client);
    for id in ids {
        let worker_state = state.clone();
        tokio::spawn(async move {
            let Ok(_permit) = worker().acquire().await else {
                return;
            };
            if let Err(_error) = run_job(&worker_state, id).await {
                tracing::error!(job_id=%id,error_class="database_encryption_recovered_job_failed","Recovered database encryption job failed");
                let _ = mark_job_failed(&worker_state, id, "batch_failed", "batch_failed").await;
            }
        });
    }
}
