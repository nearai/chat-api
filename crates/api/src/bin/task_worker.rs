use anyhow::{anyhow, Context};
use async_trait::async_trait;
use axum::{routing::get, Json, Router};
use chrono::{Duration, Utc};
use serde::Serialize;
use services::conversation::ports::ConversationService;
use services::response::service::OpenAIProxy;
use services::tasks::{
    AccountDeletionTaskPayload, CleanupCanceledInstancesTaskPayload, NoopTaskPayload, TaskExecutor,
};
use services::user::ports::{AccountDeletionError, AccountDeletionStatus, UserRepository};
use services::vpc::{initialize_vpc_credentials, VpcAuthConfig};
use services::{agent::ports::AgentService, UserId};
use std::sync::Arc;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

struct DefaultTaskExecutor {
    db_pool: database::DbPool,
    agent_service: Arc<dyn AgentService>,
    user_repository: Arc<dyn UserRepository>,
    conversation_service: Arc<dyn ConversationService>,
}

const ACCOUNT_DELETION_LEASE_SECONDS: i64 = 300;
const MAX_ACCOUNT_DELETION_ATTEMPTS: i32 = 5;

fn progress_deleted_conversation_ids(progress: &serde_json::Value) -> Vec<String> {
    progress
        .get("cloud_deleted_conversation_ids")
        .and_then(|v| v.as_array())
        .map(|ids| {
            ids.iter()
                .filter_map(|id| id.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn build_account_deletion_progress(ids: &[String]) -> serde_json::Value {
    serde_json::json!({
        "cloud_deleted_conversation_ids": ids,
    })
}

#[async_trait]
impl TaskExecutor for DefaultTaskExecutor {
    async fn execute_noop(&self, _payload: &NoopTaskPayload) -> anyhow::Result<()> {
        tracing::info!("noop task received");
        Ok(())
    }

    async fn execute_cleanup_canceled_instances(
        &self,
        payload: &CleanupCanceledInstancesTaskPayload,
    ) -> anyhow::Result<()> {
        if payload.grace_days < 0 {
            return Err(anyhow!("grace_days must be >= 0"));
        }

        tracing::info!(
            "cleanup task started grace_days={} dry_run={}",
            payload.grace_days,
            payload.dry_run
        );

        let cutoff = Utc::now() - Duration::days(payload.grace_days);
        let mut offset: i64 = 0;
        let batch_size: i64 = 200;
        let mut total_users = 0usize;
        let mut total_instances = 0usize;
        let mut failed_instances = 0usize;

        loop {
            let client = self
                .db_pool
                .get()
                .await
                .context("failed to get DB client")?;
            let rows = client
                .query(
                    "SELECT DISTINCT s.user_id
                     FROM subscriptions s
                     WHERE s.status = 'canceled'
                       AND s.current_period_end <= $1
                       AND NOT EXISTS (
                           SELECT 1
                           FROM subscriptions active_sub
                           WHERE active_sub.user_id = s.user_id
                             AND active_sub.status IN ('active', 'trialing')
                       )
                     ORDER BY s.user_id
                     LIMIT $2 OFFSET $3",
                    &[&cutoff, &batch_size, &offset],
                )
                .await
                .context("failed to query canceled users for cleanup")?;

            if rows.is_empty() {
                tracing::info!(
                    "cleanup task: no more canceled users found after offset={}",
                    offset
                );
                break;
            }

            tracing::info!(
                "cleanup task: batch found {} canceled users offset={}",
                rows.len(),
                offset
            );

            for row in &rows {
                let user_id: UserId = row.get("user_id");
                total_users += 1;

                let (instances, _) = match self.agent_service.list_instances(user_id, 1000, 0).await
                {
                    Ok(result) => result,
                    Err(err) => {
                        tracing::error!(
                            "cleanup task: failed to list instances user_id={} err={}",
                            user_id,
                            err
                        );
                        continue;
                    }
                };

                let mut cleanup_targets = instances
                    .into_iter()
                    .filter(|instance| instance.status != "deleted")
                    .collect::<Vec<_>>();
                total_instances += cleanup_targets.len();

                if payload.dry_run {
                    for instance in &cleanup_targets {
                        tracing::info!(
                            "cleanup task dry-run: would delete instance_id={} user_id={} status={}",
                            instance.id,
                            user_id,
                            instance.status
                        );
                    }
                    continue;
                }

                for instance in cleanup_targets.drain(..) {
                    if let Err(err) = self
                        .agent_service
                        .delete_instance(
                            instance.id,
                            None,
                            "cleanup_task_cancelled_user_after_grace_period",
                        )
                        .await
                    {
                        failed_instances += 1;
                        tracing::error!(
                            "cleanup task: delete failed instance_id={} user_id={} status={} err={}",
                            instance.id,
                            user_id,
                            instance.status,
                            err
                        );
                    } else {
                        tracing::info!(
                            "cleanup task: deleted instance_id={} user_id={} previous_status={}",
                            instance.id,
                            user_id,
                            instance.status
                        );
                    }
                }
            }

            offset += rows.len() as i64;
            if rows.len() < batch_size as usize {
                break;
            }
        }

        tracing::info!(
            "cleanup task finished grace_days={} dry_run={} users_scanned={} instances_targeted={} delete_failures={}",
            payload.grace_days,
            payload.dry_run,
            total_users,
            total_instances,
            failed_instances
        );

        if failed_instances > 0 {
            return Err(anyhow!(
                "cleanup completed with {} failed instance deletions",
                failed_instances
            ));
        }

        Ok(())
    }

    async fn execute_account_deletion(
        &self,
        payload: &AccountDeletionTaskPayload,
    ) -> anyhow::Result<()> {
        let Some(existing) = self
            .user_repository
            .get_account_deletion(payload.deletion_id)
            .await
            .context("failed to load account deletion request")?
        else {
            tracing::info!(
                "account deletion task has no matching request, dropping deletion_id={}",
                payload.deletion_id
            );
            return Ok(());
        };

        if existing.status == AccountDeletionStatus::Completed {
            tracing::info!(
                "account deletion already completed deletion_id={} user_id={}",
                existing.id,
                existing.user_id
            );
            return Ok(());
        }

        if existing.status == AccountDeletionStatus::FailedNeedsReview {
            tracing::warn!(
                "account deletion requires manual review, dropping task deletion_id={} user_id={}",
                existing.id,
                existing.user_id
            );
            return Ok(());
        }

        let Some(request) = self
            .user_repository
            .claim_account_deletion(payload.deletion_id, ACCOUNT_DELETION_LEASE_SECONDS)
            .await
            .context("failed to claim account deletion request")?
        else {
            tracing::info!(
                "account deletion request is currently leased by another worker deletion_id={}",
                payload.deletion_id
            );
            return Ok(());
        };

        tracing::warn!(
            "account deletion worker started deletion_id={} user_id={} attempt={}",
            request.id,
            request.user_id,
            request.attempt_count
        );

        if request.attempt_count > MAX_ACCOUNT_DELETION_ATTEMPTS {
            let last_error = format!(
                "max deletion retry attempts exceeded (attempt_count={}, max={})",
                request.attempt_count, MAX_ACCOUNT_DELETION_ATTEMPTS
            );
            self.user_repository
                .mark_account_deletion_failed_needs_review(
                    request.id,
                    last_error.clone(),
                    request.progress.clone(),
                )
                .await
                .context("failed to mark account deletion as failed_needs_review")?;
            tracing::warn!(
                "account deletion moved to failed_needs_review deletion_id={} user_id={} reason={}",
                request.id,
                request.user_id,
                last_error
            );
            return Ok(());
        }

        let mut cloud_deleted_conversation_ids =
            progress_deleted_conversation_ids(&request.progress);
        let mut cloud_deleted_set = cloud_deleted_conversation_ids
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>();

        let conversation_ids = self
            .user_repository
            .list_owned_conversation_ids(request.user_id)
            .await
            .context("failed to list account conversations")?;

        for conversation_id in conversation_ids {
            if cloud_deleted_set.contains(&conversation_id) {
                continue;
            }

            if let Err(err) = self
                .conversation_service
                .delete_conversation_from_provider(&conversation_id)
                .await
            {
                let progress = build_account_deletion_progress(&cloud_deleted_conversation_ids);
                let last_error =
                    format!("failed to delete cloud conversation {conversation_id}: {err}");
                self.user_repository
                    .mark_account_deletion_retrying(request.id, last_error.clone(), progress)
                    .await
                    .context("failed to mark account deletion retrying")?;
                anyhow::bail!(last_error);
            }

            cloud_deleted_set.insert(conversation_id.clone());
            cloud_deleted_conversation_ids.push(conversation_id);
            self.user_repository
                .update_account_deletion_progress(
                    request.id,
                    build_account_deletion_progress(&cloud_deleted_conversation_ids),
                    ACCOUNT_DELETION_LEASE_SECONDS,
                )
                .await
                .context("failed to update account deletion progress")?;
        }

        match self
            .user_repository
            .delete_user_account(request.user_id, &cloud_deleted_conversation_ids)
            .await
        {
            Ok(()) | Err(AccountDeletionError::UserNotFound) => {
                self.user_repository
                    .mark_account_deletion_completed(request.id)
                    .await
                    .context("failed to mark account deletion completed")?;
                tracing::warn!(
                    "account deletion worker completed deletion_id={} user_id={}",
                    request.id,
                    request.user_id
                );
                Ok(())
            }
            Err(err) => {
                let progress = build_account_deletion_progress(&cloud_deleted_conversation_ids);
                let last_error = err.to_string();
                self.user_repository
                    .mark_account_deletion_retrying(request.id, last_error.clone(), progress)
                    .await
                    .context("failed to mark account deletion retrying after finalization error")?;
                Err(anyhow!(last_error))
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if let Err(e) = dotenvy::dotenv() {
        eprintln!("Warning: Could not load .env file: {e}");
        eprintln!("Continuing with environment variables...");
    }

    let config = config::Config::from_env();
    let tasks = config.tasks.clone();

    api::init_tracing_from_config(&config.logging);

    if !tasks.enabled {
        return Err(anyhow!(
            "task worker is disabled: set TASKS_ENABLED=true to run"
        ));
    }

    let region = tasks
        .aws_region
        .clone()
        .ok_or_else(|| anyhow!("AWS_REGION is required"))?;

    let queue_url = tasks
        .worker_sqs_queue_url()
        .cloned()
        .ok_or_else(|| anyhow!("SQS queue URL is required for selected TASKS_WORKER_QUEUE"))?;

    let db = database::Database::from_config(&config.database)
        .await
        .context("failed to connect database for task worker")?;

    let system_configs_service = Arc::new(
        services::system_configs::service::SystemConfigsServiceImpl::new(
            db.system_configs_repository()
                as Arc<dyn services::system_configs::ports::SystemConfigsRepository>,
        ),
    );

    let agent_service = Arc::new(services::agent::AgentServiceImpl::new(
        db.agent_repository() as Arc<dyn services::agent::ports::AgentRepository>,
        config.agent.managers.clone(),
        config.agent.nearai_api_url.clone(),
        system_configs_service as Arc<dyn services::system_configs::ports::SystemConfigsService>,
        config.agent.channel_relay_url.clone(),
        config.agent.non_tee_agent_url_pattern.clone(),
    ));

    let vpc_auth_config = if config.vpc_auth.is_configured() {
        let base_url = config.openai.base_url.as_ref().ok_or_else(|| {
            anyhow!("OPENAI_BASE_URL is required when VPC authentication is configured")
        })?;
        let shared_secret = config
            .vpc_auth
            .read_shared_secret()
            .ok_or_else(|| anyhow!("Failed to read VPC shared secret"))?;
        Some(VpcAuthConfig {
            client_id: config.vpc_auth.client_id.clone(),
            shared_secret,
            base_url: base_url.clone(),
        })
    } else {
        None
    };

    let static_api_key = if vpc_auth_config.is_none() {
        Some(config.openai.api_key.clone())
    } else {
        None
    };
    let vpc_credentials_service = initialize_vpc_credentials(
        vpc_auth_config,
        db.app_config_repository() as Arc<dyn services::vpc::VpcCredentialsRepository>,
        static_api_key,
    )
    .await?;

    let mut proxy_service = OpenAIProxy::new(vpc_credentials_service);
    if let Some(base_url) = config.openai.base_url.clone() {
        proxy_service = proxy_service.with_base_url(base_url);
    }
    let conversation_service = Arc::new(
        services::conversation::service::ConversationServiceImpl::new(
            db.conversation_repository(),
            Arc::new(proxy_service),
        ),
    );

    let aws_config = api::tasks::load_aws_sdk_config(region).await;

    let sqs_client = aws_sdk_sqs::Client::new(&aws_config);
    let executor = Arc::new(DefaultTaskExecutor {
        db_pool: db.pool().clone(),
        agent_service,
        user_repository: db.user_repository(),
        conversation_service,
    });

    let health_port = tasks.port;
    let addr = format!("{}:{health_port}", config.server.host);

    // Bind before spawning so port conflict causes a hard startup failure.
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("Failed to bind health server on {addr}"))?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        let app = Router::new().route("/health", get(health_check));
        tracing::info!("health server listening on http://{}", addr);
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            .ok();
    });

    let worker = api::tasks::AwsSqsTaskWorker::new(
        sqs_client,
        queue_url,
        tasks.worker_max_concurrency,
        tasks.worker_wait_seconds,
        tasks.worker_visibility_timeout,
        tasks.worker_max_messages,
        executor,
    );

    let result = worker
        .run_forever()
        .await
        .context("task worker loop exited unexpectedly");
    let _ = shutdown_tx.send(());
    result
}
