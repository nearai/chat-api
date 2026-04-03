use anyhow::{anyhow, Context};
use async_trait::async_trait;
use aws_smithy_http_client::{
    tls::{self, rustls_provider::CryptoMode},
    Builder as AwsHttpClientBuilder,
};
use axum::{routing::get, Json, Router};
use chrono::{Duration, Utc};
use serde::Serialize;
use services::tasks::{CleanupCanceledInstancesTaskPayload, NoopTaskPayload, TaskExecutor};
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
                break;
            }

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
                    if let Err(err) = self.agent_service.delete_instance(instance.id).await {
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
        .sqs_queue_url
        .clone()
        .ok_or_else(|| anyhow!("TASKS_SQS_QUEUE_URL is required"))?;

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

    let http_client = AwsHttpClientBuilder::new()
        .tls_provider(tls::Provider::Rustls(CryptoMode::AwsLc))
        .build_https();

    let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .http_client(http_client)
        .region(aws_sdk_sqs::config::Region::new(region))
        .load()
        .await;

    let sqs_client = aws_sdk_sqs::Client::new(&aws_config);
    let executor = Arc::new(DefaultTaskExecutor {
        db_pool: db.pool().clone(),
        agent_service,
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
            .with_graceful_shutdown(async { let _ = shutdown_rx.await; })
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
