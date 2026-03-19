use anyhow::{anyhow, Context};
use async_trait::async_trait;
use services::jobs::{CleanupCanceledInstancesTaskPayload, NoopTaskPayload, TaskExecutor};
use std::sync::Arc;

struct DefaultTaskExecutor;

#[async_trait]
impl TaskExecutor for DefaultTaskExecutor {
    async fn execute_noop(&self, payload: &NoopTaskPayload) -> anyhow::Result<()> {
        tracing::info!("noop task received: note={:?}", payload.note);
        Ok(())
    }

    async fn execute_cleanup_canceled_instances(
        &self,
        payload: &CleanupCanceledInstancesTaskPayload,
    ) -> anyhow::Result<()> {
        Err(anyhow!(
            "cleanup_canceled_instances is not implemented yet (grace_days={}, dry_run={})",
            payload.grace_days,
            payload.dry_run
        ))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if let Err(e) = dotenvy::dotenv() {
        eprintln!("Warning: Could not load .env file: {e}");
        eprintln!("Continuing with environment variables...");
    }

    let config = config::Config::from_env();
    let tasks = config.tasks;

    if !tasks.enabled {
        return Err(anyhow!(
            "task worker is disabled: set TASKS_ENABLED=true to run"
        ));
    }

    let region = tasks
        .aws_region
        .clone()
        .ok_or_else(|| anyhow!("TASKS_AWS_REGION or AWS_REGION is required"))?;

    let queue_url = tasks
        .sqs_queue_url
        .clone()
        .ok_or_else(|| anyhow!("TASKS_SQS_QUEUE_URL is required"))?;

    let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_sdk_sqs::config::Region::new(region))
        .load()
        .await;

    let sqs_client = aws_sdk_sqs::Client::new(&aws_config);
    let executor = Arc::new(DefaultTaskExecutor);

    let worker = api::tasks::AwsSqsTaskWorker::new(
        sqs_client,
        queue_url,
        tasks.worker_max_concurrency,
        tasks.worker_wait_seconds,
        tasks.worker_visibility_timeout,
        tasks.worker_max_messages,
        executor,
    );

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    worker
        .run_forever()
        .await
        .context("task worker loop exited unexpectedly")
}
