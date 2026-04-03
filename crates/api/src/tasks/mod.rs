use anyhow::{anyhow, Context};
use async_trait::async_trait;
use aws_sdk_scheduler::{
    error::{DisplayErrorContext, SdkError},
    operation::create_schedule::CreateScheduleError,
    types::{ActionAfterCompletion, FlexibleTimeWindow, FlexibleTimeWindowMode, Target},
};
use aws_smithy_http_client::{
    tls::{self, rustls_provider::CryptoMode},
    Builder as AwsHttpClientBuilder,
};
use services::tasks::{
    daily_cleanup_canceled_instances_request, dispatch_task, ScheduleSpec, ScheduledTaskRequest,
    TaskExecutor, TaskId, TaskMessage, TaskPayload, TaskScheduler,
};
use std::sync::Arc;
use tokio::{
    sync::Semaphore,
    time::{sleep, Duration},
};

const SQS_RECEIVE_RETRY_DELAY: Duration = Duration::from_secs(5);
const SQS_IDLE_HEARTBEAT_INTERVAL_POLLS: u64 = 3;

struct ScheduleRequestParts {
    target: Target,
    expression: String,
    flex_window: FlexibleTimeWindow,
    delete_after_completion: bool,
}

enum CreateScheduleOutcome {
    Created,
    Conflict(Box<ScheduleRequestParts>),
}

fn is_conflict_error(err: &SdkError<CreateScheduleError>) -> bool {
    matches!(
        err,
        SdkError::ServiceError(service_error)
            if matches!(service_error.err(), CreateScheduleError::ConflictException(_))
    )
}

fn format_aws_sdk_error<E, R>(err: &SdkError<E, R>) -> String
where
    E: std::error::Error + Send + Sync + 'static,
    R: std::fmt::Debug + Send + Sync + 'static,
{
    DisplayErrorContext(err).to_string()
}

pub async fn load_aws_sdk_config(region: String) -> aws_config::SdkConfig {
    let http_client = AwsHttpClientBuilder::new()
        .tls_provider(tls::Provider::Rustls(CryptoMode::AwsLc))
        .build_https();

    aws_config::defaults(aws_config::BehaviorVersion::latest())
        .http_client(http_client)
        .region(aws_config::Region::new(region))
        .load()
        .await
}

#[derive(Clone)]
pub struct AwsTaskScheduler {
    client: aws_sdk_scheduler::Client,
    scheduler_group: String,
    queue_arn: String,
    scheduler_role_arn: String,
}

impl AwsTaskScheduler {
    pub fn new(
        client: aws_sdk_scheduler::Client,
        scheduler_group: String,
        queue_arn: String,
        scheduler_role_arn: String,
    ) -> Self {
        Self {
            client,
            scheduler_group,
            queue_arn,
            scheduler_role_arn,
        }
    }

    fn build_target(&self, request: &ScheduledTaskRequest) -> anyhow::Result<Target> {
        let input = serde_json::to_string(&request.to_message())
            .context("failed to serialize scheduled task message")?;

        Target::builder()
            .arn(&self.queue_arn)
            .role_arn(&self.scheduler_role_arn)
            .input(input)
            .build()
            .map_err(|e| anyhow!("failed to build scheduler target: {}", e))
    }

    fn prepare_schedule_request_parts(
        &self,
        request: &ScheduledTaskRequest,
    ) -> anyhow::Result<ScheduleRequestParts> {
        let target = self.build_target(request)?;
        let expression = request.schedule.to_aws_expression();
        let flex_window = FlexibleTimeWindow::builder()
            .mode(FlexibleTimeWindowMode::Off)
            .build()
            .map_err(|e| anyhow!("failed to build flexible time window: {}", e))?;

        Ok(ScheduleRequestParts {
            target,
            expression,
            flex_window,
            delete_after_completion: matches!(request.schedule, ScheduleSpec::At(_)),
        })
    }

    async fn try_create_schedule(
        &self,
        request: &ScheduledTaskRequest,
    ) -> anyhow::Result<CreateScheduleOutcome> {
        let parts = self.prepare_schedule_request_parts(request)?;

        let mut create = self
            .client
            .create_schedule()
            .name(request.task_id.as_str())
            .group_name(&self.scheduler_group)
            .schedule_expression(&parts.expression)
            .flexible_time_window(parts.flex_window.clone())
            .target(parts.target.clone());

        if parts.delete_after_completion {
            create = create.action_after_completion(ActionAfterCompletion::Delete);
        }

        match create.send().await {
            Ok(_) => Ok(CreateScheduleOutcome::Created),
            Err(err) if is_conflict_error(&err) => {
                Ok(CreateScheduleOutcome::Conflict(Box::new(parts)))
            }
            Err(err) => Err(anyhow!(
                "failed to create schedule for task_id={}: {}",
                request.task_id,
                format_aws_sdk_error(&err)
            )),
        }
    }

    pub async fn create_task_if_absent(&self, request: ScheduledTaskRequest) -> anyhow::Result<()> {
        request.validate()?;

        match self.try_create_schedule(&request).await? {
            CreateScheduleOutcome::Created => {
                tracing::info!(
                    "created schedule task_id={} group={}",
                    request.task_id,
                    self.scheduler_group
                );
                Ok(())
            }
            CreateScheduleOutcome::Conflict(_) => {
                tracing::info!(
                    "schedule already exists, skipping create task_id={} group={}",
                    request.task_id,
                    self.scheduler_group
                );
                Ok(())
            }
        }
    }
}

#[async_trait]
impl TaskScheduler for AwsTaskScheduler {
    async fn upsert_task(&self, request: ScheduledTaskRequest) -> anyhow::Result<()> {
        request.validate()?;

        match self.try_create_schedule(&request).await? {
            CreateScheduleOutcome::Created => {
                tracing::info!(
                    "created schedule task_id={} group={}",
                    request.task_id,
                    self.scheduler_group
                );
                Ok(())
            }
            CreateScheduleOutcome::Conflict(parts) => {
                let mut update = self
                    .client
                    .update_schedule()
                    .name(request.task_id.as_str())
                    .group_name(&self.scheduler_group)
                    .schedule_expression(&parts.expression)
                    .flexible_time_window(parts.flex_window)
                    .target(parts.target);

                if parts.delete_after_completion {
                    update = update.action_after_completion(ActionAfterCompletion::Delete);
                }

                update.send().await.map_err(|e| {
                    anyhow!(
                        "failed to update existing schedule for task_id={}: {}",
                        request.task_id,
                        format_aws_sdk_error(&e)
                    )
                })?;
                tracing::info!(
                    "updated schedule task_id={} group={}",
                    request.task_id,
                    self.scheduler_group
                );
                Ok(())
            }
        }
    }

    async fn delete_task(&self, task_id: &TaskId) -> anyhow::Result<()> {
        self.client
            .delete_schedule()
            .name(task_id.as_str())
            .group_name(&self.scheduler_group)
            .send()
            .await
            .map_err(|e| {
                anyhow!(
                    "failed to delete schedule task_id={}: {}",
                    task_id,
                    format_aws_sdk_error(&e)
                )
            })?;
        Ok(())
    }
}

pub struct AwsSqsTaskWorker<E: TaskExecutor + 'static> {
    client: aws_sdk_sqs::Client,
    queue_url: String,
    max_concurrency: usize,
    wait_seconds: i32,
    visibility_timeout: i32,
    max_messages: i32,
    executor: Arc<E>,
}

impl<E: TaskExecutor + 'static> AwsSqsTaskWorker<E> {
    pub fn new(
        client: aws_sdk_sqs::Client,
        queue_url: String,
        max_concurrency: usize,
        wait_seconds: i32,
        visibility_timeout: i32,
        max_messages: i32,
        executor: Arc<E>,
    ) -> Self {
        Self {
            client,
            queue_url,
            max_concurrency,
            wait_seconds,
            visibility_timeout,
            max_messages,
            executor,
        }
    }

    pub async fn run_forever(&self) -> anyhow::Result<()> {
        let max_concurrency = self.max_concurrency.max(1);
        let semaphore = Arc::new(Semaphore::new(max_concurrency));
        let max_number_of_messages = self
            .max_messages
            .clamp(1, 10)
            .min(max_concurrency.min(10) as i32);
        let wait_seconds = self.wait_seconds.clamp(1, 20);
        let visibility_timeout = self.visibility_timeout.max(1);
        let mut consecutive_empty_polls = 0u64;

        tracing::info!(
            "starting SQS polling queue_url={} wait_seconds={} max_messages={} visibility_timeout={} max_concurrency={}",
            self.queue_url,
            wait_seconds,
            max_number_of_messages,
            visibility_timeout,
            max_concurrency
        );

        loop {
            let response = match self
                .client
                .receive_message()
                .queue_url(&self.queue_url)
                .max_number_of_messages(max_number_of_messages)
                .wait_time_seconds(wait_seconds)
                .visibility_timeout(visibility_timeout)
                .send()
                .await
            {
                Ok(response) => response,
                Err(err) => {
                    consecutive_empty_polls = 0;
                    tracing::warn!(
                        "failed to receive SQS messages queue_url={} retrying_in={}s err={}",
                        self.queue_url,
                        SQS_RECEIVE_RETRY_DELAY.as_secs(),
                        format_aws_sdk_error(&err)
                    );
                    sleep(SQS_RECEIVE_RETRY_DELAY).await;
                    continue;
                }
            };

            let messages = response.messages();
            if messages.is_empty() {
                consecutive_empty_polls += 1;

                if consecutive_empty_polls == 1
                    || consecutive_empty_polls.is_multiple_of(SQS_IDLE_HEARTBEAT_INTERVAL_POLLS)
                {
                    tracing::debug!(
                        "SQS poll returned no messages queue_url={} empty_polls={} wait_seconds={}",
                        self.queue_url,
                        consecutive_empty_polls,
                        wait_seconds
                    );
                }
            } else {
                consecutive_empty_polls = 0;
                tracing::info!(
                    "received {} SQS message(s) queue_url={}",
                    messages.len(),
                    self.queue_url
                );
            }

            for message in messages {
                let permit = semaphore.clone().acquire_owned().await?;
                let client = self.client.clone();
                let queue_url = self.queue_url.clone();
                let executor = self.executor.clone();
                let message = message.clone();

                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(err) = process_message(client, queue_url, executor, message).await {
                        tracing::error!("task processing failed: {}", err);
                    }
                });
            }
        }
    }
}

async fn delete_message(
    client: &aws_sdk_sqs::Client,
    queue_url: &str,
    receipt_handle: &str,
) -> anyhow::Result<()> {
    client
        .delete_message()
        .queue_url(queue_url)
        .receipt_handle(receipt_handle)
        .send()
        .await
        .map_err(|err| {
            anyhow!(
                "failed to delete SQS message: {}",
                format_aws_sdk_error(&err)
            )
        })?;

    Ok(())
}

enum ParsedSqsMessage {
    Task(TaskMessage),
    Drop { reason: String },
}

fn parse_sqs_message(message: &aws_sdk_sqs::types::Message) -> ParsedSqsMessage {
    let body = match message.body() {
        Some(body) => body,
        None => {
            return ParsedSqsMessage::Drop {
                reason: "SQS message missing body".to_string(),
            };
        }
    };

    match parse_task_message(body) {
        Ok(task_message) => ParsedSqsMessage::Task(task_message),
        Err(err) => ParsedSqsMessage::Drop {
            reason: err.to_string(),
        },
    }
}

async fn process_message<E: TaskExecutor + 'static>(
    client: aws_sdk_sqs::Client,
    queue_url: String,
    executor: Arc<E>,
    message: aws_sdk_sqs::types::Message,
) -> anyhow::Result<()> {
    let receipt_handle = message.receipt_handle().map(str::to_owned);

    let task_message = match parse_sqs_message(&message) {
        ParsedSqsMessage::Task(task_message) => task_message,
        ParsedSqsMessage::Drop { reason } => {
            tracing::warn!("dropping invalid SQS task message: {}", reason);
            if let Some(receipt_handle) = receipt_handle.as_deref() {
                delete_message(&client, &queue_url, receipt_handle).await?;
            }
            return Ok(());
        }
    };

    tracing::debug!(
        "task message received task_id={} payload={:?}",
        task_message.task_id,
        task_message.payload
    );

    // Extend visibility timeout for delete tasks — the external agent-manager delete call
    // can take several seconds under load, so we give it up to 5 minutes before
    // SQS would redeliver the message to another worker.
    if matches!(
        task_message.payload,
        TaskPayload::CleanupCanceledInstances(_)
    ) {
        if let Some(receipt_handle) = receipt_handle.as_deref() {
            client
                .change_message_visibility()
                .queue_url(&queue_url)
                .receipt_handle(receipt_handle)
                .visibility_timeout(300) // 5 minutes
                .send()
                .await
                .map_err(|err| {
                    anyhow!(
                        "failed to extend visibility timeout for cleanup task: {}",
                        format_aws_sdk_error(&err)
                    )
                })?;
            tracing::info!(
                "extended visibility timeout for task_id={}",
                task_message.task_id
            );
        }
    }

    dispatch_task(executor.as_ref(), &task_message.payload)
        .await
        .with_context(|| {
            format!(
                "task handler execution failed task_id={}",
                task_message.task_id
            )
        })?;

    tracing::info!("task completed task_id={}", task_message.task_id);

    if let Some(receipt_handle) = receipt_handle.as_deref() {
        delete_message(&client, &queue_url, receipt_handle).await?;
        tracing::info!("SQS message deleted for task_id={}", task_message.task_id);
    }

    Ok(())
}

fn parse_task_message(body: &str) -> anyhow::Result<TaskMessage> {
    serde_json::from_str(body).context("failed to parse task message")
}

pub async fn ensure_daily_cleanup_task(task_config: &config::TaskConfig) -> anyhow::Result<()> {
    if !task_config.enabled {
        return Ok(());
    }

    if !task_config.is_scheduler_configured() {
        return Err(anyhow!(
            "tasks scheduler is not configured: TASKS_SQS_QUEUE_ARN and TASKS_SCHEDULER_ROLE_ARN are required"
        ));
    }

    let region = task_config
        .aws_region
        .clone()
        .ok_or_else(|| anyhow!("AWS_REGION is required for scheduler"))?;
    let queue_arn = task_config
        .sqs_queue_arn
        .clone()
        .ok_or_else(|| anyhow!("TASKS_SQS_QUEUE_ARN is required"))?;
    let scheduler_role_arn = task_config
        .scheduler_role_arn
        .clone()
        .ok_or_else(|| anyhow!("TASKS_SCHEDULER_ROLE_ARN is required"))?;

    let aws_config = load_aws_sdk_config(region).await;

    let scheduler = AwsTaskScheduler::new(
        aws_sdk_scheduler::Client::new(&aws_config),
        task_config.scheduler_group.clone(),
        queue_arn,
        scheduler_role_arn,
    );

    scheduler
        .upsert_task(daily_cleanup_canceled_instances_request(
            task_config.cleanup_canceled_instances_daily_cron.clone(),
            task_config.cleanup_canceled_instances_grace_days,
        )?)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use services::tasks::{
        CleanupCanceledInstancesTaskPayload, NoopTaskPayload, TaskId, TaskPayload,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestExecutor {
        noop_calls: AtomicUsize,
        cleanup_calls: AtomicUsize,
        fail_noop: bool,
    }

    #[async_trait]
    impl TaskExecutor for TestExecutor {
        async fn execute_noop(&self, _: &NoopTaskPayload) -> anyhow::Result<()> {
            self.noop_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_noop {
                anyhow::bail!("noop failed");
            }
            Ok(())
        }

        async fn execute_cleanup_canceled_instances(
            &self,
            _: &CleanupCanceledInstancesTaskPayload,
        ) -> anyhow::Result<()> {
            self.cleanup_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn test_parse_task_message_success() {
        let body = r#"{
            "task_id":"daily_cleanup",
            "payload":{"task_type":"noop","payload":{"note":"ok"}}
        }"#;
        let message = parse_task_message(body).unwrap();
        assert_eq!(message.task_id.as_str(), "daily_cleanup");
        match message.payload {
            TaskPayload::Noop(payload) => assert_eq!(payload.note.as_deref(), Some("ok")),
            TaskPayload::CleanupCanceledInstances(_) => panic!("unexpected payload variant"),
        }
    }

    #[test]
    fn test_parse_task_message_invalid_json() {
        let body = r#"{"task_id":"bad","payload":{"task_type":"unknown"}}"#;
        assert!(parse_task_message(body).is_err());
    }

    #[test]
    fn test_parse_sqs_message_drops_missing_body() {
        let message = aws_sdk_sqs::types::Message::builder()
            .receipt_handle("receipt")
            .build();

        match parse_sqs_message(&message) {
            ParsedSqsMessage::Drop { reason } => {
                assert!(reason.contains("missing body"));
            }
            ParsedSqsMessage::Task(_) => panic!("expected drop for missing body"),
        }
    }

    #[test]
    fn test_parse_sqs_message_drops_invalid_json() {
        let message = aws_sdk_sqs::types::Message::builder()
            .body(r#"{"task_id":"bad","payload":{"task_type":"unknown"}}"#)
            .receipt_handle("receipt")
            .build();

        match parse_sqs_message(&message) {
            ParsedSqsMessage::Drop { reason } => {
                assert!(reason.contains("failed to parse task message"));
            }
            ParsedSqsMessage::Task(_) => panic!("expected drop for invalid JSON"),
        }
    }

    #[test]
    fn test_parse_sqs_message_parses_valid_message() {
        let message = aws_sdk_sqs::types::Message::builder()
            .body(
                r#"{
                    "task_id":"daily_cleanup",
                    "payload":{"task_type":"noop","payload":{"note":"ok"}}
                }"#,
            )
            .receipt_handle("receipt")
            .build();

        match parse_sqs_message(&message) {
            ParsedSqsMessage::Task(task_message) => {
                assert_eq!(task_message.task_id.as_str(), "daily_cleanup");
            }
            ParsedSqsMessage::Drop { .. } => panic!("expected parsed task message"),
        }
    }

    #[tokio::test]
    async fn test_dispatch_task_error_bubbles_up() {
        let executor = TestExecutor {
            noop_calls: AtomicUsize::new(0),
            cleanup_calls: AtomicUsize::new(0),
            fail_noop: true,
        };
        let payload = TaskPayload::Noop(NoopTaskPayload { note: None });
        let result = dispatch_task(&executor, &payload).await;
        assert!(result.is_err());
        assert_eq!(executor.noop_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_dispatch_cleanup_hits_expected_handler() {
        let executor = TestExecutor {
            noop_calls: AtomicUsize::new(0),
            cleanup_calls: AtomicUsize::new(0),
            fail_noop: false,
        };
        let payload = TaskPayload::CleanupCanceledInstances(CleanupCanceledInstancesTaskPayload {
            grace_days: 15,
            dry_run: true,
        });
        dispatch_task(&executor, &payload).await.unwrap();
        assert_eq!(executor.noop_calls.load(Ordering::SeqCst), 0);
        assert_eq!(executor.cleanup_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_task_message_roundtrip_json() {
        let msg = TaskMessage {
            task_id: TaskId::new("roundtrip_1".to_string()).unwrap(),
            payload: TaskPayload::Noop(NoopTaskPayload {
                note: Some("hello".to_string()),
            }),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: TaskMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.task_id.as_str(), "roundtrip_1");
    }

    #[tokio::test]
    async fn test_ensure_daily_cleanup_task_noop_when_disabled() {
        let cfg = config::TaskConfig {
            enabled: false,
            ..Default::default()
        };
        assert!(ensure_daily_cleanup_task(&cfg).await.is_ok());
    }

    #[tokio::test]
    async fn test_ensure_daily_cleanup_task_requires_scheduler_config() {
        let cfg = config::TaskConfig {
            enabled: true,
            aws_region: Some("us-east-1".to_string()),
            ..Default::default()
        };
        let err = ensure_daily_cleanup_task(&cfg).await.unwrap_err();
        assert!(err
            .to_string()
            .contains("TASKS_SQS_QUEUE_ARN and TASKS_SCHEDULER_ROLE_ARN are required"));
    }
}
