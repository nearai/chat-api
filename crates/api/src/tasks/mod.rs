use anyhow::{anyhow, Context};
use async_trait::async_trait;
use aws_sdk_scheduler::types::{
    ActionAfterCompletion, FlexibleTimeWindow, FlexibleTimeWindowMode, Target,
};
use services::jobs::{
    dispatch_task, ScheduledTaskRequest, ScheduleSpec, TaskExecutor, TaskId, TaskScheduler,
    TaskMessage,
};
use std::sync::Arc;
use tokio::sync::Semaphore;

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
}

#[async_trait]
impl TaskScheduler for AwsTaskScheduler {
    async fn upsert_task(&self, request: ScheduledTaskRequest) -> anyhow::Result<()> {
        request.validate()?;

        let target = self.build_target(&request)?;
        let expression = request.schedule.to_aws_expression();
        let flex_window = FlexibleTimeWindow::builder()
            .mode(FlexibleTimeWindowMode::Off)
            .build()
            .map_err(|e| anyhow!("failed to build flexible time window: {}", e))?;

        let mut create = self
            .client
            .create_schedule()
            .name(request.task_id.as_str())
            .group_name(&self.scheduler_group)
            .schedule_expression(&expression)
            .flexible_time_window(flex_window.clone())
            .target(target.clone());

        if matches!(request.schedule, ScheduleSpec::At(_)) {
            create = create.action_after_completion(ActionAfterCompletion::Delete);
        }

        match create.send().await {
            Ok(_) => Ok(()),
            Err(err) => {
                let err_text = err.to_string();
                if err_text.contains("ConflictException") || err_text.contains("already exists") {
                    let mut update = self
                        .client
                        .update_schedule()
                        .name(request.task_id.as_str())
                        .group_name(&self.scheduler_group)
                        .schedule_expression(&expression)
                        .flexible_time_window(flex_window)
                        .target(target);

                    if matches!(request.schedule, ScheduleSpec::At(_)) {
                        update = update.action_after_completion(ActionAfterCompletion::Delete);
                    }

                    update.send().await.map_err(|e| {
                        anyhow!(
                            "failed to update existing schedule for task_id={}: {}",
                            request.task_id,
                            e
                        )
                    })?;
                    Ok(())
                } else {
                    Err(anyhow!(
                        "failed to create schedule for task_id={}: {}",
                        request.task_id,
                        err
                    ))
                }
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
            .map_err(|e| anyhow!("failed to delete schedule task_id={}: {}", task_id, e))?;
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
        let semaphore = Arc::new(Semaphore::new(self.max_concurrency.max(1)));

        loop {
            let response = self
                .client
                .receive_message()
                .queue_url(&self.queue_url)
                .max_number_of_messages(self.max_messages.clamp(1, 10))
                .wait_time_seconds(self.wait_seconds.clamp(1, 20))
                .visibility_timeout(self.visibility_timeout.max(1))
                .send()
                .await
                .context("failed to receive SQS messages")?;

            for message in response.messages() {
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

async fn process_message<E: TaskExecutor + 'static>(
    client: aws_sdk_sqs::Client,
    queue_url: String,
    executor: Arc<E>,
    message: aws_sdk_sqs::types::Message,
) -> anyhow::Result<()> {
    let body = message
        .body()
        .ok_or_else(|| anyhow!("SQS message missing body"))?;

    let task_message = parse_task_message(body)?;

    dispatch_task(executor.as_ref(), &task_message.payload)
        .await
        .context("task handler execution failed")?;

    if let Some(receipt_handle) = message.receipt_handle() {
        client
            .delete_message()
            .queue_url(queue_url)
            .receipt_handle(receipt_handle)
            .send()
            .await
            .context("failed to delete SQS message")?;
    }

    Ok(())
}

fn parse_task_message(body: &str) -> anyhow::Result<TaskMessage> {
    serde_json::from_str(body).context("failed to parse task message")
}

#[cfg(test)]
mod tests {
    use super::*;
    use services::jobs::{
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
}
