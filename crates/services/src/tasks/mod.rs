use anyhow::anyhow;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct TaskId(String);

impl TaskId {
    pub fn new(value: String) -> anyhow::Result<Self> {
        let is_valid = !value.is_empty()
            && value.len() <= 64
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));

        if !is_valid {
            return Err(anyhow!(
                "invalid task id: expected 1-64 chars [A-Za-z0-9._-]"
            ));
        }

        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for TaskId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        TaskId::new(value).map_err(D::Error::custom)
    }
}

impl std::fmt::Display for TaskId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleSpec {
    At(DateTime<Utc>),
    Cron(String),
}

impl ScheduleSpec {
    pub fn validate(&self) -> anyhow::Result<()> {
        match self {
            Self::At(_) => Ok(()),
            Self::Cron(expr) => {
                let trimmed = expr.trim();
                if trimmed.starts_with("cron(") && trimmed.ends_with(')') && trimmed.len() > 6 {
                    Ok(())
                } else {
                    Err(anyhow!(
                        "invalid cron expression: expected format cron(...)"
                    ))
                }
            }
        }
    }

    pub fn to_aws_expression(&self) -> String {
        match self {
            Self::At(at) => format!("at({})", at.format("%Y-%m-%dT%H:%M:%S")),
            Self::Cron(expr) => expr.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NoopTaskPayload {
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CleanupCanceledInstancesTaskPayload {
    pub grace_days: i64,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountDeletionTaskPayload {
    pub deletion_id: Uuid,
}

pub const CLEANUP_CANCELED_INSTANCES_DAILY_CRON_UTC: &str = "cron(0 0 * * ? *)";
pub const CLEANUP_CANCELED_INSTANCES_DEFAULT_GRACE_DAYS: i64 = 15;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "task_type", content = "payload", rename_all = "snake_case")]
pub enum TaskPayload {
    Noop(NoopTaskPayload),
    CleanupCanceledInstances(CleanupCanceledInstancesTaskPayload),
    AccountDeletion(AccountDeletionTaskPayload),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskMessage {
    pub task_id: TaskId,
    pub payload: TaskPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledTaskRequest {
    pub task_id: TaskId,
    pub schedule: ScheduleSpec,
    pub payload: TaskPayload,
}

impl ScheduledTaskRequest {
    pub fn validate(&self) -> anyhow::Result<()> {
        self.schedule.validate()
    }

    pub fn to_message(&self) -> TaskMessage {
        TaskMessage {
            task_id: self.task_id.clone(),
            payload: self.payload.clone(),
        }
    }
}

pub fn daily_cleanup_canceled_instances_request(
    task_id: String,
    cron: String,
    grace_days: i64,
) -> anyhow::Result<ScheduledTaskRequest> {
    Ok(ScheduledTaskRequest {
        task_id: TaskId::new(task_id)?,
        schedule: ScheduleSpec::Cron(cron),
        payload: TaskPayload::CleanupCanceledInstances(CleanupCanceledInstancesTaskPayload {
            grace_days,
            dry_run: false,
        }),
    })
}

#[async_trait]
pub trait TaskScheduler: Send + Sync {
    async fn upsert_task(&self, request: ScheduledTaskRequest) -> anyhow::Result<()>;
    async fn delete_task(&self, task_id: &TaskId) -> anyhow::Result<()>;
}

#[async_trait]
pub trait TaskExecutor: Send + Sync {
    async fn execute_noop(&self, payload: &NoopTaskPayload) -> anyhow::Result<()>;

    async fn execute_cleanup_canceled_instances(
        &self,
        payload: &CleanupCanceledInstancesTaskPayload,
    ) -> anyhow::Result<()>;

    async fn execute_account_deletion(
        &self,
        payload: &AccountDeletionTaskPayload,
    ) -> anyhow::Result<()>;
}

pub async fn dispatch_task<E>(executor: &E, payload: &TaskPayload) -> anyhow::Result<()>
where
    E: TaskExecutor + ?Sized,
{
    match payload {
        TaskPayload::Noop(payload) => executor.execute_noop(payload).await,
        TaskPayload::CleanupCanceledInstances(payload) => {
            executor.execute_cleanup_canceled_instances(payload).await
        }
        TaskPayload::AccountDeletion(payload) => executor.execute_account_deletion(payload).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_task_id_validation() {
        let valid = TaskId::new("cleanup.canceled_15d-1".to_string()).unwrap();
        assert_eq!(valid.as_str(), "cleanup.canceled_15d-1");

        assert!(TaskId::new("".to_string()).is_err());
        assert!(TaskId::new("with space".to_string()).is_err());
        assert!(TaskId::new("slash/not-allowed".to_string()).is_err());
        assert!(TaskId::new("a".repeat(65)).is_err());
    }

    #[test]
    fn test_task_id_deserialize_validates_input() {
        let valid: TaskId = serde_json::from_str(r#""cleanup.canceled_15d-1""#).unwrap();
        assert_eq!(valid.as_str(), "cleanup.canceled_15d-1");

        let err = serde_json::from_str::<TaskId>(r#""with space""#).unwrap_err();
        assert!(err.to_string().contains("invalid task id"));
    }

    #[test]
    fn test_schedule_to_aws_expression() {
        let at = chrono::DateTime::parse_from_rfc3339("2026-03-18T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            ScheduleSpec::At(at).to_aws_expression(),
            "at(2026-03-18T10:00:00)"
        );
        assert_eq!(
            ScheduleSpec::Cron("cron(0 8 * * ? *)".to_string()).to_aws_expression(),
            "cron(0 8 * * ? *)"
        );
    }

    #[test]
    fn test_schedule_validate_cron() {
        assert!(ScheduleSpec::Cron("cron(0 8 * * ? *)".to_string())
            .validate()
            .is_ok());
        assert!(ScheduleSpec::Cron("0 8 * * *".to_string())
            .validate()
            .is_err());
        assert!(ScheduleSpec::Cron("cron()".to_string()).validate().is_err());
    }

    #[test]
    fn test_scheduled_task_request_validate_propagates_schedule_error() {
        let req = ScheduledTaskRequest {
            task_id: TaskId::new("test_task".to_string()).unwrap(),
            schedule: ScheduleSpec::Cron("invalid".to_string()),
            payload: TaskPayload::Noop(NoopTaskPayload { note: None }),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn test_scheduled_task_request_to_message_copies_fields() {
        let req = ScheduledTaskRequest {
            task_id: TaskId::new("test_task".to_string()).unwrap(),
            schedule: ScheduleSpec::Cron("cron(0 0 * * ? *)".to_string()),
            payload: TaskPayload::Noop(NoopTaskPayload {
                note: Some("hello".to_string()),
            }),
        };

        let msg = req.to_message();
        assert_eq!(msg.task_id.as_str(), "test_task");
        match msg.payload {
            TaskPayload::Noop(payload) => assert_eq!(payload.note.as_deref(), Some("hello")),
            TaskPayload::CleanupCanceledInstances(_) => panic!("unexpected payload variant"),
            TaskPayload::AccountDeletion(_) => panic!("unexpected payload variant"),
        }
    }

    #[test]
    fn test_daily_cleanup_request_shape() {
        let req = daily_cleanup_canceled_instances_request(
            config::TASKS_CLEANUP_CANCELED_INSTANCES_DAILY_TASK_ID_DEFAULT.to_string(),
            CLEANUP_CANCELED_INSTANCES_DAILY_CRON_UTC.to_string(),
            CLEANUP_CANCELED_INSTANCES_DEFAULT_GRACE_DAYS,
        )
        .unwrap();
        assert_eq!(
            req.task_id.as_str(),
            config::TASKS_CLEANUP_CANCELED_INSTANCES_DAILY_TASK_ID_DEFAULT
        );
        assert_eq!(
            req.schedule,
            ScheduleSpec::Cron(CLEANUP_CANCELED_INSTANCES_DAILY_CRON_UTC.to_string())
        );
        match req.payload {
            TaskPayload::CleanupCanceledInstances(payload) => {
                assert_eq!(
                    payload.grace_days,
                    CLEANUP_CANCELED_INSTANCES_DEFAULT_GRACE_DAYS
                );
                assert!(!payload.dry_run);
            }
            TaskPayload::Noop(_) => panic!("unexpected payload variant"),
            TaskPayload::AccountDeletion(_) => panic!("unexpected payload variant"),
        }
    }

    struct TestExecutor {
        noop_calls: AtomicUsize,
        cleanup_calls: AtomicUsize,
    }

    #[async_trait]
    impl TaskExecutor for TestExecutor {
        async fn execute_noop(&self, _: &NoopTaskPayload) -> anyhow::Result<()> {
            self.noop_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn execute_cleanup_canceled_instances(
            &self,
            _: &CleanupCanceledInstancesTaskPayload,
        ) -> anyhow::Result<()> {
            self.cleanup_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn execute_account_deletion(
            &self,
            _: &AccountDeletionTaskPayload,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_dispatch_task_by_enum_variant() {
        let exec = TestExecutor {
            noop_calls: AtomicUsize::new(0),
            cleanup_calls: AtomicUsize::new(0),
        };

        dispatch_task(
            &exec,
            &TaskPayload::Noop(NoopTaskPayload {
                note: Some("test".to_string()),
            }),
        )
        .await
        .unwrap();

        dispatch_task(
            &exec,
            &TaskPayload::CleanupCanceledInstances(CleanupCanceledInstancesTaskPayload {
                grace_days: 15,
                dry_run: true,
            }),
        )
        .await
        .unwrap();

        assert_eq!(exec.noop_calls.load(Ordering::SeqCst), 1);
        assert_eq!(exec.cleanup_calls.load(Ordering::SeqCst), 1);
    }
}
