use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::net::IpAddr;

use crate::types::{OrganizationId, UserId, WorkspaceId};

/// Actor type for audit logs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActorType {
    User,
    System,
    Api,
}

impl ActorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ActorType::User => "user",
            ActorType::System => "system",
            ActorType::Api => "api",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "user" => Some(ActorType::User),
            "system" => Some(ActorType::System),
            "api" => Some(ActorType::Api),
            _ => None,
        }
    }
}

impl Default for ActorType {
    fn default() -> Self {
        ActorType::User
    }
}

/// Audit log status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditStatus {
    Success,
    Failure,
    Pending,
}

impl AuditStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditStatus::Success => "success",
            AuditStatus::Failure => "failure",
            AuditStatus::Pending => "pending",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "success" => Some(AuditStatus::Success),
            "failure" => Some(AuditStatus::Failure),
            "pending" => Some(AuditStatus::Pending),
            _ => None,
        }
    }
}

impl Default for AuditStatus {
    fn default() -> Self {
        AuditStatus::Success
    }
}

/// Represents an audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: i64,
    pub organization_id: OrganizationId,
    pub workspace_id: Option<WorkspaceId>,
    pub actor_id: Option<UserId>,
    pub actor_type: ActorType,
    pub actor_ip: Option<IpAddr>,
    pub actor_user_agent: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub changes: Option<JsonValue>,
    pub metadata: Option<JsonValue>,
    pub status: AuditStatus,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Parameters for creating an audit log entry
#[derive(Debug, Clone)]
pub struct CreateAuditLogParams {
    pub organization_id: OrganizationId,
    pub workspace_id: Option<WorkspaceId>,
    pub actor_id: Option<UserId>,
    pub actor_type: ActorType,
    pub actor_ip: Option<IpAddr>,
    pub actor_user_agent: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub changes: Option<JsonValue>,
    pub metadata: Option<JsonValue>,
    pub status: AuditStatus,
    pub error_message: Option<String>,
}

impl CreateAuditLogParams {
    /// Create a new audit log params for a user action
    pub fn user_action(
        organization_id: OrganizationId,
        actor_id: UserId,
        action: &str,
        resource_type: &str,
    ) -> Self {
        Self {
            organization_id,
            workspace_id: None,
            actor_id: Some(actor_id),
            actor_type: ActorType::User,
            actor_ip: None,
            actor_user_agent: None,
            action: action.to_string(),
            resource_type: resource_type.to_string(),
            resource_id: None,
            changes: None,
            metadata: None,
            status: AuditStatus::Success,
            error_message: None,
        }
    }

    /// Create a new audit log params for a system action
    pub fn system_action(
        organization_id: OrganizationId,
        action: &str,
        resource_type: &str,
    ) -> Self {
        Self {
            organization_id,
            workspace_id: None,
            actor_id: None,
            actor_type: ActorType::System,
            actor_ip: None,
            actor_user_agent: None,
            action: action.to_string(),
            resource_type: resource_type.to_string(),
            resource_id: None,
            changes: None,
            metadata: None,
            status: AuditStatus::Success,
            error_message: None,
        }
    }

    pub fn with_workspace(mut self, workspace_id: WorkspaceId) -> Self {
        self.workspace_id = Some(workspace_id);
        self
    }

    pub fn with_resource_id(mut self, resource_id: &str) -> Self {
        self.resource_id = Some(resource_id.to_string());
        self
    }

    pub fn with_changes(mut self, changes: JsonValue) -> Self {
        self.changes = Some(changes);
        self
    }

    pub fn with_metadata(mut self, metadata: JsonValue) -> Self {
        self.metadata = Some(metadata);
        self
    }

    pub fn with_ip(mut self, ip: IpAddr) -> Self {
        self.actor_ip = Some(ip);
        self
    }

    pub fn with_user_agent(mut self, user_agent: &str) -> Self {
        self.actor_user_agent = Some(user_agent.to_string());
        self
    }

    pub fn with_failure(mut self, error_message: &str) -> Self {
        self.status = AuditStatus::Failure;
        self.error_message = Some(error_message.to_string());
        self
    }
}

/// Query parameters for audit logs
#[derive(Debug, Clone, Default)]
pub struct AuditLogQuery {
    pub organization_id: OrganizationId,
    pub workspace_id: Option<WorkspaceId>,
    pub actor_id: Option<UserId>,
    pub action: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub status: Option<AuditStatus>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
    pub limit: i64,
    pub offset: i64,
}

/// Export format for audit logs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Csv,
}

/// Repository trait for audit log operations
#[async_trait]
pub trait AuditRepository: Send + Sync {
    /// Create an audit log entry
    async fn create_audit_log(&self, params: CreateAuditLogParams) -> anyhow::Result<i64>;

    /// Query audit logs with filters and pagination
    async fn query_audit_logs(
        &self,
        query: AuditLogQuery,
    ) -> anyhow::Result<(Vec<AuditLog>, u64)>;

    /// Get audit log by ID
    async fn get_audit_log(
        &self,
        organization_id: OrganizationId,
        log_id: i64,
    ) -> anyhow::Result<Option<AuditLog>>;
}

/// Service trait for audit log operations
#[async_trait]
pub trait AuditService: Send + Sync {
    /// Log an event (async, fire-and-forget)
    fn log(&self, params: CreateAuditLogParams);

    /// Log an event synchronously
    async fn log_sync(&self, params: CreateAuditLogParams) -> anyhow::Result<i64>;

    /// Query audit logs
    async fn query(&self, query: AuditLogQuery) -> anyhow::Result<(Vec<AuditLog>, u64)>;

    /// Export audit logs to a specific format
    async fn export(
        &self,
        query: AuditLogQuery,
        format: ExportFormat,
    ) -> anyhow::Result<Vec<u8>>;

    /// Get a specific audit log entry
    async fn get_audit_log(
        &self,
        organization_id: OrganizationId,
        log_id: i64,
    ) -> anyhow::Result<AuditLog>;
}
