use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::{OrganizationId, UserId, WorkspaceId, WorkspaceMembershipId};

/// Workspace status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkspaceStatus {
    Active,
    Archived,
    Deleted,
}

impl WorkspaceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            WorkspaceStatus::Active => "active",
            WorkspaceStatus::Archived => "archived",
            WorkspaceStatus::Deleted => "deleted",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "active" => Some(WorkspaceStatus::Active),
            "archived" => Some(WorkspaceStatus::Archived),
            "deleted" => Some(WorkspaceStatus::Deleted),
            _ => None,
        }
    }
}

impl Default for WorkspaceStatus {
    fn default() -> Self {
        WorkspaceStatus::Active
    }
}

/// Workspace role for a member
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkspaceRole {
    Admin,
    Member,
    Viewer,
}

impl WorkspaceRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            WorkspaceRole::Admin => "admin",
            WorkspaceRole::Member => "member",
            WorkspaceRole::Viewer => "viewer",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(WorkspaceRole::Admin),
            "member" => Some(WorkspaceRole::Member),
            "viewer" => Some(WorkspaceRole::Viewer),
            _ => None,
        }
    }
}

impl Default for WorkspaceRole {
    fn default() -> Self {
        WorkspaceRole::Member
    }
}

/// Membership status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MembershipStatus {
    Active,
    Invited,
    Suspended,
}

impl MembershipStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            MembershipStatus::Active => "active",
            MembershipStatus::Invited => "invited",
            MembershipStatus::Suspended => "suspended",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "active" => Some(MembershipStatus::Active),
            "invited" => Some(MembershipStatus::Invited),
            "suspended" => Some(MembershipStatus::Suspended),
            _ => None,
        }
    }
}

impl Default for MembershipStatus {
    fn default() -> Self {
        MembershipStatus::Active
    }
}

/// Workspace settings stored as JSONB
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkspaceSettings {
    /// Default model for the workspace
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,

    /// System prompt override for the workspace
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<String>,

    /// Whether web search is enabled by default
    #[serde(default)]
    pub web_search_enabled: bool,
}

/// Represents a workspace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub id: WorkspaceId,
    pub organization_id: OrganizationId,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub settings: WorkspaceSettings,
    pub is_default: bool,
    pub status: WorkspaceStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Parameters for creating a workspace
#[derive(Debug, Clone)]
pub struct CreateWorkspaceParams {
    pub organization_id: OrganizationId,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub settings: WorkspaceSettings,
    pub is_default: bool,
}

/// Parameters for updating a workspace
#[derive(Debug, Clone, Default)]
pub struct UpdateWorkspaceParams {
    pub name: Option<String>,
    pub description: Option<String>,
    pub settings: Option<WorkspaceSettings>,
}

/// Workspace membership
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceMembership {
    pub id: WorkspaceMembershipId,
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub role: WorkspaceRole,
    pub status: MembershipStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Workspace member with user details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceMember {
    pub user_id: UserId,
    pub email: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub role: WorkspaceRole,
    pub status: MembershipStatus,
    pub joined_at: DateTime<Utc>,
}

/// Repository trait for workspace operations
#[async_trait]
pub trait WorkspaceRepository: Send + Sync {
    /// Get workspace by ID
    async fn get_workspace(&self, workspace_id: WorkspaceId) -> anyhow::Result<Option<Workspace>>;

    /// Get workspace by org and slug
    async fn get_workspace_by_slug(
        &self,
        organization_id: OrganizationId,
        slug: &str,
    ) -> anyhow::Result<Option<Workspace>>;

    /// Create a new workspace
    async fn create_workspace(&self, params: CreateWorkspaceParams) -> anyhow::Result<Workspace>;

    /// Update a workspace
    async fn update_workspace(
        &self,
        workspace_id: WorkspaceId,
        params: UpdateWorkspaceParams,
    ) -> anyhow::Result<Workspace>;

    /// Soft delete a workspace
    async fn delete_workspace(&self, workspace_id: WorkspaceId) -> anyhow::Result<()>;

    /// Get all workspaces for an organization
    async fn get_organization_workspaces(
        &self,
        organization_id: OrganizationId,
    ) -> anyhow::Result<Vec<Workspace>>;

    /// Get all workspaces a user has access to
    async fn get_user_workspaces(&self, user_id: UserId) -> anyhow::Result<Vec<Workspace>>;

    /// Get the default workspace for an organization
    async fn get_default_workspace(
        &self,
        organization_id: OrganizationId,
    ) -> anyhow::Result<Option<Workspace>>;

    /// Get workspace members
    async fn get_workspace_members(
        &self,
        workspace_id: WorkspaceId,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<WorkspaceMember>, u64)>;

    /// Add a member to a workspace
    async fn add_workspace_member(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
        role: WorkspaceRole,
    ) -> anyhow::Result<WorkspaceMembership>;

    /// Update a member's role
    async fn update_workspace_member_role(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
        role: WorkspaceRole,
    ) -> anyhow::Result<()>;

    /// Remove a member from a workspace
    async fn remove_workspace_member(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
    ) -> anyhow::Result<()>;

    /// Get user's membership in a workspace
    async fn get_workspace_membership(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
    ) -> anyhow::Result<Option<WorkspaceMembership>>;

    /// Check if slug is available within an organization
    async fn is_slug_available(
        &self,
        organization_id: OrganizationId,
        slug: &str,
    ) -> anyhow::Result<bool>;
}

/// Service trait for workspace operations
#[async_trait]
pub trait WorkspaceService: Send + Sync {
    /// Get workspace by ID
    async fn get_workspace(&self, workspace_id: WorkspaceId) -> anyhow::Result<Workspace>;

    /// Get workspace by org and slug
    async fn get_workspace_by_slug(
        &self,
        organization_id: OrganizationId,
        slug: &str,
    ) -> anyhow::Result<Workspace>;

    /// Create a new workspace
    async fn create_workspace(
        &self,
        params: CreateWorkspaceParams,
        creator_user_id: UserId,
    ) -> anyhow::Result<Workspace>;

    /// Update a workspace
    async fn update_workspace(
        &self,
        workspace_id: WorkspaceId,
        params: UpdateWorkspaceParams,
    ) -> anyhow::Result<Workspace>;

    /// Delete a workspace
    async fn delete_workspace(&self, workspace_id: WorkspaceId) -> anyhow::Result<()>;

    /// Get all workspaces for an organization
    async fn get_organization_workspaces(
        &self,
        organization_id: OrganizationId,
    ) -> anyhow::Result<Vec<Workspace>>;

    /// Get all workspaces a user has access to
    async fn get_user_workspaces(&self, user_id: UserId) -> anyhow::Result<Vec<Workspace>>;

    /// Get workspace members with pagination
    async fn get_workspace_members(
        &self,
        workspace_id: WorkspaceId,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<WorkspaceMember>, u64)>;

    /// Add a member to a workspace
    async fn add_workspace_member(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
        role: WorkspaceRole,
    ) -> anyhow::Result<WorkspaceMembership>;

    /// Update a member's role
    async fn update_workspace_member_role(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
        role: WorkspaceRole,
    ) -> anyhow::Result<()>;

    /// Remove a member from a workspace
    async fn remove_workspace_member(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
    ) -> anyhow::Result<()>;

    /// Check if user has access to workspace
    async fn user_has_workspace_access(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
    ) -> anyhow::Result<bool>;

    /// Get user's role in workspace
    async fn get_user_workspace_role(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
    ) -> anyhow::Result<Option<WorkspaceRole>>;
}
