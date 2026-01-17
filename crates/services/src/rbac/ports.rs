use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::{OrganizationId, PermissionId, RoleId, UserId, WorkspaceId};

/// Represents a permission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub id: PermissionId,
    pub code: String,
    pub name: String,
    pub description: Option<String>,
    pub module: String,
    pub action: String,
    pub created_at: DateTime<Utc>,
}

/// Represents a role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: RoleId,
    pub organization_id: Option<OrganizationId>,
    pub name: String,
    pub description: Option<String>,
    pub is_system: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Parameters for creating a custom role
#[derive(Debug, Clone)]
pub struct CreateRoleParams {
    pub organization_id: OrganizationId,
    pub name: String,
    pub description: Option<String>,
    pub permission_ids: Vec<PermissionId>,
}

/// Parameters for updating a role
#[derive(Debug, Clone, Default)]
pub struct UpdateRoleParams {
    pub name: Option<String>,
    pub description: Option<String>,
    pub permission_ids: Option<Vec<PermissionId>>,
}

/// User role assignment with scope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRoleAssignment {
    pub user_id: UserId,
    pub role_id: RoleId,
    pub role_name: String,
    pub organization_id: Option<OrganizationId>,
    pub workspace_id: Option<WorkspaceId>,
    pub created_at: DateTime<Utc>,
}

/// Repository trait for permission operations
#[async_trait]
pub trait PermissionRepository: Send + Sync {
    /// Get all permissions
    async fn get_all_permissions(&self) -> anyhow::Result<Vec<Permission>>;

    /// Get permissions by module
    async fn get_permissions_by_module(&self, module: &str) -> anyhow::Result<Vec<Permission>>;

    /// Get permission by code
    async fn get_permission_by_code(&self, code: &str) -> anyhow::Result<Option<Permission>>;

    /// Get permissions for a role
    async fn get_role_permissions(&self, role_id: RoleId) -> anyhow::Result<Vec<Permission>>;
}

/// Repository trait for role operations
#[async_trait]
pub trait RoleRepository: Send + Sync {
    /// Get role by ID
    async fn get_role(&self, role_id: RoleId) -> anyhow::Result<Option<Role>>;

    /// Get role by name (system roles)
    async fn get_system_role_by_name(&self, name: &str) -> anyhow::Result<Option<Role>>;

    /// Get all system roles
    async fn get_system_roles(&self) -> anyhow::Result<Vec<Role>>;

    /// Get organization-specific roles
    async fn get_organization_roles(
        &self,
        organization_id: OrganizationId,
    ) -> anyhow::Result<Vec<Role>>;

    /// Create a custom role
    async fn create_role(&self, params: CreateRoleParams) -> anyhow::Result<Role>;

    /// Update a role
    async fn update_role(
        &self,
        role_id: RoleId,
        params: UpdateRoleParams,
    ) -> anyhow::Result<Role>;

    /// Delete a custom role
    async fn delete_role(&self, role_id: RoleId) -> anyhow::Result<()>;

    /// Assign role to user
    async fn assign_role_to_user(
        &self,
        user_id: UserId,
        role_id: RoleId,
        organization_id: Option<OrganizationId>,
        workspace_id: Option<WorkspaceId>,
    ) -> anyhow::Result<()>;

    /// Remove role from user
    async fn remove_role_from_user(
        &self,
        user_id: UserId,
        role_id: RoleId,
        organization_id: Option<OrganizationId>,
        workspace_id: Option<WorkspaceId>,
    ) -> anyhow::Result<()>;

    /// Get user's role assignments
    async fn get_user_roles(
        &self,
        user_id: UserId,
        organization_id: Option<OrganizationId>,
        workspace_id: Option<WorkspaceId>,
    ) -> anyhow::Result<Vec<UserRoleAssignment>>;

    /// Get all permissions for a user (aggregated from all roles)
    async fn get_user_permissions(
        &self,
        user_id: UserId,
        organization_id: Option<OrganizationId>,
        workspace_id: Option<WorkspaceId>,
    ) -> anyhow::Result<Vec<String>>;

    /// Set permissions for a role
    async fn set_role_permissions(
        &self,
        role_id: RoleId,
        permission_ids: Vec<PermissionId>,
    ) -> anyhow::Result<()>;
}

/// Service trait for permission operations
#[async_trait]
pub trait PermissionService: Send + Sync {
    /// Get all permissions
    async fn get_all_permissions(&self) -> anyhow::Result<Vec<Permission>>;

    /// Get permissions grouped by module
    async fn get_permissions_by_module(&self, module: &str) -> anyhow::Result<Vec<Permission>>;

    /// Check if user has a specific permission
    async fn has_permission(
        &self,
        user_id: UserId,
        permission_code: &str,
        organization_id: Option<OrganizationId>,
        workspace_id: Option<WorkspaceId>,
    ) -> anyhow::Result<bool>;

    /// Get all permissions for a user
    async fn get_user_permissions(
        &self,
        user_id: UserId,
        organization_id: Option<OrganizationId>,
        workspace_id: Option<WorkspaceId>,
    ) -> anyhow::Result<Vec<String>>;
}

/// Service trait for role operations
#[async_trait]
pub trait RoleService: Send + Sync {
    /// Get role by ID
    async fn get_role(&self, role_id: RoleId) -> anyhow::Result<Role>;

    /// Get all system roles
    async fn get_system_roles(&self) -> anyhow::Result<Vec<Role>>;

    /// Get organization-specific roles (includes system roles)
    async fn get_organization_roles(
        &self,
        organization_id: OrganizationId,
    ) -> anyhow::Result<Vec<Role>>;

    /// Create a custom role
    async fn create_role(&self, params: CreateRoleParams) -> anyhow::Result<Role>;

    /// Update a role
    async fn update_role(
        &self,
        role_id: RoleId,
        params: UpdateRoleParams,
    ) -> anyhow::Result<Role>;

    /// Delete a custom role
    async fn delete_role(&self, role_id: RoleId) -> anyhow::Result<()>;

    /// Assign role to user
    async fn assign_role_to_user(
        &self,
        user_id: UserId,
        role_id: RoleId,
        organization_id: Option<OrganizationId>,
        workspace_id: Option<WorkspaceId>,
    ) -> anyhow::Result<()>;

    /// Remove role from user
    async fn remove_role_from_user(
        &self,
        user_id: UserId,
        role_id: RoleId,
        organization_id: Option<OrganizationId>,
        workspace_id: Option<WorkspaceId>,
    ) -> anyhow::Result<()>;

    /// Get user's role assignments
    async fn get_user_roles(
        &self,
        user_id: UserId,
        organization_id: Option<OrganizationId>,
        workspace_id: Option<WorkspaceId>,
    ) -> anyhow::Result<Vec<UserRoleAssignment>>;

    /// Get permissions for a role
    async fn get_role_permissions(&self, role_id: RoleId) -> anyhow::Result<Vec<Permission>>;
}
