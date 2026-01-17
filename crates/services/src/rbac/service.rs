use async_trait::async_trait;
use std::sync::Arc;

use super::ports::{
    CreateRoleParams, Permission, PermissionRepository, PermissionService, Role, RoleRepository,
    RoleService, UpdateRoleParams, UserRoleAssignment,
};
use crate::types::{OrganizationId, RoleId, UserId, WorkspaceId};

pub struct PermissionServiceImpl {
    permission_repository: Arc<dyn PermissionRepository>,
    role_repository: Arc<dyn RoleRepository>,
}

impl PermissionServiceImpl {
    pub fn new(
        permission_repository: Arc<dyn PermissionRepository>,
        role_repository: Arc<dyn RoleRepository>,
    ) -> Self {
        Self {
            permission_repository,
            role_repository,
        }
    }
}

#[async_trait]
impl PermissionService for PermissionServiceImpl {
    async fn get_all_permissions(&self) -> anyhow::Result<Vec<Permission>> {
        tracing::info!("Getting all permissions");
        self.permission_repository.get_all_permissions().await
    }

    async fn get_permissions_by_module(&self, module: &str) -> anyhow::Result<Vec<Permission>> {
        tracing::info!("Getting permissions for module: {}", module);
        self.permission_repository
            .get_permissions_by_module(module)
            .await
    }

    async fn has_permission(
        &self,
        user_id: UserId,
        permission_code: &str,
        organization_id: Option<OrganizationId>,
        workspace_id: Option<WorkspaceId>,
    ) -> anyhow::Result<bool> {
        tracing::debug!(
            "Checking permission: user_id={}, permission={}, org_id={:?}, workspace_id={:?}",
            user_id,
            permission_code,
            organization_id,
            workspace_id
        );

        let permissions = self
            .role_repository
            .get_user_permissions(user_id, organization_id, workspace_id)
            .await?;

        let has_perm = permissions.contains(&permission_code.to_string());

        tracing::debug!(
            "Permission check result: user_id={}, permission={}, has_permission={}",
            user_id,
            permission_code,
            has_perm
        );

        Ok(has_perm)
    }

    async fn get_user_permissions(
        &self,
        user_id: UserId,
        organization_id: Option<OrganizationId>,
        workspace_id: Option<WorkspaceId>,
    ) -> anyhow::Result<Vec<String>> {
        tracing::info!(
            "Getting user permissions: user_id={}, org_id={:?}, workspace_id={:?}",
            user_id,
            organization_id,
            workspace_id
        );

        self.role_repository
            .get_user_permissions(user_id, organization_id, workspace_id)
            .await
    }
}

pub struct RoleServiceImpl {
    role_repository: Arc<dyn RoleRepository>,
    permission_repository: Arc<dyn PermissionRepository>,
}

impl RoleServiceImpl {
    pub fn new(
        role_repository: Arc<dyn RoleRepository>,
        permission_repository: Arc<dyn PermissionRepository>,
    ) -> Self {
        Self {
            role_repository,
            permission_repository,
        }
    }
}

#[async_trait]
impl RoleService for RoleServiceImpl {
    async fn get_role(&self, role_id: RoleId) -> anyhow::Result<Role> {
        tracing::info!("Getting role: role_id={}", role_id);

        self.role_repository
            .get_role(role_id)
            .await?
            .ok_or_else(|| {
                tracing::error!("Role not found: role_id={}", role_id);
                anyhow::anyhow!("Role not found")
            })
    }

    async fn get_system_roles(&self) -> anyhow::Result<Vec<Role>> {
        tracing::info!("Getting system roles");
        self.role_repository.get_system_roles().await
    }

    async fn get_organization_roles(
        &self,
        organization_id: OrganizationId,
    ) -> anyhow::Result<Vec<Role>> {
        tracing::info!(
            "Getting roles for organization: organization_id={}",
            organization_id
        );

        // Get both system roles and org-specific roles
        let mut roles = self.role_repository.get_system_roles().await?;
        let org_roles = self
            .role_repository
            .get_organization_roles(organization_id)
            .await?;
        roles.extend(org_roles);

        Ok(roles)
    }

    async fn create_role(&self, params: CreateRoleParams) -> anyhow::Result<Role> {
        tracing::info!(
            "Creating role: name={}, organization_id={}",
            params.name,
            params.organization_id
        );

        let role = self.role_repository.create_role(params).await?;

        tracing::info!("Role created successfully: role_id={}", role.id);

        Ok(role)
    }

    async fn update_role(
        &self,
        role_id: RoleId,
        params: UpdateRoleParams,
    ) -> anyhow::Result<Role> {
        tracing::info!("Updating role: role_id={}", role_id);

        // Check if role exists and is not a system role
        let role = self.get_role(role_id).await?;
        if role.is_system {
            tracing::error!("Cannot update system role: role_id={}", role_id);
            return Err(anyhow::anyhow!("Cannot modify system roles"));
        }

        let updated_role = self.role_repository.update_role(role_id, params).await?;

        tracing::info!("Role updated successfully: role_id={}", role_id);

        Ok(updated_role)
    }

    async fn delete_role(&self, role_id: RoleId) -> anyhow::Result<()> {
        tracing::warn!("Deleting role: role_id={}", role_id);

        // Check if role exists and is not a system role
        let role = self.get_role(role_id).await?;
        if role.is_system {
            tracing::error!("Cannot delete system role: role_id={}", role_id);
            return Err(anyhow::anyhow!("Cannot delete system roles"));
        }

        self.role_repository.delete_role(role_id).await?;

        tracing::info!("Role deleted successfully: role_id={}", role_id);

        Ok(())
    }

    async fn assign_role_to_user(
        &self,
        user_id: UserId,
        role_id: RoleId,
        organization_id: Option<OrganizationId>,
        workspace_id: Option<WorkspaceId>,
    ) -> anyhow::Result<()> {
        tracing::info!(
            "Assigning role to user: user_id={}, role_id={}, org_id={:?}, workspace_id={:?}",
            user_id,
            role_id,
            organization_id,
            workspace_id
        );

        self.role_repository
            .assign_role_to_user(user_id, role_id, organization_id, workspace_id)
            .await?;

        tracing::info!(
            "Role assigned successfully: user_id={}, role_id={}",
            user_id,
            role_id
        );

        Ok(())
    }

    async fn remove_role_from_user(
        &self,
        user_id: UserId,
        role_id: RoleId,
        organization_id: Option<OrganizationId>,
        workspace_id: Option<WorkspaceId>,
    ) -> anyhow::Result<()> {
        tracing::warn!(
            "Removing role from user: user_id={}, role_id={}, org_id={:?}, workspace_id={:?}",
            user_id,
            role_id,
            organization_id,
            workspace_id
        );

        self.role_repository
            .remove_role_from_user(user_id, role_id, organization_id, workspace_id)
            .await?;

        tracing::info!(
            "Role removed successfully: user_id={}, role_id={}",
            user_id,
            role_id
        );

        Ok(())
    }

    async fn get_user_roles(
        &self,
        user_id: UserId,
        organization_id: Option<OrganizationId>,
        workspace_id: Option<WorkspaceId>,
    ) -> anyhow::Result<Vec<UserRoleAssignment>> {
        tracing::info!(
            "Getting user roles: user_id={}, org_id={:?}, workspace_id={:?}",
            user_id,
            organization_id,
            workspace_id
        );

        self.role_repository
            .get_user_roles(user_id, organization_id, workspace_id)
            .await
    }

    async fn get_role_permissions(&self, role_id: RoleId) -> anyhow::Result<Vec<Permission>> {
        tracing::info!("Getting permissions for role: role_id={}", role_id);
        self.permission_repository.get_role_permissions(role_id).await
    }
}
