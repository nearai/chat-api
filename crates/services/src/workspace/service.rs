use async_trait::async_trait;
use std::sync::Arc;

use super::ports::{
    CreateWorkspaceParams, UpdateWorkspaceParams, Workspace, WorkspaceMember,
    WorkspaceMembership, WorkspaceRepository, WorkspaceRole, WorkspaceService,
};
use crate::types::{OrganizationId, UserId, WorkspaceId};

pub struct WorkspaceServiceImpl {
    workspace_repository: Arc<dyn WorkspaceRepository>,
}

impl WorkspaceServiceImpl {
    pub fn new(workspace_repository: Arc<dyn WorkspaceRepository>) -> Self {
        Self {
            workspace_repository,
        }
    }
}

#[async_trait]
impl WorkspaceService for WorkspaceServiceImpl {
    async fn get_workspace(&self, workspace_id: WorkspaceId) -> anyhow::Result<Workspace> {
        tracing::info!("Getting workspace: workspace_id={}", workspace_id);

        self.workspace_repository
            .get_workspace(workspace_id)
            .await?
            .ok_or_else(|| {
                tracing::error!("Workspace not found: workspace_id={}", workspace_id);
                anyhow::anyhow!("Workspace not found")
            })
    }

    async fn get_workspace_by_slug(
        &self,
        organization_id: OrganizationId,
        slug: &str,
    ) -> anyhow::Result<Workspace> {
        tracing::info!(
            "Getting workspace by slug: organization_id={}, slug={}",
            organization_id,
            slug
        );

        self.workspace_repository
            .get_workspace_by_slug(organization_id, slug)
            .await?
            .ok_or_else(|| {
                tracing::error!(
                    "Workspace not found: organization_id={}, slug={}",
                    organization_id,
                    slug
                );
                anyhow::anyhow!("Workspace not found")
            })
    }

    async fn create_workspace(
        &self,
        params: CreateWorkspaceParams,
        creator_user_id: UserId,
    ) -> anyhow::Result<Workspace> {
        tracing::info!(
            "Creating workspace: name={}, slug={}, organization_id={}, creator_user_id={}",
            params.name,
            params.slug,
            params.organization_id,
            creator_user_id
        );

        // Check if slug is available
        if !self
            .workspace_repository
            .is_slug_available(params.organization_id, &params.slug)
            .await?
        {
            tracing::error!(
                "Slug already taken: organization_id={}, slug={}",
                params.organization_id,
                params.slug
            );
            return Err(anyhow::anyhow!(
                "Workspace slug is already taken in this organization"
            ));
        }

        // Create the workspace
        let workspace = self
            .workspace_repository
            .create_workspace(params)
            .await?;

        // Add the creator as admin
        self.workspace_repository
            .add_workspace_member(workspace.id, creator_user_id, WorkspaceRole::Admin)
            .await?;

        tracing::info!(
            "Workspace created successfully: workspace_id={}",
            workspace.id
        );

        Ok(workspace)
    }

    async fn update_workspace(
        &self,
        workspace_id: WorkspaceId,
        params: UpdateWorkspaceParams,
    ) -> anyhow::Result<Workspace> {
        tracing::info!("Updating workspace: workspace_id={}", workspace_id);

        let workspace = self
            .workspace_repository
            .update_workspace(workspace_id, params)
            .await?;

        tracing::info!(
            "Workspace updated successfully: workspace_id={}",
            workspace_id
        );

        Ok(workspace)
    }

    async fn delete_workspace(&self, workspace_id: WorkspaceId) -> anyhow::Result<()> {
        tracing::warn!("Deleting workspace: workspace_id={}", workspace_id);

        // Check if it's the default workspace
        let workspace = self.get_workspace(workspace_id).await?;
        if workspace.is_default {
            return Err(anyhow::anyhow!("Cannot delete the default workspace"));
        }

        self.workspace_repository
            .delete_workspace(workspace_id)
            .await?;

        tracing::info!(
            "Workspace deleted successfully: workspace_id={}",
            workspace_id
        );

        Ok(())
    }

    async fn get_organization_workspaces(
        &self,
        organization_id: OrganizationId,
    ) -> anyhow::Result<Vec<Workspace>> {
        tracing::info!(
            "Getting workspaces for organization: organization_id={}",
            organization_id
        );

        self.workspace_repository
            .get_organization_workspaces(organization_id)
            .await
    }

    async fn get_user_workspaces(&self, user_id: UserId) -> anyhow::Result<Vec<Workspace>> {
        tracing::info!("Getting workspaces for user: user_id={}", user_id);

        self.workspace_repository.get_user_workspaces(user_id).await
    }

    async fn get_workspace_members(
        &self,
        workspace_id: WorkspaceId,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<WorkspaceMember>, u64)> {
        tracing::info!(
            "Getting members for workspace: workspace_id={}, limit={}, offset={}",
            workspace_id,
            limit,
            offset
        );

        self.workspace_repository
            .get_workspace_members(workspace_id, limit, offset)
            .await
    }

    async fn add_workspace_member(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
        role: WorkspaceRole,
    ) -> anyhow::Result<WorkspaceMembership> {
        tracing::info!(
            "Adding member to workspace: workspace_id={}, user_id={}, role={:?}",
            workspace_id,
            user_id,
            role
        );

        // Check if user is already a member
        if let Some(_existing) = self
            .workspace_repository
            .get_workspace_membership(workspace_id, user_id)
            .await?
        {
            tracing::warn!(
                "User is already a member of workspace: workspace_id={}, user_id={}",
                workspace_id,
                user_id
            );
            return Err(anyhow::anyhow!("User is already a member of this workspace"));
        }

        let membership = self
            .workspace_repository
            .add_workspace_member(workspace_id, user_id, role)
            .await?;

        tracing::info!(
            "Member added to workspace successfully: workspace_id={}, user_id={}",
            workspace_id,
            user_id
        );

        Ok(membership)
    }

    async fn update_workspace_member_role(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
        role: WorkspaceRole,
    ) -> anyhow::Result<()> {
        tracing::info!(
            "Updating member role: workspace_id={}, user_id={}, role={:?}",
            workspace_id,
            user_id,
            role
        );

        self.workspace_repository
            .update_workspace_member_role(workspace_id, user_id, role)
            .await
    }

    async fn remove_workspace_member(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
    ) -> anyhow::Result<()> {
        tracing::warn!(
            "Removing member from workspace: workspace_id={}, user_id={}",
            workspace_id,
            user_id
        );

        self.workspace_repository
            .remove_workspace_member(workspace_id, user_id)
            .await?;

        tracing::info!(
            "Member removed from workspace successfully: workspace_id={}, user_id={}",
            workspace_id,
            user_id
        );

        Ok(())
    }

    async fn user_has_workspace_access(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
    ) -> anyhow::Result<bool> {
        let membership = self
            .workspace_repository
            .get_workspace_membership(workspace_id, user_id)
            .await?;

        Ok(membership.is_some())
    }

    async fn get_user_workspace_role(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
    ) -> anyhow::Result<Option<WorkspaceRole>> {
        let membership = self
            .workspace_repository
            .get_workspace_membership(workspace_id, user_id)
            .await?;

        Ok(membership.map(|m| m.role))
    }
}
