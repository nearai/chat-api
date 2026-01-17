use async_trait::async_trait;
use std::sync::Arc;

use super::ports::{
    CreateOrganizationParams, OrgRole, Organization, OrganizationMember, OrganizationRepository,
    OrganizationService, OrganizationSettings, PlanTier, UpdateOrganizationParams,
};
use crate::types::{OrganizationId, UserId};
use crate::workspace::ports::{CreateWorkspaceParams, WorkspaceRepository};

pub struct OrganizationServiceImpl {
    organization_repository: Arc<dyn OrganizationRepository>,
    workspace_repository: Arc<dyn WorkspaceRepository>,
}

impl OrganizationServiceImpl {
    pub fn new(
        organization_repository: Arc<dyn OrganizationRepository>,
        workspace_repository: Arc<dyn WorkspaceRepository>,
    ) -> Self {
        Self {
            organization_repository,
            workspace_repository,
        }
    }
}

#[async_trait]
impl OrganizationService for OrganizationServiceImpl {
    async fn get_organization(
        &self,
        organization_id: OrganizationId,
    ) -> anyhow::Result<Organization> {
        tracing::info!(
            "Getting organization: organization_id={}",
            organization_id
        );

        self.organization_repository
            .get_organization(organization_id)
            .await?
            .ok_or_else(|| {
                tracing::error!("Organization not found: organization_id={}", organization_id);
                anyhow::anyhow!("Organization not found")
            })
    }

    async fn get_organization_by_slug(&self, slug: &str) -> anyhow::Result<Organization> {
        tracing::info!("Getting organization by slug: slug={}", slug);

        self.organization_repository
            .get_organization_by_slug(slug)
            .await?
            .ok_or_else(|| {
                tracing::error!("Organization not found: slug={}", slug);
                anyhow::anyhow!("Organization not found")
            })
    }

    async fn create_organization(
        &self,
        params: CreateOrganizationParams,
        creator_user_id: UserId,
    ) -> anyhow::Result<Organization> {
        tracing::info!(
            "Creating organization: name={}, slug={}, creator_user_id={}",
            params.name,
            params.slug,
            creator_user_id
        );

        // Check if slug is available
        if !self
            .organization_repository
            .is_slug_available(&params.slug)
            .await?
        {
            tracing::error!("Slug already taken: slug={}", params.slug);
            return Err(anyhow::anyhow!("Organization slug is already taken"));
        }

        // Create the organization
        let organization = self
            .organization_repository
            .create_organization(params)
            .await?;

        // Set the creator as the owner
        self.organization_repository
            .set_user_organization(creator_user_id, organization.id, OrgRole::Owner)
            .await?;

        // Create default workspace
        let workspace_params = CreateWorkspaceParams {
            organization_id: organization.id,
            name: "Default".to_string(),
            slug: "default".to_string(),
            description: Some("Default workspace".to_string()),
            settings: Default::default(),
            is_default: true,
        };

        let workspace = self
            .workspace_repository
            .create_workspace(workspace_params)
            .await?;

        // Add creator to the default workspace as admin
        self.workspace_repository
            .add_workspace_member(
                workspace.id,
                creator_user_id,
                crate::workspace::ports::WorkspaceRole::Admin,
            )
            .await?;

        tracing::info!(
            "Organization created successfully: organization_id={}, workspace_id={}",
            organization.id,
            workspace.id
        );

        Ok(organization)
    }

    async fn update_organization(
        &self,
        organization_id: OrganizationId,
        params: UpdateOrganizationParams,
    ) -> anyhow::Result<Organization> {
        tracing::info!(
            "Updating organization: organization_id={}",
            organization_id
        );

        let organization = self
            .organization_repository
            .update_organization(organization_id, params)
            .await?;

        tracing::info!(
            "Organization updated successfully: organization_id={}",
            organization_id
        );

        Ok(organization)
    }

    async fn delete_organization(&self, organization_id: OrganizationId) -> anyhow::Result<()> {
        tracing::warn!(
            "Deleting organization: organization_id={}",
            organization_id
        );

        self.organization_repository
            .delete_organization(organization_id)
            .await?;

        tracing::info!(
            "Organization deleted successfully: organization_id={}",
            organization_id
        );

        Ok(())
    }

    async fn get_user_organizations(&self, user_id: UserId) -> anyhow::Result<Vec<Organization>> {
        tracing::info!("Getting organizations for user: user_id={}", user_id);

        let organizations = self
            .organization_repository
            .get_user_organizations(user_id)
            .await?;

        tracing::info!(
            "Found {} organization(s) for user_id={}",
            organizations.len(),
            user_id
        );

        Ok(organizations)
    }

    async fn get_organization_members(
        &self,
        organization_id: OrganizationId,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<OrganizationMember>, u64)> {
        tracing::info!(
            "Getting members for organization: organization_id={}, limit={}, offset={}",
            organization_id,
            limit,
            offset
        );

        self.organization_repository
            .get_organization_members(organization_id, limit, offset)
            .await
    }

    async fn add_user_to_organization(
        &self,
        user_id: UserId,
        organization_id: OrganizationId,
        role: OrgRole,
    ) -> anyhow::Result<()> {
        tracing::info!(
            "Adding user to organization: user_id={}, organization_id={}, role={:?}",
            user_id,
            organization_id,
            role
        );

        self.organization_repository
            .set_user_organization(user_id, organization_id, role)
            .await?;

        // Add user to the default workspace
        if let Some(default_workspace) = self
            .workspace_repository
            .get_default_workspace(organization_id)
            .await?
        {
            self.workspace_repository
                .add_workspace_member(
                    default_workspace.id,
                    user_id,
                    crate::workspace::ports::WorkspaceRole::Member,
                )
                .await?;
        }

        tracing::info!(
            "User added to organization successfully: user_id={}, organization_id={}",
            user_id,
            organization_id
        );

        Ok(())
    }

    async fn remove_user_from_organization(
        &self,
        user_id: UserId,
        organization_id: OrganizationId,
    ) -> anyhow::Result<()> {
        tracing::warn!(
            "Removing user from organization: user_id={}, organization_id={}",
            user_id,
            organization_id
        );

        self.organization_repository
            .remove_user_from_organization(user_id, organization_id)
            .await?;

        tracing::info!(
            "User removed from organization successfully: user_id={}, organization_id={}",
            user_id,
            organization_id
        );

        Ok(())
    }

    async fn update_user_org_role(
        &self,
        user_id: UserId,
        organization_id: OrganizationId,
        role: OrgRole,
    ) -> anyhow::Result<()> {
        tracing::info!(
            "Updating user org role: user_id={}, organization_id={}, role={:?}",
            user_id,
            organization_id,
            role
        );

        self.organization_repository
            .set_user_organization(user_id, organization_id, role)
            .await
    }

    async fn is_slug_available(&self, slug: &str) -> anyhow::Result<bool> {
        self.organization_repository.is_slug_available(slug).await
    }

    async fn create_personal_organization(
        &self,
        user_id: UserId,
        email: &str,
        name: Option<&str>,
    ) -> anyhow::Result<Organization> {
        tracing::info!(
            "Creating personal organization for user: user_id={}",
            user_id
        );

        // Generate slug from email
        let base_slug = email
            .split('@')
            .next()
            .unwrap_or("user")
            .to_lowercase()
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '-' })
            .collect::<String>();

        // Find an available slug
        let mut slug = base_slug.clone();
        let mut counter = 0;
        while !self.organization_repository.is_slug_available(&slug).await? {
            counter += 1;
            slug = format!("{}-{}", base_slug, counter);
        }

        let display_name = name.unwrap_or_else(|| email.split('@').next().unwrap_or("User"));

        let params = CreateOrganizationParams {
            name: format!("{}'s Organization", display_name),
            slug,
            display_name: Some(display_name.to_string()),
            logo_url: None,
            plan_tier: PlanTier::Free,
            billing_email: Some(email.to_string()),
            settings: OrganizationSettings {
                personal: true,
                ..Default::default()
            },
        };

        self.create_organization(params, user_id).await
    }
}
