use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::{OrganizationId, UserId};

/// Organization plan tiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlanTier {
    Free,
    Pro,
    Enterprise,
}

impl PlanTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            PlanTier::Free => "free",
            PlanTier::Pro => "pro",
            PlanTier::Enterprise => "enterprise",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "free" => Some(PlanTier::Free),
            "pro" => Some(PlanTier::Pro),
            "enterprise" => Some(PlanTier::Enterprise),
            _ => None,
        }
    }
}

impl Default for PlanTier {
    fn default() -> Self {
        PlanTier::Free
    }
}

/// Organization status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrganizationStatus {
    Active,
    Suspended,
    Deleted,
}

impl OrganizationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            OrganizationStatus::Active => "active",
            OrganizationStatus::Suspended => "suspended",
            OrganizationStatus::Deleted => "deleted",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "active" => Some(OrganizationStatus::Active),
            "suspended" => Some(OrganizationStatus::Suspended),
            "deleted" => Some(OrganizationStatus::Deleted),
            _ => None,
        }
    }
}

impl Default for OrganizationStatus {
    fn default() -> Self {
        OrganizationStatus::Active
    }
}

/// Organization role for a user within an organization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrgRole {
    Owner,
    Admin,
    Member,
}

impl OrgRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            OrgRole::Owner => "owner",
            OrgRole::Admin => "admin",
            OrgRole::Member => "member",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "owner" => Some(OrgRole::Owner),
            "admin" => Some(OrgRole::Admin),
            "member" => Some(OrgRole::Member),
            _ => None,
        }
    }
}

impl Default for OrgRole {
    fn default() -> Self {
        OrgRole::Member
    }
}

/// Organization settings stored as JSONB
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrganizationSettings {
    /// Whether this is a personal organization (auto-created for each user)
    #[serde(default)]
    pub personal: bool,

    /// Default model for the organization
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,

    /// Whether to enforce SSO for all users
    #[serde(default)]
    pub enforce_sso: bool,

    /// Allowed email domains for JIT provisioning
    #[serde(default)]
    pub allowed_email_domains: Vec<String>,
}

/// Represents an organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: OrganizationId,
    pub name: String,
    pub slug: String,
    pub display_name: Option<String>,
    pub logo_url: Option<String>,
    pub plan_tier: PlanTier,
    pub billing_email: Option<String>,
    pub settings: OrganizationSettings,
    pub status: OrganizationStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Parameters for creating an organization
#[derive(Debug, Clone)]
pub struct CreateOrganizationParams {
    pub name: String,
    pub slug: String,
    pub display_name: Option<String>,
    pub logo_url: Option<String>,
    pub plan_tier: PlanTier,
    pub billing_email: Option<String>,
    pub settings: OrganizationSettings,
}

/// Parameters for updating an organization
#[derive(Debug, Clone, Default)]
pub struct UpdateOrganizationParams {
    pub name: Option<String>,
    pub display_name: Option<String>,
    pub logo_url: Option<String>,
    pub billing_email: Option<String>,
    pub settings: Option<OrganizationSettings>,
}

/// Organization member with user details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationMember {
    pub user_id: UserId,
    pub email: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub org_role: OrgRole,
    pub joined_at: DateTime<Utc>,
}

/// Repository trait for organization operations
#[async_trait]
pub trait OrganizationRepository: Send + Sync {
    /// Get organization by ID
    async fn get_organization(
        &self,
        organization_id: OrganizationId,
    ) -> anyhow::Result<Option<Organization>>;

    /// Get organization by slug
    async fn get_organization_by_slug(&self, slug: &str) -> anyhow::Result<Option<Organization>>;

    /// Create a new organization
    async fn create_organization(
        &self,
        params: CreateOrganizationParams,
    ) -> anyhow::Result<Organization>;

    /// Update an organization
    async fn update_organization(
        &self,
        organization_id: OrganizationId,
        params: UpdateOrganizationParams,
    ) -> anyhow::Result<Organization>;

    /// Soft delete an organization
    async fn delete_organization(&self, organization_id: OrganizationId) -> anyhow::Result<()>;

    /// Get all organizations for a user
    async fn get_user_organizations(&self, user_id: UserId) -> anyhow::Result<Vec<Organization>>;

    /// Get organization members
    async fn get_organization_members(
        &self,
        organization_id: OrganizationId,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<OrganizationMember>, u64)>;

    /// Set user's organization and role
    async fn set_user_organization(
        &self,
        user_id: UserId,
        organization_id: OrganizationId,
        role: OrgRole,
    ) -> anyhow::Result<()>;

    /// Remove user from organization
    async fn remove_user_from_organization(
        &self,
        user_id: UserId,
        organization_id: OrganizationId,
    ) -> anyhow::Result<()>;

    /// Check if slug is available
    async fn is_slug_available(&self, slug: &str) -> anyhow::Result<bool>;

    /// Get user's current organization
    async fn get_user_organization(&self, user_id: UserId) -> anyhow::Result<Option<Organization>>;

    /// Get user's role in organization
    async fn get_user_org_role(
        &self,
        user_id: UserId,
        organization_id: OrganizationId,
    ) -> anyhow::Result<Option<OrgRole>>;
}

/// Service trait for organization operations
#[async_trait]
pub trait OrganizationService: Send + Sync {
    /// Get organization by ID
    async fn get_organization(
        &self,
        organization_id: OrganizationId,
    ) -> anyhow::Result<Organization>;

    /// Get organization by slug
    async fn get_organization_by_slug(&self, slug: &str) -> anyhow::Result<Organization>;

    /// Create a new organization
    async fn create_organization(
        &self,
        params: CreateOrganizationParams,
        creator_user_id: UserId,
    ) -> anyhow::Result<Organization>;

    /// Update an organization
    async fn update_organization(
        &self,
        organization_id: OrganizationId,
        params: UpdateOrganizationParams,
    ) -> anyhow::Result<Organization>;

    /// Delete an organization
    async fn delete_organization(&self, organization_id: OrganizationId) -> anyhow::Result<()>;

    /// Get all organizations for a user
    async fn get_user_organizations(&self, user_id: UserId) -> anyhow::Result<Vec<Organization>>;

    /// Get organization members with pagination
    async fn get_organization_members(
        &self,
        organization_id: OrganizationId,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<OrganizationMember>, u64)>;

    /// Add user to organization
    async fn add_user_to_organization(
        &self,
        user_id: UserId,
        organization_id: OrganizationId,
        role: OrgRole,
    ) -> anyhow::Result<()>;

    /// Remove user from organization
    async fn remove_user_from_organization(
        &self,
        user_id: UserId,
        organization_id: OrganizationId,
    ) -> anyhow::Result<()>;

    /// Update user's role in organization
    async fn update_user_org_role(
        &self,
        user_id: UserId,
        organization_id: OrganizationId,
        role: OrgRole,
    ) -> anyhow::Result<()>;

    /// Check if slug is available
    async fn is_slug_available(&self, slug: &str) -> anyhow::Result<bool>;

    /// Create a personal organization for a user
    async fn create_personal_organization(&self, user_id: UserId, email: &str, name: Option<&str>) -> anyhow::Result<Organization>;
}
