use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::{OrganizationId, SessionId, UserId, WorkspaceId};

/// Attribute mapping for SAML responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAttributeMapping {
    #[serde(default = "default_email")]
    pub email: String,
    #[serde(default = "default_first_name")]
    pub first_name: String,
    #[serde(default = "default_last_name")]
    pub last_name: String,
    #[serde(default = "default_display_name")]
    pub display_name: String,
}

fn default_email() -> String {
    "email".to_string()
}

fn default_first_name() -> String {
    "firstName".to_string()
}

fn default_last_name() -> String {
    "lastName".to_string()
}

fn default_display_name() -> String {
    "displayName".to_string()
}

impl Default for SamlAttributeMapping {
    fn default() -> Self {
        Self {
            email: default_email(),
            first_name: default_first_name(),
            last_name: default_last_name(),
            display_name: default_display_name(),
        }
    }
}

/// SAML IdP configuration for an organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlConfig {
    pub id: uuid::Uuid,
    pub organization_id: OrganizationId,

    // IdP configuration
    pub idp_entity_id: String,
    pub idp_sso_url: String,
    pub idp_slo_url: Option<String>,
    pub idp_certificate: String,

    // SP configuration
    pub sp_entity_id: String,
    pub sp_acs_url: String,

    // Attribute mapping
    pub attribute_mapping: SamlAttributeMapping,

    // JIT provisioning
    pub jit_provisioning_enabled: bool,
    pub jit_default_role: String,
    pub jit_default_workspace_id: Option<WorkspaceId>,

    // Status
    pub is_enabled: bool,
    pub is_verified: bool,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Parameters for creating/updating SAML config
#[derive(Debug, Clone)]
pub struct CreateSamlConfigParams {
    pub organization_id: OrganizationId,
    pub idp_entity_id: String,
    pub idp_sso_url: String,
    pub idp_slo_url: Option<String>,
    pub idp_certificate: String,
    pub sp_entity_id: String,
    pub sp_acs_url: String,
    pub attribute_mapping: SamlAttributeMapping,
    pub jit_provisioning_enabled: bool,
    pub jit_default_role: String,
    pub jit_default_workspace_id: Option<WorkspaceId>,
}

#[derive(Debug, Clone, Default)]
pub struct UpdateSamlConfigParams {
    pub idp_entity_id: Option<String>,
    pub idp_sso_url: Option<String>,
    pub idp_slo_url: Option<String>,
    pub idp_certificate: Option<String>,
    pub attribute_mapping: Option<SamlAttributeMapping>,
    pub jit_provisioning_enabled: Option<bool>,
    pub jit_default_role: Option<String>,
    pub jit_default_workspace_id: Option<WorkspaceId>,
    pub is_enabled: Option<bool>,
}

/// SAML session (for SLO support)
#[derive(Debug, Clone)]
pub struct SamlSession {
    pub id: uuid::Uuid,
    pub session_id: SessionId,
    pub organization_id: OrganizationId,
    pub name_id: String,
    pub name_id_format: Option<String>,
    pub session_index: Option<String>,
    pub idp_session_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// SAML authentication state (for CSRF protection)
#[derive(Debug, Clone)]
pub struct SamlAuthState {
    pub id: String,
    pub organization_id: OrganizationId,
    pub relay_state: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Result of processing a SAML response
#[derive(Debug, Clone)]
pub struct SamlAuthResult {
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub display_name: Option<String>,
    pub organization_id: OrganizationId,
    pub name_id: String,
    pub name_id_format: Option<String>,
    pub session_index: Option<String>,
    /// Whether this is a new user that was JIT provisioned
    pub is_new_user: bool,
    /// User ID (existing or newly created)
    pub user_id: Option<UserId>,
}

/// SAML AuthnRequest data
#[derive(Debug, Clone)]
pub struct SamlAuthnRequest {
    pub request_id: String,
    pub redirect_url: String,
}

/// Repository trait for SAML IdP configurations
#[async_trait]
pub trait SamlIdpConfigRepository: Send + Sync {
    /// Get SAML config for an organization
    async fn get_saml_config(
        &self,
        organization_id: OrganizationId,
    ) -> anyhow::Result<Option<SamlConfig>>;

    /// Create SAML config
    async fn create_saml_config(&self, params: CreateSamlConfigParams) -> anyhow::Result<SamlConfig>;

    /// Update SAML config
    async fn update_saml_config(
        &self,
        organization_id: OrganizationId,
        params: UpdateSamlConfigParams,
    ) -> anyhow::Result<SamlConfig>;

    /// Delete SAML config
    async fn delete_saml_config(&self, organization_id: OrganizationId) -> anyhow::Result<()>;

    /// Mark SAML config as verified
    async fn verify_saml_config(&self, organization_id: OrganizationId) -> anyhow::Result<()>;
}

/// Repository trait for SAML authentication state
#[async_trait]
pub trait SamlAuthStateRepository: Send + Sync {
    /// Create auth state for CSRF protection
    async fn create_auth_state(&self, state: SamlAuthState) -> anyhow::Result<()>;

    /// Get and consume auth state
    async fn consume_auth_state(&self, state_id: &str) -> anyhow::Result<Option<SamlAuthState>>;

    /// Clean up expired states
    async fn cleanup_expired_states(&self) -> anyhow::Result<u64>;

    /// Create SAML session
    async fn create_saml_session(&self, session: SamlSession) -> anyhow::Result<()>;

    /// Get SAML session by app session ID
    async fn get_saml_session(&self, session_id: SessionId) -> anyhow::Result<Option<SamlSession>>;

    /// Delete SAML session
    async fn delete_saml_session(&self, session_id: SessionId) -> anyhow::Result<()>;
}

/// Service trait for SAML operations
#[async_trait]
pub trait SamlService: Send + Sync {
    /// Get SAML config for an organization
    async fn get_saml_config(
        &self,
        organization_id: OrganizationId,
    ) -> anyhow::Result<Option<SamlConfig>>;

    /// Create or update SAML config
    async fn upsert_saml_config(&self, params: CreateSamlConfigParams) -> anyhow::Result<SamlConfig>;

    /// Update SAML config
    async fn update_saml_config(
        &self,
        organization_id: OrganizationId,
        params: UpdateSamlConfigParams,
    ) -> anyhow::Result<SamlConfig>;

    /// Delete SAML config
    async fn delete_saml_config(&self, organization_id: OrganizationId) -> anyhow::Result<()>;

    /// Enable/disable SAML for an organization
    async fn set_saml_enabled(
        &self,
        organization_id: OrganizationId,
        enabled: bool,
    ) -> anyhow::Result<()>;

    /// Create SAML authentication request (SP-initiated SSO)
    async fn create_authn_request(
        &self,
        organization_id: OrganizationId,
        relay_state: Option<String>,
    ) -> anyhow::Result<SamlAuthnRequest>;

    /// Process SAML response from IdP
    async fn process_saml_response(
        &self,
        saml_response: &str,
        relay_state: Option<&str>,
    ) -> anyhow::Result<SamlAuthResult>;

    /// Generate SP metadata XML
    async fn generate_sp_metadata(&self, organization_id: OrganizationId) -> anyhow::Result<String>;

    /// Create SAML session after successful authentication
    async fn create_saml_session(
        &self,
        session_id: SessionId,
        auth_result: &SamlAuthResult,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<()>;

    /// Handle Single Logout (SLO)
    async fn handle_logout(&self, session_id: SessionId) -> anyhow::Result<Option<String>>;
}
