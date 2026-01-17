use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::Arc;

use super::ports::{
    CreateSamlConfigParams, SamlAuthResult, SamlAuthState, SamlAuthStateRepository,
    SamlAuthnRequest, SamlConfig, SamlIdpConfigRepository, SamlService, SamlSession,
    UpdateSamlConfigParams,
};
use crate::types::{OrganizationId, SessionId};

pub struct SamlServiceImpl {
    idp_config_repository: Arc<dyn SamlIdpConfigRepository>,
    auth_state_repository: Arc<dyn SamlAuthStateRepository>,
    sp_base_url: String,
}

impl SamlServiceImpl {
    pub fn new(
        idp_config_repository: Arc<dyn SamlIdpConfigRepository>,
        auth_state_repository: Arc<dyn SamlAuthStateRepository>,
        sp_base_url: String,
    ) -> Self {
        Self {
            idp_config_repository,
            auth_state_repository,
            sp_base_url,
        }
    }

    fn generate_request_id() -> String {
        format!("_{}_{}", uuid::Uuid::new_v4(), Utc::now().timestamp())
    }
}

#[async_trait]
impl SamlService for SamlServiceImpl {
    async fn get_saml_config(
        &self,
        organization_id: OrganizationId,
    ) -> anyhow::Result<Option<SamlConfig>> {
        tracing::info!(
            "Getting SAML config: organization_id={}",
            organization_id
        );

        self.idp_config_repository
            .get_saml_config(organization_id)
            .await
    }

    async fn upsert_saml_config(&self, params: CreateSamlConfigParams) -> anyhow::Result<SamlConfig> {
        tracing::info!(
            "Upserting SAML config: organization_id={}",
            params.organization_id
        );

        // Check if config already exists
        let existing = self
            .idp_config_repository
            .get_saml_config(params.organization_id)
            .await?;

        if existing.is_some() {
            // Update existing config
            let update_params = UpdateSamlConfigParams {
                idp_entity_id: Some(params.idp_entity_id),
                idp_sso_url: Some(params.idp_sso_url),
                idp_slo_url: params.idp_slo_url,
                idp_certificate: Some(params.idp_certificate),
                attribute_mapping: Some(params.attribute_mapping),
                jit_provisioning_enabled: Some(params.jit_provisioning_enabled),
                jit_default_role: Some(params.jit_default_role),
                jit_default_workspace_id: params.jit_default_workspace_id,
                is_enabled: None,
            };

            self.idp_config_repository
                .update_saml_config(params.organization_id, update_params)
                .await
        } else {
            // Create new config
            self.idp_config_repository.create_saml_config(params).await
        }
    }

    async fn update_saml_config(
        &self,
        organization_id: OrganizationId,
        params: UpdateSamlConfigParams,
    ) -> anyhow::Result<SamlConfig> {
        tracing::info!(
            "Updating SAML config: organization_id={}",
            organization_id
        );

        self.idp_config_repository
            .update_saml_config(organization_id, params)
            .await
    }

    async fn delete_saml_config(&self, organization_id: OrganizationId) -> anyhow::Result<()> {
        tracing::warn!(
            "Deleting SAML config: organization_id={}",
            organization_id
        );

        self.idp_config_repository
            .delete_saml_config(organization_id)
            .await
    }

    async fn set_saml_enabled(
        &self,
        organization_id: OrganizationId,
        enabled: bool,
    ) -> anyhow::Result<()> {
        tracing::info!(
            "Setting SAML enabled: organization_id={}, enabled={}",
            organization_id,
            enabled
        );

        let params = UpdateSamlConfigParams {
            is_enabled: Some(enabled),
            ..Default::default()
        };

        self.idp_config_repository
            .update_saml_config(organization_id, params)
            .await?;

        Ok(())
    }

    async fn create_authn_request(
        &self,
        organization_id: OrganizationId,
        relay_state: Option<String>,
    ) -> anyhow::Result<SamlAuthnRequest> {
        tracing::info!(
            "Creating SAML AuthnRequest: organization_id={}",
            organization_id
        );

        // Get SAML config
        let config = self
            .idp_config_repository
            .get_saml_config(organization_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("SAML is not configured for this organization"))?;

        if !config.is_enabled {
            return Err(anyhow::anyhow!("SAML is not enabled for this organization"));
        }

        // Generate request ID
        let request_id = Self::generate_request_id();

        // Store auth state for CSRF protection
        let state = SamlAuthState {
            id: request_id.clone(),
            organization_id,
            relay_state: relay_state.clone(),
            created_at: Utc::now(),
        };
        self.auth_state_repository.create_auth_state(state).await?;

        // Build redirect URL with SAML request
        // Note: In production, this would use the samael crate to build proper SAML XML
        let redirect_url = format!(
            "{}?SAMLRequest={}&RelayState={}",
            config.idp_sso_url,
            urlencoding::encode(&request_id),
            urlencoding::encode(&relay_state.unwrap_or_default())
        );

        Ok(SamlAuthnRequest {
            request_id,
            redirect_url,
        })
    }

    async fn process_saml_response(
        &self,
        _saml_response: &str,
        relay_state: Option<&str>,
    ) -> anyhow::Result<SamlAuthResult> {
        tracing::info!("Processing SAML response");

        // Consume the auth state to prevent replay attacks
        let state_id = relay_state.unwrap_or("");
        let _auth_state = self
            .auth_state_repository
            .consume_auth_state(state_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Invalid or expired SAML state"))?;

        // Note: In production, this would:
        // 1. Parse and validate the SAML response using samael crate
        // 2. Verify the signature against the IdP certificate
        // 3. Check assertion conditions (NotBefore, NotOnOrAfter, Audience)
        // 4. Extract attributes based on the attribute mapping

        // Placeholder implementation - in production use samael crate
        Err(anyhow::anyhow!(
            "SAML response processing requires samael crate integration"
        ))
    }

    async fn generate_sp_metadata(&self, organization_id: OrganizationId) -> anyhow::Result<String> {
        tracing::info!(
            "Generating SP metadata: organization_id={}",
            organization_id
        );

        let config = self
            .idp_config_repository
            .get_saml_config(organization_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("SAML is not configured for this organization"))?;

        // Generate SP metadata XML
        // Note: In production, use samael crate for proper XML generation
        let metadata = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="{}">
    <md:SPSSODescriptor
        AuthnRequestsSigned="true"
        WantAssertionsSigned="true"
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
        <md:AssertionConsumerService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="{}"
            index="0"
            isDefault="true"/>
    </md:SPSSODescriptor>
</md:EntityDescriptor>"#,
            config.sp_entity_id, config.sp_acs_url
        );

        Ok(metadata)
    }

    async fn create_saml_session(
        &self,
        session_id: SessionId,
        auth_result: &SamlAuthResult,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        tracing::info!(
            "Creating SAML session: session_id={}, organization_id={}",
            session_id,
            auth_result.organization_id
        );

        let saml_session = SamlSession {
            id: uuid::Uuid::new_v4(),
            session_id,
            organization_id: auth_result.organization_id,
            name_id: auth_result.name_id.clone(),
            name_id_format: auth_result.name_id_format.clone(),
            session_index: auth_result.session_index.clone(),
            idp_session_id: None,
            created_at: Utc::now(),
            expires_at,
        };

        self.auth_state_repository
            .create_saml_session(saml_session)
            .await
    }

    async fn handle_logout(&self, session_id: SessionId) -> anyhow::Result<Option<String>> {
        tracing::info!("Handling SAML logout: session_id={}", session_id);

        // Get SAML session
        let saml_session = self
            .auth_state_repository
            .get_saml_session(session_id)
            .await?;

        if let Some(session) = saml_session {
            // Get SAML config to check for SLO URL
            let config = self
                .idp_config_repository
                .get_saml_config(session.organization_id)
                .await?;

            // Delete SAML session
            self.auth_state_repository
                .delete_saml_session(session_id)
                .await?;

            // Return SLO URL if configured
            if let Some(config) = config {
                if let Some(slo_url) = config.idp_slo_url {
                    return Ok(Some(slo_url));
                }
            }
        }

        Ok(None)
    }
}
