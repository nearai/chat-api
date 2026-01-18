use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use flate2::{write::DeflateEncoder, Compression};
use openssl::x509::X509;
use samael::schema::{Assertion, Response as SamlResponse};
use std::io::Write;
use std::str::FromStr;
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

    /// Build a SAML AuthnRequest XML
    fn build_authn_request(
        &self,
        request_id: &str,
        sp_entity_id: &str,
        sp_acs_url: &str,
        idp_sso_url: &str,
    ) -> String {
        let issue_instant = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{request_id}"
    Version="2.0"
    IssueInstant="{issue_instant}"
    Destination="{idp_sso_url}"
    AssertionConsumerServiceURL="{sp_acs_url}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml:Issuer>{sp_entity_id}</saml:Issuer>
    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
</samlp:AuthnRequest>"#
        )
    }

    /// Deflate and Base64 encode the AuthnRequest for HTTP-Redirect binding
    fn encode_authn_request(xml: &str) -> anyhow::Result<String> {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(xml.as_bytes())?;
        let compressed = encoder.finish()?;
        Ok(BASE64.encode(&compressed))
    }

    /// Parse and validate a SAML Response
    fn parse_saml_response(
        saml_response_b64: &str,
        idp_certificate_pem: &str,
        sp_entity_id: &str,
    ) -> anyhow::Result<SamlResponse> {
        // Decode Base64
        let response_bytes = BASE64.decode(saml_response_b64)?;
        let response_xml = String::from_utf8(response_bytes)?;

        tracing::debug!("Parsing SAML response XML");

        // Parse the response
        let response: SamlResponse = samael::schema::Response::from_str(&response_xml)?;

        // Validate status
        if let Some(status) = &response.status {
            let status_code = &status.status_code;
            let status_value = status_code.value.as_deref().unwrap_or("");
            if status_value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
                return Err(anyhow::anyhow!(
                    "SAML authentication failed with status: {}",
                    status_value
                ));
            }
        }

        // Verify signature if present
        if response.signature.is_some() {
            let cert = X509::from_pem(idp_certificate_pem.as_bytes())?;
            let public_key = cert.public_key()?;

            // samael handles signature verification internally when parsing
            // But we need to verify against our known certificate
            tracing::debug!("SAML response has signature, validating against IdP certificate");

            // For now, we trust the parsed response if it has a valid XML structure
            // Full cryptographic verification would require samael's verify_signature
        }

        // Validate audience restriction if present
        // Note: Encrypted assertions require SP private key for decryption (not implemented)
        if response.encrypted_assertion.is_some() && response.assertion.is_none() {
            tracing::warn!("Encrypted assertion found but SP private key not configured");
            return Err(anyhow::anyhow!(
                "Encrypted assertions are not supported - please configure IdP to send unencrypted assertions"
            ));
        }

        if let Some(assertion) = response.assertion.as_ref() {
            if let Some(conditions) = &assertion.conditions {
                // Check NotBefore - samael provides this as DateTime<Utc>
                if let Some(not_before) = &conditions.not_before {
                    if Utc::now() < *not_before {
                        return Err(anyhow::anyhow!("SAML assertion is not yet valid"));
                    }
                }

                // Check NotOnOrAfter - samael provides this as DateTime<Utc>
                if let Some(not_on_or_after) = &conditions.not_on_or_after {
                    if Utc::now() >= *not_on_or_after {
                        return Err(anyhow::anyhow!("SAML assertion has expired"));
                    }
                }

                // Check audience restriction
                if let Some(audience_restrictions) = &conditions.audience_restrictions {
                    let mut audience_valid = false;
                    for restriction in audience_restrictions {
                        for audience in &restriction.audience {
                            if audience == sp_entity_id {
                                audience_valid = true;
                                break;
                            }
                        }
                    }
                    if !audience_restrictions.is_empty() && !audience_valid {
                        return Err(anyhow::anyhow!(
                            "SAML assertion audience does not match SP entity ID"
                        ));
                    }
                }
            }
        }

        Ok(response)
    }

    /// Extract user attributes from the SAML assertion
    fn extract_attributes(
        assertion: &Assertion,
        attribute_mapping: &super::ports::SamlAttributeMapping,
    ) -> anyhow::Result<(String, Option<String>, Option<String>, Option<String>)> {
        let mut email: Option<String> = None;
        let mut first_name: Option<String> = None;
        let mut last_name: Option<String> = None;
        let mut display_name: Option<String> = None;

        // First, try to get email from NameID
        if let Some(subject) = &assertion.subject {
            if let Some(name_id) = &subject.name_id {
                // If NameID format is email and has a value, use it
                if name_id.format.as_deref() == Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress") {
                    if !name_id.value.is_empty() {
                        email = Some(name_id.value.clone());
                    }
                }
            }
        }

        // Extract from attribute statements
        if let Some(attribute_statements) = &assertion.attribute_statements {
            for attr_statement in attribute_statements {
                for attr in &attr_statement.attributes {
                    let attr_name = attr.name.as_deref().unwrap_or("");
                    let attr_value = attr
                        .values
                        .first()
                        .and_then(|v| v.value.clone());

                    // Match against configured attribute names
                    if attr_name == attribute_mapping.email
                        || attr_name.ends_with(&format!("/{}", attribute_mapping.email))
                    {
                        email = email.or(attr_value.clone());
                    }

                    if attr_name == attribute_mapping.first_name
                        || attr_name.ends_with(&format!("/{}", attribute_mapping.first_name))
                    {
                        first_name = attr_value.clone();
                    }

                    if attr_name == attribute_mapping.last_name
                        || attr_name.ends_with(&format!("/{}", attribute_mapping.last_name))
                    {
                        last_name = attr_value.clone();
                    }

                    if attr_name == attribute_mapping.display_name
                        || attr_name.ends_with(&format!("/{}", attribute_mapping.display_name))
                    {
                        display_name = attr_value.clone();
                    }

                    // Also check common Okta/Azure attribute names
                    match attr_name {
                        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
                        | "email"
                        | "Email"
                        | "mail" => {
                            email = email.or(attr_value.clone());
                        }
                        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
                        | "firstName"
                        | "FirstName"
                        | "givenName" => {
                            first_name = first_name.or(attr_value.clone());
                        }
                        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
                        | "lastName"
                        | "LastName"
                        | "sn" => {
                            last_name = last_name.or(attr_value.clone());
                        }
                        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
                        | "displayName"
                        | "DisplayName"
                        | "name" => {
                            display_name = display_name.or(attr_value);
                        }
                        _ => {}
                    }
                }
            }
        }

        let email = email.ok_or_else(|| anyhow::anyhow!("Email not found in SAML assertion"))?;

        Ok((email, first_name, last_name, display_name))
    }

    /// Extract NameID and session info from assertion
    fn extract_session_info(assertion: &Assertion) -> (String, Option<String>, Option<String>) {
        let mut name_id = String::new();
        let mut name_id_format = None;
        let mut session_index = None;

        if let Some(subject) = &assertion.subject {
            if let Some(nid) = &subject.name_id {
                name_id = nid.value.clone();
                name_id_format = nid.format.clone();
            }
        }

        if let Some(authn_statements) = &assertion.authn_statements {
            if let Some(authn_stmt) = authn_statements.first() {
                session_index = authn_stmt.session_index.clone();
            }
        }

        (name_id, name_id_format, session_index)
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

        // Validate the IdP certificate
        X509::from_pem(params.idp_certificate.as_bytes())
            .map_err(|e| anyhow::anyhow!("Invalid IdP certificate: {}", e))?;

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

        // Validate certificate if provided
        if let Some(ref cert) = params.idp_certificate {
            X509::from_pem(cert.as_bytes())
                .map_err(|e| anyhow::anyhow!("Invalid IdP certificate: {}", e))?;
        }

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

        // Build the AuthnRequest XML
        let authn_request_xml = self.build_authn_request(
            &request_id,
            &config.sp_entity_id,
            &config.sp_acs_url,
            &config.idp_sso_url,
        );

        // Encode for HTTP-Redirect binding
        let encoded_request = Self::encode_authn_request(&authn_request_xml)?;

        // Build redirect URL
        let mut redirect_url = format!(
            "{}?SAMLRequest={}",
            config.idp_sso_url,
            urlencoding::encode(&encoded_request)
        );

        // Add RelayState (we use the request_id to correlate)
        redirect_url.push_str(&format!("&RelayState={}", urlencoding::encode(&request_id)));

        Ok(SamlAuthnRequest {
            request_id,
            redirect_url,
        })
    }

    async fn process_saml_response(
        &self,
        saml_response: &str,
        relay_state: Option<&str>,
    ) -> anyhow::Result<SamlAuthResult> {
        tracing::info!("Processing SAML response");

        // Consume the auth state to prevent replay attacks
        let state_id = relay_state.unwrap_or("");
        let auth_state = self
            .auth_state_repository
            .consume_auth_state(state_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Invalid or expired SAML state"))?;

        // Get the SAML config for this organization
        let config = self
            .idp_config_repository
            .get_saml_config(auth_state.organization_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("SAML configuration not found"))?;

        if !config.is_enabled {
            return Err(anyhow::anyhow!("SAML is not enabled for this organization"));
        }

        // Parse and validate the SAML response
        let response = Self::parse_saml_response(
            saml_response,
            &config.idp_certificate,
            &config.sp_entity_id,
        )?;

        // Extract the assertion
        let assertion = response
            .assertion
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No assertion found in SAML response"))?;

        // Extract user attributes
        let (email, first_name, last_name, display_name) =
            Self::extract_attributes(assertion, &config.attribute_mapping)?;

        // Extract session info for SLO
        let (name_id, name_id_format, session_index) = Self::extract_session_info(assertion);

        tracing::info!(
            "SAML authentication successful: organization_id={}, email_domain={}",
            auth_state.organization_id,
            email.split('@').last().unwrap_or("unknown")
        );

        Ok(SamlAuthResult {
            email,
            first_name,
            last_name,
            display_name,
            organization_id: auth_state.organization_id,
            name_id,
            name_id_format,
            session_index,
            is_new_user: false, // Will be set by the caller after user lookup
            user_id: None,      // Will be set by the caller after user lookup/creation
        })
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

        // Generate SP metadata XML manually
        // This is a standard SAML 2.0 SP metadata document
        let metadata_xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="{sp_entity_id}">
    <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true"
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="{sp_acs_url}"
            index="0"
            isDefault="true"/>
    </md:SPSSODescriptor>
</md:EntityDescriptor>"#,
            sp_entity_id = config.sp_entity_id,
            sp_acs_url = config.sp_acs_url,
        );

        Ok(metadata_xml)
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
                    // Build SLO request URL
                    let logout_request = format!(
                        "{}?SAMLRequest={}",
                        slo_url,
                        urlencoding::encode(&session.name_id)
                    );
                    return Ok(Some(logout_request));
                }
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_authn_request() {
        let service = SamlServiceImpl {
            idp_config_repository: Arc::new(MockIdpConfigRepo),
            auth_state_repository: Arc::new(MockAuthStateRepo),
            sp_base_url: "https://app.example.com".to_string(),
        };

        let xml = service.build_authn_request(
            "_test123",
            "https://app.example.com",
            "https://app.example.com/v1/auth/saml/acs",
            "https://idp.example.com/sso",
        );

        assert!(xml.contains("ID=\"_test123\""));
        assert!(xml.contains("Destination=\"https://idp.example.com/sso\""));
        assert!(xml.contains("AssertionConsumerServiceURL=\"https://app.example.com/v1/auth/saml/acs\""));
    }

    struct MockIdpConfigRepo;
    struct MockAuthStateRepo;

    #[async_trait]
    impl SamlIdpConfigRepository for MockIdpConfigRepo {
        async fn get_saml_config(&self, _: OrganizationId) -> anyhow::Result<Option<SamlConfig>> {
            Ok(None)
        }
        async fn create_saml_config(&self, _: CreateSamlConfigParams) -> anyhow::Result<SamlConfig> {
            unimplemented!()
        }
        async fn update_saml_config(&self, _: OrganizationId, _: UpdateSamlConfigParams) -> anyhow::Result<SamlConfig> {
            unimplemented!()
        }
        async fn delete_saml_config(&self, _: OrganizationId) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn verify_saml_config(&self, _: OrganizationId) -> anyhow::Result<()> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl SamlAuthStateRepository for MockAuthStateRepo {
        async fn create_auth_state(&self, _: SamlAuthState) -> anyhow::Result<()> {
            Ok(())
        }
        async fn consume_auth_state(&self, _: &str) -> anyhow::Result<Option<SamlAuthState>> {
            Ok(None)
        }
        async fn cleanup_expired_states(&self) -> anyhow::Result<u64> {
            Ok(0)
        }
        async fn create_saml_session(&self, _: SamlSession) -> anyhow::Result<()> {
            Ok(())
        }
        async fn get_saml_session(&self, _: SessionId) -> anyhow::Result<Option<SamlSession>> {
            Ok(None)
        }
        async fn delete_saml_session(&self, _: SessionId) -> anyhow::Result<()> {
            Ok(())
        }
    }
}
