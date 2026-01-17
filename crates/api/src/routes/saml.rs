use crate::{error::ApiError, middleware::TenantContext, state::AppState};
use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use services::{
    saml::ports::{CreateSamlConfigParams, SamlAttributeMapping, SamlConfig, UpdateSamlConfigParams},
    OrganizationId, WorkspaceId,
};

// --- Request/Response types ---

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SamlConfigResponse {
    pub organization_id: OrganizationId,
    pub idp_entity_id: String,
    pub idp_sso_url: String,
    pub idp_slo_url: Option<String>,
    pub sp_entity_id: String,
    pub sp_acs_url: String,
    pub jit_provisioning_enabled: bool,
    pub jit_default_role: String,
    pub is_enabled: bool,
    pub is_verified: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl From<SamlConfig> for SamlConfigResponse {
    fn from(c: SamlConfig) -> Self {
        Self {
            organization_id: c.organization_id,
            idp_entity_id: c.idp_entity_id,
            idp_sso_url: c.idp_sso_url,
            idp_slo_url: c.idp_slo_url,
            sp_entity_id: c.sp_entity_id,
            sp_acs_url: c.sp_acs_url,
            jit_provisioning_enabled: c.jit_provisioning_enabled,
            jit_default_role: c.jit_default_role,
            is_enabled: c.is_enabled,
            is_verified: c.is_verified,
            created_at: c.created_at.to_rfc3339(),
            updated_at: c.updated_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateSamlConfigRequest {
    /// IdP Entity ID
    pub idp_entity_id: String,
    /// IdP SSO URL
    pub idp_sso_url: String,
    /// IdP SLO URL (optional)
    pub idp_slo_url: Option<String>,
    /// IdP Certificate (PEM format)
    pub idp_certificate: String,
    /// SP Entity ID
    pub sp_entity_id: String,
    /// SP ACS URL
    pub sp_acs_url: String,
    /// Enable JIT provisioning
    pub jit_provisioning_enabled: Option<bool>,
    /// Default role for JIT-provisioned users
    pub jit_default_role: Option<String>,
    /// Default workspace for JIT-provisioned users
    pub jit_default_workspace_id: Option<WorkspaceId>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateSamlConfigRequest {
    /// IdP Entity ID
    pub idp_entity_id: Option<String>,
    /// IdP SSO URL
    pub idp_sso_url: Option<String>,
    /// IdP SLO URL
    pub idp_slo_url: Option<String>,
    /// IdP Certificate (PEM format)
    pub idp_certificate: Option<String>,
    /// Enable JIT provisioning
    pub jit_provisioning_enabled: Option<bool>,
    /// Default role for JIT-provisioned users
    pub jit_default_role: Option<String>,
    /// Enable/disable SAML
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct SamlLoginQuery {
    pub relay_state: Option<String>,
}

// --- Handlers ---

/// Get SAML configuration for organization
#[utoipa::path(
    get,
    path = "/v1/admin/saml",
    tag = "SAML SSO",
    responses(
        (status = 200, description = "SAML configuration", body = SamlConfigResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Not found", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn get_saml_config(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
) -> Result<Json<SamlConfigResponse>, ApiError> {
    tracing::info!(
        "Getting SAML config: organization_id={}, user_id={}",
        tenant.organization_id,
        tenant.user_id
    );

    // Check permission
    if !tenant.permissions.contains(&"saml:read".to_string()) {
        return Err(ApiError::forbidden("Missing permission to view SAML configuration"));
    }

    let saml_service = app_state.saml_service.as_ref().ok_or_else(|| {
        ApiError::internal_server_error("SAML SSO is not configured for this deployment")
    })?;

    let config = saml_service
        .get_saml_config(tenant.organization_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get SAML config: {}", e);
            ApiError::internal_server_error("Failed to get SAML configuration")
        })?
        .ok_or_else(|| ApiError::not_found("SAML configuration not found"))?;

    Ok(Json(config.into()))
}

/// Create SAML configuration
#[utoipa::path(
    post,
    path = "/v1/admin/saml",
    tag = "SAML SSO",
    request_body = CreateSamlConfigRequest,
    responses(
        (status = 201, description = "SAML configuration created", body = SamlConfigResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn create_saml_config(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Json(request): Json<CreateSamlConfigRequest>,
) -> Result<(StatusCode, Json<SamlConfigResponse>), ApiError> {
    tracing::info!(
        "Creating SAML config: organization_id={}, user_id={}",
        tenant.organization_id,
        tenant.user_id
    );

    // Check permission
    if !tenant.permissions.contains(&"saml:manage".to_string()) {
        return Err(ApiError::forbidden("Missing permission to manage SAML configuration"));
    }

    let saml_service = app_state.saml_service.as_ref().ok_or_else(|| {
        ApiError::internal_server_error("SAML SSO is not configured for this deployment")
    })?;

    let params = CreateSamlConfigParams {
        organization_id: tenant.organization_id,
        idp_entity_id: request.idp_entity_id,
        idp_sso_url: request.idp_sso_url,
        idp_slo_url: request.idp_slo_url,
        idp_certificate: request.idp_certificate,
        sp_entity_id: request.sp_entity_id,
        sp_acs_url: request.sp_acs_url,
        attribute_mapping: SamlAttributeMapping::default(),
        jit_provisioning_enabled: request.jit_provisioning_enabled.unwrap_or(true),
        jit_default_role: request.jit_default_role.unwrap_or_else(|| "member".to_string()),
        jit_default_workspace_id: request.jit_default_workspace_id,
    };

    let config = saml_service.upsert_saml_config(params).await.map_err(|e| {
        tracing::error!("Failed to create SAML config: {}", e);
        if e.to_string().contains("already exists") {
            ApiError::bad_request("SAML configuration already exists for this organization")
        } else if e.to_string().contains("invalid") {
            ApiError::bad_request(&e.to_string())
        } else {
            ApiError::internal_server_error("Failed to create SAML configuration")
        }
    })?;

    Ok((StatusCode::CREATED, Json(config.into())))
}

/// Update SAML configuration
#[utoipa::path(
    put,
    path = "/v1/admin/saml",
    tag = "SAML SSO",
    request_body = UpdateSamlConfigRequest,
    responses(
        (status = 200, description = "SAML configuration updated", body = SamlConfigResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Not found", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn update_saml_config(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Json(request): Json<UpdateSamlConfigRequest>,
) -> Result<Json<SamlConfigResponse>, ApiError> {
    tracing::info!(
        "Updating SAML config: organization_id={}, user_id={}",
        tenant.organization_id,
        tenant.user_id
    );

    // Check permission
    if !tenant.permissions.contains(&"saml:manage".to_string()) {
        return Err(ApiError::forbidden("Missing permission to manage SAML configuration"));
    }

    let saml_service = app_state.saml_service.as_ref().ok_or_else(|| {
        ApiError::internal_server_error("SAML SSO is not configured for this deployment")
    })?;

    let params = UpdateSamlConfigParams {
        idp_entity_id: request.idp_entity_id,
        idp_sso_url: request.idp_sso_url,
        idp_slo_url: request.idp_slo_url,
        idp_certificate: request.idp_certificate,
        attribute_mapping: None,
        jit_provisioning_enabled: request.jit_provisioning_enabled,
        jit_default_role: request.jit_default_role,
        jit_default_workspace_id: None,
        is_enabled: request.is_enabled,
    };

    let config = saml_service
        .update_saml_config(tenant.organization_id, params)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update SAML config: {}", e);
            if e.to_string().contains("not found") {
                ApiError::not_found("SAML configuration not found")
            } else if e.to_string().contains("invalid") {
                ApiError::bad_request(&e.to_string())
            } else {
                ApiError::internal_server_error("Failed to update SAML configuration")
            }
        })?;

    Ok(Json(config.into()))
}

/// Delete SAML configuration
#[utoipa::path(
    delete,
    path = "/v1/admin/saml",
    tag = "SAML SSO",
    responses(
        (status = 204, description = "SAML configuration deleted"),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Not found", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn delete_saml_config(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
) -> Result<StatusCode, ApiError> {
    tracing::warn!(
        "Deleting SAML config: organization_id={}, user_id={}",
        tenant.organization_id,
        tenant.user_id
    );

    // Check permission
    if !tenant.permissions.contains(&"saml:manage".to_string()) {
        return Err(ApiError::forbidden("Missing permission to manage SAML configuration"));
    }

    let saml_service = app_state.saml_service.as_ref().ok_or_else(|| {
        ApiError::internal_server_error("SAML SSO is not configured for this deployment")
    })?;

    saml_service
        .delete_saml_config(tenant.organization_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete SAML config: {}", e);
            if e.to_string().contains("not found") {
                ApiError::not_found("SAML configuration not found")
            } else {
                ApiError::internal_server_error("Failed to delete SAML configuration")
            }
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Get SP metadata for organization
#[utoipa::path(
    get,
    path = "/v1/auth/saml/{org_slug}/metadata",
    tag = "SAML SSO",
    params(
        ("org_slug" = String, Path, description = "Organization slug")
    ),
    responses(
        (status = 200, description = "SP metadata XML"),
        (status = 404, description = "Not found", body = crate::error::ApiErrorResponse),
    )
)]
pub async fn get_sp_metadata(
    State(app_state): State<AppState>,
    Path(org_slug): Path<String>,
) -> Result<Response, ApiError> {
    tracing::info!("Getting SP metadata for org_slug={}", org_slug);

    let saml_service = app_state.saml_service.as_ref().ok_or_else(|| {
        ApiError::internal_server_error("SAML SSO is not configured for this deployment")
    })?;

    // Get organization by slug
    let organization = app_state
        .organization_service
        .get_organization_by_slug(&org_slug)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get organization: {}", e);
            ApiError::not_found("Organization not found")
        })?;

    let metadata_xml = saml_service
        .generate_sp_metadata(organization.id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get SP metadata: {}", e);
            ApiError::internal_server_error("Failed to get SP metadata")
        })?;

    // Return XML with proper content type
    Ok((
        StatusCode::OK,
        [("Content-Type", "application/xml")],
        metadata_xml,
    )
        .into_response())
}

/// Initiate SP-initiated SSO
#[utoipa::path(
    get,
    path = "/v1/auth/saml/{org_slug}/login",
    tag = "SAML SSO",
    params(
        ("org_slug" = String, Path, description = "Organization slug"),
        ("relay_state" = Option<String>, Query, description = "URL to redirect to after login")
    ),
    responses(
        (status = 302, description = "Redirect to IdP"),
        (status = 404, description = "Not found", body = crate::error::ApiErrorResponse),
    )
)]
pub async fn saml_login(
    State(app_state): State<AppState>,
    Path(org_slug): Path<String>,
    Query(params): Query<SamlLoginQuery>,
) -> Result<Response, ApiError> {
    tracing::info!("SAML login initiated for org_slug={}", org_slug);

    let saml_service = app_state.saml_service.as_ref().ok_or_else(|| {
        ApiError::internal_server_error("SAML SSO is not configured for this deployment")
    })?;

    // Get organization by slug
    let organization = app_state
        .organization_service
        .get_organization_by_slug(&org_slug)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get organization: {}", e);
            ApiError::not_found("Organization not found")
        })?;

    let authn_request = saml_service
        .create_authn_request(organization.id, params.relay_state)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create SAML AuthnRequest: {}", e);
            if e.to_string().contains("not configured") {
                ApiError::not_found("SAML is not configured for this organization")
            } else {
                ApiError::internal_server_error("Failed to initiate SAML login")
            }
        })?;

    Ok(Redirect::temporary(&authn_request.redirect_url).into_response())
}

/// SAML Assertion Consumer Service (ACS) - handles POST from IdP
#[utoipa::path(
    post,
    path = "/v1/auth/saml/acs",
    tag = "SAML SSO",
    responses(
        (status = 302, description = "Redirect to application"),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
    )
)]
pub async fn saml_acs(
    State(app_state): State<AppState>,
    axum::Form(form): axum::Form<std::collections::HashMap<String, String>>,
) -> Result<Response, ApiError> {
    tracing::info!("SAML ACS callback received");

    let saml_service = app_state.saml_service.as_ref().ok_or_else(|| {
        ApiError::internal_server_error("SAML SSO is not configured for this deployment")
    })?;

    let saml_response = form.get("SAMLResponse").ok_or_else(|| {
        ApiError::bad_request("Missing SAMLResponse in form data")
    })?;

    let relay_state = form.get("RelayState").map(|s| s.as_str());

    let auth_result = saml_service
        .process_saml_response(saml_response, relay_state)
        .await
        .map_err(|e| {
            tracing::error!("Failed to process SAML response: {}", e);
            if e.to_string().contains("invalid") || e.to_string().contains("expired") {
                ApiError::bad_request(&format!("SAML authentication failed: {}", e))
            } else {
                ApiError::internal_server_error("Failed to process SAML authentication")
            }
        })?;

    tracing::info!(
        "SAML authentication successful: email={}, is_new_user={}",
        auth_result.email,
        auth_result.is_new_user
    );

    // For now, redirect to the relay state or home
    // A full implementation would create a session here
    let redirect_location = relay_state.unwrap_or("/");

    Ok(Redirect::temporary(redirect_location).into_response())
}

/// Create SAML admin router (requires auth + tenant middleware)
pub fn create_saml_admin_router() -> Router<AppState> {
    Router::new().route(
        "/",
        get(get_saml_config)
            .post(create_saml_config)
            .put(update_saml_config)
            .delete(delete_saml_config),
    )
}

/// Create SAML auth router (public routes for SSO flow)
pub fn create_saml_auth_router() -> Router<AppState> {
    Router::new()
        .route("/{org_slug}/metadata", get(get_sp_metadata))
        .route("/{org_slug}/login", get(saml_login))
        .route("/acs", post(saml_acs))
}
