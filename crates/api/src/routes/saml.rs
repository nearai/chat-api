use crate::{error::ApiError, middleware::TenantContext, state::AppState};
use axum::{
    extract::{Extension, Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use services::{
    organization::ports::OrgRole,
    saml::ports::{CreateSamlConfigParams, SamlAttributeMapping, SamlConfig, UpdateSamlConfigParams},
    workspace::ports::WorkspaceRole,
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
    /// Attribute mapping configuration
    pub attribute_mapping: Option<SamlAttributeMappingRequest>,
    /// Enable JIT provisioning
    pub jit_provisioning_enabled: Option<bool>,
    /// Default role for JIT-provisioned users
    pub jit_default_role: Option<String>,
    /// Default workspace for JIT-provisioned users
    pub jit_default_workspace_id: Option<WorkspaceId>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SamlAttributeMappingRequest {
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub display_name: Option<String>,
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
    /// Attribute mapping configuration
    pub attribute_mapping: Option<SamlAttributeMappingRequest>,
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

    let attribute_mapping = if let Some(mapping) = request.attribute_mapping {
        SamlAttributeMapping {
            email: mapping.email.unwrap_or_else(|| "email".to_string()),
            first_name: mapping.first_name.unwrap_or_else(|| "firstName".to_string()),
            last_name: mapping.last_name.unwrap_or_else(|| "lastName".to_string()),
            display_name: mapping.display_name.unwrap_or_else(|| "displayName".to_string()),
        }
    } else {
        SamlAttributeMapping::default()
    };

    let params = CreateSamlConfigParams {
        organization_id: tenant.organization_id,
        idp_entity_id: request.idp_entity_id,
        idp_sso_url: request.idp_sso_url,
        idp_slo_url: request.idp_slo_url,
        idp_certificate: request.idp_certificate,
        sp_entity_id: request.sp_entity_id,
        sp_acs_url: request.sp_acs_url,
        attribute_mapping,
        jit_provisioning_enabled: request.jit_provisioning_enabled.unwrap_or(true),
        jit_default_role: request.jit_default_role.unwrap_or_else(|| "member".to_string()),
        jit_default_workspace_id: request.jit_default_workspace_id,
    };

    let config = saml_service.upsert_saml_config(params).await.map_err(|e| {
        tracing::error!("Failed to create SAML config: {}", e);
        if e.to_string().contains("already exists") {
            ApiError::bad_request("SAML configuration already exists for this organization")
        } else if e.to_string().contains("Invalid") {
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

    let attribute_mapping = request.attribute_mapping.map(|mapping| SamlAttributeMapping {
        email: mapping.email.unwrap_or_else(|| "email".to_string()),
        first_name: mapping.first_name.unwrap_or_else(|| "firstName".to_string()),
        last_name: mapping.last_name.unwrap_or_else(|| "lastName".to_string()),
        display_name: mapping.display_name.unwrap_or_else(|| "displayName".to_string()),
    });

    let params = UpdateSamlConfigParams {
        idp_entity_id: request.idp_entity_id,
        idp_sso_url: request.idp_sso_url,
        idp_slo_url: request.idp_slo_url,
        idp_certificate: request.idp_certificate,
        attribute_mapping,
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
            } else if e.to_string().contains("Invalid") {
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

    // Process the SAML response
    let mut auth_result = saml_service
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

    // Get SAML config for JIT provisioning settings
    let saml_config = saml_service
        .get_saml_config(auth_result.organization_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get SAML config: {}", e);
            ApiError::internal_server_error("Failed to get SAML configuration")
        })?
        .ok_or_else(|| ApiError::internal_server_error("SAML configuration not found"))?;

    // Look up or create user
    let existing_user = app_state
        .user_repository
        .get_user_by_email(&auth_result.email)
        .await
        .map_err(|e| {
            tracing::error!("Failed to look up user: {}", e);
            ApiError::internal_server_error("Failed to look up user")
        })?;

    let (user_id, is_new_user) = match existing_user {
        Some(user) => {
            tracing::info!(
                "SAML auth: existing user found, user_id={}",
                user.id
            );
            (user.id, false)
        }
        None => {
            // JIT provisioning
            if !saml_config.jit_provisioning_enabled {
                return Err(ApiError::forbidden(
                    "User not found and JIT provisioning is disabled",
                ));
            }

            tracing::info!(
                "SAML auth: JIT provisioning new user, email_domain={}",
                auth_result.email.split('@').last().unwrap_or("unknown")
            );

            // Build display name from attributes
            let display_name = auth_result
                .display_name
                .clone()
                .or_else(|| {
                    match (&auth_result.first_name, &auth_result.last_name) {
                        (Some(f), Some(l)) => Some(format!("{} {}", f, l)),
                        (Some(f), None) => Some(f.clone()),
                        (None, Some(l)) => Some(l.clone()),
                        _ => None,
                    }
                });

            // Create user via the repository
            let new_user = app_state
                .user_repository
                .create_user(
                    auth_result.email.clone(),
                    display_name,
                    None, // No avatar URL from SAML
                )
                .await
                .map_err(|e| {
                    tracing::error!("Failed to create user via JIT: {}", e);
                    ApiError::internal_server_error("Failed to create user")
                })?;

            // Parse the JIT default role
            let org_role = match saml_config.jit_default_role.as_str() {
                "owner" => OrgRole::Owner,
                "admin" => OrgRole::Admin,
                _ => OrgRole::Member,
            };

            // Add user to organization
            app_state
                .organization_service
                .add_user_to_organization(new_user.id, auth_result.organization_id, org_role)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to add user to organization: {}", e);
                    ApiError::internal_server_error("Failed to assign user to organization")
                })?;

            // Add to default workspace if configured
            if let Some(workspace_id) = saml_config.jit_default_workspace_id {
                if let Err(e) = app_state
                    .workspace_service
                    .add_workspace_member(workspace_id, new_user.id, WorkspaceRole::Member)
                    .await
                {
                    // Non-fatal - log but continue
                    tracing::warn!("Failed to add user to default workspace: {}", e);
                }
            }

            (new_user.id, true)
        }
    };

    auth_result.user_id = Some(user_id);
    auth_result.is_new_user = is_new_user;

    // Create app session
    let session = app_state
        .session_repository
        .create_session(user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create session: {}", e);
            ApiError::internal_server_error("Failed to create session")
        })?;

    // Create SAML session for SLO support
    let session_expires_at = Utc::now() + Duration::days(7);
    saml_service
        .create_saml_session(session.session_id, &auth_result, session_expires_at)
        .await
        .map_err(|e| {
            tracing::warn!("Failed to create SAML session (non-fatal): {}", e);
            // Non-fatal - SLO won't work but login should succeed
        })
        .ok();

    tracing::info!(
        "SAML authentication successful: user_id={}, is_new_user={}, organization_id={}",
        user_id,
        is_new_user,
        auth_result.organization_id
    );

    // Build redirect response with session cookie
    let session_token = session.token.unwrap_or_default();
    let redirect_location = "/"; // Default redirect

    // Set cookie and redirect
    let cookie_value = format!(
        "session_token={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        session_token,
        60 * 60 * 24 * 7 // 7 days
    );

    Ok((
        StatusCode::FOUND,
        [
            (header::LOCATION, redirect_location),
            (header::SET_COOKIE, &cookie_value),
        ],
        "",
    )
        .into_response())
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
