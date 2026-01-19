use crate::{error::ApiError, middleware::TenantContext, state::AppState};
use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    routing::{delete, get},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use services::{
    organization::ports::{
        CreateOrganizationParams, OrgRole, Organization, OrganizationMember,
        OrganizationSettings, PlanTier, UpdateOrganizationParams,
    },
    OrganizationId, UserId,
};

use super::admin::PaginationQuery;

// --- Request/Response types ---

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OrganizationResponse {
    pub id: OrganizationId,
    pub name: String,
    pub slug: String,
    pub display_name: Option<String>,
    pub logo_url: Option<String>,
    pub plan_tier: String,
    pub billing_email: Option<String>,
    pub settings: OrganizationSettingsResponse,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OrganizationSettingsResponse {
    pub personal: bool,
    pub default_model: Option<String>,
    pub enforce_sso: bool,
    pub allowed_email_domains: Vec<String>,
}

impl From<Organization> for OrganizationResponse {
    fn from(org: Organization) -> Self {
        Self {
            id: org.id,
            name: org.name,
            slug: org.slug,
            display_name: org.display_name,
            logo_url: org.logo_url,
            plan_tier: org.plan_tier.as_str().to_string(),
            billing_email: org.billing_email,
            settings: OrganizationSettingsResponse {
                personal: org.settings.personal,
                default_model: org.settings.default_model,
                enforce_sso: org.settings.enforce_sso,
                allowed_email_domains: org.settings.allowed_email_domains,
            },
            status: org.status.as_str().to_string(),
            created_at: org.created_at.to_rfc3339(),
            updated_at: org.updated_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateOrganizationRequest {
    pub name: String,
    pub slug: String,
    pub display_name: Option<String>,
    pub logo_url: Option<String>,
    pub billing_email: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateOrganizationRequest {
    pub name: Option<String>,
    pub display_name: Option<String>,
    pub logo_url: Option<String>,
    pub billing_email: Option<String>,
    pub settings: Option<UpdateOrganizationSettingsRequest>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateOrganizationSettingsRequest {
    pub default_model: Option<String>,
    pub enforce_sso: Option<bool>,
    pub allowed_email_domains: Option<Vec<String>>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct OrganizationListResponse {
    pub organizations: Vec<OrganizationResponse>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OrganizationMemberResponse {
    pub user_id: UserId,
    pub email: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub org_role: String,
    pub joined_at: String,
}

impl From<OrganizationMember> for OrganizationMemberResponse {
    fn from(member: OrganizationMember) -> Self {
        Self {
            user_id: member.user_id,
            email: member.email,
            name: member.name,
            avatar_url: member.avatar_url,
            org_role: member.org_role.as_str().to_string(),
            joined_at: member.joined_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct OrganizationMemberListResponse {
    pub members: Vec<OrganizationMemberResponse>,
    pub limit: i64,
    pub offset: i64,
    pub total: u64,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AddMemberRequest {
    pub user_id: UserId,
    pub role: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateMemberRoleRequest {
    pub role: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SlugAvailabilityResponse {
    pub available: bool,
}

// --- Handlers ---

/// List user's organizations
#[utoipa::path(
    get,
    path = "/v1/organizations",
    tag = "Organizations",
    responses(
        (status = 200, description = "List of organizations", body = OrganizationListResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn list_organizations(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
) -> Result<Json<OrganizationListResponse>, ApiError> {
    tracing::info!("Listing organizations for user_id={}", tenant.user_id);

    let organizations = app_state
        .organization_service
        .get_user_organizations(tenant.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list organizations: {}", e);
            ApiError::internal_server_error("Failed to list organizations")
        })?;

    Ok(Json(OrganizationListResponse {
        organizations: organizations.into_iter().map(Into::into).collect(),
    }))
}

/// Create a new organization
#[utoipa::path(
    post,
    path = "/v1/organizations",
    tag = "Organizations",
    request_body = CreateOrganizationRequest,
    responses(
        (status = 201, description = "Organization created", body = OrganizationResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn create_organization(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Json(request): Json<CreateOrganizationRequest>,
) -> Result<(StatusCode, Json<OrganizationResponse>), ApiError> {
    tracing::info!(
        "Creating organization: name={}, slug={}, user_id={}",
        request.name,
        request.slug,
        tenant.user_id
    );

    // Validate slug format
    if !is_valid_slug(&request.slug) {
        return Err(ApiError::bad_request(
            "Slug must contain only lowercase letters, numbers, and hyphens",
        ));
    }

    let params = CreateOrganizationParams {
        name: request.name,
        slug: request.slug,
        display_name: request.display_name,
        logo_url: request.logo_url,
        plan_tier: PlanTier::Free,
        billing_email: request.billing_email,
        settings: OrganizationSettings::default(),
    };

    let organization = app_state
        .organization_service
        .create_organization(params, tenant.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create organization: {}", e);
            if e.to_string().contains("already taken") {
                ApiError::bad_request("Organization slug is already taken")
            } else {
                ApiError::internal_server_error("Failed to create organization")
            }
        })?;

    Ok((StatusCode::CREATED, Json(organization.into())))
}

/// Get organization by ID
#[utoipa::path(
    get,
    path = "/v1/organizations/{id}",
    tag = "Organizations",
    params(
        ("id" = OrganizationId, Path, description = "Organization ID")
    ),
    responses(
        (status = 200, description = "Organization details", body = OrganizationResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Not found", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn get_organization(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Path(id): Path<OrganizationId>,
) -> Result<Json<OrganizationResponse>, ApiError> {
    tracing::info!(
        "Getting organization: organization_id={}, user_id={}",
        id,
        tenant.user_id
    );

    // Verify user has access to this organization
    if tenant.organization_id != id {
        return Err(ApiError::forbidden("Not a member of this organization"));
    }

    let organization = app_state
        .organization_service
        .get_organization(id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get organization: {}", e);
            if e.to_string().contains("not found") {
                ApiError::not_found("Organization not found")
            } else {
                ApiError::internal_server_error("Failed to get organization")
            }
        })?;

    Ok(Json(organization.into()))
}

/// Update organization
#[utoipa::path(
    patch,
    path = "/v1/organizations/{id}",
    tag = "Organizations",
    params(
        ("id" = OrganizationId, Path, description = "Organization ID")
    ),
    request_body = UpdateOrganizationRequest,
    responses(
        (status = 200, description = "Organization updated", body = OrganizationResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Not found", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn update_organization(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Path(id): Path<OrganizationId>,
    Json(request): Json<UpdateOrganizationRequest>,
) -> Result<Json<OrganizationResponse>, ApiError> {
    tracing::info!(
        "Updating organization: organization_id={}, user_id={}",
        id,
        tenant.user_id
    );

    // Check permission
    if !tenant
        .permissions
        .contains(&"organizations:update:own".to_string())
    {
        return Err(ApiError::forbidden("Missing permission to update organization"));
    }

    // Verify user has access to this organization
    if tenant.organization_id != id {
        return Err(ApiError::forbidden("Not a member of this organization"));
    }

    let settings = if let Some(s) = request.settings {
        let current = app_state
            .organization_service
            .get_organization(id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to get organization: {}", e);
                ApiError::internal_server_error("Failed to load organization settings")
            })?;

        Some(OrganizationSettings {
            personal: current.settings.personal, // Cannot change personal flag
            default_model: s.default_model.or(current.settings.default_model),
            enforce_sso: s.enforce_sso.unwrap_or(current.settings.enforce_sso),
            allowed_email_domains: s
                .allowed_email_domains
                .unwrap_or(current.settings.allowed_email_domains),
        })
    } else {
        None
    };

    let params = UpdateOrganizationParams {
        name: request.name,
        display_name: request.display_name,
        logo_url: request.logo_url,
        billing_email: request.billing_email,
        settings,
    };

    let organization = app_state
        .organization_service
        .update_organization(id, params)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update organization: {}", e);
            ApiError::internal_server_error("Failed to update organization")
        })?;

    Ok(Json(organization.into()))
}

/// Get organization members
#[utoipa::path(
    get,
    path = "/v1/organizations/{id}/members",
    tag = "Organizations",
    params(
        ("id" = OrganizationId, Path, description = "Organization ID"),
        ("limit" = Option<i64>, Query, description = "Maximum number of items"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip")
    ),
    responses(
        (status = 200, description = "List of members", body = OrganizationMemberListResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn get_organization_members(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Path(id): Path<OrganizationId>,
    Query(params): Query<PaginationQuery>,
) -> Result<Json<OrganizationMemberListResponse>, ApiError> {
    tracing::info!(
        "Getting organization members: organization_id={}, user_id={}",
        id,
        tenant.user_id
    );

    // Verify user has access to this organization
    if tenant.organization_id != id {
        return Err(ApiError::forbidden("Not a member of this organization"));
    }

    params.validate()?;

    let (members, total) = app_state
        .organization_service
        .get_organization_members(id, params.limit, params.offset)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get organization members: {}", e);
            ApiError::internal_server_error("Failed to get organization members")
        })?;

    Ok(Json(OrganizationMemberListResponse {
        members: members.into_iter().map(Into::into).collect(),
        limit: params.limit,
        offset: params.offset,
        total,
    }))
}

/// Add member to organization
#[utoipa::path(
    post,
    path = "/v1/organizations/{id}/members",
    tag = "Organizations",
    params(
        ("id" = OrganizationId, Path, description = "Organization ID")
    ),
    request_body = AddMemberRequest,
    responses(
        (status = 204, description = "Member added"),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn add_organization_member(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Path(id): Path<OrganizationId>,
    Json(request): Json<AddMemberRequest>,
) -> Result<StatusCode, ApiError> {
    tracing::info!(
        "Adding member to organization: organization_id={}, user_id={}, new_member={}",
        id,
        tenant.user_id,
        request.user_id
    );

    // Check permission
    if !tenant
        .permissions
        .contains(&"organizations:manage:members".to_string())
    {
        return Err(ApiError::forbidden("Missing permission to manage members"));
    }

    // Verify user has access to this organization
    if tenant.organization_id != id {
        return Err(ApiError::forbidden("Not a member of this organization"));
    }

    let role = OrgRole::from_str(&request.role).ok_or_else(|| {
        ApiError::bad_request("Invalid role. Must be one of: owner, admin, member")
    })?;

    app_state
        .organization_service
        .add_user_to_organization(request.user_id, id, role)
        .await
        .map_err(|e| {
            tracing::error!("Failed to add member: {}", e);
            ApiError::internal_server_error("Failed to add member")
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Remove member from organization
#[utoipa::path(
    delete,
    path = "/v1/organizations/{id}/members/{user_id}",
    tag = "Organizations",
    params(
        ("id" = OrganizationId, Path, description = "Organization ID"),
        ("user_id" = UserId, Path, description = "User ID to remove")
    ),
    responses(
        (status = 204, description = "Member removed"),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn remove_organization_member(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Path((id, user_id)): Path<(OrganizationId, UserId)>,
) -> Result<StatusCode, ApiError> {
    tracing::info!(
        "Removing member from organization: organization_id={}, user_id={}, remove_user={}",
        id,
        tenant.user_id,
        user_id
    );

    // Check permission
    if !tenant
        .permissions
        .contains(&"organizations:manage:members".to_string())
    {
        return Err(ApiError::forbidden("Missing permission to manage members"));
    }

    // Verify user has access to this organization
    if tenant.organization_id != id {
        return Err(ApiError::forbidden("Not a member of this organization"));
    }

    // Cannot remove yourself
    if tenant.user_id == user_id {
        return Err(ApiError::bad_request("Cannot remove yourself from organization"));
    }

    app_state
        .organization_service
        .remove_user_from_organization(user_id, id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to remove member: {}", e);
            ApiError::internal_server_error("Failed to remove member")
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Check if slug is available
#[utoipa::path(
    get,
    path = "/v1/organizations/check-slug/{slug}",
    tag = "Organizations",
    params(
        ("slug" = String, Path, description = "Slug to check")
    ),
    responses(
        (status = 200, description = "Slug availability", body = SlugAvailabilityResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn check_slug_availability(
    State(app_state): State<AppState>,
    Path(slug): Path<String>,
) -> Result<Json<SlugAvailabilityResponse>, ApiError> {
    let available = app_state
        .organization_service
        .is_slug_available(&slug)
        .await
        .map_err(|e| {
            tracing::error!("Failed to check slug availability: {}", e);
            ApiError::internal_server_error("Failed to check slug availability")
        })?;

    Ok(Json(SlugAvailabilityResponse { available }))
}

// --- Helper functions ---

fn is_valid_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= 100
        && slug
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !slug.starts_with('-')
        && !slug.ends_with('-')
}

/// Create organizations router
pub fn create_organizations_router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_organizations).post(create_organization))
        .route("/check-slug/{slug}", get(check_slug_availability))
        .route("/{id}", get(get_organization).patch(update_organization))
        .route(
            "/{id}/members",
            get(get_organization_members).post(add_organization_member),
        )
        .route("/{id}/members/{user_id}", delete(remove_organization_member))
}
