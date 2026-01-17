use crate::{error::ApiError, middleware::TenantContext, state::AppState};
use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use services::{
    rbac::ports::{CreateRoleParams, Permission, Role, UpdateRoleParams},
    OrganizationId, PermissionId, RoleId, UserId, WorkspaceId,
};

use super::admin::PaginationQuery;

// --- Request/Response types ---

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PermissionResponse {
    pub id: PermissionId,
    pub code: String,
    pub name: String,
    pub description: Option<String>,
    pub module: String,
}

impl From<Permission> for PermissionResponse {
    fn from(p: Permission) -> Self {
        Self {
            id: p.id,
            code: p.code,
            name: p.name,
            description: p.description,
            module: p.module,
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PermissionListResponse {
    pub permissions: Vec<PermissionResponse>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RoleResponse {
    pub id: RoleId,
    pub name: String,
    pub description: Option<String>,
    pub is_system: bool,
    pub organization_id: Option<OrganizationId>,
    pub permissions: Vec<PermissionResponse>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RoleListResponse {
    pub roles: Vec<RoleResponse>,
    pub limit: i64,
    pub offset: i64,
    pub total: u64,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateRoleRequest {
    pub name: String,
    pub description: Option<String>,
    pub permission_ids: Vec<PermissionId>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateRoleRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub permission_ids: Option<Vec<PermissionId>>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AssignRoleRequest {
    pub role_id: RoleId,
    pub organization_id: Option<OrganizationId>,
    pub workspace_id: Option<WorkspaceId>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UserPermissionsResponse {
    pub permissions: Vec<String>,
}

// --- Helper function to build RoleResponse ---
async fn role_to_response(
    app_state: &AppState,
    role: Role,
) -> Result<RoleResponse, ApiError> {
    let permissions = app_state
        .role_service
        .get_role_permissions(role.id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get role permissions: {}", e);
            ApiError::internal_server_error("Failed to get role permissions")
        })?;

    Ok(RoleResponse {
        id: role.id,
        name: role.name,
        description: role.description,
        is_system: role.is_system,
        organization_id: role.organization_id,
        permissions: permissions.into_iter().map(Into::into).collect(),
        created_at: role.created_at.to_rfc3339(),
        updated_at: role.updated_at.to_rfc3339(),
    })
}

// --- Handlers ---

/// List all permissions
#[utoipa::path(
    get,
    path = "/v1/permissions",
    tag = "RBAC",
    responses(
        (status = 200, description = "List of permissions", body = PermissionListResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn list_permissions(
    State(app_state): State<AppState>,
) -> Result<Json<PermissionListResponse>, ApiError> {
    tracing::info!("Listing all permissions");

    let permissions = app_state
        .permission_service
        .get_all_permissions()
        .await
        .map_err(|e| {
            tracing::error!("Failed to list permissions: {}", e);
            ApiError::internal_server_error("Failed to list permissions")
        })?;

    Ok(Json(PermissionListResponse {
        permissions: permissions.into_iter().map(Into::into).collect(),
    }))
}

/// List roles in organization
#[utoipa::path(
    get,
    path = "/v1/roles",
    tag = "RBAC",
    params(
        ("limit" = Option<i64>, Query, description = "Maximum number of items"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip")
    ),
    responses(
        (status = 200, description = "List of roles", body = RoleListResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn list_roles(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Query(params): Query<PaginationQuery>,
) -> Result<Json<RoleListResponse>, ApiError> {
    tracing::info!(
        "Listing roles for organization_id={}",
        tenant.organization_id
    );

    params.validate()?;

    let roles = app_state
        .role_service
        .get_organization_roles(tenant.organization_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list roles: {}", e);
            ApiError::internal_server_error("Failed to list roles")
        })?;

    let total = roles.len() as u64;

    // Apply pagination
    let roles: Vec<_> = roles
        .into_iter()
        .skip(params.offset as usize)
        .take(params.limit as usize)
        .collect();

    // Build responses with permissions
    let mut role_responses = Vec::new();
    for role in roles {
        role_responses.push(role_to_response(&app_state, role).await?);
    }

    Ok(Json(RoleListResponse {
        roles: role_responses,
        limit: params.limit,
        offset: params.offset,
        total,
    }))
}

/// Create a custom role
#[utoipa::path(
    post,
    path = "/v1/roles",
    tag = "RBAC",
    request_body = CreateRoleRequest,
    responses(
        (status = 201, description = "Role created", body = RoleResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn create_role(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Json(request): Json<CreateRoleRequest>,
) -> Result<(StatusCode, Json<RoleResponse>), ApiError> {
    tracing::info!(
        "Creating role: name={}, organization_id={}",
        request.name,
        tenant.organization_id
    );

    // Check permission
    if !tenant.permissions.contains(&"roles:create".to_string()) {
        return Err(ApiError::forbidden("Missing permission to create roles"));
    }

    let params = CreateRoleParams {
        organization_id: tenant.organization_id,
        name: request.name,
        description: request.description,
        permission_ids: request.permission_ids,
    };

    let role = app_state
        .role_service
        .create_role(params)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create role: {}", e);
            if e.to_string().contains("already exists") {
                ApiError::bad_request("Role with this name already exists")
            } else {
                ApiError::internal_server_error("Failed to create role")
            }
        })?;

    let response = role_to_response(&app_state, role).await?;

    Ok((StatusCode::CREATED, Json(response)))
}

/// Get role by ID
#[utoipa::path(
    get,
    path = "/v1/roles/{id}",
    tag = "RBAC",
    params(
        ("id" = RoleId, Path, description = "Role ID")
    ),
    responses(
        (status = 200, description = "Role details", body = RoleResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Not found", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn get_role(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Path(id): Path<RoleId>,
) -> Result<Json<RoleResponse>, ApiError> {
    tracing::info!("Getting role: role_id={}", id);

    let role = app_state.role_service.get_role(id).await.map_err(|e| {
        tracing::error!("Failed to get role: {}", e);
        if e.to_string().contains("not found") {
            ApiError::not_found("Role not found")
        } else {
            ApiError::internal_server_error("Failed to get role")
        }
    })?;

    // Verify user has access to this role (system roles are accessible to all)
    if let Some(org_id) = role.organization_id {
        if org_id != tenant.organization_id {
            return Err(ApiError::forbidden("Role belongs to another organization"));
        }
    }

    let response = role_to_response(&app_state, role).await?;

    Ok(Json(response))
}

/// Update role
#[utoipa::path(
    put,
    path = "/v1/roles/{id}",
    tag = "RBAC",
    params(
        ("id" = RoleId, Path, description = "Role ID")
    ),
    request_body = UpdateRoleRequest,
    responses(
        (status = 200, description = "Role updated", body = RoleResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Not found", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn update_role(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Path(id): Path<RoleId>,
    Json(request): Json<UpdateRoleRequest>,
) -> Result<Json<RoleResponse>, ApiError> {
    tracing::info!("Updating role: role_id={}", id);

    // Check permission
    if !tenant.permissions.contains(&"roles:update".to_string()) {
        return Err(ApiError::forbidden("Missing permission to update roles"));
    }

    // Get current role to verify access and type
    let current_role = app_state.role_service.get_role(id).await.map_err(|e| {
        tracing::error!("Failed to get role: {}", e);
        ApiError::not_found("Role not found")
    })?;

    // Cannot update system roles
    if current_role.is_system {
        return Err(ApiError::forbidden("Cannot update system roles"));
    }

    // Verify user has access
    if let Some(org_id) = current_role.organization_id {
        if org_id != tenant.organization_id {
            return Err(ApiError::forbidden("Role belongs to another organization"));
        }
    }

    let params = UpdateRoleParams {
        name: request.name,
        description: request.description,
        permission_ids: request.permission_ids,
    };

    let role = app_state
        .role_service
        .update_role(id, params)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update role: {}", e);
            ApiError::internal_server_error("Failed to update role")
        })?;

    let response = role_to_response(&app_state, role).await?;

    Ok(Json(response))
}

/// Delete role
#[utoipa::path(
    delete,
    path = "/v1/roles/{id}",
    tag = "RBAC",
    params(
        ("id" = RoleId, Path, description = "Role ID")
    ),
    responses(
        (status = 204, description = "Role deleted"),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Not found", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn delete_role(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Path(id): Path<RoleId>,
) -> Result<StatusCode, ApiError> {
    tracing::warn!("Deleting role: role_id={}", id);

    // Check permission
    if !tenant.permissions.contains(&"roles:delete".to_string()) {
        return Err(ApiError::forbidden("Missing permission to delete roles"));
    }

    // Get current role to verify access and type
    let current_role = app_state.role_service.get_role(id).await.map_err(|e| {
        tracing::error!("Failed to get role: {}", e);
        ApiError::not_found("Role not found")
    })?;

    // Cannot delete system roles
    if current_role.is_system {
        return Err(ApiError::forbidden("Cannot delete system roles"));
    }

    // Verify user has access
    if let Some(org_id) = current_role.organization_id {
        if org_id != tenant.organization_id {
            return Err(ApiError::forbidden("Role belongs to another organization"));
        }
    }

    app_state
        .role_service
        .delete_role(id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete role: {}", e);
            ApiError::internal_server_error("Failed to delete role")
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Assign role to user
#[utoipa::path(
    post,
    path = "/v1/users/{user_id}/roles",
    tag = "RBAC",
    params(
        ("user_id" = UserId, Path, description = "User ID")
    ),
    request_body = AssignRoleRequest,
    responses(
        (status = 204, description = "Role assigned"),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn assign_role_to_user(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Path(user_id): Path<UserId>,
    Json(request): Json<AssignRoleRequest>,
) -> Result<StatusCode, ApiError> {
    tracing::info!(
        "Assigning role to user: user_id={}, role_id={}",
        user_id,
        request.role_id
    );

    // Check permission
    if !tenant.permissions.contains(&"roles:assign".to_string()) {
        return Err(ApiError::forbidden("Missing permission to assign roles"));
    }

    let org_id = request.organization_id.unwrap_or(tenant.organization_id);

    // Verify user is in same organization
    if org_id != tenant.organization_id {
        return Err(ApiError::forbidden("Cannot assign roles in other organizations"));
    }

    app_state
        .role_service
        .assign_role_to_user(user_id, request.role_id, Some(org_id), request.workspace_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to assign role: {}", e);
            if e.to_string().contains("already assigned") {
                ApiError::bad_request("User already has this role")
            } else {
                ApiError::internal_server_error("Failed to assign role")
            }
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Remove role from user
#[utoipa::path(
    delete,
    path = "/v1/users/{user_id}/roles/{role_id}",
    tag = "RBAC",
    params(
        ("user_id" = UserId, Path, description = "User ID"),
        ("role_id" = RoleId, Path, description = "Role ID")
    ),
    responses(
        (status = 204, description = "Role removed"),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn remove_role_from_user(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Path((user_id, role_id)): Path<(UserId, RoleId)>,
) -> Result<StatusCode, ApiError> {
    tracing::info!(
        "Removing role from user: user_id={}, role_id={}",
        user_id,
        role_id
    );

    // Check permission
    if !tenant.permissions.contains(&"roles:assign".to_string()) {
        return Err(ApiError::forbidden("Missing permission to manage role assignments"));
    }

    app_state
        .role_service
        .remove_role_from_user(user_id, role_id, Some(tenant.organization_id), None)
        .await
        .map_err(|e| {
            tracing::error!("Failed to remove role: {}", e);
            ApiError::internal_server_error("Failed to remove role")
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Get user's permissions
#[utoipa::path(
    get,
    path = "/v1/users/{user_id}/permissions",
    tag = "RBAC",
    params(
        ("user_id" = UserId, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User permissions", body = UserPermissionsResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn get_user_permissions(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Path(user_id): Path<UserId>,
) -> Result<Json<UserPermissionsResponse>, ApiError> {
    tracing::info!("Getting user permissions: user_id={}", user_id);

    // Users can only view their own permissions unless they have the permission to view others
    if user_id != tenant.user_id
        && !tenant.permissions.contains(&"users:read:all".to_string())
    {
        return Err(ApiError::forbidden("Cannot view other users' permissions"));
    }

    let permissions = app_state
        .permission_service
        .get_user_permissions(user_id, Some(tenant.organization_id), tenant.workspace_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user permissions: {}", e);
            ApiError::internal_server_error("Failed to get user permissions")
        })?;

    Ok(Json(UserPermissionsResponse { permissions }))
}

/// Create roles router
pub fn create_roles_router() -> Router<AppState> {
    Router::new()
        .route("/permissions", get(list_permissions))
        .route("/", get(list_roles).post(create_role))
        .route("/{id}", get(get_role).put(update_role).delete(delete_role))
}

/// Create user roles router (nested under /users)
pub fn create_user_roles_router() -> Router<AppState> {
    Router::new()
        .route("/{user_id}/roles", post(assign_role_to_user))
        .route("/{user_id}/roles/{role_id}", delete(remove_role_from_user))
        .route("/{user_id}/permissions", get(get_user_permissions))
}
