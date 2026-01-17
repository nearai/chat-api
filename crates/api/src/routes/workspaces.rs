use crate::{error::ApiError, middleware::TenantContext, state::AppState};
use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    routing::{get, patch},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use services::{
    workspace::ports::{
        CreateWorkspaceParams, UpdateWorkspaceParams, Workspace, WorkspaceMember,
        WorkspaceRole, WorkspaceSettings,
    },
    OrganizationId, UserId, WorkspaceId,
};

use super::admin::PaginationQuery;

// --- Request/Response types ---

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct WorkspaceResponse {
    pub id: WorkspaceId,
    pub organization_id: OrganizationId,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub settings: WorkspaceSettingsResponse,
    pub is_default: bool,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct WorkspaceSettingsResponse {
    pub default_model: Option<String>,
    pub system_prompt: Option<String>,
    pub web_search_enabled: bool,
}

impl From<Workspace> for WorkspaceResponse {
    fn from(ws: Workspace) -> Self {
        Self {
            id: ws.id,
            organization_id: ws.organization_id,
            name: ws.name,
            slug: ws.slug,
            description: ws.description,
            settings: WorkspaceSettingsResponse {
                default_model: ws.settings.default_model,
                system_prompt: ws.settings.system_prompt,
                web_search_enabled: ws.settings.web_search_enabled,
            },
            is_default: ws.is_default,
            status: ws.status.as_str().to_string(),
            created_at: ws.created_at.to_rfc3339(),
            updated_at: ws.updated_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateWorkspaceRequest {
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub settings: Option<WorkspaceSettingsRequest>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateWorkspaceRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub settings: Option<WorkspaceSettingsRequest>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct WorkspaceSettingsRequest {
    pub default_model: Option<String>,
    pub system_prompt: Option<String>,
    pub web_search_enabled: Option<bool>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct WorkspaceListResponse {
    pub workspaces: Vec<WorkspaceResponse>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct WorkspaceMemberResponse {
    pub user_id: UserId,
    pub email: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub role: String,
    pub status: String,
    pub joined_at: String,
}

impl From<WorkspaceMember> for WorkspaceMemberResponse {
    fn from(member: WorkspaceMember) -> Self {
        Self {
            user_id: member.user_id,
            email: member.email,
            name: member.name,
            avatar_url: member.avatar_url,
            role: member.role.as_str().to_string(),
            status: member.status.as_str().to_string(),
            joined_at: member.joined_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct WorkspaceMemberListResponse {
    pub members: Vec<WorkspaceMemberResponse>,
    pub limit: i64,
    pub offset: i64,
    pub total: u64,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AddWorkspaceMemberRequest {
    pub user_id: UserId,
    pub role: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateWorkspaceMemberRoleRequest {
    pub role: String,
}

// --- Handlers ---

/// List workspaces in organization
#[utoipa::path(
    get,
    path = "/v1/workspaces",
    tag = "Workspaces",
    responses(
        (status = 200, description = "List of workspaces", body = WorkspaceListResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn list_workspaces(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
) -> Result<Json<WorkspaceListResponse>, ApiError> {
    tracing::info!(
        "Listing workspaces for user_id={}, organization_id={}",
        tenant.user_id,
        tenant.organization_id
    );

    let workspaces = app_state
        .workspace_service
        .get_user_workspaces(tenant.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list workspaces: {}", e);
            ApiError::internal_server_error("Failed to list workspaces")
        })?;

    Ok(Json(WorkspaceListResponse {
        workspaces: workspaces.into_iter().map(Into::into).collect(),
    }))
}

/// Create a new workspace
#[utoipa::path(
    post,
    path = "/v1/workspaces",
    tag = "Workspaces",
    request_body = CreateWorkspaceRequest,
    responses(
        (status = 201, description = "Workspace created", body = WorkspaceResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn create_workspace(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Json(request): Json<CreateWorkspaceRequest>,
) -> Result<(StatusCode, Json<WorkspaceResponse>), ApiError> {
    tracing::info!(
        "Creating workspace: name={}, slug={}, organization_id={}",
        request.name,
        request.slug,
        tenant.organization_id
    );

    // Check permission
    if !tenant.permissions.contains(&"workspaces:create".to_string()) {
        return Err(ApiError::forbidden("Missing permission to create workspaces"));
    }

    // Validate slug format
    if !is_valid_slug(&request.slug) {
        return Err(ApiError::bad_request(
            "Slug must contain only lowercase letters, numbers, and hyphens",
        ));
    }

    let settings = request.settings.map(|s| WorkspaceSettings {
        default_model: s.default_model,
        system_prompt: s.system_prompt,
        web_search_enabled: s.web_search_enabled.unwrap_or(true),
    }).unwrap_or_default();

    let params = CreateWorkspaceParams {
        organization_id: tenant.organization_id,
        name: request.name,
        slug: request.slug,
        description: request.description,
        settings,
        is_default: false,
    };

    let workspace = app_state
        .workspace_service
        .create_workspace(params, tenant.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create workspace: {}", e);
            if e.to_string().contains("already taken") {
                ApiError::bad_request("Workspace slug is already taken in this organization")
            } else {
                ApiError::internal_server_error("Failed to create workspace")
            }
        })?;

    Ok((StatusCode::CREATED, Json(workspace.into())))
}

/// Get workspace by ID
#[utoipa::path(
    get,
    path = "/v1/workspaces/{id}",
    tag = "Workspaces",
    params(
        ("id" = WorkspaceId, Path, description = "Workspace ID")
    ),
    responses(
        (status = 200, description = "Workspace details", body = WorkspaceResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Not found", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn get_workspace(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Path(id): Path<WorkspaceId>,
) -> Result<Json<WorkspaceResponse>, ApiError> {
    tracing::info!(
        "Getting workspace: workspace_id={}, user_id={}",
        id,
        tenant.user_id
    );

    // Verify user has access to this workspace
    let has_access = app_state
        .workspace_service
        .user_has_workspace_access(id, tenant.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to check workspace access: {}", e);
            ApiError::internal_server_error("Failed to check workspace access")
        })?;

    if !has_access {
        return Err(ApiError::forbidden("Not a member of this workspace"));
    }

    let workspace = app_state
        .workspace_service
        .get_workspace(id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get workspace: {}", e);
            if e.to_string().contains("not found") {
                ApiError::not_found("Workspace not found")
            } else {
                ApiError::internal_server_error("Failed to get workspace")
            }
        })?;

    Ok(Json(workspace.into()))
}

/// Update workspace
#[utoipa::path(
    patch,
    path = "/v1/workspaces/{id}",
    tag = "Workspaces",
    params(
        ("id" = WorkspaceId, Path, description = "Workspace ID")
    ),
    request_body = UpdateWorkspaceRequest,
    responses(
        (status = 200, description = "Workspace updated", body = WorkspaceResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Not found", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn update_workspace(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Path(id): Path<WorkspaceId>,
    Json(request): Json<UpdateWorkspaceRequest>,
) -> Result<Json<WorkspaceResponse>, ApiError> {
    tracing::info!(
        "Updating workspace: workspace_id={}, user_id={}",
        id,
        tenant.user_id
    );

    // Check permission
    let has_permission = tenant
        .permissions
        .contains(&"workspaces:update:own".to_string())
        || tenant
            .permissions
            .contains(&"workspaces:update:all".to_string());

    if !has_permission {
        return Err(ApiError::forbidden("Missing permission to update workspace"));
    }

    // Verify user has access to this workspace
    let has_access = app_state
        .workspace_service
        .user_has_workspace_access(id, tenant.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to check workspace access: {}", e);
            ApiError::internal_server_error("Failed to check workspace access")
        })?;

    if !has_access {
        return Err(ApiError::forbidden("Not a member of this workspace"));
    }

    let settings = request.settings.map(|s| WorkspaceSettings {
        default_model: s.default_model,
        system_prompt: s.system_prompt,
        web_search_enabled: s.web_search_enabled.unwrap_or(true),
    });

    let params = UpdateWorkspaceParams {
        name: request.name,
        description: request.description,
        settings,
    };

    let workspace = app_state
        .workspace_service
        .update_workspace(id, params)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update workspace: {}", e);
            ApiError::internal_server_error("Failed to update workspace")
        })?;

    Ok(Json(workspace.into()))
}

/// Delete workspace
#[utoipa::path(
    delete,
    path = "/v1/workspaces/{id}",
    tag = "Workspaces",
    params(
        ("id" = WorkspaceId, Path, description = "Workspace ID")
    ),
    responses(
        (status = 204, description = "Workspace deleted"),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Not found", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn delete_workspace(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Path(id): Path<WorkspaceId>,
) -> Result<StatusCode, ApiError> {
    tracing::warn!(
        "Deleting workspace: workspace_id={}, user_id={}",
        id,
        tenant.user_id
    );

    // Check permission
    let has_permission = tenant
        .permissions
        .contains(&"workspaces:delete:own".to_string())
        || tenant
            .permissions
            .contains(&"workspaces:delete:all".to_string());

    if !has_permission {
        return Err(ApiError::forbidden("Missing permission to delete workspace"));
    }

    app_state
        .workspace_service
        .delete_workspace(id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete workspace: {}", e);
            if e.to_string().contains("default workspace") {
                ApiError::bad_request("Cannot delete the default workspace")
            } else {
                ApiError::internal_server_error("Failed to delete workspace")
            }
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Get workspace members
#[utoipa::path(
    get,
    path = "/v1/workspaces/{id}/members",
    tag = "Workspaces",
    params(
        ("id" = WorkspaceId, Path, description = "Workspace ID"),
        ("limit" = Option<i64>, Query, description = "Maximum number of items"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip")
    ),
    responses(
        (status = 200, description = "List of members", body = WorkspaceMemberListResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn get_workspace_members(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Path(id): Path<WorkspaceId>,
    Query(params): Query<PaginationQuery>,
) -> Result<Json<WorkspaceMemberListResponse>, ApiError> {
    tracing::info!(
        "Getting workspace members: workspace_id={}, user_id={}",
        id,
        tenant.user_id
    );

    // Verify user has access to this workspace
    let has_access = app_state
        .workspace_service
        .user_has_workspace_access(id, tenant.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to check workspace access: {}", e);
            ApiError::internal_server_error("Failed to check workspace access")
        })?;

    if !has_access {
        return Err(ApiError::forbidden("Not a member of this workspace"));
    }

    params.validate()?;

    let (members, total) = app_state
        .workspace_service
        .get_workspace_members(id, params.limit, params.offset)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get workspace members: {}", e);
            ApiError::internal_server_error("Failed to get workspace members")
        })?;

    Ok(Json(WorkspaceMemberListResponse {
        members: members.into_iter().map(Into::into).collect(),
        limit: params.limit,
        offset: params.offset,
        total,
    }))
}

/// Add member to workspace
#[utoipa::path(
    post,
    path = "/v1/workspaces/{id}/members",
    tag = "Workspaces",
    params(
        ("id" = WorkspaceId, Path, description = "Workspace ID")
    ),
    request_body = AddWorkspaceMemberRequest,
    responses(
        (status = 204, description = "Member added"),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn add_workspace_member(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Path(id): Path<WorkspaceId>,
    Json(request): Json<AddWorkspaceMemberRequest>,
) -> Result<StatusCode, ApiError> {
    tracing::info!(
        "Adding member to workspace: workspace_id={}, user_id={}, new_member={}",
        id,
        tenant.user_id,
        request.user_id
    );

    // Check permission
    if !tenant
        .permissions
        .contains(&"workspaces:manage:members".to_string())
    {
        return Err(ApiError::forbidden("Missing permission to manage workspace members"));
    }

    let role = WorkspaceRole::from_str(&request.role).ok_or_else(|| {
        ApiError::bad_request("Invalid role. Must be one of: admin, member, viewer")
    })?;

    app_state
        .workspace_service
        .add_workspace_member(id, request.user_id, role)
        .await
        .map_err(|e| {
            tracing::error!("Failed to add member: {}", e);
            if e.to_string().contains("already a member") {
                ApiError::bad_request("User is already a member of this workspace")
            } else {
                ApiError::internal_server_error("Failed to add member")
            }
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Update member role
#[utoipa::path(
    patch,
    path = "/v1/workspaces/{id}/members/{user_id}",
    tag = "Workspaces",
    params(
        ("id" = WorkspaceId, Path, description = "Workspace ID"),
        ("user_id" = UserId, Path, description = "User ID")
    ),
    request_body = UpdateWorkspaceMemberRoleRequest,
    responses(
        (status = 204, description = "Member role updated"),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn update_workspace_member_role(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Path((id, user_id)): Path<(WorkspaceId, UserId)>,
    Json(request): Json<UpdateWorkspaceMemberRoleRequest>,
) -> Result<StatusCode, ApiError> {
    tracing::info!(
        "Updating member role: workspace_id={}, user_id={}, target_user={}",
        id,
        tenant.user_id,
        user_id
    );

    // Check permission
    if !tenant
        .permissions
        .contains(&"workspaces:manage:members".to_string())
    {
        return Err(ApiError::forbidden("Missing permission to manage workspace members"));
    }

    let role = WorkspaceRole::from_str(&request.role).ok_or_else(|| {
        ApiError::bad_request("Invalid role. Must be one of: admin, member, viewer")
    })?;

    app_state
        .workspace_service
        .update_workspace_member_role(id, user_id, role)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update member role: {}", e);
            ApiError::internal_server_error("Failed to update member role")
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Remove member from workspace
#[utoipa::path(
    delete,
    path = "/v1/workspaces/{id}/members/{user_id}",
    tag = "Workspaces",
    params(
        ("id" = WorkspaceId, Path, description = "Workspace ID"),
        ("user_id" = UserId, Path, description = "User ID to remove")
    ),
    responses(
        (status = 204, description = "Member removed"),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn remove_workspace_member(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Path((id, user_id)): Path<(WorkspaceId, UserId)>,
) -> Result<StatusCode, ApiError> {
    tracing::info!(
        "Removing member from workspace: workspace_id={}, user_id={}, remove_user={}",
        id,
        tenant.user_id,
        user_id
    );

    // Check permission
    if !tenant
        .permissions
        .contains(&"workspaces:manage:members".to_string())
    {
        return Err(ApiError::forbidden("Missing permission to manage workspace members"));
    }

    // Cannot remove yourself
    if tenant.user_id == user_id {
        return Err(ApiError::bad_request("Cannot remove yourself from workspace"));
    }

    app_state
        .workspace_service
        .remove_workspace_member(id, user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to remove member: {}", e);
            ApiError::internal_server_error("Failed to remove member")
        })?;

    Ok(StatusCode::NO_CONTENT)
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

/// Create workspaces router
pub fn create_workspaces_router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_workspaces).post(create_workspace))
        .route(
            "/{id}",
            get(get_workspace)
                .patch(update_workspace)
                .delete(delete_workspace),
        )
        .route(
            "/{id}/members",
            get(get_workspace_members).post(add_workspace_member),
        )
        .route(
            "/{id}/members/{user_id}",
            patch(update_workspace_member_role).delete(remove_workspace_member),
        )
}
