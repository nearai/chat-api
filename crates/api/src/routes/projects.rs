//! Project and OAuth Client management routes

use axum::{
    extract::{Path, State},
    routing::{delete, get, post, put},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{error::ApiError, middleware::AuthenticatedUser, state::AppState};
use services::auth::oauth_ports::{CreateOAuthClient, CreateProject, OAuthClientType, UpdateProject};

// =============================================================================
// Project Routes
// =============================================================================

/// Create a new project.
#[utoipa::path(
    post,
    path = "/v1/projects",
    tag = "Projects",
    request_body = CreateProjectRequest,
    responses(
        (status = 201, description = "Project created", body = ProjectResponse),
        (status = 400, description = "Invalid request", body = crate::error::ApiErrorResponse),
    )
)]
pub async fn create_project(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(body): Json<CreateProjectRequest>,
) -> Result<Json<ProjectResponse>, ApiError> {
    let project = state
        .project_repository
        .create(CreateProject {
            owner_id: user.user_id,
            name: body.name,
            description: body.description,
            homepage_url: body.homepage_url,
            privacy_policy_url: body.privacy_policy_url,
            terms_url: body.terms_url,
        })
        .await
        .map_err(|e| ApiError::internal_server_error(&e.to_string()))?;

    Ok(Json(ProjectResponse::from(project)))
}

/// List user's projects.
#[utoipa::path(
    get,
    path = "/v1/projects",
    tag = "Projects",
    responses(
        (status = 200, description = "List of projects", body = Vec<ProjectResponse>),
    )
)]
pub async fn list_projects(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<Vec<ProjectResponse>>, ApiError> {
    let projects = state
        .project_repository
        .list_by_owner(user.user_id)
        .await
        .map_err(|e| ApiError::internal_server_error(&e.to_string()))?;

    Ok(Json(projects.into_iter().map(ProjectResponse::from).collect()))
}

/// Get a project by ID.
#[utoipa::path(
    get,
    path = "/v1/projects/{id}",
    tag = "Projects",
    params(
        ("id" = Uuid, Path, description = "Project ID")
    ),
    responses(
        (status = 200, description = "Project details", body = ProjectResponse),
        (status = 404, description = "Project not found"),
    )
)]
pub async fn get_project(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<ProjectResponse>, ApiError> {
    let project = state
        .project_repository
        .get_by_id(id)
        .await
        .map_err(|e| ApiError::internal_server_error(&e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Project not found"))?;

    // Verify ownership
    if project.owner_id != user.user_id {
        return Err(ApiError::forbidden("You don't own this project"));
    }

    Ok(Json(ProjectResponse::from(project)))
}

/// Update a project.
#[utoipa::path(
    put,
    path = "/v1/projects/{id}",
    tag = "Projects",
    params(
        ("id" = Uuid, Path, description = "Project ID")
    ),
    request_body = UpdateProjectRequest,
    responses(
        (status = 200, description = "Project updated", body = ProjectResponse),
        (status = 404, description = "Project not found"),
    )
)]
pub async fn update_project(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateProjectRequest>,
) -> Result<Json<ProjectResponse>, ApiError> {
    // Verify ownership
    let existing = state
        .project_repository
        .get_by_id(id)
        .await
        .map_err(|e| ApiError::internal_server_error(&e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Project not found"))?;

    if existing.owner_id != user.user_id {
        return Err(ApiError::forbidden("You don't own this project"));
    }

    let project = state
        .project_repository
        .update(
            id,
            UpdateProject {
                name: body.name,
                description: body.description,
                homepage_url: body.homepage_url,
                privacy_policy_url: body.privacy_policy_url,
                terms_url: body.terms_url,
            },
        )
        .await
        .map_err(|e| ApiError::internal_server_error(&e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Project not found"))?;

    Ok(Json(ProjectResponse::from(project)))
}

/// Delete a project.
#[utoipa::path(
    delete,
    path = "/v1/projects/{id}",
    tag = "Projects",
    params(
        ("id" = Uuid, Path, description = "Project ID")
    ),
    responses(
        (status = 204, description = "Project deleted"),
        (status = 404, description = "Project not found"),
    )
)]
pub async fn delete_project(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(id): Path<Uuid>,
) -> Result<(), ApiError> {
    // Verify ownership
    let existing = state
        .project_repository
        .get_by_id(id)
        .await
        .map_err(|e| ApiError::internal_server_error(&e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Project not found"))?;

    if existing.owner_id != user.user_id {
        return Err(ApiError::forbidden("You don't own this project"));
    }

    state
        .project_repository
        .delete(id)
        .await
        .map_err(|e| ApiError::internal_server_error(&e.to_string()))?;

    Ok(())
}

// =============================================================================
// OAuth Client Routes
// =============================================================================

/// Create an OAuth client for a project.
#[utoipa::path(
    post,
    path = "/v1/projects/{project_id}/clients",
    tag = "OAuth Clients",
    params(
        ("project_id" = Uuid, Path, description = "Project ID")
    ),
    request_body = CreateOAuthClientRequest,
    responses(
        (status = 201, description = "OAuth client created", body = OAuthClientResponse),
        (status = 400, description = "Invalid request", body = crate::error::ApiErrorResponse),
    )
)]
pub async fn create_oauth_client(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(project_id): Path<Uuid>,
    Json(body): Json<CreateOAuthClientRequest>,
) -> Result<Json<OAuthClientResponse>, ApiError> {
    // Verify project ownership
    let project = state
        .project_repository
        .get_by_id(project_id)
        .await
        .map_err(|e| ApiError::internal_server_error(&e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Project not found"))?;

    if project.owner_id != user.user_id {
        return Err(ApiError::forbidden("You don't own this project"));
    }

    // Parse client_type from string
    let client_type = OAuthClientType::from_str(&body.client_type)
        .ok_or_else(|| ApiError::bad_request("Invalid client_type. Must be 'confidential' or 'public'"))?;

    // Generate client_id and optionally hash client_secret
    let client_id = format!("client_{}", Uuid::new_v4().simple());
    let client_secret_hash = body.client_secret.as_ref().map(|secret| {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        format!("{:x}", hasher.finalize())
    });

    let client = state
        .oauth_client_repository
        .create(CreateOAuthClient {
            project_id,
            client_id,
            client_secret_hash,
            client_type,
            redirect_uris: body.redirect_uris,
            allowed_scopes: body.allowed_scopes,
        })
        .await
        .map_err(|e| ApiError::internal_server_error(&e.to_string()))?;

    Ok(Json(OAuthClientResponse::from(client)))
}

/// List OAuth clients for a project.
#[utoipa::path(
    get,
    path = "/v1/projects/{project_id}/clients",
    tag = "OAuth Clients",
    params(
        ("project_id" = Uuid, Path, description = "Project ID")
    ),
    responses(
        (status = 200, description = "List of OAuth clients", body = Vec<OAuthClientResponse>),
    )
)]
pub async fn list_oauth_clients(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(project_id): Path<Uuid>,
) -> Result<Json<Vec<OAuthClientResponse>>, ApiError> {
    // Verify project ownership
    let project = state
        .project_repository
        .get_by_id(project_id)
        .await
        .map_err(|e| ApiError::internal_server_error(&e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Project not found"))?;

    if project.owner_id != user.user_id {
        return Err(ApiError::forbidden("You don't own this project"));
    }

    let clients = state
        .oauth_client_repository
        .list_by_project(project_id)
        .await
        .map_err(|e| ApiError::internal_server_error(&e.to_string()))?;

    Ok(Json(clients.into_iter().map(OAuthClientResponse::from).collect()))
}

/// List authorized projects (projects whose OAuth clients the user has granted access to).
#[utoipa::path(
    get,
    path = "/v1/authorized-projects",
    tag = "Projects",
    responses(
        (status = 200, description = "List of authorized projects", body = Vec<AuthorizedProjectResponse>),
    )
)]
pub async fn list_authorized_projects(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<Vec<AuthorizedProjectResponse>>, ApiError> {
    let grants = state
        .access_grant_repository
        .list_by_user(user.user_id)
        .await
        .map_err(|e| ApiError::internal_server_error(&e.to_string()))?;

    let mut authorized_projects = Vec::new();

    for grant in grants {
        // Get the OAuth client
        if let Ok(Some(client)) = state
            .oauth_client_repository
            .get_by_client_id(&grant.client_id)
            .await
        {
            // Get the project
            if let Ok(Some(project)) = state
                .project_repository
                .get_by_id(client.project_id)
                .await
            {
                authorized_projects.push(AuthorizedProjectResponse {
                    project_id: project.id,
                    project_name: project.name,
                    project_description: project.description,
                    client_id: client.client_id,
                    scopes: grant.scopes,
                    granted_at: grant.created_at,
                });
            }
        }
    }

    Ok(Json(authorized_projects))
}

/// Revoke access to an authorized app.
#[utoipa::path(
    delete,
    path = "/v1/authorized-projects/{client_id}",
    tag = "Projects",
    params(
        ("client_id" = String, Path, description = "OAuth Client ID to revoke")
    ),
    responses(
        (status = 204, description = "Access revoked"),
        (status = 404, description = "Grant not found"),
    )
)]
pub async fn revoke_authorized_project(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(client_id): Path<String>,
) -> Result<(), ApiError> {
    let revoked = state
        .access_grant_repository
        .revoke(user.user_id, &client_id)
        .await
        .map_err(|e| ApiError::internal_server_error(&e.to_string()))?;

    if !revoked {
        return Err(ApiError::not_found("Grant not found"));
    }

    Ok(())
}

// =============================================================================
// DTOs
// =============================================================================

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateProjectRequest {
    pub name: String,
    pub description: Option<String>,
    pub homepage_url: Option<String>,
    pub privacy_policy_url: Option<String>,
    pub terms_url: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateProjectRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub homepage_url: Option<String>,
    pub privacy_policy_url: Option<String>,
    pub terms_url: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProjectResponse {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub homepage_url: Option<String>,
    pub privacy_policy_url: Option<String>,
    pub terms_url: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<services::auth::oauth_ports::Project> for ProjectResponse {
    fn from(p: services::auth::oauth_ports::Project) -> Self {
        Self {
            id: p.id,
            owner_id: p.owner_id.into_uuid(),
            name: p.name,
            description: p.description,
            homepage_url: p.homepage_url,
            privacy_policy_url: p.privacy_policy_url,
            terms_url: p.terms_url,
            created_at: p.created_at.to_rfc3339(),
            updated_at: p.updated_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateOAuthClientRequest {
    /// Client type: "confidential" or "public"
    pub client_type: String,
    pub client_secret: Option<String>,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OAuthClientResponse {
    pub id: Uuid,
    pub project_id: Uuid,
    pub client_id: String,
    pub client_type: String,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub created_at: String,
    pub revoked_at: Option<String>,
}

impl From<services::auth::oauth_ports::OAuthClient> for OAuthClientResponse {
    fn from(c: services::auth::oauth_ports::OAuthClient) -> Self {
        Self {
            id: c.id,
            project_id: c.project_id,
            client_id: c.client_id,
            client_type: format!("{:?}", c.client_type),
            redirect_uris: c.redirect_uris,
            allowed_scopes: c.allowed_scopes,
            created_at: c.created_at.to_rfc3339(),
            revoked_at: c.revoked_at.map(|dt| dt.to_rfc3339()),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthorizedProjectResponse {
    pub project_id: Uuid,
    pub project_name: String,
    pub project_description: Option<String>,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub granted_at: chrono::DateTime<chrono::Utc>,
}

// =============================================================================
// Router
// =============================================================================

pub fn create_project_router() -> Router<AppState> {
    Router::new()
        .route("/projects", post(create_project).get(list_projects))
        .route(
            "/projects/{id}",
            get(get_project).put(update_project).delete(delete_project),
        )
        .route(
            "/projects/{project_id}/clients",
            post(create_oauth_client).get(list_oauth_clients),
        )
        .route("/authorized-projects", get(list_authorized_projects))
        .route("/authorized-projects/{client_id}", delete(revoke_authorized_project))
}
