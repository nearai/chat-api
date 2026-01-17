use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use services::{OrganizationId, UserId, WorkspaceId};
use std::sync::Arc;

use crate::error::ApiError;

use super::AuthenticatedUser;

/// Tenant context extracted from the request
#[derive(Debug, Clone)]
pub struct TenantContext {
    pub user_id: UserId,
    pub organization_id: OrganizationId,
    pub workspace_id: Option<WorkspaceId>,
    pub permissions: Vec<String>,
}

/// State for tenant context middleware
#[derive(Clone)]
pub struct TenantState {
    pub organization_repository: Arc<dyn services::organization::ports::OrganizationRepository>,
    pub workspace_repository: Arc<dyn services::workspace::ports::WorkspaceRepository>,
    pub role_repository: Arc<dyn services::rbac::ports::RoleRepository>,
}

/// Extract organization ID from request headers or path
fn extract_organization_id(request: &Request) -> Option<OrganizationId> {
    // Try header first
    if let Some(org_id_header) = request
        .headers()
        .get("X-Organization-Id")
        .and_then(|h| h.to_str().ok())
    {
        if let Ok(org_id) = org_id_header.parse::<OrganizationId>() {
            return Some(org_id);
        }
    }

    None
}

/// Extract workspace ID from request headers
fn extract_workspace_id(request: &Request) -> Option<WorkspaceId> {
    request
        .headers()
        .get("X-Workspace-Id")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<WorkspaceId>().ok())
}

/// Tenant context middleware that extracts organization and workspace from request
/// and loads the user's permissions for that context.
///
/// Prerequisites:
/// - AuthenticatedUser must be in request extensions (run auth_middleware first)
///
/// Behavior:
/// - If X-Organization-Id header is provided, uses that org (verifies user is a member)
/// - Otherwise, uses the user's primary organization
/// - If X-Workspace-Id header is provided, uses that workspace (verifies user has access)
/// - Loads all permissions for the user in this org/workspace context
pub async fn tenant_middleware(
    State(state): State<TenantState>,
    mut request: Request,
    next: Next,
) -> Result<Response, Response> {
    let path = request.uri().path().to_string();

    // Get authenticated user from request extensions
    let authenticated_user = request
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .ok_or_else(|| {
            tracing::error!("Tenant middleware: No authenticated user in request extensions");
            ApiError::internal_server_error("Authentication required").into_response()
        })?;

    let user_id = authenticated_user.user_id;

    tracing::debug!(
        "Tenant middleware: Processing request for user_id={}, path={}",
        user_id,
        path
    );

    // Get organization ID from header or user's default org
    let organization_id = match extract_organization_id(&request) {
        Some(org_id) => {
            // Verify user belongs to this organization
            let user_role = state
                .organization_repository
                .get_user_org_role(user_id, org_id)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to get user org role: {}", e);
                    ApiError::internal_server_error("Failed to verify organization access")
                        .into_response()
                })?;

            if user_role.is_none() {
                tracing::warn!(
                    "User {} attempted to access organization {} without membership",
                    user_id,
                    org_id
                );
                return Err(ApiError::forbidden("Not a member of this organization").into_response());
            }

            org_id
        }
        None => {
            // Get user's primary organization
            let org = state
                .organization_repository
                .get_user_organization(user_id)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to get user organization: {}", e);
                    ApiError::internal_server_error("Failed to get user organization")
                        .into_response()
                })?
                .ok_or_else(|| {
                    tracing::warn!("User {} has no organization", user_id);
                    ApiError::forbidden("No organization found for user").into_response()
                })?;

            org.id
        }
    };

    // Get workspace ID from header if provided
    let workspace_id = if let Some(ws_id) = extract_workspace_id(&request) {
        // Verify user has access to this workspace
        let membership = state
            .workspace_repository
            .get_workspace_membership(ws_id, user_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to get workspace membership: {}", e);
                ApiError::internal_server_error("Failed to verify workspace access").into_response()
            })?;

        if membership.is_none() {
            tracing::warn!(
                "User {} attempted to access workspace {} without membership",
                user_id,
                ws_id
            );
            return Err(ApiError::forbidden("Not a member of this workspace").into_response());
        }

        // Verify workspace belongs to the organization
        let workspace = state
            .workspace_repository
            .get_workspace(ws_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to get workspace: {}", e);
                ApiError::internal_server_error("Failed to verify workspace").into_response()
            })?
            .ok_or_else(|| {
                tracing::warn!("Workspace {} not found", ws_id);
                ApiError::not_found("Workspace not found").into_response()
            })?;

        if workspace.organization_id != organization_id {
            tracing::warn!(
                "Workspace {} does not belong to organization {}",
                ws_id,
                organization_id
            );
            return Err(
                ApiError::forbidden("Workspace does not belong to this organization")
                    .into_response(),
            );
        }

        Some(ws_id)
    } else {
        None
    };

    // Load user permissions for this context
    let permissions = state
        .role_repository
        .get_user_permissions(user_id, Some(organization_id), workspace_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user permissions: {}", e);
            ApiError::internal_server_error("Failed to load user permissions").into_response()
        })?;

    tracing::debug!(
        "Tenant context loaded: user_id={}, org_id={}, workspace_id={:?}, permissions_count={}",
        user_id,
        organization_id,
        workspace_id,
        permissions.len()
    );

    // Create tenant context and add to request extensions
    let tenant_context = TenantContext {
        user_id,
        organization_id,
        workspace_id,
        permissions,
    };

    request.extensions_mut().insert(tenant_context);

    let response = next.run(request).await;
    Ok(response)
}

/// Create a permission checking middleware for a specific permission
///
/// Use this with axum::middleware::from_fn to create a middleware that checks
/// for a specific permission before allowing the request to proceed.
pub fn require_permission(
    permission: &'static str,
) -> impl Fn(Request, Next) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Response, Response>> + Send>,
> + Clone
       + Send
       + 'static {
    move |request: Request, next: Next| {
        Box::pin(async move {
            // Get tenant context from request extensions
            let tenant_context = request
                .extensions()
                .get::<TenantContext>()
                .cloned()
                .ok_or_else(|| {
                    tracing::error!("Permission check: No tenant context in request extensions");
                    ApiError::internal_server_error("Tenant context required").into_response()
                })?;

            // Check if user has the required permission
            if !tenant_context.permissions.contains(&permission.to_string()) {
                tracing::warn!(
                    "Permission denied: user_id={}, required={}, org_id={}, workspace_id={:?}",
                    tenant_context.user_id,
                    permission,
                    tenant_context.organization_id,
                    tenant_context.workspace_id
                );
                return Err(ApiError::forbidden(&format!(
                    "Missing required permission: {}",
                    permission
                ))
                .into_response());
            }

            tracing::debug!(
                "Permission granted: user_id={}, permission={}",
                tenant_context.user_id,
                permission
            );

            let response = next.run(request).await;
            Ok(response)
        })
    }
}

/// Helper to check if a tenant context has any of the specified permissions
pub fn has_any_permission(context: &TenantContext, permissions: &[&str]) -> bool {
    permissions
        .iter()
        .any(|p| context.permissions.contains(&p.to_string()))
}

/// Helper to check if a tenant context has all of the specified permissions
pub fn has_all_permissions(context: &TenantContext, permissions: &[&str]) -> bool {
    permissions
        .iter()
        .all(|p| context.permissions.contains(&p.to_string()))
}
