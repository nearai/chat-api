use crate::{consts::PAGE_SIZE_MAX, error::ApiError, models::*, state::AppState};
use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use serde::Deserialize;

/// Pagination query parameters
#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    /// Page number (1-based, default: 1)
    #[serde(default = "default_page")]
    pub page: u32,
    /// Number of items per page (default: 20, max: PAGE_SIZE_MAX)
    #[serde(default = "default_page_size")]
    pub page_size: u32,
}

fn default_page() -> u32 {
    1
}

fn default_page_size() -> u32 {
    20
}

/// List users
///
/// Returns a paginated list of users. Requires admin authentication.
#[utoipa::path(
    get,
    path = "/v1/admin/users",
    tag = "Admin",
    params(
        ("page" = Option<u32>, Query, description = "Page number (1-based, default: 1)"),
        ("page_size" = Option<u32>, Query, description = "Number of items per page (default: 20, max: 100)")
    ),
    responses(
        (status = 200, description = "User list retrieved", body = UserListResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn list_users(
    State(app_state): State<AppState>,
    Query(params): Query<PaginationQuery>,
) -> Result<Json<UserListResponse>, ApiError> {
    tracing::info!(
        "Listing users with page={}, page_size={}",
        params.page,
        params.page_size
    );

    if params.page == 0 {
        return Err(ApiError::bad_request(
            "page is less than minimum value of 1",
        ));
    }

    if params.page_size > PAGE_SIZE_MAX {
        return Err(ApiError::bad_request(format!(
            "page_size exceeds maximum value of {}",
            PAGE_SIZE_MAX
        )));
    }

    let (users, total) = app_state
        .user_service
        .list_users(params.page, params.page_size)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list users: {}", e);
            ApiError::internal_server_error("Failed to list users")
        })?;

    let total_pages = ((total as f64) / (params.page_size as f64)).ceil() as u32;

    Ok(Json(UserListResponse {
        users: users.into_iter().map(Into::into).collect(),
        page: params.page,
        page_size: params.page_size,
        total,
        total_pages,
    }))
}

/// Create admin router with all admin routes (requires admin authentication)
pub fn create_admin_router() -> Router<AppState> {
    Router::new().route("/users", get(list_users))
}
