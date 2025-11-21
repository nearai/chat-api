use crate::{consts::LIMIT_MAX, error::ApiError, models::*, state::AppState};
use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use serde::Deserialize;

/// Pagination query parameters
#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    /// Maximum number of items to return (default: 20, max: LIMIT_MAX)
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Number of items to skip (default: 0)
    #[serde(default = "default_offset")]
    pub offset: i64,
}

impl PaginationQuery {
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.limit < 1 {
            return Err(ApiError::bad_request(
                "limit is less than minimum value of 1",
            ));
        }

        if self.limit > LIMIT_MAX {
            return Err(ApiError::bad_request(format!(
                "limit exceeds maximum value of {}",
                LIMIT_MAX
            )));
        }

        Ok(())
    }
}

fn default_limit() -> i64 {
    20
}

fn default_offset() -> i64 {
    0
}

/// List users
///
/// Returns a paginated list of users. Requires admin authentication.
#[utoipa::path(
    get,
    path = "/v1/admin/users",
    tag = "Admin",
    params(
        ("limit" = Option<u32>, Query, description = "Maximum number of items to return (default: 20, max: 100)"),
        ("offset" = Option<u32>, Query, description = "Number of items to skip (default: 0)")
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
        "Listing users with limit={}, offset={}",
        params.limit,
        params.offset
    );

    params.validate()?;

    let (users, total) = app_state
        .user_service
        .list_users(params.limit, params.offset)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list users: {}", e);
            ApiError::internal_server_error("Failed to list users")
        })?;

    Ok(Json(UserListResponse {
        users: users.into_iter().map(Into::into).collect(),
        limit: params.limit,
        offset: params.offset,
        total,
    }))
}

/// Create admin router with all admin routes (requires admin authentication)
pub fn create_admin_router() -> Router<AppState> {
    Router::new().route("/users", get(list_users))
}
