use crate::{error::ApiError, models::*, state::AppState};
use axum::{extract::State, routing::get, Json, Router};

/// Get system configs (requires user authentication, not admin)
#[utoipa::path(
    get,
    path = "/v1/configs",
    tag = "Configs",
    responses(
        (status = 200, description = "System configs retrieved", body = Option<SystemConfigsResponse>),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn get_system_configs(
    State(app_state): State<AppState>,
) -> Result<Json<Option<SystemConfigsResponse>>, ApiError> {
    tracing::info!("Getting system configs");

    let config = app_state
        .system_configs_service
        .get_configs()
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to get system configs");
            ApiError::internal_server_error("Failed to get system configs")
        })?;

    Ok(Json(config.map(Into::into)))
}

/// Create configs router with all configs routes (requires user authentication)
pub fn create_configs_router() -> Router<AppState> {
    Router::new().route("/v1/configs", get(get_system_configs))
}
