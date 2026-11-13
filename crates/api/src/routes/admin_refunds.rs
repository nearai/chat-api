use crate::{error::ApiError, middleware::AuthenticatedUser, state::AppState};
use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use serde::Deserialize;
use services::subscription::refunds::*;
use uuid::Uuid;
fn error(e: RefundError) -> ApiError {
    match e {
        RefundError::Invalid(m) => ApiError::bad_request(m),
        RefundError::Conflict(m) => ApiError::conflict(m),
        RefundError::NotFound => ApiError::not_found(e.to_string()),
        RefundError::Disabled => ApiError::forbidden(e.to_string()),
        RefundError::Upstream => ApiError::bad_gateway(e.to_string()),
        RefundError::Database => ApiError::internal_server_error(e.to_string()),
    }
}
#[derive(Deserialize)]
pub struct ListQuery {
    pub subscription_id: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}
pub async fn list(
    State(s): State<AppState>,
    Query(q): Query<ListQuery>,
) -> std::result::Result<Json<RefundList>, ApiError> {
    s.subscription_service
        .admin_list_refunds(
            q.subscription_id,
            q.limit.unwrap_or(20),
            q.offset.unwrap_or(0),
        )
        .await
        .map(Json)
        .map_err(error)
}
pub async fn prepare(
    State(s): State<AppState>,
    Extension(admin): Extension<AuthenticatedUser>,
    Json(r): Json<PrepareRefund>,
) -> std::result::Result<Json<RefundOperation>, ApiError> {
    s.subscription_service
        .admin_prepare_refund(r, admin.user_id)
        .await
        .map(Json)
        .map_err(error)
}
pub async fn execute(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    Extension(admin): Extension<AuthenticatedUser>,
    Json(r): Json<RefundConfirmation>,
) -> std::result::Result<Json<RefundOperation>, ApiError> {
    s.subscription_service
        .admin_refund_action(id, Action::Execute, Some(r), admin.user_id)
        .await
        .map(Json)
        .map_err(error)
}
pub async fn retry(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    Extension(admin): Extension<AuthenticatedUser>,
    Json(r): Json<RefundConfirmation>,
) -> std::result::Result<Json<RefundOperation>, ApiError> {
    s.subscription_service
        .admin_refund_action(id, Action::RetryFailed, Some(r), admin.user_id)
        .await
        .map(Json)
        .map_err(error)
}
pub async fn sync(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    Extension(admin): Extension<AuthenticatedUser>,
) -> std::result::Result<Json<RefundOperation>, ApiError> {
    s.subscription_service
        .admin_refund_action(id, Action::Sync, None, admin.user_id)
        .await
        .map(Json)
        .map_err(error)
}
