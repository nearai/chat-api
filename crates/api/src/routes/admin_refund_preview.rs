use crate::{error::ApiError, state::AppState};
use axum::{
    extract::{Path, State},
    Json,
};
use services::subscription::{
    ports::SubscriptionError,
    refund_preview::{RefundPreview, RefundPreviewRequest},
};

fn valid_id(value: &str, prefix: &str) -> bool {
    value.starts_with(prefix)
        && value.len() > prefix.len()
        && value.len() <= 255
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

pub async fn preview(
    State(state): State<AppState>,
    Path(subscription_id): Path<String>,
    Json(request): Json<RefundPreviewRequest>,
) -> Result<Json<RefundPreview>, ApiError> {
    if !valid_id(&subscription_id, "sub_")
        || request
            .starting_after
            .as_deref()
            .is_some_and(|id| !valid_id(id, "in_"))
    {
        return Err(ApiError::bad_request(
            "Invalid subscription ID or invoice cursor",
        ));
    }
    if request.effective_at.timestamp_subsec_nanos() != 0 {
        return Err(ApiError::bad_request(
            "Effective date must use whole seconds",
        ));
    }
    state
        .subscription_service
        .admin_refund_preview(&subscription_id, request)
        .await
        .map(Json)
        .map_err(|e| match e {
            SubscriptionError::SubscriptionNotFound => {
                ApiError::not_found("Subscription not found for this user")
            }
            SubscriptionError::InvalidProvider(_) => {
                ApiError::bad_request("Only Stripe subscriptions support refund previews")
            }
            SubscriptionError::NotConfigured => {
                ApiError::service_unavailable("Stripe is not configured")
            }
            _ => {
                tracing::error!(
                    error_type = services::logging::error_type(&e),
                    "Refund preview failed"
                );
                ApiError::bad_gateway("Unable to read billing records. Retry the preview.")
            }
        })
}
