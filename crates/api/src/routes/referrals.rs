use crate::{error::ApiError, middleware::AuthenticatedUser, state::AppState};
use axum::{extract::State, routing::get, Extension, Json, Router};
use services::referral::ports::{ReferralDashboard, ReferralError};

fn referral_error_to_api_error(error: ReferralError) -> ApiError {
    match error {
        ReferralError::InvalidReferralCode => ApiError::bad_request("Invalid referral code"),
        ReferralError::SelfReferral => ApiError::bad_request("A user cannot refer themselves"),
        ReferralError::InvalidConfig(msg) => ApiError::bad_request(msg),
        ReferralError::Database(err) => {
            tracing::error!(error = ?err, "Referral operation failed");
            ApiError::internal_server_error("Failed to process referral request")
        }
    }
}

/// Get current user's referral dashboard.
#[utoipa::path(
    get,
    path = "/v1/referrals/me",
    tag = "Referrals",
    responses(
        (status = 200, description = "Referral dashboard", body = ReferralDashboard),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn get_my_referrals(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<ReferralDashboard>, ApiError> {
    let dashboard = app_state
        .referral_service
        .get_dashboard(user.user_id)
        .await
        .map_err(referral_error_to_api_error)?;

    Ok(Json(dashboard))
}

pub fn create_referrals_router() -> Router<AppState> {
    Router::new().route("/v1/referrals/me", get(get_my_referrals))
}
