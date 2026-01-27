use crate::{error::ApiError, middleware::AuthenticatedUser, state::AppState};
use axum::{
    extract::{Extension, State},
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use services::analytics::{ActivityType, AuthMethod, RecordActivityRequest};
use services::metrics::consts::{METRIC_USER_LOGIN, TAG_AUTH_METHOD, TAG_IS_NEW_USER};
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
pub struct BeginAuthenticationRequest {
    /// Email to restrict allowed credentials to a specific user.
    pub email: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BeginRegistrationResponse {
    pub challenge_id: services::PasskeyChallengeId,
    /// JSON publicKey options for `navigator.credentials.*({ publicKey })`
    #[schema(value_type = serde_json::Value)]
    pub public_key: services::auth::ports::PasskeyRegistrationOptions,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BeginAuthenticationResponse {
    pub challenge_id: services::PasskeyChallengeId,
    /// JSON publicKey options for `navigator.credentials.get({ publicKey })`
    #[schema(value_type = serde_json::Value)]
    pub public_key: services::auth::ports::PasskeyAuthenticationOptions,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct FinishRegistrationRequest {
    pub challenge_id: services::PasskeyChallengeId,
    /// Browser `RegisterPublicKeyCredential` JSON.
    #[schema(value_type = serde_json::Value)]
    pub credential: services::auth::ports::PasskeyRegistrationCredential,
    /// Optional user-facing label for this passkey.
    pub label: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FinishRegistrationResponse {
    pub passkey_id: services::PasskeyId,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct FinishAuthenticationRequest {
    pub challenge_id: services::PasskeyChallengeId,
    /// Browser `PublicKeyCredential` JSON (assertion).
    #[schema(value_type = serde_json::Value)]
    pub credential: services::auth::ports::PasskeyAuthenticationCredential,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PasskeyAuthResponse {
    pub token: String,
    pub session_id: String,
    pub expires_at: String,
}

fn passkey_service(
    app_state: &AppState,
) -> Result<&std::sync::Arc<dyn services::auth::ports::PasskeyService>, ApiError> {
    app_state
        .passkey_service
        .as_ref()
        .ok_or_else(|| ApiError::service_unavailable("Passkey authentication is not configured"))
}

/// Begin passkey registration (bind to authenticated user).
#[utoipa::path(
    post,
    path = "/v1/auth/passkey/registration/options",
    tag = "Auth",
    responses(
        (status = 200, description = "Passkey registration options", body = BeginRegistrationResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 503, description = "Passkey not configured", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn begin_registration(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<BeginRegistrationResponse>, ApiError> {
    let svc = passkey_service(&app_state)?;
    let res = svc
        .begin_registration(user.user_id)
        .await
        .map_err(|_| ApiError::internal_server_error("Failed to begin passkey registration"))?;

    Ok(Json(BeginRegistrationResponse {
        challenge_id: res.challenge_id,
        public_key: res.public_key,
    }))
}

/// Finish passkey registration (verify + store).
#[utoipa::path(
    post,
    path = "/v1/auth/passkey/registration/verify",
    tag = "Auth",
    request_body = FinishRegistrationRequest,
    responses(
        (status = 200, description = "Passkey registered", body = FinishRegistrationResponse),
        (status = 400, description = "Invalid registration", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 503, description = "Passkey not configured", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn finish_registration(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<FinishRegistrationRequest>,
) -> Result<Json<FinishRegistrationResponse>, ApiError> {
    let svc = passkey_service(&app_state)?;

    let passkey_id = svc
        .finish_registration(user.user_id, req.challenge_id, req.credential, req.label)
        .await
        .map_err(|_| ApiError::bad_request("Passkey registration verification failed"))?;

    Ok(Json(FinishRegistrationResponse { passkey_id }))
}

/// Begin passkey authentication (login).
#[utoipa::path(
    post,
    path = "/v1/auth/passkey/authentication/options",
    tag = "Auth",
    request_body = BeginAuthenticationRequest,
    responses(
        (status = 200, description = "Passkey authentication options", body = BeginAuthenticationResponse),
        (status = 400, description = "Invalid request", body = crate::error::ApiErrorResponse),
        (status = 503, description = "Passkey not configured", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    )
)]
pub async fn begin_authentication(
    State(app_state): State<AppState>,
    Json(req): Json<BeginAuthenticationRequest>,
) -> Result<Json<BeginAuthenticationResponse>, ApiError> {
    let svc = passkey_service(&app_state)?;
    let res = svc
        .begin_authentication(req.email)
        .await
        .map_err(|_| ApiError::bad_request("Failed to begin passkey authentication"))?;

    Ok(Json(BeginAuthenticationResponse {
        challenge_id: res.challenge_id,
        public_key: res.public_key,
    }))
}

/// Finish passkey authentication (verify + issue session).
#[utoipa::path(
    post,
    path = "/v1/auth/passkey/authentication/verify",
    tag = "Auth",
    request_body = FinishAuthenticationRequest,
    responses(
        (status = 200, description = "Authenticated", body = PasskeyAuthResponse),
        (status = 401, description = "Authentication failed", body = crate::error::ApiErrorResponse),
        (status = 503, description = "Passkey not configured", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    )
)]
pub async fn finish_authentication(
    State(app_state): State<AppState>,
    Json(req): Json<FinishAuthenticationRequest>,
) -> Result<Json<PasskeyAuthResponse>, ApiError> {
    let svc = passkey_service(&app_state)?;
    let session = svc
        .finish_authentication(req.challenge_id, req.credential)
        .await
        .map_err(|_| ApiError::unauthorized("Passkey authentication failed"))?;

    // Metrics + analytics (login only; not signup)
    let auth_method = AuthMethod::Passkey;
    let tags = [
        format!("{}:{}", TAG_AUTH_METHOD, auth_method.as_str()),
        format!("{}:{}", TAG_IS_NEW_USER, false),
    ];
    let tags_str: Vec<&str> = tags.iter().map(|s| s.as_str()).collect();
    app_state
        .metrics_service
        .record_count(METRIC_USER_LOGIN, 1, &tags_str);

    if let Err(e) = app_state
        .analytics_service
        .record_activity(RecordActivityRequest {
            user_id: session.user_id,
            activity_type: ActivityType::Login,
            auth_method: Some(auth_method),
            metadata: None,
        })
        .await
    {
        tracing::warn!(
            "Failed to record analytics for passkey login: user_id={}",
            session.user_id
        );
        tracing::debug!("Passkey analytics error: {}", e);
    }

    let token = session
        .token
        .ok_or_else(|| ApiError::internal_server_error("Failed to create session"))?;

    Ok(Json(PasskeyAuthResponse {
        token,
        session_id: session.session_id.to_string(),
        expires_at: session.expires_at.to_rfc3339(),
    }))
}

pub fn create_passkey_public_router() -> Router<AppState> {
    Router::new()
        .route("/authentication/options", post(begin_authentication))
        .route("/authentication/verify", post(finish_authentication))
}

pub fn create_passkey_registration_router() -> Router<AppState> {
    Router::new()
        .route("/registration/options", post(begin_registration))
        .route("/registration/verify", post(finish_registration))
}
