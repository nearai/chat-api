use crate::{
    models::{ApiGatewayAttestation, AttestationReport, CombinedAttestationReport, ErrorResponse},
    state::AppState,
};
use axum::{
    extract::Query, extract::State, http::StatusCode, response::Json, routing::get, Router,
};
use futures::TryStreamExt;
use http::Method;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Deserialize, Serialize)]
pub struct AttestationQuery {
    /// Optional model name to get specific attestations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,

    /// Signing algorithm: "ecdsa" or "ed25519"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_algo: Option<String>,
}

/// GET /v1/attestation/report
///
/// Returns a combined attestation report combining attestations from multiple layers.
///
/// This endpoint (chat-api) acts as an AI Gateway Service and combines attestations from multiple layers:
/// 1. **This API's own CPU attestation** (chat_api_gateway_attestation) - Proves this chat-api runs in a trusted TEE (currently mock data)
/// 2. **Cloud-API gateway attestation** (cloud_api_gateway_attestation) - Fetched from proxy_service `/v1/attestation/report` endpoint
/// 3. **Model provider attestations** (model_attestations) - Fetched from proxy_service `/v1/attestation/report` endpoint
///
/// The `signing_algo` query parameter (ecdsa or ed25519) is passed to proxy_service to get the appropriate attestations.
#[utoipa::path(
    get,
    path = "/v1/attestation/report",
    params(
        ("model" = Option<String>, Query, description = "Optional model name to filter attestations"),
        ("signing_algo" = Option<String>, Query, description = "Signing algorithm: 'ecdsa' or 'ed25519'")
    ),
    responses(
        (status = 200, description = "Combined attestation report", body = CombinedAttestationReport),
        (status = 503, description = "Attestation service unavailable", body = ErrorResponse)
    ),
    tag = "attestation"
)]
pub async fn get_attestation_report(
    State(app_state): State<AppState>,
    Query(params): Query<AttestationQuery>,
) -> Result<Json<CombinedAttestationReport>, (StatusCode, Json<ErrorResponse>)> {
    let query = serde_urlencoded::to_string(&params).unwrap();

    // Build the path for proxy_service attestation endpoint
    let path = format!("attestation/report?{}", query);

    // Use proxy_service to forward the request
    let proxy_response = app_state
        .proxy_service
        .forward_request(Method::GET, &path, http::HeaderMap::new(), None)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to fetch attestation report from proxy_service: {}",
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("Failed to fetch attestation report: {}", e),
                }),
            )
        })?;

    // Check response status
    if proxy_response.status < 200 || proxy_response.status >= 300 {
        tracing::error!(
            "proxy_service returned error status {}",
            proxy_response.status
        );
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: format!(
                    "Attestation service returned error: {}",
                    proxy_response.status
                ),
            }),
        ));
    }

    // Collect the response body from the stream
    let body_bytes: bytes::Bytes = proxy_response
        .body
        .try_collect::<Vec<_>>()
        .await
        .map_err(|e| {
            tracing::error!("Failed to read response body from proxy_service: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to read response body: {}", e),
                }),
            )
        })?
        .into_iter()
        .flatten()
        .collect();

    // Parse the response JSON
    let proxy_report: AttestationReport = serde_json::from_slice(&body_bytes).map_err(|e| {
        tracing::error!(
            "Failed to parse attestation report from proxy_service: {}",
            e
        );
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to parse attestation report: {}", e),
            }),
        )
    })?;

    // Mock THIS chat-api's own CPU attestation (proves this service runs in a trusted TEE)
    // TODO: Implement real chat-api gateway attestation
    let chat_api_gateway_attestation = ApiGatewayAttestation {
        intel_quote: "0x04000000b40015000000000003000000000000004d4a04040000000000000000010000000000000089be4e9fcc80eaca7c4fba9c387e85bf8bf0e88170e0a5de8eafb8a1c99ad4a0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        event_log: Some(json!("0x0800000001000000746573745f6576656e745f6c6f670000000000000000")),
    };

    let cloud_api_gateway_attestation = proxy_report.gateway_attestation;

    let model_attestations = proxy_report.model_attestations;

    let report = CombinedAttestationReport {
        chat_api_gateway_attestation,
        cloud_api_gateway_attestation,
        model_attestations,
    };

    Ok(Json(report))
}

/// Create the attestation router
pub fn create_attestation_router() -> Router<AppState> {
    Router::new().route("/v1/attestation/report", get(get_attestation_report))
}
