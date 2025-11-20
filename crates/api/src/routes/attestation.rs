use crate::common::is_dev;
use crate::{
    models::{ApiGatewayAttestation, AttestationReport, CombinedAttestationReport},
    state::AppState,
    ApiError,
};
use axum::{extract::Query, extract::State, response::Json, routing::get, Router};
use futures::TryStreamExt;
use http::Method;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct AttestationQuery {
    /// Optional model name to get specific attestations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,

    /// Signing algorithm: "ecdsa" or "ed25519"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_algo: Option<String>,

    /// random hex string WITHOUT 0x prefix (32 bytes)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// GET /v1/attestation/report
///
/// Returns a combined attestation report combining attestations from multiple layers.
///
/// This endpoint (chat-api) acts as an AI Gateway Service and combines attestations from multiple layers:
/// 1. **This API's own CPU attestation** (chat_api_gateway_attestation) - Proves this chat-api runs in a trusted TEE
/// 2. **Cloud-API gateway attestation** (cloud_api_gateway_attestation) - Fetched from proxy_service `/v1/attestation/report` endpoint
/// 3. **Model provider attestations** (model_attestations) - Fetched from proxy_service `/v1/attestation/report` endpoint
///
/// The `signing_algo` query parameter (ecdsa or ed25519) is passed to proxy_service to get the appropriate attestations.
#[utoipa::path(
    get,
    path = "/v1/attestation/report",
    params(
        ("model" = Option<String>, Query, description = "Optional model name to filter model attestations"),
        ("signing_algo" = Option<String>, Query, description = "Signing algorithm: 'ecdsa' or 'ed25519'"),
        ("nonce" = Option<String>, Query, description = "64 length (32 bytes) hex string")
    ),
    responses(
        (status = 200, description = "Combined attestation report", body = CombinedAttestationReport),
        (status = 503, description = "Attestation service unavailable", body = crate::error::ApiErrorResponse)
    ),
    tag = "attestation"
)]
pub async fn get_attestation_report(
    State(app_state): State<AppState>,
    Query(params): Query<AttestationQuery>,
) -> Result<Json<CombinedAttestationReport>, ApiError> {
    let query = serde_urlencoded::to_string(&params).expect("Failed to serialize query string");

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
            ApiError::bad_gateway(format!("Failed to fetch attestation report: {}", e))
        })?;

    // Check response status
    if proxy_response.status < 200 || proxy_response.status >= 300 {
        tracing::error!(
            "proxy_service returned error status {}",
            proxy_response.status
        );
        return Err(ApiError::service_unavailable(format!(
            "Attestation service returned error: {}",
            proxy_response.status
        )));
    }

    // Collect the response body from the stream
    let body_bytes: bytes::Bytes = proxy_response
        .body
        .try_collect::<Vec<_>>()
        .await
        .map_err(|e| {
            tracing::error!("Failed to read response body from proxy_service: {}", e);
            ApiError::internal_server_error(format!("Failed to read response body: {}", e))
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
        ApiError::internal_server_error(format!("Failed to parse attestation report: {}", e))
    })?;

    let mut report_data = vec![0u8; 64];

    let request_nonce = proxy_report.gateway_attestation.request_nonce.clone();

    // Parse nonce from cloud API gateway attestation to keep consistent
    let nonce_bytes = hex::decode(&request_nonce).map_err(|e| {
        tracing::error!("Failed to decode nonce hex string: {}", e);
        ApiError::internal_server_error(format!("Invalid nonce format: {e}"))
    })?;

    report_data[32..].copy_from_slice(&nonce_bytes);

    let chat_api_gateway_attestation = if is_dev() {
        ApiGatewayAttestation {
            intel_quote: "0x1234567890abcdef".to_string(),
            event_log: None,
            request_nonce,
            info: None,
        }
    } else {
        let client = dstack_sdk::dstack_client::DstackClient::new(None);

        let info = client.info().await.map_err(|_| {
            tracing::error!("Failed to get chat API attestation info, are you running in a CVM?");
            ApiError::internal_server_error("Failed to get chat API attestation info")
        })?;

        let cpu_quote = client.get_quote(report_data).await.map_err(|_| {
            tracing::error!("Failed to get chat API attestation, are you running in a CVM?");
            ApiError::internal_server_error("Failed to get chat API attestation")
        })?;

        ApiGatewayAttestation {
            intel_quote: cpu_quote.quote,
            event_log: serde_json::from_str(&cpu_quote.event_log)
                .map_err(|_| ApiError::internal_server_error("Failed to deserialize event_log"))?,
            info: Some(serde_json::to_value(info).map_err(|_| ApiError::internal_server_error("Failed to serialize attestation info"))?),
            request_nonce,
        }
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
