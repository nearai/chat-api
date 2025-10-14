use axum::{extract::Query, http::StatusCode, response::Json, routing::get, Router};
use serde::Deserialize;

use crate::{
    models::{ApiGatewayAttestation, CombinedAttestationReport, ErrorResponse, ModelAttestation},
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct AttestationQuery {
    /// Optional model name to get specific attestations
    pub model: Option<String>,

    /// Signing algorithm: "ecdsa" or "ed25519"
    pub signing_algo: Option<String>,
}

/// GET /v1/attestation/report
///
/// Returns a combined attestation report with mock data demonstrating the API interface.
///
/// This endpoint (chat-api) acts as an AI Gateway Service and combines attestations from multiple layers:
/// 1. **This API's own CPU attestation** (your_gateway_attestation) - Proves this chat-api runs in a trusted TEE
/// 2. **Cloud-API gateway attestation** (cloud_api_gateway_attestation) - From the intermediate service we depend on
/// 3. **Model provider attestations** (model_attestations) - From VLLM inference providers with Intel TDX + NVIDIA GPU attestation
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
    Query(params): Query<AttestationQuery>,
) -> Result<Json<CombinedAttestationReport>, (StatusCode, Json<ErrorResponse>)> {
    let model_name = params.model.unwrap_or_else(|| "llama-3".to_string());
    let signing_algo = params.signing_algo.unwrap_or_else(|| "ecdsa".to_string());

    // Mock THIS chat-api's own CPU attestation (proves this service runs in a trusted TEE)
    let chat_api_gateway_attestation = ApiGatewayAttestation {
        quote: "0x04000000b40015000000000003000000000000004d4a04040000000000000000010000000000000089be4e9fcc80eaca7c4fba9c387e85bf8bf0e88170e0a5de8eafb8a1c99ad4a0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        event_log: "0x0800000001000000746573745f6576656e745f6c6f670000000000000000".to_string(),
    };

    // Mock cloud-api gateway attestation
    let cloud_api_gateway_attestation = ApiGatewayAttestation {
        quote: "0x04000000c50015000000000003000000000000005e5b05050000000000000000010000000000000097cf5f9acc91fbdb8d5fca9c498f96cf9cf1f99271f1b6ef9fbfc9b2d99be5b1000000000000000000000000000000000000000000000000000000000000000".to_string(),
        event_log: "0x0900000001000000636c6f75645f6170695f6576656e745f6c6f67000000".to_string(),
    };

    // Mock model attestations - returns different data based on signing algorithm
    let model_attestations = if signing_algo == "ed25519" {
        vec![ModelAttestation {
            signing_address: "ed25519:a5f8d3c7b2e1f4a6c8b9d3e7f1a5c8b2d4e6f8a1c3b5d7e9f1a3c5b7d9e1f3a5".to_string(),
            intel_quote: "AgABAM0LAAANAA8AAAAAqQIBAgJyQtTJ0KHRhUKxvXqPhrGd5m6z7B07TGwNhh4pAAAAEBECAAEAAAABAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUAAAAAAAAApAAAAAAAAADd2I8gyY3O6gPPUGHzKMU8mJ19zMHKmDMhOFRlhWz3AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAtsrIrjH3SWF7qvZ0rF5T/3pE3oBwG6l4cB1XBQSjuXQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD1U0q8m4qdY0WnZUWWPvJhKBvv5bHLK3qb6NR4yVfAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            nvidia_payload: r#"{"nonce":"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef","evidence_list":[{"certificate":"-----BEGIN CERTIFICATE-----\nMIICpDCCAYwCCQDXrW2KRlMzwDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls\nb2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYD\nVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDM\n-----END CERTIFICATE-----","evidence":"base64_encoded_gpu_attestation_data","arch":"HOPPER"}],"attestation_cert_chain":["-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJANqL6+X...\n-----END CERTIFICATE-----"]}"#.to_string(),
            event_log: Some(serde_json::json!({
                "pcrs": {
                    "0": "000000000000000000000000000000000000000000000000000000000000000",
                    "1": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                },
                "events": [
                    {
                        "pcr_index": 0,
                        "event_type": "EV_POST_CODE",
                        "digest": "000000000000000000000000000000000000000000000000000000000000000"
                    }
                ]
            })),
            info: Some(serde_json::json!({
                "tappd_version": "1.0.0",
                "tdx_module_version": "1.5.0",
                "boot_time": "2024-10-14T10:30:00Z"
            })),
        }]
    } else {
        // Default ECDSA
        vec![ModelAttestation {
            signing_address: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb".to_string(),
            intel_quote: "AgABAM0LAAANAA8AAAAAqQIBAgJyQtTJ0KHRhUKxvXqPhrGd5m6z7B07TGwNhh4pAAAAEBECAAEAAAABAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUAAAAAAAAApAAAAAAAAADd2I8gyY3O6gPPUGHzKMU8mJ19zMHKmDMhOFRlhWz3AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAtsrIrjH3SWF7qvZ0rF5T/3pE3oBwG6l4cB1XBQSjuXQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD1U0q8m4qdY0WnZUWPvJhKBvv5bHLK3qb6NR4yVfAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            nvidia_payload: r#"{"nonce":"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890","evidence_list":[{"certificate":"-----BEGIN CERTIFICATE-----\nMIICpDCCAYwCCQDXrW2KRlMzwDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls\nb2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYD\nVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDM\n-----END CERTIFICATE-----","evidence":"base64_encoded_gpu_attestation_data","arch":"HOPPER"}],"attestation_cert_chain":["-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJANqL6+X...\n-----END CERTIFICATE-----"]}"#.to_string(),
            event_log: Some(serde_json::json!({
                "pcrs": {
                    "0": "000000000000000000000000000000000000000000000000000000000000000",
                    "1": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                },
                "events": [
                    {
                        "pcr_index": 0,
                        "event_type": "EV_POST_CODE",
                        "digest": "000000000000000000000000000000000000000000000000000000000000000"
                    }
                ]
            })),
            info: Some(serde_json::json!({
                "tappd_version": "1.0.0",
                "tdx_module_version": "1.5.0",
                "boot_time": "2024-10-14T10:30:00Z"
            })),
        }]
    };

    tracing::info!(
        "Returning mock attestation report for model={}, signing_algo={}",
        model_name,
        signing_algo
    );

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
