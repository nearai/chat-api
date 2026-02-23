use crate::common::is_dev;
use crate::{
    models::{ApiGatewayAttestation, AttestationReport, CombinedAttestationReport},
    state::AppState,
    ApiError,
};
use axum::{
    extract::{Query, State},
    response::Json,
    routing::get,
    Router,
};
use futures::TryStreamExt;
use http::Method;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use services::vpc::load_vpc_info;

#[derive(Debug, Clone, Deserialize, Serialize)]
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

    /// Signing address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_address: Option<String>,

    /// Optional agent instance ID to get agent attestations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
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
        ("nonce" = Option<String>, Query, description = "64 length (32 bytes) hex string"),
        ("signing_address" = Option<String>, Query, description = "Query the attestation of the specific model that owns this signing address"),
        ("agent" = Option<String>, Query, description = "Optional agent instance ID to include agent attestations in response")
    ),
    responses(
        (status = 200, description = "Combined attestation report", body = CombinedAttestationReport),
        (status = 503, description = "Attestation service unavailable", body = crate::error::ApiErrorResponse)
    ),
    tag = "Attestation"
)]
pub async fn get_attestation_report(
    State(app_state): State<AppState>,
    Query(params): Query<AttestationQuery>,
) -> Result<Json<CombinedAttestationReport>, ApiError> {
    // Exclude agent parameter from cloud-api query since it's not relevant there
    let mut cloud_api_params = params.clone();
    cloud_api_params.agent = None;
    let query =
        serde_urlencoded::to_string(&cloud_api_params).expect("Failed to serialize query string");

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

    // Load VPC info once
    let vpc_info = load_vpc_info().map(Into::into);

    let chat_api_gateway_attestation = if is_dev() {
        ApiGatewayAttestation {
            signing_address: None,
            signing_algo: None,
            intel_quote: "0x1234567890abcdef".to_string(),
            event_log: None,
            request_nonce: request_nonce.clone(),
            info: None,
            vpc: vpc_info,
        }
    } else {
        let client = dstack_sdk::dstack_client::DstackClient::new(None);

        let info = client.info().await.map_err(|e| {
            tracing::error!(
                "Failed to get chat API attestation info, are you running in a CVM?: {:?}",
                e
            );
            ApiError::internal_server_error("Failed to get chat API attestation info")
        })?;

        let cpu_quote = client.get_quote(report_data).await.map_err(|e| {
            tracing::error!(
                "Failed to get chat API attestation, are you running in a CVM?: {:?}",
                e
            );
            ApiError::internal_server_error("Failed to get chat API attestation")
        })?;

        ApiGatewayAttestation {
            signing_address: None,
            signing_algo: None,
            intel_quote: cpu_quote.quote,
            event_log: serde_json::from_str(&cpu_quote.event_log)
                .map_err(|_| ApiError::internal_server_error("Failed to deserialize event_log"))?,
            info: Some(serde_json::to_value(info).map_err(|_| {
                ApiError::internal_server_error("Failed to serialize attestation info")
            })?),
            request_nonce: request_nonce.clone(),
            vpc: vpc_info,
        }
    };

    let cloud_api_gateway_attestation = proxy_report.gateway_attestation;

    let model_attestations = proxy_report.model_attestations;

    // Fetch agent attestations if agent parameter is provided (no user auth required)
    let agent_attestations = if let Some(agent_id) = &params.agent {
        match fetch_agent_attestations(&app_state, agent_id, &request_nonce).await {
            Ok(attestations) => Some(attestations),
            Err(e) => {
                tracing::warn!("Failed to fetch agent attestations: {:?}", e);
                // Don't fail the entire request if agent attestation fetch fails
                None
            }
        }
    } else {
        None
    };

    let report = CombinedAttestationReport {
        chat_api_gateway_attestation,
        cloud_api_gateway_attestation,
        model_attestations,
        agent_attestations,
    };

    Ok(Json(report))
}

/// Fetch agent attestations from compose-api
#[derive(Debug, Deserialize)]
struct AgentAttestationResponse {
    event_log: Option<String>,
    quote: Option<String>,
    #[serde(default)]
    info: Option<serde_json::Value>,
    tls_certificate: Option<String>,
    tls_certificate_fingerprint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AgentInstanceAttestationResponse {
    image_digest: Option<String>,
    name: String,
}

/// Validate nonce is properly formatted and reasonable length (replay protection)
fn validate_nonce(nonce: &str) -> Result<(), ApiError> {
    // Nonce should be a valid hex string of reasonable length (64 chars = 32 bytes)
    const EXPECTED_NONCE_LEN: usize = 64;
    const MAX_NONCE_LEN: usize = 256;

    if nonce.len() > MAX_NONCE_LEN {
        tracing::warn!("Nonce exceeds maximum length: {}", nonce.len());
        return Err(ApiError::bad_request("Nonce is too long"));
    }

    if !nonce.chars().all(|c| c.is_ascii_hexdigit()) {
        tracing::warn!("Nonce contains non-hex characters");
        return Err(ApiError::bad_request("Nonce must be a valid hex string"));
    }

    if nonce.len() != EXPECTED_NONCE_LEN {
        tracing::warn!(
            "Nonce has unexpected length: {} (expected {})",
            nonce.len(),
            EXPECTED_NONCE_LEN
        );
        return Err(ApiError::bad_request(format!(
            "Nonce must be exactly {} characters",
            EXPECTED_NONCE_LEN
        )));
    }

    Ok(())
}

/// Validate instance name doesn't contain path traversal sequences
fn validate_instance_name(name: &str) -> Result<(), ApiError> {
    // Reject names containing path traversal sequences
    if name.contains("..") || name.contains("/") || name.contains("\\") {
        tracing::warn!("Instance name contains invalid characters: {}", name);
        return Err(ApiError::bad_request(
            "Instance name contains invalid characters",
        ));
    }

    if name.is_empty() {
        return Err(ApiError::bad_request("Instance name cannot be empty"));
    }

    Ok(())
}

/// Build full URL for agent manager request (handles base URL with/without trailing slash)
fn build_manager_url(base_url: &str, path: &str) -> Result<String, ApiError> {
    let base = url::Url::parse(base_url).map_err(|e| {
        tracing::error!("Invalid agent manager URL {}: {}", base_url, e);
        ApiError::internal_server_error("Invalid agent manager URL")
    })?;
    let full = base.join(path).map_err(|e| {
        tracing::error!("Failed to build manager URL: {}", e);
        ApiError::internal_server_error("Failed to build manager URL")
    })?;
    Ok(full.to_string())
}

/// Helper to handle HTTP response from agent manager (status check + body)
async fn handle_manager_response(
    response: reqwest::Response,
    context: &str,
) -> Result<bytes::Bytes, ApiError> {
    let status = response.status();
    if !status.is_success() {
        tracing::error!(
            "Agent manager returned error status {} for {}",
            status,
            context
        );
        return Err(ApiError::service_unavailable(format!(
            "{} service returned error: {}",
            context, status
        )));
    }
    response.bytes().await.map_err(|e| {
        tracing::error!("Failed to read {} response: {}", context, e);
        ApiError::internal_server_error(format!("Failed to read {} response", context))
    })
}

async fn fetch_agent_attestations(
    app_state: &AppState,
    agent_id: &str,
    request_nonce: &str,
) -> Result<Vec<crate::models::AgentAttestation>, ApiError> {
    use uuid::Uuid;

    // Security: Validate nonce to prevent panic/DoS from malformed input
    validate_nonce(request_nonce)?;

    // Parse the agent_id as UUID
    let agent_uuid = Uuid::parse_str(agent_id).map_err(|e| {
        tracing::error!("Invalid agent ID format: {}", e);
        ApiError::bad_request(format!("Invalid agent ID format: {}", e))
    })?;

    // Fetch the agent instance from database (no user_id check - attestation is public)
    let agent_instance = app_state
        .agent_repository
        .get_instance(agent_uuid)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch agent instance from database: {}", e);
            ApiError::internal_server_error("Failed to fetch agent instance")
        })?
        .ok_or_else(|| {
            tracing::warn!("Agent instance not found: {}", agent_id);
            ApiError::not_found("Agent instance not found")
        })?;

    // Security: Validate instance name to prevent path traversal attacks
    validate_instance_name(&agent_instance.name)?;

    // Get the agent manager URL - each instance is hosted on a specific manager
    let manager_base_url = agent_instance
        .agent_api_base_url
        .as_deref()
        .ok_or_else(|| {
            tracing::warn!("Agent instance has no agent_api_base_url: {}", agent_id);
            ApiError::bad_gateway("Agent instance has no manager URL; cannot fetch attestation")
        })?;

    let instance_name = &agent_instance.name;
    // URL-encode instance name for safe URL construction
    let encoded_instance_name = urlencoding::encode(instance_name);

    // Build URLs for the manager that hosts this instance
    // NOTE: Nonce is critical for replay protection - bind the quote to the client's nonce
    let attestation_url = build_manager_url(
        manager_base_url,
        &format!("attestation/report?nonce={}", request_nonce),
    )?;
    let instance_attestation_url = build_manager_url(
        manager_base_url,
        &format!("instances/{}/attestation", encoded_instance_name),
    )?;

    // Fetch both attestations concurrently from the corresponding agent manager
    let http_client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| {
            tracing::error!("Failed to create HTTP client: {}", e);
            ApiError::internal_server_error("Failed to create HTTP client")
        })?;

    let (attestation_response, instance_response) = tokio::join!(
        http_client.get(&attestation_url).send(),
        http_client.get(&instance_attestation_url).send(),
    );

    let attestation_response = attestation_response.map_err(|e| {
        tracing::error!(
            "Failed to fetch agent attestation from manager {}: {}",
            manager_base_url,
            e
        );
        ApiError::bad_gateway(format!("Failed to fetch agent attestation: {}", e))
    })?;

    let attestation_bytes =
        handle_manager_response(attestation_response, "Agent attestation").await?;

    let attestation_data: AgentAttestationResponse = serde_json::from_slice(&attestation_bytes)
        .map_err(|e| {
            tracing::error!("Failed to parse agent attestation response: {}", e);
            ApiError::internal_server_error("Failed to parse agent attestation")
        })?;

    let instance_response = instance_response.map_err(|e| {
        tracing::error!(
            "Failed to fetch instance attestation from manager {}: {}",
            manager_base_url,
            e
        );
        ApiError::bad_gateway(format!("Failed to fetch instance attestation: {}", e))
    })?;

    let instance_bytes = handle_manager_response(instance_response, "Instance attestation").await?;

    let instance_data: AgentInstanceAttestationResponse = serde_json::from_slice(&instance_bytes)
        .map_err(|e| {
        tracing::error!("Failed to parse instance attestation response: {}", e);
        ApiError::internal_server_error("Failed to parse instance attestation")
    })?;

    // Combine the data
    let agent_attestation = crate::models::AgentAttestation {
        name: instance_data.name,
        image_digest: instance_data.image_digest,
        event_log: attestation_data.event_log,
        info: attestation_data.info,
        intel_quote: attestation_data.quote,
        request_nonce: Some(request_nonce.to_string()),
        tls_certificate: attestation_data.tls_certificate,
        tls_certificate_fingerprint: attestation_data.tls_certificate_fingerprint,
    };

    Ok(vec![agent_attestation])
}

/// Create the attestation router
pub fn create_attestation_router() -> Router<AppState> {
    Router::new().route("/v1/attestation/report", get(get_attestation_report))
}
