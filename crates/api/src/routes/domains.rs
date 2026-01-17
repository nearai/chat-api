use crate::{error::ApiError, middleware::TenantContext, state::AppState};
use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use services::{
    domain::ports::{DomainVerification, VerificationInstructions, VerificationMethod, VerificationStatus},
    DomainVerificationId, OrganizationId,
};

// --- Request/Response types ---

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct DomainResponse {
    pub id: DomainVerificationId,
    pub organization_id: OrganizationId,
    pub domain: String,
    pub verification_method: String,
    pub verification_token: String,
    pub status: String,
    pub verified_at: Option<String>,
    pub expires_at: String,
    pub created_at: String,
    pub updated_at: String,
}

impl From<DomainVerification> for DomainResponse {
    fn from(d: DomainVerification) -> Self {
        Self {
            id: d.id,
            organization_id: d.organization_id,
            domain: d.domain,
            verification_method: d.verification_method.as_str().to_string(),
            verification_token: d.verification_token,
            status: d.status.as_str().to_string(),
            verified_at: d.verified_at.map(|t| t.to_rfc3339()),
            expires_at: d.expires_at.to_rfc3339(),
            created_at: d.created_at.to_rfc3339(),
            updated_at: d.updated_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct DomainListResponse {
    pub domains: Vec<DomainResponse>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AddDomainRequest {
    /// Domain to verify (e.g., "example.com")
    pub domain: String,
    /// Verification method: "dns_txt" or "http_file"
    pub verification_method: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct VerificationInstructionsResponse {
    pub domain: String,
    pub verification_method: String,
    pub token: String,
    pub expected_value: String,
    pub instructions: String,
    pub expires_at: String,
    pub dns_record_type: Option<String>,
    pub dns_record_name: Option<String>,
    pub dns_record_value: Option<String>,
    pub http_path: Option<String>,
    pub http_content: Option<String>,
}

impl From<VerificationInstructions> for VerificationInstructionsResponse {
    fn from(v: VerificationInstructions) -> Self {
        let (dns_record_type, dns_record_name, dns_record_value, http_path, http_content) =
            match v.method {
                VerificationMethod::DnsTxt => (
                    Some("TXT".to_string()),
                    Some(format!("_nearai-verify.{}", v.domain)),
                    Some(v.expected_value.clone()),
                    None,
                    None,
                ),
                VerificationMethod::HttpFile => (
                    None,
                    None,
                    None,
                    Some(format!("https://{}/.well-known/nearai-verify.txt", v.domain)),
                    Some(v.expected_value.clone()),
                ),
            };

        Self {
            domain: v.domain,
            verification_method: v.method.as_str().to_string(),
            token: v.token,
            expected_value: v.expected_value,
            instructions: v.instructions,
            expires_at: v.expires_at.to_rfc3339(),
            dns_record_type,
            dns_record_name,
            dns_record_value,
            http_path,
            http_content,
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct VerifyDomainResponse {
    pub success: bool,
    pub message: String,
    pub status: String,
    pub domain: Option<DomainResponse>,
}

// --- Handlers ---

/// List organization domains
#[utoipa::path(
    get,
    path = "/v1/admin/domains",
    tag = "Domains",
    responses(
        (status = 200, description = "List of domains", body = DomainListResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn list_domains(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
) -> Result<Json<DomainListResponse>, ApiError> {
    tracing::info!(
        "Listing domains for organization_id={}",
        tenant.organization_id
    );

    // Check permission
    if !tenant.permissions.contains(&"domains:read".to_string()) {
        return Err(ApiError::forbidden("Missing permission to view domains"));
    }

    let domains = app_state
        .domain_service
        .get_organization_domains(tenant.organization_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list domains: {}", e);
            ApiError::internal_server_error("Failed to list domains")
        })?;

    Ok(Json(DomainListResponse {
        domains: domains.into_iter().map(Into::into).collect(),
    }))
}

/// Add domain for verification
#[utoipa::path(
    post,
    path = "/v1/admin/domains",
    tag = "Domains",
    request_body = AddDomainRequest,
    responses(
        (status = 201, description = "Domain added", body = VerificationInstructionsResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn add_domain(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Json(request): Json<AddDomainRequest>,
) -> Result<(StatusCode, Json<VerificationInstructionsResponse>), ApiError> {
    tracing::info!(
        "Adding domain: domain={}, organization_id={}",
        request.domain,
        tenant.organization_id
    );

    // Check permission
    if !tenant.permissions.contains(&"domains:manage".to_string()) {
        return Err(ApiError::forbidden("Missing permission to manage domains"));
    }

    // Validate domain format
    if !is_valid_domain(&request.domain) {
        return Err(ApiError::bad_request("Invalid domain format"));
    }

    let verification_method = match request.verification_method.as_deref() {
        Some("http_file") | Some("http") => VerificationMethod::HttpFile,
        Some("dns_txt") | Some("dns") | None => VerificationMethod::DnsTxt,
        Some(other) => {
            return Err(ApiError::bad_request(&format!(
                "Invalid verification method: '{}'. Must be 'dns_txt' or 'http_file'",
                other
            )));
        }
    };

    let instructions = app_state
        .domain_service
        .initiate_verification(tenant.organization_id, request.domain.clone(), verification_method)
        .await
        .map_err(|e| {
            tracing::error!("Failed to add domain: {}", e);
            if e.to_string().contains("already") {
                ApiError::bad_request("Domain is already being verified or claimed")
            } else {
                ApiError::internal_server_error("Failed to add domain")
            }
        })?;

    Ok((StatusCode::CREATED, Json(instructions.into())))
}

/// Get domain details and verification instructions
#[utoipa::path(
    get,
    path = "/v1/admin/domains/{id}",
    tag = "Domains",
    params(
        ("id" = DomainVerificationId, Path, description = "Domain verification ID")
    ),
    responses(
        (status = 200, description = "Domain details with verification instructions", body = VerificationInstructionsResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Not found", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn get_domain(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Path(id): Path<DomainVerificationId>,
) -> Result<Json<VerificationInstructionsResponse>, ApiError> {
    tracing::info!("Getting domain: domain_id={}", id);

    // Check permission
    if !tenant.permissions.contains(&"domains:read".to_string()) {
        return Err(ApiError::forbidden("Missing permission to view domains"));
    }

    let domain = app_state
        .domain_service
        .get_domain_verification(id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get domain: {}", e);
            if e.to_string().contains("not found") {
                ApiError::not_found("Domain not found")
            } else {
                ApiError::internal_server_error("Failed to get domain")
            }
        })?;

    // Verify access
    if domain.organization_id != tenant.organization_id {
        return Err(ApiError::forbidden("Domain belongs to another organization"));
    }

    let instructions = app_state
        .domain_service
        .get_verification_instructions(id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get verification instructions: {}", e);
            ApiError::internal_server_error("Failed to get verification instructions")
        })?;

    Ok(Json(instructions.into()))
}

/// Check domain verification status
#[utoipa::path(
    post,
    path = "/v1/admin/domains/{id}/verify",
    tag = "Domains",
    params(
        ("id" = DomainVerificationId, Path, description = "Domain verification ID")
    ),
    responses(
        (status = 200, description = "Verification result", body = VerifyDomainResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Not found", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn verify_domain(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Path(id): Path<DomainVerificationId>,
) -> Result<Json<VerifyDomainResponse>, ApiError> {
    tracing::info!("Verifying domain: domain_id={}", id);

    // Check permission
    if !tenant.permissions.contains(&"domains:manage".to_string()) {
        return Err(ApiError::forbidden("Missing permission to manage domains"));
    }

    // First get domain to verify access
    let domain = app_state
        .domain_service
        .get_domain_verification(id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get domain: {}", e);
            ApiError::not_found("Domain not found")
        })?;

    if domain.organization_id != tenant.organization_id {
        return Err(ApiError::forbidden("Domain belongs to another organization"));
    }

    // Check verification
    let result = app_state
        .domain_service
        .check_verification(id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to verify domain: {}", e);
            ApiError::internal_server_error("Failed to verify domain")
        })?;

    let (success, message) = match result.status {
        VerificationStatus::Verified => (true, "Domain verified successfully".to_string()),
        VerificationStatus::Failed => (false, "Verification failed. Please check your DNS/HTTP configuration.".to_string()),
        VerificationStatus::Pending => (false, "Verification not yet complete. DNS changes may take time to propagate.".to_string()),
        VerificationStatus::Expired => (false, "Verification token has expired. Please add the domain again.".to_string()),
    };

    Ok(Json(VerifyDomainResponse {
        success,
        message,
        status: result.status.as_str().to_string(),
        domain: Some(result.into()),
    }))
}

/// Remove domain
#[utoipa::path(
    delete,
    path = "/v1/admin/domains/{id}",
    tag = "Domains",
    params(
        ("id" = DomainVerificationId, Path, description = "Domain verification ID")
    ),
    responses(
        (status = 204, description = "Domain removed"),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Not found", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn remove_domain(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Path(id): Path<DomainVerificationId>,
) -> Result<StatusCode, ApiError> {
    tracing::warn!("Removing domain: domain_id={}", id);

    // Check permission
    if !tenant.permissions.contains(&"domains:manage".to_string()) {
        return Err(ApiError::forbidden("Missing permission to manage domains"));
    }

    // remove_domain checks ownership internally
    app_state
        .domain_service
        .remove_domain(tenant.organization_id, id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to remove domain: {}", e);
            let msg = e.to_string();
            if msg.contains("not found") {
                ApiError::not_found("Domain not found")
            } else if msg.contains("does not belong") {
                ApiError::forbidden("Domain belongs to another organization")
            } else {
                ApiError::internal_server_error("Failed to remove domain")
            }
        })?;

    Ok(StatusCode::NO_CONTENT)
}

// --- Helper functions ---

fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }

    // Simple domain validation: must have at least one dot, no leading/trailing dots
    if !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }

    // Each label must be 1-63 characters, alphanumeric + hyphens
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }

    true
}

/// Create domains router
pub fn create_domains_router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_domains).post(add_domain))
        .route("/{id}", get(get_domain).delete(remove_domain))
        .route("/{id}/verify", post(verify_domain))
}
