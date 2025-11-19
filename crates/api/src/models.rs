use crate::consts::SYSTEM_PROMPT_MAX_LEN;
use crate::ApiError;
use serde::{Deserialize, Serialize};
use services::UserId;
use utoipa::ToSchema;

/// User response DTO
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UserResponse {
    pub id: UserId,
    pub email: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Linked OAuth account response
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct LinkedAccountResponse {
    pub provider: String,
    pub linked_at: String,
}

/// User profile response with linked accounts
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UserProfileResponse {
    pub user: UserResponse,
    pub linked_accounts: Vec<LinkedAccountResponse>,
}

/// Response for successful authentication
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AuthResponse {
    pub token: String,
    pub expires_at: String,
}

impl From<services::user::ports::User> for UserResponse {
    fn from(user: services::user::ports::User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            name: user.name,
            avatar_url: user.avatar_url,
            created_at: user.created_at.to_rfc3339(),
            updated_at: user.updated_at.to_rfc3339(),
        }
    }
}

impl From<services::user::ports::LinkedOAuthAccount> for LinkedAccountResponse {
    fn from(account: services::user::ports::LinkedOAuthAccount) -> Self {
        let provider = match account.provider {
            services::user::ports::OAuthProvider::Google => "google",
            services::user::ports::OAuthProvider::Github => "github",
        };
        Self {
            provider: provider.to_string(),
            linked_at: account.linked_at.to_rfc3339(),
        }
    }
}

impl From<services::user::ports::UserProfile> for UserProfileResponse {
    fn from(profile: services::user::ports::UserProfile) -> Self {
        Self {
            user: profile.user.into(),
            linked_accounts: profile
                .linked_accounts
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}

/// Cloud-API gateway attestation (forwarded from dependency)
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApiGatewayAttestation {
    /// Intel TDX quote in hex format
    pub intel_quote: String,
    /// Event log
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_log: Option<serde_json::Value>,
    /// Request nonce
    pub request_nonce: String,
    /// Attestation info
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<serde_json::Value>,
}

/// Model attestation from VLLM inference providers
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ModelAttestation {
    /// Cryptographic signing address (ECDSA or Ed25519)
    pub signing_address: String,

    /// Base64-encoded Intel TDX quote from model host
    pub intel_quote: String,

    /// JSON string containing NVIDIA GPU attestation
    pub nvidia_payload: String,

    /// TDX event log
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_log: Option<serde_json::Value>,

    /// Additional TDX/tappd info
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<serde_json::Value>,
}

/// Complete attestation report combining all layers
///
/// This report proves the entire trust chain:
/// 1. This chat-api service runs in a TEE (your_gateway_attestation)
/// 2. The cloud-api dependency runs in a TEE (cloud_api_gateway_attestation)  
/// 3. The model inference providers run on trusted hardware (model_attestations)
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CombinedAttestationReport {
    /// This chat-api's own CPU attestation (proves this service runs in a TEE)
    pub chat_api_gateway_attestation: ApiGatewayAttestation,

    /// Cloud-API's gateway attestation (the intermediate service we depend on)
    pub cloud_api_gateway_attestation: ApiGatewayAttestation,

    /// Model provider attestations (can be multiple when routing to different models)
    pub model_attestations: Option<Vec<ModelAttestation>>,
}

/// Attestation report structure from proxy_service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    pub gateway_attestation: ApiGatewayAttestation,
    pub model_attestations: Option<Vec<ModelAttestation>>,
}

/// User settings content for API responses
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UserSettingsContent {
    /// Notification preference
    pub notification: bool,
    /// System prompt
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<String>,
}

impl From<services::user::ports::UserSettingsContent> for UserSettingsContent {
    fn from(content: services::user::ports::UserSettingsContent) -> Self {
        Self {
            notification: content.notification,
            system_prompt: content.system_prompt,
        }
    }
}

/// User settings response
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UserSettingsResponse {
    /// User ID
    pub user_id: UserId,
    /// Settings content (serialized as "settings")
    #[serde(rename = "settings")]
    pub content: UserSettingsContent,
}

/// User settings update request
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UpdateUserSettingsRequest {
    /// Notification preference
    pub notification: bool,
    /// System prompt
    pub system_prompt: Option<String>,
}

impl UpdateUserSettingsRequest {
    pub fn validate(&self) -> Result<(), ApiError> {
        if let Some(ref system_prompt) = self.system_prompt {
            if system_prompt.len() > SYSTEM_PROMPT_MAX_LEN {
                return Err(ApiError::bad_request("System prompt exceeds max length"));
            }
        }

        Ok(())
    }
}

/// User settings update request (partial update)
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UpdateUserSettingsPartiallyRequest {
    /// Notification preference
    pub notification: Option<bool>,
    /// System prompt
    pub system_prompt: Option<String>,
}

impl UpdateUserSettingsPartiallyRequest {
    pub fn validate(&self) -> Result<(), ApiError> {
        if let Some(ref system_prompt) = self.system_prompt {
            if system_prompt.len() > SYSTEM_PROMPT_MAX_LEN {
                return Err(ApiError::bad_request("System prompt exceeds max length"));
            }
        }

        Ok(())
    }
}
