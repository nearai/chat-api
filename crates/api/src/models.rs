use crate::consts::SYSTEM_PROMPT_MAX_LEN;
use crate::ApiError;
use serde::{Deserialize, Serialize};
use services::file::ports::FileData;
use services::system_configs::ports::SubscriptionPlanConfig;
use services::UserId;
use std::collections::HashMap;
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
            services::user::ports::OAuthProvider::Near => "near",
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

/// VPC information in attestation
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct VpcInfo {
    /// VPC server app ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vpc_server_app_id: Option<String>,
    /// VPC hostname of this node
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vpc_hostname: Option<String>,
}

impl From<services::vpc::VpcInfo> for VpcInfo {
    fn from(v: services::vpc::VpcInfo) -> Self {
        Self {
            vpc_server_app_id: v.vpc_server_app_id,
            vpc_hostname: v.vpc_hostname,
        }
    }
}

/// Cloud-API gateway attestation (forwarded from dependency)
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApiGatewayAttestation {
    /// Signing address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_address: Option<String>,
    /// Signing algorithm
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_algo: Option<String>,
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
    /// VPC information (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vpc: Option<VpcInfo>,
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

/// Agent attestation from agent instance
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AgentAttestation {
    /// Agent instance name
    pub name: String,

    /// Container image digest
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_digest: Option<String>,

    /// TDX event log
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_log: Option<String>,

    /// Additional TDX/tappd info
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<String>,

    /// Intel TDX quote in hex format
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intel_quote: Option<String>,

    /// Request nonce
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_nonce: Option<String>,

    /// TLS certificate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_certificate: Option<String>,

    /// TLS certificate fingerprint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_certificate_fingerprint: Option<String>,
}

/// Complete attestation report combining all layers
///
/// This report proves the entire trust chain:
/// 1. This chat-api service runs in a TEE (your_gateway_attestation)
/// 2. The cloud-api dependency runs in a TEE (cloud_api_gateway_attestation)
/// 3. The model inference providers run on trusted hardware (model_attestations)
/// 4. Optional agent instance attestations when agent parameter is provided
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CombinedAttestationReport {
    /// This chat-api's own CPU attestation (proves this service runs in a TEE)
    pub chat_api_gateway_attestation: ApiGatewayAttestation,

    /// Cloud-API's gateway attestation (the intermediate service we depend on)
    pub cloud_api_gateway_attestation: ApiGatewayAttestation,

    /// Model provider attestations (can be multiple when routing to different models)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_attestations: Option<Vec<ModelAttestation>>,

    /// Agent instance attestations (included when agent query parameter is provided)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_attestations: Option<Vec<AgentAttestation>>,
}

/// Attestation report structure from proxy_service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    pub gateway_attestation: ApiGatewayAttestation,
    pub model_attestations: Option<Vec<ModelAttestation>>,
}

/// Appearance preference
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub enum Appearance {
    Light,
    Dark,
    System,
}

impl From<services::user::ports::Appearance> for Appearance {
    fn from(appearance: services::user::ports::Appearance) -> Self {
        match appearance {
            services::user::ports::Appearance::Light => Appearance::Light,
            services::user::ports::Appearance::Dark => Appearance::Dark,
            services::user::ports::Appearance::System => Appearance::System,
        }
    }
}

impl From<Appearance> for services::user::ports::Appearance {
    fn from(appearance: Appearance) -> Self {
        match appearance {
            Appearance::Light => services::user::ports::Appearance::Light,
            Appearance::Dark => services::user::ports::Appearance::Dark,
            Appearance::System => services::user::ports::Appearance::System,
        }
    }
}

/// User settings content for API responses
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UserSettingsContent {
    /// Notification preference
    pub notification: bool,
    /// System prompt
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<String>,
    /// Web search preference
    pub web_search: bool,
    /// Appearance preference
    pub appearance: Appearance,
}

impl From<services::user::ports::UserSettingsContent> for UserSettingsContent {
    fn from(content: services::user::ports::UserSettingsContent) -> Self {
        Self {
            notification: content.notification,
            system_prompt: content.system_prompt,
            web_search: content.web_search,
            appearance: content.appearance.into(),
        }
    }
}

/// User settings update request
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UpdateUserSettingsRequest {
    /// Notification preference
    pub notification: bool,
    /// System prompt
    pub system_prompt: Option<String>,
    /// Web search preference
    pub web_search: bool,
    /// Appearance preference
    pub appearance: Appearance,
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
    /// Web search preference
    pub web_search: Option<bool>,
    /// Appearance preference
    pub appearance: Option<Appearance>,
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

/// User settings response
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UserSettingsResponse {
    /// User ID
    pub user_id: UserId,
    /// Settings content (serialized as "settings")
    #[serde(rename = "settings")]
    pub content: UserSettingsContent,
}

/// Model settings content for API responses
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ModelSettings {
    /// Whether models are public (visible/usable in responses)
    pub public: bool,
    /// Optional system-level system prompt for this model
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<String>,
}

impl From<services::model::ports::ModelSettings> for ModelSettings {
    fn from(content: services::model::ports::ModelSettings) -> Self {
        Self {
            public: content.public,
            system_prompt: content.system_prompt,
        }
    }
}

impl From<ModelSettings> for services::model::ports::ModelSettings {
    fn from(content: ModelSettings) -> Self {
        Self {
            public: content.public,
            system_prompt: content.system_prompt,
        }
    }
}

/// Partial model settings for API requests
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PartialModelSettings {
    /// Whether models are public (visible/usable in responses)
    pub public: Option<bool>,
    /// Optional system-level system prompt for this model
    pub system_prompt: Option<String>,
}

impl From<services::model::ports::PartialModelSettings> for PartialModelSettings {
    fn from(content: services::model::ports::PartialModelSettings) -> Self {
        Self {
            public: content.public,
            system_prompt: content.system_prompt,
        }
    }
}

impl From<PartialModelSettings> for services::model::ports::PartialModelSettings {
    fn from(content: PartialModelSettings) -> Self {
        Self {
            public: content.public,
            system_prompt: content.system_prompt,
        }
    }
}

/// Complete model response
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ModelResponse {
    /// External model identifier (e.g. "gpt-4.1")
    pub model_id: String,
    /// Settings stored for this model
    pub settings: ModelSettings,
}

impl From<services::model::ports::Model> for ModelResponse {
    fn from(model: services::model::ports::Model) -> Self {
        Self {
            model_id: model.model_id,
            settings: model.settings.into(),
        }
    }
}

/// Model upsert request
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UpsertModelsRequest {
    pub settings: ModelSettings,
}

/// Model settings update request (partial update)
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UpdateModelRequest {
    pub settings: Option<PartialModelSettings>,
}

/// Batch model upsert request
///
/// Maps model_id to partial settings to update.
/// Example: { "gpt-4": { "public": true }, "gpt-3.5": { "public": false, "system_prompt": "..." } }
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct BatchUpsertModelsRequest {
    #[serde(flatten)]
    pub models: std::collections::HashMap<String, PartialModelSettings>,
}

/// Model list response with pagination
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ModelListResponse {
    /// List of models
    pub models: Vec<ModelResponse>,
    /// Maximum number of items returned
    pub limit: i64,
    /// Number of items skipped
    pub offset: i64,
    /// Total number of models
    pub total: i64,
}

/// User usage summary (token sum, image count, cost in nano-USD). Used by /users/me/usage and admin usage API.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UserUsageResponse {
    pub user_id: services::UserId,
    pub token_sum: i64,
    /// Sum of image.generate + image.edit quantity (image count).
    pub image_num: i64,
    pub cost_nano_usd: i64,
}

/// Paginated user list response
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UserListResponse {
    /// List of users
    pub users: Vec<UserResponse>,
    /// Maximum number of items returned
    pub limit: i64,
    /// Number of items skipped
    pub offset: i64,
    /// Total number of users
    pub total: u64,
}

/// Rate limit configuration (API model)
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RateLimitConfig {
    /// Maximum number of concurrent requests per user
    pub max_concurrent: usize,
    /// Maximum number of requests per time window per user
    pub max_requests_per_window: usize,
    /// Duration of the short-term rate limit window in seconds
    pub window_duration_seconds: u64,
    /// Sliding window limits based on activity_log
    pub window_limits: Vec<WindowLimit>,
    /// Token usage limits per window (limit = max tokens in window)
    pub token_window_limits: Vec<WindowLimit>,
    /// Cost usage limits per window (limit = max nano-dollars in window)
    pub cost_window_limits: Vec<WindowLimit>,
}

/// Configuration for a single time window limit (API model)
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct WindowLimit {
    /// Duration of the time window for the limit (in seconds)
    pub window_duration_seconds: u64,
    /// Maximum number of requests allowed in this window
    pub limit: usize,
}

impl From<services::system_configs::ports::RateLimitConfig> for RateLimitConfig {
    fn from(config: services::system_configs::ports::RateLimitConfig) -> Self {
        Self {
            max_concurrent: config.max_concurrent,
            max_requests_per_window: config.max_requests_per_window,
            window_duration_seconds: u64::try_from(config.window_duration.num_seconds())
                .unwrap_or(u64::MAX),
            window_limits: config.window_limits.into_iter().map(Into::into).collect(),
            token_window_limits: config
                .token_window_limits
                .into_iter()
                .map(Into::into)
                .collect(),
            cost_window_limits: config
                .cost_window_limits
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}

impl From<services::system_configs::ports::WindowLimit> for WindowLimit {
    fn from(limit: services::system_configs::ports::WindowLimit) -> Self {
        Self {
            window_duration_seconds: u64::try_from(limit.window_duration.num_seconds())
                .unwrap_or(u64::MAX),
            limit: limit.limit,
        }
    }
}

impl TryFrom<RateLimitConfig> for services::system_configs::ports::RateLimitConfig {
    type Error = String;

    fn try_from(api_config: RateLimitConfig) -> Result<Self, Self::Error> {
        use chrono::Duration;

        let window_duration_seconds =
            i64::try_from(api_config.window_duration_seconds).map_err(|_| {
                format!(
                    "window_duration_seconds {} is too large (max: {})",
                    api_config.window_duration_seconds,
                    i64::MAX
                )
            })?;

        let window_limits: Result<Vec<_>, _> = api_config
            .window_limits
            .into_iter()
            .map(|limit| limit.try_into())
            .collect();

        let token_window_limits: Result<Vec<_>, _> = api_config
            .token_window_limits
            .into_iter()
            .map(|limit| limit.try_into())
            .collect();
        let cost_window_limits: Result<Vec<_>, _> = api_config
            .cost_window_limits
            .into_iter()
            .map(|limit| limit.try_into())
            .collect();

        Ok(Self {
            max_concurrent: api_config.max_concurrent,
            max_requests_per_window: api_config.max_requests_per_window,
            window_duration: Duration::seconds(window_duration_seconds),
            window_limits: window_limits?,
            token_window_limits: token_window_limits?,
            cost_window_limits: cost_window_limits?,
        })
    }
}

impl TryFrom<WindowLimit> for services::system_configs::ports::WindowLimit {
    type Error = String;

    fn try_from(api_limit: WindowLimit) -> Result<Self, Self::Error> {
        use chrono::Duration;

        let window_duration_seconds =
            i64::try_from(api_limit.window_duration_seconds).map_err(|_| {
                format!(
                    "window_duration_seconds {} is too large (max: {})",
                    api_limit.window_duration_seconds,
                    i64::MAX
                )
            })?;

        Ok(Self {
            window_duration: Duration::seconds(window_duration_seconds),
            limit: api_limit.limit,
        })
    }
}

impl RateLimitConfig {
    /// Validates a slice of window limits. `field_name` is used in error messages (e.g. "window_limits").
    fn validate_window_limits(limits: &[WindowLimit], field_name: &str) -> Result<(), ApiError> {
        for (index, window_limit) in limits.iter().enumerate() {
            if window_limit.window_duration_seconds == 0 {
                return Err(ApiError::bad_request(format!(
                    "{}[{}].window_duration_seconds must be greater than 0",
                    field_name, index
                )));
            }
            if window_limit.limit == 0 {
                return Err(ApiError::bad_request(format!(
                    "{}[{}].limit must be greater than 0",
                    field_name, index
                )));
            }
        }
        Ok(())
    }

    /// Validate the rate limit configuration
    ///
    /// Returns an error if any field is invalid:
    /// - `max_concurrent` must be greater than 0
    /// - `max_requests_per_window` must be greater than 0
    /// - `window_duration_seconds` must be greater than 0
    /// - `window_limits`, `token_window_limits`, and `cost_window_limits` may be empty
    /// - Each entry in those arrays must have `window_duration_seconds > 0` and `limit > 0`
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.max_concurrent == 0 {
            return Err(ApiError::bad_request(
                "max_concurrent must be greater than 0",
            ));
        }

        if self.max_requests_per_window == 0 {
            return Err(ApiError::bad_request(
                "max_requests_per_window must be greater than 0",
            ));
        }

        if self.window_duration_seconds == 0 {
            return Err(ApiError::bad_request(
                "window_duration_seconds must be greater than 0",
            ));
        }

        // window_limits / token_window_limits / cost_window_limits can be empty
        Self::validate_window_limits(&self.window_limits, "window_limits")?;
        Self::validate_window_limits(&self.token_window_limits, "token_window_limits")?;
        Self::validate_window_limits(&self.cost_window_limits, "cost_window_limits")?;

        Ok(())
    }
}

/// Public system configs response (limited fields for non-admin users)
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PublicSystemConfigsResponse {
    /// Default model identifier to use when not specified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,
}

impl From<services::system_configs::ports::SystemConfigs> for PublicSystemConfigsResponse {
    fn from(config: services::system_configs::ports::SystemConfigs) -> Self {
        Self {
            default_model: config.default_model,
        }
    }
}

/// Full system configs response (all fields, for admin)
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SystemConfigsResponse {
    /// Default model identifier to use when not specified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,
    /// Rate limit configuration (always present, uses defaults if not set)
    pub rate_limit: RateLimitConfig,
    /// Subscription plan configurations mapping plan names to provider-specific configs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_plans: Option<HashMap<String, SubscriptionPlanConfig>>,
    /// Maximum number of agent instances per manager (round-robin skips full managers)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_instances_per_manager: Option<u64>,
}

impl From<services::system_configs::ports::SystemConfigs> for SystemConfigsResponse {
    fn from(config: services::system_configs::ports::SystemConfigs) -> Self {
        Self {
            default_model: config.default_model,
            rate_limit: config.rate_limit.into(),
            subscription_plans: config.subscription_plans,
            max_instances_per_manager: config.max_instances_per_manager,
        }
    }
}

/// System configs upsert request
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UpsertSystemConfigsRequest {
    /// Default model identifier to use when not specified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,
    /// Rate limit configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitConfig>,
    /// Subscription plan configurations (plan name -> config with providers, agent_instances, monthly_tokens)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_plans: Option<HashMap<String, SubscriptionPlanConfig>>,
    /// Maximum number of agent instances per manager (round-robin skips full managers)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_instances_per_manager: Option<u64>,
}

impl TryFrom<UpsertSystemConfigsRequest> for services::system_configs::ports::PartialSystemConfigs {
    type Error = String;

    fn try_from(req: UpsertSystemConfigsRequest) -> Result<Self, Self::Error> {
        let rate_limit = if let Some(rate_limit) = req.rate_limit {
            Some(rate_limit.try_into()?)
        } else {
            None
        };

        Ok(services::system_configs::ports::PartialSystemConfigs {
            default_model: req.default_model,
            rate_limit,
            subscription_plans: req.subscription_plans,
            max_instances_per_manager: req.max_instances_per_manager,
        })
    }
}

/// File list response with pagination
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct FileListResponse {
    /// Always "list"
    pub object: String,
    /// List of files (without `object` field per item)
    pub data: Vec<FileGetResponse>,
    /// First file ID in the list
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_id: Option<String>,
    /// Last file ID in the list
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_id: Option<String>,
    /// Whether there are more files available
    pub has_more: bool,
}

/// File get response with `object` field
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct FileGetResponse {
    /// Always "file"
    pub object: String,
    #[serde(flatten)]
    pub file: FileData,
}

impl From<FileData> for FileGetResponse {
    fn from(file: FileData) -> Self {
        Self {
            object: "file".to_string(),
            file,
        }
    }
}

// ============================================================================
// Agent Models
// ============================================================================

/// Request to create an agent instance (proxied to Agent API).
/// The chat-api creates an API key on behalf of the user and configures the agent to use it.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateInstanceRequest {
    /// Image to use for the instance (null for default)
    #[serde(default)]
    pub image: Option<String>,
    /// Instance name (null for auto-generated)
    #[serde(default)]
    pub name: Option<String>,
    /// SSH public key
    #[serde(default)]
    pub ssh_pubkey: Option<String>,
}

/// Request to update an agent instance
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateInstanceRequest {
    /// New instance name (optional)
    pub name: Option<String>,
    /// New public SSH key (optional)
    pub public_ssh_key: Option<String>,
}

/// Agent API instance response (deserialized from external Agent API)
#[derive(Debug, Deserialize)]
pub struct AgentApiResponse {
    pub instance: AgentApiInstance,
    pub message: String,
    pub stage: String,
}

/// Agent API instance data (deserialized from external Agent API)
#[derive(Debug, Deserialize)]
pub struct AgentApiInstance {
    pub dashboard_url: String,
    pub gateway_port: i32,
    pub image: String,
    pub image_digest: Option<String>,
    pub name: String,
    pub ssh_command: String,
    pub ssh_port: i32,
    pub token: String,
    pub url: String,
    #[serde(default)]
    pub ssh_pubkey: Option<String>,
}

/// Instance status derived from connection info (dashboard_url indicates running instance)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum InstanceStatus {
    Running,
    Stopped,
}

/// Agent instance response
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct InstanceResponse {
    pub id: String,
    pub instance_id: String,
    pub name: String,
    pub public_ssh_key: Option<String>,
    /// Dashboard URL to open OpenClaw (from Agent API)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dashboard_url: Option<String>,
    /// Instance status from Agent API (running, stopped)
    pub status: InstanceStatus,
    /// SSH command to connect to the instance (from Agent API when available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_command: Option<String>,
    /// Service type selected when creating the instance (e.g. "openclaw", "ironclaw")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_type: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<services::agent::ports::AgentInstance> for InstanceResponse {
    fn from(inst: services::agent::ports::AgentInstance) -> Self {
        let status = status_from_agent_api(None);
        Self {
            id: inst.id.to_string(),
            instance_id: inst.instance_id,
            name: inst.name,
            public_ssh_key: inst.public_ssh_key,
            dashboard_url: inst.dashboard_url,
            status,
            ssh_command: None,
            service_type: inst.service_type,
            created_at: inst.created_at.to_rfc3339(),
            updated_at: inst.updated_at.to_rfc3339(),
        }
    }
}

/// Build InstanceResponse with status and ssh_command from Agent API when available.
pub fn instance_response_with_enrichment(
    inst: services::agent::ports::AgentInstance,
    enrichment: Option<&services::agent::ports::AgentApiInstanceEnrichment>,
) -> InstanceResponse {
    let status = status_from_agent_api(enrichment.and_then(|e| e.status.as_deref()));
    let ssh_command = enrichment.and_then(|e| e.ssh_command.clone());
    InstanceResponse {
        id: inst.id.to_string(),
        instance_id: inst.instance_id,
        name: inst.name,
        public_ssh_key: inst.public_ssh_key,
        dashboard_url: inst.dashboard_url,
        status,
        ssh_command,
        service_type: inst.service_type,
        created_at: inst.created_at.to_rfc3339(),
        updated_at: inst.updated_at.to_rfc3339(),
    }
}

/// Map Agent API (compose-api) status string to InstanceStatus.
/// Compose-api returns Docker container State: "running", "exited", "dead", "not found", "unknown".
fn status_from_agent_api(agent_api_status: Option<&str>) -> InstanceStatus {
    match agent_api_status {
        Some(s) if s.eq_ignore_ascii_case("running") => InstanceStatus::Running,
        Some(s)
            if s.eq_ignore_ascii_case("stopped")
                || s.eq_ignore_ascii_case("exited")
                || s.eq_ignore_ascii_case("dead")
                || s.eq_ignore_ascii_case("not found") =>
        {
            InstanceStatus::Stopped
        }
        _ => InstanceStatus::Stopped,
    }
}

/// Request to create an API key
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateApiKeyRequest {
    /// Human-readable key name
    pub name: String,
    /// Optional spend limit in nano-dollars ($1.00 = 1,000,000,000 nano-dollars)
    pub spend_limit: Option<i64>,
    /// Optional expiration timestamp
    pub expires_at: Option<String>,
}

/// Request to bind an unbound API key to an instance
#[derive(Debug, Deserialize, ToSchema)]
pub struct BindApiKeyRequest {
    /// The instance ID to bind the key to
    pub instance_id: String,
}

/// Response when creating an API key (includes plaintext key)
#[derive(Debug, Serialize, ToSchema)]
pub struct CreateApiKeyResponse {
    pub id: String,
    pub name: String,
    /// The plaintext API key (only returned on creation!)
    pub api_key: String,
    pub spend_limit: Option<String>,
    pub expires_at: Option<String>,
    pub created_at: String,
}

/// API key response (no plaintext key)
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiKeyResponse {
    pub id: String,
    pub name: String,
    pub spend_limit: Option<String>,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl From<services::agent::ports::AgentApiKey> for ApiKeyResponse {
    fn from(key: services::agent::ports::AgentApiKey) -> Self {
        Self {
            id: key.id.to_string(),
            name: key.name,
            spend_limit: key.spend_limit.map(format_nano_dollars),
            expires_at: key.expires_at.map(|e| e.to_rfc3339()),
            last_used_at: key.last_used_at.map(|u| u.to_rfc3339()),
            is_active: key.is_active,
            created_at: key.created_at.to_rfc3339(),
            updated_at: key.updated_at.to_rfc3339(),
        }
    }
}

/// Usage log entry response
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UsageResponse {
    pub id: String,
    pub api_key_name: String,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
    pub input_cost: String,  // nano-dollars formatted as string
    pub output_cost: String, // nano-dollars formatted as string
    pub total_cost: String,  // nano-dollars formatted as string
    pub model_id: String,
    pub request_type: String,
    pub created_at: String,
}

impl From<services::agent::ports::UsageLogEntry> for UsageResponse {
    fn from(usage: services::agent::ports::UsageLogEntry) -> Self {
        Self {
            id: usage.id.to_string(),
            api_key_name: usage.api_key_name,
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            total_tokens: usage.total_tokens,
            input_cost: format_nano_dollars(usage.input_cost),
            output_cost: format_nano_dollars(usage.output_cost),
            total_cost: format_nano_dollars(usage.total_cost),
            model_id: usage.model_id,
            request_type: usage.request_type,
            created_at: usage.created_at.to_rfc3339(),
        }
    }
}

/// Instance balance response
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct BalanceResponse {
    pub total_spent: String, // formatted nano-dollars
    pub total_requests: i64,
    pub total_tokens: i64,
    pub last_usage_at: Option<String>,
    pub updated_at: String,
}

impl From<services::agent::ports::InstanceBalance> for BalanceResponse {
    fn from(balance: services::agent::ports::InstanceBalance) -> Self {
        Self {
            total_spent: format_nano_dollars(balance.total_spent),
            total_requests: balance.total_requests,
            total_tokens: balance.total_tokens,
            last_usage_at: balance.last_usage_at.map(|u| u.to_rfc3339()),
            updated_at: balance.updated_at.to_rfc3339(),
        }
    }
}

/// Paginated list response
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub limit: i64,
    pub offset: i64,
    pub total: i64,
}

/// Query parameters for usage listing
#[derive(Debug, Deserialize, ToSchema)]
pub struct UsageQueryParams {
    /// Start date (ISO 8601 format, optional)
    pub start_date: Option<String>,
    /// End date (ISO 8601 format, optional)
    pub end_date: Option<String>,
    /// Maximum number of items to return (default 20)
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Number of items to skip (default 0)
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    20
}

/// Request to set a user's subscription (admin only)
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AdminSetSubscriptionRequest {
    /// Payment provider (e.g., "stripe")
    pub provider: String,
    /// Plan name (e.g., "basic", "pro")
    pub plan: String,
    /// Subscription period end date (ISO 8601 format)
    pub current_period_end: String,
}

/// Format nano-dollars as a decimal string (e.g., "0.000000001" for 1 nano-dollar)
pub fn format_nano_dollars(nano_dollars: i64) -> String {
    // Use integer arithmetic to avoid floating point precision errors
    // Handle negative values by working with absolute value and prepending sign
    let is_negative = nano_dollars < 0;
    let abs_nano = nano_dollars.abs();
    let dollars = abs_nano / 1_000_000_000;
    let nanos = abs_nano % 1_000_000_000;

    let formatted = if nanos == 0 {
        dollars.to_string()
    } else {
        format!("{}.{:09}", dollars, nanos)
            .trim_end_matches('0')
            .trim_end_matches('.')
            .to_string()
    };

    if is_negative && formatted != "0" {
        format!("-{}", formatted)
    } else {
        formatted
    }
}
