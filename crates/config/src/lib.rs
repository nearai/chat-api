use serde::Deserialize;
use std::collections::HashMap;
use url::Url;

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub host: Option<String>,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub password: String,
    pub max_connections: u32,
    pub tls_enabled: bool,
    pub tls_ca_cert_path: Option<String>,
    pub primary_app_id: String,
    pub gateway_subdomain: String,
    pub refresh_interval: u64,
    pub mock: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            host: std::env::var("DATABASE_HOST").ok(),
            port: std::env::var("DATABASE_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(5432),
            database: std::env::var("DATABASE_NAME").unwrap_or_else(|_| "chat_api".to_string()),
            username: std::env::var("DATABASE_USER").unwrap_or_else(|_| "postgres".to_string()),
            password: if let Ok(path) = std::env::var("DATABASE_PASSWORD_FILE") {
                std::fs::read_to_string(&path)
                    .map(|p| p.trim().to_string())
                    .unwrap_or_else(|e| {
                        panic!("Failed to read DATABASE_PASSWORD_FILE at {}: {}", path, e)
                    })
            } else {
                std::env::var("DATABASE_PASSWORD").unwrap_or_else(|_| "postgres".to_string())
            },
            max_connections: std::env::var("DATABASE_MAX_CONNECTIONS")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(10),
            tls_enabled: std::env::var("DATABASE_TLS_ENABLED")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
            tls_ca_cert_path: std::env::var("DATABASE_TLS_CA_CERT_PATH").ok(),
            primary_app_id: std::env::var("DATABASE_PRIMARY_APP_ID").unwrap_or_default(),
            gateway_subdomain: std::env::var("GATEWAY_SUBDOMAIN").unwrap_or_default(),
            refresh_interval: std::env::var("DATABASE_REFRESH_INTERVAL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            mock: std::env::var("DATABASE_MOCK")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct OAuthConfig {
    pub google_client_id: String,
    pub google_client_secret: String,
    pub github_client_id: String,
    pub github_client_secret: String,
    pub redirect_uri: String,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            google_client_id: std::env::var("GOOGLE_CLIENT_ID").unwrap_or_default(),
            google_client_secret: std::env::var("GOOGLE_CLIENT_SECRET").unwrap_or_default(),
            github_client_id: std::env::var("GITHUB_CLIENT_ID").unwrap_or_default(),
            github_client_secret: std::env::var("GITHUB_CLIENT_SECRET").unwrap_or_default(),
            redirect_uri: std::env::var("REDIRECT_URI")
                .unwrap_or_else(|_| "http://localhost:8080".to_string()),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct EmailAuthConfig {
    pub enabled: bool,
    pub resend_api_key: String,
    pub resend_base_url: String,
    pub turnstile_secret_key: String,
    pub email_from: String,
    pub trusted_proxy_count: usize,
    pub otp_ttl_minutes: i64,
    pub otp_rate_limit_per_hour: u64,
    pub otp_max_verify_attempts: i32,
    pub otp_verify_failures_per_hour: u64,
    pub otp_requests_per_ip_per_hour: u64,
    pub otp_verifies_per_ip_per_hour: u64,
    pub otp_hmac_secret: String,
}

impl Default for EmailAuthConfig {
    fn default() -> Self {
        Self {
            enabled: std::env::var("EMAIL_AUTH_ENABLED")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
            resend_api_key: std::env::var("RESEND_API_KEY").unwrap_or_default(),
            resend_base_url: std::env::var("RESEND_BASE_URL")
                .unwrap_or_else(|_| "https://api.resend.com".to_string()),
            turnstile_secret_key: std::env::var("EMAIL_OTP_TURNSTILE_SECRET_KEY")
                .unwrap_or_default(),
            email_from: std::env::var("EMAIL_FROM").unwrap_or_default(),
            trusted_proxy_count: std::env::var("EMAIL_AUTH_TRUSTED_PROXY_COUNT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            otp_ttl_minutes: std::env::var("EMAIL_OTP_TTL_MINUTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
            otp_rate_limit_per_hour: std::env::var("EMAIL_OTP_RATE_LIMIT_PER_HOUR")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
            otp_max_verify_attempts: std::env::var("EMAIL_OTP_MAX_VERIFY_ATTEMPTS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            otp_verify_failures_per_hour: std::env::var("EMAIL_OTP_VERIFY_FAILURES_PER_HOUR")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(20),
            otp_requests_per_ip_per_hour: std::env::var("EMAIL_OTP_REQUESTS_PER_IP_PER_HOUR")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            otp_verifies_per_ip_per_hour: std::env::var("EMAIL_OTP_VERIFIES_PER_IP_PER_HOUR")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            otp_hmac_secret: std::env::var("EMAIL_OTP_HMAC_SECRET").unwrap_or_default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: std::env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: std::env::var("SERVER_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(8080),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpenAIConfig {
    pub api_key: String,
    pub base_url: Option<String>,
}

impl Default for OpenAIConfig {
    fn default() -> Self {
        Self {
            // API key can be set directly, from file, or via VPC auth (handled at startup)
            api_key: if let Ok(path) = std::env::var("OPENAI_API_KEY_FILE") {
                std::fs::read_to_string(&path)
                    .map(|p| p.trim().to_string())
                    .unwrap_or_else(|e| {
                        panic!("Failed to read OPENAI_API_KEY_FILE at {}: {}", path, e)
                    })
            } else {
                std::env::var("OPENAI_API_KEY").unwrap_or_default()
            },
            base_url: std::env::var("OPENAI_BASE_URL").ok(),
        }
    }
}

/// Configuration for VPC authentication to obtain API keys dynamically
#[derive(Debug, Clone, Deserialize)]
pub struct VpcAuthConfig {
    /// Path to the file containing the VPC shared secret
    pub shared_secret_file: Option<String>,
    /// Client ID for VPC authentication
    pub client_id: String,
}

impl Default for VpcAuthConfig {
    fn default() -> Self {
        Self {
            shared_secret_file: std::env::var("VPC_SHARED_SECRET_FILE").ok(),
            client_id: std::env::var("VPC_CLIENT_ID")
                .unwrap_or_else(|_| "chat-api-client".to_string()),
        }
    }
}

impl VpcAuthConfig {
    /// Returns true if VPC authentication is configured
    pub fn is_configured(&self) -> bool {
        self.shared_secret_file.is_some()
    }

    /// Reads the shared secret from the configured file
    pub fn read_shared_secret(&self) -> Option<String> {
        self.shared_secret_file.as_ref().and_then(|path| {
            std::fs::read_to_string(path)
                .map(|s| s.trim().to_string())
                .ok()
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CorsConfig {
    pub exact_matches: Vec<String>,
    pub wildcard_suffixes: Vec<String>,
}

impl Default for CorsConfig {
    fn default() -> Self {
        let raw_origins = std::env::var("CORS_ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:3000,https://near.ai,*.near.ai".to_string());

        let mut exact_matches = Vec::new();
        let mut wildcard_suffixes = Vec::new();

        for origin in raw_origins.split(',') {
            let s = origin.trim();
            if s.is_empty() {
                continue;
            }

            if let Some(suffix) = s.strip_prefix('*') {
                let safe_suffix = if suffix.starts_with('.') || suffix.starts_with('-') {
                    suffix.to_string()
                } else {
                    format!(".{}", suffix)
                };
                wildcard_suffixes.push(safe_suffix);
            } else {
                exact_matches.push(s.to_string());
            }
        }

        Self {
            exact_matches,
            wildcard_suffixes,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdminConfig {
    pub admin_domains: Vec<String>,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            admin_domains: std::env::var("AUTH_ADMIN_DOMAINS")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
        }
    }
}

/// Configuration for OpenTelemetry metrics export
#[derive(Debug, Clone, Deserialize)]
pub struct TelemetryConfig {
    /// Service name for metrics (default: "chat-api")
    pub service_name: String,
    /// OTLP gRPC endpoint (e.g., "http://localhost:4317")
    /// If not set, metrics export is disabled
    pub otlp_endpoint: Option<String>,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            service_name: std::env::var("TELEMETRY_SERVICE_NAME")
                .unwrap_or_else(|_| "chat-api".to_string()),
            otlp_endpoint: std::env::var("TELEMETRY_OTLP_ENDPOINT").ok(),
        }
    }
}

impl TelemetryConfig {
    /// Returns true if OTLP export is configured
    pub fn is_enabled(&self) -> bool {
        self.otlp_endpoint.is_some()
    }
}

/// Stripe payment configuration
#[derive(Debug, Clone, Deserialize)]
pub struct StripeConfig {
    /// Stripe secret key for API authentication
    pub secret_key: String,
    /// Stripe webhook secret for verifying webhook signatures
    pub webhook_secret: String,
    /// Enable Stripe test clock functionality for testing subscription billing
    pub test_clock_enabled: bool,
}

impl Default for StripeConfig {
    fn default() -> Self {
        Self {
            secret_key: if let Ok(path) = std::env::var("STRIPE_SECRET_KEY_FILE") {
                std::fs::read_to_string(&path)
                    .map(|p| p.trim().to_string())
                    .unwrap_or_else(|e| {
                        panic!("Failed to read STRIPE_SECRET_KEY_FILE at {}: {}", path, e)
                    })
            } else {
                std::env::var("STRIPE_SECRET_KEY").unwrap_or_default()
            },
            webhook_secret: if let Ok(path) = std::env::var("STRIPE_WEBHOOK_SECRET_FILE") {
                std::fs::read_to_string(&path)
                    .map(|p| p.trim().to_string())
                    .unwrap_or_else(|e| {
                        panic!(
                            "Failed to read STRIPE_WEBHOOK_SECRET_FILE at {}: {}",
                            path, e
                        )
                    })
            } else {
                std::env::var("STRIPE_WEBHOOK_SECRET").unwrap_or_default()
            },
            test_clock_enabled: std::env::var("STRIPE_TEST_CLOCK_ENABLED")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
        }
    }
}

/// NEAR-related configuration (shared between services)
#[derive(Debug, Clone, Deserialize)]
pub struct NearConfig {
    /// NEAR JSON-RPC endpoint used for on-chain queries (e.g. balance checks)
    pub rpc_url: Url,
}

impl Default for NearConfig {
    fn default() -> Self {
        let raw =
            std::env::var("NEAR_RPC_URL").unwrap_or("https://free.rpc.fastnear.com".to_string());
        Self {
            rpc_url: Url::parse(&raw).expect("NEAR_RPC_URL must be a valid URL"),
        }
    }
}

fn default_nearai_api_url() -> String {
    std::env::var("BACKEND_URL")
        .map(|url| url.trim_end_matches('/').to_string() + "/v1")
        .unwrap_or_else(|_| "https://private.near.ai/v1".to_string())
}

fn default_non_tee_agent_url() -> String {
    std::env::var("NON_TEE_AGENT_URL").unwrap_or_else(|_| "claws".to_string())
}

/// A single agent manager endpoint with its URL and bearer token
#[derive(Clone, serde::Deserialize)]
pub struct AgentManager {
    pub url: String,
    pub token: String,
    /// Whether this manager is non-TEE (true) or TEE (false)
    /// Set at construction time based on infrastructure mode
    #[serde(default)]
    pub is_non_tee: bool,
}

impl AgentManager {
    /// Get the effective is_non_tee value based on explicit configuration
    pub fn get_is_non_tee(&self) -> bool {
        self.is_non_tee
    }
}

// Custom Debug to redact bearer tokens from log output (CLAUDE.md: never log credentials)
impl std::fmt::Debug for AgentManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentManager")
            .field("url", &self.url)
            .field("is_non_tee", &self.get_is_non_tee())
            .field("token", &"[REDACTED]")
            .finish()
    }
}

/// Configuration for agent API integration (supports various agent types)
#[derive(Debug, Clone, serde::Deserialize)]
pub struct AgentConfig {
    /// Agent API managers (URL + token pairs). Supports multiple managers for load balancing.
    /// Configured via comma-separated AGENT_MANAGER_URLS + AGENT_MANAGER_TOKENS,
    /// or legacy single-manager AGENT_API_BASE_URL + AGENT_API_TOKEN.
    #[serde(default)]
    pub managers: Vec<AgentManager>,
    /// Chat-API base URL that agents use to reach this service
    /// Used as nearai_api_url when creating instances so the agent knows where to authenticate.
    #[serde(default = "default_nearai_api_url")]
    pub nearai_api_url: String,
    /// Channel-relay URL for Slack integration. When set, provisioned IronClaw
    /// instances receive CHANNEL_RELAY_URL and CHANNEL_RELAY_API_KEY in their
    /// environment. The per-instance OPENCLAW_GATEWAY_TOKEN is used as the
    /// signing secret instead of the former shared CHANNEL_RELAY_SIGNING_SECRET.
    #[serde(default)]
    pub channel_relay_url: Option<String>,
    /// URL pattern to identify non-TEE compose-api endpoints for instance type detection
    /// Configurable via NON_TEE_AGENT_URL environment variable (defaults to "claws")
    #[serde(default = "default_non_tee_agent_url")]
    pub non_tee_agent_url_pattern: String,
}

/// Split a comma-separated env var value into non-empty trimmed entries.
fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

impl Default for AgentConfig {
    fn default() -> Self {
        // Load managers from both TEE and non-TEE configurations
        // This supports mixed environments with both manager types available
        // Manager type is determined dynamically from URL pattern, not from this setting
        let mut managers: Vec<AgentManager> = Vec::new();

        // Load TEE managers from AGENT_MANAGER_URLS_TEE
        if let Ok(urls_raw) = std::env::var("AGENT_MANAGER_URLS_TEE") {
            let urls = split_csv(&urls_raw);
            if !urls.is_empty() {
                let tokens_raw = std::env::var("AGENT_MANAGER_TOKENS_TEE").unwrap_or_default();
                let tokens = split_csv(&tokens_raw);
                if urls.len() != tokens.len() {
                    panic!(
                        "AGENT_MANAGER_URLS_TEE has {} entries but AGENT_MANAGER_TOKENS_TEE has {} — they must match",
                        urls.len(),
                        tokens.len()
                    );
                }
                let tee_mgrs: Vec<AgentManager> = urls
                    .into_iter()
                    .zip(tokens)
                    .map(|(url, token)| AgentManager {
                        url,
                        token,
                        is_non_tee: false,
                    })
                    .collect();
                managers.extend(tee_mgrs);
            }
        }

        // Load non-TEE managers from AGENT_MANAGER_URLS
        if let Ok(urls_raw) = std::env::var("AGENT_MANAGER_URLS") {
            let urls = split_csv(&urls_raw);
            if !urls.is_empty() {
                let tokens_raw = std::env::var("AGENT_MANAGER_TOKENS").unwrap_or_default();
                let tokens = split_csv(&tokens_raw);
                if urls.len() != tokens.len() {
                    panic!(
                        "AGENT_MANAGER_URLS has {} entries but AGENT_MANAGER_TOKENS has {} — they must match",
                        urls.len(),
                        tokens.len()
                    );
                }
                let non_tee_mgrs: Vec<AgentManager> = urls
                    .into_iter()
                    .zip(tokens)
                    .map(|(url, token)| AgentManager {
                        url,
                        token,
                        is_non_tee: true,
                    })
                    .collect();
                managers.extend(non_tee_mgrs);
            }
        }

        // If no managers configured, fall back to legacy AGENT_API_BASE_URL
        // This will be interpreted as TEE if no "claws" pattern in URL
        if managers.is_empty() {
            let url = std::env::var("AGENT_API_BASE_URL")
                .unwrap_or_else(|_| "https://api.agent.near.ai".to_string());
            let token = std::env::var("AGENT_API_TOKEN").unwrap_or_default();
            managers.push(AgentManager {
                url,
                token,
                is_non_tee: false,
            });
        }

        // Sort for deterministic ordering
        managers.sort_by(|a, b| a.url.cmp(&b.url));

        Self {
            managers,
            nearai_api_url: std::env::var("BACKEND_URL")
                .map(|url| url.trim_end_matches('/').to_string() + "/v1")
                .unwrap_or_else(|_| "https://private.near.ai/v1".to_string()),
            channel_relay_url: std::env::var("CHANNEL_RELAY_URL").ok(),
            non_tee_agent_url_pattern: default_non_tee_agent_url(),
        }
    }
}

/// Infrastructure mode configuration (TEE vs non-TEE)
#[derive(Debug, Clone, Deserialize)]
pub struct InfrastructureConfig {
    /// Use non-TEE infrastructure (false = TEE/cloud, true = non-TEE)
    /// When true, expects Agent API to provide instance URLs
    /// When false, expects Agent API to provide URLs (traditional TEE mode)
    pub non_tee_infra: bool,
}

impl Default for InfrastructureConfig {
    fn default() -> Self {
        Self {
            non_tee_infra: std::env::var("NON_TEE_INFRA")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
        }
    }
}

pub const TASKS_CLEANUP_CANCELED_INSTANCES_DAILY_CRON_DEFAULT: &str = "cron(0 0 * * ? *)";
pub const TASKS_CLEANUP_CANCELED_INSTANCES_GRACE_DAYS_DEFAULT: i64 = 15;
pub const TASKS_CLEANUP_CANCELED_INSTANCES_DAILY_TASK_ID_DEFAULT: &str =
    "cleanup.canceled-instances.daily";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TaskWorkerQueueKind {
    #[default]
    Default,
    AccountDeletion,
}

impl TaskWorkerQueueKind {
    fn from_env_value(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "account_deletion" | "account-deletion" => Self::AccountDeletion,
            _ => Self::Default,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TaskConfig {
    pub enabled: bool,
    pub aws_region: Option<String>,
    pub sqs_queue_url: Option<String>,
    pub sqs_queue_arn: Option<String>,
    pub account_deletion_sqs_queue_url: Option<String>,
    pub worker_queue: TaskWorkerQueueKind,
    pub scheduler_role_arn: Option<String>,
    pub scheduler_group: String,
    pub cleanup_canceled_instances_daily_task_id: String,
    pub cleanup_canceled_instances_daily_cron: String,
    pub cleanup_canceled_instances_grace_days: i64,
    pub worker_wait_seconds: i32,
    pub worker_visibility_timeout: i32,
    pub worker_max_messages: i32,
    pub worker_max_concurrency: usize,
    pub port: u16,
}

impl Default for TaskConfig {
    fn default() -> Self {
        Self {
            enabled: std::env::var("TASKS_ENABLED")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
            aws_region: std::env::var("AWS_REGION").ok(),
            sqs_queue_url: std::env::var("TASKS_SQS_QUEUE_URL").ok(),
            sqs_queue_arn: std::env::var("TASKS_SQS_QUEUE_ARN").ok(),
            account_deletion_sqs_queue_url: std::env::var("ACCOUNT_DELETION_TASKS_SQS_QUEUE_URL")
                .ok(),
            worker_queue: std::env::var("TASKS_WORKER_QUEUE")
                .map(|v| TaskWorkerQueueKind::from_env_value(&v))
                .unwrap_or_default(),
            scheduler_role_arn: std::env::var("TASKS_SCHEDULER_ROLE_ARN").ok(),
            scheduler_group: std::env::var("TASKS_SCHEDULER_GROUP")
                .unwrap_or_else(|_| "default".to_string()),
            cleanup_canceled_instances_daily_task_id: std::env::var(
                "TASKS_CLEANUP_CANCELED_INSTANCES_DAILY_TASK_ID",
            )
            .map(|v| v.trim().to_string())
            .unwrap_or_else(|_| TASKS_CLEANUP_CANCELED_INSTANCES_DAILY_TASK_ID_DEFAULT.to_string()),
            cleanup_canceled_instances_daily_cron: std::env::var(
                "TASKS_CLEANUP_CANCELED_INSTANCES_DAILY_CRON",
            )
            .unwrap_or_else(|_| TASKS_CLEANUP_CANCELED_INSTANCES_DAILY_CRON_DEFAULT.to_string()),
            cleanup_canceled_instances_grace_days: std::env::var(
                "TASKS_CLEANUP_CANCELED_INSTANCES_GRACE_DAYS",
            )
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(TASKS_CLEANUP_CANCELED_INSTANCES_GRACE_DAYS_DEFAULT),
            worker_wait_seconds: std::env::var("TASKS_WORKER_WAIT_SECONDS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(20),
            worker_visibility_timeout: std::env::var("TASKS_WORKER_VISIBILITY_TIMEOUT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            worker_max_messages: std::env::var("TASKS_WORKER_MAX_MESSAGES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
            worker_max_concurrency: std::env::var("TASKS_WORKER_MAX_CONCURRENCY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
            port: std::env::var("TASKS_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3001),
        }
    }
}

impl TaskConfig {
    pub fn is_scheduler_configured(&self) -> bool {
        self.sqs_queue_arn.is_some() && self.scheduler_role_arn.is_some()
    }

    pub fn is_worker_configured(&self) -> bool {
        match self.worker_queue {
            TaskWorkerQueueKind::Default => self.sqs_queue_url.is_some(),
            TaskWorkerQueueKind::AccountDeletion => self.account_deletion_sqs_queue_url.is_some(),
        }
    }

    pub fn worker_sqs_queue_url(&self) -> Option<&String> {
        match self.worker_queue {
            TaskWorkerQueueKind::Default => self.sqs_queue_url.as_ref(),
            TaskWorkerQueueKind::AccountDeletion => self.account_deletion_sqs_queue_url.as_ref(),
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct LoggingConfig {
    /// Global log level for the application.
    ///
    /// Valid values: "error", "warn", "info", "debug", "trace".
    /// Default: "info" (from LOG_LEVEL env var or fallback).
    pub level: String,
    /// Log output format.
    ///
    /// Valid values: "pretty", "json".
    /// Default: "pretty" (from LOG_FORMAT env var or fallback).
    pub format: String,
    /// Per-module log levels.
    pub modules: HashMap<String, String>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        let mut modules = HashMap::new();

        if let Ok(level) = std::env::var("LOG_MODULE_API") {
            modules.insert("api".to_string(), level);
        }
        if let Ok(level) = std::env::var("LOG_MODULE_SERVICES") {
            modules.insert("services".to_string(), level);
        }
        if let Ok(level) = std::env::var("LOG_MODULE_DATABASE") {
            modules.insert("database".to_string(), level);
        }

        Self {
            level: std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
            format: std::env::var("LOG_FORMAT").unwrap_or_else(|_| "pretty".to_string()),
            modules,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Config {
    pub database: DatabaseConfig,
    pub oauth: OAuthConfig,
    pub email_auth: EmailAuthConfig,
    pub server: ServerConfig,
    pub openai: OpenAIConfig,
    /// NEAR-related configuration
    pub near: NearConfig,
    /// Stripe payment configuration
    pub stripe: StripeConfig,
    pub cors: CorsConfig,
    pub admin: AdminConfig,
    pub vpc_auth: VpcAuthConfig,
    pub telemetry: TelemetryConfig,
    pub logging: LoggingConfig,
    pub agent: AgentConfig,
    /// Infrastructure mode (TEE vs non-TEE)
    pub infrastructure: InfrastructureConfig,
    pub tasks: TaskConfig,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            database: DatabaseConfig::default(),
            oauth: OAuthConfig::default(),
            email_auth: EmailAuthConfig::default(),
            server: ServerConfig::default(),
            openai: OpenAIConfig::default(),
            near: NearConfig::default(),
            stripe: StripeConfig::default(),
            cors: CorsConfig::default(),
            admin: AdminConfig::default(),
            vpc_auth: VpcAuthConfig::default(),
            telemetry: TelemetryConfig::default(),
            logging: LoggingConfig::default(),
            agent: AgentConfig::default(),
            infrastructure: InfrastructureConfig::default(),
            tasks: TaskConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_cors_config_parsing_exact_matches() {
        std::env::set_var(
            "CORS_ALLOWED_ORIGINS",
            "https://example.com,http://test.com",
        );
        let config = CorsConfig::default();
        assert!(config
            .exact_matches
            .contains(&"https://example.com".to_string()));
        assert!(config
            .exact_matches
            .contains(&"http://test.com".to_string()));
        assert!(config.wildcard_suffixes.is_empty());
        std::env::remove_var("CORS_ALLOWED_ORIGINS");
    }

    #[test]
    #[serial]
    fn test_cors_config_parsing_wildcard_with_dot() {
        std::env::set_var("CORS_ALLOWED_ORIGINS", "*.near.ai");
        let config = CorsConfig::default();
        assert_eq!(config.wildcard_suffixes, vec![".near.ai"]);
        assert!(config.exact_matches.is_empty());
        std::env::remove_var("CORS_ALLOWED_ORIGINS");
    }

    #[test]
    #[serial]
    fn test_cors_config_parsing_wildcard_without_dot() {
        std::env::set_var("CORS_ALLOWED_ORIGINS", "*near.ai");
        let config = CorsConfig::default();
        assert_eq!(config.wildcard_suffixes, vec![".near.ai"]);
        std::env::remove_var("CORS_ALLOWED_ORIGINS");
    }

    #[test]
    #[serial]
    fn test_cors_config_parsing_wildcard_with_hyphen() {
        std::env::set_var("CORS_ALLOWED_ORIGINS", "*-example.com");
        let config = CorsConfig::default();
        assert_eq!(config.wildcard_suffixes, vec!["-example.com"]);
        std::env::remove_var("CORS_ALLOWED_ORIGINS");
    }

    #[test]
    #[serial]
    fn test_cors_config_parsing_mixed() {
        std::env::set_var(
            "CORS_ALLOWED_ORIGINS",
            "https://example.com,*.near.ai,http://test.com",
        );
        let config = CorsConfig::default();
        assert_eq!(config.exact_matches.len(), 2);
        assert!(config
            .exact_matches
            .contains(&"https://example.com".to_string()));
        assert!(config
            .exact_matches
            .contains(&"http://test.com".to_string()));
        assert_eq!(config.wildcard_suffixes, vec![".near.ai"]);
        std::env::remove_var("CORS_ALLOWED_ORIGINS");
    }

    #[test]
    #[serial]
    fn test_cors_config_parsing_whitespace() {
        std::env::set_var("CORS_ALLOWED_ORIGINS", " https://example.com , *.near.ai ");
        let config = CorsConfig::default();
        assert!(config
            .exact_matches
            .contains(&"https://example.com".to_string()));
        assert_eq!(config.wildcard_suffixes, vec![".near.ai"]);
        std::env::remove_var("CORS_ALLOWED_ORIGINS");
    }

    #[test]
    #[serial]
    fn test_cors_config_parsing_empty_entries() {
        std::env::set_var("CORS_ALLOWED_ORIGINS", "https://example.com,,*.near.ai,");
        let config = CorsConfig::default();
        assert_eq!(config.exact_matches.len(), 1);
        assert_eq!(config.wildcard_suffixes.len(), 1);
        std::env::remove_var("CORS_ALLOWED_ORIGINS");
    }

    #[test]
    #[serial]
    fn test_agent_config_legacy_single_url() {
        std::env::remove_var("AGENT_MANAGER_URLS");
        std::env::remove_var("AGENT_MANAGER_TOKENS");
        std::env::set_var("AGENT_API_BASE_URL", "https://mgr.example.com");
        std::env::set_var("AGENT_API_TOKEN", "secret123");
        let config = AgentConfig::default();
        assert_eq!(config.managers.len(), 1);
        assert_eq!(config.managers[0].url, "https://mgr.example.com");
        assert_eq!(config.managers[0].token, "secret123");
        std::env::remove_var("AGENT_API_BASE_URL");
        std::env::remove_var("AGENT_API_TOKEN");
    }

    #[test]
    #[serial]
    fn test_agent_config_csv_multiple_managers() {
        // CSV managers are used in non-TEE mode
        std::env::set_var("NON_TEE_INFRA", "true");
        std::env::set_var(
            "AGENT_MANAGER_URLS",
            "https://mgr2.example.com,https://mgr1.example.com",
        );
        std::env::set_var("AGENT_MANAGER_TOKENS", "tok2,tok1");
        let config = AgentConfig::default();
        assert_eq!(config.managers.len(), 2);
        // Sorted by URL for deterministic ordering
        assert_eq!(config.managers[0].url, "https://mgr1.example.com");
        assert_eq!(config.managers[0].token, "tok1");
        assert_eq!(config.managers[1].url, "https://mgr2.example.com");
        assert_eq!(config.managers[1].token, "tok2");
        std::env::remove_var("NON_TEE_INFRA");
        std::env::remove_var("AGENT_MANAGER_URLS");
        std::env::remove_var("AGENT_MANAGER_TOKENS");
    }

    #[test]
    #[serial]
    fn test_agent_config_csv_overrides_legacy() {
        // CSV managers are used in non-TEE mode
        std::env::set_var("NON_TEE_INFRA", "true");
        std::env::set_var("AGENT_MANAGER_URLS", "https://csv.example.com");
        std::env::set_var("AGENT_MANAGER_TOKENS", "csv-tok");
        std::env::set_var("AGENT_API_BASE_URL", "https://legacy.example.com");
        std::env::set_var("AGENT_API_TOKEN", "legacy-tok");
        let config = AgentConfig::default();
        // CSV format takes priority over legacy vars
        assert_eq!(config.managers.len(), 1);
        assert_eq!(config.managers[0].url, "https://csv.example.com");
        assert_eq!(config.managers[0].token, "csv-tok");
        std::env::remove_var("NON_TEE_INFRA");
        std::env::remove_var("AGENT_MANAGER_URLS");
        std::env::remove_var("AGENT_MANAGER_TOKENS");
        std::env::remove_var("AGENT_API_BASE_URL");
        std::env::remove_var("AGENT_API_TOKEN");
    }

    #[test]
    #[serial]
    #[should_panic(expected = "AGENT_MANAGER_URLS has 2 entries but AGENT_MANAGER_TOKENS has 1")]
    fn test_agent_config_csv_mismatched_lengths_panics() {
        // CSV managers are validated in non-TEE mode
        std::env::set_var("NON_TEE_INFRA", "true");
        std::env::set_var(
            "AGENT_MANAGER_URLS",
            "https://mgr1.example.com,https://mgr2.example.com",
        );
        std::env::set_var("AGENT_MANAGER_TOKENS", "tok1");
        let _ = AgentConfig::default();
        // Cleanup happens after panic
        std::env::remove_var("NON_TEE_INFRA");
        std::env::remove_var("AGENT_MANAGER_URLS");
        std::env::remove_var("AGENT_MANAGER_TOKENS");
    }

    #[test]
    #[serial]
    fn test_agent_config_csv_whitespace_and_trailing_commas() {
        // CSV managers are used in non-TEE mode
        std::env::set_var("NON_TEE_INFRA", "true");
        std::env::set_var(
            "AGENT_MANAGER_URLS",
            " https://mgr1.example.com , https://mgr2.example.com , ",
        );
        std::env::set_var("AGENT_MANAGER_TOKENS", " tok1 , tok2 , ");
        let config = AgentConfig::default();
        assert_eq!(config.managers.len(), 2);
        assert_eq!(config.managers[0].url, "https://mgr1.example.com");
        assert_eq!(config.managers[0].token, "tok1");
        assert_eq!(config.managers[1].url, "https://mgr2.example.com");
        assert_eq!(config.managers[1].token, "tok2");
        std::env::remove_var("NON_TEE_INFRA");
        std::env::remove_var("AGENT_MANAGER_URLS");
        std::env::remove_var("AGENT_MANAGER_TOKENS");
    }

    #[test]
    #[serial]
    fn test_agent_manager_debug_redacts_token() {
        let mgr = AgentManager {
            url: "https://test.com".to_string(),
            token: "super-secret".to_string(),
            is_non_tee: false,
        };
        let debug_output = format!("{:?}", mgr);
        assert!(debug_output.contains("https://test.com"));
        assert!(!debug_output.contains("super-secret"));
        assert!(debug_output.contains("REDACTED"));
    }

    // ============================================================================
    // Infrastructure Configuration Tests (TEE vs non-TEE mode)
    // ============================================================================

    #[test]
    #[serial]
    fn test_infrastructure_config_default_is_tee_mode() {
        std::env::remove_var("NON_TEE_INFRA");
        let config = InfrastructureConfig::default();
        assert!(!config.non_tee_infra, "Default should be TEE mode (false)");
    }

    #[test]
    #[serial]
    fn test_task_config_defaults() {
        std::env::remove_var("TASKS_ENABLED");
        std::env::remove_var("AWS_REGION");
        std::env::remove_var("TASKS_SQS_QUEUE_URL");
        std::env::remove_var("TASKS_SQS_QUEUE_ARN");
        std::env::remove_var("TASKS_SCHEDULER_ROLE_ARN");
        std::env::remove_var("TASKS_SCHEDULER_GROUP");
        std::env::remove_var("TASKS_CLEANUP_CANCELED_INSTANCES_DAILY_TASK_ID");
        std::env::remove_var("TASKS_PORT");
        std::env::remove_var("TASKS_CLEANUP_CANCELED_INSTANCES_DAILY_CRON");
        std::env::remove_var("TASKS_CLEANUP_CANCELED_INSTANCES_GRACE_DAYS");
        std::env::remove_var("TASKS_WORKER_WAIT_SECONDS");
        std::env::remove_var("TASKS_WORKER_VISIBILITY_TIMEOUT");
        std::env::remove_var("TASKS_WORKER_MAX_MESSAGES");
        std::env::remove_var("TASKS_WORKER_MAX_CONCURRENCY");

        let cfg = TaskConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.aws_region.is_none());
        assert_eq!(cfg.scheduler_group, "default");
        assert_eq!(
            cfg.cleanup_canceled_instances_daily_task_id,
            TASKS_CLEANUP_CANCELED_INSTANCES_DAILY_TASK_ID_DEFAULT
        );
        assert_eq!(cfg.port, 3001);
        assert_eq!(cfg.worker_wait_seconds, 20);
        assert_eq!(cfg.worker_visibility_timeout, 60);
        assert_eq!(cfg.worker_max_messages, 10);
        assert_eq!(cfg.worker_max_concurrency, 10);
        assert!(!cfg.is_scheduler_configured());
        assert!(!cfg.is_worker_configured());
    }

    #[test]
    #[serial]
    fn test_infrastructure_config_non_tee_enabled() {
        std::env::set_var("NON_TEE_INFRA", "true");
        let config = InfrastructureConfig::default();
        assert!(
            config.non_tee_infra,
            "NON_TEE_INFRA=true should enable non-TEE mode"
        );
        std::env::remove_var("NON_TEE_INFRA");
    }

    #[test]
    #[serial]
    fn test_infrastructure_config_non_tee_disabled() {
        std::env::set_var("NON_TEE_INFRA", "false");
        let config = InfrastructureConfig::default();
        assert!(
            !config.non_tee_infra,
            "NON_TEE_INFRA=false should disable non-TEE mode (TEE mode)"
        );
        std::env::remove_var("NON_TEE_INFRA");
    }

    #[test]
    #[serial]
    fn test_infrastructure_config_invalid_value_defaults_to_tee() {
        std::env::set_var("NON_TEE_INFRA", "invalid");
        let config = InfrastructureConfig::default();
        assert!(
            !config.non_tee_infra,
            "Invalid NON_TEE_INFRA value should default to TEE mode"
        );
        std::env::remove_var("NON_TEE_INFRA");
    }

    // ============================================================================
    // Agent Config Tests with Infrastructure Mode Switching
    // ============================================================================

    #[test]
    #[serial]
    fn test_agent_config_tee_mode_leaves_fields_empty() {
        // TEE mode: NON_TEE_INFRA=false or unset
        // Clean up any leftover env vars from other tests
        std::env::remove_var("NON_TEE_INFRA");
        std::env::remove_var("AGENT_DOMAIN");
        std::env::remove_var("INSTANCE_DEFAULT_CPUS");
        std::env::remove_var("INSTANCE_DEFAULT_MEM_LIMIT");
        std::env::remove_var("INSTANCE_DEFAULT_STORAGE_SIZE");
        std::env::remove_var("AGENT_MANAGER_URLS");
        std::env::remove_var("AGENT_MANAGER_TOKENS");
        std::env::remove_var("AGENT_MANAGER_URLS_TEE");
        std::env::remove_var("AGENT_MANAGER_TOKENS_TEE");

        let config = AgentConfig::default();

        // Config creation should succeed (instance defaults now configured via system_configs)
        assert!(!config.managers.is_empty());
    }

    #[test]
    #[serial]
    fn test_agent_config_non_tee_mode_sets_fields() {
        // Clean up any leftover env vars from other tests
        std::env::remove_var("AGENT_MANAGER_URLS");
        std::env::remove_var("AGENT_MANAGER_TOKENS");
        std::env::remove_var("AGENT_MANAGER_URLS_TEE");
        std::env::remove_var("AGENT_MANAGER_TOKENS_TEE");

        // Non-TEE mode: NON_TEE_INFRA=true
        std::env::set_var("NON_TEE_INFRA", "true");
        std::env::set_var("AGENT_DOMAIN", "test.sare.dev");

        let config = AgentConfig::default();

        // Config creation should succeed (instance defaults now configured via system_configs)
        assert!(!config.managers.is_empty());

        std::env::remove_var("NON_TEE_INFRA");
        std::env::remove_var("AGENT_DOMAIN");
        std::env::remove_var("AGENT_MANAGER_URLS");
        std::env::remove_var("AGENT_MANAGER_TOKENS");
        std::env::remove_var("AGENT_MANAGER_URLS_TEE");
        std::env::remove_var("AGENT_MANAGER_TOKENS_TEE");
    }

    #[test]
    #[serial]
    fn test_agent_config_non_tee_mode_uses_defaults_when_env_not_set() {
        // Clean up any leftover env vars from other tests
        std::env::remove_var("AGENT_MANAGER_URLS");
        std::env::remove_var("AGENT_MANAGER_TOKENS");
        std::env::remove_var("AGENT_MANAGER_URLS_TEE");
        std::env::remove_var("AGENT_MANAGER_TOKENS_TEE");

        // Non-TEE mode with defaults
        std::env::set_var("NON_TEE_INFRA", "true");
        std::env::remove_var("AGENT_DOMAIN");
        std::env::remove_var("INSTANCE_DEFAULT_CPUS");
        std::env::remove_var("INSTANCE_DEFAULT_MEM_LIMIT");
        std::env::remove_var("INSTANCE_DEFAULT_STORAGE_SIZE");

        let config = AgentConfig::default();

        // Config creation should succeed (instance defaults now configured via system_configs)
        assert!(!config.managers.is_empty());

        std::env::remove_var("NON_TEE_INFRA");
        std::env::remove_var("AGENT_MANAGER_URLS");
        std::env::remove_var("AGENT_MANAGER_TOKENS");
        std::env::remove_var("AGENT_MANAGER_URLS_TEE");
        std::env::remove_var("AGENT_MANAGER_TOKENS_TEE");
    }

    #[test]
    #[serial]
    fn test_agent_config_switching_modes() {
        // Clean up any leftover env vars from other tests
        std::env::remove_var("AGENT_MANAGER_URLS");
        std::env::remove_var("AGENT_MANAGER_TOKENS");

        // Test switching from TEE to non-TEE
        std::env::set_var("NON_TEE_INFRA", "false");
        std::env::set_var("AGENT_DOMAIN", "ignored.dev");
        let _tee_config = AgentConfig::default();

        // Switch to non-TEE
        std::env::set_var("NON_TEE_INFRA", "true");
        let _non_tee_config = AgentConfig::default();

        std::env::remove_var("NON_TEE_INFRA");
        std::env::remove_var("AGENT_DOMAIN");
        std::env::remove_var("AGENT_MANAGER_URLS");
        std::env::remove_var("AGENT_MANAGER_TOKENS");
    }

    #[test]
    #[serial]
    fn test_config_struct_includes_infrastructure() {
        std::env::remove_var("NON_TEE_INFRA");
        // Clean up any leftover env vars from previous tests (especially from panicking tests)
        std::env::remove_var("AGENT_MANAGER_URLS");
        std::env::remove_var("AGENT_MANAGER_TOKENS");
        std::env::remove_var("AGENT_MANAGER_URLS_TEE");
        std::env::remove_var("AGENT_MANAGER_TOKENS_TEE");
        let config = Config::from_env();

        // Verify infrastructure config is part of Config struct
        assert!(
            !config.infrastructure.non_tee_infra,
            "Config should include infrastructure with default TEE mode"
        );
    }

    #[test]
    #[serial]
    fn test_config_struct_non_tee_mode() {
        // Clean up any leftover env vars from other tests
        std::env::remove_var("AGENT_MANAGER_URLS");
        std::env::remove_var("AGENT_MANAGER_TOKENS");
        std::env::remove_var("AGENT_MANAGER_URLS_TEE");
        std::env::remove_var("AGENT_MANAGER_TOKENS_TEE");

        std::env::set_var("NON_TEE_INFRA", "true");
        std::env::set_var("AGENT_DOMAIN", "production.dev");

        let config = Config::from_env();

        assert!(
            config.infrastructure.non_tee_infra,
            "Config infrastructure should reflect NON_TEE_INFRA setting"
        );

        std::env::remove_var("NON_TEE_INFRA");
        std::env::remove_var("AGENT_DOMAIN");
        std::env::remove_var("AGENT_MANAGER_URLS");
        std::env::remove_var("AGENT_MANAGER_TOKENS");
    }

    #[test]
    #[serial]
    fn test_agent_manager_type_detection_from_url() {
        // Test that manager type uses explicit is_non_tee field (not URL pattern detection)

        // Manager with is_non_tee=true should be detected as non-TEE
        let non_tee_mgr = AgentManager {
            url: "https://api.openclaw-dev.near.ai".to_string(),
            token: "token1".to_string(),
            is_non_tee: true,
        };
        assert!(
            non_tee_mgr.get_is_non_tee(),
            "Manager with is_non_tee=true should be non-TEE"
        );

        // Manager with is_non_tee=false should be detected as TEE
        let tee_mgr = AgentManager {
            url: "https://agents.example.com/api/crabshack".to_string(),
            token: "token2".to_string(),
            is_non_tee: false,
        };
        assert!(
            !tee_mgr.get_is_non_tee(),
            "Manager with is_non_tee=false should be TEE"
        );

        // Test that is_non_tee field is respected regardless of URL
        let compose_mgr = AgentManager {
            url: "https://compose.example.com".to_string(),
            token: "token3".to_string(),
            is_non_tee: true,
        };
        assert!(
            compose_mgr.get_is_non_tee(),
            "Manager with is_non_tee=true should be non-TEE even with generic URL"
        );
    }

    #[test]
    #[serial]
    fn test_task_config_reads_env_and_region_fallback() {
        std::env::set_var("TASKS_ENABLED", "true");
        std::env::set_var("AWS_REGION", "us-west-2");
        std::env::set_var("TASKS_SQS_QUEUE_URL", "https://example.com/queue");
        std::env::set_var("TASKS_SQS_QUEUE_ARN", "arn:aws:sqs:us-west-2:123:queue");
        std::env::set_var(
            "TASKS_SCHEDULER_ROLE_ARN",
            "arn:aws:iam::123:role/scheduler",
        );
        std::env::set_var("TASKS_SCHEDULER_GROUP", "group-a");
        std::env::set_var(
            "TASKS_CLEANUP_CANCELED_INSTANCES_DAILY_TASK_ID",
            "  cleanup.canceled-instances.daily.prod  ",
        );
        std::env::set_var(
            "TASKS_CLEANUP_CANCELED_INSTANCES_DAILY_CRON",
            "cron(0 12 * * ? *)",
        );
        std::env::set_var("TASKS_CLEANUP_CANCELED_INSTANCES_GRACE_DAYS", "21");
        std::env::set_var("TASKS_WORKER_WAIT_SECONDS", "12");
        std::env::set_var("TASKS_WORKER_VISIBILITY_TIMEOUT", "90");
        std::env::set_var("TASKS_WORKER_MAX_MESSAGES", "7");
        std::env::set_var("TASKS_WORKER_MAX_CONCURRENCY", "22");

        let cfg = TaskConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.aws_region.as_deref(), Some("us-west-2"));
        assert_eq!(cfg.scheduler_group, "group-a");
        assert_eq!(
            cfg.cleanup_canceled_instances_daily_task_id,
            "cleanup.canceled-instances.daily.prod"
        );
        assert_eq!(
            cfg.cleanup_canceled_instances_daily_cron,
            "cron(0 12 * * ? *)"
        );
        assert_eq!(cfg.cleanup_canceled_instances_grace_days, 21);
        assert_eq!(cfg.worker_wait_seconds, 12);
        assert_eq!(cfg.worker_visibility_timeout, 90);
        assert_eq!(cfg.worker_max_messages, 7);
        assert_eq!(cfg.worker_max_concurrency, 22);
        assert!(cfg.is_scheduler_configured());
        assert!(cfg.is_worker_configured());

        std::env::remove_var("TASKS_ENABLED");
        std::env::remove_var("AWS_REGION");
        std::env::remove_var("TASKS_SQS_QUEUE_URL");
        std::env::remove_var("TASKS_SQS_QUEUE_ARN");
        std::env::remove_var("TASKS_SCHEDULER_ROLE_ARN");
        std::env::remove_var("TASKS_SCHEDULER_GROUP");
        std::env::remove_var("TASKS_CLEANUP_CANCELED_INSTANCES_DAILY_TASK_ID");
        std::env::remove_var("TASKS_CLEANUP_CANCELED_INSTANCES_DAILY_CRON");
        std::env::remove_var("TASKS_CLEANUP_CANCELED_INSTANCES_GRACE_DAYS");
        std::env::remove_var("TASKS_WORKER_WAIT_SECONDS");
        std::env::remove_var("TASKS_WORKER_VISIBILITY_TIMEOUT");
        std::env::remove_var("TASKS_WORKER_MAX_MESSAGES");
        std::env::remove_var("TASKS_WORKER_MAX_CONCURRENCY");
    }
}
