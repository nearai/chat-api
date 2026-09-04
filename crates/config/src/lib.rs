use serde::Deserialize;
use std::collections::HashMap;
use std::fmt;
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

#[derive(Clone, Deserialize)]
pub struct LukkaAmlConfig {
    pub enabled: bool,
    pub base_url: String,
    pub bearer_token: String,
    pub high_risk_risk_levels: Vec<String>,
    pub high_risk_score_threshold: Option<i64>,
    pub high_risk_slack_webhook_url: String,
    pub high_risk_slack_timeout_ms: u64,
    pub high_risk_slack_alert_on_cached_reports: bool,
    pub report_refresh_days: i64,
    pub timeout_ms: u64,
    pub max_retries: u32,
    pub cache_ttl_secs: u64,
}

/// Parsing details for the AML high-risk policy environment variables.
///
/// The parsed policy remains intentionally permissive while AML is disabled so local and
/// staged deployments can be configured before enabling the check. `main` validates these
/// diagnostics before starting an AML-enabled server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LukkaAmlPolicyDiagnostics {
    pub risk_level_source: Option<String>,
    pub invalid_risk_level_tokens: Vec<String>,
    pub score_threshold_source: Option<String>,
    pub invalid_score_threshold: Option<String>,
}

#[derive(Debug)]
struct ParsedLukkaAmlPolicy {
    high_risk_risk_levels: Vec<String>,
    high_risk_score_threshold: Option<i64>,
    diagnostics: LukkaAmlPolicyDiagnostics,
}

impl fmt::Debug for LukkaAmlConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LukkaAmlConfig")
            .field("enabled", &self.enabled)
            .field("base_url", &self.base_url)
            .field("bearer_token", &"<redacted>")
            .field("high_risk_risk_levels", &self.high_risk_risk_levels)
            .field("high_risk_score_threshold", &self.high_risk_score_threshold)
            .field("high_risk_slack_webhook_url", &"<redacted>")
            .field(
                "high_risk_slack_timeout_ms",
                &self.high_risk_slack_timeout_ms,
            )
            .field(
                "high_risk_slack_alert_on_cached_reports",
                &self.high_risk_slack_alert_on_cached_reports,
            )
            .field("report_refresh_days", &self.report_refresh_days)
            .field("timeout_ms", &self.timeout_ms)
            .field("max_retries", &self.max_retries)
            .field("cache_ttl_secs", &self.cache_ttl_secs)
            .finish()
    }
}

impl Default for LukkaAmlConfig {
    fn default() -> Self {
        let policy = parse_lukka_aml_policy();
        Self {
            enabled: std::env::var("LUKKA_AML_ENABLED")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
            base_url: std::env::var("LUKKA_BASE_URL")
                .unwrap_or_else(|_| "https://api.blockchain-analytics.lukka.tech".to_string()),
            bearer_token: std::env::var("LUKKA_BEARER_TOKEN").unwrap_or_default(),
            high_risk_risk_levels: policy.high_risk_risk_levels,
            high_risk_score_threshold: policy.high_risk_score_threshold,
            high_risk_slack_webhook_url: std::env::var("LUKKA_AML_HIGH_RISK_SLACK_WEBHOOK_URL")
                .unwrap_or_default(),
            high_risk_slack_timeout_ms: std::env::var("LUKKA_AML_HIGH_RISK_SLACK_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1_000),
            high_risk_slack_alert_on_cached_reports: std::env::var(
                "LUKKA_AML_HIGH_RISK_SLACK_ALERT_ON_CACHED_REPORTS",
            )
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(false),
            report_refresh_days: std::env::var("LUKKA_AML_REPORT_REFRESH_DAYS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            timeout_ms: std::env::var("LUKKA_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3_000),
            max_retries: std::env::var("LUKKA_MAX_RETRIES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1),
            cache_ttl_secs: std::env::var("LUKKA_CACHE_TTL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
        }
    }
}

impl LukkaAmlConfig {
    /// Returns the exact parsing diagnostics used by the environment-backed configuration.
    pub fn high_risk_policy_diagnostics(&self) -> LukkaAmlPolicyDiagnostics {
        parse_lukka_aml_policy().diagnostics
    }

    /// Reject policy typos and an empty policy when AML enforcement is enabled.
    ///
    /// Keeping this validation separate from parsing lets callers inspect and log the safe
    /// configuration values after tracing is initialized, while still preventing a fail-open
    /// production startup.
    pub fn validate_high_risk_policy(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        let diagnostics = self.high_risk_policy_diagnostics();
        let mut errors = Vec::new();
        if !diagnostics.invalid_risk_level_tokens.is_empty() {
            errors.push(format!(
                "{} contains unrecognized risk level token(s): {}",
                diagnostics
                    .risk_level_source
                    .as_deref()
                    .unwrap_or("LUKKA_AML_HIGH_RISK_LEVELS"),
                diagnostics.invalid_risk_level_tokens.join(", "),
            ));
        }
        if let Some(value) = diagnostics.invalid_score_threshold {
            errors.push(format!(
                "{} has invalid score threshold {value:?}; expected integer 1..=100 or disabled",
                diagnostics
                    .score_threshold_source
                    .as_deref()
                    .unwrap_or("LUKKA_AML_SCORE_BLOCK_THRESHOLD"),
            ));
        }
        if self.high_risk_risk_levels.is_empty() && self.high_risk_score_threshold.is_none() {
            errors.push("AML is enabled but both high-risk predicates are disabled".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

fn lukka_aml_env_value(primary: &str, alias: &str) -> Option<(String, String)> {
    std::env::var(primary)
        .map(|value| (primary.to_string(), value))
        .or_else(|_| std::env::var(alias).map(|value| (alias.to_string(), value)))
        .ok()
}

fn is_lukka_aml_policy_disabled(value: &str) -> bool {
    let value = value.trim();
    value.is_empty()
        || ["disabled", "none", "off", "false"]
            .iter()
            .any(|disabled| value.eq_ignore_ascii_case(disabled))
}

fn parse_lukka_aml_policy() -> ParsedLukkaAmlPolicy {
    let (high_risk_risk_levels, risk_level_source, invalid_risk_level_tokens) =
        match lukka_aml_env_value(
            "LUKKA_AML_HIGH_RISK_LEVELS",
            "LUKKA_AML_BLOCKED_RISK_LEVELS",
        ) {
            None => (vec!["HIGH".to_string()], None, Vec::new()),
            Some((source, raw)) if is_lukka_aml_policy_disabled(&raw) => {
                (Vec::new(), Some(source), Vec::new())
            }
            Some((source, raw)) => {
                let mut levels = Vec::new();
                let mut invalid_tokens = Vec::new();
                for token in raw
                    .split(',')
                    .map(str::trim)
                    .filter(|token| !token.is_empty())
                {
                    let level = token.to_ascii_uppercase();
                    if matches!(level.as_str(), "LOW" | "MEDIUM" | "HIGH") {
                        if !levels.contains(&level) {
                            levels.push(level);
                        }
                    } else {
                        invalid_tokens.push(token.to_string());
                    }
                }
                (levels, Some(source), invalid_tokens)
            }
        };

    let (high_risk_score_threshold, score_threshold_source, invalid_score_threshold) =
        match lukka_aml_env_value(
            "LUKKA_AML_SCORE_BLOCK_THRESHOLD",
            "LUKKA_AML_HIGH_RISK_SCORE_THRESHOLD",
        ) {
            None => (None, None, None),
            Some((source, raw)) if is_lukka_aml_policy_disabled(&raw) => (None, Some(source), None),
            Some((source, raw)) => {
                let value = raw.trim();
                let threshold = value
                    .parse::<i64>()
                    .ok()
                    .filter(|threshold| (1..=100).contains(threshold));
                let invalid = threshold.is_none().then(|| value.to_string());
                (threshold, Some(source), invalid)
            }
        };

    ParsedLukkaAmlPolicy {
        high_risk_risk_levels,
        high_risk_score_threshold,
        diagnostics: LukkaAmlPolicyDiagnostics {
            risk_level_source,
            invalid_risk_level_tokens,
            score_threshold_source,
            invalid_score_threshold,
        },
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
    pub admin_emails: Vec<String>,
}

impl Default for AdminConfig {
    fn default() -> Self {
        let admin_domains: Vec<String> = std::env::var("AUTH_ADMIN_DOMAINS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        let mut admin_emails: Vec<String> = std::env::var("AUTH_ADMIN_EMAILS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        admin_emails.retain(|email| {
            let Some((_, domain)) = email.split_once('@') else {
                eprintln!(
                    "Ignoring invalid AUTH_ADMIN_EMAILS entry without '@': {}",
                    email
                );
                return false;
            };
            let allowed = admin_domains.iter().any(|d| d == domain);
            if !allowed {
                eprintln!(
                    "Ignoring AUTH_ADMIN_EMAILS entry outside AUTH_ADMIN_DOMAINS: {}",
                    email
                );
            }
            allowed
        });

        Self {
            admin_domains,
            admin_emails,
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

fn default_near_network_id() -> String {
    std::env::var("NEAR_NETWORK_ID")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "mainnet".to_string())
}

/// NEAR-related configuration (shared between services)
#[derive(Debug, Clone, Deserialize)]
pub struct NearConfig {
    /// NEAR JSON-RPC endpoint used for on-chain queries (e.g. balance checks)
    pub rpc_url: Url,
    /// Logical NEAR network id (e.g. `mainnet`, `testnet`). Set via `NEAR_NETWORK_ID`; passed through to
    /// subscription service and included in HoS `POST /v1/subscriptions` JSON as `network_id` so clients
    /// can pair RPC URLs with the intended network in testnet/staging.
    #[serde(default = "default_near_network_id")]
    pub network_id: String,
    /// Optional staking contract account id (e.g. `stake.dao`).
    /// Required for `house-of-stake` subscription intents and RPC sync (`NEAR_STAKING_CONTRACT_ID` env or `near.staking_contract_id` in config; `near.near_staking_contract_id` remains accepted as a legacy TOML key).
    #[serde(default, alias = "near_staking_contract_id")]
    pub staking_contract_id: Option<String>,
}

impl Default for NearConfig {
    fn default() -> Self {
        let raw =
            std::env::var("NEAR_RPC_URL").unwrap_or("https://free.rpc.fastnear.com".to_string());
        let staking_contract_id = std::env::var("NEAR_STAKING_CONTRACT_ID")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string());
        Self {
            rpc_url: Url::parse(&raw).expect("NEAR_RPC_URL must be a valid URL"),
            network_id: default_near_network_id(),
            staking_contract_id,
        }
    }
}

fn default_nearai_api_url() -> String {
    std::env::var("BACKEND_URL")
        .map(|url| url.trim_end_matches('/').to_string() + "/v1")
        .unwrap_or_else(|_| "https://private.near.ai/v1".to_string())
}

/// A single agent manager endpoint with its URL and bearer token
#[derive(Clone, serde::Deserialize)]
pub struct AgentManager {
    pub url: String,
    pub token: String,
}

// Custom Debug to redact bearer tokens from log output (CLAUDE.md: never log credentials)
impl std::fmt::Debug for AgentManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentManager")
            .field("url", &self.url)
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
        let mut managers: Vec<AgentManager> = Vec::new();

        // Load managers from AGENT_MANAGER_URLS
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
                let mgrs: Vec<AgentManager> = urls
                    .into_iter()
                    .zip(tokens)
                    .map(|(url, token)| AgentManager { url, token })
                    .collect();
                managers.extend(mgrs);
            }
        }

        // If no managers configured, fall back to legacy AGENT_API_BASE_URL
        if managers.is_empty() {
            let url = std::env::var("AGENT_API_BASE_URL")
                .unwrap_or_else(|_| "https://api.agent.near.ai".to_string());
            let token = std::env::var("AGENT_API_TOKEN").unwrap_or_default();
            managers.push(AgentManager { url, token });
        }

        // Sort for deterministic ordering
        managers.sort_by(|a, b| a.url.cmp(&b.url));

        Self {
            managers,
            nearai_api_url: std::env::var("BACKEND_URL")
                .map(|url| url.trim_end_matches('/').to_string() + "/v1")
                .unwrap_or_else(|_| "https://private.near.ai/v1".to_string()),
            channel_relay_url: std::env::var("CHANNEL_RELAY_URL").ok(),
        }
    }
}

pub const TASKS_CLEANUP_CANCELED_INSTANCES_DAILY_CRON_DEFAULT: &str = "cron(0 0 * * ? *)";
pub const TASKS_CLEANUP_CANCELED_INSTANCES_GRACE_DAYS_DEFAULT: i64 = 15;
pub const TASKS_CLEANUP_CANCELED_INSTANCES_DAILY_TASK_ID_DEFAULT: &str =
    "cleanup.canceled-instances.daily";

#[derive(Debug, Clone, Deserialize)]
pub struct TaskConfig {
    pub enabled: bool,
    pub aws_region: Option<String>,
    pub sqs_queue_url: Option<String>,
    pub sqs_queue_arn: Option<String>,
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
        self.sqs_queue_url.is_some()
    }

    pub fn worker_sqs_queue_url(&self) -> Option<&String> {
        self.sqs_queue_url.as_ref()
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
    pub database_encryption: DatabaseEncryptionConfig,
    pub oauth: OAuthConfig,
    pub email_auth: EmailAuthConfig,
    pub server: ServerConfig,
    pub openai: OpenAIConfig,
    pub lukka_aml: LukkaAmlConfig,
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
    pub tasks: TaskConfig,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            database: DatabaseConfig::default(),
            database_encryption: DatabaseEncryptionConfig::default(),
            oauth: OAuthConfig::default(),
            email_auth: EmailAuthConfig::default(),
            server: ServerConfig::default(),
            openai: OpenAIConfig::default(),
            lukka_aml: LukkaAmlConfig::default(),
            near: NearConfig::default(),
            stripe: StripeConfig::default(),
            cors: CorsConfig::default(),
            admin: AdminConfig::default(),
            vpc_auth: VpcAuthConfig::default(),
            telemetry: TelemetryConfig::default(),
            logging: LoggingConfig::default(),
            agent: AgentConfig::default(),
            tasks: TaskConfig::default(),
        }
    }
}

#[derive(Clone, Deserialize)]
pub struct DatabaseEncryptionConfig {
    /// Dedicated AES-256 key for confidential database fields. Empty disables
    /// database field encryption and its admin endpoints.
    pub key: String,
    pub key_id: String,
    /// Enables encrypted repository writes and execute-mode backfills.
    pub write_enabled: bool,
}

impl fmt::Debug for DatabaseEncryptionConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseEncryptionConfig")
            .field("key", &"[REDACTED]")
            .field("key_id", &self.key_id)
            .field("write_enabled", &self.write_enabled)
            .finish()
    }
}

impl Default for DatabaseEncryptionConfig {
    fn default() -> Self {
        let key = if let Ok(path) = std::env::var("DB_ENCRYPTION_KEY_FILE") {
            std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("Failed to read DB_ENCRYPTION_KEY_FILE at {path}: {e}"))
                .trim()
                .to_string()
        } else {
            std::env::var("DB_ENCRYPTION_KEY").unwrap_or_default()
        };
        Self {
            key,
            key_id: std::env::var("DB_ENCRYPTION_KEY_ID").unwrap_or_else(|_| "db-v1".to_string()),
            write_enabled: std::env::var("DB_ENCRYPTION_WRITE_ENABLED")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn database_encryption_defaults_safe_and_redacts_key() {
        std::env::set_var("DB_ENCRYPTION_KEY", "super-secret-test-value");
        std::env::remove_var("DB_ENCRYPTION_KEY_FILE");
        std::env::remove_var("DB_ENCRYPTION_WRITE_ENABLED");
        let config = DatabaseEncryptionConfig::default();
        assert!(!config.write_enabled);
        assert_eq!(config.key_id, "db-v1");
        let debug = format!("{config:?}");
        assert!(!debug.contains("super-secret-test-value"));
        std::env::remove_var("DB_ENCRYPTION_KEY");
    }

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
    fn test_lukka_aml_high_risk_score_threshold_env() {
        std::env::remove_var("LUKKA_AML_HIGH_RISK_SCORE_THRESHOLD");
        std::env::remove_var("LUKKA_AML_SCORE_BLOCK_THRESHOLD");
        assert_eq!(LukkaAmlConfig::default().high_risk_score_threshold, None);

        std::env::set_var("LUKKA_AML_SCORE_BLOCK_THRESHOLD", "82");
        assert_eq!(
            LukkaAmlConfig::default().high_risk_score_threshold,
            Some(82)
        );

        std::env::set_var("LUKKA_AML_HIGH_RISK_SCORE_THRESHOLD", "91");
        assert_eq!(
            LukkaAmlConfig::default().high_risk_score_threshold,
            Some(82)
        );

        std::env::remove_var("LUKKA_AML_SCORE_BLOCK_THRESHOLD");
        assert_eq!(
            LukkaAmlConfig::default().high_risk_score_threshold,
            Some(91)
        );

        std::env::set_var("LUKKA_AML_HIGH_RISK_SCORE_THRESHOLD", "101");
        assert_eq!(LukkaAmlConfig::default().high_risk_score_threshold, None);

        std::env::set_var("LUKKA_AML_HIGH_RISK_SCORE_THRESHOLD", "disabled");
        assert_eq!(LukkaAmlConfig::default().high_risk_score_threshold, None);
        std::env::remove_var("LUKKA_AML_HIGH_RISK_SCORE_THRESHOLD");
        std::env::remove_var("LUKKA_AML_SCORE_BLOCK_THRESHOLD");
    }

    #[test]
    #[serial]
    fn test_lukka_aml_high_risk_levels_env() {
        std::env::remove_var("LUKKA_AML_HIGH_RISK_LEVELS");
        std::env::remove_var("LUKKA_AML_BLOCKED_RISK_LEVELS");
        assert_eq!(
            LukkaAmlConfig::default().high_risk_risk_levels,
            vec!["HIGH".to_string()]
        );

        std::env::set_var("LUKKA_AML_BLOCKED_RISK_LEVELS", " medium, high, medium ");
        assert_eq!(
            LukkaAmlConfig::default().high_risk_risk_levels,
            vec!["MEDIUM".to_string(), "HIGH".to_string()]
        );

        std::env::set_var("LUKKA_AML_HIGH_RISK_LEVELS", "disabled");
        assert!(LukkaAmlConfig::default().high_risk_risk_levels.is_empty());

        std::env::set_var("LUKKA_AML_HIGH_RISK_LEVELS", "typo");
        assert!(LukkaAmlConfig::default().high_risk_risk_levels.is_empty());
        std::env::remove_var("LUKKA_AML_HIGH_RISK_LEVELS");
        std::env::remove_var("LUKKA_AML_BLOCKED_RISK_LEVELS");
    }

    #[test]
    #[serial]
    fn test_enabled_lukka_aml_rejects_invalid_or_empty_high_risk_policy() {
        for variable in [
            "LUKKA_AML_HIGH_RISK_LEVELS",
            "LUKKA_AML_BLOCKED_RISK_LEVELS",
            "LUKKA_AML_SCORE_BLOCK_THRESHOLD",
            "LUKKA_AML_HIGH_RISK_SCORE_THRESHOLD",
        ] {
            std::env::remove_var(variable);
        }
        std::env::set_var("LUKKA_AML_ENABLED", "true");

        std::env::set_var("LUKKA_AML_HIGH_RISK_LEVELS", "HIGH, HGIH");
        std::env::set_var("LUKKA_AML_SCORE_BLOCK_THRESHOLD", "75");
        let config = LukkaAmlConfig::default();
        let diagnostics = config.high_risk_policy_diagnostics();
        assert_eq!(diagnostics.invalid_risk_level_tokens, vec!["HGIH"]);
        assert!(config.validate_high_risk_policy().is_err());

        std::env::set_var("LUKKA_AML_HIGH_RISK_LEVELS", "disabled");
        std::env::set_var("LUKKA_AML_SCORE_BLOCK_THRESHOLD", "disabled");
        let config = LukkaAmlConfig::default();
        assert!(config.high_risk_risk_levels.is_empty());
        assert_eq!(config.high_risk_score_threshold, None);
        assert!(config.validate_high_risk_policy().is_err());

        std::env::set_var("LUKKA_AML_HIGH_RISK_LEVELS", "HIGH");
        std::env::set_var("LUKKA_AML_SCORE_BLOCK_THRESHOLD", "101");
        let config = LukkaAmlConfig::default();
        let diagnostics = config.high_risk_policy_diagnostics();
        assert_eq!(diagnostics.invalid_score_threshold.as_deref(), Some("101"));
        assert!(config.validate_high_risk_policy().is_err());

        std::env::remove_var("LUKKA_AML_SCORE_BLOCK_THRESHOLD");
        let config = LukkaAmlConfig::default();
        assert!(config.validate_high_risk_policy().is_ok());

        std::env::remove_var("LUKKA_AML_ENABLED");
        std::env::remove_var("LUKKA_AML_HIGH_RISK_LEVELS");
        std::env::remove_var("LUKKA_AML_SCORE_BLOCK_THRESHOLD");
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
        std::env::remove_var("AGENT_MANAGER_URLS");
        std::env::remove_var("AGENT_MANAGER_TOKENS");
    }

    #[test]
    #[serial]
    fn test_agent_config_csv_overrides_legacy() {
        std::env::set_var("AGENT_MANAGER_URLS", "https://csv.example.com");
        std::env::set_var("AGENT_MANAGER_TOKENS", "csv-tok");
        std::env::set_var("AGENT_API_BASE_URL", "https://legacy.example.com");
        std::env::set_var("AGENT_API_TOKEN", "legacy-tok");
        let config = AgentConfig::default();
        // CSV format takes priority over legacy vars
        assert_eq!(config.managers.len(), 1);
        assert_eq!(config.managers[0].url, "https://csv.example.com");
        assert_eq!(config.managers[0].token, "csv-tok");
        std::env::remove_var("AGENT_MANAGER_URLS");
        std::env::remove_var("AGENT_MANAGER_TOKENS");
        std::env::remove_var("AGENT_API_BASE_URL");
        std::env::remove_var("AGENT_API_TOKEN");
    }

    #[test]
    #[serial]
    #[should_panic(expected = "AGENT_MANAGER_URLS has 2 entries but AGENT_MANAGER_TOKENS has 1")]
    fn test_agent_config_csv_mismatched_lengths_panics() {
        std::env::set_var(
            "AGENT_MANAGER_URLS",
            "https://mgr1.example.com,https://mgr2.example.com",
        );
        std::env::set_var("AGENT_MANAGER_TOKENS", "tok1");
        let _ = AgentConfig::default();
        // Cleanup happens after panic
        std::env::remove_var("AGENT_MANAGER_URLS");
        std::env::remove_var("AGENT_MANAGER_TOKENS");
    }

    #[test]
    #[serial]
    fn test_agent_config_csv_whitespace_and_trailing_commas() {
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
        std::env::remove_var("AGENT_MANAGER_URLS");
        std::env::remove_var("AGENT_MANAGER_TOKENS");
    }

    #[test]
    #[serial]
    fn test_agent_manager_debug_redacts_token() {
        let mgr = AgentManager {
            url: "https://test.com".to_string(),
            token: "super-secret".to_string(),
        };
        let debug_output = format!("{:?}", mgr);
        assert!(debug_output.contains("https://test.com"));
        assert!(!debug_output.contains("super-secret"));
        assert!(debug_output.contains("REDACTED"));
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
    fn test_agent_config_defaults_when_env_not_set() {
        // Clean up any leftover env vars from other tests
        std::env::remove_var("AGENT_MANAGER_URLS");
        std::env::remove_var("AGENT_MANAGER_TOKENS");
        std::env::remove_var("AGENT_DOMAIN");
        std::env::remove_var("INSTANCE_DEFAULT_CPUS");
        std::env::remove_var("INSTANCE_DEFAULT_MEM_LIMIT");
        std::env::remove_var("INSTANCE_DEFAULT_STORAGE_SIZE");

        let config = AgentConfig::default();

        // Config creation should succeed (instance defaults now configured via system_configs)
        assert!(!config.managers.is_empty());
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
