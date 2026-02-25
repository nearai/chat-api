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
        // Comma-separated lists: AGENT_MANAGER_URLS=url1,url2  AGENT_MANAGER_TOKENS=tok1,tok2
        let managers = if let Ok(urls_raw) = std::env::var("AGENT_MANAGER_URLS") {
            let urls = split_csv(&urls_raw);
            if urls.is_empty() {
                // AGENT_MANAGER_URLS is set but empty/blank — fall through to legacy
                let url = std::env::var("AGENT_API_BASE_URL")
                    .unwrap_or_else(|_| "https://api.agent.near.ai".to_string());
                let token = std::env::var("AGENT_API_TOKEN").unwrap_or_default();
                vec![AgentManager { url, token }]
            } else {
                let tokens_raw = std::env::var("AGENT_MANAGER_TOKENS").unwrap_or_default();
                let tokens = split_csv(&tokens_raw);
                if urls.len() != tokens.len() {
                    panic!(
                        "AGENT_MANAGER_URLS has {} entries but AGENT_MANAGER_TOKENS has {} — they must match",
                        urls.len(),
                        tokens.len()
                    );
                }
                let mut mgrs: Vec<AgentManager> = urls
                    .into_iter()
                    .zip(tokens)
                    .map(|(url, token)| AgentManager { url, token })
                    .collect();
                // Sort by URL for deterministic ordering across restarts
                mgrs.sort_by(|a, b| a.url.cmp(&b.url));
                mgrs
            }
        } else {
            // Legacy: single AGENT_API_BASE_URL + AGENT_API_TOKEN
            let url = std::env::var("AGENT_API_BASE_URL")
                .unwrap_or_else(|_| "https://api.agent.near.ai".to_string());
            let token = std::env::var("AGENT_API_TOKEN").unwrap_or_default();
            vec![AgentManager { url, token }]
        };

        Self {
            managers,
            nearai_api_url: std::env::var("BACKEND_URL")
                .map(|url| url.trim_end_matches('/').to_string() + "/v1")
                .unwrap_or_else(|_| "https://private.near.ai/v1".to_string()),
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
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            database: DatabaseConfig::default(),
            oauth: OAuthConfig::default(),
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
}
