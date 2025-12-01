#![allow(clippy::uninlined_format_args)]

use serde::Deserialize;

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
            api_key: std::env::var("OPENAI_API_KEY").unwrap_or_default(),
            base_url: std::env::var("OPENAI_BASE_URL").ok(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: std::env::var("CORS_ALLOWED_ORIGINS")
                .unwrap_or_else(|_| "http://localhost:3000".to_string())
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
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

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Config {
    pub database: DatabaseConfig,
    pub oauth: OAuthConfig,
    pub server: ServerConfig,
    pub openai: OpenAIConfig,
    pub cors: CorsConfig,
    pub admin: AdminConfig,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            database: DatabaseConfig::default(),
            oauth: OAuthConfig::default(),
            server: ServerConfig::default(),
            openai: OpenAIConfig::default(),
            cors: CorsConfig::default(),
            admin: AdminConfig::default(),
        }
    }
}
