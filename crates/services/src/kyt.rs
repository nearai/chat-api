use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const PROVIDER_LUKKA: &str = "lukka";
const NEAR_ADDRESS_TYPE: &str = "NEAR";

#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum KytRiskLevel {
    Low,
    Medium,
    High,
    Unknown,
}

impl KytRiskLevel {
    fn from_provider(value: Option<&str>) -> Self {
        match value
            .unwrap_or_default()
            .trim()
            .to_ascii_uppercase()
            .as_str()
        {
            "LOW" => Self::Low,
            "MEDIUM" => Self::Medium,
            "HIGH" => Self::High,
            _ => Self::Unknown,
        }
    }
}

#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KytCheckResult {
    pub provider: String,
    pub account_id: String,
    pub address_type: String,
    pub risk_level: KytRiskLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_id: Option<String>,
    pub checked_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Default for KytCheckResult {
    fn default() -> Self {
        Self::unknown("", "not_checked")
    }
}

impl KytCheckResult {
    pub fn unknown(account_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            provider: PROVIDER_LUKKA.to_string(),
            account_id: account_id.into(),
            address_type: NEAR_ADDRESS_TYPE.to_string(),
            risk_level: KytRiskLevel::Unknown,
            score: None,
            report_id: None,
            checked_at: Utc::now(),
            reason: Some(reason.into()),
        }
    }

    pub fn is_high_risk(&self) -> bool {
        self.risk_level == KytRiskLevel::High
    }
}

#[async_trait]
pub trait KytRiskService: Send + Sync {
    async fn check_near_account(&self, account_id: &str) -> KytCheckResult;
}

pub struct NoopKytRiskService;

#[async_trait]
impl KytRiskService for NoopKytRiskService {
    async fn check_near_account(&self, account_id: &str) -> KytCheckResult {
        KytCheckResult::unknown(account_id.trim(), "disabled")
    }
}

#[derive(Clone)]
pub struct LukkaKytService {
    config: config::LukkaKytConfig,
    http_client: reqwest::Client,
    cache: Arc<RwLock<HashMap<String, CachedKytResult>>>,
}

#[derive(Clone)]
struct CachedKytResult {
    result: KytCheckResult,
    cached_at: Instant,
}

#[derive(Debug, Deserialize)]
struct LukkaAmlScoreResponse {
    report_info_section: Option<LukkaReportInfoSection>,
    cscore_section: Option<LukkaCscoreSection>,
}

#[derive(Debug, Deserialize)]
struct LukkaReportInfoSection {
    address: Option<String>,
    report_id: Option<String>,
    address_type: Option<String>,
    report_time: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LukkaCscoreSection {
    cscore: Option<i64>,
    risk_level: Option<String>,
}

impl LukkaKytService {
    pub fn new(config: config::LukkaKytConfig) -> Self {
        let timeout = Duration::from_millis(config.timeout_ms.max(1));
        let http_client = reqwest::Client::builder()
            .timeout(timeout)
            .no_proxy()
            .build()
            .unwrap_or_else(|err| {
                tracing::warn!(
                    error = %err,
                    "Failed to build Lukka KYT HTTP client with configured timeout; using default client"
                );
                reqwest::Client::new()
            });

        Self {
            config,
            http_client,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn auth_mode(&self) -> LukkaAuthMode<'_> {
        let bearer = self.config.bearer_token.trim();
        if !bearer.is_empty() {
            return LukkaAuthMode::Bearer(bearer);
        }

        let api_key = self.config.api_key.trim();
        let api_secret = self.config.api_secret.trim();
        if api_key.is_empty() {
            LukkaAuthMode::Missing
        } else if api_secret.is_empty() {
            LukkaAuthMode::Bearer(api_key)
        } else {
            LukkaAuthMode::KeySecret {
                api_key,
                api_secret,
            }
        }
    }

    fn score_url(&self, account_id: &str) -> String {
        let base = self.config.base_url.trim_end_matches('/');
        let encoded = urlencoding::encode(account_id);
        format!("{base}/v3/reports/aml/score/{encoded}?address_type={NEAR_ADDRESS_TYPE}")
    }

    async fn cached_result(&self, account_id: &str) -> Option<KytCheckResult> {
        let ttl = self.config.cache_ttl_secs;
        if ttl == 0 {
            return None;
        }

        self.cache
            .read()
            .await
            .get(account_id)
            .filter(|entry| entry.cached_at.elapsed().as_secs() < ttl)
            .map(|entry| entry.result.clone())
    }

    async fn store_cache(&self, account_id: &str, result: KytCheckResult) -> KytCheckResult {
        if self.config.cache_ttl_secs > 0 {
            self.cache.write().await.insert(
                account_id.to_string(),
                CachedKytResult {
                    result: result.clone(),
                    cached_at: Instant::now(),
                },
            );
        }
        result
    }

    async fn fetch_near_score(&self, account_id: &str) -> KytCheckResult {
        let auth_mode = self.auth_mode();
        if matches!(auth_mode, LukkaAuthMode::Missing) {
            tracing::warn!("Lukka KYT enabled but credentials are not configured");
            return KytCheckResult::unknown(account_id, "not_configured");
        }

        let url = self.score_url(account_id);
        let attempts = self.config.max_retries.saturating_add(1);
        let started = Instant::now();
        let mut last_reason = "provider_error".to_string();

        for attempt in 0..attempts {
            let mut request = self.http_client.get(&url);
            request = match auth_mode {
                LukkaAuthMode::Bearer(token) => request.bearer_auth(token),
                LukkaAuthMode::KeySecret {
                    api_key,
                    api_secret,
                } => request
                    .header("x-api-key", api_key)
                    .header("x-api-secret", api_secret),
                LukkaAuthMode::Missing => request,
            };

            match request.send().await {
                Ok(response) if response.status().is_success() => {
                    let parsed = response.json::<LukkaAmlScoreResponse>().await;
                    return match parsed {
                        Ok(body) => {
                            let result = normalize_lukka_response(account_id, body);
                            tracing::info!(
                                account_id = %result.account_id,
                                risk_level = ?result.risk_level,
                                elapsed_ms = started.elapsed().as_millis() as u64,
                                "Lukka KYT check completed"
                            );
                            if result.is_high_risk() {
                                tracing::warn!(
                                    account_id = %result.account_id,
                                    report_id = ?result.report_id,
                                    "Lukka KYT high risk NEAR account detected"
                                );
                            }
                            result
                        }
                        Err(err) => {
                            tracing::warn!(
                                account_id = %account_id,
                                error = %err,
                                "Failed to decode Lukka KYT response"
                            );
                            KytCheckResult::unknown(account_id, "provider_decode_error")
                        }
                    };
                }
                Ok(response) => {
                    let status = response.status();
                    last_reason = format!("provider_http_{}", status.as_u16());
                    tracing::warn!(
                        account_id = %account_id,
                        status = status.as_u16(),
                        attempt = attempt + 1,
                        attempts,
                        "Lukka KYT provider returned non-success status"
                    );
                    if !status.is_server_error() || attempt + 1 >= attempts {
                        break;
                    }
                }
                Err(err) => {
                    last_reason = if err.is_timeout() {
                        "provider_timeout".to_string()
                    } else {
                        "provider_error".to_string()
                    };
                    tracing::warn!(
                        account_id = %account_id,
                        error = %err,
                        attempt = attempt + 1,
                        attempts,
                        "Lukka KYT provider request failed"
                    );
                    if attempt + 1 >= attempts {
                        break;
                    }
                }
            }
        }

        KytCheckResult::unknown(account_id, last_reason)
    }
}

enum LukkaAuthMode<'a> {
    Missing,
    Bearer(&'a str),
    KeySecret {
        api_key: &'a str,
        api_secret: &'a str,
    },
}

fn normalize_lukka_response(account_id: &str, body: LukkaAmlScoreResponse) -> KytCheckResult {
    let report = body.report_info_section;
    let cscore = body.cscore_section;

    let checked_at = report
        .as_ref()
        .and_then(|r| r.report_time.as_deref())
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);

    KytCheckResult {
        provider: PROVIDER_LUKKA.to_string(),
        account_id: report
            .as_ref()
            .and_then(|r| r.address.clone())
            .filter(|address| !address.trim().is_empty())
            .unwrap_or_else(|| account_id.to_string()),
        address_type: report
            .as_ref()
            .and_then(|r| r.address_type.clone())
            .filter(|address_type| !address_type.trim().is_empty())
            .unwrap_or_else(|| NEAR_ADDRESS_TYPE.to_string()),
        risk_level: KytRiskLevel::from_provider(
            cscore
                .as_ref()
                .and_then(|section| section.risk_level.as_deref()),
        ),
        score: cscore.and_then(|section| section.cscore),
        report_id: report.and_then(|r| r.report_id),
        checked_at,
        reason: None,
    }
}

#[async_trait]
impl KytRiskService for LukkaKytService {
    async fn check_near_account(&self, account_id: &str) -> KytCheckResult {
        let account_id = account_id.trim();
        if account_id.is_empty() {
            return KytCheckResult::unknown("", "invalid_account");
        }
        if !self.config.enabled {
            return KytCheckResult::unknown(account_id, "disabled");
        }
        if let Some(result) = self.cached_result(account_id).await {
            tracing::debug!(
                account_id = %account_id,
                risk_level = ?result.risk_level,
                "Lukka KYT cache hit"
            );
            return result;
        }

        let result = self.fetch_near_score(account_id).await;
        self.store_cache(account_id, result).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_config(base_url: String) -> config::LukkaKytConfig {
        config::LukkaKytConfig {
            enabled: true,
            base_url,
            bearer_token: "test-token".to_string(),
            api_key: String::new(),
            api_secret: String::new(),
            timeout_ms: 1_000,
            max_retries: 0,
            cache_ttl_secs: 300,
        }
    }

    fn high_risk_fixture() -> serde_json::Value {
        serde_json::json!({
            "report_info_section": {
                "version": "3.4",
                "address": "gregoshes.near",
                "description": "Address related to a hacker (Stader exploit August 16, 2022).",
                "report_id": "4512815d6784a68a7101c72c8e0435e49c1652f6a9295639229bc980bc51dd49",
                "address_type": "NEAR",
                "address_subtype": "NEAR",
                "report_type": "scoring",
                "report_time": "2026-07-08T19:08:43.545Z"
            },
            "cscore_section": {
                "cscore": 99,
                "risk_level": "HIGH"
            },
            "profile_section": {
                "identified_profiles": [
                    { "profile_name": "Hacker", "profile_type": "ADDRESS" }
                ]
            }
        })
    }

    #[tokio::test]
    async fn lukka_request_uses_near_score_endpoint() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v3/reports/aml/score/gregoshes.near"))
            .and(query_param("address_type", "NEAR"))
            .and(header("authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(high_risk_fixture()))
            .expect(1)
            .mount(&server)
            .await;

        let service = LukkaKytService::new(test_config(server.uri()));
        let result = service.check_near_account("gregoshes.near").await;

        assert_eq!(result.account_id, "gregoshes.near");
        assert_eq!(result.address_type, "NEAR");
        assert_eq!(result.risk_level, KytRiskLevel::High);
        assert_eq!(result.score, Some(99));
        assert_eq!(
            result.report_id.as_deref(),
            Some("4512815d6784a68a7101c72c8e0435e49c1652f6a9295639229bc980bc51dd49")
        );
        assert_eq!(result.reason, None);
    }

    #[test]
    fn maps_provider_risk_levels() {
        for (provider_value, expected) in [
            ("LOW", KytRiskLevel::Low),
            ("MEDIUM", KytRiskLevel::Medium),
            ("HIGH", KytRiskLevel::High),
            ("unexpected", KytRiskLevel::Unknown),
        ] {
            let body = LukkaAmlScoreResponse {
                report_info_section: None,
                cscore_section: Some(LukkaCscoreSection {
                    cscore: Some(7),
                    risk_level: Some(provider_value.to_string()),
                }),
            };
            assert_eq!(
                normalize_lukka_response("alice.near", body).risk_level,
                expected
            );
        }
    }

    #[tokio::test]
    async fn provider_error_returns_unknown_without_crashing() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;

        let service = LukkaKytService::new(test_config(server.uri()));
        let result = service.check_near_account("alice.near").await;

        assert_eq!(result.risk_level, KytRiskLevel::Unknown);
        assert_eq!(result.reason.as_deref(), Some("provider_http_503"));
    }

    #[tokio::test]
    async fn cache_avoids_duplicate_provider_calls_for_same_account() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v3/reports/aml/score/gregoshes.near"))
            .respond_with(ResponseTemplate::new(200).set_body_json(high_risk_fixture()))
            .expect(1)
            .mount(&server)
            .await;

        let service = LukkaKytService::new(test_config(server.uri()));
        let first = service.check_near_account("gregoshes.near").await;
        let second = service.check_near_account("gregoshes.near").await;

        assert_eq!(first.risk_level, KytRiskLevel::High);
        assert_eq!(second.risk_level, KytRiskLevel::High);
    }

    #[tokio::test]
    async fn disabled_service_returns_unknown() {
        let mut cfg = test_config("http://127.0.0.1:1".to_string());
        cfg.enabled = false;
        let service = LukkaKytService::new(cfg);

        let result = service.check_near_account("alice.near").await;

        assert_eq!(result.risk_level, KytRiskLevel::Unknown);
        assert_eq!(result.reason.as_deref(), Some("disabled"));
    }
}
