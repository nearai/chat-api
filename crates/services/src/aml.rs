use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use uuid::Uuid;

const PROVIDER_LUKKA: &str = "lukka";
const NEAR_ADDRESS_TYPE: &str = "NEAR";
const PROVIDER_FAILURE_CACHE_TTL_SECS: u64 = 60;
const PROVIDER_FAILURE_ALERT_TTL_SECS: u64 = 300;

#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AmlRiskLevel {
    Low,
    Medium,
    High,
    Unknown,
}

impl AmlRiskLevel {
    fn from_provider(value: Option<&str>) -> Option<Self> {
        Some(match value?.trim().to_ascii_uppercase().as_str() {
            "LOW" => Self::Low,
            "MEDIUM" => Self::Medium,
            "HIGH" => Self::High,
            _ => return None,
        })
    }
}

#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmlCheckResult {
    pub provider: String,
    pub account_id: String,
    pub address_type: String,
    pub risk_level: AmlRiskLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_id: Option<String>,
    pub checked_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Default for AmlCheckResult {
    fn default() -> Self {
        Self::unknown("", "not_checked")
    }
}

impl AmlCheckResult {
    pub fn unknown(account_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            provider: PROVIDER_LUKKA.to_string(),
            account_id: account_id.into(),
            address_type: NEAR_ADDRESS_TYPE.to_string(),
            risk_level: AmlRiskLevel::Unknown,
            score: None,
            report_id: None,
            checked_at: Utc::now(),
            reason: Some(reason.into()),
        }
    }

    pub fn is_high_risk(&self) -> bool {
        self.risk_level == AmlRiskLevel::High
    }

    pub fn is_provider_failure(&self) -> bool {
        self.risk_level == AmlRiskLevel::Unknown
            && self
                .reason
                .as_deref()
                .is_some_and(|reason| reason.starts_with("provider_"))
    }
}

fn send_high_risk_aml_slack_alert(
    http_client: reqwest::Client,
    webhook_url: &str,
    user_id: crate::UserId,
    flow: &str,
    result: &AmlCheckResult,
) {
    let webhook_url = webhook_url.trim();
    if webhook_url.is_empty() {
        return;
    }

    let webhook_url = webhook_url.to_string();
    let account_id = result.account_id.clone();
    let provider = result.provider.clone();
    let report_id = result.report_id.clone();
    let reason = result.reason.clone();
    let score = result
        .score
        .map(|score| score.to_string())
        .unwrap_or_else(|| "n/a".to_string());
    let checked_at = result.checked_at.to_rfc3339();
    let flow = flow.to_string();
    let payload = serde_json::json!({
        "text": format!(
            "High-risk AML detection: account={} user_id={} flow={} provider={} address_type={} risk_level={:?} score={} report_id={} reason={} checked_at={}",
            account_id,
            user_id,
            flow,
            provider,
            result.address_type,
            result.risk_level,
            score,
            report_id.as_deref().unwrap_or("n/a"),
            reason.as_deref().unwrap_or("n/a"),
            checked_at
        ),
    });

    tokio::spawn(async move {
        match http_client.post(&webhook_url).json(&payload).send().await {
            Ok(response) if response.status().is_success() => {}
            Ok(response) => {
                tracing::error!(
                    user_id = %user_id,
                    flow = %flow,
                    status = response.status().as_u16(),
                    "Slack webhook returned non-success status for high-risk AML alert"
                );
            }
            Err(err) => {
                tracing::error!(
                    user_id = %user_id,
                    flow = %flow,
                    error = %err,
                    "Failed to send high-risk AML Slack alert"
                );
            }
        }
    });
}

fn send_aml_provider_failure_slack_alert(
    http_client: reqwest::Client,
    webhook_url: &str,
    user_id: crate::UserId,
    flow: &str,
    result: &AmlCheckResult,
) {
    let webhook_url = webhook_url.trim();
    if webhook_url.is_empty() {
        return;
    }

    let webhook_url = webhook_url.to_string();
    let account_id = result.account_id.clone();
    let provider = result.provider.clone();
    let address_type = result.address_type.clone();
    let risk_level = result.risk_level;
    let reason = result
        .reason
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    let report_id = result
        .report_id
        .clone()
        .unwrap_or_else(|| "n/a".to_string());
    let score = result
        .score
        .map(|score| score.to_string())
        .unwrap_or_else(|| "n/a".to_string());
    let checked_at = result.checked_at.to_rfc3339();
    let flow = flow.to_string();
    let payload = serde_json::json!({
        "text": format!(
            "AML provider failure: account={} user_id={} flow={} provider={} address_type={} risk_level={:?} score={} report_id={} reason={} checked_at={} action=fail_open",
            account_id,
            user_id,
            flow,
            provider,
            address_type,
            risk_level,
            score,
            report_id,
            reason,
            checked_at
        ),
    });

    tokio::spawn(async move {
        match http_client.post(&webhook_url).json(&payload).send().await {
            Ok(response) if response.status().is_success() => {}
            Ok(response) => {
                tracing::error!(
                    user_id = %user_id,
                    flow = %flow,
                    status = response.status().as_u16(),
                    "Slack webhook returned non-success status for AML provider failure alert"
                );
            }
            Err(err) => {
                tracing::error!(
                    user_id = %user_id,
                    flow = %flow,
                    error = %err,
                    "Failed to send AML provider failure Slack alert"
                );
            }
        }
    });
}

#[async_trait]
pub trait AmlRiskService: Send + Sync {
    fn is_enabled(&self) -> bool;
    fn report_refresh_days(&self) -> i64 {
        30
    }
    fn alert_on_cached_reports(&self) -> bool {
        false
    }
    fn send_high_risk_slack_alert(
        &self,
        _user_id: crate::UserId,
        _flow: &str,
        _result: &AmlCheckResult,
    ) {
    }
    fn send_provider_failure_slack_alert(
        &self,
        _user_id: crate::UserId,
        _flow: &str,
        _result: &AmlCheckResult,
    ) {
    }
    async fn check_near_account(&self, account_id: &str) -> AmlCheckResult;
}

#[derive(Debug, Clone)]
pub struct AmlReportRecord {
    pub id: Uuid,
    pub user_id: Option<crate::UserId>,
    pub flow: String,
    pub provider: String,
    pub account_id: String,
    pub address_type: String,
    pub risk_level: AmlRiskLevel,
    pub score: Option<i64>,
    pub report_id: Option<String>,
    pub checked_at: DateTime<Utc>,
    pub reason: Option<String>,
    pub result: AmlCheckResult,
    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct AmlAccountAllowlistEntry {
    pub account_id: String,
    pub reason: Option<String>,
    pub created_by: Option<crate::UserId>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct AmlReportEvent {
    pub user_id: crate::UserId,
    pub flow: String,
    pub result: AmlCheckResult,
}

#[async_trait]
pub trait AmlReportRepository: Send + Sync {
    async fn record_report(&self, event: AmlReportEvent) -> anyhow::Result<AmlReportRecord>;
    async fn latest_active_report(
        &self,
        account_id: &str,
    ) -> anyhow::Result<Option<AmlReportRecord>>;
    async fn is_account_allowlisted(&self, account_id: &str) -> anyhow::Result<bool>;
    async fn list_reports(
        &self,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<AmlReportRecord>, i64)>;
    async fn list_allowlist(&self) -> anyhow::Result<Vec<AmlAccountAllowlistEntry>>;
    async fn add_allowlist_entry(
        &self,
        account_id: &str,
        reason: Option<String>,
        created_by: Option<crate::UserId>,
    ) -> anyhow::Result<AmlAccountAllowlistEntry>;
    async fn remove_allowlist_entry(&self, account_id: &str) -> anyhow::Result<bool>;
    async fn set_report_active(
        &self,
        id: Uuid,
        active: bool,
    ) -> anyhow::Result<Option<AmlReportRecord>>;
}

pub struct NoopAmlRiskService;

#[async_trait]
impl AmlRiskService for NoopAmlRiskService {
    fn is_enabled(&self) -> bool {
        false
    }

    async fn check_near_account(&self, account_id: &str) -> AmlCheckResult {
        AmlCheckResult::unknown(account_id.trim(), "disabled")
    }
}

pub struct NoopAmlReportRepository;

#[async_trait]
impl AmlReportRepository for NoopAmlReportRepository {
    async fn record_report(&self, event: AmlReportEvent) -> anyhow::Result<AmlReportRecord> {
        let now = Utc::now();
        let active = event.result.risk_level != AmlRiskLevel::Unknown;
        Ok(AmlReportRecord {
            id: Uuid::new_v4(),
            user_id: Some(event.user_id),
            flow: event.flow,
            provider: event.result.provider.clone(),
            account_id: event.result.account_id.clone(),
            address_type: event.result.address_type.clone(),
            risk_level: event.result.risk_level,
            score: event.result.score,
            report_id: event.result.report_id.clone(),
            checked_at: event.result.checked_at,
            reason: event.result.reason.clone(),
            result: event.result,
            active,
            created_at: now,
            updated_at: now,
        })
    }

    async fn latest_active_report(
        &self,
        _account_id: &str,
    ) -> anyhow::Result<Option<AmlReportRecord>> {
        Ok(None)
    }

    async fn is_account_allowlisted(&self, _account_id: &str) -> anyhow::Result<bool> {
        Ok(false)
    }

    async fn list_reports(
        &self,
        _limit: i64,
        _offset: i64,
    ) -> anyhow::Result<(Vec<AmlReportRecord>, i64)> {
        Ok((Vec::new(), 0))
    }

    async fn list_allowlist(&self) -> anyhow::Result<Vec<AmlAccountAllowlistEntry>> {
        Ok(Vec::new())
    }

    async fn add_allowlist_entry(
        &self,
        account_id: &str,
        reason: Option<String>,
        created_by: Option<crate::UserId>,
    ) -> anyhow::Result<AmlAccountAllowlistEntry> {
        Ok(AmlAccountAllowlistEntry {
            account_id: normalize_account_id(account_id),
            reason,
            created_by,
            created_at: Utc::now(),
        })
    }

    async fn remove_allowlist_entry(&self, _account_id: &str) -> anyhow::Result<bool> {
        Ok(false)
    }

    async fn set_report_active(
        &self,
        _id: Uuid,
        _active: bool,
    ) -> anyhow::Result<Option<AmlReportRecord>> {
        Ok(None)
    }
}

pub fn normalize_account_id(account_id: &str) -> String {
    account_id.trim().to_ascii_lowercase()
}

#[derive(Clone)]
pub struct LukkaAmlService {
    config: config::LukkaAmlConfig,
    http_client: reqwest::Client,
    slack_http_client: reqwest::Client,
    cache: Arc<RwLock<HashMap<String, CachedAmlResult>>>,
    provider_failure_alert_cache: Arc<RwLock<HashMap<String, Instant>>>,
}

#[derive(Clone)]
struct CachedAmlResult {
    result: AmlCheckResult,
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

impl LukkaAmlService {
    pub fn new(config: config::LukkaAmlConfig) -> Self {
        let timeout = Duration::from_millis(config.timeout_ms.max(1));
        let http_client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_else(|err| {
                tracing::warn!(
                    error = %err,
                    "Failed to build Lukka AML HTTP client with configured timeout; using default client"
                );
                reqwest::Client::new()
            });
        let slack_http_client = reqwest::Client::builder()
            .timeout(Duration::from_millis(
                config.high_risk_slack_timeout_ms.max(1),
            ))
            .build()
            .unwrap_or_else(|err| {
                tracing::warn!(
                    error = %err,
                    "Failed to build AML Slack HTTP client with configured timeout; using default client"
                );
                reqwest::Client::new()
            });

        Self {
            config,
            http_client,
            slack_http_client,
            cache: Arc::new(RwLock::new(HashMap::new())),
            provider_failure_alert_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn auth_mode(&self) -> LukkaAuthMode<'_> {
        let bearer = self.config.bearer_token.trim();
        if !bearer.is_empty() {
            return LukkaAuthMode::Bearer(bearer);
        }

        LukkaAuthMode::Missing
    }

    fn score_url(&self, account_id: &str) -> String {
        let base = self.config.base_url.trim_end_matches('/');
        let encoded = urlencoding::encode(account_id);
        format!("{base}/v3/reports/aml/score/{encoded}?address_type={NEAR_ADDRESS_TYPE}")
    }

    fn provider_failure_alert_key(
        user_id: crate::UserId,
        flow: &str,
        result: &AmlCheckResult,
    ) -> String {
        format!(
            "{}:{}:{}:{}",
            user_id,
            flow,
            result.account_id,
            result.reason.as_deref().unwrap_or("unknown")
        )
    }

    fn should_send_provider_failure_alert(
        &self,
        user_id: crate::UserId,
        flow: &str,
        result: &AmlCheckResult,
    ) -> bool {
        if !result.is_provider_failure() {
            return false;
        }

        let key = Self::provider_failure_alert_key(user_id, flow, result);
        let Ok(mut cache) = self.provider_failure_alert_cache.try_write() else {
            return false;
        };
        cache.retain(|_, sent_at| sent_at.elapsed().as_secs() < PROVIDER_FAILURE_ALERT_TTL_SECS);
        if cache
            .get(&key)
            .is_some_and(|sent_at| sent_at.elapsed().as_secs() < PROVIDER_FAILURE_ALERT_TTL_SECS)
        {
            return false;
        }
        cache.insert(key, Instant::now());
        true
    }

    async fn cached_result(&self, account_id: &str) -> Option<AmlCheckResult> {
        if self.config.cache_ttl_secs == 0 {
            return None;
        }

        self.cache
            .read()
            .await
            .get(account_id)
            .filter(|entry| {
                entry.cached_at.elapsed().as_secs() < self.cache_ttl_secs(&entry.result)
            })
            .map(|entry| entry.result.clone())
    }

    fn cache_ttl_secs(&self, result: &AmlCheckResult) -> u64 {
        if result.is_provider_failure() {
            return self
                .config
                .cache_ttl_secs
                .min(PROVIDER_FAILURE_CACHE_TTL_SECS);
        }
        self.config.cache_ttl_secs
    }

    async fn store_cache(&self, account_id: &str, result: AmlCheckResult) -> AmlCheckResult {
        if self.config.cache_ttl_secs > 0 {
            if result.risk_level == AmlRiskLevel::Unknown && !result.is_provider_failure() {
                return result;
            }

            let mut cache = self.cache.write().await;
            cache.retain(|_, entry| {
                entry.cached_at.elapsed().as_secs() < self.cache_ttl_secs(&entry.result)
            });
            cache.insert(
                account_id.to_string(),
                CachedAmlResult {
                    result: result.clone(),
                    cached_at: Instant::now(),
                },
            );
        }
        result
    }

    async fn fetch_near_score(&self, account_id: &str) -> AmlCheckResult {
        let auth_mode = self.auth_mode();
        if matches!(auth_mode, LukkaAuthMode::Missing) {
            tracing::warn!("Lukka AML enabled but credentials are not configured");
            return AmlCheckResult::unknown(account_id, "not_configured");
        }

        let url = self.score_url(account_id);
        let attempts = self.config.max_retries.saturating_add(1);
        let started = Instant::now();
        let mut last_reason = "provider_error".to_string();

        for attempt in 0..attempts {
            let mut request = self.http_client.get(&url);
            request = match auth_mode {
                LukkaAuthMode::Bearer(token) => request.bearer_auth(token),
                LukkaAuthMode::Missing => request,
            };

            match request.send().await {
                Ok(response) if response.status().is_success() => {
                    let parsed = response.json::<LukkaAmlScoreResponse>().await;
                    return match parsed {
                        Ok(body) => {
                            let result = normalize_lukka_response(account_id, body);
                            tracing::debug!(
                                elapsed_ms = started.elapsed().as_millis() as u64,
                                "Lukka AML check completed"
                            );
                            if result.is_high_risk() {
                                tracing::warn!(
                                    report_id = ?result.report_id,
                                    "Lukka AML high risk NEAR account detected"
                                );
                            }
                            result
                        }
                        Err(err) => {
                            tracing::warn!(
                                error = %err,
                                "Failed to decode Lukka AML response"
                            );
                            AmlCheckResult::unknown(account_id, "provider_decode_error")
                        }
                    };
                }
                Ok(response) => {
                    let status = response.status();
                    last_reason = format!("provider_http_{}", status.as_u16());
                    tracing::warn!(
                        status = status.as_u16(),
                        attempt = attempt + 1,
                        attempts,
                        "Lukka AML provider returned non-success status"
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
                        error = %err,
                        attempt = attempt + 1,
                        attempts,
                        "Lukka AML provider request failed"
                    );
                    if attempt + 1 >= attempts {
                        break;
                    }
                }
            }
        }

        AmlCheckResult::unknown(account_id, last_reason)
    }
}

#[derive(Clone, Copy)]
enum LukkaAuthMode<'a> {
    Missing,
    Bearer(&'a str),
}

fn normalize_lukka_response(account_id: &str, body: LukkaAmlScoreResponse) -> AmlCheckResult {
    let report = body.report_info_section;
    let cscore = body.cscore_section;
    let risk_level = AmlRiskLevel::from_provider(
        cscore
            .as_ref()
            .and_then(|section| section.risk_level.as_deref()),
    );

    let Some(risk_level) = risk_level else {
        let mut result = AmlCheckResult::unknown(account_id, "provider_invalid_response");
        if let Some(report) = report {
            if let Some(address) = report.address.filter(|address| !address.trim().is_empty()) {
                result.account_id = address;
            }
            if let Some(address_type) = report
                .address_type
                .filter(|address_type| !address_type.trim().is_empty())
            {
                result.address_type = address_type;
            }
            result.report_id = report.report_id;
            result.checked_at = report
                .report_time
                .as_deref()
                .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or(result.checked_at);
        }
        if let Some(cscore) = cscore.and_then(|section| section.cscore) {
            result.score = Some(cscore);
        }
        return result;
    };

    let checked_at = report
        .as_ref()
        .and_then(|r| r.report_time.as_deref())
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);

    AmlCheckResult {
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
        risk_level,
        score: cscore.and_then(|section| section.cscore),
        report_id: report.and_then(|r| r.report_id),
        checked_at,
        reason: None,
    }
}

#[async_trait]
impl AmlRiskService for LukkaAmlService {
    fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    fn report_refresh_days(&self) -> i64 {
        self.config.report_refresh_days.max(1)
    }

    fn alert_on_cached_reports(&self) -> bool {
        self.config.high_risk_slack_alert_on_cached_reports
    }

    fn send_high_risk_slack_alert(
        &self,
        user_id: crate::UserId,
        flow: &str,
        result: &AmlCheckResult,
    ) {
        send_high_risk_aml_slack_alert(
            self.slack_http_client.clone(),
            &self.config.high_risk_slack_webhook_url,
            user_id,
            flow,
            result,
        );
    }

    fn send_provider_failure_slack_alert(
        &self,
        user_id: crate::UserId,
        flow: &str,
        result: &AmlCheckResult,
    ) {
        if !self.should_send_provider_failure_alert(user_id, flow, result) {
            return;
        }
        send_aml_provider_failure_slack_alert(
            self.slack_http_client.clone(),
            &self.config.high_risk_slack_webhook_url,
            user_id,
            flow,
            result,
        );
    }

    async fn check_near_account(&self, account_id: &str) -> AmlCheckResult {
        let account_id = account_id.trim();
        if account_id.is_empty() {
            return AmlCheckResult::unknown("", "invalid_account");
        }
        if !self.config.enabled {
            return AmlCheckResult::unknown(account_id, "disabled");
        }
        if let Some(result) = self.cached_result(account_id).await {
            tracing::debug!(
                account_id = %account_id,
                risk_level = ?result.risk_level,
                "Lukka AML cache hit"
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

    fn test_config(base_url: String) -> config::LukkaAmlConfig {
        config::LukkaAmlConfig {
            enabled: true,
            base_url,
            bearer_token: "test-token".to_string(),
            high_risk_slack_webhook_url: String::new(),
            high_risk_slack_timeout_ms: 1_000,
            high_risk_slack_alert_on_cached_reports: false,
            report_refresh_days: 30,
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

    fn aml_result(account_id: &str, risk_level: AmlRiskLevel) -> AmlCheckResult {
        AmlCheckResult {
            provider: PROVIDER_LUKKA.to_string(),
            account_id: account_id.to_string(),
            address_type: NEAR_ADDRESS_TYPE.to_string(),
            risk_level,
            score: Some(1),
            report_id: Some("report".to_string()),
            checked_at: Utc::now(),
            reason: None,
        }
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

        let service = LukkaAmlService::new(test_config(server.uri()));
        let result = service.check_near_account("gregoshes.near").await;

        assert_eq!(result.account_id, "gregoshes.near");
        assert_eq!(result.address_type, "NEAR");
        assert_eq!(result.risk_level, AmlRiskLevel::High);
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
            ("LOW", AmlRiskLevel::Low),
            ("MEDIUM", AmlRiskLevel::Medium),
            ("HIGH", AmlRiskLevel::High),
        ] {
            let body = LukkaAmlScoreResponse {
                report_info_section: None,
                cscore_section: Some(LukkaCscoreSection {
                    cscore: Some(7),
                    risk_level: Some(provider_value.to_string()),
                }),
            };
            assert_eq!(
                AmlRiskLevel::from_provider(
                    body.cscore_section
                        .as_ref()
                        .and_then(|section| section.risk_level.as_deref())
                ),
                Some(expected)
            );
        }
    }

    #[test]
    fn incomplete_success_response_is_provider_failure() {
        let result = normalize_lukka_response(
            "alice.near",
            LukkaAmlScoreResponse {
                report_info_section: None,
                cscore_section: None,
            },
        );

        assert_eq!(result.risk_level, AmlRiskLevel::Unknown);
        assert_eq!(result.reason.as_deref(), Some("provider_invalid_response"));
        assert!(result.is_provider_failure());
    }

    #[test]
    fn unsupported_provider_risk_level_is_provider_failure() {
        let result = normalize_lukka_response(
            "alice.near",
            LukkaAmlScoreResponse {
                report_info_section: None,
                cscore_section: Some(LukkaCscoreSection {
                    cscore: Some(7),
                    risk_level: Some("unexpected".to_string()),
                }),
            },
        );

        assert_eq!(result.risk_level, AmlRiskLevel::Unknown);
        assert_eq!(result.reason.as_deref(), Some("provider_invalid_response"));
        assert!(result.is_provider_failure());
        assert_eq!(result.score, Some(7));
    }

    #[test]
    fn provider_failure_detection_only_matches_unknown_provider_reasons() {
        assert!(AmlCheckResult::unknown("alice.near", "provider_timeout").is_provider_failure());
        assert!(AmlCheckResult::unknown("alice.near", "provider_http_503").is_provider_failure());
        assert!(!AmlCheckResult::unknown("alice.near", "disabled").is_provider_failure());
        assert!(!aml_result("alice.near", AmlRiskLevel::High).is_provider_failure());
    }

    #[test]
    fn provider_failure_alerts_are_throttled() {
        let service = LukkaAmlService::new(test_config("http://127.0.0.1:1".to_string()));
        let user_id = crate::UserId::new();
        let result = AmlCheckResult::unknown("alice.near", "provider_timeout");

        assert!(service.should_send_provider_failure_alert(user_id, "user_status", &result));
        assert!(!service.should_send_provider_failure_alert(user_id, "user_status", &result));
        assert!(service.should_send_provider_failure_alert(user_id, "change_plan", &result));
    }

    #[tokio::test]
    async fn provider_error_returns_unknown_without_crashing() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;

        let service = LukkaAmlService::new(test_config(server.uri()));
        let result = service.check_near_account("alice.near").await;

        assert_eq!(result.risk_level, AmlRiskLevel::Unknown);
        assert_eq!(result.reason.as_deref(), Some("provider_http_503"));
    }

    #[tokio::test]
    async fn provider_error_is_negative_cached() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;

        let service = LukkaAmlService::new(test_config(server.uri()));
        let first = service.check_near_account("alice.near").await;
        let second = service.check_near_account("alice.near").await;

        assert!(first.is_provider_failure());
        assert_eq!(second, first);
    }

    #[tokio::test]
    async fn store_cache_evicts_expired_entries() {
        let mut cfg = test_config("http://127.0.0.1:1".to_string());
        cfg.cache_ttl_secs = 1;
        let service = LukkaAmlService::new(cfg);

        service.cache.write().await.insert(
            "expired.near".to_string(),
            CachedAmlResult {
                result: aml_result("expired.near", AmlRiskLevel::Low),
                cached_at: Instant::now() - Duration::from_secs(2),
            },
        );

        service
            .store_cache("fresh.near", aml_result("fresh.near", AmlRiskLevel::Low))
            .await;

        let cache = service.cache.read().await;
        assert!(!cache.contains_key("expired.near"));
        assert!(cache.contains_key("fresh.near"));
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

        let service = LukkaAmlService::new(test_config(server.uri()));
        let first = service.check_near_account("gregoshes.near").await;
        let second = service.check_near_account("gregoshes.near").await;

        assert_eq!(first.risk_level, AmlRiskLevel::High);
        assert_eq!(second.risk_level, AmlRiskLevel::High);
    }

    #[tokio::test]
    async fn disabled_service_returns_unknown() {
        let mut cfg = test_config("http://127.0.0.1:1".to_string());
        cfg.enabled = false;
        let service = LukkaAmlService::new(cfg);

        let result = service.check_near_account("alice.near").await;

        assert_eq!(result.risk_level, AmlRiskLevel::Unknown);
        assert_eq!(result.reason.as_deref(), Some("disabled"));
    }
}
