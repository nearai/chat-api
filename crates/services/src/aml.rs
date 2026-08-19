use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use uuid::Uuid;

pub const DEFAULT_AML_HIGH_RISK_SCORE_THRESHOLD: i64 = 75;
const PROVIDER_LUKKA: &str = "lukka";
const NEAR_ADDRESS_TYPE: &str = "NEAR";
const AML_SLACK_SOURCE_APP: &str = "chat-api";
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

    fn as_str(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Unknown => "UNKNOWN",
        }
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

    pub fn is_high_risk_at_score_threshold(&self, threshold: i64) -> bool {
        self.score.is_some_and(|score| score >= threshold)
    }

    pub fn is_high_risk_by_policy(
        &self,
        risk_levels: &[AmlRiskLevel],
        score_threshold: Option<i64>,
    ) -> bool {
        (self.risk_level != AmlRiskLevel::Unknown && risk_levels.contains(&self.risk_level))
            || score_threshold
                .is_some_and(|threshold| self.is_high_risk_at_score_threshold(threshold))
    }

    pub fn is_high_risk(&self) -> bool {
        self.is_high_risk_by_policy(
            &[AmlRiskLevel::High],
            Some(DEFAULT_AML_HIGH_RISK_SCORE_THRESHOLD),
        )
    }

    pub fn is_provider_failure(&self) -> bool {
        self.risk_level == AmlRiskLevel::Unknown
            && self
                .reason
                .as_deref()
                .is_some_and(|reason| reason.starts_with("provider_"))
    }
}

fn high_risk_aml_slack_payload(
    user_id: crate::UserId,
    flow: &str,
    result: &AmlCheckResult,
    high_risk_risk_levels: &[AmlRiskLevel],
    high_risk_score_threshold: Option<i64>,
) -> serde_json::Value {
    let risk_levels = high_risk_risk_levels
        .iter()
        .map(|level| level.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let risk_levels = if risk_levels.is_empty() {
        "disabled".to_string()
    } else {
        risk_levels
    };
    let threshold = high_risk_score_threshold
        .map(|threshold| threshold.to_string())
        .unwrap_or_else(|| "disabled".to_string());
    let score = result
        .score
        .map(|score| score.to_string())
        .unwrap_or_else(|| "n/a".to_string());
    serde_json::json!({
        "text": format!(
            "High-risk AML detection: source_app={} account={} user_id={} flow={} provider={} address_type={} risk_level={:?} score={} high_risk_risk_levels={} high_risk_score_threshold={} report_id={} reason={} checked_at={}",
            AML_SLACK_SOURCE_APP,
            result.account_id,
            user_id,
            flow,
            result.provider,
            result.address_type,
            result.risk_level,
            score,
            risk_levels,
            threshold,
            result.report_id.as_deref().unwrap_or("n/a"),
            result.reason.as_deref().unwrap_or("n/a"),
            result.checked_at.to_rfc3339()
        ),
    })
}

fn send_high_risk_aml_slack_alert(
    http_client: reqwest::Client,
    webhook_url: &str,
    user_id: crate::UserId,
    flow: &str,
    result: &AmlCheckResult,
    high_risk_risk_levels: &[AmlRiskLevel],
    high_risk_score_threshold: Option<i64>,
) {
    let webhook_url = webhook_url.trim();
    if webhook_url.is_empty() {
        return;
    }

    let webhook_url = webhook_url.to_string();
    let flow = flow.to_string();
    let payload = high_risk_aml_slack_payload(
        user_id,
        &flow,
        result,
        high_risk_risk_levels,
        high_risk_score_threshold,
    );

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

fn aml_provider_failure_slack_payload(
    user_id: crate::UserId,
    flow: &str,
    result: &AmlCheckResult,
) -> serde_json::Value {
    let score = result
        .score
        .map(|score| score.to_string())
        .unwrap_or_else(|| "n/a".to_string());
    serde_json::json!({
        "text": format!(
            "AML provider failure: source_app={} account={} user_id={} flow={} provider={} address_type={} risk_level={:?} score={} report_id={} reason={} checked_at={} action=fail_open",
            AML_SLACK_SOURCE_APP,
            result.account_id,
            user_id,
            flow,
            result.provider,
            result.address_type,
            result.risk_level,
            score,
            result.report_id.as_deref().unwrap_or("n/a"),
            result.reason.as_deref().unwrap_or("unknown"),
            result.checked_at.to_rfc3339()
        ),
    })
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
    let flow = flow.to_string();
    let payload = aml_provider_failure_slack_payload(user_id, &flow, result);

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
    fn high_risk_risk_levels(&self) -> Vec<AmlRiskLevel> {
        vec![AmlRiskLevel::High]
    }
    fn high_risk_score_threshold(&self) -> Option<i64> {
        Some(DEFAULT_AML_HIGH_RISK_SCORE_THRESHOLD)
    }
    fn is_high_risk_result(&self, result: &AmlCheckResult) -> bool {
        result.is_high_risk_by_policy(
            &self.high_risk_risk_levels(),
            self.high_risk_score_threshold(),
        )
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
    #[serde(default, deserialize_with = "optional_i64_from_json")]
    cscore: Option<i64>,
    risk_level: Option<String>,
}

fn optional_i64_from_json<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(None);
    };
    if let Some(number) = value.as_i64() {
        return Ok(Some(number));
    }
    if let Some(number) = value.as_f64() {
        if number.is_finite() && number >= i64::MIN as f64 && number <= i64::MAX as f64 {
            return Ok(Some(number.round() as i64));
        }
    }
    Ok(value
        .as_str()
        .and_then(|value| value.trim().parse::<i64>().ok()))
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
                            let result = normalize_lukka_response(
                                account_id,
                                body,
                                self.config.high_risk_risk_levels.is_empty()
                                    && self.config.high_risk_score_threshold.is_some(),
                            );
                            tracing::debug!(
                                elapsed_ms = started.elapsed().as_millis() as u64,
                                "Lukka AML check completed"
                            );
                            if self.is_high_risk_result(&result) {
                                tracing::warn!(
                                    report_id = ?result.report_id,
                                    score = ?result.score,
                                    high_risk_risk_levels = ?self.config.high_risk_risk_levels,
                                    high_risk_score_threshold = self.config.high_risk_score_threshold,
                                    "Lukka AML high-risk policy matched for NEAR account"
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

fn normalize_lukka_response(
    account_id: &str,
    body: LukkaAmlScoreResponse,
    require_score: bool,
) -> AmlCheckResult {
    let report = body.report_info_section;
    let cscore = body.cscore_section;
    let score = cscore.as_ref().and_then(|section| section.cscore);

    if cscore.is_none() {
        return unknown_lukka_response(account_id, report, cscore, "provider_invalid_response");
    }

    if require_score && score.is_none() {
        return unknown_lukka_response(account_id, report, cscore, "provider_missing_score");
    }

    let provider_risk_level = cscore
        .as_ref()
        .and_then(|section| section.risk_level.as_deref());
    let risk_level =
        AmlRiskLevel::from_provider(provider_risk_level).unwrap_or(AmlRiskLevel::Unknown);
    let reason = if risk_level == AmlRiskLevel::Unknown {
        Some(
            provider_risk_level
                .map(|value| format!("unrecognized_risk_level:{}", value.trim()))
                .unwrap_or_else(|| "missing_risk_level".to_string()),
        )
    } else {
        None
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
        score,
        report_id: report.and_then(|r| r.report_id),
        checked_at,
        reason,
    }
}

fn unknown_lukka_response(
    account_id: &str,
    report: Option<LukkaReportInfoSection>,
    cscore: Option<LukkaCscoreSection>,
    reason: &str,
) -> AmlCheckResult {
    let mut result = AmlCheckResult::unknown(account_id, reason);
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
    result.score = cscore.and_then(|section| section.cscore);
    result
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

    fn high_risk_risk_levels(&self) -> Vec<AmlRiskLevel> {
        self.config
            .high_risk_risk_levels
            .iter()
            .filter_map(|level| AmlRiskLevel::from_provider(Some(level)))
            .collect()
    }

    fn high_risk_score_threshold(&self) -> Option<i64> {
        self.config.high_risk_score_threshold
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
            &self.high_risk_risk_levels(),
            self.config.high_risk_score_threshold,
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
            high_risk_risk_levels: vec!["HIGH".to_string()],
            high_risk_score_threshold: Some(75),
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

    fn aml_result_with_score(
        account_id: &str,
        risk_level: AmlRiskLevel,
        score: Option<i64>,
    ) -> AmlCheckResult {
        AmlCheckResult {
            score,
            ..aml_result(account_id, risk_level)
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
    fn high_risk_policy_supports_risk_level_score_and_combined_predicates() {
        assert!(
            aml_result_with_score("risk-level.near", AmlRiskLevel::High, None)
                .is_high_risk_by_policy(&[AmlRiskLevel::High], None)
        );
        assert!(
            aml_result_with_score("alice.near", AmlRiskLevel::Low, Some(75))
                .is_high_risk_by_policy(&[], Some(75))
        );
        assert!(
            !aml_result_with_score("bob.near", AmlRiskLevel::High, Some(74))
                .is_high_risk_by_policy(&[], Some(75))
        );
        assert!(
            aml_result_with_score("carol.near", AmlRiskLevel::Medium, Some(80))
                .is_high_risk_by_policy(&[AmlRiskLevel::High], Some(75))
        );
    }

    #[test]
    fn incomplete_success_response_is_provider_failure() {
        let result = normalize_lukka_response(
            "alice.near",
            LukkaAmlScoreResponse {
                report_info_section: None,
                cscore_section: None,
            },
            true,
        );

        assert_eq!(result.risk_level, AmlRiskLevel::Unknown);
        assert_eq!(result.reason.as_deref(), Some("provider_invalid_response"));
        assert!(result.is_provider_failure());
    }

    #[test]
    fn missing_score_is_provider_failure_when_score_threshold_is_only_policy() {
        let result = normalize_lukka_response(
            "alice.near",
            LukkaAmlScoreResponse {
                report_info_section: None,
                cscore_section: Some(LukkaCscoreSection {
                    cscore: None,
                    risk_level: Some("HIGH".to_string()),
                }),
            },
            true,
        );

        assert_eq!(result.risk_level, AmlRiskLevel::Unknown);
        assert_eq!(result.reason.as_deref(), Some("provider_missing_score"));
        assert!(result.is_provider_failure());
        assert!(!result.is_high_risk_at_score_threshold(75));
    }

    #[test]
    fn missing_score_keeps_risk_level_when_risk_level_policy_is_present() {
        let result = normalize_lukka_response(
            "alice.near",
            LukkaAmlScoreResponse {
                report_info_section: None,
                cscore_section: Some(LukkaCscoreSection {
                    cscore: None,
                    risk_level: Some("HIGH".to_string()),
                }),
            },
            false,
        );

        assert_eq!(result.risk_level, AmlRiskLevel::High);
        assert_eq!(result.score, None);
        assert_eq!(result.reason, None);
        assert!(result.is_high_risk_by_policy(&[AmlRiskLevel::High], None));
    }

    #[tokio::test]
    async fn malformed_score_returns_provider_failure() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v3/reports/aml/score/alice.near"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "report_info_section": {
                    "address": "alice.near",
                    "address_type": "NEAR"
                },
                "cscore_section": {
                    "cscore": "not-a-number",
                    "risk_level": "HIGH"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut cfg = test_config(server.uri());
        cfg.high_risk_risk_levels.clear();
        let service = LukkaAmlService::new(cfg);
        let result = service.check_near_account("alice.near").await;

        assert_eq!(result.risk_level, AmlRiskLevel::Unknown);
        assert_eq!(result.reason.as_deref(), Some("provider_missing_score"));
        assert!(result.is_provider_failure());
        assert!(!result.is_high_risk_at_score_threshold(75));
    }

    #[tokio::test]
    async fn malformed_score_keeps_risk_level_when_risk_level_policy_is_present() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v3/reports/aml/score/alice.near"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "report_info_section": {
                    "address": "alice.near",
                    "address_type": "NEAR"
                },
                "cscore_section": {
                    "cscore": "not-a-number",
                    "risk_level": "HIGH"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut cfg = test_config(server.uri());
        cfg.high_risk_score_threshold = None;
        let service = LukkaAmlService::new(cfg);
        let result = service.check_near_account("alice.near").await;

        assert_eq!(result.risk_level, AmlRiskLevel::High);
        assert_eq!(result.score, None);
        assert!(!result.is_provider_failure());
        assert!(service.is_high_risk_result(&result));
    }

    #[test]
    fn unsupported_provider_risk_level_is_audit_metadata_not_high_risk_predicate() {
        let result = normalize_lukka_response(
            "alice.near",
            LukkaAmlScoreResponse {
                report_info_section: None,
                cscore_section: Some(LukkaCscoreSection {
                    cscore: Some(7),
                    risk_level: Some("unexpected".to_string()),
                }),
            },
            true,
        );

        assert_eq!(result.risk_level, AmlRiskLevel::Unknown);
        assert_eq!(
            result.reason.as_deref(),
            Some("unrecognized_risk_level:unexpected")
        );
        assert!(!result.is_provider_failure());
        assert_eq!(result.score, Some(7));
    }

    #[test]
    fn high_risk_slack_payload_includes_score_threshold_decision_context() {
        let user_id = crate::UserId::new();
        let result = aml_result_with_score("alice.near", AmlRiskLevel::Low, Some(91));

        let payload = high_risk_aml_slack_payload(
            user_id,
            "user_status",
            &result,
            &[AmlRiskLevel::High],
            Some(75),
        );
        let text = payload["text"].as_str().expect("slack text");

        assert!(text.contains("source_app=chat-api"));
        assert!(text.contains("risk_level=Low"));
        assert!(text.contains("score=91"));
        assert!(text.contains("high_risk_risk_levels=HIGH"));
        assert!(text.contains("high_risk_score_threshold=75"));
        assert!(!text.contains("test-token"));
    }

    #[test]
    fn provider_failure_slack_payload_includes_source_app() {
        let user_id = crate::UserId::new();
        let result = AmlCheckResult::unknown("alice.near", "provider_timeout");

        let payload = aml_provider_failure_slack_payload(user_id, "user_status", &result);
        let text = payload["text"].as_str().expect("slack text");

        assert!(text.contains("source_app=chat-api"));
        assert!(text.contains("reason=provider_timeout"));
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
