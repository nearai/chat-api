use crate::{error::ApiError, state::AppState};
use axum::{
    extract::State,
    http::{header, HeaderName, StatusCode},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;
use utoipa::ToSchema;

#[derive(Clone, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentHostingSunset {
    cutoff_at: DateTime<Utc>,
    export_deadline_at: DateTime<Utc>,
    shutdown_at: DateTime<Utc>,
    export_url: String,
    support_url: String,
    // Auth is shared by the whole Chat API deployment. Only enable this where
    // stopping creation of Chat API accounts is part of the rollout.
    close_signups: bool,
}

impl AgentHostingSunset {
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let value = match std::env::var("AGENT_HOSTING_SUNSET") {
            Ok(value) if !value.trim().is_empty() => value,
            Ok(_) | Err(std::env::VarError::NotPresent) => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        Self::parse(&value).map(Some)
    }

    fn parse(value: &str) -> anyhow::Result<Self> {
        let sunset: Self = serde_json::from_str(value)?;
        anyhow::ensure!(
            sunset.cutoff_at < sunset.export_deadline_at
                && sunset.export_deadline_at <= sunset.shutdown_at,
            "Expected cutoff < export deadline <= shutdown"
        );
        for link in [&sunset.export_url, &sunset.support_url] {
            let url = Url::parse(link)?;
            anyhow::ensure!(
                url.scheme() == "https"
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none(),
                "Agent Hosting sunset links must be HTTPS URLs without credentials"
            );
        }
        Ok(sunset)
    }

    pub fn signup_cutoff(&self) -> Option<DateTime<Utc>> {
        self.close_signups.then_some(self.cutoff_at)
    }

    fn is_closed_at(&self, now: DateTime<Utc>) -> bool {
        now >= self.cutoff_at
    }
}

#[derive(Serialize, ToSchema)]
pub struct AgentHostingSunsetResponse {
    schedule: Option<AgentHostingSunset>,
    server_time: DateTime<Utc>,
}

/// Schedule and server time for the Agent Hosting transition.
#[utoipa::path(
    get,
    path = "/v1/agent-hosting/sunset",
    tag = "Agents",
    responses((status = 200, description = "Agent Hosting sunset status", body = AgentHostingSunsetResponse))
)]
pub async fn get_sunset(
    State(state): State<AppState>,
) -> (
    [(HeaderName, &'static str); 1],
    Json<AgentHostingSunsetResponse>,
) {
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(AgentHostingSunsetResponse {
            schedule: state.agent_hosting_sunset,
            server_time: Utc::now(),
        }),
    )
}

pub fn require_new_activity_allowed(state: &AppState) -> Result<(), ApiError> {
    if state
        .agent_hosting_sunset
        .as_ref()
        .is_some_and(|sunset| sunset.is_closed_at(Utc::now()))
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "agent_hosting_closed",
            "Agent Hosting no longer accepts new deployments, subscriptions or credit purchases.",
        ));
    }
    Ok(())
}

pub fn signups_closed_error() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "agent_hosting_signups_closed",
        "Agent Hosting is closed to new signups. Existing users can still sign in.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"{
        "cutoff_at":"2030-01-01T10:00:00+08:00",
        "export_deadline_at":"2030-01-10T02:00:00Z",
        "shutdown_at":"2030-01-10T02:00:00Z",
        "export_url":"https://example.com/export",
        "support_url":"https://example.com/support",
        "close_signups":true
    }"#;

    #[test]
    fn cutoff_is_inclusive_and_respects_offset() {
        let sunset = AgentHostingSunset::parse(CONFIG).unwrap();
        assert!(!sunset.is_closed_at("2030-01-01T01:59:59Z".parse().unwrap()));
        assert!(sunset.is_closed_at("2030-01-01T02:00:00Z".parse().unwrap()));
    }

    #[test]
    fn invalid_timeline_or_link_is_rejected() {
        assert!(AgentHostingSunset::parse(&CONFIG.replace("2030-01-10", "2029-01-10")).is_err());
        assert!(AgentHostingSunset::parse(&CONFIG.replace("https://", "http://")).is_err());
    }
}
