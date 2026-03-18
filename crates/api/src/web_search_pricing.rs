//! In-memory cache for web_search pricing from cloud-api (GET /v1/services/web_search).
//! Used to compute cost in nano-dollars for web_search usage recording.

use chrono::{DateTime, Utc};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::debug;

/// TTL for cached web_search pricing (5 minutes).
pub const WEB_SEARCH_PRICING_CACHE_TTL_SECS: i64 = 300;

/// Cached cost per request in nano-USD.
#[derive(Debug, Clone)]
pub struct WebSearchPricing {
    pub cost_per_unit: i64,
}

/// Typed response from cloud-api GET /v1/services/{service_name}.
/// Matches AdminServiceResponse schema (camelCase).
#[derive(Debug, serde::Deserialize)]
struct ServicePricingResponse {
    #[serde(rename = "costPerUnit")]
    cost_per_unit: i64,
}

/// Cache entry with fetched-at time for TTL.
#[derive(Clone)]
struct CacheEntry {
    pricing: WebSearchPricing,
    fetched_at: DateTime<Utc>,
}

/// Thread-safe in-memory cache for web_search pricing with TTL.
/// Fetches from cloud-api GET /v1/services/web_search (unauthenticated) on miss or expiry.
#[derive(Clone)]
pub struct WebSearchPricingCache {
    base_url: String,
    http_client: reqwest::Client,
    cache: Arc<RwLock<Option<CacheEntry>>>,
    ttl_secs: i64,
}

impl WebSearchPricingCache {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
            cache: Arc::new(RwLock::new(None)),
            ttl_secs: WEB_SEARCH_PRICING_CACHE_TTL_SECS,
        }
    }

    /// Returns cost_per_unit (nano-USD) for web_search if available.
    /// Returns 0 if base_url is empty, fetch fails, or response is invalid.
    pub async fn get_cost_per_unit(&self) -> i64 {
        if self.base_url.is_empty() {
            return 0;
        }

        let now = Utc::now();
        {
            let cache = self.cache.read().await;
            if let Some(ref entry) = *cache {
                let age = now.signed_duration_since(entry.fetched_at);
                if age.num_seconds() >= 0 && age.num_seconds() < self.ttl_secs {
                    debug!("Web search pricing cache hit");
                    return entry.pricing.cost_per_unit;
                }
            }
        }

        let url = crate::cloud_api::web_search_service_url(&self.base_url);
        let resp = match self.http_client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Failed to fetch web_search pricing from {}: {}", url, e);
                return 0;
            }
        };

        if !resp.status().is_success() {
            tracing::warn!(
                "Web search pricing API returned {} for {}",
                resp.status(),
                url
            );
            return 0;
        }

        let body = match resp.json::<ServicePricingResponse>().await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("Failed to parse web_search pricing response: {}", e);
                return 0;
            }
        };

        let cost_per_unit = body.cost_per_unit.max(0);
        let pricing = WebSearchPricing { cost_per_unit };

        {
            let mut cache = self.cache.write().await;
            *cache = Some(CacheEntry {
                pricing: pricing.clone(),
                fetched_at: now,
            });
        }

        pricing.cost_per_unit
    }
}
