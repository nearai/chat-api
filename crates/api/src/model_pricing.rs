//! In-memory cache for model pricing from cloud-api (GET /v1/model/{model_name}).
//! Used to compute cost in nano-dollars from token usage for rate limiting and analytics.

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::debug;

/// TTL for cached model pricing (5 minutes).
pub const MODEL_PRICING_CACHE_TTL_SECS: i64 = 300;

/// Pricing for a model: cost per token in nano-dollars (1e-9 USD).
#[derive(Debug, Clone)]
pub struct ModelPricing {
    /// Input tokens: nano-dollars per token.
    pub input_nano_per_token: i64,
    /// Output tokens: nano-dollars per token.
    pub output_nano_per_token: i64,
}

impl ModelPricing {
    /// Compute total cost in nano-dollars from input and output token counts.
    /// Uses i128 for intermediate math to avoid overflow; panics if result exceeds i64 range.
    pub fn cost_nano_usd(&self, input_tokens: u64, output_tokens: u64) -> i64 {
        let input_cost = (input_tokens as i128) * (self.input_nano_per_token as i128);
        let output_cost = (output_tokens as i128) * (self.output_nano_per_token as i128);
        let total = input_cost + output_cost;
        total
            .try_into()
            .expect("cost_nano_usd overflow: result exceeds i64 range")
    }
}

/// Raw response from cloud-api GET /v1/model/{model_name}.
/// Supports common field names; add #[serde(alias = "...")] if the API uses different names.
#[derive(Debug, serde::Deserialize)]
struct ModelPricingResponse {
    #[serde(alias = "input_cost_nano_per_token", alias = "input_nano_per_token")]
    pub input_nano_per_token: i64,
    #[serde(alias = "output_cost_nano_per_token", alias = "output_nano_per_token")]
    pub output_nano_per_token: i64,
}

/// Cache entry with fetched-at time for TTL.
#[derive(Clone)]
struct CacheEntry {
    pricing: ModelPricing,
    fetched_at: DateTime<Utc>,
}

/// Thread-safe in-memory cache for model pricing with TTL.
/// Fetches from cloud-api GET /v1/model/{model_name} (unauthenticated) on miss or expiry.
#[derive(Clone)]
pub struct ModelPricingCache {
    base_url: String,
    http_client: reqwest::Client,
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    ttl_secs: i64,
}

impl ModelPricingCache {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
            cache: Arc::new(RwLock::new(HashMap::new())),
            ttl_secs: MODEL_PRICING_CACHE_TTL_SECS,
        }
    }

    /// Returns pricing for the model if available (from cache or after fetching).
    /// Returns None if base_url is empty, fetch fails, or response is invalid.
    pub async fn get_pricing(&self, model_name: &str) -> Option<ModelPricing> {
        if model_name.is_empty() || self.base_url.is_empty() {
            return None;
        }

        let now = Utc::now();
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(model_name) {
                let age = now.signed_duration_since(entry.fetched_at);
                if age.num_seconds() >= 0 && age.num_seconds() < self.ttl_secs {
                    debug!(
                        "Model pricing cache hit: model_name={}",
                        if model_name.len() > 32 {
                            format!("{}...", &model_name[..32])
                        } else {
                            model_name.to_string()
                        }
                    );
                    return Some(entry.pricing.clone());
                }
            }
        }

        let url = format!(
            "{}/v1/model/{}",
            self.base_url,
            urlencoding::encode(model_name)
        );
        let resp = match self.http_client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Failed to fetch model pricing from {}: {}", url, e);
                return None;
            }
        };

        if !resp.status().is_success() {
            tracing::debug!(
                "Model pricing API returned {} for model_name={}",
                resp.status(),
                if model_name.len() > 32 {
                    format!("{}...", &model_name[..32])
                } else {
                    model_name.to_string()
                }
            );
            return None;
        }

        let body = match resp.json::<ModelPricingResponse>().await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(
                    "Failed to parse model pricing response for model_name={}: {}",
                    if model_name.len() > 32 {
                        format!("{}...", &model_name[..32])
                    } else {
                        model_name.to_string()
                    },
                    e
                );
                return None;
            }
        };

        let pricing = ModelPricing {
            input_nano_per_token: body.input_nano_per_token,
            output_nano_per_token: body.output_nano_per_token,
        };

        {
            let mut cache = self.cache.write().await;
            cache.insert(
                model_name.to_string(),
                CacheEntry {
                    pricing: pricing.clone(),
                    fetched_at: now,
                },
            );
        }

        Some(pricing)
    }
}
