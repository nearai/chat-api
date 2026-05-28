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

/// Pricing for a model: cost per token and per image in nano-dollars (1e-9 USD).
#[derive(Debug, Clone)]
pub struct ModelPricing {
    /// Input tokens: nano-dollars per token.
    pub input_nano_per_token: i64,
    /// Output tokens: nano-dollars per token.
    pub output_nano_per_token: i64,
    /// Cached input tokens: nano-dollars per token. 0 means cache pricing is disabled.
    pub cache_read_nano_per_token: i64,
    /// Image (generation/edit): nano-dollars per image.
    pub nano_per_image: i64,
}

impl ModelPricing {
    /// Compute input cost in nano-dollars, applying cache-read pricing when configured.
    /// Uses i128 for intermediate math to avoid overflow; panics if result exceeds i64 range.
    pub fn input_cost_nano_usd(&self, input_tokens: u64, cache_read_tokens: u64) -> i64 {
        let cache_read = cache_read_tokens.min(input_tokens);
        let non_cached_input = input_tokens - cache_read;
        let cache_rate = if self.cache_read_nano_per_token == 0 {
            self.input_nano_per_token
        } else {
            self.cache_read_nano_per_token
        };
        let input_cost = (non_cached_input as i128) * (self.input_nano_per_token as i128)
            + (cache_read as i128) * (cache_rate as i128);
        input_cost
            .try_into()
            .expect("input_cost_nano_usd overflow: result exceeds i64 range")
    }

    /// Compute output cost in nano-dollars.
    /// Uses i128 for intermediate math to avoid overflow; panics if result exceeds i64 range.
    pub fn output_cost_nano_usd(&self, output_tokens: u64) -> i64 {
        let output_cost = (output_tokens as i128) * (self.output_nano_per_token as i128);
        output_cost
            .try_into()
            .expect("output_cost_nano_usd overflow: result exceeds i64 range")
    }

    /// Compute total cost in nano-dollars from input and output token counts.
    /// Uses i128 for intermediate math to avoid overflow; panics if result exceeds i64 range.
    pub fn cost_nano_usd(
        &self,
        input_tokens: u64,
        output_tokens: u64,
        cache_read_tokens: u64,
    ) -> i64 {
        let input_cost = self.input_cost_nano_usd(input_tokens, cache_read_tokens) as i128;
        let output_cost = self.output_cost_nano_usd(output_tokens) as i128;
        let total = input_cost + output_cost;
        total
            .try_into()
            .expect("cost_nano_usd overflow: result exceeds i64 range")
    }

    /// Compute cost in nano-dollars for image operations (generation/edit).
    /// Uses i128 for intermediate math to avoid overflow; panics if result exceeds i64 range.
    pub fn cost_nano_usd_for_images(&self, image_count: u32) -> i64 {
        let total = (image_count as i128) * (self.nano_per_image as i128);
        total
            .try_into()
            .expect("cost_nano_usd_for_images overflow: result exceeds i64 range")
    }
}

/// Price with amount/scale/currency from cloud-api (e.g. scale 9 = nano-USD).
#[derive(Debug, serde::Deserialize)]
struct DecimalPrice {
    amount: i64,
    scale: i32,
    currency: String,
}

/// Raw response from cloud-api GET /model/{model_name}.
/// Matches the current cloud-api schema (camelCase).
///
/// Example:
/// {
///   "modelId": "...",
///   "inputCostPerToken": { "amount": 150, "scale": 9, "currency": "USD" },
///   "outputCostPerToken": { "amount": 550, "scale": 9, "currency": "USD" },
///   "costPerImage": { "amount": 40000000, "scale": 9, "currency": "USD" },
///   "cacheReadCostPerToken": { "amount": 15, "scale": 9, "currency": "USD" },
///   ...
/// }
#[derive(Debug, serde::Deserialize)]
struct ModelPricingResponse {
    #[serde(rename = "inputCostPerToken")]
    input_cost_per_token: DecimalPrice,
    #[serde(rename = "outputCostPerToken")]
    output_cost_per_token: DecimalPrice,
    #[serde(rename = "costPerImage")]
    cost_per_image: DecimalPrice,
    #[serde(rename = "cacheReadCostPerToken")]
    cache_read_cost_per_token: Option<DecimalPrice>,
}

fn is_usd_nano_price(price: &DecimalPrice) -> bool {
    price.currency == "USD" && price.scale == 9
}

fn cache_read_nano_per_token(model_name: &str, price: Option<&DecimalPrice>) -> i64 {
    let Some(price) = price else {
        return 0;
    };

    if is_usd_nano_price(price) {
        price.amount
    } else {
        tracing::warn!(
            "Ignoring unsupported cache read pricing for model_name={}: currency={}, scale={}",
            model_name,
            price.currency,
            price.scale,
        );
        0
    }
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
            "{}/model/{}",
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
            tracing::warn!(
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

        // Current cloud-api returns cost with scale=9 (nano-USD). We intentionally keep
        // the logic simple: only accept scale=9 and treat `amount` as nano-dollars.
        if !is_usd_nano_price(&body.input_cost_per_token)
            || !is_usd_nano_price(&body.output_cost_per_token)
            || !is_usd_nano_price(&body.cost_per_image)
        {
            tracing::warn!(
                "Unsupported pricing scale for model_name={}: input_scale={}, output_scale={}, cost_per_image_scale={}",
                model_name,
                body.input_cost_per_token.scale,
                body.output_cost_per_token.scale,
                body.cost_per_image.scale,
            );
            return None;
        }
        let cache_read_nano_per_token =
            cache_read_nano_per_token(model_name, body.cache_read_cost_per_token.as_ref());

        let pricing = ModelPricing {
            input_nano_per_token: body.input_cost_per_token.amount,
            output_nano_per_token: body.output_cost_per_token.amount,
            cache_read_nano_per_token,
            nano_per_image: body.cost_per_image.amount,
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

#[cfg(test)]
mod tests {
    use super::{cache_read_nano_per_token, DecimalPrice, ModelPricing};

    #[test]
    fn cost_uses_cache_read_rate_when_configured() {
        let pricing = ModelPricing {
            input_nano_per_token: 10,
            output_nano_per_token: 20,
            cache_read_nano_per_token: 2,
            nano_per_image: 0,
        };

        assert_eq!(pricing.input_cost_nano_usd(100, 40), 680);
        assert_eq!(pricing.output_cost_nano_usd(5), 100);
        assert_eq!(pricing.cost_nano_usd(100, 5, 40), 780);
    }

    #[test]
    fn zero_cache_read_rate_disables_discount() {
        let pricing = ModelPricing {
            input_nano_per_token: 10,
            output_nano_per_token: 20,
            cache_read_nano_per_token: 0,
            nano_per_image: 0,
        };

        assert_eq!(pricing.input_cost_nano_usd(100, 40), 1_000);
        assert_eq!(pricing.cost_nano_usd(100, 5, 40), 1_100);
    }

    #[test]
    fn cache_read_tokens_are_capped_to_input_tokens() {
        let pricing = ModelPricing {
            input_nano_per_token: 10,
            output_nano_per_token: 20,
            cache_read_nano_per_token: 2,
            nano_per_image: 0,
        };

        assert_eq!(pricing.input_cost_nano_usd(100, 150), 200);
    }

    #[test]
    fn invalid_cache_read_price_falls_back_to_normal_input_pricing() {
        let invalid_cache_price = DecimalPrice {
            amount: 2,
            scale: 6,
            currency: "USD".to_string(),
        };

        assert_eq!(
            cache_read_nano_per_token("test-model", Some(&invalid_cache_price)),
            0
        );
    }

    #[test]
    fn valid_cache_read_price_is_used() {
        let cache_price = DecimalPrice {
            amount: 2,
            scale: 9,
            currency: "USD".to_string(),
        };

        assert_eq!(
            cache_read_nano_per_token("test-model", Some(&cache_price)),
            2
        );
    }
}
