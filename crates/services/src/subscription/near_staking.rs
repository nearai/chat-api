//! JSON-RPC view calls to the stake.dao staking contract (`NEAR_STAKING_CONTRACT_ID`).

use crate::subscription::ports::{DowngradeIntentStatus, Subscription};
use crate::UserId;
use chrono::{DateTime, Utc};
use near_api::{AccountId, Contract, Data, NetworkConfig};
use serde::de::{DeserializeOwned, Error as _};
use serde::{Deserialize, Deserializer, Serialize};
use std::time::Duration;
use tokio::time::timeout;

/// Upper bound for NEAR JSON-RPC view calls so API handlers do not block indefinitely.
const NEAR_VIEW_RPC_TIMEOUT: Duration = Duration::from_secs(15);

const NEAR_VIEW_RPC_TIMEOUT_MSG: &str = "NEAR RPC view call timed out";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct YoctoNear(u128);

impl YoctoNear {
    pub fn as_u128(self) -> u128 {
        self.0
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum IntegerStringOrNumber {
    String(String),
    Number(u64),
}

fn parse_u128_value<'de, D>(value: IntegerStringOrNumber) -> Result<u128, D::Error>
where
    D: Deserializer<'de>,
{
    match value {
        IntegerStringOrNumber::String(s) => s.parse::<u128>().map_err(D::Error::custom),
        IntegerStringOrNumber::Number(n) => Ok(u128::from(n)),
    }
}

fn deserialize_required_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let value = IntegerStringOrNumber::deserialize(deserializer)?;
    parse_u128_value::<D>(value).and_then(|n| {
        u64::try_from(n).map_err(|_| D::Error::custom("expected u64-compatible integer"))
    })
}

fn deserialize_optional_u64<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(value) = Option::<IntegerStringOrNumber>::deserialize(deserializer)? else {
        return Ok(None);
    };
    parse_u128_value::<D>(value).and_then(|n| {
        u64::try_from(n)
            .map(Some)
            .map_err(|_| D::Error::custom("expected u64-compatible integer"))
    })
}

fn deserialize_required_yocto_near<'de, D>(deserializer: D) -> Result<YoctoNear, D::Error>
where
    D: Deserializer<'de>,
{
    let value = IntegerStringOrNumber::deserialize(deserializer)?;
    parse_u128_value::<D>(value).map(YoctoNear)
}

fn deserialize_optional_yocto_near<'de, D>(deserializer: D) -> Result<Option<YoctoNear>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(value) = Option::<IntegerStringOrNumber>::deserialize(deserializer)? else {
        return Ok(None);
    };
    parse_u128_value::<D>(value).map(|amount| Some(YoctoNear(amount)))
}

#[derive(Debug, Clone, Serialize)]
struct GetSubscriptionForPriceArgs<'a> {
    account_id: &'a str,
    price_id: &'a str,
}

#[derive(Debug, Clone, Serialize)]
struct GetPriceArgs<'a> {
    price_id: &'a str,
}

#[derive(Debug, Clone, Serialize)]
struct GetPurchaseArgs<'a> {
    purchase_id: &'a str,
}

#[derive(Debug, Clone, Serialize)]
struct GetLockArgs<'a> {
    lock_id: &'a str,
}

#[derive(Debug, Clone, Serialize)]
struct StorageBalanceOfArgs<'a> {
    account_id: &'a str,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NearStakingSubscription {
    pub subscription_id: String,
    pub price_id: String,
    #[serde(deserialize_with = "deserialize_required_u64")]
    pub end_ns: u64,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub cancel_at_period_end: bool,
    #[serde(default)]
    pub pending_update: Option<NearStakingPendingUpdate>,
    #[serde(default)]
    pub pending_downgrade_price_id: Option<String>,
    #[serde(default)]
    pub last_lock_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NearStakingPendingUpdate {
    #[serde(default)]
    pub target_price_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_yocto_near")]
    pub target_amount: Option<YoctoNear>,
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    pub apply_ns: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NearStakingStorageBalance {
    #[serde(deserialize_with = "deserialize_required_yocto_near")]
    pub total: YoctoNear,
    #[serde(deserialize_with = "deserialize_required_yocto_near")]
    pub available: YoctoNear,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NearStakingStorageBalanceBounds {
    #[serde(deserialize_with = "deserialize_required_yocto_near")]
    pub min: YoctoNear,
    #[serde(default, deserialize_with = "deserialize_optional_yocto_near")]
    pub max: Option<YoctoNear>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NearStakingPrice {
    #[serde(default, deserialize_with = "deserialize_optional_yocto_near")]
    pub amount: Option<YoctoNear>,
    #[serde(default)]
    pub product_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub price_type: Option<String>,
}

impl NearStakingPrice {
    pub fn amount_yocto(&self) -> Option<u128> {
        self.amount.map(YoctoNear::as_u128)
    }

    pub fn is_one_off(&self) -> bool {
        matches!(
            self.price_type.as_deref(),
            Some("OneOff") | Some("one_off") | Some("one-off")
        )
    }

    pub fn is_active(&self) -> bool {
        matches!(self.status.as_deref(), Some("Active") | Some("active"))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct NearStakingPurchase {
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub price_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    pub quantity: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_optional_yocto_near")]
    pub amount_paid: Option<YoctoNear>,
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    pub created_ns: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NearStakingLock {
    #[serde(default, deserialize_with = "deserialize_optional_yocto_near")]
    pub amount_near: Option<YoctoNear>,
}

async fn view_call<Args, Response>(
    rpc_url: &str,
    contract_id: &str,
    method_name: &str,
    args: Args,
) -> Result<Option<Response>, String>
where
    Args: Serialize + Send,
    Response: DeserializeOwned + Send + Sync,
{
    timeout(NEAR_VIEW_RPC_TIMEOUT, async {
        let url = rpc_url
            .parse()
            .map_err(|e: url::ParseError| e.to_string())?;
        let network = NetworkConfig::from_rpc_url("configured", url);
        let cid: AccountId = contract_id
            .parse()
            .map_err(|e| format!("invalid staking contract account id: {e}"))?;

        let data: Data<Option<Response>> = Contract(cid)
            .call_function(method_name, args)
            .read_only()
            .fetch_from(&network)
            .await
            .map_err(|e| e.to_string())?;

        Ok::<Option<Response>, String>(data.data)
    })
    .await
    .map_err(|_| NEAR_VIEW_RPC_TIMEOUT_MSG.to_string())?
}

/// Fetch `get_subscription_for_price(account_id, price_id)` (returns `null` when absent).
pub async fn view_get_subscription_for_price(
    rpc_url: &str,
    contract_id: &str,
    account_id: &str,
    anchor_price_id: &str,
) -> Result<Option<NearStakingSubscription>, String> {
    view_call(
        rpc_url,
        contract_id,
        "get_subscription_for_price",
        GetSubscriptionForPriceArgs {
            account_id,
            price_id: anchor_price_id,
        },
    )
    .await
}

/// Fetch `get_price(price_id)` for catalog comparisons (upgrade vs downgrade).
pub async fn view_get_price(
    rpc_url: &str,
    contract_id: &str,
    price_id: &str,
) -> Result<Option<NearStakingPrice>, String> {
    view_call(rpc_url, contract_id, "get_price", GetPriceArgs { price_id }).await
}

/// Fetch `get_purchase(purchase_id)` for direct one-off `pay` verification.
pub async fn view_get_purchase(
    rpc_url: &str,
    contract_id: &str,
    purchase_id: &str,
) -> Result<Option<NearStakingPurchase>, String> {
    view_call(
        rpc_url,
        contract_id,
        "get_purchase",
        GetPurchaseArgs { purchase_id },
    )
    .await
}

/// Fetch NEP-145 `storage_balance_of(account_id)` for wallet preflight.
pub async fn view_storage_balance_of(
    rpc_url: &str,
    contract_id: &str,
    account_id: &str,
) -> Result<Option<NearStakingStorageBalance>, String> {
    view_call(
        rpc_url,
        contract_id,
        "storage_balance_of",
        StorageBalanceOfArgs { account_id },
    )
    .await
}

/// Fetch NEP-145 `storage_balance_bounds()` for wallet preflight.
pub async fn view_storage_balance_bounds(
    rpc_url: &str,
    contract_id: &str,
) -> Result<Option<NearStakingStorageBalanceBounds>, String> {
    view_call(
        rpc_url,
        contract_id,
        "storage_balance_bounds",
        serde_json::json!({}),
    )
    .await
}

/// Fetch `get_lock(lock_id)` for current HoS subscription stake amount comparisons.
pub async fn view_get_lock(
    rpc_url: &str,
    contract_id: &str,
    lock_id: &str,
) -> Result<Option<NearStakingLock>, String> {
    view_call(rpc_url, contract_id, "get_lock", GetLockArgs { lock_id }).await
}

/// Parse lock `amount_near` field as yoctoNEAR integer.
pub fn lock_amount_yocto(lock: &NearStakingLock) -> Option<u128> {
    lock.amount_near.map(YoctoNear::as_u128)
}

/// Map stake.dao `Subscription` into our DB [`Subscription`] row (`provider = house-of-stake`).
pub fn subscription_row_from_chain(
    user_id: UserId,
    near_account: &str,
    chain: &NearStakingSubscription,
) -> Result<Subscription, String> {
    let subscription_id = chain.subscription_id.clone();
    let price_id = chain.price_id.clone();
    let current_period_end = ts_ns_to_datetime(chain.end_ns)?;

    let status_raw = chain.status.as_deref().unwrap_or("Active");
    let status_lower = status_raw.to_ascii_lowercase();
    let mut status = match status_lower.as_str() {
        "active" => "active".to_string(),
        "cancelled" | "canceled" | "expired" => "canceled".to_string(),
        _ => {
            if status_lower.contains("active") {
                "active".to_string()
            } else {
                "canceled".to_string()
            }
        }
    };

    let cancel_at_period_end = chain.cancel_at_period_end;
    if status == "active" && current_period_end <= Utc::now() {
        status = "canceled".to_string();
    }

    let pending_down = pending_downgrade_price_id(chain);
    let has_stake_only_pending_update = chain
        .pending_update
        .as_ref()
        .and_then(|pending| pending.target_amount)
        .is_some();
    let pending_apply_at = chain
        .pending_update
        .as_ref()
        .and_then(|pending| pending.apply_ns)
        .map(ts_ns_to_datetime)
        .transpose()?;

    let (pd_target, pd_from, pd_end, pd_status) = if let Some(ref tgt) = pending_down {
        (
            Some(tgt.clone()),
            Some(price_id.clone()),
            Some(pending_apply_at.unwrap_or(current_period_end)),
            Some(DowngradeIntentStatus::Pending),
        )
    } else if has_stake_only_pending_update {
        (
            None,
            Some(price_id.clone()),
            Some(pending_apply_at.unwrap_or(current_period_end)),
            Some(DowngradeIntentStatus::Pending),
        )
    } else {
        (None, None, None, None)
    };

    Ok(Subscription {
        subscription_id,
        user_id,
        provider: "house-of-stake".to_string(),
        customer_id: format!("near:{near_account}"),
        price_id,
        status,
        current_period_end,
        cancel_at_period_end,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        pending_downgrade_target_price_id: pd_target,
        pending_downgrade_from_price_id: pd_from,
        pending_downgrade_expected_period_end: pd_end,
        pending_downgrade_status: pd_status,
        pending_downgrade_updated_at: pd_status.map(|_| Utc::now()),
    })
}

fn pending_downgrade_price_id(chain: &NearStakingSubscription) -> Option<String> {
    chain
        .pending_update
        .as_ref()
        .and_then(|pending| pending.target_price_id.clone())
        .or_else(|| chain.pending_downgrade_price_id.clone())
}

fn ts_ns_to_datetime(ns: u64) -> Result<DateTime<Utc>, String> {
    let secs = (ns / 1_000_000_000) as i64;
    let nsec = (ns % 1_000_000_000) as u32;
    DateTime::from_timestamp(secs, nsec).ok_or_else(|| "timestamp out of range".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use uuid::Uuid;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn call_function_query_response(result_json: &Value) -> Value {
        let payload = serde_json::to_vec(result_json).expect("serialize contract return");
        let encoded: Vec<Value> = payload.iter().map(|b| json!(b)).collect();
        json!({
            "jsonrpc": "2.0",
            "id": "0",
            "result": {
                "block_hash": "11111111111111111111111111111111",
                "block_height": 12345u64,
                "logs": [],
                "result": encoded
            }
        })
    }

    fn chain_subscription(value: Value) -> NearStakingSubscription {
        serde_json::from_value(value).expect("typed chain subscription")
    }

    #[tokio::test]
    async fn view_get_subscription_for_price_null_from_rpc() {
        for k in [
            "http_proxy",
            "https_proxy",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "all_proxy",
        ] {
            std::env::remove_var(k);
        }
        std::env::set_var("NO_PROXY", "127.0.0.1,localhost");
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(call_function_query_response(&Value::Null)),
            )
            .mount(&mock)
            .await;

        let url = mock.uri();
        let out =
            view_get_subscription_for_price(&url, "staking.testnet", "alice.testnet", "price_fake")
                .await
                .expect("rpc client");
        assert!(out.is_none());
    }

    #[test]
    fn subscription_row_marks_cancel_at_period_end_row_canceled_after_period_end() {
        let past_end_ns = (Utc::now() - chrono::Duration::hours(1))
            .timestamp_nanos_opt()
            .expect("timestamp nanos")
            .to_string();
        let chain = chain_subscription(json!({
            "subscription_id": "sub_hos_expired",
            "price_id": "price_hos_basic",
            "end_ns": past_end_ns,
            "status": "Active",
            "cancel_at_period_end": true
        }));
        let row = subscription_row_from_chain(UserId(Uuid::new_v4()), "alice.testnet", &chain)
            .expect("parse chain subscription");

        assert_eq!(row.status, "canceled");
        assert!(row.cancel_at_period_end);
    }

    #[test]
    fn subscription_row_marks_active_row_canceled_after_period_end() {
        let past_end_ns = (Utc::now() - chrono::Duration::hours(1))
            .timestamp_nanos_opt()
            .expect("timestamp nanos")
            .to_string();
        let chain = chain_subscription(json!({
            "subscription_id": "sub_hos_expired",
            "price_id": "price_hos_basic",
            "end_ns": past_end_ns,
            "status": "Active",
            "cancel_at_period_end": false
        }));
        let row = subscription_row_from_chain(UserId(Uuid::new_v4()), "alice.testnet", &chain)
            .expect("parse chain subscription");

        assert_eq!(row.status, "canceled");
        assert!(!row.cancel_at_period_end);
    }

    #[test]
    fn subscription_row_reads_pending_update_downgrade_price_id() {
        let future_end_ns = (Utc::now() + chrono::Duration::hours(1))
            .timestamp_nanos_opt()
            .expect("timestamp nanos")
            .to_string();
        let chain = chain_subscription(json!({
            "subscription_id": "sub_hos_pending",
            "price_id": "price_hos_pro",
            "end_ns": future_end_ns,
            "status": "Active",
            "pending_update": {
                "target_price_id": "price_hos_basic",
                "target_amount": null,
                "apply_ns": future_end_ns
            }
        }));
        let row = subscription_row_from_chain(UserId(Uuid::new_v4()), "alice.testnet", &chain)
            .expect("parse chain subscription");

        assert_eq!(
            row.pending_downgrade_target_price_id.as_deref(),
            Some("price_hos_basic")
        );
        assert_eq!(
            row.pending_downgrade_from_price_id.as_deref(),
            Some("price_hos_pro")
        );
        assert_eq!(
            row.pending_downgrade_status,
            Some(DowngradeIntentStatus::Pending)
        );
        assert!(row.pending_downgrade_expected_period_end.is_some());
        assert!(row.pending_downgrade_updated_at.is_some());
    }

    #[test]
    fn subscription_row_reads_pending_update_stake_only_apply_ns() {
        let future_end_ns = (Utc::now() + chrono::Duration::hours(2))
            .timestamp_nanos_opt()
            .expect("timestamp nanos");
        let chain = chain_subscription(json!({
            "subscription_id": "sub_hos_pending_stake_only",
            "price_id": "price_hos_pro",
            "end_ns": (future_end_ns + 1_000_000_000).to_string(),
            "status": "Active",
            "pending_update": {
                "target_price_id": null,
                "target_amount": "1000000000000000000000000",
                "apply_ns": future_end_ns.to_string()
            }
        }));
        let row = subscription_row_from_chain(UserId(Uuid::new_v4()), "alice.testnet", &chain)
            .expect("parse chain subscription");

        assert_eq!(row.pending_downgrade_target_price_id, None);
        assert_eq!(
            row.pending_downgrade_from_price_id.as_deref(),
            Some("price_hos_pro")
        );
        assert_eq!(
            row.pending_downgrade_status,
            Some(DowngradeIntentStatus::Pending)
        );
        assert_eq!(
            row.pending_downgrade_expected_period_end,
            Some(
                ts_ns_to_datetime(u64::try_from(future_end_ns).expect("positive apply_ns"))
                    .expect("apply_ns datetime")
            )
        );
    }

    #[test]
    fn subscription_row_reads_legacy_pending_downgrade_price_id() {
        let future_end_ns = (Utc::now() + chrono::Duration::hours(1))
            .timestamp_nanos_opt()
            .expect("timestamp nanos")
            .to_string();
        let chain = chain_subscription(json!({
            "subscription_id": "sub_hos_pending_legacy",
            "price_id": "price_hos_pro",
            "end_ns": future_end_ns,
            "status": "Active",
            "pending_downgrade_price_id": "price_hos_basic"
        }));
        let row = subscription_row_from_chain(UserId(Uuid::new_v4()), "alice.testnet", &chain)
            .expect("parse chain subscription");

        assert_eq!(
            row.pending_downgrade_target_price_id.as_deref(),
            Some("price_hos_basic")
        );
        assert_eq!(
            row.pending_downgrade_status,
            Some(DowngradeIntentStatus::Pending)
        );
    }
}
