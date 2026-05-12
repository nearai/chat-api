//! JSON-RPC view calls to the stake.dao staking contract (`NEAR_STAKING_CONTRACT_ID`).

use crate::subscription::ports::{DowngradeIntentStatus, Subscription};
use crate::UserId;
use chrono::{DateTime, Utc};
use near_api::{AccountId, Contract, Data, NetworkConfig};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::time::timeout;

/// Upper bound for NEAR JSON-RPC view calls so API handlers do not block indefinitely.
const NEAR_VIEW_RPC_TIMEOUT: Duration = Duration::from_secs(15);

fn view_timeout_err() -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "NEAR RPC view call timed out",
    ))
}

/// Fetch `get_subscription_for_price(account_id, price_id)` (returns JSON `null` when absent).
pub async fn view_get_subscription_for_price(
    rpc_url: &str,
    contract_id: &str,
    account_id: &str,
    anchor_price_id: &str,
) -> Result<Option<Value>, Box<dyn std::error::Error + Send + Sync>> {
    timeout(NEAR_VIEW_RPC_TIMEOUT, async {
        let url = rpc_url.parse()?;
        let network = NetworkConfig::from_rpc_url("configured", url);
        let cid: AccountId = contract_id
            .parse()
            .map_err(|e| format!("invalid staking contract account id: {e}"))?;

        let data: Data<Option<Value>> = Contract(cid)
            .call_function(
                "get_subscription_for_price",
                json!({
                    "account_id": account_id,
                    "price_id": anchor_price_id,
                }),
            )
            .read_only()
            .fetch_from(&network)
            .await?;

        Ok::<Option<Value>, Box<dyn std::error::Error + Send + Sync>>(data.data)
    })
    .await
    .map_err(|_| view_timeout_err())?
}

/// Fetch `get_price(price_id)` for catalog comparisons (upgrade vs downgrade).
pub async fn view_get_price(
    rpc_url: &str,
    contract_id: &str,
    price_id: &str,
) -> Result<Option<Value>, Box<dyn std::error::Error + Send + Sync>> {
    timeout(NEAR_VIEW_RPC_TIMEOUT, async {
        let url = rpc_url.parse()?;
        let network = NetworkConfig::from_rpc_url("configured", url);
        let cid: AccountId = contract_id
            .parse()
            .map_err(|e| format!("invalid staking contract account id: {e}"))?;

        let data: Data<Option<Value>> = Contract(cid)
            .call_function("get_price", json!({ "price_id": price_id }))
            .read_only()
            .fetch_from(&network)
            .await?;

        Ok::<Option<Value>, Box<dyn std::error::Error + Send + Sync>>(data.data)
    })
    .await
    .map_err(|_| view_timeout_err())?
}

/// Parse catalog `amount` field (`U128` JSON) as yoctoNEAR integer.
pub fn price_amount_yocto_json(price: &Value) -> Option<u128> {
    let a = price.get("amount")?;
    let s = match a {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => return None,
    };
    s.parse().ok()
}

/// Map stake.dao `Subscription` JSON into our DB [`Subscription`] row (`provider = house-of-stake`).
pub fn subscription_row_from_chain_json(
    user_id: UserId,
    near_account: &str,
    v: &Value,
) -> Result<Subscription, String> {
    let subscription_id = v
        .get("subscription_id")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "missing subscription_id".to_string())?
        .to_string();
    let price_id = v
        .get("price_id")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "missing price_id".to_string())?
        .to_string();

    let end_ns = json_u64(
        v.get("end_ns")
            .ok_or_else(|| "missing end_ns".to_string())?,
    )?;
    let current_period_end = ts_ns_to_datetime(end_ns)?;

    let status_raw = v.get("status").and_then(|x| x.as_str()).unwrap_or("Active");
    let status_lower = status_raw.to_ascii_lowercase();
    let status = match status_lower.as_str() {
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

    let cancel_at_period_end = v
        .get("cancel_at_period_end")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);

    let pending_down = v.get("pending_downgrade_price_id").and_then(|x| {
        if x.is_null() {
            None
        } else {
            x.as_str().map(|s| s.to_string())
        }
    });

    let (pd_target, pd_from, pd_end, pd_status) = if let Some(ref tgt) = pending_down {
        (
            Some(tgt.clone()),
            Some(price_id.clone()),
            Some(current_period_end),
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

fn json_u64(v: &Value) -> Result<u64, String> {
    match v {
        Value::String(s) => s
            .parse::<u64>()
            .map_err(|e: std::num::ParseIntError| e.to_string()),
        Value::Number(n) => n.as_u64().ok_or_else(|| "expected u64".to_string()),
        _ => Err("bad json for u64".to_string()),
    }
}

fn ts_ns_to_datetime(ns: u64) -> Result<DateTime<Utc>, String> {
    let secs = (ns / 1_000_000_000) as i64;
    let nsec = (ns % 1_000_000_000) as u32;
    DateTime::from_timestamp(secs, nsec).ok_or_else(|| "timestamp out of range".to_string())
}
