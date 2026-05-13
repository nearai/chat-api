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

const NEAR_VIEW_RPC_TIMEOUT_MSG: &str = "NEAR RPC view call timed out";

/// Fetch `get_subscription_for_price(account_id, price_id)` (returns JSON `null` when absent).
pub async fn view_get_subscription_for_price(
    rpc_url: &str,
    contract_id: &str,
    account_id: &str,
    anchor_price_id: &str,
) -> Result<Option<Value>, String> {
    timeout(NEAR_VIEW_RPC_TIMEOUT, async {
        let url = rpc_url
            .parse()
            .map_err(|e: url::ParseError| e.to_string())?;
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
            .await
            .map_err(|e| e.to_string())?;

        Ok::<Option<Value>, String>(data.data)
    })
    .await
    .map_err(|_| NEAR_VIEW_RPC_TIMEOUT_MSG.to_string())?
}

/// Fetch `get_price(price_id)` for catalog comparisons (upgrade vs downgrade).
pub async fn view_get_price(
    rpc_url: &str,
    contract_id: &str,
    price_id: &str,
) -> Result<Option<Value>, String> {
    timeout(NEAR_VIEW_RPC_TIMEOUT, async {
        let url = rpc_url
            .parse()
            .map_err(|e: url::ParseError| e.to_string())?;
        let network = NetworkConfig::from_rpc_url("configured", url);
        let cid: AccountId = contract_id
            .parse()
            .map_err(|e| format!("invalid staking contract account id: {e}"))?;

        let data: Data<Option<Value>> = Contract(cid)
            .call_function("get_price", json!({ "price_id": price_id }))
            .read_only()
            .fetch_from(&network)
            .await
            .map_err(|e| e.to_string())?;

        Ok::<Option<Value>, String>(data.data)
    })
    .await
    .map_err(|_| NEAR_VIEW_RPC_TIMEOUT_MSG.to_string())?
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
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
}
