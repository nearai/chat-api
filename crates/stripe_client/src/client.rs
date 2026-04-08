use crate::error::StripeClientError;
use crate::types::{
    StripeBillingPortalSessionResponse, StripeCheckoutLineItem, StripeCheckoutLineItems,
    StripeCheckoutSession, StripeCheckoutSessionResponse, StripeCreateCustomerResponse,
    StripeCustomerRef, StripeErrorResponse, StripePortalSession, StripeRetrieveCustomerResponse,
    StripeSubscriptionResponse, StripeSubscriptionSnapshot,
};
use chrono::DateTime;
use reqwest::header::AUTHORIZATION;
use serde_json::Value;
use std::time::Duration;

const STRIPE_API_BASE: &str = "https://api.stripe.com";

#[derive(Clone)]
pub struct StripeClient {
    http: reqwest::Client,
    secret_key: String,
}

pub struct CreateCustomerParams<'a> {
    pub email: Option<&'a str>,
    pub name: Option<&'a str>,
    pub user_id: &'a str,
    pub test_clock_id: Option<&'a str>,
}

pub struct CreateSubscriptionCheckoutParams<'a> {
    pub customer_id: &'a str,
    pub price_id: &'a str,
    pub success_url: &'a str,
    pub cancel_url: &'a str,
    pub trial_period_days: Option<u32>,
    pub idempotency_key: &'a str,
}

pub struct CreateCreditsCheckoutParams<'a> {
    pub customer_id: &'a str,
    pub price_id: &'a str,
    pub credits: u64,
    pub success_url: &'a str,
    pub cancel_url: &'a str,
    pub user_id: &'a str,
    pub idempotency_key: &'a str,
}

pub struct UpdateSubscriptionParams<'a> {
    pub cancel_at_period_end: Option<bool>,
    pub item_id: Option<&'a str>,
    pub price_id: Option<&'a str>,
    pub proration_behavior: Option<&'static str>,
    pub payment_behavior: Option<&'static str>,
    pub billing_cycle_anchor: Option<&'static str>,
}

impl StripeClient {
    pub fn new(secret_key: String) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("valid reqwest client config"),
            secret_key,
        }
    }

    pub async fn create_customer(
        &self,
        params: CreateCustomerParams<'_>,
    ) -> Result<String, StripeClientError> {
        let mut form = vec![("metadata[user_id]", params.user_id.to_string())];
        if let Some(email) = params.email {
            form.push(("email", email.to_string()));
        }
        if let Some(name) = params.name {
            form.push(("name", name.to_string()));
        }
        if let Some(test_clock_id) = params.test_clock_id {
            form.push(("test_clock", test_clock_id.to_string()));
        }

        let response: StripeCreateCustomerResponse =
            self.post_form("/v1/customers", &form, None).await?;
        Ok(response.id)
    }

    pub async fn retrieve_customer(
        &self,
        customer_id: &str,
    ) -> Result<StripeCustomerRef, StripeClientError> {
        let response: StripeRetrieveCustomerResponse = self
            .get_json(&format!("/v1/customers/{customer_id}"), &[])
            .await?;
        Ok(StripeCustomerRef {
            id: response.id,
            metadata: response.metadata,
        })
    }

    pub async fn create_subscription_checkout_session(
        &self,
        params: CreateSubscriptionCheckoutParams<'_>,
    ) -> Result<StripeCheckoutSession, StripeClientError> {
        let mut form = vec![
            ("mode", "subscription".to_string()),
            ("customer", params.customer_id.to_string()),
            ("success_url", params.success_url.to_string()),
            ("cancel_url", params.cancel_url.to_string()),
            ("line_items[0][price]", params.price_id.to_string()),
            ("line_items[0][quantity]", "1".to_string()),
        ];
        if let Some(days) = params.trial_period_days {
            form.push(("subscription_data[trial_period_days]", days.to_string()));
        }

        self.create_checkout_session(&form, params.idempotency_key)
            .await
    }

    pub async fn create_credits_checkout_session(
        &self,
        params: CreateCreditsCheckoutParams<'_>,
    ) -> Result<StripeCheckoutSession, StripeClientError> {
        let credits_str = params.credits.to_string();
        let form = vec![
            ("mode", "payment".to_string()),
            ("customer", params.customer_id.to_string()),
            ("success_url", params.success_url.to_string()),
            ("cancel_url", params.cancel_url.to_string()),
            ("line_items[0][price]", params.price_id.to_string()),
            ("line_items[0][quantity]", credits_str.clone()),
            ("metadata[user_id]", params.user_id.to_string()),
            ("metadata[credits]", credits_str.clone()),
            ("invoice_creation[enabled]", "true".to_string()),
            (
                "invoice_creation[invoice_data][metadata][user_id]",
                params.user_id.to_string(),
            ),
            (
                "invoice_creation[invoice_data][metadata][credits]",
                credits_str,
            ),
        ];

        self.create_checkout_session(&form, params.idempotency_key)
            .await
    }

    pub async fn retrieve_checkout_session(
        &self,
        checkout_session_id: &str,
    ) -> Result<StripeCheckoutSession, StripeClientError> {
        let response: StripeCheckoutSessionResponse = self
            .get_json(
                &format!("/v1/checkout/sessions/{checkout_session_id}"),
                &[("expand[]", "line_items")],
            )
            .await?;
        map_checkout_session(response)
    }

    pub async fn retrieve_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<StripeSubscriptionSnapshot, StripeClientError> {
        let response: StripeSubscriptionResponse = self
            .get_json(&format!("/v1/subscriptions/{subscription_id}"), &[])
            .await?;
        map_subscription(response)
    }

    pub async fn update_subscription(
        &self,
        subscription_id: &str,
        params: UpdateSubscriptionParams<'_>,
    ) -> Result<StripeSubscriptionSnapshot, StripeClientError> {
        let mut form = Vec::new();
        if let Some(cancel_at_period_end) = params.cancel_at_period_end {
            form.push((
                "cancel_at_period_end",
                if cancel_at_period_end {
                    "true"
                } else {
                    "false"
                }
                .to_string(),
            ));
        }
        if let Some(item_id) = params.item_id {
            form.push(("items[0][id]", item_id.to_string()));
        }
        if let Some(price_id) = params.price_id {
            form.push(("items[0][price]", price_id.to_string()));
        }
        if let Some(proration_behavior) = params.proration_behavior {
            form.push(("proration_behavior", proration_behavior.to_string()));
        }
        if let Some(payment_behavior) = params.payment_behavior {
            form.push(("payment_behavior", payment_behavior.to_string()));
        }
        if let Some(billing_cycle_anchor) = params.billing_cycle_anchor {
            form.push(("billing_cycle_anchor", billing_cycle_anchor.to_string()));
        }

        let response: StripeSubscriptionResponse = self
            .post_form(&format!("/v1/subscriptions/{subscription_id}"), &form, None)
            .await?;
        map_subscription(response)
    }

    pub async fn create_billing_portal_session(
        &self,
        customer_id: &str,
        return_url: &str,
    ) -> Result<StripePortalSession, StripeClientError> {
        let form = vec![
            ("customer", customer_id.to_string()),
            ("return_url", return_url.to_string()),
        ];
        let response: StripeBillingPortalSessionResponse = self
            .post_form("/v1/billing_portal/sessions", &form, None)
            .await?;
        Ok(StripePortalSession {
            id: response.id,
            url: response.url,
        })
    }

    async fn create_checkout_session(
        &self,
        form: &[(impl AsRef<str>, String)],
        idempotency_key: &str,
    ) -> Result<StripeCheckoutSession, StripeClientError> {
        let owned_form: Vec<(&str, String)> =
            form.iter().map(|(k, v)| (k.as_ref(), v.clone())).collect();
        let response: StripeCheckoutSessionResponse = self
            .post_form("/v1/checkout/sessions", &owned_form, Some(idempotency_key))
            .await?;
        map_checkout_session(response)
    }

    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<T, StripeClientError> {
        let request = self
            .http
            .get(format!("{STRIPE_API_BASE}{path}"))
            .header(AUTHORIZATION, format!("Bearer {}", self.secret_key))
            .query(query);
        let response = request.send().await?;
        decode_response(response).await
    }

    async fn post_form<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        form: &[(&str, String)],
        idempotency_key: Option<&str>,
    ) -> Result<T, StripeClientError> {
        let mut request = self
            .http
            .post(format!("{STRIPE_API_BASE}{path}"))
            .header(AUTHORIZATION, format!("Bearer {}", self.secret_key))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(encode_form(form));
        if let Some(idempotency_key) = idempotency_key {
            request = request.header("Idempotency-Key", idempotency_key);
        }
        let response = request.send().await?;
        decode_response(response).await
    }
}

fn encode_form(form: &[(&str, String)]) -> String {
    form.iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                urlencoding::encode(k),
                urlencoding::encode(v.as_str())
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

async fn decode_response<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, StripeClientError> {
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        let message = serde_json::from_str::<StripeErrorResponse>(&body)
            .ok()
            .and_then(|err| err.error.message)
            .unwrap_or(body);
        return Err(StripeClientError::Http { status, message });
    }
    match serde_json::from_str(&body) {
        Ok(parsed) => Ok(parsed),
        Err(err) => {
            log_response_shape(&body);
            Err(StripeClientError::ResponseParse(err))
        }
    }
}

fn log_response_shape(body: &str) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        tracing::error!("Failed to parse Stripe response body as JSON for shape logging");
        return;
    };

    let top_level_keys = value
        .as_object()
        .map(|obj| obj.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let item_keys = value
        .get("items")
        .and_then(|items| items.get("data"))
        .and_then(|data| data.as_array())
        .and_then(|data| data.first())
        .and_then(|item| item.as_object())
        .map(|obj| obj.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let has_current_period_end = value.get("current_period_end").is_some();
    let item_has_current_period_end = value
        .get("items")
        .and_then(|items| items.get("data"))
        .and_then(|data| data.as_array())
        .and_then(|data| data.first())
        .and_then(|item| item.get("current_period_end"))
        .is_some();

    tracing::error!(
        top_level_keys = ?top_level_keys,
        item_keys = ?item_keys,
        has_current_period_end,
        item_has_current_period_end,
        "Stripe response shape did not match expected schema"
    );
}

fn map_checkout_session(
    response: StripeCheckoutSessionResponse,
) -> Result<StripeCheckoutSession, StripeClientError> {
    let line_items = response
        .line_items
        .map(
            |line_items| -> Result<StripeCheckoutLineItems, StripeClientError> {
                let data = line_items
                    .data
                    .into_iter()
                    .map(|item| {
                        let price_id =
                            item.price
                                .map(|p| p.id)
                                .ok_or(StripeClientError::InvalidResponse(
                                    "missing checkout session line item price",
                                ))?;
                        let quantity = item.quantity.ok_or(StripeClientError::InvalidResponse(
                            "missing checkout session line item quantity",
                        ))?;

                        Ok(StripeCheckoutLineItem { price_id, quantity })
                    })
                    .collect::<Result<Vec<_>, StripeClientError>>()?;

                Ok(StripeCheckoutLineItems {
                    has_more: line_items.has_more,
                    data,
                })
            },
        )
        .transpose()?;

    Ok(StripeCheckoutSession {
        id: response.id,
        url: response.url,
        line_items,
    })
}

fn map_subscription(
    response: StripeSubscriptionResponse,
) -> Result<StripeSubscriptionSnapshot, StripeClientError> {
    let first_item = response
        .items
        .data
        .first()
        .ok_or(StripeClientError::InvalidResponse(
            "missing subscription item",
        ))?;
    let price_id = first_item
        .price
        .as_ref()
        .map(|price| price.id.clone())
        .ok_or(StripeClientError::InvalidResponse(
            "missing subscription price",
        ))?;
    let first_item_id = first_item.id.clone();
    let customer_id = match response.customer {
        Value::String(id) => id,
        Value::Object(map) => map
            .get("id")
            .and_then(|v| v.as_str())
            .map(ToString::to_string)
            .ok_or(StripeClientError::InvalidResponse("missing customer id"))?,
        _ => return Err(StripeClientError::InvalidResponse("invalid customer value")),
    };
    let current_period_end_ts = response
        .current_period_end
        .or(first_item.current_period_end)
        .ok_or(StripeClientError::InvalidResponse(
            "missing current_period_end on subscription and first item",
        ))?;
    let current_period_end = DateTime::from_timestamp(current_period_end_ts, 0).ok_or(
        StripeClientError::InvalidResponse("invalid current_period_end"),
    )?;

    Ok(StripeSubscriptionSnapshot {
        id: response.id,
        customer_id,
        price_id,
        status: response.status,
        current_period_end,
        cancel_at_period_end: response.cancel_at_period_end,
        first_item_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        StripeCheckoutSessionResponse, StripeLineItemResponse, StripeLineItemsResponse,
    };

    #[test]
    fn map_checkout_session_rejects_missing_line_item_price() {
        let response = StripeCheckoutSessionResponse {
            id: "cs_test".to_string(),
            url: Some("https://example.com".to_string()),
            line_items: Some(StripeLineItemsResponse {
                has_more: false,
                data: vec![StripeLineItemResponse {
                    price: None,
                    quantity: Some(1),
                }],
            }),
        };

        let err = map_checkout_session(response).unwrap_err();
        assert!(matches!(
            err,
            StripeClientError::InvalidResponse("missing checkout session line item price")
        ));
    }

    #[test]
    fn map_checkout_session_rejects_missing_line_item_quantity() {
        let response = StripeCheckoutSessionResponse {
            id: "cs_test".to_string(),
            url: Some("https://example.com".to_string()),
            line_items: Some(StripeLineItemsResponse {
                has_more: false,
                data: vec![StripeLineItemResponse {
                    price: Some(crate::types::StripePriceRef {
                        id: "price_test".to_string(),
                    }),
                    quantity: None,
                }],
            }),
        };

        let err = map_checkout_session(response).unwrap_err();
        assert!(matches!(
            err,
            StripeClientError::InvalidResponse("missing checkout session line item quantity")
        ));
    }
}
