use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct StripeCustomerRef {
    pub id: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct StripeSubscriptionSnapshot {
    pub id: String,
    pub customer_id: String,
    pub price_id: String,
    pub status: String,
    pub current_period_end: DateTime<Utc>,
    pub cancel_at_period_end: bool,
    pub first_item_id: String,
}

#[derive(Debug, Clone)]
pub struct StripeCheckoutSession {
    pub id: String,
    pub url: Option<String>,
    pub line_items: Option<StripeCheckoutLineItems>,
}

#[derive(Debug, Clone)]
pub struct StripeCheckoutLineItems {
    pub has_more: bool,
    pub data: Vec<StripeCheckoutLineItem>,
}

#[derive(Debug, Clone)]
pub struct StripeCheckoutLineItem {
    pub price_id: String,
    pub quantity: i64,
}

#[derive(Debug, Clone)]
pub struct StripePortalSession {
    pub id: String,
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct StripeErrorResponse {
    pub error: StripeErrorBody,
}

#[derive(Debug, Deserialize)]
pub(crate) struct StripeErrorBody {
    pub message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct StripeCreateCustomerResponse {
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct StripeRetrieveCustomerResponse {
    pub id: String,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct StripeCheckoutSessionResponse {
    pub id: String,
    pub url: Option<String>,
    pub line_items: Option<StripeLineItemsResponse>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct StripeLineItemsResponse {
    pub has_more: bool,
    #[serde(default)]
    pub data: Vec<StripeLineItemResponse>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct StripeLineItemResponse {
    pub price: Option<StripePriceRef>,
    pub quantity: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct StripePriceRef {
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct StripeSubscriptionResponse {
    pub id: String,
    pub customer: serde_json::Value,
    pub status: String,
    pub current_period_end: Option<i64>,
    pub cancel_at_period_end: bool,
    pub items: StripeSubscriptionItemsResponse,
}

#[derive(Debug, Deserialize)]
pub(crate) struct StripeSubscriptionItemsResponse {
    #[serde(default)]
    pub data: Vec<StripeSubscriptionItemResponse>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct StripeSubscriptionItemResponse {
    pub id: String,
    pub price: Option<StripePriceRef>,
    pub current_period_end: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct StripeBillingPortalSessionResponse {
    pub id: String,
    pub url: String,
}
