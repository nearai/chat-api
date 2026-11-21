use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreviewMethod {
    UnusedSecondsFloor,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefundPreviewRequest {
    pub user_id: Uuid,
    pub effective_at: DateTime<Utc>,
    pub method: PreviewMethod,
    pub starting_after: Option<String>,
}

pub struct RefundInvoice {
    pub invoice_id: String,
    pub currency: String,
    pub amount_paid: i64,
    pub amount_refunded: Option<i64>,
    pub charge_id: Option<String>,
    pub period_start: Option<i64>,
    pub period_end: Option<i64>,
    pub review_reason: Option<String>,
}

pub struct RefundInvoicePage {
    pub invoices: Vec<RefundInvoice>,
    pub has_more: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreviewStatus {
    Estimate,
    NoUnusedTime,
    ManualReview,
}

#[derive(Debug, Serialize)]
pub struct RefundPreviewRow {
    pub invoice_id: String,
    pub charge_id: Option<String>,
    pub currency: String,
    /// All monetary values use the currency's smallest unit, never floating point.
    pub amount_paid: i64,
    pub amount_refunded: Option<i64>,
    pub period_start: Option<i64>,
    pub period_end: Option<i64>,
    pub estimated_refund: Option<i64>,
    pub status: PreviewStatus,
    pub review_reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RefundPreview {
    pub preview_only: bool,
    pub subscription_id: String,
    pub effective_at: DateTime<Utc>,
    pub method: PreviewMethod,
    pub rows: Vec<RefundPreviewRow>,
    pub next_cursor: Option<String>,
}

pub fn build_preview(
    subscription_id: &str,
    request: &RefundPreviewRequest,
    page: RefundInvoicePage,
) -> RefundPreview {
    let next_cursor = if page.has_more {
        page.invoices.last().map(|i| i.invoice_id.clone())
    } else {
        None
    };
    let rows = page
        .invoices
        .into_iter()
        .map(|invoice| {
            let mut reason = invoice.review_reason;
            let amount = match (invoice.period_start, invoice.period_end) {
                (Some(start), Some(end))
                    if end > start && invoice.amount_paid > 0 && reason.is_none() =>
                {
                    let duration = i128::from(end) - i128::from(start);
                    let unused = (i128::from(end) - i128::from(request.effective_at.timestamp()))
                        .clamp(0, duration);
                    Some((i128::from(invoice.amount_paid) * unused / duration) as i64)
                }
                _ => {
                    reason.get_or_insert_with(|| {
                        "Missing or invalid paid amount or service period".into()
                    });
                    None
                }
            };
            let status = match amount {
                Some(_)
                    if request.effective_at.timestamp()
                        >= invoice.period_end.unwrap_or(i64::MAX) =>
                {
                    PreviewStatus::NoUnusedTime
                }
                Some(_) => PreviewStatus::Estimate,
                None => PreviewStatus::ManualReview,
            };
            RefundPreviewRow {
                invoice_id: invoice.invoice_id,
                charge_id: invoice.charge_id,
                currency: invoice.currency,
                amount_paid: invoice.amount_paid,
                amount_refunded: invoice.amount_refunded,
                period_start: invoice.period_start,
                period_end: invoice.period_end,
                estimated_refund: amount,
                status,
                review_reason: reason,
            }
        })
        .collect();
    RefundPreview {
        preview_only: true,
        subscription_id: subscription_id.into(),
        effective_at: request.effective_at,
        method: request.method,
        rows,
        next_cursor,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preview(
        cutoff: i64,
        amount: i64,
        start: i64,
        end: i64,
        reason: Option<&str>,
    ) -> RefundPreview {
        build_preview(
            "sub_test",
            &RefundPreviewRequest {
                user_id: Uuid::nil(),
                effective_at: DateTime::from_timestamp(cutoff, 0).unwrap(),
                method: PreviewMethod::UnusedSecondsFloor,
                starting_after: None,
            },
            RefundInvoicePage {
                has_more: true,
                invoices: vec![RefundInvoice {
                    invoice_id: "in_test".into(),
                    charge_id: Some("ch_test".into()),
                    currency: "jpy".into(),
                    amount_paid: amount,
                    amount_refunded: Some(0),
                    period_start: Some(start),
                    period_end: Some(end),
                    review_reason: reason.map(String::from),
                }],
            },
        )
    }

    #[test]
    fn refund_preview_bounds_and_rounding() {
        for (cutoff, expected) in [
            (0, 1001),
            (100, 1001),
            (150, 500),
            (199, 10),
            (200, 0),
            (300, 0),
        ] {
            let result = preview(cutoff, 1001, 100, 200, None);
            assert_eq!(result.rows[0].estimated_refund, Some(expected));
            assert_eq!(result.next_cursor.as_deref(), Some("in_test"));
            assert!(result.preview_only);
        }
    }

    #[test]
    fn refund_preview_does_not_guess_for_exceptions() {
        assert_eq!(
            preview(150, 1000, 100, 200, Some("Prior refund")).rows[0].estimated_refund,
            None
        );
        assert_eq!(
            preview(150, 1000, 200, 100, None).rows[0].estimated_refund,
            None
        );
        assert_eq!(
            preview(150, 0, 100, 200, None).rows[0].estimated_refund,
            None
        );
        assert_eq!(
            preview(150, i64::MAX, 100, 200, None).rows[0].estimated_refund,
            Some(i64::MAX / 2)
        );
    }

    #[test]
    fn refund_preview_requires_explicit_supported_method() {
        let request =
            serde_json::json!({"user_id": Uuid::nil(), "effective_at": "2026-11-13T00:00:00Z"});
        assert!(serde_json::from_value::<RefundPreviewRequest>(request.clone()).is_err());
        let mut unknown = request;
        unknown["method"] = "automatic".into();
        assert!(serde_json::from_value::<RefundPreviewRequest>(unknown).is_err());
    }
}
