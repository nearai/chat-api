//! Read-only billing evidence for sunset refund estimates.
use crate::{StripeClient, StripeClientError};
use serde::Deserialize;
use serde_json::Value;

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

#[derive(Deserialize)]
struct InvoicePage {
    data: Vec<Value>,
    has_more: bool,
}

pub(crate) fn object_id(value: &Value) -> Option<&str> {
    value.as_str().or_else(|| value.get("id")?.as_str())
}

pub(crate) fn safe_id(id: &str, prefix: &str) -> bool {
    id.starts_with(prefix)
        && id.len() > prefix.len()
        && id.len() <= 255
        && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

fn nonempty(value: &Value) -> bool {
    !value.is_null() && value.as_array().is_none_or(|a| !a.is_empty())
}

impl StripeClient {
    pub async fn refund_preview_invoices(
        &self,
        subscription_id: &str,
        customer_id: &str,
        starting_after: Option<&str>,
    ) -> Result<RefundInvoicePage, StripeClientError> {
        if !safe_id(subscription_id, "sub_")
            || !safe_id(customer_id, "cus_")
            || starting_after.is_some_and(|id| !safe_id(id, "in_"))
        {
            return Err(StripeClientError::InvalidResponse(
                "Invalid billing identifier",
            ));
        }
        let mut query = vec![
            ("subscription", subscription_id),
            ("customer", customer_id),
            ("status", "paid"),
            ("limit", "10"),
        ];
        if let Some(cursor) = starting_after {
            query.push(("starting_after", cursor));
        }
        let page: InvoicePage = self.get_json("/v1/invoices", &query).await?;
        if page.data.len() > 10 || (page.has_more && page.data.is_empty()) {
            return Err(StripeClientError::InvalidResponse(
                "Invalid invoice pagination",
            ));
        }
        let mut invoices = Vec::new();
        for mut invoice in page.data {
            let mut row = normalize_invoice(&invoice, subscription_id, customer_id)?;
            if invoice["parent"]["subscription_details"].is_object()
                && invoice.get("payments").is_none_or(Value::is_null)
                && object_id(&invoice["charge"]).is_none()
                && object_id(&invoice["payment_intent"]).is_none()
            {
                invoice["payments"] = self
                    .get_json::<Value>(
                        "/v1/invoice_payments",
                        &[("invoice", &row.invoice_id), ("limit", "2")],
                    )
                    .await?;
            }

            // Read payment evidence even for manual-review invoices when unambiguous,
            // so operators can see existing refunds without inferring them from invoice totals.
            if let Some((kind, id)) = payment_reference(&invoice) {
                let charge = match kind {
                    "charge" if safe_id(&id, "ch_") => Some(
                        self.get_json::<Value>(
                            &format!("/v1/charges/{id}"),
                            &[("expand[]", "refunds")],
                        )
                        .await?,
                    ),
                    "payment_intent" if safe_id(&id, "pi_") => {
                        let payment: Value = self
                            .get_json(
                                &format!("/v1/payment_intents/{id}"),
                                &[("expand[]", "latest_charge.refunds")],
                            )
                            .await?;
                        payment
                            .get("latest_charge")
                            .filter(|c| c.is_object())
                            .cloned()
                    }
                    _ => None,
                };
                if let Some(charge) = charge {
                    apply_charge(&mut row, &charge, customer_id);
                }
            }
            if row.charge_id.is_none() {
                row.review_reason
                    .get_or_insert("Original payment could not be verified".into());
            }
            invoices.push(row);
        }
        Ok(RefundInvoicePage {
            invoices,
            has_more: page.has_more,
        })
    }
}

pub(crate) fn payment_reference(invoice: &Value) -> Option<(&'static str, String)> {
    // Pre-Basil invoices expose the charge/payment intent directly.
    if let Some(charge) = object_id(&invoice["charge"]) {
        return Some(("charge", charge.into()));
    }
    if let Some(pi) = object_id(&invoice["payment_intent"]) {
        return Some(("payment_intent", pi.into()));
    }
    let payments = &invoice["payments"];
    if payments["has_more"] != false {
        return None;
    }
    let data = payments["data"].as_array()?;
    if data.len() != 1 || data[0]["status"] != "paid" {
        return None;
    }
    let payment = &data[0]["payment"];
    match payment["type"].as_str()? {
        "charge" => Some(("charge", object_id(&payment["charge"])?.into())),
        "payment_intent" => Some((
            "payment_intent",
            object_id(&payment["payment_intent"])?.into(),
        )),
        _ => None,
    }
}

fn normalize_invoice(
    invoice: &Value,
    subscription: &str,
    customer: &str,
) -> Result<RefundInvoice, StripeClientError> {
    let id = invoice["id"]
        .as_str()
        .filter(|id| safe_id(id, "in_"))
        .ok_or(StripeClientError::InvalidResponse("Missing invoice ID"))?;
    let invoice_subscription = object_id(&invoice["subscription"])
        .or_else(|| object_id(&invoice["parent"]["subscription_details"]["subscription"]));
    if invoice_subscription != Some(subscription)
        || object_id(&invoice["customer"]) != Some(customer)
    {
        return Err(StripeClientError::InvalidResponse(
            "Invoice does not belong to the requested subscription",
        ));
    }
    let currency = invoice["currency"]
        .as_str()
        .filter(|c| c.len() == 3 && c.bytes().all(|b| b.is_ascii_lowercase()))
        .ok_or(StripeClientError::InvalidResponse(
            "Missing invoice currency",
        ))?;
    let paid = invoice["amount_paid"]
        .as_i64()
        .filter(|a| *a >= 0)
        .ok_or(StripeClientError::InvalidResponse("Invalid paid amount"))?;
    let mut row = RefundInvoice {
        invoice_id: id.into(),
        currency: currency.into(),
        amount_paid: paid,
        amount_refunded: None,
        charge_id: None,
        period_start: None,
        period_end: None,
        review_reason: None,
    };
    let lines = invoice["lines"]["data"].as_array();
    let reason = if invoice["status"] != "paid" || paid == 0 {
        Some("Invoice is not a positive paid invoice")
    } else if invoice["lines"]["has_more"] != false || lines.is_none_or(|l| l.len() != 1) {
        Some("Multiple or incomplete invoice lines require review")
    } else {
        let line = &lines.unwrap()[0];
        row.period_start = line["period"]["start"].as_i64();
        row.period_end = line["period"]["end"].as_i64();
        let details = &line["parent"]["subscription_item_details"];
        let recurring = (line["type"] == "subscription" && line["proration"] == false)
            || (line["parent"]["type"] == "subscription_item_details"
                && details["proration"] == false);
        if !recurring
            || !matches!(
                invoice["billing_reason"].as_str(),
                Some("subscription_cycle" | "subscription_create")
            )
        {
            Some("Subscription changes or non-recurring lines require review")
        } else if [
            "total_discount_amounts",
            "total_tax_amounts",
            "total_taxes",
            "discounts",
        ]
        .iter()
        .any(|key| nonempty(&invoice[key]))
            || [
                "discount_amounts",
                "discounts",
                "tax_amounts",
                "taxes",
                "pretax_credit_amounts",
            ]
            .iter()
            .any(|key| nonempty(&line[key]))
            || invoice["tax"].as_i64().is_some_and(|v| v != 0)
        {
            Some("Tax or discount treatment requires an approved policy")
        } else if invoice["total"].as_i64() != Some(paid)
            || line["amount"].as_i64() != Some(paid)
            || [
                "starting_balance",
                "ending_balance",
                "pre_payment_credit_notes_amount",
                "post_payment_credit_notes_amount",
                "amount_overpaid",
            ]
            .iter()
            .any(|key| invoice[key].as_i64().is_some_and(|v| v != 0))
        {
            Some("Credits, adjustments or partial payments require review")
        } else if row
            .period_start
            .zip(row.period_end)
            .is_none_or(|(start, end)| start < 0 || end <= start || end > 253402300799)
        {
            Some("Missing or invalid service period")
        } else {
            None
        }
    };
    row.review_reason = reason.map(String::from);
    Ok(row)
}

fn apply_charge(row: &mut RefundInvoice, charge: &Value, customer: &str) {
    row.charge_id = object_id(charge)
        .filter(|id| safe_id(id, "ch_"))
        .map(String::from);
    row.amount_refunded = charge["amount_refunded"].as_i64().filter(|a| *a >= 0);
    let reason = if object_id(&charge["customer"]) != Some(customer)
        || charge["currency"] != row.currency
        || charge["paid"] != true
        || charge["captured"] != true
        || charge["status"] != "succeeded"
        || charge["amount_captured"].as_i64() != Some(row.amount_paid)
        || charge["amount"].as_i64() != Some(row.amount_paid)
    {
        Some("Captured payment does not match the invoice")
    } else if charge["disputed"] != false {
        Some("Disputed payment or unknown dispute state")
    } else if row.amount_refunded != Some(0)
        || charge["refunds"]["has_more"] != false
        || charge["refunds"]["data"]
            .as_array()
            .is_none_or(|r| !r.is_empty())
    {
        Some("Existing refunds or incomplete refund history require reconciliation")
    } else {
        None
    };
    if let Some(reason) = reason {
        row.review_reason.get_or_insert(reason.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn invoice() -> Value {
        json!({
            "id":"in_test","subscription":"sub_test","customer":"cus_test","currency":"usd",
            "amount_paid":1001,"total":1001,"status":"paid","billing_reason":"subscription_cycle","charge":"ch_test",
            "lines":{"has_more":false,"data":[{"type":"subscription","proration":false,"amount":1001,"period":{"start":100,"end":200}}]}
        })
    }
    fn charge() -> Value {
        json!({"id":"ch_test","customer":"cus_test","currency":"usd","amount":1001,"amount_captured":1001,"amount_refunded":0,"paid":true,"captured":true,"status":"succeeded","disputed":false,"refunds":{"has_more":false,"data":[]}})
    }
    fn normalize(i: &Value, c: &Value) -> RefundInvoice {
        let mut row = normalize_invoice(i, "sub_test", "cus_test").unwrap();
        apply_charge(&mut row, c, "cus_test");
        row
    }
    #[test]
    fn refund_preview_accepts_verified_simple_recurring_payment() {
        let row = normalize(&invoice(), &charge());
        assert!(row.review_reason.is_none());
        assert_eq!(row.period_start, Some(100));
        assert_eq!(row.amount_refunded, Some(0));
        assert_eq!(
            payment_reference(&invoice()),
            Some(("charge", "ch_test".into()))
        );
    }
    #[test]
    fn refund_preview_supports_modern_invoice_shape_without_guessing_split_payments() {
        let mut i = invoice();
        i.as_object_mut().unwrap().remove("subscription");
        i.as_object_mut().unwrap().remove("charge");
        i["parent"] = json!({"subscription_details":{"subscription":"sub_test"}});
        i["lines"]["data"][0]["type"] = Value::Null;
        i["lines"]["data"][0]["parent"] = json!({"type":"subscription_item_details","subscription_item_details":{"proration":false}});
        i["payments"] = json!({"has_more":false,"data":[{"status":"paid","payment":{"type":"payment_intent","payment_intent":"pi_test"}}]});
        assert!(normalize(&i, &charge()).review_reason.is_none());
        assert_eq!(
            payment_reference(&i),
            Some(("payment_intent", "pi_test".into()))
        );
        i["payments"]["has_more"] = true.into();
        assert!(payment_reference(&i).is_none());
        i["payments"]["has_more"] = false.into();
        i["payments"]["data"]
            .as_array_mut()
            .unwrap()
            .push(json!({}));
        assert!(payment_reference(&i).is_none());
    }
    #[test]
    fn refund_preview_flags_billing_exceptions() {
        for (path, value) in [
            ("/total_discount_amounts", json!([{"amount":1}])),
            ("/total_taxes", json!([{"amount":1}])),
            ("/tax", json!(1)),
            ("/lines/has_more", json!(true)),
            ("/lines/data/0/proration", json!(true)),
            ("/billing_reason", json!("subscription_update")),
            ("/amount_paid", json!(500)),
            ("/lines/data/0/period/end", json!(100)),
            ("/status", json!("open")),
        ] {
            let mut i = invoice();
            if let Some(v) = i.pointer_mut(path) {
                *v = value;
            } else {
                i[path.trim_start_matches('/')] = value;
            }
            assert!(normalize(&i, &charge()).review_reason.is_some(), "{path}");
        }
        for (key, value) in [
            ("amount_refunded", json!(1)),
            ("disputed", json!(true)),
            ("captured", json!(false)),
            ("amount_captured", json!(999)),
            ("customer", json!("cus_other")),
            ("currency", json!("eur")),
            (
                "refunds",
                json!({"has_more":false,"data":[{"status":"pending"}]}),
            ),
        ] {
            let mut c = charge();
            c[key] = value;
            assert!(normalize(&invoice(), &c).review_reason.is_some(), "{key}");
        }
    }
    #[test]
    fn refund_preview_rejects_wrong_scope_and_incomplete_evidence() {
        let mut i = invoice();
        i["subscription"] = "sub_other".into();
        assert!(normalize_invoice(&i, "sub_test", "cus_test").is_err());
        let mut c = charge();
        c.as_object_mut().unwrap().remove("refunds");
        assert!(normalize(&invoice(), &c).review_reason.is_some());
        assert!(!safe_id("sub_test/../customers", "sub_"));
    }
}
