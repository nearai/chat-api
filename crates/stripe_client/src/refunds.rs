use crate::{
    refund_preview::{object_id, payment_reference, safe_id},
    StripeClient, StripeClientError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StripeRefund {
    pub id: String,
    pub charge: String,
    pub amount: i64,
    pub currency: String,
    pub status: String,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    pub failure_reason: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RefundEvidence {
    pub invoice_id: String,
    pub charge_id: String,
    pub customer_id: String,
    pub currency: String,
    pub amount_paid: i64,
    pub amount_refunded: i64,
    pub livemode: bool,
    pub refunds: Vec<StripeRefund>,
}

#[derive(Deserialize)]
struct RefundPage {
    data: Vec<StripeRefund>,
    has_more: bool,
}

impl StripeClient {
    pub async fn refund_evidence(
        &self,
        invoice_id: &str,
        subscription_id: &str,
        customer_id: &str,
    ) -> Result<RefundEvidence, StripeClientError> {
        if !safe_id(invoice_id, "in_")
            || !safe_id(subscription_id, "sub_")
            || !safe_id(customer_id, "cus_")
        {
            return Err(StripeClientError::InvalidResponse(
                "Invalid billing identifier",
            ));
        }
        let mut invoice: Value = self
            .get_json(&format!("/v1/invoices/{invoice_id}"), &[])
            .await?;
        if object_id(&invoice) != Some(invoice_id)
            || object_id(&invoice["customer"]) != Some(customer_id)
            || object_id(&invoice["subscription"])
                .or_else(|| object_id(&invoice["parent"]["subscription_details"]["subscription"]))
                != Some(subscription_id)
            || invoice["status"] != "paid"
            || invoice["paid_out_of_band"] == true
        {
            return Err(StripeClientError::InvalidResponse(
                "Invoice ownership or payment is unverified",
            ));
        }
        if invoice.get("payments").is_none_or(Value::is_null)
            && invoice["parent"]["subscription_details"].is_object()
        {
            invoice["payments"] = self
                .get_json::<Value>(
                    "/v1/invoice_payments",
                    &[("invoice", invoice_id), ("limit", "2")],
                )
                .await?;
        }
        let (kind, id) = payment_reference(&invoice).ok_or(StripeClientError::InvalidResponse(
            "Invoice has ambiguous payment allocation",
        ))?;
        let charge_id = match kind {
            "charge" if safe_id(&id, "ch_") => id,
            "payment_intent" if safe_id(&id, "pi_") => {
                let pi: Value = self
                    .get_json(&format!("/v1/payment_intents/{id}"), &[])
                    .await?;
                object_id(&pi["latest_charge"])
                    .filter(|id| safe_id(id, "ch_"))
                    .ok_or(StripeClientError::InvalidResponse(
                        "Missing original charge",
                    ))?
                    .to_owned()
            }
            _ => {
                return Err(StripeClientError::InvalidResponse(
                    "Unsupported original payment",
                ))
            }
        };
        let charge: Value = self
            .get_json(&format!("/v1/charges/{charge_id}"), &[])
            .await?;
        let mut evidence = validate_payment(&invoice, &charge, customer_id)?;
        if evidence.charge_id != charge_id {
            return Err(StripeClientError::InvalidResponse(
                "Charge identity mismatch",
            ));
        }
        let mut cursor = String::new();
        let mut seen = HashSet::new();
        // Bound the read; incomplete evidence never permits execution.
        for _ in 0..10 {
            let mut query = vec![("charge", charge_id.as_str()), ("limit", "100")];
            if !cursor.is_empty() {
                query.push(("starting_after", cursor.as_str()));
            }
            let page: RefundPage = self.get_json("/v1/refunds", &query).await?;
            if page.has_more && page.data.is_empty() {
                break;
            }
            for refund in page.data {
                if refund.charge != charge_id || !seen.insert(refund.id.clone()) {
                    return Err(StripeClientError::InvalidResponse(
                        "Refund history mismatch",
                    ));
                }
                cursor = refund.id.clone();
                evidence.refunds.push(refund);
            }
            if !page.has_more {
                return Ok(evidence);
            }
        }
        Err(StripeClientError::InvalidResponse(
            "Refund history is incomplete",
        ))
    }

    pub async fn create_sunset_refund(
        &self,
        charge: &str,
        amount: i64,
        operation: &str,
        attempt: &str,
    ) -> Result<StripeRefund, StripeClientError> {
        if !safe_id(charge, "ch_") || amount <= 0 {
            return Err(StripeClientError::InvalidResponse("Invalid refund request"));
        }
        let form = vec![
            ("charge", charge.to_owned()),
            ("amount", amount.to_string()),
            ("metadata[sunset_operation_id]", operation.to_owned()),
            ("metadata[sunset_attempt_id]", attempt.to_owned()),
        ];
        self.post_form(
            "/v1/refunds",
            &form,
            Some(&format!("agent-hosting-sunset:{attempt}")),
        )
        .await
    }
}

fn validate_payment(
    invoice: &Value,
    charge: &Value,
    customer: &str,
) -> Result<RefundEvidence, StripeClientError> {
    let invalid =
        || StripeClientError::InvalidResponse("Captured payment does not match paid invoice");
    let amount = invoice["amount_paid"]
        .as_i64()
        .filter(|v| *v > 0 && *v <= 9_007_199_254_740_991)
        .ok_or_else(invalid)?;
    let currency = invoice["currency"]
        .as_str()
        .filter(|v| v.len() == 3 && v.bytes().all(|b| b.is_ascii_lowercase()))
        .ok_or_else(invalid)?;
    if charge["amount_captured"].as_i64() != Some(amount)
        || charge["amount"].as_i64() != Some(amount)
        || charge["currency"] != currency
        || object_id(&charge["customer"]) != Some(customer)
        || charge["paid"] != true
        || charge["captured"] != true
        || charge["disputed"] != false
        || charge["status"] != "succeeded"
    {
        return Err(invalid());
    }
    let refunded = charge["amount_refunded"]
        .as_i64()
        .filter(|v| *v >= 0 && *v <= amount)
        .ok_or_else(invalid)?;
    Ok(RefundEvidence {
        invoice_id: object_id(invoice).ok_or_else(invalid)?.into(),
        charge_id: object_id(charge)
            .filter(|id| safe_id(id, "ch_"))
            .ok_or_else(invalid)?
            .into(),
        customer_id: customer.into(),
        currency: currency.into(),
        amount_paid: amount,
        amount_refunded: refunded,
        livemode: charge["livemode"].as_bool().ok_or_else(invalid)?,
        refunds: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::{
        matchers::{body_string_contains, header, method, path, query_param},
        Mock, MockServer, ResponseTemplate,
    };

    fn invoice() -> Value {
        json!({"id":"in_test","customer":"cus_test","subscription":"sub_test","status":"paid","charge":"ch_test","amount_paid":1001,"currency":"usd"})
    }
    fn charge() -> Value {
        json!({"id":"ch_test","customer":"cus_test","amount":1001,"amount_captured":1001,"amount_refunded":0,"currency":"usd","paid":true,"captured":true,"disputed":false,"status":"succeeded","livemode":false})
    }
    fn refund(id: &str) -> Value {
        json!({"id":id,"charge":"ch_test","amount":500,"currency":"usd","status":"failed","metadata":{},"failure_reason":"declined"})
    }
    async fn payment(server: &MockServer, invoice: Value, charge: Value) {
        Mock::given(method("GET"))
            .and(path("/v1/invoices/in_test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(invoice))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/charges/ch_test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(charge))
            .mount(server)
            .await;
    }
    #[tokio::test]
    async fn refunds_paginate_and_verify_payment_before_execution() {
        let server = MockServer::start().await;
        payment(&server, invoice(), charge()).await;
        Mock::given(method("GET"))
            .and(path("/v1/refunds"))
            .and(query_param("charge", "ch_test"))
            .and(query_param("limit", "100"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"data":[refund("re_first")],"has_more":true})),
            )
            .with_priority(2)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/refunds"))
            .and(query_param("starting_after", "re_first"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"data":[refund("re_last")],"has_more":false})),
            )
            .with_priority(1)
            .expect(1)
            .mount(&server)
            .await;
        let e = StripeClient::for_test(server.uri())
            .refund_evidence("in_test", "sub_test", "cus_test")
            .await
            .unwrap();
        assert_eq!(e.refunds.len(), 2);
        assert_eq!(e.charge_id, "ch_test");
        assert_eq!(e.amount_paid, 1001);
        assert!(!e.livemode);
    }
    #[tokio::test]
    async fn refund_post_uses_original_charge_amount_metadata_and_stable_key() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/refunds"))
            .and(header("idempotency-key", "agent-hosting-sunset:attempt-1"))
            .and(header("authorization", "Bearer sk_test_fixture"))
            .and(body_string_contains("charge=ch_test"))
            .and(body_string_contains("amount=500"))
            .and(body_string_contains(
                "metadata%5Bsunset_operation_id%5D=operation-1",
            ))
            .and(body_string_contains(
                "metadata%5Bsunset_attempt_id%5D=attempt-1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(refund("re_original")))
            .expect(2)
            .mount(&server)
            .await;
        let c = StripeClient::for_test(server.uri());
        for _ in 0..2 {
            assert_eq!(
                c.create_sunset_refund("ch_test", 500, "operation-1", "attempt-1")
                    .await
                    .unwrap()
                    .id,
                "re_original"
            );
        }
    }
    #[tokio::test]
    async fn unverified_payments_and_incomplete_history_fail_closed() {
        for field in ["customer", "status", "amount_captured", "disputed"] {
            let server = MockServer::start().await;
            let mut ch = charge();
            ch[field] = json!(null);
            payment(&server, invoice(), ch).await;
            assert!(StripeClient::for_test(server.uri())
                .refund_evidence("in_test", "sub_test", "cus_test")
                .await
                .is_err());
        }
        let server = MockServer::start().await;
        payment(&server, invoice(), charge()).await;
        Mock::given(path("/v1/refunds"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"data":[],"has_more":true})),
            )
            .mount(&server)
            .await;
        assert!(StripeClient::for_test(server.uri())
            .refund_evidence("in_test", "sub_test", "cus_test")
            .await
            .is_err());
    }
    #[tokio::test]
    async fn modern_invoice_payment_intent_resolves_original_charge() {
        let server = MockServer::start().await;
        let mut inv = invoice();
        inv.as_object_mut().unwrap().remove("charge");
        inv.as_object_mut().unwrap().remove("subscription");
        inv["parent"] = json!({"subscription_details":{"subscription":"sub_test"}});
        payment(&server, inv, charge()).await;
        Mock::given(path("/v1/invoice_payments")).and(query_param("invoice","in_test")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"has_more":false,"data":[{"status":"paid","amount_paid":1001,"payment":{"type":"payment_intent","payment_intent":"pi_test"}}]}))).mount(&server).await;
        Mock::given(path("/v1/payment_intents/pi_test"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"latest_charge":"ch_test"})),
            )
            .mount(&server)
            .await;
        Mock::given(path("/v1/refunds"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"data":[],"has_more":false})),
            )
            .mount(&server)
            .await;
        assert_eq!(
            StripeClient::for_test(server.uri())
                .refund_evidence("in_test", "sub_test", "cus_test")
                .await
                .unwrap()
                .charge_id,
            "ch_test"
        );
    }
}
