use crate::error::StripeWebhookError;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

#[derive(Debug, Clone)]
pub struct VerifiedStripeWebhook {
    pub timestamp: i64,
}

#[derive(Debug, Clone)]
pub struct StripeWebhookVerifier {
    tolerance_seconds: i64,
}

impl Default for StripeWebhookVerifier {
    fn default() -> Self {
        Self::new(300)
    }
}

impl StripeWebhookVerifier {
    pub fn new(tolerance_seconds: i64) -> Self {
        Self { tolerance_seconds }
    }

    pub fn verify(
        &self,
        raw_body: &[u8],
        stripe_signature: &str,
        secret: &str,
        now: DateTime<Utc>,
    ) -> Result<VerifiedStripeWebhook, StripeWebhookError> {
        if stripe_signature.is_empty() {
            return Err(StripeWebhookError::MissingSignatureHeader);
        }

        let header = ParsedStripeSignature::parse(stripe_signature)?;
        let expected = compute_signature(secret, header.timestamp, raw_body);

        let any_match = header
            .v1_signatures
            .iter()
            .any(|candidate| secure_hex_eq(&expected, candidate));

        if !any_match {
            return Err(StripeWebhookError::SignatureMismatch);
        }

        let timestamp_age = now
            .timestamp()
            .checked_sub(header.timestamp)
            .ok_or(StripeWebhookError::TimestampOutsideTolerance)?;
        if self.tolerance_seconds > 0 && timestamp_age > self.tolerance_seconds {
            return Err(StripeWebhookError::TimestampOutsideTolerance);
        }

        Ok(VerifiedStripeWebhook {
            timestamp: header.timestamp,
        })
    }
}

#[derive(Debug)]
struct ParsedStripeSignature {
    timestamp: i64,
    v1_signatures: Vec<String>,
}

impl ParsedStripeSignature {
    fn parse(header: &str) -> Result<Self, StripeWebhookError> {
        let mut timestamp = None;
        let mut v1_signatures = Vec::new();

        for pair in header.split(',') {
            let (key, value) = pair
                .split_once('=')
                .ok_or(StripeWebhookError::InvalidSignatureHeader)?;
            match key {
                "t" => {
                    timestamp = Some(
                        value
                            .parse::<i64>()
                            .map_err(|_| StripeWebhookError::InvalidSignatureHeader)?,
                    );
                }
                "v1" => v1_signatures.push(value.to_string()),
                _ => {}
            }
        }

        let timestamp = timestamp.ok_or(StripeWebhookError::MissingTimestamp)?;
        if v1_signatures.is_empty() {
            return Err(StripeWebhookError::MissingV1Signature);
        }
        if v1_signatures.iter().any(|sig| hex::decode(sig).is_err()) {
            return Err(StripeWebhookError::InvalidSignatureEncoding);
        }

        Ok(Self {
            timestamp,
            v1_signatures,
        })
    }
}

fn compute_signature(secret: &str, timestamp: i64, raw_body: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC-SHA256 accepts keys of any length");
    let timestamp = timestamp.to_string();
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(raw_body);
    mac.finalize().into_bytes().to_vec()
}

fn secure_hex_eq(expected: &[u8], candidate_hex: &str) -> bool {
    let Ok(candidate) = hex::decode(candidate_hex) else {
        return false;
    };
    expected.ct_eq(&candidate).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sign(secret: &str, timestamp: i64, payload: &[u8]) -> String {
        let sig = compute_signature(secret, timestamp, payload);
        hex::encode(sig)
    }

    #[test]
    fn verifies_single_valid_v1() {
        let verifier = StripeWebhookVerifier::default();
        let payload = br#"{"id":"evt_1"}"#;
        let ts = 1_700_000_000;
        let sig = sign("whsec_test", ts, payload);
        let header = format!("t={ts},v1={sig}");
        let now = Utc.timestamp_opt(ts + 10, 0).unwrap();

        assert!(verifier.verify(payload, &header, "whsec_test", now).is_ok());
    }

    #[test]
    fn verifies_when_any_v1_matches() {
        let verifier = StripeWebhookVerifier::default();
        let payload = br#"{"id":"evt_1"}"#;
        let ts = 1_700_000_000;
        let sig = sign("whsec_test", ts, payload);
        let header = format!("t={ts},v1=deadbeef,v1={sig}");
        let now = Utc.timestamp_opt(ts + 10, 0).unwrap();

        assert!(verifier.verify(payload, &header, "whsec_test", now).is_ok());
    }

    #[test]
    fn rejects_old_timestamp() {
        let verifier = StripeWebhookVerifier::default();
        let payload = br#"{"id":"evt_1"}"#;
        let ts = 1_700_000_000;
        let sig = sign("whsec_test", ts, payload);
        let header = format!("t={ts},v1={sig}");
        let now = Utc.timestamp_opt(ts + 301, 0).unwrap();

        let err = verifier
            .verify(payload, &header, "whsec_test", now)
            .unwrap_err();
        assert!(matches!(err, StripeWebhookError::TimestampOutsideTolerance));
    }

    #[test]
    fn accepts_timestamp_at_tolerance_boundary() {
        let verifier = StripeWebhookVerifier::default();
        let payload = br#"{"id":"evt_1"}"#;
        let ts = 1_700_000_000;
        let sig = sign("whsec_test", ts, payload);
        let header = format!("t={ts},v1={sig}");
        let now = Utc.timestamp_opt(ts + 300, 0).unwrap();

        assert!(verifier.verify(payload, &header, "whsec_test", now).is_ok());
    }

    #[test]
    fn does_not_use_absolute_timestamp_difference() {
        let verifier = StripeWebhookVerifier::default();
        let payload = br#"{"id":"evt_1"}"#;
        let ts = 1_700_000_000;
        let sig = sign("whsec_test", ts, payload);
        let header = format!("t={ts},v1={sig}");
        let now = Utc.timestamp_opt(ts - 301, 0).unwrap();

        assert!(verifier.verify(payload, &header, "whsec_test", now).is_ok());
    }

    #[test]
    fn rejects_signature_mismatch() {
        let verifier = StripeWebhookVerifier::default();
        let payload = br#"{"id":"evt_1"}"#;
        let ts = 1_700_000_000;
        let header = format!("t={ts},v1={}", sign("whsec_other", ts, payload));
        let now = Utc.timestamp_opt(ts + 10, 0).unwrap();

        let err = verifier
            .verify(payload, &header, "whsec_test", now)
            .unwrap_err();
        assert!(matches!(err, StripeWebhookError::SignatureMismatch));
    }

    #[test]
    fn rejects_invalid_signature_header() {
        let verifier = StripeWebhookVerifier::default();
        let payload = br#"{"id":"evt_1"}"#;
        let now = Utc.timestamp_opt(1_700_000_010, 0).unwrap();

        let err = verifier
            .verify(payload, "t=1700000000,v1", "whsec_test", now)
            .unwrap_err();
        assert!(matches!(err, StripeWebhookError::InvalidSignatureHeader));
    }

    #[test]
    fn rejects_missing_timestamp() {
        let verifier = StripeWebhookVerifier::default();
        let payload = br#"{"id":"evt_1"}"#;
        let sig = sign("whsec_test", 1_700_000_000, payload);
        let now = Utc.timestamp_opt(1_700_000_010, 0).unwrap();

        let err = verifier
            .verify(payload, &format!("v1={sig}"), "whsec_test", now)
            .unwrap_err();
        assert!(matches!(err, StripeWebhookError::MissingTimestamp));
    }

    #[test]
    fn rejects_missing_v1_signature() {
        let verifier = StripeWebhookVerifier::default();
        let payload = br#"{"id":"evt_1"}"#;
        let now = Utc.timestamp_opt(1_700_000_010, 0).unwrap();

        let err = verifier
            .verify(payload, "t=1700000000", "whsec_test", now)
            .unwrap_err();
        assert!(matches!(err, StripeWebhookError::MissingV1Signature));
    }

    #[test]
    fn rejects_invalid_signature_encoding() {
        let verifier = StripeWebhookVerifier::default();
        let payload = br#"{"id":"evt_1"}"#;
        let now = Utc.timestamp_opt(1_700_000_010, 0).unwrap();

        let err = verifier
            .verify(payload, "t=1700000000,v1=not_hex", "whsec_test", now)
            .unwrap_err();
        assert!(matches!(err, StripeWebhookError::InvalidSignatureEncoding));
    }

    #[test]
    fn rejects_timestamp_age_overflow() {
        let verifier = StripeWebhookVerifier::default();
        let payload = br#"{"id":"evt_1"}"#;
        let ts = i64::MIN;
        let sig = sign("whsec_test", ts, payload);
        let header = format!("t={ts},v1={sig}");
        let now = Utc.timestamp_opt(0, 0).unwrap();

        let err = verifier
            .verify(payload, &header, "whsec_test", now)
            .unwrap_err();
        assert!(matches!(err, StripeWebhookError::TimestampOutsideTolerance));
    }
}
