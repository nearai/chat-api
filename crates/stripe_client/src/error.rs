use thiserror::Error;

#[derive(Debug, Error)]
pub enum StripeWebhookError {
    #[error("missing Stripe-Signature header")]
    MissingSignatureHeader,
    #[error("invalid Stripe-Signature header")]
    InvalidSignatureHeader,
    #[error("missing timestamp in Stripe-Signature header")]
    MissingTimestamp,
    #[error("missing v1 signature in Stripe-Signature header")]
    MissingV1Signature,
    #[error("invalid v1 signature encoding")]
    InvalidSignatureEncoding,
    #[error("signature mismatch")]
    SignatureMismatch,
    #[error("timestamp outside tolerance")]
    TimestampOutsideTolerance,
}

#[derive(Debug, Error)]
pub enum StripeClientError {
    #[error("Stripe request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("Stripe returned HTTP {status}: {message}")]
    Http {
        status: reqwest::StatusCode,
        message: String,
    },
    #[error("failed to parse Stripe response: {0}")]
    ResponseParse(#[from] serde_json::Error),
    #[error("invalid Stripe response: {0}")]
    InvalidResponse(&'static str),
}
