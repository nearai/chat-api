use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum RefundError {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("{0}")]
    Conflict(&'static str),
    #[error("Refund record not found")]
    NotFound,
    #[error("Refund execution is disabled")]
    Disabled,
    #[error("Unable to verify Stripe payment data; retry synchronization")]
    Upstream,
    #[error("Unable to persist refund state")]
    Database,
}
impl From<tokio_postgres::Error> for RefundError {
    fn from(_: tokio_postgres::Error) -> Self {
        Self::Database
    }
}
impl From<deadpool_postgres::PoolError> for RefundError {
    fn from(_: deadpool_postgres::PoolError) -> Self {
        Self::Database
    }
}
pub type Result<T> = std::result::Result<T, RefundError>;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareRefund {
    pub user_id: Uuid,
    pub subscription_id: String,
    pub invoice_id: String,
    pub amount: i64,
    pub currency: String,
    pub effective_at: DateTime<Utc>,
    pub policy_reference: String,
    pub reconciliation_reference: String,
    pub approved: bool,
}
impl PrepareRefund {
    pub fn validate(&self) -> Result<()> {
        let reference = |s: &str| {
            !s.is_empty()
                && s.len() <= 100
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.:/#".contains(&b))
        };
        let stripe_id = |id: &str, prefix: &str| {
            id.starts_with(prefix)
                && id.len() > prefix.len()
                && id.len() <= 255
                && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        };
        if !stripe_id(&self.invoice_id, "in_") || !stripe_id(&self.subscription_id, "sub_") {
            return Err(RefundError::Invalid(
                "Invalid invoice or subscription identifier",
            ));
        }
        if !self.approved {
            return Err(RefundError::Invalid("Eligibility, amount and other compensation must be approved before recording a refund"));
        }
        if self.amount <= 0 || self.amount > 9_007_199_254_740_991 {
            return Err(RefundError::Invalid(
                "Amount must be a positive integer in minor units",
            ));
        }
        if self.currency.len() != 3 || !self.currency.bytes().all(|b| b.is_ascii_lowercase()) {
            return Err(RefundError::Invalid("Invalid currency"));
        }
        if !reference(&self.policy_reference) || !reference(&self.reconciliation_reference) {
            return Err(RefundError::Invalid("Provide policy and reconciliation reference IDs (1-100 ASCII ID/URL-path characters; no personal data)"));
        }
        if self.effective_at.timestamp_subsec_nanos() != 0 {
            return Err(RefundError::Invalid(
                "Effective date must use whole seconds",
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefundConfirmation {
    pub expected_attempt_id: Uuid,
    pub confirmed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RefundAttempt {
    pub id: Uuid,
    pub sequence: i32,
    pub initiated_by: Option<Uuid>,
    pub status: String,
    pub stripe_refund_id: Option<String>,
    pub first_submitted_at: Option<DateTime<Utc>>,
    pub submission_count: i32,
    pub failure_reason: Option<String>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
#[derive(Clone, Debug, Serialize)]
pub struct RefundOperation {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub approved_by: Option<Uuid>,
    pub subscription_id: String,
    pub invoice_id: String,
    #[serde(skip_serializing)]
    pub customer_id: String,
    pub charge_id: String,
    pub amount: i64,
    pub currency: String,
    pub livemode: bool,
    pub effective_at: DateTime<Utc>,
    pub policy_reference: String,
    pub reconciliation_reference: String,
    pub review_reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub attempts: Vec<RefundAttempt>,
}
impl RefundOperation {
    pub fn current(&self) -> Result<&RefundAttempt> {
        self.attempts.last().ok_or(RefundError::Database)
    }
    pub fn matches(&self, r: &PrepareRefund) -> bool {
        self.user_id == Some(r.user_id)
            && self.subscription_id == r.subscription_id
            && self.invoice_id == r.invoice_id
            && self.amount == r.amount
            && self.currency == r.currency
            && self.effective_at == r.effective_at
            && self.policy_reference == r.policy_reference
            && self.reconciliation_reference == r.reconciliation_reference
    }
}
#[derive(Serialize)]
pub struct RefundList {
    pub items: Vec<RefundOperation>,
    pub total: i64,
    pub execution_enabled: bool,
}
#[derive(Clone, Copy, PartialEq)]
pub enum Action {
    Sync,
    Execute,
    RetryFailed,
}
