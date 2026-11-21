use super::types::*;
use crate::db_pool::DbPool;
use stripe_client::refunds::{RefundEvidence, StripeRefund};
use tokio_postgres::Row;
use uuid::Uuid;

pub struct Store<'a>(pub &'a DbPool);
fn attempt(r: Row) -> RefundAttempt {
    RefundAttempt {
        id: r.get("id"),
        sequence: r.get("sequence"),
        initiated_by: r.get("initiated_by"),
        status: r.get("status"),
        stripe_refund_id: r.get("stripe_refund_id"),
        first_submitted_at: r.get("first_submitted_at"),
        submission_count: r.get("submission_count"),
        failure_reason: r.get("failure_reason"),
        last_error: r.get("last_error"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
    }
}
fn operation(r: Row) -> RefundOperation {
    RefundOperation {
        id: r.get("id"),
        user_id: r.get("user_id"),
        approved_by: r.get("approved_by"),
        subscription_id: r.get("subscription_id"),
        invoice_id: r.get("invoice_id"),
        customer_id: r.get("customer_id"),
        charge_id: r.get("charge_id"),
        amount: r.get("amount"),
        currency: r.get("currency"),
        livemode: r.get("livemode"),
        effective_at: r.get("effective_at"),
        policy_reference: r.get("policy_reference"),
        reconciliation_reference: r.get("reconciliation_reference"),
        review_reason: r.get("review_reason"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
        attempts: vec![],
    }
}
impl Store<'_> {
    pub async fn get(&self, id: Uuid) -> Result<RefundOperation> {
        let c = self.0.get().await?;
        let row = c
            .query_opt("SELECT * FROM agent_hosting_refunds WHERE id=$1", &[&id])
            .await?
            .ok_or(RefundError::NotFound)?;
        let mut op = operation(row);
        op.attempts = c
            .query(
                "SELECT * FROM agent_hosting_refund_attempts WHERE refund_id=$1 ORDER BY sequence",
                &[&id],
            )
            .await?
            .into_iter()
            .map(attempt)
            .collect();
        Ok(op)
    }
    pub async fn by_invoice(&self, id: &str, sub: &str) -> Result<Option<RefundOperation>> {
        let c = self.0.get().await?;
        let row = c
            .query_opt(
                "SELECT id FROM agent_hosting_refunds WHERE invoice_id=$1 AND subscription_id=$2",
                &[&id, &sub],
            )
            .await?;
        drop(c);
        match row {
            Some(r) => Ok(Some(self.get(r.get(0)).await?)),
            None => Ok(None),
        }
    }
    pub async fn by_charge(&self, id: &str) -> Result<Option<Uuid>> {
        Ok(self
            .0
            .get()
            .await?
            .query_opt(
                "SELECT id FROM agent_hosting_refunds WHERE charge_id=$1",
                &[&id],
            )
            .await?
            .map(|r| r.get(0)))
    }
    pub async fn list(
        &self,
        sub: Option<&str>,
        limit: i64,
        offset: i64,
        enabled: bool,
    ) -> Result<RefundList> {
        let c = self.0.get().await?;
        let total = c
            .query_one(
                "SELECT COUNT(*)
            FROM agent_hosting_refunds
            WHERE ($1::text IS NULL OR subscription_id=$1)",
                &[&sub],
            )
            .await?
            .get(0);
        let ids = c
            .query(
                "SELECT id
            FROM agent_hosting_refunds
            WHERE ($1::text IS NULL OR subscription_id=$1)
            ORDER BY created_at DESC,id DESC
            LIMIT $2 OFFSET $3",
                &[&sub, &limit, &offset],
            )
            .await?;
        drop(c);
        let mut items = vec![];
        for row in ids {
            items.push(self.get(row.get(0)).await?);
        }
        Ok(RefundList {
            items,
            total,
            execution_enabled: enabled,
        })
    }
    pub async fn create(
        &self,
        r: &PrepareRefund,
        e: &RefundEvidence,
        actor: Uuid,
    ) -> Result<RefundOperation> {
        let mut c = self.0.get().await?;
        let t = c.transaction().await?;
        let id = Uuid::new_v4();
        let attempt_id = Uuid::new_v4();
        let inserted = t.execute(
            "INSERT INTO agent_hosting_refunds(id,user_id,approved_by,subscription_id,invoice_id,
                customer_id,charge_id,amount,currency,livemode,effective_at,policy_reference,
                reconciliation_reference)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
            ON CONFLICT DO NOTHING",
            &[
                &id, &r.user_id, &actor, &r.subscription_id, &r.invoice_id,
                &e.customer_id, &e.charge_id, &r.amount, &r.currency, &e.livemode,
                &r.effective_at, &r.policy_reference, &r.reconciliation_reference,
            ],
        ).await?;
        let actual = if inserted == 1 {
            t.execute(
                "INSERT INTO agent_hosting_refund_attempts(id,refund_id,sequence) VALUES($1,$2,1)",
                &[&attempt_id, &id],
            )
            .await?;
            id
        } else {
            t.query_one(
                "SELECT id FROM agent_hosting_refunds WHERE charge_id=$1 OR invoice_id=$2",
                &[&e.charge_id, &r.invoice_id],
            )
            .await?
            .get(0)
        };
        t.commit().await?;
        drop(c);
        let op = self.get(actual).await?;
        if !op.matches(r) {
            return Err(RefundError::Conflict("This payment already has a different refund record; reconcile it instead of creating another"));
        }
        Ok(op)
    }
    pub async fn claim(&self, id: Uuid, token: Uuid) -> Result<()> {
        let c = self.0.get().await?;
        if c.execute(
            "UPDATE agent_hosting_refunds
            SET lease_token=$2,lease_until=NOW()+INTERVAL '5 minutes'
            WHERE id=$1
            AND (lease_until IS NULL OR lease_until<NOW())",
            &[&id, &token],
        )
        .await?
            == 0
        {
            if c.query_opt("SELECT id FROM agent_hosting_refunds WHERE id=$1", &[&id])
                .await?
                .is_none()
            {
                return Err(RefundError::NotFound);
            }
            return Err(RefundError::Conflict(
                "A refund action is already running; refresh before trying again",
            ));
        }
        Ok(())
    }
    pub async fn release(&self, id: Uuid, token: Uuid) -> Result<()> {
        self.0
            .get()
            .await?
            .execute(
                "UPDATE agent_hosting_refunds
            SET lease_token=NULL,lease_until=NULL
            WHERE id=$1
            AND lease_token=$2",
                &[&id, &token],
            )
            .await?;
        Ok(())
    }
    pub async fn review(&self, id: Uuid, token: Uuid, reason: Option<&str>) -> Result<()> {
        let n = self
            .0
            .get()
            .await?
            .execute(
                "UPDATE agent_hosting_refunds
            SET review_reason=$3,updated_at=NOW()
            WHERE id=$1
            AND lease_token=$2",
                &[&id, &token, &reason],
            )
            .await?;
        if n != 1 {
            return Err(RefundError::Conflict(
                "Refund action lease changed; synchronize again",
            ));
        }
        Ok(())
    }
    pub async fn save(&self, op: Uuid, token: Uuid, attempt: Uuid, r: &StripeRefund) -> Result<()> {
        let reason = r.failure_reason.as_deref().map(|v| {
            if v.len() <= 100 && v.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') {
                v
            } else {
                "unknown"
            }
        });
        let n = self
            .0
            .get()
            .await?
            .execute(
                "UPDATE agent_hosting_refund_attempts
            SET status=$4,stripe_refund_id=$5,failure_reason=$6,last_error=NULL,updated_at=NOW()
            WHERE id=$3
            AND refund_id=$1
            AND EXISTS(SELECT 1
            FROM agent_hosting_refunds
            WHERE id=$1
            AND lease_token=$2)",
                &[&op, &token, &attempt, &r.status, &r.id, &reason],
            )
            .await?;
        if n != 1 {
            return Err(RefundError::Database);
        }
        Ok(())
    }
    pub async fn error(
        &self,
        op: Uuid,
        token: Uuid,
        attempt: Uuid,
        code: &str,
        unknown: bool,
    ) -> Result<()> {
        self.0
            .get()
            .await?
            .execute(
                "UPDATE agent_hosting_refund_attempts
            SET last_error=$4,status=CASE WHEN $5 THEN 'unknown' ELSE status END,updated_at=NOW()
            WHERE id=$3
            AND refund_id=$1
            AND EXISTS(SELECT 1
            FROM agent_hosting_refunds
            WHERE id=$1
            AND lease_token=$2)",
                &[&op, &token, &attempt, &code, &unknown],
            )
            .await?;
        Ok(())
    }
    pub async fn may_resubmit(&self, attempt: Uuid) -> Result<bool> {
        Ok(self
            .0
            .get()
            .await?
            .query_one(
                "SELECT first_submitted_at IS NULL OR first_submitted_at>NOW()-INTERVAL '23 hours'
            FROM agent_hosting_refund_attempts
            WHERE id=$1",
                &[&attempt],
            )
            .await?
            .get(0))
    }
    pub async fn mark_submitting(
        &self,
        op: Uuid,
        token: Uuid,
        attempt: Uuid,
        actor: Uuid,
    ) -> Result<()> {
        let n = self
            .0
            .get()
            .await?
            .execute(
                "UPDATE agent_hosting_refund_attempts
            SET status='submitting',
                initiated_by=CASE WHEN first_submitted_at IS NULL THEN $4 ELSE initiated_by END,
                first_submitted_at=COALESCE(first_submitted_at,NOW()),
                submission_count=submission_count+1,last_error=NULL,updated_at=NOW()
            WHERE id=$3
            AND refund_id=$1
            AND EXISTS(SELECT 1
            FROM agent_hosting_refunds
            WHERE id=$1
            AND lease_token=$2)",
                &[&op, &token, &attempt, &actor],
            )
            .await?;
        if n != 1 {
            return Err(RefundError::Database);
        }
        Ok(())
    }
    pub async fn new_attempt(&self, op: &RefundOperation, token: Uuid, actor: Uuid) -> Result<()> {
        let id = Uuid::new_v4();
        let sequence = op
            .current()?
            .sequence
            .checked_add(1)
            .ok_or(RefundError::Database)?;
        let n = self.0.get().await?.execute(
            "INSERT INTO agent_hosting_refund_attempts(id,refund_id,sequence,initiated_by) SELECT $3,$1,$4,$5
            FROM agent_hosting_refunds
            WHERE id=$1
            AND lease_token=$2",
            &[&op.id, &token, &id, &sequence, &actor],
        ).await?;
        if n != 1 {
            return Err(RefundError::Database);
        }
        Ok(())
    }
}
