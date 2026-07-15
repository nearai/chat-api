use crate::pool::DbPool;
use async_trait::async_trait;
use services::kyt::{KytAuditRepository, KytHighRiskAuditEvent};

pub struct PostgresKytAuditRepository {
    pool: DbPool,
}

impl PostgresKytAuditRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl KytAuditRepository for PostgresKytAuditRepository {
    async fn record_high_risk(&self, event: KytHighRiskAuditEvent) -> anyhow::Result<()> {
        let client = self.pool.get().await?;
        let result_json = serde_json::to_value(&event.result)?;
        let risk_level = format!("{:?}", event.result.risk_level).to_ascii_uppercase();

        client
            .execute(
                r#"
                INSERT INTO kyt_high_risk_events (
                    user_id,
                    flow,
                    provider,
                    account_id,
                    address_type,
                    risk_level,
                    score,
                    report_id,
                    checked_at,
                    reason,
                    result
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                "#,
                &[
                    &event.user_id,
                    &event.flow,
                    &event.result.provider,
                    &event.result.account_id,
                    &event.result.address_type,
                    &risk_level,
                    &event.result.score,
                    &event.result.report_id,
                    &event.result.checked_at,
                    &event.result.reason,
                    &result_json,
                ],
            )
            .await?;

        Ok(())
    }
}
