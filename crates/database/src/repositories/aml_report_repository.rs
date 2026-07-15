use crate::pool::DbPool;
use async_trait::async_trait;
use services::aml::{
    normalize_account_id, AmlAccountAllowlistEntry, AmlCheckResult, AmlReportEvent,
    AmlReportRecord, AmlReportRepository, AmlRiskLevel,
};
use tokio_postgres::Row;
use uuid::Uuid;

pub struct PostgresAmlReportRepository {
    pool: DbPool,
}

impl PostgresAmlReportRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    fn risk_level_to_db(risk_level: AmlRiskLevel) -> String {
        format!("{risk_level:?}").to_ascii_uppercase()
    }

    fn risk_level_from_db(value: &str) -> AmlRiskLevel {
        match value {
            "LOW" => AmlRiskLevel::Low,
            "MEDIUM" => AmlRiskLevel::Medium,
            "HIGH" => AmlRiskLevel::High,
            _ => AmlRiskLevel::Unknown,
        }
    }

    fn report_from_row(row: Row) -> anyhow::Result<AmlReportRecord> {
        let result_json: serde_json::Value = row.get("result");
        let result = serde_json::from_value::<AmlCheckResult>(result_json)?;
        let risk_level: String = row.get("risk_level");
        Ok(AmlReportRecord {
            id: row.get("id"),
            user_id: row.get("user_id"),
            flow: row.get("flow"),
            provider: row.get("provider"),
            account_id: row.get("account_id"),
            address_type: row.get("address_type"),
            risk_level: Self::risk_level_from_db(&risk_level),
            score: row.get("score"),
            report_id: row.get("provider_report_id"),
            checked_at: row.get("checked_at"),
            reason: row.get("reason"),
            result,
            active: row.get("active"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    fn allowlist_from_row(row: Row) -> AmlAccountAllowlistEntry {
        AmlAccountAllowlistEntry {
            account_id: row.get("account_id"),
            reason: row.get("reason"),
            created_by: row.get("created_by"),
            created_at: row.get("created_at"),
        }
    }
}

#[async_trait]
impl AmlReportRepository for PostgresAmlReportRepository {
    async fn record_report(&self, event: AmlReportEvent) -> anyhow::Result<AmlReportRecord> {
        let client = self.pool.get().await?;
        let result_json = serde_json::to_value(&event.result)?;
        let account_id = normalize_account_id(&event.result.account_id);
        let risk_level = Self::risk_level_to_db(event.result.risk_level);

        let row = client
            .query_one(
                r#"
                INSERT INTO aml_risk_reports (
                    user_id,
                    flow,
                    provider,
                    account_id,
                    address_type,
                    risk_level,
                    score,
                    provider_report_id,
                    checked_at,
                    reason,
                    result,
                    active
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, TRUE)
                RETURNING *
                "#,
                &[
                    &event.user_id,
                    &event.flow,
                    &event.result.provider,
                    &account_id,
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

        Self::report_from_row(row)
    }

    async fn latest_active_report(
        &self,
        account_id: &str,
    ) -> anyhow::Result<Option<AmlReportRecord>> {
        let client = self.pool.get().await?;
        let account_id = normalize_account_id(account_id);
        let row = client
            .query_opt(
                r#"
                SELECT *
                FROM aml_risk_reports
                WHERE account_id = $1 AND active = TRUE
                ORDER BY checked_at DESC, created_at DESC
                LIMIT 1
                "#,
                &[&account_id],
            )
            .await?;

        row.map(Self::report_from_row).transpose()
    }

    async fn is_account_allowlisted(&self, account_id: &str) -> anyhow::Result<bool> {
        let client = self.pool.get().await?;
        let account_id = normalize_account_id(account_id);
        let exists = client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM aml_account_allowlist WHERE account_id = $1)",
                &[&account_id],
            )
            .await?
            .get::<_, bool>(0);
        Ok(exists)
    }

    async fn list_reports(
        &self,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<AmlReportRecord>, i64)> {
        let client = self.pool.get().await?;
        let total = client
            .query_one("SELECT COUNT(*) FROM aml_risk_reports", &[])
            .await?
            .get::<_, i64>(0);
        let rows = client
            .query(
                r#"
                SELECT *
                FROM aml_risk_reports
                ORDER BY checked_at DESC, created_at DESC
                LIMIT $1 OFFSET $2
                "#,
                &[&limit, &offset],
            )
            .await?;
        let reports = rows
            .into_iter()
            .map(Self::report_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        Ok((reports, total))
    }

    async fn list_allowlist(&self) -> anyhow::Result<Vec<AmlAccountAllowlistEntry>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                r#"
                SELECT *
                FROM aml_account_allowlist
                ORDER BY created_at DESC
                "#,
                &[],
            )
            .await?;
        Ok(rows.into_iter().map(Self::allowlist_from_row).collect())
    }

    async fn add_allowlist_entry(
        &self,
        account_id: &str,
        reason: Option<String>,
        created_by: Option<services::UserId>,
    ) -> anyhow::Result<AmlAccountAllowlistEntry> {
        let client = self.pool.get().await?;
        let account_id = normalize_account_id(account_id);
        let row = client
            .query_one(
                r#"
                INSERT INTO aml_account_allowlist (account_id, reason, created_by)
                VALUES ($1, $2, $3)
                ON CONFLICT (account_id)
                DO UPDATE SET reason = EXCLUDED.reason, created_by = EXCLUDED.created_by
                RETURNING *
                "#,
                &[&account_id, &reason, &created_by],
            )
            .await?;
        Ok(Self::allowlist_from_row(row))
    }

    async fn remove_allowlist_entry(&self, account_id: &str) -> anyhow::Result<bool> {
        let client = self.pool.get().await?;
        let account_id = normalize_account_id(account_id);
        let deleted = client
            .execute(
                "DELETE FROM aml_account_allowlist WHERE account_id = $1",
                &[&account_id],
            )
            .await?;
        Ok(deleted > 0)
    }

    async fn set_report_active(
        &self,
        id: Uuid,
        active: bool,
    ) -> anyhow::Result<Option<AmlReportRecord>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                r#"
                UPDATE aml_risk_reports
                SET active = $2
                WHERE id = $1
                RETURNING *
                "#,
                &[&id, &active],
            )
            .await?;
        row.map(Self::report_from_row).transpose()
    }
}
