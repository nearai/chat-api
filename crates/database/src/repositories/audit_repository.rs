use crate::pool::DbPool;
use async_trait::async_trait;
use services::{
    audit::ports::{
        ActorType, AuditLog, AuditLogQuery, AuditRepository, AuditStatus, CreateAuditLogParams,
    },
    OrganizationId,
};
use std::net::IpAddr;

pub struct PostgresAuditRepository {
    pool: DbPool,
}

impl PostgresAuditRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuditRepository for PostgresAuditRepository {
    async fn create_audit_log(&self, params: CreateAuditLogParams) -> anyhow::Result<i64> {
        tracing::debug!(
            "Repository: Creating audit log action={}, resource_type={}",
            params.action,
            params.resource_type
        );

        let client = self.pool.get().await?;

        let row = client
            .query_one(
                "INSERT INTO audit_logs (
                    organization_id, workspace_id, actor_id, actor_type, actor_ip,
                    actor_user_agent, action, resource_type, resource_id, changes,
                    metadata, status, error_message
                 )
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                 RETURNING id",
                &[
                    &params.organization_id,
                    &params.workspace_id,
                    &params.actor_id,
                    &params.actor_type.as_str(),
                    &params.actor_ip,
                    &params.actor_user_agent,
                    &params.action,
                    &params.resource_type,
                    &params.resource_id,
                    &params.changes,
                    &params.metadata,
                    &params.status.as_str(),
                    &params.error_message,
                ],
            )
            .await?;

        let log_id: i64 = row.get(0);

        tracing::debug!("Repository: Audit log created log_id={}", log_id);

        Ok(log_id)
    }

    async fn query_audit_logs(
        &self,
        query: AuditLogQuery,
    ) -> anyhow::Result<(Vec<AuditLog>, u64)> {
        tracing::debug!(
            "Repository: Querying audit logs for organization_id={}",
            query.organization_id
        );

        let client = self.pool.get().await?;

        // Build dynamic query
        let mut conditions = vec!["organization_id = $1".to_string()];
        let mut param_idx = 2;
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> =
            vec![Box::new(query.organization_id)];

        if let Some(ref workspace_id) = query.workspace_id {
            conditions.push(format!("workspace_id = ${}", param_idx));
            params.push(Box::new(*workspace_id));
            param_idx += 1;
        }

        if let Some(ref actor_id) = query.actor_id {
            conditions.push(format!("actor_id = ${}", param_idx));
            params.push(Box::new(*actor_id));
            param_idx += 1;
        }

        if let Some(ref action) = query.action {
            conditions.push(format!("action = ${}", param_idx));
            params.push(Box::new(action.clone()));
            param_idx += 1;
        }

        if let Some(ref resource_type) = query.resource_type {
            conditions.push(format!("resource_type = ${}", param_idx));
            params.push(Box::new(resource_type.clone()));
            param_idx += 1;
        }

        if let Some(ref resource_id) = query.resource_id {
            conditions.push(format!("resource_id = ${}", param_idx));
            params.push(Box::new(resource_id.clone()));
            param_idx += 1;
        }

        if let Some(ref status) = query.status {
            conditions.push(format!("status = ${}", param_idx));
            params.push(Box::new(status.as_str().to_string()));
            param_idx += 1;
        }

        if let Some(ref from_date) = query.from_date {
            conditions.push(format!("created_at >= ${}", param_idx));
            params.push(Box::new(*from_date));
            param_idx += 1;
        }

        if let Some(ref to_date) = query.to_date {
            conditions.push(format!("created_at <= ${}", param_idx));
            params.push(Box::new(*to_date));
            param_idx += 1;
        }

        params.push(Box::new(query.limit));
        let limit_idx = param_idx;
        param_idx += 1;

        params.push(Box::new(query.offset));
        let offset_idx = param_idx;

        let sql = format!(
            "SELECT id, organization_id, workspace_id, actor_id, actor_type, actor_ip,
                    actor_user_agent, action, resource_type, resource_id, changes,
                    metadata, status, error_message, created_at,
                    COUNT(*) OVER() as total_count
             FROM audit_logs
             WHERE {}
             ORDER BY created_at DESC
             LIMIT ${} OFFSET ${}",
            conditions.join(" AND "),
            limit_idx,
            offset_idx
        );

        let query_params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|v| v.as_ref() as _).collect();

        let rows = client.query(&sql, &query_params).await?;

        let total_count: i64 = if rows.is_empty() {
            0
        } else {
            rows[0].get("total_count")
        };

        let logs = rows
            .into_iter()
            .map(|r| AuditLog {
                id: r.get(0),
                organization_id: r.get(1),
                workspace_id: r.get(2),
                actor_id: r.get(3),
                actor_type: ActorType::from_str(r.get::<_, String>(4).as_str())
                    .unwrap_or_default(),
                actor_ip: r.get::<_, Option<IpAddr>>(5),
                actor_user_agent: r.get(6),
                action: r.get(7),
                resource_type: r.get(8),
                resource_id: r.get(9),
                changes: r.get(10),
                metadata: r.get(11),
                status: AuditStatus::from_str(r.get::<_, String>(12).as_str())
                    .unwrap_or_default(),
                error_message: r.get(13),
                created_at: r.get(14),
            })
            .collect();

        Ok((logs, total_count as u64))
    }

    async fn get_audit_log(
        &self,
        organization_id: OrganizationId,
        log_id: i64,
    ) -> anyhow::Result<Option<AuditLog>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, organization_id, workspace_id, actor_id, actor_type, actor_ip,
                        actor_user_agent, action, resource_type, resource_id, changes,
                        metadata, status, error_message, created_at
                 FROM audit_logs
                 WHERE id = $1 AND organization_id = $2",
                &[&log_id, &organization_id],
            )
            .await?;

        Ok(row.map(|r| AuditLog {
            id: r.get(0),
            organization_id: r.get(1),
            workspace_id: r.get(2),
            actor_id: r.get(3),
            actor_type: ActorType::from_str(r.get::<_, String>(4).as_str())
                .unwrap_or_default(),
            actor_ip: r.get::<_, Option<IpAddr>>(5),
            actor_user_agent: r.get(6),
            action: r.get(7),
            resource_type: r.get(8),
            resource_id: r.get(9),
            changes: r.get(10),
            metadata: r.get(11),
            status: AuditStatus::from_str(r.get::<_, String>(12).as_str())
                .unwrap_or_default(),
            error_message: r.get(13),
            created_at: r.get(14),
        }))
    }
}
