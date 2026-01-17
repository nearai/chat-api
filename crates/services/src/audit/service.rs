use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::mpsc;

use super::ports::{
    AuditLog, AuditLogQuery, AuditRepository, AuditService, CreateAuditLogParams, ExportFormat,
};
use crate::types::OrganizationId;

pub struct AuditServiceImpl {
    repository: Arc<dyn AuditRepository>,
    log_sender: mpsc::UnboundedSender<CreateAuditLogParams>,
}

impl AuditServiceImpl {
    pub fn new(repository: Arc<dyn AuditRepository>) -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();

        // Spawn background task to process audit logs
        let repo = repository.clone();
        tokio::spawn(Self::process_logs(repo, receiver));

        Self {
            repository,
            log_sender: sender,
        }
    }

    async fn process_logs(
        repository: Arc<dyn AuditRepository>,
        mut receiver: mpsc::UnboundedReceiver<CreateAuditLogParams>,
    ) {
        while let Some(params) = receiver.recv().await {
            if let Err(e) = repository.create_audit_log(params).await {
                tracing::error!("Failed to create audit log: {}", e);
            }
        }
    }

    fn export_to_csv(logs: &[AuditLog]) -> anyhow::Result<Vec<u8>> {
        let mut wtr = csv::Writer::from_writer(vec![]);

        // Write header
        wtr.write_record([
            "id",
            "organization_id",
            "workspace_id",
            "actor_id",
            "actor_type",
            "actor_ip",
            "action",
            "resource_type",
            "resource_id",
            "status",
            "error_message",
            "created_at",
        ])?;

        // Write records
        for log in logs {
            wtr.write_record([
                log.id.to_string(),
                log.organization_id.to_string(),
                log.workspace_id.map(|w| w.to_string()).unwrap_or_default(),
                log.actor_id.map(|a| a.to_string()).unwrap_or_default(),
                log.actor_type.as_str().to_string(),
                log.actor_ip.map(|ip| ip.to_string()).unwrap_or_default(),
                log.action.clone(),
                log.resource_type.clone(),
                log.resource_id.clone().unwrap_or_default(),
                log.status.as_str().to_string(),
                log.error_message.clone().unwrap_or_default(),
                log.created_at.to_rfc3339(),
            ])?;
        }

        Ok(wtr.into_inner()?)
    }
}

#[async_trait]
impl AuditService for AuditServiceImpl {
    fn log(&self, params: CreateAuditLogParams) {
        // Fire-and-forget: send to background task
        if let Err(e) = self.log_sender.send(params) {
            tracing::error!("Failed to send audit log to background task: {}", e);
        }
    }

    async fn log_sync(&self, params: CreateAuditLogParams) -> anyhow::Result<i64> {
        tracing::debug!(
            "Creating audit log: action={}, resource_type={}, org_id={}",
            params.action,
            params.resource_type,
            params.organization_id
        );

        let log_id = self.repository.create_audit_log(params).await?;

        tracing::debug!("Audit log created: log_id={}", log_id);

        Ok(log_id)
    }

    async fn query(&self, query: AuditLogQuery) -> anyhow::Result<(Vec<AuditLog>, u64)> {
        tracing::info!(
            "Querying audit logs: org_id={}, limit={}, offset={}",
            query.organization_id,
            query.limit,
            query.offset
        );

        self.repository.query_audit_logs(query).await
    }

    async fn export(
        &self,
        query: AuditLogQuery,
        format: ExportFormat,
    ) -> anyhow::Result<Vec<u8>> {
        tracing::info!(
            "Exporting audit logs: org_id={}, format={:?}",
            query.organization_id,
            format
        );

        // Get all matching logs (with high limit for export)
        let export_query = AuditLogQuery {
            limit: 10000, // Max export limit
            offset: 0,
            ..query
        };

        let (logs, _total) = self.repository.query_audit_logs(export_query).await?;

        match format {
            ExportFormat::Json => {
                let json = serde_json::to_vec_pretty(&logs)?;
                Ok(json)
            }
            ExportFormat::Csv => Self::export_to_csv(&logs),
        }
    }

    async fn get_audit_log(
        &self,
        organization_id: OrganizationId,
        log_id: i64,
    ) -> anyhow::Result<AuditLog> {
        tracing::info!(
            "Getting audit log: org_id={}, log_id={}",
            organization_id,
            log_id
        );

        self.repository
            .get_audit_log(organization_id, log_id)
            .await?
            .ok_or_else(|| {
                tracing::error!(
                    "Audit log not found: org_id={}, log_id={}",
                    organization_id,
                    log_id
                );
                anyhow::anyhow!("Audit log not found")
            })
    }
}
