use crate::pool::DbPool;
use async_trait::async_trait;
use services::subscription::ports::{PaymentWebhook, PaymentWebhookRepository};

pub struct PostgresPaymentWebhookRepository {
    #[allow(dead_code)]
    pool: DbPool,
}

impl PostgresPaymentWebhookRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PaymentWebhookRepository for PostgresPaymentWebhookRepository {
    async fn store_webhook(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        provider: String,
        event_id: String,
        payload: serde_json::Value,
    ) -> anyhow::Result<PaymentWebhook> {
        tracing::info!(
            "Repository: Storing payment webhook - provider={}, event_id={}",
            provider,
            event_id
        );

        // This query is idempotent due to UNIQUE(provider, event_id) constraint
        let result = txn
            .query_opt(
                "INSERT INTO payment_webhooks (provider, event_id, payload)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (provider, event_id) DO NOTHING
                 RETURNING id, provider, event_id, payload, created_at",
                &[&provider, &event_id, &payload],
            )
            .await?;

        if let Some(row) = result {
            Ok(PaymentWebhook {
                id: row.get("id"),
                provider: row.get("provider"),
                event_id: row.get("event_id"),
                payload: row.get("payload"),
                created_at: row.get("created_at"),
            })
        } else {
            // Webhook already exists, fetch it
            tracing::debug!(
                "Repository: Webhook already exists, fetching - provider={}, event_id={}",
                provider,
                event_id
            );

            let row = txn
                .query_one(
                    "SELECT id, provider, event_id, payload, created_at
                     FROM payment_webhooks
                     WHERE provider = $1 AND event_id = $2",
                    &[&provider, &event_id],
                )
                .await?;

            Ok(PaymentWebhook {
                id: row.get("id"),
                provider: row.get("provider"),
                event_id: row.get("event_id"),
                payload: row.get("payload"),
                created_at: row.get("created_at"),
            })
        }
    }
}
