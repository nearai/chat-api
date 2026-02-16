use crate::pool::DbPool;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use services::agent::ports::{
    AgentApiKey, AgentInstance, AgentRepository, CreateInstanceParams, InstanceBalance,
    UsageLogEntry,
};
use services::UserId;
use uuid::Uuid;

pub struct PostgresAgentRepository {
    pool: DbPool,
}

impl PostgresAgentRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AgentRepository for PostgresAgentRepository {
    async fn create_instance(&self, params: CreateInstanceParams) -> anyhow::Result<AgentInstance> {
        tracing::debug!(
            "Creating instance in DB: user_id={}, instance_id={}",
            params.user_id,
            params.instance_id
        );

        let client = self.pool.get().await?;

        let row = client
            .query_one(
                "INSERT INTO agent_instances (user_id, instance_id, name, public_ssh_key, instance_url, instance_token, gateway_port, dashboard_url)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 RETURNING id, user_id, instance_id, name, public_ssh_key, instance_url, instance_token, gateway_port, dashboard_url, created_at, updated_at",
                &[&params.user_id, &params.instance_id, &params.name, &params.public_ssh_key, &params.instance_url, &params.instance_token, &params.gateway_port, &params.dashboard_url],
            )
            .await?;

        let instance = AgentInstance {
            id: row.get(0),
            user_id: row.get(1),
            instance_id: row.get(2),
            name: row.get(3),
            public_ssh_key: row.get(4),
            instance_url: row.get(5),
            instance_token: row.get(6),
            gateway_port: row.get(7),
            dashboard_url: row.get(8),
            created_at: row.get(9),
            updated_at: row.get(10),
        };

        Ok(instance)
    }

    async fn get_instance(&self, instance_id: Uuid) -> anyhow::Result<Option<AgentInstance>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, user_id, instance_id, name, public_ssh_key, instance_url, instance_token, gateway_port, dashboard_url, created_at, updated_at
                 FROM agent_instances
                 WHERE id = $1",
                &[&instance_id],
            )
            .await?;

        Ok(row.map(|r| AgentInstance {
            id: r.get(0),
            user_id: r.get(1),
            instance_id: r.get(2),
            name: r.get(3),
            public_ssh_key: r.get(4),
            instance_url: r.get(5),
            instance_token: r.get(6),
            gateway_port: r.get(7),
            dashboard_url: r.get(8),
            created_at: r.get(9),
            updated_at: r.get(10),
        }))
    }

    async fn get_instance_by_instance_id(
        &self,
        instance_id: &str,
    ) -> anyhow::Result<Option<AgentInstance>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, user_id, instance_id, name, public_ssh_key, instance_url, instance_token, gateway_port, dashboard_url, created_at, updated_at
                 FROM agent_instances
                 WHERE instance_id = $1",
                &[&instance_id],
            )
            .await?;

        Ok(row.map(|r| AgentInstance {
            id: r.get(0),
            user_id: r.get(1),
            instance_id: r.get(2),
            name: r.get(3),
            public_ssh_key: r.get(4),
            instance_url: r.get(5),
            instance_token: r.get(6),
            gateway_port: r.get(7),
            dashboard_url: r.get(8),
            created_at: r.get(9),
            updated_at: r.get(10),
        }))
    }

    async fn get_instance_by_api_key_hash(
        &self,
        key_hash: &str,
    ) -> anyhow::Result<Option<(AgentInstance, AgentApiKey)>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT oi.id, oi.user_id, oi.instance_id, oi.name, oi.public_ssh_key,
                        oi.instance_url, oi.instance_token, oi.gateway_port, oi.dashboard_url,
                        oi.created_at, oi.updated_at,
                        ak.id, ak.instance_id, ak.user_id, ak.name, ak.spend_limit,
                        ak.expires_at, ak.last_used_at, ak.is_active, ak.created_at, ak.updated_at
                 FROM agent_api_keys ak
                 JOIN agent_instances oi ON ak.instance_id = oi.id
                 WHERE ak.key_hash = $1 AND ak.is_active = true",
                &[&key_hash],
            )
            .await?;

        Ok(row.map(|r| {
            let instance = AgentInstance {
                id: r.get(0),
                user_id: r.get(1),
                instance_id: r.get(2),
                name: r.get(3),
                public_ssh_key: r.get(4),
                instance_url: r.get(5),
                instance_token: r.get(6),
                gateway_port: r.get(7),
                dashboard_url: r.get(8),
                created_at: r.get(9),
                updated_at: r.get(10),
            };
            let api_key = AgentApiKey {
                id: r.get(11),
                instance_id: r.get(12),
                user_id: r.get(13),
                name: r.get(14),
                spend_limit: r.get(15),
                expires_at: r.get(16),
                last_used_at: r.get(17),
                is_active: r.get(18),
                created_at: r.get(19),
                updated_at: r.get(20),
            };
            (instance, api_key)
        }))
    }

    async fn list_user_instances(
        &self,
        user_id: UserId,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<AgentInstance>, i64)> {
        let client = self.pool.get().await?;

        // Get total count
        let count_row = client
            .query_one(
                "SELECT COUNT(*) FROM agent_instances WHERE user_id = $1",
                &[&user_id],
            )
            .await?;
        let total: i64 = count_row.get(0);

        // Get paginated results
        let rows = client
            .query(
                "SELECT id, user_id, instance_id, name, public_ssh_key, instance_url, instance_token, gateway_port, dashboard_url, created_at, updated_at
                 FROM agent_instances
                 WHERE user_id = $1
                 ORDER BY created_at DESC
                 LIMIT $2 OFFSET $3",
                &[&user_id, &limit, &offset],
            )
            .await?;

        let instances = rows
            .into_iter()
            .map(|r| AgentInstance {
                id: r.get(0),
                user_id: r.get(1),
                instance_id: r.get(2),
                name: r.get(3),
                public_ssh_key: r.get(4),
                instance_url: r.get(5),
                instance_token: r.get(6),
                gateway_port: r.get(7),
                dashboard_url: r.get(8),
                created_at: r.get(9),
                updated_at: r.get(10),
            })
            .collect();

        Ok((instances, total))
    }

    async fn list_all_instances(
        &self,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<AgentInstance>, i64)> {
        let client = self.pool.get().await?;

        let count_row = client
            .query_one("SELECT COUNT(*) FROM agent_instances", &[])
            .await?;
        let total: i64 = count_row.get(0);

        let rows = client
            .query(
                "SELECT id, user_id, instance_id, name, public_ssh_key, instance_url, instance_token, gateway_port, dashboard_url, created_at, updated_at
                 FROM agent_instances
                 ORDER BY created_at DESC
                 LIMIT $1 OFFSET $2",
                &[&limit, &offset],
            )
            .await?;

        let instances = rows
            .into_iter()
            .map(|r| AgentInstance {
                id: r.get(0),
                user_id: r.get(1),
                instance_id: r.get(2),
                name: r.get(3),
                public_ssh_key: r.get(4),
                instance_url: r.get(5),
                instance_token: r.get(6),
                gateway_port: r.get(7),
                dashboard_url: r.get(8),
                created_at: r.get(9),
                updated_at: r.get(10),
            })
            .collect();

        Ok((instances, total))
    }

    async fn update_instance(
        &self,
        instance_id: Uuid,
        name: Option<String>,
        public_ssh_key: Option<String>,
    ) -> anyhow::Result<AgentInstance> {
        let client = self.pool.get().await?;

        // Build dynamic query based on which fields are provided
        match (name.clone(), public_ssh_key.clone()) {
            (Some(n), Some(key)) => {
                let row = client
                    .query_one(
                        "UPDATE agent_instances
                         SET name = $1, public_ssh_key = $2, updated_at = NOW()
                         WHERE id = $3
                         RETURNING id, user_id, instance_id, name, public_ssh_key, instance_url, instance_token, gateway_port, dashboard_url, created_at, updated_at",
                        &[&n, &key, &instance_id],
                    )
                    .await?;

                Ok(AgentInstance {
                    id: row.get(0),
                    user_id: row.get(1),
                    instance_id: row.get(2),
                    name: row.get(3),
                    public_ssh_key: row.get(4),
                    instance_url: row.get(5),
                    instance_token: row.get(6),
                    gateway_port: row.get(7),
                    dashboard_url: row.get(8),
                    created_at: row.get(9),
                    updated_at: row.get(10),
                })
            }
            (Some(n), None) => {
                let row = client
                    .query_one(
                        "UPDATE agent_instances
                         SET name = $1, updated_at = NOW()
                         WHERE id = $2
                         RETURNING id, user_id, instance_id, name, public_ssh_key, instance_url, instance_token, gateway_port, dashboard_url, created_at, updated_at",
                        &[&n, &instance_id],
                    )
                    .await?;

                Ok(AgentInstance {
                    id: row.get(0),
                    user_id: row.get(1),
                    instance_id: row.get(2),
                    name: row.get(3),
                    public_ssh_key: row.get(4),
                    instance_url: row.get(5),
                    instance_token: row.get(6),
                    gateway_port: row.get(7),
                    dashboard_url: row.get(8),
                    created_at: row.get(9),
                    updated_at: row.get(10),
                })
            }
            (None, Some(key)) => {
                let row = client
                    .query_one(
                        "UPDATE agent_instances
                         SET public_ssh_key = $1, updated_at = NOW()
                         WHERE id = $2
                         RETURNING id, user_id, instance_id, name, public_ssh_key, instance_url, instance_token, gateway_port, dashboard_url, created_at, updated_at",
                        &[&key, &instance_id],
                    )
                    .await?;

                Ok(AgentInstance {
                    id: row.get(0),
                    user_id: row.get(1),
                    instance_id: row.get(2),
                    name: row.get(3),
                    public_ssh_key: row.get(4),
                    instance_url: row.get(5),
                    instance_token: row.get(6),
                    gateway_port: row.get(7),
                    dashboard_url: row.get(8),
                    created_at: row.get(9),
                    updated_at: row.get(10),
                })
            }
            (None, None) => {
                // No changes, just return current instance
                let row = client
                    .query_one(
                        "SELECT id, user_id, instance_id, name, public_ssh_key, instance_url, instance_token, gateway_port, dashboard_url, created_at, updated_at
                         FROM agent_instances
                         WHERE id = $1",
                        &[&instance_id],
                    )
                    .await?;

                Ok(AgentInstance {
                    id: row.get(0),
                    user_id: row.get(1),
                    instance_id: row.get(2),
                    name: row.get(3),
                    public_ssh_key: row.get(4),
                    instance_url: row.get(5),
                    instance_token: row.get(6),
                    gateway_port: row.get(7),
                    dashboard_url: row.get(8),
                    created_at: row.get(9),
                    updated_at: row.get(10),
                })
            }
        }
    }

    async fn delete_instance(&self, instance_id: Uuid) -> anyhow::Result<()> {
        let client = self.pool.get().await?;

        client
            .execute("DELETE FROM agent_instances WHERE id = $1", &[&instance_id])
            .await?;

        Ok(())
    }

    async fn create_api_key(
        &self,
        instance_id: Uuid,
        user_id: UserId,
        key_hash: String,
        name: String,
        spend_limit: Option<i64>,
        expires_at: Option<DateTime<Utc>>,
    ) -> anyhow::Result<AgentApiKey> {
        let client = self.pool.get().await?;

        let row = client
            .query_one(
                "INSERT INTO agent_api_keys
                 (instance_id, user_id, key_hash, name, spend_limit, expires_at, is_active)
                 VALUES ($1, $2, $3, $4, $5, $6, true)
                 RETURNING id, instance_id, user_id, name, spend_limit, expires_at,
                           last_used_at, is_active, created_at, updated_at",
                &[
                    &instance_id,
                    &user_id,
                    &key_hash,
                    &name,
                    &spend_limit,
                    &expires_at,
                ],
            )
            .await?;

        let api_key = AgentApiKey {
            id: row.get(0),
            instance_id: row.get(1),
            user_id: row.get(2),
            name: row.get(3),
            spend_limit: row.get(4),
            expires_at: row.get(5),
            last_used_at: row.get(6),
            is_active: row.get(7),
            created_at: row.get(8),
            updated_at: row.get(9),
        };

        Ok(api_key)
    }

    async fn create_unbound_api_key(
        &self,
        user_id: UserId,
        key_hash: String,
        name: String,
        spend_limit: Option<i64>,
        expires_at: Option<DateTime<Utc>>,
    ) -> anyhow::Result<AgentApiKey> {
        tracing::debug!("Creating unbound API key in DB: user_id={}", user_id);

        let client = self.pool.get().await?;

        let row = client
            .query_one(
                "INSERT INTO agent_api_keys (instance_id, user_id, key_hash, name, spend_limit, expires_at)
                 VALUES (NULL, $1, $2, $3, $4, $5)
                 RETURNING id, instance_id, user_id, name, spend_limit, expires_at,
                           last_used_at, is_active, created_at, updated_at",
                &[&user_id, &key_hash, &name, &spend_limit, &expires_at],
            )
            .await?;

        let api_key = AgentApiKey {
            id: row.get(0),
            instance_id: row.get(1),
            user_id: row.get(2),
            name: row.get(3),
            spend_limit: row.get(4),
            expires_at: row.get(5),
            last_used_at: row.get(6),
            is_active: row.get(7),
            created_at: row.get(8),
            updated_at: row.get(9),
        };

        Ok(api_key)
    }

    async fn bind_api_key_to_instance(
        &self,
        api_key_id: Uuid,
        instance_id: Uuid,
    ) -> anyhow::Result<()> {
        tracing::debug!(
            "Binding API key to instance: api_key_id={}, instance_id={}",
            api_key_id,
            instance_id
        );

        let client = self.pool.get().await?;

        client
            .execute(
                "UPDATE agent_api_keys SET instance_id = $1, updated_at = NOW() WHERE id = $2",
                &[&instance_id, &api_key_id],
            )
            .await?;

        Ok(())
    }

    async fn get_api_key_by_hash(&self, key_hash: &str) -> anyhow::Result<Option<AgentApiKey>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, instance_id, user_id, name, spend_limit, expires_at,
                        last_used_at, is_active, created_at, updated_at
                 FROM agent_api_keys
                 WHERE key_hash = $1",
                &[&key_hash],
            )
            .await?;

        Ok(row.map(|r| AgentApiKey {
            id: r.get(0),
            instance_id: r.get(1),
            user_id: r.get(2),
            name: r.get(3),
            spend_limit: r.get(4),
            expires_at: r.get(5),
            last_used_at: r.get(6),
            is_active: r.get(7),
            created_at: r.get(8),
            updated_at: r.get(9),
        }))
    }

    async fn get_api_key_by_id(&self, api_key_id: Uuid) -> anyhow::Result<Option<AgentApiKey>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, instance_id, user_id, name, spend_limit, expires_at,
                        last_used_at, is_active, created_at, updated_at
                 FROM agent_api_keys
                 WHERE id = $1",
                &[&api_key_id],
            )
            .await?;

        Ok(row.map(|r| AgentApiKey {
            id: r.get(0),
            instance_id: r.get(1),
            user_id: r.get(2),
            name: r.get(3),
            spend_limit: r.get(4),
            expires_at: r.get(5),
            last_used_at: r.get(6),
            is_active: r.get(7),
            created_at: r.get(8),
            updated_at: r.get(9),
        }))
    }

    async fn list_instance_keys(
        &self,
        instance_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<AgentApiKey>, i64)> {
        let client = self.pool.get().await?;

        // Get total count
        let count_row = client
            .query_one(
                "SELECT COUNT(*) FROM agent_api_keys WHERE instance_id = $1",
                &[&instance_id],
            )
            .await?;
        let total: i64 = count_row.get(0);

        // Get paginated results
        let rows = client
            .query(
                "SELECT id, instance_id, user_id, name, spend_limit, expires_at,
                        last_used_at, is_active, created_at, updated_at
                 FROM agent_api_keys
                 WHERE instance_id = $1
                 ORDER BY created_at DESC
                 LIMIT $2 OFFSET $3",
                &[&instance_id, &limit, &offset],
            )
            .await?;

        let keys = rows
            .into_iter()
            .map(|r| AgentApiKey {
                id: r.get(0),
                instance_id: r.get(1),
                user_id: r.get(2),
                name: r.get(3),
                spend_limit: r.get(4),
                expires_at: r.get(5),
                last_used_at: r.get(6),
                is_active: r.get(7),
                created_at: r.get(8),
                updated_at: r.get(9),
            })
            .collect();

        Ok((keys, total))
    }

    async fn revoke_api_key(&self, api_key_id: Uuid) -> anyhow::Result<()> {
        let client = self.pool.get().await?;

        client
            .execute(
                "UPDATE agent_api_keys SET is_active = false, updated_at = NOW() WHERE id = $1",
                &[&api_key_id],
            )
            .await?;

        Ok(())
    }

    async fn update_api_key_last_used(&self, api_key_id: Uuid) -> anyhow::Result<()> {
        let client = self.pool.get().await?;

        client
            .execute(
                "UPDATE agent_api_keys SET last_used_at = NOW() WHERE id = $1",
                &[&api_key_id],
            )
            .await?;

        Ok(())
    }

    async fn log_usage(&self, usage: UsageLogEntry) -> anyhow::Result<()> {
        let client = self.pool.get().await?;

        client
            .execute(
                "INSERT INTO agent_usage_log
                 (id, user_id, instance_id, api_key_id, input_tokens, output_tokens, total_tokens,
                  input_cost, output_cost, total_cost, model_id, request_type, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
                &[
                    &usage.id,
                    &usage.user_id,
                    &usage.instance_id,
                    &usage.api_key_id,
                    &usage.input_tokens,
                    &usage.output_tokens,
                    &usage.total_tokens,
                    &usage.input_cost,
                    &usage.output_cost,
                    &usage.total_cost,
                    &usage.model_id,
                    &usage.request_type,
                    &usage.created_at,
                ],
            )
            .await?;

        Ok(())
    }

    async fn get_instance_usage(
        &self,
        instance_id: Uuid,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<UsageLogEntry>, i64)> {
        let client = self.pool.get().await?;

        // Get total count
        let total = if let (Some(start), Some(end)) = (start_date, end_date) {
            let count_row = client
                .query_one(
                    "SELECT COUNT(*) FROM agent_usage_log
                     WHERE instance_id = $1 AND created_at >= $2 AND created_at <= $3",
                    &[&instance_id, &start, &end],
                )
                .await?;
            count_row.get(0)
        } else if let Some(start) = start_date {
            let count_row = client
                .query_one(
                    "SELECT COUNT(*) FROM agent_usage_log
                     WHERE instance_id = $1 AND created_at >= $2",
                    &[&instance_id, &start],
                )
                .await?;
            count_row.get(0)
        } else if let Some(end) = end_date {
            let count_row = client
                .query_one(
                    "SELECT COUNT(*) FROM agent_usage_log
                     WHERE instance_id = $1 AND created_at <= $2",
                    &[&instance_id, &end],
                )
                .await?;
            count_row.get(0)
        } else {
            let count_row = client
                .query_one(
                    "SELECT COUNT(*) FROM agent_usage_log WHERE instance_id = $1",
                    &[&instance_id],
                )
                .await?;
            count_row.get(0)
        };

        // Get paginated results
        let rows = if let (Some(start), Some(end)) = (start_date, end_date) {
            client
                .query(
                    "SELECT id, user_id, instance_id, api_key_id, input_tokens, output_tokens,
                            total_tokens, input_cost, output_cost, total_cost, model_id,
                            request_type, created_at
                     FROM agent_usage_log
                     WHERE instance_id = $1 AND created_at >= $2 AND created_at <= $3
                     ORDER BY created_at DESC
                     LIMIT $4 OFFSET $5",
                    &[&instance_id, &start, &end, &limit, &offset],
                )
                .await?
        } else if let Some(start) = start_date {
            client
                .query(
                    "SELECT id, user_id, instance_id, api_key_id, input_tokens, output_tokens,
                            total_tokens, input_cost, output_cost, total_cost, model_id,
                            request_type, created_at
                     FROM agent_usage_log
                     WHERE instance_id = $1 AND created_at >= $2
                     ORDER BY created_at DESC
                     LIMIT $3 OFFSET $4",
                    &[&instance_id, &start, &limit, &offset],
                )
                .await?
        } else if let Some(end) = end_date {
            client
                .query(
                    "SELECT id, user_id, instance_id, api_key_id, input_tokens, output_tokens,
                            total_tokens, input_cost, output_cost, total_cost, model_id,
                            request_type, created_at
                     FROM agent_usage_log
                     WHERE instance_id = $1 AND created_at <= $2
                     ORDER BY created_at DESC
                     LIMIT $3 OFFSET $4",
                    &[&instance_id, &end, &limit, &offset],
                )
                .await?
        } else {
            client
                .query(
                    "SELECT id, user_id, instance_id, api_key_id, input_tokens, output_tokens,
                            total_tokens, input_cost, output_cost, total_cost, model_id,
                            request_type, created_at
                     FROM agent_usage_log
                     WHERE instance_id = $1
                     ORDER BY created_at DESC
                     LIMIT $2 OFFSET $3",
                    &[&instance_id, &limit, &offset],
                )
                .await?
        };

        let usage = rows
            .into_iter()
            .map(|r| UsageLogEntry {
                id: r.get(0),
                user_id: r.get(1),
                instance_id: r.get(2),
                api_key_id: r.get(3),
                input_tokens: r.get(4),
                output_tokens: r.get(5),
                total_tokens: r.get(6),
                input_cost: r.get(7),
                output_cost: r.get(8),
                total_cost: r.get(9),
                model_id: r.get(10),
                request_type: r.get(11),
                created_at: r.get(12),
            })
            .collect();

        Ok((usage, total))
    }

    async fn get_instance_balance(
        &self,
        instance_id: Uuid,
    ) -> anyhow::Result<Option<InstanceBalance>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT instance_id, total_spent, total_requests, total_tokens,
                        last_usage_at, updated_at
                 FROM agent_balance
                 WHERE instance_id = $1",
                &[&instance_id],
            )
            .await?;

        Ok(row.map(|r| InstanceBalance {
            instance_id: r.get(0),
            total_spent: r.get(1),
            total_requests: r.get(2),
            total_tokens: r.get(3),
            last_usage_at: r.get(4),
            updated_at: r.get(5),
        }))
    }

    async fn update_instance_balance(
        &self,
        instance_id: Uuid,
        total_cost: i64,
    ) -> anyhow::Result<()> {
        let client = self.pool.get().await?;

        client
            .execute(
                "UPDATE agent_balance
                 SET total_spent = total_spent + $1,
                     total_requests = total_requests + 1,
                     last_usage_at = NOW(),
                     updated_at = NOW()
                 WHERE instance_id = $2",
                &[&total_cost, &instance_id],
            )
            .await?;

        Ok(())
    }

    /// ATOMIC: Log usage and update balance in a single transaction
    /// This ensures financial consistency - if one fails, both are rolled back
    async fn log_usage_and_update_balance(&self, usage: UsageLogEntry) -> anyhow::Result<()> {
        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;

        // Log usage
        transaction
            .execute(
                "INSERT INTO agent_usage_log
                 (id, user_id, instance_id, api_key_id, input_tokens, output_tokens, total_tokens,
                  input_cost, output_cost, total_cost, model_id, request_type, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
                &[
                    &usage.id,
                    &usage.user_id,
                    &usage.instance_id,
                    &usage.api_key_id,
                    &usage.input_tokens,
                    &usage.output_tokens,
                    &usage.total_tokens,
                    &usage.input_cost,
                    &usage.output_cost,
                    &usage.total_cost,
                    &usage.model_id,
                    &usage.request_type,
                    &usage.created_at,
                ],
            )
            .await?;

        // Update balance (including token tracking)
        transaction
            .execute(
                "UPDATE agent_balance
                 SET total_spent = total_spent + $1,
                     total_requests = total_requests + 1,
                     total_tokens = total_tokens + $2,
                     last_usage_at = NOW(),
                     updated_at = NOW()
                 WHERE instance_id = $3",
                &[&usage.total_cost, &usage.total_tokens, &usage.instance_id],
            )
            .await?;

        // Commit transaction
        transaction.commit().await?;

        Ok(())
    }

    async fn get_user_total_spending(&self, user_id: UserId) -> anyhow::Result<i64> {
        let client = self.pool.get().await?;

        let row = client
            .query_one(
                "SELECT COALESCE(SUM(total_spent), 0)
                 FROM agent_balance
                 WHERE instance_id IN (SELECT id FROM agent_instances WHERE user_id = $1)",
                &[&user_id],
            )
            .await?;

        Ok(row.get(0))
    }
}
