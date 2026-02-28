use crate::pool::DbPool;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use services::bi_metrics::{
    BiMetricsRepository, DeploymentFilter, DeploymentRecord, DeploymentStatusCount,
    DeploymentSummary, StatusChangeRecord, TopConsumer, TopConsumerFilter, TopConsumerGroupBy,
    UsageAggregation, UsageFilter, UsageGroupBy, UsageRankBy,
};
use uuid::Uuid;

/// Statement timeout for heavy aggregation queries (30 seconds).
const AGGREGATION_TIMEOUT_MS: u32 = 30_000;

/// Hard limit for unbounded queries (status history, usage aggregation).
const MAX_UNBOUNDED_ROWS: i64 = 1000;

pub struct PostgresBiMetricsRepository {
    pool: DbPool,
}

impl PostgresBiMetricsRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

/// Helper to build dynamic WHERE clauses and collect parameterized values.
struct QueryBuilder {
    conditions: Vec<String>,
    params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>>,
}

impl QueryBuilder {
    fn new() -> Self {
        Self {
            conditions: Vec::new(),
            params: Vec::new(),
        }
    }

    /// Current 1-based parameter index for the next parameter.
    fn next_param_idx(&self) -> u32 {
        self.params.len() as u32 + 1
    }

    /// Push a condition with a parameterized value.
    fn push<T: tokio_postgres::types::ToSql + Sync + Send + 'static>(
        &mut self,
        col: &str,
        op: &str,
        value: T,
    ) {
        let idx = self.next_param_idx();
        self.conditions.push(format!("{col} {op} ${idx}"));
        self.params.push(Box::new(value));
    }

    fn where_clause(&self) -> String {
        if self.conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", self.conditions.join(" AND "))
        }
    }

    fn param_refs(&self) -> Vec<&(dyn tokio_postgres::types::ToSql + Sync)> {
        self.params.iter().map(|p| p.as_ref() as _).collect()
    }
}

#[async_trait]
impl BiMetricsRepository for PostgresBiMetricsRepository {
    async fn list_deployments(
        &self,
        filter: &DeploymentFilter,
    ) -> anyhow::Result<(Vec<DeploymentRecord>, i64)> {
        let client = self.pool.get().await?;

        let mut qb = QueryBuilder::new();

        if let Some(ref t) = filter.instance_type {
            qb.push("ai.type", "=", t.clone());
        }
        if let Some(ref s) = filter.status {
            qb.push("ai.status", "=", s.clone());
        }
        if let Some(sd) = filter.start_date {
            qb.push("ai.created_at", ">=", sd);
        }
        if let Some(ed) = filter.end_date {
            qb.push("ai.created_at", "<=", ed);
        }

        let where_clause = qb.where_clause();

        // Use COUNT(*) OVER() window function to get total in a single query
        // LEFT JOIN users to get user_email and user_name for admin display
        let limit_idx = qb.next_param_idx();
        let offset_idx = limit_idx + 1;
        let data_sql = format!(
            "SELECT ai.id, ai.user_id, u.email, u.name, u.avatar_url, ai.instance_id, ai.type, ai.status, ai.created_at, ai.updated_at,
                    COUNT(*) OVER() as total_count
             FROM agent_instances ai
             LEFT JOIN users u ON ai.user_id = u.id
             {where_clause}
             ORDER BY ai.created_at DESC
             LIMIT ${limit_idx} OFFSET ${offset_idx}"
        );
        qb.params.push(Box::new(filter.limit));
        qb.params.push(Box::new(filter.offset));

        let rows = client.query(&data_sql, &qb.param_refs()).await?;

        let total: i64 = rows.first().map(|r| r.get(10)).unwrap_or(0);

        let records = rows
            .into_iter()
            .map(|r| DeploymentRecord {
                id: r.get(0),
                user_id: r.get(1),
                user_email: r.get(2),
                user_name: r.get(3),
                user_avatar_url: r.get(4),
                instance_id: r.get(5),
                instance_type: r.get(6),
                status: r.get(7),
                created_at: r.get(8),
                updated_at: r.get(9),
            })
            .collect();

        Ok((records, total))
    }

    async fn get_deployment_summary(
        &self,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
    ) -> anyhow::Result<DeploymentSummary> {
        let mut client = self.pool.get().await?;

        // Run all summary queries in a single REPEATABLE READ transaction
        let tx = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .start()
            .await?;

        // Total deployments (all time, all statuses)
        let total_row = tx
            .query_one("SELECT COUNT(*) FROM agent_instances", &[])
            .await?;
        let total_deployments: i64 = total_row.get(0);

        // Counts by type + status
        let breakdown_rows = tx
            .query(
                "SELECT type, status, COUNT(*) as cnt
                 FROM agent_instances
                 GROUP BY type, status
                 ORDER BY type, status",
                &[],
            )
            .await?;

        let counts_by_type_status = breakdown_rows
            .into_iter()
            .map(|r| DeploymentStatusCount {
                instance_type: r.get(0),
                status: r.get(1),
                count: r.get(2),
            })
            .collect();

        // New deployments in range (created_at within range)
        let new_deployments_in_range = if start_date.is_none() && end_date.is_none() {
            total_deployments
        } else {
            let mut qb = QueryBuilder::new();
            if let Some(sd) = start_date {
                qb.push("created_at", ">=", sd);
            }
            if let Some(ed) = end_date {
                qb.push("created_at", "<=", ed);
            }
            let where_clause = qb.where_clause();
            let sql = format!("SELECT COUNT(*) FROM agent_instances {where_clause}");
            let row = tx.query_one(&sql, &qb.param_refs()).await?;
            row.get(0)
        };

        // Deleted in range: count transitions to 'deleted' in status history
        let deleted_in_range = {
            let mut qb = QueryBuilder::new();
            qb.push("new_status", "=", "deleted".to_string());
            if let Some(sd) = start_date {
                qb.push("changed_at", ">=", sd);
            }
            if let Some(ed) = end_date {
                qb.push("changed_at", "<=", ed);
            }
            let where_clause = qb.where_clause();
            let sql = format!("SELECT COUNT(*) FROM agent_instance_status_history {where_clause}");
            let row = tx.query_one(&sql, &qb.param_refs()).await?;
            row.get(0)
        };

        tx.commit().await?;

        Ok(DeploymentSummary {
            total_deployments,
            counts_by_type_status,
            new_deployments_in_range,
            deleted_in_range,
        })
    }

    async fn get_status_history(
        &self,
        instance_id: Uuid,
        limit: i64,
    ) -> anyhow::Result<Vec<StatusChangeRecord>> {
        let client = self.pool.get().await?;
        let capped_limit = limit.min(MAX_UNBOUNDED_ROWS);

        let rows = client
            .query(
                "SELECT id, instance_id, old_status, new_status, changed_at
                 FROM agent_instance_status_history
                 WHERE instance_id = $1
                 ORDER BY changed_at DESC
                 LIMIT $2",
                &[&instance_id, &capped_limit],
            )
            .await?;

        let records = rows
            .into_iter()
            .map(|r| StatusChangeRecord {
                id: r.get(0),
                instance_id: r.get(1),
                old_status: r.get(2),
                new_status: r.get(3),
                changed_at: r.get(4),
            })
            .collect();

        Ok(records)
    }

    async fn get_usage_aggregation(
        &self,
        filter: &UsageFilter,
    ) -> anyhow::Result<Vec<UsageAggregation>> {
        let mut client = self.pool.get().await?;

        // Wrap in a transaction so SET LOCAL statement_timeout takes effect
        let tx = client.build_transaction().start().await?;
        tx.execute(
            &format!("SET LOCAL statement_timeout = '{AGGREGATION_TIMEOUT_MS}'"),
            &[],
        )
        .await?;

        // Determine GROUP BY, SELECT, and user-join expressions
        let (group_expr, select_expr, user_select, user_group) = match filter.group_by {
            UsageGroupBy::Day => (
                "DATE(u.created_at)",
                "CAST(DATE(u.created_at) AS TEXT) as group_key",
                "NULL::TEXT as user_email, NULL::TEXT as user_name, NULL::TEXT as user_avatar_url",
                "",
            ),
            UsageGroupBy::User => (
                "u.user_id, u2.email, u2.name, u2.avatar_url",
                "CAST(u.user_id AS TEXT) as group_key",
                "u2.email as user_email, u2.name as user_name, u2.avatar_url as user_avatar_url",
                "LEFT JOIN users u2 ON u.user_id = u2.id",
            ),
            UsageGroupBy::Instance => (
                "u.instance_id",
                "CAST(u.instance_id AS TEXT) as group_key",
                "NULL::TEXT as user_email, NULL::TEXT as user_name, NULL::TEXT as user_avatar_url",
                "",
            ),
            UsageGroupBy::Model => (
                "COALESCE(u.model_id, 'unknown')",
                "COALESCE(u.model_id, 'unknown') as group_key",
                "NULL::TEXT as user_email, NULL::TEXT as user_name, NULL::TEXT as user_avatar_url",
                "",
            ),
        };

        let mut qb = QueryBuilder::new();

        // Only include agent rows (instance_id IS NOT NULL)
        qb.conditions.push("u.instance_id IS NOT NULL".to_string());

        if let Some(sd) = filter.start_date {
            qb.push("u.created_at", ">=", sd);
        }
        if let Some(ed) = filter.end_date {
            qb.push("u.created_at", "<=", ed);
        }
        if let Some(uid) = filter.user_id {
            qb.push("u.user_id", "=", uid);
        }
        if let Some(iid) = filter.instance_id {
            qb.push("u.instance_id", "=", iid);
        }
        if let Some(ref t) = filter.instance_type {
            qb.push("ai.type", "=", t.clone());
        }

        let join_clause = if filter.instance_type.is_some() {
            "JOIN agent_instances ai ON u.instance_id = ai.id"
        } else {
            ""
        };

        let where_clause = qb.where_clause();
        let limit_idx = qb.next_param_idx();
        qb.params.push(Box::new(filter.limit));

        let sql = format!(
            "SELECT {select_expr},
                    {user_select},
                    COALESCE(SUM((u.details->>'input_tokens')::BIGINT), 0)::BIGINT,
                    COALESCE(SUM((u.details->>'output_tokens')::BIGINT), 0)::BIGINT,
                    COALESCE(SUM(u.quantity), 0)::BIGINT,
                    COALESCE(SUM((u.details->>'input_cost')::BIGINT), 0)::BIGINT,
                    COALESCE(SUM((u.details->>'output_cost')::BIGINT), 0)::BIGINT,
                    COALESCE(SUM(u.cost_nano_usd), 0)::BIGINT,
                    COUNT(*)
             FROM user_usage_event u
             {join_clause}
             {user_group}
             {where_clause}
             GROUP BY {group_expr}
             ORDER BY {group_expr}
             LIMIT ${limit_idx}"
        );

        let rows = tx.query(&sql, &qb.param_refs()).await?;
        tx.commit().await?;

        let records = rows
            .into_iter()
            .map(|r| UsageAggregation {
                group_key: r.get(0),
                user_email: r.get(1),
                user_name: r.get(2),
                user_avatar_url: r.get(3),
                input_tokens: r.get(4),
                output_tokens: r.get(5),
                total_tokens: r.get(6),
                input_cost_nano: r.get(7),
                output_cost_nano: r.get(8),
                total_cost_nano: r.get(9),
                request_count: r.get(10),
            })
            .collect();

        Ok(records)
    }

    async fn get_top_consumers(
        &self,
        filter: &TopConsumerFilter,
    ) -> anyhow::Result<Vec<TopConsumer>> {
        let mut client = self.pool.get().await?;

        // Wrap in a transaction so SET LOCAL statement_timeout takes effect
        let tx = client.build_transaction().start().await?;
        tx.execute(
            &format!("SET LOCAL statement_timeout = '{AGGREGATION_TIMEOUT_MS}'"),
            &[],
        )
        .await?;

        let (group_col, id_expr) = match filter.group_by {
            TopConsumerGroupBy::User => ("u.user_id", "CAST(u.user_id AS TEXT)"),
            TopConsumerGroupBy::Instance => ("u.instance_id", "CAST(u.instance_id AS TEXT)"),
        };

        let order_col = match filter.rank_by {
            UsageRankBy::Tokens => "total_tokens",
            UsageRankBy::Cost => "total_cost_nano",
        };

        let mut qb = QueryBuilder::new();

        // Only include agent rows (instance_id IS NOT NULL)
        qb.conditions.push("u.instance_id IS NOT NULL".to_string());

        if let Some(sd) = filter.start_date {
            qb.push("u.created_at", ">=", sd);
        }
        if let Some(ed) = filter.end_date {
            qb.push("u.created_at", "<=", ed);
        }
        if let Some(ref t) = filter.instance_type {
            qb.push("ai.type", "=", t.clone());
        }

        let needs_join = filter.instance_type.is_some()
            || matches!(filter.group_by, TopConsumerGroupBy::Instance);
        let join_clause = if needs_join {
            "JOIN agent_instances ai ON u.instance_id = ai.id"
        } else {
            ""
        };

        // User info: when grouped by User join users on u.user_id; when by Instance join on ai.user_id
        let (user_join, user_select, user_group) = match filter.group_by {
            TopConsumerGroupBy::User => (
                "LEFT JOIN users u2 ON u.user_id = u2.id",
                "u2.email as user_email, u2.name as user_name, u2.avatar_url as user_avatar_url",
                ", u2.email, u2.name, u2.avatar_url",
            ),
            TopConsumerGroupBy::Instance => (
                "LEFT JOIN users u2 ON ai.user_id = u2.id",
                "u2.email as user_email, u2.name as user_name, u2.avatar_url as user_avatar_url",
                ", u2.email, u2.name, u2.avatar_url",
            ),
        };

        let type_select = if matches!(filter.group_by, TopConsumerGroupBy::Instance) {
            "ai.type as instance_type"
        } else {
            "NULL as instance_type"
        };

        let where_clause = qb.where_clause();
        let limit_idx = qb.next_param_idx();
        qb.params.push(Box::new(filter.limit));

        let extra_group = if matches!(filter.group_by, TopConsumerGroupBy::Instance) {
            ", ai.type"
        } else {
            ""
        };

        let sql = format!(
            "SELECT {id_expr} as id,
                    {type_select},
                    {user_select},
                    COALESCE(SUM(u.quantity), 0)::BIGINT as total_tokens,
                    COALESCE(SUM(u.cost_nano_usd), 0)::BIGINT as total_cost_nano,
                    COUNT(*) as request_count
             FROM user_usage_event u
             {join_clause}
             {user_join}
             {where_clause}
             GROUP BY {group_col}{extra_group}{user_group}
             ORDER BY {order_col} DESC
             LIMIT ${limit_idx}"
        );

        let rows = tx.query(&sql, &qb.param_refs()).await?;
        tx.commit().await?;

        let records = rows
            .into_iter()
            .map(|r| TopConsumer {
                id: r.get(0),
                instance_type: r.get(1),
                user_email: r.get(2),
                user_name: r.get(3),
                user_avatar_url: r.get(4),
                total_tokens: r.get(5),
                total_cost_nano: r.get(6),
                request_count: r.get(7),
            })
            .collect();

        Ok(records)
    }
}
