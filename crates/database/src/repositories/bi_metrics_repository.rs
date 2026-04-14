use crate::pool::DbPool;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use services::bi_metrics::{
    BiMetricsRepository, DeploymentFilter, DeploymentRecord, DeploymentStatusCount,
    DeploymentSummary, DeploymentsSortBy, DeploymentsSortOrder, ListUsersFilter, ListUsersSort,
    StatusChangeRecord, TopConsumer, TopConsumerFilter, TopConsumerGroupBy, UsageAggregation,
    UsageFilter, UsageGroupBy, UsageRankBy, UserWithStats, UsersSortBy, UsersSortOrder,
};
use services::user::ports::User;
use services::UserId;
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

    /// Search deployments by agent name, user email, or user name (ILIKE, one param).
    fn push_search_deployments(&mut self, pattern: String) {
        let idx = self.next_param_idx();
        self.conditions.push(format!(
            "(ai.name ILIKE ${idx} OR u.email ILIKE ${idx} OR u.name ILIKE ${idx})"
        ));
        self.params.push(Box::new(pattern));
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

fn list_deployments_order_clause(
    sort_by: DeploymentsSortBy,
    sort_order: DeploymentsSortOrder,
) -> String {
    let col = match sort_by {
        DeploymentsSortBy::CreatedAt => "ai.created_at",
        DeploymentsSortBy::UpdatedAt => "ai.updated_at",
        DeploymentsSortBy::InstanceType => "ai.type",
        DeploymentsSortBy::Status => "ai.status",
        DeploymentsSortBy::UserEmail => "u.email",
        DeploymentsSortBy::UserName => "u.name",
        DeploymentsSortBy::Name => "ai.name",
        DeploymentsSortBy::TotalSpentNano => "COALESCE(uue.total_spent_nano, 0)",
        DeploymentsSortBy::TotalTokens => "COALESCE(uue.total_tokens, 0)",
    };
    let order = match sort_order {
        DeploymentsSortOrder::Asc => "ASC",
        DeploymentsSortOrder::Desc => "DESC",
    };
    let nulls = match sort_by {
        DeploymentsSortBy::UserEmail | DeploymentsSortBy::UserName | DeploymentsSortBy::Name => {
            " NULLS LAST"
        }
        _ => "",
    };
    format!("{col} {order}{nulls}")
}

fn list_users_order_clause(sort: &ListUsersSort) -> String {
    let col = match sort.sort_by {
        UsersSortBy::CreatedAt => "enriched.created_at",
        UsersSortBy::TotalSpentNano => "enriched.total_spent_nano",
        UsersSortBy::AgentSpentNano => "enriched.agent_spent_nano",
        UsersSortBy::AgentTokenUsage => "enriched.agent_token_usage",
        UsersSortBy::LastActivityAt => "enriched.last_activity_at",
        UsersSortBy::AgentCount => "enriched.agent_count",
        UsersSortBy::Email => "enriched.email",
        UsersSortBy::Name => "enriched.name",
        UsersSortBy::PurchasedCreditsNano => "enriched.purchased_credits_nano",
        UsersSortBy::SpentPurchasedCreditsNano => "enriched.spent_purchased_credits_nano",
    };
    let order = match sort.sort_order {
        UsersSortOrder::Asc => "ASC",
        UsersSortOrder::Desc => "DESC",
    };
    let nulls = match sort.sort_by {
        UsersSortBy::LastActivityAt | UsersSortBy::Name => " NULLS LAST",
        _ => "",
    };
    format!("{col} {order}{nulls}")
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
        if let Some(ref search) = filter.search {
            let escaped = search
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            let pattern = format!("%{escaped}%");
            qb.push_search_deployments(pattern);
        }

        let where_clause = qb.where_clause();
        let order_clause = list_deployments_order_clause(filter.sort_by, filter.sort_order);

        // Use COUNT(*) OVER() window function to get total in a single query
        // LEFT JOIN users to get user_email, user_name, and for search/sort
        // LEFT JOIN LATERAL: aggregate usage only for this row's instance_id (avoids full table aggregate)
        let limit_idx = qb.next_param_idx();
        let offset_idx = limit_idx + 1;
        let data_sql = format!(
            "SELECT ai.id AS id, ai.user_id AS user_id, u.email AS user_email, u.name AS user_name, u.avatar_url AS user_avatar_url,
                    ai.name AS name, ai.instance_id AS instance_id, ai.type AS instance_type, ai.status AS status,
                    ai.created_at AS created_at, ai.updated_at AS updated_at,
                    COALESCE(uue.total_spent_nano, 0)::BIGINT AS total_spent_nano, COALESCE(uue.total_tokens, 0)::BIGINT AS total_tokens,
                    COUNT(*) OVER() AS total_count
             FROM agent_instances ai
             LEFT JOIN users u ON ai.user_id = u.id
             LEFT JOIN LATERAL (
                 SELECT COALESCE(SUM(cost_nano_usd), 0)::BIGINT AS total_spent_nano,
                        COALESCE(SUM(CASE WHEN metric_key = 'llm.tokens' THEN quantity ELSE 0 END), 0)::BIGINT AS total_tokens
                 FROM user_usage_event WHERE instance_id = ai.id
             ) uue ON TRUE
             {where_clause}
             ORDER BY {order_clause}
             LIMIT ${limit_idx} OFFSET ${offset_idx}"
        );
        qb.params.push(Box::new(filter.limit));
        qb.params.push(Box::new(filter.offset));

        let rows = client.query(&data_sql, &qb.param_refs()).await?;

        let total: i64 = rows
            .first()
            .map(|r| r.get::<_, i64>("total_count"))
            .unwrap_or(0);

        let records = rows
            .into_iter()
            .map(|r| DeploymentRecord {
                id: r.get("id"),
                user_id: r.get("user_id"),
                user_email: r.get("user_email"),
                user_name: r.get("user_name"),
                user_avatar_url: r.get("user_avatar_url"),
                name: r.get("name"),
                instance_id: r.get("instance_id"),
                instance_type: r.get("instance_type"),
                status: r.get("status"),
                created_at: r.get("created_at"),
                updated_at: r.get("updated_at"),
                total_spent_nano: r.get("total_spent_nano"),
                total_tokens: r.get("total_tokens"),
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
                "SELECT h.id AS id,
                        h.instance_id AS instance_id,
                        h.old_status AS old_status,
                        h.new_status AS new_status,
                        h.changed_by_user_id AS changed_by_user_id,
                        COALESCE(NULLIF(u.name, ''), NULLIF(u.email, '')) AS changed_by_user_name,
                        u.avatar_url AS changed_by_user_avatar_url,
                        h.change_reason AS change_reason,
                        h.changed_at AS changed_at
                 FROM agent_instance_status_history h
                 LEFT JOIN users u ON h.changed_by_user_id = u.id
                 WHERE h.instance_id = $1
                 ORDER BY h.changed_at DESC
                 LIMIT $2",
                &[&instance_id, &capped_limit],
            )
            .await?;

        let records = rows
            .into_iter()
            .map(|r| StatusChangeRecord {
                id: r.get("id"),
                instance_id: r.get("instance_id"),
                old_status: r.get("old_status"),
                new_status: r.get("new_status"),
                changed_by_user_id: r.get("changed_by_user_id"),
                changed_by_user_name: r.get("changed_by_user_name"),
                changed_by_user_avatar_url: r.get("changed_by_user_avatar_url"),
                change_reason: r.get("change_reason"),
                changed_at: r.get("changed_at"),
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

        // Determine GROUP BY, SELECT, joins, and optional active_agents / active_users counts
        let (group_expr, select_expr, user_select, type_select, join_clause, user_group, active_agents_select, active_users_select) =
            match filter.group_by {
                UsageGroupBy::Day => (
                    "DATE(u.created_at)",
                    "CAST(DATE(u.created_at) AS TEXT) as group_key",
                    "NULL::TEXT as user_email, NULL::TEXT as user_name, NULL::TEXT as user_avatar_url",
                    "NULL::TEXT as instance_type",
                    "",
                    "",
                    ", COUNT(DISTINCT CASE WHEN (u.quantity > 0 OR COALESCE(u.cost_nano_usd, 0) > 0) THEN u.instance_id END)::BIGINT AS active_agents_count",
                    ", COUNT(DISTINCT CASE WHEN (u.quantity > 0 OR COALESCE(u.cost_nano_usd, 0) > 0) THEN u.user_id END)::BIGINT AS active_users_count",
                ),
                UsageGroupBy::User => (
                    "u.user_id, u2.email, u2.name, u2.avatar_url",
                    "CAST(u.user_id AS TEXT) as group_key",
                    "u2.email as user_email, u2.name as user_name, u2.avatar_url as user_avatar_url",
                    "NULL::TEXT as instance_type",
                    "",
                    "LEFT JOIN users u2 ON u.user_id = u2.id",
                    ", COUNT(DISTINCT CASE WHEN (u.quantity > 0 OR COALESCE(u.cost_nano_usd, 0) > 0) THEN u.instance_id END)::BIGINT AS active_agents_count",
                    "",
                ),
                UsageGroupBy::Instance => (
                    "u.instance_id, ai.type, u2.email, u2.name, u2.avatar_url",
                    "CAST(u.instance_id AS TEXT) as group_key",
                    "u2.email as user_email, u2.name as user_name, u2.avatar_url as user_avatar_url",
                    "ai.type as instance_type",
                    "JOIN agent_instances ai ON u.instance_id = ai.id",
                    "LEFT JOIN users u2 ON ai.user_id = u2.id",
                    "",
                    "",
                ),
                UsageGroupBy::Model => (
                    "COALESCE(u.model_id, 'unknown')",
                    "COALESCE(u.model_id, 'unknown') as group_key",
                    "NULL::TEXT as user_email, NULL::TEXT as user_name, NULL::TEXT as user_avatar_url",
                    "NULL::TEXT as instance_type",
                    "",
                    "",
                    ", COUNT(DISTINCT CASE WHEN (u.quantity > 0 OR COALESCE(u.cost_nano_usd, 0) > 0) THEN u.instance_id END)::BIGINT AS active_agents_count",
                    ", COUNT(DISTINCT CASE WHEN (u.quantity > 0 OR COALESCE(u.cost_nano_usd, 0) > 0) THEN u.user_id END)::BIGINT AS active_users_count",
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

        // For Instance we always join agent_instances; for instance_type filter we need it too
        let effective_join = if !join_clause.is_empty() {
            join_clause
        } else if filter.instance_type.is_some() {
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
                    {type_select},
                    COALESCE(SUM((u.details->>'input_tokens')::BIGINT), 0)::BIGINT,
                    COALESCE(SUM((u.details->>'output_tokens')::BIGINT), 0)::BIGINT,
                    COALESCE(SUM(u.quantity), 0)::BIGINT,
                    COALESCE(SUM((u.details->>'input_cost')::BIGINT), 0)::BIGINT,
                    COALESCE(SUM((u.details->>'output_cost')::BIGINT), 0)::BIGINT,
                    COALESCE(SUM(u.cost_nano_usd), 0)::BIGINT,
                    COUNT(*){active_agents_select}{active_users_select}
             FROM user_usage_event u
             {effective_join}
             {user_group}
             {where_clause}
             GROUP BY {group_expr}
             ORDER BY {group_expr}
             LIMIT ${limit_idx}"
        );

        let rows = tx.query(&sql, &qb.param_refs()).await?;
        tx.commit().await?;

        let include_active_agents = matches!(
            filter.group_by,
            UsageGroupBy::Day | UsageGroupBy::User | UsageGroupBy::Model
        );
        let include_active_users =
            matches!(filter.group_by, UsageGroupBy::Day | UsageGroupBy::Model);
        let records = rows
            .into_iter()
            .map(|r| {
                let active_agents_count = if include_active_agents {
                    Some(r.get::<_, i64>("active_agents_count"))
                } else {
                    None
                };
                let active_users_count = if include_active_users {
                    Some(r.get::<_, i64>("active_users_count"))
                } else {
                    None
                };
                UsageAggregation {
                    group_key: r.get(0),
                    user_email: r.get(1),
                    user_name: r.get(2),
                    user_avatar_url: r.get(3),
                    instance_type: r.get(4),
                    input_tokens: r.get(5),
                    output_tokens: r.get(6),
                    total_tokens: r.get(7),
                    input_cost_nano: r.get(8),
                    output_cost_nano: r.get(9),
                    total_cost_nano: r.get(10),
                    request_count: r.get(11),
                    active_agents_count,
                    active_users_count,
                }
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

    async fn get_user_summary(
        &self,
    ) -> anyhow::Result<(Vec<(Option<String>, i64)>, Vec<(i64, i64)>)> {
        let mut client = self.pool.get().await?;

        // Wrap in a transaction so SET LOCAL statement_timeout takes effect
        let tx = client.build_transaction().start().await?;
        tx.execute(
            &format!("SET LOCAL statement_timeout = '{AGGREGATION_TIMEOUT_MS}'"),
            &[],
        )
        .await?;

        // Single query: one CTE pass, two aggregations via UNION ALL
        let sql = r#"
WITH agent_counts AS (
    SELECT user_id, COUNT(*)::bigint AS agent_count
    FROM agent_instances
    WHERE status != 'deleted'
    GROUP BY user_id
),
enriched AS (
    SELECT
        sub.price_id AS subscription_price_id,
        COALESCE(ac.agent_count, 0)::bigint AS agent_count
    FROM users u
    LEFT JOIN LATERAL (
        SELECT price_id FROM subscriptions s
        WHERE s.user_id = u.id AND s.status IN ('active', 'trialing')
        ORDER BY s.created_at DESC
        LIMIT 1
    ) sub ON true
    LEFT JOIN agent_counts ac ON u.id = ac.user_id
),
by_plan AS (
    SELECT 1 AS part, subscription_price_id, NULL::bigint AS agent_count, COUNT(*)::bigint AS user_count
    FROM enriched GROUP BY subscription_price_id
),
by_agent AS (
    SELECT 2 AS part, NULL::text AS subscription_price_id, agent_count, COUNT(*)::bigint AS user_count
    FROM enriched GROUP BY agent_count
)
SELECT part, subscription_price_id, agent_count, user_count FROM by_plan
UNION ALL
SELECT part, subscription_price_id, agent_count, user_count FROM by_agent ORDER BY part, agent_count
"#;

        let rows = tx.query(sql, &[]).await?;
        tx.commit().await?;

        let mut by_subscription_price_id: Vec<(Option<String>, i64)> = Vec::new();
        let mut by_agent_count: Vec<(i64, i64)> = Vec::new();
        for r in rows {
            let part: i32 = r.get("part");
            let user_count: i64 = r.get("user_count");
            if part == 1 {
                by_subscription_price_id.push((r.get("subscription_price_id"), user_count));
            } else {
                by_agent_count.push((r.get::<_, i64>("agent_count"), user_count));
            }
        }

        Ok((by_subscription_price_id, by_agent_count))
    }

    async fn list_users_with_stats(
        &self,
        limit: i64,
        offset: i64,
        filter: &ListUsersFilter,
        sort: &ListUsersSort,
    ) -> anyhow::Result<(Vec<UserWithStats>, u64)> {
        let mut client = self.pool.get().await?;

        // Wrap in a transaction so SET LOCAL statement_timeout takes effect
        let tx = client.build_transaction().start().await?;
        tx.execute(
            &format!("SET LOCAL statement_timeout = '{AGGREGATION_TIMEOUT_MS}'"),
            &[],
        )
        .await?;

        let mut filter_clauses = Vec::new();
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Send + Sync>> = Vec::new();
        let mut param_idx = 1u32;

        if let Some(s) = filter.subscription_status.as_ref() {
            match s.as_str() {
                "none" => filter_clauses.push("enriched.subscription_status IS NULL".to_string()),
                "active" | "trialing" => {
                    filter_clauses.push(format!("enriched.subscription_status = ${param_idx}"));
                    params.push(Box::new(s.to_string()));
                    param_idx += 1;
                }
                _ => {}
            }
        }

        if filter.subscription_plan_none {
            filter_clauses.push("enriched.subscription_price_id IS NULL".to_string());
        }

        if let Some(ref price_ids) = filter.subscription_plan_price_ids {
            if price_ids.is_empty() {
                filter_clauses.push("1 = 0".to_string());
            } else {
                filter_clauses.push(format!(
                    "enriched.subscription_price_id = ANY(${param_idx}::text[])"
                ));
                params.push(Box::new(price_ids.clone()));
                param_idx += 1;
            }
        }

        if let Some(ref search) = filter.search {
            let escaped = search
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            let pattern = format!("%{escaped}%");
            filter_clauses.push(format!(
                "(enriched.email ILIKE ${param_idx} OR COALESCE(enriched.name, '') ILIKE ${param_idx})"
            ));
            params.push(Box::new(pattern));
            param_idx += 1;
        }

        let filter_sql = if filter_clauses.is_empty() {
            String::new()
        } else {
            " AND ".to_string() + &filter_clauses.join(" AND ")
        };

        let order_sql = list_users_order_clause(sort);
        let limit_param = param_idx;
        let offset_param = param_idx + 1;

        let base_query = r#"
WITH agent_counts AS (
    SELECT user_id, COUNT(*)::bigint AS agent_count
    FROM agent_instances
    WHERE status != 'deleted'
    GROUP BY user_id
),
usage_stats AS (
    SELECT
        user_id,
        (COALESCE(SUM(cost_nano_usd), 0))::bigint AS total_spent_nano,
        (COALESCE(SUM(CASE WHEN instance_id IS NOT NULL THEN cost_nano_usd ELSE 0 END), 0))::bigint AS agent_spent_nano,
        (COALESCE(SUM(CASE WHEN instance_id IS NOT NULL AND metric_key = 'llm.tokens' THEN quantity ELSE 0 END), 0))::bigint AS agent_token_usage,
        MAX(created_at) AS last_usage_at
    FROM user_usage_event
    GROUP BY user_id
),
credits_balance AS (
    SELECT
        user_id,
        -- purchased_credits_nano = total purchased+granted; remaining = purchased - spent_purchased
        (COALESCE(total_nano_usd, 0))::bigint AS purchased_credits_nano,
        (COALESCE(spent_nano_usd, 0))::bigint AS used_purchased_nano
    FROM user_credits
),
enriched AS (
    SELECT
        u.id,
        u.email,
        u.name,
        u.avatar_url,
        u.created_at,
        u.updated_at,
        sub.status AS subscription_status,
        sub.price_id AS subscription_price_id,
        COALESCE(ac.agent_count, 0) AS agent_count,
        COALESCE(us.total_spent_nano, 0) AS total_spent_nano,
        COALESCE(us.agent_spent_nano, 0) AS agent_spent_nano,
        COALESCE(us.agent_token_usage, 0) AS agent_token_usage,
        COALESCE(us.last_usage_at, u.updated_at) AS last_activity_at,
        COALESCE(cb.purchased_credits_nano, 0) AS purchased_credits_nano,
        COALESCE(cb.used_purchased_nano, 0) AS spent_purchased_credits_nano
    FROM users u
    LEFT JOIN LATERAL (
        SELECT status, price_id FROM subscriptions s
        WHERE s.user_id = u.id AND s.status IN ('active', 'trialing')
        ORDER BY s.created_at DESC
        LIMIT 1
    ) sub ON true
    LEFT JOIN agent_counts ac ON u.id = ac.user_id
    LEFT JOIN usage_stats us ON u.id = us.user_id
    LEFT JOIN credits_balance cb ON u.id = cb.user_id
)
SELECT id, email, name, avatar_url, created_at, updated_at,
       subscription_status, subscription_price_id, agent_count, total_spent_nano, agent_spent_nano,
       agent_token_usage, last_activity_at, purchased_credits_nano, spent_purchased_credits_nano,
       COUNT(*) OVER() AS total_count
FROM enriched
WHERE 1=1
"#;

        let query = format!(
            "{} {} ORDER BY {} LIMIT ${} OFFSET ${}",
            base_query, filter_sql, order_sql, limit_param, offset_param,
        );

        let mut query_params: Vec<Box<dyn tokio_postgres::types::ToSql + Send + Sync>> = params;
        query_params.push(Box::new(limit));
        query_params.push(Box::new(offset));

        let rows = tx
            .query(
                &query,
                &query_params
                    .iter()
                    .map(|b| b.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync))
                    .collect::<Vec<_>>(),
            )
            .await?;
        tx.commit().await?;

        let total_count: i64 = if rows.is_empty() {
            0
        } else {
            rows[0].get("total_count")
        };

        let users = rows
            .into_iter()
            .map(|r| {
                let id: UserId = r.get("id");
                let email: String = r.get("email");
                let name: Option<String> = r.get("name");
                let avatar_url: Option<String> = r.get("avatar_url");
                let created_at: DateTime<Utc> = r.get("created_at");
                let updated_at: DateTime<Utc> = r.get("updated_at");
                UserWithStats {
                    user: User {
                        id,
                        email,
                        name,
                        avatar_url,
                        created_at,
                        updated_at,
                    },
                    subscription_status: r.get("subscription_status"),
                    subscription_price_id: r.get("subscription_price_id"),
                    agent_count: r.get::<_, i64>("agent_count"),
                    total_spent_nano: r.get::<_, i64>("total_spent_nano"),
                    agent_spent_nano: r.get::<_, i64>("agent_spent_nano"),
                    agent_token_usage: r.get::<_, i64>("agent_token_usage"),
                    last_activity_at: r.get("last_activity_at"),
                    purchased_credits_nano: r.get::<_, i64>("purchased_credits_nano"),
                    spent_purchased_credits_nano: r.get::<_, i64>("spent_purchased_credits_nano"),
                }
            })
            .collect();

        Ok((users, total_count as u64))
    }
}
