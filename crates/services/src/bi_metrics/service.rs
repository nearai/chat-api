use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::system_configs::ports::SystemConfigsService;

use super::ports::*;

pub struct BiMetricsServiceImpl {
    repo: Arc<dyn BiMetricsRepository>,
    system_configs_service: Arc<dyn SystemConfigsService>,
}

impl BiMetricsServiceImpl {
    pub fn new(
        repo: Arc<dyn BiMetricsRepository>,
        system_configs_service: Arc<dyn SystemConfigsService>,
    ) -> Self {
        Self {
            repo,
            system_configs_service,
        }
    }

    fn build_price_id_to_plan_name(
        config: &Option<crate::system_configs::ports::SystemConfigs>,
    ) -> HashMap<String, String> {
        let mut map = HashMap::new();
        if let Some(config) = config.as_ref() {
            if let Some(plans) = config.subscription_plans.as_ref() {
                for (plan_name, plan_config) in plans {
                    for provider_config in plan_config.providers.values() {
                        map.insert(provider_config.price_id.clone(), plan_name.clone());
                    }
                }
            }
        }
        map
    }
}

#[async_trait]
impl BiMetricsService for BiMetricsServiceImpl {
    async fn list_deployments(
        &self,
        filter: &DeploymentFilter,
    ) -> anyhow::Result<(Vec<DeploymentRecord>, i64)> {
        self.repo.list_deployments(filter).await
    }

    async fn get_deployment_summary(
        &self,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
    ) -> anyhow::Result<DeploymentSummary> {
        self.repo.get_deployment_summary(start_date, end_date).await
    }

    async fn get_status_history(
        &self,
        instance_id: Uuid,
        limit: i64,
    ) -> anyhow::Result<Vec<StatusChangeRecord>> {
        self.repo.get_status_history(instance_id, limit).await
    }

    async fn get_usage_aggregation(
        &self,
        filter: &UsageFilter,
    ) -> anyhow::Result<Vec<UsageAggregation>> {
        self.repo.get_usage_aggregation(filter).await
    }

    async fn get_top_consumers(
        &self,
        filter: &TopConsumerFilter,
    ) -> anyhow::Result<Vec<TopConsumer>> {
        self.repo.get_top_consumers(filter).await
    }

    async fn get_user_summary(&self) -> anyhow::Result<UserSummary> {
        let (by_price_id, by_agent_count) = self.repo.get_user_summary().await?;

        let config = self.system_configs_service.get_configs().await?;
        let price_to_plan = Self::build_price_id_to_plan_name(&config);

        let by_subscription_plan: Vec<UserSummaryPlanCount> = by_price_id
            .into_iter()
            .map(|(price_id_opt, user_count)| {
                let plan = match price_id_opt {
                    None => "none".to_string(),
                    Some(id) => price_to_plan
                        .get(&id)
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string()),
                };
                UserSummaryPlanCount { plan, user_count }
            })
            .collect();

        let by_agent_count: Vec<UserSummaryAgentCountBucket> = by_agent_count
            .into_iter()
            .map(|(agent_count, user_count)| UserSummaryAgentCountBucket {
                agent_count,
                user_count,
            })
            .collect();

        Ok(UserSummary {
            by_subscription_plan,
            by_agent_count,
        })
    }

    async fn list_users_with_stats(
        &self,
        limit: i64,
        offset: i64,
        filter: &ListUsersFilter,
        sort: &ListUsersSort,
    ) -> anyhow::Result<(Vec<UserWithStats>, u64)> {
        self.repo
            .list_users_with_stats(limit, offset, filter, sort)
            .await
    }

    async fn get_daily_active_agents(
        &self,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
    ) -> anyhow::Result<Vec<DailyActiveAgentsPoint>> {
        self.repo
            .get_daily_active_agents(start_date, end_date)
            .await
    }
}
