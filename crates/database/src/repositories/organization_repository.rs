use crate::pool::DbPool;
use async_trait::async_trait;
use services::{
    organization::ports::{
        CreateOrganizationParams, OrgRole, Organization, OrganizationMember,
        OrganizationRepository, OrganizationSettings, OrganizationStatus, PlanTier,
        UpdateOrganizationParams,
    },
    OrganizationId, UserId,
};

pub struct PostgresOrganizationRepository {
    pool: DbPool,
}

impl PostgresOrganizationRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl OrganizationRepository for PostgresOrganizationRepository {
    async fn get_organization(
        &self,
        organization_id: OrganizationId,
    ) -> anyhow::Result<Option<Organization>> {
        tracing::debug!(
            "Repository: Fetching organization by organization_id={}",
            organization_id
        );

        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, name, slug, display_name, logo_url, plan_tier, billing_email,
                        settings, status, created_at, updated_at, deleted_at
                 FROM organizations
                 WHERE id = $1 AND deleted_at IS NULL",
                &[&organization_id],
            )
            .await?;

        Ok(row.map(|r| Organization {
            id: r.get(0),
            name: r.get(1),
            slug: r.get(2),
            display_name: r.get(3),
            logo_url: r.get(4),
            plan_tier: PlanTier::from_str(r.get::<_, String>(5).as_str())
                .unwrap_or_default(),
            billing_email: r.get(6),
            settings: serde_json::from_value(r.get(7)).unwrap_or_default(),
            status: OrganizationStatus::from_str(r.get::<_, String>(8).as_str())
                .unwrap_or_default(),
            created_at: r.get(9),
            updated_at: r.get(10),
            deleted_at: r.get(11),
        }))
    }

    async fn get_organization_by_slug(&self, slug: &str) -> anyhow::Result<Option<Organization>> {
        tracing::debug!("Repository: Fetching organization by slug={}", slug);

        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, name, slug, display_name, logo_url, plan_tier, billing_email,
                        settings, status, created_at, updated_at, deleted_at
                 FROM organizations
                 WHERE slug = $1 AND deleted_at IS NULL",
                &[&slug],
            )
            .await?;

        Ok(row.map(|r| Organization {
            id: r.get(0),
            name: r.get(1),
            slug: r.get(2),
            display_name: r.get(3),
            logo_url: r.get(4),
            plan_tier: PlanTier::from_str(r.get::<_, String>(5).as_str())
                .unwrap_or_default(),
            billing_email: r.get(6),
            settings: serde_json::from_value(r.get(7)).unwrap_or_default(),
            status: OrganizationStatus::from_str(r.get::<_, String>(8).as_str())
                .unwrap_or_default(),
            created_at: r.get(9),
            updated_at: r.get(10),
            deleted_at: r.get(11),
        }))
    }

    async fn create_organization(
        &self,
        params: CreateOrganizationParams,
    ) -> anyhow::Result<Organization> {
        tracing::info!(
            "Repository: Creating organization with name={}, slug={}",
            params.name,
            params.slug
        );

        let client = self.pool.get().await?;
        let settings_json = serde_json::to_value(&params.settings)?;

        let row = client
            .query_one(
                "INSERT INTO organizations (name, slug, display_name, logo_url, plan_tier,
                                           billing_email, settings, status)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, 'active')
                 RETURNING id, name, slug, display_name, logo_url, plan_tier, billing_email,
                           settings, status, created_at, updated_at, deleted_at",
                &[
                    &params.name,
                    &params.slug,
                    &params.display_name,
                    &params.logo_url,
                    &params.plan_tier.as_str(),
                    &params.billing_email,
                    &settings_json,
                ],
            )
            .await?;

        let org = Organization {
            id: row.get(0),
            name: row.get(1),
            slug: row.get(2),
            display_name: row.get(3),
            logo_url: row.get(4),
            plan_tier: PlanTier::from_str(row.get::<_, String>(5).as_str())
                .unwrap_or_default(),
            billing_email: row.get(6),
            settings: serde_json::from_value(row.get(7)).unwrap_or_default(),
            status: OrganizationStatus::from_str(row.get::<_, String>(8).as_str())
                .unwrap_or_default(),
            created_at: row.get(9),
            updated_at: row.get(10),
            deleted_at: row.get(11),
        };

        tracing::info!(
            "Repository: Organization created with organization_id={}",
            org.id
        );

        Ok(org)
    }

    async fn update_organization(
        &self,
        organization_id: OrganizationId,
        params: UpdateOrganizationParams,
    ) -> anyhow::Result<Organization> {
        tracing::info!(
            "Repository: Updating organization organization_id={}",
            organization_id
        );

        let client = self.pool.get().await?;

        // Build dynamic update query
        let mut updates = Vec::new();
        let mut param_idx = 2;
        let mut values: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> =
            vec![Box::new(organization_id)];

        if let Some(ref name) = params.name {
            updates.push(format!("name = ${}", param_idx));
            values.push(Box::new(name.clone()));
            param_idx += 1;
        }

        if let Some(ref display_name) = params.display_name {
            updates.push(format!("display_name = ${}", param_idx));
            values.push(Box::new(display_name.clone()));
            param_idx += 1;
        }

        if let Some(ref logo_url) = params.logo_url {
            updates.push(format!("logo_url = ${}", param_idx));
            values.push(Box::new(logo_url.clone()));
            param_idx += 1;
        }

        if let Some(ref billing_email) = params.billing_email {
            updates.push(format!("billing_email = ${}", param_idx));
            values.push(Box::new(billing_email.clone()));
            param_idx += 1;
        }

        if let Some(ref settings) = params.settings {
            let settings_json = serde_json::to_value(settings)?;
            updates.push(format!("settings = ${}", param_idx));
            values.push(Box::new(settings_json));
        }

        if updates.is_empty() {
            return self
                .get_organization(organization_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Organization not found"));
        }

        let query = format!(
            "UPDATE organizations SET {} WHERE id = $1 AND deleted_at IS NULL
             RETURNING id, name, slug, display_name, logo_url, plan_tier, billing_email,
                       settings, status, created_at, updated_at, deleted_at",
            updates.join(", ")
        );

        let params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            values.iter().map(|v| v.as_ref() as _).collect();

        let row = client.query_one(&query, &params).await?;

        Ok(Organization {
            id: row.get(0),
            name: row.get(1),
            slug: row.get(2),
            display_name: row.get(3),
            logo_url: row.get(4),
            plan_tier: PlanTier::from_str(row.get::<_, String>(5).as_str())
                .unwrap_or_default(),
            billing_email: row.get(6),
            settings: serde_json::from_value(row.get(7)).unwrap_or_default(),
            status: OrganizationStatus::from_str(row.get::<_, String>(8).as_str())
                .unwrap_or_default(),
            created_at: row.get(9),
            updated_at: row.get(10),
            deleted_at: row.get(11),
        })
    }

    async fn delete_organization(&self, organization_id: OrganizationId) -> anyhow::Result<()> {
        tracing::warn!(
            "Repository: Soft deleting organization organization_id={}",
            organization_id
        );

        let client = self.pool.get().await?;

        client
            .execute(
                "UPDATE organizations SET deleted_at = NOW(), status = 'deleted'
                 WHERE id = $1 AND deleted_at IS NULL",
                &[&organization_id],
            )
            .await?;

        Ok(())
    }

    async fn get_user_organizations(&self, user_id: UserId) -> anyhow::Result<Vec<Organization>> {
        tracing::debug!(
            "Repository: Fetching organizations for user_id={}",
            user_id
        );

        let client = self.pool.get().await?;

        let rows = client
            .query(
                "SELECT o.id, o.name, o.slug, o.display_name, o.logo_url, o.plan_tier,
                        o.billing_email, o.settings, o.status, o.created_at, o.updated_at,
                        o.deleted_at
                 FROM organizations o
                 JOIN users u ON u.organization_id = o.id
                 WHERE u.id = $1 AND o.deleted_at IS NULL
                 ORDER BY o.name",
                &[&user_id],
            )
            .await?;

        Ok(rows
            .into_iter()
            .map(|r| Organization {
                id: r.get(0),
                name: r.get(1),
                slug: r.get(2),
                display_name: r.get(3),
                logo_url: r.get(4),
                plan_tier: PlanTier::from_str(r.get::<_, String>(5).as_str())
                    .unwrap_or_default(),
                billing_email: r.get(6),
                settings: serde_json::from_value(r.get(7)).unwrap_or_default(),
                status: OrganizationStatus::from_str(r.get::<_, String>(8).as_str())
                    .unwrap_or_default(),
                created_at: r.get(9),
                updated_at: r.get(10),
                deleted_at: r.get(11),
            })
            .collect())
    }

    async fn get_organization_members(
        &self,
        organization_id: OrganizationId,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<OrganizationMember>, u64)> {
        tracing::debug!(
            "Repository: Fetching members for organization_id={}",
            organization_id
        );

        let client = self.pool.get().await?;

        let rows = client
            .query(
                "SELECT u.id, u.email, u.name, u.avatar_url, u.org_role, u.created_at,
                        COUNT(*) OVER() as total_count
                 FROM users u
                 WHERE u.organization_id = $1
                 ORDER BY u.created_at DESC
                 LIMIT $2 OFFSET $3",
                &[&organization_id, &limit, &offset],
            )
            .await?;

        let total_count: i64 = if rows.is_empty() {
            0
        } else {
            rows[0].get("total_count")
        };

        let members = rows
            .into_iter()
            .map(|r| OrganizationMember {
                user_id: r.get(0),
                email: r.get(1),
                name: r.get(2),
                avatar_url: r.get(3),
                org_role: OrgRole::from_str(
                    r.get::<_, Option<String>>(4)
                        .unwrap_or_else(|| "member".to_string())
                        .as_str(),
                )
                .unwrap_or_default(),
                joined_at: r.get(5),
            })
            .collect();

        Ok((members, total_count as u64))
    }

    async fn set_user_organization(
        &self,
        user_id: UserId,
        organization_id: OrganizationId,
        role: OrgRole,
    ) -> anyhow::Result<()> {
        tracing::info!(
            "Repository: Setting user organization: user_id={}, organization_id={}, role={:?}",
            user_id,
            organization_id,
            role
        );

        let client = self.pool.get().await?;

        client
            .execute(
                "UPDATE users SET organization_id = $2, org_role = $3 WHERE id = $1",
                &[&user_id, &organization_id, &role.as_str()],
            )
            .await?;

        Ok(())
    }

    async fn remove_user_from_organization(
        &self,
        user_id: UserId,
        organization_id: OrganizationId,
    ) -> anyhow::Result<()> {
        tracing::warn!(
            "Repository: Removing user from organization: user_id={}, organization_id={}",
            user_id,
            organization_id
        );

        let client = self.pool.get().await?;

        client
            .execute(
                "UPDATE users SET organization_id = NULL, org_role = NULL
                 WHERE id = $1 AND organization_id = $2",
                &[&user_id, &organization_id],
            )
            .await?;

        Ok(())
    }

    async fn is_slug_available(&self, slug: &str) -> anyhow::Result<bool> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT 1 FROM organizations WHERE slug = $1",
                &[&slug],
            )
            .await?;

        Ok(row.is_none())
    }

    async fn get_user_organization(&self, user_id: UserId) -> anyhow::Result<Option<Organization>> {
        tracing::debug!(
            "Repository: Fetching organization for user_id={}",
            user_id
        );

        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT o.id, o.name, o.slug, o.display_name, o.logo_url, o.plan_tier,
                        o.billing_email, o.settings, o.status, o.created_at, o.updated_at,
                        o.deleted_at
                 FROM organizations o
                 JOIN users u ON u.organization_id = o.id
                 WHERE u.id = $1 AND o.deleted_at IS NULL",
                &[&user_id],
            )
            .await?;

        Ok(row.map(|r| Organization {
            id: r.get(0),
            name: r.get(1),
            slug: r.get(2),
            display_name: r.get(3),
            logo_url: r.get(4),
            plan_tier: PlanTier::from_str(r.get::<_, String>(5).as_str())
                .unwrap_or_default(),
            billing_email: r.get(6),
            settings: serde_json::from_value(r.get(7)).unwrap_or_default(),
            status: OrganizationStatus::from_str(r.get::<_, String>(8).as_str())
                .unwrap_or_default(),
            created_at: r.get(9),
            updated_at: r.get(10),
            deleted_at: r.get(11),
        }))
    }

    async fn get_user_org_role(
        &self,
        user_id: UserId,
        organization_id: OrganizationId,
    ) -> anyhow::Result<Option<OrgRole>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT org_role FROM users WHERE id = $1 AND organization_id = $2",
                &[&user_id, &organization_id],
            )
            .await?;

        Ok(row.and_then(|r| {
            r.get::<_, Option<String>>(0)
                .and_then(|s| OrgRole::from_str(&s))
        }))
    }
}
