use crate::pool::DbPool;
use async_trait::async_trait;
use services::{
    workspace::ports::{
        CreateWorkspaceParams, MembershipStatus, UpdateWorkspaceParams, Workspace,
        WorkspaceMember, WorkspaceMembership, WorkspaceRepository, WorkspaceRole,
        WorkspaceSettings, WorkspaceStatus,
    },
    OrganizationId, UserId, WorkspaceId, WorkspaceMembershipId,
};

pub struct PostgresWorkspaceRepository {
    pool: DbPool,
}

impl PostgresWorkspaceRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl WorkspaceRepository for PostgresWorkspaceRepository {
    async fn get_workspace(&self, workspace_id: WorkspaceId) -> anyhow::Result<Option<Workspace>> {
        tracing::debug!(
            "Repository: Fetching workspace by workspace_id={}",
            workspace_id
        );

        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, organization_id, name, slug, description, settings, is_default,
                        status, created_at, updated_at, deleted_at
                 FROM workspaces
                 WHERE id = $1 AND deleted_at IS NULL",
                &[&workspace_id],
            )
            .await?;

        Ok(row.map(|r| Workspace {
            id: r.get(0),
            organization_id: r.get(1),
            name: r.get(2),
            slug: r.get(3),
            description: r.get(4),
            settings: serde_json::from_value(r.get(5)).unwrap_or_default(),
            is_default: r.get(6),
            status: WorkspaceStatus::from_str(r.get::<_, String>(7).as_str())
                .unwrap_or_default(),
            created_at: r.get(8),
            updated_at: r.get(9),
            deleted_at: r.get(10),
        }))
    }

    async fn get_workspace_by_slug(
        &self,
        organization_id: OrganizationId,
        slug: &str,
    ) -> anyhow::Result<Option<Workspace>> {
        tracing::debug!(
            "Repository: Fetching workspace by organization_id={}, slug={}",
            organization_id,
            slug
        );

        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, organization_id, name, slug, description, settings, is_default,
                        status, created_at, updated_at, deleted_at
                 FROM workspaces
                 WHERE organization_id = $1 AND slug = $2 AND deleted_at IS NULL",
                &[&organization_id, &slug],
            )
            .await?;

        Ok(row.map(|r| Workspace {
            id: r.get(0),
            organization_id: r.get(1),
            name: r.get(2),
            slug: r.get(3),
            description: r.get(4),
            settings: serde_json::from_value(r.get(5)).unwrap_or_default(),
            is_default: r.get(6),
            status: WorkspaceStatus::from_str(r.get::<_, String>(7).as_str())
                .unwrap_or_default(),
            created_at: r.get(8),
            updated_at: r.get(9),
            deleted_at: r.get(10),
        }))
    }

    async fn create_workspace(&self, params: CreateWorkspaceParams) -> anyhow::Result<Workspace> {
        tracing::info!(
            "Repository: Creating workspace name={}, organization_id={}",
            params.name,
            params.organization_id
        );

        let client = self.pool.get().await?;
        let settings_json = serde_json::to_value(&params.settings)?;

        let row = client
            .query_one(
                "INSERT INTO workspaces (organization_id, name, slug, description, settings, is_default, status)
                 VALUES ($1, $2, $3, $4, $5, $6, 'active')
                 RETURNING id, organization_id, name, slug, description, settings, is_default,
                           status, created_at, updated_at, deleted_at",
                &[
                    &params.organization_id,
                    &params.name,
                    &params.slug,
                    &params.description,
                    &settings_json,
                    &params.is_default,
                ],
            )
            .await?;

        let workspace = Workspace {
            id: row.get(0),
            organization_id: row.get(1),
            name: row.get(2),
            slug: row.get(3),
            description: row.get(4),
            settings: serde_json::from_value(row.get(5)).unwrap_or_default(),
            is_default: row.get(6),
            status: WorkspaceStatus::from_str(row.get::<_, String>(7).as_str())
                .unwrap_or_default(),
            created_at: row.get(8),
            updated_at: row.get(9),
            deleted_at: row.get(10),
        };

        tracing::info!(
            "Repository: Workspace created workspace_id={}",
            workspace.id
        );

        Ok(workspace)
    }

    async fn update_workspace(
        &self,
        workspace_id: WorkspaceId,
        params: UpdateWorkspaceParams,
    ) -> anyhow::Result<Workspace> {
        tracing::info!(
            "Repository: Updating workspace workspace_id={}",
            workspace_id
        );

        let client = self.pool.get().await?;

        let mut updates = Vec::new();
        let mut param_idx = 2;
        let mut values: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> =
            vec![Box::new(workspace_id)];

        if let Some(ref name) = params.name {
            updates.push(format!("name = ${}", param_idx));
            values.push(Box::new(name.clone()));
            param_idx += 1;
        }

        if let Some(ref description) = params.description {
            updates.push(format!("description = ${}", param_idx));
            values.push(Box::new(description.clone()));
            param_idx += 1;
        }

        if let Some(ref settings) = params.settings {
            let settings_json = serde_json::to_value(settings)?;
            updates.push(format!("settings = ${}", param_idx));
            values.push(Box::new(settings_json));
        }

        if updates.is_empty() {
            return self
                .get_workspace(workspace_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Workspace not found"));
        }

        let query = format!(
            "UPDATE workspaces SET {} WHERE id = $1 AND deleted_at IS NULL
             RETURNING id, organization_id, name, slug, description, settings, is_default,
                       status, created_at, updated_at, deleted_at",
            updates.join(", ")
        );

        let params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            values.iter().map(|v| v.as_ref() as _).collect();

        let row = client.query_one(&query, &params).await?;

        Ok(Workspace {
            id: row.get(0),
            organization_id: row.get(1),
            name: row.get(2),
            slug: row.get(3),
            description: row.get(4),
            settings: serde_json::from_value(row.get(5)).unwrap_or_default(),
            is_default: row.get(6),
            status: WorkspaceStatus::from_str(row.get::<_, String>(7).as_str())
                .unwrap_or_default(),
            created_at: row.get(8),
            updated_at: row.get(9),
            deleted_at: row.get(10),
        })
    }

    async fn delete_workspace(&self, workspace_id: WorkspaceId) -> anyhow::Result<()> {
        tracing::warn!(
            "Repository: Soft deleting workspace workspace_id={}",
            workspace_id
        );

        let client = self.pool.get().await?;

        client
            .execute(
                "UPDATE workspaces SET deleted_at = NOW(), status = 'deleted'
                 WHERE id = $1 AND deleted_at IS NULL",
                &[&workspace_id],
            )
            .await?;

        Ok(())
    }

    async fn get_organization_workspaces(
        &self,
        organization_id: OrganizationId,
    ) -> anyhow::Result<Vec<Workspace>> {
        tracing::debug!(
            "Repository: Fetching workspaces for organization_id={}",
            organization_id
        );

        let client = self.pool.get().await?;

        let rows = client
            .query(
                "SELECT id, organization_id, name, slug, description, settings, is_default,
                        status, created_at, updated_at, deleted_at
                 FROM workspaces
                 WHERE organization_id = $1 AND deleted_at IS NULL
                 ORDER BY is_default DESC, name",
                &[&organization_id],
            )
            .await?;

        Ok(rows
            .into_iter()
            .map(|r| Workspace {
                id: r.get(0),
                organization_id: r.get(1),
                name: r.get(2),
                slug: r.get(3),
                description: r.get(4),
                settings: serde_json::from_value(r.get(5)).unwrap_or_default(),
                is_default: r.get(6),
                status: WorkspaceStatus::from_str(r.get::<_, String>(7).as_str())
                    .unwrap_or_default(),
                created_at: r.get(8),
                updated_at: r.get(9),
                deleted_at: r.get(10),
            })
            .collect())
    }

    async fn get_user_workspaces(&self, user_id: UserId) -> anyhow::Result<Vec<Workspace>> {
        tracing::debug!(
            "Repository: Fetching workspaces for user_id={}",
            user_id
        );

        let client = self.pool.get().await?;

        let rows = client
            .query(
                "SELECT w.id, w.organization_id, w.name, w.slug, w.description, w.settings,
                        w.is_default, w.status, w.created_at, w.updated_at, w.deleted_at
                 FROM workspaces w
                 JOIN workspace_memberships wm ON wm.workspace_id = w.id
                 WHERE wm.user_id = $1 AND wm.status = 'active' AND w.deleted_at IS NULL
                 ORDER BY w.is_default DESC, w.name",
                &[&user_id],
            )
            .await?;

        Ok(rows
            .into_iter()
            .map(|r| Workspace {
                id: r.get(0),
                organization_id: r.get(1),
                name: r.get(2),
                slug: r.get(3),
                description: r.get(4),
                settings: serde_json::from_value(r.get(5)).unwrap_or_default(),
                is_default: r.get(6),
                status: WorkspaceStatus::from_str(r.get::<_, String>(7).as_str())
                    .unwrap_or_default(),
                created_at: r.get(8),
                updated_at: r.get(9),
                deleted_at: r.get(10),
            })
            .collect())
    }

    async fn get_default_workspace(
        &self,
        organization_id: OrganizationId,
    ) -> anyhow::Result<Option<Workspace>> {
        tracing::debug!(
            "Repository: Fetching default workspace for organization_id={}",
            organization_id
        );

        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, organization_id, name, slug, description, settings, is_default,
                        status, created_at, updated_at, deleted_at
                 FROM workspaces
                 WHERE organization_id = $1 AND is_default = TRUE AND deleted_at IS NULL",
                &[&organization_id],
            )
            .await?;

        Ok(row.map(|r| Workspace {
            id: r.get(0),
            organization_id: r.get(1),
            name: r.get(2),
            slug: r.get(3),
            description: r.get(4),
            settings: serde_json::from_value(r.get(5)).unwrap_or_default(),
            is_default: r.get(6),
            status: WorkspaceStatus::from_str(r.get::<_, String>(7).as_str())
                .unwrap_or_default(),
            created_at: r.get(8),
            updated_at: r.get(9),
            deleted_at: r.get(10),
        }))
    }

    async fn get_workspace_members(
        &self,
        workspace_id: WorkspaceId,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<WorkspaceMember>, u64)> {
        tracing::debug!(
            "Repository: Fetching members for workspace_id={}",
            workspace_id
        );

        let client = self.pool.get().await?;

        let rows = client
            .query(
                "SELECT u.id, u.email, u.name, u.avatar_url, wm.role, wm.status, wm.created_at,
                        COUNT(*) OVER() as total_count
                 FROM workspace_memberships wm
                 JOIN users u ON u.id = wm.user_id
                 WHERE wm.workspace_id = $1
                 ORDER BY wm.created_at DESC
                 LIMIT $2 OFFSET $3",
                &[&workspace_id, &limit, &offset],
            )
            .await?;

        let total_count: i64 = if rows.is_empty() {
            0
        } else {
            rows[0].get("total_count")
        };

        let members = rows
            .into_iter()
            .map(|r| WorkspaceMember {
                user_id: r.get(0),
                email: r.get(1),
                name: r.get(2),
                avatar_url: r.get(3),
                role: WorkspaceRole::from_str(r.get::<_, String>(4).as_str())
                    .unwrap_or_default(),
                status: MembershipStatus::from_str(r.get::<_, String>(5).as_str())
                    .unwrap_or_default(),
                joined_at: r.get(6),
            })
            .collect();

        Ok((members, total_count as u64))
    }

    async fn add_workspace_member(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
        role: WorkspaceRole,
    ) -> anyhow::Result<WorkspaceMembership> {
        tracing::info!(
            "Repository: Adding member to workspace: workspace_id={}, user_id={}, role={:?}",
            workspace_id,
            user_id,
            role
        );

        let client = self.pool.get().await?;

        let row = client
            .query_one(
                "INSERT INTO workspace_memberships (workspace_id, user_id, role, status)
                 VALUES ($1, $2, $3, 'active')
                 RETURNING id, workspace_id, user_id, role, status, created_at, updated_at",
                &[&workspace_id, &user_id, &role.as_str()],
            )
            .await?;

        Ok(WorkspaceMembership {
            id: row.get(0),
            workspace_id: row.get(1),
            user_id: row.get(2),
            role: WorkspaceRole::from_str(row.get::<_, String>(3).as_str())
                .unwrap_or_default(),
            status: MembershipStatus::from_str(row.get::<_, String>(4).as_str())
                .unwrap_or_default(),
            created_at: row.get(5),
            updated_at: row.get(6),
        })
    }

    async fn update_workspace_member_role(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
        role: WorkspaceRole,
    ) -> anyhow::Result<()> {
        tracing::info!(
            "Repository: Updating member role: workspace_id={}, user_id={}, role={:?}",
            workspace_id,
            user_id,
            role
        );

        let client = self.pool.get().await?;

        client
            .execute(
                "UPDATE workspace_memberships SET role = $3
                 WHERE workspace_id = $1 AND user_id = $2",
                &[&workspace_id, &user_id, &role.as_str()],
            )
            .await?;

        Ok(())
    }

    async fn remove_workspace_member(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
    ) -> anyhow::Result<()> {
        tracing::warn!(
            "Repository: Removing member from workspace: workspace_id={}, user_id={}",
            workspace_id,
            user_id
        );

        let client = self.pool.get().await?;

        client
            .execute(
                "DELETE FROM workspace_memberships WHERE workspace_id = $1 AND user_id = $2",
                &[&workspace_id, &user_id],
            )
            .await?;

        Ok(())
    }

    async fn get_workspace_membership(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
    ) -> anyhow::Result<Option<WorkspaceMembership>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, workspace_id, user_id, role, status, created_at, updated_at
                 FROM workspace_memberships
                 WHERE workspace_id = $1 AND user_id = $2",
                &[&workspace_id, &user_id],
            )
            .await?;

        Ok(row.map(|r| WorkspaceMembership {
            id: r.get(0),
            workspace_id: r.get(1),
            user_id: r.get(2),
            role: WorkspaceRole::from_str(r.get::<_, String>(3).as_str())
                .unwrap_or_default(),
            status: MembershipStatus::from_str(r.get::<_, String>(4).as_str())
                .unwrap_or_default(),
            created_at: r.get(5),
            updated_at: r.get(6),
        }))
    }

    async fn is_slug_available(
        &self,
        organization_id: OrganizationId,
        slug: &str,
    ) -> anyhow::Result<bool> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT 1 FROM workspaces WHERE organization_id = $1 AND slug = $2",
                &[&organization_id, &slug],
            )
            .await?;

        Ok(row.is_none())
    }
}
