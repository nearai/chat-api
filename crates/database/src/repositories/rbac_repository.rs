use crate::pool::DbPool;
use async_trait::async_trait;
use services::{
    rbac::ports::{
        CreateRoleParams, Permission, PermissionRepository, Role, RoleRepository,
        UpdateRoleParams, UserRoleAssignment,
    },
    OrganizationId, PermissionId, RoleId, UserId, WorkspaceId,
};

pub struct PostgresPermissionRepository {
    pool: DbPool,
}

impl PostgresPermissionRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PermissionRepository for PostgresPermissionRepository {
    async fn get_all_permissions(&self) -> anyhow::Result<Vec<Permission>> {
        let client = self.pool.get().await?;

        let rows = client
            .query(
                "SELECT id, code, name, description, module, action, created_at
                 FROM permissions
                 ORDER BY module, action",
                &[],
            )
            .await?;

        Ok(rows
            .into_iter()
            .map(|r| Permission {
                id: r.get(0),
                code: r.get(1),
                name: r.get(2),
                description: r.get(3),
                module: r.get(4),
                action: r.get(5),
                created_at: r.get(6),
            })
            .collect())
    }

    async fn get_permissions_by_module(&self, module: &str) -> anyhow::Result<Vec<Permission>> {
        let client = self.pool.get().await?;

        let rows = client
            .query(
                "SELECT id, code, name, description, module, action, created_at
                 FROM permissions
                 WHERE module = $1
                 ORDER BY action",
                &[&module],
            )
            .await?;

        Ok(rows
            .into_iter()
            .map(|r| Permission {
                id: r.get(0),
                code: r.get(1),
                name: r.get(2),
                description: r.get(3),
                module: r.get(4),
                action: r.get(5),
                created_at: r.get(6),
            })
            .collect())
    }

    async fn get_permission_by_code(&self, code: &str) -> anyhow::Result<Option<Permission>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, code, name, description, module, action, created_at
                 FROM permissions
                 WHERE code = $1",
                &[&code],
            )
            .await?;

        Ok(row.map(|r| Permission {
            id: r.get(0),
            code: r.get(1),
            name: r.get(2),
            description: r.get(3),
            module: r.get(4),
            action: r.get(5),
            created_at: r.get(6),
        }))
    }

    async fn get_role_permissions(&self, role_id: RoleId) -> anyhow::Result<Vec<Permission>> {
        let client = self.pool.get().await?;

        let rows = client
            .query(
                "SELECT p.id, p.code, p.name, p.description, p.module, p.action, p.created_at
                 FROM permissions p
                 JOIN role_permissions rp ON rp.permission_id = p.id
                 WHERE rp.role_id = $1
                 ORDER BY p.module, p.action",
                &[&role_id],
            )
            .await?;

        Ok(rows
            .into_iter()
            .map(|r| Permission {
                id: r.get(0),
                code: r.get(1),
                name: r.get(2),
                description: r.get(3),
                module: r.get(4),
                action: r.get(5),
                created_at: r.get(6),
            })
            .collect())
    }
}

pub struct PostgresRoleRepository {
    pool: DbPool,
}

impl PostgresRoleRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RoleRepository for PostgresRoleRepository {
    async fn get_role(&self, role_id: RoleId) -> anyhow::Result<Option<Role>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, organization_id, name, description, is_system, created_at, updated_at
                 FROM roles
                 WHERE id = $1",
                &[&role_id],
            )
            .await?;

        Ok(row.map(|r| Role {
            id: r.get(0),
            organization_id: r.get(1),
            name: r.get(2),
            description: r.get(3),
            is_system: r.get(4),
            created_at: r.get(5),
            updated_at: r.get(6),
        }))
    }

    async fn get_system_role_by_name(&self, name: &str) -> anyhow::Result<Option<Role>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, organization_id, name, description, is_system, created_at, updated_at
                 FROM roles
                 WHERE name = $1 AND is_system = TRUE",
                &[&name],
            )
            .await?;

        Ok(row.map(|r| Role {
            id: r.get(0),
            organization_id: r.get(1),
            name: r.get(2),
            description: r.get(3),
            is_system: r.get(4),
            created_at: r.get(5),
            updated_at: r.get(6),
        }))
    }

    async fn get_system_roles(&self) -> anyhow::Result<Vec<Role>> {
        let client = self.pool.get().await?;

        let rows = client
            .query(
                "SELECT id, organization_id, name, description, is_system, created_at, updated_at
                 FROM roles
                 WHERE is_system = TRUE
                 ORDER BY name",
                &[],
            )
            .await?;

        Ok(rows
            .into_iter()
            .map(|r| Role {
                id: r.get(0),
                organization_id: r.get(1),
                name: r.get(2),
                description: r.get(3),
                is_system: r.get(4),
                created_at: r.get(5),
                updated_at: r.get(6),
            })
            .collect())
    }

    async fn get_organization_roles(
        &self,
        organization_id: OrganizationId,
    ) -> anyhow::Result<Vec<Role>> {
        let client = self.pool.get().await?;

        let rows = client
            .query(
                "SELECT id, organization_id, name, description, is_system, created_at, updated_at
                 FROM roles
                 WHERE organization_id = $1
                 ORDER BY name",
                &[&organization_id],
            )
            .await?;

        Ok(rows
            .into_iter()
            .map(|r| Role {
                id: r.get(0),
                organization_id: r.get(1),
                name: r.get(2),
                description: r.get(3),
                is_system: r.get(4),
                created_at: r.get(5),
                updated_at: r.get(6),
            })
            .collect())
    }

    async fn create_role(&self, params: CreateRoleParams) -> anyhow::Result<Role> {
        tracing::info!(
            "Repository: Creating role name={}, organization_id={}",
            params.name,
            params.organization_id
        );

        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;

        let row = transaction
            .query_one(
                "INSERT INTO roles (organization_id, name, description, is_system)
                 VALUES ($1, $2, $3, FALSE)
                 RETURNING id, organization_id, name, description, is_system, created_at, updated_at",
                &[&params.organization_id, &params.name, &params.description],
            )
            .await?;

        let role = Role {
            id: row.get(0),
            organization_id: row.get(1),
            name: row.get(2),
            description: row.get(3),
            is_system: row.get(4),
            created_at: row.get(5),
            updated_at: row.get(6),
        };

        // Add permissions
        for permission_id in params.permission_ids {
            transaction
                .execute(
                    "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)",
                    &[&role.id, &permission_id],
                )
                .await?;
        }

        transaction.commit().await?;

        tracing::info!("Repository: Role created role_id={}", role.id);

        Ok(role)
    }

    async fn update_role(
        &self,
        role_id: RoleId,
        params: UpdateRoleParams,
    ) -> anyhow::Result<Role> {
        tracing::info!("Repository: Updating role role_id={}", role_id);

        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;

        let mut updates = Vec::new();
        let mut param_idx = 2;
        let mut values: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> =
            vec![Box::new(role_id)];

        if let Some(ref name) = params.name {
            updates.push(format!("name = ${}", param_idx));
            values.push(Box::new(name.clone()));
            param_idx += 1;
        }

        if let Some(ref description) = params.description {
            updates.push(format!("description = ${}", param_idx));
            values.push(Box::new(description.clone()));
        }

        let role = if updates.is_empty() {
            self.get_role(role_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Role not found"))?
        } else {
            let query = format!(
                "UPDATE roles SET {} WHERE id = $1
                 RETURNING id, organization_id, name, description, is_system, created_at, updated_at",
                updates.join(", ")
            );

            let query_params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
                values.iter().map(|v| v.as_ref() as _).collect();

            let row = transaction.query_one(&query, &query_params).await?;

            Role {
                id: row.get(0),
                organization_id: row.get(1),
                name: row.get(2),
                description: row.get(3),
                is_system: row.get(4),
                created_at: row.get(5),
                updated_at: row.get(6),
            }
        };

        // Update permissions if provided
        if let Some(permission_ids) = params.permission_ids {
            transaction
                .execute(
                    "DELETE FROM role_permissions WHERE role_id = $1",
                    &[&role_id],
                )
                .await?;

            for permission_id in permission_ids {
                transaction
                    .execute(
                        "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)",
                        &[&role_id, &permission_id],
                    )
                    .await?;
            }
        }

        transaction.commit().await?;

        Ok(role)
    }

    async fn delete_role(&self, role_id: RoleId) -> anyhow::Result<()> {
        tracing::warn!("Repository: Deleting role role_id={}", role_id);

        let client = self.pool.get().await?;

        client
            .execute("DELETE FROM roles WHERE id = $1 AND is_system = FALSE", &[&role_id])
            .await?;

        Ok(())
    }

    async fn assign_role_to_user(
        &self,
        user_id: UserId,
        role_id: RoleId,
        organization_id: Option<OrganizationId>,
        workspace_id: Option<WorkspaceId>,
    ) -> anyhow::Result<()> {
        tracing::info!(
            "Repository: Assigning role to user: user_id={}, role_id={}",
            user_id,
            role_id
        );

        let client = self.pool.get().await?;

        client
            .execute(
                "INSERT INTO user_roles (user_id, role_id, organization_id, workspace_id)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (user_id, role_id, organization_id, workspace_id) DO NOTHING",
                &[&user_id, &role_id, &organization_id, &workspace_id],
            )
            .await?;

        Ok(())
    }

    async fn remove_role_from_user(
        &self,
        user_id: UserId,
        role_id: RoleId,
        organization_id: Option<OrganizationId>,
        workspace_id: Option<WorkspaceId>,
    ) -> anyhow::Result<()> {
        tracing::warn!(
            "Repository: Removing role from user: user_id={}, role_id={}",
            user_id,
            role_id
        );

        let client = self.pool.get().await?;

        // Handle NULL comparisons properly
        client
            .execute(
                "DELETE FROM user_roles
                 WHERE user_id = $1 AND role_id = $2
                 AND (organization_id = $3 OR (organization_id IS NULL AND $3 IS NULL))
                 AND (workspace_id = $4 OR (workspace_id IS NULL AND $4 IS NULL))",
                &[&user_id, &role_id, &organization_id, &workspace_id],
            )
            .await?;

        Ok(())
    }

    async fn get_user_roles(
        &self,
        user_id: UserId,
        organization_id: Option<OrganizationId>,
        workspace_id: Option<WorkspaceId>,
    ) -> anyhow::Result<Vec<UserRoleAssignment>> {
        let client = self.pool.get().await?;

        let rows = client
            .query(
                "SELECT ur.user_id, ur.role_id, r.name, ur.organization_id, ur.workspace_id, ur.created_at
                 FROM user_roles ur
                 JOIN roles r ON r.id = ur.role_id
                 WHERE ur.user_id = $1
                 AND (ur.organization_id = $2 OR ur.organization_id IS NULL OR $2 IS NULL)
                 AND (ur.workspace_id = $3 OR ur.workspace_id IS NULL OR $3 IS NULL)",
                &[&user_id, &organization_id, &workspace_id],
            )
            .await?;

        Ok(rows
            .into_iter()
            .map(|r| UserRoleAssignment {
                user_id: r.get(0),
                role_id: r.get(1),
                role_name: r.get(2),
                organization_id: r.get(3),
                workspace_id: r.get(4),
                created_at: r.get(5),
            })
            .collect())
    }

    async fn get_user_permissions(
        &self,
        user_id: UserId,
        organization_id: Option<OrganizationId>,
        workspace_id: Option<WorkspaceId>,
    ) -> anyhow::Result<Vec<String>> {
        let client = self.pool.get().await?;

        let rows = client
            .query(
                "SELECT DISTINCT p.code
                 FROM permissions p
                 JOIN role_permissions rp ON rp.permission_id = p.id
                 JOIN user_roles ur ON ur.role_id = rp.role_id
                 WHERE ur.user_id = $1
                 AND (ur.organization_id = $2 OR ur.organization_id IS NULL OR $2 IS NULL)
                 AND (ur.workspace_id = $3 OR ur.workspace_id IS NULL OR $3 IS NULL)",
                &[&user_id, &organization_id, &workspace_id],
            )
            .await?;

        Ok(rows.into_iter().map(|r| r.get(0)).collect())
    }

    async fn set_role_permissions(
        &self,
        role_id: RoleId,
        permission_ids: Vec<PermissionId>,
    ) -> anyhow::Result<()> {
        tracing::info!(
            "Repository: Setting role permissions: role_id={}, count={}",
            role_id,
            permission_ids.len()
        );

        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;

        transaction
            .execute("DELETE FROM role_permissions WHERE role_id = $1", &[&role_id])
            .await?;

        for permission_id in permission_ids {
            transaction
                .execute(
                    "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)",
                    &[&role_id, &permission_id],
                )
                .await?;
        }

        transaction.commit().await?;

        Ok(())
    }
}
