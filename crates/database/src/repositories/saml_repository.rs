use crate::pool::DbPool;
use async_trait::async_trait;
use services::{
    saml::ports::{
        CreateSamlConfigParams, SamlAttributeMapping, SamlAuthState, SamlAuthStateRepository,
        SamlConfig, SamlIdpConfigRepository, SamlSession, UpdateSamlConfigParams,
    },
    OrganizationId, SessionId,
};

pub struct PostgresSamlIdpConfigRepository {
    pool: DbPool,
}

impl PostgresSamlIdpConfigRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SamlIdpConfigRepository for PostgresSamlIdpConfigRepository {
    async fn get_saml_config(
        &self,
        organization_id: OrganizationId,
    ) -> anyhow::Result<Option<SamlConfig>> {
        tracing::debug!(
            "Repository: Fetching SAML config for organization_id={}",
            organization_id
        );

        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, organization_id, idp_entity_id, idp_sso_url, idp_slo_url,
                        idp_certificate, sp_entity_id, sp_acs_url, attribute_mapping,
                        jit_provisioning_enabled, jit_default_role, jit_default_workspace_id,
                        is_enabled, is_verified, created_at, updated_at
                 FROM saml_configs
                 WHERE organization_id = $1",
                &[&organization_id],
            )
            .await?;

        Ok(row.map(|r| SamlConfig {
            id: r.get(0),
            organization_id: r.get(1),
            idp_entity_id: r.get(2),
            idp_sso_url: r.get(3),
            idp_slo_url: r.get(4),
            idp_certificate: r.get(5),
            sp_entity_id: r.get(6),
            sp_acs_url: r.get(7),
            attribute_mapping: serde_json::from_value(r.get(8)).unwrap_or_default(),
            jit_provisioning_enabled: r.get(9),
            jit_default_role: r.get(10),
            jit_default_workspace_id: r.get(11),
            is_enabled: r.get(12),
            is_verified: r.get(13),
            created_at: r.get(14),
            updated_at: r.get(15),
        }))
    }

    async fn create_saml_config(&self, params: CreateSamlConfigParams) -> anyhow::Result<SamlConfig> {
        tracing::info!(
            "Repository: Creating SAML config for organization_id={}",
            params.organization_id
        );

        let client = self.pool.get().await?;
        let attribute_mapping_json = serde_json::to_value(&params.attribute_mapping)?;

        let row = client
            .query_one(
                "INSERT INTO saml_configs (
                    organization_id, idp_entity_id, idp_sso_url, idp_slo_url, idp_certificate,
                    sp_entity_id, sp_acs_url, attribute_mapping, jit_provisioning_enabled,
                    jit_default_role, jit_default_workspace_id
                 )
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                 RETURNING id, organization_id, idp_entity_id, idp_sso_url, idp_slo_url,
                           idp_certificate, sp_entity_id, sp_acs_url, attribute_mapping,
                           jit_provisioning_enabled, jit_default_role, jit_default_workspace_id,
                           is_enabled, is_verified, created_at, updated_at",
                &[
                    &params.organization_id,
                    &params.idp_entity_id,
                    &params.idp_sso_url,
                    &params.idp_slo_url,
                    &params.idp_certificate,
                    &params.sp_entity_id,
                    &params.sp_acs_url,
                    &attribute_mapping_json,
                    &params.jit_provisioning_enabled,
                    &params.jit_default_role,
                    &params.jit_default_workspace_id,
                ],
            )
            .await?;

        Ok(SamlConfig {
            id: row.get(0),
            organization_id: row.get(1),
            idp_entity_id: row.get(2),
            idp_sso_url: row.get(3),
            idp_slo_url: row.get(4),
            idp_certificate: row.get(5),
            sp_entity_id: row.get(6),
            sp_acs_url: row.get(7),
            attribute_mapping: serde_json::from_value(row.get(8)).unwrap_or_default(),
            jit_provisioning_enabled: row.get(9),
            jit_default_role: row.get(10),
            jit_default_workspace_id: row.get(11),
            is_enabled: row.get(12),
            is_verified: row.get(13),
            created_at: row.get(14),
            updated_at: row.get(15),
        })
    }

    async fn update_saml_config(
        &self,
        organization_id: OrganizationId,
        params: UpdateSamlConfigParams,
    ) -> anyhow::Result<SamlConfig> {
        tracing::info!(
            "Repository: Updating SAML config for organization_id={}",
            organization_id
        );

        let client = self.pool.get().await?;

        let mut updates = Vec::new();
        let mut param_idx = 2;
        let mut values: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> =
            vec![Box::new(organization_id)];

        if let Some(ref idp_entity_id) = params.idp_entity_id {
            updates.push(format!("idp_entity_id = ${}", param_idx));
            values.push(Box::new(idp_entity_id.clone()));
            param_idx += 1;
        }

        if let Some(ref idp_sso_url) = params.idp_sso_url {
            updates.push(format!("idp_sso_url = ${}", param_idx));
            values.push(Box::new(idp_sso_url.clone()));
            param_idx += 1;
        }

        if let Some(ref idp_slo_url) = params.idp_slo_url {
            updates.push(format!("idp_slo_url = ${}", param_idx));
            values.push(Box::new(idp_slo_url.clone()));
            param_idx += 1;
        }

        if let Some(ref idp_certificate) = params.idp_certificate {
            updates.push(format!("idp_certificate = ${}", param_idx));
            values.push(Box::new(idp_certificate.clone()));
            param_idx += 1;
        }

        if let Some(ref attribute_mapping) = params.attribute_mapping {
            let json = serde_json::to_value(attribute_mapping)?;
            updates.push(format!("attribute_mapping = ${}", param_idx));
            values.push(Box::new(json));
            param_idx += 1;
        }

        if let Some(jit_enabled) = params.jit_provisioning_enabled {
            updates.push(format!("jit_provisioning_enabled = ${}", param_idx));
            values.push(Box::new(jit_enabled));
            param_idx += 1;
        }

        if let Some(ref jit_role) = params.jit_default_role {
            updates.push(format!("jit_default_role = ${}", param_idx));
            values.push(Box::new(jit_role.clone()));
            param_idx += 1;
        }

        if let Some(ref jit_workspace_id) = params.jit_default_workspace_id {
            updates.push(format!("jit_default_workspace_id = ${}", param_idx));
            values.push(Box::new(*jit_workspace_id));
            param_idx += 1;
        }

        if let Some(is_enabled) = params.is_enabled {
            updates.push(format!("is_enabled = ${}", param_idx));
            values.push(Box::new(is_enabled));
        }

        if updates.is_empty() {
            return self
                .get_saml_config(organization_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("SAML config not found"));
        }

        let query = format!(
            "UPDATE saml_configs SET {}
             WHERE organization_id = $1
             RETURNING id, organization_id, idp_entity_id, idp_sso_url, idp_slo_url,
                       idp_certificate, sp_entity_id, sp_acs_url, attribute_mapping,
                       jit_provisioning_enabled, jit_default_role, jit_default_workspace_id,
                       is_enabled, is_verified, created_at, updated_at",
            updates.join(", ")
        );

        let query_params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            values.iter().map(|v| v.as_ref() as _).collect();

        let row = client.query_one(&query, &query_params).await?;

        Ok(SamlConfig {
            id: row.get(0),
            organization_id: row.get(1),
            idp_entity_id: row.get(2),
            idp_sso_url: row.get(3),
            idp_slo_url: row.get(4),
            idp_certificate: row.get(5),
            sp_entity_id: row.get(6),
            sp_acs_url: row.get(7),
            attribute_mapping: serde_json::from_value(row.get(8)).unwrap_or_default(),
            jit_provisioning_enabled: row.get(9),
            jit_default_role: row.get(10),
            jit_default_workspace_id: row.get(11),
            is_enabled: row.get(12),
            is_verified: row.get(13),
            created_at: row.get(14),
            updated_at: row.get(15),
        })
    }

    async fn delete_saml_config(&self, organization_id: OrganizationId) -> anyhow::Result<()> {
        tracing::warn!(
            "Repository: Deleting SAML config for organization_id={}",
            organization_id
        );

        let client = self.pool.get().await?;

        client
            .execute(
                "DELETE FROM saml_configs WHERE organization_id = $1",
                &[&organization_id],
            )
            .await?;

        Ok(())
    }

    async fn verify_saml_config(&self, organization_id: OrganizationId) -> anyhow::Result<()> {
        tracing::info!(
            "Repository: Verifying SAML config for organization_id={}",
            organization_id
        );

        let client = self.pool.get().await?;

        client
            .execute(
                "UPDATE saml_configs SET is_verified = TRUE WHERE organization_id = $1",
                &[&organization_id],
            )
            .await?;

        Ok(())
    }
}

pub struct PostgresSamlAuthStateRepository {
    pool: DbPool,
}

impl PostgresSamlAuthStateRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SamlAuthStateRepository for PostgresSamlAuthStateRepository {
    async fn create_auth_state(&self, state: SamlAuthState) -> anyhow::Result<()> {
        let client = self.pool.get().await?;

        client
            .execute(
                "INSERT INTO saml_auth_states (id, organization_id, relay_state)
                 VALUES ($1, $2, $3)",
                &[&state.id, &state.organization_id, &state.relay_state],
            )
            .await?;

        Ok(())
    }

    async fn consume_auth_state(&self, state_id: &str) -> anyhow::Result<Option<SamlAuthState>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "DELETE FROM saml_auth_states
                 WHERE id = $1 AND created_at > NOW() - INTERVAL '10 minutes'
                 RETURNING id, organization_id, relay_state, created_at",
                &[&state_id],
            )
            .await?;

        Ok(row.map(|r| SamlAuthState {
            id: r.get(0),
            organization_id: r.get(1),
            relay_state: r.get(2),
            created_at: r.get(3),
        }))
    }

    async fn cleanup_expired_states(&self) -> anyhow::Result<u64> {
        let client = self.pool.get().await?;

        let result = client
            .execute(
                "DELETE FROM saml_auth_states WHERE created_at < NOW() - INTERVAL '10 minutes'",
                &[],
            )
            .await?;

        Ok(result)
    }

    async fn create_saml_session(&self, session: SamlSession) -> anyhow::Result<()> {
        let client = self.pool.get().await?;

        client
            .execute(
                "INSERT INTO saml_sessions (id, session_id, organization_id, name_id,
                                           name_id_format, session_index, idp_session_id, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                &[
                    &session.id,
                    &session.session_id,
                    &session.organization_id,
                    &session.name_id,
                    &session.name_id_format,
                    &session.session_index,
                    &session.idp_session_id,
                    &session.expires_at,
                ],
            )
            .await?;

        Ok(())
    }

    async fn get_saml_session(&self, session_id: SessionId) -> anyhow::Result<Option<SamlSession>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, session_id, organization_id, name_id, name_id_format,
                        session_index, idp_session_id, created_at, expires_at
                 FROM saml_sessions
                 WHERE session_id = $1 AND expires_at > NOW()",
                &[&session_id],
            )
            .await?;

        Ok(row.map(|r| SamlSession {
            id: r.get(0),
            session_id: r.get(1),
            organization_id: r.get(2),
            name_id: r.get(3),
            name_id_format: r.get(4),
            session_index: r.get(5),
            idp_session_id: r.get(6),
            created_at: r.get(7),
            expires_at: r.get(8),
        }))
    }

    async fn delete_saml_session(&self, session_id: SessionId) -> anyhow::Result<()> {
        let client = self.pool.get().await?;

        client
            .execute(
                "DELETE FROM saml_sessions WHERE session_id = $1",
                &[&session_id],
            )
            .await?;

        Ok(())
    }
}
