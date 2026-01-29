//! PostgreSQL implementations for OAuth client and token repositories.

use async_trait::async_trait;
use uuid::Uuid;

use crate::pool::DbPool;
use services::{
    auth::{
        AccessGrantRepository, AccessTokenRepository, AuthorizationCodeRepository,
        CreateAccessToken, CreateAuthorizationCode, CreateOAuthClient, CreatePendingAuthorization,
        CreateProject, CreateRefreshToken, OAuthAccessGrant, OAuthAccessToken,
        OAuthAuthorizationCode, OAuthClient, OAuthClientRepository, OAuthClientType,
        OAuthPendingAuthorization, OAuthRefreshToken, PendingAuthorizationRepository, Project,
        ProjectRepository, RefreshTokenRepository, UpdateProject, UpsertAccessGrant,
    },
    UserId,
};

// =============================================================================
// Project Repository
// =============================================================================

pub struct PostgresProjectRepository {
    pool: DbPool,
}

impl PostgresProjectRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ProjectRepository for PostgresProjectRepository {
    async fn create(&self, input: CreateProject) -> anyhow::Result<Project> {
        let client = self.pool.get().await?;

        let row = client
            .query_one(
                "INSERT INTO projects (owner_id, name, description, homepage_url, privacy_policy_url, terms_url)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 RETURNING id, owner_id, name, description, homepage_url, privacy_policy_url, terms_url, created_at, updated_at",
                &[
                    &input.owner_id,
                    &input.name,
                    &input.description,
                    &input.homepage_url,
                    &input.privacy_policy_url,
                    &input.terms_url,
                ],
            )
            .await?;

        Ok(Project {
            id: row.get(0),
            owner_id: row.get(1),
            name: row.get(2),
            description: row.get(3),
            homepage_url: row.get(4),
            privacy_policy_url: row.get(5),
            terms_url: row.get(6),
            created_at: row.get(7),
            updated_at: row.get(8),
        })
    }

    async fn get_by_id(&self, id: Uuid) -> anyhow::Result<Option<Project>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, owner_id, name, description, homepage_url, privacy_policy_url, terms_url, created_at, updated_at
                 FROM projects WHERE id = $1",
                &[&id],
            )
            .await?;

        Ok(row.map(|r| Project {
            id: r.get(0),
            owner_id: r.get(1),
            name: r.get(2),
            description: r.get(3),
            homepage_url: r.get(4),
            privacy_policy_url: r.get(5),
            terms_url: r.get(6),
            created_at: r.get(7),
            updated_at: r.get(8),
        }))
    }

    async fn list_by_owner(&self, owner_id: UserId) -> anyhow::Result<Vec<Project>> {
        let client = self.pool.get().await?;

        let rows = client
            .query(
                "SELECT id, owner_id, name, description, homepage_url, privacy_policy_url, terms_url, created_at, updated_at
                 FROM projects WHERE owner_id = $1 ORDER BY created_at DESC",
                &[&owner_id],
            )
            .await?;

        Ok(rows
            .iter()
            .map(|r| Project {
                id: r.get(0),
                owner_id: r.get(1),
                name: r.get(2),
                description: r.get(3),
                homepage_url: r.get(4),
                privacy_policy_url: r.get(5),
                terms_url: r.get(6),
                created_at: r.get(7),
                updated_at: r.get(8),
            })
            .collect())
    }

    async fn update(&self, id: Uuid, input: UpdateProject) -> anyhow::Result<Option<Project>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "UPDATE projects SET
                    name = COALESCE($2, name),
                    description = COALESCE($3, description),
                    homepage_url = COALESCE($4, homepage_url),
                    privacy_policy_url = COALESCE($5, privacy_policy_url),
                    terms_url = COALESCE($6, terms_url),
                    updated_at = NOW()
                 WHERE id = $1
                 RETURNING id, owner_id, name, description, homepage_url, privacy_policy_url, terms_url, created_at, updated_at",
                &[
                    &id,
                    &input.name,
                    &input.description,
                    &input.homepage_url,
                    &input.privacy_policy_url,
                    &input.terms_url,
                ],
            )
            .await?;

        Ok(row.map(|r| Project {
            id: r.get(0),
            owner_id: r.get(1),
            name: r.get(2),
            description: r.get(3),
            homepage_url: r.get(4),
            privacy_policy_url: r.get(5),
            terms_url: r.get(6),
            created_at: r.get(7),
            updated_at: r.get(8),
        }))
    }

    async fn delete(&self, id: Uuid) -> anyhow::Result<bool> {
        let client = self.pool.get().await?;

        let result = client
            .execute("DELETE FROM projects WHERE id = $1", &[&id])
            .await?;

        Ok(result > 0)
    }
}

// =============================================================================
// OAuth Client Repository
// =============================================================================

pub struct PostgresOAuthClientRepository {
    pool: DbPool,
}

impl PostgresOAuthClientRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

fn row_to_oauth_client(row: &tokio_postgres::Row) -> OAuthClient {
    let client_type_str: String = row.get(4);
    OAuthClient {
        id: row.get(0),
        project_id: row.get(1),
        client_id: row.get(2),
        client_secret_hash: row.get(3),
        client_type: OAuthClientType::from_str(&client_type_str).unwrap_or(OAuthClientType::Public),
        redirect_uris: row.get(5),
        allowed_scopes: row.get(6),
        created_at: row.get(7),
        revoked_at: row.get(8),
    }
}

#[async_trait]
impl OAuthClientRepository for PostgresOAuthClientRepository {
    async fn create(&self, input: CreateOAuthClient) -> anyhow::Result<OAuthClient> {
        let client = self.pool.get().await?;

        let row = client
            .query_one(
                "INSERT INTO oauth_clients (project_id, client_id, client_secret_hash, client_type, redirect_uris, allowed_scopes)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 RETURNING id, project_id, client_id, client_secret_hash, client_type, redirect_uris, allowed_scopes, created_at, revoked_at",
                &[
                    &input.project_id,
                    &input.client_id,
                    &input.client_secret_hash,
                    &input.client_type.as_str(),
                    &input.redirect_uris,
                    &input.allowed_scopes,
                ],
            )
            .await?;

        Ok(row_to_oauth_client(&row))
    }

    async fn get_by_client_id(&self, client_id: &str) -> anyhow::Result<Option<OAuthClient>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, project_id, client_id, client_secret_hash, client_type, redirect_uris, allowed_scopes, created_at, revoked_at
                 FROM oauth_clients WHERE client_id = $1",
                &[&client_id],
            )
            .await?;

        Ok(row.map(|r| row_to_oauth_client(&r)))
    }

    async fn get_by_id(&self, id: Uuid) -> anyhow::Result<Option<OAuthClient>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, project_id, client_id, client_secret_hash, client_type, redirect_uris, allowed_scopes, created_at, revoked_at
                 FROM oauth_clients WHERE id = $1",
                &[&id],
            )
            .await?;

        Ok(row.map(|r| row_to_oauth_client(&r)))
    }

    async fn list_by_project(&self, project_id: Uuid) -> anyhow::Result<Vec<OAuthClient>> {
        let client = self.pool.get().await?;

        let rows = client
            .query(
                "SELECT id, project_id, client_id, client_secret_hash, client_type, redirect_uris, allowed_scopes, created_at, revoked_at
                 FROM oauth_clients WHERE project_id = $1 ORDER BY created_at DESC",
                &[&project_id],
            )
            .await?;

        Ok(rows.iter().map(row_to_oauth_client).collect())
    }

    async fn revoke(&self, client_id: &str) -> anyhow::Result<bool> {
        let client = self.pool.get().await?;

        let result = client
            .execute(
                "UPDATE oauth_clients SET revoked_at = NOW() WHERE client_id = $1 AND revoked_at IS NULL",
                &[&client_id],
            )
            .await?;

        Ok(result > 0)
    }

    async fn update_secret(&self, client_id: &str, new_secret_hash: String) -> anyhow::Result<bool> {
        let client = self.pool.get().await?;

        let result = client
            .execute(
                "UPDATE oauth_clients SET client_secret_hash = $2 WHERE client_id = $1",
                &[&client_id, &new_secret_hash],
            )
            .await?;

        Ok(result > 0)
    }
}

// =============================================================================
// Authorization Code Repository
// =============================================================================

pub struct PostgresAuthorizationCodeRepository {
    pool: DbPool,
}

impl PostgresAuthorizationCodeRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuthorizationCodeRepository for PostgresAuthorizationCodeRepository {
    async fn create(&self, input: CreateAuthorizationCode) -> anyhow::Result<()> {
        let client = self.pool.get().await?;

        client
            .execute(
                "INSERT INTO oauth_authorization_codes (code, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                &[
                    &input.code,
                    &input.client_id,
                    &input.user_id,
                    &input.redirect_uri,
                    &input.scopes,
                    &input.code_challenge,
                    &input.code_challenge_method,
                    &input.expires_at,
                ],
            )
            .await?;

        Ok(())
    }

    async fn consume(&self, code: &str) -> anyhow::Result<Option<OAuthAuthorizationCode>> {
        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;

        // Get and delete in one transaction
        let row = transaction
            .query_opt(
                "DELETE FROM oauth_authorization_codes
                 WHERE code = $1 AND expires_at > NOW()
                 RETURNING code, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, expires_at, created_at",
                &[&code],
            )
            .await?;

        transaction.commit().await?;

        Ok(row.map(|r| OAuthAuthorizationCode {
            code: r.get(0),
            client_id: r.get(1),
            user_id: r.get(2),
            redirect_uri: r.get(3),
            scopes: r.get(4),
            code_challenge: r.get(5),
            code_challenge_method: r.get(6),
            expires_at: r.get(7),
            created_at: r.get(8),
        }))
    }

    async fn delete_expired(&self) -> anyhow::Result<u64> {
        let client = self.pool.get().await?;

        let result = client
            .execute(
                "DELETE FROM oauth_authorization_codes WHERE expires_at <= NOW()",
                &[],
            )
            .await?;

        Ok(result)
    }
}

// =============================================================================
// Access Token Repository
// =============================================================================

pub struct PostgresAccessTokenRepository {
    pool: DbPool,
}

impl PostgresAccessTokenRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

fn row_to_access_token(row: &tokio_postgres::Row) -> OAuthAccessToken {
    OAuthAccessToken {
        id: row.get(0),
        token_hash: row.get(1),
        client_id: row.get(2),
        user_id: row.get(3),
        scopes: row.get(4),
        expires_at: row.get(5),
        created_at: row.get(6),
        revoked_at: row.get(7),
    }
}

#[async_trait]
impl AccessTokenRepository for PostgresAccessTokenRepository {
    async fn create(&self, input: CreateAccessToken) -> anyhow::Result<OAuthAccessToken> {
        let client = self.pool.get().await?;

        let row = client
            .query_one(
                "INSERT INTO oauth_access_tokens (token_hash, client_id, user_id, scopes, expires_at)
                 VALUES ($1, $2, $3, $4, $5)
                 RETURNING id, token_hash, client_id, user_id, scopes, expires_at, created_at, revoked_at",
                &[
                    &input.token_hash,
                    &input.client_id,
                    &input.user_id,
                    &input.scopes,
                    &input.expires_at,
                ],
            )
            .await?;

        Ok(row_to_access_token(&row))
    }

    async fn get_by_hash(&self, token_hash: &str) -> anyhow::Result<Option<OAuthAccessToken>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, token_hash, client_id, user_id, scopes, expires_at, created_at, revoked_at
                 FROM oauth_access_tokens WHERE token_hash = $1",
                &[&token_hash],
            )
            .await?;

        Ok(row.map(|r| row_to_access_token(&r)))
    }

    async fn get_by_id(&self, id: Uuid) -> anyhow::Result<Option<OAuthAccessToken>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, token_hash, client_id, user_id, scopes, expires_at, created_at, revoked_at
                 FROM oauth_access_tokens WHERE id = $1",
                &[&id],
            )
            .await?;

        Ok(row.map(|r| row_to_access_token(&r)))
    }

    async fn list_by_user(&self, user_id: UserId) -> anyhow::Result<Vec<OAuthAccessToken>> {
        let client = self.pool.get().await?;

        let rows = client
            .query(
                "SELECT id, token_hash, client_id, user_id, scopes, expires_at, created_at, revoked_at
                 FROM oauth_access_tokens WHERE user_id = $1 ORDER BY created_at DESC",
                &[&user_id],
            )
            .await?;

        Ok(rows.iter().map(row_to_access_token).collect())
    }

    async fn revoke(&self, id: Uuid) -> anyhow::Result<bool> {
        let client = self.pool.get().await?;

        let result = client
            .execute(
                "UPDATE oauth_access_tokens SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL",
                &[&id],
            )
            .await?;

        Ok(result > 0)
    }

    async fn revoke_by_user_and_client(
        &self,
        user_id: UserId,
        client_id: &str,
    ) -> anyhow::Result<u64> {
        let client = self.pool.get().await?;

        let result = client
            .execute(
                "UPDATE oauth_access_tokens SET revoked_at = NOW() WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL",
                &[&user_id, &client_id],
            )
            .await?;

        Ok(result)
    }

    async fn delete_expired(&self) -> anyhow::Result<u64> {
        let client = self.pool.get().await?;

        let result = client
            .execute(
                "DELETE FROM oauth_access_tokens WHERE expires_at <= NOW() AND revoked_at IS NOT NULL",
                &[],
            )
            .await?;

        Ok(result)
    }
}

// =============================================================================
// Refresh Token Repository
// =============================================================================

pub struct PostgresRefreshTokenRepository {
    pool: DbPool,
}

impl PostgresRefreshTokenRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

fn row_to_refresh_token(row: &tokio_postgres::Row) -> OAuthRefreshToken {
    OAuthRefreshToken {
        id: row.get(0),
        token_hash: row.get(1),
        access_token_id: row.get(2),
        user_id: row.get(3),
        client_id: row.get(4),
        expires_at: row.get(5),
        created_at: row.get(6),
        revoked_at: row.get(7),
    }
}

#[async_trait]
impl RefreshTokenRepository for PostgresRefreshTokenRepository {
    async fn create(&self, input: CreateRefreshToken) -> anyhow::Result<OAuthRefreshToken> {
        let client = self.pool.get().await?;

        let row = client
            .query_one(
                "INSERT INTO oauth_refresh_tokens (token_hash, access_token_id, user_id, client_id, expires_at)
                 VALUES ($1, $2, $3, $4, $5)
                 RETURNING id, token_hash, access_token_id, user_id, client_id, expires_at, created_at, revoked_at",
                &[&input.token_hash, &input.access_token_id, &input.user_id, &input.client_id, &input.expires_at],
            )
            .await?;

        Ok(row_to_refresh_token(&row))
    }

    async fn get_by_hash(&self, token_hash: &str) -> anyhow::Result<Option<OAuthRefreshToken>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, token_hash, access_token_id, user_id, client_id, expires_at, created_at, revoked_at
                 FROM oauth_refresh_tokens WHERE token_hash = $1",
                &[&token_hash],
            )
            .await?;

        Ok(row.map(|r| row_to_refresh_token(&r)))
    }

    async fn revoke(&self, id: Uuid) -> anyhow::Result<bool> {
        let client = self.pool.get().await?;

        let result = client
            .execute(
                "UPDATE oauth_refresh_tokens SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL",
                &[&id],
            )
            .await?;

        Ok(result > 0)
    }

    async fn revoke_by_access_token(&self, access_token_id: Uuid) -> anyhow::Result<bool> {
        let client = self.pool.get().await?;

        let result = client
            .execute(
                "UPDATE oauth_refresh_tokens SET revoked_at = NOW() WHERE access_token_id = $1 AND revoked_at IS NULL",
                &[&access_token_id],
            )
            .await?;

        Ok(result > 0)
    }

    async fn delete_expired(&self) -> anyhow::Result<u64> {
        let client = self.pool.get().await?;

        let result = client
            .execute(
                "DELETE FROM oauth_refresh_tokens WHERE expires_at <= NOW() AND revoked_at IS NOT NULL",
                &[],
            )
            .await?;

        Ok(result)
    }
}

// =============================================================================
// Access Grant Repository
// =============================================================================

pub struct PostgresAccessGrantRepository {
    pool: DbPool,
}

impl PostgresAccessGrantRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

fn row_to_access_grant(row: &tokio_postgres::Row) -> OAuthAccessGrant {
    OAuthAccessGrant {
        id: row.get(0),
        user_id: row.get(1),
        client_id: row.get(2),
        scopes: row.get(3),
        created_at: row.get(4),
        revoked_at: row.get(5),
    }
}

#[async_trait]
impl AccessGrantRepository for PostgresAccessGrantRepository {
    async fn upsert(&self, input: UpsertAccessGrant) -> anyhow::Result<OAuthAccessGrant> {
        let client = self.pool.get().await?;

        // Upsert: insert or update scopes (merge with existing)
        let row = client
            .query_one(
                "INSERT INTO oauth_access_grants (user_id, client_id, scopes)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (user_id, client_id) DO UPDATE SET
                    scopes = (
                        SELECT ARRAY(SELECT DISTINCT unnest FROM unnest(oauth_access_grants.scopes || EXCLUDED.scopes))
                    ),
                    revoked_at = NULL
                 RETURNING id, user_id, client_id, scopes, created_at, revoked_at",
                &[&input.user_id, &input.client_id, &input.scopes],
            )
            .await?;

        Ok(row_to_access_grant(&row))
    }

    async fn get(&self, user_id: UserId, client_id: &str) -> anyhow::Result<Option<OAuthAccessGrant>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, user_id, client_id, scopes, created_at, revoked_at
                 FROM oauth_access_grants WHERE user_id = $1 AND client_id = $2",
                &[&user_id, &client_id],
            )
            .await?;

        Ok(row.map(|r| row_to_access_grant(&r)))
    }

    async fn list_by_user(&self, user_id: UserId) -> anyhow::Result<Vec<OAuthAccessGrant>> {
        let client = self.pool.get().await?;

        let rows = client
            .query(
                "SELECT id, user_id, client_id, scopes, created_at, revoked_at
                 FROM oauth_access_grants WHERE user_id = $1 AND revoked_at IS NULL
                 ORDER BY created_at DESC",
                &[&user_id],
            )
            .await?;

        Ok(rows.iter().map(row_to_access_grant).collect())
    }

    async fn revoke(&self, user_id: UserId, client_id: &str) -> anyhow::Result<bool> {
        let client = self.pool.get().await?;

        let result = client
            .execute(
                "UPDATE oauth_access_grants SET revoked_at = NOW() WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL",
                &[&user_id, &client_id],
            )
            .await?;

        Ok(result > 0)
    }
}

// =============================================================================
// Pending Authorization Repository
// =============================================================================

pub struct PostgresPendingAuthorizationRepository {
    pool: DbPool,
}

impl PostgresPendingAuthorizationRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

fn row_to_pending_authorization(row: &tokio_postgres::Row) -> OAuthPendingAuthorization {
    OAuthPendingAuthorization {
        id: row.get(0),
        client_id: row.get(1),
        user_id: row.get(2),
        redirect_uri: row.get(3),
        scopes: row.get(4),
        state: row.get(5),
        code_challenge: row.get(6),
        code_challenge_method: row.get(7),
        expires_at: row.get(8),
        created_at: row.get(9),
    }
}

#[async_trait]
impl PendingAuthorizationRepository for PostgresPendingAuthorizationRepository {
    async fn create(&self, input: CreatePendingAuthorization) -> anyhow::Result<OAuthPendingAuthorization> {
        let client = self.pool.get().await?;

        let row = client
            .query_one(
                "INSERT INTO oauth_pending_authorizations (client_id, user_id, redirect_uri, scopes, state, code_challenge, code_challenge_method, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 RETURNING id, client_id, user_id, redirect_uri, scopes, state, code_challenge, code_challenge_method, expires_at, created_at",
                &[
                    &input.client_id,
                    &input.user_id,
                    &input.redirect_uri,
                    &input.scopes,
                    &input.state,
                    &input.code_challenge,
                    &input.code_challenge_method,
                    &input.expires_at,
                ],
            )
            .await?;

        Ok(row_to_pending_authorization(&row))
    }

    async fn get_by_id(&self, id: Uuid) -> anyhow::Result<Option<OAuthPendingAuthorization>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, client_id, user_id, redirect_uri, scopes, state, code_challenge, code_challenge_method, expires_at, created_at
                 FROM oauth_pending_authorizations WHERE id = $1 AND expires_at > NOW()",
                &[&id],
            )
            .await?;

        Ok(row.map(|r| row_to_pending_authorization(&r)))
    }

    async fn consume(&self, id: Uuid) -> anyhow::Result<Option<OAuthPendingAuthorization>> {
        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;

        // Get and delete in one transaction
        let row = transaction
            .query_opt(
                "DELETE FROM oauth_pending_authorizations
                 WHERE id = $1 AND expires_at > NOW()
                 RETURNING id, client_id, user_id, redirect_uri, scopes, state, code_challenge, code_challenge_method, expires_at, created_at",
                &[&id],
            )
            .await?;

        transaction.commit().await?;

        Ok(row.map(|r| row_to_pending_authorization(&r)))
    }

    async fn delete_expired(&self) -> anyhow::Result<u64> {
        let client = self.pool.get().await?;

        let result = client
            .execute(
                "DELETE FROM oauth_pending_authorizations WHERE expires_at <= NOW()",
                &[],
            )
            .await?;

        Ok(result)
    }
}
