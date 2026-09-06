use crate::pool::DbPool;
use async_trait::async_trait;
use services::{
    auth::ports::{OAuthRepository, OAuthState, OAuthTokens},
    user::ports::OAuthProvider,
    UserId,
};
use uuid::Uuid;

pub struct PostgresOAuthRepository {
    pool: DbPool,
}

impl PostgresOAuthRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    fn encode_token(&self, column: &str, id: Uuid, value: &str) -> anyhow::Result<String> {
        match self.pool.field_encryption() {
            Some(config) if config.write_enabled => crate::field_encryption::encrypt(
                &config.key,
                &config.key_id,
                "oauth_tokens",
                column,
                id,
                value,
            ),
            _ => Ok(value.to_string()),
        }
    }

    fn decode_token(&self, column: &str, id: Uuid, value: String) -> anyhow::Result<String> {
        match self.pool.field_encryption() {
            Some(config) => crate::field_encryption::decrypt_if_encrypted(
                &config.key,
                &config.key_id,
                "oauth_tokens",
                column,
                id,
                value,
            ),
            None => Ok(value),
        }
    }
}

#[async_trait]
impl OAuthRepository for PostgresOAuthRepository {
    async fn store_oauth_state(&self, state: &OAuthState) -> anyhow::Result<()> {
        let state_present = !state.state.is_empty();
        let state_len = state.state.len();
        tracing::debug!(
            state_present,
            state_len,
            provider = ?state.provider,
            "Repository: Storing OAuth state"
        );

        let client = self.pool.get().await?;

        let provider_str = match state.provider {
            OAuthProvider::Google => "google",
            OAuthProvider::Github => "github",
            OAuthProvider::Near => "near",
        };

        client
            .execute(
                "INSERT INTO oauth_states (state, provider, redirect_uri, frontend_callback, created_at) 
                 VALUES ($1, $2, $3, $4, $5)",
                &[
                    &state.state,
                    &provider_str,
                    &state.redirect_uri,
                    &state.frontend_callback,
                    &state.created_at,
                ],
            )
            .await?;

        tracing::debug!(
            state_present,
            state_len,
            "Repository: OAuth state stored successfully"
        );

        Ok(())
    }

    async fn consume_oauth_state(&self, state: &str) -> anyhow::Result<Option<OAuthState>> {
        let state_present = !state.is_empty();
        let state_len = state.len();
        tracing::debug!(
            state_present,
            state_len,
            "Repository: Consuming OAuth state"
        );

        let mut client = self.pool.get().await?;

        // Start a transaction
        let transaction = client.transaction().await?;

        // Get and delete the state in one go
        let row = transaction
            .query_opt(
                "DELETE FROM oauth_states 
                 WHERE state = $1 
                 RETURNING state, provider, redirect_uri, frontend_callback, created_at",
                &[&state],
            )
            .await?;

        transaction.commit().await?;

        let result = row.map(|r| {
            let provider_str: String = r.get(1);
            let provider = match provider_str.as_str() {
                "google" => OAuthProvider::Google,
                "github" => OAuthProvider::Github,
                "near" => OAuthProvider::Near,
                _ => OAuthProvider::Google, // fallback
            };

            OAuthState {
                state: r.get(0),
                provider,
                redirect_uri: r.get(2),
                frontend_callback: r.get(3),
                created_at: r.get(4),
            }
        });

        if result.is_some() {
            tracing::debug!(
                state_present,
                state_len,
                "Repository: OAuth state consumed successfully"
            );
        } else {
            tracing::warn!(
                state_present,
                state_len,
                "Repository: OAuth state not found or already consumed"
            );
        }

        Ok(result)
    }

    async fn store_oauth_tokens(
        &self,
        user_id: UserId,
        provider: OAuthProvider,
        tokens: &OAuthTokens,
    ) -> anyhow::Result<()> {
        tracing::debug!(
            "Repository: Storing OAuth tokens - user_id={}, provider={:?}, has_refresh_token={}",
            user_id,
            provider,
            tokens.refresh_token.is_some()
        );

        let mut client = self.pool.get().await?;

        let provider_str = match provider {
            OAuthProvider::Google => "google",
            OAuthProvider::Github => "github",
            OAuthProvider::Near => "near",
        };

        let transaction = client.transaction().await?;
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[&format!("oauth-token:{}:{provider_str}", user_id.0)],
            )
            .await?;
        let id = transaction
            .query_opt(
                "SELECT id FROM oauth_tokens WHERE user_id = $1 AND provider = $2 FOR UPDATE",
                &[&user_id, &provider_str],
            )
            .await?
            .map(|row| row.get(0))
            .unwrap_or_else(Uuid::new_v4);
        let access_token = self.encode_token("access_token", id, &tokens.access_token)?;
        let refresh_token = tokens
            .refresh_token
            .as_deref()
            .map(|value| self.encode_token("refresh_token", id, value))
            .transpose()?;
        let rows_affected = transaction
            .execute(
                "INSERT INTO oauth_tokens (id, user_id, provider, access_token, refresh_token, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (user_id, provider)
                 DO UPDATE SET
                    access_token = EXCLUDED.access_token,
                    refresh_token = EXCLUDED.refresh_token,
                    expires_at = EXCLUDED.expires_at,
                    updated_at = NOW()",
                &[
                    &id,
                    &user_id,
                    &provider_str,
                    &access_token,
                    &refresh_token,
                    &tokens.expires_at,
                ],
            )
            .await?;
        transaction.commit().await?;

        tracing::debug!(
            "Repository: OAuth tokens stored successfully - user_id={}, provider={:?}, rows_affected={}",
            user_id,
            provider,
            rows_affected
        );

        Ok(())
    }

    async fn get_oauth_tokens(
        &self,
        user_id: UserId,
        provider: OAuthProvider,
    ) -> anyhow::Result<Option<OAuthTokens>> {
        let client = self.pool.get().await?;

        let provider_str = match provider {
            OAuthProvider::Google => "google",
            OAuthProvider::Github => "github",
            OAuthProvider::Near => "near",
        };

        let row = client
            .query_opt(
                "SELECT id, access_token, refresh_token, expires_at
                 FROM oauth_tokens
                 WHERE user_id = $1 AND provider = $2",
                &[&user_id, &provider_str],
            )
            .await?;

        row.map(|r| {
            let id = r.get(0);
            Ok(OAuthTokens {
                access_token: self.decode_token("access_token", id, r.get(1))?,
                refresh_token: r
                    .get::<_, Option<String>>(2)
                    .map(|value| self.decode_token("refresh_token", id, value))
                    .transpose()?,
                expires_at: r.get(3),
            })
        })
        .transpose()
    }
}
