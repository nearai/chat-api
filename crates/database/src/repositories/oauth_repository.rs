use crate::pool::DbPool;
use async_trait::async_trait;
use services::{
    auth::ports::{OAuthRepository, OAuthState, OAuthTokens},
    user::ports::OAuthProvider,
    UserId,
};

pub struct PostgresOAuthRepository {
    pool: DbPool,
}

impl PostgresOAuthRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl OAuthRepository for PostgresOAuthRepository {
    async fn store_oauth_state(&self, state: &OAuthState) -> anyhow::Result<()> {
        tracing::debug!(
            "Repository: Storing OAuth state - state={}, provider={:?}",
            state.state,
            state.provider
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
            "Repository: OAuth state stored successfully - state={}",
            state.state
        );

        Ok(())
    }

    async fn consume_oauth_state(&self, state: &str) -> anyhow::Result<Option<OAuthState>> {
        tracing::debug!("Repository: Consuming OAuth state - state={}", state);

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
                "Repository: OAuth state consumed successfully - state={}",
                state
            );
        } else {
            tracing::warn!(
                "Repository: OAuth state not found or already consumed - state={}",
                state
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

        let client = self.pool.get().await?;

        let provider_str = match provider {
            OAuthProvider::Google => "google",
            OAuthProvider::Github => "github",
            OAuthProvider::Near => "near",
        };

        let rows_affected = client
            .execute(
                "INSERT INTO oauth_tokens (user_id, provider, access_token, refresh_token, expires_at) 
                 VALUES ($1, $2, $3, $4, $5) 
                 ON CONFLICT (user_id, provider) 
                 DO UPDATE SET 
                    access_token = EXCLUDED.access_token, 
                    refresh_token = EXCLUDED.refresh_token, 
                    expires_at = EXCLUDED.expires_at,
                    updated_at = NOW()",
                &[
                    &user_id,
                    &provider_str,
                    &tokens.access_token,
                    &tokens.refresh_token,
                    &tokens.expires_at,
                ],
            )
            .await?;

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
                "SELECT access_token, refresh_token, expires_at 
                 FROM oauth_tokens 
                 WHERE user_id = $1 AND provider = $2",
                &[&user_id, &provider_str],
            )
            .await?;

        Ok(row.map(|r| OAuthTokens {
            access_token: r.get(0),
            refresh_token: r.get(1),
            expires_at: r.get(2),
        }))
    }
}
