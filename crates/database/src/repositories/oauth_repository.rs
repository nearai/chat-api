use crate::pool::DbPool;
use crate::repositories::session_repository::{generate_session_token, hash_session_token};
use async_trait::async_trait;
use services::{
    auth::ports::{
        OAuthCallbackCode, OAuthCodeExchangeSuccess, OAuthFrontendResponseMode, OAuthRepository,
        OAuthState, OAuthTokens, UserSession,
    },
    user::ports::OAuthProvider,
    SessionId, UserId,
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
                "INSERT INTO oauth_states (
                    state,
                    provider,
                    redirect_uri,
                    frontend_callback,
                    frontend_response_mode,
                    frontend_code_challenge,
                    frontend_state,
                    created_at
                 )
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                &[
                    &state.state,
                    &provider_str,
                    &state.redirect_uri,
                    &state.frontend_callback,
                    &state.frontend_response_mode.as_str(),
                    &state.frontend_code_challenge,
                    &state.frontend_state,
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
                 RETURNING state, provider, redirect_uri, frontend_callback,
                           frontend_response_mode, frontend_code_challenge,
                           frontend_state, created_at",
                &[&state],
            )
            .await?;

        transaction.commit().await?;

        let result = row
            .map(|r| -> anyhow::Result<OAuthState> {
                let provider_str: String = r.get(1);
                let provider = match provider_str.as_str() {
                    "google" => OAuthProvider::Google,
                    "github" => OAuthProvider::Github,
                    "near" => OAuthProvider::Near,
                    _ => OAuthProvider::Google, // fallback
                };

                Ok(OAuthState {
                    state: r.get(0),
                    provider,
                    redirect_uri: r.get(2),
                    frontend_callback: r.get(3),
                    frontend_response_mode: OAuthFrontendResponseMode::parse(
                        &r.get::<_, String>(4),
                    )?,
                    frontend_code_challenge: r.get(5),
                    frontend_state: r.get(6),
                    created_at: r.get(7),
                })
            })
            .transpose()?;

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

    async fn store_callback_code(
        &self,
        code_hash: &str,
        callback_code: &OAuthCallbackCode,
    ) -> anyhow::Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO oauth_callback_codes (
                    code_hash, session_id, code_challenge, is_new_user, expires_at
                 ) VALUES ($1, $2, $3, $4, $5)",
                &[
                    &code_hash,
                    &callback_code.session_id,
                    &callback_code.code_challenge,
                    &callback_code.is_new_user,
                    &callback_code.expires_at,
                ],
            )
            .await?;
        Ok(())
    }

    async fn exchange_callback_code(
        &self,
        code_hash: &str,
        code_challenge: &str,
    ) -> anyhow::Result<Option<OAuthCodeExchangeSuccess>> {
        let token = generate_session_token();
        let token_hash = hash_session_token(&token);
        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;
        // Opportunistic cleanup keeps abandoned/expired handoff codes from
        // accumulating without introducing a separate maintenance job.
        transaction
            .execute(
                "DELETE FROM oauth_callback_codes WHERE expires_at <= NOW()",
                &[],
            )
            .await?;
        let callback_row = transaction
            .query_opt(
                "DELETE FROM oauth_callback_codes
                 WHERE code_hash = $1
                   AND code_challenge = $2
                   AND expires_at > NOW()
                 RETURNING session_id, code_challenge, is_new_user, expires_at",
                &[&code_hash, &code_challenge],
            )
            .await?;

        let Some(callback_row) = callback_row else {
            transaction.commit().await?;
            return Ok(None);
        };

        let session_id: SessionId = callback_row.get(0);
        let is_new_user: bool = callback_row.get(2);
        let session_row = transaction
            .query_opt(
                "UPDATE sessions
                 SET token_hash = $2
                 WHERE id = $1 AND expires_at > NOW()
                 RETURNING id, user_id, created_at, expires_at",
                &[&session_id, &token_hash],
            )
            .await?
            .ok_or_else(|| anyhow::anyhow!("OAuth callback session is missing or expired"))?;

        transaction.commit().await?;

        Ok(Some(OAuthCodeExchangeSuccess {
            session: UserSession {
                session_id: session_row.get(0),
                user_id: session_row.get(1),
                created_at: session_row.get(2),
                expires_at: session_row.get(3),
                token: Some(token),
            },
            is_new_user,
        }))
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
