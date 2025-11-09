use async_trait::async_trait;
use chrono::Utc;
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl,
    RefreshToken, Scope, TokenResponse, TokenUrl,
};
use std::sync::Arc;

use super::ports::{
    OAuthRepository, OAuthService, OAuthState, OAuthTokens, OAuthUserInfo, SessionRepository,
    UserSession,
};
use crate::types::{SessionId, UserId};
use crate::user::ports::{OAuthProvider, UserRepository};

/// Custom error type for HTTP client
#[derive(Debug, thiserror::Error)]
enum HttpClientError {
    #[error("HTTP request failed: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("HTTP response build failed: {0}")]
    Http(#[from] oauth2::http::Error),
}

/// Custom HTTP client for OAuth2 using reqwest
async fn async_http_client(
    request: oauth2::HttpRequest,
) -> Result<oauth2::HttpResponse, HttpClientError> {
    let client = reqwest::Client::new();

    let mut request_builder = client
        .request(request.method().clone(), request.uri().to_string())
        .body(request.body().clone());

    for (name, value) in request.headers() {
        request_builder = request_builder.header(name.as_str(), value.as_bytes());
    }

    let response = request_builder.send().await?;

    let status_code = response.status();
    let headers = response.headers().clone();
    let body = response.bytes().await?;

    let mut http_response_builder = oauth2::http::Response::builder().status(status_code);

    for (name, value) in headers.iter() {
        http_response_builder = http_response_builder.header(name, value);
    }

    Ok(http_response_builder.body(body.to_vec())?)
}

pub struct OAuthServiceImpl {
    oauth_repository: Arc<dyn OAuthRepository>,
    session_repository: Arc<dyn SessionRepository>,
    user_repository: Arc<dyn UserRepository>,
    google_client_id: String,
    google_client_secret: String,
    github_client_id: String,
    github_client_secret: String,
    redirect_uri: String,
}

impl OAuthServiceImpl {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        oauth_repository: Arc<dyn OAuthRepository>,
        session_repository: Arc<dyn SessionRepository>,
        user_repository: Arc<dyn UserRepository>,
        google_client_id: String,
        google_client_secret: String,
        github_client_id: String,
        github_client_secret: String,
        redirect_uri: String,
    ) -> Self {
        Self {
            oauth_repository,
            session_repository,
            user_repository,
            google_client_id,
            google_client_secret,
            github_client_id,
            github_client_secret,
            redirect_uri,
        }
    }

    async fn fetch_google_user_info(&self, access_token: &str) -> anyhow::Result<OAuthUserInfo> {
        tracing::debug!("Fetching Google user info");
        let client = reqwest::Client::new();
        let response = client
            .get("https://www.googleapis.com/oauth2/v2/userinfo")
            .bearer_auth(access_token)
            .send()
            .await?;

        let status = response.status();
        tracing::debug!("Google userinfo API response status: {}", status);

        if !status.is_success() {
            tracing::error!("Failed to fetch Google user info: status {}", status);
            return Err(anyhow::anyhow!(
                "Failed to fetch Google user info: {}",
                status
            ));
        }

        let user_data: serde_json::Value = response.json().await?;
        tracing::debug!("Google user data received: {:?}", user_data);

        let user_info = OAuthUserInfo {
            provider: OAuthProvider::Google,
            provider_user_id: user_data["id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing user id"))?
                .to_string(),
            email: user_data["email"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing email"))?
                .to_string(),
            name: user_data["name"].as_str().map(|s| s.to_string()),
            avatar_url: user_data["picture"].as_str().map(|s| s.to_string()),
        };

        tracing::info!(
            "Successfully fetched Google user info: email={}, provider_user_id={}",
            user_info.email,
            user_info.provider_user_id
        );

        Ok(user_info)
    }

    async fn fetch_github_user_info(&self, access_token: &str) -> anyhow::Result<OAuthUserInfo> {
        tracing::debug!("Fetching Github user info");
        let client = reqwest::Client::new();

        // Get user info
        tracing::debug!("Calling Github /user API");
        let user_response = client
            .get("https://api.github.com/user")
            .bearer_auth(access_token)
            .header("User-Agent", "chat-api")
            .send()
            .await?;

        let status = user_response.status();
        tracing::debug!("Github /user API response status: {}", status);

        if !status.is_success() {
            tracing::error!("Failed to fetch Github user info: status {}", status);
            return Err(anyhow::anyhow!(
                "Failed to fetch Github user info: {}",
                status
            ));
        }

        let user_data: serde_json::Value = user_response.json().await?;
        tracing::debug!("Github user data received");

        // Get primary email
        tracing::debug!("Calling Github /user/emails API");
        let emails_response = client
            .get("https://api.github.com/user/emails")
            .bearer_auth(access_token)
            .header("User-Agent", "chat-api")
            .send()
            .await?;

        let emails: Vec<serde_json::Value> = emails_response.json().await?;
        tracing::debug!("Github emails received: {} email(s)", emails.len());

        let primary_email = emails
            .iter()
            .find(|e| e["primary"].as_bool().unwrap_or(false))
            .or_else(|| emails.first())
            .and_then(|e| e["email"].as_str())
            .ok_or_else(|| anyhow::anyhow!("No email found for Github user"))?;

        let user_info = OAuthUserInfo {
            provider: OAuthProvider::Github,
            provider_user_id: user_data["id"]
                .as_i64()
                .ok_or_else(|| anyhow::anyhow!("Missing user id"))?
                .to_string(),
            email: primary_email.to_string(),
            name: user_data["name"].as_str().map(|s| s.to_string()),
            avatar_url: user_data["avatar_url"].as_str().map(|s| s.to_string()),
        };

        tracing::info!(
            "Successfully fetched Github user info: email={}, provider_user_id={}",
            user_info.email,
            user_info.provider_user_id
        );

        Ok(user_info)
    }

    async fn find_or_create_user_from_oauth(
        &self,
        user_info: &OAuthUserInfo,
    ) -> anyhow::Result<UserId> {
        tracing::info!(
            "Finding or creating user for OAuth login: provider={:?}, email={}",
            user_info.provider,
            user_info.email
        );

        // First check if user exists by OAuth provider
        tracing::debug!(
            "Checking for existing user by OAuth: provider={:?}, provider_user_id={}",
            user_info.provider,
            user_info.provider_user_id
        );

        if let Some(user_id) = self
            .user_repository
            .find_user_by_oauth(user_info.provider, &user_info.provider_user_id)
            .await?
        {
            tracing::info!(
                "Found existing user by OAuth: user_id={}, provider={:?}",
                user_id,
                user_info.provider
            );
            return Ok(user_id);
        }

        tracing::debug!(
            "No user found by OAuth, checking by email: {}",
            user_info.email
        );

        // Check if user exists by email
        if let Some(existing_user) = self
            .user_repository
            .get_user_by_email(&user_info.email)
            .await?
        {
            tracing::info!(
                "Found existing user by email: user_id={}, email={}",
                existing_user.id,
                user_info.email
            );

            // Link the OAuth account
            tracing::debug!(
                "Linking OAuth account to existing user: user_id={}, provider={:?}",
                existing_user.id,
                user_info.provider
            );

            self.user_repository
                .link_oauth_account(
                    existing_user.id,
                    user_info.provider,
                    user_info.provider_user_id.clone(),
                )
                .await?;

            tracing::info!(
                "Successfully linked {:?} account to user_id={}",
                user_info.provider,
                existing_user.id
            );

            return Ok(existing_user.id);
        }

        // Create new user
        tracing::info!(
            "No existing user found, creating new user for email: {}",
            user_info.email
        );

        let user = self
            .user_repository
            .create_user(
                user_info.email.clone(),
                user_info.name.clone(),
                user_info.avatar_url.clone(),
            )
            .await?;

        tracing::info!(
            "Created new user: user_id={}, email={}",
            user.id,
            user.email
        );

        // Link the OAuth account
        tracing::debug!(
            "Linking OAuth account to new user: user_id={}, provider={:?}",
            user.id,
            user_info.provider
        );

        self.user_repository
            .link_oauth_account(
                user.id,
                user_info.provider,
                user_info.provider_user_id.clone(),
            )
            .await?;

        tracing::info!(
            "Successfully linked {:?} account to new user_id={}",
            user_info.provider,
            user.id
        );

        Ok(user.id)
    }

    /// Internal implementation that handles the callback with a pre-validated state
    /// Returns (UserSession, frontend_callback_url)
    async fn handle_callback_impl(
        &self,
        provider: OAuthProvider,
        code: String,
        oauth_state: OAuthState,
    ) -> anyhow::Result<(UserSession, Option<String>)> {
        tracing::info!(
            "Processing OAuth callback: provider={:?}, redirect_uri={}",
            provider,
            oauth_state.redirect_uri
        );

        // Build client for token exchange
        let (client_id, client_secret, auth_url, token_url) = match provider {
            OAuthProvider::Google => (
                &self.google_client_id,
                &self.google_client_secret,
                "https://accounts.google.com/o/oauth2/v2/auth",
                "https://oauth2.googleapis.com/token",
            ),
            OAuthProvider::Github => (
                &self.github_client_id,
                &self.github_client_secret,
                "https://github.com/login/oauth/authorize",
                "https://github.com/login/oauth/access_token",
            ),
        };

        tracing::debug!(
            "Building OAuth client for token exchange with provider: {:?}",
            provider
        );

        let client = BasicClient::new(ClientId::new(client_id.clone()))
            .set_client_secret(ClientSecret::new(client_secret.clone()))
            .set_auth_uri(AuthUrl::new(auth_url.to_string())?)
            .set_token_uri(TokenUrl::new(token_url.to_string())?)
            .set_redirect_uri(RedirectUrl::new(oauth_state.redirect_uri.clone())?);

        tracing::debug!("Exchanging authorization code for access token");

        let token_result = client
            .exchange_code(AuthorizationCode::new(code))
            .request_async(&async_http_client)
            .await
            .map_err(|e| {
                tracing::error!("Token exchange failed for provider {:?}: {:?}", provider, e);
                anyhow::anyhow!("Token exchange failed: {:?}", e)
            })?;

        tracing::info!("Successfully exchanged authorization code for access token");

        let access_token = token_result.access_token().secret();
        let has_refresh_token = token_result.refresh_token().is_some();
        let expires_in = token_result.expires_in();

        tracing::debug!(
            "Token details: has_refresh_token={}, expires_in={:?}",
            has_refresh_token,
            expires_in
        );

        // Fetch user info from provider
        tracing::debug!("Fetching user info from provider: {:?}", provider);
        let user_info = match provider {
            OAuthProvider::Google => self.fetch_google_user_info(access_token).await?,
            OAuthProvider::Github => self.fetch_github_user_info(access_token).await?,
        };

        // Find or create user
        let user_id = self.find_or_create_user_from_oauth(&user_info).await?;

        // Store OAuth tokens
        let oauth_tokens = OAuthTokens {
            access_token: access_token.to_string(),
            refresh_token: token_result.refresh_token().map(|t| t.secret().to_string()),
            expires_at: token_result
                .expires_in()
                .map(|d| Utc::now() + chrono::Duration::from_std(d).unwrap()),
        };

        tracing::debug!(
            "Storing OAuth tokens for user_id={}, provider={:?}",
            user_id,
            provider
        );

        self.oauth_repository
            .store_oauth_tokens(user_id, provider, &oauth_tokens)
            .await?;

        tracing::info!("OAuth tokens stored successfully for user_id={}", user_id);

        // Create session
        tracing::debug!("Creating session for user_id={}", user_id);
        let session = self.session_repository.create_session(user_id).await?;

        tracing::info!(
            "User {} logged in via {:?} - session_id={}",
            user_id,
            provider,
            session.session_id
        );

        Ok((session, oauth_state.frontend_callback))
    }
}

#[async_trait]
impl OAuthService for OAuthServiceImpl {
    async fn get_authorization_url(
        &self,
        provider: OAuthProvider,
        redirect_uri: String,
        frontend_callback: Option<String>,
    ) -> anyhow::Result<String> {
        tracing::info!(
            "Generating authorization URL for provider={:?}, redirect_uri={}, frontend_callback={:?}",
            provider,
            redirect_uri,
            frontend_callback
        );

        let (client_id, client_secret, auth_url, token_url, scopes) = match provider {
            OAuthProvider::Google => (
                &self.google_client_id,
                &self.google_client_secret,
                "https://accounts.google.com/o/oauth2/v2/auth",
                "https://oauth2.googleapis.com/token",
                vec!["openid", "email", "profile"],
            ),
            OAuthProvider::Github => (
                &self.github_client_id,
                &self.github_client_secret,
                "https://github.com/login/oauth/authorize",
                "https://github.com/login/oauth/access_token",
                vec!["user:email", "read:user"],
            ),
        };

        tracing::debug!("OAuth scopes for {:?}: {:?}", provider, scopes);

        let client = BasicClient::new(ClientId::new(client_id.clone()))
            .set_client_secret(ClientSecret::new(client_secret.clone()))
            .set_auth_uri(AuthUrl::new(auth_url.to_string())?)
            .set_token_uri(TokenUrl::new(token_url.to_string())?)
            .set_redirect_uri(RedirectUrl::new(redirect_uri.clone())?);

        let mut auth_request = client.authorize_url(CsrfToken::new_random);
        for scope in scopes {
            auth_request = auth_request.add_scope(Scope::new(scope.to_string()));
        }

        let (auth_url, csrf_token) = auth_request.url();

        tracing::debug!("Generated CSRF token: {}", csrf_token.secret());

        // Store the state for verification
        let oauth_state = OAuthState {
            state: csrf_token.secret().to_string(),
            provider,
            redirect_uri: redirect_uri.clone(),
            frontend_callback: frontend_callback.clone(),
            created_at: Utc::now(),
        };

        tracing::debug!("Storing OAuth state in database");

        self.oauth_repository
            .store_oauth_state(&oauth_state)
            .await?;

        tracing::info!(
            "Successfully generated and stored authorization URL for provider={:?}",
            provider
        );

        Ok(auth_url.to_string())
    }

    async fn refresh_token(
        &self,
        user_id: UserId,
        provider: OAuthProvider,
    ) -> anyhow::Result<OAuthTokens> {
        // Get existing tokens
        let existing_tokens = self
            .oauth_repository
            .get_oauth_tokens(user_id, provider)
            .await?
            .ok_or_else(|| anyhow::anyhow!("No OAuth tokens found for user"))?;

        let refresh_token_str = existing_tokens
            .refresh_token
            .clone()
            .ok_or_else(|| anyhow::anyhow!("No refresh token available"))?;

        // Build client for token refresh
        let (client_id, client_secret, auth_url, token_url) = match provider {
            OAuthProvider::Google => (
                &self.google_client_id,
                &self.google_client_secret,
                "https://accounts.google.com/o/oauth2/v2/auth",
                "https://oauth2.googleapis.com/token",
            ),
            OAuthProvider::Github => (
                &self.github_client_id,
                &self.github_client_secret,
                "https://github.com/login/oauth/authorize",
                "https://github.com/login/oauth/access_token",
            ),
        };

        let client = BasicClient::new(ClientId::new(client_id.clone()))
            .set_client_secret(ClientSecret::new(client_secret.clone()))
            .set_auth_uri(AuthUrl::new(auth_url.to_string())?)
            .set_token_uri(TokenUrl::new(token_url.to_string())?)
            .set_redirect_uri(RedirectUrl::new(self.redirect_uri.clone())?);

        let token_result = client
            .exchange_refresh_token(&RefreshToken::new(refresh_token_str))
            .request_async(&async_http_client)
            .await
            .map_err(|e| anyhow::anyhow!("Token refresh failed: {:?}", e))?;

        let new_tokens = OAuthTokens {
            access_token: token_result.access_token().secret().to_string(),
            refresh_token: token_result
                .refresh_token()
                .map(|t| t.secret().to_string())
                .or(existing_tokens.refresh_token),
            expires_at: token_result
                .expires_in()
                .map(|d| Utc::now() + chrono::Duration::from_std(d).unwrap()),
        };

        // Store updated tokens
        self.oauth_repository
            .store_oauth_tokens(user_id, provider, &new_tokens)
            .await?;

        Ok(new_tokens)
    }

    async fn handle_callback_unified(
        &self,
        code: String,
        state: String,
    ) -> anyhow::Result<(UserSession, Option<String>)> {
        tracing::info!("Handling unified OAuth callback with state: {}", state);

        // First, look up the state to determine the provider
        tracing::debug!("Looking up OAuth state in database");
        let oauth_state = self
            .oauth_repository
            .consume_oauth_state(&state)
            .await?
            .ok_or_else(|| {
                tracing::error!("Invalid or expired OAuth state: {}", state);
                anyhow::anyhow!("Invalid or expired OAuth state")
            })?;

        tracing::info!(
            "OAuth state found and consumed: provider={:?}, created_at={}",
            oauth_state.provider,
            oauth_state.created_at
        );

        // Now call the regular callback handler with the determined provider
        self.handle_callback_impl(oauth_state.provider, code, oauth_state)
            .await
    }

    async fn revoke_session(&self, session_id: SessionId) -> anyhow::Result<()> {
        tracing::info!("Revoking session: session_id={}", session_id);

        self.session_repository.delete_session(session_id).await?;

        tracing::info!("Session revoked successfully: session_id={}", session_id);
        Ok(())
    }
}
