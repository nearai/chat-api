use anyhow::Context;
use async_trait::async_trait;
use chrono::Utc;
use hmac::{Hmac, Mac};
use near_api::signer::NEP413Payload;
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl,
    RefreshToken, Scope, TokenResponse, TokenUrl,
};
use rand::Rng;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

use super::ports::{
    EmailAuthService, EmailAuthSuccess, EmailVerificationChallengeRepository, OAuthRepository,
    OAuthService, OAuthState, OAuthTokens, OAuthUserInfo, RequestEmailCodeError, SessionRepository,
    UserSession, VerifyEmailCodeError,
};
use super::{NearAuthService, NearNonceRepository};
use crate::types::{SessionId, UserId};
use crate::user::ports::{OAuthProvider, UserRepository};

type HmacSha256 = Hmac<Sha256>;
const TURNSTILE_SITEVERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

/// Custom error type for HTTP client
#[derive(Debug, thiserror::Error)]
enum HttpClientError {
    #[error("HTTP request failed: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("HTTP response build failed: {0}")]
    Http(#[from] oauth2::http::Error),
}

#[derive(Debug, thiserror::Error)]
enum EmailAuthAvailabilityError {
    #[error("Email authentication is disabled")]
    Disabled,
    #[error("Email authentication is not fully configured")]
    Misconfigured,
}

#[derive(Debug, Deserialize)]
struct ResendSendEmailResponse {
    id: String,
}

#[derive(Debug, Deserialize)]
struct TurnstileVerifyResponse {
    success: bool,
    #[serde(rename = "error-codes")]
    error_codes: Option<Vec<String>>,
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
    near_auth: NearAuthService,
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
        near_nonce_repository: Arc<dyn NearNonceRepository>,
        google_client_id: String,
        google_client_secret: String,
        github_client_id: String,
        github_client_secret: String,
        redirect_uri: String,
        near_rpc_url: url::Url,
    ) -> Self {
        let near_auth = NearAuthService::new(
            session_repository.clone(),
            user_repository.clone(),
            near_nonce_repository,
            near_rpc_url,
        );

        Self {
            oauth_repository,
            session_repository,
            user_repository,
            near_auth,
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
            email_verified: user_data["verified_email"].as_bool().unwrap_or(false),
            name: user_data["name"].as_str().map(|s| s.to_string()),
            avatar_url: user_data["picture"].as_str().map(|s| s.to_string()),
        };

        tracing::info!(
            "Successfully fetched Google user info: provider_user_id={}",
            user_info.provider_user_id
        );

        Ok(user_info)
    }

    async fn fetch_github_user_info(&self, access_token: &str) -> anyhow::Result<OAuthUserInfo> {
        tracing::debug!("Fetching Github user info");
        let client = reqwest::Client::new();

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

        let emails_response = client
            .get("https://api.github.com/user/emails")
            .bearer_auth(access_token)
            .header("User-Agent", "chat-api")
            .send()
            .await?;

        let emails_status = emails_response.status();
        tracing::debug!("Github /user/emails API response status: {}", emails_status);

        if !emails_status.is_success() {
            return Err(anyhow::anyhow!(
                "Failed to fetch Github user emails: {}",
                emails_status
            ));
        }

        let emails: Vec<serde_json::Value> = emails_response.json().await?;

        let verified_email = emails
            .iter()
            .find(|e| {
                e["verified"].as_bool().unwrap_or(false) && e["primary"].as_bool().unwrap_or(false)
            })
            .or_else(|| {
                emails
                    .iter()
                    .find(|e| e["verified"].as_bool().unwrap_or(false))
            })
            .and_then(|e| e["email"].as_str())
            .ok_or_else(|| anyhow::anyhow!("No verified email found for Github user"))?;

        let user_info = OAuthUserInfo {
            provider: OAuthProvider::Github,
            provider_user_id: user_data["id"]
                .as_i64()
                .ok_or_else(|| anyhow::anyhow!("Missing user id"))?
                .to_string(),
            email: verified_email.to_string(),
            email_verified: true,
            name: user_data["name"].as_str().map(|s| s.to_string()),
            avatar_url: user_data["avatar_url"].as_str().map(|s| s.to_string()),
        };

        tracing::info!(
            "Successfully fetched Github user info: provider_user_id={}",
            user_info.provider_user_id
        );

        Ok(user_info)
    }

    /// Find or create user from OAuth
    /// Returns (user_id, is_new_user)
    async fn find_or_create_user_from_oauth(
        &self,
        user_info: &OAuthUserInfo,
    ) -> anyhow::Result<(UserId, bool)> {
        if let Some(user_id) = self
            .user_repository
            .find_user_by_oauth(user_info.provider, &user_info.provider_user_id)
            .await?
        {
            return Ok((user_id, false));
        }

        let (user_id, is_new_user) = if let Some(existing_user) = self
            .user_repository
            .get_user_by_email(&user_info.email)
            .await?
        {
            if !user_info.email_verified {
                return Err(anyhow::anyhow!("OAuth provider email is not verified"));
            }

            (existing_user.id, false)
        } else {
            match self
                .user_repository
                .create_user(
                    user_info.email.clone(),
                    user_info.name.clone(),
                    user_info.avatar_url.clone(),
                )
                .await
            {
                Ok(user) => (user.id, true),
                Err(create_err) => {
                    // Race: another request created this email concurrently.
                    // Only merge if the OAuth email is verified — unverified emails
                    // must not silently take over an existing account.
                    if let Some(existing_user) = self
                        .user_repository
                        .get_user_by_email(&user_info.email)
                        .await?
                    {
                        if user_info.email_verified {
                            (existing_user.id, false)
                        } else {
                            // Email already taken by another account; refuse to merge.
                            // The real account holder should use their original auth path.
                            return Err(create_err);
                        }
                    } else {
                        return Err(create_err);
                    }
                }
            }
        };

        if let Err(link_err) = self
            .user_repository
            .link_oauth_account(
                user_id,
                user_info.provider,
                user_info.provider_user_id.clone(),
            )
            .await
        {
            if let Some(existing_user_id) = self
                .user_repository
                .find_user_by_oauth(user_info.provider, &user_info.provider_user_id)
                .await?
            {
                return Ok((existing_user_id, false));
            }

            return Err(link_err);
        }

        Ok((user_id, is_new_user))
    }

    /// Internal implementation that handles the callback with a pre-validated state
    /// Returns (UserSession, frontend_callback_url, is_new_user, provider)
    async fn handle_callback_impl(
        &self,
        provider: OAuthProvider,
        code: String,
        oauth_state: OAuthState,
    ) -> anyhow::Result<(UserSession, Option<String>, bool, OAuthProvider)> {
        tracing::info!(
            "Processing OAuth callback: provider={:?}, redirect_uri={}",
            provider,
            oauth_state.redirect_uri
        );

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
            OAuthProvider::Near => {
                return Err(anyhow::anyhow!(
                    "NEAR authentication does not use OAuth2 flow"
                ));
            }
        };

        let client = BasicClient::new(ClientId::new(client_id.clone()))
            .set_client_secret(ClientSecret::new(client_secret.clone()))
            .set_auth_uri(AuthUrl::new(auth_url.to_string())?)
            .set_token_uri(TokenUrl::new(token_url.to_string())?)
            .set_redirect_uri(RedirectUrl::new(oauth_state.redirect_uri.clone())?);

        let token_result = client
            .exchange_code(AuthorizationCode::new(code))
            .request_async(&async_http_client)
            .await
            .map_err(|e| {
                tracing::error!("Token exchange failed for provider {:?}: {:?}", provider, e);
                anyhow::anyhow!("Token exchange failed: {:?}", e)
            })?;

        let access_token = token_result.access_token().secret();

        let user_info = match provider {
            OAuthProvider::Google => self.fetch_google_user_info(access_token).await?,
            OAuthProvider::Github => self.fetch_github_user_info(access_token).await?,
            OAuthProvider::Near => {
                return Err(anyhow::anyhow!(
                    "NEAR authentication does not use OAuth2 flow"
                ));
            }
        };

        let (user_id, is_new_user) = self.find_or_create_user_from_oauth(&user_info).await?;

        let oauth_tokens = OAuthTokens {
            access_token: access_token.to_string(),
            refresh_token: token_result.refresh_token().map(|t| t.secret().to_string()),
            expires_at: token_result
                .expires_in()
                .map(|d| Utc::now() + chrono::Duration::from_std(d).unwrap()),
        };

        self.oauth_repository
            .store_oauth_tokens(user_id, provider, &oauth_tokens)
            .await?;

        let session = self.session_repository.create_session(user_id).await?;

        tracing::info!(
            "User authenticated via OAuth: user_id={}, provider={:?}, session_id={}",
            user_id,
            provider,
            session.session_id
        );

        Ok((
            session,
            oauth_state.frontend_callback,
            is_new_user,
            provider,
        ))
    }
}

pub struct EmailAuthServiceImpl {
    challenge_repository: Arc<dyn EmailVerificationChallengeRepository>,
    session_repository: Arc<dyn SessionRepository>,
    user_repository: Arc<dyn UserRepository>,
    http_client: reqwest::Client,
    config: config::EmailAuthConfig,
    turnstile_verify_url: String,
}

impl EmailAuthServiceImpl {
    pub fn new(
        challenge_repository: Arc<dyn EmailVerificationChallengeRepository>,
        session_repository: Arc<dyn SessionRepository>,
        user_repository: Arc<dyn UserRepository>,
        http_client: reqwest::Client,
        config: config::EmailAuthConfig,
    ) -> Self {
        Self::new_with_turnstile_verify_url(
            challenge_repository,
            session_repository,
            user_repository,
            http_client,
            config,
            TURNSTILE_SITEVERIFY_URL.to_string(),
        )
    }

    pub fn new_with_turnstile_verify_url(
        challenge_repository: Arc<dyn EmailVerificationChallengeRepository>,
        session_repository: Arc<dyn SessionRepository>,
        user_repository: Arc<dyn UserRepository>,
        http_client: reqwest::Client,
        config: config::EmailAuthConfig,
        turnstile_verify_url: String,
    ) -> Self {
        Self {
            challenge_repository,
            session_repository,
            user_repository,
            http_client,
            config,
            turnstile_verify_url,
        }
    }

    fn ensure_enabled(&self) -> Result<(), EmailAuthAvailabilityError> {
        if !self.config.enabled {
            return Err(EmailAuthAvailabilityError::Disabled);
        }

        if self.config.resend_api_key.is_empty()
            || self.config.email_from.is_empty()
            || self.config.turnstile_secret_key.is_empty()
            || self.config.otp_hmac_secret.is_empty()
        {
            return Err(EmailAuthAvailabilityError::Misconfigured);
        }

        Ok(())
    }

    fn normalize_email(email: &str) -> String {
        email.trim().to_ascii_lowercase()
    }

    fn email_log_hash(email: &str) -> String {
        let digest = Sha256::digest(email.as_bytes());
        hex::encode(&digest[..6])
    }

    async fn find_or_create_user_by_email_exact(
        &self,
        email: &str,
    ) -> anyhow::Result<(UserId, bool)> {
        if let Some(existing_user) = self.user_repository.get_user_by_email(email).await? {
            return Ok((existing_user.id, false));
        }

        match self
            .user_repository
            .create_user(email.to_string(), None, None)
            .await
        {
            Ok(user) => Ok((user.id, true)),
            Err(create_err) => {
                if let Some(existing_user) = self.user_repository.get_user_by_email(email).await? {
                    Ok((existing_user.id, false))
                } else {
                    Err(create_err)
                }
            }
        }
    }

    fn generate_verification_code(&self) -> String {
        let mut rng = rand::rng();
        format!("{:06}", rng.random_range(0..1_000_000))
    }

    /// Compute HMAC-SHA256 over email and code only. The challenge_id is not included
    /// to allow the verify step to be a single atomic DB call. The OTP's time TTL and
    /// rate-limit constraints make challenge_id in the MAC unnecessary for security.
    fn compute_code_mac(&self, email: &str, code: &str) -> anyhow::Result<String> {
        let mut mac = HmacSha256::new_from_slice(self.config.otp_hmac_secret.as_bytes())
            .context("Invalid email OTP HMAC secret")?;
        mac.update(email.as_bytes());
        mac.update(b"|");
        mac.update(code.as_bytes());
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    fn format_code_for_display(&self, code: &str) -> String {
        if code.len() == 6 {
            format!("{}-{}", &code[..3], &code[3..])
        } else {
            code.to_string()
        }
    }

    fn verification_email_text(&self, code: &str) -> String {
        let display_code = self.format_code_for_display(code);
        format!(
            "Enter this verification code to sign in to NEAR AI.\n\n{display_code}\n\nThis code expires in {} minutes.\n\nDon't share this code with anyone. NEAR AI employees will never ask for this code.\n\nIf you didn't request this code, you can ignore this email.",
            self.config.otp_ttl_minutes,
        )
    }

    fn verification_email_html(&self, code: &str) -> String {
        let display_code = self.format_code_for_display(code);
        format!(
            "<!doctype html><html><body style=\"margin:0;padding:0;background:#eff5f2;\"><table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"background:#eff5f2;\"><tr><td align=\"center\" style=\"padding:24px 12px;\"><table role=\"presentation\" width=\"620\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"width:620px;max-width:620px;background:#ffffff;border:1px solid #d3e0d8;border-radius:14px;overflow:hidden;\"><tr><td style=\"padding:18px 24px;background:#103c34;background-image:linear-gradient(135deg,#103c34 0%,#1a5648 55%,#245f4f 100%);font-family:Arial,'Helvetica Neue',Helvetica,sans-serif;border-bottom:2px solid #171717;\"><span style=\"display:inline-block;color:#ffffff;font-size:20px;font-weight:700;letter-spacing:0.4px;\">NEAR AI</span></td></tr><tr><td style=\"padding:24px 24px 22px;font-family:Arial,'Helvetica Neue',Helvetica,sans-serif;color:#1a1a1a;\"><p style=\"margin:0 0 16px;font-size:15px;line-height:1.6;color:#22312b;\">Enter this verification code to sign in to NEAR AI.</p><table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"border:1px solid #bfd3c9;background:#f7faf8;border-radius:10px;\"><tr><td align=\"center\" style=\"padding:12px 12px 4px;font-family:Arial,'Helvetica Neue',Helvetica,sans-serif;font-size:11px;line-height:1.2;font-weight:700;letter-spacing:1px;color:#1a5648;text-transform:uppercase;\">Verification Code</td></tr><tr><td align=\"center\" style=\"padding:2px 12px 16px;font-family:Arial,'Helvetica Neue',Helvetica,sans-serif;font-size:36px;line-height:1;font-weight:700;letter-spacing:3px;color:#121212;\">{display_code}</td></tr></table><p style=\"margin:16px 0 0;font-size:13px;line-height:1.6;font-weight:700;color:#121212;\">Code expires in {} minutes.</p><table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"margin-top:14px;border:1px solid #d8e4dc;background:#f4f8f5;border-radius:8px;\"><tr><td style=\"padding:12px 14px;font-family:Arial,'Helvetica Neue',Helvetica,sans-serif;font-size:13px;line-height:1.6;color:#22312b;\">Don't share this code with anyone. <span style=\"color:#121212;font-weight:700;\">NEAR AI employees will never ask for this code.</span></td></tr></table><p style=\"margin:16px 0 0;font-size:13px;line-height:1.6;color:#5b6a62;\">If you didn't request this code, you can ignore this email.</p></td></tr></table><table role=\"presentation\" width=\"620\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"width:620px;max-width:620px;\"><tr><td align=\"center\" style=\"padding:10px 8px 0;font-family:Arial,'Helvetica Neue',Helvetica,sans-serif;font-size:11px;line-height:1.4;color:#617068;\">This is an automated security message from <span style=\"color:#121212;\">NEAR AI</span>.</td></tr></table></td></tr></table></body></html>",
            self.config.otp_ttl_minutes
        )
    }

    async fn send_verification_email(
        &self,
        email: &str,
        code: &str,
    ) -> anyhow::Result<Option<String>> {
        let response = self
            .http_client
            .post(format!(
                "{}/emails",
                self.config.resend_base_url.trim_end_matches('/')
            ))
            .bearer_auth(&self.config.resend_api_key)
            .json(&serde_json::json!({
                "from": self.config.email_from,
                "to": [email],
                "subject": "Your NEAR AI verification code",
                "text": self.verification_email_text(code),
                "html": self.verification_email_html(code),
            }))
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            return Err(anyhow::anyhow!(
                "Resend email send failed with status {}",
                status
            ));
        }

        let body: ResendSendEmailResponse = response
            .json()
            .await
            .context("Failed to parse Resend email send response")?;

        Ok(Some(body.id))
    }

    async fn verify_turnstile_token(
        &self,
        token: &str,
        client_ip: &str,
        email_hash: &str,
    ) -> Result<(), RequestEmailCodeError> {
        let response = self
            .http_client
            .post(&self.turnstile_verify_url)
            .form(&[
                ("secret", self.config.turnstile_secret_key.as_str()),
                ("response", token),
                ("remoteip", client_ip),
            ])
            .send()
            .await
            .map_err(|err| RequestEmailCodeError::Internal(err.into()))?;

        let status = response.status();
        if !status.is_success() {
            return Err(RequestEmailCodeError::Internal(anyhow::anyhow!(
                "Turnstile verify failed with status {}",
                status
            )));
        }

        let body: TurnstileVerifyResponse = response
            .json()
            .await
            .context("Failed to parse Turnstile verify response")
            .map_err(RequestEmailCodeError::Internal)?;

        if !body.success {
            tracing::warn!(
                email_hash = %email_hash,
                client_ip = %client_ip,
                error_codes = ?body.error_codes,
                "Turnstile verification rejected request"
            );
            return Err(RequestEmailCodeError::HumanVerificationFailed);
        }

        Ok(())
    }
}

#[async_trait]
impl EmailAuthService for EmailAuthServiceImpl {
    async fn request_code(
        &self,
        email: String,
        client_ip: String,
        turnstile_token: String,
    ) -> Result<(), RequestEmailCodeError> {
        self.ensure_enabled().map_err(|err| match err {
            EmailAuthAvailabilityError::Disabled => RequestEmailCodeError::Disabled,
            EmailAuthAvailabilityError::Misconfigured => RequestEmailCodeError::Misconfigured,
        })?;

        let email = Self::normalize_email(&email);
        let email_hash = Self::email_log_hash(&email);

        self.verify_turnstile_token(&turnstile_token, &client_ip, &email_hash)
            .await?;

        let now = Utc::now();
        let since = now - chrono::Duration::hours(1);

        if self
            .challenge_repository
            .count_recent_challenges_for_email(&email, since)
            .await?
            >= self.config.otp_rate_limit_per_hour
        {
            tracing::warn!(
                email_hash = %email_hash,
                client_ip = %client_ip,
                "Email OTP request rate-limited by email threshold"
            );
            return Err(RequestEmailCodeError::RateLimited);
        }

        if self
            .challenge_repository
            .count_recent_challenges_for_ip(&client_ip, since)
            .await?
            >= self.config.otp_requests_per_ip_per_hour
        {
            tracing::warn!(
                email_hash = %email_hash,
                client_ip = %client_ip,
                "Email OTP request rate-limited by IP threshold"
            );
            return Err(RequestEmailCodeError::RateLimited);
        }

        let challenge_id = Uuid::new_v4();
        let code = self.generate_verification_code();
        let code_mac = self.compute_code_mac(&email, &code)?;
        let expires_at = now + chrono::Duration::minutes(self.config.otp_ttl_minutes);

        let challenge = self
            .challenge_repository
            .create_pending_challenge(challenge_id, &email, &code_mac, &client_ip, expires_at)
            .await?;

        match self.send_verification_email(&email, &code).await {
            Ok(provider_message_id) => {
                self.challenge_repository
                    .mark_challenge_sent(challenge.id, provider_message_id.as_deref())
                    .await?;
                Ok(())
            }
            Err(send_err) => {
                self.challenge_repository
                    .mark_challenge_failed(challenge.id)
                    .await?;
                Err(RequestEmailCodeError::Internal(send_err))
            }
        }
    }

    async fn verify_code(
        &self,
        email: String,
        code: String,
        client_ip: String,
    ) -> Result<EmailAuthSuccess, VerifyEmailCodeError> {
        self.ensure_enabled().map_err(|err| match err {
            EmailAuthAvailabilityError::Disabled => VerifyEmailCodeError::Disabled,
            EmailAuthAvailabilityError::Misconfigured => VerifyEmailCodeError::Misconfigured,
        })?;

        let email = Self::normalize_email(&email);
        let email_hash = Self::email_log_hash(&email);

        let now = Utc::now();
        let since = now - chrono::Duration::hours(1);

        if self
            .challenge_repository
            .count_recent_failed_verifications_for_email(&email, since)
            .await
            .map_err(VerifyEmailCodeError::Internal)?
            >= self.config.otp_verify_failures_per_hour
        {
            tracing::warn!(
                email_hash = %email_hash,
                client_ip = %client_ip,
                "Email OTP verify rate-limited by email failure threshold"
            );
            return Err(VerifyEmailCodeError::RateLimited);
        }

        if self
            .challenge_repository
            .count_recent_failed_verifications_for_ip(&client_ip, since)
            .await
            .map_err(VerifyEmailCodeError::Internal)?
            >= self.config.otp_verifies_per_ip_per_hour
        {
            tracing::warn!(
                email_hash = %email_hash,
                client_ip = %client_ip,
                "Email OTP verify rate-limited by IP failure threshold"
            );
            return Err(VerifyEmailCodeError::RateLimited);
        }

        let code_mac = self
            .compute_code_mac(&email, &code)
            .map_err(VerifyEmailCodeError::Internal)?;

        let matched = self
            .challenge_repository
            .verify_email_code(&email, &code_mac, self.config.otp_max_verify_attempts)
            .await
            .map_err(VerifyEmailCodeError::Internal)?
            .ok_or(VerifyEmailCodeError::InvalidOrExpired)?;

        if !matched {
            return Err(VerifyEmailCodeError::InvalidOrExpired);
        }

        let (user_id, is_new_user) = self
            .find_or_create_user_by_email_exact(&email)
            .await
            .map_err(VerifyEmailCodeError::Internal)?;

        let session = self
            .session_repository
            .create_session(user_id)
            .await
            .map_err(VerifyEmailCodeError::Internal)?;

        Ok(EmailAuthSuccess {
            session,
            is_new_user,
        })
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
            OAuthProvider::Near => {
                return Err(anyhow::anyhow!(
                    "NEAR authentication does not use OAuth2 flow"
                ));
            }
        };

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

        let oauth_state = OAuthState {
            state: csrf_token.secret().to_string(),
            provider,
            redirect_uri: redirect_uri.clone(),
            frontend_callback: frontend_callback.clone(),
            created_at: Utc::now(),
        };

        self.oauth_repository
            .store_oauth_state(&oauth_state)
            .await?;

        Ok(auth_url.to_string())
    }

    async fn refresh_token(
        &self,
        user_id: UserId,
        provider: OAuthProvider,
    ) -> anyhow::Result<OAuthTokens> {
        let existing_tokens = self
            .oauth_repository
            .get_oauth_tokens(user_id, provider)
            .await?
            .ok_or_else(|| anyhow::anyhow!("No OAuth tokens found for user"))?;

        let refresh_token_str = existing_tokens
            .refresh_token
            .clone()
            .ok_or_else(|| anyhow::anyhow!("No refresh token available"))?;

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
            OAuthProvider::Near => {
                return Err(anyhow::anyhow!(
                    "NEAR authentication does not use OAuth2 token refresh"
                ));
            }
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

        self.oauth_repository
            .store_oauth_tokens(user_id, provider, &new_tokens)
            .await?;

        Ok(new_tokens)
    }

    async fn handle_callback_unified(
        &self,
        code: String,
        state: String,
    ) -> anyhow::Result<(UserSession, Option<String>, bool, OAuthProvider)> {
        tracing::info!("Handling unified OAuth callback with state: {}", state);

        let oauth_state = self
            .oauth_repository
            .consume_oauth_state(&state)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Invalid or expired OAuth state"))?;

        self.handle_callback_impl(oauth_state.provider, code, oauth_state)
            .await
    }

    async fn revoke_session(&self, session_id: SessionId) -> anyhow::Result<()> {
        tracing::info!("Revoking session: session_id={}", session_id);

        self.session_repository.delete_session(session_id).await?;

        tracing::info!("Session revoked successfully: session_id={}", session_id);
        Ok(())
    }

    async fn authenticate_near(
        &self,
        signed_message: super::near::SignedMessage,
        payload: NEP413Payload,
    ) -> anyhow::Result<(UserSession, bool)> {
        self.near_auth
            .verify_and_authenticate(signed_message, payload)
            .await
    }
}
