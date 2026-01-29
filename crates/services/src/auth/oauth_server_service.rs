//! OAuth 2.0 Authorization Server Service
//!
//! Implements the authorization code grant flow per RFC 6749, enabling third-party
//! applications to access user data with consent.

use async_trait::async_trait;
use chrono::{Duration, Utc};
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::{
    oauth_ports::{
        AccessGrantRepository, AccessTokenRepository, AuthorizationCodeRepository,
        CreateAccessToken, CreateAuthorizationCode, CreatePendingAuthorization,
        CreateRefreshToken, OAuthClientRepository, OAuthClientType,
        PendingAuthorizationRepository, RefreshTokenRepository, UpsertAccessGrant,
    },
    pkce::{validate_challenge_method, verify_pkce, PkceError, SUPPORTED_CHALLENGE_METHOD},
    scopes::{has_offline_access, validate_scopes, ScopeError},
    tokens::{
        generate_access_token, generate_authorization_code, generate_refresh_token, hash_token,
        verify_client_secret,
    },
};
use crate::types::UserId;

// Token lifetimes
const AUTHORIZATION_CODE_LIFETIME_MINUTES: i64 = 10;
const ACCESS_TOKEN_LIFETIME_MINUTES: i64 = 15;
const REFRESH_TOKEN_LIFETIME_DAYS: i64 = 30;
const PENDING_AUTH_LIFETIME_MINUTES: i64 = 10;

/// Result of an authorization request.
#[derive(Debug)]
pub enum AuthorizeResult {
    /// Authorization succeeded, return code to client.
    Success {
        code: String,
        state: Option<String>,
    },
    /// User needs to review and approve consent.
    NeedsConsent {
        pending_id: Uuid,
        client_name: String,
        scopes: Vec<String>,
    },
}

/// Token response from the token endpoint.
#[derive(Debug)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: Option<String>,
    pub scope: String,
}

/// Errors that can occur during OAuth server operations.
#[derive(Debug, thiserror::Error)]
pub enum OAuthServerError {
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Invalid client: {0}")]
    InvalidClient(String),

    #[error("Invalid grant: {0}")]
    InvalidGrant(String),

    #[error("Invalid scope: {0}")]
    InvalidScope(String),

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Server error: {0}")]
    ServerError(String),

    #[error("Unsupported grant type: {0}")]
    UnsupportedGrantType(String),

    #[error("PKCE error: {0}")]
    Pkce(#[from] PkceError),

    #[error("Scope error: {0}")]
    Scope(#[from] ScopeError),
}

impl OAuthServerError {
    /// Get the OAuth error code per RFC 6749.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "invalid_request",
            Self::InvalidClient(_) => "invalid_client",
            Self::InvalidGrant(_) => "invalid_grant",
            Self::InvalidScope(_) => "invalid_scope",
            Self::AccessDenied(_) => "access_denied",
            Self::ServerError(_) => "server_error",
            Self::UnsupportedGrantType(_) => "unsupported_grant_type",
            Self::Pkce(_) => "invalid_grant",
            Self::Scope(_) => "invalid_scope",
        }
    }
}

/// OAuth 2.0 Authorization Server service trait.
#[async_trait]
pub trait OAuthServerService: Send + Sync {
    /// Handle an authorization request (GET /oauth/authorize).
    ///
    /// Validates the request and either:
    /// - Returns a code if the user has already granted consent for these scopes
    /// - Returns NeedsConsent if user approval is required
    async fn authorize(
        &self,
        user_id: UserId,
        client_id: &str,
        redirect_uri: &str,
        scope: &str,
        state: Option<&str>,
        code_challenge: Option<&str>,
        code_challenge_method: Option<&str>,
    ) -> Result<AuthorizeResult, OAuthServerError>;

    /// Approve a pending authorization after user consent.
    async fn approve_consent(
        &self,
        user_id: UserId,
        pending_id: Uuid,
        approved_scopes: Vec<String>,
    ) -> Result<AuthorizeResult, OAuthServerError>;

    /// Deny a pending authorization.
    async fn deny_consent(&self, pending_id: Uuid) -> Result<(), OAuthServerError>;

    /// Exchange an authorization code for tokens (POST /oauth/token, grant_type=authorization_code).
    async fn token_authorization_code(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        code: &str,
        redirect_uri: &str,
        code_verifier: Option<&str>,
    ) -> Result<TokenResponse, OAuthServerError>;

    /// Refresh an access token (POST /oauth/token, grant_type=refresh_token).
    async fn token_refresh(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        refresh_token: &str,
    ) -> Result<TokenResponse, OAuthServerError>;

    /// Get pending authorization details for consent UI.
    async fn get_pending_authorization(
        &self,
        pending_id: Uuid,
        user_id: UserId,
    ) -> Result<Option<PendingAuthorizationInfo>, OAuthServerError>;
}

/// Information about a pending authorization for the consent UI.
#[derive(Debug)]
pub struct PendingAuthorizationInfo {
    pub client_name: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub redirect_uri: String,
}

/// Implementation of the OAuth 2.0 Authorization Server.
pub struct OAuthServerServiceImpl {
    client_repo: Arc<dyn OAuthClientRepository>,
    code_repo: Arc<dyn AuthorizationCodeRepository>,
    access_token_repo: Arc<dyn AccessTokenRepository>,
    refresh_token_repo: Arc<dyn RefreshTokenRepository>,
    grant_repo: Arc<dyn AccessGrantRepository>,
    pending_auth_repo: Arc<dyn PendingAuthorizationRepository>,
    project_repo: Arc<dyn crate::auth::oauth_ports::ProjectRepository>,
}

impl OAuthServerServiceImpl {
    pub fn new(
        client_repo: Arc<dyn OAuthClientRepository>,
        code_repo: Arc<dyn AuthorizationCodeRepository>,
        access_token_repo: Arc<dyn AccessTokenRepository>,
        refresh_token_repo: Arc<dyn RefreshTokenRepository>,
        grant_repo: Arc<dyn AccessGrantRepository>,
        pending_auth_repo: Arc<dyn PendingAuthorizationRepository>,
        project_repo: Arc<dyn crate::auth::oauth_ports::ProjectRepository>,
    ) -> Self {
        Self {
            client_repo,
            code_repo,
            access_token_repo,
            refresh_token_repo,
            grant_repo,
            pending_auth_repo,
            project_repo,
        }
    }

    /// Validate client credentials for the token endpoint.
    async fn authenticate_client(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
    ) -> Result<crate::auth::oauth_ports::OAuthClient, OAuthServerError> {
        let client = self
            .client_repo
            .get_by_client_id(client_id)
            .await
            .map_err(|e| OAuthServerError::ServerError(e.to_string()))?
            .ok_or_else(|| OAuthServerError::InvalidClient("Client not found".to_string()))?;

        if !client.is_active() {
            return Err(OAuthServerError::InvalidClient(
                "Client has been revoked".to_string(),
            ));
        }

        // Confidential clients must provide valid secret
        if client.client_type == OAuthClientType::Confidential {
            let secret = client_secret
                .ok_or_else(|| OAuthServerError::InvalidClient("Client secret required".to_string()))?;

            let secret_hash = client
                .client_secret_hash
                .as_ref()
                .ok_or_else(|| OAuthServerError::ServerError("Client secret not configured".to_string()))?;

            if !verify_client_secret(secret, secret_hash) {
                return Err(OAuthServerError::InvalidClient(
                    "Invalid client credentials".to_string(),
                ));
            }
        }

        Ok(client)
    }

    /// Get the project name for a client (for consent UI).
    async fn get_client_name(&self, project_id: Uuid) -> Result<String, OAuthServerError> {
        let project = self
            .project_repo
            .get_by_id(project_id)
            .await
            .map_err(|e| OAuthServerError::ServerError(e.to_string()))?
            .ok_or_else(|| OAuthServerError::ServerError("Project not found".to_string()))?;

        Ok(project.name)
    }

    /// Issue tokens for a successful authorization.
    async fn issue_tokens(
        &self,
        client_id: &str,
        user_id: UserId,
        scopes: &[String],
        _client_type: OAuthClientType,
    ) -> Result<TokenResponse, OAuthServerError> {
        let now = Utc::now();
        let access_token_expires = now + Duration::minutes(ACCESS_TOKEN_LIFETIME_MINUTES);
        let refresh_token_expires = now + Duration::days(REFRESH_TOKEN_LIFETIME_DAYS);

        // Generate access token
        let access_token = generate_access_token();
        let access_token_hash = access_token.hash();

        let access_token_record = self
            .access_token_repo
            .create(CreateAccessToken {
                token_hash: access_token_hash,
                client_id: client_id.to_string(),
                user_id,
                scopes: scopes.to_vec(),
                expires_at: access_token_expires,
            })
            .await
            .map_err(|e| OAuthServerError::ServerError(e.to_string()))?;

        // Generate refresh token if offline_access scope was granted
        let refresh_token = if has_offline_access(scopes) {
            let refresh_token = generate_refresh_token();
            let refresh_token_hash = refresh_token.hash();

            self.refresh_token_repo
                .create(CreateRefreshToken {
                    token_hash: refresh_token_hash,
                    access_token_id: access_token_record.id,
                    user_id,
                    client_id: client_id.to_string(),
                    expires_at: refresh_token_expires,
                })
                .await
                .map_err(|e| OAuthServerError::ServerError(e.to_string()))?;

            Some(refresh_token.to_string())
        } else {
            None
        };

        // For public clients, we always rotate refresh tokens on use
        // The refresh_token field is already set above based on offline_access

        Ok(TokenResponse {
            access_token: access_token.to_string(),
            token_type: "Bearer".to_string(),
            expires_in: ACCESS_TOKEN_LIFETIME_MINUTES * 60,
            refresh_token,
            scope: scopes.join(" "),
        })
    }
}

#[async_trait]
impl OAuthServerService for OAuthServerServiceImpl {
    async fn authorize(
        &self,
        user_id: UserId,
        client_id: &str,
        redirect_uri: &str,
        scope: &str,
        state: Option<&str>,
        code_challenge: Option<&str>,
        code_challenge_method: Option<&str>,
    ) -> Result<AuthorizeResult, OAuthServerError> {
        // Validate client exists and is active
        let client = self
            .client_repo
            .get_by_client_id(client_id)
            .await
            .map_err(|e| OAuthServerError::ServerError(e.to_string()))?
            .ok_or_else(|| OAuthServerError::InvalidClient("Client not found".to_string()))?;

        if !client.is_active() {
            return Err(OAuthServerError::InvalidClient(
                "Client has been revoked".to_string(),
            ));
        }

        // Validate redirect_uri
        if !client.is_redirect_uri_allowed(redirect_uri) {
            return Err(OAuthServerError::InvalidRequest(
                "Invalid redirect_uri".to_string(),
            ));
        }

        // Parse and validate scopes
        let requested_scopes: Vec<String> = scope.split_whitespace().map(String::from).collect();
        let validated_scopes = validate_scopes(&requested_scopes, &client.allowed_scopes)?;

        // Require PKCE for public clients
        if client.client_type == OAuthClientType::Public {
            if code_challenge.is_none() {
                return Err(OAuthServerError::Pkce(PkceError::ChallengeRequired));
            }
        }

        // Validate code_challenge_method if provided
        if let Some(method) = code_challenge_method {
            validate_challenge_method(method)?;
        } else if code_challenge.is_some() {
            // If challenge is provided but method is not, default to S256
            // (we'll store S256 as the method)
        }

        // Check if user has already granted these scopes
        if let Some(existing_grant) = self
            .grant_repo
            .get(user_id, client_id)
            .await
            .map_err(|e| OAuthServerError::ServerError(e.to_string()))?
        {
            if existing_grant.is_active() && existing_grant.covers_scopes(&validated_scopes) {
                // User already granted these scopes, issue code directly
                let code = generate_authorization_code();
                let code_hash = hash_token(code.as_str());

                self.code_repo
                    .create(CreateAuthorizationCode {
                        code: code_hash,
                        client_id: client_id.to_string(),
                        user_id,
                        redirect_uri: redirect_uri.to_string(),
                        scopes: validated_scopes,
                        code_challenge: code_challenge.map(String::from),
                        code_challenge_method: code_challenge
                            .map(|_| code_challenge_method.unwrap_or(SUPPORTED_CHALLENGE_METHOD).to_string()),
                        expires_at: Utc::now() + Duration::minutes(AUTHORIZATION_CODE_LIFETIME_MINUTES),
                    })
                    .await
                    .map_err(|e| OAuthServerError::ServerError(e.to_string()))?;

                return Ok(AuthorizeResult::Success {
                    code: code.0,
                    state: state.map(String::from),
                });
            }
        }

        // User needs to consent - create pending authorization
        let pending = self
            .pending_auth_repo
            .create(CreatePendingAuthorization {
                client_id: client_id.to_string(),
                user_id,
                redirect_uri: redirect_uri.to_string(),
                scopes: validated_scopes.clone(),
                state: state.map(String::from),
                code_challenge: code_challenge.map(String::from),
                code_challenge_method: code_challenge
                    .map(|_| code_challenge_method.unwrap_or(SUPPORTED_CHALLENGE_METHOD).to_string()),
                expires_at: Utc::now() + Duration::minutes(PENDING_AUTH_LIFETIME_MINUTES),
            })
            .await
            .map_err(|e| OAuthServerError::ServerError(e.to_string()))?;

        let client_name = self.get_client_name(client.project_id).await?;

        Ok(AuthorizeResult::NeedsConsent {
            pending_id: pending.id,
            client_name,
            scopes: validated_scopes,
        })
    }

    async fn approve_consent(
        &self,
        user_id: UserId,
        pending_id: Uuid,
        approved_scopes: Vec<String>,
    ) -> Result<AuthorizeResult, OAuthServerError> {
        // Consume the pending authorization (get and delete atomically)
        let pending = self
            .pending_auth_repo
            .consume(pending_id)
            .await
            .map_err(|e| OAuthServerError::ServerError(e.to_string()))?
            .ok_or_else(|| {
                OAuthServerError::InvalidRequest("Pending authorization not found or expired".to_string())
            })?;

        // Verify user matches
        if pending.user_id != user_id {
            return Err(OAuthServerError::AccessDenied(
                "User mismatch".to_string(),
            ));
        }

        // Verify approved scopes are subset of requested scopes
        for scope in &approved_scopes {
            if !pending.scopes.contains(scope) {
                return Err(OAuthServerError::InvalidScope(format!(
                    "Scope '{}' was not requested",
                    scope
                )));
            }
        }

        // Record the user's consent
        self.grant_repo
            .upsert(UpsertAccessGrant {
                user_id,
                client_id: pending.client_id.clone(),
                scopes: approved_scopes.clone(),
            })
            .await
            .map_err(|e| OAuthServerError::ServerError(e.to_string()))?;

        // Generate authorization code
        let code = generate_authorization_code();
        let code_hash = hash_token(code.as_str());

        self.code_repo
            .create(CreateAuthorizationCode {
                code: code_hash,
                client_id: pending.client_id,
                user_id,
                redirect_uri: pending.redirect_uri,
                scopes: approved_scopes,
                code_challenge: pending.code_challenge,
                code_challenge_method: pending.code_challenge_method,
                expires_at: Utc::now() + Duration::minutes(AUTHORIZATION_CODE_LIFETIME_MINUTES),
            })
            .await
            .map_err(|e| OAuthServerError::ServerError(e.to_string()))?;

        Ok(AuthorizeResult::Success {
            code: code.0,
            state: pending.state,
        })
    }

    async fn deny_consent(&self, pending_id: Uuid) -> Result<(), OAuthServerError> {
        // Just consume and discard the pending authorization
        self.pending_auth_repo
            .consume(pending_id)
            .await
            .map_err(|e| OAuthServerError::ServerError(e.to_string()))?;

        Ok(())
    }

    async fn token_authorization_code(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        code: &str,
        redirect_uri: &str,
        code_verifier: Option<&str>,
    ) -> Result<TokenResponse, OAuthServerError> {
        // Authenticate client
        let client = self.authenticate_client(client_id, client_secret).await?;

        // Hash the code to look it up
        let code_hash = hash_token(code);

        // Consume the authorization code (get and delete atomically)
        let auth_code = self
            .code_repo
            .consume(&code_hash)
            .await
            .map_err(|e| OAuthServerError::ServerError(e.to_string()))?
            .ok_or_else(|| {
                OAuthServerError::InvalidGrant("Authorization code not found or expired".to_string())
            })?;

        // Verify client_id matches
        if auth_code.client_id != client_id {
            return Err(OAuthServerError::InvalidGrant(
                "Authorization code was not issued to this client".to_string(),
            ));
        }

        // Verify redirect_uri matches
        if auth_code.redirect_uri != redirect_uri {
            return Err(OAuthServerError::InvalidGrant(
                "redirect_uri mismatch".to_string(),
            ));
        }

        // Verify PKCE if code_challenge was stored
        if let Some(challenge) = &auth_code.code_challenge {
            let verifier = code_verifier
                .ok_or_else(|| OAuthServerError::InvalidGrant("code_verifier required".to_string()))?;

            verify_pkce(verifier, challenge)?;
        } else if code_verifier.is_some() {
            // Code verifier provided but no challenge was stored - this is an error
            return Err(OAuthServerError::InvalidGrant(
                "code_verifier provided but no code_challenge was stored".to_string(),
            ));
        }

        // Issue tokens
        self.issue_tokens(
            client_id,
            auth_code.user_id,
            &auth_code.scopes,
            client.client_type,
        )
        .await
    }

    async fn token_refresh(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        refresh_token: &str,
    ) -> Result<TokenResponse, OAuthServerError> {
        // Authenticate client
        let client = self.authenticate_client(client_id, client_secret).await?;

        // Hash the refresh token to look it up
        let token_hash = hash_token(refresh_token);

        // Get the refresh token
        let refresh_token_record = self
            .refresh_token_repo
            .get_by_hash(&token_hash)
            .await
            .map_err(|e| OAuthServerError::ServerError(e.to_string()))?
            .ok_or_else(|| OAuthServerError::InvalidGrant("Invalid refresh token".to_string()))?;

        // Check if token is valid
        if !refresh_token_record.is_valid() {
            return Err(OAuthServerError::InvalidGrant(
                "Refresh token has expired or been revoked".to_string(),
            ));
        }

        // Get user_id and client_id from refresh token record (new fields)
        // Fall back to looking up via access token if not present (for backwards compatibility)
        let (user_id, token_client_id, scopes) = if let (Some(uid), Some(cid)) = (
            refresh_token_record.user_id,
            refresh_token_record.client_id.as_ref(),
        ) {
            // Use the new direct fields - get scopes from the grant
            let grant = self
                .grant_repo
                .get(uid, cid)
                .await
                .map_err(|e| OAuthServerError::ServerError(e.to_string()))?
                .ok_or_else(|| OAuthServerError::InvalidGrant("Grant not found".to_string()))?;

            (uid, cid.clone(), grant.scopes)
        } else {
            // Backwards compatibility: look up via access token
            let access_token = self
                .access_token_repo
                .get_by_id(refresh_token_record.access_token_id)
                .await
                .map_err(|e| OAuthServerError::ServerError(e.to_string()))?
                .ok_or_else(|| {
                    OAuthServerError::InvalidGrant("Associated access token not found".to_string())
                })?;

            (access_token.user_id, access_token.client_id.clone(), access_token.scopes)
        };

        // Verify client_id matches
        if token_client_id != client_id {
            return Err(OAuthServerError::InvalidGrant(
                "Refresh token was not issued to this client".to_string(),
            ));
        }

        // For public clients, rotate the refresh token (revoke old one)
        if client.client_type == OAuthClientType::Public {
            self.refresh_token_repo
                .revoke(refresh_token_record.id)
                .await
                .map_err(|e| OAuthServerError::ServerError(e.to_string()))?;
        }

        // Issue new tokens
        self.issue_tokens(client_id, user_id, &scopes, client.client_type)
            .await
    }

    async fn get_pending_authorization(
        &self,
        pending_id: Uuid,
        user_id: UserId,
    ) -> Result<Option<PendingAuthorizationInfo>, OAuthServerError> {
        let pending = self
            .pending_auth_repo
            .get_by_id(pending_id)
            .await
            .map_err(|e| OAuthServerError::ServerError(e.to_string()))?;

        let pending = match pending {
            Some(p) if p.user_id == user_id => p,
            _ => return Ok(None),
        };

        // Get client info
        let client = self
            .client_repo
            .get_by_client_id(&pending.client_id)
            .await
            .map_err(|e| OAuthServerError::ServerError(e.to_string()))?
            .ok_or_else(|| OAuthServerError::ServerError("Client not found".to_string()))?;

        let client_name = self.get_client_name(client.project_id).await?;

        Ok(Some(PendingAuthorizationInfo {
            client_name,
            client_id: pending.client_id,
            scopes: pending.scopes,
            redirect_uri: pending.redirect_uri,
        }))
    }
}
