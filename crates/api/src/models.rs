use serde::{Deserialize, Serialize};
use services::UserId;
use utoipa::ToSchema;

/// User response DTO
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UserResponse {
    pub id: UserId,
    pub email: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Linked OAuth account response
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct LinkedAccountResponse {
    pub provider: String,
    pub linked_at: String,
}

/// User profile response with linked accounts
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UserProfileResponse {
    pub user: UserResponse,
    pub linked_accounts: Vec<LinkedAccountResponse>,
}

/// Response for successful authentication
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AuthResponse {
    pub token: String,
    pub expires_at: String,
}

/// Error response
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ErrorResponse {
    pub error: String,
}

impl From<services::user::ports::User> for UserResponse {
    fn from(user: services::user::ports::User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            name: user.name,
            avatar_url: user.avatar_url,
            created_at: user.created_at.to_rfc3339(),
            updated_at: user.updated_at.to_rfc3339(),
        }
    }
}

impl From<services::user::ports::LinkedOAuthAccount> for LinkedAccountResponse {
    fn from(account: services::user::ports::LinkedOAuthAccount) -> Self {
        let provider = match account.provider {
            services::user::ports::OAuthProvider::Google => "google",
            services::user::ports::OAuthProvider::Github => "github",
        };
        Self {
            provider: provider.to_string(),
            linked_at: account.linked_at.to_rfc3339(),
        }
    }
}

impl From<services::user::ports::UserProfile> for UserProfileResponse {
    fn from(profile: services::user::ports::UserProfile) -> Self {
        Self {
            user: profile.user.into(),
            linked_accounts: profile
                .linked_accounts
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}
