//! OAuth token generation and utilities.
//!
//! This module provides secure token generation for OAuth 2.0 flows,
//! including access tokens, refresh tokens, authorization codes, and client credentials.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fmt;

/// Token prefixes for easy identification and routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenPrefix {
    /// First-party session token (existing system)
    Session,
    /// OAuth access token (third-party apps)
    AccessToken,
    /// OAuth refresh token
    RefreshToken,
}

impl TokenPrefix {
    /// Get the string prefix for this token type.
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenPrefix::Session => "pm_st_",
            TokenPrefix::AccessToken => "pm_at_",
            TokenPrefix::RefreshToken => "pm_rt_",
        }
    }

    /// Detect token type from a token string.
    pub fn from_token(token: &str) -> Option<Self> {
        if token.starts_with(Self::Session.as_str()) {
            Some(Self::Session)
        } else if token.starts_with(Self::AccessToken.as_str()) {
            Some(Self::AccessToken)
        } else if token.starts_with(Self::RefreshToken.as_str()) {
            Some(Self::RefreshToken)
        } else {
            None
        }
    }
}

impl fmt::Display for TokenPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Newtype for OAuth client IDs (public identifier).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientId(pub String);

impl ClientId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for ClientId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for ClientId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Newtype for OAuth client secrets (confidential).
#[derive(Clone)]
pub struct ClientSecret(String);

impl ClientSecret {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Hash the client secret for storage.
    pub fn hash(&self) -> String {
        hash_token(&self.0)
    }
}

// Don't leak secrets in debug output
impl fmt::Debug for ClientSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClientSecret([REDACTED])")
    }
}

/// Newtype for authorization codes.
#[derive(Debug, Clone)]
pub struct AuthorizationCode(pub String);

impl AuthorizationCode {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Newtype for access token IDs (the actual token value before hashing).
#[derive(Clone)]
pub struct AccessTokenId(String);

impl AccessTokenId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Hash the token for storage.
    pub fn hash(&self) -> String {
        hash_token(&self.0)
    }
}

impl fmt::Debug for AccessTokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AccessTokenId([REDACTED])")
    }
}

impl fmt::Display for AccessTokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Newtype for refresh token IDs.
#[derive(Clone)]
pub struct RefreshTokenId(String);

impl RefreshTokenId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Hash the token for storage.
    pub fn hash(&self) -> String {
        hash_token(&self.0)
    }
}

impl fmt::Debug for RefreshTokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RefreshTokenId([REDACTED])")
    }
}

impl fmt::Display for RefreshTokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Generate cryptographically secure random bytes.
fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

/// Generate a random hex string of specified byte length.
fn generate_hex_string(byte_len: usize) -> String {
    hex::encode(generate_random_bytes(byte_len))
}

/// Generate a random URL-safe base64 string of specified byte length.
fn generate_base64_string(byte_len: usize) -> String {
    URL_SAFE_NO_PAD.encode(generate_random_bytes(byte_len))
}

/// Hash a token using SHA256 for secure storage.
///
/// Tokens are never stored in plain text - only their hashes.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate a new OAuth client ID.
///
/// Format: 32 character hex string (16 bytes of entropy)
pub fn generate_client_id() -> ClientId {
    ClientId(generate_hex_string(16))
}

/// Generate a new OAuth client secret.
///
/// Format: 64 character hex string (32 bytes of entropy)
pub fn generate_client_secret() -> ClientSecret {
    ClientSecret(generate_hex_string(32))
}

/// Generate a new authorization code.
///
/// Format: 43 character base64url string (32 bytes of entropy)
pub fn generate_authorization_code() -> AuthorizationCode {
    AuthorizationCode(generate_base64_string(32))
}

/// Generate a new access token.
///
/// Format: pm_at_ prefix + 43 character base64url string
pub fn generate_access_token() -> AccessTokenId {
    let random_part = generate_base64_string(32);
    AccessTokenId(format!("{}{}", TokenPrefix::AccessToken.as_str(), random_part))
}

/// Generate a new refresh token.
///
/// Format: pm_rt_ prefix + 43 character base64url string
pub fn generate_refresh_token() -> RefreshTokenId {
    let random_part = generate_base64_string(32);
    RefreshTokenId(format!("{}{}", TokenPrefix::RefreshToken.as_str(), random_part))
}

/// Verify a client secret against its stored hash.
pub fn verify_client_secret(secret: &str, hash: &str) -> bool {
    hash_token(secret) == hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_prefix_detection() {
        assert_eq!(
            TokenPrefix::from_token("pm_st_abc123"),
            Some(TokenPrefix::Session)
        );
        assert_eq!(
            TokenPrefix::from_token("pm_at_abc123"),
            Some(TokenPrefix::AccessToken)
        );
        assert_eq!(
            TokenPrefix::from_token("pm_rt_abc123"),
            Some(TokenPrefix::RefreshToken)
        );
        assert_eq!(TokenPrefix::from_token("invalid_token"), None);
    }

    #[test]
    fn test_generate_client_id() {
        let client_id = generate_client_id();
        assert_eq!(client_id.0.len(), 32);
        assert!(client_id.0.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_client_secret() {
        let secret = generate_client_secret();
        assert_eq!(secret.0.len(), 64);
        assert!(secret.0.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_authorization_code() {
        let code = generate_authorization_code();
        assert_eq!(code.0.len(), 43); // base64url of 32 bytes
    }

    #[test]
    fn test_generate_access_token() {
        let token = generate_access_token();
        assert!(token.0.starts_with("pm_at_"));
        assert_eq!(token.0.len(), 6 + 43); // prefix + base64url
    }

    #[test]
    fn test_generate_refresh_token() {
        let token = generate_refresh_token();
        assert!(token.0.starts_with("pm_rt_"));
        assert_eq!(token.0.len(), 6 + 43); // prefix + base64url
    }

    #[test]
    fn test_hash_token() {
        let token = "test_token";
        let hash = hash_token(token);

        // SHA256 produces 64 hex characters
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));

        // Same input should produce same hash
        assert_eq!(hash, hash_token(token));

        // Different input should produce different hash
        assert_ne!(hash, hash_token("different_token"));
    }

    #[test]
    fn test_verify_client_secret() {
        let secret = generate_client_secret();
        let hash = secret.hash();

        assert!(verify_client_secret(secret.as_str(), &hash));
        assert!(!verify_client_secret("wrong_secret", &hash));
    }

    #[test]
    fn test_uniqueness() {
        // Generate multiple tokens and ensure they're unique
        let tokens: Vec<_> = (0..100).map(|_| generate_access_token().0).collect();
        let unique: std::collections::HashSet<_> = tokens.iter().collect();
        assert_eq!(tokens.len(), unique.len());
    }

    #[test]
    fn test_client_secret_debug_redacted() {
        let secret = generate_client_secret();
        let debug_output = format!("{:?}", secret);
        assert!(debug_output.contains("REDACTED"));
        assert!(!debug_output.contains(&secret.0));
    }
}
