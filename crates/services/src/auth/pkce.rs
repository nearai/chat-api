//! PKCE (Proof Key for Code Exchange) implementation per RFC 7636.
//!
//! PKCE protects public OAuth clients (SPAs, mobile apps) from authorization code
//! interception attacks by requiring proof of the original authorization request.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors that can occur during PKCE validation.
#[derive(Debug, Error)]
pub enum PkceError {
    #[error("Code verifier must be between 43 and 128 characters")]
    InvalidVerifierLength,

    #[error("Code verifier contains invalid characters")]
    InvalidVerifierCharacters,

    #[error("Code challenge verification failed")]
    ChallengeMismatch,

    #[error("Unsupported code challenge method: {0}")]
    UnsupportedMethod(String),

    #[error("Code challenge is required for public clients")]
    ChallengeRequired,
}

/// The only supported code challenge method.
/// We do not support 'plain' method as it provides no security benefit.
pub const SUPPORTED_CHALLENGE_METHOD: &str = "S256";

/// Verify a PKCE code verifier against a code challenge.
///
/// # Arguments
/// * `code_verifier` - The original random string sent by the client
/// * `code_challenge` - The challenge stored during authorization (BASE64URL(SHA256(verifier)))
///
/// # Returns
/// * `Ok(())` if verification succeeds
/// * `Err(PkceError)` if verification fails
pub fn verify_pkce(code_verifier: &str, code_challenge: &str) -> Result<(), PkceError> {
    // First validate the verifier format
    validate_code_verifier(code_verifier)?;

    // S256: BASE64URL(SHA256(code_verifier)) == code_challenge
    let computed_challenge = generate_code_challenge(code_verifier);

    if computed_challenge == code_challenge {
        Ok(())
    } else {
        Err(PkceError::ChallengeMismatch)
    }
}

/// Generate a code challenge from a code verifier using S256 method.
///
/// # Arguments
/// * `code_verifier` - The random string to hash
///
/// # Returns
/// The BASE64URL-encoded SHA256 hash of the verifier (no padding)
pub fn generate_code_challenge(code_verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let hash = hasher.finalize();
    URL_SAFE_NO_PAD.encode(hash)
}

/// Validate that a code verifier meets RFC 7636 requirements.
///
/// Requirements:
/// - Length: 43-128 characters
/// - Characters: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
///
/// # Arguments
/// * `verifier` - The code verifier to validate
///
/// # Returns
/// * `Ok(())` if valid
/// * `Err(PkceError)` if invalid
pub fn validate_code_verifier(verifier: &str) -> Result<(), PkceError> {
    // RFC 7636: code_verifier = 43*128unreserved
    if verifier.len() < 43 || verifier.len() > 128 {
        return Err(PkceError::InvalidVerifierLength);
    }

    // unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
    let is_valid_char = |c: char| c.is_ascii_alphanumeric() || "-._~".contains(c);

    if !verifier.chars().all(is_valid_char) {
        return Err(PkceError::InvalidVerifierCharacters);
    }

    Ok(())
}

/// Validate the code challenge method.
///
/// Only S256 is supported for security reasons.
///
/// # Arguments
/// * `method` - The method string (should be "S256")
///
/// # Returns
/// * `Ok(())` if method is supported
/// * `Err(PkceError)` if method is not supported
pub fn validate_challenge_method(method: &str) -> Result<(), PkceError> {
    if method == SUPPORTED_CHALLENGE_METHOD {
        Ok(())
    } else {
        Err(PkceError::UnsupportedMethod(method.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_challenge() {
        // Test vector from RFC 7636 Appendix B
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        let challenge = generate_code_challenge(verifier);
        assert_eq!(challenge, expected_challenge);
    }

    #[test]
    fn test_verify_pkce_success() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        assert!(verify_pkce(verifier, challenge).is_ok());
    }

    #[test]
    fn test_verify_pkce_failure() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let wrong_challenge = "wrong_challenge_value_here_abcdefghij";

        assert!(matches!(
            verify_pkce(verifier, wrong_challenge),
            Err(PkceError::ChallengeMismatch)
        ));
    }

    #[test]
    fn test_validate_verifier_length() {
        // Too short (42 chars)
        let short = "a".repeat(42);
        assert!(matches!(
            validate_code_verifier(&short),
            Err(PkceError::InvalidVerifierLength)
        ));

        // Minimum valid (43 chars)
        let min_valid = "a".repeat(43);
        assert!(validate_code_verifier(&min_valid).is_ok());

        // Maximum valid (128 chars)
        let max_valid = "a".repeat(128);
        assert!(validate_code_verifier(&max_valid).is_ok());

        // Too long (129 chars)
        let long = "a".repeat(129);
        assert!(matches!(
            validate_code_verifier(&long),
            Err(PkceError::InvalidVerifierLength)
        ));
    }

    #[test]
    fn test_validate_verifier_characters() {
        // Valid characters
        let valid = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        // Pad to minimum length
        let valid_padded = format!("{}{}", valid, "a".repeat(43 - valid.len().min(43)));
        assert!(validate_code_verifier(&valid_padded).is_ok());

        // Invalid character (space)
        let invalid_space = format!("{}a b{}", "a".repeat(20), "a".repeat(20));
        assert!(matches!(
            validate_code_verifier(&invalid_space),
            Err(PkceError::InvalidVerifierCharacters)
        ));

        // Invalid character (special)
        let invalid_special = format!("{}@{}", "a".repeat(42), "a");
        assert!(matches!(
            validate_code_verifier(&invalid_special),
            Err(PkceError::InvalidVerifierCharacters)
        ));
    }

    #[test]
    fn test_validate_challenge_method() {
        assert!(validate_challenge_method("S256").is_ok());
        assert!(matches!(
            validate_challenge_method("plain"),
            Err(PkceError::UnsupportedMethod(_))
        ));
        assert!(matches!(
            validate_challenge_method("s256"), // case sensitive
            Err(PkceError::UnsupportedMethod(_))
        ));
    }
}
