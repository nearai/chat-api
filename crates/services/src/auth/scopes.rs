//! OAuth scope definitions and validation for the Private Memory API.
//!
//! Scopes control what access third-party applications have to user data.

use thiserror::Error;

/// All valid OAuth scopes for the Private Memory API.
pub const VALID_SCOPES: &[&str] = &[
    "memory.read",           // Read memories created by this app (app-scoped)
    "memory.read.all",       // Read all user memories (cross-app, global)
    "memory.write",          // Write memories (global by design)
    "files.read",            // Read files uploaded by this app (app-scoped)
    "files.read.all",        // Read all user files (global)
    "files.write",           // Upload files (global)
    "conversations.read",    // Read conversations from this app (app-scoped)
    "conversations.read.all", // Read all conversations (global)
    "profile.read",          // Read user profile (name, email)
    "offline_access",        // Request refresh tokens (meta scope)
];

/// Errors that can occur during scope validation.
#[derive(Debug, Error)]
pub enum ScopeError {
    #[error("Invalid scope: {0}")]
    InvalidScope(String),

    #[error("Scope not allowed for this client: {0}")]
    ScopeNotAllowed(String),

    #[error("No scopes requested")]
    NoScopes,
}

/// Check if a scope is valid (exists in the system).
pub fn is_valid_scope(scope: &str) -> bool {
    VALID_SCOPES.contains(&scope)
}

/// Check if a scope grants global access (vs app-scoped access).
pub fn is_global_scope(scope: &str) -> bool {
    matches!(
        scope,
        "memory.read.all"
            | "memory.write"
            | "files.read.all"
            | "files.write"
            | "conversations.read.all"
            | "profile.read"
            | "offline_access"
    )
}

/// Check if a scope is app-scoped (limited to data created by the requesting app).
pub fn is_app_scoped(scope: &str) -> bool {
    matches!(scope, "memory.read" | "files.read" | "conversations.read")
}

/// Validate requested scopes against a client's allowed scopes.
///
/// # Arguments
/// * `requested` - Scopes requested by the client in the authorization request
/// * `allowed` - Scopes that the client is allowed to request (configured during client registration)
///
/// # Returns
/// * `Ok(Vec<String>)` - The validated scopes (same as requested if all valid)
/// * `Err(ScopeError)` - If any scope is invalid or not allowed
pub fn validate_scopes(requested: &[String], allowed: &[String]) -> Result<Vec<String>, ScopeError> {
    if requested.is_empty() {
        return Err(ScopeError::NoScopes);
    }

    for scope in requested {
        if !VALID_SCOPES.contains(&scope.as_str()) {
            return Err(ScopeError::InvalidScope(scope.clone()));
        }
        if !allowed.contains(scope) {
            return Err(ScopeError::ScopeNotAllowed(scope.clone()));
        }
    }

    Ok(requested.to_vec())
}

/// Parse a space-separated scope string into a vector of scopes.
///
/// # Arguments
/// * `scope_string` - Space-separated list of scopes (e.g., "memory.read memory.write")
///
/// # Returns
/// A vector of individual scope strings
pub fn parse_scope_string(scope_string: &str) -> Vec<String> {
    scope_string
        .split_whitespace()
        .map(|s| s.to_string())
        .collect()
}

/// Join a vector of scopes into a space-separated string.
///
/// # Arguments
/// * `scopes` - Vector of scope strings
///
/// # Returns
/// A space-separated scope string
pub fn join_scopes(scopes: &[String]) -> String {
    scopes.join(" ")
}

/// Check if a set of scopes includes read access (either app-scoped or global).
pub fn has_memory_read_access(scopes: &[String]) -> bool {
    scopes.iter().any(|s| s == "memory.read" || s == "memory.read.all")
}

/// Check if a set of scopes includes global memory read access.
pub fn has_global_memory_read(scopes: &[String]) -> bool {
    scopes.iter().any(|s| s == "memory.read.all")
}

/// Check if a set of scopes includes memory write access.
pub fn has_memory_write_access(scopes: &[String]) -> bool {
    scopes.iter().any(|s| s == "memory.write")
}

/// Check if a set of scopes requests offline access (refresh tokens).
pub fn has_offline_access(scopes: &[String]) -> bool {
    scopes.iter().any(|s| s == "offline_access")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_scopes() {
        assert!(is_valid_scope("memory.read"));
        assert!(is_valid_scope("memory.write"));
        assert!(is_valid_scope("offline_access"));
        assert!(!is_valid_scope("invalid.scope"));
        assert!(!is_valid_scope(""));
    }

    #[test]
    fn test_global_vs_app_scoped() {
        assert!(is_app_scoped("memory.read"));
        assert!(!is_app_scoped("memory.read.all"));
        assert!(is_global_scope("memory.read.all"));
        assert!(is_global_scope("memory.write"));
        assert!(!is_global_scope("memory.read"));
    }

    #[test]
    fn test_validate_scopes_success() {
        let requested = vec!["memory.read".to_string(), "memory.write".to_string()];
        let allowed = vec![
            "memory.read".to_string(),
            "memory.write".to_string(),
            "profile.read".to_string(),
        ];

        let result = validate_scopes(&requested, &allowed);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), requested);
    }

    #[test]
    fn test_validate_scopes_invalid() {
        let requested = vec!["memory.read".to_string(), "invalid.scope".to_string()];
        let allowed = vec!["memory.read".to_string()];

        let result = validate_scopes(&requested, &allowed);
        assert!(matches!(result, Err(ScopeError::InvalidScope(_))));
    }

    #[test]
    fn test_validate_scopes_not_allowed() {
        let requested = vec!["memory.read".to_string(), "memory.write".to_string()];
        let allowed = vec!["memory.read".to_string()]; // memory.write not allowed

        let result = validate_scopes(&requested, &allowed);
        assert!(matches!(result, Err(ScopeError::ScopeNotAllowed(_))));
    }

    #[test]
    fn test_validate_scopes_empty() {
        let requested: Vec<String> = vec![];
        let allowed = vec!["memory.read".to_string()];

        let result = validate_scopes(&requested, &allowed);
        assert!(matches!(result, Err(ScopeError::NoScopes)));
    }

    #[test]
    fn test_parse_scope_string() {
        let scopes = parse_scope_string("memory.read memory.write profile.read");
        assert_eq!(scopes.len(), 3);
        assert_eq!(scopes[0], "memory.read");
        assert_eq!(scopes[1], "memory.write");
        assert_eq!(scopes[2], "profile.read");
    }

    #[test]
    fn test_join_scopes() {
        let scopes = vec![
            "memory.read".to_string(),
            "memory.write".to_string(),
        ];
        assert_eq!(join_scopes(&scopes), "memory.read memory.write");
    }

    #[test]
    fn test_has_memory_access() {
        let scopes_app = vec!["memory.read".to_string()];
        let scopes_global = vec!["memory.read.all".to_string()];
        let scopes_write = vec!["memory.write".to_string()];
        let scopes_none = vec!["profile.read".to_string()];

        assert!(has_memory_read_access(&scopes_app));
        assert!(has_memory_read_access(&scopes_global));
        assert!(!has_memory_read_access(&scopes_write));
        assert!(!has_memory_read_access(&scopes_none));

        assert!(!has_global_memory_read(&scopes_app));
        assert!(has_global_memory_read(&scopes_global));

        assert!(has_memory_write_access(&scopes_write));
        assert!(!has_memory_write_access(&scopes_app));
    }
}
