//! Validation utilities for API request data
use url::{Host, Url};

/// Validates a URL for Stripe checkout/portal redirects.
/// Requires https for production. Allows http only for loopback (localhost, 127.0.0.1, [::1]).
pub fn validate_redirect_url(url_str: &str, field_name: &str) -> Result<(), String> {
    let url =
        Url::parse(url_str).map_err(|_| format!("Invalid {}: must be a valid URL", field_name))?;
    match url.scheme() {
        "https" => Ok(()),
        "http" => {
            let host_ok = match url.host() {
                Some(Host::Domain(d)) => d == "localhost",
                Some(Host::Ipv4(ip)) => ip.is_loopback(),
                Some(Host::Ipv6(ip)) => ip.is_loopback(),
                _ => false,
            };
            if host_ok {
                Ok(())
            } else {
                Err(format!(
                    "Invalid {}: URL must use https for non-localhost",
                    field_name
                ))
            }
        }
        _ => Err(format!(
            "Invalid {}: URL scheme must be https or http (localhost only)",
            field_name
        )),
    }
}

/// Validates an email address format.
///
/// Email addresses must:
/// - Not contain spaces
/// - Have exactly one '@' character
/// - Have non-empty local and domain parts
/// - Have at least one dot in the domain part
/// - Not start or end with a dot in the domain
///
/// # Arguments
/// * `email` - The email address to validate
///
/// # Returns
/// * `Ok(())` - Email is valid
/// * `Err(String)` - Error message describing why validation failed
///
/// # Examples
/// ```
/// use api::validation::validate_email;
///
/// assert!(validate_email("user@example.com").is_ok());
/// assert!(validate_email("user.name@subdomain.example.com").is_ok());
/// assert!(validate_email("invalid").is_err());
/// assert!(validate_email("@example.com").is_err());
/// ```
pub fn validate_email(email: &str) -> Result<(), String> {
    let trimmed = email.trim();

    if trimmed.is_empty() {
        return Err("Email cannot be empty".to_string());
    }

    // Reject spaces
    if trimmed.contains(' ') {
        return Err("Email cannot contain spaces".to_string());
    }

    // Require exactly one '@' and non-empty local/domain parts
    let (local, domain) = match trimmed.split_once('@') {
        Some(parts) => parts,
        None => return Err("Email must contain exactly one '@' character".to_string()),
    };

    if local.is_empty() {
        return Err("Email local part (before @) cannot be empty".to_string());
    }

    if domain.is_empty() {
        return Err("Email domain part (after @) cannot be empty".to_string());
    }

    // Ensure there are no additional '@' characters in the domain part
    if domain.contains('@') {
        return Err("Email domain part cannot contain '@' character".to_string());
    }

    // Require at least one dot in the domain, not at start or end
    if !domain.contains('.') {
        return Err("Email domain must contain at least one dot (e.g., example.com)".to_string());
    }

    if domain.starts_with('.') || domain.ends_with('.') {
        return Err("Email domain cannot start or end with a dot".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_emails() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("user.name@example.com").is_ok());
        assert!(validate_email("user+tag@subdomain.example.com").is_ok());
        assert!(validate_email("user_name@example.co.uk").is_ok());
        assert!(validate_email("  user@example.com  ").is_ok()); // Trimmed
    }

    #[test]
    fn test_invalid_emails() {
        // Empty
        assert!(validate_email("").is_err());
        assert!(validate_email("   ").is_err());

        // Missing @
        assert!(validate_email("userexample.com").is_err());

        // Multiple @
        assert!(validate_email("user@example@com").is_err());

        // Empty local part
        assert!(validate_email("@example.com").is_err());

        // Empty domain part
        assert!(validate_email("user@").is_err());

        // No dot in domain
        assert!(validate_email("user@example").is_err());

        // Domain starts with dot
        assert!(validate_email("user@.example.com").is_err());

        // Domain ends with dot
        assert!(validate_email("user@example.com.").is_err());

        // Contains spaces
        assert!(validate_email("user @example.com").is_err());
        assert!(validate_email("user@example .com").is_err());
    }
}
