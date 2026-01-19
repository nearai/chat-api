//! Validation utilities for API request data
use near_api::AccountId;

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

/// Validates a NEAR account ID format.
///
/// NEAR account IDs must:
/// - Be parseable as a valid NEAR AccountId
/// - Follow NEAR account naming conventions (2-64 characters, alphanumeric or separators)
///
/// # Arguments
/// * `account_id` - The NEAR account ID to validate
///
/// # Returns
/// * `Ok(())` - Account ID is valid
/// * `Err(String)` - Error message describing why validation failed
///
/// # Examples
/// ```
/// use api::validation::validate_near_account;
///
/// assert!(validate_near_account("alice.near").is_ok());
/// assert!(validate_near_account("bob.testnet").is_ok());
/// assert!(validate_near_account("test@invalid").is_err()); // Contains invalid character
/// ```
pub fn validate_near_account(account_id: &str) -> Result<(), String> {
    let trimmed = account_id.trim();

    if trimmed.is_empty() {
        return Err("NEAR account ID cannot be empty".to_string());
    }

    // Try to parse as NEAR AccountId
    match trimmed.parse::<AccountId>() {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Invalid NEAR account ID format: {}", e)),
    }
}

/// Validates an organization email pattern for conversation sharing.
///
/// Email patterns must:
/// - Start with '@' or '%@' (wildcard prefix)
/// - Contain at least one '.' in the domain part
/// - Have minimum 3 characters after the '@' (e.g., @a.b)
///
/// # Arguments
/// * `pattern` - The email pattern to validate (e.g., "@company.com" or "%@company.com")
///
/// # Returns
/// * `Ok(String)` - Trimmed and validated email pattern
/// * `Err(String)` - Error message describing why validation failed
///
/// # Examples
/// ```
/// use api::validation::validate_org_email_pattern;
///
/// assert!(validate_org_email_pattern("@company.com").is_ok());
/// assert!(validate_org_email_pattern("%@company.com").is_ok()); // Normalized pattern
/// assert!(validate_org_email_pattern("@subdomain.company.com").is_ok());
/// assert!(validate_org_email_pattern("company.com").is_err()); // Missing @
/// assert!(validate_org_email_pattern("@company").is_err()); // Missing .
/// ```
pub fn validate_org_email_pattern(pattern: &str) -> Result<String, String> {
    let trimmed = pattern.trim();

    if trimmed.is_empty() {
        return Err("Email pattern cannot be empty".to_string());
    }

    // Validate email pattern format (must start with @ or %@ and have valid domain)
    // Accept both user-provided format (@company.com) and normalized format (%@company.com)
    let domain_part = if let Some(stripped) = trimmed.strip_prefix("%@") {
        stripped
    } else if let Some(stripped) = trimmed.strip_prefix('@') {
        stripped
    } else {
        return Err("Email pattern must start with @ (e.g., @company.com)".to_string());
    };

    // Basic validation: domain should have at least one dot and minimum length
    if domain_part.is_empty() || !domain_part.contains('.') || domain_part.len() < 3 {
        return Err("Invalid email pattern. Must be in format @domain.com".to_string());
    }

    Ok(trimmed.to_string())
}

/// Validates a share recipient based on its kind.
///
/// - For Email recipients: validates email format
/// - For NearAccount recipients: validates NEAR account ID format
///
/// # Arguments
/// * `kind` - The recipient kind (Email or NearAccount)
/// * `value` - The recipient value to validate
///
/// # Returns
/// * `Ok(())` - Recipient value is valid
/// * `Err(String)` - Error message describing why validation failed
pub fn validate_share_recipient(
    kind: &services::conversation::ports::ShareRecipientKind,
    value: &str,
) -> Result<(), String> {
    match kind {
        services::conversation::ports::ShareRecipientKind::Email => validate_email(value),
        services::conversation::ports::ShareRecipientKind::NearAccount => {
            validate_near_account(value)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_email_patterns() {
        assert!(validate_org_email_pattern("@company.com").is_ok());
        assert!(validate_org_email_pattern("@subdomain.company.com").is_ok());
        assert!(validate_org_email_pattern("  @company.com  ").is_ok()); // Trimmed
        assert!(validate_org_email_pattern("@a.b.c").is_ok());
        // Normalized patterns (with %@ prefix) should also be valid
        assert!(validate_org_email_pattern("%@company.com").is_ok());
        assert!(validate_org_email_pattern("%@subdomain.company.com").is_ok());
        assert!(validate_org_email_pattern("  %@company.com  ").is_ok()); // Trimmed
    }

    #[test]
    fn test_invalid_email_patterns() {
        // Empty
        assert!(validate_org_email_pattern("").is_err());
        assert!(validate_org_email_pattern("   ").is_err());

        // Missing @
        assert!(validate_org_email_pattern("company.com").is_err());

        // Missing domain parts
        assert!(validate_org_email_pattern("@").is_err());
        assert!(validate_org_email_pattern("@company").is_err());
        assert!(validate_org_email_pattern("@a").is_err());
        assert!(validate_org_email_pattern("@a.").is_err());

        // Invalid normalized patterns (missing domain parts after %@)
        assert!(validate_org_email_pattern("%@").is_err());
        assert!(validate_org_email_pattern("%@company").is_err());
        assert!(validate_org_email_pattern("%@a").is_err());
    }

    #[test]
    fn test_trimming() {
        let result = validate_org_email_pattern("  @company.com  ");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "@company.com");
    }

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

    #[test]
    fn test_valid_near_accounts() {
        assert!(validate_near_account("alice.near").is_ok());
        assert!(validate_near_account("bob.testnet").is_ok());
        assert!(validate_near_account("contract.mainnet").is_ok());
        assert!(validate_near_account("  alice.near  ").is_ok()); // Trimmed
    }

    #[test]
    fn test_invalid_near_accounts() {
        // Empty
        assert!(validate_near_account("").is_err());
        assert!(validate_near_account("   ").is_err());

        // Invalid format - too short (NEAR accounts must be at least 2 characters)
        assert!(validate_near_account("a").is_err());

        // Invalid format - contains invalid characters
        assert!(validate_near_account("test@invalid").is_err());
        assert!(validate_near_account("test#invalid").is_err());

        // Invalid format - too long (NEAR accounts max 64 chars, but some patterns are invalid)
        // Note: "invalid" and "too-short" might actually be valid NEAR account IDs
        // So we test with clearly invalid patterns
    }
}
