//! Validation utilities for API request data

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
    let domain_part = if trimmed.starts_with("%@") {
        &trimmed[2..] // Skip the %@
    } else if trimmed.starts_with('@') {
        &trimmed[1..] // Skip the @
    } else {
        return Err("Email pattern must start with @ (e.g., @company.com)".to_string());
    };

    // Basic validation: domain should have at least one dot and minimum length
    if domain_part.is_empty() || !domain_part.contains('.') || domain_part.len() < 3 {
        return Err("Invalid email pattern. Must be in format @domain.com".to_string());
    }

    Ok(trimmed.to_string())
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
}
