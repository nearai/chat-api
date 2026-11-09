//! Metadata for logs that must not contain error messages or their source chains.

/// Return only the static Rust type of an error, including string-backed errors.
///
/// Display and Debug implementations can expose HTTP URLs, OAuth responses, SQL
/// row values, and channel payloads. Do not format the error or inspect its source
/// chain here. Log operation names, IDs, status codes, and counts separately.
pub fn error_type<T: ?Sized>(_: &T) -> &'static str {
    std::any::type_name::<T>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;

    struct SensitiveError;

    impl fmt::Display for SensitiveError {
        fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
            panic!("logging must never invoke an error's Display implementation");
        }
    }

    impl fmt::Debug for SensitiveError {
        fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
            panic!("logging must never invoke an error's Debug implementation");
        }
    }

    impl std::error::Error for SensitiveError {}

    #[test]
    fn error_metadata_never_formats_values_or_sources() {
        let error = anyhow::Error::new(SensitiveError)
            .context("https://dashboard.example/?token=STOLEN_TOKEN_SENTINEL");
        let provider_body = "access_token=PROVIDER_TOKEN_SENTINEL".to_string();

        let metadata = format!(
            "{} {:?} {:#}",
            error_type(&SensitiveError),
            error_type(&provider_body),
            error_type(&error),
        );

        assert!(metadata.contains("SensitiveError"));
        assert!(metadata.contains("alloc::string::String"));
        assert!(metadata.contains("anyhow::Error"));
        assert!(!metadata.contains("SENTINEL"));
        assert!(!metadata.contains("https://"));
    }
}
