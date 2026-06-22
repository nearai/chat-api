use http::header::{HeaderName, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use http::{HeaderValue, Method};
use tower_http::cors::{AllowOrigin, CorsLayer};

pub(super) fn create_cors_layer(cors_config: config::CorsConfig) -> CorsLayer {
    CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(
            move |origin: &HeaderValue, _request_parts: &http::request::Parts| {
                let Ok(origin_str) = origin.to_str() else {
                    return false;
                };
                is_origin_allowed(origin_str, &cors_config)
            },
        ))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            AUTHORIZATION,
            CONTENT_TYPE,
            ACCEPT,
            crate::middleware::request_id_header_name(),
            HeaderName::from_static("ngrok-skip-browser-warning"),
        ])
        .expose_headers([crate::middleware::request_id_header_name()])
        .allow_credentials(true)
}

fn is_origin_allowed(origin_str: &str, cors_config: &config::CorsConfig) -> bool {
    if cors_config.exact_matches.iter().any(|o| o == origin_str) {
        return true;
    }

    origin_str.starts_with("https://")
        && cors_config
            .wildcard_suffixes
            .iter()
            .any(|suffix| origin_str.ends_with(suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cors_config() -> config::CorsConfig {
        config::CorsConfig {
            exact_matches: vec![
                "https://example.com".to_string(),
                "http://test.com".to_string(),
                "http://localhost".to_string(),
                "http://localhost:3000".to_string(),
                "http://localhost:8080".to_string(),
                "http://127.0.0.1".to_string(),
                "http://127.0.0.1:3000".to_string(),
                "http://127.0.0.1:8080".to_string(),
            ],
            wildcard_suffixes: vec![".near.ai".to_string(), "-example.com".to_string()],
        }
    }

    #[test]
    fn test_exact_match_allowed() {
        let config = test_cors_config();
        assert!(is_origin_allowed("https://example.com", &config));
        assert!(is_origin_allowed("http://test.com", &config));
    }

    #[test]
    fn test_exact_match_denied() {
        let config = test_cors_config();
        assert!(!is_origin_allowed("https://evil.com", &config));
        assert!(!is_origin_allowed("http://example.com", &config));
    }

    #[test]
    fn test_localhost_allowed() {
        let config = test_cors_config();
        assert!(is_origin_allowed("http://localhost:3000", &config));
        assert!(is_origin_allowed("http://localhost:8080", &config));
        assert!(is_origin_allowed("http://localhost", &config));
    }

    #[test]
    fn test_localhost_subdomain_denied() {
        let config = test_cors_config();
        assert!(!is_origin_allowed("http://localhost.evil.com", &config));
        assert!(!is_origin_allowed(
            "http://localhost.evil.com:3000",
            &config
        ));
    }

    #[test]
    fn test_127_0_0_1_allowed() {
        let config = test_cors_config();
        assert!(is_origin_allowed("http://127.0.0.1:3000", &config));
        assert!(is_origin_allowed("http://127.0.0.1:8080", &config));
        assert!(is_origin_allowed("http://127.0.0.1", &config));
    }

    #[test]
    fn test_127_0_0_1_subdomain_denied() {
        let config = test_cors_config();
        assert!(!is_origin_allowed("http://127.0.0.1.evil.com", &config));
    }

    #[test]
    fn test_local_development_origins_denied_when_not_configured() {
        let config = config::CorsConfig {
            exact_matches: vec![],
            wildcard_suffixes: vec![],
        };

        assert!(!is_origin_allowed("http://localhost", &config));
        assert!(!is_origin_allowed("http://localhost:3000", &config));
        assert!(!is_origin_allowed("http://127.0.0.1", &config));
        assert!(!is_origin_allowed("http://127.0.0.1:3000", &config));
    }

    #[test]
    fn test_https_wildcard_allowed() {
        let config = test_cors_config();
        assert!(is_origin_allowed("https://app.near.ai", &config));
        assert!(is_origin_allowed("https://chat.near.ai", &config));
        assert!(is_origin_allowed("https://preview-example.com", &config));
    }

    #[test]
    fn test_https_wildcard_denied() {
        let config = test_cors_config();
        assert!(!is_origin_allowed("http://app.near.ai", &config));
        assert!(!is_origin_allowed("https://fakenear.ai", &config));
        assert!(!is_origin_allowed("https://near.ai.evil.com", &config));
    }

    #[test]
    fn test_wildcard_suffix_protection() {
        let config = config::CorsConfig {
            exact_matches: vec![],
            wildcard_suffixes: vec![".near.ai".to_string()],
        };
        assert!(is_origin_allowed("https://app.near.ai", &config));
        assert!(!is_origin_allowed("https://fakenear.ai", &config));
    }

    #[test]
    fn test_wildcard_with_hyphen_allowed() {
        let config = test_cors_config();
        assert!(is_origin_allowed("https://preview-example.com", &config));
        assert!(is_origin_allowed("https://staging-example.com", &config));
    }
}
