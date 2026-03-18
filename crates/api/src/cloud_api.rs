/// Normalize Cloud API configuration so callers can accept either the API root
/// (e.g. `https://cloud-api.example.com`) or the OpenAI-compatible `/v1` base URL
/// (e.g. `https://cloud-api.example.com/v1`).
pub fn root_url(base_url: &str) -> String {
    let trimmed = base_url.trim_end_matches('/');
    trimmed.strip_suffix("/v1").unwrap_or(trimmed).to_string()
}

pub fn mcp_url(base_url: &str) -> String {
    format!("{}/mcp", root_url(base_url))
}

pub fn web_search_service_url(base_url: &str) -> String {
    format!("{}/v1/services/web_search", root_url(base_url))
}

#[cfg(test)]
mod tests {
    use super::{mcp_url, root_url, web_search_service_url};

    #[test]
    fn normalizes_root_without_suffix() {
        assert_eq!(
            root_url("https://api.example.com"),
            "https://api.example.com"
        );
        assert_eq!(
            mcp_url("https://api.example.com"),
            "https://api.example.com/mcp"
        );
        assert_eq!(
            web_search_service_url("https://api.example.com"),
            "https://api.example.com/v1/services/web_search"
        );
    }

    #[test]
    fn normalizes_root_with_v1_suffix_and_trailing_slash() {
        assert_eq!(
            root_url("https://api.example.com/v1/"),
            "https://api.example.com"
        );
        assert_eq!(
            mcp_url("https://api.example.com/v1/"),
            "https://api.example.com/mcp"
        );
        assert_eq!(
            web_search_service_url("https://api.example.com/v1/"),
            "https://api.example.com/v1/services/web_search"
        );
    }
}
