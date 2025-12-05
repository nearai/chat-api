// User metrics
pub const METRIC_USER_SIGNUP: &str = "chat_api.user.signup";
pub const METRIC_USER_LOGIN: &str = "chat_api.user.login";

// Activity metrics
pub const METRIC_RESPONSE_CREATED: &str = "chat_api.response.created";
pub const METRIC_CONVERSATION_CREATED: &str = "chat_api.conversation.created";
pub const METRIC_FILE_UPLOADED: &str = "chat_api.file.uploaded";

// HTTP metrics
pub const METRIC_HTTP_REQUESTS: &str = "chat_api.http.requests";
pub const METRIC_HTTP_DURATION: &str = "chat_api.http.duration";

// Tags
pub const TAG_AUTH_METHOD: &str = "auth_method";
pub const TAG_IS_NEW_USER: &str = "is_new_user";
pub const TAG_ENVIRONMENT: &str = "environment";
pub const TAG_STATUS_CODE: &str = "status_code";
pub const TAG_ENDPOINT: &str = "endpoint";
pub const TAG_METHOD: &str = "method";

/// Get environment from ENV or default to "development"
pub fn get_environment() -> &'static str {
    static ENVIRONMENT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ENVIRONMENT
        .get_or_init(|| std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string()))
}
