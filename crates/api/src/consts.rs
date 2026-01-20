pub const SYSTEM_PROMPT_MAX_LEN: usize = 64 * 1024;
pub const LIST_USERS_LIMIT_MAX: i64 = 100;
pub const LIST_FILES_LIMIT_MAX: i64 = 10_000;

/// Maximum size for request body (50 MB)
/// Prevents DoS attacks from unbounded memory allocation
/// Large enough for file uploads and large conversation payloads
pub const MAX_REQUEST_BODY_SIZE: usize = 50 * 1024 * 1024;

/// Maximum size for response body (50 MB)
/// Prevents DoS attacks from malicious upstream services
/// Large enough for conversation lists and file downloads
pub const MAX_RESPONSE_BODY_SIZE: usize = 50 * 1024 * 1024;

/// Idle timeout for user rate limit state cleanup (1 hour)
pub const USER_STATE_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3600);
