pub const SYSTEM_PROMPT_MAX_LEN: usize = 64 * 1024;
pub const LIST_USERS_LIMIT_MAX: i64 = 100;
pub const LIST_FILES_LIMIT_MAX: i64 = 10_000;

/// Idle timeout for user rate limit state cleanup (1 hour)
pub const USER_STATE_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3600);
