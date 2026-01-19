use chrono::Duration;

pub const SYSTEM_PROMPT_MAX_LEN: usize = 64 * 1024;
pub const LIST_USERS_LIMIT_MAX: i64 = 100;
pub const LIST_FILES_LIMIT_MAX: i64 = 10_000;

pub const USER_STATE_IDLE_TIMEOUT: Duration = Duration::hours(1);
