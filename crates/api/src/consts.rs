pub const SYSTEM_PROMPT_MAX_LEN: usize = 64 * 1024;
pub const LIST_USERS_LIMIT_MAX: i64 = 100;
pub const LIST_FILES_LIMIT_MAX: i64 = 10_000;

/// Allowed proxy paths that can be forwarded to OpenAI
pub const ALLOWED_PROXY_PATHS: &[&str] = &[
    "responses",
    "chat/completions",
    "models",
    "model/list",
    "files",
    "signature",
];
