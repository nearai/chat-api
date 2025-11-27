pub const SYSTEM_PROMPT_MAX_LEN: usize = 64 * 1024;
pub const LIMIT_MAX: i64 = 100;

/// Allowed proxy paths that can be forwarded to OpenAI
pub const ALLOWED_PROXY_PATHS: &[&str] = &[
    "responses",
    "chat/completions",
    "models",
    "model/list",
    "files",
];
