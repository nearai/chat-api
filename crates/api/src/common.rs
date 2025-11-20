pub fn is_dev() -> bool {
    std::env::var("DEV")
        .ok()
        .and_then(|v| v.parse::<bool>().ok())
        .unwrap_or_default()
}
