use super::ports::VpcInfo;
use crate::logging::error_type;

/// Load VPC (Virtual Private Cloud) information from environment variables
pub fn load_vpc_info() -> Option<VpcInfo> {
    // Read VPC server app ID from environment
    let vpc_server_app_id = std::env::var("VPC_SERVER_APP_ID").ok();

    // Read VPC hostname from file
    let vpc_hostname = if let Ok(path) = std::env::var("VPC_HOSTNAME_FILE") {
        std::fs::read_to_string(path)
            .map_err(|e| {
                tracing::warn!(
                    error_type = error_type(&e),
                    "Failed to read VPC hostname file"
                )
            })
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    } else {
        None
    };

    // Only return Some if at least one field is present
    if vpc_server_app_id.is_some() || vpc_hostname.is_some() {
        Some(VpcInfo {
            vpc_server_app_id,
            vpc_hostname,
        })
    } else {
        None
    }
}
