use serde::{Deserialize, Serialize};

/// VPC (Virtual Private Cloud) metadata included in attestation reports
/// This information is helpful to identify the VPC server and this VPC node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpcInfo {
    /// VPC server app ID
    pub vpc_server_app_id: Option<String>,
    /// VPC hostname of this node
    pub vpc_hostname: Option<String>,
}
