use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::{DomainVerificationId, OrganizationId};

/// Domain verification method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMethod {
    DnsTxt,
    HttpFile,
}

impl VerificationMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            VerificationMethod::DnsTxt => "dns_txt",
            VerificationMethod::HttpFile => "http_file",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "dns_txt" => Some(VerificationMethod::DnsTxt),
            "http_file" => Some(VerificationMethod::HttpFile),
            _ => None,
        }
    }
}

impl Default for VerificationMethod {
    fn default() -> Self {
        VerificationMethod::DnsTxt
    }
}

/// Domain verification status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerificationStatus {
    Pending,
    Verified,
    Failed,
    Expired,
}

impl VerificationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            VerificationStatus::Pending => "pending",
            VerificationStatus::Verified => "verified",
            VerificationStatus::Failed => "failed",
            VerificationStatus::Expired => "expired",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(VerificationStatus::Pending),
            "verified" => Some(VerificationStatus::Verified),
            "failed" => Some(VerificationStatus::Failed),
            "expired" => Some(VerificationStatus::Expired),
            _ => None,
        }
    }
}

impl Default for VerificationStatus {
    fn default() -> Self {
        VerificationStatus::Pending
    }
}

/// Represents a domain verification record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainVerification {
    pub id: DomainVerificationId,
    pub organization_id: OrganizationId,
    pub domain: String,
    pub verification_method: VerificationMethod,
    pub verification_token: String,
    pub status: VerificationStatus,
    pub verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Verification instructions for the user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationInstructions {
    pub method: VerificationMethod,
    pub domain: String,
    pub token: String,
    /// For DNS TXT: the TXT record to add
    /// For HTTP file: the URL where the file should be placed
    pub instructions: String,
    /// Expected value to find
    pub expected_value: String,
    /// Time until the verification token expires
    pub expires_at: DateTime<Utc>,
}

/// Repository trait for domain verification operations
#[async_trait]
pub trait DomainRepository: Send + Sync {
    /// Get domain verification by ID
    async fn get_domain_verification(
        &self,
        id: DomainVerificationId,
    ) -> anyhow::Result<Option<DomainVerification>>;

    /// Get domain verification by domain name
    async fn get_domain_verification_by_domain(
        &self,
        domain: &str,
    ) -> anyhow::Result<Option<DomainVerification>>;

    /// Get all domain verifications for an organization
    async fn get_organization_domains(
        &self,
        organization_id: OrganizationId,
    ) -> anyhow::Result<Vec<DomainVerification>>;

    /// Create a new domain verification
    async fn create_domain_verification(
        &self,
        organization_id: OrganizationId,
        domain: String,
        method: VerificationMethod,
        token: String,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<DomainVerification>;

    /// Update domain verification status
    async fn update_verification_status(
        &self,
        id: DomainVerificationId,
        status: VerificationStatus,
    ) -> anyhow::Result<()>;

    /// Delete domain verification
    async fn delete_domain_verification(&self, id: DomainVerificationId) -> anyhow::Result<()>;

    /// Check if domain is already verified by another organization
    async fn is_domain_claimed(&self, domain: &str) -> anyhow::Result<bool>;
}

/// Service trait for domain verification operations
#[async_trait]
pub trait DomainVerificationService: Send + Sync {
    /// Initiate domain verification
    async fn initiate_verification(
        &self,
        organization_id: OrganizationId,
        domain: String,
        method: VerificationMethod,
    ) -> anyhow::Result<VerificationInstructions>;

    /// Check verification status and update if verified
    async fn check_verification(
        &self,
        id: DomainVerificationId,
    ) -> anyhow::Result<DomainVerification>;

    /// Get all domains for an organization
    async fn get_organization_domains(
        &self,
        organization_id: OrganizationId,
    ) -> anyhow::Result<Vec<DomainVerification>>;

    /// Get domain verification by ID
    async fn get_domain_verification(
        &self,
        id: DomainVerificationId,
    ) -> anyhow::Result<DomainVerification>;

    /// Remove a domain verification
    async fn remove_domain(
        &self,
        organization_id: OrganizationId,
        id: DomainVerificationId,
    ) -> anyhow::Result<()>;

    /// Get verification instructions for a domain
    async fn get_verification_instructions(
        &self,
        id: DomainVerificationId,
    ) -> anyhow::Result<VerificationInstructions>;
}
