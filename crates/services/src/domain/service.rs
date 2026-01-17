use async_trait::async_trait;
use chrono::{Duration, Utc};
use hickory_resolver::TokioResolver;
use std::sync::Arc;

use super::ports::{
    DomainRepository, DomainVerification, DomainVerificationService, VerificationInstructions,
    VerificationMethod, VerificationStatus,
};
use crate::types::{DomainVerificationId, OrganizationId};

pub struct DomainVerificationServiceImpl {
    repository: Arc<dyn DomainRepository>,
    verification_prefix: String,
}

impl DomainVerificationServiceImpl {
    pub fn new(repository: Arc<dyn DomainRepository>) -> Self {
        Self {
            repository,
            verification_prefix: "nearai-verify".to_string(),
        }
    }

    fn generate_token() -> String {
        use rand::Rng;
        let mut rng = rand::rng();
        let token: String = (0..32)
            .map(|_| {
                let idx = rng.random_range(0..36);
                if idx < 10 {
                    (b'0' + idx) as char
                } else {
                    (b'a' + idx - 10) as char
                }
            })
            .collect();
        token
    }

    fn get_dns_record_name(&self, domain: &str) -> String {
        format!("_{}={}.{}", self.verification_prefix, domain, domain)
    }

    async fn verify_dns_txt(&self, domain: &str, expected_token: &str) -> anyhow::Result<bool> {
        let resolver = TokioResolver::builder_tokio()?
            .build();

        let lookup_name = format!("_{}.{}", self.verification_prefix, domain);

        match resolver.txt_lookup(&lookup_name).await {
            Ok(response) => {
                for record in response.iter() {
                    let txt_data = record.to_string();
                    if txt_data.contains(expected_token) {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Err(e) => {
                tracing::debug!(
                    "DNS TXT lookup failed for {}: {}",
                    lookup_name,
                    e
                );
                Ok(false)
            }
        }
    }

    async fn verify_http_file(&self, domain: &str, expected_token: &str) -> anyhow::Result<bool> {
        let url = format!(
            "https://{}/.well-known/{}.txt",
            domain, self.verification_prefix
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        match client.get(&url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    let body = response.text().await?;
                    Ok(body.trim() == expected_token)
                } else {
                    Ok(false)
                }
            }
            Err(e) => {
                tracing::debug!("HTTP verification failed for {}: {}", url, e);
                Ok(false)
            }
        }
    }
}

#[async_trait]
impl DomainVerificationService for DomainVerificationServiceImpl {
    async fn initiate_verification(
        &self,
        organization_id: OrganizationId,
        domain: String,
        method: VerificationMethod,
    ) -> anyhow::Result<VerificationInstructions> {
        tracing::info!(
            "Initiating domain verification: org_id={}, domain={}, method={:?}",
            organization_id,
            domain,
            method
        );

        // Check if domain is already claimed
        if self.repository.is_domain_claimed(&domain).await? {
            return Err(anyhow::anyhow!(
                "Domain is already claimed by another organization"
            ));
        }

        // Check if there's already a pending verification
        if let Some(existing) = self
            .repository
            .get_domain_verification_by_domain(&domain)
            .await?
        {
            if existing.organization_id == organization_id
                && existing.status == VerificationStatus::Pending
            {
                // Return existing verification instructions
                return self.get_verification_instructions(existing.id).await;
            } else if existing.organization_id != organization_id {
                return Err(anyhow::anyhow!(
                    "Domain is already being verified by another organization"
                ));
            }
        }

        // Generate verification token
        let token = Self::generate_token();
        let expires_at = Utc::now() + Duration::days(7);

        // Create verification record
        let verification = self
            .repository
            .create_domain_verification(organization_id, domain.clone(), method, token.clone(), expires_at)
            .await?;

        let instructions = match method {
            VerificationMethod::DnsTxt => {
                format!(
                    "Add a TXT record to your DNS:\nName: _{}.{}\nValue: {}",
                    self.verification_prefix, domain, token
                )
            }
            VerificationMethod::HttpFile => {
                format!(
                    "Create a file at: https://{}/.well-known/{}.txt\nContents: {}",
                    domain, self.verification_prefix, token
                )
            }
        };

        tracing::info!(
            "Domain verification initiated: id={}, domain={}",
            verification.id,
            domain
        );

        Ok(VerificationInstructions {
            method,
            domain,
            token,
            instructions,
            expected_value: verification.verification_token,
            expires_at,
        })
    }

    async fn check_verification(
        &self,
        id: DomainVerificationId,
    ) -> anyhow::Result<DomainVerification> {
        tracing::info!("Checking domain verification: id={}", id);

        let mut verification = self
            .repository
            .get_domain_verification(id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Domain verification not found"))?;

        // Check if expired
        if verification.expires_at < Utc::now() {
            self.repository
                .update_verification_status(id, VerificationStatus::Expired)
                .await?;
            verification.status = VerificationStatus::Expired;
            return Ok(verification);
        }

        // Already verified
        if verification.status == VerificationStatus::Verified {
            return Ok(verification);
        }

        // Perform verification
        let is_verified = match verification.verification_method {
            VerificationMethod::DnsTxt => {
                self.verify_dns_txt(&verification.domain, &verification.verification_token)
                    .await?
            }
            VerificationMethod::HttpFile => {
                self.verify_http_file(&verification.domain, &verification.verification_token)
                    .await?
            }
        };

        if is_verified {
            self.repository
                .update_verification_status(id, VerificationStatus::Verified)
                .await?;
            verification.status = VerificationStatus::Verified;
            verification.verified_at = Some(Utc::now());

            tracing::info!(
                "Domain verified successfully: id={}, domain={}",
                id,
                verification.domain
            );
        } else {
            tracing::debug!(
                "Domain verification check failed: id={}, domain={}",
                id,
                verification.domain
            );
        }

        Ok(verification)
    }

    async fn get_organization_domains(
        &self,
        organization_id: OrganizationId,
    ) -> anyhow::Result<Vec<DomainVerification>> {
        tracing::info!(
            "Getting domains for organization: org_id={}",
            organization_id
        );

        self.repository.get_organization_domains(organization_id).await
    }

    async fn get_domain_verification(
        &self,
        id: DomainVerificationId,
    ) -> anyhow::Result<DomainVerification> {
        self.repository
            .get_domain_verification(id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Domain verification not found"))
    }

    async fn remove_domain(
        &self,
        organization_id: OrganizationId,
        id: DomainVerificationId,
    ) -> anyhow::Result<()> {
        tracing::warn!(
            "Removing domain verification: org_id={}, id={}",
            organization_id,
            id
        );

        // Verify ownership
        let verification = self.get_domain_verification(id).await?;
        if verification.organization_id != organization_id {
            return Err(anyhow::anyhow!("Domain does not belong to this organization"));
        }

        self.repository.delete_domain_verification(id).await?;

        tracing::info!("Domain removed: id={}", id);

        Ok(())
    }

    async fn get_verification_instructions(
        &self,
        id: DomainVerificationId,
    ) -> anyhow::Result<VerificationInstructions> {
        let verification = self.get_domain_verification(id).await?;

        let instructions = match verification.verification_method {
            VerificationMethod::DnsTxt => {
                format!(
                    "Add a TXT record to your DNS:\nName: _{}.{}\nValue: {}",
                    self.verification_prefix,
                    verification.domain,
                    verification.verification_token
                )
            }
            VerificationMethod::HttpFile => {
                format!(
                    "Create a file at: https://{}/.well-known/{}.txt\nContents: {}",
                    verification.domain,
                    self.verification_prefix,
                    verification.verification_token
                )
            }
        };

        Ok(VerificationInstructions {
            method: verification.verification_method,
            domain: verification.domain,
            token: verification.verification_token.clone(),
            instructions,
            expected_value: verification.verification_token,
            expires_at: verification.expires_at,
        })
    }
}
