use crate::pool::DbPool;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use services::{
    domain::ports::{
        DomainRepository, DomainVerification, VerificationMethod, VerificationStatus,
    },
    DomainVerificationId, OrganizationId,
};

pub struct PostgresDomainRepository {
    pool: DbPool,
}

impl PostgresDomainRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DomainRepository for PostgresDomainRepository {
    async fn get_domain_verification(
        &self,
        id: DomainVerificationId,
    ) -> anyhow::Result<Option<DomainVerification>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, organization_id, domain, verification_method, verification_token,
                        status, verified_at, created_at, updated_at, expires_at
                 FROM domain_verifications
                 WHERE id = $1",
                &[&id],
            )
            .await?;

        Ok(row.map(|r| DomainVerification {
            id: r.get(0),
            organization_id: r.get(1),
            domain: r.get(2),
            verification_method: VerificationMethod::from_str(r.get::<_, String>(3).as_str())
                .unwrap_or_default(),
            verification_token: r.get(4),
            status: VerificationStatus::from_str(r.get::<_, String>(5).as_str())
                .unwrap_or_default(),
            verified_at: r.get(6),
            created_at: r.get(7),
            updated_at: r.get(8),
            expires_at: r.get(9),
        }))
    }

    async fn get_domain_verification_by_domain(
        &self,
        domain: &str,
    ) -> anyhow::Result<Option<DomainVerification>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, organization_id, domain, verification_method, verification_token,
                        status, verified_at, created_at, updated_at, expires_at
                 FROM domain_verifications
                 WHERE domain = $1",
                &[&domain],
            )
            .await?;

        Ok(row.map(|r| DomainVerification {
            id: r.get(0),
            organization_id: r.get(1),
            domain: r.get(2),
            verification_method: VerificationMethod::from_str(r.get::<_, String>(3).as_str())
                .unwrap_or_default(),
            verification_token: r.get(4),
            status: VerificationStatus::from_str(r.get::<_, String>(5).as_str())
                .unwrap_or_default(),
            verified_at: r.get(6),
            created_at: r.get(7),
            updated_at: r.get(8),
            expires_at: r.get(9),
        }))
    }

    async fn get_organization_domains(
        &self,
        organization_id: OrganizationId,
    ) -> anyhow::Result<Vec<DomainVerification>> {
        let client = self.pool.get().await?;

        let rows = client
            .query(
                "SELECT id, organization_id, domain, verification_method, verification_token,
                        status, verified_at, created_at, updated_at, expires_at
                 FROM domain_verifications
                 WHERE organization_id = $1
                 ORDER BY created_at DESC",
                &[&organization_id],
            )
            .await?;

        Ok(rows
            .into_iter()
            .map(|r| DomainVerification {
                id: r.get(0),
                organization_id: r.get(1),
                domain: r.get(2),
                verification_method: VerificationMethod::from_str(r.get::<_, String>(3).as_str())
                    .unwrap_or_default(),
                verification_token: r.get(4),
                status: VerificationStatus::from_str(r.get::<_, String>(5).as_str())
                    .unwrap_or_default(),
                verified_at: r.get(6),
                created_at: r.get(7),
                updated_at: r.get(8),
                expires_at: r.get(9),
            })
            .collect())
    }

    async fn create_domain_verification(
        &self,
        organization_id: OrganizationId,
        domain: String,
        method: VerificationMethod,
        token: String,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<DomainVerification> {
        tracing::info!(
            "Repository: Creating domain verification for domain={}, organization_id={}",
            domain,
            organization_id
        );

        let client = self.pool.get().await?;

        let row = client
            .query_one(
                "INSERT INTO domain_verifications (organization_id, domain, verification_method,
                                                   verification_token, expires_at)
                 VALUES ($1, $2, $3, $4, $5)
                 RETURNING id, organization_id, domain, verification_method, verification_token,
                           status, verified_at, created_at, updated_at, expires_at",
                &[
                    &organization_id,
                    &domain,
                    &method.as_str(),
                    &token,
                    &expires_at,
                ],
            )
            .await?;

        Ok(DomainVerification {
            id: row.get(0),
            organization_id: row.get(1),
            domain: row.get(2),
            verification_method: VerificationMethod::from_str(row.get::<_, String>(3).as_str())
                .unwrap_or_default(),
            verification_token: row.get(4),
            status: VerificationStatus::from_str(row.get::<_, String>(5).as_str())
                .unwrap_or_default(),
            verified_at: row.get(6),
            created_at: row.get(7),
            updated_at: row.get(8),
            expires_at: row.get(9),
        })
    }

    async fn update_verification_status(
        &self,
        id: DomainVerificationId,
        status: VerificationStatus,
    ) -> anyhow::Result<()> {
        tracing::info!(
            "Repository: Updating domain verification status: id={}, status={:?}",
            id,
            status
        );

        let client = self.pool.get().await?;

        let verified_at = if status == VerificationStatus::Verified {
            Some(Utc::now())
        } else {
            None
        };

        client
            .execute(
                "UPDATE domain_verifications SET status = $2, verified_at = $3 WHERE id = $1",
                &[&id, &status.as_str(), &verified_at],
            )
            .await?;

        Ok(())
    }

    async fn delete_domain_verification(&self, id: DomainVerificationId) -> anyhow::Result<()> {
        tracing::warn!("Repository: Deleting domain verification: id={}", id);

        let client = self.pool.get().await?;

        client
            .execute("DELETE FROM domain_verifications WHERE id = $1", &[&id])
            .await?;

        Ok(())
    }

    async fn is_domain_claimed(&self, domain: &str) -> anyhow::Result<bool> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT 1 FROM domain_verifications WHERE domain = $1 AND status = 'verified'",
                &[&domain],
            )
            .await?;

        Ok(row.is_some())
    }
}
