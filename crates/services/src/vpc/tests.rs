use super::ports::{VpcCredentialsRepository, VpcCredentialsService};
use super::service::{initialize_cloud_api_credentials, VpcCredentialsServiceImpl};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Default)]
struct Repository {
    values: RwLock<HashMap<String, String>>,
    reads: AtomicUsize,
    fail_reads: AtomicBool,
    fail_deletes: AtomicBool,
}

impl Repository {
    async fn seed(&self, organization: &str, key: &str) {
        let mut values = self.values.write().await;
        values.insert("vpc_organization_id".into(), organization.into());
        values.insert("vpc_api_key".into(), key.into());
    }
}

#[async_trait]
impl VpcCredentialsRepository for Repository {
    async fn get(&self, key: &str) -> anyhow::Result<Option<String>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        anyhow::ensure!(
            !self.fail_reads.load(Ordering::SeqCst),
            "sensitive repository detail"
        );

        Ok(self.values.read().await.get(key).cloned())
    }

    async fn set(&self, key: &str, value: &str) -> anyhow::Result<()> {
        self.values.write().await.insert(key.into(), value.into());
        Ok(())
    }

    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.fail_deletes.load(Ordering::SeqCst),
            "sensitive delete detail"
        );

        self.values.write().await.remove(key);
        Ok(())
    }
}

#[tokio::test]
async fn cache_first_without_vpc_preserves_identity_and_survives_restart() {
    let repository = Arc::new(Repository::default());
    repository.seed("existing-org", "cached-key").await;

    let service = initialize_cloud_api_credentials(repository.clone(), Some("fallback".into()))
        .await
        .unwrap();
    let reads_after_startup = repository.reads.load(Ordering::SeqCst);
    repository.fail_reads.store(true, Ordering::SeqCst);

    assert_eq!(service.get_api_key().await.unwrap(), "cached-key");
    assert_eq!(
        service
            .get_credentials()
            .await
            .unwrap()
            .unwrap()
            .organization_id,
        "existing-org"
    );
    assert_eq!(repository.reads.load(Ordering::SeqCst), reads_after_startup);

    repository.fail_reads.store(false, Ordering::SeqCst);
    let restarted = initialize_cloud_api_credentials(repository, None)
        .await
        .unwrap();

    assert_eq!(restarted.get_api_key().await.unwrap(), "cached-key");
}

#[tokio::test]
async fn empty_or_incomplete_cache_uses_static_without_persisting_it() {
    for pair in [None, Some(("", "cached")), Some(("org", " "))] {
        let repository = Arc::new(Repository::default());
        if let Some((org, key)) = pair {
            repository.seed(org, key).await;
        }
        let before = repository.values.read().await.clone();

        let service = initialize_cloud_api_credentials(repository.clone(), Some("fallback".into()))
            .await
            .unwrap();

        let reads_after_startup = repository.reads.load(Ordering::SeqCst);
        repository.fail_reads.store(true, Ordering::SeqCst);

        assert_eq!(service.get_api_key().await.unwrap(), "fallback");
        assert!(service.get_credentials().await.unwrap().is_none());
        assert_eq!(repository.reads.load(Ordering::SeqCst), reads_after_startup);
        assert_eq!(*repository.values.read().await, before);
    }
}

#[tokio::test]
async fn missing_credentials_fail_startup_without_vpc() {
    for key in [None, Some("".into()), Some(" \n".into())] {
        let result = initialize_cloud_api_credentials(Arc::new(Repository::default()), key).await;

        assert!(result.is_err());
    }
}

#[tokio::test]
async fn database_error_is_not_a_cache_miss_and_is_redacted() {
    let repository = Arc::new(Repository::default());
    repository.fail_reads.store(true, Ordering::SeqCst);

    let result = initialize_cloud_api_credentials(repository, Some("fallback".into())).await;
    let error = result.err().unwrap().to_string();

    assert_eq!(error, "Failed to load cached Cloud API credentials");
}

#[tokio::test]
async fn invalidation_without_vpc_clears_cache_and_uses_fallback() {
    let repository = Arc::new(Repository::default());
    repository.seed("org", "cached").await;
    let service = initialize_cloud_api_credentials(repository.clone(), Some("fallback".into()))
        .await
        .unwrap();

    service.revoke_credentials().await.unwrap();

    assert_eq!(service.get_api_key().await.unwrap(), "fallback");
    assert!(repository.values.read().await.is_empty());
    assert!(service.get_credentials().await.unwrap().is_none());
}

#[tokio::test]
async fn failed_invalidation_reports_failure_without_leaking_repository_details() {
    let repository = Arc::new(Repository::default());
    repository.seed("org", "cached").await;
    let service = initialize_cloud_api_credentials(repository.clone(), Some("fallback".into()))
        .await
        .unwrap();
    repository.fail_deletes.store(true, Ordering::SeqCst);

    let error = service.revoke_credentials().await.unwrap_err();

    assert_eq!(error.to_string(), "Failed to delete cached Cloud API key");
}

#[tokio::test]
async fn simultaneous_cold_requests_load_persisted_credentials_once() {
    let repository = Arc::new(Repository::default());
    repository.seed("org", "cached").await;
    let service = Arc::new(VpcCredentialsServiceImpl::new(repository.clone(), None));
    let mut requests = Vec::new();

    for _ in 0..16 {
        let service = service.clone();
        requests.push(tokio::spawn(
            async move { service.get_api_key().await.unwrap() },
        ));
    }

    for request in requests {
        assert_eq!(request.await.unwrap(), "cached");
    }
    // Legacy refresh-token lookup plus the organization/key pair.
    assert_eq!(repository.reads.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn a_partial_persisted_pair_does_not_invent_an_organization() {
    for missing in ["vpc_api_key", "vpc_organization_id"] {
        let repository = Arc::new(Repository::default());
        repository.seed("org", "cached").await;
        repository.values.write().await.remove(missing);

        let service = initialize_cloud_api_credentials(repository, Some("fallback".into()))
            .await
            .unwrap();

        assert_eq!(service.get_api_key().await.unwrap(), "fallback");
        assert!(service.get_credentials().await.unwrap().is_none());
    }
}

#[tokio::test]
async fn peer_process_rechecks_persistence_after_restart() {
    let repository = Arc::new(Repository::default());
    repository.seed("org", "cached").await;
    let api = initialize_cloud_api_credentials(repository.clone(), Some("fallback".into()))
        .await
        .unwrap();
    let worker = initialize_cloud_api_credentials(repository.clone(), Some("fallback".into()))
        .await
        .unwrap();

    api.revoke_credentials().await.unwrap();

    assert_eq!(api.get_api_key().await.unwrap(), "fallback");
    assert_eq!(worker.get_api_key().await.unwrap(), "cached");

    let restarted_worker = initialize_cloud_api_credentials(repository, Some("fallback".into()))
        .await
        .unwrap();

    assert_eq!(restarted_worker.get_api_key().await.unwrap(), "fallback");
}
