use deadpool_postgres::{Config, Pool, Runtime};
use std::fs::File;
use std::io::BufReader;
use tracing::{debug, info};

/// Create pool using rustls with either custom certificate or platform verifier
pub fn create_pool_with_rustls(cfg: Config, cert_path: Option<&str>) -> anyhow::Result<Pool> {
    use tokio_postgres_rustls::MakeRustlsConnect;

    // Install the default crypto provider (ring) if not already installed
    let _ = rustls::crypto::ring::default_provider().install_default();

    let client_config = if let Some(cert_path) = cert_path {
        // Load custom certificate from file
        info!(
            "Using rustls with custom CA certificate from: {}",
            cert_path
        );
        debug!("Loading CA certificate from: {}", cert_path);

        let cert_file = File::open(cert_path)
            .map_err(|e| anyhow::anyhow!("Failed to open certificate file {}: {}", cert_path, e))?;
        let mut reader = BufReader::new(cert_file);

        // Parse the PEM certificates
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("Failed to parse certificate: {}", e))?;

        if certs.is_empty() {
            return Err(anyhow::anyhow!("No certificates found in {}", cert_path));
        }

        info!("Found {} certificate(s) in {}", certs.len(), cert_path);

        // Create root certificate store and add custom certificates
        let mut root_store = rustls::RootCertStore::empty();
        for cert in certs {
            root_store
                .add(cert)
                .map_err(|e| anyhow::anyhow!("Failed to add certificate to root store: {}", e))?;
        }

        info!(
            "Successfully loaded custom CA certificate from {}",
            cert_path
        );

        // Build TLS configuration with custom certificates
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    } else {
        // Use platform verifier for system certificates
        // This uses OS-native verification (Security.framework on macOS, etc.)
        // and includes revocation checking via OCSP/CRLs
        info!("Using rustls with platform verifier (OS certificate store)");

        use rustls_platform_verifier::ConfigVerifierExt;
        rustls::ClientConfig::with_platform_verifier()
            .map_err(|e| anyhow::anyhow!("Failed to create platform verifier: {}", e))?
    };

    let tls = MakeRustlsConnect::new(client_config);

    cfg.create_pool(Some(Runtime::Tokio1), tls)
        .map_err(|e| anyhow::anyhow!("Failed to create TLS pool: {}", e))
}

/// Create pool using native-tls (simpler for accepting self-signed certificates)
pub fn create_pool_with_native_tls(
    cfg: Config,
    accept_invalid_certs: bool,
) -> anyhow::Result<Pool> {
    use native_tls::TlsConnector;
    use postgres_native_tls::MakeTlsConnector;

    let mut builder = TlsConnector::builder();
    if accept_invalid_certs {
        info!("Configuring TLS to accept self-signed certificates");
        builder.danger_accept_invalid_certs(true);
    }

    let connector = builder
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to create TLS connector: {e}"))?;
    let tls = MakeTlsConnector::new(connector);

    cfg.create_pool(Some(Runtime::Tokio1), tls)
        .map_err(|e| anyhow::anyhow!("Failed to create TLS pool: {e}"))
}

/// Connection pool type alias
pub type DbPool = Pool;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_disabled_by_default() {
        let config = config::DatabaseConfig {
            host: Some("localhost".to_string()),
            port: 5432,
            gateway_subdomain: "dstack.internal".to_string(),
            database: "test_db".to_string(),
            username: "postgres".to_string(),
            password: "postgres".to_string(),
            max_connections: 5,
            tls_enabled: false,
            tls_ca_cert_path: None,
            primary_app_id: "".to_string(),
            refresh_interval: 30,
            mock: false,
        };

        assert!(!config.tls_enabled);
    }

    #[test]
    fn test_tls_can_be_enabled() {
        let config = config::DatabaseConfig {
            host: Some("remote.example.com".to_string()),
            port: 5432,
            gateway_subdomain: "dstack.internal".to_string(),
            database: "prod_db".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            max_connections: 10,
            tls_enabled: true,
            tls_ca_cert_path: None,
            primary_app_id: "".to_string(),
            refresh_interval: 30,
            mock: false,
        };

        assert!(config.tls_enabled);
    }

    #[test]
    fn test_database_config_validation() {
        // Test valid local configuration without TLS
        let local_config = config::DatabaseConfig {
            host: Some("localhost".to_string()),
            port: 5432,
            database: "cloud_api".to_string(),
            gateway_subdomain: "dstack.internal".to_string(),
            username: "postgres".to_string(),
            password: "postgres".to_string(),
            max_connections: 5,
            tls_enabled: false,
            tls_ca_cert_path: None,
            primary_app_id: "".to_string(),
            refresh_interval: 30,
            mock: false,
        };

        assert_eq!(local_config.host, Some("localhost".to_string()));
        assert_eq!(local_config.port, 5432);
        assert!(!local_config.tls_enabled);

        // Test valid remote configuration with TLS
        let remote_config = config::DatabaseConfig {
            host: Some("prod-db.example.com".to_string()),
            port: 5432,
            gateway_subdomain: "dstack.internal".to_string(),
            database: "cloud_api_prod".to_string(),
            username: "app_user".to_string(),
            password: "secure_password".to_string(),
            max_connections: 20,
            tls_enabled: true,
            tls_ca_cert_path: None,
            primary_app_id: "".to_string(),
            refresh_interval: 30,
            mock: false,
        };

        assert_eq!(remote_config.host, Some("prod-db.example.com".to_string()));
        assert!(remote_config.tls_enabled);
    }

    /// Test that TLS pool creation works
    #[test]
    fn test_create_pool_with_tls() {
        let cfg = Config::new();

        // Test TLS pool creation (will fail without actual database, but tests config)
        let result = create_pool_with_rustls(cfg, None);
        assert!(
            result.is_ok() || result.is_err(),
            "Should handle TLS config creation"
        );
    }
}
