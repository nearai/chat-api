use anyhow::{anyhow, ensure, Result};
use async_trait::async_trait;
use config::encryption_keys::{parse_encryption_keys, KeySource};
use config::DatabaseEncryptionConfig;
use database::field_encryption::{parse_key, KeyRing};
use services::db_pool::FieldEncryptionConfig;
use zeroize::Zeroizing;

/// The dstack boundary is injectable so key-source tests never need a CVM.
#[async_trait]
pub trait DstackKeyFetcher: Send + Sync {
    async fn get_key(&self, path: &str) -> Result<Vec<u8>>;
}

pub struct DstackKeyClient;

#[async_trait]
impl DstackKeyFetcher for DstackKeyClient {
    async fn get_key(&self, path: &str) -> Result<Vec<u8>> {
        // Match the existing attestation route: use the SDK's default endpoint selection.
        let client = dstack_sdk::dstack_client::DstackClient::new(None);
        let response = client
            .get_key(Some(path.to_owned()), None)
            .await
            .map_err(|_| anyhow!("database encryption dstack key fetch failed"))?;
        let encoded = Zeroizing::new(response.key);
        hex::decode(encoded.as_str())
            .map_err(|_| anyhow!("database encryption dstack key decoding failed"))
    }
}

pub async fn resolve_field_encryption(
    config: &DatabaseEncryptionConfig,
) -> Result<FieldEncryptionConfig> {
    resolve_field_encryption_with(config, &DstackKeyClient).await
}

pub async fn resolve_field_encryption_with(
    config: &DatabaseEncryptionConfig,
    fetcher: &dyn DstackKeyFetcher,
) -> Result<FieldEncryptionConfig> {
    let keys = Zeroizing::new(if let Some(raw) = &config.keys {
        let sources = parse_encryption_keys(raw).map_err(|message| anyhow!(message))?;
        let mut keys = Zeroizing::new(Vec::with_capacity(sources.len()));
        for source in &sources {
            let master =
                Zeroizing::new(match &source.source {
                    KeySource::Hex(value) => parse_key(value)
                        .map_err(|_| anyhow!("database encryption hex key is invalid"))?,
                    KeySource::File(path) => {
                        let file_error = |kind, message: &'static str| {
                            tracing::error!(
                                key_id = %source.key_id,
                                path = %path,
                                error_kind = ?kind,
                                "database encryption key file source failed"
                            );
                            anyhow!(message)
                        };
                        let value = Zeroizing::new(std::fs::read(path).map_err(|error| {
                            file_error(
                                error.kind(),
                                "database encryption key file could not be read",
                            )
                        })?);
                        let encoded = std::str::from_utf8(&value).map_err(|_| {
                            file_error(
                                std::io::ErrorKind::InvalidData,
                                "database encryption key file must contain a 32-byte hex key",
                            )
                        })?;
                        parse_key(encoded.trim()).map_err(|_| {
                            file_error(
                                std::io::ErrorKind::InvalidData,
                                "database encryption key file must contain a 32-byte hex key",
                            )
                        })?
                    }
                    KeySource::Dstack(path) => {
                        let bytes =
                            Zeroizing::new(fetcher.get_key(path).await.map_err(|_| {
                                anyhow!("database encryption dstack key fetch failed")
                            })?);
                        bytes.as_slice().try_into().map_err(|_| {
                            anyhow!("database encryption dstack key must be 32 bytes")
                        })?
                    }
                });
            keys.push((source.key_id.clone(), *master));
        }
        std::mem::take(&mut *keys)
    } else {
        ensure!(
            !config.key.is_empty(),
            "DB_ENCRYPTION_KEY or DB_ENCRYPTION_KEY_FILE is required"
        );
        vec![(
            config.key_id.clone(),
            parse_key(&config.key).map_err(|_| {
                anyhow!("database encryption key must contain 32 hex-encoded bytes")
            })?,
        )]
    });
    ensure!(
        !keys.is_empty(),
        "database encryption key ring must not be empty"
    );
    let key = Zeroizing::new(keys[0].1);
    let ring = KeyRing::new(keys[0].0.clone(), *key, keys[1..].to_vec())?;
    Ok(FieldEncryptionConfig {
        ring,
        write_enabled: config.write_enabled,
        agent_secrets_write_enabled: config.agent_secrets_write_enabled,
        app_config_write_enabled: config.app_config_write_enabled,
    })
}

#[cfg(test)]
#[path = "encryption_key_resolver_tests.rs"]
mod tests;
