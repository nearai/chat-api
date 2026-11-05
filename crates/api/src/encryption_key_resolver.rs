use anyhow::{anyhow, ensure, Result};
use async_trait::async_trait;
use config::encryption_keys::{parse_encryption_keys, KeySource};
use config::DatabaseEncryptionConfig;
use database::field_encryption::{parse_key, KeyRing};
use services::db_pool::FieldEncryptionConfig;

/// The dstack boundary is injectable so key-source tests never need a CVM.
#[async_trait]
pub trait DstackKeyFetcher: Send + Sync {
    async fn get_key(&self, path: &str) -> Result<Vec<u8>>;
}

pub struct DstackKeyClient;

#[async_trait]
impl DstackKeyFetcher for DstackKeyClient {
    async fn get_key(&self, path: &str) -> Result<Vec<u8>> {
        let client = dstack_sdk::dstack_client::DstackClient::new(None);
        let response = client
            .get_key(Some(path.to_owned()), None)
            .await
            .map_err(|_| anyhow!("database encryption dstack key fetch failed"))?;
        response
            .decode_key()
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
    let mut keys = if let Some(raw) = &config.keys {
        let sources = parse_encryption_keys(raw).map_err(|message| anyhow!(message))?;
        let mut keys = Vec::with_capacity(sources.len());
        for source in sources {
            let master = match source.source {
                KeySource::Hex(value) => parse_key(&value)
                    .map_err(|_| anyhow!("database encryption hex key is invalid"))?,
                KeySource::File(path) => {
                    let value = std::fs::read_to_string(path)
                        .map_err(|_| anyhow!("database encryption key file could not be read"))?;
                    parse_key(value.trim()).map_err(|_| {
                        anyhow!("database encryption key file must contain a 32-byte hex key")
                    })?
                }
                KeySource::Dstack(path) => fetcher
                    .get_key(&path)
                    .await
                    .map_err(|_| anyhow!("database encryption dstack key fetch failed"))?
                    .try_into()
                    .map_err(|_| anyhow!("database encryption dstack key must be 32 bytes"))?,
            };
            keys.push((source.key_id, master));
        }
        keys
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
    };
    ensure!(
        !keys.is_empty(),
        "database encryption key ring must not be empty"
    );
    let (key_id, key) = keys.remove(0);
    KeyRing::new(key_id.clone(), key, keys.clone())?;
    Ok(FieldEncryptionConfig {
        key,
        key_id,
        previous_keys: keys,
        write_enabled: config.write_enabled,
        agent_secrets_write_enabled: config.agent_secrets_write_enabled,
    })
}

#[cfg(test)]
#[path = "encryption_key_resolver_tests.rs"]
mod tests;
