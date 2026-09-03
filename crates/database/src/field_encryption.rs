use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use uuid::Uuid;

pub const MARKER: &str = "__near_db_encrypted";
pub const DEFAULT_KEY_ID: &str = "db-v1";

pub fn parse_key(hex_key: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_key).context("database encryption key must be hex encoded")?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| anyhow!("database encryption key must be 32 bytes, got {len}"))
}

pub fn validate_key_id(key_id: &str) -> Result<()> {
    ensure!(
        !key_id.is_empty()
            && key_id.len() <= 64
            && key_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
        "database encryption key id must be 1-64 safe ASCII characters"
    );
    Ok(())
}

pub fn is_envelope(value: &Value) -> bool {
    value[MARKER] == true
        && value["version"] == 1
        && value["alg"] == "AES-256-GCM"
        && value["key_id"].as_str().is_some()
        && value["nonce"].as_str().is_some()
        && value["ciphertext"].as_str().is_some()
}

pub fn encrypt(
    key: &[u8; 32],
    key_id: &str,
    table: &str,
    column: &str,
    row_id: Uuid,
    plaintext: &str,
) -> Result<String> {
    validate_key_id(key_id)?;
    let mut nonce = [0; 12];
    OsRng.fill_bytes(&mut nonce);
    let aad = format!("{table}:{column}:{row_id}");
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| anyhow!("invalid key"))?;
    let ciphertext = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plaintext.as_bytes(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| anyhow!("encryption failed"))?;
    Ok(json!({
        MARKER: true,
        "version": 1,
        "alg": "AES-256-GCM",
        "key_id": key_id,
        "nonce": BASE64.encode(nonce),
        "ciphertext": BASE64.encode(ciphertext),
    })
    .to_string())
}

pub fn decrypt(
    key: &[u8; 32],
    expected_key_id: &str,
    table: &str,
    column: &str,
    row_id: Uuid,
    encoded: &str,
) -> Result<String> {
    validate_key_id(expected_key_id)?;
    let value: Value = serde_json::from_str(encoded)?;
    ensure!(is_envelope(&value), "invalid encrypted envelope");
    ensure!(
        value["key_id"] == expected_key_id,
        "unsupported encryption key id"
    );
    let nonce: [u8; 12] = BASE64
        .decode(
            value["nonce"]
                .as_str()
                .ok_or_else(|| anyhow!("missing nonce"))?,
        )?
        .try_into()
        .map_err(|_| anyhow!("invalid nonce length"))?;
    let ciphertext = BASE64.decode(
        value["ciphertext"]
            .as_str()
            .ok_or_else(|| anyhow!("missing ciphertext"))?,
    )?;
    let aad = format!("{table}:{column}:{row_id}");
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| anyhow!("invalid key"))?;
    let plaintext = cipher
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &ciphertext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| anyhow!("envelope authentication failed"))?;
    Ok(String::from_utf8(plaintext)?)
}

pub fn decrypt_if_encrypted(
    key: &[u8; 32],
    key_id: &str,
    table: &str,
    column: &str,
    row_id: Uuid,
    value: String,
) -> Result<String> {
    match serde_json::from_str::<Value>(&value) {
        Ok(envelope) if is_envelope(&envelope) => {
            decrypt(key, key_id, table, column, row_id, &value)
        }
        _ => Ok(value),
    }
}

pub fn search_token(key: &[u8; 32], domain: &str, value: &str) -> Result<Vec<u8>> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .map_err(|_| anyhow!("invalid search-token key"))?;
    mac.update(b"near-chat-db-search-v1\0");
    mac.update(domain.as_bytes());
    mac.update(b"\0");
    mac.update(value.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut key = [0; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    #[test]
    fn envelope_round_trips_and_authenticates_context() {
        let key = test_key();
        let id = Uuid::new_v4();
        let encoded = encrypt(&key, "test-v1", "files", "filename", id, "private.txt").unwrap();
        assert!(!encoded.contains("private.txt"));
        assert_eq!(
            decrypt(&key, "test-v1", "files", "filename", id, &encoded).unwrap(),
            "private.txt"
        );
        assert!(decrypt(
            &key,
            "test-v1",
            "files",
            "filename",
            Uuid::new_v4(),
            &encoded
        )
        .is_err());
        assert!(decrypt(&key, "other", "files", "filename", id, &encoded).is_err());
    }

    #[test]
    fn plaintext_and_marker_shaped_user_data_remain_readable() {
        let key = test_key();
        let id = Uuid::new_v4();
        for value in ["legacy", r#"{"__near_db_encrypted":true,"user":"value"}"#] {
            assert_eq!(
                decrypt_if_encrypted(&key, "test-v1", "files", "filename", id, value.into())
                    .unwrap(),
                value
            );
        }
    }

    #[test]
    fn search_tokens_are_stable_and_domain_separated() {
        let key = test_key();
        let a = search_token(&key, "files.provider_id", "file-1").unwrap();
        assert_eq!(
            a,
            search_token(&key, "files.provider_id", "file-1").unwrap()
        );
        assert_ne!(
            a,
            search_token(&key, "conversations.provider_id", "file-1").unwrap()
        );
        assert_ne!(
            a,
            search_token(&key, "files.provider_id", "file-2").unwrap()
        );
    }
}
