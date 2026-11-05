use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use uuid::Uuid;

pub const MARKER: &str = "__near_db_encrypted";
pub const DEFAULT_KEY_ID: &str = "db-v1";
const AEAD_KEY_INFO: &[u8] = b"near-chat-db-aead-v1";
const SEARCH_KEY_INFO: &[u8] = b"near-chat-db-search-v1";

fn derive_key(master_key: &[u8; 32], info: &[u8]) -> Result<[u8; 32]> {
    let mut key = *master_key;
    Hkdf::<Sha256>::new(None, master_key)
        .expand(info, &mut key)
        .map_err(|_| anyhow!("database encryption key derivation failed"))?;
    Ok(key)
}

pub fn parse_key(hex_key: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_key).context("database encryption key must be hex encoded")?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| anyhow!("database encryption key must be 32 bytes, got {len}"))
}

pub use services::encryption_key_ring::{validate_key_id, KeyRing};

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
    let aead_key = derive_key(key, AEAD_KEY_INFO)?;
    let cipher = Aes256Gcm::new_from_slice(&aead_key).map_err(|_| anyhow!("invalid key"))?;
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
    let ring = KeyRing::new(expected_key_id.into(), *key, vec![])?;
    decrypt_with_ring(encoded, &ring, table, column, row_id)
}

pub fn decrypt_with_ring(
    encoded: &str,
    ring: &KeyRing,
    table: &str,
    column: &str,
    row_id: Uuid,
) -> Result<String> {
    let value: Value = serde_json::from_str(encoded)?;
    ensure!(is_envelope(&value), "invalid encrypted envelope");
    let key = envelope_key_id(&value)
        .and_then(|id| ring.lookup(id))
        .ok_or_else(|| anyhow!("unsupported encryption key id"))?;
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
    let aead_key = derive_key(key, AEAD_KEY_INFO)?;
    let cipher = Aes256Gcm::new_from_slice(&aead_key).map_err(|_| anyhow!("invalid key"))?;
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
    let ring = KeyRing::new(key_id.into(), *key, vec![])?;
    decrypt_if_encrypted_with_ring(value, &ring, table, column, row_id)
}

pub fn decrypt_if_encrypted_with_ring(
    value: String,
    ring: &KeyRing,
    table: &str,
    column: &str,
    row_id: Uuid,
) -> Result<String> {
    match serde_json::from_str::<Value>(&value) {
        Ok(envelope) if is_envelope(&envelope) => {
            decrypt_with_ring(&value, ring, table, column, row_id)
        }
        _ => Ok(value),
    }
}

pub fn envelope_key_id(value: &Value) -> Option<&str> {
    is_envelope(value)
        .then(|| value["key_id"].as_str())
        .flatten()
}

pub fn search_tokens_for_lookup(ring: &KeyRing, domain: &str, value: &str) -> Result<Vec<Vec<u8>>> {
    ring.keys()
        .map(|(_, key)| search_token_with_key(key, domain, value))
        .collect()
}

pub fn search_token(key: &[u8; 32], domain: &str, value: &str) -> Result<Vec<u8>> {
    search_token_with_key(key, domain, value)
}

pub fn search_token_with_key(key: &[u8; 32], domain: &str, value: &str) -> Result<Vec<u8>> {
    let search_key = derive_key(key, SEARCH_KEY_INFO)?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&search_key)
        .map_err(|_| anyhow!("invalid search-token key"))?;
    mac.update(b"near-chat-db-search-v1\0");
    mac.update(domain.as_bytes());
    mac.update(b"\0");
    mac.update(value.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(test)]
#[path = "field_encryption_tests.rs"]
mod tests;
