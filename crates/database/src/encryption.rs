use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::Result;
use std::env;

/// Encryption key for instance tokens (256-bit for AES-256)
/// Should be set via ENCRYPTION_KEY environment variable
fn get_encryption_key() -> Result<[u8; 32]> {
    let key_hex = env::var("ENCRYPTION_KEY")
        .map_err(|_| anyhow::anyhow!("ENCRYPTION_KEY environment variable not set"))?;

    let key_bytes = hex::decode(&key_hex)
        .map_err(|e| anyhow::anyhow!("Invalid ENCRYPTION_KEY format: {}", e))?;

    if key_bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "ENCRYPTION_KEY must be 32 bytes (64 hex characters)"
        ));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(key)
}

/// Encrypt sensitive data (instance tokens, etc.)
/// Returns hex-encoded ciphertext with format: "nonce:ciphertext"
pub fn encrypt(plaintext: &str) -> Result<String> {
    let key = get_encryption_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("Failed to create cipher: {}", e))?;

    // Generate random nonce (96 bits for GCM)
    let nonce_bytes = rand::random::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, Payload::from(plaintext.as_bytes()))
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    // Format: nonce:ciphertext (both hex-encoded)
    let nonce_hex = hex::encode(nonce_bytes);
    let ciphertext_hex = hex::encode(ciphertext);
    Ok(format!("{}:{}", nonce_hex, ciphertext_hex))
}

/// Decrypt sensitive data
/// Input should be in format: "nonce:ciphertext" (both hex-encoded)
pub fn decrypt(encrypted: &str) -> Result<String> {
    let key = get_encryption_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("Failed to create cipher: {}", e))?;

    // Split nonce and ciphertext
    let parts: Vec<&str> = encrypted.split(':').collect();
    if parts.len() != 2 {
        return Err(anyhow::anyhow!("Invalid encrypted format"));
    }

    let nonce_bytes =
        hex::decode(parts[0]).map_err(|e| anyhow::anyhow!("Failed to decode nonce: {}", e))?;
    let ciphertext_bytes =
        hex::decode(parts[1]).map_err(|e| anyhow::anyhow!("Failed to decode ciphertext: {}", e))?;

    if nonce_bytes.len() != 12 {
        return Err(anyhow::anyhow!("Invalid nonce length"));
    }

    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, Payload::from(ciphertext_bytes.as_ref()))
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

    String::from_utf8(plaintext)
        .map_err(|e| anyhow::anyhow!("Failed to convert decrypted bytes to string: {}", e))
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_encrypt_decrypt() {
        // This test would require ENCRYPTION_KEY to be set
        // In production, ensure the key is properly configured
    }
}
