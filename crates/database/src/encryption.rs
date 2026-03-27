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

/// Encrypt sensitive data using an explicit key.
/// Returns hex-encoded ciphertext with format: "nonce:ciphertext"
pub fn encrypt_with_key(key: &[u8; 32], plaintext: &str) -> Result<String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("Failed to create cipher: {}", e))?;

    let nonce_bytes = rand::random::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, Payload::from(plaintext.as_bytes()))
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    let nonce_hex = hex::encode(nonce_bytes);
    let ciphertext_hex = hex::encode(ciphertext);
    Ok(format!("{}:{}", nonce_hex, ciphertext_hex))
}

/// Decrypt sensitive data using an explicit key.
/// Input should be in format: "nonce:ciphertext" (both hex-encoded)
pub fn decrypt_with_key(key: &[u8; 32], encrypted: &str) -> Result<String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("Failed to create cipher: {}", e))?;

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

/// Encrypt sensitive data (instance tokens, etc.)
/// Returns hex-encoded ciphertext with format: "nonce:ciphertext"
pub fn encrypt(plaintext: &str) -> Result<String> {
    let key = get_encryption_key()?;
    encrypt_with_key(&key, plaintext)
}

/// Decrypt sensitive data
/// Input should be in format: "nonce:ciphertext" (both hex-encoded)
pub fn decrypt(encrypted: &str) -> Result<String> {
    let key = get_encryption_key()?;
    decrypt_with_key(&key, encrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(b"0123456789abcdef");
        key[16..].copy_from_slice(b"fedcba9876543210");
        key
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = "my-secret-instance-token-12345";
        let encrypted = encrypt_with_key(&key, plaintext).unwrap();
        let decrypted = decrypt_with_key(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_produces_different_ciphertexts() {
        let key = test_key();
        let plaintext = "same-plaintext";
        let encrypted1 = encrypt_with_key(&key, plaintext).unwrap();
        let encrypted2 = encrypt_with_key(&key, plaintext).unwrap();
        assert_ne!(encrypted1, encrypted2);
        assert_eq!(decrypt_with_key(&key, &encrypted1).unwrap(), plaintext);
        assert_eq!(decrypt_with_key(&key, &encrypted2).unwrap(), plaintext);
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let key = test_key();
        let mut wrong_key = [0u8; 32];
        wrong_key[0] = 0xFF;
        let encrypted = encrypt_with_key(&key, "secret").unwrap();
        assert!(decrypt_with_key(&wrong_key, &encrypted).is_err());
    }

    #[test]
    fn test_decrypt_invalid_format_fails() {
        let key = test_key();
        assert!(decrypt_with_key(&key, "not-valid-format").is_err());
        assert!(decrypt_with_key(&key, "aabbcc:").is_err());
        assert!(decrypt_with_key(&key, ":aabbcc").is_err());
    }
}
