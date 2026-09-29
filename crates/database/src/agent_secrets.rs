//! Transition agent credentials from the legacy app key to database field encryption.
//! Readers accept both formats; new writes need a separate, explicit rollout gate.

use crate::{encryption, field_encryption};
use anyhow::{anyhow, ensure, Result};
use serde_json::Value;
use services::db_pool::FieldEncryptionConfig;
use uuid::Uuid;

pub fn encrypt(
    config: Option<&FieldEncryptionConfig>,
    table: &str,
    column: &str,
    row_id: Uuid,
    plaintext: &str,
) -> Result<String> {
    if let Some(config) = config.filter(|config| config.agent_secrets_write_enabled) {
        ensure!(
            config.write_enabled,
            "DB_ENCRYPTION_WRITE_ENABLED must also be enabled"
        );
        field_encryption::encrypt(
            &config.key,
            &config.key_id,
            table,
            column,
            row_id,
            plaintext,
        )
    } else {
        encryption::encrypt(plaintext)
    }
}

/// Recognize the marker even in a damaged envelope, so it cannot be read or
/// backfilled as plaintext. Agent credentials do not contain JSON envelopes.
pub fn is_field_envelope(value: &str) -> bool {
    serde_json::from_str::<Value>(value)
        .is_ok_and(|value| value.get(field_encryption::MARKER).is_some())
}

pub fn decrypt(
    config: Option<&FieldEncryptionConfig>,
    table: &str,
    column: &str,
    row_id: Uuid,
    value: &str,
) -> Result<String> {
    if is_field_envelope(value) {
        let config =
            config.ok_or_else(|| anyhow!("database field encryption is not configured"))?;
        field_encryption::decrypt(&config.key, &config.key_id, table, column, row_id, value)
    } else {
        decrypt_legacy(value)
    }
}

/// The legacy encoding starts with a 12-byte, hex-encoded nonce. A colon alone
/// is not enough: historical plaintext credentials can contain colons too.
/// Once this prefix is recognized, even a damaged ciphertext must be decrypted
/// strictly instead of being treated as plaintext.
pub fn is_legacy_ciphertext(value: &str) -> bool {
    value.split_once(':').is_some_and(|(nonce, _)| {
        nonce.len() == 24 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

/// Read historical plaintext or the legacy `nonce:ciphertext` format.
/// Never fall back to plaintext when recognized ciphertext cannot be decrypted.
pub fn decrypt_legacy(value: &str) -> Result<String> {
    if is_legacy_ciphertext(value) {
        encryption::decrypt(value).map_err(|_| anyhow!("legacy agent secret decryption failed"))
    } else {
        Ok(value.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_credentials_require_the_correct_key_and_row_context() {
        let config = FieldEncryptionConfig {
            key: rand::random(),
            key_id: "test-v1".into(),
            write_enabled: true,
            agent_secrets_write_enabled: true,
        };
        let user_id = Uuid::new_v4();
        let ciphertext = encrypt(
            Some(&config),
            "user_passkey_credentials",
            "auth_secret",
            user_id,
            "secret",
        )
        .unwrap();
        assert_eq!(
            decrypt(
                Some(&config),
                "user_passkey_credentials",
                "auth_secret",
                user_id,
                &ciphertext
            )
            .unwrap(),
            "secret"
        );
        assert!(decrypt(
            Some(&config),
            "user_passkey_credentials",
            "backup_passphrase",
            user_id,
            &ciphertext
        )
        .is_err());
        assert!(decrypt(
            Some(&config),
            "user_passkey_credentials",
            "auth_secret",
            Uuid::new_v4(),
            &ciphertext
        )
        .is_err());
        assert!(decrypt(
            None,
            "user_passkey_credentials",
            "auth_secret",
            user_id,
            &ciphertext
        )
        .is_err());
        let wrong_key = FieldEncryptionConfig {
            key: rand::random(),
            ..config
        };
        assert!(decrypt(
            Some(&wrong_key),
            "user_passkey_credentials",
            "auth_secret",
            user_id,
            &ciphertext
        )
        .is_err());
    }

    #[test]
    fn plaintext_compatibility_does_not_hide_damaged_ciphertext() {
        let id = Uuid::new_v4();
        for plaintext in ["historical-token", "user:pass", "https://example.com/token"] {
            assert_eq!(
                decrypt(None, "agent_instances", "instance_token", id, plaintext).unwrap(),
                plaintext
            );
        }
        assert!(decrypt(
            None,
            "agent_instances",
            "instance_token",
            id,
            "0123456789abcdef01234567:bad-ciphertext"
        )
        .is_err());
        assert!(decrypt(
            None,
            "agent_instances",
            "instance_token",
            id,
            r#"{"__near_db_encrypted":1}"#
        )
        .is_err());
    }

    #[test]
    fn agent_gate_cannot_bypass_the_global_write_gate() {
        let config = FieldEncryptionConfig {
            key: rand::random(),
            key_id: "test-v1".into(),
            write_enabled: false,
            agent_secrets_write_enabled: true,
        };
        assert!(encrypt(
            Some(&config),
            "agent_instances",
            "instance_token",
            Uuid::new_v4(),
            "token"
        )
        .is_err());
    }
}
