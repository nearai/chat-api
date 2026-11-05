use std::{collections::HashSet, fmt};
use zeroize::Zeroize;

#[derive(Clone, PartialEq, Eq)]
pub enum KeySource {
    File(String),
    Dstack(String),
    Hex(String),
}

impl Drop for KeySource {
    fn drop(&mut self) {
        if let Self::Hex(value) = self {
            value.zeroize();
        }
    }
}

impl fmt::Debug for KeySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::File(_) => "File([REDACTED])",
            Self::Dstack(_) => "Dstack([REDACTED])",
            Self::Hex(_) => "Hex([REDACTED])",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptionKeySource {
    pub key_id: String,
    pub source: KeySource,
}

/// Parse an ordered key ring without exposing source values in errors.
pub fn parse_encryption_keys(raw: &str) -> Result<Vec<EncryptionKeySource>, &'static str> {
    let mut seen = HashSet::new();
    raw.split(',')
        .map(|entry| {
            let (id, source) = entry
                .trim()
                .split_once('=')
                .ok_or("DB_ENCRYPTION_KEYS entries must have key_id=source")?;
            let id = id.trim();
            if id.is_empty()
                || id.len() > 64
                || !id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            {
                return Err("DB_ENCRYPTION_KEYS key id must be 1-64 safe ASCII characters");
            }
            if !seen.insert(id) {
                return Err("DB_ENCRYPTION_KEYS contains duplicate key ids");
            }
            let (kind, value) = source
                .trim()
                .split_once(':')
                .ok_or("DB_ENCRYPTION_KEYS source must use file:, dstack: or hex:")?;
            let value = value.trim();
            if value.is_empty() {
                return Err("DB_ENCRYPTION_KEYS source must not be empty");
            }
            let source = match kind {
                "file" => KeySource::File(value.into()),
                "dstack" => KeySource::Dstack(value.into()),
                "hex"
                    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
                {
                    KeySource::Hex(value.into())
                }
                "hex" => {
                    return Err("DB_ENCRYPTION_KEYS hex source must contain 64 hex characters")
                }
                _ => return Err("DB_ENCRYPTION_KEYS source must use file:, dstack: or hex:"),
            };
            Ok(EncryptionKeySource {
                key_id: id.into(),
                source,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ordered_sources_and_redacts_values() {
        let key = crate::random_key_hex();
        let raw = format!("new=hex:{key}, old=file:/keys/old, older=dstack:db/older");
        let keys = parse_encryption_keys(&raw).unwrap();
        assert_eq!(
            keys.iter()
                .map(|key| key.key_id.as_str())
                .collect::<Vec<_>>(),
            ["new", "old", "older"]
        );
        assert_eq!(keys[1].source, KeySource::File("/keys/old".into()));
        assert_eq!(keys[2].source, KeySource::Dstack("db/older".into()));
        assert!(!format!("{keys:?}").contains(&key));
    }

    #[test]
    fn rejects_malformed_and_duplicate_sources_without_echoing_them() {
        for raw in [
            "",
            "missing",
            "=file:/key",
            "bad id=file:/key",
            "id=file:",
            "id=dstack:",
            "id=hex:",
            "id=raw:secret",
            "id=hex:secret",
            "id=file:/key,",
            "id=file:/one,id=file:/two",
        ] {
            let error = parse_encryption_keys(raw).unwrap_err();
            assert!(!error.contains("secret"));
        }
        assert!(parse_encryption_keys(&format!("{}=file:/key", "x".repeat(65))).is_err());
        assert!(parse_encryption_keys(&format!("id=hex:{}", "gg".repeat(32))).is_err());
    }
}
