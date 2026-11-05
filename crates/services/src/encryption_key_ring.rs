use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fmt;

/// An ordered set of database master keys; only the first key is used for writes.
#[derive(Clone)]
pub struct KeyRing {
    keys: Vec<(String, [u8; 32])>,
}

impl KeyRing {
    pub fn new(
        write_id: String,
        write_key: [u8; 32],
        previous_keys: Vec<(String, [u8; 32])>,
    ) -> Result<Self> {
        let mut keys = Vec::with_capacity(previous_keys.len() + 1);
        keys.push((write_id, write_key));
        keys.extend(previous_keys);
        let mut seen = HashSet::with_capacity(keys.len());
        for (id, _) in &keys {
            validate_key_id(id)?;
            ensure!(seen.insert(id), "duplicate database encryption key id");
        }
        Ok(Self { keys })
    }

    pub fn write_id(&self) -> &str {
        &self.keys[0].0
    }

    pub fn ids(&self) -> Vec<&str> {
        self.keys.iter().map(|(id, _)| id.as_str()).collect()
    }

    pub fn lookup(&self, id: &str) -> Option<&[u8; 32]> {
        self.keys
            .iter()
            .find(|(key_id, _)| key_id == id)
            .map(|(_, key)| key)
    }

    pub fn fingerprints(&self) -> BTreeMap<String, String> {
        self.keys
            .iter()
            .map(|(id, key)| {
                (
                    id.clone(),
                    hex::encode(Sha256::digest(key))[..16].to_owned(),
                )
            })
            .collect()
    }

    pub fn keys(&self) -> impl Iterator<Item = (&str, &[u8; 32])> {
        self.keys.iter().map(|(id, key)| (id.as_str(), key))
    }
}

impl fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyRing").field("ids", &self.ids()).finish()
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_lookup_fingerprints_and_redaction() {
        let ring =
            KeyRing::new("new".into(), [0x21; 32], vec![("old".into(), [0x42; 32])]).unwrap();
        assert_eq!(ring.write_id(), "new");
        assert_eq!(ring.ids(), ["new", "old"]);
        assert_eq!(ring.lookup("old"), Some(&[0x42; 32]));
        assert!(ring.lookup("missing").is_none());
        assert_eq!(
            ring.fingerprints()["new"],
            &hex::encode(Sha256::digest([0x21; 32]))[..16]
        );
        assert!(!format!("{ring:?}").contains(&"21".repeat(32)));
        assert!(!format!("{ring:?}").contains("33, 33"));
    }

    #[test]
    fn rejects_duplicate_and_invalid_ids() {
        assert!(KeyRing::new("same".into(), [1; 32], vec![("same".into(), [2; 32])]).is_err());
        for id in ["", "has space", "unsafe:separator", &"x".repeat(65)] {
            assert!(KeyRing::new(id.into(), [1; 32], vec![]).is_err());
        }
    }
}
