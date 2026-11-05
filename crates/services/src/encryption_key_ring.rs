use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// An ordered set of database master keys; only the first key is used for writes.
#[derive(Clone)]
pub struct KeyRing {
    keys: Zeroizing<Vec<(String, [u8; 32])>>,
}

impl KeyRing {
    pub fn new(
        write_id: String,
        mut write_key: [u8; 32],
        previous_keys: Vec<(String, [u8; 32])>,
    ) -> Result<Self> {
        let previous_keys = Zeroizing::new(previous_keys);
        let mut keys = Zeroizing::new(Vec::with_capacity(previous_keys.len() + 1));
        keys.push((write_id, write_key));
        write_key.zeroize();
        keys.extend(previous_keys.iter().cloned());
        let mut seen = HashSet::with_capacity(keys.len());
        for (index, (id, key)) in keys.iter().enumerate() {
            validate_key_id(id)?;
            ensure!(seen.insert(id), "duplicate database encryption key id");
            ensure!(
                keys[..index].iter().all(|(_, previous)| previous != key),
                "duplicate database encryption key bytes"
            );
        }
        Ok(Self { keys })
    }

    pub fn write_id(&self) -> &str {
        &self.keys[0].0
    }

    pub fn write_key(&self) -> &[u8; 32] {
        &self.keys[0].1
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
        let current_key = crate::random_key();
        let previous_key = crate::random_key();
        let ring = KeyRing::new(
            "new".into(),
            current_key,
            vec![("old".into(), previous_key)],
        )
        .unwrap();
        assert_eq!(ring.write_id(), "new");
        assert_eq!(ring.ids(), ["new", "old"]);
        assert_eq!(ring.lookup("old"), Some(&previous_key));
        assert!(ring.lookup("missing").is_none());
        assert_eq!(
            ring.fingerprints()["new"],
            &hex::encode(Sha256::digest(current_key))[..16]
        );
        assert!(!format!("{ring:?}").contains(&hex::encode(current_key)));
        assert!(!format!("{ring:?}").contains(&format!("{current_key:?}")));
    }

    #[test]
    fn rejects_identical_bytes_under_distinct_ids() {
        let key = crate::random_key();
        let result = KeyRing::new("new".into(), key, vec![("old".into(), key)]);
        assert!(result.is_err(), "identical key bytes must not have two ids");
        assert!(result.unwrap_err().to_string().contains("key bytes"));
        let result = KeyRing::new(
            "new".into(),
            crate::random_key(),
            vec![("old".into(), key), ("oldest".into(), key)],
        );
        assert!(
            result.is_err(),
            "previous keys must also have distinct bytes"
        );
    }

    #[test]
    fn rejects_duplicate_and_invalid_ids() {
        assert!(KeyRing::new(
            "same".into(),
            crate::random_key(),
            vec![("same".into(), crate::random_key())]
        )
        .is_err());
        for id in ["", "has space", "unsafe:separator", &"x".repeat(65)] {
            assert!(KeyRing::new(id.into(), crate::random_key(), vec![]).is_err());
        }
    }
}
