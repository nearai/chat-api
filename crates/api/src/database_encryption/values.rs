use super::*;
use database::field_encryption::KeyRing;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum StoredValue<'ring> {
    Current(String),
    Stale {
        plaintext: String,
        key_id: &'ring str,
    },
    LegacyEncrypted(String),
    Plaintext(String),
}

impl<'ring> StoredValue<'ring> {
    pub(super) fn key_id(&self, ring: &'ring KeyRing) -> Option<&'ring str> {
        match self {
            Self::Current(_) => Some(ring.write_id()),
            Self::Stale { key_id, .. } => Some(key_id),
            Self::LegacyEncrypted(_) | Self::Plaintext(_) => None,
        }
    }
}

/// Authenticate the envelope before using its declared key id for classification.
pub(super) fn read_value<'ring>(
    ring: &'ring KeyRing,
    field: &Field,
    id: Uuid,
    raw: &str,
) -> anyhow::Result<StoredValue<'ring>> {
    let parsed = serde_json::from_str::<Value>(raw).ok();
    let envelope = parsed.as_ref().filter(|value| match field.kind {
        Kind::AgentSecret => value.get(database::field_encryption::MARKER).is_some(),
        Kind::Text => database::field_encryption::is_envelope(value),
    });
    if let Some(envelope) = envelope {
        let plaintext = database::field_encryption::decrypt_parsed_with_ring(
            envelope,
            ring,
            field.table,
            field.column,
            id,
        )?;
        let key_id = ring
            .keys()
            .find_map(|(key_id, _)| {
                (Some(key_id) == database::field_encryption::envelope_key_id(envelope))
                    .then_some(key_id)
            })
            .ok_or_else(|| anyhow::anyhow!("unsupported encryption key id"))?;
        return Ok(if key_id == ring.write_id() {
            StoredValue::Current(plaintext)
        } else {
            StoredValue::Stale { plaintext, key_id }
        });
    }
    if matches!(field.kind, Kind::AgentSecret) && database::agent_secrets::is_legacy_ciphertext(raw)
    {
        return database::agent_secrets::decrypt_legacy(raw).map(StoredValue::LegacyEncrypted);
    }
    Ok(StoredValue::Plaintext(raw.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(kind: Kind) -> Field {
        Field {
            table: "files",
            column: "filename",
            id_column: "id",
            kind,
            reason: "test",
            token: None,
        }
    }

    fn ring(current_key: [u8; 32], previous_key: [u8; 32]) -> KeyRing {
        KeyRing::new(
            "current".into(),
            current_key,
            vec![("previous".into(), previous_key)],
        )
        .unwrap()
    }

    #[test]
    fn authenticated_values_are_current_stale_or_plaintext() {
        let current_key = crate::random_key();
        let previous_key = crate::random_key();
        let ring = ring(current_key, previous_key);
        let id = Uuid::new_v4();
        let field = field(Kind::Text);
        let current = database::field_encryption::encrypt(
            &current_key,
            "current",
            "files",
            "filename",
            id,
            "a",
        )
        .unwrap();
        let stale = database::field_encryption::encrypt(
            &previous_key,
            "previous",
            "files",
            "filename",
            id,
            "b",
        )
        .unwrap();
        assert_eq!(
            read_value(&ring, &field, id, &current).unwrap(),
            StoredValue::Current("a".into())
        );
        assert_eq!(
            read_value(&ring, &field, id, &stale).unwrap(),
            StoredValue::Stale {
                plaintext: "b".into(),
                key_id: "previous"
            }
        );
        assert_eq!(
            read_value(&ring, &field, id, "hello").unwrap(),
            StoredValue::Plaintext("hello".into())
        );
        for (raw, expected_id) in [
            (current.as_str(), Some("current")),
            (stale.as_str(), Some("previous")),
            ("hello", None),
        ] {
            assert_eq!(
                read_value(&ring, &field, id, raw).unwrap().key_id(&ring),
                expected_id
            );
        }
        assert!(read_value(&ring, &field, Uuid::new_v4(), &stale).is_err());
        let unknown = database::field_encryption::encrypt(
            &previous_key,
            "unknown",
            "files",
            "filename",
            id,
            "c",
        )
        .unwrap();
        assert!(read_value(&ring, &field, id, &unknown).is_err());
        let tampered = current.replace("\"key_id\":\"current\"", "\"key_id\":\"previous\"");
        assert!(read_value(&ring, &field, id, &tampered).is_err());
    }

    #[test]
    fn invalid_envelopes_never_contribute_per_key_counts() {
        let current_key = crate::random_key();
        let ring = ring(current_key, crate::random_key());
        let field = field(Kind::Text);
        let id = Uuid::new_v4();
        let valid = database::field_encryption::encrypt(
            &current_key,
            "current",
            "files",
            "filename",
            id,
            "secret",
        )
        .unwrap();
        let mut by_key_id = std::collections::BTreeMap::<String, i64>::new();
        let mut invalid = 0;
        for declared_id in ["current".to_owned(), "unknown".to_owned(), "x".repeat(4096)] {
            let mut forged: Value = serde_json::from_str(&valid).unwrap();
            forged["key_id"] = json!(declared_id);
            forged["ciphertext"] = json!("Zm9yZ2Vk");
            let raw = forged.to_string();
            match read_value(&ring, &field, id, &raw) {
                Ok(classified) => {
                    if let Some(key_id) = classified.key_id(&ring) {
                        *by_key_id.entry(key_id.to_owned()).or_default() += 1;
                    }
                }
                Err(_) => invalid += 1,
            }
        }
        assert_eq!(invalid, 3);
        assert!(
            by_key_id.is_empty(),
            "invalid envelopes polluted key counts: {by_key_id:?}"
        );
    }

    #[test]
    fn malformed_agent_envelopes_are_invalid() {
        let ring = ring(crate::random_key(), crate::random_key());
        let field = field(Kind::AgentSecret);
        for value in [
            r#"{"__near_db_encrypted":true}"#,
            r#"{"__near_db_encrypted":false}"#,
        ] {
            assert!(
                read_value(&ring, &field, Uuid::nil(), value).is_err(),
                "agent marker must not become plaintext"
            );
        }
    }
}
