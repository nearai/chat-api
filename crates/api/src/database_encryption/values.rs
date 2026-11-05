use super::*;
use database::field_encryption::KeyRing;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum StoredValue {
    Current(String),
    Stale(String),
    LegacyEncrypted(String),
    Plaintext(String),
}

/// Authenticate the envelope before using its declared key id for classification.
pub(super) fn read_value(
    ring: &KeyRing,
    field: &Field,
    id: Uuid,
    raw: &str,
) -> anyhow::Result<StoredValue> {
    let parsed = serde_json::from_str::<Value>(raw).ok();
    let is_envelope = match field.kind {
        Kind::AgentSecret => database::agent_secrets::is_field_envelope(raw),
        Kind::Text => parsed
            .as_ref()
            .is_some_and(database::field_encryption::is_envelope),
    };
    if is_envelope {
        let plaintext = database::field_encryption::decrypt_with_ring(
            raw,
            ring,
            field.table,
            field.column,
            id,
        )?;
        return Ok(
            if parsed
                .as_ref()
                .and_then(database::field_encryption::envelope_key_id)
                == Some(ring.write_id())
            {
                StoredValue::Current(plaintext)
            } else {
                StoredValue::Stale(plaintext)
            },
        );
    }
    if matches!(field.kind, Kind::AgentSecret) && database::agent_secrets::is_legacy_ciphertext(raw)
    {
        return database::agent_secrets::decrypt_legacy(raw).map(StoredValue::LegacyEncrypted);
    }
    Ok(StoredValue::Plaintext(raw.to_owned()))
}

pub(super) fn stored_key_id(raw: &str) -> Option<String> {
    let parsed: Value = serde_json::from_str(raw).ok()?;
    database::field_encryption::envelope_key_id(&parsed).map(str::to_owned)
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
            StoredValue::Stale("b".into())
        );
        assert_eq!(
            read_value(&ring, &field, id, "hello").unwrap(),
            StoredValue::Plaintext("hello".into())
        );
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
