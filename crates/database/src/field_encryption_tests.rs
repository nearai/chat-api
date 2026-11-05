use super::*;

fn test_key() -> [u8; 32] {
    Aes256Gcm::generate_key(OsRng).into()
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
            decrypt_if_encrypted(&key, "test-v1", "files", "filename", id, value.into()).unwrap(),
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

#[test]
fn encryption_and_search_use_distinct_subkeys() {
    let key = test_key();
    assert_ne!(
        derive_key(&key, AEAD_KEY_INFO).unwrap(),
        derive_key(&key, SEARCH_KEY_INFO).unwrap()
    );
}
#[test]
fn previous_key_round_trip_enforces_context_and_unknown_id() {
    let current_key = test_key();
    let previous_key = test_key();
    let ring = KeyRing::new(
        "new".into(),
        current_key,
        vec![("old".into(), previous_key)],
    )
    .unwrap();
    let row = Uuid::new_v4();
    let encrypted = encrypt(&previous_key, "old", "files", "filename", row, "before.txt").unwrap();
    assert_eq!(
        decrypt_with_ring(&encrypted, &ring, "files", "filename", row).unwrap(),
        "before.txt"
    );
    assert!(decrypt_with_ring(&encrypted, &ring, "files", "filename", Uuid::new_v4()).is_err());
    assert!(decrypt_with_ring(&encrypted, &ring, "other", "filename", row).is_err());
    let current_only = KeyRing::new("new".into(), current_key, vec![]).unwrap();
    assert_eq!(
        decrypt_with_ring(&encrypted, &current_only, "files", "filename", row)
            .unwrap_err()
            .to_string(),
        "unsupported encryption key id"
    );
    let envelope = serde_json::from_str(&encrypted).unwrap();
    assert_eq!(envelope_key_id(&envelope), Some("old"));
    assert_eq!(envelope_key_id(&json!({"key_id":"old"})), None);
}

#[test]
fn lookup_tokens_follow_ring_order_and_write_primitive_stays_compatible() {
    let current_key = test_key();
    let previous_key = test_key();
    let ring = KeyRing::new(
        "new".into(),
        current_key,
        vec![("old".into(), previous_key)],
    )
    .unwrap();
    let tokens = search_tokens_for_lookup(&ring, "groups.name", "name").unwrap();
    assert_ne!(tokens[0], tokens[1]);
    assert_eq!(
        tokens[0],
        search_token(&current_key, "groups.name", "name").unwrap()
    );
    assert_eq!(
        tokens[1],
        search_token_with_key(&previous_key, "groups.name", "name").unwrap()
    );
}
