use super::*;
use std::sync::Mutex;

struct FakeFetcher {
    calls: Mutex<Vec<String>>,
    key: Vec<u8>,
    fail: bool,
}

#[async_trait]
impl DstackKeyFetcher for FakeFetcher {
    async fn get_key(&self, path: &str) -> Result<Vec<u8>> {
        self.calls.lock().unwrap().push(path.into());
        if self.fail {
            return Err(anyhow!("sensitive-upstream-response"));
        }
        Ok(self.key.clone())
    }
}

fn config(raw: Option<String>) -> DatabaseEncryptionConfig {
    DatabaseEncryptionConfig {
        key: hex::encode(crate::random_key()),
        key_id: "legacy".into(),
        keys: raw,
        write_enabled: true,
        agent_secrets_write_enabled: false,
    }
}

fn fetcher(key: Vec<u8>) -> FakeFetcher {
    FakeFetcher {
        calls: Mutex::new(vec![]),
        key,
        fail: false,
    }
}

#[tokio::test]
async fn resolves_ordered_sources_and_preserves_write_gates() {
    let current_key = crate::random_key();
    let previous_key = crate::random_key();
    let fake = fetcher(previous_key.to_vec());
    let raw = format!("new=hex:{},old=dstack:db/old", hex::encode(current_key));
    let resolved = resolve_field_encryption_with(&config(Some(raw)), &fake)
        .await
        .unwrap();
    assert_eq!(resolved.ring().unwrap().ids(), ["new", "old"]);
    assert_eq!(resolved.key, current_key);
    assert_eq!(resolved.previous_keys, vec![("old".into(), previous_key)]);
    assert_eq!(*fake.calls.lock().unwrap(), ["db/old"]);
    assert!(resolved.write_enabled);
    assert!(!resolved.agent_secrets_write_enabled);
}

#[tokio::test]
async fn legacy_config_uses_single_key_without_fetching() {
    let fake = fetcher(vec![]);
    let settings = config(None);
    let expected_key = parse_key(&settings.key).unwrap();
    let resolved = resolve_field_encryption_with(&settings, &fake)
        .await
        .unwrap();
    assert_eq!(resolved.ring().unwrap().ids(), ["legacy"]);
    assert_eq!(resolved.key, expected_key);
    assert!(fake.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn resolves_trimmed_file_and_rejects_invalid_file_contents() {
    let path = std::env::temp_dir().join(format!("db-ring-key-{}", uuid::Uuid::new_v4()));
    let key = crate::random_key();
    std::fs::write(&path, format!(" {}\n", hex::encode(key))).unwrap();
    let settings = config(Some(format!("new=file:{}", path.display())));
    let fake = fetcher(vec![]);
    let resolved = resolve_field_encryption_with(&settings, &fake)
        .await
        .unwrap();
    assert_eq!(resolved.key, key);
    std::fs::write(&path, "sensitive-invalid-content").unwrap();
    let error = resolve_field_encryption_with(&settings, &fake)
        .await
        .err()
        .unwrap();
    assert!(!format!("{error:?}").contains("sensitive-invalid-content"));
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn source_errors_fail_closed_without_sensitive_details() {
    let mut fake = fetcher(crate::random_key()[..31].to_vec());
    let settings = config(Some("new=dstack:key/path".into()));
    assert!(resolve_field_encryption_with(&settings, &fake)
        .await
        .err()
        .unwrap()
        .to_string()
        .contains("32 bytes"));
    fake.fail = true;
    let error = resolve_field_encryption_with(&settings, &fake)
        .await
        .err()
        .unwrap();
    assert!(!format!("{error:?}").contains("sensitive-upstream-response"));
    assert!(
        resolve_field_encryption_with(&config(Some("new=file:/missing/key".into())), &fake)
            .await
            .is_err()
    );
    for raw in ["", "bad", "new=hex:secret", "new=file:"] {
        assert!(
            resolve_field_encryption_with(&config(Some(raw.into())), &fake)
                .await
                .is_err()
        );
    }
    let mut absent = config(None);
    absent.key.clear();
    assert!(resolve_field_encryption_with(&absent, &fake).await.is_err());
}

#[tokio::test]
async fn invalid_sources_and_legacy_keys_fail_before_dstack_fetch() {
    let fake = fetcher(crate::random_key().to_vec());
    for raw in [
        "new=dstack:path,new=file:/key",
        "new=dstack:path,bad=hex:short",
    ] {
        assert!(
            resolve_field_encryption_with(&config(Some(raw.into())), &fake)
                .await
                .is_err()
        );
    }
    assert!(fake.calls.lock().unwrap().is_empty());
    let mut legacy = config(None);
    legacy.key_id = "invalid:id".into();
    assert!(resolve_field_encryption_with(&legacy, &fake).await.is_err());
    legacy.key_id = "legacy".into();
    legacy.key = hex::encode(&crate::random_key()[..31]);
    assert!(resolve_field_encryption_with(&legacy, &fake).await.is_err());
}
