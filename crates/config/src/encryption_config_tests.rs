use super::DatabaseEncryptionConfig;
use serial_test::serial;

struct EncryptionEnv(Vec<(&'static str, Option<std::ffi::OsString>)>);

impl EncryptionEnv {
    fn new() -> Self {
        let names = [
            "DB_ENCRYPTION_KEYS",
            "DB_ENCRYPTION_KEY_ID",
            "DB_ENCRYPTION_KEY",
            "DB_ENCRYPTION_KEY_FILE",
            "DB_ENCRYPTION_ALLOW_INLINE_KEYS",
        ];
        Self(
            names
                .into_iter()
                .map(|name| {
                    let previous = std::env::var_os(name);
                    std::env::remove_var(name);
                    (name, previous)
                })
                .collect(),
        )
    }
}

impl Drop for EncryptionEnv {
    fn drop(&mut self) {
        for (name, value) in &self.0 {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

#[test]
#[serial]
fn blank_ring_falls_back_to_legacy_inline_key() {
    let _env = EncryptionEnv::new();
    let legacy_key = super::random_key_hex();
    std::env::set_var("DB_ENCRYPTION_KEY", &legacy_key);
    std::env::set_var("DB_ENCRYPTION_KEY_ID", "existing");
    for blank in ["", " \t\r\n"] {
        std::env::set_var("DB_ENCRYPTION_KEYS", blank);

        let config = DatabaseEncryptionConfig::default();

        assert!(config.keys.is_none());
        assert_eq!(config.key, legacy_key);
        assert_eq!(config.key_id, "existing");
    }
}

#[test]
#[serial]
fn blank_ring_falls_back_to_legacy_key_file() {
    let _env = EncryptionEnv::new();
    let legacy_key = super::random_key_hex();
    let legacy_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(legacy_file.path(), format!("{legacy_key}\n")).unwrap();
    std::env::set_var("DB_ENCRYPTION_KEY_FILE", legacy_file.path());
    std::env::set_var("DB_ENCRYPTION_KEY", super::random_key_hex());
    for blank in ["", " \t\r\n"] {
        std::env::set_var("DB_ENCRYPTION_KEYS", blank);

        let config = DatabaseEncryptionConfig::default();

        assert!(config.keys.is_none());
        assert_eq!(config.key, legacy_key);
    }
}

#[test]
#[serial]
fn rejects_ring_that_drops_explicit_legacy_id() {
    let _env = EncryptionEnv::new();
    std::env::set_var("DB_ENCRYPTION_KEYS", "new=file:/keys/new");
    std::env::set_var("DB_ENCRYPTION_KEY_ID", "db-v1");
    let loaded = std::panic::catch_unwind(DatabaseEncryptionConfig::default);
    assert!(
        loaded.is_err(),
        "dropping the existing envelope id must fail startup"
    );
}

#[test]
#[serial]
fn accepts_ring_without_explicit_legacy_id() {
    let _env = EncryptionEnv::new();
    std::env::set_var("DB_ENCRYPTION_KEYS", "new=file:/keys/new");
    assert!(std::panic::catch_unwind(DatabaseEncryptionConfig::default).is_ok());
}

#[test]
#[serial]
fn accepts_ring_preserving_explicit_legacy_id() {
    let _env = EncryptionEnv::new();
    std::env::set_var(
        "DB_ENCRYPTION_KEYS",
        "new=file:/keys/new,db-v1=file:/keys/old",
    );
    std::env::set_var("DB_ENCRYPTION_KEY_ID", "db-v1");
    assert!(std::panic::catch_unwind(DatabaseEncryptionConfig::default).is_ok());
}

#[test]
#[serial]
fn inline_sources_require_explicit_opt_in() {
    let _env = EncryptionEnv::new();
    std::env::set_var(
        "DB_ENCRYPTION_KEYS",
        format!("new=hex:{}", super::random_key_hex()),
    );
    assert!(std::panic::catch_unwind(DatabaseEncryptionConfig::default).is_err());
}

#[test]
#[serial]
fn inline_sources_accept_explicit_opt_in() {
    let _env = EncryptionEnv::new();
    std::env::set_var(
        "DB_ENCRYPTION_KEYS",
        format!("new=hex:{}", super::random_key_hex()),
    );
    std::env::set_var("DB_ENCRYPTION_ALLOW_INLINE_KEYS", "true");
    assert!(std::panic::catch_unwind(DatabaseEncryptionConfig::default).is_ok());
}

#[test]
fn encryption_startup_probe() {
    if std::env::var_os("ENCRYPTION_STARTUP_PROBE").is_some() {
        let _config = DatabaseEncryptionConfig::default();
    }
}

#[test]
fn ring_startup_warns_once_and_ignores_removed_legacy_file() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "encryption_config_tests::encryption_startup_probe",
            "--exact",
            "--nocapture",
        ])
        .env("ENCRYPTION_STARTUP_PROBE", "1")
        .env("DB_ENCRYPTION_KEYS", "new=file:/keys/new")
        .env_remove("DB_ENCRYPTION_KEY_ID")
        .env("DB_ENCRYPTION_KEY_FILE", "/no-such-legacy-key-file")
        .env("DB_ENCRYPTION_KEY", "sensitive-ignored-legacy-key")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert!(stderr.contains("DB_ENCRYPTION_KEYS"));
    assert!(!stderr.contains("sensitive-ignored-legacy-key"));
}
