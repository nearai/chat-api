use crate::pool::DbPool;
use anyhow::{Context, Result};
use refinery::load_sql_migrations;
use tracing::info;

/// Run database migrations
pub async fn run(pool: &DbPool) -> Result<()> {
    let mut client = pool
        .get()
        .await
        .context("Failed to get database connection for migrations")?;

    // Load the migration SQL files from the migrations/sql folder
    // Priority: 1) DATABASE_MIGRATIONS_PATH env var, 2) relative path from current dir, 3) compile-time path
    let env_path = std::env::var("DATABASE_MIGRATIONS_PATH")
        .ok()
        .map(std::path::PathBuf::from);
    let relative_path = std::env::current_dir()
        .context("Failed to get current directory")?
        .join("crates/database/src/migrations/sql");
    let compile_time_path =
        std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/src/migrations/sql"));

    let candidate_paths: Vec<_> = env_path
        .iter()
        .chain([&relative_path, &compile_time_path])
        .cloned()
        .collect();

    let migrations_path = candidate_paths
        .iter()
        .find(|path| path.exists())
        .ok_or_else(|| {
            let paths_str = candidate_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::anyhow!("Migrations folder not found. Checked paths: {paths_str}")
        })?;

    let migrations = load_sql_migrations(migrations_path)
        .with_context(|| format!("Failed to load migrations from {migrations_path:?}"))?;

    let migration_report = refinery::Runner::new(&migrations)
        .run_async(&mut **client)
        .await
        .context("Failed to run migrations")?;

    for migration in migration_report.applied_migrations() {
        info!("Applied migration: {}", migration.name());
    }

    info!("All migrations completed successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    const V39: &str = include_str!("sql/V39__conversation_file_database_encryption.sql");

    #[test]
    fn v39_preserves_legacy_conflict_arbiters_for_rolling_deployments() {
        for name in [
            "conversation_share_groups_owner_user_id_name_key",
            "conversation_share_group_memb_group_id_member_type_member_v_key",
            "idx_conversation_shares_direct_unique",
            "idx_conversation_shares_org_unique",
        ] {
            assert!(!V39.contains(&format!("DROP INDEX IF EXISTS {name}")));
            assert!(!V39.contains(&format!("DROP CONSTRAINT IF EXISTS {name}")));
        }
    }

    #[test]
    fn v39_keeps_job_history_without_blocking_account_deletion() {
        assert!(V39.contains("admin_actor UUID REFERENCES users(id) ON DELETE SET NULL"));
    }

    #[test]
    fn v39_forbids_bounded_verification_jobs() {
        assert!(V39.contains("CHECK (mode <> 'verify' OR max_rows IS NULL)"));
    }

    #[test]
    fn v39_uses_cloud_file_uuid_without_an_auxiliary_encryption_id() {
        assert!(!V39.contains("encryption_id"));
    }

    #[test]
    fn v39_keeps_organization_patterns_in_plaintext() {
        assert!(!V39.contains("org_domain_search_token"));
        assert!(V39.contains("ALTER COLUMN org_email_pattern TYPE TEXT"));
    }
}
