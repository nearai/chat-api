use chrono::{Duration, Utc};
use database::Database;
use services::user::ports::{BanType, UserRepository};

/// Test that creating a ban after an expired ban succeeds without database errors.
/// This verifies that expired bans are automatically revoked before inserting new ones.
#[tokio::test]
async fn test_create_ban_after_expired_ban() {
    // Load .env file
    dotenvy::dotenv().ok();

    // Load configuration
    let config = config::Config::from_env();

    // Create database connection
    let db = Database::from_config(&config.database)
        .await
        .expect("Failed to connect to database");

    // Run migrations
    db.run_migrations()
        .await
        .expect("Failed to run database migrations");

    let user_repo = db.user_repository();

    // Create a test user
    let user = user_repo
        .create_user(
            "test-ban@example.com".to_string(),
            Some("Test User".to_string()),
            None,
        )
        .await
        .expect("Failed to create test user");

    let user_id = user.id;
    let ban_type = BanType::NearBalanceLow;

    // Step 1: Create an expired ban directly in the database
    // This simulates a ban that has expired but hasn't been revoked yet
    let client = db
        .pool()
        .get()
        .await
        .expect("Failed to get database client");

    let expired_time = Utc::now() - Duration::hours(1); // 1 hour ago

    client
        .execute(
            "INSERT INTO user_bans (user_id, reason, ban_type, expires_at, revoked_at)
             VALUES ($1, $2, $3, $4, NULL)",
            &[
                &user_id,
                &Some("Test expired ban".to_string()),
                &ban_type.as_str(),
                &Some(expired_time),
            ],
        )
        .await
        .expect("Failed to insert expired ban");

    // Step 2: Verify that has_active_ban returns false (ban is expired)
    let has_active = user_repo
        .has_active_ban(user_id)
        .await
        .expect("Failed to check active ban");

    assert!(!has_active, "Expired ban should not be considered active");

    // Step 3: Try to create a new ban - this should succeed because the expired ban
    // will be automatically revoked in the transaction
    let new_expires_at = Utc::now() + Duration::hours(1);

    user_repo
        .create_user_ban(
            user_id,
            ban_type,
            Some("New ban after expired one".to_string()),
            Some(new_expires_at),
        )
        .await
        .expect("Failed to create new ban after expired ban");

    // Step 4: Verify that the new ban is active
    let has_active_after = user_repo
        .has_active_ban(user_id)
        .await
        .expect("Failed to check active ban after creating new ban");

    assert!(has_active_after, "New ban should be active");

    // Step 5: Verify that the expired ban was revoked
    let revoked_count = client
        .query_one(
            "SELECT COUNT(*) FROM user_bans
             WHERE user_id = $1
               AND ban_type = $2
               AND revoked_at IS NOT NULL
               AND expires_at < NOW()",
            &[&user_id, &ban_type.as_str()],
        )
        .await
        .expect("Failed to query revoked bans");

    let count: i64 = revoked_count.get(0);
    assert_eq!(count, 1, "The expired ban should have been revoked");

    // Step 6: Verify that there's exactly one active ban
    let active_count = client
        .query_one(
            "SELECT COUNT(*) FROM user_bans
             WHERE user_id = $1
               AND ban_type = $2
               AND revoked_at IS NULL
               AND (expires_at IS NULL OR expires_at > NOW())",
            &[&user_id, &ban_type.as_str()],
        )
        .await
        .expect("Failed to query active bans");

    let active_count: i64 = active_count.get(0);
    assert_eq!(active_count, 1, "There should be exactly one active ban");
}

/// Test that creating multiple bans with the same ban_type for the same user
/// after expiration works correctly.
#[tokio::test]
async fn test_multiple_bans_after_expiration() {
    // Load .env file
    dotenvy::dotenv().ok();

    // Load configuration
    let config = config::Config::from_env();

    // Create database connection
    let db = Database::from_config(&config.database)
        .await
        .expect("Failed to connect to database");

    // Run migrations
    db.run_migrations()
        .await
        .expect("Failed to run database migrations");

    let user_repo = db.user_repository();

    // Create a test user
    let user = user_repo
        .create_user(
            "test-multiple-bans@example.com".to_string(),
            Some("Test User".to_string()),
            None,
        )
        .await
        .expect("Failed to create test user");

    let user_id = user.id;
    let ban_type = BanType::Manual;

    // Create first ban (will expire soon)
    let first_expires_at = Utc::now() + Duration::seconds(1);
    user_repo
        .create_user_ban(
            user_id,
            ban_type,
            Some("First ban".to_string()),
            Some(first_expires_at),
        )
        .await
        .expect("Failed to create first ban");

    // Wait for the ban to expire
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Verify ban is expired
    let has_active = user_repo
        .has_active_ban(user_id)
        .await
        .expect("Failed to check active ban");
    assert!(!has_active, "Ban should be expired");

    // Create second ban - should succeed because expired ban will be auto-revoked
    let second_expires_at = Utc::now() + Duration::hours(1);
    user_repo
        .create_user_ban(
            user_id,
            ban_type,
            Some("Second ban".to_string()),
            Some(second_expires_at),
        )
        .await
        .expect("Failed to create second ban after expiration");

    // Verify new ban is active
    let has_active_after = user_repo
        .has_active_ban(user_id)
        .await
        .expect("Failed to check active ban");
    assert!(has_active_after, "New ban should be active");
}
