use chrono::{Duration, Utc};
use database::Database;
use services::user::ports::{BanType, UserRepository, UserService};
use services::user::UserServiceImpl;
use uuid::Uuid;

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

    // Create a test user with unique email
    let email = format!("test-ban-{}@example.com", Uuid::new_v4());
    let user = user_repo
        .create_user(email, Some("Test User".to_string()), None)
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

    // Create a test user with unique email
    let email = format!("test-multiple-bans-{}@example.com", Uuid::new_v4());
    let user = user_repo
        .create_user(email, Some("Test User".to_string()), None)
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

/// Test that creating a ban when an active (non-expired) ban already exists
/// should fail due to unique index constraint violation.
/// This tests the edge case where create_user_ban is called directly without
/// checking has_active_ban first.
#[tokio::test]
async fn test_create_ban_with_active_ban_exists() {
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

    // Create a test user with unique email
    let email = format!("test-active-ban-{}@example.com", Uuid::new_v4());
    let user = user_repo
        .create_user(email, Some("Test User".to_string()), None)
        .await
        .expect("Failed to create test user");

    let user_id = user.id;
    let ban_type = BanType::Manual;

    // Step 1: Create an active ban
    let first_expires_at = Utc::now() + Duration::hours(1);
    user_repo
        .create_user_ban(
            user_id,
            ban_type,
            Some("First active ban".to_string()),
            Some(first_expires_at),
        )
        .await
        .expect("Failed to create first active ban");

    // Step 2: Verify that has_active_ban returns true
    let has_active = user_repo
        .has_active_ban(user_id)
        .await
        .expect("Failed to check active ban");
    assert!(has_active, "Ban should be active");

    // Step 3: Try to create another ban with the same user_id and ban_type
    // This should fail due to unique index constraint violation
    let second_expires_at = Utc::now() + Duration::hours(2);
    let result = user_repo
        .create_user_ban(
            user_id,
            ban_type,
            Some("Second ban attempt".to_string()),
            Some(second_expires_at),
        )
        .await;

    // Step 4: Verify that the operation failed with a database constraint error
    assert!(
        result.is_err(),
        "Creating a ban when an active ban already exists should fail"
    );

    let error = result.unwrap_err();
    let error_string = error.to_string();
    assert!(
        error_string.contains("db error"),
        "Error should be related to unique constraint violation, got: {}",
        error_string
    );

    // Step 5: Verify that only one active ban exists (the original one)
    let client = db
        .pool()
        .get()
        .await
        .expect("Failed to get database client");

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
    assert_eq!(
        active_count, 1,
        "There should be exactly one active ban (the original one)"
    );
}

/// Test that ban_user_for_duration correctly skips creating a new ban
/// when an active ban already exists.
#[tokio::test]
async fn test_ban_user_for_duration_skips_when_active_ban_exists() {
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
    let user_service = UserServiceImpl::new(user_repo.clone());

    // Create a test user with unique email
    let email = format!("test-ban-service-{}@example.com", Uuid::new_v4());
    let user = user_repo
        .create_user(email, Some("Test User".to_string()), None)
        .await
        .expect("Failed to create test user");

    let user_id = user.id;
    let ban_type = BanType::NearBalanceLow;

    // Step 1: Create an active ban using ban_user_for_duration
    user_service
        .ban_user_for_duration(
            user_id,
            ban_type,
            Some("First ban".to_string()),
            Duration::hours(1),
        )
        .await
        .expect("Failed to create first ban");

    // Step 2: Verify that has_active_ban returns true
    let has_active = user_service
        .has_active_ban(user_id)
        .await
        .expect("Failed to check active ban");
    assert!(has_active, "Ban should be active");

    // Step 3: Try to create another ban using ban_user_for_duration
    // This should succeed but skip creating a new ban
    user_service
        .ban_user_for_duration(
            user_id,
            ban_type,
            Some("Second ban attempt".to_string()),
            Duration::hours(2),
        )
        .await
        .expect("ban_user_for_duration should succeed even when active ban exists");

    // Step 4: Verify that only one active ban exists (the original one)
    let client = db
        .pool()
        .get()
        .await
        .expect("Failed to get database client");

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
    assert_eq!(
        active_count, 1,
        "There should be exactly one active ban (the original one, not replaced)"
    );

    // Step 5: Verify that the original ban's expiration time was not changed
    let ban_row = client
        .query_one(
            "SELECT expires_at FROM user_bans
             WHERE user_id = $1
               AND ban_type = $2
               AND revoked_at IS NULL
               AND expires_at > NOW()
             ORDER BY created_at ASC
             LIMIT 1",
            &[&user_id, &ban_type.as_str()],
        )
        .await
        .expect("Failed to query ban");

    let expires_at: Option<chrono::DateTime<Utc>> = ban_row.get(0);
    assert!(
        expires_at.is_some(),
        "Original ban should still exist with its expiration time"
    );
}
