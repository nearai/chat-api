//! Bounded cleanup of expired browser session families on every API replica.
use database::repositories::browser_session_repository::BrowserSessionRepository;
use std::time::Duration;
use tokio::time::{interval, MissedTickBehavior};

pub async fn run(pool: database::DbPool) {
    let repository = BrowserSessionRepository(pool);
    let mut ticks = interval(Duration::from_secs(5 * 60));
    ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        // The first tick runs immediately, including after a process restart.
        ticks.tick().await;
        let mut deleted = 0;

        // Bound each transaction and total work per pass. Remaining expired
        // roots are picked up on subsequent ticks or by another replica.
        for _ in 0..10 {
            match repository.cleanup_expired(500).await {
                Ok(count) => {
                    deleted += count;
                    if count < 500 {
                        break;
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "Browser session cleanup failed; retrying next tick"
                    );
                    break;
                }
            }
        }

        if deleted > 0 {
            tracing::info!(deleted, "Removed expired browser session families");
        }
    }
}
