pub mod agent;
pub mod aml;
pub mod analytics;
pub mod auth;
pub mod bi_metrics;
pub mod consts;
pub mod conversation;
pub mod db_pool;
pub mod encryption_key_ring;
pub mod file;
pub mod logging;
pub mod metrics;
pub mod model;
pub mod response;
pub mod subscription;
pub mod system_configs;
pub mod tasks;
pub mod types;
pub mod user;
pub mod user_usage;
pub mod vpc;

pub use types::{SessionId, UserId};

#[cfg(test)]
fn random_key() -> [u8; 32] {
    use rand::{Rng, TryRngCore};
    rand::rngs::OsRng.unwrap_err().random()
}
