use deadpool_postgres::Pool;

/// Shared, swappable handle to the active write pool.
///
/// Holders keep clones of this handle and acquire connections through it per
/// call. When the Patroni leader changes, the database crate's ClusterManager
/// installs the new leader's pool via [`DbPool::replace`] and every clone
/// immediately routes new acquisitions to the new leader. A plain
/// `deadpool::Pool` clone cannot do this — its target host is fixed at
/// creation, so pools captured at startup keep dialing the old leader after a
/// failover (the 2026-07-12 outage: the leader change was detected and a new
/// pool was built, but no holder ever saw it).
///
/// Defined here rather than in the database crate because services (e.g. the
/// subscription service) hold the handle directly and the database crate
/// depends on this one.
#[derive(Clone)]
pub struct DbPool {
    inner: std::sync::Arc<std::sync::RwLock<Option<Pool>>>,
}

impl DbPool {
    /// Create a handle wrapping an already-built pool.
    pub fn new(pool: Pool) -> Self {
        Self {
            inner: std::sync::Arc::new(std::sync::RwLock::new(Some(pool))),
        }
    }

    /// Create a handle with no pool installed yet. [`DbPool::get`] fails with
    /// `PoolError::Closed` until [`DbPool::replace`] installs one.
    pub fn uninitialized() -> Self {
        Self {
            inner: std::sync::Arc::new(std::sync::RwLock::new(None)),
        }
    }

    /// Install `pool` as the active pool for this handle and every clone of it.
    /// The previous pool (if any) is dropped once its checked-out connections
    /// are returned.
    pub fn replace(&self, pool: Pool) {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        *guard = Some(pool);
    }

    /// The currently installed pool, if any.
    pub fn current(&self) -> Option<Pool> {
        self.inner.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Acquire a connection from the currently installed pool.
    pub async fn get(&self) -> Result<deadpool_postgres::Object, deadpool_postgres::PoolError> {
        // Clone the pool out of the lock so it is not held across the await.
        let pool = self.current().ok_or(deadpool_postgres::PoolError::Closed)?;
        pool.get().await
    }

    /// Status of the currently installed pool, or `None` before initialization.
    pub fn status(&self) -> Option<deadpool_postgres::Status> {
        self.current().map(|pool| pool.status())
    }
}

impl From<Pool> for DbPool {
    fn from(pool: Pool) -> Self {
        Self::new(pool)
    }
}

// Manual impl: the inner pool's Debug output includes connection config, which
// must never end up in logs.
impl std::fmt::Debug for DbPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbPool")
            .field("initialized", &self.current().is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deadpool_postgres::{Config, PoolConfig, Runtime};

    fn lazy_pool(max_size: usize) -> Pool {
        // deadpool creates connections lazily, so building a pool against an
        // unreachable host is fine as long as no connection is acquired.
        let mut cfg = Config::new();
        cfg.host = Some("pool-test-host.invalid".to_string());
        cfg.port = Some(5432);
        cfg.dbname = Some("test".to_string());
        cfg.user = Some("test".to_string());
        cfg.password = Some("test".to_string());
        cfg.pool = Some(PoolConfig::new(max_size));
        cfg.create_pool(Some(Runtime::Tokio1), tokio_postgres::NoTls)
            .expect("lazy pool must build without connecting")
    }

    #[tokio::test]
    async fn replace_propagates_to_existing_clones() {
        let handle = DbPool::new(lazy_pool(3));
        // Simulates a holder keeping a clone taken at startup.
        let startup_clone = handle.clone();
        assert_eq!(startup_clone.status().unwrap().max_size, 3);

        handle.replace(lazy_pool(7));
        assert_eq!(
            startup_clone.status().unwrap().max_size,
            7,
            "clones taken before replace() must observe the new pool"
        );
    }

    #[tokio::test]
    async fn get_on_uninitialized_handle_fails_closed() {
        let handle = DbPool::uninitialized();
        assert!(handle.status().is_none());
        match handle.get().await {
            Err(deadpool_postgres::PoolError::Closed) => {}
            other => panic!("expected PoolError::Closed, got {other:?}"),
        }
    }
}
