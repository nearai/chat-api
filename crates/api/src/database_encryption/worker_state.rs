use std::sync::Arc;
use tokio::sync::Semaphore;

/// Local worker admission shared by handlers and recovery in one server.
#[derive(Clone)]
pub struct WorkerState {
    pub(super) semaphore: Arc<Semaphore>,
}

impl Default for WorkerState {
    fn default() -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(1)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::WorkerState;

    #[test]
    fn cloned_server_state_serializes_workers() {
        // Given two handles belonging to one server.
        let server = WorkerState::default();
        let recovery = server.clone();
        // When a submitted job owns admission.
        let permit = server.semaphore.try_acquire().unwrap();
        // Then recovery cannot overlap it, but can run after it finishes.
        assert!(recovery.semaphore.try_acquire().is_err());
        drop(permit);
        assert!(recovery.semaphore.try_acquire().is_ok());
    }

    #[test]
    fn separate_servers_do_not_skip_recovery_when_another_worker_is_busy() {
        // Given independent servers (and independent databases).
        let busy_server = WorkerState::default();
        let recovering_server = WorkerState::default();
        // When a job holds admission, including throughout its batch delay.
        let _permit = busy_server.semaphore.try_acquire().unwrap();
        // Then the other server must still admit its recovery scan.
        assert!(
            recovering_server.semaphore.try_acquire().is_ok(),
            "a job in another server must not make recovery skip its only attempt"
        );
    }
}
