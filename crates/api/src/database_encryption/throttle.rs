use std::{future::Future, time::Duration};

/// Returns true when cancellation was observed during the delay.
pub(super) async fn wait<F, C>(delay: Duration, mut cancelled: C) -> anyhow::Result<bool>
where
    C: FnMut() -> F,
    F: Future<Output = anyhow::Result<bool>>,
{
    let mut remaining = delay;
    while !remaining.is_zero() {
        if cancelled().await? {
            return Ok(true);
        }
        let slice = remaining.min(Duration::from_millis(500));
        tokio::time::sleep(slice).await;
        remaining -= slice;
    }
    cancelled().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[tokio::test]
    async fn large_delay_observes_cancellation_within_two_seconds() {
        let cancelled = AtomicBool::new(false);
        let delay = wait(Duration::from_secs(10), || async {
            Ok(cancelled.load(Ordering::SeqCst))
        });
        let cancel = async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            cancelled.store(true, Ordering::SeqCst);
        };
        let result = tokio::time::timeout(Duration::from_secs(2), async {
            let (result, ()) = tokio::join!(delay, cancel);
            result
        })
        .await;
        assert!(result
            .expect("cancellation must interrupt a long delay")
            .unwrap());
    }
}
