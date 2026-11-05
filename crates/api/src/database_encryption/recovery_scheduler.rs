use futures::{Stream, StreamExt};
use std::future::Future;
use std::time::Duration;

pub(super) fn ticks(interval: Duration) -> impl Stream<Item = ()> + Unpin {
    let mut timer = tokio::time::interval(interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tokio_stream::wrappers::IntervalStream::new(timer).map(|_| ())
}

pub(super) async fn run<S, F, R>(mut ticks: S, mut recover: F)
where
    S: Stream<Item = ()> + Unpin,
    F: FnMut() -> R,
    R: Future<Output = ()>,
{
    while ticks.next().await.is_some() {
        recover().await;
    }
}

#[cfg(test)]
mod tests {
    use futures::{FutureExt, StreamExt};
    use std::cell::Cell;
    use std::time::Duration;

    #[tokio::test]
    async fn recovery_first_tick_is_immediate_even_with_a_long_interval() {
        let mut ticks = super::ticks(Duration::from_secs(60));
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(100), ticks.next()).await,
            Ok(Some(()))
        );
        assert!(ticks.next().now_or_never().is_none());
    }

    #[tokio::test]
    async fn recovery_ticks_continue_after_startup() {
        let mut ticks = super::ticks(Duration::from_millis(10));
        assert_eq!(ticks.next().await, Some(()));
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(100), ticks.next()).await,
            Ok(Some(()))
        );
    }

    #[tokio::test]
    async fn recovery_ticks_wait_for_the_previous_scan() {
        // Given several recovery ticks and a scan that yields before finishing.
        let active = Cell::new(0);
        let scans = Cell::new(0);
        let ticks = futures::stream::iter([(), (), ()]);

        // When the scheduler consumes the injected ticks.
        super::run(ticks, || async {
            active.set(active.get() + 1);
            assert_eq!(active.get(), 1, "recovery scans must never overlap");
            tokio::task::yield_now().await;
            scans.set(scans.get() + 1);
            active.set(active.get() - 1);
        })
        .await;

        // Then every scan finished before another tick started a scan.
        assert_eq!(scans.get(), 3);
        assert_eq!(active.get(), 0);
    }
}
