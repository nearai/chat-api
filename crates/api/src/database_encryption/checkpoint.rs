use super::*;
use database::field_encryption::KeyRing;

const RING_CONTEXT_VERSION: u64 = 1;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum RingContextError {
    Missing,
    Changed,
}

impl std::fmt::Display for RingContextError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "checkpoint key context missing",
            Self::Changed => "checkpoint key context changed",
        })
    }
}

impl std::error::Error for RingContextError {}

fn ring_context(ring: &KeyRing) -> Value {
    json!({
        "version": RING_CONTEXT_VERSION,
        "write_id": ring.write_id(),
        "read_ids": ring.ids(),
        "fingerprints": ring.fingerprints(),
    })
}

#[derive(Default)]
pub(super) struct Checkpoint {
    pub(super) field_index: usize,
    pub(super) after: Uuid,
    pub(super) progress: Progress,
    pub(super) ring_context: Value,
}

impl Checkpoint {
    pub(super) fn restore(
        restart_dry_run: bool,
        cursor: Value,
        progress: Value,
        ring: &KeyRing,
    ) -> anyhow::Result<Self> {
        // Projection lives only in the running task. After a process restart,
        // dry runs reset cursor and counters and replay their entire scope;
        // execute/verify jobs retain their durable checkpoint.
        let context = ring_context(ring);
        let saved_context = cursor.get("ring_context");
        if !restart_dry_run {
            match saved_context {
                Some(saved) if saved == &context => {}
                Some(saved) if saved["version"].as_u64() != Some(RING_CONTEXT_VERSION) => {
                    return Err(RingContextError::Changed.into())
                }
                Some(_) => return Err(RingContextError::Changed.into()),
                None if cursor.as_object().is_some_and(|object| object.is_empty())
                    && progress.as_object().is_some_and(|object| object.is_empty()) => {}
                None => return Err(RingContextError::Missing.into()),
            }
        }
        if restart_dry_run {
            return Ok(Self {
                ring_context: context,
                ..Self::default()
            });
        }
        Ok(Self {
            field_index: usize::try_from(cursor["field_index"].as_u64().unwrap_or(0))?,
            after: cursor["after_id"]
                .as_str()
                .and_then(|value| Uuid::parse_str(value).ok())
                .unwrap_or(Uuid::nil()),
            progress: serde_json::from_value(progress)?,
            ring_context: context,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovered_dry_run_replays_prior_batches_and_rebuilds_projection() {
        let first = Uuid::new_v4();
        // A first batch projected an old-key token into the write-key domain.
        // The next old-key row converges to the same token, so resuming without
        // replaying the first batch would overlook that conflict.
        let cursor = json!({"field_index":3,"after_id":first});
        let progress = json!({"processed":1,"rewrapped":1,"stale":1,
            "tokens_rewritten":1,"token_conflicts_estimated":true,"by_key_id":{"previous":1},
            "fields":{"conversation_share_groups.name":{"processed":1,"rewrapped":1}}});
        let restored = Checkpoint::restore(true, cursor, progress, &test_ring()).unwrap();
        assert_eq!(
            restored.field_index, 0,
            "session loss must replay prior fields"
        );
        assert_eq!(
            restored.after,
            Uuid::nil(),
            "session loss must replay prior rows"
        );
        assert_eq!(restored.progress.totals.processed, 0);
        assert_eq!(restored.progress.totals.rewrapped, 0);
        assert!(restored.progress.totals.by_key_id.is_empty());
        assert!(restored.progress.fields.is_empty());
        assert!(!restored.progress.token_conflicts_estimated);
    }

    #[test]
    fn uninterrupted_dry_run_keeps_its_saved_checkpoint() {
        let after = Uuid::new_v4();
        let ring = test_ring();
        let restored = Checkpoint::restore(
            false,
            json!({"field_index":2,"after_id":after,"ring_context":ring_context(&ring)}),
            json!({"processed":7,"plaintext":7,"token_conflicts_estimated":true}),
            &ring,
        )
        .unwrap();
        assert_eq!(restored.field_index, 2);
        assert_eq!(restored.after, after);
        assert_eq!(restored.progress.totals.processed, 7);
        assert_eq!(restored.progress.totals.plaintext, 7);
        assert!(restored.progress.token_conflicts_estimated);
    }

    #[test]
    fn persistent_execute_and_verify_results_resume_at_the_saved_row() {
        let after = Uuid::new_v4();
        let ring = test_ring();
        let restored = Checkpoint::restore(
            false,
            json!({"field_index":3,"after_id":after,"ring_context":ring_context(&ring)}),
            json!({"processed":9,"rewrapped":4,"token_conflicts":1}),
            &ring,
        )
        .unwrap();
        assert_eq!(restored.field_index, 3);
        assert_eq!(restored.after, after);
        assert_eq!(restored.progress.totals.processed, 9);
        assert_eq!(restored.progress.totals.rewrapped, 4);
        assert_eq!(restored.progress.totals.token_conflicts, 1);
    }

    fn test_ring() -> KeyRing {
        KeyRing::new(
            "current".into(),
            [1; 32],
            vec![("previous".into(), [2; 32])],
        )
        .unwrap()
    }

    #[test]
    fn pristine_checkpoint_may_bind_ring_on_first_batch() {
        let ring = test_ring();
        assert!(Checkpoint::restore(false, json!({}), json!({}), &ring).is_ok());
    }

    #[test]
    fn persistent_checkpoint_requires_matching_ring_context() {
        let ring = test_ring();
        let cursor =
            json!({"field_index":0,"after_id":Uuid::nil(),"ring_context":ring_context(&ring)});
        assert!(Checkpoint::restore(false, json!({}), json!({}), &ring).is_ok());
        assert!(matches!(
            Checkpoint::restore(
                false,
                json!({"field_index":0,"after_id":Uuid::nil()}),
                json!({"processed":0}),
                &ring
            )
            ,
            Err(error) if error.downcast_ref::<RingContextError>() == Some(&RingContextError::Missing)
        ));
        let changed_id = KeyRing::new(
            "rotated".into(),
            [1; 32],
            vec![("previous".into(), [2; 32])],
        )
        .unwrap();
        assert!(
            matches!(Checkpoint::restore(false, cursor.clone(), json!({"processed":1}), &changed_id), Err(error) if error.downcast_ref::<RingContextError>() == Some(&RingContextError::Changed))
        );
        let changed_bytes = KeyRing::new(
            "current".into(),
            [3; 32],
            vec![("previous".into(), [2; 32])],
        )
        .unwrap();
        assert!(
            matches!(Checkpoint::restore(false, cursor, json!({"processed":1}), &changed_bytes), Err(error) if error.downcast_ref::<RingContextError>() == Some(&RingContextError::Changed))
        );
    }
}
