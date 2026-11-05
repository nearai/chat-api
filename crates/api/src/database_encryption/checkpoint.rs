use super::*;

#[derive(Default)]
pub(super) struct Checkpoint {
    pub(super) field_index: usize,
    pub(super) after: Uuid,
    pub(super) progress: Progress,
}

impl Checkpoint {
    pub(super) fn restore(
        replay_projection: bool,
        cursor: Value,
        progress: Value,
    ) -> anyhow::Result<Self> {
        // The projection lives in the database session, so a recovered dry run
        // must replay its earlier rows to rebuild it and recount each row once.
        if replay_projection {
            return Ok(Self::default());
        }
        Ok(Self {
            field_index: usize::try_from(cursor["field_index"].as_u64().unwrap_or(0))?,
            after: cursor["after_id"]
                .as_str()
                .and_then(|value| Uuid::parse_str(value).ok())
                .unwrap_or(Uuid::nil()),
            progress: serde_json::from_value(progress)?,
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
            "tokens_rewritten":1,"by_key_id":{"previous":1},
            "fields":{"conversation_share_groups.name":{"processed":1,"rewrapped":1}}});
        let restored = Checkpoint::restore(true, cursor, progress).unwrap();
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
    }

    #[test]
    fn existing_encrypt_dry_run_keeps_its_saved_checkpoint() {
        let after = Uuid::new_v4();
        let restored = Checkpoint::restore(
            false,
            json!({"field_index":2,"after_id":after}),
            json!({"processed":7,"plaintext":7}),
        )
        .unwrap();
        assert_eq!(restored.field_index, 2);
        assert_eq!(restored.after, after);
        assert_eq!(restored.progress.totals.processed, 7);
        assert_eq!(restored.progress.totals.plaintext, 7);
    }

    #[test]
    fn persistent_execute_and_verify_results_resume_at_the_saved_row() {
        let after = Uuid::new_v4();
        let restored = Checkpoint::restore(
            false,
            json!({"field_index":3,"after_id":after}),
            json!({"processed":9,"rewrapped":4,"token_conflicts":1}),
        )
        .unwrap();
        assert_eq!(restored.field_index, 3);
        assert_eq!(restored.after, after);
        assert_eq!(restored.progress.totals.processed, 9);
        assert_eq!(restored.progress.totals.rewrapped, 4);
        assert_eq!(restored.progress.totals.token_conflicts, 1);
    }
}
