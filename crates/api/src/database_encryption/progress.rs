use super::*;
use std::collections::BTreeMap;

#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
pub(super) struct Counters {
    pub(super) processed: i64,
    pub(super) encrypted: i64,
    pub(super) plaintext: i64,
    pub(super) legacy_encrypted: i64,
    pub(super) invalid_envelopes: i64,
    pub(super) rewrapped: i64,
    pub(super) already_current: i64,
    pub(super) stale: i64,
    pub(super) tokens_rewritten: i64,
    pub(super) token_conflicts: i64,
    pub(super) by_key_id: BTreeMap<String, i64>,
    pub(super) invalid_sample_ids: Vec<Uuid>,
    pub(super) token_conflict_sample_ids: Vec<Uuid>,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
pub(super) struct Progress {
    #[serde(flatten)]
    pub(super) totals: Counters,
    pub(super) fields: BTreeMap<String, Counters>,
}

impl Progress {
    pub(super) fn record(&mut self, field: &Field, update: impl Fn(&mut Counters)) {
        update(&mut self.totals);
        update(
            self.fields
                .entry(format!("{}.{}", field.table, field.column))
                .or_default(),
        );
    }

    pub(super) fn invalid(&mut self, field: &Field, id: Uuid) {
        self.record(field, |counts| {
            counts.invalid_envelopes += 1;
            sample(&mut counts.invalid_sample_ids, id);
        });
    }

    pub(super) fn conflict(&mut self, field: &Field, id: Uuid) {
        self.record(field, |counts| {
            counts.token_conflicts += 1;
            sample(&mut counts.token_conflict_sample_ids, id);
        });
    }
}

fn sample(ids: &mut Vec<Uuid>, id: Uuid) {
    if ids.len() < 10 {
        ids.push(id);
    }
}
