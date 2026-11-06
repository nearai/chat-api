use super::*;

const GROUP_NAME: FieldKey = ("conversation_share_groups", "name");
const MEMBER_VALUE: FieldKey = ("conversation_share_group_members", "member_value");

const fn id(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

#[test]
fn duplicate_projected_token_conflicts_across_batches() {
    // Given a completed batch whose first row successfully changes its token.
    let mut projection = Projection::default();
    assert!(projection.try_record(GROUP_NAME, id(1), [1; 32], &[], false));
    let next_batch_candidates = projection.projected_ids(GROUP_NAME, &[1; 32]);
    assert_eq!(next_batch_candidates, &[id(1)]);

    // When the next batch's scoped database lookup finds that projected row.
    let accepted = projection.try_record(GROUP_NAME, id(2), [1; 32], &[], true);

    // Then the new row conflicts and contributes no simulated rewrite.
    assert!(!accepted);
    assert_eq!(projection.projected_ids(GROUP_NAME, &[1; 32]), &[id(1)]);
}

#[test]
fn successful_rewrite_releases_its_stored_token() {
    // Given an earlier row that released its old stored token.
    let mut projection = Projection::default();
    assert!(projection.try_record(GROUP_NAME, id(1), [1; 32], &[], false));

    // When a later row wants the token still stored on that projected row.
    let accepted = projection.try_record(GROUP_NAME, id(2), [2; 32], &[id(1)], false);

    // Then the stored match is ignored and the replacement is tracked.
    assert!(accepted);
    assert_eq!(projection.projected_ids(GROUP_NAME, &[2; 32]), &[id(2)]);
}

#[test]
fn rejected_rewrite_does_not_release_its_stored_token() {
    // Given a rewrite blocked by an untouched row's stored token.
    let mut projection = Projection::default();
    assert!(!projection.try_record(GROUP_NAME, id(1), [1; 32], &[id(3)], false));
    assert!(projection.projected_ids(GROUP_NAME, &[1; 32]).is_empty());

    // When a later rewrite matches the rejected row's stored token.
    let accepted = projection.try_record(GROUP_NAME, id(2), [2; 32], &[id(1)], false);

    // Then that row still blocks it.
    assert!(!accepted);
}

#[test]
fn equal_tokens_in_different_unique_scopes_are_allowed() {
    // Given an equal projected token in a different owner/group/type scope.
    let mut projection = Projection::default();
    assert!(projection.try_record(GROUP_NAME, id(1), [1; 32], &[], false));
    assert_eq!(projection.projected_ids(GROUP_NAME, &[1; 32]), &[id(1)]);

    // When the database scoped lookup reports no matching projected row.
    let accepted = projection.try_record(GROUP_NAME, id(2), [1; 32], &[], false);

    // Then both scoped projections are retained for subsequent lookups.
    assert!(accepted);
    assert_eq!(
        projection.projected_ids(GROUP_NAME, &[1; 32]),
        &[id(1), id(2)]
    );
}

#[test]
fn projection_keys_isolate_fields_and_tables() {
    // Given projections in one table and one column.
    let mut projection = Projection::default();
    assert!(projection.try_record(GROUP_NAME, id(1), [1; 32], &[], false));
    let other_column = (GROUP_NAME.0, "other_column");
    assert!(projection.projected_ids(other_column, &[1; 32]).is_empty());
    assert!(projection.projected_ids(MEMBER_VALUE, &[1; 32]).is_empty());

    // When the same UUID is a real stored match for another table.
    let accepted = projection.try_record(MEMBER_VALUE, id(2), [2; 32], &[id(1)], false);

    // Then the other table's projected row cannot release this stored match.
    assert!(!accepted);
}

#[test]
fn field_transition_releases_tracking_for_the_next_field() {
    // Given a completed field.
    let mut projection = Projection::default();
    assert!(projection.try_record(GROUP_NAME, id(1), [1; 32], &[], false));

    // When the worker moves to its next field.
    projection.clear_field();

    // Then no old token or released row remains and exact mode is preserved.
    assert!(projection.projected_ids(GROUP_NAME, &[1; 32]).is_empty());
    assert!(!projection.estimated());
    assert!(!projection.try_record(GROUP_NAME, id(2), [2; 32], &[id(1)], false));
}

#[test]
fn field_transition_reuses_the_full_tracking_capacity() {
    // Given a field that consumed the complete tracking capacity.
    let mut projection = Projection::default();
    for row in 1..=100_000 {
        assert!(projection.try_record(GROUP_NAME, id(row), [1; 32], &[], false));
    }

    // When the next field starts with a fresh projection.
    projection.clear_field();
    assert!(projection.try_record(MEMBER_VALUE, id(1), [2; 32], &[], false));

    // Then its first row is tracked exactly without triggering overflow.
    assert!(!projection.estimated());
    assert_eq!(projection.projected_ids(MEMBER_VALUE, &[2; 32]), &[id(1)]);
}

#[test]
fn cap_is_exact_until_the_first_successful_overflow() {
    // Given exactly the maximum number of successfully tracked row projections.
    let mut projection = Projection::default();
    for row in 1..=100_000 {
        assert!(projection.try_record(GROUP_NAME, id(row), [1; 32], &[], false));
    }
    assert!(!projection.estimated());
    assert_eq!(
        projection.projected_ids(GROUP_NAME, &[1; 32]).len(),
        100_000
    );
    assert!(!projection.try_record(GROUP_NAME, id(100_001), [1; 32], &[], true));
    assert!(!projection.estimated());

    // When the first successful row exceeds the cap.
    assert!(projection.try_record(GROUP_NAME, id(100_001), [2; 32], &[], false));

    // Then tracking is discarded and estimation stays on across field changes.
    assert!(projection.estimated());
    assert!(projection.projected_ids(GROUP_NAME, &[1; 32]).is_empty());
    projection.clear_field();
    assert!(projection.estimated());
    assert!(projection.try_record(MEMBER_VALUE, id(1), [3; 32], &[], false));
    assert!(projection.projected_ids(MEMBER_VALUE, &[3; 32]).is_empty());
    assert!(!projection.try_record(MEMBER_VALUE, id(2), [3; 32], &[id(1)], false));
}
