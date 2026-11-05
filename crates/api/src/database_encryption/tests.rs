use super::*;
#[test]
fn batch_delay_rejects_negative_and_excessive_values() {
    for delay in [-1, 10_001] {
        let request = json!({"mode":"dry_run","scope":{"tables":["files"]},"actions":["rewrap"],"batch_delay_ms":delay});
        assert!(
            serde_json::from_value::<CreateJobRequest>(request).is_err(),
            "invalid delay {delay} was accepted"
        );
    }
}

#[test]
fn registry_covers_required_stage_one_values() {
    for (table, column) in [
        ("files", "filename"),
        ("conversation_share_groups", "name"),
        ("conversation_share_group_members", "member_value"),
        ("conversation_shares", "recipient_value"),
        ("oauth_tokens", "access_token"),
        ("oauth_tokens", "refresh_token"),
        ("agent_instances", "auth_session_token"),
        ("agent_instances", "instance_url"),
        ("agent_instances", "dashboard_url"),
    ] {
        assert!(FIELDS
            .iter()
            .any(|field| field.table == table && field.column == column));
    }
}

#[test]
fn scope_rejects_unknown_fields_and_selects_registered_fields() {
    assert!(selected(&Scope {
        tables: vec!["unknown".into()],
        options: JobOptions::default(),
        fields: vec![]
    })
    .is_err());
    let fields = selected(&Scope {
        tables: vec![],
        options: JobOptions::default(),
        fields: vec![FieldName {
            table: "files".into(),
            column: "filename".into(),
        }],
    })
    .unwrap();
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].table, "files");
}

#[test]
fn opaque_provider_identifiers_are_explicitly_approved() {
    for (table, column) in [
        ("conversations", "id"),
        ("files", "id"),
        ("conversation_shares", "conversation_id"),
    ] {
        assert_eq!(
            classification(table, column, "character varying")
                .unwrap()
                .0,
            "approved_plaintext"
        );
        assert!(APPROVED
            .iter()
            .any(|(known_table, known_column, reason)| *known_table == table
                && *known_column == column
                && reason.contains("identifier")));
    }
}

#[test]
fn agent_credentials_use_the_legacy_aware_migration() {
    for (table, column) in [
        ("agent_instances", "instance_token"),
        ("user_passkey_credentials", "auth_secret"),
        ("user_passkey_credentials", "backup_passphrase"),
    ] {
        let (kind, _) = classification(table, column, "text").unwrap();
        assert_eq!(kind, "encrypt");
        let field = FIELDS
            .iter()
            .find(|field| field.table == table && field.column == column)
            .unwrap();
        assert!(matches!(field.kind, Kind::AgentSecret));
        if table == "user_passkey_credentials" {
            assert_eq!(row_id_expression(field, None), "user_id");
        }
    }
}

#[test]
fn wildcard_organization_patterns_remain_approved_plaintext() {
    let (kind, reason) = classification("conversation_shares", "org_email_pattern", "text")
        .expect("organization pattern is classified");
    assert_eq!(kind, "approved_plaintext");
    assert!(reason.contains("wildcard"));
    assert!(!FIELDS.iter().any(|field| {
        field.table == "conversation_shares" && field.column == "org_email_pattern"
    }));
}

#[test]
fn reviewed_fields_are_approved_for_plaintext_storage() {
    for (table, column) in [
        ("users", "email"),
        ("subscriptions", "customer_id"),
        ("aml_risk_reports", "result"),
    ] {
        let (kind, reason) = classification(table, column, "character varying").unwrap();
        assert_eq!(kind, "approved_plaintext");
        assert!(!reason.is_empty());
    }
    assert!(classification("new_unreviewed_table", "payload", "jsonb").is_none());
}

#[test]
fn disabled_write_gate_blocks_only_execute_batches() {
    assert!(write_gate_blocks("execute", false));
    assert!(!write_gate_blocks("execute", true));
    assert!(!write_gate_blocks("dry_run", false));
    assert!(!write_gate_blocks("verify", false));
}

#[test]
fn search_token_validation_rejects_missing_stale_and_copied_tokens() {
    let key = [7u8; 32];
    let field = FIELDS
        .iter()
        .find(|field| field.table == "conversation_shares" && field.column == "recipient_value")
        .unwrap();
    let token = database::field_encryption::search_token(
        &key,
        "conversation_shares.recipient_value",
        "user@example.com",
    )
    .unwrap();
    assert!(search_token_matches(
        &key,
        field,
        " User@Example.COM ",
        Some(&token)
    ));
    assert!(!search_token_matches(
        &key,
        field,
        "other@example.com",
        Some(&token)
    ));
    assert!(!search_token_matches(&key, field, "user@example.com", None));
}

#[test]
fn group_name_tokens_preserve_case_and_whitespace() {
    let domain = "conversation_share_groups.name";
    assert_eq!(normalized_token_value(domain, "Team"), "Team");
    assert_eq!(normalized_token_value(domain, "team"), "team");
    assert_eq!(normalized_token_value(domain, "Team "), "Team ");
}

#[test]
fn rewrap_actions_are_exclusive_and_match_mode() {
    for mode in [Mode::DryRun, Mode::Execute] {
        for action in ["encrypt", "rewrap"] {
            assert!(requests::validate_actions(&mode, &[action.into()]).is_ok());
        }
        for actions in [
            vec![],
            vec!["verify".into()],
            vec!["rewrap".into(), "encrypt".into()],
        ] {
            assert!(requests::validate_actions(&mode, &actions).is_err());
        }
    }
    assert!(requests::validate_actions(&Mode::Verify, &["verify".into()]).is_ok());
    assert!(requests::validate_actions(&Mode::Verify, &["rewrap".into()]).is_err());
}

#[test]
fn delay_is_bounded_and_persisted_as_job_options() {
    for delay in [0, 10_000] {
        let request: CreateJobRequest = serde_json::from_value(json!({"mode":"dry_run","scope":{"tables":["files"]},"actions":["rewrap"],"batch_delay_ms":delay})).unwrap();
        assert_eq!(request.batch_delay_ms, delay);
        let scope = Scope {
            options: JobOptions {
                batch_delay_ms: delay,
            },
            ..Scope::default()
        };
        let stored = serde_json::to_value(&scope).unwrap();
        assert_eq!(stored["options"]["batch_delay_ms"], delay);
        let restored: Scope = serde_json::from_value(stored).unwrap();
        assert_eq!(restored.options.batch_delay_ms, delay);
    }
    for delay in [-1, 10_001] {
        assert!(serde_json::from_value::<VerifyRequest>(json!({"batch_delay_ms":delay})).is_err());
    }
}

#[test]
fn per_field_progress_and_bounded_samples_survive_resume() {
    let field = &FIELDS[1];
    let mut progress = Progress::default();
    for _ in 0..20 {
        progress.invalid(field, Uuid::new_v4());
        progress.conflict(field, Uuid::new_v4());
    }
    let stored = serde_json::to_value(&progress).unwrap();
    let restored: Progress = serde_json::from_value(stored).unwrap();
    assert_eq!(restored.totals.invalid_envelopes, 20);
    assert_eq!(restored.totals.token_conflicts, 20);
    assert_eq!(restored.totals.invalid_sample_ids.len(), 10);
    assert_eq!(
        restored.fields["files.filename"]
            .token_conflict_sample_ids
            .len(),
        10
    );
}
