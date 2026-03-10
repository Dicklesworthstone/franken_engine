#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use frankenengine_engine::parser_evidence_indexer::{
    CorrelationKey, EvidenceIndexerError, IndexedParserEvent, PARSER_EVIDENCE_INDEX_SCHEMA_V1,
    ParserEvidenceIndexBuilder, ParserRunArtifactRef, SchemaMigrationStep,
};

fn manifest(run_id: &str, schema_version: &str, replay_command: &str) -> serde_json::Value {
    serde_json::json!({
        "schema_version": schema_version,
        "run_id": run_id,
        "replay_command": replay_command,
        "generated_at_utc": "2026-02-25T00:00:00Z",
        "outcome": "pass"
    })
}

#[test]
fn e2e_index_build_and_correlation_round_trip() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder
        .add_run(
            &manifest(
                "run-20260225-a",
                "franken-engine.parser-evidence-index.run.v1",
                "./scripts/replay_a.sh",
            ),
            "artifacts/a/run_manifest.json",
            "artifacts/a/events.jsonl",
            "artifacts/a/commands.txt",
        )
        .unwrap();
    builder
        .add_run(
            &manifest(
                "run-20260225-b",
                "franken-engine.parser-evidence-index.run.v1",
                "./scripts/replay_b.sh",
            ),
            "artifacts/b/run_manifest.json",
            "artifacts/b/events.jsonl",
            "artifacts/b/commands.txt",
        )
        .unwrap();

    let event_a = r#"{"schema_version":"franken-engine.parser-log-event.v1","trace_id":"trace-a","decision_id":"decision-a","policy_id":"policy-v1","component":"parser_evidence_indexer","event":"drift_detected","outcome":"fail","error_code":"FE-PARSER-DRIFT-0001","scenario_id":"fixture-foo","replay_command":"./scripts/replay_a.sh"}"#;
    let event_b = r#"{"schema_version":"franken-engine.parser-log-event.v1","trace_id":"trace-b","decision_id":"decision-b","policy_id":"policy-v1","component":"parser_evidence_indexer","event":"drift_detected","outcome":"fail","error_code":"FE-PARSER-DRIFT-0001","scenario_id":"fixture-foo","replay_command":"./scripts/replay_b.sh"}"#;

    builder.add_events_jsonl("run-20260225-a", event_a).unwrap();
    builder.add_events_jsonl("run-20260225-b", event_b).unwrap();

    let index = builder.build();
    let json = serde_json::to_string_pretty(&index).unwrap();
    let back: frankenengine_engine::parser_evidence_indexer::ParserEvidenceIndex =
        serde_json::from_str(&json).unwrap();

    assert_eq!(back.runs.len(), 2);
    assert_eq!(back.events.len(), 2);

    let clusters = back.correlate_regressions();
    assert_eq!(clusters.len(), 1);
    let cluster = &clusters[0];
    assert_eq!(cluster.run_count, 2);
    assert_eq!(cluster.occurrence_count, 2);
    assert_eq!(cluster.key.component, "parser_evidence_indexer");
    assert_eq!(cluster.key.event, "drift_detected");
    assert_eq!(
        cluster.key.error_code.as_deref(),
        Some("FE-PARSER-DRIFT-0001")
    );
    assert_eq!(cluster.key.scenario_id.as_deref(), Some("fixture-foo"));
}

#[test]
fn migration_pipeline_supports_multi_hop_event_upgrade() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder
        .add_run(
            &manifest(
                "run-20260225-migrate",
                "franken-engine.parser-evidence-index.run.v1",
                "./scripts/replay_migrate.sh",
            ),
            "artifacts/m/run_manifest.json",
            "artifacts/m/events.jsonl",
            "artifacts/m/commands.txt",
        )
        .unwrap();

    let events = r#"
{"schema_version":"franken-engine.parser-log-event.v1","trace_id":"trace-1","decision_id":"decision-1","policy_id":"policy-v1","component":"parser_evidence_indexer","event":"index_started","outcome":"pass","error_code":null}
{"schema_version":"franken-engine.parser-log-event.v1","trace_id":"trace-2","decision_id":"decision-2","policy_id":"policy-v1","component":"parser_evidence_indexer","event":"index_finished","outcome":"pass","error_code":null}
"#;
    builder
        .add_events_jsonl("run-20260225-migrate", events)
        .unwrap();

    let mut index = builder.build();
    let receipts = index
        .migrate_event_schemas(
            "franken-engine.parser-log-event.v3",
            &[
                SchemaMigrationStep {
                    migration_id: "mig-parser-log-v1-v2".to_string(),
                    from_schema: "franken-engine.parser-log-event.v1".to_string(),
                    to_schema: "franken-engine.parser-log-event.v2".to_string(),
                },
                SchemaMigrationStep {
                    migration_id: "mig-parser-log-v2-v3".to_string(),
                    from_schema: "franken-engine.parser-log-event.v2".to_string(),
                    to_schema: "franken-engine.parser-log-event.v3".to_string(),
                },
            ],
        )
        .unwrap();

    assert_eq!(receipts.len(), 2);
    assert!(
        index
            .events
            .iter()
            .all(|event| event.schema_version == "franken-engine.parser-log-event.v3")
    );
    assert!(index.schema_migrations.is_empty());
}

#[test]
fn deterministic_ordering_is_stable_across_insertion_order() {
    let mut left = ParserEvidenceIndexBuilder::new();
    left.add_run(
        &manifest(
            "run-z",
            "franken-engine.parser-evidence-index.run.v1",
            "./scripts/replay_z.sh",
        ),
        "artifacts/z/run_manifest.json",
        "artifacts/z/events.jsonl",
        "artifacts/z/commands.txt",
    )
    .unwrap();
    left.add_run(
        &manifest(
            "run-a",
            "franken-engine.parser-evidence-index.run.v1",
            "./scripts/replay_a.sh",
        ),
        "artifacts/a/run_manifest.json",
        "artifacts/a/events.jsonl",
        "artifacts/a/commands.txt",
    )
    .unwrap();

    left.add_events_jsonl(
        "run-z",
        r#"{"schema_version":"franken-engine.parser-log-event.v1","trace_id":"trace-z","decision_id":"decision-z","policy_id":"policy-v1","component":"idx","event":"done","outcome":"pass","error_code":null}"#,
    )
    .unwrap();
    left.add_events_jsonl(
        "run-a",
        r#"{"schema_version":"franken-engine.parser-log-event.v1","trace_id":"trace-a","decision_id":"decision-a","policy_id":"policy-v1","component":"idx","event":"done","outcome":"pass","error_code":null}"#,
    )
    .unwrap();

    let left_index = left.build();

    let mut right = ParserEvidenceIndexBuilder::new();
    right
        .add_run(
            &manifest(
                "run-a",
                "franken-engine.parser-evidence-index.run.v1",
                "./scripts/replay_a.sh",
            ),
            "artifacts/a/run_manifest.json",
            "artifacts/a/events.jsonl",
            "artifacts/a/commands.txt",
        )
        .unwrap();
    right
        .add_run(
            &manifest(
                "run-z",
                "franken-engine.parser-evidence-index.run.v1",
                "./scripts/replay_z.sh",
            ),
            "artifacts/z/run_manifest.json",
            "artifacts/z/events.jsonl",
            "artifacts/z/commands.txt",
        )
        .unwrap();

    right
        .add_events_jsonl(
            "run-a",
            r#"{"schema_version":"franken-engine.parser-log-event.v1","trace_id":"trace-a","decision_id":"decision-a","policy_id":"policy-v1","component":"idx","event":"done","outcome":"pass","error_code":null}"#,
        )
        .unwrap();
    right
        .add_events_jsonl(
            "run-z",
            r#"{"schema_version":"franken-engine.parser-log-event.v1","trace_id":"trace-z","decision_id":"decision-z","policy_id":"policy-v1","component":"idx","event":"done","outcome":"pass","error_code":null}"#,
        )
        .unwrap();

    let right_index = right.build();

    let left_json = serde_json::to_string(&left_index).unwrap();
    let right_json = serde_json::to_string(&right_index).unwrap();
    assert_eq!(left_json, right_json);
}

// ────────────────────────────────────────────────────────────
// Enrichment: serde, error display, validation, edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn evidence_indexer_error_display_all_variants() {
    let errors: Vec<EvidenceIndexerError> = vec![
        EvidenceIndexerError::MissingField("schema_version"),
        EvidenceIndexerError::InvalidFieldType {
            field: "run_id",
            expected: "string",
        },
        EvidenceIndexerError::DuplicateRunId("run-001".to_string()),
        EvidenceIndexerError::UnknownRunId("run-unknown".to_string()),
        EvidenceIndexerError::InvalidSchemaVersion("bad-version".to_string()),
        EvidenceIndexerError::IncompatibleSchemaFamily {
            from_schema: "family-a.v1".to_string(),
            to_schema: "family-b.v2".to_string(),
        },
        EvidenceIndexerError::NoMigrationPath {
            from_schema: "a.v1".to_string(),
            to_schema: "a.v5".to_string(),
        },
        EvidenceIndexerError::Json("parse error".to_string()),
    ];
    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.is_empty(), "error display must not be empty: {err:?}");
    }
}

#[test]
fn parser_run_artifact_ref_serde_round_trip() {
    let artifact = ParserRunArtifactRef {
        run_id: "run-001".to_string(),
        manifest_schema_version: "franken-engine.parser-evidence-index.run.v1".to_string(),
        manifest_path: "artifacts/run_manifest.json".to_string(),
        events_path: "artifacts/events.jsonl".to_string(),
        commands_path: "artifacts/commands.txt".to_string(),
        replay_command: "./scripts/replay.sh".to_string(),
        generated_at_utc: Some("2026-02-25T00:00:00Z".to_string()),
        outcome: Some("pass".to_string()),
    };
    let json = serde_json::to_string(&artifact).expect("serialize");
    let recovered: ParserRunArtifactRef = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(artifact, recovered);
}

#[test]
fn indexed_parser_event_serde_round_trip() {
    let event = IndexedParserEvent {
        run_id: "run-001".to_string(),
        sequence: 0,
        schema_version: "franken-engine.parser-log-event.v1".to_string(),
        trace_id: "trace-001".to_string(),
        decision_id: "decision-001".to_string(),
        policy_id: "policy-v1".to_string(),
        component: "parser_evidence_indexer".to_string(),
        event: "drift_detected".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("FE-PARSER-DRIFT-0001".to_string()),
        replay_command: Some("./scripts/replay.sh".to_string()),
        scenario_id: Some("fixture-foo".to_string()),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: IndexedParserEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, recovered);
}

#[test]
fn correlation_key_ordering_is_deterministic() {
    let a = CorrelationKey {
        component: "a".to_string(),
        event: "x".to_string(),
        scenario_id: None,
        error_code: None,
        outcome: "fail".to_string(),
    };
    let b = CorrelationKey {
        component: "b".to_string(),
        event: "x".to_string(),
        scenario_id: None,
        error_code: None,
        outcome: "fail".to_string(),
    };
    assert!(a < b);
}

#[test]
fn schema_migration_step_serde_round_trip() {
    let step = SchemaMigrationStep {
        migration_id: "mig-v1-v2".to_string(),
        from_schema: "franken-engine.parser-log-event.v1".to_string(),
        to_schema: "franken-engine.parser-log-event.v2".to_string(),
    };
    let json = serde_json::to_string(&step).expect("serialize");
    let recovered: SchemaMigrationStep = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(step, recovered);
}

#[test]
fn parser_evidence_index_schema_constant_is_well_formed() {
    assert!(PARSER_EVIDENCE_INDEX_SCHEMA_V1.starts_with("franken-engine."));
    assert!(PARSER_EVIDENCE_INDEX_SCHEMA_V1.contains(".v1"));
}

#[test]
fn builder_rejects_duplicate_run_id() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder
        .add_run(
            &manifest(
                "run-dup",
                "franken-engine.parser-evidence-index.run.v1",
                "./scripts/replay.sh",
            ),
            "artifacts/a/run_manifest.json",
            "artifacts/a/events.jsonl",
            "artifacts/a/commands.txt",
        )
        .unwrap();
    let err = builder
        .add_run(
            &manifest(
                "run-dup",
                "franken-engine.parser-evidence-index.run.v1",
                "./scripts/replay2.sh",
            ),
            "artifacts/b/run_manifest.json",
            "artifacts/b/events.jsonl",
            "artifacts/b/commands.txt",
        )
        .expect_err("duplicate run_id should fail");
    assert!(err.to_string().contains("run-dup"));
}

#[test]
fn builder_rejects_events_for_unknown_run_id() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    let err = builder
        .add_events_jsonl(
            "run-nonexistent",
            r#"{"schema_version":"franken-engine.parser-log-event.v1","trace_id":"t","decision_id":"d","policy_id":"p","component":"c","event":"e","outcome":"pass","error_code":null}"#,
        )
        .expect_err("unknown run_id should fail");
    assert!(err.to_string().contains("run-nonexistent"));
}

#[test]
fn empty_index_correlates_to_no_regressions() {
    let builder = ParserEvidenceIndexBuilder::new();
    let index = builder.build();
    assert!(index.runs.is_empty());
    assert!(index.events.is_empty());
    let clusters = index.correlate_regressions();
    assert!(clusters.is_empty());
}

#[test]
fn correlation_key_serde_roundtrip() {
    let key = CorrelationKey {
        component: "parser_evidence_indexer".to_string(),
        event: "drift_detected".to_string(),
        scenario_id: Some("fixture-foo".to_string()),
        error_code: Some("FE-PARSER-DRIFT-0001".to_string()),
        outcome: "fail".to_string(),
    };
    let json = serde_json::to_string(&key).expect("serialize");
    let recovered: CorrelationKey = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(key, recovered);
}

#[test]
fn builder_build_produces_correct_schema_version() {
    let builder = ParserEvidenceIndexBuilder::new();
    let index = builder.build();
    assert_eq!(index.schema_version, PARSER_EVIDENCE_INDEX_SCHEMA_V1);
}

#[test]
fn single_run_single_pass_event_produces_no_regression_clusters() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder
        .add_run(
            &manifest(
                "run-pass-only",
                "franken-engine.parser-evidence-index.run.v1",
                "./scripts/replay_pass.sh",
            ),
            "artifacts/p/run_manifest.json",
            "artifacts/p/events.jsonl",
            "artifacts/p/commands.txt",
        )
        .unwrap();
    builder
        .add_events_jsonl(
            "run-pass-only",
            r#"{"schema_version":"franken-engine.parser-log-event.v1","trace_id":"t","decision_id":"d","policy_id":"p","component":"c","event":"done","outcome":"pass","error_code":null}"#,
        )
        .unwrap();
    let index = builder.build();
    assert_eq!(index.runs.len(), 1);
    assert_eq!(index.events.len(), 1);
    let clusters = index.correlate_regressions();
    assert!(clusters.is_empty());
}

#[test]
fn parser_evidence_index_schema_constant_is_non_empty() {
    assert!(!PARSER_EVIDENCE_INDEX_SCHEMA_V1.trim().is_empty());
}

#[test]
fn correlation_key_serde_round_trip() {
    let key = CorrelationKey {
        component: "parser".to_string(),
        event: "gate_completed".to_string(),
        scenario_id: Some("s1".to_string()),
        error_code: None,
        outcome: "pass".to_string(),
    };
    let json = serde_json::to_string(&key).expect("serialize");
    let recovered: CorrelationKey = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(key, recovered);
}

#[test]
fn evidence_indexer_error_debug_is_non_empty() {
    let err = EvidenceIndexerError::MissingField("test_field");
    assert!(!format!("{err:?}").is_empty());
}

#[test]
fn indexed_parser_event_serde_roundtrip() {
    let event = IndexedParserEvent {
        run_id: "run-1".to_string(),
        sequence: 0,
        schema_version: PARSER_EVIDENCE_INDEX_SCHEMA_V1.to_string(),
        trace_id: "trace-1".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: "policy-1".to_string(),
        component: "parser".to_string(),
        event: "gate_completed".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        replay_command: None,
        scenario_id: Some("s1".to_string()),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: IndexedParserEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.run_id, "run-1");
}

#[test]
fn parser_run_artifact_ref_serde_roundtrip() {
    let ref_ = ParserRunArtifactRef {
        run_id: "run-1".to_string(),
        manifest_schema_version: PARSER_EVIDENCE_INDEX_SCHEMA_V1.to_string(),
        manifest_path: "path/to/manifest.json".to_string(),
        events_path: "path/to/events.jsonl".to_string(),
        commands_path: "path/to/commands.jsonl".to_string(),
        replay_command: "./replay.sh".to_string(),
        generated_at_utc: Some("2026-02-25T00:00:00Z".to_string()),
        outcome: Some("pass".to_string()),
    };
    let json = serde_json::to_string(&ref_).expect("serialize");
    let recovered: ParserRunArtifactRef = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.run_id, "run-1");
}

#[test]
fn empty_builder_produces_empty_index() {
    let builder = ParserEvidenceIndexBuilder::new();
    let index = builder.build();
    assert!(index.runs.is_empty());
    assert!(index.events.is_empty());
}

#[test]
fn schema_migration_step_debug_is_nonempty() {
    let step = SchemaMigrationStep {
        migration_id: "mig-debug".to_string(),
        from_schema: "v1".to_string(),
        to_schema: "v2".to_string(),
    };
    assert!(!format!("{step:?}").is_empty());
}

#[test]
fn indexed_parser_event_debug_is_nonempty() {
    let event = IndexedParserEvent {
        run_id: "run-dbg".to_string(),
        sequence: 0,
        schema_version: PARSER_EVIDENCE_INDEX_SCHEMA_V1.to_string(),
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        replay_command: None,
        scenario_id: None,
    };
    assert!(!format!("{event:?}").is_empty());
}

#[test]
fn parser_run_artifact_ref_debug_is_nonempty() {
    let ref_ = ParserRunArtifactRef {
        run_id: "run-dbg".to_string(),
        manifest_schema_version: PARSER_EVIDENCE_INDEX_SCHEMA_V1.to_string(),
        manifest_path: "m.json".to_string(),
        events_path: "e.jsonl".to_string(),
        commands_path: "c.txt".to_string(),
        replay_command: "./replay.sh".to_string(),
        generated_at_utc: None,
        outcome: None,
    };
    assert!(!format!("{ref_:?}").is_empty());
}

// ---------- Enrichment: additional edge cases ----------

#[test]
fn correlation_key_with_none_fields_round_trips() {
    let key = CorrelationKey {
        component: "comp".to_string(),
        event: "evt".to_string(),
        scenario_id: None,
        error_code: None,
        outcome: "pass".to_string(),
    };
    let json = serde_json::to_string(&key).expect("serialize");
    let recovered: CorrelationKey = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(key, recovered);
    assert!(recovered.scenario_id.is_none());
    assert!(recovered.error_code.is_none());
}

#[test]
fn indexed_parser_event_sequence_ordering() {
    let event_a = IndexedParserEvent {
        run_id: "run-1".to_string(),
        sequence: 0,
        schema_version: PARSER_EVIDENCE_INDEX_SCHEMA_V1.to_string(),
        trace_id: "t-a".to_string(),
        decision_id: "d-a".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        replay_command: None,
        scenario_id: None,
    };
    let event_b = IndexedParserEvent {
        run_id: "run-1".to_string(),
        sequence: 1,
        schema_version: PARSER_EVIDENCE_INDEX_SCHEMA_V1.to_string(),
        trace_id: "t-b".to_string(),
        decision_id: "d-b".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        replay_command: None,
        scenario_id: None,
    };
    assert!(event_a.sequence < event_b.sequence);
}

#[test]
fn multiple_events_per_run_are_indexed() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder
        .add_run(
            &manifest(
                "run-multi",
                "franken-engine.parser-evidence-index.run.v1",
                "./scripts/replay_multi.sh",
            ),
            "artifacts/m/run_manifest.json",
            "artifacts/m/events.jsonl",
            "artifacts/m/commands.txt",
        )
        .unwrap();

    let events = [
        r#"{"schema_version":"franken-engine.parser-log-event.v1","trace_id":"t1","decision_id":"d1","policy_id":"p","component":"c","event":"start","outcome":"pass","error_code":null}"#,
        r#"{"schema_version":"franken-engine.parser-log-event.v1","trace_id":"t2","decision_id":"d2","policy_id":"p","component":"c","event":"end","outcome":"pass","error_code":null}"#,
    ]
    .join("\n");
    builder.add_events_jsonl("run-multi", &events).unwrap();

    let index = builder.build();
    assert_eq!(index.events.len(), 2);
    assert_eq!(index.events[0].sequence, 0);
    assert_eq!(index.events[1].sequence, 1);
}

#[test]
fn parser_run_artifact_ref_optional_fields_none_serde() {
    let ref_ = ParserRunArtifactRef {
        run_id: "run-none-fields".to_string(),
        manifest_schema_version: PARSER_EVIDENCE_INDEX_SCHEMA_V1.to_string(),
        manifest_path: "m.json".to_string(),
        events_path: "e.jsonl".to_string(),
        commands_path: "c.txt".to_string(),
        replay_command: "./replay.sh".to_string(),
        generated_at_utc: None,
        outcome: None,
    };
    let json = serde_json::to_string(&ref_).expect("serialize");
    let recovered: ParserRunArtifactRef = serde_json::from_str(&json).expect("deserialize");
    assert!(recovered.generated_at_utc.is_none());
    assert!(recovered.outcome.is_none());
}

#[test]
fn index_full_serde_roundtrip() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder
        .add_run(
            &manifest(
                "run-rt",
                "franken-engine.parser-evidence-index.run.v1",
                "./scripts/replay_rt.sh",
            ),
            "artifacts/rt/run_manifest.json",
            "artifacts/rt/events.jsonl",
            "artifacts/rt/commands.txt",
        )
        .unwrap();
    builder
        .add_events_jsonl(
            "run-rt",
            r#"{"schema_version":"franken-engine.parser-log-event.v1","trace_id":"trt","decision_id":"drt","policy_id":"prt","component":"crt","event":"done","outcome":"pass","error_code":null}"#,
        )
        .unwrap();

    let index = builder.build();
    let json = serde_json::to_string_pretty(&index).unwrap();
    let recovered: frankenengine_engine::parser_evidence_indexer::ParserEvidenceIndex =
        serde_json::from_str(&json).unwrap();
    assert_eq!(index.schema_version, recovered.schema_version);
    assert_eq!(index.runs.len(), recovered.runs.len());
    assert_eq!(index.events.len(), recovered.events.len());
}

#[test]
fn evidence_indexer_error_json_variant_display() {
    let err = EvidenceIndexerError::Json("unexpected token at position 42".to_string());
    let msg = err.to_string();
    assert!(msg.contains("42"), "error message should contain detail");
}

#[test]
fn correlation_key_equality() {
    let key1 = CorrelationKey {
        component: "parser".to_string(),
        event: "drift".to_string(),
        scenario_id: Some("s1".to_string()),
        error_code: Some("E001".to_string()),
        outcome: "fail".to_string(),
    };
    let key2 = key1.clone();
    assert_eq!(key1, key2);
}
