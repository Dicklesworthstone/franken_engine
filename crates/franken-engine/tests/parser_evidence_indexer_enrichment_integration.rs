#![allow(clippy::too_many_arguments)]

use std::collections::BTreeSet;

use frankenengine_engine::parser_evidence_indexer::{
    AppliedSchemaMigration, CorrelatedRegression, CorrelationKey, EvidenceIndexerError,
    IndexedParserEvent, ParserEvidenceIndex, ParserEvidenceIndexBuilder, ParserRunArtifactRef,
    SchemaMigrationBoundary, SchemaMigrationStep, SchemaVersionTag,
    PARSER_EVIDENCE_INDEX_SCHEMA_V1,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn manifest(run_id: &str, schema: &str, replay: &str) -> serde_json::Value {
    serde_json::json!({
        "schema_version": schema,
        "run_id": run_id,
        "replay_command": replay,
        "generated_at_utc": "2026-03-19T00:00:00Z",
        "outcome": "pass"
    })
}

fn make_event_jsonl(run_id: &str, schema: &str, component: &str, outcome: &str) -> String {
    format!(
        "{{\"schema_version\":\"{schema}\",\"trace_id\":\"t-{run_id}\",\"decision_id\":\"d-{run_id}\",\"policy_id\":\"p\",\"component\":\"{component}\",\"event\":\"check\",\"outcome\":\"{outcome}\"}}"
    )
}

fn make_fail_event_jsonl(run_id: &str, error_code: &str) -> String {
    format!(
        "{{\"schema_version\":\"fam.event.v1\",\"trace_id\":\"t-{run_id}\",\"decision_id\":\"d-{run_id}\",\"policy_id\":\"p\",\"component\":\"gate\",\"event\":\"fail_check\",\"outcome\":\"fail\",\"error_code\":\"{error_code}\"}}"
    )
}

// ---------------------------------------------------------------------------
// Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn serde_roundtrip_schema_version_tag() {
    let tag = SchemaVersionTag::parse("franken-engine.parser-log-event.v12").unwrap();
    let json = serde_json::to_string(&tag).unwrap();
    let back: SchemaVersionTag = serde_json::from_str(&json).unwrap();
    assert_eq!(tag, back);
}

#[test]
fn serde_roundtrip_parser_run_artifact_ref() {
    let artifact = ParserRunArtifactRef {
        run_id: "run-1".into(),
        manifest_schema_version: "fam.run.v1".into(),
        manifest_path: "path/manifest.json".into(),
        events_path: "path/events.jsonl".into(),
        commands_path: "path/commands.sh".into(),
        replay_command: "replay --run run-1".into(),
        generated_at_utc: Some("2026-03-19T00:00:00Z".into()),
        outcome: Some("pass".into()),
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let back: ParserRunArtifactRef = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, back);
}

#[test]
fn serde_roundtrip_indexed_parser_event() {
    let event = IndexedParserEvent {
        run_id: "run-1".into(),
        sequence: 7,
        schema_version: "fam.event.v1".into(),
        trace_id: "t-1".into(),
        decision_id: "d-1".into(),
        policy_id: "pol-1".into(),
        component: "parser".into(),
        event: "parse_complete".into(),
        outcome: "pass".into(),
        error_code: None,
        replay_command: Some("replay --run run-1".into()),
        scenario_id: Some("scen-1".into()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: IndexedParserEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn serde_roundtrip_schema_migration_boundary() {
    let boundary = SchemaMigrationBoundary {
        run_id: "run-1".into(),
        sequence: 42,
        from_schema: "fam.event.v1".into(),
        to_schema: "fam.event.v2".into(),
    };
    let json = serde_json::to_string(&boundary).unwrap();
    let back: SchemaMigrationBoundary = serde_json::from_str(&json).unwrap();
    assert_eq!(boundary, back);
}

#[test]
fn serde_roundtrip_schema_migration_step() {
    let step = SchemaMigrationStep {
        migration_id: "mig-1".into(),
        from_schema: "fam.event.v1".into(),
        to_schema: "fam.event.v2".into(),
    };
    let json = serde_json::to_string(&step).unwrap();
    let back: SchemaMigrationStep = serde_json::from_str(&json).unwrap();
    assert_eq!(step, back);
}

#[test]
fn serde_roundtrip_applied_schema_migration() {
    let m = AppliedSchemaMigration {
        migration_id: "mig-1".into(),
        from_schema: "fam.v1".into(),
        to_schema: "fam.v2".into(),
        affected_records: 42,
    };
    let json = serde_json::to_string(&m).unwrap();
    let back: AppliedSchemaMigration = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn serde_roundtrip_correlation_key() {
    let key = CorrelationKey {
        component: "parser".into(),
        event: "drift".into(),
        scenario_id: Some("s1".into()),
        error_code: Some("E01".into()),
        outcome: "fail".into(),
    };
    let json = serde_json::to_string(&key).unwrap();
    let back: CorrelationKey = serde_json::from_str(&json).unwrap();
    assert_eq!(key, back);
}

#[test]
fn serde_roundtrip_correlated_regression() {
    let cr = CorrelatedRegression {
        key: CorrelationKey {
            component: "parser".into(),
            event: "drift".into(),
            scenario_id: None,
            error_code: Some("E01".into()),
            outcome: "fail".into(),
        },
        run_count: 3,
        occurrence_count: 7,
        run_ids: vec!["r1".into(), "r2".into()],
        trace_ids: vec!["t1".into()],
        replay_commands: vec!["cmd".into()],
        severity: "high".into(),
    };
    let json = serde_json::to_string(&cr).unwrap();
    let back: CorrelatedRegression = serde_json::from_str(&json).unwrap();
    assert_eq!(cr, back);
}

#[test]
fn serde_roundtrip_parser_evidence_index_empty() {
    let index = ParserEvidenceIndex {
        schema_version: PARSER_EVIDENCE_INDEX_SCHEMA_V1.to_string(),
        runs: vec![],
        events: vec![],
        schema_migrations: vec![],
    };
    let json = serde_json::to_string(&index).unwrap();
    let back: ParserEvidenceIndex = serde_json::from_str(&json).unwrap();
    assert_eq!(index, back);
}

// ---------------------------------------------------------------------------
// SchemaVersionTag parsing
// ---------------------------------------------------------------------------

#[test]
fn schema_version_parse_ok() {
    let tag = SchemaVersionTag::parse("franken-engine.parser-log-event.v12").unwrap();
    assert_eq!(tag.family, "franken-engine.parser-log-event");
    assert_eq!(tag.major, 12);
}

#[test]
fn schema_version_parse_zero_major() {
    let tag = SchemaVersionTag::parse("fam.v0").unwrap();
    assert_eq!(tag.major, 0);
}

#[test]
fn schema_version_parse_large_major() {
    let tag = SchemaVersionTag::parse("franken-engine.v999999").unwrap();
    assert_eq!(tag.major, 999_999);
}

#[test]
fn schema_version_parse_rejects_no_dot_v() {
    let err = SchemaVersionTag::parse("family-v1").unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::InvalidSchemaVersion(_)));
}

#[test]
fn schema_version_parse_rejects_empty_family() {
    let err = SchemaVersionTag::parse(".v1").unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::InvalidSchemaVersion(_)));
}

#[test]
fn schema_version_parse_rejects_non_numeric_major() {
    let err = SchemaVersionTag::parse("family.vabc").unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::InvalidSchemaVersion(_)));
}

#[test]
fn schema_version_tag_ordering() {
    let a = SchemaVersionTag::parse("alpha.v1").unwrap();
    let b = SchemaVersionTag::parse("alpha.v2").unwrap();
    let c = SchemaVersionTag::parse("beta.v1").unwrap();
    assert!(a < b);
    assert!(a < c);
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

#[test]
fn builder_empty_index() {
    let builder = ParserEvidenceIndexBuilder::new();
    let index = builder.build();
    assert_eq!(index.schema_version, PARSER_EVIDENCE_INDEX_SCHEMA_V1);
    assert!(index.runs.is_empty());
    assert!(index.events.is_empty());
    assert!(index.schema_migrations.is_empty());
}

#[test]
fn builder_sorts_runs_by_id() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder
        .add_run(
            &manifest("run-b", "fam.run.v1", "replay-b"),
            "mb.json",
            "eb.jsonl",
            "cb.txt",
        )
        .unwrap();
    builder
        .add_run(
            &manifest("run-a", "fam.run.v1", "replay-a"),
            "ma.json",
            "ea.jsonl",
            "ca.txt",
        )
        .unwrap();
    let index = builder.build();
    assert_eq!(index.runs[0].run_id, "run-a");
    assert_eq!(index.runs[1].run_id, "run-b");
}

#[test]
fn builder_duplicate_run_id_rejected() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder
        .add_run(
            &manifest("run-a", "fam.run.v1", "replay-a"),
            "m.json",
            "e.jsonl",
            "c.txt",
        )
        .unwrap();
    let err = builder
        .add_run(
            &manifest("run-a", "fam.run.v1", "replay-a2"),
            "m2.json",
            "e2.jsonl",
            "c2.txt",
        )
        .unwrap_err();
    assert!(matches!(
        err,
        EvidenceIndexerError::DuplicateRunId(id) if id == "run-a"
    ));
}

#[test]
fn builder_events_for_unknown_run_rejected() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    let err = builder
        .add_events_jsonl("nonexistent", &make_event_jsonl("x", "fam.v1", "c", "pass"))
        .unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::UnknownRunId(_)));
}

#[test]
fn builder_skips_blank_lines_in_jsonl() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder
        .add_run(
            &manifest("run-a", "fam.run.v1", "replay"),
            "m.json",
            "e.jsonl",
            "c.txt",
        )
        .unwrap();
    let jsonl = format!(
        "\n  \n{}\n\n",
        make_event_jsonl("run-a", "fam.event.v1", "c", "pass")
    );
    builder.add_events_jsonl("run-a", &jsonl).unwrap();
    let index = builder.build();
    assert_eq!(index.events.len(), 1);
}

#[test]
fn builder_events_sequence_monotonically_increases() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder
        .add_run(
            &manifest("run-a", "fam.run.v1", "replay"),
            "m.json",
            "e.jsonl",
            "c.txt",
        )
        .unwrap();
    builder
        .add_events_jsonl(
            "run-a",
            &make_event_jsonl("run-a", "fam.event.v1", "c", "pass"),
        )
        .unwrap();
    builder
        .add_events_jsonl(
            "run-a",
            &make_event_jsonl("run-a", "fam.event.v1", "c", "pass"),
        )
        .unwrap();
    let index = builder.build();
    assert_eq!(index.events[0].sequence, 0);
    assert_eq!(index.events[1].sequence, 1);
}

// ---------------------------------------------------------------------------
// Correlation
// ---------------------------------------------------------------------------

#[test]
fn correlate_regressions_clusters_repeated_failures() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    for run_id in ["run-a", "run-b"] {
        builder
            .add_run(
                &manifest(run_id, "fam.run.v1", &format!("replay-{run_id}")),
                format!("{run_id}-m.json"),
                format!("{run_id}-e.jsonl"),
                format!("{run_id}-c.txt"),
            )
            .unwrap();
        builder
            .add_events_jsonl(run_id, &make_fail_event_jsonl(run_id, "FE-DRIFT"))
            .unwrap();
    }
    let index = builder.build();
    let clusters = index.correlate_regressions();
    assert_eq!(clusters.len(), 1);
    assert_eq!(clusters[0].run_count, 2);
    assert_eq!(clusters[0].severity, "high");
}

#[test]
fn correlate_regressions_ignores_single_run_failures() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder
        .add_run(
            &manifest("run-a", "fam.run.v1", "replay-a"),
            "m.json",
            "e.jsonl",
            "c.txt",
        )
        .unwrap();
    builder
        .add_events_jsonl("run-a", &make_fail_event_jsonl("run-a", "E01"))
        .unwrap();
    let index = builder.build();
    assert!(index.correlate_regressions().is_empty());
}

#[test]
fn correlate_regressions_ignores_pass_events() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    for run_id in ["run-a", "run-b"] {
        builder
            .add_run(
                &manifest(run_id, "fam.run.v1", &format!("replay-{run_id}")),
                format!("{run_id}-m.json"),
                format!("{run_id}-e.jsonl"),
                format!("{run_id}-c.txt"),
            )
            .unwrap();
        builder
            .add_events_jsonl(
                run_id,
                &make_event_jsonl(run_id, "fam.event.v1", "gate", "pass"),
            )
            .unwrap();
    }
    let index = builder.build();
    assert!(index.correlate_regressions().is_empty());
}

#[test]
fn correlate_regressions_sorted_by_occurrence_desc() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    for run_id in ["run-a", "run-b"] {
        builder
            .add_run(
                &manifest(run_id, "fam.run.v1", &format!("replay-{run_id}")),
                format!("{run_id}-m.json"),
                format!("{run_id}-e.jsonl"),
                format!("{run_id}-c.txt"),
            )
            .unwrap();
        let ev_a = format!(
            "{{\"schema_version\":\"fam.event.v1\",\"trace_id\":\"ta-{run_id}\",\"decision_id\":\"da\",\"policy_id\":\"p\",\"component\":\"gate\",\"event\":\"check_a\",\"outcome\":\"fail\"}}"
        );
        builder.add_events_jsonl(run_id, &ev_a).unwrap();
        let ev_b = format!(
            "{{\"schema_version\":\"fam.event.v1\",\"trace_id\":\"tb-{run_id}\",\"decision_id\":\"db\",\"policy_id\":\"p\",\"component\":\"gate\",\"event\":\"check_b\",\"outcome\":\"fail\"}}"
        );
        builder.add_events_jsonl(run_id, &ev_b).unwrap();
    }
    builder
        .add_events_jsonl(
            "run-a",
            r#"{"schema_version":"fam.event.v1","trace_id":"tb-a-extra","decision_id":"db","policy_id":"p","component":"gate","event":"check_b","outcome":"fail"}"#,
        )
        .unwrap();
    let index = builder.build();
    let clusters = index.correlate_regressions();
    assert!(clusters[0].occurrence_count >= clusters[1].occurrence_count);
}

// ---------------------------------------------------------------------------
// Schema compatibility validation
// ---------------------------------------------------------------------------

#[test]
fn validate_schema_compatibility_accepts_same_version() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder
        .add_run(
            &manifest("run-a", "fam.run.v1", "replay"),
            "m.json",
            "e.jsonl",
            "c.txt",
        )
        .unwrap();
    builder
        .add_events_jsonl(
            "run-a",
            &make_event_jsonl("run-a", "fam.event.v2", "c", "pass"),
        )
        .unwrap();
    let index = builder.build();
    index
        .validate_event_schema_compatibility("fam.event.v2")
        .unwrap();
}

#[test]
fn validate_schema_compatibility_rejects_newer_major() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder
        .add_run(
            &manifest("run-a", "fam.run.v1", "replay"),
            "m.json",
            "e.jsonl",
            "c.txt",
        )
        .unwrap();
    builder
        .add_events_jsonl(
            "run-a",
            &make_event_jsonl("run-a", "fam.event.v3", "c", "pass"),
        )
        .unwrap();
    let index = builder.build();
    let err = index
        .validate_event_schema_compatibility("fam.event.v2")
        .unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::NoMigrationPath { .. }));
}

#[test]
fn validate_schema_compatibility_rejects_different_family() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder
        .add_run(
            &manifest("run-a", "fam.run.v1", "replay"),
            "m.json",
            "e.jsonl",
            "c.txt",
        )
        .unwrap();
    builder
        .add_events_jsonl(
            "run-a",
            &make_event_jsonl("run-a", "fam-a.event.v1", "c", "pass"),
        )
        .unwrap();
    let index = builder.build();
    let err = index
        .validate_event_schema_compatibility("fam-b.event.v1")
        .unwrap_err();
    assert!(matches!(
        err,
        EvidenceIndexerError::IncompatibleSchemaFamily { .. }
    ));
}

#[test]
fn validate_schema_empty_events_passes() {
    let index = ParserEvidenceIndex {
        schema_version: PARSER_EVIDENCE_INDEX_SCHEMA_V1.into(),
        runs: vec![],
        events: vec![],
        schema_migrations: vec![],
    };
    index
        .validate_event_schema_compatibility("fam.event.v99")
        .unwrap();
}

// ---------------------------------------------------------------------------
// Migration
// ---------------------------------------------------------------------------

#[test]
fn migrate_noop_when_at_target() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder
        .add_run(
            &manifest("run-a", "fam.run.v1", "replay"),
            "m.json",
            "e.jsonl",
            "c.txt",
        )
        .unwrap();
    builder
        .add_events_jsonl(
            "run-a",
            &make_event_jsonl("run-a", "fam.event.v2", "c", "pass"),
        )
        .unwrap();
    let mut index = builder.build();
    let receipts = index.migrate_event_schemas("fam.event.v2", &[]).unwrap();
    assert!(receipts.is_empty());
}

#[test]
fn migrate_single_hop() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder
        .add_run(
            &manifest("run-a", "fam.run.v1", "replay"),
            "m.json",
            "e.jsonl",
            "c.txt",
        )
        .unwrap();
    builder
        .add_events_jsonl(
            "run-a",
            &make_event_jsonl("run-a", "fam.event.v1", "c", "pass"),
        )
        .unwrap();
    let mut index = builder.build();
    let steps = vec![SchemaMigrationStep {
        migration_id: "mig-1-2".into(),
        from_schema: "fam.event.v1".into(),
        to_schema: "fam.event.v2".into(),
    }];
    let receipts = index.migrate_event_schemas("fam.event.v2", &steps).unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].affected_records, 1);
    assert!(index
        .events
        .iter()
        .all(|e| e.schema_version == "fam.event.v2"));
}

#[test]
fn migrate_multi_hop() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder
        .add_run(
            &manifest("run-a", "fam.run.v1", "replay"),
            "m.json",
            "e.jsonl",
            "c.txt",
        )
        .unwrap();
    builder
        .add_events_jsonl(
            "run-a",
            &make_event_jsonl("run-a", "fam.event.v1", "c", "pass"),
        )
        .unwrap();
    let steps = vec![
        SchemaMigrationStep {
            migration_id: "mig-1-2".into(),
            from_schema: "fam.event.v1".into(),
            to_schema: "fam.event.v2".into(),
        },
        SchemaMigrationStep {
            migration_id: "mig-2-3".into(),
            from_schema: "fam.event.v2".into(),
            to_schema: "fam.event.v3".into(),
        },
    ];
    let mut index = builder.build();
    let receipts = index.migrate_event_schemas("fam.event.v3", &steps).unwrap();
    assert_eq!(receipts.len(), 2);
    assert!(index
        .events
        .iter()
        .all(|e| e.schema_version == "fam.event.v3"));
}

#[test]
fn migrate_no_path_returns_error() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder
        .add_run(
            &manifest("run-a", "fam.run.v1", "replay"),
            "m.json",
            "e.jsonl",
            "c.txt",
        )
        .unwrap();
    builder
        .add_events_jsonl(
            "run-a",
            &make_event_jsonl("run-a", "fam.event.v1", "c", "pass"),
        )
        .unwrap();
    let mut index = builder.build();
    let err = index
        .migrate_event_schemas("fam.event.v5", &[])
        .unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::NoMigrationPath { .. }));
}

// ---------------------------------------------------------------------------
// Schema migration boundaries
// ---------------------------------------------------------------------------

#[test]
fn schema_migration_boundary_detected() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder
        .add_run(
            &manifest("run-a", "fam.run.v1", "replay"),
            "m.json",
            "e.jsonl",
            "c.txt",
        )
        .unwrap();
    builder
        .add_events_jsonl(
            "run-a",
            &format!(
                "{}\n{}",
                make_event_jsonl("run-a", "fam.event.v1", "c", "pass"),
                make_event_jsonl("run-a", "fam.event.v2", "c", "pass")
                    .replace("t-run-a", "t2-run-a")
                    .replace("d-run-a", "d2-run-a"),
            ),
        )
        .unwrap();
    let index = builder.build();
    assert_eq!(index.schema_migrations.len(), 1);
    assert_eq!(index.schema_migrations[0].from_schema, "fam.event.v1");
    assert_eq!(index.schema_migrations[0].to_schema, "fam.event.v2");
}

#[test]
fn schema_migration_not_inferred_across_runs() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder
        .add_run(
            &manifest("run-a", "fam.run.v1", "replay-a"),
            "a-m.json",
            "a-e.jsonl",
            "a-c.txt",
        )
        .unwrap();
    builder
        .add_run(
            &manifest("run-b", "fam.run.v1", "replay-b"),
            "b-m.json",
            "b-e.jsonl",
            "b-c.txt",
        )
        .unwrap();
    builder
        .add_events_jsonl(
            "run-a",
            &make_event_jsonl("run-a", "fam.event.v1", "c", "pass"),
        )
        .unwrap();
    builder
        .add_events_jsonl(
            "run-b",
            &make_event_jsonl("run-b", "fam.event.v2", "c", "pass"),
        )
        .unwrap();
    let index = builder.build();
    assert!(index.schema_migrations.is_empty());
}

// ---------------------------------------------------------------------------
// Error display
// ---------------------------------------------------------------------------

#[test]
fn error_display_all_variants_distinct() {
    let variants: Vec<EvidenceIndexerError> = vec![
        EvidenceIndexerError::MissingField("run_id"),
        EvidenceIndexerError::InvalidFieldType {
            field: "run_id",
            expected: "string",
        },
        EvidenceIndexerError::DuplicateRunId("run-a".into()),
        EvidenceIndexerError::UnknownRunId("run-x".into()),
        EvidenceIndexerError::InvalidSchemaVersion("bad".into()),
        EvidenceIndexerError::IncompatibleSchemaFamily {
            from_schema: "a.v1".into(),
            to_schema: "b.v1".into(),
        },
        EvidenceIndexerError::NoMigrationPath {
            from_schema: "a.v1".into(),
            to_schema: "a.v9".into(),
        },
        EvidenceIndexerError::Json("parse error".into()),
    ];
    let set: BTreeSet<String> = variants.iter().map(|e| e.to_string()).collect();
    assert_eq!(set.len(), variants.len());
}

#[test]
fn error_is_std_error() {
    let err: Box<dyn std::error::Error> =
        Box::new(EvidenceIndexerError::MissingField("f"));
    assert!(!err.to_string().is_empty());
}

#[test]
fn json_error_conversion() {
    let bad_json = "not json";
    let err: Result<serde_json::Value, _> = serde_json::from_str(bad_json);
    let indexer_err: EvidenceIndexerError = err.unwrap_err().into();
    assert!(matches!(indexer_err, EvidenceIndexerError::Json(_)));
}

// ---------------------------------------------------------------------------
// Manifest validation
// ---------------------------------------------------------------------------

#[test]
fn manifest_missing_run_id_rejected() {
    let val = serde_json::json!({
        "schema_version": "fam.run.v1",
        "replay_command": "replay"
    });
    let err = ParserRunArtifactRef::from_manifest_value(&val, "m", "e", "c").unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::MissingField("run_id")));
}

#[test]
fn manifest_empty_run_id_rejected() {
    let val = serde_json::json!({
        "schema_version": "fam.run.v1",
        "run_id": "",
        "replay_command": "replay"
    });
    let err = ParserRunArtifactRef::from_manifest_value(&val, "m", "e", "c").unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::MissingField("run_id")));
}

#[test]
fn manifest_non_string_run_id_rejected() {
    let val = serde_json::json!({
        "schema_version": "fam.run.v1",
        "run_id": 42,
        "replay_command": "replay"
    });
    let err = ParserRunArtifactRef::from_manifest_value(&val, "m", "e", "c").unwrap_err();
    assert!(matches!(
        err,
        EvidenceIndexerError::InvalidFieldType {
            field: "run_id",
            ..
        }
    ));
}

#[test]
fn manifest_optional_fields_absent() {
    let val = serde_json::json!({
        "schema_version": "fam.run.v1",
        "run_id": "run-1",
        "replay_command": "replay-cmd"
    });
    let r = ParserRunArtifactRef::from_manifest_value(&val, "m", "e", "c").unwrap();
    assert!(r.generated_at_utc.is_none());
    assert!(r.outcome.is_none());
}

// ---------------------------------------------------------------------------
// CorrelationKey ordering
// ---------------------------------------------------------------------------

#[test]
fn correlation_key_ordering_deterministic() {
    let a = CorrelationKey {
        component: "a".into(),
        event: "e".into(),
        scenario_id: None,
        error_code: None,
        outcome: "fail".into(),
    };
    let b = CorrelationKey {
        component: "b".into(),
        event: "e".into(),
        scenario_id: None,
        error_code: None,
        outcome: "fail".into(),
    };
    assert!(a < b);
    assert!(a == a.clone());
}

// ---------------------------------------------------------------------------
// Clone / Eq
// ---------------------------------------------------------------------------

#[test]
fn clone_eq_parser_evidence_index() {
    let index = ParserEvidenceIndex {
        schema_version: PARSER_EVIDENCE_INDEX_SCHEMA_V1.into(),
        runs: vec![],
        events: vec![],
        schema_migrations: vec![],
    };
    let cloned = index.clone();
    assert_eq!(index, cloned);
}
