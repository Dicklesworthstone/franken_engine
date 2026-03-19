#![forbid(unsafe_code)]
//! Enrichment integration tests for the `parser_evidence_indexer` module.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::parser_evidence_indexer::{
    AppliedSchemaMigration, CorrelatedRegression, CorrelationKey, EvidenceIndexerError,
    ParserEvidenceIndex, ParserEvidenceIndexBuilder, ParserRunArtifactRef,
    SchemaMigrationBoundary, SchemaMigrationStep, SchemaVersionTag,
    PARSER_EVIDENCE_INDEX_SCHEMA_V1,
};

fn manifest(run_id: &str, schema: &str, replay: &str) -> serde_json::Value {
    serde_json::json!({
        "schema_version": schema,
        "run_id": run_id,
        "replay_command": replay,
        "generated_at_utc": "2026-03-19T00:00:00Z",
        "outcome": "pass"
    })
}

#[test]
fn enrichment_schema_version_tag_parse_ok() {
    let tag = SchemaVersionTag::parse("franken-engine.parser-log-event.v12").unwrap();
    assert_eq!(tag.family, "franken-engine.parser-log-event");
    assert_eq!(tag.major, 12);
}

#[test]
fn enrichment_schema_version_tag_parse_empty_family() {
    let err = SchemaVersionTag::parse(".v1").unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::InvalidSchemaVersion(_)));
}

#[test]
fn enrichment_schema_version_tag_parse_non_numeric() {
    let err = SchemaVersionTag::parse("fam.vabc").unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::InvalidSchemaVersion(_)));
}

#[test]
fn enrichment_schema_version_tag_parse_no_dot_v() {
    let err = SchemaVersionTag::parse("fam-v1").unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::InvalidSchemaVersion(_)));
}

#[test]
fn enrichment_schema_version_tag_parse_zero_major() {
    let tag = SchemaVersionTag::parse("fam.v0").unwrap();
    assert_eq!(tag.major, 0);
}

#[test]
fn enrichment_schema_version_tag_serde_roundtrip() {
    let tag = SchemaVersionTag::parse("franken-engine.v5").unwrap();
    let json = serde_json::to_string(&tag).unwrap();
    let back: SchemaVersionTag = serde_json::from_str(&json).unwrap();
    assert_eq!(tag, back);
}

#[test]
fn enrichment_schema_version_tag_ordering() {
    let a = SchemaVersionTag::parse("alpha.v1").unwrap();
    let b = SchemaVersionTag::parse("alpha.v2").unwrap();
    assert!(a < b);
}

#[test]
fn enrichment_error_display_all_variants_unique() {
    let variants: Vec<EvidenceIndexerError> = vec![
        EvidenceIndexerError::MissingField("f"),
        EvidenceIndexerError::InvalidFieldType { field: "f", expected: "string" },
        EvidenceIndexerError::DuplicateRunId("r".into()),
        EvidenceIndexerError::UnknownRunId("r".into()),
        EvidenceIndexerError::InvalidSchemaVersion("bad".into()),
        EvidenceIndexerError::IncompatibleSchemaFamily { from_schema: "a.v1".into(), to_schema: "b.v1".into() },
        EvidenceIndexerError::NoMigrationPath { from_schema: "a.v1".into(), to_schema: "a.v9".into() },
        EvidenceIndexerError::Json("error".into()),
    ];
    let set: BTreeSet<String> = variants.iter().map(|e| e.to_string()).collect();
    assert_eq!(set.len(), variants.len());
}

#[test]
fn enrichment_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(EvidenceIndexerError::MissingField("f"));
    assert!(!err.to_string().is_empty());
}

#[test]
fn enrichment_builder_duplicate_run_rejected() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder.add_run(&manifest("run-a", "fam.run.v1", "replay"), "m", "e", "c").unwrap();
    let err = builder.add_run(&manifest("run-a", "fam.run.v1", "replay2"), "m2", "e2", "c2").unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::DuplicateRunId(id) if id == "run-a"));
}

#[test]
fn enrichment_builder_unknown_run_events_rejected() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    let err = builder.add_events_jsonl("nonexistent", r#"{"schema_version":"fam.v1","trace_id":"t","decision_id":"d","policy_id":"p","component":"c","event":"e","outcome":"pass"}"#).unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::UnknownRunId(_)));
}

#[test]
fn enrichment_builder_skips_blank_lines() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder.add_run(&manifest("run-a", "fam.run.v1", "replay"), "m", "e", "c").unwrap();
    builder.add_events_jsonl("run-a", "\n  \n{\"schema_version\":\"fam.event.v1\",\"trace_id\":\"t\",\"decision_id\":\"d\",\"policy_id\":\"p\",\"component\":\"c\",\"event\":\"e\",\"outcome\":\"pass\"}\n\n").unwrap();
    let index = builder.build();
    assert_eq!(index.events.len(), 1);
}

#[test]
fn enrichment_builder_appends_sequence() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder.add_run(&manifest("run-a", "fam.run.v1", "replay"), "m", "e", "c").unwrap();
    builder.add_events_jsonl("run-a", r#"{"schema_version":"fam.event.v1","trace_id":"t1","decision_id":"d1","policy_id":"p","component":"c","event":"e1","outcome":"pass"}"#).unwrap();
    builder.add_events_jsonl("run-a", r#"{"schema_version":"fam.event.v1","trace_id":"t2","decision_id":"d2","policy_id":"p","component":"c","event":"e2","outcome":"pass"}"#).unwrap();
    let index = builder.build();
    assert_eq!(index.events.len(), 2);
    assert_eq!(index.events[0].sequence, 0);
    assert_eq!(index.events[1].sequence, 1);
}

#[test]
fn enrichment_build_sorts_runs_by_id() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder.add_run(&manifest("run-b", "fam.run.v1", "replay-b"), "mb", "eb", "cb").unwrap();
    builder.add_run(&manifest("run-a", "fam.run.v1", "replay-a"), "ma", "ea", "ca").unwrap();
    let index = builder.build();
    assert_eq!(index.runs[0].run_id, "run-a");
    assert_eq!(index.runs[1].run_id, "run-b");
}

#[test]
fn enrichment_build_empty_index() {
    let builder = ParserEvidenceIndexBuilder::new();
    let index = builder.build();
    assert_eq!(index.schema_version, PARSER_EVIDENCE_INDEX_SCHEMA_V1);
    assert!(index.runs.is_empty());
    assert!(index.events.is_empty());
    assert!(index.schema_migrations.is_empty());
}

#[test]
fn enrichment_correlate_ignores_single_run() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder.add_run(&manifest("run-a", "fam.run.v1", "replay"), "m", "e", "c").unwrap();
    builder.add_events_jsonl("run-a", r#"{"schema_version":"fam.event.v1","trace_id":"t","decision_id":"d","policy_id":"p","component":"gate","event":"fail_check","outcome":"fail","error_code":"E01"}"#).unwrap();
    let index = builder.build();
    assert!(index.correlate_regressions().is_empty());
}

#[test]
fn enrichment_correlate_cross_run_regression() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    for run_id in ["run-a", "run-b"] {
        builder.add_run(&manifest(run_id, "fam.run.v1", &format!("replay-{run_id}")), format!("{run_id}-m"), format!("{run_id}-e"), format!("{run_id}-c")).unwrap();
        let ev = format!("{{\"schema_version\":\"fam.event.v1\",\"trace_id\":\"t-{run_id}\",\"decision_id\":\"d-{run_id}\",\"policy_id\":\"p\",\"component\":\"gate\",\"event\":\"drift\",\"outcome\":\"fail\",\"error_code\":\"E-DRIFT\"}}");
        builder.add_events_jsonl(run_id, &ev).unwrap();
    }
    let index = builder.build();
    let clusters = index.correlate_regressions();
    assert_eq!(clusters.len(), 1);
    assert_eq!(clusters[0].run_count, 2);
    assert_eq!(clusters[0].severity, "high");
}

#[test]
fn enrichment_correlate_ignores_pass_events() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    for run_id in ["run-a", "run-b"] {
        builder.add_run(&manifest(run_id, "fam.run.v1", &format!("replay-{run_id}")), format!("{run_id}-m"), format!("{run_id}-e"), format!("{run_id}-c")).unwrap();
        let ev = format!("{{\"schema_version\":\"fam.event.v1\",\"trace_id\":\"t-{run_id}\",\"decision_id\":\"d\",\"policy_id\":\"p\",\"component\":\"gate\",\"event\":\"check\",\"outcome\":\"pass\"}}");
        builder.add_events_jsonl(run_id, &ev).unwrap();
    }
    let index = builder.build();
    assert!(index.correlate_regressions().is_empty());
}

#[test]
fn enrichment_validate_compat_same_version() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder.add_run(&manifest("run-a", "fam.run.v1", "replay"), "m", "e", "c").unwrap();
    builder.add_events_jsonl("run-a", r#"{"schema_version":"fam.event.v2","trace_id":"t","decision_id":"d","policy_id":"p","component":"c","event":"e","outcome":"pass"}"#).unwrap();
    let index = builder.build();
    index.validate_event_schema_compatibility("fam.event.v2").unwrap();
}

#[test]
fn enrichment_validate_compat_rejects_newer() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder.add_run(&manifest("run-a", "fam.run.v1", "replay"), "m", "e", "c").unwrap();
    builder.add_events_jsonl("run-a", r#"{"schema_version":"fam.event.v3","trace_id":"t","decision_id":"d","policy_id":"p","component":"c","event":"e","outcome":"pass"}"#).unwrap();
    let index = builder.build();
    let err = index.validate_event_schema_compatibility("fam.event.v2").unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::NoMigrationPath { .. }));
}

#[test]
fn enrichment_migrate_noop() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder.add_run(&manifest("run-a", "fam.run.v1", "replay"), "m", "e", "c").unwrap();
    builder.add_events_jsonl("run-a", r#"{"schema_version":"fam.event.v2","trace_id":"t","decision_id":"d","policy_id":"p","component":"c","event":"e","outcome":"pass"}"#).unwrap();
    let mut index = builder.build();
    let receipts = index.migrate_event_schemas("fam.event.v2", &[]).unwrap();
    assert!(receipts.is_empty());
}

#[test]
fn enrichment_migrate_single_hop() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder.add_run(&manifest("run-a", "fam.run.v1", "replay"), "m", "e", "c").unwrap();
    builder.add_events_jsonl("run-a", r#"{"schema_version":"fam.event.v1","trace_id":"t","decision_id":"d","policy_id":"p","component":"c","event":"e","outcome":"pass"}"#).unwrap();
    let steps = vec![SchemaMigrationStep { migration_id: "mig-1-2".into(), from_schema: "fam.event.v1".into(), to_schema: "fam.event.v2".into() }];
    let mut index = builder.build();
    let receipts = index.migrate_event_schemas("fam.event.v2", &steps).unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].affected_records, 1);
    assert!(index.events.iter().all(|e| e.schema_version == "fam.event.v2"));
}

#[test]
fn enrichment_migrate_no_path() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder.add_run(&manifest("run-a", "fam.run.v1", "replay"), "m", "e", "c").unwrap();
    builder.add_events_jsonl("run-a", r#"{"schema_version":"fam.event.v1","trace_id":"t","decision_id":"d","policy_id":"p","component":"c","event":"e","outcome":"pass"}"#).unwrap();
    let mut index = builder.build();
    let err = index.migrate_event_schemas("fam.event.v5", &[]).unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::NoMigrationPath { .. }));
}

#[test]
fn enrichment_boundary_on_version_change() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder.add_run(&manifest("run-a", "fam.run.v1", "replay"), "m", "e", "c").unwrap();
    builder.add_events_jsonl("run-a", concat!(
        r#"{"schema_version":"fam.event.v1","trace_id":"t1","decision_id":"d1","policy_id":"p","component":"c","event":"e","outcome":"pass"}"#,
        "\n",
        r#"{"schema_version":"fam.event.v2","trace_id":"t2","decision_id":"d2","policy_id":"p","component":"c","event":"e","outcome":"pass"}"#,
    )).unwrap();
    let index = builder.build();
    assert_eq!(index.schema_migrations.len(), 1);
    assert_eq!(index.schema_migrations[0].from_schema, "fam.event.v1");
    assert_eq!(index.schema_migrations[0].to_schema, "fam.event.v2");
}

#[test]
fn enrichment_boundary_not_across_runs() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder.add_run(&manifest("run-a", "fam.run.v1", "replay-a"), "ma", "ea", "ca").unwrap();
    builder.add_run(&manifest("run-b", "fam.run.v1", "replay-b"), "mb", "eb", "cb").unwrap();
    builder.add_events_jsonl("run-a", r#"{"schema_version":"fam.event.v1","trace_id":"ta","decision_id":"da","policy_id":"p","component":"c","event":"e","outcome":"pass"}"#).unwrap();
    builder.add_events_jsonl("run-b", r#"{"schema_version":"fam.event.v2","trace_id":"tb","decision_id":"db","policy_id":"p","component":"c","event":"e","outcome":"pass"}"#).unwrap();
    let index = builder.build();
    assert!(index.schema_migrations.is_empty());
}

#[test]
fn enrichment_parser_evidence_index_serde_roundtrip() {
    let index = ParserEvidenceIndex { schema_version: PARSER_EVIDENCE_INDEX_SCHEMA_V1.into(), runs: vec![], events: vec![], schema_migrations: vec![] };
    let json = serde_json::to_string(&index).unwrap();
    let back: ParserEvidenceIndex = serde_json::from_str(&json).unwrap();
    assert_eq!(index, back);
}

#[test]
fn enrichment_correlation_key_serde_roundtrip() {
    let key = CorrelationKey { component: "parser".into(), event: "drift".into(), scenario_id: Some("s1".into()), error_code: Some("E01".into()), outcome: "fail".into() };
    let json = serde_json::to_string(&key).unwrap();
    let back: CorrelationKey = serde_json::from_str(&json).unwrap();
    assert_eq!(key, back);
}

#[test]
fn enrichment_correlated_regression_serde_roundtrip() {
    let cr = CorrelatedRegression {
        key: CorrelationKey { component: "p".into(), event: "e".into(), scenario_id: None, error_code: None, outcome: "fail".into() },
        run_count: 2, occurrence_count: 3, run_ids: vec!["r1".into()], trace_ids: vec!["t1".into()], replay_commands: vec![], severity: "medium".into(),
    };
    let json = serde_json::to_string(&cr).unwrap();
    let back: CorrelatedRegression = serde_json::from_str(&json).unwrap();
    assert_eq!(cr, back);
}

#[test]
fn enrichment_applied_migration_serde_roundtrip() {
    let m = AppliedSchemaMigration { migration_id: "mig-1".into(), from_schema: "fam.v1".into(), to_schema: "fam.v2".into(), affected_records: 42 };
    let json = serde_json::to_string(&m).unwrap();
    let back: AppliedSchemaMigration = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn enrichment_migration_boundary_serde_roundtrip() {
    let b = SchemaMigrationBoundary { run_id: "run-1".into(), sequence: 5, from_schema: "fam.v1".into(), to_schema: "fam.v2".into() };
    let json = serde_json::to_string(&b).unwrap();
    let back: SchemaMigrationBoundary = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
}

#[test]
fn enrichment_migration_step_serde_roundtrip() {
    let s = SchemaMigrationStep { migration_id: "mig-x".into(), from_schema: "fam.v1".into(), to_schema: "fam.v2".into() };
    let json = serde_json::to_string(&s).unwrap();
    let back: SchemaMigrationStep = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn enrichment_manifest_missing_run_id() {
    let val = serde_json::json!({ "schema_version": "fam.run.v1", "replay_command": "replay" });
    let err = ParserRunArtifactRef::from_manifest_value(&val, "m", "e", "c").unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::MissingField("run_id")));
}

#[test]
fn enrichment_manifest_empty_run_id() {
    let val = serde_json::json!({ "schema_version": "fam.run.v1", "run_id": "", "replay_command": "replay" });
    let err = ParserRunArtifactRef::from_manifest_value(&val, "m", "e", "c").unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::MissingField("run_id")));
}

#[test]
fn enrichment_manifest_non_string_run_id() {
    let val = serde_json::json!({ "schema_version": "fam.run.v1", "run_id": 42, "replay_command": "replay" });
    let err = ParserRunArtifactRef::from_manifest_value(&val, "m", "e", "c").unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::InvalidFieldType { field: "run_id", .. }));
}

#[test]
fn enrichment_manifest_optional_null_fields() {
    let val = serde_json::json!({ "schema_version": "fam.run.v1", "run_id": "run-1", "replay_command": "replay", "generated_at_utc": null, "outcome": null });
    let r = ParserRunArtifactRef::from_manifest_value(&val, "m", "e", "c").unwrap();
    assert!(r.generated_at_utc.is_none());
    assert!(r.outcome.is_none());
}

#[test]
fn enrichment_correlation_key_ordering() {
    let a = CorrelationKey { component: "a".into(), event: "e".into(), scenario_id: None, error_code: None, outcome: "fail".into() };
    let b = CorrelationKey { component: "b".into(), event: "e".into(), scenario_id: None, error_code: None, outcome: "fail".into() };
    assert!(a < b);
}

#[test]
fn enrichment_json_error_conversion() {
    let bad: Result<serde_json::Value, _> = serde_json::from_str("not json");
    let err: EvidenceIndexerError = bad.unwrap_err().into();
    assert!(matches!(err, EvidenceIndexerError::Json(_)));
    assert!(err.to_string().contains("json error"));
}
