#![forbid(unsafe_code)]

//! Integration tests for `frankenengine_engine::parser_evidence_indexer`.
//!
//! Coverage targets:
//! - SchemaVersionTag: parse happy/error paths, ordering, serde
//! - ParserRunArtifactRef: from_manifest_value with all field variants
//! - ParserEvidenceIndexBuilder: add_run, add_events_jsonl, build determinism
//! - ParserEvidenceIndex: correlate_regressions, validate_event_schema_compatibility,
//!   migrate_event_schemas (single/multi-hop, noop, error paths)
//! - SchemaMigrationBoundary: detection within/across runs
//! - Error variant coverage, Display, std::error::Error
//! - Serde round-trips for all public types
//! - Edge cases: blank JSONL lines, empty index, duplicate runs, unknown runs,
//!   multi-run correlation clustering, replay command collection

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use frankenengine_engine::parser_evidence_indexer::{
    AppliedSchemaMigration, CorrelatedRegression, CorrelationKey, EvidenceIndexerError,
    IndexedParserEvent, PARSER_EVIDENCE_INDEX_SCHEMA_V1, ParserEvidenceIndex,
    ParserEvidenceIndexBuilder, ParserRunArtifactRef, SchemaMigrationBoundary, SchemaMigrationStep,
    SchemaVersionTag,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn manifest(run_id: &str, schema: &str, replay: &str) -> serde_json::Value {
    serde_json::json!({
        "schema_version": schema,
        "run_id": run_id,
        "replay_command": replay,
        "generated_at_utc": "2026-02-27T00:00:00Z",
        "outcome": "pass"
    })
}

fn manifest_minimal(run_id: &str, schema: &str, replay: &str) -> serde_json::Value {
    serde_json::json!({
        "schema_version": schema,
        "run_id": run_id,
        "replay_command": replay
    })
}

fn event_jsonl(schema: &str, trace: &str, component: &str, event: &str, outcome: &str) -> String {
    format!(
        r#"{{"schema_version":"{schema}","trace_id":"{trace}","decision_id":"d-{trace}","policy_id":"pol","component":"{component}","event":"{event}","outcome":"{outcome}"}}"#,
    )
}

fn event_jsonl_with_error(
    schema: &str,
    trace: &str,
    component: &str,
    event: &str,
    outcome: &str,
    error_code: &str,
) -> String {
    format!(
        r#"{{"schema_version":"{schema}","trace_id":"{trace}","decision_id":"d-{trace}","policy_id":"pol","component":"{component}","event":"{event}","outcome":"{outcome}","error_code":"{error_code}"}}"#,
    )
}

#[allow(clippy::too_many_arguments)]
fn event_jsonl_full(
    schema: &str,
    trace: &str,
    component: &str,
    event: &str,
    outcome: &str,
    error_code: Option<&str>,
    replay: Option<&str>,
    scenario_id: Option<&str>,
) -> String {
    let ec = error_code
        .map(|e| format!(r#","error_code":"{e}""#))
        .unwrap_or_default();
    let rc = replay
        .map(|r| format!(r#","replay_command":"{r}""#))
        .unwrap_or_default();
    let sc = scenario_id
        .map(|s| format!(r#","scenario_id":"{s}""#))
        .unwrap_or_default();
    format!(
        r#"{{"schema_version":"{schema}","trace_id":"{trace}","decision_id":"d-{trace}","policy_id":"pol","component":"{component}","event":"{event}","outcome":"{outcome}"{ec}{rc}{sc}}}"#,
    )
}

fn add_run(builder: &mut ParserEvidenceIndexBuilder, run_id: &str, schema: &str) {
    builder
        .add_run(
            &manifest(run_id, schema, &format!("replay-{run_id}")),
            format!("{run_id}-manifest.json"),
            format!("{run_id}-events.jsonl"),
            format!("{run_id}-commands.txt"),
        )
        .unwrap();
}

// ---------------------------------------------------------------------------
// Section 1: SchemaVersionTag
// ---------------------------------------------------------------------------

#[test]
fn schema_version_tag_parse_valid() {
    let tag = SchemaVersionTag::parse("franken-engine.parser-log-event.v3").unwrap();
    assert_eq!(tag.family, "franken-engine.parser-log-event");
    assert_eq!(tag.major, 3);
}

#[test]
fn schema_version_tag_parse_zero_major() {
    let tag = SchemaVersionTag::parse("family.v0").unwrap();
    assert_eq!(tag.family, "family");
    assert_eq!(tag.major, 0);
}

#[test]
fn schema_version_tag_parse_large_major() {
    let tag = SchemaVersionTag::parse("my-ns.v4294967295").unwrap();
    assert_eq!(tag.major, u32::MAX);
}

#[test]
fn schema_version_tag_parse_nested_dots_in_family() {
    // "a.b.c.v2" -> rsplit_once(".v") gives family="a.b.c", major=2
    let tag = SchemaVersionTag::parse("a.b.c.v2").unwrap();
    assert_eq!(tag.family, "a.b.c");
    assert_eq!(tag.major, 2);
}

#[test]
fn schema_version_tag_parse_rejects_no_dot_v() {
    let err = SchemaVersionTag::parse("family-v1").unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::InvalidSchemaVersion(s) if s == "family-v1"));
}

#[test]
fn schema_version_tag_parse_rejects_empty_family() {
    let err = SchemaVersionTag::parse(".v1").unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::InvalidSchemaVersion(_)));
}

#[test]
fn schema_version_tag_parse_rejects_non_numeric_major() {
    let err = SchemaVersionTag::parse("family.vabc").unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::InvalidSchemaVersion(_)));
}

#[test]
fn schema_version_tag_parse_rejects_empty_string() {
    let err = SchemaVersionTag::parse("").unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::InvalidSchemaVersion(_)));
}

#[test]
fn schema_version_tag_parse_rejects_only_dot_v() {
    let err = SchemaVersionTag::parse(".v").unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::InvalidSchemaVersion(_)));
}

#[test]
fn schema_version_tag_ordering() {
    let a = SchemaVersionTag::parse("alpha.v1").unwrap();
    let b = SchemaVersionTag::parse("alpha.v2").unwrap();
    let c = SchemaVersionTag::parse("beta.v1").unwrap();
    assert!(a < b, "same family, lower major should be less");
    assert!(a < c, "alpha family < beta family");
    assert!(b < c, "alpha.v2 < beta.v1 because family ordering");
}

#[test]
fn schema_version_tag_serde_roundtrip() {
    let tag = SchemaVersionTag::parse("franken-engine.event.v7").unwrap();
    let json = serde_json::to_string(&tag).unwrap();
    let back: SchemaVersionTag = serde_json::from_str(&json).unwrap();
    assert_eq!(tag, back);
}

// ---------------------------------------------------------------------------
// Section 2: ParserRunArtifactRef from_manifest_value
// ---------------------------------------------------------------------------

#[test]
fn artifact_ref_from_manifest_happy_path() {
    let m = manifest("run-42", "ns.run.v1", "bash replay.sh");
    let r = ParserRunArtifactRef::from_manifest_value(&m, "m.json", "e.jsonl", "c.txt").unwrap();
    assert_eq!(r.run_id, "run-42");
    assert_eq!(r.manifest_schema_version, "ns.run.v1");
    assert_eq!(r.manifest_path, "m.json");
    assert_eq!(r.events_path, "e.jsonl");
    assert_eq!(r.commands_path, "c.txt");
    assert_eq!(r.replay_command, "bash replay.sh");
    assert_eq!(r.generated_at_utc.as_deref(), Some("2026-02-27T00:00:00Z"));
    assert_eq!(r.outcome.as_deref(), Some("pass"));
}

#[test]
fn artifact_ref_optional_fields_absent() {
    let m = manifest_minimal("run-1", "ns.run.v1", "replay");
    let r = ParserRunArtifactRef::from_manifest_value(&m, "m", "e", "c").unwrap();
    assert!(r.generated_at_utc.is_none());
    assert!(r.outcome.is_none());
}

#[test]
fn artifact_ref_optional_fields_null() {
    let m = serde_json::json!({
        "schema_version": "ns.run.v1",
        "run_id": "run-1",
        "replay_command": "replay",
        "generated_at_utc": null,
        "outcome": null
    });
    let r = ParserRunArtifactRef::from_manifest_value(&m, "m", "e", "c").unwrap();
    assert!(r.generated_at_utc.is_none());
    assert!(r.outcome.is_none());
}

#[test]
fn artifact_ref_missing_run_id() {
    let m = serde_json::json!({
        "schema_version": "ns.run.v1",
        "replay_command": "replay"
    });
    let err = ParserRunArtifactRef::from_manifest_value(&m, "m", "e", "c").unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::MissingField("run_id")));
}

#[test]
fn artifact_ref_empty_run_id() {
    let m = serde_json::json!({
        "schema_version": "ns.run.v1",
        "run_id": "",
        "replay_command": "replay"
    });
    let err = ParserRunArtifactRef::from_manifest_value(&m, "m", "e", "c").unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::MissingField("run_id")));
}

#[test]
fn artifact_ref_non_string_run_id() {
    let m = serde_json::json!({
        "schema_version": "ns.run.v1",
        "run_id": 123,
        "replay_command": "replay"
    });
    let err = ParserRunArtifactRef::from_manifest_value(&m, "m", "e", "c").unwrap_err();
    assert!(matches!(
        err,
        EvidenceIndexerError::InvalidFieldType {
            field: "run_id",
            expected: "string"
        }
    ));
}

#[test]
fn artifact_ref_missing_schema_version() {
    let m = serde_json::json!({
        "run_id": "run-1",
        "replay_command": "replay"
    });
    let err = ParserRunArtifactRef::from_manifest_value(&m, "m", "e", "c").unwrap_err();
    assert!(matches!(
        err,
        EvidenceIndexerError::MissingField("schema_version")
    ));
}

#[test]
fn artifact_ref_invalid_schema_version_format() {
    let m = serde_json::json!({
        "schema_version": "no-version-tag",
        "run_id": "run-1",
        "replay_command": "replay"
    });
    let err = ParserRunArtifactRef::from_manifest_value(&m, "m", "e", "c").unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::InvalidSchemaVersion(_)));
}

#[test]
fn artifact_ref_missing_replay_command() {
    let m = serde_json::json!({
        "schema_version": "ns.run.v1",
        "run_id": "run-1"
    });
    let err = ParserRunArtifactRef::from_manifest_value(&m, "m", "e", "c").unwrap_err();
    assert!(matches!(
        err,
        EvidenceIndexerError::MissingField("replay_command")
    ));
}

#[test]
fn artifact_ref_non_string_optional_field_rejected() {
    let m = serde_json::json!({
        "schema_version": "ns.run.v1",
        "run_id": "run-1",
        "replay_command": "replay",
        "outcome": 42
    });
    let err = ParserRunArtifactRef::from_manifest_value(&m, "m", "e", "c").unwrap_err();
    assert!(matches!(
        err,
        EvidenceIndexerError::InvalidFieldType {
            field: "outcome",
            expected: "string|null"
        }
    ));
}

#[test]
fn artifact_ref_serde_roundtrip() {
    let m = manifest("run-1", "ns.run.v1", "replay");
    let r = ParserRunArtifactRef::from_manifest_value(&m, "m", "e", "c").unwrap();
    let json = serde_json::to_string(&r).unwrap();
    let back: ParserRunArtifactRef = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// Section 3: Builder — add_run, add_events_jsonl, build
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
fn builder_duplicate_run_id_rejected() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    let err = builder
        .add_run(
            &manifest("run-a", "ns.run.v1", "replay-dup"),
            "m2.json",
            "e2.jsonl",
            "c2.txt",
        )
        .unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::DuplicateRunId(id) if id == "run-a"));
}

#[test]
fn builder_events_for_unknown_run_rejected() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    let err = builder
        .add_events_jsonl(
            "ghost-run",
            &event_jsonl("ns.event.v1", "t", "c", "e", "pass"),
        )
        .unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::UnknownRunId(id) if id == "ghost-run"));
}

#[test]
fn builder_skips_blank_lines_in_jsonl() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    let jsonl = format!(
        "\n  \n{}\n\n  \n",
        event_jsonl("ns.event.v1", "t1", "comp", "ev", "pass")
    );
    builder.add_events_jsonl("run-a", &jsonl).unwrap();
    let index = builder.build();
    assert_eq!(index.events.len(), 1);
}

#[test]
fn builder_invalid_json_in_events_returns_json_error() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    let err = builder
        .add_events_jsonl("run-a", "this is not json")
        .unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::Json(_)));
}

#[test]
fn builder_events_missing_required_field() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    // Missing trace_id
    let jsonl = r#"{"schema_version":"ns.event.v1","decision_id":"d","policy_id":"p","component":"c","event":"e","outcome":"pass"}"#;
    let err = builder.add_events_jsonl("run-a", jsonl).unwrap_err();
    assert!(matches!(
        err,
        EvidenceIndexerError::MissingField("trace_id")
    ));
}

#[test]
fn builder_events_invalid_schema_in_event() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    let jsonl = r#"{"schema_version":"bad-schema","trace_id":"t","decision_id":"d","policy_id":"p","component":"c","event":"e","outcome":"pass"}"#;
    let err = builder.add_events_jsonl("run-a", jsonl).unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::InvalidSchemaVersion(_)));
}

#[test]
fn builder_runs_sorted_by_id_in_output() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-c", "ns.run.v1");
    add_run(&mut builder, "run-a", "ns.run.v1");
    add_run(&mut builder, "run-b", "ns.run.v1");
    let index = builder.build();
    let ids: Vec<&str> = index.runs.iter().map(|r| r.run_id.as_str()).collect();
    assert_eq!(ids, vec!["run-a", "run-b", "run-c"]);
}

#[test]
fn builder_events_sorted_by_run_id_then_sequence() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-b", "ns.run.v1");
    add_run(&mut builder, "run-a", "ns.run.v1");
    builder
        .add_events_jsonl(
            "run-b",
            &event_jsonl("ns.event.v1", "tb", "comp", "ev", "pass"),
        )
        .unwrap();
    builder
        .add_events_jsonl(
            "run-a",
            &event_jsonl("ns.event.v1", "ta", "comp", "ev", "pass"),
        )
        .unwrap();
    let index = builder.build();
    assert_eq!(index.events[0].run_id, "run-a");
    assert_eq!(index.events[1].run_id, "run-b");
}

#[test]
fn builder_sequence_increments_across_multiple_add_events_calls() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    builder
        .add_events_jsonl(
            "run-a",
            &event_jsonl("ns.event.v1", "t1", "c", "e1", "pass"),
        )
        .unwrap();
    builder
        .add_events_jsonl(
            "run-a",
            &event_jsonl("ns.event.v1", "t2", "c", "e2", "pass"),
        )
        .unwrap();
    let index = builder.build();
    assert_eq!(index.events.len(), 2);
    assert_eq!(index.events[0].sequence, 0);
    assert_eq!(index.events[1].sequence, 1);
}

#[test]
fn builder_multi_event_batch_sequences_correctly() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    let batch = format!(
        "{}\n{}\n{}",
        event_jsonl("ns.event.v1", "t1", "c", "e1", "pass"),
        event_jsonl("ns.event.v1", "t2", "c", "e2", "pass"),
        event_jsonl("ns.event.v1", "t3", "c", "e3", "pass"),
    );
    builder.add_events_jsonl("run-a", &batch).unwrap();
    let index = builder.build();
    assert_eq!(index.events.len(), 3);
    for (i, ev) in index.events.iter().enumerate() {
        assert_eq!(ev.sequence, i as u64);
    }
}

#[test]
fn builder_event_scenario_id_from_fixture_id() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    let jsonl = r#"{"schema_version":"ns.event.v1","trace_id":"t","decision_id":"d","policy_id":"p","component":"c","event":"e","outcome":"pass","fixture_id":"fix-99"}"#;
    builder.add_events_jsonl("run-a", jsonl).unwrap();
    let index = builder.build();
    assert_eq!(index.events[0].scenario_id.as_deref(), Some("fix-99"));
}

#[test]
fn builder_event_scenario_id_preferred_over_fixture_id() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    let jsonl = r#"{"schema_version":"ns.event.v1","trace_id":"t","decision_id":"d","policy_id":"p","component":"c","event":"e","outcome":"pass","scenario_id":"scen-1","fixture_id":"fix-99"}"#;
    builder.add_events_jsonl("run-a", jsonl).unwrap();
    let index = builder.build();
    assert_eq!(index.events[0].scenario_id.as_deref(), Some("scen-1"));
}

#[test]
fn builder_event_no_scenario_or_fixture() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    builder
        .add_events_jsonl("run-a", &event_jsonl("ns.event.v1", "t", "c", "e", "pass"))
        .unwrap();
    let index = builder.build();
    assert!(index.events[0].scenario_id.is_none());
}

// ---------------------------------------------------------------------------
// Section 4: correlate_regressions
// ---------------------------------------------------------------------------

#[test]
fn correlate_regressions_clusters_repeated_failures() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    for run_id in ["run-a", "run-b", "run-c"] {
        add_run(&mut builder, run_id, "ns.run.v1");
        builder
            .add_events_jsonl(
                run_id,
                &event_jsonl_with_error(
                    "ns.event.v1",
                    &format!("t-{run_id}"),
                    "parser",
                    "drift",
                    "fail",
                    "E-DRIFT",
                ),
            )
            .unwrap();
    }
    let index = builder.build();
    let clusters = index.correlate_regressions();
    assert_eq!(clusters.len(), 1);
    assert_eq!(clusters[0].run_count, 3);
    assert_eq!(clusters[0].occurrence_count, 3);
    assert_eq!(clusters[0].key.component, "parser");
    assert_eq!(clusters[0].key.event, "drift");
    assert_eq!(clusters[0].key.error_code.as_deref(), Some("E-DRIFT"));
    assert_eq!(clusters[0].severity, "high");
}

#[test]
fn correlate_regressions_ignores_single_run_failure() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    builder
        .add_events_jsonl(
            "run-a",
            &event_jsonl_with_error("ns.event.v1", "t1", "gate", "check", "fail", "E01"),
        )
        .unwrap();
    let index = builder.build();
    assert!(index.correlate_regressions().is_empty());
}

#[test]
fn correlate_regressions_ignores_pass_events() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    for run_id in ["run-a", "run-b"] {
        add_run(&mut builder, run_id, "ns.run.v1");
        builder
            .add_events_jsonl(
                run_id,
                &event_jsonl("ns.event.v1", &format!("t-{run_id}"), "c", "e", "pass"),
            )
            .unwrap();
    }
    let index = builder.build();
    assert!(index.correlate_regressions().is_empty());
}

#[test]
fn correlate_regressions_severity_medium_for_fail_no_error_code() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    for run_id in ["run-a", "run-b"] {
        add_run(&mut builder, run_id, "ns.run.v1");
        builder
            .add_events_jsonl(
                run_id,
                &event_jsonl(
                    "ns.event.v1",
                    &format!("t-{run_id}"),
                    "gate",
                    "check",
                    "fail",
                ),
            )
            .unwrap();
    }
    let index = builder.build();
    let clusters = index.correlate_regressions();
    assert_eq!(clusters.len(), 1);
    assert_eq!(clusters[0].severity, "medium");
}

#[test]
fn correlate_regressions_severity_info_for_warn_with_error_code() {
    // error_code is Some => severity = "high" regardless of outcome
    let mut builder = ParserEvidenceIndexBuilder::new();
    for run_id in ["run-a", "run-b"] {
        add_run(&mut builder, run_id, "ns.run.v1");
        builder
            .add_events_jsonl(
                run_id,
                &event_jsonl_with_error(
                    "ns.event.v1",
                    &format!("t-{run_id}"),
                    "gate",
                    "check",
                    "warn",
                    "E02",
                ),
            )
            .unwrap();
    }
    let index = builder.build();
    let clusters = index.correlate_regressions();
    assert_eq!(clusters.len(), 1);
    assert_eq!(clusters[0].severity, "high");
}

#[test]
fn correlate_regressions_collects_replay_commands() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    for run_id in ["run-a", "run-b"] {
        add_run(&mut builder, run_id, "ns.run.v1");
        builder
            .add_events_jsonl(
                run_id,
                &event_jsonl_full(
                    "ns.event.v1",
                    &format!("t-{run_id}"),
                    "gate",
                    "check",
                    "fail",
                    None,
                    Some(&format!("replay-{run_id}")),
                    None,
                ),
            )
            .unwrap();
    }
    let index = builder.build();
    let clusters = index.correlate_regressions();
    assert_eq!(clusters.len(), 1);
    assert_eq!(clusters[0].replay_commands.len(), 2);
    assert!(
        clusters[0]
            .replay_commands
            .contains(&"replay-run-a".to_string())
    );
    assert!(
        clusters[0]
            .replay_commands
            .contains(&"replay-run-b".to_string())
    );
}

#[test]
fn correlate_regressions_skips_empty_replay_commands() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    for run_id in ["run-a", "run-b"] {
        add_run(&mut builder, run_id, "ns.run.v1");
        builder
            .add_events_jsonl(
                run_id,
                &event_jsonl_full(
                    "ns.event.v1",
                    &format!("t-{run_id}"),
                    "gate",
                    "check",
                    "fail",
                    None,
                    Some(""),
                    None,
                ),
            )
            .unwrap();
    }
    let index = builder.build();
    let clusters = index.correlate_regressions();
    assert_eq!(clusters.len(), 1);
    // Empty replay commands should be filtered out
    assert!(clusters[0].replay_commands.is_empty());
}

#[test]
fn correlate_regressions_sorted_by_occurrence_count_desc() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    for run_id in ["run-a", "run-b"] {
        add_run(&mut builder, run_id, "ns.run.v1");
        // 2 occurrences of failure-A, 1 of failure-B per run
        let batch = format!(
            "{}\n{}\n{}",
            event_jsonl(
                "ns.event.v1",
                &format!("t1-{run_id}"),
                "comp-a",
                "fail-a",
                "fail"
            ),
            event_jsonl(
                "ns.event.v1",
                &format!("t2-{run_id}"),
                "comp-a",
                "fail-a",
                "fail"
            ),
            event_jsonl(
                "ns.event.v1",
                &format!("t3-{run_id}"),
                "comp-b",
                "fail-b",
                "fail"
            ),
        );
        builder.add_events_jsonl(run_id, &batch).unwrap();
    }
    let index = builder.build();
    let clusters = index.correlate_regressions();
    assert_eq!(clusters.len(), 2);
    // Higher occurrence_count first
    assert!(clusters[0].occurrence_count >= clusters[1].occurrence_count);
    assert_eq!(clusters[0].key.component, "comp-a");
    assert_eq!(clusters[0].occurrence_count, 4);
    assert_eq!(clusters[1].key.component, "comp-b");
    assert_eq!(clusters[1].occurrence_count, 2);
}

#[test]
fn correlate_regressions_separate_keys_for_different_scenarios() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    for run_id in ["run-a", "run-b"] {
        add_run(&mut builder, run_id, "ns.run.v1");
        let batch = format!(
            "{}\n{}",
            event_jsonl_full(
                "ns.event.v1",
                &format!("t1-{run_id}"),
                "comp",
                "ev",
                "fail",
                None,
                None,
                Some("scenario-1"),
            ),
            event_jsonl_full(
                "ns.event.v1",
                &format!("t2-{run_id}"),
                "comp",
                "ev",
                "fail",
                None,
                None,
                Some("scenario-2"),
            ),
        );
        builder.add_events_jsonl(run_id, &batch).unwrap();
    }
    let index = builder.build();
    let clusters = index.correlate_regressions();
    assert_eq!(clusters.len(), 2);
}

// ---------------------------------------------------------------------------
// Section 5: validate_event_schema_compatibility
// ---------------------------------------------------------------------------

#[test]
fn validate_schema_compatibility_accepts_same_version() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    builder
        .add_events_jsonl("run-a", &event_jsonl("ns.event.v2", "t", "c", "e", "pass"))
        .unwrap();
    let index = builder.build();
    index
        .validate_event_schema_compatibility("ns.event.v2")
        .unwrap();
}

#[test]
fn validate_schema_compatibility_accepts_older_version() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    builder
        .add_events_jsonl("run-a", &event_jsonl("ns.event.v1", "t", "c", "e", "pass"))
        .unwrap();
    let index = builder.build();
    // v1 is compatible with target v3 (older version, can migrate)
    index
        .validate_event_schema_compatibility("ns.event.v3")
        .unwrap();
}

#[test]
fn validate_schema_compatibility_rejects_newer_major() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    builder
        .add_events_jsonl("run-a", &event_jsonl("ns.event.v5", "t", "c", "e", "pass"))
        .unwrap();
    let index = builder.build();
    let err = index
        .validate_event_schema_compatibility("ns.event.v3")
        .unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::NoMigrationPath { .. }));
}

#[test]
fn validate_schema_compatibility_rejects_different_family() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    builder
        .add_events_jsonl(
            "run-a",
            &event_jsonl("family-a.event.v1", "t", "c", "e", "pass"),
        )
        .unwrap();
    let index = builder.build();
    let err = index
        .validate_event_schema_compatibility("family-b.event.v1")
        .unwrap_err();
    assert!(matches!(
        err,
        EvidenceIndexerError::IncompatibleSchemaFamily { .. }
    ));
}

#[test]
fn validate_schema_compatibility_empty_index_succeeds() {
    let builder = ParserEvidenceIndexBuilder::new();
    let index = builder.build();
    index
        .validate_event_schema_compatibility("ns.event.v1")
        .unwrap();
}

// ---------------------------------------------------------------------------
// Section 6: migrate_event_schemas
// ---------------------------------------------------------------------------

#[test]
fn migrate_single_step() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    builder
        .add_events_jsonl("run-a", &event_jsonl("ns.event.v1", "t1", "c", "e", "pass"))
        .unwrap();
    let mut index = builder.build();
    let receipts = index
        .migrate_event_schemas(
            "ns.event.v2",
            &[SchemaMigrationStep {
                migration_id: "mig-v1-v2".into(),
                from_schema: "ns.event.v1".into(),
                to_schema: "ns.event.v2".into(),
            }],
        )
        .unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].migration_id, "mig-v1-v2");
    assert_eq!(receipts[0].affected_records, 1);
    assert!(
        index
            .events
            .iter()
            .all(|e| e.schema_version == "ns.event.v2")
    );
}

#[test]
fn migrate_multi_hop() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    builder
        .add_events_jsonl("run-a", &event_jsonl("ns.event.v1", "t1", "c", "e", "pass"))
        .unwrap();
    let steps = vec![
        SchemaMigrationStep {
            migration_id: "mig-1-2".into(),
            from_schema: "ns.event.v1".into(),
            to_schema: "ns.event.v2".into(),
        },
        SchemaMigrationStep {
            migration_id: "mig-2-3".into(),
            from_schema: "ns.event.v2".into(),
            to_schema: "ns.event.v3".into(),
        },
    ];
    let mut index = builder.build();
    let receipts = index.migrate_event_schemas("ns.event.v3", &steps).unwrap();
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0].migration_id, "mig-1-2");
    assert_eq!(receipts[1].migration_id, "mig-2-3");
    assert!(
        index
            .events
            .iter()
            .all(|e| e.schema_version == "ns.event.v3")
    );
}

#[test]
fn migrate_noop_when_already_at_target() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    builder
        .add_events_jsonl("run-a", &event_jsonl("ns.event.v2", "t1", "c", "e", "pass"))
        .unwrap();
    let mut index = builder.build();
    let receipts = index.migrate_event_schemas("ns.event.v2", &[]).unwrap();
    assert!(receipts.is_empty());
}

#[test]
fn migrate_affected_records_accumulates_across_events() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    let batch = format!(
        "{}\n{}\n{}",
        event_jsonl("ns.event.v1", "t1", "c", "e1", "pass"),
        event_jsonl("ns.event.v1", "t2", "c", "e2", "pass"),
        event_jsonl("ns.event.v1", "t3", "c", "e3", "pass"),
    );
    builder.add_events_jsonl("run-a", &batch).unwrap();
    let mut index = builder.build();
    let receipts = index
        .migrate_event_schemas(
            "ns.event.v2",
            &[SchemaMigrationStep {
                migration_id: "mig-v1-v2".into(),
                from_schema: "ns.event.v1".into(),
                to_schema: "ns.event.v2".into(),
            }],
        )
        .unwrap();
    assert_eq!(receipts[0].affected_records, 3);
}

#[test]
fn migrate_no_path_returns_error() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    builder
        .add_events_jsonl("run-a", &event_jsonl("ns.event.v1", "t1", "c", "e", "pass"))
        .unwrap();
    let mut index = builder.build();
    let err = index.migrate_event_schemas("ns.event.v5", &[]).unwrap_err();
    assert!(matches!(err, EvidenceIndexerError::NoMigrationPath { .. }));
}

#[test]
fn migrate_incompatible_family_returns_error() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    builder
        .add_events_jsonl("run-a", &event_jsonl("ns.event.v1", "t1", "c", "e", "pass"))
        .unwrap();
    let mut index = builder.build();
    let err = index
        .migrate_event_schemas(
            "other.event.v2",
            &[SchemaMigrationStep {
                migration_id: "mig".into(),
                from_schema: "ns.event.v1".into(),
                to_schema: "other.event.v2".into(),
            }],
        )
        .unwrap_err();
    assert!(matches!(
        err,
        EvidenceIndexerError::IncompatibleSchemaFamily { .. }
    ));
}

#[test]
fn migrate_mixed_versions_partial_application() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    let batch = format!(
        "{}\n{}",
        event_jsonl("ns.event.v1", "t1", "c", "e1", "pass"),
        event_jsonl("ns.event.v2", "t2", "c", "e2", "pass"),
    );
    builder.add_events_jsonl("run-a", &batch).unwrap();
    let mut index = builder.build();
    let receipts = index
        .migrate_event_schemas(
            "ns.event.v2",
            &[SchemaMigrationStep {
                migration_id: "mig-v1-v2".into(),
                from_schema: "ns.event.v1".into(),
                to_schema: "ns.event.v2".into(),
            }],
        )
        .unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].affected_records, 1);
    assert!(
        index
            .events
            .iter()
            .all(|e| e.schema_version == "ns.event.v2")
    );
}

#[test]
fn migrate_updates_schema_migrations_field() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    // Two events: v1 and v2
    let batch = format!(
        "{}\n{}",
        event_jsonl("ns.event.v1", "t1", "c", "e1", "pass"),
        event_jsonl("ns.event.v2", "t2", "c", "e2", "pass"),
    );
    builder.add_events_jsonl("run-a", &batch).unwrap();
    let mut index = builder.build();
    // Before migration there should be a boundary v1->v2
    assert_eq!(index.schema_migrations.len(), 1);
    // Migrate all to v2
    index
        .migrate_event_schemas(
            "ns.event.v2",
            &[SchemaMigrationStep {
                migration_id: "mig-v1-v2".into(),
                from_schema: "ns.event.v1".into(),
                to_schema: "ns.event.v2".into(),
            }],
        )
        .unwrap();
    // After migration, all events are v2, so no boundaries
    assert!(index.schema_migrations.is_empty());
}

// ---------------------------------------------------------------------------
// Section 7: Schema migration boundaries
// ---------------------------------------------------------------------------

#[test]
fn schema_migration_boundary_detected_on_version_change() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    let batch = format!(
        "{}\n{}",
        event_jsonl("ns.event.v1", "t1", "c", "e1", "pass"),
        event_jsonl("ns.event.v2", "t2", "c", "e2", "pass"),
    );
    builder.add_events_jsonl("run-a", &batch).unwrap();
    let index = builder.build();
    assert_eq!(index.schema_migrations.len(), 1);
    assert_eq!(index.schema_migrations[0].from_schema, "ns.event.v1");
    assert_eq!(index.schema_migrations[0].to_schema, "ns.event.v2");
    assert_eq!(index.schema_migrations[0].run_id, "run-a");
}

#[test]
fn schema_migration_boundary_not_detected_across_runs() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    add_run(&mut builder, "run-b", "ns.run.v1");
    builder
        .add_events_jsonl("run-a", &event_jsonl("ns.event.v1", "ta", "c", "e", "pass"))
        .unwrap();
    builder
        .add_events_jsonl("run-b", &event_jsonl("ns.event.v2", "tb", "c", "e", "pass"))
        .unwrap();
    let index = builder.build();
    assert!(
        index.schema_migrations.is_empty(),
        "cross-run version differences must not produce boundaries"
    );
}

#[test]
fn schema_migration_boundary_multiple_transitions() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    let batch = format!(
        "{}\n{}\n{}",
        event_jsonl("ns.event.v1", "t1", "c", "e1", "pass"),
        event_jsonl("ns.event.v2", "t2", "c", "e2", "pass"),
        event_jsonl("ns.event.v3", "t3", "c", "e3", "pass"),
    );
    builder.add_events_jsonl("run-a", &batch).unwrap();
    let index = builder.build();
    assert_eq!(index.schema_migrations.len(), 2);
    assert_eq!(index.schema_migrations[0].from_schema, "ns.event.v1");
    assert_eq!(index.schema_migrations[0].to_schema, "ns.event.v2");
    assert_eq!(index.schema_migrations[1].from_schema, "ns.event.v2");
    assert_eq!(index.schema_migrations[1].to_schema, "ns.event.v3");
}

// ---------------------------------------------------------------------------
// Section 8: Error variants and Display
// ---------------------------------------------------------------------------

#[test]
fn error_display_missing_field() {
    let err = EvidenceIndexerError::MissingField("run_id");
    assert_eq!(err.to_string(), "missing required field `run_id`");
}

#[test]
fn error_display_invalid_field_type() {
    let err = EvidenceIndexerError::InvalidFieldType {
        field: "run_id",
        expected: "string",
    };
    assert_eq!(
        err.to_string(),
        "invalid field type for `run_id` (expected string)"
    );
}

#[test]
fn error_display_duplicate_run_id() {
    let err = EvidenceIndexerError::DuplicateRunId("run-42".into());
    assert_eq!(err.to_string(), "duplicate run_id `run-42`");
}

#[test]
fn error_display_unknown_run_id() {
    let err = EvidenceIndexerError::UnknownRunId("ghost".into());
    assert_eq!(err.to_string(), "unknown run_id `ghost`");
}

#[test]
fn error_display_invalid_schema_version() {
    let err = EvidenceIndexerError::InvalidSchemaVersion("bad".into());
    assert!(err.to_string().contains("bad"));
    assert!(err.to_string().contains("<family>.v<major>"));
}

#[test]
fn error_display_incompatible_schema_family() {
    let err = EvidenceIndexerError::IncompatibleSchemaFamily {
        from_schema: "a.v1".into(),
        to_schema: "b.v1".into(),
    };
    assert!(err.to_string().contains("incompatible"));
    assert!(err.to_string().contains("a.v1"));
    assert!(err.to_string().contains("b.v1"));
}

#[test]
fn error_display_no_migration_path() {
    let err = EvidenceIndexerError::NoMigrationPath {
        from_schema: "ns.v1".into(),
        to_schema: "ns.v9".into(),
    };
    assert!(err.to_string().contains("no migration path"));
}

#[test]
fn error_display_json() {
    let err = EvidenceIndexerError::Json("parse failure".into());
    assert!(err.to_string().contains("json error"));
    assert!(err.to_string().contains("parse failure"));
}

#[test]
fn error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(EvidenceIndexerError::MissingField("f"));
    assert!(!err.to_string().is_empty());
}

#[test]
fn error_from_serde_json() {
    let bad: Result<serde_json::Value, _> = serde_json::from_str("broken");
    let err: EvidenceIndexerError = bad.unwrap_err().into();
    assert!(matches!(err, EvidenceIndexerError::Json(_)));
}

// ---------------------------------------------------------------------------
// Section 9: Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn parser_evidence_index_serde_roundtrip() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    builder
        .add_events_jsonl("run-a", &event_jsonl("ns.event.v1", "t1", "c", "e", "pass"))
        .unwrap();
    let index = builder.build();
    let json = serde_json::to_string(&index).unwrap();
    let back: ParserEvidenceIndex = serde_json::from_str(&json).unwrap();
    assert_eq!(index, back);
}

#[test]
fn indexed_parser_event_serde_roundtrip() {
    let ev = IndexedParserEvent {
        run_id: "run-1".into(),
        sequence: 42,
        schema_version: "ns.event.v1".into(),
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "comp".into(),
        event: "ev".into(),
        outcome: "pass".into(),
        error_code: Some("E01".into()),
        replay_command: Some("replay".into()),
        scenario_id: Some("sc-1".into()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: IndexedParserEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn schema_migration_boundary_serde_roundtrip() {
    let b = SchemaMigrationBoundary {
        run_id: "run-1".into(),
        sequence: 5,
        from_schema: "ns.v1".into(),
        to_schema: "ns.v2".into(),
    };
    let json = serde_json::to_string(&b).unwrap();
    let back: SchemaMigrationBoundary = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
}

#[test]
fn correlated_regression_serde_roundtrip() {
    let cr = CorrelatedRegression {
        key: CorrelationKey {
            component: "parser".into(),
            event: "drift".into(),
            scenario_id: Some("s1".into()),
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
fn correlation_key_serde_roundtrip() {
    let key = CorrelationKey {
        component: "c".into(),
        event: "e".into(),
        scenario_id: None,
        error_code: None,
        outcome: "fail".into(),
    };
    let json = serde_json::to_string(&key).unwrap();
    let back: CorrelationKey = serde_json::from_str(&json).unwrap();
    assert_eq!(key, back);
}

#[test]
fn applied_schema_migration_serde_roundtrip() {
    let m = AppliedSchemaMigration {
        migration_id: "mig-1".into(),
        from_schema: "ns.v1".into(),
        to_schema: "ns.v2".into(),
        affected_records: 42,
    };
    let json = serde_json::to_string(&m).unwrap();
    let back: AppliedSchemaMigration = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn schema_migration_step_serde_roundtrip() {
    let s = SchemaMigrationStep {
        migration_id: "step-1".into(),
        from_schema: "ns.v1".into(),
        to_schema: "ns.v2".into(),
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: SchemaMigrationStep = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ---------------------------------------------------------------------------
// Section 10: Full end-to-end scenarios
// ---------------------------------------------------------------------------

#[test]
fn e2e_multi_run_index_build_correlate_migrate() {
    let mut builder = ParserEvidenceIndexBuilder::new();

    // Three runs, each with a mix of pass and fail events
    for run_id in ["run-alpha", "run-beta", "run-gamma"] {
        add_run(&mut builder, run_id, "ns.run.v1");
        let batch = format!(
            "{}\n{}\n{}",
            event_jsonl(
                "ns.event.v1",
                &format!("pass-{run_id}"),
                "gate",
                "check",
                "pass"
            ),
            event_jsonl_with_error(
                "ns.event.v1",
                &format!("fail-{run_id}"),
                "parser",
                "drift",
                "fail",
                "E-DRIFT"
            ),
            event_jsonl(
                "ns.event.v1",
                &format!("warn-{run_id}"),
                "validator",
                "timeout",
                "warn"
            ),
        );
        builder.add_events_jsonl(run_id, &batch).unwrap();
    }

    let mut index = builder.build();

    // Verify structure
    assert_eq!(index.runs.len(), 3);
    assert_eq!(index.events.len(), 9);
    assert_eq!(index.schema_version, PARSER_EVIDENCE_INDEX_SCHEMA_V1);

    // Correlate regressions: drift failures appear in all 3 runs
    let clusters = index.correlate_regressions();
    assert!(!clusters.is_empty());
    let drift_cluster = clusters
        .iter()
        .find(|c| c.key.event == "drift")
        .expect("expected drift cluster");
    assert_eq!(drift_cluster.run_count, 3);
    assert_eq!(drift_cluster.severity, "high");

    // Validate schema compatibility
    index
        .validate_event_schema_compatibility("ns.event.v1")
        .unwrap();

    // Migrate to v2
    let receipts = index
        .migrate_event_schemas(
            "ns.event.v2",
            &[SchemaMigrationStep {
                migration_id: "mig-v1-v2".into(),
                from_schema: "ns.event.v1".into(),
                to_schema: "ns.event.v2".into(),
            }],
        )
        .unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].affected_records, 9);
    assert!(
        index
            .events
            .iter()
            .all(|e| e.schema_version == "ns.event.v2")
    );
}

#[test]
fn e2e_index_serde_preserves_all_data() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    add_run(&mut builder, "run-a", "ns.run.v1");
    add_run(&mut builder, "run-b", "ns.run.v1");
    let batch_a = format!(
        "{}\n{}",
        event_jsonl("ns.event.v1", "t1a", "c1", "e1", "pass"),
        event_jsonl("ns.event.v2", "t2a", "c2", "e2", "fail"),
    );
    builder.add_events_jsonl("run-a", &batch_a).unwrap();
    builder
        .add_events_jsonl(
            "run-b",
            &event_jsonl("ns.event.v1", "t1b", "c1", "e1", "pass"),
        )
        .unwrap();

    let index = builder.build();
    let json = serde_json::to_string_pretty(&index).unwrap();
    let restored: ParserEvidenceIndex = serde_json::from_str(&json).unwrap();
    assert_eq!(index.runs, restored.runs);
    assert_eq!(index.events, restored.events);
    assert_eq!(index.schema_migrations, restored.schema_migrations);
    assert_eq!(index.schema_version, restored.schema_version);
}

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
    assert_eq!(a, a.clone());
}

#[test]
fn constant_schema_v1_value() {
    assert_eq!(
        PARSER_EVIDENCE_INDEX_SCHEMA_V1,
        "franken-engine.parser-evidence-index.v1"
    );
}

#[test]
fn builder_chaining_returns_mutable_self() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    // add_run and add_events_jsonl return &mut Self, enabling chaining
    builder
        .add_run(
            &manifest("run-a", "ns.run.v1", "replay-a"),
            "m.json",
            "e.jsonl",
            "c.txt",
        )
        .unwrap()
        .add_run(
            &manifest("run-b", "ns.run.v1", "replay-b"),
            "m2.json",
            "e2.jsonl",
            "c2.txt",
        )
        .unwrap();

    builder
        .add_events_jsonl("run-a", &event_jsonl("ns.event.v1", "t1", "c", "e", "pass"))
        .unwrap()
        .add_events_jsonl("run-b", &event_jsonl("ns.event.v1", "t2", "c", "e", "pass"))
        .unwrap();

    let index = builder.build();
    assert_eq!(index.runs.len(), 2);
    assert_eq!(index.events.len(), 2);
}

#[test]
fn builder_default_is_empty() {
    let builder = ParserEvidenceIndexBuilder::default();
    let index = builder.build();
    assert!(index.runs.is_empty());
    assert!(index.events.is_empty());
}

#[test]
fn empty_optional_string_becomes_none() {
    // When optional fields have empty string values they should become None
    let m = serde_json::json!({
        "schema_version": "ns.run.v1",
        "run_id": "run-1",
        "replay_command": "replay",
        "generated_at_utc": "",
        "outcome": ""
    });
    let r = ParserRunArtifactRef::from_manifest_value(&m, "m", "e", "c").unwrap();
    assert!(r.generated_at_utc.is_none());
    assert!(r.outcome.is_none());
}
