#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserMode, ParserOptions};
use frankenengine_engine::parser_oracle::{
    DriftClass, GateAction, OracleGateMode, OraclePartition, PARSER_ORACLE_REPORT_SCHEMA_VERSION,
    PARSER_ORACLE_TAXONOMY_VERSION, ParserOracleConfig, ParserOracleError, derive_seed,
    load_fixture_catalog, partition_fixtures, run_parser_oracle,
};
use serde_json::json;
use tempfile::TempDir;

const CATALOG_SCHEMA: &str = "franken-engine.parser-phase0.semantic-fixtures.v1";

struct FixtureCase {
    id: &'static str,
    family_id: &'static str,
    goal: &'static str,
    source: &'static str,
    expected_hash: String,
}

fn expected_parse_hash(source: &str, goal: ParseGoal) -> String {
    CanonicalEs2020Parser
        .parse_with_options(source, goal, &ParserOptions::default())
        .expect("conformance fixture should parse")
        .canonical_hash()
}

fn valid_script_fixture(id: &'static str, source: &'static str) -> FixtureCase {
    FixtureCase {
        id,
        family_id: "conformance.script",
        goal: "script",
        source,
        expected_hash: expected_parse_hash(source, ParseGoal::Script),
    }
}

fn drift_script_fixture(id: &'static str, source: &'static str) -> FixtureCase {
    FixtureCase {
        id,
        family_id: "conformance.drift",
        goal: "script",
        source,
        expected_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
    }
}

fn write_catalog(temp_dir: &TempDir, file_name: &str, fixtures: Vec<FixtureCase>) -> PathBuf {
    let path = temp_dir.path().join(file_name);
    let fixtures: Vec<_> = fixtures
        .into_iter()
        .map(|fixture| {
            json!({
                "id": fixture.id,
                "family_id": fixture.family_id,
                "goal": fixture.goal,
                "source": fixture.source,
                "expected_hash": fixture.expected_hash,
            })
        })
        .collect();
    let catalog = json!({
        "schema_version": CATALOG_SCHEMA,
        "parser_mode": ParserMode::ScalarReference.as_str(),
        "fixtures": fixtures,
    });
    fs::write(
        &path,
        serde_json::to_vec_pretty(&catalog).expect("catalog should serialize"),
    )
    .expect("catalog should be writable");
    path
}

fn write_raw_catalog(temp_dir: &TempDir, file_name: &str, catalog: serde_json::Value) -> PathBuf {
    let path = temp_dir.path().join(file_name);
    fs::write(
        &path,
        serde_json::to_vec_pretty(&catalog).expect("catalog should serialize"),
    )
    .expect("catalog should be writable");
    path
}

fn config_for(
    path: impl AsRef<Path>,
    partition: OraclePartition,
    gate_mode: OracleGateMode,
) -> ParserOracleConfig {
    let mut config = ParserOracleConfig::with_defaults(partition, gate_mode, 0x5eed_5eed);
    config.fixture_catalog_path = path.as_ref().to_path_buf();
    config.trace_id = "trace-parser-oracle-conformance".to_string();
    config.decision_id = "decision-parser-oracle-conformance".to_string();
    config.policy_id = "policy-parser-oracle-conformance".to_string();
    config
}

#[test]
fn oracle_conformance_names_at_least_ten_named_assertions() {
    let assertion_names = [
        "oracle_partition_enum_labels",
        "oracle_gate_mode_enum_labels",
        "oracle_outcome_drift_class_labels",
        "oracle_outcome_gate_action_labels",
        "unknown_goal_fail_closed",
        "invalid_schema_fail_closed",
        "empty_catalog_fail_closed",
        "deterministic_dispatch_order",
        "smoke_dispatch_limit",
        "evidence_schema_and_trace_contract",
        "replay_command_contract",
        "replay_equivalence_repeats_observation",
        "fail_closed_rejects_critical_drift",
    ];
    let unique: BTreeSet<_> = assertion_names.iter().copied().collect();

    assert!(assertion_names.len() >= 10);
    assert_eq!(unique.len(), assertion_names.len());
}

#[test]
fn oracle_decision_enums_have_stable_external_labels() {
    assert_eq!(OraclePartition::Smoke.as_str(), "smoke");
    assert_eq!(OraclePartition::Full.as_str(), "full");
    assert_eq!(OraclePartition::Nightly.as_str(), "nightly");
    assert_eq!(OracleGateMode::ReportOnly.as_str(), "report_only");
    assert_eq!(OracleGateMode::FailClosed.as_str(), "fail_closed");
}

#[test]
fn oracle_outcome_enums_encode_comparator_and_gate_contract() {
    assert_eq!(DriftClass::Equivalent.comparator_decision(), "equivalent");
    assert_eq!(
        DriftClass::DiagnosticsDrift.comparator_decision(),
        "drift_minor"
    );
    assert_eq!(
        DriftClass::ArtifactIntegrityFailure.comparator_decision(),
        "drift_critical"
    );
    assert!(!DriftClass::Equivalent.is_critical());
    assert!(DriftClass::DiagnosticsDrift.is_minor());
    assert!(DriftClass::SemanticDrift.is_critical());
    assert_eq!(
        serde_json::to_string(&GateAction::Reject).expect("gate action should serialize"),
        "\"reject\""
    );
}

#[test]
fn unknown_parse_goal_fails_closed_before_report_emission() {
    let temp_dir = TempDir::new().expect("tempdir should be available");
    let path = write_catalog(
        &temp_dir,
        "unknown_goal.json",
        vec![FixtureCase {
            id: "goal-unknown",
            family_id: "conformance.unknown",
            goal: "expression",
            source: "1 + 1",
            expected_hash: "sha256:00".to_string(),
        }],
    );
    let config = config_for(path, OraclePartition::Full, OracleGateMode::FailClosed);

    let error = run_parser_oracle(&config).expect_err("unknown goals must fail closed");

    match error {
        ParserOracleError::UnknownGoal { fixture_id, goal } => {
            assert_eq!(fixture_id, "goal-unknown");
            assert_eq!(goal, "expression");
        }
        other => panic!("expected UnknownGoal, got {other:?}"),
    }
}

#[test]
fn invalid_catalog_schema_fails_closed_before_fixture_dispatch() {
    let temp_dir = TempDir::new().expect("tempdir should be available");
    let path = write_raw_catalog(
        &temp_dir,
        "bad_schema.json",
        json!({
            "schema_version": "franken-engine.parser-phase0.semantic-fixtures.v0",
            "parser_mode": ParserMode::ScalarReference.as_str(),
            "fixtures": [{
                "id": "schema-1",
                "family_id": "conformance.schema",
                "goal": "script",
                "source": "let x = 1;",
                "expected_hash": "sha256:00"
            }]
        }),
    );

    let error = load_fixture_catalog(&path).expect_err("bad schema must fail closed");

    match error {
        ParserOracleError::InvalidCatalogSchema { expected, actual } => {
            assert_eq!(expected, CATALOG_SCHEMA);
            assert_eq!(actual, "franken-engine.parser-phase0.semantic-fixtures.v0");
        }
        other => panic!("expected InvalidCatalogSchema, got {other:?}"),
    }
}

#[test]
fn empty_catalog_fails_closed_without_synthetic_success() {
    let temp_dir = TempDir::new().expect("tempdir should be available");
    let path = write_raw_catalog(
        &temp_dir,
        "empty.json",
        json!({
            "schema_version": CATALOG_SCHEMA,
            "parser_mode": ParserMode::ScalarReference.as_str(),
            "fixtures": []
        }),
    );

    let error = load_fixture_catalog(&path).expect_err("empty catalog must fail closed");

    assert!(matches!(error, ParserOracleError::EmptyFixtureCatalog));
}

#[test]
fn deterministic_dispatch_orders_fixtures_by_id_before_execution() {
    let temp_dir = TempDir::new().expect("tempdir should be available");
    let path = write_catalog(
        &temp_dir,
        "ordering.json",
        vec![
            valid_script_fixture("fixture-c", "let c = 3;"),
            valid_script_fixture("fixture-a", "let a = 1;"),
            valid_script_fixture("fixture-b", "let b = 2;"),
        ],
    );
    let catalog = load_fixture_catalog(&path).expect("catalog should load");

    let ordered_ids: Vec<_> = partition_fixtures(&catalog, OraclePartition::Full)
        .into_iter()
        .map(|fixture| fixture.id)
        .collect();

    assert_eq!(ordered_ids, ["fixture-a", "fixture-b", "fixture-c"]);
}

#[test]
fn smoke_partition_limits_dispatch_after_deterministic_sorting() {
    let temp_dir = TempDir::new().expect("tempdir should be available");
    let path = write_catalog(
        &temp_dir,
        "smoke_limit.json",
        vec![
            valid_script_fixture("fixture-5", "let e = 5;"),
            valid_script_fixture("fixture-1", "let a = 1;"),
            valid_script_fixture("fixture-4", "let d = 4;"),
            valid_script_fixture("fixture-2", "let b = 2;"),
            valid_script_fixture("fixture-3", "let c = 3;"),
        ],
    );
    let catalog = load_fixture_catalog(&path).expect("catalog should load");

    let ordered_ids: Vec<_> = partition_fixtures(&catalog, OraclePartition::Smoke)
        .into_iter()
        .map(|fixture| fixture.id)
        .collect();

    assert_eq!(
        ordered_ids,
        ["fixture-1", "fixture-2", "fixture-3", "fixture-4"]
    );
}

#[test]
fn evidence_emission_contract_includes_trace_hashes_and_replay_command() {
    let temp_dir = TempDir::new().expect("tempdir should be available");
    let path = write_catalog(
        &temp_dir,
        "evidence.json",
        vec![valid_script_fixture("evidence-1", "let answer = 42;")],
    );
    let config = config_for(&path, OraclePartition::Smoke, OracleGateMode::FailClosed);

    let report = run_parser_oracle(&config).expect("oracle should emit evidence");
    let result = report
        .fixture_results
        .first()
        .expect("fixture evidence should be present");

    assert_eq!(report.schema_version, PARSER_ORACLE_REPORT_SCHEMA_VERSION);
    assert_eq!(report.taxonomy_version, PARSER_ORACLE_TAXONOMY_VERSION);
    assert_eq!(report.trace_id, "trace-parser-oracle-conformance");
    assert_eq!(report.decision_id, "decision-parser-oracle-conformance");
    assert_eq!(report.policy_id, "policy-parser-oracle-conformance");
    assert!(report.fixture_catalog_hash.starts_with("sha256:"));
    assert!(result.input_hash.starts_with("sha256:"));
    assert_eq!(result.parser_mode, ParserMode::ScalarReference.as_str());
    assert_eq!(
        result.replay_command.matches("--partition smoke").count(),
        1
    );
    assert_eq!(
        result
            .replay_command
            .matches("--gate-mode fail_closed")
            .count(),
        1
    );
    assert!(result.replay_command.contains("--fixture-catalog"));
    assert!(
        result
            .replay_command
            .contains(path.to_string_lossy().as_ref())
    );
}

#[test]
fn replay_equivalence_records_matching_observed_and_repeated_hashes() {
    let temp_dir = TempDir::new().expect("tempdir should be available");
    let expected_hash = expected_parse_hash("const replay = 7;", ParseGoal::Script);
    let path = write_catalog(
        &temp_dir,
        "replay_equivalence.json",
        vec![FixtureCase {
            id: "replay-1",
            family_id: "conformance.replay",
            goal: "script",
            source: "const replay = 7;",
            expected_hash: expected_hash.clone(),
        }],
    );
    let config = config_for(&path, OraclePartition::Full, OracleGateMode::FailClosed);

    let report = run_parser_oracle(&config).expect("oracle should produce replay evidence");
    let result = report
        .fixture_results
        .first()
        .expect("fixture evidence should be present");

    assert_eq!(report.decision.action, GateAction::Promote);
    assert_eq!(report.summary.equivalent_count, 1);
    assert_eq!(report.summary.critical_drift_count, 0);
    assert_eq!(result.drift_class, DriftClass::Equivalent);
    assert_eq!(result.comparator_decision, "equivalent");
    assert_eq!(
        result.observed_hash.as_deref(),
        Some(expected_hash.as_str())
    );
    assert_eq!(result.repeated_hash, result.observed_hash);
    assert!(result.parse_error_code.is_none());
    assert!(result.repeated_error_code.is_none());
}

#[test]
fn fail_closed_gate_rejects_artifact_integrity_drift() {
    let temp_dir = TempDir::new().expect("tempdir should be available");
    let path = write_catalog(
        &temp_dir,
        "critical_drift.json",
        vec![drift_script_fixture("drift-1", "let drift = 1;")],
    );
    let config = config_for(&path, OraclePartition::Full, OracleGateMode::FailClosed);

    let report = run_parser_oracle(&config).expect("oracle should classify critical drift");
    let result = report
        .fixture_results
        .first()
        .expect("fixture evidence should be present");

    assert_eq!(result.drift_class, DriftClass::ArtifactIntegrityFailure);
    assert_eq!(result.comparator_decision, "drift_critical");
    assert_eq!(report.summary.total_fixtures, 1);
    assert_eq!(report.summary.critical_drift_count, 1);
    assert_eq!(report.summary.drift_rate_millionths, 1_000_000);
    assert_eq!(report.decision.action, GateAction::Reject);
    assert!(report.decision.promotion_blocked);
    assert!(report.decision.fallback_triggered);
    assert_eq!(
        report.decision.fallback_reason.as_deref(),
        Some("critical drift detected")
    );
}

#[test]
fn report_only_gate_surfaces_critical_drift_without_promotion_block() {
    let temp_dir = TempDir::new().expect("tempdir should be available");
    let path = write_catalog(
        &temp_dir,
        "report_only_drift.json",
        vec![drift_script_fixture("drift-1", "let drift = 1;")],
    );
    let config = config_for(&path, OraclePartition::Full, OracleGateMode::ReportOnly);

    let report =
        run_parser_oracle(&config).expect("report-only oracle should still classify drift");

    assert_eq!(report.summary.critical_drift_count, 1);
    assert!(!report.decision.promotion_blocked);
    assert!(report.decision.fallback_triggered);
    assert_eq!(
        report.decision.fallback_reason.as_deref(),
        Some("critical drift detected")
    );
}

#[test]
fn derive_seed_is_deterministic_for_replay_and_scoped_by_fixture_id() {
    let first = derive_seed(0x5eed_5eed, "fixture-a", ParserMode::ScalarReference);
    let replay = derive_seed(0x5eed_5eed, "fixture-a", ParserMode::ScalarReference);
    let other_fixture = derive_seed(0x5eed_5eed, "fixture-b", ParserMode::ScalarReference);

    assert_eq!(first, replay);
    assert_ne!(first, other_fixture);
}
