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

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser, ParserMode};
use frankenengine_engine::parser_oracle::{
    DriftClass, OracleGateMode, OraclePartition, ParserOracleConfig, derive_seed, run_parser_oracle,
};
use serde_json::json;

fn fixture_hash(source: &str, goal: ParseGoal) -> String {
    CanonicalEs2020Parser
        .parse(source, goal)
        .unwrap_or_else(|error| panic!("failed to parse `{source}` for fixture hash: {error}"))
        .canonical_hash()
}

fn write_fixture_catalog(fixtures: serde_json::Value) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("franken_engine_parser_oracle_{nanos}.json"));
    let payload = json!({
        "schema_version": "franken-engine.parser-phase0.semantic-fixtures.v1",
        "parser_mode": "scalar_reference",
        "fixtures": fixtures
    });
    fs::write(
        &path,
        serde_json::to_vec_pretty(&payload).expect("serialize fixture catalog"),
    )
    .expect("write fixture catalog");
    path
}

#[test]
fn derive_seed_is_deterministic_and_mode_scoped() {
    let first = derive_seed(17, "fixture_a", ParserMode::ScalarReference);
    let second = derive_seed(17, "fixture_a", ParserMode::ScalarReference);
    let third = derive_seed(17, "fixture_b", ParserMode::ScalarReference);
    assert_eq!(first, second);
    assert_ne!(first, third);
}

#[test]
fn smoke_partition_selects_four_sorted_fixtures() {
    let fixtures = json!([
        {
            "id": "fixture_zeta",
            "family_id": "statement.expression",
            "goal": "script",
            "source": "alpha",
            "expected_hash": fixture_hash("alpha", ParseGoal::Script)
        },
        {
            "id": "fixture_beta",
            "family_id": "statement.expression",
            "goal": "script",
            "source": "beta",
            "expected_hash": fixture_hash("beta", ParseGoal::Script)
        },
        {
            "id": "fixture_theta",
            "family_id": "statement.expression",
            "goal": "script",
            "source": "theta",
            "expected_hash": fixture_hash("theta", ParseGoal::Script)
        },
        {
            "id": "fixture_alpha",
            "family_id": "statement.expression",
            "goal": "script",
            "source": "alpha + beta",
            "expected_hash": fixture_hash("alpha + beta", ParseGoal::Script)
        },
        {
            "id": "fixture_delta",
            "family_id": "statement.expression",
            "goal": "script",
            "source": "delta",
            "expected_hash": fixture_hash("delta", ParseGoal::Script)
        }
    ]);
    let path = write_fixture_catalog(fixtures);

    let mut config =
        ParserOracleConfig::with_defaults(OraclePartition::Smoke, OracleGateMode::FailClosed, 7);
    config.fixture_catalog_path = path.clone();
    config.trace_id = "trace-test-smoke".to_string();
    config.decision_id = "decision-test-smoke".to_string();
    config.policy_id = "policy-test-smoke".to_string();

    let report = run_parser_oracle(&config).expect("run parser oracle");
    assert_eq!(
        report.taxonomy_version,
        "franken-engine.parser-oracle.taxonomy.v1"
    );
    assert_eq!(report.summary.total_fixtures, 4);
    let ids: Vec<&str> = report
        .fixture_results
        .iter()
        .map(|entry| entry.fixture_id.as_str())
        .collect();
    assert_eq!(
        ids,
        vec![
            "fixture_alpha",
            "fixture_beta",
            "fixture_delta",
            "fixture_theta"
        ]
    );
    assert!(!report.decision.promotion_blocked);

    let _ = fs::remove_file(path);
}

#[test]
fn artifact_hash_mismatch_is_critical_in_fail_closed_mode() {
    let fixtures = json!([
        {
            "id": "fixture_bad_hash",
            "family_id": "statement.expression",
            "goal": "script",
            "source": "alpha",
            "expected_hash": "sha256:deadbeef"
        }
    ]);
    let path = write_fixture_catalog(fixtures);

    let mut config =
        ParserOracleConfig::with_defaults(OraclePartition::Full, OracleGateMode::FailClosed, 13);
    config.fixture_catalog_path = path.clone();
    config.trace_id = "trace-test-fail-closed".to_string();
    config.decision_id = "decision-test-fail-closed".to_string();
    config.policy_id = "policy-test-fail-closed".to_string();

    let report = run_parser_oracle(&config).expect("run parser oracle");
    assert_eq!(
        report.taxonomy_version,
        "franken-engine.parser-oracle.taxonomy.v1"
    );
    assert_eq!(report.summary.critical_drift_count, 1);
    assert!(report.decision.promotion_blocked);
    assert_eq!(
        report.decision.action,
        frankenengine_engine::parser_oracle::GateAction::Reject
    );
    assert_eq!(
        report.fixture_results[0].drift_class,
        DriftClass::ArtifactIntegrityFailure
    );

    let _ = fs::remove_file(path);
}

#[test]
fn report_only_mode_does_not_block_even_when_critical_drift_exists() {
    let fixtures = json!([
        {
            "id": "fixture_bad_hash",
            "family_id": "statement.expression",
            "goal": "script",
            "source": "alpha",
            "expected_hash": "sha256:deadbeef"
        }
    ]);
    let path = write_fixture_catalog(fixtures);

    let mut config =
        ParserOracleConfig::with_defaults(OraclePartition::Full, OracleGateMode::ReportOnly, 13);
    config.fixture_catalog_path = path.clone();
    config.trace_id = "trace-test-report-only".to_string();
    config.decision_id = "decision-test-report-only".to_string();
    config.policy_id = "policy-test-report-only".to_string();

    let report = run_parser_oracle(&config).expect("run parser oracle");
    assert_eq!(
        report.taxonomy_version,
        "franken-engine.parser-oracle.taxonomy.v1"
    );
    assert_eq!(report.summary.critical_drift_count, 1);
    assert!(!report.decision.promotion_blocked);
    assert!(report.decision.fallback_triggered);

    let _ = fs::remove_file(path);
}

// ---------- OraclePartition ----------

#[test]
fn oracle_partition_as_str_values() {
    assert_eq!(OraclePartition::Smoke.as_str(), "smoke");
    assert_eq!(OraclePartition::Full.as_str(), "full");
    assert_eq!(OraclePartition::Nightly.as_str(), "nightly");
}

#[test]
fn oracle_partition_smoke_fixture_limit_is_four() {
    assert_eq!(OraclePartition::Smoke.fixture_limit(), Some(4));
}

#[test]
fn oracle_partition_full_has_no_fixture_limit() {
    assert_eq!(OraclePartition::Full.fixture_limit(), None);
}

#[test]
fn oracle_partition_nightly_has_no_fixture_limit() {
    assert_eq!(OraclePartition::Nightly.fixture_limit(), None);
}

#[test]
fn oracle_partition_metamorphic_pairs_increase_by_tier() {
    assert!(OraclePartition::Smoke.metamorphic_pairs() < OraclePartition::Full.metamorphic_pairs());
    assert!(
        OraclePartition::Full.metamorphic_pairs() < OraclePartition::Nightly.metamorphic_pairs()
    );
}

#[test]
fn oracle_partition_from_str_roundtrip() {
    for p in [
        OraclePartition::Smoke,
        OraclePartition::Full,
        OraclePartition::Nightly,
    ] {
        let parsed: OraclePartition = p.as_str().parse().expect("parse partition");
        assert_eq!(parsed, p);
    }
}

// ---------- OracleGateMode ----------

#[test]
fn oracle_gate_mode_as_str_values() {
    assert_eq!(OracleGateMode::ReportOnly.as_str(), "report_only");
    assert_eq!(OracleGateMode::FailClosed.as_str(), "fail_closed");
}

#[test]
fn oracle_gate_mode_from_str_roundtrip() {
    for m in [OracleGateMode::ReportOnly, OracleGateMode::FailClosed] {
        let parsed: OracleGateMode = m.as_str().parse().expect("parse gate mode");
        assert_eq!(parsed, m);
    }
}

// ---------- DriftClass ----------

#[test]
fn drift_class_equivalent_is_not_critical_or_minor() {
    assert!(!DriftClass::Equivalent.is_critical());
    assert!(!DriftClass::Equivalent.is_minor());
}

#[test]
fn drift_class_semantic_drift_is_critical() {
    assert!(DriftClass::SemanticDrift.is_critical());
    assert!(!DriftClass::SemanticDrift.is_minor());
}

#[test]
fn drift_class_diagnostics_drift_is_minor() {
    assert!(!DriftClass::DiagnosticsDrift.is_critical());
    assert!(DriftClass::DiagnosticsDrift.is_minor());
}

#[test]
fn drift_class_harness_nondeterminism_is_critical() {
    assert!(DriftClass::HarnessNondeterminism.is_critical());
}

#[test]
fn drift_class_artifact_integrity_failure_is_critical() {
    assert!(DriftClass::ArtifactIntegrityFailure.is_critical());
}

#[test]
fn drift_class_comparator_decisions() {
    assert_eq!(DriftClass::Equivalent.comparator_decision(), "equivalent");
    assert_eq!(
        DriftClass::DiagnosticsDrift.comparator_decision(),
        "drift_minor"
    );
    assert_eq!(
        DriftClass::SemanticDrift.comparator_decision(),
        "drift_critical"
    );
    assert_eq!(
        DriftClass::HarnessNondeterminism.comparator_decision(),
        "drift_critical"
    );
    assert_eq!(
        DriftClass::ArtifactIntegrityFailure.comparator_decision(),
        "drift_critical"
    );
}

// ---------- full partition ----------

#[test]
fn full_partition_uses_all_fixtures() {
    let fixtures = json!([
        { "id": "f1", "family_id": "fam", "goal": "script", "source": "a", "expected_hash": fixture_hash("a", ParseGoal::Script) },
        { "id": "f2", "family_id": "fam", "goal": "script", "source": "b", "expected_hash": fixture_hash("b", ParseGoal::Script) },
        { "id": "f3", "family_id": "fam", "goal": "script", "source": "c", "expected_hash": fixture_hash("c", ParseGoal::Script) },
        { "id": "f4", "family_id": "fam", "goal": "script", "source": "d", "expected_hash": fixture_hash("d", ParseGoal::Script) },
        { "id": "f5", "family_id": "fam", "goal": "script", "source": "e", "expected_hash": fixture_hash("e", ParseGoal::Script) }
    ]);
    let path = write_fixture_catalog(fixtures);
    let mut config =
        ParserOracleConfig::with_defaults(OraclePartition::Full, OracleGateMode::FailClosed, 42);
    config.fixture_catalog_path = path.clone();
    config.trace_id = "trace-full".to_string();
    config.decision_id = "decision-full".to_string();
    config.policy_id = "policy-full".to_string();
    let report = run_parser_oracle(&config).expect("oracle");
    assert_eq!(report.summary.total_fixtures, 5);
    assert_eq!(report.fixture_results.len(), 5);
    let _ = fs::remove_file(path);
}

// ---------- all equivalent = Promote ----------

#[test]
fn all_equivalent_fixtures_produce_promote_action() {
    let fixtures = json!([
        { "id": "ok1", "family_id": "fam", "goal": "script", "source": "x", "expected_hash": fixture_hash("x", ParseGoal::Script) },
        { "id": "ok2", "family_id": "fam", "goal": "script", "source": "y", "expected_hash": fixture_hash("y", ParseGoal::Script) }
    ]);
    let path = write_fixture_catalog(fixtures);
    let mut config =
        ParserOracleConfig::with_defaults(OraclePartition::Full, OracleGateMode::FailClosed, 99);
    config.fixture_catalog_path = path.clone();
    config.trace_id = "trace-promote".to_string();
    config.decision_id = "decision-promote".to_string();
    config.policy_id = "policy-promote".to_string();
    let report = run_parser_oracle(&config).expect("oracle");
    assert_eq!(report.summary.equivalent_count, 2);
    assert_eq!(report.summary.critical_drift_count, 0);
    assert_eq!(report.summary.minor_drift_count, 0);
    assert!(!report.decision.promotion_blocked);
    assert_eq!(
        report.decision.action,
        frankenengine_engine::parser_oracle::GateAction::Promote
    );
    let _ = fs::remove_file(path);
}

// ---------- report fields ----------

#[test]
fn report_schema_version_matches_constant() {
    let fixtures = json!([
        { "id": "sv", "family_id": "fam", "goal": "script", "source": "z", "expected_hash": fixture_hash("z", ParseGoal::Script) }
    ]);
    let path = write_fixture_catalog(fixtures);
    let mut config =
        ParserOracleConfig::with_defaults(OraclePartition::Full, OracleGateMode::ReportOnly, 1);
    config.fixture_catalog_path = path.clone();
    config.trace_id = "trace-sv".to_string();
    config.decision_id = "decision-sv".to_string();
    config.policy_id = "policy-sv".to_string();
    let report = run_parser_oracle(&config).expect("oracle");
    assert_eq!(
        report.schema_version,
        frankenengine_engine::parser_oracle::PARSER_ORACLE_REPORT_SCHEMA_VERSION
    );
    assert_eq!(
        report.taxonomy_version,
        frankenengine_engine::parser_oracle::PARSER_ORACLE_TAXONOMY_VERSION
    );
    let _ = fs::remove_file(path);
}

#[test]
fn report_fixture_results_have_replay_commands() {
    let fixtures = json!([
        { "id": "rc", "family_id": "fam", "goal": "script", "source": "w", "expected_hash": fixture_hash("w", ParseGoal::Script) }
    ]);
    let path = write_fixture_catalog(fixtures);
    let mut config =
        ParserOracleConfig::with_defaults(OraclePartition::Full, OracleGateMode::FailClosed, 2);
    config.fixture_catalog_path = path.clone();
    config.trace_id = "trace-rc".to_string();
    config.decision_id = "decision-rc".to_string();
    config.policy_id = "policy-rc".to_string();
    let report = run_parser_oracle(&config).expect("oracle");
    for result in &report.fixture_results {
        assert!(
            !result.replay_command.is_empty(),
            "must have replay command"
        );
        assert!(!result.fixture_id.is_empty());
        assert!(!result.input_hash.is_empty());
    }
    let _ = fs::remove_file(path);
}

// ---------- derive_seed ----------

#[test]
fn derive_seed_different_master_seeds_diverge() {
    let a = derive_seed(1, "fixture_same", ParserMode::ScalarReference);
    let b = derive_seed(2, "fixture_same", ParserMode::ScalarReference);
    assert_ne!(a, b);
}

// ---------- config defaults ----------

#[test]
fn config_with_defaults_populates_trace_and_decision_ids() {
    let config =
        ParserOracleConfig::with_defaults(OraclePartition::Smoke, OracleGateMode::FailClosed, 123);
    assert!(!config.trace_id.is_empty());
    assert!(!config.decision_id.is_empty());
    assert!(!config.policy_id.is_empty());
    assert_eq!(config.seed, 123);
}

// ---------- summary drift rate ----------

#[test]
fn summary_drift_rate_zero_when_all_equivalent() {
    let fixtures = json!([
        { "id": "dr", "family_id": "fam", "goal": "script", "source": "v", "expected_hash": fixture_hash("v", ParseGoal::Script) }
    ]);
    let path = write_fixture_catalog(fixtures);
    let mut config =
        ParserOracleConfig::with_defaults(OraclePartition::Full, OracleGateMode::FailClosed, 3);
    config.fixture_catalog_path = path.clone();
    config.trace_id = "trace-dr".to_string();
    config.decision_id = "decision-dr".to_string();
    config.policy_id = "policy-dr".to_string();
    let report = run_parser_oracle(&config).expect("oracle");
    assert_eq!(report.summary.drift_rate_millionths, 0);
    let _ = fs::remove_file(path);
}

// ---------- serde roundtrip ----------

#[test]
fn oracle_report_serde_roundtrip_preserves_all_fields() {
    let fixtures = json!([
        { "id": "serde1", "family_id": "fam", "goal": "script", "source": "q", "expected_hash": fixture_hash("q", ParseGoal::Script) },
        { "id": "serde2", "family_id": "fam", "goal": "script", "source": "r", "expected_hash": "sha256:bad" }
    ]);
    let path = write_fixture_catalog(fixtures);
    let mut config =
        ParserOracleConfig::with_defaults(OraclePartition::Full, OracleGateMode::FailClosed, 55);
    config.fixture_catalog_path = path.clone();
    config.trace_id = "trace-serde-rt".to_string();
    config.decision_id = "decision-serde-rt".to_string();
    config.policy_id = "policy-serde-rt".to_string();
    let report = run_parser_oracle(&config).expect("oracle");

    let json_bytes = serde_json::to_vec(&report).expect("serialize report");
    let recovered: serde_json::Value =
        serde_json::from_slice(&json_bytes).expect("deserialize report");
    let obj = recovered.as_object().expect("report should be an object");

    assert!(obj.contains_key("schema_version"));
    assert!(obj.contains_key("taxonomy_version"));
    assert!(obj.contains_key("summary"));
    assert!(obj.contains_key("decision"));
    assert!(obj.contains_key("fixture_results"));

    let results = obj["fixture_results"].as_array().expect("results array");
    assert_eq!(results.len(), 2);
    assert_eq!(obj["summary"]["critical_drift_count"].as_u64().unwrap(), 1);
    let _ = fs::remove_file(path);
}

// ---------- drift_rate nonzero ----------

#[test]
fn summary_drift_rate_nonzero_when_critical_drift_present() {
    let fixtures = json!([
        { "id": "good", "family_id": "fam", "goal": "script", "source": "m", "expected_hash": fixture_hash("m", ParseGoal::Script) },
        { "id": "bad",  "family_id": "fam", "goal": "script", "source": "n", "expected_hash": "sha256:wrong" }
    ]);
    let path = write_fixture_catalog(fixtures);
    let mut config =
        ParserOracleConfig::with_defaults(OraclePartition::Full, OracleGateMode::FailClosed, 77);
    config.fixture_catalog_path = path.clone();
    config.trace_id = "trace-nonzero-dr".to_string();
    config.decision_id = "decision-nonzero-dr".to_string();
    config.policy_id = "policy-nonzero-dr".to_string();
    let report = run_parser_oracle(&config).expect("oracle");
    assert!(
        report.summary.drift_rate_millionths > 0,
        "drift rate must be positive when a fixture has critical drift"
    );
    let _ = fs::remove_file(path);
}

// ---------- derive_seed mode isolation ----------

#[test]
fn derive_seed_varies_with_fixture_id_not_just_master_seed() {
    let a = derive_seed(42, "fixture_one", ParserMode::ScalarReference);
    let b = derive_seed(42, "fixture_two", ParserMode::ScalarReference);
    let c = derive_seed(42, "fixture_one", ParserMode::ScalarReference);
    assert_ne!(
        a, b,
        "same master seed but different fixture IDs must produce different seeds"
    );
    assert_eq!(a, c, "identical inputs must produce identical seeds");
}

// ---------- smoke partition truncation ----------

#[test]
fn smoke_partition_truncates_to_four_even_with_many_fixtures() {
    let mut fixture_array = Vec::new();
    for i in 0..10 {
        let src = format!("src_{i}");
        fixture_array.push(json!({
            "id": format!("fix_{i}"),
            "family_id": "fam",
            "goal": "script",
            "source": src,
            "expected_hash": fixture_hash(&src, ParseGoal::Script)
        }));
    }
    let fixtures = serde_json::Value::Array(fixture_array);
    let path = write_fixture_catalog(fixtures);
    let mut config =
        ParserOracleConfig::with_defaults(OraclePartition::Smoke, OracleGateMode::FailClosed, 99);
    config.fixture_catalog_path = path.clone();
    config.trace_id = "trace-trunc".to_string();
    config.decision_id = "decision-trunc".to_string();
    config.policy_id = "policy-trunc".to_string();
    let report = run_parser_oracle(&config).expect("oracle");
    assert_eq!(
        report.summary.total_fixtures, 4,
        "smoke partition must limit to 4 fixtures regardless of catalog size"
    );
    assert_eq!(report.fixture_results.len(), 4);
    let _ = fs::remove_file(path);
}

// ---------- nightly partition uses all fixtures ----------

#[test]
fn nightly_partition_uses_all_fixtures_like_full() {
    let fixtures = json!([
        { "id": "n1", "family_id": "fam", "goal": "script", "source": "aa", "expected_hash": fixture_hash("aa", ParseGoal::Script) },
        { "id": "n2", "family_id": "fam", "goal": "script", "source": "bb", "expected_hash": fixture_hash("bb", ParseGoal::Script) },
        { "id": "n3", "family_id": "fam", "goal": "script", "source": "cc", "expected_hash": fixture_hash("cc", ParseGoal::Script) },
        { "id": "n4", "family_id": "fam", "goal": "script", "source": "dd", "expected_hash": fixture_hash("dd", ParseGoal::Script) },
        { "id": "n5", "family_id": "fam", "goal": "script", "source": "ee", "expected_hash": fixture_hash("ee", ParseGoal::Script) },
        { "id": "n6", "family_id": "fam", "goal": "script", "source": "ff", "expected_hash": fixture_hash("ff", ParseGoal::Script) }
    ]);
    let path = write_fixture_catalog(fixtures);
    let mut config =
        ParserOracleConfig::with_defaults(OraclePartition::Nightly, OracleGateMode::FailClosed, 11);
    config.fixture_catalog_path = path.clone();
    config.trace_id = "trace-nightly".to_string();
    config.decision_id = "decision-nightly".to_string();
    config.policy_id = "policy-nightly".to_string();
    let report = run_parser_oracle(&config).expect("oracle");
    assert_eq!(
        report.summary.total_fixtures, 6,
        "nightly partition must include all fixtures (no limit)"
    );
    assert!(!report.decision.promotion_blocked);
    let _ = fs::remove_file(path);
}

#[test]
fn drift_class_serde_roundtrip_all_variants() {
    for class in [
        DriftClass::Equivalent,
        DriftClass::DiagnosticsDrift,
        DriftClass::SemanticDrift,
        DriftClass::HarnessNondeterminism,
        DriftClass::ArtifactIntegrityFailure,
    ] {
        let json = serde_json::to_string(&class).expect("serialize drift class");
        let recovered: DriftClass = serde_json::from_str(&json).expect("deserialize drift class");
        assert_eq!(recovered, class, "serde roundtrip must preserve DriftClass");
    }
}

#[test]
fn gate_action_serde_roundtrip() {
    use frankenengine_engine::parser_oracle::GateAction;
    for action in [GateAction::Promote, GateAction::Reject, GateAction::Hold] {
        let json = serde_json::to_string(&action).expect("serialize gate action");
        let recovered: GateAction = serde_json::from_str(&json).expect("deserialize gate action");
        assert_eq!(
            recovered, action,
            "serde roundtrip must preserve GateAction"
        );
    }
}

#[test]
fn load_fixture_catalog_returns_correct_schema() {
    use frankenengine_engine::parser_oracle::load_fixture_catalog;
    let fixtures = json!([
        { "id": "lfc1", "family_id": "fam", "goal": "script", "source": "cat", "expected_hash": fixture_hash("cat", ParseGoal::Script) }
    ]);
    let path = write_fixture_catalog(fixtures);
    let catalog = load_fixture_catalog(&path).expect("load catalog");
    assert_eq!(
        catalog.schema_version,
        "franken-engine.parser-phase0.semantic-fixtures.v1"
    );
    assert_eq!(catalog.parser_mode, "scalar_reference");
    assert_eq!(catalog.fixtures.len(), 1);
    assert_eq!(catalog.fixtures[0].id, "lfc1");
    let _ = fs::remove_file(path);
}

#[test]
fn partition_fixtures_smoke_sorts_and_limits() {
    use frankenengine_engine::parser_oracle::{
        OracleFixtureCatalog, OracleFixtureSpec, partition_fixtures,
    };
    let specs: Vec<OracleFixtureSpec> = (0..8)
        .map(|i| OracleFixtureSpec {
            id: format!("pf_{i}"),
            family_id: "fam".into(),
            goal: "script".into(),
            source: format!("src_{i}"),
            expected_hash: fixture_hash(&format!("src_{i}"), ParseGoal::Script),
        })
        .collect();
    let catalog = OracleFixtureCatalog {
        schema_version: "franken-engine.parser-phase0.semantic-fixtures.v1".into(),
        parser_mode: "scalar_reference".into(),
        fixtures: specs,
    };
    let partitioned = partition_fixtures(&catalog, OraclePartition::Smoke);
    assert_eq!(partitioned.len(), 4, "smoke must limit to 4");
    // Must be sorted by id
    for window in partitioned.windows(2) {
        assert!(
            window[0].id <= window[1].id,
            "partitioned fixtures must be sorted by id"
        );
    }
}

#[test]
fn report_decision_fallback_not_triggered_when_no_drift_in_fail_closed() {
    let fixtures = json!([
        { "id": "no_drift", "family_id": "fam", "goal": "script", "source": "clean", "expected_hash": fixture_hash("clean", ParseGoal::Script) }
    ]);
    let path = write_fixture_catalog(fixtures);
    let mut config =
        ParserOracleConfig::with_defaults(OraclePartition::Full, OracleGateMode::FailClosed, 200);
    config.fixture_catalog_path = path.clone();
    config.trace_id = "trace-no-fb".to_string();
    config.decision_id = "decision-no-fb".to_string();
    config.policy_id = "policy-no-fb".to_string();
    let report = run_parser_oracle(&config).expect("oracle");
    assert!(
        !report.decision.fallback_triggered,
        "fallback should not trigger when no drift"
    );
    assert!(!report.decision.promotion_blocked);
    let _ = fs::remove_file(path);
}

// ===== PearlTower enrichment session 2026-03-14 =====

#[test]
fn enrichment_derive_seed_deterministic_for_same_inputs() {
    let a = derive_seed(1, "fixture_x", ParserMode::ScalarReference);
    let b = derive_seed(1, "fixture_x", ParserMode::ScalarReference);
    assert_eq!(a, b, "same inputs must produce identical seeds");
}

#[test]
fn enrichment_derive_seed_varies_by_invocation() {
    let a = derive_seed(1, "f", ParserMode::ScalarReference);
    let b = derive_seed(2, "f", ParserMode::ScalarReference);
    assert_ne!(
        a, b,
        "different invocation indices must produce different seeds"
    );
}

#[test]
fn enrichment_drift_class_all_variants_distinct() {
    use std::collections::BTreeSet;
    let all = [
        format!("{:?}", DriftClass::Equivalent),
        format!("{:?}", DriftClass::SemanticDrift),
        format!("{:?}", DriftClass::DiagnosticsDrift),
        format!("{:?}", DriftClass::HarnessNondeterminism),
        format!("{:?}", DriftClass::ArtifactIntegrityFailure),
    ];
    let set: BTreeSet<&str> = all.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        set.len(),
        5,
        "all DriftClass variants must have unique debug output"
    );
}

#[test]
fn enrichment_drift_class_debug_all_unique() {
    use std::collections::BTreeSet;
    let all = [
        DriftClass::Equivalent,
        DriftClass::SemanticDrift,
        DriftClass::DiagnosticsDrift,
        DriftClass::HarnessNondeterminism,
        DriftClass::ArtifactIntegrityFailure,
    ];
    let dbgs: BTreeSet<String> = all.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), 5);
}

#[test]
fn enrichment_drift_class_serde_roundtrip() {
    let all = [
        DriftClass::Equivalent,
        DriftClass::SemanticDrift,
        DriftClass::DiagnosticsDrift,
        DriftClass::HarnessNondeterminism,
        DriftClass::ArtifactIntegrityFailure,
    ];
    for dc in &all {
        let json = serde_json::to_string(dc).unwrap();
        let back: DriftClass = serde_json::from_str(&json).unwrap();
        assert_eq!(dc, &back);
    }
}

#[test]
fn enrichment_oracle_partition_serde_roundtrip() {
    let all = [OraclePartition::Smoke, OraclePartition::Full];
    for p in &all {
        let json = serde_json::to_string(p).unwrap();
        let back: OraclePartition = serde_json::from_str(&json).unwrap();
        assert_eq!(p, &back);
    }
}

#[test]
fn enrichment_oracle_gate_mode_serde_roundtrip() {
    let all = [OracleGateMode::FailClosed, OracleGateMode::ReportOnly];
    for m in &all {
        let json = serde_json::to_string(m).unwrap();
        let back: OracleGateMode = serde_json::from_str(&json).unwrap();
        assert_eq!(m, &back);
    }
}

#[test]
fn enrichment_parser_oracle_config_defaults_are_sensible() {
    let config =
        ParserOracleConfig::with_defaults(OraclePartition::Smoke, OracleGateMode::FailClosed, 100);
    assert!(!config.trace_id.is_empty());
    assert!(!config.decision_id.is_empty());
    assert!(!config.policy_id.is_empty());
    assert_eq!(config.seed, 100);
}

#[test]
fn enrichment_oracle_report_serde_for_clean_run() {
    let fixtures = json!([
        { "id": "serde_clean", "family_id": "fam", "goal": "script", "source": "var x = 1", "expected_hash": fixture_hash("var x = 1", ParseGoal::Script) }
    ]);
    let path = write_fixture_catalog(fixtures);
    let mut config =
        ParserOracleConfig::with_defaults(OraclePartition::Full, OracleGateMode::FailClosed, 200);
    config.fixture_catalog_path = path.clone();
    config.trace_id = "trace-serde".to_string();
    config.decision_id = "decision-serde".to_string();
    config.policy_id = "policy-serde".to_string();
    let report = run_parser_oracle(&config).expect("oracle");
    let json_str = serde_json::to_string(&report).expect("serialize report");
    let _: serde_json::Value = serde_json::from_str(&json_str).expect("reparse report");
    let _ = fs::remove_file(path);
}

#[test]
fn enrichment_oracle_report_deterministic_for_same_input() {
    let fixtures = json!([
        { "id": "det_check", "family_id": "fam", "goal": "script", "source": "1+2", "expected_hash": fixture_hash("1+2", ParseGoal::Script) }
    ]);
    let path = write_fixture_catalog(fixtures);
    let mut config =
        ParserOracleConfig::with_defaults(OraclePartition::Full, OracleGateMode::FailClosed, 200);
    config.fixture_catalog_path = path.clone();
    config.trace_id = "trace-det".to_string();
    config.decision_id = "decision-det".to_string();
    config.policy_id = "policy-det".to_string();
    let r1 = run_parser_oracle(&config).expect("oracle 1");
    let r2 = run_parser_oracle(&config).expect("oracle 2");
    assert_eq!(
        r1.decision.fallback_triggered,
        r2.decision.fallback_triggered
    );
    assert_eq!(r1.decision.promotion_blocked, r2.decision.promotion_blocked);
    let _ = fs::remove_file(path);
}
