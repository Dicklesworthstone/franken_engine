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
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::parser_multi_engine_harness::{
    AstNormalizationAdapter, DiagnosticNormalizationAdapter, DriftCategory, DriftSeverity,
    EngineOutcomeKind, GovernanceActionKind, HarnessEngineKind, HarnessEngineSpec,
    MultiEngineHarnessConfig, MultiEngineHarnessError, build_drift_governance_action_report,
    derive_drift_governance_actions, derive_engine_seed, has_critical_drift, load_fixture_catalog,
    run_multi_engine_harness,
};

type EngineSignature = (String, String, bool, bool);
type FixtureSignature = (String, Vec<EngineSignature>);
type TelemetryDeterministicSignature = (String, u64, u64, u64, u64);

fn test_config(seed: u64) -> MultiEngineHarnessConfig {
    let mut config = MultiEngineHarnessConfig::with_defaults(seed);
    config.fixture_catalog_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/parser_phase0_semantic_fixtures.json");
    config.fixture_limit = Some(2);
    config.trace_id = "trace-parser-multi-engine-integration".to_string();
    config.decision_id = "decision-parser-multi-engine-integration".to_string();
    config.policy_id = "policy-parser-multi-engine-integration-v1".to_string();
    config
}

fn write_empty_source_fixture_catalog() -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "franken-engine-parser-harness-empty-source-{timestamp}.json"
    ));
    let payload = serde_json::json!({
        "schema_version": "franken-engine.parser-phase0.semantic-fixtures.v1",
        "parser_mode": "scalar_reference",
        "fixtures": [
            {
                "id": "empty-source-diagnostic-parity",
                "family_id": "diagnostics.empty_source",
                "goal": "script",
                "source": "   ",
                "expected_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            }
        ]
    });
    fs::write(
        &path,
        serde_json::to_vec_pretty(&payload).expect("catalog payload should serialize"),
    )
    .expect("fixture catalog should write");
    path
}

fn stable_fixture_signatures(
    report: &frankenengine_engine::parser_multi_engine_harness::MultiEngineHarnessReport,
) -> Vec<FixtureSignature> {
    report
        .fixture_results
        .iter()
        .map(|fixture| {
            let engine_rows = fixture
                .engine_results
                .iter()
                .map(|engine| {
                    (
                        engine.engine_id.clone(),
                        format!("{:?}:{}", engine.first_run.kind, engine.first_run.value),
                        engine.first_run.deterministic,
                        engine.second_run.deterministic,
                    )
                })
                .collect::<Vec<_>>();
            (fixture.fixture_id.clone(), engine_rows)
        })
        .collect()
}

fn stable_telemetry_signature(
    report: &frankenengine_engine::parser_multi_engine_harness::MultiEngineHarnessReport,
) -> TelemetryDeterministicSignature {
    (
        report.parser_telemetry.schema_version.clone(),
        report.parser_telemetry.sample_count,
        report.parser_telemetry.bytes_per_source_avg,
        report.parser_telemetry.tokens_per_source_avg,
        report.parser_telemetry.allocs_per_token_millionths,
    )
}

#[test]
fn harness_report_is_stable_for_same_seed_and_fixture_slice() {
    let config = test_config(7);
    let left = run_multi_engine_harness(&config).expect("left run should succeed");
    let right = run_multi_engine_harness(&config).expect("right run should succeed");

    assert_eq!(left.run_id, right.run_id);
    assert_eq!(left.fixture_catalog_hash, right.fixture_catalog_hash);
    assert_eq!(left.summary, right.summary);
    assert_eq!(
        stable_fixture_signatures(&left),
        stable_fixture_signatures(&right)
    );
    assert_eq!(
        stable_telemetry_signature(&left),
        stable_telemetry_signature(&right)
    );

    for fixture in &left.fixture_results {
        assert!(
            fixture
                .replay_command
                .contains("franken_parser_multi_engine_harness"),
            "missing replay command for fixture `{}`",
            fixture.fixture_id
        );
        assert!(
            fixture.replay_command.contains("--fixture-id"),
            "replay command should include fixture id for `{}`",
            fixture.fixture_id
        );
    }
}

#[test]
fn harness_report_exposes_parser_telemetry_contract() {
    let config = test_config(17);
    let report = run_multi_engine_harness(&config).expect("run should succeed");
    let telemetry = &report.parser_telemetry;

    assert_eq!(
        telemetry.schema_version,
        "franken-engine.parser-telemetry.v1"
    );
    assert_eq!(telemetry.sample_count, report.fixture_count * 2);
    assert_eq!(report.trace_id, config.trace_id);
    assert_eq!(report.decision_id, config.decision_id);
    assert_eq!(report.policy_id, config.policy_id);
    assert!(telemetry.bytes_per_source_avg > 0);
    assert!(telemetry.tokens_per_source_avg > 0);
    assert!(telemetry.allocs_per_token_millionths > 0);
    assert!(telemetry.latency_ns_p50 <= telemetry.latency_ns_p95);
    assert!(telemetry.latency_ns_p95 <= telemetry.latency_ns_p99);
}

#[test]
fn harness_detects_external_engine_divergence_deterministically() {
    let mut config = test_config(13);
    config.fixture_limit = Some(1);
    config.engines = vec![
        HarnessEngineSpec::franken_canonical("frankenengine-engine@workspace"),
        HarnessEngineSpec {
            engine_id: "external_mock".to_string(),
            display_name: "External Mock".to_string(),
            kind: HarnessEngineKind::ExternalCommand,
            version_pin: "external-mock@v1".to_string(),
            command: Some("sh".to_string()),
            args: vec![
                "-c".to_string(),
                "cat >/dev/null; printf '{\"hash\":\"sha256:0000000000000000000000000000000000000000000000000000000000000000\"}\\n'"
                    .to_string(),
            ],
        },
    ];

    let report = run_multi_engine_harness(&config).expect("run should succeed");
    assert_eq!(report.summary.total_fixtures, 1);
    assert_eq!(report.summary.divergent_fixtures, 1);
    assert_eq!(report.summary.fixtures_with_nondeterminism, 0);
    assert_eq!(report.fixture_results.len(), 1);
    assert!(!report.fixture_results[0].equivalent_across_engines);
    assert!(
        report.fixture_results[0]
            .divergence_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("external_mock")),
        "divergence reason should name external engine"
    );
    let classification = report.fixture_results[0]
        .drift_classification
        .as_ref()
        .expect("drift classification");
    assert_eq!(classification.category, DriftCategory::Semantic);
    assert_eq!(classification.severity, DriftSeverity::Critical);
    assert_eq!(classification.owner_hint, "parser-core");
    let repro_pack = report.fixture_results[0]
        .repro_pack
        .as_ref()
        .expect("repro pack should exist for divergent fixture");
    assert_eq!(repro_pack.fixture_id, report.fixture_results[0].fixture_id);
    assert_eq!(repro_pack.drift_classification, *classification);
    assert!(repro_pack.provenance_hash.starts_with("sha256:"));
    assert!(repro_pack.minimized_source_hash.starts_with("sha256:"));
    assert!(repro_pack.minimization.minimized_bytes <= repro_pack.minimization.original_bytes);
    assert_eq!(repro_pack.promotion_hooks.len(), 3);
    assert!(has_critical_drift(&report));

    let actions = derive_drift_governance_actions(&report);
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].owner_hint, "parser-core");
    assert_eq!(actions[0].severity, DriftSeverity::Critical);
    assert_eq!(actions[0].bead_id.len(), "bd-auto-".len() + 8);
    assert_eq!(actions[0].fingerprint, repro_pack.provenance_hash);
    assert_eq!(
        actions[0].minimized_source_hash,
        repro_pack.minimized_source_hash
    );

    let governance = build_drift_governance_action_report(&report);
    assert_eq!(governance.run_id, report.run_id);
    assert_eq!(governance.trace_id, report.trace_id);
    assert_eq!(governance.actions, actions);
}

#[test]
fn harness_returns_explicit_error_when_fixture_filter_is_missing() {
    let mut config = test_config(5);
    config.fixture_id_filter = Some("does-not-exist".to_string());
    let err = run_multi_engine_harness(&config).expect_err("missing fixture should fail");
    assert!(
        matches!(
            err,
            MultiEngineHarnessError::FixtureFilterNotFound { ref fixture_id }
            if fixture_id == "does-not-exist"
        ),
        "unexpected error variant: {err}"
    );
}

#[test]
fn harness_normalizes_equivalent_parse_errors_across_engines() {
    let fixture_catalog = write_empty_source_fixture_catalog();

    let mut config = MultiEngineHarnessConfig::with_defaults(23);
    config.fixture_catalog_path = fixture_catalog.clone();
    config.fixture_limit = Some(1);
    config.trace_id = "trace-parser-multi-engine-diagnostic-normalization".to_string();
    config.decision_id = "decision-parser-multi-engine-diagnostic-normalization".to_string();
    config.policy_id = "policy-parser-multi-engine-diagnostic-normalization-v1".to_string();
    config.engines = vec![
        HarnessEngineSpec::franken_canonical("frankenengine-engine@workspace"),
        HarnessEngineSpec {
            engine_id: "external_lc_error".to_string(),
            display_name: "External Lowercase Error".to_string(),
            kind: HarnessEngineKind::ExternalCommand,
            version_pin: "external-lc-error@v1".to_string(),
            command: Some("sh".to_string()),
            args: vec![
                "-c".to_string(),
                "cat >/dev/null; printf '{\"error_code\":\"empty_source\"}\\n'".to_string(),
            ],
        },
    ];

    let report = run_multi_engine_harness(&config).expect("run should succeed");
    assert_eq!(report.summary.total_fixtures, 1);
    assert_eq!(report.summary.equivalent_fixtures, 1);
    assert_eq!(report.summary.divergent_fixtures, 0);

    let fixture = report
        .fixture_results
        .first()
        .expect("fixture result should exist");
    assert!(
        fixture.equivalent_across_engines,
        "normalized diagnostics should be equivalent across engines"
    );
    assert_eq!(fixture.engine_results.len(), 2);
    let first = fixture.engine_results[0]
        .first_run
        .normalized_diagnostic
        .as_ref()
        .expect("franken diagnostic artifact");
    let second = fixture.engine_results[1]
        .first_run
        .normalized_diagnostic
        .as_ref()
        .expect("external diagnostic artifact");
    assert_eq!(first.diagnostic_code, second.diagnostic_code);
    assert_eq!(first.canonical_hash, second.canonical_hash);

    let _ = fs::remove_file(fixture_catalog);
}

#[test]
fn harness_classifies_diagnostics_drift_as_minor() {
    let fixture_catalog = write_empty_source_fixture_catalog();

    let mut config = MultiEngineHarnessConfig::with_defaults(29);
    config.fixture_catalog_path = fixture_catalog.clone();
    config.fixture_limit = Some(1);
    config.trace_id = "trace-parser-multi-engine-diagnostic-drift".to_string();
    config.decision_id = "decision-parser-multi-engine-diagnostic-drift".to_string();
    config.policy_id = "policy-parser-multi-engine-diagnostic-drift-v1".to_string();
    config.engines = vec![
        HarnessEngineSpec::franken_canonical("frankenengine-engine@workspace"),
        HarnessEngineSpec {
            engine_id: "external_invalid_goal".to_string(),
            display_name: "External Invalid Goal".to_string(),
            kind: HarnessEngineKind::ExternalCommand,
            version_pin: "external-invalid-goal@v1".to_string(),
            command: Some("sh".to_string()),
            args: vec![
                "-c".to_string(),
                "cat >/dev/null; printf '{\"error_code\":\"invalid_goal\"}\\n'".to_string(),
            ],
        },
    ];

    let report = run_multi_engine_harness(&config).expect("run should succeed");
    assert_eq!(report.summary.total_fixtures, 1);
    assert_eq!(report.summary.divergent_fixtures, 1);
    assert_eq!(report.summary.drift_minor_fixtures, 1);
    assert_eq!(report.summary.drift_critical_fixtures, 0);

    let fixture = report
        .fixture_results
        .first()
        .expect("fixture result should exist");
    let classification = fixture
        .drift_classification
        .as_ref()
        .expect("classification should exist");
    assert_eq!(classification.category, DriftCategory::Diagnostics);
    assert_eq!(classification.severity, DriftSeverity::Minor);
    assert_eq!(classification.comparator_decision, "drift_minor");
    assert_eq!(classification.owner_hint, "parser-diagnostics-taxonomy");
    let repro_pack = fixture
        .repro_pack
        .as_ref()
        .expect("repro pack should exist");
    assert_eq!(repro_pack.drift_classification, *classification);
    assert!(repro_pack.minimized_source_hash.starts_with("sha256:"));
    assert!(!has_critical_drift(&report));

    let actions = derive_drift_governance_actions(&report);
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].owner_hint, "parser-diagnostics-taxonomy");
    assert_eq!(actions[0].severity, DriftSeverity::Minor);

    let _ = fs::remove_file(fixture_catalog);
}

// ────────────────────────────────────────────────────────────
// Enrichment: serde, display, defaults, edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn drift_category_serde_round_trip_all_variants() {
    for category in [
        DriftCategory::Semantic,
        DriftCategory::Diagnostics,
        DriftCategory::Harness,
        DriftCategory::Artifact,
    ] {
        let json = serde_json::to_string(&category).expect("serialize");
        let recovered: DriftCategory = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(category, recovered);
    }
}

#[test]
fn drift_severity_serde_round_trip() {
    for severity in [DriftSeverity::Minor, DriftSeverity::Critical] {
        let json = serde_json::to_string(&severity).expect("serialize");
        let recovered: DriftSeverity = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(severity, recovered);
    }
}

#[test]
fn harness_engine_kind_serde_round_trip_all_variants() {
    for kind in [
        HarnessEngineKind::FrankenCanonical,
        HarnessEngineKind::FixtureExpectedHash,
        HarnessEngineKind::ExternalCommand,
    ] {
        let json = serde_json::to_string(&kind).expect("serialize");
        let recovered: HarnessEngineKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(kind, recovered);
    }
}

#[test]
fn harness_engine_spec_franken_canonical_has_stable_engine_id() {
    let spec = HarnessEngineSpec::franken_canonical("frankenengine-engine@workspace");
    assert_eq!(spec.kind, HarnessEngineKind::FrankenCanonical);
    assert!(!spec.engine_id.is_empty());
    assert!(!spec.display_name.is_empty());
    let json = serde_json::to_string(&spec).expect("serialize");
    let recovered: HarnessEngineSpec = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(spec, recovered);
}

#[test]
fn multi_engine_harness_config_with_defaults_produces_stable_config() {
    let a = MultiEngineHarnessConfig::with_defaults(42);
    let b = MultiEngineHarnessConfig::with_defaults(42);
    assert_eq!(a.trace_id, b.trace_id);
    assert_eq!(a.decision_id, b.decision_id);
    assert!(!a.engines.is_empty());
}

#[test]
fn multi_engine_harness_error_display_is_non_empty() {
    let err = MultiEngineHarnessError::FixtureFilterNotFound {
        fixture_id: "missing-fixture".to_string(),
    };
    let msg = err.to_string();
    assert!(!msg.is_empty());
    assert!(msg.contains("missing-fixture"));
}

// ────────────────────────────────────────────────────────────
// Engine seed derivation
// ────────────────────────────────────────────────────────────

#[test]
fn derive_engine_seed_is_deterministic() {
    let a = derive_engine_seed(42, "fixture-1", "engine-a");
    let b = derive_engine_seed(42, "fixture-1", "engine-a");
    assert_eq!(a, b);
}

#[test]
fn derive_engine_seed_varies_with_fixture_id() {
    let a = derive_engine_seed(42, "fixture-1", "engine-a");
    let b = derive_engine_seed(42, "fixture-2", "engine-a");
    assert_ne!(a, b);
}

#[test]
fn derive_engine_seed_varies_with_engine_id() {
    let a = derive_engine_seed(42, "fixture-1", "engine-a");
    let b = derive_engine_seed(42, "fixture-1", "engine-b");
    assert_ne!(a, b);
}

#[test]
fn derive_engine_seed_varies_with_master_seed() {
    let a = derive_engine_seed(42, "fixture-1", "engine-a");
    let b = derive_engine_seed(43, "fixture-1", "engine-a");
    assert_ne!(a, b);
}

#[test]
fn derive_engine_seed_swap_fixture_engine_yields_different_seed() {
    let a = derive_engine_seed(42, "alpha", "beta");
    let b = derive_engine_seed(42, "beta", "alpha");
    assert_ne!(
        a, b,
        "swapping fixture_id and engine_id should produce different seeds"
    );
}

// ────────────────────────────────────────────────────────────
// Catalog loading
// ────────────────────────────────────────────────────────────

#[test]
fn load_fixture_catalog_succeeds_for_default_catalog() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/parser_phase0_semantic_fixtures.json");
    let catalog = load_fixture_catalog(&path).expect("load should succeed");
    assert!(!catalog.fixtures.is_empty());
    assert_eq!(
        catalog.schema_version,
        "franken-engine.parser-phase0.semantic-fixtures.v1"
    );
    assert_eq!(catalog.parser_mode, "scalar_reference");
}

#[test]
fn load_fixture_catalog_rejects_missing_file() {
    let err = load_fixture_catalog(Path::new("/tmp/nonexistent-fixture-catalog-xyz.json"))
        .expect_err("missing file should fail");
    assert!(matches!(err, MultiEngineHarnessError::Io { .. }));
}

#[test]
fn load_fixture_catalog_rejects_malformed_json() {
    let path = std::env::temp_dir().join("franken-malformed-catalog.json");
    fs::write(&path, b"not valid json {{{").expect("write");
    let err = load_fixture_catalog(&path).expect_err("malformed json should fail");
    assert!(matches!(err, MultiEngineHarnessError::DecodeCatalog(_)));
    let _ = fs::remove_file(&path);
}

#[test]
fn load_fixture_catalog_rejects_wrong_schema_version() {
    let path = std::env::temp_dir().join("franken-wrong-schema-catalog.json");
    let payload = serde_json::json!({
        "schema_version": "wrong-version",
        "parser_mode": "scalar_reference",
        "fixtures": [{"id": "a", "family_id": "f", "goal": "script", "source": "1", "expected_hash": "sha256:abc"}]
    });
    fs::write(&path, serde_json::to_vec_pretty(&payload).unwrap()).unwrap();
    let err = load_fixture_catalog(&path).expect_err("wrong schema should fail");
    assert!(
        matches!(err, MultiEngineHarnessError::InvalidCatalogSchema { ref expected, ref actual }
            if expected.contains("semantic-fixtures") && actual == "wrong-version"),
        "unexpected error: {err}"
    );
    let _ = fs::remove_file(&path);
}

#[test]
fn load_fixture_catalog_rejects_wrong_parser_mode() {
    let path = std::env::temp_dir().join("franken-wrong-mode-catalog.json");
    let payload = serde_json::json!({
        "schema_version": "franken-engine.parser-phase0.semantic-fixtures.v1",
        "parser_mode": "wrong_mode",
        "fixtures": [{"id": "a", "family_id": "f", "goal": "script", "source": "1", "expected_hash": "sha256:abc"}]
    });
    fs::write(&path, serde_json::to_vec_pretty(&payload).unwrap()).unwrap();
    let err = load_fixture_catalog(&path).expect_err("wrong parser mode should fail");
    assert!(matches!(
        err,
        MultiEngineHarnessError::InvalidCatalogParserMode { .. }
    ));
    let _ = fs::remove_file(&path);
}

#[test]
fn load_fixture_catalog_rejects_empty_fixtures() {
    let path = std::env::temp_dir().join("franken-empty-fixtures-catalog.json");
    let payload = serde_json::json!({
        "schema_version": "franken-engine.parser-phase0.semantic-fixtures.v1",
        "parser_mode": "scalar_reference",
        "fixtures": []
    });
    fs::write(&path, serde_json::to_vec_pretty(&payload).unwrap()).unwrap();
    let err = load_fixture_catalog(&path).expect_err("empty fixtures should fail");
    assert!(matches!(err, MultiEngineHarnessError::EmptyFixtureCatalog));
    let _ = fs::remove_file(&path);
}

#[test]
fn load_fixture_catalog_rejects_duplicate_fixture_ids() {
    let path = std::env::temp_dir().join("franken-dup-ids-catalog.json");
    let payload = serde_json::json!({
        "schema_version": "franken-engine.parser-phase0.semantic-fixtures.v1",
        "parser_mode": "scalar_reference",
        "fixtures": [
            {"id": "dup", "family_id": "f", "goal": "script", "source": "1", "expected_hash": "sha256:a"},
            {"id": "dup", "family_id": "f", "goal": "script", "source": "2", "expected_hash": "sha256:b"}
        ]
    });
    fs::write(&path, serde_json::to_vec_pretty(&payload).unwrap()).unwrap();
    let err = load_fixture_catalog(&path).expect_err("dup IDs should fail");
    assert!(
        matches!(err, MultiEngineHarnessError::DuplicateFixtureId { ref fixture_id } if fixture_id == "dup"),
        "unexpected error: {err}"
    );
    let _ = fs::remove_file(&path);
}

// ────────────────────────────────────────────────────────────
// Config validation via run_multi_engine_harness
// ────────────────────────────────────────────────────────────

#[test]
fn harness_rejects_empty_trace_id() {
    let mut config = test_config(1);
    config.trace_id = String::new();
    let err = run_multi_engine_harness(&config).expect_err("empty trace_id should fail");
    assert!(matches!(err, MultiEngineHarnessError::InvalidConfig(_)));
}

#[test]
fn harness_rejects_empty_decision_id() {
    let mut config = test_config(1);
    config.decision_id = "  ".to_string();
    let err = run_multi_engine_harness(&config).expect_err("blank decision_id should fail");
    assert!(matches!(err, MultiEngineHarnessError::InvalidConfig(_)));
}

#[test]
fn harness_rejects_single_engine() {
    let mut config = test_config(1);
    config.engines = vec![HarnessEngineSpec::franken_canonical("v1")];
    let err = run_multi_engine_harness(&config).expect_err("single engine should fail");
    assert!(matches!(err, MultiEngineHarnessError::InvalidConfig(_)));
}

#[test]
fn harness_rejects_duplicate_engine_ids() {
    let mut config = test_config(1);
    config.engines = vec![
        HarnessEngineSpec::franken_canonical("v1"),
        HarnessEngineSpec::franken_canonical("v2"),
    ];
    let err = run_multi_engine_harness(&config).expect_err("dup engine IDs should fail");
    assert!(
        matches!(err, MultiEngineHarnessError::InvalidConfig(ref msg) if msg.contains("more than once")),
        "unexpected: {err}"
    );
}

// ────────────────────────────────────────────────────────────
// Fixture limit
// ────────────────────────────────────────────────────────────

#[test]
fn harness_fixture_limit_truncates_correctly() {
    let mut config = test_config(42);
    config.fixture_limit = Some(1);
    let report = run_multi_engine_harness(&config).expect("run should succeed");
    assert_eq!(report.fixture_count, 1);
    assert_eq!(report.fixture_results.len(), 1);
}

#[test]
fn harness_fixture_limit_none_runs_all() {
    let mut config = test_config(42);
    config.fixture_limit = Some(100);
    let report_unlimited = run_multi_engine_harness(&config).expect("run should succeed");

    config.fixture_limit = Some(2);
    let report_limited = run_multi_engine_harness(&config).expect("run should succeed");

    assert!(report_unlimited.fixture_count >= report_limited.fixture_count);
    assert_eq!(report_limited.fixture_count, 2);
}

// ────────────────────────────────────────────────────────────
// Report field validation
// ────────────────────────────────────────────────────────────

#[test]
fn harness_report_contains_all_required_fields() {
    let config = test_config(99);
    let report = run_multi_engine_harness(&config).expect("run should succeed");

    assert_eq!(
        report.schema_version,
        "franken-engine.parser-multi-engine.report.v2"
    );
    assert!(report.run_id.starts_with("sha256:"));
    assert!(!report.generated_at_utc.is_empty());
    assert_eq!(report.trace_id, config.trace_id);
    assert_eq!(report.decision_id, config.decision_id);
    assert_eq!(report.policy_id, config.policy_id);
    assert_eq!(report.seed, config.seed);
    assert_eq!(report.locale, config.locale);
    assert_eq!(report.timezone, config.timezone);
    assert_eq!(report.engine_specs.len(), config.engines.len());
    assert_eq!(report.parser_mode, "scalar_reference");
    assert!(!report.fixture_catalog_hash.is_empty());
    assert!(report.fixture_catalog_hash.starts_with("sha256:"));
}

#[test]
fn harness_report_engine_specs_match_config() {
    let config = test_config(55);
    let report = run_multi_engine_harness(&config).expect("run should succeed");

    for (i, spec) in config.engines.iter().enumerate() {
        assert_eq!(report.engine_specs[i].engine_id, spec.engine_id);
        assert_eq!(report.engine_specs[i].kind, spec.kind);
        assert_eq!(report.engine_specs[i].version_pin, spec.version_pin);
    }
}

#[test]
fn harness_report_summary_counts_are_consistent() {
    let config = test_config(77);
    let report = run_multi_engine_harness(&config).expect("run should succeed");

    assert_eq!(
        report.summary.total_fixtures,
        report.summary.equivalent_fixtures + report.summary.divergent_fixtures
    );
    assert_eq!(report.summary.total_fixtures, report.fixture_count);
    assert_eq!(report.fixture_results.len() as u64, report.fixture_count);
}

#[test]
fn harness_report_equivalent_fixture_has_no_drift() {
    let config = test_config(33);
    let report = run_multi_engine_harness(&config).expect("run should succeed");

    for fixture in &report.fixture_results {
        if fixture.equivalent_across_engines {
            assert!(fixture.drift_classification.is_none());
            assert!(fixture.divergence_reason.is_none());
        }
    }
}

#[test]
fn harness_report_fixture_results_have_source_hash() {
    let config = test_config(44);
    let report = run_multi_engine_harness(&config).expect("run should succeed");

    for fixture in &report.fixture_results {
        assert!(fixture.source_hash.starts_with("sha256:"));
        assert!(fixture.source_hash.len() > 10);
    }
}

// ────────────────────────────────────────────────────────────
// Engine run outcomes
// ────────────────────────────────────────────────────────────

#[test]
fn harness_canonical_engine_outcomes_have_ast_normalization_artifacts() {
    let mut config = test_config(11);
    config.fixture_limit = Some(1);
    let report = run_multi_engine_harness(&config).expect("run should succeed");

    let fixture = &report.fixture_results[0];
    for engine_result in &fixture.engine_results {
        if engine_result.engine_id == "franken_canonical" {
            let first = &engine_result.first_run;
            if first.kind == EngineOutcomeKind::Hash {
                let ast = first
                    .normalized_ast
                    .as_ref()
                    .expect("canonical should have normalized_ast");
                assert_eq!(
                    ast.adapter,
                    AstNormalizationAdapter::CanonicalHashPassthroughV1
                );
                assert!(ast.canonical_hash.starts_with("sha256:"));
            }
        }
    }
}

#[test]
fn harness_engine_results_are_deterministic_for_canonical_parser() {
    let mut config = test_config(22);
    config.fixture_limit = Some(2);
    let report = run_multi_engine_harness(&config).expect("run should succeed");

    for fixture in &report.fixture_results {
        for engine_result in &fixture.engine_results {
            if engine_result.engine_id == "franken_canonical" {
                assert!(
                    engine_result.first_run.deterministic,
                    "canonical engine should be deterministic for fixture {}",
                    fixture.fixture_id
                );
            }
        }
    }
}

// ────────────────────────────────────────────────────────────
// Serialization round-trips for additional types
// ────────────────────────────────────────────────────────────

#[test]
fn engine_outcome_kind_is_comparable_and_distinct() {
    assert_ne!(EngineOutcomeKind::Hash, EngineOutcomeKind::Error);
    // Derive(Ord) means variants are ordered by declaration order
    assert!(
        EngineOutcomeKind::Hash <= EngineOutcomeKind::Error
            || EngineOutcomeKind::Error <= EngineOutcomeKind::Hash
    );
}

#[test]
fn ast_normalization_adapter_serde_round_trip() {
    let adapter = AstNormalizationAdapter::CanonicalHashPassthroughV1;
    let json = serde_json::to_string(&adapter).expect("serialize");
    let recovered: AstNormalizationAdapter = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(adapter, recovered);
}

#[test]
fn diagnostic_normalization_adapter_serde_round_trip() {
    let adapter = DiagnosticNormalizationAdapter::ParserDiagnosticsTaxonomyV1;
    let json = serde_json::to_string(&adapter).expect("serialize");
    let recovered: DiagnosticNormalizationAdapter =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(adapter, recovered);
}

#[test]
fn governance_action_kind_serde_round_trip() {
    for kind in [GovernanceActionKind::Create, GovernanceActionKind::Update] {
        let json = serde_json::to_string(&kind).expect("serialize");
        let recovered: GovernanceActionKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(kind, recovered);
    }
}

#[test]
fn harness_engine_spec_fixture_expected_hash_has_stable_id() {
    let spec = HarnessEngineSpec::fixture_expected_hash("catalog@v1");
    assert_eq!(spec.kind, HarnessEngineKind::FixtureExpectedHash);
    assert_eq!(spec.engine_id, "fixture_expected_hash");
    assert!(!spec.display_name.is_empty());
    assert!(spec.command.is_none());
    assert!(spec.args.is_empty());
}

// ────────────────────────────────────────────────────────────
// Error display coverage
// ────────────────────────────────────────────────────────────

#[test]
fn error_display_decode_catalog() {
    let err = MultiEngineHarnessError::DecodeCatalog("parse error".to_string());
    let msg = err.to_string();
    assert!(msg.contains("decode") || msg.contains("catalog"));
    assert!(msg.contains("parse error"));
}

#[test]
fn error_display_invalid_catalog_schema() {
    let err = MultiEngineHarnessError::InvalidCatalogSchema {
        expected: "v1".to_string(),
        actual: "v2".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("v1"));
    assert!(msg.contains("v2"));
}

#[test]
fn error_display_invalid_catalog_parser_mode() {
    let err = MultiEngineHarnessError::InvalidCatalogParserMode {
        expected: "scalar_reference".to_string(),
        actual: "bad_mode".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("scalar_reference") || msg.contains("bad_mode"));
}

#[test]
fn error_display_empty_fixture_catalog() {
    let err = MultiEngineHarnessError::EmptyFixtureCatalog;
    let msg = err.to_string();
    assert!(!msg.is_empty());
}

#[test]
fn error_display_duplicate_fixture_id() {
    let err = MultiEngineHarnessError::DuplicateFixtureId {
        fixture_id: "dup-id".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("dup-id"));
}

#[test]
fn error_display_unknown_goal() {
    let err = MultiEngineHarnessError::UnknownGoal {
        fixture_id: "fix1".to_string(),
        goal: "invalid_goal".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("invalid_goal"));
}

#[test]
fn error_display_invalid_config() {
    let err = MultiEngineHarnessError::InvalidConfig("bad config".to_string());
    let msg = err.to_string();
    assert!(msg.contains("bad config"));
}

#[test]
fn error_display_external_engine() {
    let err = MultiEngineHarnessError::ExternalEngine {
        engine_id: "ext1".to_string(),
        detail: "command failed".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("ext1") || msg.contains("command failed"));
}

#[test]
fn error_display_normalization() {
    let err = MultiEngineHarnessError::Normalization {
        engine_id: "eng1".to_string(),
        detail: "adapter error".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("eng1") || msg.contains("adapter error"));
}

// ────────────────────────────────────────────────────────────
// Governance action report
// ────────────────────────────────────────────────────────────

#[test]
fn governance_report_for_equivalent_fixtures_has_no_actions() {
    let config = test_config(88);
    let report = run_multi_engine_harness(&config).expect("run should succeed");
    if report.summary.divergent_fixtures == 0 {
        let actions = derive_drift_governance_actions(&report);
        assert!(actions.is_empty());
        let governance = build_drift_governance_action_report(&report);
        assert!(governance.actions.is_empty());
        assert_eq!(governance.run_id, report.run_id);
        assert!(!governance.generated_at_utc.is_empty());
    }
}

#[test]
fn governance_action_report_schema_version() {
    let config = test_config(88);
    let report = run_multi_engine_harness(&config).expect("run should succeed");
    let governance = build_drift_governance_action_report(&report);
    assert_eq!(
        governance.schema_version,
        "franken-engine.parser-drift-governance-actions.v1"
    );
}

#[test]
fn has_critical_drift_returns_false_for_equivalent_report() {
    let config = test_config(88);
    let report = run_multi_engine_harness(&config).expect("run should succeed");
    if report.summary.divergent_fixtures == 0 {
        assert!(!has_critical_drift(&report));
    }
}

// ────────────────────────────────────────────────────────────
// Multi-fixture aggregation
// ────────────────────────────────────────────────────────────

#[test]
fn harness_multi_fixture_summary_aggregates_correctly() {
    let mut config = test_config(7);
    config.fixture_limit = Some(4);
    let report = run_multi_engine_harness(&config).expect("run should succeed");

    assert_eq!(
        report.summary.total_fixtures,
        report.fixture_results.len() as u64
    );
    let equivalent_count = report
        .fixture_results
        .iter()
        .filter(|f| f.equivalent_across_engines)
        .count() as u64;
    let divergent_count = report
        .fixture_results
        .iter()
        .filter(|f| !f.equivalent_across_engines)
        .count() as u64;
    assert_eq!(report.summary.equivalent_fixtures, equivalent_count);
    assert_eq!(report.summary.divergent_fixtures, divergent_count);
}

#[test]
fn harness_multi_fixture_telemetry_sample_count_scales_with_fixture_count() {
    let mut config1 = test_config(7);
    config1.fixture_limit = Some(1);
    let report1 = run_multi_engine_harness(&config1).expect("run should succeed");

    let mut config2 = test_config(7);
    config2.fixture_limit = Some(2);
    let report2 = run_multi_engine_harness(&config2).expect("run should succeed");

    assert!(
        report2.parser_telemetry.sample_count >= report1.parser_telemetry.sample_count,
        "more fixtures should produce at least as many samples"
    );
}

// ────────────────────────────────────────────────────────────
// Report serialization
// ────────────────────────────────────────────────────────────

#[test]
fn harness_report_serializes_to_json() {
    let config = test_config(50);
    let report = run_multi_engine_harness(&config).expect("run should succeed");
    let json = serde_json::to_string_pretty(&report).expect("report should serialize to JSON");
    assert!(json.contains("franken-engine.parser-multi-engine.report.v2"));
    assert!(json.contains("fixture_results"));
    assert!(json.contains("parser_telemetry"));
}

#[test]
fn harness_report_json_contains_stable_fields() {
    let config = test_config(50);
    let report = run_multi_engine_harness(&config).expect("run should succeed");
    let json_val: serde_json::Value = serde_json::to_value(&report).expect("to_value");
    assert!(json_val.get("schema_version").is_some());
    assert!(json_val.get("run_id").is_some());
    assert!(json_val.get("summary").is_some());
    assert!(json_val.get("engine_specs").is_some());
    let summary = json_val.get("summary").unwrap();
    assert!(summary.get("total_fixtures").is_some());
    assert!(summary.get("equivalent_fixtures").is_some());
    assert!(summary.get("divergent_fixtures").is_some());
}

// ────────────────────────────────────────────────────────────
// Diagnostic normalization artifacts
// ────────────────────────────────────────────────────────────

#[test]
fn harness_diagnostic_normalization_artifacts_have_taxonomy_version() {
    let fixture_catalog = write_empty_source_fixture_catalog();
    let mut config = MultiEngineHarnessConfig::with_defaults(41);
    config.fixture_catalog_path = fixture_catalog.clone();
    config.fixture_limit = Some(1);
    config.trace_id = "trace-diag-taxonomy".to_string();
    config.decision_id = "decision-diag-taxonomy".to_string();
    config.policy_id = "policy-diag-taxonomy-v1".to_string();
    config.engines = vec![
        HarnessEngineSpec::franken_canonical("frankenengine-engine@workspace"),
        HarnessEngineSpec {
            engine_id: "external_error".to_string(),
            display_name: "External Error".to_string(),
            kind: HarnessEngineKind::ExternalCommand,
            version_pin: "external-error@v1".to_string(),
            command: Some("sh".to_string()),
            args: vec![
                "-c".to_string(),
                "cat >/dev/null; printf '{\"error_code\":\"empty_source\"}\\n'".to_string(),
            ],
        },
    ];

    let report = run_multi_engine_harness(&config).expect("run should succeed");
    let fixture = &report.fixture_results[0];
    for engine_result in &fixture.engine_results {
        if let Some(diag) = &engine_result.first_run.normalized_diagnostic {
            assert_eq!(
                diag.adapter,
                DiagnosticNormalizationAdapter::ParserDiagnosticsTaxonomyV1
            );
            assert!(!diag.diagnostic_code.is_empty());
            assert!(diag.canonical_hash.starts_with("sha256:"));
        }
    }
    let _ = fs::remove_file(fixture_catalog);
}

// ────────────────────────────────────────────────────────────
// Fixture ID filter
// ────────────────────────────────────────────────────────────

#[test]
fn harness_fixture_id_filter_selects_single_fixture() {
    let catalog_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/parser_phase0_semantic_fixtures.json");
    let catalog = load_fixture_catalog(&catalog_path).expect("load");
    let first_id = catalog.fixtures[0].id.clone();

    let mut config = test_config(60);
    config.fixture_id_filter = Some(first_id.clone());
    config.fixture_limit = None;
    let report = run_multi_engine_harness(&config).expect("run should succeed");
    assert_eq!(report.fixture_results.len(), 1);
    assert_eq!(report.fixture_results[0].fixture_id, first_id);
}

// ────────────────────────────────────────────────────────────
// Default config
// ────────────────────────────────────────────────────────────

#[test]
fn default_config_has_two_engines() {
    let config = MultiEngineHarnessConfig::with_defaults(1);
    assert_eq!(config.engines.len(), 2);
    assert_eq!(config.engines[0].kind, HarnessEngineKind::FrankenCanonical);
    assert_eq!(
        config.engines[1].kind,
        HarnessEngineKind::FixtureExpectedHash
    );
}

#[test]
fn default_config_locale_and_timezone() {
    let config = MultiEngineHarnessConfig::with_defaults(1);
    assert_eq!(config.locale, "C");
    assert_eq!(config.timezone, "UTC");
}

#[test]
fn default_config_seed_propagates() {
    let config = MultiEngineHarnessConfig::with_defaults(12345);
    assert_eq!(config.seed, 12345);
}

#[test]
fn default_config_fixture_limit_is_set() {
    let config = MultiEngineHarnessConfig::with_defaults(1);
    assert!(config.fixture_limit.is_some());
}

// ────────────────────────────────────────────────────────────
// Repro pack details
// ────────────────────────────────────────────────────────────

#[test]
fn repro_pack_contains_minimization_stats() {
    let mut config = test_config(13);
    config.fixture_limit = Some(1);
    config.engines = vec![
        HarnessEngineSpec::franken_canonical("frankenengine-engine@workspace"),
        HarnessEngineSpec {
            engine_id: "external_zero".to_string(),
            display_name: "External Zero Hash".to_string(),
            kind: HarnessEngineKind::ExternalCommand,
            version_pin: "external-zero@v1".to_string(),
            command: Some("sh".to_string()),
            args: vec![
                "-c".to_string(),
                "cat >/dev/null; printf '{\"hash\":\"sha256:0000000000000000000000000000000000000000000000000000000000000000\"}\\n'"
                    .to_string(),
            ],
        },
    ];

    let report = run_multi_engine_harness(&config).expect("run should succeed");
    let fixture = &report.fixture_results[0];
    let repro = fixture
        .repro_pack
        .as_ref()
        .expect("repro pack should exist");

    assert!(!repro.minimized_source.is_empty() || repro.minimization.minimized_bytes == 0);
    assert!(repro.minimization.original_bytes > 0);
    assert!(repro.minimization.minimized_bytes <= repro.minimization.original_bytes);
    assert!(!repro.replay_command.is_empty());
    assert!(!repro.promotion_hooks.is_empty());
    assert!(repro.schema_version.contains("repro-pack"));
    assert!(!repro.family_id.is_empty());
}

#[test]
fn repro_pack_provenance_hash_is_deterministic() {
    let mut config = test_config(13);
    config.fixture_limit = Some(1);
    config.engines = vec![
        HarnessEngineSpec::franken_canonical("frankenengine-engine@workspace"),
        HarnessEngineSpec {
            engine_id: "external_zero2".to_string(),
            display_name: "External Zero Hash".to_string(),
            kind: HarnessEngineKind::ExternalCommand,
            version_pin: "external-zero@v1".to_string(),
            command: Some("sh".to_string()),
            args: vec![
                "-c".to_string(),
                "cat >/dev/null; printf '{\"hash\":\"sha256:0000000000000000000000000000000000000000000000000000000000000000\"}\\n'"
                    .to_string(),
            ],
        },
    ];

    let report1 = run_multi_engine_harness(&config).expect("run 1");
    let report2 = run_multi_engine_harness(&config).expect("run 2");

    let repro1 = report1.fixture_results[0].repro_pack.as_ref().unwrap();
    let repro2 = report2.fixture_results[0].repro_pack.as_ref().unwrap();
    assert_eq!(repro1.provenance_hash, repro2.provenance_hash);
}
