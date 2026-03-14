#![forbid(unsafe_code)]
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

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use frankenengine_engine::e2e_harness::{
    ArtifactCollector, DeterministicRunner, DeterministicRunnerConfig, FixtureStore,
    FixtureValidationError, GoldenStore, ReplayEnvironmentFingerprint, RunReport, ScenarioClass,
    ScenarioMatrixEntry, ScenarioStep, TestFixture, build_evidence_linkage,
    diagnose_cross_machine_replay, evaluate_replay_performance, run_scenario_matrix,
    validate_replay_input, verify_replay,
};
use serde::Deserialize;

const CONTRACT_SCHEMA_VERSION: &str = "frx.end-to-end-scenario-matrix.v1";
const CONTRACT_JSON: &str = include_str!("../../../docs/frx_end_to_end_scenario_matrix_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct MatrixContract {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    track: Track,
    required_structured_log_fields: Vec<String>,
    matrix_policy: MatrixPolicy,
    scenario_catalog: Vec<ScenarioSpec>,
    chaos_profiles: Vec<ChaosProfile>,
    differential_contract: DifferentialContract,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Track {
    id: String,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct MatrixPolicy {
    failure_mode: String,
    require_unit_anchor_ids: bool,
    require_invariant_refs: bool,
    differential_requires_baseline: bool,
    chaos_requires_profile: bool,
    deterministic_seed_required: bool,
    correlation_id_fields: Vec<String>,
    promotion_gate_consumers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ScenarioSpec {
    scenario_id: String,
    class: String,
    fixture_ref: String,
    coverage_tags: Vec<String>,
    baseline_scenario_id: Option<String>,
    chaos_profile: Option<String>,
    unit_anchor_ids: Vec<String>,
    invariant_refs: Vec<String>,
    decision_path: String,
    expected_outcome: String,
    replay_seed: u64,
    target_arch: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ChaosProfile {
    profile_id: String,
    seed_offset: u64,
    fault_injectors: Vec<String>,
    expected_policy_actions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct DifferentialContract {
    baseline_classes: Vec<String>,
    comparison_dimensions: Vec<String>,
    drift_thresholds_millionths: DriftThresholds,
    block_on_unexplained_drift: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct DriftThresholds {
    output_digest_mismatch: u64,
    event_count_delta: u64,
    error_code_delta: u64,
    decision_path_delta: u64,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_contract() -> MatrixContract {
    serde_json::from_str(CONTRACT_JSON).expect("scenario matrix contract json must parse")
}

fn parse_scenario_class(raw: &str) -> ScenarioClass {
    match raw {
        "baseline" => ScenarioClass::Baseline,
        "differential" => ScenarioClass::Differential,
        "chaos" => ScenarioClass::Chaos,
        "stress" => ScenarioClass::Stress,
        "fault_injection" => ScenarioClass::FaultInjection,
        "cross_arch" => ScenarioClass::CrossArch,
        other => panic!("unknown scenario class: {other}"),
    }
}

fn scenario_fixture(spec: &ScenarioSpec) -> TestFixture {
    let mut decision_metadata = BTreeMap::new();
    decision_metadata.insert("decision_path".to_string(), spec.decision_path.clone());
    decision_metadata.insert("fixture_ref".to_string(), spec.fixture_ref.clone());

    match spec.expected_outcome.as_str() {
        "fail" => {
            decision_metadata.insert("error_code".to_string(), "FE-FRX-20-3-E2E-0001".to_string());
        }
        "fallback" => {
            decision_metadata.insert("outcome".to_string(), "fallback".to_string());
        }
        "pass" => {
            decision_metadata.insert("outcome".to_string(), "ok".to_string());
        }
        other => panic!("unknown expected_outcome: {other}"),
    }

    TestFixture {
        fixture_id: format!("fixture-{}", spec.scenario_id),
        fixture_version: TestFixture::CURRENT_VERSION,
        seed: spec.replay_seed,
        virtual_time_start_micros: 10_000,
        policy_id: "policy-frx-20-3-v1".to_string(),
        steps: vec![
            ScenarioStep {
                component: "scheduler".to_string(),
                event: "dispatch".to_string(),
                advance_micros: 100,
                metadata: BTreeMap::new(),
            },
            ScenarioStep {
                component: "guardplane".to_string(),
                event: spec.decision_path.clone(),
                advance_micros: 150,
                metadata: decision_metadata,
            },
        ],
        expected_events: Vec::new(),
        determinism_check: true,
    }
}

fn test_temp_dir(suffix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("franken-engine-{suffix}-{nanos}"));
    fs::create_dir_all(&path).expect("temp dir");
    path
}

#[test]
fn frx_20_3_doc_contains_required_sections() {
    let path = repo_root().join("docs/FRX_END_TO_END_SCENARIO_MATRIX_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    for section in [
        "# FRX End-to-End Scenario Matrix V1",
        "## Scope",
        "## Scenario Classes and Coverage",
        "## Differential Lane Contract",
        "## Chaos Lane Contract",
        "## Unit-Anchor and Invariant Linkage Contract",
        "## Structured Logging and Correlation Contract",
        "## Promotion Gate Evidence Contract",
        "## Operator Verification",
    ] {
        assert!(
            doc.contains(section),
            "missing required section in {}: {section}",
            path.display()
        );
    }

    let doc_lower = doc.to_ascii_lowercase();
    for phrase in [
        "fail-closed",
        "differential",
        "chaos",
        "baseline",
        "replay",
        "correlation",
        "unit-test anchors",
        "invariant",
    ] {
        assert!(
            doc_lower.contains(phrase),
            "missing required phrase in {}: {phrase}",
            path.display()
        );
    }
}

#[test]
fn frx_20_3_contract_is_versioned_and_fail_closed() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, CONTRACT_SCHEMA_VERSION);
    assert_eq!(contract.bead_id, "bd-mjh3.20.3");
    assert_eq!(contract.generated_by, "bd-mjh3.20.3");
    assert_eq!(contract.track.id, "FRX-20.3");
    assert!(contract.track.name.contains("End-to-End Scenario Matrix"));
    assert!(contract.generated_at_utc.ends_with('Z'));

    assert_eq!(contract.matrix_policy.failure_mode, "fail_closed");
    assert!(contract.matrix_policy.require_unit_anchor_ids);
    assert!(contract.matrix_policy.require_invariant_refs);
    assert!(contract.matrix_policy.differential_requires_baseline);
    assert!(contract.matrix_policy.chaos_requires_profile);
    assert!(contract.matrix_policy.deterministic_seed_required);
    assert_eq!(
        contract.matrix_policy.correlation_id_fields,
        vec![
            "trace_id".to_string(),
            "decision_id".to_string(),
            "policy_id".to_string()
        ]
    );

    let gate_consumers: BTreeSet<_> = contract
        .matrix_policy
        .promotion_gate_consumers
        .iter()
        .map(String::as_str)
        .collect();
    let expected_consumers: BTreeSet<_> = [
        "frx_cut_line_c1",
        "frx_cut_line_c2",
        "frx_release_evidence_integrator",
    ]
    .into_iter()
    .collect();
    assert_eq!(gate_consumers, expected_consumers);

    assert!(contract.differential_contract.block_on_unexplained_drift);
    assert_eq!(
        contract.differential_contract.baseline_classes,
        vec!["baseline".to_string()]
    );
    assert_eq!(
        contract
            .differential_contract
            .drift_thresholds_millionths
            .output_digest_mismatch,
        0
    );
    assert_eq!(
        contract
            .differential_contract
            .drift_thresholds_millionths
            .event_count_delta,
        0
    );
    assert_eq!(
        contract
            .differential_contract
            .drift_thresholds_millionths
            .error_code_delta,
        0
    );
    assert_eq!(
        contract
            .differential_contract
            .drift_thresholds_millionths
            .decision_path_delta,
        0
    );
}

#[test]
fn frx_20_3_scenario_catalog_has_coverage_and_linkage_requirements() {
    let contract = parse_contract();

    assert!(
        contract.scenario_catalog.len() >= 8,
        "expected full baseline/differential/chaos matrix"
    );

    let scenario_ids: BTreeSet<_> = contract
        .scenario_catalog
        .iter()
        .map(|scenario| scenario.scenario_id.as_str())
        .collect();
    assert_eq!(scenario_ids.len(), contract.scenario_catalog.len());

    let baseline_ids: BTreeSet<_> = contract
        .scenario_catalog
        .iter()
        .filter(|scenario| scenario.class == "baseline")
        .map(|scenario| scenario.scenario_id.as_str())
        .collect();

    let chaos_profiles: BTreeSet<_> = contract
        .chaos_profiles
        .iter()
        .map(|profile| profile.profile_id.as_str())
        .collect();
    assert!(
        !chaos_profiles.is_empty(),
        "chaos profile catalog must be non-empty"
    );

    let mut coverage_tags = BTreeSet::new();
    for scenario in &contract.scenario_catalog {
        assert!(!scenario.fixture_ref.trim().is_empty());
        assert!(!scenario.decision_path.trim().is_empty());
        assert!(scenario.replay_seed > 0);
        assert!(
            !scenario.unit_anchor_ids.is_empty(),
            "scenario {} missing unit anchors",
            scenario.scenario_id
        );
        assert!(
            !scenario.invariant_refs.is_empty(),
            "scenario {} missing invariant refs",
            scenario.scenario_id
        );

        for anchor in &scenario.unit_anchor_ids {
            assert!(
                anchor.starts_with("unit."),
                "unit anchor must start with unit.: {anchor}"
            );
        }

        for invariant in &scenario.invariant_refs {
            assert!(
                invariant.starts_with("inv."),
                "invariant ref must start with inv.: {invariant}"
            );
        }

        for tag in &scenario.coverage_tags {
            coverage_tags.insert(tag.as_str());
        }

        match scenario.class.as_str() {
            "differential" => {
                let baseline = scenario
                    .baseline_scenario_id
                    .as_deref()
                    .expect("differential scenario requires baseline id");
                assert!(
                    baseline_ids.contains(baseline),
                    "differential scenario {} references unknown baseline {baseline}",
                    scenario.scenario_id
                );
            }
            "chaos" => {
                let profile = scenario
                    .chaos_profile
                    .as_deref()
                    .expect("chaos scenario requires chaos profile");
                assert!(
                    chaos_profiles.contains(profile),
                    "chaos scenario {} references unknown profile {profile}",
                    scenario.scenario_id
                );
            }
            "cross_arch" => {
                assert!(
                    scenario.target_arch.is_some(),
                    "cross_arch scenario {} must set target_arch",
                    scenario.scenario_id
                );
            }
            _ => {}
        }
    }

    for required_tag in [
        "render",
        "update",
        "hydration",
        "navigation",
        "error_recovery",
        "degraded_mode",
        "adversarial",
    ] {
        assert!(
            coverage_tags.contains(required_tag),
            "missing required coverage tag: {required_tag}"
        );
    }

    for profile in &contract.chaos_profiles {
        assert!(profile.seed_offset > 0);
        assert!(!profile.fault_injectors.is_empty());
        assert!(!profile.expected_policy_actions.is_empty());
    }
}

#[test]
fn frx_20_3_structured_log_requirements_are_pinned() {
    let contract = parse_contract();

    let required: BTreeSet<_> = contract
        .required_structured_log_fields
        .iter()
        .map(String::as_str)
        .collect();

    for field in [
        "schema_version",
        "scenario_id",
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "decision_path",
        "seed",
        "timing_us",
        "outcome",
        "error_code",
    ] {
        assert!(
            required.contains(field),
            "missing structured log field: {field}"
        );
    }

    let dimensions: BTreeSet<_> = contract
        .differential_contract
        .comparison_dimensions
        .iter()
        .map(String::as_str)
        .collect();
    let expected_dimensions: BTreeSet<_> = [
        "output_digest",
        "event_count",
        "first_error_code",
        "decision_path",
    ]
    .into_iter()
    .collect();
    assert_eq!(dimensions, expected_dimensions);

    assert!(
        contract
            .operator_verification
            .iter()
            .any(|entry| entry.contains("run_frx_end_to_end_scenario_matrix_suite.sh ci")),
        "operator verification must include ci suite command"
    );
}

#[test]
fn frx_20_3_scenario_matrix_execution_is_deterministic_and_linked() {
    let contract = parse_contract();

    let scenarios: Vec<ScenarioMatrixEntry> = contract
        .scenario_catalog
        .iter()
        .map(|spec| ScenarioMatrixEntry {
            scenario_id: spec.scenario_id.clone(),
            scenario_class: parse_scenario_class(&spec.class),
            fixture: scenario_fixture(spec),
            baseline_scenario_id: spec.baseline_scenario_id.clone(),
            chaos_profile: spec.chaos_profile.clone(),
            unit_anchor_ids: spec.unit_anchor_ids.clone(),
            target_arch: spec.target_arch.clone(),
            worker_pool: Some(format!("pool-{}", spec.class)),
        })
        .collect();

    let runner = DeterministicRunner::default();
    let root = test_temp_dir("frx-end-to-end-scenario-matrix");
    let collector = ArtifactCollector::new(root.join("artifacts")).expect("collector");

    let execution = run_scenario_matrix(&runner, &collector, &scenarios).expect("matrix run");

    assert_eq!(
        execution.report.total_scenarios as usize,
        contract.scenario_catalog.len()
    );
    assert_eq!(
        execution.report.schema_version,
        "franken-engine.e2e-scenario-matrix.report.v2"
    );
    assert!(execution.summary_json_path.exists());
    assert!(execution.summary_markdown_path.exists());

    for pack in &execution.report.scenario_packs {
        assert!(!pack.run_id.trim().is_empty());
        assert!(pack.replay_pointer.starts_with("replay://"));
        assert!(!pack.unit_anchor_ids.is_empty());

        match pack.scenario_class {
            ScenarioClass::Differential => {
                assert!(pack.baseline_scenario_id.is_some());
            }
            ScenarioClass::Chaos => {
                assert!(pack.chaos_profile.is_some());
            }
            _ => {}
        }
    }

    assert!(
        execution.report.fail_scenarios > 0,
        "matrix should include at least one failing adversarial scenario"
    );
    assert!(
        execution.report.pass_scenarios > 0,
        "matrix should include passing baseline/differential scenarios"
    );

    let summary_json =
        fs::read_to_string(&execution.summary_json_path).expect("scenario matrix summary json");
    let summary_markdown = fs::read_to_string(&execution.summary_markdown_path)
        .expect("scenario matrix summary markdown");

    for scenario in &contract.scenario_catalog {
        assert!(summary_json.contains(&scenario.scenario_id));
        assert!(summary_markdown.contains(&scenario.scenario_id));
    }
}

// ---------- parse_scenario_class helper ----------

#[test]
fn parse_scenario_class_maps_all_known_classes() {
    let pairs = [
        ("baseline", ScenarioClass::Baseline),
        ("differential", ScenarioClass::Differential),
        ("chaos", ScenarioClass::Chaos),
        ("stress", ScenarioClass::Stress),
        ("fault_injection", ScenarioClass::FaultInjection),
        ("cross_arch", ScenarioClass::CrossArch),
    ];
    for (raw, expected) in pairs {
        assert_eq!(parse_scenario_class(raw), expected);
    }
}

#[test]
#[should_panic(expected = "unknown scenario class")]
fn parse_scenario_class_panics_on_unknown() {
    parse_scenario_class("performance");
}

// ---------- ScenarioClass ----------

#[test]
fn scenario_class_serde_roundtrip() {
    for class in ScenarioClass::ALL {
        let json = serde_json::to_string(&class).expect("serialize");
        let recovered: ScenarioClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, class);
    }
}

#[test]
fn scenario_class_as_str_is_nonempty() {
    for class in ScenarioClass::ALL {
        assert!(!class.as_str().is_empty());
    }
}

// ---------- MatrixContract ----------

#[test]
fn contract_schema_version_is_stable() {
    let contract = parse_contract();
    assert_eq!(contract.schema_version, CONTRACT_SCHEMA_VERSION);
}

#[test]
fn contract_has_at_least_eight_scenarios() {
    let contract = parse_contract();
    assert!(contract.scenario_catalog.len() >= 8);
}

#[test]
fn contract_scenario_ids_are_unique() {
    let contract = parse_contract();
    let mut ids = BTreeSet::new();
    for scenario in &contract.scenario_catalog {
        assert!(
            ids.insert(scenario.scenario_id.as_str()),
            "duplicate scenario id: {}",
            scenario.scenario_id
        );
    }
}

// ---------- scenario_fixture helper ----------

#[test]
fn scenario_fixture_sets_correct_fixture_id() {
    let contract = parse_contract();
    let spec = &contract.scenario_catalog[0];
    let fixture = scenario_fixture(spec);
    assert!(fixture.fixture_id.starts_with("fixture-"));
    assert!(fixture.fixture_id.contains(&spec.scenario_id));
}

#[test]
fn scenario_fixture_has_two_steps() {
    let contract = parse_contract();
    let spec = &contract.scenario_catalog[0];
    let fixture = scenario_fixture(spec);
    assert_eq!(fixture.steps.len(), 2);
    assert_eq!(fixture.steps[0].component, "scheduler");
    assert_eq!(fixture.steps[1].component, "guardplane");
}

#[test]
fn scenario_fixture_seed_matches_spec() {
    let contract = parse_contract();
    for spec in &contract.scenario_catalog {
        let fixture = scenario_fixture(spec);
        assert_eq!(fixture.seed, spec.replay_seed);
    }
}

// ---------- chaos profiles ----------

#[test]
fn chaos_profiles_have_unique_ids() {
    let contract = parse_contract();
    let mut ids = BTreeSet::new();
    for profile in &contract.chaos_profiles {
        assert!(
            ids.insert(profile.profile_id.as_str()),
            "duplicate chaos profile id: {}",
            profile.profile_id
        );
    }
}

#[test]
fn chaos_profiles_have_seed_offsets() {
    let contract = parse_contract();
    for profile in &contract.chaos_profiles {
        assert!(profile.seed_offset > 0);
    }
}

// ---------- differential contract ----------

#[test]
fn differential_contract_drift_thresholds_are_zero() {
    let contract = parse_contract();
    let thresholds = &contract.differential_contract.drift_thresholds_millionths;
    assert_eq!(thresholds.output_digest_mismatch, 0);
    assert_eq!(thresholds.event_count_delta, 0);
    assert_eq!(thresholds.error_code_delta, 0);
    assert_eq!(thresholds.decision_path_delta, 0);
}

// ---------- DeterministicRunner ----------

#[test]
fn deterministic_runner_produces_stable_output() {
    let contract = parse_contract();
    let spec = &contract.scenario_catalog[0];
    let fixture = scenario_fixture(spec);
    let runner = DeterministicRunner::default();
    let first = runner.run_fixture(&fixture).expect("first run");
    let second = runner.run_fixture(&fixture).expect("second run");
    assert_eq!(first.output_digest, second.output_digest);
    assert_eq!(first.events.len(), second.events.len());
}

// ---------- ArtifactCollector ----------

#[test]
fn artifact_collector_creates_output_directory() {
    let root = test_temp_dir("artifact-collector-test");
    let collector = ArtifactCollector::new(root.join("artifacts")).expect("collector");
    assert!(collector.root().exists());
}

// ---------- operator verification ----------

#[test]
fn operator_verification_includes_ci_command() {
    let contract = parse_contract();
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|entry| entry.contains("run_frx_end_to_end_scenario_matrix_suite.sh ci")),
    );
}

#[test]
fn contract_has_nonempty_bead_id() {
    let contract = parse_contract();
    assert!(!contract.bead_id.trim().is_empty());
}

#[test]
fn contract_has_nonempty_generated_by() {
    let contract = parse_contract();
    assert!(!contract.generated_by.trim().is_empty());
}

#[test]
fn contract_deterministic_double_parse() {
    let a = parse_contract();
    let b = parse_contract();
    assert_eq!(a.schema_version, b.schema_version);
    assert_eq!(a.bead_id, b.bead_id);
    assert_eq!(a.scenario_catalog.len(), b.scenario_catalog.len());
}

// ────────────────────────────────────────────────────────────
// Batch enrichment: fixture validation, scenario expected outcomes,
// replay seed uniqueness, scenario class coverage, chaos profile
// fault injectors nonempty, differential baseline coverage,
// operator verification replay command
// ────────────────────────────────────────────────────────────

#[test]
fn all_generated_fixtures_pass_validation() {
    let contract = parse_contract();
    for spec in &contract.scenario_catalog {
        let fixture = scenario_fixture(spec);
        fixture.validate().unwrap_or_else(|err| {
            panic!(
                "fixture for scenario {} failed validation: {err:?}",
                spec.scenario_id
            )
        });
    }
}

#[test]
fn scenario_replay_seeds_are_all_positive() {
    let contract = parse_contract();
    for spec in &contract.scenario_catalog {
        assert!(
            spec.replay_seed > 0,
            "scenario {} has zero replay_seed",
            spec.scenario_id
        );
    }
}

#[test]
fn scenario_catalog_covers_all_required_classes() {
    let contract = parse_contract();
    let classes: BTreeSet<_> = contract
        .scenario_catalog
        .iter()
        .map(|s| s.class.as_str())
        .collect();
    for required in ["baseline", "differential", "chaos"] {
        assert!(
            classes.contains(required),
            "scenario catalog missing class: {required}"
        );
    }
}

#[test]
fn chaos_profile_fault_injectors_are_nonempty_strings() {
    let contract = parse_contract();
    for profile in &contract.chaos_profiles {
        assert!(!profile.fault_injectors.is_empty());
        for injector in &profile.fault_injectors {
            assert!(
                !injector.trim().is_empty(),
                "chaos profile {} has empty fault injector",
                profile.profile_id
            );
        }
    }
}

#[test]
fn differential_scenarios_reference_existing_baselines() {
    let contract = parse_contract();
    let baseline_ids: BTreeSet<_> = contract
        .scenario_catalog
        .iter()
        .filter(|s| s.class == "baseline")
        .map(|s| s.scenario_id.as_str())
        .collect();
    for spec in &contract.scenario_catalog {
        if spec.class == "differential" {
            let baseline_ref = spec
                .baseline_scenario_id
                .as_deref()
                .expect("differential must have baseline_scenario_id");
            assert!(
                baseline_ids.contains(baseline_ref),
                "differential {} references missing baseline {}",
                spec.scenario_id,
                baseline_ref
            );
        }
    }
}

#[test]
fn scenario_fixture_determinism_check_is_enabled() {
    let contract = parse_contract();
    for spec in &contract.scenario_catalog {
        let fixture = scenario_fixture(spec);
        assert!(
            fixture.determinism_check,
            "fixture for {} should have determinism_check enabled",
            spec.scenario_id
        );
    }
}

#[test]
fn operator_verification_includes_replay_command() {
    let contract = parse_contract();
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|entry| entry.contains("replay")),
        "operator verification must include a replay command"
    );
}

// ────────────────────────────────────────────────────────────
// Enrichment batch: serde roundtrips, clone/debug, edge cases,
// field validation, invariant checks, replay verification,
// golden store, fixture store, evidence linkage, and more
// ────────────────────────────────────────────────────────────

#[test]
fn scenario_class_clone_and_debug_impls() {
    for class in ScenarioClass::ALL {
        let cloned = class.clone();
        assert_eq!(class, cloned);
        let debug_str = format!("{:?}", class);
        assert!(!debug_str.is_empty());
    }
}

#[test]
fn scenario_class_all_has_six_variants() {
    assert_eq!(ScenarioClass::ALL.len(), 6);
    let as_strs: BTreeSet<_> = ScenarioClass::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(as_strs.len(), 6, "each variant must have a unique as_str");
}

#[test]
fn deterministic_runner_config_serde_roundtrip() {
    let config = DeterministicRunnerConfig::default();
    let json = serde_json::to_string(&config).expect("serialize");
    let recovered: DeterministicRunnerConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, recovered);
    assert_eq!(recovered.trace_prefix, "trace");
}

#[test]
fn deterministic_runner_config_custom_prefix() {
    let json = r#"{"trace_prefix":"custom-prefix"}"#;
    let config: DeterministicRunnerConfig = serde_json::from_str(json).expect("deserialize");
    assert_eq!(config.trace_prefix, "custom-prefix");
}

#[test]
fn test_fixture_validate_rejects_empty_fixture_id() {
    let fixture = TestFixture {
        fixture_id: "".to_string(),
        fixture_version: TestFixture::CURRENT_VERSION,
        seed: 1,
        virtual_time_start_micros: 100,
        policy_id: "policy-1".to_string(),
        steps: vec![ScenarioStep {
            component: "c".to_string(),
            event: "e".to_string(),
            advance_micros: 10,
            metadata: BTreeMap::new(),
        }],
        expected_events: Vec::new(),
        determinism_check: false,
    };
    let err = fixture.validate().unwrap_err();
    assert!(
        matches!(err, FixtureValidationError::MissingFixtureId),
        "expected MissingFixtureId, got {err:?}"
    );
}

#[test]
fn test_fixture_validate_rejects_wrong_version() {
    let fixture = TestFixture {
        fixture_id: "fix-1".to_string(),
        fixture_version: 999,
        seed: 1,
        virtual_time_start_micros: 100,
        policy_id: "policy-1".to_string(),
        steps: vec![ScenarioStep {
            component: "c".to_string(),
            event: "e".to_string(),
            advance_micros: 10,
            metadata: BTreeMap::new(),
        }],
        expected_events: Vec::new(),
        determinism_check: false,
    };
    let err = fixture.validate().unwrap_err();
    assert!(
        matches!(err, FixtureValidationError::UnsupportedVersion { .. }),
        "expected UnsupportedVersion, got {err:?}"
    );
}

#[test]
fn test_fixture_validate_rejects_empty_steps() {
    let fixture = TestFixture {
        fixture_id: "fix-1".to_string(),
        fixture_version: TestFixture::CURRENT_VERSION,
        seed: 1,
        virtual_time_start_micros: 100,
        policy_id: "policy-1".to_string(),
        steps: Vec::new(),
        expected_events: Vec::new(),
        determinism_check: false,
    };
    let err = fixture.validate().unwrap_err();
    assert!(
        matches!(err, FixtureValidationError::MissingSteps),
        "expected MissingSteps, got {err:?}"
    );
}

#[test]
fn verify_replay_matches_identical_results() {
    let contract = parse_contract();
    let spec = &contract.scenario_catalog[0];
    let fixture = scenario_fixture(spec);
    let runner = DeterministicRunner::default();
    let result_a = runner.run_fixture(&fixture).expect("run a");
    let result_b = runner.run_fixture(&fixture).expect("run b");
    let verification = verify_replay(&result_a, &result_b);
    assert!(verification.matches, "identical runs should match");
    assert!(verification.reason.is_none());
    assert!(verification.mismatch_kind.is_none());
    assert_eq!(verification.expected_digest, verification.actual_digest);
}

#[test]
fn build_evidence_linkage_produces_one_record_per_event() {
    let contract = parse_contract();
    let spec = &contract.scenario_catalog[0];
    let fixture = scenario_fixture(spec);
    let runner = DeterministicRunner::default();
    let result = runner.run_fixture(&fixture).expect("run");
    let linkage = build_evidence_linkage(&result.events);
    assert_eq!(linkage.len(), result.events.len());
    for (record, event) in linkage.iter().zip(result.events.iter()) {
        assert_eq!(record.trace_id, event.trace_id);
        assert_eq!(record.decision_id, event.decision_id);
        assert_eq!(record.policy_id, event.policy_id);
        assert_eq!(record.event_sequence, event.sequence);
        assert!(!record.evidence_hash.is_empty());
    }
}

#[test]
fn validate_replay_input_rejects_missing_snapshot() {
    let contract = parse_contract();
    let spec = &contract.scenario_catalog[0];
    let fixture = scenario_fixture(spec);
    let runner = DeterministicRunner::default();
    let result = runner.run_fixture(&fixture).expect("run");
    let err = validate_replay_input(&result, None).unwrap_err();
    assert!(
        err.to_string().contains("model snapshot"),
        "error should mention model snapshot: {}",
        err
    );
}

#[test]
fn validate_replay_input_accepts_valid_snapshot() {
    let contract = parse_contract();
    let spec = &contract.scenario_catalog[0];
    let fixture = scenario_fixture(spec);
    let runner = DeterministicRunner::default();
    let result = runner.run_fixture(&fixture).expect("run");
    validate_replay_input(&result, Some("model://snapshot/abc/seed/42")).expect("should accept");
}

#[test]
fn evaluate_replay_performance_faster_than_realtime() {
    let contract = parse_contract();
    let spec = &contract.scenario_catalog[0];
    let fixture = scenario_fixture(spec);
    let runner = DeterministicRunner::default();
    let result = runner.run_fixture(&fixture).expect("run");
    let perf = evaluate_replay_performance(&result, 1);
    assert!(
        perf.faster_than_realtime,
        "1 us wall time should be faster than realtime"
    );
    assert!(perf.speedup_milli > 0);
}

#[test]
fn run_report_from_result_captures_fields() {
    let contract = parse_contract();
    let spec = contract
        .scenario_catalog
        .iter()
        .find(|s| s.expected_outcome == "fail")
        .expect("should have at least one fail scenario");
    let fixture = scenario_fixture(spec);
    let runner = DeterministicRunner::default();
    let result = runner.run_fixture(&fixture).expect("run");
    let report = RunReport::from_result(&result);
    assert_eq!(report.fixture_id, result.fixture_id);
    assert_eq!(report.run_id, result.run_id);
    assert_eq!(report.event_count, result.events.len());
    assert_eq!(report.output_digest, result.output_digest);
}

#[test]
fn run_report_to_markdown_contains_fixture_id() {
    let contract = parse_contract();
    let spec = &contract.scenario_catalog[0];
    let fixture = scenario_fixture(spec);
    let runner = DeterministicRunner::default();
    let result = runner.run_fixture(&fixture).expect("run");
    let report = RunReport::from_result(&result);
    let md = report.to_markdown();
    assert!(md.contains(&report.fixture_id));
    assert!(md.contains("E2E Run Report"));
    assert!(md.contains(&report.output_digest));
}

#[test]
fn replay_environment_fingerprint_local_serde_roundtrip() {
    let env_fp = ReplayEnvironmentFingerprint::local();
    assert!(!env_fp.os.is_empty());
    assert!(!env_fp.architecture.is_empty());
    assert!(!env_fp.family.is_empty());
    assert!(env_fp.pointer_width_bits > 0);
    assert!(
        env_fp.endian == "little" || env_fp.endian == "big",
        "endian should be little or big"
    );
    let json = serde_json::to_string(&env_fp).expect("serialize");
    let recovered: ReplayEnvironmentFingerprint = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(env_fp, recovered);
}

#[test]
fn diagnose_cross_machine_replay_same_env_matches() {
    let contract = parse_contract();
    let spec = &contract.scenario_catalog[0];
    let fixture = scenario_fixture(spec);
    let runner = DeterministicRunner::default();
    let result = runner.run_fixture(&fixture).expect("run");
    let env_fp = ReplayEnvironmentFingerprint::local();
    let diagnosis = diagnose_cross_machine_replay(&result, &result, &env_fp, &env_fp);
    assert!(
        diagnosis.cross_machine_match,
        "identical result + same env should match"
    );
    assert!(diagnosis.environment_mismatches.is_empty());
}

#[test]
fn fixture_store_save_and_load_roundtrip() {
    let root = test_temp_dir("fixture-store-roundtrip");
    let store = FixtureStore::new(root.join("fixtures")).expect("fixture store");
    let contract = parse_contract();
    let spec = &contract.scenario_catalog[0];
    let fixture = scenario_fixture(spec);
    let path = store.save_fixture(&fixture).expect("save");
    assert!(path.exists());
    let loaded = store.load_fixture(&path).expect("load");
    assert_eq!(loaded.fixture_id, fixture.fixture_id);
    assert_eq!(loaded.seed, fixture.seed);
    assert_eq!(loaded.steps.len(), fixture.steps.len());
}

#[test]
fn golden_store_write_then_verify() {
    let root = test_temp_dir("golden-store-verify");
    let store = GoldenStore::new(root.join("golden")).expect("golden store");
    let contract = parse_contract();
    let spec = &contract.scenario_catalog[0];
    let fixture = scenario_fixture(spec);
    let runner = DeterministicRunner::default();
    let result = runner.run_fixture(&fixture).expect("run");
    store.write_baseline(&result).expect("write baseline");
    store
        .verify_run(&result)
        .expect("verify should succeed for matching digest");
}
