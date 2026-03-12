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

#[path = "../src/e2e_harness.rs"]
mod e2e_harness;

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use e2e_harness::{
    ArtifactCollector, ArtifactCompletenessReport, CounterfactualDelta,
    CounterfactualDivergenceKind, CounterfactualDivergenceSample, CrossMachineReplayDiagnosis,
    DeterministicRng, DeterministicRunner, DeterministicRunnerConfig, EvidenceLinkageRecord,
    ExpectedEvent, FixtureMigrationError, FixtureStore, FixtureValidationError, GoldenBaseline,
    GoldenStore, GoldenVerificationError, HarnessEvent, LogAssertionError, LogExpectation,
    RGC_ADVANCED_E2E_SCENARIO_SCHEMA_VERSION, ReplayEnvironmentFingerprint, ReplayInputError,
    ReplayInputErrorCode, ReplayMismatchKind, ReplayPerformance, ReplayVerification, RunManifest,
    RunReport, ScenarioArtifactPaths, ScenarioClass, ScenarioEvidencePack, ScenarioMatrixEntry,
    ScenarioMatrixReport, ScenarioStep, SignedGoldenUpdate, TestFixture, VirtualClock,
    assert_structured_logs, audit_collected_artifacts, build_evidence_linkage,
    compare_counterfactual, diagnose_cross_machine_replay, evaluate_replay_performance,
    parse_fixture_with_migration, rgc_advanced_scenario_matrix_registry, run_scenario_matrix,
    select_rgc_advanced_scenario_matrix, validate_replay_input, verify_replay,
};

fn test_temp_dir(suffix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("franken-engine-{suffix}-{nanos}"));
    fs::create_dir_all(&path).expect("temp dir");
    path
}

fn sample_fixture() -> TestFixture {
    let mut error_metadata = BTreeMap::new();
    error_metadata.insert("error_code".to_string(), "FE-E2E-0007".to_string());

    TestFixture {
        fixture_id: "fixture-hello".to_string(),
        fixture_version: TestFixture::CURRENT_VERSION,
        seed: 42,
        virtual_time_start_micros: 1_000,
        policy_id: "policy-default".to_string(),
        steps: vec![
            ScenarioStep {
                component: "scheduler".to_string(),
                event: "dispatch".to_string(),
                advance_micros: 100,
                metadata: BTreeMap::new(),
            },
            ScenarioStep {
                component: "guardplane".to_string(),
                event: "challenge".to_string(),
                advance_micros: 200,
                metadata: error_metadata,
            },
        ],
        expected_events: vec![],
        determinism_check: true,
    }
}

fn non_error_fixture(fixture_id: &str, seed: u64, step_count: usize) -> TestFixture {
    let mut steps = Vec::with_capacity(step_count);
    for idx in 0..step_count {
        steps.push(ScenarioStep {
            component: "scheduler".to_string(),
            event: format!("tick-{idx}"),
            advance_micros: 10,
            metadata: BTreeMap::new(),
        });
    }
    TestFixture {
        fixture_id: fixture_id.to_string(),
        fixture_version: TestFixture::CURRENT_VERSION,
        seed,
        virtual_time_start_micros: 5_000,
        policy_id: "policy-matrix".to_string(),
        steps,
        expected_events: vec![],
        determinism_check: true,
    }
}

#[test]
fn deterministic_runner_replays_identically_for_same_fixture() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();

    let first = runner.run_fixture(&fixture).expect("first run");
    let second = runner.run_fixture(&fixture).expect("second run");
    let verification = verify_replay(&first, &second);

    assert!(verification.matches);
    assert_eq!(first.output_digest, second.output_digest);
    assert_eq!(first.events, second.events);
}

#[test]
fn deterministic_runner_detects_seed_change_as_replay_mismatch() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();

    let expected = runner.run_fixture(&fixture).expect("expected run");

    let mut mutated = fixture.clone();
    mutated.seed = fixture.seed + 1;
    let actual = runner.run_fixture(&mutated).expect("actual run");

    let verification = verify_replay(&expected, &actual);
    assert!(!verification.matches);
    assert_eq!(verification.reason.as_deref(), Some("digest mismatch"));
}

#[test]
fn fixture_store_roundtrips_content_addressed_fixture() {
    let root = test_temp_dir("fixture-store");
    let store = FixtureStore::new(&root).expect("store");
    let fixture = sample_fixture();

    let path = store.save_fixture(&fixture).expect("save");
    assert!(path.exists());
    assert!(path.file_name().and_then(|n| n.to_str()).is_some());

    let loaded = store.load_fixture(&path).expect("load");
    assert_eq!(loaded, fixture);
}

#[test]
fn structured_log_assertions_match_and_reject_expected_patterns() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();
    let run = runner.run_fixture(&fixture).expect("run");

    let positive = vec![
        LogExpectation {
            component: "scheduler".to_string(),
            event: "dispatch".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        },
        LogExpectation {
            component: "guardplane".to_string(),
            event: "challenge".to_string(),
            outcome: "error".to_string(),
            error_code: Some("FE-E2E-0007".to_string()),
        },
    ];
    assert!(assert_structured_logs(&run.events, &positive).is_ok());

    let negative = vec![LogExpectation {
        component: "guardplane".to_string(),
        event: "challenge".to_string(),
        outcome: "error".to_string(),
        error_code: Some("FE-E2E-9999".to_string()),
    }];
    assert!(assert_structured_logs(&run.events, &negative).is_err());
}

#[test]
fn artifact_collector_writes_manifest_events_and_reports() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();
    let run = runner.run_fixture(&fixture).expect("run");

    let root = test_temp_dir("artifacts");
    let collector = ArtifactCollector::new(&root).expect("collector");
    let artifacts = collector.collect(&run).expect("collect");

    assert!(artifacts.manifest_path.exists());
    assert!(artifacts.events_path.exists());
    assert!(artifacts.evidence_linkage_path.exists());
    assert!(artifacts.report_json_path.exists());
    assert!(artifacts.report_markdown_path.exists());

    let manifest = fs::read_to_string(&artifacts.manifest_path).expect("manifest string");
    assert!(manifest.contains("fixture-hello"));
    assert!(manifest.contains("replay://"));

    let report_md = fs::read_to_string(&artifacts.report_markdown_path).expect("report md");
    assert!(report_md.contains("# E2E Run Report"));
    assert!(report_md.contains("fixture-hello"));

    let completeness = audit_collected_artifacts(&artifacts);
    assert!(completeness.complete);
    assert_eq!(completeness.event_count, run.events.len());
    assert_eq!(completeness.linkage_count, run.events.len());
}

#[test]
fn replay_input_validation_surfaces_deterministic_edge_codes() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();
    let run = runner.run_fixture(&fixture).expect("run");

    let missing_snapshot_err = validate_replay_input(&run, None).expect_err("missing snapshot");
    assert_eq!(
        missing_snapshot_err.code,
        ReplayInputErrorCode::MissingModelSnapshot
    );

    let mut transcript_corrupted = run.clone();
    transcript_corrupted.random_transcript.pop();
    let transcript_err = validate_replay_input(
        &transcript_corrupted,
        Some("model://snapshot/fixture-hello/seed/42"),
    )
    .expect_err("corrupted transcript");
    assert_eq!(
        transcript_err.code,
        ReplayInputErrorCode::CorruptedTranscript
    );
}

#[test]
fn version_controlled_fixture_loads_and_runs() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture_path = root.join("tests/fixtures/minimal_fixture.json");
    let store = FixtureStore::new(root.join("tests/fixtures")).expect("fixture store");
    let fixture = store
        .load_fixture(&fixture_path)
        .expect("load fixture file");

    let runner = DeterministicRunner::default();
    let run = runner.run_fixture(&fixture).expect("run");

    assert_eq!(run.fixture_id, "minimal-fixture");
    assert_eq!(run.events.len(), fixture.steps.len());
    assert!(!run.output_digest.is_empty());
}

#[test]
fn invalid_fixture_is_rejected() {
    let runner = DeterministicRunner::default();
    let mut invalid = sample_fixture();
    invalid.fixture_id.clear();

    let error = runner
        .run_fixture(&invalid)
        .expect_err("invalid fixture should fail");
    assert_eq!(error.to_string(), "fixture_id is required");
}

#[test]
fn golden_store_detects_mismatch_and_emits_signed_update_artifact() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();

    let baseline_run = runner.run_fixture(&fixture).expect("baseline run");
    let mut changed_fixture = fixture.clone();
    changed_fixture.seed = fixture.seed + 1;
    let changed_run = runner.run_fixture(&changed_fixture).expect("changed run");

    let root = test_temp_dir("golden-store");
    let store = GoldenStore::new(root.join("golden")).expect("golden store");
    let baseline_path = store.write_baseline(&baseline_run).expect("write baseline");
    assert!(baseline_path.exists());

    assert!(store.verify_run(&baseline_run).is_ok());

    let mismatch = store
        .verify_run(&changed_run)
        .expect_err("changed digest should mismatch");
    assert!(matches!(
        mismatch,
        GoldenVerificationError::DigestMismatch { .. }
    ));

    let update_path = store
        .write_signed_update(
            &changed_run,
            "maintainer@franken.engine",
            "sig:deadbeef",
            "accept deterministic update for fixture evolution",
        )
        .expect("write update artifact");
    assert!(update_path.exists());

    let update_json = fs::read_to_string(update_path).expect("update artifact json");
    assert!(update_json.contains("maintainer@franken.engine"));
    assert!(update_json.contains("sig:deadbeef"));
}

#[test]
fn golden_store_reports_missing_baseline() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();
    let run = runner.run_fixture(&fixture).expect("run");

    let root = test_temp_dir("golden-missing");
    let store = GoldenStore::new(root.join("golden")).expect("golden store");
    let err = store
        .verify_run(&run)
        .expect_err("missing baseline should fail");

    assert!(matches!(
        err,
        GoldenVerificationError::MissingBaseline { .. }
    ));
}

#[test]
fn scenario_matrix_emits_evidence_packs_for_baseline_differential_chaos_and_cross_arch() {
    let runner = DeterministicRunner::default();
    let root = test_temp_dir("scenario-matrix");
    let collector = ArtifactCollector::new(root.join("artifacts")).expect("collector");

    let scenarios = rgc_advanced_scenario_matrix_registry();

    let execution = run_scenario_matrix(&runner, &collector, &scenarios).expect("matrix run");
    assert_eq!(execution.report.total_scenarios, 6);
    assert_eq!(execution.report.pass_scenarios, 5);
    assert_eq!(execution.report.fail_scenarios, 1);
    assert_eq!(
        execution.report.schema_version,
        "franken-engine.e2e-scenario-matrix.report.v2"
    );
    assert!(execution.summary_json_path.exists());
    assert!(execution.summary_markdown_path.exists());

    for pack in &execution.report.scenario_packs {
        assert!(!pack.scenario_id.is_empty());
        assert!(pack.replay_pointer.starts_with("replay://"));
        assert!(
            !pack.unit_anchor_ids.is_empty(),
            "unit anchors must be present for {}",
            pack.scenario_id
        );
        assert!(
            collector
                .root()
                .join(&pack.artifact_paths.manifest)
                .exists(),
            "manifest missing for {}",
            pack.scenario_id
        );
        assert!(
            collector.root().join(&pack.artifact_paths.events).exists(),
            "events missing for {}",
            pack.scenario_id
        );
        assert!(
            collector
                .root()
                .join(&pack.artifact_paths.evidence_linkage)
                .exists(),
            "evidence linkage missing for {}",
            pack.scenario_id
        );
    }

    let cross_arch = execution
        .report
        .scenario_packs
        .iter()
        .find(|pack| pack.scenario_class == ScenarioClass::CrossArch)
        .expect("cross-arch scenario");
    assert_eq!(
        cross_arch.target_arch.as_deref(),
        Some("aarch64-unknown-linux-gnu")
    );
    let differential = execution
        .report
        .scenario_packs
        .iter()
        .find(|pack| pack.scenario_class == ScenarioClass::Differential)
        .expect("differential scenario");
    assert_eq!(
        differential.baseline_scenario_id.as_deref(),
        Some("rgc-053-runtime-baseline-01")
    );
    let chaos = execution
        .report
        .scenario_packs
        .iter()
        .find(|pack| pack.scenario_class == ScenarioClass::Chaos)
        .expect("chaos scenario");
    assert_eq!(
        chaos.chaos_profile.as_deref(),
        Some("latency_spike_partial_failure")
    );

    let summary_json =
        fs::read_to_string(&execution.summary_json_path).expect("matrix summary json");
    assert!(summary_json.contains("rgc-053-runtime-baseline-01"));
    assert!(summary_json.contains("rgc-053-module-differential-01"));
    assert!(summary_json.contains("rgc-053-security-chaos-01"));
    assert!(summary_json.contains("rgc-053-runtime-stress-01"));
    assert!(summary_json.contains("rgc-053-security-fault-01"));
    assert!(summary_json.contains("rgc-053-runtime-cross-arch-01"));
    assert!(summary_json.contains("franken-engine.e2e-scenario-matrix.report.v2"));
}

#[test]
fn scenario_matrix_rejects_empty_input() {
    let runner = DeterministicRunner::default();
    let root = test_temp_dir("scenario-matrix-empty");
    let collector = ArtifactCollector::new(root.join("artifacts")).expect("collector");
    let err = run_scenario_matrix(&runner, &collector, &[]).expect_err("must reject empty matrix");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn scenario_matrix_rejects_missing_unit_anchors() {
    let runner = DeterministicRunner::default();
    let root = test_temp_dir("scenario-matrix-missing-unit-anchors");
    let collector = ArtifactCollector::new(root.join("artifacts")).expect("collector");
    let scenarios = vec![ScenarioMatrixEntry {
        scenario_id: "baseline-missing-unit".to_string(),
        scenario_class: ScenarioClass::Baseline,
        fixture: non_error_fixture("baseline-missing-unit", 710, 4),
        baseline_scenario_id: None,
        chaos_profile: None,
        unit_anchor_ids: Vec::new(),
        target_arch: None,
        worker_pool: Some("pool-baseline".to_string()),
    }];

    let err = run_scenario_matrix(&runner, &collector, &scenarios)
        .expect_err("missing unit anchors should fail");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        err.to_string()
            .contains("requires at least one unit_anchor_id"),
        "unexpected error: {err}"
    );
}

#[test]
fn scenario_matrix_rejects_differential_without_baseline_id() {
    let runner = DeterministicRunner::default();
    let root = test_temp_dir("scenario-matrix-differential-missing-baseline");
    let collector = ArtifactCollector::new(root.join("artifacts")).expect("collector");
    let scenarios = vec![ScenarioMatrixEntry {
        scenario_id: "differential-no-baseline".to_string(),
        scenario_class: ScenarioClass::Differential,
        fixture: non_error_fixture("differential-no-baseline", 711, 5),
        baseline_scenario_id: None,
        chaos_profile: None,
        unit_anchor_ids: vec!["unit.e2e_harness.diff_missing_baseline".to_string()],
        target_arch: None,
        worker_pool: Some("pool-diff".to_string()),
    }];

    let err = run_scenario_matrix(&runner, &collector, &scenarios)
        .expect_err("differential scenarios require baseline_scenario_id");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        err.to_string()
            .contains("(differential) requires baseline_scenario_id"),
        "unexpected error: {err}"
    );
}

#[test]
fn scenario_matrix_rejects_chaos_without_profile() {
    let runner = DeterministicRunner::default();
    let root = test_temp_dir("scenario-matrix-chaos-missing-profile");
    let collector = ArtifactCollector::new(root.join("artifacts")).expect("collector");
    let scenarios = vec![ScenarioMatrixEntry {
        scenario_id: "chaos-no-profile".to_string(),
        scenario_class: ScenarioClass::Chaos,
        fixture: non_error_fixture("chaos-no-profile", 712, 5),
        baseline_scenario_id: None,
        chaos_profile: None,
        unit_anchor_ids: vec!["unit.e2e_harness.chaos_missing_profile".to_string()],
        target_arch: None,
        worker_pool: Some("pool-chaos".to_string()),
    }];

    let err = run_scenario_matrix(&runner, &collector, &scenarios)
        .expect_err("chaos scenarios require chaos_profile");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        err.to_string().contains("(chaos) requires chaos_profile"),
        "unexpected error: {err}"
    );
}

#[test]
fn advanced_scenario_matrix_selector_filters_classes_and_faults() {
    let all = select_rgc_advanced_scenario_matrix(&[], true);
    assert_eq!(all.len(), 6);

    let no_faults = select_rgc_advanced_scenario_matrix(&[], false);
    assert_eq!(no_faults.len(), 5);
    assert!(
        no_faults
            .iter()
            .all(|scenario| scenario.scenario_class != ScenarioClass::FaultInjection)
    );

    let chaos_only = select_rgc_advanced_scenario_matrix(&[ScenarioClass::Chaos], true);
    assert_eq!(chaos_only.len(), 1);
    assert_eq!(chaos_only[0].scenario_class, ScenarioClass::Chaos);
    assert_eq!(
        chaos_only[0].chaos_profile.as_deref(),
        Some("latency_spike_partial_failure")
    );
}

#[test]
fn deterministic_e2e_harness_lane_script_preserves_step_logs_and_exit_classification() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script_path = root.join("scripts/run_deterministic_e2e_harness.sh");
    let script = fs::read_to_string(&script_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", script_path.display()));

    for fragment in [
        "step_logs_dir=\"${run_dir}/step_logs\"",
        "\"step_logs\": [",
        "failed_command=\"${command_text} (rch-exit=${status}; remote-exit=${remote_exit_code})\"",
        "cargo clippy -p frankenengine-engine --test e2e_harness -- -D warnings",
        "cargo clippy -p frankenengine-engine --test e2e_harness_integration -- -D warnings",
    ] {
        assert!(
            script.contains(fragment),
            "missing script fragment in {}: {fragment}",
            script_path.display()
        );
    }
}

#[test]
fn scenario_class_serde_roundtrip() {
    for class in ScenarioClass::ALL {
        let json = serde_json::to_string(&class).expect("serialize");
        let recovered: ScenarioClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, class);
    }
}

#[test]
fn scenario_class_as_str_all_nonempty() {
    for class in ScenarioClass::ALL {
        assert!(!class.as_str().is_empty());
    }
}

#[test]
fn scenario_class_all_has_six_variants() {
    assert_eq!(ScenarioClass::ALL.len(), 6);
}

#[test]
fn test_fixture_serde_roundtrip() {
    let fixture = sample_fixture();
    let json = serde_json::to_string(&fixture).expect("serialize");
    let recovered: TestFixture = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, fixture);
}

#[test]
fn run_result_serde_roundtrip() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();
    let run = runner.run_fixture(&fixture).expect("run");

    let json = serde_json::to_string(&run).expect("serialize");
    let recovered: e2e_harness::RunResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.fixture_id, run.fixture_id);
    assert_eq!(recovered.output_digest, run.output_digest);
    assert_eq!(recovered.events.len(), run.events.len());
}

#[test]
fn counterfactual_delta_identical_runs_no_divergence() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();
    let run_a = runner.run_fixture(&fixture).expect("run a");
    let run_b = runner.run_fixture(&fixture).expect("run b");

    let delta = e2e_harness::compare_counterfactual(&run_a, &run_b);
    assert!(!delta.digest_changed);
    assert_eq!(delta.changed_events, 0);
    assert_eq!(delta.diverged_at_sequence, None);
    assert!(!delta.transcript_changed);
}

#[test]
fn counterfactual_delta_different_seeds_detects_divergence() {
    let runner = DeterministicRunner::default();
    let fixture_a = non_error_fixture("baseline", 1, 3);
    let mut fixture_b = non_error_fixture("counterfactual", 999, 3);
    fixture_b.fixture_id = "counterfactual".to_string();

    let run_a = runner.run_fixture(&fixture_a).expect("run a");
    let run_b = runner.run_fixture(&fixture_b).expect("run b");

    let delta = e2e_harness::compare_counterfactual(&run_a, &run_b);
    assert!(delta.digest_changed);
}

#[test]
fn replay_performance_evaluates_speedup() {
    let runner = DeterministicRunner::default();
    let fixture = non_error_fixture("perf-test", 42, 5);
    let run = runner.run_fixture(&fixture).expect("run");

    let perf = e2e_harness::evaluate_replay_performance(&run, 1_000);
    assert!(perf.wall_duration_micros > 0 || perf.wall_duration_micros == 1_000);
    assert!(perf.virtual_duration_micros > 0);
}

#[test]
fn evidence_linkage_has_entries_per_event() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();
    let run = runner.run_fixture(&fixture).expect("run");

    let linkage = e2e_harness::build_evidence_linkage(&run.events);
    assert_eq!(linkage.len(), run.events.len());
}

#[test]
fn deterministic_e2e_harness_readme_documents_ci_clippy_and_step_logs() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let readme_path = root.join("README.md");
    let readme = fs::read_to_string(&readme_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", readme_path.display()));

    for fragment in [
        "# CI shortcut (check + test + clippy)",
        "./scripts/run_deterministic_e2e_harness.sh ci",
        "step_logs/step_*.log",
    ] {
        assert!(
            readme.contains(fragment),
            "missing README fragment in {}: {fragment}",
            readme_path.display()
        );
    }
}

#[test]
fn parse_fixture_with_migration_rejects_invalid_json() {
    let bad_bytes = b"this is not json";
    let err = e2e_harness::parse_fixture_with_migration(bad_bytes)
        .expect_err("invalid JSON should fail migration parse");
    let msg = format!("{err}");
    assert!(!msg.is_empty(), "migration error should have a message");
}

#[test]
fn golden_store_write_baseline_is_idempotent() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();
    let run = runner.run_fixture(&fixture).expect("run");

    let root = test_temp_dir("golden-idempotent");
    let store = GoldenStore::new(root.join("golden")).expect("golden store");

    let path_a = store.write_baseline(&run).expect("first write");
    let path_b = store.write_baseline(&run).expect("second write");
    assert_eq!(
        path_a, path_b,
        "writing the same baseline twice must produce the same path"
    );
    assert!(store.verify_run(&run).is_ok());
}

#[test]
fn evidence_linkage_records_are_serde_deterministic() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();
    let run = runner.run_fixture(&fixture).expect("run");

    let linkage = e2e_harness::build_evidence_linkage(&run.events);
    let json_a = serde_json::to_string(&linkage).expect("first serialize");
    let json_b = serde_json::to_string(&linkage).expect("second serialize");
    assert_eq!(
        json_a, json_b,
        "evidence linkage serialization must be deterministic"
    );
}

#[test]
fn scenario_class_debug_is_nonempty() {
    let class = ScenarioClass::Baseline;
    assert!(!format!("{class:?}").is_empty());
}

#[test]
fn log_expectation_debug_is_nonempty() {
    let exp = LogExpectation {
        component: "test".to_string(),
        event: "init".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    assert!(!format!("{exp:?}").is_empty());
}

#[test]
fn replay_input_error_code_debug_is_nonempty() {
    let code = ReplayInputErrorCode::MissingModelSnapshot;
    assert!(!format!("{code:?}").is_empty());
}

// ---------------------------------------------------------------------------
// VirtualClock deterministic advance
// ---------------------------------------------------------------------------

#[test]
fn virtual_clock_advances_deterministically() {
    let mut clock = VirtualClock::new(1_000);
    assert_eq!(clock.now_micros(), 1_000); // Copy, so self isn't consumed
    clock.advance(500);
    assert_eq!(clock.now_micros(), 1_500);
    // saturating add caps at u64::MAX
    clock.advance(u64::MAX);
    assert_eq!(clock.now_micros(), u64::MAX);
}

// ---------------------------------------------------------------------------
// DeterministicRng reproducibility
// ---------------------------------------------------------------------------

#[test]
fn deterministic_rng_same_seed_produces_same_sequence() {
    let mut rng_a = DeterministicRng::seeded(42);
    let mut rng_b = DeterministicRng::seeded(42);
    let seq_a: Vec<u64> = (0..10).map(|_| rng_a.next_u64()).collect();
    let seq_b: Vec<u64> = (0..10).map(|_| rng_b.next_u64()).collect();
    assert_eq!(seq_a, seq_b, "same seed must produce identical sequences");
    // zero seed also works
    let mut rng_zero = DeterministicRng::seeded(0);
    let val = rng_zero.next_u64();
    assert_ne!(
        val, 0,
        "zero seed should be remapped to avoid degenerate xorshift"
    );
}

// ---------------------------------------------------------------------------
// ReplayEnvironmentFingerprint::local()
// ---------------------------------------------------------------------------

#[test]
fn replay_environment_fingerprint_local_is_populated() {
    let fp = ReplayEnvironmentFingerprint::local();
    assert!(!fp.os.is_empty());
    assert!(!fp.architecture.is_empty());
    assert!(!fp.family.is_empty());
    assert!(fp.pointer_width_bits > 0);
    assert!(!fp.endian.is_empty());
    // serde roundtrip
    let json = serde_json::to_string(&fp).expect("serialize");
    let recovered: ReplayEnvironmentFingerprint = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(fp, recovered);
}

// ---------------------------------------------------------------------------
// RunReport::from_result and to_markdown
// ---------------------------------------------------------------------------

#[test]
fn run_report_from_result_captures_error_status() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture(); // has an error_code step
    let run = runner.run_fixture(&fixture).expect("run");

    let report = RunReport::from_result(&run);
    assert_eq!(report.fixture_id, "fixture-hello");
    assert_eq!(report.event_count, fixture.steps.len());
    assert!(
        !report.pass,
        "fixture with error_code step should report fail"
    );
    assert_eq!(report.first_error_code.as_deref(), Some("FE-E2E-0007"));
    let md = report.to_markdown();
    assert!(md.contains("# E2E Run Report"));
    assert!(md.contains("fail"));
    assert!(md.contains("FE-E2E-0007"));
}

// ---------------------------------------------------------------------------
// diagnose_cross_machine_replay same environment
// ---------------------------------------------------------------------------

#[test]
fn diagnose_cross_machine_replay_same_env_matches() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();
    let run_a = runner.run_fixture(&fixture).expect("run a");
    let run_b = runner.run_fixture(&fixture).expect("run b");
    let env_fp = ReplayEnvironmentFingerprint::local();

    let diag = diagnose_cross_machine_replay(&run_a, &run_b, &env_fp, &env_fp);
    assert!(
        diag.cross_machine_match,
        "same seed + same env should match"
    );
    assert!(diag.environment_mismatches.is_empty());
    assert!(diag.replay_verification.matches);
}

// ---------------------------------------------------------------------------
// Enrichment: VirtualClock
// ---------------------------------------------------------------------------

#[test]
fn virtual_clock_serde_roundtrip() {
    let clock = VirtualClock::new(999_999);
    let json = serde_json::to_string(&clock).expect("serialize");
    let recovered: VirtualClock = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, clock);
}

#[test]
fn virtual_clock_zero_start() {
    let clock = VirtualClock::new(0);
    assert_eq!(clock.now_micros(), 0);
}

#[test]
fn virtual_clock_max_start() {
    let clock = VirtualClock::new(u64::MAX);
    assert_eq!(clock.now_micros(), u64::MAX);
}

#[test]
fn virtual_clock_advance_zero_is_noop() {
    let mut clock = VirtualClock::new(500);
    clock.advance(0);
    assert_eq!(clock.now_micros(), 500);
}

#[test]
fn virtual_clock_multiple_advances_accumulate() {
    let mut clock = VirtualClock::new(100);
    clock.advance(10);
    clock.advance(20);
    clock.advance(30);
    assert_eq!(clock.now_micros(), 160);
}

// ---------------------------------------------------------------------------
// Enrichment: DeterministicRng
// ---------------------------------------------------------------------------

#[test]
fn deterministic_rng_serde_roundtrip() {
    let rng = DeterministicRng::seeded(12345);
    let json = serde_json::to_string(&rng).expect("serialize");
    let recovered: DeterministicRng = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, rng);
}

#[test]
fn deterministic_rng_different_seeds_produce_different_sequences() {
    let mut rng_a = DeterministicRng::seeded(1);
    let mut rng_b = DeterministicRng::seeded(2);
    let a: Vec<u64> = (0..5).map(|_| rng_a.next_u64()).collect();
    let b: Vec<u64> = (0..5).map(|_| rng_b.next_u64()).collect();
    assert_ne!(a, b);
}

#[test]
fn deterministic_rng_max_seed() {
    let mut rng = DeterministicRng::seeded(u64::MAX);
    let val = rng.next_u64();
    assert_ne!(val, 0, "max seed should produce non-zero output");
}

// ---------------------------------------------------------------------------
// Enrichment: ScenarioStep serde
// ---------------------------------------------------------------------------

#[test]
fn scenario_step_serde_roundtrip() {
    let mut metadata = BTreeMap::new();
    metadata.insert("key".to_string(), "value".to_string());
    let step = ScenarioStep {
        component: "router".to_string(),
        event: "ingest".to_string(),
        advance_micros: 42,
        metadata,
    };
    let json = serde_json::to_string(&step).expect("serialize");
    let recovered: ScenarioStep = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.component, "router");
    assert_eq!(recovered.event, "ingest");
    assert_eq!(recovered.advance_micros, 42);
    assert_eq!(recovered.metadata.get("key").unwrap(), "value");
}

#[test]
fn scenario_step_serde_defaults_for_missing_fields() {
    let json = r#"{"component":"test","event":"init"}"#;
    let step: ScenarioStep = serde_json::from_str(json).expect("deserialize");
    assert_eq!(step.advance_micros, 0);
    assert!(step.metadata.is_empty());
}

// ---------------------------------------------------------------------------
// Enrichment: ExpectedEvent serde
// ---------------------------------------------------------------------------

#[test]
fn expected_event_serde_roundtrip() {
    let event = ExpectedEvent {
        component: "scheduler".to_string(),
        event: "dispatch".to_string(),
        outcome: "ok".to_string(),
        error_code: Some("FE-E2E-0001".to_string()),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: ExpectedEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, event);
}

#[test]
fn expected_event_serde_roundtrip_no_error_code() {
    let event = ExpectedEvent {
        component: "runner".to_string(),
        event: "start".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: ExpectedEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, event);
}

// ---------------------------------------------------------------------------
// Enrichment: HarnessEvent serde
// ---------------------------------------------------------------------------

#[test]
fn harness_event_serde_roundtrip() {
    let event = HarnessEvent {
        trace_id: "trace-1".to_string(),
        decision_id: "d-0001".to_string(),
        policy_id: "policy-x".to_string(),
        component: "guardplane".to_string(),
        event: "challenge".to_string(),
        outcome: "error".to_string(),
        error_code: Some("FE-0099".to_string()),
        sequence: 7,
        virtual_time_micros: 123_456,
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: HarnessEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, event);
}

#[test]
fn harness_event_serde_roundtrip_no_error() {
    let event = HarnessEvent {
        trace_id: "trace-2".to_string(),
        decision_id: "d-0002".to_string(),
        policy_id: "policy-y".to_string(),
        component: "scheduler".to_string(),
        event: "tick".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
        sequence: 0,
        virtual_time_micros: 0,
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: HarnessEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, event);
}

// ---------------------------------------------------------------------------
// Enrichment: DeterministicRunnerConfig
// ---------------------------------------------------------------------------

#[test]
fn deterministic_runner_config_default_trace_prefix() {
    let config = DeterministicRunnerConfig::default();
    assert_eq!(config.trace_prefix, "trace");
}

#[test]
fn deterministic_runner_config_serde_roundtrip() {
    let config = DeterministicRunnerConfig {
        trace_prefix: "custom-prefix".to_string(),
    };
    let json = serde_json::to_string(&config).expect("serialize");
    let recovered: DeterministicRunnerConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, config);
}

// ---------------------------------------------------------------------------
// Enrichment: TestFixture validation edge cases
// ---------------------------------------------------------------------------

#[test]
fn fixture_validate_rejects_empty_policy_id() {
    let fixture = TestFixture {
        fixture_id: "valid-id".to_string(),
        fixture_version: TestFixture::CURRENT_VERSION,
        seed: 1,
        virtual_time_start_micros: 0,
        policy_id: "".to_string(),
        steps: vec![ScenarioStep {
            component: "c".to_string(),
            event: "e".to_string(),
            advance_micros: 1,
            metadata: BTreeMap::new(),
        }],
        expected_events: vec![],
        determinism_check: false,
    };
    let err = fixture.validate().expect_err("empty policy_id");
    assert_eq!(err.to_string(), "policy_id is required");
}

#[test]
fn fixture_validate_rejects_empty_steps() {
    let fixture = TestFixture {
        fixture_id: "valid-id".to_string(),
        fixture_version: TestFixture::CURRENT_VERSION,
        seed: 1,
        virtual_time_start_micros: 0,
        policy_id: "policy".to_string(),
        steps: vec![],
        expected_events: vec![],
        determinism_check: false,
    };
    let err = fixture.validate().expect_err("empty steps");
    assert_eq!(err.to_string(), "fixture must contain at least one step");
}

#[test]
fn fixture_validate_rejects_wrong_version() {
    let fixture = TestFixture {
        fixture_id: "valid-id".to_string(),
        fixture_version: 99,
        seed: 1,
        virtual_time_start_micros: 0,
        policy_id: "policy".to_string(),
        steps: vec![ScenarioStep {
            component: "c".to_string(),
            event: "e".to_string(),
            advance_micros: 1,
            metadata: BTreeMap::new(),
        }],
        expected_events: vec![],
        determinism_check: false,
    };
    let err = fixture.validate().expect_err("wrong version");
    assert!(err.to_string().contains("unsupported fixture version"));
    assert!(err.to_string().contains("99"));
}

#[test]
fn fixture_validate_rejects_empty_step_component() {
    let fixture = TestFixture {
        fixture_id: "valid-id".to_string(),
        fixture_version: TestFixture::CURRENT_VERSION,
        seed: 1,
        virtual_time_start_micros: 0,
        policy_id: "policy".to_string(),
        steps: vec![ScenarioStep {
            component: "".to_string(),
            event: "e".to_string(),
            advance_micros: 1,
            metadata: BTreeMap::new(),
        }],
        expected_events: vec![],
        determinism_check: false,
    };
    let err = fixture.validate().expect_err("empty component");
    assert!(err.to_string().contains("component is empty"));
}

#[test]
fn fixture_validate_rejects_empty_step_event() {
    let fixture = TestFixture {
        fixture_id: "valid-id".to_string(),
        fixture_version: TestFixture::CURRENT_VERSION,
        seed: 1,
        virtual_time_start_micros: 0,
        policy_id: "policy".to_string(),
        steps: vec![ScenarioStep {
            component: "c".to_string(),
            event: "  ".to_string(),
            advance_micros: 1,
            metadata: BTreeMap::new(),
        }],
        expected_events: vec![],
        determinism_check: false,
    };
    let err = fixture.validate().expect_err("empty event");
    assert!(err.to_string().contains("event is empty"));
}

#[test]
fn fixture_validate_accepts_valid_fixture() {
    let fixture = sample_fixture();
    assert!(fixture.validate().is_ok());
}

#[test]
fn fixture_current_version_is_one() {
    assert_eq!(TestFixture::CURRENT_VERSION, 1);
}

// ---------------------------------------------------------------------------
// Enrichment: FixtureValidationError Display
// ---------------------------------------------------------------------------

#[test]
fn fixture_validation_error_display_missing_fixture_id() {
    let err = FixtureValidationError::MissingFixtureId;
    assert_eq!(err.to_string(), "fixture_id is required");
}

#[test]
fn fixture_validation_error_display_missing_policy_id() {
    let err = FixtureValidationError::MissingPolicyId;
    assert_eq!(err.to_string(), "policy_id is required");
}

#[test]
fn fixture_validation_error_display_missing_steps() {
    let err = FixtureValidationError::MissingSteps;
    assert_eq!(err.to_string(), "fixture must contain at least one step");
}

#[test]
fn fixture_validation_error_display_unsupported_version() {
    let err = FixtureValidationError::UnsupportedVersion {
        expected: 1,
        actual: 5,
    };
    let msg = err.to_string();
    assert!(msg.contains("unsupported fixture version"));
    assert!(msg.contains("1"));
    assert!(msg.contains("5"));
}

#[test]
fn fixture_validation_error_display_invalid_step() {
    let err = FixtureValidationError::InvalidStep {
        index: 3,
        reason: "component is empty".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("invalid step at index 3"));
    assert!(msg.contains("component is empty"));
}

// ---------------------------------------------------------------------------
// Enrichment: FixtureMigrationError Display and serde
// ---------------------------------------------------------------------------

#[test]
fn fixture_migration_error_display_invalid_payload() {
    let err = FixtureMigrationError::InvalidFixturePayload {
        message: "bad json".to_string(),
    };
    assert!(err.to_string().contains("invalid fixture payload"));
    assert!(err.to_string().contains("bad json"));
}

#[test]
fn fixture_migration_error_display_unsupported_version() {
    let err = FixtureMigrationError::UnsupportedVersion {
        expected: 1,
        actual: 42,
    };
    let msg = err.to_string();
    assert!(msg.contains("unsupported fixture version"));
    assert!(msg.contains("42"));
}

#[test]
fn fixture_migration_error_display_invalid_migrated() {
    let err = FixtureMigrationError::InvalidMigratedFixture {
        message: "missing field".to_string(),
    };
    assert!(err.to_string().contains("invalid migrated fixture"));
    assert!(err.to_string().contains("missing field"));
}

#[test]
fn fixture_migration_error_serde_roundtrip_all_variants() {
    let variants = vec![
        FixtureMigrationError::InvalidFixturePayload {
            message: "msg".to_string(),
        },
        FixtureMigrationError::UnsupportedVersion {
            expected: 1,
            actual: 7,
        },
        FixtureMigrationError::InvalidMigratedFixture {
            message: "migr".to_string(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).expect("serialize");
        let recovered: FixtureMigrationError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(&recovered, v);
    }
}

// ---------------------------------------------------------------------------
// Enrichment: parse_fixture_with_migration
// ---------------------------------------------------------------------------

#[test]
fn parse_fixture_with_migration_v0_migrates_successfully() {
    let v0_json = serde_json::json!({
        "fixture_id": "legacy-fixture",
        "fixture_version": 0,
        "seed": 7,
        "virtual_time_start_micros": 1000,
        "policy_id": "legacy-policy",
        "steps": [
            {"component": "sched", "event": "tick", "advance_micros": 10, "metadata": {}}
        ]
    });
    let bytes = serde_json::to_vec(&v0_json).expect("encode");
    let fixture = parse_fixture_with_migration(&bytes).expect("migrate");
    assert_eq!(fixture.fixture_id, "legacy-fixture");
    assert_eq!(fixture.fixture_version, TestFixture::CURRENT_VERSION);
    assert!(fixture.expected_events.is_empty());
    assert!(fixture.determinism_check);
}

#[test]
fn parse_fixture_with_migration_v1_passes_through() {
    let fixture = sample_fixture();
    let bytes = serde_json::to_vec(&fixture).expect("encode");
    let recovered = parse_fixture_with_migration(&bytes).expect("parse v1");
    assert_eq!(recovered, fixture);
}

#[test]
fn parse_fixture_with_migration_unsupported_version() {
    let v99_json = serde_json::json!({
        "fixture_id": "future",
        "fixture_version": 99,
        "seed": 1,
        "virtual_time_start_micros": 0,
        "policy_id": "p",
        "steps": [{"component": "c", "event": "e"}]
    });
    let bytes = serde_json::to_vec(&v99_json).expect("encode");
    let err = parse_fixture_with_migration(&bytes).expect_err("unsupported version");
    assert!(matches!(
        err,
        FixtureMigrationError::UnsupportedVersion { .. }
    ));
}

#[test]
fn parse_fixture_with_migration_missing_version_field() {
    let bad_json = serde_json::json!({"fixture_id": "no-version"});
    let bytes = serde_json::to_vec(&bad_json).expect("encode");
    let err = parse_fixture_with_migration(&bytes).expect_err("missing version");
    assert!(matches!(
        err,
        FixtureMigrationError::InvalidFixturePayload { .. }
    ));
}

// ---------------------------------------------------------------------------
// Enrichment: ReplayInputErrorCode as_str coverage
// ---------------------------------------------------------------------------

#[test]
fn replay_input_error_code_serde_roundtrip_all_variants() {
    let variants = [
        ReplayInputErrorCode::MissingModelSnapshot,
        ReplayInputErrorCode::PartialTrace,
        ReplayInputErrorCode::CorruptedTranscript,
    ];
    for code in &variants {
        let json = serde_json::to_string(code).expect("serialize");
        let recovered: ReplayInputErrorCode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(&recovered, code);
    }
}

// ---------------------------------------------------------------------------
// Enrichment: ReplayInputError Display
// ---------------------------------------------------------------------------

#[test]
fn replay_input_error_display_contains_code_and_message() {
    let err = ReplayInputError {
        code: ReplayInputErrorCode::PartialTrace,
        message: "gap at index 2".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("partial_trace"));
    assert!(msg.contains("gap at index 2"));
}

#[test]
fn replay_input_error_serde_roundtrip() {
    let err = ReplayInputError {
        code: ReplayInputErrorCode::MissingModelSnapshot,
        message: "snapshot missing".to_string(),
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: ReplayInputError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, err);
}

// ---------------------------------------------------------------------------
// Enrichment: validate_replay_input edge cases
// ---------------------------------------------------------------------------

#[test]
fn validate_replay_input_rejects_empty_snapshot_pointer() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();
    let run = runner.run_fixture(&fixture).expect("run");
    let err = validate_replay_input(&run, Some("  ")).expect_err("whitespace snapshot");
    assert_eq!(err.code, ReplayInputErrorCode::MissingModelSnapshot);
}

#[test]
fn validate_replay_input_accepts_valid_run() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();
    let run = runner.run_fixture(&fixture).expect("run");
    assert!(validate_replay_input(&run, Some("model://snapshot/fixture-hello/seed/42")).is_ok());
}

// ---------------------------------------------------------------------------
// Enrichment: EvidenceLinkageRecord serde
// ---------------------------------------------------------------------------

#[test]
fn evidence_linkage_record_serde_roundtrip() {
    let record = EvidenceLinkageRecord {
        trace_id: "trace-1".to_string(),
        decision_id: "d-0001".to_string(),
        policy_id: "policy-x".to_string(),
        event_sequence: 5,
        evidence_hash: "abcdef0123456789".to_string(),
    };
    let json = serde_json::to_string(&record).expect("serialize");
    let recovered: EvidenceLinkageRecord = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, record);
}

#[test]
fn evidence_linkage_empty_events_produces_empty_vec() {
    let linkage = build_evidence_linkage(&[]);
    assert!(linkage.is_empty());
}

// ---------------------------------------------------------------------------
// Enrichment: ReplayMismatchKind serde
// ---------------------------------------------------------------------------

#[test]
fn replay_mismatch_kind_serde_roundtrip_all_variants() {
    let variants = [
        ReplayMismatchKind::Digest,
        ReplayMismatchKind::EventStream,
        ReplayMismatchKind::RandomTranscript,
    ];
    for kind in &variants {
        let json = serde_json::to_string(kind).expect("serialize");
        let recovered: ReplayMismatchKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(&recovered, kind);
    }
}

// ---------------------------------------------------------------------------
// Enrichment: ReplayVerification serde
// ---------------------------------------------------------------------------

#[test]
fn replay_verification_serde_roundtrip() {
    let v = ReplayVerification {
        matches: false,
        expected_digest: "abc".to_string(),
        actual_digest: "def".to_string(),
        reason: Some("digest mismatch".to_string()),
        mismatch_kind: Some(ReplayMismatchKind::Digest),
        diverged_event_sequence: Some(3),
        transcript_mismatch_index: Some(1),
        expected_event_count: 10,
        actual_event_count: 10,
        expected_transcript_len: 10,
        actual_transcript_len: 10,
    };
    let json = serde_json::to_string(&v).expect("serialize");
    let recovered: ReplayVerification = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, v);
}

// ---------------------------------------------------------------------------
// Enrichment: verify_replay mismatch kinds
// ---------------------------------------------------------------------------

#[test]
fn verify_replay_event_stream_mismatch_detected() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();
    let run = runner.run_fixture(&fixture).expect("run");

    let mut altered = run.clone();
    if let Some(event) = altered.events.first_mut() {
        event.outcome = "altered_outcome".to_string();
    }
    // Recompute digest to match so only event stream differs
    // Actually, the digest will also differ. Let's force digest match:
    altered.output_digest = run.output_digest.clone();

    let verification = verify_replay(&run, &altered);
    assert!(!verification.matches);
}

#[test]
fn verify_replay_identical_runs_match() {
    let runner = DeterministicRunner::default();
    let fixture = non_error_fixture("replay-check", 123, 3);
    let run_a = runner.run_fixture(&fixture).expect("a");
    let run_b = runner.run_fixture(&fixture).expect("b");
    let v = verify_replay(&run_a, &run_b);
    assert!(v.matches);
    assert!(v.reason.is_none());
    assert!(v.mismatch_kind.is_none());
    assert_eq!(v.diverged_event_sequence, None);
    assert_eq!(v.transcript_mismatch_index, None);
}

// ---------------------------------------------------------------------------
// Enrichment: ReplayPerformance serde
// ---------------------------------------------------------------------------

#[test]
fn replay_performance_serde_roundtrip() {
    let perf = ReplayPerformance {
        virtual_duration_micros: 5000,
        wall_duration_micros: 1000,
        faster_than_realtime: true,
        speedup_milli: 5000,
    };
    let json = serde_json::to_string(&perf).expect("serialize");
    let recovered: ReplayPerformance = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, perf);
}

#[test]
fn evaluate_replay_performance_zero_wall_duration_gives_max_speedup() {
    let runner = DeterministicRunner::default();
    let fixture = non_error_fixture("perf-zero", 1, 2);
    let run = runner.run_fixture(&fixture).expect("run");
    let perf = evaluate_replay_performance(&run, 0);
    assert_eq!(perf.speedup_milli, u64::MAX);
    assert!(perf.faster_than_realtime);
}

#[test]
fn evaluate_replay_performance_slower_than_realtime() {
    let runner = DeterministicRunner::default();
    // fixture with small virtual time but big wall time
    let fixture = non_error_fixture("perf-slow", 1, 1);
    let run = runner.run_fixture(&fixture).expect("run");
    let virtual_span = run.end_virtual_time_micros - run.start_virtual_time_micros;
    let perf = evaluate_replay_performance(&run, virtual_span + 1_000_000);
    assert!(!perf.faster_than_realtime);
}

// ---------------------------------------------------------------------------
// Enrichment: ReplayEnvironmentFingerprint
// ---------------------------------------------------------------------------

#[test]
fn replay_environment_fingerprint_serde_roundtrip() {
    let fp = ReplayEnvironmentFingerprint {
        os: "linux".to_string(),
        architecture: "x86_64".to_string(),
        family: "unix".to_string(),
        pointer_width_bits: 64,
        endian: "little".to_string(),
    };
    let json = serde_json::to_string(&fp).expect("serialize");
    let recovered: ReplayEnvironmentFingerprint = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, fp);
}

// ---------------------------------------------------------------------------
// Enrichment: CrossMachineReplayDiagnosis
// ---------------------------------------------------------------------------

#[test]
fn cross_machine_replay_diagnosis_serde_roundtrip() {
    let diag = CrossMachineReplayDiagnosis {
        cross_machine_match: false,
        replay_verification: ReplayVerification {
            matches: false,
            expected_digest: "a".to_string(),
            actual_digest: "b".to_string(),
            reason: Some("digest mismatch".to_string()),
            mismatch_kind: Some(ReplayMismatchKind::Digest),
            diverged_event_sequence: None,
            transcript_mismatch_index: None,
            expected_event_count: 2,
            actual_event_count: 2,
            expected_transcript_len: 2,
            actual_transcript_len: 2,
        },
        expected_environment: ReplayEnvironmentFingerprint::local(),
        actual_environment: ReplayEnvironmentFingerprint::local(),
        environment_mismatches: vec!["os".to_string()],
        diagnosis: Some("env differ".to_string()),
    };
    let json = serde_json::to_string(&diag).expect("serialize");
    let recovered: CrossMachineReplayDiagnosis = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, diag);
}

#[test]
fn diagnose_cross_machine_replay_with_env_mismatch() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();
    let run_a = runner.run_fixture(&fixture).expect("a");
    let run_b = runner.run_fixture(&fixture).expect("b");

    let env_a = ReplayEnvironmentFingerprint::local();
    let env_b = ReplayEnvironmentFingerprint {
        os: "windows".to_string(),
        architecture: "aarch64".to_string(),
        family: "windows".to_string(),
        pointer_width_bits: 64,
        endian: "little".to_string(),
    };
    let diag = diagnose_cross_machine_replay(&run_a, &run_b, &env_a, &env_b);
    // Replay matches (same seed) but environments differ
    assert!(diag.cross_machine_match);
    assert!(!diag.environment_mismatches.is_empty());
    assert!(diag.diagnosis.is_some());
    let diagnosis = diag.diagnosis.unwrap();
    assert!(diagnosis.contains("replay matched across environment deltas"));
}

#[test]
fn diagnose_cross_machine_replay_mismatch_with_env_diff() {
    let runner = DeterministicRunner::default();
    let fixture_a = non_error_fixture("cm-a", 1, 2);
    let fixture_b = non_error_fixture("cm-b", 999, 2);

    let run_a = runner.run_fixture(&fixture_a).expect("a");
    let run_b = runner.run_fixture(&fixture_b).expect("b");

    let env_a = ReplayEnvironmentFingerprint::local();
    let env_b = ReplayEnvironmentFingerprint {
        os: "macos".to_string(),
        ..env_a.clone()
    };
    let diag = diagnose_cross_machine_replay(&run_a, &run_b, &env_a, &env_b);
    assert!(!diag.cross_machine_match);
    assert!(
        diag.diagnosis
            .as_ref()
            .unwrap()
            .contains("environment mismatch fields")
    );
}

// ---------------------------------------------------------------------------
// Enrichment: CounterfactualDivergenceKind serde
// ---------------------------------------------------------------------------

#[test]
fn counterfactual_divergence_kind_serde_roundtrip_all_variants() {
    let variants = [
        CounterfactualDivergenceKind::EventMismatch,
        CounterfactualDivergenceKind::MissingBaselineEvent,
        CounterfactualDivergenceKind::MissingCounterfactualEvent,
    ];
    for kind in &variants {
        let json = serde_json::to_string(kind).expect("serialize");
        let recovered: CounterfactualDivergenceKind =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(&recovered, kind);
    }
}

// ---------------------------------------------------------------------------
// Enrichment: CounterfactualDivergenceSample serde
// ---------------------------------------------------------------------------

#[test]
fn counterfactual_divergence_sample_serde_roundtrip() {
    let sample = CounterfactualDivergenceSample {
        sequence: 3,
        kind: CounterfactualDivergenceKind::EventMismatch,
        baseline_component: Some("scheduler".to_string()),
        counterfactual_component: Some("router".to_string()),
        baseline_event: Some("dispatch".to_string()),
        counterfactual_event: Some("route".to_string()),
        baseline_outcome: Some("ok".to_string()),
        counterfactual_outcome: Some("error".to_string()),
        baseline_error_code: None,
        counterfactual_error_code: Some("FE-001".to_string()),
    };
    let json = serde_json::to_string(&sample).expect("serialize");
    let recovered: CounterfactualDivergenceSample =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, sample);
}

// ---------------------------------------------------------------------------
// Enrichment: CounterfactualDelta serde
// ---------------------------------------------------------------------------

#[test]
fn counterfactual_delta_serde_roundtrip() {
    let delta = CounterfactualDelta {
        baseline_run_id: "run-a".to_string(),
        counterfactual_run_id: "run-b".to_string(),
        digest_changed: true,
        diverged_at_sequence: Some(0),
        changed_events: 2,
        changed_outcomes: 1,
        changed_error_codes: 0,
        baseline_event_count: 3,
        counterfactual_event_count: 3,
        transcript_changed: true,
        transcript_diverged_at_index: Some(0),
        divergence_samples: vec![],
    };
    let json = serde_json::to_string(&delta).expect("serialize");
    let recovered: CounterfactualDelta = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, delta);
}

// ---------------------------------------------------------------------------
// Enrichment: compare_counterfactual edge cases
// ---------------------------------------------------------------------------

#[test]
fn compare_counterfactual_mismatched_event_counts() {
    let runner = DeterministicRunner::default();
    let fixture_a = non_error_fixture("cf-short", 1, 2);
    let fixture_b = non_error_fixture("cf-long", 1, 5);
    let run_a = runner.run_fixture(&fixture_a).expect("a");
    let run_b = runner.run_fixture(&fixture_b).expect("b");
    let delta = compare_counterfactual(&run_a, &run_b);
    assert!(delta.digest_changed);
    assert_ne!(delta.baseline_event_count, delta.counterfactual_event_count);
    assert!(delta.changed_events > 0);
    assert!(!delta.divergence_samples.is_empty());
}

#[test]
fn compare_counterfactual_divergence_samples_capped() {
    let runner = DeterministicRunner::default();
    // Create runs with many differing events
    let fixture_a = non_error_fixture("cf-cap-a", 1, 20);
    let fixture_b = non_error_fixture("cf-cap-b", 999, 20);
    let run_a = runner.run_fixture(&fixture_a).expect("a");
    let run_b = runner.run_fixture(&fixture_b).expect("b");
    let delta = compare_counterfactual(&run_a, &run_b);
    // Samples are capped at 8
    assert!(delta.divergence_samples.len() <= 8);
}

#[test]
fn compare_counterfactual_tracks_changed_outcomes_and_error_codes() {
    let runner = DeterministicRunner::default();
    let fixture_ok = non_error_fixture("cf-ok", 1, 3);
    let run_ok = runner.run_fixture(&fixture_ok).expect("ok");

    let fixture_err = sample_fixture(); // has error_code step
    let run_err = runner.run_fixture(&fixture_err).expect("err");

    let delta = compare_counterfactual(&run_ok, &run_err);
    assert!(delta.digest_changed);
}

// ---------------------------------------------------------------------------
// Enrichment: GoldenBaseline serde
// ---------------------------------------------------------------------------

#[test]
fn golden_baseline_serde_roundtrip() {
    let baseline = GoldenBaseline {
        fixture_id: "f-1".to_string(),
        output_digest: "digest-abc".to_string(),
        source_run_id: "run-xyz".to_string(),
    };
    let json = serde_json::to_string(&baseline).expect("serialize");
    let recovered: GoldenBaseline = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, baseline);
}

// ---------------------------------------------------------------------------
// Enrichment: SignedGoldenUpdate serde
// ---------------------------------------------------------------------------

#[test]
fn signed_golden_update_serde_roundtrip() {
    let update = SignedGoldenUpdate {
        update_id: "u-1".to_string(),
        fixture_id: "f-1".to_string(),
        previous_digest: "old".to_string(),
        next_digest: "new".to_string(),
        source_run_id: "run-1".to_string(),
        signer: "alice@eng".to_string(),
        signature: "sig:aabbcc".to_string(),
        rationale: "evolution".to_string(),
    };
    let json = serde_json::to_string(&update).expect("serialize");
    let recovered: SignedGoldenUpdate = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, update);
}

// ---------------------------------------------------------------------------
// Enrichment: GoldenVerificationError Display
// ---------------------------------------------------------------------------

#[test]
fn golden_verification_error_display_missing_baseline() {
    let err = GoldenVerificationError::MissingBaseline {
        fixture_id: "test-fixture".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("missing golden baseline"));
    assert!(msg.contains("test-fixture"));
}

#[test]
fn golden_verification_error_display_digest_mismatch() {
    let err = GoldenVerificationError::DigestMismatch {
        expected: "aaa".to_string(),
        actual: "bbb".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("golden digest mismatch"));
    assert!(msg.contains("aaa"));
    assert!(msg.contains("bbb"));
}

#[test]
fn golden_verification_error_display_invalid_baseline() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
    let err = GoldenVerificationError::InvalidBaseline(io_err);
    let msg = err.to_string();
    assert!(msg.contains("invalid golden baseline"));
}

// ---------------------------------------------------------------------------
// Enrichment: GoldenStore write_signed_update validation
// ---------------------------------------------------------------------------

#[test]
fn golden_store_write_signed_update_rejects_empty_signer() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();
    let baseline_run = runner.run_fixture(&fixture).expect("baseline");

    let root = test_temp_dir("golden-empty-signer");
    let store = GoldenStore::new(root.join("golden")).expect("store");
    store.write_baseline(&baseline_run).expect("write baseline");

    let err = store
        .write_signed_update(&baseline_run, "", "sig:abc", "reason")
        .expect_err("empty signer");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn golden_store_write_signed_update_rejects_empty_signature() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();
    let baseline_run = runner.run_fixture(&fixture).expect("baseline");

    let root = test_temp_dir("golden-empty-sig");
    let store = GoldenStore::new(root.join("golden")).expect("store");
    store.write_baseline(&baseline_run).expect("write baseline");

    let err = store
        .write_signed_update(&baseline_run, "alice", "", "reason")
        .expect_err("empty signature");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn golden_store_write_signed_update_rejects_empty_rationale() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();
    let baseline_run = runner.run_fixture(&fixture).expect("baseline");

    let root = test_temp_dir("golden-empty-rationale");
    let store = GoldenStore::new(root.join("golden")).expect("store");
    store.write_baseline(&baseline_run).expect("write baseline");

    let err = store
        .write_signed_update(&baseline_run, "alice", "sig:abc", "  ")
        .expect_err("empty rationale");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

// ---------------------------------------------------------------------------
// Enrichment: LogAssertionError Display
// ---------------------------------------------------------------------------

#[test]
fn log_assertion_error_display_is_nonempty() {
    let err = LogAssertionError {
        missing: vec![LogExpectation {
            component: "scheduler".to_string(),
            event: "tick".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        }],
    };
    let msg = err.to_string();
    assert!(!msg.is_empty());
}

#[test]
fn assert_structured_logs_empty_expectations_always_pass() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();
    let run = runner.run_fixture(&fixture).expect("run");
    assert!(assert_structured_logs(&run.events, &[]).is_ok());
}

// ---------------------------------------------------------------------------
// Enrichment: RunManifest serde
// ---------------------------------------------------------------------------

#[test]
fn run_manifest_serde_roundtrip() {
    let manifest = RunManifest {
        fixture_id: "f-1".to_string(),
        run_id: "run-1".to_string(),
        seed: 42,
        event_count: 3,
        output_digest: "digest-xyz".to_string(),
        replay_pointer: "replay://run-1".to_string(),
        model_snapshot_pointer: "model://snapshot/f-1/seed/42".to_string(),
        artifact_schema_version: 1,
        environment_fingerprint: ReplayEnvironmentFingerprint::local(),
    };
    let json = serde_json::to_string(&manifest).expect("serialize");
    let recovered: RunManifest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, manifest);
}

// ---------------------------------------------------------------------------
// Enrichment: RunReport
// ---------------------------------------------------------------------------

#[test]
fn run_report_serde_roundtrip() {
    let report = RunReport {
        fixture_id: "f-1".to_string(),
        run_id: "run-1".to_string(),
        pass: true,
        event_count: 5,
        output_digest: "digest-000".to_string(),
        first_error_code: None,
    };
    let json = serde_json::to_string(&report).expect("serialize");
    let recovered: RunReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, report);
}

#[test]
fn run_report_from_result_pass_case() {
    let runner = DeterministicRunner::default();
    let fixture = non_error_fixture("pass-fixture", 1, 3);
    let run = runner.run_fixture(&fixture).expect("run");
    let report = RunReport::from_result(&run);
    assert!(report.pass);
    assert!(report.first_error_code.is_none());
    assert_eq!(report.event_count, 3);
}

#[test]
fn run_report_to_markdown_pass_contains_pass_status() {
    let runner = DeterministicRunner::default();
    let fixture = non_error_fixture("pass-md", 1, 2);
    let run = runner.run_fixture(&fixture).expect("run");
    let report = RunReport::from_result(&run);
    let md = report.to_markdown();
    assert!(md.contains("pass"));
    assert!(md.contains("# E2E Run Report"));
    assert!(md.contains("none")); // first_error_code is "none"
}

// ---------------------------------------------------------------------------
// Enrichment: ArtifactCompletenessReport serde
// ---------------------------------------------------------------------------

#[test]
fn artifact_completeness_report_serde_roundtrip() {
    let report = ArtifactCompletenessReport {
        complete: true,
        missing_files: vec![],
        diagnostics: vec![],
        event_count: 5,
        linkage_count: 5,
    };
    let json = serde_json::to_string(&report).expect("serialize");
    let recovered: ArtifactCompletenessReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, report);
}

#[test]
fn artifact_completeness_report_serde_roundtrip_incomplete() {
    let report = ArtifactCompletenessReport {
        complete: false,
        missing_files: vec!["manifest".to_string()],
        diagnostics: vec!["manifest parse error: bad json".to_string()],
        event_count: 0,
        linkage_count: 0,
    };
    let json = serde_json::to_string(&report).expect("serialize");
    let recovered: ArtifactCompletenessReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, report);
}

// ---------------------------------------------------------------------------
// Enrichment: ScenarioClass as_str individual variants
// ---------------------------------------------------------------------------

#[test]
fn scenario_class_as_str_baseline() {
    assert_eq!(ScenarioClass::Baseline.as_str(), "baseline");
}

#[test]
fn scenario_class_as_str_differential() {
    assert_eq!(ScenarioClass::Differential.as_str(), "differential");
}

#[test]
fn scenario_class_as_str_chaos() {
    assert_eq!(ScenarioClass::Chaos.as_str(), "chaos");
}

#[test]
fn scenario_class_as_str_stress() {
    assert_eq!(ScenarioClass::Stress.as_str(), "stress");
}

#[test]
fn scenario_class_as_str_fault_injection() {
    assert_eq!(ScenarioClass::FaultInjection.as_str(), "fault_injection");
}

#[test]
fn scenario_class_as_str_cross_arch() {
    assert_eq!(ScenarioClass::CrossArch.as_str(), "cross_arch");
}

// ---------------------------------------------------------------------------
// Enrichment: ScenarioClass Display/Debug
// ---------------------------------------------------------------------------

#[test]
fn scenario_class_debug_all_variants_nonempty() {
    for class in ScenarioClass::ALL {
        let dbg = format!("{class:?}");
        assert!(!dbg.is_empty(), "debug should be nonempty for {class:?}");
    }
}

// ---------------------------------------------------------------------------
// Enrichment: RGC_ADVANCED_E2E_SCENARIO_SCHEMA_VERSION constant
// ---------------------------------------------------------------------------

#[test]
fn rgc_advanced_e2e_scenario_schema_version_is_nonempty() {
    assert!(!RGC_ADVANCED_E2E_SCENARIO_SCHEMA_VERSION.is_empty());
    assert!(RGC_ADVANCED_E2E_SCENARIO_SCHEMA_VERSION.starts_with("franken-engine."));
}

// ---------------------------------------------------------------------------
// Enrichment: ScenarioMatrixEntry serde
// ---------------------------------------------------------------------------

#[test]
fn scenario_matrix_entry_serde_roundtrip() {
    let entry = ScenarioMatrixEntry {
        scenario_id: "test-scenario".to_string(),
        scenario_class: ScenarioClass::Baseline,
        fixture: non_error_fixture("serde-test", 1, 2),
        baseline_scenario_id: None,
        chaos_profile: None,
        unit_anchor_ids: vec!["anchor-1".to_string()],
        target_arch: None,
        worker_pool: Some("pool-1".to_string()),
    };
    let json = serde_json::to_string(&entry).expect("serialize");
    let recovered: ScenarioMatrixEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, entry);
}

// ---------------------------------------------------------------------------
// Enrichment: ScenarioArtifactPaths serde
// ---------------------------------------------------------------------------

#[test]
fn scenario_artifact_paths_serde_roundtrip() {
    let paths = ScenarioArtifactPaths {
        manifest: "run-1/manifest.json".to_string(),
        events: "run-1/events.jsonl".to_string(),
        evidence_linkage: "run-1/evidence_linkage.json".to_string(),
        report_json: "run-1/report.json".to_string(),
        report_markdown: "run-1/report.md".to_string(),
    };
    let json = serde_json::to_string(&paths).expect("serialize");
    let recovered: ScenarioArtifactPaths = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, paths);
}

// ---------------------------------------------------------------------------
// Enrichment: ScenarioMatrixReport serde
// ---------------------------------------------------------------------------

#[test]
fn scenario_matrix_report_serde_roundtrip() {
    let report = ScenarioMatrixReport {
        schema_version: "v2".to_string(),
        summary_id: "sum-1".to_string(),
        total_scenarios: 2,
        pass_scenarios: 1,
        fail_scenarios: 1,
        scenario_packs: vec![],
    };
    let json = serde_json::to_string(&report).expect("serialize");
    let recovered: ScenarioMatrixReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, report);
}

// ---------------------------------------------------------------------------
// Enrichment: select_rgc_advanced_scenario_matrix additional filters
// ---------------------------------------------------------------------------

#[test]
fn select_rgc_advanced_scenario_matrix_stress_only() {
    let stress = select_rgc_advanced_scenario_matrix(&[ScenarioClass::Stress], true);
    assert_eq!(stress.len(), 1);
    assert_eq!(stress[0].scenario_class, ScenarioClass::Stress);
}

#[test]
fn select_rgc_advanced_scenario_matrix_baseline_only() {
    let baseline = select_rgc_advanced_scenario_matrix(&[ScenarioClass::Baseline], true);
    assert_eq!(baseline.len(), 1);
    assert_eq!(baseline[0].scenario_class, ScenarioClass::Baseline);
}

#[test]
fn select_rgc_advanced_scenario_matrix_cross_arch_only() {
    let cross = select_rgc_advanced_scenario_matrix(&[ScenarioClass::CrossArch], true);
    assert_eq!(cross.len(), 1);
    assert_eq!(cross[0].scenario_class, ScenarioClass::CrossArch);
    assert!(cross[0].target_arch.is_some());
}

#[test]
fn select_rgc_advanced_scenario_matrix_fault_injection_excluded() {
    let all_no_fault = select_rgc_advanced_scenario_matrix(&[], false);
    assert!(
        all_no_fault
            .iter()
            .all(|s| s.scenario_class != ScenarioClass::FaultInjection)
    );
}

#[test]
fn select_rgc_advanced_scenario_matrix_multiple_classes() {
    let selected =
        select_rgc_advanced_scenario_matrix(&[ScenarioClass::Baseline, ScenarioClass::Chaos], true);
    assert_eq!(selected.len(), 2);
    assert!(
        selected
            .iter()
            .any(|s| s.scenario_class == ScenarioClass::Baseline)
    );
    assert!(
        selected
            .iter()
            .any(|s| s.scenario_class == ScenarioClass::Chaos)
    );
}

// ---------------------------------------------------------------------------
// Enrichment: rgc_advanced_scenario_matrix_registry structure
// ---------------------------------------------------------------------------

#[test]
fn rgc_advanced_scenario_matrix_registry_sorted_by_id() {
    let scenarios = rgc_advanced_scenario_matrix_registry();
    let ids: Vec<&str> = scenarios.iter().map(|s| s.scenario_id.as_str()).collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted, "registry must be sorted by scenario_id");
}

#[test]
fn rgc_advanced_scenario_matrix_registry_all_have_unit_anchors() {
    let scenarios = rgc_advanced_scenario_matrix_registry();
    for s in &scenarios {
        assert!(
            !s.unit_anchor_ids.is_empty(),
            "scenario {} must have unit anchors",
            s.scenario_id
        );
    }
}

#[test]
fn rgc_advanced_scenario_matrix_registry_differential_has_baseline_id() {
    let scenarios = rgc_advanced_scenario_matrix_registry();
    for s in &scenarios {
        if s.scenario_class == ScenarioClass::Differential {
            assert!(
                s.baseline_scenario_id.is_some(),
                "differential {} must have baseline_scenario_id",
                s.scenario_id
            );
        }
    }
}

#[test]
fn rgc_advanced_scenario_matrix_registry_chaos_has_profile() {
    let scenarios = rgc_advanced_scenario_matrix_registry();
    for s in &scenarios {
        if s.scenario_class == ScenarioClass::Chaos {
            assert!(
                s.chaos_profile.is_some(),
                "chaos {} must have chaos_profile",
                s.scenario_id
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Enrichment: run_scenario_matrix validation
// ---------------------------------------------------------------------------

#[test]
fn run_scenario_matrix_rejects_empty_scenario_id() {
    let runner = DeterministicRunner::default();
    let root = test_temp_dir("scenario-matrix-empty-id");
    let collector = ArtifactCollector::new(root.join("artifacts")).expect("collector");
    let scenarios = vec![ScenarioMatrixEntry {
        scenario_id: "".to_string(),
        scenario_class: ScenarioClass::Baseline,
        fixture: non_error_fixture("empty-id", 1, 2),
        baseline_scenario_id: None,
        chaos_profile: None,
        unit_anchor_ids: vec!["anchor".to_string()],
        target_arch: None,
        worker_pool: None,
    }];
    let err = run_scenario_matrix(&runner, &collector, &scenarios).expect_err("empty scenario_id");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

// ---------------------------------------------------------------------------
// Enrichment: FixtureStore edge cases
// ---------------------------------------------------------------------------

#[test]
fn fixture_store_save_rejects_invalid_fixture() {
    let root = test_temp_dir("fixture-store-invalid");
    let store = FixtureStore::new(&root).expect("store");
    let mut fixture = sample_fixture();
    fixture.fixture_id.clear();
    let err = store.save_fixture(&fixture).expect_err("invalid fixture");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn fixture_store_load_nonexistent_file_fails() {
    let root = test_temp_dir("fixture-store-missing");
    let store = FixtureStore::new(&root).expect("store");
    let err = store
        .load_fixture(root.join("nonexistent.json"))
        .expect_err("missing file");
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

// ---------------------------------------------------------------------------
// Enrichment: DeterministicRunner with custom config
// ---------------------------------------------------------------------------

#[test]
fn deterministic_runner_custom_trace_prefix() {
    let runner = DeterministicRunner {
        config: DeterministicRunnerConfig {
            trace_prefix: "custom".to_string(),
        },
    };
    let fixture = non_error_fixture("custom-trace", 1, 2);
    let run = runner.run_fixture(&fixture).expect("run");
    assert!(
        run.events[0].trace_id.starts_with("custom-"),
        "trace_id should use custom prefix"
    );
}

#[test]
fn deterministic_runner_run_fixture_produces_correct_event_count() {
    let runner = DeterministicRunner::default();
    let fixture = non_error_fixture("count-test", 1, 7);
    let run = runner.run_fixture(&fixture).expect("run");
    assert_eq!(run.events.len(), 7);
    assert_eq!(run.random_transcript.len(), 7);
}

#[test]
fn deterministic_runner_events_have_sequential_sequences() {
    let runner = DeterministicRunner::default();
    let fixture = non_error_fixture("seq-test", 1, 5);
    let run = runner.run_fixture(&fixture).expect("run");
    for (idx, event) in run.events.iter().enumerate() {
        assert_eq!(event.sequence, idx as u64);
    }
}

#[test]
fn deterministic_runner_error_step_emits_error_outcome() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture(); // second step has error_code
    let run = runner.run_fixture(&fixture).expect("run");
    assert_eq!(run.events[1].outcome, "error");
    assert_eq!(run.events[1].error_code.as_deref(), Some("FE-E2E-0007"));
}

#[test]
fn deterministic_runner_ok_step_has_ok_outcome() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();
    let run = runner.run_fixture(&fixture).expect("run");
    assert_eq!(run.events[0].outcome, "ok");
    assert!(run.events[0].error_code.is_none());
}

// ---------------------------------------------------------------------------
// Enrichment: ArtifactCollector root() accessor
// ---------------------------------------------------------------------------

#[test]
fn artifact_collector_root_returns_configured_path() {
    let root = test_temp_dir("collector-root");
    let collector = ArtifactCollector::new(&root).expect("collector");
    assert_eq!(collector.root(), root.as_path());
}

// ---------------------------------------------------------------------------
// Enrichment: audit_collected_artifacts with non-existent paths
// ---------------------------------------------------------------------------

#[test]
fn audit_collected_artifacts_reports_missing_files() {
    let root = test_temp_dir("audit-missing");
    let artifacts = e2e_harness::CollectedArtifacts {
        manifest_path: root.join("no-manifest.json"),
        events_path: root.join("no-events.jsonl"),
        evidence_linkage_path: root.join("no-linkage.json"),
        report_json_path: root.join("no-report.json"),
        report_markdown_path: root.join("no-report.md"),
    };
    let completeness = audit_collected_artifacts(&artifacts);
    assert!(!completeness.complete);
    assert!(!completeness.missing_files.is_empty());
}

// ---------------------------------------------------------------------------
// Enrichment: ScenarioEvidencePack serde (minimal)
// ---------------------------------------------------------------------------

#[test]
fn scenario_evidence_pack_serde_roundtrip() {
    let pack = ScenarioEvidencePack {
        scenario_id: "test-001".to_string(),
        scenario_class: ScenarioClass::Baseline,
        baseline_scenario_id: None,
        chaos_profile: None,
        unit_anchor_ids: vec!["unit.test".to_string()],
        target_arch: None,
        worker_pool: None,
        fixture_id: "fix-1".to_string(),
        run_id: "run-1".to_string(),
        output_digest: "digest".to_string(),
        event_count: 3,
        pass: true,
        first_error_code: None,
        replay_pointer: "replay://run-1".to_string(),
        artifact_paths: ScenarioArtifactPaths {
            manifest: "m.json".to_string(),
            events: "e.jsonl".to_string(),
            evidence_linkage: "el.json".to_string(),
            report_json: "r.json".to_string(),
            report_markdown: "r.md".to_string(),
        },
        completeness: ArtifactCompletenessReport {
            complete: true,
            missing_files: vec![],
            diagnostics: vec![],
            event_count: 3,
            linkage_count: 3,
        },
    };
    let json = serde_json::to_string(&pack).expect("serialize");
    let recovered: ScenarioEvidencePack = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, pack);
}
