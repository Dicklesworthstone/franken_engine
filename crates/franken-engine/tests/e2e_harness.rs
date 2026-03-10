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
    ArtifactCollector, DeterministicRng, DeterministicRunner, FixtureStore, GoldenStore,
    GoldenVerificationError, LogExpectation, ReplayEnvironmentFingerprint, ReplayInputErrorCode,
    RunReport, ScenarioClass, ScenarioMatrixEntry, ScenarioStep, TestFixture, VirtualClock,
    assert_structured_logs, audit_collected_artifacts, diagnose_cross_machine_replay,
    rgc_advanced_scenario_matrix_registry, run_scenario_matrix,
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
