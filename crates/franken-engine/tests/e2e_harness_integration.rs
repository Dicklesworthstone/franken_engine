//! Integration tests for `frankenengine_engine::e2e_harness`.
//!
//! Exercises the deterministic E2E harness from the public crate boundary:
//! VirtualClock, DeterministicRng, TestFixture, DeterministicRunner,
//! replay verification, structured log assertions, counterfactual analysis,
//! evidence linkage, cross-machine replay diagnosis, and fixture migration.

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

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::e2e_harness::{
    ArtifactCollector, CounterfactualDelta, DeterministicRng, DeterministicRunner,
    DeterministicRunnerConfig, EvidenceLinkageRecord, ExpectedEvent, FixtureMigrationError,
    FixtureValidationError, GoldenBaseline, LogExpectation, ReplayEnvironmentFingerprint,
    ReplayInputError, ReplayInputErrorCode, ReplayMismatchKind, ReplayVerification, ScenarioClass,
    ScenarioStep, SignedGoldenUpdate, TestFixture, VirtualClock, assert_structured_logs,
    build_evidence_linkage, compare_counterfactual, diagnose_cross_machine_replay,
    evaluate_replay_performance, parse_fixture_with_migration,
    rgc_advanced_scenario_matrix_registry, run_scenario_matrix,
    select_rgc_advanced_scenario_matrix, validate_replay_input, verify_replay,
};

// ── Helpers ─────────────────────────────────────────────────────────────

fn make_step(component: &str, event: &str, advance: u64) -> ScenarioStep {
    ScenarioStep {
        component: component.to_string(),
        event: event.to_string(),
        advance_micros: advance,
        metadata: BTreeMap::new(),
    }
}

fn make_valid_fixture() -> TestFixture {
    TestFixture {
        fixture_id: "test-fixture-1".to_string(),
        fixture_version: TestFixture::CURRENT_VERSION,
        seed: 42,
        virtual_time_start_micros: 1_000_000,
        policy_id: "policy-default".to_string(),
        steps: vec![
            make_step("router", "route_request", 100),
            make_step("scheduler", "schedule_task", 200),
            make_step("executor", "execute_cell", 300),
        ],
        expected_events: vec![],
        determinism_check: true,
    }
}

fn make_runner() -> DeterministicRunner {
    DeterministicRunner {
        config: DeterministicRunnerConfig::default(),
    }
}

fn temp_artifact_dir(suffix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("franken-engine-e2e-int-{suffix}-{nanos}"));
    fs::create_dir_all(&path).expect("temp artifact dir");
    path
}

// ── VirtualClock ────────────────────────────────────────────────────────

#[test]
fn virtual_clock_new_and_read() {
    let clock = VirtualClock::new(1_000);
    assert_eq!(clock.now_micros(), 1_000);
}

#[test]
fn virtual_clock_advance() {
    let mut clock = VirtualClock::new(0);
    clock.advance(500);
    assert_eq!(clock.now_micros(), 500);
    clock.advance(1_000);
    assert_eq!(clock.now_micros(), 1_500);
}

#[test]
fn virtual_clock_advance_saturates() {
    let mut clock = VirtualClock::new(u64::MAX - 10);
    clock.advance(100);
    assert_eq!(clock.now_micros(), u64::MAX);
}

#[test]
fn virtual_clock_serde_roundtrip() {
    let clock = VirtualClock::new(42_000);
    let json = serde_json::to_string(&clock).unwrap();
    let back: VirtualClock = serde_json::from_str(&json).unwrap();
    assert_eq!(back.now_micros(), 42_000);
}

// ── DeterministicRng ────────────────────────────────────────────────────

#[test]
fn rng_seeded_deterministic() {
    let mut rng1 = DeterministicRng::seeded(123);
    let mut rng2 = DeterministicRng::seeded(123);
    for _ in 0..100 {
        assert_eq!(rng1.next_u64(), rng2.next_u64());
    }
}

#[test]
fn rng_different_seeds_differ() {
    let mut rng1 = DeterministicRng::seeded(1);
    let mut rng2 = DeterministicRng::seeded(2);
    // Very unlikely all 10 match with different seeds
    let same = (0..10).all(|_| rng1.next_u64() == rng2.next_u64());
    assert!(!same);
}

#[test]
fn rng_zero_seed_does_not_produce_all_zeros() {
    let mut rng = DeterministicRng::seeded(0);
    let vals: Vec<u64> = (0..10).map(|_| rng.next_u64()).collect();
    assert!(vals.iter().any(|&v| v != 0));
}

#[test]
fn rng_serde_roundtrip() {
    let rng = DeterministicRng::seeded(999);
    let json = serde_json::to_string(&rng).unwrap();
    let back: DeterministicRng = serde_json::from_str(&json).unwrap();
    assert_eq!(rng, back);
}

// ── TestFixture ─────────────────────────────────────────────────────────

#[test]
fn fixture_validate_ok() {
    let fixture = make_valid_fixture();
    assert!(fixture.validate().is_ok());
}

#[test]
fn fixture_validate_missing_id() {
    let mut fixture = make_valid_fixture();
    fixture.fixture_id = "".to_string();
    assert!(matches!(
        fixture.validate(),
        Err(FixtureValidationError::MissingFixtureId)
    ));
}

#[test]
fn fixture_validate_missing_policy() {
    let mut fixture = make_valid_fixture();
    fixture.policy_id = "  ".to_string();
    assert!(matches!(
        fixture.validate(),
        Err(FixtureValidationError::MissingPolicyId)
    ));
}

#[test]
fn fixture_validate_no_steps() {
    let mut fixture = make_valid_fixture();
    fixture.steps.clear();
    assert!(matches!(
        fixture.validate(),
        Err(FixtureValidationError::MissingSteps)
    ));
}

#[test]
fn fixture_validate_bad_version() {
    let mut fixture = make_valid_fixture();
    fixture.fixture_version = 99;
    assert!(matches!(
        fixture.validate(),
        Err(FixtureValidationError::UnsupportedVersion { .. })
    ));
}

#[test]
fn fixture_validate_empty_component() {
    let mut fixture = make_valid_fixture();
    fixture.steps[1].component = "".to_string();
    assert!(matches!(
        fixture.validate(),
        Err(FixtureValidationError::InvalidStep { index: 1, .. })
    ));
}

#[test]
fn fixture_validate_empty_event() {
    let mut fixture = make_valid_fixture();
    fixture.steps[0].event = "  ".to_string();
    assert!(matches!(
        fixture.validate(),
        Err(FixtureValidationError::InvalidStep { index: 0, .. })
    ));
}

#[test]
fn fixture_serde_roundtrip() {
    let fixture = make_valid_fixture();
    let json = serde_json::to_string(&fixture).unwrap();
    let back: TestFixture = serde_json::from_str(&json).unwrap();
    assert_eq!(back, fixture);
}

// ── FixtureValidationError ──────────────────────────────────────────────

#[test]
fn fixture_validation_error_display() {
    let err = FixtureValidationError::MissingFixtureId;
    assert!(format!("{}", err).contains("fixture_id"));

    let err = FixtureValidationError::UnsupportedVersion {
        expected: 1,
        actual: 99,
    };
    let s = format!("{}", err);
    assert!(s.contains("99"));
}

// ── DeterministicRunner ─────────────────────────────────────────────────

#[test]
fn runner_runs_fixture_ok() {
    let runner = make_runner();
    let fixture = make_valid_fixture();
    let result = runner.run_fixture(&fixture).unwrap();
    assert_eq!(result.fixture_id, "test-fixture-1");
    assert_eq!(result.seed, 42);
    assert_eq!(result.events.len(), 3);
    assert_eq!(result.random_transcript.len(), 3);
    assert!(!result.output_digest.is_empty());
}

#[test]
fn runner_events_have_correct_components() {
    let runner = make_runner();
    let fixture = make_valid_fixture();
    let result = runner.run_fixture(&fixture).unwrap();
    assert_eq!(result.events[0].component, "router");
    assert_eq!(result.events[1].component, "scheduler");
    assert_eq!(result.events[2].component, "executor");
}

#[test]
fn runner_events_have_sequential_sequences() {
    let runner = make_runner();
    let fixture = make_valid_fixture();
    let result = runner.run_fixture(&fixture).unwrap();
    for (i, event) in result.events.iter().enumerate() {
        assert_eq!(event.sequence, i as u64);
    }
}

#[test]
fn runner_virtual_time_advances() {
    let runner = make_runner();
    let fixture = make_valid_fixture();
    let result = runner.run_fixture(&fixture).unwrap();
    assert_eq!(result.start_virtual_time_micros, 1_000_000);
    // 1_000_000 + 100 + 200 + 300 = 1_000_600
    assert_eq!(result.end_virtual_time_micros, 1_000_600);
}

#[test]
fn runner_deterministic_across_runs() {
    let runner = make_runner();
    let fixture = make_valid_fixture();
    let r1 = runner.run_fixture(&fixture).unwrap();
    let r2 = runner.run_fixture(&fixture).unwrap();
    assert_eq!(r1.output_digest, r2.output_digest);
    assert_eq!(r1.random_transcript, r2.random_transcript);
    assert_eq!(r1.events, r2.events);
}

#[test]
fn runner_rejects_invalid_fixture() {
    let runner = make_runner();
    let mut fixture = make_valid_fixture();
    fixture.fixture_id = "".to_string();
    assert!(runner.run_fixture(&fixture).is_err());
}

#[test]
fn runner_error_metadata_produces_error_event() {
    let runner = make_runner();
    let mut fixture = make_valid_fixture();
    fixture.steps[1]
        .metadata
        .insert("error_code".to_string(), "E001".to_string());
    let result = runner.run_fixture(&fixture).unwrap();
    assert_eq!(result.events[1].outcome, "error");
    assert_eq!(result.events[1].error_code, Some("E001".to_string()));
}

#[test]
fn runner_outcome_metadata_overrides_default() {
    let runner = make_runner();
    let mut fixture = make_valid_fixture();
    fixture.steps[0]
        .metadata
        .insert("outcome".to_string(), "skipped".to_string());
    let result = runner.run_fixture(&fixture).unwrap();
    assert_eq!(result.events[0].outcome, "skipped");
}

#[test]
fn runner_trace_prefix_in_config() {
    let runner = DeterministicRunner {
        config: DeterministicRunnerConfig {
            trace_prefix: "custom-prefix".to_string(),
        },
    };
    let fixture = make_valid_fixture();
    let result = runner.run_fixture(&fixture).unwrap();
    assert!(result.events[0].trace_id.starts_with("custom-prefix-"));
}

// ── verify_replay ───────────────────────────────────────────────────────

#[test]
fn replay_verification_identical_runs_match() {
    let runner = make_runner();
    let fixture = make_valid_fixture();
    let r1 = runner.run_fixture(&fixture).unwrap();
    let r2 = runner.run_fixture(&fixture).unwrap();
    let v = verify_replay(&r1, &r2);
    assert!(v.matches);
    assert!(v.reason.is_none());
    assert!(v.mismatch_kind.is_none());
}

#[test]
fn replay_verification_different_digest() {
    let runner = make_runner();
    let fixture = make_valid_fixture();
    let r1 = runner.run_fixture(&fixture).unwrap();
    let mut r2 = runner.run_fixture(&fixture).unwrap();
    r2.output_digest = "tampered".to_string();
    let v = verify_replay(&r1, &r2);
    assert!(!v.matches);
    assert_eq!(v.mismatch_kind, Some(ReplayMismatchKind::Digest));
}

#[test]
fn replay_verification_different_events() {
    let runner = make_runner();
    let fixture = make_valid_fixture();
    let r1 = runner.run_fixture(&fixture).unwrap();
    let mut r2 = runner.run_fixture(&fixture).unwrap();
    r2.output_digest = r1.output_digest.clone(); // same digest
    r2.events[1].outcome = "diverged".to_string();
    let v = verify_replay(&r1, &r2);
    assert!(!v.matches);
    assert_eq!(v.mismatch_kind, Some(ReplayMismatchKind::EventStream));
    assert_eq!(v.diverged_event_sequence, Some(1));
}

// ── evaluate_replay_performance ─────────────────────────────────────────

#[test]
fn replay_performance_faster_than_realtime() {
    let runner = make_runner();
    let fixture = make_valid_fixture();
    let result = runner.run_fixture(&fixture).unwrap();
    // virtual_duration = 600, wall = 100 → faster
    let perf = evaluate_replay_performance(&result, 100);
    assert!(perf.faster_than_realtime);
    assert!(perf.speedup_milli > 1000);
}

#[test]
fn replay_performance_slower_than_realtime() {
    let runner = make_runner();
    let fixture = make_valid_fixture();
    let result = runner.run_fixture(&fixture).unwrap();
    // virtual_duration = 600, wall = 10_000 → slower
    let perf = evaluate_replay_performance(&result, 10_000);
    assert!(!perf.faster_than_realtime);
}

#[test]
fn replay_performance_zero_wall_time_max_speedup() {
    let runner = make_runner();
    let fixture = make_valid_fixture();
    let result = runner.run_fixture(&fixture).unwrap();
    let perf = evaluate_replay_performance(&result, 0);
    assert_eq!(perf.speedup_milli, u64::MAX);
}

// ── assert_structured_logs ──────────────────────────────────────────────

#[test]
fn log_assertion_all_present() {
    let runner = make_runner();
    let fixture = make_valid_fixture();
    let result = runner.run_fixture(&fixture).unwrap();
    let expectations = vec![LogExpectation {
        component: "router".to_string(),
        event: "route_request".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    }];
    assert!(assert_structured_logs(&result.events, &expectations).is_ok());
}

#[test]
fn log_assertion_missing_event() {
    let runner = make_runner();
    let fixture = make_valid_fixture();
    let result = runner.run_fixture(&fixture).unwrap();
    let expectations = vec![LogExpectation {
        component: "nonexistent".to_string(),
        event: "missing".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    }];
    let err = assert_structured_logs(&result.events, &expectations).unwrap_err();
    assert_eq!(err.missing.len(), 1);
    assert!(format!("{}", err).contains("1"));
}

// ── build_evidence_linkage ──────────────────────────────────────────────

#[test]
fn evidence_linkage_rows_match_events() {
    let runner = make_runner();
    let fixture = make_valid_fixture();
    let result = runner.run_fixture(&fixture).unwrap();
    let linkage = build_evidence_linkage(&result.events);
    assert_eq!(linkage.len(), result.events.len());
    for (i, row) in linkage.iter().enumerate() {
        assert_eq!(row.event_sequence, i as u64);
        assert!(!row.evidence_hash.is_empty());
    }
}

#[test]
fn evidence_linkage_deterministic() {
    let runner = make_runner();
    let fixture = make_valid_fixture();
    let r1 = runner.run_fixture(&fixture).unwrap();
    let r2 = runner.run_fixture(&fixture).unwrap();
    let l1 = build_evidence_linkage(&r1.events);
    let l2 = build_evidence_linkage(&r2.events);
    for (a, b) in l1.iter().zip(l2.iter()) {
        assert_eq!(a.evidence_hash, b.evidence_hash);
    }
}

// ── validate_replay_input ───────────────────────────────────────────────

#[test]
fn validate_replay_input_ok() {
    let runner = make_runner();
    let fixture = make_valid_fixture();
    let result = runner.run_fixture(&fixture).unwrap();
    assert!(validate_replay_input(&result, Some("snapshot-ptr")).is_ok());
}

#[test]
fn validate_replay_input_missing_snapshot() {
    let runner = make_runner();
    let fixture = make_valid_fixture();
    let result = runner.run_fixture(&fixture).unwrap();
    let err = validate_replay_input(&result, None).unwrap_err();
    assert_eq!(err.code, ReplayInputErrorCode::MissingModelSnapshot);
}

#[test]
fn validate_replay_input_empty_snapshot() {
    let runner = make_runner();
    let fixture = make_valid_fixture();
    let result = runner.run_fixture(&fixture).unwrap();
    let err = validate_replay_input(&result, Some("  ")).unwrap_err();
    assert_eq!(err.code, ReplayInputErrorCode::MissingModelSnapshot);
}

#[test]
fn validate_replay_input_corrupted_digest() {
    let runner = make_runner();
    let fixture = make_valid_fixture();
    let mut result = runner.run_fixture(&fixture).unwrap();
    result.output_digest = "corrupted".to_string();
    let err = validate_replay_input(&result, Some("ptr")).unwrap_err();
    assert_eq!(err.code, ReplayInputErrorCode::CorruptedTranscript);
}

#[test]
fn validate_replay_input_transcript_length_mismatch() {
    let runner = make_runner();
    let fixture = make_valid_fixture();
    let mut result = runner.run_fixture(&fixture).unwrap();
    result.random_transcript.push(999);
    let err = validate_replay_input(&result, Some("ptr")).unwrap_err();
    assert_eq!(err.code, ReplayInputErrorCode::CorruptedTranscript);
}

#[test]
fn replay_input_error_display() {
    let err = ReplayInputError {
        code: ReplayInputErrorCode::PartialTrace,
        message: "gap at index 5".to_string(),
    };
    let s = format!("{}", err);
    assert!(s.contains("partial_trace"));
    assert!(s.contains("gap at index 5"));
}

// ── diagnose_cross_machine_replay ───────────────────────────────────────

#[test]
fn cross_machine_replay_same_env_matches() {
    let runner = make_runner();
    let fixture = make_valid_fixture();
    let r1 = runner.run_fixture(&fixture).unwrap();
    let r2 = runner.run_fixture(&fixture).unwrap();
    let env = ReplayEnvironmentFingerprint::local();
    let diag = diagnose_cross_machine_replay(&r1, &r2, &env, &env);
    assert!(diag.cross_machine_match);
    assert!(diag.environment_mismatches.is_empty());
    assert!(diag.diagnosis.is_none());
}

#[test]
fn cross_machine_replay_different_env_mismatch_noted() {
    let runner = make_runner();
    let fixture = make_valid_fixture();
    let r1 = runner.run_fixture(&fixture).unwrap();
    let r2 = runner.run_fixture(&fixture).unwrap();
    let env1 = ReplayEnvironmentFingerprint::local();
    let mut env2 = env1.clone();
    env2.os = "windows".to_string();
    let diag = diagnose_cross_machine_replay(&r1, &r2, &env1, &env2);
    // Replay still matches (deterministic), but environment delta noted
    assert!(diag.cross_machine_match);
    assert!(diag.environment_mismatches.contains(&"os".to_string()));
}

// ── compare_counterfactual ──────────────────────────────────────────────

#[test]
fn counterfactual_identical_runs_no_divergence() {
    let runner = make_runner();
    let fixture = make_valid_fixture();
    let r1 = runner.run_fixture(&fixture).unwrap();
    let r2 = runner.run_fixture(&fixture).unwrap();
    let delta = compare_counterfactual(&r1, &r2);
    assert!(!delta.digest_changed);
    assert_eq!(delta.changed_events, 0);
    assert_eq!(delta.diverged_at_sequence, None);
    assert!(!delta.transcript_changed);
}

#[test]
fn counterfactual_different_seed_diverges() {
    let runner = make_runner();
    let f1 = make_valid_fixture();
    let mut f2 = make_valid_fixture();
    f2.seed = 999;
    let r1 = runner.run_fixture(&f1).unwrap();
    let r2 = runner.run_fixture(&f2).unwrap();
    let delta = compare_counterfactual(&r1, &r2);
    assert!(delta.digest_changed);
    assert!(delta.transcript_changed);
}

#[test]
fn counterfactual_different_event_count() {
    let runner = make_runner();
    let f1 = make_valid_fixture();
    let mut f2 = make_valid_fixture();
    f2.steps.push(make_step("extra", "extra_step", 50));
    let r1 = runner.run_fixture(&f1).unwrap();
    let r2 = runner.run_fixture(&f2).unwrap();
    let delta = compare_counterfactual(&r1, &r2);
    assert!(delta.changed_events > 0);
    assert!(!delta.divergence_samples.is_empty());
}

// ── parse_fixture_with_migration ────────────────────────────────────────

#[test]
fn migration_v1_passthrough() {
    let fixture = make_valid_fixture();
    let bytes = serde_json::to_vec(&fixture).unwrap();
    let parsed = parse_fixture_with_migration(&bytes).unwrap();
    assert_eq!(parsed, fixture);
}

#[test]
fn migration_v0_upgrades() {
    let v0 = serde_json::json!({
        "fixture_id": "legacy-1",
        "fixture_version": 0,
        "seed": 42,
        "virtual_time_start_micros": 1000,
        "policy_id": "policy-v0",
        "steps": [{"component": "router", "event": "test"}]
    });
    let bytes = serde_json::to_vec(&v0).unwrap();
    let parsed = parse_fixture_with_migration(&bytes).unwrap();
    assert_eq!(parsed.fixture_version, TestFixture::CURRENT_VERSION);
    assert_eq!(parsed.fixture_id, "legacy-1");
    assert!(parsed.determinism_check);
    assert!(parsed.expected_events.is_empty());
}

#[test]
fn migration_unsupported_version() {
    let bad = serde_json::json!({
        "fixture_id": "bad",
        "fixture_version": 42,
        "seed": 1,
        "virtual_time_start_micros": 0,
        "policy_id": "pol",
        "steps": [{"component": "c", "event": "e"}]
    });
    let bytes = serde_json::to_vec(&bad).unwrap();
    let err = parse_fixture_with_migration(&bytes).unwrap_err();
    assert!(matches!(
        err,
        FixtureMigrationError::UnsupportedVersion { .. }
    ));
}

#[test]
fn migration_invalid_json() {
    let err = parse_fixture_with_migration(b"not json").unwrap_err();
    assert!(matches!(
        err,
        FixtureMigrationError::InvalidFixturePayload { .. }
    ));
}

// ── ReplayEnvironmentFingerprint ────────────────────────────────────────

#[test]
fn environment_fingerprint_local() {
    let fp = ReplayEnvironmentFingerprint::local();
    assert!(!fp.os.is_empty());
    assert!(!fp.architecture.is_empty());
    assert!(fp.pointer_width_bits > 0);
}

#[test]
fn environment_fingerprint_serde_roundtrip() {
    let fp = ReplayEnvironmentFingerprint::local();
    let json = serde_json::to_string(&fp).unwrap();
    let back: ReplayEnvironmentFingerprint = serde_json::from_str(&json).unwrap();
    assert_eq!(back, fp);
}

// ── Serde Roundtrips for Data Types ─────────────────────────────────────

#[test]
fn scenario_step_serde_roundtrip() {
    let step = make_step("comp", "evt", 500);
    let json = serde_json::to_string(&step).unwrap();
    let back: ScenarioStep = serde_json::from_str(&json).unwrap();
    assert_eq!(back, step);
}

#[test]
fn expected_event_serde_roundtrip() {
    let ev = ExpectedEvent {
        component: "router".to_string(),
        event: "route".to_string(),
        outcome: "ok".to_string(),
        error_code: Some("E001".to_string()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: ExpectedEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ev);
}

#[test]
fn golden_baseline_serde_roundtrip() {
    let baseline = GoldenBaseline {
        fixture_id: "f1".to_string(),
        output_digest: "abc123".to_string(),
        source_run_id: "run-1".to_string(),
    };
    let json = serde_json::to_string(&baseline).unwrap();
    let back: GoldenBaseline = serde_json::from_str(&json).unwrap();
    assert_eq!(back, baseline);
}

#[test]
fn signed_golden_update_serde_roundtrip() {
    let update = SignedGoldenUpdate {
        update_id: "u1".to_string(),
        fixture_id: "f1".to_string(),
        previous_digest: "old".to_string(),
        next_digest: "new".to_string(),
        source_run_id: "run-2".to_string(),
        signer: "agent-1".to_string(),
        signature: "sig123".to_string(),
        rationale: "schema evolution".to_string(),
    };
    let json = serde_json::to_string(&update).unwrap();
    let back: SignedGoldenUpdate = serde_json::from_str(&json).unwrap();
    assert_eq!(back, update);
}

#[test]
fn replay_verification_serde_roundtrip() {
    let v = ReplayVerification {
        matches: true,
        expected_digest: "a".to_string(),
        actual_digest: "a".to_string(),
        reason: None,
        mismatch_kind: None,
        diverged_event_sequence: None,
        transcript_mismatch_index: None,
        expected_event_count: 3,
        actual_event_count: 3,
        expected_transcript_len: 3,
        actual_transcript_len: 3,
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: ReplayVerification = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn evidence_linkage_record_serde_roundtrip() {
    let rec = EvidenceLinkageRecord {
        trace_id: "t1".to_string(),
        decision_id: "d1".to_string(),
        policy_id: "p1".to_string(),
        event_sequence: 0,
        evidence_hash: "hash123".to_string(),
    };
    let json = serde_json::to_string(&rec).unwrap();
    let back: EvidenceLinkageRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back, rec);
}

#[test]
fn counterfactual_delta_serde_roundtrip() {
    let delta = CounterfactualDelta {
        baseline_run_id: "b1".to_string(),
        counterfactual_run_id: "c1".to_string(),
        digest_changed: false,
        diverged_at_sequence: None,
        changed_events: 0,
        changed_outcomes: 0,
        changed_error_codes: 0,
        baseline_event_count: 3,
        counterfactual_event_count: 3,
        transcript_changed: false,
        transcript_diverged_at_index: None,
        divergence_samples: vec![],
    };
    let json = serde_json::to_string(&delta).unwrap();
    let back: CounterfactualDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(back, delta);
}

// ── Full Lifecycle ──────────────────────────────────────────────────────

#[test]
fn full_lifecycle_run_validate_replay_compare() {
    let runner = make_runner();
    let fixture = make_valid_fixture();

    // 1. Run fixture
    let result = runner.run_fixture(&fixture).unwrap();
    assert_eq!(result.events.len(), 3);

    // 2. Validate replay input
    assert!(validate_replay_input(&result, Some("model-snapshot")).is_ok());

    // 3. Build evidence linkage
    let linkage = build_evidence_linkage(&result.events);
    assert_eq!(linkage.len(), 3);

    // 4. Second run (deterministic replay)
    let replay = runner.run_fixture(&fixture).unwrap();

    // 5. Verify replay
    let verification = verify_replay(&result, &replay);
    assert!(verification.matches);

    // 6. Performance check
    let perf = evaluate_replay_performance(&result, 100);
    assert!(perf.virtual_duration_micros > 0);

    // 7. Counterfactual with different seed
    let mut alt_fixture = make_valid_fixture();
    alt_fixture.seed = 7777;
    let alt_result = runner.run_fixture(&alt_fixture).unwrap();
    let delta = compare_counterfactual(&result, &alt_result);
    assert!(delta.transcript_changed);
    assert!(delta.digest_changed);
}

#[test]
fn public_advanced_scenario_registry_runs_and_emits_artifact_packs() {
    let runner = make_runner();
    let root = temp_artifact_dir("advanced-scenario-registry");
    let collector = ArtifactCollector::new(root.join("artifacts")).expect("collector");

    let scenarios = rgc_advanced_scenario_matrix_registry();
    let execution = run_scenario_matrix(&runner, &collector, &scenarios).expect("matrix run");

    assert_eq!(execution.report.total_scenarios, 6);
    assert_eq!(execution.report.pass_scenarios, 5);
    assert_eq!(execution.report.fail_scenarios, 1);
    assert!(execution.summary_json_path.exists());
    assert!(execution.summary_markdown_path.exists());

    for pack in &execution.report.scenario_packs {
        assert!(!pack.unit_anchor_ids.is_empty());
        assert!(
            collector
                .root()
                .join(&pack.artifact_paths.manifest)
                .exists()
        );
        assert!(collector.root().join(&pack.artifact_paths.events).exists());
        assert!(
            collector
                .root()
                .join(&pack.artifact_paths.evidence_linkage)
                .exists()
        );
    }
}

#[test]
fn public_advanced_scenario_selector_can_filter_fault_injection() {
    let no_fault = select_rgc_advanced_scenario_matrix(&[], false);
    assert_eq!(no_fault.len(), 5);
    assert!(
        no_fault
            .iter()
            .all(|scenario| scenario.scenario_class != ScenarioClass::FaultInjection)
    );

    let differential_only =
        select_rgc_advanced_scenario_matrix(&[ScenarioClass::Differential], true);
    assert_eq!(differential_only.len(), 1);
    assert_eq!(
        differential_only[0].scenario_class,
        ScenarioClass::Differential
    );
    assert_eq!(
        differential_only[0].baseline_scenario_id.as_deref(),
        Some("rgc-053-runtime-baseline-01")
    );
}
