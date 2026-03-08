#![forbid(unsafe_code)]
//! Enrichment integration tests for `e2e_harness`.
//!
//! Adds Display exactness, Debug distinctness, JSON field-name stability,
//! serde roundtrips, config defaults, validation edge cases, and
//! deterministic-runner behavior beyond the existing 61 integration tests.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::e2e_harness::{
    CounterfactualDivergenceKind, DeterministicRng, DeterministicRunner, DeterministicRunnerConfig,
    ExpectedEvent, FixtureMigrationError, FixtureValidationError, HarnessEvent, LogExpectation,
    ReplayEnvironmentFingerprint, ReplayInputError, ReplayInputErrorCode, ReplayMismatchKind,
    RunResult, ScenarioStep, TestFixture, VirtualClock, assert_structured_logs,
    build_evidence_linkage, compare_counterfactual, diagnose_cross_machine_replay,
    evaluate_replay_performance, parse_fixture_with_migration, validate_replay_input,
    verify_replay,
};

// ===========================================================================
// helpers
// ===========================================================================

fn minimal_fixture() -> TestFixture {
    TestFixture {
        fixture_id: "fix-1".into(),
        fixture_version: TestFixture::CURRENT_VERSION,
        seed: 42,
        virtual_time_start_micros: 1000,
        policy_id: "pol-1".into(),
        steps: vec![ScenarioStep {
            component: "engine".into(),
            event: "start".into(),
            advance_micros: 100,
            metadata: BTreeMap::new(),
        }],
        expected_events: vec![],
        determinism_check: false,
    }
}

fn run_minimal() -> RunResult {
    let runner = DeterministicRunner::default();
    runner.run_fixture(&minimal_fixture()).unwrap()
}

// ===========================================================================
// 1) TestFixture::CURRENT_VERSION
// ===========================================================================

#[test]
fn test_fixture_current_version_is_one() {
    assert_eq!(TestFixture::CURRENT_VERSION, 1);
}

// ===========================================================================
// 2) VirtualClock — basic ops
// ===========================================================================

#[test]
fn virtual_clock_new_returns_given_value() {
    let c = VirtualClock::new(500);
    assert_eq!(c.now_micros(), 500);
}

#[test]
fn virtual_clock_advance_adds_delta() {
    let mut c = VirtualClock::new(100);
    c.advance(200);
    assert_eq!(c.now_micros(), 300);
}

#[test]
fn virtual_clock_advance_saturates() {
    let mut c = VirtualClock::new(u64::MAX - 10);
    c.advance(100);
    assert_eq!(c.now_micros(), u64::MAX);
}

#[test]
fn virtual_clock_serde_roundtrip() {
    let c = VirtualClock::new(12345);
    let json = serde_json::to_string(&c).unwrap();
    let rt: VirtualClock = serde_json::from_str(&json).unwrap();
    assert_eq!(c, rt);
}

// ===========================================================================
// 3) DeterministicRng — determinism
// ===========================================================================

#[test]
fn deterministic_rng_same_seed_same_sequence() {
    let mut a = DeterministicRng::seeded(42);
    let mut b = DeterministicRng::seeded(42);
    for _ in 0..10 {
        assert_eq!(a.next_u64(), b.next_u64());
    }
}

#[test]
fn deterministic_rng_different_seed_different_sequence() {
    let mut a = DeterministicRng::seeded(42);
    let mut b = DeterministicRng::seeded(99);
    // At least one value should differ in 10 samples
    let different = (0..10).any(|_| a.next_u64() != b.next_u64());
    assert!(different);
}

#[test]
fn deterministic_rng_zero_seed_still_works() {
    let mut rng = DeterministicRng::seeded(0);
    let v = rng.next_u64();
    assert_ne!(v, 0);
}

#[test]
fn deterministic_rng_serde_roundtrip() {
    let rng = DeterministicRng::seeded(777);
    let json = serde_json::to_string(&rng).unwrap();
    let rt: DeterministicRng = serde_json::from_str(&json).unwrap();
    assert_eq!(rng, rt);
}

// ===========================================================================
// 4) DeterministicRunnerConfig — default
// ===========================================================================

#[test]
fn runner_config_default_trace_prefix() {
    let c = DeterministicRunnerConfig::default();
    assert_eq!(c.trace_prefix, "trace");
}

#[test]
fn runner_config_serde_roundtrip() {
    let c = DeterministicRunnerConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let rt: DeterministicRunnerConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, rt);
}

// ===========================================================================
// 5) FixtureValidationError — Display exact values
// ===========================================================================

#[test]
fn validation_error_display_missing_fixture_id() {
    let e = FixtureValidationError::MissingFixtureId;
    assert_eq!(e.to_string(), "fixture_id is required");
}

#[test]
fn validation_error_display_missing_policy_id() {
    let e = FixtureValidationError::MissingPolicyId;
    assert_eq!(e.to_string(), "policy_id is required");
}

#[test]
fn validation_error_display_missing_steps() {
    let e = FixtureValidationError::MissingSteps;
    assert_eq!(e.to_string(), "fixture must contain at least one step");
}

#[test]
fn validation_error_display_unsupported_version() {
    let e = FixtureValidationError::UnsupportedVersion {
        expected: 1,
        actual: 99,
    };
    let s = e.to_string();
    assert!(s.contains("99"), "{s}");
    assert!(s.contains("1"), "{s}");
}

#[test]
fn validation_error_display_invalid_step() {
    let e = FixtureValidationError::InvalidStep {
        index: 3,
        reason: "component is empty".into(),
    };
    let s = e.to_string();
    assert!(s.contains("3"), "{s}");
    assert!(s.contains("component is empty"), "{s}");
}

#[test]
fn validation_error_is_std_error() {
    let e = FixtureValidationError::MissingFixtureId;
    let _: &dyn std::error::Error = &e;
}

// ===========================================================================
// 6) FixtureValidationError — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_fixture_validation_error() {
    let variants = [
        format!("{:?}", FixtureValidationError::MissingFixtureId),
        format!("{:?}", FixtureValidationError::MissingPolicyId),
        format!("{:?}", FixtureValidationError::MissingSteps),
        format!(
            "{:?}",
            FixtureValidationError::UnsupportedVersion {
                expected: 1,
                actual: 2
            }
        ),
        format!(
            "{:?}",
            FixtureValidationError::InvalidStep {
                index: 0,
                reason: "x".into()
            }
        ),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 5);
}

// ===========================================================================
// 7) FixtureMigrationError — Display and serde
// ===========================================================================

#[test]
fn migration_error_display_invalid_payload() {
    let e = FixtureMigrationError::InvalidFixturePayload {
        message: "bad json".into(),
    };
    let s = e.to_string();
    assert!(s.contains("bad json"), "{s}");
}

#[test]
fn migration_error_display_unsupported_version() {
    let e = FixtureMigrationError::UnsupportedVersion {
        expected: 1,
        actual: 5,
    };
    let s = e.to_string();
    assert!(s.contains("5"), "{s}");
}

#[test]
fn migration_error_display_invalid_migrated() {
    let e = FixtureMigrationError::InvalidMigratedFixture {
        message: "bad fixture".into(),
    };
    let s = e.to_string();
    assert!(s.contains("bad fixture"), "{s}");
}

#[test]
fn migration_error_is_std_error() {
    let e = FixtureMigrationError::InvalidFixturePayload {
        message: "x".into(),
    };
    let _: &dyn std::error::Error = &e;
}

#[test]
fn migration_error_serde_roundtrip() {
    let e = FixtureMigrationError::UnsupportedVersion {
        expected: 1,
        actual: 99,
    };
    let json = serde_json::to_string(&e).unwrap();
    let rt: FixtureMigrationError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, rt);
}

// ===========================================================================
// 8) ReplayInputErrorCode — as_str via Display
// ===========================================================================

#[test]
fn replay_input_error_display_contains_code() {
    let e = ReplayInputError {
        code: ReplayInputErrorCode::MissingModelSnapshot,
        message: "no snapshot".into(),
    };
    let s = e.to_string();
    assert!(s.contains("missing_model_snapshot"), "{s}");
    assert!(s.contains("no snapshot"), "{s}");
}

#[test]
fn replay_input_error_is_std_error() {
    let e = ReplayInputError {
        code: ReplayInputErrorCode::PartialTrace,
        message: "gap".into(),
    };
    let _: &dyn std::error::Error = &e;
}

// ===========================================================================
// 9) Debug distinctness — ReplayInputErrorCode
// ===========================================================================

#[test]
fn debug_distinct_replay_input_error_code() {
    let variants = [
        format!("{:?}", ReplayInputErrorCode::MissingModelSnapshot),
        format!("{:?}", ReplayInputErrorCode::PartialTrace),
        format!("{:?}", ReplayInputErrorCode::CorruptedTranscript),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

// ===========================================================================
// 10) Debug distinctness — ReplayMismatchKind
// ===========================================================================

#[test]
fn debug_distinct_replay_mismatch_kind() {
    let variants = [
        format!("{:?}", ReplayMismatchKind::Digest),
        format!("{:?}", ReplayMismatchKind::EventStream),
        format!("{:?}", ReplayMismatchKind::RandomTranscript),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

// ===========================================================================
// 11) Debug distinctness — CounterfactualDivergenceKind
// ===========================================================================

#[test]
fn debug_distinct_counterfactual_divergence_kind() {
    let variants = [
        format!("{:?}", CounterfactualDivergenceKind::EventMismatch),
        format!("{:?}", CounterfactualDivergenceKind::MissingBaselineEvent),
        format!(
            "{:?}",
            CounterfactualDivergenceKind::MissingCounterfactualEvent
        ),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

// ===========================================================================
// 12) Serde exact tags — ReplayInputErrorCode (snake_case)
// ===========================================================================

#[test]
fn serde_tags_replay_input_error_code() {
    let codes = [
        ReplayInputErrorCode::MissingModelSnapshot,
        ReplayInputErrorCode::PartialTrace,
        ReplayInputErrorCode::CorruptedTranscript,
    ];
    let expected = [
        "\"missing_model_snapshot\"",
        "\"partial_trace\"",
        "\"corrupted_transcript\"",
    ];
    for (c, exp) in codes.iter().zip(expected.iter()) {
        let json = serde_json::to_string(c).unwrap();
        assert_eq!(json, *exp, "ReplayInputErrorCode tag mismatch for {c:?}");
    }
}

// ===========================================================================
// 13) Serde exact tags — ReplayMismatchKind (snake_case)
// ===========================================================================

#[test]
fn serde_tags_replay_mismatch_kind() {
    let kinds = [
        ReplayMismatchKind::Digest,
        ReplayMismatchKind::EventStream,
        ReplayMismatchKind::RandomTranscript,
    ];
    let expected = ["\"digest\"", "\"event_stream\"", "\"random_transcript\""];
    for (k, exp) in kinds.iter().zip(expected.iter()) {
        let json = serde_json::to_string(k).unwrap();
        assert_eq!(json, *exp, "ReplayMismatchKind tag mismatch for {k:?}");
    }
}

// ===========================================================================
// 14) Serde exact tags — CounterfactualDivergenceKind (snake_case)
// ===========================================================================

#[test]
fn serde_tags_counterfactual_divergence_kind() {
    let kinds = [
        CounterfactualDivergenceKind::EventMismatch,
        CounterfactualDivergenceKind::MissingBaselineEvent,
        CounterfactualDivergenceKind::MissingCounterfactualEvent,
    ];
    let expected = [
        "\"event_mismatch\"",
        "\"missing_baseline_event\"",
        "\"missing_counterfactual_event\"",
    ];
    for (k, exp) in kinds.iter().zip(expected.iter()) {
        let json = serde_json::to_string(k).unwrap();
        assert_eq!(
            json, *exp,
            "CounterfactualDivergenceKind tag mismatch for {k:?}"
        );
    }
}

// ===========================================================================
// 15) JSON field-name stability — ScenarioStep
// ===========================================================================

#[test]
fn json_fields_scenario_step() {
    let s = ScenarioStep {
        component: "c".into(),
        event: "e".into(),
        advance_micros: 0,
        metadata: BTreeMap::new(),
    };
    let v: serde_json::Value = serde_json::to_value(&s).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["component", "event", "advance_micros", "metadata"] {
        assert!(obj.contains_key(key), "ScenarioStep missing field: {key}");
    }
}

// ===========================================================================
// 16) JSON field-name stability — ExpectedEvent
// ===========================================================================

#[test]
fn json_fields_expected_event() {
    let e = ExpectedEvent {
        component: "c".into(),
        event: "e".into(),
        outcome: "ok".into(),
        error_code: None,
    };
    let v: serde_json::Value = serde_json::to_value(&e).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["component", "event", "outcome", "error_code"] {
        assert!(obj.contains_key(key), "ExpectedEvent missing field: {key}");
    }
}

// ===========================================================================
// 17) JSON field-name stability — HarnessEvent
// ===========================================================================

#[test]
fn json_fields_harness_event() {
    let e = HarnessEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "c".into(),
        event: "e".into(),
        outcome: "ok".into(),
        error_code: None,
        sequence: 0,
        virtual_time_micros: 0,
    };
    let v: serde_json::Value = serde_json::to_value(&e).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
        "sequence",
        "virtual_time_micros",
    ] {
        assert!(obj.contains_key(key), "HarnessEvent missing field: {key}");
    }
}

// ===========================================================================
// 18) JSON field-name stability — RunResult
// ===========================================================================

#[test]
fn json_fields_run_result() {
    let r = run_minimal();
    let v: serde_json::Value = serde_json::to_value(&r).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "fixture_id",
        "run_id",
        "seed",
        "start_virtual_time_micros",
        "end_virtual_time_micros",
        "random_transcript",
        "events",
        "output_digest",
    ] {
        assert!(obj.contains_key(key), "RunResult missing field: {key}");
    }
}

// ===========================================================================
// 19) JSON field-name stability — ReplayVerification
// ===========================================================================

#[test]
fn json_fields_replay_verification() {
    let r = run_minimal();
    let rv = verify_replay(&r, &r);
    let v: serde_json::Value = serde_json::to_value(&rv).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "matches",
        "expected_digest",
        "actual_digest",
        "reason",
        "mismatch_kind",
        "diverged_event_sequence",
        "transcript_mismatch_index",
        "expected_event_count",
        "actual_event_count",
        "expected_transcript_len",
        "actual_transcript_len",
    ] {
        assert!(
            obj.contains_key(key),
            "ReplayVerification missing field: {key}"
        );
    }
}

// ===========================================================================
// 20) JSON field-name stability — ReplayPerformance
// ===========================================================================

#[test]
fn json_fields_replay_performance() {
    let r = run_minimal();
    let rp = evaluate_replay_performance(&r, 50);
    let v: serde_json::Value = serde_json::to_value(rp).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "virtual_duration_micros",
        "wall_duration_micros",
        "faster_than_realtime",
        "speedup_milli",
    ] {
        assert!(
            obj.contains_key(key),
            "ReplayPerformance missing field: {key}"
        );
    }
}

// ===========================================================================
// 21) JSON field-name stability — EvidenceLinkageRecord
// ===========================================================================

#[test]
fn json_fields_evidence_linkage_record() {
    let r = run_minimal();
    let records = build_evidence_linkage(&r.events);
    assert!(!records.is_empty());
    let v: serde_json::Value = serde_json::to_value(&records[0]).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "event_sequence",
        "evidence_hash",
    ] {
        assert!(
            obj.contains_key(key),
            "EvidenceLinkageRecord missing field: {key}"
        );
    }
}

// ===========================================================================
// 22) Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_scenario_step() {
    let s = ScenarioStep {
        component: "engine".into(),
        event: "tick".into(),
        advance_micros: 50,
        metadata: BTreeMap::from([("key".into(), "val".into())]),
    };
    let json = serde_json::to_string(&s).unwrap();
    let rt: ScenarioStep = serde_json::from_str(&json).unwrap();
    assert_eq!(s, rt);
}

#[test]
fn serde_roundtrip_expected_event() {
    let e = ExpectedEvent {
        component: "c".into(),
        event: "e".into(),
        outcome: "ok".into(),
        error_code: Some("err-1".into()),
    };
    let json = serde_json::to_string(&e).unwrap();
    let rt: ExpectedEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, rt);
}

#[test]
fn serde_roundtrip_harness_event() {
    let e = HarnessEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "c".into(),
        event: "e".into(),
        outcome: "ok".into(),
        error_code: None,
        sequence: 7,
        virtual_time_micros: 1234,
    };
    let json = serde_json::to_string(&e).unwrap();
    let rt: HarnessEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, rt);
}

#[test]
fn serde_roundtrip_run_result() {
    let r = run_minimal();
    let json = serde_json::to_string(&r).unwrap();
    let rt: RunResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, rt);
}

#[test]
fn serde_roundtrip_test_fixture() {
    let f = minimal_fixture();
    let json = serde_json::to_string(&f).unwrap();
    let rt: TestFixture = serde_json::from_str(&json).unwrap();
    assert_eq!(f, rt);
}

// ===========================================================================
// 23) DeterministicRunner — determinism
// ===========================================================================

#[test]
fn runner_produces_deterministic_digest() {
    let runner = DeterministicRunner::default();
    let f = minimal_fixture();
    let r1 = runner.run_fixture(&f).unwrap();
    let r2 = runner.run_fixture(&f).unwrap();
    assert_eq!(r1.output_digest, r2.output_digest);
}

#[test]
fn runner_produces_deterministic_events() {
    let runner = DeterministicRunner::default();
    let f = minimal_fixture();
    let r1 = runner.run_fixture(&f).unwrap();
    let r2 = runner.run_fixture(&f).unwrap();
    assert_eq!(r1.events, r2.events);
}

#[test]
fn runner_trace_id_uses_prefix_and_fixture_id() {
    let runner = DeterministicRunner::default();
    let r = runner.run_fixture(&minimal_fixture()).unwrap();
    assert!(
        r.events[0].trace_id.starts_with("trace-"),
        "trace_id: {}",
        r.events[0].trace_id
    );
    assert!(
        r.events[0].trace_id.contains("fix-1"),
        "trace_id: {}",
        r.events[0].trace_id
    );
}

#[test]
fn runner_advances_virtual_time() {
    let runner = DeterministicRunner::default();
    let r = runner.run_fixture(&minimal_fixture()).unwrap();
    assert_eq!(r.start_virtual_time_micros, 1000);
    assert_eq!(r.end_virtual_time_micros, 1100); // 1000 + 100
}

// ===========================================================================
// 24) TestFixture::validate — edge cases
// ===========================================================================

#[test]
fn validate_rejects_empty_fixture_id() {
    let mut f = minimal_fixture();
    f.fixture_id = "  ".into();
    assert!(matches!(
        f.validate(),
        Err(FixtureValidationError::MissingFixtureId)
    ));
}

#[test]
fn validate_rejects_wrong_version() {
    let mut f = minimal_fixture();
    f.fixture_version = 99;
    assert!(matches!(
        f.validate(),
        Err(FixtureValidationError::UnsupportedVersion { .. })
    ));
}

#[test]
fn validate_rejects_empty_steps() {
    let mut f = minimal_fixture();
    f.steps.clear();
    assert!(matches!(
        f.validate(),
        Err(FixtureValidationError::MissingSteps)
    ));
}

#[test]
fn validate_rejects_empty_component() {
    let mut f = minimal_fixture();
    f.steps[0].component = "".into();
    assert!(matches!(
        f.validate(),
        Err(FixtureValidationError::InvalidStep { .. })
    ));
}

// ===========================================================================
// 25) verify_replay — matching
// ===========================================================================

#[test]
fn verify_replay_identical_runs_match() {
    let r = run_minimal();
    let rv = verify_replay(&r, &r);
    assert!(rv.matches);
    assert!(rv.reason.is_none());
    assert!(rv.mismatch_kind.is_none());
}

// ===========================================================================
// 26) assert_structured_logs
// ===========================================================================

#[test]
fn assert_structured_logs_pass_on_match() {
    let r = run_minimal();
    let expectations = vec![LogExpectation {
        component: "engine".into(),
        event: "start".into(),
        outcome: "ok".into(),
        error_code: None,
    }];
    assert!(assert_structured_logs(&r.events, &expectations).is_ok());
}

#[test]
fn assert_structured_logs_fail_on_missing() {
    let r = run_minimal();
    let expectations = vec![LogExpectation {
        component: "nonexistent".into(),
        event: "x".into(),
        outcome: "ok".into(),
        error_code: None,
    }];
    let err = assert_structured_logs(&r.events, &expectations).unwrap_err();
    assert_eq!(err.missing.len(), 1);
    assert!(err.to_string().contains("1"));
}

// ===========================================================================
// 27) build_evidence_linkage
// ===========================================================================

#[test]
fn evidence_linkage_one_per_event() {
    let r = run_minimal();
    let records = build_evidence_linkage(&r.events);
    assert_eq!(records.len(), r.events.len());
}

// ===========================================================================
// 28) evaluate_replay_performance
// ===========================================================================

#[test]
fn replay_performance_faster_than_realtime() {
    let r = run_minimal();
    let rp = evaluate_replay_performance(&r, 10);
    assert!(rp.faster_than_realtime);
}

#[test]
fn replay_performance_slower_than_realtime() {
    let r = run_minimal();
    let rp = evaluate_replay_performance(&r, 1_000_000);
    assert!(!rp.faster_than_realtime);
}

// ===========================================================================
// 29) validate_replay_input
// ===========================================================================

#[test]
fn validate_replay_input_missing_snapshot() {
    let r = run_minimal();
    let err = validate_replay_input(&r, None).unwrap_err();
    assert!(matches!(
        err.code,
        ReplayInputErrorCode::MissingModelSnapshot
    ));
}

#[test]
fn validate_replay_input_valid() {
    let r = run_minimal();
    assert!(validate_replay_input(&r, Some("snapshot-ptr")).is_ok());
}

// ===========================================================================
// 30) parse_fixture_with_migration — v0 → v1
// ===========================================================================

#[test]
fn parse_fixture_with_migration_v0_succeeds() {
    let v0 = serde_json::json!({
        "fixture_id": "fix-v0",
        "fixture_version": 0,
        "seed": 42,
        "virtual_time_start_micros": 0,
        "policy_id": "pol-1",
        "steps": [{"component": "c", "event": "e"}]
    });
    let bytes = serde_json::to_vec(&v0).unwrap();
    let f = parse_fixture_with_migration(&bytes).unwrap();
    assert_eq!(f.fixture_version, TestFixture::CURRENT_VERSION);
    assert_eq!(f.fixture_id, "fix-v0");
    assert!(f.determinism_check);
}

#[test]
fn parse_fixture_with_migration_unsupported_version() {
    let bad = serde_json::json!({
        "fixture_id": "fix",
        "fixture_version": 99,
        "seed": 1,
        "virtual_time_start_micros": 0,
        "policy_id": "p",
        "steps": [{"component": "c", "event": "e"}]
    });
    let bytes = serde_json::to_vec(&bad).unwrap();
    let err = parse_fixture_with_migration(&bytes).unwrap_err();
    assert!(matches!(
        err,
        FixtureMigrationError::UnsupportedVersion { .. }
    ));
}

// ===========================================================================
// 31) compare_counterfactual — identical runs
// ===========================================================================

#[test]
fn compare_counterfactual_identical_no_divergence() {
    let r = run_minimal();
    let delta = compare_counterfactual(&r, &r);
    assert!(!delta.digest_changed);
    assert_eq!(delta.changed_events, 0);
    assert_eq!(delta.changed_outcomes, 0);
    assert!(delta.diverged_at_sequence.is_none());
}

// ===========================================================================
// 32) ReplayEnvironmentFingerprint::local
// ===========================================================================

#[test]
fn replay_env_fingerprint_local_has_values() {
    let fp = ReplayEnvironmentFingerprint::local();
    assert!(!fp.os.is_empty());
    assert!(!fp.architecture.is_empty());
    assert!(!fp.family.is_empty());
    assert!(fp.pointer_width_bits > 0);
    assert!(!fp.endian.is_empty());
}

#[test]
fn replay_env_fingerprint_serde_roundtrip() {
    let fp = ReplayEnvironmentFingerprint::local();
    let json = serde_json::to_string(&fp).unwrap();
    let rt: ReplayEnvironmentFingerprint = serde_json::from_str(&json).unwrap();
    assert_eq!(fp, rt);
}

// ===========================================================================
// 33) diagnose_cross_machine_replay — same env
// ===========================================================================

#[test]
fn diagnose_cross_machine_same_env_match() {
    let r = run_minimal();
    let env = ReplayEnvironmentFingerprint::local();
    let diag = diagnose_cross_machine_replay(&r, &r, &env, &env);
    assert!(diag.cross_machine_match);
    assert!(diag.environment_mismatches.is_empty());
    assert!(diag.diagnosis.is_none());
}
