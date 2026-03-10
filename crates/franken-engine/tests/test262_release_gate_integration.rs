#![forbid(unsafe_code)]
//! Integration tests for the `test262_release_gate` module.
//!
//! Exercises the Test262 release gate pipeline from outside the crate
//! boundary: pin/profile/waiver validation, profile classification,
//! runner execution with pass/fail/waiver/timeout/crash outcomes,
//! worker assignment, high-water-mark logic, evidence collection,
//! and serde round-trips.

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

use frankenengine_engine::test262_release_gate::{
    DeterministicWorkerAssignment, ProfileDecision, Test262GateError, Test262GateRun,
    Test262GateRunner, Test262HighWaterMark, Test262LogEvent, Test262ObservedOutcome,
    Test262ObservedResult, Test262Outcome, Test262PinSet, Test262Profile, Test262ProfileExclude,
    Test262ProfileInclude, Test262RunSummary, Test262RunnerConfig, Test262Waiver,
    Test262WaiverReason, Test262WaiverSet, deterministic_worker_assignments, next_high_water_mark,
};

// ===========================================================================
// Helpers
// ===========================================================================

fn valid_pin_set() -> Test262PinSet {
    Test262PinSet {
        schema_version: "franken-engine.test262-pin.v1".into(),
        source_repo: "tc39/test262".into(),
        es_profile: "ES2020".into(),
        test262_commit: "a".repeat(40),
    }
}

fn valid_profile() -> Test262Profile {
    Test262Profile {
        schema_version: "franken-engine.test262-profile.v1".into(),
        profile_name: "es2020-core".into(),
        es_profile: "ES2020".into(),
        includes: vec![Test262ProfileInclude {
            pattern: "built-ins/Array/*".into(),
            rationale: "core array tests".into(),
            normative_clause: "22.1".into(),
        }],
        excludes: vec![],
    }
}

fn valid_waiver_set() -> Test262WaiverSet {
    Test262WaiverSet {
        schema_version: "franken-engine.test262-waiver.v1".into(),
        waivers: vec![],
    }
}

fn valid_config() -> Test262RunnerConfig {
    Test262RunnerConfig {
        trace_prefix: "trace-test262".into(),
        policy_id: "policy-test262-es2020".into(),
        run_date: "2026-01-15".into(),
        worker_count: 4,
        locale: "C".into(),
        timezone: "UTC".into(),
        gc_schedule: "deterministic".into(),
        acknowledge_pass_regression: false,
    }
}

fn observed_pass(test_id: &str) -> Test262ObservedResult {
    Test262ObservedResult {
        test_id: test_id.into(),
        es2020_clause: "22.1".into(),
        outcome: Test262ObservedOutcome::Pass,
        duration_us: 100,
        error_code: None,
        error_detail: None,
    }
}

fn observed_fail(test_id: &str) -> Test262ObservedResult {
    Test262ObservedResult {
        test_id: test_id.into(),
        es2020_clause: "22.1".into(),
        outcome: Test262ObservedOutcome::Fail,
        duration_us: 200,
        error_code: Some("SyntaxError".into()),
        error_detail: Some("unexpected token".into()),
    }
}

// ===========================================================================
// 1. PinSet validation
// ===========================================================================

#[test]
fn pin_set_valid() {
    assert!(valid_pin_set().validate().is_ok());
}

#[test]
fn pin_set_bad_schema_version() {
    let mut pins = valid_pin_set();
    pins.schema_version = "wrong".into();
    let err = pins.validate().unwrap_err();
    let info = err.stable();
    assert!(info.detail.contains("schema"), "detail: {}", info.detail);
}

#[test]
fn pin_set_empty_source_repo() {
    let mut pins = valid_pin_set();
    pins.source_repo = String::new();
    assert!(pins.validate().is_err());
}

#[test]
fn pin_set_bad_es_profile() {
    let mut pins = valid_pin_set();
    pins.es_profile = "ES2015".into();
    assert!(pins.validate().is_err());
}

#[test]
fn pin_set_bad_commit_hash_length() {
    let mut pins = valid_pin_set();
    pins.test262_commit = "abc".into();
    assert!(pins.validate().is_err());
}

#[test]
fn pin_set_bad_commit_hash_non_hex() {
    let mut pins = valid_pin_set();
    pins.test262_commit = "z".repeat(40); // z is not valid hex
    assert!(pins.validate().is_err());
}

#[test]
fn pin_set_serde_round_trip() {
    let pins = valid_pin_set();
    let json = serde_json::to_string(&pins).unwrap();
    let back: Test262PinSet = serde_json::from_str(&json).unwrap();
    assert_eq!(back, pins);
}

// ===========================================================================
// 2. Profile validation
// ===========================================================================

#[test]
fn profile_valid() {
    assert!(valid_profile().validate().is_ok());
}

#[test]
fn profile_bad_schema() {
    let mut prof = valid_profile();
    prof.schema_version = "wrong".into();
    assert!(prof.validate().is_err());
}

#[test]
fn profile_empty_name() {
    let mut prof = valid_profile();
    prof.profile_name = String::new();
    assert!(prof.validate().is_err());
}

#[test]
fn profile_bad_es_profile() {
    let mut prof = valid_profile();
    prof.es_profile = "ES2015".into();
    assert!(prof.validate().is_err());
}

#[test]
fn profile_no_includes() {
    let mut prof = valid_profile();
    prof.includes = vec![];
    assert!(prof.validate().is_err());
}

#[test]
fn profile_empty_include_pattern() {
    let mut prof = valid_profile();
    prof.includes[0].pattern = String::new();
    assert!(prof.validate().is_err());
}

#[test]
fn profile_serde_round_trip() {
    let prof = valid_profile();
    let json = serde_json::to_string(&prof).unwrap();
    let back: Test262Profile = serde_json::from_str(&json).unwrap();
    assert_eq!(back, prof);
}

// ===========================================================================
// 3. Profile classification
// ===========================================================================

#[test]
fn profile_classify_included() {
    let prof = valid_profile();
    let decision = prof.classify("built-ins/Array/from");
    assert_eq!(decision, ProfileDecision::Included);
}

#[test]
fn profile_classify_not_selected() {
    let prof = valid_profile();
    let decision = prof.classify("built-ins/Object/keys");
    assert_eq!(decision, ProfileDecision::NotSelected);
}

#[test]
fn profile_classify_excluded() {
    let mut prof = valid_profile();
    prof.excludes.push(Test262ProfileExclude {
        pattern: "built-ins/Array/from".into(),
        rationale: "excluded".into(),
        normative_clause: "22.1.2.1".into(),
    });
    let decision = prof.classify("built-ins/Array/from");
    assert!(matches!(decision, ProfileDecision::Excluded { .. }));
}

#[test]
fn profile_classify_wildcard_match() {
    let prof = Test262Profile {
        schema_version: "franken-engine.test262-profile.v1".into(),
        profile_name: "all".into(),
        es_profile: "ES2020".into(),
        includes: vec![Test262ProfileInclude {
            pattern: "*".into(),
            rationale: "all tests".into(),
            normative_clause: "all".into(),
        }],
        excludes: vec![],
    };
    assert_eq!(prof.classify("anything/at/all"), ProfileDecision::Included);
}

// ===========================================================================
// 4. WaiverSet validation
// ===========================================================================

#[test]
fn waiver_set_valid_empty() {
    assert!(valid_waiver_set().validate().is_ok());
}

#[test]
fn waiver_set_valid_with_waiver() {
    let mut ws = valid_waiver_set();
    ws.waivers.push(Test262Waiver {
        test_id: "built-ins/Array/from".into(),
        reason_code: Test262WaiverReason::NotYetImplemented,
        es2020_clause: "22.1.2.1".into(),
        tracking_bead: "bd-abc".into(),
        expiry_date: "2027-06-30".into(),
        reviewer: "eng-team".into(),
    });
    assert!(ws.validate().is_ok());
}

#[test]
fn waiver_set_bad_schema() {
    let mut ws = valid_waiver_set();
    ws.schema_version = "wrong".into();
    assert!(ws.validate().is_err());
}

#[test]
fn waiver_set_empty_test_id() {
    let mut ws = valid_waiver_set();
    ws.waivers.push(Test262Waiver {
        test_id: String::new(),
        reason_code: Test262WaiverReason::HarnessGap,
        es2020_clause: "22.1".into(),
        tracking_bead: "bd-abc".into(),
        expiry_date: "2027-01-01".into(),
        reviewer: "eng".into(),
    });
    assert!(ws.validate().is_err());
}

#[test]
fn waiver_set_bad_expiry_format() {
    let mut ws = valid_waiver_set();
    ws.waivers.push(Test262Waiver {
        test_id: "test1".into(),
        reason_code: Test262WaiverReason::HarnessGap,
        es2020_clause: "22.1".into(),
        tracking_bead: "bd-abc".into(),
        expiry_date: "Jan 1 2027".into(), // Not YYYY-MM-DD
        reviewer: "eng".into(),
    });
    assert!(ws.validate().is_err());
}

// ===========================================================================
// 5. WaiverReason serde
// ===========================================================================

#[test]
fn waiver_reason_serde_round_trip() {
    for r in [
        Test262WaiverReason::HarnessGap,
        Test262WaiverReason::HostHookMissing,
        Test262WaiverReason::IntentionalDivergence,
        Test262WaiverReason::NotYetImplemented,
    ] {
        let json = serde_json::to_string(&r).unwrap();
        let back: Test262WaiverReason = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }
}

// ===========================================================================
// 6. ObservedOutcome serde
// ===========================================================================

#[test]
fn observed_outcome_serde_round_trip() {
    for o in [
        Test262ObservedOutcome::Pass,
        Test262ObservedOutcome::Fail,
        Test262ObservedOutcome::Timeout,
        Test262ObservedOutcome::Crash,
    ] {
        let json = serde_json::to_string(&o).unwrap();
        let back: Test262ObservedOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(back, o);
    }
}

// ===========================================================================
// 7. Test262Outcome serde
// ===========================================================================

#[test]
fn outcome_serde_round_trip() {
    for o in [
        Test262Outcome::Pass,
        Test262Outcome::Fail,
        Test262Outcome::Waived,
        Test262Outcome::Timeout,
        Test262Outcome::Crash,
    ] {
        let json = serde_json::to_string(&o).unwrap();
        let back: Test262Outcome = serde_json::from_str(&json).unwrap();
        assert_eq!(back, o);
    }
}

// ===========================================================================
// 8. Runner: all-pass results
// ===========================================================================

#[test]
fn runner_all_pass_not_blocked() {
    let pins = valid_pin_set();
    let prof = valid_profile();
    let waivers = valid_waiver_set();
    let config = valid_config();

    let observed = vec![
        observed_pass("built-ins/Array/from"),
        observed_pass("built-ins/Array/isArray"),
    ];

    let runner = Test262GateRunner { config };
    let run = runner.run(&pins, &prof, &waivers, &observed, None).unwrap();
    assert!(!run.blocked);
    assert_eq!(run.summary.passed, 2);
    assert_eq!(run.summary.failed, 0);
}

#[test]
fn runner_all_pass_logs_contain_events() {
    let pins = valid_pin_set();
    let prof = valid_profile();
    let waivers = valid_waiver_set();
    let config = valid_config();

    let observed = vec![observed_pass("built-ins/Array/from")];

    let runner = Test262GateRunner { config };
    let run = runner.run(&pins, &prof, &waivers, &observed, None).unwrap();
    assert!(!run.logs.is_empty());
    assert_eq!(run.logs[0].outcome, Test262Outcome::Pass);
}

// ===========================================================================
// 9. Runner: failure blocks release
// ===========================================================================

#[test]
fn runner_failure_blocks_release() {
    let pins = valid_pin_set();
    let prof = valid_profile();
    let waivers = valid_waiver_set();
    let config = valid_config();

    let observed = vec![
        observed_pass("built-ins/Array/from"),
        observed_fail("built-ins/Array/isArray"),
    ];

    let runner = Test262GateRunner { config };
    let run = runner.run(&pins, &prof, &waivers, &observed, None).unwrap();
    assert!(run.blocked);
    assert_eq!(run.summary.failed, 1);
    assert!(run.summary.blocked_failures > 0);
}

// ===========================================================================
// 10. Runner: waived failure does not block
// ===========================================================================

#[test]
fn runner_waived_failure_not_blocked() {
    let pins = valid_pin_set();
    let prof = valid_profile();
    let mut waivers = valid_waiver_set();
    waivers.waivers.push(Test262Waiver {
        test_id: "built-ins/Array/isArray".into(),
        reason_code: Test262WaiverReason::NotYetImplemented,
        es2020_clause: "22.1.2.2".into(),
        tracking_bead: "bd-fix-isarray".into(),
        expiry_date: "2027-12-31".into(),
        reviewer: "eng-team".into(),
    });
    let config = valid_config();

    let observed = vec![
        observed_pass("built-ins/Array/from"),
        observed_fail("built-ins/Array/isArray"),
    ];

    let runner = Test262GateRunner { config };
    let run = runner.run(&pins, &prof, &waivers, &observed, None).unwrap();
    assert!(!run.blocked);
    assert_eq!(run.summary.waived, 1);
    assert_eq!(run.summary.blocked_failures, 0);
}

// ===========================================================================
// 11. Runner: timeout and crash
// ===========================================================================

#[test]
fn runner_timeout_blocks_release() {
    let pins = valid_pin_set();
    let prof = valid_profile();
    let waivers = valid_waiver_set();
    let config = valid_config();

    let observed = vec![Test262ObservedResult {
        test_id: "built-ins/Array/from".into(),
        es2020_clause: "22.1.2.1".into(),
        outcome: Test262ObservedOutcome::Timeout,
        duration_us: 30_000_000,
        error_code: None,
        error_detail: None,
    }];

    let runner = Test262GateRunner { config };
    let run = runner.run(&pins, &prof, &waivers, &observed, None).unwrap();
    assert!(run.blocked);
    assert_eq!(run.summary.timed_out, 1);
}

#[test]
fn runner_crash_blocks_release() {
    let pins = valid_pin_set();
    let prof = valid_profile();
    let waivers = valid_waiver_set();
    let config = valid_config();

    let observed = vec![Test262ObservedResult {
        test_id: "built-ins/Array/from".into(),
        es2020_clause: "22.1.2.1".into(),
        outcome: Test262ObservedOutcome::Crash,
        duration_us: 500,
        error_code: Some("SIGSEGV".into()),
        error_detail: Some("segfault".into()),
    }];

    let runner = Test262GateRunner { config };
    let run = runner.run(&pins, &prof, &waivers, &observed, None).unwrap();
    assert!(run.blocked);
    assert_eq!(run.summary.crashed, 1);
}

// ===========================================================================
// 12. Runner: not-selected tests ignored
// ===========================================================================

#[test]
fn runner_ignores_not_selected_tests() {
    let pins = valid_pin_set();
    let prof = valid_profile(); // Only includes built-ins/Array/*
    let waivers = valid_waiver_set();
    let config = valid_config();

    let observed = vec![
        observed_pass("built-ins/Array/from"),
        observed_fail("built-ins/Object/keys"), // Not selected by profile
    ];

    let runner = Test262GateRunner { config };
    let run = runner.run(&pins, &prof, &waivers, &observed, None).unwrap();
    assert!(!run.blocked); // The Object failure is not selected
    assert_eq!(run.summary.total_profile_tests, 1);
}

// ===========================================================================
// 13. Runner: duplicate observed result error
// ===========================================================================

#[test]
fn runner_duplicate_observed_result_error() {
    let pins = valid_pin_set();
    let prof = valid_profile();
    let waivers = valid_waiver_set();
    let config = valid_config();

    let observed = vec![
        observed_pass("built-ins/Array/from"),
        observed_pass("built-ins/Array/from"), // duplicate
    ];

    let runner = Test262GateRunner { config };
    let result = runner.run(&pins, &prof, &waivers, &observed, None);
    assert!(result.is_err());
    if let Err(Test262GateError::DuplicateObservedResult { test_id }) = result {
        assert_eq!(test_id, "built-ins/Array/from");
    }
}

// ===========================================================================
// 14. Runner: config validation failures
// ===========================================================================

#[test]
fn runner_bad_locale_fails() {
    let pins = valid_pin_set();
    let prof = valid_profile();
    let waivers = valid_waiver_set();
    let mut config = valid_config();
    config.locale = "en_US".into();

    let runner = Test262GateRunner { config };
    assert!(runner.run(&pins, &prof, &waivers, &[], None).is_err());
}

#[test]
fn runner_bad_timezone_fails() {
    let pins = valid_pin_set();
    let prof = valid_profile();
    let waivers = valid_waiver_set();
    let mut config = valid_config();
    config.timezone = "America/New_York".into();

    let runner = Test262GateRunner { config };
    assert!(runner.run(&pins, &prof, &waivers, &[], None).is_err());
}

#[test]
fn runner_bad_gc_schedule_fails() {
    let pins = valid_pin_set();
    let prof = valid_profile();
    let waivers = valid_waiver_set();
    let mut config = valid_config();
    config.gc_schedule = "concurrent".into();

    let runner = Test262GateRunner { config };
    assert!(runner.run(&pins, &prof, &waivers, &[], None).is_err());
}

// ===========================================================================
// 15. Deterministic worker assignments
// ===========================================================================

#[test]
fn worker_assignments_empty() {
    let assignments = deterministic_worker_assignments(&[], 4);
    assert!(assignments.is_empty());
}

#[test]
fn worker_assignments_round_robin() {
    let test_ids: Vec<String> = (0..6).map(|i| format!("test_{i:03}")).collect();
    let assignments = deterministic_worker_assignments(&test_ids, 3);
    assert_eq!(assignments.len(), 6);
    // Workers should be assigned round-robin
    let workers: Vec<usize> = assignments.iter().map(|a| a.worker_index).collect();
    assert_eq!(workers, vec![0, 1, 2, 0, 1, 2]);
}

#[test]
fn worker_assignments_single_worker() {
    let test_ids = vec!["a".to_string(), "b".to_string()];
    let assignments = deterministic_worker_assignments(&test_ids, 1);
    assert_eq!(assignments.len(), 2);
    assert!(assignments.iter().all(|a| a.worker_index == 0));
}

#[test]
fn worker_assignments_deterministic() {
    let test_ids: Vec<String> = (0..10).map(|i| format!("test_{i}")).collect();
    let a1 = deterministic_worker_assignments(&test_ids, 4);
    let a2 = deterministic_worker_assignments(&test_ids, 4);
    assert_eq!(a1, a2);
}

// ===========================================================================
// 16. High water mark
// ===========================================================================

#[test]
fn next_hwm_no_previous() {
    let run = make_simple_run(5, false);
    let hwm = next_high_water_mark(&run, None);
    assert_eq!(hwm.pass_count, 5);
}

#[test]
fn next_hwm_with_higher_previous() {
    let run = make_simple_run(3, false);
    let prev = Test262HighWaterMark {
        schema_version: "franken-engine.test262-high-water-mark.v1".into(),
        profile_hash: run.summary.profile_hash.clone(),
        pass_count: 10,
        recorded_at_utc: "2026-01-01T00:00:00Z".into(),
    };
    let hwm = next_high_water_mark(&run, Some(&prev));
    assert_eq!(hwm.pass_count, 10); // keeps higher previous
}

#[test]
fn next_hwm_with_lower_previous() {
    let run = make_simple_run(10, false);
    let prev = Test262HighWaterMark {
        schema_version: "franken-engine.test262-high-water-mark.v1".into(),
        profile_hash: run.summary.profile_hash.clone(),
        pass_count: 5,
        recorded_at_utc: "2026-01-01T00:00:00Z".into(),
    };
    let hwm = next_high_water_mark(&run, Some(&prev));
    assert_eq!(hwm.pass_count, 10); // uses new higher count
}

fn make_simple_run(passed: usize, blocked: bool) -> Test262GateRun {
    Test262GateRun {
        run_id: "test262-abcdef012345".into(),
        blocked,
        logs: vec![],
        summary: Test262RunSummary {
            run_id: "test262-abcdef012345".into(),
            total_profile_tests: passed,
            passed,
            failed: 0,
            waived: 0,
            timed_out: 0,
            crashed: 0,
            blocked_failures: 0,
            profile_hash: "a".repeat(64),
            waiver_hash: "b".repeat(64),
            pin_hash: "c".repeat(64),
            env_fingerprint: "d".repeat(64),
            pass_regression_warning: None,
        },
    }
}

// ===========================================================================
// 17. Pass regression detection
// ===========================================================================

#[test]
fn runner_pass_regression_blocks_without_ack() {
    let pins = valid_pin_set();
    let prof = valid_profile();
    let waivers = valid_waiver_set();
    let config = valid_config();

    // Run with 1 passing test
    let observed = vec![observed_pass("built-ins/Array/from")];

    // Previous HWM had 5 passing tests
    let prev_hwm = Test262HighWaterMark {
        schema_version: "franken-engine.test262-high-water-mark.v1".into(),
        profile_hash: "ignored".into(), // Profile hash computed by runner
        pass_count: 5,
        recorded_at_utc: "2026-01-01T00:00:00Z".into(),
    };

    let runner = Test262GateRunner { config };
    let run = runner
        .run(&pins, &prof, &waivers, &observed, Some(&prev_hwm))
        .unwrap();
    // Should be blocked due to pass regression (1 < 5)
    assert!(run.blocked);
    assert!(run.summary.pass_regression_warning.is_some());
    let warning = run.summary.pass_regression_warning.as_ref().unwrap();
    assert_eq!(warning.previous_high_water_mark, 5);
    assert_eq!(warning.current_pass_count, 1);
    assert!(warning.acknowledgement_required);
    assert!(!warning.acknowledged);
}

#[test]
fn runner_pass_regression_unblocked_with_ack() {
    let pins = valid_pin_set();
    let prof = valid_profile();
    let waivers = valid_waiver_set();
    let mut config = valid_config();
    config.acknowledge_pass_regression = true;

    let observed = vec![observed_pass("built-ins/Array/from")];

    let prev_hwm = Test262HighWaterMark {
        schema_version: "franken-engine.test262-high-water-mark.v1".into(),
        profile_hash: "ignored".into(),
        pass_count: 5,
        recorded_at_utc: "2026-01-01T00:00:00Z".into(),
    };

    let runner = Test262GateRunner { config };
    let run = runner
        .run(&pins, &prof, &waivers, &observed, Some(&prev_hwm))
        .unwrap();
    // Should NOT be blocked with ack
    assert!(!run.blocked);
    let warning = run.summary.pass_regression_warning.as_ref().unwrap();
    assert!(warning.acknowledged);
}

// ===========================================================================
// 18. Error codes
// ===========================================================================

#[test]
fn gate_error_invalid_config_code() {
    let err = Test262GateError::InvalidConfig("bad locale".into());
    let info = err.stable();
    assert!(info.code.starts_with("FE-T262"), "code: {}", info.code);
}

#[test]
fn gate_error_duplicate_result_code() {
    let err = Test262GateError::DuplicateObservedResult {
        test_id: "test1".into(),
    };
    let info = err.stable();
    assert!(info.code.starts_with("FE-T262"), "code: {}", info.code);
    assert!(info.detail.contains("test1"), "detail: {}", info.detail);
}

#[test]
fn gate_error_invalid_profile_code() {
    let err = Test262GateError::InvalidProfile("bad profile".into());
    let info = err.stable();
    assert!(info.code.starts_with("FE-T262"), "code: {}", info.code);
}

#[test]
fn gate_error_missing_field_code() {
    let err = Test262GateError::MissingObservedField {
        test_id: "test1".into(),
        field: "es2020_clause",
    };
    let info = err.stable();
    assert!(info.code.starts_with("FE-T262"), "code: {}", info.code);
}

#[test]
fn gate_error_display() {
    let err = Test262GateError::InvalidConfig("bad".into());
    let display = format!("{err}");
    assert!(!display.is_empty());
}

// ===========================================================================
// 19. GateRun serde round-trip
// ===========================================================================

#[test]
fn gate_run_serde_round_trip() {
    let run = make_simple_run(5, false);
    let json = serde_json::to_string(&run).unwrap();
    let back: Test262GateRun = serde_json::from_str(&json).unwrap();
    assert_eq!(back.run_id, run.run_id);
    assert_eq!(back.summary.passed, 5);
}

#[test]
fn run_summary_serde_round_trip() {
    let run = make_simple_run(10, true);
    let json = serde_json::to_string(&run.summary).unwrap();
    let back: Test262RunSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back.total_profile_tests, 10);
    assert_eq!(back.profile_hash, "a".repeat(64));
}

// ===========================================================================
// 20. High water mark serde
// ===========================================================================

#[test]
fn high_water_mark_serde_round_trip() {
    let hwm = Test262HighWaterMark {
        schema_version: "franken-engine.test262-high-water-mark.v1".into(),
        profile_hash: "a".repeat(64),
        pass_count: 42,
        recorded_at_utc: "2026-01-15T12:00:00Z".into(),
    };
    let json = serde_json::to_string(&hwm).unwrap();
    let back: Test262HighWaterMark = serde_json::from_str(&json).unwrap();
    assert_eq!(back.pass_count, 42);
}

// ===========================================================================
// 21. ProfileDecision equality
// ===========================================================================

#[test]
fn profile_decision_equality() {
    assert_eq!(ProfileDecision::Included, ProfileDecision::Included);
    assert_eq!(ProfileDecision::NotSelected, ProfileDecision::NotSelected);
    assert_ne!(ProfileDecision::Included, ProfileDecision::NotSelected);
}

// ===========================================================================
// 22. Runner: empty observed results
// ===========================================================================

#[test]
fn runner_empty_observed_not_blocked() {
    let pins = valid_pin_set();
    let prof = valid_profile();
    let waivers = valid_waiver_set();
    let config = valid_config();

    let runner = Test262GateRunner { config };
    let run = runner.run(&pins, &prof, &waivers, &[], None).unwrap();
    assert!(!run.blocked);
    assert_eq!(run.summary.total_profile_tests, 0);
}

// ===========================================================================
// 23. Runner: multiple profiles with excludes
// ===========================================================================

#[test]
fn runner_profile_exclude_overrides_include() {
    let pins = valid_pin_set();
    let prof = Test262Profile {
        schema_version: "franken-engine.test262-profile.v1".into(),
        profile_name: "selective".into(),
        es_profile: "ES2020".into(),
        includes: vec![Test262ProfileInclude {
            pattern: "built-ins/Array/*".into(),
            rationale: "array tests".into(),
            normative_clause: "22.1".into(),
        }],
        excludes: vec![Test262ProfileExclude {
            pattern: "built-ins/Array/from".into(),
            rationale: "known divergence".into(),
            normative_clause: "22.1.2.1".into(),
        }],
    };
    let waivers = valid_waiver_set();
    let config = valid_config();

    let observed = vec![
        observed_fail("built-ins/Array/from"), // excluded, should be ignored
        observed_pass("built-ins/Array/isArray"), // included
    ];

    let runner = Test262GateRunner { config };
    let run = runner.run(&pins, &prof, &waivers, &observed, None).unwrap();
    assert!(!run.blocked); // from is excluded, so its failure doesn't count
    assert_eq!(run.summary.total_profile_tests, 1);
}

// ===========================================================================
// 24. Runner config default
// ===========================================================================

#[test]
fn runner_config_default_has_expected_fields() {
    let config = Test262RunnerConfig::default();
    assert_eq!(config.locale, "C");
    assert_eq!(config.timezone, "UTC");
    assert_eq!(config.gc_schedule, "deterministic");
    assert!(config.worker_count >= 1);
}

// ===========================================================================
// 25. Runner: run_id is deterministic
// ===========================================================================

#[test]
fn runner_run_id_deterministic() {
    let pins = valid_pin_set();
    let prof = valid_profile();
    let waivers = valid_waiver_set();
    let config = valid_config();

    let observed = vec![observed_pass("built-ins/Array/from")];

    let runner = Test262GateRunner {
        config: config.clone(),
    };
    let run1 = runner.run(&pins, &prof, &waivers, &observed, None).unwrap();
    let runner2 = Test262GateRunner { config };
    let run2 = runner2
        .run(&pins, &prof, &waivers, &observed, None)
        .unwrap();
    assert_eq!(run1.run_id, run2.run_id);
}

// ===========================================================================
// 26. Log event fields
// ===========================================================================

#[test]
fn log_event_has_correct_component() {
    let pins = valid_pin_set();
    let prof = valid_profile();
    let waivers = valid_waiver_set();
    let config = valid_config();

    let observed = vec![observed_pass("built-ins/Array/from")];

    let runner = Test262GateRunner { config };
    let run = runner.run(&pins, &prof, &waivers, &observed, None).unwrap();

    for log in &run.logs {
        assert_eq!(log.component, "test262_release_gate");
    }
}

#[test]
fn log_event_has_trace_id_prefix() {
    let pins = valid_pin_set();
    let prof = valid_profile();
    let waivers = valid_waiver_set();
    let config = valid_config();

    let observed = vec![observed_pass("built-ins/Array/from")];

    let runner = Test262GateRunner { config };
    let run = runner.run(&pins, &prof, &waivers, &observed, None).unwrap();

    for log in &run.logs {
        assert!(
            log.trace_id.starts_with("trace-test262"),
            "trace_id: {}",
            log.trace_id
        );
    }
}

// ===========================================================================
// 27. ObservedResult serde
// ===========================================================================

#[test]
fn observed_result_serde_round_trip() {
    let result = observed_fail("built-ins/Array/from");
    let json = serde_json::to_string(&result).unwrap();
    let back: Test262ObservedResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back.test_id, "built-ins/Array/from");
    assert_eq!(back.outcome, Test262ObservedOutcome::Fail);
    assert_eq!(back.error_code.as_deref(), Some("SyntaxError"));
}

// ===========================================================================
// 28. Waiver serde
// ===========================================================================

#[test]
fn waiver_serde_round_trip() {
    let waiver = Test262Waiver {
        test_id: "test1".into(),
        reason_code: Test262WaiverReason::HostHookMissing,
        es2020_clause: "22.1".into(),
        tracking_bead: "bd-abc".into(),
        expiry_date: "2027-06-30".into(),
        reviewer: "eng".into(),
    };
    let json = serde_json::to_string(&waiver).unwrap();
    let back: Test262Waiver = serde_json::from_str(&json).unwrap();
    assert_eq!(back.test_id, "test1");
    assert_eq!(back.reason_code, Test262WaiverReason::HostHookMissing);
}

// ===========================================================================
// 29. Worker assignment serde
// ===========================================================================

#[test]
fn worker_assignment_serde_round_trip() {
    let a = DeterministicWorkerAssignment {
        test_id: "test1".into(),
        worker_index: 2,
        queue_index: 0,
    };
    let json = serde_json::to_string(&a).unwrap();
    let back: DeterministicWorkerAssignment = serde_json::from_str(&json).unwrap();
    assert_eq!(back.worker_index, 2);
}

// ===========================================================================
// 30. Log event serde
// ===========================================================================

#[test]
fn log_event_serde_round_trip() {
    let log = Test262LogEvent {
        trace_id: "trace-1".into(),
        decision_id: "d1".into(),
        policy_id: "p1".into(),
        component: "test262_release_gate".into(),
        event: "test262_case_evaluated".into(),
        test_id: "test/a".into(),
        es2020_clause: "22.1".into(),
        outcome: Test262Outcome::Pass,
        duration_us: 100,
        error_code: None,
        error_detail: None,
        worker_index: 0,
    };
    let json = serde_json::to_string(&log).unwrap();
    let back: Test262LogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.trace_id, "trace-1");
    assert_eq!(back.outcome, Test262Outcome::Pass);
}

// ===========================================================================
// 31. Evidence collector (file I/O)
// ===========================================================================

#[test]
fn evidence_collector_creates_artifacts() {
    use frankenengine_engine::test262_release_gate::Test262EvidenceCollector;
    let dir = std::env::temp_dir().join(format!("test262_evidence_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let collector = Test262EvidenceCollector::new(&dir).unwrap();
    let run = make_simple_run(5, false);
    let hwm = next_high_water_mark(&run, None);
    let artifacts = collector.collect(&run, &hwm).unwrap();

    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.evidence_path.exists());
    assert!(artifacts.high_water_mark_path.exists());

    // Clean up
    let _ = std::fs::remove_dir_all(&dir);
}

// ===========================================================================
// 32. Runner: mixed outcomes
// ===========================================================================

#[test]
fn runner_mixed_outcomes_summary_correct() {
    let pins = valid_pin_set();
    let prof = Test262Profile {
        schema_version: "franken-engine.test262-profile.v1".into(),
        profile_name: "broad".into(),
        es_profile: "ES2020".into(),
        includes: vec![Test262ProfileInclude {
            pattern: "test/*".into(),
            rationale: "all test".into(),
            normative_clause: "all".into(),
        }],
        excludes: vec![],
    };
    let mut waivers = valid_waiver_set();
    waivers.waivers.push(Test262Waiver {
        test_id: "test/timeout_case".into(),
        reason_code: Test262WaiverReason::HarnessGap,
        es2020_clause: "22.1".into(),
        tracking_bead: "bd-t".into(),
        expiry_date: "2027-12-31".into(),
        reviewer: "eng".into(),
    });
    let config = valid_config();

    let observed = vec![
        observed_pass("test/pass1"),
        observed_pass("test/pass2"),
        observed_fail("test/fail1"),
        Test262ObservedResult {
            test_id: "test/timeout_case".into(),
            es2020_clause: "22.1".into(),
            outcome: Test262ObservedOutcome::Timeout,
            duration_us: 30_000_000,
            error_code: None,
            error_detail: None,
        },
    ];

    let runner = Test262GateRunner { config };
    let run = runner.run(&pins, &prof, &waivers, &observed, None).unwrap();
    assert!(run.blocked); // fail1 is unwaived
    assert_eq!(run.summary.passed, 2);
    assert_eq!(run.summary.failed, 1);
    assert_eq!(run.summary.waived, 1); // timeout_case waived
    assert_eq!(run.summary.total_profile_tests, 4);
}

// ===========================================================================
// 33. Expired waiver does not apply
// ===========================================================================

#[test]
fn runner_expired_waiver_does_not_apply() {
    let pins = valid_pin_set();
    let prof = valid_profile();
    let mut waivers = valid_waiver_set();
    waivers.waivers.push(Test262Waiver {
        test_id: "built-ins/Array/from".into(),
        reason_code: Test262WaiverReason::NotYetImplemented,
        es2020_clause: "22.1.2.1".into(),
        tracking_bead: "bd-old".into(),
        expiry_date: "2020-01-01".into(), // expired
        reviewer: "eng".into(),
    });
    let mut config = valid_config();
    config.run_date = "2026-01-15".into();

    let observed = vec![observed_fail("built-ins/Array/from")];

    let runner = Test262GateRunner { config };
    let run = runner.run(&pins, &prof, &waivers, &observed, None).unwrap();
    // Waiver is expired, so failure should block
    assert!(run.blocked);
    assert_eq!(run.summary.failed, 1);
}

// ===========================================================================
// 34. Waiver reason display
// ===========================================================================

#[test]
fn waiver_reason_json_snake_case() {
    let json = serde_json::to_string(&Test262WaiverReason::HostHookMissing).unwrap();
    assert_eq!(json, "\"host_hook_missing\"");
}

#[test]
fn observed_outcome_json_snake_case() {
    let json = serde_json::to_string(&Test262ObservedOutcome::Timeout).unwrap();
    assert_eq!(json, "\"timeout\"");
}
