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

#[path = "../src/test262_release_gate.rs"]
mod test262_release_gate;

use std::fs;
use std::path::PathBuf;

use test262_release_gate::{
    ProfileDecision, Test262EvidenceCollector, Test262GateError, Test262GateRun, Test262GateRunner,
    Test262HighWaterMark, Test262ObservedOutcome, Test262ObservedResult, Test262PinSet,
    Test262Profile, Test262RunnerConfig, Test262WaiverReason, Test262WaiverSet,
    deterministic_worker_assignments, next_high_water_mark,
};

fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(path)
}

fn observed(test_id: &str, clause: &str, outcome: Test262ObservedOutcome) -> Test262ObservedResult {
    Test262ObservedResult {
        test_id: test_id.to_string(),
        es2020_clause: clause.to_string(),
        outcome,
        duration_us: 42,
        error_code: None,
        error_detail: None,
    }
}

fn runner(run_date: &str, acknowledge_pass_regression: bool) -> Test262GateRunner {
    Test262GateRunner {
        config: Test262RunnerConfig {
            run_date: run_date.to_string(),
            acknowledge_pass_regression,
            ..Test262RunnerConfig::default()
        },
    }
}

fn load_profile() -> Test262Profile {
    let profile =
        Test262Profile::load_toml(fixture("test262_es2020_profile.toml")).expect("profile load");
    profile.validate().expect("profile validate");
    profile
}

fn load_pins() -> Test262PinSet {
    let pins =
        Test262PinSet::load_toml(fixture("test262_conformance_pins.toml")).expect("pins load");
    pins.validate().expect("pins validate");
    pins
}

fn load_waivers() -> Test262WaiverSet {
    let waivers = Test262WaiverSet::load_toml(fixture("test262_conformance_waivers.toml"))
        .expect("waivers load");
    waivers.validate().expect("waivers validate");
    waivers
}

#[test]
fn fixture_files_parse_and_validate() {
    let _ = load_profile();
    let _ = load_pins();
    let _ = load_waivers();
}

#[test]
fn profile_selects_includes_and_excludes() {
    let profile = load_profile();

    assert!(matches!(
        profile.classify("language/expressions/optional-chaining/case.js"),
        ProfileDecision::Included
    ));
    assert!(matches!(
        profile.classify("built-ins/Promise/allSettled/case.js"),
        ProfileDecision::Included
    ));
    assert!(matches!(
        profile.classify("language/annexB/legacy/escape.js"),
        ProfileDecision::Excluded { .. }
    ));
    assert!(matches!(
        profile.classify("built-ins/intl402/DateTimeFormat/default.js"),
        ProfileDecision::Excluded { .. }
    ));
    assert!(matches!(
        profile.classify("harness/assert.js"),
        ProfileDecision::NotSelected
    ));
}

#[test]
fn zero_silent_failures_block_unwaived_test() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[
                observed(
                    "language/expressions/optional-chaining/pass.js",
                    "13.3.1",
                    Test262ObservedOutcome::Pass,
                ),
                observed(
                    "language/statements/for/let-fail.js",
                    "13.7",
                    Test262ObservedOutcome::Fail,
                ),
            ],
            None,
        )
        .expect("gate run");

    assert!(run.blocked, "unwaived failure must block release gate");
    assert_eq!(run.summary.passed, 1);
    assert_eq!(run.summary.failed, 1);
    assert_eq!(run.summary.waived, 0);
    assert_eq!(run.summary.blocked_failures, 1);

    let fail_log = run
        .logs
        .iter()
        .find(|entry| entry.test_id == "language/statements/for/let-fail.js")
        .expect("missing fail log");
    assert_eq!(fail_log.error_code.as_deref(), Some("FE-T262-1005"));
}

#[test]
fn active_waiver_allows_failures_without_blocking() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[
                observed(
                    "language/expressions/optional-chaining/short-circuiting.js",
                    "13.3.1",
                    Test262ObservedOutcome::Fail,
                ),
                observed(
                    "built-ins/Array/prototype/map/basic.js",
                    "23.1.3",
                    Test262ObservedOutcome::Pass,
                ),
            ],
            None,
        )
        .expect("gate run");

    assert!(!run.blocked, "waived failures should not block gate");
    assert_eq!(run.summary.passed, 1);
    assert_eq!(run.summary.waived, 1);
    assert_eq!(run.summary.failed, 0);
    assert_eq!(run.summary.blocked_failures, 0);
}

#[test]
fn expired_waiver_is_not_applied() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed(
                "built-ins/Promise/allSettled/reject-late.js",
                "27.2.4",
                Test262ObservedOutcome::Fail,
            )],
            None,
        )
        .expect("gate run");

    assert!(run.blocked);
    assert_eq!(run.summary.failed, 1);
    assert_eq!(run.summary.waived, 0);
}

#[test]
fn deterministic_worker_assignment_is_stable() {
    let test_ids = vec![
        "language/b.js".to_string(),
        "language/a.js".to_string(),
        "built-ins/z.js".to_string(),
        "built-ins/m.js".to_string(),
    ];

    let first = deterministic_worker_assignments(&test_ids, 3);
    let second = deterministic_worker_assignments(&test_ids, 3);

    assert_eq!(first, second);
    assert_eq!(first[0].test_id, "built-ins/m.js");
    assert_eq!(first[1].test_id, "built-ins/z.js");
    assert_eq!(first[2].test_id, "language/a.js");
    assert_eq!(first[3].test_id, "language/b.js");
}

#[test]
fn pass_regression_requires_acknowledgement() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let previous_hwm = Test262HighWaterMark {
        schema_version: "franken-engine.test262-high-water-mark.v1".to_string(),
        profile_hash: "abc".to_string(),
        pass_count: 3,
        recorded_at_utc: "2026-02-21T00:00:00Z".to_string(),
    };

    let observed_results = vec![
        observed("language/a.js", "13.1", Test262ObservedOutcome::Pass),
        observed("language/b.js", "13.2", Test262ObservedOutcome::Pass),
    ];

    let blocked = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &observed_results,
            Some(&previous_hwm),
        )
        .expect("gate run");
    assert!(blocked.blocked);
    assert_eq!(blocked.summary.blocked_failures, 1);
    assert!(
        blocked
            .summary
            .pass_regression_warning
            .as_ref()
            .is_some_and(|warning| warning.acknowledgement_required && !warning.acknowledged)
    );

    let acknowledged = runner("2026-02-22", true)
        .run(
            &pins,
            &profile,
            &waivers,
            &observed_results,
            Some(&previous_hwm),
        )
        .expect("gate run");
    assert!(!acknowledged.blocked);
    assert_eq!(acknowledged.summary.blocked_failures, 0);
}

#[test]
fn high_water_mark_is_monotonic() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed(
                "language/a.js",
                "13.1",
                Test262ObservedOutcome::Pass,
            )],
            None,
        )
        .expect("gate run");

    let previous = Test262HighWaterMark {
        schema_version: "franken-engine.test262-high-water-mark.v1".to_string(),
        profile_hash: "abc".to_string(),
        pass_count: 10,
        recorded_at_utc: "2026-02-21T00:00:00Z".to_string(),
    };

    let next = next_high_water_mark(&run, Some(&previous));
    assert_eq!(next.pass_count, 10);
}

#[test]
fn collector_writes_manifest_and_evidence() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed(
                "built-ins/Array/prototype/filter/basic.js",
                "23.1.3",
                Test262ObservedOutcome::Pass,
            )],
            None,
        )
        .expect("gate run");

    let unique = format!(
        "collector-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock drift")
            .as_nanos()
    );
    let temp_root = fixture("artifacts")
        .join("test262_release_gate")
        .join(unique);

    let collector = Test262EvidenceCollector::new(&temp_root).expect("collector create");
    let hwm = next_high_water_mark(&run, None);
    let artifacts = collector.collect(&run, &hwm).expect("collect");

    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.evidence_path.exists());
    assert!(artifacts.high_water_mark_path.exists());
    let loaded_hwm = Test262HighWaterMark::load_json(&artifacts.high_water_mark_path)
        .expect("load hwm")
        .expect("hwm present");
    assert_eq!(loaded_hwm.pass_count, hwm.pass_count);

    let evidence = fs::read_to_string(&artifacts.evidence_path).expect("read evidence");
    assert!(evidence.contains("test262_case_evaluated"));
    assert!(evidence.contains("built-ins/Array/prototype/filter/basic.js"));
}

#[test]
fn worker_assignments_single_worker() {
    let test_ids = vec!["a.js".to_string(), "b.js".to_string()];
    let assignments = deterministic_worker_assignments(&test_ids, 1);
    assert_eq!(assignments.len(), 2);
    assert!(assignments.iter().all(|a| a.worker_index == 0));
}

#[test]
fn worker_assignments_empty_input() {
    let assignments = deterministic_worker_assignments(&[], 4);
    assert!(assignments.is_empty());
}

#[test]
fn observed_helper_populates_fields() {
    let result = observed("test/a.js", "13.1", Test262ObservedOutcome::Pass);
    assert_eq!(result.test_id, "test/a.js");
    assert_eq!(result.es2020_clause, "13.1");
    assert!(matches!(result.outcome, Test262ObservedOutcome::Pass));
    assert_eq!(result.duration_us, 42);
    assert!(result.error_code.is_none());
    assert!(result.error_detail.is_none());
}

#[test]
fn next_high_water_mark_without_previous() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[
                observed("a.js", "13.1", Test262ObservedOutcome::Pass),
                observed("b.js", "13.2", Test262ObservedOutcome::Pass),
            ],
            None,
        )
        .expect("gate run");

    let hwm = next_high_water_mark(&run, None);
    // Without a previous HWM, the initial high water mark starts at 0
    assert_eq!(hwm.pass_count, 0);
}

#[test]
fn all_pass_run_is_not_blocked() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed(
                "language/expressions/optional-chaining/pass.js",
                "13.3.1",
                Test262ObservedOutcome::Pass,
            )],
            None,
        )
        .expect("gate run");
    assert!(!run.blocked);
    assert_eq!(run.summary.passed, 1);
    assert_eq!(run.summary.failed, 0);
    assert_eq!(run.summary.blocked_failures, 0);
}

#[test]
fn test262_observed_outcome_serde_round_trip() {
    for outcome in [Test262ObservedOutcome::Pass, Test262ObservedOutcome::Fail] {
        let json = serde_json::to_string(&outcome).expect("serialize");
        let recovered: Test262ObservedOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(outcome, recovered);
    }
}

#[test]
fn test262_high_water_mark_serde_round_trip() {
    let hwm = Test262HighWaterMark {
        schema_version: "franken-engine.test262-high-water-mark.v1".to_string(),
        profile_hash: "abc123".to_string(),
        pass_count: 42,
        recorded_at_utc: "2026-02-22T00:00:00Z".to_string(),
    };
    let json = serde_json::to_string(&hwm).expect("serialize");
    let recovered: Test262HighWaterMark = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(hwm, recovered);
}

#[test]
fn runner_default_config_has_nonempty_run_date() {
    let config = Test262RunnerConfig::default();
    assert!(!config.run_date.is_empty(), "run_date should be non-empty");
    assert!(config.worker_count > 0, "worker_count should be positive");
}

#[test]
fn fixture_helper_produces_correct_path() {
    let path = fixture("test262_es2020_profile.toml");
    assert!(path.ends_with("tests/test262_es2020_profile.toml"));
}

// ---------- enrichment: serde roundtrips, error paths, display ----------

#[test]
fn test262_waiver_reason_serde_round_trip() {
    for reason in [
        Test262WaiverReason::HarnessGap,
        Test262WaiverReason::HostHookMissing,
        Test262WaiverReason::IntentionalDivergence,
        Test262WaiverReason::NotYetImplemented,
    ] {
        let json = serde_json::to_string(&reason).expect("serialize");
        let recovered: Test262WaiverReason = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(reason, recovered);
    }
}

#[test]
fn test262_pin_set_serde_round_trip() {
    let pins = load_pins();
    let json = serde_json::to_string(&pins).expect("serialize");
    let recovered: Test262PinSet = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(pins, recovered);
}

#[test]
fn test262_profile_serde_round_trip() {
    let profile = load_profile();
    let json = serde_json::to_string(&profile).expect("serialize");
    let recovered: Test262Profile = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(profile, recovered);
}

#[test]
fn test262_waiver_set_serde_round_trip() {
    let waivers = load_waivers();
    let json = serde_json::to_string(&waivers).expect("serialize");
    let recovered: Test262WaiverSet = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(waivers, recovered);
}

#[test]
fn test262_observed_result_serde_round_trip() {
    let result = observed("test/round-trip.js", "13.1", Test262ObservedOutcome::Pass);
    let json = serde_json::to_string(&result).expect("serialize");
    let recovered: Test262ObservedResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(result, recovered);
}

#[test]
fn test262_gate_run_serde_round_trip() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();
    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed("a.js", "13.1", Test262ObservedOutcome::Pass)],
            None,
        )
        .expect("gate run");
    let json = serde_json::to_string(&run).expect("serialize");
    let recovered: Test262GateRun = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(run.run_id, recovered.run_id);
    assert_eq!(run.blocked, recovered.blocked);
    assert_eq!(run.summary.passed, recovered.summary.passed);
}

#[test]
fn test262_gate_error_display_is_nonempty() {
    let err = Test262GateError::InvalidConfig("bad config".to_string());
    let msg = err.to_string();
    assert!(!msg.is_empty());
    assert!(msg.contains("FE-T262"));
}

#[test]
fn test262_gate_error_stable_codes_are_unique() {
    let errors = [
        Test262GateError::InvalidConfig("a".to_string()),
        Test262GateError::DuplicateObservedResult {
            test_id: "test.js".to_string(),
        },
        Test262GateError::MissingObservedField {
            test_id: "test.js".to_string(),
            field: "outcome",
        },
        Test262GateError::InvalidProfile("bad".to_string()),
    ];
    let codes: Vec<&str> = errors.iter().map(|e| e.stable().code).collect();
    // Verify all codes start with FE-T262
    assert!(codes.iter().all(|c| c.starts_with("FE-T262")));
}

#[test]
fn test262_gate_error_is_std_error() {
    let err = Test262GateError::InvalidConfig("test".to_string());
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
}

#[test]
fn test262_observed_outcome_timeout_and_crash_variants() {
    for outcome in [
        Test262ObservedOutcome::Timeout,
        Test262ObservedOutcome::Crash,
    ] {
        let json = serde_json::to_string(&outcome).expect("serialize");
        let recovered: Test262ObservedOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(outcome, recovered);
    }
}

#[test]
fn profile_decision_not_selected_for_unmatched_path() {
    let profile = load_profile();
    let decision = profile.classify("totally/unrelated/path.js");
    assert!(matches!(decision, ProfileDecision::NotSelected));
}

#[test]
fn test262_runner_config_serde_round_trip() {
    let config = Test262RunnerConfig {
        run_date: "2026-03-05".to_string(),
        acknowledge_pass_regression: true,
        ..Test262RunnerConfig::default()
    };
    let json = serde_json::to_string(&config).expect("serialize");
    let recovered: Test262RunnerConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.run_date, "2026-03-05");
    assert!(recovered.acknowledge_pass_regression);
}

#[test]
fn test262_runner_config_default_does_not_acknowledge_regression() {
    let config = Test262RunnerConfig::default();
    assert!(!config.acknowledge_pass_regression);
}

// ── enrichment batch 2: expanded coverage (PearlTower 2026-03-12) ──────

use test262_release_gate::{
    DeterministicWorkerAssignment, Test262CollectedArtifacts, Test262GateErrorInfo,
    Test262LogEvent, Test262Outcome, Test262PassRegressionWarning, Test262ProfileExclude,
    Test262ProfileInclude, Test262RunSummary, Test262Waiver,
};

// ── Test262Outcome serde roundtrip ──────────────────────────────────

#[test]
fn test262_outcome_all_variants_serde_round_trip() {
    for outcome in [
        Test262Outcome::Pass,
        Test262Outcome::Fail,
        Test262Outcome::Waived,
        Test262Outcome::Timeout,
        Test262Outcome::Crash,
    ] {
        let json = serde_json::to_string(&outcome).expect("serialize");
        let recovered: Test262Outcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(outcome, recovered);
    }
}

#[test]
fn test262_outcome_serde_uses_snake_case() {
    let json = serde_json::to_string(&Test262Outcome::Waived).expect("serialize");
    assert_eq!(json, "\"waived\"");
    let json = serde_json::to_string(&Test262Outcome::Timeout).expect("serialize");
    assert_eq!(json, "\"timeout\"");
    let json = serde_json::to_string(&Test262Outcome::Crash).expect("serialize");
    assert_eq!(json, "\"crash\"");
}

#[test]
fn test262_observed_outcome_serde_uses_snake_case() {
    let json = serde_json::to_string(&Test262ObservedOutcome::Pass).expect("serialize");
    assert_eq!(json, "\"pass\"");
    let json = serde_json::to_string(&Test262ObservedOutcome::Fail).expect("serialize");
    assert_eq!(json, "\"fail\"");
    let json = serde_json::to_string(&Test262ObservedOutcome::Timeout).expect("serialize");
    assert_eq!(json, "\"timeout\"");
    let json = serde_json::to_string(&Test262ObservedOutcome::Crash).expect("serialize");
    assert_eq!(json, "\"crash\"");
}

// ── Test262Waiver serde roundtrip ───────────────────────────────────

#[test]
fn test262_waiver_serde_round_trip() {
    let waiver = Test262Waiver {
        test_id: "language/test-001.js".to_string(),
        reason_code: Test262WaiverReason::HarnessGap,
        es2020_clause: "13.1".to_string(),
        tracking_bead: "bd-42".to_string(),
        expiry_date: "2030-06-15".to_string(),
        reviewer: "runtime-conformance".to_string(),
    };
    let json = serde_json::to_string(&waiver).expect("serialize");
    let recovered: Test262Waiver = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(waiver, recovered);
}

#[test]
fn test262_waiver_all_reason_codes_serde() {
    for reason in [
        Test262WaiverReason::HarnessGap,
        Test262WaiverReason::HostHookMissing,
        Test262WaiverReason::IntentionalDivergence,
        Test262WaiverReason::NotYetImplemented,
    ] {
        let waiver = Test262Waiver {
            test_id: "test.js".to_string(),
            reason_code: reason,
            es2020_clause: "1.0".to_string(),
            tracking_bead: "bd-1".to_string(),
            expiry_date: "2030-01-01".to_string(),
            reviewer: "dev".to_string(),
        };
        let json = serde_json::to_string(&waiver).expect("serialize");
        let recovered: Test262Waiver = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(waiver.reason_code, recovered.reason_code);
    }
}

// ── Test262LogEvent serde roundtrip ─────────────────────────────────

#[test]
fn test262_log_event_serde_round_trip() {
    let event = Test262LogEvent {
        trace_id: "trace-test262-run-0001".to_string(),
        decision_id: "decision-test262-0001".to_string(),
        policy_id: "policy-test262-es2020".to_string(),
        component: "test262_release_gate".to_string(),
        event: "test262_case_evaluated".to_string(),
        test_id: "language/expressions/arrow.js".to_string(),
        es2020_clause: "14.2".to_string(),
        outcome: Test262Outcome::Pass,
        duration_us: 123,
        error_code: None,
        error_detail: None,
        worker_index: 0,
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: Test262LogEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, recovered);
}

#[test]
fn test262_log_event_with_error_fields_serde() {
    let event = Test262LogEvent {
        trace_id: "tr-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: "test262_release_gate".to_string(),
        event: "test262_case_evaluated".to_string(),
        test_id: "test.js".to_string(),
        es2020_clause: "1.0".to_string(),
        outcome: Test262Outcome::Fail,
        duration_us: 999,
        error_code: Some("FE-T262-1005".to_string()),
        error_detail: Some("non-passing test without active waiver".to_string()),
        worker_index: 3,
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: Test262LogEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event.error_code, recovered.error_code);
    assert_eq!(event.error_detail, recovered.error_detail);
}

// ── Test262RunSummary serde roundtrip ───────────────────────────────

#[test]
fn test262_run_summary_serde_round_trip() {
    let summary = Test262RunSummary {
        run_id: "test262-abc123".to_string(),
        total_profile_tests: 500,
        passed: 400,
        failed: 50,
        waived: 30,
        timed_out: 10,
        crashed: 5,
        blocked_failures: 65,
        profile_hash: "deadbeef".to_string(),
        waiver_hash: "cafebabe".to_string(),
        pin_hash: "0badf00d".to_string(),
        env_fingerprint: "abcdef0123456789".to_string(),
        pass_regression_warning: None,
    };
    let json = serde_json::to_string(&summary).expect("serialize");
    let recovered: Test262RunSummary = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(summary, recovered);
}

#[test]
fn test262_run_summary_with_regression_warning_serde() {
    let summary = Test262RunSummary {
        run_id: "test262-xyz".to_string(),
        total_profile_tests: 100,
        passed: 80,
        failed: 5,
        waived: 10,
        timed_out: 3,
        crashed: 2,
        blocked_failures: 10,
        profile_hash: "ph".to_string(),
        waiver_hash: "wh".to_string(),
        pin_hash: "pnh".to_string(),
        env_fingerprint: "ef".to_string(),
        pass_regression_warning: Some(Test262PassRegressionWarning {
            previous_high_water_mark: 90,
            current_pass_count: 80,
            acknowledgement_required: true,
            acknowledged: false,
        }),
    };
    let json = serde_json::to_string(&summary).expect("serialize");
    let recovered: Test262RunSummary = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        summary.pass_regression_warning,
        recovered.pass_regression_warning
    );
}

// ── Test262PassRegressionWarning serde roundtrip ────────────────────

#[test]
fn test262_pass_regression_warning_serde_round_trip() {
    let warning = Test262PassRegressionWarning {
        previous_high_water_mark: 200,
        current_pass_count: 180,
        acknowledgement_required: true,
        acknowledged: false,
    };
    let json = serde_json::to_string(&warning).expect("serialize");
    let recovered: Test262PassRegressionWarning = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(warning, recovered);
}

#[test]
fn test262_pass_regression_warning_acknowledged_serde() {
    let warning = Test262PassRegressionWarning {
        previous_high_water_mark: 50,
        current_pass_count: 40,
        acknowledgement_required: true,
        acknowledged: true,
    };
    let json = serde_json::to_string(&warning).expect("serialize");
    let recovered: Test262PassRegressionWarning = serde_json::from_str(&json).expect("deserialize");
    assert!(recovered.acknowledged);
}

// ── Test262CollectedArtifacts serde roundtrip ───────────────────────

#[test]
fn test262_collected_artifacts_serde_round_trip() {
    let artifacts = Test262CollectedArtifacts {
        run_manifest_path: PathBuf::from("/tmp/test262/run_manifest.json"),
        evidence_path: PathBuf::from("/tmp/test262/evidence.jsonl"),
        high_water_mark_path: PathBuf::from("/tmp/test262/hwm.json"),
    };
    let json = serde_json::to_string(&artifacts).expect("serialize");
    let recovered: Test262CollectedArtifacts = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(artifacts, recovered);
}

// ── DeterministicWorkerAssignment serde roundtrip ───────────────────

#[test]
fn deterministic_worker_assignment_serde_round_trip() {
    let assignment = DeterministicWorkerAssignment {
        test_id: "language/expressions/add.js".to_string(),
        worker_index: 2,
        queue_index: 5,
    };
    let json = serde_json::to_string(&assignment).expect("serialize");
    let recovered: DeterministicWorkerAssignment =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(assignment, recovered);
}

// ── Test262ProfileInclude/Exclude serde roundtrips ──────────────────

#[test]
fn test262_profile_include_serde_round_trip() {
    let include = Test262ProfileInclude {
        pattern: "built-ins/Array/*".to_string(),
        rationale: "Array tests are essential".to_string(),
        normative_clause: "22.1".to_string(),
    };
    let json = serde_json::to_string(&include).expect("serialize");
    let recovered: Test262ProfileInclude = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(include, recovered);
}

#[test]
fn test262_profile_exclude_serde_round_trip() {
    let exclude = Test262ProfileExclude {
        pattern: "proposals/*".to_string(),
        rationale: "Post-ES2020 proposals are out of scope".to_string(),
        normative_clause: "N/A".to_string(),
    };
    let json = serde_json::to_string(&exclude).expect("serialize");
    let recovered: Test262ProfileExclude = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(exclude, recovered);
}

// ── Test262GateErrorInfo ────────────────────────────────────────────

#[test]
fn test262_gate_error_info_clone_and_eq() {
    let info = Test262GateErrorInfo {
        code: "FE-T262-1001",
        detail: "bad config".to_string(),
    };
    let cloned = info.clone();
    assert_eq!(info, cloned);
}

// ── Test262GateError Display for all variants ───────────────────────

#[test]
fn test262_gate_error_invalid_profile_display() {
    let err = Test262GateError::InvalidProfile("bad profile data".to_string());
    let msg = err.to_string();
    assert!(msg.contains("FE-T262-1002"));
    assert!(msg.contains("bad profile data"));
}

#[test]
fn test262_gate_error_duplicate_result_display() {
    let err = Test262GateError::DuplicateObservedResult {
        test_id: "test/dup.js".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("FE-T262-1004"));
    assert!(msg.contains("test/dup.js"));
}

#[test]
fn test262_gate_error_missing_field_display() {
    let err = Test262GateError::MissingObservedField {
        test_id: "test/missing.js".to_string(),
        field: "es2020_clause",
    };
    let msg = err.to_string();
    assert!(msg.contains("FE-T262-1006"));
    assert!(msg.contains("test/missing.js"));
    assert!(msg.contains("es2020_clause"));
}

#[test]
fn test262_gate_error_io_display() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
    let err = Test262GateError::Io(io_err);
    let msg = err.to_string();
    assert!(msg.contains("FE-T262-1001"));
    assert!(msg.contains("file not found"));
}

// ── Test262GateError source() ───────────────────────────────────────

#[test]
fn test262_gate_error_io_source_returns_some() {
    let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
    let err = Test262GateError::Io(io_err);
    let dyn_err: &dyn std::error::Error = &err;
    assert!(dyn_err.source().is_some());
}

#[test]
fn test262_gate_error_non_io_source_returns_none() {
    let variants: Vec<Test262GateError> = vec![
        Test262GateError::InvalidConfig("x".to_string()),
        Test262GateError::InvalidProfile("x".to_string()),
        Test262GateError::DuplicateObservedResult {
            test_id: "t".to_string(),
        },
        Test262GateError::MissingObservedField {
            test_id: "t".to_string(),
            field: "f",
        },
    ];
    for err in &variants {
        let dyn_err: &dyn std::error::Error = err;
        assert!(dyn_err.source().is_none());
    }
}

// ── Test262GateError stable() codes are all unique ──────────────────

#[test]
fn test262_gate_error_all_variants_stable_codes() {
    let io_err = std::io::Error::other("io");
    let errors: Vec<Test262GateError> = vec![
        Test262GateError::InvalidConfig("a".to_string()),
        Test262GateError::InvalidProfile("b".to_string()),
        Test262GateError::DuplicateObservedResult {
            test_id: "t".to_string(),
        },
        Test262GateError::MissingObservedField {
            test_id: "t".to_string(),
            field: "f",
        },
        Test262GateError::Io(io_err),
    ];
    let codes: Vec<&str> = errors.iter().map(|e| e.stable().code).collect();
    assert_eq!(codes[0], "FE-T262-1001"); // InvalidConfig
    assert_eq!(codes[1], "FE-T262-1002"); // InvalidProfile
    assert_eq!(codes[2], "FE-T262-1004"); // DuplicateObservedResult
    assert_eq!(codes[3], "FE-T262-1006"); // MissingObservedField
    assert_eq!(codes[4], "FE-T262-1001"); // Io (maps to InvalidConfig code)
}

// ── Test262GateError From<io::Error> ────────────────────────────────

#[test]
fn test262_gate_error_from_io_error() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
    let gate_err: Test262GateError = io_err.into();
    let info = gate_err.stable();
    assert_eq!(info.code, "FE-T262-1001");
    assert!(info.detail.contains("not found"));
}

// ── WaiverSet default ───────────────────────────────────────────────

#[test]
fn waiver_set_default_has_correct_schema_and_empty_waivers() {
    let ws = Test262WaiverSet::default();
    assert_eq!(ws.schema_version, "franken-engine.test262-waiver.v1");
    assert!(ws.waivers.is_empty());
}

#[test]
fn waiver_set_default_validates() {
    let ws = Test262WaiverSet::default();
    assert!(ws.validate().is_ok());
}

// ── RunnerConfig default field values ───────────────────────────────

#[test]
fn runner_config_default_field_values() {
    let config = Test262RunnerConfig::default();
    assert_eq!(config.trace_prefix, "trace-test262");
    assert_eq!(config.policy_id, "policy-test262-es2020");
    assert_eq!(config.run_date, "1970-01-01");
    assert_eq!(config.worker_count, 8);
    assert_eq!(config.locale, "C");
    assert_eq!(config.timezone, "UTC");
    assert_eq!(config.gc_schedule, "deterministic");
    assert!(!config.acknowledge_pass_regression);
}

// ── Timeout outcome blocks release gate ─────────────────────────────

#[test]
fn timeout_outcome_blocks_release_gate() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed(
                "language/statements/for/timeout-test.js",
                "13.7",
                Test262ObservedOutcome::Timeout,
            )],
            None,
        )
        .expect("gate run");

    assert!(run.blocked, "timeout must block release gate");
    assert_eq!(run.summary.timed_out, 1);
    assert_eq!(run.summary.blocked_failures, 1);
}

#[test]
fn timeout_outcome_log_has_correct_error_code() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed(
                "language/statements/for/timeout-test.js",
                "13.7",
                Test262ObservedOutcome::Timeout,
            )],
            None,
        )
        .expect("gate run");

    let log = run
        .logs
        .iter()
        .find(|e| e.test_id == "language/statements/for/timeout-test.js")
        .expect("missing log");
    assert_eq!(log.error_code.as_deref(), Some("FE-T262-1008"));
    assert!(matches!(log.outcome, Test262Outcome::Timeout));
}

// ── Crash outcome blocks release gate ───────────────────────────────

#[test]
fn crash_outcome_blocks_release_gate() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed(
                "language/statements/for/crash-test.js",
                "13.7",
                Test262ObservedOutcome::Crash,
            )],
            None,
        )
        .expect("gate run");

    assert!(run.blocked, "crash must block release gate");
    assert_eq!(run.summary.crashed, 1);
    assert_eq!(run.summary.blocked_failures, 1);
}

#[test]
fn crash_outcome_log_has_correct_error_code() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed(
                "language/statements/for/crash-test.js",
                "13.7",
                Test262ObservedOutcome::Crash,
            )],
            None,
        )
        .expect("gate run");

    let log = run
        .logs
        .iter()
        .find(|e| e.test_id == "language/statements/for/crash-test.js")
        .expect("missing log");
    assert_eq!(log.error_code.as_deref(), Some("FE-T262-1009"));
    assert!(matches!(log.outcome, Test262Outcome::Crash));
}

// ── Waived timeout does not block ───────────────────────────────────

#[test]
fn waived_timeout_does_not_block() {
    let profile = load_profile();
    let pins = load_pins();
    let mut waivers = load_waivers();
    waivers.waivers.push(Test262Waiver {
        test_id: "language/statements/timeout-waived.js".to_string(),
        reason_code: Test262WaiverReason::NotYetImplemented,
        es2020_clause: "13.7".to_string(),
        tracking_bead: "bd-wt".to_string(),
        expiry_date: "2030-12-31".to_string(),
        reviewer: "test-admin".to_string(),
    });

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed(
                "language/statements/timeout-waived.js",
                "13.7",
                Test262ObservedOutcome::Timeout,
            )],
            None,
        )
        .expect("gate run");

    assert!(!run.blocked);
    assert_eq!(run.summary.waived, 1);
    assert_eq!(run.summary.timed_out, 0);
}

// ── Waived crash does not block ─────────────────────────────────────

#[test]
fn waived_crash_does_not_block() {
    let profile = load_profile();
    let pins = load_pins();
    let mut waivers = load_waivers();
    waivers.waivers.push(Test262Waiver {
        test_id: "language/statements/crash-waived.js".to_string(),
        reason_code: Test262WaiverReason::HostHookMissing,
        es2020_clause: "13.7".to_string(),
        tracking_bead: "bd-wc".to_string(),
        expiry_date: "2030-12-31".to_string(),
        reviewer: "test-admin".to_string(),
    });

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed(
                "language/statements/crash-waived.js",
                "13.7",
                Test262ObservedOutcome::Crash,
            )],
            None,
        )
        .expect("gate run");

    assert!(!run.blocked);
    assert_eq!(run.summary.waived, 1);
    assert_eq!(run.summary.crashed, 0);
}

// ── Waived failure log has FE-T262-1010 code ────────────────────────

#[test]
fn waived_failure_log_has_waived_error_code() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed(
                "language/expressions/optional-chaining/short-circuiting.js",
                "13.3.1",
                Test262ObservedOutcome::Fail,
            )],
            None,
        )
        .expect("gate run");

    let log = run
        .logs
        .iter()
        .find(|e| e.test_id == "language/expressions/optional-chaining/short-circuiting.js")
        .expect("missing log");
    assert_eq!(log.error_code.as_deref(), Some("FE-T262-1010"));
    assert!(matches!(log.outcome, Test262Outcome::Waived));
}

// ── Empty observed results produces empty run ───────────────────────

#[test]
fn empty_observed_results_produces_unblocked_run() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(&pins, &profile, &waivers, &[], None)
        .expect("gate run");

    assert!(!run.blocked);
    assert_eq!(run.summary.passed, 0);
    assert_eq!(run.summary.failed, 0);
    assert_eq!(run.summary.waived, 0);
    assert_eq!(run.summary.timed_out, 0);
    assert_eq!(run.summary.crashed, 0);
    assert_eq!(run.summary.total_profile_tests, 0);
    assert!(run.logs.is_empty());
}

// ── Mixed outcomes in a single run ──────────────────────────────────

#[test]
fn mixed_outcomes_all_counted_correctly() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[
                observed(
                    "language/expressions/optional-chaining/pass-1.js",
                    "13.3.1",
                    Test262ObservedOutcome::Pass,
                ),
                observed(
                    "language/statements/for/fail-1.js",
                    "13.7",
                    Test262ObservedOutcome::Fail,
                ),
                observed(
                    "language/statements/for/timeout-1.js",
                    "13.7",
                    Test262ObservedOutcome::Timeout,
                ),
                observed(
                    "language/statements/for/crash-1.js",
                    "13.7",
                    Test262ObservedOutcome::Crash,
                ),
            ],
            None,
        )
        .expect("gate run");

    assert!(run.blocked);
    assert_eq!(run.summary.passed, 1);
    assert_eq!(run.summary.failed, 1);
    assert_eq!(run.summary.timed_out, 1);
    assert_eq!(run.summary.crashed, 1);
    assert_eq!(run.summary.waived, 0);
    assert_eq!(run.summary.blocked_failures, 3);
    assert_eq!(run.summary.total_profile_tests, 4);
}

// ── Multiple failures in a single run ───────────────────────────────

#[test]
fn multiple_failures_all_block() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[
                observed(
                    "language/statements/for/fail-a.js",
                    "13.7",
                    Test262ObservedOutcome::Fail,
                ),
                observed(
                    "language/statements/for/fail-b.js",
                    "13.7",
                    Test262ObservedOutcome::Fail,
                ),
                observed(
                    "language/statements/for/fail-c.js",
                    "13.7",
                    Test262ObservedOutcome::Fail,
                ),
            ],
            None,
        )
        .expect("gate run");

    assert!(run.blocked);
    assert_eq!(run.summary.failed, 3);
    assert_eq!(run.summary.blocked_failures, 3);
}

// ── Non-selected tests are excluded from run ────────────────────────

#[test]
fn non_selected_tests_excluded_from_summary() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[
                observed(
                    "language/expressions/optional-chaining/selected.js",
                    "13.3.1",
                    Test262ObservedOutcome::Pass,
                ),
                observed(
                    "harness/internal-test.js",
                    "N/A",
                    Test262ObservedOutcome::Fail,
                ),
            ],
            None,
        )
        .expect("gate run");

    assert!(!run.blocked);
    assert_eq!(run.summary.total_profile_tests, 1);
    assert_eq!(run.summary.passed, 1);
    assert_eq!(run.summary.failed, 0);
}

// ── Excluded tests are not counted ──────────────────────────────────

#[test]
fn excluded_tests_not_counted_in_run() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[
                observed(
                    "language/annexB/legacy/escape.js",
                    "B.2",
                    Test262ObservedOutcome::Fail,
                ),
                observed(
                    "language/expressions/pass.js",
                    "13.3",
                    Test262ObservedOutcome::Pass,
                ),
            ],
            None,
        )
        .expect("gate run");

    assert!(!run.blocked);
    assert_eq!(run.summary.total_profile_tests, 1);
    assert_eq!(run.summary.passed, 1);
    assert_eq!(run.summary.failed, 0);
}

// ── Duplicate observed test_id is an error ──────────────────────────

#[test]
fn duplicate_observed_test_id_returns_error() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let err = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[
                observed("language/a.js", "13.1", Test262ObservedOutcome::Pass),
                observed("language/a.js", "13.1", Test262ObservedOutcome::Pass),
            ],
            None,
        )
        .expect_err("should fail on duplicate");

    let info = err.stable();
    assert_eq!(info.code, "FE-T262-1004");
    assert!(info.detail.contains("language/a.js"));
}

// ── Empty test_id is an error ───────────────────────────────────────

#[test]
fn empty_test_id_returns_error() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let err = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed("", "13.1", Test262ObservedOutcome::Pass)],
            None,
        )
        .expect_err("should fail on empty test_id");

    let info = err.stable();
    assert_eq!(info.code, "FE-T262-1006");
}

// ── Empty es2020_clause is an error ─────────────────────────────────

#[test]
fn empty_es2020_clause_returns_error() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let err = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed("language/a.js", "", Test262ObservedOutcome::Pass)],
            None,
        )
        .expect_err("should fail on empty clause");

    let info = err.stable();
    assert_eq!(info.code, "FE-T262-1006");
}

// ── Whitespace-only test_id is an error ─────────────────────────────

#[test]
fn whitespace_only_test_id_returns_error() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let err = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed("   ", "13.1", Test262ObservedOutcome::Pass)],
            None,
        )
        .expect_err("should fail on whitespace test_id");

    let info = err.stable();
    assert_eq!(info.code, "FE-T262-1006");
}

// ── Whitespace-only clause is an error ──────────────────────────────

#[test]
fn whitespace_only_clause_returns_error() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let err = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed(
                "language/a.js",
                "  ",
                Test262ObservedOutcome::Pass,
            )],
            None,
        )
        .expect_err("should fail on whitespace clause");

    let info = err.stable();
    assert_eq!(info.code, "FE-T262-1006");
}

// ── Run ID starts with test262- prefix ──────────────────────────────

#[test]
fn run_id_starts_with_test262_prefix() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed(
                "language/a.js",
                "13.1",
                Test262ObservedOutcome::Pass,
            )],
            None,
        )
        .expect("gate run");

    assert!(run.run_id.starts_with("test262-"));
    assert!(run.summary.run_id.starts_with("test262-"));
    assert_eq!(run.run_id, run.summary.run_id);
}

// ── Run ID is deterministic ─────────────────────────────────────────

#[test]
fn run_id_is_deterministic_for_same_inputs() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let obs = vec![observed(
        "language/a.js",
        "13.1",
        Test262ObservedOutcome::Pass,
    )];

    let run1 = runner("2026-02-22", false)
        .run(&pins, &profile, &waivers, &obs, None)
        .expect("gate run 1");
    let run2 = runner("2026-02-22", false)
        .run(&pins, &profile, &waivers, &obs, None)
        .expect("gate run 2");

    assert_eq!(run1.run_id, run2.run_id);
}

// ── Log events have correct fields ──────────────────────────────────

#[test]
fn log_events_have_correct_component_and_event() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed(
                "language/a.js",
                "13.1",
                Test262ObservedOutcome::Pass,
            )],
            None,
        )
        .expect("gate run");

    for log in &run.logs {
        assert_eq!(log.component, "test262_release_gate");
        assert_eq!(log.event, "test262_case_evaluated");
        assert!(!log.trace_id.is_empty());
        assert!(!log.decision_id.is_empty());
    }
}

#[test]
fn log_events_policy_id_matches_config() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed(
                "language/a.js",
                "13.1",
                Test262ObservedOutcome::Pass,
            )],
            None,
        )
        .expect("gate run");

    for log in &run.logs {
        assert_eq!(log.policy_id, "policy-test262-es2020");
    }
}

// ── Summary hashes are deterministic ────────────────────────────────

#[test]
fn summary_hashes_are_deterministic() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let obs = vec![observed(
        "language/a.js",
        "13.1",
        Test262ObservedOutcome::Pass,
    )];

    let run1 = runner("2026-02-22", false)
        .run(&pins, &profile, &waivers, &obs, None)
        .expect("run 1");
    let run2 = runner("2026-02-22", false)
        .run(&pins, &profile, &waivers, &obs, None)
        .expect("run 2");

    assert_eq!(run1.summary.profile_hash, run2.summary.profile_hash);
    assert_eq!(run1.summary.waiver_hash, run2.summary.waiver_hash);
    assert_eq!(run1.summary.pin_hash, run2.summary.pin_hash);
    assert_eq!(run1.summary.env_fingerprint, run2.summary.env_fingerprint);
}

#[test]
fn summary_hashes_are_64_char_hex() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed(
                "language/a.js",
                "13.1",
                Test262ObservedOutcome::Pass,
            )],
            None,
        )
        .expect("gate run");

    assert_eq!(run.summary.profile_hash.len(), 64);
    assert_eq!(run.summary.waiver_hash.len(), 64);
    assert_eq!(run.summary.pin_hash.len(), 64);
    assert_eq!(run.summary.env_fingerprint.len(), 64);
    assert!(
        run.summary
            .profile_hash
            .chars()
            .all(|c| c.is_ascii_hexdigit())
    );
    assert!(
        run.summary
            .waiver_hash
            .chars()
            .all(|c| c.is_ascii_hexdigit())
    );
    assert!(run.summary.pin_hash.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(
        run.summary
            .env_fingerprint
            .chars()
            .all(|c| c.is_ascii_hexdigit())
    );
}

// ── HWM boundary: equal pass_count means no regression ──────────────

#[test]
fn hwm_equal_pass_count_no_regression() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let previous_hwm = Test262HighWaterMark {
        schema_version: "franken-engine.test262-high-water-mark.v1".to_string(),
        profile_hash: "abc".to_string(),
        pass_count: 1,
        recorded_at_utc: "2026-02-21T00:00:00Z".to_string(),
    };

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed(
                "language/a.js",
                "13.1",
                Test262ObservedOutcome::Pass,
            )],
            Some(&previous_hwm),
        )
        .expect("gate run");

    assert!(!run.blocked);
    assert!(run.summary.pass_regression_warning.is_none());
}

// ── HWM next takes max of previous and current ─────────────────────

#[test]
fn hwm_next_takes_current_when_higher() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[
                observed("language/a.js", "13.1", Test262ObservedOutcome::Pass),
                observed("language/b.js", "13.2", Test262ObservedOutcome::Pass),
                observed("language/c.js", "13.3", Test262ObservedOutcome::Pass),
            ],
            None,
        )
        .expect("gate run");

    let previous = Test262HighWaterMark {
        schema_version: "franken-engine.test262-high-water-mark.v1".to_string(),
        profile_hash: "abc".to_string(),
        pass_count: 2,
        recorded_at_utc: "2026-02-21T00:00:00Z".to_string(),
    };

    let hwm = next_high_water_mark(&run, Some(&previous));
    assert_eq!(hwm.pass_count, 3); // max(3, 2)
}

#[test]
fn hwm_next_takes_previous_when_higher() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed(
                "language/a.js",
                "13.1",
                Test262ObservedOutcome::Pass,
            )],
            None,
        )
        .expect("gate run");

    let previous = Test262HighWaterMark {
        schema_version: "franken-engine.test262-high-water-mark.v1".to_string(),
        profile_hash: "abc".to_string(),
        pass_count: 50,
        recorded_at_utc: "2026-02-21T00:00:00Z".to_string(),
    };

    let hwm = next_high_water_mark(&run, Some(&previous));
    assert_eq!(hwm.pass_count, 50); // max(1, 50)
}

#[test]
fn hwm_next_has_correct_schema_version() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed(
                "language/a.js",
                "13.1",
                Test262ObservedOutcome::Pass,
            )],
            None,
        )
        .expect("gate run");

    let hwm = next_high_water_mark(&run, None);
    assert_eq!(
        hwm.schema_version,
        "franken-engine.test262-high-water-mark.v1"
    );
}

// ── Pass regression acknowledgement log event ───────────────────────

#[test]
fn pass_regression_creates_regression_ack_log_event() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let previous_hwm = Test262HighWaterMark {
        schema_version: "franken-engine.test262-high-water-mark.v1".to_string(),
        profile_hash: "abc".to_string(),
        pass_count: 10,
        recorded_at_utc: "2026-02-21T00:00:00Z".to_string(),
    };

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed(
                "language/a.js",
                "13.1",
                Test262ObservedOutcome::Pass,
            )],
            Some(&previous_hwm),
        )
        .expect("gate run");

    let ack_log = run
        .logs
        .iter()
        .find(|e| e.event == "pass_regression_ack_missing")
        .expect("missing regression ack log");
    assert_eq!(ack_log.error_code.as_deref(), Some("FE-T262-1007"));
    assert_eq!(ack_log.test_id, "__meta__/pass_regression");
    assert!(matches!(ack_log.outcome, Test262Outcome::Fail));
}

#[test]
fn acknowledged_regression_does_not_create_ack_log_event() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let previous_hwm = Test262HighWaterMark {
        schema_version: "franken-engine.test262-high-water-mark.v1".to_string(),
        profile_hash: "abc".to_string(),
        pass_count: 10,
        recorded_at_utc: "2026-02-21T00:00:00Z".to_string(),
    };

    let run = runner("2026-02-22", true)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed(
                "language/a.js",
                "13.1",
                Test262ObservedOutcome::Pass,
            )],
            Some(&previous_hwm),
        )
        .expect("gate run");

    let ack_log = run
        .logs
        .iter()
        .find(|e| e.event == "pass_regression_ack_missing");
    assert!(ack_log.is_none());
}

// ── Worker assignment edge cases ────────────────────────────────────

#[test]
fn worker_assignment_more_workers_than_tests() {
    let test_ids = vec!["a.js".to_string(), "b.js".to_string()];
    let assignments = deterministic_worker_assignments(&test_ids, 100);
    assert_eq!(assignments.len(), 2);
    // Each test gets a unique worker
    assert_ne!(assignments[0].worker_index, assignments[1].worker_index);
}

#[test]
fn worker_assignment_equal_workers_and_tests() {
    let test_ids: Vec<String> = (0..5).map(|i| format!("test-{i:03}.js")).collect();
    let assignments = deterministic_worker_assignments(&test_ids, 5);
    assert_eq!(assignments.len(), 5);
    // Each worker gets exactly one test
    let mut workers: Vec<usize> = assignments.iter().map(|a| a.worker_index).collect();
    workers.sort();
    assert_eq!(workers, vec![0, 1, 2, 3, 4]);
}

#[test]
fn worker_assignment_queue_indices_increment_per_worker() {
    let test_ids: Vec<String> = (0..9).map(|i| format!("test-{i:03}.js")).collect();
    let assignments = deterministic_worker_assignments(&test_ids, 3);
    // Worker 0 gets tests 0, 3, 6 with queue indices 0, 1, 2
    let w0_queues: Vec<usize> = assignments
        .iter()
        .filter(|a| a.worker_index == 0)
        .map(|a| a.queue_index)
        .collect();
    assert_eq!(w0_queues, vec![0, 1, 2]);
}

#[test]
fn worker_assignment_preserves_sorted_order() {
    let test_ids = vec!["z.js".to_string(), "a.js".to_string(), "m.js".to_string()];
    let assignments = deterministic_worker_assignments(&test_ids, 3);
    assert_eq!(assignments[0].test_id, "a.js");
    assert_eq!(assignments[1].test_id, "m.js");
    assert_eq!(assignments[2].test_id, "z.js");
}

// ── Observed result with error_code and error_detail ────────────────

#[test]
fn observed_result_with_error_fields_serde() {
    let result = Test262ObservedResult {
        test_id: "test/err.js".to_string(),
        es2020_clause: "13.1".to_string(),
        outcome: Test262ObservedOutcome::Fail,
        duration_us: 500,
        error_code: Some("CUSTOM-ERR".to_string()),
        error_detail: Some("detailed error message".to_string()),
    };
    let json = serde_json::to_string(&result).expect("serialize");
    let recovered: Test262ObservedResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(result, recovered);
}

#[test]
fn observed_result_zero_duration_serde() {
    let result = Test262ObservedResult {
        test_id: "test/zero.js".to_string(),
        es2020_clause: "1.0".to_string(),
        outcome: Test262ObservedOutcome::Pass,
        duration_us: 0,
        error_code: None,
        error_detail: None,
    };
    let json = serde_json::to_string(&result).expect("serialize");
    let recovered: Test262ObservedResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.duration_us, 0);
}

// ── Profile classify with multiple include/exclude patterns ─────────

#[test]
fn profile_classify_multiple_includes_both_match() {
    let profile = load_profile();
    // Profile has includes for "language/*" and "built-ins/*"
    assert!(matches!(
        profile.classify("language/expressions/test.js"),
        ProfileDecision::Included
    ));
    assert!(matches!(
        profile.classify("built-ins/Array/basic.js"),
        ProfileDecision::Included
    ));
}

#[test]
fn profile_classify_excluded_overrides_included() {
    let profile = load_profile();
    // "language/annexB/*" is excluded
    assert!(matches!(
        profile.classify("language/annexB/legacy/test.js"),
        ProfileDecision::Excluded { .. }
    ));
}

#[test]
fn profile_classify_intl402_excluded() {
    let profile = load_profile();
    assert!(matches!(
        profile.classify("built-ins/intl402/DateTimeFormat/test.js"),
        ProfileDecision::Excluded { .. }
    ));
}

#[test]
fn profile_classify_proposals_excluded() {
    let profile = load_profile();
    assert!(matches!(
        profile.classify("proposals/temporal/test.js"),
        ProfileDecision::Excluded { .. }
    ));
}

// ── Evidence collector with blocked run ─────────────────────────────

#[test]
fn evidence_collector_with_blocked_run() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[
                observed("language/a.js", "13.1", Test262ObservedOutcome::Pass),
                observed("language/b.js", "13.2", Test262ObservedOutcome::Fail),
            ],
            None,
        )
        .expect("gate run");

    assert!(run.blocked);

    let unique = format!(
        "blocked-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    );
    let temp_root = fixture("artifacts")
        .join("test262_release_gate")
        .join(unique);

    let collector = Test262EvidenceCollector::new(&temp_root).expect("collector");
    let hwm = next_high_water_mark(&run, None);
    let artifacts = collector.collect(&run, &hwm).expect("collect");

    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.evidence_path.exists());
    assert!(artifacts.high_water_mark_path.exists());

    let evidence = fs::read_to_string(&artifacts.evidence_path).expect("read evidence");
    assert!(evidence.contains("test262_case_evaluated"));
    assert!(evidence.contains("FE-T262-1005")); // unwaived failure code
}

// ── Evidence collector with multiple outcome types ──────────────────

#[test]
fn evidence_collector_with_mixed_outcomes() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[
                observed("language/a.js", "13.1", Test262ObservedOutcome::Pass),
                observed(
                    "language/expressions/optional-chaining/short-circuiting.js",
                    "13.3.1",
                    Test262ObservedOutcome::Fail,
                ),
            ],
            None,
        )
        .expect("gate run");

    let unique = format!(
        "mixed-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    );
    let temp_root = fixture("artifacts")
        .join("test262_release_gate")
        .join(unique);

    let collector = Test262EvidenceCollector::new(&temp_root).expect("collector");
    let hwm = next_high_water_mark(&run, None);
    let artifacts = collector.collect(&run, &hwm).expect("collect");

    let evidence = fs::read_to_string(&artifacts.evidence_path).expect("read evidence");
    // Should contain both the summary line and individual test log lines
    let lines: Vec<&str> = evidence.lines().collect();
    assert!(lines.len() >= 3); // summary + 2 tests
}

// ── PinSet validation edge cases ────────────────────────────────────

#[test]
fn pin_set_with_uppercase_hex_commit_invalid() {
    let pins = Test262PinSet {
        schema_version: "franken-engine.test262-pin.v1".to_string(),
        source_repo: "tc39/test262".to_string(),
        es_profile: "ES2020".to_string(),
        test262_commit: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
    };
    // Uppercase hex is valid hex, so should pass
    assert!(pins.validate().is_ok());
}

#[test]
fn pin_set_with_short_commit_invalid() {
    let pins = Test262PinSet {
        schema_version: "franken-engine.test262-pin.v1".to_string(),
        source_repo: "tc39/test262".to_string(),
        es_profile: "ES2020".to_string(),
        test262_commit: "abcdef".to_string(),
    };
    assert!(pins.validate().is_err());
}

#[test]
fn pin_set_with_non_hex_commit_invalid() {
    let pins = Test262PinSet {
        schema_version: "franken-engine.test262-pin.v1".to_string(),
        source_repo: "tc39/test262".to_string(),
        es_profile: "ES2020".to_string(),
        test262_commit: "g".repeat(40),
    };
    assert!(pins.validate().is_err());
}

// ── GateRun serde roundtrip ─────────────────────────────────────────

#[test]
fn gate_run_full_serde_round_trip() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[
                observed("language/a.js", "13.1", Test262ObservedOutcome::Pass),
                observed("language/b.js", "13.2", Test262ObservedOutcome::Fail),
            ],
            None,
        )
        .expect("gate run");

    let json = serde_json::to_string(&run).expect("serialize");
    let recovered: Test262GateRun = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(run.run_id, recovered.run_id);
    assert_eq!(run.blocked, recovered.blocked);
    assert_eq!(run.logs.len(), recovered.logs.len());
    assert_eq!(run.summary.passed, recovered.summary.passed);
    assert_eq!(run.summary.failed, recovered.summary.failed);
}

// ── GateRunner default is valid default config ──────────────────────

#[test]
fn gate_runner_default_clone() {
    let runner1 = Test262GateRunner::default();
    let runner2 = runner1.clone();
    assert_eq!(runner1.config.run_date, runner2.config.run_date);
    assert_eq!(runner1.config.worker_count, runner2.config.worker_count);
}

// ── Observed result with error_detail on passing test ───────────────

#[test]
fn pass_result_with_custom_error_detail_carried_through() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let mut obs = observed("language/a.js", "13.1", Test262ObservedOutcome::Pass);
    obs.error_detail = Some("custom diagnostic info".to_string());

    let run = runner("2026-02-22", false)
        .run(&pins, &profile, &waivers, &[obs], None)
        .expect("gate run");

    let log = &run.logs[0];
    assert_eq!(log.error_detail.as_deref(), Some("custom diagnostic info"));
}

// ── HighWaterMark write and load round trip via evidence collector ───

#[test]
fn hwm_written_by_collector_is_loadable() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[
                observed("language/a.js", "13.1", Test262ObservedOutcome::Pass),
                observed("language/b.js", "13.2", Test262ObservedOutcome::Pass),
            ],
            None,
        )
        .expect("gate run");

    let unique = format!(
        "hwm-load-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    );
    let temp_root = fixture("artifacts")
        .join("test262_release_gate")
        .join(unique);

    let collector = Test262EvidenceCollector::new(&temp_root).expect("collector");
    let hwm = next_high_water_mark(&run, None);
    let artifacts = collector.collect(&run, &hwm).expect("collect");

    let loaded = Test262HighWaterMark::load_json(&artifacts.high_water_mark_path)
        .expect("load")
        .expect("hwm present");
    assert_eq!(loaded.pass_count, hwm.pass_count);
    assert_eq!(loaded.schema_version, hwm.schema_version);
    assert_eq!(loaded.profile_hash, hwm.profile_hash);
}

// ── HWM load_json from nonexistent file returns None ────────────────

#[test]
fn hwm_load_json_nonexistent_returns_none() {
    let path = fixture("artifacts")
        .join("test262_release_gate")
        .join("does_not_exist.json");
    let result = Test262HighWaterMark::load_json(&path).expect("should not error");
    assert!(result.is_none());
}

// ── Log event worker_index is correctly assigned ────────────────────

#[test]
fn log_events_worker_index_matches_deterministic_assignment() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[
                observed("language/a.js", "13.1", Test262ObservedOutcome::Pass),
                observed("language/b.js", "13.2", Test262ObservedOutcome::Pass),
                observed("language/c.js", "13.3", Test262ObservedOutcome::Pass),
            ],
            None,
        )
        .expect("gate run");

    // With default 8 workers and 3 tests, each test should get a different worker
    let workers: Vec<usize> = run.logs.iter().map(|l| l.worker_index).collect();
    assert_eq!(workers.len(), 3);
    // All workers should be < 8 (default worker count)
    assert!(workers.iter().all(|&w| w < 8));
}

// ── WaiverReason serde snake_case values ────────────────────────────

#[test]
fn waiver_reason_serde_snake_case_values() {
    assert_eq!(
        serde_json::to_string(&Test262WaiverReason::HarnessGap).expect("serialize"),
        "\"harness_gap\""
    );
    assert_eq!(
        serde_json::to_string(&Test262WaiverReason::HostHookMissing).expect("serialize"),
        "\"host_hook_missing\""
    );
    assert_eq!(
        serde_json::to_string(&Test262WaiverReason::IntentionalDivergence).expect("serialize"),
        "\"intentional_divergence\""
    );
    assert_eq!(
        serde_json::to_string(&Test262WaiverReason::NotYetImplemented).expect("serialize"),
        "\"not_yet_implemented\""
    );
}
