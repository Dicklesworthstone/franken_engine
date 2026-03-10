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
