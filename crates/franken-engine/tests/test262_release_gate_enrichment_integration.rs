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
    clippy::identity_op
)]

use frankenengine_engine::test262_release_gate::{
    DeterministicWorkerAssignment, ProfileDecision, Test262CollectedArtifacts, Test262GateError,
    Test262GateRun, Test262GateRunner, Test262HighWaterMark, Test262ObservedOutcome,
    Test262ObservedResult, Test262Outcome, Test262PassRegressionWarning, Test262PinSet,
    Test262Profile, Test262ProfileExclude, Test262ProfileInclude, Test262RunSummary,
    Test262RunnerConfig, Test262Waiver, Test262WaiverReason, Test262WaiverSet,
    deterministic_worker_assignments, next_high_water_mark,
};

// ── Helpers ──────────────────────────────────────────────────────────────

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

// =========================================================================
// A. Test262GateError Display and Error trait
// =========================================================================

#[test]
fn enrichment_gate_error_io_display() {
    let err = Test262GateError::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "file not found",
    ));
    let info = err.stable();
    assert!(info.detail.contains("file not found"));
    assert!(info.code.starts_with("FE-T262"));
}

#[test]
fn enrichment_gate_error_io_source() {
    let err = Test262GateError::Io(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "denied",
    ));
    let source = std::error::Error::source(&err);
    assert!(source.is_some());
}

#[test]
fn enrichment_gate_error_non_io_no_source() {
    let err = Test262GateError::InvalidConfig("bad".into());
    let source = std::error::Error::source(&err);
    assert!(source.is_none());
}

#[test]
fn enrichment_gate_error_display_all_variants() {
    let errors: Vec<Test262GateError> = vec![
        Test262GateError::InvalidConfig("config err".into()),
        Test262GateError::DuplicateObservedResult {
            test_id: "dup-test".into(),
        },
        Test262GateError::MissingObservedField {
            test_id: "miss-test".into(),
            field: "es2020_clause",
        },
        Test262GateError::InvalidProfile("bad profile".into()),
        Test262GateError::Io(std::io::Error::other("io err")),
    ];
    let mut displays = std::collections::BTreeSet::new();
    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.is_empty());
        assert!(msg.contains("FE-T262"));
        displays.insert(msg);
    }
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_gate_error_implements_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(Test262GateError::InvalidConfig("test".into()));
    assert!(!err.to_string().is_empty());
}

// =========================================================================
// B. Test262PassRegressionWarning serde
// =========================================================================

#[test]
fn enrichment_pass_regression_warning_serde() {
    let warning = Test262PassRegressionWarning {
        previous_high_water_mark: 100,
        current_pass_count: 90,
        acknowledgement_required: true,
        acknowledged: false,
    };
    let json = serde_json::to_string(&warning).unwrap();
    let back: Test262PassRegressionWarning = serde_json::from_str(&json).unwrap();
    assert_eq!(warning, back);
}

#[test]
fn enrichment_pass_regression_warning_acknowledged_serde() {
    let warning = Test262PassRegressionWarning {
        previous_high_water_mark: 50,
        current_pass_count: 30,
        acknowledgement_required: true,
        acknowledged: true,
    };
    let json = serde_json::to_string(&warning).unwrap();
    let back: Test262PassRegressionWarning = serde_json::from_str(&json).unwrap();
    assert!(back.acknowledged);
}

// =========================================================================
// C. Test262RunnerConfig serde and validation edge cases
// =========================================================================

#[test]
fn enrichment_runner_config_serde_roundtrip() {
    let config = valid_config();
    let json = serde_json::to_string(&config).unwrap();
    let back: Test262RunnerConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn enrichment_runner_config_default_serde() {
    let config = Test262RunnerConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: Test262RunnerConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn enrichment_runner_empty_trace_prefix_fails() {
    let mut config = valid_config();
    config.trace_prefix = String::new();
    let runner = Test262GateRunner { config };
    let err = runner
        .run(
            &valid_pin_set(),
            &valid_profile(),
            &valid_waiver_set(),
            &[],
            None,
        )
        .unwrap_err();
    assert!(err.to_string().contains("trace_prefix"));
}

#[test]
fn enrichment_runner_empty_policy_id_fails() {
    let mut config = valid_config();
    config.policy_id = String::new();
    let runner = Test262GateRunner { config };
    let err = runner
        .run(
            &valid_pin_set(),
            &valid_profile(),
            &valid_waiver_set(),
            &[],
            None,
        )
        .unwrap_err();
    assert!(err.to_string().contains("policy_id"));
}

#[test]
fn enrichment_runner_zero_workers_fails() {
    let mut config = valid_config();
    config.worker_count = 0;
    let runner = Test262GateRunner { config };
    let err = runner
        .run(
            &valid_pin_set(),
            &valid_profile(),
            &valid_waiver_set(),
            &[],
            None,
        )
        .unwrap_err();
    assert!(err.to_string().contains("worker_count"));
}

#[test]
fn enrichment_runner_bad_run_date_format_fails() {
    let mut config = valid_config();
    config.run_date = "Jan 15 2026".into();
    let runner = Test262GateRunner { config };
    let err = runner
        .run(
            &valid_pin_set(),
            &valid_profile(),
            &valid_waiver_set(),
            &[],
            None,
        )
        .unwrap_err();
    assert!(err.to_string().contains("run_date"));
}

// =========================================================================
// D. Worker assignment queue_index correctness
// =========================================================================

#[test]
fn enrichment_worker_assignments_queue_index_increments() {
    let test_ids: Vec<String> = (0..6).map(|i| format!("test_{i:03}")).collect();
    let assignments = deterministic_worker_assignments(&test_ids, 2);
    // Worker 0 gets tests 0, 2, 4 with queue_index 0, 1, 2
    let w0: Vec<usize> = assignments
        .iter()
        .filter(|a| a.worker_index == 0)
        .map(|a| a.queue_index)
        .collect();
    assert_eq!(w0, vec![0, 1, 2]);
    // Worker 1 gets tests 1, 3, 5 with queue_index 0, 1, 2
    let w1: Vec<usize> = assignments
        .iter()
        .filter(|a| a.worker_index == 1)
        .map(|a| a.queue_index)
        .collect();
    assert_eq!(w1, vec![0, 1, 2]);
}

#[test]
fn enrichment_worker_assignments_more_workers_than_tests() {
    let test_ids = vec!["only_test".to_string()];
    let assignments = deterministic_worker_assignments(&test_ids, 10);
    assert_eq!(assignments.len(), 1);
    assert_eq!(assignments[0].worker_index, 0);
    assert_eq!(assignments[0].queue_index, 0);
}

#[test]
fn enrichment_worker_assignments_serde_roundtrip() {
    let a = DeterministicWorkerAssignment {
        test_id: "test/foo".into(),
        worker_index: 3,
        queue_index: 7,
    };
    let json = serde_json::to_string(&a).unwrap();
    let back: DeterministicWorkerAssignment = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

// =========================================================================
// E. next_high_water_mark edge cases
// =========================================================================

#[test]
fn enrichment_hwm_same_count_keeps_same() {
    let run = make_simple_run(5, false);
    let prev = Test262HighWaterMark {
        schema_version: "franken-engine.test262-high-water-mark.v1".into(),
        profile_hash: run.summary.profile_hash.clone(),
        pass_count: 5,
        recorded_at_utc: "2026-01-01T00:00:00Z".into(),
    };
    let hwm = next_high_water_mark(&run, Some(&prev));
    assert_eq!(hwm.pass_count, 5);
}

#[test]
fn enrichment_hwm_schema_version_present() {
    let run = make_simple_run(3, false);
    let hwm = next_high_water_mark(&run, None);
    assert!(!hwm.schema_version.is_empty());
    assert!(hwm.schema_version.contains("high-water-mark"));
}

#[test]
fn enrichment_hwm_recorded_at_utc_nonempty() {
    let run = make_simple_run(1, false);
    let hwm = next_high_water_mark(&run, None);
    assert!(!hwm.recorded_at_utc.is_empty());
}

// =========================================================================
// F. Profile classify with multiple includes/excludes
// =========================================================================

#[test]
fn enrichment_profile_classify_multiple_includes() {
    let prof = Test262Profile {
        schema_version: "franken-engine.test262-profile.v1".into(),
        profile_name: "multi".into(),
        es_profile: "ES2020".into(),
        includes: vec![
            Test262ProfileInclude {
                pattern: "built-ins/Array/*".into(),
                rationale: "array".into(),
                normative_clause: "22.1".into(),
            },
            Test262ProfileInclude {
                pattern: "built-ins/Object/*".into(),
                rationale: "object".into(),
                normative_clause: "19.1".into(),
            },
        ],
        excludes: vec![],
    };
    assert_eq!(
        prof.classify("built-ins/Array/from"),
        ProfileDecision::Included
    );
    assert_eq!(
        prof.classify("built-ins/Object/keys"),
        ProfileDecision::Included
    );
    assert_eq!(
        prof.classify("built-ins/String/trim"),
        ProfileDecision::NotSelected
    );
}

#[test]
fn enrichment_profile_classify_exclude_rationale() {
    let prof = Test262Profile {
        schema_version: "franken-engine.test262-profile.v1".into(),
        profile_name: "with-excl".into(),
        es_profile: "ES2020".into(),
        includes: vec![Test262ProfileInclude {
            pattern: "built-ins/Array/*".into(),
            rationale: "all array".into(),
            normative_clause: "22.1".into(),
        }],
        excludes: vec![Test262ProfileExclude {
            pattern: "built-ins/Array/from".into(),
            rationale: "known divergence".into(),
            normative_clause: "22.1.2.1".into(),
        }],
    };
    match prof.classify("built-ins/Array/from") {
        ProfileDecision::Excluded { rationale } => {
            assert_eq!(rationale, "known divergence");
        }
        other => panic!("expected Excluded, got {:?}", other),
    }
}

// =========================================================================
// G. Waiver timeout/crash waived scenarios
// =========================================================================

#[test]
fn enrichment_runner_timeout_waived_not_blocked() {
    let pins = valid_pin_set();
    let prof = valid_profile();
    let mut waivers = valid_waiver_set();
    waivers.waivers.push(Test262Waiver {
        test_id: "built-ins/Array/from".into(),
        reason_code: Test262WaiverReason::HarnessGap,
        es2020_clause: "22.1.2.1".into(),
        tracking_bead: "bd-timeout".into(),
        expiry_date: "2027-12-31".into(),
        reviewer: "eng".into(),
    });
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
    assert!(!run.blocked);
    assert_eq!(run.summary.waived, 1);
    assert_eq!(run.summary.timed_out, 0);
}

#[test]
fn enrichment_runner_crash_waived_not_blocked() {
    let pins = valid_pin_set();
    let prof = valid_profile();
    let mut waivers = valid_waiver_set();
    waivers.waivers.push(Test262Waiver {
        test_id: "built-ins/Array/from".into(),
        reason_code: Test262WaiverReason::HostHookMissing,
        es2020_clause: "22.1.2.1".into(),
        tracking_bead: "bd-crash".into(),
        expiry_date: "2027-12-31".into(),
        reviewer: "eng".into(),
    });
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
    assert!(!run.blocked);
    assert_eq!(run.summary.waived, 1);
    assert_eq!(run.summary.crashed, 0);
}

// =========================================================================
// H. Missing observed field errors
// =========================================================================

#[test]
fn enrichment_runner_missing_test_id_errors() {
    let pins = valid_pin_set();
    let prof = valid_profile();
    let waivers = valid_waiver_set();
    let config = valid_config();

    let observed = vec![Test262ObservedResult {
        test_id: String::new(),
        es2020_clause: "22.1".into(),
        outcome: Test262ObservedOutcome::Pass,
        duration_us: 100,
        error_code: None,
        error_detail: None,
    }];

    let runner = Test262GateRunner { config };
    let err = runner
        .run(&pins, &prof, &waivers, &observed, None)
        .unwrap_err();
    let info = err.stable();
    assert!(info.detail.contains("test_id"));
}

#[test]
fn enrichment_runner_missing_es2020_clause_errors() {
    let pins = valid_pin_set();
    let prof = valid_profile();
    let waivers = valid_waiver_set();
    let config = valid_config();

    let observed = vec![Test262ObservedResult {
        test_id: "built-ins/Array/from".into(),
        es2020_clause: String::new(),
        outcome: Test262ObservedOutcome::Pass,
        duration_us: 100,
        error_code: None,
        error_detail: None,
    }];

    let runner = Test262GateRunner { config };
    let err = runner
        .run(&pins, &prof, &waivers, &observed, None)
        .unwrap_err();
    let info = err.stable();
    assert!(info.detail.contains("es2020_clause"));
}

// =========================================================================
// I. Log event worker_index
// =========================================================================

#[test]
fn enrichment_log_event_worker_index_within_bounds() {
    let pins = valid_pin_set();
    let prof = Test262Profile {
        schema_version: "franken-engine.test262-profile.v1".into(),
        profile_name: "broad".into(),
        es_profile: "ES2020".into(),
        includes: vec![Test262ProfileInclude {
            pattern: "*".into(),
            rationale: "all".into(),
            normative_clause: "all".into(),
        }],
        excludes: vec![],
    };
    let waivers = valid_waiver_set();
    let mut config = valid_config();
    config.worker_count = 3;

    let observed: Vec<Test262ObservedResult> = (0..9)
        .map(|i| observed_pass(&format!("test/case_{i:03}")))
        .collect();

    let runner = Test262GateRunner { config };
    let run = runner.run(&pins, &prof, &waivers, &observed, None).unwrap();
    for log in &run.logs {
        assert!(
            log.worker_index < 3,
            "worker_index {} >= 3",
            log.worker_index
        );
    }
}

#[test]
fn enrichment_log_event_policy_id_from_config() {
    let pins = valid_pin_set();
    let prof = valid_profile();
    let waivers = valid_waiver_set();
    let config = valid_config();

    let observed = vec![observed_pass("built-ins/Array/from")];
    let runner = Test262GateRunner { config };
    let run = runner.run(&pins, &prof, &waivers, &observed, None).unwrap();

    for log in &run.logs {
        assert_eq!(log.policy_id, "policy-test262-es2020");
    }
}

// =========================================================================
// J. Test262CollectedArtifacts serde
// =========================================================================

#[test]
fn enrichment_collected_artifacts_serde_roundtrip() {
    let artifacts = Test262CollectedArtifacts {
        run_manifest_path: "/tmp/run_manifest.json".into(),
        evidence_path: "/tmp/evidence.jsonl".into(),
        high_water_mark_path: "/tmp/hwm.json".into(),
    };
    let json = serde_json::to_string(&artifacts).unwrap();
    let back: Test262CollectedArtifacts = serde_json::from_str(&json).unwrap();
    assert_eq!(artifacts, back);
}

// =========================================================================
// K. Debug formatting
// =========================================================================

#[test]
fn enrichment_debug_all_types_nonempty() {
    assert!(!format!("{:?}", valid_pin_set()).is_empty());
    assert!(!format!("{:?}", valid_profile()).is_empty());
    assert!(!format!("{:?}", valid_waiver_set()).is_empty());
    assert!(!format!("{:?}", valid_config()).is_empty());
    assert!(!format!("{:?}", ProfileDecision::Included).is_empty());
    assert!(!format!("{:?}", ProfileDecision::NotSelected).is_empty());
    assert!(
        !format!(
            "{:?}",
            ProfileDecision::Excluded {
                rationale: "r".into()
            }
        )
        .is_empty()
    );
    assert!(!format!("{:?}", Test262WaiverReason::HarnessGap).is_empty());
    assert!(!format!("{:?}", Test262ObservedOutcome::Pass).is_empty());
    assert!(!format!("{:?}", Test262Outcome::Waived).is_empty());
    assert!(!format!("{:?}", Test262GateError::InvalidConfig("x".into())).is_empty());
    assert!(!format!("{:?}", make_simple_run(1, false)).is_empty());
}

// =========================================================================
// L. Run summary hashes are deterministic
// =========================================================================

#[test]
fn enrichment_run_summary_hashes_nonempty() {
    let pins = valid_pin_set();
    let prof = valid_profile();
    let waivers = valid_waiver_set();
    let config = valid_config();

    let observed = vec![observed_pass("built-ins/Array/from")];
    let runner = Test262GateRunner { config };
    let run = runner.run(&pins, &prof, &waivers, &observed, None).unwrap();

    assert!(!run.summary.profile_hash.is_empty());
    assert!(!run.summary.waiver_hash.is_empty());
    assert!(!run.summary.pin_hash.is_empty());
    assert!(!run.summary.env_fingerprint.is_empty());
    // All should be hex strings (SHA-256 = 64 hex chars)
    assert_eq!(run.summary.profile_hash.len(), 64);
    assert_eq!(run.summary.waiver_hash.len(), 64);
    assert_eq!(run.summary.pin_hash.len(), 64);
    assert_eq!(run.summary.env_fingerprint.len(), 64);
}

#[test]
fn enrichment_run_summary_hashes_deterministic() {
    let pins = valid_pin_set();
    let prof = valid_profile();
    let waivers = valid_waiver_set();
    let config = valid_config();
    let observed = vec![observed_pass("built-ins/Array/from")];

    let runner1 = Test262GateRunner {
        config: config.clone(),
    };
    let run1 = runner1
        .run(&pins, &prof, &waivers, &observed, None)
        .unwrap();
    let runner2 = Test262GateRunner { config };
    let run2 = runner2
        .run(&pins, &prof, &waivers, &observed, None)
        .unwrap();

    assert_eq!(run1.summary.profile_hash, run2.summary.profile_hash);
    assert_eq!(run1.summary.waiver_hash, run2.summary.waiver_hash);
    assert_eq!(run1.summary.pin_hash, run2.summary.pin_hash);
    assert_eq!(run1.summary.env_fingerprint, run2.summary.env_fingerprint);
}

// =========================================================================
// M. WaiverSet validation edge cases
// =========================================================================

#[test]
fn enrichment_waiver_missing_tracking_bead_fails() {
    let mut ws = valid_waiver_set();
    ws.waivers.push(Test262Waiver {
        test_id: "test1".into(),
        reason_code: Test262WaiverReason::HarnessGap,
        es2020_clause: "22.1".into(),
        tracking_bead: String::new(),
        expiry_date: "2027-01-01".into(),
        reviewer: "eng".into(),
    });
    let err = ws.validate().unwrap_err();
    assert!(err.to_string().contains("tracking_bead"));
}

#[test]
fn enrichment_waiver_missing_reviewer_fails() {
    let mut ws = valid_waiver_set();
    ws.waivers.push(Test262Waiver {
        test_id: "test1".into(),
        reason_code: Test262WaiverReason::HarnessGap,
        es2020_clause: "22.1".into(),
        tracking_bead: "bd-abc".into(),
        expiry_date: "2027-01-01".into(),
        reviewer: String::new(),
    });
    let err = ws.validate().unwrap_err();
    assert!(err.to_string().contains("reviewer"));
}

#[test]
fn enrichment_waiver_missing_es2020_clause_fails() {
    let mut ws = valid_waiver_set();
    ws.waivers.push(Test262Waiver {
        test_id: "test1".into(),
        reason_code: Test262WaiverReason::HarnessGap,
        es2020_clause: String::new(),
        tracking_bead: "bd-abc".into(),
        expiry_date: "2027-01-01".into(),
        reviewer: "eng".into(),
    });
    let err = ws.validate().unwrap_err();
    assert!(err.to_string().contains("es2020_clause"));
}

// =========================================================================
// N. Profile validation edge cases
// =========================================================================

#[test]
fn enrichment_profile_empty_include_rationale_fails() {
    let mut prof = valid_profile();
    prof.includes[0].rationale = String::new();
    let err = prof.validate().unwrap_err();
    assert!(err.to_string().contains("rationale"));
}

#[test]
fn enrichment_profile_empty_include_normative_clause_fails() {
    let mut prof = valid_profile();
    prof.includes[0].normative_clause = String::new();
    let err = prof.validate().unwrap_err();
    assert!(err.to_string().contains("normative_clause"));
}

#[test]
fn enrichment_profile_empty_exclude_pattern_fails() {
    let mut prof = valid_profile();
    prof.excludes.push(Test262ProfileExclude {
        pattern: String::new(),
        rationale: "some reason".into(),
        normative_clause: "22.1".into(),
    });
    let err = prof.validate().unwrap_err();
    assert!(err.to_string().contains("exclude pattern"));
}

#[test]
fn enrichment_profile_empty_exclude_rationale_fails() {
    let mut prof = valid_profile();
    prof.excludes.push(Test262ProfileExclude {
        pattern: "built-ins/Array/from".into(),
        rationale: String::new(),
        normative_clause: "22.1".into(),
    });
    let err = prof.validate().unwrap_err();
    assert!(err.to_string().contains("rationale"));
}

// =========================================================================
// O. Log event with waived outcome contains waiver detail
// =========================================================================

#[test]
fn enrichment_log_event_waived_has_error_detail() {
    let pins = valid_pin_set();
    let prof = valid_profile();
    let mut waivers = valid_waiver_set();
    waivers.waivers.push(Test262Waiver {
        test_id: "built-ins/Array/from".into(),
        reason_code: Test262WaiverReason::IntentionalDivergence,
        es2020_clause: "22.1.2.1".into(),
        tracking_bead: "bd-waiver".into(),
        expiry_date: "2027-12-31".into(),
        reviewer: "eng-team".into(),
    });
    let config = valid_config();

    let observed = vec![observed_fail("built-ins/Array/from")];
    let runner = Test262GateRunner { config };
    let run = runner.run(&pins, &prof, &waivers, &observed, None).unwrap();

    assert_eq!(run.logs.len(), 1);
    let log = &run.logs[0];
    assert_eq!(log.outcome, Test262Outcome::Waived);
    assert!(log.error_detail.is_some());
    let detail = log.error_detail.as_ref().unwrap();
    assert!(detail.contains("bd-waiver"));
    assert!(detail.contains("eng-team"));
}

// =========================================================================
// P. GateRun with regression warning + logs contain ack event
// =========================================================================

#[test]
fn enrichment_regression_blocked_has_ack_log_event() {
    let pins = valid_pin_set();
    let prof = valid_profile();
    let waivers = valid_waiver_set();
    let config = valid_config();
    let observed = vec![observed_pass("built-ins/Array/from")];
    let prev_hwm = Test262HighWaterMark {
        schema_version: "franken-engine.test262-high-water-mark.v1".into(),
        profile_hash: "ignored".into(),
        pass_count: 10,
        recorded_at_utc: "2026-01-01T00:00:00Z".into(),
    };

    let runner = Test262GateRunner { config };
    let run = runner
        .run(&pins, &prof, &waivers, &observed, Some(&prev_hwm))
        .unwrap();
    assert!(run.blocked);

    // Should have a log event for the regression ack
    let ack_log = run
        .logs
        .iter()
        .find(|l| l.event == "pass_regression_ack_missing");
    assert!(ack_log.is_some());
    let log = ack_log.unwrap();
    assert_eq!(log.test_id, "__meta__/pass_regression");
    assert_eq!(log.outcome, Test262Outcome::Fail);
}

// =========================================================================
// Q. Evidence collector artifact content
// =========================================================================

#[test]
fn enrichment_evidence_collector_hwm_file_is_valid_json() {
    use frankenengine_engine::test262_release_gate::Test262EvidenceCollector;
    let dir = std::env::temp_dir().join(format!(
        "test262_enrichment_evidence_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);

    let collector = Test262EvidenceCollector::new(&dir).unwrap();
    let run = make_simple_run(5, false);
    let hwm = next_high_water_mark(&run, None);
    let artifacts = collector.collect(&run, &hwm).unwrap();

    let hwm_bytes = std::fs::read(&artifacts.high_water_mark_path).unwrap();
    let loaded: Test262HighWaterMark = serde_json::from_slice(&hwm_bytes).unwrap();
    assert_eq!(loaded.pass_count, 5);

    let _ = std::fs::remove_dir_all(&dir);
}

// =========================================================================
// R. WaiverSet default has correct schema
// =========================================================================

#[test]
fn enrichment_waiver_set_default_valid() {
    let ws = Test262WaiverSet::default();
    assert!(ws.validate().is_ok());
    assert!(ws.waivers.is_empty());
}

// =========================================================================
// S. PinSet commit hash validation edge cases
// =========================================================================

#[test]
fn enrichment_pin_set_uppercase_hex_accepted() {
    // is_hex_hash accepts uppercase hex chars via is_ascii_hexdigit
    let mut pins = valid_pin_set();
    pins.test262_commit = "A".repeat(40);
    // The validate docs say "lowercase hex" but is_ascii_hexdigit is case-insensitive.
    // If it passes, uppercase is accepted; if not, it's rejected.
    // Test the actual behavior: uppercase is accepted.
    assert!(pins.validate().is_ok());
}

#[test]
fn enrichment_pin_set_41_char_hex_fails() {
    let mut pins = valid_pin_set();
    pins.test262_commit = "a".repeat(41);
    assert!(pins.validate().is_err());
}

#[test]
fn enrichment_pin_set_39_char_hex_fails() {
    let mut pins = valid_pin_set();
    pins.test262_commit = "a".repeat(39);
    assert!(pins.validate().is_err());
}
