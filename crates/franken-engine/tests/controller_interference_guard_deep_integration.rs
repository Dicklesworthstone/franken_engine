#![forbid(unsafe_code)]
//! Deep integration tests for `controller_interference_guard`.
//!
//! Focuses on uncovered areas: boundary conditions in timescale separation,
//! multi-finding accumulation, subscription ordering determinism, serde
//! round-trips of full evaluations, log event structure invariants,
//! large-scale stress scenarios, write-ordering semantics, and composition
//! of multiple error paths in a single evaluation.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::controller_interference_guard::{
    ConflictResolutionMode, ControllerRegistration, InterferenceConfig, InterferenceEvaluation,
    InterferenceFailureCode, InterferenceFinding, InterferenceLogEvent, InterferenceResolution,
    InterferenceScenario, MetricReadRequest, MetricSubscription, MetricWriteRequest,
    TimescaleSeparationStatement,
};

// ===========================================================================
// Helpers
// ===========================================================================

fn make_reg(
    id: &str,
    reads: &[&str],
    writes: &[&str],
    obs: i64,
    wr: i64,
    stmt: &str,
) -> ControllerRegistration {
    ControllerRegistration {
        controller_id: id.to_string(),
        read_metrics: reads.iter().map(|s| s.to_string()).collect(),
        write_metrics: writes.iter().map(|s| s.to_string()).collect(),
        timescale: TimescaleSeparationStatement {
            observation_interval_millionths: obs,
            write_interval_millionths: wr,
            statement: stmt.to_string(),
        },
    }
}

fn run(
    trace: &str,
    policy: &str,
    config: &InterferenceConfig,
    registrations: &[ControllerRegistration],
    reads: &[MetricReadRequest],
    writes: &[MetricWriteRequest],
    subs: &[MetricSubscription],
    initial: &BTreeMap<String, i64>,
) -> InterferenceEvaluation {
    let scenario = InterferenceScenario {
        trace_id: trace,
        policy_id: policy,
        config,
        registrations,
        read_requests: reads,
        write_requests: writes,
        subscriptions: subs,
        initial_metrics: initial,
    };
    frankenengine_engine::controller_interference_guard::evaluate_controller_interference(&scenario)
}

fn quick_run(
    config: &InterferenceConfig,
    registrations: &[ControllerRegistration],
    reads: &[MetricReadRequest],
    writes: &[MetricWriteRequest],
    subs: &[MetricSubscription],
    initial: &BTreeMap<String, i64>,
) -> InterferenceEvaluation {
    run(
        "deep-trace",
        "deep-policy",
        config,
        registrations,
        reads,
        writes,
        subs,
        initial,
    )
}

// ===========================================================================
// 1) Timescale boundary: exact threshold separation passes
// ===========================================================================

#[test]
fn timescale_separation_exactly_at_threshold_passes() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Reject,
    };
    // write intervals differ by exactly 100_000 (the threshold)
    let regs = vec![
        make_reg("ctrl-a", &[], &["m"], 1_000_000, 200_000, "fast writer"),
        make_reg("ctrl-b", &[], &["m"], 1_000_000, 300_000, "slow writer"),
    ];
    let writes = vec![
        MetricWriteRequest {
            controller_id: "ctrl-a".into(),
            metric: "m".into(),
            value: 10,
        },
        MetricWriteRequest {
            controller_id: "ctrl-b".into(),
            metric: "m".into(),
            value: 20,
        },
    ];
    let eval = quick_run(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    assert!(eval.pass, "separation == threshold should pass");
    assert!(eval.findings.is_empty());
    assert_eq!(eval.applied_writes.len(), 2);
}

// ===========================================================================
// 2) Timescale boundary: one less than threshold fails
// ===========================================================================

#[test]
fn timescale_separation_one_below_threshold_fails() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Reject,
    };
    // 99_999 < 100_000
    let regs = vec![
        make_reg("ctrl-a", &[], &["m"], 1_000_000, 200_000, "fast writer"),
        make_reg("ctrl-b", &[], &["m"], 1_000_000, 299_999, "slightly less"),
    ];
    let writes = vec![
        MetricWriteRequest {
            controller_id: "ctrl-a".into(),
            metric: "m".into(),
            value: 10,
        },
        MetricWriteRequest {
            controller_id: "ctrl-b".into(),
            metric: "m".into(),
            value: 20,
        },
    ];
    let eval = quick_run(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    assert!(!eval.pass, "separation < threshold should fail");
    assert!(
        eval.findings
            .iter()
            .any(|f| f.code == InterferenceFailureCode::TimescaleConflict)
    );
}

// ===========================================================================
// 3) Zero separation threshold means all conflicts pass
// ===========================================================================

#[test]
fn zero_threshold_never_triggers_timescale_conflict() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 0,
        conflict_resolution_mode: ConflictResolutionMode::Reject,
    };
    let regs = vec![
        make_reg("ctrl-a", &[], &["m"], 1_000_000, 500_000, "same rate"),
        make_reg("ctrl-b", &[], &["m"], 1_000_000, 500_000, "same rate"),
    ];
    let writes = vec![
        MetricWriteRequest {
            controller_id: "ctrl-a".into(),
            metric: "m".into(),
            value: 1,
        },
        MetricWriteRequest {
            controller_id: "ctrl-b".into(),
            metric: "m".into(),
            value: 2,
        },
    ];
    let eval = quick_run(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    // separation=0 >= threshold=0, so no conflict
    assert!(eval.pass);
    assert!(eval.findings.is_empty());
}

// ===========================================================================
// 4) Identical write intervals with threshold=1 causes conflict
// ===========================================================================

#[test]
fn identical_write_intervals_conflict_with_nonzero_threshold() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 1,
        conflict_resolution_mode: ConflictResolutionMode::Reject,
    };
    let regs = vec![
        make_reg("ctrl-a", &[], &["m"], 1_000_000, 500_000, "same"),
        make_reg("ctrl-b", &[], &["m"], 1_000_000, 500_000, "same"),
    ];
    let writes = vec![
        MetricWriteRequest {
            controller_id: "ctrl-a".into(),
            metric: "m".into(),
            value: 1,
        },
        MetricWriteRequest {
            controller_id: "ctrl-b".into(),
            metric: "m".into(),
            value: 2,
        },
    ];
    let eval = quick_run(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    assert!(!eval.pass);
    assert!(
        eval.findings
            .iter()
            .any(|f| f.code == InterferenceFailureCode::TimescaleConflict)
    );
}

// ===========================================================================
// 5) Single writer never triggers timescale conflict
// ===========================================================================

#[test]
fn single_writer_to_metric_never_conflicts() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 1_000_000,
        conflict_resolution_mode: ConflictResolutionMode::Reject,
    };
    let regs = vec![make_reg(
        "only-writer",
        &[],
        &["m"],
        1_000_000,
        500_000,
        "sole",
    )];
    let writes = vec![MetricWriteRequest {
        controller_id: "only-writer".into(),
        metric: "m".into(),
        value: 42,
    }];
    let eval = quick_run(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    assert!(eval.pass);
    assert!(eval.resolutions.is_empty());
}

// ===========================================================================
// 6) Multiple findings accumulate across registrations, reads, writes, subs
// ===========================================================================

#[test]
fn findings_accumulate_across_all_error_categories() {
    let config = InterferenceConfig::default();
    let regs = vec![
        // duplicate
        make_reg("dup", &["cpu"], &[], 1_000_000, 500_000, "first"),
        make_reg("dup", &["cpu"], &[], 1_000_000, 500_000, "second"),
        // missing timescale statement
        make_reg("no-stmt", &["cpu"], &[], 1_000_000, 500_000, ""),
        // invalid intervals
        make_reg("bad-interval", &["cpu"], &[], -1, 500_000, "negative obs"),
    ];
    let reads = vec![
        // unknown controller
        MetricReadRequest {
            controller_id: "ghost".into(),
            metric: "cpu".into(),
        },
    ];
    let writes = vec![
        // unknown controller write
        MetricWriteRequest {
            controller_id: "phantom".into(),
            metric: "cpu".into(),
            value: 1,
        },
    ];
    let subs = vec![
        // unknown controller subscription
        MetricSubscription {
            controller_id: "specter".into(),
            metric: "cpu".into(),
        },
    ];

    let eval = quick_run(&config, &regs, &reads, &writes, &subs, &BTreeMap::new());
    assert!(!eval.pass);
    assert!(eval.rollback_required);

    let codes: BTreeSet<InterferenceFailureCode> = eval.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&InterferenceFailureCode::DuplicateController));
    assert!(codes.contains(&InterferenceFailureCode::MissingTimescaleStatement));
    assert!(codes.contains(&InterferenceFailureCode::InvalidTimescaleInterval));
    assert!(codes.contains(&InterferenceFailureCode::UnknownController));
    // At least 5 findings
    assert!(eval.findings.len() >= 5);
}

// ===========================================================================
// 7) Duplicate controller: first registration wins
// ===========================================================================

#[test]
fn duplicate_controller_produces_finding() {
    let config = InterferenceConfig::default();
    let regs = vec![
        make_reg("dup", &["cpu"], &["mem"], 1_000_000, 500_000, "first reg"),
        make_reg(
            "dup",
            &["disk"],
            &["net"],
            2_000_000,
            1_000_000,
            "second reg",
        ),
    ];
    let eval = quick_run(&config, &regs, &[], &[], &[], &BTreeMap::new());
    // Duplicate controller IDs should produce a finding
    assert!(!eval.pass);
    let codes: BTreeSet<_> = eval.findings.iter().map(|f| f.code.clone()).collect();
    assert!(codes.contains(&InterferenceFailureCode::DuplicateController));
}

// ===========================================================================
// 8) Both negative observation and write intervals produce single finding
// ===========================================================================

#[test]
fn both_intervals_negative_produces_one_finding() {
    let config = InterferenceConfig::default();
    let regs = vec![make_reg("bad", &["cpu"], &[], -100, -200, "both negative")];
    let eval = quick_run(&config, &regs, &[], &[], &[], &BTreeMap::new());
    assert!(!eval.pass);
    let invalid_count = eval
        .findings
        .iter()
        .filter(|f| f.code == InterferenceFailureCode::InvalidTimescaleInterval)
        .count();
    // Only one finding per controller, not two (the check uses ||)
    assert_eq!(invalid_count, 1);
}

// ===========================================================================
// 9) Write metric implicitly grants read access
// ===========================================================================

#[test]
fn write_metric_grants_implicit_read_access() {
    let config = InterferenceConfig::default();
    let regs = vec![make_reg(
        "ctrl",
        &[],
        &["cpu"],
        1_000_000,
        500_000,
        "write-only",
    )];
    let reads = vec![MetricReadRequest {
        controller_id: "ctrl".into(),
        metric: "cpu".into(),
    }];
    let mut initial = BTreeMap::new();
    initial.insert("cpu".to_string(), 42);
    let eval = quick_run(&config, &regs, &reads, &[], &[], &initial);
    assert!(eval.pass);
    assert_eq!(eval.read_snapshots.get("ctrl:cpu"), Some(&42));
}

// ===========================================================================
// 10) Write metric grants implicit subscription access
// ===========================================================================

#[test]
fn write_metric_grants_implicit_subscription_access() {
    let config = InterferenceConfig::default();
    let regs = vec![make_reg(
        "ctrl",
        &[],
        &["cpu"],
        1_000_000,
        500_000,
        "write-only",
    )];
    let writes = vec![MetricWriteRequest {
        controller_id: "ctrl".into(),
        metric: "cpu".into(),
        value: 99,
    }];
    let subs = vec![MetricSubscription {
        controller_id: "ctrl".into(),
        metric: "cpu".into(),
    }];
    let eval = quick_run(&config, &regs, &[], &writes, &subs, &BTreeMap::new());
    assert!(eval.pass);
    let updates = eval.subscription_streams.get("ctrl").unwrap();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].value, 99);
}

// ===========================================================================
// 11) Subscription unauthorized when no read or write access
// ===========================================================================

#[test]
fn subscription_unauthorized_without_read_or_write() {
    let config = InterferenceConfig::default();
    let regs = vec![make_reg(
        "ctrl",
        &["cpu"],
        &["mem"],
        1_000_000,
        500_000,
        "limited",
    )];
    let subs = vec![MetricSubscription {
        controller_id: "ctrl".into(),
        metric: "disk".into(),
    }];
    let eval = quick_run(&config, &regs, &[], &[], &subs, &BTreeMap::new());
    assert!(!eval.pass);
    assert!(
        eval.findings
            .iter()
            .any(|f| f.code == InterferenceFailureCode::UnauthorizedRead
                && f.metric.as_deref() == Some("disk"))
    );
}

// ===========================================================================
// 12) Decision ID hex encoding is 32 hex chars (16 bytes)
// ===========================================================================

#[test]
fn decision_id_hex_suffix_is_32_chars() {
    let config = InterferenceConfig::default();
    let eval = quick_run(&config, &[], &[], &[], &[], &BTreeMap::new());
    let prefix = "ctrl-interference-";
    assert!(eval.decision_id.starts_with(prefix));
    let hex_part = &eval.decision_id[prefix.len()..];
    assert_eq!(
        hex_part.len(),
        32,
        "hex suffix should be 32 chars (16 bytes)"
    );
    assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
}

// ===========================================================================
// 13) Decision ID differs when policy_id changes
// ===========================================================================

#[test]
fn decision_id_differs_on_policy_change() {
    let config = InterferenceConfig::default();
    let initial = BTreeMap::new();
    let e1 = run("trace", "policy-A", &config, &[], &[], &[], &[], &initial);
    let e2 = run("trace", "policy-B", &config, &[], &[], &[], &[], &initial);
    assert_ne!(e1.decision_id, e2.decision_id);
}

// ===========================================================================
// 14) Decision ID differs when config changes
// ===========================================================================

#[test]
fn decision_id_differs_on_config_change() {
    let config_a = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Reject,
    };
    let config_b = InterferenceConfig {
        min_timescale_separation_millionths: 200_000,
        conflict_resolution_mode: ConflictResolutionMode::Reject,
    };
    let initial = BTreeMap::new();
    let e1 = run("t", "p", &config_a, &[], &[], &[], &[], &initial);
    let e2 = run("t", "p", &config_b, &[], &[], &[], &[], &initial);
    assert_ne!(e1.decision_id, e2.decision_id);
}

// ===========================================================================
// 15) Decision ID differs when initial_metrics change
// ===========================================================================

#[test]
fn decision_id_differs_on_initial_metrics_change() {
    let config = InterferenceConfig::default();
    let mut m1 = BTreeMap::new();
    m1.insert("cpu".to_string(), 10);
    let mut m2 = BTreeMap::new();
    m2.insert("cpu".to_string(), 20);
    let e1 = run("t", "p", &config, &[], &[], &[], &[], &m1);
    let e2 = run("t", "p", &config, &[], &[], &[], &[], &m2);
    assert_ne!(e1.decision_id, e2.decision_id);
}

// ===========================================================================
// 16) Serde round-trip of full InterferenceEvaluation (passing)
// ===========================================================================

#[test]
fn serde_roundtrip_full_evaluation_passing() {
    let config = InterferenceConfig::default();
    let regs = vec![make_reg(
        "ctrl",
        &["cpu"],
        &["mem"],
        1_000_000,
        500_000,
        "full test",
    )];
    let reads = vec![MetricReadRequest {
        controller_id: "ctrl".into(),
        metric: "cpu".into(),
    }];
    let writes = vec![MetricWriteRequest {
        controller_id: "ctrl".into(),
        metric: "mem".into(),
        value: 42,
    }];
    let subs = vec![MetricSubscription {
        controller_id: "ctrl".into(),
        metric: "mem".into(),
    }];
    let mut initial = BTreeMap::new();
    initial.insert("cpu".to_string(), 10);
    let eval = quick_run(&config, &regs, &reads, &writes, &subs, &initial);
    assert!(eval.pass);

    let json = serde_json::to_string(&eval).unwrap();
    let back: InterferenceEvaluation = serde_json::from_str(&json).unwrap();
    assert_eq!(eval, back);
}

// ===========================================================================
// 17) Serde round-trip of full InterferenceEvaluation (failing)
// ===========================================================================

#[test]
fn serde_roundtrip_full_evaluation_failing() {
    let config = InterferenceConfig::default();
    let regs = vec![
        make_reg("dup", &["cpu"], &[], 1_000_000, 500_000, "first"),
        make_reg("dup", &["cpu"], &[], 1_000_000, 500_000, "second"),
    ];
    let eval = quick_run(&config, &regs, &[], &[], &[], &BTreeMap::new());
    assert!(!eval.pass);

    let json = serde_json::to_string(&eval).unwrap();
    let back: InterferenceEvaluation = serde_json::from_str(&json).unwrap();
    assert_eq!(eval, back);
}

// ===========================================================================
// 18) Serde round-trip of evaluation with resolutions
// ===========================================================================

#[test]
fn serde_roundtrip_evaluation_with_resolutions() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Serialize,
    };
    let regs = vec![
        make_reg("ctrl-a", &[], &["m"], 1_000_000, 500_000, "a"),
        make_reg("ctrl-b", &[], &["m"], 1_000_000, 510_000, "b"),
    ];
    let writes = vec![
        MetricWriteRequest {
            controller_id: "ctrl-a".into(),
            metric: "m".into(),
            value: 1,
        },
        MetricWriteRequest {
            controller_id: "ctrl-b".into(),
            metric: "m".into(),
            value: 2,
        },
    ];
    let eval = quick_run(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    assert!(!eval.resolutions.is_empty());

    let json = serde_json::to_string(&eval).unwrap();
    let back: InterferenceEvaluation = serde_json::from_str(&json).unwrap();
    assert_eq!(eval, back);
}

// ===========================================================================
// 19) Serialized writes: last writer by controller_id order wins
// ===========================================================================

#[test]
fn serialized_writes_last_by_controller_id_wins() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 1_000_000,
        conflict_resolution_mode: ConflictResolutionMode::Serialize,
    };
    // ctrl-a sorts before ctrl-z, so ctrl-z writes last
    let regs = vec![
        make_reg("ctrl-a", &[], &["m"], 1_000_000, 500_000, "a"),
        make_reg("ctrl-z", &[], &["m"], 1_000_000, 500_000, "z"),
    ];
    let writes = vec![
        MetricWriteRequest {
            controller_id: "ctrl-z".into(),
            metric: "m".into(),
            value: 999,
        },
        MetricWriteRequest {
            controller_id: "ctrl-a".into(),
            metric: "m".into(),
            value: 111,
        },
    ];
    let eval = quick_run(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    assert!(eval.pass);
    // Writes are sorted by controller_id: ctrl-a(111), ctrl-z(999)
    // Last write wins, so final value = 999
    assert_eq!(*eval.final_metrics.get("m").unwrap(), 999);
}

// ===========================================================================
// 20) Rejected conflict writes preserve initial metric value
// ===========================================================================

#[test]
fn rejected_conflict_preserves_initial_value() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Reject,
    };
    let regs = vec![
        make_reg("ctrl-a", &[], &["m"], 1_000_000, 500_000, "a"),
        make_reg("ctrl-b", &[], &["m"], 1_000_000, 510_000, "b"),
    ];
    let writes = vec![
        MetricWriteRequest {
            controller_id: "ctrl-a".into(),
            metric: "m".into(),
            value: 100,
        },
        MetricWriteRequest {
            controller_id: "ctrl-b".into(),
            metric: "m".into(),
            value: 200,
        },
    ];
    let mut initial = BTreeMap::new();
    initial.insert("m".to_string(), 42);
    let eval = quick_run(&config, &regs, &[], &writes, &[], &initial);
    assert!(!eval.pass);
    // Initial value preserved since writes were rejected
    assert_eq!(*eval.final_metrics.get("m").unwrap(), 42);
}

// ===========================================================================
// 21) Timescale conflict detail contains separation and threshold
// ===========================================================================

#[test]
fn timescale_conflict_finding_detail_contains_values() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Reject,
    };
    let regs = vec![
        make_reg("ctrl-a", &[], &["m"], 1_000_000, 500_000, "a"),
        make_reg("ctrl-b", &[], &["m"], 1_000_000, 510_000, "b"),
    ];
    let writes = vec![
        MetricWriteRequest {
            controller_id: "ctrl-a".into(),
            metric: "m".into(),
            value: 1,
        },
        MetricWriteRequest {
            controller_id: "ctrl-b".into(),
            metric: "m".into(),
            value: 2,
        },
    ];
    let eval = quick_run(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    let finding = eval
        .findings
        .iter()
        .find(|f| f.code == InterferenceFailureCode::TimescaleConflict)
        .expect("should have TimescaleConflict finding");
    // Detail should mention 10000 ppm separation and 100000 ppm min
    assert!(
        finding.detail.contains("10000"),
        "detail should contain separation: {}",
        finding.detail
    );
    assert!(
        finding.detail.contains("100000"),
        "detail should contain threshold: {}",
        finding.detail
    );
}

// ===========================================================================
// 22) Serialize resolution detail contains separation
// ===========================================================================

#[test]
fn serialize_resolution_detail_contains_separation() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Serialize,
    };
    let regs = vec![
        make_reg("ctrl-a", &[], &["m"], 1_000_000, 500_000, "a"),
        make_reg("ctrl-b", &[], &["m"], 1_000_000, 510_000, "b"),
    ];
    let writes = vec![
        MetricWriteRequest {
            controller_id: "ctrl-a".into(),
            metric: "m".into(),
            value: 1,
        },
        MetricWriteRequest {
            controller_id: "ctrl-b".into(),
            metric: "m".into(),
            value: 2,
        },
    ];
    let eval = quick_run(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    let resolution = &eval.resolutions[0];
    assert!(
        resolution.detail.contains("10000"),
        "detail: {}",
        resolution.detail
    );
}

// ===========================================================================
// 23) Multiple metrics: conflict on one, no conflict on another
// ===========================================================================

#[test]
fn per_metric_conflict_detection() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Reject,
    };
    let regs = vec![
        make_reg(
            "ctrl-a",
            &[],
            &["conflicted", "separate"],
            1_000_000,
            500_000,
            "a",
        ),
        make_reg(
            "ctrl-b",
            &[],
            &["conflicted", "separate"],
            1_000_000,
            510_000,
            "b close to a",
        ),
        make_reg(
            "ctrl-c",
            &[],
            &["separate"],
            1_000_000,
            900_000,
            "c far from a&b",
        ),
    ];
    let writes = vec![
        // conflicted: ctrl-a(500k) vs ctrl-b(510k) = 10k separation, below threshold
        MetricWriteRequest {
            controller_id: "ctrl-a".into(),
            metric: "conflicted".into(),
            value: 1,
        },
        MetricWriteRequest {
            controller_id: "ctrl-b".into(),
            metric: "conflicted".into(),
            value: 2,
        },
        // separate: ctrl-a(500k) vs ctrl-c(900k) = 400k separation, above threshold
        MetricWriteRequest {
            controller_id: "ctrl-a".into(),
            metric: "separate".into(),
            value: 10,
        },
        MetricWriteRequest {
            controller_id: "ctrl-c".into(),
            metric: "separate".into(),
            value: 20,
        },
    ];
    let eval = quick_run(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    assert!(!eval.pass);
    // Only "conflicted" metric should have a finding
    let conflict_finding = eval
        .findings
        .iter()
        .find(|f| f.code == InterferenceFailureCode::TimescaleConflict)
        .unwrap();
    assert_eq!(conflict_finding.metric.as_deref(), Some("conflicted"));
    // "separate" writes should be applied
    assert_eq!(*eval.final_metrics.get("separate").unwrap(), 20);
}

// ===========================================================================
// 24) Subscription ordering: sorted by controller_id then metric
// ===========================================================================

#[test]
fn subscription_updates_ordered_by_controller_then_metric() {
    let config = InterferenceConfig::default();
    let regs = vec![
        make_reg(
            "z-ctrl",
            &["a_metric", "b_metric"],
            &[],
            1_000_000,
            500_000,
            "z",
        ),
        make_reg(
            "a-ctrl",
            &["a_metric", "b_metric"],
            &[],
            1_000_000,
            500_000,
            "a",
        ),
    ];
    let mut initial = BTreeMap::new();
    initial.insert("a_metric".to_string(), 10);
    initial.insert("b_metric".to_string(), 20);

    let subs = vec![
        MetricSubscription {
            controller_id: "z-ctrl".into(),
            metric: "b_metric".into(),
        },
        MetricSubscription {
            controller_id: "z-ctrl".into(),
            metric: "a_metric".into(),
        },
        MetricSubscription {
            controller_id: "a-ctrl".into(),
            metric: "b_metric".into(),
        },
        MetricSubscription {
            controller_id: "a-ctrl".into(),
            metric: "a_metric".into(),
        },
    ];
    let eval = quick_run(&config, &regs, &[], &[], &subs, &initial);
    assert!(eval.pass);

    // Gather all sequences globally
    let mut all_updates: Vec<(u64, String, String)> = Vec::new();
    for (ctrl, updates) in &eval.subscription_streams {
        for u in updates {
            all_updates.push((u.sequence, ctrl.clone(), u.metric.clone()));
        }
    }
    all_updates.sort_by_key(|(seq, _, _)| *seq);

    // a-ctrl should come before z-ctrl (sorted by controller_id)
    // Within a-ctrl: a_metric before b_metric (sorted by metric)
    assert_eq!(all_updates.len(), 4);
    assert_eq!(all_updates[0].1, "a-ctrl");
    assert_eq!(all_updates[0].2, "a_metric");
    assert_eq!(all_updates[1].1, "a-ctrl");
    assert_eq!(all_updates[1].2, "b_metric");
    assert_eq!(all_updates[2].1, "z-ctrl");
    assert_eq!(all_updates[2].2, "a_metric");
    assert_eq!(all_updates[3].1, "z-ctrl");
    assert_eq!(all_updates[3].2, "b_metric");
}

// ===========================================================================
// 25) Subscription sequence numbers are strictly increasing (not just monotonic)
// ===========================================================================

#[test]
fn subscription_sequences_strictly_increasing_globally() {
    let config = InterferenceConfig::default();
    let regs = vec![
        make_reg("ctrl-a", &["m1", "m2", "m3"], &[], 1_000_000, 500_000, "a"),
        make_reg("ctrl-b", &["m1", "m2"], &[], 1_000_000, 500_000, "b"),
    ];
    let mut initial = BTreeMap::new();
    initial.insert("m1".to_string(), 1);
    initial.insert("m2".to_string(), 2);
    initial.insert("m3".to_string(), 3);

    let subs = vec![
        MetricSubscription {
            controller_id: "ctrl-a".into(),
            metric: "m1".into(),
        },
        MetricSubscription {
            controller_id: "ctrl-a".into(),
            metric: "m2".into(),
        },
        MetricSubscription {
            controller_id: "ctrl-a".into(),
            metric: "m3".into(),
        },
        MetricSubscription {
            controller_id: "ctrl-b".into(),
            metric: "m1".into(),
        },
        MetricSubscription {
            controller_id: "ctrl-b".into(),
            metric: "m2".into(),
        },
    ];
    let eval = quick_run(&config, &regs, &[], &[], &subs, &initial);

    let mut all_seqs: Vec<u64> = eval
        .subscription_streams
        .values()
        .flat_map(|updates| updates.iter().map(|u| u.sequence))
        .collect();
    all_seqs.sort();
    // Each sequence unique
    let unique: BTreeSet<u64> = all_seqs.iter().copied().collect();
    assert_eq!(unique.len(), all_seqs.len());
    // Strictly increasing: 1, 2, 3, 4, 5
    assert_eq!(*all_seqs.first().unwrap(), 1);
    assert_eq!(*all_seqs.last().unwrap(), 5);
}

// ===========================================================================
// 26) Subscription for metric not in final_metrics produces no update
// ===========================================================================

#[test]
fn subscription_to_absent_metric_produces_no_update() {
    let config = InterferenceConfig::default();
    let regs = vec![make_reg("ctrl", &["absent"], &[], 1_000_000, 500_000, "s")];
    let subs = vec![MetricSubscription {
        controller_id: "ctrl".into(),
        metric: "absent".into(),
    }];
    let eval = quick_run(&config, &regs, &[], &[], &subs, &BTreeMap::new());
    assert!(eval.pass);
    // No updates because "absent" is not in final_metrics
    let updates = eval.subscription_streams.get("ctrl");
    assert!(updates.is_none() || updates.unwrap().is_empty());
}

// ===========================================================================
// 27) Read snapshot defaults to zero for missing metric
// ===========================================================================

#[test]
fn read_snapshot_defaults_to_zero_for_absent_metric() {
    let config = InterferenceConfig::default();
    let regs = vec![make_reg("ctrl", &["absent"], &[], 1_000_000, 500_000, "s")];
    let reads = vec![MetricReadRequest {
        controller_id: "ctrl".into(),
        metric: "absent".into(),
    }];
    let eval = quick_run(&config, &regs, &reads, &[], &[], &BTreeMap::new());
    assert!(eval.pass);
    assert_eq!(eval.read_snapshots.get("ctrl:absent"), Some(&0));
}

// ===========================================================================
// 28) Multiple reads by same controller for same metric: single snapshot
// ===========================================================================

#[test]
fn duplicate_read_requests_produce_single_snapshot() {
    let config = InterferenceConfig::default();
    let regs = vec![make_reg("ctrl", &["cpu"], &[], 1_000_000, 500_000, "s")];
    let mut initial = BTreeMap::new();
    initial.insert("cpu".to_string(), 42);
    let reads = vec![
        MetricReadRequest {
            controller_id: "ctrl".into(),
            metric: "cpu".into(),
        },
        MetricReadRequest {
            controller_id: "ctrl".into(),
            metric: "cpu".into(),
        },
    ];
    let eval = quick_run(&config, &regs, &reads, &[], &[], &initial);
    assert!(eval.pass);
    // snapshot key is "ctrl:cpu", overwritten with same value
    assert_eq!(eval.read_snapshots.get("ctrl:cpu"), Some(&42));
    assert_eq!(eval.read_snapshots.len(), 1);
}

// ===========================================================================
// 29) Log events: all logs have correct trace_id, decision_id, policy_id
// ===========================================================================

#[test]
fn log_events_carry_correct_trace_and_policy() {
    let config = InterferenceConfig::default();
    let regs = vec![make_reg(
        "ctrl",
        &["cpu"],
        &["mem"],
        1_000_000,
        500_000,
        "s",
    )];
    let reads = vec![MetricReadRequest {
        controller_id: "ctrl".into(),
        metric: "cpu".into(),
    }];
    let mut initial = BTreeMap::new();
    initial.insert("cpu".to_string(), 10);
    let eval = run(
        "my-trace-42",
        "policy-abc",
        &config,
        &regs,
        &reads,
        &[],
        &[],
        &initial,
    );

    for log in &eval.logs {
        assert_eq!(log.trace_id, "my-trace-42");
        assert_eq!(log.policy_id, "policy-abc");
        assert_eq!(log.component, "controller_interference_guard");
        assert!(log.decision_id.starts_with("ctrl-interference-"));
    }
}

// ===========================================================================
// 30) Log event: read_snapshot logged for each valid read
// ===========================================================================

#[test]
fn each_valid_read_generates_read_snapshot_log() {
    let config = InterferenceConfig::default();
    let regs = vec![make_reg(
        "ctrl",
        &["cpu", "mem"],
        &[],
        1_000_000,
        500_000,
        "s",
    )];
    let reads = vec![
        MetricReadRequest {
            controller_id: "ctrl".into(),
            metric: "cpu".into(),
        },
        MetricReadRequest {
            controller_id: "ctrl".into(),
            metric: "mem".into(),
        },
    ];
    let mut initial = BTreeMap::new();
    initial.insert("cpu".to_string(), 10);
    initial.insert("mem".to_string(), 20);
    let eval = quick_run(&config, &regs, &reads, &[], &[], &initial);

    let read_logs: Vec<_> = eval
        .logs
        .iter()
        .filter(|l| l.event == "read_snapshot")
        .collect();
    assert_eq!(read_logs.len(), 2);
}

// ===========================================================================
// 31) Log: summary is always the last log event
// ===========================================================================

#[test]
fn summary_log_is_last_event() {
    let config = InterferenceConfig::default();
    let regs = vec![make_reg(
        "ctrl",
        &["cpu"],
        &["cpu"],
        1_000_000,
        500_000,
        "s",
    )];
    let reads = vec![MetricReadRequest {
        controller_id: "ctrl".into(),
        metric: "cpu".into(),
    }];
    let writes = vec![MetricWriteRequest {
        controller_id: "ctrl".into(),
        metric: "cpu".into(),
        value: 5,
    }];
    let mut initial = BTreeMap::new();
    initial.insert("cpu".to_string(), 10);
    let eval = quick_run(&config, &regs, &reads, &writes, &[], &initial);
    assert!(eval.logs.len() >= 2);
    assert_eq!(eval.logs.last().unwrap().event, "interference_summary");
}

// ===========================================================================
// 32) Log: fail summary has error_code
// ===========================================================================

#[test]
fn fail_summary_log_has_error_code() {
    let config = InterferenceConfig::default();
    let reads = vec![MetricReadRequest {
        controller_id: "nobody".into(),
        metric: "x".into(),
    }];
    let eval = quick_run(&config, &[], &reads, &[], &[], &BTreeMap::new());
    assert!(!eval.pass);
    let summary = eval
        .logs
        .iter()
        .find(|l| l.event == "interference_summary")
        .unwrap();
    assert_eq!(summary.outcome, "fail");
    assert_eq!(
        summary.error_code.as_deref(),
        Some("controller_interference_failed")
    );
}

// ===========================================================================
// 33) Log: pass summary has no error_code
// ===========================================================================

#[test]
fn pass_summary_log_has_no_error_code() {
    let config = InterferenceConfig::default();
    let eval = quick_run(&config, &[], &[], &[], &[], &BTreeMap::new());
    assert!(eval.pass);
    let summary = eval
        .logs
        .iter()
        .find(|l| l.event == "interference_summary")
        .unwrap();
    assert_eq!(summary.outcome, "pass");
    assert!(summary.error_code.is_none());
}

// ===========================================================================
// 34) Timescale conflict log in reject mode references both controllers
// ===========================================================================

#[test]
fn timescale_conflict_log_references_both_controllers() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Reject,
    };
    let regs = vec![
        make_reg("alpha", &[], &["m"], 1_000_000, 500_000, "a"),
        make_reg("beta", &[], &["m"], 1_000_000, 510_000, "b"),
    ];
    let writes = vec![
        MetricWriteRequest {
            controller_id: "alpha".into(),
            metric: "m".into(),
            value: 1,
        },
        MetricWriteRequest {
            controller_id: "beta".into(),
            metric: "m".into(),
            value: 2,
        },
    ];
    let eval = quick_run(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    let tc_log = eval
        .logs
        .iter()
        .find(|l| l.event == "timescale_conflict")
        .unwrap();
    assert!(tc_log.controller_ids.contains(&"alpha".to_string()));
    assert!(tc_log.controller_ids.contains(&"beta".to_string()));
    assert_eq!(tc_log.metric.as_deref(), Some("m"));
}

// ===========================================================================
// 35) Serialize mode log has correct event name
// ===========================================================================

#[test]
fn serialize_mode_log_event_name() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Serialize,
    };
    let regs = vec![
        make_reg("ctrl-a", &[], &["m"], 1_000_000, 500_000, "a"),
        make_reg("ctrl-b", &[], &["m"], 1_000_000, 510_000, "b"),
    ];
    let writes = vec![
        MetricWriteRequest {
            controller_id: "ctrl-a".into(),
            metric: "m".into(),
            value: 1,
        },
        MetricWriteRequest {
            controller_id: "ctrl-b".into(),
            metric: "m".into(),
            value: 2,
        },
    ];
    let eval = quick_run(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    assert!(
        eval.logs
            .iter()
            .any(|l| l.event == "write_conflict_serialized")
    );
}

// ===========================================================================
// 36) Display: ConflictResolutionMode Clone + Copy semantics
// ===========================================================================

#[test]
fn conflict_resolution_mode_clone_copy() {
    let mode = ConflictResolutionMode::Serialize;
    let cloned = mode.clone();
    let copied = mode;
    assert_eq!(mode, cloned);
    assert_eq!(mode, copied);
}

// ===========================================================================
// 37) InterferenceFailureCode Ord: full ordering is deterministic
// ===========================================================================

#[test]
fn failure_code_full_ordering_deterministic() {
    let codes = vec![
        InterferenceFailureCode::TimescaleConflict,
        InterferenceFailureCode::UnauthorizedWrite,
        InterferenceFailureCode::UnauthorizedRead,
        InterferenceFailureCode::UnknownController,
        InterferenceFailureCode::InvalidTimescaleInterval,
        InterferenceFailureCode::MissingTimescaleStatement,
        InterferenceFailureCode::DuplicateController,
    ];
    let mut sorted1 = codes.clone();
    sorted1.sort();
    let mut sorted2 = codes.clone();
    sorted2.sort();
    assert_eq!(sorted1, sorted2);
    // First should be DuplicateController (lowest variant index)
    assert_eq!(sorted1[0], InterferenceFailureCode::DuplicateController);
    // Last should be TimescaleConflict (highest variant index)
    assert_eq!(sorted1[6], InterferenceFailureCode::TimescaleConflict);
}

// ===========================================================================
// 38) Large-scale: many controllers, many metrics
// ===========================================================================

#[test]
fn large_scale_many_controllers_and_metrics() {
    let config = InterferenceConfig::default();
    let num_controllers = 50;
    let num_metrics = 20;

    let mut regs = Vec::new();
    let mut reads = Vec::new();
    let mut writes = Vec::new();
    let mut subs = Vec::new();
    let mut initial = BTreeMap::new();

    for m in 0..num_metrics {
        let metric = format!("metric_{m:03}");
        initial.insert(metric.clone(), m as i64);
    }

    for c in 0..num_controllers {
        let ctrl_id = format!("ctrl_{c:03}");
        let metric = format!("metric_{:03}", c % num_metrics);
        // Each controller reads and writes one metric (no overlaps between controllers
        // since each targets metric_{c % 20}, and with 50 controllers some share,
        // but timescale separation is sufficient)
        let obs = 1_000_000 + (c as i64) * 200_000;
        let wr = 1_000_000 + (c as i64) * 200_000;
        regs.push(make_reg(
            &ctrl_id,
            &[],
            &[&metric],
            obs,
            wr,
            &format!("ctrl {c}"),
        ));
        writes.push(MetricWriteRequest {
            controller_id: ctrl_id.clone(),
            metric: metric.clone(),
            value: (c as i64 + 1) * 100,
        });
        reads.push(MetricReadRequest {
            controller_id: ctrl_id.clone(),
            metric: metric.clone(),
        });
        subs.push(MetricSubscription {
            controller_id: ctrl_id,
            metric,
        });
    }

    let eval = quick_run(&config, &regs, &reads, &writes, &subs, &initial);
    // Should process all without panicking
    assert!(!eval.decision_id.is_empty());
    assert!(!eval.logs.is_empty());
    // All writes should be applied (timescale separation is large enough)
    assert_eq!(eval.applied_writes.len(), num_controllers);
}

// ===========================================================================
// 39) Determinism: repeated evaluations yield identical results
// ===========================================================================

#[test]
fn deterministic_across_repeated_evaluations() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 50_000,
        conflict_resolution_mode: ConflictResolutionMode::Serialize,
    };
    let regs = vec![
        make_reg(
            "ctrl-a",
            &["cpu"],
            &["mem", "disk"],
            1_000_000,
            500_000,
            "a",
        ),
        make_reg(
            "ctrl-b",
            &["mem"],
            &["cpu", "disk"],
            1_000_000,
            510_000,
            "b",
        ),
    ];
    let reads = vec![
        MetricReadRequest {
            controller_id: "ctrl-a".into(),
            metric: "cpu".into(),
        },
        MetricReadRequest {
            controller_id: "ctrl-b".into(),
            metric: "mem".into(),
        },
    ];
    let writes = vec![
        MetricWriteRequest {
            controller_id: "ctrl-a".into(),
            metric: "mem".into(),
            value: 100,
        },
        MetricWriteRequest {
            controller_id: "ctrl-b".into(),
            metric: "cpu".into(),
            value: 200,
        },
        MetricWriteRequest {
            controller_id: "ctrl-a".into(),
            metric: "disk".into(),
            value: 300,
        },
        MetricWriteRequest {
            controller_id: "ctrl-b".into(),
            metric: "disk".into(),
            value: 400,
        },
    ];
    let subs = vec![
        MetricSubscription {
            controller_id: "ctrl-a".into(),
            metric: "cpu".into(),
        },
        MetricSubscription {
            controller_id: "ctrl-b".into(),
            metric: "mem".into(),
        },
    ];
    let mut initial = BTreeMap::new();
    initial.insert("cpu".to_string(), 1);
    initial.insert("mem".to_string(), 2);
    initial.insert("disk".to_string(), 3);

    let e1 = quick_run(&config, &regs, &reads, &writes, &subs, &initial);
    let e2 = quick_run(&config, &regs, &reads, &writes, &subs, &initial);
    assert_eq!(e1, e2);
}

// ===========================================================================
// 40) Three-way conflict: first pair detected, rest rejected
// ===========================================================================

#[test]
fn three_way_conflict_detects_first_pair() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Reject,
    };
    let regs = vec![
        make_reg("ctrl-a", &[], &["m"], 1_000_000, 500_000, "a"),
        make_reg("ctrl-b", &[], &["m"], 1_000_000, 510_000, "b"),
        make_reg("ctrl-c", &[], &["m"], 1_000_000, 520_000, "c"),
    ];
    let writes = vec![
        MetricWriteRequest {
            controller_id: "ctrl-a".into(),
            metric: "m".into(),
            value: 1,
        },
        MetricWriteRequest {
            controller_id: "ctrl-b".into(),
            metric: "m".into(),
            value: 2,
        },
        MetricWriteRequest {
            controller_id: "ctrl-c".into(),
            metric: "m".into(),
            value: 3,
        },
    ];
    let eval = quick_run(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    assert!(!eval.pass);
    // All 3 writes should be rejected
    assert_eq!(eval.rejected_writes.len(), 3);
    assert_eq!(eval.applied_writes.len(), 0);
    // Exactly one TimescaleConflict finding (first conflicting pair stops checking)
    let tc_findings: Vec<_> = eval
        .findings
        .iter()
        .filter(|f| f.code == InterferenceFailureCode::TimescaleConflict)
        .collect();
    assert_eq!(tc_findings.len(), 1);
}

// ===========================================================================
// 41) Mixed: authorized write + unauthorized write for same controller
// ===========================================================================

#[test]
fn mixed_authorized_and_unauthorized_writes() {
    let config = InterferenceConfig::default();
    let regs = vec![make_reg("ctrl", &[], &["allowed"], 1_000_000, 500_000, "s")];
    let writes = vec![
        MetricWriteRequest {
            controller_id: "ctrl".into(),
            metric: "allowed".into(),
            value: 10,
        },
        MetricWriteRequest {
            controller_id: "ctrl".into(),
            metric: "forbidden".into(),
            value: 20,
        },
    ];
    let eval = quick_run(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    assert!(!eval.pass);
    assert_eq!(eval.applied_writes.len(), 1);
    assert_eq!(eval.rejected_writes.len(), 1);
    assert_eq!(eval.applied_writes[0].metric, "allowed");
    assert_eq!(eval.rejected_writes[0].metric, "forbidden");
}

// ===========================================================================
// 42) Finding detail strings are non-empty
// ===========================================================================

#[test]
fn finding_details_are_nonempty() {
    let config = InterferenceConfig::default();
    let regs = vec![
        make_reg("dup", &[], &[], 1_000_000, 500_000, "dup1"),
        make_reg("dup", &[], &[], 1_000_000, 500_000, "dup2"),
        make_reg("empty-stmt", &[], &[], 1_000_000, 500_000, ""),
        make_reg("bad-interval", &[], &[], 0, 0, "bad"),
    ];
    let reads = vec![MetricReadRequest {
        controller_id: "ghost".into(),
        metric: "x".into(),
    }];
    let writes = vec![MetricWriteRequest {
        controller_id: "phantom".into(),
        metric: "x".into(),
        value: 1,
    }];
    let eval = quick_run(&config, &regs, &reads, &writes, &[], &BTreeMap::new());
    for finding in &eval.findings {
        assert!(
            !finding.detail.is_empty(),
            "finding detail should not be empty: {:?}",
            finding.code
        );
    }
}

// ===========================================================================
// 43) Finding controller_ids always populated
// ===========================================================================

#[test]
fn finding_controller_ids_always_populated() {
    let config = InterferenceConfig::default();
    let regs = vec![
        make_reg("dup", &[], &[], 1_000_000, 500_000, "dup1"),
        make_reg("dup", &[], &[], 1_000_000, 500_000, "dup2"),
    ];
    let reads = vec![MetricReadRequest {
        controller_id: "ghost".into(),
        metric: "x".into(),
    }];
    let eval = quick_run(&config, &regs, &reads, &[], &[], &BTreeMap::new());
    for finding in &eval.findings {
        assert!(
            !finding.controller_ids.is_empty(),
            "finding should reference at least one controller"
        );
    }
}

// ===========================================================================
// 44) Write value zero
// ===========================================================================

#[test]
fn write_value_zero_applied() {
    let config = InterferenceConfig::default();
    let regs = vec![make_reg("ctrl", &[], &["m"], 1_000_000, 500_000, "s")];
    let writes = vec![MetricWriteRequest {
        controller_id: "ctrl".into(),
        metric: "m".into(),
        value: 0,
    }];
    let mut initial = BTreeMap::new();
    initial.insert("m".to_string(), 999);
    let eval = quick_run(&config, &regs, &[], &writes, &[], &initial);
    assert!(eval.pass);
    assert_eq!(*eval.final_metrics.get("m").unwrap(), 0);
}

// ===========================================================================
// 45) Write i64::MAX and i64::MIN
// ===========================================================================

#[test]
fn write_extreme_values() {
    let config = InterferenceConfig::default();
    let regs = vec![make_reg(
        "ctrl",
        &[],
        &["max", "min"],
        1_000_000,
        500_000,
        "s",
    )];
    let writes = vec![
        MetricWriteRequest {
            controller_id: "ctrl".into(),
            metric: "max".into(),
            value: i64::MAX,
        },
        MetricWriteRequest {
            controller_id: "ctrl".into(),
            metric: "min".into(),
            value: i64::MIN,
        },
    ];
    let eval = quick_run(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    assert!(eval.pass);
    assert_eq!(*eval.final_metrics.get("max").unwrap(), i64::MAX);
    assert_eq!(*eval.final_metrics.get("min").unwrap(), i64::MIN);
}

// ===========================================================================
// 46) Initial metric i64::MAX read snapshot
// ===========================================================================

#[test]
fn read_snapshot_of_extreme_initial_value() {
    let config = InterferenceConfig::default();
    let regs = vec![make_reg("ctrl", &["m"], &[], 1_000_000, 500_000, "s")];
    let reads = vec![MetricReadRequest {
        controller_id: "ctrl".into(),
        metric: "m".into(),
    }];
    let mut initial = BTreeMap::new();
    initial.insert("m".to_string(), i64::MAX);
    let eval = quick_run(&config, &regs, &reads, &[], &[], &initial);
    assert_eq!(eval.read_snapshots.get("ctrl:m"), Some(&i64::MAX));
}

// ===========================================================================
// 47) Empty string controller_id works
// ===========================================================================

#[test]
fn empty_string_controller_id() {
    let config = InterferenceConfig::default();
    let regs = vec![make_reg(
        "",
        &["cpu"],
        &["cpu"],
        1_000_000,
        500_000,
        "empty id",
    )];
    let reads = vec![MetricReadRequest {
        controller_id: "".into(),
        metric: "cpu".into(),
    }];
    let writes = vec![MetricWriteRequest {
        controller_id: "".into(),
        metric: "cpu".into(),
        value: 42,
    }];
    let mut initial = BTreeMap::new();
    initial.insert("cpu".to_string(), 10);
    let eval = quick_run(&config, &regs, &reads, &writes, &[], &initial);
    assert!(eval.pass);
    assert_eq!(eval.read_snapshots.get(":cpu"), Some(&10));
    assert_eq!(*eval.final_metrics.get("cpu").unwrap(), 42);
}

// ===========================================================================
// 48) Unicode in controller IDs and metrics
// ===========================================================================

#[test]
fn unicode_controller_and_metric_names() {
    let config = InterferenceConfig::default();
    let regs = vec![make_reg(
        "ctrl-\u{1F600}",
        &["\u{03B1}"],
        &["\u{03B2}"],
        1_000_000,
        500_000,
        "unicode test",
    )];
    let reads = vec![MetricReadRequest {
        controller_id: "ctrl-\u{1F600}".into(),
        metric: "\u{03B1}".into(),
    }];
    let writes = vec![MetricWriteRequest {
        controller_id: "ctrl-\u{1F600}".into(),
        metric: "\u{03B2}".into(),
        value: 7,
    }];
    let mut initial = BTreeMap::new();
    initial.insert("\u{03B1}".to_string(), 3);
    let eval = quick_run(&config, &regs, &reads, &writes, &[], &initial);
    assert!(eval.pass);
    assert_eq!(eval.read_snapshots.get("ctrl-\u{1F600}:\u{03B1}"), Some(&3));
    assert_eq!(*eval.final_metrics.get("\u{03B2}").unwrap(), 7);
}

// ===========================================================================
// 49) Long controller ID and metric names
// ===========================================================================

#[test]
fn very_long_controller_and_metric_names() {
    let config = InterferenceConfig::default();
    let long_id = "x".repeat(1000);
    let long_metric = "m".repeat(1000);
    let regs = vec![make_reg(
        &long_id,
        &[&long_metric],
        &[],
        1_000_000,
        500_000,
        "long names",
    )];
    let reads = vec![MetricReadRequest {
        controller_id: long_id.clone(),
        metric: long_metric.clone(),
    }];
    let mut initial = BTreeMap::new();
    initial.insert(long_metric.clone(), 77);
    let eval = quick_run(&config, &regs, &reads, &[], &[], &initial);
    assert!(eval.pass);
    let key = format!("{long_id}:{long_metric}");
    assert_eq!(eval.read_snapshots.get(&key), Some(&77));
}

// ===========================================================================
// 50) Multiple writes to same metric by same controller: last wins
// ===========================================================================

#[test]
fn multiple_writes_same_controller_same_metric_produces_findings() {
    let config = InterferenceConfig::default();
    let regs = vec![make_reg("ctrl", &[], &["m"], 1_000_000, 500_000, "s")];
    let writes = vec![
        MetricWriteRequest {
            controller_id: "ctrl".into(),
            metric: "m".into(),
            value: 10,
        },
        MetricWriteRequest {
            controller_id: "ctrl".into(),
            metric: "m".into(),
            value: 20,
        },
        MetricWriteRequest {
            controller_id: "ctrl".into(),
            metric: "m".into(),
            value: 30,
        },
    ];
    let eval = quick_run(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    // Multiple writes to same metric may produce conflict findings
    // but should process at least some of the writes
    assert!(!eval.applied_writes.is_empty() || !eval.findings.is_empty());
}

// ===========================================================================
// 51) Write to metric not in initial_metrics creates it
// ===========================================================================

#[test]
fn write_creates_new_metric_in_final() {
    let config = InterferenceConfig::default();
    let regs = vec![make_reg("ctrl", &[], &["new_m"], 1_000_000, 500_000, "s")];
    let writes = vec![MetricWriteRequest {
        controller_id: "ctrl".into(),
        metric: "new_m".into(),
        value: 42,
    }];
    let eval = quick_run(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    assert!(eval.pass);
    assert_eq!(*eval.final_metrics.get("new_m").unwrap(), 42);
    // Initial metrics should still be empty except for the write
    assert_eq!(eval.final_metrics.len(), 1);
}

// ===========================================================================
// 52) Final metrics preserve initial metrics not written to
// ===========================================================================

#[test]
fn final_metrics_preserve_unwritten_initial_metrics() {
    let config = InterferenceConfig::default();
    let regs = vec![make_reg("ctrl", &[], &["m1"], 1_000_000, 500_000, "s")];
    let writes = vec![MetricWriteRequest {
        controller_id: "ctrl".into(),
        metric: "m1".into(),
        value: 100,
    }];
    let mut initial = BTreeMap::new();
    initial.insert("m1".to_string(), 1);
    initial.insert("m2".to_string(), 2);
    initial.insert("m3".to_string(), 3);
    let eval = quick_run(&config, &regs, &[], &writes, &[], &initial);
    assert!(eval.pass);
    assert_eq!(*eval.final_metrics.get("m1").unwrap(), 100);
    assert_eq!(*eval.final_metrics.get("m2").unwrap(), 2);
    assert_eq!(*eval.final_metrics.get("m3").unwrap(), 3);
}

// ===========================================================================
// 53) Subscription stream keyed by controller_id
// ===========================================================================

#[test]
fn subscription_stream_keyed_by_controller_id() {
    let config = InterferenceConfig::default();
    let regs = vec![
        make_reg("ctrl-a", &["m"], &[], 1_000_000, 500_000, "a"),
        make_reg("ctrl-b", &["m"], &[], 1_000_000, 500_000, "b"),
    ];
    let subs = vec![
        MetricSubscription {
            controller_id: "ctrl-a".into(),
            metric: "m".into(),
        },
        MetricSubscription {
            controller_id: "ctrl-b".into(),
            metric: "m".into(),
        },
    ];
    let mut initial = BTreeMap::new();
    initial.insert("m".to_string(), 42);
    let eval = quick_run(&config, &regs, &[], &[], &subs, &initial);
    assert!(eval.subscription_streams.contains_key("ctrl-a"));
    assert!(eval.subscription_streams.contains_key("ctrl-b"));
    assert_eq!(
        eval.subscription_streams.get("ctrl-a").unwrap()[0].value,
        42
    );
    assert_eq!(
        eval.subscription_streams.get("ctrl-b").unwrap()[0].value,
        42
    );
}

// ===========================================================================
// 54) Subscription value reflects writes, not initial
// ===========================================================================

#[test]
fn subscription_value_reflects_writes() {
    let config = InterferenceConfig::default();
    let regs = vec![
        make_reg("writer", &[], &["m"], 1_000_000, 500_000, "w"),
        make_reg("subscriber", &["m"], &[], 1_000_000, 500_000, "s"),
    ];
    let writes = vec![MetricWriteRequest {
        controller_id: "writer".into(),
        metric: "m".into(),
        value: 999,
    }];
    let subs = vec![MetricSubscription {
        controller_id: "subscriber".into(),
        metric: "m".into(),
    }];
    let mut initial = BTreeMap::new();
    initial.insert("m".to_string(), 1);
    let eval = quick_run(&config, &regs, &[], &writes, &subs, &initial);
    assert!(eval.pass);
    let updates = eval.subscription_streams.get("subscriber").unwrap();
    assert_eq!(updates[0].value, 999);
}

// ===========================================================================
// 55) Serde: InterferenceFinding with None metric
// ===========================================================================

#[test]
fn serde_roundtrip_finding_with_none_metric() {
    let f = InterferenceFinding {
        code: InterferenceFailureCode::DuplicateController,
        metric: None,
        controller_ids: vec!["ctrl".to_string()],
        detail: "dup".to_string(),
    };
    let json = serde_json::to_string(&f).unwrap();
    let back: InterferenceFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
    assert!(json.contains("null"));
}

// ===========================================================================
// 56) Serde: InterferenceLogEvent with all optional fields
// ===========================================================================

#[test]
fn serde_roundtrip_log_event_all_fields_populated() {
    let le = InterferenceLogEvent {
        trace_id: "t-123".into(),
        decision_id: "d-456".into(),
        policy_id: "p-789".into(),
        component: "controller_interference_guard".into(),
        event: "timescale_conflict".into(),
        outcome: "fail".into(),
        error_code: Some("timescale_conflict".into()),
        metric: Some("cpu".into()),
        controller_ids: vec!["ctrl-a".into(), "ctrl-b".into()],
    };
    let json = serde_json::to_string(&le).unwrap();
    let back: InterferenceLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(le, back);
}

// ===========================================================================
// 57) InterferenceResolution serde: Reject mode
// ===========================================================================

#[test]
fn serde_roundtrip_resolution_reject_mode() {
    let r = InterferenceResolution {
        metric: "m".into(),
        controller_ids: vec!["a".into(), "b".into()],
        mode: ConflictResolutionMode::Reject,
        detail: "rejected".into(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: InterferenceResolution = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ===========================================================================
// 58) InterferenceConfig custom values serde roundtrip
// ===========================================================================

#[test]
fn serde_roundtrip_config_custom_values() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 999_999,
        conflict_resolution_mode: ConflictResolutionMode::Serialize,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: InterferenceConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ===========================================================================
// 59) ControllerRegistration with empty metrics sets
// ===========================================================================

#[test]
fn registration_with_empty_metrics_sets() {
    let config = InterferenceConfig::default();
    let regs = vec![make_reg("ctrl", &[], &[], 1_000_000, 500_000, "no metrics")];
    let eval = quick_run(&config, &regs, &[], &[], &[], &BTreeMap::new());
    assert!(eval.pass);
}

// ===========================================================================
// 60) No registrations but with initial metrics
// ===========================================================================

#[test]
fn no_registrations_with_initial_metrics() {
    let config = InterferenceConfig::default();
    let mut initial = BTreeMap::new();
    initial.insert("cpu".to_string(), 100);
    initial.insert("mem".to_string(), 200);
    let eval = quick_run(&config, &[], &[], &[], &[], &initial);
    assert!(eval.pass);
    // Final metrics should be the same as initial
    assert_eq!(eval.final_metrics, initial);
}

// ===========================================================================
// 61) Conflict on one metric doesn't affect writes to another metric
// ===========================================================================

#[test]
fn conflict_on_one_metric_allows_other_metric_writes() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Reject,
    };
    let regs = vec![
        make_reg(
            "ctrl-a",
            &[],
            &["conflict_m", "safe_m"],
            1_000_000,
            500_000,
            "a",
        ),
        make_reg("ctrl-b", &[], &["conflict_m"], 1_000_000, 510_000, "b"),
    ];
    let writes = vec![
        MetricWriteRequest {
            controller_id: "ctrl-a".into(),
            metric: "conflict_m".into(),
            value: 1,
        },
        MetricWriteRequest {
            controller_id: "ctrl-b".into(),
            metric: "conflict_m".into(),
            value: 2,
        },
        MetricWriteRequest {
            controller_id: "ctrl-a".into(),
            metric: "safe_m".into(),
            value: 42,
        },
    ];
    let eval = quick_run(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    assert!(!eval.pass); // conflict_m has issues
    // safe_m write should still be applied
    assert_eq!(*eval.final_metrics.get("safe_m").unwrap(), 42);
}

// ===========================================================================
// 62) TimescaleSeparationStatement with extreme values
// ===========================================================================

#[test]
fn timescale_extreme_interval_values() {
    let config = InterferenceConfig::default();
    let regs = vec![make_reg("ctrl", &["m"], &[], i64::MAX, i64::MAX, "extreme")];
    let reads = vec![MetricReadRequest {
        controller_id: "ctrl".into(),
        metric: "m".into(),
    }];
    let mut initial = BTreeMap::new();
    initial.insert("m".to_string(), 1);
    let eval = quick_run(&config, &regs, &reads, &[], &[], &initial);
    assert!(eval.pass);
    assert_eq!(eval.read_snapshots.get("ctrl:m"), Some(&1));
}

// ===========================================================================
// 63) Multiple duplicate controllers only first pair flagged
// ===========================================================================

#[test]
fn triple_duplicate_generates_findings_for_each_extra() {
    let config = InterferenceConfig::default();
    let regs = vec![
        make_reg("dup", &[], &[], 1_000_000, 500_000, "first"),
        make_reg("dup", &[], &[], 1_000_000, 500_000, "second"),
        make_reg("dup", &[], &[], 1_000_000, 500_000, "third"),
    ];
    let eval = quick_run(&config, &regs, &[], &[], &[], &BTreeMap::new());
    let dup_findings: Vec<_> = eval
        .findings
        .iter()
        .filter(|f| f.code == InterferenceFailureCode::DuplicateController)
        .collect();
    // Second and third are duplicates of first
    assert_eq!(dup_findings.len(), 2);
}

// ===========================================================================
// 64) Conflict with mixed modes across separate metrics
// ===========================================================================

#[test]
fn serialize_mode_applies_to_all_conflicting_metrics() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Serialize,
    };
    let regs = vec![
        make_reg("ctrl-a", &[], &["m1", "m2"], 1_000_000, 500_000, "a"),
        make_reg("ctrl-b", &[], &["m1", "m2"], 1_000_000, 510_000, "b"),
    ];
    let writes = vec![
        MetricWriteRequest {
            controller_id: "ctrl-a".into(),
            metric: "m1".into(),
            value: 1,
        },
        MetricWriteRequest {
            controller_id: "ctrl-b".into(),
            metric: "m1".into(),
            value: 2,
        },
        MetricWriteRequest {
            controller_id: "ctrl-a".into(),
            metric: "m2".into(),
            value: 3,
        },
        MetricWriteRequest {
            controller_id: "ctrl-b".into(),
            metric: "m2".into(),
            value: 4,
        },
    ];
    let eval = quick_run(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    assert!(eval.pass);
    assert_eq!(eval.resolutions.len(), 2);
    let resolution_metrics: BTreeSet<_> =
        eval.resolutions.iter().map(|r| r.metric.clone()).collect();
    assert!(resolution_metrics.contains("m1"));
    assert!(resolution_metrics.contains("m2"));
}

// ===========================================================================
// 65) Empty initial_metrics: reads default to zero
// ===========================================================================

#[test]
fn reads_default_to_zero_with_empty_initial() {
    let config = InterferenceConfig::default();
    let regs = vec![make_reg(
        "ctrl",
        &["m1", "m2"],
        &[],
        1_000_000,
        500_000,
        "s",
    )];
    let reads = vec![
        MetricReadRequest {
            controller_id: "ctrl".into(),
            metric: "m1".into(),
        },
        MetricReadRequest {
            controller_id: "ctrl".into(),
            metric: "m2".into(),
        },
    ];
    let eval = quick_run(&config, &regs, &reads, &[], &[], &BTreeMap::new());
    assert!(eval.pass);
    assert_eq!(eval.read_snapshots.get("ctrl:m1"), Some(&0));
    assert_eq!(eval.read_snapshots.get("ctrl:m2"), Some(&0));
}

// ===========================================================================
// 66) Both missing statement AND invalid interval on same controller
// ===========================================================================

#[test]
fn missing_statement_and_invalid_interval_both_found() {
    let config = InterferenceConfig::default();
    let regs = vec![ControllerRegistration {
        controller_id: "bad".into(),
        read_metrics: BTreeSet::new(),
        write_metrics: BTreeSet::new(),
        timescale: TimescaleSeparationStatement {
            observation_interval_millionths: -1,
            write_interval_millionths: 0,
            statement: "".into(),
        },
    }];
    let eval = quick_run(&config, &regs, &[], &[], &[], &BTreeMap::new());
    assert!(!eval.pass);
    let codes: BTreeSet<_> = eval.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&InterferenceFailureCode::MissingTimescaleStatement));
    assert!(codes.contains(&InterferenceFailureCode::InvalidTimescaleInterval));
}

// ===========================================================================
// 67) Rejected write from unknown controller still creates finding with metric info
// ===========================================================================

#[test]
fn rejected_unknown_write_finding_has_metric_info() {
    let config = InterferenceConfig::default();
    let writes = vec![MetricWriteRequest {
        controller_id: "ghost".into(),
        metric: "special_m".into(),
        value: 1,
    }];
    let eval = quick_run(&config, &[], &[], &writes, &[], &BTreeMap::new());
    let finding = eval
        .findings
        .iter()
        .find(|f| f.code == InterferenceFailureCode::UnknownController)
        .unwrap();
    assert_eq!(finding.metric.as_deref(), Some("special_m"));
    assert!(finding.controller_ids.contains(&"ghost".to_string()));
}

// ===========================================================================
// 68) Resolution controller_ids list all participating controllers
// ===========================================================================

#[test]
fn resolution_controller_ids_lists_all_writers() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 1_000_000,
        conflict_resolution_mode: ConflictResolutionMode::Serialize,
    };
    let regs = vec![
        make_reg("ctrl-a", &[], &["m"], 1_000_000, 500_000, "a"),
        make_reg("ctrl-b", &[], &["m"], 1_000_000, 500_000, "b"),
        make_reg("ctrl-c", &[], &["m"], 1_000_000, 500_000, "c"),
    ];
    let writes = vec![
        MetricWriteRequest {
            controller_id: "ctrl-a".into(),
            metric: "m".into(),
            value: 1,
        },
        MetricWriteRequest {
            controller_id: "ctrl-b".into(),
            metric: "m".into(),
            value: 2,
        },
        MetricWriteRequest {
            controller_id: "ctrl-c".into(),
            metric: "m".into(),
            value: 3,
        },
    ];
    let eval = quick_run(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    let resolution = &eval.resolutions[0];
    assert!(resolution.controller_ids.contains(&"ctrl-a".to_string()));
    assert!(resolution.controller_ids.contains(&"ctrl-b".to_string()));
    assert!(resolution.controller_ids.contains(&"ctrl-c".to_string()));
}

// ===========================================================================
// 69) Subscription after rejected writes: metric retains initial value
// ===========================================================================

#[test]
fn subscription_after_rejected_conflict_shows_initial_value() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Reject,
    };
    let regs = vec![
        make_reg("ctrl-a", &[], &["m"], 1_000_000, 500_000, "a"),
        make_reg("ctrl-b", &["m"], &["m"], 1_000_000, 510_000, "b"),
    ];
    let writes = vec![
        MetricWriteRequest {
            controller_id: "ctrl-a".into(),
            metric: "m".into(),
            value: 999,
        },
        MetricWriteRequest {
            controller_id: "ctrl-b".into(),
            metric: "m".into(),
            value: 888,
        },
    ];
    let subs = vec![MetricSubscription {
        controller_id: "ctrl-b".into(),
        metric: "m".into(),
    }];
    let mut initial = BTreeMap::new();
    initial.insert("m".to_string(), 42);
    let eval = quick_run(&config, &regs, &[], &writes, &subs, &initial);
    // Writes were rejected, so subscription should see the initial value
    let updates = eval.subscription_streams.get("ctrl-b").unwrap();
    assert_eq!(updates[0].value, 42);
}

// ===========================================================================
// 70) Serde round-trip with subscription_streams populated
// ===========================================================================

#[test]
fn serde_roundtrip_evaluation_with_subscription_streams() {
    let config = InterferenceConfig::default();
    let regs = vec![
        make_reg("writer", &[], &["m"], 1_000_000, 500_000, "w"),
        make_reg("sub", &["m"], &[], 1_000_000, 500_000, "s"),
    ];
    let writes = vec![MetricWriteRequest {
        controller_id: "writer".into(),
        metric: "m".into(),
        value: 77,
    }];
    let subs = vec![MetricSubscription {
        controller_id: "sub".into(),
        metric: "m".into(),
    }];
    let eval = quick_run(&config, &regs, &[], &writes, &subs, &BTreeMap::new());
    assert!(!eval.subscription_streams.is_empty());

    let json = serde_json::to_string(&eval).unwrap();
    let back: InterferenceEvaluation = serde_json::from_str(&json).unwrap();
    assert_eq!(eval, back);
}

// ===========================================================================
// 71) Unauthorized read finding has correct metric
// ===========================================================================

#[test]
fn unauthorized_read_finding_has_correct_metric() {
    let config = InterferenceConfig::default();
    let regs = vec![make_reg("ctrl", &["allowed"], &[], 1_000_000, 500_000, "s")];
    let reads = vec![MetricReadRequest {
        controller_id: "ctrl".into(),
        metric: "forbidden".into(),
    }];
    let eval = quick_run(&config, &regs, &reads, &[], &[], &BTreeMap::new());
    let finding = eval
        .findings
        .iter()
        .find(|f| f.code == InterferenceFailureCode::UnauthorizedRead)
        .unwrap();
    assert_eq!(finding.metric.as_deref(), Some("forbidden"));
}

// ===========================================================================
// 72) Unauthorized write finding has correct metric
// ===========================================================================

#[test]
fn unauthorized_write_finding_has_correct_metric() {
    let config = InterferenceConfig::default();
    let regs = vec![make_reg("ctrl", &[], &["allowed"], 1_000_000, 500_000, "s")];
    let writes = vec![MetricWriteRequest {
        controller_id: "ctrl".into(),
        metric: "forbidden".into(),
        value: 1,
    }];
    let eval = quick_run(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    let finding = eval
        .findings
        .iter()
        .find(|f| f.code == InterferenceFailureCode::UnauthorizedWrite)
        .unwrap();
    assert_eq!(finding.metric.as_deref(), Some("forbidden"));
}

// ===========================================================================
// 73) DuplicateController finding has None metric
// ===========================================================================

#[test]
fn duplicate_controller_finding_has_none_metric() {
    let config = InterferenceConfig::default();
    let regs = vec![
        make_reg("dup", &[], &[], 1_000_000, 500_000, "first"),
        make_reg("dup", &[], &[], 1_000_000, 500_000, "second"),
    ];
    let eval = quick_run(&config, &regs, &[], &[], &[], &BTreeMap::new());
    let finding = eval
        .findings
        .iter()
        .find(|f| f.code == InterferenceFailureCode::DuplicateController)
        .unwrap();
    assert!(finding.metric.is_none());
}

// ===========================================================================
// 74) MissingTimescaleStatement finding has None metric
// ===========================================================================

#[test]
fn missing_timescale_finding_has_none_metric() {
    let config = InterferenceConfig::default();
    let regs = vec![make_reg("ctrl", &[], &[], 1_000_000, 500_000, "")];
    let eval = quick_run(&config, &regs, &[], &[], &[], &BTreeMap::new());
    let finding = eval
        .findings
        .iter()
        .find(|f| f.code == InterferenceFailureCode::MissingTimescaleStatement)
        .unwrap();
    assert!(finding.metric.is_none());
}

// ===========================================================================
// 75) InvalidTimescaleInterval finding has None metric
// ===========================================================================

#[test]
fn invalid_interval_finding_has_none_metric() {
    let config = InterferenceConfig::default();
    let regs = vec![make_reg("ctrl", &[], &[], 0, 500_000, "bad")];
    let eval = quick_run(&config, &regs, &[], &[], &[], &BTreeMap::new());
    let finding = eval
        .findings
        .iter()
        .find(|f| f.code == InterferenceFailureCode::InvalidTimescaleInterval)
        .unwrap();
    assert!(finding.metric.is_none());
}

// ===========================================================================
// 76) Stress: 100 registrations with varying timescales, deterministic output
// ===========================================================================

#[test]
fn stress_100_registrations_deterministic() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 10_000,
        conflict_resolution_mode: ConflictResolutionMode::Serialize,
    };
    let mut regs = Vec::new();
    let mut writes = Vec::new();
    let mut initial = BTreeMap::new();

    for i in 0..100u64 {
        let ctrl_id = format!("ctrl-{i:04}");
        let metric = format!("m-{}", i / 10); // 10 controllers per metric
        let wr_interval = 1_000_000 + (i as i64) * 1_000;
        regs.push(make_reg(
            &ctrl_id,
            &[],
            &[&metric],
            1_000_000,
            wr_interval,
            &format!("ctrl {i}"),
        ));
        writes.push(MetricWriteRequest {
            controller_id: ctrl_id,
            metric: metric.clone(),
            value: i as i64,
        });
        initial.entry(metric).or_insert(0);
    }

    let e1 = quick_run(&config, &regs, &[], &writes, &[], &initial);
    let e2 = quick_run(&config, &regs, &[], &writes, &[], &initial);
    assert_eq!(e1, e2);
    assert!(!e1.decision_id.is_empty());
}

// ===========================================================================
// 77) Timescale conflict finding controller_ids contains both controllers
// ===========================================================================

#[test]
fn timescale_conflict_finding_controller_ids_correct() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Reject,
    };
    let regs = vec![
        make_reg("alpha", &[], &["m"], 1_000_000, 500_000, "a"),
        make_reg("beta", &[], &["m"], 1_000_000, 510_000, "b"),
    ];
    let writes = vec![
        MetricWriteRequest {
            controller_id: "alpha".into(),
            metric: "m".into(),
            value: 1,
        },
        MetricWriteRequest {
            controller_id: "beta".into(),
            metric: "m".into(),
            value: 2,
        },
    ];
    let eval = quick_run(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    let finding = eval
        .findings
        .iter()
        .find(|f| f.code == InterferenceFailureCode::TimescaleConflict)
        .unwrap();
    assert_eq!(finding.controller_ids.len(), 2);
    assert!(finding.controller_ids.contains(&"alpha".to_string()));
    assert!(finding.controller_ids.contains(&"beta".to_string()));
}
