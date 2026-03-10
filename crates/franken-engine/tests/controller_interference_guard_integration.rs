//! Integration tests for the `controller_interference_guard` module.
//!
//! Bead: bd-s6rf

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::controller_interference_guard::{
    ConflictResolutionMode, ControllerRegistration, InterferenceConfig, InterferenceEvaluation,
    InterferenceFailureCode, InterferenceScenario, MetricReadRequest, MetricSubscription,
    MetricUpdate, MetricWriteRequest, TimescaleSeparationStatement,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn reg(
    id: &str,
    reads: &[&str],
    writes: &[&str],
    obs_millionths: i64,
    write_millionths: i64,
    statement: &str,
) -> ControllerRegistration {
    ControllerRegistration {
        controller_id: id.to_string(),
        read_metrics: reads.iter().map(|s| s.to_string()).collect(),
        write_metrics: writes.iter().map(|s| s.to_string()).collect(),
        timescale: TimescaleSeparationStatement {
            observation_interval_millionths: obs_millionths,
            write_interval_millionths: write_millionths,
            statement: statement.to_string(),
        },
    }
}

fn default_metrics() -> BTreeMap<String, i64> {
    BTreeMap::from([
        ("cpu".to_string(), 50),
        ("mem".to_string(), 200),
        ("latency".to_string(), 100),
    ])
}

#[allow(clippy::too_many_arguments)]
fn eval<'a>(
    trace: &'a str,
    policy: &'a str,
    config: &'a InterferenceConfig,
    registrations: &'a [ControllerRegistration],
    reads: &'a [MetricReadRequest],
    writes: &'a [MetricWriteRequest],
    subs: &'a [MetricSubscription],
    metrics: &'a BTreeMap<String, i64>,
) -> InterferenceEvaluation {
    frankenengine_engine::controller_interference_guard::evaluate_controller_interference(
        &InterferenceScenario {
            trace_id: trace,
            policy_id: policy,
            config,
            registrations,
            read_requests: reads,
            write_requests: writes,
            subscriptions: subs,
            initial_metrics: metrics,
        },
    )
}

// ---------------------------------------------------------------------------
// Display impls
// ---------------------------------------------------------------------------

#[test]
fn conflict_resolution_mode_display_serialize() {
    assert_eq!(ConflictResolutionMode::Serialize.to_string(), "serialize");
}

#[test]
fn conflict_resolution_mode_display_reject() {
    assert_eq!(ConflictResolutionMode::Reject.to_string(), "reject");
}

#[test]
fn interference_failure_code_display_all_variants() {
    let cases = [
        (
            InterferenceFailureCode::DuplicateController,
            "duplicate_controller",
        ),
        (
            InterferenceFailureCode::MissingTimescaleStatement,
            "missing_timescale_statement",
        ),
        (
            InterferenceFailureCode::InvalidTimescaleInterval,
            "invalid_timescale_interval",
        ),
        (
            InterferenceFailureCode::UnknownController,
            "unknown_controller",
        ),
        (
            InterferenceFailureCode::UnauthorizedRead,
            "unauthorized_read",
        ),
        (
            InterferenceFailureCode::UnauthorizedWrite,
            "unauthorized_write",
        ),
        (
            InterferenceFailureCode::TimescaleConflict,
            "timescale_conflict",
        ),
    ];
    for (code, expected) in cases {
        assert_eq!(code.to_string(), expected, "mismatch for {code:?}");
    }
}

// ---------------------------------------------------------------------------
// InterferenceConfig default
// ---------------------------------------------------------------------------

#[test]
fn interference_config_default_has_reject_mode_and_100k_separation() {
    let config = InterferenceConfig::default();
    assert_eq!(config.min_timescale_separation_millionths, 100_000);
    assert_eq!(
        config.conflict_resolution_mode,
        ConflictResolutionMode::Reject
    );
}

// ---------------------------------------------------------------------------
// Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn conflict_resolution_mode_serde_roundtrip() {
    for mode in [
        ConflictResolutionMode::Serialize,
        ConflictResolutionMode::Reject,
    ] {
        let json = serde_json::to_string(&mode).unwrap();
        let back: ConflictResolutionMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, back);
    }
}

#[test]
fn interference_config_serde_roundtrip() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 42_000,
        conflict_resolution_mode: ConflictResolutionMode::Serialize,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: InterferenceConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn controller_registration_serde_roundtrip() {
    let r = reg(
        "ctrl-1",
        &["cpu", "mem"],
        &["latency"],
        500_000,
        1_000_000,
        "test",
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: ControllerRegistration = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn metric_read_request_serde_roundtrip() {
    let r = MetricReadRequest {
        controller_id: "ctrl-x".to_string(),
        metric: "cpu".to_string(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: MetricReadRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn metric_write_request_serde_roundtrip() {
    let w = MetricWriteRequest {
        controller_id: "ctrl-y".to_string(),
        metric: "mem".to_string(),
        value: 1024,
    };
    let json = serde_json::to_string(&w).unwrap();
    let back: MetricWriteRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(w, back);
}

#[test]
fn metric_subscription_serde_roundtrip() {
    let s = MetricSubscription {
        controller_id: "ctrl-z".to_string(),
        metric: "latency".to_string(),
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: MetricSubscription = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn metric_update_serde_roundtrip() {
    let u = MetricUpdate {
        sequence: 7,
        metric: "cpu".to_string(),
        value: 99,
    };
    let json = serde_json::to_string(&u).unwrap();
    let back: MetricUpdate = serde_json::from_str(&json).unwrap();
    assert_eq!(u, back);
}

#[test]
fn interference_failure_code_serde_roundtrip() {
    let codes = [
        InterferenceFailureCode::DuplicateController,
        InterferenceFailureCode::MissingTimescaleStatement,
        InterferenceFailureCode::InvalidTimescaleInterval,
        InterferenceFailureCode::UnknownController,
        InterferenceFailureCode::UnauthorizedRead,
        InterferenceFailureCode::UnauthorizedWrite,
        InterferenceFailureCode::TimescaleConflict,
    ];
    for code in codes {
        let json = serde_json::to_string(&code).unwrap();
        let back: InterferenceFailureCode = serde_json::from_str(&json).unwrap();
        assert_eq!(code, back);
    }
}

#[test]
fn interference_failure_code_ord() {
    assert!(
        InterferenceFailureCode::DuplicateController < InterferenceFailureCode::TimescaleConflict
    );
}

// ---------------------------------------------------------------------------
// evaluate_controller_interference — clean scenario
// ---------------------------------------------------------------------------

#[test]
fn clean_scenario_passes_with_no_findings() {
    let registrations = vec![reg(
        "ctrl-a",
        &["cpu"],
        &["cpu"],
        1_000_000,
        2_000_000,
        "reads 1s, writes 2s",
    )];
    let config = InterferenceConfig::default();
    let metrics = default_metrics();
    let reads = [MetricReadRequest {
        controller_id: "ctrl-a".to_string(),
        metric: "cpu".to_string(),
    }];
    let writes = [MetricWriteRequest {
        controller_id: "ctrl-a".to_string(),
        metric: "cpu".to_string(),
        value: 75,
    }];

    let result = eval(
        "t1",
        "p1",
        &config,
        &registrations,
        &reads,
        &writes,
        &[],
        &metrics,
    );

    assert!(result.pass);
    assert!(!result.rollback_required);
    assert!(result.findings.is_empty());
    assert_eq!(result.applied_writes.len(), 1);
    assert_eq!(result.rejected_writes.len(), 0);
    assert_eq!(result.final_metrics.get("cpu"), Some(&75));
    assert_eq!(result.read_snapshots.get("ctrl-a:cpu"), Some(&50));
}

#[test]
fn empty_scenario_passes() {
    let config = InterferenceConfig::default();
    let metrics = BTreeMap::new();

    let result = eval("t-empty", "p-empty", &config, &[], &[], &[], &[], &metrics);

    assert!(result.pass);
    assert!(!result.rollback_required);
    assert!(result.findings.is_empty());
    assert!(result.applied_writes.is_empty());
    assert!(result.final_metrics.is_empty());
}

// ---------------------------------------------------------------------------
// Decision ID determinism
// ---------------------------------------------------------------------------

#[test]
fn decision_id_is_deterministic_for_same_input() {
    let registrations = vec![reg(
        "ctrl-det",
        &["cpu"],
        &[],
        500_000,
        1_000_000,
        "determinism test",
    )];
    let config = InterferenceConfig::default();
    let metrics = default_metrics();

    let r1 = eval(
        "t-det",
        "p-det",
        &config,
        &registrations,
        &[],
        &[],
        &[],
        &metrics,
    );
    let r2 = eval(
        "t-det",
        "p-det",
        &config,
        &registrations,
        &[],
        &[],
        &[],
        &metrics,
    );

    assert_eq!(r1.decision_id, r2.decision_id);
    assert!(r1.decision_id.starts_with("ctrl-interference-"));
}

#[test]
fn decision_id_changes_with_different_input() {
    let registrations = vec![reg(
        "ctrl-det",
        &["cpu"],
        &[],
        500_000,
        1_000_000,
        "determinism test",
    )];
    let config = InterferenceConfig::default();
    let metrics = default_metrics();

    let r1 = eval(
        "t-det-a",
        "p-det",
        &config,
        &registrations,
        &[],
        &[],
        &[],
        &metrics,
    );
    let r2 = eval(
        "t-det-b",
        "p-det",
        &config,
        &registrations,
        &[],
        &[],
        &[],
        &metrics,
    );

    assert_ne!(r1.decision_id, r2.decision_id);
}

// ---------------------------------------------------------------------------
// Duplicate controller
// ---------------------------------------------------------------------------

#[test]
fn duplicate_controller_generates_finding() {
    let registrations = vec![
        reg("ctrl-dup", &["cpu"], &[], 500_000, 1_000_000, "first"),
        reg("ctrl-dup", &["mem"], &[], 600_000, 1_200_000, "second"),
    ];
    let config = InterferenceConfig::default();
    let metrics = default_metrics();

    let result = eval(
        "t-dup",
        "p-dup",
        &config,
        &registrations,
        &[],
        &[],
        &[],
        &metrics,
    );

    assert!(!result.pass);
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.code == InterferenceFailureCode::DuplicateController
                && f.controller_ids.contains(&"ctrl-dup".to_string()))
    );
}

// ---------------------------------------------------------------------------
// Missing timescale statement
// ---------------------------------------------------------------------------

#[test]
fn missing_timescale_statement_generates_finding() {
    let registrations = vec![reg("ctrl-no-ts", &["cpu"], &[], 500_000, 1_000_000, "")];
    let config = InterferenceConfig::default();
    let metrics = default_metrics();

    let result = eval(
        "t-mts",
        "p-mts",
        &config,
        &registrations,
        &[],
        &[],
        &[],
        &metrics,
    );

    assert!(!result.pass);
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.code == InterferenceFailureCode::MissingTimescaleStatement)
    );
}

#[test]
fn whitespace_only_timescale_statement_generates_finding() {
    let registrations = vec![reg("ctrl-ws", &["cpu"], &[], 500_000, 1_000_000, "   \t  ")];
    let config = InterferenceConfig::default();
    let metrics = default_metrics();

    let result = eval(
        "t-ws",
        "p-ws",
        &config,
        &registrations,
        &[],
        &[],
        &[],
        &metrics,
    );

    assert!(!result.pass);
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.code == InterferenceFailureCode::MissingTimescaleStatement)
    );
}

// ---------------------------------------------------------------------------
// Invalid timescale interval
// ---------------------------------------------------------------------------

#[test]
fn zero_observation_interval_generates_finding() {
    let registrations = vec![reg("ctrl-bad-obs", &["cpu"], &[], 0, 1_000_000, "zero obs")];
    let config = InterferenceConfig::default();
    let metrics = default_metrics();

    let result = eval(
        "t-zi",
        "p-zi",
        &config,
        &registrations,
        &[],
        &[],
        &[],
        &metrics,
    );

    assert!(!result.pass);
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.code == InterferenceFailureCode::InvalidTimescaleInterval)
    );
}

#[test]
fn negative_write_interval_generates_finding() {
    let registrations = vec![reg(
        "ctrl-neg",
        &["cpu"],
        &[],
        500_000,
        -1,
        "negative write",
    )];
    let config = InterferenceConfig::default();
    let metrics = default_metrics();

    let result = eval(
        "t-neg",
        "p-neg",
        &config,
        &registrations,
        &[],
        &[],
        &[],
        &metrics,
    );

    assert!(!result.pass);
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.code == InterferenceFailureCode::InvalidTimescaleInterval)
    );
}

// ---------------------------------------------------------------------------
// Unknown controller
// ---------------------------------------------------------------------------

#[test]
fn read_from_unknown_controller_generates_finding() {
    let config = InterferenceConfig::default();
    let metrics = default_metrics();
    let reads = [MetricReadRequest {
        controller_id: "ghost".to_string(),
        metric: "cpu".to_string(),
    }];

    let result = eval("t-uk-r", "p-uk-r", &config, &[], &reads, &[], &[], &metrics);

    assert!(!result.pass);
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.code == InterferenceFailureCode::UnknownController
                && f.metric.as_deref() == Some("cpu"))
    );
}

#[test]
fn write_from_unknown_controller_generates_finding_and_rejects() {
    let config = InterferenceConfig::default();
    let metrics = default_metrics();
    let writes = [MetricWriteRequest {
        controller_id: "phantom".to_string(),
        metric: "cpu".to_string(),
        value: 99,
    }];

    let result = eval(
        "t-uk-w",
        "p-uk-w",
        &config,
        &[],
        &[],
        &writes,
        &[],
        &metrics,
    );

    assert!(!result.pass);
    assert_eq!(result.rejected_writes.len(), 1);
    assert_eq!(result.applied_writes.len(), 0);
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.code == InterferenceFailureCode::UnknownController)
    );
}

#[test]
fn subscription_from_unknown_controller_generates_finding() {
    let config = InterferenceConfig::default();
    let metrics = default_metrics();
    let subs = [MetricSubscription {
        controller_id: "specter".to_string(),
        metric: "cpu".to_string(),
    }];

    let result = eval("t-uk-s", "p-uk-s", &config, &[], &[], &[], &subs, &metrics);

    assert!(!result.pass);
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.code == InterferenceFailureCode::UnknownController
                && f.metric.as_deref() == Some("cpu"))
    );
}

// ---------------------------------------------------------------------------
// Unauthorized read / write
// ---------------------------------------------------------------------------

#[test]
fn read_of_unauthorized_metric_generates_finding() {
    let registrations = vec![reg(
        "ctrl-r",
        &["cpu"],
        &[],
        500_000,
        1_000_000,
        "reads cpu only",
    )];
    let config = InterferenceConfig::default();
    let metrics = default_metrics();
    let reads = [MetricReadRequest {
        controller_id: "ctrl-r".to_string(),
        metric: "mem".to_string(),
    }];

    let result = eval(
        "t-ur",
        "p-ur",
        &config,
        &registrations,
        &reads,
        &[],
        &[],
        &metrics,
    );

    assert!(!result.pass);
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.code == InterferenceFailureCode::UnauthorizedRead
                && f.metric.as_deref() == Some("mem"))
    );
}

#[test]
fn write_to_unauthorized_metric_generates_finding_and_rejects() {
    let registrations = vec![reg(
        "ctrl-w",
        &[],
        &["cpu"],
        500_000,
        1_000_000,
        "writes cpu only",
    )];
    let config = InterferenceConfig::default();
    let metrics = default_metrics();
    let writes = [MetricWriteRequest {
        controller_id: "ctrl-w".to_string(),
        metric: "mem".to_string(),
        value: 512,
    }];

    let result = eval(
        "t-uw",
        "p-uw",
        &config,
        &registrations,
        &[],
        &writes,
        &[],
        &metrics,
    );

    assert!(!result.pass);
    assert_eq!(result.rejected_writes.len(), 1);
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.code == InterferenceFailureCode::UnauthorizedWrite
                && f.metric.as_deref() == Some("mem"))
    );
}

#[test]
fn subscription_for_unauthorized_metric_generates_finding() {
    let registrations = vec![reg(
        "ctrl-sub",
        &["cpu"],
        &[],
        500_000,
        1_000_000,
        "reads cpu",
    )];
    let config = InterferenceConfig::default();
    let metrics = default_metrics();
    let subs = [MetricSubscription {
        controller_id: "ctrl-sub".to_string(),
        metric: "latency".to_string(),
    }];

    let result = eval(
        "t-us",
        "p-us",
        &config,
        &registrations,
        &[],
        &[],
        &subs,
        &metrics,
    );

    assert!(!result.pass);
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.code == InterferenceFailureCode::UnauthorizedRead
                && f.metric.as_deref() == Some("latency"))
    );
}

// ---------------------------------------------------------------------------
// Writer can also read its own write metrics
// ---------------------------------------------------------------------------

#[test]
fn controller_can_read_its_own_write_metric() {
    let registrations = vec![reg(
        "ctrl-rw",
        &[],
        &["cpu"],
        500_000,
        1_000_000,
        "writes cpu, implicit read",
    )];
    let config = InterferenceConfig::default();
    let metrics = default_metrics();
    let reads = [MetricReadRequest {
        controller_id: "ctrl-rw".to_string(),
        metric: "cpu".to_string(),
    }];

    let result = eval(
        "t-rw",
        "p-rw",
        &config,
        &registrations,
        &reads,
        &[],
        &[],
        &metrics,
    );

    assert!(result.pass);
    assert_eq!(result.read_snapshots.get("ctrl-rw:cpu"), Some(&50));
}

// ---------------------------------------------------------------------------
// Timescale conflict — Reject mode
// ---------------------------------------------------------------------------

#[test]
fn timescale_conflict_in_reject_mode_rejects_all_conflicting_writes() {
    let registrations = vec![
        reg("fast-a", &[], &["cpu"], 100_000, 100_000, "100ms writes"),
        reg("fast-b", &[], &["cpu"], 110_000, 110_000, "110ms writes"),
    ];
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Reject,
    };
    let metrics = default_metrics();
    let writes = [
        MetricWriteRequest {
            controller_id: "fast-a".to_string(),
            metric: "cpu".to_string(),
            value: 80,
        },
        MetricWriteRequest {
            controller_id: "fast-b".to_string(),
            metric: "cpu".to_string(),
            value: 90,
        },
    ];

    let result = eval(
        "t-tc-r",
        "p-tc-r",
        &config,
        &registrations,
        &[],
        &writes,
        &[],
        &metrics,
    );

    assert!(!result.pass);
    assert!(result.rollback_required);
    assert_eq!(result.applied_writes.len(), 0);
    assert_eq!(result.rejected_writes.len(), 2);
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.code == InterferenceFailureCode::TimescaleConflict
                && f.metric.as_deref() == Some("cpu"))
    );
    // Original value preserved
    assert_eq!(result.final_metrics.get("cpu"), Some(&50));
}

// ---------------------------------------------------------------------------
// Timescale conflict — Serialize mode
// ---------------------------------------------------------------------------

#[test]
fn timescale_conflict_in_serialize_mode_applies_writes_in_controller_id_order() {
    let registrations = vec![
        reg("ser-b", &[], &["latency"], 100_000, 100_000, "100ms writes"),
        reg("ser-a", &[], &["latency"], 110_000, 110_000, "110ms writes"),
    ];
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Serialize,
    };
    let metrics = default_metrics();
    let writes = [
        MetricWriteRequest {
            controller_id: "ser-b".to_string(),
            metric: "latency".to_string(),
            value: 77,
        },
        MetricWriteRequest {
            controller_id: "ser-a".to_string(),
            metric: "latency".to_string(),
            value: 88,
        },
    ];

    let result = eval(
        "t-tc-s",
        "p-tc-s",
        &config,
        &registrations,
        &[],
        &writes,
        &[],
        &metrics,
    );

    assert!(result.pass);
    assert_eq!(result.rejected_writes.len(), 0);
    assert_eq!(result.applied_writes.len(), 2);
    assert_eq!(result.resolutions.len(), 1);
    assert_eq!(
        result.resolutions[0].mode,
        ConflictResolutionMode::Serialize
    );
    assert_eq!(result.resolutions[0].metric, "latency");
    // Last write wins after serialization by controller_id order:
    // ser-a (88) is sorted before ser-b (77), so ser-b writes last
    assert_eq!(result.final_metrics.get("latency"), Some(&77));
}

// ---------------------------------------------------------------------------
// No conflict when timescale separation is sufficient
// ---------------------------------------------------------------------------

#[test]
fn writes_pass_when_timescale_separation_is_sufficient() {
    let registrations = vec![
        reg("slow-a", &[], &["mem"], 100_000, 100_000, "100ms writes"),
        reg("slow-b", &[], &["mem"], 300_000, 300_000, "300ms writes"),
    ];
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Reject,
    };
    let metrics = default_metrics();
    let writes = [
        MetricWriteRequest {
            controller_id: "slow-a".to_string(),
            metric: "mem".to_string(),
            value: 400,
        },
        MetricWriteRequest {
            controller_id: "slow-b".to_string(),
            metric: "mem".to_string(),
            value: 512,
        },
    ];

    let result = eval(
        "t-ok",
        "p-ok",
        &config,
        &registrations,
        &[],
        &writes,
        &[],
        &metrics,
    );

    assert!(result.pass);
    assert_eq!(result.applied_writes.len(), 2);
    assert_eq!(result.rejected_writes.len(), 0);
    assert!(result.resolutions.is_empty());
}

// ---------------------------------------------------------------------------
// Read snapshots reflect initial metrics, not writes
// ---------------------------------------------------------------------------

#[test]
fn read_snapshots_reflect_initial_metrics() {
    let registrations = vec![
        reg(
            "reader",
            &["cpu", "mem"],
            &[],
            500_000,
            1_000_000,
            "reads cpu+mem",
        ),
        reg("writer", &[], &["cpu"], 1_000_000, 2_000_000, "writes cpu"),
    ];
    let config = InterferenceConfig::default();
    let metrics = default_metrics();
    let reads = [
        MetricReadRequest {
            controller_id: "reader".to_string(),
            metric: "cpu".to_string(),
        },
        MetricReadRequest {
            controller_id: "reader".to_string(),
            metric: "mem".to_string(),
        },
    ];
    let writes = [MetricWriteRequest {
        controller_id: "writer".to_string(),
        metric: "cpu".to_string(),
        value: 99,
    }];

    let result = eval(
        "t-snap",
        "p-snap",
        &config,
        &registrations,
        &reads,
        &writes,
        &[],
        &metrics,
    );

    assert!(result.pass);
    // Snapshot uses initial value, not the written value
    assert_eq!(result.read_snapshots.get("reader:cpu"), Some(&50));
    assert_eq!(result.read_snapshots.get("reader:mem"), Some(&200));
    // But final metrics reflect the write
    assert_eq!(result.final_metrics.get("cpu"), Some(&99));
}

#[test]
fn read_snapshot_of_missing_metric_defaults_to_zero() {
    let registrations = vec![reg(
        "reader",
        &["nonexistent"],
        &[],
        500_000,
        1_000_000,
        "reads missing metric",
    )];
    let config = InterferenceConfig::default();
    let metrics = default_metrics();
    let reads = [MetricReadRequest {
        controller_id: "reader".to_string(),
        metric: "nonexistent".to_string(),
    }];

    let result = eval(
        "t-miss",
        "p-miss",
        &config,
        &registrations,
        &reads,
        &[],
        &[],
        &metrics,
    );

    assert!(result.pass);
    assert_eq!(result.read_snapshots.get("reader:nonexistent"), Some(&0));
}

// ---------------------------------------------------------------------------
// Subscriptions
// ---------------------------------------------------------------------------

#[test]
fn subscription_receives_update_after_write() {
    let registrations = vec![
        reg("sub-ctrl", &["cpu"], &[], 500_000, 1_000_000, "subscriber"),
        reg("writer", &[], &["cpu"], 1_000_000, 2_000_000, "writer"),
    ];
    let config = InterferenceConfig::default();
    let metrics = default_metrics();
    let writes = [MetricWriteRequest {
        controller_id: "writer".to_string(),
        metric: "cpu".to_string(),
        value: 88,
    }];
    let subs = [MetricSubscription {
        controller_id: "sub-ctrl".to_string(),
        metric: "cpu".to_string(),
    }];

    let result = eval(
        "t-sub",
        "p-sub",
        &config,
        &registrations,
        &[],
        &writes,
        &subs,
        &metrics,
    );

    assert!(result.pass);
    let updates = result.subscription_streams.get("sub-ctrl").unwrap();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].value, 88);
    assert_eq!(updates[0].metric, "cpu");
    assert_eq!(updates[0].sequence, 1);
}

#[test]
fn subscription_for_unmodified_metric_receives_initial_value() {
    let registrations = vec![reg(
        "sub-ctrl",
        &["mem"],
        &[],
        500_000,
        1_000_000,
        "subscriber",
    )];
    let config = InterferenceConfig::default();
    let metrics = default_metrics();
    let subs = [MetricSubscription {
        controller_id: "sub-ctrl".to_string(),
        metric: "mem".to_string(),
    }];

    let result = eval(
        "t-sub-init",
        "p-sub-init",
        &config,
        &registrations,
        &[],
        &[],
        &subs,
        &metrics,
    );

    assert!(result.pass);
    let updates = result.subscription_streams.get("sub-ctrl").unwrap();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].value, 200); // initial mem value
}

#[test]
fn multiple_subscriptions_get_monotonic_sequences() {
    let registrations = vec![
        reg("sub-a", &["cpu", "mem"], &[], 500_000, 1_000_000, "sub a"),
        reg("sub-b", &["cpu"], &[], 600_000, 1_200_000, "sub b"),
        reg(
            "writer",
            &[],
            &["cpu", "mem"],
            1_000_000,
            2_000_000,
            "writer",
        ),
    ];
    let config = InterferenceConfig::default();
    let metrics = default_metrics();
    let writes = [
        MetricWriteRequest {
            controller_id: "writer".to_string(),
            metric: "cpu".to_string(),
            value: 77,
        },
        MetricWriteRequest {
            controller_id: "writer".to_string(),
            metric: "mem".to_string(),
            value: 256,
        },
    ];
    let subs = [
        MetricSubscription {
            controller_id: "sub-a".to_string(),
            metric: "cpu".to_string(),
        },
        MetricSubscription {
            controller_id: "sub-a".to_string(),
            metric: "mem".to_string(),
        },
        MetricSubscription {
            controller_id: "sub-b".to_string(),
            metric: "cpu".to_string(),
        },
    ];

    let result = eval(
        "t-multi-sub",
        "p-multi-sub",
        &config,
        &registrations,
        &[],
        &writes,
        &subs,
        &metrics,
    );

    assert!(result.pass);

    // Collect all sequences across all streams
    let mut all_sequences: Vec<u64> = result
        .subscription_streams
        .values()
        .flat_map(|updates| updates.iter().map(|u| u.sequence))
        .collect();
    all_sequences.sort();
    all_sequences.dedup();
    // Each sequence number should be unique
    let total_updates: usize = result.subscription_streams.values().map(|u| u.len()).sum();
    assert_eq!(all_sequences.len(), total_updates);
}

#[test]
fn subscription_for_metric_not_in_final_metrics_produces_no_update() {
    let registrations = vec![reg(
        "sub-ctrl",
        &["nonexistent"],
        &[],
        500_000,
        1_000_000,
        "subscriber",
    )];
    let config = InterferenceConfig::default();
    let metrics = BTreeMap::new();
    let subs = [MetricSubscription {
        controller_id: "sub-ctrl".to_string(),
        metric: "nonexistent".to_string(),
    }];

    let result = eval(
        "t-no-met",
        "p-no-met",
        &config,
        &registrations,
        &[],
        &[],
        &subs,
        &metrics,
    );

    assert!(result.pass);
    // No updates because metric doesn't exist in final_metrics
    assert!(
        !result.subscription_streams.contains_key("sub-ctrl")
            || result
                .subscription_streams
                .get("sub-ctrl")
                .unwrap()
                .is_empty()
    );
}

// ---------------------------------------------------------------------------
// Write to non-initial metric creates it
// ---------------------------------------------------------------------------

#[test]
fn write_to_new_metric_creates_it_in_final_metrics() {
    let registrations = vec![reg(
        "ctrl-new",
        &[],
        &["new_metric"],
        500_000,
        1_000_000,
        "creates new metric",
    )];
    let config = InterferenceConfig::default();
    let metrics = BTreeMap::new();
    let writes = [MetricWriteRequest {
        controller_id: "ctrl-new".to_string(),
        metric: "new_metric".to_string(),
        value: 42,
    }];

    let result = eval(
        "t-new",
        "p-new",
        &config,
        &registrations,
        &[],
        &writes,
        &[],
        &metrics,
    );

    assert!(result.pass);
    assert_eq!(result.final_metrics.get("new_metric"), Some(&42));
}

// ---------------------------------------------------------------------------
// Log events
// ---------------------------------------------------------------------------

#[test]
fn logs_contain_interference_summary_event() {
    let registrations = vec![reg(
        "ctrl-log",
        &["cpu"],
        &[],
        500_000,
        1_000_000,
        "log test",
    )];
    let config = InterferenceConfig::default();
    let metrics = default_metrics();

    let result = eval(
        "t-log",
        "p-log",
        &config,
        &registrations,
        &[],
        &[],
        &[],
        &metrics,
    );

    assert!(
        result
            .logs
            .iter()
            .any(|log| log.event == "interference_summary"
                && log.outcome == "pass"
                && log.trace_id == "t-log"
                && log.policy_id == "p-log")
    );
}

#[test]
fn logs_contain_read_snapshot_events() {
    let registrations = vec![reg(
        "ctrl-log-r",
        &["cpu"],
        &[],
        500_000,
        1_000_000,
        "log read",
    )];
    let config = InterferenceConfig::default();
    let metrics = default_metrics();
    let reads = [MetricReadRequest {
        controller_id: "ctrl-log-r".to_string(),
        metric: "cpu".to_string(),
    }];

    let result = eval(
        "t-log-r",
        "p-log-r",
        &config,
        &registrations,
        &reads,
        &[],
        &[],
        &metrics,
    );

    assert!(result.logs.iter().any(|log| log.event == "read_snapshot"
        && log.metric.as_deref() == Some("cpu")
        && log.controller_ids.contains(&"ctrl-log-r".to_string())));
}

#[test]
fn logs_contain_timescale_conflict_event_on_reject() {
    let registrations = vec![
        reg("tc-a", &[], &["cpu"], 100_000, 100_000, "100ms"),
        reg("tc-b", &[], &["cpu"], 110_000, 110_000, "110ms"),
    ];
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Reject,
    };
    let metrics = default_metrics();
    let writes = [
        MetricWriteRequest {
            controller_id: "tc-a".to_string(),
            metric: "cpu".to_string(),
            value: 1,
        },
        MetricWriteRequest {
            controller_id: "tc-b".to_string(),
            metric: "cpu".to_string(),
            value: 2,
        },
    ];

    let result = eval(
        "t-tc-log",
        "p-tc-log",
        &config,
        &registrations,
        &[],
        &writes,
        &[],
        &metrics,
    );

    assert!(
        result
            .logs
            .iter()
            .any(|log| log.event == "timescale_conflict"
                && log.outcome == "fail"
                && log.error_code.as_deref() == Some("timescale_conflict"))
    );
}

#[test]
fn logs_contain_write_conflict_serialized_event_on_serialize_mode() {
    let registrations = vec![
        reg("sc-a", &[], &["latency"], 100_000, 100_000, "100ms"),
        reg("sc-b", &[], &["latency"], 110_000, 110_000, "110ms"),
    ];
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Serialize,
    };
    let metrics = default_metrics();
    let writes = [
        MetricWriteRequest {
            controller_id: "sc-a".to_string(),
            metric: "latency".to_string(),
            value: 10,
        },
        MetricWriteRequest {
            controller_id: "sc-b".to_string(),
            metric: "latency".to_string(),
            value: 20,
        },
    ];

    let result = eval(
        "t-sc-log",
        "p-sc-log",
        &config,
        &registrations,
        &[],
        &writes,
        &[],
        &metrics,
    );

    assert!(
        result
            .logs
            .iter()
            .any(|log| log.event == "write_conflict_serialized" && log.outcome == "pass")
    );
}

#[test]
fn failing_evaluation_summary_log_has_fail_outcome() {
    let config = InterferenceConfig::default();
    let metrics = default_metrics();
    let reads = [MetricReadRequest {
        controller_id: "nobody".to_string(),
        metric: "cpu".to_string(),
    }];

    let result = eval(
        "t-fail-log",
        "p-fail-log",
        &config,
        &[],
        &reads,
        &[],
        &[],
        &metrics,
    );

    assert!(!result.pass);
    let summary = result
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

// ---------------------------------------------------------------------------
// Multi-metric, multi-controller scenarios
// ---------------------------------------------------------------------------

#[test]
fn multiple_controllers_reading_and_writing_different_metrics() {
    let registrations = vec![
        reg(
            "ctrl-cpu",
            &["cpu"],
            &["cpu"],
            500_000,
            1_000_000,
            "cpu controller",
        ),
        reg(
            "ctrl-mem",
            &["mem"],
            &["mem"],
            600_000,
            1_200_000,
            "mem controller",
        ),
        reg(
            "ctrl-lat",
            &["latency"],
            &["latency"],
            700_000,
            1_400_000,
            "latency controller",
        ),
    ];
    let config = InterferenceConfig::default();
    let metrics = default_metrics();
    let reads = [
        MetricReadRequest {
            controller_id: "ctrl-cpu".to_string(),
            metric: "cpu".to_string(),
        },
        MetricReadRequest {
            controller_id: "ctrl-mem".to_string(),
            metric: "mem".to_string(),
        },
    ];
    let writes = [
        MetricWriteRequest {
            controller_id: "ctrl-cpu".to_string(),
            metric: "cpu".to_string(),
            value: 75,
        },
        MetricWriteRequest {
            controller_id: "ctrl-mem".to_string(),
            metric: "mem".to_string(),
            value: 512,
        },
        MetricWriteRequest {
            controller_id: "ctrl-lat".to_string(),
            metric: "latency".to_string(),
            value: 5,
        },
    ];
    let subs = [
        MetricSubscription {
            controller_id: "ctrl-cpu".to_string(),
            metric: "cpu".to_string(),
        },
        MetricSubscription {
            controller_id: "ctrl-mem".to_string(),
            metric: "mem".to_string(),
        },
    ];

    let result = eval(
        "t-multi",
        "p-multi",
        &config,
        &registrations,
        &reads,
        &writes,
        &subs,
        &metrics,
    );

    assert!(result.pass);
    assert_eq!(result.final_metrics.get("cpu"), Some(&75));
    assert_eq!(result.final_metrics.get("mem"), Some(&512));
    assert_eq!(result.final_metrics.get("latency"), Some(&5));
    assert_eq!(result.read_snapshots.get("ctrl-cpu:cpu"), Some(&50));
    assert_eq!(result.read_snapshots.get("ctrl-mem:mem"), Some(&200));
    assert_eq!(result.applied_writes.len(), 3);
    assert!(result.subscription_streams.contains_key("ctrl-cpu"));
    assert!(result.subscription_streams.contains_key("ctrl-mem"));
}

// ---------------------------------------------------------------------------
// Single writer to multiple metrics
// ---------------------------------------------------------------------------

#[test]
fn single_controller_writes_multiple_metrics() {
    let registrations = vec![reg(
        "omni",
        &["cpu", "mem"],
        &["cpu", "mem"],
        500_000,
        1_000_000,
        "all metrics",
    )];
    let config = InterferenceConfig::default();
    let metrics = default_metrics();
    let writes = [
        MetricWriteRequest {
            controller_id: "omni".to_string(),
            metric: "cpu".to_string(),
            value: 10,
        },
        MetricWriteRequest {
            controller_id: "omni".to_string(),
            metric: "mem".to_string(),
            value: 20,
        },
    ];

    let result = eval(
        "t-omni",
        "p-omni",
        &config,
        &registrations,
        &[],
        &writes,
        &[],
        &metrics,
    );

    assert!(result.pass);
    assert_eq!(result.final_metrics.get("cpu"), Some(&10));
    assert_eq!(result.final_metrics.get("mem"), Some(&20));
    assert_eq!(result.applied_writes.len(), 2);
}

// ---------------------------------------------------------------------------
// Struct construction smoke tests
// ---------------------------------------------------------------------------

#[test]
fn timescale_separation_statement_fields_accessible() {
    let ts = TimescaleSeparationStatement {
        observation_interval_millionths: 100_000,
        write_interval_millionths: 200_000,
        statement: "test statement".to_string(),
    };
    assert_eq!(ts.observation_interval_millionths, 100_000);
    assert_eq!(ts.write_interval_millionths, 200_000);
    assert_eq!(ts.statement, "test statement");
}

#[test]
fn controller_registration_read_write_metrics_are_btreesets() {
    let r = reg("ctrl-set", &["b", "a", "c"], &["z", "y"], 100, 200, "sets");
    // BTreeSet keeps elements sorted
    let reads: Vec<&String> = r.read_metrics.iter().collect();
    assert_eq!(reads, vec!["a", "b", "c"]);
    let writes: Vec<&String> = r.write_metrics.iter().collect();
    assert_eq!(writes, vec!["y", "z"]);
}

#[test]
fn interference_evaluation_serde_roundtrip() {
    let registrations = vec![reg(
        "ctrl-serde",
        &["cpu"],
        &["cpu"],
        500_000,
        1_000_000,
        "serde test",
    )];
    let config = InterferenceConfig::default();
    let metrics = default_metrics();
    let writes = [MetricWriteRequest {
        controller_id: "ctrl-serde".to_string(),
        metric: "cpu".to_string(),
        value: 42,
    }];

    let result = eval(
        "t-serde",
        "p-serde",
        &config,
        &registrations,
        &[],
        &writes,
        &[],
        &metrics,
    );
    let json = serde_json::to_string(&result).unwrap();
    let back: InterferenceEvaluation = serde_json::from_str(&json).unwrap();

    assert_eq!(result.decision_id, back.decision_id);
    assert_eq!(result.pass, back.pass);
    assert_eq!(result.rollback_required, back.rollback_required);
    assert_eq!(result.final_metrics, back.final_metrics);
    assert_eq!(result.applied_writes, back.applied_writes);
    assert_eq!(result.findings.len(), back.findings.len());
}

// ---------------------------------------------------------------------------
// Edge case: findings from both registration and request phases
// ---------------------------------------------------------------------------

#[test]
fn multiple_findings_accumulate_from_different_phases() {
    // Registration issues + request issues in the same evaluation
    let registrations = vec![
        reg(
            "ctrl-ok",
            &["cpu"],
            &["cpu"],
            500_000,
            1_000_000,
            "ok controller",
        ),
        reg(
            "ctrl-bad-ts",
            &["mem"],
            &[],
            0,
            1_000_000,
            "invalid obs interval",
        ),
    ];
    let config = InterferenceConfig::default();
    let metrics = default_metrics();
    let reads = [MetricReadRequest {
        controller_id: "ghost".to_string(),
        metric: "cpu".to_string(),
    }];

    let result = eval(
        "t-multi-err",
        "p-multi-err",
        &config,
        &registrations,
        &reads,
        &[],
        &[],
        &metrics,
    );

    assert!(!result.pass);
    let codes: BTreeSet<InterferenceFailureCode> = result.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&InterferenceFailureCode::InvalidTimescaleInterval));
    assert!(codes.contains(&InterferenceFailureCode::UnknownController));
}

#[test]
fn write_with_controller_having_missing_timescale_still_applies_if_authorized() {
    // Missing timescale statement produces a finding, but authorized writes still apply
    let registrations = vec![reg("ctrl-mt", &[], &["cpu"], 500_000, 1_000_000, "")];
    let config = InterferenceConfig::default();
    let metrics = default_metrics();
    let writes = [MetricWriteRequest {
        controller_id: "ctrl-mt".to_string(),
        metric: "cpu".to_string(),
        value: 99,
    }];

    let result = eval(
        "t-mt-write",
        "p-mt-write",
        &config,
        &registrations,
        &[],
        &writes,
        &[],
        &metrics,
    );

    // Fails because of missing timescale statement
    assert!(!result.pass);
    // But the write still applies (finding is about registration, not the write itself)
    assert_eq!(result.applied_writes.len(), 1);
    assert_eq!(result.final_metrics.get("cpu"), Some(&99));
}
