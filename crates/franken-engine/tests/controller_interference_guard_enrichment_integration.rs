#![forbid(unsafe_code)]
//! Enrichment integration tests for `controller_interference_guard`.
//!
//! Adds JSON field-name stability, exact serde enum values, Debug distinctness,
//! edge cases for metrics/subscriptions, and log event field validation beyond
//! the existing 51 integration tests.

use std::collections::BTreeMap;

use frankenengine_engine::controller_interference_guard::{
    ConflictResolutionMode, ControllerRegistration, InterferenceConfig, InterferenceEvaluation,
    InterferenceFailureCode, InterferenceFinding, InterferenceLogEvent, InterferenceResolution,
    InterferenceScenario, MetricReadRequest, MetricSubscription, MetricUpdate, MetricWriteRequest,
    TimescaleSeparationStatement,
};

// ===========================================================================
// Test helpers
// ===========================================================================

fn reg(id: &str, reads: &[&str], writes: &[&str]) -> ControllerRegistration {
    ControllerRegistration {
        controller_id: id.to_string(),
        read_metrics: reads.iter().map(|s| s.to_string()).collect(),
        write_metrics: writes.iter().map(|s| s.to_string()).collect(),
        timescale: TimescaleSeparationStatement {
            observation_interval_millionths: 1_000_000,
            write_interval_millionths: 500_000,
            statement: "test statement".to_string(),
        },
    }
}

fn run_scenario(
    config: &InterferenceConfig,
    registrations: &[ControllerRegistration],
    reads: &[MetricReadRequest],
    writes: &[MetricWriteRequest],
    subs: &[MetricSubscription],
    initial: &BTreeMap<String, i64>,
) -> InterferenceEvaluation {
    let scenario = InterferenceScenario {
        trace_id: "test-trace",
        policy_id: "test-policy",
        config,
        registrations,
        read_requests: reads,
        write_requests: writes,
        subscriptions: subs,
        initial_metrics: initial,
    };
    frankenengine_engine::controller_interference_guard::evaluate_controller_interference(&scenario)
}

// ===========================================================================
// 1) ConflictResolutionMode — exact Display
// ===========================================================================

#[test]
fn conflict_resolution_mode_display_exact_serialize() {
    assert_eq!(ConflictResolutionMode::Serialize.to_string(), "serialize");
}

#[test]
fn conflict_resolution_mode_display_exact_reject() {
    assert_eq!(ConflictResolutionMode::Reject.to_string(), "reject");
}

// ===========================================================================
// 2) InterferenceFailureCode — exact Display
// ===========================================================================

#[test]
fn failure_code_display_exact_all() {
    assert_eq!(
        InterferenceFailureCode::DuplicateController.to_string(),
        "duplicate_controller"
    );
    assert_eq!(
        InterferenceFailureCode::MissingTimescaleStatement.to_string(),
        "missing_timescale_statement"
    );
    assert_eq!(
        InterferenceFailureCode::InvalidTimescaleInterval.to_string(),
        "invalid_timescale_interval"
    );
    assert_eq!(
        InterferenceFailureCode::UnknownController.to_string(),
        "unknown_controller"
    );
    assert_eq!(
        InterferenceFailureCode::UnauthorizedRead.to_string(),
        "unauthorized_read"
    );
    assert_eq!(
        InterferenceFailureCode::UnauthorizedWrite.to_string(),
        "unauthorized_write"
    );
    assert_eq!(
        InterferenceFailureCode::TimescaleConflict.to_string(),
        "timescale_conflict"
    );
}

// ===========================================================================
// 3) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_conflict_resolution_mode() {
    let a = format!("{:?}", ConflictResolutionMode::Serialize);
    let b = format!("{:?}", ConflictResolutionMode::Reject);
    assert_ne!(a, b);
}

#[test]
fn debug_distinct_failure_codes() {
    let codes = [
        InterferenceFailureCode::DuplicateController,
        InterferenceFailureCode::MissingTimescaleStatement,
        InterferenceFailureCode::InvalidTimescaleInterval,
        InterferenceFailureCode::UnknownController,
        InterferenceFailureCode::UnauthorizedRead,
        InterferenceFailureCode::UnauthorizedWrite,
        InterferenceFailureCode::TimescaleConflict,
    ];
    let debugs: std::collections::BTreeSet<String> =
        codes.iter().map(|c| format!("{c:?}")).collect();
    assert_eq!(debugs.len(), codes.len());
}

// ===========================================================================
// 4) serde exact enum values
// ===========================================================================

#[test]
fn serde_exact_conflict_resolution_mode() {
    assert_eq!(
        serde_json::to_string(&ConflictResolutionMode::Serialize).unwrap(),
        "\"Serialize\""
    );
    assert_eq!(
        serde_json::to_string(&ConflictResolutionMode::Reject).unwrap(),
        "\"Reject\""
    );
}

#[test]
fn serde_exact_failure_code_tags() {
    assert_eq!(
        serde_json::to_string(&InterferenceFailureCode::DuplicateController).unwrap(),
        "\"DuplicateController\""
    );
    assert_eq!(
        serde_json::to_string(&InterferenceFailureCode::MissingTimescaleStatement).unwrap(),
        "\"MissingTimescaleStatement\""
    );
    assert_eq!(
        serde_json::to_string(&InterferenceFailureCode::InvalidTimescaleInterval).unwrap(),
        "\"InvalidTimescaleInterval\""
    );
    assert_eq!(
        serde_json::to_string(&InterferenceFailureCode::UnknownController).unwrap(),
        "\"UnknownController\""
    );
    assert_eq!(
        serde_json::to_string(&InterferenceFailureCode::UnauthorizedRead).unwrap(),
        "\"UnauthorizedRead\""
    );
    assert_eq!(
        serde_json::to_string(&InterferenceFailureCode::UnauthorizedWrite).unwrap(),
        "\"UnauthorizedWrite\""
    );
    assert_eq!(
        serde_json::to_string(&InterferenceFailureCode::TimescaleConflict).unwrap(),
        "\"TimescaleConflict\""
    );
}

// ===========================================================================
// 5) JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_interference_config() {
    let c = InterferenceConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    assert!(json.contains("\"min_timescale_separation_millionths\""));
    assert!(json.contains("\"conflict_resolution_mode\""));
}

#[test]
fn json_fields_timescale_separation_statement() {
    let t = TimescaleSeparationStatement {
        observation_interval_millionths: 1_000_000,
        write_interval_millionths: 500_000,
        statement: "test".to_string(),
    };
    let json = serde_json::to_string(&t).unwrap();
    assert!(json.contains("\"observation_interval_millionths\""));
    assert!(json.contains("\"write_interval_millionths\""));
    assert!(json.contains("\"statement\""));
}

#[test]
fn json_fields_controller_registration() {
    let r = reg("ctrl-1", &["cpu"], &["mem"]);
    let json = serde_json::to_string(&r).unwrap();
    assert!(json.contains("\"controller_id\""));
    assert!(json.contains("\"read_metrics\""));
    assert!(json.contains("\"write_metrics\""));
    assert!(json.contains("\"timescale\""));
}

#[test]
fn json_fields_metric_read_request() {
    let r = MetricReadRequest {
        controller_id: "ctrl-1".to_string(),
        metric: "cpu".to_string(),
    };
    let json = serde_json::to_string(&r).unwrap();
    assert!(json.contains("\"controller_id\""));
    assert!(json.contains("\"metric\""));
}

#[test]
fn json_fields_metric_write_request() {
    let w = MetricWriteRequest {
        controller_id: "ctrl-1".to_string(),
        metric: "mem".to_string(),
        value: 42,
    };
    let json = serde_json::to_string(&w).unwrap();
    assert!(json.contains("\"controller_id\""));
    assert!(json.contains("\"metric\""));
    assert!(json.contains("\"value\""));
}

#[test]
fn json_fields_metric_subscription() {
    let s = MetricSubscription {
        controller_id: "ctrl-1".to_string(),
        metric: "cpu".to_string(),
    };
    let json = serde_json::to_string(&s).unwrap();
    assert!(json.contains("\"controller_id\""));
    assert!(json.contains("\"metric\""));
}

#[test]
fn json_fields_metric_update() {
    let u = MetricUpdate {
        sequence: 1,
        metric: "cpu".to_string(),
        value: 100,
    };
    let json = serde_json::to_string(&u).unwrap();
    assert!(json.contains("\"sequence\""));
    assert!(json.contains("\"metric\""));
    assert!(json.contains("\"value\""));
}

#[test]
fn json_fields_interference_finding() {
    let f = InterferenceFinding {
        code: InterferenceFailureCode::DuplicateController,
        metric: Some("cpu".to_string()),
        controller_ids: vec!["ctrl-1".to_string()],
        detail: "test detail".to_string(),
    };
    let json = serde_json::to_string(&f).unwrap();
    assert!(json.contains("\"code\""));
    assert!(json.contains("\"metric\""));
    assert!(json.contains("\"controller_ids\""));
    assert!(json.contains("\"detail\""));
}

#[test]
fn json_fields_interference_resolution() {
    let r = InterferenceResolution {
        metric: "cpu".to_string(),
        controller_ids: vec!["ctrl-1".to_string(), "ctrl-2".to_string()],
        mode: ConflictResolutionMode::Serialize,
        detail: "serialized".to_string(),
    };
    let json = serde_json::to_string(&r).unwrap();
    assert!(json.contains("\"metric\""));
    assert!(json.contains("\"controller_ids\""));
    assert!(json.contains("\"mode\""));
    assert!(json.contains("\"detail\""));
}

#[test]
fn json_fields_interference_log_event() {
    let le = InterferenceLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "o".to_string(),
        error_code: None,
        metric: None,
        controller_ids: vec![],
    };
    let json = serde_json::to_string(&le).unwrap();
    assert!(json.contains("\"trace_id\""));
    assert!(json.contains("\"decision_id\""));
    assert!(json.contains("\"policy_id\""));
    assert!(json.contains("\"component\""));
    assert!(json.contains("\"event\""));
    assert!(json.contains("\"outcome\""));
    assert!(json.contains("\"error_code\""));
    assert!(json.contains("\"metric\""));
    assert!(json.contains("\"controller_ids\""));
}

#[test]
fn json_fields_interference_evaluation() {
    let config = InterferenceConfig::default();
    let regs = vec![reg("ctrl-1", &["cpu"], &["mem"])];
    let initial = BTreeMap::new();
    let eval = run_scenario(&config, &regs, &[], &[], &[], &initial);
    let json = serde_json::to_string(&eval).unwrap();
    assert!(json.contains("\"decision_id\""));
    assert!(json.contains("\"pass\""));
    assert!(json.contains("\"rollback_required\""));
    assert!(json.contains("\"read_snapshots\""));
    assert!(json.contains("\"applied_writes\""));
    assert!(json.contains("\"rejected_writes\""));
    assert!(json.contains("\"resolutions\""));
    assert!(json.contains("\"subscription_streams\""));
    assert!(json.contains("\"final_metrics\""));
    assert!(json.contains("\"findings\""));
    assert!(json.contains("\"logs\""));
}

// ===========================================================================
// 6) InterferenceConfig default exact values
// ===========================================================================

#[test]
fn config_default_exact() {
    let c = InterferenceConfig::default();
    assert_eq!(c.min_timescale_separation_millionths, 100_000);
    assert_eq!(c.conflict_resolution_mode, ConflictResolutionMode::Reject);
}

// ===========================================================================
// 7) Edge cases
// ===========================================================================

#[test]
fn empty_scenario_passes_with_no_findings() {
    let config = InterferenceConfig::default();
    let eval = run_scenario(&config, &[], &[], &[], &[], &BTreeMap::new());
    assert!(eval.pass);
    assert!(!eval.rollback_required);
    assert!(eval.findings.is_empty());
    assert!(eval.applied_writes.is_empty());
    assert!(eval.rejected_writes.is_empty());
    assert!(eval.resolutions.is_empty());
}

#[test]
fn large_metric_values() {
    let config = InterferenceConfig::default();
    let regs = vec![reg("ctrl-1", &["m"], &["m"])];
    let writes = vec![MetricWriteRequest {
        controller_id: "ctrl-1".to_string(),
        metric: "m".to_string(),
        value: i64::MAX,
    }];
    let mut initial = BTreeMap::new();
    initial.insert("m".to_string(), i64::MIN);
    let eval = run_scenario(&config, &regs, &[], &writes, &[], &initial);
    assert!(eval.pass);
    assert_eq!(*eval.final_metrics.get("m").unwrap(), i64::MAX);
}

#[test]
fn negative_metric_values() {
    let config = InterferenceConfig::default();
    let regs = vec![reg("ctrl-1", &["m"], &["m"])];
    let writes = vec![MetricWriteRequest {
        controller_id: "ctrl-1".to_string(),
        metric: "m".to_string(),
        value: -42,
    }];
    let eval = run_scenario(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    assert!(eval.pass);
    assert_eq!(*eval.final_metrics.get("m").unwrap(), -42);
}

// ===========================================================================
// 8) Log event component field value
// ===========================================================================

#[test]
fn log_component_is_controller_interference_guard() {
    let config = InterferenceConfig::default();
    let regs = vec![reg("ctrl-1", &["cpu"], &["mem"])];
    let reads = vec![MetricReadRequest {
        controller_id: "ctrl-1".to_string(),
        metric: "cpu".to_string(),
    }];
    let mut initial = BTreeMap::new();
    initial.insert("cpu".to_string(), 50);
    let eval = run_scenario(&config, &regs, &reads, &[], &[], &initial);
    for log in &eval.logs {
        assert_eq!(log.component, "controller_interference_guard");
    }
}

// ===========================================================================
// 9) Decision ID prefix
// ===========================================================================

#[test]
fn decision_id_starts_with_prefix() {
    let config = InterferenceConfig::default();
    let regs = vec![reg("ctrl-1", &["cpu"], &[])];
    let eval = run_scenario(&config, &regs, &[], &[], &[], &BTreeMap::new());
    assert!(
        eval.decision_id.starts_with("ctrl-interference-"),
        "decision_id should start with 'ctrl-interference-', got: {}",
        eval.decision_id
    );
}

// ===========================================================================
// 10) Subscription monotonic sequences
// ===========================================================================

#[test]
fn subscription_sequences_are_monotonic() {
    let config = InterferenceConfig::default();
    let regs = vec![reg("ctrl-1", &["m1", "m2"], &["m1", "m2"])];
    let writes = vec![
        MetricWriteRequest {
            controller_id: "ctrl-1".to_string(),
            metric: "m1".to_string(),
            value: 10,
        },
        MetricWriteRequest {
            controller_id: "ctrl-1".to_string(),
            metric: "m2".to_string(),
            value: 20,
        },
    ];
    let subs = vec![
        MetricSubscription {
            controller_id: "ctrl-1".to_string(),
            metric: "m1".to_string(),
        },
        MetricSubscription {
            controller_id: "ctrl-1".to_string(),
            metric: "m2".to_string(),
        },
    ];
    let eval = run_scenario(&config, &regs, &[], &writes, &subs, &BTreeMap::new());

    for updates in eval.subscription_streams.values() {
        let mut prev_seq = 0u64;
        for upd in updates {
            assert!(
                upd.sequence >= prev_seq,
                "sequence should be monotonic, got {} after {}",
                upd.sequence,
                prev_seq
            );
            prev_seq = upd.sequence;
        }
    }
}

// ===========================================================================
// 11) serde roundtrips for additional types
// ===========================================================================

#[test]
fn serde_roundtrip_interference_finding() {
    let f = InterferenceFinding {
        code: InterferenceFailureCode::TimescaleConflict,
        metric: Some("cpu".to_string()),
        controller_ids: vec!["ctrl-a".to_string(), "ctrl-b".to_string()],
        detail: "conflicting writes".to_string(),
    };
    let json = serde_json::to_string(&f).unwrap();
    let back: InterferenceFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}

#[test]
fn serde_roundtrip_interference_resolution() {
    let r = InterferenceResolution {
        metric: "cpu".to_string(),
        controller_ids: vec!["a".to_string()],
        mode: ConflictResolutionMode::Serialize,
        detail: "serialized".to_string(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: InterferenceResolution = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn serde_roundtrip_interference_log_event() {
    let le = InterferenceLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "controller_interference_guard".to_string(),
        event: "interference_summary".to_string(),
        outcome: "pass".to_string(),
        error_code: Some("test_err".to_string()),
        metric: Some("cpu".to_string()),
        controller_ids: vec!["ctrl-1".to_string()],
    };
    let json = serde_json::to_string(&le).unwrap();
    let back: InterferenceLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(le, back);
}

// ===========================================================================
// 12) Findings accumulate from duplicate + unauthorized
// ===========================================================================

#[test]
fn multiple_findings_from_duplicate_and_unauthorized() {
    let config = InterferenceConfig::default();
    let regs = vec![
        reg("ctrl-dup", &["cpu"], &["mem"]),
        reg("ctrl-dup", &["cpu"], &["mem"]), // duplicate
    ];
    let reads = vec![MetricReadRequest {
        controller_id: "ctrl-dup".to_string(),
        metric: "disk".to_string(), // unauthorized read
    }];
    let eval = run_scenario(&config, &regs, &reads, &[], &[], &BTreeMap::new());
    assert!(!eval.pass);
    let codes: Vec<_> = eval.findings.iter().map(|f| &f.code).collect();
    assert!(codes.contains(&&InterferenceFailureCode::DuplicateController));
    assert!(codes.contains(&&InterferenceFailureCode::UnauthorizedRead));
}

// ===========================================================================
// 13) Read snapshot key format
// ===========================================================================

#[test]
fn read_snapshot_key_format() {
    let config = InterferenceConfig::default();
    let regs = vec![reg("ctrl-1", &["cpu"], &[])];
    let reads = vec![MetricReadRequest {
        controller_id: "ctrl-1".to_string(),
        metric: "cpu".to_string(),
    }];
    let mut initial = BTreeMap::new();
    initial.insert("cpu".to_string(), 75);
    let eval = run_scenario(&config, &regs, &reads, &[], &[], &initial);
    // Key should be "controller_id:metric"
    assert!(
        eval.read_snapshots.contains_key("ctrl-1:cpu"),
        "read_snapshots should contain key 'ctrl-1:cpu', got keys: {:?}",
        eval.read_snapshots.keys().collect::<Vec<_>>()
    );
    assert_eq!(*eval.read_snapshots.get("ctrl-1:cpu").unwrap(), 75);
}

// ===========================================================================
// 14) serde roundtrips — remaining types
// ===========================================================================

#[test]
fn serde_roundtrip_interference_config() {
    let c = InterferenceConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: InterferenceConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn serde_roundtrip_controller_registration() {
    let r = reg("ctrl-serde", &["cpu", "mem"], &["disk"]);
    let json = serde_json::to_string(&r).unwrap();
    let back: ControllerRegistration = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn serde_roundtrip_metric_read_request() {
    let r = MetricReadRequest {
        controller_id: "ctrl-1".to_string(),
        metric: "cpu".to_string(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: MetricReadRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn serde_roundtrip_metric_write_request() {
    let w = MetricWriteRequest {
        controller_id: "ctrl-1".to_string(),
        metric: "mem".to_string(),
        value: -999,
    };
    let json = serde_json::to_string(&w).unwrap();
    let back: MetricWriteRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(w, back);
}

#[test]
fn serde_roundtrip_metric_subscription() {
    let s = MetricSubscription {
        controller_id: "ctrl-1".to_string(),
        metric: "cpu".to_string(),
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: MetricSubscription = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn serde_roundtrip_metric_update() {
    let u = MetricUpdate {
        sequence: 42,
        metric: "cpu".to_string(),
        value: 100,
    };
    let json = serde_json::to_string(&u).unwrap();
    let back: MetricUpdate = serde_json::from_str(&json).unwrap();
    assert_eq!(u, back);
}

#[test]
fn serde_roundtrip_timescale_separation_statement() {
    let t = TimescaleSeparationStatement {
        observation_interval_millionths: 2_000_000,
        write_interval_millionths: 750_000,
        statement: "roundtrip test".to_string(),
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: TimescaleSeparationStatement = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn serde_roundtrip_conflict_resolution_mode() {
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
fn serde_roundtrip_failure_code_all() {
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

// ===========================================================================
// 15) Ordering stability
// ===========================================================================

#[test]
fn failure_code_ordering_stable() {
    let mut codes = vec![
        InterferenceFailureCode::TimescaleConflict,
        InterferenceFailureCode::DuplicateController,
        InterferenceFailureCode::UnauthorizedRead,
        InterferenceFailureCode::InvalidTimescaleInterval,
        InterferenceFailureCode::UnknownController,
        InterferenceFailureCode::MissingTimescaleStatement,
        InterferenceFailureCode::UnauthorizedWrite,
    ];
    codes.sort();
    // Verify deterministic ordering
    let mut codes2 = codes.clone();
    codes2.sort();
    assert_eq!(codes, codes2);
}

// ===========================================================================
// 16) Timescale conflict: Reject mode produces findings
// ===========================================================================

#[test]
fn timescale_conflict_reject_mode_produces_finding() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Reject,
    };
    // Two controllers writing same metric with similar write intervals
    let regs = vec![
        ControllerRegistration {
            controller_id: "ctrl-a".to_string(),
            read_metrics: std::collections::BTreeSet::new(),
            write_metrics: ["shared_m".to_string()].into_iter().collect(),
            timescale: TimescaleSeparationStatement {
                observation_interval_millionths: 1_000_000,
                write_interval_millionths: 500_000,
                statement: "controller a".to_string(),
            },
        },
        ControllerRegistration {
            controller_id: "ctrl-b".to_string(),
            read_metrics: std::collections::BTreeSet::new(),
            write_metrics: ["shared_m".to_string()].into_iter().collect(),
            timescale: TimescaleSeparationStatement {
                observation_interval_millionths: 1_000_000,
                write_interval_millionths: 510_000, // within 100k of ctrl-a's 500k
                statement: "controller b".to_string(),
            },
        },
    ];
    let writes = vec![
        MetricWriteRequest {
            controller_id: "ctrl-a".to_string(),
            metric: "shared_m".to_string(),
            value: 10,
        },
        MetricWriteRequest {
            controller_id: "ctrl-b".to_string(),
            metric: "shared_m".to_string(),
            value: 20,
        },
    ];
    let eval = run_scenario(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    assert!(!eval.pass);
    assert!(eval.rollback_required);
    let has_timescale = eval
        .findings
        .iter()
        .any(|f| f.code == InterferenceFailureCode::TimescaleConflict);
    assert!(has_timescale, "should produce TimescaleConflict finding");
}

// ===========================================================================
// 17) Timescale conflict: Serialize mode produces resolution
// ===========================================================================

#[test]
fn timescale_conflict_serialize_mode_produces_resolution() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Serialize,
    };
    let regs = vec![
        ControllerRegistration {
            controller_id: "ctrl-a".to_string(),
            read_metrics: std::collections::BTreeSet::new(),
            write_metrics: ["m".to_string()].into_iter().collect(),
            timescale: TimescaleSeparationStatement {
                observation_interval_millionths: 1_000_000,
                write_interval_millionths: 500_000,
                statement: "ctrl a".to_string(),
            },
        },
        ControllerRegistration {
            controller_id: "ctrl-b".to_string(),
            read_metrics: std::collections::BTreeSet::new(),
            write_metrics: ["m".to_string()].into_iter().collect(),
            timescale: TimescaleSeparationStatement {
                observation_interval_millionths: 1_000_000,
                write_interval_millionths: 510_000,
                statement: "ctrl b".to_string(),
            },
        },
    ];
    let writes = vec![
        MetricWriteRequest {
            controller_id: "ctrl-a".to_string(),
            metric: "m".to_string(),
            value: 100,
        },
        MetricWriteRequest {
            controller_id: "ctrl-b".to_string(),
            metric: "m".to_string(),
            value: 200,
        },
    ];
    let eval = run_scenario(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    assert!(eval.pass, "Serialize mode should pass");
    assert!(!eval.resolutions.is_empty(), "should have resolutions");
    assert_eq!(eval.resolutions[0].mode, ConflictResolutionMode::Serialize);
}

// ===========================================================================
// 18) Unknown controller for read/write/subscribe
// ===========================================================================

#[test]
fn unknown_controller_read() {
    let config = InterferenceConfig::default();
    let regs = vec![reg("ctrl-1", &["cpu"], &[])];
    let reads = vec![MetricReadRequest {
        controller_id: "unknown-ctrl".to_string(),
        metric: "cpu".to_string(),
    }];
    let eval = run_scenario(&config, &regs, &reads, &[], &[], &BTreeMap::new());
    assert!(!eval.pass);
    let has_unknown = eval
        .findings
        .iter()
        .any(|f| f.code == InterferenceFailureCode::UnknownController);
    assert!(has_unknown);
}

#[test]
fn unknown_controller_write() {
    let config = InterferenceConfig::default();
    let regs = vec![reg("ctrl-1", &[], &["mem"])];
    let writes = vec![MetricWriteRequest {
        controller_id: "no-such-ctrl".to_string(),
        metric: "mem".to_string(),
        value: 1,
    }];
    let eval = run_scenario(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    assert!(!eval.pass);
    let has_unknown = eval
        .findings
        .iter()
        .any(|f| f.code == InterferenceFailureCode::UnknownController);
    assert!(has_unknown);
}

// ===========================================================================
// 19) Unauthorized write detection
// ===========================================================================

#[test]
fn unauthorized_write_detected() {
    let config = InterferenceConfig::default();
    let regs = vec![reg("ctrl-1", &["cpu"], &[])]; // read-only for cpu, no write
    let writes = vec![MetricWriteRequest {
        controller_id: "ctrl-1".to_string(),
        metric: "cpu".to_string(),
        value: 42,
    }];
    let eval = run_scenario(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    assert!(!eval.pass);
    let has_unauth = eval
        .findings
        .iter()
        .any(|f| f.code == InterferenceFailureCode::UnauthorizedWrite);
    assert!(has_unauth);
}

// ===========================================================================
// 20) Missing timescale statement
// ===========================================================================

#[test]
fn missing_timescale_statement_detected() {
    let config = InterferenceConfig::default();
    let regs = vec![ControllerRegistration {
        controller_id: "ctrl-empty-ts".to_string(),
        read_metrics: ["cpu".to_string()].into_iter().collect(),
        write_metrics: std::collections::BTreeSet::new(),
        timescale: TimescaleSeparationStatement {
            observation_interval_millionths: 1_000_000,
            write_interval_millionths: 500_000,
            statement: "   ".to_string(), // whitespace-only
        },
    }];
    let eval = run_scenario(&config, &regs, &[], &[], &[], &BTreeMap::new());
    assert!(!eval.pass);
    let has_missing = eval
        .findings
        .iter()
        .any(|f| f.code == InterferenceFailureCode::MissingTimescaleStatement);
    assert!(has_missing);
}

// ===========================================================================
// 21) Invalid timescale interval
// ===========================================================================

#[test]
fn invalid_timescale_interval_detected() {
    let config = InterferenceConfig::default();
    let regs = vec![ControllerRegistration {
        controller_id: "ctrl-bad-interval".to_string(),
        read_metrics: ["cpu".to_string()].into_iter().collect(),
        write_metrics: std::collections::BTreeSet::new(),
        timescale: TimescaleSeparationStatement {
            observation_interval_millionths: 0, // invalid: not > 0
            write_interval_millionths: 500_000,
            statement: "bad interval".to_string(),
        },
    }];
    let eval = run_scenario(&config, &regs, &[], &[], &[], &BTreeMap::new());
    assert!(!eval.pass);
    let has_invalid = eval
        .findings
        .iter()
        .any(|f| f.code == InterferenceFailureCode::InvalidTimescaleInterval);
    assert!(has_invalid);
}

// ===========================================================================
// 22) Evaluation pass/rollback_required invariant
// ===========================================================================

#[test]
fn pass_and_rollback_are_inverse() {
    let config = InterferenceConfig::default();

    // Pass case
    let regs = vec![reg("ctrl-1", &["cpu"], &["mem"])];
    let eval_pass = run_scenario(&config, &regs, &[], &[], &[], &BTreeMap::new());
    assert!(eval_pass.pass);
    assert!(!eval_pass.rollback_required);

    // Fail case
    let eval_fail = run_scenario(
        &config,
        &[],
        &[MetricReadRequest {
            controller_id: "nobody".to_string(),
            metric: "x".to_string(),
        }],
        &[],
        &[],
        &BTreeMap::new(),
    );
    assert!(!eval_fail.pass);
    assert!(eval_fail.rollback_required);
}

// ===========================================================================
// 23) Decision ID is deterministic for same inputs
// ===========================================================================

#[test]
fn decision_id_deterministic_same_inputs() {
    let config = InterferenceConfig::default();
    let regs = vec![reg("ctrl-1", &["cpu"], &["mem"])];
    let initial = BTreeMap::new();

    let eval1 = run_scenario(&config, &regs, &[], &[], &[], &initial);
    let eval2 = run_scenario(&config, &regs, &[], &[], &[], &initial);
    assert_eq!(eval1.decision_id, eval2.decision_id);
}

// ===========================================================================
// 24) Applied writes update final_metrics
// ===========================================================================

#[test]
fn applied_writes_reflected_in_final_metrics() {
    let config = InterferenceConfig::default();
    let regs = vec![reg("ctrl-1", &[], &["m1", "m2"])];
    let writes = vec![
        MetricWriteRequest {
            controller_id: "ctrl-1".to_string(),
            metric: "m1".to_string(),
            value: 100,
        },
        MetricWriteRequest {
            controller_id: "ctrl-1".to_string(),
            metric: "m2".to_string(),
            value: 200,
        },
    ];
    let mut initial = BTreeMap::new();
    initial.insert("m1".to_string(), 0);
    let eval = run_scenario(&config, &regs, &[], &writes, &[], &initial);
    assert!(eval.pass);
    assert_eq!(*eval.final_metrics.get("m1").unwrap(), 100);
    assert_eq!(*eval.final_metrics.get("m2").unwrap(), 200);
    assert_eq!(eval.applied_writes.len(), 2);
}

// ===========================================================================
// 25) Rejected writes tracked
// ===========================================================================

#[test]
fn unauthorized_writes_appear_in_rejected() {
    let config = InterferenceConfig::default();
    let regs = vec![reg("ctrl-1", &["cpu"], &[])]; // no write permissions
    let writes = vec![MetricWriteRequest {
        controller_id: "ctrl-1".to_string(),
        metric: "cpu".to_string(),
        value: 42,
    }];
    let eval = run_scenario(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    assert!(!eval.pass);
    assert!(!eval.rejected_writes.is_empty());
}

// ===========================================================================
// 26) Log events include summary event
// ===========================================================================

#[test]
fn log_events_include_interference_summary() {
    let config = InterferenceConfig::default();
    let regs = vec![reg("ctrl-1", &["cpu"], &["mem"])];
    let eval = run_scenario(&config, &regs, &[], &[], &[], &BTreeMap::new());
    let has_summary = eval.logs.iter().any(|l| l.event == "interference_summary");
    assert!(
        has_summary,
        "logs should include interference_summary event"
    );
}

// ===========================================================================
// 27) Multiple controllers: no conflict when write intervals differ enough
// ===========================================================================

#[test]
fn no_conflict_when_timescale_separation_sufficient() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Reject,
    };
    let regs = vec![
        ControllerRegistration {
            controller_id: "fast".to_string(),
            read_metrics: std::collections::BTreeSet::new(),
            write_metrics: ["m".to_string()].into_iter().collect(),
            timescale: TimescaleSeparationStatement {
                observation_interval_millionths: 1_000_000,
                write_interval_millionths: 100_000, // fast
                statement: "fast controller".to_string(),
            },
        },
        ControllerRegistration {
            controller_id: "slow".to_string(),
            read_metrics: std::collections::BTreeSet::new(),
            write_metrics: ["m".to_string()].into_iter().collect(),
            timescale: TimescaleSeparationStatement {
                observation_interval_millionths: 1_000_000,
                write_interval_millionths: 900_000, // 800k separation >> 100k threshold
                statement: "slow controller".to_string(),
            },
        },
    ];
    let writes = vec![
        MetricWriteRequest {
            controller_id: "fast".to_string(),
            metric: "m".to_string(),
            value: 10,
        },
        MetricWriteRequest {
            controller_id: "slow".to_string(),
            metric: "m".to_string(),
            value: 20,
        },
    ];
    let eval = run_scenario(&config, &regs, &[], &writes, &[], &BTreeMap::new());
    assert!(
        eval.pass,
        "should pass when timescale separation is sufficient"
    );
    assert!(eval.findings.is_empty());
}
