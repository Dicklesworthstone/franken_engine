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
    InterferenceFailureCode, InterferenceScenario, MetricReadRequest, MetricSubscription,
    MetricWriteRequest, TimescaleSeparationStatement, evaluate_controller_interference,
};

fn registration(
    id: &str,
    read_metrics: &[&str],
    write_metrics: &[&str],
    observation_interval_millionths: i64,
    write_interval_millionths: i64,
    statement: &str,
) -> ControllerRegistration {
    ControllerRegistration {
        controller_id: id.to_string(),
        read_metrics: read_metrics
            .iter()
            .map(|metric| (*metric).to_string())
            .collect::<BTreeSet<_>>(),
        write_metrics: write_metrics
            .iter()
            .map(|metric| (*metric).to_string())
            .collect::<BTreeSet<_>>(),
        timescale: TimescaleSeparationStatement {
            observation_interval_millionths,
            write_interval_millionths,
            statement: statement.to_string(),
        },
    }
}

fn initial_metrics() -> BTreeMap<String, i64> {
    BTreeMap::from([
        ("cpu".to_string(), 10),
        ("latency".to_string(), 100),
        ("throughput".to_string(), 1_000),
    ])
}

fn scenario<'a>(
    trace_id: &'a str,
    policy_id: &'a str,
    config: &'a InterferenceConfig,
    registrations: &'a [ControllerRegistration],
    metric_ops: (
        &'a [MetricReadRequest],
        &'a [MetricWriteRequest],
        &'a [MetricSubscription],
    ),
    initial_metrics: &'a BTreeMap<String, i64>,
) -> InterferenceScenario<'a> {
    let (read_requests, write_requests, subscriptions) = metric_ops;
    InterferenceScenario {
        trace_id,
        policy_id,
        config,
        registrations,
        read_requests,
        write_requests,
        subscriptions,
        initial_metrics,
    }
}

#[test]
fn conflicting_writers_are_rejected_with_structured_logs() {
    let registrations = vec![
        registration(
            "writer-a",
            &["throughput"],
            &["throughput"],
            100_000,
            100_000,
            "writes every 100ms",
        ),
        registration(
            "writer-b",
            &["throughput"],
            &["throughput"],
            120_000,
            120_000,
            "writes every 120ms",
        ),
    ];

    let config = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Reject,
    };
    let read_requests: [MetricReadRequest; 0] = [];
    let write_requests = [
        MetricWriteRequest {
            controller_id: "writer-a".to_string(),
            metric: "throughput".to_string(),
            value: 700,
        },
        MetricWriteRequest {
            controller_id: "writer-b".to_string(),
            metric: "throughput".to_string(),
            value: 600,
        },
    ];
    let subscriptions: [MetricSubscription; 0] = [];
    let metrics = initial_metrics();

    let evaluation = evaluate_controller_interference(&scenario(
        "trace-interference-fail",
        "policy-interference-fail",
        &config,
        &registrations,
        (&read_requests, &write_requests, &subscriptions),
        &metrics,
    ));

    assert!(!evaluation.pass);
    assert!(evaluation.rollback_required);
    assert_eq!(evaluation.rejected_writes.len(), 2);
    assert!(evaluation.findings.iter().any(|finding| {
        finding.code == InterferenceFailureCode::TimescaleConflict
            && finding.metric.as_deref() == Some("throughput")
    }));
    assert!(evaluation.logs.iter().any(|event| {
        event.event == "timescale_conflict"
            && event.outcome == "fail"
            && event.error_code.as_deref() == Some("timescale_conflict")
    }));
}

#[test]
fn serialize_mode_preserves_deterministic_write_order_and_subscription_fanout() {
    let registrations = vec![
        registration(
            "writer-b",
            &["latency"],
            &["latency"],
            100_000,
            100_000,
            "writes every 100ms",
        ),
        registration(
            "writer-a",
            &["latency"],
            &["latency"],
            120_000,
            120_000,
            "writes every 120ms",
        ),
        registration(
            "subscriber",
            &["latency"],
            &[],
            500_000,
            2_000_000,
            "subscribes every 500ms",
        ),
    ];

    let config = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Serialize,
    };
    let read_requests = [MetricReadRequest {
        controller_id: "subscriber".to_string(),
        metric: "latency".to_string(),
    }];
    let write_requests = [
        MetricWriteRequest {
            controller_id: "writer-b".to_string(),
            metric: "latency".to_string(),
            value: 70,
        },
        MetricWriteRequest {
            controller_id: "writer-a".to_string(),
            metric: "latency".to_string(),
            value: 80,
        },
    ];
    let subscriptions = [MetricSubscription {
        controller_id: "subscriber".to_string(),
        metric: "latency".to_string(),
    }];
    let metrics = initial_metrics();

    let evaluation = evaluate_controller_interference(&scenario(
        "trace-interference-serialize",
        "policy-interference-serialize",
        &config,
        &registrations,
        (&read_requests, &write_requests, &subscriptions),
        &metrics,
    ));

    assert!(evaluation.pass);
    assert_eq!(evaluation.applied_writes.len(), 2);
    assert_eq!(evaluation.final_metrics.get("latency"), Some(&70));
    assert_eq!(evaluation.resolutions.len(), 1);
    assert!(
        evaluation
            .logs
            .iter()
            .any(|event| { event.event == "write_conflict_serialized" && event.outcome == "pass" })
    );
    assert_eq!(
        evaluation
            .subscription_streams
            .get("subscriber")
            .and_then(|updates| updates.first())
            .map(|update| update.value),
        Some(70)
    );
}

#[test]
fn long_duration_soak_preserves_metric_integrity_without_drift() {
    let registrations = vec![
        registration(
            "reader",
            &["cpu"],
            &[],
            250_000,
            2_000_000,
            "reads every 250ms",
        ),
        registration(
            "writer",
            &["cpu"],
            &["cpu"],
            1_000_000,
            1_000_000,
            "writes every 1s",
        ),
    ];

    let mut metrics = initial_metrics();
    for iteration in 0..10_000i64 {
        let next_value = 10 + (iteration % 11);
        let config = InterferenceConfig::default();
        let read_requests = [MetricReadRequest {
            controller_id: "reader".to_string(),
            metric: "cpu".to_string(),
        }];
        let write_requests = [MetricWriteRequest {
            controller_id: "writer".to_string(),
            metric: "cpu".to_string(),
            value: next_value,
        }];
        let subscriptions: [MetricSubscription; 0] = [];

        let evaluation = evaluate_controller_interference(&scenario(
            "trace-interference-soak",
            "policy-interference-soak",
            &config,
            &registrations,
            (&read_requests, &write_requests, &subscriptions),
            &metrics,
        ));

        assert!(evaluation.pass, "soak iteration {iteration} failed");
        assert_eq!(
            evaluation.read_snapshots.get("reader:cpu"),
            metrics.get("cpu")
        );
        assert_eq!(evaluation.final_metrics.get("cpu"), Some(&next_value));
        metrics = evaluation.final_metrics;
    }

    assert!(matches!(metrics.get("cpu"), Some(value) if (10..=20).contains(value)));
}

#[test]
fn log_events_keep_required_stable_fields() {
    let registrations = vec![registration(
        "ctrl",
        &["cpu"],
        &["cpu"],
        1_000_000,
        1_000_000,
        "writes every 1s",
    )];

    let config = InterferenceConfig::default();
    let read_requests: [MetricReadRequest; 0] = [];
    let write_requests = [MetricWriteRequest {
        controller_id: "ctrl".to_string(),
        metric: "cpu".to_string(),
        value: 15,
    }];
    let subscriptions: [MetricSubscription; 0] = [];
    let metrics = initial_metrics();

    let evaluation = evaluate_controller_interference(&scenario(
        "trace-interference-log",
        "policy-interference-log",
        &config,
        &registrations,
        (&read_requests, &write_requests, &subscriptions),
        &metrics,
    ));

    assert!(evaluation.logs.iter().all(|event| {
        !event.trace_id.is_empty()
            && !event.decision_id.is_empty()
            && !event.policy_id.is_empty()
            && !event.component.is_empty()
            && !event.event.is_empty()
            && !event.outcome.is_empty()
    }));
}

// ────────────────────────────────────────────────────────────
// Enrichment: error paths, serde, edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn empty_registrations_and_writes_produce_passing_evaluation() {
    let registrations: Vec<ControllerRegistration> = vec![];
    let config = InterferenceConfig::default();
    let read_requests: [MetricReadRequest; 0] = [];
    let write_requests: [MetricWriteRequest; 0] = [];
    let subscriptions: [MetricSubscription; 0] = [];
    let metrics = BTreeMap::new();

    let evaluation = evaluate_controller_interference(&scenario(
        "trace-empty",
        "policy-empty",
        &config,
        &registrations,
        (&read_requests, &write_requests, &subscriptions),
        &metrics,
    ));

    assert!(evaluation.pass);
    assert!(!evaluation.rollback_required);
    assert!(evaluation.applied_writes.is_empty());
    assert!(evaluation.rejected_writes.is_empty());
    assert!(evaluation.findings.is_empty());
}

#[test]
fn single_writer_no_conflict_passes() {
    let registrations = vec![registration(
        "solo",
        &["cpu"],
        &["cpu"],
        1_000_000,
        1_000_000,
        "writes every 1s",
    )];

    let config = InterferenceConfig::default();
    let read_requests: [MetricReadRequest; 0] = [];
    let write_requests = [MetricWriteRequest {
        controller_id: "solo".to_string(),
        metric: "cpu".to_string(),
        value: 42,
    }];
    let subscriptions: [MetricSubscription; 0] = [];
    let metrics = initial_metrics();

    let evaluation = evaluate_controller_interference(&scenario(
        "trace-solo",
        "policy-solo",
        &config,
        &registrations,
        (&read_requests, &write_requests, &subscriptions),
        &metrics,
    ));

    assert!(evaluation.pass);
    assert_eq!(evaluation.applied_writes.len(), 1);
    assert_eq!(evaluation.final_metrics.get("cpu"), Some(&42));
}

#[test]
fn unknown_controller_write_is_rejected() {
    let registrations = vec![registration(
        "known",
        &["cpu"],
        &["cpu"],
        1_000_000,
        1_000_000,
        "writes every 1s",
    )];

    let config = InterferenceConfig::default();
    let read_requests: [MetricReadRequest; 0] = [];
    let write_requests = [MetricWriteRequest {
        controller_id: "unknown-ctrl".to_string(),
        metric: "cpu".to_string(),
        value: 99,
    }];
    let subscriptions: [MetricSubscription; 0] = [];
    let metrics = initial_metrics();

    let evaluation = evaluate_controller_interference(&scenario(
        "trace-unknown",
        "policy-unknown",
        &config,
        &registrations,
        (&read_requests, &write_requests, &subscriptions),
        &metrics,
    ));

    assert!(!evaluation.pass);
    assert!(
        evaluation
            .findings
            .iter()
            .any(|f| { f.code == InterferenceFailureCode::UnknownController })
    );
}

#[test]
fn unauthorized_write_metric_is_rejected() {
    let registrations = vec![registration(
        "reader-only",
        &["cpu"],
        &[], // no write metrics
        1_000_000,
        1_000_000,
        "reads only",
    )];

    let config = InterferenceConfig::default();
    let read_requests: [MetricReadRequest; 0] = [];
    let write_requests = [MetricWriteRequest {
        controller_id: "reader-only".to_string(),
        metric: "cpu".to_string(),
        value: 99,
    }];
    let subscriptions: [MetricSubscription; 0] = [];
    let metrics = initial_metrics();

    let evaluation = evaluate_controller_interference(&scenario(
        "trace-unauth-write",
        "policy-unauth-write",
        &config,
        &registrations,
        (&read_requests, &write_requests, &subscriptions),
        &metrics,
    ));

    assert!(!evaluation.pass);
    assert!(
        evaluation
            .findings
            .iter()
            .any(|f| { f.code == InterferenceFailureCode::UnauthorizedWrite })
    );
}

#[test]
fn unauthorized_read_metric_is_rejected() {
    let registrations = vec![registration(
        "other-ctrl",
        &["throughput"], // only authorized for throughput
        &["throughput"],
        1_000_000,
        1_000_000,
        "reads/writes throughput only",
    )];

    let config = InterferenceConfig::default();
    let read_requests = [MetricReadRequest {
        controller_id: "other-ctrl".to_string(),
        metric: "cpu".to_string(), // NOT in read_metrics or write_metrics
    }];
    let write_requests: [MetricWriteRequest; 0] = [];
    let subscriptions: [MetricSubscription; 0] = [];
    let metrics = initial_metrics();

    let evaluation = evaluate_controller_interference(&scenario(
        "trace-unauth-read",
        "policy-unauth-read",
        &config,
        &registrations,
        (&read_requests, &write_requests, &subscriptions),
        &metrics,
    ));

    assert!(!evaluation.pass);
    assert!(
        evaluation
            .findings
            .iter()
            .any(|f| { f.code == InterferenceFailureCode::UnauthorizedRead })
    );
}

#[test]
fn duplicate_controller_registration_is_rejected() {
    let registrations = vec![
        registration(
            "dup-ctrl",
            &["cpu"],
            &["cpu"],
            1_000_000,
            1_000_000,
            "first",
        ),
        registration(
            "dup-ctrl",
            &["cpu"],
            &["cpu"],
            1_000_000,
            1_000_000,
            "second",
        ),
    ];

    let config = InterferenceConfig::default();
    let read_requests: [MetricReadRequest; 0] = [];
    let write_requests: [MetricWriteRequest; 0] = [];
    let subscriptions: [MetricSubscription; 0] = [];
    let metrics = initial_metrics();

    let evaluation = evaluate_controller_interference(&scenario(
        "trace-dup",
        "policy-dup",
        &config,
        &registrations,
        (&read_requests, &write_requests, &subscriptions),
        &metrics,
    ));

    assert!(!evaluation.pass);
    assert!(
        evaluation
            .findings
            .iter()
            .any(|f| { f.code == InterferenceFailureCode::DuplicateController })
    );
}

#[test]
fn read_snapshot_captures_initial_metric_value() {
    let registrations = vec![registration(
        "reader",
        &["latency"],
        &[],
        1_000_000,
        2_000_000,
        "reads only",
    )];

    let config = InterferenceConfig::default();
    let read_requests = [MetricReadRequest {
        controller_id: "reader".to_string(),
        metric: "latency".to_string(),
    }];
    let write_requests: [MetricWriteRequest; 0] = [];
    let subscriptions: [MetricSubscription; 0] = [];
    let metrics = initial_metrics();

    let evaluation = evaluate_controller_interference(&scenario(
        "trace-read-snap",
        "policy-read-snap",
        &config,
        &registrations,
        (&read_requests, &write_requests, &subscriptions),
        &metrics,
    ));

    assert!(evaluation.pass);
    assert_eq!(evaluation.read_snapshots.get("reader:latency"), Some(&100));
}

#[test]
fn conflict_resolution_mode_display() {
    assert_eq!(ConflictResolutionMode::Serialize.to_string(), "serialize");
    assert_eq!(ConflictResolutionMode::Reject.to_string(), "reject");
}

#[test]
fn interference_failure_code_display_covers_all_variants() {
    let codes = [
        InterferenceFailureCode::DuplicateController,
        InterferenceFailureCode::MissingTimescaleStatement,
        InterferenceFailureCode::InvalidTimescaleInterval,
        InterferenceFailureCode::UnknownController,
        InterferenceFailureCode::UnauthorizedRead,
        InterferenceFailureCode::UnauthorizedWrite,
        InterferenceFailureCode::TimescaleConflict,
    ];
    for code in &codes {
        let s = code.to_string();
        assert!(!s.is_empty(), "Display for {code:?} must not be empty");
    }
}

#[test]
fn interference_config_default_values() {
    let config = InterferenceConfig::default();
    assert_eq!(config.min_timescale_separation_millionths, 100_000);
    assert_eq!(
        config.conflict_resolution_mode,
        ConflictResolutionMode::Reject
    );
}

#[test]
fn interference_evaluation_serde_round_trip() {
    let registrations = vec![registration(
        "ctrl",
        &["cpu"],
        &["cpu"],
        1_000_000,
        1_000_000,
        "writes every 1s",
    )];
    let config = InterferenceConfig::default();
    let read_requests: [MetricReadRequest; 0] = [];
    let write_requests = [MetricWriteRequest {
        controller_id: "ctrl".to_string(),
        metric: "cpu".to_string(),
        value: 15,
    }];
    let subscriptions: [MetricSubscription; 0] = [];
    let metrics = initial_metrics();

    let evaluation = evaluate_controller_interference(&scenario(
        "trace-serde",
        "policy-serde",
        &config,
        &registrations,
        (&read_requests, &write_requests, &subscriptions),
        &metrics,
    ));

    let json = serde_json::to_string(&evaluation).expect("serialize");
    let recovered: InterferenceEvaluation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(evaluation.pass, recovered.pass);
    assert_eq!(evaluation.decision_id, recovered.decision_id);
    assert_eq!(evaluation.final_metrics, recovered.final_metrics);
}

#[test]
fn multiple_independent_metrics_no_conflict() {
    let registrations = vec![
        registration(
            "cpu-ctrl",
            &["cpu"],
            &["cpu"],
            1_000_000,
            1_000_000,
            "writes cpu",
        ),
        registration(
            "latency-ctrl",
            &["latency"],
            &["latency"],
            1_000_000,
            1_000_000,
            "writes latency",
        ),
    ];

    let config = InterferenceConfig::default();
    let read_requests: [MetricReadRequest; 0] = [];
    let write_requests = [
        MetricWriteRequest {
            controller_id: "cpu-ctrl".to_string(),
            metric: "cpu".to_string(),
            value: 50,
        },
        MetricWriteRequest {
            controller_id: "latency-ctrl".to_string(),
            metric: "latency".to_string(),
            value: 200,
        },
    ];
    let subscriptions: [MetricSubscription; 0] = [];
    let metrics = initial_metrics();

    let evaluation = evaluate_controller_interference(&scenario(
        "trace-multi-metric",
        "policy-multi-metric",
        &config,
        &registrations,
        (&read_requests, &write_requests, &subscriptions),
        &metrics,
    ));

    assert!(evaluation.pass);
    assert_eq!(evaluation.final_metrics.get("cpu"), Some(&50));
    assert_eq!(evaluation.final_metrics.get("latency"), Some(&200));
}

#[test]
fn controller_registration_serde_round_trip() {
    let reg = registration(
        "ctrl-serde",
        &["cpu", "latency"],
        &["cpu"],
        100_000,
        200_000,
        "test registration",
    );
    let json = serde_json::to_string(&reg).expect("serialize");
    let recovered: ControllerRegistration = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(reg.controller_id, recovered.controller_id);
    assert_eq!(reg.read_metrics, recovered.read_metrics);
    assert_eq!(reg.write_metrics, recovered.write_metrics);
    assert_eq!(
        reg.timescale.observation_interval_millionths,
        recovered.timescale.observation_interval_millionths
    );
}

// ────────────────────────────────────────────────────────────
// Enrichment batch 8: serde roundtrips, failure code coverage,
// edge cases, struct validation
// ────────────────────────────────────────────────────────────

#[test]
fn interference_failure_code_serde_round_trip() {
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
        let json = serde_json::to_string(&code).expect("serialize");
        let recovered: InterferenceFailureCode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(code, recovered);
    }
}

#[test]
fn interference_failure_code_display_all_unique() {
    let codes = [
        InterferenceFailureCode::DuplicateController,
        InterferenceFailureCode::MissingTimescaleStatement,
        InterferenceFailureCode::InvalidTimescaleInterval,
        InterferenceFailureCode::UnknownController,
        InterferenceFailureCode::UnauthorizedRead,
        InterferenceFailureCode::UnauthorizedWrite,
        InterferenceFailureCode::TimescaleConflict,
    ];
    let displays: BTreeSet<String> = codes.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), codes.len());
}

#[test]
fn conflict_resolution_mode_serde_round_trip() {
    for mode in [
        ConflictResolutionMode::Serialize,
        ConflictResolutionMode::Reject,
    ] {
        let json = serde_json::to_string(&mode).expect("serialize");
        let recovered: ConflictResolutionMode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(mode, recovered);
    }
}

#[test]
fn timescale_separation_statement_serde_round_trip() {
    let stmt = TimescaleSeparationStatement {
        observation_interval_millionths: 250_000,
        write_interval_millionths: 1_000_000,
        statement: "quarter-second observe, one-second write".to_string(),
    };
    let json = serde_json::to_string(&stmt).expect("serialize");
    let recovered: TimescaleSeparationStatement = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(stmt, recovered);
}

#[test]
fn metric_read_request_serde_round_trip() {
    let req = MetricReadRequest {
        controller_id: "ctrl-1".to_string(),
        metric: "cpu".to_string(),
    };
    let json = serde_json::to_string(&req).expect("serialize");
    let recovered: MetricReadRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(req, recovered);
}

#[test]
fn metric_write_request_serde_round_trip() {
    let req = MetricWriteRequest {
        controller_id: "ctrl-1".to_string(),
        metric: "latency".to_string(),
        value: 42,
    };
    let json = serde_json::to_string(&req).expect("serialize");
    let recovered: MetricWriteRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(req, recovered);
}

#[test]
fn metric_subscription_serde_round_trip() {
    let sub = MetricSubscription {
        controller_id: "watcher".to_string(),
        metric: "throughput".to_string(),
    };
    let json = serde_json::to_string(&sub).expect("serialize");
    let recovered: MetricSubscription = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(sub, recovered);
}

#[test]
fn interference_config_serde_round_trip() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 500_000,
        conflict_resolution_mode: ConflictResolutionMode::Serialize,
    };
    let json = serde_json::to_string(&config).expect("serialize");
    let recovered: InterferenceConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, recovered);
}

#[test]
fn write_to_nonexistent_metric_passes_and_creates_entry() {
    let registrations = vec![registration(
        "writer",
        &["new_metric"],
        &["new_metric"],
        1_000_000,
        1_000_000,
        "writes new metric",
    )];

    let config = InterferenceConfig::default();
    let read_requests: [MetricReadRequest; 0] = [];
    let write_requests = [MetricWriteRequest {
        controller_id: "writer".to_string(),
        metric: "new_metric".to_string(),
        value: 999,
    }];
    let subscriptions: [MetricSubscription; 0] = [];
    let metrics = BTreeMap::new(); // empty initial metrics

    let evaluation = evaluate_controller_interference(&scenario(
        "trace-new-metric",
        "policy-new-metric",
        &config,
        &registrations,
        (&read_requests, &write_requests, &subscriptions),
        &metrics,
    ));

    assert!(evaluation.pass);
    assert_eq!(evaluation.final_metrics.get("new_metric"), Some(&999));
}

#[test]
fn read_nonexistent_metric_still_passes() {
    let registrations = vec![registration(
        "reader",
        &["ghost"],
        &[],
        1_000_000,
        2_000_000,
        "reads only",
    )];

    let config = InterferenceConfig::default();
    let read_requests = [MetricReadRequest {
        controller_id: "reader".to_string(),
        metric: "ghost".to_string(),
    }];
    let write_requests: [MetricWriteRequest; 0] = [];
    let subscriptions: [MetricSubscription; 0] = [];
    let metrics = BTreeMap::new();

    let evaluation = evaluate_controller_interference(&scenario(
        "trace-ghost-read",
        "policy-ghost-read",
        &config,
        &registrations,
        (&read_requests, &write_requests, &subscriptions),
        &metrics,
    ));

    assert!(evaluation.pass);
}

#[test]
fn serialize_mode_with_three_writers_resolves_deterministically() {
    let registrations = vec![
        registration("w-a", &["m"], &["m"], 100_000, 100_000, "a"),
        registration("w-b", &["m"], &["m"], 100_000, 100_000, "b"),
        registration("w-c", &["m"], &["m"], 100_000, 100_000, "c"),
    ];

    let config = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Serialize,
    };
    let read_requests: [MetricReadRequest; 0] = [];
    let write_requests = [
        MetricWriteRequest {
            controller_id: "w-a".to_string(),
            metric: "m".to_string(),
            value: 10,
        },
        MetricWriteRequest {
            controller_id: "w-b".to_string(),
            metric: "m".to_string(),
            value: 20,
        },
        MetricWriteRequest {
            controller_id: "w-c".to_string(),
            metric: "m".to_string(),
            value: 30,
        },
    ];
    let subscriptions: [MetricSubscription; 0] = [];
    let metrics = BTreeMap::from([("m".to_string(), 0)]);

    let eval1 = evaluate_controller_interference(&scenario(
        "trace-3w",
        "policy-3w",
        &config,
        &registrations,
        (&read_requests, &write_requests, &subscriptions),
        &metrics,
    ));

    // Run again to verify determinism
    let eval2 = evaluate_controller_interference(&scenario(
        "trace-3w",
        "policy-3w",
        &config,
        &registrations,
        (&read_requests, &write_requests, &subscriptions),
        &metrics,
    ));

    assert!(eval1.pass);
    assert_eq!(eval1.final_metrics.get("m"), eval2.final_metrics.get("m"));
    assert_eq!(eval1.applied_writes.len(), 3);
}

#[test]
fn evaluation_decision_id_is_nonempty() {
    let registrations: Vec<ControllerRegistration> = vec![];
    let config = InterferenceConfig::default();
    let read_requests: [MetricReadRequest; 0] = [];
    let write_requests: [MetricWriteRequest; 0] = [];
    let subscriptions: [MetricSubscription; 0] = [];
    let metrics = BTreeMap::new();

    let evaluation = evaluate_controller_interference(&scenario(
        "trace-id",
        "policy-id",
        &config,
        &registrations,
        (&read_requests, &write_requests, &subscriptions),
        &metrics,
    ));

    assert!(!evaluation.decision_id.is_empty());
}

#[test]
fn subscription_without_matching_write_gets_initial_value() {
    let registrations = vec![registration(
        "subscriber",
        &["cpu"],
        &[],
        500_000,
        2_000_000,
        "sub",
    )];

    let config = InterferenceConfig::default();
    let read_requests: [MetricReadRequest; 0] = [];
    let write_requests: [MetricWriteRequest; 0] = [];
    let subscriptions = [MetricSubscription {
        controller_id: "subscriber".to_string(),
        metric: "cpu".to_string(),
    }];
    let metrics = initial_metrics();

    let evaluation = evaluate_controller_interference(&scenario(
        "trace-sub-no-write",
        "policy-sub-no-write",
        &config,
        &registrations,
        (&read_requests, &write_requests, &subscriptions),
        &metrics,
    ));

    assert!(evaluation.pass);
    // Subscriber should still get streamed the current metric value
    let updates = evaluation.subscription_streams.get("subscriber");
    assert!(updates.is_some());
}

#[test]
fn interference_config_debug_is_nonempty() {
    let config = InterferenceConfig::default();
    assert!(!format!("{config:?}").is_empty());
}

#[test]
fn controller_registration_serde_is_deterministic() {
    let reg = registration("ctrl-det", &["m1"], &["m1"], 1_000_000, 500_000, "test");
    let a = serde_json::to_string(&reg).expect("first");
    let b = serde_json::to_string(&reg).expect("second");
    assert_eq!(a, b);
}

#[test]
fn conflict_resolution_mode_debug_is_nonempty() {
    let mode = ConflictResolutionMode::Reject;
    assert!(!format!("{mode:?}").is_empty());
}

// ===========================================================================
// Enrichment: ConflictResolutionMode — Display all variants
// ===========================================================================

#[test]
fn enrichment_conflict_resolution_mode_display_all() {
    assert_eq!(ConflictResolutionMode::Serialize.to_string(), "serialize");
    assert_eq!(ConflictResolutionMode::Reject.to_string(), "reject");
}

#[test]
fn enrichment_conflict_resolution_mode_serde_roundtrip() {
    for mode in [
        ConflictResolutionMode::Serialize,
        ConflictResolutionMode::Reject,
    ] {
        let json = serde_json::to_string(&mode).unwrap();
        let back: ConflictResolutionMode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, mode);
    }
}

// ===========================================================================
// Enrichment: InterferenceFailureCode — Display all 7 variants
// ===========================================================================

#[test]
fn enrichment_interference_failure_code_display_all() {
    let codes = [
        InterferenceFailureCode::DuplicateController,
        InterferenceFailureCode::MissingTimescaleStatement,
        InterferenceFailureCode::InvalidTimescaleInterval,
        InterferenceFailureCode::UnknownController,
        InterferenceFailureCode::UnauthorizedRead,
        InterferenceFailureCode::UnauthorizedWrite,
        InterferenceFailureCode::TimescaleConflict,
    ];
    let displays: BTreeSet<String> = codes.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), 7, "7 distinct display strings");
    for d in &displays {
        assert!(!d.is_empty());
    }
}

#[test]
fn enrichment_interference_failure_code_serde_roundtrip() {
    let codes = [
        InterferenceFailureCode::DuplicateController,
        InterferenceFailureCode::MissingTimescaleStatement,
        InterferenceFailureCode::InvalidTimescaleInterval,
        InterferenceFailureCode::UnknownController,
        InterferenceFailureCode::UnauthorizedRead,
        InterferenceFailureCode::UnauthorizedWrite,
        InterferenceFailureCode::TimescaleConflict,
    ];
    for c in &codes {
        let json = serde_json::to_string(c).unwrap();
        let back: InterferenceFailureCode = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

// ===========================================================================
// Enrichment: InterferenceConfig — default values
// ===========================================================================

#[test]
fn enrichment_interference_config_default_values() {
    let config = InterferenceConfig::default();
    assert_eq!(config.min_timescale_separation_millionths, 100_000);
    assert_eq!(
        config.conflict_resolution_mode,
        ConflictResolutionMode::Reject
    );
}

#[test]
fn enrichment_interference_config_serde_roundtrip() {
    let config = InterferenceConfig {
        min_timescale_separation_millionths: 250_000,
        conflict_resolution_mode: ConflictResolutionMode::Serialize,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: InterferenceConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, config);
}

// ===========================================================================
// Enrichment: TimescaleSeparationStatement — serde roundtrip
// ===========================================================================

#[test]
fn enrichment_timescale_separation_statement_serde_roundtrip() {
    let ts = TimescaleSeparationStatement {
        observation_interval_millionths: 500_000,
        write_interval_millionths: 1_000_000,
        statement: "observe every 500ms, write every 1s".to_string(),
    };
    let json = serde_json::to_string(&ts).unwrap();
    let back: TimescaleSeparationStatement = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ts);
}

// ===========================================================================
// Enrichment: MetricReadRequest / MetricWriteRequest / MetricSubscription serde
// ===========================================================================

#[test]
fn enrichment_metric_read_request_serde_roundtrip() {
    let req = MetricReadRequest {
        controller_id: "ctrl-1".to_string(),
        metric: "cpu".to_string(),
    };
    let json = serde_json::to_string(&req).unwrap();
    let back: MetricReadRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(back, req);
}

#[test]
fn enrichment_metric_write_request_serde_roundtrip() {
    let req = MetricWriteRequest {
        controller_id: "ctrl-1".to_string(),
        metric: "latency".to_string(),
        value: 42,
    };
    let json = serde_json::to_string(&req).unwrap();
    let back: MetricWriteRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(back, req);
}

#[test]
fn enrichment_metric_subscription_serde_roundtrip() {
    let sub = MetricSubscription {
        controller_id: "ctrl-1".to_string(),
        metric: "throughput".to_string(),
    };
    let json = serde_json::to_string(&sub).unwrap();
    let back: MetricSubscription = serde_json::from_str(&json).unwrap();
    assert_eq!(back, sub);
}

// ===========================================================================
// Enrichment: ControllerRegistration — serde roundtrip
// ===========================================================================

#[test]
fn enrichment_controller_registration_serde_roundtrip() {
    let reg = registration(
        "ctrl-rt",
        &["cpu", "latency"],
        &["throughput"],
        1_000_000,
        500_000,
        "fast controller",
    );
    let json = serde_json::to_string(&reg).unwrap();
    let back: ControllerRegistration = serde_json::from_str(&json).unwrap();
    assert_eq!(back, reg);
}

// ===========================================================================
// Enrichment: InterferenceEvaluation — serde roundtrip via evaluate
// ===========================================================================

#[test]
fn enrichment_interference_evaluation_serde_roundtrip() {
    let config = InterferenceConfig::default();
    let registrations = vec![registration(
        "ctrl-serde",
        &["cpu"],
        &["cpu"],
        500_000,
        500_000,
        "serde test",
    )];
    let read_requests: [MetricReadRequest; 0] = [];
    let write_requests = [MetricWriteRequest {
        controller_id: "ctrl-serde".to_string(),
        metric: "cpu".to_string(),
        value: 42,
    }];
    let subscriptions: [MetricSubscription; 0] = [];
    let metrics = initial_metrics();

    let evaluation = evaluate_controller_interference(&scenario(
        "trace-serde",
        "policy-serde",
        &config,
        &registrations,
        (&read_requests, &write_requests, &subscriptions),
        &metrics,
    ));

    let json = serde_json::to_string(&evaluation).unwrap();
    let back: InterferenceEvaluation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, evaluation);
}

// ===========================================================================
// Enrichment: evaluate — empty registrations yields pass
// ===========================================================================

#[test]
fn enrichment_evaluate_empty_registrations_pass() {
    let config = InterferenceConfig::default();
    let registrations: Vec<ControllerRegistration> = vec![];
    let read_requests: [MetricReadRequest; 0] = [];
    let write_requests: [MetricWriteRequest; 0] = [];
    let subscriptions: [MetricSubscription; 0] = [];
    let metrics = initial_metrics();

    let evaluation = evaluate_controller_interference(&scenario(
        "trace-empty",
        "policy-empty",
        &config,
        &registrations,
        (&read_requests, &write_requests, &subscriptions),
        &metrics,
    ));
    assert!(evaluation.pass);
    assert!(evaluation.findings.is_empty());
}

// ===========================================================================
// Enrichment: evaluate — read snapshot reflects initial metrics
// ===========================================================================

#[test]
fn enrichment_evaluate_read_snapshot_reflects_initial() {
    let config = InterferenceConfig::default();
    let registrations = vec![registration(
        "reader",
        &["cpu", "latency"],
        &[],
        1_000_000,
        0,
        "read-only",
    )];
    let read_requests = [
        MetricReadRequest {
            controller_id: "reader".to_string(),
            metric: "cpu".to_string(),
        },
        MetricReadRequest {
            controller_id: "reader".to_string(),
            metric: "latency".to_string(),
        },
    ];
    let write_requests: [MetricWriteRequest; 0] = [];
    let subscriptions: [MetricSubscription; 0] = [];
    let metrics = initial_metrics();

    let evaluation = evaluate_controller_interference(&scenario(
        "trace-read",
        "policy-read",
        &config,
        &registrations,
        (&read_requests, &write_requests, &subscriptions),
        &metrics,
    ));
    assert!(evaluation.pass);
    assert_eq!(evaluation.read_snapshots.get("cpu"), Some(&10));
    assert_eq!(evaluation.read_snapshots.get("latency"), Some(&100));
}

// ===========================================================================
// Enrichment: evaluate — decision_id is nonempty
// ===========================================================================

#[test]
fn enrichment_evaluate_decision_id_present() {
    let config = InterferenceConfig::default();
    let registrations = vec![registration("c", &[], &[], 1_000_000, 1_000_000, "s")];
    let read_requests: [MetricReadRequest; 0] = [];
    let write_requests: [MetricWriteRequest; 0] = [];
    let subscriptions: [MetricSubscription; 0] = [];
    let metrics = initial_metrics();

    let evaluation = evaluate_controller_interference(&scenario(
        "trace-id",
        "policy-id",
        &config,
        &registrations,
        (&read_requests, &write_requests, &subscriptions),
        &metrics,
    ));
    assert!(!evaluation.decision_id.is_empty());
}

// ===========================================================================
// Enrichment: evaluate — single writer without conflict passes
// ===========================================================================

#[test]
fn enrichment_evaluate_single_writer_passes() {
    let config = InterferenceConfig::default();
    let registrations = vec![registration(
        "writer",
        &["cpu"],
        &["cpu"],
        1_000_000,
        500_000,
        "single writer",
    )];
    let read_requests: [MetricReadRequest; 0] = [];
    let write_requests = [MetricWriteRequest {
        controller_id: "writer".to_string(),
        metric: "cpu".to_string(),
        value: 99,
    }];
    let subscriptions: [MetricSubscription; 0] = [];
    let metrics = initial_metrics();

    let evaluation = evaluate_controller_interference(&scenario(
        "trace-single",
        "policy-single",
        &config,
        &registrations,
        (&read_requests, &write_requests, &subscriptions),
        &metrics,
    ));
    assert!(evaluation.pass);
    assert_eq!(evaluation.applied_writes.len(), 1);
    assert!(evaluation.rejected_writes.is_empty());
    assert_eq!(evaluation.final_metrics.get("cpu"), Some(&99));
}

// ===========================================================================
// Enrichment: evaluate — log events have correct component
// ===========================================================================

#[test]
fn enrichment_evaluate_log_events_have_component() {
    let config = InterferenceConfig::default();
    let registrations = vec![registration(
        "logtest",
        &["cpu"],
        &["cpu"],
        1_000_000,
        1_000_000,
        "log check",
    )];
    let read_requests: [MetricReadRequest; 0] = [];
    let write_requests = [MetricWriteRequest {
        controller_id: "logtest".to_string(),
        metric: "cpu".to_string(),
        value: 50,
    }];
    let subscriptions: [MetricSubscription; 0] = [];
    let metrics = initial_metrics();

    let evaluation = evaluate_controller_interference(&scenario(
        "trace-log",
        "policy-log",
        &config,
        &registrations,
        (&read_requests, &write_requests, &subscriptions),
        &metrics,
    ));
    for log in &evaluation.logs {
        assert!(!log.component.is_empty());
        assert!(!log.trace_id.is_empty());
        assert!(!log.event.is_empty());
        assert!(!log.outcome.is_empty());
    }
}
