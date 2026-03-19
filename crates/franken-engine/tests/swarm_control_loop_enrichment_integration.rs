//! Enrichment integration tests for `swarm_control_loop` module.
//!
//! Tests advanced lifecycle scenarios, wave transitions, risk budget edge cases,
//! bottleneck detection, rationale deltas, and multi-iteration recomputation.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use std::collections::BTreeSet;

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::swarm_control_loop::{
    Bottleneck, BottleneckSeverity, ControlLoopConfig, ControlLoopError, CrossCuttingSignals,
    QueueArtifact, QueueEntry, RationaleDelta, SWARM_CONTROL_SCHEMA_VERSION, SwarmControlLoop,
    SwarmRiskBudget, TaskNode, Wave,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

fn make_task(id: &str, deps: &[&str]) -> TaskNode {
    TaskNode {
        task_id: id.to_string(),
        title: format!("Task {id}"),
        depends_on: deps.iter().map(|d| d.to_string()).collect(),
        dependents: BTreeSet::new(),
        completed: false,
        impact_millionths: 800_000,
        confidence_millionths: 900_000,
        reuse_millionths: 200_000,
        effort_millionths: 300_000,
        friction_millionths: 100_000,
        primary_risk: "none".to_string(),
        countermeasure: "n/a".to_string(),
        fallback_trigger: "never".to_string(),
        first_action: "start".to_string(),
        assignee: "agent-1".to_string(),
    }
}

fn default_loop() -> SwarmControlLoop {
    SwarmControlLoop::new(ControlLoopConfig::default()).unwrap()
}

fn add_chain(ctrl: &mut SwarmControlLoop, ids: &[&str]) {
    for (i, id) in ids.iter().enumerate() {
        let deps: Vec<&str> = if i > 0 { vec![ids[i - 1]] } else { vec![] };
        let mut task = make_task(id, &deps);
        if i > 0
            && let Some(prev) = ctrl.graph.get_mut(ids[i - 1])
        {
            prev.dependents.insert(id.to_string());
        }
        task.dependents = if i + 1 < ids.len() {
            let mut s = BTreeSet::new();
            s.insert(ids[i + 1].to_string());
            s
        } else {
            BTreeSet::new()
        };
        ctrl.add_task(task).unwrap();
    }
}

fn default_signals() -> CrossCuttingSignals {
    CrossCuttingSignals::default()
}

fn ep(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

// ---------------------------------------------------------------------------
// 1. Wave assignment transitions
// ---------------------------------------------------------------------------

#[test]
fn enrich_wave_ready_now_when_no_deps() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    let art = ctrl.recompute(ep(1), 0, default_signals(), vec![]).unwrap();
    assert_eq!(art.queue[0].wave, Wave::ReadyNow);
}

#[test]
fn enrich_wave_ready_next_with_one_incomplete_dep() {
    let mut ctrl = default_loop();
    add_chain(&mut ctrl, &["a", "b"]);
    let art = ctrl.recompute(ep(1), 0, default_signals(), vec![]).unwrap();
    let b_entry = art.queue.iter().find(|e| e.task_id == "b");
    if let Some(e) = b_entry {
        assert_eq!(e.wave, Wave::ReadyNext);
    }
}

// ---------------------------------------------------------------------------
// 2. Complete task changes wave
// ---------------------------------------------------------------------------

#[test]
fn enrich_completing_dep_promotes_wave() {
    let mut ctrl = default_loop();
    add_chain(&mut ctrl, &["a", "b"]);
    ctrl.complete_task("a");
    let art = ctrl.recompute(ep(1), 0, default_signals(), vec![]).unwrap();
    let b_entry = art.queue.iter().find(|e| e.task_id == "b");
    if let Some(e) = b_entry {
        assert_eq!(e.wave, Wave::ReadyNow);
    }
}

// ---------------------------------------------------------------------------
// 3. Risk budget edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrich_risk_budget_consume_negative_ignored() {
    let mut budget = SwarmRiskBudget::default();
    let triggered = budget.consume(-100);
    assert!(!triggered);
    assert_eq!(budget.remaining_millionths, MILLION);
}

#[test]
fn enrich_risk_budget_reallocate_with_zero() {
    let mut budget = SwarmRiskBudget::default();
    budget.consume(500_000);
    budget.reallocate(0);
    assert_eq!(budget.remaining_millionths, 0);
    assert!(budget.conservative_mode);
}

#[test]
fn enrich_risk_budget_reallocate_above_million_clamped() {
    let mut budget = SwarmRiskBudget::default();
    budget.reallocate(2_000_000);
    assert_eq!(budget.remaining_millionths, MILLION);
}

#[test]
fn enrich_risk_budget_display_format() {
    let budget = SwarmRiskBudget::default();
    let s = budget.to_string();
    assert!(s.contains("remaining="));
    assert!(s.contains("consumed="));
}

// ---------------------------------------------------------------------------
// 4. CrossCuttingSignals edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrich_signals_all_zeros_health_zero() {
    let s = CrossCuttingSignals {
        observability_quality_millionths: 0,
        catastrophic_tail_score_millionths: 0,
        bifurcation_distance_millionths: 0,
        unit_depth_score_millionths: 0,
        e2e_stability_score_millionths: 0,
        logging_integrity_score_millionths: 0,
    };
    assert_eq!(s.composite_health_millionths(), 0);
}

#[test]
fn enrich_signals_partial_health() {
    let s = CrossCuttingSignals {
        observability_quality_millionths: 500_000,
        catastrophic_tail_score_millionths: 0,
        bifurcation_distance_millionths: 500_000,
        unit_depth_score_millionths: 500_000,
        e2e_stability_score_millionths: 500_000,
        logging_integrity_score_millionths: 500_000,
    };
    assert_eq!(s.composite_health_millionths(), 500_000);
}

#[test]
fn enrich_signals_serde_roundtrip_custom() {
    let s = CrossCuttingSignals {
        observability_quality_millionths: 123_456,
        catastrophic_tail_score_millionths: 78_901,
        bifurcation_distance_millionths: 234_567,
        unit_depth_score_millionths: 345_678,
        e2e_stability_score_millionths: 456_789,
        logging_integrity_score_millionths: 567_890,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: CrossCuttingSignals = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ---------------------------------------------------------------------------
// 5. TaskNode EV edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrich_task_ev_with_zero_impact() {
    let mut t = make_task("t", &[]);
    t.impact_millionths = 0;
    assert_eq!(t.ev_millionths(), -t.friction_millionths);
}

#[test]
fn enrich_task_relevance_floors_at_zero() {
    let mut t = make_task("t", &[]);
    t.impact_millionths = 0;
    t.confidence_millionths = 0;
    t.reuse_millionths = 0;
    t.effort_millionths = MILLION;
    t.friction_millionths = MILLION;
    assert_eq!(t.relevance_millionths(), 0);
}

// ---------------------------------------------------------------------------
// 6. ControlLoopError display and serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_error_display_all_variants() {
    let errors: Vec<ControlLoopError> = vec![
        ControlLoopError::EmptyGraph,
        ControlLoopError::TooManyTasks {
            count: 5000,
            max: 4096,
        },
        ControlLoopError::CycleDetected {
            involved: vec!["a".into(), "b".into()],
        },
        ControlLoopError::UnknownDependency {
            task_id: "x".into(),
            dependency_id: "y".into(),
        },
        ControlLoopError::InvalidConfig {
            detail: "bad value".into(),
        },
    ];
    for e in &errors {
        assert!(!e.to_string().is_empty());
    }
}

#[test]
fn enrich_error_serde_all_variants() {
    let errors: Vec<ControlLoopError> = vec![
        ControlLoopError::EmptyGraph,
        ControlLoopError::TooManyTasks {
            count: 100,
            max: 50,
        },
        ControlLoopError::CycleDetected {
            involved: vec!["a".into()],
        },
        ControlLoopError::UnknownDependency {
            task_id: "x".into(),
            dependency_id: "y".into(),
        },
        ControlLoopError::InvalidConfig {
            detail: "test".into(),
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: ControlLoopError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ---------------------------------------------------------------------------
// 7. Queue depth configuration
// ---------------------------------------------------------------------------

#[test]
fn enrich_invalid_queue_depth_zero() {
    let mut config = ControlLoopConfig::default();
    config.queue_depth = 0;
    assert!(SwarmControlLoop::new(config).is_err());
}

#[test]
fn enrich_invalid_queue_depth_too_large() {
    let mut config = ControlLoopConfig::default();
    config.queue_depth = 100;
    assert!(SwarmControlLoop::new(config).is_err());
}

#[test]
fn enrich_queue_depth_limits_output() {
    let mut config = ControlLoopConfig::default();
    config.queue_depth = 3;
    let mut ctrl = SwarmControlLoop::new(config).unwrap();
    for i in 0..10 {
        ctrl.add_task(make_task(&format!("t{i}"), &[])).unwrap();
    }
    let art = ctrl.recompute(ep(1), 0, default_signals(), vec![]).unwrap();
    assert!(art.queue.len() <= 3);
}

// ---------------------------------------------------------------------------
// 8. Iteration counting
// ---------------------------------------------------------------------------

#[test]
fn enrich_iteration_count_increments() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    assert_eq!(ctrl.iteration_count, 0);
    let _ = ctrl.recompute(ep(1), 0, default_signals(), vec![]).unwrap();
    assert_eq!(ctrl.iteration_count, 1);
    let _ = ctrl.recompute(ep(2), 0, default_signals(), vec![]).unwrap();
    assert_eq!(ctrl.iteration_count, 2);
}

// ---------------------------------------------------------------------------
// 9. Rationale deltas on first iteration
// ---------------------------------------------------------------------------

#[test]
fn enrich_first_iteration_all_entered_queue() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    ctrl.add_task(make_task("t2", &[])).unwrap();
    let art = ctrl.recompute(ep(1), 0, default_signals(), vec![]).unwrap();
    for delta in &art.rationale_deltas {
        assert_eq!(delta.previous_rank, 0);
        assert!(delta.new_rank > 0);
    }
}

// ---------------------------------------------------------------------------
// 10. Completed task not in queue
// ---------------------------------------------------------------------------

#[test]
fn enrich_completed_task_not_in_queue() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    ctrl.add_task(make_task("t2", &[])).unwrap();
    ctrl.complete_task("t1");
    let art = ctrl.recompute(ep(1), 0, default_signals(), vec![]).unwrap();
    assert!(!art.queue.iter().any(|e| e.task_id == "t1"));
}

// ---------------------------------------------------------------------------
// 11. Bottleneck detection
// ---------------------------------------------------------------------------

#[test]
fn enrich_bottleneck_detected_for_task_with_dependents() {
    let mut ctrl = default_loop();
    let mut root = make_task("root", &[]);
    root.dependents = BTreeSet::from(["c1".into(), "c2".into(), "c3".into()]);
    ctrl.add_task(root).unwrap();
    for i in 1..=3 {
        ctrl.add_task(make_task(&format!("c{i}"), &["root"]))
            .unwrap();
    }
    let art = ctrl.recompute(ep(1), 0, default_signals(), vec![]).unwrap();
    assert!(!art.bottlenecks.is_empty());
}

// ---------------------------------------------------------------------------
// 12. QueueArtifact methods
// ---------------------------------------------------------------------------

#[test]
fn enrich_artifact_completion_half() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    ctrl.add_task(make_task("t2", &[])).unwrap();
    ctrl.complete_task("t1");
    let art = ctrl.recompute(ep(1), 0, default_signals(), vec![]).unwrap();
    assert_eq!(art.completion_millionths(), 500_000);
}

#[test]
fn enrich_artifact_is_conservative_false_by_default() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    let art = ctrl.recompute(ep(1), 0, default_signals(), vec![]).unwrap();
    assert!(!art.is_conservative());
}

// ---------------------------------------------------------------------------
// 13. Low health triggers conservative
// ---------------------------------------------------------------------------

#[test]
fn enrich_low_health_consumes_risk_budget() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    let bad_signals = CrossCuttingSignals {
        catastrophic_tail_score_millionths: MILLION,
        ..Default::default()
    };
    let art = ctrl.recompute(ep(1), 0, bad_signals, vec![]).unwrap();
    // Health is 0, deficit is min_health (400_000), consumed from risk budget.
    // After consuming 400_000, remaining = 600_000 > threshold 200_000.
    // Need multiple iterations to exhaust.
    assert!(art.risk_budget.consumed_millionths > 0);
}

// ---------------------------------------------------------------------------
// 14. Evidence IDs preserved
// ---------------------------------------------------------------------------

#[test]
fn enrich_evidence_ids_preserved_in_artifact() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    let evidence = vec!["ev-1".into(), "ev-2".into()];
    let art = ctrl
        .recompute(ep(1), 0, default_signals(), evidence.clone())
        .unwrap();
    assert_eq!(art.evidence_ids, evidence);
}

// ---------------------------------------------------------------------------
// 15. Schema version
// ---------------------------------------------------------------------------

#[test]
fn enrich_artifact_schema_version() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    let art = ctrl.recompute(ep(1), 0, default_signals(), vec![]).unwrap();
    assert_eq!(art.schema_version, SWARM_CONTROL_SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// 16. Artifact hash deterministic
// ---------------------------------------------------------------------------

#[test]
fn enrich_artifact_hash_deterministic() {
    let mut ctrl1 = default_loop();
    ctrl1.add_task(make_task("t1", &[])).unwrap();
    let a1 = ctrl1
        .recompute(ep(1), 100, default_signals(), vec![])
        .unwrap();

    let mut ctrl2 = default_loop();
    ctrl2.add_task(make_task("t1", &[])).unwrap();
    let a2 = ctrl2
        .recompute(ep(1), 100, default_signals(), vec![])
        .unwrap();
    assert_eq!(a1.artifact_hash, a2.artifact_hash);
}

// ---------------------------------------------------------------------------
// 17. Gated tasks excluded by default
// ---------------------------------------------------------------------------

#[test]
fn enrich_gated_tasks_excluded_by_default() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("a", &[])).unwrap();
    ctrl.add_task(make_task("b", &[])).unwrap();
    ctrl.add_task(make_task("c", &[])).unwrap();
    let mut gated = make_task("gated", &["a", "b", "c"]);
    gated.depends_on = BTreeSet::from(["a".into(), "b".into(), "c".into()]);
    ctrl.add_task(gated).unwrap();
    let art = ctrl.recompute(ep(1), 0, default_signals(), vec![]).unwrap();
    assert!(!art.queue.iter().any(|e| e.task_id == "gated"));
}

// ---------------------------------------------------------------------------
// 18. include_gated_in_queue
// ---------------------------------------------------------------------------

#[test]
fn enrich_gated_tasks_included_when_configured() {
    let mut config = ControlLoopConfig::default();
    config.include_gated_in_queue = true;
    let mut ctrl = SwarmControlLoop::new(config).unwrap();
    ctrl.add_task(make_task("a", &[])).unwrap();
    ctrl.add_task(make_task("b", &[])).unwrap();
    ctrl.add_task(make_task("c", &[])).unwrap();
    let mut gated = make_task("gated", &["a", "b", "c"]);
    gated.depends_on = BTreeSet::from(["a".into(), "b".into(), "c".into()]);
    ctrl.add_task(gated).unwrap();
    let art = ctrl.recompute(ep(1), 0, default_signals(), vec![]).unwrap();
    assert!(art.queue.iter().any(|e| e.task_id == "gated"));
}

// ---------------------------------------------------------------------------
// 19. Task count and completed count
// ---------------------------------------------------------------------------

#[test]
fn enrich_task_count_and_completed_count() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    ctrl.add_task(make_task("t2", &[])).unwrap();
    ctrl.add_task(make_task("t3", &[])).unwrap();
    assert_eq!(ctrl.task_count(), 3);
    assert_eq!(ctrl.completed_count(), 0);
    ctrl.complete_task("t1");
    assert_eq!(ctrl.completed_count(), 1);
}

// ---------------------------------------------------------------------------
// 20. Complete unknown task returns false
// ---------------------------------------------------------------------------

#[test]
fn enrich_complete_unknown_task_returns_false() {
    let mut ctrl = default_loop();
    assert!(!ctrl.complete_task("nonexistent"));
}

// ---------------------------------------------------------------------------
// 21. Validate detects unknown dependency
// ---------------------------------------------------------------------------

#[test]
fn enrich_validate_unknown_dependency_error() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &["nonexistent"])).unwrap();
    let err = ctrl.validate().unwrap_err();
    assert!(matches!(err, ControlLoopError::UnknownDependency { .. }));
}

// ---------------------------------------------------------------------------
// 22. Wave Display
// ---------------------------------------------------------------------------

#[test]
fn enrich_wave_display_all_variants() {
    assert_eq!(Wave::ReadyNow.to_string(), "ready_now");
    assert_eq!(Wave::ReadyNext.to_string(), "ready_next");
    assert_eq!(Wave::Gated.to_string(), "gated");
}

// ---------------------------------------------------------------------------
// 23. RationaleDelta serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_rationale_delta_serde_roundtrip() {
    let d = RationaleDelta {
        task_id: "t1".into(),
        previous_rank: 3,
        new_rank: 1,
        reason: "promoted".into(),
    };
    let json = serde_json::to_string(&d).unwrap();
    let back: RationaleDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

// ---------------------------------------------------------------------------
// 24. SwarmControlLoop Display
// ---------------------------------------------------------------------------

#[test]
fn enrich_swarm_control_loop_display() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    let s = ctrl.to_string();
    assert!(s.contains("swarm_control"));
}

// ---------------------------------------------------------------------------
// 25. QueueArtifact Display
// ---------------------------------------------------------------------------

#[test]
fn enrich_queue_artifact_display() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    let art = ctrl.recompute(ep(1), 0, default_signals(), vec![]).unwrap();
    let s = art.to_string();
    assert!(s.contains("queue_artifact"));
}

// ---------------------------------------------------------------------------
// 26. QueueEntry serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_queue_entry_serde_roundtrip() {
    let e = QueueEntry {
        rank: 1,
        task_id: "t1".into(),
        title: "Task 1".into(),
        impact_millionths: 800_000,
        confidence_millionths: 900_000,
        reuse_millionths: 200_000,
        effort_millionths: 300_000,
        friction_millionths: 100_000,
        ev_millionths: 620_000,
        relevance_millionths: 520_000,
        primary_risk: "none".into(),
        countermeasure: "n/a".into(),
        fallback_trigger: "never".into(),
        first_action: "start".into(),
        wave: Wave::ReadyNow,
        open_blocker_count: 0,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: QueueEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// 27. Validate empty graph
// ---------------------------------------------------------------------------

#[test]
fn enrich_validate_empty_graph_error() {
    let ctrl = default_loop();
    let err = ctrl.validate().unwrap_err();
    assert!(matches!(err, ControlLoopError::EmptyGraph));
}

// ---------------------------------------------------------------------------
// 28. Bottleneck Display
// ---------------------------------------------------------------------------

#[test]
fn enrich_bottleneck_display_contains_info() {
    let b = Bottleneck {
        task_id: "root".into(),
        downstream_count: 10,
        unassigned: true,
        severity: BottleneckSeverity::Critical,
    };
    let s = b.to_string();
    assert!(s.contains("root"));
    assert!(s.contains("downstream=10"));
}

// ---------------------------------------------------------------------------
// 29. QueueArtifact serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_queue_artifact_serde_roundtrip() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    ctrl.add_task(make_task("t2", &[])).unwrap();
    let art = ctrl
        .recompute(ep(1), 1000, default_signals(), vec!["ev1".into()])
        .unwrap();
    let json = serde_json::to_string(&art).unwrap();
    let back: QueueArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(art, back);
}

// ---------------------------------------------------------------------------
// 30. BottleneckSeverity all variants display
// ---------------------------------------------------------------------------

#[test]
fn enrich_bottleneck_severity_display_all() {
    assert_eq!(BottleneckSeverity::Low.to_string(), "low");
    assert_eq!(BottleneckSeverity::Medium.to_string(), "medium");
    assert_eq!(BottleneckSeverity::High.to_string(), "high");
    assert_eq!(BottleneckSeverity::Critical.to_string(), "critical");
}
