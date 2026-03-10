#![forbid(unsafe_code)]
//! Integration tests for the `swarm_control_loop` module.
//!
//! Exercises every public type, constant, enum variant, method, error path,
//! Display impl, serde roundtrip, and cross-concern lifecycle scenario from
//! outside the crate boundary.

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

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::swarm_control_loop::{
    Bottleneck, BottleneckSeverity, ControlLoopConfig, ControlLoopError, CrossCuttingSignals,
    QueueArtifact, QueueEntry, RationaleDelta, SWARM_CONTROL_SCHEMA_VERSION, SwarmControlLoop,
    SwarmRiskBudget, TaskNode, Wave,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn make_unassigned_task(id: &str, deps: &[&str]) -> TaskNode {
    let mut t = make_task(id, deps);
    t.assignee = String::new();
    t
}

fn default_loop() -> SwarmControlLoop {
    SwarmControlLoop::new(ControlLoopConfig::default()).unwrap()
}

fn default_signals() -> CrossCuttingSignals {
    CrossCuttingSignals::default()
}

fn default_epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

/// Add a linear chain of tasks: ids[0] -> ids[1] -> ... -> ids[n-1].
/// Wires up `depends_on` and `dependents` correctly.
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

fn recompute_default(
    ctrl: &mut SwarmControlLoop,
    epoch: u64,
) -> Result<QueueArtifact, ControlLoopError> {
    ctrl.recompute(
        SecurityEpoch::from_raw(epoch),
        epoch * 1_000,
        default_signals(),
        vec![],
    )
}

// ===========================================================================
// 1. Public constant
// ===========================================================================

#[test]
fn schema_version_is_nonempty_semver() {
    assert!(!SWARM_CONTROL_SCHEMA_VERSION.is_empty());
    let parts: Vec<&str> = SWARM_CONTROL_SCHEMA_VERSION.split('.').collect();
    assert_eq!(parts.len(), 3, "expected semver x.y.z");
    for p in &parts {
        assert!(p.parse::<u64>().is_ok(), "non-numeric semver part: {p}");
    }
}

// ===========================================================================
// 2. Wave enum
// ===========================================================================

#[test]
fn wave_display_all_variants() {
    assert_eq!(Wave::ReadyNow.to_string(), "ready_now");
    assert_eq!(Wave::ReadyNext.to_string(), "ready_next");
    assert_eq!(Wave::Gated.to_string(), "gated");
}

#[test]
fn wave_serde_roundtrip() {
    for w in [Wave::ReadyNow, Wave::ReadyNext, Wave::Gated] {
        let json = serde_json::to_string(&w).unwrap();
        let back: Wave = serde_json::from_str(&json).unwrap();
        assert_eq!(back, w);
    }
}

#[test]
fn wave_ordering() {
    assert!(Wave::ReadyNow < Wave::ReadyNext);
    assert!(Wave::ReadyNext < Wave::Gated);
    assert!(Wave::ReadyNow < Wave::Gated);
}

#[test]
fn wave_clone_eq() {
    let w = Wave::ReadyNext;
    let w2 = w;
    assert_eq!(w, w2);
}

#[test]
fn wave_serde_snake_case_format() {
    let json = serde_json::to_string(&Wave::ReadyNow).unwrap();
    assert_eq!(json, "\"ready_now\"");
    let json = serde_json::to_string(&Wave::ReadyNext).unwrap();
    assert_eq!(json, "\"ready_next\"");
    let json = serde_json::to_string(&Wave::Gated).unwrap();
    assert_eq!(json, "\"gated\"");
}

// ===========================================================================
// 3. BottleneckSeverity enum
// ===========================================================================

#[test]
fn bottleneck_severity_display() {
    assert_eq!(BottleneckSeverity::Low.to_string(), "low");
    assert_eq!(BottleneckSeverity::Medium.to_string(), "medium");
    assert_eq!(BottleneckSeverity::High.to_string(), "high");
    assert_eq!(BottleneckSeverity::Critical.to_string(), "critical");
}

#[test]
fn bottleneck_severity_ordering() {
    let mut sevs = vec![
        BottleneckSeverity::Critical,
        BottleneckSeverity::Low,
        BottleneckSeverity::High,
        BottleneckSeverity::Medium,
    ];
    sevs.sort();
    assert_eq!(
        sevs,
        vec![
            BottleneckSeverity::Low,
            BottleneckSeverity::Medium,
            BottleneckSeverity::High,
            BottleneckSeverity::Critical,
        ]
    );
}

#[test]
fn bottleneck_severity_serde_roundtrip() {
    for s in [
        BottleneckSeverity::Low,
        BottleneckSeverity::Medium,
        BottleneckSeverity::High,
        BottleneckSeverity::Critical,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: BottleneckSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

// ===========================================================================
// 4. CrossCuttingSignals
// ===========================================================================

#[test]
fn signals_default_all_healthy() {
    let s = CrossCuttingSignals::default();
    assert_eq!(s.observability_quality_millionths, MILLION);
    assert_eq!(s.catastrophic_tail_score_millionths, 0);
    assert_eq!(s.bifurcation_distance_millionths, MILLION);
    assert_eq!(s.unit_depth_score_millionths, MILLION);
    assert_eq!(s.e2e_stability_score_millionths, MILLION);
    assert_eq!(s.logging_integrity_score_millionths, MILLION);
}

#[test]
fn signals_composite_health_all_perfect() {
    let s = CrossCuttingSignals::default();
    assert_eq!(s.composite_health_millionths(), MILLION);
}

#[test]
fn signals_composite_health_penalises_tail() {
    let s = CrossCuttingSignals {
        catastrophic_tail_score_millionths: 300_000,
        ..Default::default()
    };
    // avg_positive = 1_000_000, penalty = 300_000 → 700_000
    assert_eq!(s.composite_health_millionths(), 700_000);
}

#[test]
fn signals_composite_health_floors_at_zero() {
    let s = CrossCuttingSignals {
        catastrophic_tail_score_millionths: 5_000_000,
        ..Default::default()
    };
    assert_eq!(s.composite_health_millionths(), 0);
}

#[test]
fn signals_composite_health_mixed_scores() {
    let s = CrossCuttingSignals {
        observability_quality_millionths: 600_000,
        catastrophic_tail_score_millionths: 100_000,
        bifurcation_distance_millionths: 400_000,
        unit_depth_score_millionths: 500_000,
        e2e_stability_score_millionths: 300_000,
        logging_integrity_score_millionths: 200_000,
    };
    // positive sum = 600k + 400k + 500k + 300k + 200k = 2_000_000
    // avg = 400_000
    // health = 400_000 - 100_000 = 300_000
    assert_eq!(s.composite_health_millionths(), 300_000);
}

#[test]
fn signals_display_contains_all_fields() {
    let s = CrossCuttingSignals::default();
    let d = s.to_string();
    for label in ["obs=", "tail=", "bifurc=", "unit=", "e2e=", "log="] {
        assert!(d.contains(label), "missing label {label} in '{d}'");
    }
}

#[test]
fn signals_serde_roundtrip() {
    let s = CrossCuttingSignals {
        observability_quality_millionths: 500_000,
        catastrophic_tail_score_millionths: 200_000,
        bifurcation_distance_millionths: 700_000,
        unit_depth_score_millionths: 300_000,
        e2e_stability_score_millionths: 900_000,
        logging_integrity_score_millionths: 100_000,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: CrossCuttingSignals = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s);
}

// ===========================================================================
// 5. TaskNode
// ===========================================================================

#[test]
fn task_node_ev_computation() {
    let t = make_task("t1", &[]);
    // EV = 800_000 * 900_000 / 1_000_000 - 100_000 = 720_000 - 100_000 = 620_000
    assert_eq!(t.ev_millionths(), 620_000);
}

#[test]
fn task_node_ev_zero_impact() {
    let mut t = make_task("t1", &[]);
    t.impact_millionths = 0;
    t.friction_millionths = 0;
    assert_eq!(t.ev_millionths(), 0);
}

#[test]
fn task_node_ev_negative_from_high_friction() {
    let mut t = make_task("t1", &[]);
    t.impact_millionths = 100_000;
    t.confidence_millionths = 100_000;
    t.friction_millionths = 500_000;
    // raw_ev = 100_000 * 100_000 / 1_000_000 = 10_000
    // ev = 10_000 - 500_000 = -490_000
    assert_eq!(t.ev_millionths(), -490_000);
}

#[test]
fn task_node_relevance_floors_at_zero() {
    let mut t = make_task("t1", &[]);
    t.impact_millionths = 0;
    t.confidence_millionths = 0;
    t.reuse_millionths = 0;
    t.effort_millionths = MILLION;
    t.friction_millionths = MILLION;
    // ev = 0 - 1_000_000 = -1_000_000
    // relevance = (-1_000_000 + 0 - 500_000).max(0) = 0
    assert_eq!(t.relevance_millionths(), 0);
}

#[test]
fn task_node_relevance_includes_reuse_bonus() {
    let t = make_task("t1", &[]);
    let ev = t.ev_millionths();
    let reuse_bonus = t.reuse_millionths / 4;
    let effort_penalty = t.effort_millionths / 2;
    let expected = (ev + reuse_bonus - effort_penalty).max(0);
    assert_eq!(t.relevance_millionths(), expected);
}

#[test]
fn task_node_display() {
    let t = make_task("alpha", &[]);
    let d = t.to_string();
    assert!(d.contains("alpha"));
    assert!(d.contains("ev="));
    assert!(d.contains("rel="));
    assert!(d.contains("done=false"));
}

#[test]
fn task_node_serde_roundtrip() {
    let t = make_task("t1", &["dep1", "dep2"]);
    let json = serde_json::to_string(&t).unwrap();
    let back: TaskNode = serde_json::from_str(&json).unwrap();
    assert_eq!(back, t);
}

// ===========================================================================
// 6. QueueEntry
// ===========================================================================

#[test]
fn queue_entry_display() {
    let e = QueueEntry {
        rank: 3,
        task_id: "abc".to_string(),
        title: "ABC".to_string(),
        impact_millionths: 0,
        confidence_millionths: 0,
        reuse_millionths: 0,
        effort_millionths: 0,
        friction_millionths: 0,
        ev_millionths: 42,
        relevance_millionths: 99,
        primary_risk: String::new(),
        countermeasure: String::new(),
        fallback_trigger: String::new(),
        first_action: String::new(),
        wave: Wave::Gated,
        open_blocker_count: 5,
    };
    let d = e.to_string();
    assert!(d.contains("#3"));
    assert!(d.contains("abc"));
    assert!(d.contains("ev=42"));
    assert!(d.contains("gated"));
}

#[test]
fn queue_entry_serde_roundtrip() {
    let e = QueueEntry {
        rank: 1,
        task_id: "t1".to_string(),
        title: "Task 1".to_string(),
        impact_millionths: 800_000,
        confidence_millionths: 900_000,
        reuse_millionths: 200_000,
        effort_millionths: 300_000,
        friction_millionths: 100_000,
        ev_millionths: 620_000,
        relevance_millionths: 520_000,
        primary_risk: "risk".to_string(),
        countermeasure: "cm".to_string(),
        fallback_trigger: "fb".to_string(),
        first_action: "go".to_string(),
        wave: Wave::ReadyNow,
        open_blocker_count: 0,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: QueueEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

// ===========================================================================
// 7. RationaleDelta
// ===========================================================================

#[test]
fn rationale_delta_display() {
    let d = RationaleDelta {
        task_id: "t5".to_string(),
        previous_rank: 7,
        new_rank: 2,
        reason: "promoted".to_string(),
    };
    let s = d.to_string();
    assert!(s.contains("t5"));
    assert!(s.contains("7 → 2"));
    assert!(s.contains("promoted"));
}

#[test]
fn rationale_delta_serde_roundtrip() {
    let d = RationaleDelta {
        task_id: "x".to_string(),
        previous_rank: 0,
        new_rank: 1,
        reason: "entered queue".to_string(),
    };
    let json = serde_json::to_string(&d).unwrap();
    let back: RationaleDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d);
}

// ===========================================================================
// 8. Bottleneck
// ===========================================================================

#[test]
fn bottleneck_display() {
    let b = Bottleneck {
        task_id: "blocker".to_string(),
        downstream_count: 12,
        unassigned: true,
        severity: BottleneckSeverity::Critical,
    };
    let d = b.to_string();
    assert!(d.contains("blocker"));
    assert!(d.contains("downstream=12"));
    assert!(d.contains("critical"));
}

#[test]
fn bottleneck_serde_roundtrip() {
    let b = Bottleneck {
        task_id: "b1".to_string(),
        downstream_count: 5,
        unassigned: false,
        severity: BottleneckSeverity::Medium,
    };
    let json = serde_json::to_string(&b).unwrap();
    let back: Bottleneck = serde_json::from_str(&json).unwrap();
    assert_eq!(back, b);
}

// ===========================================================================
// 9. SwarmRiskBudget
// ===========================================================================

#[test]
fn risk_budget_default_values() {
    let b = SwarmRiskBudget::default();
    assert_eq!(b.remaining_millionths, MILLION);
    assert_eq!(b.consumed_millionths, 0);
    assert!(!b.conservative_mode);
    assert_eq!(b.conservative_threshold_millionths, 200_000);
}

#[test]
fn risk_budget_consume_basic() {
    let mut b = SwarmRiskBudget::default();
    let triggered = b.consume(100_000);
    assert!(!triggered);
    assert_eq!(b.remaining_millionths, 900_000);
    assert_eq!(b.consumed_millionths, 100_000);
    assert!(!b.conservative_mode);
}

#[test]
fn risk_budget_consume_triggers_conservative_mode() {
    let mut b = SwarmRiskBudget::default();
    let triggered = b.consume(850_000);
    assert!(triggered);
    assert!(b.conservative_mode);
    assert_eq!(b.remaining_millionths, 150_000);
    assert_eq!(b.consumed_millionths, 850_000);
}

#[test]
fn risk_budget_consume_clamps_negative_amount() {
    let mut b = SwarmRiskBudget::default();
    let triggered = b.consume(-500);
    assert!(!triggered);
    assert_eq!(b.remaining_millionths, MILLION);
    assert_eq!(b.consumed_millionths, 0);
}

#[test]
fn risk_budget_consume_clamps_overflow() {
    let mut b = SwarmRiskBudget::default();
    b.consume(MILLION + 9999);
    assert_eq!(b.remaining_millionths, 0);
    assert_eq!(b.consumed_millionths, MILLION);
}

#[test]
fn risk_budget_consume_idempotent_conservative_trigger() {
    let mut b = SwarmRiskBudget::default();
    let first = b.consume(850_000);
    assert!(first);
    assert!(b.conservative_mode);
    // Second consume should not re-trigger (already conservative)
    let second = b.consume(50_000);
    assert!(!second);
    assert!(b.conservative_mode);
}

#[test]
fn risk_budget_reallocate_basic() {
    let mut b = SwarmRiskBudget::default();
    b.consume(400_000);
    b.reallocate(MILLION);
    assert_eq!(b.remaining_millionths, 600_000);
    assert!(!b.conservative_mode);
}

#[test]
fn risk_budget_reallocate_triggers_conservative() {
    let mut b = SwarmRiskBudget::default();
    b.consume(600_000);
    b.reallocate(800_000);
    // remaining = 800_000 - 600_000 = 200_000 <= threshold (200_000) → conservative
    assert_eq!(b.remaining_millionths, 200_000);
    assert!(b.conservative_mode);
}

#[test]
fn risk_budget_reallocate_clamps_total() {
    let mut b = SwarmRiskBudget::default();
    b.reallocate(2_000_000); // clamped to MILLION
    assert_eq!(b.remaining_millionths, MILLION);
    b.reallocate(-100); // clamped to 0
    assert_eq!(b.remaining_millionths, 0);
}

#[test]
fn risk_budget_display() {
    let b = SwarmRiskBudget::default();
    let d = b.to_string();
    assert!(d.contains("remaining="));
    assert!(d.contains("consumed="));
    assert!(d.contains("conservative="));
}

#[test]
fn risk_budget_serde_roundtrip() {
    let mut b = SwarmRiskBudget::default();
    b.consume(300_000);
    let json = serde_json::to_string(&b).unwrap();
    let back: SwarmRiskBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(back, b);
}

// ===========================================================================
// 10. ControlLoopConfig
// ===========================================================================

#[test]
fn config_defaults() {
    let c = ControlLoopConfig::default();
    assert_eq!(c.queue_depth, 10);
    assert_eq!(c.min_health_millionths, 400_000);
    assert_eq!(c.conservative_threshold_millionths, 200_000);
    assert_eq!(c.ready_next_max_blockers, 2);
    assert!(!c.include_gated_in_queue);
}

#[test]
fn config_serde_roundtrip() {
    let c = ControlLoopConfig {
        queue_depth: 5,
        min_health_millionths: 500_000,
        conservative_threshold_millionths: 100_000,
        ready_next_max_blockers: 3,
        include_gated_in_queue: true,
    };
    let json = serde_json::to_string(&c).unwrap();
    let back: ControlLoopConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
}

// ===========================================================================
// 11. ControlLoopError
// ===========================================================================

#[test]
fn error_display_all_variants() {
    let cases: Vec<(ControlLoopError, &str)> = vec![
        (ControlLoopError::EmptyGraph, "empty"),
        (
            ControlLoopError::TooManyTasks {
                count: 5000,
                max: 4096,
            },
            "5000",
        ),
        (
            ControlLoopError::CycleDetected {
                involved: vec!["a".into(), "b".into()],
            },
            "cycle",
        ),
        (
            ControlLoopError::UnknownDependency {
                task_id: "t1".into(),
                dependency_id: "t99".into(),
            },
            "unknown",
        ),
        (
            ControlLoopError::InvalidConfig {
                detail: "bad depth".into(),
            },
            "invalid",
        ),
    ];
    for (err, keyword) in &cases {
        let s = err.to_string();
        assert!(s.contains(keyword), "expected '{keyword}' in '{s}'");
    }
}

#[test]
fn error_implements_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(ControlLoopError::EmptyGraph);
    assert!(!err.to_string().is_empty());
}

#[test]
fn error_serde_roundtrip_all_variants() {
    let errs = vec![
        ControlLoopError::EmptyGraph,
        ControlLoopError::TooManyTasks { count: 99, max: 50 },
        ControlLoopError::CycleDetected {
            involved: vec!["x".into()],
        },
        ControlLoopError::UnknownDependency {
            task_id: "a".into(),
            dependency_id: "b".into(),
        },
        ControlLoopError::InvalidConfig {
            detail: "oops".into(),
        },
    ];
    for err in &errs {
        let json = serde_json::to_string(err).unwrap();
        let back: ControlLoopError = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, err);
    }
}

// ===========================================================================
// 12. SwarmControlLoop construction
// ===========================================================================

#[test]
fn new_creates_empty_loop() {
    let ctrl = default_loop();
    assert_eq!(ctrl.task_count(), 0);
    assert_eq!(ctrl.completed_count(), 0);
    assert_eq!(ctrl.iteration_count, 0);
    assert_eq!(ctrl.epoch, SecurityEpoch::from_raw(0));
}

#[test]
fn new_rejects_zero_queue_depth() {
    let r = SwarmControlLoop::new(ControlLoopConfig {
        queue_depth: 0,
        ..Default::default()
    });
    assert!(matches!(r, Err(ControlLoopError::InvalidConfig { .. })));
}

#[test]
fn new_rejects_excessive_queue_depth() {
    let r = SwarmControlLoop::new(ControlLoopConfig {
        queue_depth: 65,
        ..Default::default()
    });
    assert!(matches!(r, Err(ControlLoopError::InvalidConfig { .. })));
}

#[test]
fn new_accepts_max_queue_depth_64() {
    let r = SwarmControlLoop::new(ControlLoopConfig {
        queue_depth: 64,
        ..Default::default()
    });
    assert!(r.is_ok());
}

#[test]
fn new_rejects_negative_min_health() {
    let r = SwarmControlLoop::new(ControlLoopConfig {
        min_health_millionths: -1,
        ..Default::default()
    });
    assert!(matches!(r, Err(ControlLoopError::InvalidConfig { .. })));
}

#[test]
fn new_rejects_over_million_min_health() {
    let r = SwarmControlLoop::new(ControlLoopConfig {
        min_health_millionths: MILLION + 1,
        ..Default::default()
    });
    assert!(matches!(r, Err(ControlLoopError::InvalidConfig { .. })));
}

#[test]
fn new_propagates_conservative_threshold() {
    let ctrl = SwarmControlLoop::new(ControlLoopConfig {
        conservative_threshold_millionths: 500_000,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(ctrl.risk_budget.conservative_threshold_millionths, 500_000);
}

// ===========================================================================
// 13. Task graph manipulation
// ===========================================================================

#[test]
fn add_task_increments_count() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    assert_eq!(ctrl.task_count(), 1);
    ctrl.add_task(make_task("t2", &[])).unwrap();
    assert_eq!(ctrl.task_count(), 2);
}

#[test]
fn complete_task_known() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    assert!(ctrl.complete_task("t1"));
    assert_eq!(ctrl.completed_count(), 1);
}

#[test]
fn complete_task_unknown_returns_false() {
    let mut ctrl = default_loop();
    assert!(!ctrl.complete_task("nonexistent"));
}

#[test]
fn complete_task_idempotent() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    assert!(ctrl.complete_task("t1"));
    assert!(ctrl.complete_task("t1")); // still returns true (task exists)
    assert_eq!(ctrl.completed_count(), 1);
}

// ===========================================================================
// 14. Validation
// ===========================================================================

#[test]
fn validate_empty_graph_errors() {
    let ctrl = default_loop();
    assert!(matches!(ctrl.validate(), Err(ControlLoopError::EmptyGraph)));
}

#[test]
fn validate_valid_single_task_ok() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    assert!(ctrl.validate().is_ok());
}

#[test]
fn validate_unknown_dependency_errors() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &["ghost"])).unwrap();
    let err = ctrl.validate().unwrap_err();
    assert!(matches!(err, ControlLoopError::UnknownDependency { .. }));
}

#[test]
fn validate_cycle_two_nodes() {
    let mut ctrl = default_loop();
    let mut a = make_task("a", &["b"]);
    a.dependents.insert("b".to_string());
    let mut b = make_task("b", &["a"]);
    b.dependents.insert("a".to_string());
    ctrl.add_task(a).unwrap();
    ctrl.add_task(b).unwrap();
    let err = ctrl.validate().unwrap_err();
    if let ControlLoopError::CycleDetected { involved } = &err {
        assert!(involved.contains(&"a".to_string()));
        assert!(involved.contains(&"b".to_string()));
    } else {
        panic!("expected CycleDetected, got {err}");
    }
}

#[test]
fn validate_chain_ok() {
    let mut ctrl = default_loop();
    add_chain(&mut ctrl, &["a", "b", "c", "d"]);
    assert!(ctrl.validate().is_ok());
}

// ===========================================================================
// 15. Recompute — basic
// ===========================================================================

#[test]
fn recompute_empty_graph_fails() {
    let mut ctrl = default_loop();
    assert!(recompute_default(&mut ctrl, 1).is_err());
}

#[test]
fn recompute_single_task_produces_artifact() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    let art = recompute_default(&mut ctrl, 1).unwrap();
    assert_eq!(art.schema_version, SWARM_CONTROL_SCHEMA_VERSION);
    assert_eq!(art.epoch, default_epoch(1));
    assert_eq!(art.total_tasks, 1);
    assert_eq!(art.completed_tasks, 0);
    assert_eq!(art.queue.len(), 1);
    assert_eq!(art.queue[0].rank, 1);
    assert_eq!(art.queue[0].task_id, "t1");
    assert_eq!(art.queue[0].wave, Wave::ReadyNow);
    assert_eq!(art.queue[0].open_blocker_count, 0);
}

#[test]
fn recompute_increments_iteration_count() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    recompute_default(&mut ctrl, 1).unwrap();
    assert_eq!(ctrl.iteration_count, 1);
    recompute_default(&mut ctrl, 2).unwrap();
    assert_eq!(ctrl.iteration_count, 2);
}

#[test]
fn recompute_queue_respects_depth() {
    let mut ctrl = SwarmControlLoop::new(ControlLoopConfig {
        queue_depth: 3,
        ..Default::default()
    })
    .unwrap();
    for i in 0..10 {
        ctrl.add_task(make_task(&format!("t{i}"), &[])).unwrap();
    }
    let art = recompute_default(&mut ctrl, 1).unwrap();
    assert_eq!(art.queue.len(), 3);
    // Ranks are 1-based sequential
    for (i, entry) in art.queue.iter().enumerate() {
        assert_eq!(entry.rank, (i + 1) as u64);
    }
}

#[test]
fn recompute_excludes_completed_tasks() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    ctrl.add_task(make_task("t2", &[])).unwrap();
    ctrl.complete_task("t1");
    let art = recompute_default(&mut ctrl, 1).unwrap();
    assert_eq!(art.completed_tasks, 1);
    assert!(art.queue.iter().all(|e| e.task_id != "t1"));
}

// ===========================================================================
// 16. Recompute — wave filtering
// ===========================================================================

#[test]
fn recompute_excludes_gated_by_default() {
    let mut ctrl = default_loop();
    // root is ready_now; d1, d2, d3 depend on root (ready_next);
    // gated depends on d1,d2,d3 (3 blockers → gated)
    let mut root = make_task("root", &[]);
    root.dependents = ["d1", "d2", "d3"].iter().map(|s| s.to_string()).collect();
    ctrl.add_task(root).unwrap();
    for id in ["d1", "d2", "d3"] {
        ctrl.add_task(make_task(id, &["root"])).unwrap();
    }
    ctrl.add_task(make_task("gated", &["d1", "d2", "d3"]))
        .unwrap();
    let art = recompute_default(&mut ctrl, 1).unwrap();
    assert!(
        art.queue.iter().all(|e| e.task_id != "gated"),
        "gated tasks excluded by default"
    );
}

#[test]
fn recompute_includes_gated_when_configured() {
    let mut ctrl = SwarmControlLoop::new(ControlLoopConfig {
        include_gated_in_queue: true,
        ..Default::default()
    })
    .unwrap();
    ctrl.add_task(make_task("root", &[])).unwrap();
    for id in ["d1", "d2", "d3"] {
        ctrl.add_task(make_task(id, &["root"])).unwrap();
    }
    ctrl.add_task(make_task("gated", &["d1", "d2", "d3"]))
        .unwrap();
    let art = recompute_default(&mut ctrl, 1).unwrap();
    assert!(art.queue.iter().any(|e| e.task_id == "gated"));
}

// ===========================================================================
// 17. Queue ordering
// ===========================================================================

#[test]
fn queue_orders_ready_now_before_ready_next() {
    let mut ctrl = default_loop();
    let mut t1 = make_task("t1", &[]);
    t1.dependents.insert("t2".to_string());
    t1.impact_millionths = 100_000; // low EV
    ctrl.add_task(t1).unwrap();

    let mut t2 = make_task("t2", &["t1"]);
    t2.impact_millionths = 999_000; // high EV
    ctrl.add_task(t2).unwrap();

    let art = recompute_default(&mut ctrl, 1).unwrap();
    assert_eq!(art.queue[0].task_id, "t1", "ready_now first");
    assert_eq!(art.queue[1].task_id, "t2", "ready_next second");
}

#[test]
fn queue_orders_by_relevance_within_same_wave() {
    let mut ctrl = default_loop();
    let mut low = make_task("low", &[]);
    low.impact_millionths = 200_000;
    ctrl.add_task(low).unwrap();

    let mut high = make_task("high", &[]);
    high.impact_millionths = 950_000;
    ctrl.add_task(high).unwrap();

    let art = recompute_default(&mut ctrl, 1).unwrap();
    assert_eq!(art.queue[0].task_id, "high");
    assert_eq!(art.queue[1].task_id, "low");
}

// ===========================================================================
// 18. Rationale deltas
// ===========================================================================

#[test]
fn rationale_delta_first_run_all_entered() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    ctrl.add_task(make_task("t2", &[])).unwrap();
    let art = recompute_default(&mut ctrl, 1).unwrap();
    assert!(art.rationale_deltas.len() >= 2);
    for d in &art.rationale_deltas {
        assert_eq!(d.previous_rank, 0);
        assert!(d.reason.contains("entered"));
    }
}

#[test]
fn rationale_delta_dropped_on_completion() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    ctrl.add_task(make_task("t2", &[])).unwrap();
    recompute_default(&mut ctrl, 1).unwrap();

    ctrl.complete_task("t1");
    let art = recompute_default(&mut ctrl, 2).unwrap();
    let dropped = art
        .rationale_deltas
        .iter()
        .find(|d| d.task_id == "t1")
        .unwrap();
    assert_eq!(dropped.new_rank, 0);
    assert!(dropped.reason.contains("dropped"));
}

#[test]
fn rationale_delta_promotion() {
    let mut ctrl = default_loop();
    // Two tasks with different impacts; on first run t_low ranks lower.
    let mut t_high = make_task("t_high", &[]);
    t_high.impact_millionths = 900_000;
    ctrl.add_task(t_high).unwrap();

    let mut t_low = make_task("t_low", &[]);
    t_low.impact_millionths = 200_000;
    ctrl.add_task(t_low).unwrap();

    recompute_default(&mut ctrl, 1).unwrap();

    // Now boost t_low's impact so it becomes rank 1
    ctrl.graph.get_mut("t_low").unwrap().impact_millionths = 999_000;
    let art = recompute_default(&mut ctrl, 2).unwrap();

    let promoted = art.rationale_deltas.iter().find(|d| d.task_id == "t_low");
    assert!(promoted.is_some());
    let promoted = promoted.unwrap();
    assert!(promoted.new_rank < promoted.previous_rank);
    assert!(promoted.reason.contains("promoted"));
}

// ===========================================================================
// 19. Bottleneck detection
// ===========================================================================

#[test]
fn bottleneck_detection_chain() {
    let mut ctrl = default_loop();
    add_chain(&mut ctrl, &["a", "b", "c", "d"]);
    let art = recompute_default(&mut ctrl, 1).unwrap();
    // "a" blocks b, c, d (3 downstream) → Medium severity
    let a_bn = art.bottlenecks.iter().find(|b| b.task_id == "a");
    assert!(a_bn.is_some());
    assert!(a_bn.unwrap().downstream_count >= 3);
}

#[test]
fn bottleneck_completed_excluded() {
    let mut ctrl = default_loop();
    add_chain(&mut ctrl, &["a", "b"]);
    ctrl.complete_task("a");
    let art = recompute_default(&mut ctrl, 1).unwrap();
    assert!(
        art.bottlenecks.iter().all(|b| b.task_id != "a"),
        "completed task not a bottleneck"
    );
}

#[test]
fn bottleneck_unassigned_critical() {
    let mut ctrl = default_loop();
    let mut root = make_unassigned_task("root", &[]);
    let mut dep_names = BTreeSet::new();
    for i in 0..11 {
        let id = format!("d{i}");
        dep_names.insert(id.clone());
        ctrl.add_task(make_task(&id, &["root"])).unwrap();
    }
    root.dependents = dep_names;
    ctrl.add_task(root).unwrap();
    let art = recompute_default(&mut ctrl, 1).unwrap();
    let root_bn = art
        .bottlenecks
        .iter()
        .find(|b| b.task_id == "root")
        .unwrap();
    assert_eq!(root_bn.severity, BottleneckSeverity::Critical);
    assert!(root_bn.unassigned);
}

#[test]
fn bottleneck_severity_thresholds() {
    // Low: downstream < 3, Medium: 3..9, High: >=10 assigned, Critical: >=10 unassigned
    let mut ctrl = default_loop();

    // Task with 2 dependents → Low
    let mut t_low = make_task("t_low", &[]);
    t_low.dependents = ["x1", "x2"].iter().map(|s| s.to_string()).collect();
    ctrl.add_task(t_low).unwrap();
    ctrl.add_task(make_task("x1", &["t_low"])).unwrap();
    ctrl.add_task(make_task("x2", &["t_low"])).unwrap();

    let art = recompute_default(&mut ctrl, 1).unwrap();
    let bn = art
        .bottlenecks
        .iter()
        .find(|b| b.task_id == "t_low")
        .unwrap();
    assert_eq!(bn.severity, BottleneckSeverity::Low);
}

// ===========================================================================
// 20. Conservative mode via low health
// ===========================================================================

#[test]
fn low_health_triggers_conservative_mode() {
    let mut ctrl = SwarmControlLoop::new(ControlLoopConfig {
        conservative_threshold_millionths: 800_000,
        ..Default::default()
    })
    .unwrap();
    ctrl.add_task(make_task("t1", &[])).unwrap();

    let bad = CrossCuttingSignals {
        observability_quality_millionths: 50_000,
        catastrophic_tail_score_millionths: 900_000,
        bifurcation_distance_millionths: 50_000,
        unit_depth_score_millionths: 50_000,
        e2e_stability_score_millionths: 50_000,
        logging_integrity_score_millionths: 50_000,
    };
    let art = ctrl
        .recompute(default_epoch(1), 1_000, bad, vec![])
        .unwrap();
    assert!(art.is_conservative());
}

#[test]
fn healthy_signals_no_conservative() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    let art = recompute_default(&mut ctrl, 1).unwrap();
    assert!(!art.is_conservative());
}

// ===========================================================================
// 21. QueueArtifact accessors
// ===========================================================================

#[test]
fn artifact_completion_percentage() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    ctrl.add_task(make_task("t2", &[])).unwrap();
    ctrl.add_task(make_task("t3", &[])).unwrap();
    ctrl.add_task(make_task("t4", &[])).unwrap();
    ctrl.complete_task("t1");
    ctrl.complete_task("t2");
    let art = recompute_default(&mut ctrl, 1).unwrap();
    // 2 / 4 = 0.5 → 500_000 millionths
    assert_eq!(art.completion_millionths(), 500_000);
}

#[test]
fn artifact_completion_empty_is_million() {
    let a = QueueArtifact {
        schema_version: SWARM_CONTROL_SCHEMA_VERSION.to_string(),
        epoch: SecurityEpoch::from_raw(0),
        timestamp_ns: 0,
        queue: vec![],
        signals: CrossCuttingSignals::default(),
        bottlenecks: vec![],
        risk_budget: SwarmRiskBudget::default(),
        rationale_deltas: vec![],
        evidence_ids: vec![],
        total_tasks: 0,
        completed_tasks: 0,
        ready_now_count: 0,
        ready_next_count: 0,
        gated_count: 0,
        artifact_hash: ContentHash::compute(b"empty"),
    };
    assert_eq!(a.completion_millionths(), MILLION);
}

#[test]
fn artifact_critical_bottleneck_count() {
    let a = QueueArtifact {
        schema_version: SWARM_CONTROL_SCHEMA_VERSION.to_string(),
        epoch: SecurityEpoch::from_raw(0),
        timestamp_ns: 0,
        queue: vec![],
        signals: CrossCuttingSignals::default(),
        bottlenecks: vec![
            Bottleneck {
                task_id: "a".into(),
                downstream_count: 20,
                unassigned: true,
                severity: BottleneckSeverity::Critical,
            },
            Bottleneck {
                task_id: "b".into(),
                downstream_count: 5,
                unassigned: false,
                severity: BottleneckSeverity::Medium,
            },
            Bottleneck {
                task_id: "c".into(),
                downstream_count: 15,
                unassigned: true,
                severity: BottleneckSeverity::Critical,
            },
        ],
        risk_budget: SwarmRiskBudget::default(),
        rationale_deltas: vec![],
        evidence_ids: vec![],
        total_tasks: 10,
        completed_tasks: 0,
        ready_now_count: 0,
        ready_next_count: 0,
        gated_count: 0,
        artifact_hash: ContentHash::compute(b"test"),
    };
    assert_eq!(a.critical_bottleneck_count(), 2);
}

#[test]
fn artifact_display() {
    let mut ctrl = default_loop();
    add_chain(&mut ctrl, &["t1", "t2"]);
    let art = recompute_default(&mut ctrl, 5).unwrap();
    let d = art.to_string();
    assert!(d.contains("queue_artifact"));
    assert!(d.contains("epoch=5"));
}

#[test]
fn artifact_serde_roundtrip() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    let art = ctrl
        .recompute(
            default_epoch(3),
            3_000,
            default_signals(),
            vec!["ev-1".into(), "ev-2".into()],
        )
        .unwrap();
    let json = serde_json::to_string(&art).unwrap();
    let back: QueueArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(back.epoch, art.epoch);
    assert_eq!(back.queue.len(), art.queue.len());
    assert_eq!(back.evidence_ids, art.evidence_ids);
    assert_eq!(back.artifact_hash, art.artifact_hash);
}

// ===========================================================================
// 22. SwarmControlLoop display and serde
// ===========================================================================

#[test]
fn loop_display() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    let d = ctrl.to_string();
    assert!(d.contains("swarm_control"));
    assert!(d.contains("tasks=1"));
    assert!(d.contains("iterations=0"));
}

#[test]
fn loop_serde_roundtrip() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    ctrl.add_task(make_task("t2", &["t1"])).unwrap();
    recompute_default(&mut ctrl, 1).unwrap();
    let json = serde_json::to_string(&ctrl).unwrap();
    let back: SwarmControlLoop = serde_json::from_str(&json).unwrap();
    assert_eq!(back.task_count(), 2);
    assert_eq!(back.iteration_count, 1);
}

// ===========================================================================
// 23. Artifact hash determinism
// ===========================================================================

#[test]
fn artifact_hash_deterministic() {
    let run = |_: ()| {
        let mut ctrl = default_loop();
        ctrl.add_task(make_task("t1", &[])).unwrap();
        recompute_default(&mut ctrl, 1).unwrap().artifact_hash
    };
    assert_eq!(run(()), run(()));
}

#[test]
fn artifact_hash_differs_with_different_tasks() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    let h1 = recompute_default(&mut ctrl, 1).unwrap().artifact_hash;

    ctrl.add_task(make_task("t2", &[])).unwrap();
    let h2 = recompute_default(&mut ctrl, 2).unwrap().artifact_hash;
    assert_ne!(h1, h2);
}

// ===========================================================================
// 24. Evidence ID linkage
// ===========================================================================

#[test]
fn evidence_ids_preserved() {
    let mut ctrl = default_loop();
    ctrl.add_task(make_task("t1", &[])).unwrap();
    let ids = vec!["ev-a".to_string(), "ev-b".to_string(), "ev-c".to_string()];
    let art = ctrl
        .recompute(default_epoch(1), 1_000, default_signals(), ids.clone())
        .unwrap();
    assert_eq!(art.evidence_ids, ids);
}

// ===========================================================================
// 25. Wave counts
// ===========================================================================

#[test]
fn wave_counts_computed() {
    let mut ctrl = default_loop();
    // root: ready_now (no deps)
    let mut root = make_task("root", &[]);
    root.dependents = ["mid1", "mid2"].iter().map(|s| s.to_string()).collect();
    ctrl.add_task(root).unwrap();

    // mid1, mid2: ready_next (1 blocker)
    ctrl.add_task(make_task("mid1", &["root"])).unwrap();
    ctrl.add_task(make_task("mid2", &["root"])).unwrap();

    // leaf: depends on root, mid1, mid2 → 3 blockers → gated
    ctrl.add_task(make_task("leaf", &["root", "mid1", "mid2"]))
        .unwrap();

    let art = recompute_default(&mut ctrl, 1).unwrap();
    assert_eq!(art.ready_now_count, 1);
    assert_eq!(art.ready_next_count, 2); // mid1, mid2
    assert_eq!(art.gated_count, 1); // leaf
    assert_eq!(art.total_tasks, 4);
    assert_eq!(art.completed_tasks, 0);
}

// ===========================================================================
// 26. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_add_recompute_complete_recompute() {
    let mut ctrl = default_loop();

    // Phase 1: build a small graph
    add_chain(&mut ctrl, &["setup", "build", "test", "deploy"]);
    assert_eq!(ctrl.task_count(), 4);

    // Phase 2: first recompute
    let art1 = recompute_default(&mut ctrl, 1).unwrap();
    assert_eq!(art1.total_tasks, 4);
    assert_eq!(art1.completed_tasks, 0);
    assert_eq!(art1.ready_now_count, 1); // "setup"
    assert_eq!(ctrl.iteration_count, 1);

    // Phase 3: complete "setup"
    assert!(ctrl.complete_task("setup"));
    let art2 = recompute_default(&mut ctrl, 2).unwrap();
    assert_eq!(art2.completed_tasks, 1);
    // "build" should now be ready_now
    assert!(art2.ready_now_count >= 1);
    assert_eq!(ctrl.iteration_count, 2);

    // Phase 4: complete remaining
    assert!(ctrl.complete_task("build"));
    assert!(ctrl.complete_task("test"));
    assert!(ctrl.complete_task("deploy"));
    let art3 = recompute_default(&mut ctrl, 3).unwrap();
    assert_eq!(art3.completed_tasks, 4);
    assert_eq!(art3.queue.len(), 0); // nothing left
    assert_eq!(art3.completion_millionths(), MILLION);
}

#[test]
fn lifecycle_risk_budget_degrades_over_bad_iterations() {
    let mut ctrl = SwarmControlLoop::new(ControlLoopConfig {
        conservative_threshold_millionths: 500_000,
        min_health_millionths: 800_000,
        ..Default::default()
    })
    .unwrap();
    ctrl.add_task(make_task("t1", &[])).unwrap();

    // Signal health below threshold: health ~ 0
    let bad = CrossCuttingSignals {
        observability_quality_millionths: 0,
        catastrophic_tail_score_millionths: MILLION,
        bifurcation_distance_millionths: 0,
        unit_depth_score_millionths: 0,
        e2e_stability_score_millionths: 0,
        logging_integrity_score_millionths: 0,
    };

    // Iteration 1: consumes 800k deficit
    let art1 = ctrl
        .recompute(default_epoch(1), 1_000, bad.clone(), vec![])
        .unwrap();
    assert!(art1.is_conservative());
    assert!(ctrl.risk_budget.remaining_millionths < 500_000);

    // Iteration 2: remaining budget continues to deplete
    let art2 = ctrl
        .recompute(default_epoch(2), 2_000, bad, vec![])
        .unwrap();
    assert!(art2.is_conservative());
    assert!(ctrl.risk_budget.remaining_millionths <= art1.risk_budget.remaining_millionths);
}
