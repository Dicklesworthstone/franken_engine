//! Integration tests for the causal intervention planner and counterfactual
//! optimization oracle (RGC-615).

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

use std::collections::BTreeSet;

use frankenengine_engine::causal_intervention_planner::{
    BEAD_ID, COMPONENT, CausalDag, CausalEdge, CausalInterventionPlanner, CausalNode, EdgeKind,
    Identifiability, IdentifiabilityCertificate, InterventionPlan, InterventionPriority, MAX_EDGES,
    MAX_NODES, NodeKind, PlannerError, PlannerReport, SCHEMA_VERSION, build_seed_dag,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn lever(id: &str) -> CausalNode {
    CausalNode {
        id: id.to_string(),
        name: id.to_string(),
        kind: NodeKind::Lever,
        description: format!("test lever {id}"),
        observable: true,
        interventionable: true,
    }
}

fn metric(id: &str) -> CausalNode {
    CausalNode {
        id: id.to_string(),
        name: id.to_string(),
        kind: NodeKind::Metric,
        description: format!("test metric {id}"),
        observable: true,
        interventionable: false,
    }
}

fn confounder(id: &str) -> CausalNode {
    CausalNode {
        id: id.to_string(),
        name: id.to_string(),
        kind: NodeKind::Confounder,
        description: format!("test confounder {id}"),
        observable: true,
        interventionable: false,
    }
}

fn direct_edge(from: &str, to: &str, effect: i64) -> CausalEdge {
    CausalEdge {
        from: from.to_string(),
        to: to.to_string(),
        kind: EdgeKind::Direct,
        effect_size_millionths: effect,
        confidence_millionths: 800_000,
    }
}

fn confounding_edge(from: &str, to: &str) -> CausalEdge {
    CausalEdge {
        from: from.to_string(),
        to: to.to_string(),
        kind: EdgeKind::Confounding,
        effect_size_millionths: 0,
        confidence_millionths: 500_000,
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_have_expected_values() {
    assert_eq!(COMPONENT, "causal_intervention_planner");
    assert_eq!(BEAD_ID, "bd-1lsy.7.15");
    assert!(SCHEMA_VERSION.contains("causal-intervention-planner"));
    assert!(SCHEMA_VERSION.contains(".v1"));
    assert_eq!(MAX_NODES, 1000);
    assert_eq!(MAX_EDGES, 10_000);
}

// ---------------------------------------------------------------------------
// NodeKind
// ---------------------------------------------------------------------------

#[test]
fn node_kind_as_str_all_variants() {
    assert_eq!(NodeKind::Lever.as_str(), "lever");
    assert_eq!(NodeKind::Metric.as_str(), "metric");
    assert_eq!(NodeKind::Confounder.as_str(), "confounder");
    assert_eq!(NodeKind::Mediator.as_str(), "mediator");
    assert_eq!(NodeKind::Instrument.as_str(), "instrument");
}

#[test]
fn node_kind_display_matches_as_str() {
    for kind in [
        NodeKind::Lever,
        NodeKind::Metric,
        NodeKind::Confounder,
        NodeKind::Mediator,
        NodeKind::Instrument,
    ] {
        assert_eq!(format!("{kind}"), kind.as_str());
    }
}

#[test]
fn node_kind_serde_roundtrip_all() {
    for kind in [
        NodeKind::Lever,
        NodeKind::Metric,
        NodeKind::Confounder,
        NodeKind::Mediator,
        NodeKind::Instrument,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: NodeKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

#[test]
fn node_kind_ordering_deterministic() {
    let mut kinds = vec![
        NodeKind::Instrument,
        NodeKind::Lever,
        NodeKind::Mediator,
        NodeKind::Confounder,
        NodeKind::Metric,
    ];
    let mut kinds2 = kinds.clone();
    kinds.sort();
    kinds2.sort();
    assert_eq!(kinds, kinds2);
}

// ---------------------------------------------------------------------------
// EdgeKind
// ---------------------------------------------------------------------------

#[test]
fn edge_kind_as_str_all_variants() {
    assert_eq!(EdgeKind::Direct.as_str(), "direct");
    assert_eq!(EdgeKind::Confounding.as_str(), "confounding");
    assert_eq!(EdgeKind::Instrumental.as_str(), "instrumental");
    assert_eq!(EdgeKind::Mediated.as_str(), "mediated");
}

#[test]
fn edge_kind_display_matches_as_str() {
    for kind in [
        EdgeKind::Direct,
        EdgeKind::Confounding,
        EdgeKind::Instrumental,
        EdgeKind::Mediated,
    ] {
        assert_eq!(format!("{kind}"), kind.as_str());
    }
}

#[test]
fn edge_kind_serde_roundtrip_all() {
    for kind in [
        EdgeKind::Direct,
        EdgeKind::Confounding,
        EdgeKind::Instrumental,
        EdgeKind::Mediated,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: EdgeKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

// ---------------------------------------------------------------------------
// CausalNode serde
// ---------------------------------------------------------------------------

#[test]
fn causal_node_serde_roundtrip() {
    let node = lever("test_lever");
    let json = serde_json::to_string(&node).unwrap();
    let back: CausalNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, back);
}

// ---------------------------------------------------------------------------
// CausalEdge serde
// ---------------------------------------------------------------------------

#[test]
fn causal_edge_serde_roundtrip() {
    let edge = CausalEdge {
        from: "a".to_string(),
        to: "b".to_string(),
        kind: EdgeKind::Direct,
        effect_size_millionths: -150_000,
        confidence_millionths: 800_000,
    };
    let json = serde_json::to_string(&edge).unwrap();
    let back: CausalEdge = serde_json::from_str(&json).unwrap();
    assert_eq!(edge, back);
}

#[test]
fn causal_edge_negative_effect_preserved() {
    let edge = CausalEdge {
        from: "x".to_string(),
        to: "y".to_string(),
        kind: EdgeKind::Direct,
        effect_size_millionths: -500_000,
        confidence_millionths: 900_000,
    };
    let json = serde_json::to_string(&edge).unwrap();
    let back: CausalEdge = serde_json::from_str(&json).unwrap();
    assert_eq!(back.effect_size_millionths, -500_000);
}

// ---------------------------------------------------------------------------
// CausalDag construction
// ---------------------------------------------------------------------------

#[test]
fn empty_dag_has_zero_counts() {
    let dag = CausalDag::new();
    assert_eq!(dag.node_count(), 0);
    assert_eq!(dag.edge_count(), 0);
    assert!(dag.levers().is_empty());
    assert!(dag.metrics().is_empty());
    assert!(dag.confounders().is_empty());
}

#[test]
fn dag_default_equals_new() {
    let a = CausalDag::new();
    let b = CausalDag::default();
    assert_eq!(a.node_count(), b.node_count());
    assert_eq!(a.edge_count(), b.edge_count());
    assert_eq!(a.version, b.version);
}

#[test]
fn dag_add_nodes_increments_count() {
    let mut dag = CausalDag::new();
    dag.add_node(lever("l1")).unwrap();
    dag.add_node(metric("m1")).unwrap();
    dag.add_node(confounder("c1")).unwrap();
    assert_eq!(dag.node_count(), 3);
    assert_eq!(dag.levers().len(), 1);
    assert_eq!(dag.metrics().len(), 1);
    assert_eq!(dag.confounders().len(), 1);
}

#[test]
fn dag_duplicate_node_rejected() {
    let mut dag = CausalDag::new();
    dag.add_node(lever("l1")).unwrap();
    let err = dag.add_node(lever("l1")).unwrap_err();
    assert!(matches!(err, PlannerError::DuplicateNode { id } if id == "l1"));
}

#[test]
fn dag_add_edge_valid() {
    let mut dag = CausalDag::new();
    dag.add_node(lever("l1")).unwrap();
    dag.add_node(metric("m1")).unwrap();
    dag.add_edge(direct_edge("l1", "m1", 100_000)).unwrap();
    assert_eq!(dag.edge_count(), 1);
}

#[test]
fn dag_add_edge_missing_from_node() {
    let mut dag = CausalDag::new();
    dag.add_node(metric("m1")).unwrap();
    let err = dag
        .add_edge(direct_edge("nonexistent", "m1", 0))
        .unwrap_err();
    assert!(matches!(err, PlannerError::MissingNode { id } if id == "nonexistent"));
}

#[test]
fn dag_add_edge_missing_to_node() {
    let mut dag = CausalDag::new();
    dag.add_node(lever("l1")).unwrap();
    let err = dag
        .add_edge(direct_edge("l1", "nonexistent", 0))
        .unwrap_err();
    assert!(matches!(err, PlannerError::MissingNode { id } if id == "nonexistent"));
}

// ---------------------------------------------------------------------------
// Parents / Children
// ---------------------------------------------------------------------------

#[test]
fn parents_and_children_basic() {
    let mut dag = CausalDag::new();
    dag.add_node(lever("l1")).unwrap();
    dag.add_node(metric("m1")).unwrap();
    dag.add_edge(direct_edge("l1", "m1", 50_000)).unwrap();
    assert!(dag.parents("m1").contains("l1"));
    assert!(dag.children("l1").contains("m1"));
    assert!(dag.parents("l1").is_empty());
    assert!(dag.children("m1").is_empty());
}

#[test]
fn parents_multiple() {
    let mut dag = CausalDag::new();
    dag.add_node(lever("l1")).unwrap();
    dag.add_node(lever("l2")).unwrap();
    dag.add_node(metric("m1")).unwrap();
    dag.add_edge(direct_edge("l1", "m1", 50_000)).unwrap();
    dag.add_edge(direct_edge("l2", "m1", 30_000)).unwrap();
    let parents = dag.parents("m1");
    assert_eq!(parents.len(), 2);
    assert!(parents.contains("l1"));
    assert!(parents.contains("l2"));
}

#[test]
fn children_multiple() {
    let mut dag = CausalDag::new();
    dag.add_node(lever("l1")).unwrap();
    dag.add_node(metric("m1")).unwrap();
    dag.add_node(metric("m2")).unwrap();
    dag.add_edge(direct_edge("l1", "m1", 50_000)).unwrap();
    dag.add_edge(direct_edge("l1", "m2", 30_000)).unwrap();
    let children = dag.children("l1");
    assert_eq!(children.len(), 2);
}

// ---------------------------------------------------------------------------
// Adjustment set
// ---------------------------------------------------------------------------

#[test]
fn adjustment_set_no_confounders() {
    let mut dag = CausalDag::new();
    dag.add_node(lever("l1")).unwrap();
    dag.add_node(metric("m1")).unwrap();
    dag.add_edge(direct_edge("l1", "m1", 0)).unwrap();
    let adj = dag.adjustment_set("l1", "m1").unwrap();
    assert!(adj.is_empty());
}

#[test]
fn adjustment_set_with_confounder_parent() {
    let mut dag = CausalDag::new();
    dag.add_node(confounder("c1")).unwrap();
    dag.add_node(lever("l1")).unwrap();
    dag.add_node(metric("m1")).unwrap();
    dag.add_edge(direct_edge("c1", "l1", 0)).unwrap();
    dag.add_edge(direct_edge("l1", "m1", 50_000)).unwrap();
    let adj = dag.adjustment_set("l1", "m1").unwrap();
    assert!(adj.contains("c1"));
}

#[test]
fn adjustment_set_returns_none_for_missing_treatment() {
    let mut dag = CausalDag::new();
    dag.add_node(metric("m1")).unwrap();
    assert!(dag.adjustment_set("missing", "m1").is_none());
}

#[test]
fn adjustment_set_returns_none_for_missing_outcome() {
    let mut dag = CausalDag::new();
    dag.add_node(lever("l1")).unwrap();
    assert!(dag.adjustment_set("l1", "missing").is_none());
}

// ---------------------------------------------------------------------------
// Content hash determinism
// ---------------------------------------------------------------------------

#[test]
fn content_hash_deterministic_across_builds() {
    let d1 = build_seed_dag();
    let d2 = build_seed_dag();
    assert_eq!(d1.content_hash(), d2.content_hash());
}

#[test]
fn content_hash_changes_with_extra_node() {
    let d1 = build_seed_dag();
    let mut d2 = build_seed_dag();
    d2.add_node(lever("extra_lever")).unwrap();
    assert_ne!(d1.content_hash(), d2.content_hash());
}

#[test]
fn content_hash_changes_with_extra_edge() {
    let mut d1 = CausalDag::new();
    d1.add_node(lever("l1")).unwrap();
    d1.add_node(metric("m1")).unwrap();
    let mut d2 = d1.clone();
    d2.add_edge(direct_edge("l1", "m1", 100_000)).unwrap();
    assert_ne!(d1.content_hash(), d2.content_hash());
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn dag_serde_roundtrip_with_content_hash() {
    let dag = build_seed_dag();
    let json = serde_json::to_string(&dag).unwrap();
    let back: CausalDag = serde_json::from_str(&json).unwrap();
    assert_eq!(dag.node_count(), back.node_count());
    assert_eq!(dag.edge_count(), back.edge_count());
    assert_eq!(dag.content_hash(), back.content_hash());
}

#[test]
fn empty_dag_serde_roundtrip() {
    let dag = CausalDag::new();
    let json = serde_json::to_string(&dag).unwrap();
    let back: CausalDag = serde_json::from_str(&json).unwrap();
    assert_eq!(dag, back);
}

// ---------------------------------------------------------------------------
// Identifiability
// ---------------------------------------------------------------------------

#[test]
fn identifiability_is_identifiable_true_variants() {
    assert!(Identifiability::BackDoorIdentifiable.is_identifiable());
    assert!(Identifiability::FrontDoorIdentifiable.is_identifiable());
    assert!(Identifiability::InstrumentalOnly.is_identifiable());
}

#[test]
fn identifiability_is_identifiable_false_variants() {
    assert!(!Identifiability::NotIdentifiable.is_identifiable());
    assert!(!Identifiability::Undetermined.is_identifiable());
}

#[test]
fn identifiability_as_str_all() {
    assert_eq!(
        Identifiability::BackDoorIdentifiable.as_str(),
        "back_door_identifiable"
    );
    assert_eq!(
        Identifiability::FrontDoorIdentifiable.as_str(),
        "front_door_identifiable"
    );
    assert_eq!(
        Identifiability::InstrumentalOnly.as_str(),
        "instrumental_only"
    );
    assert_eq!(
        Identifiability::NotIdentifiable.as_str(),
        "not_identifiable"
    );
    assert_eq!(Identifiability::Undetermined.as_str(), "undetermined");
}

#[test]
fn identifiability_display_matches_as_str() {
    for id in [
        Identifiability::BackDoorIdentifiable,
        Identifiability::FrontDoorIdentifiable,
        Identifiability::InstrumentalOnly,
        Identifiability::NotIdentifiable,
        Identifiability::Undetermined,
    ] {
        assert_eq!(format!("{id}"), id.as_str());
    }
}

#[test]
fn identifiability_serde_roundtrip_all() {
    for id in [
        Identifiability::BackDoorIdentifiable,
        Identifiability::FrontDoorIdentifiable,
        Identifiability::InstrumentalOnly,
        Identifiability::NotIdentifiable,
        Identifiability::Undetermined,
    ] {
        let json = serde_json::to_string(&id).unwrap();
        let back: Identifiability = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }
}

// ---------------------------------------------------------------------------
// InterventionPriority
// ---------------------------------------------------------------------------

#[test]
fn priority_as_str_all() {
    assert_eq!(InterventionPriority::Critical.as_str(), "critical");
    assert_eq!(InterventionPriority::High.as_str(), "high");
    assert_eq!(InterventionPriority::Medium.as_str(), "medium");
    assert_eq!(InterventionPriority::Low.as_str(), "low");
    assert_eq!(InterventionPriority::Deferred.as_str(), "deferred");
}

#[test]
fn priority_display_matches_as_str() {
    for p in [
        InterventionPriority::Critical,
        InterventionPriority::High,
        InterventionPriority::Medium,
        InterventionPriority::Low,
        InterventionPriority::Deferred,
    ] {
        assert_eq!(format!("{p}"), p.as_str());
    }
}

#[test]
fn priority_serde_roundtrip_all() {
    for p in [
        InterventionPriority::Critical,
        InterventionPriority::High,
        InterventionPriority::Medium,
        InterventionPriority::Low,
        InterventionPriority::Deferred,
    ] {
        let json = serde_json::to_string(&p).unwrap();
        let back: InterventionPriority = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }
}

// ---------------------------------------------------------------------------
// IdentifiabilityCertificate
// ---------------------------------------------------------------------------

#[test]
fn identifiability_certificate_serde_roundtrip() {
    let cert = IdentifiabilityCertificate {
        treatment: "lever_a".to_string(),
        outcome: "metric_x".to_string(),
        status: Identifiability::BackDoorIdentifiable,
        adjustment_set: Some(BTreeSet::from(["c1".to_string(), "c2".to_string()])),
        rationale: "Back-door criterion satisfied".to_string(),
    };
    let json = serde_json::to_string(&cert).unwrap();
    let back: IdentifiabilityCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

// ---------------------------------------------------------------------------
// InterventionPlan
// ---------------------------------------------------------------------------

#[test]
fn intervention_plan_serde_roundtrip() {
    let plan = InterventionPlan {
        id: "plan_l1_m1".to_string(),
        lever_id: "l1".to_string(),
        target_metric_id: "m1".to_string(),
        priority: InterventionPriority::High,
        expected_effect_millionths: 150_000,
        confidence_millionths: 800_000,
        identifiability: Identifiability::BackDoorIdentifiable,
        adjustment_set: BTreeSet::new(),
        risk_description: "low risk".to_string(),
        cost_description: "low cost".to_string(),
        tracking_bead: Some("bd-test".to_string()),
    };
    let json = serde_json::to_string(&plan).unwrap();
    let back: InterventionPlan = serde_json::from_str(&json).unwrap();
    assert_eq!(plan, back);
}

// ---------------------------------------------------------------------------
// Seed DAG
// ---------------------------------------------------------------------------

#[test]
fn seed_dag_has_expected_structure() {
    let dag = build_seed_dag();
    assert_eq!(dag.levers().len(), 3);
    assert_eq!(dag.metrics().len(), 3);
    assert_eq!(dag.confounders().len(), 1);
    assert_eq!(dag.edge_count(), 7);
    assert_eq!(dag.version, SCHEMA_VERSION);
}

#[test]
fn seed_dag_lever_ids() {
    let dag = build_seed_dag();
    let ids: BTreeSet<String> = dag.levers().iter().map(|n| n.id.clone()).collect();
    assert!(ids.contains("inline_cache"));
    assert!(ids.contains("gc_tuning"));
    assert!(ids.contains("tier_up_threshold"));
}

#[test]
fn seed_dag_metric_ids() {
    let dag = build_seed_dag();
    let ids: BTreeSet<String> = dag.metrics().iter().map(|n| n.id.clone()).collect();
    assert!(ids.contains("p99_latency"));
    assert!(ids.contains("throughput"));
    assert!(ids.contains("memory_footprint"));
}

// ---------------------------------------------------------------------------
// Planner
// ---------------------------------------------------------------------------

#[test]
fn planner_default_equals_new() {
    let a = CausalInterventionPlanner::new();
    let b = CausalInterventionPlanner;
    let dag = CausalDag::new();
    let ra = a.analyze(&dag);
    let rb = b.analyze(&dag);
    assert_eq!(ra.node_count, rb.node_count);
}

#[test]
fn planner_empty_dag_produces_empty_report() {
    let planner = CausalInterventionPlanner::new();
    let dag = CausalDag::new();
    let report = planner.analyze(&dag);
    assert_eq!(report.lever_count, 0);
    assert_eq!(report.metric_count, 0);
    assert_eq!(report.confounder_count, 0);
    assert!(report.certificates.is_empty());
    assert!(report.intervention_plans.is_empty());
}

#[test]
fn planner_seed_dag_all_identifiable() {
    let planner = CausalInterventionPlanner::new();
    let dag = build_seed_dag();
    let report = planner.analyze(&dag);
    assert_eq!(report.identifiable_count, 9); // 3 levers * 3 metrics
    assert_eq!(report.not_identifiable_count, 0);
}

#[test]
fn planner_report_has_correct_counts() {
    let planner = CausalInterventionPlanner::new();
    let dag = build_seed_dag();
    let report = planner.analyze(&dag);
    assert_eq!(report.lever_count, 3);
    assert_eq!(report.metric_count, 3);
    assert_eq!(report.confounder_count, 1);
    assert_eq!(report.node_count, dag.node_count());
    assert_eq!(report.edge_count, dag.edge_count());
}

#[test]
fn planner_report_schema_version() {
    let planner = CausalInterventionPlanner::new();
    let dag = build_seed_dag();
    let report = planner.analyze(&dag);
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.bead_id, BEAD_ID);
    assert_eq!(report.component, COMPONENT);
}

#[test]
fn planner_report_has_intervention_plans() {
    let planner = CausalInterventionPlanner::new();
    let dag = build_seed_dag();
    let report = planner.analyze(&dag);
    assert!(!report.intervention_plans.is_empty());
    // All plans should be identifiable
    for plan in &report.intervention_plans {
        assert!(plan.identifiability.is_identifiable());
    }
}

#[test]
fn planner_report_plans_sorted_by_priority() {
    let planner = CausalInterventionPlanner::new();
    let dag = build_seed_dag();
    let report = planner.analyze(&dag);
    for window in report.intervention_plans.windows(2) {
        assert!(window[0].priority <= window[1].priority);
    }
}

#[test]
fn planner_priority_assignment_critical() {
    // effect > 200_000 => Critical
    let mut dag = CausalDag::new();
    dag.add_node(lever("l1")).unwrap();
    dag.add_node(metric("m1")).unwrap();
    dag.add_edge(direct_edge("l1", "m1", 250_000)).unwrap();
    let planner = CausalInterventionPlanner::new();
    let report = planner.analyze(&dag);
    assert_eq!(
        report.intervention_plans[0].priority,
        InterventionPriority::Critical
    );
}

#[test]
fn planner_priority_assignment_high() {
    // effect > 100_000 but <= 200_000 => High
    let mut dag = CausalDag::new();
    dag.add_node(lever("l1")).unwrap();
    dag.add_node(metric("m1")).unwrap();
    dag.add_edge(direct_edge("l1", "m1", 150_000)).unwrap();
    let planner = CausalInterventionPlanner::new();
    let report = planner.analyze(&dag);
    assert_eq!(
        report.intervention_plans[0].priority,
        InterventionPriority::High
    );
}

#[test]
fn planner_priority_assignment_deferred_for_zero_effect() {
    // No direct edge => effect=0 => Deferred
    let mut dag = CausalDag::new();
    dag.add_node(lever("l1")).unwrap();
    dag.add_node(metric("m1")).unwrap();
    let planner = CausalInterventionPlanner::new();
    let report = planner.analyze(&dag);
    assert_eq!(
        report.intervention_plans[0].priority,
        InterventionPriority::Deferred
    );
}

#[test]
fn planner_report_serde_roundtrip() {
    let planner = CausalInterventionPlanner::new();
    let dag = build_seed_dag();
    let report = planner.analyze(&dag);
    let json = serde_json::to_string(&report).unwrap();
    let back: PlannerReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report.lever_count, back.lever_count);
    assert_eq!(report.metric_count, back.metric_count);
    assert_eq!(report.identifiable_count, back.identifiable_count);
    assert_eq!(report.dag_hash, back.dag_hash);
}

#[test]
fn planner_report_dag_hash_matches() {
    let planner = CausalInterventionPlanner::new();
    let dag = build_seed_dag();
    let report = planner.analyze(&dag);
    assert_eq!(report.dag_hash, dag.content_hash());
}

// ---------------------------------------------------------------------------
// PlannerError
// ---------------------------------------------------------------------------

#[test]
fn error_display_duplicate_node() {
    let e = PlannerError::DuplicateNode {
        id: "test_node".to_string(),
    };
    let msg = format!("{e}");
    assert!(msg.contains("test_node"));
    assert!(msg.contains("duplicate"));
}

#[test]
fn error_display_missing_node() {
    let e = PlannerError::MissingNode {
        id: "missing_node".to_string(),
    };
    let msg = format!("{e}");
    assert!(msg.contains("missing_node"));
    assert!(msg.contains("missing"));
}

#[test]
fn error_display_node_overflow() {
    let e = PlannerError::NodeOverflow {
        max: 1000,
        attempted: 1001,
    };
    let msg = format!("{e}");
    assert!(msg.contains("1001"));
    assert!(msg.contains("1000"));
}

#[test]
fn error_display_edge_overflow() {
    let e = PlannerError::EdgeOverflow {
        max: 10_000,
        attempted: 10_001,
    };
    let msg = format!("{e}");
    assert!(msg.contains("10001"));
    assert!(msg.contains("10000"));
}

#[test]
fn error_serde_roundtrip() {
    let e = PlannerError::DuplicateNode {
        id: "foo".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: PlannerError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// Complex DAG scenarios
// ---------------------------------------------------------------------------

#[test]
fn dag_with_confounder_parent_on_treatment() {
    let mut dag = CausalDag::new();
    dag.add_node(confounder("c")).unwrap();
    dag.add_node(lever("l")).unwrap();
    dag.add_node(metric("m")).unwrap();
    dag.add_edge(direct_edge("c", "l", 0)).unwrap();
    dag.add_edge(confounding_edge("c", "m")).unwrap();
    dag.add_edge(direct_edge("l", "m", 100_000)).unwrap();
    let adj = dag.adjustment_set("l", "m").unwrap();
    assert!(adj.contains("c"));
}

#[test]
fn dag_confounding_edges_not_counted_as_parents() {
    let mut dag = CausalDag::new();
    dag.add_node(confounder("c")).unwrap();
    dag.add_node(lever("l")).unwrap();
    dag.add_node(metric("m")).unwrap();
    // Confounding edge, not direct
    dag.add_edge(confounding_edge("c", "l")).unwrap();
    dag.add_edge(direct_edge("l", "m", 100_000)).unwrap();
    // parents() only considers Direct edges
    let parents = dag.parents("l");
    assert!(parents.is_empty());
}
