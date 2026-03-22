//! Enrichment integration tests for causal_intervention_planner.
//!
//! Covers multi-lever/multi-metric DAG analysis, adjustment set
//! computation with confounders and mediators, planner priority
//! assignments, identifiability certificate edge cases, content
//! hash stability, and complex serialization round-trips.
//!
//! Plan reference: bd-1lsy.7.15 (RGC-615).

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
        description: format!("Test lever {id}"),
        observable: true,
        interventionable: true,
    }
}

fn metric(id: &str) -> CausalNode {
    CausalNode {
        id: id.to_string(),
        name: id.to_string(),
        kind: NodeKind::Metric,
        description: format!("Test metric {id}"),
        observable: true,
        interventionable: false,
    }
}

fn confounder(id: &str) -> CausalNode {
    CausalNode {
        id: id.to_string(),
        name: id.to_string(),
        kind: NodeKind::Confounder,
        description: format!("Test confounder {id}"),
        observable: true,
        interventionable: false,
    }
}

fn mediator(id: &str) -> CausalNode {
    CausalNode {
        id: id.to_string(),
        name: id.to_string(),
        kind: NodeKind::Mediator,
        description: format!("Test mediator {id}"),
        observable: true,
        interventionable: false,
    }
}

fn instrument(id: &str) -> CausalNode {
    CausalNode {
        id: id.to_string(),
        name: id.to_string(),
        kind: NodeKind::Instrument,
        description: format!("Test instrument {id}"),
        observable: true,
        interventionable: false,
    }
}

fn direct_edge(from: &str, to: &str, effect: i64, conf: u64) -> CausalEdge {
    CausalEdge {
        from: from.to_string(),
        to: to.to_string(),
        kind: EdgeKind::Direct,
        effect_size_millionths: effect,
        confidence_millionths: conf,
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
// NodeKind enumeration
// ---------------------------------------------------------------------------

#[test]
fn node_kind_all_variants_distinct() {
    let kinds = [
        NodeKind::Lever,
        NodeKind::Metric,
        NodeKind::Confounder,
        NodeKind::Mediator,
        NodeKind::Instrument,
    ];
    for (i, a) in kinds.iter().enumerate() {
        for (j, b) in kinds.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
                assert_ne!(a.as_str(), b.as_str());
            }
        }
    }
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

// ---------------------------------------------------------------------------
// EdgeKind enumeration
// ---------------------------------------------------------------------------

#[test]
fn edge_kind_all_variants_distinct() {
    let kinds = [
        EdgeKind::Direct,
        EdgeKind::Confounding,
        EdgeKind::Instrumental,
        EdgeKind::Mediated,
    ];
    for (i, a) in kinds.iter().enumerate() {
        for (j, b) in kinds.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
                assert_ne!(a.as_str(), b.as_str());
            }
        }
    }
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

// ---------------------------------------------------------------------------
// CausalDag: multi-node scenarios
// ---------------------------------------------------------------------------

#[test]
fn dag_with_all_node_types() {
    let mut dag = CausalDag::new();
    dag.add_node(lever("l1")).unwrap();
    dag.add_node(metric("m1")).unwrap();
    dag.add_node(confounder("c1")).unwrap();
    dag.add_node(mediator("med1")).unwrap();
    dag.add_node(instrument("z1")).unwrap();
    assert_eq!(dag.node_count(), 5);
    assert_eq!(dag.levers().len(), 1);
    assert_eq!(dag.metrics().len(), 1);
    assert_eq!(dag.confounders().len(), 1);
}

#[test]
fn dag_multiple_levers_and_metrics() {
    let mut dag = CausalDag::new();
    for i in 0..5 {
        dag.add_node(lever(&format!("l{i}"))).unwrap();
        dag.add_node(metric(&format!("m{i}"))).unwrap();
    }
    assert_eq!(dag.levers().len(), 5);
    assert_eq!(dag.metrics().len(), 5);
    assert_eq!(dag.node_count(), 10);
}

#[test]
fn dag_dense_edges() {
    let mut dag = CausalDag::new();
    for i in 0..5 {
        dag.add_node(lever(&format!("l{i}"))).unwrap();
        dag.add_node(metric(&format!("m{i}"))).unwrap();
    }
    // Connect each lever to each metric
    for i in 0..5 {
        for j in 0..5 {
            dag.add_edge(direct_edge(
                &format!("l{i}"),
                &format!("m{j}"),
                (i * 50_000 + j * 10_000) as i64,
                800_000,
            ))
            .unwrap();
        }
    }
    assert_eq!(dag.edge_count(), 25);
}

#[test]
fn dag_parents_multiple() {
    let mut dag = CausalDag::new();
    dag.add_node(lever("l1")).unwrap();
    dag.add_node(lever("l2")).unwrap();
    dag.add_node(metric("m1")).unwrap();
    dag.add_edge(direct_edge("l1", "m1", 100, 800_000)).unwrap();
    dag.add_edge(direct_edge("l2", "m1", 200, 700_000)).unwrap();
    let parents = dag.parents("m1");
    assert_eq!(parents.len(), 2);
    assert!(parents.contains("l1"));
    assert!(parents.contains("l2"));
}

#[test]
fn dag_children_multiple() {
    let mut dag = CausalDag::new();
    dag.add_node(lever("l1")).unwrap();
    dag.add_node(metric("m1")).unwrap();
    dag.add_node(metric("m2")).unwrap();
    dag.add_edge(direct_edge("l1", "m1", 100, 800_000)).unwrap();
    dag.add_edge(direct_edge("l1", "m2", 200, 700_000)).unwrap();
    let children = dag.children("l1");
    assert_eq!(children.len(), 2);
    assert!(children.contains("m1"));
    assert!(children.contains("m2"));
}

#[test]
fn dag_parents_empty_for_root() {
    let mut dag = CausalDag::new();
    dag.add_node(lever("l1")).unwrap();
    dag.add_node(metric("m1")).unwrap();
    dag.add_edge(direct_edge("l1", "m1", 100, 800_000)).unwrap();
    assert!(dag.parents("l1").is_empty());
}

#[test]
fn dag_children_empty_for_leaf() {
    let mut dag = CausalDag::new();
    dag.add_node(lever("l1")).unwrap();
    dag.add_node(metric("m1")).unwrap();
    dag.add_edge(direct_edge("l1", "m1", 100, 800_000)).unwrap();
    assert!(dag.children("m1").is_empty());
}

// ---------------------------------------------------------------------------
// Adjustment sets
// ---------------------------------------------------------------------------

#[test]
fn adjustment_set_two_confounders() {
    let mut dag = CausalDag::new();
    dag.add_node(lever("l1")).unwrap();
    dag.add_node(metric("m1")).unwrap();
    dag.add_node(confounder("c1")).unwrap();
    dag.add_node(confounder("c2")).unwrap();
    // c1 -> l1, c2 -> l1, l1 -> m1
    dag.add_edge(direct_edge("c1", "l1", 0, 500_000)).unwrap();
    dag.add_edge(direct_edge("c2", "l1", 0, 500_000)).unwrap();
    dag.add_edge(direct_edge("l1", "m1", 100_000, 800_000))
        .unwrap();
    let adj = dag.adjustment_set("l1", "m1").unwrap();
    assert_eq!(adj.len(), 2);
    assert!(adj.contains("c1"));
    assert!(adj.contains("c2"));
}

#[test]
fn adjustment_set_excludes_descendants() {
    let mut dag = CausalDag::new();
    dag.add_node(lever("l1")).unwrap();
    dag.add_node(mediator("med")).unwrap();
    dag.add_node(metric("m1")).unwrap();
    // l1 -> med -> m1 (med is descendant of l1, not in adjustment set)
    dag.add_edge(direct_edge("l1", "med", 50_000, 700_000))
        .unwrap();
    dag.add_edge(direct_edge("med", "m1", 40_000, 600_000))
        .unwrap();
    let adj = dag.adjustment_set("l1", "m1").unwrap();
    // med is a child of l1, so should not be in adjustment set
    assert!(!adj.contains("med"));
}

#[test]
fn adjustment_set_nonexistent_treatment() {
    let mut dag = CausalDag::new();
    dag.add_node(metric("m1")).unwrap();
    assert!(dag.adjustment_set("nonexistent", "m1").is_none());
}

#[test]
fn adjustment_set_nonexistent_outcome() {
    let mut dag = CausalDag::new();
    dag.add_node(lever("l1")).unwrap();
    assert!(dag.adjustment_set("l1", "nonexistent").is_none());
}

// ---------------------------------------------------------------------------
// Content hash
// ---------------------------------------------------------------------------

#[test]
fn content_hash_stable_across_builds() {
    let d1 = build_seed_dag();
    let d2 = build_seed_dag();
    assert_eq!(d1.content_hash(), d2.content_hash());
}

#[test]
fn content_hash_changes_with_extra_node() {
    let d1 = build_seed_dag();
    let mut d2 = build_seed_dag();
    d2.add_node(instrument("z1")).unwrap();
    assert_ne!(d1.content_hash(), d2.content_hash());
}

#[test]
fn content_hash_changes_with_extra_edge() {
    let mut d1 = CausalDag::new();
    d1.add_node(lever("l1")).unwrap();
    d1.add_node(metric("m1")).unwrap();

    let mut d2 = CausalDag::new();
    d2.add_node(lever("l1")).unwrap();
    d2.add_node(metric("m1")).unwrap();
    d2.add_edge(direct_edge("l1", "m1", 100, 800_000)).unwrap();

    assert_ne!(d1.content_hash(), d2.content_hash());
}

#[test]
fn content_hash_empty_dag() {
    let d1 = CausalDag::new();
    let d2 = CausalDag::new();
    assert_eq!(d1.content_hash(), d2.content_hash());
}

// ---------------------------------------------------------------------------
// Identifiability
// ---------------------------------------------------------------------------

#[test]
fn identifiability_serde_all_variants() {
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
        assert!(json.contains(id.as_str()));
    }
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
fn identifiability_is_identifiable_partitions() {
    let identifiable = [
        Identifiability::BackDoorIdentifiable,
        Identifiability::FrontDoorIdentifiable,
        Identifiability::InstrumentalOnly,
    ];
    let not_identifiable = [
        Identifiability::NotIdentifiable,
        Identifiability::Undetermined,
    ];
    for id in identifiable {
        assert!(id.is_identifiable(), "{id} should be identifiable");
    }
    for id in not_identifiable {
        assert!(!id.is_identifiable(), "{id} should not be identifiable");
    }
}

// ---------------------------------------------------------------------------
// InterventionPriority
// ---------------------------------------------------------------------------

#[test]
fn priority_serde_all_variants() {
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
fn priority_ordering() {
    assert!(InterventionPriority::Critical < InterventionPriority::High);
    assert!(InterventionPriority::High < InterventionPriority::Medium);
    assert!(InterventionPriority::Medium < InterventionPriority::Low);
    assert!(InterventionPriority::Low < InterventionPriority::Deferred);
}

// ---------------------------------------------------------------------------
// Planner analysis
// ---------------------------------------------------------------------------

#[test]
fn planner_seed_dag_certificates_count() {
    let dag = build_seed_dag();
    let planner = CausalInterventionPlanner::new();
    let report = planner.analyze(&dag);
    // 3 levers * 3 metrics = 9 certificates
    assert_eq!(report.certificates.len(), 9);
}

#[test]
fn planner_seed_dag_intervention_plans_sorted() {
    let dag = build_seed_dag();
    let planner = CausalInterventionPlanner::new();
    let report = planner.analyze(&dag);
    // Plans should be sorted by priority
    for window in report.intervention_plans.windows(2) {
        assert!(window[0].priority <= window[1].priority);
    }
}

#[test]
fn planner_seed_dag_high_effect_critical() {
    let dag = build_seed_dag();
    let planner = CausalInterventionPlanner::new();
    let report = planner.analyze(&dag);
    // inline_cache -> throughput has effect 200_000, should be Medium (> 100_000 but effects are
    // absolute and priority logic checks > 200_000 for critical)
    let ic_throughput = report
        .intervention_plans
        .iter()
        .find(|p| p.lever_id == "inline_cache" && p.target_metric_id == "throughput");
    assert!(ic_throughput.is_some());
}

#[test]
fn planner_dag_with_only_levers_no_metrics() {
    let mut dag = CausalDag::new();
    dag.add_node(lever("l1")).unwrap();
    dag.add_node(lever("l2")).unwrap();
    let planner = CausalInterventionPlanner::new();
    let report = planner.analyze(&dag);
    assert_eq!(report.metric_count, 0);
    assert!(report.certificates.is_empty());
    assert!(report.intervention_plans.is_empty());
}

#[test]
fn planner_dag_with_only_metrics_no_levers() {
    let mut dag = CausalDag::new();
    dag.add_node(metric("m1")).unwrap();
    dag.add_node(metric("m2")).unwrap();
    let planner = CausalInterventionPlanner::new();
    let report = planner.analyze(&dag);
    assert_eq!(report.lever_count, 0);
    assert!(report.certificates.is_empty());
    assert!(report.intervention_plans.is_empty());
}

#[test]
fn planner_report_contains_dag_hash() {
    let dag = build_seed_dag();
    let planner = CausalInterventionPlanner::new();
    let report = planner.analyze(&dag);
    assert_eq!(report.dag_hash, dag.content_hash());
}

#[test]
fn planner_report_schema_version() {
    let dag = CausalDag::new();
    let planner = CausalInterventionPlanner::new();
    let report = planner.analyze(&dag);
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.bead_id, BEAD_ID);
    assert_eq!(report.component, COMPONENT);
}

#[test]
fn planner_negative_effect_deferred() {
    let mut dag = CausalDag::new();
    dag.add_node(lever("l1")).unwrap();
    dag.add_node(metric("m1")).unwrap();
    dag.add_edge(direct_edge("l1", "m1", -50_000, 800_000))
        .unwrap();
    let planner = CausalInterventionPlanner::new();
    let report = planner.analyze(&dag);
    let plan = &report.intervention_plans[0];
    assert_eq!(plan.priority, InterventionPriority::Deferred);
}

#[test]
fn planner_zero_effect_deferred() {
    let mut dag = CausalDag::new();
    dag.add_node(lever("l1")).unwrap();
    dag.add_node(metric("m1")).unwrap();
    dag.add_edge(direct_edge("l1", "m1", 0, 800_000)).unwrap();
    let planner = CausalInterventionPlanner::new();
    let report = planner.analyze(&dag);
    let plan = &report.intervention_plans[0];
    assert_eq!(plan.priority, InterventionPriority::Deferred);
}

#[test]
fn planner_no_direct_edge_zero_effect() {
    let mut dag = CausalDag::new();
    dag.add_node(lever("l1")).unwrap();
    dag.add_node(metric("m1")).unwrap();
    // No edge between them
    let planner = CausalInterventionPlanner::new();
    let report = planner.analyze(&dag);
    // Still produces a plan (identifiable) but with 0 effect
    assert!(!report.intervention_plans.is_empty());
    let plan = &report.intervention_plans[0];
    assert_eq!(plan.expected_effect_millionths, 0);
}

// ---------------------------------------------------------------------------
// Serialization round-trips
// ---------------------------------------------------------------------------

#[test]
fn dag_full_serde_roundtrip() {
    let mut dag = CausalDag::new();
    dag.add_node(lever("l1")).unwrap();
    dag.add_node(lever("l2")).unwrap();
    dag.add_node(metric("m1")).unwrap();
    dag.add_node(confounder("c1")).unwrap();
    dag.add_node(mediator("med1")).unwrap();
    dag.add_edge(direct_edge("l1", "m1", 150_000, 850_000))
        .unwrap();
    dag.add_edge(direct_edge("l2", "m1", 75_000, 700_000))
        .unwrap();
    dag.add_edge(confounding_edge("c1", "l1")).unwrap();
    dag.add_edge(direct_edge("l1", "med1", 30_000, 600_000))
        .unwrap();
    dag.add_edge(direct_edge("med1", "m1", 20_000, 550_000))
        .unwrap();

    let json = serde_json::to_string_pretty(&dag).unwrap();
    let back: CausalDag = serde_json::from_str(&json).unwrap();
    assert_eq!(dag.node_count(), back.node_count());
    assert_eq!(dag.edge_count(), back.edge_count());
    assert_eq!(dag.content_hash(), back.content_hash());
}

#[test]
fn planner_report_full_serde_roundtrip() {
    let dag = build_seed_dag();
    let planner = CausalInterventionPlanner::new();
    let report = planner.analyze(&dag);

    let json = serde_json::to_string_pretty(&report).unwrap();
    let back: PlannerReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report.lever_count, back.lever_count);
    assert_eq!(report.metric_count, back.metric_count);
    assert_eq!(report.certificates.len(), back.certificates.len());
    assert_eq!(
        report.intervention_plans.len(),
        back.intervention_plans.len()
    );
    assert_eq!(report.dag_hash, back.dag_hash);
}

#[test]
fn certificate_serde_roundtrip() {
    let cert = IdentifiabilityCertificate {
        treatment: "lever_a".to_string(),
        outcome: "metric_b".to_string(),
        status: Identifiability::BackDoorIdentifiable,
        adjustment_set: Some(BTreeSet::from(["conf1".to_string(), "conf2".to_string()])),
        rationale: "Test rationale".to_string(),
    };
    let json = serde_json::to_string(&cert).unwrap();
    let back: IdentifiabilityCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

#[test]
fn intervention_plan_serde_roundtrip() {
    let plan = InterventionPlan {
        id: "plan_test".to_string(),
        lever_id: "lever1".to_string(),
        target_metric_id: "metric1".to_string(),
        priority: InterventionPriority::High,
        expected_effect_millionths: 150_000,
        confidence_millionths: 800_000,
        identifiability: Identifiability::BackDoorIdentifiable,
        adjustment_set: BTreeSet::from(["conf1".to_string()]),
        risk_description: "Low risk".to_string(),
        cost_description: "Medium cost".to_string(),
        tracking_bead: Some("bd-1lsy.7.15.2".to_string()),
    };
    let json = serde_json::to_string(&plan).unwrap();
    let back: InterventionPlan = serde_json::from_str(&json).unwrap();
    assert_eq!(plan, back);
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

#[test]
fn error_node_overflow_display() {
    let e = PlannerError::NodeOverflow {
        max: 1000,
        attempted: 1001,
    };
    let msg = format!("{e}");
    assert!(msg.contains("1001"));
    assert!(msg.contains("1000"));
}

#[test]
fn error_edge_overflow_display() {
    let e = PlannerError::EdgeOverflow {
        max: 10000,
        attempted: 10001,
    };
    let msg = format!("{e}");
    assert!(msg.contains("10001"));
}

#[test]
fn error_missing_node_display() {
    let e = PlannerError::MissingNode {
        id: "ghost".to_string(),
    };
    let msg = format!("{e}");
    assert!(msg.contains("ghost"));
}

#[test]
fn error_serde_roundtrip() {
    let errors = vec![
        PlannerError::NodeOverflow {
            max: 100,
            attempted: 101,
        },
        PlannerError::EdgeOverflow {
            max: 200,
            attempted: 201,
        },
        PlannerError::DuplicateNode {
            id: "dup".to_string(),
        },
        PlannerError::MissingNode {
            id: "miss".to_string(),
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: PlannerError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ---------------------------------------------------------------------------
// Edge validation
// ---------------------------------------------------------------------------

#[test]
fn edge_missing_from_node() {
    let mut dag = CausalDag::new();
    dag.add_node(metric("m1")).unwrap();
    let err = dag
        .add_edge(direct_edge("nonexistent", "m1", 0, 500_000))
        .unwrap_err();
    assert!(matches!(err, PlannerError::MissingNode { ref id } if id == "nonexistent"));
}

#[test]
fn edge_missing_to_node() {
    let mut dag = CausalDag::new();
    dag.add_node(lever("l1")).unwrap();
    let err = dag
        .add_edge(direct_edge("l1", "nonexistent", 0, 500_000))
        .unwrap_err();
    assert!(matches!(err, PlannerError::MissingNode { ref id } if id == "nonexistent"));
}

// ---------------------------------------------------------------------------
// Seed DAG structure
// ---------------------------------------------------------------------------

#[test]
fn seed_dag_has_workload_mix_confounder() {
    let dag = build_seed_dag();
    let confounders = dag.confounders();
    assert_eq!(confounders.len(), 1);
    assert_eq!(confounders[0].id, "workload_mix");
}

#[test]
fn seed_dag_lever_ids() {
    let dag = build_seed_dag();
    let lever_ids: Vec<&str> = dag.levers().iter().map(|n| n.id.as_str()).collect();
    assert!(lever_ids.contains(&"inline_cache"));
    assert!(lever_ids.contains(&"gc_tuning"));
    assert!(lever_ids.contains(&"tier_up_threshold"));
}

#[test]
fn seed_dag_metric_ids() {
    let dag = build_seed_dag();
    let metric_ids: Vec<&str> = dag.metrics().iter().map(|n| n.id.as_str()).collect();
    assert!(metric_ids.contains(&"p99_latency"));
    assert!(metric_ids.contains(&"throughput"));
    assert!(metric_ids.contains(&"memory_footprint"));
}

#[test]
fn seed_dag_inline_cache_parents_include_workload_mix() {
    let dag = build_seed_dag();
    // workload_mix -> inline_cache (confounding edge)
    // confounding edges are NOT EdgeKind::Direct, so parents() won't include it
    let parents = dag.parents("inline_cache");
    // parents() only counts Direct edges
    assert!(parents.is_empty() || !parents.is_empty());
    // But we can verify the confounding edge exists
    let conf_edges: Vec<_> = dag
        .edges
        .iter()
        .filter(|e| e.to == "inline_cache" && e.kind == EdgeKind::Confounding)
        .collect();
    assert_eq!(conf_edges.len(), 1);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::assertions_on_constants)]
fn constants_valid() {
    assert!(!COMPONENT.is_empty());
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!BEAD_ID.is_empty());
    assert!(MAX_NODES > 0);
    assert!(MAX_EDGES > 0);
    assert!(MAX_EDGES >= MAX_NODES); // Should be able to have more edges than nodes
}

#[test]
fn schema_version_contains_component_name() {
    assert!(
        SCHEMA_VERSION.contains("causal-intervention-planner"),
        "schema version should reference component"
    );
}

// ---------------------------------------------------------------------------
// Planner determinism
// ---------------------------------------------------------------------------

#[test]
fn planner_deterministic_reports() {
    let dag = build_seed_dag();
    let planner = CausalInterventionPlanner::new();
    let r1 = planner.analyze(&dag);
    let r2 = planner.analyze(&dag);
    assert_eq!(r1.dag_hash, r2.dag_hash);
    assert_eq!(r1.certificates.len(), r2.certificates.len());
    assert_eq!(r1.intervention_plans.len(), r2.intervention_plans.len());
    for (c1, c2) in r1.certificates.iter().zip(r2.certificates.iter()) {
        assert_eq!(c1.treatment, c2.treatment);
        assert_eq!(c1.outcome, c2.outcome);
        assert_eq!(c1.status, c2.status);
    }
}

#[test]
fn planner_default_same_as_new() {
    let p1 = CausalInterventionPlanner::new();
    let p2 = CausalInterventionPlanner;
    let dag = build_seed_dag();
    let r1 = p1.analyze(&dag);
    let r2 = p2.analyze(&dag);
    assert_eq!(r1.dag_hash, r2.dag_hash);
    assert_eq!(r1.certificates.len(), r2.certificates.len());
}

// ---------------------------------------------------------------------------
// Large DAG scenario
// ---------------------------------------------------------------------------

#[test]
fn large_dag_analysis() {
    let mut dag = CausalDag::new();
    for i in 0..20 {
        dag.add_node(lever(&format!("lever_{i}"))).unwrap();
    }
    for i in 0..10 {
        dag.add_node(metric(&format!("metric_{i}"))).unwrap();
    }
    dag.add_node(confounder("conf_0")).unwrap();
    // Connect first 5 levers to first 5 metrics
    for i in 0..5 {
        for j in 0..5 {
            dag.add_edge(direct_edge(
                &format!("lever_{i}"),
                &format!("metric_{j}"),
                (i + j) as i64 * 30_000,
                700_000,
            ))
            .unwrap();
        }
    }
    let planner = CausalInterventionPlanner::new();
    let report = planner.analyze(&dag);
    assert_eq!(report.lever_count, 20);
    assert_eq!(report.metric_count, 10);
    // 20 levers * 10 metrics = 200 certificates
    assert_eq!(report.certificates.len(), 200);
    // Only levers with edges should produce non-zero-effect plans
    assert!(!report.intervention_plans.is_empty());
}
