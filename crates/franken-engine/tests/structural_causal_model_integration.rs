#![forbid(unsafe_code)]
//! Integration tests for the `structural_causal_model` module (FRX-15.1).
//!
//! Exercises the full SCM API from outside the crate boundary: DAG
//! construction, path queries, confounder classification, backdoor
//! criterion, intervention surfaces, ATE estimation, attribution
//! decomposition, and the canonical lane-decision DAG builder.

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

use frankenengine_engine::structural_causal_model::{
    AttributionDecomposition, BackdoorResult, CausalEdge, CausalEffect, CausalNode,
    ClassifiedConfounder, ConfounderClass, EdgeSign, Intervention, InterventionSurface, NodeRole,
    Observation, PathwayContribution, ScmError, StructuralCausalModel, VariableDomain,
    build_lane_decision_dag,
};

// ===========================================================================
// Helpers
// ===========================================================================

fn node(id: &str, role: NodeRole, domain: VariableDomain) -> CausalNode {
    CausalNode {
        id: id.to_string(),
        label: id.to_string(),
        role,
        domain,
        observable: true,
        fixed_value_millionths: None,
    }
}

fn edge(src: &str, tgt: &str, sign: EdgeSign, strength: i64) -> CausalEdge {
    CausalEdge {
        source: src.to_string(),
        target: tgt.to_string(),
        sign,
        strength_millionths: strength,
        mechanism: format!("{src} → {tgt}"),
    }
}

fn observation(epoch: u64, tick: u64, values: &[(&str, i64)]) -> Observation {
    let vals: BTreeMap<String, i64> = values.iter().map(|(k, v)| (k.to_string(), *v)).collect();
    Observation {
        epoch,
        tick,
        values: vals,
    }
}

/// Build a simple confounding DAG: C → T, C → Y, T → Y
fn confounded_dag() -> StructuralCausalModel {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(node("C", NodeRole::Confounder, VariableDomain::Regime))
        .unwrap();
    scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    scm.add_node(node(
        "Y",
        NodeRole::Outcome,
        VariableDomain::ObservedOutcome,
    ))
    .unwrap();
    scm.add_edge(edge("C", "T", EdgeSign::Positive, 500_000))
        .unwrap();
    scm.add_edge(edge("C", "Y", EdgeSign::Positive, 300_000))
        .unwrap();
    scm.add_edge(edge("T", "Y", EdgeSign::Positive, 700_000))
        .unwrap();
    scm
}

// ===========================================================================
// 1. NodeRole display and serde
// ===========================================================================

#[test]
fn node_role_debug_all() {
    let roles = [
        NodeRole::Exogenous,
        NodeRole::Endogenous,
        NodeRole::Treatment,
        NodeRole::Outcome,
        NodeRole::Confounder,
        NodeRole::Mediator,
        NodeRole::Instrument,
    ];
    let debugs: BTreeSet<String> = roles.iter().map(|r| format!("{r:?}")).collect();
    assert_eq!(debugs.len(), roles.len(), "all roles have unique debug");
}

#[test]
fn node_role_serde_round_trip() {
    for role in [
        NodeRole::Exogenous,
        NodeRole::Treatment,
        NodeRole::Confounder,
    ] {
        let json = serde_json::to_string(&role).unwrap();
        let back: NodeRole = serde_json::from_str(&json).unwrap();
        assert_eq!(back, role);
    }
}

// ===========================================================================
// 2. VariableDomain display and serde
// ===========================================================================

#[test]
fn variable_domain_debug_all() {
    let domains = [
        VariableDomain::LaneChoice,
        VariableDomain::WorkloadCharacteristic,
        VariableDomain::PolicySetting,
        VariableDomain::ObservedOutcome,
        VariableDomain::RiskBelief,
        VariableDomain::Regime,
        VariableDomain::CalibrationMetric,
        VariableDomain::EnvironmentFactor,
    ];
    let debugs: BTreeSet<String> = domains.iter().map(|d| format!("{d:?}")).collect();
    assert_eq!(debugs.len(), domains.len());
}

#[test]
fn variable_domain_serde_round_trip() {
    let d = VariableDomain::LaneChoice;
    let json = serde_json::to_string(&d).unwrap();
    let back: VariableDomain = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d);
}

// ===========================================================================
// 3. EdgeSign display and serde
// ===========================================================================

#[test]
fn edge_sign_debug_all() {
    let signs = [EdgeSign::Positive, EdgeSign::Negative, EdgeSign::Ambiguous];
    let debugs: BTreeSet<String> = signs.iter().map(|s| format!("{s:?}")).collect();
    assert_eq!(debugs.len(), 3);
}

#[test]
fn edge_sign_serde_round_trip() {
    let s = EdgeSign::Negative;
    let json = serde_json::to_string(&s).unwrap();
    let back: EdgeSign = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s);
}

// ===========================================================================
// 4. ConfounderClass display and serde
// ===========================================================================

#[test]
fn confounder_class_debug_all() {
    let classes = [
        ConfounderClass::Observable,
        ConfounderClass::Latent,
        ConfounderClass::TimeVarying,
        ConfounderClass::Collider,
    ];
    let debugs: BTreeSet<String> = classes.iter().map(|c| format!("{c:?}")).collect();
    assert_eq!(debugs.len(), 4);
}

#[test]
fn confounder_class_serde_round_trip() {
    let c = ConfounderClass::Latent;
    let json = serde_json::to_string(&c).unwrap();
    let back: ConfounderClass = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
}

// ===========================================================================
// 5. ScmError display and serde
// ===========================================================================

#[test]
fn scm_error_display_variants() {
    let errors = [
        ScmError::NodeNotFound("X".to_string()),
        ScmError::DuplicateNode("X".to_string()),
        ScmError::NoTreatmentNode,
        ScmError::NoOutcomeNode,
        ScmError::NotIdentified {
            reason: "latent confounder".to_string(),
        },
    ];
    for e in &errors {
        assert!(!e.to_string().is_empty());
    }
}

#[test]
fn scm_error_serde_round_trip() {
    let e = ScmError::NodeNotFound("missing".to_string());
    let json = serde_json::to_string(&e).unwrap();
    let back: ScmError = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

// ===========================================================================
// 6. Empty SCM
// ===========================================================================

#[test]
fn empty_scm() {
    let scm = StructuralCausalModel::new();
    assert!(scm.nodes().is_empty());
    assert!(scm.edges().is_empty());
    assert_eq!(scm.observation_count(), 0);
}

#[test]
fn default_scm_same_as_new() {
    let s1 = StructuralCausalModel::new();
    let s2 = StructuralCausalModel::default();
    assert_eq!(s1.nodes().len(), s2.nodes().len());
}

// ===========================================================================
// 7. Adding nodes
// ===========================================================================

#[test]
fn add_node() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(node("X", NodeRole::Exogenous, VariableDomain::Regime))
        .unwrap();
    assert_eq!(scm.nodes().len(), 1);
    assert!(scm.node("X").is_some());
}

#[test]
fn duplicate_node_error() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(node("X", NodeRole::Exogenous, VariableDomain::Regime))
        .unwrap();
    let result = scm.add_node(node("X", NodeRole::Exogenous, VariableDomain::Regime));
    assert!(matches!(result, Err(ScmError::DuplicateNode(_))));
}

// ===========================================================================
// 8. Adding edges
// ===========================================================================

#[test]
fn add_edge() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(node("A", NodeRole::Exogenous, VariableDomain::Regime))
        .unwrap();
    scm.add_node(node("B", NodeRole::Endogenous, VariableDomain::RiskBelief))
        .unwrap();
    scm.add_edge(edge("A", "B", EdgeSign::Positive, 500_000))
        .unwrap();
    assert_eq!(scm.edges().len(), 1);
}

#[test]
fn edge_to_unknown_node_error() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(node("A", NodeRole::Exogenous, VariableDomain::Regime))
        .unwrap();
    let result = scm.add_edge(edge("A", "missing", EdgeSign::Positive, 500_000));
    assert!(matches!(result, Err(ScmError::NodeNotFound(_))));
}

#[test]
fn cycle_detection_error() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(node("A", NodeRole::Exogenous, VariableDomain::Regime))
        .unwrap();
    scm.add_node(node("B", NodeRole::Endogenous, VariableDomain::RiskBelief))
        .unwrap();
    scm.add_edge(edge("A", "B", EdgeSign::Positive, 500_000))
        .unwrap();
    let result = scm.add_edge(edge("B", "A", EdgeSign::Positive, 500_000));
    assert!(matches!(result, Err(ScmError::CycleDetected { .. })));
}

#[test]
fn duplicate_edge_error() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(node("A", NodeRole::Exogenous, VariableDomain::Regime))
        .unwrap();
    scm.add_node(node("B", NodeRole::Endogenous, VariableDomain::RiskBelief))
        .unwrap();
    scm.add_edge(edge("A", "B", EdgeSign::Positive, 500_000))
        .unwrap();
    let result = scm.add_edge(edge("A", "B", EdgeSign::Negative, 300_000));
    assert!(matches!(result, Err(ScmError::EdgeAlreadyExists { .. })));
}

// ===========================================================================
// 9. Path queries
// ===========================================================================

#[test]
fn has_path_direct() {
    let scm = confounded_dag();
    assert!(scm.has_path(&"T".to_string(), &"Y".to_string()));
    assert!(scm.has_path(&"C".to_string(), &"Y".to_string()));
}

#[test]
fn has_path_transitive() {
    let scm = confounded_dag();
    assert!(scm.has_path(&"C".to_string(), &"Y".to_string()));
}

#[test]
fn no_path_reverse() {
    let scm = confounded_dag();
    assert!(!scm.has_path(&"Y".to_string(), &"T".to_string()));
}

#[test]
fn children_of() {
    let scm = confounded_dag();
    let children = scm.children_of("C");
    assert!(children.contains("T"));
    assert!(children.contains("Y"));
}

#[test]
fn parents_of() {
    let scm = confounded_dag();
    let parents = scm.parents_of("Y");
    assert!(parents.contains("C"));
    assert!(parents.contains("T"));
}

#[test]
fn ancestors_of() {
    let scm = confounded_dag();
    let ancestors = scm.ancestors_of("Y");
    assert!(ancestors.contains("C"));
    assert!(ancestors.contains("T"));
}

#[test]
fn descendants_of() {
    let scm = confounded_dag();
    let desc = scm.descendants_of("C");
    assert!(desc.contains("T"));
    assert!(desc.contains("Y"));
}

#[test]
fn all_directed_paths() {
    let scm = confounded_dag();
    let paths = scm.all_directed_paths("C", "Y");
    // C→Y (direct) and C→T→Y (through treatment)
    assert_eq!(paths.len(), 2);
}

// ===========================================================================
// 10. Observations
// ===========================================================================

#[test]
fn record_and_count_observations() {
    let mut scm = confounded_dag();
    scm.record_observation(observation(1, 1, &[("C", 1), ("T", 1), ("Y", 500_000)]));
    scm.record_observation(observation(1, 2, &[("C", 0), ("T", 0), ("Y", 200_000)]));
    assert_eq!(scm.observation_count(), 2);
    assert_eq!(scm.observations().len(), 2);
}

// ===========================================================================
// 11. Confounder classification
// ===========================================================================

#[test]
fn classify_confounders_basic() {
    let mut scm = confounded_dag();
    let confounders = scm.classify_confounders("T", "Y").unwrap();
    assert!(!confounders.is_empty());
    assert!(confounders.iter().any(|c| c.node_id == "C"));
}

#[test]
fn classify_confounders_has_class() {
    let mut scm = confounded_dag();
    let confounders = scm.classify_confounders("T", "Y").unwrap();
    let c = confounders.iter().find(|c| c.node_id == "C").unwrap();
    // C is observable and a Regime variable; classification depends on domain
    // (Regime variables are classified as TimeVarying by convention)
    assert!(
        c.class == ConfounderClass::Observable || c.class == ConfounderClass::TimeVarying,
        "C should be Observable or TimeVarying, got {:?}",
        c.class
    );
}

#[test]
fn classify_confounders_latent() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(CausalNode {
        id: "U".to_string(),
        label: "latent".to_string(),
        role: NodeRole::Confounder,
        domain: VariableDomain::Regime,
        observable: false,
        fixed_value_millionths: None,
    })
    .unwrap();
    scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    scm.add_node(node(
        "Y",
        NodeRole::Outcome,
        VariableDomain::ObservedOutcome,
    ))
    .unwrap();
    scm.add_edge(edge("U", "T", EdgeSign::Positive, 500_000))
        .unwrap();
    scm.add_edge(edge("U", "Y", EdgeSign::Positive, 300_000))
        .unwrap();
    scm.add_edge(edge("T", "Y", EdgeSign::Positive, 700_000))
        .unwrap();
    let confounders = scm.classify_confounders("T", "Y").unwrap();
    let u = confounders.iter().find(|c| c.node_id == "U").unwrap();
    assert_eq!(u.class, ConfounderClass::Latent);
}

#[test]
fn confounders_accessor() {
    let mut scm = confounded_dag();
    assert!(scm.confounders().is_empty());
    scm.classify_confounders("T", "Y").unwrap();
    assert!(!scm.confounders().is_empty());
}

// ===========================================================================
// 12. Backdoor criterion
// ===========================================================================

#[test]
fn backdoor_identified_with_observable_confounder() {
    let scm = confounded_dag();
    let result = scm.backdoor_criterion("T", "Y").unwrap();
    assert!(result.identified);
    assert!(result.adjustment_set.contains("C"));
}

#[test]
fn backdoor_confounding_paths_found() {
    let scm = confounded_dag();
    let result = scm.backdoor_criterion("T", "Y").unwrap();
    assert!(!result.confounding_paths.is_empty());
}

#[test]
fn backdoor_no_confounders_no_adjustment() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    scm.add_node(node(
        "Y",
        NodeRole::Outcome,
        VariableDomain::ObservedOutcome,
    ))
    .unwrap();
    scm.add_edge(edge("T", "Y", EdgeSign::Positive, 800_000))
        .unwrap();
    let result = scm.backdoor_criterion("T", "Y").unwrap();
    assert!(result.identified);
    assert!(result.adjustment_set.is_empty());
}

#[test]
fn backdoor_missing_treatment_error() {
    let scm = StructuralCausalModel::new();
    let result = scm.backdoor_criterion("T", "Y");
    assert!(result.is_err());
}

// ===========================================================================
// 13. Intervention surfaces
// ===========================================================================

#[test]
fn compute_intervention_surfaces() {
    let mut scm = confounded_dag();
    let surfaces = scm.compute_intervention_surfaces("T", "Y").unwrap();
    assert!(!surfaces.is_empty());
    // At least one surface should be sufficient for identification
    assert!(surfaces.iter().any(|s| s.sufficient_for_identification));
}

#[test]
fn intervention_surfaces_accessor() {
    let mut scm = confounded_dag();
    assert!(scm.intervention_surfaces().is_empty());
    scm.compute_intervention_surfaces("T", "Y").unwrap();
    assert!(!scm.intervention_surfaces().is_empty());
}

// ===========================================================================
// 14. Do-intervention
// ===========================================================================

#[test]
fn do_intervention_removes_incoming_edges() {
    let scm = confounded_dag();
    let intervention = Intervention {
        node_id: "T".to_string(),
        value_millionths: 1_000_000,
        description: "set treatment to 1".to_string(),
    };
    let intervened = scm.do_intervention(&intervention).unwrap();
    // T should have no parents in intervened graph
    let parents = intervened.parents_of("T");
    assert!(parents.is_empty());
    // T→Y edge should still exist
    assert!(intervened.has_path(&"T".to_string(), &"Y".to_string()));
    // C→Y should still exist
    assert!(intervened.has_path(&"C".to_string(), &"Y".to_string()));
    // C→T should be removed
    assert!(!intervened.has_path(&"C".to_string(), &"T".to_string()));
}

#[test]
fn do_intervention_fixes_value() {
    let scm = confounded_dag();
    let intervention = Intervention {
        node_id: "T".to_string(),
        value_millionths: 750_000,
        description: "fix T".to_string(),
    };
    let intervened = scm.do_intervention(&intervention).unwrap();
    let t = intervened.node("T").unwrap();
    assert_eq!(t.fixed_value_millionths, Some(750_000));
}

#[test]
fn do_intervention_unknown_node_error() {
    let scm = confounded_dag();
    let intervention = Intervention {
        node_id: "missing".to_string(),
        value_millionths: 0,
        description: "bad".to_string(),
    };
    let result = scm.do_intervention(&intervention);
    assert!(matches!(result, Err(ScmError::NodeNotFound(_))));
}

// ===========================================================================
// 15. ATE estimation
// ===========================================================================

#[test]
fn estimate_ate_with_observations() {
    let mut scm = confounded_dag();
    // Record observations: when T=1, Y is higher; when T=0, Y is lower
    for i in 0..50 {
        scm.record_observation(observation(
            1,
            i,
            &[("C", 1_000_000), ("T", 1_000_000), ("Y", 800_000)],
        ));
    }
    for i in 50..100 {
        scm.record_observation(observation(
            1,
            i,
            &[("C", 1_000_000), ("T", 0), ("Y", 300_000)],
        ));
    }
    let effect = scm.estimate_ate("T", "Y", 1_000_000, 0, 10).unwrap();
    assert!(effect.ate_millionths > 0);
    assert_eq!(effect.sample_size, 100);
}

#[test]
fn estimate_ate_insufficient_observations() {
    let scm = confounded_dag();
    let result = scm.estimate_ate("T", "Y", 1_000_000, 0, 100);
    assert!(matches!(
        result,
        Err(ScmError::InsufficientObservations { .. })
    ));
}

// ===========================================================================
// 16. Attribution decomposition
// ===========================================================================

#[test]
fn decompose_attribution_basic() {
    let scm = confounded_dag();
    let decomp = scm.decompose_attribution("T", "Y", 500_000).unwrap();
    assert_eq!(decomp.total_delta_millionths, 500_000);
    assert!(!decomp.pathways.is_empty());
    // All pathway fractions should sum close to 1_000_000 (minus residual)
    let total_fraction: i64 = decomp.pathways.iter().map(|p| p.fraction_millionths).sum();
    assert!(total_fraction > 0);
}

#[test]
fn decompose_attribution_pathways_match_dag() {
    let scm = confounded_dag();
    let decomp = scm.decompose_attribution("T", "Y", 1_000_000).unwrap();
    // T→Y is the only direct path
    assert!(decomp.pathways.iter().any(|p| p.path.len() == 2));
}

// ===========================================================================
// 17. Topological ordering
// ===========================================================================

#[test]
fn topological_order() {
    let scm = confounded_dag();
    let order = scm.topological_order();
    assert_eq!(order.len(), 3);
    // C must come before T and Y
    let pos_c = order.iter().position(|n| n == "C").unwrap();
    let pos_t = order.iter().position(|n| n == "T").unwrap();
    let pos_y = order.iter().position(|n| n == "Y").unwrap();
    assert!(pos_c < pos_t);
    assert!(pos_t < pos_y);
}

#[test]
fn topological_order_deterministic() {
    let o1 = confounded_dag().topological_order();
    let o2 = confounded_dag().topological_order();
    assert_eq!(o1, o2);
}

// ===========================================================================
// 18. Report
// ===========================================================================

#[test]
fn report_nonempty() {
    let scm = confounded_dag();
    let report = scm.report();
    assert!(!report.is_empty());
}

// ===========================================================================
// 19. Canonical lane-decision DAG
// ===========================================================================

#[test]
fn canonical_dag_builds_successfully() {
    let scm = build_lane_decision_dag().unwrap();
    assert!(scm.nodes().len() >= 10);
    assert!(!scm.edges().is_empty());
}

#[test]
fn canonical_dag_has_treatment_and_outcome() {
    let scm = build_lane_decision_dag().unwrap();
    assert!(scm.node("lane_choice").is_some());
    assert!(scm.node("latency_outcome").is_some());
    assert!(scm.node("correctness_outcome").is_some());
}

#[test]
fn canonical_dag_treatment_has_path_to_outcomes() {
    let scm = build_lane_decision_dag().unwrap();
    assert!(scm.has_path(&"lane_choice".to_string(), &"latency_outcome".to_string()));
    assert!(scm.has_path(
        &"lane_choice".to_string(),
        &"correctness_outcome".to_string()
    ));
}

#[test]
fn canonical_dag_has_confounders() {
    let scm = build_lane_decision_dag().unwrap();
    assert!(scm.node("regime").is_some());
    let regime = scm.node("regime").unwrap();
    assert_eq!(regime.role, NodeRole::Confounder);
}

#[test]
fn canonical_dag_topological_order() {
    let scm = build_lane_decision_dag().unwrap();
    let order = scm.topological_order();
    // All exogenous nodes should come first
    let exogenous: Vec<_> = scm
        .nodes()
        .values()
        .filter(|n| n.role == NodeRole::Exogenous)
        .map(|n| n.id.clone())
        .collect();
    for ex in &exogenous {
        let ex_pos = order.iter().position(|n| n == ex).unwrap();
        // Treatment should come after exogenous
        if let Some(t_pos) = order.iter().position(|n| n == "lane_choice") {
            assert!(ex_pos < t_pos, "{ex} should precede lane_choice");
        }
    }
}

#[test]
fn canonical_dag_backdoor_criterion() {
    let scm = build_lane_decision_dag().unwrap();
    let result = scm
        .backdoor_criterion("lane_choice", "latency_outcome")
        .unwrap();
    assert!(result.identified);
}

#[test]
fn canonical_dag_confounder_classification() {
    let mut scm = build_lane_decision_dag().unwrap();
    let confounders = scm
        .classify_confounders("lane_choice", "latency_outcome")
        .unwrap();
    // regime is a confounder for lane_choice→latency_outcome
    assert!(confounders.iter().any(|c| c.node_id == "regime"));
}

#[test]
fn canonical_dag_intervention_surfaces() {
    let mut scm = build_lane_decision_dag().unwrap();
    let surfaces = scm
        .compute_intervention_surfaces("lane_choice", "latency_outcome")
        .unwrap();
    assert!(!surfaces.is_empty());
}

#[test]
fn canonical_dag_report() {
    let scm = build_lane_decision_dag().unwrap();
    let report = scm.report();
    assert!(report.contains("lane_choice"));
    assert!(report.contains("regime"));
}

// ===========================================================================
// 20. Complex DAG — mediator
// ===========================================================================

#[test]
fn mediator_on_causal_path() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    scm.add_node(node(
        "M",
        NodeRole::Mediator,
        VariableDomain::CalibrationMetric,
    ))
    .unwrap();
    scm.add_node(node(
        "Y",
        NodeRole::Outcome,
        VariableDomain::ObservedOutcome,
    ))
    .unwrap();
    scm.add_edge(edge("T", "M", EdgeSign::Positive, 600_000))
        .unwrap();
    scm.add_edge(edge("M", "Y", EdgeSign::Positive, 800_000))
        .unwrap();
    // Paths: T→M→Y
    let paths = scm.all_directed_paths("T", "Y");
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].len(), 3);
}

// ===========================================================================
// 21. Complex DAG — instrument
// ===========================================================================

#[test]
fn instrument_only_affects_treatment() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(node(
        "Z",
        NodeRole::Instrument,
        VariableDomain::EnvironmentFactor,
    ))
    .unwrap();
    scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    scm.add_node(node(
        "Y",
        NodeRole::Outcome,
        VariableDomain::ObservedOutcome,
    ))
    .unwrap();
    scm.add_edge(edge("Z", "T", EdgeSign::Positive, 500_000))
        .unwrap();
    scm.add_edge(edge("T", "Y", EdgeSign::Positive, 700_000))
        .unwrap();
    // Z should reach Y only through T
    assert!(scm.has_path(&"Z".to_string(), &"Y".to_string()));
    let paths = scm.all_directed_paths("Z", "Y");
    assert_eq!(paths.len(), 1);
    assert!(paths[0].contains(&"T".to_string()));
}

// ===========================================================================
// 22. Serde round-trips for data types
// ===========================================================================

#[test]
fn causal_node_serde_round_trip() {
    let n = node("T", NodeRole::Treatment, VariableDomain::LaneChoice);
    let json = serde_json::to_string(&n).unwrap();
    let back: CausalNode = serde_json::from_str(&json).unwrap();
    assert_eq!(back, n);
}

#[test]
fn causal_edge_serde_round_trip() {
    let e = edge("A", "B", EdgeSign::Negative, 300_000);
    let json = serde_json::to_string(&e).unwrap();
    let back: CausalEdge = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

#[test]
fn observation_serde_round_trip() {
    let o = observation(1, 42, &[("X", 100), ("Y", 200)]);
    let json = serde_json::to_string(&o).unwrap();
    let back: Observation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, o);
}

#[test]
fn intervention_serde_round_trip() {
    let i = Intervention {
        node_id: "T".to_string(),
        value_millionths: 500_000,
        description: "fix treatment".to_string(),
    };
    let json = serde_json::to_string(&i).unwrap();
    let back: Intervention = serde_json::from_str(&json).unwrap();
    assert_eq!(back, i);
}

#[test]
fn classified_confounder_serde_round_trip() {
    let c = ClassifiedConfounder {
        node_id: "C".to_string(),
        class: ConfounderClass::Observable,
        adjusted: true,
        bias_bound_millionths: 100_000,
        description: "regime confounder".to_string(),
    };
    let json = serde_json::to_string(&c).unwrap();
    let back: ClassifiedConfounder = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
}

#[test]
fn backdoor_result_serde_round_trip() {
    let r = BackdoorResult {
        treatment: "T".to_string(),
        outcome: "Y".to_string(),
        adjustment_set: ["C".to_string()].into_iter().collect(),
        identified: true,
        confounding_paths: vec![vec!["T".to_string(), "C".to_string(), "Y".to_string()]],
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: BackdoorResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

#[test]
fn causal_effect_serde_round_trip() {
    let e = CausalEffect {
        treatment: "T".to_string(),
        outcome: "Y".to_string(),
        ate_millionths: 250_000,
        adjustment_set: BTreeSet::new(),
        sample_size: 100,
        identified: true,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: CausalEffect = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

#[test]
fn pathway_contribution_serde_round_trip() {
    let p = PathwayContribution {
        path: vec!["T".to_string(), "Y".to_string()],
        effect_millionths: 500_000,
        fraction_millionths: 1_000_000,
    };
    let json = serde_json::to_string(&p).unwrap();
    let back: PathwayContribution = serde_json::from_str(&json).unwrap();
    assert_eq!(back, p);
}

#[test]
fn attribution_decomposition_serde_round_trip() {
    let a = AttributionDecomposition {
        treatment: "T".to_string(),
        outcome: "Y".to_string(),
        total_delta_millionths: 1_000_000,
        pathways: vec![PathwayContribution {
            path: vec!["T".to_string(), "Y".to_string()],
            effect_millionths: 1_000_000,
            fraction_millionths: 1_000_000,
        }],
        residual_millionths: 0,
    };
    let json = serde_json::to_string(&a).unwrap();
    let back: AttributionDecomposition = serde_json::from_str(&json).unwrap();
    assert_eq!(back, a);
}

#[test]
fn intervention_surface_serde_round_trip() {
    let s = InterventionSurface {
        name: "direct".to_string(),
        node_ids: ["T".to_string()].into_iter().collect(),
        sufficient_for_identification: true,
        justification: "do-calculus".to_string(),
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: InterventionSurface = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s);
}

// ===========================================================================
// 23. Node accessor returns correct data
// ===========================================================================

#[test]
fn node_accessor_correct() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(CausalNode {
        id: "my_node".to_string(),
        label: "My Custom Node".to_string(),
        role: NodeRole::Treatment,
        domain: VariableDomain::LaneChoice,
        observable: true,
        fixed_value_millionths: Some(42),
    })
    .unwrap();
    let n = scm.node("my_node").unwrap();
    assert_eq!(n.label, "My Custom Node");
    assert_eq!(n.fixed_value_millionths, Some(42));
    assert!(n.observable);
}

#[test]
fn node_not_found() {
    let scm = StructuralCausalModel::new();
    assert!(scm.node("nonexistent").is_none());
}

// ===========================================================================
// 24. Large DAG
// ===========================================================================

#[test]
fn large_chain_dag() {
    let mut scm = StructuralCausalModel::new();
    let n = 20;
    for i in 0..n {
        scm.add_node(node(
            &format!("N_{i}"),
            NodeRole::Endogenous,
            VariableDomain::RiskBelief,
        ))
        .unwrap();
    }
    for i in 0..(n - 1) {
        scm.add_edge(edge(
            &format!("N_{i}"),
            &format!("N_{}", i + 1),
            EdgeSign::Positive,
            500_000,
        ))
        .unwrap();
    }
    assert!(scm.has_path(&"N_0".to_string(), &format!("N_{}", n - 1)));
    let order = scm.topological_order();
    assert_eq!(order.len(), n);
}
