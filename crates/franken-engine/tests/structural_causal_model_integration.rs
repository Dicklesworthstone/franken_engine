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

// ===========================================================================
// Enrichment tests — PearlTower 2026-03-12
// ===========================================================================

// ── NodeRole enrichment ─────────────────────────────────────────────────

#[test]
fn enrichment_node_role_clone() {
    let r = NodeRole::Treatment;
    let r2 = r.clone();
    assert_eq!(r, r2);
}

#[test]
fn enrichment_node_role_partial_eq_self() {
    for role in [
        NodeRole::Exogenous,
        NodeRole::Endogenous,
        NodeRole::Treatment,
        NodeRole::Outcome,
        NodeRole::Confounder,
        NodeRole::Mediator,
        NodeRole::Instrument,
    ] {
        assert_eq!(role, role);
    }
}

#[test]
fn enrichment_node_role_inequalities() {
    assert_ne!(NodeRole::Exogenous, NodeRole::Endogenous);
    assert_ne!(NodeRole::Treatment, NodeRole::Outcome);
    assert_ne!(NodeRole::Confounder, NodeRole::Mediator);
    assert_ne!(NodeRole::Mediator, NodeRole::Instrument);
}

#[test]
fn enrichment_node_role_btreeset_insert_all() {
    let set: BTreeSet<NodeRole> = [
        NodeRole::Exogenous,
        NodeRole::Endogenous,
        NodeRole::Treatment,
        NodeRole::Outcome,
        NodeRole::Confounder,
        NodeRole::Mediator,
        NodeRole::Instrument,
    ]
    .into_iter()
    .collect();
    assert_eq!(set.len(), 7);
}

#[test]
fn enrichment_node_role_serde_json_field_names_stable() {
    let json = serde_json::to_string(&NodeRole::Exogenous).unwrap();
    assert!(json.contains("Exogenous"));
    let json2 = serde_json::to_string(&NodeRole::Instrument).unwrap();
    assert!(json2.contains("Instrument"));
}

// ── VariableDomain enrichment ────────────────────────────────────────────

#[test]
fn enrichment_variable_domain_clone() {
    let d = VariableDomain::PolicySetting;
    let d2 = d.clone();
    assert_eq!(d, d2);
}

#[test]
fn enrichment_variable_domain_all_serde_roundtrip() {
    for domain in [
        VariableDomain::LaneChoice,
        VariableDomain::WorkloadCharacteristic,
        VariableDomain::PolicySetting,
        VariableDomain::ObservedOutcome,
        VariableDomain::RiskBelief,
        VariableDomain::Regime,
        VariableDomain::CalibrationMetric,
        VariableDomain::EnvironmentFactor,
    ] {
        let json = serde_json::to_string(&domain).unwrap();
        let back: VariableDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(back, domain);
    }
}

#[test]
fn enrichment_variable_domain_btreeset_all_variants() {
    let set: BTreeSet<VariableDomain> = [
        VariableDomain::LaneChoice,
        VariableDomain::WorkloadCharacteristic,
        VariableDomain::PolicySetting,
        VariableDomain::ObservedOutcome,
        VariableDomain::RiskBelief,
        VariableDomain::Regime,
        VariableDomain::CalibrationMetric,
        VariableDomain::EnvironmentFactor,
    ]
    .into_iter()
    .collect();
    assert_eq!(set.len(), 8);
}

// ── EdgeSign enrichment ──────────────────────────────────────────────────

#[test]
fn enrichment_edge_sign_clone() {
    let s = EdgeSign::Ambiguous;
    let s2 = s.clone();
    assert_eq!(s, s2);
}

#[test]
fn enrichment_edge_sign_all_variants_serde() {
    for sign in [EdgeSign::Positive, EdgeSign::Negative, EdgeSign::Ambiguous] {
        let json = serde_json::to_string(&sign).unwrap();
        let back: EdgeSign = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sign);
    }
}

#[test]
fn enrichment_edge_sign_ord() {
    let mut signs = vec![EdgeSign::Ambiguous, EdgeSign::Positive, EdgeSign::Negative];
    signs.sort();
    assert_eq!(signs.len(), 3);
    // Just verify sorting doesn't panic and all remain
}

// ── ConfounderClass enrichment ───────────────────────────────────────────

#[test]
fn enrichment_confounder_class_clone() {
    let c = ConfounderClass::Collider;
    let c2 = c.clone();
    assert_eq!(c, c2);
}

#[test]
fn enrichment_confounder_class_inequalities() {
    assert_ne!(ConfounderClass::Observable, ConfounderClass::Latent);
    assert_ne!(ConfounderClass::TimeVarying, ConfounderClass::Collider);
    assert_ne!(ConfounderClass::Observable, ConfounderClass::Collider);
}

// ── ScmError enrichment ─────────────────────────────────────────────────

#[test]
fn enrichment_scm_error_clone() {
    let e = ScmError::NodeNotFound("Z".to_string());
    let e2 = e.clone();
    assert_eq!(e, e2);
}

#[test]
fn enrichment_scm_error_display_edge_already_exists() {
    let e = ScmError::EdgeAlreadyExists {
        source: "A".to_string(),
        target: "B".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("edge already exists"));
    assert!(s.contains("A"));
    assert!(s.contains("B"));
}

#[test]
fn enrichment_scm_error_display_duplicate_node() {
    let e = ScmError::DuplicateNode("X".to_string());
    assert_eq!(e.to_string(), "duplicate node: X");
}

#[test]
fn enrichment_scm_error_display_no_treatment() {
    assert_eq!(ScmError::NoTreatmentNode.to_string(), "no treatment node in DAG");
}

#[test]
fn enrichment_scm_error_display_no_outcome() {
    assert_eq!(ScmError::NoOutcomeNode.to_string(), "no outcome node in DAG");
}

#[test]
fn enrichment_scm_error_display_insufficient_observations() {
    let e = ScmError::InsufficientObservations {
        required: 50,
        available: 3,
    };
    let s = e.to_string();
    assert!(s.contains("50"));
    assert!(s.contains("3"));
}

#[test]
fn enrichment_scm_error_display_not_identified() {
    let e = ScmError::NotIdentified {
        reason: "latent confounders block identification".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("not identified"));
    assert!(s.contains("latent confounders"));
}

#[test]
fn enrichment_scm_error_display_cycle_detected_joins_with_arrow() {
    let e = ScmError::CycleDetected {
        path: vec!["X".to_string(), "Y".to_string(), "X".to_string()],
    };
    let s = e.to_string();
    assert!(s.contains("cycle detected"));
    assert!(s.contains("X"));
    assert!(s.contains("Y"));
}

#[test]
fn enrichment_scm_error_serde_all_variants_roundtrip() {
    let errors = [
        ScmError::NodeNotFound("x".to_string()),
        ScmError::EdgeAlreadyExists {
            source: "a".to_string(),
            target: "b".to_string(),
        },
        ScmError::CycleDetected {
            path: vec!["a".to_string(), "b".to_string()],
        },
        ScmError::DuplicateNode("d".to_string()),
        ScmError::NoTreatmentNode,
        ScmError::NoOutcomeNode,
        ScmError::InsufficientObservations {
            required: 10,
            available: 5,
        },
        ScmError::NotIdentified {
            reason: "test".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ScmError = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, err);
    }
}

#[test]
fn enrichment_scm_error_is_std_error() {
    let e: Box<dyn std::error::Error> =
        Box::new(ScmError::InsufficientObservations {
            required: 100,
            available: 0,
        });
    assert!(!e.to_string().is_empty());
}

// ── CausalNode enrichment ────────────────────────────────────────────────

#[test]
fn enrichment_causal_node_clone() {
    let n = node("N1", NodeRole::Exogenous, VariableDomain::Regime);
    let n2 = n.clone();
    assert_eq!(n, n2);
}

#[test]
fn enrichment_causal_node_debug() {
    let n = node("dbg", NodeRole::Mediator, VariableDomain::CalibrationMetric);
    let s = format!("{n:?}");
    assert!(s.contains("dbg"));
    assert!(s.contains("Mediator"));
}

#[test]
fn enrichment_causal_node_serde_with_fixed_value() {
    let n = CausalNode {
        id: "fixed".to_string(),
        label: "Fixed Node".to_string(),
        role: NodeRole::Treatment,
        domain: VariableDomain::LaneChoice,
        observable: false,
        fixed_value_millionths: Some(-500_000),
    };
    let json = serde_json::to_string(&n).unwrap();
    let back: CausalNode = serde_json::from_str(&json).unwrap();
    assert_eq!(back, n);
    assert_eq!(back.fixed_value_millionths, Some(-500_000));
    assert!(!back.observable);
}

#[test]
fn enrichment_causal_node_serde_json_field_names() {
    let n = node("f", NodeRole::Outcome, VariableDomain::ObservedOutcome);
    let json = serde_json::to_string(&n).unwrap();
    assert!(json.contains("\"id\""));
    assert!(json.contains("\"label\""));
    assert!(json.contains("\"role\""));
    assert!(json.contains("\"domain\""));
    assert!(json.contains("\"observable\""));
    assert!(json.contains("\"fixed_value_millionths\""));
}

// ── CausalEdge enrichment ────────────────────────────────────────────────

#[test]
fn enrichment_causal_edge_clone() {
    let e = edge("X", "Y", EdgeSign::Negative, 300_000);
    let e2 = e.clone();
    assert_eq!(e, e2);
}

#[test]
fn enrichment_causal_edge_debug() {
    let e = edge("A", "B", EdgeSign::Ambiguous, 0);
    let s = format!("{e:?}");
    assert!(s.contains("Ambiguous"));
}

#[test]
fn enrichment_causal_edge_serde_json_field_names() {
    let e = edge("s", "t", EdgeSign::Positive, 100_000);
    let json = serde_json::to_string(&e).unwrap();
    assert!(json.contains("\"source\""));
    assert!(json.contains("\"target\""));
    assert!(json.contains("\"sign\""));
    assert!(json.contains("\"strength_millionths\""));
    assert!(json.contains("\"mechanism\""));
}

#[test]
fn enrichment_causal_edge_zero_strength() {
    let e = edge("X", "Y", EdgeSign::Positive, 0);
    let json = serde_json::to_string(&e).unwrap();
    let back: CausalEdge = serde_json::from_str(&json).unwrap();
    assert_eq!(back.strength_millionths, 0);
}

#[test]
fn enrichment_causal_edge_negative_strength() {
    let e = CausalEdge {
        source: "A".to_string(),
        target: "B".to_string(),
        sign: EdgeSign::Negative,
        strength_millionths: -1_000_000,
        mechanism: "inhibition".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: CausalEdge = serde_json::from_str(&json).unwrap();
    assert_eq!(back.strength_millionths, -1_000_000);
}

// ── Observation enrichment ────────────────────────────────────────────────

#[test]
fn enrichment_observation_empty_values() {
    let o = Observation {
        epoch: 0,
        tick: 0,
        values: BTreeMap::new(),
    };
    let json = serde_json::to_string(&o).unwrap();
    let back: Observation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, o);
    assert!(back.values.is_empty());
}

#[test]
fn enrichment_observation_clone() {
    let o = observation(5, 10, &[("A", 100), ("B", 200)]);
    let o2 = o.clone();
    assert_eq!(o, o2);
}

#[test]
fn enrichment_observation_debug() {
    let o = observation(1, 2, &[("X", 42)]);
    let s = format!("{o:?}");
    assert!(s.contains("epoch"));
    assert!(s.contains("tick"));
}

#[test]
fn enrichment_observation_json_field_names() {
    let o = observation(1, 2, &[("X", 100)]);
    let json = serde_json::to_string(&o).unwrap();
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"tick\""));
    assert!(json.contains("\"values\""));
}

// ── Intervention enrichment ──────────────────────────────────────────────

#[test]
fn enrichment_intervention_clone() {
    let iv = Intervention {
        node_id: "T".to_string(),
        value_millionths: 500_000,
        description: "test".to_string(),
    };
    let iv2 = iv.clone();
    assert_eq!(iv, iv2);
}

#[test]
fn enrichment_intervention_debug() {
    let iv = Intervention {
        node_id: "X".to_string(),
        value_millionths: 0,
        description: "zero".to_string(),
    };
    let s = format!("{iv:?}");
    assert!(s.contains("X"));
}

#[test]
fn enrichment_intervention_negative_value() {
    let iv = Intervention {
        node_id: "T".to_string(),
        value_millionths: -1_000_000,
        description: "neg".to_string(),
    };
    let json = serde_json::to_string(&iv).unwrap();
    let back: Intervention = serde_json::from_str(&json).unwrap();
    assert_eq!(back.value_millionths, -1_000_000);
}

#[test]
fn enrichment_intervention_json_field_names() {
    let iv = Intervention {
        node_id: "N".to_string(),
        value_millionths: 0,
        description: "d".to_string(),
    };
    let json = serde_json::to_string(&iv).unwrap();
    assert!(json.contains("\"node_id\""));
    assert!(json.contains("\"value_millionths\""));
    assert!(json.contains("\"description\""));
}

// ── InterventionSurface enrichment ──────────────────────────────────────

#[test]
fn enrichment_intervention_surface_clone() {
    let s = InterventionSurface {
        name: "test".to_string(),
        node_ids: BTreeSet::from(["A".to_string()]),
        sufficient_for_identification: false,
        justification: "j".to_string(),
    };
    let s2 = s.clone();
    assert_eq!(s, s2);
}

#[test]
fn enrichment_intervention_surface_empty_node_ids() {
    let s = InterventionSurface {
        name: "empty".to_string(),
        node_ids: BTreeSet::new(),
        sufficient_for_identification: false,
        justification: "none".to_string(),
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: InterventionSurface = serde_json::from_str(&json).unwrap();
    assert!(back.node_ids.is_empty());
    assert!(!back.sufficient_for_identification);
}

// ── BackdoorResult enrichment ───────────────────────────────────────────

#[test]
fn enrichment_backdoor_result_clone() {
    let r = BackdoorResult {
        treatment: "T".to_string(),
        outcome: "Y".to_string(),
        adjustment_set: BTreeSet::new(),
        identified: false,
        confounding_paths: Vec::new(),
    };
    let r2 = r.clone();
    assert_eq!(r, r2);
}

#[test]
fn enrichment_backdoor_result_empty_adjustment_set() {
    let r = BackdoorResult {
        treatment: "T".to_string(),
        outcome: "Y".to_string(),
        adjustment_set: BTreeSet::new(),
        identified: true,
        confounding_paths: Vec::new(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: BackdoorResult = serde_json::from_str(&json).unwrap();
    assert!(back.adjustment_set.is_empty());
    assert!(back.identified);
}

// ── CausalEffect enrichment ────────────────────────────────────────────

#[test]
fn enrichment_causal_effect_clone() {
    let e = CausalEffect {
        treatment: "T".to_string(),
        outcome: "Y".to_string(),
        ate_millionths: 0,
        adjustment_set: BTreeSet::new(),
        sample_size: 0,
        identified: false,
    };
    let e2 = e.clone();
    assert_eq!(e, e2);
}

#[test]
fn enrichment_causal_effect_negative_ate() {
    let e = CausalEffect {
        treatment: "T".to_string(),
        outcome: "Y".to_string(),
        ate_millionths: -750_000,
        adjustment_set: BTreeSet::from(["C".to_string()]),
        sample_size: 200,
        identified: true,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: CausalEffect = serde_json::from_str(&json).unwrap();
    assert_eq!(back.ate_millionths, -750_000);
}

#[test]
fn enrichment_causal_effect_json_field_names() {
    let e = CausalEffect {
        treatment: "T".to_string(),
        outcome: "Y".to_string(),
        ate_millionths: 100_000,
        adjustment_set: BTreeSet::new(),
        sample_size: 10,
        identified: true,
    };
    let json = serde_json::to_string(&e).unwrap();
    assert!(json.contains("\"treatment\""));
    assert!(json.contains("\"outcome\""));
    assert!(json.contains("\"ate_millionths\""));
    assert!(json.contains("\"adjustment_set\""));
    assert!(json.contains("\"sample_size\""));
    assert!(json.contains("\"identified\""));
}

// ── PathwayContribution enrichment ──────────────────────────────────────

#[test]
fn enrichment_pathway_contribution_clone() {
    let p = PathwayContribution {
        path: vec!["A".to_string(), "B".to_string()],
        effect_millionths: 100,
        fraction_millionths: 500_000,
    };
    let p2 = p.clone();
    assert_eq!(p, p2);
}

#[test]
fn enrichment_pathway_contribution_empty_path() {
    let p = PathwayContribution {
        path: Vec::new(),
        effect_millionths: 0,
        fraction_millionths: 0,
    };
    let json = serde_json::to_string(&p).unwrap();
    let back: PathwayContribution = serde_json::from_str(&json).unwrap();
    assert!(back.path.is_empty());
}

// ── AttributionDecomposition enrichment ─────────────────────────────────

#[test]
fn enrichment_attribution_decomposition_clone() {
    let a = AttributionDecomposition {
        treatment: "T".to_string(),
        outcome: "Y".to_string(),
        total_delta_millionths: 0,
        pathways: Vec::new(),
        residual_millionths: 0,
    };
    let a2 = a.clone();
    assert_eq!(a, a2);
}

#[test]
fn enrichment_attribution_decomposition_json_field_names() {
    let a = AttributionDecomposition {
        treatment: "T".to_string(),
        outcome: "Y".to_string(),
        total_delta_millionths: 100,
        pathways: Vec::new(),
        residual_millionths: 100,
    };
    let json = serde_json::to_string(&a).unwrap();
    assert!(json.contains("\"treatment\""));
    assert!(json.contains("\"outcome\""));
    assert!(json.contains("\"total_delta_millionths\""));
    assert!(json.contains("\"pathways\""));
    assert!(json.contains("\"residual_millionths\""));
}

// ── ClassifiedConfounder enrichment ─────────────────────────────────────

#[test]
fn enrichment_classified_confounder_clone() {
    let c = ClassifiedConfounder {
        node_id: "C".to_string(),
        class: ConfounderClass::Observable,
        adjusted: true,
        bias_bound_millionths: 100_000,
        description: "test".to_string(),
    };
    let c2 = c.clone();
    assert_eq!(c, c2);
}

#[test]
fn enrichment_classified_confounder_json_field_names() {
    let c = ClassifiedConfounder {
        node_id: "C".to_string(),
        class: ConfounderClass::Latent,
        adjusted: false,
        bias_bound_millionths: 0,
        description: "x".to_string(),
    };
    let json = serde_json::to_string(&c).unwrap();
    assert!(json.contains("\"node_id\""));
    assert!(json.contains("\"class\""));
    assert!(json.contains("\"adjusted\""));
    assert!(json.contains("\"bias_bound_millionths\""));
    assert!(json.contains("\"description\""));
}

// ── StructuralCausalModel enrichment ────────────────────────────────────

#[test]
fn enrichment_scm_serde_roundtrip_empty() {
    let scm = StructuralCausalModel::new();
    let json = serde_json::to_string(&scm).unwrap();
    let back: StructuralCausalModel = serde_json::from_str(&json).unwrap();
    assert_eq!(back, scm);
}

#[test]
fn enrichment_scm_serde_roundtrip_with_data() {
    let mut scm = confounded_dag();
    scm.record_observation(observation(1, 1, &[("C", 100), ("T", 200), ("Y", 300)]));
    let json = serde_json::to_string(&scm).unwrap();
    let back: StructuralCausalModel = serde_json::from_str(&json).unwrap();
    assert_eq!(back.nodes().len(), 3);
    assert_eq!(back.edges().len(), 3);
    assert_eq!(back.observation_count(), 1);
}

#[test]
fn enrichment_scm_clone() {
    let scm = confounded_dag();
    let scm2 = scm.clone();
    assert_eq!(scm, scm2);
}

#[test]
fn enrichment_scm_debug() {
    let scm = StructuralCausalModel::new();
    let s = format!("{scm:?}");
    assert!(s.contains("StructuralCausalModel"));
}

#[test]
fn enrichment_scm_default_eq_new() {
    let d = StructuralCausalModel::default();
    let n = StructuralCausalModel::new();
    assert_eq!(d, n);
}

// ── Edge error paths ────────────────────────────────────────────────────

#[test]
fn enrichment_edge_source_not_found() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(node("B", NodeRole::Endogenous, VariableDomain::RiskBelief))
        .unwrap();
    let result = scm.add_edge(edge("missing_src", "B", EdgeSign::Positive, 100_000));
    assert!(matches!(result, Err(ScmError::NodeNotFound(ref id)) if id == "missing_src"));
}

#[test]
fn enrichment_edge_target_not_found() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(node("A", NodeRole::Exogenous, VariableDomain::Regime))
        .unwrap();
    let result = scm.add_edge(edge("A", "missing_tgt", EdgeSign::Positive, 100_000));
    assert!(matches!(result, Err(ScmError::NodeNotFound(ref id)) if id == "missing_tgt"));
}

#[test]
fn enrichment_self_loop_rejected() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(node("S", NodeRole::Endogenous, VariableDomain::RiskBelief))
        .unwrap();
    let result = scm.add_edge(edge("S", "S", EdgeSign::Positive, 500_000));
    assert!(matches!(result, Err(ScmError::CycleDetected { .. })));
}

// ── Path query enrichment ───────────────────────────────────────────────

#[test]
fn enrichment_has_path_self_returns_true() {
    let scm = confounded_dag();
    // A node has a trivial "path" to itself (visited == to on first iteration)
    assert!(scm.has_path(&"C".to_string(), &"C".to_string()));
}

#[test]
fn enrichment_has_path_nonexistent_nodes() {
    let scm = confounded_dag();
    assert!(!scm.has_path(&"X".to_string(), &"Y".to_string()));
    assert!(!scm.has_path(&"C".to_string(), &"Z".to_string()));
}

#[test]
fn enrichment_children_of_leaf() {
    let scm = confounded_dag();
    assert!(scm.children_of("Y").is_empty());
}

#[test]
fn enrichment_parents_of_root() {
    let scm = confounded_dag();
    assert!(scm.parents_of("C").is_empty());
}

#[test]
fn enrichment_ancestors_of_root() {
    let scm = confounded_dag();
    assert!(scm.ancestors_of("C").is_empty());
}

#[test]
fn enrichment_descendants_of_leaf() {
    let scm = confounded_dag();
    assert!(scm.descendants_of("Y").is_empty());
}

#[test]
fn enrichment_all_directed_paths_no_path() {
    let scm = confounded_dag();
    let paths = scm.all_directed_paths("Y", "C");
    assert!(paths.is_empty());
}

#[test]
fn enrichment_all_directed_paths_self() {
    let scm = confounded_dag();
    let paths = scm.all_directed_paths("T", "T");
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0], vec!["T".to_string()]);
}

// ── Observation enrichment ──────────────────────────────────────────────

#[test]
fn enrichment_record_many_observations() {
    let mut scm = confounded_dag();
    for i in 0..100 {
        scm.record_observation(observation(1, i, &[("C", 1), ("T", 1), ("Y", i as i64)]));
    }
    assert_eq!(scm.observation_count(), 100);
    assert_eq!(scm.observations().len(), 100);
}

#[test]
fn enrichment_observation_values_preserved() {
    let mut scm = confounded_dag();
    scm.record_observation(observation(42, 99, &[("C", -500_000), ("T", 0), ("Y", 1_000_000)]));
    let obs = &scm.observations()[0];
    assert_eq!(obs.epoch, 42);
    assert_eq!(obs.tick, 99);
    assert_eq!(*obs.values.get("C").unwrap(), -500_000);
    assert_eq!(*obs.values.get("T").unwrap(), 0);
    assert_eq!(*obs.values.get("Y").unwrap(), 1_000_000);
}

// ── Confounder classification enrichment ────────────────────────────────

#[test]
fn enrichment_classify_confounders_missing_treatment() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(node("Y", NodeRole::Outcome, VariableDomain::ObservedOutcome))
        .unwrap();
    let result = scm.classify_confounders("T", "Y");
    assert!(matches!(result, Err(ScmError::NodeNotFound(_))));
}

#[test]
fn enrichment_classify_confounders_missing_outcome() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    let result = scm.classify_confounders("T", "Y");
    assert!(matches!(result, Err(ScmError::NodeNotFound(_))));
}

#[test]
fn enrichment_classify_confounders_no_confounders() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    scm.add_node(node("Y", NodeRole::Outcome, VariableDomain::ObservedOutcome))
        .unwrap();
    scm.add_edge(edge("T", "Y", EdgeSign::Positive, 800_000))
        .unwrap();
    let confounders = scm.classify_confounders("T", "Y").unwrap();
    assert!(confounders.is_empty());
}

#[test]
fn enrichment_classify_confounders_environment_is_time_varying() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(CausalNode {
        id: "E".to_string(),
        label: "environment".to_string(),
        role: NodeRole::Confounder,
        domain: VariableDomain::EnvironmentFactor,
        observable: true,
        fixed_value_millionths: None,
    })
    .unwrap();
    scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    scm.add_node(node("Y", NodeRole::Outcome, VariableDomain::ObservedOutcome))
        .unwrap();
    scm.add_edge(edge("E", "T", EdgeSign::Positive, 500_000))
        .unwrap();
    scm.add_edge(edge("E", "Y", EdgeSign::Positive, 300_000))
        .unwrap();
    scm.add_edge(edge("T", "Y", EdgeSign::Positive, 700_000))
        .unwrap();
    let confounders = scm.classify_confounders("T", "Y").unwrap();
    let e = confounders.iter().find(|c| c.node_id == "E").unwrap();
    assert_eq!(e.class, ConfounderClass::TimeVarying);
}

#[test]
fn enrichment_classify_confounders_workload_is_observable() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(CausalNode {
        id: "W".to_string(),
        label: "workload".to_string(),
        role: NodeRole::Confounder,
        domain: VariableDomain::WorkloadCharacteristic,
        observable: true,
        fixed_value_millionths: None,
    })
    .unwrap();
    scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    scm.add_node(node("Y", NodeRole::Outcome, VariableDomain::ObservedOutcome))
        .unwrap();
    scm.add_edge(edge("W", "T", EdgeSign::Positive, 500_000))
        .unwrap();
    scm.add_edge(edge("W", "Y", EdgeSign::Positive, 300_000))
        .unwrap();
    scm.add_edge(edge("T", "Y", EdgeSign::Positive, 700_000))
        .unwrap();
    let confounders = scm.classify_confounders("T", "Y").unwrap();
    let w = confounders.iter().find(|c| c.node_id == "W").unwrap();
    assert_eq!(w.class, ConfounderClass::Observable);
    assert!(w.adjusted);
}

#[test]
fn enrichment_classify_confounders_sorted_by_node_id() {
    let mut scm = StructuralCausalModel::new();
    for id in ["Z_conf", "A_conf"] {
        scm.add_node(CausalNode {
            id: id.to_string(),
            label: id.to_string(),
            role: NodeRole::Confounder,
            domain: VariableDomain::PolicySetting,
            observable: true,
            fixed_value_millionths: None,
        })
        .unwrap();
    }
    scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    scm.add_node(node("Y", NodeRole::Outcome, VariableDomain::ObservedOutcome))
        .unwrap();
    for id in ["Z_conf", "A_conf"] {
        scm.add_edge(edge(id, "T", EdgeSign::Positive, 500_000))
            .unwrap();
        scm.add_edge(edge(id, "Y", EdgeSign::Positive, 500_000))
            .unwrap();
    }
    scm.add_edge(edge("T", "Y", EdgeSign::Positive, 800_000))
        .unwrap();
    let confounders = scm.classify_confounders("T", "Y").unwrap();
    assert_eq!(confounders.len(), 2);
    assert!(confounders[0].node_id < confounders[1].node_id);
}

// ── Backdoor criterion enrichment ───────────────────────────────────────

#[test]
fn enrichment_backdoor_missing_outcome() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    let result = scm.backdoor_criterion("T", "Y");
    assert!(matches!(result, Err(ScmError::NodeNotFound(_))));
}

#[test]
fn enrichment_backdoor_latent_confounder_not_identified() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(CausalNode {
        id: "U".to_string(),
        label: "Latent".to_string(),
        role: NodeRole::Confounder,
        domain: VariableDomain::EnvironmentFactor,
        observable: false,
        fixed_value_millionths: None,
    })
    .unwrap();
    scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    scm.add_node(node("Y", NodeRole::Outcome, VariableDomain::ObservedOutcome))
        .unwrap();
    scm.add_edge(edge("U", "T", EdgeSign::Positive, 500_000))
        .unwrap();
    scm.add_edge(edge("U", "Y", EdgeSign::Positive, 300_000))
        .unwrap();
    scm.add_edge(edge("T", "Y", EdgeSign::Positive, 700_000))
        .unwrap();
    let result = scm.backdoor_criterion("T", "Y").unwrap();
    assert!(!result.identified);
    assert!(!result.adjustment_set.contains("U"));
}

#[test]
fn enrichment_backdoor_multiple_confounders_all_in_set() {
    let mut scm = StructuralCausalModel::new();
    for id in ["C1", "C2", "C3"] {
        scm.add_node(CausalNode {
            id: id.to_string(),
            label: id.to_string(),
            role: NodeRole::Confounder,
            domain: VariableDomain::WorkloadCharacteristic,
            observable: true,
            fixed_value_millionths: None,
        })
        .unwrap();
    }
    scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    scm.add_node(node("Y", NodeRole::Outcome, VariableDomain::ObservedOutcome))
        .unwrap();
    for id in ["C1", "C2", "C3"] {
        scm.add_edge(edge(id, "T", EdgeSign::Positive, 400_000))
            .unwrap();
        scm.add_edge(edge(id, "Y", EdgeSign::Positive, 400_000))
            .unwrap();
    }
    scm.add_edge(edge("T", "Y", EdgeSign::Positive, 800_000))
        .unwrap();
    let result = scm.backdoor_criterion("T", "Y").unwrap();
    assert!(result.identified);
    assert!(result.adjustment_set.contains("C1"));
    assert!(result.adjustment_set.contains("C2"));
    assert!(result.adjustment_set.contains("C3"));
}

// ── Intervention enrichment ─────────────────────────────────────────────

#[test]
fn enrichment_do_intervention_zero_value() {
    let scm = confounded_dag();
    let intervention = Intervention {
        node_id: "T".to_string(),
        value_millionths: 0,
        description: "set to zero".to_string(),
    };
    let intervened = scm.do_intervention(&intervention).unwrap();
    assert_eq!(intervened.node("T").unwrap().fixed_value_millionths, Some(0));
}

#[test]
fn enrichment_do_intervention_negative_value() {
    let scm = confounded_dag();
    let intervention = Intervention {
        node_id: "T".to_string(),
        value_millionths: -500_000,
        description: "negative".to_string(),
    };
    let intervened = scm.do_intervention(&intervention).unwrap();
    assert_eq!(
        intervened.node("T").unwrap().fixed_value_millionths,
        Some(-500_000)
    );
}

#[test]
fn enrichment_do_intervention_preserves_node_count() {
    let scm = confounded_dag();
    let intervention = Intervention {
        node_id: "T".to_string(),
        value_millionths: 1_000_000,
        description: "test".to_string(),
    };
    let intervened = scm.do_intervention(&intervention).unwrap();
    assert_eq!(intervened.nodes().len(), scm.nodes().len());
}

#[test]
fn enrichment_do_intervention_edge_count_decreases() {
    let scm = confounded_dag();
    let intervention = Intervention {
        node_id: "T".to_string(),
        value_millionths: 1_000_000,
        description: "test".to_string(),
    };
    let intervened = scm.do_intervention(&intervention).unwrap();
    // C->T edge should be removed
    assert!(intervened.edges().len() < scm.edges().len());
}

#[test]
fn enrichment_do_intervention_does_not_mutate_original() {
    let scm = confounded_dag();
    let intervention = Intervention {
        node_id: "T".to_string(),
        value_millionths: 999_999,
        description: "test".to_string(),
    };
    let _intervened = scm.do_intervention(&intervention).unwrap();
    assert!(scm.node("T").unwrap().fixed_value_millionths.is_none());
    assert_eq!(scm.edges().len(), 3);
}

// ── Intervention surfaces enrichment ────────────────────────────────────

#[test]
fn enrichment_intervention_surfaces_missing_treatment() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(node("Y", NodeRole::Outcome, VariableDomain::ObservedOutcome))
        .unwrap();
    let result = scm.compute_intervention_surfaces("T", "Y");
    assert!(matches!(result, Err(ScmError::NodeNotFound(_))));
}

#[test]
fn enrichment_intervention_surfaces_missing_outcome() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    let result = scm.compute_intervention_surfaces("T", "Y");
    assert!(matches!(result, Err(ScmError::NodeNotFound(_))));
}

#[test]
fn enrichment_intervention_surfaces_always_has_direct() {
    let mut scm = confounded_dag();
    let surfaces = scm.compute_intervention_surfaces("T", "Y").unwrap();
    assert!(
        surfaces
            .iter()
            .any(|s| s.name.contains("direct_intervention"))
    );
}

#[test]
fn enrichment_intervention_surfaces_with_instrument() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(node("Z", NodeRole::Instrument, VariableDomain::PolicySetting))
        .unwrap();
    scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    scm.add_node(node("Y", NodeRole::Outcome, VariableDomain::ObservedOutcome))
        .unwrap();
    scm.add_edge(edge("Z", "T", EdgeSign::Positive, 500_000))
        .unwrap();
    scm.add_edge(edge("T", "Y", EdgeSign::Positive, 800_000))
        .unwrap();
    let surfaces = scm.compute_intervention_surfaces("T", "Y").unwrap();
    assert!(
        surfaces
            .iter()
            .any(|s| s.name.contains("instrumental_variable"))
    );
}

// ── ATE estimation enrichment ───────────────────────────────────────────

#[test]
fn enrichment_estimate_ate_missing_treatment() {
    let scm = StructuralCausalModel::new();
    let result = scm.estimate_ate("T", "Y", 1_000_000, 0, 1);
    assert!(matches!(result, Err(ScmError::NodeNotFound(_))));
}

#[test]
fn enrichment_estimate_ate_missing_outcome() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    let result = scm.estimate_ate("T", "Y", 1_000_000, 0, 1);
    assert!(matches!(result, Err(ScmError::NodeNotFound(_))));
}

#[test]
fn enrichment_estimate_ate_zero_effect() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    scm.add_node(node("Y", NodeRole::Outcome, VariableDomain::ObservedOutcome))
        .unwrap();
    scm.add_edge(edge("T", "Y", EdgeSign::Positive, 500_000))
        .unwrap();
    // Same outcome regardless of treatment
    for i in 0..10 {
        scm.record_observation(observation(1, i, &[("T", 1_000_000), ("Y", 500_000)]));
        scm.record_observation(observation(1, i + 10, &[("T", 0), ("Y", 500_000)]));
    }
    let effect = scm.estimate_ate("T", "Y", 1_000_000, 0, 5).unwrap();
    assert_eq!(effect.ate_millionths, 0);
    assert!(effect.identified);
}

#[test]
fn enrichment_estimate_ate_deterministic() {
    let make_scm = || {
        let mut scm = StructuralCausalModel::new();
        scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
            .unwrap();
        scm.add_node(node("Y", NodeRole::Outcome, VariableDomain::ObservedOutcome))
            .unwrap();
        scm.add_edge(edge("T", "Y", EdgeSign::Positive, 900_000))
            .unwrap();
        for i in 0..20 {
            scm.record_observation(observation(1, i, &[("T", 1_000_000), ("Y", 800_000)]));
            scm.record_observation(observation(1, i + 20, &[("T", 0), ("Y", 200_000)]));
        }
        scm
    };
    let e1 = make_scm().estimate_ate("T", "Y", 1_000_000, 0, 5).unwrap();
    let e2 = make_scm().estimate_ate("T", "Y", 1_000_000, 0, 5).unwrap();
    assert_eq!(e1.ate_millionths, e2.ate_millionths);
    assert_eq!(e1.sample_size, e2.sample_size);
}

// ── Attribution decomposition enrichment ────────────────────────────────

#[test]
fn enrichment_decompose_attribution_missing_treatment() {
    let scm = StructuralCausalModel::new();
    let result = scm.decompose_attribution("T", "Y", 100_000);
    assert!(matches!(result, Err(ScmError::NodeNotFound(_))));
}

#[test]
fn enrichment_decompose_attribution_missing_outcome() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    let result = scm.decompose_attribution("T", "Y", 100_000);
    assert!(matches!(result, Err(ScmError::NodeNotFound(_))));
}

#[test]
fn enrichment_decompose_attribution_no_path_full_residual() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    scm.add_node(node("Y", NodeRole::Outcome, VariableDomain::ObservedOutcome))
        .unwrap();
    let decomp = scm.decompose_attribution("T", "Y", 750_000).unwrap();
    assert!(decomp.pathways.is_empty());
    assert_eq!(decomp.residual_millionths, 750_000);
}

#[test]
fn enrichment_decompose_attribution_zero_delta() {
    let scm = confounded_dag();
    let decomp = scm.decompose_attribution("T", "Y", 0).unwrap();
    assert_eq!(decomp.total_delta_millionths, 0);
    for p in &decomp.pathways {
        assert_eq!(p.effect_millionths, 0);
    }
}

#[test]
fn enrichment_decompose_attribution_deterministic() {
    let d1 = confounded_dag()
        .decompose_attribution("T", "Y", 1_000_000)
        .unwrap();
    let d2 = confounded_dag()
        .decompose_attribution("T", "Y", 1_000_000)
        .unwrap();
    assert_eq!(d1, d2);
}

#[test]
fn enrichment_decompose_attribution_negative_delta() {
    let scm = confounded_dag();
    let decomp = scm.decompose_attribution("T", "Y", -500_000).unwrap();
    assert_eq!(decomp.total_delta_millionths, -500_000);
    // effect_millionths should be negative for negative total delta
    let total_effect: i64 = decomp.pathways.iter().map(|p| p.effect_millionths).sum();
    // total_effect + residual == total_delta
    assert_eq!(total_effect + decomp.residual_millionths, -500_000);
}

// ── Topological order enrichment ────────────────────────────────────────

#[test]
fn enrichment_topological_order_empty_scm() {
    let scm = StructuralCausalModel::new();
    let order = scm.topological_order();
    assert!(order.is_empty());
}

#[test]
fn enrichment_topological_order_single_node() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(node("A", NodeRole::Exogenous, VariableDomain::Regime))
        .unwrap();
    let order = scm.topological_order();
    assert_eq!(order, vec!["A".to_string()]);
}

#[test]
fn enrichment_topological_order_respects_all_edges() {
    let scm = confounded_dag();
    let order = scm.topological_order();
    for e in scm.edges() {
        let src_pos = order.iter().position(|n| *n == e.source).unwrap();
        let tgt_pos = order.iter().position(|n| *n == e.target).unwrap();
        assert!(
            src_pos < tgt_pos,
            "Edge {} -> {} violated: src_pos={} tgt_pos={}",
            e.source,
            e.target,
            src_pos,
            tgt_pos
        );
    }
}

#[test]
fn enrichment_topological_order_deterministic() {
    let o1 = confounded_dag().topological_order();
    let o2 = confounded_dag().topological_order();
    let o3 = confounded_dag().topological_order();
    assert_eq!(o1, o2);
    assert_eq!(o2, o3);
}

// ── Report enrichment ───────────────────────────────────────────────────

#[test]
fn enrichment_report_empty_scm() {
    let scm = StructuralCausalModel::new();
    let report = scm.report();
    assert!(report.contains("Nodes: 0"));
    assert!(report.contains("Edges: 0"));
    assert!(report.contains("Observations: 0"));
}

#[test]
fn enrichment_report_includes_node_roles() {
    let scm = confounded_dag();
    let report = scm.report();
    assert!(report.contains("Confounder"));
    assert!(report.contains("Treatment"));
    assert!(report.contains("Outcome"));
}

#[test]
fn enrichment_report_includes_edge_signs() {
    let scm = confounded_dag();
    let report = scm.report();
    assert!(report.contains("Positive"));
}

#[test]
fn enrichment_report_includes_confounders_section() {
    let mut scm = confounded_dag();
    scm.classify_confounders("T", "Y").unwrap();
    let report = scm.report();
    assert!(report.contains("Confounders"));
}

#[test]
fn enrichment_report_includes_intervention_surfaces_section() {
    let mut scm = confounded_dag();
    scm.compute_intervention_surfaces("T", "Y").unwrap();
    let report = scm.report();
    assert!(report.contains("Intervention Surfaces"));
}

#[test]
fn enrichment_report_shows_observable_vs_latent() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(CausalNode {
        id: "L".to_string(),
        label: "Latent Node".to_string(),
        role: NodeRole::Confounder,
        domain: VariableDomain::Regime,
        observable: false,
        fixed_value_millionths: None,
    })
    .unwrap();
    let report = scm.report();
    assert!(report.contains("latent"));
}

// ── Canonical DAG enrichment ────────────────────────────────────────────

#[test]
fn enrichment_canonical_dag_deterministic() {
    let d1 = build_lane_decision_dag().unwrap();
    let d2 = build_lane_decision_dag().unwrap();
    assert_eq!(d1, d2);
}

#[test]
fn enrichment_canonical_dag_node_count() {
    let dag = build_lane_decision_dag().unwrap();
    assert_eq!(dag.nodes().len(), 11);
}

#[test]
fn enrichment_canonical_dag_edge_count() {
    let dag = build_lane_decision_dag().unwrap();
    assert_eq!(dag.edges().len(), 15);
}

#[test]
fn enrichment_canonical_dag_exogenous_nodes() {
    let dag = build_lane_decision_dag().unwrap();
    let exo: Vec<_> = dag
        .nodes()
        .values()
        .filter(|n| n.role == NodeRole::Exogenous)
        .map(|n| n.id.clone())
        .collect();
    assert!(exo.contains(&"workload_complexity".to_string()));
    assert!(exo.contains(&"component_count".to_string()));
    assert!(exo.contains(&"effect_depth".to_string()));
    assert!(exo.contains(&"environment_load".to_string()));
}

#[test]
fn enrichment_canonical_dag_mediator_exists() {
    let dag = build_lane_decision_dag().unwrap();
    let n = dag.node("calibration_quality").unwrap();
    assert_eq!(n.role, NodeRole::Mediator);
    assert_eq!(n.domain, VariableDomain::CalibrationMetric);
}

#[test]
fn enrichment_canonical_dag_serde_roundtrip() {
    let dag = build_lane_decision_dag().unwrap();
    let json = serde_json::to_string(&dag).unwrap();
    let back: StructuralCausalModel = serde_json::from_str(&json).unwrap();
    assert_eq!(back, dag);
}

#[test]
fn enrichment_canonical_dag_lane_to_correctness() {
    let dag = build_lane_decision_dag().unwrap();
    let paths = dag.all_directed_paths("lane_choice", "correctness_outcome");
    assert!(paths.len() >= 2, "should have direct + mediated paths");
}

#[test]
fn enrichment_canonical_dag_risk_belief_is_endogenous() {
    let dag = build_lane_decision_dag().unwrap();
    let rb = dag.node("risk_belief").unwrap();
    assert_eq!(rb.role, NodeRole::Endogenous);
    assert_eq!(rb.domain, VariableDomain::RiskBelief);
}

// ── Diamond DAG enrichment ──────────────────────────────────────────────

#[test]
fn enrichment_diamond_dag_two_paths() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    scm.add_node(node("A", NodeRole::Mediator, VariableDomain::CalibrationMetric))
        .unwrap();
    scm.add_node(node("B", NodeRole::Mediator, VariableDomain::RiskBelief))
        .unwrap();
    scm.add_node(node("Y", NodeRole::Outcome, VariableDomain::ObservedOutcome))
        .unwrap();
    scm.add_edge(edge("T", "A", EdgeSign::Positive, 600_000)).unwrap();
    scm.add_edge(edge("T", "B", EdgeSign::Negative, 400_000)).unwrap();
    scm.add_edge(edge("A", "Y", EdgeSign::Positive, 800_000)).unwrap();
    scm.add_edge(edge("B", "Y", EdgeSign::Positive, 700_000)).unwrap();

    let paths = scm.all_directed_paths("T", "Y");
    assert_eq!(paths.len(), 2);

    let decomp = scm.decompose_attribution("T", "Y", 1_000_000).unwrap();
    assert_eq!(decomp.pathways.len(), 2);
    let total_fraction: i64 = decomp.pathways.iter().map(|p| p.fraction_millionths).sum();
    // Fractions sum close to 1.0
    assert!((total_fraction - 1_000_000).abs() < 10);
}

// ── Wide DAG enrichment ─────────────────────────────────────────────────

#[test]
fn enrichment_wide_dag_many_roots() {
    let mut scm = StructuralCausalModel::new();
    for i in 0..10 {
        scm.add_node(node(
            &format!("root_{i}"),
            NodeRole::Exogenous,
            VariableDomain::EnvironmentFactor,
        ))
        .unwrap();
    }
    scm.add_node(node("sink", NodeRole::Outcome, VariableDomain::ObservedOutcome))
        .unwrap();
    for i in 0..10 {
        scm.add_edge(edge(
            &format!("root_{i}"),
            "sink",
            EdgeSign::Positive,
            100_000,
        ))
        .unwrap();
    }
    assert_eq!(scm.parents_of("sink").len(), 10);
    let order = scm.topological_order();
    assert_eq!(order.len(), 11);
    // sink is last
    assert_eq!(order.last().unwrap(), "sink");
}

// ── Collider detection enrichment ───────────────────────────────────────

#[test]
fn enrichment_collider_detection_basic() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    scm.add_node(node("Y", NodeRole::Outcome, VariableDomain::ObservedOutcome))
        .unwrap();
    scm.add_node(node("M", NodeRole::Endogenous, VariableDomain::CalibrationMetric))
        .unwrap();
    scm.add_edge(edge("T", "M", EdgeSign::Positive, 500_000))
        .unwrap();
    scm.add_edge(edge("Y", "M", EdgeSign::Positive, 500_000))
        .unwrap();
    let confounders = scm.classify_confounders("T", "Y").unwrap();
    let colliders: Vec<_> = confounders
        .iter()
        .filter(|c| c.class == ConfounderClass::Collider)
        .collect();
    assert_eq!(colliders.len(), 1);
    assert_eq!(colliders[0].node_id, "M");
    assert!(!colliders[0].adjusted, "colliders should NOT be adjusted");
}

// ── Determinism enrichment ──────────────────────────────────────────────

#[test]
fn enrichment_backdoor_deterministic() {
    let r1 = confounded_dag().backdoor_criterion("T", "Y").unwrap();
    let r2 = confounded_dag().backdoor_criterion("T", "Y").unwrap();
    assert_eq!(r1, r2);
}

#[test]
fn enrichment_classify_confounders_deterministic() {
    let mut s1 = confounded_dag();
    let mut s2 = confounded_dag();
    let c1 = s1.classify_confounders("T", "Y").unwrap();
    let c2 = s2.classify_confounders("T", "Y").unwrap();
    assert_eq!(c1, c2);
}

#[test]
fn enrichment_intervention_surfaces_deterministic() {
    let mut s1 = confounded_dag();
    let mut s2 = confounded_dag();
    let i1 = s1.compute_intervention_surfaces("T", "Y").unwrap();
    let i2 = s2.compute_intervention_surfaces("T", "Y").unwrap();
    assert_eq!(i1, i2);
}

#[test]
fn enrichment_report_deterministic() {
    let r1 = confounded_dag().report();
    let r2 = confounded_dag().report();
    assert_eq!(r1, r2);
}
