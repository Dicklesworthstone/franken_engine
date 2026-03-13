//! Enrichment integration tests for `structural_causal_model`.
//!
//! Covers: Copy/Clone semantics, BTreeSet ordering, serde roundtrips, Display
//! coverage, Debug nonempty, std::error::Error trait, JSON field-name stability,
//! DAG construction/traversal, confounder analysis, backdoor criterion,
//! intervention surfaces, do-intervention, ATE estimation, attribution
//! decomposition, topological sort, all_directed_paths.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::structural_causal_model::{
    AttributionDecomposition, BackdoorResult, CausalEdge, CausalEffect, CausalNode,
    ClassifiedConfounder, ConfounderClass, EdgeSign, Intervention, InterventionSurface,
    NodeRole, Observation, PathwayContribution, ScmError, StructuralCausalModel, VariableDomain,
};

// ── Helpers ──────────────────────────────────────────────────────────

fn make_node(id: &str, role: NodeRole, domain: VariableDomain) -> CausalNode {
    CausalNode {
        id: id.to_string(),
        label: format!("node_{id}"),
        role,
        domain,
        observable: true,
        fixed_value_millionths: None,
    }
}

fn make_edge(source: &str, target: &str) -> CausalEdge {
    CausalEdge {
        source: source.to_string(),
        target: target.to_string(),
        sign: EdgeSign::Positive,
        strength_millionths: 500_000,
        mechanism: format!("{source} -> {target}"),
    }
}

/// Build a simple DAG: confounder C -> T (treatment), C -> Y (outcome), T -> Y
fn build_simple_confounded_dag() -> StructuralCausalModel {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(make_node("C", NodeRole::Confounder, VariableDomain::WorkloadCharacteristic))
        .unwrap();
    scm.add_node(make_node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    scm.add_node(make_node("Y", NodeRole::Outcome, VariableDomain::ObservedOutcome))
        .unwrap();
    scm.add_edge(make_edge("C", "T")).unwrap();
    scm.add_edge(make_edge("C", "Y")).unwrap();
    scm.add_edge(make_edge("T", "Y")).unwrap();
    scm
}

// -----------------------------------------------------------------------
// 1. Copy semantics for Copy types
// -----------------------------------------------------------------------

#[test]
fn enrichment_node_role_copy() {
    let a = NodeRole::Exogenous;
    let b = a;
    assert_eq!(a, b);
    let c = NodeRole::Treatment;
    let d = c;
    assert_eq!(c, d);
}

#[test]
fn enrichment_variable_domain_copy() {
    let a = VariableDomain::LaneChoice;
    let b = a;
    assert_eq!(a, b);
    let c = VariableDomain::Regime;
    let d = c;
    assert_eq!(c, d);
}

#[test]
fn enrichment_edge_sign_copy() {
    let a = EdgeSign::Positive;
    let b = a;
    assert_eq!(a, b);
    let c = EdgeSign::Ambiguous;
    let d = c;
    assert_eq!(c, d);
}

#[test]
fn enrichment_confounder_class_copy() {
    let a = ConfounderClass::Observable;
    let b = a;
    assert_eq!(a, b);
    let c = ConfounderClass::Collider;
    let d = c;
    assert_eq!(c, d);
}

// -----------------------------------------------------------------------
// 2. Clone independence
// -----------------------------------------------------------------------

#[test]
fn enrichment_causal_node_clone_independence() {
    let a = make_node("T", NodeRole::Treatment, VariableDomain::LaneChoice);
    let mut b = a.clone();
    b.id = "T2".to_string();
    b.observable = false;
    assert_eq!(a.id, "T");
    assert!(a.observable);
}

#[test]
fn enrichment_causal_edge_clone_independence() {
    let a = make_edge("A", "B");
    let mut b = a.clone();
    b.source = "X".to_string();
    b.strength_millionths = 999_999;
    assert_eq!(a.source, "A");
    assert_eq!(a.strength_millionths, 500_000);
}

#[test]
fn enrichment_classified_confounder_clone_independence() {
    let a = ClassifiedConfounder {
        node_id: "C".to_string(),
        class: ConfounderClass::Observable,
        adjusted: true,
        bias_bound_millionths: 100_000,
        description: "test".to_string(),
    };
    let mut b = a.clone();
    b.node_id = "C2".to_string();
    b.adjusted = false;
    assert_eq!(a.node_id, "C");
    assert!(a.adjusted);
}

#[test]
fn enrichment_scm_clone_independence() {
    let a = build_simple_confounded_dag();
    let mut b = a.clone();
    b.add_node(make_node("Z", NodeRole::Exogenous, VariableDomain::EnvironmentFactor))
        .unwrap();
    assert!(a.node("Z").is_none());
    assert!(b.node("Z").is_some());
}

// -----------------------------------------------------------------------
// 3. BTreeSet ordering
// -----------------------------------------------------------------------

#[test]
fn enrichment_node_role_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(NodeRole::Outcome);
    set.insert(NodeRole::Treatment);
    set.insert(NodeRole::Exogenous);
    set.insert(NodeRole::Treatment); // duplicate
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_variable_domain_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(VariableDomain::Regime);
    set.insert(VariableDomain::LaneChoice);
    set.insert(VariableDomain::CalibrationMetric);
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_edge_sign_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(EdgeSign::Negative);
    set.insert(EdgeSign::Positive);
    set.insert(EdgeSign::Ambiguous);
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_confounder_class_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(ConfounderClass::Collider);
    set.insert(ConfounderClass::Observable);
    set.insert(ConfounderClass::Latent);
    set.insert(ConfounderClass::TimeVarying);
    assert_eq!(set.len(), 4);
}

// -----------------------------------------------------------------------
// 4. Serde roundtrips
// -----------------------------------------------------------------------

#[test]
fn enrichment_node_role_serde_roundtrip() {
    let roles = [
        NodeRole::Exogenous,
        NodeRole::Endogenous,
        NodeRole::Treatment,
        NodeRole::Outcome,
        NodeRole::Confounder,
        NodeRole::Mediator,
        NodeRole::Instrument,
    ];
    for role in roles {
        let json = serde_json::to_string(&role).unwrap();
        let back: NodeRole = serde_json::from_str(&json).unwrap();
        assert_eq!(back, role);
    }
}

#[test]
fn enrichment_variable_domain_serde_roundtrip() {
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
    for d in domains {
        let json = serde_json::to_string(&d).unwrap();
        let back: VariableDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);
    }
}

#[test]
fn enrichment_edge_sign_serde_roundtrip() {
    for sign in [EdgeSign::Positive, EdgeSign::Negative, EdgeSign::Ambiguous] {
        let json = serde_json::to_string(&sign).unwrap();
        let back: EdgeSign = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sign);
    }
}

#[test]
fn enrichment_confounder_class_serde_roundtrip() {
    let classes = [
        ConfounderClass::Observable,
        ConfounderClass::Latent,
        ConfounderClass::TimeVarying,
        ConfounderClass::Collider,
    ];
    for c in classes {
        let json = serde_json::to_string(&c).unwrap();
        let back: ConfounderClass = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
    }
}

#[test]
fn enrichment_causal_node_serde_roundtrip() {
    let node = make_node("T", NodeRole::Treatment, VariableDomain::LaneChoice);
    let json = serde_json::to_string(&node).unwrap();
    let back: CausalNode = serde_json::from_str(&json).unwrap();
    assert_eq!(back, node);
}

#[test]
fn enrichment_causal_edge_serde_roundtrip() {
    let edge = make_edge("A", "B");
    let json = serde_json::to_string(&edge).unwrap();
    let back: CausalEdge = serde_json::from_str(&json).unwrap();
    assert_eq!(back, edge);
}

#[test]
fn enrichment_classified_confounder_serde_roundtrip() {
    let cc = ClassifiedConfounder {
        node_id: "C".to_string(),
        class: ConfounderClass::Observable,
        adjusted: true,
        bias_bound_millionths: 50_000,
        description: "test confounder".to_string(),
    };
    let json = serde_json::to_string(&cc).unwrap();
    let back: ClassifiedConfounder = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cc);
}

#[test]
fn enrichment_intervention_serde_roundtrip() {
    let iv = Intervention {
        node_id: "T".to_string(),
        value_millionths: 1_000_000,
        description: "set treatment to 1".to_string(),
    };
    let json = serde_json::to_string(&iv).unwrap();
    let back: Intervention = serde_json::from_str(&json).unwrap();
    assert_eq!(back, iv);
}

#[test]
fn enrichment_intervention_surface_serde_roundtrip() {
    let surface = InterventionSurface {
        name: "test_surface".to_string(),
        node_ids: BTreeSet::from(["T".to_string()]),
        sufficient_for_identification: true,
        justification: "test justification".to_string(),
    };
    let json = serde_json::to_string(&surface).unwrap();
    let back: InterventionSurface = serde_json::from_str(&json).unwrap();
    assert_eq!(back, surface);
}

#[test]
fn enrichment_backdoor_result_serde_roundtrip() {
    let br = BackdoorResult {
        treatment: "T".to_string(),
        outcome: "Y".to_string(),
        adjustment_set: BTreeSet::from(["C".to_string()]),
        identified: true,
        confounding_paths: vec![vec!["T".to_string(), "C".to_string(), "Y".to_string()]],
    };
    let json = serde_json::to_string(&br).unwrap();
    let back: BackdoorResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, br);
}

#[test]
fn enrichment_causal_effect_serde_roundtrip() {
    let ce = CausalEffect {
        treatment: "T".to_string(),
        outcome: "Y".to_string(),
        ate_millionths: 250_000,
        adjustment_set: BTreeSet::new(),
        sample_size: 100,
        identified: true,
    };
    let json = serde_json::to_string(&ce).unwrap();
    let back: CausalEffect = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ce);
}

#[test]
fn enrichment_pathway_contribution_serde_roundtrip() {
    let pc = PathwayContribution {
        path: vec!["T".to_string(), "Y".to_string()],
        effect_millionths: 500_000,
        fraction_millionths: 1_000_000,
    };
    let json = serde_json::to_string(&pc).unwrap();
    let back: PathwayContribution = serde_json::from_str(&json).unwrap();
    assert_eq!(back, pc);
}

#[test]
fn enrichment_attribution_decomposition_serde_roundtrip() {
    let ad = AttributionDecomposition {
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
    let json = serde_json::to_string(&ad).unwrap();
    let back: AttributionDecomposition = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ad);
}

#[test]
fn enrichment_observation_serde_roundtrip() {
    let mut values = BTreeMap::new();
    values.insert("T".to_string(), 1_000_000i64);
    values.insert("Y".to_string(), 500_000i64);
    let obs = Observation {
        epoch: 1,
        tick: 42,
        values,
    };
    let json = serde_json::to_string(&obs).unwrap();
    let back: Observation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, obs);
}

#[test]
fn enrichment_scm_error_serde_roundtrip() {
    let errors = [
        ScmError::NodeNotFound("X".to_string()),
        ScmError::DuplicateNode("X".to_string()),
        ScmError::EdgeAlreadyExists {
            source: "A".to_string(),
            target: "B".to_string(),
        },
        ScmError::CycleDetected {
            path: vec!["A".to_string(), "B".to_string()],
        },
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
fn enrichment_scm_serde_roundtrip() {
    let scm = build_simple_confounded_dag();
    let json = serde_json::to_string(&scm).unwrap();
    let back: StructuralCausalModel = serde_json::from_str(&json).unwrap();
    assert_eq!(back, scm);
}

// -----------------------------------------------------------------------
// 5. Display coverage
// -----------------------------------------------------------------------

#[test]
fn enrichment_scm_error_display_all_variants() {
    let errors = [
        ScmError::NodeNotFound("X".to_string()),
        ScmError::DuplicateNode("X".to_string()),
        ScmError::EdgeAlreadyExists {
            source: "A".to_string(),
            target: "B".to_string(),
        },
        ScmError::CycleDetected {
            path: vec!["A".to_string(), "B".to_string()],
        },
        ScmError::NoTreatmentNode,
        ScmError::NoOutcomeNode,
        ScmError::InsufficientObservations {
            required: 10,
            available: 5,
        },
        ScmError::NotIdentified {
            reason: "test reason".to_string(),
        },
    ];
    for err in &errors {
        let s = err.to_string();
        assert!(!s.is_empty(), "Display for {:?} is empty", err);
    }
}

// -----------------------------------------------------------------------
// 6. std::error::Error trait
// -----------------------------------------------------------------------

#[test]
fn enrichment_scm_error_implements_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(ScmError::NoTreatmentNode);
    assert!(!err.to_string().is_empty());
}

// -----------------------------------------------------------------------
// 7. Debug nonempty
// -----------------------------------------------------------------------

#[test]
fn enrichment_node_role_debug() {
    let roles = [
        NodeRole::Exogenous,
        NodeRole::Endogenous,
        NodeRole::Treatment,
        NodeRole::Outcome,
        NodeRole::Confounder,
        NodeRole::Mediator,
        NodeRole::Instrument,
    ];
    for r in roles {
        assert!(!format!("{r:?}").is_empty());
    }
}

#[test]
fn enrichment_variable_domain_debug() {
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
    for d in domains {
        assert!(!format!("{d:?}").is_empty());
    }
}

#[test]
fn enrichment_edge_sign_debug() {
    for s in [EdgeSign::Positive, EdgeSign::Negative, EdgeSign::Ambiguous] {
        assert!(!format!("{s:?}").is_empty());
    }
}

#[test]
fn enrichment_causal_node_debug() {
    let n = make_node("T", NodeRole::Treatment, VariableDomain::LaneChoice);
    assert!(!format!("{n:?}").is_empty());
}

#[test]
fn enrichment_causal_edge_debug() {
    let e = make_edge("A", "B");
    assert!(!format!("{e:?}").is_empty());
}

#[test]
fn enrichment_scm_debug() {
    let scm = StructuralCausalModel::new();
    assert!(!format!("{scm:?}").is_empty());
}

// -----------------------------------------------------------------------
// 8. DAG construction
// -----------------------------------------------------------------------

#[test]
fn enrichment_scm_new_is_empty() {
    let scm = StructuralCausalModel::new();
    assert!(scm.nodes().is_empty());
    assert!(scm.edges().is_empty());
    assert_eq!(scm.observation_count(), 0);
}

#[test]
fn enrichment_add_node() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(make_node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    assert_eq!(scm.nodes().len(), 1);
    let n = scm.node("T").unwrap();
    assert_eq!(n.role, NodeRole::Treatment);
}

#[test]
fn enrichment_add_duplicate_node_error() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(make_node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    let err = scm
        .add_node(make_node("T", NodeRole::Outcome, VariableDomain::ObservedOutcome))
        .unwrap_err();
    assert!(matches!(err, ScmError::DuplicateNode(_)));
}

#[test]
fn enrichment_add_edge() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(make_node("A", NodeRole::Exogenous, VariableDomain::EnvironmentFactor))
        .unwrap();
    scm.add_node(make_node("B", NodeRole::Endogenous, VariableDomain::RiskBelief))
        .unwrap();
    scm.add_edge(make_edge("A", "B")).unwrap();
    assert_eq!(scm.edges().len(), 1);
}

#[test]
fn enrichment_add_edge_missing_node() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(make_node("A", NodeRole::Exogenous, VariableDomain::EnvironmentFactor))
        .unwrap();
    let err = scm.add_edge(make_edge("A", "MISSING")).unwrap_err();
    assert!(matches!(err, ScmError::NodeNotFound(_)));
}

#[test]
fn enrichment_add_edge_duplicate_error() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(make_node("A", NodeRole::Exogenous, VariableDomain::EnvironmentFactor))
        .unwrap();
    scm.add_node(make_node("B", NodeRole::Endogenous, VariableDomain::RiskBelief))
        .unwrap();
    scm.add_edge(make_edge("A", "B")).unwrap();
    let err = scm.add_edge(make_edge("A", "B")).unwrap_err();
    assert!(matches!(err, ScmError::EdgeAlreadyExists { .. }));
}

#[test]
fn enrichment_add_edge_cycle_detected() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(make_node("A", NodeRole::Exogenous, VariableDomain::EnvironmentFactor))
        .unwrap();
    scm.add_node(make_node("B", NodeRole::Endogenous, VariableDomain::RiskBelief))
        .unwrap();
    scm.add_edge(make_edge("A", "B")).unwrap();
    let err = scm.add_edge(make_edge("B", "A")).unwrap_err();
    assert!(matches!(err, ScmError::CycleDetected { .. }));
}

// -----------------------------------------------------------------------
// 9. DAG traversal
// -----------------------------------------------------------------------

#[test]
fn enrichment_children_of() {
    let scm = build_simple_confounded_dag();
    let children = scm.children_of("C");
    assert!(children.contains("T"));
    assert!(children.contains("Y"));
    assert_eq!(children.len(), 2);
}

#[test]
fn enrichment_parents_of() {
    let scm = build_simple_confounded_dag();
    let parents = scm.parents_of("Y");
    assert!(parents.contains("C"));
    assert!(parents.contains("T"));
    assert_eq!(parents.len(), 2);
}

#[test]
fn enrichment_ancestors_of() {
    let scm = build_simple_confounded_dag();
    let ancestors = scm.ancestors_of("Y");
    assert!(ancestors.contains("C"));
    assert!(ancestors.contains("T"));
}

#[test]
fn enrichment_descendants_of() {
    let scm = build_simple_confounded_dag();
    let descendants = scm.descendants_of("C");
    assert!(descendants.contains("T"));
    assert!(descendants.contains("Y"));
}

#[test]
fn enrichment_has_path() {
    let scm = build_simple_confounded_dag();
    assert!(scm.has_path(&"C".to_string(), &"Y".to_string()));
    assert!(scm.has_path(&"T".to_string(), &"Y".to_string()));
    assert!(!scm.has_path(&"Y".to_string(), &"C".to_string()));
}

#[test]
fn enrichment_children_of_missing_node() {
    let scm = StructuralCausalModel::new();
    let children = scm.children_of("MISSING");
    assert!(children.is_empty());
}

// -----------------------------------------------------------------------
// 10. Topological order
// -----------------------------------------------------------------------

#[test]
fn enrichment_topological_order() {
    let scm = build_simple_confounded_dag();
    let order = scm.topological_order();
    assert_eq!(order.len(), 3);
    // C must come before T and Y; T must come before Y
    let pos_c = order.iter().position(|x| x == "C").unwrap();
    let pos_t = order.iter().position(|x| x == "T").unwrap();
    let pos_y = order.iter().position(|x| x == "Y").unwrap();
    assert!(pos_c < pos_t);
    assert!(pos_c < pos_y);
    assert!(pos_t < pos_y);
}

#[test]
fn enrichment_topological_order_empty() {
    let scm = StructuralCausalModel::new();
    let order = scm.topological_order();
    assert!(order.is_empty());
}

// -----------------------------------------------------------------------
// 11. All directed paths
// -----------------------------------------------------------------------

#[test]
fn enrichment_all_directed_paths_simple() {
    let scm = build_simple_confounded_dag();
    let paths = scm.all_directed_paths("C", "Y");
    // C->Y (direct) and C->T->Y (indirect)
    assert_eq!(paths.len(), 2);
}

#[test]
fn enrichment_all_directed_paths_none() {
    let scm = build_simple_confounded_dag();
    let paths = scm.all_directed_paths("Y", "C");
    assert!(paths.is_empty());
}

#[test]
fn enrichment_all_directed_paths_direct() {
    let scm = build_simple_confounded_dag();
    let paths = scm.all_directed_paths("T", "Y");
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0], vec!["T".to_string(), "Y".to_string()]);
}

// -----------------------------------------------------------------------
// 12. Confounder analysis
// -----------------------------------------------------------------------

#[test]
fn enrichment_classify_confounders() {
    let mut scm = build_simple_confounded_dag();
    let confounders = scm.classify_confounders("T", "Y").unwrap();
    assert!(!confounders.is_empty());
    assert!(confounders.iter().any(|c| c.node_id == "C"));
}

#[test]
fn enrichment_classify_confounders_node_not_found() {
    let mut scm = build_simple_confounded_dag();
    let err = scm.classify_confounders("MISSING", "Y").unwrap_err();
    assert!(matches!(err, ScmError::NodeNotFound(_)));
}

#[test]
fn enrichment_classify_confounders_no_confounders() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(make_node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    scm.add_node(make_node("Y", NodeRole::Outcome, VariableDomain::ObservedOutcome))
        .unwrap();
    scm.add_edge(make_edge("T", "Y")).unwrap();
    let confounders = scm.classify_confounders("T", "Y").unwrap();
    assert!(confounders.is_empty());
}

#[test]
fn enrichment_classify_latent_confounder() {
    let mut scm = StructuralCausalModel::new();
    let mut latent = make_node("U", NodeRole::Confounder, VariableDomain::WorkloadCharacteristic);
    latent.observable = false;
    scm.add_node(latent).unwrap();
    scm.add_node(make_node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    scm.add_node(make_node("Y", NodeRole::Outcome, VariableDomain::ObservedOutcome))
        .unwrap();
    scm.add_edge(make_edge("U", "T")).unwrap();
    scm.add_edge(make_edge("U", "Y")).unwrap();
    scm.add_edge(make_edge("T", "Y")).unwrap();
    let confounders = scm.classify_confounders("T", "Y").unwrap();
    assert!(confounders.iter().any(|c| c.class == ConfounderClass::Latent));
}

#[test]
fn enrichment_classify_time_varying_confounder() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(make_node("R", NodeRole::Confounder, VariableDomain::Regime))
        .unwrap();
    scm.add_node(make_node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    scm.add_node(make_node("Y", NodeRole::Outcome, VariableDomain::ObservedOutcome))
        .unwrap();
    scm.add_edge(make_edge("R", "T")).unwrap();
    scm.add_edge(make_edge("R", "Y")).unwrap();
    scm.add_edge(make_edge("T", "Y")).unwrap();
    let confounders = scm.classify_confounders("T", "Y").unwrap();
    assert!(confounders
        .iter()
        .any(|c| c.class == ConfounderClass::TimeVarying));
}

// -----------------------------------------------------------------------
// 13. Backdoor criterion
// -----------------------------------------------------------------------

#[test]
fn enrichment_backdoor_criterion_confounded() {
    let scm = build_simple_confounded_dag();
    let result = scm.backdoor_criterion("T", "Y").unwrap();
    assert!(result.identified);
    assert!(!result.adjustment_set.is_empty());
    assert!(result.adjustment_set.contains("C"));
}

#[test]
fn enrichment_backdoor_criterion_no_confounding() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(make_node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    scm.add_node(make_node("Y", NodeRole::Outcome, VariableDomain::ObservedOutcome))
        .unwrap();
    scm.add_edge(make_edge("T", "Y")).unwrap();
    let result = scm.backdoor_criterion("T", "Y").unwrap();
    assert!(result.identified);
    assert!(result.adjustment_set.is_empty());
    assert!(result.confounding_paths.is_empty());
}

#[test]
fn enrichment_backdoor_criterion_node_not_found() {
    let scm = StructuralCausalModel::new();
    let err = scm.backdoor_criterion("MISSING", "Y").unwrap_err();
    assert!(matches!(err, ScmError::NodeNotFound(_)));
}

// -----------------------------------------------------------------------
// 14. do-intervention
// -----------------------------------------------------------------------

#[test]
fn enrichment_do_intervention_removes_incoming_edges() {
    let scm = build_simple_confounded_dag();
    let intervention = Intervention {
        node_id: "T".to_string(),
        value_millionths: 1_000_000,
        description: "set treatment to 1".to_string(),
    };
    let mutated = scm.do_intervention(&intervention).unwrap();
    // T should have no parents in the mutated model
    assert!(mutated.parents_of("T").is_empty());
    // T should still have children (T->Y)
    assert!(mutated.children_of("T").contains("Y"));
    // T's value should be fixed
    assert_eq!(
        mutated.node("T").unwrap().fixed_value_millionths,
        Some(1_000_000)
    );
}

#[test]
fn enrichment_do_intervention_node_not_found() {
    let scm = StructuralCausalModel::new();
    let iv = Intervention {
        node_id: "MISSING".to_string(),
        value_millionths: 0,
        description: "".to_string(),
    };
    let err = scm.do_intervention(&iv).unwrap_err();
    assert!(matches!(err, ScmError::NodeNotFound(_)));
}

// -----------------------------------------------------------------------
// 15. Intervention surfaces
// -----------------------------------------------------------------------

#[test]
fn enrichment_compute_intervention_surfaces() {
    let mut scm = build_simple_confounded_dag();
    let surfaces = scm.compute_intervention_surfaces("T", "Y").unwrap();
    // At least direct intervention surface
    assert!(!surfaces.is_empty());
    assert!(surfaces.iter().any(|s| s.name.contains("direct_intervention")));
    // Backdoor adjustment surface should also exist
    assert!(surfaces.iter().any(|s| s.name.contains("backdoor_adjustment")));
}

#[test]
fn enrichment_intervention_surfaces_with_instrument() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(make_node("Z", NodeRole::Instrument, VariableDomain::EnvironmentFactor))
        .unwrap();
    scm.add_node(make_node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    scm.add_node(make_node("Y", NodeRole::Outcome, VariableDomain::ObservedOutcome))
        .unwrap();
    scm.add_edge(make_edge("Z", "T")).unwrap();
    scm.add_edge(make_edge("T", "Y")).unwrap();
    let surfaces = scm.compute_intervention_surfaces("T", "Y").unwrap();
    assert!(surfaces.iter().any(|s| s.name.contains("instrumental_variable")));
}

// -----------------------------------------------------------------------
// 16. ATE estimation — simple difference in means
// -----------------------------------------------------------------------

#[test]
fn enrichment_estimate_ate_no_confounding() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(make_node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    scm.add_node(make_node("Y", NodeRole::Outcome, VariableDomain::ObservedOutcome))
        .unwrap();
    scm.add_edge(make_edge("T", "Y")).unwrap();

    // Add observations: treated (T=1_000_000) -> Y=800_000, control (T=0) -> Y=300_000
    for _ in 0..5 {
        let mut vals = BTreeMap::new();
        vals.insert("T".to_string(), 1_000_000i64);
        vals.insert("Y".to_string(), 800_000i64);
        scm.record_observation(Observation {
            epoch: 1,
            tick: 0,
            values: vals,
        });
    }
    for _ in 0..5 {
        let mut vals = BTreeMap::new();
        vals.insert("T".to_string(), 0i64);
        vals.insert("Y".to_string(), 300_000i64);
        scm.record_observation(Observation {
            epoch: 1,
            tick: 0,
            values: vals,
        });
    }

    let effect = scm
        .estimate_ate("T", "Y", 1_000_000, 0, 5)
        .unwrap();
    assert_eq!(effect.ate_millionths, 500_000); // 800_000 - 300_000
    assert!(effect.identified);
    assert_eq!(effect.sample_size, 10);
}

#[test]
fn enrichment_estimate_ate_insufficient_observations() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(make_node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    scm.add_node(make_node("Y", NodeRole::Outcome, VariableDomain::ObservedOutcome))
        .unwrap();
    scm.add_edge(make_edge("T", "Y")).unwrap();
    let err = scm.estimate_ate("T", "Y", 1_000_000, 0, 10).unwrap_err();
    assert!(matches!(
        err,
        ScmError::InsufficientObservations { .. }
    ));
}

#[test]
fn enrichment_estimate_ate_node_not_found() {
    let scm = StructuralCausalModel::new();
    let err = scm.estimate_ate("MISSING", "Y", 0, 0, 0).unwrap_err();
    assert!(matches!(err, ScmError::NodeNotFound(_)));
}

// -----------------------------------------------------------------------
// 17. Attribution decomposition
// -----------------------------------------------------------------------

#[test]
fn enrichment_decompose_attribution_single_path() {
    let mut scm = StructuralCausalModel::new();
    scm.add_node(make_node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
        .unwrap();
    scm.add_node(make_node("Y", NodeRole::Outcome, VariableDomain::ObservedOutcome))
        .unwrap();
    scm.add_edge(make_edge("T", "Y")).unwrap();
    let decomp = scm.decompose_attribution("T", "Y", 1_000_000).unwrap();
    assert_eq!(decomp.pathways.len(), 1);
    assert_eq!(decomp.pathways[0].fraction_millionths, 1_000_000);
    assert_eq!(decomp.treatment, "T");
    assert_eq!(decomp.outcome, "Y");
}

#[test]
fn enrichment_decompose_attribution_multiple_paths() {
    let scm = build_simple_confounded_dag();
    // C->Y direct and C->T->Y indirect
    let decomp = scm.decompose_attribution("C", "Y", 1_000_000).unwrap();
    assert_eq!(decomp.pathways.len(), 2);
    let total_fraction: i64 = decomp.pathways.iter().map(|p| p.fraction_millionths).sum();
    assert!(total_fraction > 0);
}

#[test]
fn enrichment_decompose_attribution_no_path() {
    let scm = build_simple_confounded_dag();
    let decomp = scm.decompose_attribution("Y", "C", 1_000_000).unwrap();
    assert!(decomp.pathways.is_empty());
    assert_eq!(decomp.residual_millionths, 1_000_000);
}

#[test]
fn enrichment_decompose_attribution_node_not_found() {
    let scm = StructuralCausalModel::new();
    let err = scm.decompose_attribution("MISSING", "Y", 0).unwrap_err();
    assert!(matches!(err, ScmError::NodeNotFound(_)));
}

// -----------------------------------------------------------------------
// 18. Observations
// -----------------------------------------------------------------------

#[test]
fn enrichment_record_observation() {
    let mut scm = StructuralCausalModel::new();
    assert_eq!(scm.observation_count(), 0);
    let mut vals = BTreeMap::new();
    vals.insert("T".to_string(), 1_000_000i64);
    scm.record_observation(Observation {
        epoch: 1,
        tick: 0,
        values: vals,
    });
    assert_eq!(scm.observation_count(), 1);
    assert_eq!(scm.observations().len(), 1);
}

// -----------------------------------------------------------------------
// 19. JSON field-name stability
// -----------------------------------------------------------------------

#[test]
fn enrichment_causal_node_json_fields() {
    let n = make_node("T", NodeRole::Treatment, VariableDomain::LaneChoice);
    let json = serde_json::to_string(&n).unwrap();
    assert!(json.contains("\"id\""));
    assert!(json.contains("\"label\""));
    assert!(json.contains("\"role\""));
    assert!(json.contains("\"domain\""));
    assert!(json.contains("\"observable\""));
}

#[test]
fn enrichment_causal_edge_json_fields() {
    let e = make_edge("A", "B");
    let json = serde_json::to_string(&e).unwrap();
    assert!(json.contains("\"source\""));
    assert!(json.contains("\"target\""));
    assert!(json.contains("\"sign\""));
    assert!(json.contains("\"strength_millionths\""));
    assert!(json.contains("\"mechanism\""));
}

#[test]
fn enrichment_observation_json_fields() {
    let mut vals = BTreeMap::new();
    vals.insert("T".to_string(), 1_000_000i64);
    let obs = Observation {
        epoch: 1,
        tick: 42,
        values: vals,
    };
    let json = serde_json::to_string(&obs).unwrap();
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"tick\""));
    assert!(json.contains("\"values\""));
}

#[test]
fn enrichment_backdoor_result_json_fields() {
    let br = BackdoorResult {
        treatment: "T".to_string(),
        outcome: "Y".to_string(),
        adjustment_set: BTreeSet::new(),
        identified: true,
        confounding_paths: Vec::new(),
    };
    let json = serde_json::to_string(&br).unwrap();
    assert!(json.contains("\"treatment\""));
    assert!(json.contains("\"outcome\""));
    assert!(json.contains("\"adjustment_set\""));
    assert!(json.contains("\"identified\""));
    assert!(json.contains("\"confounding_paths\""));
}

#[test]
fn enrichment_causal_effect_json_fields() {
    let ce = CausalEffect {
        treatment: "T".to_string(),
        outcome: "Y".to_string(),
        ate_millionths: 0,
        adjustment_set: BTreeSet::new(),
        sample_size: 0,
        identified: true,
    };
    let json = serde_json::to_string(&ce).unwrap();
    assert!(json.contains("\"ate_millionths\""));
    assert!(json.contains("\"sample_size\""));
    assert!(json.contains("\"identified\""));
}

// -----------------------------------------------------------------------
// 20. Node lookup
// -----------------------------------------------------------------------

#[test]
fn enrichment_node_lookup_found() {
    let scm = build_simple_confounded_dag();
    assert!(scm.node("T").is_some());
    assert!(scm.node("C").is_some());
    assert!(scm.node("Y").is_some());
}

#[test]
fn enrichment_node_lookup_not_found() {
    let scm = StructuralCausalModel::new();
    assert!(scm.node("MISSING").is_none());
}

// -----------------------------------------------------------------------
// 21. Confounders accessor
// -----------------------------------------------------------------------

#[test]
fn enrichment_confounders_empty_before_classify() {
    let scm = build_simple_confounded_dag();
    assert!(scm.confounders().is_empty());
}

#[test]
fn enrichment_confounders_populated_after_classify() {
    let mut scm = build_simple_confounded_dag();
    scm.classify_confounders("T", "Y").unwrap();
    assert!(!scm.confounders().is_empty());
}

// -----------------------------------------------------------------------
// 22. Intervention surfaces accessor
// -----------------------------------------------------------------------

#[test]
fn enrichment_intervention_surfaces_empty_before_compute() {
    let scm = build_simple_confounded_dag();
    assert!(scm.intervention_surfaces().is_empty());
}

#[test]
fn enrichment_intervention_surfaces_populated_after_compute() {
    let mut scm = build_simple_confounded_dag();
    scm.compute_intervention_surfaces("T", "Y").unwrap();
    assert!(!scm.intervention_surfaces().is_empty());
}
