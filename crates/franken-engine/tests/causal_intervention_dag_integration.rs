//! Integration tests for the causal intervention DAG module.
//!
//! Tests the structural causal model construction, adjustment set computation,
//! identifiability certificates, and FrankenEngine optimization DAG.

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

use frankenengine_engine::causal_intervention_dag::{
    AdjustmentSet, CAUSAL_DAG_COMPONENT, CAUSAL_DAG_POLICY_ID, CAUSAL_DAG_SCHEMA_VERSION,
    CausalDag, CausalDagBuilder, CausalDagError, CausalDagEvidenceManifest, CausalEdge,
    CausalVariable, EdgeConfidence, EdgeKind, IdentifiabilityCertificate, IdentificationStrategy,
    MeasurementScale, Observability, UnidentifiableReason, VariableDomain,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn var(id: u32, name: &str, domain: VariableDomain) -> CausalVariable {
    CausalVariable {
        id,
        name: name.to_string(),
        domain,
        observability: Observability::Observable,
        scale: MeasurementScale::Binary,
        description: format!("{name} variable"),
        subsystem: "test".to_string(),
    }
}

fn edge(from: u32, to: u32, kind: EdgeKind) -> CausalEdge {
    CausalEdge {
        from,
        to,
        kind,
        confidence: EdgeConfidence::Structural,
        mechanism: format!("{from} -> {to}"),
    }
}

fn simple_confounded_dag() -> CausalDag {
    let mut b = CausalDagBuilder::new();
    // C -> T -> Y, C -> Y  (backdoor path via C)
    b.add_variable(var(1, "T", VariableDomain::Treatment))
        .unwrap();
    b.add_variable(var(2, "Y", VariableDomain::Outcome))
        .unwrap();
    b.add_variable(var(3, "C", VariableDomain::Confounder))
        .unwrap();
    b.add_edge(edge(1, 2, EdgeKind::Direct));
    b.add_edge(edge(3, 1, EdgeKind::Confounding));
    b.add_edge(edge(3, 2, EdgeKind::Confounding));
    b.build().unwrap()
}

fn chain_dag() -> CausalDag {
    // A -> B -> C -> D
    let mut b = CausalDagBuilder::new();
    b.add_variable(var(1, "A", VariableDomain::Treatment))
        .unwrap();
    b.add_variable(var(2, "B", VariableDomain::Mediator))
        .unwrap();
    b.add_variable(var(3, "C", VariableDomain::Mediator))
        .unwrap();
    b.add_variable(var(4, "D", VariableDomain::Outcome))
        .unwrap();
    b.add_edge(edge(1, 2, EdgeKind::Direct));
    b.add_edge(edge(2, 3, EdgeKind::Mediated));
    b.add_edge(edge(3, 4, EdgeKind::Mediated));
    b.build().unwrap()
}

fn diamond_dag() -> CausalDag {
    // T -> M1 -> Y, T -> M2 -> Y (two mediating paths)
    let mut b = CausalDagBuilder::new();
    b.add_variable(var(1, "T", VariableDomain::Treatment))
        .unwrap();
    b.add_variable(var(2, "M1", VariableDomain::Mediator))
        .unwrap();
    b.add_variable(var(3, "M2", VariableDomain::Mediator))
        .unwrap();
    b.add_variable(var(4, "Y", VariableDomain::Outcome))
        .unwrap();
    b.add_edge(edge(1, 2, EdgeKind::Direct));
    b.add_edge(edge(1, 3, EdgeKind::Direct));
    b.add_edge(edge(2, 4, EdgeKind::Mediated));
    b.add_edge(edge(3, 4, EdgeKind::Mediated));
    b.build().unwrap()
}

// ===========================================================================
// Section 1: Schema Constants
// ===========================================================================

#[test]
fn integration_schema_version_nonempty() {
    assert!(!CAUSAL_DAG_SCHEMA_VERSION.is_empty());
    assert!(CAUSAL_DAG_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn integration_component_name() {
    assert_eq!(CAUSAL_DAG_COMPONENT, "causal_intervention_dag");
}

#[test]
fn integration_policy_id() {
    assert_eq!(CAUSAL_DAG_POLICY_ID, "RGC-615A");
}

// ===========================================================================
// Section 2: VariableDomain
// ===========================================================================

#[test]
fn integration_variable_domain_all_covered() {
    assert_eq!(VariableDomain::ALL.len(), 6);
}

#[test]
fn integration_variable_domain_as_str_unique() {
    let strs: Vec<&str> = VariableDomain::ALL.iter().map(|d| d.as_str()).collect();
    for (i, s) in strs.iter().enumerate() {
        for (j, s2) in strs.iter().enumerate() {
            if i != j {
                assert_ne!(s, s2, "domains {i} and {j} have same as_str");
            }
        }
    }
}

#[test]
fn integration_variable_domain_display_matches_as_str() {
    for domain in VariableDomain::ALL {
        assert_eq!(format!("{domain}"), domain.as_str());
    }
}

#[test]
fn integration_variable_domain_serde_all_variants() {
    for domain in VariableDomain::ALL {
        let json = serde_json::to_string(domain).unwrap();
        let back: VariableDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(*domain, back);
    }
}

// ===========================================================================
// Section 3: MeasurementScale & Observability Serde
// ===========================================================================

#[test]
fn integration_measurement_scale_serde() {
    for scale in [
        MeasurementScale::Binary,
        MeasurementScale::Ordinal,
        MeasurementScale::Continuous,
        MeasurementScale::Categorical,
    ] {
        let json = serde_json::to_string(&scale).unwrap();
        let back: MeasurementScale = serde_json::from_str(&json).unwrap();
        assert_eq!(scale, back);
    }
}

#[test]
fn integration_observability_serde() {
    for obs in [
        Observability::Observable,
        Observability::Latent,
        Observability::Proxy,
    ] {
        let json = serde_json::to_string(&obs).unwrap();
        let back: Observability = serde_json::from_str(&json).unwrap();
        assert_eq!(obs, back);
    }
}

// ===========================================================================
// Section 4: EdgeKind & EdgeConfidence Serde
// ===========================================================================

#[test]
fn integration_edge_kind_serde() {
    for kind in [
        EdgeKind::Direct,
        EdgeKind::Mediated,
        EdgeKind::Confounding,
        EdgeKind::Instrumental,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: EdgeKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

#[test]
fn integration_edge_confidence_serde() {
    for conf in [
        EdgeConfidence::Structural,
        EdgeConfidence::Empirical,
        EdgeConfidence::Hypothesized,
    ] {
        let json = serde_json::to_string(&conf).unwrap();
        let back: EdgeConfidence = serde_json::from_str(&json).unwrap();
        assert_eq!(conf, back);
    }
}

// ===========================================================================
// Section 5: DAG Builder — Error Cases
// ===========================================================================

#[test]
fn integration_builder_empty_dag_error() {
    let b = CausalDagBuilder::new();
    let err = b.build().unwrap_err();
    assert!(matches!(err, CausalDagError::EmptyDag));
    assert!(format!("{err}").contains("empty"));
}

#[test]
fn integration_builder_default_empty() {
    let b = CausalDagBuilder::default();
    assert!(matches!(b.build(), Err(CausalDagError::EmptyDag)));
}

#[test]
fn integration_builder_duplicate_variable() {
    let mut b = CausalDagBuilder::new();
    b.add_variable(var(1, "A", VariableDomain::Treatment))
        .unwrap();
    let err = b
        .add_variable(var(1, "B", VariableDomain::Outcome))
        .unwrap_err();
    assert!(matches!(err, CausalDagError::DuplicateVariable { id: 1 }));
}

#[test]
fn integration_builder_unknown_variable_from() {
    let mut b = CausalDagBuilder::new();
    b.add_variable(var(1, "A", VariableDomain::Treatment))
        .unwrap();
    b.add_edge(edge(99, 1, EdgeKind::Direct));
    let err = b.build().unwrap_err();
    assert!(matches!(err, CausalDagError::UnknownVariable { id: 99 }));
}

#[test]
fn integration_builder_unknown_variable_to() {
    let mut b = CausalDagBuilder::new();
    b.add_variable(var(1, "A", VariableDomain::Treatment))
        .unwrap();
    b.add_edge(edge(1, 99, EdgeKind::Direct));
    let err = b.build().unwrap_err();
    assert!(matches!(err, CausalDagError::UnknownVariable { id: 99 }));
}

#[test]
fn integration_builder_cycle_detection_simple() {
    let mut b = CausalDagBuilder::new();
    b.add_variable(var(1, "A", VariableDomain::Treatment))
        .unwrap();
    b.add_variable(var(2, "B", VariableDomain::Outcome))
        .unwrap();
    b.add_edge(edge(1, 2, EdgeKind::Direct));
    b.add_edge(edge(2, 1, EdgeKind::Direct));
    assert!(matches!(
        b.build(),
        Err(CausalDagError::CycleDetected { .. })
    ));
}

#[test]
fn integration_builder_cycle_detection_transitive() {
    let mut b = CausalDagBuilder::new();
    for i in 1..=4 {
        b.add_variable(var(i, &format!("V{i}"), VariableDomain::Treatment))
            .unwrap();
    }
    b.add_edge(edge(1, 2, EdgeKind::Direct));
    b.add_edge(edge(2, 3, EdgeKind::Direct));
    b.add_edge(edge(3, 4, EdgeKind::Direct));
    b.add_edge(edge(4, 1, EdgeKind::Direct)); // cycle: 1->2->3->4->1
    assert!(matches!(
        b.build(),
        Err(CausalDagError::CycleDetected { .. })
    ));
}

// ===========================================================================
// Section 6: DAG Builder — Success Cases
// ===========================================================================

#[test]
fn integration_builder_single_variable() {
    let mut b = CausalDagBuilder::new();
    b.add_variable(var(1, "Solo", VariableDomain::Treatment))
        .unwrap();
    let dag = b.build().unwrap();
    assert_eq!(dag.variable_count(), 1);
    assert_eq!(dag.edge_count(), 0);
}

#[test]
fn integration_builder_simple_confounded() {
    let dag = simple_confounded_dag();
    assert_eq!(dag.variable_count(), 3);
    assert_eq!(dag.edge_count(), 3);
}

#[test]
fn integration_builder_chain() {
    let dag = chain_dag();
    assert_eq!(dag.variable_count(), 4);
    assert_eq!(dag.edge_count(), 3);
}

#[test]
fn integration_builder_diamond() {
    let dag = diamond_dag();
    assert_eq!(dag.variable_count(), 4);
    assert_eq!(dag.edge_count(), 4);
}

#[test]
fn integration_builder_structure_hash_deterministic() {
    let d1 = simple_confounded_dag();
    let d2 = simple_confounded_dag();
    assert_eq!(d1.structure_hash, d2.structure_hash);
}

#[test]
fn integration_builder_different_dags_different_hashes() {
    let d1 = simple_confounded_dag();
    let d2 = chain_dag();
    assert_ne!(d1.structure_hash, d2.structure_hash);
}

// ===========================================================================
// Section 7: Graph Queries — ancestors
// ===========================================================================

#[test]
fn integration_ancestors_of_root() {
    let dag = chain_dag();
    let anc = dag.ancestors(1); // A has no parents
    assert!(anc.is_empty());
}

#[test]
fn integration_ancestors_of_leaf() {
    let dag = chain_dag();
    let anc = dag.ancestors(4); // D is leaf
    assert_eq!(anc.len(), 3); // A, B, C
    assert!(anc.contains(&1));
    assert!(anc.contains(&2));
    assert!(anc.contains(&3));
}

#[test]
fn integration_ancestors_confounded() {
    let dag = simple_confounded_dag();
    let anc = dag.ancestors(2); // outcome
    assert!(anc.contains(&1)); // treatment
    assert!(anc.contains(&3)); // confounder
}

#[test]
fn integration_ancestors_diamond_merge() {
    let dag = diamond_dag();
    let anc = dag.ancestors(4); // Y
    assert_eq!(anc.len(), 3); // T, M1, M2
}

// ===========================================================================
// Section 8: Graph Queries — descendants
// ===========================================================================

#[test]
fn integration_descendants_of_leaf() {
    let dag = chain_dag();
    let desc = dag.descendants(4); // D has no children
    assert!(desc.is_empty());
}

#[test]
fn integration_descendants_of_root() {
    let dag = chain_dag();
    let desc = dag.descendants(1); // A
    assert_eq!(desc.len(), 3); // B, C, D
    assert!(desc.contains(&2));
    assert!(desc.contains(&3));
    assert!(desc.contains(&4));
}

#[test]
fn integration_descendants_confounder_fan_out() {
    let dag = simple_confounded_dag();
    let desc = dag.descendants(3); // confounder
    assert!(desc.contains(&1)); // treatment
    assert!(desc.contains(&2)); // outcome
}

#[test]
fn integration_descendants_diamond_fan_in() {
    let dag = diamond_dag();
    let desc = dag.descendants(1); // T
    assert_eq!(desc.len(), 3); // M1, M2, Y
}

// ===========================================================================
// Section 9: Graph Queries — has_path
// ===========================================================================

#[test]
fn integration_has_path_self() {
    let dag = chain_dag();
    assert!(dag.has_path(1, 1));
}

#[test]
fn integration_has_path_direct() {
    let dag = chain_dag();
    assert!(dag.has_path(1, 2));
}

#[test]
fn integration_has_path_transitive() {
    let dag = chain_dag();
    assert!(dag.has_path(1, 4));
}

#[test]
fn integration_has_path_no_reverse() {
    let dag = chain_dag();
    assert!(!dag.has_path(4, 1));
}

#[test]
fn integration_has_path_disconnected() {
    let mut b = CausalDagBuilder::new();
    b.add_variable(var(1, "A", VariableDomain::Treatment))
        .unwrap();
    b.add_variable(var(2, "B", VariableDomain::Outcome))
        .unwrap();
    let dag = b.build().unwrap();
    assert!(!dag.has_path(1, 2));
    assert!(!dag.has_path(2, 1));
}

// ===========================================================================
// Section 10: Graph Queries — variables_by_domain
// ===========================================================================

#[test]
fn integration_variables_by_domain_treatment() {
    let dag = simple_confounded_dag();
    let t = dag.variables_by_domain(VariableDomain::Treatment);
    assert_eq!(t, vec![1]);
}

#[test]
fn integration_variables_by_domain_multiple() {
    let dag = diamond_dag();
    let m = dag.variables_by_domain(VariableDomain::Mediator);
    assert_eq!(m.len(), 2);
}

#[test]
fn integration_variables_by_domain_empty() {
    let dag = simple_confounded_dag();
    let instruments = dag.variables_by_domain(VariableDomain::Instrument);
    assert!(instruments.is_empty());
}

// ===========================================================================
// Section 11: Backdoor Adjustment
// ===========================================================================

#[test]
fn integration_backdoor_adjustment_valid_with_confounder() {
    let dag = simple_confounded_dag();
    let adj = dag.backdoor_adjustment(1, 2);
    assert!(adj.is_valid);
    assert!(adj.variables.contains(&3)); // must condition on C
    assert_eq!(adj.treatment, 1);
    assert_eq!(adj.outcome, 2);
    assert!(adj.reason.is_none());
}

#[test]
fn integration_backdoor_adjustment_no_confounders() {
    let dag = chain_dag();
    let adj = dag.backdoor_adjustment(1, 4);
    assert!(adj.is_valid);
    assert!(adj.variables.is_empty()); // no confounders
}

#[test]
fn integration_backdoor_adjustment_latent_confounder() {
    let mut b = CausalDagBuilder::new();
    b.add_variable(var(1, "T", VariableDomain::Treatment))
        .unwrap();
    b.add_variable(var(2, "Y", VariableDomain::Outcome))
        .unwrap();
    b.add_variable(CausalVariable {
        id: 3,
        name: "U".to_string(),
        domain: VariableDomain::Confounder,
        observability: Observability::Latent, // latent!
        scale: MeasurementScale::Categorical,
        description: "latent confounder".to_string(),
        subsystem: "test".to_string(),
    })
    .unwrap();
    b.add_edge(edge(1, 2, EdgeKind::Direct));
    b.add_edge(edge(3, 1, EdgeKind::Confounding));
    b.add_edge(edge(3, 2, EdgeKind::Confounding));
    let dag = b.build().unwrap();
    let adj = dag.backdoor_adjustment(1, 2);
    // Latent confounder can't be conditioned on
    assert!(!adj.is_valid);
    assert!(adj.reason.is_some());
}

#[test]
fn integration_backdoor_adjustment_serde() {
    let dag = simple_confounded_dag();
    let adj = dag.backdoor_adjustment(1, 2);
    let json = serde_json::to_string(&adj).unwrap();
    let back: AdjustmentSet = serde_json::from_str(&json).unwrap();
    assert_eq!(adj, back);
}

// ===========================================================================
// Section 12: Front-door Identification
// ===========================================================================

#[test]
fn integration_front_door_mediator_found() {
    let mut b = CausalDagBuilder::new();
    b.add_variable(var(1, "T", VariableDomain::Treatment))
        .unwrap();
    b.add_variable(var(2, "Y", VariableDomain::Outcome))
        .unwrap();
    b.add_variable(var(3, "M", VariableDomain::Mediator))
        .unwrap();
    b.add_variable(CausalVariable {
        id: 4,
        name: "U".to_string(),
        domain: VariableDomain::Confounder,
        observability: Observability::Latent,
        scale: MeasurementScale::Categorical,
        description: "latent confounder".to_string(),
        subsystem: "test".to_string(),
    })
    .unwrap();
    b.add_edge(edge(1, 3, EdgeKind::Direct)); // T -> M
    b.add_edge(edge(3, 2, EdgeKind::Mediated)); // M -> Y
    b.add_edge(edge(4, 1, EdgeKind::Confounding)); // U -> T
    b.add_edge(edge(4, 2, EdgeKind::Confounding)); // U -> Y
    let dag = b.build().unwrap();
    let mediator = dag.front_door_mediator(1, 2);
    assert_eq!(mediator, Some(3));
}

#[test]
fn integration_front_door_no_mediator() {
    let dag = simple_confounded_dag();
    let mediator = dag.front_door_mediator(1, 2);
    assert!(mediator.is_none()); // no mediator variable in the simple dag
}

#[test]
fn integration_front_door_latent_mediator_rejected() {
    let mut b = CausalDagBuilder::new();
    b.add_variable(var(1, "T", VariableDomain::Treatment))
        .unwrap();
    b.add_variable(var(2, "Y", VariableDomain::Outcome))
        .unwrap();
    b.add_variable(CausalVariable {
        id: 3,
        name: "M".to_string(),
        domain: VariableDomain::Mediator,
        observability: Observability::Latent, // latent mediator
        scale: MeasurementScale::Continuous,
        description: "latent mediator".to_string(),
        subsystem: "test".to_string(),
    })
    .unwrap();
    b.add_edge(edge(1, 3, EdgeKind::Direct));
    b.add_edge(edge(3, 2, EdgeKind::Mediated));
    let dag = b.build().unwrap();
    assert!(dag.front_door_mediator(1, 2).is_none());
}

// ===========================================================================
// Section 13: Instrumental Variable
// ===========================================================================

#[test]
fn integration_find_instrument_valid() {
    let mut b = CausalDagBuilder::new();
    b.add_variable(var(1, "T", VariableDomain::Treatment))
        .unwrap();
    b.add_variable(var(2, "Y", VariableDomain::Outcome))
        .unwrap();
    b.add_variable(var(3, "Z", VariableDomain::Instrument))
        .unwrap();
    b.add_edge(edge(3, 1, EdgeKind::Instrumental));
    b.add_edge(edge(1, 2, EdgeKind::Direct));
    let dag = b.build().unwrap();
    assert_eq!(dag.find_instrument(1, 2), Some(3));
}

#[test]
fn integration_find_instrument_none_available() {
    let dag = simple_confounded_dag();
    assert!(dag.find_instrument(1, 2).is_none());
}

#[test]
fn integration_find_instrument_latent_rejected() {
    let mut b = CausalDagBuilder::new();
    b.add_variable(var(1, "T", VariableDomain::Treatment))
        .unwrap();
    b.add_variable(var(2, "Y", VariableDomain::Outcome))
        .unwrap();
    b.add_variable(CausalVariable {
        id: 3,
        name: "Z".to_string(),
        domain: VariableDomain::Instrument,
        observability: Observability::Latent,
        scale: MeasurementScale::Binary,
        description: "latent instrument".to_string(),
        subsystem: "test".to_string(),
    })
    .unwrap();
    b.add_edge(edge(3, 1, EdgeKind::Instrumental));
    b.add_edge(edge(1, 2, EdgeKind::Direct));
    let dag = b.build().unwrap();
    assert!(dag.find_instrument(1, 2).is_none());
}

// ===========================================================================
// Section 14: Identifiability Certificates
// ===========================================================================

#[test]
fn integration_identify_effect_backdoor_strategy() {
    let dag = simple_confounded_dag();
    let cert = dag.identify_effect(1, 2);
    assert!(cert.is_identifiable);
    assert_eq!(cert.strategy, IdentificationStrategy::Backdoor);
    assert!(cert.adjustment_set.is_some());
    assert!(cert.front_door_mediator.is_none());
    assert!(cert.instrument.is_none());
    assert!(cert.unidentifiable_reasons.is_empty());
}

#[test]
fn integration_identify_effect_not_connected() {
    let mut b = CausalDagBuilder::new();
    b.add_variable(var(1, "T", VariableDomain::Treatment))
        .unwrap();
    b.add_variable(var(2, "Y", VariableDomain::Outcome))
        .unwrap();
    let dag = b.build().unwrap();
    let cert = dag.identify_effect(1, 2);
    assert!(!cert.is_identifiable);
    assert_eq!(cert.strategy, IdentificationStrategy::Unidentifiable);
    assert!(
        cert.unidentifiable_reasons
            .contains(&UnidentifiableReason::NotConnected)
    );
}

#[test]
fn integration_identify_effect_latent_treatment() {
    let mut b = CausalDagBuilder::new();
    b.add_variable(CausalVariable {
        id: 1,
        name: "T".to_string(),
        domain: VariableDomain::Treatment,
        observability: Observability::Latent,
        scale: MeasurementScale::Binary,
        description: "latent treatment".to_string(),
        subsystem: "test".to_string(),
    })
    .unwrap();
    b.add_variable(var(2, "Y", VariableDomain::Outcome))
        .unwrap();
    b.add_edge(edge(1, 2, EdgeKind::Direct));
    let dag = b.build().unwrap();
    let cert = dag.identify_effect(1, 2);
    // Even with latent treatment, backdoor may still work (no confounders)
    // but TreatmentNotObservable should be flagged if unidentifiable
    assert!(
        cert.is_identifiable
            || cert
                .unidentifiable_reasons
                .contains(&UnidentifiableReason::TreatmentNotObservable)
    );
}

#[test]
fn integration_identify_effect_certificate_schema() {
    let dag = simple_confounded_dag();
    let cert = dag.identify_effect(1, 2);
    assert_eq!(cert.schema_version, CAUSAL_DAG_SCHEMA_VERSION);
    assert_eq!(cert.treatment, 1);
    assert_eq!(cert.outcome, 2);
    assert_eq!(cert.dag_hash, dag.structure_hash);
}

#[test]
fn integration_identify_effect_certificate_hash_deterministic() {
    let dag = simple_confounded_dag();
    let c1 = dag.identify_effect(1, 2);
    let c2 = dag.identify_effect(1, 2);
    assert_eq!(c1.certificate_hash, c2.certificate_hash);
    assert_eq!(c1.dag_hash, c2.dag_hash);
}

#[test]
fn integration_identify_effect_certificate_serde() {
    let dag = simple_confounded_dag();
    let cert = dag.identify_effect(1, 2);
    let json = serde_json::to_string(&cert).unwrap();
    let back: IdentifiabilityCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

// ===========================================================================
// Section 15: IdentificationStrategy
// ===========================================================================

#[test]
fn integration_identification_strategy_as_str() {
    assert_eq!(IdentificationStrategy::Backdoor.as_str(), "backdoor");
    assert_eq!(IdentificationStrategy::FrontDoor.as_str(), "front_door");
    assert_eq!(
        IdentificationStrategy::Instrumental.as_str(),
        "instrumental"
    );
    assert_eq!(
        IdentificationStrategy::Unidentifiable.as_str(),
        "unidentifiable"
    );
}

#[test]
fn integration_identification_strategy_display() {
    for s in [
        IdentificationStrategy::Backdoor,
        IdentificationStrategy::FrontDoor,
        IdentificationStrategy::Instrumental,
        IdentificationStrategy::Unidentifiable,
    ] {
        assert_eq!(format!("{s}"), s.as_str());
    }
}

#[test]
fn integration_identification_strategy_serde() {
    for s in [
        IdentificationStrategy::Backdoor,
        IdentificationStrategy::FrontDoor,
        IdentificationStrategy::Instrumental,
        IdentificationStrategy::Unidentifiable,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: IdentificationStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

// ===========================================================================
// Section 16: UnidentifiableReason
// ===========================================================================

#[test]
fn integration_unidentifiable_reason_display_all() {
    let reasons = [
        UnidentifiableReason::NoBackdoorSet,
        UnidentifiableReason::NoFrontDoorPath,
        UnidentifiableReason::NoInstrument,
        UnidentifiableReason::NotConnected,
        UnidentifiableReason::AllConfoundersLatent,
        UnidentifiableReason::TreatmentNotObservable,
        UnidentifiableReason::OutcomeNotObservable,
    ];
    for r in &reasons {
        let s = format!("{r}");
        assert!(!s.is_empty());
    }
}

#[test]
fn integration_unidentifiable_reason_serde() {
    for r in [
        UnidentifiableReason::NoBackdoorSet,
        UnidentifiableReason::NoFrontDoorPath,
        UnidentifiableReason::NoInstrument,
        UnidentifiableReason::NotConnected,
        UnidentifiableReason::AllConfoundersLatent,
        UnidentifiableReason::TreatmentNotObservable,
        UnidentifiableReason::OutcomeNotObservable,
    ] {
        let json = serde_json::to_string(&r).unwrap();
        let back: UnidentifiableReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}

// ===========================================================================
// Section 17: CausalDagError Display
// ===========================================================================

#[test]
fn integration_error_display_empty_dag() {
    let e = CausalDagError::EmptyDag;
    assert!(format!("{e}").contains("empty"));
}

#[test]
fn integration_error_display_unknown_variable() {
    let e = CausalDagError::UnknownVariable { id: 42 };
    let s = format!("{e}");
    assert!(s.contains("42"));
    assert!(s.contains("unknown"));
}

#[test]
fn integration_error_display_cycle() {
    let e = CausalDagError::CycleDetected { from: 1, to: 2 };
    let s = format!("{e}");
    assert!(s.contains("cycle"));
}

#[test]
fn integration_error_display_no_path() {
    let e = CausalDagError::NoPath { from: 5, to: 10 };
    let s = format!("{e}");
    assert!(s.contains("5"));
    assert!(s.contains("10"));
}

#[test]
fn integration_error_serde() {
    for e in [
        CausalDagError::EmptyDag,
        CausalDagError::UnknownVariable { id: 1 },
        CausalDagError::CycleDetected { from: 1, to: 2 },
        CausalDagError::DuplicateVariable { id: 3 },
        CausalDagError::NoPath { from: 1, to: 2 },
    ] {
        let json = serde_json::to_string(&e).unwrap();
        let back: CausalDagError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }
}

// ===========================================================================
// Section 18: CausalEdge & CausalVariable Serde
// ===========================================================================

#[test]
fn integration_causal_edge_serde_roundtrip() {
    let e = edge(10, 20, EdgeKind::Mediated);
    let json = serde_json::to_string(&e).unwrap();
    let back: CausalEdge = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn integration_causal_variable_serde_roundtrip() {
    let v = var(5, "test_var", VariableDomain::Confounder);
    let json = serde_json::to_string(&v).unwrap();
    let back: CausalVariable = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn integration_causal_variable_with_all_observabilities() {
    for obs in [
        Observability::Observable,
        Observability::Latent,
        Observability::Proxy,
    ] {
        let v = CausalVariable {
            id: 1,
            name: "X".to_string(),
            domain: VariableDomain::Treatment,
            observability: obs,
            scale: MeasurementScale::Binary,
            description: "test".to_string(),
            subsystem: "test".to_string(),
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: CausalVariable = serde_json::from_str(&json).unwrap();
        assert_eq!(v.observability, back.observability);
    }
}

// ===========================================================================
// Section 19: DAG Serde
// ===========================================================================

#[test]
fn integration_dag_serde_roundtrip_simple() {
    let dag = simple_confounded_dag();
    let json = serde_json::to_string(&dag).unwrap();
    let back: CausalDag = serde_json::from_str(&json).unwrap();
    assert_eq!(dag.variable_count(), back.variable_count());
    assert_eq!(dag.edge_count(), back.edge_count());
    assert_eq!(dag.structure_hash, back.structure_hash);
}

#[test]
fn integration_dag_serde_roundtrip_chain() {
    let dag = chain_dag();
    let json = serde_json::to_string(&dag).unwrap();
    let back: CausalDag = serde_json::from_str(&json).unwrap();
    assert_eq!(dag, back);
}

#[test]
fn integration_dag_serde_roundtrip_diamond() {
    let dag = diamond_dag();
    let json = serde_json::to_string(&dag).unwrap();
    let back: CausalDag = serde_json::from_str(&json).unwrap();
    assert_eq!(dag, back);
}

// ===========================================================================
// Section 20: FrankenEngine Optimization DAG
// ===========================================================================

#[test]
fn integration_frankenengine_dag_builds_successfully() {
    let dag =
        frankenengine_engine::causal_intervention_dag::frankenengine_optimization_dag().unwrap();
    assert!(dag.variable_count() >= 12);
    assert!(dag.edge_count() >= 16);
}

#[test]
fn integration_frankenengine_dag_has_all_domains() {
    let dag =
        frankenengine_engine::causal_intervention_dag::frankenengine_optimization_dag().unwrap();
    let treatments = dag.variables_by_domain(VariableDomain::Treatment);
    let outcomes = dag.variables_by_domain(VariableDomain::Outcome);
    let confounders = dag.variables_by_domain(VariableDomain::Confounder);
    let mediators = dag.variables_by_domain(VariableDomain::Mediator);
    let instruments = dag.variables_by_domain(VariableDomain::Instrument);

    assert!(
        treatments.len() >= 3,
        "expected >=3 treatments, got {}",
        treatments.len()
    );
    assert!(
        outcomes.len() >= 3,
        "expected >=3 outcomes, got {}",
        outcomes.len()
    );
    assert!(
        confounders.len() >= 3,
        "expected >=3 confounders, got {}",
        confounders.len()
    );
    assert!(
        mediators.len() >= 2,
        "expected >=2 mediators, got {}",
        mediators.len()
    );
    assert!(!instruments.is_empty(), "expected >=1 instrument");
}

#[test]
fn integration_frankenengine_dag_acyclic() {
    // Builder validates acyclicity; if build succeeds, it's a DAG
    assert!(
        frankenengine_engine::causal_intervention_dag::frankenengine_optimization_dag().is_ok()
    );
}

#[test]
fn integration_frankenengine_dag_hash_deterministic() {
    let d1 =
        frankenengine_engine::causal_intervention_dag::frankenengine_optimization_dag().unwrap();
    let d2 =
        frankenengine_engine::causal_intervention_dag::frankenengine_optimization_dag().unwrap();
    assert_eq!(d1.structure_hash, d2.structure_hash);
}

#[test]
fn integration_frankenengine_dag_tiering_affects_latency() {
    let dag =
        frankenengine_engine::causal_intervention_dag::frankenengine_optimization_dag().unwrap();
    // tiering_level (1) should have a path to p99_latency (30)
    assert!(
        dag.has_path(1, 30),
        "tiering_level should affect p99_latency"
    );
}

#[test]
fn integration_frankenengine_dag_cache_affects_latency() {
    let dag =
        frankenengine_engine::causal_intervention_dag::frankenengine_optimization_dag().unwrap();
    // cache_policy (2) -> cache_hit_rate (21) -> p99_latency (30)
    assert!(
        dag.has_path(2, 30),
        "cache_policy should affect p99_latency"
    );
}

#[test]
fn integration_frankenengine_dag_gc_affects_memory() {
    let dag =
        frankenengine_engine::causal_intervention_dag::frankenengine_optimization_dag().unwrap();
    // gc_strategy (3) -> memory_usage (32)
    assert!(
        dag.has_path(3, 32),
        "gc_strategy should affect memory_usage"
    );
}

#[test]
fn integration_frankenengine_dag_instrument_affects_treatment() {
    let dag =
        frankenengine_engine::causal_intervention_dag::frankenengine_optimization_dag().unwrap();
    // randomized_tier_assignment (40) -> tiering_level (1)
    assert!(dag.has_path(40, 1), "instrument should affect tiering");
}

#[test]
fn integration_frankenengine_dag_workload_confounds_tiering() {
    let dag =
        frankenengine_engine::causal_intervention_dag::frankenengine_optimization_dag().unwrap();
    // workload_type (10) should be parent of tiering_level (1)
    let t_parents = dag
        .parents
        .get(&1)
        .expect("tiering_level should have parents");
    assert!(
        t_parents.contains(&10),
        "workload_type should confound tiering"
    );
}

// ===========================================================================
// Section 21: Evidence Manifest
// ===========================================================================

#[test]
fn integration_evidence_manifest_runs() {
    let manifest = frankenengine_engine::causal_intervention_dag::run_causal_dag_evidence();
    assert!(manifest.error.is_none());
    assert!(manifest.certificates_generated > 0);
    assert_eq!(
        manifest.identifiable_count + manifest.unidentifiable_count,
        manifest.certificates_generated
    );
}

#[test]
fn integration_evidence_manifest_schema() {
    let manifest = frankenengine_engine::causal_intervention_dag::run_causal_dag_evidence();
    assert_eq!(manifest.schema_version, CAUSAL_DAG_SCHEMA_VERSION);
}

#[test]
fn integration_evidence_manifest_counts() {
    let manifest = frankenengine_engine::causal_intervention_dag::run_causal_dag_evidence();
    assert!(manifest.dag_variable_count >= 12);
    assert!(manifest.dag_edge_count >= 16);
    // 3 treatments × 3 outcomes = 9 certificates
    assert!(manifest.certificates_generated >= 9);
}

#[test]
fn integration_evidence_manifest_has_identifiable() {
    let manifest = frankenengine_engine::causal_intervention_dag::run_causal_dag_evidence();
    assert!(
        manifest.identifiable_count > 0,
        "should have at least some identifiable effects"
    );
}

#[test]
fn integration_evidence_manifest_deterministic() {
    let m1 = frankenengine_engine::causal_intervention_dag::run_causal_dag_evidence();
    let m2 = frankenengine_engine::causal_intervention_dag::run_causal_dag_evidence();
    assert_eq!(m1.manifest_hash, m2.manifest_hash);
    assert_eq!(m1.certificates_generated, m2.certificates_generated);
    assert_eq!(m1.identifiable_count, m2.identifiable_count);
}

#[test]
fn integration_evidence_manifest_serde() {
    let manifest = frankenengine_engine::causal_intervention_dag::run_causal_dag_evidence();
    let json = serde_json::to_string(&manifest).unwrap();
    let back: CausalDagEvidenceManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest.manifest_hash, back.manifest_hash);
    assert_eq!(manifest.certificates_generated, back.certificates_generated);
}

#[test]
fn integration_evidence_manifest_certificates_well_formed() {
    let manifest = frankenengine_engine::causal_intervention_dag::run_causal_dag_evidence();
    for cert in &manifest.certificates {
        assert_eq!(cert.schema_version, CAUSAL_DAG_SCHEMA_VERSION);
        if cert.is_identifiable {
            assert_ne!(cert.strategy, IdentificationStrategy::Unidentifiable);
            assert!(cert.unidentifiable_reasons.is_empty());
        } else {
            assert_eq!(cert.strategy, IdentificationStrategy::Unidentifiable);
            assert!(!cert.unidentifiable_reasons.is_empty());
        }
    }
}

// ===========================================================================
// Section 22: Complex Topologies
// ===========================================================================

#[test]
fn integration_wide_fan_out_dag() {
    let mut b = CausalDagBuilder::new();
    b.add_variable(var(1, "Root", VariableDomain::Treatment))
        .unwrap();
    for i in 2..=10 {
        b.add_variable(var(i, &format!("Leaf{i}"), VariableDomain::Outcome))
            .unwrap();
        b.add_edge(edge(1, i, EdgeKind::Direct));
    }
    let dag = b.build().unwrap();
    assert_eq!(dag.variable_count(), 10);
    assert_eq!(dag.edge_count(), 9);
    let desc = dag.descendants(1);
    assert_eq!(desc.len(), 9);
}

#[test]
fn integration_wide_fan_in_dag() {
    let mut b = CausalDagBuilder::new();
    for i in 1..=9 {
        b.add_variable(var(i, &format!("Source{i}"), VariableDomain::Confounder))
            .unwrap();
        b.add_edge(edge(i, 10, EdgeKind::Confounding));
    }
    b.add_variable(var(10, "Sink", VariableDomain::Outcome))
        .unwrap();
    let dag = b.build().unwrap();
    assert_eq!(dag.variable_count(), 10);
    let anc = dag.ancestors(10);
    assert_eq!(anc.len(), 9);
}

#[test]
fn integration_layered_dag() {
    // 3-layer DAG: L1(1,2) -> L2(3,4) -> L3(5,6)
    let mut b = CausalDagBuilder::new();
    b.add_variable(var(1, "L1a", VariableDomain::Treatment))
        .unwrap();
    b.add_variable(var(2, "L1b", VariableDomain::Treatment))
        .unwrap();
    b.add_variable(var(3, "L2a", VariableDomain::Mediator))
        .unwrap();
    b.add_variable(var(4, "L2b", VariableDomain::Mediator))
        .unwrap();
    b.add_variable(var(5, "L3a", VariableDomain::Outcome))
        .unwrap();
    b.add_variable(var(6, "L3b", VariableDomain::Outcome))
        .unwrap();

    b.add_edge(edge(1, 3, EdgeKind::Direct));
    b.add_edge(edge(1, 4, EdgeKind::Direct));
    b.add_edge(edge(2, 3, EdgeKind::Direct));
    b.add_edge(edge(2, 4, EdgeKind::Direct));
    b.add_edge(edge(3, 5, EdgeKind::Mediated));
    b.add_edge(edge(3, 6, EdgeKind::Mediated));
    b.add_edge(edge(4, 5, EdgeKind::Mediated));
    b.add_edge(edge(4, 6, EdgeKind::Mediated));

    let dag = b.build().unwrap();
    assert_eq!(dag.variable_count(), 6);
    assert_eq!(dag.edge_count(), 8);

    // All L1 nodes should reach all L3 nodes
    assert!(dag.has_path(1, 5));
    assert!(dag.has_path(1, 6));
    assert!(dag.has_path(2, 5));
    assert!(dag.has_path(2, 6));
}

// ===========================================================================
// Section 23: Multiple Confounders
// ===========================================================================

#[test]
fn integration_multiple_observable_confounders() {
    let mut b = CausalDagBuilder::new();
    b.add_variable(var(1, "T", VariableDomain::Treatment))
        .unwrap();
    b.add_variable(var(2, "Y", VariableDomain::Outcome))
        .unwrap();
    b.add_variable(var(3, "C1", VariableDomain::Confounder))
        .unwrap();
    b.add_variable(var(4, "C2", VariableDomain::Confounder))
        .unwrap();
    b.add_variable(var(5, "C3", VariableDomain::Confounder))
        .unwrap();
    b.add_edge(edge(3, 1, EdgeKind::Confounding));
    b.add_edge(edge(3, 2, EdgeKind::Confounding));
    b.add_edge(edge(4, 1, EdgeKind::Confounding));
    b.add_edge(edge(4, 2, EdgeKind::Confounding));
    b.add_edge(edge(5, 1, EdgeKind::Confounding));
    b.add_edge(edge(5, 2, EdgeKind::Confounding));
    b.add_edge(edge(1, 2, EdgeKind::Direct));
    let dag = b.build().unwrap();

    let adj = dag.backdoor_adjustment(1, 2);
    assert!(adj.is_valid);
    // Should adjust for all 3 confounders
    assert!(adj.variables.contains(&3));
    assert!(adj.variables.contains(&4));
    assert!(adj.variables.contains(&5));
}

// ===========================================================================
// Section 24: Edge Cases
// ===========================================================================

#[test]
fn integration_self_loop_via_builder_prevented() {
    // A self-loop A->A shouldn't be caught by cycle detection since
    // the variable would have in-degree > 0 if it's also the source
    let mut b = CausalDagBuilder::new();
    b.add_variable(var(1, "A", VariableDomain::Treatment))
        .unwrap();
    b.add_edge(edge(1, 1, EdgeKind::Direct));
    assert!(b.build().is_err());
}

#[test]
fn integration_many_variables_dag() {
    let mut b = CausalDagBuilder::new();
    for i in 1..=50 {
        let domain = match i % 5 {
            0 => VariableDomain::Treatment,
            1 => VariableDomain::Outcome,
            2 => VariableDomain::Confounder,
            3 => VariableDomain::Mediator,
            _ => VariableDomain::Instrument,
        };
        b.add_variable(var(i, &format!("V{i}"), domain)).unwrap();
    }
    // Chain edges: 1->2->3->...->50 (no cycles)
    for i in 1..50 {
        b.add_edge(edge(i, i + 1, EdgeKind::Direct));
    }
    let dag = b.build().unwrap();
    assert_eq!(dag.variable_count(), 50);
    assert_eq!(dag.edge_count(), 49);
    assert!(dag.has_path(1, 50));
}

#[test]
fn integration_proxy_observability_in_adjustment() {
    let mut b = CausalDagBuilder::new();
    b.add_variable(var(1, "T", VariableDomain::Treatment))
        .unwrap();
    b.add_variable(var(2, "Y", VariableDomain::Outcome))
        .unwrap();
    b.add_variable(CausalVariable {
        id: 3,
        name: "P".to_string(),
        domain: VariableDomain::Confounder,
        observability: Observability::Proxy, // proxy should be usable
        scale: MeasurementScale::Categorical,
        description: "proxy confounder".to_string(),
        subsystem: "test".to_string(),
    })
    .unwrap();
    b.add_edge(edge(1, 2, EdgeKind::Direct));
    b.add_edge(edge(3, 1, EdgeKind::Confounding));
    b.add_edge(edge(3, 2, EdgeKind::Confounding));
    let dag = b.build().unwrap();
    let adj = dag.backdoor_adjustment(1, 2);
    assert!(adj.is_valid);
    assert!(adj.variables.contains(&3)); // proxy should be in adjustment set
}
