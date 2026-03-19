//! Enrichment integration tests for `causal_intervention_dag` module.
//!
//! Deep coverage of DAG construction, adjustment sets, identification strategies,
//! serde roundtrips, Display distinctness, and error handling.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use std::collections::BTreeSet;

use frankenengine_engine::causal_intervention_dag::{
    AdjustmentSet, CAUSAL_DAG_COMPONENT, CAUSAL_DAG_POLICY_ID, CAUSAL_DAG_SCHEMA_VERSION,
    CausalDag, CausalDagBuilder, CausalDagError, CausalDagEvidenceManifest, CausalEdge,
    CausalVariable, EdgeConfidence, EdgeKind, IdentifiabilityCertificate, IdentificationStrategy,
    MeasurementScale, Observability, UnidentifiableReason, VariableDomain,
    frankenengine_optimization_dag, run_causal_dag_evidence,
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

fn simple_dag() -> CausalDag {
    let mut b = CausalDagBuilder::new();
    b.add_variable(var(1, "treatment", VariableDomain::Treatment))
        .unwrap();
    b.add_variable(var(2, "outcome", VariableDomain::Outcome))
        .unwrap();
    b.add_variable(var(3, "confounder", VariableDomain::Confounder))
        .unwrap();
    b.add_edge(edge(1, 2, EdgeKind::Direct));
    b.add_edge(edge(3, 1, EdgeKind::Confounding));
    b.add_edge(edge(3, 2, EdgeKind::Confounding));
    b.build().unwrap()
}

// ---------------------------------------------------------------------------
// VariableDomain — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_variable_domain_display_distinct() {
    let displays: BTreeSet<String> = VariableDomain::ALL.iter().map(|d| d.to_string()).collect();
    assert_eq!(displays.len(), VariableDomain::ALL.len());
}

#[test]
fn enrich_variable_domain_as_str_matches_display() {
    for d in VariableDomain::ALL {
        assert_eq!(d.to_string(), d.as_str());
    }
}

#[test]
fn enrich_variable_domain_serde_all() {
    for d in VariableDomain::ALL {
        let json = serde_json::to_string(d).unwrap();
        let back: VariableDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, back);
    }
}

#[test]
fn enrich_variable_domain_all_count() {
    assert_eq!(VariableDomain::ALL.len(), 6);
}

// ---------------------------------------------------------------------------
// Observability — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_observability_serde_roundtrip() {
    let variants = [
        Observability::Observable,
        Observability::Latent,
        Observability::Proxy,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: Observability = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrich_observability_ord() {
    assert!(Observability::Observable < Observability::Latent);
    assert!(Observability::Latent < Observability::Proxy);
}

// ---------------------------------------------------------------------------
// MeasurementScale — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_measurement_scale_serde_roundtrip() {
    let variants = [
        MeasurementScale::Binary,
        MeasurementScale::Ordinal,
        MeasurementScale::Continuous,
        MeasurementScale::Categorical,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: MeasurementScale = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// EdgeKind — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_edge_kind_serde_roundtrip() {
    let variants = [
        EdgeKind::Direct,
        EdgeKind::Mediated,
        EdgeKind::Confounding,
        EdgeKind::Instrumental,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: EdgeKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// EdgeConfidence — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_edge_confidence_serde_roundtrip() {
    let variants = [
        EdgeConfidence::Structural,
        EdgeConfidence::Empirical,
        EdgeConfidence::Hypothesized,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: EdgeConfidence = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// CausalVariable — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_causal_variable_serde_roundtrip() {
    let v = CausalVariable {
        id: 42,
        name: "test-var".to_string(),
        domain: VariableDomain::Mediator,
        observability: Observability::Proxy,
        scale: MeasurementScale::Continuous,
        description: "A test variable".to_string(),
        subsystem: "test-subsystem".to_string(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: CausalVariable = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ---------------------------------------------------------------------------
// CausalEdge — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_causal_edge_serde_roundtrip() {
    let e = CausalEdge {
        from: 1,
        to: 2,
        kind: EdgeKind::Mediated,
        confidence: EdgeConfidence::Empirical,
        mechanism: "test mechanism".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: CausalEdge = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// CausalDagBuilder — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_builder_default_same_as_new() {
    let b1 = CausalDagBuilder::new();
    let b2 = CausalDagBuilder::default();
    // Both should be empty builders; we can verify by building → EmptyDag
    assert!(matches!(b1.build(), Err(CausalDagError::EmptyDag)));
    assert!(matches!(b2.build(), Err(CausalDagError::EmptyDag)));
}

#[test]
fn enrich_builder_duplicate_variable_error() {
    let mut b = CausalDagBuilder::new();
    b.add_variable(var(1, "first", VariableDomain::Treatment))
        .unwrap();
    let err = b
        .add_variable(var(1, "second", VariableDomain::Outcome))
        .unwrap_err();
    assert!(matches!(err, CausalDagError::DuplicateVariable { id: 1 }));
}

#[test]
fn enrich_builder_unknown_variable_edge() {
    let mut b = CausalDagBuilder::new();
    b.add_variable(var(1, "t", VariableDomain::Treatment))
        .unwrap();
    b.add_edge(edge(1, 99, EdgeKind::Direct));
    let err = b.build().unwrap_err();
    assert!(matches!(err, CausalDagError::UnknownVariable { id: 99 }));
}

#[test]
fn enrich_builder_cycle_detection() {
    let mut b = CausalDagBuilder::new();
    b.add_variable(var(1, "a", VariableDomain::Treatment))
        .unwrap();
    b.add_variable(var(2, "b", VariableDomain::Outcome))
        .unwrap();
    b.add_edge(edge(1, 2, EdgeKind::Direct));
    b.add_edge(edge(2, 1, EdgeKind::Direct));
    let err = b.build().unwrap_err();
    assert!(matches!(err, CausalDagError::CycleDetected { .. }));
}

// ---------------------------------------------------------------------------
// CausalDag — graph queries enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_dag_variable_count() {
    let dag = simple_dag();
    assert_eq!(dag.variable_count(), 3);
}

#[test]
fn enrich_dag_edge_count() {
    let dag = simple_dag();
    assert_eq!(dag.edge_count(), 3);
}

#[test]
fn enrich_dag_ancestors_of_outcome() {
    let dag = simple_dag();
    let anc = dag.ancestors(2);
    assert!(anc.contains(&1)); // treatment -> outcome
    assert!(anc.contains(&3)); // confounder -> outcome
}

#[test]
fn enrich_dag_descendants_of_confounder() {
    let dag = simple_dag();
    let desc = dag.descendants(3);
    assert!(desc.contains(&1));
    assert!(desc.contains(&2));
}

#[test]
fn enrich_dag_has_path_self() {
    let dag = simple_dag();
    assert!(dag.has_path(1, 1));
}

#[test]
fn enrich_dag_has_path_direct() {
    let dag = simple_dag();
    assert!(dag.has_path(1, 2));
}

#[test]
fn enrich_dag_no_path_reverse() {
    let dag = simple_dag();
    assert!(!dag.has_path(2, 1));
}

#[test]
fn enrich_dag_variables_by_domain() {
    let dag = simple_dag();
    let treatments = dag.variables_by_domain(VariableDomain::Treatment);
    assert_eq!(treatments, vec![1]);
    let outcomes = dag.variables_by_domain(VariableDomain::Outcome);
    assert_eq!(outcomes, vec![2]);
    let confounders = dag.variables_by_domain(VariableDomain::Confounder);
    assert_eq!(confounders, vec![3]);
}

#[test]
fn enrich_dag_structure_hash_deterministic() {
    let d1 = simple_dag();
    let d2 = simple_dag();
    assert_eq!(d1.structure_hash, d2.structure_hash);
}

#[test]
fn enrich_dag_serde_roundtrip() {
    let dag = simple_dag();
    let json = serde_json::to_string(&dag).unwrap();
    let back: CausalDag = serde_json::from_str(&json).unwrap();
    assert_eq!(dag, back);
}

// ---------------------------------------------------------------------------
// CausalDagError — Display enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_error_display_unknown_variable() {
    let e = CausalDagError::UnknownVariable { id: 42 };
    assert!(e.to_string().contains("42"));
}

#[test]
fn enrich_error_display_cycle_detected() {
    let e = CausalDagError::CycleDetected { from: 1, to: 2 };
    let s = e.to_string();
    assert!(s.contains("1"));
    assert!(s.contains("2"));
}

#[test]
fn enrich_error_display_duplicate_variable() {
    let e = CausalDagError::DuplicateVariable { id: 7 };
    assert!(e.to_string().contains("7"));
}

#[test]
fn enrich_error_display_no_path() {
    let e = CausalDagError::NoPath { from: 10, to: 20 };
    assert!(e.to_string().contains("10"));
}

#[test]
fn enrich_error_display_empty_dag() {
    let e = CausalDagError::EmptyDag;
    assert!(e.to_string().contains("empty"));
}

#[test]
fn enrich_error_serde_roundtrip() {
    let errors = vec![
        CausalDagError::UnknownVariable { id: 1 },
        CausalDagError::CycleDetected { from: 2, to: 3 },
        CausalDagError::DuplicateVariable { id: 4 },
        CausalDagError::NoPath { from: 5, to: 6 },
        CausalDagError::EmptyDag,
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: CausalDagError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ---------------------------------------------------------------------------
// IdentificationStrategy — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_identification_strategy_display_distinct() {
    let strats = [
        IdentificationStrategy::Backdoor,
        IdentificationStrategy::FrontDoor,
        IdentificationStrategy::Instrumental,
        IdentificationStrategy::Unidentifiable,
    ];
    let displays: BTreeSet<String> = strats.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrich_identification_strategy_as_str_matches_display() {
    let strats = [
        IdentificationStrategy::Backdoor,
        IdentificationStrategy::FrontDoor,
        IdentificationStrategy::Instrumental,
        IdentificationStrategy::Unidentifiable,
    ];
    for s in &strats {
        assert_eq!(s.to_string(), s.as_str());
    }
}

#[test]
fn enrich_identification_strategy_serde_all() {
    let strats = [
        IdentificationStrategy::Backdoor,
        IdentificationStrategy::FrontDoor,
        IdentificationStrategy::Instrumental,
        IdentificationStrategy::Unidentifiable,
    ];
    for s in &strats {
        let json = serde_json::to_string(s).unwrap();
        let back: IdentificationStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ---------------------------------------------------------------------------
// UnidentifiableReason — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_unidentifiable_reason_display_distinct() {
    let reasons = [
        UnidentifiableReason::NoBackdoorSet,
        UnidentifiableReason::NoFrontDoorPath,
        UnidentifiableReason::NoInstrument,
        UnidentifiableReason::NotConnected,
        UnidentifiableReason::AllConfoundersLatent,
        UnidentifiableReason::TreatmentNotObservable,
        UnidentifiableReason::OutcomeNotObservable,
    ];
    let displays: BTreeSet<String> = reasons.iter().map(|r| r.to_string()).collect();
    assert_eq!(displays.len(), 7);
}

#[test]
fn enrich_unidentifiable_reason_serde_all() {
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
        let json = serde_json::to_string(r).unwrap();
        let back: UnidentifiableReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ---------------------------------------------------------------------------
// Backdoor adjustment — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_backdoor_simple_dag_valid() {
    let dag = simple_dag();
    let adj = dag.backdoor_adjustment(1, 2);
    assert!(adj.is_valid);
    assert!(adj.variables.contains(&3)); // confounder in adjustment set
}

#[test]
fn enrich_backdoor_no_confounders_empty_set() {
    let mut b = CausalDagBuilder::new();
    b.add_variable(var(1, "t", VariableDomain::Treatment))
        .unwrap();
    b.add_variable(var(2, "o", VariableDomain::Outcome))
        .unwrap();
    b.add_edge(edge(1, 2, EdgeKind::Direct));
    let dag = b.build().unwrap();
    let adj = dag.backdoor_adjustment(1, 2);
    assert!(adj.is_valid);
    assert!(adj.variables.is_empty());
}

// ---------------------------------------------------------------------------
// identify_effect — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_identify_effect_backdoor_identified() {
    let dag = simple_dag();
    let cert = dag.identify_effect(1, 2);
    assert!(cert.is_identifiable);
    assert_eq!(cert.strategy, IdentificationStrategy::Backdoor);
    assert!(cert.adjustment_set.is_some());
}

#[test]
fn enrich_identify_effect_not_connected() {
    let mut b = CausalDagBuilder::new();
    b.add_variable(var(1, "t", VariableDomain::Treatment))
        .unwrap();
    b.add_variable(var(2, "o", VariableDomain::Outcome))
        .unwrap();
    // No edges between them
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
fn enrich_identify_effect_certificate_hash_deterministic() {
    let dag = simple_dag();
    let c1 = dag.identify_effect(1, 2);
    let c2 = dag.identify_effect(1, 2);
    assert_eq!(c1.certificate_hash, c2.certificate_hash);
}

#[test]
fn enrich_identify_effect_certificate_serde_roundtrip() {
    let dag = simple_dag();
    let cert = dag.identify_effect(1, 2);
    let json = serde_json::to_string(&cert).unwrap();
    let back: IdentifiabilityCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

// ---------------------------------------------------------------------------
// AdjustmentSet — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_adjustment_set_serde_roundtrip() {
    let adj = AdjustmentSet {
        treatment: 1,
        outcome: 2,
        variables: BTreeSet::from([3, 4]),
        is_valid: true,
        reason: None,
    };
    let json = serde_json::to_string(&adj).unwrap();
    let back: AdjustmentSet = serde_json::from_str(&json).unwrap();
    assert_eq!(adj, back);
}

#[test]
fn enrich_adjustment_set_with_reason() {
    let adj = AdjustmentSet {
        treatment: 1,
        outcome: 2,
        variables: BTreeSet::new(),
        is_valid: false,
        reason: Some("latent confounders".to_string()),
    };
    assert!(!adj.is_valid);
    assert!(adj.reason.is_some());
}

// ---------------------------------------------------------------------------
// frankenengine_optimization_dag — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_optimization_dag_builds_successfully() {
    let dag = frankenengine_optimization_dag().unwrap();
    assert!(dag.variable_count() > 0);
    assert!(dag.edge_count() > 0);
}

#[test]
fn enrich_optimization_dag_has_all_domains() {
    let dag = frankenengine_optimization_dag().unwrap();
    for domain in VariableDomain::ALL {
        let vars = dag.variables_by_domain(*domain);
        // The canonical DAG may not have Colliders, but should have Treatments, Outcomes, etc.
        if *domain != VariableDomain::Collider {
            assert!(!vars.is_empty(), "missing domain: {domain}");
        }
    }
}

#[test]
fn enrich_optimization_dag_deterministic_hash() {
    let d1 = frankenengine_optimization_dag().unwrap();
    let d2 = frankenengine_optimization_dag().unwrap();
    assert_eq!(d1.structure_hash, d2.structure_hash);
}

// ---------------------------------------------------------------------------
// run_causal_dag_evidence — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_evidence_manifest_has_certificates() {
    let manifest = run_causal_dag_evidence();
    assert!(manifest.certificates_generated > 0);
}

#[test]
fn enrich_evidence_manifest_counts_consistent() {
    let manifest = run_causal_dag_evidence();
    assert_eq!(
        manifest.identifiable_count + manifest.unidentifiable_count,
        manifest.certificates_generated
    );
}

#[test]
fn enrich_evidence_manifest_serde_roundtrip() {
    let manifest = run_causal_dag_evidence();
    let json = serde_json::to_string(&manifest).unwrap();
    let back: CausalDagEvidenceManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

#[test]
fn enrich_evidence_manifest_schema_version() {
    let manifest = run_causal_dag_evidence();
    assert_eq!(manifest.schema_version, CAUSAL_DAG_SCHEMA_VERSION);
}

#[test]
fn enrich_evidence_manifest_no_error() {
    let manifest = run_causal_dag_evidence();
    assert!(manifest.error.is_none());
}

// ---------------------------------------------------------------------------
// Constants — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_constants_nonempty() {
    assert!(!CAUSAL_DAG_SCHEMA_VERSION.is_empty());
    assert!(!CAUSAL_DAG_COMPONENT.is_empty());
    assert!(!CAUSAL_DAG_POLICY_ID.is_empty());
}

#[test]
fn enrich_schema_version_format() {
    assert!(CAUSAL_DAG_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn enrich_policy_id_format() {
    assert!(CAUSAL_DAG_POLICY_ID.starts_with("RGC-"));
}
