//! Integration tests for the `reputation` module.
//!
//! Covers trust-level lifecycle, evidence management, revocation propagation,
//! operator overrides, dependency risk scoring, provenance, serde roundtrips,
//! and adversarial scenarios that complement the inline unit tests.

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

use frankenengine_engine::reputation::{
    EdgeType, EvidenceNode, EvidenceSource, EvidenceType, ExtensionNode, IncidentNode,
    IncidentSeverity, OperatorOverrideInput, ProvenanceRecord, PublisherNode, ReputationGraph,
    ReputationGraphError, ResolutionStatus, TrustLevel, TrustLookupResult, TrustTransition,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_extension(id: &str, publisher: &str) -> ExtensionNode {
    ExtensionNode {
        extension_id: id.to_string(),
        package_name: format!("pkg-{id}"),
        version: "1.0.0".to_string(),
        publisher_id: publisher.to_string(),
        manifest_hash: [0u8; 32],
        first_seen_ns: 1_000_000_000,
        current_trust_level: TrustLevel::Unknown,
        dependencies: BTreeSet::new(),
    }
}

fn test_extension_with_deps(id: &str, publisher: &str, deps: &[&str]) -> ExtensionNode {
    let mut ext = test_extension(id, publisher);
    ext.dependencies = deps.iter().map(|d| d.to_string()).collect();
    ext
}

fn test_publisher(id: &str) -> PublisherNode {
    PublisherNode {
        publisher_id: id.to_string(),
        identity_attestation: [1u8; 32],
        published_count: 1,
        trust_score: 500_000,
        first_published_ns: 1_000_000_000,
    }
}

fn test_evidence(id: &str) -> EvidenceNode {
    EvidenceNode {
        evidence_id: id.to_string(),
        evidence_type: EvidenceType::BehavioralObservation,
        source: EvidenceSource::BayesianSentinel,
        timestamp_ns: 2_000_000_000,
        content_hash: [2u8; 32],
        linked_decision_ids: vec!["dec-1".to_string()],
        epoch: SecurityEpoch::from_raw(1),
    }
}

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

// ---------------------------------------------------------------------------
// TrustLevel serde & display
// ---------------------------------------------------------------------------

#[test]
fn trust_level_serde_roundtrip_all_variants() {
    for level in &TrustLevel::ALL {
        let json = serde_json::to_string(level).unwrap();
        let back: TrustLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(*level, back);
    }
}

#[test]
fn trust_level_display_all_variants() {
    let expected = [
        (TrustLevel::Unknown, "unknown"),
        (TrustLevel::Provisional, "provisional"),
        (TrustLevel::Established, "established"),
        (TrustLevel::Trusted, "trusted"),
        (TrustLevel::Suspicious, "suspicious"),
        (TrustLevel::Compromised, "compromised"),
        (TrustLevel::Revoked, "revoked"),
    ];
    for (level, name) in &expected {
        assert_eq!(level.to_string(), *name);
    }
}

#[test]
fn trust_level_all_has_seven_entries() {
    assert_eq!(TrustLevel::ALL.len(), 7);
}

// ---------------------------------------------------------------------------
// EvidenceType / EvidenceSource serde
// ---------------------------------------------------------------------------

#[test]
fn evidence_type_serde_roundtrip_all_variants() {
    let variants = [
        EvidenceType::BehavioralObservation,
        EvidenceType::AdversarialCampaignResult,
        EvidenceType::FleetEvidence,
        EvidenceType::IncidentRecord,
        EvidenceType::ThreatIntelligence,
        EvidenceType::ProvenanceAttestation,
        EvidenceType::OperatorAssessment,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: EvidenceType = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn evidence_source_serde_roundtrip_all_variants() {
    let variants = [
        EvidenceSource::BayesianSentinel,
        EvidenceSource::AdversarialCampaign,
        EvidenceSource::FleetImmuneSystem,
        EvidenceSource::OperatorManual,
        EvidenceSource::ExternalThreatFeed,
        EvidenceSource::BuildProvenance,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: EvidenceSource = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// IncidentSeverity / ResolutionStatus serde
// ---------------------------------------------------------------------------

#[test]
fn incident_severity_serde_roundtrip() {
    let variants = [
        IncidentSeverity::Low,
        IncidentSeverity::Medium,
        IncidentSeverity::High,
        IncidentSeverity::Critical,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: IncidentSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn resolution_status_serde_roundtrip() {
    let variants = [
        ResolutionStatus::Active,
        ResolutionStatus::Contained,
        ResolutionStatus::Resolved,
        ResolutionStatus::FalsePositive,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: ResolutionStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// Node serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn extension_node_serde_roundtrip() {
    let ext = test_extension_with_deps("ext-1", "pub-1", &["dep-a", "dep-b"]);
    let json = serde_json::to_string(&ext).unwrap();
    let back: ExtensionNode = serde_json::from_str(&json).unwrap();
    assert_eq!(ext, back);
}

#[test]
fn publisher_node_serde_roundtrip() {
    let p = test_publisher("pub-1");
    let json = serde_json::to_string(&p).unwrap();
    let back: PublisherNode = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn evidence_node_serde_roundtrip() {
    let ev = EvidenceNode {
        evidence_id: "ev-1".into(),
        evidence_type: EvidenceType::ThreatIntelligence,
        source: EvidenceSource::ExternalThreatFeed,
        timestamp_ns: 5_000_000_000,
        content_hash: [0xAB; 32],
        linked_decision_ids: vec!["dec-a".into(), "dec-b".into()],
        epoch: epoch(3),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: EvidenceNode = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn incident_node_serde_roundtrip() {
    let inc = IncidentNode {
        incident_id: "inc-1".into(),
        severity: IncidentSeverity::Critical,
        affected_extensions: ["ext-1".into(), "ext-2".into()].into_iter().collect(),
        containment_actions: vec!["quarantine".into(), "revoke".into()],
        resolution_status: ResolutionStatus::Contained,
        timestamp_ns: 7_000_000_000,
    };
    let json = serde_json::to_string(&inc).unwrap();
    let back: IncidentNode = serde_json::from_str(&json).unwrap();
    assert_eq!(inc, back);
}

#[test]
fn provenance_record_serde_roundtrip() {
    let record = ProvenanceRecord {
        extension_id: "ext-1".into(),
        publisher_verified: true,
        build_attested: true,
        attestation_source: Some("sigstore".into()),
        dependency_depth: 3,
        has_provenance_gap: false,
        gap_descriptions: vec![],
    };
    let json = serde_json::to_string(&record).unwrap();
    let back: ProvenanceRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, back);
}

// ---------------------------------------------------------------------------
// EdgeType serde
// ---------------------------------------------------------------------------

#[test]
fn edge_type_serde_roundtrip_all_variants() {
    let edges = [
        EdgeType::PublishedBy {
            extension_id: "ext-1".into(),
            publisher_id: "pub-1".into(),
        },
        EdgeType::DependsOn {
            dependent_id: "ext-a".into(),
            dependency_id: "ext-b".into(),
        },
        EdgeType::DerivedFrom {
            new_version_id: "ext-v2".into(),
            old_version_id: "ext-v1".into(),
        },
        EdgeType::ObservedBehavior {
            extension_id: "ext-1".into(),
            evidence_id: "ev-1".into(),
        },
        EdgeType::RevokedBy {
            extension_id: "ext-1".into(),
            incident_id: "inc-1".into(),
        },
        EdgeType::RevocationPropagatedTo {
            source_extension_id: "ext-a".into(),
            target_extension_id: "ext-b".into(),
            incident_id: "inc-1".into(),
        },
        EdgeType::TrustTransitioned {
            extension_id: "ext-1".into(),
            transition_id: "tt-00000001".into(),
        },
    ];
    for edge in &edges {
        let json = serde_json::to_string(edge).unwrap();
        let back: EdgeType = serde_json::from_str(&json).unwrap();
        assert_eq!(*edge, back);
    }
}

// ---------------------------------------------------------------------------
// TrustTransition serde
// ---------------------------------------------------------------------------

#[test]
fn trust_transition_with_operator_override_serde_roundtrip() {
    let tt = TrustTransition {
        transition_id: "tt-00000001".into(),
        extension_id: "ext-1".into(),
        old_level: TrustLevel::Compromised,
        new_level: TrustLevel::Provisional,
        triggering_evidence_ids: vec!["ev-resolution".into()],
        policy_version: 2,
        operator_override: true,
        operator_justification: Some("Incident resolved".into()),
        timestamp_ns: 10_000_000_000,
        epoch: epoch(3),
    };
    let json = serde_json::to_string(&tt).unwrap();
    let back: TrustTransition = serde_json::from_str(&json).unwrap();
    assert_eq!(tt, back);
    assert!(back.operator_override);
    assert!(back.operator_justification.is_some());
}

// ---------------------------------------------------------------------------
// OperatorOverrideInput / TrustLookupResult serde
// ---------------------------------------------------------------------------

#[test]
fn operator_override_input_serde_roundtrip() {
    let input = OperatorOverrideInput {
        extension_id: "ext-1".into(),
        new_level: TrustLevel::Established,
        justification: "Reviewed and approved".into(),
        evidence_ids: vec!["ev-a".into()],
        policy_version: 5,
        epoch: epoch(2),
        timestamp_ns: 8_000_000_000,
    };
    let json = serde_json::to_string(&input).unwrap();
    let back: OperatorOverrideInput = serde_json::from_str(&json).unwrap();
    assert_eq!(back.extension_id, "ext-1");
    assert_eq!(back.new_level, TrustLevel::Established);
}

#[test]
fn trust_lookup_result_serde_roundtrip() {
    let result = TrustLookupResult {
        extension_id: "ext-1".into(),
        current_trust_level: TrustLevel::Established,
        transition_count: 2,
        last_transition: None,
        evidence_count: 5,
        dependency_risk_score: 300_000,
        publisher_trust_score: Some(700_000),
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: TrustLookupResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// ReputationGraphError serde, display, std::error
// ---------------------------------------------------------------------------

#[test]
fn reputation_graph_error_display_all_variants() {
    let err = ReputationGraphError::ExtensionNotFound {
        extension_id: "ext-1".into(),
    };
    assert!(err.to_string().contains("ext-1"));

    let err = ReputationGraphError::PublisherNotFound {
        publisher_id: "pub-1".into(),
    };
    assert!(err.to_string().contains("pub-1"));

    let err = ReputationGraphError::AutoUpgradeDenied {
        extension_id: "ext-1".into(),
        current: TrustLevel::Suspicious,
        attempted: TrustLevel::Established,
    };
    let s = err.to_string();
    assert!(s.contains("ext-1"));
    assert!(s.contains("operator override"));

    let err = ReputationGraphError::DuplicateExtension {
        extension_id: "ext-1".into(),
    };
    assert!(err.to_string().contains("duplicate"));

    let err = ReputationGraphError::DuplicateEvidence {
        evidence_id: "ev-1".into(),
    };
    assert!(err.to_string().contains("duplicate"));

    let err = ReputationGraphError::CircularDependency {
        extension_id: "ext-a".into(),
        dependency_chain: vec!["ext-b".into(), "ext-a".into()],
    };
    let s = err.to_string();
    assert!(s.contains("circular"));
    assert!(s.contains("ext-b -> ext-a"));
}

#[test]
fn reputation_graph_error_implements_std_error() {
    let err = ReputationGraphError::ExtensionNotFound {
        extension_id: "ext-1".into(),
    };
    let _: &dyn std::error::Error = &err;
}

// ---------------------------------------------------------------------------
// ReputationGraph — default
// ---------------------------------------------------------------------------

#[test]
fn default_graph_is_empty() {
    let graph = ReputationGraph::default();
    assert_eq!(graph.extension_count(), 0);
    assert_eq!(graph.evidence_count(), 0);
    assert_eq!(graph.edge_count(), 0);
    assert_eq!(graph.total_transitions(), 0);
}

// ---------------------------------------------------------------------------
// ReputationGraph — full lifecycle
// ---------------------------------------------------------------------------

#[test]
fn full_lifecycle_register_evidence_transition_revocation_override_lookup() {
    let mut graph = ReputationGraph::new();

    // Register publisher and extension.
    graph.register_publisher(test_publisher("pub-1"));
    graph
        .register_extension(test_extension("ext-1", "pub-1"))
        .unwrap();

    // Add evidence.
    graph.add_evidence("ext-1", test_evidence("ev-1")).unwrap();
    assert_eq!(graph.evidence_count(), 1);

    // Auto-upgrade: Unknown → Provisional.
    let tt1 = graph
        .transition_trust(
            "ext-1",
            TrustLevel::Provisional,
            vec!["ev-1".into()],
            1,
            epoch(1),
            1_000,
        )
        .unwrap();
    assert_eq!(tt1.old_level, TrustLevel::Unknown);
    assert!(!tt1.operator_override);

    // Auto-upgrade: Provisional → Established.
    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Established,
            vec!["ev-1".into()],
            1,
            epoch(1),
            2_000,
        )
        .unwrap();

    // Auto-degrade: Established → Suspicious.
    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Suspicious,
            vec!["ev-bad".into()],
            1,
            epoch(1),
            3_000,
        )
        .unwrap();

    // Auto-upgrade from degraded → denied.
    let result =
        graph.transition_trust("ext-1", TrustLevel::Established, vec![], 1, epoch(1), 4_000);
    assert!(matches!(
        result,
        Err(ReputationGraphError::AutoUpgradeDenied { .. })
    ));

    // Operator override: Suspicious → Provisional.
    let tt_override = graph
        .operator_trust_override(OperatorOverrideInput {
            extension_id: "ext-1".into(),
            new_level: TrustLevel::Provisional,
            justification: "Incident resolved".into(),
            evidence_ids: vec!["ev-resolution".into()],
            policy_version: 2,
            epoch: epoch(2),
            timestamp_ns: 5_000,
        })
        .unwrap();
    assert!(tt_override.operator_override);
    assert_eq!(tt_override.new_level, TrustLevel::Provisional);

    // Trust lookup reflects final state.
    let lookup = graph.trust_lookup("ext-1").unwrap();
    assert_eq!(lookup.current_trust_level, TrustLevel::Provisional);
    assert_eq!(lookup.transition_count, 4);
    assert_eq!(lookup.evidence_count, 1);
    assert_eq!(lookup.publisher_trust_score, Some(500_000));

    // Trust history ordered chronologically.
    let history = graph.trust_history("ext-1");
    assert_eq!(history.len(), 4);
    assert_eq!(history[0].new_level, TrustLevel::Provisional);
    assert_eq!(history[3].new_level, TrustLevel::Provisional);
    assert!(history[3].operator_override);
}

// ---------------------------------------------------------------------------
// Transitive revocation propagation
// ---------------------------------------------------------------------------

#[test]
fn revocation_propagation_transitive_chain() {
    let mut graph = ReputationGraph::new();

    // Chain: ext-a ← ext-b ← ext-c.
    graph
        .register_extension(test_extension("ext-a", "pub-1"))
        .unwrap();
    graph
        .register_extension(test_extension_with_deps("ext-b", "pub-1", &["ext-a"]))
        .unwrap();
    graph
        .register_extension(test_extension_with_deps("ext-c", "pub-1", &["ext-b"]))
        .unwrap();

    // Revoke ext-a.
    graph
        .transition_trust(
            "ext-a",
            TrustLevel::Revoked,
            vec!["incident-1".into()],
            1,
            epoch(1),
            1_000,
        )
        .unwrap();

    let impact = graph
        .propagate_revocation("ext-a", "incident-1", epoch(1), 2_000)
        .unwrap();

    // ext-b is directly affected (depends on ext-a).
    assert!(impact.directly_affected.contains("ext-b"));
    // ext-c is transitively affected (depends on ext-b).
    assert!(impact.transitively_affected.contains("ext-c"));
}

#[test]
fn revocation_propagation_does_not_degrade_already_degraded() {
    let mut graph = ReputationGraph::new();

    graph
        .register_extension(test_extension("ext-a", "pub-1"))
        .unwrap();

    let mut ext_b = test_extension_with_deps("ext-b", "pub-1", &["ext-a"]);
    ext_b.current_trust_level = TrustLevel::Compromised; // Already degraded.
    graph.register_extension(ext_b).unwrap();

    let impact = graph
        .propagate_revocation("ext-a", "inc-1", epoch(1), 1_000)
        .unwrap();

    // ext-b is directly affected but no transition generated (already degraded).
    assert!(impact.directly_affected.contains("ext-b"));
    assert!(impact.trust_degradations.is_empty());
    assert_eq!(
        graph.get_extension("ext-b").unwrap().current_trust_level,
        TrustLevel::Compromised
    );
}

// ---------------------------------------------------------------------------
// Trust transition ID monotonicity
// ---------------------------------------------------------------------------

#[test]
fn trust_transition_ids_are_monotonic() {
    let mut graph = ReputationGraph::new();
    graph
        .register_extension(test_extension("ext-1", "pub-1"))
        .unwrap();

    let tt1 = graph
        .transition_trust("ext-1", TrustLevel::Provisional, vec![], 1, epoch(1), 1_000)
        .unwrap();
    let tt2 = graph
        .transition_trust("ext-1", TrustLevel::Established, vec![], 1, epoch(1), 2_000)
        .unwrap();
    let tt3 = graph
        .transition_trust("ext-1", TrustLevel::Suspicious, vec![], 1, epoch(1), 3_000)
        .unwrap();

    assert!(tt1.transition_id < tt2.transition_id);
    assert!(tt2.transition_id < tt3.transition_id);
}

// ---------------------------------------------------------------------------
// Evidence and incident queries
// ---------------------------------------------------------------------------

#[test]
fn get_evidence_for_extension_returns_linked() {
    let mut graph = ReputationGraph::new();
    graph
        .register_extension(test_extension("ext-1", "pub-1"))
        .unwrap();
    graph
        .register_extension(test_extension("ext-2", "pub-1"))
        .unwrap();

    graph.add_evidence("ext-1", test_evidence("ev-1")).unwrap();
    graph.add_evidence("ext-1", test_evidence("ev-2")).unwrap();
    graph.add_evidence("ext-2", test_evidence("ev-3")).unwrap();

    let ev1 = graph.get_evidence_for_extension("ext-1");
    assert_eq!(ev1.len(), 2);
    let ev2 = graph.get_evidence_for_extension("ext-2");
    assert_eq!(ev2.len(), 1);
    let ev_none = graph.get_evidence_for_extension("nonexistent");
    assert!(ev_none.is_empty());
}

#[test]
fn incident_count_for_extension() {
    let mut graph = ReputationGraph::new();
    graph
        .register_extension(test_extension("ext-1", "pub-1"))
        .unwrap();
    graph
        .register_extension(test_extension("ext-2", "pub-1"))
        .unwrap();

    assert_eq!(graph.incident_count_for_extension("ext-1"), 0);

    let inc = IncidentNode {
        incident_id: "inc-1".into(),
        severity: IncidentSeverity::High,
        affected_extensions: ["ext-1".into()].into_iter().collect(),
        containment_actions: vec!["isolate".into()],
        resolution_status: ResolutionStatus::Active,
        timestamp_ns: 5_000_000_000,
    };
    graph.add_incident(inc);

    assert_eq!(graph.incident_count_for_extension("ext-1"), 1);
    assert_eq!(graph.incident_count_for_extension("ext-2"), 0);
}

// ---------------------------------------------------------------------------
// Dependency risk scoring
// ---------------------------------------------------------------------------

#[test]
fn dependency_risk_score_per_trust_level() {
    // Test the risk computation for each trust level.
    let trust_risk_pairs = [
        (TrustLevel::Trusted, 0),
        (TrustLevel::Established, 50_000),
        (TrustLevel::Provisional, 150_000),
        (TrustLevel::Unknown, 300_000),
        (TrustLevel::Suspicious, 500_000),
        (TrustLevel::Compromised, 800_000),
        (TrustLevel::Revoked, 1_000_000),
    ];

    for (level, expected_risk) in &trust_risk_pairs {
        let mut graph = ReputationGraph::new();
        let mut dep = test_extension("dep", "pub-1");
        dep.current_trust_level = *level;
        graph.register_extension(dep).unwrap();
        graph
            .register_extension(test_extension_with_deps("ext", "pub-1", &["dep"]))
            .unwrap();

        let result = graph.trust_lookup("ext").unwrap();
        assert_eq!(
            result.dependency_risk_score, *expected_risk,
            "risk for {level} should be {expected_risk}"
        );
    }
}

#[test]
fn dependency_risk_missing_dep_treated_as_high_risk() {
    let mut graph = ReputationGraph::new();
    // ext depends on "missing-dep" which is not registered.
    graph
        .register_extension(test_extension_with_deps("ext", "pub-1", &["missing-dep"]))
        .unwrap();

    let result = graph.trust_lookup("ext").unwrap();
    assert_eq!(result.dependency_risk_score, 500_000);
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

#[test]
fn provenance_with_gaps() {
    let mut graph = ReputationGraph::new();
    graph
        .register_extension(test_extension("ext-1", "pub-1"))
        .unwrap();

    let record = ProvenanceRecord {
        extension_id: "ext-1".into(),
        publisher_verified: false,
        build_attested: false,
        attestation_source: None,
        dependency_depth: 5,
        has_provenance_gap: true,
        gap_descriptions: vec!["unverified publisher".into(), "no build attestation".into()],
    };
    graph.set_provenance(record).unwrap();

    let prov = graph.get_provenance("ext-1").unwrap();
    assert!(!prov.publisher_verified);
    assert!(prov.has_provenance_gap);
    assert_eq!(prov.gap_descriptions.len(), 2);
}

// ---------------------------------------------------------------------------
// Operator override on nonexistent extension
// ---------------------------------------------------------------------------

#[test]
fn operator_override_nonexistent_extension_fails() {
    let mut graph = ReputationGraph::new();
    let result = graph.operator_trust_override(OperatorOverrideInput {
        extension_id: "nonexistent".into(),
        new_level: TrustLevel::Established,
        justification: "test".into(),
        evidence_ids: vec![],
        policy_version: 1,
        epoch: epoch(1),
        timestamp_ns: 1_000,
    });
    assert!(matches!(
        result,
        Err(ReputationGraphError::ExtensionNotFound { .. })
    ));
}

// ---------------------------------------------------------------------------
// can_auto_transition_to comprehensive
// ---------------------------------------------------------------------------

#[test]
fn can_auto_transition_to_downgrades_within_non_degraded_denied() {
    // Trusted → Established (downgrade within non-degraded) is not auto-allowed.
    assert!(!TrustLevel::Trusted.can_auto_transition_to(TrustLevel::Established));
    assert!(!TrustLevel::Trusted.can_auto_transition_to(TrustLevel::Provisional));
    assert!(!TrustLevel::Trusted.can_auto_transition_to(TrustLevel::Unknown));
    assert!(!TrustLevel::Established.can_auto_transition_to(TrustLevel::Provisional));
    assert!(!TrustLevel::Established.can_auto_transition_to(TrustLevel::Unknown));
    assert!(!TrustLevel::Provisional.can_auto_transition_to(TrustLevel::Unknown));
}

// ---------------------------------------------------------------------------
// Graph serde roundtrip with full data
// ---------------------------------------------------------------------------

#[test]
fn graph_serde_roundtrip_with_full_data() {
    let mut graph = ReputationGraph::new();

    graph.register_publisher(test_publisher("pub-1"));
    graph
        .register_extension(test_extension("ext-1", "pub-1"))
        .unwrap();
    graph
        .register_extension(test_extension_with_deps("ext-2", "pub-1", &["ext-1"]))
        .unwrap();

    graph.add_evidence("ext-1", test_evidence("ev-1")).unwrap();
    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Provisional,
            vec!["ev-1".into()],
            1,
            epoch(1),
            1_000,
        )
        .unwrap();

    let inc = IncidentNode {
        incident_id: "inc-1".into(),
        severity: IncidentSeverity::Medium,
        affected_extensions: ["ext-1".into()].into_iter().collect(),
        containment_actions: vec!["monitor".into()],
        resolution_status: ResolutionStatus::Resolved,
        timestamp_ns: 3_000,
    };
    graph.add_incident(inc);

    let record = ProvenanceRecord {
        extension_id: "ext-1".into(),
        publisher_verified: true,
        build_attested: true,
        attestation_source: Some("npm-provenance".into()),
        dependency_depth: 0,
        has_provenance_gap: false,
        gap_descriptions: vec![],
    };
    graph.set_provenance(record).unwrap();

    let json = serde_json::to_string(&graph).unwrap();
    let back: ReputationGraph = serde_json::from_str(&json).unwrap();

    assert_eq!(back.extension_count(), 2);
    assert_eq!(back.evidence_count(), 1);
    assert_eq!(back.total_transitions(), 1);
    assert!(back.get_extension("ext-1").is_some());
    assert!(back.get_publisher("pub-1").is_some());
    assert!(back.get_provenance("ext-1").is_some());
}

// ---------------------------------------------------------------------------
// Stress test
// ---------------------------------------------------------------------------

#[test]
fn stress_many_extensions_and_transitions() {
    let mut graph = ReputationGraph::new();
    graph.register_publisher(test_publisher("pub-1"));

    let n = 50u64;
    for i in 0..n {
        let ext = test_extension(&format!("ext-{i}"), "pub-1");
        graph.register_extension(ext).unwrap();
    }
    assert_eq!(graph.extension_count(), n as usize);

    // Transition each extension through Unknown → Provisional → Established.
    for i in 0..n {
        let id = format!("ext-{i}");
        graph
            .transition_trust(&id, TrustLevel::Provisional, vec![], 1, epoch(1), i * 1_000)
            .unwrap();
        graph
            .transition_trust(
                &id,
                TrustLevel::Established,
                vec![],
                1,
                epoch(1),
                i * 1_000 + 500,
            )
            .unwrap();
    }

    assert_eq!(graph.total_transitions(), (n * 2) as usize);

    // All extensions should be Established.
    for i in 0..n {
        let ext = graph.get_extension(&format!("ext-{i}")).unwrap();
        assert_eq!(ext.current_trust_level, TrustLevel::Established);
    }

    // Serde roundtrip preserves everything.
    let json = serde_json::to_string(&graph).unwrap();
    let back: ReputationGraph = serde_json::from_str(&json).unwrap();
    assert_eq!(back.extension_count(), n as usize);
    assert_eq!(back.total_transitions(), (n * 2) as usize);
}

// ---------------------------------------------------------------------------
// Multi-publisher trust lookup
// ---------------------------------------------------------------------------

#[test]
fn trust_lookup_without_publisher_registration() {
    let mut graph = ReputationGraph::new();
    graph
        .register_extension(test_extension("ext-1", "pub-1"))
        .unwrap();

    // Publisher not registered — trust score should be None.
    let result = graph.trust_lookup("ext-1").unwrap();
    assert_eq!(result.publisher_trust_score, None);
}

#[test]
fn trust_lookup_last_transition_populated() {
    let mut graph = ReputationGraph::new();
    graph
        .register_extension(test_extension("ext-1", "pub-1"))
        .unwrap();

    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Provisional,
            vec!["ev-1".into()],
            1,
            epoch(1),
            1_000,
        )
        .unwrap();
    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Suspicious,
            vec!["ev-bad".into()],
            1,
            epoch(1),
            2_000,
        )
        .unwrap();

    let result = graph.trust_lookup("ext-1").unwrap();
    assert_eq!(result.transition_count, 2);
    let last = result.last_transition.unwrap();
    assert_eq!(last.new_level, TrustLevel::Suspicious);
    assert_eq!(last.old_level, TrustLevel::Provisional);
}

// ---------------------------------------------------------------------------
// TrustLevel::is_degraded comprehensive
// ---------------------------------------------------------------------------

#[test]
fn trust_level_is_degraded_classification() {
    // Non-degraded states.
    assert!(!TrustLevel::Unknown.is_degraded());
    assert!(!TrustLevel::Provisional.is_degraded());
    assert!(!TrustLevel::Established.is_degraded());
    assert!(!TrustLevel::Trusted.is_degraded());

    // Degraded states.
    assert!(TrustLevel::Suspicious.is_degraded());
    assert!(TrustLevel::Compromised.is_degraded());
    assert!(TrustLevel::Revoked.is_degraded());
}

// ---------------------------------------------------------------------------
// can_auto_transition_to — upgrade and same-level paths
// ---------------------------------------------------------------------------

#[test]
fn can_auto_transition_to_same_level_always_allowed() {
    for level in &TrustLevel::ALL {
        assert!(
            level.can_auto_transition_to(*level),
            "same-level transition should be allowed for {level}"
        );
    }
}

#[test]
fn can_auto_transition_to_upgrade_paths_allowed() {
    // Non-degraded upgrade paths are auto-allowed.
    assert!(TrustLevel::Unknown.can_auto_transition_to(TrustLevel::Provisional));
    assert!(TrustLevel::Unknown.can_auto_transition_to(TrustLevel::Established));
    assert!(TrustLevel::Unknown.can_auto_transition_to(TrustLevel::Trusted));
    assert!(TrustLevel::Provisional.can_auto_transition_to(TrustLevel::Established));
    assert!(TrustLevel::Provisional.can_auto_transition_to(TrustLevel::Trusted));
    assert!(TrustLevel::Established.can_auto_transition_to(TrustLevel::Trusted));
}

#[test]
fn can_auto_transition_to_degraded_always_allowed() {
    // Any level can auto-transition to any degraded state.
    let degraded = [
        TrustLevel::Suspicious,
        TrustLevel::Compromised,
        TrustLevel::Revoked,
    ];
    for source in &TrustLevel::ALL {
        for target in &degraded {
            assert!(
                source.can_auto_transition_to(*target),
                "{source} -> {target} should be auto-allowed"
            );
        }
    }
}

#[test]
fn can_auto_transition_from_degraded_to_nondegraded_denied() {
    // From degraded back to non-degraded requires operator override.
    let degraded = [
        TrustLevel::Suspicious,
        TrustLevel::Compromised,
        TrustLevel::Revoked,
    ];
    let non_degraded = [
        TrustLevel::Unknown,
        TrustLevel::Provisional,
        TrustLevel::Established,
        TrustLevel::Trusted,
    ];
    for source in &degraded {
        for target in &non_degraded {
            assert!(
                !source.can_auto_transition_to(*target),
                "{source} -> {target} should be denied without operator override"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// ReputationGraphError serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn reputation_graph_error_serde_roundtrip_all_variants() {
    let errors: Vec<ReputationGraphError> = vec![
        ReputationGraphError::ExtensionNotFound {
            extension_id: "ext-missing".into(),
        },
        ReputationGraphError::PublisherNotFound {
            publisher_id: "pub-missing".into(),
        },
        ReputationGraphError::AutoUpgradeDenied {
            extension_id: "ext-1".into(),
            current: TrustLevel::Compromised,
            attempted: TrustLevel::Trusted,
        },
        ReputationGraphError::DuplicateExtension {
            extension_id: "ext-dup".into(),
        },
        ReputationGraphError::DuplicateEvidence {
            evidence_id: "ev-dup".into(),
        },
        ReputationGraphError::CircularDependency {
            extension_id: "ext-a".into(),
            dependency_chain: vec!["ext-b".into(), "ext-c".into(), "ext-a".into()],
        },
    ];

    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ReputationGraphError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ---------------------------------------------------------------------------
// RevocationImpact serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn revocation_impact_serde_roundtrip() {
    let impact = frankenengine_engine::reputation::RevocationImpact {
        directly_affected: ["ext-b".into()].into_iter().collect(),
        transitively_affected: ["ext-c".into(), "ext-d".into()].into_iter().collect(),
        trust_degradations: vec![TrustTransition {
            transition_id: "tt-00000001".into(),
            extension_id: "ext-b".into(),
            old_level: TrustLevel::Established,
            new_level: TrustLevel::Suspicious,
            triggering_evidence_ids: vec!["revocation-propagation:inc-1".into()],
            policy_version: 0,
            operator_override: false,
            operator_justification: None,
            timestamp_ns: 5_000,
            epoch: epoch(1),
        }],
    };
    let json = serde_json::to_string(&impact).unwrap();
    let back: frankenengine_engine::reputation::RevocationImpact =
        serde_json::from_str(&json).unwrap();
    assert_eq!(impact, back);
    assert_eq!(back.directly_affected.len(), 1);
    assert_eq!(back.transitively_affected.len(), 2);
    assert_eq!(back.trust_degradations.len(), 1);
}

// ---------------------------------------------------------------------------
// Error paths: duplicate extension, duplicate evidence, nonexistent lookups
// ---------------------------------------------------------------------------

#[test]
fn duplicate_extension_registration_returns_error() {
    let mut graph = ReputationGraph::new();
    graph
        .register_extension(test_extension("ext-1", "pub-1"))
        .unwrap();

    let result = graph.register_extension(test_extension("ext-1", "pub-1"));
    assert!(matches!(
        result,
        Err(ReputationGraphError::DuplicateExtension { .. })
    ));
    let err = result.unwrap_err();
    assert!(err.to_string().contains("ext-1"));
}

#[test]
fn duplicate_evidence_returns_error() {
    let mut graph = ReputationGraph::new();
    graph
        .register_extension(test_extension("ext-1", "pub-1"))
        .unwrap();
    graph.add_evidence("ext-1", test_evidence("ev-1")).unwrap();

    let result = graph.add_evidence("ext-1", test_evidence("ev-1"));
    assert!(matches!(
        result,
        Err(ReputationGraphError::DuplicateEvidence { .. })
    ));
}

#[test]
fn add_evidence_to_nonexistent_extension_fails() {
    let mut graph = ReputationGraph::new();
    let result = graph.add_evidence("nonexistent", test_evidence("ev-1"));
    assert!(matches!(
        result,
        Err(ReputationGraphError::ExtensionNotFound { .. })
    ));
}

#[test]
fn set_provenance_on_nonexistent_extension_fails() {
    let mut graph = ReputationGraph::new();
    let record = ProvenanceRecord {
        extension_id: "nonexistent".into(),
        publisher_verified: true,
        build_attested: true,
        attestation_source: Some("sigstore".into()),
        dependency_depth: 0,
        has_provenance_gap: false,
        gap_descriptions: vec![],
    };
    let result = graph.set_provenance(record);
    assert!(matches!(
        result,
        Err(ReputationGraphError::ExtensionNotFound { .. })
    ));
}

#[test]
fn trust_lookup_on_nonexistent_extension_fails() {
    let graph = ReputationGraph::new();
    let result = graph.trust_lookup("nonexistent");
    assert!(matches!(
        result,
        Err(ReputationGraphError::ExtensionNotFound { .. })
    ));
}

#[test]
fn propagate_revocation_on_nonexistent_extension_fails() {
    let mut graph = ReputationGraph::new();
    let result = graph.propagate_revocation("nonexistent", "inc-1", epoch(1), 1_000);
    assert!(matches!(
        result,
        Err(ReputationGraphError::ExtensionNotFound { .. })
    ));
}

// ---------------------------------------------------------------------------
// Dependency risk with multiple deps — average computation
// ---------------------------------------------------------------------------

#[test]
fn dependency_risk_averaged_across_multiple_deps() {
    let mut graph = ReputationGraph::new();

    // dep-a is Trusted (risk = 0), dep-b is Revoked (risk = 1_000_000).
    let mut dep_a = test_extension("dep-a", "pub-1");
    dep_a.current_trust_level = TrustLevel::Trusted;
    graph.register_extension(dep_a).unwrap();

    let mut dep_b = test_extension("dep-b", "pub-1");
    dep_b.current_trust_level = TrustLevel::Revoked;
    graph.register_extension(dep_b).unwrap();

    graph
        .register_extension(test_extension_with_deps(
            "ext",
            "pub-1",
            &["dep-a", "dep-b"],
        ))
        .unwrap();

    let result = graph.trust_lookup("ext").unwrap();
    // Average of 0 and 1_000_000 = 500_000.
    assert_eq!(result.dependency_risk_score, 500_000);
}

// ---------------------------------------------------------------------------
// Edge count tracking across operations
// ---------------------------------------------------------------------------

#[test]
fn edge_count_tracks_all_operations() {
    let mut graph = ReputationGraph::new();

    // register_extension adds a PublishedBy edge.
    graph
        .register_extension(test_extension("ext-1", "pub-1"))
        .unwrap();
    assert_eq!(graph.edge_count(), 1); // 1 PublishedBy

    // add_evidence adds an ObservedBehavior edge.
    graph.add_evidence("ext-1", test_evidence("ev-1")).unwrap();
    assert_eq!(graph.edge_count(), 2); // +1 ObservedBehavior

    // transition_trust adds a TrustTransitioned edge.
    graph
        .transition_trust("ext-1", TrustLevel::Provisional, vec![], 1, epoch(1), 1_000)
        .unwrap();
    assert_eq!(graph.edge_count(), 3); // +1 TrustTransitioned

    // add_incident adds RevokedBy edges for affected extensions.
    let inc = IncidentNode {
        incident_id: "inc-1".into(),
        severity: IncidentSeverity::High,
        affected_extensions: ["ext-1".into()].into_iter().collect(),
        containment_actions: vec!["isolate".into()],
        resolution_status: ResolutionStatus::Active,
        timestamp_ns: 5_000_000_000,
    };
    graph.add_incident(inc);
    assert_eq!(graph.edge_count(), 4); // +1 RevokedBy
}

// ---------------------------------------------------------------------------
// Clone semantics on ReputationGraph
// ---------------------------------------------------------------------------

#[test]
fn graph_clone_is_independent() {
    let mut graph = ReputationGraph::new();
    graph.register_publisher(test_publisher("pub-1"));
    graph
        .register_extension(test_extension("ext-1", "pub-1"))
        .unwrap();
    graph.add_evidence("ext-1", test_evidence("ev-1")).unwrap();
    graph
        .transition_trust("ext-1", TrustLevel::Provisional, vec![], 1, epoch(1), 1_000)
        .unwrap();

    let cloned = graph.clone();

    // Mutating the original does not affect the clone.
    graph
        .register_extension(test_extension("ext-2", "pub-1"))
        .unwrap();
    assert_eq!(graph.extension_count(), 2);
    assert_eq!(cloned.extension_count(), 1);

    // Clone preserves trust state.
    let lookup = cloned.trust_lookup("ext-1").unwrap();
    assert_eq!(lookup.current_trust_level, TrustLevel::Provisional);
    assert_eq!(lookup.transition_count, 1);
    assert_eq!(lookup.evidence_count, 1);
}

// ---------------------------------------------------------------------------
// trust_history for extension with no transitions
// ---------------------------------------------------------------------------

#[test]
fn trust_history_empty_for_extension_with_no_transitions() {
    let mut graph = ReputationGraph::new();
    graph
        .register_extension(test_extension("ext-1", "pub-1"))
        .unwrap();

    let history = graph.trust_history("ext-1");
    assert!(history.is_empty());

    // Also verify for nonexistent extension: returns empty (not an error).
    let history_none = graph.trust_history("nonexistent");
    assert!(history_none.is_empty());
}

// ---------------------------------------------------------------------------
// get_provenance returns None when not set
// ---------------------------------------------------------------------------

#[test]
fn get_provenance_returns_none_when_not_set() {
    let mut graph = ReputationGraph::new();
    graph
        .register_extension(test_extension("ext-1", "pub-1"))
        .unwrap();
    assert!(graph.get_provenance("ext-1").is_none());
    assert!(graph.get_provenance("nonexistent").is_none());
}

// ---------------------------------------------------------------------------
// Provenance overwrite on set_provenance
// ---------------------------------------------------------------------------

#[test]
fn set_provenance_overwrites_existing() {
    let mut graph = ReputationGraph::new();
    graph
        .register_extension(test_extension("ext-1", "pub-1"))
        .unwrap();

    let record1 = ProvenanceRecord {
        extension_id: "ext-1".into(),
        publisher_verified: false,
        build_attested: false,
        attestation_source: None,
        dependency_depth: 0,
        has_provenance_gap: true,
        gap_descriptions: vec!["no publisher verification".into()],
    };
    graph.set_provenance(record1).unwrap();
    assert!(graph.get_provenance("ext-1").unwrap().has_provenance_gap);

    let record2 = ProvenanceRecord {
        extension_id: "ext-1".into(),
        publisher_verified: true,
        build_attested: true,
        attestation_source: Some("sigstore".into()),
        dependency_depth: 0,
        has_provenance_gap: false,
        gap_descriptions: vec![],
    };
    graph.set_provenance(record2).unwrap();
    let prov = graph.get_provenance("ext-1").unwrap();
    assert!(!prov.has_provenance_gap);
    assert!(prov.publisher_verified);
    assert_eq!(prov.attestation_source.as_deref(), Some("sigstore"));
}

// ---------------------------------------------------------------------------
// TrustTransition serde roundtrip — non-operator (no override)
// ---------------------------------------------------------------------------

#[test]
fn trust_transition_without_override_serde_roundtrip() {
    let tt = TrustTransition {
        transition_id: "tt-00000042".into(),
        extension_id: "ext-42".into(),
        old_level: TrustLevel::Unknown,
        new_level: TrustLevel::Provisional,
        triggering_evidence_ids: vec!["ev-a".into(), "ev-b".into()],
        policy_version: 1,
        operator_override: false,
        operator_justification: None,
        timestamp_ns: 3_000_000_000,
        epoch: epoch(1),
    };
    let json = serde_json::to_string(&tt).unwrap();
    let back: TrustTransition = serde_json::from_str(&json).unwrap();
    assert_eq!(tt, back);
    assert!(!back.operator_override);
    assert!(back.operator_justification.is_none());
    assert_eq!(back.triggering_evidence_ids.len(), 2);
}

// ---------------------------------------------------------------------------
// Dependency risk with zero dependencies returns zero
// ---------------------------------------------------------------------------

#[test]
fn dependency_risk_zero_for_no_deps() {
    let mut graph = ReputationGraph::new();
    graph
        .register_extension(test_extension("ext-solo", "pub-1"))
        .unwrap();

    let result = graph.trust_lookup("ext-solo").unwrap();
    assert_eq!(result.dependency_risk_score, 0);
}

// ---------------------------------------------------------------------------
// Multiple publishers support
// ---------------------------------------------------------------------------

#[test]
fn multiple_publishers_with_different_trust_scores() {
    let mut graph = ReputationGraph::new();

    let mut pub1 = test_publisher("pub-1");
    pub1.trust_score = 900_000;
    graph.register_publisher(pub1);

    let mut pub2 = test_publisher("pub-2");
    pub2.trust_score = 200_000;
    graph.register_publisher(pub2);

    graph
        .register_extension(test_extension("ext-a", "pub-1"))
        .unwrap();
    graph
        .register_extension(test_extension("ext-b", "pub-2"))
        .unwrap();

    let lookup_a = graph.trust_lookup("ext-a").unwrap();
    assert_eq!(lookup_a.publisher_trust_score, Some(900_000));

    let lookup_b = graph.trust_lookup("ext-b").unwrap();
    assert_eq!(lookup_b.publisher_trust_score, Some(200_000));
}
