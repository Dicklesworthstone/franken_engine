#![forbid(unsafe_code)]
//! Enrichment integration tests for `reputation`.
//!
//! Adds TrustLevel Display/ordering, error uniqueness, serde roundtrips,
//! JSON field-name stability, Debug distinctness, graph construction,
//! trust transition rules, and revocation propagation beyond the existing
//! 34 integration tests.

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
    ReputationGraphError, ResolutionStatus, RevocationImpact, TrustLevel, TrustLookupResult,
    TrustTransition,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// 1) TrustLevel — Display + ordering + ALL
// ===========================================================================

#[test]
fn trust_level_display_all_distinct() {
    let displays: Vec<String> = TrustLevel::ALL.iter().map(|t| t.to_string()).collect();
    let unique: BTreeSet<_> = displays.iter().collect();
    assert_eq!(unique.len(), 7);
}

#[test]
fn trust_level_all_has_seven() {
    assert_eq!(TrustLevel::ALL.len(), 7);
}

#[test]
fn trust_level_ordering_stable() {
    let mut levels = [
        TrustLevel::Revoked,
        TrustLevel::Unknown,
        TrustLevel::Trusted,
        TrustLevel::Provisional,
    ];
    levels.sort();
    // Ordering should be deterministic
    let first = levels[0];
    let last = levels[levels.len() - 1];
    assert!(first <= last);
}

#[test]
fn trust_level_is_degraded() {
    assert!(!TrustLevel::Unknown.is_degraded());
    assert!(!TrustLevel::Provisional.is_degraded());
    assert!(!TrustLevel::Established.is_degraded());
    assert!(!TrustLevel::Trusted.is_degraded());
    assert!(TrustLevel::Suspicious.is_degraded());
    assert!(TrustLevel::Compromised.is_degraded());
    assert!(TrustLevel::Revoked.is_degraded());
}

#[test]
fn trust_level_can_auto_transition_degraded_only() {
    // Can auto-transition to degraded states
    assert!(TrustLevel::Trusted.can_auto_transition_to(TrustLevel::Suspicious));
    assert!(TrustLevel::Established.can_auto_transition_to(TrustLevel::Compromised));
    // Cannot auto-upgrade from degraded to non-degraded
    assert!(!TrustLevel::Suspicious.can_auto_transition_to(TrustLevel::Trusted));
    assert!(!TrustLevel::Compromised.can_auto_transition_to(TrustLevel::Established));
    assert!(!TrustLevel::Revoked.can_auto_transition_to(TrustLevel::Provisional));
}

// ===========================================================================
// 2) ReputationGraphError — Display uniqueness + std::error::Error
// ===========================================================================

#[test]
fn graph_error_display_all_unique() {
    let variants: Vec<String> = vec![
        ReputationGraphError::ExtensionNotFound {
            extension_id: "e1".into(),
        }
        .to_string(),
        ReputationGraphError::PublisherNotFound {
            publisher_id: "p1".into(),
        }
        .to_string(),
        ReputationGraphError::AutoUpgradeDenied {
            extension_id: "e2".into(),
            current: TrustLevel::Suspicious,
            attempted: TrustLevel::Trusted,
        }
        .to_string(),
        ReputationGraphError::DuplicateExtension {
            extension_id: "e3".into(),
        }
        .to_string(),
        ReputationGraphError::DuplicateEvidence {
            evidence_id: "ev1".into(),
        }
        .to_string(),
        ReputationGraphError::CircularDependency {
            extension_id: "e4".into(),
            dependency_chain: vec!["a".into(), "b".into()],
        }
        .to_string(),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), variants.len());
}

#[test]
fn graph_error_is_std_error() {
    let e = ReputationGraphError::ExtensionNotFound {
        extension_id: "x".into(),
    };
    let _: &dyn std::error::Error = &e;
}

#[test]
fn graph_error_display_contains_id() {
    let e = ReputationGraphError::ExtensionNotFound {
        extension_id: "my-ext-123".into(),
    };
    let s = e.to_string();
    assert!(s.contains("my-ext-123"), "should contain extension_id: {s}");
}

// ===========================================================================
// 3) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_trust_level() {
    let variants: Vec<String> = TrustLevel::ALL.iter().map(|t| format!("{t:?}")).collect();
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 7);
}

#[test]
fn debug_distinct_evidence_type() {
    let variants = [
        format!("{:?}", EvidenceType::BehavioralObservation),
        format!("{:?}", EvidenceType::AdversarialCampaignResult),
        format!("{:?}", EvidenceType::FleetEvidence),
        format!("{:?}", EvidenceType::IncidentRecord),
        format!("{:?}", EvidenceType::ThreatIntelligence),
        format!("{:?}", EvidenceType::ProvenanceAttestation),
        format!("{:?}", EvidenceType::OperatorAssessment),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 7);
}

#[test]
fn debug_distinct_evidence_source() {
    let variants = [
        format!("{:?}", EvidenceSource::BayesianSentinel),
        format!("{:?}", EvidenceSource::AdversarialCampaign),
        format!("{:?}", EvidenceSource::FleetImmuneSystem),
        format!("{:?}", EvidenceSource::OperatorManual),
        format!("{:?}", EvidenceSource::ExternalThreatFeed),
        format!("{:?}", EvidenceSource::BuildProvenance),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 6);
}

#[test]
fn debug_distinct_incident_severity() {
    let variants = [
        format!("{:?}", IncidentSeverity::Low),
        format!("{:?}", IncidentSeverity::Medium),
        format!("{:?}", IncidentSeverity::High),
        format!("{:?}", IncidentSeverity::Critical),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 4);
}

#[test]
fn debug_distinct_resolution_status() {
    let variants = [
        format!("{:?}", ResolutionStatus::Active),
        format!("{:?}", ResolutionStatus::Contained),
        format!("{:?}", ResolutionStatus::Resolved),
        format!("{:?}", ResolutionStatus::FalsePositive),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 4);
}

// ===========================================================================
// 4) Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_trust_level_all() {
    for t in TrustLevel::ALL {
        let json = serde_json::to_string(&t).unwrap();
        let rt: TrustLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(t, rt);
    }
}

#[test]
fn serde_roundtrip_evidence_type() {
    for et in [
        EvidenceType::BehavioralObservation,
        EvidenceType::AdversarialCampaignResult,
        EvidenceType::FleetEvidence,
        EvidenceType::IncidentRecord,
        EvidenceType::ThreatIntelligence,
        EvidenceType::ProvenanceAttestation,
        EvidenceType::OperatorAssessment,
    ] {
        let json = serde_json::to_string(&et).unwrap();
        let rt: EvidenceType = serde_json::from_str(&json).unwrap();
        assert_eq!(et, rt);
    }
}

#[test]
fn serde_roundtrip_evidence_source() {
    for es in [
        EvidenceSource::BayesianSentinel,
        EvidenceSource::AdversarialCampaign,
        EvidenceSource::FleetImmuneSystem,
        EvidenceSource::OperatorManual,
        EvidenceSource::ExternalThreatFeed,
        EvidenceSource::BuildProvenance,
    ] {
        let json = serde_json::to_string(&es).unwrap();
        let rt: EvidenceSource = serde_json::from_str(&json).unwrap();
        assert_eq!(es, rt);
    }
}

#[test]
fn serde_roundtrip_incident_severity() {
    for s in [
        IncidentSeverity::Low,
        IncidentSeverity::Medium,
        IncidentSeverity::High,
        IncidentSeverity::Critical,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let rt: IncidentSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(s, rt);
    }
}

#[test]
fn serde_roundtrip_resolution_status() {
    for s in [
        ResolutionStatus::Active,
        ResolutionStatus::Contained,
        ResolutionStatus::Resolved,
        ResolutionStatus::FalsePositive,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let rt: ResolutionStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, rt);
    }
}

#[test]
fn serde_roundtrip_extension_node() {
    let node = ExtensionNode {
        extension_id: "ext-1".into(),
        package_name: "pkg".into(),
        version: "1.0.0".into(),
        publisher_id: "pub-1".into(),
        manifest_hash: [0xAA; 32],
        first_seen_ns: 1000,
        current_trust_level: TrustLevel::Provisional,
        dependencies: BTreeSet::new(),
    };
    let json = serde_json::to_string(&node).unwrap();
    let rt: ExtensionNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, rt);
}

#[test]
fn serde_roundtrip_publisher_node() {
    let node = PublisherNode {
        publisher_id: "pub-1".into(),
        identity_attestation: [0xBB; 32],
        published_count: 5,
        trust_score: 800_000,
        first_published_ns: 500,
    };
    let json = serde_json::to_string(&node).unwrap();
    let rt: PublisherNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, rt);
}

#[test]
fn serde_roundtrip_evidence_node() {
    let node = EvidenceNode {
        evidence_id: "ev-1".into(),
        evidence_type: EvidenceType::BehavioralObservation,
        source: EvidenceSource::BayesianSentinel,
        timestamp_ns: 2000,
        content_hash: [0xCC; 32],
        linked_decision_ids: vec!["d1".into()],
        epoch: SecurityEpoch::from_raw(1),
    };
    let json = serde_json::to_string(&node).unwrap();
    let rt: EvidenceNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, rt);
}

#[test]
fn serde_roundtrip_incident_node() {
    let node = IncidentNode {
        incident_id: "inc-1".into(),
        severity: IncidentSeverity::High,
        affected_extensions: {
            let mut s = BTreeSet::new();
            s.insert("ext-1".into());
            s
        },
        containment_actions: vec!["revoke".into()],
        resolution_status: ResolutionStatus::Active,
        timestamp_ns: 3000,
    };
    let json = serde_json::to_string(&node).unwrap();
    let rt: IncidentNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, rt);
}

#[test]
fn serde_roundtrip_graph_error_all() {
    let variants = vec![
        ReputationGraphError::ExtensionNotFound {
            extension_id: "e1".into(),
        },
        ReputationGraphError::PublisherNotFound {
            publisher_id: "p1".into(),
        },
        ReputationGraphError::AutoUpgradeDenied {
            extension_id: "e2".into(),
            current: TrustLevel::Suspicious,
            attempted: TrustLevel::Trusted,
        },
        ReputationGraphError::DuplicateExtension {
            extension_id: "e3".into(),
        },
        ReputationGraphError::DuplicateEvidence {
            evidence_id: "ev1".into(),
        },
        ReputationGraphError::CircularDependency {
            extension_id: "e4".into(),
            dependency_chain: vec!["a".into(), "b".into()],
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let rt: ReputationGraphError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, rt);
    }
}

#[test]
fn serde_roundtrip_edge_type() {
    let edges = vec![
        EdgeType::PublishedBy {
            extension_id: "e".into(),
            publisher_id: "p".into(),
        },
        EdgeType::DependsOn {
            dependent_id: "a".into(),
            dependency_id: "b".into(),
        },
        EdgeType::DerivedFrom {
            new_version_id: "v2".into(),
            old_version_id: "v1".into(),
        },
        EdgeType::ObservedBehavior {
            extension_id: "e".into(),
            evidence_id: "ev".into(),
        },
        EdgeType::RevokedBy {
            extension_id: "e".into(),
            incident_id: "i".into(),
        },
        EdgeType::RevocationPropagatedTo {
            source_extension_id: "s".into(),
            target_extension_id: "t".into(),
            incident_id: "i".into(),
        },
        EdgeType::TrustTransitioned {
            extension_id: "e".into(),
            transition_id: "tr".into(),
        },
    ];
    for e in &edges {
        let json = serde_json::to_string(e).unwrap();
        let rt: EdgeType = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, rt);
    }
}

// ===========================================================================
// 5) JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_extension_node() {
    let node = ExtensionNode {
        extension_id: "e".into(),
        package_name: "p".into(),
        version: "1.0".into(),
        publisher_id: "pub".into(),
        manifest_hash: [0; 32],
        first_seen_ns: 0,
        current_trust_level: TrustLevel::Unknown,
        dependencies: BTreeSet::new(),
    };
    let v: serde_json::Value = serde_json::to_value(&node).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "extension_id",
        "package_name",
        "version",
        "publisher_id",
        "manifest_hash",
        "first_seen_ns",
        "current_trust_level",
        "dependencies",
    ] {
        assert!(obj.contains_key(key), "ExtensionNode missing field: {key}");
    }
}

#[test]
fn json_fields_publisher_node() {
    let node = PublisherNode {
        publisher_id: "p".into(),
        identity_attestation: [0; 32],
        published_count: 0,
        trust_score: 0,
        first_published_ns: 0,
    };
    let v: serde_json::Value = serde_json::to_value(&node).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "publisher_id",
        "identity_attestation",
        "published_count",
        "trust_score",
        "first_published_ns",
    ] {
        assert!(obj.contains_key(key), "PublisherNode missing field: {key}");
    }
}

#[test]
fn json_fields_evidence_node() {
    let node = EvidenceNode {
        evidence_id: "e".into(),
        evidence_type: EvidenceType::FleetEvidence,
        source: EvidenceSource::BuildProvenance,
        timestamp_ns: 0,
        content_hash: [0; 32],
        linked_decision_ids: vec![],
        epoch: SecurityEpoch::from_raw(0),
    };
    let v: serde_json::Value = serde_json::to_value(&node).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "evidence_id",
        "evidence_type",
        "source",
        "timestamp_ns",
        "content_hash",
        "linked_decision_ids",
        "epoch",
    ] {
        assert!(obj.contains_key(key), "EvidenceNode missing field: {key}");
    }
}

#[test]
fn json_fields_incident_node() {
    let node = IncidentNode {
        incident_id: "i".into(),
        severity: IncidentSeverity::Low,
        affected_extensions: BTreeSet::new(),
        containment_actions: vec![],
        resolution_status: ResolutionStatus::Active,
        timestamp_ns: 0,
    };
    let v: serde_json::Value = serde_json::to_value(&node).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "incident_id",
        "severity",
        "affected_extensions",
        "containment_actions",
        "resolution_status",
        "timestamp_ns",
    ] {
        assert!(obj.contains_key(key), "IncidentNode missing field: {key}");
    }
}

#[test]
fn json_fields_provenance_record() {
    let rec = ProvenanceRecord {
        extension_id: "e".into(),
        publisher_verified: true,
        build_attested: false,
        attestation_source: None,
        dependency_depth: 0,
        has_provenance_gap: false,
        gap_descriptions: vec![],
    };
    let v: serde_json::Value = serde_json::to_value(&rec).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "extension_id",
        "publisher_verified",
        "build_attested",
        "attestation_source",
        "dependency_depth",
        "has_provenance_gap",
        "gap_descriptions",
    ] {
        assert!(
            obj.contains_key(key),
            "ProvenanceRecord missing field: {key}"
        );
    }
}

// ===========================================================================
// 6) ReputationGraph — construction and initial state
// ===========================================================================

#[test]
fn graph_new_empty() {
    let graph = ReputationGraph::new();
    assert_eq!(graph.extension_count(), 0);
    assert_eq!(graph.evidence_count(), 0);
    assert_eq!(graph.edge_count(), 0);
    assert_eq!(graph.total_transitions(), 0);
}

#[test]
fn graph_default_matches_new() {
    let g1 = ReputationGraph::new();
    let g2 = ReputationGraph::default();
    assert_eq!(g1.extension_count(), g2.extension_count());
    assert_eq!(g1.evidence_count(), g2.evidence_count());
}

#[test]
fn graph_get_extension_unknown() {
    let graph = ReputationGraph::new();
    assert!(graph.get_extension("nonexistent").is_none());
}

#[test]
fn graph_get_publisher_unknown() {
    let graph = ReputationGraph::new();
    assert!(graph.get_publisher("nonexistent").is_none());
}

#[test]
fn graph_trust_history_unknown() {
    let graph = ReputationGraph::new();
    assert!(graph.trust_history("nonexistent").is_empty());
}

// ===========================================================================
// 7) ReputationGraph — register + lookup
// ===========================================================================

fn make_extension(id: &str, publisher: &str) -> ExtensionNode {
    ExtensionNode {
        extension_id: id.into(),
        package_name: format!("pkg-{id}"),
        version: "1.0.0".into(),
        publisher_id: publisher.into(),
        manifest_hash: [0x11; 32],
        first_seen_ns: 1000,
        current_trust_level: TrustLevel::Provisional,
        dependencies: BTreeSet::new(),
    }
}

fn make_publisher(id: &str) -> PublisherNode {
    PublisherNode {
        publisher_id: id.into(),
        identity_attestation: [0x22; 32],
        published_count: 1,
        trust_score: 500_000,
        first_published_ns: 500,
    }
}

#[test]
fn graph_register_extension_and_lookup() {
    let mut graph = ReputationGraph::new();
    graph.register_publisher(make_publisher("pub-1"));
    graph
        .register_extension(make_extension("ext-1", "pub-1"))
        .unwrap();

    assert_eq!(graph.extension_count(), 1);
    let ext = graph.get_extension("ext-1").unwrap();
    assert_eq!(ext.extension_id, "ext-1");
    assert_eq!(ext.current_trust_level, TrustLevel::Provisional);
}

#[test]
fn graph_duplicate_extension_rejected() {
    let mut graph = ReputationGraph::new();
    graph.register_publisher(make_publisher("pub-1"));
    graph
        .register_extension(make_extension("ext-1", "pub-1"))
        .unwrap();
    let result = graph.register_extension(make_extension("ext-1", "pub-1"));
    assert!(result.is_err());
}

#[test]
fn graph_trust_lookup() {
    let mut graph = ReputationGraph::new();
    graph.register_publisher(make_publisher("pub-1"));
    graph
        .register_extension(make_extension("ext-1", "pub-1"))
        .unwrap();

    let lookup = graph.trust_lookup("ext-1").unwrap();
    assert_eq!(lookup.extension_id, "ext-1");
    assert_eq!(lookup.current_trust_level, TrustLevel::Provisional);
    assert_eq!(lookup.transition_count, 0);
}

#[test]
fn graph_trust_lookup_unknown_fails() {
    let graph = ReputationGraph::new();
    assert!(graph.trust_lookup("nonexistent").is_err());
}

// ===========================================================================
// 8) Trust transitions — auto + operator override
// ===========================================================================

#[test]
fn graph_auto_degradation_succeeds() {
    let mut graph = ReputationGraph::new();
    graph.register_publisher(make_publisher("pub-1"));
    graph
        .register_extension(make_extension("ext-1", "pub-1"))
        .unwrap();

    let transition = graph
        .transition_trust(
            "ext-1",
            TrustLevel::Suspicious,
            vec!["ev-1".into()],
            1,
            SecurityEpoch::from_raw(1),
            2000,
        )
        .unwrap();
    assert_eq!(transition.old_level, TrustLevel::Provisional);
    assert_eq!(transition.new_level, TrustLevel::Suspicious);
    assert!(!transition.operator_override);
}

#[test]
fn graph_auto_upgrade_from_degraded_denied() {
    let mut graph = ReputationGraph::new();
    graph.register_publisher(make_publisher("pub-1"));
    graph
        .register_extension(make_extension("ext-1", "pub-1"))
        .unwrap();

    // First degrade
    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Suspicious,
            vec!["ev-1".into()],
            1,
            SecurityEpoch::from_raw(1),
            2000,
        )
        .unwrap();

    // Try to auto-upgrade — should fail
    let result = graph.transition_trust(
        "ext-1",
        TrustLevel::Trusted,
        vec!["ev-2".into()],
        1,
        SecurityEpoch::from_raw(1),
        3000,
    );
    assert!(result.is_err());
}

#[test]
fn graph_operator_override_from_degraded() {
    let mut graph = ReputationGraph::new();
    graph.register_publisher(make_publisher("pub-1"));
    graph
        .register_extension(make_extension("ext-1", "pub-1"))
        .unwrap();

    // First degrade
    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Suspicious,
            vec!["ev-1".into()],
            1,
            SecurityEpoch::from_raw(1),
            2000,
        )
        .unwrap();

    // Operator override should work
    let transition = graph
        .operator_trust_override(OperatorOverrideInput {
            extension_id: "ext-1".into(),
            new_level: TrustLevel::Established,
            justification: "False positive confirmed".into(),
            evidence_ids: vec!["ev-2".into()],
            policy_version: 1,
            epoch: SecurityEpoch::from_raw(1),
            timestamp_ns: 3000,
        })
        .unwrap();
    assert!(transition.operator_override);
    assert_eq!(transition.new_level, TrustLevel::Established);
}

// ===========================================================================
// 9) Evidence management
// ===========================================================================

#[test]
fn graph_add_evidence() {
    let mut graph = ReputationGraph::new();
    graph.register_publisher(make_publisher("pub-1"));
    graph
        .register_extension(make_extension("ext-1", "pub-1"))
        .unwrap();

    let evidence = EvidenceNode {
        evidence_id: "ev-1".into(),
        evidence_type: EvidenceType::BehavioralObservation,
        source: EvidenceSource::BayesianSentinel,
        timestamp_ns: 2000,
        content_hash: [0xCC; 32],
        linked_decision_ids: vec!["d1".into()],
        epoch: SecurityEpoch::from_raw(1),
    };
    graph.add_evidence("ext-1", evidence).unwrap();
    assert_eq!(graph.evidence_count(), 1);

    let evs = graph.get_evidence_for_extension("ext-1");
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].evidence_id, "ev-1");
}

#[test]
fn graph_add_evidence_unknown_extension_fails() {
    let mut graph = ReputationGraph::new();
    let evidence = EvidenceNode {
        evidence_id: "ev-1".into(),
        evidence_type: EvidenceType::FleetEvidence,
        source: EvidenceSource::FleetImmuneSystem,
        timestamp_ns: 1000,
        content_hash: [0; 32],
        linked_decision_ids: vec![],
        epoch: SecurityEpoch::from_raw(0),
    };
    assert!(graph.add_evidence("nonexistent", evidence).is_err());
}

// ===========================================================================
// 10) Provenance
// ===========================================================================

#[test]
fn graph_provenance_set_and_get() {
    let mut graph = ReputationGraph::new();
    graph.register_publisher(make_publisher("pub-1"));
    graph
        .register_extension(make_extension("ext-1", "pub-1"))
        .unwrap();

    let prov = ProvenanceRecord {
        extension_id: "ext-1".into(),
        publisher_verified: true,
        build_attested: true,
        attestation_source: Some("ci-pipeline".into()),
        dependency_depth: 2,
        has_provenance_gap: false,
        gap_descriptions: vec![],
    };
    graph.set_provenance(prov).unwrap();

    let got = graph.get_provenance("ext-1").unwrap();
    assert!(got.publisher_verified);
    assert!(got.build_attested);
}

#[test]
fn graph_provenance_unknown_extension_fails() {
    let mut graph = ReputationGraph::new();
    let prov = ProvenanceRecord {
        extension_id: "nonexistent".into(),
        publisher_verified: false,
        build_attested: false,
        attestation_source: None,
        dependency_depth: 0,
        has_provenance_gap: true,
        gap_descriptions: vec!["no publisher".into()],
    };
    assert!(graph.set_provenance(prov).is_err());
}

// ===========================================================================
// 11) Serde roundtrips for complex types
// ===========================================================================

#[test]
fn serde_roundtrip_trust_transition() {
    let tt = TrustTransition {
        transition_id: "tr-1".into(),
        extension_id: "ext-1".into(),
        old_level: TrustLevel::Provisional,
        new_level: TrustLevel::Suspicious,
        triggering_evidence_ids: vec!["ev-1".into()],
        policy_version: 1,
        operator_override: false,
        operator_justification: None,
        timestamp_ns: 5000,
        epoch: SecurityEpoch::from_raw(1),
    };
    let json = serde_json::to_string(&tt).unwrap();
    let rt: TrustTransition = serde_json::from_str(&json).unwrap();
    assert_eq!(tt, rt);
}

#[test]
fn serde_roundtrip_provenance_record() {
    let pr = ProvenanceRecord {
        extension_id: "ext-1".into(),
        publisher_verified: true,
        build_attested: false,
        attestation_source: Some("ci".into()),
        dependency_depth: 3,
        has_provenance_gap: true,
        gap_descriptions: vec!["gap1".into()],
    };
    let json = serde_json::to_string(&pr).unwrap();
    let rt: ProvenanceRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(pr, rt);
}

#[test]
fn serde_roundtrip_trust_lookup_result() {
    let tlr = TrustLookupResult {
        extension_id: "ext-1".into(),
        current_trust_level: TrustLevel::Established,
        transition_count: 2,
        last_transition: None,
        evidence_count: 3,
        dependency_risk_score: 150_000,
        publisher_trust_score: Some(800_000),
    };
    let json = serde_json::to_string(&tlr).unwrap();
    let rt: TrustLookupResult = serde_json::from_str(&json).unwrap();
    assert_eq!(tlr, rt);
}

#[test]
fn serde_roundtrip_revocation_impact() {
    let ri = RevocationImpact {
        directly_affected: {
            let mut s = BTreeSet::new();
            s.insert("ext-1".into());
            s
        },
        transitively_affected: BTreeSet::new(),
        trust_degradations: vec![],
    };
    let json = serde_json::to_string(&ri).unwrap();
    let rt: RevocationImpact = serde_json::from_str(&json).unwrap();
    assert_eq!(ri, rt);
}
