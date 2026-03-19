//! Integration-level enrichment tests for the `ifc_provenance_index` module.
//!
//! Covers: Copy/Clone semantics, BTreeSet ordering, serde roundtrips,
//! Display coverage, Debug non-empty, std::error::Error compliance,
//! CRUD lifecycle, lineage queries, confinement status, replay joins,
//! extension isolation, time range and epoch queries, error codes,
//! JSON field-name stability, deterministic ordering, and record counts.

use std::collections::BTreeSet;

use frankenengine_engine::ifc_artifacts::{
    ClaimStrength, DeclassificationDecision, Label, ProofMethod,
};
use frankenengine_engine::ifc_provenance_index::{
    ConfinementClaimRecord, ConfinementStatus, DeclassReceiptRecord, FlowDecision, FlowEventRecord,
    FlowProofRecord, IfcProvenanceIndex, LineageEvidenceType, LineageHop, LineagePath,
    ProvenanceError, ProvenanceEvent, RecordCounts, error_code,
};
use frankenengine_engine::storage_adapter::{EventContext, InMemoryStorageAdapter};

// ── helpers ─────────────────────────────────────────────────────────────

fn ctx() -> EventContext {
    EventContext::new("trace-enr", "decision-enr", "policy-enr").unwrap()
}

fn make_index() -> IfcProvenanceIndex<InMemoryStorageAdapter> {
    IfcProvenanceIndex::new(InMemoryStorageAdapter::new())
}

fn flow_event(id: &str, ext: &str, src: Label, sink: Label, dec: FlowDecision) -> FlowEventRecord {
    FlowEventRecord {
        event_id: id.to_string(),
        extension_id: ext.to_string(),
        source_label: src,
        sink_clearance: sink,
        flow_location: "src/test.rs:1".to_string(),
        decision: dec,
        receipt_ref: None,
        timestamp_ms: 1000,
    }
}

fn flow_proof(id: &str, ext: &str, src: Label, sink: Label, epoch: u64) -> FlowProofRecord {
    FlowProofRecord {
        proof_id: id.to_string(),
        extension_id: ext.to_string(),
        source_label: src,
        sink_clearance: sink,
        proof_method: ProofMethod::StaticAnalysis,
        epoch_id: epoch,
    }
}

fn declass_receipt(
    id: &str,
    ext: &str,
    src: Label,
    sink: Label,
    decision: DeclassificationDecision,
) -> DeclassReceiptRecord {
    DeclassReceiptRecord {
        receipt_id: id.to_string(),
        extension_id: ext.to_string(),
        decision,
        source_label: src,
        sink_clearance: sink,
        declassification_route_ref: format!("route-{id}"),
        decision_contract_id: format!("decision-{id}"),
        timestamp_ms: 2000,
    }
}

fn confinement_claim(
    id: &str,
    ext: &str,
    strength: ClaimStrength,
    epoch: u64,
) -> ConfinementClaimRecord {
    ConfinementClaimRecord {
        claim_id: id.to_string(),
        extension_id: ext.to_string(),
        claim_strength: strength,
        epoch_id: epoch,
    }
}

// ── Copy semantics ──────────────────────────────────────────────────────

#[test]
fn enrichment_flow_decision_copy() {
    let a = FlowDecision::Allowed;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_flow_decision_copy_all_variants() {
    for v in [
        FlowDecision::Allowed,
        FlowDecision::Blocked,
        FlowDecision::Declassified,
    ] {
        let copy = v;
        assert_eq!(v, copy);
    }
}

#[test]
fn enrichment_lineage_evidence_type_copy() {
    let a = LineageEvidenceType::FlowEvent;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_lineage_evidence_type_copy_all_variants() {
    for v in [
        LineageEvidenceType::FlowEvent,
        LineageEvidenceType::FlowProof,
        LineageEvidenceType::DeclassificationReceipt,
    ] {
        let copy = v;
        assert_eq!(v, copy);
    }
}

// ── Clone independence ──────────────────────────────────────────────────

#[test]
fn enrichment_flow_event_record_clone_independence() {
    let original = flow_event(
        "ev1",
        "ext-a",
        Label::Public,
        Label::Internal,
        FlowDecision::Allowed,
    );
    let mut cloned = original.clone();
    cloned.event_id = "modified".to_string();
    cloned.timestamp_ms = 9999;
    assert_eq!(original.event_id, "ev1");
    assert_eq!(original.timestamp_ms, 1000);
}

#[test]
fn enrichment_flow_proof_record_clone_independence() {
    let original = flow_proof("p1", "ext-a", Label::Public, Label::Internal, 1);
    let mut cloned = original.clone();
    cloned.proof_id = "modified".to_string();
    cloned.epoch_id = 99;
    assert_eq!(original.proof_id, "p1");
    assert_eq!(original.epoch_id, 1);
}

#[test]
fn enrichment_declass_receipt_clone_independence() {
    let original = declass_receipt(
        "r1",
        "ext-a",
        Label::Secret,
        Label::Public,
        DeclassificationDecision::Allow,
    );
    let mut cloned = original.clone();
    cloned.receipt_id = "modified".to_string();
    cloned.decision = DeclassificationDecision::Deny;
    assert_eq!(original.receipt_id, "r1");
    assert_eq!(original.decision, DeclassificationDecision::Allow);
}

#[test]
fn enrichment_confinement_claim_clone_independence() {
    let original = confinement_claim("c1", "ext-a", ClaimStrength::Full, 1);
    let mut cloned = original.clone();
    cloned.claim_id = "modified".to_string();
    cloned.claim_strength = ClaimStrength::Partial;
    assert_eq!(original.claim_id, "c1");
    assert_eq!(original.claim_strength, ClaimStrength::Full);
}

#[test]
fn enrichment_lineage_hop_clone_independence() {
    let original = LineageHop {
        source_label: Label::Public,
        sink_clearance: Label::Internal,
        evidence_ref: "ev1".to_string(),
        evidence_type: LineageEvidenceType::FlowEvent,
    };
    let mut cloned = original.clone();
    cloned.evidence_ref = "modified".to_string();
    assert_eq!(original.evidence_ref, "ev1");
}

#[test]
fn enrichment_lineage_path_clone_independence() {
    let original = LineagePath {
        extension_id: "ext-a".to_string(),
        hops: vec![LineageHop {
            source_label: Label::Public,
            sink_clearance: Label::Internal,
            evidence_ref: "ev1".to_string(),
            evidence_type: LineageEvidenceType::FlowEvent,
        }],
    };
    let mut cloned = original.clone();
    cloned.hops.clear();
    assert_eq!(original.hops.len(), 1);
}

#[test]
fn enrichment_confinement_status_clone_independence() {
    let original = ConfinementStatus {
        extension_id: "ext-a".to_string(),
        proven_flows: 5,
        unproven_flows: 2,
        strongest_claim: Some(ClaimStrength::Full),
        latest_proof_epoch: Some(3),
    };
    let mut cloned = original.clone();
    cloned.proven_flows = 0;
    cloned.strongest_claim = None;
    assert_eq!(original.proven_flows, 5);
    assert_eq!(original.strongest_claim, Some(ClaimStrength::Full));
}

#[test]
fn enrichment_record_counts_clone_independence() {
    let original = RecordCounts {
        flow_events: 10,
        flow_proofs: 5,
        declass_receipts: 3,
        confinement_claims: 2,
    };
    let cloned = original.clone();
    assert_eq!(cloned.flow_events, original.flow_events);
    assert_eq!(cloned.total(), original.total());
}

// ── BTreeSet ordering ───────────────────────────────────────────────────

#[test]
fn enrichment_flow_decision_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(FlowDecision::Declassified);
    set.insert(FlowDecision::Allowed);
    set.insert(FlowDecision::Blocked);
    let ordered: Vec<_> = set.iter().collect();
    assert_eq!(ordered.len(), 3);
    for window in ordered.windows(2) {
        assert!(window[0] < window[1]);
    }
}

#[test]
fn enrichment_lineage_evidence_type_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(LineageEvidenceType::DeclassificationReceipt);
    set.insert(LineageEvidenceType::FlowEvent);
    set.insert(LineageEvidenceType::FlowProof);
    assert_eq!(set.len(), 3);
    let ordered: Vec<_> = set.iter().collect();
    for window in ordered.windows(2) {
        assert!(window[0] < window[1]);
    }
}

#[test]
fn enrichment_flow_decision_btreeset_dedup() {
    let mut set = BTreeSet::new();
    set.insert(FlowDecision::Allowed);
    set.insert(FlowDecision::Allowed);
    assert_eq!(set.len(), 1);
}

// ── Serde roundtrips ────────────────────────────────────────────────────

#[test]
fn enrichment_flow_event_record_serde_with_receipt_ref() {
    let mut ev = flow_event(
        "ev1",
        "ext-a",
        Label::Confidential,
        Label::Public,
        FlowDecision::Declassified,
    );
    ev.receipt_ref = Some("r1".to_string());
    let json = serde_json::to_string(&ev).unwrap();
    let back: FlowEventRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
    assert_eq!(back.receipt_ref, Some("r1".to_string()));
}

#[test]
fn enrichment_flow_event_record_serde_without_receipt_ref() {
    let ev = flow_event(
        "ev1",
        "ext-a",
        Label::Public,
        Label::Internal,
        FlowDecision::Allowed,
    );
    let json = serde_json::to_string(&ev).unwrap();
    let back: FlowEventRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
    assert!(back.receipt_ref.is_none());
}

#[test]
fn enrichment_flow_proof_record_serde_roundtrip() {
    let proof = flow_proof("p1", "ext-a", Label::Internal, Label::Confidential, 5);
    let json = serde_json::to_string(&proof).unwrap();
    let back: FlowProofRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(proof, back);
}

#[test]
fn enrichment_declass_receipt_serde_roundtrip() {
    let receipt = declass_receipt(
        "r1",
        "ext-a",
        Label::Secret,
        Label::Public,
        DeclassificationDecision::Allow,
    );
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DeclassReceiptRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn enrichment_confinement_claim_serde_roundtrip() {
    let claim = confinement_claim("c1", "ext-a", ClaimStrength::Full, 7);
    let json = serde_json::to_string(&claim).unwrap();
    let back: ConfinementClaimRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(claim, back);
}

#[test]
fn enrichment_lineage_hop_serde_roundtrip() {
    let hop = LineageHop {
        source_label: Label::Confidential,
        sink_clearance: Label::Public,
        evidence_ref: "ev1".to_string(),
        evidence_type: LineageEvidenceType::FlowEvent,
    };
    let json = serde_json::to_string(&hop).unwrap();
    let back: LineageHop = serde_json::from_str(&json).unwrap();
    assert_eq!(hop, back);
}

#[test]
fn enrichment_lineage_path_serde_roundtrip() {
    let path = LineagePath {
        extension_id: "ext-a".to_string(),
        hops: vec![
            LineageHop {
                source_label: Label::Public,
                sink_clearance: Label::Internal,
                evidence_ref: "ev1".to_string(),
                evidence_type: LineageEvidenceType::FlowEvent,
            },
            LineageHop {
                source_label: Label::Internal,
                sink_clearance: Label::Confidential,
                evidence_ref: "p1".to_string(),
                evidence_type: LineageEvidenceType::FlowProof,
            },
        ],
    };
    let json = serde_json::to_string(&path).unwrap();
    let back: LineagePath = serde_json::from_str(&json).unwrap();
    assert_eq!(path, back);
}

#[test]
fn enrichment_confinement_status_serde_roundtrip() {
    let status = ConfinementStatus {
        extension_id: "ext-a".to_string(),
        proven_flows: 5,
        unproven_flows: 2,
        strongest_claim: Some(ClaimStrength::Full),
        latest_proof_epoch: Some(3),
    };
    let json = serde_json::to_string(&status).unwrap();
    let back: ConfinementStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(status, back);
}

#[test]
fn enrichment_confinement_status_serde_none_fields() {
    let status = ConfinementStatus {
        extension_id: "ext-z".to_string(),
        proven_flows: 0,
        unproven_flows: 0,
        strongest_claim: None,
        latest_proof_epoch: None,
    };
    let json = serde_json::to_string(&status).unwrap();
    let back: ConfinementStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(status, back);
}

#[test]
fn enrichment_record_counts_serde_roundtrip() {
    let counts = RecordCounts {
        flow_events: 10,
        flow_proofs: 5,
        declass_receipts: 3,
        confinement_claims: 2,
    };
    let json = serde_json::to_string(&counts).unwrap();
    let back: RecordCounts = serde_json::from_str(&json).unwrap();
    assert_eq!(counts, back);
    assert_eq!(back.total(), 20);
}

#[test]
fn enrichment_provenance_error_serde_all_variants() {
    let errors = vec![
        ProvenanceError::EmptyId {
            record_type: "flow_event".to_string(),
        },
        ProvenanceError::EmptyExtensionId,
        ProvenanceError::DuplicateRecord {
            key: "k1".to_string(),
        },
        ProvenanceError::StorageError("disk full".to_string()),
        ProvenanceError::SerializationError("bad json".to_string()),
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ProvenanceError = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, err);
    }
}

#[test]
fn enrichment_provenance_event_serde_roundtrip() {
    let event = ProvenanceEvent {
        trace_id: "t1".to_string(),
        component: "ifc_provenance_index".to_string(),
        event: "flow_event_inserted".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
        extension_id: Some("ext-a".to_string()),
        record_count: Some(1),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ProvenanceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn enrichment_flow_decision_serde_all() {
    for d in [
        FlowDecision::Allowed,
        FlowDecision::Blocked,
        FlowDecision::Declassified,
    ] {
        let json = serde_json::to_string(&d).unwrap();
        let back: FlowDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }
}

#[test]
fn enrichment_lineage_evidence_type_serde_all() {
    for t in [
        LineageEvidenceType::FlowEvent,
        LineageEvidenceType::FlowProof,
        LineageEvidenceType::DeclassificationReceipt,
    ] {
        let json = serde_json::to_string(&t).unwrap();
        let back: LineageEvidenceType = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }
}

// ── Display coverage ────────────────────────────────────────────────────

#[test]
fn enrichment_flow_decision_display_exact() {
    assert_eq!(FlowDecision::Allowed.to_string(), "allowed");
    assert_eq!(FlowDecision::Blocked.to_string(), "blocked");
    assert_eq!(FlowDecision::Declassified.to_string(), "declassified");
}

#[test]
fn enrichment_lineage_evidence_type_display_exact() {
    assert_eq!(LineageEvidenceType::FlowEvent.to_string(), "flow_event");
    assert_eq!(LineageEvidenceType::FlowProof.to_string(), "flow_proof");
    assert_eq!(
        LineageEvidenceType::DeclassificationReceipt.to_string(),
        "declassification_receipt"
    );
}

#[test]
fn enrichment_provenance_error_display_exact() {
    assert_eq!(
        ProvenanceError::EmptyId {
            record_type: "flow_event".to_string()
        }
        .to_string(),
        "flow_event has empty ID"
    );
    assert_eq!(
        ProvenanceError::EmptyExtensionId.to_string(),
        "extension_id is empty"
    );
    assert_eq!(
        ProvenanceError::DuplicateRecord {
            key: "k1".to_string()
        }
        .to_string(),
        "duplicate record: k1"
    );
    assert_eq!(
        ProvenanceError::StorageError("disk full".to_string()).to_string(),
        "storage: disk full"
    );
    assert_eq!(
        ProvenanceError::SerializationError("bad json".to_string()).to_string(),
        "serialization: bad json"
    );
}

// ── std::error::Error ───────────────────────────────────────────────────

#[test]
fn enrichment_provenance_error_is_std_error() {
    let err = ProvenanceError::EmptyExtensionId;
    let _: &dyn std::error::Error = &err;
}

#[test]
fn enrichment_provenance_error_source_is_none() {
    use std::error::Error;
    for err in [
        ProvenanceError::EmptyId {
            record_type: "x".to_string(),
        },
        ProvenanceError::EmptyExtensionId,
        ProvenanceError::DuplicateRecord {
            key: "k".to_string(),
        },
        ProvenanceError::StorageError("e".to_string()),
        ProvenanceError::SerializationError("e".to_string()),
    ] {
        assert!(err.source().is_none());
    }
}

// ── Debug nonempty ──────────────────────────────────────────────────────

#[test]
fn enrichment_flow_event_record_debug_nonempty() {
    let ev = flow_event(
        "ev1",
        "ext-a",
        Label::Public,
        Label::Internal,
        FlowDecision::Allowed,
    );
    assert!(!format!("{ev:?}").is_empty());
}

#[test]
fn enrichment_flow_proof_record_debug_nonempty() {
    let proof = flow_proof("p1", "ext-a", Label::Public, Label::Internal, 1);
    assert!(!format!("{proof:?}").is_empty());
}

#[test]
fn enrichment_declass_receipt_debug_nonempty() {
    let receipt = declass_receipt(
        "r1",
        "ext-a",
        Label::Secret,
        Label::Public,
        DeclassificationDecision::Allow,
    );
    assert!(!format!("{receipt:?}").is_empty());
}

#[test]
fn enrichment_confinement_claim_debug_nonempty() {
    let claim = confinement_claim("c1", "ext-a", ClaimStrength::Full, 1);
    assert!(!format!("{claim:?}").is_empty());
}

#[test]
fn enrichment_lineage_hop_debug_nonempty() {
    let hop = LineageHop {
        source_label: Label::Public,
        sink_clearance: Label::Internal,
        evidence_ref: "ev1".to_string(),
        evidence_type: LineageEvidenceType::FlowEvent,
    };
    assert!(!format!("{hop:?}").is_empty());
}

#[test]
fn enrichment_provenance_error_debug_nonempty() {
    let err = ProvenanceError::EmptyExtensionId;
    assert!(!format!("{err:?}").is_empty());
}

#[test]
fn enrichment_record_counts_debug_nonempty() {
    let counts = RecordCounts {
        flow_events: 0,
        flow_proofs: 0,
        declass_receipts: 0,
        confinement_claims: 0,
    };
    assert!(!format!("{counts:?}").is_empty());
}

// ── Error codes ─────────────────────────────────────────────────────────

#[test]
fn enrichment_error_codes_stable() {
    assert_eq!(
        error_code(&ProvenanceError::EmptyId {
            record_type: "x".to_string()
        }),
        "PROV_EMPTY_ID"
    );
    assert_eq!(
        error_code(&ProvenanceError::EmptyExtensionId),
        "PROV_EMPTY_EXTENSION_ID"
    );
    assert_eq!(
        error_code(&ProvenanceError::DuplicateRecord {
            key: "k".to_string()
        }),
        "PROV_DUPLICATE"
    );
    assert_eq!(
        error_code(&ProvenanceError::StorageError(String::new())),
        "PROV_STORAGE_ERROR"
    );
    assert_eq!(
        error_code(&ProvenanceError::SerializationError(String::new())),
        "PROV_SERIALIZATION_ERROR"
    );
}

#[test]
fn enrichment_error_codes_all_unique() {
    let errors = [
        ProvenanceError::EmptyId {
            record_type: "x".to_string(),
        },
        ProvenanceError::EmptyExtensionId,
        ProvenanceError::DuplicateRecord {
            key: "k".to_string(),
        },
        ProvenanceError::StorageError(String::new()),
        ProvenanceError::SerializationError(String::new()),
    ];
    let codes: Vec<&str> = errors.iter().map(|e| error_code(e)).collect();
    let mut deduped = codes.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(codes.len(), deduped.len());
}

// ── RecordCounts ────────────────────────────────────────────────────────

#[test]
fn enrichment_record_counts_total() {
    let counts = RecordCounts {
        flow_events: 3,
        flow_proofs: 2,
        declass_receipts: 1,
        confinement_claims: 4,
    };
    assert_eq!(counts.total(), 10);
}

#[test]
fn enrichment_record_counts_total_zero() {
    let counts = RecordCounts {
        flow_events: 0,
        flow_proofs: 0,
        declass_receipts: 0,
        confinement_claims: 0,
    };
    assert_eq!(counts.total(), 0);
}

// ── Index CRUD lifecycle ────────────────────────────────────────────────

#[test]
fn enrichment_insert_and_get_flow_event() {
    let mut idx = make_index();
    let ctx = ctx();
    let ev = flow_event(
        "ev1",
        "ext-a",
        Label::Public,
        Label::Internal,
        FlowDecision::Allowed,
    );
    idx.insert_flow_event(&ev, &ctx).unwrap();

    let got = idx.get_flow_event("ev1", &ctx).unwrap().unwrap();
    assert_eq!(got.event_id, "ev1");
    assert_eq!(got.extension_id, "ext-a");
    assert_eq!(got.source_label, Label::Public);
    assert_eq!(got.sink_clearance, Label::Internal);
    assert_eq!(got.decision, FlowDecision::Allowed);
}

#[test]
fn enrichment_insert_and_get_flow_proof() {
    let mut idx = make_index();
    let ctx = ctx();
    let proof = flow_proof("p1", "ext-a", Label::Internal, Label::Confidential, 3);
    idx.insert_flow_proof(&proof, &ctx).unwrap();

    let got = idx.get_flow_proof("p1", &ctx).unwrap().unwrap();
    assert_eq!(got.proof_id, "p1");
    assert_eq!(got.proof_method, ProofMethod::StaticAnalysis);
    assert_eq!(got.epoch_id, 3);
}

#[test]
fn enrichment_insert_and_get_declass_receipt() {
    let mut idx = make_index();
    let ctx = ctx();
    let receipt = declass_receipt(
        "r1",
        "ext-a",
        Label::Secret,
        Label::Public,
        DeclassificationDecision::Allow,
    );
    idx.insert_declass_receipt(&receipt, &ctx).unwrap();

    let got = idx.get_declass_receipt("r1", &ctx).unwrap().unwrap();
    assert_eq!(got.receipt_id, "r1");
    assert_eq!(got.decision, DeclassificationDecision::Allow);
    assert_eq!(got.declassification_route_ref, "route-r1");
    assert_eq!(got.decision_contract_id, "decision-r1");
}

#[test]
fn enrichment_insert_and_get_confinement_claim() {
    let mut idx = make_index();
    let ctx = ctx();
    let claim = confinement_claim("c1", "ext-a", ClaimStrength::Full, 5);
    idx.insert_confinement_claim(&claim, &ctx).unwrap();

    let got = idx.get_confinement_claim("c1", &ctx).unwrap().unwrap();
    assert_eq!(got.claim_id, "c1");
    assert_eq!(got.claim_strength, ClaimStrength::Full);
    assert_eq!(got.epoch_id, 5);
}

#[test]
fn enrichment_get_missing_returns_none() {
    let mut idx = make_index();
    let ctx = ctx();
    assert!(idx.get_flow_event("nonexistent", &ctx).unwrap().is_none());
    assert!(idx.get_flow_proof("nonexistent", &ctx).unwrap().is_none());
    assert!(
        idx.get_declass_receipt("nonexistent", &ctx)
            .unwrap()
            .is_none()
    );
    assert!(
        idx.get_confinement_claim("nonexistent", &ctx)
            .unwrap()
            .is_none()
    );
}

// ── Validation errors ───────────────────────────────────────────────────

#[test]
fn enrichment_reject_empty_event_id() {
    let mut idx = make_index();
    let ctx = ctx();
    let ev = flow_event(
        "",
        "ext-a",
        Label::Public,
        Label::Internal,
        FlowDecision::Allowed,
    );
    let err = idx.insert_flow_event(&ev, &ctx).unwrap_err();
    assert!(
        matches!(err, ProvenanceError::EmptyId { ref record_type } if record_type == "flow_event")
    );
}

#[test]
fn enrichment_reject_empty_proof_id() {
    let mut idx = make_index();
    let ctx = ctx();
    let proof = flow_proof("", "ext-a", Label::Public, Label::Internal, 1);
    let err = idx.insert_flow_proof(&proof, &ctx).unwrap_err();
    assert!(matches!(err, ProvenanceError::EmptyId { .. }));
}

#[test]
fn enrichment_reject_empty_receipt_id() {
    let mut idx = make_index();
    let ctx = ctx();
    let receipt = declass_receipt(
        "",
        "ext-a",
        Label::Public,
        Label::Internal,
        DeclassificationDecision::Allow,
    );
    let err = idx.insert_declass_receipt(&receipt, &ctx).unwrap_err();
    assert!(matches!(err, ProvenanceError::EmptyId { .. }));
}

#[test]
fn enrichment_reject_empty_claim_id() {
    let mut idx = make_index();
    let ctx = ctx();
    let claim = confinement_claim("", "ext-a", ClaimStrength::Full, 1);
    let err = idx.insert_confinement_claim(&claim, &ctx).unwrap_err();
    assert!(matches!(err, ProvenanceError::EmptyId { .. }));
}

#[test]
fn enrichment_reject_empty_extension_id_all_record_types() {
    let mut idx = make_index();
    let ctx = ctx();

    let ev = flow_event(
        "ev1",
        "",
        Label::Public,
        Label::Internal,
        FlowDecision::Allowed,
    );
    assert_eq!(
        idx.insert_flow_event(&ev, &ctx).unwrap_err(),
        ProvenanceError::EmptyExtensionId
    );

    let proof = flow_proof("p1", "", Label::Public, Label::Internal, 1);
    assert_eq!(
        idx.insert_flow_proof(&proof, &ctx).unwrap_err(),
        ProvenanceError::EmptyExtensionId
    );

    let receipt = declass_receipt(
        "r1",
        "",
        Label::Public,
        Label::Internal,
        DeclassificationDecision::Allow,
    );
    assert_eq!(
        idx.insert_declass_receipt(&receipt, &ctx).unwrap_err(),
        ProvenanceError::EmptyExtensionId
    );

    let claim = confinement_claim("c1", "", ClaimStrength::Full, 1);
    assert_eq!(
        idx.insert_confinement_claim(&claim, &ctx).unwrap_err(),
        ProvenanceError::EmptyExtensionId
    );
}

// ── Extension isolation ─────────────────────────────────────────────────

#[test]
fn enrichment_extension_isolation_flow_events() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.insert_flow_event(
        &flow_event(
            "ev1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_event(
        &flow_event(
            "ev2",
            "ext-b",
            Label::Internal,
            Label::Confidential,
            FlowDecision::Blocked,
        ),
        &ctx,
    )
    .unwrap();

    let a = idx.flow_events_by_extension("ext-a", &ctx).unwrap();
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].event_id, "ev1");

    let b = idx.flow_events_by_extension("ext-b", &ctx).unwrap();
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].event_id, "ev2");

    let c = idx.flow_events_by_extension("ext-c", &ctx).unwrap();
    assert!(c.is_empty());
}

#[test]
fn enrichment_extension_isolation_flow_proofs() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.insert_flow_proof(
        &flow_proof("p1", "ext-a", Label::Public, Label::Internal, 1),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_proof(
        &flow_proof("p2", "ext-b", Label::Public, Label::Internal, 1),
        &ctx,
    )
    .unwrap();

    let a = idx.flow_proofs_by_extension("ext-a", &ctx).unwrap();
    assert_eq!(a.len(), 1);
    let b = idx.flow_proofs_by_extension("ext-b", &ctx).unwrap();
    assert_eq!(b.len(), 1);
}

// ── Lineage queries ─────────────────────────────────────────────────────

#[test]
fn enrichment_lineage_single_hop() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.insert_flow_event(
        &flow_event(
            "ev1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &ctx,
    )
    .unwrap();

    let paths = idx
        .source_to_sink_lineage("ext-a", &Label::Public, &ctx)
        .unwrap();
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].hops.len(), 1);
    assert_eq!(paths[0].hops[0].source_label, Label::Public);
    assert_eq!(paths[0].hops[0].sink_clearance, Label::Internal);
    assert_eq!(
        paths[0].hops[0].evidence_type,
        LineageEvidenceType::FlowEvent
    );
}

#[test]
fn enrichment_lineage_multi_hop_transitive() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.insert_flow_event(
        &flow_event(
            "e1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_event(
        &flow_event(
            "e2",
            "ext-a",
            Label::Internal,
            Label::Confidential,
            FlowDecision::Allowed,
        ),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_event(
        &flow_event(
            "e3",
            "ext-a",
            Label::Confidential,
            Label::Secret,
            FlowDecision::Allowed,
        ),
        &ctx,
    )
    .unwrap();

    let paths = idx
        .source_to_sink_lineage("ext-a", &Label::Public, &ctx)
        .unwrap();
    let max_hops = paths.iter().map(|p| p.hops.len()).max().unwrap();
    assert_eq!(max_hops, 3);
    let three_hop: Vec<_> = paths.iter().filter(|p| p.hops.len() == 3).collect();
    assert_eq!(three_hop.len(), 1);
    assert_eq!(three_hop[0].hops[2].sink_clearance, Label::Secret);
}

#[test]
fn enrichment_lineage_cycle_terminates() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.insert_flow_event(
        &flow_event(
            "e1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_event(
        &flow_event(
            "e2",
            "ext-a",
            Label::Internal,
            Label::Public,
            FlowDecision::Allowed,
        ),
        &ctx,
    )
    .unwrap();

    let paths = idx
        .source_to_sink_lineage("ext-a", &Label::Public, &ctx)
        .unwrap();
    assert!(!paths.is_empty());
    assert!(paths.iter().all(|p| p.hops.len() <= 2));
}

#[test]
fn enrichment_lineage_empty_for_no_match() {
    let mut idx = make_index();
    let ctx = ctx();
    let paths = idx
        .source_to_sink_lineage("ext-a", &Label::Secret, &ctx)
        .unwrap();
    assert!(paths.is_empty());
}

#[test]
fn enrichment_lineage_mixed_evidence_types() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.insert_flow_event(
        &flow_event(
            "e1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_proof(
        &flow_proof("p1", "ext-a", Label::Internal, Label::Confidential, 1),
        &ctx,
    )
    .unwrap();
    idx.insert_declass_receipt(
        &declass_receipt(
            "r1",
            "ext-a",
            Label::Confidential,
            Label::Secret,
            DeclassificationDecision::Allow,
        ),
        &ctx,
    )
    .unwrap();

    let paths = idx
        .source_to_sink_lineage("ext-a", &Label::Public, &ctx)
        .unwrap();
    let three_hop: Vec<_> = paths.iter().filter(|p| p.hops.len() == 3).collect();
    assert_eq!(three_hop.len(), 1);
    assert_eq!(
        three_hop[0].hops[0].evidence_type,
        LineageEvidenceType::FlowEvent
    );
    assert_eq!(
        three_hop[0].hops[1].evidence_type,
        LineageEvidenceType::FlowProof
    );
    assert_eq!(
        three_hop[0].hops[2].evidence_type,
        LineageEvidenceType::DeclassificationReceipt
    );
}

#[test]
fn enrichment_lineage_deny_receipts_excluded() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.insert_declass_receipt(
        &declass_receipt(
            "r1",
            "ext-a",
            Label::Secret,
            Label::Public,
            DeclassificationDecision::Allow,
        ),
        &ctx,
    )
    .unwrap();
    idx.insert_declass_receipt(
        &declass_receipt(
            "r2",
            "ext-a",
            Label::Secret,
            Label::Internal,
            DeclassificationDecision::Deny,
        ),
        &ctx,
    )
    .unwrap();

    let paths = idx
        .source_to_sink_lineage("ext-a", &Label::Secret, &ctx)
        .unwrap();
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].hops[0].sink_clearance, Label::Public);
}

// ── Sink provenance ─────────────────────────────────────────────────────

#[test]
fn enrichment_sink_provenance_direct_sources() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.insert_flow_event(
        &flow_event(
            "ev1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_event(
        &flow_event(
            "ev2",
            "ext-a",
            Label::Confidential,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &ctx,
    )
    .unwrap();

    let sources = idx
        .sink_provenance("ext-a", &Label::Internal, &ctx)
        .unwrap();
    assert_eq!(sources.len(), 2);
    assert!(sources.contains(&Label::Public));
    assert!(sources.contains(&Label::Confidential));
}

#[test]
fn enrichment_sink_provenance_transitive() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.insert_flow_event(
        &flow_event(
            "e1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_event(
        &flow_event(
            "e2",
            "ext-a",
            Label::Internal,
            Label::Confidential,
            FlowDecision::Allowed,
        ),
        &ctx,
    )
    .unwrap();

    let sources = idx
        .sink_provenance("ext-a", &Label::Confidential, &ctx)
        .unwrap();
    assert!(sources.contains(&Label::Internal));
    assert!(sources.contains(&Label::Public));
}

#[test]
fn enrichment_sink_provenance_from_proofs() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.insert_flow_proof(
        &flow_proof("p1", "ext-a", Label::Public, Label::Internal, 1),
        &ctx,
    )
    .unwrap();

    let sources = idx
        .sink_provenance("ext-a", &Label::Internal, &ctx)
        .unwrap();
    assert!(sources.contains(&Label::Public));
}

#[test]
fn enrichment_sink_provenance_deny_receipts_excluded() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.insert_declass_receipt(
        &declass_receipt(
            "r1",
            "ext-a",
            Label::Secret,
            Label::Public,
            DeclassificationDecision::Allow,
        ),
        &ctx,
    )
    .unwrap();
    idx.insert_declass_receipt(
        &declass_receipt(
            "r2",
            "ext-a",
            Label::Confidential,
            Label::Public,
            DeclassificationDecision::Deny,
        ),
        &ctx,
    )
    .unwrap();

    let sources = idx.sink_provenance("ext-a", &Label::Public, &ctx).unwrap();
    assert_eq!(sources.len(), 1);
    assert!(sources.contains(&Label::Secret));
}

#[test]
fn enrichment_sink_provenance_empty() {
    let mut idx = make_index();
    let ctx = ctx();
    let sources = idx
        .sink_provenance("ext-a", &Label::TopSecret, &ctx)
        .unwrap();
    assert!(sources.is_empty());
}

// ── Confinement status ──────────────────────────────────────────────────

#[test]
fn enrichment_confinement_status_full_coverage() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.insert_flow_event(
        &flow_event(
            "ev1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_proof(
        &flow_proof("p1", "ext-a", Label::Public, Label::Internal, 2),
        &ctx,
    )
    .unwrap();
    idx.insert_confinement_claim(
        &confinement_claim("c1", "ext-a", ClaimStrength::Full, 2),
        &ctx,
    )
    .unwrap();

    let status = idx.confinement_status("ext-a", &ctx).unwrap();
    assert_eq!(status.proven_flows, 1);
    assert_eq!(status.unproven_flows, 0);
    assert_eq!(status.strongest_claim, Some(ClaimStrength::Full));
    assert_eq!(status.latest_proof_epoch, Some(2));
}

#[test]
fn enrichment_confinement_status_partial_coverage() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.insert_flow_event(
        &flow_event(
            "ev1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_event(
        &flow_event(
            "ev2",
            "ext-a",
            Label::Internal,
            Label::Confidential,
            FlowDecision::Allowed,
        ),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_proof(
        &flow_proof("p1", "ext-a", Label::Public, Label::Internal, 1),
        &ctx,
    )
    .unwrap();

    let status = idx.confinement_status("ext-a", &ctx).unwrap();
    assert_eq!(status.proven_flows, 1);
    assert_eq!(status.unproven_flows, 1);
}

#[test]
fn enrichment_confinement_status_selects_full_over_partial() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.insert_confinement_claim(
        &confinement_claim("c1", "ext-a", ClaimStrength::Partial, 1),
        &ctx,
    )
    .unwrap();
    idx.insert_confinement_claim(
        &confinement_claim("c2", "ext-a", ClaimStrength::Full, 2),
        &ctx,
    )
    .unwrap();

    let status = idx.confinement_status("ext-a", &ctx).unwrap();
    assert_eq!(status.strongest_claim, Some(ClaimStrength::Full));
}

#[test]
fn enrichment_confinement_status_empty_extension() {
    let mut idx = make_index();
    let ctx = ctx();
    let status = idx.confinement_status("ext-empty", &ctx).unwrap();
    assert_eq!(status.proven_flows, 0);
    assert_eq!(status.unproven_flows, 0);
    assert!(status.strongest_claim.is_none());
    assert!(status.latest_proof_epoch.is_none());
}

#[test]
fn enrichment_confinement_status_latest_epoch() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.insert_flow_proof(
        &flow_proof("p1", "ext-a", Label::Public, Label::Internal, 3),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_proof(
        &flow_proof("p2", "ext-a", Label::Public, Label::Internal, 7),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_proof(
        &flow_proof("p3", "ext-a", Label::Public, Label::Internal, 5),
        &ctx,
    )
    .unwrap();

    let status = idx.confinement_status("ext-a", &ctx).unwrap();
    assert_eq!(status.latest_proof_epoch, Some(7));
}

// ── Replay join ─────────────────────────────────────────────────────────

#[test]
fn enrichment_join_events_with_matching_receipt() {
    let mut idx = make_index();
    let ctx = ctx();
    let mut ev = flow_event(
        "ev1",
        "ext-a",
        Label::Confidential,
        Label::Public,
        FlowDecision::Declassified,
    );
    ev.receipt_ref = Some("r1".to_string());
    idx.insert_flow_event(&ev, &ctx).unwrap();

    idx.insert_declass_receipt(
        &declass_receipt(
            "r1",
            "ext-a",
            Label::Confidential,
            Label::Public,
            DeclassificationDecision::Allow,
        ),
        &ctx,
    )
    .unwrap();

    let joined = idx.join_events_with_receipts("ext-a", &ctx).unwrap();
    assert_eq!(joined.len(), 1);
    assert!(joined[0].1.is_some());
    assert_eq!(joined[0].1.as_ref().unwrap().receipt_id, "r1");
    assert_eq!(
        joined[0].1.as_ref().unwrap().declassification_route_ref,
        "route-r1"
    );
    assert_eq!(
        joined[0].1.as_ref().unwrap().decision_contract_id,
        "decision-r1"
    );
}

#[test]
fn enrichment_join_events_without_receipt() {
    let mut idx = make_index();
    let ctx = ctx();
    let ev = flow_event(
        "ev1",
        "ext-a",
        Label::Public,
        Label::Internal,
        FlowDecision::Allowed,
    );
    idx.insert_flow_event(&ev, &ctx).unwrap();

    let joined = idx.join_events_with_receipts("ext-a", &ctx).unwrap();
    assert_eq!(joined.len(), 1);
    assert!(joined[0].1.is_none());
}

#[test]
fn enrichment_join_events_multiple() {
    let mut idx = make_index();
    let ctx = ctx();
    let mut ev1 = flow_event(
        "ev1",
        "ext-a",
        Label::Confidential,
        Label::Public,
        FlowDecision::Declassified,
    );
    ev1.receipt_ref = Some("r1".to_string());
    idx.insert_flow_event(&ev1, &ctx).unwrap();

    let ev2 = flow_event(
        "ev2",
        "ext-a",
        Label::Public,
        Label::Internal,
        FlowDecision::Allowed,
    );
    idx.insert_flow_event(&ev2, &ctx).unwrap();

    idx.insert_declass_receipt(
        &declass_receipt(
            "r1",
            "ext-a",
            Label::Confidential,
            Label::Public,
            DeclassificationDecision::Allow,
        ),
        &ctx,
    )
    .unwrap();

    let joined = idx.join_events_with_receipts("ext-a", &ctx).unwrap();
    assert_eq!(joined.len(), 2);
    let with_receipt: Vec<_> = joined.iter().filter(|(_, r)| r.is_some()).collect();
    let without_receipt: Vec<_> = joined.iter().filter(|(_, r)| r.is_none()).collect();
    assert_eq!(with_receipt.len(), 1);
    assert_eq!(without_receipt.len(), 1);
}

// ── Time range and epoch queries ────────────────────────────────────────

#[test]
fn enrichment_time_range_query() {
    let mut idx = make_index();
    let ctx = ctx();
    let mut ev1 = flow_event(
        "e1",
        "ext-a",
        Label::Public,
        Label::Internal,
        FlowDecision::Allowed,
    );
    ev1.timestamp_ms = 100;
    let mut ev2 = flow_event(
        "e2",
        "ext-a",
        Label::Internal,
        Label::Confidential,
        FlowDecision::Blocked,
    );
    ev2.timestamp_ms = 200;
    let mut ev3 = flow_event(
        "e3",
        "ext-a",
        Label::Public,
        Label::Secret,
        FlowDecision::Allowed,
    );
    ev3.timestamp_ms = 300;

    idx.insert_flow_event(&ev1, &ctx).unwrap();
    idx.insert_flow_event(&ev2, &ctx).unwrap();
    idx.insert_flow_event(&ev3, &ctx).unwrap();

    let results = idx
        .flow_events_by_time_range("ext-a", 150, 250, &ctx)
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].event_id, "e2");
}

#[test]
fn enrichment_time_range_inclusive_boundaries() {
    let mut idx = make_index();
    let ctx = ctx();
    let mut ev = flow_event(
        "e1",
        "ext-a",
        Label::Public,
        Label::Internal,
        FlowDecision::Allowed,
    );
    ev.timestamp_ms = 500;
    idx.insert_flow_event(&ev, &ctx).unwrap();

    let results = idx
        .flow_events_by_time_range("ext-a", 500, 500, &ctx)
        .unwrap();
    assert_eq!(results.len(), 1);
}

#[test]
fn enrichment_epoch_query() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.insert_flow_proof(
        &flow_proof("p1", "ext-a", Label::Public, Label::Internal, 1),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_proof(
        &flow_proof("p2", "ext-a", Label::Internal, Label::Confidential, 2),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_proof(
        &flow_proof("p3", "ext-a", Label::Public, Label::Secret, 1),
        &ctx,
    )
    .unwrap();

    let epoch1 = idx.flow_proofs_by_epoch("ext-a", 1, &ctx).unwrap();
    assert_eq!(epoch1.len(), 2);
    let epoch2 = idx.flow_proofs_by_epoch("ext-a", 2, &ctx).unwrap();
    assert_eq!(epoch2.len(), 1);
    let epoch99 = idx.flow_proofs_by_epoch("ext-a", 99, &ctx).unwrap();
    assert!(epoch99.is_empty());
}

// ── Record counts via index ─────────────────────────────────────────────

#[test]
fn enrichment_record_counts_via_index() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.insert_flow_event(
        &flow_event(
            "e1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_event(
        &flow_event(
            "e2",
            "ext-a",
            Label::Internal,
            Label::Secret,
            FlowDecision::Blocked,
        ),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_proof(
        &flow_proof("p1", "ext-a", Label::Public, Label::Internal, 1),
        &ctx,
    )
    .unwrap();
    idx.insert_declass_receipt(
        &declass_receipt(
            "r1",
            "ext-a",
            Label::Secret,
            Label::Public,
            DeclassificationDecision::Allow,
        ),
        &ctx,
    )
    .unwrap();
    idx.insert_confinement_claim(
        &confinement_claim("c1", "ext-a", ClaimStrength::Full, 1),
        &ctx,
    )
    .unwrap();

    let counts = idx.record_counts("ext-a", &ctx).unwrap();
    assert_eq!(counts.flow_events, 2);
    assert_eq!(counts.flow_proofs, 1);
    assert_eq!(counts.declass_receipts, 1);
    assert_eq!(counts.confinement_claims, 1);
    assert_eq!(counts.total(), 5);
}

#[test]
fn enrichment_record_counts_isolates_extensions() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.insert_flow_event(
        &flow_event(
            "e1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_event(
        &flow_event(
            "e2",
            "ext-b",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &ctx,
    )
    .unwrap();

    let a = idx.record_counts("ext-a", &ctx).unwrap();
    assert_eq!(a.flow_events, 1);
    let b = idx.record_counts("ext-b", &ctx).unwrap();
    assert_eq!(b.flow_events, 1);
}

// ── Events ──────────────────────────────────────────────────────────────

#[test]
fn enrichment_events_emitted_on_insert() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.insert_flow_event(
        &flow_event(
            "ev1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &ctx,
    )
    .unwrap();
    assert_eq!(idx.events().len(), 1);
    assert_eq!(idx.events()[0].event, "flow_event_inserted");
    assert_eq!(idx.events()[0].outcome, "ok");
    assert_eq!(idx.events()[0].component, "ifc_provenance_index");
}

#[test]
fn enrichment_events_emitted_on_each_insert_type() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.insert_flow_event(
        &flow_event(
            "ev1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_proof(
        &flow_proof("p1", "ext-a", Label::Public, Label::Internal, 1),
        &ctx,
    )
    .unwrap();
    idx.insert_declass_receipt(
        &declass_receipt(
            "r1",
            "ext-a",
            Label::Secret,
            Label::Public,
            DeclassificationDecision::Allow,
        ),
        &ctx,
    )
    .unwrap();
    idx.insert_confinement_claim(
        &confinement_claim("c1", "ext-a", ClaimStrength::Full, 1),
        &ctx,
    )
    .unwrap();

    assert_eq!(idx.events().len(), 4);
    let event_names: Vec<&str> = idx.events().iter().map(|e| e.event.as_str()).collect();
    assert!(event_names.contains(&"flow_event_inserted"));
    assert!(event_names.contains(&"flow_proof_inserted"));
    assert!(event_names.contains(&"declass_receipt_inserted"));
    assert!(event_names.contains(&"confinement_claim_inserted"));
}

#[test]
fn enrichment_events_emitted_on_lineage_query() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.source_to_sink_lineage("ext-a", &Label::Public, &ctx)
        .unwrap();
    assert!(idx.events().iter().any(|e| e.event == "lineage_query"));
}

#[test]
fn enrichment_drain_events_clears() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.insert_flow_event(
        &flow_event(
            "ev1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &ctx,
    )
    .unwrap();
    assert_eq!(idx.events().len(), 1);
    let drained = idx.drain_events();
    assert_eq!(drained.len(), 1);
    assert!(idx.events().is_empty());
}

#[test]
fn enrichment_drain_events_empty() {
    let mut idx = make_index();
    let drained = idx.drain_events();
    assert!(drained.is_empty());
}

// ── store_mut accessor ──────────────────────────────────────────────────

#[test]
fn enrichment_store_mut_accessible() {
    let mut idx = make_index();
    let _store: &mut InMemoryStorageAdapter = idx.store_mut();
}

// ── Deterministic ordering ──────────────────────────────────────────────

#[test]
fn enrichment_query_results_sorted() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.insert_flow_event(
        &flow_event(
            "ev-z",
            "ext-a",
            Label::Secret,
            Label::Public,
            FlowDecision::Blocked,
        ),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_event(
        &flow_event(
            "ev-a",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_event(
        &flow_event(
            "ev-m",
            "ext-a",
            Label::Internal,
            Label::Confidential,
            FlowDecision::Declassified,
        ),
        &ctx,
    )
    .unwrap();

    let results = idx.flow_events_by_extension("ext-a", &ctx).unwrap();
    assert_eq!(results.len(), 3);
    for i in 1..results.len() {
        assert!(results[i - 1] <= results[i]);
    }
}

#[test]
fn enrichment_lineage_results_deterministic() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.insert_flow_event(
        &flow_event(
            "e1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_proof(
        &flow_proof("p1", "ext-a", Label::Public, Label::Confidential, 1),
        &ctx,
    )
    .unwrap();

    let paths1 = idx
        .source_to_sink_lineage("ext-a", &Label::Public, &ctx)
        .unwrap();
    let paths2 = idx
        .source_to_sink_lineage("ext-a", &Label::Public, &ctx)
        .unwrap();
    assert_eq!(paths1, paths2);
}

// ── JSON field-name stability ───────────────────────────────────────────

#[test]
fn enrichment_json_fields_flow_event_record() {
    let ev = flow_event(
        "ev1",
        "ext-a",
        Label::Public,
        Label::Internal,
        FlowDecision::Allowed,
    );
    let json = serde_json::to_string(&ev).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("event_id").is_some());
    assert!(v.get("extension_id").is_some());
    assert!(v.get("source_label").is_some());
    assert!(v.get("sink_clearance").is_some());
    assert!(v.get("flow_location").is_some());
    assert!(v.get("decision").is_some());
    assert!(v.get("receipt_ref").is_some());
    assert!(v.get("timestamp_ms").is_some());
}

#[test]
fn enrichment_json_fields_flow_proof_record() {
    let proof = flow_proof("p1", "ext-a", Label::Public, Label::Internal, 1);
    let json = serde_json::to_string(&proof).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("proof_id").is_some());
    assert!(v.get("extension_id").is_some());
    assert!(v.get("source_label").is_some());
    assert!(v.get("sink_clearance").is_some());
    assert!(v.get("proof_method").is_some());
    assert!(v.get("epoch_id").is_some());
}

#[test]
fn enrichment_json_fields_declass_receipt() {
    let receipt = declass_receipt(
        "r1",
        "ext-a",
        Label::Secret,
        Label::Public,
        DeclassificationDecision::Allow,
    );
    let json = serde_json::to_string(&receipt).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("receipt_id").is_some());
    assert!(v.get("decision").is_some());
    assert!(v.get("source_label").is_some());
    assert!(v.get("sink_clearance").is_some());
    assert!(v.get("declassification_route_ref").is_some());
    assert!(v.get("decision_contract_id").is_some());
    assert!(v.get("timestamp_ms").is_some());
}

#[test]
fn enrichment_json_fields_confinement_claim() {
    let claim = confinement_claim("c1", "ext-a", ClaimStrength::Full, 1);
    let json = serde_json::to_string(&claim).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("claim_id").is_some());
    assert!(v.get("extension_id").is_some());
    assert!(v.get("claim_strength").is_some());
    assert!(v.get("epoch_id").is_some());
}

#[test]
fn enrichment_json_fields_record_counts() {
    let counts = RecordCounts {
        flow_events: 1,
        flow_proofs: 2,
        declass_receipts: 3,
        confinement_claims: 4,
    };
    let json = serde_json::to_string(&counts).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("flow_events").is_some());
    assert!(v.get("flow_proofs").is_some());
    assert!(v.get("declass_receipts").is_some());
    assert!(v.get("confinement_claims").is_some());
}

#[test]
fn enrichment_json_fields_confinement_status() {
    let status = ConfinementStatus {
        extension_id: "ext-a".to_string(),
        proven_flows: 1,
        unproven_flows: 0,
        strongest_claim: Some(ClaimStrength::Full),
        latest_proof_epoch: Some(1),
    };
    let json = serde_json::to_string(&status).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("extension_id").is_some());
    assert!(v.get("proven_flows").is_some());
    assert!(v.get("unproven_flows").is_some());
    assert!(v.get("strongest_claim").is_some());
    assert!(v.get("latest_proof_epoch").is_some());
}

// ── Custom label support ────────────────────────────────────────────────

#[test]
fn enrichment_custom_label_in_flow_event() {
    let mut idx = make_index();
    let ctx = ctx();
    let custom = Label::Custom {
        name: "pii".to_string(),
        level: 3,
    };
    let ev = FlowEventRecord {
        event_id: "ev-custom".to_string(),
        extension_id: "ext-a".to_string(),
        source_label: custom.clone(),
        sink_clearance: Label::Internal,
        flow_location: "src/test.rs:1".to_string(),
        decision: FlowDecision::Allowed,
        receipt_ref: None,
        timestamp_ms: 1000,
    };
    idx.insert_flow_event(&ev, &ctx).unwrap();
    let got = idx.get_flow_event("ev-custom", &ctx).unwrap().unwrap();
    assert_eq!(got.source_label, custom);
}

#[test]
fn enrichment_custom_label_in_lineage() {
    let mut idx = make_index();
    let ctx = ctx();
    let custom_src = Label::Custom {
        name: "pii".to_string(),
        level: 3,
    };
    let ev = FlowEventRecord {
        event_id: "ev-custom".to_string(),
        extension_id: "ext-a".to_string(),
        source_label: custom_src.clone(),
        sink_clearance: Label::Internal,
        flow_location: "src/test.rs:1".to_string(),
        decision: FlowDecision::Allowed,
        receipt_ref: None,
        timestamp_ms: 1000,
    };
    idx.insert_flow_event(&ev, &ctx).unwrap();

    let paths = idx
        .source_to_sink_lineage("ext-a", &custom_src, &ctx)
        .unwrap();
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].hops[0].source_label, custom_src);
}

// ── Multiple records ────────────────────────────────────────────────────

#[test]
fn enrichment_multiple_flow_events() {
    let mut idx = make_index();
    let ctx = ctx();
    for i in 0..10 {
        idx.insert_flow_event(
            &flow_event(
                &format!("ev{i}"),
                "ext-a",
                Label::Public,
                Label::Internal,
                FlowDecision::Allowed,
            ),
            &ctx,
        )
        .unwrap();
    }
    let events = idx.flow_events_by_extension("ext-a", &ctx).unwrap();
    assert_eq!(events.len(), 10);
}

#[test]
fn enrichment_multiple_flow_proofs() {
    let mut idx = make_index();
    let ctx = ctx();
    for i in 0..5 {
        idx.insert_flow_proof(
            &flow_proof(&format!("p{i}"), "ext-a", Label::Public, Label::Internal, i),
            &ctx,
        )
        .unwrap();
    }
    let proofs = idx.flow_proofs_by_extension("ext-a", &ctx).unwrap();
    assert_eq!(proofs.len(), 5);
}

// ── Ord determinism ─────────────────────────────────────────────────────

#[test]
fn enrichment_flow_decision_ord() {
    assert!(FlowDecision::Allowed < FlowDecision::Blocked);
    assert!(FlowDecision::Blocked < FlowDecision::Declassified);
}

#[test]
fn enrichment_lineage_evidence_type_ord() {
    assert!(LineageEvidenceType::FlowEvent < LineageEvidenceType::FlowProof);
    assert!(LineageEvidenceType::FlowProof < LineageEvidenceType::DeclassificationReceipt);
}

#[test]
fn enrichment_flow_event_record_ord() {
    let a = flow_event(
        "ev-a",
        "ext-1",
        Label::Public,
        Label::Internal,
        FlowDecision::Allowed,
    );
    let b = flow_event(
        "ev-b",
        "ext-1",
        Label::Public,
        Label::Internal,
        FlowDecision::Allowed,
    );
    assert!(a < b);
}

#[test]
fn enrichment_lineage_path_ord() {
    let path_a = LineagePath {
        extension_id: "ext-a".to_string(),
        hops: vec![],
    };
    let path_b = LineagePath {
        extension_id: "ext-b".to_string(),
        hops: vec![],
    };
    assert!(path_a < path_b);
}
