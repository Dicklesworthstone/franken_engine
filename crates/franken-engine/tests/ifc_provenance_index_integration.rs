#![forbid(unsafe_code)]
//! Integration tests for the `ifc_provenance_index` module.
//!
//! Exercises all public types, enums, struct fields, methods, error paths,
//! serde round-trips, Display impls, and deterministic replay from outside
//! the crate boundary.

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

use frankenengine_engine::ifc_artifacts::{
    ClaimStrength, DeclassificationDecision, Label, ProofMethod,
};
use frankenengine_engine::ifc_provenance_index::{
    ConfinementClaimRecord, ConfinementStatus, DeclassReceiptRecord, FlowDecision, FlowEventRecord,
    FlowProofRecord, IfcProvenanceIndex, LineageEvidenceType, LineageHop, LineagePath,
    ProvenanceError, ProvenanceEvent, RecordCounts, error_code,
};
use frankenengine_engine::storage_adapter::{EventContext, InMemoryStorageAdapter};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_ctx() -> EventContext {
    EventContext::new("trace-integ", "decision-integ", "policy-integ").expect("ctx")
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
        flow_location: "src/main.rs:42".to_string(),
        decision: dec,
        receipt_ref: None,
        timestamp_ms: 1000,
    }
}

fn flow_event_at(
    id: &str,
    ext: &str,
    src: Label,
    sink: Label,
    dec: FlowDecision,
    ts: u64,
) -> FlowEventRecord {
    FlowEventRecord {
        event_id: id.to_string(),
        extension_id: ext.to_string(),
        source_label: src,
        sink_clearance: sink,
        flow_location: "src/main.rs:42".to_string(),
        decision: dec,
        receipt_ref: None,
        timestamp_ms: ts,
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

// ===========================================================================
// Section 1: Display impls
// ===========================================================================

#[test]
fn flow_decision_display_all_variants() {
    assert_eq!(FlowDecision::Allowed.to_string(), "allowed");
    assert_eq!(FlowDecision::Blocked.to_string(), "blocked");
    assert_eq!(FlowDecision::Declassified.to_string(), "declassified");
}

#[test]
fn lineage_evidence_type_display_all_variants() {
    assert_eq!(LineageEvidenceType::FlowEvent.to_string(), "flow_event");
    assert_eq!(LineageEvidenceType::FlowProof.to_string(), "flow_proof");
    assert_eq!(
        LineageEvidenceType::DeclassificationReceipt.to_string(),
        "declassification_receipt"
    );
}

#[test]
fn provenance_error_display_empty_id() {
    let err = ProvenanceError::EmptyId {
        record_type: "flow_event".to_string(),
    };
    assert!(err.to_string().contains("flow_event"));
    assert!(err.to_string().contains("empty ID"));
}

#[test]
fn provenance_error_display_empty_extension_id() {
    let err = ProvenanceError::EmptyExtensionId;
    assert!(err.to_string().contains("empty"));
}

#[test]
fn provenance_error_display_empty_required_field() {
    let err = ProvenanceError::EmptyRequiredField {
        record_type: "declass_receipt".to_string(),
        field_name: "decision_contract_id".to_string(),
    };
    assert!(err.to_string().contains("declass_receipt"));
    assert!(err.to_string().contains("decision_contract_id"));
    assert!(err.to_string().contains("empty"));
}

#[test]
fn provenance_error_display_duplicate() {
    let err = ProvenanceError::DuplicateRecord {
        key: "test-key".to_string(),
    };
    assert!(err.to_string().contains("duplicate"));
    assert!(err.to_string().contains("test-key"));
}

#[test]
fn provenance_error_display_storage() {
    let err = ProvenanceError::StorageError("disk full".to_string());
    assert!(err.to_string().contains("storage"));
    assert!(err.to_string().contains("disk full"));
}

#[test]
fn provenance_error_display_serialization() {
    let err = ProvenanceError::SerializationError("bad json".to_string());
    assert!(err.to_string().contains("serialization"));
    assert!(err.to_string().contains("bad json"));
}

#[test]
fn provenance_error_is_std_error() {
    let err = ProvenanceError::EmptyExtensionId;
    let _: &dyn std::error::Error = &err;
}

// ===========================================================================
// Section 2: Error code stability
// ===========================================================================

#[test]
fn error_codes_stable_for_all_variants() {
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
        error_code(&ProvenanceError::EmptyRequiredField {
            record_type: "declass_receipt".to_string(),
            field_name: "decision_contract_id".to_string()
        }),
        "PROV_EMPTY_REQUIRED_FIELD"
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

// ===========================================================================
// Section 3: Construction / Defaults
// ===========================================================================

#[test]
fn flow_event_record_construction() {
    let ev = flow_event(
        "ev1",
        "ext-a",
        Label::Public,
        Label::Internal,
        FlowDecision::Allowed,
    );
    assert_eq!(ev.event_id, "ev1");
    assert_eq!(ev.extension_id, "ext-a");
    assert_eq!(ev.source_label, Label::Public);
    assert_eq!(ev.sink_clearance, Label::Internal);
    assert_eq!(ev.decision, FlowDecision::Allowed);
    assert_eq!(ev.timestamp_ms, 1000);
    assert!(ev.receipt_ref.is_none());
}

#[test]
fn flow_proof_record_construction() {
    let proof = flow_proof("p1", "ext-a", Label::Internal, Label::Confidential, 5);
    assert_eq!(proof.proof_id, "p1");
    assert_eq!(proof.extension_id, "ext-a");
    assert_eq!(proof.source_label, Label::Internal);
    assert_eq!(proof.sink_clearance, Label::Confidential);
    assert_eq!(proof.proof_method, ProofMethod::StaticAnalysis);
    assert_eq!(proof.epoch_id, 5);
}

#[test]
fn declass_receipt_record_construction() {
    let receipt = declass_receipt(
        "r1",
        "ext-b",
        Label::Secret,
        Label::Public,
        DeclassificationDecision::Allow,
    );
    assert_eq!(receipt.receipt_id, "r1");
    assert_eq!(receipt.extension_id, "ext-b");
    assert_eq!(receipt.decision, DeclassificationDecision::Allow);
    assert_eq!(receipt.source_label, Label::Secret);
    assert_eq!(receipt.sink_clearance, Label::Public);
    assert_eq!(receipt.declassification_route_ref, "route-r1");
    assert_eq!(receipt.decision_contract_id, "decision-r1");
}

#[test]
fn confinement_claim_record_construction() {
    let claim = confinement_claim("c1", "ext-a", ClaimStrength::Full, 3);
    assert_eq!(claim.claim_id, "c1");
    assert_eq!(claim.extension_id, "ext-a");
    assert_eq!(claim.claim_strength, ClaimStrength::Full);
    assert_eq!(claim.epoch_id, 3);
}

#[test]
fn lineage_hop_construction() {
    let hop = LineageHop {
        source_label: Label::Public,
        sink_clearance: Label::Internal,
        evidence_ref: "ev1".to_string(),
        evidence_type: LineageEvidenceType::FlowEvent,
    };
    assert_eq!(hop.source_label, Label::Public);
    assert_eq!(hop.sink_clearance, Label::Internal);
    assert_eq!(hop.evidence_ref, "ev1");
    assert_eq!(hop.evidence_type, LineageEvidenceType::FlowEvent);
}

#[test]
fn lineage_path_construction() {
    let path = LineagePath {
        extension_id: "ext-a".to_string(),
        hops: vec![LineageHop {
            source_label: Label::Public,
            sink_clearance: Label::Internal,
            evidence_ref: "ev1".to_string(),
            evidence_type: LineageEvidenceType::FlowEvent,
        }],
    };
    assert_eq!(path.extension_id, "ext-a");
    assert_eq!(path.hops.len(), 1);
}

#[test]
fn confinement_status_construction() {
    let status = ConfinementStatus {
        extension_id: "ext-a".to_string(),
        proven_flows: 3,
        unproven_flows: 1,
        strongest_claim: Some(ClaimStrength::Full),
        latest_proof_epoch: Some(7),
    };
    assert_eq!(status.extension_id, "ext-a");
    assert_eq!(status.proven_flows, 3);
    assert_eq!(status.unproven_flows, 1);
    assert_eq!(status.strongest_claim, Some(ClaimStrength::Full));
    assert_eq!(status.latest_proof_epoch, Some(7));
}

#[test]
fn provenance_event_construction() {
    let ev = ProvenanceEvent {
        trace_id: "t1".to_string(),
        component: "ifc_provenance_index".to_string(),
        event: "test".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
        extension_id: Some("ext-a".to_string()),
        record_count: Some(5),
    };
    assert_eq!(ev.trace_id, "t1");
    assert_eq!(ev.component, "ifc_provenance_index");
    assert!(ev.error_code.is_none());
}

#[test]
fn record_counts_total() {
    let counts = RecordCounts {
        flow_events: 3,
        flow_proofs: 2,
        declass_receipts: 1,
        confinement_claims: 4,
    };
    assert_eq!(counts.total(), 10);
}

#[test]
fn record_counts_total_zero() {
    let counts = RecordCounts {
        flow_events: 0,
        flow_proofs: 0,
        declass_receipts: 0,
        confinement_claims: 0,
    };
    assert_eq!(counts.total(), 0);
}

// ===========================================================================
// Section 4: Insert and Query Operations
// ===========================================================================

#[test]
fn insert_and_query_flow_event() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let ev = flow_event(
        "ev1",
        "ext-a",
        Label::Public,
        Label::Internal,
        FlowDecision::Allowed,
    );
    idx.insert_flow_event(&ev, &ctx).unwrap();

    let results = idx.flow_events_by_extension("ext-a", &ctx).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0], ev);
}

#[test]
fn insert_and_query_flow_proof() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let proof = flow_proof("p1", "ext-a", Label::Internal, Label::Confidential, 1);
    idx.insert_flow_proof(&proof, &ctx).unwrap();

    let results = idx.flow_proofs_by_extension("ext-a", &ctx).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0], proof);
}

#[test]
fn insert_and_query_declass_receipt() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let receipt = declass_receipt(
        "r1",
        "ext-a",
        Label::Confidential,
        Label::Public,
        DeclassificationDecision::Allow,
    );
    idx.insert_declass_receipt(&receipt, &ctx).unwrap();

    let results = idx.declass_receipts_by_extension("ext-a", &ctx).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0], receipt);
}

#[test]
fn insert_and_query_confinement_claim() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let claim = confinement_claim("c1", "ext-a", ClaimStrength::Full, 1);
    idx.insert_confinement_claim(&claim, &ctx).unwrap();

    let results = idx.confinement_claims_by_extension("ext-a", &ctx).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0], claim);
}

#[test]
fn get_single_flow_event_by_id() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let ev = flow_event(
        "ev1",
        "ext-a",
        Label::Public,
        Label::Internal,
        FlowDecision::Allowed,
    );
    idx.insert_flow_event(&ev, &ctx).unwrap();

    let found = idx.get_flow_event("ev1", &ctx).unwrap();
    assert_eq!(found, Some(ev));
}

#[test]
fn get_single_flow_event_missing() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let found = idx.get_flow_event("nonexistent", &ctx).unwrap();
    assert!(found.is_none());
}

#[test]
fn single_record_getters_trim_lookup_ids() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let ev = flow_event(
        "ev1",
        "ext-a",
        Label::Public,
        Label::Internal,
        FlowDecision::Allowed,
    );
    let proof = flow_proof("p1", "ext-a", Label::Public, Label::Internal, 1);
    let receipt = declass_receipt(
        "r1",
        "ext-a",
        Label::Secret,
        Label::Public,
        DeclassificationDecision::Allow,
    );
    let claim = confinement_claim("c1", "ext-a", ClaimStrength::Partial, 2);

    idx.insert_flow_event(&ev, &ctx).unwrap();
    idx.insert_flow_proof(&proof, &ctx).unwrap();
    idx.insert_declass_receipt(&receipt, &ctx).unwrap();
    idx.insert_confinement_claim(&claim, &ctx).unwrap();

    assert_eq!(idx.get_flow_event("  ev1  ", &ctx).unwrap(), Some(ev));
    assert_eq!(idx.get_flow_proof("  p1  ", &ctx).unwrap(), Some(proof));
    assert_eq!(
        idx.get_declass_receipt("  r1  ", &ctx).unwrap(),
        Some(receipt)
    );
    assert_eq!(
        idx.get_confinement_claim("  c1  ", &ctx).unwrap(),
        Some(claim)
    );
}

#[test]
fn get_single_flow_proof_by_id() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let proof = flow_proof("p1", "ext-a", Label::Public, Label::Internal, 1);
    idx.insert_flow_proof(&proof, &ctx).unwrap();

    let found = idx.get_flow_proof("p1", &ctx).unwrap();
    assert_eq!(found, Some(proof));
}

#[test]
fn get_single_declass_receipt_by_id() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let receipt = declass_receipt(
        "r1",
        "ext-a",
        Label::Secret,
        Label::Public,
        DeclassificationDecision::Allow,
    );
    idx.insert_declass_receipt(&receipt, &ctx).unwrap();

    let found = idx.get_declass_receipt("r1", &ctx).unwrap();
    assert_eq!(found, Some(receipt));
}

#[test]
fn get_single_confinement_claim_by_id() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let claim = confinement_claim("c1", "ext-a", ClaimStrength::Partial, 2);
    idx.insert_confinement_claim(&claim, &ctx).unwrap();

    let found = idx.get_confinement_claim("c1", &ctx).unwrap();
    assert_eq!(found, Some(claim));
}

// ===========================================================================
// Section 5: Error Conditions
// ===========================================================================

#[test]
fn reject_empty_event_id() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let ev = flow_event(
        "",
        "ext-a",
        Label::Public,
        Label::Internal,
        FlowDecision::Allowed,
    );
    let err = idx.insert_flow_event(&ev, &ctx).unwrap_err();
    assert!(matches!(err, ProvenanceError::EmptyId { .. }));
    assert_eq!(error_code(&err), "PROV_EMPTY_ID");
}

#[test]
fn reject_blank_event_id() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let ev = flow_event(
        "   ",
        "ext-a",
        Label::Public,
        Label::Internal,
        FlowDecision::Allowed,
    );
    let err = idx.insert_flow_event(&ev, &ctx).unwrap_err();
    assert!(matches!(err, ProvenanceError::EmptyId { .. }));
    assert_eq!(error_code(&err), "PROV_EMPTY_ID");
}

#[test]
fn reject_empty_extension_id_on_flow_event() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let ev = flow_event(
        "ev1",
        "",
        Label::Public,
        Label::Internal,
        FlowDecision::Allowed,
    );
    let err = idx.insert_flow_event(&ev, &ctx).unwrap_err();
    assert_eq!(err, ProvenanceError::EmptyExtensionId);
}

#[test]
fn reject_blank_extension_id_on_flow_event() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let ev = flow_event(
        "ev1",
        "   ",
        Label::Public,
        Label::Internal,
        FlowDecision::Allowed,
    );
    let err = idx.insert_flow_event(&ev, &ctx).unwrap_err();
    assert_eq!(err, ProvenanceError::EmptyExtensionId);
}

#[test]
fn reject_declassified_flow_event_without_receipt_ref() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let ev = flow_event(
        "ev1",
        "ext-a",
        Label::Confidential,
        Label::Public,
        FlowDecision::Declassified,
    );

    let err = idx.insert_flow_event(&ev, &ctx).unwrap_err();
    assert_eq!(
        err,
        ProvenanceError::EmptyRequiredField {
            record_type: "flow_event".to_string(),
            field_name: "receipt_ref".to_string(),
        }
    );
}

#[test]
fn reject_declassified_flow_event_with_blank_receipt_ref() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let mut ev = flow_event(
        "ev1",
        "ext-a",
        Label::Confidential,
        Label::Public,
        FlowDecision::Declassified,
    );
    ev.receipt_ref = Some("   ".to_string());

    let err = idx.insert_flow_event(&ev, &ctx).unwrap_err();
    assert_eq!(
        err,
        ProvenanceError::EmptyRequiredField {
            record_type: "flow_event".to_string(),
            field_name: "receipt_ref".to_string(),
        }
    );
}

#[test]
fn reject_empty_proof_id() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let proof = flow_proof("", "ext-a", Label::Public, Label::Internal, 1);
    let err = idx.insert_flow_proof(&proof, &ctx).unwrap_err();
    assert!(matches!(err, ProvenanceError::EmptyId { .. }));
}

#[test]
fn reject_blank_proof_id() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let proof = flow_proof("   ", "ext-a", Label::Public, Label::Internal, 1);
    let err = idx.insert_flow_proof(&proof, &ctx).unwrap_err();
    assert!(matches!(err, ProvenanceError::EmptyId { .. }));
}

#[test]
fn reject_empty_extension_id_on_proof() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let proof = flow_proof("p1", "", Label::Public, Label::Internal, 1);
    let err = idx.insert_flow_proof(&proof, &ctx).unwrap_err();
    assert_eq!(err, ProvenanceError::EmptyExtensionId);
}

#[test]
fn reject_blank_extension_id_on_proof() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let proof = flow_proof("p1", "   ", Label::Public, Label::Internal, 1);
    let err = idx.insert_flow_proof(&proof, &ctx).unwrap_err();
    assert_eq!(err, ProvenanceError::EmptyExtensionId);
}

#[test]
fn reject_empty_receipt_id() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let receipt = declass_receipt(
        "",
        "ext-a",
        Label::Secret,
        Label::Public,
        DeclassificationDecision::Allow,
    );
    let err = idx.insert_declass_receipt(&receipt, &ctx).unwrap_err();
    assert!(matches!(err, ProvenanceError::EmptyId { .. }));
}

#[test]
fn reject_empty_extension_id_on_receipt() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let receipt = declass_receipt(
        "r1",
        "",
        Label::Secret,
        Label::Public,
        DeclassificationDecision::Allow,
    );
    let err = idx.insert_declass_receipt(&receipt, &ctx).unwrap_err();
    assert_eq!(err, ProvenanceError::EmptyExtensionId);
}

#[test]
fn reject_empty_route_ref_on_receipt() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let mut receipt = declass_receipt(
        "r1",
        "ext-a",
        Label::Secret,
        Label::Public,
        DeclassificationDecision::Allow,
    );
    receipt.declassification_route_ref.clear();

    let err = idx.insert_declass_receipt(&receipt, &ctx).unwrap_err();
    assert_eq!(
        err,
        ProvenanceError::EmptyRequiredField {
            record_type: "declass_receipt".to_string(),
            field_name: "declassification_route_ref".to_string(),
        }
    );
}

#[test]
fn reject_empty_decision_contract_on_receipt() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let mut receipt = declass_receipt(
        "r1",
        "ext-a",
        Label::Secret,
        Label::Public,
        DeclassificationDecision::Allow,
    );
    receipt.decision_contract_id.clear();

    let err = idx.insert_declass_receipt(&receipt, &ctx).unwrap_err();
    assert_eq!(
        err,
        ProvenanceError::EmptyRequiredField {
            record_type: "declass_receipt".to_string(),
            field_name: "decision_contract_id".to_string(),
        }
    );
}

#[test]
fn reject_empty_claim_id() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let claim = confinement_claim("", "ext-a", ClaimStrength::Full, 1);
    let err = idx.insert_confinement_claim(&claim, &ctx).unwrap_err();
    assert!(matches!(err, ProvenanceError::EmptyId { .. }));
}

#[test]
fn reject_blank_claim_id() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let claim = confinement_claim("   ", "ext-a", ClaimStrength::Full, 1);
    let err = idx.insert_confinement_claim(&claim, &ctx).unwrap_err();
    assert!(matches!(err, ProvenanceError::EmptyId { .. }));
}

#[test]
fn reject_empty_extension_id_on_claim() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let claim = confinement_claim("c1", "", ClaimStrength::Full, 1);
    let err = idx.insert_confinement_claim(&claim, &ctx).unwrap_err();
    assert_eq!(err, ProvenanceError::EmptyExtensionId);
}

#[test]
fn reject_blank_extension_id_on_claim() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let claim = confinement_claim("c1", "   ", ClaimStrength::Full, 1);
    let err = idx.insert_confinement_claim(&claim, &ctx).unwrap_err();
    assert_eq!(err, ProvenanceError::EmptyExtensionId);
}

// ===========================================================================
// Section 6: Extension Isolation
// ===========================================================================

#[test]
fn queries_filter_by_extension_id() {
    let mut idx = make_index();
    let ctx = test_ctx();
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
}

#[test]
fn queries_canonicalize_whitespace_extension_ids() {
    let mut idx = make_index();
    let ctx = test_ctx();

    idx.insert_flow_event(
        &flow_event(
            "ev1",
            "  ext-a  ",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_proof(
        &flow_proof("p1", "  ext-a  ", Label::Public, Label::Internal, 1),
        &ctx,
    )
    .unwrap();
    idx.insert_confinement_claim(
        &confinement_claim("c1", "  ext-a  ", ClaimStrength::Full, 1),
        &ctx,
    )
    .unwrap();

    let events = idx.flow_events_by_extension("ext-a", &ctx).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].extension_id, "ext-a");

    let proofs = idx.flow_proofs_by_extension("  ext-a  ", &ctx).unwrap();
    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0].extension_id, "ext-a");

    let claims = idx.confinement_claims_by_extension("ext-a", &ctx).unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].extension_id, "ext-a");
}

#[test]
fn queries_return_empty_for_unknown_extension() {
    let mut idx = make_index();
    let ctx = test_ctx();
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

    assert!(
        idx.flow_events_by_extension("ext-unknown", &ctx)
            .unwrap()
            .is_empty()
    );
    assert!(
        idx.flow_proofs_by_extension("ext-unknown", &ctx)
            .unwrap()
            .is_empty()
    );
    assert!(
        idx.declass_receipts_by_extension("ext-unknown", &ctx)
            .unwrap()
            .is_empty()
    );
    assert!(
        idx.confinement_claims_by_extension("ext-unknown", &ctx)
            .unwrap()
            .is_empty()
    );
    assert!(
        idx.flow_events_by_extension("   ", &ctx)
            .unwrap()
            .is_empty()
    );
    assert!(
        idx.flow_proofs_by_extension("   ", &ctx)
            .unwrap()
            .is_empty()
    );
    assert!(
        idx.declass_receipts_by_extension("   ", &ctx)
            .unwrap()
            .is_empty()
    );
    assert!(
        idx.confinement_claims_by_extension("   ", &ctx)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn proof_isolation_by_extension() {
    let mut idx = make_index();
    let ctx = test_ctx();
    idx.insert_flow_proof(
        &flow_proof("p1", "ext-a", Label::Public, Label::Internal, 1),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_proof(
        &flow_proof("p2", "ext-b", Label::Confidential, Label::Secret, 2),
        &ctx,
    )
    .unwrap();

    let a = idx.flow_proofs_by_extension("ext-a", &ctx).unwrap();
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].proof_id, "p1");

    let b = idx.flow_proofs_by_extension("ext-b", &ctx).unwrap();
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].proof_id, "p2");
}

// ===========================================================================
// Section 7: Lineage Queries
// ===========================================================================

#[test]
fn source_to_sink_lineage_single_hop_event() {
    let mut idx = make_index();
    let ctx = test_ctx();
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
    assert_eq!(
        paths[0].hops[0].evidence_type,
        LineageEvidenceType::FlowEvent
    );
    assert_eq!(paths[0].hops[0].evidence_ref, "ev1");
}

#[test]
fn source_to_sink_lineage_from_proof() {
    let mut idx = make_index();
    let ctx = test_ctx();
    idx.insert_flow_proof(
        &flow_proof("p1", "ext-a", Label::Internal, Label::Confidential, 1),
        &ctx,
    )
    .unwrap();

    let paths = idx
        .source_to_sink_lineage("ext-a", &Label::Internal, &ctx)
        .unwrap();
    assert_eq!(paths.len(), 1);
    assert_eq!(
        paths[0].hops[0].evidence_type,
        LineageEvidenceType::FlowProof
    );
}

#[test]
fn source_to_sink_lineage_from_allowed_declass_receipt() {
    let mut idx = make_index();
    let ctx = test_ctx();
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

    let paths = idx
        .source_to_sink_lineage("ext-a", &Label::Secret, &ctx)
        .unwrap();
    assert_eq!(paths.len(), 1);
    assert_eq!(
        paths[0].hops[0].evidence_type,
        LineageEvidenceType::DeclassificationReceipt
    );
}

#[test]
fn source_to_sink_lineage_excludes_denied_declass() {
    let mut idx = make_index();
    let ctx = test_ctx();
    idx.insert_declass_receipt(
        &declass_receipt(
            "r1",
            "ext-a",
            Label::Secret,
            Label::Public,
            DeclassificationDecision::Deny,
        ),
        &ctx,
    )
    .unwrap();

    let paths = idx
        .source_to_sink_lineage("ext-a", &Label::Secret, &ctx)
        .unwrap();
    assert!(paths.is_empty());
}

#[test]
fn source_to_sink_lineage_multi_hop() {
    let mut idx = make_index();
    let ctx = test_ctx();
    // Chain: Public -> Internal -> Confidential
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

    let paths = idx
        .source_to_sink_lineage("ext-a", &Label::Public, &ctx)
        .unwrap();
    // Should find at least: 1-hop (Public->Internal), 2-hop (Public->Internal->Confidential)
    assert!(paths.len() >= 2);
    let multi_hop: Vec<_> = paths.iter().filter(|p| p.hops.len() == 2).collect();
    assert_eq!(multi_hop.len(), 1);
    assert_eq!(multi_hop[0].hops[0].sink_clearance, Label::Internal);
    assert_eq!(multi_hop[0].hops[1].sink_clearance, Label::Confidential);
}

#[test]
fn source_to_sink_lineage_three_hop_chain() {
    let mut idx = make_index();
    let ctx = test_ctx();
    // Chain: Public -> Internal -> Confidential -> Secret
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
}

#[test]
fn source_to_sink_lineage_empty_for_no_match() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let paths = idx
        .source_to_sink_lineage("ext-a", &Label::Secret, &ctx)
        .unwrap();
    assert!(paths.is_empty());
}

#[test]
fn source_to_sink_lineage_isolated_by_extension() {
    let mut idx = make_index();
    let ctx = test_ctx();
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
        .source_to_sink_lineage("ext-b", &Label::Public, &ctx)
        .unwrap();
    assert!(paths.is_empty());
}

// ===========================================================================
// Section 8: Sink Provenance
// ===========================================================================

#[test]
fn sink_provenance_collects_direct_sources() {
    let mut idx = make_index();
    let ctx = test_ctx();
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
fn sink_provenance_includes_proof_sources() {
    let mut idx = make_index();
    let ctx = test_ctx();
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
fn sink_provenance_includes_allowed_declass_receipts() {
    let mut idx = make_index();
    let ctx = test_ctx();
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

    let sources = idx.sink_provenance("ext-a", &Label::Public, &ctx).unwrap();
    assert!(sources.contains(&Label::Secret));
}

#[test]
fn sink_provenance_excludes_denied_declass() {
    let mut idx = make_index();
    let ctx = test_ctx();
    idx.insert_declass_receipt(
        &declass_receipt(
            "r1",
            "ext-a",
            Label::Secret,
            Label::Public,
            DeclassificationDecision::Deny,
        ),
        &ctx,
    )
    .unwrap();

    let sources = idx.sink_provenance("ext-a", &Label::Public, &ctx).unwrap();
    assert!(!sources.contains(&Label::Secret));
}

#[test]
fn sink_provenance_transitive_sources() {
    let mut idx = make_index();
    let ctx = test_ctx();
    // Public -> Internal -> Confidential
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

    let sources = idx
        .sink_provenance("ext-a", &Label::Confidential, &ctx)
        .unwrap();
    // Transitive: both Internal (direct) and Public (via Internal) should be sources
    assert!(sources.contains(&Label::Internal));
    assert!(sources.contains(&Label::Public));
}

#[test]
fn sink_provenance_empty_for_no_match() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let sources = idx.sink_provenance("ext-a", &Label::Secret, &ctx).unwrap();
    assert!(sources.is_empty());
}

// ===========================================================================
// Section 9: Time-Range and Epoch Queries
// ===========================================================================

#[test]
fn flow_events_by_time_range_inclusive() {
    let mut idx = make_index();
    let ctx = test_ctx();
    idx.insert_flow_event(
        &flow_event_at(
            "ev1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
            100,
        ),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_event(
        &flow_event_at(
            "ev2",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
            200,
        ),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_event(
        &flow_event_at(
            "ev3",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
            300,
        ),
        &ctx,
    )
    .unwrap();

    let results = idx
        .flow_events_by_time_range("ext-a", 100, 200, &ctx)
        .unwrap();
    assert_eq!(results.len(), 2);
}

#[test]
fn flow_events_by_time_range_excludes_outside() {
    let mut idx = make_index();
    let ctx = test_ctx();
    idx.insert_flow_event(
        &flow_event_at(
            "ev1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
            50,
        ),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_event(
        &flow_event_at(
            "ev2",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
            500,
        ),
        &ctx,
    )
    .unwrap();

    let results = idx
        .flow_events_by_time_range("ext-a", 100, 200, &ctx)
        .unwrap();
    assert!(results.is_empty());
}

#[test]
fn flow_proofs_by_epoch_filters_correctly() {
    let mut idx = make_index();
    let ctx = test_ctx();
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
        &flow_proof("p3", "ext-a", Label::Confidential, Label::Secret, 1),
        &ctx,
    )
    .unwrap();

    let epoch1 = idx.flow_proofs_by_epoch("ext-a", 1, &ctx).unwrap();
    assert_eq!(epoch1.len(), 2);

    let epoch2 = idx.flow_proofs_by_epoch("ext-a", 2, &ctx).unwrap();
    assert_eq!(epoch2.len(), 1);
    assert_eq!(epoch2[0].proof_id, "p2");
}

#[test]
fn flow_proofs_by_epoch_empty_for_no_match() {
    let mut idx = make_index();
    let ctx = test_ctx();
    idx.insert_flow_proof(
        &flow_proof("p1", "ext-a", Label::Public, Label::Internal, 1),
        &ctx,
    )
    .unwrap();

    let results = idx.flow_proofs_by_epoch("ext-a", 999, &ctx).unwrap();
    assert!(results.is_empty());
}

// ===========================================================================
// Section 10: Record Counts
// ===========================================================================

#[test]
fn record_counts_for_populated_extension() {
    let mut idx = make_index();
    let ctx = test_ctx();

    for i in 0..3 {
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
    for i in 0..2 {
        idx.insert_flow_proof(
            &flow_proof(&format!("p{i}"), "ext-a", Label::Public, Label::Internal, 1),
            &ctx,
        )
        .unwrap();
    }
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
    assert_eq!(counts.flow_events, 3);
    assert_eq!(counts.flow_proofs, 2);
    assert_eq!(counts.declass_receipts, 1);
    assert_eq!(counts.confinement_claims, 1);
    assert_eq!(counts.total(), 7);
}

#[test]
fn record_counts_for_empty_extension() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let counts = idx.record_counts("ext-empty", &ctx).unwrap();
    assert_eq!(counts.total(), 0);
}

// ===========================================================================
// Section 11: Confinement Status
// ===========================================================================

#[test]
fn confinement_status_proven_and_unproven() {
    let mut idx = make_index();
    let ctx = test_ctx();

    // Two event flows
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

    // One proof covering first flow
    idx.insert_flow_proof(
        &flow_proof("p1", "ext-a", Label::Public, Label::Internal, 5),
        &ctx,
    )
    .unwrap();

    // One partial claim
    idx.insert_confinement_claim(
        &confinement_claim("c1", "ext-a", ClaimStrength::Partial, 5),
        &ctx,
    )
    .unwrap();

    let status = idx.confinement_status("ext-a", &ctx).unwrap();
    assert_eq!(status.proven_flows, 1);
    assert_eq!(status.unproven_flows, 1);
    assert_eq!(status.strongest_claim, Some(ClaimStrength::Partial));
    assert_eq!(status.latest_proof_epoch, Some(5));
}

#[test]
fn confinement_status_full_coverage() {
    let mut idx = make_index();
    let ctx = test_ctx();

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
        &flow_proof("p1", "ext-a", Label::Public, Label::Internal, 3),
        &ctx,
    )
    .unwrap();
    idx.insert_confinement_claim(
        &confinement_claim("c1", "ext-a", ClaimStrength::Full, 3),
        &ctx,
    )
    .unwrap();

    let status = idx.confinement_status("ext-a", &ctx).unwrap();
    assert_eq!(status.proven_flows, 1);
    assert_eq!(status.unproven_flows, 0);
    assert_eq!(status.strongest_claim, Some(ClaimStrength::Full));
}

#[test]
fn confinement_status_empty_extension() {
    let mut idx = make_index();
    let ctx = test_ctx();
    let status = idx.confinement_status("empty-ext", &ctx).unwrap();
    assert_eq!(status.proven_flows, 0);
    assert_eq!(status.unproven_flows, 0);
    assert!(status.strongest_claim.is_none());
    assert!(status.latest_proof_epoch.is_none());
}

#[test]
fn confinement_status_full_beats_partial() {
    let mut idx = make_index();
    let ctx = test_ctx();

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

// ===========================================================================
// Section 12: Replay Join (events + receipts)
// ===========================================================================

#[test]
fn join_events_with_matching_receipt() {
    let mut idx = make_index();
    let ctx = test_ctx();

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
fn join_events_without_receipt_ref() {
    let mut idx = make_index();
    let ctx = test_ctx();

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
fn join_events_with_dangling_receipt_ref() {
    let mut idx = make_index();
    let ctx = test_ctx();

    let mut ev = flow_event(
        "ev1",
        "ext-a",
        Label::Secret,
        Label::Public,
        FlowDecision::Declassified,
    );
    ev.receipt_ref = Some("nonexistent".to_string());
    idx.insert_flow_event(&ev, &ctx).unwrap();

    let joined = idx.join_events_with_receipts("ext-a", &ctx).unwrap();
    assert_eq!(joined.len(), 1);
    assert!(joined[0].1.is_none()); // No matching receipt
}

#[test]
fn join_events_with_padded_receipt_ref_and_receipt_id() {
    let mut idx = make_index();
    let ctx = test_ctx();

    let mut ev = flow_event(
        "ev1",
        "ext-a",
        Label::Secret,
        Label::Public,
        FlowDecision::Declassified,
    );
    ev.receipt_ref = Some("  r1  ".to_string());
    idx.insert_flow_event(&ev, &ctx).unwrap();

    let mut receipt = declass_receipt(
        "  r1  ",
        "  ext-a  ",
        Label::Secret,
        Label::Public,
        DeclassificationDecision::Allow,
    );
    receipt.declassification_route_ref = "  route-r1  ".to_string();
    receipt.decision_contract_id = "  decision-r1  ".to_string();
    idx.insert_declass_receipt(&receipt, &ctx).unwrap();

    let stored_event = idx.get_flow_event("ev1", &ctx).unwrap().unwrap();
    let stored_receipt = idx.get_declass_receipt("r1", &ctx).unwrap().unwrap();
    assert_eq!(stored_event.receipt_ref.as_deref(), Some("r1"));
    assert_eq!(stored_receipt.receipt_id, "r1");
    assert_eq!(stored_receipt.extension_id, "ext-a");
    assert_eq!(stored_receipt.declassification_route_ref, "route-r1");
    assert_eq!(stored_receipt.decision_contract_id, "decision-r1");

    let joined = idx.join_events_with_receipts("ext-a", &ctx).unwrap();
    assert_eq!(joined.len(), 1);
    assert_eq!(joined[0].1.as_ref().unwrap().receipt_id, "r1");
}

// ===========================================================================
// Section 13: Events Emitted
// ===========================================================================

#[test]
fn events_emitted_on_flow_event_insert() {
    let mut idx = make_index();
    let ctx = test_ctx();
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

    let events = idx.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "flow_event_inserted");
    assert_eq!(events[0].outcome, "ok");
}

#[test]
fn events_emitted_on_proof_insert() {
    let mut idx = make_index();
    let ctx = test_ctx();
    idx.insert_flow_proof(
        &flow_proof("p1", "ext-a", Label::Public, Label::Internal, 1),
        &ctx,
    )
    .unwrap();

    let events = idx.events();
    assert!(events.iter().any(|e| e.event == "flow_proof_inserted"));
}

#[test]
fn events_emitted_on_receipt_insert() {
    let mut idx = make_index();
    let ctx = test_ctx();
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

    let events = idx.events();
    assert!(events.iter().any(|e| e.event == "declass_receipt_inserted"));
}

#[test]
fn events_emitted_on_claim_insert() {
    let mut idx = make_index();
    let ctx = test_ctx();
    idx.insert_confinement_claim(
        &confinement_claim("c1", "ext-a", ClaimStrength::Full, 1),
        &ctx,
    )
    .unwrap();

    let events = idx.events();
    assert!(
        events
            .iter()
            .any(|e| e.event == "confinement_claim_inserted")
    );
}

#[test]
fn events_emitted_on_lineage_query() {
    let mut idx = make_index();
    let ctx = test_ctx();
    idx.source_to_sink_lineage("ext-a", &Label::Public, &ctx)
        .unwrap();
    assert!(idx.events().iter().any(|e| e.event == "lineage_query"));
}

#[test]
fn drain_events_clears_accumulated() {
    let mut idx = make_index();
    let ctx = test_ctx();
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
    assert!(!idx.events().is_empty());

    let drained = idx.drain_events();
    assert!(!drained.is_empty());
    assert!(idx.events().is_empty());
}

// ===========================================================================
// Section 14: Serde Round-Trips
// ===========================================================================

#[test]
fn flow_event_record_serde_roundtrip() {
    let ev = flow_event(
        "ev1",
        "ext-a",
        Label::Public,
        Label::Internal,
        FlowDecision::Allowed,
    );
    let json = serde_json::to_string(&ev).unwrap();
    let deser: FlowEventRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, deser);
}

#[test]
fn flow_proof_record_serde_roundtrip() {
    let proof = flow_proof("p1", "ext-a", Label::Internal, Label::Confidential, 1);
    let json = serde_json::to_string(&proof).unwrap();
    let deser: FlowProofRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(proof, deser);
}

#[test]
fn declass_receipt_record_serde_roundtrip() {
    let receipt = declass_receipt(
        "r1",
        "ext-a",
        Label::Secret,
        Label::Public,
        DeclassificationDecision::Allow,
    );
    let json = serde_json::to_string(&receipt).unwrap();
    let deser: DeclassReceiptRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, deser);
}

#[test]
fn declass_receipt_record_legacy_serde_defaults_route_and_contract() {
    let mut value = serde_json::to_value(declass_receipt(
        "r1",
        "ext-a",
        Label::Secret,
        Label::Public,
        DeclassificationDecision::Allow,
    ))
    .unwrap();
    value
        .as_object_mut()
        .unwrap()
        .remove("declassification_route_ref");
    value
        .as_object_mut()
        .unwrap()
        .remove("decision_contract_id");
    let deser: DeclassReceiptRecord = serde_json::from_value(value).unwrap();
    assert_eq!(deser.receipt_id, "r1");
    assert!(deser.declassification_route_ref.is_empty());
    assert!(deser.decision_contract_id.is_empty());
}

#[test]
fn confinement_claim_record_serde_roundtrip() {
    let claim = confinement_claim("c1", "ext-a", ClaimStrength::Full, 1);
    let json = serde_json::to_string(&claim).unwrap();
    let deser: ConfinementClaimRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(claim, deser);
}

#[test]
fn flow_decision_serde_roundtrip_all_variants() {
    for dec in [
        FlowDecision::Allowed,
        FlowDecision::Blocked,
        FlowDecision::Declassified,
    ] {
        let json = serde_json::to_string(&dec).unwrap();
        let deser: FlowDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(dec, deser);
    }
}

#[test]
fn lineage_evidence_type_serde_roundtrip_all_variants() {
    for typ in [
        LineageEvidenceType::FlowEvent,
        LineageEvidenceType::FlowProof,
        LineageEvidenceType::DeclassificationReceipt,
    ] {
        let json = serde_json::to_string(&typ).unwrap();
        let deser: LineageEvidenceType = serde_json::from_str(&json).unwrap();
        assert_eq!(typ, deser);
    }
}

#[test]
fn lineage_hop_serde_roundtrip() {
    let hop = LineageHop {
        source_label: Label::Public,
        sink_clearance: Label::Internal,
        evidence_ref: "ev1".to_string(),
        evidence_type: LineageEvidenceType::FlowEvent,
    };
    let json = serde_json::to_string(&hop).unwrap();
    let deser: LineageHop = serde_json::from_str(&json).unwrap();
    assert_eq!(hop, deser);
}

#[test]
fn lineage_path_serde_roundtrip() {
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
    let deser: LineagePath = serde_json::from_str(&json).unwrap();
    assert_eq!(path, deser);
}

#[test]
fn confinement_status_serde_roundtrip() {
    let status = ConfinementStatus {
        extension_id: "ext-a".to_string(),
        proven_flows: 5,
        unproven_flows: 2,
        strongest_claim: Some(ClaimStrength::Full),
        latest_proof_epoch: Some(3),
    };
    let json = serde_json::to_string(&status).unwrap();
    let deser: ConfinementStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(status, deser);
}

#[test]
fn confinement_status_serde_roundtrip_none_fields() {
    let status = ConfinementStatus {
        extension_id: "ext-b".to_string(),
        proven_flows: 0,
        unproven_flows: 0,
        strongest_claim: None,
        latest_proof_epoch: None,
    };
    let json = serde_json::to_string(&status).unwrap();
    let deser: ConfinementStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(status, deser);
}

#[test]
fn record_counts_serde_roundtrip() {
    let counts = RecordCounts {
        flow_events: 10,
        flow_proofs: 5,
        declass_receipts: 3,
        confinement_claims: 2,
    };
    let json = serde_json::to_string(&counts).unwrap();
    let deser: RecordCounts = serde_json::from_str(&json).unwrap();
    assert_eq!(counts, deser);
}

#[test]
fn provenance_error_serde_roundtrip_all_variants() {
    let errors = vec![
        ProvenanceError::EmptyId {
            record_type: "flow_event".to_string(),
        },
        ProvenanceError::EmptyExtensionId,
        ProvenanceError::EmptyRequiredField {
            record_type: "declass_receipt".to_string(),
            field_name: "decision_contract_id".to_string(),
        },
        ProvenanceError::DuplicateRecord {
            key: "k1".to_string(),
        },
        ProvenanceError::StorageError("test".to_string()),
        ProvenanceError::SerializationError("test".to_string()),
    ];
    for err in errors {
        let json = serde_json::to_string(&err).unwrap();
        let deser: ProvenanceError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, deser);
    }
}

#[test]
fn provenance_event_serde_roundtrip() {
    let ev = ProvenanceEvent {
        trace_id: "t1".to_string(),
        component: "ifc_provenance_index".to_string(),
        event: "flow_event_inserted".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
        extension_id: Some("ext-a".to_string()),
        record_count: Some(1),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let deser: ProvenanceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, deser);
}

#[test]
fn provenance_event_serde_with_error_code() {
    let ev = ProvenanceEvent {
        trace_id: "t1".to_string(),
        component: "ifc_provenance_index".to_string(),
        event: "error".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("PROV_EMPTY_ID".to_string()),
        extension_id: None,
        record_count: None,
    };
    let json = serde_json::to_string(&ev).unwrap();
    let deser: ProvenanceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, deser);
}

// ===========================================================================
// Section 15: Deterministic Replay
// ===========================================================================

#[test]
fn deterministic_replay_same_operations_same_results() {
    let ctx = test_ctx();

    let run = || {
        let mut idx = make_index();
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

        let events = idx.flow_events_by_extension("ext-a", &ctx).unwrap();
        let proofs = idx.flow_proofs_by_extension("ext-a", &ctx).unwrap();
        let receipts = idx.declass_receipts_by_extension("ext-a", &ctx).unwrap();
        let claims = idx.confinement_claims_by_extension("ext-a", &ctx).unwrap();
        let lineage = idx
            .source_to_sink_lineage("ext-a", &Label::Public, &ctx)
            .unwrap();
        let provenance = idx
            .sink_provenance("ext-a", &Label::Confidential, &ctx)
            .unwrap();
        let status = idx.confinement_status("ext-a", &ctx).unwrap();
        let counts = idx.record_counts("ext-a", &ctx).unwrap();

        (
            events, proofs, receipts, claims, lineage, provenance, status, counts,
        )
    };

    let run1 = run();
    let run2 = run();
    assert_eq!(run1.0, run2.0, "flow events differ");
    assert_eq!(run1.1, run2.1, "flow proofs differ");
    assert_eq!(run1.2, run2.2, "declass receipts differ");
    assert_eq!(run1.3, run2.3, "confinement claims differ");
    assert_eq!(run1.4, run2.4, "lineage paths differ");
    assert_eq!(run1.5, run2.5, "sink provenance differs");
    assert_eq!(run1.6, run2.6, "confinement status differs");
    assert_eq!(run1.7, run2.7, "record counts differ");
}

// ===========================================================================
// Section 16: Multiple Records and Ordering
// ===========================================================================

#[test]
fn multiple_flow_events_returned_sorted() {
    let mut idx = make_index();
    let ctx = test_ctx();

    // Insert in reverse order
    for i in (0..5).rev() {
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

    let results = idx.flow_events_by_extension("ext-a", &ctx).unwrap();
    assert_eq!(results.len(), 5);
    // Results should be sorted (by Ord impl on FlowEventRecord)
    for i in 1..results.len() {
        assert!(results[i - 1] <= results[i]);
    }
}

#[test]
fn multiple_proofs_across_epochs() {
    let mut idx = make_index();
    let ctx = test_ctx();

    for i in 0..4 {
        idx.insert_flow_proof(
            &flow_proof(
                &format!("p{i}"),
                "ext-a",
                Label::Public,
                Label::Internal,
                (i + 1) as u64,
            ),
            &ctx,
        )
        .unwrap();
    }

    let results = idx.flow_proofs_by_extension("ext-a", &ctx).unwrap();
    assert_eq!(results.len(), 4);
}

// ===========================================================================
// Section 17: Custom Label Support
// ===========================================================================

#[test]
fn custom_label_in_flow_event() {
    let mut idx = make_index();
    let ctx = test_ctx();

    let custom = Label::Custom {
        name: "pii".to_string(),
        level: 3,
    };
    let ev = flow_event(
        "ev1",
        "ext-a",
        custom.clone(),
        Label::Secret,
        FlowDecision::Allowed,
    );
    idx.insert_flow_event(&ev, &ctx).unwrap();

    let results = idx.flow_events_by_extension("ext-a", &ctx).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].source_label, custom);
}

#[test]
fn custom_label_lineage_traversal() {
    let mut idx = make_index();
    let ctx = test_ctx();

    let pii = Label::Custom {
        name: "pii".to_string(),
        level: 3,
    };
    idx.insert_flow_event(
        &flow_event(
            "ev1",
            "ext-a",
            pii.clone(),
            Label::Secret,
            FlowDecision::Allowed,
        ),
        &ctx,
    )
    .unwrap();

    let paths = idx.source_to_sink_lineage("ext-a", &pii, &ctx).unwrap();
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].hops[0].source_label, pii);
}

// ===========================================================================
// Section 18: All FlowDecision Variants
// ===========================================================================

#[test]
fn all_flow_decision_variants_insert_and_query() {
    let mut idx = make_index();
    let ctx = test_ctx();

    for (i, dec) in [
        FlowDecision::Allowed,
        FlowDecision::Blocked,
        FlowDecision::Declassified,
    ]
    .iter()
    .enumerate()
    {
        idx.insert_flow_event(
            &{
                let mut ev = flow_event(
                    &format!("ev{i}"),
                    "ext-a",
                    Label::Public,
                    Label::Internal,
                    *dec,
                );
                if matches!(dec, FlowDecision::Declassified) {
                    ev.receipt_ref = Some(format!("r{i}"));
                }
                ev
            },
            &ctx,
        )
        .unwrap();
    }

    let results = idx.flow_events_by_extension("ext-a", &ctx).unwrap();
    assert_eq!(results.len(), 3);
    let decisions: BTreeSet<FlowDecision> = results.iter().map(|r| r.decision).collect();
    assert!(decisions.contains(&FlowDecision::Allowed));
    assert!(decisions.contains(&FlowDecision::Blocked));
    assert!(decisions.contains(&FlowDecision::Declassified));
}

// ===========================================================================
// Section 19: All ProofMethod Variants
// ===========================================================================

#[test]
fn all_proof_method_variants() {
    let mut idx = make_index();
    let ctx = test_ctx();

    let methods = [
        ProofMethod::StaticAnalysis,
        ProofMethod::RuntimeCheck,
        ProofMethod::Declassification,
    ];
    for (i, method) in methods.iter().enumerate() {
        let proof = FlowProofRecord {
            proof_id: format!("p{i}"),
            extension_id: "ext-a".to_string(),
            source_label: Label::Public,
            sink_clearance: Label::Internal,
            proof_method: *method,
            epoch_id: 1,
        };
        idx.insert_flow_proof(&proof, &ctx).unwrap();
    }

    let results = idx.flow_proofs_by_extension("ext-a", &ctx).unwrap();
    assert_eq!(results.len(), 3);
}

// ===========================================================================
// Section 20: Store Accessor
// ===========================================================================

#[test]
fn store_mut_accessor_available() {
    let mut idx = make_index();
    // Ensure store_mut compiles and returns mutable ref
    let _store = idx.store_mut();
}

// ===========================================================================
// Section 21: End-to-End Multi-Extension Scenario
// ===========================================================================

#[test]
fn end_to_end_multi_extension_scenario() {
    let mut idx = make_index();
    let ctx = test_ctx();

    // Extension A: Public -> Internal (event + proof)
    idx.insert_flow_event(
        &flow_event(
            "a-ev1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &ctx,
    )
    .unwrap();
    idx.insert_flow_proof(
        &flow_proof("a-p1", "ext-a", Label::Public, Label::Internal, 1),
        &ctx,
    )
    .unwrap();
    idx.insert_confinement_claim(
        &confinement_claim("a-c1", "ext-a", ClaimStrength::Full, 1),
        &ctx,
    )
    .unwrap();

    // Extension B: Secret -> Public (declassification)
    idx.insert_flow_event(
        &{
            let mut ev = flow_event(
                "b-ev1",
                "ext-b",
                Label::Secret,
                Label::Public,
                FlowDecision::Declassified,
            );
            ev.receipt_ref = Some("b-r1".to_string());
            ev
        },
        &ctx,
    )
    .unwrap();
    idx.insert_declass_receipt(
        &declass_receipt(
            "b-r1",
            "ext-b",
            Label::Secret,
            Label::Public,
            DeclassificationDecision::Allow,
        ),
        &ctx,
    )
    .unwrap();

    // Verify ext-a confinement
    let status_a = idx.confinement_status("ext-a", &ctx).unwrap();
    assert_eq!(status_a.proven_flows, 1);
    assert_eq!(status_a.unproven_flows, 0);
    assert_eq!(status_a.strongest_claim, Some(ClaimStrength::Full));

    // Verify ext-b join
    let joined = idx.join_events_with_receipts("ext-b", &ctx).unwrap();
    assert_eq!(joined.len(), 1);
    assert!(joined[0].1.is_some());

    // Verify isolation
    assert!(
        idx.flow_events_by_extension("ext-a", &ctx)
            .unwrap()
            .iter()
            .all(|e| e.extension_id == "ext-a")
    );
    assert!(
        idx.flow_events_by_extension("ext-b", &ctx)
            .unwrap()
            .iter()
            .all(|e| e.extension_id == "ext-b")
    );

    // Verify lineage for ext-b
    let paths = idx
        .source_to_sink_lineage("ext-b", &Label::Secret, &ctx)
        .unwrap();
    assert!(!paths.is_empty());
}
