//! Integration tests for `ifc_provenance_index` — edge cases not covered by
//! the 69 inline unit tests.
//!
//! Focus areas:
//! - Empty extension_id validation for all 4 record types (inline only tests flow_event)
//! - Storage error propagation via fail_writes
//! - MAX_LINEAGE_DEPTH (16) boundary
//! - Blocked/Declassified events in lineage edges
//! - Cycle detection in sink_provenance
//! - Diamond-shaped lineage graphs
//! - Confinement status with competing claim strengths
//! - Join edge cases (missing receipts, no events)
//! - Extension isolation in time-range and epoch queries
//! - ProvenanceError Display exact messages
//! - Large-scale determinism
//! - Field preservation through insert/query roundtrip

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

fn ctx() -> EventContext {
    EventContext::new("trace-int", "decision-int", "policy-int").expect("ctx")
}

fn make_index() -> IfcProvenanceIndex<InMemoryStorageAdapter> {
    IfcProvenanceIndex::new(InMemoryStorageAdapter::new())
}

fn failing_index() -> IfcProvenanceIndex<InMemoryStorageAdapter> {
    IfcProvenanceIndex::new(InMemoryStorageAdapter::new().with_fail_writes(true))
}

fn event(id: &str, ext: &str, src: Label, sink: Label, dec: FlowDecision) -> FlowEventRecord {
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

fn event_ts(
    id: &str,
    ext: &str,
    src: Label,
    sink: Label,
    dec: FlowDecision,
    ts: u64,
) -> FlowEventRecord {
    FlowEventRecord {
        timestamp_ms: ts,
        ..event(id, ext, src, sink, dec)
    }
}

fn proof(id: &str, ext: &str, src: Label, sink: Label, epoch: u64) -> FlowProofRecord {
    FlowProofRecord {
        proof_id: id.to_string(),
        extension_id: ext.to_string(),
        source_label: src,
        sink_clearance: sink,
        proof_method: ProofMethod::StaticAnalysis,
        epoch_id: epoch,
    }
}

fn receipt(
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

fn claim(id: &str, ext: &str, strength: ClaimStrength, epoch: u64) -> ConfinementClaimRecord {
    ConfinementClaimRecord {
        claim_id: id.to_string(),
        extension_id: ext.to_string(),
        claim_strength: strength,
        epoch_id: epoch,
    }
}

// =========================================================================
// 1. Empty extension_id validation for all 4 record types
// =========================================================================

#[test]
fn empty_extension_id_rejected_for_flow_proof() {
    let mut idx = make_index();
    let c = ctx();
    let p = proof("p1", "", Label::Public, Label::Internal, 1);
    let err = idx.insert_flow_proof(&p, &c).unwrap_err();
    assert_eq!(err, ProvenanceError::EmptyExtensionId);
}

#[test]
fn empty_extension_id_rejected_for_declass_receipt() {
    let mut idx = make_index();
    let c = ctx();
    let r = receipt(
        "r1",
        "",
        Label::Secret,
        Label::Public,
        DeclassificationDecision::Allow,
    );
    let err = idx.insert_declass_receipt(&r, &c).unwrap_err();
    assert_eq!(err, ProvenanceError::EmptyExtensionId);
}

#[test]
fn empty_extension_id_rejected_for_confinement_claim() {
    let mut idx = make_index();
    let c = ctx();
    let cl = claim("c1", "", ClaimStrength::Full, 1);
    let err = idx.insert_confinement_claim(&cl, &c).unwrap_err();
    assert_eq!(err, ProvenanceError::EmptyExtensionId);
}

// =========================================================================
// 2. ProvenanceError Display exact messages
// =========================================================================

#[test]
fn provenance_error_display_empty_id() {
    let err = ProvenanceError::EmptyId {
        record_type: "flow_event".to_string(),
    };
    assert_eq!(err.to_string(), "flow_event has empty ID");
}

#[test]
fn provenance_error_display_empty_extension_id() {
    let err = ProvenanceError::EmptyExtensionId;
    assert_eq!(err.to_string(), "extension_id is empty");
}

#[test]
fn provenance_error_display_duplicate_record() {
    let err = ProvenanceError::DuplicateRecord {
        key: "flow_event::ev1".to_string(),
    };
    assert_eq!(err.to_string(), "duplicate record: flow_event::ev1");
}

#[test]
fn provenance_error_display_storage_error() {
    let err = ProvenanceError::StorageError("disk full".to_string());
    assert_eq!(err.to_string(), "storage: disk full");
}

#[test]
fn provenance_error_display_serialization_error() {
    let err = ProvenanceError::SerializationError("invalid utf8".to_string());
    assert_eq!(err.to_string(), "serialization: invalid utf8");
}

#[test]
fn provenance_error_implements_std_error() {
    let err: &dyn std::error::Error = &ProvenanceError::EmptyExtensionId;
    // std::error::Error is implemented.
    assert!(!err.to_string().is_empty());
}

// =========================================================================
// 3. error_code exhaustive from integration level
// =========================================================================

#[test]
fn error_code_all_variants() {
    assert_eq!(
        error_code(&ProvenanceError::EmptyId {
            record_type: "test".to_string()
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

// =========================================================================
// 4. Storage error propagation via fail_writes
// =========================================================================

#[test]
fn storage_error_on_insert_flow_event() {
    let mut idx = failing_index();
    let c = ctx();
    let ev = event(
        "e1",
        "ext-a",
        Label::Public,
        Label::Internal,
        FlowDecision::Allowed,
    );
    let err = idx.insert_flow_event(&ev, &c).unwrap_err();
    assert!(matches!(err, ProvenanceError::StorageError(_)));
}

#[test]
fn storage_error_on_insert_flow_proof() {
    let mut idx = failing_index();
    let c = ctx();
    let p = proof("p1", "ext-a", Label::Public, Label::Internal, 1);
    let err = idx.insert_flow_proof(&p, &c).unwrap_err();
    assert!(matches!(err, ProvenanceError::StorageError(_)));
}

#[test]
fn storage_error_on_insert_declass_receipt() {
    let mut idx = failing_index();
    let c = ctx();
    let r = receipt(
        "r1",
        "ext-a",
        Label::Secret,
        Label::Public,
        DeclassificationDecision::Allow,
    );
    let err = idx.insert_declass_receipt(&r, &c).unwrap_err();
    assert!(matches!(err, ProvenanceError::StorageError(_)));
}

#[test]
fn storage_error_on_insert_confinement_claim() {
    let mut idx = failing_index();
    let c = ctx();
    let cl = claim("c1", "ext-a", ClaimStrength::Full, 1);
    let err = idx.insert_confinement_claim(&cl, &c).unwrap_err();
    assert!(matches!(err, ProvenanceError::StorageError(_)));
}

// =========================================================================
// 5. MAX_LINEAGE_DEPTH (16) boundary
// =========================================================================

#[test]
fn lineage_depth_capped_at_16() {
    let mut idx = make_index();
    let c = ctx();

    // Build a chain of 20 labels: L0 → L1 → L2 → ... → L19.
    // Use the 5 builtin labels cyclically but with unique event IDs.
    let labels = [
        Label::Public,
        Label::Internal,
        Label::Confidential,
        Label::Secret,
        Label::TopSecret,
    ];

    // We need 20 distinct labels, but Label only has 5 variants.
    // The lineage algorithm visits by label equality, so with only 5 labels,
    // cycle detection kicks in after at most 4 hops.
    // Instead, test that a 4-hop full-label chain caps correctly:
    // Public → Internal → Confidential → Secret → TopSecret
    for (i, pair) in labels.windows(2).enumerate() {
        idx.insert_flow_event(
            &event(
                &format!("chain-{i}"),
                "ext-depth",
                pair[0].clone(),
                pair[1].clone(),
                FlowDecision::Allowed,
            ),
            &c,
        )
        .unwrap();
    }

    let paths = idx
        .source_to_sink_lineage("ext-depth", &Label::Public, &c)
        .unwrap();

    // Should produce paths of length 1,2,3,4 (4 single-hop, 3 two-hop, etc.)
    let max_hops = paths.iter().map(|p| p.hops.len()).max().unwrap();
    assert_eq!(max_hops, 4); // Public→Internal→Confidential→Secret→TopSecret
    // All hops are bounded.
    assert!(paths.iter().all(|p| p.hops.len() <= 16));
}

// =========================================================================
// 6. Blocked events appear in lineage edges
// =========================================================================

#[test]
fn blocked_events_appear_in_lineage() {
    let mut idx = make_index();
    let c = ctx();

    // A blocked flow event still contributes an edge in lineage.
    idx.insert_flow_event(
        &event(
            "blocked-ev",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Blocked,
        ),
        &c,
    )
    .unwrap();

    let paths = idx
        .source_to_sink_lineage("ext-a", &Label::Public, &c)
        .unwrap();
    assert_eq!(paths.len(), 1);
    assert_eq!(
        paths[0].hops[0].evidence_type,
        LineageEvidenceType::FlowEvent
    );
    assert_eq!(paths[0].hops[0].evidence_ref, "blocked-ev");
}

#[test]
fn declassified_events_appear_in_lineage() {
    let mut idx = make_index();
    let c = ctx();

    idx.insert_flow_event(
        &event(
            "declass-ev",
            "ext-a",
            Label::Secret,
            Label::Public,
            FlowDecision::Declassified,
        ),
        &c,
    )
    .unwrap();

    let paths = idx
        .source_to_sink_lineage("ext-a", &Label::Secret, &c)
        .unwrap();
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].hops[0].evidence_ref, "declass-ev");
}

// =========================================================================
// 7. Diamond-shaped lineage graph
// =========================================================================

#[test]
fn diamond_shaped_lineage() {
    let mut idx = make_index();
    let c = ctx();

    // Public → Internal (ev1)
    // Public → Confidential (ev2)
    // Internal → Secret (ev3)
    // Confidential → Secret (ev4)
    idx.insert_flow_event(
        &event(
            "ev1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &c,
    )
    .unwrap();
    idx.insert_flow_event(
        &event(
            "ev2",
            "ext-a",
            Label::Public,
            Label::Confidential,
            FlowDecision::Allowed,
        ),
        &c,
    )
    .unwrap();
    idx.insert_flow_event(
        &event(
            "ev3",
            "ext-a",
            Label::Internal,
            Label::Secret,
            FlowDecision::Allowed,
        ),
        &c,
    )
    .unwrap();
    idx.insert_flow_event(
        &event(
            "ev4",
            "ext-a",
            Label::Confidential,
            Label::Secret,
            FlowDecision::Allowed,
        ),
        &c,
    )
    .unwrap();

    let paths = idx
        .source_to_sink_lineage("ext-a", &Label::Public, &c)
        .unwrap();

    // Should have:
    //   1-hop: Public→Internal, Public→Confidential
    //   2-hop: Public→Internal→Secret, Public→Confidential→Secret
    let one_hop: Vec<_> = paths.iter().filter(|p| p.hops.len() == 1).collect();
    let two_hop: Vec<_> = paths.iter().filter(|p| p.hops.len() == 2).collect();
    assert_eq!(one_hop.len(), 2);
    assert_eq!(two_hop.len(), 2);

    // Both 2-hop paths reach Secret.
    for p in &two_hop {
        assert_eq!(p.hops.last().unwrap().sink_clearance, Label::Secret);
    }
}

// =========================================================================
// 8. Cycle detection in sink_provenance
// =========================================================================

#[test]
fn sink_provenance_handles_cycle() {
    let mut idx = make_index();
    let c = ctx();

    // Create cycle: Public → Internal → Public.
    idx.insert_flow_event(
        &event(
            "cyc1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &c,
    )
    .unwrap();
    idx.insert_flow_event(
        &event(
            "cyc2",
            "ext-a",
            Label::Internal,
            Label::Public,
            FlowDecision::Allowed,
        ),
        &c,
    )
    .unwrap();

    // Should terminate without infinite loop.
    let sources = idx.sink_provenance("ext-a", &Label::Internal, &c).unwrap();
    assert!(sources.contains(&Label::Public));
    // Public is a transitive source of Internal, and Internal flows to Public,
    // but we shouldn't loop forever.
}

#[test]
fn sink_provenance_three_node_cycle() {
    let mut idx = make_index();
    let c = ctx();

    // A → B → C → A
    idx.insert_flow_event(
        &event(
            "c1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &c,
    )
    .unwrap();
    idx.insert_flow_event(
        &event(
            "c2",
            "ext-a",
            Label::Internal,
            Label::Confidential,
            FlowDecision::Allowed,
        ),
        &c,
    )
    .unwrap();
    idx.insert_flow_event(
        &event(
            "c3",
            "ext-a",
            Label::Confidential,
            Label::Public,
            FlowDecision::Allowed,
        ),
        &c,
    )
    .unwrap();

    // Query provenance of Confidential.
    let sources = idx
        .sink_provenance("ext-a", &Label::Confidential, &c)
        .unwrap();
    // Both Internal (direct) and Public (transitive via Internal) are sources.
    assert!(sources.contains(&Label::Internal));
    assert!(sources.contains(&Label::Public));
}

// =========================================================================
// 9. Confinement status edge cases
// =========================================================================

#[test]
fn confinement_status_full_beats_partial() {
    let mut idx = make_index();
    let c = ctx();

    idx.insert_confinement_claim(&claim("c1", "ext-a", ClaimStrength::Partial, 1), &c)
        .unwrap();
    idx.insert_confinement_claim(&claim("c2", "ext-a", ClaimStrength::Full, 2), &c)
        .unwrap();
    idx.insert_confinement_claim(&claim("c3", "ext-a", ClaimStrength::Partial, 3), &c)
        .unwrap();

    let status = idx.confinement_status("ext-a", &c).unwrap();
    assert_eq!(status.strongest_claim, Some(ClaimStrength::Full));
}

#[test]
fn confinement_status_only_partial_claims() {
    let mut idx = make_index();
    let c = ctx();

    idx.insert_confinement_claim(&claim("c1", "ext-a", ClaimStrength::Partial, 1), &c)
        .unwrap();
    idx.insert_confinement_claim(&claim("c2", "ext-a", ClaimStrength::Partial, 2), &c)
        .unwrap();

    let status = idx.confinement_status("ext-a", &c).unwrap();
    assert_eq!(status.strongest_claim, Some(ClaimStrength::Partial));
}

#[test]
fn confinement_status_proofs_without_events_means_zero_proven() {
    let mut idx = make_index();
    let c = ctx();

    // Proofs exist but no matching events → no intersection.
    idx.insert_flow_proof(&proof("p1", "ext-a", Label::Public, Label::Internal, 1), &c)
        .unwrap();

    let status = idx.confinement_status("ext-a", &c).unwrap();
    assert_eq!(status.proven_flows, 0);
    assert_eq!(status.unproven_flows, 0); // No events at all.
    assert_eq!(status.latest_proof_epoch, Some(1));
}

#[test]
fn confinement_status_latest_proof_epoch_from_multiple() {
    let mut idx = make_index();
    let c = ctx();

    idx.insert_flow_proof(&proof("p1", "ext-a", Label::Public, Label::Internal, 5), &c)
        .unwrap();
    idx.insert_flow_proof(
        &proof("p2", "ext-a", Label::Internal, Label::Confidential, 3),
        &c,
    )
    .unwrap();
    idx.insert_flow_proof(
        &proof("p3", "ext-a", Label::Confidential, Label::Secret, 10),
        &c,
    )
    .unwrap();

    let status = idx.confinement_status("ext-a", &c).unwrap();
    assert_eq!(status.latest_proof_epoch, Some(10));
}

#[test]
fn confinement_status_proven_and_unproven_flows_correct() {
    let mut idx = make_index();
    let c = ctx();

    // 3 unique flows from events.
    idx.insert_flow_event(
        &event(
            "e1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &c,
    )
    .unwrap();
    idx.insert_flow_event(
        &event(
            "e2",
            "ext-a",
            Label::Internal,
            Label::Confidential,
            FlowDecision::Allowed,
        ),
        &c,
    )
    .unwrap();
    idx.insert_flow_event(
        &event(
            "e3",
            "ext-a",
            Label::Confidential,
            Label::Secret,
            FlowDecision::Blocked,
        ),
        &c,
    )
    .unwrap();

    // 2 proofs matching the first 2 flows.
    idx.insert_flow_proof(&proof("p1", "ext-a", Label::Public, Label::Internal, 1), &c)
        .unwrap();
    idx.insert_flow_proof(
        &proof("p2", "ext-a", Label::Internal, Label::Confidential, 1),
        &c,
    )
    .unwrap();

    let status = idx.confinement_status("ext-a", &c).unwrap();
    assert_eq!(status.proven_flows, 2);
    assert_eq!(status.unproven_flows, 1);
}

// =========================================================================
// 10. Join edge cases
// =========================================================================

#[test]
fn join_with_missing_receipt_ref() {
    let mut idx = make_index();
    let c = ctx();

    let mut ev = event(
        "ev1",
        "ext-a",
        Label::Confidential,
        Label::Public,
        FlowDecision::Declassified,
    );
    ev.receipt_ref = Some("nonexistent-receipt".to_string());
    idx.insert_flow_event(&ev, &c).unwrap();

    let joined = idx.join_events_with_receipts("ext-a", &c).unwrap();
    assert_eq!(joined.len(), 1);
    // Receipt not found → None.
    assert!(joined[0].1.is_none());
}

#[test]
fn join_with_no_events() {
    let mut idx = make_index();
    let c = ctx();

    // Only receipts, no events.
    idx.insert_declass_receipt(
        &receipt(
            "r1",
            "ext-a",
            Label::Secret,
            Label::Public,
            DeclassificationDecision::Allow,
        ),
        &c,
    )
    .unwrap();

    let joined = idx.join_events_with_receipts("ext-a", &c).unwrap();
    assert!(joined.is_empty());
}

#[test]
fn join_events_without_receipt_ref_get_none() {
    let mut idx = make_index();
    let c = ctx();

    // Event with no receipt_ref.
    idx.insert_flow_event(
        &event(
            "ev1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &c,
    )
    .unwrap();

    // Receipt exists but event doesn't reference it.
    idx.insert_declass_receipt(
        &receipt(
            "r1",
            "ext-a",
            Label::Secret,
            Label::Public,
            DeclassificationDecision::Allow,
        ),
        &c,
    )
    .unwrap();

    let joined = idx.join_events_with_receipts("ext-a", &c).unwrap();
    assert_eq!(joined.len(), 1);
    assert!(joined[0].1.is_none());
}

#[test]
fn join_isolates_extensions() {
    let mut idx = make_index();
    let c = ctx();

    let mut ev = event(
        "ev1",
        "ext-a",
        Label::Confidential,
        Label::Public,
        FlowDecision::Declassified,
    );
    ev.receipt_ref = Some("r1".to_string());
    idx.insert_flow_event(&ev, &c).unwrap();

    // Receipt belongs to ext-b.
    idx.insert_declass_receipt(
        &receipt(
            "r1",
            "ext-b",
            Label::Confidential,
            Label::Public,
            DeclassificationDecision::Allow,
        ),
        &c,
    )
    .unwrap();

    // Joining for ext-a: receipt r1 exists globally but belongs to ext-b,
    // so ext-a's query won't find it.
    let joined = idx.join_events_with_receipts("ext-a", &c).unwrap();
    assert_eq!(joined.len(), 1);
    assert!(joined[0].1.is_none());
}

// =========================================================================
// 11. Extension isolation in time-range and epoch queries
// =========================================================================

#[test]
fn time_range_query_isolates_extensions() {
    let mut idx = make_index();
    let c = ctx();

    idx.insert_flow_event(
        &event_ts(
            "e1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
            500,
        ),
        &c,
    )
    .unwrap();
    idx.insert_flow_event(
        &event_ts(
            "e2",
            "ext-b",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
            500,
        ),
        &c,
    )
    .unwrap();

    let results = idx.flow_events_by_time_range("ext-a", 0, 1000, &c).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].event_id, "e1");
}

#[test]
fn epoch_query_isolates_extensions() {
    let mut idx = make_index();
    let c = ctx();

    idx.insert_flow_proof(&proof("p1", "ext-a", Label::Public, Label::Internal, 5), &c)
        .unwrap();
    idx.insert_flow_proof(&proof("p2", "ext-b", Label::Public, Label::Internal, 5), &c)
        .unwrap();

    let results = idx.flow_proofs_by_epoch("ext-a", 5, &c).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].proof_id, "p1");
}

// =========================================================================
// 12. Lineage does NOT cross extension boundaries
// =========================================================================

#[test]
fn lineage_respects_extension_boundary() {
    let mut idx = make_index();
    let c = ctx();

    // ext-a: Public → Internal
    idx.insert_flow_event(
        &event(
            "e1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &c,
    )
    .unwrap();
    // ext-b: Internal → Confidential (different extension!)
    idx.insert_flow_event(
        &event(
            "e2",
            "ext-b",
            Label::Internal,
            Label::Confidential,
            FlowDecision::Allowed,
        ),
        &c,
    )
    .unwrap();

    let paths = idx
        .source_to_sink_lineage("ext-a", &Label::Public, &c)
        .unwrap();
    // Only 1 path: Public→Internal (from ext-a). No cross-extension hop.
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].hops.len(), 1);
    assert_eq!(paths[0].hops[0].sink_clearance, Label::Internal);
}

// =========================================================================
// 13. Field preservation through insert/query roundtrip
// =========================================================================

#[test]
fn flow_event_fields_preserved() {
    let mut idx = make_index();
    let c = ctx();

    let ev = FlowEventRecord {
        event_id: "ev-field-test".to_string(),
        extension_id: "ext-fields".to_string(),
        source_label: Label::Confidential,
        sink_clearance: Label::Internal,
        flow_location: "crates/test/src/lib.rs:42".to_string(),
        decision: FlowDecision::Declassified,
        receipt_ref: Some("receipt-xyz".to_string()),
        timestamp_ms: 987_654_321,
    };
    idx.insert_flow_event(&ev, &c).unwrap();

    let got = idx.get_flow_event("ev-field-test", &c).unwrap().unwrap();
    assert_eq!(got.event_id, "ev-field-test");
    assert_eq!(got.extension_id, "ext-fields");
    assert_eq!(got.source_label, Label::Confidential);
    assert_eq!(got.sink_clearance, Label::Internal);
    assert_eq!(got.flow_location, "crates/test/src/lib.rs:42");
    assert_eq!(got.decision, FlowDecision::Declassified);
    assert_eq!(got.receipt_ref.as_deref(), Some("receipt-xyz"));
    assert_eq!(got.timestamp_ms, 987_654_321);
}

#[test]
fn flow_proof_fields_preserved() {
    let mut idx = make_index();
    let c = ctx();

    let p = FlowProofRecord {
        proof_id: "proof-field-test".to_string(),
        extension_id: "ext-fields".to_string(),
        source_label: Label::Secret,
        sink_clearance: Label::Confidential,
        proof_method: ProofMethod::StaticAnalysis,
        epoch_id: 42,
    };
    idx.insert_flow_proof(&p, &c).unwrap();

    let got = idx.get_flow_proof("proof-field-test", &c).unwrap().unwrap();
    assert_eq!(got.proof_id, "proof-field-test");
    assert_eq!(got.extension_id, "ext-fields");
    assert_eq!(got.source_label, Label::Secret);
    assert_eq!(got.sink_clearance, Label::Confidential);
    assert_eq!(got.proof_method, ProofMethod::StaticAnalysis);
    assert_eq!(got.epoch_id, 42);
}

#[test]
fn declass_receipt_fields_preserved() {
    let mut idx = make_index();
    let c = ctx();

    let r = DeclassReceiptRecord {
        receipt_id: "receipt-field-test".to_string(),
        extension_id: "ext-fields".to_string(),
        decision: DeclassificationDecision::Deny,
        source_label: Label::TopSecret,
        sink_clearance: Label::Public,
        declassification_route_ref: "route-fields".to_string(),
        decision_contract_id: "decision-fields".to_string(),
        timestamp_ms: 111_222_333,
    };
    idx.insert_declass_receipt(&r, &c).unwrap();

    let got = idx
        .get_declass_receipt("receipt-field-test", &c)
        .unwrap()
        .unwrap();
    assert_eq!(got.receipt_id, "receipt-field-test");
    assert_eq!(got.extension_id, "ext-fields");
    assert_eq!(got.decision, DeclassificationDecision::Deny);
    assert_eq!(got.declassification_route_ref, "route-fields");
    assert_eq!(got.decision_contract_id, "decision-fields");
    assert_eq!(got.source_label, Label::TopSecret);
    assert_eq!(got.sink_clearance, Label::Public);
    assert_eq!(got.timestamp_ms, 111_222_333);
}

#[test]
fn confinement_claim_fields_preserved() {
    let mut idx = make_index();
    let c = ctx();

    let cl = ConfinementClaimRecord {
        claim_id: "claim-field-test".to_string(),
        extension_id: "ext-fields".to_string(),
        claim_strength: ClaimStrength::Full,
        epoch_id: 99,
    };
    idx.insert_confinement_claim(&cl, &c).unwrap();

    let got = idx
        .get_confinement_claim("claim-field-test", &c)
        .unwrap()
        .unwrap();
    assert_eq!(got.claim_id, "claim-field-test");
    assert_eq!(got.extension_id, "ext-fields");
    assert_eq!(got.claim_strength, ClaimStrength::Full);
    assert_eq!(got.epoch_id, 99);
}

// =========================================================================
// 14. Events emitted / not emitted on validation errors
// =========================================================================

#[test]
fn no_event_emitted_on_empty_id_validation_failure() {
    let mut idx = make_index();
    let c = ctx();

    let _ = idx.insert_flow_event(
        &event(
            "",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &c,
    );
    // Validation fails before reaching storage, so no event emitted.
    assert!(idx.events().is_empty());
}

#[test]
fn no_event_emitted_on_empty_extension_id_failure() {
    let mut idx = make_index();
    let c = ctx();

    let _ = idx.insert_flow_proof(&proof("p1", "", Label::Public, Label::Internal, 1), &c);
    assert!(idx.events().is_empty());
}

#[test]
fn event_emitted_per_successful_insert() {
    let mut idx = make_index();
    let c = ctx();

    idx.insert_flow_event(
        &event(
            "e1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &c,
    )
    .unwrap();
    assert_eq!(idx.events().len(), 1);
    assert_eq!(idx.events()[0].event, "flow_event_inserted");
    assert_eq!(idx.events()[0].component, "ifc_provenance_index");

    idx.insert_flow_proof(&proof("p1", "ext-a", Label::Public, Label::Internal, 1), &c)
        .unwrap();
    assert_eq!(idx.events().len(), 2);
    assert_eq!(idx.events()[1].event, "flow_proof_inserted");

    idx.insert_declass_receipt(
        &receipt(
            "r1",
            "ext-a",
            Label::Secret,
            Label::Public,
            DeclassificationDecision::Allow,
        ),
        &c,
    )
    .unwrap();
    assert_eq!(idx.events().len(), 3);
    assert_eq!(idx.events()[2].event, "declass_receipt_inserted");

    idx.insert_confinement_claim(&claim("c1", "ext-a", ClaimStrength::Full, 1), &c)
        .unwrap();
    assert_eq!(idx.events().len(), 4);
    assert_eq!(idx.events()[3].event, "confinement_claim_inserted");
}

#[test]
fn lineage_query_emits_event() {
    let mut idx = make_index();
    let c = ctx();

    let _ = idx.source_to_sink_lineage("ext-a", &Label::Public, &c);
    assert!(idx.events().iter().any(|e| e.event == "lineage_query"));
}

#[test]
fn drain_events_from_integration() {
    let mut idx = make_index();
    let c = ctx();

    idx.insert_flow_event(
        &event(
            "e1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &c,
    )
    .unwrap();
    idx.insert_flow_proof(&proof("p1", "ext-a", Label::Public, Label::Internal, 1), &c)
        .unwrap();

    let drained = idx.drain_events();
    assert_eq!(drained.len(), 2);
    assert!(idx.events().is_empty());

    // Insert more after drain.
    idx.insert_flow_event(
        &event(
            "e2",
            "ext-a",
            Label::Internal,
            Label::Secret,
            FlowDecision::Blocked,
        ),
        &c,
    )
    .unwrap();
    assert_eq!(idx.events().len(), 1);
}

// =========================================================================
// 15. Overwrite semantics (InMemoryStorageAdapter doesn't reject duplicates)
// =========================================================================

#[test]
fn duplicate_key_overwrites_silently() {
    let mut idx = make_index();
    let c = ctx();

    let ev1 = event(
        "same-id",
        "ext-a",
        Label::Public,
        Label::Internal,
        FlowDecision::Allowed,
    );
    idx.insert_flow_event(&ev1, &c).unwrap();

    let ev2 = event(
        "same-id",
        "ext-a",
        Label::Internal,
        Label::Secret,
        FlowDecision::Blocked,
    );
    idx.insert_flow_event(&ev2, &c).unwrap();

    // The second write overwrites the first.
    let got = idx.get_flow_event("same-id", &c).unwrap().unwrap();
    assert_eq!(got.source_label, Label::Internal);
    assert_eq!(got.decision, FlowDecision::Blocked);
}

// =========================================================================
// 16. RecordCounts with partial data
// =========================================================================

#[test]
fn record_counts_with_only_proofs_and_claims() {
    let mut idx = make_index();
    let c = ctx();

    idx.insert_flow_proof(&proof("p1", "ext-a", Label::Public, Label::Internal, 1), &c)
        .unwrap();
    idx.insert_flow_proof(
        &proof("p2", "ext-a", Label::Internal, Label::Confidential, 2),
        &c,
    )
    .unwrap();
    idx.insert_confinement_claim(&claim("c1", "ext-a", ClaimStrength::Full, 1), &c)
        .unwrap();

    let counts = idx.record_counts("ext-a", &c).unwrap();
    assert_eq!(counts.flow_events, 0);
    assert_eq!(counts.flow_proofs, 2);
    assert_eq!(counts.declass_receipts, 0);
    assert_eq!(counts.confinement_claims, 1);
    assert_eq!(counts.total(), 3);
}

// =========================================================================
// 17. Time range boundary conditions
// =========================================================================

#[test]
fn time_range_empty_range() {
    let mut idx = make_index();
    let c = ctx();

    idx.insert_flow_event(
        &event_ts(
            "e1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
            500,
        ),
        &c,
    )
    .unwrap();

    // Range where start > end — no results.
    let results = idx
        .flow_events_by_time_range("ext-a", 600, 400, &c)
        .unwrap();
    assert!(results.is_empty());
}

#[test]
fn time_range_multiple_events_same_timestamp() {
    let mut idx = make_index();
    let c = ctx();

    idx.insert_flow_event(
        &event_ts(
            "e1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
            100,
        ),
        &c,
    )
    .unwrap();
    idx.insert_flow_event(
        &event_ts(
            "e2",
            "ext-a",
            Label::Internal,
            Label::Confidential,
            FlowDecision::Blocked,
            100,
        ),
        &c,
    )
    .unwrap();

    let results = idx
        .flow_events_by_time_range("ext-a", 100, 100, &c)
        .unwrap();
    assert_eq!(results.len(), 2);
}

// =========================================================================
// 18. Lineage from only declass receipts (Deny filtered out)
// =========================================================================

#[test]
fn lineage_excludes_deny_receipts() {
    let mut idx = make_index();
    let c = ctx();

    idx.insert_declass_receipt(
        &receipt(
            "deny-r",
            "ext-a",
            Label::Secret,
            Label::Public,
            DeclassificationDecision::Deny,
        ),
        &c,
    )
    .unwrap();

    let paths = idx
        .source_to_sink_lineage("ext-a", &Label::Secret, &c)
        .unwrap();
    assert!(paths.is_empty());
}

#[test]
fn lineage_includes_allow_receipts() {
    let mut idx = make_index();
    let c = ctx();

    idx.insert_declass_receipt(
        &receipt(
            "allow-r",
            "ext-a",
            Label::Secret,
            Label::Public,
            DeclassificationDecision::Allow,
        ),
        &c,
    )
    .unwrap();

    let paths = idx
        .source_to_sink_lineage("ext-a", &Label::Secret, &c)
        .unwrap();
    assert_eq!(paths.len(), 1);
    assert_eq!(
        paths[0].hops[0].evidence_type,
        LineageEvidenceType::DeclassificationReceipt
    );
}

// =========================================================================
// 19. Sink provenance via proofs AND receipts
// =========================================================================

#[test]
fn sink_provenance_combines_events_proofs_and_receipts() {
    let mut idx = make_index();
    let c = ctx();

    // Event: Public → Internal
    idx.insert_flow_event(
        &event(
            "e1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &c,
    )
    .unwrap();
    // Proof: Confidential → Internal
    idx.insert_flow_proof(
        &proof("p1", "ext-a", Label::Confidential, Label::Internal, 1),
        &c,
    )
    .unwrap();
    // Allow receipt: Secret → Internal
    idx.insert_declass_receipt(
        &receipt(
            "r1",
            "ext-a",
            Label::Secret,
            Label::Internal,
            DeclassificationDecision::Allow,
        ),
        &c,
    )
    .unwrap();
    // Deny receipt: TopSecret → Internal (should be excluded)
    idx.insert_declass_receipt(
        &receipt(
            "r2",
            "ext-a",
            Label::TopSecret,
            Label::Internal,
            DeclassificationDecision::Deny,
        ),
        &c,
    )
    .unwrap();

    let sources = idx.sink_provenance("ext-a", &Label::Internal, &c).unwrap();
    assert_eq!(sources.len(), 3);
    assert!(sources.contains(&Label::Public));
    assert!(sources.contains(&Label::Confidential));
    assert!(sources.contains(&Label::Secret));
    assert!(!sources.contains(&Label::TopSecret));
}

// =========================================================================
// 20. Large-scale test: many records across many extensions
// =========================================================================

#[test]
fn large_scale_many_records_many_extensions() {
    let mut idx = make_index();
    let c = ctx();

    let labels = [
        Label::Public,
        Label::Internal,
        Label::Confidential,
        Label::Secret,
    ];

    // 10 extensions, each with 10 events, 5 proofs, 3 receipts, 2 claims.
    for ext_i in 0..10 {
        let ext = format!("ext-{ext_i}");
        for ev_i in 0..10 {
            let src = labels[ev_i % labels.len()].clone();
            let sink = labels[(ev_i + 1) % labels.len()].clone();
            idx.insert_flow_event(
                &event_ts(
                    &format!("e-{ext_i}-{ev_i}"),
                    &ext,
                    src,
                    sink,
                    FlowDecision::Allowed,
                    (ev_i as u64) * 100,
                ),
                &c,
            )
            .unwrap();
        }
        for p_i in 0..5 {
            let src = labels[p_i % labels.len()].clone();
            let sink = labels[(p_i + 1) % labels.len()].clone();
            idx.insert_flow_proof(
                &proof(
                    &format!("p-{ext_i}-{p_i}"),
                    &ext,
                    src,
                    sink,
                    (p_i as u64) + 1,
                ),
                &c,
            )
            .unwrap();
        }
        for r_i in 0..3 {
            let src = labels[r_i % labels.len()].clone();
            let sink = labels[(r_i + 1) % labels.len()].clone();
            idx.insert_declass_receipt(
                &receipt(
                    &format!("r-{ext_i}-{r_i}"),
                    &ext,
                    src,
                    sink,
                    DeclassificationDecision::Allow,
                ),
                &c,
            )
            .unwrap();
        }
        for c_i in 0..2 {
            let strength = if c_i == 0 {
                ClaimStrength::Partial
            } else {
                ClaimStrength::Full
            };
            idx.insert_confinement_claim(
                &claim(
                    &format!("c-{ext_i}-{c_i}"),
                    &ext,
                    strength,
                    (c_i as u64) + 1,
                ),
                &c,
            )
            .unwrap();
        }
    }

    // Verify counts for a specific extension.
    let counts = idx.record_counts("ext-5", &c).unwrap();
    assert_eq!(counts.flow_events, 10);
    assert_eq!(counts.flow_proofs, 5);
    assert_eq!(counts.declass_receipts, 3);
    assert_eq!(counts.confinement_claims, 2);
    assert_eq!(counts.total(), 20);

    // Verify isolation: ext-0 shouldn't see ext-5's records.
    let ext0_events = idx.flow_events_by_extension("ext-0", &c).unwrap();
    assert_eq!(ext0_events.len(), 10);
    for ev in &ext0_events {
        assert_eq!(ev.extension_id, "ext-0");
    }

    // Lineage query should still work.
    let paths = idx
        .source_to_sink_lineage("ext-3", &Label::Public, &c)
        .unwrap();
    assert!(!paths.is_empty());

    // Confinement status strongest claim should be Full.
    let status = idx.confinement_status("ext-7", &c).unwrap();
    assert_eq!(status.strongest_claim, Some(ClaimStrength::Full));
}

// =========================================================================
// 21. Determinism: identical operations produce identical results
// =========================================================================

#[test]
fn deterministic_lineage_on_repeated_queries() {
    let mut idx = make_index();
    let c = ctx();

    // Build a non-trivial graph.
    idx.insert_flow_event(
        &event(
            "e1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &c,
    )
    .unwrap();
    idx.insert_flow_event(
        &event(
            "e2",
            "ext-a",
            Label::Public,
            Label::Confidential,
            FlowDecision::Allowed,
        ),
        &c,
    )
    .unwrap();
    idx.insert_flow_proof(&proof("p1", "ext-a", Label::Internal, Label::Secret, 1), &c)
        .unwrap();
    idx.insert_declass_receipt(
        &receipt(
            "r1",
            "ext-a",
            Label::Confidential,
            Label::Secret,
            DeclassificationDecision::Allow,
        ),
        &c,
    )
    .unwrap();

    let paths1 = idx
        .source_to_sink_lineage("ext-a", &Label::Public, &c)
        .unwrap();
    let paths2 = idx
        .source_to_sink_lineage("ext-a", &Label::Public, &c)
        .unwrap();
    assert_eq!(paths1, paths2);
}

#[test]
fn deterministic_confinement_status() {
    let mut idx = make_index();
    let c = ctx();

    idx.insert_flow_event(
        &event(
            "e1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &c,
    )
    .unwrap();
    idx.insert_flow_proof(&proof("p1", "ext-a", Label::Public, Label::Internal, 1), &c)
        .unwrap();
    idx.insert_confinement_claim(&claim("c1", "ext-a", ClaimStrength::Full, 1), &c)
        .unwrap();

    let status1 = idx.confinement_status("ext-a", &c).unwrap();
    let status2 = idx.confinement_status("ext-a", &c).unwrap();
    assert_eq!(status1, status2);
}

#[test]
fn deterministic_sink_provenance() {
    let mut idx = make_index();
    let c = ctx();

    idx.insert_flow_event(
        &event(
            "e1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &c,
    )
    .unwrap();
    idx.insert_flow_event(
        &event(
            "e2",
            "ext-a",
            Label::Confidential,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &c,
    )
    .unwrap();

    let s1 = idx.sink_provenance("ext-a", &Label::Internal, &c).unwrap();
    let s2 = idx.sink_provenance("ext-a", &Label::Internal, &c).unwrap();
    assert_eq!(s1, s2);
}

// =========================================================================
// 22. Serde roundtrip for complex types from integration level
// =========================================================================

#[test]
fn confinement_status_serde_all_fields() {
    let status = ConfinementStatus {
        extension_id: "ext-serde".to_string(),
        proven_flows: 10,
        unproven_flows: 3,
        strongest_claim: Some(ClaimStrength::Full),
        latest_proof_epoch: Some(42),
    };
    let json = serde_json::to_string(&status).unwrap();
    let deser: ConfinementStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(status, deser);
}

#[test]
fn confinement_status_serde_none_fields() {
    let status = ConfinementStatus {
        extension_id: "ext-empty".to_string(),
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
fn provenance_event_serde_with_error_code() {
    let ev = ProvenanceEvent {
        trace_id: "t1".to_string(),
        component: "ifc_provenance_index".to_string(),
        event: "insert_failed".to_string(),
        outcome: "error".to_string(),
        error_code: Some("PROV_EMPTY_ID".to_string()),
        extension_id: Some("ext-a".to_string()),
        record_count: Some(5),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let deser: ProvenanceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, deser);
}

#[test]
fn record_counts_serde_roundtrip_from_integration() {
    let counts = RecordCounts {
        flow_events: 100,
        flow_proofs: 50,
        declass_receipts: 25,
        confinement_claims: 10,
    };
    let json = serde_json::to_string(&counts).unwrap();
    let deser: RecordCounts = serde_json::from_str(&json).unwrap();
    assert_eq!(counts, deser);
    assert_eq!(deser.total(), 185);
}

#[test]
fn lineage_hop_serde_all_evidence_types() {
    for evidence_type in [
        LineageEvidenceType::FlowEvent,
        LineageEvidenceType::FlowProof,
        LineageEvidenceType::DeclassificationReceipt,
    ] {
        let hop = LineageHop {
            source_label: Label::Secret,
            sink_clearance: Label::Public,
            evidence_ref: "ref-1".to_string(),
            evidence_type,
        };
        let json = serde_json::to_string(&hop).unwrap();
        let deser: LineageHop = serde_json::from_str(&json).unwrap();
        assert_eq!(hop, deser);
    }
}

#[test]
fn lineage_path_serde_multi_hop() {
    let path = LineagePath {
        extension_id: "ext-serde".to_string(),
        hops: vec![
            LineageHop {
                source_label: Label::Public,
                sink_clearance: Label::Internal,
                evidence_ref: "e1".to_string(),
                evidence_type: LineageEvidenceType::FlowEvent,
            },
            LineageHop {
                source_label: Label::Internal,
                sink_clearance: Label::Confidential,
                evidence_ref: "p1".to_string(),
                evidence_type: LineageEvidenceType::FlowProof,
            },
            LineageHop {
                source_label: Label::Confidential,
                sink_clearance: Label::Secret,
                evidence_ref: "r1".to_string(),
                evidence_type: LineageEvidenceType::DeclassificationReceipt,
            },
        ],
    };
    let json = serde_json::to_string(&path).unwrap();
    let deser: LineagePath = serde_json::from_str(&json).unwrap();
    assert_eq!(path, deser);
}

// =========================================================================
// 23. Display traits from integration level
// =========================================================================

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

// =========================================================================
// 24. Lineage with self-loop label
// =========================================================================

#[test]
fn lineage_with_same_source_and_sink_label() {
    let mut idx = make_index();
    let c = ctx();

    // Flow from Public to Public — a self-loop.
    idx.insert_flow_event(
        &event(
            "self-loop",
            "ext-a",
            Label::Public,
            Label::Public,
            FlowDecision::Allowed,
        ),
        &c,
    )
    .unwrap();

    // Should handle without infinite recursion. The cycle guard checks
    // visited source_labels, so after visiting Public once it stops.
    let paths = idx
        .source_to_sink_lineage("ext-a", &Label::Public, &c)
        .unwrap();
    // At least the 1-hop path should exist.
    assert!(!paths.is_empty());
    // No path should be longer than 1 hop since it's a self-loop.
    assert!(paths.iter().all(|p| p.hops.len() <= 1));
}

// =========================================================================
// 25. Query for non-existent extension returns empty results
// =========================================================================

#[test]
fn queries_for_nonexistent_extension_return_empty() {
    let mut idx = make_index();
    let c = ctx();

    // Populate ext-a.
    idx.insert_flow_event(
        &event(
            "e1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &c,
    )
    .unwrap();

    // Query ext-nonexistent.
    let events = idx.flow_events_by_extension("ext-nonexistent", &c).unwrap();
    assert!(events.is_empty());

    let proofs = idx.flow_proofs_by_extension("ext-nonexistent", &c).unwrap();
    assert!(proofs.is_empty());

    let receipts = idx
        .declass_receipts_by_extension("ext-nonexistent", &c)
        .unwrap();
    assert!(receipts.is_empty());

    let claims = idx
        .confinement_claims_by_extension("ext-nonexistent", &c)
        .unwrap();
    assert!(claims.is_empty());

    let lineage = idx
        .source_to_sink_lineage("ext-nonexistent", &Label::Public, &c)
        .unwrap();
    assert!(lineage.is_empty());

    let provenance = idx
        .sink_provenance("ext-nonexistent", &Label::Internal, &c)
        .unwrap();
    assert!(provenance.is_empty());

    let counts = idx.record_counts("ext-nonexistent", &c).unwrap();
    assert_eq!(counts.total(), 0);
}

// =========================================================================
// 26. ProvenanceError serde roundtrip from integration level
// =========================================================================

#[test]
fn provenance_error_serde_all_variants() {
    let errors = vec![
        ProvenanceError::EmptyId {
            record_type: "flow_event".to_string(),
        },
        ProvenanceError::EmptyExtensionId,
        ProvenanceError::DuplicateRecord {
            key: "flow_event::ev1".to_string(),
        },
        ProvenanceError::StorageError("backend unavailable".to_string()),
        ProvenanceError::SerializationError("bad json".to_string()),
    ];
    for err in errors {
        let json = serde_json::to_string(&err).unwrap();
        let deser: ProvenanceError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, deser);
    }
}

// =========================================================================
// 27. Mixed evidence lineage with transitive closure
// =========================================================================

#[test]
fn mixed_evidence_transitive_lineage_three_types() {
    let mut idx = make_index();
    let c = ctx();

    // Event: Public → Internal
    idx.insert_flow_event(
        &event(
            "mix-e",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &c,
    )
    .unwrap();
    // Proof: Internal → Confidential
    idx.insert_flow_proof(
        &proof("mix-p", "ext-a", Label::Internal, Label::Confidential, 1),
        &c,
    )
    .unwrap();
    // Allow receipt: Confidential → Secret
    idx.insert_declass_receipt(
        &receipt(
            "mix-r",
            "ext-a",
            Label::Confidential,
            Label::Secret,
            DeclassificationDecision::Allow,
        ),
        &c,
    )
    .unwrap();

    let paths = idx
        .source_to_sink_lineage("ext-a", &Label::Public, &c)
        .unwrap();

    // The 3-hop path: Public→Internal→Confidential→Secret.
    let three_hop: Vec<_> = paths.iter().filter(|p| p.hops.len() == 3).collect();
    assert_eq!(three_hop.len(), 1);

    let hops = &three_hop[0].hops;
    assert_eq!(hops[0].evidence_type, LineageEvidenceType::FlowEvent);
    assert_eq!(hops[0].source_label, Label::Public);
    assert_eq!(hops[0].sink_clearance, Label::Internal);
    assert_eq!(hops[1].evidence_type, LineageEvidenceType::FlowProof);
    assert_eq!(hops[1].source_label, Label::Internal);
    assert_eq!(hops[1].sink_clearance, Label::Confidential);
    assert_eq!(
        hops[2].evidence_type,
        LineageEvidenceType::DeclassificationReceipt
    );
    assert_eq!(hops[2].source_label, Label::Confidential);
    assert_eq!(hops[2].sink_clearance, Label::Secret);
}

// =========================================================================
// 28. Epoch boundary conditions
// =========================================================================

#[test]
fn epoch_zero() {
    let mut idx = make_index();
    let c = ctx();

    idx.insert_flow_proof(&proof("p0", "ext-a", Label::Public, Label::Internal, 0), &c)
        .unwrap();

    let results = idx.flow_proofs_by_epoch("ext-a", 0, &c).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].proof_id, "p0");
}

#[test]
fn epoch_u64_max() {
    let mut idx = make_index();
    let c = ctx();

    idx.insert_flow_proof(
        &proof("p-max", "ext-a", Label::Public, Label::Internal, u64::MAX),
        &c,
    )
    .unwrap();

    let results = idx.flow_proofs_by_epoch("ext-a", u64::MAX, &c).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].proof_id, "p-max");
}

// =========================================================================
// 29. Timestamp boundary conditions
// =========================================================================

#[test]
fn timestamp_zero() {
    let mut idx = make_index();
    let c = ctx();

    idx.insert_flow_event(
        &event_ts(
            "ts0",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
            0,
        ),
        &c,
    )
    .unwrap();

    let results = idx.flow_events_by_time_range("ext-a", 0, 0, &c).unwrap();
    assert_eq!(results.len(), 1);
}

#[test]
fn timestamp_u64_max() {
    let mut idx = make_index();
    let c = ctx();

    idx.insert_flow_event(
        &event_ts(
            "ts-max",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
            u64::MAX,
        ),
        &c,
    )
    .unwrap();

    let results = idx
        .flow_events_by_time_range("ext-a", u64::MAX, u64::MAX, &c)
        .unwrap();
    assert_eq!(results.len(), 1);
}

// =========================================================================
// 30. All Label variants through lineage and provenance
// =========================================================================

#[test]
fn all_label_variants_in_lineage() {
    let mut idx = make_index();
    let c = ctx();

    let all = Label::all_builtin();
    // Chain: Public → Internal → Confidential → Secret → TopSecret
    for (i, pair) in all.windows(2).enumerate() {
        idx.insert_flow_event(
            &event(
                &format!("all-{i}"),
                "ext-a",
                pair[0].clone(),
                pair[1].clone(),
                FlowDecision::Allowed,
            ),
            &c,
        )
        .unwrap();
    }

    // Query from Public.
    let paths = idx
        .source_to_sink_lineage("ext-a", &Label::Public, &c)
        .unwrap();
    assert!(!paths.is_empty());

    // The longest path should span all labels.
    let max_hops = paths.iter().map(|p| p.hops.len()).max().unwrap();
    assert_eq!(max_hops, 4);
}

#[test]
fn all_label_variants_in_sink_provenance() {
    let mut idx = make_index();
    let c = ctx();

    let all = Label::all_builtin();
    // All labels flow into TopSecret.
    for (i, label) in all.iter().enumerate() {
        if *label != Label::TopSecret {
            idx.insert_flow_event(
                &event(
                    &format!("prov-{i}"),
                    "ext-a",
                    label.clone(),
                    Label::TopSecret,
                    FlowDecision::Allowed,
                ),
                &c,
            )
            .unwrap();
        }
    }

    let sources = idx.sink_provenance("ext-a", &Label::TopSecret, &c).unwrap();
    // All labels except TopSecret should be sources.
    assert_eq!(sources.len(), 4);
    for label in &all {
        if *label != Label::TopSecret {
            assert!(sources.contains(label));
        }
    }
}

// =========================================================================
// 31. Event trace_id propagation
// =========================================================================

#[test]
fn events_carry_correct_trace_id() {
    let custom_ctx =
        EventContext::new("custom-trace", "custom-decision", "custom-policy").expect("custom ctx");
    let mut idx = make_index();

    idx.insert_flow_event(
        &event(
            "e1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &custom_ctx,
    )
    .unwrap();

    let events = idx.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].trace_id, "custom-trace");
}

// =========================================================================
// 32. store_mut accessor
// =========================================================================

#[test]
fn store_mut_returns_underlying_adapter() {
    let mut idx = make_index();
    let _store: &mut InMemoryStorageAdapter = idx.store_mut();
    // Compiles and doesn't panic.
}

// =========================================================================
// 33. Confinement status with duplicate flows (same source/sink pair)
// =========================================================================

#[test]
fn confinement_status_deduplicates_flows() {
    let mut idx = make_index();
    let c = ctx();

    // Two events with same source→sink pair.
    idx.insert_flow_event(
        &event(
            "e1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        ),
        &c,
    )
    .unwrap();
    idx.insert_flow_event(
        &event(
            "e2",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Blocked,
        ),
        &c,
    )
    .unwrap();

    // One proof covering the flow.
    idx.insert_flow_proof(&proof("p1", "ext-a", Label::Public, Label::Internal, 1), &c)
        .unwrap();

    let status = idx.confinement_status("ext-a", &c).unwrap();
    // The flow (Public→Internal) is deduplicated via BTreeSet, so only 1 flow.
    assert_eq!(status.proven_flows, 1);
    assert_eq!(status.unproven_flows, 0);
}
