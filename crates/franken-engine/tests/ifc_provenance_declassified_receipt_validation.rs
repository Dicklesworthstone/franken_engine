#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use frankenengine_engine::ifc_artifacts::{DeclassificationDecision, Label};
use frankenengine_engine::ifc_provenance_index::{
    DeclassReceiptRecord, FlowDecision, FlowEventRecord, IfcProvenanceIndex, ProvenanceError,
    error_code,
};
use frankenengine_engine::storage_adapter::{
    EventContext, InMemoryStorageAdapter, StorageAdapter, StoreKind,
};

fn ctx() -> EventContext {
    EventContext::new(
        "trace-ifc-receipt",
        "decision-ifc-receipt",
        "policy-ifc-receipt",
    )
    .expect("valid test context")
}

fn make_index() -> IfcProvenanceIndex<InMemoryStorageAdapter> {
    IfcProvenanceIndex::new(InMemoryStorageAdapter::new())
}

fn declassified_event(event_id: &str, receipt_ref: &str) -> FlowEventRecord {
    FlowEventRecord {
        event_id: event_id.to_string(),
        extension_id: "ext-a".to_string(),
        source_label: Label::Confidential,
        sink_clearance: Label::Public,
        flow_location: "src/ext_a.rs:42".to_string(),
        decision: FlowDecision::Declassified,
        receipt_ref: Some(receipt_ref.to_string()),
        timestamp_ms: 1_700_000_000_000,
    }
}

fn receipt(
    receipt_id: &str,
    extension_id: &str,
    decision: DeclassificationDecision,
    source_label: Label,
    sink_clearance: Label,
) -> DeclassReceiptRecord {
    DeclassReceiptRecord {
        receipt_id: receipt_id.to_string(),
        extension_id: extension_id.to_string(),
        decision,
        source_label,
        sink_clearance,
        declassification_route_ref: format!("route-{receipt_id}"),
        decision_contract_id: format!("decision-{receipt_id}"),
        timestamp_ms: 1_700_000_000_010,
    }
}

fn put_raw_flow_event(
    idx: &mut IfcProvenanceIndex<InMemoryStorageAdapter>,
    event: &FlowEventRecord,
    ctx: &EventContext,
) {
    idx.store_mut()
        .put(
            StoreKind::IfcProvenance,
            format!("flow_event::{}", event.event_id),
            serde_json::to_vec(event).expect("event json"),
            BTreeMap::new(),
            ctx,
        )
        .expect("raw event insert");
}

fn put_raw_receipt_bytes(
    idx: &mut IfcProvenanceIndex<InMemoryStorageAdapter>,
    receipt_id: &str,
    bytes: &[u8],
    ctx: &EventContext,
) {
    idx.store_mut()
        .put(
            StoreKind::IfcProvenance,
            format!("declass_receipt::{receipt_id}"),
            bytes.to_vec(),
            BTreeMap::new(),
            ctx,
        )
        .expect("raw receipt insert");
}

#[test]
fn declassified_flow_event_rejects_missing_receipt() {
    let mut idx = make_index();
    let ctx = ctx();
    let event = declassified_event("ev-missing", "receipt-missing");

    let err = idx.insert_flow_event(&event, &ctx).unwrap_err();

    assert_eq!(error_code(&err), "PROV_MISSING_DECLASS_RECEIPT");
    assert!(matches!(
        err,
        ProvenanceError::MissingDeclassificationReceipt { event_id, receipt_ref }
            if event_id == "ev-missing" && receipt_ref == "receipt-missing"
    ));
    assert!(idx.get_flow_event("ev-missing", &ctx).unwrap().is_none());
}

#[test]
fn declassified_flow_event_rejects_cross_extension_receipt() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.insert_declass_receipt(
        &receipt(
            "receipt-cross-ext",
            "ext-b",
            DeclassificationDecision::Allow,
            Label::Confidential,
            Label::Public,
        ),
        &ctx,
    )
    .expect("receipt insert");
    let event = declassified_event("ev-cross-ext", "receipt-cross-ext");

    let err = idx.insert_flow_event(&event, &ctx).unwrap_err();

    assert_eq!(error_code(&err), "PROV_INVALID_DECLASS_RECEIPT");
    assert!(matches!(
        err,
        ProvenanceError::InvalidDeclassificationReceipt { reason, .. }
            if reason.contains("extension_id")
    ));
}

#[test]
fn declassified_flow_event_rejects_deny_receipt() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.insert_declass_receipt(
        &receipt(
            "receipt-deny",
            "ext-a",
            DeclassificationDecision::Deny,
            Label::Confidential,
            Label::Public,
        ),
        &ctx,
    )
    .expect("receipt insert");
    let event = declassified_event("ev-deny", "receipt-deny");

    let err = idx.insert_flow_event(&event, &ctx).unwrap_err();

    assert_eq!(error_code(&err), "PROV_INVALID_DECLASS_RECEIPT");
    assert!(matches!(
        err,
        ProvenanceError::InvalidDeclassificationReceipt { reason, .. }
            if reason.contains("not Allow")
    ));
}

#[test]
fn declassified_flow_event_rejects_label_mismatch_receipt() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.insert_declass_receipt(
        &receipt(
            "receipt-label-mismatch",
            "ext-a",
            DeclassificationDecision::Allow,
            Label::Internal,
            Label::Public,
        ),
        &ctx,
    )
    .expect("receipt insert");
    let event = declassified_event("ev-label-mismatch", "receipt-label-mismatch");

    let err = idx.insert_flow_event(&event, &ctx).unwrap_err();

    assert_eq!(error_code(&err), "PROV_INVALID_DECLASS_RECEIPT");
    assert!(matches!(
        err,
        ProvenanceError::InvalidDeclassificationReceipt { reason, .. }
            if reason.contains("source_label")
    ));
}

#[test]
fn declassified_flow_event_accepts_matching_allow_receipt() {
    let mut idx = make_index();
    let ctx = ctx();
    idx.insert_declass_receipt(
        &receipt(
            "receipt-ok",
            "ext-a",
            DeclassificationDecision::Allow,
            Label::Confidential,
            Label::Public,
        ),
        &ctx,
    )
    .expect("receipt insert");
    let mut event = declassified_event("ev-ok", "  receipt-ok  ");

    idx.insert_flow_event(&event, &ctx)
        .expect("matching receipt should authorize declassified event");
    event.receipt_ref = Some("receipt-ok".to_string());

    let joined = idx
        .join_events_with_receipts("ext-a", &ctx)
        .expect("join should succeed");
    assert_eq!(
        joined,
        vec![(
            event,
            Some(receipt(
                "receipt-ok",
                "ext-a",
                DeclassificationDecision::Allow,
                Label::Confidential,
                Label::Public,
            ))
        )]
    );
}

#[test]
fn join_events_with_receipts_rejects_legacy_dangling_declassified_event() {
    let mut idx = make_index();
    let ctx = ctx();
    put_raw_flow_event(
        &mut idx,
        &declassified_event("ev-legacy-dangling", "receipt-absent"),
        &ctx,
    );

    let err = idx.join_events_with_receipts("ext-a", &ctx).unwrap_err();

    assert_eq!(error_code(&err), "PROV_MISSING_DECLASS_RECEIPT");
    assert!(matches!(
        err,
        ProvenanceError::MissingDeclassificationReceipt { event_id, receipt_ref }
            if event_id == "ev-legacy-dangling" && receipt_ref == "receipt-absent"
    ));
}

#[test]
fn lineage_queries_reject_legacy_dangling_declassified_event() {
    let mut idx = make_index();
    let ctx = ctx();
    put_raw_flow_event(
        &mut idx,
        &declassified_event("ev-lineage-dangling", "receipt-absent"),
        &ctx,
    );

    let err = idx
        .source_to_sink_lineage("ext-a", &Label::Confidential, &ctx)
        .unwrap_err();

    assert_eq!(error_code(&err), "PROV_MISSING_DECLASS_RECEIPT");
    assert!(matches!(
        err,
        ProvenanceError::MissingDeclassificationReceipt { event_id, receipt_ref }
            if event_id == "ev-lineage-dangling" && receipt_ref == "receipt-absent"
    ));
}

#[test]
fn join_events_with_receipts_rejects_corrupt_referenced_receipt_record() {
    let mut idx = make_index();
    let ctx = ctx();
    put_raw_flow_event(
        &mut idx,
        &declassified_event("ev-corrupt-receipt", "receipt-corrupt"),
        &ctx,
    );
    put_raw_receipt_bytes(
        &mut idx,
        "receipt-corrupt",
        b"{not valid receipt json",
        &ctx,
    );

    let err = idx.join_events_with_receipts("ext-a", &ctx).unwrap_err();

    assert_eq!(error_code(&err), "PROV_SERIALIZATION_ERROR");
    assert!(matches!(err, ProvenanceError::SerializationError(_)));
}
