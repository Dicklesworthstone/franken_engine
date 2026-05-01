use std::fs;

use frankenengine_engine::live_revocation_first_gate_example::{
    BEAD_ID, COMPONENT, DECISION_ID, GRANTED_CAPABILITY, LIVE_REVOCATION_FIRST_GATE_SCHEMA_VERSION,
    LIVE_REVOCATION_RECEIPT_SCHEMA_VERSION, run_live_revocation_first_gate_example,
    write_live_revocation_first_gate_artifacts,
};
use serde_json::Value;

#[test]
fn live_revocation_first_gate_denies_after_revoke_and_verifies_receipts() {
    let execution = run_live_revocation_first_gate_example().expect("live example should run");

    assert_eq!(
        execution.report.schema_version,
        LIVE_REVOCATION_FIRST_GATE_SCHEMA_VERSION
    );
    assert_eq!(execution.report.component, COMPONENT);
    assert_eq!(execution.report.bead_id, BEAD_ID);
    assert_eq!(execution.report.decision_request.request_id, DECISION_ID);
    assert_eq!(
        execution.report.decision_request.requested_capability,
        GRANTED_CAPABILITY
    );
    assert_eq!(execution.report.decision, "deny");
    assert_eq!(execution.report.denial_reason, "revoked_capability_witness");
    assert_eq!(execution.report.active_query_count_after_revocation, 0);
    assert_eq!(execution.report.revoked_query_count_after_revocation, 1);
    assert!(execution.report.signed_receipts_verified);

    assert_eq!(
        execution.publication_receipt.schema_version,
        LIVE_REVOCATION_RECEIPT_SCHEMA_VERSION
    );
    assert_eq!(execution.publication_receipt.receipt_kind, "publication");
    assert_eq!(execution.revocation_receipt.receipt_kind, "revocation");
    assert_eq!(
        execution.revocation_receipt.revocation_reason.as_deref(),
        Some("synthetic compromise receipt: revoked before decision")
    );
    assert_eq!(execution.publication_receipt.log_sequence, 0);
    assert_eq!(execution.revocation_receipt.log_sequence, 1);
    assert_eq!(
        execution.publication_receipt.tree_head_signature_hex.len(),
        128
    );
    assert_eq!(
        execution.revocation_receipt.tree_head_signature_hex.len(),
        128
    );

    let decision_event = execution
        .events
        .iter()
        .find(|event| event.step_id == "decision")
        .expect("decision event should be emitted");
    assert_eq!(decision_event.decision, "deny");
    assert_eq!(decision_event.reason, "revoked_capability_witness");
}

#[test]
fn live_revocation_first_gate_writes_bundle_inputs_for_manifest_contract() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let report =
        write_live_revocation_first_gate_artifacts(temp_dir.path()).expect("bundle inputs");

    let source_report_path = temp_dir.path().join("source_report.json");
    let events_path = temp_dir.path().join("events.jsonl");
    let publication_receipt_path = temp_dir.path().join("receipts/publication_receipt.json");
    let revocation_receipt_path = temp_dir.path().join("receipts/revocation_receipt.json");

    assert!(source_report_path.is_file());
    assert!(events_path.is_file());
    assert!(publication_receipt_path.is_file());
    assert!(revocation_receipt_path.is_file());
    assert_eq!(report.receipt_artifacts.len(), 2);
    assert!(
        report
            .receipt_artifacts
            .iter()
            .all(|artifact| artifact.sha256.starts_with("sha256:"))
    );

    let source_report: Value =
        serde_json::from_slice(&fs::read(source_report_path).expect("read source report"))
            .expect("source report json");
    assert_eq!(source_report["decision"], "deny");
    assert_eq!(source_report["signed_receipts_verified"], true);

    let events = fs::read_to_string(events_path).expect("read events");
    let event_lines = events.lines().collect::<Vec<_>>();
    assert_eq!(event_lines.len(), 3);
    for line in event_lines {
        let event: Value = serde_json::from_str(line).expect("event json");
        assert_eq!(
            event["schema_version"],
            "franken-engine.proof-artifact-event.v1"
        );
        assert!(event["artifact_sha256"].as_str().is_some_and(|hash| {
            hash.starts_with("sha256:") && hash.len() == "sha256:".len() + 64
        }));
    }

    let revocation_receipt: Value = serde_json::from_slice(
        &fs::read(revocation_receipt_path).expect("read revocation receipt"),
    )
    .expect("revocation receipt json");
    assert_eq!(revocation_receipt["receipt_kind"], "revocation");
    assert_eq!(
        revocation_receipt["revocation_reason"],
        "synthetic compromise receipt: revoked before decision"
    );
}
