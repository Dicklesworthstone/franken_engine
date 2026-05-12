use frankenengine_engine::engine_object_id::{ObjectDomain, SchemaId, derive_id};
use frankenengine_engine::governance_hooks::{
    AuditExportFormat, AuditExportRequest, AuditExportResult, EvidenceEntry, export_audit_evidence,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use std::collections::BTreeMap;

/// Helper to create a test evidence entry
fn create_test_evidence_entry(
    id: &str,
    kind: &str,
    summary: &str,
    timestamp_seconds: u64,
) -> EvidenceEntry {
    // Create a dummy schema for the object ID
    let schema_id = SchemaId::from_definition(b"test-evidence-schema");
    let entry_id = derive_id(
        ObjectDomain::EvidenceRecord,
        id,
        &schema_id,
        format!("evidence-{}", id).as_bytes(),
    )
    .expect("Failed to derive EngineObjectId");

    EvidenceEntry {
        entry_id,
        kind: kind.to_string(),
        timestamp: DeterministicTimestamp(timestamp_seconds),
        summary: summary.to_string(),
        attributes: BTreeMap::new(),
        evidence_hash: ContentHash::compute(format!("evidence-{}", id).as_bytes()),
    }
}

/// Helper to create an audit export request for CompliancePdf format
fn create_pdf_export_request() -> AuditExportRequest {
    AuditExportRequest {
        format: AuditExportFormat::CompliancePdf,
        start_tick: DeterministicTimestamp(0),
        end_tick: DeterministicTimestamp(u64::MAX),
        evidence_kinds: None,
        max_entries: None,
        requester: "test_suite".to_string(),
        correlation_id: Some("test-correlation-001".to_string()),
    }
}

/// Helper function to test PDF export with given entries
fn test_pdf_export_with_entries(
    entries: Vec<EvidenceEntry>,
) -> Result<AuditExportResult, frankenengine_engine::governance_hooks::GovernanceError> {
    let request = create_pdf_export_request();
    let now = DeterministicTimestamp(1640995200); // 2022-01-01
    export_audit_evidence(request, entries, now)
}

fn assert_real_pdf_payload(payload: &[u8]) {
    assert!(
        payload.starts_with(b"%PDF-1.4"),
        "PDF output must start with a real PDF header"
    );
    assert!(
        payload.ends_with(b"%%EOF"),
        "PDF output must end with an EOF marker"
    );

    let output = String::from_utf8_lossy(payload);
    for required in [
        "/Type /Catalog",
        "/Type /Pages",
        "/Type /Page",
        "/Type /Font",
        "xref",
        "trailer",
        "startxref",
    ] {
        assert!(
            output.contains(required),
            "PDF output should contain {required}: {output}"
        );
    }
    assert!(
        !output.contains("FRANKEN_COMPLIANCE_REPORT_V1"),
        "PDF output must not contain the old fake report marker: {output}"
    );
}

#[test]
fn test_pdf_compliance_export_generates_real_pdf() {
    // Create a simple evidence entry
    let entry = create_test_evidence_entry(
        "test-001",
        "access_control",
        "User authentication logged",
        1640995200, // 2022-01-01 00:00:00 UTC
    );

    let entries = vec![entry];

    let output = test_pdf_export_with_entries(entries)
        .expect("CompliancePdf export should generate a real PDF");

    assert_eq!(output.format, AuditExportFormat::CompliancePdf);
    assert_eq!(output.format.file_extension(), "pdf");
    assert_real_pdf_payload(&output.payload_bytes);

    let output_text = String::from_utf8_lossy(&output.payload_bytes);
    assert!(output_text.contains("access_control"));
    assert!(output_text.contains("User authentication logged"));
}

#[test]
fn test_pdf_export_is_deterministic() {
    // Test that the generated PDF is deterministic across multiple calls
    let entry1 = create_test_evidence_entry(
        "det-001",
        "compliance_check",
        "Policy validation passed",
        1640995200,
    );
    let entry2 =
        create_test_evidence_entry("det-002", "audit_log", "System access recorded", 1640995260);

    let entries_clone1 = vec![entry1.clone(), entry2.clone()];
    let entries_clone2 = vec![entry1.clone(), entry2.clone()];
    let entries_clone3 = vec![entry1, entry2];

    // Call export multiple times
    let result1 = test_pdf_export_with_entries(entries_clone1).expect("first PDF export succeeds");
    let result2 = test_pdf_export_with_entries(entries_clone2).expect("second PDF export succeeds");
    let result3 = test_pdf_export_with_entries(entries_clone3).expect("third PDF export succeeds");

    assert_eq!(
        result1.payload_bytes, result2.payload_bytes,
        "PDF output should be deterministic"
    );
    assert_eq!(
        result2.payload_bytes, result3.payload_bytes,
        "PDF output should be deterministic"
    );
}

#[test]
fn test_pdf_export_with_empty_entries_generates_valid_pdf() {
    // Even empty compliance exports should produce a structurally valid report.
    let entries: Vec<EvidenceEntry> = vec![];

    let output = test_pdf_export_with_entries(entries)
        .expect("CompliancePdf export should succeed with empty entries");

    assert_real_pdf_payload(&output.payload_bytes);
}

#[test]
fn test_pdf_export_with_large_entries_embeds_content() {
    // Test with multiple entries to ensure PDF generation is independent of entry count.
    let entries: Vec<EvidenceEntry> = (0..10)
        .map(|i| {
            create_test_evidence_entry(
                &format!("large-{:03}", i),
                "data_processing",
                &format!("Processed batch {}", i),
                1640995200 + i * 60, // One minute apart
            )
        })
        .collect();

    let output = test_pdf_export_with_entries(entries)
        .expect("CompliancePdf export should succeed regardless of entry count");

    assert_real_pdf_payload(&output.payload_bytes);
    let output_text = String::from_utf8_lossy(&output.payload_bytes);
    assert!(output_text.contains("data_processing"));
    assert!(output_text.contains("Processed batch 0"));
    assert!(output_text.contains("Processed batch 9"));
}

#[test]
fn test_other_formats_still_work() {
    // Verify that other export formats are not affected by the PDF change
    let entry = create_test_evidence_entry(
        "other-001",
        "verification",
        "Format compatibility test",
        1640995200,
    );

    let entries = vec![entry.clone()];
    let now = DeterministicTimestamp(1640995200);

    // JsonLines should work
    let json_request = AuditExportRequest {
        format: AuditExportFormat::JsonLines,
        start_tick: DeterministicTimestamp(0),
        end_tick: DeterministicTimestamp(u64::MAX),
        evidence_kinds: None,
        max_entries: None,
        requester: "test_suite".to_string(),
        correlation_id: Some("test-json".to_string()),
    };
    let json_result = export_audit_evidence(json_request, entries.clone(), now);
    assert!(
        json_result.is_ok(),
        "JsonLines format should still work: {:?}",
        json_result.err()
    );
    let json_output = json_result.unwrap().payload_bytes;
    assert!(
        !json_output.is_empty(),
        "JsonLines output should not be empty"
    );

    // CSV should work
    let csv_request = AuditExportRequest {
        format: AuditExportFormat::Csv,
        start_tick: DeterministicTimestamp(0),
        end_tick: DeterministicTimestamp(u64::MAX),
        evidence_kinds: None,
        max_entries: None,
        requester: "test_suite".to_string(),
        correlation_id: Some("test-csv".to_string()),
    };
    let csv_result = export_audit_evidence(csv_request, entries, now);
    assert!(
        csv_result.is_ok(),
        "Csv format should still work: {:?}",
        csv_result.err()
    );
    let csv_output = csv_result.unwrap().payload_bytes;
    assert!(!csv_output.is_empty(), "CSV output should not be empty");
    assert!(
        csv_output.starts_with(b"entry_id,kind,timestamp,summary,evidence_hash\n"),
        "CSV output should have proper header"
    );
}

#[test]
fn test_pdf_contains_required_content_and_metadata() {
    // Test that the PDF content provides sufficient information for users.
    let entry = create_test_evidence_entry(
        "msg-001",
        "message_test",
        "Error message content verification",
        1640995200,
    );

    let entries = vec![entry];
    let output = test_pdf_export_with_entries(entries)
        .expect("CompliancePdf export should generate a real PDF");

    assert_eq!(output.format, AuditExportFormat::CompliancePdf);
    assert_eq!(output.request.format.file_extension(), "pdf");
    assert_real_pdf_payload(&output.payload_bytes);

    let output_text = String::from_utf8_lossy(&output.payload_bytes);
    assert!(output_text.contains("message_test"));
    assert!(output_text.contains("Error message content verification"));
}

#[test]
fn test_compliance_pdf_vs_fake_pdf_behavior() {
    // This test documents the old fake report marker to ensure real PDF output
    // never regresses to FRANKEN_COMPLIANCE_REPORT_V1 text content.
    let entry = create_test_evidence_entry(
        "behavior-001",
        "behavioral_test",
        "Old vs new behavior validation",
        1640995200,
    );

    let entries = vec![entry];
    let output = test_pdf_export_with_entries(entries)
        .expect("CompliancePdf export should generate real PDF content");

    assert_real_pdf_payload(&output.payload_bytes);
    let output_text = String::from_utf8_lossy(&output.payload_bytes);
    assert!(output_text.contains("behavioral_test"));
    assert!(output_text.contains("Old vs new behavior validation"));
}
