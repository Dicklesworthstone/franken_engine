use frankenengine_engine::governance_hooks::{
    export_audit_evidence, AuditExportFormat, AuditExportRequest, EvidenceEntry, GovernanceError,
};
use frankenengine_engine::content_hash::ContentHash;
use frankenengine_engine::deterministic_timestamp::DeterministicTimestamp;
use frankenengine_engine::engine_object_id::{EngineObjectId, ObjectDomain};
use frankenengine_engine::schema_id::SchemaId;
use std::collections::{BTreeMap, BTreeSet};

/// Helper to create a test evidence entry
fn create_test_evidence_entry(
    id: &str,
    kind: &str,
    summary: &str,
    timestamp_seconds: u64,
) -> EvidenceEntry {
    // Create a dummy schema for the object ID
    let schema_id = SchemaId::from_definition(b"test-evidence-schema");
    let entry_id = EngineObjectId::derive(
        ObjectDomain::EvidenceRecord,
        id,
        &schema_id,
        format!("evidence-{}", id).as_bytes(),
    ).expect("Failed to derive EngineObjectId");

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
fn test_pdf_export_with_entries(entries: Vec<EvidenceEntry>) -> Result<(), GovernanceError> {
    let request = create_pdf_export_request();
    let now = DeterministicTimestamp(1640995200); // 2022-01-01

    match export_audit_evidence(request, entries, now) {
        Ok(_) => Ok(()), // Unexpected success
        Err(err) => Err(err),
    }
}

#[test]
fn test_pdf_compliance_export_returns_not_implemented_error() {
    // Create a simple evidence entry
    let entry = create_test_evidence_entry(
        "test-001",
        "access_control",
        "User authentication logged",
        1640995200, // 2022-01-01 00:00:00 UTC
    );

    let entries = vec![entry];

    // Attempt to export as CompliancePdf - should fail with ExportError
    let result = test_pdf_export_with_entries(entries);

    assert!(result.is_err(), "CompliancePdf export should return an error");

    match result.unwrap_err() {
        GovernanceError::ExportError { message } => {
            assert!(
                message.contains("CompliancePdf format is not yet implemented"),
                "Error message should indicate PDF format is not implemented, got: {}",
                message
            );
            assert!(
                message.contains("Real PDF generation requires external PDF library"),
                "Error message should mention PDF library requirement, got: {}",
                message
            );
            assert!(
                message.contains("Use JsonLines or Csv formats as alternatives"),
                "Error message should suggest alternatives, got: {}",
                message
            );
        }
        other => panic!(
            "Expected ExportError variant, got: {:?}",
            other
        ),
    }
}

#[test]
fn test_pdf_export_error_deterministic() {
    // Test that the error is deterministic across multiple calls
    let entry1 = create_test_evidence_entry(
        "det-001",
        "compliance_check",
        "Policy validation passed",
        1640995200
    );
    let entry2 = create_test_evidence_entry(
        "det-002",
        "audit_log",
        "System access recorded",
        1640995260
    );

    let entries_clone1 = vec![entry1.clone(), entry2.clone()];
    let entries_clone2 = vec![entry1.clone(), entry2.clone()];
    let entries_clone3 = vec![entry1, entry2];

    // Call export multiple times
    let result1 = test_pdf_export_with_entries(entries_clone1);
    let result2 = test_pdf_export_with_entries(entries_clone2);
    let result3 = test_pdf_export_with_entries(entries_clone3);

    // All should return the same error
    assert!(result1.is_err());
    assert!(result2.is_err());
    assert!(result3.is_err());

    // Extract error messages
    let error1 = result1.unwrap_err();
    let error2 = result2.unwrap_err();
    let error3 = result3.unwrap_err();

    assert_eq!(error1, error2, "Error should be deterministic");
    assert_eq!(error2, error3, "Error should be deterministic");
}

#[test]
fn test_pdf_export_error_with_empty_entries() {
    // Test that even with empty entries, we still get the not implemented error
    let entries: Vec<EvidenceEntry> = vec![];

    let result = test_pdf_export_with_entries(entries);

    assert!(
        result.is_err(),
        "CompliancePdf export should fail even with empty entries"
    );

    match result.unwrap_err() {
        GovernanceError::ExportError { .. } => {
            // Expected error type
        }
        other => panic!(
            "Expected ExportError for empty entries, got: {:?}",
            other
        ),
    }
}

#[test]
fn test_pdf_export_error_with_large_entries() {
    // Test with multiple entries to ensure error is independent of entry count
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

    let result = test_pdf_export_with_entries(entries);

    assert!(
        result.is_err(),
        "CompliancePdf export should fail regardless of entry count"
    );

    match result.unwrap_err() {
        GovernanceError::ExportError { message } => {
            assert!(
                message.contains("not yet implemented"),
                "Error message should be consistent regardless of entry count"
            );
        }
        other => panic!(
            "Expected ExportError for large entries, got: {:?}",
            other
        ),
    }
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
    let json_output = json_result.unwrap().payload;
    assert!(!json_output.is_empty(), "JsonLines output should not be empty");

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
    let csv_output = csv_result.unwrap().payload;
    assert!(!csv_output.is_empty(), "CSV output should not be empty");
    assert!(
        csv_output.starts_with(b"entry_id,kind,timestamp,summary,evidence_hash\n"),
        "CSV output should have proper header"
    );
}

#[test]
fn test_pdf_error_message_content_quality() {
    // Test that the error message provides sufficient information for users
    let entry = create_test_evidence_entry(
        "msg-001",
        "message_test",
        "Error message content verification",
        1640995200,
    );

    let entries = vec![entry];
    let result = test_pdf_export_with_entries(entries);

    match result.unwrap_err() {
        GovernanceError::ExportError { message } => {
            // Check for key information in error message
            assert!(
                message.contains("CompliancePdf"),
                "Error should mention the specific format: {}",
                message
            );
            assert!(
                message.contains("not yet implemented") || message.contains("not implemented"),
                "Error should clearly state implementation status: {}",
                message
            );
            assert!(
                message.contains("PDF"),
                "Error should mention PDF specifically: {}",
                message
            );
            assert!(
                message.contains("JsonLines") || message.contains("Csv"),
                "Error should suggest working alternatives: {}",
                message
            );

            // Ensure message is reasonably concise but informative
            assert!(
                message.len() > 50,
                "Error message should be informative (>50 chars): {}",
                message
            );
            assert!(
                message.len() < 300,
                "Error message should be concise (<300 chars): {}",
                message
            );
        }
        other => panic!(
            "Expected ExportError for message content test, got: {:?}",
            other
        ),
    }
}

#[test]
fn test_compliance_pdf_vs_fake_pdf_behavior() {
    // This test documents the OLD vs NEW behavior to ensure we're actually
    // fixing the problem (no longer emitting fake PDF content)
    let entry = create_test_evidence_entry(
        "behavior-001",
        "behavioral_test",
        "Old vs new behavior validation",
        1640995200,
    );

    let entries = vec![entry];
    let result = test_pdf_export_with_entries(entries);

    // NEW behavior: should fail with ExportError
    assert!(result.is_err(), "Should fail instead of returning fake content");

    if let Ok(output) = result {
        // If it somehow succeeds, it MUST NOT contain the old fake content
        let output_str = String::from_utf8_lossy(&output);
        assert!(
            !output_str.contains("FRANKEN_COMPLIANCE_REPORT_V1"),
            "Output should not contain fake header: {}",
            output_str
        );
        assert!(
            output_str.starts_with("%PDF-") && output_str.ends_with("%%EOF"),
            "If PDF generation succeeds, it must be valid PDF format: {}",
            output_str
        );
    } else {
        // Expected: error case
        match result.unwrap_err() {
            GovernanceError::ExportError { .. } => {
                // This is the expected behavior - fail loud instead of fake
            }
            other => panic!(
                "If PDF fails, it should be ExportError, got: {:?}",
                other
            ),
        }
    }
}