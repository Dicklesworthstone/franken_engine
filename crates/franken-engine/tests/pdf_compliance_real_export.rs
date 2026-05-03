#![forbid(unsafe_code)]

//! Integration tests for real PDF generation in compliance export format.
//!
//! These tests verify that the CompliancePdf export format now generates
//! actual valid PDF files instead of the previous fail-loud behavior.
//!
//! Tests cover PDF structure validation, deterministic output, content
//! embedding, and basic PDF specification compliance.

use frankenengine_engine::engine_object_id::{ObjectDomain, SchemaId, derive_id};
use frankenengine_engine::governance_hooks::{
    AuditExportFormat, AuditExportRequest, EvidenceEntry, export_audit_evidence,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use std::collections::BTreeMap;

/// Create a test evidence entry for PDF export testing
fn create_test_evidence_entry(
    id: &str,
    kind: &str,
    summary: &str,
    timestamp: u64,
) -> EvidenceEntry {
    let schema_id = SchemaId::from_definition(b"pdf-compliance-real-export-test-schema");
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
        timestamp: DeterministicTimestamp(timestamp),
        summary: summary.to_string(),
        evidence_hash: ContentHash::compute(b"test-evidence-data"),
        attributes: BTreeMap::new(),
    }
}

/// Helper to export entries as PDF for testing
fn export_entries_as_pdf(
    entries: Vec<EvidenceEntry>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let request = AuditExportRequest {
        format: AuditExportFormat::CompliancePdf,
        start_tick: DeterministicTimestamp(0),
        end_tick: DeterministicTimestamp(u64::MAX),
        evidence_kinds: None,
        max_entries: Some(entries.len() as u64),
        requester: "pdf_compliance_real_export_test".to_string(),
        correlation_id: Some("pdf-real-export".to_string()),
    };

    let result = export_audit_evidence(request, entries, DeterministicTimestamp(1640995200))?;
    Ok(result.payload_bytes)
}

#[test]
fn pdf_output_starts_with_pdf_header() {
    let entries = vec![create_test_evidence_entry(
        "test-001",
        "compliance_check",
        "Test entry",
        1640995200,
    )];

    let pdf_bytes = export_entries_as_pdf(entries).expect("PDF export should succeed");

    assert!(
        pdf_bytes.starts_with(b"%PDF-1.4"),
        "PDF output must start with %PDF-1.4 header"
    );
}

#[test]
fn pdf_output_ends_with_eof() {
    let entries = vec![create_test_evidence_entry(
        "test-002",
        "audit_log",
        "Test entry",
        1640995260,
    )];

    let pdf_bytes = export_entries_as_pdf(entries).expect("PDF export should succeed");

    assert!(
        pdf_bytes.ends_with(b"%%EOF"),
        "PDF output must end with %%EOF marker"
    );
}

#[test]
fn pdf_contains_required_structural_elements() {
    let entries = vec![create_test_evidence_entry(
        "test-003",
        "security_check",
        "Test entry",
        1640995320,
    )];

    let pdf_bytes = export_entries_as_pdf(entries).expect("PDF export should succeed");
    let pdf_str = std::str::from_utf8(&pdf_bytes).expect("PDF should be valid UTF-8");

    // Check for required PDF objects
    assert!(
        pdf_str.contains("/Type /Catalog"),
        "PDF must contain catalog object"
    );
    assert!(
        pdf_str.contains("/Type /Pages"),
        "PDF must contain pages object"
    );
    assert!(
        pdf_str.contains("/Type /Page"),
        "PDF must contain page object"
    );
    assert!(
        pdf_str.contains("/Type /Font"),
        "PDF must contain font object"
    );
    assert!(pdf_str.contains("xref"), "PDF must contain xref table");
    assert!(pdf_str.contains("trailer"), "PDF must contain trailer");
    assert!(pdf_str.contains("startxref"), "PDF must contain startxref");
}

#[test]
fn pdf_deterministic_output_same_input() {
    let entries = vec![create_test_evidence_entry(
        "test-004",
        "compliance",
        "Deterministic test",
        1640995380,
    )];

    let pdf_bytes1 =
        export_entries_as_pdf(entries.clone()).expect("First PDF export should succeed");
    let pdf_bytes2 = export_entries_as_pdf(entries).expect("Second PDF export should succeed");

    assert_eq!(
        pdf_bytes1, pdf_bytes2,
        "PDF output should be deterministic for same input"
    );
}

#[test]
fn pdf_embeds_audit_content() {
    let entries = vec![create_test_evidence_entry(
        "test-005",
        "audit_trail",
        "Specific audit content",
        1640995440,
    )];

    let pdf_bytes = export_entries_as_pdf(entries).expect("PDF export should succeed");
    let pdf_str = std::str::from_utf8(&pdf_bytes).expect("PDF should be valid UTF-8");

    // Check that entry content is embedded in PDF
    assert!(pdf_str.contains("test-005"), "PDF should contain entry ID");
    assert!(
        pdf_str.contains("audit_trail"),
        "PDF should contain entry kind"
    );
    assert!(
        pdf_str.contains("Specific audit content"),
        "PDF should contain entry summary"
    );
}

#[test]
fn pdf_handles_multiple_entries() {
    let entries = vec![
        create_test_evidence_entry("test-006a", "check_alpha", "First entry", 1640995500),
        create_test_evidence_entry("test-006b", "check_beta", "Second entry", 1640995560),
        create_test_evidence_entry("test-006c", "check_gamma", "Third entry", 1640995620),
    ];

    let pdf_bytes = export_entries_as_pdf(entries).expect("PDF export should succeed");
    let pdf_str = std::str::from_utf8(&pdf_bytes).expect("PDF should be valid UTF-8");

    // Verify all entries are included
    assert!(
        pdf_str.contains("test-006a"),
        "PDF should contain first entry"
    );
    assert!(
        pdf_str.contains("test-006b"),
        "PDF should contain second entry"
    );
    assert!(
        pdf_str.contains("test-006c"),
        "PDF should contain third entry"
    );

    assert!(
        pdf_str.contains("check_alpha"),
        "PDF should contain first entry kind"
    );
    assert!(
        pdf_str.contains("check_beta"),
        "PDF should contain second entry kind"
    );
    assert!(
        pdf_str.contains("check_gamma"),
        "PDF should contain third entry kind"
    );
}

#[test]
fn pdf_xref_offsets_are_valid() {
    let entries = vec![create_test_evidence_entry(
        "test-007",
        "offset_check",
        "XRef validation",
        1640995680,
    )];

    let pdf_bytes = export_entries_as_pdf(entries).expect("PDF export should succeed");
    let pdf_str = std::str::from_utf8(&pdf_bytes).expect("PDF should be valid UTF-8");

    // Find xref table
    let xref_start = pdf_str
        .find("xref\n")
        .expect("PDF should contain xref table");
    let xref_section = &pdf_str[xref_start..];

    // Basic validation that offsets are numeric and properly formatted
    assert!(
        xref_section.contains("0000000000 65535 f"),
        "Should contain free object entry"
    );

    // Check that there are offset entries (10 digits followed by " 00000 n")
    // Count occurrences manually without regex dependency
    let mut offset_count = 0;
    let mut search_pos = 0;
    while let Some(pos) = xref_section[search_pos..].find(" 00000 n") {
        let line_start = search_pos + pos;
        // Check if the 10 characters before " 00000 n" are digits
        if line_start >= 10 {
            let potential_offset = &xref_section[line_start - 10..line_start];
            if potential_offset.chars().all(|c| c.is_ascii_digit()) {
                offset_count += 1;
            }
        }
        search_pos = line_start + 1;
    }

    assert!(
        offset_count >= 5,
        "PDF should contain offset entries for all objects (found {})",
        offset_count
    );
}

#[test]
fn pdf_empty_entries_produces_valid_pdf() {
    let entries: Vec<EvidenceEntry> = vec![];

    let pdf_bytes =
        export_entries_as_pdf(entries).expect("PDF export should succeed even with empty entries");

    // Should still be a valid PDF structure
    assert!(
        pdf_bytes.starts_with(b"%PDF-1.4"),
        "Empty PDF should still have header"
    );
    assert!(
        pdf_bytes.ends_with(b"%%EOF"),
        "Empty PDF should still have EOF"
    );

    let pdf_str = std::str::from_utf8(&pdf_bytes).expect("PDF should be valid UTF-8");
    assert!(
        pdf_str.contains("xref"),
        "Empty PDF should still have xref table"
    );
}
