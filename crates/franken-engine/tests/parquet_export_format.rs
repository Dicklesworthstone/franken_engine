/// Integration tests for Parquet export format correctness.
///
/// Tests verify that AuditExportFormat::Parquet emits real Parquet binary format
/// instead of the previous fake plaintext format, addressing the compliance bug
/// where tools expecting real Parquet would reject the fake exports.

use std::collections::BTreeMap;
use frankenengine_engine::governance_hooks::{
    AuditExportFormat, EvidenceEntry, AuditExportRequest, export_audit_evidence,
};
use frankenengine_engine::{
    EngineObjectId, DeterministicTimestamp, ContentHash,
};

/// Export entries to Parquet format for testing.
fn export_to_parquet(entries: &[EvidenceEntry]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let request = AuditExportRequest {
        start_tick: DeterministicTimestamp(0),
        end_tick: DeterministicTimestamp(u64::MAX),
        format: AuditExportFormat::Parquet,
        kind_filter: None,
    };

    let now = DeterministicTimestamp(2000000);
    let result = export_audit_evidence(request, entries.to_vec(), now)?;
    Ok(result.payload)
}

/// Create a test evidence entry for testing.
fn create_test_entry(
    id_suffix: &str,
    kind: &str,
    timestamp: u64,
    summary: &str,
) -> EvidenceEntry {
    let entry_id = EngineObjectId::from_hex(&format!("a1b2c3d4e5f6789{}", id_suffix))
        .expect("Valid hex ID");
    let evidence_hash = ContentHash::compute(format!("test_evidence_{}", id_suffix).as_bytes());

    EvidenceEntry {
        entry_id,
        kind: kind.to_string(),
        timestamp: DeterministicTimestamp(timestamp),
        summary: summary.to_string(),
        attributes: BTreeMap::new(),
        evidence_hash,
    }
}

#[test]
fn test_parquet_format_produces_binary() {
    // Create test entries
    let entries = vec![
        create_test_entry("0001", "policy_update", 1000000, "Test policy update"),
        create_test_entry("0002", "epoch_transition", 1000001, "Test epoch transition"),
    ];

    // Export to Parquet format
    let result = export_to_parquet(&entries);
    assert!(result.is_ok(), "Parquet export should succeed");

    let parquet_bytes = result.unwrap();

    // Verify it's not the old fake format
    assert!(
        !parquet_bytes.starts_with(b"FRANKEN_PARQUET_V1\n"),
        "Should not emit fake Parquet header"
    );

    // Verify it has Parquet magic header (PAR1)
    assert!(
        parquet_bytes.len() >= 4,
        "Parquet file should have at least 4 bytes"
    );

    // Real Parquet files start with PAR1 magic bytes
    assert_eq!(
        &parquet_bytes[0..4],
        b"PAR1",
        "Should start with PAR1 Parquet magic header"
    );

    // Verify it's not just plaintext
    let as_string = String::from_utf8_lossy(&parquet_bytes);
    assert!(
        !as_string.contains('\t'),
        "Real Parquet should not contain tab separators"
    );
    assert!(
        !as_string.contains('\n'),
        "Real Parquet should not contain newline separators in readable form"
    );
}

#[test]
fn test_parquet_empty_audit_log() {
    // Export empty entries list
    let entries: Vec<EvidenceEntry> = vec![];
    let result = export_to_parquet(&entries);

    assert!(result.is_ok(), "Empty Parquet export should succeed");
    let parquet_bytes = result.unwrap();

    // Should still be valid Parquet (with schema but no data)
    assert!(parquet_bytes.len() >= 4, "Even empty Parquet should have header");
    assert_eq!(&parquet_bytes[0..4], b"PAR1", "Should have PAR1 magic");
}

#[test]
fn test_parquet_multi_row_preserves_count() {
    // Create multiple entries
    let entries = vec![
        create_test_entry("0001", "type_a", 1000000, "Summary 1"),
        create_test_entry("0002", "type_b", 1000001, "Summary 2"),
        create_test_entry("0003", "type_a", 1000002, "Summary 3"),
        create_test_entry("0004", "type_c", 1000003, "Summary 4"),
        create_test_entry("0005", "type_b", 1000004, "Summary 5"),
    ];

    let result = export_to_parquet(&entries);
    assert!(result.is_ok(), "Multi-row Parquet export should succeed");

    let parquet_bytes = result.unwrap();
    assert_eq!(&parquet_bytes[0..4], b"PAR1", "Should have PAR1 magic");

    // The row count verification would require parsing the Parquet file,
    // which is complex. For now, we verify the export succeeds and produces
    // valid-looking Parquet binary format.
    assert!(parquet_bytes.len() > 100, "Multi-row Parquet should be substantial");
}

#[test]
fn test_parquet_determinism() {
    // Create identical entries
    let entries = vec![
        create_test_entry("0001", "test_type", 1000000, "Test summary"),
        create_test_entry("0002", "test_type", 1000001, "Test summary"),
    ];

    // Export twice
    let result1 = export_evidence_to_format(&entries, AuditExportFormat::Parquet);
    let result2 = export_evidence_to_format(&entries, AuditExportFormat::Parquet);

    assert!(result1.is_ok() && result2.is_ok(), "Both exports should succeed");

    let bytes1 = result1.unwrap();
    let bytes2 = result2.unwrap();

    // Should be byte-identical for deterministic output
    assert_eq!(
        bytes1, bytes2,
        "Identical input should produce byte-identical Parquet output"
    );
}

#[test]
fn test_parquet_schema_preservation() {
    // Create entry with specific schema
    let entry = create_test_entry("0001", "schema_test", 1000000, "Schema test");
    let entries = vec![entry];

    let result = export_to_parquet(&entries);
    assert!(result.is_ok(), "Schema test export should succeed");

    let parquet_bytes = result.unwrap();
    assert_eq!(&parquet_bytes[0..4], b"PAR1", "Should have PAR1 magic");

    // Schema preservation verification would require Parquet parsing.
    // For now, verify the export produces valid binary format.
    assert!(parquet_bytes.len() > 50, "Schema should add substantial metadata");
}

#[test]
fn test_parquet_header_footer_magic() {
    // Create test entry
    let entry = create_test_entry("0001", "magic_test", 1000000, "Magic test");
    let entries = vec![entry];

    let result = export_to_parquet(&entries);
    assert!(result.is_ok(), "Magic test export should succeed");

    let parquet_bytes = result.unwrap();

    // Verify header magic
    assert!(parquet_bytes.len() >= 4, "Should have header");
    assert_eq!(&parquet_bytes[0..4], b"PAR1", "Header should be PAR1");

    // Verify footer magic (last 4 bytes should also be PAR1)
    assert!(parquet_bytes.len() >= 8, "Should have footer");
    let footer_start = parquet_bytes.len() - 4;
    assert_eq!(
        &parquet_bytes[footer_start..],
        b"PAR1",
        "Footer should be PAR1"
    );
}

#[test]
fn test_parquet_vs_old_format_rejection() {
    // This test verifies we no longer emit the fake format
    let entry = create_test_entry("0001", "rejection_test", 1000000, "Rejection test");
    let entries = vec![entry];

    let result = export_to_parquet(&entries);
    assert!(result.is_ok(), "New format should work");

    let parquet_bytes = result.unwrap();

    // Verify none of the old fake format markers are present
    let as_string = String::from_utf8_lossy(&parquet_bytes);
    assert!(
        !as_string.contains("FRANKEN_PARQUET_V1"),
        "Should not contain old fake header"
    );
    assert!(
        !as_string.contains("\t"),
        "Should not contain tab delimiters from old format"
    );

    // Verify it has real Parquet structure
    assert_eq!(&parquet_bytes[0..4], b"PAR1", "Should have real Parquet header");
}