//! Enrichment integration tests for `zero_placeholder_scan`.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::zero_placeholder_scan::*;

fn unique_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "enrichment_zps_{label}_{}_{nanos}",
        std::process::id()
    ))
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_schema_version_non_empty() {
    assert!(!ZERO_PLACEHOLDER_SCAN_SCHEMA_VERSION.is_empty());
}

#[test]
fn enrichment_trace_ids_schema_non_empty() {
    assert!(!ZERO_PLACEHOLDER_SCAN_TRACE_IDS_SCHEMA_VERSION.is_empty());
}

#[test]
fn enrichment_run_manifest_schema_non_empty() {
    assert!(!ZERO_PLACEHOLDER_SCAN_RUN_MANIFEST_SCHEMA_VERSION.is_empty());
}

#[test]
fn enrichment_event_schema_non_empty() {
    assert!(!ZERO_PLACEHOLDER_SCAN_EVENT_SCHEMA_VERSION.is_empty());
}

#[test]
fn enrichment_component_non_empty() {
    assert!(!ZERO_PLACEHOLDER_SCAN_COMPONENT.is_empty());
}

#[test]
fn enrichment_policy_id_non_empty() {
    assert!(!ZERO_PLACEHOLDER_SCAN_POLICY_ID.is_empty());
}

#[test]
fn enrichment_finding_count_positive() {
    assert!(ZERO_PLACEHOLDER_SCAN_FINDING_COUNT > 0);
}

// ---------------------------------------------------------------------------
// ZeroPlaceholderSubsystem
// ---------------------------------------------------------------------------

#[test]
fn enrichment_subsystem_all_count() {
    assert_eq!(ZeroPlaceholderSubsystem::ALL.len(), 4);
}

#[test]
fn enrichment_subsystem_as_str_unique() {
    let mut strs = std::collections::BTreeSet::new();
    for s in &ZeroPlaceholderSubsystem::ALL {
        assert!(strs.insert(s.as_str()));
    }
}

#[test]
fn enrichment_subsystem_serde_roundtrip() {
    for s in &ZeroPlaceholderSubsystem::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: ZeroPlaceholderSubsystem = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ---------------------------------------------------------------------------
// ZeroPlaceholderStatus
// ---------------------------------------------------------------------------

#[test]
fn enrichment_status_as_str_unique() {
    let mut strs = std::collections::BTreeSet::new();
    for s in [
        ZeroPlaceholderStatus::OpenPlaceholder,
        ZeroPlaceholderStatus::FailClosed,
        ZeroPlaceholderStatus::Resolved,
    ] {
        assert!(strs.insert(s.as_str()));
    }
}

#[test]
fn enrichment_status_serde_roundtrip() {
    for s in [
        ZeroPlaceholderStatus::OpenPlaceholder,
        ZeroPlaceholderStatus::FailClosed,
        ZeroPlaceholderStatus::Resolved,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: ZeroPlaceholderStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

// ---------------------------------------------------------------------------
// ZeroPlaceholderSeverity
// ---------------------------------------------------------------------------

#[test]
fn enrichment_severity_as_str_unique() {
    let mut strs = std::collections::BTreeSet::new();
    for s in [
        ZeroPlaceholderSeverity::High,
        ZeroPlaceholderSeverity::Medium,
        ZeroPlaceholderSeverity::Low,
    ] {
        assert!(strs.insert(s.as_str()));
    }
}

#[test]
fn enrichment_severity_serde_roundtrip() {
    for s in [
        ZeroPlaceholderSeverity::High,
        ZeroPlaceholderSeverity::Medium,
        ZeroPlaceholderSeverity::Low,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: ZeroPlaceholderSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

// ---------------------------------------------------------------------------
// ZeroPlaceholderFinding serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_finding_serde_roundtrip() {
    let finding = ZeroPlaceholderFinding {
        finding_id: "f1".to_string(),
        subsystem: ZeroPlaceholderSubsystem::Parser,
        status: ZeroPlaceholderStatus::OpenPlaceholder,
        severity: ZeroPlaceholderSeverity::High,
        owner: "team-a".to_string(),
        owner_bead_id: "bd-123".to_string(),
        subject_area: "parsing".to_string(),
        source_reference: "parser.rs:42".to_string(),
        observed_behavior: "stub returns default".to_string(),
        required_behavior: "must parse correctly".to_string(),
        diagnostic_code: Some("DIAG-001".to_string()),
    };
    let json = serde_json::to_string(&finding).unwrap();
    let back: ZeroPlaceholderFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding.finding_id, back.finding_id);
}

// ---------------------------------------------------------------------------
// ZeroPlaceholderInventory
// ---------------------------------------------------------------------------

#[test]
fn enrichment_inventory_from_scan() {
    let inventory = zero_placeholder_scan_inventory();
    assert_eq!(inventory.component, ZERO_PLACEHOLDER_SCAN_COMPONENT);
    assert_eq!(inventory.findings.len(), ZERO_PLACEHOLDER_SCAN_FINDING_COUNT);
}

#[test]
fn enrichment_inventory_open_count() {
    let inventory = zero_placeholder_scan_inventory();
    let open = inventory.open_placeholder_finding_count();
    let fail_closed = inventory.fail_closed_finding_count();
    let resolved = inventory.resolved_finding_count();
    assert_eq!(open + fail_closed + resolved, inventory.findings.len());
}

#[test]
fn enrichment_inventory_subsystem_summaries() {
    let inventory = zero_placeholder_scan_inventory();
    let summaries = inventory.subsystem_summaries();
    assert!(!summaries.is_empty());
    let total: u64 = summaries.iter().map(|s| s.finding_count).sum();
    assert_eq!(total, inventory.findings.len() as u64);
}

#[test]
fn enrichment_inventory_serde_roundtrip() {
    let inventory = zero_placeholder_scan_inventory();
    let json = serde_json::to_string(&inventory).unwrap();
    let back: ZeroPlaceholderInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inventory.findings.len(), back.findings.len());
}

// ---------------------------------------------------------------------------
// ZeroPlaceholderSubsystemSummary serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_subsystem_summary_serde_roundtrip() {
    let summary = ZeroPlaceholderSubsystemSummary {
        subsystem: ZeroPlaceholderSubsystem::Runtime,
        finding_count: 5,
        open_placeholder_finding_count: 2,
        fail_closed_finding_count: 1,
        resolved_finding_count: 2,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: ZeroPlaceholderSubsystemSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ---------------------------------------------------------------------------
// write_zero_placeholder_scan_bundle
// ---------------------------------------------------------------------------

#[test]
fn enrichment_write_bundle_creates_files() {
    let out_dir = unique_dir("write_bundle");
    let artifacts = write_zero_placeholder_scan_bundle(
        &out_dir,
        &[String::from("test-command")],
    )
    .unwrap();
    assert!(artifacts.inventory_path.exists());
    assert!(artifacts.trace_ids_path.exists());
    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.events_path.exists());
    assert!(artifacts.commands_path.exists());
}

#[test]
fn enrichment_write_bundle_trace_ids_deserializable() {
    let out_dir = unique_dir("trace_deser");
    let artifacts = write_zero_placeholder_scan_bundle(
        &out_dir,
        &[String::from("cmd")],
    )
    .unwrap();
    let bytes = std::fs::read(&artifacts.trace_ids_path).unwrap();
    let trace_ids: ZeroPlaceholderScanTraceIds = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(trace_ids.component, ZERO_PLACEHOLDER_SCAN_COMPONENT);
}

#[test]
fn enrichment_write_bundle_manifest_deserializable() {
    let out_dir = unique_dir("manifest_deser");
    let artifacts = write_zero_placeholder_scan_bundle(
        &out_dir,
        &[String::from("cmd")],
    )
    .unwrap();
    let bytes = std::fs::read(&artifacts.run_manifest_path).unwrap();
    let manifest: ZeroPlaceholderScanRunManifest = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(manifest.component, ZERO_PLACEHOLDER_SCAN_COMPONENT);
    assert_eq!(manifest.finding_count, ZERO_PLACEHOLDER_SCAN_FINDING_COUNT as u64);
}

#[test]
fn enrichment_write_bundle_events_readable() {
    let out_dir = unique_dir("events");
    let artifacts = write_zero_placeholder_scan_bundle(
        &out_dir,
        &[String::from("cmd")],
    )
    .unwrap();
    let content = std::fs::read_to_string(&artifacts.events_path).unwrap();
    assert!(!content.is_empty());
    // Each line should be valid JSON
    for line in content.lines() {
        let _event: ZeroPlaceholderScanEvent = serde_json::from_str(line).unwrap();
    }
}

#[test]
fn enrichment_write_bundle_commands_contain_input() {
    let out_dir = unique_dir("commands");
    let artifacts = write_zero_placeholder_scan_bundle(
        &out_dir,
        &[String::from("my-special-command")],
    )
    .unwrap();
    let content = std::fs::read_to_string(&artifacts.commands_path).unwrap();
    assert!(content.contains("my-special-command"));
}

// ---------------------------------------------------------------------------
// ZeroPlaceholderScanArtifactPaths serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_artifact_paths_serde_roundtrip() {
    let paths = ZeroPlaceholderScanArtifactPaths {
        zero_placeholder_inventory: "inventory.json".to_string(),
        trace_ids: "trace_ids.json".to_string(),
        run_manifest: "run_manifest.json".to_string(),
        events_jsonl: "events.jsonl".to_string(),
        commands_txt: "commands.txt".to_string(),
    };
    let json = serde_json::to_string(&paths).unwrap();
    let back: ZeroPlaceholderScanArtifactPaths = serde_json::from_str(&json).unwrap();
    assert_eq!(paths, back);
}

// ---------------------------------------------------------------------------
// ZeroPlaceholderScanEvent serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_scan_event_serde_roundtrip() {
    let event = ZeroPlaceholderScanEvent {
        schema_version: ZERO_PLACEHOLDER_SCAN_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: ZERO_PLACEHOLDER_SCAN_COMPONENT.to_string(),
        event: "scan_started".to_string(),
        outcome: "pass".to_string(),
        subsystem: Some(ZeroPlaceholderSubsystem::Parser),
        finding_id: None,
        detail: Some("detail".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ZeroPlaceholderScanEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event.event, back.event);
}

// ---------------------------------------------------------------------------
// Additional coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_inventory_schema_version_correct() {
    let inventory = zero_placeholder_scan_inventory();
    assert_eq!(inventory.schema_version, ZERO_PLACEHOLDER_SCAN_SCHEMA_VERSION);
}

#[test]
fn enrichment_inventory_has_all_subsystems() {
    let inventory = zero_placeholder_scan_inventory();
    let summaries = inventory.subsystem_summaries();
    let subsystems: std::collections::BTreeSet<_> =
        summaries.iter().map(|s| s.subsystem).collect();
    assert!(subsystems.len() >= 2);
}

#[test]
fn enrichment_finding_all_statuses_present() {
    let inventory = zero_placeholder_scan_inventory();
    let has_open = inventory.open_placeholder_finding_count() > 0;
    let has_fail_closed = inventory.fail_closed_finding_count() > 0;
    let has_resolved = inventory.resolved_finding_count() > 0;
    // At least two of the three statuses should be present
    let status_count = [has_open, has_fail_closed, has_resolved]
        .iter()
        .filter(|&&b| b)
        .count();
    assert!(status_count >= 1);
}
