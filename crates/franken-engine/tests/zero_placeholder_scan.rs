use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{self, Command};
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::zero_placeholder_scan::{
    self as zscan, ZERO_PLACEHOLDER_SCAN_COMPONENT, ZERO_PLACEHOLDER_SCAN_EVENT_SCHEMA_VERSION,
    ZERO_PLACEHOLDER_SCAN_FINDING_COUNT, ZERO_PLACEHOLDER_SCAN_POLICY_ID,
    ZERO_PLACEHOLDER_SCAN_RUN_MANIFEST_SCHEMA_VERSION, ZERO_PLACEHOLDER_SCAN_SCHEMA_VERSION,
    ZERO_PLACEHOLDER_SCAN_TRACE_IDS_SCHEMA_VERSION, ZeroPlaceholderFinding,
    ZeroPlaceholderInventory, ZeroPlaceholderScanRunManifest, ZeroPlaceholderScanTraceIds,
    ZeroPlaceholderSeverity, ZeroPlaceholderStatus, ZeroPlaceholderSubsystem,
    ZeroPlaceholderSubsystemSummary,
};

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    env::temp_dir().join(format!("frankenengine-{label}-{}-{nanos}", process::id()))
}

#[test]
fn zero_placeholder_scan_cli_writes_artifact_bundle() {
    let out_dir = unique_temp_dir("zero-placeholder-cli");
    let output = Command::new(env!("CARGO_BIN_EXE_franken_zero_placeholder_scan"))
        .arg("--out-dir")
        .arg(&out_dir)
        .output()
        .expect("run zero placeholder scan binary");
    assert!(
        output.status.success(),
        "stdout:\n{}\n\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let inventory: ZeroPlaceholderInventory =
        serde_json::from_slice(&fs::read(out_dir.join("zero_placeholder_inventory.json")).unwrap())
            .expect("inventory json");
    assert_eq!(
        inventory.schema_version,
        ZERO_PLACEHOLDER_SCAN_SCHEMA_VERSION
    );
    assert_eq!(inventory.component, ZERO_PLACEHOLDER_SCAN_COMPONENT);
    assert_eq!(
        inventory.findings.len(),
        ZERO_PLACEHOLDER_SCAN_FINDING_COUNT
    );
    assert_eq!(inventory.open_placeholder_finding_count(), 6);

    let manifest: ZeroPlaceholderScanRunManifest =
        serde_json::from_slice(&fs::read(out_dir.join("run_manifest.json")).unwrap())
            .expect("manifest json");
    assert_eq!(
        manifest.schema_version,
        ZERO_PLACEHOLDER_SCAN_RUN_MANIFEST_SCHEMA_VERSION
    );
    assert_eq!(manifest.component, ZERO_PLACEHOLDER_SCAN_COMPONENT);
    assert_eq!(manifest.policy_id, ZERO_PLACEHOLDER_SCAN_POLICY_ID);
    assert_eq!(
        manifest.finding_count as usize,
        ZERO_PLACEHOLDER_SCAN_FINDING_COUNT
    );
    assert_eq!(manifest.open_placeholder_finding_count, 6);
    assert_eq!(
        manifest.open_placeholder_finding_count
            + manifest.fail_closed_finding_count
            + manifest.resolved_finding_count,
        manifest.finding_count
    );
    assert_eq!(manifest.subsystem_summaries.len(), 4);

    let trace_ids: ZeroPlaceholderScanTraceIds =
        serde_json::from_slice(&fs::read(out_dir.join("trace_ids.json")).unwrap())
            .expect("trace ids json");
    assert_eq!(
        trace_ids.schema_version,
        ZERO_PLACEHOLDER_SCAN_TRACE_IDS_SCHEMA_VERSION
    );
    assert_eq!(trace_ids.component, ZERO_PLACEHOLDER_SCAN_COMPONENT);
    assert_eq!(trace_ids.policy_id, ZERO_PLACEHOLDER_SCAN_POLICY_ID);

    let events = fs::read_to_string(out_dir.join("events.jsonl")).expect("read events");
    assert_eq!(
        events.lines().count(),
        ZERO_PLACEHOLDER_SCAN_FINDING_COUNT + 2
    );

    let commands = fs::read_to_string(out_dir.join("commands.txt")).expect("read commands");
    assert!(commands.contains("franken_zero_placeholder_scan"));
    assert!(commands.contains("--out-dir"));

    let cli_json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout json summary");
    assert_eq!(
        cli_json["finding_count"].as_u64().expect("finding_count") as usize,
        ZERO_PLACEHOLDER_SCAN_FINDING_COUNT
    );
    assert_eq!(
        cli_json["inventory_hash"]
            .as_str()
            .expect("inventory_hash")
            .len(),
        64
    );
}

#[test]
fn zero_placeholder_scan_cli_help_exits_successfully() {
    let output = Command::new(env!("CARGO_BIN_EXE_franken_zero_placeholder_scan"))
        .arg("--help")
        .output()
        .expect("run zero placeholder scan help");
    assert!(
        output.status.success(),
        "stdout:\n{}\n\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage: franken_zero_placeholder_scan --out-dir <DIR>"));
    assert!(output.stderr.is_empty());
}

#[test]
fn zero_placeholder_inventory_counts_match_expectations() {
    let inventory = zscan::zero_placeholder_scan_inventory();
    assert_eq!(
        inventory.findings.len(),
        ZERO_PLACEHOLDER_SCAN_FINDING_COUNT
    );
    assert_eq!(inventory.open_placeholder_finding_count(), 6);
    assert_eq!(
        inventory.open_placeholder_finding_count()
            + inventory.fail_closed_finding_count()
            + inventory.resolved_finding_count(),
        inventory.findings.len()
    );
}

#[test]
fn zero_placeholder_inventory_contains_one_cli_docs_guard() {
    let inventory = zscan::zero_placeholder_scan_inventory();
    let cli_docs_findings: Vec<_> = inventory
        .findings
        .iter()
        .filter(|finding| finding.subsystem == ZeroPlaceholderSubsystem::CliDocs)
        .collect();
    assert_eq!(cli_docs_findings.len(), 1);
    assert_ne!(
        cli_docs_findings[0].status,
        ZeroPlaceholderStatus::OpenPlaceholder
    );
}

#[test]
fn zero_placeholder_inventory_runtime_findings_are_present() {
    let inventory = zscan::zero_placeholder_scan_inventory();
    let runtime_findings: Vec<_> = inventory
        .findings
        .iter()
        .filter(|finding| finding.subsystem == ZeroPlaceholderSubsystem::Runtime)
        .collect();
    assert_eq!(runtime_findings.len(), 2);
    assert!(runtime_findings.iter().all(|finding| {
        finding.finding_id.starts_with("runtime::")
            && finding.status == ZeroPlaceholderStatus::OpenPlaceholder
    }));
}

#[test]
fn zero_placeholder_scan_schema_constants_nonempty() {
    assert!(!ZERO_PLACEHOLDER_SCAN_SCHEMA_VERSION.is_empty());
    assert!(!ZERO_PLACEHOLDER_SCAN_TRACE_IDS_SCHEMA_VERSION.is_empty());
    assert!(!ZERO_PLACEHOLDER_SCAN_RUN_MANIFEST_SCHEMA_VERSION.is_empty());
    assert!(!ZERO_PLACEHOLDER_SCAN_EVENT_SCHEMA_VERSION.is_empty());
    assert!(!ZERO_PLACEHOLDER_SCAN_COMPONENT.is_empty());
    assert!(!ZERO_PLACEHOLDER_SCAN_POLICY_ID.is_empty());
}

#[test]
fn inventory_serde_round_trip() {
    let inventory = zscan::zero_placeholder_scan_inventory();
    let json = serde_json::to_string(&inventory).expect("serialize");
    let restored: ZeroPlaceholderInventory = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(restored.schema_version, inventory.schema_version);
    assert_eq!(restored.component, inventory.component);
    assert_eq!(restored.findings.len(), inventory.findings.len());
}

#[test]
fn finding_serde_round_trip() {
    let inventory = zscan::zero_placeholder_scan_inventory();
    for finding in &inventory.findings {
        let json = serde_json::to_string(finding).expect("serialize finding");
        let restored: ZeroPlaceholderFinding = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.finding_id, finding.finding_id);
        assert_eq!(restored.subsystem, finding.subsystem);
        assert_eq!(restored.status, finding.status);
        assert_eq!(restored.severity, finding.severity);
    }
}

#[test]
fn all_finding_ids_are_unique() {
    let inventory = zscan::zero_placeholder_scan_inventory();
    let ids: BTreeSet<_> = inventory
        .findings
        .iter()
        .map(|f| f.finding_id.clone())
        .collect();
    assert_eq!(ids.len(), inventory.findings.len());
}

#[test]
fn finding_ids_have_subsystem_prefix() {
    let inventory = zscan::zero_placeholder_scan_inventory();
    for finding in &inventory.findings {
        let prefix = match finding.subsystem {
            ZeroPlaceholderSubsystem::Parser => "parser::",
            ZeroPlaceholderSubsystem::Lowering => "lowering::",
            ZeroPlaceholderSubsystem::Runtime => "runtime::",
            ZeroPlaceholderSubsystem::CliDocs => "cli_docs::",
        };
        assert!(
            finding.finding_id.starts_with(prefix),
            "finding {} should start with {}",
            finding.finding_id,
            prefix
        );
    }
}

#[test]
fn inventory_determinism_across_runs() {
    let first = zscan::zero_placeholder_scan_inventory();
    let second = zscan::zero_placeholder_scan_inventory();
    let json1 = serde_json::to_string(&first).expect("serialize first");
    let json2 = serde_json::to_string(&second).expect("serialize second");
    assert_eq!(json1, json2);
}

#[test]
fn subsystem_summaries_cover_all_four() {
    let inventory = zscan::zero_placeholder_scan_inventory();
    let summaries = inventory.subsystem_summaries();
    assert_eq!(summaries.len(), 4);
    let subsystems: BTreeSet<_> = summaries.iter().map(|s| s.subsystem).collect();
    assert!(subsystems.contains(&ZeroPlaceholderSubsystem::Parser));
    assert!(subsystems.contains(&ZeroPlaceholderSubsystem::Lowering));
    assert!(subsystems.contains(&ZeroPlaceholderSubsystem::Runtime));
    assert!(subsystems.contains(&ZeroPlaceholderSubsystem::CliDocs));
}

#[test]
fn subsystem_summary_counts_sum_to_finding_count() {
    let inventory = zscan::zero_placeholder_scan_inventory();
    let summaries = inventory.subsystem_summaries();
    let total: u64 = summaries.iter().map(|s| s.finding_count).sum();
    assert_eq!(total as usize, ZERO_PLACEHOLDER_SCAN_FINDING_COUNT);
}

#[test]
fn subsystem_summary_status_breakdown_sums_to_finding_count() {
    let inventory = zscan::zero_placeholder_scan_inventory();
    for summary in inventory.subsystem_summaries() {
        assert_eq!(
            summary.open_placeholder_finding_count
                + summary.fail_closed_finding_count
                + summary.resolved_finding_count,
            summary.finding_count,
            "breakdown mismatch for {:?}",
            summary.subsystem
        );
    }
}

#[test]
fn subsystem_summary_serde_round_trip() {
    let inventory = zscan::zero_placeholder_scan_inventory();
    let summaries = inventory.subsystem_summaries();
    for summary in &summaries {
        let json = serde_json::to_string(summary).expect("serialize summary");
        let restored: ZeroPlaceholderSubsystemSummary =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.subsystem, summary.subsystem);
        assert_eq!(restored.finding_count, summary.finding_count);
    }
}

#[test]
fn all_findings_have_nonempty_fields() {
    let inventory = zscan::zero_placeholder_scan_inventory();
    for finding in &inventory.findings {
        assert!(!finding.finding_id.is_empty(), "empty finding_id");
        assert!(
            !finding.owner.is_empty(),
            "empty owner in {}",
            finding.finding_id
        );
        assert!(
            !finding.owner_bead_id.is_empty(),
            "empty bead_id in {}",
            finding.finding_id
        );
        assert!(
            !finding.subject_area.is_empty(),
            "empty subject_area in {}",
            finding.finding_id
        );
        assert!(
            !finding.source_reference.is_empty(),
            "empty source_reference in {}",
            finding.finding_id
        );
        assert!(
            !finding.observed_behavior.is_empty(),
            "empty observed_behavior in {}",
            finding.finding_id
        );
        assert!(
            !finding.required_behavior.is_empty(),
            "empty required_behavior in {}",
            finding.finding_id
        );
    }
}

#[test]
fn open_placeholder_findings_are_high_severity() {
    let inventory = zscan::zero_placeholder_scan_inventory();
    for finding in &inventory.findings {
        if finding.status == ZeroPlaceholderStatus::OpenPlaceholder {
            assert_eq!(
                finding.severity,
                ZeroPlaceholderSeverity::High,
                "open placeholder {} should be high severity",
                finding.finding_id
            );
        }
    }
}

#[test]
fn fail_closed_findings_are_medium_severity() {
    let inventory = zscan::zero_placeholder_scan_inventory();
    for finding in &inventory.findings {
        if finding.status == ZeroPlaceholderStatus::FailClosed {
            assert_eq!(
                finding.severity,
                ZeroPlaceholderSeverity::Medium,
                "fail-closed {} should be medium severity",
                finding.finding_id
            );
        }
    }
}

#[test]
fn resolved_findings_are_low_severity() {
    let inventory = zscan::zero_placeholder_scan_inventory();
    for finding in &inventory.findings {
        if finding.status == ZeroPlaceholderStatus::Resolved {
            assert_eq!(
                finding.severity,
                ZeroPlaceholderSeverity::Low,
                "resolved {} should be low severity",
                finding.finding_id
            );
        }
    }
}

#[test]
fn parser_subsystem_has_six_findings() {
    let inventory = zscan::zero_placeholder_scan_inventory();
    let count = inventory
        .findings
        .iter()
        .filter(|f| f.subsystem == ZeroPlaceholderSubsystem::Parser)
        .count();
    assert_eq!(count, 6);
}

#[test]
fn lowering_subsystem_has_six_findings() {
    let inventory = zscan::zero_placeholder_scan_inventory();
    let count = inventory
        .findings
        .iter()
        .filter(|f| f.subsystem == ZeroPlaceholderSubsystem::Lowering)
        .count();
    assert_eq!(count, 6);
}

#[test]
fn runtime_findings_reference_stdlib() {
    let inventory = zscan::zero_placeholder_scan_inventory();
    for finding in &inventory.findings {
        if finding.subsystem == ZeroPlaceholderSubsystem::Runtime {
            assert!(
                finding.source_reference.contains("stdlib"),
                "runtime finding {} should reference stdlib",
                finding.finding_id
            );
        }
    }
}

#[test]
fn cli_docs_finding_references_readme_and_frankenctl() {
    let inventory = zscan::zero_placeholder_scan_inventory();
    let cli_finding = inventory
        .findings
        .iter()
        .find(|f| f.subsystem == ZeroPlaceholderSubsystem::CliDocs)
        .expect("cli_docs finding");
    assert!(cli_finding.source_reference.contains("README.md"));
    assert!(cli_finding.source_reference.contains("frankenctl"));
}

#[test]
fn write_bundle_produces_deterministic_hash() {
    let dir1 = unique_temp_dir("hash-det-1");
    let dir2 = unique_temp_dir("hash-det-2");
    let commands = vec!["test_cmd".to_string()];
    let a1 = zscan::write_zero_placeholder_scan_bundle(&dir1, &commands).expect("write 1");
    let a2 = zscan::write_zero_placeholder_scan_bundle(&dir2, &commands).expect("write 2");
    assert_eq!(a1.inventory_hash, a2.inventory_hash);
    assert_eq!(a1.finding_count, a2.finding_count);
}

#[test]
fn write_bundle_inventory_hash_is_64_hex_chars() {
    let out_dir = unique_temp_dir("hash-format");
    let commands = vec!["test".to_string()];
    let artifacts = zscan::write_zero_placeholder_scan_bundle(&out_dir, &commands).expect("write");
    assert_eq!(artifacts.inventory_hash.len(), 64);
    assert!(
        artifacts
            .inventory_hash
            .chars()
            .all(|c| c.is_ascii_hexdigit())
    );
}

#[test]
fn write_bundle_events_jsonl_lines_are_valid_json() {
    let out_dir = unique_temp_dir("events-valid");
    let commands = vec!["test".to_string()];
    let artifacts = zscan::write_zero_placeholder_scan_bundle(&out_dir, &commands).expect("write");
    let events_text = fs::read_to_string(&artifacts.events_path).expect("read events");
    for (i, line) in events_text.lines().enumerate() {
        let parsed: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("line {i} invalid json: {e}"));
        assert_eq!(
            parsed["schema_version"].as_str().unwrap(),
            ZERO_PLACEHOLDER_SCAN_EVENT_SCHEMA_VERSION
        );
    }
}

#[test]
fn write_bundle_events_have_start_and_end_bookends() {
    let out_dir = unique_temp_dir("events-bookend");
    let commands = vec!["test".to_string()];
    let artifacts = zscan::write_zero_placeholder_scan_bundle(&out_dir, &commands).expect("write");
    let events_text = fs::read_to_string(&artifacts.events_path).expect("read events");
    let lines: Vec<&str> = events_text.lines().collect();
    let first: serde_json::Value = serde_json::from_str(lines[0]).expect("first event");
    let last: serde_json::Value = serde_json::from_str(lines[lines.len() - 1]).expect("last event");
    assert_eq!(first["event"].as_str().unwrap(), "inventory_started");
    assert_eq!(last["event"].as_str().unwrap(), "inventory_completed");
}

#[test]
fn write_bundle_manifest_subsystem_summaries_total() {
    let out_dir = unique_temp_dir("manifest-total");
    let commands = vec!["test".to_string()];
    let artifacts = zscan::write_zero_placeholder_scan_bundle(&out_dir, &commands).expect("write");
    let manifest: ZeroPlaceholderScanRunManifest =
        serde_json::from_slice(&fs::read(&artifacts.run_manifest_path).unwrap()).expect("parse");
    let sum: u64 = manifest
        .subsystem_summaries
        .iter()
        .map(|s| s.finding_count)
        .sum();
    assert_eq!(sum, manifest.finding_count);
}

#[test]
fn write_bundle_trace_ids_contain_hash_prefix() {
    let out_dir = unique_temp_dir("trace-prefix");
    let commands = vec!["test".to_string()];
    let artifacts = zscan::write_zero_placeholder_scan_bundle(&out_dir, &commands).expect("write");
    let trace_ids: ZeroPlaceholderScanTraceIds =
        serde_json::from_slice(&fs::read(&artifacts.trace_ids_path).unwrap()).expect("parse");
    let short = &artifacts.inventory_hash[..16];
    assert!(
        trace_ids.trace_id.contains(short),
        "trace_id should contain hash prefix"
    );
    assert!(
        trace_ids.decision_id.contains(short),
        "decision_id should contain hash prefix"
    );
}

#[test]
fn write_bundle_commands_txt_records_all_args() {
    let out_dir = unique_temp_dir("commands-args");
    let commands = vec![
        "franken_zero_placeholder_scan".to_string(),
        "--out-dir".to_string(),
        "/tmp/test".to_string(),
    ];
    let artifacts = zscan::write_zero_placeholder_scan_bundle(&out_dir, &commands).expect("write");
    let text = fs::read_to_string(&artifacts.commands_path).expect("read commands");
    for cmd in &commands {
        assert!(text.contains(cmd), "commands.txt should contain {cmd}");
    }
}

#[test]
fn write_bundle_no_lock_file_after_success() {
    let out_dir = unique_temp_dir("no-lock");
    let commands = vec!["test".to_string()];
    zscan::write_zero_placeholder_scan_bundle(&out_dir, &commands).expect("write");
    assert!(
        !out_dir.join(".zero_placeholder_scan.lock").exists(),
        "lock should be cleaned up after write"
    );
}

#[test]
fn schema_version_strings_contain_version_segment() {
    assert!(ZERO_PLACEHOLDER_SCAN_SCHEMA_VERSION.contains(".v"));
    assert!(ZERO_PLACEHOLDER_SCAN_TRACE_IDS_SCHEMA_VERSION.contains(".v"));
    assert!(ZERO_PLACEHOLDER_SCAN_RUN_MANIFEST_SCHEMA_VERSION.contains(".v"));
    assert!(ZERO_PLACEHOLDER_SCAN_EVENT_SCHEMA_VERSION.contains(".v"));
}

#[test]
fn schema_version_strings_contain_franken_engine_prefix() {
    assert!(ZERO_PLACEHOLDER_SCAN_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(ZERO_PLACEHOLDER_SCAN_TRACE_IDS_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(ZERO_PLACEHOLDER_SCAN_RUN_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(ZERO_PLACEHOLDER_SCAN_EVENT_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn owner_bead_ids_start_with_bd_prefix() {
    let inventory = zscan::zero_placeholder_scan_inventory();
    for finding in &inventory.findings {
        assert!(
            finding.owner_bead_id.starts_with("bd-"),
            "bead id {} should start with bd-",
            finding.owner_bead_id
        );
    }
}

#[test]
fn write_bundle_artifact_paths_are_relative() {
    let out_dir = unique_temp_dir("rel-paths");
    let commands = vec!["test".to_string()];
    let artifacts = zscan::write_zero_placeholder_scan_bundle(&out_dir, &commands).expect("write");
    let manifest: ZeroPlaceholderScanRunManifest =
        serde_json::from_slice(&fs::read(&artifacts.run_manifest_path).unwrap()).expect("parse");
    assert!(
        !manifest
            .artifact_paths
            .zero_placeholder_inventory
            .contains('/')
    );
    assert!(!manifest.artifact_paths.trace_ids.contains('/'));
    assert!(!manifest.artifact_paths.run_manifest.contains('/'));
    assert!(!manifest.artifact_paths.events_jsonl.contains('/'));
    assert!(!manifest.artifact_paths.commands_txt.contains('/'));
}
