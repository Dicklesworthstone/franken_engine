#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::lowering_gap_inventory::{
    LoweringGapInventoryRunManifest, LoweringGapSiteId, LoweringGapStatus,
    LoweringGapTruthConsumerParityReport, lowering_gap_inventory,
    write_lowering_gap_inventory_bundle,
};
use frankenengine_engine::zero_placeholder_scan::{
    ZeroPlaceholderStatus, ZeroPlaceholderSubsystem, zero_placeholder_scan_inventory,
};

fn unique_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "frankenengine-lowering-truth-parity-{label}-{}-{nanos}",
        std::process::id()
    ))
}

#[test]
fn lowering_inventory_and_zero_placeholder_scan_agree_on_execution_ready_truth() {
    let lowering_inventory = lowering_gap_inventory();
    let scan_inventory = zero_placeholder_scan_inventory();
    let lowering_findings: BTreeMap<&str, _> = scan_inventory
        .findings
        .iter()
        .filter(|finding| finding.subsystem == ZeroPlaceholderSubsystem::Lowering)
        .map(|finding| {
            let site_id = finding
                .finding_id
                .strip_prefix("lowering::")
                .expect("lowering finding id prefix");
            (site_id, finding)
        })
        .collect();

    assert_eq!(lowering_findings.len(), LoweringGapSiteId::ALL.len());
    for site in &lowering_inventory.sites {
        let finding = lowering_findings
            .get(site.site_id.as_str())
            .unwrap_or_else(|| {
                panic!(
                    "missing zero-placeholder lowering finding for {}",
                    site.site_id
                )
            });
        assert_eq!(site.status, LoweringGapStatus::Resolved);
        assert!(site.parser_ready_syntax);
        assert!(site.execution_ready_semantics);
        assert_eq!(finding.status, ZeroPlaceholderStatus::Resolved);
        assert!(
            finding
                .observed_behavior
                .contains("parser_ready_syntax=true")
        );
        assert!(
            finding
                .observed_behavior
                .contains("execution_ready_semantics=true")
        );
        assert!(finding.observed_behavior.contains(site.status.as_str()));
    }
}

#[test]
fn lowering_truth_consumer_parity_bundle_has_required_replay_artifacts() {
    let out_dir = unique_dir("bundle");
    let command = "CARGO_INCREMENTAL=0 cargo test -p frankenengine-engine lowering".to_string();
    let artifacts =
        write_lowering_gap_inventory_bundle(&out_dir, &[command]).expect("write lowering bundle");

    let required_paths = [
        artifacts.inventory_path.clone(),
        artifacts.trace_ids_path.clone(),
        artifacts.run_manifest_path.clone(),
        artifacts.events_path.clone(),
        artifacts.commands_path.clone(),
        artifacts.consumer_parity_report_path.clone(),
        artifacts.step_logs_dir.join("step_000_generate.log"),
    ];
    for path in required_paths {
        assert!(
            path.exists(),
            "missing required artifact {}",
            path.display()
        );
    }

    let manifest: LoweringGapInventoryRunManifest =
        serde_json::from_slice(&fs::read(&artifacts.run_manifest_path).expect("read manifest"))
            .expect("manifest json");
    let artifact_names = BTreeSet::from([
        manifest.artifact_paths.lowering_gap_inventory,
        manifest.artifact_paths.trace_ids,
        manifest.artifact_paths.run_manifest,
        manifest.artifact_paths.events_jsonl,
        manifest.artifact_paths.commands_txt,
        manifest.artifact_paths.step_logs,
        manifest.artifact_paths.consumer_parity_report,
    ]);
    assert!(artifact_names.contains("lowering_gap_inventory.json"));
    assert!(artifact_names.contains("trace_ids.json"));
    assert!(artifact_names.contains("run_manifest.json"));
    assert!(artifact_names.contains("events.jsonl"));
    assert!(artifact_names.contains("commands.txt"));
    assert!(artifact_names.contains("step_logs"));
    assert!(artifact_names.contains("lowering_gap_truth_consumer_parity_report.json"));
}

#[test]
fn lowering_truth_consumer_parity_report_records_both_consumers_per_site() {
    let out_dir = unique_dir("report");
    let artifacts = write_lowering_gap_inventory_bundle(&out_dir, &[String::from("parity")])
        .expect("write lowering bundle");
    let report: LoweringGapTruthConsumerParityReport = serde_json::from_slice(
        &fs::read(&artifacts.consumer_parity_report_path).expect("read parity report"),
    )
    .expect("parity report json");

    assert!(report.all_consumers_agree);
    assert_eq!(report.site_count as usize, LoweringGapSiteId::ALL.len());
    assert_eq!(report.consumer_count, 2);

    let mut consumers_by_site: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for record in &report.records {
        assert_eq!(record.status, LoweringGapStatus::Resolved);
        assert!(record.parser_ready_syntax);
        assert!(record.execution_ready_semantics);
        assert_eq!(record.zero_placeholder_status, "resolved");
        assert!(record.parity_ok);
        consumers_by_site
            .entry(record.site_id.clone())
            .or_default()
            .insert(record.consumer_name.clone());
    }

    for site in LoweringGapSiteId::ALL {
        let consumers = consumers_by_site
            .get(site.as_str())
            .unwrap_or_else(|| panic!("missing parity records for {}", site.as_str()));
        assert!(consumers.contains("lowering_gap_inventory"));
        assert!(consumers.contains("zero_placeholder_scan"));
    }
}
