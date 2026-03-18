//! Deep integration tests for lowering_parity_evidence module.
//!
//! Covers: parity inventory determinism, verdict computation edge cases,
//! serde roundtrips, evidence bundle filesystem artifacts, event generation,
//! and cross-surface contract validation.

use frankenengine_engine::lowering_parity_evidence::{
    PARITY_EVIDENCE_COMPONENT, PARITY_EVIDENCE_EVENT_SCHEMA_VERSION,
    PARITY_EVIDENCE_MANIFEST_SCHEMA_VERSION, PARITY_EVIDENCE_POLICY_ID,
    PARITY_EVIDENCE_SCHEMA_VERSION, ParityEvidenceArtifactPaths, ParityEvidenceEvent,
    ParityEvidenceInventory, ParityEvidenceRunManifest, ParityFinding, ParityVerdict,
    parity_evidence_inventory, write_parity_evidence_bundle,
};

use std::path::PathBuf;

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    std::env::temp_dir().join(format!("{}-{}-{}", prefix, pid, ts))
}

// ---------------------------------------------------------------------------
// Inventory determinism
// ---------------------------------------------------------------------------

#[test]
fn deep_inventory_deterministic_across_calls() {
    let inv1 = parity_evidence_inventory();
    let inv2 = parity_evidence_inventory();
    assert_eq!(inv1, inv2, "Two calls should produce identical inventories");
}

#[test]
fn deep_inventory_serde_roundtrip_exact() {
    let inv = parity_evidence_inventory();
    let json = serde_json::to_string_pretty(&inv).unwrap();
    let decoded: ParityEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, decoded);

    // Re-serialize and verify byte-identical JSON
    let json2 = serde_json::to_string_pretty(&decoded).unwrap();
    assert_eq!(json, json2);
}

#[test]
fn deep_inventory_schema_version_matches_constant() {
    let inv = parity_evidence_inventory();
    assert_eq!(inv.schema_version, PARITY_EVIDENCE_SCHEMA_VERSION);
}

#[test]
fn deep_inventory_component_matches_constant() {
    let inv = parity_evidence_inventory();
    assert_eq!(inv.component, PARITY_EVIDENCE_COMPONENT);
}

// ---------------------------------------------------------------------------
// Verdict logic
// ---------------------------------------------------------------------------

#[test]
fn deep_verdict_as_str_all_variants() {
    let expected = [
        (ParityVerdict::Covered, "covered"),
        (ParityVerdict::FailClosedAgreed, "fail_closed_agreed"),
        (ParityVerdict::ParserLeadsLowering, "parser_leads_lowering"),
        (ParityVerdict::LoweringLeadsParser, "lowering_leads_parser"),
        (ParityVerdict::OpenGap, "open_gap"),
    ];
    for (verdict, name) in expected {
        assert_eq!(verdict.as_str(), name);
    }
}

#[test]
fn deep_verdict_is_parity_violation_exhaustive() {
    assert!(!ParityVerdict::Covered.is_parity_violation());
    assert!(!ParityVerdict::FailClosedAgreed.is_parity_violation());
    assert!(ParityVerdict::ParserLeadsLowering.is_parity_violation());
    assert!(!ParityVerdict::LoweringLeadsParser.is_parity_violation());
    assert!(!ParityVerdict::OpenGap.is_parity_violation());
}

#[test]
fn deep_verdict_serde_roundtrip_all() {
    let verdicts = [
        ParityVerdict::Covered,
        ParityVerdict::FailClosedAgreed,
        ParityVerdict::ParserLeadsLowering,
        ParityVerdict::LoweringLeadsParser,
        ParityVerdict::OpenGap,
    ];
    for v in verdicts {
        let json = serde_json::to_string(&v).unwrap();
        let decoded: ParityVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, decoded);
    }
}

// ---------------------------------------------------------------------------
// Inventory contract properties
// ---------------------------------------------------------------------------

#[test]
fn deep_inventory_contract_satisfied() {
    let inv = parity_evidence_inventory();
    assert!(
        inv.contract_satisfied(),
        "Parity contract must be satisfied (no parser-leads-lowering violations)"
    );
}

#[test]
fn deep_inventory_no_parity_violations() {
    let inv = parity_evidence_inventory();
    assert_eq!(inv.parity_violation_count(), 0);
}

#[test]
fn deep_inventory_no_open_gaps() {
    let inv = parity_evidence_inventory();
    assert_eq!(inv.open_gap_count(), 0);
}

#[test]
fn deep_inventory_nonzero_covered() {
    let inv = parity_evidence_inventory();
    assert!(
        inv.covered_count() > 0,
        "Should have at least one covered finding"
    );
}

#[test]
fn deep_inventory_counts_add_up() {
    let inv = parity_evidence_inventory();
    let total = inv.covered_count()
        + inv.fail_closed_agreed_count()
        + inv.parity_violation_count()
        + inv.open_gap_count();
    // There might be LoweringLeadsParser which isn't in any of the above groups
    let lowering_leads = inv
        .findings
        .iter()
        .filter(|f| f.verdict == ParityVerdict::LoweringLeadsParser)
        .count();
    assert_eq!(
        inv.findings.len(),
        total + lowering_leads,
        "Sum of counted verdicts should equal total findings"
    );
}

// ---------------------------------------------------------------------------
// Finding structure validation
// ---------------------------------------------------------------------------

#[test]
fn deep_findings_non_empty_fields() {
    let inv = parity_evidence_inventory();
    for finding in &inv.findings {
        assert!(!finding.site_id.is_empty(), "site_id must not be empty");
        assert!(
            !finding.feature_family.is_empty(),
            "feature_family must not be empty for {}",
            finding.site_id
        );
        assert!(
            !finding.parser_status.is_empty(),
            "parser_status must not be empty for {}",
            finding.site_id
        );
        assert!(
            !finding.lowering_status.is_empty(),
            "lowering_status must not be empty for {}",
            finding.site_id
        );
        assert!(
            !finding.diagnostic_code.is_empty(),
            "diagnostic_code must not be empty for {}",
            finding.site_id
        );
    }
}

#[test]
fn deep_findings_sorted_by_site_id() {
    let inv = parity_evidence_inventory();
    let ids: Vec<&str> = inv.findings.iter().map(|f| f.site_id.as_str()).collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted, "Findings must be sorted by site_id");
}

#[test]
fn deep_findings_unique_site_ids() {
    let inv = parity_evidence_inventory();
    let mut seen = std::collections::BTreeSet::new();
    for finding in &inv.findings {
        assert!(
            seen.insert(&finding.site_id),
            "Duplicate site_id: {}",
            finding.site_id
        );
    }
}

#[test]
fn deep_finding_serde_roundtrip() {
    let finding = ParityFinding {
        site_id: "deep_test.roundtrip".to_string(),
        feature_family: "test_family".to_string(),
        parser_status: "resolved".to_string(),
        lowering_status: "resolved".to_string(),
        verdict: ParityVerdict::Covered,
        diagnostic_code: "FE-TEST-DEEP-001".to_string(),
    };
    let json = serde_json::to_string(&finding).unwrap();
    let decoded: ParityFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding, decoded);
}

// ---------------------------------------------------------------------------
// Event structure
// ---------------------------------------------------------------------------

#[test]
fn deep_event_serde_roundtrip() {
    let event = ParityEvidenceEvent {
        schema_version: PARITY_EVIDENCE_EVENT_SCHEMA_VERSION.to_string(),
        component: PARITY_EVIDENCE_COMPONENT.to_string(),
        event: "test_event".to_string(),
        policy_id: PARITY_EVIDENCE_POLICY_ID.to_string(),
        site_id: Some("test.site".to_string()),
        verdict: Some("covered".to_string()),
        detail: Some("detail for deep test".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let decoded: ParityEvidenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, decoded);
}

#[test]
fn deep_event_optional_fields_none() {
    let event = ParityEvidenceEvent {
        schema_version: PARITY_EVIDENCE_EVENT_SCHEMA_VERSION.to_string(),
        component: PARITY_EVIDENCE_COMPONENT.to_string(),
        event: "lifecycle_event".to_string(),
        policy_id: PARITY_EVIDENCE_POLICY_ID.to_string(),
        site_id: None,
        verdict: None,
        detail: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let decoded: ParityEvidenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, decoded);
    assert!(json.contains("null"));
}

// ---------------------------------------------------------------------------
// Run manifest structure
// ---------------------------------------------------------------------------

#[test]
fn deep_run_manifest_serde_roundtrip() {
    let manifest = ParityEvidenceRunManifest {
        schema_version: PARITY_EVIDENCE_MANIFEST_SCHEMA_VERSION.to_string(),
        component: PARITY_EVIDENCE_COMPONENT.to_string(),
        trace_id: "trace-deep-001".to_string(),
        decision_id: "decision-deep-001".to_string(),
        policy_id: PARITY_EVIDENCE_POLICY_ID.to_string(),
        inventory_hash: "abc123def456".to_string(),
        finding_count: 42,
        covered_count: 40,
        fail_closed_agreed_count: 2,
        parity_violation_count: 0,
        open_gap_count: 0,
        contract_satisfied: true,
        artifact_paths: ParityEvidenceArtifactPaths {
            parity_evidence_inventory: "inventory.json".to_string(),
            run_manifest: "manifest.json".to_string(),
            events_jsonl: "events.jsonl".to_string(),
            commands_txt: "commands.txt".to_string(),
        },
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let decoded: ParityEvidenceRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, decoded);
}

// ---------------------------------------------------------------------------
// Bundle write — filesystem artifacts
// ---------------------------------------------------------------------------

#[test]
fn deep_bundle_write_creates_all_artifacts() {
    let dir = unique_temp_dir("deep-parity-evidence-all-artifacts");
    let commands = vec!["deep_test_command".to_string()];
    let artifacts = write_parity_evidence_bundle(&dir, &commands).unwrap();

    assert!(artifacts.inventory_path.exists());
    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.events_path.exists());
    assert!(artifacts.commands_path.exists());
}

#[test]
fn deep_bundle_inventory_matches_direct_call() {
    let dir = unique_temp_dir("deep-parity-evidence-match");
    let commands = vec!["verify_match".to_string()];
    let artifacts = write_parity_evidence_bundle(&dir, &commands).unwrap();

    let written: ParityEvidenceInventory =
        serde_json::from_slice(&std::fs::read(&artifacts.inventory_path).unwrap()).unwrap();
    let direct = parity_evidence_inventory();
    assert_eq!(written, direct);
}

#[test]
fn deep_bundle_manifest_counts_match_inventory() {
    let dir = unique_temp_dir("deep-parity-evidence-counts");
    let commands = vec!["verify_counts".to_string()];
    let artifacts = write_parity_evidence_bundle(&dir, &commands).unwrap();

    let manifest: ParityEvidenceRunManifest =
        serde_json::from_slice(&std::fs::read(&artifacts.run_manifest_path).unwrap()).unwrap();
    let inventory = parity_evidence_inventory();

    assert_eq!(manifest.finding_count, inventory.findings.len() as u64);
    assert_eq!(manifest.covered_count, inventory.covered_count() as u64);
    assert_eq!(
        manifest.fail_closed_agreed_count,
        inventory.fail_closed_agreed_count() as u64
    );
    assert_eq!(
        manifest.parity_violation_count,
        inventory.parity_violation_count() as u64
    );
    assert_eq!(manifest.open_gap_count, inventory.open_gap_count() as u64);
    assert_eq!(manifest.contract_satisfied, inventory.contract_satisfied());
}

#[test]
fn deep_bundle_events_jsonl_valid() {
    let dir = unique_temp_dir("deep-parity-evidence-events");
    let commands = vec!["verify_events".to_string()];
    let artifacts = write_parity_evidence_bundle(&dir, &commands).unwrap();

    let events_text = std::fs::read_to_string(&artifacts.events_path).unwrap();
    for line in events_text.lines() {
        let event: ParityEvidenceEvent = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("Invalid event JSON: {}: {}", e, line));
        assert_eq!(event.schema_version, PARITY_EVIDENCE_EVENT_SCHEMA_VERSION);
        assert_eq!(event.component, PARITY_EVIDENCE_COMPONENT);
        assert!(!event.event.is_empty());
    }
}

#[test]
fn deep_bundle_events_have_start_and_end() {
    let dir = unique_temp_dir("deep-parity-evidence-start-end");
    let commands = vec!["verify_lifecycle".to_string()];
    let artifacts = write_parity_evidence_bundle(&dir, &commands).unwrap();

    let events_text = std::fs::read_to_string(&artifacts.events_path).unwrap();
    let events: Vec<ParityEvidenceEvent> = events_text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();

    assert!(events.len() >= 2, "Need at least start and end events");
    assert_eq!(events.first().unwrap().event, "parity_evidence_run_started");
    assert_eq!(
        events.last().unwrap().event,
        "parity_evidence_run_completed"
    );
}

#[test]
fn deep_bundle_events_include_finding_events() {
    let dir = unique_temp_dir("deep-parity-evidence-findings");
    let commands = vec!["verify_finding_events".to_string()];
    let artifacts = write_parity_evidence_bundle(&dir, &commands).unwrap();

    let events_text = std::fs::read_to_string(&artifacts.events_path).unwrap();
    let finding_events: Vec<ParityEvidenceEvent> = events_text
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .filter(|e: &ParityEvidenceEvent| e.event == "parity_finding_recorded")
        .collect();

    let inventory = parity_evidence_inventory();
    assert_eq!(
        finding_events.len(),
        inventory.findings.len(),
        "One event per finding"
    );
}

#[test]
fn deep_bundle_commands_written() {
    let dir = unique_temp_dir("deep-parity-evidence-commands");
    let commands = vec![
        "franken_parity_evidence".to_string(),
        "--verbose".to_string(),
        "--format=json".to_string(),
    ];
    let artifacts = write_parity_evidence_bundle(&dir, &commands).unwrap();

    let written = std::fs::read_to_string(&artifacts.commands_path).unwrap();
    assert!(written.contains("franken_parity_evidence"));
    assert!(written.contains("--verbose"));
    assert!(written.contains("--format=json"));
}

#[test]
fn deep_bundle_inventory_hash_nonempty() {
    let dir = unique_temp_dir("deep-parity-evidence-hash");
    let commands = vec!["verify_hash".to_string()];
    let artifacts = write_parity_evidence_bundle(&dir, &commands).unwrap();
    assert!(!artifacts.inventory_hash.is_empty());
}

#[test]
fn deep_bundle_inventory_hash_deterministic() {
    let dir1 = unique_temp_dir("deep-parity-evidence-det1");
    let dir2 = unique_temp_dir("deep-parity-evidence-det2");
    let commands = vec!["determinism_check".to_string()];

    let a1 = write_parity_evidence_bundle(&dir1, &commands).unwrap();
    let a2 = write_parity_evidence_bundle(&dir2, &commands).unwrap();
    assert_eq!(
        a1.inventory_hash, a2.inventory_hash,
        "Same inventory should produce same hash"
    );
}

#[test]
fn deep_bundle_manifest_trace_id_contains_hash() {
    let dir = unique_temp_dir("deep-parity-evidence-trace");
    let commands = vec!["verify_trace".to_string()];
    let artifacts = write_parity_evidence_bundle(&dir, &commands).unwrap();

    let manifest: ParityEvidenceRunManifest =
        serde_json::from_slice(&std::fs::read(&artifacts.run_manifest_path).unwrap()).unwrap();

    assert!(manifest.trace_id.starts_with("parity-evidence-"));
    assert!(manifest.trace_id.contains(&artifacts.inventory_hash[..12]));
}

// ---------------------------------------------------------------------------
// Artifact paths structure
// ---------------------------------------------------------------------------

#[test]
fn deep_artifact_paths_serde_roundtrip() {
    let paths = ParityEvidenceArtifactPaths {
        parity_evidence_inventory: "custom/inventory.json".to_string(),
        run_manifest: "custom/manifest.json".to_string(),
        events_jsonl: "custom/events.jsonl".to_string(),
        commands_txt: "custom/commands.txt".to_string(),
    };
    let json = serde_json::to_string(&paths).unwrap();
    let decoded: ParityEvidenceArtifactPaths = serde_json::from_str(&json).unwrap();
    assert_eq!(paths, decoded);
}

// ---------------------------------------------------------------------------
// Schema version constants
// ---------------------------------------------------------------------------

#[test]
fn deep_schema_versions_non_empty() {
    assert!(!PARITY_EVIDENCE_SCHEMA_VERSION.is_empty());
    assert!(!PARITY_EVIDENCE_MANIFEST_SCHEMA_VERSION.is_empty());
    assert!(!PARITY_EVIDENCE_EVENT_SCHEMA_VERSION.is_empty());
}

#[test]
fn deep_schema_versions_contain_component_name() {
    assert!(PARITY_EVIDENCE_SCHEMA_VERSION.contains("lowering-parity-evidence"));
    assert!(PARITY_EVIDENCE_MANIFEST_SCHEMA_VERSION.contains("lowering-parity-evidence"));
    assert!(PARITY_EVIDENCE_EVENT_SCHEMA_VERSION.contains("lowering-parity-evidence"));
}

#[test]
fn deep_policy_id_non_empty() {
    assert!(!PARITY_EVIDENCE_POLICY_ID.is_empty());
    assert!(PARITY_EVIDENCE_POLICY_ID.contains("lowering-parity-evidence"));
}

#[test]
fn deep_component_constant() {
    assert_eq!(PARITY_EVIDENCE_COMPONENT, "lowering_parity_evidence");
}

// ---------------------------------------------------------------------------
// Covered findings all have resolved status
// ---------------------------------------------------------------------------

#[test]
fn deep_covered_findings_have_resolved_status() {
    let inv = parity_evidence_inventory();
    for finding in inv
        .findings
        .iter()
        .filter(|f| f.verdict == ParityVerdict::Covered)
    {
        assert_eq!(
            finding.parser_status, "resolved",
            "Covered finding {} should have resolved parser status",
            finding.site_id
        );
        assert_eq!(
            finding.lowering_status, "resolved",
            "Covered finding {} should have resolved lowering status",
            finding.site_id
        );
    }
}

// ---------------------------------------------------------------------------
// Inventory cross-reference: every finding has consistent verdict
// ---------------------------------------------------------------------------

#[test]
fn deep_verdict_consistent_with_statuses() {
    let inv = parity_evidence_inventory();
    for finding in &inv.findings {
        match finding.verdict {
            ParityVerdict::Covered => {
                assert_eq!(finding.parser_status, "resolved");
                assert_eq!(finding.lowering_status, "resolved");
            }
            ParityVerdict::FailClosedAgreed => {
                assert_eq!(finding.parser_status, "fail_closed");
                assert_eq!(finding.lowering_status, "fail_closed");
            }
            ParityVerdict::ParserLeadsLowering => {
                assert_eq!(finding.parser_status, "resolved");
                assert!(
                    finding.lowering_status == "fail_closed"
                        || finding.lowering_status == "open_placeholder"
                        || finding.lowering_status == "missing"
                );
            }
            ParityVerdict::LoweringLeadsParser => {
                assert!(
                    finding.parser_status == "fail_closed"
                        || finding.parser_status == "open_placeholder"
                        || finding.parser_status == "missing"
                );
            }
            ParityVerdict::OpenGap => {
                assert!(
                    finding.parser_status == "open_placeholder"
                        || finding.parser_status == "fail_closed"
                );
                assert!(
                    finding.lowering_status == "open_placeholder"
                        || finding.lowering_status == "fail_closed"
                );
            }
        }
    }
}
