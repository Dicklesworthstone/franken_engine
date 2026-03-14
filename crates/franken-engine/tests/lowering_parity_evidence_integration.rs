//! Integration tests for the lowering_parity_evidence module.
//!
//! Tests the parser-to-lowering parity evidence contract, verdict computation,
//! inventory construction, bundle artifacts, serde round-trips, and manifest
//! integrity.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use frankenengine_engine::lowering_parity_evidence::{
    PARITY_EVIDENCE_COMPONENT, PARITY_EVIDENCE_EVENT_SCHEMA_VERSION,
    PARITY_EVIDENCE_MANIFEST_SCHEMA_VERSION, PARITY_EVIDENCE_POLICY_ID,
    PARITY_EVIDENCE_SCHEMA_VERSION, ParityEvidenceArtifactPaths, ParityEvidenceEvent,
    ParityEvidenceInventory, ParityEvidenceRunManifest, ParityFinding, ParityVerdict,
};

fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tid = std::thread::current().id();
    std::env::temp_dir().join(format!("{prefix}-integration-{ts}-{tid:?}"))
}

// ── ParityVerdict ──

#[test]
fn parity_verdict_as_str_round_trips_all_variants() {
    let variants = [
        (ParityVerdict::Covered, "covered"),
        (ParityVerdict::FailClosedAgreed, "fail_closed_agreed"),
        (ParityVerdict::ParserLeadsLowering, "parser_leads_lowering"),
        (ParityVerdict::LoweringLeadsParser, "lowering_leads_parser"),
        (ParityVerdict::OpenGap, "open_gap"),
    ];
    for (v, expected) in variants {
        assert_eq!(v.as_str(), expected);
    }
}

#[test]
fn parity_verdict_is_parity_violation_only_for_parser_leads() {
    assert!(!ParityVerdict::Covered.is_parity_violation());
    assert!(!ParityVerdict::FailClosedAgreed.is_parity_violation());
    assert!(ParityVerdict::ParserLeadsLowering.is_parity_violation());
    assert!(!ParityVerdict::LoweringLeadsParser.is_parity_violation());
    assert!(!ParityVerdict::OpenGap.is_parity_violation());
}

#[test]
fn parity_verdict_serde_round_trip() {
    let variants = [
        ParityVerdict::Covered,
        ParityVerdict::FailClosedAgreed,
        ParityVerdict::ParserLeadsLowering,
        ParityVerdict::LoweringLeadsParser,
        ParityVerdict::OpenGap,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let back: ParityVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn parity_verdict_json_uses_snake_case() {
    let json = serde_json::to_string(&ParityVerdict::FailClosedAgreed).unwrap();
    assert_eq!(json, "\"fail_closed_agreed\"");
    let json = serde_json::to_string(&ParityVerdict::ParserLeadsLowering).unwrap();
    assert_eq!(json, "\"parser_leads_lowering\"");
}

#[test]
fn parity_verdict_ordering_is_consistent() {
    assert!(ParityVerdict::Covered < ParityVerdict::FailClosedAgreed);
    assert!(ParityVerdict::FailClosedAgreed < ParityVerdict::ParserLeadsLowering);
    assert!(ParityVerdict::ParserLeadsLowering < ParityVerdict::LoweringLeadsParser);
    assert!(ParityVerdict::LoweringLeadsParser < ParityVerdict::OpenGap);
}

// ── ParityFinding ──

fn sample_finding(verdict: ParityVerdict) -> ParityFinding {
    ParityFinding {
        site_id: "test_site".to_string(),
        feature_family: "test_family".to_string(),
        parser_status: "resolved".to_string(),
        lowering_status: "resolved".to_string(),
        verdict,
        diagnostic_code: "FE-TEST-0001".to_string(),
    }
}

#[test]
fn parity_finding_serde_round_trip() {
    let finding = sample_finding(ParityVerdict::Covered);
    let json = serde_json::to_string(&finding).unwrap();
    let back: ParityFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding, back);
}

#[test]
fn parity_finding_json_field_names() {
    let finding = sample_finding(ParityVerdict::Covered);
    let json = serde_json::to_string(&finding).unwrap();
    assert!(json.contains("\"site_id\""));
    assert!(json.contains("\"feature_family\""));
    assert!(json.contains("\"parser_status\""));
    assert!(json.contains("\"lowering_status\""));
    assert!(json.contains("\"verdict\""));
    assert!(json.contains("\"diagnostic_code\""));
}

#[test]
fn parity_finding_all_verdicts_serde_round_trip() {
    for v in [
        ParityVerdict::Covered,
        ParityVerdict::FailClosedAgreed,
        ParityVerdict::ParserLeadsLowering,
        ParityVerdict::LoweringLeadsParser,
        ParityVerdict::OpenGap,
    ] {
        let finding = sample_finding(v);
        let json = serde_json::to_string(&finding).unwrap();
        let back: ParityFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(finding.verdict, back.verdict);
    }
}

// ── ParityEvidenceInventory ──

#[test]
fn inventory_from_live_data_has_findings() {
    let inventory = frankenengine_engine::lowering_parity_evidence::parity_evidence_inventory();
    assert!(
        !inventory.findings.is_empty(),
        "live inventory should have findings"
    );
}

#[test]
fn inventory_schema_version_is_correct() {
    let inventory = frankenengine_engine::lowering_parity_evidence::parity_evidence_inventory();
    assert_eq!(inventory.schema_version, PARITY_EVIDENCE_SCHEMA_VERSION);
}

#[test]
fn inventory_component_is_correct() {
    let inventory = frankenengine_engine::lowering_parity_evidence::parity_evidence_inventory();
    assert_eq!(inventory.component, PARITY_EVIDENCE_COMPONENT);
}

#[test]
fn inventory_contract_currently_satisfied() {
    let inventory = frankenengine_engine::lowering_parity_evidence::parity_evidence_inventory();
    assert!(
        inventory.contract_satisfied(),
        "contract should be satisfied; violations={}",
        inventory.parity_violation_count()
    );
}

#[test]
fn inventory_zero_parity_violations() {
    let inventory = frankenengine_engine::lowering_parity_evidence::parity_evidence_inventory();
    assert_eq!(inventory.parity_violation_count(), 0);
}

#[test]
fn inventory_zero_open_gaps() {
    let inventory = frankenengine_engine::lowering_parity_evidence::parity_evidence_inventory();
    assert_eq!(inventory.open_gap_count(), 0);
}

#[test]
fn inventory_all_findings_are_covered() {
    let inventory = frankenengine_engine::lowering_parity_evidence::parity_evidence_inventory();
    assert_eq!(inventory.covered_count(), inventory.findings.len());
}

#[test]
fn inventory_finding_count_consistency() {
    let inventory = frankenengine_engine::lowering_parity_evidence::parity_evidence_inventory();
    let total = inventory.covered_count()
        + inventory.fail_closed_agreed_count()
        + inventory.parity_violation_count()
        + inventory.open_gap_count();
    // LoweringLeadsParser findings aren't counted by the above, so use <=
    assert!(total <= inventory.findings.len());
}

#[test]
fn inventory_findings_sorted_by_site_id() {
    let inventory = frankenengine_engine::lowering_parity_evidence::parity_evidence_inventory();
    for window in inventory.findings.windows(2) {
        assert!(
            window[0].site_id <= window[1].site_id,
            "findings should be sorted by site_id: {} > {}",
            window[0].site_id,
            window[1].site_id
        );
    }
}

#[test]
fn inventory_serde_round_trip() {
    let inventory = frankenengine_engine::lowering_parity_evidence::parity_evidence_inventory();
    let json = serde_json::to_string(&inventory).unwrap();
    let back: ParityEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inventory, back);
}

#[test]
fn inventory_deterministic_across_calls() {
    let inv1 = frankenengine_engine::lowering_parity_evidence::parity_evidence_inventory();
    let inv2 = frankenengine_engine::lowering_parity_evidence::parity_evidence_inventory();
    assert_eq!(inv1, inv2);
}

#[test]
fn inventory_findings_have_valid_structure() {
    let inventory = frankenengine_engine::lowering_parity_evidence::parity_evidence_inventory();
    for finding in &inventory.findings {
        assert!(!finding.site_id.is_empty(), "site_id should not be empty");
        assert!(
            !finding.feature_family.is_empty(),
            "feature_family should not be empty"
        );
        assert!(
            !finding.parser_status.is_empty(),
            "parser_status should not be empty"
        );
        assert!(
            !finding.lowering_status.is_empty(),
            "lowering_status should not be empty"
        );
        assert!(
            !finding.diagnostic_code.is_empty(),
            "diagnostic_code should not be empty"
        );
    }
}

#[test]
fn inventory_no_missing_statuses() {
    let inventory = frankenengine_engine::lowering_parity_evidence::parity_evidence_inventory();
    for finding in &inventory.findings {
        assert_ne!(finding.parser_status, "missing");
        assert_ne!(finding.lowering_status, "missing");
    }
}

// ── write_parity_evidence_bundle ──

#[test]
fn bundle_write_creates_all_artifact_files() {
    let out_dir = unique_temp_dir("parity-bundle");
    let commands = vec![
        "franken_parity_evidence".to_string(),
        "--out-dir".to_string(),
        out_dir.display().to_string(),
    ];
    let artifacts = frankenengine_engine::lowering_parity_evidence::write_parity_evidence_bundle(
        &out_dir, &commands,
    )
    .expect("bundle write");
    assert!(artifacts.inventory_path.exists());
    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.events_path.exists());
    assert!(artifacts.commands_path.exists());
}

#[test]
fn bundle_inventory_file_is_valid_json() {
    let out_dir = unique_temp_dir("parity-inv-json");
    let commands = vec!["test".to_string()];
    let artifacts = frankenengine_engine::lowering_parity_evidence::write_parity_evidence_bundle(
        &out_dir, &commands,
    )
    .unwrap();
    let contents = std::fs::read_to_string(&artifacts.inventory_path).unwrap();
    let inv: ParityEvidenceInventory = serde_json::from_str(&contents).unwrap();
    assert!(!inv.findings.is_empty());
}

#[test]
fn bundle_manifest_is_valid_json() {
    let out_dir = unique_temp_dir("parity-manifest-json");
    let commands = vec!["test".to_string()];
    let artifacts = frankenengine_engine::lowering_parity_evidence::write_parity_evidence_bundle(
        &out_dir, &commands,
    )
    .unwrap();
    let contents = std::fs::read_to_string(&artifacts.run_manifest_path).unwrap();
    let manifest: ParityEvidenceRunManifest = serde_json::from_str(&contents).unwrap();
    assert_eq!(
        manifest.schema_version,
        PARITY_EVIDENCE_MANIFEST_SCHEMA_VERSION
    );
    assert_eq!(manifest.component, PARITY_EVIDENCE_COMPONENT);
    assert_eq!(manifest.policy_id, PARITY_EVIDENCE_POLICY_ID);
}

#[test]
fn bundle_manifest_contract_satisfied() {
    let out_dir = unique_temp_dir("parity-contract");
    let commands = vec!["test".to_string()];
    let artifacts = frankenengine_engine::lowering_parity_evidence::write_parity_evidence_bundle(
        &out_dir, &commands,
    )
    .unwrap();
    let contents = std::fs::read_to_string(&artifacts.run_manifest_path).unwrap();
    let manifest: ParityEvidenceRunManifest = serde_json::from_str(&contents).unwrap();
    assert!(manifest.contract_satisfied);
    assert_eq!(manifest.parity_violation_count, 0);
}

#[test]
fn bundle_manifest_finding_count_matches_inventory() {
    let out_dir = unique_temp_dir("parity-count");
    let commands = vec!["test".to_string()];
    let artifacts = frankenengine_engine::lowering_parity_evidence::write_parity_evidence_bundle(
        &out_dir, &commands,
    )
    .unwrap();
    let inv: ParityEvidenceInventory =
        serde_json::from_str(&std::fs::read_to_string(&artifacts.inventory_path).unwrap()).unwrap();
    let manifest: ParityEvidenceRunManifest =
        serde_json::from_str(&std::fs::read_to_string(&artifacts.run_manifest_path).unwrap())
            .unwrap();
    assert_eq!(manifest.finding_count, inv.findings.len() as u64);
    assert_eq!(manifest.covered_count, inv.covered_count() as u64);
    assert_eq!(manifest.open_gap_count, inv.open_gap_count() as u64);
}

#[test]
fn bundle_manifest_hash_matches_artifacts_hash() {
    let out_dir = unique_temp_dir("parity-hash");
    let commands = vec!["test".to_string()];
    let artifacts = frankenengine_engine::lowering_parity_evidence::write_parity_evidence_bundle(
        &out_dir, &commands,
    )
    .unwrap();
    let manifest: ParityEvidenceRunManifest =
        serde_json::from_str(&std::fs::read_to_string(&artifacts.run_manifest_path).unwrap())
            .unwrap();
    assert_eq!(manifest.inventory_hash, artifacts.inventory_hash);
    assert!(!artifacts.inventory_hash.is_empty());
}

#[test]
fn bundle_events_has_start_findings_and_end() {
    let out_dir = unique_temp_dir("parity-events");
    let commands = vec!["test".to_string()];
    let artifacts = frankenengine_engine::lowering_parity_evidence::write_parity_evidence_bundle(
        &out_dir, &commands,
    )
    .unwrap();
    let events_str = std::fs::read_to_string(&artifacts.events_path).unwrap();
    let lines: Vec<&str> = events_str.lines().collect();
    assert!(lines.len() >= 3, "need at least start + 1 finding + end");

    let first: ParityEvidenceEvent = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(first.event, "parity_evidence_run_started");

    let last: ParityEvidenceEvent = serde_json::from_str(lines[lines.len() - 1]).unwrap();
    assert_eq!(last.event, "parity_evidence_run_completed");
}

#[test]
fn bundle_events_findings_match_inventory_count() {
    let out_dir = unique_temp_dir("parity-event-count");
    let commands = vec!["test".to_string()];
    let artifacts = frankenengine_engine::lowering_parity_evidence::write_parity_evidence_bundle(
        &out_dir, &commands,
    )
    .unwrap();
    let inv: ParityEvidenceInventory =
        serde_json::from_str(&std::fs::read_to_string(&artifacts.inventory_path).unwrap()).unwrap();
    let events_str = std::fs::read_to_string(&artifacts.events_path).unwrap();
    // events = 1 start + N findings + 1 end
    assert_eq!(events_str.lines().count(), inv.findings.len() + 2);
}

#[test]
fn bundle_commands_file_contains_input() {
    let out_dir = unique_temp_dir("parity-cmds");
    let commands = vec![
        "franken_parity_evidence".to_string(),
        "--out-dir".to_string(),
        "/tmp/test".to_string(),
    ];
    let artifacts = frankenengine_engine::lowering_parity_evidence::write_parity_evidence_bundle(
        &out_dir, &commands,
    )
    .unwrap();
    let cmds = std::fs::read_to_string(&artifacts.commands_path).unwrap();
    assert!(cmds.contains("franken_parity_evidence"));
    assert!(cmds.contains("--out-dir"));
}

#[test]
fn bundle_deterministic_hash() {
    let dir1 = unique_temp_dir("parity-det-1");
    let dir2 = unique_temp_dir("parity-det-2");
    let cmds = vec!["test".to_string()];
    let a1 =
        frankenengine_engine::lowering_parity_evidence::write_parity_evidence_bundle(&dir1, &cmds)
            .unwrap();
    let a2 =
        frankenengine_engine::lowering_parity_evidence::write_parity_evidence_bundle(&dir2, &cmds)
            .unwrap();
    assert_eq!(a1.inventory_hash, a2.inventory_hash);
}

// ── ParityEvidenceRunManifest serde ──

#[test]
fn manifest_serde_round_trip() {
    let manifest = ParityEvidenceRunManifest {
        schema_version: PARITY_EVIDENCE_MANIFEST_SCHEMA_VERSION.to_string(),
        component: PARITY_EVIDENCE_COMPONENT.to_string(),
        trace_id: "test-trace".to_string(),
        decision_id: "test-decision".to_string(),
        policy_id: PARITY_EVIDENCE_POLICY_ID.to_string(),
        inventory_hash: "abc123".to_string(),
        finding_count: 6,
        covered_count: 6,
        fail_closed_agreed_count: 0,
        parity_violation_count: 0,
        open_gap_count: 0,
        contract_satisfied: true,
        artifact_paths: ParityEvidenceArtifactPaths {
            parity_evidence_inventory: "inv.json".to_string(),
            run_manifest: "manifest.json".to_string(),
            events_jsonl: "events.jsonl".to_string(),
            commands_txt: "commands.txt".to_string(),
        },
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let back: ParityEvidenceRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

#[test]
fn manifest_json_field_names_stable() {
    let manifest = ParityEvidenceRunManifest {
        schema_version: PARITY_EVIDENCE_MANIFEST_SCHEMA_VERSION.to_string(),
        component: PARITY_EVIDENCE_COMPONENT.to_string(),
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        inventory_hash: "h".to_string(),
        finding_count: 1,
        covered_count: 1,
        fail_closed_agreed_count: 0,
        parity_violation_count: 0,
        open_gap_count: 0,
        contract_satisfied: true,
        artifact_paths: ParityEvidenceArtifactPaths {
            parity_evidence_inventory: "a".to_string(),
            run_manifest: "b".to_string(),
            events_jsonl: "c".to_string(),
            commands_txt: "d".to_string(),
        },
    };
    let json = serde_json::to_string(&manifest).unwrap();
    for field in [
        "schema_version",
        "component",
        "trace_id",
        "decision_id",
        "policy_id",
        "inventory_hash",
        "finding_count",
        "covered_count",
        "fail_closed_agreed_count",
        "parity_violation_count",
        "open_gap_count",
        "contract_satisfied",
        "artifact_paths",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

// ── ParityEvidenceEvent serde ──

#[test]
fn event_serde_round_trip() {
    let event = ParityEvidenceEvent {
        schema_version: PARITY_EVIDENCE_EVENT_SCHEMA_VERSION.to_string(),
        component: PARITY_EVIDENCE_COMPONENT.to_string(),
        event: "test_event".to_string(),
        policy_id: PARITY_EVIDENCE_POLICY_ID.to_string(),
        site_id: Some("test_site".to_string()),
        verdict: Some("covered".to_string()),
        detail: Some("test detail".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ParityEvidenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn event_with_none_fields_serde_round_trip() {
    let event = ParityEvidenceEvent {
        schema_version: PARITY_EVIDENCE_EVENT_SCHEMA_VERSION.to_string(),
        component: PARITY_EVIDENCE_COMPONENT.to_string(),
        event: "start".to_string(),
        policy_id: PARITY_EVIDENCE_POLICY_ID.to_string(),
        site_id: None,
        verdict: None,
        detail: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ParityEvidenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ── Constants ──

#[test]
fn schema_version_constants_not_empty() {
    assert!(!PARITY_EVIDENCE_SCHEMA_VERSION.is_empty());
    assert!(!PARITY_EVIDENCE_MANIFEST_SCHEMA_VERSION.is_empty());
    assert!(!PARITY_EVIDENCE_EVENT_SCHEMA_VERSION.is_empty());
    assert!(!PARITY_EVIDENCE_COMPONENT.is_empty());
    assert!(!PARITY_EVIDENCE_POLICY_ID.is_empty());
}

#[test]
fn schema_version_has_expected_prefix() {
    assert!(PARITY_EVIDENCE_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(PARITY_EVIDENCE_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(PARITY_EVIDENCE_EVENT_SCHEMA_VERSION.starts_with("franken-engine."));
}

// ── Clone / Debug / PartialEq on all exported types ──

#[test]
fn test_parity_verdict_clone_is_copy_equivalent() {
    let original = ParityVerdict::FailClosedAgreed;
    let cloned = original.clone();
    assert_eq!(original, cloned);
    // ParityVerdict is Copy, so the original should still be usable.
    let _ = original.as_str();
}

#[test]
fn test_parity_verdict_debug_contains_variant_name() {
    assert!(format!("{:?}", ParityVerdict::Covered).contains("Covered"));
    assert!(format!("{:?}", ParityVerdict::FailClosedAgreed).contains("FailClosedAgreed"));
    assert!(format!("{:?}", ParityVerdict::ParserLeadsLowering).contains("ParserLeadsLowering"));
    assert!(format!("{:?}", ParityVerdict::LoweringLeadsParser).contains("LoweringLeadsParser"));
    assert!(format!("{:?}", ParityVerdict::OpenGap).contains("OpenGap"));
}

#[test]
fn test_parity_finding_clone_equals_original() {
    let finding = sample_finding(ParityVerdict::LoweringLeadsParser);
    let cloned = finding.clone();
    assert_eq!(finding, cloned);
}

#[test]
fn test_parity_finding_debug_contains_site_id() {
    let finding = sample_finding(ParityVerdict::OpenGap);
    let dbg = format!("{:?}", finding);
    assert!(dbg.contains("test_site"));
}

#[test]
fn test_parity_evidence_inventory_clone_equals_original() {
    let inv = frankenengine_engine::lowering_parity_evidence::parity_evidence_inventory();
    let cloned = inv.clone();
    assert_eq!(inv, cloned);
}

#[test]
fn test_parity_evidence_inventory_debug_is_non_empty() {
    let inv = frankenengine_engine::lowering_parity_evidence::parity_evidence_inventory();
    let dbg = format!("{:?}", inv);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("ParityEvidenceInventory"));
}

#[test]
fn test_parity_evidence_event_clone_equals_original() {
    let event = ParityEvidenceEvent {
        schema_version: PARITY_EVIDENCE_EVENT_SCHEMA_VERSION.to_string(),
        component: PARITY_EVIDENCE_COMPONENT.to_string(),
        event: "clone_test".to_string(),
        policy_id: PARITY_EVIDENCE_POLICY_ID.to_string(),
        site_id: Some("site_x".to_string()),
        verdict: Some("covered".to_string()),
        detail: Some("detail text".to_string()),
    };
    let cloned = event.clone();
    assert_eq!(event, cloned);
}

#[test]
fn test_parity_evidence_event_debug_contains_event_field() {
    let event = ParityEvidenceEvent {
        schema_version: PARITY_EVIDENCE_EVENT_SCHEMA_VERSION.to_string(),
        component: PARITY_EVIDENCE_COMPONENT.to_string(),
        event: "debug_event_name".to_string(),
        policy_id: PARITY_EVIDENCE_POLICY_ID.to_string(),
        site_id: None,
        verdict: None,
        detail: None,
    };
    let dbg = format!("{:?}", event);
    assert!(dbg.contains("debug_event_name"));
}

#[test]
fn test_parity_evidence_run_manifest_clone_equals_original() {
    let manifest = ParityEvidenceRunManifest {
        schema_version: PARITY_EVIDENCE_MANIFEST_SCHEMA_VERSION.to_string(),
        component: PARITY_EVIDENCE_COMPONENT.to_string(),
        trace_id: "clone-trace".to_string(),
        decision_id: "clone-decision".to_string(),
        policy_id: PARITY_EVIDENCE_POLICY_ID.to_string(),
        inventory_hash: "cafebabe".to_string(),
        finding_count: 3,
        covered_count: 2,
        fail_closed_agreed_count: 1,
        parity_violation_count: 0,
        open_gap_count: 0,
        contract_satisfied: true,
        artifact_paths: ParityEvidenceArtifactPaths {
            parity_evidence_inventory: "i.json".to_string(),
            run_manifest: "m.json".to_string(),
            events_jsonl: "e.jsonl".to_string(),
            commands_txt: "c.txt".to_string(),
        },
    };
    let cloned = manifest.clone();
    assert_eq!(manifest, cloned);
}

#[test]
fn test_parity_evidence_artifact_paths_clone_and_debug() {
    let paths = ParityEvidenceArtifactPaths {
        parity_evidence_inventory: "inv.json".to_string(),
        run_manifest: "run.json".to_string(),
        events_jsonl: "events.jsonl".to_string(),
        commands_txt: "commands.txt".to_string(),
    };
    let cloned = paths.clone();
    assert_eq!(paths, cloned);
    let dbg = format!("{:?}", paths);
    assert!(dbg.contains("inv.json"));
}

#[test]
fn test_parity_evidence_artifact_paths_serde_round_trip() {
    let paths = ParityEvidenceArtifactPaths {
        parity_evidence_inventory: "parity_evidence_inventory.json".to_string(),
        run_manifest: "run_manifest.json".to_string(),
        events_jsonl: "events.jsonl".to_string(),
        commands_txt: "commands.txt".to_string(),
    };
    let json = serde_json::to_string(&paths).unwrap();
    let back: ParityEvidenceArtifactPaths = serde_json::from_str(&json).unwrap();
    assert_eq!(paths, back);
}

// ── Inventory count correctness with hand-crafted findings ──

#[test]
fn test_inventory_only_fail_closed_agreed_findings() {
    let inv = ParityEvidenceInventory {
        schema_version: PARITY_EVIDENCE_SCHEMA_VERSION.to_string(),
        component: PARITY_EVIDENCE_COMPONENT.to_string(),
        findings: vec![
            ParityFinding {
                site_id: "s1".to_string(),
                feature_family: "fam".to_string(),
                parser_status: "fail_closed".to_string(),
                lowering_status: "fail_closed".to_string(),
                verdict: ParityVerdict::FailClosedAgreed,
                diagnostic_code: "FE-F1".to_string(),
            },
            ParityFinding {
                site_id: "s2".to_string(),
                feature_family: "fam".to_string(),
                parser_status: "fail_closed".to_string(),
                lowering_status: "fail_closed".to_string(),
                verdict: ParityVerdict::FailClosedAgreed,
                diagnostic_code: "FE-F2".to_string(),
            },
        ],
    };
    assert_eq!(inv.fail_closed_agreed_count(), 2);
    assert_eq!(inv.covered_count(), 0);
    assert_eq!(inv.parity_violation_count(), 0);
    assert_eq!(inv.open_gap_count(), 0);
    // Contract is satisfied when there are no parser-leads-lowering violations.
    assert!(inv.contract_satisfied());
}

#[test]
fn test_inventory_only_open_gap_findings() {
    let inv = ParityEvidenceInventory {
        schema_version: PARITY_EVIDENCE_SCHEMA_VERSION.to_string(),
        component: PARITY_EVIDENCE_COMPONENT.to_string(),
        findings: vec![ParityFinding {
            site_id: "gap1".to_string(),
            feature_family: "fam_gap".to_string(),
            parser_status: "open_placeholder".to_string(),
            lowering_status: "open_placeholder".to_string(),
            verdict: ParityVerdict::OpenGap,
            diagnostic_code: "FE-G1".to_string(),
        }],
    };
    assert_eq!(inv.open_gap_count(), 1);
    assert_eq!(inv.covered_count(), 0);
    assert_eq!(inv.parity_violation_count(), 0);
    // No ParserLeadsLowering => still satisfied.
    assert!(inv.contract_satisfied());
}

#[test]
fn test_inventory_lowering_leads_parser_not_counted_by_named_counters() {
    let inv = ParityEvidenceInventory {
        schema_version: PARITY_EVIDENCE_SCHEMA_VERSION.to_string(),
        component: PARITY_EVIDENCE_COMPONENT.to_string(),
        findings: vec![
            ParityFinding {
                site_id: "llp1".to_string(),
                feature_family: "fam".to_string(),
                parser_status: "missing".to_string(),
                lowering_status: "resolved".to_string(),
                verdict: ParityVerdict::LoweringLeadsParser,
                diagnostic_code: "FE-L1".to_string(),
            },
            ParityFinding {
                site_id: "cov1".to_string(),
                feature_family: "fam".to_string(),
                parser_status: "resolved".to_string(),
                lowering_status: "resolved".to_string(),
                verdict: ParityVerdict::Covered,
                diagnostic_code: "FE-C1".to_string(),
            },
        ],
    };
    // LoweringLeadsParser is not counted by any of the four named counters.
    let named_total = inv.covered_count()
        + inv.fail_closed_agreed_count()
        + inv.parity_violation_count()
        + inv.open_gap_count();
    assert_eq!(
        named_total, 1,
        "LoweringLeadsParser should not be in named counts"
    );
    assert_eq!(inv.findings.len(), 2);
    // Contract still satisfied — no parser-leads-lowering violations.
    assert!(inv.contract_satisfied());
}

#[test]
fn test_inventory_multiple_violations_fails_contract() {
    let make_violation = |id: &str| ParityFinding {
        site_id: id.to_string(),
        feature_family: "fam".to_string(),
        parser_status: "resolved".to_string(),
        lowering_status: "open_placeholder".to_string(),
        verdict: ParityVerdict::ParserLeadsLowering,
        diagnostic_code: format!("FE-{id}"),
    };
    let inv = ParityEvidenceInventory {
        schema_version: PARITY_EVIDENCE_SCHEMA_VERSION.to_string(),
        component: PARITY_EVIDENCE_COMPONENT.to_string(),
        findings: vec![
            make_violation("V1"),
            make_violation("V2"),
            make_violation("V3"),
        ],
    };
    assert_eq!(inv.parity_violation_count(), 3);
    assert!(!inv.contract_satisfied());
}

// ── Bundle edge-cases ──

#[test]
fn test_bundle_with_empty_commands_slice() {
    let out_dir = unique_temp_dir("parity-empty-cmds");
    let artifacts =
        frankenengine_engine::lowering_parity_evidence::write_parity_evidence_bundle(&out_dir, &[])
            .expect("bundle write with empty commands");
    // commands.txt should exist (but may be empty)
    assert!(artifacts.commands_path.exists());
    let cmds = std::fs::read_to_string(&artifacts.commands_path).unwrap();
    assert_eq!(cmds, "");
}

#[test]
fn test_bundle_manifest_trace_and_decision_id_format() {
    let out_dir = unique_temp_dir("parity-trace-fmt");
    let artifacts = frankenengine_engine::lowering_parity_evidence::write_parity_evidence_bundle(
        &out_dir,
        &["cmd".to_string()],
    )
    .expect("write");
    let contents = std::fs::read_to_string(&artifacts.run_manifest_path).unwrap();
    let manifest: ParityEvidenceRunManifest = serde_json::from_str(&contents).unwrap();
    assert!(
        manifest.trace_id.starts_with("parity-evidence-"),
        "trace_id should start with 'parity-evidence-': {}",
        manifest.trace_id
    );
    assert!(
        manifest
            .decision_id
            .starts_with("decision-parity-evidence-"),
        "decision_id should start with 'decision-parity-evidence-': {}",
        manifest.decision_id
    );
}

#[test]
fn test_bundle_events_each_line_is_valid_json() {
    let out_dir = unique_temp_dir("parity-events-json");
    let artifacts = frankenengine_engine::lowering_parity_evidence::write_parity_evidence_bundle(
        &out_dir,
        &["cmd".to_string()],
    )
    .expect("write");
    let events_str = std::fs::read_to_string(&artifacts.events_path).unwrap();
    for (idx, line) in events_str.lines().enumerate() {
        let parsed: Result<ParityEvidenceEvent, _> = serde_json::from_str(line);
        assert!(
            parsed.is_ok(),
            "line {idx} is not valid JSON for ParityEvidenceEvent: {line}"
        );
    }
}

#[test]
fn test_bundle_finding_events_have_site_id_and_verdict() {
    let out_dir = unique_temp_dir("parity-finding-events");
    let artifacts = frankenengine_engine::lowering_parity_evidence::write_parity_evidence_bundle(
        &out_dir,
        &["cmd".to_string()],
    )
    .expect("write");
    let events_str = std::fs::read_to_string(&artifacts.events_path).unwrap();
    let lines: Vec<&str> = events_str.lines().collect();
    // Skip first (start) and last (end) lines; all middle lines are findings.
    for line in lines.iter().skip(1).take(lines.len().saturating_sub(2)) {
        let event: ParityEvidenceEvent = serde_json::from_str(line).unwrap();
        assert_eq!(event.event, "parity_finding_recorded");
        assert!(event.site_id.is_some(), "finding event should have site_id");
        assert!(event.verdict.is_some(), "finding event should have verdict");
    }
}

#[test]
fn test_bundle_event_schema_version_consistent() {
    let out_dir = unique_temp_dir("parity-ev-schema");
    let artifacts = frankenengine_engine::lowering_parity_evidence::write_parity_evidence_bundle(
        &out_dir,
        &["cmd".to_string()],
    )
    .expect("write");
    let events_str = std::fs::read_to_string(&artifacts.events_path).unwrap();
    for line in events_str.lines() {
        let event: ParityEvidenceEvent = serde_json::from_str(line).unwrap();
        assert_eq!(
            event.schema_version, PARITY_EVIDENCE_EVENT_SCHEMA_VERSION,
            "every event line must carry the correct schema_version"
        );
        assert_eq!(event.component, PARITY_EVIDENCE_COMPONENT);
        assert_eq!(event.policy_id, PARITY_EVIDENCE_POLICY_ID);
    }
}

// ── ParityVerdict: exhaustive as_str coverage ──

#[test]
fn test_parity_verdict_as_str_no_spaces() {
    for v in [
        ParityVerdict::Covered,
        ParityVerdict::FailClosedAgreed,
        ParityVerdict::ParserLeadsLowering,
        ParityVerdict::LoweringLeadsParser,
        ParityVerdict::OpenGap,
    ] {
        let s = v.as_str();
        assert!(
            !s.contains(' '),
            "as_str should use underscores, not spaces: {s}"
        );
    }
}

#[test]
fn test_parity_verdict_all_unique_as_str() {
    use std::collections::BTreeSet;
    let strs: BTreeSet<&str> = [
        ParityVerdict::Covered,
        ParityVerdict::FailClosedAgreed,
        ParityVerdict::ParserLeadsLowering,
        ParityVerdict::LoweringLeadsParser,
        ParityVerdict::OpenGap,
    ]
    .iter()
    .map(|v| v.as_str())
    .collect();
    assert_eq!(
        strs.len(),
        5,
        "all five variants must have distinct as_str values"
    );
}

#[test]
fn test_parity_verdict_partial_eq_symmetry() {
    assert_eq!(ParityVerdict::Covered, ParityVerdict::Covered);
    assert_ne!(ParityVerdict::Covered, ParityVerdict::OpenGap);
    assert_ne!(
        ParityVerdict::FailClosedAgreed,
        ParityVerdict::ParserLeadsLowering
    );
}
