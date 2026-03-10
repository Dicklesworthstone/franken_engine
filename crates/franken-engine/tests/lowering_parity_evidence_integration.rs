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
