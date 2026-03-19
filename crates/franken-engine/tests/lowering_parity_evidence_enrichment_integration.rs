//! Enrichment integration tests for the lowering_parity_evidence module.
//!
//! Covers gaps not addressed by the base and deep integration test files:
//! content hash byte-level determinism, BTreeMap-based verdict aggregation,
//! serde pretty vs compact equivalence, cross-artifact consistency between
//! manifest inventory and events, large synthetic inventory stress tests,
//! JSON value-level structural validation, verdict ordering transitivity,
//! finding field boundary conditions, and bundle idempotency under
//! repeated writes to the same directory.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use frankenengine_engine::lowering_parity_evidence::{
    PARITY_EVIDENCE_COMPONENT, PARITY_EVIDENCE_EVENT_SCHEMA_VERSION,
    PARITY_EVIDENCE_MANIFEST_SCHEMA_VERSION, PARITY_EVIDENCE_POLICY_ID,
    PARITY_EVIDENCE_SCHEMA_VERSION, ParityEvidenceArtifactPaths, ParityEvidenceEvent,
    ParityEvidenceInventory, ParityEvidenceRunManifest, ParityFinding, ParityVerdict,
    parity_evidence_inventory, write_parity_evidence_bundle,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tid = std::thread::current().id();
    std::env::temp_dir().join(format!("{prefix}-enrichment-{ts}-{tid:?}"))
}

fn make_finding(site_id: &str, verdict: ParityVerdict) -> ParityFinding {
    let (parser, lowering) = match verdict {
        ParityVerdict::Covered => ("resolved", "resolved"),
        ParityVerdict::FailClosedAgreed => ("fail_closed", "fail_closed"),
        ParityVerdict::ParserLeadsLowering => ("resolved", "open_placeholder"),
        ParityVerdict::LoweringLeadsParser => ("missing", "resolved"),
        ParityVerdict::OpenGap => ("open_placeholder", "open_placeholder"),
    };
    ParityFinding {
        site_id: site_id.to_string(),
        feature_family: format!("family_{site_id}"),
        parser_status: parser.to_string(),
        lowering_status: lowering.to_string(),
        verdict,
        diagnostic_code: format!("FE-{}", site_id.to_uppercase()),
    }
}

fn make_inventory(findings: Vec<ParityFinding>) -> ParityEvidenceInventory {
    ParityEvidenceInventory {
        schema_version: PARITY_EVIDENCE_SCHEMA_VERSION.to_string(),
        component: PARITY_EVIDENCE_COMPONENT.to_string(),
        findings,
    }
}

fn all_verdicts() -> [ParityVerdict; 5] {
    [
        ParityVerdict::Covered,
        ParityVerdict::FailClosedAgreed,
        ParityVerdict::ParserLeadsLowering,
        ParityVerdict::LoweringLeadsParser,
        ParityVerdict::OpenGap,
    ]
}

// ---------------------------------------------------------------------------
// Verdict serde: pretty vs compact equivalence
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_verdict_pretty_vs_compact_equivalence() {
    for v in all_verdicts() {
        let compact = serde_json::to_string(&v).unwrap();
        let pretty = serde_json::to_string_pretty(&v).unwrap();
        let from_compact: ParityVerdict = serde_json::from_str(&compact).unwrap();
        let from_pretty: ParityVerdict = serde_json::from_str(&pretty).unwrap();
        assert_eq!(from_compact, from_pretty);
        assert_eq!(from_compact, v);
    }
}

// ---------------------------------------------------------------------------
// Verdict ordering transitivity
// ---------------------------------------------------------------------------

#[test]
fn enrichment_ordering_verdict_transitivity() {
    let verdicts = all_verdicts();
    for i in 0..verdicts.len() {
        for j in 0..verdicts.len() {
            for k in 0..verdicts.len() {
                if verdicts[i] <= verdicts[j] && verdicts[j] <= verdicts[k] {
                    assert!(
                        verdicts[i] <= verdicts[k],
                        "Transitivity violated: {:?} <= {:?} <= {:?} but {:?} > {:?}",
                        verdicts[i],
                        verdicts[j],
                        verdicts[k],
                        verdicts[i],
                        verdicts[k]
                    );
                }
            }
        }
    }
}

#[test]
fn enrichment_ordering_verdict_antisymmetry() {
    let verdicts = all_verdicts();
    for i in 0..verdicts.len() {
        for j in 0..verdicts.len() {
            if verdicts[i] <= verdicts[j] && verdicts[j] <= verdicts[i] {
                assert_eq!(verdicts[i], verdicts[j]);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Verdict as_str matches serde snake_case encoding bijection
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_verdict_as_str_is_serde_value() {
    for v in all_verdicts() {
        let serde_str: String = serde_json::from_str(&serde_json::to_string(&v).unwrap()).unwrap();
        assert_eq!(
            v.as_str(),
            serde_str,
            "as_str and serde encoding must agree for {:?}",
            v
        );
    }
}

// ---------------------------------------------------------------------------
// Display uniqueness: as_str produces 5 distinct strings
// ---------------------------------------------------------------------------

#[test]
fn enrichment_display_verdict_as_str_uniqueness_via_btreeset() {
    let strs: BTreeSet<&str> = all_verdicts().iter().map(|v| v.as_str()).collect();
    assert_eq!(
        strs.len(),
        5,
        "all five verdict variants must produce unique as_str values"
    );
}

// ---------------------------------------------------------------------------
// BTreeMap aggregation of findings by verdict
// ---------------------------------------------------------------------------

#[test]
fn enrichment_aggregation_findings_by_verdict_btreemap() {
    let inv = parity_evidence_inventory();
    let mut by_verdict: BTreeMap<ParityVerdict, usize> = BTreeMap::new();
    for finding in &inv.findings {
        *by_verdict.entry(finding.verdict).or_insert(0) += 1;
    }
    let covered = by_verdict
        .get(&ParityVerdict::Covered)
        .copied()
        .unwrap_or(0);
    assert_eq!(covered, inv.covered_count());
    let fc = by_verdict
        .get(&ParityVerdict::FailClosedAgreed)
        .copied()
        .unwrap_or(0);
    assert_eq!(fc, inv.fail_closed_agreed_count());
    let violations = by_verdict
        .get(&ParityVerdict::ParserLeadsLowering)
        .copied()
        .unwrap_or(0);
    assert_eq!(violations, inv.parity_violation_count());
    let gaps = by_verdict
        .get(&ParityVerdict::OpenGap)
        .copied()
        .unwrap_or(0);
    assert_eq!(gaps, inv.open_gap_count());
}

// ---------------------------------------------------------------------------
// Inventory serde: byte-identical re-serialization
// ---------------------------------------------------------------------------

#[test]
fn enrichment_determinism_inventory_serde_byte_identical_reserialization() {
    let inv = parity_evidence_inventory();
    let json1 = serde_json::to_string_pretty(&inv).unwrap();
    let decoded: ParityEvidenceInventory = serde_json::from_str(&json1).unwrap();
    let json2 = serde_json::to_string_pretty(&decoded).unwrap();
    assert_eq!(json1, json2, "re-serialized JSON must be byte-identical");
}

// ---------------------------------------------------------------------------
// Content hash determinism at byte level
// ---------------------------------------------------------------------------

#[test]
fn enrichment_determinism_content_hash_hex_chars_only() {
    let dir = unique_temp_dir("enrichment-hash-hex");
    let artifacts = write_parity_evidence_bundle(&dir, &["test".to_string()]).unwrap();
    assert!(
        !artifacts.inventory_hash.is_empty(),
        "hash must not be empty"
    );
    for ch in artifacts.inventory_hash.chars() {
        assert!(
            ch.is_ascii_hexdigit(),
            "hash char '{}' is not hex in: {}",
            ch,
            artifacts.inventory_hash
        );
    }
}

#[test]
fn enrichment_determinism_content_hash_length_is_64() {
    let dir = unique_temp_dir("enrichment-hash-len");
    let artifacts = write_parity_evidence_bundle(&dir, &["test".to_string()]).unwrap();
    assert_eq!(
        artifacts.inventory_hash.len(),
        64,
        "SHA-256 hex hash should be 64 characters, got {}",
        artifacts.inventory_hash.len()
    );
}

#[test]
fn enrichment_determinism_three_consecutive_hashes_identical() {
    let d1 = unique_temp_dir("enrichment-det-1");
    let d2 = unique_temp_dir("enrichment-det-2");
    let d3 = unique_temp_dir("enrichment-det-3");
    let cmds = vec!["determinism".to_string()];
    let a1 = write_parity_evidence_bundle(&d1, &cmds).unwrap();
    let a2 = write_parity_evidence_bundle(&d2, &cmds).unwrap();
    let a3 = write_parity_evidence_bundle(&d3, &cmds).unwrap();
    assert_eq!(a1.inventory_hash, a2.inventory_hash);
    assert_eq!(a2.inventory_hash, a3.inventory_hash);
}

// ---------------------------------------------------------------------------
// Cross-artifact consistency: manifest vs inventory vs events
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cross_artifact_manifest_hash_embedded_in_trace_id() {
    let dir = unique_temp_dir("enrichment-cross-trace");
    let artifacts = write_parity_evidence_bundle(&dir, &["cmd".to_string()]).unwrap();
    let manifest: ParityEvidenceRunManifest =
        serde_json::from_str(&std::fs::read_to_string(&artifacts.run_manifest_path).unwrap())
            .unwrap();
    let hash_prefix: String = artifacts.inventory_hash.chars().take(12).collect();
    assert!(
        manifest.trace_id.ends_with(&hash_prefix),
        "trace_id '{}' should end with hash prefix '{}'",
        manifest.trace_id,
        hash_prefix
    );
}

#[test]
fn enrichment_cross_artifact_decision_id_contains_trace_id() {
    let dir = unique_temp_dir("enrichment-cross-decision");
    let artifacts = write_parity_evidence_bundle(&dir, &["cmd".to_string()]).unwrap();
    let manifest: ParityEvidenceRunManifest =
        serde_json::from_str(&std::fs::read_to_string(&artifacts.run_manifest_path).unwrap())
            .unwrap();
    assert!(
        manifest.decision_id.contains(&manifest.trace_id),
        "decision_id '{}' should contain trace_id '{}'",
        manifest.decision_id,
        manifest.trace_id
    );
}

#[test]
fn enrichment_cross_artifact_event_count_equals_findings_plus_two() {
    let dir = unique_temp_dir("enrichment-cross-event-count");
    let artifacts = write_parity_evidence_bundle(&dir, &["cmd".to_string()]).unwrap();
    let inv: ParityEvidenceInventory =
        serde_json::from_str(&std::fs::read_to_string(&artifacts.inventory_path).unwrap()).unwrap();
    let events_text = std::fs::read_to_string(&artifacts.events_path).unwrap();
    let event_count = events_text.lines().count();
    assert_eq!(
        event_count,
        inv.findings.len() + 2,
        "events = 1 start + {} findings + 1 end, got {}",
        inv.findings.len(),
        event_count
    );
}

#[test]
fn enrichment_cross_artifact_manifest_counts_sum_to_finding_count() {
    let dir = unique_temp_dir("enrichment-cross-sum");
    let artifacts = write_parity_evidence_bundle(&dir, &["cmd".to_string()]).unwrap();
    let manifest: ParityEvidenceRunManifest =
        serde_json::from_str(&std::fs::read_to_string(&artifacts.run_manifest_path).unwrap())
            .unwrap();
    let inv: ParityEvidenceInventory =
        serde_json::from_str(&std::fs::read_to_string(&artifacts.inventory_path).unwrap()).unwrap();
    let lowering_leads_count = inv
        .findings
        .iter()
        .filter(|f| f.verdict == ParityVerdict::LoweringLeadsParser)
        .count() as u64;
    let named_sum = manifest.covered_count
        + manifest.fail_closed_agreed_count
        + manifest.parity_violation_count
        + manifest.open_gap_count;
    assert_eq!(
        named_sum + lowering_leads_count,
        manifest.finding_count,
        "named counts + lowering_leads should equal finding_count"
    );
}

// ---------------------------------------------------------------------------
// Bundle idempotency: writing twice to same directory
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lifecycle_bundle_overwrite_same_directory() {
    let dir = unique_temp_dir("enrichment-overwrite");
    let cmds1 = vec!["first_write".to_string()];
    let cmds2 = vec!["second_write".to_string()];
    let _a1 = write_parity_evidence_bundle(&dir, &cmds1).unwrap();
    let a2 = write_parity_evidence_bundle(&dir, &cmds2).unwrap();
    let commands_content = std::fs::read_to_string(&a2.commands_path).unwrap();
    assert_eq!(
        commands_content, "second_write",
        "second write should overwrite commands file"
    );
    assert!(a2.inventory_path.exists());
    assert!(a2.run_manifest_path.exists());
}

// ---------------------------------------------------------------------------
// Large synthetic inventory stress
// ---------------------------------------------------------------------------

#[test]
fn enrichment_stress_large_inventory_counts_correct() {
    let mut findings = Vec::new();
    for i in 0..100 {
        let verdict = match i % 5 {
            0 => ParityVerdict::Covered,
            1 => ParityVerdict::FailClosedAgreed,
            2 => ParityVerdict::ParserLeadsLowering,
            3 => ParityVerdict::LoweringLeadsParser,
            4 => ParityVerdict::OpenGap,
            _ => unreachable!(),
        };
        findings.push(make_finding(&format!("site_{i:03}"), verdict));
    }
    let inv = make_inventory(findings);
    assert_eq!(inv.covered_count(), 20);
    assert_eq!(inv.fail_closed_agreed_count(), 20);
    assert_eq!(inv.parity_violation_count(), 20);
    assert_eq!(inv.open_gap_count(), 20);
    assert!(!inv.contract_satisfied());
}

#[test]
fn enrichment_stress_large_inventory_serde_roundtrip() {
    let findings: Vec<ParityFinding> = (0..50)
        .map(|i| make_finding(&format!("stress_{i:03}"), ParityVerdict::Covered))
        .collect();
    let inv = make_inventory(findings);
    let json = serde_json::to_string(&inv).unwrap();
    let back: ParityEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, back);
    assert_eq!(back.findings.len(), 50);
}

// ---------------------------------------------------------------------------
// JSON value-level structural validation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_json_finding_has_exactly_six_fields() {
    let finding = make_finding("structural", ParityVerdict::Covered);
    let json = serde_json::to_string(&finding).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = val.as_object().unwrap();
    assert_eq!(
        obj.len(),
        6,
        "ParityFinding should serialize to exactly 6 fields, got {}",
        obj.len()
    );
    assert!(obj.contains_key("site_id"));
    assert!(obj.contains_key("feature_family"));
    assert!(obj.contains_key("parser_status"));
    assert!(obj.contains_key("lowering_status"));
    assert!(obj.contains_key("verdict"));
    assert!(obj.contains_key("diagnostic_code"));
}

#[test]
fn enrichment_json_event_has_seven_fields() {
    let event = ParityEvidenceEvent {
        schema_version: PARITY_EVIDENCE_EVENT_SCHEMA_VERSION.to_string(),
        component: PARITY_EVIDENCE_COMPONENT.to_string(),
        event: "test".to_string(),
        policy_id: PARITY_EVIDENCE_POLICY_ID.to_string(),
        site_id: Some("s".to_string()),
        verdict: Some("v".to_string()),
        detail: Some("d".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = val.as_object().unwrap();
    assert_eq!(obj.len(), 7, "ParityEvidenceEvent should have 7 fields");
}

#[test]
fn enrichment_json_inventory_has_three_top_level_fields() {
    let inv = make_inventory(vec![make_finding("tl", ParityVerdict::Covered)]);
    let json = serde_json::to_string(&inv).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = val.as_object().unwrap();
    assert_eq!(obj.len(), 3);
    assert!(obj.contains_key("schema_version"));
    assert!(obj.contains_key("component"));
    assert!(obj.contains_key("findings"));
    assert!(obj["findings"].is_array());
}

#[test]
fn enrichment_json_manifest_artifact_paths_nested() {
    let manifest = ParityEvidenceRunManifest {
        schema_version: PARITY_EVIDENCE_MANIFEST_SCHEMA_VERSION.to_string(),
        component: PARITY_EVIDENCE_COMPONENT.to_string(),
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: PARITY_EVIDENCE_POLICY_ID.to_string(),
        inventory_hash: "h".to_string(),
        finding_count: 0,
        covered_count: 0,
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
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(val["artifact_paths"].is_object());
    let ap = val["artifact_paths"].as_object().unwrap();
    assert_eq!(ap.len(), 4);
    assert!(ap.contains_key("parity_evidence_inventory"));
    assert!(ap.contains_key("run_manifest"));
    assert!(ap.contains_key("events_jsonl"));
    assert!(ap.contains_key("commands_txt"));
}

// ---------------------------------------------------------------------------
// Edge case: empty-string site_id in synthetic finding
// ---------------------------------------------------------------------------

#[test]
fn enrichment_edge_empty_findings_vector_contract_satisfied() {
    let inv = make_inventory(Vec::new());
    assert!(inv.contract_satisfied());
    assert_eq!(inv.covered_count(), 0);
    assert_eq!(inv.fail_closed_agreed_count(), 0);
    assert_eq!(inv.parity_violation_count(), 0);
    assert_eq!(inv.open_gap_count(), 0);
}

#[test]
fn enrichment_edge_single_violation_fails_contract() {
    let inv = make_inventory(vec![make_finding(
        "only",
        ParityVerdict::ParserLeadsLowering,
    )]);
    assert!(!inv.contract_satisfied());
    assert_eq!(inv.parity_violation_count(), 1);
}

#[test]
fn enrichment_edge_mixed_verdicts_without_violation_satisfies_contract() {
    let inv = make_inventory(vec![
        make_finding("a", ParityVerdict::Covered),
        make_finding("b", ParityVerdict::FailClosedAgreed),
        make_finding("c", ParityVerdict::LoweringLeadsParser),
        make_finding("d", ParityVerdict::OpenGap),
    ]);
    assert!(
        inv.contract_satisfied(),
        "No ParserLeadsLowering => contract satisfied"
    );
    assert_eq!(inv.parity_violation_count(), 0);
}

// ---------------------------------------------------------------------------
// Verdict deserialization rejects invalid inputs
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_verdict_rejects_camel_case() {
    let result: Result<ParityVerdict, _> = serde_json::from_str("\"failClosedAgreed\"");
    assert!(
        result.is_err(),
        "camelCase should be rejected by snake_case serde"
    );
}

#[test]
fn enrichment_serde_verdict_rejects_upper_case() {
    let result: Result<ParityVerdict, _> = serde_json::from_str("\"COVERED\"");
    assert!(result.is_err(), "UPPER_CASE should be rejected");
}

#[test]
fn enrichment_serde_verdict_rejects_empty_string() {
    let result: Result<ParityVerdict, _> = serde_json::from_str("\"\"");
    assert!(result.is_err(), "empty string should be rejected");
}

#[test]
fn enrichment_serde_verdict_rejects_boolean() {
    let result: Result<ParityVerdict, _> = serde_json::from_str("true");
    assert!(result.is_err(), "boolean should be rejected");
}

#[test]
fn enrichment_serde_verdict_rejects_array() {
    let result: Result<ParityVerdict, _> = serde_json::from_str("[\"covered\"]");
    assert!(result.is_err(), "array should be rejected");
}

// ---------------------------------------------------------------------------
// Debug format stability
// ---------------------------------------------------------------------------

#[test]
fn enrichment_debug_finding_contains_all_field_values() {
    let finding = ParityFinding {
        site_id: "debug_site_xyz".to_string(),
        feature_family: "debug_family_abc".to_string(),
        parser_status: "resolved".to_string(),
        lowering_status: "resolved".to_string(),
        verdict: ParityVerdict::Covered,
        diagnostic_code: "FE-DEBUG-999".to_string(),
    };
    let dbg = format!("{:?}", finding);
    assert!(dbg.contains("debug_site_xyz"));
    assert!(dbg.contains("debug_family_abc"));
    assert!(dbg.contains("FE-DEBUG-999"));
    assert!(dbg.contains("Covered"));
}

#[test]
fn enrichment_debug_inventory_contains_schema_version() {
    let inv = make_inventory(vec![make_finding("dbg", ParityVerdict::Covered)]);
    let dbg = format!("{:?}", inv);
    assert!(dbg.contains(PARITY_EVIDENCE_SCHEMA_VERSION));
    assert!(dbg.contains(PARITY_EVIDENCE_COMPONENT));
}

#[test]
fn enrichment_debug_event_contains_event_name() {
    let event = ParityEvidenceEvent {
        schema_version: PARITY_EVIDENCE_EVENT_SCHEMA_VERSION.to_string(),
        component: PARITY_EVIDENCE_COMPONENT.to_string(),
        event: "unique_debug_event_name_12345".to_string(),
        policy_id: PARITY_EVIDENCE_POLICY_ID.to_string(),
        site_id: None,
        verdict: None,
        detail: None,
    };
    let dbg = format!("{:?}", event);
    assert!(dbg.contains("unique_debug_event_name_12345"));
}

// ---------------------------------------------------------------------------
// Manifest serde: contract_satisfied boolean encodes correctly
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_manifest_contract_satisfied_true_false() {
    for satisfied in [true, false] {
        let manifest = ParityEvidenceRunManifest {
            schema_version: PARITY_EVIDENCE_MANIFEST_SCHEMA_VERSION.to_string(),
            component: PARITY_EVIDENCE_COMPONENT.to_string(),
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: PARITY_EVIDENCE_POLICY_ID.to_string(),
            inventory_hash: "h".to_string(),
            finding_count: 1,
            covered_count: if satisfied { 1 } else { 0 },
            fail_closed_agreed_count: 0,
            parity_violation_count: if satisfied { 0 } else { 1 },
            open_gap_count: 0,
            contract_satisfied: satisfied,
            artifact_paths: ParityEvidenceArtifactPaths {
                parity_evidence_inventory: "i.json".to_string(),
                run_manifest: "m.json".to_string(),
                events_jsonl: "e.jsonl".to_string(),
                commands_txt: "c.txt".to_string(),
            },
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["contract_satisfied"].as_bool().unwrap(), satisfied);
        let back: ParityEvidenceRunManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.contract_satisfied, satisfied);
    }
}

// ---------------------------------------------------------------------------
// Bundle: events JSONL finding events carry correct verdict strings
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lifecycle_event_verdicts_match_inventory_findings() {
    let dir = unique_temp_dir("enrichment-event-verdicts");
    let artifacts = write_parity_evidence_bundle(&dir, &["cmd".to_string()]).unwrap();
    let inv: ParityEvidenceInventory =
        serde_json::from_str(&std::fs::read_to_string(&artifacts.inventory_path).unwrap()).unwrap();
    let events_text = std::fs::read_to_string(&artifacts.events_path).unwrap();
    let finding_events: Vec<ParityEvidenceEvent> = events_text
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .filter(|e: &ParityEvidenceEvent| e.event == "parity_finding_recorded")
        .collect();
    assert_eq!(finding_events.len(), inv.findings.len());
    for (finding, event) in inv.findings.iter().zip(finding_events.iter()) {
        assert_eq!(
            event.site_id.as_deref(),
            Some(finding.site_id.as_str()),
            "event site_id should match finding"
        );
        assert_eq!(
            event.verdict.as_deref(),
            Some(finding.verdict.as_str()),
            "event verdict should match finding verdict"
        );
    }
}

// ---------------------------------------------------------------------------
// Artifact paths: all are relative filenames, no slashes
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lifecycle_bundle_artifact_paths_are_plain_filenames() {
    let dir = unique_temp_dir("enrichment-plain-names");
    let artifacts = write_parity_evidence_bundle(&dir, &["cmd".to_string()]).unwrap();
    let manifest: ParityEvidenceRunManifest =
        serde_json::from_str(&std::fs::read_to_string(&artifacts.run_manifest_path).unwrap())
            .unwrap();
    let paths = [
        &manifest.artifact_paths.parity_evidence_inventory,
        &manifest.artifact_paths.run_manifest,
        &manifest.artifact_paths.events_jsonl,
        &manifest.artifact_paths.commands_txt,
    ];
    for p in paths {
        assert!(
            !p.contains('/'),
            "artifact path should be a plain filename: {p}"
        );
        assert!(
            !p.contains('\\'),
            "artifact path should not contain backslash: {p}"
        );
        assert!(!p.is_empty(), "artifact path should not be empty");
    }
}

// ---------------------------------------------------------------------------
// Constants: schema versions contain version suffix
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_schema_versions_end_with_v1() {
    assert!(
        PARITY_EVIDENCE_SCHEMA_VERSION.ends_with(".v1"),
        "inventory schema version should end with .v1: {}",
        PARITY_EVIDENCE_SCHEMA_VERSION
    );
    assert!(
        PARITY_EVIDENCE_MANIFEST_SCHEMA_VERSION.ends_with(".v1"),
        "manifest schema version should end with .v1: {}",
        PARITY_EVIDENCE_MANIFEST_SCHEMA_VERSION
    );
    assert!(
        PARITY_EVIDENCE_EVENT_SCHEMA_VERSION.ends_with(".v1"),
        "event schema version should end with .v1: {}",
        PARITY_EVIDENCE_EVENT_SCHEMA_VERSION
    );
    assert!(
        PARITY_EVIDENCE_POLICY_ID.ends_with(".v1"),
        "policy_id should end with .v1: {}",
        PARITY_EVIDENCE_POLICY_ID
    );
}

#[test]
fn enrichment_constants_all_five_are_distinct() {
    let consts = [
        PARITY_EVIDENCE_SCHEMA_VERSION,
        PARITY_EVIDENCE_MANIFEST_SCHEMA_VERSION,
        PARITY_EVIDENCE_EVENT_SCHEMA_VERSION,
        PARITY_EVIDENCE_POLICY_ID,
        PARITY_EVIDENCE_COMPONENT,
    ];
    let set: BTreeSet<&str> = consts.iter().copied().collect();
    assert_eq!(set.len(), consts.len(), "all 5 constants must be distinct");
}

// ---------------------------------------------------------------------------
// Live inventory: diagnostic codes are non-empty and unique
// ---------------------------------------------------------------------------

#[test]
fn enrichment_live_inventory_diagnostic_codes_non_empty() {
    let inv = parity_evidence_inventory();
    for finding in &inv.findings {
        assert!(
            !finding.diagnostic_code.is_empty(),
            "diagnostic_code must not be empty for site {}",
            finding.site_id
        );
    }
}

// ---------------------------------------------------------------------------
// Inventory: multiple calls produce structurally identical JSON
// ---------------------------------------------------------------------------

#[test]
fn enrichment_determinism_inventory_json_byte_stable() {
    let inv1 = parity_evidence_inventory();
    let inv2 = parity_evidence_inventory();
    let json1 = serde_json::to_string(&inv1).unwrap();
    let json2 = serde_json::to_string(&inv2).unwrap();
    assert_eq!(
        json1, json2,
        "inventory JSON must be byte-stable across calls"
    );
}

// ---------------------------------------------------------------------------
// Bundle: nested directory creation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lifecycle_bundle_creates_nested_output_dir() {
    let base = unique_temp_dir("enrichment-nested");
    let nested = base.join("level1").join("level2").join("level3");
    assert!(!nested.exists());
    let artifacts = write_parity_evidence_bundle(&nested, &["nested_cmd".to_string()]).unwrap();
    assert!(nested.exists());
    assert!(artifacts.inventory_path.exists());
}

// ---------------------------------------------------------------------------
// Bundle: commands with special characters
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lifecycle_bundle_commands_preserve_special_chars() {
    let dir = unique_temp_dir("enrichment-special-cmds");
    let commands = vec![
        "franken --flag=\"value with spaces\"".to_string(),
        "--path=/tmp/foo/bar".to_string(),
        "unicode: alpha beta gamma".to_string(),
    ];
    let artifacts = write_parity_evidence_bundle(&dir, &commands).unwrap();
    let content = std::fs::read_to_string(&artifacts.commands_path).unwrap();
    for cmd in &commands {
        assert!(
            content.contains(cmd.as_str()),
            "commands file should contain: {}",
            cmd
        );
    }
}
