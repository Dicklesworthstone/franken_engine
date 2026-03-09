//! Integration tests for the parser_frontier_evidence module.

use frankenengine_engine::parser_frontier_evidence::{
    ActualParseOutcome, ExpectedParseOutcome, FrontierEvidenceArtifactPaths,
    FrontierEvidenceEvent, FrontierEvidenceRunManifest,
    FrontierSpecimen, FrontierSpecimenEvidence, FrontierVerdict, PARSER_FRONTIER_COMPONENT,
    PARSER_FRONTIER_EVENT_SCHEMA_VERSION, PARSER_FRONTIER_EVIDENCE_SCHEMA_VERSION,
    PARSER_FRONTIER_MANIFEST_SCHEMA_VERSION, PARSER_FRONTIER_POLICY_ID,
    ParserFrontierEvidenceInventory, ParserFrontierFamily, frontier_corpus, run_frontier_corpus,
    write_frontier_evidence_bundle,
};
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tid = std::thread::current().id();
    std::env::temp_dir().join(format!("{prefix}-int-{ts}-{tid:?}"))
}

// ── Corpus ──

#[test]
fn corpus_non_empty() {
    assert!(!frontier_corpus().is_empty());
}

#[test]
fn corpus_covers_all_families() {
    let corpus = frontier_corpus();
    let covered: BTreeSet<ParserFrontierFamily> = corpus.iter().map(|s| s.family).collect();
    for f in ParserFrontierFamily::ALL {
        assert!(covered.contains(f), "missing {:?}", f);
    }
}

#[test]
fn corpus_ids_unique() {
    let corpus = frontier_corpus();
    let ids: BTreeSet<&str> = corpus.iter().map(|s| s.specimen_id.as_str()).collect();
    assert_eq!(ids.len(), corpus.len());
}

#[test]
fn corpus_has_positive_and_negative() {
    let corpus = frontier_corpus();
    assert!(
        corpus
            .iter()
            .any(|s| s.expected_outcome == ExpectedParseOutcome::Accepted)
    );
    assert!(
        corpus
            .iter()
            .any(|s| s.expected_outcome == ExpectedParseOutcome::Rejected)
    );
}

#[test]
fn corpus_specimens_have_valid_fields() {
    for s in &frontier_corpus() {
        assert!(!s.specimen_id.is_empty());
        assert!(!s.description.is_empty());
    }
}

// ── Family enum ──

#[test]
fn family_as_str_distinct() {
    let strs: BTreeSet<&str> = ParserFrontierFamily::ALL
        .iter()
        .map(|f| f.as_str())
        .collect();
    assert_eq!(strs.len(), ParserFrontierFamily::ALL.len());
}

#[test]
fn family_serde_roundtrip() {
    for f in ParserFrontierFamily::ALL {
        let json = serde_json::to_string(f).unwrap();
        let back: ParserFrontierFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*f, back);
    }
}

// ── Running the corpus ──

#[test]
fn all_specimens_pass() {
    let inv = run_frontier_corpus();
    for ev in &inv.evidence {
        assert_eq!(
            ev.verdict,
            FrontierVerdict::Pass,
            "specimen {} failed: expected={:?}, actual={:?}",
            ev.specimen_id,
            ev.expected_outcome,
            ev.actual_outcome
        );
    }
}

#[test]
fn contract_satisfied() {
    let inv = run_frontier_corpus();
    assert!(inv.contract_satisfied());
}

#[test]
fn counts_consistent() {
    let inv = run_frontier_corpus();
    assert_eq!(inv.pass_count + inv.fail_count, inv.specimen_count);
    assert_eq!(inv.accepted_count + inv.rejected_count, inv.specimen_count);
    assert_eq!(inv.evidence.len() as u64, inv.specimen_count);
}

#[test]
fn family_coverage_sums() {
    let inv = run_frontier_corpus();
    let total: u64 = inv.family_coverage.values().sum();
    assert_eq!(total, inv.specimen_count);
}

#[test]
fn rejected_specimens_have_error_codes() {
    let inv = run_frontier_corpus();
    for ev in &inv.evidence {
        if ev.actual_outcome == ActualParseOutcome::Rejected {
            assert!(
                ev.error_code.is_some(),
                "specimen {} needs error_code",
                ev.specimen_id
            );
        }
    }
}

#[test]
fn all_specimens_have_event_ir_hash() {
    let inv = run_frontier_corpus();
    for ev in &inv.evidence {
        assert!(
            ev.event_ir_hash.is_some(),
            "specimen {} needs event_ir_hash",
            ev.specimen_id
        );
    }
}

#[test]
fn corpus_deterministic() {
    let inv1 = run_frontier_corpus();
    let inv2 = run_frontier_corpus();
    assert_eq!(inv1, inv2);
}

// ── Schema constants ──

#[test]
fn schema_constants_non_empty() {
    assert!(!PARSER_FRONTIER_EVIDENCE_SCHEMA_VERSION.is_empty());
    assert!(!PARSER_FRONTIER_MANIFEST_SCHEMA_VERSION.is_empty());
    assert!(!PARSER_FRONTIER_EVENT_SCHEMA_VERSION.is_empty());
    assert!(!PARSER_FRONTIER_COMPONENT.is_empty());
    assert!(!PARSER_FRONTIER_POLICY_ID.is_empty());
}

#[test]
fn schema_versions_prefixed() {
    assert!(PARSER_FRONTIER_EVIDENCE_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(PARSER_FRONTIER_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(PARSER_FRONTIER_EVENT_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn inventory_schema_matches() {
    let inv = run_frontier_corpus();
    assert_eq!(inv.schema_version, PARSER_FRONTIER_EVIDENCE_SCHEMA_VERSION);
    assert_eq!(inv.component, PARSER_FRONTIER_COMPONENT);
}

// ── Serde ──

#[test]
fn evidence_inventory_serde_roundtrip() {
    let inv = run_frontier_corpus();
    let json = serde_json::to_string(&inv).unwrap();
    let back: ParserFrontierEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, back);
}

#[test]
fn specimen_evidence_serde_roundtrip() {
    let inv = run_frontier_corpus();
    for ev in &inv.evidence {
        let json = serde_json::to_string(ev).unwrap();
        let back: FrontierSpecimenEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(*ev, back);
    }
}

#[test]
fn corpus_specimen_serde_roundtrip() {
    for s in &frontier_corpus() {
        let json = serde_json::to_string(s).unwrap();
        let back: FrontierSpecimen = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

#[test]
fn manifest_serde_roundtrip() {
    let m = FrontierEvidenceRunManifest {
        schema_version: PARSER_FRONTIER_MANIFEST_SCHEMA_VERSION.to_string(),
        component: PARSER_FRONTIER_COMPONENT.to_string(),
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: PARSER_FRONTIER_POLICY_ID.to_string(),
        inventory_hash: "h".to_string(),
        specimen_count: 25,
        pass_count: 25,
        fail_count: 0,
        accepted_count: 22,
        rejected_count: 3,
        contract_satisfied: true,
        artifact_paths: FrontierEvidenceArtifactPaths {
            evidence_inventory: "a.json".to_string(),
            run_manifest: "b.json".to_string(),
            events_jsonl: "c.jsonl".to_string(),
            commands_txt: "d.txt".to_string(),
        },
    };
    let json = serde_json::to_string(&m).unwrap();
    let back: FrontierEvidenceRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn event_serde_roundtrip() {
    let ev = FrontierEvidenceEvent {
        schema_version: PARSER_FRONTIER_EVENT_SCHEMA_VERSION.to_string(),
        component: PARSER_FRONTIER_COMPONENT.to_string(),
        event: "test".to_string(),
        policy_id: PARSER_FRONTIER_POLICY_ID.to_string(),
        specimen_id: Some("s".to_string()),
        verdict: Some("pass".to_string()),
        detail: Some("d".to_string()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: FrontierEvidenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

// ── Bundle writing ──

#[test]
fn bundle_creates_all_artifacts() {
    let out = unique_temp_dir("pfe-bundle");
    let cmds = vec!["test".to_string()];
    let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
    assert!(arts.inventory_path.exists());
    assert!(arts.run_manifest_path.exists());
    assert!(arts.events_path.exists());
    assert!(arts.commands_path.exists());
}

#[test]
fn bundle_inventory_valid_json() {
    let out = unique_temp_dir("pfe-inv-json");
    let cmds = vec!["test".to_string()];
    let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
    let inv: ParserFrontierEvidenceInventory =
        serde_json::from_slice(&fs::read(&arts.inventory_path).unwrap()).unwrap();
    assert!(!inv.evidence.is_empty());
}

#[test]
fn bundle_manifest_satisfied() {
    let out = unique_temp_dir("pfe-manifest");
    let cmds = vec!["test".to_string()];
    let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
    let m: FrontierEvidenceRunManifest =
        serde_json::from_slice(&fs::read(&arts.run_manifest_path).unwrap()).unwrap();
    assert!(m.contract_satisfied);
    assert_eq!(m.fail_count, 0);
}

#[test]
fn bundle_manifest_fields() {
    let out = unique_temp_dir("pfe-fields");
    let cmds = vec!["test".to_string()];
    let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
    let m: FrontierEvidenceRunManifest =
        serde_json::from_slice(&fs::read(&arts.run_manifest_path).unwrap()).unwrap();
    assert_eq!(m.schema_version, PARSER_FRONTIER_MANIFEST_SCHEMA_VERSION);
    assert_eq!(m.component, PARSER_FRONTIER_COMPONENT);
    assert_eq!(m.policy_id, PARSER_FRONTIER_POLICY_ID);
}

#[test]
fn bundle_hash_matches_manifest() {
    let out = unique_temp_dir("pfe-hash");
    let cmds = vec!["test".to_string()];
    let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
    let m: FrontierEvidenceRunManifest =
        serde_json::from_slice(&fs::read(&arts.run_manifest_path).unwrap()).unwrap();
    assert_eq!(m.inventory_hash, arts.inventory_hash);
}

#[test]
fn bundle_events_valid_jsonl() {
    let out = unique_temp_dir("pfe-events-valid");
    let cmds = vec!["test".to_string()];
    let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
    let events = fs::read_to_string(&arts.events_path).unwrap();
    for (i, line) in events.lines().enumerate() {
        let _: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("line {} invalid: {}", i, e));
    }
}

#[test]
fn bundle_events_start_and_end() {
    let out = unique_temp_dir("pfe-events-se");
    let cmds = vec!["test".to_string()];
    let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
    let events = fs::read_to_string(&arts.events_path).unwrap();
    let lines: Vec<&str> = events.lines().collect();
    assert!(lines.len() >= 3);
    let first: FrontierEvidenceEvent = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(first.event, "frontier_evidence_run_started");
    let last: FrontierEvidenceEvent = serde_json::from_str(lines[lines.len() - 1]).unwrap();
    assert_eq!(last.event, "frontier_evidence_run_completed");
}

#[test]
fn bundle_events_count() {
    let out = unique_temp_dir("pfe-events-cnt");
    let cmds = vec!["test".to_string()];
    let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
    let events = fs::read_to_string(&arts.events_path).unwrap();
    let corpus = frontier_corpus();
    assert_eq!(events.lines().count(), corpus.len() + 2);
}

#[test]
fn bundle_commands_content() {
    let out = unique_temp_dir("pfe-cmds");
    let cmds = vec!["alpha".to_string(), "beta".to_string()];
    let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
    let txt = fs::read_to_string(&arts.commands_path).unwrap();
    assert!(txt.contains("alpha"));
    assert!(txt.contains("beta"));
}

#[test]
fn bundle_hash_deterministic() {
    let out1 = unique_temp_dir("pfe-det1");
    let out2 = unique_temp_dir("pfe-det2");
    let cmds = vec!["det".to_string()];
    let a1 = write_frontier_evidence_bundle(&out1, &cmds).expect("w1");
    let a2 = write_frontier_evidence_bundle(&out2, &cmds).expect("w2");
    assert_eq!(a1.inventory_hash, a2.inventory_hash);
}

#[test]
fn bundle_hash_64_hex() {
    let out = unique_temp_dir("pfe-hex");
    let cmds = vec!["test".to_string()];
    let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
    assert_eq!(arts.inventory_hash.len(), 64);
    assert!(arts.inventory_hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn bundle_artifact_paths_relative() {
    let out = unique_temp_dir("pfe-rel");
    let cmds = vec!["test".to_string()];
    let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
    let m: FrontierEvidenceRunManifest =
        serde_json::from_slice(&fs::read(&arts.run_manifest_path).unwrap()).unwrap();
    assert!(!m.artifact_paths.evidence_inventory.contains('/'));
    assert!(!m.artifact_paths.run_manifest.contains('/'));
    assert!(!m.artifact_paths.events_jsonl.contains('/'));
    assert!(!m.artifact_paths.commands_txt.contains('/'));
}
