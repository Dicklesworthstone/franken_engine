//! Integration tests for the ts_normalization_evidence module.
//!
//! Tests the fail-closed TS diagnostic corpus, evidence harness execution,
//! bundle artifact generation, serde round-trips, and contract satisfaction.

use frankenengine_engine::ts_normalization_evidence::{
    ActualOutcome, CorpusSpecimen, ExpectedOutcome, SpecimenEvidence, SpecimenVerdict,
    TS_DIAGNOSTIC_CORPUS_SCHEMA_VERSION, TS_EVIDENCE_COMPONENT, TS_EVIDENCE_EVENT_SCHEMA_VERSION,
    TS_EVIDENCE_MANIFEST_SCHEMA_VERSION, TS_EVIDENCE_POLICY_ID, TsEvidenceArtifactPaths,
    TsEvidenceBundleArtifacts, TsEvidenceEvent, TsEvidenceRunManifest, TsFeatureFamily,
    TsNormalizationEvidenceInventory, diagnostic_corpus, run_diagnostic_corpus,
    write_evidence_bundle,
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

// ── Corpus structure ──

#[test]
fn corpus_is_non_empty() {
    let corpus = diagnostic_corpus();
    assert!(!corpus.is_empty());
}

#[test]
fn corpus_covers_all_feature_families() {
    let corpus = diagnostic_corpus();
    let covered: BTreeSet<TsFeatureFamily> = corpus.iter().map(|s| s.feature_family).collect();
    for family in TsFeatureFamily::ALL {
        assert!(
            covered.contains(family),
            "missing coverage for {:?}",
            family
        );
    }
}

#[test]
fn corpus_specimen_ids_unique() {
    let corpus = diagnostic_corpus();
    let ids: BTreeSet<&str> = corpus.iter().map(|s| s.specimen_id.as_str()).collect();
    assert_eq!(ids.len(), corpus.len());
}

#[test]
fn corpus_specimens_have_valid_fields() {
    let corpus = diagnostic_corpus();
    for s in &corpus {
        assert!(!s.specimen_id.is_empty());
        assert!(!s.ts_source.is_empty());
        assert!(!s.description.is_empty());
    }
}

#[test]
fn corpus_has_at_least_one_per_outcome_type() {
    let corpus = diagnostic_corpus();
    let has_normalized = corpus
        .iter()
        .any(|s| s.expected_outcome == ExpectedOutcome::NormalizedAway);
    let has_lowered = corpus
        .iter()
        .any(|s| s.expected_outcome == ExpectedOutcome::LoweredToEs2020);
    let has_fail_closed = corpus
        .iter()
        .any(|s| s.expected_outcome == ExpectedOutcome::FailClosed);
    let has_known_gap = corpus
        .iter()
        .any(|s| s.expected_outcome == ExpectedOutcome::KnownGap);
    assert!(has_normalized, "missing NormalizedAway specimen");
    assert!(has_lowered, "missing LoweredToEs2020 specimen");
    assert!(has_fail_closed, "missing FailClosed specimen");
    assert!(has_known_gap, "missing KnownGap specimen");
}

// ── Feature family enum ──

#[test]
fn feature_family_as_str_unique() {
    let strs: BTreeSet<&str> = TsFeatureFamily::ALL.iter().map(|f| f.as_str()).collect();
    assert_eq!(strs.len(), TsFeatureFamily::ALL.len());
}

#[test]
fn feature_family_description_non_empty() {
    for f in TsFeatureFamily::ALL {
        assert!(!f.description().is_empty());
    }
}

#[test]
fn feature_family_serde_roundtrip() {
    for f in TsFeatureFamily::ALL {
        let json = serde_json::to_string(f).unwrap();
        let back: TsFeatureFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*f, back);
    }
}

#[test]
fn feature_family_json_uses_snake_case() {
    let json = serde_json::to_string(&TsFeatureFamily::TypeAnnotation).unwrap();
    assert_eq!(json, "\"type_annotation\"");
    let json = serde_json::to_string(&TsFeatureFamily::HostcallTypeParam).unwrap();
    assert_eq!(json, "\"hostcall_type_param\"");
}

// ── Expected outcome enum ──

#[test]
fn expected_outcome_as_str_distinct() {
    let strs: BTreeSet<&str> = [
        ExpectedOutcome::NormalizedAway,
        ExpectedOutcome::LoweredToEs2020,
        ExpectedOutcome::FailClosed,
        ExpectedOutcome::KnownGap,
    ]
    .iter()
    .map(|o| o.as_str())
    .collect();
    assert_eq!(strs.len(), 4);
}

#[test]
fn expected_outcome_serde_roundtrip() {
    for o in [
        ExpectedOutcome::NormalizedAway,
        ExpectedOutcome::LoweredToEs2020,
        ExpectedOutcome::FailClosed,
        ExpectedOutcome::KnownGap,
    ] {
        let json = serde_json::to_string(&o).unwrap();
        let back: ExpectedOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(o, back);
    }
}

// ── Running the corpus ──

#[test]
fn diagnostic_corpus_all_pass() {
    let inv = run_diagnostic_corpus();
    assert_eq!(inv.fail_count, 0);
    assert_eq!(inv.pass_count, inv.specimen_count);
}

#[test]
fn diagnostic_corpus_contract_satisfied() {
    let inv = run_diagnostic_corpus();
    assert!(inv.contract_satisfied());
}

#[test]
fn corpus_counts_consistent() {
    let inv = run_diagnostic_corpus();
    assert_eq!(inv.pass_count + inv.fail_count, inv.specimen_count);
    assert_eq!(inv.evidence.len() as u64, inv.specimen_count);
}

#[test]
fn corpus_tracks_known_gaps() {
    let inv = run_diagnostic_corpus();
    assert!(inv.known_gap_count > 0, "should have known gaps");
    let gap_evidence: Vec<_> = inv
        .evidence
        .iter()
        .filter(|e| e.expected_outcome == ExpectedOutcome::KnownGap)
        .collect();
    assert_eq!(gap_evidence.len() as u64, inv.known_gap_count);
}

#[test]
fn feature_family_coverage_sums_to_specimen_count() {
    let inv = run_diagnostic_corpus();
    let total: u64 = inv.feature_family_coverage.values().sum();
    assert_eq!(total, inv.specimen_count);
}

#[test]
fn every_evidence_record_has_valid_fields() {
    let inv = run_diagnostic_corpus();
    for ev in &inv.evidence {
        assert!(!ev.specimen_id.is_empty());
    }
}

#[test]
fn no_unexpected_failures_in_evidence() {
    let inv = run_diagnostic_corpus();
    for ev in &inv.evidence {
        assert_eq!(
            ev.verdict,
            SpecimenVerdict::Pass,
            "specimen {} failed",
            ev.specimen_id
        );
    }
}

#[test]
fn corpus_deterministic_across_runs() {
    let inv1 = run_diagnostic_corpus();
    let inv2 = run_diagnostic_corpus();
    assert_eq!(inv1, inv2);
}

// ── Schema and constants ──

#[test]
fn schema_version_constants_non_empty() {
    assert!(!TS_DIAGNOSTIC_CORPUS_SCHEMA_VERSION.is_empty());
    assert!(!TS_EVIDENCE_MANIFEST_SCHEMA_VERSION.is_empty());
    assert!(!TS_EVIDENCE_EVENT_SCHEMA_VERSION.is_empty());
    assert!(!TS_EVIDENCE_COMPONENT.is_empty());
    assert!(!TS_EVIDENCE_POLICY_ID.is_empty());
}

#[test]
fn schema_versions_have_expected_prefix() {
    assert!(TS_DIAGNOSTIC_CORPUS_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(TS_EVIDENCE_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(TS_EVIDENCE_EVENT_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn inventory_schema_version_matches() {
    let inv = run_diagnostic_corpus();
    assert_eq!(inv.schema_version, TS_DIAGNOSTIC_CORPUS_SCHEMA_VERSION);
    assert_eq!(inv.component, TS_EVIDENCE_COMPONENT);
}

// ── Serde roundtrips ──

#[test]
fn evidence_inventory_serde_roundtrip() {
    let inv = run_diagnostic_corpus();
    let json = serde_json::to_string(&inv).unwrap();
    let back: TsNormalizationEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, back);
}

#[test]
fn specimen_evidence_serde_roundtrip() {
    let inv = run_diagnostic_corpus();
    for ev in &inv.evidence {
        let json = serde_json::to_string(ev).unwrap();
        let back: SpecimenEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(*ev, back);
    }
}

#[test]
fn corpus_specimen_serde_roundtrip() {
    let corpus = diagnostic_corpus();
    for s in &corpus {
        let json = serde_json::to_string(s).unwrap();
        let back: CorpusSpecimen = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

#[test]
fn manifest_serde_roundtrip() {
    let manifest = TsEvidenceRunManifest {
        schema_version: TS_EVIDENCE_MANIFEST_SCHEMA_VERSION.to_string(),
        component: TS_EVIDENCE_COMPONENT.to_string(),
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: TS_EVIDENCE_POLICY_ID.to_string(),
        inventory_hash: "h".to_string(),
        specimen_count: 16,
        pass_count: 16,
        fail_count: 0,
        known_gap_count: 6,
        contract_satisfied: true,
        artifact_paths: TsEvidenceArtifactPaths {
            evidence_inventory: "a.json".to_string(),
            run_manifest: "b.json".to_string(),
            events_jsonl: "c.jsonl".to_string(),
            commands_txt: "d.txt".to_string(),
        },
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let back: TsEvidenceRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

#[test]
fn event_serde_roundtrip() {
    let ev = TsEvidenceEvent {
        schema_version: TS_EVIDENCE_EVENT_SCHEMA_VERSION.to_string(),
        component: TS_EVIDENCE_COMPONENT.to_string(),
        event: "test".to_string(),
        policy_id: TS_EVIDENCE_POLICY_ID.to_string(),
        specimen_id: Some("s".to_string()),
        verdict: Some("pass".to_string()),
        detail: Some("d".to_string()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: TsEvidenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn event_with_none_fields_serde_roundtrip() {
    let ev = TsEvidenceEvent {
        schema_version: TS_EVIDENCE_EVENT_SCHEMA_VERSION.to_string(),
        component: TS_EVIDENCE_COMPONENT.to_string(),
        event: "start".to_string(),
        policy_id: TS_EVIDENCE_POLICY_ID.to_string(),
        specimen_id: None,
        verdict: None,
        detail: None,
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: TsEvidenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

// ── Bundle writing ──

#[test]
fn bundle_creates_all_artifacts() {
    let out = unique_temp_dir("ts-ev-bundle");
    let cmds = vec!["test".to_string()];
    let arts = write_evidence_bundle(&out, &cmds).expect("write");
    assert!(arts.inventory_path.exists());
    assert!(arts.run_manifest_path.exists());
    assert!(arts.events_path.exists());
    assert!(arts.commands_path.exists());
}

#[test]
fn bundle_inventory_is_valid_json() {
    let out = unique_temp_dir("ts-ev-inv-json");
    let cmds = vec!["test".to_string()];
    let arts = write_evidence_bundle(&out, &cmds).expect("write");
    let inv: TsNormalizationEvidenceInventory =
        serde_json::from_slice(&fs::read(&arts.inventory_path).unwrap()).unwrap();
    assert!(!inv.evidence.is_empty());
}

#[test]
fn bundle_manifest_contract_satisfied() {
    let out = unique_temp_dir("ts-ev-manifest");
    let cmds = vec!["test".to_string()];
    let arts = write_evidence_bundle(&out, &cmds).expect("write");
    let manifest: TsEvidenceRunManifest =
        serde_json::from_slice(&fs::read(&arts.run_manifest_path).unwrap()).unwrap();
    assert!(manifest.contract_satisfied);
    assert_eq!(manifest.fail_count, 0);
}

#[test]
fn bundle_manifest_fields_consistent() {
    let out = unique_temp_dir("ts-ev-consistent");
    let cmds = vec!["test".to_string()];
    let arts = write_evidence_bundle(&out, &cmds).expect("write");
    let manifest: TsEvidenceRunManifest =
        serde_json::from_slice(&fs::read(&arts.run_manifest_path).unwrap()).unwrap();
    assert_eq!(manifest.schema_version, TS_EVIDENCE_MANIFEST_SCHEMA_VERSION);
    assert_eq!(manifest.component, TS_EVIDENCE_COMPONENT);
    assert_eq!(manifest.policy_id, TS_EVIDENCE_POLICY_ID);
    assert_eq!(
        manifest.pass_count + manifest.fail_count,
        manifest.specimen_count
    );
}

#[test]
fn bundle_manifest_hash_matches() {
    let out = unique_temp_dir("ts-ev-hash-match");
    let cmds = vec!["test".to_string()];
    let arts = write_evidence_bundle(&out, &cmds).expect("write");
    let manifest: TsEvidenceRunManifest =
        serde_json::from_slice(&fs::read(&arts.run_manifest_path).unwrap()).unwrap();
    assert_eq!(manifest.inventory_hash, arts.inventory_hash);
}

#[test]
fn bundle_events_jsonl_valid() {
    let out = unique_temp_dir("ts-ev-events-valid");
    let cmds = vec!["test".to_string()];
    let arts = write_evidence_bundle(&out, &cmds).expect("write");
    let events = fs::read_to_string(&arts.events_path).unwrap();
    for (i, line) in events.lines().enumerate() {
        let _: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("event line {} invalid: {}", i, e));
    }
}

#[test]
fn bundle_events_start_and_end() {
    let out = unique_temp_dir("ts-ev-events-se");
    let cmds = vec!["test".to_string()];
    let arts = write_evidence_bundle(&out, &cmds).expect("write");
    let events = fs::read_to_string(&arts.events_path).unwrap();
    let lines: Vec<&str> = events.lines().collect();
    assert!(lines.len() >= 3);

    let first: TsEvidenceEvent = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(first.event, "evidence_run_started");

    let last: TsEvidenceEvent = serde_json::from_str(lines[lines.len() - 1]).unwrap();
    assert_eq!(last.event, "evidence_run_completed");
}

#[test]
fn bundle_events_line_count() {
    let out = unique_temp_dir("ts-ev-events-count");
    let cmds = vec!["test".to_string()];
    let arts = write_evidence_bundle(&out, &cmds).expect("write");
    let events = fs::read_to_string(&arts.events_path).unwrap();
    let corpus = diagnostic_corpus();
    // start + per-specimen + end
    assert_eq!(events.lines().count(), corpus.len() + 2);
}

#[test]
fn bundle_commands_file_contents() {
    let out = unique_temp_dir("ts-ev-cmds");
    let cmds = vec!["alpha".to_string(), "beta".to_string()];
    let arts = write_evidence_bundle(&out, &cmds).expect("write");
    let txt = fs::read_to_string(&arts.commands_path).unwrap();
    assert!(txt.contains("alpha"));
    assert!(txt.contains("beta"));
}

#[test]
fn bundle_hash_deterministic() {
    let out1 = unique_temp_dir("ts-ev-det1");
    let out2 = unique_temp_dir("ts-ev-det2");
    let cmds = vec!["det".to_string()];
    let a1 = write_evidence_bundle(&out1, &cmds).expect("write1");
    let a2 = write_evidence_bundle(&out2, &cmds).expect("write2");
    assert_eq!(a1.inventory_hash, a2.inventory_hash);
}

#[test]
fn bundle_hash_is_64_hex_chars() {
    let out = unique_temp_dir("ts-ev-hexlen");
    let cmds = vec!["test".to_string()];
    let arts = write_evidence_bundle(&out, &cmds).expect("write");
    assert_eq!(arts.inventory_hash.len(), 64);
    assert!(arts.inventory_hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn bundle_manifest_artifact_paths_are_relative() {
    let out = unique_temp_dir("ts-ev-relpaths");
    let cmds = vec!["test".to_string()];
    let arts = write_evidence_bundle(&out, &cmds).expect("write");
    let manifest: TsEvidenceRunManifest =
        serde_json::from_slice(&fs::read(&arts.run_manifest_path).unwrap()).unwrap();
    assert!(!manifest.artifact_paths.evidence_inventory.contains('/'));
    assert!(!manifest.artifact_paths.run_manifest.contains('/'));
    assert!(!manifest.artifact_paths.events_jsonl.contains('/'));
    assert!(!manifest.artifact_paths.commands_txt.contains('/'));
}

// ── Known specific specimens ──

#[test]
fn type_annotation_specimen_normalizes_away() {
    let inv = run_diagnostic_corpus();
    let ev = inv
        .evidence
        .iter()
        .find(|e| e.specimen_id == "type_annotation_variable")
        .unwrap();
    assert_eq!(ev.verdict, SpecimenVerdict::Pass);
    assert_eq!(ev.actual_outcome, ActualOutcome::Success);
}

#[test]
fn enum_specimen_lowers_to_es2020() {
    let inv = run_diagnostic_corpus();
    let ev = inv
        .evidence
        .iter()
        .find(|e| e.specimen_id == "enum_declaration")
        .unwrap();
    assert_eq!(ev.verdict, SpecimenVerdict::Pass);
    assert_eq!(ev.expected_outcome, ExpectedOutcome::LoweredToEs2020);
}

#[test]
fn namespace_specimen_fails_closed() {
    let inv = run_diagnostic_corpus();
    let ev = inv
        .evidence
        .iter()
        .find(|e| e.specimen_id == "namespace_simple")
        .unwrap();
    assert_eq!(ev.verdict, SpecimenVerdict::Pass);
    assert_eq!(ev.expected_outcome, ExpectedOutcome::FailClosed);
    assert_eq!(ev.actual_outcome, ActualOutcome::Rejected);
}

#[test]
fn interface_specimen_is_known_gap() {
    let inv = run_diagnostic_corpus();
    let ev = inv
        .evidence
        .iter()
        .find(|e| e.specimen_id == "interface_declaration")
        .unwrap();
    assert_eq!(ev.verdict, SpecimenVerdict::Pass);
    assert_eq!(ev.expected_outcome, ExpectedOutcome::KnownGap);
}

#[test]
fn decorator_specimen_lowers_correctly() {
    let inv = run_diagnostic_corpus();
    let ev = inv
        .evidence
        .iter()
        .find(|e| e.specimen_id == "class_decorator")
        .unwrap();
    assert_eq!(ev.verdict, SpecimenVerdict::Pass);
}
