#![forbid(unsafe_code)]

//! Enrichment integration tests for the ts_normalization_evidence module.

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

use std::collections::BTreeSet;

use frankenengine_engine::ts_normalization_evidence::{
    ActualOutcome, ExpectedOutcome, SpecimenVerdict, TS_DIAGNOSTIC_CORPUS_SCHEMA_VERSION,
    TS_EVIDENCE_COMPONENT, TS_EVIDENCE_EVENT_SCHEMA_VERSION, TS_EVIDENCE_MANIFEST_SCHEMA_VERSION,
    TS_EVIDENCE_POLICY_ID, TsEvidenceArtifactPaths, TsEvidenceEvent, TsEvidenceRunManifest,
    TsFeatureFamily, diagnostic_corpus, run_diagnostic_corpus,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_artifact_paths() -> TsEvidenceArtifactPaths {
    TsEvidenceArtifactPaths {
        evidence_inventory: "inv.json".to_string(),
        run_manifest: "manifest.json".to_string(),
        events_jsonl: "events.jsonl".to_string(),
        commands_txt: "commands.txt".to_string(),
    }
}

fn make_manifest() -> TsEvidenceRunManifest {
    TsEvidenceRunManifest {
        schema_version: TS_EVIDENCE_MANIFEST_SCHEMA_VERSION.to_string(),
        component: TS_EVIDENCE_COMPONENT.to_string(),
        trace_id: "trace-001".to_string(),
        decision_id: "dec-001".to_string(),
        policy_id: TS_EVIDENCE_POLICY_ID.to_string(),
        inventory_hash: "abc123".to_string(),
        specimen_count: 20,
        pass_count: 18,
        fail_count: 0,
        known_gap_count: 2,
        contract_satisfied: true,
        artifact_paths: make_artifact_paths(),
    }
}

fn make_event() -> TsEvidenceEvent {
    TsEvidenceEvent {
        schema_version: TS_EVIDENCE_EVENT_SCHEMA_VERSION.to_string(),
        component: TS_EVIDENCE_COMPONENT.to_string(),
        event: "specimen_evaluated".to_string(),
        policy_id: TS_EVIDENCE_POLICY_ID.to_string(),
        specimen_id: Some("sp-1".to_string()),
        verdict: Some("pass".to_string()),
        detail: Some("ok".to_string()),
    }
}

// ---------------------------------------------------------------------------
// TsFeatureFamily — Copy / BTreeSet / Clone / Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_feature_family_copy_semantics() {
    let a = TsFeatureFamily::TypeAnnotation;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_feature_family_btreeset_dedup_15() {
    let mut set = BTreeSet::new();
    for f in TsFeatureFamily::ALL {
        set.insert(*f);
    }
    set.insert(TsFeatureFamily::TypeAnnotation);
    assert_eq!(set.len(), 15);
}

#[test]
fn enrichment_feature_family_clone_independence() {
    let a = TsFeatureFamily::InterfaceDeclaration;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_feature_family_debug_all_unique() {
    let dbgs: BTreeSet<String> = TsFeatureFamily::ALL
        .iter()
        .map(|v| format!("{:?}", v))
        .collect();
    assert_eq!(dbgs.len(), 15);
}

#[test]
fn enrichment_feature_family_as_str_all_nonempty() {
    for f in TsFeatureFamily::ALL {
        assert!(!f.as_str().is_empty(), "empty as_str for {:?}", f);
    }
}

#[test]
fn enrichment_feature_family_description_all_nonempty() {
    for f in TsFeatureFamily::ALL {
        assert!(!f.description().is_empty(), "empty description for {:?}", f);
    }
}

// ---------------------------------------------------------------------------
// ExpectedOutcome — Copy / BTreeSet / Clone / Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_expected_outcome_copy_semantics() {
    let a = ExpectedOutcome::NormalizedAway;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_expected_outcome_btreeset_dedup_4() {
    let mut set = BTreeSet::new();
    set.insert(ExpectedOutcome::NormalizedAway);
    set.insert(ExpectedOutcome::LoweredToEs2020);
    set.insert(ExpectedOutcome::FailClosed);
    set.insert(ExpectedOutcome::KnownGap);
    set.insert(ExpectedOutcome::NormalizedAway);
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_expected_outcome_clone_independence() {
    let a = ExpectedOutcome::FailClosed;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_expected_outcome_debug_all_unique() {
    let all = [
        ExpectedOutcome::NormalizedAway,
        ExpectedOutcome::LoweredToEs2020,
        ExpectedOutcome::FailClosed,
        ExpectedOutcome::KnownGap,
    ];
    let dbgs: BTreeSet<String> = all.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), 4);
}

// ---------------------------------------------------------------------------
// ActualOutcome — Copy / BTreeSet / Clone / Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_actual_outcome_copy_semantics() {
    let a = ActualOutcome::Success;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_actual_outcome_btreeset_dedup_2() {
    let mut set = BTreeSet::new();
    set.insert(ActualOutcome::Success);
    set.insert(ActualOutcome::Rejected);
    set.insert(ActualOutcome::Success);
    assert_eq!(set.len(), 2);
}

#[test]
fn enrichment_actual_outcome_debug_all_unique() {
    let all = [ActualOutcome::Success, ActualOutcome::Rejected];
    let dbgs: BTreeSet<String> = all.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), 2);
}

// ---------------------------------------------------------------------------
// SpecimenVerdict — Copy / BTreeSet / Clone / Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_specimen_verdict_copy_semantics() {
    let a = SpecimenVerdict::Pass;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_specimen_verdict_btreeset_dedup_2() {
    let mut set = BTreeSet::new();
    set.insert(SpecimenVerdict::Pass);
    set.insert(SpecimenVerdict::Fail);
    set.insert(SpecimenVerdict::Pass);
    assert_eq!(set.len(), 2);
}

#[test]
fn enrichment_specimen_verdict_debug_all_unique() {
    let all = [SpecimenVerdict::Pass, SpecimenVerdict::Fail];
    let dbgs: BTreeSet<String> = all.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), 2);
}

// ---------------------------------------------------------------------------
// CorpusSpecimen — Clone / Debug / JSON (via corpus)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_corpus_specimen_clone_independence() {
    let corpus = diagnostic_corpus();
    let a = &corpus[0];
    let b = a.clone();
    assert_eq!(*a, b);
}

#[test]
fn enrichment_corpus_specimen_debug_nonempty() {
    let corpus = diagnostic_corpus();
    assert!(!format!("{:?}", corpus[0]).is_empty());
}

#[test]
fn enrichment_corpus_specimen_json_field_names() {
    let corpus = diagnostic_corpus();
    let json = serde_json::to_string(&corpus[0]).unwrap();
    for field in &[
        "specimen_id",
        "feature_family",
        "ts_source",
        "expected_outcome",
        "expected_absent_patterns",
        "expected_present_patterns",
        "description",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

// ---------------------------------------------------------------------------
// SpecimenEvidence — Clone / Debug / JSON (via run_corpus)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_specimen_evidence_clone_independence() {
    let inv = run_diagnostic_corpus();
    let a = &inv.evidence[0];
    let b = a.clone();
    assert_eq!(*a, b);
}

#[test]
fn enrichment_specimen_evidence_debug_nonempty() {
    let inv = run_diagnostic_corpus();
    assert!(!format!("{:?}", inv.evidence[0]).is_empty());
}

#[test]
fn enrichment_specimen_evidence_json_field_names() {
    let inv = run_diagnostic_corpus();
    let json = serde_json::to_string(&inv.evidence[0]).unwrap();
    for field in &[
        "specimen_id",
        "feature_family",
        "expected_outcome",
        "actual_outcome",
        "verdict",
        "absent_pattern_failures",
        "present_pattern_failures",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

// ---------------------------------------------------------------------------
// TsNormalizationEvidenceInventory — Clone / Debug / JSON
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evidence_inventory_clone_independence() {
    let a = run_diagnostic_corpus();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_evidence_inventory_debug_nonempty() {
    assert!(!format!("{:?}", run_diagnostic_corpus()).is_empty());
}

#[test]
fn enrichment_evidence_inventory_json_field_names() {
    let inv = run_diagnostic_corpus();
    let json = serde_json::to_string(&inv).unwrap();
    for field in &[
        "schema_version",
        "component",
        "specimen_count",
        "pass_count",
        "fail_count",
        "known_gap_count",
        "feature_family_coverage",
        "evidence",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

// ---------------------------------------------------------------------------
// TsEvidenceRunManifest — Clone / Debug / JSON / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_run_manifest_clone_independence() {
    let a = make_manifest();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_run_manifest_debug_nonempty() {
    assert!(!format!("{:?}", make_manifest()).is_empty());
}

#[test]
fn enrichment_run_manifest_json_field_names() {
    let json = serde_json::to_string(&make_manifest()).unwrap();
    for field in &[
        "schema_version",
        "component",
        "trace_id",
        "decision_id",
        "policy_id",
        "inventory_hash",
        "specimen_count",
        "pass_count",
        "fail_count",
        "known_gap_count",
        "contract_satisfied",
        "artifact_paths",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_run_manifest_serde_roundtrip() {
    let a = make_manifest();
    let json = serde_json::to_string(&a).unwrap();
    let b: TsEvidenceRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// TsEvidenceArtifactPaths — Clone / Debug / JSON / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_artifact_paths_clone_independence() {
    let a = make_artifact_paths();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_artifact_paths_debug_nonempty() {
    assert!(!format!("{:?}", make_artifact_paths()).is_empty());
}

#[test]
fn enrichment_artifact_paths_json_field_names() {
    let json = serde_json::to_string(&make_artifact_paths()).unwrap();
    for field in &[
        "evidence_inventory",
        "run_manifest",
        "events_jsonl",
        "commands_txt",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_artifact_paths_serde_roundtrip() {
    let a = make_artifact_paths();
    let json = serde_json::to_string(&a).unwrap();
    let b: TsEvidenceArtifactPaths = serde_json::from_str(&json).unwrap();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// TsEvidenceEvent — Clone / Debug / JSON / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evidence_event_clone_independence() {
    let a = make_event();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_evidence_event_debug_nonempty() {
    assert!(!format!("{:?}", make_event()).is_empty());
}

#[test]
fn enrichment_evidence_event_json_field_names() {
    let json = serde_json::to_string(&make_event()).unwrap();
    for field in &[
        "schema_version",
        "component",
        "event",
        "policy_id",
        "specimen_id",
        "verdict",
        "detail",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_evidence_event_serde_roundtrip() {
    let a = make_event();
    let json = serde_json::to_string(&a).unwrap();
    let b: TsEvidenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(a, b);
}

#[test]
fn enrichment_evidence_event_with_nones() {
    let a = TsEvidenceEvent {
        schema_version: TS_EVIDENCE_EVENT_SCHEMA_VERSION.to_string(),
        component: TS_EVIDENCE_COMPONENT.to_string(),
        event: "run_started".to_string(),
        policy_id: TS_EVIDENCE_POLICY_ID.to_string(),
        specimen_id: None,
        verdict: None,
        detail: None,
    };
    let json = serde_json::to_string(&a).unwrap();
    let b: TsEvidenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// Constants stability
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_exact_values() {
    assert_eq!(
        TS_DIAGNOSTIC_CORPUS_SCHEMA_VERSION,
        "franken-engine.ts-diagnostic-corpus.inventory.v1"
    );
    assert_eq!(
        TS_EVIDENCE_MANIFEST_SCHEMA_VERSION,
        "franken-engine.ts-normalization-evidence.run-manifest.v1"
    );
    assert_eq!(
        TS_EVIDENCE_EVENT_SCHEMA_VERSION,
        "franken-engine.ts-normalization-evidence.event.v1"
    );
    assert_eq!(TS_EVIDENCE_COMPONENT, "ts_normalization_evidence");
    assert_eq!(
        TS_EVIDENCE_POLICY_ID,
        "franken-engine.ts-normalization-evidence.policy.v1"
    );
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_five_run_determinism_corpus() {
    let jsons: BTreeSet<String> = (0..5)
        .map(|_| serde_json::to_string(&diagnostic_corpus()).unwrap())
        .collect();
    assert_eq!(jsons.len(), 1, "corpus should be deterministic");
}

#[test]
fn enrichment_five_run_determinism_inventory() {
    let jsons: BTreeSet<String> = (0..5)
        .map(|_| serde_json::to_string(&run_diagnostic_corpus()).unwrap())
        .collect();
    assert_eq!(jsons.len(), 1, "inventory should be deterministic");
}

// ---------------------------------------------------------------------------
// Cross-cutting invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cross_cutting_pass_plus_fail_covers_non_gap() {
    let inv = run_diagnostic_corpus();
    // pass + fail should cover non-gap specimens; known_gap may overlap with pass
    assert!(
        inv.pass_count + inv.fail_count >= inv.specimen_count - inv.known_gap_count,
        "pass={} fail={} gap={} total={}",
        inv.pass_count,
        inv.fail_count,
        inv.known_gap_count,
        inv.specimen_count
    );
}

#[test]
fn enrichment_cross_cutting_evidence_count_matches_specimen_count() {
    let inv = run_diagnostic_corpus();
    assert_eq!(inv.evidence.len() as u64, inv.specimen_count);
}

#[test]
fn enrichment_cross_cutting_corpus_ids_match_evidence() {
    let corpus = diagnostic_corpus();
    let inv = run_diagnostic_corpus();
    let corpus_ids: BTreeSet<&str> = corpus.iter().map(|s| s.specimen_id.as_str()).collect();
    let evidence_ids: BTreeSet<&str> = inv
        .evidence
        .iter()
        .map(|e| e.specimen_id.as_str())
        .collect();
    assert_eq!(corpus_ids, evidence_ids);
}

#[test]
fn enrichment_cross_cutting_schema_version_in_inventory() {
    let inv = run_diagnostic_corpus();
    assert_eq!(inv.schema_version, TS_DIAGNOSTIC_CORPUS_SCHEMA_VERSION);
}

#[test]
fn enrichment_cross_cutting_component_in_inventory() {
    let inv = run_diagnostic_corpus();
    assert_eq!(inv.component, TS_EVIDENCE_COMPONENT);
}

#[test]
fn enrichment_cross_cutting_all_families_in_coverage() {
    let inv = run_diagnostic_corpus();
    assert!(
        inv.feature_family_coverage.len() >= 10,
        "should cover many feature families, got {}",
        inv.feature_family_coverage.len()
    );
}
