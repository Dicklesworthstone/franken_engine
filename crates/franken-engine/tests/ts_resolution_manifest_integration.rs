//! Integration tests for TS module-resolution manifest (RGC-204B).

use frankenengine_engine::ts_resolution_manifest::{
    IrPipelineLineage, ManifestBuildInput, ManifestEvidenceEvent, ManifestEvidenceInventory,
    ManifestExpectedOutcome, ManifestFeatureFamily, ManifestRunManifest, ManifestSpecimen,
    ManifestVerdict, NormalizationLineage, ReplayValidationReport, ReplayValidationStatus,
    ResolutionLineage, TS_EXECUTION_MANIFEST_SCHEMA_VERSION, TS_MANIFEST_COMPONENT,
    TS_MANIFEST_EVENT_SCHEMA_VERSION, TS_MANIFEST_POLICY_ID, TS_MANIFEST_RUN_SCHEMA_VERSION,
    TS_MANIFEST_SCHEMA_VERSION, TS_REPLAY_INDEX_SCHEMA_VERSION, TsExecutionManifest,
    TsModuleResolutionMode, TsRequestStyle, TsResolutionDriftClass, TsResolutionReplayEntry,
    TsResolutionReplayIndex, TsconfigSnapshot, manifest_corpus, run_manifest_corpus,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn simple_replay_entry(specifier: &str) -> TsResolutionReplayEntry {
    TsResolutionReplayEntry {
        specifier: specifier.into(),
        referrer: Some("src/index.ts".into()),
        style: TsRequestStyle::Import,
        resolved_path: format!("node_modules/{specifier}/index.js"),
        package_name: Some(specifier.into()),
        selected_condition: Some("import".into()),
        resolved_content_hash: Some("abc123".into()),
        probe_count: 3,
    }
}

fn simple_normalization() -> NormalizationLineage {
    NormalizationLineage {
        source_hash: "src-hash".into(),
        normalized_hash: "norm-hash".into(),
        compiler_options_hash: "opts-hash".into(),
        normalization_applied: true,
    }
}

fn simple_resolution() -> ResolutionLineage {
    ResolutionLineage {
        decision_count: 5,
        resolved_count: 5,
        failed_count: 0,
        drift_class: TsResolutionDriftClass::NoDrift,
        replay_index_hash: Some("idx-hash".into()),
    }
}

fn simple_ir_pipeline() -> IrPipelineLineage {
    IrPipelineLineage {
        ir0_hash: "ir0-hash".into(),
        ir1_hash: Some("ir1-hash".into()),
        ir2_hash: Some("ir2-hash".into()),
        ir3_hash: Some("ir3-hash".into()),
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_non_empty() {
    assert!(!TS_MANIFEST_SCHEMA_VERSION.is_empty());
    assert!(!TS_REPLAY_INDEX_SCHEMA_VERSION.is_empty());
    assert!(!TS_EXECUTION_MANIFEST_SCHEMA_VERSION.is_empty());
    assert!(!TS_MANIFEST_RUN_SCHEMA_VERSION.is_empty());
    assert!(!TS_MANIFEST_EVENT_SCHEMA_VERSION.is_empty());
    assert!(!TS_MANIFEST_COMPONENT.is_empty());
    assert!(!TS_MANIFEST_POLICY_ID.is_empty());
}

#[test]
fn schema_versions_unique() {
    let versions = [
        TS_MANIFEST_SCHEMA_VERSION,
        TS_REPLAY_INDEX_SCHEMA_VERSION,
        TS_EXECUTION_MANIFEST_SCHEMA_VERSION,
        TS_MANIFEST_RUN_SCHEMA_VERSION,
        TS_MANIFEST_EVENT_SCHEMA_VERSION,
    ];
    for i in 0..versions.len() {
        for j in (i + 1)..versions.len() {
            assert_ne!(versions[i], versions[j], "schema versions must be unique");
        }
    }
}

// ---------------------------------------------------------------------------
// TsconfigSnapshot
// ---------------------------------------------------------------------------

#[test]
fn tsconfig_default() {
    let ts = TsconfigSnapshot::default();
    assert!(!ts.root_dir.is_empty());
}

#[test]
fn tsconfig_content_hash_deterministic() {
    let t1 = TsconfigSnapshot::default();
    let t2 = TsconfigSnapshot::default();
    assert_eq!(t1.content_hash(), t2.content_hash());
}

#[test]
fn tsconfig_serde_round_trip() {
    let ts = TsconfigSnapshot::default();
    let json = serde_json::to_string(&ts).unwrap();
    let back: TsconfigSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(ts, back);
}

// ---------------------------------------------------------------------------
// ReplayValidationStatus
// ---------------------------------------------------------------------------

#[test]
fn replay_status_all_variants() {
    let all = ReplayValidationStatus::ALL;
    assert!(all.len() >= 6);
}

#[test]
fn replay_status_matched_is_ok() {
    assert!(ReplayValidationStatus::Matched.is_ok());
    assert!(!ReplayValidationStatus::PathMismatch.is_ok());
    assert!(!ReplayValidationStatus::ContentDrift.is_ok());
}

#[test]
fn replay_status_as_str_non_empty() {
    for s in ReplayValidationStatus::ALL {
        assert!(!s.as_str().is_empty());
    }
}

#[test]
fn replay_status_display() {
    for s in ReplayValidationStatus::ALL {
        assert!(!format!("{s}").is_empty());
    }
}

#[test]
fn replay_status_serde_round_trip() {
    for s in ReplayValidationStatus::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: ReplayValidationStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ---------------------------------------------------------------------------
// TsResolutionReplayEntry
// ---------------------------------------------------------------------------

#[test]
fn replay_entry_lookup_key_deterministic() {
    let e1 = simple_replay_entry("react");
    let e2 = simple_replay_entry("react");
    assert_eq!(e1.lookup_key(), e2.lookup_key());
}

#[test]
fn replay_entry_lookup_key_differs() {
    let e1 = simple_replay_entry("react");
    let e2 = simple_replay_entry("vue");
    assert_ne!(e1.lookup_key(), e2.lookup_key());
}

#[test]
fn replay_entry_serde_round_trip() {
    let entry = simple_replay_entry("react");
    let json = serde_json::to_string(&entry).unwrap();
    let back: TsResolutionReplayEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ---------------------------------------------------------------------------
// TsResolutionReplayIndex
// ---------------------------------------------------------------------------

#[test]
fn replay_index_build_and_lookup() {
    let entries = vec![simple_replay_entry("react"), simple_replay_entry("lodash")];
    let index = TsResolutionReplayIndex::build(
        entries,
        "tsconfig-hash-1",
        TsModuleResolutionMode::Node16,
        "2026-03-09T00:00:00Z",
    );
    assert_eq!(index.entry_count(), 2);
    let found = index.lookup("react", Some("src/index.ts"), TsRequestStyle::Import);
    assert!(found.is_some());
    assert_eq!(found.unwrap().specifier, "react");
}

#[test]
fn replay_index_lookup_missing() {
    let index = TsResolutionReplayIndex::build(
        vec![simple_replay_entry("react")],
        "hash",
        TsModuleResolutionMode::Node16,
        "2026-03-09T00:00:00Z",
    );
    let found = index.lookup("vue", Some("src/index.ts"), TsRequestStyle::Import);
    assert!(found.is_none());
}

#[test]
fn replay_index_validate_matched() {
    let entry = simple_replay_entry("react");
    let resolved_path = entry.resolved_path.clone();
    let content_hash = entry.resolved_content_hash.clone();
    let index = TsResolutionReplayIndex::build(
        vec![entry],
        "hash",
        TsModuleResolutionMode::Node16,
        "2026-03-09T00:00:00Z",
    );
    let status = index.validate_resolution(
        "react",
        Some("src/index.ts"),
        TsRequestStyle::Import,
        &resolved_path,
        content_hash.as_deref(),
    );
    assert_eq!(status, ReplayValidationStatus::Matched);
}

#[test]
fn replay_index_validate_path_mismatch() {
    let index = TsResolutionReplayIndex::build(
        vec![simple_replay_entry("react")],
        "hash",
        TsModuleResolutionMode::Node16,
        "2026-03-09T00:00:00Z",
    );
    let status = index.validate_resolution(
        "react",
        Some("src/index.ts"),
        TsRequestStyle::Import,
        "node_modules/react/cjs/index.js", // different path
        Some("abc123"),
    );
    assert_eq!(status, ReplayValidationStatus::PathMismatch);
}

#[test]
fn replay_index_serde_round_trip() {
    let index = TsResolutionReplayIndex::build(
        vec![simple_replay_entry("react")],
        "hash",
        TsModuleResolutionMode::Node16,
        "2026-03-09T00:00:00Z",
    );
    let json = serde_json::to_string(&index).unwrap();
    let back: TsResolutionReplayIndex = serde_json::from_str(&json).unwrap();
    assert_eq!(index, back);
}

#[test]
fn replay_index_hash_deterministic() {
    let i1 = TsResolutionReplayIndex::build(
        vec![simple_replay_entry("react")],
        "hash",
        TsModuleResolutionMode::Node16,
        "2026-03-09T00:00:00Z",
    );
    let i2 = TsResolutionReplayIndex::build(
        vec![simple_replay_entry("react")],
        "hash",
        TsModuleResolutionMode::Node16,
        "2026-03-09T00:00:00Z",
    );
    assert_eq!(i1.index_hash, i2.index_hash);
}

// ---------------------------------------------------------------------------
// ReplayValidationReport
// ---------------------------------------------------------------------------

#[test]
fn validation_report_all_matched() {
    let statuses = vec![
        ReplayValidationStatus::Matched,
        ReplayValidationStatus::Matched,
    ];
    let report = ReplayValidationReport::from_statuses(&statuses);
    assert!(report.passed);
    assert_eq!(report.total_entries, 2);
    assert_eq!(report.matched_count, 2);
}

#[test]
fn validation_report_with_mismatches() {
    let statuses = vec![
        ReplayValidationStatus::Matched,
        ReplayValidationStatus::PathMismatch,
        ReplayValidationStatus::ContentDrift,
    ];
    let report = ReplayValidationReport::from_statuses(&statuses);
    assert!(!report.passed);
    assert_eq!(report.total_entries, 3);
    assert_eq!(report.matched_count, 1);
    assert_eq!(report.path_mismatch_count, 1);
    assert_eq!(report.content_drift_count, 1);
}

#[test]
fn validation_report_serde_round_trip() {
    let report = ReplayValidationReport::from_statuses(&[ReplayValidationStatus::Matched]);
    let json = serde_json::to_string(&report).unwrap();
    let back: ReplayValidationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// TsExecutionManifest
// ---------------------------------------------------------------------------

#[test]
fn execution_manifest_build() {
    let input = ManifestBuildInput {
        trace_id: "trace-1".into(),
        decision_id: "dec-1".into(),
        policy_id: TS_MANIFEST_POLICY_ID.into(),
        tsconfig_hash: "tsconfig-hash".into(),
        source_path: "src/app.ts".into(),
        source_language: "TypeScript".into(),
        normalization: simple_normalization(),
        resolution: simple_resolution(),
        ir_pipeline: simple_ir_pipeline(),
        generated_at_utc: "2026-03-09T00:00:00Z".into(),
    };
    let manifest = TsExecutionManifest::build(input);
    assert!(!manifest.manifest_hash.is_empty());
    assert!(manifest.is_fully_resolved());
}

#[test]
fn execution_manifest_not_fully_resolved() {
    let input = ManifestBuildInput {
        trace_id: "trace-2".into(),
        decision_id: "dec-2".into(),
        policy_id: TS_MANIFEST_POLICY_ID.into(),
        tsconfig_hash: "tsconfig-hash".into(),
        source_path: "src/app.ts".into(),
        source_language: "TypeScript".into(),
        normalization: simple_normalization(),
        resolution: ResolutionLineage {
            decision_count: 5,
            resolved_count: 3,
            failed_count: 2,
            drift_class: TsResolutionDriftClass::NoDrift,
            replay_index_hash: None,
        },
        ir_pipeline: simple_ir_pipeline(),
        generated_at_utc: "2026-03-09T00:00:00Z".into(),
    };
    let manifest = TsExecutionManifest::build(input);
    assert!(!manifest.is_fully_resolved());
}

#[test]
fn execution_manifest_serde_round_trip() {
    let input = ManifestBuildInput {
        trace_id: "trace-serde".into(),
        decision_id: "dec-serde".into(),
        policy_id: TS_MANIFEST_POLICY_ID.into(),
        tsconfig_hash: "hash".into(),
        source_path: "src/app.ts".into(),
        source_language: "TypeScript".into(),
        normalization: simple_normalization(),
        resolution: simple_resolution(),
        ir_pipeline: simple_ir_pipeline(),
        generated_at_utc: "2026-03-09T00:00:00Z".into(),
    };
    let manifest = TsExecutionManifest::build(input);
    let json = serde_json::to_string(&manifest).unwrap();
    let back: TsExecutionManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

// ---------------------------------------------------------------------------
// ManifestFeatureFamily
// ---------------------------------------------------------------------------

#[test]
fn feature_family_all_nine() {
    assert_eq!(ManifestFeatureFamily::ALL.len(), 9);
}

#[test]
fn feature_family_as_str_unique() {
    let strs: Vec<&str> = ManifestFeatureFamily::ALL
        .iter()
        .map(|f| f.as_str())
        .collect();
    for i in 0..strs.len() {
        for j in (i + 1)..strs.len() {
            assert_ne!(strs[i], strs[j]);
        }
    }
}

#[test]
fn feature_family_description_non_empty() {
    for f in ManifestFeatureFamily::ALL {
        assert!(!f.description().is_empty());
    }
}

#[test]
fn feature_family_display() {
    for f in ManifestFeatureFamily::ALL {
        assert_eq!(format!("{f}"), f.as_str());
    }
}

// ---------------------------------------------------------------------------
// ManifestVerdict / ManifestExpectedOutcome
// ---------------------------------------------------------------------------

#[test]
fn verdict_as_str() {
    assert_eq!(ManifestVerdict::Pass.as_str(), "pass");
    assert_eq!(ManifestVerdict::Fail.as_str(), "fail");
}

#[test]
fn expected_outcome_as_str() {
    assert!(!ManifestExpectedOutcome::Valid.as_str().is_empty());
    assert!(!ManifestExpectedOutcome::ReplayMatch.as_str().is_empty());
    assert!(!ManifestExpectedOutcome::ReplayMismatch.as_str().is_empty());
    assert!(
        !ManifestExpectedOutcome::ManifestComplete
            .as_str()
            .is_empty()
    );
}

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

#[test]
fn corpus_non_empty() {
    let corpus = manifest_corpus();
    assert!(!corpus.is_empty());
}

#[test]
fn corpus_specimen_ids_unique() {
    let corpus = manifest_corpus();
    let ids: Vec<&str> = corpus.iter().map(|s| s.specimen_id.as_str()).collect();
    for i in 0..ids.len() {
        for j in (i + 1)..ids.len() {
            assert_ne!(ids[i], ids[j]);
        }
    }
}

#[test]
fn corpus_specimen_serde_round_trip() {
    let corpus = manifest_corpus();
    for s in &corpus {
        let json = serde_json::to_string(s).unwrap();
        let back: ManifestSpecimen = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ---------------------------------------------------------------------------
// run_manifest_corpus
// ---------------------------------------------------------------------------

#[test]
fn run_corpus_produces_manifest() {
    let (manifest, _inventory, _events) = run_manifest_corpus();
    assert_eq!(manifest.component, TS_MANIFEST_COMPONENT);
    assert_eq!(manifest.policy_id, TS_MANIFEST_POLICY_ID);
    assert!(manifest.specimen_count > 0);
}

#[test]
fn run_corpus_manifest_counts_consistent() {
    let (manifest, _inventory, _events) = run_manifest_corpus();
    assert_eq!(
        manifest.specimen_count,
        manifest.pass_count + manifest.fail_count
    );
}

#[test]
fn run_corpus_produces_inventory() {
    let (_manifest, inventory, _events) = run_manifest_corpus();
    assert_eq!(inventory.component, TS_MANIFEST_COMPONENT);
    assert!(!inventory.specimens.is_empty());
    assert!(!inventory.evidence_hash.is_empty());
}

#[test]
fn run_corpus_produces_events() {
    let (_manifest, _inventory, events) = run_manifest_corpus();
    assert!(!events.is_empty());
    for ev in &events {
        assert_eq!(ev.component, TS_MANIFEST_COMPONENT);
    }
}

#[test]
fn run_corpus_deterministic() {
    let (m1, inv1, ev1) = run_manifest_corpus();
    let (m2, inv2, ev2) = run_manifest_corpus();
    assert_eq!(m1, m2);
    assert_eq!(inv1, inv2);
    assert_eq!(ev1, ev2);
}

#[test]
fn run_corpus_evidence_hash_deterministic() {
    let (_, inv1, _) = run_manifest_corpus();
    let (_, inv2, _) = run_manifest_corpus();
    assert_eq!(inv1.evidence_hash, inv2.evidence_hash);
}

// ---------------------------------------------------------------------------
// Serde round-trips for evidence types
// ---------------------------------------------------------------------------

#[test]
fn serde_round_trip_run_manifest() {
    let (manifest, _, _) = run_manifest_corpus();
    let json = serde_json::to_string(&manifest).unwrap();
    let back: ManifestRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

#[test]
fn serde_round_trip_evidence_inventory() {
    let (_, inventory, _) = run_manifest_corpus();
    let json = serde_json::to_string(&inventory).unwrap();
    let back: ManifestEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inventory, back);
}

#[test]
fn serde_round_trip_evidence_event() {
    let (_, _, events) = run_manifest_corpus();
    for ev in &events {
        let json = serde_json::to_string(ev).unwrap();
        let back: ManifestEvidenceEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(*ev, back);
    }
}
