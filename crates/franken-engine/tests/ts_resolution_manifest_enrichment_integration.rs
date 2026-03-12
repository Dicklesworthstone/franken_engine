//! Enrichment integration tests for ts_resolution_manifest (RGC-204B).
//!
//! Covers areas not exercised by the base integration test file:
//! - Exhaustive enum serde roundtrips with per-variant validation
//! - TsconfigSnapshot content_hash sensitivity to individual fields
//! - ReplayIndex validate_resolution edge cases (UnexpectedSuccess, ContentDrift, unknown specifier)
//! - ReplayValidationReport exhaustive status counting
//! - ManifestFeatureFamily description uniqueness
//! - ManifestExpectedOutcome exhaustive serde
//! - ManifestVerdict serde
//! - Evidence harness artifact type serde
//! - Execution manifest hash sensitivity and is_fully_resolved with drift
//! - Lineage serde roundtrips (Normalization, Resolution, IrPipeline)
//! - ManifestArtifactPaths serde
//! - Corpus family coverage map completeness
//! - write_manifest_evidence_bundle file creation

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

use frankenengine_engine::ts_resolution_manifest::{
    IrPipelineLineage, ManifestArtifactPaths, ManifestBuildInput, ManifestEvidenceEvent,
    ManifestEvidenceInventory, ManifestExpectedOutcome, ManifestFeatureFamily, ManifestRunManifest,
    ManifestSpecimen, ManifestSpecimenEvidence, ManifestVerdict, NormalizationLineage,
    ReplayValidationReport, ReplayValidationStatus, ResolutionLineage,
    TS_EXECUTION_MANIFEST_SCHEMA_VERSION, TS_MANIFEST_COMPONENT, TS_MANIFEST_EVENT_SCHEMA_VERSION,
    TS_MANIFEST_POLICY_ID, TS_MANIFEST_RUN_SCHEMA_VERSION, TS_MANIFEST_SCHEMA_VERSION,
    TS_REPLAY_INDEX_SCHEMA_VERSION, TsExecutionManifest, TsModuleResolutionMode, TsRequestStyle,
    TsResolutionDriftClass, TsResolutionReplayEntry, TsResolutionReplayIndex, TsconfigSnapshot,
    manifest_corpus, run_manifest_corpus, write_manifest_evidence_bundle,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_entry(
    specifier: &str,
    referrer: Option<&str>,
    style: TsRequestStyle,
) -> TsResolutionReplayEntry {
    TsResolutionReplayEntry {
        specifier: specifier.into(),
        referrer: referrer.map(String::from),
        style,
        resolved_path: format!("/resolved/{specifier}.ts"),
        package_name: None,
        selected_condition: None,
        resolved_content_hash: None,
        probe_count: 1,
    }
}

fn build_manifest_input(trace: &str) -> ManifestBuildInput {
    ManifestBuildInput {
        trace_id: trace.into(),
        decision_id: format!("dec-{trace}"),
        policy_id: TS_MANIFEST_POLICY_ID.into(),
        tsconfig_hash: "tsconfig-hash-1".into(),
        source_path: "src/app.ts".into(),
        source_language: "TypeScript".into(),
        normalization: NormalizationLineage {
            source_hash: "sha256:src".into(),
            normalized_hash: "sha256:norm".into(),
            compiler_options_hash: "sha256:opts".into(),
            normalization_applied: true,
        },
        resolution: ResolutionLineage {
            decision_count: 3,
            resolved_count: 3,
            failed_count: 0,
            drift_class: TsResolutionDriftClass::NoDrift,
            replay_index_hash: Some("sha256:idx".into()),
        },
        ir_pipeline: IrPipelineLineage {
            ir0_hash: "sha256:ir0".into(),
            ir1_hash: Some("sha256:ir1".into()),
            ir2_hash: Some("sha256:ir2".into()),
            ir3_hash: Some("sha256:ir3".into()),
        },
        generated_at_utc: "2026-03-12T00:00:00Z".into(),
    }
}

// ---------------------------------------------------------------------------
// ReplayValidationStatus — exhaustive serde + is_ok + display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_replay_status_exhaustive_serde_per_variant() {
    let expected_strs = [
        (ReplayValidationStatus::Matched, "matched"),
        (ReplayValidationStatus::PathMismatch, "path_mismatch"),
        (
            ReplayValidationStatus::SelectionMismatch,
            "selection_mismatch",
        ),
        (
            ReplayValidationStatus::UnexpectedSuccess,
            "unexpected_success",
        ),
        (
            ReplayValidationStatus::UnexpectedFailure,
            "unexpected_failure",
        ),
        (ReplayValidationStatus::ContentDrift, "content_drift"),
    ];
    for (variant, expected_as_str) in &expected_strs {
        assert_eq!(variant.as_str(), *expected_as_str);
        let json = serde_json::to_string(variant).unwrap();
        let back: ReplayValidationStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, back);
    }
}

#[test]
fn enrichment_replay_status_only_matched_is_ok() {
    for s in ReplayValidationStatus::ALL {
        if *s == ReplayValidationStatus::Matched {
            assert!(s.is_ok());
        } else {
            assert!(!s.is_ok(), "{} should not be ok", s);
        }
    }
}

#[test]
fn enrichment_replay_status_display_strings_unique() {
    let displays: BTreeSet<String> = ReplayValidationStatus::ALL
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(displays.len(), ReplayValidationStatus::ALL.len());
}

// ---------------------------------------------------------------------------
// TsconfigSnapshot — content_hash sensitivity to individual fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_tsconfig_hash_sensitive_to_target() {
    let mut s1 = TsconfigSnapshot::default();
    let h1 = s1.content_hash();
    s1.target = "es2022".into();
    assert_ne!(h1, s1.content_hash());
}

#[test]
fn enrichment_tsconfig_hash_sensitive_to_jsx() {
    let mut s1 = TsconfigSnapshot::default();
    let h1 = s1.content_hash();
    s1.jsx = "preserve".into();
    assert_ne!(h1, s1.content_hash());
}

#[test]
fn enrichment_tsconfig_hash_sensitive_to_strict() {
    let mut s1 = TsconfigSnapshot::default();
    let h1 = s1.content_hash();
    s1.strict = false;
    assert_ne!(h1, s1.content_hash());
}

#[test]
fn enrichment_tsconfig_hash_sensitive_to_module_system() {
    let mut s1 = TsconfigSnapshot::default();
    let h1 = s1.content_hash();
    s1.module_system = "commonjs".into();
    assert_ne!(h1, s1.content_hash());
}

#[test]
fn enrichment_tsconfig_hash_sensitive_to_module_resolution() {
    let mut s1 = TsconfigSnapshot::default();
    let h1 = s1.content_hash();
    s1.module_resolution = TsModuleResolutionMode::Bundler;
    assert_ne!(h1, s1.content_hash());
}

#[test]
fn enrichment_tsconfig_hash_sensitive_to_custom_conditions() {
    let mut s1 = TsconfigSnapshot::default();
    let h1 = s1.content_hash();
    s1.custom_conditions.push("worker".into());
    assert_ne!(h1, s1.content_hash());
}

#[test]
fn enrichment_tsconfig_hash_sensitive_to_base_url() {
    let mut s1 = TsconfigSnapshot::default();
    let h1 = s1.content_hash();
    s1.base_url = "./packages".into();
    assert_ne!(h1, s1.content_hash());
}

#[test]
fn enrichment_tsconfig_hash_sensitive_to_root_dir() {
    let mut s1 = TsconfigSnapshot::default();
    let h1 = s1.content_hash();
    s1.root_dir = "/usr/src".into();
    assert_ne!(h1, s1.content_hash());
}

#[test]
fn enrichment_tsconfig_with_multiple_path_aliases() {
    let mut snap = TsconfigSnapshot::default();
    snap.paths
        .insert("@app/*".into(), vec!["./src/app/*".into()]);
    snap.paths
        .insert("@lib/*".into(), vec!["./src/lib/*".into()]);
    let h1 = snap.content_hash();
    // Adding another path changes the hash
    snap.paths.insert("@test/*".into(), vec!["./test/*".into()]);
    let h2 = snap.content_hash();
    assert_ne!(h1, h2);
}

// ---------------------------------------------------------------------------
// TsResolutionReplayEntry — lookup_key edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_replay_entry_lookup_key_no_referrer() {
    let entry = make_entry("react", None, TsRequestStyle::Import);
    let key = entry.lookup_key();
    // Format: "specifier||style_debug"
    assert!(key.starts_with("react|"));
    assert!(key.contains("||")); // empty referrer produces consecutive pipes
}

#[test]
fn enrichment_replay_entry_lookup_key_require_style() {
    let entry = make_entry("lodash", Some("index.js"), TsRequestStyle::Require);
    let key = entry.lookup_key();
    assert!(key.contains("Require"));
    assert!(key.contains("lodash"));
    assert!(key.contains("index.js"));
}

#[test]
fn enrichment_replay_entry_same_specifier_different_style_different_key() {
    let e1 = make_entry("react", Some("app.ts"), TsRequestStyle::Import);
    let e2 = make_entry("react", Some("app.ts"), TsRequestStyle::Require);
    assert_ne!(e1.lookup_key(), e2.lookup_key());
}

#[test]
fn enrichment_replay_entry_same_specifier_different_referrer_different_key() {
    let e1 = make_entry("react", Some("a.ts"), TsRequestStyle::Import);
    let e2 = make_entry("react", Some("b.ts"), TsRequestStyle::Import);
    assert_ne!(e1.lookup_key(), e2.lookup_key());
}

// ---------------------------------------------------------------------------
// ReplayIndex — validate_resolution edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_validate_unknown_specifier_empty_actual_path_matched() {
    let index =
        TsResolutionReplayIndex::build(Vec::new(), "h", TsModuleResolutionMode::NodeNext, "t");
    // Unknown specifier + empty actual path → Matched (both sides agree: not found)
    let status = index.validate_resolution("unknown", None, TsRequestStyle::Import, "", None);
    assert_eq!(status, ReplayValidationStatus::Matched);
}

#[test]
fn enrichment_validate_unknown_specifier_nonempty_actual_unexpected_success() {
    let index =
        TsResolutionReplayIndex::build(Vec::new(), "h", TsModuleResolutionMode::NodeNext, "t");
    let status =
        index.validate_resolution("unknown", None, TsRequestStyle::Import, "/found.ts", None);
    assert_eq!(status, ReplayValidationStatus::UnexpectedSuccess);
}

#[test]
fn enrichment_validate_recorded_empty_actual_nonempty_unexpected_success() {
    // Entry with empty resolved_path (failed resolution), but actual resolves
    let entry = TsResolutionReplayEntry {
        specifier: "./missing".into(),
        referrer: None,
        style: TsRequestStyle::Import,
        resolved_path: String::new(),
        package_name: None,
        selected_condition: None,
        resolved_content_hash: None,
        probe_count: 3,
    };
    let index =
        TsResolutionReplayIndex::build(vec![entry], "h", TsModuleResolutionMode::NodeNext, "t");
    let status =
        index.validate_resolution("./missing", None, TsRequestStyle::Import, "/found.ts", None);
    assert_eq!(status, ReplayValidationStatus::UnexpectedSuccess);
}

#[test]
fn enrichment_validate_unexpected_failure() {
    let entry = TsResolutionReplayEntry {
        specifier: "./x".into(),
        referrer: None,
        style: TsRequestStyle::Import,
        resolved_path: "/x.ts".into(),
        package_name: None,
        selected_condition: None,
        resolved_content_hash: None,
        probe_count: 1,
    };
    let index =
        TsResolutionReplayIndex::build(vec![entry], "h", TsModuleResolutionMode::NodeNext, "t");
    // Entry has non-empty resolved_path but actual is empty → UnexpectedFailure
    let status = index.validate_resolution("./x", None, TsRequestStyle::Import, "", None);
    assert_eq!(status, ReplayValidationStatus::UnexpectedFailure);
}

#[test]
fn enrichment_validate_content_drift() {
    let entry = TsResolutionReplayEntry {
        specifier: "./x".into(),
        referrer: None,
        style: TsRequestStyle::Import,
        resolved_path: "/x.ts".into(),
        package_name: None,
        selected_condition: None,
        resolved_content_hash: Some("sha256:old".into()),
        probe_count: 1,
    };
    let index =
        TsResolutionReplayIndex::build(vec![entry], "h", TsModuleResolutionMode::NodeNext, "t");
    let status = index.validate_resolution(
        "./x",
        None,
        TsRequestStyle::Import,
        "/x.ts",
        Some("sha256:new"),
    );
    assert_eq!(status, ReplayValidationStatus::ContentDrift);
}

#[test]
fn enrichment_validate_content_hash_match_is_matched() {
    let entry = TsResolutionReplayEntry {
        specifier: "./x".into(),
        referrer: None,
        style: TsRequestStyle::Import,
        resolved_path: "/x.ts".into(),
        package_name: None,
        selected_condition: None,
        resolved_content_hash: Some("sha256:same".into()),
        probe_count: 1,
    };
    let index =
        TsResolutionReplayIndex::build(vec![entry], "h", TsModuleResolutionMode::NodeNext, "t");
    let status = index.validate_resolution(
        "./x",
        None,
        TsRequestStyle::Import,
        "/x.ts",
        Some("sha256:same"),
    );
    assert_eq!(status, ReplayValidationStatus::Matched);
}

// ---------------------------------------------------------------------------
// ReplayIndex — dedup & mode sensitivity
// ---------------------------------------------------------------------------

#[test]
fn enrichment_replay_index_duplicate_entries_last_wins() {
    let mut e1 = make_entry("react", Some("app.ts"), TsRequestStyle::Import);
    e1.resolved_path = "/first.ts".into();
    let mut e2 = make_entry("react", Some("app.ts"), TsRequestStyle::Import);
    e2.resolved_path = "/second.ts".into();
    // Same lookup key — the build loop inserts both, last overwrites
    let index =
        TsResolutionReplayIndex::build(vec![e1, e2], "h", TsModuleResolutionMode::NodeNext, "t");
    // Only one entry should exist (deduped by key)
    assert_eq!(index.entry_count(), 1);
    let found = index
        .lookup("react", Some("app.ts"), TsRequestStyle::Import)
        .unwrap();
    assert_eq!(found.resolved_path, "/second.ts");
}

#[test]
fn enrichment_replay_index_different_modes_different_hashes() {
    let entries = vec![make_entry("react", None, TsRequestStyle::Import)];
    let i1 =
        TsResolutionReplayIndex::build(entries.clone(), "h", TsModuleResolutionMode::Node16, "t");
    let i2 =
        TsResolutionReplayIndex::build(entries.clone(), "h", TsModuleResolutionMode::NodeNext, "t");
    let i3 = TsResolutionReplayIndex::build(entries, "h", TsModuleResolutionMode::Bundler, "t");
    // All three should produce distinct hashes
    assert_ne!(i1.index_hash, i2.index_hash);
    assert_ne!(i1.index_hash, i3.index_hash);
    assert_ne!(i2.index_hash, i3.index_hash);
}

#[test]
fn enrichment_replay_index_different_tsconfig_hash_different_index_hash() {
    let entries = vec![make_entry("react", None, TsRequestStyle::Import)];
    let i1 = TsResolutionReplayIndex::build(
        entries.clone(),
        "hash-a",
        TsModuleResolutionMode::NodeNext,
        "t",
    );
    let i2 =
        TsResolutionReplayIndex::build(entries, "hash-b", TsModuleResolutionMode::NodeNext, "t");
    assert_ne!(i1.index_hash, i2.index_hash);
}

#[test]
fn enrichment_replay_index_schema_version_set() {
    let index = TsResolutionReplayIndex::build(
        Vec::new(),
        "h",
        TsModuleResolutionMode::NodeNext,
        "2026-03-12T00:00:00Z",
    );
    assert_eq!(index.schema_version, TS_REPLAY_INDEX_SCHEMA_VERSION);
    assert_eq!(index.generated_at_utc, "2026-03-12T00:00:00Z");
}

// ---------------------------------------------------------------------------
// ReplayValidationReport — exhaustive counting
// ---------------------------------------------------------------------------

#[test]
fn enrichment_validation_report_empty_statuses() {
    let report = ReplayValidationReport::from_statuses(&[]);
    assert!(report.passed); // 0 == 0 matched
    assert_eq!(report.total_entries, 0);
    assert_eq!(report.matched_count, 0);
}

#[test]
fn enrichment_validation_report_all_six_status_types() {
    let statuses = vec![
        ReplayValidationStatus::Matched,
        ReplayValidationStatus::PathMismatch,
        ReplayValidationStatus::SelectionMismatch,
        ReplayValidationStatus::UnexpectedSuccess,
        ReplayValidationStatus::UnexpectedFailure,
        ReplayValidationStatus::ContentDrift,
    ];
    let report = ReplayValidationReport::from_statuses(&statuses);
    assert!(!report.passed);
    assert_eq!(report.total_entries, 6);
    assert_eq!(report.matched_count, 1);
    assert_eq!(report.path_mismatch_count, 1);
    assert_eq!(report.selection_mismatch_count, 1);
    assert_eq!(report.unexpected_count, 2); // UnexpectedSuccess + UnexpectedFailure
    assert_eq!(report.content_drift_count, 1);
}

#[test]
fn enrichment_validation_report_serde_with_all_fields_populated() {
    let statuses = vec![
        ReplayValidationStatus::Matched,
        ReplayValidationStatus::PathMismatch,
        ReplayValidationStatus::SelectionMismatch,
        ReplayValidationStatus::ContentDrift,
        ReplayValidationStatus::UnexpectedSuccess,
    ];
    let report = ReplayValidationReport::from_statuses(&statuses);
    let json = serde_json::to_string(&report).unwrap();
    let back: ReplayValidationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
    assert!(!back.passed);
}

// ---------------------------------------------------------------------------
// ManifestFeatureFamily — exhaustive serde + description uniqueness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_feature_family_exhaustive_serde_roundtrip() {
    for f in ManifestFeatureFamily::ALL {
        let json = serde_json::to_string(f).unwrap();
        let back: ManifestFeatureFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*f, back, "roundtrip failed for {:?}", f);
    }
}

#[test]
fn enrichment_feature_family_descriptions_unique() {
    let descs: BTreeSet<&str> = ManifestFeatureFamily::ALL
        .iter()
        .map(|f| f.description())
        .collect();
    assert_eq!(descs.len(), ManifestFeatureFamily::ALL.len());
}

#[test]
fn enrichment_feature_family_display_equals_as_str() {
    for f in ManifestFeatureFamily::ALL {
        assert_eq!(f.to_string(), f.as_str());
    }
}

// ---------------------------------------------------------------------------
// ManifestExpectedOutcome — exhaustive serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_expected_outcome_exhaustive_serde() {
    let variants = [
        ManifestExpectedOutcome::Valid,
        ManifestExpectedOutcome::ReplayMatch,
        ManifestExpectedOutcome::ReplayMismatch,
        ManifestExpectedOutcome::ManifestComplete,
    ];
    let mut as_strs = BTreeSet::new();
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: ManifestExpectedOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
        as_strs.insert(v.as_str());
    }
    assert_eq!(as_strs.len(), 4, "as_str values must be unique");
}

// ---------------------------------------------------------------------------
// ManifestVerdict — serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_verdict_serde_roundtrip() {
    for v in [ManifestVerdict::Pass, ManifestVerdict::Fail] {
        let json = serde_json::to_string(&v).unwrap();
        let back: ManifestVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn enrichment_verdict_as_str_unique() {
    assert_ne!(
        ManifestVerdict::Pass.as_str(),
        ManifestVerdict::Fail.as_str()
    );
}

// ---------------------------------------------------------------------------
// Lineage types — serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn enrichment_normalization_lineage_serde() {
    let lineage = NormalizationLineage {
        source_hash: "sha256:src".into(),
        normalized_hash: "sha256:norm".into(),
        compiler_options_hash: "sha256:opts".into(),
        normalization_applied: true,
    };
    let json = serde_json::to_string(&lineage).unwrap();
    let back: NormalizationLineage = serde_json::from_str(&json).unwrap();
    assert_eq!(lineage, back);
}

#[test]
fn enrichment_normalization_lineage_js_no_normalization() {
    let lineage = NormalizationLineage {
        source_hash: "sha256:src".into(),
        normalized_hash: "sha256:src".into(), // same as source for JS
        compiler_options_hash: "sha256:opts".into(),
        normalization_applied: false,
    };
    assert!(!lineage.normalization_applied);
    assert_eq!(lineage.source_hash, lineage.normalized_hash);
    let json = serde_json::to_string(&lineage).unwrap();
    let back: NormalizationLineage = serde_json::from_str(&json).unwrap();
    assert_eq!(lineage, back);
}

#[test]
fn enrichment_resolution_lineage_serde() {
    let lineage = ResolutionLineage {
        decision_count: 10,
        resolved_count: 8,
        failed_count: 2,
        drift_class: TsResolutionDriftClass::CandidateOrderMismatch,
        replay_index_hash: Some("sha256:idx".into()),
    };
    let json = serde_json::to_string(&lineage).unwrap();
    let back: ResolutionLineage = serde_json::from_str(&json).unwrap();
    assert_eq!(lineage, back);
}

#[test]
fn enrichment_resolution_lineage_no_replay_index() {
    let lineage = ResolutionLineage {
        decision_count: 5,
        resolved_count: 5,
        failed_count: 0,
        drift_class: TsResolutionDriftClass::NoDrift,
        replay_index_hash: None,
    };
    let json = serde_json::to_string(&lineage).unwrap();
    let back: ResolutionLineage = serde_json::from_str(&json).unwrap();
    assert_eq!(lineage, back);
    assert!(back.replay_index_hash.is_none());
}

#[test]
fn enrichment_ir_pipeline_lineage_serde_all_some() {
    let lineage = IrPipelineLineage {
        ir0_hash: "sha256:ir0".into(),
        ir1_hash: Some("sha256:ir1".into()),
        ir2_hash: Some("sha256:ir2".into()),
        ir3_hash: Some("sha256:ir3".into()),
    };
    let json = serde_json::to_string(&lineage).unwrap();
    let back: IrPipelineLineage = serde_json::from_str(&json).unwrap();
    assert_eq!(lineage, back);
}

#[test]
fn enrichment_ir_pipeline_lineage_serde_partial_none() {
    let lineage = IrPipelineLineage {
        ir0_hash: "sha256:ir0".into(),
        ir1_hash: Some("sha256:ir1".into()),
        ir2_hash: None,
        ir3_hash: None,
    };
    let json = serde_json::to_string(&lineage).unwrap();
    let back: IrPipelineLineage = serde_json::from_str(&json).unwrap();
    assert_eq!(lineage, back);
    assert!(back.ir2_hash.is_none());
    assert!(back.ir3_hash.is_none());
}

// ---------------------------------------------------------------------------
// TsExecutionManifest — hash sensitivity & is_fully_resolved
// ---------------------------------------------------------------------------

#[test]
fn enrichment_execution_manifest_hash_sensitive_to_trace_id() {
    let m1 = TsExecutionManifest::build(build_manifest_input("trace-a"));
    let m2 = TsExecutionManifest::build(build_manifest_input("trace-b"));
    assert_ne!(m1.manifest_hash, m2.manifest_hash);
}

#[test]
fn enrichment_execution_manifest_hash_starts_with_sha256() {
    let m = TsExecutionManifest::build(build_manifest_input("trace-1"));
    assert!(m.manifest_hash.starts_with("sha256:"));
}

#[test]
fn enrichment_execution_manifest_schema_version_set() {
    let m = TsExecutionManifest::build(build_manifest_input("trace-1"));
    assert_eq!(m.schema_version, TS_EXECUTION_MANIFEST_SCHEMA_VERSION);
}

#[test]
fn enrichment_execution_manifest_is_fully_resolved_false_with_drift() {
    let mut input = build_manifest_input("trace-drift");
    input.resolution.drift_class = TsResolutionDriftClass::FullMismatch;
    let m = TsExecutionManifest::build(input);
    assert!(!m.is_fully_resolved());
}

#[test]
fn enrichment_execution_manifest_is_fully_resolved_false_with_failures() {
    let mut input = build_manifest_input("trace-fail");
    input.resolution.failed_count = 1;
    let m = TsExecutionManifest::build(input);
    assert!(!m.is_fully_resolved());
}

#[test]
fn enrichment_execution_manifest_is_fully_resolved_true_clean() {
    let m = TsExecutionManifest::build(build_manifest_input("trace-clean"));
    assert!(m.is_fully_resolved());
}

#[test]
fn enrichment_execution_manifest_serde_all_fields() {
    let m = TsExecutionManifest::build(build_manifest_input("trace-serde"));
    let json = serde_json::to_string(&m).unwrap();
    let back: TsExecutionManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
    assert_eq!(back.policy_id, TS_MANIFEST_POLICY_ID);
    assert_eq!(back.source_language, "TypeScript");
}

// ---------------------------------------------------------------------------
// Evidence harness types — serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_specimen_serde() {
    let s = ManifestSpecimen {
        specimen_id: "test-001".into(),
        feature_family: ManifestFeatureFamily::ReplayValidation,
        expected_outcome: ManifestExpectedOutcome::ReplayMatch,
        description: "Test specimen".into(),
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: ManifestSpecimen = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn enrichment_manifest_specimen_evidence_serde() {
    let ev = ManifestSpecimenEvidence {
        specimen_id: "test-002".into(),
        feature_family: ManifestFeatureFamily::ExecutionManifest,
        verdict: ManifestVerdict::Pass,
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: ManifestSpecimenEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn enrichment_manifest_evidence_event_serde() {
    let event = ManifestEvidenceEvent {
        schema_version: TS_MANIFEST_EVENT_SCHEMA_VERSION.into(),
        component: TS_MANIFEST_COMPONENT.into(),
        specimen_id: "test-003".into(),
        verdict: ManifestVerdict::Fail,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ManifestEvidenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn enrichment_manifest_run_manifest_serde() {
    let rm = ManifestRunManifest {
        schema_version: TS_MANIFEST_RUN_SCHEMA_VERSION.into(),
        component: TS_MANIFEST_COMPONENT.into(),
        policy_id: TS_MANIFEST_POLICY_ID.into(),
        specimen_count: 17,
        pass_count: 16,
        fail_count: 1,
    };
    let json = serde_json::to_string(&rm).unwrap();
    let back: ManifestRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(rm, back);
}

#[test]
fn enrichment_manifest_artifact_paths_serde() {
    let paths = ManifestArtifactPaths {
        run_manifest: "/tmp/test/run.json".into(),
        evidence_inventory: "/tmp/test/inv.json".into(),
        events_jsonl: "/tmp/test/events.jsonl".into(),
    };
    let json = serde_json::to_string(&paths).unwrap();
    let back: ManifestArtifactPaths = serde_json::from_str(&json).unwrap();
    assert_eq!(paths, back);
}

// ---------------------------------------------------------------------------
// Corpus — deeper invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_corpus_all_families_represented() {
    let corpus = manifest_corpus();
    let families: BTreeSet<ManifestFeatureFamily> =
        corpus.iter().map(|s| s.feature_family).collect();
    for f in ManifestFeatureFamily::ALL {
        assert!(
            families.contains(f),
            "corpus missing family: {}",
            f.as_str()
        );
    }
}

#[test]
fn enrichment_corpus_descriptions_non_empty() {
    for s in manifest_corpus() {
        assert!(
            !s.description.is_empty(),
            "specimen {} has empty description",
            s.specimen_id
        );
    }
}

#[test]
fn enrichment_corpus_specimen_ids_non_empty() {
    for s in manifest_corpus() {
        assert!(!s.specimen_id.is_empty());
    }
}

#[test]
fn enrichment_run_corpus_no_failures() {
    let (manifest, _, _) = run_manifest_corpus();
    assert_eq!(
        manifest.fail_count, 0,
        "corpus has {} failures",
        manifest.fail_count
    );
    assert_eq!(manifest.pass_count, manifest.specimen_count);
}

#[test]
fn enrichment_run_corpus_family_coverage_complete() {
    let (_, inventory, _) = run_manifest_corpus();
    // family_coverage should have entries for all families used
    for f in ManifestFeatureFamily::ALL {
        let key = f.as_str().to_string();
        assert!(
            inventory.family_coverage.contains_key(&key),
            "missing coverage for family: {}",
            key
        );
        assert!(
            *inventory.family_coverage.get(&key).unwrap() > 0,
            "zero coverage for family: {}",
            key
        );
    }
}

#[test]
fn enrichment_run_corpus_events_match_specimens() {
    let (_, inventory, events) = run_manifest_corpus();
    assert_eq!(events.len(), inventory.specimens.len());
    for (ev, spec) in events.iter().zip(inventory.specimens.iter()) {
        assert_eq!(ev.specimen_id, spec.specimen_id);
        assert_eq!(ev.verdict, spec.verdict);
    }
}

#[test]
fn enrichment_run_corpus_schema_versions_correct() {
    let (manifest, inventory, events) = run_manifest_corpus();
    assert_eq!(manifest.schema_version, TS_MANIFEST_RUN_SCHEMA_VERSION);
    assert_eq!(inventory.schema_version, TS_MANIFEST_SCHEMA_VERSION);
    for ev in &events {
        assert_eq!(ev.schema_version, TS_MANIFEST_EVENT_SCHEMA_VERSION);
    }
}

#[test]
fn enrichment_run_corpus_component_and_policy_correct() {
    let (manifest, inventory, events) = run_manifest_corpus();
    assert_eq!(manifest.component, TS_MANIFEST_COMPONENT);
    assert_eq!(manifest.policy_id, TS_MANIFEST_POLICY_ID);
    assert_eq!(inventory.component, TS_MANIFEST_COMPONENT);
    assert_eq!(inventory.policy_id, TS_MANIFEST_POLICY_ID);
    for ev in &events {
        assert_eq!(ev.component, TS_MANIFEST_COMPONENT);
    }
}

// ---------------------------------------------------------------------------
// write_manifest_evidence_bundle — file I/O
// ---------------------------------------------------------------------------

#[test]
fn enrichment_write_evidence_bundle_creates_files() {
    let (manifest, inventory, events) = run_manifest_corpus();
    let dir = std::env::temp_dir().join("ts_manifest_enrichment_bundle_test");
    let _ = std::fs::remove_dir_all(&dir);
    let paths = write_manifest_evidence_bundle(&dir, &manifest, &inventory, &events).unwrap();
    assert!(paths.run_manifest.exists());
    assert!(paths.evidence_inventory.exists());
    assert!(paths.events_jsonl.exists());
    // Verify run manifest can be deserialized from file
    let content = std::fs::read_to_string(&paths.run_manifest).unwrap();
    let loaded: ManifestRunManifest = serde_json::from_str(&content).unwrap();
    assert_eq!(loaded, manifest);
    // Verify inventory can be deserialized
    let inv_content = std::fs::read_to_string(&paths.evidence_inventory).unwrap();
    let loaded_inv: ManifestEvidenceInventory = serde_json::from_str(&inv_content).unwrap();
    assert_eq!(loaded_inv, inventory);
    // Verify events JSONL has correct line count
    let events_content = std::fs::read_to_string(&paths.events_jsonl).unwrap();
    let lines: Vec<&str> = events_content.lines().collect();
    assert_eq!(lines.len(), events.len());
    for (line, expected) in lines.iter().zip(events.iter()) {
        let parsed: ManifestEvidenceEvent = serde_json::from_str(line).unwrap();
        assert_eq!(parsed, *expected);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Constants — prefixes and content
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_schema_prefix() {
    assert!(TS_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(TS_REPLAY_INDEX_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(TS_EXECUTION_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(TS_MANIFEST_RUN_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(TS_MANIFEST_EVENT_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn enrichment_policy_id_is_rgc() {
    assert!(TS_MANIFEST_POLICY_ID.starts_with("RGC-"));
}
