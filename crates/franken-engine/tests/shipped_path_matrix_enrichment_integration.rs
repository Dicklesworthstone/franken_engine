//! Enrichment integration tests for the `shipped_path_matrix` module.
//!
//! Covers WorkloadClass, Surface, ArtifactKind, MismatchClass, MismatchSeverity,
//! CellVerdict, CapturedArtifact, compare_artifacts, classify_mismatch,
//! compute_cell_verdict, build_cell, evaluate_matrix, DecisionReceipt, and
//! serde roundtrips with edge cases.

#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::shipped_path_matrix::{
    ArtifactKind, BEAD_ID, COMPONENT, CapturedArtifact, CellVerdict, ClassifiedMismatch,
    DEFAULT_MAX_SIZE_DIVERGENCE, DecisionReceipt, MatrixCell, MatrixConfig, MatrixError,
    MatrixReport, MismatchClass, MismatchSeverity, POLICY_ID, SCHEMA_VERSION, Surface,
    WorkloadClass, build_cell, classify_mismatch, compare_artifacts, compute_cell_verdict,
    evaluate_matrix,
};

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(100)
}

fn relaxed_config() -> MatrixConfig {
    MatrixConfig {
        required_workload_classes: BTreeSet::new(),
        max_size_divergence_millionths: 1_000_000,
        require_source_maps: false,
        require_binding_traces: false,
        severity_threshold: MismatchSeverity::Critical,
    }
}

fn passing_cell(wc: WorkloadClass) -> MatrixCell {
    MatrixCell::new(wc, vec![], vec![], vec![], CellVerdict::Pass)
}

fn failing_cell(wc: WorkloadClass) -> MatrixCell {
    let mm = vec![ClassifiedMismatch {
        class: MismatchClass::ContentDivergence,
        severity: MismatchSeverity::Critical,
        surface: Surface::Cli,
        artifact_kind: ArtifactKind::CompiledOutput,
        workload_class: wc,
        detail: "test failure".to_string(),
        content_hash_a: Some(ContentHash::compute(b"a")),
        content_hash_b: Some(ContentHash::compute(b"b")),
    }];
    MatrixCell::new(wc, vec![], vec![], mm, CellVerdict::Fail)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_nonempty() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!COMPONENT.is_empty());
    assert!(!BEAD_ID.is_empty());
    assert!(!POLICY_ID.is_empty());
}

#[test]
fn enrichment_default_max_size_divergence_is_ten_percent() {
    assert_eq!(DEFAULT_MAX_SIZE_DIVERGENCE, 100_000);
}

// ---------------------------------------------------------------------------
// WorkloadClass
// ---------------------------------------------------------------------------

#[test]
fn enrichment_workload_class_all_six() {
    assert_eq!(WorkloadClass::ALL.len(), 6);
    let set: BTreeSet<WorkloadClass> = WorkloadClass::ALL.iter().copied().collect();
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_workload_class_as_str_display_match() {
    for wc in WorkloadClass::ALL {
        assert_eq!(wc.to_string(), wc.as_str());
    }
}

#[test]
fn enrichment_workload_class_serde_roundtrip() {
    for wc in WorkloadClass::ALL {
        let json = serde_json::to_string(wc).unwrap();
        let back: WorkloadClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*wc, back);
    }
}

#[test]
fn enrichment_workload_class_ordering() {
    assert!(WorkloadClass::PureJs < WorkloadClass::PureTs);
    assert!(WorkloadClass::MixedJsTs < WorkloadClass::Esm);
}

// ---------------------------------------------------------------------------
// Surface
// ---------------------------------------------------------------------------

#[test]
fn enrichment_surface_all_two() {
    assert_eq!(Surface::ALL.len(), 2);
}

#[test]
fn enrichment_surface_as_str_match_display() {
    for s in Surface::ALL {
        assert_eq!(s.to_string(), s.as_str());
    }
}

#[test]
fn enrichment_surface_serde_roundtrip() {
    for s in Surface::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: Surface = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ---------------------------------------------------------------------------
// ArtifactKind
// ---------------------------------------------------------------------------

#[test]
fn enrichment_artifact_kind_all_six() {
    assert_eq!(ArtifactKind::ALL.len(), 6);
}

#[test]
fn enrichment_artifact_kind_display_matches_as_str() {
    for k in ArtifactKind::ALL {
        assert_eq!(k.to_string(), k.as_str());
    }
}

#[test]
fn enrichment_artifact_kind_semantic_weight_compiled_highest() {
    assert_eq!(ArtifactKind::CompiledOutput.semantic_weight(), 10);
    assert!(
        ArtifactKind::CompiledOutput.semantic_weight() > ArtifactKind::Diagnostic.semantic_weight()
    );
}

#[test]
fn enrichment_artifact_kind_serde_roundtrip() {
    for k in ArtifactKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: ArtifactKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

// ---------------------------------------------------------------------------
// MismatchClass
// ---------------------------------------------------------------------------

#[test]
fn enrichment_mismatch_class_all_six() {
    assert_eq!(MismatchClass::ALL.len(), 6);
}

#[test]
fn enrichment_mismatch_class_display_matches_as_str() {
    for mc in MismatchClass::ALL {
        assert_eq!(mc.to_string(), mc.as_str());
    }
}

#[test]
fn enrichment_mismatch_class_serde_roundtrip() {
    for mc in MismatchClass::ALL {
        let json = serde_json::to_string(mc).unwrap();
        let back: MismatchClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*mc, back);
    }
}

// ---------------------------------------------------------------------------
// MismatchSeverity
// ---------------------------------------------------------------------------

#[test]
fn enrichment_severity_rank_ascending() {
    assert!(MismatchSeverity::Informational.rank() < MismatchSeverity::Minor.rank());
    assert!(MismatchSeverity::Minor.rank() < MismatchSeverity::Major.rank());
    assert!(MismatchSeverity::Major.rank() < MismatchSeverity::Critical.rank());
}

#[test]
fn enrichment_severity_serde_roundtrip() {
    for s in MismatchSeverity::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: MismatchSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ---------------------------------------------------------------------------
// CellVerdict
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cell_verdict_display_matches_as_str() {
    for v in CellVerdict::ALL {
        assert_eq!(v.to_string(), v.as_str());
    }
}

#[test]
fn enrichment_cell_verdict_serde_roundtrip() {
    for v in CellVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: CellVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// CapturedArtifact
// ---------------------------------------------------------------------------

#[test]
fn enrichment_captured_artifact_new_fields() {
    let a = CapturedArtifact::new(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        b"hello world",
        WorkloadClass::PureJs,
    );
    assert_eq!(a.kind, ArtifactKind::CompiledOutput);
    assert_eq!(a.surface, Surface::Library);
    assert_eq!(a.size_bytes, 11);
    assert_eq!(a.workload_class, WorkloadClass::PureJs);
}

#[test]
fn enrichment_captured_artifact_hash_deterministic() {
    let a = CapturedArtifact::new(
        ArtifactKind::SourceMap,
        Surface::Cli,
        b"data",
        WorkloadClass::Esm,
    );
    let b = CapturedArtifact::new(
        ArtifactKind::SourceMap,
        Surface::Cli,
        b"data",
        WorkloadClass::Esm,
    );
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn enrichment_captured_artifact_different_payload_different_hash() {
    let a = CapturedArtifact::new(
        ArtifactKind::SourceMap,
        Surface::Cli,
        b"alpha",
        WorkloadClass::Esm,
    );
    let b = CapturedArtifact::new(
        ArtifactKind::SourceMap,
        Surface::Cli,
        b"beta",
        WorkloadClass::Esm,
    );
    assert_ne!(a.content_hash, b.content_hash);
}

#[test]
fn enrichment_captured_artifact_serde_roundtrip() {
    let a = CapturedArtifact::new(
        ArtifactKind::Diagnostic,
        Surface::Library,
        b"msg",
        WorkloadClass::Cjs,
    );
    let json = serde_json::to_string(&a).unwrap();
    let back: CapturedArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

// ---------------------------------------------------------------------------
// classify_mismatch
// ---------------------------------------------------------------------------

#[test]
fn enrichment_classify_compiled_output_critical() {
    let sev = classify_mismatch(
        &ArtifactKind::CompiledOutput,
        Surface::Library,
        "divergence",
    );
    assert_eq!(sev, MismatchSeverity::Critical);
}

#[test]
fn enrichment_classify_module_graph_critical() {
    let sev = classify_mismatch(&ArtifactKind::ModuleGraph, Surface::Cli, "divergence");
    assert_eq!(sev, MismatchSeverity::Critical);
}

#[test]
fn enrichment_classify_source_map_minor() {
    let sev = classify_mismatch(&ArtifactKind::SourceMap, Surface::Library, "divergence");
    assert_eq!(sev, MismatchSeverity::Minor);
}

#[test]
fn enrichment_classify_diagnostic_informational() {
    let sev = classify_mismatch(&ArtifactKind::Diagnostic, Surface::Cli, "divergence");
    assert_eq!(sev, MismatchSeverity::Informational);
}

#[test]
fn enrichment_classify_missing_high_weight_critical() {
    let sev = classify_mismatch(
        &ArtifactKind::CompiledOutput,
        Surface::Cli,
        "missing from CLI",
    );
    assert_eq!(sev, MismatchSeverity::Critical);
}

#[test]
fn enrichment_classify_missing_low_weight_major() {
    let sev = classify_mismatch(&ArtifactKind::SourceMap, Surface::Library, "absent");
    assert_eq!(sev, MismatchSeverity::Major);
}

// ---------------------------------------------------------------------------
// compare_artifacts
// ---------------------------------------------------------------------------

#[test]
fn enrichment_compare_identical_no_mismatches() {
    let cfg = relaxed_config();
    let a = vec![CapturedArtifact::new(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        b"code",
        WorkloadClass::PureJs,
    )];
    let b = vec![CapturedArtifact::new(
        ArtifactKind::CompiledOutput,
        Surface::Cli,
        b"code",
        WorkloadClass::PureJs,
    )];
    let mm = compare_artifacts(&a, &b, &cfg);
    assert!(mm.is_empty());
}

#[test]
fn enrichment_compare_content_divergence() {
    let cfg = relaxed_config();
    let a = vec![CapturedArtifact::new(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        b"alpha",
        WorkloadClass::PureJs,
    )];
    let b = vec![CapturedArtifact::new(
        ArtifactKind::CompiledOutput,
        Surface::Cli,
        b"beta",
        WorkloadClass::PureJs,
    )];
    let mm = compare_artifacts(&a, &b, &cfg);
    assert!(
        mm.iter()
            .any(|m| m.class == MismatchClass::ContentDivergence)
    );
}

#[test]
fn enrichment_compare_missing_artifact() {
    let cfg = relaxed_config();
    let a = vec![CapturedArtifact::new(
        ArtifactKind::ModuleGraph,
        Surface::Library,
        b"graph",
        WorkloadClass::Esm,
    )];
    let mm = compare_artifacts(&a, &[], &cfg);
    assert!(mm.iter().any(|m| m.class == MismatchClass::Missing));
}

#[test]
fn enrichment_compare_extra_artifact() {
    let cfg = relaxed_config();
    let b = vec![CapturedArtifact::new(
        ArtifactKind::Diagnostic,
        Surface::Cli,
        b"diag",
        WorkloadClass::Cjs,
    )];
    let mm = compare_artifacts(&[], &b, &cfg);
    assert!(mm.iter().any(|m| m.class == MismatchClass::Extra));
}

#[test]
fn enrichment_compare_empty_no_mismatches() {
    let cfg = relaxed_config();
    let mm = compare_artifacts(&[], &[], &cfg);
    assert!(mm.is_empty());
}

// ---------------------------------------------------------------------------
// compute_cell_verdict
// ---------------------------------------------------------------------------

#[test]
fn enrichment_verdict_pass_no_mismatches() {
    let cfg = MatrixConfig::default();
    let v = compute_cell_verdict(&[], &cfg);
    assert_eq!(v, CellVerdict::Pass);
}

#[test]
fn enrichment_verdict_fail_critical() {
    let cfg = MatrixConfig::default();
    let mm = vec![ClassifiedMismatch {
        class: MismatchClass::ContentDivergence,
        severity: MismatchSeverity::Critical,
        surface: Surface::Cli,
        artifact_kind: ArtifactKind::CompiledOutput,
        workload_class: WorkloadClass::PureJs,
        detail: "test".to_string(),
        content_hash_a: None,
        content_hash_b: None,
    }];
    let v = compute_cell_verdict(&mm, &cfg);
    assert_eq!(v, CellVerdict::Fail);
}

#[test]
fn enrichment_verdict_pass_below_threshold() {
    let cfg = MatrixConfig {
        severity_threshold: MismatchSeverity::Critical,
        ..MatrixConfig::default()
    };
    let mm = vec![ClassifiedMismatch {
        class: MismatchClass::SemanticDivergence,
        severity: MismatchSeverity::Minor,
        surface: Surface::Library,
        artifact_kind: ArtifactKind::Diagnostic,
        workload_class: WorkloadClass::MixedJsTs,
        detail: "minor".to_string(),
        content_hash_a: None,
        content_hash_b: None,
    }];
    let v = compute_cell_verdict(&mm, &cfg);
    assert_eq!(v, CellVerdict::Pass);
}

// ---------------------------------------------------------------------------
// build_cell
// ---------------------------------------------------------------------------

#[test]
fn enrichment_build_cell_pass_identical() {
    let cfg = relaxed_config();
    let a = vec![CapturedArtifact::new(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        b"x",
        WorkloadClass::PureJs,
    )];
    let b = vec![CapturedArtifact::new(
        ArtifactKind::CompiledOutput,
        Surface::Cli,
        b"x",
        WorkloadClass::PureJs,
    )];
    let cell = build_cell(WorkloadClass::PureJs, a, b, &cfg);
    assert_eq!(cell.verdict, CellVerdict::Pass);
    assert!(cell.mismatches.is_empty());
}

#[test]
fn enrichment_build_cell_divergence_detected() {
    let cfg = relaxed_config();
    let a = vec![CapturedArtifact::new(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        b"alpha",
        WorkloadClass::PureTs,
    )];
    let b = vec![CapturedArtifact::new(
        ArtifactKind::CompiledOutput,
        Surface::Cli,
        b"beta",
        WorkloadClass::PureTs,
    )];
    let cell = build_cell(WorkloadClass::PureTs, a, b, &cfg);
    assert!(!cell.mismatches.is_empty());
}

// ---------------------------------------------------------------------------
// evaluate_matrix
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evaluate_no_cells_error() {
    let cfg = relaxed_config();
    let err = evaluate_matrix(&[], &cfg, &epoch(), 0).unwrap_err();
    assert!(matches!(err, MatrixError::NoCells));
}

#[test]
fn enrichment_evaluate_duplicate_class_error() {
    let cfg = relaxed_config();
    let cells = vec![
        passing_cell(WorkloadClass::PureJs),
        passing_cell(WorkloadClass::PureJs),
    ];
    let err = evaluate_matrix(&cells, &cfg, &epoch(), 0).unwrap_err();
    assert!(matches!(err, MatrixError::DuplicateWorkloadClass { .. }));
}

#[test]
fn enrichment_evaluate_all_pass() {
    let cfg = relaxed_config();
    let cells: Vec<MatrixCell> = WorkloadClass::ALL
        .iter()
        .map(|wc| passing_cell(*wc))
        .collect();
    let report = evaluate_matrix(&cells, &cfg, &epoch(), 1000).unwrap();
    assert_eq!(report.overall_verdict, CellVerdict::Pass);
    assert_eq!(report.total_mismatches, 0);
}

#[test]
fn enrichment_evaluate_one_fail_overall_fail() {
    let cfg = relaxed_config();
    let cells = vec![
        passing_cell(WorkloadClass::PureJs),
        failing_cell(WorkloadClass::PureTs),
    ];
    let report = evaluate_matrix(&cells, &cfg, &epoch(), 0).unwrap();
    assert_eq!(report.overall_verdict, CellVerdict::Fail);
    assert_eq!(report.critical_count, 1);
}

#[test]
fn enrichment_evaluate_inconclusive_propagates() {
    let cfg = relaxed_config();
    let cells = vec![
        passing_cell(WorkloadClass::PureJs),
        MatrixCell::new(
            WorkloadClass::Esm,
            vec![],
            vec![],
            vec![],
            CellVerdict::Inconclusive,
        ),
    ];
    let report = evaluate_matrix(&cells, &cfg, &epoch(), 0).unwrap();
    assert_eq!(report.overall_verdict, CellVerdict::Inconclusive);
}

#[test]
fn enrichment_evaluate_fail_beats_inconclusive() {
    let cfg = relaxed_config();
    let cells = vec![
        failing_cell(WorkloadClass::PureJs),
        MatrixCell::new(
            WorkloadClass::Esm,
            vec![],
            vec![],
            vec![],
            CellVerdict::Inconclusive,
        ),
    ];
    let report = evaluate_matrix(&cells, &cfg, &epoch(), 0).unwrap();
    assert_eq!(report.overall_verdict, CellVerdict::Fail);
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

#[test]
fn enrichment_receipt_deterministic() {
    let e = epoch();
    let ih = ContentHash::compute(b"input");
    let r1 = DecisionReceipt::compute(&e, ih, CellVerdict::Pass, 1_000_000);
    let r2 = DecisionReceipt::compute(&e, ih, CellVerdict::Pass, 1_000_000);
    assert_eq!(r1.verdict_hash, r2.verdict_hash);
}

#[test]
fn enrichment_receipt_different_verdict_different_hash() {
    let e = epoch();
    let ih = ContentHash::compute(b"input");
    let r1 = DecisionReceipt::compute(&e, ih, CellVerdict::Pass, 1000);
    let r2 = DecisionReceipt::compute(&e, ih, CellVerdict::Fail, 1000);
    assert_ne!(r1.verdict_hash, r2.verdict_hash);
}

#[test]
fn enrichment_receipt_fields_correct() {
    let r = DecisionReceipt::compute(&epoch(), ContentHash::compute(b"x"), CellVerdict::Pass, 42);
    assert_eq!(r.schema_version, SCHEMA_VERSION);
    assert_eq!(r.component, COMPONENT);
    assert_eq!(r.bead_id, BEAD_ID);
    assert_eq!(r.policy_id, POLICY_ID);
    assert_eq!(r.timestamp_micros, 42);
}

#[test]
fn enrichment_receipt_serde_roundtrip() {
    let r = DecisionReceipt::compute(&epoch(), ContentHash::compute(b"x"), CellVerdict::Fail, 999);
    let json = serde_json::to_string(&r).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// MatrixError
// ---------------------------------------------------------------------------

#[test]
fn enrichment_matrix_error_display_no_cells() {
    let e = MatrixError::NoCells;
    assert_eq!(format!("{e}"), "no cells provided for matrix evaluation");
}

#[test]
fn enrichment_matrix_error_serde_roundtrip() {
    let errors = [
        MatrixError::NoCells,
        MatrixError::MissingWorkloadClass {
            class: WorkloadClass::Esm,
        },
        MatrixError::DuplicateWorkloadClass {
            class: WorkloadClass::Cjs,
        },
        MatrixError::InvalidConfig {
            detail: "bad".to_string(),
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: MatrixError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ---------------------------------------------------------------------------
// MatrixConfig
// ---------------------------------------------------------------------------

#[test]
fn enrichment_config_default_all_required() {
    let cfg = MatrixConfig::default();
    assert_eq!(cfg.required_workload_classes.len(), 6);
    assert!(cfg.require_source_maps);
    assert!(!cfg.require_binding_traces);
}

#[test]
fn enrichment_config_serde_roundtrip() {
    let cfg = MatrixConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: MatrixConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ---------------------------------------------------------------------------
// MatrixReport serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_serde_roundtrip() {
    let cfg = relaxed_config();
    let cells = vec![passing_cell(WorkloadClass::PureJs)];
    let report = evaluate_matrix(&cells, &cfg, &epoch(), 1).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let back: MatrixReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// MatrixCell
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cell_critical_and_major_count() {
    let cell = failing_cell(WorkloadClass::PureJs);
    assert_eq!(cell.critical_count(), 1);
    assert_eq!(cell.major_count(), 0);
}

#[test]
fn enrichment_cell_passing_no_mismatches() {
    let cell = passing_cell(WorkloadClass::PureTs);
    assert_eq!(cell.verdict, CellVerdict::Pass);
    assert_eq!(cell.mismatches.len(), 0);
}
