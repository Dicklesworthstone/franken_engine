//! Integration tests for `shipped_path_matrix` module.
//!
//! Validates public API surface, serde contracts, determinism, mismatch
//! classification, matrix evaluation, receipt integrity, and edge-case
//! handling for JS/TS shipped-path parity verification.

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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::shipped_path_matrix::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(500)
}

fn art(
    kind: ArtifactKind,
    surface: Surface,
    payload: &[u8],
    wc: WorkloadClass,
) -> CapturedArtifact {
    CapturedArtifact::new(kind, surface, payload, wc)
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

fn strict_config() -> MatrixConfig {
    MatrixConfig {
        required_workload_classes: WorkloadClass::ALL.iter().copied().collect(),
        max_size_divergence_millionths: 50_000,
        require_source_maps: true,
        require_binding_traces: true,
        severity_threshold: MismatchSeverity::Major,
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
        detail: "critical divergence".to_string(),
        content_hash_a: Some(ContentHash::compute(b"lib")),
        content_hash_b: Some(ContentHash::compute(b"cli")),
    }];
    MatrixCell::new(wc, vec![], vec![], mm, CellVerdict::Fail)
}

fn inconclusive_cell(wc: WorkloadClass) -> MatrixCell {
    MatrixCell::new(wc, vec![], vec![], vec![], CellVerdict::Inconclusive)
}

fn all_passing_cells() -> Vec<MatrixCell> {
    WorkloadClass::ALL
        .iter()
        .map(|wc| passing_cell(*wc))
        .collect()
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_value() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SCHEMA_VERSION.contains("shipped-path-matrix"));
}

#[test]
fn test_component_value() {
    assert_eq!(COMPONENT, "shipped_path_matrix");
}

#[test]
fn test_bead_id_value() {
    assert_eq!(BEAD_ID, "bd-1lsy.9.6.2");
}

#[test]
fn test_policy_id_value() {
    assert_eq!(POLICY_ID, "RGC-806B");
}

#[test]
fn test_default_max_size_divergence_value() {
    assert_eq!(DEFAULT_MAX_SIZE_DIVERGENCE, 100_000);
}

// ---------------------------------------------------------------------------
// WorkloadClass — exhaustive
// ---------------------------------------------------------------------------

#[test]
fn test_workload_class_all_variants() {
    let all = WorkloadClass::ALL;
    assert_eq!(all.len(), 6);
    assert!(all.contains(&WorkloadClass::PureJs));
    assert!(all.contains(&WorkloadClass::PureTs));
    assert!(all.contains(&WorkloadClass::MixedJsTs));
    assert!(all.contains(&WorkloadClass::Esm));
    assert!(all.contains(&WorkloadClass::Cjs));
    assert!(all.contains(&WorkloadClass::MixedEsmCjs));
}

#[test]
fn test_workload_class_as_str_exhaustive() {
    assert_eq!(WorkloadClass::PureJs.as_str(), "pure_js");
    assert_eq!(WorkloadClass::PureTs.as_str(), "pure_ts");
    assert_eq!(WorkloadClass::MixedJsTs.as_str(), "mixed_js_ts");
    assert_eq!(WorkloadClass::Esm.as_str(), "esm");
    assert_eq!(WorkloadClass::Cjs.as_str(), "cjs");
    assert_eq!(WorkloadClass::MixedEsmCjs.as_str(), "mixed_esm_cjs");
}

#[test]
fn test_workload_class_display_matches_as_str() {
    for wc in WorkloadClass::ALL {
        assert_eq!(format!("{wc}"), wc.as_str());
    }
}

#[test]
fn test_workload_class_serde_all() {
    for wc in WorkloadClass::ALL {
        let json = serde_json::to_string(wc).unwrap();
        let back: WorkloadClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*wc, back);
    }
}

#[test]
fn test_workload_class_ordering_total() {
    for (i, a) in WorkloadClass::ALL.iter().enumerate() {
        for (j, b) in WorkloadClass::ALL.iter().enumerate() {
            if i < j {
                assert!(a < b, "{a} should be < {b}");
            } else if i > j {
                assert!(a > b, "{a} should be > {b}");
            } else {
                assert_eq!(a, b);
            }
        }
    }
}

#[test]
fn test_workload_class_btreeset_insertion() {
    let set: BTreeSet<WorkloadClass> = WorkloadClass::ALL.iter().copied().collect();
    assert_eq!(set.len(), 6);
}

// ---------------------------------------------------------------------------
// Surface
// ---------------------------------------------------------------------------

#[test]
fn test_surface_all_variants() {
    assert_eq!(Surface::ALL.len(), 2);
    assert!(Surface::ALL.contains(&Surface::Library));
    assert!(Surface::ALL.contains(&Surface::Cli));
}

#[test]
fn test_surface_as_str_exhaustive() {
    assert_eq!(Surface::Library.as_str(), "library");
    assert_eq!(Surface::Cli.as_str(), "cli");
}

#[test]
fn test_surface_display_all() {
    for s in Surface::ALL {
        assert_eq!(format!("{s}"), s.as_str());
    }
}

#[test]
fn test_surface_serde_all() {
    for s in Surface::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: Surface = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

#[test]
fn test_surface_clone_copy() {
    let s = Surface::Library;
    let s2 = s;
    assert_eq!(s, s2);
}

// ---------------------------------------------------------------------------
// ArtifactKind
// ---------------------------------------------------------------------------

#[test]
fn test_artifact_kind_all_variants() {
    assert_eq!(ArtifactKind::ALL.len(), 6);
}

#[test]
fn test_artifact_kind_as_str_exhaustive() {
    assert_eq!(ArtifactKind::CompiledOutput.as_str(), "compiled_output");
    assert_eq!(ArtifactKind::SourceMap.as_str(), "source_map");
    assert_eq!(ArtifactKind::TypeAnnotation.as_str(), "type_annotation");
    assert_eq!(ArtifactKind::Diagnostic.as_str(), "diagnostic");
    assert_eq!(ArtifactKind::ModuleGraph.as_str(), "module_graph");
    assert_eq!(ArtifactKind::BindingTrace.as_str(), "binding_trace");
}

#[test]
fn test_artifact_kind_display_all() {
    for k in ArtifactKind::ALL {
        assert_eq!(format!("{k}"), k.as_str());
    }
}

#[test]
fn test_artifact_kind_serde_all() {
    for k in ArtifactKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: ArtifactKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

#[test]
fn test_artifact_kind_semantic_weight_range() {
    for k in ArtifactKind::ALL {
        let w = k.semantic_weight();
        assert!(
            w >= 1 && w <= 10,
            "weight {w} out of expected range for {k}"
        );
    }
}

#[test]
fn test_artifact_kind_semantic_weight_compiled_highest() {
    assert_eq!(ArtifactKind::CompiledOutput.semantic_weight(), 10);
}

#[test]
fn test_artifact_kind_semantic_weight_diagnostic_lowest() {
    assert_eq!(ArtifactKind::Diagnostic.semantic_weight(), 3);
}

// ---------------------------------------------------------------------------
// CapturedArtifact
// ---------------------------------------------------------------------------

#[test]
fn test_captured_artifact_construction() {
    let a = CapturedArtifact::new(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        b"function f() {}",
        WorkloadClass::PureJs,
    );
    assert_eq!(a.kind, ArtifactKind::CompiledOutput);
    assert_eq!(a.surface, Surface::Library);
    assert_eq!(a.size_bytes, 15);
    assert_eq!(a.workload_class, WorkloadClass::PureJs);
}

#[test]
fn test_captured_artifact_empty_payload() {
    let a = CapturedArtifact::new(
        ArtifactKind::Diagnostic,
        Surface::Cli,
        b"",
        WorkloadClass::Cjs,
    );
    assert_eq!(a.size_bytes, 0);
}

#[test]
fn test_captured_artifact_hash_deterministic() {
    let a = CapturedArtifact::new(
        ArtifactKind::SourceMap,
        Surface::Library,
        b"map",
        WorkloadClass::Esm,
    );
    let b = CapturedArtifact::new(
        ArtifactKind::SourceMap,
        Surface::Library,
        b"map",
        WorkloadClass::Esm,
    );
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn test_captured_artifact_hash_varies_with_payload() {
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
fn test_captured_artifact_serde_roundtrip() {
    let a = CapturedArtifact::new(
        ArtifactKind::ModuleGraph,
        Surface::Library,
        b"graph-data",
        WorkloadClass::MixedJsTs,
    );
    let json = serde_json::to_string(&a).unwrap();
    let back: CapturedArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

#[test]
fn test_captured_artifact_large_payload() {
    let payload = vec![0xFFu8; 65536];
    let a = CapturedArtifact::new(
        ArtifactKind::CompiledOutput,
        Surface::Cli,
        &payload,
        WorkloadClass::PureTs,
    );
    assert_eq!(a.size_bytes, 65536);
}

// ---------------------------------------------------------------------------
// MismatchClass
// ---------------------------------------------------------------------------

#[test]
fn test_mismatch_class_all_count() {
    assert_eq!(MismatchClass::ALL.len(), 6);
}

#[test]
fn test_mismatch_class_as_str_exhaustive() {
    assert_eq!(MismatchClass::Missing.as_str(), "missing");
    assert_eq!(MismatchClass::Extra.as_str(), "extra");
    assert_eq!(
        MismatchClass::ContentDivergence.as_str(),
        "content_divergence"
    );
    assert_eq!(MismatchClass::SizeDivergence.as_str(), "size_divergence");
    assert_eq!(MismatchClass::OrderDivergence.as_str(), "order_divergence");
    assert_eq!(
        MismatchClass::SemanticDivergence.as_str(),
        "semantic_divergence"
    );
}

#[test]
fn test_mismatch_class_display_all() {
    for mc in MismatchClass::ALL {
        assert_eq!(format!("{mc}"), mc.as_str());
    }
}

#[test]
fn test_mismatch_class_serde_all() {
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
fn test_severity_all_count() {
    assert_eq!(MismatchSeverity::ALL.len(), 4);
}

#[test]
fn test_severity_rank_monotonic() {
    let mut prev = 0;
    for s in MismatchSeverity::ALL {
        assert!(s.rank() >= prev, "{s} rank {} < prev {prev}", s.rank());
        prev = s.rank();
    }
}

#[test]
fn test_severity_rank_values() {
    assert_eq!(MismatchSeverity::Informational.rank(), 0);
    assert_eq!(MismatchSeverity::Minor.rank(), 1);
    assert_eq!(MismatchSeverity::Major.rank(), 2);
    assert_eq!(MismatchSeverity::Critical.rank(), 3);
}

#[test]
fn test_severity_display_all() {
    for s in MismatchSeverity::ALL {
        assert_eq!(format!("{s}"), s.as_str());
    }
}

#[test]
fn test_severity_serde_all() {
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
fn test_cell_verdict_all_count() {
    assert_eq!(CellVerdict::ALL.len(), 3);
}

#[test]
fn test_cell_verdict_as_str_exhaustive() {
    assert_eq!(CellVerdict::Pass.as_str(), "pass");
    assert_eq!(CellVerdict::Fail.as_str(), "fail");
    assert_eq!(CellVerdict::Inconclusive.as_str(), "inconclusive");
}

#[test]
fn test_cell_verdict_display_all() {
    for v in CellVerdict::ALL {
        assert_eq!(format!("{v}"), v.as_str());
    }
}

#[test]
fn test_cell_verdict_serde_all() {
    for v in CellVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: CellVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// classify_mismatch
// ---------------------------------------------------------------------------

#[test]
fn test_classify_compiled_output_critical() {
    let s = classify_mismatch(
        &ArtifactKind::CompiledOutput,
        Surface::Library,
        "divergence",
    );
    assert_eq!(s, MismatchSeverity::Critical);
}

#[test]
fn test_classify_module_graph_critical() {
    let s = classify_mismatch(&ArtifactKind::ModuleGraph, Surface::Cli, "changed");
    assert_eq!(s, MismatchSeverity::Critical);
}

#[test]
fn test_classify_binding_trace_major() {
    let s = classify_mismatch(&ArtifactKind::BindingTrace, Surface::Library, "divergence");
    assert_eq!(s, MismatchSeverity::Major);
}

#[test]
fn test_classify_type_annotation_major() {
    let s = classify_mismatch(&ArtifactKind::TypeAnnotation, Surface::Cli, "divergence");
    assert_eq!(s, MismatchSeverity::Major);
}

#[test]
fn test_classify_source_map_minor() {
    let s = classify_mismatch(&ArtifactKind::SourceMap, Surface::Library, "offset");
    assert_eq!(s, MismatchSeverity::Minor);
}

#[test]
fn test_classify_diagnostic_informational() {
    let s = classify_mismatch(&ArtifactKind::Diagnostic, Surface::Cli, "order changed");
    assert_eq!(s, MismatchSeverity::Informational);
}

#[test]
fn test_classify_missing_high_weight_is_critical() {
    let s = classify_mismatch(
        &ArtifactKind::CompiledOutput,
        Surface::Cli,
        "missing on CLI",
    );
    assert_eq!(s, MismatchSeverity::Critical);
}

#[test]
fn test_classify_missing_low_weight_is_major() {
    let s = classify_mismatch(
        &ArtifactKind::Diagnostic,
        Surface::Library,
        "absent from lib",
    );
    assert_eq!(s, MismatchSeverity::Major);
}

#[test]
fn test_classify_absent_keyword_triggers_missing_path() {
    let s = classify_mismatch(&ArtifactKind::SourceMap, Surface::Cli, "artifact absent");
    assert_eq!(s, MismatchSeverity::Major);
}

// ---------------------------------------------------------------------------
// compare_artifacts — basic scenarios
// ---------------------------------------------------------------------------

#[test]
fn test_compare_empty_lists() {
    let mm = compare_artifacts(&[], &[], &relaxed_config());
    assert!(mm.is_empty());
}

#[test]
fn test_compare_identical_single() {
    let cfg = relaxed_config();
    let a = vec![art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        b"code",
        WorkloadClass::PureJs,
    )];
    let b = vec![art(
        ArtifactKind::CompiledOutput,
        Surface::Cli,
        b"code",
        WorkloadClass::PureJs,
    )];
    let mm = compare_artifacts(&a, &b, &cfg);
    assert!(mm.is_empty());
}

#[test]
fn test_compare_content_divergence() {
    let cfg = relaxed_config();
    let a = vec![art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        b"aaa",
        WorkloadClass::PureJs,
    )];
    let b = vec![art(
        ArtifactKind::CompiledOutput,
        Surface::Cli,
        b"bbb",
        WorkloadClass::PureJs,
    )];
    let mm = compare_artifacts(&a, &b, &cfg);
    assert!(
        mm.iter()
            .any(|m| m.class == MismatchClass::ContentDivergence)
    );
}

#[test]
fn test_compare_missing_from_b() {
    let cfg = relaxed_config();
    let a = vec![art(
        ArtifactKind::ModuleGraph,
        Surface::Library,
        b"graph",
        WorkloadClass::Esm,
    )];
    let mm = compare_artifacts(&a, &[], &cfg);
    assert!(mm.iter().any(|m| m.class == MismatchClass::Missing));
    assert!(mm.iter().any(|m| m.surface == Surface::Cli));
}

#[test]
fn test_compare_extra_on_b() {
    let cfg = relaxed_config();
    let b = vec![art(
        ArtifactKind::Diagnostic,
        Surface::Cli,
        b"warn",
        WorkloadClass::Cjs,
    )];
    let mm = compare_artifacts(&[], &b, &cfg);
    assert!(mm.iter().any(|m| m.class == MismatchClass::Extra));
}

#[test]
fn test_compare_size_divergence_detected() {
    let cfg = MatrixConfig {
        max_size_divergence_millionths: 50_000,
        require_source_maps: false,
        require_binding_traces: false,
        ..relaxed_config()
    };
    let a = vec![art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        &[0u8; 100],
        WorkloadClass::PureTs,
    )];
    let b = vec![art(
        ArtifactKind::CompiledOutput,
        Surface::Cli,
        &[0u8; 200],
        WorkloadClass::PureTs,
    )];
    let mm = compare_artifacts(&a, &b, &cfg);
    assert!(mm.iter().any(|m| m.class == MismatchClass::SizeDivergence));
}

#[test]
fn test_compare_size_divergence_within_tolerance() {
    let cfg = MatrixConfig {
        max_size_divergence_millionths: 1_000_000,
        require_source_maps: false,
        require_binding_traces: false,
        ..relaxed_config()
    };
    let a = vec![art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        &[0u8; 100],
        WorkloadClass::PureTs,
    )];
    let b = vec![art(
        ArtifactKind::CompiledOutput,
        Surface::Cli,
        &[0u8; 110],
        WorkloadClass::PureTs,
    )];
    let mm = compare_artifacts(&a, &b, &cfg);
    assert!(!mm.iter().any(|m| m.class == MismatchClass::SizeDivergence));
}

// ---------------------------------------------------------------------------
// compare_artifacts — required artifact policies
// ---------------------------------------------------------------------------

#[test]
fn test_compare_require_source_maps_both_missing() {
    let cfg = MatrixConfig {
        require_source_maps: true,
        require_binding_traces: false,
        ..relaxed_config()
    };
    let a = vec![art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        b"code",
        WorkloadClass::PureJs,
    )];
    let b = vec![art(
        ArtifactKind::CompiledOutput,
        Surface::Cli,
        b"code",
        WorkloadClass::PureJs,
    )];
    let mm = compare_artifacts(&a, &b, &cfg);
    let sm_mm: Vec<_> = mm
        .iter()
        .filter(|m| m.artifact_kind == ArtifactKind::SourceMap)
        .collect();
    assert_eq!(
        sm_mm.len(),
        2,
        "both surfaces should flag missing source map"
    );
}

#[test]
fn test_compare_require_source_maps_present_no_flag() {
    let cfg = MatrixConfig {
        require_source_maps: true,
        require_binding_traces: false,
        ..relaxed_config()
    };
    let a = vec![
        art(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            b"code",
            WorkloadClass::PureJs,
        ),
        art(
            ArtifactKind::SourceMap,
            Surface::Library,
            b"map",
            WorkloadClass::PureJs,
        ),
    ];
    let b = vec![
        art(
            ArtifactKind::CompiledOutput,
            Surface::Cli,
            b"code",
            WorkloadClass::PureJs,
        ),
        art(
            ArtifactKind::SourceMap,
            Surface::Cli,
            b"map",
            WorkloadClass::PureJs,
        ),
    ];
    let mm = compare_artifacts(&a, &b, &cfg);
    let sm_mm: Vec<_> = mm
        .iter()
        .filter(|m| m.artifact_kind == ArtifactKind::SourceMap && m.class == MismatchClass::Missing)
        .collect();
    assert!(sm_mm.is_empty());
}

#[test]
fn test_compare_require_binding_traces_both_missing() {
    let cfg = MatrixConfig {
        require_source_maps: false,
        require_binding_traces: true,
        ..relaxed_config()
    };
    let a = vec![art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        b"code",
        WorkloadClass::MixedEsmCjs,
    )];
    let b = vec![art(
        ArtifactKind::CompiledOutput,
        Surface::Cli,
        b"code",
        WorkloadClass::MixedEsmCjs,
    )];
    let mm = compare_artifacts(&a, &b, &cfg);
    let bt_mm: Vec<_> = mm
        .iter()
        .filter(|m| m.artifact_kind == ArtifactKind::BindingTrace)
        .collect();
    assert_eq!(bt_mm.len(), 2);
}

// ---------------------------------------------------------------------------
// compare_artifacts — multiple kinds
// ---------------------------------------------------------------------------

#[test]
fn test_compare_multiple_kinds_pass() {
    let cfg = relaxed_config();
    let a = vec![
        art(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            b"code",
            WorkloadClass::PureJs,
        ),
        art(
            ArtifactKind::SourceMap,
            Surface::Library,
            b"map",
            WorkloadClass::PureJs,
        ),
        art(
            ArtifactKind::Diagnostic,
            Surface::Library,
            b"warn",
            WorkloadClass::PureJs,
        ),
    ];
    let b = vec![
        art(
            ArtifactKind::CompiledOutput,
            Surface::Cli,
            b"code",
            WorkloadClass::PureJs,
        ),
        art(
            ArtifactKind::SourceMap,
            Surface::Cli,
            b"map",
            WorkloadClass::PureJs,
        ),
        art(
            ArtifactKind::Diagnostic,
            Surface::Cli,
            b"warn",
            WorkloadClass::PureJs,
        ),
    ];
    let mm = compare_artifacts(&a, &b, &cfg);
    assert!(mm.is_empty());
}

#[test]
fn test_compare_multiple_kinds_partial_divergence() {
    let cfg = relaxed_config();
    let a = vec![
        art(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            b"code",
            WorkloadClass::Esm,
        ),
        art(
            ArtifactKind::SourceMap,
            Surface::Library,
            b"map_a",
            WorkloadClass::Esm,
        ),
    ];
    let b = vec![
        art(
            ArtifactKind::CompiledOutput,
            Surface::Cli,
            b"code",
            WorkloadClass::Esm,
        ),
        art(
            ArtifactKind::SourceMap,
            Surface::Cli,
            b"map_b",
            WorkloadClass::Esm,
        ),
    ];
    let mm = compare_artifacts(&a, &b, &cfg);
    assert!(mm.iter().any(|m| m.artifact_kind == ArtifactKind::SourceMap
        && m.class == MismatchClass::ContentDivergence));
    assert!(
        !mm.iter()
            .any(|m| m.artifact_kind == ArtifactKind::CompiledOutput
                && m.class == MismatchClass::ContentDivergence)
    );
}

// ---------------------------------------------------------------------------
// compute_cell_verdict
// ---------------------------------------------------------------------------

#[test]
fn test_verdict_pass_empty() {
    assert_eq!(
        compute_cell_verdict(&[], &relaxed_config()),
        CellVerdict::Pass
    );
}

#[test]
fn test_verdict_fail_at_threshold() {
    let cfg = MatrixConfig {
        severity_threshold: MismatchSeverity::Major,
        ..relaxed_config()
    };
    let mm = vec![ClassifiedMismatch {
        class: MismatchClass::Missing,
        severity: MismatchSeverity::Major,
        surface: Surface::Cli,
        artifact_kind: ArtifactKind::SourceMap,
        workload_class: WorkloadClass::Esm,
        detail: "missing".to_string(),
        content_hash_a: None,
        content_hash_b: None,
    }];
    assert_eq!(compute_cell_verdict(&mm, &cfg), CellVerdict::Fail);
}

#[test]
fn test_verdict_pass_below_threshold() {
    let cfg = MatrixConfig {
        severity_threshold: MismatchSeverity::Critical,
        ..relaxed_config()
    };
    let mm = vec![ClassifiedMismatch {
        class: MismatchClass::SemanticDivergence,
        severity: MismatchSeverity::Minor,
        surface: Surface::Library,
        artifact_kind: ArtifactKind::Diagnostic,
        workload_class: WorkloadClass::PureJs,
        detail: "minor".to_string(),
        content_hash_a: None,
        content_hash_b: None,
    }];
    assert_eq!(compute_cell_verdict(&mm, &cfg), CellVerdict::Pass);
}

#[test]
fn test_verdict_fail_above_threshold() {
    let cfg = MatrixConfig {
        severity_threshold: MismatchSeverity::Minor,
        ..relaxed_config()
    };
    let mm = vec![ClassifiedMismatch {
        class: MismatchClass::ContentDivergence,
        severity: MismatchSeverity::Major,
        surface: Surface::Cli,
        artifact_kind: ArtifactKind::CompiledOutput,
        workload_class: WorkloadClass::PureTs,
        detail: "major".to_string(),
        content_hash_a: None,
        content_hash_b: None,
    }];
    assert_eq!(compute_cell_verdict(&mm, &cfg), CellVerdict::Fail);
}

// ---------------------------------------------------------------------------
// MatrixCell
// ---------------------------------------------------------------------------

#[test]
fn test_matrix_cell_new() {
    let cell = MatrixCell::new(
        WorkloadClass::PureJs,
        vec![],
        vec![],
        vec![],
        CellVerdict::Pass,
    );
    assert_eq!(cell.workload_class, WorkloadClass::PureJs);
    assert!(cell.artifacts_a.is_empty());
    assert!(cell.artifacts_b.is_empty());
    assert!(cell.mismatches.is_empty());
    assert_eq!(cell.verdict, CellVerdict::Pass);
}

#[test]
fn test_matrix_cell_critical_count_zero() {
    let cell = passing_cell(WorkloadClass::Esm);
    assert_eq!(cell.critical_count(), 0);
}

#[test]
fn test_matrix_cell_critical_count_nonzero() {
    let cell = failing_cell(WorkloadClass::PureTs);
    assert_eq!(cell.critical_count(), 1);
}

#[test]
fn test_matrix_cell_major_count() {
    let mm = vec![ClassifiedMismatch {
        class: MismatchClass::Missing,
        severity: MismatchSeverity::Major,
        surface: Surface::Cli,
        artifact_kind: ArtifactKind::SourceMap,
        workload_class: WorkloadClass::Cjs,
        detail: "test".to_string(),
        content_hash_a: None,
        content_hash_b: None,
    }];
    let cell = MatrixCell::new(WorkloadClass::Cjs, vec![], vec![], mm, CellVerdict::Fail);
    assert_eq!(cell.major_count(), 1);
    assert_eq!(cell.critical_count(), 0);
}

// ---------------------------------------------------------------------------
// MatrixConfig
// ---------------------------------------------------------------------------

#[test]
fn test_config_default_has_all_workload_classes() {
    let cfg = MatrixConfig::default();
    assert_eq!(cfg.required_workload_classes.len(), 6);
    for wc in WorkloadClass::ALL {
        assert!(cfg.required_workload_classes.contains(wc));
    }
}

#[test]
fn test_config_default_values() {
    let cfg = MatrixConfig::default();
    assert_eq!(
        cfg.max_size_divergence_millionths,
        DEFAULT_MAX_SIZE_DIVERGENCE
    );
    assert!(cfg.require_source_maps);
    assert!(!cfg.require_binding_traces);
    assert_eq!(cfg.severity_threshold, MismatchSeverity::Major);
}

#[test]
fn test_config_serde_roundtrip() {
    let cfg = strict_config();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: MatrixConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_fields() {
    let r = DecisionReceipt::compute(
        &epoch(),
        ContentHash::compute(b"in"),
        CellVerdict::Pass,
        999,
    );
    assert_eq!(r.schema_version, SCHEMA_VERSION);
    assert_eq!(r.component, COMPONENT);
    assert_eq!(r.bead_id, BEAD_ID);
    assert_eq!(r.policy_id, POLICY_ID);
    assert_eq!(r.epoch, epoch());
    assert_eq!(r.timestamp_micros, 999);
}

#[test]
fn test_receipt_deterministic() {
    let ih = ContentHash::compute(b"input");
    let r1 = DecisionReceipt::compute(&epoch(), ih.clone(), CellVerdict::Pass, 42);
    let r2 = DecisionReceipt::compute(&epoch(), ih, CellVerdict::Pass, 42);
    assert_eq!(r1.verdict_hash, r2.verdict_hash);
    assert_eq!(r1.input_hash, r2.input_hash);
}

#[test]
fn test_receipt_varies_with_verdict() {
    let ih = ContentHash::compute(b"same");
    let r1 = DecisionReceipt::compute(&epoch(), ih.clone(), CellVerdict::Pass, 1);
    let r2 = DecisionReceipt::compute(&epoch(), ih, CellVerdict::Fail, 1);
    assert_ne!(r1.verdict_hash, r2.verdict_hash);
}

#[test]
fn test_receipt_varies_with_epoch() {
    let ih = ContentHash::compute(b"same");
    let r1 = DecisionReceipt::compute(
        &SecurityEpoch::from_raw(1),
        ih.clone(),
        CellVerdict::Pass,
        1,
    );
    let r2 = DecisionReceipt::compute(&SecurityEpoch::from_raw(2), ih, CellVerdict::Pass, 1);
    assert_ne!(r1.verdict_hash, r2.verdict_hash);
}

#[test]
fn test_receipt_varies_with_timestamp() {
    let ih = ContentHash::compute(b"same");
    let r1 = DecisionReceipt::compute(&epoch(), ih.clone(), CellVerdict::Pass, 100);
    let r2 = DecisionReceipt::compute(&epoch(), ih, CellVerdict::Pass, 200);
    assert_ne!(r1.verdict_hash, r2.verdict_hash);
}

#[test]
fn test_receipt_serde_roundtrip() {
    let r = DecisionReceipt::compute(&epoch(), ContentHash::compute(b"x"), CellVerdict::Fail, 42);
    let json = serde_json::to_string(&r).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// evaluate_matrix — error paths
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_no_cells() {
    let err = evaluate_matrix(&[], &relaxed_config(), &epoch(), 0).unwrap_err();
    assert!(matches!(err, MatrixError::NoCells));
}

#[test]
fn test_evaluate_duplicate_workload_class() {
    let cells = vec![
        passing_cell(WorkloadClass::PureJs),
        passing_cell(WorkloadClass::PureJs),
    ];
    let err = evaluate_matrix(&cells, &relaxed_config(), &epoch(), 0).unwrap_err();
    assert!(matches!(
        err,
        MatrixError::DuplicateWorkloadClass {
            class: WorkloadClass::PureJs
        }
    ));
}

#[test]
fn test_evaluate_missing_required_class() {
    let cfg = MatrixConfig::default(); // requires all 6
    let cells = vec![passing_cell(WorkloadClass::PureJs)];
    let err = evaluate_matrix(&cells, &cfg, &epoch(), 0).unwrap_err();
    assert!(matches!(err, MatrixError::MissingWorkloadClass { .. }));
}

// ---------------------------------------------------------------------------
// evaluate_matrix — success paths
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_all_pass() {
    let cfg = relaxed_config();
    let cells = all_passing_cells();
    let report = evaluate_matrix(&cells, &cfg, &epoch(), 1000).unwrap();
    assert_eq!(report.overall_verdict, CellVerdict::Pass);
    assert_eq!(report.total_mismatches, 0);
    assert_eq!(report.critical_count, 0);
    assert_eq!(report.major_count, 0);
    assert_eq!(report.cells.len(), 6);
}

#[test]
fn test_evaluate_single_cell_pass() {
    let cfg = relaxed_config();
    let cells = vec![passing_cell(WorkloadClass::Esm)];
    let report = evaluate_matrix(&cells, &cfg, &epoch(), 0).unwrap();
    assert_eq!(report.overall_verdict, CellVerdict::Pass);
}

#[test]
fn test_evaluate_one_fail_overall_fail() {
    let cfg = relaxed_config();
    let cells = vec![
        passing_cell(WorkloadClass::PureJs),
        failing_cell(WorkloadClass::PureTs),
        passing_cell(WorkloadClass::Esm),
    ];
    let report = evaluate_matrix(&cells, &cfg, &epoch(), 0).unwrap();
    assert_eq!(report.overall_verdict, CellVerdict::Fail);
    assert_eq!(report.critical_count, 1);
}

#[test]
fn test_evaluate_inconclusive_propagates() {
    let cfg = relaxed_config();
    let cells = vec![
        passing_cell(WorkloadClass::PureJs),
        inconclusive_cell(WorkloadClass::MixedJsTs),
    ];
    let report = evaluate_matrix(&cells, &cfg, &epoch(), 0).unwrap();
    assert_eq!(report.overall_verdict, CellVerdict::Inconclusive);
}

#[test]
fn test_evaluate_fail_beats_inconclusive() {
    let cfg = relaxed_config();
    let cells = vec![
        failing_cell(WorkloadClass::PureJs),
        inconclusive_cell(WorkloadClass::Esm),
        passing_cell(WorkloadClass::Cjs),
    ];
    let report = evaluate_matrix(&cells, &cfg, &epoch(), 0).unwrap();
    assert_eq!(report.overall_verdict, CellVerdict::Fail);
}

#[test]
fn test_evaluate_aggregates_mismatches() {
    let cfg = relaxed_config();
    let cells = vec![
        failing_cell(WorkloadClass::PureJs),
        failing_cell(WorkloadClass::PureTs),
    ];
    let report = evaluate_matrix(&cells, &cfg, &epoch(), 0).unwrap();
    assert_eq!(report.total_mismatches, 2);
    assert_eq!(report.critical_count, 2);
}

#[test]
fn test_evaluate_receipt_present() {
    let cfg = relaxed_config();
    let cells = vec![passing_cell(WorkloadClass::MixedEsmCjs)];
    let report = evaluate_matrix(&cells, &cfg, &epoch(), 77_000).unwrap();
    assert_eq!(report.receipt.timestamp_micros, 77_000);
    assert_eq!(report.receipt.schema_version, SCHEMA_VERSION);
}

#[test]
fn test_evaluate_receipt_deterministic() {
    let cfg = relaxed_config();
    let cells = all_passing_cells();
    let r1 = evaluate_matrix(&cells, &cfg, &epoch(), 100).unwrap();
    let r2 = evaluate_matrix(&cells, &cfg, &epoch(), 100).unwrap();
    assert_eq!(r1.receipt.verdict_hash, r2.receipt.verdict_hash);
    assert_eq!(r1.receipt.input_hash, r2.receipt.input_hash);
}

// ---------------------------------------------------------------------------
// MatrixError
// ---------------------------------------------------------------------------

#[test]
fn test_matrix_error_display_no_cells() {
    let e = MatrixError::NoCells;
    assert_eq!(format!("{e}"), "no cells provided for matrix evaluation");
}

#[test]
fn test_matrix_error_display_missing_class() {
    let e = MatrixError::MissingWorkloadClass {
        class: WorkloadClass::MixedJsTs,
    };
    let s = format!("{e}");
    assert!(s.contains("mixed_js_ts"));
}

#[test]
fn test_matrix_error_display_duplicate() {
    let e = MatrixError::DuplicateWorkloadClass {
        class: WorkloadClass::Cjs,
    };
    let s = format!("{e}");
    assert!(s.contains("cjs"));
}

#[test]
fn test_matrix_error_display_invalid_config() {
    let e = MatrixError::InvalidConfig {
        detail: "bad threshold".to_string(),
    };
    let s = format!("{e}");
    assert!(s.contains("bad threshold"));
}

#[test]
fn test_matrix_error_serde_roundtrip_all() {
    let errors = vec![
        MatrixError::NoCells,
        MatrixError::MissingWorkloadClass {
            class: WorkloadClass::Esm,
        },
        MatrixError::DuplicateWorkloadClass {
            class: WorkloadClass::PureTs,
        },
        MatrixError::InvalidConfig {
            detail: "test".to_string(),
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: MatrixError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ---------------------------------------------------------------------------
// build_cell
// ---------------------------------------------------------------------------

#[test]
fn test_build_cell_identical_pass() {
    let cfg = relaxed_config();
    let a = vec![art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        b"x",
        WorkloadClass::PureJs,
    )];
    let b = vec![art(
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
fn test_build_cell_divergence() {
    let cfg = relaxed_config();
    let a = vec![art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        b"lib",
        WorkloadClass::PureTs,
    )];
    let b = vec![art(
        ArtifactKind::CompiledOutput,
        Surface::Cli,
        b"cli",
        WorkloadClass::PureTs,
    )];
    let cell = build_cell(WorkloadClass::PureTs, a, b, &cfg);
    assert!(!cell.mismatches.is_empty());
}

#[test]
fn test_build_cell_empty_artifacts() {
    let cfg = relaxed_config();
    let cell = build_cell(WorkloadClass::Esm, vec![], vec![], &cfg);
    assert_eq!(cell.verdict, CellVerdict::Pass);
    assert!(cell.mismatches.is_empty());
}

#[test]
fn test_build_cell_sets_workload_class() {
    let cfg = relaxed_config();
    let cell = build_cell(WorkloadClass::MixedEsmCjs, vec![], vec![], &cfg);
    assert_eq!(cell.workload_class, WorkloadClass::MixedEsmCjs);
}

// ---------------------------------------------------------------------------
// MatrixReport serde
// ---------------------------------------------------------------------------

#[test]
fn test_report_serde_roundtrip_pass() {
    let cfg = relaxed_config();
    let cells = vec![passing_cell(WorkloadClass::PureJs)];
    let report = evaluate_matrix(&cells, &cfg, &epoch(), 1).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let back: MatrixReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn test_report_serde_roundtrip_fail() {
    let cfg = relaxed_config();
    let cells = vec![failing_cell(WorkloadClass::PureTs)];
    let report = evaluate_matrix(&cells, &cfg, &epoch(), 1).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let back: MatrixReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// End-to-end scenarios
// ---------------------------------------------------------------------------

#[test]
fn test_e2e_full_matrix_all_workloads_pass() {
    let cfg = MatrixConfig {
        required_workload_classes: WorkloadClass::ALL.iter().copied().collect(),
        require_source_maps: false,
        require_binding_traces: false,
        ..relaxed_config()
    };
    let mut cells = Vec::new();
    for wc in WorkloadClass::ALL {
        let a = vec![art(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            b"code",
            *wc,
        )];
        let b = vec![art(
            ArtifactKind::CompiledOutput,
            Surface::Cli,
            b"code",
            *wc,
        )];
        cells.push(build_cell(*wc, a, b, &cfg));
    }
    let report = evaluate_matrix(&cells, &cfg, &epoch(), 5000).unwrap();
    assert_eq!(report.overall_verdict, CellVerdict::Pass);
    assert_eq!(report.cells.len(), 6);
    assert_eq!(report.total_mismatches, 0);
}

#[test]
fn test_e2e_one_workload_diverges() {
    let cfg = MatrixConfig {
        required_workload_classes: BTreeSet::from([WorkloadClass::PureJs, WorkloadClass::PureTs]),
        severity_threshold: MismatchSeverity::Critical,
        require_source_maps: false,
        require_binding_traces: false,
        ..relaxed_config()
    };
    let cell_js = build_cell(
        WorkloadClass::PureJs,
        vec![art(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            b"same",
            WorkloadClass::PureJs,
        )],
        vec![art(
            ArtifactKind::CompiledOutput,
            Surface::Cli,
            b"same",
            WorkloadClass::PureJs,
        )],
        &cfg,
    );
    let cell_ts = build_cell(
        WorkloadClass::PureTs,
        vec![art(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            b"lib_ts",
            WorkloadClass::PureTs,
        )],
        vec![art(
            ArtifactKind::CompiledOutput,
            Surface::Cli,
            b"cli_ts",
            WorkloadClass::PureTs,
        )],
        &cfg,
    );
    let report = evaluate_matrix(&[cell_js, cell_ts], &cfg, &epoch(), 0).unwrap();
    // CompiledOutput divergence is classified Critical, threshold is Critical => Fail
    assert_eq!(report.overall_verdict, CellVerdict::Fail);
    assert!(report.total_mismatches > 0);
}

#[test]
fn test_e2e_strict_config_missing_source_maps_fail() {
    let cfg = MatrixConfig {
        required_workload_classes: BTreeSet::from([WorkloadClass::PureJs]),
        max_size_divergence_millionths: 50_000,
        require_source_maps: true,
        require_binding_traces: false,
        severity_threshold: MismatchSeverity::Major,
    };
    let a = vec![art(
        ArtifactKind::CompiledOutput,
        Surface::Library,
        b"code",
        WorkloadClass::PureJs,
    )];
    let b = vec![art(
        ArtifactKind::CompiledOutput,
        Surface::Cli,
        b"code",
        WorkloadClass::PureJs,
    )];
    let cell = build_cell(WorkloadClass::PureJs, a, b, &cfg);
    let report = evaluate_matrix(&[cell], &cfg, &epoch(), 0).unwrap();
    // Missing source maps should trigger Major mismatches => Fail
    assert_eq!(report.overall_verdict, CellVerdict::Fail);
}

#[test]
fn test_e2e_with_binding_traces_pass() {
    let cfg = MatrixConfig {
        required_workload_classes: BTreeSet::from([WorkloadClass::Esm]),
        require_source_maps: false,
        require_binding_traces: true,
        severity_threshold: MismatchSeverity::Critical,
        ..relaxed_config()
    };
    let a = vec![
        art(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            b"code",
            WorkloadClass::Esm,
        ),
        art(
            ArtifactKind::BindingTrace,
            Surface::Library,
            b"trace",
            WorkloadClass::Esm,
        ),
    ];
    let b = vec![
        art(
            ArtifactKind::CompiledOutput,
            Surface::Cli,
            b"code",
            WorkloadClass::Esm,
        ),
        art(
            ArtifactKind::BindingTrace,
            Surface::Cli,
            b"trace",
            WorkloadClass::Esm,
        ),
    ];
    let cell = build_cell(WorkloadClass::Esm, a, b, &cfg);
    let report = evaluate_matrix(&[cell], &cfg, &epoch(), 0).unwrap();
    assert_eq!(report.overall_verdict, CellVerdict::Pass);
}

#[test]
fn test_e2e_mixed_esm_cjs_workload() {
    let cfg = relaxed_config();
    let a = vec![
        art(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            b"cjs_code",
            WorkloadClass::MixedEsmCjs,
        ),
        art(
            ArtifactKind::ModuleGraph,
            Surface::Library,
            b"graph",
            WorkloadClass::MixedEsmCjs,
        ),
    ];
    let b = vec![
        art(
            ArtifactKind::CompiledOutput,
            Surface::Cli,
            b"cjs_code",
            WorkloadClass::MixedEsmCjs,
        ),
        art(
            ArtifactKind::ModuleGraph,
            Surface::Cli,
            b"graph",
            WorkloadClass::MixedEsmCjs,
        ),
    ];
    let cell = build_cell(WorkloadClass::MixedEsmCjs, a, b, &cfg);
    assert_eq!(cell.verdict, CellVerdict::Pass);
}

// ---------------------------------------------------------------------------
// ClassifiedMismatch serde
// ---------------------------------------------------------------------------

#[test]
fn test_classified_mismatch_serde_roundtrip() {
    let m = ClassifiedMismatch {
        class: MismatchClass::ContentDivergence,
        severity: MismatchSeverity::Critical,
        surface: Surface::Cli,
        artifact_kind: ArtifactKind::CompiledOutput,
        workload_class: WorkloadClass::PureJs,
        detail: "test detail".to_string(),
        content_hash_a: Some(ContentHash::compute(b"a")),
        content_hash_b: Some(ContentHash::compute(b"b")),
    };
    let json = serde_json::to_string(&m).unwrap();
    let back: ClassifiedMismatch = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn test_classified_mismatch_with_none_hashes() {
    let m = ClassifiedMismatch {
        class: MismatchClass::Missing,
        severity: MismatchSeverity::Major,
        surface: Surface::Cli,
        artifact_kind: ArtifactKind::SourceMap,
        workload_class: WorkloadClass::Esm,
        detail: "no hash available".to_string(),
        content_hash_a: None,
        content_hash_b: None,
    };
    let json = serde_json::to_string(&m).unwrap();
    let back: ClassifiedMismatch = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}
