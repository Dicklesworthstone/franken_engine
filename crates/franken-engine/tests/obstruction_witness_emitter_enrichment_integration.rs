#![forbid(unsafe_code)]

//! Enrichment integration tests for the obstruction_witness_emitter module.

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

use frankenengine_engine::obstruction_witness_emitter::{
    BEAD_ID, COMPONENT, MILLIONTHS, NongluableProgram, ObstructionError, ObstructionKind,
    ObstructionReport, ObstructionWitness, POLICY_ID, SCHEMA_VERSION, SeamDiagnosis,
    SupportSurface, build_report, detect_nongluable, diagnose_seam, emit_witness,
    franken_engine_obstruction_manifest, minimize_witness,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_witness(surface: SupportSurface, kind: ObstructionKind) -> ObstructionWitness {
    emit_witness(
        surface,
        kind,
        "function test() { return 42; }",
        "test failure description",
        "parser→lowering",
    )
    .unwrap()
}

fn make_nongluable() -> NongluableProgram {
    detect_nongluable(
        "let x = 1;",
        SupportSurface::Parser,
        SupportSurface::Lowering,
        "parsed as declaration",
        "lowered as expression",
    )
}

// ---------------------------------------------------------------------------
// SupportSurface — Clone / BTreeSet / Debug / Display / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_support_surface_clone_independence() {
    let a = SupportSurface::Parser;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_support_surface_btreeset_dedup_8() {
    let mut set = BTreeSet::new();
    set.insert(SupportSurface::Parser);
    set.insert(SupportSurface::Lowering);
    set.insert(SupportSurface::Runtime);
    set.insert(SupportSurface::Module);
    set.insert(SupportSurface::TypeScript);
    set.insert(SupportSurface::React);
    set.insert(SupportSurface::Cli);
    set.insert(SupportSurface::CrossSurface);
    set.insert(SupportSurface::Parser);
    assert_eq!(set.len(), 8);
}

#[test]
fn enrichment_support_surface_debug_all_unique() {
    let surfaces = [
        SupportSurface::Parser,
        SupportSurface::Lowering,
        SupportSurface::Runtime,
        SupportSurface::Module,
        SupportSurface::TypeScript,
        SupportSurface::React,
        SupportSurface::Cli,
        SupportSurface::CrossSurface,
    ];
    let dbgs: BTreeSet<String> = surfaces.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), 8);
}

#[test]
fn enrichment_support_surface_display_all_unique() {
    let surfaces = [
        SupportSurface::Parser,
        SupportSurface::Lowering,
        SupportSurface::Runtime,
        SupportSurface::Module,
        SupportSurface::TypeScript,
        SupportSurface::React,
        SupportSurface::Cli,
        SupportSurface::CrossSurface,
    ];
    let displays: BTreeSet<String> = surfaces.iter().map(|v| format!("{}", v)).collect();
    assert_eq!(displays.len(), 8);
}

#[test]
fn enrichment_support_surface_display_values() {
    assert_eq!(format!("{}", SupportSurface::Parser), "parser");
    assert_eq!(format!("{}", SupportSurface::Lowering), "lowering");
    assert_eq!(format!("{}", SupportSurface::Runtime), "runtime");
    assert_eq!(format!("{}", SupportSurface::CrossSurface), "cross-surface");
}

#[test]
fn enrichment_support_surface_serde_roundtrip_all() {
    let surfaces = [
        SupportSurface::Parser,
        SupportSurface::Lowering,
        SupportSurface::Runtime,
        SupportSurface::Module,
        SupportSurface::TypeScript,
        SupportSurface::React,
        SupportSurface::Cli,
        SupportSurface::CrossSurface,
    ];
    for s in &surfaces {
        let json = serde_json::to_string(s).unwrap();
        let rt: SupportSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, rt);
    }
}

// ---------------------------------------------------------------------------
// ObstructionKind — Clone / BTreeSet / Debug / Display / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_obstruction_kind_clone_independence() {
    let a = ObstructionKind::TypeMismatch;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_obstruction_kind_btreeset_dedup_7() {
    let mut set = BTreeSet::new();
    set.insert(ObstructionKind::TypeMismatch);
    set.insert(ObstructionKind::SemanticGap);
    set.insert(ObstructionKind::BoundaryIncompatibility);
    set.insert(ObstructionKind::ResourceViolation);
    set.insert(ObstructionKind::TimingDependence);
    set.insert(ObstructionKind::NondeterministicBehavior);
    set.insert(ObstructionKind::UnsupportedFeature);
    set.insert(ObstructionKind::TypeMismatch);
    assert_eq!(set.len(), 7);
}

#[test]
fn enrichment_obstruction_kind_debug_all_unique() {
    let kinds = [
        ObstructionKind::TypeMismatch,
        ObstructionKind::SemanticGap,
        ObstructionKind::BoundaryIncompatibility,
        ObstructionKind::ResourceViolation,
        ObstructionKind::TimingDependence,
        ObstructionKind::NondeterministicBehavior,
        ObstructionKind::UnsupportedFeature,
    ];
    let dbgs: BTreeSet<String> = kinds.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), 7);
}

#[test]
fn enrichment_obstruction_kind_display_all_unique() {
    let kinds = [
        ObstructionKind::TypeMismatch,
        ObstructionKind::SemanticGap,
        ObstructionKind::BoundaryIncompatibility,
        ObstructionKind::ResourceViolation,
        ObstructionKind::TimingDependence,
        ObstructionKind::NondeterministicBehavior,
        ObstructionKind::UnsupportedFeature,
    ];
    let displays: BTreeSet<String> = kinds.iter().map(|v| format!("{}", v)).collect();
    assert_eq!(displays.len(), 7);
}

#[test]
fn enrichment_obstruction_kind_display_values() {
    assert_eq!(
        format!("{}", ObstructionKind::TypeMismatch),
        "type-mismatch"
    );
    assert_eq!(format!("{}", ObstructionKind::SemanticGap), "semantic-gap");
    assert_eq!(
        format!("{}", ObstructionKind::NondeterministicBehavior),
        "nondeterministic-behavior"
    );
}

#[test]
fn enrichment_obstruction_kind_serde_roundtrip_all() {
    let kinds = [
        ObstructionKind::TypeMismatch,
        ObstructionKind::SemanticGap,
        ObstructionKind::BoundaryIncompatibility,
        ObstructionKind::ResourceViolation,
        ObstructionKind::TimingDependence,
        ObstructionKind::NondeterministicBehavior,
        ObstructionKind::UnsupportedFeature,
    ];
    for k in &kinds {
        let json = serde_json::to_string(k).unwrap();
        let rt: ObstructionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, rt);
    }
}

// ---------------------------------------------------------------------------
// ObstructionError — Clone / Debug / Display / Error / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_obstruction_error_clone_independence() {
    let a = ObstructionError::EmptyWitness;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_obstruction_error_debug_all_unique() {
    let errors = [
        ObstructionError::EmptyWitness,
        ObstructionError::InvalidSurface,
        ObstructionError::MinimizationFailed,
        ObstructionError::SeamNotFound,
        ObstructionError::InternalError("test".to_string()),
    ];
    let dbgs: BTreeSet<String> = errors.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), 5);
}

#[test]
fn enrichment_obstruction_error_display_all_unique() {
    let errors = [
        ObstructionError::EmptyWitness,
        ObstructionError::InvalidSurface,
        ObstructionError::MinimizationFailed,
        ObstructionError::SeamNotFound,
        ObstructionError::InternalError("custom msg".to_string()),
    ];
    let displays: BTreeSet<String> = errors.iter().map(|v| format!("{}", v)).collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_obstruction_error_display_contains_text() {
    let e = ObstructionError::EmptyWitness;
    assert!(format!("{}", e).contains("empty"));
    let e2 = ObstructionError::InternalError("oops".to_string());
    assert!(format!("{}", e2).contains("oops"));
}

#[test]
fn enrichment_obstruction_error_serde_roundtrip_all() {
    let errors = [
        ObstructionError::EmptyWitness,
        ObstructionError::InvalidSurface,
        ObstructionError::MinimizationFailed,
        ObstructionError::SeamNotFound,
        ObstructionError::InternalError("test".to_string()),
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let rt: ObstructionError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, rt);
    }
}

// ---------------------------------------------------------------------------
// ObstructionWitness — Clone / Debug / JSON fields / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_obstruction_witness_clone_independence() {
    let w = make_witness(SupportSurface::Parser, ObstructionKind::SemanticGap);
    let w2 = w.clone();
    assert_eq!(w, w2);
}

#[test]
fn enrichment_obstruction_witness_debug_nonempty() {
    let w = make_witness(SupportSurface::Parser, ObstructionKind::SemanticGap);
    assert!(!format!("{:?}", w).is_empty());
}

#[test]
fn enrichment_obstruction_witness_json_field_names() {
    let w = make_witness(SupportSurface::Parser, ObstructionKind::SemanticGap);
    let json = serde_json::to_string(&w).unwrap();
    for field in &[
        "witness_id",
        "surface",
        "kind",
        "program_source",
        "failure_description",
        "minimal",
        "reduction_steps",
        "seam_location",
        "content_hash",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_obstruction_witness_serde_roundtrip() {
    let w = make_witness(SupportSurface::Parser, ObstructionKind::SemanticGap);
    let json = serde_json::to_string(&w).unwrap();
    let rt: ObstructionWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(w, rt);
}

#[test]
fn enrichment_obstruction_witness_not_minimal_on_emit() {
    let w = make_witness(SupportSurface::Parser, ObstructionKind::SemanticGap);
    assert!(!w.minimal);
    assert_eq!(w.reduction_steps, 0);
}

// ---------------------------------------------------------------------------
// NongluableProgram — Clone / Debug / JSON fields / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_nongluable_program_clone_independence() {
    let n = make_nongluable();
    let n2 = n.clone();
    assert_eq!(n, n2);
}

#[test]
fn enrichment_nongluable_program_debug_nonempty() {
    assert!(!format!("{:?}", make_nongluable()).is_empty());
}

#[test]
fn enrichment_nongluable_program_json_field_names() {
    let n = make_nongluable();
    let json = serde_json::to_string(&n).unwrap();
    for field in &[
        "program_id",
        "source_text",
        "left_surface",
        "right_surface",
        "left_interpretation",
        "right_interpretation",
        "divergence_description",
        "content_hash",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_nongluable_program_serde_roundtrip() {
    let n = make_nongluable();
    let json = serde_json::to_string(&n).unwrap();
    let rt: NongluableProgram = serde_json::from_str(&json).unwrap();
    assert_eq!(n, rt);
}

#[test]
fn enrichment_nongluable_program_divergence_description_format() {
    let n = make_nongluable();
    assert!(n.divergence_description.contains("Left surface"));
    assert!(n.divergence_description.contains("Right surface"));
}

// ---------------------------------------------------------------------------
// SeamDiagnosis — Clone / Debug / JSON fields / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_seam_diagnosis_clone_independence() {
    let witnesses = vec![make_witness(
        SupportSurface::Parser,
        ObstructionKind::SemanticGap,
    )];
    let d = diagnose_seam(&witnesses, SupportSurface::Parser, SupportSurface::Lowering);
    let d2 = d.clone();
    assert_eq!(d, d2);
}

#[test]
fn enrichment_seam_diagnosis_debug_nonempty() {
    let witnesses = vec![make_witness(
        SupportSurface::Parser,
        ObstructionKind::SemanticGap,
    )];
    let d = diagnose_seam(&witnesses, SupportSurface::Parser, SupportSurface::Lowering);
    assert!(!format!("{:?}", d).is_empty());
}

#[test]
fn enrichment_seam_diagnosis_json_field_names() {
    let witnesses = vec![make_witness(
        SupportSurface::Parser,
        ObstructionKind::SemanticGap,
    )];
    let d = diagnose_seam(&witnesses, SupportSurface::Parser, SupportSurface::Lowering);
    let json = serde_json::to_string(&d).unwrap();
    for field in &[
        "seam_id",
        "left_surface",
        "right_surface",
        "obstruction_count",
        "nongluable_count",
        "severity_millionths",
        "remediation_hint",
        "content_hash",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_seam_diagnosis_serde_roundtrip() {
    let witnesses = vec![make_witness(
        SupportSurface::Parser,
        ObstructionKind::SemanticGap,
    )];
    let d = diagnose_seam(&witnesses, SupportSurface::Parser, SupportSurface::Lowering);
    let json = serde_json::to_string(&d).unwrap();
    let rt: SeamDiagnosis = serde_json::from_str(&json).unwrap();
    assert_eq!(d, rt);
}

#[test]
fn enrichment_seam_diagnosis_severity_capped_at_millionths() {
    // Many diverse witnesses to push severity to cap
    let mut witnesses = Vec::new();
    let kinds = [
        ObstructionKind::TypeMismatch,
        ObstructionKind::SemanticGap,
        ObstructionKind::BoundaryIncompatibility,
        ObstructionKind::ResourceViolation,
        ObstructionKind::TimingDependence,
        ObstructionKind::NondeterministicBehavior,
        ObstructionKind::UnsupportedFeature,
    ];
    for kind in &kinds {
        for _ in 0..5 {
            witnesses.push(make_witness(SupportSurface::Parser, kind.clone()));
        }
    }
    let d = diagnose_seam(&witnesses, SupportSurface::Parser, SupportSurface::Lowering);
    assert!(d.severity_millionths <= MILLIONTHS);
}

#[test]
fn enrichment_seam_diagnosis_empty_witnesses() {
    let d = diagnose_seam(&[], SupportSurface::Parser, SupportSurface::Lowering);
    assert_eq!(d.obstruction_count, 0);
}

#[test]
fn enrichment_seam_diagnosis_remediation_hint_nonempty() {
    let witnesses = vec![make_witness(
        SupportSurface::Parser,
        ObstructionKind::SemanticGap,
    )];
    let d = diagnose_seam(&witnesses, SupportSurface::Parser, SupportSurface::Lowering);
    assert!(!d.remediation_hint.is_empty());
}

// ---------------------------------------------------------------------------
// ObstructionReport — Clone / Debug / JSON fields / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_obstruction_report_clone_independence() {
    let w = make_witness(SupportSurface::Parser, ObstructionKind::SemanticGap);
    let report = build_report(SecurityEpoch::from_raw(1), vec![w], vec![], vec![]).unwrap();
    let report2 = report.clone();
    assert_eq!(report, report2);
}

#[test]
fn enrichment_obstruction_report_debug_nonempty() {
    let report = build_report(SecurityEpoch::from_raw(1), vec![], vec![], vec![]).unwrap();
    assert!(!format!("{:?}", report).is_empty());
}

#[test]
fn enrichment_obstruction_report_json_field_names() {
    let w = make_witness(SupportSurface::Parser, ObstructionKind::SemanticGap);
    let report = build_report(SecurityEpoch::from_raw(1), vec![w], vec![], vec![]).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    for field in &[
        "report_id",
        "epoch",
        "witnesses",
        "nongluable_programs",
        "seam_diagnoses",
        "total_obstructions",
        "content_hash",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_obstruction_report_serde_roundtrip() {
    let w = make_witness(SupportSurface::Parser, ObstructionKind::SemanticGap);
    let report = build_report(SecurityEpoch::from_raw(1), vec![w], vec![], vec![]).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let rt: ObstructionReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, rt);
}

// ---------------------------------------------------------------------------
// emit_witness — validation / determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_emit_witness_empty_program_fails() {
    let result = emit_witness(
        SupportSurface::Parser,
        ObstructionKind::SemanticGap,
        "",
        "desc",
        "seam",
    );
    assert!(result.is_err());
}

#[test]
fn enrichment_emit_witness_empty_failure_fails() {
    let result = emit_witness(
        SupportSurface::Parser,
        ObstructionKind::SemanticGap,
        "code",
        "",
        "seam",
    );
    assert!(result.is_err());
}

#[test]
fn enrichment_emit_witness_empty_seam_fails() {
    let result = emit_witness(
        SupportSurface::Parser,
        ObstructionKind::SemanticGap,
        "code",
        "desc",
        "",
    );
    assert!(result.is_err());
}

#[test]
fn enrichment_emit_witness_all_surfaces() {
    let surfaces = [
        SupportSurface::Parser,
        SupportSurface::Lowering,
        SupportSurface::Runtime,
        SupportSurface::Module,
        SupportSurface::TypeScript,
        SupportSurface::React,
        SupportSurface::Cli,
        SupportSurface::CrossSurface,
    ];
    for s in &surfaces {
        let w = emit_witness(
            s.clone(),
            ObstructionKind::TypeMismatch,
            "code",
            "fail",
            "seam",
        );
        assert!(w.is_ok(), "failed for surface: {:?}", s);
    }
}

#[test]
fn enrichment_emit_witness_all_kinds() {
    let kinds = [
        ObstructionKind::TypeMismatch,
        ObstructionKind::SemanticGap,
        ObstructionKind::BoundaryIncompatibility,
        ObstructionKind::ResourceViolation,
        ObstructionKind::TimingDependence,
        ObstructionKind::NondeterministicBehavior,
        ObstructionKind::UnsupportedFeature,
    ];
    for k in &kinds {
        let w = emit_witness(SupportSurface::Parser, k.clone(), "code", "fail", "seam");
        assert!(w.is_ok(), "failed for kind: {:?}", k);
    }
}

// ---------------------------------------------------------------------------
// minimize_witness — behavior
// ---------------------------------------------------------------------------

#[test]
fn enrichment_minimize_witness_sets_minimal_flag() {
    let long_source = "aaaa parser_lowering_boundary bbbb cccc dddd eeee ffff gggg hhhh iiii jjjj kkkk llll mmmm nnnn oooo pppp";
    let w = emit_witness(
        SupportSurface::Parser,
        ObstructionKind::SemanticGap,
        long_source,
        "test failure description",
        "parser_lowering_boundary",
    )
    .unwrap();
    let min = minimize_witness(&w).unwrap();
    assert!(min.minimal);
}

#[test]
fn enrichment_minimize_witness_reduces_source() {
    let long_source = "aaaa parser_lowering_boundary bbbb cccc dddd eeee ffff gggg hhhh iiii jjjj kkkk llll mmmm nnnn oooo pppp";
    let w = emit_witness(
        SupportSurface::Parser,
        ObstructionKind::SemanticGap,
        long_source,
        "test failure",
        "parser_lowering_boundary",
    )
    .unwrap();
    let min = minimize_witness(&w).unwrap();
    assert!(min.program_source.len() <= w.program_source.len());
}

// ---------------------------------------------------------------------------
// detect_nongluable — determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_detect_nongluable_determinism() {
    let jsons: BTreeSet<String> = (0..5)
        .map(|_| serde_json::to_string(&make_nongluable()).unwrap())
        .collect();
    assert_eq!(jsons.len(), 1, "detect_nongluable should be deterministic");
}

// ---------------------------------------------------------------------------
// franken_engine_obstruction_manifest — canonical counts
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_witness_count_7() {
    let m = franken_engine_obstruction_manifest();
    assert_eq!(m.witnesses.len(), 7);
}

#[test]
fn enrichment_manifest_nongluable_count_2() {
    let m = franken_engine_obstruction_manifest();
    assert_eq!(m.nongluable_programs.len(), 2);
}

#[test]
fn enrichment_manifest_diagnosis_count_3() {
    let m = franken_engine_obstruction_manifest();
    assert_eq!(m.seam_diagnoses.len(), 3);
}

#[test]
fn enrichment_manifest_epoch_1() {
    let m = franken_engine_obstruction_manifest();
    assert_eq!(m.epoch, SecurityEpoch::from_raw(1));
}

#[test]
fn enrichment_manifest_total_obstructions_7() {
    let m = franken_engine_obstruction_manifest();
    assert_eq!(m.total_obstructions, 7);
}

#[test]
fn enrichment_manifest_determinism() {
    let jsons: BTreeSet<String> = (0..5)
        .map(|_| serde_json::to_string(&franken_engine_obstruction_manifest()).unwrap())
        .collect();
    assert_eq!(jsons.len(), 1, "manifest should be deterministic");
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_exact_values() {
    assert_eq!(
        SCHEMA_VERSION,
        "franken-engine.obstruction_witness_emitter.v1"
    );
    assert_eq!(BEAD_ID, "bd-1lsy.9.8.2");
    assert_eq!(COMPONENT, "obstruction_witness_emitter");
    assert_eq!(POLICY_ID, "RGC-808B");
    assert_eq!(MILLIONTHS, 1_000_000);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_five_run_determinism_emit_witness() {
    let jsons: BTreeSet<String> = (0..5)
        .map(|_| {
            let w = make_witness(SupportSurface::Parser, ObstructionKind::SemanticGap);
            serde_json::to_string(&w).unwrap()
        })
        .collect();
    assert_eq!(jsons.len(), 1, "emit_witness should be deterministic");
}

#[test]
fn enrichment_five_run_determinism_diagnose_seam() {
    let witnesses = vec![make_witness(
        SupportSurface::Parser,
        ObstructionKind::SemanticGap,
    )];
    let jsons: BTreeSet<String> = (0..5)
        .map(|_| {
            let d = diagnose_seam(&witnesses, SupportSurface::Parser, SupportSurface::Lowering);
            serde_json::to_string(&d).unwrap()
        })
        .collect();
    assert_eq!(jsons.len(), 1, "diagnose_seam should be deterministic");
}

#[test]
fn enrichment_five_run_determinism_build_report() {
    let jsons: BTreeSet<String> = (0..5)
        .map(|_| {
            let w = make_witness(SupportSurface::Parser, ObstructionKind::SemanticGap);
            let r = build_report(SecurityEpoch::from_raw(1), vec![w], vec![], vec![]).unwrap();
            serde_json::to_string(&r).unwrap()
        })
        .collect();
    assert_eq!(jsons.len(), 1, "build_report should be deterministic");
}

// ---------------------------------------------------------------------------
// Cross-cutting invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cross_cutting_manifest_witness_ids_unique() {
    let m = franken_engine_obstruction_manifest();
    let ids: BTreeSet<&str> = m.witnesses.iter().map(|w| w.witness_id.as_str()).collect();
    assert_eq!(ids.len(), m.witnesses.len());
}

#[test]
fn enrichment_cross_cutting_manifest_all_witnesses_have_seam() {
    let m = franken_engine_obstruction_manifest();
    for w in &m.witnesses {
        assert!(
            !w.seam_location.is_empty(),
            "witness {} missing seam",
            w.witness_id
        );
    }
}

#[test]
fn enrichment_cross_cutting_manifest_nongluable_ids_unique() {
    let m = franken_engine_obstruction_manifest();
    let ids: BTreeSet<&str> = m
        .nongluable_programs
        .iter()
        .map(|n| n.program_id.as_str())
        .collect();
    assert_eq!(ids.len(), m.nongluable_programs.len());
}

#[test]
fn enrichment_cross_cutting_manifest_diagnosis_ids_unique() {
    let m = franken_engine_obstruction_manifest();
    let ids: BTreeSet<&str> = m
        .seam_diagnoses
        .iter()
        .map(|d| d.seam_id.as_str())
        .collect();
    assert_eq!(ids.len(), m.seam_diagnoses.len());
}

#[test]
fn enrichment_cross_cutting_report_total_matches_witnesses() {
    let w1 = make_witness(SupportSurface::Parser, ObstructionKind::SemanticGap);
    let w2 = make_witness(SupportSurface::Lowering, ObstructionKind::TypeMismatch);
    let report = build_report(SecurityEpoch::from_raw(1), vec![w1, w2], vec![], vec![]).unwrap();
    assert_eq!(report.total_obstructions, 2);
    assert_eq!(report.witnesses.len(), 2);
}

#[test]
fn enrichment_cross_cutting_report_contains_epoch() {
    let report = build_report(SecurityEpoch::from_raw(42), vec![], vec![], vec![]).unwrap();
    assert_eq!(report.epoch, SecurityEpoch::from_raw(42));
}

#[test]
fn enrichment_cross_cutting_manifest_severity_within_bounds() {
    let m = franken_engine_obstruction_manifest();
    for d in &m.seam_diagnoses {
        assert!(
            d.severity_millionths <= MILLIONTHS,
            "severity exceeds cap for seam {}",
            d.seam_id
        );
    }
}
