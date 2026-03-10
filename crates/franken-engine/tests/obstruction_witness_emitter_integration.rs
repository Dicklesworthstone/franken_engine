//! Integration tests for the obstruction witness emitter (RGC-808B).

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

use frankenengine_engine::obstruction_witness_emitter::{
    self, BEAD_ID, COMPONENT, MILLIONTHS, ObstructionError, ObstructionKind, POLICY_ID,
    SCHEMA_VERSION, SupportSurface,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(SCHEMA_VERSION.contains("obstruction"));
}

#[test]
fn test_bead_id() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn test_component() {
    assert_eq!(COMPONENT, "obstruction_witness_emitter");
}

#[test]
fn test_policy_id() {
    assert_eq!(POLICY_ID, "RGC-808B");
}

#[test]
fn test_millionths() {
    assert_eq!(MILLIONTHS, 1_000_000);
}

// ---------------------------------------------------------------------------
// SupportSurface
// ---------------------------------------------------------------------------

#[test]
fn test_support_surface_display_parser() {
    assert_eq!(format!("{}", SupportSurface::Parser), "parser");
}

#[test]
fn test_support_surface_display_lowering() {
    assert_eq!(format!("{}", SupportSurface::Lowering), "lowering");
}

#[test]
fn test_support_surface_display_runtime() {
    assert_eq!(format!("{}", SupportSurface::Runtime), "runtime");
}

#[test]
fn test_support_surface_display_module() {
    assert_eq!(format!("{}", SupportSurface::Module), "module");
}

#[test]
fn test_support_surface_display_typescript() {
    assert_eq!(format!("{}", SupportSurface::TypeScript), "typescript");
}

#[test]
fn test_support_surface_display_cross() {
    assert_eq!(format!("{}", SupportSurface::CrossSurface), "cross-surface");
}

#[test]
fn test_support_surface_serde_roundtrip() {
    let s = SupportSurface::Parser;
    let json = serde_json::to_string(&s).unwrap();
    let back: SupportSurface = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ---------------------------------------------------------------------------
// ObstructionKind
// ---------------------------------------------------------------------------

#[test]
fn test_obstruction_kind_display_type_mismatch() {
    assert_eq!(
        format!("{}", ObstructionKind::TypeMismatch),
        "type-mismatch"
    );
}

#[test]
fn test_obstruction_kind_display_semantic_gap() {
    assert_eq!(format!("{}", ObstructionKind::SemanticGap), "semantic-gap");
}

#[test]
fn test_obstruction_kind_display_unsupported() {
    assert_eq!(
        format!("{}", ObstructionKind::UnsupportedFeature),
        "unsupported-feature"
    );
}

#[test]
fn test_obstruction_kind_serde_roundtrip() {
    let k = ObstructionKind::ResourceViolation;
    let json = serde_json::to_string(&k).unwrap();
    let back: ObstructionKind = serde_json::from_str(&json).unwrap();
    assert_eq!(k, back);
}

// ---------------------------------------------------------------------------
// emit_witness
// ---------------------------------------------------------------------------

#[test]
fn test_emit_witness_ok() {
    let witness = obstruction_witness_emitter::emit_witness(
        SupportSurface::Parser,
        ObstructionKind::TypeMismatch,
        "const x = 42;",
        "type error at line 1",
        "parser-lowering",
    )
    .unwrap();
    assert!(!witness.witness_id.is_empty());
    assert_eq!(witness.surface, SupportSurface::Parser);
    assert_eq!(witness.kind, ObstructionKind::TypeMismatch);
    assert!(!witness.minimal);
    assert_eq!(witness.reduction_steps, 0);
}

#[test]
fn test_emit_witness_empty_program() {
    let result = obstruction_witness_emitter::emit_witness(
        SupportSurface::Parser,
        ObstructionKind::TypeMismatch,
        "",
        "failure",
        "seam",
    );
    assert!(matches!(result, Err(ObstructionError::EmptyWitness)));
}

#[test]
fn test_emit_witness_empty_failure() {
    let result = obstruction_witness_emitter::emit_witness(
        SupportSurface::Parser,
        ObstructionKind::TypeMismatch,
        "source",
        "",
        "seam",
    );
    assert!(matches!(result, Err(ObstructionError::EmptyWitness)));
}

#[test]
fn test_emit_witness_empty_seam() {
    let result = obstruction_witness_emitter::emit_witness(
        SupportSurface::Parser,
        ObstructionKind::TypeMismatch,
        "source",
        "failure",
        "",
    );
    assert!(matches!(result, Err(ObstructionError::SeamNotFound)));
}

#[test]
fn test_emit_witness_deterministic() {
    let a = obstruction_witness_emitter::emit_witness(
        SupportSurface::Parser,
        ObstructionKind::TypeMismatch,
        "const x = 42;",
        "type error",
        "seam-1",
    )
    .unwrap();
    let b = obstruction_witness_emitter::emit_witness(
        SupportSurface::Parser,
        ObstructionKind::TypeMismatch,
        "const x = 42;",
        "type error",
        "seam-1",
    )
    .unwrap();
    assert_eq!(a.content_hash, b.content_hash);
}

// ---------------------------------------------------------------------------
// minimize_witness
// ---------------------------------------------------------------------------

#[test]
fn test_minimize_witness_ok() {
    let witness = obstruction_witness_emitter::emit_witness(
        SupportSurface::Runtime,
        ObstructionKind::SemanticGap,
        "some code that contains seam-rt marker for testing purposes seam-rt end",
        "semantic gap at runtime boundary",
        "seam-rt",
    )
    .unwrap();
    let minimized = obstruction_witness_emitter::minimize_witness(&witness).unwrap();
    assert!(minimized.minimal);
    assert!(minimized.program_source.len() <= witness.program_source.len());
}

#[test]
fn test_minimize_witness_empty_program() {
    let witness = obstruction_witness_emitter::emit_witness(
        SupportSurface::Parser,
        ObstructionKind::TypeMismatch,
        "x",
        "failure",
        "x",
    )
    .unwrap();
    // Source is only 1 char, minimization may fail or succeed depending on logic
    let _result = obstruction_witness_emitter::minimize_witness(&witness);
    // Just checking it does not panic
}

// ---------------------------------------------------------------------------
// detect_nongluable
// ---------------------------------------------------------------------------

#[test]
fn test_detect_nongluable() {
    let ng = obstruction_witness_emitter::detect_nongluable(
        "let x = 1;",
        SupportSurface::Parser,
        SupportSurface::Lowering,
        "parsed as VariableDeclaration",
        "lowered as Assignment",
    );
    assert!(!ng.program_id.is_empty());
    assert_eq!(ng.left_surface, SupportSurface::Parser);
    assert_eq!(ng.right_surface, SupportSurface::Lowering);
    assert!(!ng.divergence_description.is_empty());
}

#[test]
fn test_detect_nongluable_deterministic() {
    let a = obstruction_witness_emitter::detect_nongluable(
        "let x = 1;",
        SupportSurface::Parser,
        SupportSurface::Lowering,
        "interp-a",
        "interp-b",
    );
    let b = obstruction_witness_emitter::detect_nongluable(
        "let x = 1;",
        SupportSurface::Parser,
        SupportSurface::Lowering,
        "interp-a",
        "interp-b",
    );
    assert_eq!(a.content_hash, b.content_hash);
    assert_eq!(a.program_id, b.program_id);
}

// ---------------------------------------------------------------------------
// diagnose_seam
// ---------------------------------------------------------------------------

#[test]
fn test_diagnose_seam_empty_witnesses() {
    let diagnosis = obstruction_witness_emitter::diagnose_seam(
        &[],
        SupportSurface::Parser,
        SupportSurface::Lowering,
    );
    assert_eq!(diagnosis.obstruction_count, 0);
    assert_eq!(diagnosis.severity_millionths, 0);
}

#[test]
fn test_diagnose_seam_with_witnesses() {
    let w = obstruction_witness_emitter::emit_witness(
        SupportSurface::Parser,
        ObstructionKind::TypeMismatch,
        "source",
        "failure",
        "parser-lowering",
    )
    .unwrap();
    let diagnosis = obstruction_witness_emitter::diagnose_seam(
        &[w],
        SupportSurface::Parser,
        SupportSurface::Lowering,
    );
    assert!(diagnosis.obstruction_count > 0);
    assert!(diagnosis.severity_millionths > 0);
}

// ---------------------------------------------------------------------------
// build_report
// ---------------------------------------------------------------------------

#[test]
fn test_build_report_empty() {
    let report =
        obstruction_witness_emitter::build_report(test_epoch(), vec![], vec![], vec![]).unwrap();
    assert_eq!(report.total_obstructions, 0);
    assert!(report.witnesses.is_empty());
}

#[test]
fn test_build_report_with_data() {
    let w = obstruction_witness_emitter::emit_witness(
        SupportSurface::Parser,
        ObstructionKind::SemanticGap,
        "code",
        "gap",
        "seam-1",
    )
    .unwrap();
    let ng = obstruction_witness_emitter::detect_nongluable(
        "let x;",
        SupportSurface::Parser,
        SupportSurface::Lowering,
        "a",
        "b",
    );
    let diag = obstruction_witness_emitter::diagnose_seam(
        &[],
        SupportSurface::Parser,
        SupportSurface::Lowering,
    );
    let report =
        obstruction_witness_emitter::build_report(test_epoch(), vec![w], vec![ng], vec![diag])
            .unwrap();
    assert_eq!(report.witnesses.len(), 1);
    assert_eq!(report.nongluable_programs.len(), 1);
    assert_eq!(report.seam_diagnoses.len(), 1);
}

// ---------------------------------------------------------------------------
// ObstructionError Display
// ---------------------------------------------------------------------------

#[test]
fn test_error_display_empty_witness() {
    let e = ObstructionError::EmptyWitness;
    let s = format!("{e}");
    assert!(s.contains("empty"));
}

#[test]
fn test_error_display_invalid_surface() {
    let e = ObstructionError::InvalidSurface;
    let s = format!("{e}");
    assert!(s.contains("invalid"));
}

#[test]
fn test_error_display_seam_not_found() {
    let e = ObstructionError::SeamNotFound;
    let s = format!("{e}");
    assert!(s.contains("seam"));
}

#[test]
fn test_error_display_internal() {
    let e = ObstructionError::InternalError("oops".into());
    let s = format!("{e}");
    assert!(s.contains("oops"));
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

#[test]
fn test_manifest() {
    let report = obstruction_witness_emitter::franken_engine_obstruction_manifest();
    assert!(!report.report_id.is_empty());
}

#[test]
fn test_manifest_deterministic() {
    let a = obstruction_witness_emitter::franken_engine_obstruction_manifest();
    let b = obstruction_witness_emitter::franken_engine_obstruction_manifest();
    assert_eq!(a.report_id, b.report_id);
    assert_eq!(a.content_hash, b.content_hash);
}
