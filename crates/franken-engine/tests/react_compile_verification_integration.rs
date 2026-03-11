//! Integration tests for `react_compile_verification` module.
//!
//! Validates the public API for differential parity verification of React
//! compile outputs across library and shipped CLI surfaces. Covers enum
//! exhaustiveness, serde contracts, determinism, mismatch detection,
//! verdict logic, receipt provenance, batch operations, and edge cases.

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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::react_compile_verification::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(77)
}

fn make_artifact(kind: ArtifactKind, content: &[u8]) -> CompileArtifact {
    CompileArtifact::from_content(kind, content, "integration-test")
}

fn make_diagnostic(msg: &str, severity: DiagnosticSeverity) -> CompileDiagnostic {
    CompileDiagnostic {
        message: msg.to_string(),
        severity,
        line: 10,
        column: 5,
        source_range: (0, 50),
    }
}

fn lib_result(
    artifacts: Vec<CompileArtifact>,
    diagnostics: Vec<CompileDiagnostic>,
) -> CompileResult {
    CompileResult {
        surface: CompileSurface::Library,
        mode: CompileMode::Automatic,
        artifacts,
        diagnostics,
        success: true,
        duration_micros: 500,
    }
}

fn cli_result(
    artifacts: Vec<CompileArtifact>,
    diagnostics: Vec<CompileDiagnostic>,
) -> CompileResult {
    CompileResult {
        surface: CompileSurface::CliShipped,
        mode: CompileMode::Automatic,
        artifacts,
        diagnostics,
        success: true,
        duration_micros: 700,
    }
}

fn default_config() -> VerificationConfig {
    VerificationConfig::default()
}

fn no_sourcemap_config() -> VerificationConfig {
    VerificationConfig {
        require_source_maps: false,
        ..VerificationConfig::default()
    }
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn schema_version_starts_with_prefix() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn component_non_empty() {
    assert!(!COMPONENT.is_empty());
    assert_eq!(COMPONENT, "react_compile_verification");
}

#[test]
fn bead_id_starts_with_bd() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn policy_id_starts_with_rgc() {
    assert!(POLICY_ID.starts_with("RGC-"));
}

#[test]
fn default_size_divergence_within_scale() {
    assert!(DEFAULT_MAX_SIZE_DIVERGENCE <= 1_000_000);
    assert!(DEFAULT_MAX_SIZE_DIVERGENCE > 0);
}

#[test]
fn default_diagnostic_divergence_is_zero() {
    assert_eq!(DEFAULT_MAX_DIAGNOSTIC_DIVERGENCE, 0);
}

// ===========================================================================
// CompileMode
// ===========================================================================

#[test]
fn compile_mode_all_exhaustive() {
    assert_eq!(CompileMode::ALL.len(), 2);
    assert!(CompileMode::ALL.contains(&CompileMode::Classic));
    assert!(CompileMode::ALL.contains(&CompileMode::Automatic));
}

#[test]
fn compile_mode_as_str_non_empty() {
    for m in CompileMode::ALL {
        assert!(!m.as_str().is_empty());
    }
}

#[test]
fn compile_mode_display_matches_as_str() {
    for m in CompileMode::ALL {
        assert_eq!(m.to_string(), m.as_str());
    }
}

#[test]
fn compile_mode_serde_all_variants() {
    for m in CompileMode::ALL {
        let json = serde_json::to_string(m).unwrap();
        let back: CompileMode = serde_json::from_str(&json).unwrap();
        assert_eq!(*m, back);
    }
}

#[test]
fn compile_mode_ordering() {
    assert!(CompileMode::Classic < CompileMode::Automatic);
}

// ===========================================================================
// ArtifactKind
// ===========================================================================

#[test]
fn artifact_kind_all_exhaustive() {
    assert_eq!(ArtifactKind::ALL.len(), 5);
}

#[test]
fn artifact_kind_as_str_unique() {
    let mut names: Vec<_> = ArtifactKind::ALL.iter().map(|k| k.as_str()).collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), ArtifactKind::ALL.len());
}

#[test]
fn artifact_kind_display_matches_as_str() {
    for k in ArtifactKind::ALL {
        assert_eq!(k.to_string(), k.as_str());
    }
}

#[test]
fn artifact_kind_serde_all_variants() {
    for k in ArtifactKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: ArtifactKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

// ===========================================================================
// DiagnosticSeverity
// ===========================================================================

#[test]
fn diagnostic_severity_all_exhaustive() {
    assert_eq!(DiagnosticSeverity::ALL.len(), 4);
}

#[test]
fn diagnostic_severity_display() {
    for s in DiagnosticSeverity::ALL {
        assert_eq!(s.to_string(), s.as_str());
    }
}

#[test]
fn diagnostic_severity_serde() {
    for s in DiagnosticSeverity::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: DiagnosticSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

#[test]
fn diagnostic_severity_weights_monotonic() {
    let weights: Vec<u64> = DiagnosticSeverity::ALL.iter().map(|s| s.weight()).collect();
    for pair in weights.windows(2) {
        assert!(pair[0] < pair[1], "weights must be strictly increasing");
    }
}

#[test]
fn diagnostic_severity_error_is_max_weight() {
    assert_eq!(DiagnosticSeverity::Error.weight(), 1_000_000);
}

// ===========================================================================
// CompileSurface
// ===========================================================================

#[test]
fn compile_surface_all_exhaustive() {
    assert_eq!(CompileSurface::ALL.len(), 2);
}

#[test]
fn compile_surface_display_matches_as_str() {
    for s in CompileSurface::ALL {
        assert_eq!(s.to_string(), s.as_str());
    }
}

#[test]
fn compile_surface_serde() {
    for s in CompileSurface::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: CompileSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ===========================================================================
// MismatchKind
// ===========================================================================

#[test]
fn mismatch_kind_all_exhaustive() {
    assert_eq!(MismatchKind::ALL.len(), 6);
}

#[test]
fn mismatch_kind_as_str_unique() {
    let mut names: Vec<_> = MismatchKind::ALL.iter().map(|k| k.as_str()).collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), MismatchKind::ALL.len());
}

#[test]
fn mismatch_kind_display() {
    for k in MismatchKind::ALL {
        assert_eq!(k.to_string(), k.as_str());
    }
}

#[test]
fn mismatch_kind_serde() {
    for k in MismatchKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: MismatchKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

// ===========================================================================
// VerificationVerdict
// ===========================================================================

#[test]
fn verdict_all_exhaustive() {
    assert_eq!(VerificationVerdict::ALL.len(), 3);
}

#[test]
fn verdict_display() {
    for v in VerificationVerdict::ALL {
        assert_eq!(v.to_string(), v.as_str());
    }
}

#[test]
fn verdict_serde() {
    for v in VerificationVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: VerificationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn verdict_is_pass() {
    assert!(VerificationVerdict::Pass.is_pass());
    assert!(!VerificationVerdict::Fail.is_pass());
    assert!(!VerificationVerdict::Inconclusive.is_pass());
}

#[test]
fn verdict_is_fail() {
    assert!(VerificationVerdict::Fail.is_fail());
    assert!(!VerificationVerdict::Pass.is_fail());
    assert!(!VerificationVerdict::Inconclusive.is_fail());
}

// ===========================================================================
// CompileDiagnostic
// ===========================================================================

#[test]
fn diagnostic_hash_deterministic() {
    let d1 = make_diagnostic("msg", DiagnosticSeverity::Warning);
    let d2 = make_diagnostic("msg", DiagnosticSeverity::Warning);
    assert_eq!(d1.content_hash(), d2.content_hash());
}

#[test]
fn diagnostic_hash_varies_by_message() {
    let d1 = make_diagnostic("alpha", DiagnosticSeverity::Warning);
    let d2 = make_diagnostic("beta", DiagnosticSeverity::Warning);
    assert_ne!(d1.content_hash(), d2.content_hash());
}

#[test]
fn diagnostic_hash_varies_by_severity() {
    let d1 = make_diagnostic("msg", DiagnosticSeverity::Warning);
    let d2 = make_diagnostic("msg", DiagnosticSeverity::Error);
    assert_ne!(d1.content_hash(), d2.content_hash());
}

#[test]
fn diagnostic_display_contains_severity_and_message() {
    let d = make_diagnostic("something wrong", DiagnosticSeverity::Error);
    let s = d.to_string();
    assert!(s.contains("error"));
    assert!(s.contains("something wrong"));
}

#[test]
fn diagnostic_serde_roundtrip() {
    let d = make_diagnostic("hello", DiagnosticSeverity::Hint);
    let json = serde_json::to_string(&d).unwrap();
    let back: CompileDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

// ===========================================================================
// CompileArtifact
// ===========================================================================

#[test]
fn artifact_from_content_size_matches() {
    let data = b"react output";
    let a = CompileArtifact::from_content(ArtifactKind::CompiledOutput, data, "test");
    assert_eq!(a.size_bytes, data.len() as u64);
}

#[test]
fn artifact_from_content_hash_deterministic() {
    let a1 = CompileArtifact::from_content(ArtifactKind::SourceMap, b"map", "p1");
    let a2 = CompileArtifact::from_content(ArtifactKind::SourceMap, b"map", "p2");
    assert_eq!(a1.content_hash, a2.content_hash);
}

#[test]
fn artifact_from_content_hash_varies_by_content() {
    let a1 = CompileArtifact::from_content(ArtifactKind::CompiledOutput, b"abc", "p");
    let a2 = CompileArtifact::from_content(ArtifactKind::CompiledOutput, b"xyz", "p");
    assert_ne!(a1.content_hash, a2.content_hash);
}

#[test]
fn artifact_serde_roundtrip() {
    let a = make_artifact(ArtifactKind::BundleManifest, b"manifest data");
    let json = serde_json::to_string(&a).unwrap();
    let back: CompileArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

// ===========================================================================
// CompileResult
// ===========================================================================

#[test]
fn result_artifacts_by_kind_filters() {
    let r = lib_result(
        vec![
            make_artifact(ArtifactKind::CompiledOutput, b"js"),
            make_artifact(ArtifactKind::SourceMap, b"map"),
            make_artifact(ArtifactKind::CompiledOutput, b"js2"),
        ],
        vec![],
    );
    assert_eq!(r.artifacts_by_kind(ArtifactKind::CompiledOutput).len(), 2);
    assert_eq!(r.artifacts_by_kind(ArtifactKind::SourceMap).len(), 1);
    assert_eq!(r.artifacts_by_kind(ArtifactKind::Diagnostics).len(), 0);
}

#[test]
fn result_has_source_map_true() {
    let r = lib_result(vec![make_artifact(ArtifactKind::SourceMap, b"m")], vec![]);
    assert!(r.has_source_map());
}

#[test]
fn result_has_source_map_false() {
    let r = lib_result(vec![], vec![]);
    assert!(!r.has_source_map());
}

#[test]
fn result_diagnostic_count_filters() {
    let r = lib_result(
        vec![],
        vec![
            make_diagnostic("a", DiagnosticSeverity::Warning),
            make_diagnostic("b", DiagnosticSeverity::Error),
            make_diagnostic("c", DiagnosticSeverity::Warning),
        ],
    );
    assert_eq!(r.diagnostic_count(DiagnosticSeverity::Warning), 2);
    assert_eq!(r.diagnostic_count(DiagnosticSeverity::Error), 1);
    assert_eq!(r.diagnostic_count(DiagnosticSeverity::Info), 0);
}

#[test]
fn result_total_artifact_size() {
    let r = lib_result(
        vec![
            make_artifact(ArtifactKind::CompiledOutput, b"abc"),
            make_artifact(ArtifactKind::SourceMap, b"de"),
        ],
        vec![],
    );
    assert_eq!(r.total_artifact_size(), 5);
}

#[test]
fn result_content_hash_deterministic() {
    let arts = vec![make_artifact(ArtifactKind::CompiledOutput, b"code")];
    let r1 = lib_result(arts.clone(), vec![]);
    let r2 = lib_result(arts, vec![]);
    assert_eq!(r1.content_hash(), r2.content_hash());
}

#[test]
fn result_content_hash_varies_by_surface() {
    let arts = vec![make_artifact(ArtifactKind::CompiledOutput, b"code")];
    let r1 = lib_result(arts.clone(), vec![]);
    let r2 = cli_result(arts, vec![]);
    assert_ne!(r1.content_hash(), r2.content_hash());
}

#[test]
fn result_serde_roundtrip() {
    let r = lib_result(
        vec![make_artifact(ArtifactKind::CompiledOutput, b"code")],
        vec![make_diagnostic("w", DiagnosticSeverity::Warning)],
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: CompileResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ===========================================================================
// VerificationConfig
// ===========================================================================

#[test]
fn config_default_values() {
    let c = VerificationConfig::default();
    assert_eq!(
        c.max_size_divergence_millionths,
        DEFAULT_MAX_SIZE_DIVERGENCE
    );
    assert!(c.require_source_maps);
    assert!(c.require_diagnostics_parity);
    assert_eq!(c.max_diagnostic_divergence, 0);
}

#[test]
fn config_strict_values() {
    let c = VerificationConfig::strict();
    assert_eq!(c.max_size_divergence_millionths, 0);
    assert!(c.require_source_maps);
    assert!(c.require_diagnostics_parity);
}

#[test]
fn config_permissive_values() {
    let c = VerificationConfig::permissive();
    assert!(!c.require_source_maps);
    assert!(!c.require_diagnostics_parity);
    assert!(c.max_size_divergence_millionths > DEFAULT_MAX_SIZE_DIVERGENCE);
}

#[test]
fn config_serde_roundtrip() {
    let c = default_config();
    let json = serde_json::to_string(&c).unwrap();
    let back: VerificationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ===========================================================================
// classify_mismatch_severity
// ===========================================================================

#[test]
fn classify_all_kinds() {
    assert_eq!(
        classify_mismatch_severity(MismatchKind::ArtifactMissing),
        DiagnosticSeverity::Error
    );
    assert_eq!(
        classify_mismatch_severity(MismatchKind::ArtifactExtra),
        DiagnosticSeverity::Warning
    );
    assert_eq!(
        classify_mismatch_severity(MismatchKind::ContentDivergence),
        DiagnosticSeverity::Error
    );
    assert_eq!(
        classify_mismatch_severity(MismatchKind::DiagnosticDivergence),
        DiagnosticSeverity::Warning
    );
    assert_eq!(
        classify_mismatch_severity(MismatchKind::SizeDivergence),
        DiagnosticSeverity::Info
    );
    assert_eq!(
        classify_mismatch_severity(MismatchKind::SourceMapDivergence),
        DiagnosticSeverity::Warning
    );
}

// ===========================================================================
// verify_compile_parity — happy path
// ===========================================================================

#[test]
fn parity_identical_artifacts_pass() {
    let arts = vec![
        make_artifact(ArtifactKind::CompiledOutput, b"code"),
        make_artifact(ArtifactKind::SourceMap, b"map"),
    ];
    let a = lib_result(arts.clone(), vec![]);
    let b = cli_result(arts, vec![]);
    let r = verify_compile_parity(&a, &b, &default_config(), &epoch(), 100).unwrap();
    assert_eq!(r.verdict, VerificationVerdict::Pass);
    assert!(r.mismatches.is_empty());
}

#[test]
fn parity_empty_artifacts_pass() {
    let a = lib_result(vec![], vec![]);
    let b = cli_result(vec![], vec![]);
    let cfg = no_sourcemap_config();
    let r = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
    assert_eq!(r.verdict, VerificationVerdict::Pass);
}

#[test]
fn parity_identical_diagnostics_pass() {
    let diags = vec![make_diagnostic("x", DiagnosticSeverity::Warning)];
    let a = lib_result(vec![], diags.clone());
    let b = cli_result(vec![], diags);
    let cfg = no_sourcemap_config();
    let r = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
    assert_eq!(r.verdict, VerificationVerdict::Pass);
}

// ===========================================================================
// verify_compile_parity — error cases
// ===========================================================================

#[test]
fn parity_same_surface_error() {
    let a = lib_result(vec![], vec![]);
    let b = lib_result(vec![], vec![]);
    let err = verify_compile_parity(&a, &b, &default_config(), &epoch(), 0).unwrap_err();
    assert!(matches!(err, VerificationError::SameSurface { .. }));
}

#[test]
fn parity_mode_mismatch_error() {
    let a = lib_result(vec![], vec![]);
    let mut b = cli_result(vec![], vec![]);
    b.mode = CompileMode::Classic;
    let err = verify_compile_parity(&a, &b, &default_config(), &epoch(), 0).unwrap_err();
    assert!(matches!(err, VerificationError::ModeMismatch { .. }));
}

// ===========================================================================
// verify_compile_parity — inconclusive
// ===========================================================================

#[test]
fn parity_a_failed_inconclusive() {
    let mut a = lib_result(vec![], vec![]);
    a.success = false;
    let b = cli_result(vec![], vec![]);
    let r = verify_compile_parity(&a, &b, &default_config(), &epoch(), 0).unwrap();
    assert_eq!(r.verdict, VerificationVerdict::Inconclusive);
}

#[test]
fn parity_b_failed_inconclusive() {
    let a = lib_result(vec![], vec![]);
    let mut b = cli_result(vec![], vec![]);
    b.success = false;
    let r = verify_compile_parity(&a, &b, &default_config(), &epoch(), 0).unwrap();
    assert_eq!(r.verdict, VerificationVerdict::Inconclusive);
}

#[test]
fn parity_both_failed_inconclusive() {
    let mut a = lib_result(vec![], vec![]);
    a.success = false;
    let mut b = cli_result(vec![], vec![]);
    b.success = false;
    let r = verify_compile_parity(&a, &b, &default_config(), &epoch(), 0).unwrap();
    assert_eq!(r.verdict, VerificationVerdict::Inconclusive);
    assert!(r.mismatches.is_empty());
}

// ===========================================================================
// verify_compile_parity — artifact mismatches
// ===========================================================================

#[test]
fn parity_artifact_missing_fail() {
    let a = lib_result(
        vec![make_artifact(ArtifactKind::CompiledOutput, b"js")],
        vec![],
    );
    let b = cli_result(vec![], vec![]);
    let cfg = no_sourcemap_config();
    let r = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
    assert_eq!(r.verdict, VerificationVerdict::Fail);
    assert!(
        r.mismatches
            .iter()
            .any(|m| m.kind == MismatchKind::ArtifactMissing)
    );
}

#[test]
fn parity_artifact_extra_warning_pass() {
    let a = lib_result(vec![], vec![]);
    let b = cli_result(
        vec![make_artifact(ArtifactKind::BundleManifest, b"m")],
        vec![],
    );
    let cfg = no_sourcemap_config();
    let r = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
    // Extra artifact is warning-level only.
    assert_eq!(r.verdict, VerificationVerdict::Pass);
    assert!(
        r.mismatches
            .iter()
            .any(|m| m.kind == MismatchKind::ArtifactExtra)
    );
}

#[test]
fn parity_content_divergence_fail() {
    let a = lib_result(
        vec![make_artifact(ArtifactKind::CompiledOutput, b"code_a")],
        vec![],
    );
    let b = cli_result(
        vec![make_artifact(ArtifactKind::CompiledOutput, b"code_b")],
        vec![],
    );
    let cfg = no_sourcemap_config();
    let r = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
    assert_eq!(r.verdict, VerificationVerdict::Fail);
    assert!(
        r.mismatches
            .iter()
            .any(|m| m.kind == MismatchKind::ContentDivergence)
    );
}

#[test]
fn parity_size_divergence_detected() {
    let a = lib_result(
        vec![CompileArtifact {
            kind: ArtifactKind::CompiledOutput,
            content_hash: ContentHash::compute(b"same"),
            size_bytes: 100,
            provenance: "test".into(),
        }],
        vec![],
    );
    let b = cli_result(
        vec![CompileArtifact {
            kind: ArtifactKind::CompiledOutput,
            content_hash: ContentHash::compute(b"same"),
            size_bytes: 200,
            provenance: "test".into(),
        }],
        vec![],
    );
    let cfg = no_sourcemap_config();
    let r = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
    assert!(
        r.mismatches
            .iter()
            .any(|m| m.kind == MismatchKind::SizeDivergence)
    );
    // Size divergence is info-level, should still pass.
    assert_eq!(r.verdict, VerificationVerdict::Pass);
}

#[test]
fn parity_no_size_divergence_within_threshold() {
    let a = lib_result(
        vec![CompileArtifact {
            kind: ArtifactKind::CompiledOutput,
            content_hash: ContentHash::compute(b"same"),
            size_bytes: 1000,
            provenance: "test".into(),
        }],
        vec![],
    );
    let b = cli_result(
        vec![CompileArtifact {
            kind: ArtifactKind::CompiledOutput,
            content_hash: ContentHash::compute(b"same"),
            size_bytes: 1010, // 1% divergence, default threshold 5%
            provenance: "test".into(),
        }],
        vec![],
    );
    let cfg = no_sourcemap_config();
    let r = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
    assert!(
        !r.mismatches
            .iter()
            .any(|m| m.kind == MismatchKind::SizeDivergence)
    );
}

// ===========================================================================
// verify_compile_parity — diagnostic mismatches
// ===========================================================================

#[test]
fn parity_diagnostic_divergence_detected() {
    let a = lib_result(
        vec![],
        vec![make_diagnostic("warning A", DiagnosticSeverity::Warning)],
    );
    let b = cli_result(
        vec![],
        vec![make_diagnostic("warning B", DiagnosticSeverity::Warning)],
    );
    let cfg = no_sourcemap_config();
    let r = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
    assert!(
        r.mismatches
            .iter()
            .any(|m| m.kind == MismatchKind::DiagnosticDivergence)
    );
}

#[test]
fn parity_diagnostic_parity_not_required() {
    let a = lib_result(
        vec![],
        vec![make_diagnostic("warning A", DiagnosticSeverity::Warning)],
    );
    let b = cli_result(
        vec![],
        vec![make_diagnostic("warning B", DiagnosticSeverity::Warning)],
    );
    let cfg = VerificationConfig {
        require_source_maps: false,
        require_diagnostics_parity: false,
        ..default_config()
    };
    let r = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
    assert!(
        !r.mismatches
            .iter()
            .any(|m| m.kind == MismatchKind::DiagnosticDivergence)
    );
}

#[test]
fn parity_diagnostic_divergence_within_tolerance() {
    let a = lib_result(
        vec![],
        vec![make_diagnostic("w1", DiagnosticSeverity::Warning)],
    );
    let b = cli_result(
        vec![],
        vec![make_diagnostic("w2", DiagnosticSeverity::Warning)],
    );
    let cfg = VerificationConfig {
        require_source_maps: false,
        require_diagnostics_parity: true,
        max_diagnostic_divergence: 10, // high tolerance
        ..default_config()
    };
    let r = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
    assert!(
        !r.mismatches
            .iter()
            .any(|m| m.kind == MismatchKind::DiagnosticDivergence)
    );
}

// ===========================================================================
// verify_compile_parity — source map checks
// ===========================================================================

#[test]
fn parity_source_map_missing_one_side() {
    let a = lib_result(vec![make_artifact(ArtifactKind::SourceMap, b"map")], vec![]);
    let b = cli_result(vec![], vec![]);
    let r = verify_compile_parity(&a, &b, &default_config(), &epoch(), 0).unwrap();
    assert!(
        r.mismatches
            .iter()
            .any(|m| m.kind == MismatchKind::SourceMapDivergence)
    );
}

#[test]
fn parity_source_map_content_divergence() {
    let a = lib_result(
        vec![make_artifact(ArtifactKind::SourceMap, b"map_a")],
        vec![],
    );
    let b = cli_result(
        vec![make_artifact(ArtifactKind::SourceMap, b"map_b")],
        vec![],
    );
    let r = verify_compile_parity(&a, &b, &default_config(), &epoch(), 0).unwrap();
    assert!(
        r.mismatches
            .iter()
            .any(|m| m.kind == MismatchKind::SourceMapDivergence)
    );
}

#[test]
fn parity_source_maps_not_required_skips_check() {
    let a = lib_result(
        vec![make_artifact(ArtifactKind::SourceMap, b"map_a")],
        vec![],
    );
    let b = cli_result(vec![], vec![]);
    let cfg = VerificationConfig {
        require_source_maps: false,
        ..default_config()
    };
    let r = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
    assert!(
        !r.mismatches
            .iter()
            .any(|m| m.kind == MismatchKind::SourceMapDivergence)
    );
}

#[test]
fn parity_source_map_identical_no_divergence() {
    let a = lib_result(
        vec![make_artifact(ArtifactKind::SourceMap, b"same_map")],
        vec![],
    );
    let b = cli_result(
        vec![make_artifact(ArtifactKind::SourceMap, b"same_map")],
        vec![],
    );
    let r = verify_compile_parity(&a, &b, &default_config(), &epoch(), 0).unwrap();
    assert!(
        !r.mismatches
            .iter()
            .any(|m| m.kind == MismatchKind::SourceMapDivergence)
    );
}

// ===========================================================================
// DecisionReceipt
// ===========================================================================

#[test]
fn receipt_fields_correct() {
    let r = compute_receipt(
        ContentHash::compute(b"input"),
        &VerificationVerdict::Pass,
        &epoch(),
        12345,
    );
    assert_eq!(r.schema_version, SCHEMA_VERSION);
    assert_eq!(r.component, COMPONENT);
    assert_eq!(r.bead_id, BEAD_ID);
    assert_eq!(r.policy_id, POLICY_ID);
    assert_eq!(r.epoch.as_u64(), 77);
    assert_eq!(r.timestamp_micros, 12345);
}

#[test]
fn receipt_hash_deterministic() {
    let r1 = compute_receipt(
        ContentHash::compute(b"x"),
        &VerificationVerdict::Fail,
        &epoch(),
        0,
    );
    let r2 = compute_receipt(
        ContentHash::compute(b"x"),
        &VerificationVerdict::Fail,
        &epoch(),
        0,
    );
    assert_eq!(r1.content_hash(), r2.content_hash());
}

#[test]
fn receipt_hash_varies_by_verdict() {
    let r1 = compute_receipt(
        ContentHash::compute(b"x"),
        &VerificationVerdict::Pass,
        &epoch(),
        0,
    );
    let r2 = compute_receipt(
        ContentHash::compute(b"x"),
        &VerificationVerdict::Fail,
        &epoch(),
        0,
    );
    assert_ne!(r1.verdict_hash, r2.verdict_hash);
}

#[test]
fn receipt_serde_roundtrip() {
    let r = compute_receipt(
        ContentHash::compute(b"test"),
        &VerificationVerdict::Inconclusive,
        &epoch(),
        999,
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ===========================================================================
// VerificationReport
// ===========================================================================

#[test]
fn report_mismatch_count_by_kind() {
    let a = lib_result(
        vec![make_artifact(ArtifactKind::CompiledOutput, b"code")],
        vec![],
    );
    let b = cli_result(vec![], vec![]);
    let cfg = no_sourcemap_config();
    let r = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
    assert!(r.mismatch_count_by_kind(MismatchKind::ArtifactMissing) > 0);
    assert_eq!(r.mismatch_count_by_kind(MismatchKind::ArtifactExtra), 0);
}

#[test]
fn report_mismatch_count_by_severity() {
    let a = lib_result(
        vec![make_artifact(ArtifactKind::CompiledOutput, b"a")],
        vec![],
    );
    let b = cli_result(vec![], vec![]);
    let cfg = no_sourcemap_config();
    let r = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
    assert!(r.mismatch_count_by_severity(DiagnosticSeverity::Error) > 0);
}

#[test]
fn report_weighted_score_positive_on_mismatch() {
    let a = lib_result(
        vec![make_artifact(ArtifactKind::CompiledOutput, b"a")],
        vec![],
    );
    let b = cli_result(
        vec![make_artifact(ArtifactKind::CompiledOutput, b"b")],
        vec![],
    );
    let cfg = no_sourcemap_config();
    let r = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
    assert!(r.weighted_score() > 0);
}

#[test]
fn report_has_errors_on_fail() {
    let a = lib_result(
        vec![make_artifact(ArtifactKind::CompiledOutput, b"a")],
        vec![],
    );
    let b = cli_result(vec![], vec![]);
    let cfg = no_sourcemap_config();
    let r = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
    assert!(r.has_errors());
}

#[test]
fn report_content_hash_deterministic() {
    let arts = vec![make_artifact(ArtifactKind::CompiledOutput, b"code")];
    let a = lib_result(arts.clone(), vec![]);
    let b = cli_result(arts, vec![]);
    let cfg = no_sourcemap_config();
    let r1 = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
    let r2 = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
    assert_eq!(r1.content_hash(), r2.content_hash());
}

// ===========================================================================
// Mismatch
// ===========================================================================

#[test]
fn mismatch_content_hash_deterministic() {
    let m1 = Mismatch {
        kind: MismatchKind::ContentDivergence,
        surface: CompileSurface::Library,
        artifact_kind: Some(ArtifactKind::CompiledOutput),
        detail: "test".into(),
        severity: DiagnosticSeverity::Error,
    };
    let m2 = m1.clone();
    assert_eq!(m1.content_hash(), m2.content_hash());
}

#[test]
fn mismatch_hash_varies_by_kind() {
    let m1 = Mismatch {
        kind: MismatchKind::ArtifactMissing,
        surface: CompileSurface::Library,
        artifact_kind: None,
        detail: "d".into(),
        severity: DiagnosticSeverity::Error,
    };
    let m2 = Mismatch {
        kind: MismatchKind::ArtifactExtra,
        ..m1.clone()
    };
    assert_ne!(m1.content_hash(), m2.content_hash());
}

#[test]
fn mismatch_display_includes_kind_and_surface() {
    let m = Mismatch {
        kind: MismatchKind::ArtifactMissing,
        surface: CompileSurface::CliShipped,
        artifact_kind: Some(ArtifactKind::SourceMap),
        detail: "gone".into(),
        severity: DiagnosticSeverity::Error,
    };
    let s = m.to_string();
    assert!(s.contains("artifact_missing"));
    assert!(s.contains("cli_shipped"));
}

#[test]
fn mismatch_serde_roundtrip() {
    let m = Mismatch {
        kind: MismatchKind::SizeDivergence,
        surface: CompileSurface::Library,
        artifact_kind: None,
        detail: "size off".into(),
        severity: DiagnosticSeverity::Info,
    };
    let json = serde_json::to_string(&m).unwrap();
    let back: Mismatch = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

// ===========================================================================
// VerificationError
// ===========================================================================

#[test]
fn error_same_surface_display() {
    let e = VerificationError::SameSurface {
        surface: CompileSurface::Library,
    };
    assert!(e.to_string().contains("same surface"));
}

#[test]
fn error_mode_mismatch_display() {
    let e = VerificationError::ModeMismatch {
        mode_a: CompileMode::Classic,
        mode_b: CompileMode::Automatic,
    };
    assert!(e.to_string().contains("mode mismatch"));
}

#[test]
fn error_serde_roundtrip() {
    let errors = vec![
        VerificationError::SameSurface {
            surface: CompileSurface::CliShipped,
        },
        VerificationError::ModeMismatch {
            mode_a: CompileMode::Classic,
            mode_b: CompileMode::Automatic,
        },
        VerificationError::TooManyArtifacts { count: 5, max: 3 },
        VerificationError::TooManyDiagnostics { count: 5, max: 3 },
        VerificationError::InvalidConfig {
            reason: "bad".into(),
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: VerificationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ===========================================================================
// Batch verification
// ===========================================================================

#[test]
fn batch_empty_scenarios_pass() {
    let r = verify_batch(&[], &default_config(), &epoch(), 0).unwrap();
    assert_eq!(r.overall_verdict, VerificationVerdict::Pass);
    assert_eq!(r.total_mismatches, 0);
    assert_eq!(r.pass_count(), 0);
    assert_eq!(r.pass_rate(), 0);
}

#[test]
fn batch_single_passing_scenario() {
    let arts = vec![make_artifact(ArtifactKind::CompiledOutput, b"code")];
    let scenario = VerificationScenario {
        name: "s1".into(),
        result_a: lib_result(arts.clone(), vec![]),
        result_b: cli_result(arts, vec![]),
    };
    let cfg = no_sourcemap_config();
    let r = verify_batch(&[scenario], &cfg, &epoch(), 0).unwrap();
    assert_eq!(r.overall_verdict, VerificationVerdict::Pass);
    assert_eq!(r.pass_count(), 1);
    assert_eq!(r.fail_count(), 0);
    assert_eq!(r.pass_rate(), 1_000_000);
}

#[test]
fn batch_single_failing_scenario() {
    let scenario = VerificationScenario {
        name: "fail".into(),
        result_a: lib_result(
            vec![make_artifact(ArtifactKind::CompiledOutput, b"a")],
            vec![],
        ),
        result_b: cli_result(vec![], vec![]),
    };
    let cfg = no_sourcemap_config();
    let r = verify_batch(&[scenario], &cfg, &epoch(), 0).unwrap();
    assert_eq!(r.overall_verdict, VerificationVerdict::Fail);
    assert_eq!(r.fail_count(), 1);
}

#[test]
fn batch_mixed_verdicts() {
    let s_pass = VerificationScenario {
        name: "pass".into(),
        result_a: lib_result(vec![], vec![]),
        result_b: cli_result(vec![], vec![]),
    };
    let s_fail = VerificationScenario {
        name: "fail".into(),
        result_a: lib_result(
            vec![make_artifact(ArtifactKind::CompiledOutput, b"x")],
            vec![],
        ),
        result_b: cli_result(vec![], vec![]),
    };
    let cfg = no_sourcemap_config();
    let r = verify_batch(&[s_pass, s_fail], &cfg, &epoch(), 0).unwrap();
    assert_eq!(r.overall_verdict, VerificationVerdict::Fail);
    assert_eq!(r.pass_count(), 1);
    assert_eq!(r.fail_count(), 1);
}

#[test]
fn batch_inconclusive_propagates() {
    let mut fail_a = lib_result(vec![], vec![]);
    fail_a.success = false;
    let scenario = VerificationScenario {
        name: "inc".into(),
        result_a: fail_a,
        result_b: cli_result(vec![], vec![]),
    };
    let cfg = no_sourcemap_config();
    let r = verify_batch(&[scenario], &cfg, &epoch(), 0).unwrap();
    assert_eq!(r.overall_verdict, VerificationVerdict::Inconclusive);
}

#[test]
fn batch_fail_overrides_inconclusive() {
    let mut fail_a = lib_result(vec![], vec![]);
    fail_a.success = false;
    let s_inc = VerificationScenario {
        name: "inc".into(),
        result_a: fail_a,
        result_b: cli_result(vec![], vec![]),
    };
    let s_fail = VerificationScenario {
        name: "fail".into(),
        result_a: lib_result(
            vec![make_artifact(ArtifactKind::CompiledOutput, b"x")],
            vec![],
        ),
        result_b: cli_result(vec![], vec![]),
    };
    let cfg = no_sourcemap_config();
    let r = verify_batch(&[s_inc, s_fail], &cfg, &epoch(), 0).unwrap();
    assert_eq!(r.overall_verdict, VerificationVerdict::Fail);
}

#[test]
fn batch_content_hash_deterministic() {
    let arts = vec![make_artifact(ArtifactKind::CompiledOutput, b"c")];
    let scenarios = vec![VerificationScenario {
        name: "s1".into(),
        result_a: lib_result(arts.clone(), vec![]),
        result_b: cli_result(arts, vec![]),
    }];
    let cfg = no_sourcemap_config();
    let r1 = verify_batch(&scenarios, &cfg, &epoch(), 0).unwrap();
    let r2 = verify_batch(&scenarios, &cfg, &epoch(), 0).unwrap();
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn batch_total_mismatches_accumulated() {
    let s1 = VerificationScenario {
        name: "s1".into(),
        result_a: lib_result(
            vec![make_artifact(ArtifactKind::CompiledOutput, b"a")],
            vec![],
        ),
        result_b: cli_result(
            vec![make_artifact(ArtifactKind::CompiledOutput, b"b")],
            vec![],
        ),
    };
    let s2 = VerificationScenario {
        name: "s2".into(),
        result_a: lib_result(
            vec![make_artifact(ArtifactKind::TypeDeclaration, b"x")],
            vec![],
        ),
        result_b: cli_result(
            vec![make_artifact(ArtifactKind::TypeDeclaration, b"y")],
            vec![],
        ),
    };
    let cfg = no_sourcemap_config();
    let r = verify_batch(&[s1, s2], &cfg, &epoch(), 0).unwrap();
    assert!(r.total_mismatches >= 2);
}

#[test]
fn batch_pass_rate_half() {
    let s_pass = VerificationScenario {
        name: "pass".into(),
        result_a: lib_result(vec![], vec![]),
        result_b: cli_result(vec![], vec![]),
    };
    let s_fail = VerificationScenario {
        name: "fail".into(),
        result_a: lib_result(
            vec![make_artifact(ArtifactKind::CompiledOutput, b"x")],
            vec![],
        ),
        result_b: cli_result(vec![], vec![]),
    };
    let cfg = no_sourcemap_config();
    let r = verify_batch(&[s_pass, s_fail], &cfg, &epoch(), 0).unwrap();
    assert_eq!(r.pass_rate(), 500_000); // 50%
}

#[test]
fn batch_schema_version_propagated() {
    let r = verify_batch(&[], &default_config(), &epoch(), 0).unwrap();
    assert_eq!(r.schema_version, SCHEMA_VERSION);
}

// ===========================================================================
// Classic mode end-to-end
// ===========================================================================

#[test]
fn classic_mode_parity_pass() {
    let arts = vec![make_artifact(ArtifactKind::CompiledOutput, b"classic")];
    let a = CompileResult {
        surface: CompileSurface::Library,
        mode: CompileMode::Classic,
        artifacts: arts.clone(),
        diagnostics: vec![],
        success: true,
        duration_micros: 100,
    };
    let b = CompileResult {
        surface: CompileSurface::CliShipped,
        mode: CompileMode::Classic,
        artifacts: arts,
        diagnostics: vec![],
        success: true,
        duration_micros: 200,
    };
    let cfg = no_sourcemap_config();
    let r = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
    assert_eq!(r.verdict, VerificationVerdict::Pass);
}

// ===========================================================================
// Multiple artifact types end-to-end
// ===========================================================================

#[test]
fn multiple_artifact_types_parity() {
    let arts = vec![
        make_artifact(ArtifactKind::CompiledOutput, b"js"),
        make_artifact(ArtifactKind::SourceMap, b"map"),
        make_artifact(ArtifactKind::TypeDeclaration, b"dts"),
        make_artifact(ArtifactKind::BundleManifest, b"manifest"),
    ];
    let a = lib_result(arts.clone(), vec![]);
    let b = cli_result(arts, vec![]);
    let r = verify_compile_parity(&a, &b, &default_config(), &epoch(), 0).unwrap();
    assert_eq!(r.verdict, VerificationVerdict::Pass);
    assert!(r.mismatches.is_empty());
}

#[test]
fn missing_type_declaration_fail() {
    let a = lib_result(
        vec![
            make_artifact(ArtifactKind::CompiledOutput, b"js"),
            make_artifact(ArtifactKind::TypeDeclaration, b"dts"),
        ],
        vec![],
    );
    let b = cli_result(
        vec![make_artifact(ArtifactKind::CompiledOutput, b"js")],
        vec![],
    );
    let cfg = no_sourcemap_config();
    let r = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
    assert_eq!(r.verdict, VerificationVerdict::Fail);
}
