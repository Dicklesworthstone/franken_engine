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

//! Enrichment integration tests for the `react_compile_verification` module.

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::react_compile_verification::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn make_artifact(kind: ArtifactKind, content: &[u8]) -> CompileArtifact {
    CompileArtifact::from_content(kind, content, "test-provenance")
}

fn make_diagnostic(msg: &str, severity: DiagnosticSeverity) -> CompileDiagnostic {
    CompileDiagnostic {
        message: msg.to_string(),
        severity,
        line: 1,
        column: 1,
        source_range: (0, 10),
    }
}

fn library_result(
    artifacts: Vec<CompileArtifact>,
    diagnostics: Vec<CompileDiagnostic>,
) -> CompileResult {
    CompileResult {
        surface: CompileSurface::Library,
        mode: CompileMode::Automatic,
        artifacts,
        diagnostics,
        success: true,
        duration_micros: 1000,
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
        duration_micros: 1200,
    }
}

fn default_config() -> VerificationConfig {
    VerificationConfig::default()
}

// ===========================================================================
// CompileMode Display uniqueness
// ===========================================================================

#[test]
fn enrichment_compile_mode_display_all_unique() {
    let displays: BTreeSet<String> = CompileMode::ALL.iter().map(|m| m.to_string()).collect();
    assert_eq!(displays.len(), 2);
}

// ===========================================================================
// ArtifactKind Display uniqueness
// ===========================================================================

#[test]
fn enrichment_artifact_kind_display_all_unique() {
    let displays: BTreeSet<String> = ArtifactKind::ALL.iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), 5);
}

// ===========================================================================
// DiagnosticSeverity Display uniqueness
// ===========================================================================

#[test]
fn enrichment_diagnostic_severity_display_all_unique() {
    let displays: BTreeSet<String> = DiagnosticSeverity::ALL.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

// ===========================================================================
// CompileSurface Display uniqueness
// ===========================================================================

#[test]
fn enrichment_compile_surface_display_all_unique() {
    let displays: BTreeSet<String> = CompileSurface::ALL.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), 2);
}

// ===========================================================================
// MismatchKind Display uniqueness
// ===========================================================================

#[test]
fn enrichment_mismatch_kind_display_all_unique() {
    let displays: BTreeSet<String> = MismatchKind::ALL.iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), 6);
}

// ===========================================================================
// VerificationVerdict Display uniqueness
// ===========================================================================

#[test]
fn enrichment_verdict_display_all_unique() {
    let displays: BTreeSet<String> = VerificationVerdict::ALL.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), 3);
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_schema_constants() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert_eq!(COMPONENT, "react_compile_verification");
    assert!(BEAD_ID.starts_with("bd-"));
    assert!(POLICY_ID.starts_with("RGC-"));
}

// ===========================================================================
// DiagnosticSeverity weights ascending
// ===========================================================================

#[test]
fn enrichment_diagnostic_severity_weights_ascending() {
    let weights: Vec<u64> = DiagnosticSeverity::ALL.iter().map(|s| s.weight()).collect();
    for w in weights.windows(2) {
        assert!(w[0] < w[1]);
    }
}

// ===========================================================================
// CompileDiagnostic content hash, display
// ===========================================================================

#[test]
fn enrichment_diagnostic_content_hash_and_display() {
    let d1 = make_diagnostic("test msg", DiagnosticSeverity::Warning);
    let d2 = make_diagnostic("test msg", DiagnosticSeverity::Warning);
    assert_eq!(d1.content_hash(), d2.content_hash());

    let d3 = make_diagnostic("test", DiagnosticSeverity::Error);
    assert_ne!(d1.content_hash(), d3.content_hash());

    let s = d3.to_string();
    assert!(s.contains("error"));
    assert!(s.contains("test"));
}

// ===========================================================================
// CompileArtifact from_content
// ===========================================================================

#[test]
fn enrichment_artifact_from_content_size_matches() {
    let data = b"compiled JS output";
    let a = CompileArtifact::from_content(ArtifactKind::CompiledOutput, data, "src/app.js");
    assert_eq!(a.size_bytes, data.len() as u64);
    assert_eq!(a.kind, ArtifactKind::CompiledOutput);
    assert_eq!(a.provenance, "src/app.js");
}

#[test]
fn enrichment_artifact_from_content_hash_deterministic() {
    let a1 = CompileArtifact::from_content(ArtifactKind::SourceMap, b"map data", "test");
    let a2 = CompileArtifact::from_content(ArtifactKind::SourceMap, b"map data", "test");
    assert_eq!(a1.content_hash, a2.content_hash);
}

// ===========================================================================
// CompileResult methods
// ===========================================================================

#[test]
fn enrichment_result_artifacts_by_kind() {
    let r = library_result(
        vec![
            make_artifact(ArtifactKind::CompiledOutput, b"js1"),
            make_artifact(ArtifactKind::SourceMap, b"map"),
            make_artifact(ArtifactKind::CompiledOutput, b"js2"),
        ],
        vec![],
    );
    assert_eq!(r.artifacts_by_kind(ArtifactKind::CompiledOutput).len(), 2);
    assert_eq!(r.artifacts_by_kind(ArtifactKind::SourceMap).len(), 1);
    assert_eq!(r.artifacts_by_kind(ArtifactKind::BundleManifest).len(), 0);
}

#[test]
fn enrichment_result_has_source_map() {
    let with = library_result(vec![make_artifact(ArtifactKind::SourceMap, b"m")], vec![]);
    assert!(with.has_source_map());
    let without = library_result(vec![], vec![]);
    assert!(!without.has_source_map());
}

#[test]
fn enrichment_result_diagnostic_count_by_severity() {
    let r = library_result(
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
fn enrichment_result_total_artifact_size() {
    let r = library_result(
        vec![
            make_artifact(ArtifactKind::CompiledOutput, b"abc"),
            make_artifact(ArtifactKind::SourceMap, b"de"),
        ],
        vec![],
    );
    assert_eq!(r.total_artifact_size(), 5);
}

// ===========================================================================
// VerificationConfig
// ===========================================================================

#[test]
fn enrichment_config_strict_vs_permissive() {
    let strict = VerificationConfig::strict();
    let permissive = VerificationConfig::permissive();
    assert!(strict.max_size_divergence_millionths < permissive.max_size_divergence_millionths);
    assert!(strict.require_source_maps);
    assert!(!permissive.require_source_maps);
}

#[test]
fn enrichment_config_serde_roundtrip() {
    let configs = vec![
        VerificationConfig::default(),
        VerificationConfig::strict(),
        VerificationConfig::permissive(),
    ];
    for c in &configs {
        let json = serde_json::to_string(c).unwrap();
        let back: VerificationConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

// ===========================================================================
// classify_mismatch_severity
// ===========================================================================

#[test]
fn enrichment_classify_mismatch_severity_all_kinds() {
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
// verify_compile_parity: same surface error
// ===========================================================================

#[test]
fn enrichment_parity_same_surface_error() {
    let a = library_result(vec![], vec![]);
    let b = library_result(vec![], vec![]);
    let err = verify_compile_parity(&a, &b, &default_config(), &epoch(), 0).unwrap_err();
    assert!(matches!(err, VerificationError::SameSurface { .. }));
}

// ===========================================================================
// verify_compile_parity: mode mismatch error
// ===========================================================================

#[test]
fn enrichment_parity_mode_mismatch_error() {
    let a = library_result(vec![], vec![]);
    let mut b = cli_result(vec![], vec![]);
    b.mode = CompileMode::Classic;
    let err = verify_compile_parity(&a, &b, &default_config(), &epoch(), 0).unwrap_err();
    assert!(matches!(err, VerificationError::ModeMismatch { .. }));
}

// ===========================================================================
// verify_compile_parity: inconclusive when one side fails
// ===========================================================================

#[test]
fn enrichment_parity_inconclusive_on_failure() {
    let a = library_result(vec![], vec![]);
    let mut b = cli_result(vec![], vec![]);
    b.success = false;
    let report = verify_compile_parity(&a, &b, &default_config(), &epoch(), 0).unwrap();
    assert_eq!(report.verdict, VerificationVerdict::Inconclusive);
}

// ===========================================================================
// verify_compile_parity: identical artifacts pass
// ===========================================================================

#[test]
fn enrichment_parity_identical_pass() {
    let arts = vec![
        make_artifact(ArtifactKind::CompiledOutput, b"code"),
        make_artifact(ArtifactKind::SourceMap, b"map"),
    ];
    let a = library_result(arts.clone(), vec![]);
    let b = cli_result(arts, vec![]);
    let report = verify_compile_parity(&a, &b, &default_config(), &epoch(), 100).unwrap();
    assert_eq!(report.verdict, VerificationVerdict::Pass);
    assert!(report.mismatches.is_empty());
}

// ===========================================================================
// verify_compile_parity: missing artifact triggers fail
// ===========================================================================

#[test]
fn enrichment_parity_missing_artifact_fails() {
    let a = library_result(
        vec![make_artifact(ArtifactKind::CompiledOutput, b"code")],
        vec![],
    );
    let b = cli_result(vec![], vec![]);
    let cfg = VerificationConfig {
        require_source_maps: false,
        ..default_config()
    };
    let report = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
    assert_eq!(report.verdict, VerificationVerdict::Fail);
    assert!(report.mismatches.iter().any(|m| m.kind == MismatchKind::ArtifactMissing));
}

// ===========================================================================
// verify_compile_parity: content divergence
// ===========================================================================

#[test]
fn enrichment_parity_content_divergence_fail() {
    let a = library_result(
        vec![make_artifact(ArtifactKind::CompiledOutput, b"code_a")],
        vec![],
    );
    let b = cli_result(
        vec![make_artifact(ArtifactKind::CompiledOutput, b"code_b")],
        vec![],
    );
    let cfg = VerificationConfig {
        require_source_maps: false,
        ..default_config()
    };
    let report = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
    assert_eq!(report.verdict, VerificationVerdict::Fail);
    assert!(report.has_errors());
}

// ===========================================================================
// VerificationReport: weighted_score > 0 when mismatches exist
// ===========================================================================

#[test]
fn enrichment_report_weighted_score_positive_with_mismatches() {
    let a = library_result(
        vec![make_artifact(ArtifactKind::CompiledOutput, b"a")],
        vec![],
    );
    let b = cli_result(
        vec![make_artifact(ArtifactKind::CompiledOutput, b"b")],
        vec![],
    );
    let cfg = VerificationConfig {
        require_source_maps: false,
        ..default_config()
    };
    let report = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
    assert!(report.weighted_score() > 0);
}

// ===========================================================================
// VerificationReport: content hash deterministic
// ===========================================================================

#[test]
fn enrichment_report_content_hash_deterministic() {
    let arts = vec![make_artifact(ArtifactKind::CompiledOutput, b"code")];
    let a = library_result(arts.clone(), vec![]);
    let b = cli_result(arts, vec![]);
    let r1 = verify_compile_parity(&a, &b, &default_config(), &epoch(), 0).unwrap();
    let r2 = verify_compile_parity(&a, &b, &default_config(), &epoch(), 0).unwrap();
    assert_eq!(r1.content_hash(), r2.content_hash());
}

// ===========================================================================
// DecisionReceipt: fields populated correctly
// ===========================================================================

#[test]
fn enrichment_receipt_fields_correct() {
    let receipt = compute_receipt(
        ContentHash::compute(b"input"),
        &VerificationVerdict::Pass,
        &epoch(),
        42_000,
    );
    assert_eq!(receipt.schema_version, SCHEMA_VERSION);
    assert_eq!(receipt.component, COMPONENT);
    assert_eq!(receipt.bead_id, BEAD_ID);
    assert_eq!(receipt.policy_id, POLICY_ID);
    assert_eq!(receipt.epoch.as_u64(), 42);
    assert_eq!(receipt.timestamp_micros, 42_000);
}

#[test]
fn enrichment_receipt_serde_roundtrip() {
    let receipt = compute_receipt(
        ContentHash::compute(b"test"),
        &VerificationVerdict::Fail,
        &epoch(),
        999,
    );
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

// ===========================================================================
// Mismatch Display
// ===========================================================================

#[test]
fn enrichment_mismatch_display_contains_kind_and_surface() {
    let m = Mismatch {
        kind: MismatchKind::ArtifactMissing,
        surface: CompileSurface::CliShipped,
        artifact_kind: Some(ArtifactKind::SourceMap),
        detail: "missing source map".into(),
        severity: DiagnosticSeverity::Error,
    };
    let s = m.to_string();
    assert!(s.contains("error"));
    assert!(s.contains("artifact_missing"));
    assert!(s.contains("cli_shipped"));
}

// ===========================================================================
// Mismatch content hash deterministic
// ===========================================================================

#[test]
fn enrichment_mismatch_content_hash_deterministic() {
    let m = Mismatch {
        kind: MismatchKind::ContentDivergence,
        surface: CompileSurface::Library,
        artifact_kind: Some(ArtifactKind::CompiledOutput),
        detail: "differs".into(),
        severity: DiagnosticSeverity::Error,
    };
    assert_eq!(m.content_hash(), m.clone().content_hash());
}

// ===========================================================================
// Batch verification
// ===========================================================================

#[test]
fn enrichment_batch_empty_pass() {
    let report = verify_batch(&[], &default_config(), &epoch(), 0).unwrap();
    assert_eq!(report.overall_verdict, VerificationVerdict::Pass);
    assert_eq!(report.total_mismatches, 0);
    assert_eq!(report.pass_rate(), 0); // 0/0
}

#[test]
fn enrichment_batch_single_pass_rate_million() {
    let arts = vec![make_artifact(ArtifactKind::CompiledOutput, b"code")];
    let scenario = VerificationScenario {
        name: "s1".into(),
        result_a: library_result(arts.clone(), vec![]),
        result_b: cli_result(arts, vec![]),
    };
    let cfg = VerificationConfig {
        require_source_maps: false,
        ..default_config()
    };
    let report = verify_batch(&[scenario], &cfg, &epoch(), 0).unwrap();
    assert_eq!(report.pass_rate(), 1_000_000);
    assert_eq!(report.pass_count(), 1);
    assert_eq!(report.fail_count(), 0);
}

#[test]
fn enrichment_batch_mixed_verdict_is_fail() {
    let s_pass = VerificationScenario {
        name: "pass".into(),
        result_a: library_result(vec![], vec![]),
        result_b: cli_result(vec![], vec![]),
    };
    let s_fail = VerificationScenario {
        name: "fail".into(),
        result_a: library_result(
            vec![make_artifact(ArtifactKind::CompiledOutput, b"x")],
            vec![],
        ),
        result_b: cli_result(vec![], vec![]),
    };
    let cfg = VerificationConfig {
        require_source_maps: false,
        ..default_config()
    };
    let report = verify_batch(&[s_pass, s_fail], &cfg, &epoch(), 0).unwrap();
    assert_eq!(report.overall_verdict, VerificationVerdict::Fail);
    assert_eq!(report.pass_count(), 1);
    assert_eq!(report.fail_count(), 1);
}

// ===========================================================================
// VerificationError serde roundtrip
// ===========================================================================

#[test]
fn enrichment_verification_error_serde_roundtrip() {
    let errors = vec![
        VerificationError::SameSurface {
            surface: CompileSurface::Library,
        },
        VerificationError::ModeMismatch {
            mode_a: CompileMode::Classic,
            mode_b: CompileMode::Automatic,
        },
        VerificationError::TooManyArtifacts { count: 5, max: 3 },
        VerificationError::TooManyDiagnostics { count: 5, max: 3 },
        VerificationError::InvalidConfig {
            reason: "test".into(),
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: VerificationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ===========================================================================
// VerificationError Display uniqueness
// ===========================================================================

#[test]
fn enrichment_verification_error_display_all_unique() {
    let errors = vec![
        VerificationError::SameSurface {
            surface: CompileSurface::Library,
        },
        VerificationError::ModeMismatch {
            mode_a: CompileMode::Classic,
            mode_b: CompileMode::Automatic,
        },
        VerificationError::TooManyArtifacts { count: 5, max: 3 },
        VerificationError::TooManyDiagnostics { count: 5, max: 3 },
        VerificationError::InvalidConfig {
            reason: "test".into(),
        },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), 5);
}

// ===========================================================================
// Determinism: same inputs produce same report hash
// ===========================================================================

#[test]
fn enrichment_deterministic_report_hash() {
    let run = || {
        let arts = vec![make_artifact(ArtifactKind::CompiledOutput, b"code")];
        let a = library_result(arts.clone(), vec![]);
        let b = cli_result(arts, vec![]);
        verify_compile_parity(&a, &b, &default_config(), &epoch(), 0)
            .unwrap()
            .content_hash()
    };
    let h1 = run();
    let h2 = run();
    assert_eq!(h1, h2);
}
