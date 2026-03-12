//! Integration tests for `react_ssr_verification` module.
//!
//! Validates the public API for differential verification of React SSR and
//! client-entry execution paths. Covers enum exhaustiveness, serde contracts,
//! determinism, mismatch detection, verdict logic, receipt chaining, batch
//! operations, config validation, and edge cases.

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
use frankenengine_engine::react_ssr_verification::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(99)
}

fn make_evidence(
    path_id: &str,
    kind: ExecutionPathKind,
    mode: VerificationMode,
    content: &[u8],
) -> PathEvidence {
    PathEvidence {
        path_id: path_id.to_string(),
        execution_kind: kind,
        mode,
        hash: ContentHash::compute(content),
        epoch: epoch(),
        duration_micros: 500,
        output_size_bytes: content.len() as u64,
    }
}

fn ssr_ev(id: &str, content: &[u8]) -> PathEvidence {
    make_evidence(
        id,
        ExecutionPathKind::Ssr,
        VerificationMode::FullDifferential,
        content,
    )
}

fn client_ev(id: &str, content: &[u8]) -> PathEvidence {
    make_evidence(
        id,
        ExecutionPathKind::ClientEntry,
        VerificationMode::FullDifferential,
        content,
    )
}

fn hydration_ev(id: &str, content: &[u8]) -> PathEvidence {
    make_evidence(
        id,
        ExecutionPathKind::Hydration,
        VerificationMode::FullDifferential,
        content,
    )
}

fn streaming_ev(id: &str, content: &[u8]) -> PathEvidence {
    make_evidence(
        id,
        ExecutionPathKind::StreamingSsr,
        VerificationMode::FullDifferential,
        content,
    )
}

fn static_gen_ev(id: &str, content: &[u8]) -> PathEvidence {
    make_evidence(
        id,
        ExecutionPathKind::StaticGeneration,
        VerificationMode::FullDifferential,
        content,
    )
}

fn make_mismatch(kind: MismatchKind) -> MismatchRecord {
    MismatchRecord {
        kind,
        severity: classify_severity(kind),
        detail: format!("integration test mismatch: {}", kind),
        reference_hash: ContentHash::compute(b"integration-ref"),
        candidate_hash: ContentHash::compute(b"integration-cand"),
    }
}

fn default_config() -> VerificationConfig {
    VerificationConfig::default()
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn schema_version_starts_with_prefix() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn schema_version_contains_module_name() {
    assert!(SCHEMA_VERSION.contains("react-ssr-verification"));
}

#[test]
fn component_non_empty() {
    assert!(!COMPONENT.is_empty());
    assert_eq!(COMPONENT, "react_ssr_verification");
}

#[test]
fn bead_id_correct() {
    assert_eq!(BEAD_ID, "bd-1lsy.9.7.2");
}

#[test]
fn policy_id_correct() {
    assert_eq!(POLICY_ID, "RGC-807B");
}

#[test]
fn default_max_divergence_is_reasonable() {
    const {
        assert!(DEFAULT_MAX_DIVERGENCE > 0);
        assert!(DEFAULT_MAX_DIVERGENCE <= 1_000_000);
    }
}

#[test]
fn default_min_paths_at_least_one() {
    const {
        assert!(DEFAULT_MIN_PATHS >= 1);
    }
}

// ===========================================================================
// ExecutionPathKind
// ===========================================================================

#[test]
fn execution_path_kind_exhaustive() {
    assert_eq!(ExecutionPathKind::ALL.len(), 5);
    let mut seen = std::collections::BTreeSet::new();
    for k in ExecutionPathKind::ALL {
        assert!(seen.insert(k.as_str()), "duplicate: {}", k);
    }
}

#[test]
fn execution_path_kind_serde_all() {
    for kind in ExecutionPathKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: ExecutionPathKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

#[test]
fn execution_path_kind_display_matches_as_str() {
    for kind in ExecutionPathKind::ALL {
        assert_eq!(kind.to_string(), kind.as_str());
    }
}

#[test]
fn execution_path_kind_ssr_display() {
    assert_eq!(ExecutionPathKind::Ssr.to_string(), "ssr");
}

#[test]
fn execution_path_kind_streaming_ssr_display() {
    assert_eq!(ExecutionPathKind::StreamingSsr.to_string(), "streaming_ssr");
}

// ===========================================================================
// VerificationMode
// ===========================================================================

#[test]
fn verification_mode_exhaustive() {
    assert_eq!(VerificationMode::ALL.len(), 4);
}

#[test]
fn verification_mode_serde_all() {
    for mode in VerificationMode::ALL {
        let json = serde_json::to_string(mode).unwrap();
        let back: VerificationMode = serde_json::from_str(&json).unwrap();
        assert_eq!(*mode, back);
    }
}

#[test]
fn verification_mode_content_level_classification() {
    assert!(VerificationMode::FullDifferential.is_content_level());
    assert!(VerificationMode::SampledDifferential.is_content_level());
    assert!(!VerificationMode::SnapshotComparison.is_content_level());
    assert!(!VerificationMode::HashEquivalence.is_content_level());
}

#[test]
fn verification_mode_display() {
    assert_eq!(
        VerificationMode::FullDifferential.to_string(),
        "full_differential"
    );
}

// ===========================================================================
// MismatchKind
// ===========================================================================

#[test]
fn mismatch_kind_exhaustive() {
    assert_eq!(MismatchKind::ALL.len(), 6);
}

#[test]
fn mismatch_kind_serde_all() {
    for kind in MismatchKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: MismatchKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

#[test]
fn mismatch_kind_weights_bounded() {
    for kind in MismatchKind::ALL {
        assert!(kind.weight() > 0, "{} has zero weight", kind);
        assert!(kind.weight() <= 1_000_000, "{} weight exceeds 1.0", kind);
    }
}

#[test]
fn mismatch_kind_output_mismatch_has_max_weight() {
    assert_eq!(MismatchKind::OutputMismatch.weight(), 1_000_000);
}

#[test]
fn mismatch_kind_display_matches_as_str() {
    for kind in MismatchKind::ALL {
        assert_eq!(kind.to_string(), kind.as_str());
    }
}

// ===========================================================================
// MismatchSeverity
// ===========================================================================

#[test]
fn mismatch_severity_exhaustive() {
    assert_eq!(MismatchSeverity::ALL.len(), 4);
}

#[test]
fn mismatch_severity_weights_strictly_increasing() {
    let weights: Vec<u64> = MismatchSeverity::ALL.iter().map(|s| s.weight()).collect();
    for pair in weights.windows(2) {
        assert!(pair[0] < pair[1]);
    }
}

#[test]
fn mismatch_severity_critical_is_one() {
    assert_eq!(MismatchSeverity::Critical.weight(), 1_000_000);
}

#[test]
fn mismatch_severity_serde_all() {
    for sev in MismatchSeverity::ALL {
        let json = serde_json::to_string(sev).unwrap();
        let back: MismatchSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(*sev, back);
    }
}

// ===========================================================================
// classify_severity
// ===========================================================================

#[test]
fn classify_severity_all_kinds_return_valid() {
    for kind in MismatchKind::ALL {
        let sev = classify_severity(*kind);
        assert!(MismatchSeverity::ALL.contains(&sev));
    }
}

#[test]
fn classify_severity_output_critical() {
    assert_eq!(
        classify_severity(MismatchKind::OutputMismatch),
        MismatchSeverity::Critical
    );
}

#[test]
fn classify_severity_hydration_critical() {
    assert_eq!(
        classify_severity(MismatchKind::HydrationMismatch),
        MismatchSeverity::Critical
    );
}

#[test]
fn classify_severity_timing_info() {
    assert_eq!(
        classify_severity(MismatchKind::TimingAnomaly),
        MismatchSeverity::Info
    );
}

#[test]
fn classify_severity_event_order_warning() {
    assert_eq!(
        classify_severity(MismatchKind::EventOrderViolation),
        MismatchSeverity::Warning
    );
}

#[test]
fn classify_severity_state_incoherence_error() {
    assert_eq!(
        classify_severity(MismatchKind::StateIncoherence),
        MismatchSeverity::Error
    );
}

#[test]
fn classify_severity_stream_chunk_error() {
    assert_eq!(
        classify_severity(MismatchKind::StreamChunkDivergence),
        MismatchSeverity::Error
    );
}

// ===========================================================================
// MismatchRecord
// ===========================================================================

#[test]
fn mismatch_record_hash_deterministic() {
    let a = make_mismatch(MismatchKind::OutputMismatch);
    let b = make_mismatch(MismatchKind::OutputMismatch);
    assert_eq!(a.content_hash(), b.content_hash());
}

#[test]
fn mismatch_record_different_kinds_different_hashes() {
    let a = make_mismatch(MismatchKind::OutputMismatch);
    let b = make_mismatch(MismatchKind::TimingAnomaly);
    assert_ne!(a.content_hash(), b.content_hash());
}

#[test]
fn mismatch_record_display_includes_kind() {
    let m = make_mismatch(MismatchKind::StateIncoherence);
    assert!(m.to_string().contains("state_incoherence"));
}

#[test]
fn mismatch_record_serde_roundtrip() {
    let m = make_mismatch(MismatchKind::HydrationMismatch);
    let json = serde_json::to_string(&m).unwrap();
    let back: MismatchRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

// ===========================================================================
// PathEvidence
// ===========================================================================

#[test]
fn path_evidence_hash_deterministic() {
    let a = ssr_ev("p1", b"content");
    let b = ssr_ev("p1", b"content");
    assert_eq!(a.content_hash(), b.content_hash());
}

#[test]
fn path_evidence_different_id_different_hash() {
    let a = ssr_ev("p1", b"content");
    let b = ssr_ev("p2", b"content");
    assert_ne!(a.content_hash(), b.content_hash());
}

#[test]
fn path_evidence_different_content_different_hash() {
    let a = ssr_ev("p1", b"hello");
    let b = ssr_ev("p1", b"world");
    assert_ne!(a.content_hash(), b.content_hash());
}

#[test]
fn path_evidence_display_contains_id() {
    let e = ssr_ev("test-path", b"data");
    assert!(e.to_string().contains("test-path"));
}

#[test]
fn path_evidence_display_contains_kind() {
    let e = ssr_ev("p1", b"data");
    assert!(e.to_string().contains("ssr"));
}

#[test]
fn path_evidence_serde_roundtrip() {
    let e = ssr_ev("p1", b"payload");
    let json = serde_json::to_string(&e).unwrap();
    let back: PathEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ===========================================================================
// DifferentialPair
// ===========================================================================

#[test]
fn pair_new_has_empty_mismatches() {
    let pair = DifferentialPair::new(ssr_ev("r", b"a"), ssr_ev("c", b"a"));
    assert!(pair.mismatches.is_empty());
}

#[test]
fn pair_with_mismatches_has_correct_count() {
    let pair = DifferentialPair::with_mismatches(
        ssr_ev("r", b"a"),
        ssr_ev("c", b"b"),
        vec![
            make_mismatch(MismatchKind::OutputMismatch),
            make_mismatch(MismatchKind::TimingAnomaly),
        ],
    );
    assert_eq!(pair.mismatches.len(), 2);
}

#[test]
fn pair_kinds_match_same_kind() {
    let pair = DifferentialPair::new(ssr_ev("r", b"a"), ssr_ev("c", b"a"));
    assert!(pair.kinds_match());
}

#[test]
fn pair_kinds_mismatch_different_kind() {
    let pair = DifferentialPair::new(ssr_ev("r", b"a"), client_ev("c", b"a"));
    assert!(!pair.kinds_match());
}

#[test]
fn pair_modes_match_same_mode() {
    let pair = DifferentialPair::new(ssr_ev("r", b"a"), ssr_ev("c", b"a"));
    assert!(pair.modes_match());
}

#[test]
fn pair_modes_mismatch_different_mode() {
    let ref_ev = make_evidence(
        "r",
        ExecutionPathKind::Ssr,
        VerificationMode::FullDifferential,
        b"a",
    );
    let cand_ev = make_evidence(
        "c",
        ExecutionPathKind::Ssr,
        VerificationMode::HashEquivalence,
        b"a",
    );
    let pair = DifferentialPair::new(ref_ev, cand_ev);
    assert!(!pair.modes_match());
}

#[test]
fn pair_content_hash_deterministic() {
    let p1 = DifferentialPair::new(ssr_ev("r", b"x"), ssr_ev("c", b"y"));
    let p2 = DifferentialPair::new(ssr_ev("r", b"x"), ssr_ev("c", b"y"));
    assert_eq!(p1.content_hash(), p2.content_hash());
}

#[test]
fn pair_content_hash_varies_with_mismatches() {
    let p1 = DifferentialPair::new(ssr_ev("r", b"a"), ssr_ev("c", b"a"));
    let p2 = DifferentialPair::with_mismatches(
        ssr_ev("r", b"a"),
        ssr_ev("c", b"a"),
        vec![make_mismatch(MismatchKind::OutputMismatch)],
    );
    assert_ne!(p1.content_hash(), p2.content_hash());
}

// ===========================================================================
// VerificationConfig
// ===========================================================================

#[test]
fn config_default_passes_validation() {
    assert!(validate_config(&VerificationConfig::default()).is_ok());
}

#[test]
fn config_strict_passes_validation() {
    assert!(validate_config(&VerificationConfig::strict()).is_ok());
}

#[test]
fn config_permissive_passes_validation() {
    assert!(validate_config(&VerificationConfig::permissive()).is_ok());
}

#[test]
fn config_serde_roundtrip() {
    let c = default_config();
    let json = serde_json::to_string(&c).unwrap();
    let back: VerificationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn config_strict_has_zero_divergence() {
    let c = VerificationConfig::strict();
    assert_eq!(c.max_divergence_millionths, 0);
}

#[test]
fn config_permissive_has_high_divergence() {
    let c = VerificationConfig::permissive();
    assert!(c.max_divergence_millionths >= 200_000);
}

// ===========================================================================
// validate_config
// ===========================================================================

#[test]
fn validate_config_zero_min_paths_rejected() {
    let mut c = default_config();
    c.min_paths = 0;
    let err = validate_config(&c).unwrap_err();
    assert!(matches!(err, VerificationError::InvalidConfig { .. }));
}

#[test]
fn validate_config_divergence_over_million_rejected() {
    let mut c = default_config();
    c.max_divergence_millionths = 1_000_001;
    assert!(validate_config(&c).is_err());
}

#[test]
fn validate_config_timing_over_million_rejected() {
    let mut c = default_config();
    c.max_timing_divergence_millionths = 1_000_001;
    assert!(validate_config(&c).is_err());
}

#[test]
fn validate_config_boundary_million_accepted() {
    let mut c = default_config();
    c.max_divergence_millionths = 1_000_000;
    c.max_timing_divergence_millionths = 1_000_000;
    assert!(validate_config(&c).is_ok());
}

#[test]
fn validate_config_min_paths_one_accepted() {
    let mut c = default_config();
    c.min_paths = 1;
    assert!(validate_config(&c).is_ok());
}

// ===========================================================================
// PathVerdict
// ===========================================================================

#[test]
fn path_verdict_exhaustive() {
    assert_eq!(PathVerdict::ALL.len(), 3);
}

#[test]
fn path_verdict_serde_all() {
    for v in PathVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: PathVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn path_verdict_is_verified_correct() {
    assert!(PathVerdict::Verified.is_verified());
    assert!(!PathVerdict::Divergent.is_verified());
    assert!(!PathVerdict::Inconclusive.is_verified());
}

#[test]
fn path_verdict_is_divergent_correct() {
    assert!(!PathVerdict::Verified.is_divergent());
    assert!(PathVerdict::Divergent.is_divergent());
    assert!(!PathVerdict::Inconclusive.is_divergent());
}

#[test]
fn path_verdict_display_all() {
    for v in PathVerdict::ALL {
        assert_eq!(v.to_string(), v.as_str());
    }
}

// ===========================================================================
// compute_divergence_score
// ===========================================================================

#[test]
fn divergence_score_empty_is_zero() {
    assert_eq!(compute_divergence_score(&[]), 0);
}

#[test]
fn divergence_score_single_timing() {
    let score = compute_divergence_score(&[make_mismatch(MismatchKind::TimingAnomaly)]);
    assert_eq!(score, MismatchKind::TimingAnomaly.weight());
}

#[test]
fn divergence_score_additive_two() {
    let m = vec![
        make_mismatch(MismatchKind::TimingAnomaly),
        make_mismatch(MismatchKind::EventOrderViolation),
    ];
    let expected =
        MismatchKind::TimingAnomaly.weight() + MismatchKind::EventOrderViolation.weight();
    assert_eq!(compute_divergence_score(&m), expected);
}

#[test]
fn divergence_score_capped_at_million() {
    let many: Vec<MismatchRecord> = (0..20)
        .map(|_| make_mismatch(MismatchKind::OutputMismatch))
        .collect();
    assert_eq!(compute_divergence_score(&many), 1_000_000);
}

#[test]
fn divergence_score_all_kinds_combined() {
    let all: Vec<MismatchRecord> = MismatchKind::ALL
        .iter()
        .map(|k| make_mismatch(*k))
        .collect();
    let raw_sum: u64 = MismatchKind::ALL.iter().map(|k| k.weight()).sum();
    let expected = raw_sum.min(1_000_000);
    assert_eq!(compute_divergence_score(&all), expected);
}

// ===========================================================================
// verify_path_pair
// ===========================================================================

#[test]
fn verify_pair_no_mismatches_verified() {
    let pair = DifferentialPair::new(ssr_ev("r", b"same"), ssr_ev("c", b"same"));
    let result = verify_path_pair(&pair, &default_config()).unwrap();
    assert_eq!(result.verdict, PathVerdict::Verified);
    assert!(result.divergence_report.is_none());
}

#[test]
fn verify_pair_output_mismatch_divergent() {
    let pair = DifferentialPair::with_mismatches(
        ssr_ev("r", b"a"),
        ssr_ev("c", b"b"),
        vec![make_mismatch(MismatchKind::OutputMismatch)],
    );
    let result = verify_path_pair(&pair, &default_config()).unwrap();
    assert_eq!(result.verdict, PathVerdict::Divergent);
    assert!(result.divergence_report.is_some());
}

#[test]
fn verify_pair_kind_mismatch_error() {
    let pair = DifferentialPair::new(ssr_ev("r", b"a"), client_ev("c", b"a"));
    let err = verify_path_pair(&pair, &default_config()).unwrap_err();
    assert!(matches!(err, VerificationError::PathKindMismatch { .. }));
}

#[test]
fn verify_pair_mode_mismatch_error() {
    let r = make_evidence(
        "r",
        ExecutionPathKind::Ssr,
        VerificationMode::FullDifferential,
        b"a",
    );
    let c = make_evidence(
        "c",
        ExecutionPathKind::Ssr,
        VerificationMode::HashEquivalence,
        b"a",
    );
    let pair = DifferentialPair::new(r, c);
    let err = verify_path_pair(&pair, &default_config()).unwrap_err();
    assert!(matches!(err, VerificationError::ModeMismatch { .. }));
}

#[test]
fn verify_pair_hydration_critical_forces_divergent() {
    let pair = DifferentialPair::with_mismatches(
        hydration_ev("r", b"a"),
        hydration_ev("c", b"b"),
        vec![make_mismatch(MismatchKind::HydrationMismatch)],
    );
    let config = VerificationConfig {
        require_hydration_check: true,
        max_divergence_millionths: 1_000_000,
        ..default_config()
    };
    let result = verify_path_pair(&pair, &config).unwrap();
    assert_eq!(result.verdict, PathVerdict::Divergent);
}

#[test]
fn verify_pair_hydration_not_required_allows_pass() {
    let pair = DifferentialPair::with_mismatches(
        hydration_ev("r", b"a"),
        hydration_ev("c", b"b"),
        vec![make_mismatch(MismatchKind::TimingAnomaly)],
    );
    let config = VerificationConfig {
        require_hydration_check: false,
        fail_on_timing_anomaly: false,
        max_divergence_millionths: 1_000_000,
        ..default_config()
    };
    let result = verify_path_pair(&pair, &config).unwrap();
    assert_eq!(result.verdict, PathVerdict::Verified);
}

#[test]
fn verify_pair_timing_fail_on_timing_true() {
    let pair = DifferentialPair::with_mismatches(
        ssr_ev("r", b"a"),
        ssr_ev("c", b"a"),
        vec![make_mismatch(MismatchKind::TimingAnomaly)],
    );
    let config = VerificationConfig {
        fail_on_timing_anomaly: true,
        ..default_config()
    };
    let result = verify_path_pair(&pair, &config).unwrap();
    assert_eq!(result.verdict, PathVerdict::Divergent);
}

#[test]
fn verify_pair_timing_fail_on_timing_false() {
    let pair = DifferentialPair::with_mismatches(
        ssr_ev("r", b"a"),
        ssr_ev("c", b"a"),
        vec![make_mismatch(MismatchKind::TimingAnomaly)],
    );
    let config = VerificationConfig {
        fail_on_timing_anomaly: false,
        max_divergence_millionths: 1_000_000,
        ..default_config()
    };
    let result = verify_path_pair(&pair, &config).unwrap();
    assert_eq!(result.verdict, PathVerdict::Verified);
}

#[test]
fn verify_pair_receipt_metadata_correct() {
    let pair = DifferentialPair::new(ssr_ev("r", b"x"), ssr_ev("c", b"x"));
    let result = verify_path_pair(&pair, &default_config()).unwrap();
    assert_eq!(result.receipt.schema_version, SCHEMA_VERSION);
    assert_eq!(result.receipt.component, COMPONENT);
    assert_eq!(result.receipt.bead_id, BEAD_ID);
    assert_eq!(result.receipt.policy_id, POLICY_ID);
}

#[test]
fn verify_pair_receipt_hash_deterministic() {
    let pair = DifferentialPair::new(ssr_ev("r", b"det"), ssr_ev("c", b"det"));
    let r1 = verify_path_pair(&pair, &default_config()).unwrap();
    let r2 = verify_path_pair(&pair, &default_config()).unwrap();
    assert_eq!(r1.receipt.content_hash(), r2.receipt.content_hash());
}

#[test]
fn verify_pair_no_previous_hash_in_standalone() {
    let pair = DifferentialPair::new(ssr_ev("r", b"a"), ssr_ev("c", b"a"));
    let result = verify_path_pair(&pair, &default_config()).unwrap();
    assert!(result.receipt.previous_hash.is_none());
}

#[test]
fn verify_pair_streaming_ssr_paths() {
    let pair = DifferentialPair::new(streaming_ev("r", b"chunk1"), streaming_ev("c", b"chunk1"));
    let result = verify_path_pair(&pair, &default_config()).unwrap();
    assert_eq!(result.verdict, PathVerdict::Verified);
}

#[test]
fn verify_pair_static_generation_paths() {
    let pair = DifferentialPair::new(static_gen_ev("r", b"html"), static_gen_ev("c", b"html"));
    let result = verify_path_pair(&pair, &default_config()).unwrap();
    assert_eq!(result.verdict, PathVerdict::Verified);
}

#[test]
fn verify_pair_invalid_config_rejected() {
    let pair = DifferentialPair::new(ssr_ev("r", b"a"), ssr_ev("c", b"a"));
    let mut config = default_config();
    config.min_paths = 0;
    let err = verify_path_pair(&pair, &config).unwrap_err();
    assert!(matches!(err, VerificationError::InvalidConfig { .. }));
}

#[test]
fn verify_pair_multiple_mismatches_scored() {
    let pair = DifferentialPair::with_mismatches(
        ssr_ev("r", b"a"),
        ssr_ev("c", b"b"),
        vec![
            make_mismatch(MismatchKind::TimingAnomaly),
            make_mismatch(MismatchKind::EventOrderViolation),
        ],
    );
    let result = verify_path_pair(&pair, &default_config()).unwrap();
    let report = result.divergence_report.unwrap();
    assert_eq!(report.total_mismatches, 2);
}

#[test]
fn verify_pair_strict_config_small_mismatch_diverges() {
    let pair = DifferentialPair::with_mismatches(
        ssr_ev("r", b"a"),
        ssr_ev("c", b"b"),
        vec![make_mismatch(MismatchKind::TimingAnomaly)],
    );
    let config = VerificationConfig::strict();
    let result = verify_path_pair(&pair, &config).unwrap();
    assert_eq!(result.verdict, PathVerdict::Divergent);
}

#[test]
fn verify_pair_permissive_config_allows_mismatches() {
    let pair = DifferentialPair::with_mismatches(
        ssr_ev("r", b"a"),
        ssr_ev("c", b"b"),
        vec![make_mismatch(MismatchKind::EventOrderViolation)],
    );
    let config = VerificationConfig::permissive();
    let result = verify_path_pair(&pair, &config).unwrap();
    assert_eq!(result.verdict, PathVerdict::Verified);
}

// ===========================================================================
// verify_batch
// ===========================================================================

#[test]
fn batch_all_verified() {
    let pairs = vec![
        DifferentialPair::new(ssr_ev("r1", b"a"), ssr_ev("c1", b"a")),
        DifferentialPair::new(ssr_ev("r2", b"b"), ssr_ev("c2", b"b")),
    ];
    let result = verify_batch(&pairs, &default_config()).unwrap();
    assert_eq!(result.overall_verdict, PathVerdict::Verified);
    assert_eq!(result.verified_count, 2);
    assert_eq!(result.divergent_count, 0);
    assert_eq!(result.inconclusive_count, 0);
}

#[test]
fn batch_one_divergent_overall_divergent() {
    let pairs = vec![
        DifferentialPair::new(ssr_ev("r1", b"a"), ssr_ev("c1", b"a")),
        DifferentialPair::with_mismatches(
            ssr_ev("r2", b"b"),
            ssr_ev("c2", b"c"),
            vec![make_mismatch(MismatchKind::OutputMismatch)],
        ),
    ];
    let result = verify_batch(&pairs, &default_config()).unwrap();
    assert_eq!(result.overall_verdict, PathVerdict::Divergent);
    assert_eq!(result.verified_count, 1);
    assert_eq!(result.divergent_count, 1);
}

#[test]
fn batch_empty_below_min_paths() {
    let err = verify_batch(&[], &default_config()).unwrap_err();
    assert!(matches!(err, VerificationError::BatchTooSmall { .. }));
}

#[test]
fn batch_single_pair_with_min_one() {
    let pairs = vec![DifferentialPair::new(
        ssr_ev("r1", b"a"),
        ssr_ev("c1", b"a"),
    )];
    let mut config = default_config();
    config.min_paths = 1;
    let result = verify_batch(&pairs, &config).unwrap();
    assert_eq!(result.overall_verdict, PathVerdict::Verified);
}

#[test]
fn batch_duplicate_reference_id_rejected() {
    let pairs = vec![
        DifferentialPair::new(ssr_ev("dup", b"a"), ssr_ev("c1", b"a")),
        DifferentialPair::new(ssr_ev("r2", b"b"), ssr_ev("dup", b"b")),
    ];
    let err = verify_batch(&pairs, &default_config()).unwrap_err();
    assert!(matches!(err, VerificationError::DuplicatePathId { .. }));
}

#[test]
fn batch_receipt_chaining_first_has_no_previous() {
    let pairs = vec![
        DifferentialPair::new(ssr_ev("r1", b"a"), ssr_ev("c1", b"a")),
        DifferentialPair::new(ssr_ev("r2", b"b"), ssr_ev("c2", b"b")),
    ];
    let result = verify_batch(&pairs, &default_config()).unwrap();
    assert!(result.results[0].receipt.previous_hash.is_none());
}

#[test]
fn batch_receipt_chaining_second_has_previous() {
    let pairs = vec![
        DifferentialPair::new(ssr_ev("r1", b"a"), ssr_ev("c1", b"a")),
        DifferentialPair::new(ssr_ev("r2", b"b"), ssr_ev("c2", b"b")),
    ];
    let result = verify_batch(&pairs, &default_config()).unwrap();
    assert!(result.results[1].receipt.previous_hash.is_some());
}

#[test]
fn batch_receipt_chain_deterministic() {
    let pairs = vec![
        DifferentialPair::new(ssr_ev("r1", b"a"), ssr_ev("c1", b"a")),
        DifferentialPair::new(ssr_ev("r2", b"b"), ssr_ev("c2", b"b")),
        DifferentialPair::new(ssr_ev("r3", b"c"), ssr_ev("c3", b"c")),
    ];
    let b1 = verify_batch(&pairs, &default_config()).unwrap();
    let b2 = verify_batch(&pairs, &default_config()).unwrap();
    assert_eq!(
        b1.results[2].receipt.previous_hash,
        b2.results[2].receipt.previous_hash
    );
}

#[test]
fn batch_pass_rate_all_verified() {
    let pairs = vec![
        DifferentialPair::new(ssr_ev("r1", b"a"), ssr_ev("c1", b"a")),
        DifferentialPair::new(ssr_ev("r2", b"b"), ssr_ev("c2", b"b")),
    ];
    let result = verify_batch(&pairs, &default_config()).unwrap();
    assert_eq!(result.pass_rate(), 1_000_000);
}

#[test]
fn batch_pass_rate_all_divergent() {
    let pairs = vec![
        DifferentialPair::with_mismatches(
            ssr_ev("r1", b"a"),
            ssr_ev("c1", b"b"),
            vec![make_mismatch(MismatchKind::OutputMismatch)],
        ),
        DifferentialPair::with_mismatches(
            ssr_ev("r2", b"c"),
            ssr_ev("c2", b"d"),
            vec![make_mismatch(MismatchKind::OutputMismatch)],
        ),
    ];
    let result = verify_batch(&pairs, &default_config()).unwrap();
    assert_eq!(result.pass_rate(), 0);
}

#[test]
fn batch_pass_rate_half() {
    let pairs = vec![
        DifferentialPair::new(ssr_ev("r1", b"a"), ssr_ev("c1", b"a")),
        DifferentialPair::with_mismatches(
            ssr_ev("r2", b"b"),
            ssr_ev("c2", b"c"),
            vec![make_mismatch(MismatchKind::OutputMismatch)],
        ),
    ];
    let result = verify_batch(&pairs, &default_config()).unwrap();
    assert_eq!(result.pass_rate(), 500_000);
}

#[test]
fn batch_content_hash_deterministic() {
    let pairs = vec![
        DifferentialPair::new(ssr_ev("r1", b"x"), ssr_ev("c1", b"x")),
        DifferentialPair::new(ssr_ev("r2", b"y"), ssr_ev("c2", b"y")),
    ];
    let b1 = verify_batch(&pairs, &default_config()).unwrap();
    let b2 = verify_batch(&pairs, &default_config()).unwrap();
    assert_eq!(b1.content_hash, b2.content_hash);
}

#[test]
fn batch_total_divergence_score_accumulates() {
    let pairs = vec![
        DifferentialPair::with_mismatches(
            ssr_ev("r1", b"a"),
            ssr_ev("c1", b"b"),
            vec![make_mismatch(MismatchKind::TimingAnomaly)],
        ),
        DifferentialPair::with_mismatches(
            ssr_ev("r2", b"c"),
            ssr_ev("c2", b"d"),
            vec![make_mismatch(MismatchKind::EventOrderViolation)],
        ),
    ];
    let config = VerificationConfig {
        max_divergence_millionths: 1_000_000,
        ..default_config()
    };
    let result = verify_batch(&pairs, &config).unwrap();
    assert!(result.total_divergence_score > 0);
}

#[test]
fn batch_invalid_config_rejected() {
    let pairs = vec![DifferentialPair::new(
        ssr_ev("r1", b"a"),
        ssr_ev("c1", b"a"),
    )];
    let mut config = default_config();
    config.min_paths = 0;
    let err = verify_batch(&pairs, &config).unwrap_err();
    assert!(matches!(err, VerificationError::InvalidConfig { .. }));
}

#[test]
fn batch_kind_mismatch_in_pair_rejected() {
    let pairs = vec![
        DifferentialPair::new(ssr_ev("r1", b"a"), ssr_ev("c1", b"a")),
        DifferentialPair::new(ssr_ev("r2", b"b"), client_ev("c2", b"b")),
    ];
    let err = verify_batch(&pairs, &default_config()).unwrap_err();
    assert!(matches!(err, VerificationError::PathKindMismatch { .. }));
}

#[test]
fn batch_serde_roundtrip() {
    let pairs = vec![
        DifferentialPair::new(ssr_ev("r1", b"a"), ssr_ev("c1", b"a")),
        DifferentialPair::new(ssr_ev("r2", b"b"), ssr_ev("c2", b"b")),
    ];
    let bv = verify_batch(&pairs, &default_config()).unwrap();
    let json = serde_json::to_string(&bv).unwrap();
    let back: BatchVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(bv, back);
}

#[test]
fn batch_schema_version_in_result() {
    let pairs = vec![
        DifferentialPair::new(ssr_ev("r1", b"a"), ssr_ev("c1", b"a")),
        DifferentialPair::new(ssr_ev("r2", b"b"), ssr_ev("c2", b"b")),
    ];
    let result = verify_batch(&pairs, &default_config()).unwrap();
    assert_eq!(result.schema_version, SCHEMA_VERSION);
}

// ===========================================================================
// VerificationError
// ===========================================================================

#[test]
fn error_path_kind_mismatch_display() {
    let err = VerificationError::PathKindMismatch {
        reference: ExecutionPathKind::Ssr,
        candidate: ExecutionPathKind::ClientEntry,
    };
    let s = err.to_string();
    assert!(s.contains("ssr"));
    assert!(s.contains("client_entry"));
}

#[test]
fn error_mode_mismatch_display() {
    let err = VerificationError::ModeMismatch {
        reference: VerificationMode::FullDifferential,
        candidate: VerificationMode::HashEquivalence,
    };
    let s = err.to_string();
    assert!(s.contains("full_differential"));
    assert!(s.contains("hash_equivalence"));
}

#[test]
fn error_serde_roundtrip() {
    let err = VerificationError::InvalidConfig {
        reason: "test reason".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: VerificationError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

#[test]
fn error_batch_too_small_display() {
    let err = VerificationError::BatchTooSmall { count: 0, min: 2 };
    let s = err.to_string();
    assert!(s.contains("0"));
    assert!(s.contains("2"));
}

#[test]
fn error_duplicate_path_id_display() {
    let err = VerificationError::DuplicatePathId {
        path_id: "dup-id".to_string(),
    };
    assert!(err.to_string().contains("dup-id"));
}

// ===========================================================================
// DecisionReceipt
// ===========================================================================

#[test]
fn receipt_hash_deterministic() {
    let input = ContentHash::compute(b"inp");
    let r1 = compute_receipt(input, &PathVerdict::Verified, &epoch(), None, 100);
    let r2 = compute_receipt(input, &PathVerdict::Verified, &epoch(), None, 100);
    assert_eq!(r1.content_hash(), r2.content_hash());
}

#[test]
fn receipt_different_verdict_different_hash() {
    let input = ContentHash::compute(b"inp");
    let r1 = compute_receipt(input, &PathVerdict::Verified, &epoch(), None, 100);
    let r2 = compute_receipt(input, &PathVerdict::Divergent, &epoch(), None, 100);
    assert_ne!(r1.content_hash(), r2.content_hash());
}

#[test]
fn receipt_with_previous_differs_from_without() {
    let input = ContentHash::compute(b"inp");
    let prev = ContentHash::compute(b"prev");
    let r1 = compute_receipt(input, &PathVerdict::Verified, &epoch(), None, 100);
    let r2 = compute_receipt(input, &PathVerdict::Verified, &epoch(), Some(prev), 100);
    assert_ne!(r1.content_hash(), r2.content_hash());
}

#[test]
fn receipt_serde_roundtrip() {
    let input = ContentHash::compute(b"test");
    let r = compute_receipt(input, &PathVerdict::Verified, &epoch(), None, 42);
    let json = serde_json::to_string(&r).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ===========================================================================
// Mixed scenario tests
// ===========================================================================

#[test]
fn mixed_path_kinds_in_batch() {
    let pairs = vec![
        DifferentialPair::new(ssr_ev("r1", b"a"), ssr_ev("c1", b"a")),
        DifferentialPair::new(hydration_ev("r2", b"b"), hydration_ev("c2", b"b")),
        DifferentialPair::new(streaming_ev("r3", b"c"), streaming_ev("c3", b"c")),
    ];
    let result = verify_batch(&pairs, &default_config()).unwrap();
    assert_eq!(result.overall_verdict, PathVerdict::Verified);
    assert_eq!(result.verified_count, 3);
}

#[test]
fn stream_chunk_divergence_detected() {
    let pair = DifferentialPair::with_mismatches(
        streaming_ev("r", b"chunk-a"),
        streaming_ev("c", b"chunk-b"),
        vec![make_mismatch(MismatchKind::StreamChunkDivergence)],
    );
    let result = verify_path_pair(&pair, &default_config()).unwrap();
    assert_eq!(result.verdict, PathVerdict::Divergent);
    let report = result.divergence_report.unwrap();
    assert!(
        report
            .mismatch_counts
            .contains_key(MismatchKind::StreamChunkDivergence.as_str())
    );
}

#[test]
fn state_incoherence_detected() {
    let pair = DifferentialPair::with_mismatches(
        ssr_ev("r", b"s1"),
        ssr_ev("c", b"s2"),
        vec![make_mismatch(MismatchKind::StateIncoherence)],
    );
    let result = verify_path_pair(&pair, &default_config()).unwrap();
    assert_eq!(result.verdict, PathVerdict::Divergent);
}

#[test]
fn snapshot_comparison_mode_evidence() {
    let r = make_evidence(
        "r",
        ExecutionPathKind::Ssr,
        VerificationMode::SnapshotComparison,
        b"snap",
    );
    let c = make_evidence(
        "c",
        ExecutionPathKind::Ssr,
        VerificationMode::SnapshotComparison,
        b"snap",
    );
    let pair = DifferentialPair::new(r, c);
    let result = verify_path_pair(&pair, &default_config()).unwrap();
    assert_eq!(result.verdict, PathVerdict::Verified);
}

#[test]
fn hash_equivalence_mode_evidence() {
    let r = make_evidence(
        "r",
        ExecutionPathKind::Ssr,
        VerificationMode::HashEquivalence,
        b"he",
    );
    let c = make_evidence(
        "c",
        ExecutionPathKind::Ssr,
        VerificationMode::HashEquivalence,
        b"he",
    );
    let pair = DifferentialPair::new(r, c);
    let result = verify_path_pair(&pair, &default_config()).unwrap();
    assert_eq!(result.verdict, PathVerdict::Verified);
}
