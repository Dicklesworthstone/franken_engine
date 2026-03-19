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

//! Enrichment integration tests for the `react_ssr_verification` module.

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::react_ssr_verification::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(50)
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
        duration_micros: 1000,
        output_size_bytes: content.len() as u64,
    }
}

fn ssr_evidence(id: &str, content: &[u8]) -> PathEvidence {
    make_evidence(id, ExecutionPathKind::Ssr, VerificationMode::FullDifferential, content)
}

fn client_evidence(id: &str, content: &[u8]) -> PathEvidence {
    make_evidence(
        id,
        ExecutionPathKind::ClientEntry,
        VerificationMode::FullDifferential,
        content,
    )
}

fn hydration_evidence(id: &str, content: &[u8]) -> PathEvidence {
    make_evidence(
        id,
        ExecutionPathKind::Hydration,
        VerificationMode::FullDifferential,
        content,
    )
}

fn streaming_evidence(id: &str, content: &[u8]) -> PathEvidence {
    make_evidence(
        id,
        ExecutionPathKind::StreamingSsr,
        VerificationMode::FullDifferential,
        content,
    )
}

fn make_mismatch(kind: MismatchKind) -> MismatchRecord {
    MismatchRecord {
        kind,
        severity: classify_severity(kind),
        detail: format!("test mismatch: {kind}"),
        reference_hash: ContentHash::compute(b"ref"),
        candidate_hash: ContentHash::compute(b"cand"),
    }
}

fn default_config() -> VerificationConfig {
    VerificationConfig::default()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_execution_path_kind_all_has_five() {
    assert_eq!(ExecutionPathKind::ALL.len(), 5);
    let mut seen = std::collections::BTreeSet::new();
    for kind in ExecutionPathKind::ALL {
        assert!(seen.insert(kind.as_str()));
    }
}

#[test]
fn enrichment_verification_mode_content_level_checks() {
    assert!(VerificationMode::FullDifferential.is_content_level());
    assert!(VerificationMode::SampledDifferential.is_content_level());
    assert!(!VerificationMode::SnapshotComparison.is_content_level());
    assert!(!VerificationMode::HashEquivalence.is_content_level());
}

#[test]
fn enrichment_mismatch_kind_weights_all_positive_bounded() {
    for kind in MismatchKind::ALL {
        let w = kind.weight();
        assert!(w > 0);
        assert!(w <= 1_000_000);
    }
}

#[test]
fn enrichment_classify_severity_all_kinds() {
    let expected = vec![
        (MismatchKind::OutputMismatch, MismatchSeverity::Critical),
        (MismatchKind::TimingAnomaly, MismatchSeverity::Info),
        (MismatchKind::StateIncoherence, MismatchSeverity::Error),
        (MismatchKind::HydrationMismatch, MismatchSeverity::Critical),
        (MismatchKind::StreamChunkDivergence, MismatchSeverity::Error),
        (MismatchKind::EventOrderViolation, MismatchSeverity::Warning),
    ];
    for (kind, sev) in &expected {
        assert_eq!(classify_severity(*kind), *sev);
    }
}

#[test]
fn enrichment_mismatch_severity_weights_increasing() {
    let weights: Vec<u64> = MismatchSeverity::ALL.iter().map(|s| s.weight()).collect();
    for w in weights.windows(2) {
        assert!(w[0] < w[1]);
    }
}

#[test]
fn enrichment_config_strict_zero_tolerance() {
    let c = VerificationConfig::strict();
    assert_eq!(c.max_divergence_millionths, 0);
    assert!(c.require_hydration_check);
    assert!(c.fail_on_timing_anomaly);
    assert!(c.require_exact_stream_order);
}

#[test]
fn enrichment_config_permissive_high_tolerance() {
    let c = VerificationConfig::permissive();
    assert_eq!(c.max_divergence_millionths, 500_000);
    assert!(!c.require_hydration_check);
    assert!(!c.fail_on_timing_anomaly);
}

#[test]
fn enrichment_validate_config_accepts_boundary_millionths() {
    let mut c = default_config();
    c.max_divergence_millionths = 1_000_000;
    c.max_timing_divergence_millionths = 1_000_000;
    assert!(validate_config(&c).is_ok());
}

#[test]
fn enrichment_validate_config_rejects_over_millionths() {
    let mut c = default_config();
    c.max_divergence_millionths = 1_000_001;
    assert!(validate_config(&c).is_err());
}

#[test]
fn enrichment_validate_config_rejects_zero_min_paths() {
    let mut c = default_config();
    c.min_paths = 0;
    let err = validate_config(&c).unwrap_err();
    assert!(matches!(err, VerificationError::InvalidConfig { .. }));
}

#[test]
fn enrichment_path_verdict_all_variants_serde() {
    for v in PathVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: PathVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_path_verdict_display_matches_as_str() {
    for v in PathVerdict::ALL {
        assert_eq!(v.to_string(), v.as_str());
    }
}

#[test]
fn enrichment_compute_divergence_score_empty_is_zero() {
    assert_eq!(compute_divergence_score(&[]), 0);
}

#[test]
fn enrichment_compute_divergence_score_capped_at_million() {
    let many: Vec<MismatchRecord> = (0..20)
        .map(|_| make_mismatch(MismatchKind::OutputMismatch))
        .collect();
    assert_eq!(compute_divergence_score(&many), 1_000_000);
}

#[test]
fn enrichment_compute_divergence_score_additive() {
    let mismatches = vec![
        make_mismatch(MismatchKind::TimingAnomaly),
        make_mismatch(MismatchKind::EventOrderViolation),
    ];
    let score = compute_divergence_score(&mismatches);
    let expected = MismatchKind::TimingAnomaly.weight() + MismatchKind::EventOrderViolation.weight();
    assert_eq!(score, expected);
}

#[test]
fn enrichment_verify_pair_matching_content_verified() {
    let pair = DifferentialPair::new(ssr_evidence("ref", b"same"), ssr_evidence("cand", b"same"));
    let result = verify_path_pair(&pair, &default_config()).unwrap();
    assert_eq!(result.verdict, PathVerdict::Verified);
    assert!(result.divergence_report.is_none());
}

#[test]
fn enrichment_verify_pair_kind_mismatch_rejected() {
    let pair = DifferentialPair::new(ssr_evidence("ref", b"a"), client_evidence("cand", b"a"));
    let err = verify_path_pair(&pair, &default_config()).unwrap_err();
    assert!(matches!(err, VerificationError::PathKindMismatch { .. }));
}

#[test]
fn enrichment_verify_pair_mode_mismatch_rejected() {
    let ref_ev = make_evidence("ref", ExecutionPathKind::Ssr, VerificationMode::FullDifferential, b"a");
    let cand_ev = make_evidence("cand", ExecutionPathKind::Ssr, VerificationMode::HashEquivalence, b"a");
    let pair = DifferentialPair::new(ref_ev, cand_ev);
    let err = verify_path_pair(&pair, &default_config()).unwrap_err();
    assert!(matches!(err, VerificationError::ModeMismatch { .. }));
}

#[test]
fn enrichment_verify_pair_high_divergence_is_divergent() {
    let pair = DifferentialPair::with_mismatches(
        ssr_evidence("ref", b"a"),
        ssr_evidence("cand", b"b"),
        vec![make_mismatch(MismatchKind::OutputMismatch)],
    );
    let result = verify_path_pair(&pair, &default_config()).unwrap();
    assert_eq!(result.verdict, PathVerdict::Divergent);
    assert!(result.divergence_report.is_some());
}

#[test]
fn enrichment_verify_pair_timing_anomaly_ignored_by_default() {
    let pair = DifferentialPair::with_mismatches(
        ssr_evidence("ref", b"a"),
        ssr_evidence("cand", b"a"),
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
fn enrichment_verify_pair_timing_anomaly_fail_when_strict() {
    let pair = DifferentialPair::with_mismatches(
        ssr_evidence("ref", b"a"),
        ssr_evidence("cand", b"a"),
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
fn enrichment_verify_pair_hydration_critical_divergent() {
    let pair = DifferentialPair::with_mismatches(
        hydration_evidence("ref", b"a"),
        hydration_evidence("cand", b"b"),
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
fn enrichment_verify_pair_receipt_metadata_correct() {
    let pair = DifferentialPair::new(ssr_evidence("ref", b"x"), ssr_evidence("cand", b"x"));
    let result = verify_path_pair(&pair, &default_config()).unwrap();
    assert_eq!(result.receipt.schema_version, SCHEMA_VERSION);
    assert_eq!(result.receipt.component, COMPONENT);
    assert_eq!(result.receipt.bead_id, BEAD_ID);
    assert_eq!(result.receipt.policy_id, POLICY_ID);
}

#[test]
fn enrichment_verify_batch_all_verified() {
    let pairs = vec![
        DifferentialPair::new(ssr_evidence("r1", b"a"), ssr_evidence("c1", b"a")),
        DifferentialPair::new(ssr_evidence("r2", b"b"), ssr_evidence("c2", b"b")),
    ];
    let result = verify_batch(&pairs, &default_config()).unwrap();
    assert_eq!(result.overall_verdict, PathVerdict::Verified);
    assert_eq!(result.verified_count, 2);
    assert_eq!(result.divergent_count, 0);
    assert_eq!(result.pass_rate(), 1_000_000);
}

#[test]
fn enrichment_verify_batch_mixed_verdicts() {
    let pairs = vec![
        DifferentialPair::new(ssr_evidence("r1", b"a"), ssr_evidence("c1", b"a")),
        DifferentialPair::with_mismatches(
            ssr_evidence("r2", b"x"),
            ssr_evidence("c2", b"y"),
            vec![make_mismatch(MismatchKind::OutputMismatch)],
        ),
    ];
    let result = verify_batch(&pairs, &default_config()).unwrap();
    assert_eq!(result.overall_verdict, PathVerdict::Divergent);
    assert_eq!(result.verified_count, 1);
    assert_eq!(result.divergent_count, 1);
    assert_eq!(result.pass_rate(), 500_000);
}

#[test]
fn enrichment_verify_batch_too_small_rejected() {
    let err = verify_batch(&[], &default_config()).unwrap_err();
    assert!(matches!(err, VerificationError::BatchTooSmall { .. }));
}

#[test]
fn enrichment_verify_batch_duplicate_path_id_rejected() {
    let pairs = vec![
        DifferentialPair::new(ssr_evidence("dup", b"a"), ssr_evidence("c1", b"a")),
        DifferentialPair::new(ssr_evidence("r2", b"b"), ssr_evidence("dup", b"b")),
    ];
    let err = verify_batch(&pairs, &default_config()).unwrap_err();
    assert!(matches!(err, VerificationError::DuplicatePathId { .. }));
}

#[test]
fn enrichment_verify_batch_receipt_chain() {
    let pairs = vec![
        DifferentialPair::new(ssr_evidence("r1", b"a"), ssr_evidence("c1", b"a")),
        DifferentialPair::new(ssr_evidence("r2", b"b"), ssr_evidence("c2", b"b")),
        DifferentialPair::new(ssr_evidence("r3", b"c"), ssr_evidence("c3", b"c")),
    ];
    let result = verify_batch(&pairs, &default_config()).unwrap();
    assert!(result.results[0].receipt.previous_hash.is_none());
    assert!(result.results[1].receipt.previous_hash.is_some());
    assert!(result.results[2].receipt.previous_hash.is_some());
    assert_ne!(
        result.results[1].receipt.previous_hash,
        result.results[2].receipt.previous_hash
    );
}

#[test]
fn enrichment_batch_verdict_content_hash_deterministic() {
    let pairs = vec![
        DifferentialPair::new(ssr_evidence("r1", b"x"), ssr_evidence("c1", b"x")),
        DifferentialPair::new(ssr_evidence("r2", b"y"), ssr_evidence("c2", b"y")),
    ];
    let b1 = verify_batch(&pairs, &default_config()).unwrap();
    let b2 = verify_batch(&pairs, &default_config()).unwrap();
    assert_eq!(b1.content_hash, b2.content_hash);
}

#[test]
fn enrichment_batch_verdict_pass_rate_zero_all_divergent() {
    let pairs = vec![
        DifferentialPair::with_mismatches(
            ssr_evidence("r1", b"a"),
            ssr_evidence("c1", b"b"),
            vec![make_mismatch(MismatchKind::OutputMismatch)],
        ),
        DifferentialPair::with_mismatches(
            ssr_evidence("r2", b"c"),
            ssr_evidence("c2", b"d"),
            vec![make_mismatch(MismatchKind::OutputMismatch)],
        ),
    ];
    let result = verify_batch(&pairs, &default_config()).unwrap();
    assert_eq!(result.pass_rate(), 0);
}

#[test]
fn enrichment_compute_receipt_deterministic() {
    let input_hash = ContentHash::compute(b"input");
    let r1 = compute_receipt(input_hash, &PathVerdict::Verified, &epoch(), None, 100);
    let r2 = compute_receipt(input_hash, &PathVerdict::Verified, &epoch(), None, 100);
    assert_eq!(r1.content_hash(), r2.content_hash());
}

#[test]
fn enrichment_compute_receipt_verdict_changes_hash() {
    let input_hash = ContentHash::compute(b"input");
    let r1 = compute_receipt(input_hash, &PathVerdict::Verified, &epoch(), None, 100);
    let r2 = compute_receipt(input_hash, &PathVerdict::Divergent, &epoch(), None, 100);
    assert_ne!(r1.content_hash(), r2.content_hash());
}

#[test]
fn enrichment_compute_receipt_previous_hash_changes_result() {
    let input_hash = ContentHash::compute(b"input");
    let prev = ContentHash::compute(b"prev");
    let r1 = compute_receipt(input_hash, &PathVerdict::Verified, &epoch(), None, 100);
    let r2 = compute_receipt(input_hash, &PathVerdict::Verified, &epoch(), Some(prev), 100);
    assert_ne!(r1.content_hash(), r2.content_hash());
}

#[test]
fn enrichment_mismatch_record_content_hash_deterministic() {
    let m1 = make_mismatch(MismatchKind::StateIncoherence);
    let m2 = make_mismatch(MismatchKind::StateIncoherence);
    assert_eq!(m1.content_hash(), m2.content_hash());
}

#[test]
fn enrichment_mismatch_record_display_format() {
    let m = make_mismatch(MismatchKind::OutputMismatch);
    let s = m.to_string();
    assert!(s.contains("critical"));
    assert!(s.contains("output_mismatch"));
}

#[test]
fn enrichment_path_evidence_content_hash_varies_by_content() {
    let e1 = ssr_evidence("p1", b"content_a");
    let e2 = ssr_evidence("p1", b"content_b");
    assert_ne!(e1.content_hash(), e2.content_hash());
}

#[test]
fn enrichment_path_evidence_display() {
    let e = ssr_evidence("my-path", b"data");
    let s = e.to_string();
    assert!(s.contains("my-path"));
    assert!(s.contains("ssr"));
}

#[test]
fn enrichment_differential_pair_content_hash_stable() {
    let p1 = DifferentialPair::new(ssr_evidence("r", b"a"), ssr_evidence("c", b"b"));
    let p2 = DifferentialPair::new(ssr_evidence("r", b"a"), ssr_evidence("c", b"b"));
    assert_eq!(p1.content_hash(), p2.content_hash());
}

#[test]
fn enrichment_differential_pair_kinds_match_same_kind() {
    let pair = DifferentialPair::new(
        streaming_evidence("r", b"a"),
        streaming_evidence("c", b"b"),
    );
    assert!(pair.kinds_match());
    assert!(pair.modes_match());
}

#[test]
fn enrichment_verification_error_display_all_variants() {
    let errors: Vec<VerificationError> = vec![
        VerificationError::PathKindMismatch {
            reference: ExecutionPathKind::Ssr,
            candidate: ExecutionPathKind::ClientEntry,
        },
        VerificationError::ModeMismatch {
            reference: VerificationMode::FullDifferential,
            candidate: VerificationMode::HashEquivalence,
        },
        VerificationError::TooManyMismatches { count: 20000, max: 10000 },
        VerificationError::BatchTooLarge { count: 6000, max: 5000 },
        VerificationError::BatchTooSmall { count: 0, min: 2 },
        VerificationError::InvalidConfig { reason: "bad".to_string() },
        VerificationError::DuplicatePathId { path_id: "dup".to_string() },
    ];
    for err in &errors {
        assert!(!err.to_string().is_empty());
    }
}

#[test]
fn enrichment_verification_error_serde_roundtrip() {
    let err = VerificationError::PathKindMismatch {
        reference: ExecutionPathKind::Ssr,
        candidate: ExecutionPathKind::Hydration,
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: VerificationError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

#[test]
fn enrichment_batch_verdict_serde_roundtrip() {
    let pairs = vec![
        DifferentialPair::new(ssr_evidence("r1", b"a"), ssr_evidence("c1", b"a")),
        DifferentialPair::new(ssr_evidence("r2", b"b"), ssr_evidence("c2", b"b")),
    ];
    let bv = verify_batch(&pairs, &default_config()).unwrap();
    let json = serde_json::to_string(&bv).unwrap();
    let back: BatchVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(bv, back);
}

#[test]
fn enrichment_config_serde_roundtrip_all_variants() {
    for config in [
        VerificationConfig::default(),
        VerificationConfig::strict(),
        VerificationConfig::permissive(),
    ] {
        let json = serde_json::to_string(&config).unwrap();
        let back: VerificationConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }
}
