#![forbid(unsafe_code)]

//! Enrichment integration tests for the `novelty_scoring_contract` module.

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

use frankenengine_engine::novelty_scoring_contract::{
    AbstentionReason, BEAD_ID, COMPONENT, CandidateKind, CompositeVerdict, DimensionScore,
    HIGH_NOVELTY_THRESHOLD, MAX_DIMENSIONS, MILLIONTHS, MIN_SAMPLE_SIZE,
    MODERATE_NOVELTY_THRESHOLD, NOVELTY_COMPONENT, NOVELTY_POLICY_ID, NOVELTY_SCHEMA_VERSION,
    NoveltyBatch, NoveltyCandidate, NoveltyCertificate, NoveltyDimension, NoveltyEntry,
    NoveltyError, NoveltyProfile, NoveltyScore, NoveltyVerdict, SCHEMA_VERSION, ScoringConfig,
    certify_candidate, compute_information_gain, compute_mdl_score, default_weight_vector,
    run_novelty_evidence, score_batch, score_candidate,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn make_candidate(id: &str, bits: u64) -> NoveltyCandidate {
    NoveltyCandidate::new(
        id.to_string(),
        CandidateKind::Program,
        bits,
        vec![100_000; 7],
        id.as_bytes(),
    )
}

fn scored_entry(dim: NoveltyDimension, score: u64) -> NoveltyEntry {
    NoveltyEntry {
        dimension: dim,
        score: DimensionScore::scored(score, 900_000, 50),
    }
}

fn abstained_entry(dim: NoveltyDimension) -> NoveltyEntry {
    NoveltyEntry {
        dimension: dim,
        score: DimensionScore::abstained(AbstentionReason::EmptyReferenceBoard),
    }
}

// ===========================================================================
// NoveltyDimension — Copy, BTreeSet, Debug/Display unique, as_str
// ===========================================================================

#[test]
fn enrichment_novelty_dimension_copy_semantics() {
    let a = NoveltyDimension::Obstruction;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_novelty_dimension_btreeset_dedup_8() {
    let mut set = BTreeSet::new();
    for v in NoveltyDimension::ALL {
        set.insert(*v);
    }
    set.insert(NoveltyDimension::Obstruction);
    assert_eq!(set.len(), 8);
}

#[test]
fn enrichment_novelty_dimension_debug_all_unique() {
    let strs: BTreeSet<String> = NoveltyDimension::ALL
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
    assert_eq!(strs.len(), 8);
}

#[test]
fn enrichment_novelty_dimension_display_all_unique() {
    let strs: BTreeSet<String> = NoveltyDimension::ALL
        .iter()
        .map(|v| format!("{v}"))
        .collect();
    assert_eq!(strs.len(), 8);
}

#[test]
fn enrichment_novelty_dimension_as_str_matches_display() {
    for v in NoveltyDimension::ALL {
        assert_eq!(v.as_str(), format!("{v}"));
    }
}

#[test]
fn enrichment_novelty_dimension_requires_reference_board_count() {
    let count = NoveltyDimension::ALL
        .iter()
        .filter(|d| d.requires_reference_board())
        .count();
    assert_eq!(count, 4);
}

// ===========================================================================
// CandidateKind — Clone, BTreeSet, Debug/Display unique, as_str
// ===========================================================================

#[test]
fn enrichment_candidate_kind_btreeset_dedup_5() {
    let mut set = BTreeSet::new();
    for v in CandidateKind::ALL {
        set.insert(v.clone());
    }
    set.insert(CandidateKind::Program);
    assert_eq!(set.len(), 5);
}

#[test]
fn enrichment_candidate_kind_debug_all_unique() {
    let strs: BTreeSet<String> = CandidateKind::ALL
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
    assert_eq!(strs.len(), 5);
}

#[test]
fn enrichment_candidate_kind_display_all_unique() {
    let strs: BTreeSet<String> = CandidateKind::ALL.iter().map(|v| format!("{v}")).collect();
    assert_eq!(strs.len(), 5);
}

#[test]
fn enrichment_candidate_kind_as_str_matches_display() {
    for v in CandidateKind::ALL {
        assert_eq!(v.as_str(), format!("{v}"));
    }
}

// ===========================================================================
// NoveltyVerdict — Copy, BTreeSet, Debug/Display unique, as_str
// ===========================================================================

#[test]
fn enrichment_novelty_verdict_copy_semantics() {
    let a = NoveltyVerdict::Novel;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_novelty_verdict_btreeset_dedup_4() {
    let mut set = BTreeSet::new();
    for v in NoveltyVerdict::ALL {
        set.insert(*v);
    }
    set.insert(NoveltyVerdict::Novel);
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_novelty_verdict_debug_all_unique() {
    let strs: BTreeSet<String> = NoveltyVerdict::ALL
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
    assert_eq!(strs.len(), 4);
}

#[test]
fn enrichment_novelty_verdict_as_str_matches_display() {
    for v in NoveltyVerdict::ALL {
        assert_eq!(v.as_str(), format!("{v}"));
    }
}

// ===========================================================================
// CompositeVerdict — Copy, BTreeSet, Debug/Display unique, as_str, recommends
// ===========================================================================

#[test]
fn enrichment_composite_verdict_copy_semantics() {
    let a = CompositeVerdict::HighNovelty;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_composite_verdict_btreeset_dedup_4() {
    let mut set = BTreeSet::new();
    for v in CompositeVerdict::ALL {
        set.insert(*v);
    }
    set.insert(CompositeVerdict::HighNovelty);
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_composite_verdict_debug_all_unique() {
    let strs: BTreeSet<String> = CompositeVerdict::ALL
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
    assert_eq!(strs.len(), 4);
}

#[test]
fn enrichment_composite_verdict_as_str_matches_display() {
    for v in CompositeVerdict::ALL {
        assert_eq!(v.as_str(), format!("{v}"));
    }
}

#[test]
fn enrichment_composite_verdict_recommends_inclusion_exactly_two() {
    let recommended: Vec<_> = CompositeVerdict::ALL
        .iter()
        .filter(|v| v.recommends_inclusion())
        .collect();
    assert_eq!(recommended.len(), 2);
    assert!(CompositeVerdict::HighNovelty.recommends_inclusion());
    assert!(CompositeVerdict::ModerateNovelty.recommends_inclusion());
}

// ===========================================================================
// AbstentionReason — Clone, Debug, Display, tag uniqueness
// ===========================================================================

#[test]
fn enrichment_abstention_reason_clone_independence() {
    let a = AbstentionReason::OpaqueCandidate {
        region_label: "region-1".to_string(),
    };
    let mut b = a.clone();
    if let AbstentionReason::OpaqueCandidate {
        ref mut region_label,
    } = b
    {
        *region_label = "changed".to_string();
    }
    assert_ne!(format!("{a:?}"), format!("{b:?}"));
}

#[test]
fn enrichment_abstention_reason_tag_all_unique() {
    let variants: Vec<AbstentionReason> = vec![
        AbstentionReason::InsufficientSampleSize {
            available: 5,
            required: 10,
        },
        AbstentionReason::EmptyReferenceBoard,
        AbstentionReason::OpaqueCandidate {
            region_label: "r".to_string(),
        },
        AbstentionReason::UncalibratedModel,
        AbstentionReason::DisabledByPolicy,
    ];
    let tags: BTreeSet<&str> = variants.iter().map(|v| v.tag()).collect();
    assert_eq!(tags.len(), 5);
}

// ===========================================================================
// DimensionScore — Clone, Debug, methods
// ===========================================================================

#[test]
fn enrichment_dimension_score_scored_is_scored() {
    let ds = DimensionScore::scored(500_000, 900_000, 50);
    assert!(ds.is_scored());
    assert!(!ds.is_abstained());
    assert_eq!(ds.raw_score(), Some(500_000));
    assert_eq!(ds.confidence(), Some(900_000));
}

#[test]
fn enrichment_dimension_score_abstained_is_abstained() {
    let ds = DimensionScore::abstained(AbstentionReason::UncalibratedModel);
    assert!(!ds.is_scored());
    assert!(ds.is_abstained());
    assert_eq!(ds.raw_score(), None);
    assert_eq!(ds.confidence(), None);
}

#[test]
fn enrichment_dimension_score_clamping() {
    let ds = DimensionScore::scored(2_000_000, 3_000_000, 100);
    // Score should be clamped to MILLIONTHS
    assert_eq!(ds.raw_score(), Some(MILLIONTHS));
    assert_eq!(ds.confidence(), Some(MILLIONTHS));
}

#[test]
fn enrichment_dimension_score_serde_roundtrip_scored() {
    let ds = DimensionScore::scored(750_000, 800_000, 30);
    let json = serde_json::to_string(&ds).unwrap();
    let back: DimensionScore = serde_json::from_str(&json).unwrap();
    assert_eq!(ds, back);
}

#[test]
fn enrichment_dimension_score_serde_roundtrip_abstained() {
    let ds = DimensionScore::abstained(AbstentionReason::DisabledByPolicy);
    let json = serde_json::to_string(&ds).unwrap();
    let back: DimensionScore = serde_json::from_str(&json).unwrap();
    assert_eq!(ds, back);
}

// ===========================================================================
// NoveltyCandidate — Clone, Debug, JSON fields, serde
// ===========================================================================

#[test]
fn enrichment_novelty_candidate_clone_independence() {
    let a = make_candidate("c1", 1000);
    let mut b = a.clone();
    b.description_length_bits = 9999;
    assert_ne!(a.description_length_bits, b.description_length_bits);
}

#[test]
fn enrichment_novelty_candidate_debug_nonempty() {
    let c = make_candidate("c2", 500);
    let dbg = format!("{c:?}");
    assert!(dbg.contains("NoveltyCandidate"));
}

#[test]
fn enrichment_novelty_candidate_json_field_names() {
    let c = make_candidate("c3", 800);
    let json = serde_json::to_string(&c).unwrap();
    for field in &[
        "candidate_id",
        "kind",
        "description_length_bits",
        "feature_vector",
        "source_hash",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing: {field}");
    }
}

#[test]
fn enrichment_novelty_candidate_different_ids_different_hashes() {
    let c1 = make_candidate("alpha", 1000);
    let c2 = make_candidate("beta", 1000);
    assert_ne!(c1.source_hash, c2.source_hash);
}

// ===========================================================================
// ScoringConfig — Clone, Debug, validate, content_hash
// ===========================================================================

#[test]
fn enrichment_scoring_config_clone_independence() {
    let mut a = ScoringConfig::default_config();
    let b = a.clone();
    a.mdl_baseline_bits = 9999;
    assert_ne!(a.mdl_baseline_bits, b.mdl_baseline_bits);
}

#[test]
fn enrichment_scoring_config_debug_nonempty() {
    let cfg = ScoringConfig::default_config();
    let dbg = format!("{cfg:?}");
    assert!(dbg.contains("ScoringConfig"));
}

#[test]
fn enrichment_scoring_config_default_validates() {
    assert!(ScoringConfig::default_config().validate().is_ok());
}

#[test]
fn enrichment_scoring_config_content_hash_deterministic() {
    let h1 = ScoringConfig::default_config().content_hash();
    let h2 = ScoringConfig::default_config().content_hash();
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_scoring_config_serde_roundtrip() {
    let cfg = ScoringConfig::default_config();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: ScoringConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ===========================================================================
// NoveltyProfile — Clone, Debug, methods, serde
// ===========================================================================

#[test]
fn enrichment_novelty_profile_clone_independence() {
    let entries = vec![scored_entry(NoveltyDimension::Obstruction, 500_000)];
    let a = NoveltyProfile::new("fp-1".to_string(), entries);
    let mut b = a.clone();
    b.candidate_fingerprint = "changed".to_string();
    assert_ne!(a.candidate_fingerprint, b.candidate_fingerprint);
}

#[test]
fn enrichment_novelty_profile_debug_nonempty() {
    let entries = vec![scored_entry(NoveltyDimension::Obstruction, 500_000)];
    let p = NoveltyProfile::new("fp-2".to_string(), entries);
    let dbg = format!("{p:?}");
    assert!(dbg.contains("NoveltyProfile"));
}

#[test]
fn enrichment_novelty_profile_full_coverage() {
    let entries: Vec<_> = NoveltyDimension::ALL
        .iter()
        .map(|d| scored_entry(*d, 500_000))
        .collect();
    let p = NoveltyProfile::new("fp-full".to_string(), entries);
    assert_eq!(p.scored_count(), 8);
    assert_eq!(p.abstained_count(), 0);
    assert_eq!(p.coverage_millionths(), MILLIONTHS);
}

#[test]
fn enrichment_novelty_profile_partial_coverage() {
    let entries = vec![
        scored_entry(NoveltyDimension::Obstruction, 500_000),
        abstained_entry(NoveltyDimension::InformationGain),
    ];
    let p = NoveltyProfile::new("fp-part".to_string(), entries);
    assert_eq!(p.scored_count(), 1);
    assert_eq!(p.abstained_count(), 1);
    assert_eq!(p.coverage_millionths(), 500_000);
}

#[test]
fn enrichment_novelty_profile_score_for_returns_correct() {
    let entries = vec![scored_entry(NoveltyDimension::Obstruction, 700_000)];
    let p = NoveltyProfile::new("fp-sf".to_string(), entries);
    let score = p.score_for(NoveltyDimension::Obstruction);
    assert!(score.is_some());
    assert!(score.unwrap().is_scored());
}

#[test]
fn enrichment_novelty_profile_score_for_missing_returns_none() {
    let entries = vec![scored_entry(NoveltyDimension::Obstruction, 700_000)];
    let p = NoveltyProfile::new("fp-sf2".to_string(), entries);
    assert!(p.score_for(NoveltyDimension::InformationGain).is_none());
}

#[test]
fn enrichment_novelty_profile_content_hash_deterministic() {
    let entries1 = vec![scored_entry(NoveltyDimension::Obstruction, 500_000)];
    let entries2 = vec![scored_entry(NoveltyDimension::Obstruction, 500_000)];
    let p1 = NoveltyProfile::new("fp-det".to_string(), entries1);
    let p2 = NoveltyProfile::new("fp-det".to_string(), entries2);
    assert_eq!(p1.content_hash, p2.content_hash);
}

// ===========================================================================
// NoveltyBatch — Clone, Debug, methods, serde
// ===========================================================================

#[test]
fn enrichment_novelty_batch_clone_independence() {
    let batch = NoveltyBatch::new(epoch(), vec![]);
    let mut cloned = batch.clone();
    cloned.schema_version = "changed".to_string();
    assert_ne!(batch.schema_version, cloned.schema_version);
}

#[test]
fn enrichment_novelty_batch_debug_nonempty() {
    let batch = NoveltyBatch::new(epoch(), vec![]);
    let dbg = format!("{batch:?}");
    assert!(dbg.contains("NoveltyBatch"));
}

#[test]
fn enrichment_novelty_batch_empty_max_score_zero() {
    let batch = NoveltyBatch::new(epoch(), vec![]);
    assert_eq!(batch.max_score(), 0);
    assert_eq!(batch.candidate_count(), 0);
}

#[test]
fn enrichment_novelty_batch_serde_roundtrip() {
    let batch = NoveltyBatch::new(epoch(), vec![]);
    let json = serde_json::to_string(&batch).unwrap();
    let back: NoveltyBatch = serde_json::from_str(&json).unwrap();
    assert_eq!(batch, back);
}

// ===========================================================================
// NoveltyError — Clone, Debug, Display unique
// ===========================================================================

#[test]
fn enrichment_novelty_error_display_all_unique() {
    let variants: Vec<NoveltyError> = vec![
        NoveltyError::InvalidWeights {
            expected: 1_000_000,
            actual: 500_000,
        },
        NoveltyError::EmptyCandidateSet,
        NoveltyError::InvalidFeatureVector {
            expected_dims: 8,
            actual_dims: 3,
        },
        NoveltyError::MdlBaselineZero,
    ];
    let strs: BTreeSet<String> = variants.iter().map(|v| format!("{v}")).collect();
    assert_eq!(strs.len(), 4);
}

#[test]
fn enrichment_novelty_error_serde_all() {
    let variants: Vec<NoveltyError> = vec![
        NoveltyError::InvalidWeights {
            expected: 1_000_000,
            actual: 500_000,
        },
        NoveltyError::EmptyCandidateSet,
        NoveltyError::InvalidFeatureVector {
            expected_dims: 8,
            actual_dims: 3,
        },
        NoveltyError::MdlBaselineZero,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: NoveltyError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ===========================================================================
// Scoring functions — boundary tests
// ===========================================================================

#[test]
fn enrichment_compute_mdl_score_shorter_is_high() {
    let c = make_candidate("mdl-1", 100);
    let cfg = ScoringConfig::default_config();
    let score = compute_mdl_score(&c, cfg.mdl_baseline_bits);
    assert!(score > 0, "shorter than baseline should score > 0");
}

#[test]
fn enrichment_compute_mdl_score_equal_is_zero() {
    let cfg = ScoringConfig::default_config();
    let c = make_candidate("mdl-eq", cfg.mdl_baseline_bits);
    let score = compute_mdl_score(&c, cfg.mdl_baseline_bits);
    assert_eq!(score, 0);
}

#[test]
fn enrichment_compute_information_gain_no_prior_is_max() {
    let c = make_candidate("ig-1", 1000);
    let gain = compute_information_gain(&c, &[]);
    assert_eq!(gain, MILLIONTHS);
}

#[test]
fn enrichment_compute_information_gain_identical_prior_is_zero() {
    let c = make_candidate("ig-2", 1000);
    let gain = compute_information_gain(&c, std::slice::from_ref(&c));
    assert_eq!(gain, 0);
}

// ===========================================================================
// score_candidate — properties
// ===========================================================================

#[test]
fn enrichment_score_candidate_produces_dimension_scores() {
    let c = make_candidate("sc-1", 100);
    let cfg = ScoringConfig::default_config();
    let score = score_candidate(&c, &cfg, &[]);
    assert!(!score.dimension_scores.is_empty());
}

#[test]
fn enrichment_score_candidate_serde_roundtrip() {
    let c = make_candidate("sc-2", 200);
    let cfg = ScoringConfig::default_config();
    let score = score_candidate(&c, &cfg, &[]);
    let json = serde_json::to_string(&score).unwrap();
    let back: NoveltyScore = serde_json::from_str(&json).unwrap();
    assert_eq!(score, back);
}

// ===========================================================================
// certify_candidate — properties
// ===========================================================================

#[test]
fn enrichment_certify_candidate_hash_deterministic() {
    let c = make_candidate("cert-1", 100);
    let cfg = ScoringConfig::default_config();
    let score = score_candidate(&c, &cfg, &[]);
    let cert1 = certify_candidate(&c, &score, &cfg);
    let cert2 = certify_candidate(&c, &score, &cfg);
    assert_eq!(cert1.certificate_hash, cert2.certificate_hash);
}

#[test]
fn enrichment_certify_candidate_serde_roundtrip() {
    let c = make_candidate("cert-2", 200);
    let cfg = ScoringConfig::default_config();
    let score = score_candidate(&c, &cfg, &[]);
    let cert = certify_candidate(&c, &score, &cfg);
    let json = serde_json::to_string(&cert).unwrap();
    let back: NoveltyCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

// ===========================================================================
// score_batch — properties
// ===========================================================================

#[test]
fn enrichment_score_batch_sorted_descending() {
    let candidates = vec![
        make_candidate("b1", 50),
        make_candidate("b2", 100),
        make_candidate("b3", 500),
    ];
    let cfg = ScoringConfig::default_config();
    let batch = score_batch(&candidates, &cfg);
    for i in 1..batch.scores.len() {
        assert!(
            batch.scores[i - 1].composite_millionths >= batch.scores[i].composite_millionths,
            "batch scores should be sorted descending"
        );
    }
}

#[test]
fn enrichment_score_batch_count_matches_input() {
    let candidates = vec![make_candidate("b4", 50), make_candidate("b5", 100)];
    let cfg = ScoringConfig::default_config();
    let batch = score_batch(&candidates, &cfg);
    assert_eq!(batch.candidate_count(), candidates.len());
}

// ===========================================================================
// 5-run determinism
// ===========================================================================

#[test]
fn enrichment_five_run_determinism_score_batch() {
    let hashes: Vec<_> = (0..5)
        .map(|_| {
            let candidates = vec![make_candidate("det-1", 100), make_candidate("det-2", 200)];
            let cfg = ScoringConfig::default_config();
            let batch = score_batch(&candidates, &cfg);
            batch.content_hash
        })
        .collect();
    for h in &hashes {
        assert_eq!(*h, hashes[0]);
    }
}

#[test]
fn enrichment_five_run_determinism_evidence_manifest() {
    let hashes: Vec<_> = (0..5)
        .map(|_| {
            let manifest = run_novelty_evidence();
            manifest.manifest_hash
        })
        .collect();
    for h in &hashes {
        assert_eq!(*h, hashes[0]);
    }
}

#[test]
fn enrichment_five_run_determinism_config_hash() {
    let hashes: Vec<_> = (0..5)
        .map(|_| ScoringConfig::default_config().content_hash())
        .collect();
    for h in &hashes {
        assert_eq!(*h, hashes[0]);
    }
}

// ===========================================================================
// Constants stability
// ===========================================================================

#[test]
fn enrichment_constants_stability() {
    assert_eq!(SCHEMA_VERSION, NOVELTY_SCHEMA_VERSION);
    assert_eq!(COMPONENT, NOVELTY_COMPONENT);
    assert_eq!(BEAD_ID, "bd-1lsy.8.7.1");
    assert_eq!(NOVELTY_POLICY_ID, "RGC-707A");
    assert_eq!(MILLIONTHS, 1_000_000);
    assert_eq!(MAX_DIMENSIONS, 16);
    assert_eq!(MIN_SAMPLE_SIZE, 10);
}

#[test]
fn enrichment_thresholds_ordered() {
    assert!(HIGH_NOVELTY_THRESHOLD > MODERATE_NOVELTY_THRESHOLD);
    assert!(MODERATE_NOVELTY_THRESHOLD > 0);
}

// ===========================================================================
// Cross-cutting
// ===========================================================================

#[test]
fn enrichment_default_weight_vector_covers_all_dimensions() {
    let weights = default_weight_vector();
    let dims: BTreeSet<_> = weights.iter().map(|w| w.dimension).collect();
    for d in NoveltyDimension::ALL {
        assert!(dims.contains(d), "missing dimension: {d:?}");
    }
}

#[test]
fn enrichment_default_weight_vector_sums_to_millionths() {
    let weights = default_weight_vector();
    let total: u64 = weights.iter().map(|w| w.weight_millionths).sum();
    assert_eq!(total, MILLIONTHS);
}

#[test]
fn enrichment_evidence_manifest_has_candidates() {
    let manifest = run_novelty_evidence();
    assert!(manifest.candidates_scored > 0);
    assert!(manifest.error.is_none());
}
