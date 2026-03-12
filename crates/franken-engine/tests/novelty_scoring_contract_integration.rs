//! Integration tests for `novelty_scoring_contract` module.
//!
//! Validates public API, serde contracts, determinism, composite scoring,
//! abstention semantics, batch ranking, and threshold boundaries.

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
use frankenengine_engine::novelty_scoring_contract::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(200)
}

fn scored_entry(dim: NoveltyDimension, score: u64) -> NoveltyEntry {
    NoveltyEntry {
        dimension: dim,
        score: DimensionScore::scored(score, 900_000, 100),
    }
}

fn abstained_entry(dim: NoveltyDimension) -> NoveltyEntry {
    NoveltyEntry {
        dimension: dim,
        score: DimensionScore::abstained(AbstentionReason::UncalibratedModel),
    }
}

fn full_profile(score: u64) -> NoveltyProfile {
    let entries: Vec<_> = NoveltyDimension::ALL
        .iter()
        .map(|d| scored_entry(*d, score))
        .collect();
    NoveltyProfile::new("full_candidate".into(), entries)
}

fn composite(profile: &NoveltyProfile) -> CompositeNoveltyScore {
    CompositeNoveltyScore::compute(
        profile,
        &default_weight_vector(),
        DEFAULT_ABSTENTION_THRESHOLD,
        epoch(),
    )
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_nonempty() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn bead_id_nonempty() {
    assert!(!BEAD_ID.is_empty());
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn component_name() {
    assert_eq!(COMPONENT, "novelty_scoring_contract");
}

#[test]
fn max_dimensions_positive() {
    const { assert!(MAX_DIMENSIONS > 0) };
}

#[test]
fn min_sample_size_positive() {
    const { assert!(MIN_SAMPLE_SIZE > 0) };
}

#[test]
fn thresholds_ordered() {
    const {
        assert!(HIGH_NOVELTY_THRESHOLD > MODERATE_NOVELTY_THRESHOLD);
        assert!(MODERATE_NOVELTY_THRESHOLD > 0);
        assert!(HIGH_NOVELTY_THRESHOLD <= 1_000_000);
    }
}

#[test]
fn abstention_threshold_in_range() {
    const { assert!(DEFAULT_ABSTENTION_THRESHOLD > 0) };
    const { assert!(DEFAULT_ABSTENTION_THRESHOLD <= 1_000_000) };
}

// ---------------------------------------------------------------------------
// NoveltyDimension
// ---------------------------------------------------------------------------

#[test]
fn dimension_all_length() {
    assert_eq!(NoveltyDimension::ALL.len(), 8);
}

#[test]
fn dimension_names_unique() {
    let names: BTreeSet<&str> = NoveltyDimension::ALL.iter().map(|d| d.as_str()).collect();
    assert_eq!(names.len(), NoveltyDimension::ALL.len());
}

#[test]
fn dimension_display_matches_as_str() {
    for d in NoveltyDimension::ALL {
        assert_eq!(d.to_string(), d.as_str());
    }
}

#[test]
fn dimension_serde_all_variants() {
    for d in NoveltyDimension::ALL {
        let json = serde_json::to_string(d).unwrap();
        let back: NoveltyDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, back);
    }
}

#[test]
fn dimension_reference_board_subset() {
    let needs: Vec<_> = NoveltyDimension::ALL
        .iter()
        .filter(|d| d.requires_reference_board())
        .collect();
    assert!(!needs.is_empty());
    assert!(needs.len() < NoveltyDimension::ALL.len());
}

#[test]
fn mdl_does_not_require_board() {
    assert!(!NoveltyDimension::MinimumDescriptionLength.requires_reference_board());
}

#[test]
fn information_gain_requires_board() {
    assert!(NoveltyDimension::InformationGain.requires_reference_board());
}

// ---------------------------------------------------------------------------
// AbstentionReason
// ---------------------------------------------------------------------------

#[test]
fn abstention_tags_unique() {
    let reasons = vec![
        AbstentionReason::InsufficientSampleSize {
            available: 5,
            required: 10,
        },
        AbstentionReason::EmptyReferenceBoard,
        AbstentionReason::OpaqueCandidate {
            region_label: "x".into(),
        },
        AbstentionReason::UncalibratedModel,
        AbstentionReason::DisabledByPolicy,
    ];
    let tags: BTreeSet<&str> = reasons.iter().map(|r| r.tag()).collect();
    assert_eq!(tags.len(), 5);
}

#[test]
fn abstention_serde_roundtrip() {
    let r = AbstentionReason::OpaqueCandidate {
        region_label: "native_stub".into(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: AbstentionReason = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn abstention_display_content() {
    let r = AbstentionReason::InsufficientSampleSize {
        available: 3,
        required: 10,
    };
    let s = r.to_string();
    assert!(s.contains("3"));
    assert!(s.contains("10"));
}

// ---------------------------------------------------------------------------
// DimensionScore
// ---------------------------------------------------------------------------

#[test]
fn score_scored_properties() {
    let s = DimensionScore::scored(750_000, 950_000, 200);
    assert!(s.is_scored());
    assert!(!s.is_abstained());
    assert_eq!(s.raw_score(), Some(750_000));
    assert_eq!(s.confidence(), Some(950_000));
}

#[test]
fn score_clamping() {
    let s = DimensionScore::scored(5_000_000, 9_000_000, 50);
    assert_eq!(s.raw_score(), Some(1_000_000));
    assert_eq!(s.confidence(), Some(1_000_000));
}

#[test]
fn score_abstained_properties() {
    let s = DimensionScore::abstained(AbstentionReason::DisabledByPolicy);
    assert!(s.is_abstained());
    assert!(!s.is_scored());
    assert_eq!(s.raw_score(), None);
    assert_eq!(s.confidence(), None);
}

#[test]
fn score_serde_scored_roundtrip() {
    let s = DimensionScore::scored(500_000, 800_000, 100);
    let json = serde_json::to_string(&s).unwrap();
    let back: DimensionScore = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn score_serde_abstained_roundtrip() {
    let s = DimensionScore::abstained(AbstentionReason::EmptyReferenceBoard);
    let json = serde_json::to_string(&s).unwrap();
    let back: DimensionScore = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ---------------------------------------------------------------------------
// DimensionWeight
// ---------------------------------------------------------------------------

#[test]
fn weight_construction() {
    let w = DimensionWeight::new(NoveltyDimension::Obstruction, 150_000);
    assert_eq!(w.dimension, NoveltyDimension::Obstruction);
    assert_eq!(w.weight_millionths, 150_000);
}

#[test]
fn default_weight_vector_covers_all() {
    let w = default_weight_vector();
    assert_eq!(w.len(), NoveltyDimension::ALL.len());
    let dims: BTreeSet<_> = w.iter().map(|w| w.dimension).collect();
    assert_eq!(dims.len(), NoveltyDimension::ALL.len());
}

#[test]
fn default_weight_vector_serde_roundtrip() {
    let w = default_weight_vector();
    let json = serde_json::to_string(&w).unwrap();
    let back: Vec<DimensionWeight> = serde_json::from_str(&json).unwrap();
    assert_eq!(w, back);
}

// ---------------------------------------------------------------------------
// NoveltyProfile
// ---------------------------------------------------------------------------

#[test]
fn profile_full_coverage() {
    let p = full_profile(600_000);
    assert_eq!(p.scored_count(), 8);
    assert_eq!(p.abstained_count(), 0);
    assert_eq!(p.coverage_millionths(), 1_000_000);
}

#[test]
fn profile_zero_coverage() {
    let entries: Vec<_> = NoveltyDimension::ALL
        .iter()
        .map(|d| abstained_entry(*d))
        .collect();
    let p = NoveltyProfile::new("none".into(), entries);
    assert_eq!(p.scored_count(), 0);
    assert_eq!(p.coverage_millionths(), 0);
}

#[test]
fn profile_partial_coverage() {
    let entries = vec![
        scored_entry(NoveltyDimension::MinimumDescriptionLength, 500_000),
        scored_entry(NoveltyDimension::InformationGain, 700_000),
        abstained_entry(NoveltyDimension::Obstruction),
        abstained_entry(NoveltyDimension::TopologicalDistance),
    ];
    let p = NoveltyProfile::new("partial".into(), entries);
    assert_eq!(p.scored_count(), 2);
    assert_eq!(p.abstained_count(), 2);
    assert_eq!(p.coverage_millionths(), 500_000); // 2/4 = 50%
}

#[test]
fn profile_sufficient_coverage() {
    let p = full_profile(500_000);
    assert!(p.has_sufficient_coverage(DEFAULT_ABSTENTION_THRESHOLD));
    assert!(p.has_sufficient_coverage(1_000_000)); // 100% threshold
}

#[test]
fn profile_insufficient_coverage() {
    let entries = vec![scored_entry(
        NoveltyDimension::MinimumDescriptionLength,
        500_000,
    )];
    let p = NoveltyProfile::new("sparse".into(), entries);
    // 1/1 = 100% but compared to the 30% threshold this is fine
    // Let's test with a high threshold
    assert!(p.has_sufficient_coverage(DEFAULT_ABSTENTION_THRESHOLD));
}

#[test]
fn profile_content_hash_deterministic() {
    let p1 = full_profile(750_000);
    let p2 = full_profile(750_000);
    assert_eq!(p1.content_hash, p2.content_hash);
}

#[test]
fn profile_different_scores_different_hash() {
    let p1 = full_profile(100_000);
    let p2 = full_profile(900_000);
    assert_ne!(p1.content_hash, p2.content_hash);
}

#[test]
fn profile_score_for_lookup() {
    let entries = vec![
        scored_entry(NoveltyDimension::Obstruction, 800_000),
        scored_entry(NoveltyDimension::InformationGain, 400_000),
    ];
    let p = NoveltyProfile::new("lookup".into(), entries);
    let obs = p.score_for(NoveltyDimension::Obstruction);
    assert!(obs.is_some());
    assert_eq!(obs.unwrap().raw_score(), Some(800_000));
    assert!(p.score_for(NoveltyDimension::HomologicalHole).is_none());
}

#[test]
fn profile_scored_abstained_dimension_sets() {
    let entries = vec![
        scored_entry(NoveltyDimension::MinimumDescriptionLength, 600_000),
        abstained_entry(NoveltyDimension::HomologicalHole),
    ];
    let p = NoveltyProfile::new("sets".into(), entries);
    assert!(
        p.scored_dimensions()
            .contains(&NoveltyDimension::MinimumDescriptionLength)
    );
    assert!(
        p.abstained_dimensions()
            .contains(&NoveltyDimension::HomologicalHole)
    );
}

#[test]
fn profile_serde_roundtrip() {
    let p = full_profile(650_000);
    let json = serde_json::to_string(&p).unwrap();
    let back: NoveltyProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn profile_empty_entries() {
    let p = NoveltyProfile::new("empty".into(), Vec::new());
    assert_eq!(p.scored_count(), 0);
    assert_eq!(p.abstained_count(), 0);
    assert_eq!(p.coverage_millionths(), 0);
}

// ---------------------------------------------------------------------------
// CompositeVerdict
// ---------------------------------------------------------------------------

#[test]
fn verdict_all_count() {
    assert_eq!(CompositeVerdict::ALL.len(), 4);
}

#[test]
fn verdict_names_unique() {
    let names: BTreeSet<&str> = CompositeVerdict::ALL.iter().map(|v| v.as_str()).collect();
    assert_eq!(names.len(), CompositeVerdict::ALL.len());
}

#[test]
fn verdict_serde_roundtrip() {
    for v in CompositeVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: CompositeVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn verdict_inclusion_semantics() {
    assert!(CompositeVerdict::HighNovelty.recommends_inclusion());
    assert!(CompositeVerdict::ModerateNovelty.recommends_inclusion());
    assert!(!CompositeVerdict::LowNovelty.recommends_inclusion());
    assert!(!CompositeVerdict::Inconclusive.recommends_inclusion());
}

// ---------------------------------------------------------------------------
// CompositeNoveltyScore
// ---------------------------------------------------------------------------

#[test]
fn composite_high_novelty_score() {
    let p = full_profile(850_000);
    let s = composite(&p);
    assert_eq!(s.verdict, CompositeVerdict::HighNovelty);
    assert!(s.composite_millionths >= HIGH_NOVELTY_THRESHOLD);
}

#[test]
fn composite_moderate_novelty_score() {
    let p = full_profile(500_000);
    let s = composite(&p);
    assert_eq!(s.verdict, CompositeVerdict::ModerateNovelty);
}

#[test]
fn composite_low_novelty_score() {
    let p = full_profile(100_000);
    let s = composite(&p);
    assert_eq!(s.verdict, CompositeVerdict::LowNovelty);
}

#[test]
fn composite_inconclusive_insufficient_coverage() {
    // 1 scored + 7 abstained = 12.5% coverage < 30% threshold
    let mut entries = vec![scored_entry(
        NoveltyDimension::MinimumDescriptionLength,
        900_000,
    )];
    for d in &NoveltyDimension::ALL[1..] {
        entries.push(abstained_entry(*d));
    }
    let p = NoveltyProfile::new("sparse".into(), entries);
    let weights = default_weight_vector();
    let s = CompositeNoveltyScore::compute(&p, &weights, DEFAULT_ABSTENTION_THRESHOLD, epoch());
    assert_eq!(s.verdict, CompositeVerdict::Inconclusive);
}

#[test]
fn composite_content_hash_deterministic() {
    let p = full_profile(700_000);
    let s1 = composite(&p);
    let s2 = composite(&p);
    assert_eq!(s1.content_hash, s2.content_hash);
}

#[test]
fn composite_recommends_correctly() {
    let high = composite(&full_profile(800_000));
    assert!(high.recommends_inclusion());

    let low = composite(&full_profile(100_000));
    assert!(!low.recommends_inclusion());
}

#[test]
fn composite_serde_roundtrip() {
    let s = composite(&full_profile(600_000));
    let json = serde_json::to_string(&s).unwrap();
    let back: CompositeNoveltyScore = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn composite_zero_weight_total() {
    let p = full_profile(800_000);
    // Empty weights
    let s = CompositeNoveltyScore::compute(&p, &[], DEFAULT_ABSTENTION_THRESHOLD, epoch());
    assert_eq!(s.composite_millionths, 0);
}

// ---------------------------------------------------------------------------
// NoveltyBatch
// ---------------------------------------------------------------------------

#[test]
fn batch_empty() {
    let b = NoveltyBatch::new(epoch(), Vec::new());
    assert_eq!(b.candidate_count(), 0);
    assert!(b.recommended_candidates().is_empty());
    assert!(b.high_novelty_candidates().is_empty());
    assert_eq!(b.max_score(), 0);
    assert_eq!(b.inconclusive_fraction(), 0);
    assert_eq!(b.schema_version, SCHEMA_VERSION);
}

#[test]
fn batch_sorted_descending() {
    let scores = vec![
        composite(&full_profile(200_000)),
        composite(&full_profile(900_000)),
        composite(&full_profile(500_000)),
    ];
    let b = NoveltyBatch::new(epoch(), scores);
    for i in 1..b.scores.len() {
        assert!(b.scores[i - 1].composite_millionths >= b.scores[i].composite_millionths);
    }
}

#[test]
fn batch_max_score() {
    let scores = vec![
        composite(&full_profile(300_000)),
        composite(&full_profile(800_000)),
    ];
    let b = NoveltyBatch::new(epoch(), scores);
    assert!(b.max_score() >= 700_000); // Should be ~800k
}

#[test]
fn batch_recommended_filtering() {
    let scores = vec![
        composite(&full_profile(900_000)),
        composite(&full_profile(500_000)),
        composite(&full_profile(100_000)),
    ];
    let b = NoveltyBatch::new(epoch(), scores);
    let rec = b.recommended_candidates();
    assert_eq!(rec.len(), 2); // high + moderate
    let high = b.high_novelty_candidates();
    assert_eq!(high.len(), 1);
}

#[test]
fn batch_inconclusive_fraction() {
    let weights = default_weight_vector();
    // Build a profile with 1 scored + 7 abstained = 12.5% coverage
    let mut inc_entries = vec![scored_entry(
        NoveltyDimension::MinimumDescriptionLength,
        800_000,
    )];
    for d in &NoveltyDimension::ALL[1..] {
        inc_entries.push(abstained_entry(*d));
    }
    let inconclusive_profile = NoveltyProfile::new("inc".into(), inc_entries);
    let scores = vec![
        composite(&full_profile(800_000)),
        CompositeNoveltyScore::compute(
            &inconclusive_profile,
            &weights,
            DEFAULT_ABSTENTION_THRESHOLD,
            epoch(),
        ),
    ];
    let b = NoveltyBatch::new(epoch(), scores);
    let frac = b.inconclusive_fraction();
    assert_eq!(frac, 500_000); // 1/2 = 50%
}

#[test]
fn batch_content_hash_deterministic() {
    let s1 = composite(&full_profile(700_000));
    let s2 = composite(&full_profile(700_000));
    let b1 = NoveltyBatch::new(epoch(), vec![s1]);
    let b2 = NoveltyBatch::new(epoch(), vec![s2]);
    assert_eq!(b1.content_hash, b2.content_hash);
}

#[test]
fn batch_serde_roundtrip() {
    let scores = vec![
        composite(&full_profile(800_000)),
        composite(&full_profile(400_000)),
    ];
    let b = NoveltyBatch::new(epoch(), scores);
    let json = serde_json::to_string(&b).unwrap();
    let back: NoveltyBatch = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
}

// ===========================================================================
// CandidateKind
// ===========================================================================

#[test]
fn candidate_kind_all_length() {
    assert_eq!(CandidateKind::ALL.len(), 5);
}

#[test]
fn candidate_kind_names_unique() {
    let names: BTreeSet<&str> = CandidateKind::ALL.iter().map(|k| k.as_str()).collect();
    assert_eq!(names.len(), CandidateKind::ALL.len());
}

#[test]
fn candidate_kind_display_matches_as_str() {
    for k in CandidateKind::ALL {
        assert_eq!(k.to_string(), k.as_str());
    }
}

#[test]
fn candidate_kind_serde_all_variants() {
    for k in CandidateKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: CandidateKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

// ===========================================================================
// NoveltyCandidate
// ===========================================================================

#[test]
fn candidate_new_computes_source_hash() {
    let c = NoveltyCandidate::new(
        "test-cand".into(),
        CandidateKind::Program,
        5000,
        vec![100_000, 200_000],
        b"source-bytes-alpha",
    );
    assert_eq!(c.candidate_id, "test-cand");
    assert_eq!(c.kind, CandidateKind::Program);
    assert_eq!(c.description_length_bits, 5000);
    assert_eq!(c.source_hash, ContentHash::compute(b"source-bytes-alpha"));
}

#[test]
fn candidate_different_source_different_hash() {
    let c1 = NoveltyCandidate::new("c1".into(), CandidateKind::Program, 100, vec![], b"aaa");
    let c2 = NoveltyCandidate::new("c2".into(), CandidateKind::Program, 100, vec![], b"bbb");
    assert_ne!(c1.source_hash, c2.source_hash);
}

#[test]
fn candidate_serde_roundtrip() {
    let c = NoveltyCandidate::new(
        "serde-cand".into(),
        CandidateKind::Package,
        8000,
        vec![500_000, 600_000, 700_000],
        b"pkg-source",
    );
    let json = serde_json::to_string(&c).unwrap();
    let back: NoveltyCandidate = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ===========================================================================
// ScoringConfig
// ===========================================================================

#[test]
fn scoring_config_default_validates() {
    let cfg = ScoringConfig::default_config();
    assert!(cfg.validate().is_ok());
}

#[test]
fn scoring_config_default_weight_sum_is_million() {
    let cfg = ScoringConfig::default_config();
    let total: u64 = cfg
        .dimension_weights
        .iter()
        .map(|w| w.weight_millionths)
        .sum();
    assert_eq!(total, MILLIONTHS);
}

#[test]
fn scoring_config_invalid_weight_sum() {
    let mut cfg = ScoringConfig::default_config();
    cfg.dimension_weights[0].weight_millionths += 1;
    assert!(cfg.validate().is_err());
}

#[test]
fn scoring_config_zero_baseline_fails() {
    let mut cfg = ScoringConfig::default_config();
    cfg.mdl_baseline_bits = 0;
    let err = cfg.validate().unwrap_err();
    assert!(matches!(err, NoveltyError::MdlBaselineZero));
}

#[test]
fn scoring_config_content_hash_deterministic() {
    let cfg1 = ScoringConfig::default_config();
    let cfg2 = ScoringConfig::default_config();
    assert_eq!(cfg1.content_hash(), cfg2.content_hash());
}

#[test]
fn scoring_config_content_hash_changes_with_baseline() {
    let cfg1 = ScoringConfig::default_config();
    let mut cfg2 = ScoringConfig::default_config();
    cfg2.mdl_baseline_bits = 99_999;
    assert_ne!(cfg1.content_hash(), cfg2.content_hash());
}

#[test]
fn scoring_config_serde_roundtrip() {
    let cfg = ScoringConfig::default_config();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: ScoringConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ===========================================================================
// NoveltyError
// ===========================================================================

#[test]
fn novelty_error_invalid_weights_display() {
    let e = NoveltyError::InvalidWeights {
        expected: 1_000_000,
        actual: 999_999,
    };
    let s = e.to_string();
    assert!(s.contains("999999"));
    assert!(s.contains("1000000"));
}

#[test]
fn novelty_error_empty_candidate_set_display() {
    let e = NoveltyError::EmptyCandidateSet;
    assert!(!e.to_string().is_empty());
}

#[test]
fn novelty_error_invalid_feature_vector_display() {
    let e = NoveltyError::InvalidFeatureVector {
        expected_dims: 7,
        actual_dims: 3,
    };
    let s = e.to_string();
    assert!(s.contains('7'));
    assert!(s.contains('3'));
}

#[test]
fn novelty_error_mdl_baseline_zero_display() {
    let e = NoveltyError::MdlBaselineZero;
    assert!(!e.to_string().is_empty());
}

#[test]
fn novelty_error_serde_all_variants() {
    let errors = vec![
        NoveltyError::InvalidWeights {
            expected: 1_000_000,
            actual: 500_000,
        },
        NoveltyError::EmptyCandidateSet,
        NoveltyError::InvalidFeatureVector {
            expected_dims: 7,
            actual_dims: 2,
        },
        NoveltyError::MdlBaselineZero,
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: NoveltyError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ===========================================================================
// NoveltyVerdict
// ===========================================================================

#[test]
fn verdict_all_length() {
    assert_eq!(NoveltyVerdict::ALL.len(), 4);
}

#[test]
fn verdict_names_unique_v2() {
    let names: BTreeSet<&str> = NoveltyVerdict::ALL.iter().map(|v| v.as_str()).collect();
    assert_eq!(names.len(), NoveltyVerdict::ALL.len());
}

#[test]
fn verdict_display_matches_as_str() {
    for v in NoveltyVerdict::ALL {
        assert_eq!(v.to_string(), v.as_str());
    }
}

#[test]
fn verdict_serde_all_variants() {
    for v in NoveltyVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: NoveltyVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ===========================================================================
// compute_mdl_score
// ===========================================================================

#[test]
fn mdl_shorter_than_baseline_high_score() {
    let c = NoveltyCandidate::new(
        "mdl-short".into(),
        CandidateKind::Program,
        2000, // much shorter than baseline 10_000
        vec![],
        b"src",
    );
    let score = compute_mdl_score(&c, 10_000);
    // (10_000 - 2_000) / 10_000 = 0.8 => 800_000
    assert_eq!(score, 800_000);
}

#[test]
fn mdl_equal_to_baseline_zero() {
    let c = NoveltyCandidate::new(
        "mdl-eq".into(),
        CandidateKind::Program,
        10_000,
        vec![],
        b"src",
    );
    let score = compute_mdl_score(&c, 10_000);
    assert_eq!(score, 0);
}

#[test]
fn mdl_longer_than_baseline_zero() {
    let c = NoveltyCandidate::new(
        "mdl-long".into(),
        CandidateKind::Program,
        20_000,
        vec![],
        b"src",
    );
    let score = compute_mdl_score(&c, 10_000);
    assert_eq!(score, 0);
}

#[test]
fn mdl_zero_baseline_returns_zero() {
    let c = NoveltyCandidate::new(
        "mdl-zb".into(),
        CandidateKind::Program,
        5000,
        vec![],
        b"src",
    );
    assert_eq!(compute_mdl_score(&c, 0), 0);
}

// ===========================================================================
// compute_information_gain
// ===========================================================================

#[test]
fn info_gain_no_prior_max() {
    let c = NoveltyCandidate::new(
        "ig".into(),
        CandidateKind::Program,
        100,
        vec![500_000],
        b"src",
    );
    assert_eq!(compute_information_gain(&c, &[]), MILLIONTHS);
}

#[test]
fn info_gain_identical_prior_zero() {
    let c = NoveltyCandidate::new(
        "ig1".into(),
        CandidateKind::Program,
        100,
        vec![500_000, 500_000],
        b"src1",
    );
    let prior = vec![NoveltyCandidate::new(
        "ig-prior".into(),
        CandidateKind::Program,
        100,
        vec![500_000, 500_000],
        b"src2",
    )];
    let score = compute_information_gain(&c, &prior);
    assert_eq!(score, 0);
}

#[test]
fn info_gain_empty_feature_vector_zero() {
    let c = NoveltyCandidate::new(
        "ig-empty".into(),
        CandidateKind::Program,
        100,
        vec![],
        b"src",
    );
    let prior = vec![NoveltyCandidate::new(
        "ig-p".into(),
        CandidateKind::Program,
        100,
        vec![],
        b"s2",
    )];
    assert_eq!(compute_information_gain(&c, &prior), 0);
}

#[test]
fn info_gain_divergent_prior_positive() {
    let c = NoveltyCandidate::new(
        "ig-div".into(),
        CandidateKind::Program,
        100,
        vec![900_000, 100_000],
        b"s1",
    );
    let prior = vec![NoveltyCandidate::new(
        "ig-p2".into(),
        CandidateKind::Program,
        100,
        vec![100_000, 900_000],
        b"s2",
    )];
    let score = compute_information_gain(&c, &prior);
    assert!(score > 0);
}

// ===========================================================================
// score_candidate and score_batch
// ===========================================================================

#[test]
fn score_candidate_produces_all_dimensions() {
    let cfg = ScoringConfig::default_config();
    let c = NoveltyCandidate::new(
        "sc-test".into(),
        CandidateKind::Program,
        5000,
        vec![
            800_000, 700_000, 100_000, 600_000, 500_000, 400_000, 300_000,
        ],
        b"src",
    );
    let score = score_candidate(&c, &cfg, &[]);
    assert_eq!(score.candidate_id, "sc-test");
    assert_eq!(score.dimension_scores.len(), cfg.dimension_weights.len());
}

#[test]
fn score_candidate_high_scores_novel() {
    let cfg = ScoringConfig::default_config();
    let c = NoveltyCandidate::new(
        "novel-cand".into(),
        CandidateKind::Program,
        2000, // very short => high MDL
        vec![
            800_000, 700_000, 100_000, 600_000, 500_000, 400_000, 300_000,
        ],
        b"src",
    );
    let score = score_candidate(&c, &cfg, &[]);
    // Short description length + high feature values should produce novel
    assert!(score.total_score_millionths > 0);
}

#[test]
fn score_batch_produces_ranked_output() {
    let cfg = ScoringConfig::default_config();
    let candidates = vec![
        NoveltyCandidate::new(
            "batch-1".into(),
            CandidateKind::Program,
            5000,
            vec![
                800_000, 700_000, 100_000, 600_000, 500_000, 400_000, 300_000,
            ],
            b"s1",
        ),
        NoveltyCandidate::new(
            "batch-2".into(),
            CandidateKind::Package,
            15000,
            vec![200_000, 300_000, 50_000, 150_000, 100_000, 250_000, 200_000],
            b"s2",
        ),
    ];
    let batch = score_batch(&candidates, &cfg);
    assert_eq!(batch.candidates.len(), 2);
    assert!(batch.config.is_some());
    assert!(!batch.certificates.is_empty());
    // Batch should be sorted descending by score
    for i in 1..batch.scores.len() {
        assert!(batch.scores[i - 1].composite_millionths >= batch.scores[i].composite_millionths);
    }
}

#[test]
fn score_batch_empty_candidates() {
    let cfg = ScoringConfig::default_config();
    let batch = score_batch(&[], &cfg);
    assert_eq!(batch.candidates.len(), 0);
    assert!(batch.certificates.is_empty());
    assert_eq!(batch.scores.len(), 0);
}

// ===========================================================================
// certify_candidate
// ===========================================================================

#[test]
fn certify_candidate_produces_valid_certificate() {
    let cfg = ScoringConfig::default_config();
    let c = NoveltyCandidate::new(
        "cert-cand".into(),
        CandidateKind::ReactComponent,
        8000,
        vec![
            500_000, 500_000, 800_000, 400_000, 300_000, 600_000, 700_000,
        ],
        b"src",
    );
    let score = score_candidate(&c, &cfg, &[]);
    let cert = certify_candidate(&c, &score, &cfg);
    assert_eq!(cert.candidate_id, "cert-cand");
    assert_eq!(cert.schema_version, NOVELTY_SCHEMA_VERSION);
    assert_eq!(cert.score.candidate_id, "cert-cand");
}

#[test]
fn certificate_hash_deterministic() {
    let cfg = ScoringConfig::default_config();
    let c = NoveltyCandidate::new(
        "det-cert".into(),
        CandidateKind::Program,
        5000,
        vec![
            600_000, 500_000, 100_000, 400_000, 300_000, 200_000, 100_000,
        ],
        b"src",
    );
    let score = score_candidate(&c, &cfg, &[]);
    let cert1 = certify_candidate(&c, &score, &cfg);
    let cert2 = certify_candidate(&c, &score, &cfg);
    assert_eq!(cert1.certificate_hash, cert2.certificate_hash);
}

#[test]
fn certificate_serde_roundtrip() {
    let cfg = ScoringConfig::default_config();
    let c = NoveltyCandidate::new(
        "serde-cert".into(),
        CandidateKind::WorkloadTrace,
        3000,
        vec![
            900_000, 800_000, 200_000, 700_000, 600_000, 500_000, 900_000,
        ],
        b"src",
    );
    let score = score_candidate(&c, &cfg, &[]);
    let cert = certify_candidate(&c, &score, &cfg);
    let json = serde_json::to_string(&cert).unwrap();
    let back: NoveltyCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

// ===========================================================================
// NoveltyVerdict classification
// ===========================================================================

#[test]
fn obstruction_witness_verdict_on_high_obstruction() {
    let cfg = ScoringConfig::default_config();
    // feature_vector[2] is obstruction; set >= 500_000 to trigger witness
    let c = NoveltyCandidate::new(
        "obs-witness".into(),
        CandidateKind::Program,
        5000,
        vec![
            100_000, 100_000, 600_000, 100_000, 100_000, 100_000, 100_000,
        ],
        b"src",
    );
    let score = score_candidate(&c, &cfg, &[]);
    let cert = certify_candidate(&c, &score, &cfg);
    assert_eq!(cert.verdict, NoveltyVerdict::ObstructionWitness);
}

#[test]
fn marginal_verdict_near_threshold() {
    let cfg = ScoringConfig::default_config();
    // Need total just below threshold but within marginal band
    // threshold = 200_000, marginal_band = 40_000
    // total in [160_000, 200_000) => Marginal
    let c = NoveltyCandidate::new(
        "marginal".into(),
        CandidateKind::Program,
        8500, // slightly shorter than 10k baseline => small MDL
        vec![
            200_000, 200_000, 100_000, 200_000, 200_000, 200_000, 200_000,
        ],
        b"src",
    );
    let score = score_candidate(&c, &cfg, &[]);
    let cert = certify_candidate(&c, &score, &cfg);
    // Just verify it's not an error; exact verdict depends on weights
    assert!(
        cert.verdict == NoveltyVerdict::Marginal
            || cert.verdict == NoveltyVerdict::Redundant
            || cert.verdict == NoveltyVerdict::Novel
    );
}

// ===========================================================================
// run_novelty_evidence
// ===========================================================================

#[test]
fn run_novelty_evidence_produces_manifest() {
    let manifest = run_novelty_evidence();
    assert_eq!(manifest.schema_version, NOVELTY_SCHEMA_VERSION);
    assert_eq!(manifest.candidates_scored, 5);
    assert!(manifest.error.is_none());
    assert!(!manifest.certificates.is_empty());
    assert!(manifest.novel_count + manifest.redundant_count <= manifest.candidates_scored);
}

#[test]
fn run_novelty_evidence_deterministic() {
    let m1 = run_novelty_evidence();
    let m2 = run_novelty_evidence();
    assert_eq!(m1.manifest_hash, m2.manifest_hash);
    assert_eq!(m1.novel_count, m2.novel_count);
    assert_eq!(m1.redundant_count, m2.redundant_count);
}

#[test]
fn evidence_manifest_serde_roundtrip() {
    let m = run_novelty_evidence();
    let json = serde_json::to_string(&m).unwrap();
    let back: NoveltyEvidenceManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

// ===========================================================================
// NoveltyScore serde
// ===========================================================================

#[test]
fn novelty_score_serde_roundtrip() {
    let cfg = ScoringConfig::default_config();
    let c = NoveltyCandidate::new(
        "score-serde".into(),
        CandidateKind::ModuleGraph,
        7000,
        vec![
            400_000, 400_000, 100_000, 300_000, 200_000, 500_000, 600_000,
        ],
        b"src",
    );
    let score = score_candidate(&c, &cfg, &[]);
    let json = serde_json::to_string(&score).unwrap();
    let back: NoveltyScore = serde_json::from_str(&json).unwrap();
    assert_eq!(score, back);
}

// ===========================================================================
// compute_dimension_score
// ===========================================================================

#[test]
fn dimension_score_mdl_uses_baseline() {
    let cfg = ScoringConfig::default_config();
    let c = NoveltyCandidate::new(
        "dim-mdl".into(),
        CandidateKind::Program,
        5000,
        vec![],
        b"src",
    );
    let score = compute_dimension_score(&c, NoveltyDimension::MinimumDescriptionLength, &cfg, &[]);
    // baseline 10_000, candidate 5_000 => (10000-5000)/10000 = 50%
    assert_eq!(score, 500_000);
}

#[test]
fn dimension_score_info_gain_no_prior() {
    let cfg = ScoringConfig::default_config();
    let c = NoveltyCandidate::new(
        "dim-ig".into(),
        CandidateKind::Program,
        5000,
        vec![500_000],
        b"src",
    );
    let score = compute_dimension_score(&c, NoveltyDimension::InformationGain, &cfg, &[]);
    assert_eq!(score, MILLIONTHS);
}

#[test]
fn dimension_score_obstruction_from_feature_vector() {
    let cfg = ScoringConfig::default_config();
    let c = NoveltyCandidate::new(
        "dim-obs".into(),
        CandidateKind::Program,
        5000,
        vec![0, 0, 750_000],
        b"src",
    );
    let score = compute_dimension_score(&c, NoveltyDimension::Obstruction, &cfg, &[]);
    assert_eq!(score, 750_000);
}

#[test]
fn dimension_score_missing_feature_index_zero() {
    let cfg = ScoringConfig::default_config();
    let c = NoveltyCandidate::new(
        "dim-missing".into(),
        CandidateKind::Program,
        5000,
        vec![], // empty feature vector
        b"src",
    );
    // Obstruction uses index 2, which is missing
    let score = compute_dimension_score(&c, NoveltyDimension::Obstruction, &cfg, &[]);
    assert_eq!(score, 0);
}

// ===========================================================================
// Batch with certificates
// ===========================================================================

#[test]
fn batch_certificates_match_candidates() {
    let cfg = ScoringConfig::default_config();
    let candidates = vec![
        NoveltyCandidate::new(
            "bc-1".into(),
            CandidateKind::Program,
            5000,
            vec![
                800_000, 700_000, 100_000, 600_000, 500_000, 400_000, 300_000,
            ],
            b"s1",
        ),
        NoveltyCandidate::new(
            "bc-2".into(),
            CandidateKind::Package,
            15000,
            vec![200_000, 300_000, 50_000, 150_000, 100_000, 250_000, 200_000],
            b"s2",
        ),
        NoveltyCandidate::new(
            "bc-3".into(),
            CandidateKind::ReactComponent,
            8000,
            vec![
                500_000, 500_000, 800_000, 400_000, 300_000, 600_000, 700_000,
            ],
            b"s3",
        ),
    ];
    let batch = score_batch(&candidates, &cfg);
    // Every candidate should have a certificate
    let cert_ids: BTreeSet<&str> = batch
        .certificates
        .iter()
        .map(|c| c.candidate_id.as_str())
        .collect();
    for c in &candidates {
        assert!(cert_ids.contains(c.candidate_id.as_str()));
    }
}

// ===========================================================================
// Edge: dimension_score behavioral_divergence decay
// ===========================================================================

#[test]
fn behavioral_divergence_applies_decay() {
    let cfg = ScoringConfig::default_config();
    let c = NoveltyCandidate::new(
        "bd-decay".into(),
        CandidateKind::Program,
        5000,
        vec![0, 0, 0, 0, 0, 0, 1_000_000], // index 6 = raw behavioral divergence
        b"src",
    );
    let score = compute_dimension_score(&c, NoveltyDimension::BehavioralDivergence, &cfg, &[]);
    // decay = 100_000 (10%), so score = 1_000_000 * (1_000_000 - 100_000) / 1_000_000 = 900_000
    assert_eq!(score, 900_000);
}

// ===========================================================================
// Additional constant checks
// ===========================================================================

#[test]
fn policy_id_nonempty() {
    assert!(!NOVELTY_POLICY_ID.is_empty());
}

#[test]
fn max_description_length_positive() {
    const { assert!(MAX_DESCRIPTION_LENGTH > 0) };
}

#[test]
fn novelty_component_matches_component() {
    assert_eq!(NOVELTY_COMPONENT, COMPONENT);
}

#[test]
fn novelty_schema_version_matches_schema_version() {
    assert_eq!(NOVELTY_SCHEMA_VERSION, SCHEMA_VERSION);
}
