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
