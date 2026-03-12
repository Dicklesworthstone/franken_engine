// Enrichment integration tests for hardware_localization_residual module.
//
// Covers: hardware feature classification, microarch family ISA checks,
// localization entry arithmetic, promotion policy lifecycle, board evaluation,
// unsupported hardware detection, serde round-trips, hash determinism.
//
// Bead: bd-1lsy.7.16.3 [RGC-616C]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::hardware_localization_residual::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn make_residual(
    algo: u64,
    hw: u64,
    noise: u64,
    unexplained: u64,
) -> BTreeMap<ResidualCategory, u64> {
    let mut m = BTreeMap::new();
    m.insert(ResidualCategory::AlgorithmicGain, algo);
    m.insert(ResidualCategory::HardwareAttributable, hw);
    m.insert(ResidualCategory::MeasurementNoise, noise);
    m.insert(ResidualCategory::Unexplained, unexplained);
    m
}

fn make_entry(
    family: MicroarchFamily,
    baseline: u64,
    optimized: u64,
    algo: u64,
    hw: u64,
) -> LocalizationEntry {
    let features = family.typical_features();
    let residual = make_residual(algo, hw, 50_000, MILLIONTHS - algo - hw - 50_000);
    LocalizationEntry::new(family, features, baseline, optimized, residual)
}

// ---------------------------------------------------------------------------
// HardwareFeature classification
// ---------------------------------------------------------------------------

#[test]
fn test_hardware_feature_count() {
    assert_eq!(HardwareFeature::ALL.len(), 13);
}

#[test]
fn test_hardware_feature_all_unique() {
    let set: BTreeSet<HardwareFeature> = HardwareFeature::ALL.iter().copied().collect();
    assert_eq!(set.len(), 13);
}

#[test]
fn test_x86_features() {
    assert!(HardwareFeature::Avx2.is_x86());
    assert!(HardwareFeature::Avx512.is_x86());
    assert!(HardwareFeature::Bmi2.is_x86());
    assert!(HardwareFeature::Clmul.is_x86());
    assert!(!HardwareFeature::Neon.is_x86());
    assert!(!HardwareFeature::Aes.is_x86());
}

#[test]
fn test_arm_features() {
    assert!(HardwareFeature::Neon.is_arm());
    assert!(HardwareFeature::Sve.is_arm());
    assert!(!HardwareFeature::Avx2.is_arm());
    assert!(!HardwareFeature::PopcntHw.is_arm());
}

#[test]
fn test_neutral_features() {
    assert!(HardwareFeature::PopcntHw.is_neutral());
    assert!(HardwareFeature::Aes.is_neutral());
    assert!(HardwareFeature::CacheLinePrefetch.is_neutral());
    assert!(HardwareFeature::Numa.is_neutral());
    assert!(HardwareFeature::LargePages.is_neutral());
    assert!(HardwareFeature::BranchPredictor.is_neutral());
    assert!(HardwareFeature::Sha.is_neutral());
    assert!(!HardwareFeature::Avx2.is_neutral());
    assert!(!HardwareFeature::Neon.is_neutral());
}

#[test]
fn test_hardware_feature_display_all() {
    for feat in HardwareFeature::ALL {
        let s = feat.to_string();
        assert!(!s.is_empty());
        assert_eq!(s, feat.as_str());
    }
}

// ---------------------------------------------------------------------------
// MicroarchFamily ISA classification
// ---------------------------------------------------------------------------

#[test]
fn test_microarch_family_count() {
    assert_eq!(MicroarchFamily::ALL.len(), 8);
}

#[test]
fn test_microarch_x86_families() {
    assert!(MicroarchFamily::Zen4.is_x86());
    assert!(MicroarchFamily::Zen5.is_x86());
    assert!(MicroarchFamily::AlderLake.is_x86());
    assert!(MicroarchFamily::RaptorLake.is_x86());
    assert!(MicroarchFamily::GenericX64.is_x86());
    assert!(!MicroarchFamily::GravitonArm.is_x86());
    assert!(!MicroarchFamily::AppleM.is_x86());
}

#[test]
fn test_microarch_arm_families() {
    assert!(MicroarchFamily::GravitonArm.is_arm());
    assert!(MicroarchFamily::AppleM.is_arm());
    assert!(MicroarchFamily::GenericArm64.is_arm());
    assert!(!MicroarchFamily::Zen4.is_arm());
    assert!(!MicroarchFamily::GenericX64.is_arm());
}

#[test]
fn test_microarch_typical_features_nonempty() {
    for family in MicroarchFamily::ALL {
        let features = family.typical_features();
        assert!(
            !features.is_empty(),
            "{family:?} should have typical features"
        );
    }
}

#[test]
fn test_zen4_has_avx512() {
    let features = MicroarchFamily::Zen4.typical_features();
    assert!(features.contains(&HardwareFeature::Avx512));
}

#[test]
fn test_graviton_has_neon() {
    let features = MicroarchFamily::GravitonArm.typical_features();
    assert!(features.contains(&HardwareFeature::Neon));
}

#[test]
fn test_generic_x64_minimal_features() {
    let features = MicroarchFamily::GenericX64.typical_features();
    assert!(features.contains(&HardwareFeature::PopcntHw));
    assert!(!features.contains(&HardwareFeature::Avx512));
}

#[test]
fn test_microarch_display_all() {
    for family in MicroarchFamily::ALL {
        let s = family.to_string();
        assert!(!s.is_empty());
        assert_eq!(s, family.as_str());
    }
}

// ---------------------------------------------------------------------------
// ResidualCategory
// ---------------------------------------------------------------------------

#[test]
fn test_residual_category_count() {
    assert_eq!(ResidualCategory::ALL.len(), 4);
}

#[test]
fn test_residual_category_display_all() {
    let expected = [
        "hardware_attributable",
        "algorithmic_gain",
        "measurement_noise",
        "unexplained",
    ];
    for (cat, name) in ResidualCategory::ALL.iter().zip(expected.iter()) {
        assert_eq!(cat.to_string(), *name);
    }
}

// ---------------------------------------------------------------------------
// LocalizationEntry arithmetic
// ---------------------------------------------------------------------------

#[test]
fn test_entry_speedup_positive() {
    let entry = make_entry(MicroarchFamily::Zen4, 1000, 800, 700_000, 200_000);
    assert_eq!(entry.speedup_millionths(), 200_000);
}

#[test]
fn test_entry_speedup_zero_when_no_improvement() {
    let entry = make_entry(MicroarchFamily::Zen4, 1000, 1000, 500_000, 300_000);
    assert_eq!(entry.speedup_millionths(), 0);
}

#[test]
fn test_entry_speedup_zero_when_regression() {
    let entry = make_entry(MicroarchFamily::Zen4, 1000, 1200, 500_000, 300_000);
    assert_eq!(entry.speedup_millionths(), 0);
}

#[test]
fn test_entry_speedup_zero_baseline() {
    let entry = make_entry(MicroarchFamily::Zen4, 0, 0, 500_000, 300_000);
    assert_eq!(entry.speedup_millionths(), 0);
}

#[test]
fn test_entry_algorithmic_fraction() {
    let entry = make_entry(MicroarchFamily::Zen4, 1000, 800, 700_000, 200_000);
    assert_eq!(entry.algorithmic_fraction(), 700_000);
}

#[test]
fn test_entry_hardware_fraction() {
    let entry = make_entry(MicroarchFamily::Zen4, 1000, 800, 700_000, 200_000);
    assert_eq!(entry.hardware_fraction(), 200_000);
}

#[test]
fn test_entry_residual_sum() {
    let entry = make_entry(MicroarchFamily::Zen4, 1000, 800, 700_000, 200_000);
    assert_eq!(entry.residual_sum(), MILLIONTHS);
}

#[test]
fn test_entry_hash_deterministic() {
    let a = make_entry(MicroarchFamily::AlderLake, 2000, 1500, 600_000, 250_000);
    let b = make_entry(MicroarchFamily::AlderLake, 2000, 1500, 600_000, 250_000);
    assert_eq!(a.entry_hash, b.entry_hash);
}

#[test]
fn test_entry_hash_differs_by_family() {
    let a = make_entry(MicroarchFamily::AlderLake, 2000, 1500, 600_000, 250_000);
    let b = make_entry(MicroarchFamily::RaptorLake, 2000, 1500, 600_000, 250_000);
    assert_ne!(a.entry_hash, b.entry_hash);
}

#[test]
fn test_entry_features_available_on_same_family() {
    let entry = make_entry(MicroarchFamily::Zen4, 1000, 800, 700_000, 200_000);
    assert!(entry.features_available_on(MicroarchFamily::Zen4));
}

#[test]
fn test_entry_features_not_available_cross_isa() {
    let mut features = BTreeSet::new();
    features.insert(HardwareFeature::Avx512);
    let residual = make_residual(700_000, 200_000, 50_000, 50_000);
    let entry = LocalizationEntry::new(MicroarchFamily::Zen4, features, 1000, 800, residual);
    assert!(!entry.features_available_on(MicroarchFamily::GravitonArm));
}

// ---------------------------------------------------------------------------
// PromotionPolicy
// ---------------------------------------------------------------------------

#[test]
fn test_policy_strict_tighter_than_relaxed() {
    let s = PromotionPolicy::strict();
    let r = PromotionPolicy::relaxed();
    assert!(s.min_algorithmic_gain_millionths >= r.min_algorithmic_gain_millionths);
    assert!(s.max_hardware_attributable_millionths <= r.max_hardware_attributable_millionths);
    assert!(s.min_hardware_families_tested >= r.min_hardware_families_tested);
    assert!(s.max_noise_millionths <= r.max_noise_millionths);
}

#[test]
fn test_policy_default_is_strict() {
    let d = PromotionPolicy::default();
    let s = PromotionPolicy::strict();
    assert_eq!(d, s);
}

#[test]
fn test_policy_strict_requires_arm_and_x64() {
    let s = PromotionPolicy::strict();
    assert!(s.require_arm_and_x64);
}

#[test]
fn test_policy_relaxed_no_arm_x64_required() {
    let r = PromotionPolicy::relaxed();
    assert!(!r.require_arm_and_x64);
}

// ---------------------------------------------------------------------------
// PromotionVerdict
// ---------------------------------------------------------------------------

#[test]
fn test_verdict_only_promotable_passes() {
    assert!(PromotionVerdict::Promotable.is_pass());
    assert!(!PromotionVerdict::HardwareDependent.is_pass());
    assert!(!PromotionVerdict::InsufficientEvidence.is_pass());
    assert!(!PromotionVerdict::Rejected.is_pass());
}

#[test]
fn test_verdict_display() {
    assert_eq!(PromotionVerdict::Promotable.to_string(), "promotable");
    assert_eq!(
        PromotionVerdict::HardwareDependent.to_string(),
        "hardware_dependent"
    );
    assert_eq!(
        PromotionVerdict::InsufficientEvidence.to_string(),
        "insufficient_evidence"
    );
    assert_eq!(PromotionVerdict::Rejected.to_string(), "rejected");
}

// ---------------------------------------------------------------------------
// LocalizationBoard lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_board_starts_empty() {
    let board = LocalizationBoard::new("opt-1", epoch(), PromotionPolicy::relaxed());
    assert_eq!(board.entry_count(), 0);
    assert_eq!(board.family_count(), 0);
}

#[test]
fn test_board_add_entry_increments_count() {
    let mut board = LocalizationBoard::new("opt-1", epoch(), PromotionPolicy::relaxed());
    let entry = make_entry(MicroarchFamily::Zen4, 1000, 800, 700_000, 200_000);
    assert!(board.add_entry(entry));
    assert_eq!(board.entry_count(), 1);
    assert_eq!(board.family_count(), 1);
}

#[test]
fn test_board_distinct_families() {
    let mut board = LocalizationBoard::new("opt-1", epoch(), PromotionPolicy::relaxed());
    board.add_entry(make_entry(
        MicroarchFamily::Zen4,
        1000,
        800,
        700_000,
        200_000,
    ));
    board.add_entry(make_entry(
        MicroarchFamily::GravitonArm,
        1000,
        850,
        650_000,
        200_000,
    ));
    let families = board.distinct_families();
    assert_eq!(families.len(), 2);
    assert!(families.contains(&MicroarchFamily::Zen4));
    assert!(families.contains(&MicroarchFamily::GravitonArm));
}

#[test]
fn test_board_has_arm_and_x64() {
    let mut board = LocalizationBoard::new("opt-1", epoch(), PromotionPolicy::relaxed());
    board.add_entry(make_entry(
        MicroarchFamily::Zen4,
        1000,
        800,
        700_000,
        200_000,
    ));
    assert!(!board.has_arm_and_x64());
    board.add_entry(make_entry(
        MicroarchFamily::GravitonArm,
        1000,
        850,
        650_000,
        200_000,
    ));
    assert!(board.has_arm_and_x64());
}

#[test]
fn test_board_avg_algorithmic_gain() {
    let mut board = LocalizationBoard::new("opt-1", epoch(), PromotionPolicy::relaxed());
    board.add_entry(make_entry(
        MicroarchFamily::Zen4,
        1000,
        800,
        700_000,
        200_000,
    ));
    board.add_entry(make_entry(
        MicroarchFamily::AlderLake,
        1000,
        850,
        500_000,
        300_000,
    ));
    let avg = board.avg_algorithmic_gain();
    assert_eq!(avg, 600_000);
}

#[test]
fn test_board_avg_algorithmic_gain_empty() {
    let board = LocalizationBoard::new("opt-1", epoch(), PromotionPolicy::relaxed());
    assert_eq!(board.avg_algorithmic_gain(), 0);
}

#[test]
fn test_board_max_hardware_attributable() {
    let mut board = LocalizationBoard::new("opt-1", epoch(), PromotionPolicy::relaxed());
    board.add_entry(make_entry(
        MicroarchFamily::Zen4,
        1000,
        800,
        700_000,
        200_000,
    ));
    board.add_entry(make_entry(
        MicroarchFamily::AlderLake,
        1000,
        850,
        400_000,
        400_000,
    ));
    assert_eq!(board.max_hardware_attributable(), 400_000);
}

#[test]
fn test_board_avg_speedup() {
    let mut board = LocalizationBoard::new("opt-1", epoch(), PromotionPolicy::relaxed());
    board.add_entry(make_entry(
        MicroarchFamily::Zen4,
        1000,
        800,
        700_000,
        200_000,
    ));
    board.add_entry(make_entry(
        MicroarchFamily::AlderLake,
        1000,
        900,
        600_000,
        200_000,
    ));
    let avg = board.avg_speedup();
    assert_eq!(avg, 150_000);
}

// ---------------------------------------------------------------------------
// UnsupportedHardwareEntry
// ---------------------------------------------------------------------------

#[test]
fn test_unsupported_hardware_hash_deterministic() {
    let mut missing = BTreeSet::new();
    missing.insert(HardwareFeature::Avx512);
    let a =
        UnsupportedHardwareEntry::new(MicroarchFamily::GravitonArm, missing.clone(), 50_000, true);
    let b = UnsupportedHardwareEntry::new(MicroarchFamily::GravitonArm, missing, 50_000, true);
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn test_unsupported_hardware_hash_differs_by_fallback() {
    let mut missing = BTreeSet::new();
    missing.insert(HardwareFeature::Avx512);
    let a =
        UnsupportedHardwareEntry::new(MicroarchFamily::GravitonArm, missing.clone(), 50_000, true);
    let b = UnsupportedHardwareEntry::new(MicroarchFamily::GravitonArm, missing, 50_000, false);
    assert_ne!(a.content_hash, b.content_hash);
}

#[test]
fn test_unsupported_hardware_display() {
    let mut missing = BTreeSet::new();
    missing.insert(HardwareFeature::Avx512);
    missing.insert(HardwareFeature::Bmi2);
    let entry =
        UnsupportedHardwareEntry::new(MicroarchFamily::GravitonArm, missing, 100_000, false);
    let display = format!("{entry}");
    assert!(display.contains("graviton_arm"));
    assert!(display.contains("2 missing"));
}

// ---------------------------------------------------------------------------
// Board hash determinism
// ---------------------------------------------------------------------------

#[test]
fn test_board_hash_deterministic() {
    let mut b1 = LocalizationBoard::new("opt-1", epoch(), PromotionPolicy::relaxed());
    let mut b2 = LocalizationBoard::new("opt-1", epoch(), PromotionPolicy::relaxed());
    let entry = make_entry(MicroarchFamily::Zen4, 1000, 800, 700_000, 200_000);
    b1.add_entry(entry.clone());
    b2.add_entry(entry);
    assert_eq!(b1.content_hash, b2.content_hash);
}

#[test]
fn test_board_hash_changes_with_entry() {
    let mut board = LocalizationBoard::new("opt-1", epoch(), PromotionPolicy::relaxed());
    let hash_empty = board.content_hash;
    board.add_entry(make_entry(
        MicroarchFamily::Zen4,
        1000,
        800,
        700_000,
        200_000,
    ));
    assert_ne!(hash_empty, board.content_hash);
}

// ---------------------------------------------------------------------------
// Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn test_hardware_feature_serde_roundtrip() {
    for feat in HardwareFeature::ALL {
        let json = serde_json::to_string(feat).unwrap();
        let back: HardwareFeature = serde_json::from_str(&json).unwrap();
        assert_eq!(*feat, back);
    }
}

#[test]
fn test_microarch_family_serde_roundtrip() {
    for family in MicroarchFamily::ALL {
        let json = serde_json::to_string(family).unwrap();
        let back: MicroarchFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*family, back);
    }
}

#[test]
fn test_residual_category_serde_roundtrip() {
    for cat in ResidualCategory::ALL {
        let json = serde_json::to_string(cat).unwrap();
        let back: ResidualCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*cat, back);
    }
}

#[test]
fn test_promotion_verdict_serde_roundtrip() {
    let verdicts = [
        PromotionVerdict::Promotable,
        PromotionVerdict::HardwareDependent,
        PromotionVerdict::InsufficientEvidence,
        PromotionVerdict::Rejected,
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let back: PromotionVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn test_promotion_policy_serde_roundtrip() {
    let policy = PromotionPolicy::strict();
    let json = serde_json::to_string(&policy).unwrap();
    let back: PromotionPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

#[test]
fn test_localization_entry_serde_roundtrip() {
    let entry = make_entry(MicroarchFamily::AppleM, 1000, 750, 600_000, 250_000);
    let json = serde_json::to_string(&entry).unwrap();
    let back: LocalizationEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ---------------------------------------------------------------------------
// RejectionDetail display
// ---------------------------------------------------------------------------

#[test]
fn test_rejection_detail_algorithmic_display() {
    let d = RejectionDetail::AlgorithmicGainTooLow {
        observed_millionths: 400_000,
        threshold_millionths: 600_000,
    };
    let s = format!("{d}");
    assert!(s.contains("400000"));
    assert!(s.contains("600000"));
}

#[test]
fn test_rejection_detail_too_few_families_display() {
    let d = RejectionDetail::TooFewFamilies {
        tested: 1,
        required: 3,
    };
    let s = format!("{d}");
    assert!(s.contains("1"));
    assert!(s.contains("3"));
}

#[test]
fn test_rejection_detail_missing_isa_display() {
    let d = RejectionDetail::MissingIsaCoverage {
        has_arm: false,
        has_x64: true,
    };
    let s = format!("{d}");
    assert!(s.contains("arm=false"));
    assert!(s.contains("x64=true"));
}

#[test]
fn test_rejection_detail_empty_board() {
    let d = RejectionDetail::EmptyBoard;
    assert_eq!(format!("{d}"), "no entries in board");
}

#[test]
fn test_rejection_detail_no_speedup() {
    let d = RejectionDetail::NoSpeedupObserved;
    assert_eq!(format!("{d}"), "no speedup observed");
}
