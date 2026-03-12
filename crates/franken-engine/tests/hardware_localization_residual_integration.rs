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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::hardware_localization_residual::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn features(fs: &[HardwareFeature]) -> BTreeSet<HardwareFeature> {
    fs.iter().copied().collect()
}

fn make_residual(algo: u64, hw: u64, noise: u64, unexplained: u64) -> BTreeMap<ResidualCategory, u64> {
    let mut m = BTreeMap::new();
    m.insert(ResidualCategory::AlgorithmicGain, algo);
    m.insert(ResidualCategory::HardwareAttributable, hw);
    m.insert(ResidualCategory::MeasurementNoise, noise);
    m.insert(ResidualCategory::Unexplained, unexplained);
    m
}

fn make_entry(
    family: MicroarchFamily,
    required: &[HardwareFeature],
    baseline_ns: u64,
    optimized_ns: u64,
    algo: u64,
    hw: u64,
    noise: u64,
    unexplained: u64,
) -> LocalizationEntry {
    LocalizationEntry::new(
        family,
        features(required),
        baseline_ns,
        optimized_ns,
        make_residual(algo, hw, noise, unexplained),
    )
}

fn make_promotable_board() -> LocalizationBoard {
    let policy = PromotionPolicy::relaxed();
    let mut board = LocalizationBoard::new("opt_promote", epoch(), policy);
    // Zen4 (x86) + GravitonArm (ARM) with high algorithmic gain
    board.add_entry(make_entry(
        MicroarchFamily::Zen4,
        &[HardwareFeature::Avx2],
        1000, 600,
        700_000, 200_000, 50_000, 50_000,
    ));
    board.add_entry(make_entry(
        MicroarchFamily::GravitonArm,
        &[HardwareFeature::Neon],
        1000, 650,
        650_000, 200_000, 80_000, 70_000,
    ));
    board
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_schema_version() {
    assert!(SCHEMA_VERSION.contains("hardware-localization-residual"));
}

#[test]
fn constants_component() {
    assert_eq!(COMPONENT, "hardware_localization_residual");
}

#[test]
fn constants_bead_id() {
    assert_eq!(BEAD_ID, "bd-1lsy.7.16.3");
}

#[test]
fn constants_policy_id() {
    assert_eq!(POLICY_ID, "RGC-616C");
}

#[test]
fn constants_millionths() {
    assert_eq!(MILLIONTHS, 1_000_000);
}

#[test]
fn constants_default_min_algorithmic_gain() {
    assert_eq!(DEFAULT_MIN_ALGORITHMIC_GAIN, 600_000);
}

#[test]
fn constants_default_max_hardware_attributable() {
    assert_eq!(DEFAULT_MAX_HARDWARE_ATTRIBUTABLE, 300_000);
}

#[test]
fn constants_max_board_entries() {
    assert_eq!(MAX_BOARD_ENTRIES, 256);
}

// ---------------------------------------------------------------------------
// HardwareFeature
// ---------------------------------------------------------------------------

#[test]
fn hardware_feature_all_count() {
    assert_eq!(HardwareFeature::ALL.len(), 13);
}

#[test]
fn hardware_feature_ordering() {
    assert!(HardwareFeature::Avx2 < HardwareFeature::Clmul);
}

#[test]
fn hardware_feature_is_x86() {
    assert!(HardwareFeature::Avx2.is_x86());
    assert!(HardwareFeature::Avx512.is_x86());
    assert!(HardwareFeature::Bmi2.is_x86());
    assert!(HardwareFeature::Clmul.is_x86());
    assert!(!HardwareFeature::Neon.is_x86());
}

#[test]
fn hardware_feature_is_arm() {
    assert!(HardwareFeature::Neon.is_arm());
    assert!(HardwareFeature::Sve.is_arm());
    assert!(!HardwareFeature::Avx2.is_arm());
}

#[test]
fn hardware_feature_is_neutral() {
    assert!(HardwareFeature::PopcntHw.is_neutral());
    assert!(HardwareFeature::Aes.is_neutral());
    assert!(HardwareFeature::LargePages.is_neutral());
    assert!(!HardwareFeature::Avx2.is_neutral());
}

#[test]
fn hardware_feature_display() {
    assert_eq!(format!("{}", HardwareFeature::Avx512), "avx512");
    assert_eq!(format!("{}", HardwareFeature::Neon), "neon");
}

// ---------------------------------------------------------------------------
// MicroarchFamily
// ---------------------------------------------------------------------------

#[test]
fn microarch_family_all_count() {
    assert_eq!(MicroarchFamily::ALL.len(), 8);
}

#[test]
fn microarch_family_ordering() {
    assert!(MicroarchFamily::Zen4 < MicroarchFamily::GenericArm64);
}

#[test]
fn microarch_family_is_arm() {
    assert!(MicroarchFamily::GravitonArm.is_arm());
    assert!(MicroarchFamily::AppleM.is_arm());
    assert!(MicroarchFamily::GenericArm64.is_arm());
    assert!(!MicroarchFamily::Zen4.is_arm());
}

#[test]
fn microarch_family_is_x86() {
    assert!(MicroarchFamily::Zen4.is_x86());
    assert!(MicroarchFamily::AlderLake.is_x86());
    assert!(MicroarchFamily::GenericX64.is_x86());
    assert!(!MicroarchFamily::GravitonArm.is_x86());
}

#[test]
fn microarch_family_typical_features_zen4() {
    let feats = MicroarchFamily::Zen4.typical_features();
    assert!(feats.contains(&HardwareFeature::Avx2));
    assert!(feats.contains(&HardwareFeature::Avx512));
    assert!(feats.contains(&HardwareFeature::Bmi2));
}

#[test]
fn microarch_family_typical_features_graviton() {
    let feats = MicroarchFamily::GravitonArm.typical_features();
    assert!(feats.contains(&HardwareFeature::Neon));
    assert!(feats.contains(&HardwareFeature::Aes));
    assert!(!feats.contains(&HardwareFeature::Avx2));
}

// ---------------------------------------------------------------------------
// ResidualCategory
// ---------------------------------------------------------------------------

#[test]
fn residual_category_all_count() {
    assert_eq!(ResidualCategory::ALL.len(), 4);
}

#[test]
fn residual_category_ordering() {
    assert!(ResidualCategory::HardwareAttributable < ResidualCategory::Unexplained);
}

#[test]
fn residual_category_as_str() {
    assert_eq!(ResidualCategory::AlgorithmicGain.as_str(), "algorithmic_gain");
    assert_eq!(ResidualCategory::MeasurementNoise.as_str(), "measurement_noise");
}

// ---------------------------------------------------------------------------
// LocalizationEntry
// ---------------------------------------------------------------------------

#[test]
fn localization_entry_hash_determinism() {
    let a = make_entry(MicroarchFamily::Zen4, &[HardwareFeature::Avx2], 1000, 600, 700_000, 200_000, 50_000, 50_000);
    let b = make_entry(MicroarchFamily::Zen4, &[HardwareFeature::Avx2], 1000, 600, 700_000, 200_000, 50_000, 50_000);
    assert_eq!(a.entry_hash, b.entry_hash);
}

#[test]
fn localization_entry_speedup_positive() {
    let entry = make_entry(MicroarchFamily::Zen4, &[], 1000, 600, 500_000, 300_000, 100_000, 100_000);
    let speedup = entry.speedup_millionths();
    assert_eq!(speedup, 400_000); // (1000-600)/1000 * 1M
}

#[test]
fn localization_entry_speedup_no_improvement() {
    let entry = make_entry(MicroarchFamily::Zen4, &[], 1000, 1200, 0, 0, 500_000, 500_000);
    assert_eq!(entry.speedup_millionths(), 0);
}

#[test]
fn localization_entry_speedup_zero_baseline() {
    let entry = make_entry(MicroarchFamily::Zen4, &[], 0, 0, 0, 0, 0, 1_000_000);
    assert_eq!(entry.speedup_millionths(), 0);
}

#[test]
fn localization_entry_algorithmic_fraction() {
    let entry = make_entry(MicroarchFamily::AlderLake, &[], 1000, 500, 650_000, 200_000, 50_000, 100_000);
    assert_eq!(entry.algorithmic_fraction(), 650_000);
}

#[test]
fn localization_entry_hardware_fraction() {
    let entry = make_entry(MicroarchFamily::AlderLake, &[], 1000, 500, 650_000, 200_000, 50_000, 100_000);
    assert_eq!(entry.hardware_fraction(), 200_000);
}

#[test]
fn localization_entry_residual_sum() {
    let entry = make_entry(MicroarchFamily::Zen5, &[], 100, 50, 400_000, 300_000, 200_000, 100_000);
    assert_eq!(entry.residual_sum(), 1_000_000);
}

#[test]
fn localization_entry_features_available_on() {
    let entry = make_entry(MicroarchFamily::Zen4, &[HardwareFeature::Avx2], 1000, 600, 600_000, 200_000, 100_000, 100_000);
    assert!(entry.features_available_on(MicroarchFamily::Zen4));
    assert!(entry.features_available_on(MicroarchFamily::Zen5));
    assert!(!entry.features_available_on(MicroarchFamily::GravitonArm));
}

// ---------------------------------------------------------------------------
// PromotionPolicy
// ---------------------------------------------------------------------------

#[test]
fn promotion_policy_strict() {
    let p = PromotionPolicy::strict();
    assert_eq!(p.min_algorithmic_gain_millionths, 600_000);
    assert_eq!(p.max_hardware_attributable_millionths, 300_000);
    assert_eq!(p.min_hardware_families_tested, 3);
    assert!(p.require_arm_and_x64);
}

#[test]
fn promotion_policy_relaxed() {
    let p = PromotionPolicy::relaxed();
    assert_eq!(p.min_algorithmic_gain_millionths, 400_000);
    assert!(!p.require_arm_and_x64);
}

#[test]
fn promotion_policy_default_is_strict() {
    let d = PromotionPolicy::default();
    let s = PromotionPolicy::strict();
    assert_eq!(d, s);
}

// ---------------------------------------------------------------------------
// PromotionVerdict
// ---------------------------------------------------------------------------

#[test]
fn promotion_verdict_as_str() {
    assert_eq!(PromotionVerdict::Promotable.as_str(), "promotable");
    assert_eq!(PromotionVerdict::HardwareDependent.as_str(), "hardware_dependent");
    assert_eq!(PromotionVerdict::InsufficientEvidence.as_str(), "insufficient_evidence");
    assert_eq!(PromotionVerdict::Rejected.as_str(), "rejected");
}

#[test]
fn promotion_verdict_is_pass() {
    assert!(PromotionVerdict::Promotable.is_pass());
    assert!(!PromotionVerdict::HardwareDependent.is_pass());
    assert!(!PromotionVerdict::InsufficientEvidence.is_pass());
    assert!(!PromotionVerdict::Rejected.is_pass());
}

// ---------------------------------------------------------------------------
// LocalizationBoard
// ---------------------------------------------------------------------------

#[test]
fn board_new_empty() {
    let board = LocalizationBoard::new("opt_1", epoch(), PromotionPolicy::strict());
    assert_eq!(board.entry_count(), 0);
    assert_eq!(board.family_count(), 0);
}

#[test]
fn board_add_entry() {
    let mut board = LocalizationBoard::new("opt_2", epoch(), PromotionPolicy::relaxed());
    let entry = make_entry(MicroarchFamily::Zen4, &[], 1000, 600, 700_000, 200_000, 50_000, 50_000);
    assert!(board.add_entry(entry));
    assert_eq!(board.entry_count(), 1);
}

#[test]
fn board_distinct_families() {
    let mut board = LocalizationBoard::new("opt_3", epoch(), PromotionPolicy::relaxed());
    board.add_entry(make_entry(MicroarchFamily::Zen4, &[], 1000, 600, 700_000, 200_000, 50_000, 50_000));
    board.add_entry(make_entry(MicroarchFamily::GravitonArm, &[], 1000, 650, 650_000, 200_000, 80_000, 70_000));
    let families = board.distinct_families();
    assert_eq!(families.len(), 2);
    assert!(families.contains(&MicroarchFamily::Zen4));
    assert!(families.contains(&MicroarchFamily::GravitonArm));
}

#[test]
fn board_has_arm_and_x64() {
    let board = make_promotable_board();
    assert!(board.has_arm_and_x64());
}

#[test]
fn board_no_arm_and_x64_x86_only() {
    let mut board = LocalizationBoard::new("x86_only", epoch(), PromotionPolicy::relaxed());
    board.add_entry(make_entry(MicroarchFamily::Zen4, &[], 1000, 600, 700_000, 200_000, 50_000, 50_000));
    board.add_entry(make_entry(MicroarchFamily::AlderLake, &[], 1000, 600, 700_000, 200_000, 50_000, 50_000));
    assert!(!board.has_arm_and_x64());
}

#[test]
fn board_avg_algorithmic_gain() {
    let board = make_promotable_board();
    let avg = board.avg_algorithmic_gain();
    // (700_000 + 650_000) / 2 = 675_000
    assert_eq!(avg, 675_000);
}

#[test]
fn board_max_hardware_attributable() {
    let board = make_promotable_board();
    assert_eq!(board.max_hardware_attributable(), 200_000);
}

#[test]
fn board_avg_speedup() {
    let board = make_promotable_board();
    let avg = board.avg_speedup();
    // Zen4: (1000-600)/1000 * 1M = 400_000
    // Graviton: (1000-650)/1000 * 1M = 350_000
    // avg = 375_000
    assert_eq!(avg, 375_000);
}

#[test]
fn board_content_hash_determinism() {
    let a = make_promotable_board();
    let b = make_promotable_board();
    assert_eq!(a.content_hash, b.content_hash);
}

// ---------------------------------------------------------------------------
// Evaluate promotion
// ---------------------------------------------------------------------------

#[test]
fn evaluate_promotion_empty_board() {
    let board = LocalizationBoard::new("empty", epoch(), PromotionPolicy::relaxed());
    let (verdict, details) = board.evaluate_promotion();
    assert_eq!(verdict, PromotionVerdict::InsufficientEvidence);
    assert!(!details.is_empty());
}

#[test]
fn evaluate_promotion_no_speedup() {
    let mut board = LocalizationBoard::new("no_speed", epoch(), PromotionPolicy::relaxed());
    board.add_entry(make_entry(MicroarchFamily::Zen4, &[], 1000, 1000, 0, 0, 500_000, 500_000));
    board.add_entry(make_entry(MicroarchFamily::GravitonArm, &[], 1000, 1100, 0, 0, 500_000, 500_000));
    let (verdict, _) = board.evaluate_promotion();
    assert_eq!(verdict, PromotionVerdict::Rejected);
}

#[test]
fn evaluate_promotion_promotable() {
    let board = make_promotable_board();
    let (verdict, details) = board.evaluate_promotion();
    assert_eq!(verdict, PromotionVerdict::Promotable);
    assert!(details.is_empty());
}

#[test]
fn evaluate_promotion_hardware_dependent() {
    let mut board = LocalizationBoard::new("hw_dep", epoch(), PromotionPolicy::relaxed());
    // Low algo, high hw
    board.add_entry(make_entry(MicroarchFamily::Zen4, &[], 1000, 500, 200_000, 600_000, 100_000, 100_000));
    board.add_entry(make_entry(MicroarchFamily::GravitonArm, &[], 1000, 500, 200_000, 600_000, 100_000, 100_000));
    let (verdict, _) = board.evaluate_promotion();
    assert_eq!(verdict, PromotionVerdict::HardwareDependent);
}

#[test]
fn evaluate_promotion_insufficient_evidence_too_few_families() {
    let mut board = LocalizationBoard::new("few_fam", epoch(), PromotionPolicy::strict());
    // Only 1 family, strict requires 3
    board.add_entry(make_entry(MicroarchFamily::Zen4, &[], 1000, 500, 700_000, 100_000, 100_000, 100_000));
    let (verdict, _) = board.evaluate_promotion();
    assert_eq!(verdict, PromotionVerdict::InsufficientEvidence);
}

// ---------------------------------------------------------------------------
// Unsupported hardware identification
// ---------------------------------------------------------------------------

#[test]
fn identify_unsupported_hardware_with_x86_features() {
    let mut board = LocalizationBoard::new("unsup", epoch(), PromotionPolicy::relaxed());
    board.add_entry(make_entry(
        MicroarchFamily::Zen4,
        &[HardwareFeature::Avx512],
        1000, 500,
        700_000, 200_000, 50_000, 50_000,
    ));
    let unsupported = board.identify_unsupported_hardware();
    // ARM families should be unsupported since they lack AVX-512
    let arm_unsupported: Vec<_> = unsupported.iter().filter(|u| u.family.is_arm()).collect();
    assert!(!arm_unsupported.is_empty());
    for entry in &arm_unsupported {
        assert!(entry.missing_features.contains(&HardwareFeature::Avx512));
    }
}

#[test]
fn identify_unsupported_hardware_empty_board() {
    let board = LocalizationBoard::new("empty_unsup", epoch(), PromotionPolicy::relaxed());
    let unsupported = board.identify_unsupported_hardware();
    assert!(unsupported.is_empty());
}

// ---------------------------------------------------------------------------
// LocalizationReport (via generate_report)
// ---------------------------------------------------------------------------

#[test]
fn generate_report_promotable() {
    let board = make_promotable_board();
    let report = board.generate_report();
    assert_eq!(report.verdict, PromotionVerdict::Promotable);
    assert!(report.rejection_details.is_empty());
    assert_eq!(report.schema_version, SCHEMA_VERSION);
}

#[test]
fn generate_report_content_hash_determinism() {
    let a = make_promotable_board().generate_report();
    let b = make_promotable_board().generate_report();
    assert_eq!(a.content_hash, b.content_hash);
}

// ---------------------------------------------------------------------------
// UnsupportedHardwareEntry
// ---------------------------------------------------------------------------

#[test]
fn unsupported_entry_hash_determinism() {
    let mut missing = BTreeSet::new();
    missing.insert(HardwareFeature::Avx512);
    let a = UnsupportedHardwareEntry::new(MicroarchFamily::GravitonArm, missing.clone(), 100_000, false);
    let b = UnsupportedHardwareEntry::new(MicroarchFamily::GravitonArm, missing, 100_000, false);
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn unsupported_entry_display() {
    let mut missing = BTreeSet::new();
    missing.insert(HardwareFeature::Avx512);
    let entry = UnsupportedHardwareEntry::new(MicroarchFamily::GenericArm64, missing, 50_000, true);
    let s = format!("{}", entry);
    assert!(s.contains("generic_arm64"));
}

// ---------------------------------------------------------------------------
// E2E scenario: full promotion flow
// ---------------------------------------------------------------------------

#[test]
fn e2e_full_promotion_flow() {
    let policy = PromotionPolicy::relaxed();
    let mut board = LocalizationBoard::new("e2e_opt", epoch(), policy);

    board.add_entry(make_entry(
        MicroarchFamily::Zen4,
        &[HardwareFeature::Avx2, HardwareFeature::PopcntHw],
        2000, 1000,
        650_000, 200_000, 80_000, 70_000,
    ));
    board.add_entry(make_entry(
        MicroarchFamily::GravitonArm,
        &[HardwareFeature::Neon, HardwareFeature::PopcntHw],
        2000, 1100,
        600_000, 200_000, 100_000, 100_000,
    ));

    let report = board.generate_report();
    assert_eq!(report.verdict, PromotionVerdict::Promotable);
    assert!(report.algorithmic_gain_millionths > 0);
    assert!(!report.content_hash.as_bytes().is_empty());
}

#[test]
fn e2e_rejection_with_excessive_noise() {
    let policy = PromotionPolicy::strict();
    let mut board = LocalizationBoard::new("noisy", epoch(), policy);

    board.add_entry(make_entry(
        MicroarchFamily::Zen4,
        &[],
        1000, 500,
        600_000, 100_000, 200_000, 100_000, // noise = 200_000 > 100_000 threshold
    ));
    board.add_entry(make_entry(
        MicroarchFamily::GravitonArm,
        &[],
        1000, 500,
        600_000, 100_000, 200_000, 100_000,
    ));
    board.add_entry(make_entry(
        MicroarchFamily::AlderLake,
        &[],
        1000, 500,
        600_000, 100_000, 200_000, 100_000,
    ));

    let (verdict, details) = board.evaluate_promotion();
    assert_ne!(verdict, PromotionVerdict::Promotable);
    let has_noise_rejection = details.iter().any(|d| matches!(d, RejectionDetail::ExcessiveNoise { .. }));
    assert!(has_noise_rejection);
}

// ---------------------------------------------------------------------------
// Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn serde_hardware_feature_roundtrip() {
    for f in HardwareFeature::ALL {
        let json = serde_json::to_string(f).unwrap();
        let back: HardwareFeature = serde_json::from_str(&json).unwrap();
        assert_eq!(*f, back);
    }
}

#[test]
fn serde_microarch_family_roundtrip() {
    for f in MicroarchFamily::ALL {
        let json = serde_json::to_string(f).unwrap();
        let back: MicroarchFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*f, back);
    }
}

#[test]
fn serde_promotion_verdict_roundtrip() {
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
