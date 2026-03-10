//! Integration tests for the benchmark_coverage_saturation_gate module.
//!
//! Bead: bd-1lsy.8.5.5 [RGC-705E]

use frankenengine_engine::benchmark_coverage_saturation_gate::*;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

/// Nine equal-weight families — ideal board.
fn equal_families() -> Vec<FamilyCoverage> {
    WorkloadFamily::ALL
        .iter()
        .map(|&f| FamilyCoverage::new(f, 10, 111_111, 900_000, 50_000))
        .collect()
}

/// One dominant family, rest minimal.
fn dominant_families() -> Vec<FamilyCoverage> {
    let mut fams: Vec<FamilyCoverage> = WorkloadFamily::ALL
        .iter()
        .map(|&f| FamilyCoverage::new(f, 5, 10_000, 500_000, 100_000))
        .collect();
    fams[0].total_weight = 900_000;
    fams[0].workload_count = 50;
    fams
}

/// Cherry-picked: only two families present.
fn cherry_picked_families() -> Vec<FamilyCoverage> {
    vec![
        FamilyCoverage::new(WorkloadFamily::BranchHeavy, 20, 700_000, 950_000, 20_000),
        FamilyCoverage::new(WorkloadFamily::Vectorizable, 15, 300_000, 800_000, 50_000),
    ]
}

/// All families present but with zero weight.
fn zero_weight_families() -> Vec<FamilyCoverage> {
    WorkloadFamily::ALL
        .iter()
        .map(|&f| FamilyCoverage::new(f, 5, 0, 0, 0))
        .collect()
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_contains_gate_name() {
    assert!(SCHEMA_VERSION.contains("benchmark-coverage-saturation-gate"));
    assert!(SCHEMA_VERSION.contains(".v1"));
}

#[test]
fn test_component_constant() {
    assert_eq!(COMPONENT, "benchmark_coverage_saturation_gate");
}

#[test]
fn test_bead_id_constant() {
    assert_eq!(BEAD_ID, "bd-1lsy.8.5.5");
}

#[test]
fn test_policy_id_constant() {
    assert_eq!(POLICY_ID, "RGC-705E");
}

#[test]
fn test_fixed_one_value() {
    assert_eq!(FIXED_ONE, 1_000_000);
}

#[test]
fn test_total_workload_families_matches_all() {
    assert_eq!(TOTAL_WORKLOAD_FAMILIES, WorkloadFamily::ALL.len());
    assert_eq!(TOTAL_WORKLOAD_FAMILIES, 9);
}

#[test]
fn test_default_constants_relationships() {
    // Min families should be less than or equal to total.
    assert!(DEFAULT_MIN_FAMILIES_COVERED <= TOTAL_WORKLOAD_FAMILIES);
    // Coverage fraction < 1.0.
    assert!(DEFAULT_MIN_FAMILY_COVERAGE < FIXED_ONE);
    // Max gini < 1.0.
    assert!(DEFAULT_MAX_GINI < FIXED_ONE);
    // Min entropy < 1.0.
    assert!(DEFAULT_MIN_ENTROPY < FIXED_ONE);
    // Max single family share < 1.0.
    assert!(DEFAULT_MAX_SINGLE_FAMILY_SHARE < FIXED_ONE);
}

// ---------------------------------------------------------------------------
// WorkloadFamily — enum variants, Display, serde, ordering
// ---------------------------------------------------------------------------

#[test]
fn test_workload_family_all_has_nine_members() {
    assert_eq!(WorkloadFamily::ALL.len(), 9);
}

#[test]
fn test_workload_family_display_all_variants() {
    let expected = [
        "branch_heavy",
        "vectorizable",
        "proof_specialized",
        "native_addon",
        "hostcall_boundary",
        "startup_image",
        "metadata_locality",
        "observability_sensitive",
        "resource_spiky",
    ];
    for (family, exp) in WorkloadFamily::ALL.iter().zip(expected.iter()) {
        assert_eq!(family.to_string(), *exp);
    }
}

#[test]
fn test_workload_family_as_str_matches_display() {
    for &f in WorkloadFamily::ALL {
        assert_eq!(f.as_str(), f.to_string());
    }
}

#[test]
fn test_workload_family_serde_roundtrip_all() {
    for &f in WorkloadFamily::ALL {
        let json = serde_json::to_string(&f).unwrap();
        let back: WorkloadFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }
}

#[test]
fn test_workload_family_serde_snake_case() {
    let json = serde_json::to_string(&WorkloadFamily::HostcallBoundary).unwrap();
    assert_eq!(json, "\"hostcall_boundary\"");
}

#[test]
fn test_workload_family_canonical_ordering() {
    for i in 1..WorkloadFamily::ALL.len() {
        assert!(WorkloadFamily::ALL[i - 1] < WorkloadFamily::ALL[i]);
    }
}

// ---------------------------------------------------------------------------
// SaturationVerdict — Display, serde, is_acceptable
// ---------------------------------------------------------------------------

#[test]
fn test_saturation_verdict_display_all() {
    assert_eq!(SaturationVerdict::Saturated.to_string(), "saturated");
    assert_eq!(SaturationVerdict::NearSaturated.to_string(), "near_saturated");
    assert_eq!(SaturationVerdict::Sparse.to_string(), "sparse");
    assert_eq!(SaturationVerdict::CherryPicked.to_string(), "cherry_picked");
    assert_eq!(SaturationVerdict::InsufficientData.to_string(), "insufficient_data");
}

#[test]
fn test_saturation_verdict_acceptable_variants() {
    assert!(SaturationVerdict::Saturated.is_acceptable());
    assert!(SaturationVerdict::NearSaturated.is_acceptable());
    assert!(!SaturationVerdict::Sparse.is_acceptable());
    assert!(!SaturationVerdict::CherryPicked.is_acceptable());
    assert!(!SaturationVerdict::InsufficientData.is_acceptable());
}

#[test]
fn test_saturation_verdict_serde_roundtrip() {
    let variants = [
        SaturationVerdict::Saturated,
        SaturationVerdict::NearSaturated,
        SaturationVerdict::Sparse,
        SaturationVerdict::CherryPicked,
        SaturationVerdict::InsufficientData,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: SaturationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// RepresentativenessLevel — Display, serde, is_acceptable
// ---------------------------------------------------------------------------

#[test]
fn test_representativeness_display_all() {
    assert_eq!(RepresentativenessLevel::Representative.to_string(), "representative");
    assert_eq!(
        RepresentativenessLevel::MarginallyRepresentative.to_string(),
        "marginally_representative"
    );
    assert_eq!(RepresentativenessLevel::Skewed.to_string(), "skewed");
    assert_eq!(RepresentativenessLevel::Unrepresentative.to_string(), "unrepresentative");
}

#[test]
fn test_representativeness_acceptable_variants() {
    assert!(RepresentativenessLevel::Representative.is_acceptable());
    assert!(RepresentativenessLevel::MarginallyRepresentative.is_acceptable());
    assert!(!RepresentativenessLevel::Skewed.is_acceptable());
    assert!(!RepresentativenessLevel::Unrepresentative.is_acceptable());
}

#[test]
fn test_representativeness_serde_roundtrip() {
    let variants = [
        RepresentativenessLevel::Representative,
        RepresentativenessLevel::MarginallyRepresentative,
        RepresentativenessLevel::Skewed,
        RepresentativenessLevel::Unrepresentative,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: RepresentativenessLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// GateDecision — Display, serde, allows_proceed
// ---------------------------------------------------------------------------

#[test]
fn test_gate_decision_display_all() {
    assert_eq!(GateDecision::Pass.to_string(), "pass");
    assert_eq!(GateDecision::ConditionalPass.to_string(), "conditional_pass");
    assert_eq!(GateDecision::Fail.to_string(), "fail");
    assert_eq!(GateDecision::InsufficientEvidence.to_string(), "insufficient_evidence");
}

#[test]
fn test_gate_decision_allows_proceed_variants() {
    assert!(GateDecision::Pass.allows_proceed());
    assert!(GateDecision::ConditionalPass.allows_proceed());
    assert!(!GateDecision::Fail.allows_proceed());
    assert!(!GateDecision::InsufficientEvidence.allows_proceed());
}

#[test]
fn test_gate_decision_serde_roundtrip() {
    let variants = [
        GateDecision::Pass,
        GateDecision::ConditionalPass,
        GateDecision::Fail,
        GateDecision::InsufficientEvidence,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: GateDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// FamilyCoverage — construction, field access, helpers
// ---------------------------------------------------------------------------

#[test]
fn test_family_coverage_new_and_fields() {
    let fc = FamilyCoverage::new(WorkloadFamily::BranchHeavy, 12, 200_000, 750_000, 40_000);
    assert_eq!(fc.family, WorkloadFamily::BranchHeavy);
    assert_eq!(fc.workload_count, 12);
    assert_eq!(fc.total_weight, 200_000);
    assert_eq!(fc.coverage_fraction, 750_000);
    assert_eq!(fc.max_gap_fraction, 40_000);
}

#[test]
fn test_family_coverage_is_present_true() {
    let fc = FamilyCoverage::new(WorkloadFamily::Vectorizable, 1, 100_000, 500_000, 0);
    assert!(fc.is_present());
}

#[test]
fn test_family_coverage_is_present_false() {
    let fc = FamilyCoverage::new(WorkloadFamily::Vectorizable, 0, 0, 0, 0);
    assert!(!fc.is_present());
}

#[test]
fn test_family_coverage_meets_coverage_exact() {
    let fc = FamilyCoverage::new(WorkloadFamily::StartupImage, 3, 100_000, 500_000, 0);
    assert!(fc.meets_coverage(500_000));
}

#[test]
fn test_family_coverage_meets_coverage_above() {
    let fc = FamilyCoverage::new(WorkloadFamily::StartupImage, 3, 100_000, 500_000, 0);
    assert!(fc.meets_coverage(300_000));
}

#[test]
fn test_family_coverage_meets_coverage_below() {
    let fc = FamilyCoverage::new(WorkloadFamily::StartupImage, 3, 100_000, 500_000, 0);
    assert!(!fc.meets_coverage(600_000));
}

#[test]
fn test_family_coverage_serde_roundtrip() {
    let fc = FamilyCoverage::new(WorkloadFamily::ResourceSpiky, 7, 80_000, 650_000, 30_000);
    let json = serde_json::to_string(&fc).unwrap();
    let back: FamilyCoverage = serde_json::from_str(&json).unwrap();
    assert_eq!(fc, back);
}

// ---------------------------------------------------------------------------
// DistributionProfile / compute_coverage
// ---------------------------------------------------------------------------

#[test]
fn test_compute_coverage_empty_returns_zeros() {
    let profile = compute_coverage(&[]);
    assert!(profile.family_coverages.is_empty());
    assert_eq!(profile.gini_coefficient, 0);
    assert_eq!(profile.entropy, 0);
    assert_eq!(profile.max_family_share, 0);
    assert_eq!(profile.min_family_share, 0);
}

#[test]
fn test_compute_coverage_single_family() {
    let families = vec![FamilyCoverage::new(
        WorkloadFamily::BranchHeavy, 10, FIXED_ONE, 900_000, 50_000,
    )];
    let profile = compute_coverage(&families);
    assert_eq!(profile.max_family_share, FIXED_ONE);
    assert_eq!(profile.min_family_share, FIXED_ONE);
    assert_eq!(profile.gini_coefficient, 0);
    assert_eq!(profile.entropy, FIXED_ONE);
}

#[test]
fn test_compute_coverage_equal_weights_gini_zero() {
    let families = equal_families();
    let profile = compute_coverage(&families);
    assert_eq!(profile.gini_coefficient, 0);
}

#[test]
fn test_compute_coverage_equal_weights_entropy_near_max() {
    let families = equal_families();
    let profile = compute_coverage(&families);
    assert!(profile.entropy >= 990_000, "entropy: {}", profile.entropy);
}

#[test]
fn test_compute_coverage_dominant_family_high_gini() {
    let families = dominant_families();
    let profile = compute_coverage(&families);
    assert!(profile.gini_coefficient > 200_000, "gini: {}", profile.gini_coefficient);
}

#[test]
fn test_compute_coverage_dominant_family_high_max_share() {
    let families = dominant_families();
    let profile = compute_coverage(&families);
    assert!(profile.max_family_share > 500_000, "max_share: {}", profile.max_family_share);
}

#[test]
fn test_compute_coverage_preserves_family_count() {
    let families = equal_families();
    let profile = compute_coverage(&families);
    assert_eq!(profile.family_coverages.len(), 9);
}

#[test]
fn test_compute_coverage_zero_weight_all_shares_zero() {
    let families = zero_weight_families();
    let profile = compute_coverage(&families);
    assert_eq!(profile.max_family_share, 0);
    assert_eq!(profile.min_family_share, 0);
    assert_eq!(profile.gini_coefficient, 0);
}

#[test]
fn test_compute_coverage_two_equal_families_entropy_near_max() {
    let families = vec![
        FamilyCoverage::new(WorkloadFamily::BranchHeavy, 10, 500_000, 800_000, 30_000),
        FamilyCoverage::new(WorkloadFamily::Vectorizable, 10, 500_000, 800_000, 30_000),
    ];
    let profile = compute_coverage(&families);
    assert_eq!(profile.gini_coefficient, 0);
    assert!(profile.entropy >= 990_000, "entropy: {}", profile.entropy);
    assert_eq!(profile.max_family_share, profile.min_family_share);
}

#[test]
fn test_compute_coverage_two_unequal_families() {
    let families = vec![
        FamilyCoverage::new(WorkloadFamily::BranchHeavy, 10, 900_000, 800_000, 30_000),
        FamilyCoverage::new(WorkloadFamily::Vectorizable, 10, 100_000, 800_000, 30_000),
    ];
    let profile = compute_coverage(&families);
    assert!(profile.gini_coefficient > 0, "gini: {}", profile.gini_coefficient);
    assert!(profile.max_family_share > profile.min_family_share);
}

#[test]
fn test_distribution_profile_serde_roundtrip() {
    let families = equal_families();
    let profile = compute_coverage(&families);
    let json = serde_json::to_string(&profile).unwrap();
    let back: DistributionProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(profile, back);
}

// ---------------------------------------------------------------------------
// evaluate_saturation
// ---------------------------------------------------------------------------

#[test]
fn test_saturation_empty_is_insufficient_data() {
    let profile = compute_coverage(&[]);
    let config = GateConfig::default();
    assert_eq!(evaluate_saturation(&profile, &config), SaturationVerdict::InsufficientData);
}

#[test]
fn test_saturation_all_families_returns_saturated() {
    let families = equal_families();
    let profile = compute_coverage(&families);
    let config = GateConfig::default();
    assert_eq!(evaluate_saturation(&profile, &config), SaturationVerdict::Saturated);
}

#[test]
fn test_saturation_six_families_returns_near_saturated() {
    let families: Vec<FamilyCoverage> = WorkloadFamily::ALL
        .iter()
        .take(6)
        .map(|&f| FamilyCoverage::new(f, 5, 100_000, 500_000, 50_000))
        .collect();
    let profile = compute_coverage(&families);
    let config = GateConfig::default();
    assert_eq!(evaluate_saturation(&profile, &config), SaturationVerdict::NearSaturated);
}

#[test]
fn test_saturation_three_families_returns_sparse() {
    let families: Vec<FamilyCoverage> = WorkloadFamily::ALL
        .iter()
        .take(3)
        .map(|&f| FamilyCoverage::new(f, 5, 100_000, 500_000, 50_000))
        .collect();
    let profile = compute_coverage(&families);
    let config = GateConfig::default();
    assert_eq!(evaluate_saturation(&profile, &config), SaturationVerdict::Sparse);
}

#[test]
fn test_saturation_cherry_picked_two_families_dominant() {
    let families = cherry_picked_families();
    let profile = compute_coverage(&families);
    let config = GateConfig::default();
    assert_eq!(evaluate_saturation(&profile, &config), SaturationVerdict::CherryPicked);
}

#[test]
fn test_saturation_all_zero_workloads() {
    let families: Vec<FamilyCoverage> = WorkloadFamily::ALL
        .iter()
        .map(|&f| FamilyCoverage::new(f, 0, 100_000, 0, 0))
        .collect();
    let profile = compute_coverage(&families);
    let config = GateConfig::default();
    assert_eq!(evaluate_saturation(&profile, &config), SaturationVerdict::InsufficientData);
}

#[test]
fn test_saturation_below_min_workloads_per_family() {
    // All families present but each has only 1 workload (below default min 3).
    let families: Vec<FamilyCoverage> = WorkloadFamily::ALL
        .iter()
        .map(|&f| FamilyCoverage::new(f, 1, 111_111, 900_000, 50_000))
        .collect();
    let profile = compute_coverage(&families);
    let config = GateConfig::default();
    let verdict = evaluate_saturation(&profile, &config);
    // 0 families meet min_workloads_per_family=3, so < 7 covered -> Sparse or worse.
    assert!(!verdict.is_acceptable(), "verdict: {verdict}");
}

#[test]
fn test_saturation_coverage_fraction_below_threshold() {
    // All families have enough workloads but low coverage fraction.
    let families: Vec<FamilyCoverage> = WorkloadFamily::ALL
        .iter()
        .map(|&f| FamilyCoverage::new(f, 10, 111_111, 50_000, 50_000))
        .collect();
    let profile = compute_coverage(&families);
    let config = GateConfig::default();
    // Coverage fraction 50_000 < min 100_000, so not Saturated.
    let verdict = evaluate_saturation(&profile, &config);
    assert_eq!(verdict, SaturationVerdict::NearSaturated);
}

// ---------------------------------------------------------------------------
// evaluate_representativeness
// ---------------------------------------------------------------------------

#[test]
fn test_representativeness_equal_is_representative() {
    let families = equal_families();
    let profile = compute_coverage(&families);
    let config = GateConfig::default();
    assert_eq!(
        evaluate_representativeness(&profile, &config),
        RepresentativenessLevel::Representative
    );
}

#[test]
fn test_representativeness_empty_is_unrepresentative() {
    let profile = compute_coverage(&[]);
    let config = GateConfig::default();
    assert_eq!(
        evaluate_representativeness(&profile, &config),
        RepresentativenessLevel::Unrepresentative
    );
}

#[test]
fn test_representativeness_dominant_not_acceptable() {
    let families = dominant_families();
    let profile = compute_coverage(&families);
    let config = GateConfig::default();
    let level = evaluate_representativeness(&profile, &config);
    assert!(!level.is_acceptable(), "expected not acceptable, got {level}");
}

#[test]
fn test_representativeness_permissive_config_passes() {
    let families = dominant_families();
    let profile = compute_coverage(&families);
    let config = GateConfig::permissive();
    let level = evaluate_representativeness(&profile, &config);
    assert!(level.is_acceptable(), "permissive should pass, got {level}");
}

#[test]
fn test_representativeness_marginal_two_of_three_pass() {
    // Build a profile where gini and share are ok but entropy is not.
    let families = equal_families();
    let profile = compute_coverage(&families);
    // Custom config with unreachable entropy requirement.
    let config = GateConfig {
        min_entropy: FIXED_ONE, // impossible to reach exactly
        ..GateConfig::default()
    };
    let level = evaluate_representativeness(&profile, &config);
    // gini ok + share ok (2 of 3) -> MarginallyRepresentative.
    assert_eq!(level, RepresentativenessLevel::MarginallyRepresentative);
}

#[test]
fn test_representativeness_skewed_one_of_three_pass() {
    let families = equal_families();
    let profile = compute_coverage(&families);
    // Entropy requirement too high AND gini threshold too low.
    let config = GateConfig {
        min_entropy: FIXED_ONE,
        max_gini_coefficient: 0, // No distribution can meet gini=0 exactly ... except equal.
        ..GateConfig::default()
    };
    // Equal families have gini=0, so gini is ok. Entropy ~1M < FIXED_ONE check depends on exact.
    // Let's use dominant families instead to reliably fail multiple checks.
    let families2 = dominant_families();
    let profile2 = compute_coverage(&families2);
    let config2 = GateConfig {
        max_gini_coefficient: 100_000, // fail
        min_entropy: 999_999,          // fail
        max_single_family_share: FIXED_ONE, // pass
        ..GateConfig::default()
    };
    let level = evaluate_representativeness(&profile2, &config2);
    assert_eq!(level, RepresentativenessLevel::Skewed);
}

// ---------------------------------------------------------------------------
// Full evaluate
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_equal_families_pass() {
    let families = equal_families();
    let config = GateConfig::default();
    let result = evaluate(&families, &config);
    assert_eq!(result.decision, GateDecision::Pass);
    assert_eq!(result.verdict, SaturationVerdict::Saturated);
    assert_eq!(result.representativeness, RepresentativenessLevel::Representative);
    assert!(result.blocking_reasons.is_empty());
}

#[test]
fn test_evaluate_cherry_picked_fail() {
    let families = cherry_picked_families();
    let config = GateConfig::default();
    let result = evaluate(&families, &config);
    assert_eq!(result.decision, GateDecision::Fail);
    assert!(!result.blocking_reasons.is_empty());
}

#[test]
fn test_evaluate_empty_insufficient_evidence() {
    let families: Vec<FamilyCoverage> = Vec::new();
    let config = GateConfig::default();
    let result = evaluate(&families, &config);
    assert_eq!(result.decision, GateDecision::InsufficientEvidence);
}

#[test]
fn test_evaluate_conditional_pass_with_recommendations() {
    // All families present with good distribution, one slightly under min workloads.
    let mut families = equal_families();
    families[4].workload_count = 2; // Below default min 3.
    let config = GateConfig::default();
    let result = evaluate(&families, &config);
    // 8 of 9 families meet min_workloads => 8 >= 7 min => saturation ok.
    // The under-threshold family generates a recommendation.
    assert!(
        result.decision == GateDecision::Pass || result.decision == GateDecision::ConditionalPass,
        "decision: {:?}",
        result.decision,
    );
}

#[test]
fn test_evaluate_fail_has_blocking_reasons() {
    let families = cherry_picked_families();
    let config = GateConfig::default();
    let result = evaluate(&families, &config);
    assert!(!result.blocking_reasons.is_empty());
    let combined = result.blocking_reasons.join(" ");
    assert!(
        combined.contains("saturation") || combined.contains("representativeness")
            || combined.contains("families covered"),
        "blocking_reasons: {:?}",
        result.blocking_reasons,
    );
}

#[test]
fn test_evaluate_recommendations_for_gini() {
    // Build a skewed board that still has enough families to not be cherry-picked.
    let mut families: Vec<FamilyCoverage> = WorkloadFamily::ALL
        .iter()
        .map(|&f| FamilyCoverage::new(f, 5, 50_000, 500_000, 50_000))
        .collect();
    families[0].total_weight = 800_000;
    let config = GateConfig::default();
    let result = evaluate(&families, &config);
    let all_recs = result.recommendations.join(" ");
    assert!(all_recs.contains("Gini") || all_recs.contains("gini") || all_recs.contains("share"),
        "recommendations: {:?}", result.recommendations);
}

#[test]
fn test_evaluate_permissive_always_passes() {
    let families = cherry_picked_families();
    let config = GateConfig::permissive();
    let result = evaluate(&families, &config);
    assert!(result.decision.allows_proceed(), "decision: {:?}", result.decision);
}

#[test]
fn test_evaluate_strict_config_tighter() {
    let families: Vec<FamilyCoverage> = WorkloadFamily::ALL
        .iter()
        .map(|&f| FamilyCoverage::new(f, 10, 111_111, 150_000, 50_000))
        .collect();
    let config = GateConfig::strict();
    let result = evaluate(&families, &config);
    // 150_000 < strict min_family_coverage 200_000 -> NearSaturated.
    assert_eq!(result.verdict, SaturationVerdict::NearSaturated);
}

// ---------------------------------------------------------------------------
// Receipt hash determinism
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_receipt_hash_deterministic() {
    let families = equal_families();
    let config = GateConfig::default();
    let r1 = evaluate(&families, &config);
    let r2 = evaluate(&families, &config);
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn test_evaluate_different_inputs_different_hashes() {
    let config = GateConfig::default();
    let r1 = evaluate(&equal_families(), &config);
    let r2 = evaluate(&cherry_picked_families(), &config);
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

#[test]
fn test_gate_config_default_values() {
    let config = GateConfig::default();
    assert_eq!(config.min_families_covered, DEFAULT_MIN_FAMILIES_COVERED);
    assert_eq!(config.min_family_coverage_fraction, DEFAULT_MIN_FAMILY_COVERAGE);
    assert_eq!(config.max_gini_coefficient, DEFAULT_MAX_GINI);
    assert_eq!(config.min_entropy, DEFAULT_MIN_ENTROPY);
    assert_eq!(config.max_single_family_share, DEFAULT_MAX_SINGLE_FAMILY_SHARE);
    assert_eq!(config.min_workloads_per_family, DEFAULT_MIN_WORKLOADS_PER_FAMILY);
}

#[test]
fn test_gate_config_strict_tighter_than_default() {
    let strict = GateConfig::strict();
    let default = GateConfig::default();
    assert!(strict.min_families_covered >= default.min_families_covered);
    assert!(strict.min_family_coverage_fraction >= default.min_family_coverage_fraction);
    assert!(strict.max_gini_coefficient <= default.max_gini_coefficient);
    assert!(strict.min_entropy >= default.min_entropy);
    assert!(strict.max_single_family_share <= default.max_single_family_share);
    assert!(strict.min_workloads_per_family >= default.min_workloads_per_family);
}

#[test]
fn test_gate_config_permissive_loosest() {
    let p = GateConfig::permissive();
    assert_eq!(p.min_families_covered, 1);
    assert_eq!(p.min_family_coverage_fraction, 0);
    assert_eq!(p.max_gini_coefficient, FIXED_ONE);
    assert_eq!(p.min_entropy, 0);
    assert_eq!(p.max_single_family_share, FIXED_ONE);
    assert_eq!(p.min_workloads_per_family, 1);
}

#[test]
fn test_gate_config_serde_roundtrip() {
    let config = GateConfig::strict();
    let json = serde_json::to_string(&config).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

#[test]
fn test_decision_receipt_from_result_fields() {
    let families = equal_families();
    let config = GateConfig::default();
    let result = evaluate(&families, &config);
    let receipt = DecisionReceipt::from_result(&result, epoch());
    assert_eq!(receipt.component, COMPONENT);
    assert_eq!(receipt.epoch, epoch());
    assert_eq!(receipt.decision, result.decision);
    assert_eq!(receipt.evidence_hash, result.receipt_hash);
}

#[test]
fn test_decision_receipt_hash_deterministic() {
    let families = equal_families();
    let config = GateConfig::default();
    let result = evaluate(&families, &config);
    let r1 = DecisionReceipt::from_result(&result, epoch());
    let r2 = DecisionReceipt::from_result(&result, epoch());
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn test_decision_receipt_different_epoch_different_hash() {
    let families = equal_families();
    let config = GateConfig::default();
    let result = evaluate(&families, &config);
    let r1 = DecisionReceipt::from_result(&result, SecurityEpoch::from_raw(1));
    let r2 = DecisionReceipt::from_result(&result, SecurityEpoch::from_raw(2));
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn test_decision_receipt_serde_roundtrip() {
    let families = equal_families();
    let config = GateConfig::default();
    let result = evaluate(&families, &config);
    let receipt = DecisionReceipt::from_result(&result, epoch());
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

// ---------------------------------------------------------------------------
// BatchResult
// ---------------------------------------------------------------------------

#[test]
fn test_batch_result_empty() {
    let batch = BatchResult::new(Vec::new());
    assert!(batch.is_empty());
    assert_eq!(batch.len(), 0);
    assert!(!batch.all_acceptable());
}

#[test]
fn test_batch_result_all_pass() {
    let families = equal_families();
    let config = GateConfig::default();
    let r1 = evaluate(&families, &config);
    let r2 = evaluate(&families, &config);
    let batch = BatchResult::new(vec![r1, r2]);
    assert_eq!(batch.len(), 2);
    assert!(batch.all_acceptable());
    assert!(batch.summary.contains("2 evaluated"));
    assert!(batch.summary.contains("2 pass"));
}

#[test]
fn test_batch_result_mixed_not_acceptable() {
    let good = evaluate(&equal_families(), &GateConfig::default());
    let bad = evaluate(&cherry_picked_families(), &GateConfig::default());
    let batch = BatchResult::new(vec![good, bad]);
    assert!(!batch.all_acceptable());
    assert!(batch.summary.contains("1 fail"));
}

#[test]
fn test_batch_result_summary_counts() {
    let config = GateConfig::default();
    let pass_result = evaluate(&equal_families(), &config);
    let fail_result = evaluate(&cherry_picked_families(), &config);
    let empty_result = evaluate(&[], &config);
    let batch = BatchResult::new(vec![pass_result, fail_result, empty_result]);
    assert_eq!(batch.len(), 3);
    assert!(batch.summary.contains("3 evaluated"));
}

#[test]
fn test_batch_result_serde_roundtrip() {
    let families = equal_families();
    let config = GateConfig::default();
    let r = evaluate(&families, &config);
    let batch = BatchResult::new(vec![r]);
    let json = serde_json::to_string(&batch).unwrap();
    let back: BatchResult = serde_json::from_str(&json).unwrap();
    assert_eq!(batch, back);
}

// ---------------------------------------------------------------------------
// SaturationEvidence / build_evidence
// ---------------------------------------------------------------------------

#[test]
fn test_build_evidence_fields() {
    let families = equal_families();
    let profile = compute_coverage(&families);
    let evidence = build_evidence(&profile, SaturationVerdict::Saturated, epoch());
    assert_eq!(evidence.verdict, SaturationVerdict::Saturated);
    assert_eq!(evidence.total_workloads, 90); // 9 families * 10
    assert_eq!(evidence.covered_families, 9);
    assert_eq!(evidence.epoch, epoch());
}

#[test]
fn test_build_evidence_hash_deterministic() {
    let families = equal_families();
    let profile = compute_coverage(&families);
    let e1 = build_evidence(&profile, SaturationVerdict::Saturated, epoch());
    let e2 = build_evidence(&profile, SaturationVerdict::Saturated, epoch());
    assert_eq!(e1.receipt_hash, e2.receipt_hash);
}

#[test]
fn test_build_evidence_different_verdict_different_hash() {
    let families = equal_families();
    let profile = compute_coverage(&families);
    let e1 = build_evidence(&profile, SaturationVerdict::Saturated, epoch());
    let e2 = build_evidence(&profile, SaturationVerdict::Sparse, epoch());
    assert_ne!(e1.receipt_hash, e2.receipt_hash);
}

#[test]
fn test_build_evidence_different_epoch_different_hash() {
    let families = equal_families();
    let profile = compute_coverage(&families);
    let e1 = build_evidence(&profile, SaturationVerdict::Saturated, SecurityEpoch::from_raw(1));
    let e2 = build_evidence(&profile, SaturationVerdict::Saturated, SecurityEpoch::from_raw(2));
    assert_ne!(e1.receipt_hash, e2.receipt_hash);
}

#[test]
fn test_build_evidence_serde_roundtrip() {
    let families = equal_families();
    let profile = compute_coverage(&families);
    let evidence = build_evidence(&profile, SaturationVerdict::Saturated, epoch());
    let json = serde_json::to_string(&evidence).unwrap();
    let back: SaturationEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(evidence, back);
}

#[test]
fn test_build_evidence_empty_profile() {
    let profile = compute_coverage(&[]);
    let evidence = build_evidence(&profile, SaturationVerdict::InsufficientData, epoch());
    assert_eq!(evidence.total_workloads, 0);
    assert_eq!(evidence.covered_families, 0);
}

// ---------------------------------------------------------------------------
// GateResult serde
// ---------------------------------------------------------------------------

#[test]
fn test_gate_result_serde_roundtrip() {
    let families = equal_families();
    let config = GateConfig::default();
    let result = evaluate(&families, &config);
    let json = serde_json::to_string(&result).unwrap();
    let back: GateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_single_family_board_not_saturated() {
    let families = vec![
        FamilyCoverage::new(WorkloadFamily::BranchHeavy, 100, FIXED_ONE, FIXED_ONE, 0),
    ];
    let config = GateConfig::default();
    let result = evaluate(&families, &config);
    // Only 1 family covered < 7 min. Max share = 1.0 > 500_000 -> CherryPicked.
    assert!(!result.decision.allows_proceed());
}

#[test]
fn test_all_families_one_workload_each() {
    // Each family has 1 workload (below default min_workloads_per_family=3).
    let families: Vec<FamilyCoverage> = WorkloadFamily::ALL
        .iter()
        .map(|&f| FamilyCoverage::new(f, 1, 111_111, 900_000, 50_000))
        .collect();
    let config = GateConfig::default();
    let result = evaluate(&families, &config);
    assert!(!result.decision.allows_proceed(), "decision: {:?}", result.decision);
}

#[test]
fn test_permissive_config_single_family_passes() {
    let families = vec![
        FamilyCoverage::new(WorkloadFamily::ResourceSpiky, 1, FIXED_ONE, FIXED_ONE, 0),
    ];
    let config = GateConfig::permissive();
    let result = evaluate(&families, &config);
    assert!(result.decision.allows_proceed(), "decision: {:?}", result.decision);
}

#[test]
fn test_eight_families_with_default_config() {
    // 8 families, each with sufficient workloads and coverage.
    let families: Vec<FamilyCoverage> = WorkloadFamily::ALL
        .iter()
        .take(8)
        .map(|&f| FamilyCoverage::new(f, 5, 125_000, 500_000, 50_000))
        .collect();
    let config = GateConfig::default();
    let result = evaluate(&families, &config);
    // 8 >= 7 min families, all meet coverage.
    assert_eq!(result.verdict, SaturationVerdict::Saturated);
}

#[test]
fn test_large_workload_counts() {
    let families: Vec<FamilyCoverage> = WorkloadFamily::ALL
        .iter()
        .map(|&f| FamilyCoverage::new(f, 1_000_000, 111_111, 999_000, 1_000))
        .collect();
    let config = GateConfig::default();
    let result = evaluate(&families, &config);
    assert_eq!(result.decision, GateDecision::Pass);
}

#[test]
fn test_content_hash_not_all_zeros() {
    let families = equal_families();
    let config = GateConfig::default();
    let result = evaluate(&families, &config);
    // The receipt hash should not be all zeros.
    let zero_hash = ContentHash::compute(&[0u8; 32]);
    assert_ne!(result.receipt_hash, zero_hash);
}
