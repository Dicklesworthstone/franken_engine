//! Integration tests for the benchmark_coverage_saturation_gate module.
//!
//! Bead: bd-1lsy.8.5.5 [RGC-705E]

use frankenengine_engine::benchmark_coverage_saturation_gate::*;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn equal_families() -> Vec<FamilyCoverage> {
    WorkloadFamily::ALL
        .iter()
        .map(|&f| FamilyCoverage::new(f, 10, 111_111, 900_000, 50_000))
        .collect()
}

fn dominant_families() -> Vec<FamilyCoverage> {
    let mut fams: Vec<FamilyCoverage> = WorkloadFamily::ALL
        .iter()
        .map(|&f| FamilyCoverage::new(f, 5, 10_000, 500_000, 100_000))
        .collect();
    fams[0].total_weight = 900_000;
    fams[0].workload_count = 50;
    fams
}

fn cherry_picked_families() -> Vec<FamilyCoverage> {
    vec![
        FamilyCoverage::new(WorkloadFamily::BranchHeavy, 20, 700_000, 950_000, 20_000),
        FamilyCoverage::new(WorkloadFamily::Vectorizable, 15, 300_000, 800_000, 50_000),
    ]
}

// -- Constants --

#[test]
fn test_constants() {
    assert!(SCHEMA_VERSION.contains("benchmark-coverage-saturation-gate"));
    assert_eq!(COMPONENT, "benchmark_coverage_saturation_gate");
    assert_eq!(BEAD_ID, "bd-1lsy.8.5.5");
    assert_eq!(POLICY_ID, "RGC-705E");
    assert_eq!(FIXED_ONE, 1_000_000);
    assert_eq!(TOTAL_WORKLOAD_FAMILIES, WorkloadFamily::ALL.len());
    const {
        assert!(DEFAULT_MIN_FAMILIES_COVERED <= TOTAL_WORKLOAD_FAMILIES);
        assert!(DEFAULT_MIN_FAMILY_COVERAGE < FIXED_ONE);
        assert!(DEFAULT_MAX_GINI < FIXED_ONE);
        assert!(DEFAULT_MIN_ENTROPY < FIXED_ONE);
        assert!(DEFAULT_MAX_SINGLE_FAMILY_SHARE < FIXED_ONE);
    }
}

// -- WorkloadFamily --

#[test]
fn test_workload_family_display_all() {
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
    for (f, exp) in WorkloadFamily::ALL.iter().zip(expected.iter()) {
        assert_eq!(f.to_string(), *exp);
        assert_eq!(f.as_str(), *exp);
    }
}

#[test]
fn test_workload_family_serde_roundtrip() {
    for &f in WorkloadFamily::ALL {
        let json = serde_json::to_string(&f).unwrap();
        let back: WorkloadFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }
    assert_eq!(
        serde_json::to_string(&WorkloadFamily::HostcallBoundary).unwrap(),
        "\"hostcall_boundary\""
    );
}

#[test]
fn test_workload_family_canonical_ordering() {
    for i in 1..WorkloadFamily::ALL.len() {
        assert!(WorkloadFamily::ALL[i - 1] < WorkloadFamily::ALL[i]);
    }
}

// -- SaturationVerdict --

#[test]
fn test_saturation_verdict_display() {
    assert_eq!(SaturationVerdict::Saturated.to_string(), "saturated");
    assert_eq!(
        SaturationVerdict::NearSaturated.to_string(),
        "near_saturated"
    );
    assert_eq!(SaturationVerdict::Sparse.to_string(), "sparse");
    assert_eq!(SaturationVerdict::CherryPicked.to_string(), "cherry_picked");
    assert_eq!(
        SaturationVerdict::InsufficientData.to_string(),
        "insufficient_data"
    );
}

#[test]
fn test_saturation_verdict_acceptable() {
    assert!(SaturationVerdict::Saturated.is_acceptable());
    assert!(SaturationVerdict::NearSaturated.is_acceptable());
    assert!(!SaturationVerdict::Sparse.is_acceptable());
    assert!(!SaturationVerdict::CherryPicked.is_acceptable());
    assert!(!SaturationVerdict::InsufficientData.is_acceptable());
}

#[test]
fn test_saturation_verdict_serde() {
    for v in [
        SaturationVerdict::Saturated,
        SaturationVerdict::NearSaturated,
        SaturationVerdict::Sparse,
        SaturationVerdict::CherryPicked,
        SaturationVerdict::InsufficientData,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(v, serde_json::from_str::<SaturationVerdict>(&json).unwrap());
    }
}

// -- RepresentativenessLevel --

#[test]
fn test_representativeness_display() {
    assert_eq!(
        RepresentativenessLevel::Representative.to_string(),
        "representative"
    );
    assert_eq!(
        RepresentativenessLevel::MarginallyRepresentative.to_string(),
        "marginally_representative"
    );
    assert_eq!(RepresentativenessLevel::Skewed.to_string(), "skewed");
    assert_eq!(
        RepresentativenessLevel::Unrepresentative.to_string(),
        "unrepresentative"
    );
}

#[test]
fn test_representativeness_acceptable() {
    assert!(RepresentativenessLevel::Representative.is_acceptable());
    assert!(RepresentativenessLevel::MarginallyRepresentative.is_acceptable());
    assert!(!RepresentativenessLevel::Skewed.is_acceptable());
    assert!(!RepresentativenessLevel::Unrepresentative.is_acceptable());
}

#[test]
fn test_representativeness_serde() {
    for v in [
        RepresentativenessLevel::Representative,
        RepresentativenessLevel::MarginallyRepresentative,
        RepresentativenessLevel::Skewed,
        RepresentativenessLevel::Unrepresentative,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(
            v,
            serde_json::from_str::<RepresentativenessLevel>(&json).unwrap()
        );
    }
}

// -- GateDecision --

#[test]
fn test_gate_decision_display() {
    assert_eq!(GateDecision::Pass.to_string(), "pass");
    assert_eq!(
        GateDecision::ConditionalPass.to_string(),
        "conditional_pass"
    );
    assert_eq!(GateDecision::Fail.to_string(), "fail");
    assert_eq!(
        GateDecision::InsufficientEvidence.to_string(),
        "insufficient_evidence"
    );
}

#[test]
fn test_gate_decision_allows_proceed() {
    assert!(GateDecision::Pass.allows_proceed());
    assert!(GateDecision::ConditionalPass.allows_proceed());
    assert!(!GateDecision::Fail.allows_proceed());
    assert!(!GateDecision::InsufficientEvidence.allows_proceed());
}

#[test]
fn test_gate_decision_serde() {
    for d in [
        GateDecision::Pass,
        GateDecision::ConditionalPass,
        GateDecision::Fail,
        GateDecision::InsufficientEvidence,
    ] {
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(d, serde_json::from_str::<GateDecision>(&json).unwrap());
    }
}

// -- FamilyCoverage --

#[test]
fn test_family_coverage_new() {
    let fc = FamilyCoverage::new(WorkloadFamily::BranchHeavy, 12, 200_000, 750_000, 40_000);
    assert_eq!(fc.family, WorkloadFamily::BranchHeavy);
    assert_eq!(fc.workload_count, 12);
    assert_eq!(fc.total_weight, 200_000);
    assert_eq!(fc.coverage_fraction, 750_000);
    assert_eq!(fc.max_gap_fraction, 40_000);
}

#[test]
fn test_family_coverage_is_present() {
    assert!(FamilyCoverage::new(WorkloadFamily::Vectorizable, 1, 100_000, 500_000, 0).is_present());
    assert!(!FamilyCoverage::new(WorkloadFamily::Vectorizable, 0, 0, 0, 0).is_present());
}

#[test]
fn test_family_coverage_meets_coverage() {
    let fc = FamilyCoverage::new(WorkloadFamily::StartupImage, 3, 100_000, 500_000, 0);
    assert!(fc.meets_coverage(500_000));
    assert!(fc.meets_coverage(300_000));
    assert!(!fc.meets_coverage(600_000));
}

#[test]
fn test_family_coverage_serde() {
    let fc = FamilyCoverage::new(WorkloadFamily::ResourceSpiky, 7, 80_000, 650_000, 30_000);
    let json = serde_json::to_string(&fc).unwrap();
    assert_eq!(fc, serde_json::from_str::<FamilyCoverage>(&json).unwrap());
}

// -- compute_coverage / DistributionProfile --

#[test]
fn test_compute_coverage_empty() {
    let p = compute_coverage(&[]);
    assert!(p.family_coverages.is_empty());
    assert_eq!(p.gini_coefficient, 0);
    assert_eq!(p.entropy, 0);
    assert_eq!(p.max_family_share, 0);
}

#[test]
fn test_compute_coverage_single_family() {
    let p = compute_coverage(&[FamilyCoverage::new(
        WorkloadFamily::BranchHeavy,
        10,
        FIXED_ONE,
        900_000,
        50_000,
    )]);
    assert_eq!(p.max_family_share, FIXED_ONE);
    assert_eq!(p.gini_coefficient, 0);
    assert_eq!(p.entropy, FIXED_ONE);
}

#[test]
fn test_compute_coverage_equal_weights() {
    let p = compute_coverage(&equal_families());
    assert_eq!(p.gini_coefficient, 0);
    assert!(p.entropy >= 990_000, "entropy: {}", p.entropy);
    assert_eq!(p.family_coverages.len(), 9);
}

#[test]
fn test_compute_coverage_dominant() {
    let p = compute_coverage(&dominant_families());
    assert!(p.gini_coefficient > 200_000, "gini: {}", p.gini_coefficient);
    assert!(
        p.max_family_share > 500_000,
        "max_share: {}",
        p.max_family_share
    );
}

#[test]
fn test_compute_coverage_zero_weight() {
    let families: Vec<_> = WorkloadFamily::ALL
        .iter()
        .map(|&f| FamilyCoverage::new(f, 5, 0, 0, 0))
        .collect();
    let p = compute_coverage(&families);
    assert_eq!(p.max_family_share, 0);
    assert_eq!(p.gini_coefficient, 0);
}

#[test]
fn test_compute_coverage_two_equal() {
    let p = compute_coverage(&[
        FamilyCoverage::new(WorkloadFamily::BranchHeavy, 10, 500_000, 800_000, 30_000),
        FamilyCoverage::new(WorkloadFamily::Vectorizable, 10, 500_000, 800_000, 30_000),
    ]);
    assert_eq!(p.gini_coefficient, 0);
    assert!(p.entropy >= 990_000);
    assert_eq!(p.max_family_share, p.min_family_share);
}

#[test]
fn test_compute_coverage_two_unequal() {
    let p = compute_coverage(&[
        FamilyCoverage::new(WorkloadFamily::BranchHeavy, 10, 900_000, 800_000, 30_000),
        FamilyCoverage::new(WorkloadFamily::Vectorizable, 10, 100_000, 800_000, 30_000),
    ]);
    assert!(p.gini_coefficient > 0);
    assert!(p.max_family_share > p.min_family_share);
}

#[test]
fn test_distribution_profile_serde() {
    let p = compute_coverage(&equal_families());
    let json = serde_json::to_string(&p).unwrap();
    assert_eq!(
        p,
        serde_json::from_str::<DistributionProfile>(&json).unwrap()
    );
}

// -- evaluate_saturation --

#[test]
fn test_sat_empty_insufficient() {
    assert_eq!(
        evaluate_saturation(&compute_coverage(&[]), &GateConfig::default()),
        SaturationVerdict::InsufficientData
    );
}

#[test]
fn test_sat_equal_saturated() {
    assert_eq!(
        evaluate_saturation(&compute_coverage(&equal_families()), &GateConfig::default()),
        SaturationVerdict::Saturated
    );
}

#[test]
fn test_sat_six_families_near() {
    let fams: Vec<_> = WorkloadFamily::ALL
        .iter()
        .take(6)
        .map(|&f| FamilyCoverage::new(f, 5, 100_000, 500_000, 50_000))
        .collect();
    assert_eq!(
        evaluate_saturation(&compute_coverage(&fams), &GateConfig::default()),
        SaturationVerdict::NearSaturated
    );
}

#[test]
fn test_sat_three_families_sparse() {
    let fams: Vec<_> = WorkloadFamily::ALL
        .iter()
        .take(3)
        .map(|&f| FamilyCoverage::new(f, 5, 100_000, 500_000, 50_000))
        .collect();
    assert_eq!(
        evaluate_saturation(&compute_coverage(&fams), &GateConfig::default()),
        SaturationVerdict::Sparse
    );
}

#[test]
fn test_sat_cherry_picked() {
    assert_eq!(
        evaluate_saturation(
            &compute_coverage(&cherry_picked_families()),
            &GateConfig::default()
        ),
        SaturationVerdict::CherryPicked
    );
}

#[test]
fn test_sat_zero_workloads_insufficient() {
    let fams: Vec<_> = WorkloadFamily::ALL
        .iter()
        .map(|&f| FamilyCoverage::new(f, 0, 100_000, 0, 0))
        .collect();
    assert_eq!(
        evaluate_saturation(&compute_coverage(&fams), &GateConfig::default()),
        SaturationVerdict::InsufficientData
    );
}

#[test]
fn test_sat_below_min_workloads() {
    let fams: Vec<_> = WorkloadFamily::ALL
        .iter()
        .map(|&f| FamilyCoverage::new(f, 1, 111_111, 900_000, 50_000))
        .collect();
    assert!(!evaluate_saturation(&compute_coverage(&fams), &GateConfig::default()).is_acceptable());
}

#[test]
fn test_sat_low_coverage_fraction() {
    let fams: Vec<_> = WorkloadFamily::ALL
        .iter()
        .map(|&f| FamilyCoverage::new(f, 10, 111_111, 50_000, 50_000))
        .collect();
    assert_eq!(
        evaluate_saturation(&compute_coverage(&fams), &GateConfig::default()),
        SaturationVerdict::NearSaturated
    );
}

// -- evaluate_representativeness --

#[test]
fn test_repr_equal_representative() {
    assert_eq!(
        evaluate_representativeness(&compute_coverage(&equal_families()), &GateConfig::default()),
        RepresentativenessLevel::Representative
    );
}

#[test]
fn test_repr_empty_unrepresentative() {
    assert_eq!(
        evaluate_representativeness(&compute_coverage(&[]), &GateConfig::default()),
        RepresentativenessLevel::Unrepresentative
    );
}

#[test]
fn test_repr_dominant_not_acceptable() {
    assert!(
        !evaluate_representativeness(
            &compute_coverage(&dominant_families()),
            &GateConfig::default()
        )
        .is_acceptable()
    );
}

#[test]
fn test_repr_permissive_passes() {
    assert!(
        evaluate_representativeness(
            &compute_coverage(&dominant_families()),
            &GateConfig::permissive()
        )
        .is_acceptable()
    );
}

#[test]
fn test_repr_marginal() {
    let config = GateConfig {
        min_entropy: FIXED_ONE,
        ..GateConfig::default()
    };
    assert_eq!(
        evaluate_representativeness(&compute_coverage(&equal_families()), &config),
        RepresentativenessLevel::MarginallyRepresentative
    );
}

#[test]
fn test_repr_skewed() {
    let config = GateConfig {
        max_gini_coefficient: 100_000,
        min_entropy: 999_999,
        max_single_family_share: FIXED_ONE,
        ..GateConfig::default()
    };
    assert_eq!(
        evaluate_representativeness(&compute_coverage(&dominant_families()), &config),
        RepresentativenessLevel::Skewed
    );
}

// -- Full evaluate --

#[test]
fn test_evaluate_pass() {
    let r = evaluate(&equal_families(), &GateConfig::default());
    assert_eq!(r.decision, GateDecision::Pass);
    assert_eq!(r.verdict, SaturationVerdict::Saturated);
    assert_eq!(
        r.representativeness,
        RepresentativenessLevel::Representative
    );
    assert!(r.blocking_reasons.is_empty());
}

#[test]
fn test_evaluate_fail() {
    let r = evaluate(&cherry_picked_families(), &GateConfig::default());
    assert_eq!(r.decision, GateDecision::Fail);
    assert!(!r.blocking_reasons.is_empty());
}

#[test]
fn test_evaluate_insufficient() {
    assert_eq!(
        evaluate(&[], &GateConfig::default()).decision,
        GateDecision::InsufficientEvidence
    );
}

#[test]
fn test_evaluate_conditional() {
    let mut fams = equal_families();
    fams[4].workload_count = 2;
    let r = evaluate(&fams, &GateConfig::default());
    assert!(r.decision == GateDecision::Pass || r.decision == GateDecision::ConditionalPass);
}

#[test]
fn test_evaluate_blocking_reasons_content() {
    let r = evaluate(&cherry_picked_families(), &GateConfig::default());
    let combined = r.blocking_reasons.join(" ");
    assert!(
        combined.contains("saturation")
            || combined.contains("representativeness")
            || combined.contains("families")
    );
}

#[test]
fn test_evaluate_recommendations() {
    let mut fams: Vec<_> = WorkloadFamily::ALL
        .iter()
        .map(|&f| FamilyCoverage::new(f, 5, 50_000, 500_000, 50_000))
        .collect();
    fams[0].total_weight = 800_000;
    let r = evaluate(&fams, &GateConfig::default());
    let recs = r.recommendations.join(" ");
    assert!(recs.contains("Gini") || recs.contains("share"));
}

#[test]
fn test_evaluate_permissive_passes() {
    assert!(
        evaluate(&cherry_picked_families(), &GateConfig::permissive())
            .decision
            .allows_proceed()
    );
}

#[test]
fn test_evaluate_strict() {
    let fams: Vec<_> = WorkloadFamily::ALL
        .iter()
        .map(|&f| FamilyCoverage::new(f, 10, 111_111, 150_000, 50_000))
        .collect();
    assert_eq!(
        evaluate(&fams, &GateConfig::strict()).verdict,
        SaturationVerdict::NearSaturated
    );
}

// -- Receipt hash determinism --

#[test]
fn test_receipt_hash_deterministic() {
    let c = GateConfig::default();
    assert_eq!(
        evaluate(&equal_families(), &c).receipt_hash,
        evaluate(&equal_families(), &c).receipt_hash
    );
}

#[test]
fn test_different_inputs_different_hashes() {
    let c = GateConfig::default();
    assert_ne!(
        evaluate(&equal_families(), &c).receipt_hash,
        evaluate(&cherry_picked_families(), &c).receipt_hash
    );
}

#[test]
fn test_receipt_hash_not_trivial() {
    assert_ne!(
        evaluate(&equal_families(), &GateConfig::default()).receipt_hash,
        ContentHash::compute(&[0u8; 32])
    );
}

// -- GateConfig --

#[test]
fn test_gate_config_default() {
    let c = GateConfig::default();
    assert_eq!(c.min_families_covered, DEFAULT_MIN_FAMILIES_COVERED);
    assert_eq!(c.min_family_coverage_fraction, DEFAULT_MIN_FAMILY_COVERAGE);
    assert_eq!(c.max_gini_coefficient, DEFAULT_MAX_GINI);
    assert_eq!(c.min_entropy, DEFAULT_MIN_ENTROPY);
    assert_eq!(c.max_single_family_share, DEFAULT_MAX_SINGLE_FAMILY_SHARE);
    assert_eq!(c.min_workloads_per_family, DEFAULT_MIN_WORKLOADS_PER_FAMILY);
}

#[test]
fn test_gate_config_strict_and_permissive() {
    let (s, d) = (GateConfig::strict(), GateConfig::default());
    assert!(s.min_families_covered >= d.min_families_covered);
    assert!(s.min_family_coverage_fraction >= d.min_family_coverage_fraction);
    assert!(s.max_gini_coefficient <= d.max_gini_coefficient);
    let p = GateConfig::permissive();
    assert_eq!(p.min_families_covered, 1);
    assert_eq!(p.max_gini_coefficient, FIXED_ONE);
    assert_eq!(p.min_entropy, 0);
    // serde roundtrip
    let json = serde_json::to_string(&s).unwrap();
    assert_eq!(s, serde_json::from_str::<GateConfig>(&json).unwrap());
}

// -- DecisionReceipt --

#[test]
fn test_decision_receipt_fields_and_determinism() {
    let result = evaluate(&equal_families(), &GateConfig::default());
    let receipt = DecisionReceipt::from_result(&result, epoch());
    assert_eq!(receipt.component, COMPONENT);
    assert_eq!(receipt.epoch, epoch());
    assert_eq!(receipt.decision, result.decision);
    assert_eq!(receipt.evidence_hash, result.receipt_hash);
    // Deterministic.
    assert_eq!(
        receipt.receipt_hash,
        DecisionReceipt::from_result(&result, epoch()).receipt_hash
    );
}

#[test]
fn test_decision_receipt_epoch_varies_hash() {
    let result = evaluate(&equal_families(), &GateConfig::default());
    assert_ne!(
        DecisionReceipt::from_result(&result, SecurityEpoch::from_raw(1)).receipt_hash,
        DecisionReceipt::from_result(&result, SecurityEpoch::from_raw(2)).receipt_hash,
    );
}

#[test]
fn test_decision_receipt_serde() {
    let receipt = DecisionReceipt::from_result(
        &evaluate(&equal_families(), &GateConfig::default()),
        epoch(),
    );
    let json = serde_json::to_string(&receipt).unwrap();
    assert_eq!(
        receipt,
        serde_json::from_str::<DecisionReceipt>(&json).unwrap()
    );
}

// -- BatchResult --

#[test]
fn test_batch_empty() {
    let b = BatchResult::new(Vec::new());
    assert!(b.is_empty());
    assert_eq!(b.len(), 0);
    assert!(!b.all_acceptable());
}

#[test]
fn test_batch_all_pass() {
    let c = GateConfig::default();
    let b = BatchResult::new(vec![
        evaluate(&equal_families(), &c),
        evaluate(&equal_families(), &c),
    ]);
    assert_eq!(b.len(), 2);
    assert!(b.all_acceptable());
    assert!(b.summary.contains("2 pass"));
}

#[test]
fn test_batch_mixed() {
    let b = BatchResult::new(vec![
        evaluate(&equal_families(), &GateConfig::default()),
        evaluate(&cherry_picked_families(), &GateConfig::default()),
    ]);
    assert!(!b.all_acceptable());
    assert!(b.summary.contains("1 fail"));
}

#[test]
fn test_batch_serde() {
    let b = BatchResult::new(vec![evaluate(&equal_families(), &GateConfig::default())]);
    let json = serde_json::to_string(&b).unwrap();
    assert_eq!(b, serde_json::from_str::<BatchResult>(&json).unwrap());
}

// -- build_evidence --

#[test]
fn test_build_evidence_fields_and_determinism() {
    let p = compute_coverage(&equal_families());
    let ev = build_evidence(&p, SaturationVerdict::Saturated, epoch());
    assert_eq!(ev.verdict, SaturationVerdict::Saturated);
    assert_eq!(ev.total_workloads, 90);
    assert_eq!(ev.covered_families, 9);
    assert_eq!(ev.epoch, epoch());
    assert_eq!(
        ev.receipt_hash,
        build_evidence(&p, SaturationVerdict::Saturated, epoch()).receipt_hash
    );
}

#[test]
fn test_build_evidence_hash_varies() {
    let p = compute_coverage(&equal_families());
    assert_ne!(
        build_evidence(&p, SaturationVerdict::Saturated, epoch()).receipt_hash,
        build_evidence(&p, SaturationVerdict::Sparse, epoch()).receipt_hash,
    );
    assert_ne!(
        build_evidence(&p, SaturationVerdict::Saturated, SecurityEpoch::from_raw(1)).receipt_hash,
        build_evidence(&p, SaturationVerdict::Saturated, SecurityEpoch::from_raw(2)).receipt_hash,
    );
}

#[test]
fn test_build_evidence_empty() {
    let ev = build_evidence(
        &compute_coverage(&[]),
        SaturationVerdict::InsufficientData,
        epoch(),
    );
    assert_eq!(ev.total_workloads, 0);
    assert_eq!(ev.covered_families, 0);
}

#[test]
fn test_build_evidence_serde() {
    let ev = build_evidence(
        &compute_coverage(&equal_families()),
        SaturationVerdict::Saturated,
        epoch(),
    );
    let json = serde_json::to_string(&ev).unwrap();
    assert_eq!(
        ev,
        serde_json::from_str::<SaturationEvidence>(&json).unwrap()
    );
}

// -- GateResult serde + Edge cases --

#[test]
fn test_gate_result_serde() {
    let r = evaluate(&equal_families(), &GateConfig::default());
    let json = serde_json::to_string(&r).unwrap();
    assert_eq!(r, serde_json::from_str::<GateResult>(&json).unwrap());
}

#[test]
fn test_single_family_fails() {
    let r = evaluate(
        &[FamilyCoverage::new(
            WorkloadFamily::BranchHeavy,
            100,
            FIXED_ONE,
            FIXED_ONE,
            0,
        )],
        &GateConfig::default(),
    );
    assert!(!r.decision.allows_proceed());
}

#[test]
fn test_all_families_one_workload_fails() {
    let fams: Vec<_> = WorkloadFamily::ALL
        .iter()
        .map(|&f| FamilyCoverage::new(f, 1, 111_111, 900_000, 50_000))
        .collect();
    assert!(
        !evaluate(&fams, &GateConfig::default())
            .decision
            .allows_proceed()
    );
}

#[test]
fn test_permissive_single_family_passes() {
    let r = evaluate(
        &[FamilyCoverage::new(
            WorkloadFamily::ResourceSpiky,
            1,
            FIXED_ONE,
            FIXED_ONE,
            0,
        )],
        &GateConfig::permissive(),
    );
    assert!(r.decision.allows_proceed());
}

#[test]
fn test_eight_families_saturated() {
    let fams: Vec<_> = WorkloadFamily::ALL
        .iter()
        .take(8)
        .map(|&f| FamilyCoverage::new(f, 5, 125_000, 500_000, 50_000))
        .collect();
    assert_eq!(
        evaluate(&fams, &GateConfig::default()).verdict,
        SaturationVerdict::Saturated
    );
}

#[test]
fn test_large_workload_counts() {
    let fams: Vec<_> = WorkloadFamily::ALL
        .iter()
        .map(|&f| FamilyCoverage::new(f, 1_000_000, 111_111, 999_000, 1_000))
        .collect();
    assert_eq!(
        evaluate(&fams, &GateConfig::default()).decision,
        GateDecision::Pass
    );
}
