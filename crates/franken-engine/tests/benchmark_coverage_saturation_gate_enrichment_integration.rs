#![forbid(unsafe_code)]

//! Enrichment integration tests for the `benchmark_coverage_saturation_gate` module.

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

use frankenengine_engine::benchmark_coverage_saturation_gate::{
    BEAD_ID, BatchResult, COMPONENT, DEFAULT_MAX_GINI, DEFAULT_MAX_SINGLE_FAMILY_SHARE,
    DEFAULT_MIN_ENTROPY, DEFAULT_MIN_FAMILIES_COVERED, DEFAULT_MIN_FAMILY_COVERAGE,
    DEFAULT_MIN_WORKLOADS_PER_FAMILY, DecisionReceipt, FamilyCoverage, GateConfig, GateDecision,
    GateResult, POLICY_ID, RepresentativenessLevel, SCHEMA_VERSION, SaturationEvidence,
    SaturationVerdict, TOTAL_WORKLOAD_FAMILIES, WorkloadFamily, build_evidence, compute_coverage,
    evaluate, evaluate_representativeness, evaluate_saturation,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn family_cov(family: WorkloadFamily, count: u64, coverage: u64) -> FamilyCoverage {
    FamilyCoverage::new(family, count, count * 100_000, coverage, 0)
}

fn all_families_covered() -> Vec<FamilyCoverage> {
    WorkloadFamily::ALL
        .iter()
        .map(|f| family_cov(*f, 10, 500_000))
        .collect()
}

// ===========================================================================
// WorkloadFamily — Copy, BTreeSet, Debug/Display unique, as_str matches Display
// ===========================================================================

#[test]
fn enrichment_workload_family_copy_semantics() {
    let a = WorkloadFamily::BranchHeavy;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_workload_family_btreeset_dedup_9() {
    let mut set = BTreeSet::new();
    for v in WorkloadFamily::ALL {
        set.insert(*v);
    }
    set.insert(WorkloadFamily::BranchHeavy);
    assert_eq!(set.len(), TOTAL_WORKLOAD_FAMILIES);
}

#[test]
fn enrichment_workload_family_debug_all_unique() {
    let strs: BTreeSet<String> = WorkloadFamily::ALL
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
    assert_eq!(strs.len(), TOTAL_WORKLOAD_FAMILIES);
}

#[test]
fn enrichment_workload_family_display_all_unique() {
    let strs: BTreeSet<String> = WorkloadFamily::ALL.iter().map(|v| format!("{v}")).collect();
    assert_eq!(strs.len(), TOTAL_WORKLOAD_FAMILIES);
}

#[test]
fn enrichment_workload_family_as_str_matches_display() {
    for v in WorkloadFamily::ALL {
        assert_eq!(v.as_str(), format!("{v}"));
    }
}

#[test]
fn enrichment_workload_family_all_count() {
    assert_eq!(WorkloadFamily::ALL.len(), TOTAL_WORKLOAD_FAMILIES);
    assert_eq!(TOTAL_WORKLOAD_FAMILIES, 9);
}

// ===========================================================================
// SaturationVerdict — Copy, BTreeSet, Debug/Display unique, as_str, is_acceptable
// ===========================================================================

#[test]
fn enrichment_saturation_verdict_copy_semantics() {
    let a = SaturationVerdict::Saturated;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_saturation_verdict_debug_all_unique() {
    let variants = [
        SaturationVerdict::Saturated,
        SaturationVerdict::NearSaturated,
        SaturationVerdict::Sparse,
        SaturationVerdict::CherryPicked,
        SaturationVerdict::InsufficientData,
    ];
    let strs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(strs.len(), 5);
}

#[test]
fn enrichment_saturation_verdict_display_all_unique() {
    let variants = [
        SaturationVerdict::Saturated,
        SaturationVerdict::NearSaturated,
        SaturationVerdict::Sparse,
        SaturationVerdict::CherryPicked,
        SaturationVerdict::InsufficientData,
    ];
    let strs: BTreeSet<String> = variants.iter().map(|v| format!("{v}")).collect();
    assert_eq!(strs.len(), 5);
}

#[test]
fn enrichment_saturation_verdict_as_str_matches_display() {
    let variants = [
        SaturationVerdict::Saturated,
        SaturationVerdict::NearSaturated,
        SaturationVerdict::Sparse,
        SaturationVerdict::CherryPicked,
        SaturationVerdict::InsufficientData,
    ];
    for v in &variants {
        assert_eq!(v.as_str(), format!("{v}"));
    }
}

#[test]
fn enrichment_saturation_verdict_acceptable_exactly_two() {
    let acceptable: Vec<_> = [
        SaturationVerdict::Saturated,
        SaturationVerdict::NearSaturated,
        SaturationVerdict::Sparse,
        SaturationVerdict::CherryPicked,
        SaturationVerdict::InsufficientData,
    ]
    .iter()
    .filter(|v| v.is_acceptable())
    .collect();
    assert_eq!(acceptable.len(), 2);
    assert!(SaturationVerdict::Saturated.is_acceptable());
    assert!(SaturationVerdict::NearSaturated.is_acceptable());
}

// ===========================================================================
// RepresentativenessLevel — Copy, Debug/Display unique, as_str, is_acceptable
// ===========================================================================

#[test]
fn enrichment_representativeness_level_copy_semantics() {
    let a = RepresentativenessLevel::Representative;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_representativeness_level_debug_all_unique() {
    let variants = [
        RepresentativenessLevel::Representative,
        RepresentativenessLevel::MarginallyRepresentative,
        RepresentativenessLevel::Skewed,
        RepresentativenessLevel::Unrepresentative,
    ];
    let strs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(strs.len(), 4);
}

#[test]
fn enrichment_representativeness_level_display_all_unique() {
    let variants = [
        RepresentativenessLevel::Representative,
        RepresentativenessLevel::MarginallyRepresentative,
        RepresentativenessLevel::Skewed,
        RepresentativenessLevel::Unrepresentative,
    ];
    let strs: BTreeSet<String> = variants.iter().map(|v| format!("{v}")).collect();
    assert_eq!(strs.len(), 4);
}

#[test]
fn enrichment_representativeness_level_as_str_matches_display() {
    let variants = [
        RepresentativenessLevel::Representative,
        RepresentativenessLevel::MarginallyRepresentative,
        RepresentativenessLevel::Skewed,
        RepresentativenessLevel::Unrepresentative,
    ];
    for v in &variants {
        assert_eq!(v.as_str(), format!("{v}"));
    }
}

#[test]
fn enrichment_representativeness_level_acceptable_exactly_two() {
    let acceptable: Vec<_> = [
        RepresentativenessLevel::Representative,
        RepresentativenessLevel::MarginallyRepresentative,
        RepresentativenessLevel::Skewed,
        RepresentativenessLevel::Unrepresentative,
    ]
    .iter()
    .filter(|v| v.is_acceptable())
    .collect();
    assert_eq!(acceptable.len(), 2);
}

// ===========================================================================
// GateDecision — Copy, Debug/Display unique, as_str, allows_proceed
// ===========================================================================

#[test]
fn enrichment_gate_decision_copy_semantics() {
    let a = GateDecision::Pass;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_gate_decision_debug_all_unique() {
    let variants = [
        GateDecision::Pass,
        GateDecision::ConditionalPass,
        GateDecision::Fail,
        GateDecision::InsufficientEvidence,
    ];
    let strs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(strs.len(), 4);
}

#[test]
fn enrichment_gate_decision_display_all_unique() {
    let variants = [
        GateDecision::Pass,
        GateDecision::ConditionalPass,
        GateDecision::Fail,
        GateDecision::InsufficientEvidence,
    ];
    let strs: BTreeSet<String> = variants.iter().map(|v| format!("{v}")).collect();
    assert_eq!(strs.len(), 4);
}

#[test]
fn enrichment_gate_decision_as_str_matches_display() {
    let variants = [
        GateDecision::Pass,
        GateDecision::ConditionalPass,
        GateDecision::Fail,
        GateDecision::InsufficientEvidence,
    ];
    for v in &variants {
        assert_eq!(v.as_str(), format!("{v}"));
    }
}

#[test]
fn enrichment_gate_decision_allows_proceed_exactly_two() {
    let allowed: Vec<_> = [
        GateDecision::Pass,
        GateDecision::ConditionalPass,
        GateDecision::Fail,
        GateDecision::InsufficientEvidence,
    ]
    .iter()
    .filter(|v| v.allows_proceed())
    .collect();
    assert_eq!(allowed.len(), 2);
    assert!(GateDecision::Pass.allows_proceed());
    assert!(GateDecision::ConditionalPass.allows_proceed());
}

// ===========================================================================
// FamilyCoverage — Clone, Debug, JSON fields, serde, methods
// ===========================================================================

#[test]
fn enrichment_family_coverage_clone_independence() {
    let a = FamilyCoverage::new(WorkloadFamily::BranchHeavy, 10, 500_000, 300_000, 50_000);
    let mut b = a.clone();
    b.workload_count = 99;
    assert_ne!(a.workload_count, b.workload_count);
}

#[test]
fn enrichment_family_coverage_debug_nonempty() {
    let fc = FamilyCoverage::new(WorkloadFamily::Vectorizable, 5, 200_000, 100_000, 0);
    let dbg = format!("{fc:?}");
    assert!(dbg.contains("FamilyCoverage"));
}

#[test]
fn enrichment_family_coverage_json_field_names() {
    let fc = FamilyCoverage::new(WorkloadFamily::NativeAddon, 3, 100_000, 50_000, 10_000);
    let json = serde_json::to_string(&fc).unwrap();
    for field in &[
        "family",
        "workload_count",
        "total_weight",
        "coverage_fraction",
        "max_gap_fraction",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing: {field}");
    }
}

#[test]
fn enrichment_family_coverage_is_present_positive() {
    let fc = FamilyCoverage::new(WorkloadFamily::BranchHeavy, 1, 100_000, 100_000, 0);
    assert!(fc.is_present());
}

#[test]
fn enrichment_family_coverage_is_present_zero() {
    let fc = FamilyCoverage::new(WorkloadFamily::BranchHeavy, 0, 0, 0, 0);
    assert!(!fc.is_present());
}

#[test]
fn enrichment_family_coverage_meets_coverage_boundary() {
    let fc = FamilyCoverage::new(WorkloadFamily::BranchHeavy, 5, 500_000, 100_000, 0);
    assert!(fc.meets_coverage(100_000));
    assert!(fc.meets_coverage(99_999));
    assert!(!fc.meets_coverage(100_001));
}

#[test]
fn enrichment_family_coverage_serde_roundtrip() {
    let fc = FamilyCoverage::new(WorkloadFamily::ResourceSpiky, 7, 300_000, 200_000, 10_000);
    let json = serde_json::to_string(&fc).unwrap();
    let back: FamilyCoverage = serde_json::from_str(&json).unwrap();
    assert_eq!(fc, back);
}

// ===========================================================================
// GateConfig — Clone, Debug, JSON fields, default/strict/permissive
// ===========================================================================

#[test]
fn enrichment_gate_config_clone_independence() {
    let mut a = GateConfig::default();
    let b = a.clone();
    a.min_families_covered = 99;
    assert_ne!(a.min_families_covered, b.min_families_covered);
}

#[test]
fn enrichment_gate_config_debug_nonempty() {
    let cfg = GateConfig::default();
    let dbg = format!("{cfg:?}");
    assert!(dbg.contains("GateConfig"));
}

#[test]
fn enrichment_gate_config_json_field_names() {
    let cfg = GateConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    for field in &[
        "min_families_covered",
        "min_family_coverage_fraction",
        "max_gini_coefficient",
        "min_entropy",
        "max_single_family_share",
        "min_workloads_per_family",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing: {field}");
    }
}

#[test]
fn enrichment_gate_config_default_matches_constants() {
    let cfg = GateConfig::default();
    assert_eq!(cfg.min_families_covered, DEFAULT_MIN_FAMILIES_COVERED);
    assert_eq!(
        cfg.min_family_coverage_fraction,
        DEFAULT_MIN_FAMILY_COVERAGE
    );
    assert_eq!(cfg.max_gini_coefficient, DEFAULT_MAX_GINI);
    assert_eq!(cfg.min_entropy, DEFAULT_MIN_ENTROPY);
    assert_eq!(cfg.max_single_family_share, DEFAULT_MAX_SINGLE_FAMILY_SHARE);
    assert_eq!(
        cfg.min_workloads_per_family,
        DEFAULT_MIN_WORKLOADS_PER_FAMILY
    );
}

#[test]
fn enrichment_gate_config_strict_stricter_than_default() {
    let def = GateConfig::default();
    let strict = GateConfig::strict();
    assert!(strict.min_families_covered >= def.min_families_covered);
    assert!(strict.min_entropy >= def.min_entropy);
}

#[test]
fn enrichment_gate_config_permissive_looser_than_default() {
    let def = GateConfig::default();
    let perm = GateConfig::permissive();
    assert!(perm.min_families_covered <= def.min_families_covered);
    assert!(perm.max_gini_coefficient >= def.max_gini_coefficient);
}

#[test]
fn enrichment_gate_config_serde_roundtrip() {
    let cfg = GateConfig::strict();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ===========================================================================
// DistributionProfile — Clone, Debug, compute_coverage
// ===========================================================================

#[test]
fn enrichment_distribution_profile_clone_independence() {
    let families = all_families_covered();
    let profile = compute_coverage(&families);
    let mut cloned = profile.clone();
    cloned.gini_coefficient = 999_999;
    assert_ne!(profile.gini_coefficient, cloned.gini_coefficient);
}

#[test]
fn enrichment_distribution_profile_debug_nonempty() {
    let families = all_families_covered();
    let profile = compute_coverage(&families);
    let dbg = format!("{profile:?}");
    assert!(dbg.contains("DistributionProfile"));
}

#[test]
fn enrichment_distribution_profile_json_field_names() {
    let families = all_families_covered();
    let profile = compute_coverage(&families);
    let json = serde_json::to_string(&profile).unwrap();
    for field in &[
        "family_coverages",
        "gini_coefficient",
        "entropy",
        "max_family_share",
        "min_family_share",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing: {field}");
    }
}

#[test]
fn enrichment_compute_coverage_equal_families_low_gini() {
    let families = all_families_covered();
    let profile = compute_coverage(&families);
    // Equal distribution should have low Gini
    assert!(
        profile.gini_coefficient < 100_000,
        "equal families should have low gini, got {}",
        profile.gini_coefficient
    );
}

#[test]
fn enrichment_compute_coverage_equal_families_high_entropy() {
    let families = all_families_covered();
    let profile = compute_coverage(&families);
    // Equal distribution should have high entropy
    assert!(
        profile.entropy > 800_000,
        "equal families should have high entropy, got {}",
        profile.entropy
    );
}

#[test]
fn enrichment_compute_coverage_empty_input() {
    let profile = compute_coverage(&[]);
    assert_eq!(profile.family_coverages.len(), 0);
}

// ===========================================================================
// GateResult — Clone, Debug, JSON fields, serde
// ===========================================================================

#[test]
fn enrichment_gate_result_clone_independence() {
    let families = all_families_covered();
    let result = evaluate(&families, &GateConfig::permissive());
    let mut cloned = result.clone();
    cloned.blocking_reasons.push("extra".to_string());
    assert_ne!(result.blocking_reasons.len(), cloned.blocking_reasons.len());
}

#[test]
fn enrichment_gate_result_debug_nonempty() {
    let families = all_families_covered();
    let result = evaluate(&families, &GateConfig::permissive());
    let dbg = format!("{result:?}");
    assert!(dbg.contains("GateResult"));
}

#[test]
fn enrichment_gate_result_json_field_names() {
    let families = all_families_covered();
    let result = evaluate(&families, &GateConfig::permissive());
    let json = serde_json::to_string(&result).unwrap();
    for field in &[
        "decision",
        "verdict",
        "representativeness",
        "blocking_reasons",
        "recommendations",
        "receipt_hash",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing: {field}");
    }
}

#[test]
fn enrichment_gate_result_serde_roundtrip() {
    let families = all_families_covered();
    let result = evaluate(&families, &GateConfig::permissive());
    let json = serde_json::to_string(&result).unwrap();
    let back: GateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ===========================================================================
// SaturationEvidence — Clone, Debug, JSON fields, serde
// ===========================================================================

#[test]
fn enrichment_saturation_evidence_clone_independence() {
    let families = all_families_covered();
    let profile = compute_coverage(&families);
    let verdict = evaluate_saturation(&profile, &GateConfig::default());
    let ev = build_evidence(&profile, verdict, epoch());
    let mut cloned = ev.clone();
    cloned.total_workloads = 999_999;
    assert_ne!(ev.total_workloads, cloned.total_workloads);
}

#[test]
fn enrichment_saturation_evidence_debug_nonempty() {
    let families = all_families_covered();
    let profile = compute_coverage(&families);
    let verdict = evaluate_saturation(&profile, &GateConfig::default());
    let ev = build_evidence(&profile, verdict, epoch());
    let dbg = format!("{ev:?}");
    assert!(dbg.contains("SaturationEvidence"));
}

#[test]
fn enrichment_saturation_evidence_json_field_names() {
    let families = all_families_covered();
    let profile = compute_coverage(&families);
    let verdict = evaluate_saturation(&profile, &GateConfig::default());
    let ev = build_evidence(&profile, verdict, epoch());
    let json = serde_json::to_string(&ev).unwrap();
    for field in &[
        "verdict",
        "profile",
        "total_workloads",
        "covered_families",
        "epoch",
        "receipt_hash",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing: {field}");
    }
}

#[test]
fn enrichment_saturation_evidence_serde_roundtrip() {
    let families = all_families_covered();
    let profile = compute_coverage(&families);
    let verdict = evaluate_saturation(&profile, &GateConfig::default());
    let ev = build_evidence(&profile, verdict, epoch());
    let json = serde_json::to_string(&ev).unwrap();
    let back: SaturationEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

// ===========================================================================
// DecisionReceipt — Clone, Debug, JSON fields, serde
// ===========================================================================

#[test]
fn enrichment_decision_receipt_clone_independence() {
    let families = all_families_covered();
    let result = evaluate(&families, &GateConfig::permissive());
    let receipt = DecisionReceipt::from_result(&result, epoch());
    let mut cloned = receipt.clone();
    cloned.component = "changed".to_string();
    assert_ne!(receipt.component, cloned.component);
}

#[test]
fn enrichment_decision_receipt_debug_nonempty() {
    let families = all_families_covered();
    let result = evaluate(&families, &GateConfig::permissive());
    let receipt = DecisionReceipt::from_result(&result, epoch());
    let dbg = format!("{receipt:?}");
    assert!(dbg.contains("DecisionReceipt"));
}

#[test]
fn enrichment_decision_receipt_json_field_names() {
    let families = all_families_covered();
    let result = evaluate(&families, &GateConfig::permissive());
    let receipt = DecisionReceipt::from_result(&result, epoch());
    let json = serde_json::to_string(&receipt).unwrap();
    for field in &[
        "receipt_hash",
        "component",
        "epoch",
        "decision",
        "evidence_hash",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing: {field}");
    }
}

#[test]
fn enrichment_decision_receipt_component_matches_constant() {
    let families = all_families_covered();
    let result = evaluate(&families, &GateConfig::permissive());
    let receipt = DecisionReceipt::from_result(&result, epoch());
    assert_eq!(receipt.component, COMPONENT);
}

#[test]
fn enrichment_decision_receipt_serde_roundtrip() {
    let families = all_families_covered();
    let result = evaluate(&families, &GateConfig::permissive());
    let receipt = DecisionReceipt::from_result(&result, epoch());
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

// ===========================================================================
// BatchResult — Clone, Debug, methods, serde
// ===========================================================================

#[test]
fn enrichment_batch_result_clone_independence() {
    let families = all_families_covered();
    let r = evaluate(&families, &GateConfig::permissive());
    let batch = BatchResult::new(vec![r]);
    let mut cloned = batch.clone();
    cloned.summary = "changed".to_string();
    assert_ne!(batch.summary, cloned.summary);
}

#[test]
fn enrichment_batch_result_debug_nonempty() {
    let batch = BatchResult::new(vec![]);
    let dbg = format!("{batch:?}");
    assert!(dbg.contains("BatchResult"));
}

#[test]
fn enrichment_batch_result_empty_not_acceptable() {
    let batch = BatchResult::new(vec![]);
    assert!(batch.is_empty());
    assert!(!batch.all_acceptable());
}

#[test]
fn enrichment_batch_result_len_matches_results() {
    let families = all_families_covered();
    let r1 = evaluate(&families, &GateConfig::permissive());
    let r2 = evaluate(&families, &GateConfig::permissive());
    let batch = BatchResult::new(vec![r1, r2]);
    assert_eq!(batch.len(), 2);
}

#[test]
fn enrichment_batch_result_serde_roundtrip() {
    let families = all_families_covered();
    let r = evaluate(&families, &GateConfig::permissive());
    let batch = BatchResult::new(vec![r]);
    let json = serde_json::to_string(&batch).unwrap();
    let back: BatchResult = serde_json::from_str(&json).unwrap();
    assert_eq!(batch, back);
}

// ===========================================================================
// 5-run determinism
// ===========================================================================

#[test]
fn enrichment_five_run_determinism_evaluate() {
    let hashes: Vec<_> = (0..5)
        .map(|_| {
            let families = all_families_covered();
            let result = evaluate(&families, &GateConfig::default());
            result.receipt_hash
        })
        .collect();
    for h in &hashes {
        assert_eq!(*h, hashes[0]);
    }
}

#[test]
fn enrichment_five_run_determinism_evidence() {
    let hashes: Vec<_> = (0..5)
        .map(|_| {
            let families = all_families_covered();
            let profile = compute_coverage(&families);
            let verdict = evaluate_saturation(&profile, &GateConfig::default());
            let ev = build_evidence(&profile, verdict, epoch());
            ev.receipt_hash
        })
        .collect();
    for h in &hashes {
        assert_eq!(*h, hashes[0]);
    }
}

#[test]
fn enrichment_five_run_determinism_receipt() {
    let hashes: Vec<_> = (0..5)
        .map(|_| {
            let families = all_families_covered();
            let result = evaluate(&families, &GateConfig::default());
            let receipt = DecisionReceipt::from_result(&result, epoch());
            receipt.receipt_hash
        })
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
    assert_eq!(
        SCHEMA_VERSION,
        "franken-engine.benchmark-coverage-saturation-gate.v1"
    );
    assert_eq!(COMPONENT, "benchmark_coverage_saturation_gate");
    assert_eq!(BEAD_ID, "bd-1lsy.8.5.5");
    assert_eq!(POLICY_ID, "RGC-705E");
    assert_eq!(TOTAL_WORKLOAD_FAMILIES, 9);
}

// ===========================================================================
// Cross-cutting
// ===========================================================================

#[test]
fn enrichment_cross_cutting_permissive_less_strict() {
    let families = vec![family_cov(WorkloadFamily::BranchHeavy, 1, 10_000)];
    let strict_result = evaluate(&families, &GateConfig::strict());
    let permissive_result = evaluate(&families, &GateConfig::permissive());
    // Permissive should be at least as lenient as strict
    if strict_result.decision.allows_proceed() {
        assert!(permissive_result.decision.allows_proceed());
    }
}

#[test]
fn enrichment_cross_cutting_empty_families_insufficient() {
    let result = evaluate(&[], &GateConfig::default());
    assert_eq!(result.decision, GateDecision::InsufficientEvidence);
}

#[test]
fn enrichment_cross_cutting_all_families_default_passes() {
    let families = all_families_covered();
    let result = evaluate(&families, &GateConfig::default());
    assert!(result.decision.allows_proceed());
}

#[test]
fn enrichment_cross_cutting_different_configs_different_receipts() {
    let families = all_families_covered();
    let r1 = evaluate(&families, &GateConfig::default());
    let r2 = evaluate(&families, &GateConfig::strict());
    // Receipts may differ if decisions differ
    if r1.decision != r2.decision {
        assert_ne!(r1.receipt_hash, r2.receipt_hash);
    }
}

#[test]
fn enrichment_cross_cutting_evaluate_saturation_empty_is_insufficient() {
    let profile = compute_coverage(&[]);
    let verdict = evaluate_saturation(&profile, &GateConfig::default());
    assert_eq!(verdict, SaturationVerdict::InsufficientData);
}

#[test]
fn enrichment_cross_cutting_evaluate_representativeness_permissive() {
    let families = vec![family_cov(WorkloadFamily::BranchHeavy, 1, 10_000)];
    let profile = compute_coverage(&families);
    let level = evaluate_representativeness(&profile, &GateConfig::permissive());
    assert!(level.is_acceptable());
}
