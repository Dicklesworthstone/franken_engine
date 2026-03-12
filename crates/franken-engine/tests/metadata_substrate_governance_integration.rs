// Integration tests for metadata_substrate_governance module.
//
// Covers: constants, type ordering, constructor verification, lifecycle flows,
// verdict determination, content hash determinism, and E2E scenarios.

use frankenengine_engine::metadata_substrate_governance::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_contains_module_name() {
    assert!(SCHEMA_VERSION.contains("metadata-substrate-governance"));
}

#[test]
fn test_schema_version_ends_with_v1() {
    assert!(SCHEMA_VERSION.ends_with(".v1"));
}

#[test]
fn test_component_value() {
    assert_eq!(COMPONENT, "metadata_substrate_governance");
}

#[test]
fn test_bead_id_format() {
    assert!(BEAD_ID.starts_with("bd-"));
    assert_eq!(BEAD_ID, "bd-1lsy.7.26.3");
}

#[test]
fn test_policy_id_format() {
    assert!(POLICY_ID.starts_with("RGC-"));
    assert_eq!(POLICY_ID, "RGC-626C");
}

#[test]
fn test_fixed_one_value() {
    assert_eq!(FIXED_ONE, 1_000_000);
}

#[test]
fn test_default_constants_positive() {
    assert!(DEFAULT_MAX_CACHE_MISS_RATE > 0);
    assert!(DEFAULT_MAX_NUMA_REMOTE_RATIO > 0);
    assert!(DEFAULT_MIN_PORTABILITY_SCORE > 0);
    assert!(DEFAULT_MIN_SAMPLES > 0);
    assert!(DEFAULT_MIN_OBSERVABILITY_COVERAGE > 0);
}

// ---------------------------------------------------------------------------
// LocalityDimension ordering and display
// ---------------------------------------------------------------------------

#[test]
fn test_locality_dimension_all_returns_eight() {
    assert_eq!(LocalityDimension::all().len(), 8);
}

#[test]
fn test_locality_dimension_ordering_first_last() {
    assert!(LocalityDimension::L1Data < LocalityDimension::PrefetchEfficiency);
}

#[test]
fn test_locality_dimension_ordering_adjacent() {
    let all = LocalityDimension::all();
    for i in 0..all.len() - 1 {
        assert!(all[i] < all[i + 1], "{:?} should be < {:?}", all[i], all[i + 1]);
    }
}

#[test]
fn test_locality_dimension_display_l1_data() {
    assert_eq!(LocalityDimension::L1Data.to_string(), "l1_data");
}

#[test]
fn test_locality_dimension_display_l2_unified() {
    assert_eq!(LocalityDimension::L2Unified.to_string(), "l2_unified");
}

#[test]
fn test_locality_dimension_display_tlb() {
    assert_eq!(LocalityDimension::Tlb.to_string(), "tlb");
}

#[test]
fn test_locality_dimension_display_prefetch_efficiency() {
    assert_eq!(LocalityDimension::PrefetchEfficiency.to_string(), "prefetch_efficiency");
}

#[test]
fn test_locality_dimension_all_unique() {
    let all = LocalityDimension::all();
    for i in 0..all.len() {
        for j in (i + 1)..all.len() {
            assert_ne!(all[i], all[j]);
        }
    }
}

// ---------------------------------------------------------------------------
// PortabilityTarget ordering and display
// ---------------------------------------------------------------------------

#[test]
fn test_portability_target_all_returns_seven() {
    assert_eq!(PortabilityTarget::all().len(), 7);
}

#[test]
fn test_portability_target_ordering_first_last() {
    assert!(PortabilityTarget::X64Linux < PortabilityTarget::Wasm);
}

#[test]
fn test_portability_target_display_arm64_macos() {
    assert_eq!(PortabilityTarget::Arm64Macos.to_string(), "arm64_macos");
}

#[test]
fn test_portability_target_display_wasm() {
    assert_eq!(PortabilityTarget::Wasm.to_string(), "wasm");
}

#[test]
fn test_portability_target_display_x64_linux() {
    assert_eq!(PortabilityTarget::X64Linux.to_string(), "x64_linux");
}

// ---------------------------------------------------------------------------
// CacheMissEntry construction
// ---------------------------------------------------------------------------

#[test]
fn test_cache_miss_within_budget() {
    let c = CacheMissEntry::new(
        LocalityDimension::L1Data, "lookup".into(),
        10000, 200, 50,
        DEFAULT_MAX_CACHE_MISS_RATE,
    );
    assert!(c.within_budget);
    assert_eq!(c.miss_rate_millionths, 20_000);
}

#[test]
fn test_cache_miss_exceeds_budget() {
    let c = CacheMissEntry::new(
        LocalityDimension::L1Data, "lookup".into(),
        10000, 1000, 50,
        DEFAULT_MAX_CACHE_MISS_RATE,
    );
    assert!(!c.within_budget);
}

#[test]
fn test_cache_miss_zero_accesses() {
    let c = CacheMissEntry::new(
        LocalityDimension::L1Data, "lookup".into(),
        0, 0, 50,
        DEFAULT_MAX_CACHE_MISS_RATE,
    );
    assert_eq!(c.miss_rate_millionths, 0);
    assert!(c.within_budget);
}

#[test]
fn test_cache_miss_hash_determinism() {
    let a = CacheMissEntry::new(
        LocalityDimension::L2Unified, "op1".into(),
        5000, 100, 30,
        DEFAULT_MAX_CACHE_MISS_RATE,
    );
    let b = CacheMissEntry::new(
        LocalityDimension::L2Unified, "op1".into(),
        5000, 100, 30,
        DEFAULT_MAX_CACHE_MISS_RATE,
    );
    assert_eq!(a.entry_hash, b.entry_hash);
}

#[test]
fn test_cache_miss_hash_differs_on_dimension() {
    let a = CacheMissEntry::new(
        LocalityDimension::L1Data, "op1".into(),
        5000, 100, 30,
        DEFAULT_MAX_CACHE_MISS_RATE,
    );
    let b = CacheMissEntry::new(
        LocalityDimension::L3LastLevel, "op1".into(),
        5000, 100, 30,
        DEFAULT_MAX_CACHE_MISS_RATE,
    );
    assert_ne!(a.entry_hash, b.entry_hash);
}

// ---------------------------------------------------------------------------
// NumaEntry construction
// ---------------------------------------------------------------------------

#[test]
fn test_numa_within_budget() {
    let n = NumaEntry::new("op1".into(), 10000, 500, 2, DEFAULT_MAX_NUMA_REMOTE_RATIO);
    assert!(n.within_budget);
    assert_eq!(n.remote_ratio_millionths, 50_000);
}

#[test]
fn test_numa_exceeds_budget() {
    let n = NumaEntry::new("op1".into(), 10000, 2000, 2, DEFAULT_MAX_NUMA_REMOTE_RATIO);
    assert!(!n.within_budget);
}

#[test]
fn test_numa_zero_accesses() {
    let n = NumaEntry::new("op1".into(), 0, 0, 2, DEFAULT_MAX_NUMA_REMOTE_RATIO);
    assert_eq!(n.remote_ratio_millionths, 0);
    assert!(n.within_budget);
}

#[test]
fn test_numa_hash_determinism() {
    let a = NumaEntry::new("op1".into(), 8000, 400, 4, DEFAULT_MAX_NUMA_REMOTE_RATIO);
    let b = NumaEntry::new("op1".into(), 8000, 400, 4, DEFAULT_MAX_NUMA_REMOTE_RATIO);
    assert_eq!(a.entry_hash, b.entry_hash);
}

#[test]
fn test_numa_node_count_stored() {
    let n = NumaEntry::new("op1".into(), 10000, 500, 8, DEFAULT_MAX_NUMA_REMOTE_RATIO);
    assert_eq!(n.node_count, 8);
}

// ---------------------------------------------------------------------------
// PortabilityEntry construction
// ---------------------------------------------------------------------------

#[test]
fn test_portability_functional_entry() {
    let p = PortabilityEntry::new("op1".into(), PortabilityTarget::X64Linux, true, FIXED_ONE);
    assert!(p.functional);
    assert_eq!(p.perf_ratio_millionths, FIXED_ONE);
}

#[test]
fn test_portability_nonfunctional_entry() {
    let p = PortabilityEntry::new("op1".into(), PortabilityTarget::Wasm, false, 0);
    assert!(!p.functional);
}

#[test]
fn test_portability_entry_hash_determinism() {
    let a = PortabilityEntry::new("op1".into(), PortabilityTarget::Arm64Linux, true, 900_000);
    let b = PortabilityEntry::new("op1".into(), PortabilityTarget::Arm64Linux, true, 900_000);
    assert_eq!(a.entry_hash, b.entry_hash);
}

#[test]
fn test_portability_entry_hash_differs_on_target() {
    let a = PortabilityEntry::new("op1".into(), PortabilityTarget::X64Linux, true, FIXED_ONE);
    let b = PortabilityEntry::new("op1".into(), PortabilityTarget::Arm64Linux, true, FIXED_ONE);
    assert_ne!(a.entry_hash, b.entry_hash);
}

// ---------------------------------------------------------------------------
// GovernanceConfig
// ---------------------------------------------------------------------------

#[test]
fn test_config_strict_requires_all_targets() {
    let c = GovernanceConfig::strict();
    assert_eq!(c.required_targets.len(), 7);
    for t in PortabilityTarget::all() {
        assert!(c.required_targets.contains(t));
    }
}

#[test]
fn test_config_relaxed_no_required_targets() {
    let c = GovernanceConfig::relaxed();
    assert!(c.required_targets.is_empty());
}

#[test]
fn test_config_default_is_relaxed() {
    let d = GovernanceConfig::default();
    let r = GovernanceConfig::relaxed();
    assert_eq!(d, r);
}

#[test]
fn test_config_strict_tighter_than_relaxed() {
    let s = GovernanceConfig::strict();
    let r = GovernanceConfig::relaxed();
    assert!(s.max_cache_miss_rate <= r.max_cache_miss_rate);
    assert!(s.max_numa_remote_ratio <= r.max_numa_remote_ratio);
    assert!(s.min_portability_score >= r.min_portability_score);
    assert!(s.min_samples >= r.min_samples);
}

// ---------------------------------------------------------------------------
// GovernanceVerdict
// ---------------------------------------------------------------------------

#[test]
fn test_verdict_approved_does_not_block() {
    assert!(!GovernanceVerdict::Approved.blocks_publication());
}

#[test]
fn test_verdict_all_non_approved_block() {
    let blocking = [
        GovernanceVerdict::CacheMissExceeded,
        GovernanceVerdict::NumaRemoteExceeded,
        GovernanceVerdict::PortabilityInsufficient,
        GovernanceVerdict::TargetsMissing,
        GovernanceVerdict::MultipleViolations,
    ];
    for v in &blocking {
        assert!(v.blocks_publication(), "{:?} should block", v);
    }
}

#[test]
fn test_verdict_display_approved() {
    assert_eq!(GovernanceVerdict::Approved.to_string(), "approved");
}

#[test]
fn test_verdict_display_cache_miss_exceeded() {
    assert_eq!(GovernanceVerdict::CacheMissExceeded.to_string(), "cache_miss_exceeded");
}

#[test]
fn test_verdict_display_targets_missing() {
    assert_eq!(GovernanceVerdict::TargetsMissing.to_string(), "targets_missing");
}

#[test]
fn test_verdict_ordering() {
    assert!(GovernanceVerdict::Approved < GovernanceVerdict::MultipleViolations);
}

// ---------------------------------------------------------------------------
// GovernanceEvaluator lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_evaluator_empty_relaxed_approved() {
    let eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    assert!(receipt.violations.is_empty());
}

#[test]
fn test_evaluator_cache_miss_pass() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_cache_miss(LocalityDimension::L1Data, "op1".into(), 10000, 200, 50);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
}

#[test]
fn test_evaluator_cache_miss_fail() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_cache_miss(LocalityDimension::L1Data, "op1".into(), 10000, 1000, 50);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::CacheMissExceeded);
}

#[test]
fn test_evaluator_numa_pass() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_numa("op1".into(), 10000, 500, 2);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
}

#[test]
fn test_evaluator_numa_fail() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_numa("op1".into(), 10000, 2000, 2);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::NumaRemoteExceeded);
}

#[test]
fn test_evaluator_portability_fail() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_portability("op1".into(), PortabilityTarget::X64Linux, true, FIXED_ONE);
    eval.add_portability("op1".into(), PortabilityTarget::Arm64Linux, false, 0);
    eval.add_portability("op1".into(), PortabilityTarget::X64Macos, false, 0);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::PortabilityInsufficient);
}

#[test]
fn test_evaluator_targets_missing() {
    let mut config = GovernanceConfig::relaxed();
    config.required_targets.insert(PortabilityTarget::Wasm);
    let eval = GovernanceEvaluator::new(config);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::TargetsMissing);
    assert!(receipt.targets_missing.contains(&PortabilityTarget::Wasm));
}

#[test]
fn test_evaluator_multiple_violations_cache_and_numa() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_cache_miss(LocalityDimension::L1Data, "op1".into(), 10000, 1000, 50);
    eval.add_numa("op1".into(), 10000, 2000, 2);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::MultipleViolations);
}

#[test]
fn test_evaluator_epoch_recorded() {
    let eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    let receipt = eval.evaluate(SecurityEpoch::from_raw(99));
    assert_eq!(receipt.epoch, SecurityEpoch::from_raw(99));
}

#[test]
fn test_evaluator_portability_score_all_functional() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_portability("op1".into(), PortabilityTarget::X64Linux, true, FIXED_ONE);
    eval.add_portability("op1".into(), PortabilityTarget::Arm64Linux, true, 900_000);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.portability_score_millionths, FIXED_ONE);
}

#[test]
fn test_evaluator_portability_score_half_functional() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_portability("op1".into(), PortabilityTarget::X64Linux, true, FIXED_ONE);
    eval.add_portability("op1".into(), PortabilityTarget::Arm64Linux, false, 0);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.portability_score_millionths, 500_000);
}

#[test]
fn test_evaluator_targets_covered_tracking() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_portability("op1".into(), PortabilityTarget::X64Linux, true, FIXED_ONE);
    eval.add_portability("op1".into(), PortabilityTarget::Arm64Macos, true, 950_000);
    let receipt = eval.evaluate(epoch());
    assert!(receipt.targets_covered.contains(&PortabilityTarget::X64Linux));
    assert!(receipt.targets_covered.contains(&PortabilityTarget::Arm64Macos));
    assert_eq!(receipt.targets_covered.len(), 2);
}

// ---------------------------------------------------------------------------
// Content hash determinism
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_hash_deterministic_two_evaluations() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_cache_miss(LocalityDimension::L1Data, "op1".into(), 10000, 200, 50);
    let r1 = eval.evaluate(epoch());
    let r2 = eval.evaluate(epoch());
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn test_receipt_hash_changes_when_data_added() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    let r1 = eval.evaluate(epoch());
    eval.add_cache_miss(LocalityDimension::L1Data, "op1".into(), 10000, 200, 50);
    let r2 = eval.evaluate(epoch());
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn test_receipt_hash_changes_with_epoch() {
    let eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    let r1 = eval.evaluate(SecurityEpoch::from_raw(1));
    let r2 = eval.evaluate(SecurityEpoch::from_raw(2));
    assert_ne!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// E2E scenarios
// ---------------------------------------------------------------------------

#[test]
fn test_e2e_full_pass_relaxed() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_cache_miss(LocalityDimension::L1Data, "op1".into(), 10000, 200, 50);
    eval.add_cache_miss(LocalityDimension::L2Unified, "op1".into(), 10000, 300, 50);
    eval.add_numa("op1".into(), 10000, 500, 2);
    eval.add_portability("op1".into(), PortabilityTarget::X64Linux, true, FIXED_ONE);
    eval.add_portability("op1".into(), PortabilityTarget::Arm64Linux, true, 950_000);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    assert!(receipt.violations.is_empty());
}

#[test]
fn test_e2e_strict_empty_fails_targets() {
    let eval = GovernanceEvaluator::new(GovernanceConfig::strict());
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::TargetsMissing);
    assert_eq!(receipt.targets_missing.len(), 7);
}

#[test]
fn test_e2e_three_violation_categories() {
    let mut config = GovernanceConfig::relaxed();
    config.required_targets.insert(PortabilityTarget::Wasm);
    let mut eval = GovernanceEvaluator::new(config);
    eval.add_cache_miss(LocalityDimension::L1Data, "op1".into(), 10000, 1000, 50);
    eval.add_numa("op1".into(), 10000, 2000, 2);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::MultipleViolations);
    assert!(receipt.violations.len() >= 3);
}

#[test]
fn test_e2e_portability_all_targets_functional() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    for target in PortabilityTarget::all() {
        eval.add_portability("op1".into(), *target, true, FIXED_ONE);
    }
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    assert_eq!(receipt.portability_score_millionths, FIXED_ONE);
    assert_eq!(receipt.targets_covered.len(), 7);
}

#[test]
fn test_e2e_cache_miss_multiple_dimensions_pass() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    for dim in LocalityDimension::all() {
        eval.add_cache_miss(*dim, "op1".into(), 10000, 200, 50);
    }
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    assert_eq!(receipt.cache_miss_entries.len(), 8);
}
