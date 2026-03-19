//! Enrichment integration tests for `metadata_substrate_governance`.
//!
//! Covers: LocalityDimension serde/Display/ordering, PortabilityTarget
//! serde/Display/ordering, CacheMissEntry boundary/hash/serde, NumaEntry
//! boundary/hash/serde, PortabilityEntry hash/serde, GovernanceConfig
//! strict/relaxed/serde, GovernanceVerdict serde/Display/blocks_publication,
//! ViolationDetail content, GovernanceReceipt hash determinism/serde,
//! GovernanceEvaluator evaluation/multi-violation/serde, portability score
//! edge cases, fixed-point millionths, and full E2E scenarios.

#![allow(clippy::too_many_arguments)]

use std::collections::BTreeSet;

use frankenengine_engine::metadata_substrate_governance::{
    BEAD_ID, COMPONENT, CacheMissEntry, DEFAULT_MAX_CACHE_MISS_RATE, DEFAULT_MAX_NUMA_REMOTE_RATIO,
    DEFAULT_MIN_OBSERVABILITY_COVERAGE, DEFAULT_MIN_PORTABILITY_SCORE, DEFAULT_MIN_SAMPLES,
    FIXED_ONE, GovernanceConfig, GovernanceEvaluator, GovernanceReceipt, GovernanceVerdict,
    LocalityDimension, NumaEntry, POLICY_ID, PortabilityEntry, PortabilityTarget, SCHEMA_VERSION,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// Helpers
// ===========================================================================

fn ep(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn relaxed_eval() -> GovernanceEvaluator {
    GovernanceEvaluator::new(GovernanceConfig::relaxed())
}

fn strict_eval() -> GovernanceEvaluator {
    GovernanceEvaluator::new(GovernanceConfig::strict())
}

// ===========================================================================
// Constants tests
// ===========================================================================

#[test]
fn integ_constants() {
    assert!(SCHEMA_VERSION.contains("metadata-substrate-governance"));
    assert_eq!(COMPONENT, "metadata_substrate_governance");
    assert_eq!(BEAD_ID, "bd-1lsy.7.26.3");
    assert_eq!(POLICY_ID, "RGC-626C");
    assert_eq!(FIXED_ONE, 1_000_000);
}

#[test]
fn integ_default_thresholds() {
    assert!(DEFAULT_MAX_CACHE_MISS_RATE <= 100_000);
    assert!(DEFAULT_MAX_NUMA_REMOTE_RATIO <= 200_000);
    assert!(DEFAULT_MIN_PORTABILITY_SCORE >= 800_000);
    assert!(DEFAULT_MIN_OBSERVABILITY_COVERAGE >= 800_000);
    assert!(DEFAULT_MIN_SAMPLES >= 1);
}

// ===========================================================================
// LocalityDimension tests
// ===========================================================================

#[test]
fn integ_locality_all_count() {
    assert_eq!(LocalityDimension::all().len(), 8);
}

#[test]
fn integ_locality_display_all_unique() {
    let mut displays = BTreeSet::new();
    for dim in LocalityDimension::all() {
        displays.insert(dim.to_string());
    }
    assert_eq!(displays.len(), 8);
}

#[test]
fn integ_locality_serde_all() {
    for dim in LocalityDimension::all() {
        let json = serde_json::to_string(dim).unwrap();
        let back: LocalityDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(*dim, back);
    }
}

#[test]
fn integ_locality_ordering() {
    assert!(LocalityDimension::L1Data < LocalityDimension::PrefetchEfficiency);
}

#[test]
fn integ_locality_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for dim in LocalityDimension::all() {
        assert!(set.insert(*dim));
    }
    assert_eq!(set.len(), 8);
}

#[test]
fn integ_locality_display_exact() {
    let expected = [
        (LocalityDimension::L1Data, "l1_data"),
        (LocalityDimension::L1Instruction, "l1_instruction"),
        (LocalityDimension::L2Unified, "l2_unified"),
        (LocalityDimension::L3LastLevel, "l3_last_level"),
        (LocalityDimension::Tlb, "tlb"),
        (LocalityDimension::PageTableWalk, "page_table_walk"),
        (LocalityDimension::MemoryBus, "memory_bus"),
        (LocalityDimension::PrefetchEfficiency, "prefetch_efficiency"),
    ];
    for (dim, label) in &expected {
        assert_eq!(dim.to_string(), *label);
    }
}

// ===========================================================================
// PortabilityTarget tests
// ===========================================================================

#[test]
fn integ_target_all_count() {
    assert_eq!(PortabilityTarget::all().len(), 7);
}

#[test]
fn integ_target_display_all_unique() {
    let mut displays = BTreeSet::new();
    for t in PortabilityTarget::all() {
        displays.insert(t.to_string());
    }
    assert_eq!(displays.len(), 7);
}

#[test]
fn integ_target_serde_all() {
    for t in PortabilityTarget::all() {
        let json = serde_json::to_string(t).unwrap();
        let back: PortabilityTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, back);
    }
}

#[test]
fn integ_target_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for t in PortabilityTarget::all() {
        assert!(set.insert(*t));
    }
    assert_eq!(set.len(), 7);
}

#[test]
fn integ_target_display_exact() {
    let expected = [
        (PortabilityTarget::X64Linux, "x64_linux"),
        (PortabilityTarget::X64Macos, "x64_macos"),
        (PortabilityTarget::Arm64Linux, "arm64_linux"),
        (PortabilityTarget::Arm64Macos, "arm64_macos"),
        (PortabilityTarget::X64Windows, "x64_windows"),
        (PortabilityTarget::Arm64Windows, "arm64_windows"),
        (PortabilityTarget::Wasm, "wasm"),
    ];
    for (target, label) in &expected {
        assert_eq!(target.to_string(), *label);
    }
}

// ===========================================================================
// CacheMissEntry tests
// ===========================================================================

#[test]
fn integ_cache_miss_within_budget() {
    let c = CacheMissEntry::new(
        LocalityDimension::L1Data,
        "op1".into(),
        10000,
        200,
        50,
        DEFAULT_MAX_CACHE_MISS_RATE,
    );
    assert!(c.within_budget);
    assert_eq!(c.miss_rate_millionths, 20_000);
}

#[test]
fn integ_cache_miss_exceeds_budget() {
    let c = CacheMissEntry::new(
        LocalityDimension::L1Data,
        "op1".into(),
        10000,
        1000,
        50,
        DEFAULT_MAX_CACHE_MISS_RATE,
    );
    assert!(!c.within_budget);
    assert_eq!(c.miss_rate_millionths, 100_000);
}

#[test]
fn integ_cache_miss_exactly_at_threshold() {
    let c = CacheMissEntry::new(
        LocalityDimension::L1Data,
        "boundary_op".into(),
        10000,
        500,
        50,
        DEFAULT_MAX_CACHE_MISS_RATE,
    );
    assert_eq!(c.miss_rate_millionths, 50_000);
    assert!(c.within_budget);
}

#[test]
fn integ_cache_miss_one_over_threshold() {
    let c = CacheMissEntry::new(
        LocalityDimension::L1Data,
        "boundary_op".into(),
        10000,
        501,
        50,
        DEFAULT_MAX_CACHE_MISS_RATE,
    );
    assert_eq!(c.miss_rate_millionths, 50_100);
    assert!(!c.within_budget);
}

#[test]
fn integ_cache_miss_zero_accesses() {
    let c = CacheMissEntry::new(
        LocalityDimension::L1Data,
        "op".into(),
        0,
        0,
        50,
        DEFAULT_MAX_CACHE_MISS_RATE,
    );
    assert_eq!(c.miss_rate_millionths, 0);
    assert!(c.within_budget);
}

#[test]
fn integ_cache_miss_hash_deterministic() {
    let a = CacheMissEntry::new(
        LocalityDimension::L2Unified,
        "op1".into(),
        5000,
        100,
        30,
        DEFAULT_MAX_CACHE_MISS_RATE,
    );
    let b = CacheMissEntry::new(
        LocalityDimension::L2Unified,
        "op1".into(),
        5000,
        100,
        30,
        DEFAULT_MAX_CACHE_MISS_RATE,
    );
    assert_eq!(a.entry_hash, b.entry_hash);
}

#[test]
fn integ_cache_miss_hash_differs_on_dimension() {
    let a = CacheMissEntry::new(
        LocalityDimension::L1Data,
        "op1".into(),
        5000,
        100,
        30,
        DEFAULT_MAX_CACHE_MISS_RATE,
    );
    let b = CacheMissEntry::new(
        LocalityDimension::L3LastLevel,
        "op1".into(),
        5000,
        100,
        30,
        DEFAULT_MAX_CACHE_MISS_RATE,
    );
    assert_ne!(a.entry_hash, b.entry_hash);
}

#[test]
fn integ_cache_miss_hash_differs_on_op_id() {
    let a = CacheMissEntry::new(
        LocalityDimension::L1Data,
        "op_alpha".into(),
        5000,
        100,
        30,
        DEFAULT_MAX_CACHE_MISS_RATE,
    );
    let b = CacheMissEntry::new(
        LocalityDimension::L1Data,
        "op_beta".into(),
        5000,
        100,
        30,
        DEFAULT_MAX_CACHE_MISS_RATE,
    );
    assert_ne!(a.entry_hash, b.entry_hash);
}

#[test]
fn integ_cache_miss_serde_roundtrip() {
    let entry = CacheMissEntry::new(
        LocalityDimension::Tlb,
        "tlb_walk".into(),
        50000,
        1500,
        100,
        DEFAULT_MAX_CACHE_MISS_RATE,
    );
    let json = serde_json::to_string(&entry).unwrap();
    let back: CacheMissEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn integ_cache_miss_saturating_large_values() {
    let c = CacheMissEntry::new(
        LocalityDimension::MemoryBus,
        "huge".into(),
        u64::MAX,
        u64::MAX,
        100,
        DEFAULT_MAX_CACHE_MISS_RATE,
    );
    assert!(c.miss_rate_millionths > 0);
}

// ===========================================================================
// NumaEntry tests
// ===========================================================================

#[test]
fn integ_numa_within_budget() {
    let n = NumaEntry::new("op1".into(), 10000, 500, 2, DEFAULT_MAX_NUMA_REMOTE_RATIO);
    assert!(n.within_budget);
    assert_eq!(n.remote_ratio_millionths, 50_000);
}

#[test]
fn integ_numa_exceeds_budget() {
    let n = NumaEntry::new("op1".into(), 10000, 2000, 2, DEFAULT_MAX_NUMA_REMOTE_RATIO);
    assert!(!n.within_budget);
}

#[test]
fn integ_numa_exactly_at_threshold() {
    let n = NumaEntry::new(
        "boundary".into(),
        10000,
        1000,
        2,
        DEFAULT_MAX_NUMA_REMOTE_RATIO,
    );
    assert_eq!(n.remote_ratio_millionths, 100_000);
    assert!(n.within_budget);
}

#[test]
fn integ_numa_one_over_threshold() {
    let n = NumaEntry::new(
        "boundary".into(),
        10000,
        1001,
        2,
        DEFAULT_MAX_NUMA_REMOTE_RATIO,
    );
    assert!(!n.within_budget);
}

#[test]
fn integ_numa_zero_accesses() {
    let n = NumaEntry::new("op1".into(), 0, 0, 2, DEFAULT_MAX_NUMA_REMOTE_RATIO);
    assert_eq!(n.remote_ratio_millionths, 0);
}

#[test]
fn integ_numa_hash_deterministic() {
    let a = NumaEntry::new("scan".into(), 20000, 1000, 2, DEFAULT_MAX_NUMA_REMOTE_RATIO);
    let b = NumaEntry::new("scan".into(), 20000, 1000, 2, DEFAULT_MAX_NUMA_REMOTE_RATIO);
    assert_eq!(a.entry_hash, b.entry_hash);
}

#[test]
fn integ_numa_hash_differs_on_node_count() {
    let a = NumaEntry::new("scan".into(), 20000, 1000, 2, DEFAULT_MAX_NUMA_REMOTE_RATIO);
    let b = NumaEntry::new("scan".into(), 20000, 1000, 4, DEFAULT_MAX_NUMA_REMOTE_RATIO);
    assert_ne!(a.entry_hash, b.entry_hash);
}

#[test]
fn integ_numa_serde_roundtrip() {
    let entry = NumaEntry::new(
        "remote_scan".into(),
        80000,
        4000,
        4,
        DEFAULT_MAX_NUMA_REMOTE_RATIO,
    );
    let json = serde_json::to_string(&entry).unwrap();
    let back: NumaEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ===========================================================================
// PortabilityEntry tests
// ===========================================================================

#[test]
fn integ_portability_functional() {
    let p = PortabilityEntry::new("op1".into(), PortabilityTarget::X64Linux, true, FIXED_ONE);
    assert!(p.functional);
}

#[test]
fn integ_portability_nonfunctional() {
    let p = PortabilityEntry::new("op1".into(), PortabilityTarget::Wasm, false, 0);
    assert!(!p.functional);
}

#[test]
fn integ_portability_hash_deterministic() {
    let a = PortabilityEntry::new("op".into(), PortabilityTarget::Wasm, true, 800_000);
    let b = PortabilityEntry::new("op".into(), PortabilityTarget::Wasm, true, 800_000);
    assert_eq!(a.entry_hash, b.entry_hash);
}

#[test]
fn integ_portability_hash_differs_on_functional() {
    let a = PortabilityEntry::new("op".into(), PortabilityTarget::Wasm, true, 800_000);
    let b = PortabilityEntry::new("op".into(), PortabilityTarget::Wasm, false, 800_000);
    assert_ne!(a.entry_hash, b.entry_hash);
}

#[test]
fn integ_portability_hash_differs_on_target() {
    let a = PortabilityEntry::new("op".into(), PortabilityTarget::X64Linux, true, FIXED_ONE);
    let b = PortabilityEntry::new("op".into(), PortabilityTarget::Arm64Linux, true, FIXED_ONE);
    assert_ne!(a.entry_hash, b.entry_hash);
}

#[test]
fn integ_portability_serde_roundtrip() {
    let entry = PortabilityEntry::new(
        "cross_compile".into(),
        PortabilityTarget::Arm64Windows,
        true,
        850_000,
    );
    let json = serde_json::to_string(&entry).unwrap();
    let back: PortabilityEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ===========================================================================
// GovernanceConfig tests
// ===========================================================================

#[test]
fn integ_config_strict_values() {
    let c = GovernanceConfig::strict();
    assert_eq!(c.max_cache_miss_rate, 20_000);
    assert_eq!(c.max_numa_remote_ratio, 50_000);
    assert_eq!(c.min_portability_score, 950_000);
    assert_eq!(c.min_samples, 100);
    assert_eq!(c.min_observability_coverage, 950_000);
    assert_eq!(c.required_targets.len(), 7);
}

#[test]
fn integ_config_relaxed_values() {
    let c = GovernanceConfig::relaxed();
    assert_eq!(c.max_cache_miss_rate, DEFAULT_MAX_CACHE_MISS_RATE);
    assert_eq!(c.max_numa_remote_ratio, DEFAULT_MAX_NUMA_REMOTE_RATIO);
    assert_eq!(c.min_portability_score, DEFAULT_MIN_PORTABILITY_SCORE);
    assert_eq!(c.min_samples, DEFAULT_MIN_SAMPLES);
    assert!(c.required_targets.is_empty());
}

#[test]
fn integ_config_default_is_relaxed() {
    assert_eq!(GovernanceConfig::default(), GovernanceConfig::relaxed());
}

#[test]
fn integ_config_serde_roundtrip() {
    let config = GovernanceConfig::strict();
    let json = serde_json::to_string(&config).unwrap();
    let back: GovernanceConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ===========================================================================
// GovernanceVerdict tests
// ===========================================================================

#[test]
fn integ_verdict_display_all_unique() {
    let verdicts = [
        GovernanceVerdict::Approved,
        GovernanceVerdict::CacheMissExceeded,
        GovernanceVerdict::NumaRemoteExceeded,
        GovernanceVerdict::PortabilityInsufficient,
        GovernanceVerdict::TargetsMissing,
        GovernanceVerdict::MultipleViolations,
    ];
    let mut displays = BTreeSet::new();
    for v in &verdicts {
        displays.insert(v.to_string());
    }
    assert_eq!(displays.len(), 6);
}

#[test]
fn integ_verdict_serde_all() {
    let verdicts = [
        GovernanceVerdict::Approved,
        GovernanceVerdict::CacheMissExceeded,
        GovernanceVerdict::NumaRemoteExceeded,
        GovernanceVerdict::PortabilityInsufficient,
        GovernanceVerdict::TargetsMissing,
        GovernanceVerdict::MultipleViolations,
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let back: GovernanceVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn integ_verdict_blocks_publication() {
    assert!(!GovernanceVerdict::Approved.blocks_publication());
    assert!(GovernanceVerdict::CacheMissExceeded.blocks_publication());
    assert!(GovernanceVerdict::NumaRemoteExceeded.blocks_publication());
    assert!(GovernanceVerdict::PortabilityInsufficient.blocks_publication());
    assert!(GovernanceVerdict::TargetsMissing.blocks_publication());
    assert!(GovernanceVerdict::MultipleViolations.blocks_publication());
}

#[test]
fn integ_verdict_ordering() {
    let mut verdicts = vec![
        GovernanceVerdict::MultipleViolations,
        GovernanceVerdict::Approved,
        GovernanceVerdict::CacheMissExceeded,
    ];
    verdicts.sort();
    assert_eq!(verdicts[0], GovernanceVerdict::Approved);
}

// ===========================================================================
// GovernanceEvaluator tests
// ===========================================================================

#[test]
fn integ_evaluator_empty_approved() {
    let eval = relaxed_eval();
    let receipt = eval.evaluate(ep(1));
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
}

#[test]
fn integ_evaluator_cache_miss_pass() {
    let mut eval = relaxed_eval();
    eval.add_cache_miss(LocalityDimension::L1Data, "op1".into(), 10000, 200, 50);
    let receipt = eval.evaluate(ep(1));
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
}

#[test]
fn integ_evaluator_cache_miss_fail() {
    let mut eval = relaxed_eval();
    eval.add_cache_miss(LocalityDimension::L1Data, "op1".into(), 10000, 1000, 50);
    let receipt = eval.evaluate(ep(1));
    assert_eq!(receipt.verdict, GovernanceVerdict::CacheMissExceeded);
}

#[test]
fn integ_evaluator_numa_fail() {
    let mut eval = relaxed_eval();
    eval.add_numa("op1".into(), 10000, 2000, 2);
    let receipt = eval.evaluate(ep(1));
    assert_eq!(receipt.verdict, GovernanceVerdict::NumaRemoteExceeded);
}

#[test]
fn integ_evaluator_portability_fail() {
    let mut eval = relaxed_eval();
    eval.add_portability("op1".into(), PortabilityTarget::X64Linux, true, FIXED_ONE);
    eval.add_portability("op1".into(), PortabilityTarget::Arm64Linux, false, 0);
    eval.add_portability("op1".into(), PortabilityTarget::X64Macos, false, 0);
    let receipt = eval.evaluate(ep(1));
    assert_eq!(receipt.verdict, GovernanceVerdict::PortabilityInsufficient);
}

#[test]
fn integ_evaluator_targets_missing() {
    let mut config = GovernanceConfig::relaxed();
    config.required_targets.insert(PortabilityTarget::Wasm);
    let eval = GovernanceEvaluator::new(config);
    let receipt = eval.evaluate(ep(1));
    assert_eq!(receipt.verdict, GovernanceVerdict::TargetsMissing);
}

#[test]
fn integ_evaluator_multiple_violations() {
    let mut eval = relaxed_eval();
    eval.add_cache_miss(LocalityDimension::L1Data, "op1".into(), 10000, 1000, 50);
    eval.add_numa("op1".into(), 10000, 2000, 2);
    let receipt = eval.evaluate(ep(1));
    assert_eq!(receipt.verdict, GovernanceVerdict::MultipleViolations);
}

#[test]
fn integ_evaluator_multiple_cache_violations_same_category() {
    let mut eval = relaxed_eval();
    eval.add_cache_miss(LocalityDimension::L1Data, "op_a".into(), 1000, 200, 50);
    eval.add_cache_miss(LocalityDimension::L2Unified, "op_b".into(), 1000, 300, 50);
    let receipt = eval.evaluate(ep(1));
    assert_eq!(receipt.verdict, GovernanceVerdict::CacheMissExceeded);
    assert_eq!(receipt.violations.len(), 2);
}

// ===========================================================================
// Portability score tests
// ===========================================================================

#[test]
fn integ_portability_score_all_functional() {
    let mut eval = relaxed_eval();
    eval.add_portability("op".into(), PortabilityTarget::X64Linux, true, FIXED_ONE);
    eval.add_portability("op".into(), PortabilityTarget::Arm64Linux, true, 900_000);
    let receipt = eval.evaluate(ep(1));
    assert_eq!(receipt.portability_score_millionths, FIXED_ONE);
}

#[test]
fn integ_portability_score_half() {
    let mut eval = relaxed_eval();
    eval.add_portability("op".into(), PortabilityTarget::X64Linux, true, FIXED_ONE);
    eval.add_portability("op".into(), PortabilityTarget::Arm64Linux, false, 0);
    let receipt = eval.evaluate(ep(1));
    assert_eq!(receipt.portability_score_millionths, 500_000);
}

#[test]
fn integ_portability_score_one_third() {
    let mut eval = relaxed_eval();
    eval.add_portability("a".into(), PortabilityTarget::X64Linux, true, FIXED_ONE);
    eval.add_portability("b".into(), PortabilityTarget::Arm64Linux, false, 0);
    eval.add_portability("c".into(), PortabilityTarget::Wasm, false, 0);
    let receipt = eval.evaluate(ep(1));
    assert_eq!(receipt.portability_score_millionths, 333_333);
}

#[test]
fn integ_portability_score_empty_returns_fixed_one() {
    let eval = relaxed_eval();
    let receipt = eval.evaluate(ep(1));
    assert_eq!(receipt.portability_score_millionths, FIXED_ONE);
}

#[test]
fn integ_portability_score_all_nonfunctional() {
    let mut eval = relaxed_eval();
    eval.add_portability("op".into(), PortabilityTarget::X64Linux, false, 0);
    eval.add_portability("op".into(), PortabilityTarget::Wasm, false, 0);
    let receipt = eval.evaluate(ep(1));
    assert_eq!(receipt.portability_score_millionths, 0);
    assert_eq!(receipt.verdict, GovernanceVerdict::PortabilityInsufficient);
}

// ===========================================================================
// Covered/missing targets tests
// ===========================================================================

#[test]
fn integ_covered_targets_only_functional() {
    let mut eval = relaxed_eval();
    eval.add_portability("op".into(), PortabilityTarget::X64Linux, true, FIXED_ONE);
    eval.add_portability("op".into(), PortabilityTarget::Arm64Linux, false, 0);
    eval.add_portability("op".into(), PortabilityTarget::Wasm, true, FIXED_ONE);
    let receipt = eval.evaluate(ep(1));
    assert!(
        receipt
            .targets_covered
            .contains(&PortabilityTarget::X64Linux)
    );
    assert!(receipt.targets_covered.contains(&PortabilityTarget::Wasm));
    assert!(
        !receipt
            .targets_covered
            .contains(&PortabilityTarget::Arm64Linux)
    );
}

#[test]
fn integ_targets_missing_partial() {
    let mut config = GovernanceConfig::relaxed();
    config.required_targets.insert(PortabilityTarget::X64Linux);
    config.required_targets.insert(PortabilityTarget::Wasm);
    let mut eval = GovernanceEvaluator::new(config);
    eval.add_portability("op".into(), PortabilityTarget::X64Linux, true, FIXED_ONE);
    let receipt = eval.evaluate(ep(1));
    assert_eq!(receipt.verdict, GovernanceVerdict::TargetsMissing);
    assert!(receipt.targets_missing.contains(&PortabilityTarget::Wasm));
    assert!(
        !receipt
            .targets_missing
            .contains(&PortabilityTarget::X64Linux)
    );
}

#[test]
fn integ_targets_all_satisfied() {
    let mut config = GovernanceConfig::relaxed();
    config.required_targets.insert(PortabilityTarget::X64Linux);
    config.required_targets.insert(PortabilityTarget::Wasm);
    let mut eval = GovernanceEvaluator::new(config);
    eval.add_portability("op".into(), PortabilityTarget::X64Linux, true, FIXED_ONE);
    eval.add_portability("op".into(), PortabilityTarget::Wasm, true, FIXED_ONE);
    let receipt = eval.evaluate(ep(1));
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    assert!(receipt.targets_missing.is_empty());
}

// ===========================================================================
// Receipt hash determinism tests
// ===========================================================================

#[test]
fn integ_receipt_hash_deterministic() {
    let mut eval = relaxed_eval();
    eval.add_cache_miss(LocalityDimension::L1Data, "op1".into(), 10000, 200, 50);
    let r1 = eval.evaluate(ep(1));
    let r2 = eval.evaluate(ep(1));
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn integ_receipt_hash_changes_with_data() {
    let mut eval = relaxed_eval();
    let r1 = eval.evaluate(ep(1));
    eval.add_cache_miss(LocalityDimension::L1Data, "op1".into(), 10000, 200, 50);
    let r2 = eval.evaluate(ep(1));
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn integ_receipt_hash_changes_with_epoch() {
    let eval = relaxed_eval();
    let r1 = eval.evaluate(ep(1));
    let r2 = eval.evaluate(ep(2));
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn integ_receipt_epoch_propagated() {
    let eval = relaxed_eval();
    let receipt = eval.evaluate(ep(999));
    assert_eq!(receipt.epoch.as_u64(), 999);
}

// ===========================================================================
// Receipt serde tests
// ===========================================================================

#[test]
fn integ_receipt_serde_roundtrip() {
    let mut eval = relaxed_eval();
    eval.add_cache_miss(LocalityDimension::L1Data, "op1".into(), 10000, 200, 50);
    eval.add_numa("op1".into(), 10000, 500, 2);
    eval.add_portability("op1".into(), PortabilityTarget::X64Linux, true, FIXED_ONE);
    let receipt = eval.evaluate(ep(1));
    let json = serde_json::to_string(&receipt).unwrap();
    let back: GovernanceReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn integ_receipt_entries_cloned_into_receipt() {
    let mut eval = relaxed_eval();
    eval.add_cache_miss(LocalityDimension::L1Data, "a".into(), 10000, 100, 50);
    eval.add_cache_miss(LocalityDimension::L2Unified, "b".into(), 10000, 100, 50);
    eval.add_numa("c".into(), 10000, 100, 2);
    eval.add_portability("d".into(), PortabilityTarget::Wasm, true, FIXED_ONE);
    let receipt = eval.evaluate(ep(1));
    assert_eq!(receipt.cache_miss_entries.len(), 2);
    assert_eq!(receipt.numa_entries.len(), 1);
    assert_eq!(receipt.portability_entries.len(), 1);
}

// ===========================================================================
// Evaluator serde tests
// ===========================================================================

#[test]
fn integ_evaluator_serde_roundtrip() {
    let mut eval = relaxed_eval();
    eval.add_cache_miss(LocalityDimension::L1Data, "op".into(), 10000, 200, 50);
    eval.add_numa("op".into(), 10000, 500, 2);
    eval.add_portability("op".into(), PortabilityTarget::X64Linux, true, FIXED_ONE);
    let json = serde_json::to_string(&eval).unwrap();
    let back: GovernanceEvaluator = serde_json::from_str(&json).unwrap();
    assert_eq!(eval, back);
}

// ===========================================================================
// Violation detail tests
// ===========================================================================

#[test]
fn integ_violation_detail_cache_miss() {
    let mut eval = relaxed_eval();
    eval.add_cache_miss(LocalityDimension::L1Data, "op1".into(), 10000, 800, 50);
    let receipt = eval.evaluate(ep(1));
    assert_eq!(receipt.violations.len(), 1);
    let v = &receipt.violations[0];
    assert_eq!(v.category, GovernanceVerdict::CacheMissExceeded);
    assert_eq!(v.measured_millionths, 80_000);
    assert_eq!(v.threshold_millionths, DEFAULT_MAX_CACHE_MISS_RATE);
}

#[test]
fn integ_violation_detail_numa_summary() {
    let mut eval = relaxed_eval();
    eval.add_numa("my_special_op".into(), 10000, 5000, 4);
    let receipt = eval.evaluate(ep(1));
    assert!(receipt.violations[0].summary.contains("my_special_op"));
}

// ===========================================================================
// Strict config tests
// ===========================================================================

#[test]
fn integ_strict_requires_all_targets() {
    let eval = strict_eval();
    let receipt = eval.evaluate(ep(1));
    assert_eq!(receipt.verdict, GovernanceVerdict::TargetsMissing);
    assert_eq!(receipt.targets_missing.len(), 7);
}

#[test]
fn integ_strict_tighter_cache_threshold() {
    let mut eval = strict_eval();
    eval.add_cache_miss(LocalityDimension::L1Data, "op".into(), 10000, 300, 100);
    for target in PortabilityTarget::all() {
        eval.add_portability("op".into(), *target, true, FIXED_ONE);
    }
    eval.add_numa("op".into(), 10000, 100, 2);
    let receipt = eval.evaluate(ep(1));
    assert!(
        receipt
            .violations
            .iter()
            .any(|v| v.category == GovernanceVerdict::CacheMissExceeded)
    );
}

#[test]
fn integ_strict_all_pass() {
    let mut eval = strict_eval();
    eval.add_cache_miss(LocalityDimension::L1Data, "op".into(), 100000, 1000, 100);
    eval.add_numa("op".into(), 100000, 1000, 2);
    for target in PortabilityTarget::all() {
        eval.add_portability("op".into(), *target, true, FIXED_ONE);
    }
    let receipt = eval.evaluate(ep(1));
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
}

// ===========================================================================
// E2E full pass test
// ===========================================================================

#[test]
fn integ_e2e_full_pass() {
    let mut eval = relaxed_eval();
    eval.add_cache_miss(LocalityDimension::L1Data, "op1".into(), 10000, 200, 50);
    eval.add_numa("op1".into(), 10000, 500, 2);
    eval.add_portability("op1".into(), PortabilityTarget::X64Linux, true, FIXED_ONE);
    eval.add_portability("op1".into(), PortabilityTarget::Arm64Linux, true, 950_000);
    let receipt = eval.evaluate(ep(42));
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    assert!(receipt.violations.is_empty());
    assert_eq!(receipt.epoch.as_u64(), 42);
}
