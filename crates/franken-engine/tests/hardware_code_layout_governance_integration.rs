//! Integration tests for `hardware_code_layout_governance` (RGC-623C, bd-1lsy.7.23.3).

use std::collections::BTreeSet;

use frankenengine_engine::hardware_code_layout_governance::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn ep() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn hw_set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}

// ============================================================================
// Constants
// ============================================================================

#[test]
fn test_schema_version_contains_module_name() {
    assert!(SCHEMA_VERSION.contains("hardware-code-layout-governance"));
}

#[test]
fn test_schema_version_v1() {
    assert!(SCHEMA_VERSION.contains("v1"));
}

#[test]
fn test_component_name() {
    assert_eq!(COMPONENT, "hardware_code_layout_governance");
}

#[test]
fn test_bead_id() {
    assert_eq!(BEAD_ID, "bd-1lsy.7.23.3");
}

#[test]
fn test_policy_id() {
    assert_eq!(POLICY_ID, "RGC-623C");
}

#[test]
fn test_fixed_one_value() {
    assert_eq!(FIXED_ONE, 1_000_000);
}

#[test]
fn test_default_thresholds() {
    assert_eq!(DEFAULT_MAX_STALL_BUDGET_MILLIONTHS, 200_000);
    assert_eq!(DEFAULT_MIN_IMPROVEMENT_MILLIONTHS, 10_000);
    assert_eq!(DEFAULT_MAX_ALIGNMENT_WASTE_BYTES, 4096);
    assert_eq!(DEFAULT_MIN_HARDWARE_COVERAGE, 500_000);
}

#[test]
fn test_capacity_limits() {
    assert_eq!(MAX_STRATEGIES, 32);
    assert_eq!(MAX_ALIGNMENT_ENTRIES, 4096);
    assert_eq!(MAX_STALL_BUDGETS, 64);
    assert_eq!(MAX_POLICY_ENTRIES, 64);
}

// ============================================================================
// LayoutStrategy
// ============================================================================

#[test]
fn test_layout_strategy_all_count() {
    assert_eq!(LayoutStrategy::ALL.len(), 8);
}

#[test]
fn test_layout_strategy_display_matches_as_str() {
    for s in LayoutStrategy::ALL {
        assert_eq!(format!("{s}"), s.as_str());
    }
}

#[test]
fn test_layout_strategy_ordering() {
    assert!(LayoutStrategy::HotColdSplit < LayoutStrategy::ColdTailCompaction);
}

#[test]
fn test_layout_strategy_introduces_waste() {
    assert!(LayoutStrategy::LoopAlignment.introduces_waste());
    assert!(LayoutStrategy::BranchAlignment.introduces_waste());
    assert!(LayoutStrategy::NopPadding.introduces_waste());
    assert!(!LayoutStrategy::HotColdSplit.introduces_waste());
    assert!(!LayoutStrategy::FunctionReordering.introduces_waste());
    assert!(!LayoutStrategy::CacheFriendly.introduces_waste());
}

#[test]
fn test_layout_strategy_targets_icache() {
    assert!(LayoutStrategy::HotColdSplit.targets_icache());
    assert!(LayoutStrategy::FunctionReordering.targets_icache());
    assert!(LayoutStrategy::CacheFriendly.targets_icache());
    assert!(LayoutStrategy::CallerCalleeColocation.targets_icache());
    assert!(LayoutStrategy::ColdTailCompaction.targets_icache());
    assert!(!LayoutStrategy::LoopAlignment.targets_icache());
    assert!(!LayoutStrategy::BranchAlignment.targets_icache());
    assert!(!LayoutStrategy::NopPadding.targets_icache());
}

#[test]
fn test_layout_strategy_serde_roundtrip() {
    for s in LayoutStrategy::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: LayoutStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ============================================================================
// StallCategory
// ============================================================================

#[test]
fn test_stall_category_all_count() {
    assert_eq!(StallCategory::ALL.len(), 6);
}

#[test]
fn test_stall_category_display_matches_as_str() {
    for c in StallCategory::ALL {
        assert_eq!(format!("{c}"), c.as_str());
    }
}

#[test]
fn test_stall_category_addressable_by_alignment() {
    assert!(StallCategory::DecodeBubble.addressable_by_alignment());
    assert!(StallCategory::AlignmentPenalty.addressable_by_alignment());
    assert!(StallCategory::FetchBubble.addressable_by_alignment());
    assert!(!StallCategory::InstructionCacheMiss.addressable_by_alignment());
    assert!(!StallCategory::BranchMispredict.addressable_by_alignment());
}

#[test]
fn test_stall_category_addressable_by_placement() {
    assert!(StallCategory::InstructionCacheMiss.addressable_by_placement());
    assert!(StallCategory::MicroOpCacheOverflow.addressable_by_placement());
    assert!(!StallCategory::DecodeBubble.addressable_by_placement());
    assert!(!StallCategory::BranchMispredict.addressable_by_placement());
}

#[test]
fn test_stall_category_serde_roundtrip() {
    for c in StallCategory::ALL {
        let json = serde_json::to_string(c).unwrap();
        let back: StallCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

// ============================================================================
// AlignmentEntry
// ============================================================================

#[test]
fn test_alignment_entry_improvement_positive() {
    let e = AlignmentEntry::new("fn_hot", LayoutStrategy::LoopAlignment, 64, 50, 100, 16);
    assert!(e.is_improvement());
    assert!(!e.is_regression());
    assert!(e.improvement_millionths > 0);
}

#[test]
fn test_alignment_entry_regression() {
    let e = AlignmentEntry::new("fn_cold", LayoutStrategy::NopPadding, 64, 150, 100, 32);
    assert!(e.is_regression());
    assert!(!e.is_improvement());
    assert!(e.improvement_millionths < 0);
}

#[test]
fn test_alignment_entry_valid_alignment() {
    let e = AlignmentEntry::new("fn_a", LayoutStrategy::LoopAlignment, 64, 80, 100, 0);
    assert!(e.is_valid_alignment());
}

#[test]
fn test_alignment_entry_invalid_alignment() {
    let e = AlignmentEntry::new("fn_b", LayoutStrategy::LoopAlignment, 0, 80, 100, 0);
    assert!(!e.is_valid_alignment());

    let e2 = AlignmentEntry::new("fn_c", LayoutStrategy::LoopAlignment, 3, 80, 100, 0);
    assert!(!e2.is_valid_alignment());
}

#[test]
fn test_alignment_entry_content_hash_deterministic() {
    let a = AlignmentEntry::new("fn_x", LayoutStrategy::HotColdSplit, 64, 50, 100, 8);
    let b = AlignmentEntry::new("fn_x", LayoutStrategy::HotColdSplit, 64, 50, 100, 8);
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn test_alignment_entry_display() {
    let e = AlignmentEntry::new("fn_show", LayoutStrategy::BranchAlignment, 32, 60, 100, 4);
    let s = format!("{e}");
    assert!(s.contains("fn_show"));
    assert!(s.contains("branch_alignment"));
}

// ============================================================================
// StallBudget
// ============================================================================

#[test]
fn test_stall_budget_within_budget() {
    let b = StallBudget::new(StallCategory::InstructionCacheMiss, 1000, 800);
    assert!(b.within_budget);
    assert!(b.overshoot_millionths < 0);
    assert_eq!(b.overshoot_cycles(), 0);
}

#[test]
fn test_stall_budget_over_budget() {
    let b = StallBudget::new(StallCategory::BranchMispredict, 1000, 1500);
    assert!(!b.within_budget);
    assert!(b.overshoot_millionths > 0);
    assert_eq!(b.overshoot_cycles(), 500);
}

#[test]
fn test_stall_budget_zero_budget_zero_measured() {
    let b = StallBudget::new(StallCategory::DecodeBubble, 0, 0);
    assert!(b.within_budget);
    assert_eq!(b.overshoot_millionths, 0);
}

#[test]
fn test_stall_budget_zero_budget_nonzero_measured() {
    let b = StallBudget::new(StallCategory::FetchBubble, 0, 100);
    assert!(!b.within_budget);
    assert_eq!(b.overshoot_millionths, FIXED_ONE as i64);
}

#[test]
fn test_stall_budget_content_hash_deterministic() {
    let a = StallBudget::new(StallCategory::AlignmentPenalty, 500, 300);
    let b = StallBudget::new(StallCategory::AlignmentPenalty, 500, 300);
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn test_stall_budget_display() {
    let b = StallBudget::new(StallCategory::MicroOpCacheOverflow, 2000, 1800);
    let s = format!("{b}");
    assert!(s.contains("micro_op_cache_overflow"));
}

// ============================================================================
// LayoutPolicyEntry
// ============================================================================

#[test]
fn test_layout_policy_entry_constructor() {
    let hw = hw_set(&["skylake", "zen3"]);
    let p = LayoutPolicyEntry::new(LayoutStrategy::HotColdSplit, hw.clone(), true, true, 10_000);
    assert_eq!(p.strategy, LayoutStrategy::HotColdSplit);
    assert_eq!(p.hardware_count(), 2);
    assert!(p.covers_hardware("skylake"));
    assert!(p.covers_hardware("zen3"));
    assert!(!p.covers_hardware("raptor_lake"));
    assert!(p.pin_recommended);
    assert!(p.rollback_if_regressed);
}

#[test]
fn test_layout_policy_entry_content_hash_deterministic() {
    let hw = hw_set(&["zen4"]);
    let a = LayoutPolicyEntry::new(
        LayoutStrategy::FunctionReordering,
        hw.clone(),
        false,
        false,
        0,
    );
    let b = LayoutPolicyEntry::new(LayoutStrategy::FunctionReordering, hw, false, false, 0);
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn test_layout_policy_entry_display() {
    let hw = hw_set(&["skylake"]);
    let p = LayoutPolicyEntry::new(LayoutStrategy::CacheFriendly, hw, true, false, 5000);
    let s = format!("{p}");
    assert!(s.contains("cache_friendly"));
}

// ============================================================================
// GovernanceConfig
// ============================================================================

#[test]
fn test_governance_config_default() {
    let c = GovernanceConfig::default();
    assert_eq!(
        c.max_stall_budget_millionths,
        DEFAULT_MAX_STALL_BUDGET_MILLIONTHS
    );
    assert_eq!(
        c.min_improvement_millionths,
        DEFAULT_MIN_IMPROVEMENT_MILLIONTHS
    );
    assert_eq!(
        c.max_alignment_waste_bytes,
        DEFAULT_MAX_ALIGNMENT_WASTE_BYTES
    );
    assert_eq!(c.min_hardware_coverage, DEFAULT_MIN_HARDWARE_COVERAGE);
    assert!(c.known_hardware.is_empty());
    assert!(c.required_strategies.is_empty());
    assert!(c.fail_closed_on_empty);
}

#[test]
fn test_governance_config_builders() {
    let strats: BTreeSet<LayoutStrategy> = [LayoutStrategy::HotColdSplit].iter().copied().collect();
    let hw = hw_set(&["zen4", "raptor_lake"]);
    let c = GovernanceConfig::default()
        .with_max_stall_budget(300_000)
        .with_min_improvement(5_000)
        .with_max_alignment_waste(8192)
        .with_min_hardware_coverage(750_000)
        .with_required_strategies(strats.clone())
        .with_known_hardware(hw.clone());
    assert_eq!(c.max_stall_budget_millionths, 300_000);
    assert_eq!(c.min_improvement_millionths, 5_000);
    assert_eq!(c.max_alignment_waste_bytes, 8192);
    assert_eq!(c.min_hardware_coverage, 750_000);
    assert_eq!(c.required_strategies, strats);
    assert_eq!(c.known_hardware, hw);
}

#[test]
fn test_governance_config_display() {
    let c = GovernanceConfig::default();
    let s = format!("{c}");
    assert!(s.contains("GovernanceConfig"));
}

// ============================================================================
// ViolationKind
// ============================================================================

#[test]
fn test_violation_kind_tags() {
    let vk = ViolationKind::EmptyEvaluation;
    assert_eq!(vk.tag(), "empty_evaluation");

    let vk2 = ViolationKind::StallBudgetExceeded {
        total_overshoot_millionths: 500_000,
        threshold_millionths: 200_000,
    };
    assert_eq!(vk2.tag(), "stall_budget_exceeded");

    let vk3 = ViolationKind::MissingRequiredStrategy {
        strategy: LayoutStrategy::HotColdSplit,
    };
    assert_eq!(vk3.tag(), "missing_required_strategy");
}

#[test]
fn test_violation_kind_display() {
    let vk = ViolationKind::AlignmentWasteExceeded {
        total_waste_bytes: 8000,
        threshold_bytes: 4096,
    };
    let s = format!("{vk}");
    assert!(s.contains("alignment waste exceeded"));
    assert!(s.contains("8000"));
}

// ============================================================================
// GovernanceVerdict
// ============================================================================

#[test]
fn test_verdict_approved_allows_publication() {
    assert!(GovernanceVerdict::Approved.allows_publication());
}

#[test]
fn test_verdict_non_approved() {
    assert!(!GovernanceVerdict::StallBudgetExceeded.allows_publication());
    assert!(!GovernanceVerdict::ImprovementInsufficient.allows_publication());
    assert!(!GovernanceVerdict::AlignmentWasteExceeded.allows_publication());
    assert!(!GovernanceVerdict::HardwareCoverageGap.allows_publication());
    assert!(!GovernanceVerdict::PolicyConflict.allows_publication());
    assert!(!GovernanceVerdict::MultipleViolations { count: 2 }.allows_publication());
}

#[test]
fn test_verdict_display() {
    assert_eq!(format!("{}", GovernanceVerdict::Approved), "approved");
    let mv = GovernanceVerdict::MultipleViolations { count: 3 };
    let s = format!("{mv}");
    assert!(s.contains("multiple_violations"));
    assert!(s.contains("3"));
}

#[test]
fn test_verdict_as_str() {
    assert_eq!(GovernanceVerdict::Approved.as_str(), "approved");
    assert_eq!(
        GovernanceVerdict::StallBudgetExceeded.as_str(),
        "stall_budget_exceeded"
    );
    assert_eq!(
        GovernanceVerdict::PolicyConflict.as_str(),
        "policy_conflict"
    );
}

// ============================================================================
// GovernanceEvaluator lifecycle
// ============================================================================

#[test]
fn test_evaluator_new_with_defaults() {
    let ev = GovernanceEvaluator::with_defaults(ep());
    assert_eq!(*ev.epoch(), ep());
    assert_eq!(ev.evaluation_count(), 0);
    assert_eq!(ev.alignment_entry_count(), 0);
    assert_eq!(ev.stall_budget_count(), 0);
    assert_eq!(ev.policy_count(), 0);
}

#[test]
fn test_evaluator_add_alignment() {
    let mut ev = GovernanceEvaluator::with_defaults(ep());
    let e = AlignmentEntry::new("fn_a", LayoutStrategy::LoopAlignment, 64, 50, 100, 8);
    ev.add_alignment(e);
    assert_eq!(ev.alignment_entry_count(), 1);
}

#[test]
fn test_evaluator_add_stall_budget() {
    let mut ev = GovernanceEvaluator::with_defaults(ep());
    let b = StallBudget::new(StallCategory::InstructionCacheMiss, 1000, 800);
    ev.add_stall_budget(b);
    assert_eq!(ev.stall_budget_count(), 1);
}

#[test]
fn test_evaluator_add_policy() {
    let mut ev = GovernanceEvaluator::with_defaults(ep());
    let p = LayoutPolicyEntry::new(
        LayoutStrategy::HotColdSplit,
        hw_set(&["zen4"]),
        false,
        false,
        0,
    );
    ev.add_policy(p);
    assert_eq!(ev.policy_count(), 1);
}

#[test]
fn test_evaluator_clear_resets() {
    let mut ev = GovernanceEvaluator::with_defaults(ep());
    ev.add_alignment(AlignmentEntry::new(
        "f",
        LayoutStrategy::NopPadding,
        64,
        80,
        100,
        16,
    ));
    ev.add_stall_budget(StallBudget::new(StallCategory::DecodeBubble, 500, 400));
    ev.add_policy(LayoutPolicyEntry::new(
        LayoutStrategy::CacheFriendly,
        hw_set(&["x"]),
        false,
        false,
        0,
    ));
    ev.clear();
    assert_eq!(ev.alignment_entry_count(), 0);
    assert_eq!(ev.stall_budget_count(), 0);
    assert_eq!(ev.policy_count(), 0);
}

#[test]
fn test_evaluator_empty_fail_closed() {
    let cfg = GovernanceConfig::default();
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    let receipt = ev.evaluate();
    assert!(!receipt.is_clean());
    assert!(receipt.violation_count() > 0);
}

#[test]
fn test_evaluator_empty_fail_open() {
    let cfg = GovernanceConfig {
        fail_closed_on_empty: false,
        ..Default::default()
    };
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    let receipt = ev.evaluate();
    assert!(receipt.is_clean());
}

#[test]
fn test_evaluator_approved_with_good_data() {
    let cfg = GovernanceConfig::default()
        .with_min_improvement(0)
        .with_max_alignment_waste(1000);
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    ev.add_alignment(AlignmentEntry::new(
        "fn_hot",
        LayoutStrategy::LoopAlignment,
        64,
        50,
        100,
        8,
    ));
    ev.add_stall_budget(StallBudget::new(
        StallCategory::InstructionCacheMiss,
        1000,
        800,
    ));
    let receipt = ev.evaluate();
    assert!(receipt.is_clean());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
}

#[test]
fn test_evaluator_stall_budget_exceeded() {
    let cfg = GovernanceConfig::default().with_max_stall_budget(10_000);
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    // Alignment needed to avoid empty-evaluation violation
    ev.add_alignment(AlignmentEntry::new(
        "f",
        LayoutStrategy::LoopAlignment,
        64,
        50,
        100,
        0,
    ));
    ev.add_stall_budget(StallBudget::new(StallCategory::BranchMispredict, 100, 1000));
    let receipt = ev.evaluate();
    assert!(!receipt.is_clean());
}

#[test]
fn test_evaluator_alignment_waste_exceeded() {
    let cfg = GovernanceConfig::default()
        .with_max_alignment_waste(10)
        .with_min_improvement(0);
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    ev.add_alignment(AlignmentEntry::new(
        "fn_w",
        LayoutStrategy::NopPadding,
        64,
        90,
        100,
        100,
    ));
    let receipt = ev.evaluate();
    assert!(!receipt.is_clean());
}

#[test]
fn test_evaluator_invalid_alignment_violation() {
    let cfg = GovernanceConfig::default().with_min_improvement(0);
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    ev.add_alignment(AlignmentEntry::new(
        "fn_bad",
        LayoutStrategy::LoopAlignment,
        3,
        50,
        100,
        0,
    ));
    let receipt = ev.evaluate();
    assert!(!receipt.is_clean());
}

#[test]
fn test_evaluator_missing_required_strategy() {
    let strats: BTreeSet<LayoutStrategy> =
        [LayoutStrategy::HotColdSplit, LayoutStrategy::LoopAlignment]
            .iter()
            .copied()
            .collect();
    let cfg = GovernanceConfig::default()
        .with_required_strategies(strats)
        .with_min_improvement(0);
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    ev.add_alignment(AlignmentEntry::new(
        "fn_a",
        LayoutStrategy::LoopAlignment,
        64,
        50,
        100,
        0,
    ));
    let receipt = ev.evaluate();
    assert!(!receipt.is_clean());
}

#[test]
fn test_evaluator_hardware_coverage_gap() {
    let known = hw_set(&["skylake", "zen3", "raptor_lake", "alder_lake"]);
    let cfg = GovernanceConfig::default()
        .with_known_hardware(known)
        .with_min_hardware_coverage(750_000)
        .with_min_improvement(0);
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    ev.add_alignment(AlignmentEntry::new(
        "f",
        LayoutStrategy::HotColdSplit,
        64,
        50,
        100,
        0,
    ));
    // Only cover one hardware target
    ev.add_policy(LayoutPolicyEntry::new(
        LayoutStrategy::HotColdSplit,
        hw_set(&["skylake"]),
        false,
        false,
        0,
    ));
    let receipt = ev.evaluate();
    assert!(!receipt.is_clean());
}

#[test]
fn test_evaluator_policy_conflict() {
    let cfg = GovernanceConfig::default().with_min_improvement(0);
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    ev.add_alignment(AlignmentEntry::new(
        "f",
        LayoutStrategy::HotColdSplit,
        64,
        50,
        100,
        0,
    ));
    // Two pinned policies on same hardware
    ev.add_policy(LayoutPolicyEntry::new(
        LayoutStrategy::HotColdSplit,
        hw_set(&["zen4"]),
        true,
        false,
        0,
    ));
    ev.add_policy(LayoutPolicyEntry::new(
        LayoutStrategy::FunctionReordering,
        hw_set(&["zen4"]),
        true,
        false,
        0,
    ));
    let receipt = ev.evaluate();
    assert!(!receipt.is_clean());
}

#[test]
fn test_evaluator_total_waste_bytes() {
    let mut ev = GovernanceEvaluator::with_defaults(ep());
    ev.add_alignment(AlignmentEntry::new(
        "a",
        LayoutStrategy::LoopAlignment,
        64,
        50,
        100,
        100,
    ));
    ev.add_alignment(AlignmentEntry::new(
        "b",
        LayoutStrategy::NopPadding,
        64,
        60,
        100,
        200,
    ));
    assert_eq!(ev.total_waste_bytes(), 300);
}

#[test]
fn test_evaluator_mean_improvement() {
    let mut ev = GovernanceEvaluator::with_defaults(ep());
    ev.add_alignment(AlignmentEntry::new(
        "a",
        LayoutStrategy::LoopAlignment,
        64,
        50,
        100,
        0,
    ));
    ev.add_alignment(AlignmentEntry::new(
        "b",
        LayoutStrategy::LoopAlignment,
        64,
        0,
        100,
        0,
    ));
    let mean = ev.mean_improvement();
    assert!(mean > 0);
}

#[test]
fn test_evaluator_mean_improvement_empty() {
    let ev = GovernanceEvaluator::with_defaults(ep());
    assert_eq!(ev.mean_improvement(), 0);
}

#[test]
fn test_evaluator_covered_hardware() {
    let mut ev = GovernanceEvaluator::with_defaults(ep());
    ev.add_policy(LayoutPolicyEntry::new(
        LayoutStrategy::HotColdSplit,
        hw_set(&["skylake", "zen4"]),
        false,
        false,
        0,
    ));
    ev.add_policy(LayoutPolicyEntry::new(
        LayoutStrategy::CacheFriendly,
        hw_set(&["zen4", "raptor_lake"]),
        false,
        false,
        0,
    ));
    let covered = ev.covered_hardware();
    assert_eq!(covered.len(), 3);
    assert!(covered.contains("skylake"));
    assert!(covered.contains("zen4"));
    assert!(covered.contains("raptor_lake"));
}

#[test]
fn test_evaluator_present_strategies() {
    let mut ev = GovernanceEvaluator::with_defaults(ep());
    ev.add_alignment(AlignmentEntry::new(
        "a",
        LayoutStrategy::LoopAlignment,
        64,
        50,
        100,
        0,
    ));
    ev.add_policy(LayoutPolicyEntry::new(
        LayoutStrategy::HotColdSplit,
        hw_set(&["x"]),
        false,
        false,
        0,
    ));
    let strats = ev.present_strategies();
    assert!(strats.contains(&LayoutStrategy::LoopAlignment));
    assert!(strats.contains(&LayoutStrategy::HotColdSplit));
}

// ============================================================================
// GovernanceReceipt
// ============================================================================

#[test]
fn test_receipt_is_clean_when_approved() {
    let cfg = GovernanceConfig {
        fail_closed_on_empty: false,
        ..Default::default()
    };
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    let receipt = ev.evaluate();
    assert!(receipt.is_clean());
    assert_eq!(receipt.violation_count(), 0);
}

#[test]
fn test_receipt_display() {
    let cfg = GovernanceConfig {
        fail_closed_on_empty: false,
        ..Default::default()
    };
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    let receipt = ev.evaluate();
    let s = format!("{receipt}");
    assert!(s.contains("GovernanceReceipt"));
    assert!(s.contains("approved"));
}

// ============================================================================
// Content hash determinism
// ============================================================================

#[test]
fn test_content_hash_deterministic() {
    let build = || {
        let cfg = GovernanceConfig::default().with_min_improvement(0);
        let mut ev = GovernanceEvaluator::new(cfg, ep());
        ev.add_alignment(AlignmentEntry::new(
            "fn_a",
            LayoutStrategy::LoopAlignment,
            64,
            50,
            100,
            0,
        ));
        ev.evaluate()
    };
    let r1 = build();
    let r2 = build();
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn test_content_hash_changes_with_data() {
    let cfg = GovernanceConfig::default().with_min_improvement(0);
    let mut ev1 = GovernanceEvaluator::new(cfg.clone(), ep());
    ev1.add_alignment(AlignmentEntry::new(
        "fn_a",
        LayoutStrategy::LoopAlignment,
        64,
        50,
        100,
        0,
    ));
    let r1 = ev1.evaluate();

    let mut ev2 = GovernanceEvaluator::new(cfg, ep());
    ev2.add_alignment(AlignmentEntry::new(
        "fn_b",
        LayoutStrategy::LoopAlignment,
        64,
        50,
        100,
        0,
    ));
    let r2 = ev2.evaluate();
    assert_ne!(r1.content_hash, r2.content_hash);
}

// ============================================================================
// Free functions
// ============================================================================

#[test]
fn test_compute_improvement_positive() {
    let imp = compute_improvement(100, 50);
    assert_eq!(imp, 500_000); // 50% improvement
}

#[test]
fn test_compute_improvement_negative() {
    let imp = compute_improvement(100, 150);
    assert_eq!(imp, -500_000); // 50% regression
}

#[test]
fn test_compute_improvement_zero_baseline() {
    assert_eq!(compute_improvement(0, 100), 0);
}

#[test]
fn test_is_valid_alignment_bytes() {
    assert!(is_valid_alignment_bytes(1));
    assert!(is_valid_alignment_bytes(64));
    assert!(is_valid_alignment_bytes(4096));
    assert!(!is_valid_alignment_bytes(0));
    assert!(!is_valid_alignment_bytes(3));
    assert!(!is_valid_alignment_bytes(8192));
}

#[test]
fn test_compute_coverage_ratio() {
    let covered = hw_set(&["a", "b"]);
    let known = hw_set(&["a", "b", "c", "d"]);
    let ratio = compute_coverage_ratio(&covered, &known);
    assert_eq!(ratio, 500_000);
}

#[test]
fn test_compute_coverage_ratio_empty_known() {
    let covered = hw_set(&["a"]);
    let known = BTreeSet::new();
    assert_eq!(compute_coverage_ratio(&covered, &known), FIXED_ONE);
}

#[test]
fn test_should_rollback_regressed() {
    let p = LayoutPolicyEntry::new(
        LayoutStrategy::HotColdSplit,
        hw_set(&["x"]),
        false,
        true,
        10_000,
    );
    assert!(should_rollback(&p, -50_000));
}

#[test]
fn test_should_rollback_below_keep_threshold() {
    let p = LayoutPolicyEntry::new(
        LayoutStrategy::HotColdSplit,
        hw_set(&["x"]),
        false,
        true,
        10_000,
    );
    assert!(should_rollback(&p, 5_000));
}

#[test]
fn test_should_rollback_disabled() {
    let p = LayoutPolicyEntry::new(
        LayoutStrategy::HotColdSplit,
        hw_set(&["x"]),
        false,
        false,
        10_000,
    );
    assert!(!should_rollback(&p, -50_000));
}

#[test]
fn test_total_stall_overshoot() {
    let budgets = vec![
        StallBudget::new(StallCategory::InstructionCacheMiss, 100, 200),
        StallBudget::new(StallCategory::BranchMispredict, 100, 50),
        StallBudget::new(StallCategory::DecodeBubble, 100, 300),
    ];
    let overshoot = total_stall_overshoot(&budgets);
    assert!(overshoot > 0);
}

#[test]
fn test_missing_strategies_fn() {
    let required: BTreeSet<LayoutStrategy> = [
        LayoutStrategy::HotColdSplit,
        LayoutStrategy::LoopAlignment,
        LayoutStrategy::CacheFriendly,
    ]
    .iter()
    .copied()
    .collect();
    let present: BTreeSet<LayoutStrategy> =
        [LayoutStrategy::LoopAlignment].iter().copied().collect();
    let missing = missing_strategies(&required, &present);
    assert_eq!(missing.len(), 2);
    assert!(missing.contains(&LayoutStrategy::HotColdSplit));
    assert!(missing.contains(&LayoutStrategy::CacheFriendly));
}

// ============================================================================
// E2E scenarios
// ============================================================================

#[test]
fn test_e2e_full_passing_evaluation() {
    let strats: BTreeSet<LayoutStrategy> = [LayoutStrategy::HotColdSplit].iter().copied().collect();
    let known = hw_set(&["skylake", "zen4"]);
    let cfg = GovernanceConfig::default()
        .with_required_strategies(strats)
        .with_known_hardware(known)
        .with_min_improvement(0)
        .with_max_alignment_waste(10_000);
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    ev.add_alignment(AlignmentEntry::new(
        "main",
        LayoutStrategy::HotColdSplit,
        64,
        50,
        100,
        8,
    ));
    ev.add_stall_budget(StallBudget::new(
        StallCategory::InstructionCacheMiss,
        1000,
        800,
    ));
    ev.add_policy(LayoutPolicyEntry::new(
        LayoutStrategy::HotColdSplit,
        hw_set(&["skylake", "zen4"]),
        false,
        true,
        0,
    ));
    let receipt = ev.evaluate();
    assert!(receipt.is_clean());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
}

#[test]
fn test_e2e_serde_roundtrip_receipt() {
    let cfg = GovernanceConfig {
        fail_closed_on_empty: false,
        ..Default::default()
    };
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    let receipt = ev.evaluate();
    let json = serde_json::to_string(&receipt).unwrap();
    let back: GovernanceReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt.verdict, back.verdict);
    assert_eq!(receipt.content_hash, back.content_hash);
}

#[test]
fn test_e2e_multiple_violations_verdict() {
    let strats: BTreeSet<LayoutStrategy> =
        [LayoutStrategy::CacheFriendly].iter().copied().collect();
    let cfg = GovernanceConfig::default()
        .with_required_strategies(strats)
        .with_max_alignment_waste(1)
        .with_min_improvement(0);
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    ev.add_alignment(AlignmentEntry::new(
        "f",
        LayoutStrategy::LoopAlignment,
        64,
        50,
        100,
        100,
    ));
    let receipt = ev.evaluate();
    match receipt.verdict {
        GovernanceVerdict::MultipleViolations { count } => assert!(count >= 2),
        _ => panic!("expected MultipleViolations"),
    }
}

#[test]
fn test_e2e_evaluation_count_increments() {
    let cfg = GovernanceConfig {
        fail_closed_on_empty: false,
        ..Default::default()
    };
    let mut ev = GovernanceEvaluator::new(cfg, ep());
    assert_eq!(ev.evaluation_count(), 0);
    let _ = ev.evaluate();
    assert_eq!(ev.evaluation_count(), 1);
    let _ = ev.evaluate();
    assert_eq!(ev.evaluation_count(), 2);
}
