//! Enrichment integration tests for `hardware_code_layout_governance`.
//!
//! Covers Copy/Clone semantics, BTreeSet ordering/dedup, serde roundtrips,
//! Display coverage, Debug nonempty, Default, constants, JSON field-name
//! stability, determinism, free-function coverage, and edge cases.

use std::collections::BTreeSet;

use frankenengine_engine::hardware_code_layout_governance::{
    AlignmentEntry, BEAD_ID, COMPONENT, DEFAULT_MAX_ALIGNMENT_WASTE_BYTES,
    DEFAULT_MAX_STALL_BUDGET_MILLIONTHS, DEFAULT_MIN_HARDWARE_COVERAGE,
    DEFAULT_MIN_IMPROVEMENT_MILLIONTHS, FIXED_ONE, GovernanceConfig, GovernanceEvaluator,
    GovernanceReceipt, GovernanceVerdict, LayoutPolicyEntry, LayoutStrategy, MAX_ALIGNMENT_ENTRIES,
    MAX_POLICY_ENTRIES, MAX_STALL_BUDGETS, MAX_STRATEGIES, POLICY_ID, SCHEMA_VERSION, StallBudget,
    StallCategory, ViolationKind, compute_coverage_ratio, compute_improvement,
    is_valid_alignment_bytes, missing_strategies, should_rollback, total_stall_overshoot,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn hw_set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}

fn sample_alignment_entry() -> AlignmentEntry {
    AlignmentEntry::new("func_a", LayoutStrategy::LoopAlignment, 64, 50, 100, 14)
}

fn sample_stall_budget() -> StallBudget {
    StallBudget::new(StallCategory::InstructionCacheMiss, 1000, 800)
}

fn sample_policy_entry() -> LayoutPolicyEntry {
    LayoutPolicyEntry::new(
        LayoutStrategy::HotColdSplit,
        hw_set(&["zen4", "alderlake"]),
        false,
        true,
        10_000,
    )
}

// -----------------------------------------------------------------------
// Copy semantics — LayoutStrategy, StallCategory
// -----------------------------------------------------------------------

#[test]
fn enrichment_layout_strategy_copy() {
    let a = LayoutStrategy::LoopAlignment;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_stall_category_copy() {
    let a = StallCategory::BranchMispredict;
    let b = a;
    assert_eq!(a, b);
}

// -----------------------------------------------------------------------
// Clone independence
// -----------------------------------------------------------------------

#[test]
fn enrichment_alignment_entry_clone_independence() {
    let original = sample_alignment_entry();
    let cloned = original.clone();
    assert_eq!(original, cloned);
    assert_eq!(original.function_id, "func_a");
}

#[test]
fn enrichment_stall_budget_clone_independence() {
    let original = sample_stall_budget();
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_policy_entry_clone_independence() {
    let original = sample_policy_entry();
    let cloned = original.clone();
    assert_eq!(original, cloned);
    assert_eq!(original.hardware_count(), cloned.hardware_count());
}

#[test]
fn enrichment_governance_config_clone_independence() {
    let original = GovernanceConfig::default();
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_governance_verdict_clone_independence() {
    let original = GovernanceVerdict::Approved;
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

// -----------------------------------------------------------------------
// BTreeSet ordering and dedup
// -----------------------------------------------------------------------

#[test]
fn enrichment_layout_strategy_btreeset_ordering() {
    let set: BTreeSet<LayoutStrategy> = [
        LayoutStrategy::NopPadding,
        LayoutStrategy::HotColdSplit,
        LayoutStrategy::NopPadding,
        LayoutStrategy::CacheFriendly,
    ]
    .into_iter()
    .collect();
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_stall_category_btreeset_ordering() {
    let set: BTreeSet<StallCategory> = [
        StallCategory::FetchBubble,
        StallCategory::BranchMispredict,
        StallCategory::FetchBubble,
    ]
    .into_iter()
    .collect();
    assert_eq!(set.len(), 2);
}

// -----------------------------------------------------------------------
// Serde roundtrips
// -----------------------------------------------------------------------

#[test]
fn enrichment_layout_strategy_serde_all_variants() {
    for s in LayoutStrategy::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: LayoutStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

#[test]
fn enrichment_stall_category_serde_all_variants() {
    for c in StallCategory::ALL {
        let json = serde_json::to_string(c).unwrap();
        let back: StallCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

#[test]
fn enrichment_alignment_entry_serde_roundtrip() {
    let entry = sample_alignment_entry();
    let json = serde_json::to_string(&entry).unwrap();
    let back: AlignmentEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_stall_budget_serde_roundtrip() {
    let budget = sample_stall_budget();
    let json = serde_json::to_string(&budget).unwrap();
    let back: StallBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(budget, back);
}

#[test]
fn enrichment_policy_entry_serde_roundtrip() {
    let policy = sample_policy_entry();
    let json = serde_json::to_string(&policy).unwrap();
    let back: LayoutPolicyEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

#[test]
fn enrichment_governance_config_serde_roundtrip() {
    let config = GovernanceConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: GovernanceConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn enrichment_governance_verdict_serde_all_variants() {
    let variants = [
        GovernanceVerdict::Approved,
        GovernanceVerdict::StallBudgetExceeded,
        GovernanceVerdict::ImprovementInsufficient,
        GovernanceVerdict::AlignmentWasteExceeded,
        GovernanceVerdict::HardwareCoverageGap,
        GovernanceVerdict::PolicyConflict,
        GovernanceVerdict::MultipleViolations { count: 3 },
    ];
    assert_eq!(variants.len(), 7);
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: GovernanceVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_violation_kind_serde_roundtrip() {
    let v = ViolationKind::StallBudgetExceeded {
        total_overshoot_millionths: 300_000,
        threshold_millionths: 200_000,
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: ViolationKind = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_governance_receipt_serde_roundtrip() {
    let config = GovernanceConfig::default();
    let mut eval = GovernanceEvaluator::new(config, epoch(1));
    eval.add_alignment(sample_alignment_entry());
    eval.add_stall_budget(sample_stall_budget());
    let receipt = eval.evaluate();
    let json = serde_json::to_string(&receipt).unwrap();
    let back: GovernanceReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

// -----------------------------------------------------------------------
// Display coverage
// -----------------------------------------------------------------------

#[test]
fn enrichment_layout_strategy_display_all() {
    let set: BTreeSet<String> = LayoutStrategy::ALL.iter().map(|s| s.to_string()).collect();
    assert_eq!(set.len(), LayoutStrategy::ALL.len());
    for s in LayoutStrategy::ALL {
        assert!(!s.to_string().is_empty());
    }
}

#[test]
fn enrichment_stall_category_display_all() {
    let set: BTreeSet<String> = StallCategory::ALL.iter().map(|c| c.to_string()).collect();
    assert_eq!(set.len(), StallCategory::ALL.len());
}

#[test]
fn enrichment_alignment_entry_display() {
    let entry = sample_alignment_entry();
    let s = entry.to_string();
    assert!(s.contains("func_a"));
    assert!(s.contains("loop_alignment"));
}

#[test]
fn enrichment_stall_budget_display() {
    let budget = sample_stall_budget();
    let s = budget.to_string();
    assert!(s.contains("instruction_cache_miss"));
}

#[test]
fn enrichment_policy_entry_display() {
    let policy = sample_policy_entry();
    let s = policy.to_string();
    assert!(s.contains("hot_cold_split"));
}

#[test]
fn enrichment_governance_config_display() {
    let config = GovernanceConfig::default();
    let s = config.to_string();
    assert!(s.contains("GovernanceConfig"));
}

#[test]
fn enrichment_governance_verdict_display_all() {
    let variants = [
        GovernanceVerdict::Approved,
        GovernanceVerdict::StallBudgetExceeded,
        GovernanceVerdict::ImprovementInsufficient,
        GovernanceVerdict::AlignmentWasteExceeded,
        GovernanceVerdict::HardwareCoverageGap,
        GovernanceVerdict::PolicyConflict,
        GovernanceVerdict::MultipleViolations { count: 2 },
    ];
    let set: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(set.len(), variants.len());
}

#[test]
fn enrichment_violation_kind_display_all_unique() {
    let variants: Vec<ViolationKind> = vec![
        ViolationKind::StallBudgetExceeded {
            total_overshoot_millionths: 300_000,
            threshold_millionths: 200_000,
        },
        ViolationKind::ImprovementInsufficient {
            measured_millionths: 5_000,
            threshold_millionths: 10_000,
        },
        ViolationKind::AlignmentWasteExceeded {
            total_waste_bytes: 8192,
            threshold_bytes: 4096,
        },
        ViolationKind::HardwareCoverageGap {
            coverage_millionths: 300_000,
            threshold_millionths: 500_000,
            uncovered: hw_set(&["arm"]),
        },
        ViolationKind::MissingRequiredStrategy {
            strategy: LayoutStrategy::HotColdSplit,
        },
        ViolationKind::PolicyConflict {
            hardware: "zen4".to_string(),
            conflicting_strategies: [
                LayoutStrategy::LoopAlignment,
                LayoutStrategy::BranchAlignment,
            ]
            .into_iter()
            .collect(),
        },
        ViolationKind::InvalidAlignment {
            function_id: "f".to_string(),
            alignment_bytes: 3,
        },
        ViolationKind::EmptyEvaluation,
    ];
    let set: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(set.len(), variants.len());
}

// -----------------------------------------------------------------------
// as_str / tag coverage
// -----------------------------------------------------------------------

#[test]
fn enrichment_layout_strategy_as_str_all() {
    let set: BTreeSet<&str> = LayoutStrategy::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(set.len(), 8);
}

#[test]
fn enrichment_stall_category_as_str_all() {
    let set: BTreeSet<&str> = StallCategory::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_governance_verdict_as_str_all() {
    let variants = [
        GovernanceVerdict::Approved,
        GovernanceVerdict::StallBudgetExceeded,
        GovernanceVerdict::ImprovementInsufficient,
        GovernanceVerdict::AlignmentWasteExceeded,
        GovernanceVerdict::HardwareCoverageGap,
        GovernanceVerdict::PolicyConflict,
        GovernanceVerdict::MultipleViolations { count: 1 },
    ];
    let set: BTreeSet<&str> = variants.iter().map(|v| v.as_str()).collect();
    assert_eq!(set.len(), 7);
}

#[test]
fn enrichment_violation_kind_tag_all() {
    let variants: Vec<ViolationKind> = vec![
        ViolationKind::StallBudgetExceeded {
            total_overshoot_millionths: 0,
            threshold_millionths: 0,
        },
        ViolationKind::ImprovementInsufficient {
            measured_millionths: 0,
            threshold_millionths: 0,
        },
        ViolationKind::AlignmentWasteExceeded {
            total_waste_bytes: 0,
            threshold_bytes: 0,
        },
        ViolationKind::HardwareCoverageGap {
            coverage_millionths: 0,
            threshold_millionths: 0,
            uncovered: BTreeSet::new(),
        },
        ViolationKind::MissingRequiredStrategy {
            strategy: LayoutStrategy::NopPadding,
        },
        ViolationKind::PolicyConflict {
            hardware: String::new(),
            conflicting_strategies: BTreeSet::new(),
        },
        ViolationKind::InvalidAlignment {
            function_id: String::new(),
            alignment_bytes: 0,
        },
        ViolationKind::EmptyEvaluation,
    ];
    let set: BTreeSet<&str> = variants.iter().map(|v| v.tag()).collect();
    assert_eq!(set.len(), 8);
}

// -----------------------------------------------------------------------
// Debug nonempty
// -----------------------------------------------------------------------

#[test]
fn enrichment_alignment_entry_debug() {
    assert!(!format!("{:?}", sample_alignment_entry()).is_empty());
}

#[test]
fn enrichment_stall_budget_debug() {
    assert!(!format!("{:?}", sample_stall_budget()).is_empty());
}

#[test]
fn enrichment_policy_entry_debug() {
    assert!(!format!("{:?}", sample_policy_entry()).is_empty());
}

#[test]
fn enrichment_governance_config_debug() {
    assert!(!format!("{:?}", GovernanceConfig::default()).is_empty());
}

#[test]
fn enrichment_governance_verdict_debug() {
    assert!(!format!("{:?}", GovernanceVerdict::Approved).is_empty());
}

// -----------------------------------------------------------------------
// Default
// -----------------------------------------------------------------------

#[test]
fn enrichment_governance_config_default_values() {
    let cfg = GovernanceConfig::default();
    assert_eq!(
        cfg.max_stall_budget_millionths,
        DEFAULT_MAX_STALL_BUDGET_MILLIONTHS
    );
    assert_eq!(
        cfg.min_improvement_millionths,
        DEFAULT_MIN_IMPROVEMENT_MILLIONTHS
    );
    assert_eq!(
        cfg.max_alignment_waste_bytes,
        DEFAULT_MAX_ALIGNMENT_WASTE_BYTES
    );
    assert_eq!(cfg.min_hardware_coverage, DEFAULT_MIN_HARDWARE_COVERAGE);
    assert!(cfg.required_strategies.is_empty());
    assert!(cfg.known_hardware.is_empty());
    assert!(cfg.fail_closed_on_empty);
}

// -----------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------

#[test]
fn enrichment_constants_nonempty() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!COMPONENT.is_empty());
    assert!(!BEAD_ID.is_empty());
    assert!(!POLICY_ID.is_empty());
    assert_eq!(FIXED_ONE, 1_000_000);
    const {
        assert!(MAX_STRATEGIES > 0);
        assert!(MAX_ALIGNMENT_ENTRIES > 0);
        assert!(MAX_STALL_BUDGETS > 0);
        assert!(MAX_POLICY_ENTRIES > 0);
    }
}

// -----------------------------------------------------------------------
// LayoutStrategy methods
// -----------------------------------------------------------------------

#[test]
fn enrichment_layout_strategy_all_count() {
    assert_eq!(LayoutStrategy::ALL.len(), 8);
}

#[test]
fn enrichment_layout_strategy_introduces_waste() {
    assert!(LayoutStrategy::LoopAlignment.introduces_waste());
    assert!(LayoutStrategy::BranchAlignment.introduces_waste());
    assert!(LayoutStrategy::NopPadding.introduces_waste());
    assert!(!LayoutStrategy::HotColdSplit.introduces_waste());
    assert!(!LayoutStrategy::FunctionReordering.introduces_waste());
    assert!(!LayoutStrategy::CacheFriendly.introduces_waste());
}

#[test]
fn enrichment_layout_strategy_targets_icache() {
    assert!(LayoutStrategy::HotColdSplit.targets_icache());
    assert!(LayoutStrategy::FunctionReordering.targets_icache());
    assert!(LayoutStrategy::CacheFriendly.targets_icache());
    assert!(LayoutStrategy::CallerCalleeColocation.targets_icache());
    assert!(LayoutStrategy::ColdTailCompaction.targets_icache());
    assert!(!LayoutStrategy::LoopAlignment.targets_icache());
    assert!(!LayoutStrategy::BranchAlignment.targets_icache());
    assert!(!LayoutStrategy::NopPadding.targets_icache());
}

// -----------------------------------------------------------------------
// StallCategory methods
// -----------------------------------------------------------------------

#[test]
fn enrichment_stall_category_all_count() {
    assert_eq!(StallCategory::ALL.len(), 6);
}

#[test]
fn enrichment_stall_category_addressable_by_alignment() {
    assert!(StallCategory::DecodeBubble.addressable_by_alignment());
    assert!(StallCategory::AlignmentPenalty.addressable_by_alignment());
    assert!(StallCategory::FetchBubble.addressable_by_alignment());
    assert!(!StallCategory::InstructionCacheMiss.addressable_by_alignment());
    assert!(!StallCategory::BranchMispredict.addressable_by_alignment());
}

#[test]
fn enrichment_stall_category_addressable_by_placement() {
    assert!(StallCategory::InstructionCacheMiss.addressable_by_placement());
    assert!(StallCategory::MicroOpCacheOverflow.addressable_by_placement());
    assert!(!StallCategory::BranchMispredict.addressable_by_placement());
    assert!(!StallCategory::DecodeBubble.addressable_by_placement());
}

// -----------------------------------------------------------------------
// AlignmentEntry methods
// -----------------------------------------------------------------------

#[test]
fn enrichment_alignment_entry_improvement() {
    let entry = AlignmentEntry::new("f", LayoutStrategy::LoopAlignment, 64, 50, 100, 0);
    assert!(entry.is_improvement());
    assert!(!entry.is_regression());
    assert!(entry.improvement_millionths > 0);
}

#[test]
fn enrichment_alignment_entry_regression() {
    let entry = AlignmentEntry::new("f", LayoutStrategy::LoopAlignment, 64, 150, 100, 0);
    assert!(!entry.is_improvement());
    assert!(entry.is_regression());
    assert!(entry.improvement_millionths < 0);
}

#[test]
fn enrichment_alignment_entry_valid_alignment() {
    let entry = AlignmentEntry::new("f", LayoutStrategy::LoopAlignment, 64, 50, 100, 0);
    assert!(entry.is_valid_alignment());
}

#[test]
fn enrichment_alignment_entry_invalid_alignment() {
    let entry = AlignmentEntry::new("f", LayoutStrategy::LoopAlignment, 3, 50, 100, 0);
    assert!(!entry.is_valid_alignment());
}

#[test]
fn enrichment_alignment_entry_zero_alignment_invalid() {
    let entry = AlignmentEntry::new("f", LayoutStrategy::LoopAlignment, 0, 50, 100, 0);
    assert!(!entry.is_valid_alignment());
}

// -----------------------------------------------------------------------
// StallBudget methods
// -----------------------------------------------------------------------

#[test]
fn enrichment_stall_budget_within_budget() {
    let budget = StallBudget::new(StallCategory::BranchMispredict, 1000, 800);
    assert!(budget.within_budget);
    assert_eq!(budget.overshoot_cycles(), 0);
}

#[test]
fn enrichment_stall_budget_exceeded() {
    let budget = StallBudget::new(StallCategory::BranchMispredict, 1000, 1500);
    assert!(!budget.within_budget);
    assert_eq!(budget.overshoot_cycles(), 500);
}

#[test]
fn enrichment_stall_budget_exactly_at_budget() {
    let budget = StallBudget::new(StallCategory::BranchMispredict, 1000, 1000);
    assert!(budget.within_budget);
    assert_eq!(budget.overshoot_cycles(), 0);
}

// -----------------------------------------------------------------------
// LayoutPolicyEntry methods
// -----------------------------------------------------------------------

#[test]
fn enrichment_policy_hardware_count() {
    let policy = sample_policy_entry();
    assert_eq!(policy.hardware_count(), 2);
}

#[test]
fn enrichment_policy_covers_hardware() {
    let policy = sample_policy_entry();
    assert!(policy.covers_hardware("zen4"));
    assert!(policy.covers_hardware("alderlake"));
    assert!(!policy.covers_hardware("arm_cortex_a78"));
}

// -----------------------------------------------------------------------
// GovernanceConfig builders
// -----------------------------------------------------------------------

#[test]
fn enrichment_config_builder_chain() {
    let config = GovernanceConfig::default()
        .with_max_stall_budget(500_000)
        .with_min_improvement(20_000)
        .with_max_alignment_waste(8192)
        .with_min_hardware_coverage(750_000)
        .with_required_strategies([LayoutStrategy::HotColdSplit].into_iter().collect())
        .with_known_hardware(hw_set(&["zen4"]));
    assert_eq!(config.max_stall_budget_millionths, 500_000);
    assert_eq!(config.min_improvement_millionths, 20_000);
    assert_eq!(config.max_alignment_waste_bytes, 8192);
    assert_eq!(config.min_hardware_coverage, 750_000);
    assert_eq!(config.required_strategies.len(), 1);
    assert_eq!(config.known_hardware.len(), 1);
}

// -----------------------------------------------------------------------
// GovernanceVerdict methods
// -----------------------------------------------------------------------

#[test]
fn enrichment_verdict_allows_publication() {
    assert!(GovernanceVerdict::Approved.allows_publication());
    assert!(!GovernanceVerdict::StallBudgetExceeded.allows_publication());
    assert!(!GovernanceVerdict::ImprovementInsufficient.allows_publication());
    assert!(!GovernanceVerdict::AlignmentWasteExceeded.allows_publication());
    assert!(!GovernanceVerdict::HardwareCoverageGap.allows_publication());
    assert!(!GovernanceVerdict::PolicyConflict.allows_publication());
    assert!(!GovernanceVerdict::MultipleViolations { count: 1 }.allows_publication());
}

// -----------------------------------------------------------------------
// GovernanceEvaluator lifecycle
// -----------------------------------------------------------------------

#[test]
fn enrichment_evaluator_with_defaults() {
    let eval = GovernanceEvaluator::with_defaults(epoch(1));
    assert_eq!(eval.alignment_entry_count(), 0);
    assert_eq!(eval.stall_budget_count(), 0);
    assert_eq!(eval.policy_count(), 0);
    assert_eq!(eval.evaluation_count(), 0);
    assert_eq!(*eval.epoch(), epoch(1));
}

#[test]
fn enrichment_evaluator_add_entries() {
    let config = GovernanceConfig::default();
    let mut eval = GovernanceEvaluator::new(config, epoch(1));
    eval.add_alignment(sample_alignment_entry());
    eval.add_stall_budget(sample_stall_budget());
    eval.add_policy(sample_policy_entry());
    assert_eq!(eval.alignment_entry_count(), 1);
    assert_eq!(eval.stall_budget_count(), 1);
    assert_eq!(eval.policy_count(), 1);
}

#[test]
fn enrichment_evaluator_clear() {
    let config = GovernanceConfig::default();
    let mut eval = GovernanceEvaluator::new(config, epoch(1));
    eval.add_alignment(sample_alignment_entry());
    eval.add_stall_budget(sample_stall_budget());
    eval.add_policy(sample_policy_entry());
    eval.clear();
    assert_eq!(eval.alignment_entry_count(), 0);
    assert_eq!(eval.stall_budget_count(), 0);
    assert_eq!(eval.policy_count(), 0);
}

#[test]
fn enrichment_evaluator_total_waste() {
    let mut eval = GovernanceEvaluator::with_defaults(epoch(1));
    eval.add_alignment(AlignmentEntry::new(
        "f1",
        LayoutStrategy::LoopAlignment,
        64,
        50,
        100,
        10,
    ));
    eval.add_alignment(AlignmentEntry::new(
        "f2",
        LayoutStrategy::NopPadding,
        32,
        40,
        80,
        20,
    ));
    assert_eq!(eval.total_waste_bytes(), 30);
}

#[test]
fn enrichment_evaluator_present_strategies() {
    let mut eval = GovernanceEvaluator::with_defaults(epoch(1));
    eval.add_alignment(AlignmentEntry::new(
        "f1",
        LayoutStrategy::LoopAlignment,
        64,
        50,
        100,
        0,
    ));
    eval.add_alignment(AlignmentEntry::new(
        "f2",
        LayoutStrategy::HotColdSplit,
        64,
        30,
        100,
        0,
    ));
    let strategies = eval.present_strategies();
    assert!(strategies.contains(&LayoutStrategy::LoopAlignment));
    assert!(strategies.contains(&LayoutStrategy::HotColdSplit));
}

#[test]
fn enrichment_evaluator_evaluate_increments_count() {
    let config = GovernanceConfig::default();
    let mut eval = GovernanceEvaluator::new(config, epoch(1));
    eval.add_alignment(sample_alignment_entry());
    eval.add_stall_budget(sample_stall_budget());
    assert_eq!(eval.evaluation_count(), 0);
    let _ = eval.evaluate();
    assert_eq!(eval.evaluation_count(), 1);
    let _ = eval.evaluate();
    assert_eq!(eval.evaluation_count(), 2);
}

#[test]
fn enrichment_evaluator_receipt_is_clean_pass() {
    let config = GovernanceConfig {
        fail_closed_on_empty: false,
        ..Default::default()
    };
    let mut eval = GovernanceEvaluator::new(config, epoch(1));
    eval.add_alignment(sample_alignment_entry());
    eval.add_stall_budget(sample_stall_budget());
    let receipt = eval.evaluate();
    assert!(receipt.is_clean());
    assert_eq!(receipt.violation_count(), 0);
}

#[test]
fn enrichment_evaluator_empty_fail_closed() {
    let config = GovernanceConfig::default();
    let mut eval = GovernanceEvaluator::new(config, epoch(1));
    let receipt = eval.evaluate();
    assert!(!receipt.is_clean());
    assert!(
        receipt
            .violations
            .iter()
            .any(|v| matches!(v, ViolationKind::EmptyEvaluation))
    );
}

// -----------------------------------------------------------------------
// Free functions
// -----------------------------------------------------------------------

#[test]
fn enrichment_compute_improvement_50_percent() {
    let imp = compute_improvement(100, 50);
    assert_eq!(imp, 500_000); // 50% improvement
}

#[test]
fn enrichment_compute_improvement_zero_baseline() {
    let imp = compute_improvement(0, 50);
    assert_eq!(imp, 0);
}

#[test]
fn enrichment_compute_improvement_regression() {
    let imp = compute_improvement(100, 150);
    assert!(imp < 0);
}

#[test]
fn enrichment_is_valid_alignment_bytes_powers() {
    assert!(is_valid_alignment_bytes(1));
    assert!(is_valid_alignment_bytes(2));
    assert!(is_valid_alignment_bytes(64));
    assert!(is_valid_alignment_bytes(4096));
    assert!(!is_valid_alignment_bytes(0));
    assert!(!is_valid_alignment_bytes(3));
    assert!(!is_valid_alignment_bytes(6));
}

#[test]
fn enrichment_compute_coverage_ratio_full() {
    let covered = hw_set(&["a", "b", "c"]);
    let known = hw_set(&["a", "b", "c"]);
    assert_eq!(compute_coverage_ratio(&covered, &known), FIXED_ONE);
}

#[test]
fn enrichment_compute_coverage_ratio_half() {
    let covered = hw_set(&["a"]);
    let known = hw_set(&["a", "b"]);
    assert_eq!(compute_coverage_ratio(&covered, &known), 500_000);
}

#[test]
fn enrichment_compute_coverage_ratio_empty_known() {
    let covered = hw_set(&[]);
    let known = hw_set(&[]);
    assert_eq!(compute_coverage_ratio(&covered, &known), FIXED_ONE);
}

#[test]
fn enrichment_should_rollback_with_regression() {
    let policy = LayoutPolicyEntry::new(
        LayoutStrategy::LoopAlignment,
        hw_set(&["zen4"]),
        false,
        true,
        10_000,
    );
    assert!(should_rollback(&policy, -5_000));
}

#[test]
fn enrichment_should_rollback_without_flag() {
    let policy = LayoutPolicyEntry::new(
        LayoutStrategy::LoopAlignment,
        hw_set(&["zen4"]),
        false,
        false,
        10_000,
    );
    assert!(!should_rollback(&policy, -5_000));
}

#[test]
fn enrichment_total_stall_overshoot_none() {
    let budgets = [
        StallBudget::new(StallCategory::BranchMispredict, 1000, 800),
        StallBudget::new(StallCategory::DecodeBubble, 500, 400),
    ];
    assert_eq!(total_stall_overshoot(&budgets), 0);
}

#[test]
fn enrichment_total_stall_overshoot_some() {
    let budgets = [
        StallBudget::new(StallCategory::BranchMispredict, 1000, 1500),
        StallBudget::new(StallCategory::DecodeBubble, 500, 600),
    ];
    assert_eq!(total_stall_overshoot(&budgets), 700_000); // (500/1000 + 100/500) in millionths
}

#[test]
fn enrichment_missing_strategies_none() {
    let required: BTreeSet<LayoutStrategy> = [LayoutStrategy::HotColdSplit].into_iter().collect();
    let present: BTreeSet<LayoutStrategy> = [LayoutStrategy::HotColdSplit].into_iter().collect();
    assert!(missing_strategies(&required, &present).is_empty());
}

#[test]
fn enrichment_missing_strategies_some() {
    let required: BTreeSet<LayoutStrategy> =
        [LayoutStrategy::HotColdSplit, LayoutStrategy::LoopAlignment]
            .into_iter()
            .collect();
    let present: BTreeSet<LayoutStrategy> = [LayoutStrategy::HotColdSplit].into_iter().collect();
    let missing = missing_strategies(&required, &present);
    assert_eq!(missing.len(), 1);
    assert!(missing.contains(&LayoutStrategy::LoopAlignment));
}

// -----------------------------------------------------------------------
// JSON field-name stability
// -----------------------------------------------------------------------

#[test]
fn enrichment_alignment_entry_json_field_names() {
    let entry = sample_alignment_entry();
    let json = serde_json::to_string(&entry).unwrap();
    assert!(json.contains("\"function_id\""));
    assert!(json.contains("\"strategy\""));
    assert!(json.contains("\"alignment_bytes\""));
    assert!(json.contains("\"improvement_millionths\""));
    assert!(json.contains("\"waste_bytes\""));
    assert!(json.contains("\"content_hash\""));
}

#[test]
fn enrichment_governance_receipt_json_field_names() {
    let mut eval = GovernanceEvaluator::with_defaults(epoch(1));
    eval.add_alignment(sample_alignment_entry());
    let receipt = eval.evaluate();
    let json = serde_json::to_string(&receipt).unwrap();
    assert!(json.contains("\"verdict\""));
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"violations\""));
    assert!(json.contains("\"content_hash\""));
}

// -----------------------------------------------------------------------
// Determinism
// -----------------------------------------------------------------------

#[test]
fn enrichment_alignment_entry_content_hash_determinism() {
    let a = sample_alignment_entry();
    let b = sample_alignment_entry();
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn enrichment_receipt_determinism_20_runs() {
    let config = GovernanceConfig {
        fail_closed_on_empty: false,
        ..Default::default()
    };
    let mut first_hash = None;
    for _ in 0..20 {
        let mut eval = GovernanceEvaluator::new(config.clone(), epoch(1));
        eval.add_alignment(sample_alignment_entry());
        eval.add_stall_budget(sample_stall_budget());
        let receipt = eval.evaluate();
        if let Some(ref h) = first_hash {
            assert_eq!(receipt.content_hash, *h);
        } else {
            first_hash = Some(receipt.content_hash);
        }
    }
}
