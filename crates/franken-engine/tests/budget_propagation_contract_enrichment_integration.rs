#![forbid(unsafe_code)]

//! Enrichment integration tests for `budget_propagation_contract` module.
//!
//! Covers: BudgetBoundaryKind, BudgetDerivationStrategy, CleanupBudgetPolicy,
//! CleanupBudgetAllocation, ChildBudgetRule, BudgetPropagationError,
//! BudgetPropagationEvent, BudgetDerivationResult, BudgetPropagationPolicy,
//! BudgetPropagationValidator, BudgetPropagationReport.
//!
//! Focus: cross-cutting lifecycle scenarios, invariant stress testing,
//! serde roundtrips, Display uniqueness, determinism, boundary condition
//! coverage that goes beyond the unit tests.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use frankenengine_engine::budget_propagation_contract::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ── helpers ──────────────────────────────────────────────────────────────

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn default_validator() -> BudgetPropagationValidator {
    BudgetPropagationValidator::with_defaults()
}

fn empty_policy() -> BudgetPropagationPolicy {
    BudgetPropagationPolicy {
        child_rules: BTreeMap::new(),
        cleanup_policy: CleanupBudgetPolicy::default(),
        fail_closed_on_missing_rule: true,
        min_parent_reserve_ms: 0,
        epoch: epoch(1),
    }
}

// ── BudgetBoundaryKind ──────────────────────────────────────────────────

#[test]
fn enrichment_boundary_kind_as_str_unique() {
    let kinds = [
        BudgetBoundaryKind::ParentToChildExtension,
        BudgetBoundaryKind::ParentToChildSession,
        BudgetBoundaryKind::ParentToChildDelegate,
        BudgetBoundaryKind::ExecutionToCleanup,
        BudgetBoundaryKind::CleanupToFinalize,
        BudgetBoundaryKind::OrchestratorToCellClose,
    ];
    let labels: BTreeSet<&str> = kinds.iter().map(|k| k.as_str()).collect();
    assert_eq!(labels.len(), 6, "all boundary as_str labels must be unique");
}

#[test]
fn enrichment_boundary_kind_as_str_snake_case() {
    let kinds = [
        BudgetBoundaryKind::ParentToChildExtension,
        BudgetBoundaryKind::ParentToChildSession,
        BudgetBoundaryKind::ParentToChildDelegate,
        BudgetBoundaryKind::ExecutionToCleanup,
        BudgetBoundaryKind::CleanupToFinalize,
        BudgetBoundaryKind::OrchestratorToCellClose,
    ];
    for kind in kinds {
        let label = kind.as_str();
        assert!(
            label.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "as_str should be snake_case: {}",
            label
        );
    }
}

#[test]
fn enrichment_boundary_kind_serde_roundtrip_all_variants() {
    let kinds = [
        BudgetBoundaryKind::ParentToChildExtension,
        BudgetBoundaryKind::ParentToChildSession,
        BudgetBoundaryKind::ParentToChildDelegate,
        BudgetBoundaryKind::ExecutionToCleanup,
        BudgetBoundaryKind::CleanupToFinalize,
        BudgetBoundaryKind::OrchestratorToCellClose,
    ];
    for kind in kinds {
        let json = serde_json::to_string(&kind).unwrap();
        let back: BudgetBoundaryKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back, "serde roundtrip failed for {:?}", kind);
    }
}

#[test]
fn enrichment_boundary_kind_is_child_derivation_partition() {
    let all_kinds = [
        BudgetBoundaryKind::ParentToChildExtension,
        BudgetBoundaryKind::ParentToChildSession,
        BudgetBoundaryKind::ParentToChildDelegate,
        BudgetBoundaryKind::ExecutionToCleanup,
        BudgetBoundaryKind::CleanupToFinalize,
        BudgetBoundaryKind::OrchestratorToCellClose,
    ];
    let child_count = all_kinds.iter().filter(|k| k.is_child_derivation()).count();
    let phase_count = all_kinds.iter().filter(|k| !k.is_child_derivation()).count();
    assert_eq!(child_count, 3, "exactly 3 child derivation boundaries");
    assert_eq!(phase_count, 3, "exactly 3 phase boundaries");
}

#[test]
fn enrichment_boundary_kind_debug_unique() {
    let kinds = [
        BudgetBoundaryKind::ParentToChildExtension,
        BudgetBoundaryKind::ParentToChildSession,
        BudgetBoundaryKind::ParentToChildDelegate,
        BudgetBoundaryKind::ExecutionToCleanup,
        BudgetBoundaryKind::CleanupToFinalize,
        BudgetBoundaryKind::OrchestratorToCellClose,
    ];
    let debugs: BTreeSet<String> = kinds.iter().map(|k| format!("{:?}", k)).collect();
    assert_eq!(debugs.len(), 6);
}

// ── BudgetDerivationStrategy ────────────────────────────────────────────

#[test]
fn enrichment_strategy_serde_roundtrip_all_variants() {
    let strategies = [
        BudgetDerivationStrategy::FractionOfRemaining {
            fraction_millionths: 750_000,
        },
        BudgetDerivationStrategy::FixedAmount { amount_ms: 2_500 },
        BudgetDerivationStrategy::BoundedFraction {
            fraction_millionths: 200_000,
            min_ms: 100,
            max_ms: 10_000,
        },
        BudgetDerivationStrategy::AllRemaining,
    ];
    for strat in &strategies {
        let json = serde_json::to_string(strat).unwrap();
        let back: BudgetDerivationStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(*strat, back, "serde roundtrip failed for {:?}", strat);
    }
}

#[test]
fn enrichment_fraction_derivation_exact_percentages() {
    // 25%
    let strat = BudgetDerivationStrategy::FractionOfRemaining {
        fraction_millionths: 250_000,
    };
    assert_eq!(strat.derive(10_000), 2_500);
    assert_eq!(strat.derive(4_000), 1_000);
    assert_eq!(strat.derive(0), 0);
}

#[test]
fn enrichment_fraction_derivation_rounding_down() {
    // 33.333...% => 333_333 millionths
    let strat = BudgetDerivationStrategy::FractionOfRemaining {
        fraction_millionths: 333_333,
    };
    // 333_333 * 10 / 1_000_000 = 3 (truncated)
    let result = strat.derive(10);
    assert_eq!(result, 3);
}

#[test]
fn enrichment_fraction_derivation_never_exceeds_parent() {
    let strat = BudgetDerivationStrategy::FractionOfRemaining {
        fraction_millionths: 2_000_000, // 200% should still cap at parent
    };
    for parent in [1, 10, 100, 1_000, 10_000, u64::MAX / 4] {
        let derived = strat.derive(parent);
        assert!(
            derived <= parent,
            "fraction 200% derived {} > parent {}",
            derived,
            parent
        );
    }
}

#[test]
fn enrichment_fixed_amount_at_exact_parent() {
    let strat = BudgetDerivationStrategy::FixedAmount { amount_ms: 5_000 };
    assert_eq!(strat.derive(5_000), 5_000);
}

#[test]
fn enrichment_fixed_amount_zero_amount() {
    let strat = BudgetDerivationStrategy::FixedAmount { amount_ms: 0 };
    assert_eq!(strat.derive(10_000), 0);
    assert_eq!(strat.derive(0), 0);
}

#[test]
fn enrichment_bounded_fraction_min_exceeds_parent_capped() {
    let strat = BudgetDerivationStrategy::BoundedFraction {
        fraction_millionths: 100_000, // 10%
        min_ms: 1_000,
        max_ms: 5_000,
    };
    // 10% of 500 = 50, floor to 1000, but parent is 500 => capped at 500
    assert_eq!(strat.derive(500), 500);
}

#[test]
fn enrichment_bounded_fraction_zero_parent_zero_result() {
    let strat = BudgetDerivationStrategy::BoundedFraction {
        fraction_millionths: 500_000,
        min_ms: 100,
        max_ms: 5_000,
    };
    assert_eq!(strat.derive(0), 0);
}

#[test]
fn enrichment_all_remaining_identity() {
    let strat = BudgetDerivationStrategy::AllRemaining;
    for parent in [0, 1, 100, 10_000, 1_000_000, u64::MAX / 2] {
        assert_eq!(strat.derive(parent), parent);
    }
}

#[test]
fn enrichment_strategy_derive_deterministic() {
    let strat = BudgetDerivationStrategy::FractionOfRemaining {
        fraction_millionths: 800_000,
    };
    let a = strat.derive(12_345);
    let b = strat.derive(12_345);
    assert_eq!(a, b, "derivation must be deterministic");
}

// ── CleanupBudgetPolicy ─────────────────────────────────────────────────

#[test]
fn enrichment_cleanup_policy_default_values() {
    let policy = CleanupBudgetPolicy::default();
    assert!(policy.carved_from_parent);
    assert_eq!(policy.finalize_budget_ms, 500);
    // drain_strategy should be BoundedFraction with 10% / [50, 30000]
    if let BudgetDerivationStrategy::BoundedFraction {
        fraction_millionths,
        min_ms,
        max_ms,
    } = policy.drain_strategy
    {
        assert_eq!(fraction_millionths, 100_000);
        assert_eq!(min_ms, 50);
        assert_eq!(max_ms, 30_000);
    } else {
        panic!("expected BoundedFraction for default drain_strategy");
    }
}

#[test]
fn enrichment_cleanup_allocation_drain_plus_finalize_equals_total() {
    let policy = CleanupBudgetPolicy::default();
    for parent in [100, 500, 1_000, 10_000, 100_000] {
        let alloc = policy.compute_allocation(parent);
        assert_eq!(
            alloc.total_cleanup_ms,
            alloc.drain_budget_ms + alloc.finalize_budget_ms,
            "total != drain + finalize for parent={}",
            parent
        );
    }
}

#[test]
fn enrichment_cleanup_allocation_never_exceeds_parent_when_carved() {
    let policy = CleanupBudgetPolicy::default();
    for parent in [0, 1, 10, 50, 100, 500, 1_000, 10_000, 100_000] {
        let alloc = policy.compute_allocation(parent);
        if alloc.carved_from_parent {
            assert!(
                alloc.total_cleanup_ms <= parent,
                "cleanup {} exceeds parent {} when carved",
                alloc.total_cleanup_ms,
                parent
            );
        }
    }
}

#[test]
fn enrichment_cleanup_allocation_parent_remaining_consistent() {
    let policy = CleanupBudgetPolicy::default();
    let parent = 10_000;
    let alloc = policy.compute_allocation(parent);
    assert_eq!(
        alloc.parent_remaining_after_ms,
        parent - alloc.total_cleanup_ms,
        "parent_remaining_after = parent - total_cleanup when carved"
    );
}

#[test]
fn enrichment_cleanup_allocation_not_carved_preserves_parent() {
    let policy = CleanupBudgetPolicy {
        drain_strategy: BudgetDerivationStrategy::FixedAmount { amount_ms: 1_000 },
        finalize_budget_ms: 500,
        carved_from_parent: false,
    };
    let alloc = policy.compute_allocation(5_000);
    assert_eq!(alloc.parent_remaining_after_ms, 5_000);
    assert!(!alloc.carved_from_parent);
}

#[test]
fn enrichment_cleanup_allocation_serde_roundtrip() {
    let policy = CleanupBudgetPolicy::default();
    let alloc = policy.compute_allocation(25_000);
    let json = serde_json::to_string(&alloc).unwrap();
    let back: CleanupBudgetAllocation = serde_json::from_str(&json).unwrap();
    assert_eq!(alloc, back);
}

#[test]
fn enrichment_cleanup_policy_serde_roundtrip() {
    let policy = CleanupBudgetPolicy {
        drain_strategy: BudgetDerivationStrategy::FixedAmount { amount_ms: 333 },
        finalize_budget_ms: 77,
        carved_from_parent: false,
    };
    let json = serde_json::to_string(&policy).unwrap();
    let back: CleanupBudgetPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

#[test]
fn enrichment_cleanup_finalize_capped_when_drain_consumes_most() {
    let policy = CleanupBudgetPolicy {
        drain_strategy: BudgetDerivationStrategy::FixedAmount { amount_ms: 900 },
        finalize_budget_ms: 500,
        carved_from_parent: true,
    };
    let alloc = policy.compute_allocation(1_000);
    // drain=900, remaining for finalize = 100, finalize should be capped to 100
    assert_eq!(alloc.drain_budget_ms, 900);
    assert_eq!(alloc.finalize_budget_ms, 100);
    assert_eq!(alloc.total_cleanup_ms, 1_000);
    assert_eq!(alloc.parent_remaining_after_ms, 0);
}

// ── ChildBudgetRule ─────────────────────────────────────────────────────

#[test]
fn enrichment_child_rule_extension_defaults() {
    let rule = ChildBudgetRule::default_extension();
    assert_eq!(
        rule.boundary_kind,
        BudgetBoundaryKind::ParentToChildExtension
    );
    assert!(rule.carved_from_parent);
    assert_eq!(rule.minimum_ms, 10);
}

#[test]
fn enrichment_child_rule_session_defaults() {
    let rule = ChildBudgetRule::default_session();
    assert_eq!(rule.boundary_kind, BudgetBoundaryKind::ParentToChildSession);
    assert!(rule.carved_from_parent);
    assert_eq!(rule.minimum_ms, 10);
}

#[test]
fn enrichment_child_rule_delegate_defaults() {
    let rule = ChildBudgetRule::default_delegate();
    assert_eq!(
        rule.boundary_kind,
        BudgetBoundaryKind::ParentToChildDelegate
    );
    assert!(rule.carved_from_parent);
    // delegate uses 50% fraction
    assert_eq!(rule.derivation.derive(10_000), 5_000);
}

#[test]
fn enrichment_child_rule_serde_roundtrip_all_defaults() {
    let rules = [
        ChildBudgetRule::default_extension(),
        ChildBudgetRule::default_session(),
        ChildBudgetRule::default_delegate(),
    ];
    for rule in &rules {
        let json = serde_json::to_string(rule).unwrap();
        let back: ChildBudgetRule = serde_json::from_str(&json).unwrap();
        assert_eq!(*rule, back);
    }
}

#[test]
fn enrichment_child_rule_extension_budget_80_percent() {
    let rule = ChildBudgetRule::default_extension();
    // BoundedFraction with 80% fraction, min=10, max=30000
    let derived = rule.derivation.derive(10_000);
    assert_eq!(derived, 8_000);
}

#[test]
fn enrichment_child_rule_session_budget_80_percent() {
    let rule = ChildBudgetRule::default_session();
    // FractionOfRemaining with 80%
    let derived = rule.derivation.derive(10_000);
    assert_eq!(derived, 8_000);
}

// ── BudgetPropagationError ──────────────────────────────────────────────

#[test]
fn enrichment_error_display_unique_across_variants() {
    let errors = [
        BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 5,
            minimum_ms: 10,
            parent_remaining_ms: 20,
        },
        BudgetPropagationError::NoRuleForBoundary {
            boundary: BudgetBoundaryKind::CleanupToFinalize,
        },
        BudgetPropagationError::ParentExhausted {
            boundary: BudgetBoundaryKind::ParentToChildSession,
            parent_remaining_ms: 0,
        },
        BudgetPropagationError::CleanupExceedsParent {
            cleanup_total_ms: 5_000,
            parent_remaining_ms: 1_000,
        },
        BudgetPropagationError::ChildExceedsParent {
            child_ms: 200,
            parent_ms: 100,
        },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), errors.len(), "all error Display messages must be unique");
}

#[test]
fn enrichment_error_display_contains_boundary_label() {
    let err = BudgetPropagationError::InsufficientBudget {
        boundary: BudgetBoundaryKind::ParentToChildDelegate,
        derived_ms: 3,
        minimum_ms: 10,
        parent_remaining_ms: 15,
    };
    let msg = err.to_string();
    assert!(
        msg.contains(BudgetBoundaryKind::ParentToChildDelegate.as_str()),
        "error Display should contain boundary label"
    );
}

#[test]
fn enrichment_error_display_no_rule_mentions_boundary() {
    let err = BudgetPropagationError::NoRuleForBoundary {
        boundary: BudgetBoundaryKind::OrchestratorToCellClose,
    };
    let msg = err.to_string();
    assert!(msg.contains("orchestrator_to_cell_close"));
}

#[test]
fn enrichment_error_display_parent_exhausted_contains_remaining() {
    let err = BudgetPropagationError::ParentExhausted {
        boundary: BudgetBoundaryKind::ParentToChildExtension,
        parent_remaining_ms: 0,
    };
    let msg = err.to_string();
    assert!(msg.contains("0ms"));
    assert!(msg.contains("exhausted"));
}

#[test]
fn enrichment_error_display_cleanup_exceeds_parent() {
    let err = BudgetPropagationError::CleanupExceedsParent {
        cleanup_total_ms: 5_000,
        parent_remaining_ms: 1_000,
    };
    let msg = err.to_string();
    assert!(msg.contains("5000ms"));
    assert!(msg.contains("1000ms"));
}

#[test]
fn enrichment_error_display_child_exceeds_parent() {
    let err = BudgetPropagationError::ChildExceedsParent {
        child_ms: 200,
        parent_ms: 100,
    };
    let msg = err.to_string();
    assert!(msg.contains("200ms"));
    assert!(msg.contains("100ms"));
}

#[test]
fn enrichment_error_serde_roundtrip_all_variants() {
    let errors = [
        BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 5,
            minimum_ms: 10,
            parent_remaining_ms: 20,
        },
        BudgetPropagationError::NoRuleForBoundary {
            boundary: BudgetBoundaryKind::OrchestratorToCellClose,
        },
        BudgetPropagationError::ParentExhausted {
            boundary: BudgetBoundaryKind::ParentToChildSession,
            parent_remaining_ms: 0,
        },
        BudgetPropagationError::CleanupExceedsParent {
            cleanup_total_ms: 5_000,
            parent_remaining_ms: 1_000,
        },
        BudgetPropagationError::ChildExceedsParent {
            child_ms: 200,
            parent_ms: 100,
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: BudgetPropagationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back, "serde roundtrip failed for {:?}", err);
    }
}

// ── BudgetPropagationEvent ──────────────────────────────────────────────

#[test]
fn enrichment_event_fields_populated_on_success() {
    let mut v = default_validator();
    let _ = v
        .derive_child_budget("parent-1", "child-1", 10_000, BudgetBoundaryKind::ParentToChildExtension)
        .unwrap();
    let events = v.events();
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!(e.parent_trace_id, "parent-1");
    assert_eq!(e.child_trace_id, Some("child-1".to_owned()));
    assert_eq!(e.boundary_kind, BudgetBoundaryKind::ParentToChildExtension);
    assert_eq!(e.parent_before_ms, 10_000);
    assert!(e.derived_ms > 0);
    assert!(e.success);
    assert!(e.error.is_none());
    assert_eq!(e.sequence, 1);
}

#[test]
fn enrichment_event_fields_populated_on_failure() {
    let mut v = default_validator();
    let _ = v.derive_child_budget("parent-1", "child-1", 0, BudgetBoundaryKind::ParentToChildExtension);
    let events = v.events();
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert!(!e.success);
    assert!(e.error.is_some());
    assert_eq!(e.derived_ms, 0);
    assert_eq!(e.strategy_used, "failed");
}

#[test]
fn enrichment_event_cleanup_has_no_child_trace_id() {
    let mut v = default_validator();
    let _ = v.validate_cleanup("parent-1", 10_000).unwrap();
    let events = v.events();
    assert_eq!(events.len(), 1);
    let e = &events[0];
    // cleanup records empty string child_trace_id which becomes None
    assert!(e.child_trace_id.is_none());
    assert_eq!(e.boundary_kind, BudgetBoundaryKind::ExecutionToCleanup);
    assert_eq!(e.strategy_used, "cleanup_allocation");
}

#[test]
fn enrichment_event_serde_roundtrip_success_event() {
    let mut v = default_validator();
    let _ = v
        .derive_child_budget("p", "c", 10_000, BudgetBoundaryKind::ParentToChildSession)
        .unwrap();
    let event = &v.events()[0];
    let json = serde_json::to_string(event).unwrap();
    let back: BudgetPropagationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(*event, back);
}

#[test]
fn enrichment_event_serde_roundtrip_failure_event() {
    let mut v = default_validator();
    let _ = v.derive_child_budget("p", "c", 0, BudgetBoundaryKind::ParentToChildDelegate);
    let event = &v.events()[0];
    let json = serde_json::to_string(event).unwrap();
    let back: BudgetPropagationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(*event, back);
}

// ── BudgetDerivationResult ──────────────────────────────────────────────

#[test]
fn enrichment_derivation_result_serde_roundtrip() {
    let result = BudgetDerivationResult {
        derived_budget_ms: 4_000,
        parent_remaining_after_ms: 6_000,
        boundary_kind: BudgetBoundaryKind::ParentToChildSession,
        carved_from_parent: true,
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: BudgetDerivationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn enrichment_derivation_result_not_carved() {
    let result = BudgetDerivationResult {
        derived_budget_ms: 5_000,
        parent_remaining_after_ms: 10_000,
        boundary_kind: BudgetBoundaryKind::ParentToChildDelegate,
        carved_from_parent: false,
    };
    assert!(!result.carved_from_parent);
    assert_eq!(result.parent_remaining_after_ms, 10_000);
}

// ── BudgetPropagationPolicy ─────────────────────────────────────────────

#[test]
fn enrichment_policy_default_has_three_child_rules() {
    let policy = BudgetPropagationPolicy::default();
    assert_eq!(policy.child_rules.len(), 3);
    assert!(policy.rule_for(BudgetBoundaryKind::ParentToChildExtension).is_some());
    assert!(policy.rule_for(BudgetBoundaryKind::ParentToChildSession).is_some());
    assert!(policy.rule_for(BudgetBoundaryKind::ParentToChildDelegate).is_some());
}

#[test]
fn enrichment_policy_default_no_phase_rules() {
    let policy = BudgetPropagationPolicy::default();
    assert!(policy.rule_for(BudgetBoundaryKind::ExecutionToCleanup).is_none());
    assert!(policy.rule_for(BudgetBoundaryKind::CleanupToFinalize).is_none());
    assert!(policy.rule_for(BudgetBoundaryKind::OrchestratorToCellClose).is_none());
}

#[test]
fn enrichment_policy_default_fail_closed() {
    let policy = BudgetPropagationPolicy::default();
    assert!(policy.fail_closed_on_missing_rule);
}

#[test]
fn enrichment_policy_default_min_reserve() {
    let policy = BudgetPropagationPolicy::default();
    assert_eq!(policy.min_parent_reserve_ms, 5);
}

#[test]
fn enrichment_policy_default_epoch() {
    let policy = BudgetPropagationPolicy::default();
    assert_eq!(policy.epoch, epoch(1));
}

#[test]
fn enrichment_policy_serde_roundtrip_default() {
    let policy = BudgetPropagationPolicy::default();
    let json = serde_json::to_string(&policy).unwrap();
    let back: BudgetPropagationPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

#[test]
fn enrichment_policy_serde_roundtrip_custom() {
    let mut rules = BTreeMap::new();
    let rule = ChildBudgetRule {
        boundary_kind: BudgetBoundaryKind::ParentToChildExtension,
        derivation: BudgetDerivationStrategy::FixedAmount { amount_ms: 777 },
        minimum_ms: 50,
        carved_from_parent: false,
    };
    rules.insert(
        BudgetBoundaryKind::ParentToChildExtension.as_str().to_owned(),
        rule,
    );
    let policy = BudgetPropagationPolicy {
        child_rules: rules,
        cleanup_policy: CleanupBudgetPolicy {
            drain_strategy: BudgetDerivationStrategy::AllRemaining,
            finalize_budget_ms: 0,
            carved_from_parent: false,
        },
        fail_closed_on_missing_rule: false,
        min_parent_reserve_ms: 1_000,
        epoch: epoch(99),
    };
    let json = serde_json::to_string(&policy).unwrap();
    let back: BudgetPropagationPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

// ── BudgetPropagationValidator ──────────────────────────────────────────

#[test]
fn enrichment_validator_with_defaults_starts_clean() {
    let v = default_validator();
    assert!(!v.has_violations());
    assert!(v.violations().is_empty());
    assert!(v.events().is_empty());
}

#[test]
fn enrichment_validator_sequence_numbers_monotonic() {
    let mut v = default_validator();
    let _ = v.derive_child_budget("p", "c1", 10_000, BudgetBoundaryKind::ParentToChildExtension);
    let _ = v.derive_child_budget("p", "c2", 8_000, BudgetBoundaryKind::ParentToChildSession);
    let _ = v.derive_child_budget("p", "c3", 6_000, BudgetBoundaryKind::ParentToChildDelegate);
    let _ = v.validate_cleanup("p", 4_000);

    let events = v.events();
    for window in events.windows(2) {
        assert!(
            window[1].sequence > window[0].sequence,
            "sequences not monotonic: {} vs {}",
            window[0].sequence,
            window[1].sequence
        );
    }
}

#[test]
fn enrichment_validator_extension_carves_from_parent() {
    let mut v = default_validator();
    let r = v
        .derive_child_budget("p", "c", 10_000, BudgetBoundaryKind::ParentToChildExtension)
        .unwrap();
    assert!(r.carved_from_parent);
    assert!(r.derived_budget_ms > 0);
    assert!(r.parent_remaining_after_ms < 10_000);
    assert_eq!(
        r.derived_budget_ms + r.parent_remaining_after_ms,
        10_000,
        "derived + remaining must equal original parent"
    );
}

#[test]
fn enrichment_validator_session_carves_from_parent() {
    let mut v = default_validator();
    let r = v
        .derive_child_budget("p", "c", 10_000, BudgetBoundaryKind::ParentToChildSession)
        .unwrap();
    assert!(r.carved_from_parent);
    assert_eq!(r.derived_budget_ms + r.parent_remaining_after_ms, 10_000);
}

#[test]
fn enrichment_validator_delegate_carves_from_parent() {
    let mut v = default_validator();
    let r = v
        .derive_child_budget("p", "c", 10_000, BudgetBoundaryKind::ParentToChildDelegate)
        .unwrap();
    assert!(r.carved_from_parent);
    assert_eq!(r.derived_budget_ms + r.parent_remaining_after_ms, 10_000);
}

#[test]
fn enrichment_validator_parent_exhausted_on_zero_budget() {
    let mut v = default_validator();
    let err = v
        .derive_child_budget("p", "c", 0, BudgetBoundaryKind::ParentToChildExtension)
        .unwrap_err();
    assert!(matches!(err, BudgetPropagationError::ParentExhausted { .. }));
    assert!(v.has_violations());
    assert_eq!(v.violations().len(), 1);
}

#[test]
fn enrichment_validator_no_rule_fail_closed() {
    let mut v = BudgetPropagationValidator::new(empty_policy());
    let err = v
        .derive_child_budget("p", "c", 10_000, BudgetBoundaryKind::ParentToChildDelegate)
        .unwrap_err();
    assert!(matches!(err, BudgetPropagationError::NoRuleForBoundary { .. }));
}

#[test]
fn enrichment_validator_no_rule_fail_open_uses_all_remaining() {
    let policy = BudgetPropagationPolicy {
        child_rules: BTreeMap::new(),
        cleanup_policy: CleanupBudgetPolicy::default(),
        fail_closed_on_missing_rule: false,
        min_parent_reserve_ms: 0,
        epoch: epoch(1),
    };
    let mut v = BudgetPropagationValidator::new(policy);
    let r = v
        .derive_child_budget("p", "c", 7_000, BudgetBoundaryKind::ParentToChildExtension)
        .unwrap();
    assert_eq!(r.derived_budget_ms, 7_000);
    assert_eq!(r.parent_remaining_after_ms, 0);
    assert!(!v.has_violations());
}

#[test]
fn enrichment_validator_fail_open_strategy_is_all_remaining_fallback() {
    let policy = BudgetPropagationPolicy {
        child_rules: BTreeMap::new(),
        cleanup_policy: CleanupBudgetPolicy::default(),
        fail_closed_on_missing_rule: false,
        min_parent_reserve_ms: 0,
        epoch: epoch(1),
    };
    let mut v = BudgetPropagationValidator::new(policy);
    let _ = v
        .derive_child_budget("p", "c", 5_000, BudgetBoundaryKind::ParentToChildSession)
        .unwrap();
    let events = v.events();
    assert_eq!(events[0].strategy_used, "all_remaining_fallback");
}

#[test]
fn enrichment_validator_insufficient_budget_below_minimum() {
    let mut v = default_validator();
    // 1ms parent: 80% = 0ms, minimum=10ms => InsufficientBudget
    let err = v
        .derive_child_budget("p", "c", 1, BudgetBoundaryKind::ParentToChildExtension)
        .unwrap_err();
    assert!(matches!(err, BudgetPropagationError::InsufficientBudget { .. }));
}

#[test]
fn enrichment_validator_reserve_enforcement_reduces_child() {
    let policy = BudgetPropagationPolicy {
        min_parent_reserve_ms: 8_000,
        ..Default::default()
    };
    let mut v = BudgetPropagationValidator::new(policy);
    let r = v
        .derive_child_budget("p", "c", 10_000, BudgetBoundaryKind::ParentToChildExtension)
        .unwrap();
    // reserve=8k, parent=10k, so max child = 2k
    assert!(r.derived_budget_ms <= 2_000);
    assert!(r.parent_remaining_after_ms >= 8_000);
}

#[test]
fn enrichment_validator_reserve_enforcement_strategy_label() {
    let policy = BudgetPropagationPolicy {
        min_parent_reserve_ms: 9_000,
        ..Default::default()
    };
    let mut v = BudgetPropagationValidator::new(policy);
    let _ = v
        .derive_child_budget("p", "c", 10_000, BudgetBoundaryKind::ParentToChildExtension)
        .unwrap();
    assert_eq!(v.events()[0].strategy_used, "bounded_by_reserve");
}

#[test]
fn enrichment_validator_reserve_too_high_fails() {
    let policy = BudgetPropagationPolicy {
        min_parent_reserve_ms: 9_995, // leaves only 5ms, below minimum=10ms
        ..Default::default()
    };
    let mut v = BudgetPropagationValidator::new(policy);
    let err = v
        .derive_child_budget("p", "c", 10_000, BudgetBoundaryKind::ParentToChildExtension)
        .unwrap_err();
    assert!(matches!(err, BudgetPropagationError::InsufficientBudget { .. }));
}

#[test]
fn enrichment_validator_cleanup_basic() {
    let mut v = default_validator();
    let alloc = v.validate_cleanup("p", 10_000).unwrap();
    assert!(alloc.total_cleanup_ms > 0);
    assert!(alloc.total_cleanup_ms <= 10_000);
    assert!(alloc.carved_from_parent);
    assert!(!v.has_violations());
}

#[test]
fn enrichment_validator_cleanup_zero_parent_succeeds() {
    let mut v = default_validator();
    let alloc = v.validate_cleanup("p", 0).unwrap();
    assert_eq!(alloc.drain_budget_ms, 0);
    assert_eq!(alloc.finalize_budget_ms, 0);
    assert_eq!(alloc.total_cleanup_ms, 0);
}

#[test]
fn enrichment_validator_serde_roundtrip_with_events() {
    let mut v = default_validator();
    let _ = v.derive_child_budget("p", "c1", 10_000, BudgetBoundaryKind::ParentToChildExtension);
    let _ = v.derive_child_budget("p", "c2", 0, BudgetBoundaryKind::ParentToChildSession);
    let _ = v.validate_cleanup("p", 5_000);

    let json = serde_json::to_string(&v).unwrap();
    let back: BudgetPropagationValidator = serde_json::from_str(&json).unwrap();
    assert_eq!(v.events().len(), back.events().len());
    assert_eq!(v.violations().len(), back.violations().len());
}

// ── BudgetPropagationReport ─────────────────────────────────────────────

#[test]
fn enrichment_report_clean_when_no_violations() {
    let mut v = default_validator();
    let _ = v
        .derive_child_budget("p", "c", 10_000, BudgetBoundaryKind::ParentToChildExtension)
        .unwrap();
    let report = v.build_report();
    assert!(report.is_clean());
    assert_eq!(report.failed_derivations, 0);
    assert!(report.violations.is_empty());
}

#[test]
fn enrichment_report_not_clean_when_violations_present() {
    let mut v = default_validator();
    let _ = v.derive_child_budget("p", "c", 0, BudgetBoundaryKind::ParentToChildExtension);
    let report = v.build_report();
    assert!(!report.is_clean());
    assert_eq!(report.failed_derivations, 1);
    assert!(!report.violations.is_empty());
}

#[test]
fn enrichment_report_total_events_accurate() {
    let mut v = default_validator();
    let _ = v.derive_child_budget("p", "c1", 10_000, BudgetBoundaryKind::ParentToChildExtension);
    let _ = v.derive_child_budget("p", "c2", 8_000, BudgetBoundaryKind::ParentToChildSession);
    let _ = v.derive_child_budget("p", "c3", 0, BudgetBoundaryKind::ParentToChildDelegate);
    let _ = v.validate_cleanup("p", 5_000);

    let report = v.build_report();
    assert_eq!(report.total_events, 4);
    assert_eq!(report.successful_derivations, 3);
    assert_eq!(report.failed_derivations, 1);
}

#[test]
fn enrichment_report_boundary_event_counts_keyed_by_as_str() {
    let mut v = default_validator();
    let _ = v.derive_child_budget("p", "c1", 10_000, BudgetBoundaryKind::ParentToChildExtension);
    let _ = v.derive_child_budget("p", "c2", 8_000, BudgetBoundaryKind::ParentToChildExtension);
    let _ = v.validate_cleanup("p", 6_000);

    let report = v.build_report();
    assert_eq!(
        *report.boundary_event_counts.get("parent_to_child_extension").unwrap(),
        2,
        "two extension events expected"
    );
    assert_eq!(
        *report.boundary_event_counts.get("execution_to_cleanup").unwrap(),
        1,
        "one cleanup event expected"
    );
}

#[test]
fn enrichment_report_total_budget_derived_sums_successes() {
    let mut v = default_validator();
    let r1 = v
        .derive_child_budget("p", "c1", 10_000, BudgetBoundaryKind::ParentToChildExtension)
        .unwrap();
    let r2 = v
        .derive_child_budget("p", "c2", 5_000, BudgetBoundaryKind::ParentToChildSession)
        .unwrap();
    let alloc = v.validate_cleanup("p", 3_000).unwrap();

    let report = v.build_report();
    let expected_total = r1.derived_budget_ms + r2.derived_budget_ms + alloc.total_cleanup_ms;
    assert_eq!(report.total_budget_derived_ms, expected_total);
}

#[test]
fn enrichment_report_epoch_matches_policy_epoch() {
    let policy = BudgetPropagationPolicy {
        epoch: epoch(42),
        ..Default::default()
    };
    let mut v = BudgetPropagationValidator::new(policy);
    let _ = v.derive_child_budget("p", "c", 10_000, BudgetBoundaryKind::ParentToChildExtension);
    let report = v.build_report();
    assert_eq!(report.epoch, epoch(42));
}

#[test]
fn enrichment_report_content_hash_deterministic() {
    let make = || {
        let mut v = default_validator();
        let _ = v.derive_child_budget("p", "c", 10_000, BudgetBoundaryKind::ParentToChildExtension);
        let _ = v.validate_cleanup("p", 8_000);
        v.build_report()
    };
    let r1 = make();
    let r2 = make();
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_report_content_hash_differs_for_different_inputs() {
    let make = |parent: u64| {
        let mut v = default_validator();
        let _ = v.derive_child_budget("p", "c", parent, BudgetBoundaryKind::ParentToChildExtension);
        v.build_report()
    };
    let r1 = make(10_000);
    let r2 = make(20_000);
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_report_serde_roundtrip() {
    let mut v = default_validator();
    let _ = v.derive_child_budget("p", "c1", 10_000, BudgetBoundaryKind::ParentToChildExtension);
    let _ = v.derive_child_budget("p", "c2", 0, BudgetBoundaryKind::ParentToChildSession);
    let _ = v.validate_cleanup("p", 5_000);
    let report = v.build_report();

    let json = serde_json::to_string(&report).unwrap();
    let back: BudgetPropagationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ── Cross-cutting lifecycle scenarios ───────────────────────────────────

#[test]
fn enrichment_lifecycle_cascading_children_then_cleanup() {
    let mut v = default_validator();
    let mut remaining = 100_000u64;

    // Cascade: extension -> session -> delegate -> cleanup
    let r1 = v
        .derive_child_budget("p", "ext-1", remaining, BudgetBoundaryKind::ParentToChildExtension)
        .unwrap();
    remaining = r1.parent_remaining_after_ms;

    let r2 = v
        .derive_child_budget("p", "sess-1", remaining, BudgetBoundaryKind::ParentToChildSession)
        .unwrap();
    remaining = r2.parent_remaining_after_ms;

    let r3 = v
        .derive_child_budget("p", "del-1", remaining, BudgetBoundaryKind::ParentToChildDelegate)
        .unwrap();
    remaining = r3.parent_remaining_after_ms;

    let alloc = v.validate_cleanup("p", remaining).unwrap();

    // All derivations should have reduced the parent
    assert!(remaining < 100_000);
    // Cleanup should not exceed what was left
    assert!(alloc.total_cleanup_ms <= remaining);

    let report = v.build_report();
    assert_eq!(report.total_events, 4);
    assert_eq!(report.successful_derivations, 4);
    assert!(report.is_clean());
}

#[test]
fn enrichment_lifecycle_exhaustion_cascade() {
    let mut v = default_validator();
    let mut remaining = 100u64;
    let mut derivations = 0u64;

    // Keep deriving session children (80%) until budget is exhausted
    loop {
        match v.derive_child_budget("p", &format!("c-{}", derivations), remaining, BudgetBoundaryKind::ParentToChildSession) {
            Ok(r) => {
                remaining = r.parent_remaining_after_ms;
                derivations += 1;
                if remaining == 0 {
                    break;
                }
            }
            Err(_) => break,
        }
        if derivations > 100 {
            break; // safety valve
        }
    }

    // Should have derived at least a few children before exhaustion
    assert!(derivations >= 1, "at least one derivation should succeed");
    let report = v.build_report();
    assert!(report.total_events > 0);
}

#[test]
fn enrichment_lifecycle_mixed_successes_and_failures() {
    let mut v = default_validator();

    // Success
    let _ = v
        .derive_child_budget("p", "c1", 10_000, BudgetBoundaryKind::ParentToChildExtension)
        .unwrap();

    // Failure: exhausted parent
    let _ = v.derive_child_budget("p", "c2", 0, BudgetBoundaryKind::ParentToChildSession);

    // Success
    let _ = v
        .derive_child_budget("p", "c3", 5_000, BudgetBoundaryKind::ParentToChildDelegate)
        .unwrap();

    // Failure: too small
    let _ = v.derive_child_budget("p", "c4", 1, BudgetBoundaryKind::ParentToChildExtension);

    // Success: cleanup
    let _ = v.validate_cleanup("p", 3_000).unwrap();

    let report = v.build_report();
    assert_eq!(report.total_events, 5);
    assert_eq!(report.successful_derivations, 3);
    assert_eq!(report.failed_derivations, 2);
    assert!(!report.is_clean());
    assert_eq!(report.violations.len(), 2);
}

#[test]
fn enrichment_lifecycle_multiple_cleanups_accumulate() {
    let mut v = default_validator();
    let _ = v.validate_cleanup("p1", 10_000).unwrap();
    let _ = v.validate_cleanup("p2", 20_000).unwrap();
    let _ = v.validate_cleanup("p3", 5_000).unwrap();

    let report = v.build_report();
    assert_eq!(report.total_events, 3);
    assert_eq!(report.successful_derivations, 3);
    // All cleanups should be in the boundary counts
    assert_eq!(
        *report.boundary_event_counts.get("execution_to_cleanup").unwrap(),
        3
    );
}

// ── Invariant stress tests ──────────────────────────────────────────────

#[test]
fn enrichment_invariant_derived_never_exceeds_parent_all_strategies() {
    let strategies = [
        BudgetDerivationStrategy::FractionOfRemaining {
            fraction_millionths: 1_500_000,
        },
        BudgetDerivationStrategy::FixedAmount {
            amount_ms: 999_999,
        },
        BudgetDerivationStrategy::BoundedFraction {
            fraction_millionths: 2_000_000,
            min_ms: 0,
            max_ms: u64::MAX,
        },
        BudgetDerivationStrategy::AllRemaining,
    ];

    let parent_values = [0, 1, 5, 10, 50, 100, 1_000, 10_000, 100_000, u64::MAX / 4];
    for strat in &strategies {
        for &parent in &parent_values {
            let derived = strat.derive(parent);
            assert!(
                derived <= parent,
                "invariant violated: {:?}.derive({}) = {} > {}",
                strat,
                parent,
                derived,
                parent
            );
        }
    }
}

#[test]
fn enrichment_invariant_cleanup_total_is_sum_of_parts() {
    let policies = [
        CleanupBudgetPolicy::default(),
        CleanupBudgetPolicy {
            drain_strategy: BudgetDerivationStrategy::FixedAmount { amount_ms: 500 },
            finalize_budget_ms: 200,
            carved_from_parent: true,
        },
        CleanupBudgetPolicy {
            drain_strategy: BudgetDerivationStrategy::AllRemaining,
            finalize_budget_ms: 0,
            carved_from_parent: false,
        },
    ];

    for policy in &policies {
        for parent in [0, 1, 100, 1_000, 10_000, 100_000] {
            let alloc = policy.compute_allocation(parent);
            assert_eq!(
                alloc.total_cleanup_ms,
                alloc.drain_budget_ms + alloc.finalize_budget_ms,
                "sum invariant violated for parent={}, policy={:?}",
                parent,
                policy
            );
        }
    }
}

#[test]
fn enrichment_invariant_carve_preserves_budget_conservation() {
    let mut v = default_validator();
    let parent = 50_000u64;

    let r = v
        .derive_child_budget("p", "c", parent, BudgetBoundaryKind::ParentToChildExtension)
        .unwrap();

    if r.carved_from_parent {
        assert_eq!(
            r.derived_budget_ms + r.parent_remaining_after_ms,
            parent,
            "budget conservation: derived + remaining must equal original"
        );
    }
}

#[test]
fn enrichment_invariant_validator_event_count_matches_calls() {
    let mut v = default_validator();

    let mut total_calls = 0u64;
    for _ in 0..3 {
        let _ = v.derive_child_budget("p", "c", 10_000, BudgetBoundaryKind::ParentToChildExtension);
        total_calls += 1;
    }
    for _ in 0..2 {
        let _ = v.validate_cleanup("p", 5_000);
        total_calls += 1;
    }
    // 1 failure
    let _ = v.derive_child_budget("p", "c", 0, BudgetBoundaryKind::ParentToChildSession);
    total_calls += 1;

    assert_eq!(
        v.events().len() as u64,
        total_calls,
        "every call (success or failure) must generate exactly one event"
    );
}

// ── Overflow / large-value safety ───────────────────────────────────────

#[test]
fn enrichment_large_parent_budget_no_overflow() {
    let mut v = default_validator();
    let large = u64::MAX / 2;
    let r = v
        .derive_child_budget("p", "c", large, BudgetBoundaryKind::ParentToChildExtension)
        .unwrap();
    assert!(r.derived_budget_ms > 0);
    assert!(r.derived_budget_ms <= large);
}

#[test]
fn enrichment_saturating_fraction_overflow() {
    let strat = BudgetDerivationStrategy::FractionOfRemaining {
        fraction_millionths: u64::MAX,
    };
    // Should not panic
    let derived = strat.derive(u64::MAX);
    assert!(derived <= u64::MAX);
}

#[test]
fn enrichment_bounded_fraction_overflow_safety() {
    let strat = BudgetDerivationStrategy::BoundedFraction {
        fraction_millionths: u64::MAX,
        min_ms: 0,
        max_ms: u64::MAX,
    };
    // Should not panic
    let derived = strat.derive(u64::MAX);
    assert!(derived <= u64::MAX);
}

// ── Determinism ─────────────────────────────────────────────────────────

#[test]
fn enrichment_determinism_same_inputs_same_outputs() {
    let derive = |parent: u64, boundary: BudgetBoundaryKind| {
        let mut v = default_validator();
        let r = v.derive_child_budget("p", "c", parent, boundary).unwrap();
        (r.derived_budget_ms, r.parent_remaining_after_ms)
    };

    for boundary in [
        BudgetBoundaryKind::ParentToChildExtension,
        BudgetBoundaryKind::ParentToChildSession,
        BudgetBoundaryKind::ParentToChildDelegate,
    ] {
        let (d1, p1) = derive(25_000, boundary);
        let (d2, p2) = derive(25_000, boundary);
        assert_eq!(d1, d2, "derived not deterministic for {:?}", boundary);
        assert_eq!(p1, p2, "remaining not deterministic for {:?}", boundary);
    }
}

#[test]
fn enrichment_determinism_cleanup_allocation() {
    let policy = CleanupBudgetPolicy::default();
    let a1 = policy.compute_allocation(7_777);
    let a2 = policy.compute_allocation(7_777);
    assert_eq!(a1, a2);
}

#[test]
fn enrichment_determinism_report_across_identical_runs() {
    let make = || {
        let mut v = default_validator();
        let _ = v.derive_child_budget("p", "c1", 10_000, BudgetBoundaryKind::ParentToChildExtension);
        let _ = v.derive_child_budget("p", "c2", 8_000, BudgetBoundaryKind::ParentToChildSession);
        let _ = v.validate_cleanup("p", 6_000);
        v.build_report()
    };
    let r1 = make();
    let r2 = make();
    assert_eq!(r1, r2);
    assert_eq!(r1.content_hash, r2.content_hash);
}

// ── Delegate vs Extension ordering ──────────────────────────────────────

#[test]
fn enrichment_delegate_and_extension_both_derive_within_parent() {
    let policy = BudgetPropagationPolicy::default();
    let ext_rule = policy.rule_for(BudgetBoundaryKind::ParentToChildExtension).unwrap();
    let del_rule = policy.rule_for(BudgetBoundaryKind::ParentToChildDelegate).unwrap();

    for parent in [100, 500, 1_000, 5_000, 10_000, 50_000, 100_000] {
        let ext = ext_rule.derivation.derive(parent);
        let del = del_rule.derivation.derive(parent);
        assert!(
            ext <= parent,
            "extension {} > parent {}",
            ext,
            parent
        );
        assert!(
            del <= parent,
            "delegate {} > parent {}",
            del,
            parent
        );
    }
}

// ── Custom policy edge cases ────────────────────────────────────────────

#[test]
fn enrichment_custom_policy_not_carved_leaves_parent_intact() {
    let mut rules = BTreeMap::new();
    rules.insert(
        BudgetBoundaryKind::ParentToChildExtension.as_str().to_owned(),
        ChildBudgetRule {
            boundary_kind: BudgetBoundaryKind::ParentToChildExtension,
            derivation: BudgetDerivationStrategy::FixedAmount { amount_ms: 3_000 },
            minimum_ms: 0,
            carved_from_parent: false,
        },
    );
    let policy = BudgetPropagationPolicy {
        child_rules: rules,
        cleanup_policy: CleanupBudgetPolicy::default(),
        fail_closed_on_missing_rule: true,
        min_parent_reserve_ms: 0,
        epoch: epoch(1),
    };

    let mut v = BudgetPropagationValidator::new(policy);
    let r = v
        .derive_child_budget("p", "c", 10_000, BudgetBoundaryKind::ParentToChildExtension)
        .unwrap();
    assert_eq!(r.derived_budget_ms, 3_000);
    assert_eq!(r.parent_remaining_after_ms, 10_000); // not carved
    assert!(!r.carved_from_parent);
}

#[test]
fn enrichment_custom_policy_all_remaining_for_child() {
    let mut rules = BTreeMap::new();
    rules.insert(
        BudgetBoundaryKind::ParentToChildExtension.as_str().to_owned(),
        ChildBudgetRule {
            boundary_kind: BudgetBoundaryKind::ParentToChildExtension,
            derivation: BudgetDerivationStrategy::AllRemaining,
            minimum_ms: 0,
            carved_from_parent: true,
        },
    );
    let policy = BudgetPropagationPolicy {
        child_rules: rules,
        cleanup_policy: CleanupBudgetPolicy::default(),
        fail_closed_on_missing_rule: true,
        min_parent_reserve_ms: 0,
        epoch: epoch(1),
    };

    let mut v = BudgetPropagationValidator::new(policy);
    let r = v
        .derive_child_budget("p", "c", 10_000, BudgetBoundaryKind::ParentToChildExtension)
        .unwrap();
    assert_eq!(r.derived_budget_ms, 10_000);
    assert_eq!(r.parent_remaining_after_ms, 0);
}

#[test]
fn enrichment_custom_policy_high_minimum_causes_failure() {
    let mut rules = BTreeMap::new();
    rules.insert(
        BudgetBoundaryKind::ParentToChildExtension.as_str().to_owned(),
        ChildBudgetRule {
            boundary_kind: BudgetBoundaryKind::ParentToChildExtension,
            derivation: BudgetDerivationStrategy::FractionOfRemaining {
                fraction_millionths: 100_000, // 10%
            },
            minimum_ms: 5_000,
            carved_from_parent: true,
        },
    );
    let policy = BudgetPropagationPolicy {
        child_rules: rules,
        cleanup_policy: CleanupBudgetPolicy::default(),
        fail_closed_on_missing_rule: true,
        min_parent_reserve_ms: 0,
        epoch: epoch(1),
    };

    let mut v = BudgetPropagationValidator::new(policy);
    // 10% of 10k = 1k, but minimum is 5k => InsufficientBudget
    let err = v
        .derive_child_budget("p", "c", 10_000, BudgetBoundaryKind::ParentToChildExtension)
        .unwrap_err();
    assert!(matches!(err, BudgetPropagationError::InsufficientBudget { .. }));
}

// ── Report with no events ───────────────────────────────────────────────

#[test]
fn enrichment_report_empty_validator() {
    let v = default_validator();
    let report = v.build_report();
    assert_eq!(report.total_events, 0);
    assert_eq!(report.successful_derivations, 0);
    assert_eq!(report.failed_derivations, 0);
    assert_eq!(report.total_budget_derived_ms, 0);
    assert!(report.boundary_event_counts.is_empty());
    assert!(report.is_clean());
}

// ── Interleaved boundary types ──────────────────────────────────────────

#[test]
fn enrichment_interleaved_boundary_types_in_report() {
    let mut v = default_validator();
    let _ = v.derive_child_budget("p", "ext-1", 10_000, BudgetBoundaryKind::ParentToChildExtension);
    let _ = v.validate_cleanup("p", 8_000);
    let _ = v.derive_child_budget("p", "sess-1", 6_000, BudgetBoundaryKind::ParentToChildSession);
    let _ = v.derive_child_budget("p", "del-1", 4_000, BudgetBoundaryKind::ParentToChildDelegate);
    let _ = v.validate_cleanup("p2", 3_000);
    let _ = v.derive_child_budget("p", "ext-2", 2_000, BudgetBoundaryKind::ParentToChildExtension);

    let report = v.build_report();
    assert_eq!(report.total_events, 6);
    assert_eq!(
        *report.boundary_event_counts.get("parent_to_child_extension").unwrap(),
        2
    );
    assert_eq!(
        *report.boundary_event_counts.get("parent_to_child_session").unwrap(),
        1
    );
    assert_eq!(
        *report.boundary_event_counts.get("parent_to_child_delegate").unwrap(),
        1
    );
    assert_eq!(
        *report.boundary_event_counts.get("execution_to_cleanup").unwrap(),
        2
    );
}

// ── Standard strategy label in events ───────────────────────────────────

#[test]
fn enrichment_standard_strategy_label_for_normal_derivation() {
    let mut v = default_validator();
    let _ = v
        .derive_child_budget("p", "c", 50_000, BudgetBoundaryKind::ParentToChildExtension)
        .unwrap();
    let events = v.events();
    assert_eq!(events[0].strategy_used, "standard");
}

#[test]
fn enrichment_failed_strategy_label_on_error() {
    let mut v = default_validator();
    let _ = v.derive_child_budget("p", "c", 0, BudgetBoundaryKind::ParentToChildExtension);
    let events = v.events();
    assert_eq!(events[0].strategy_used, "failed");
}

// ── Event parent_before_ms and parent_after_ms consistency ──────────────

#[test]
fn enrichment_event_parent_before_after_consistency() {
    let mut v = default_validator();
    let parent = 10_000u64;
    let _ = v
        .derive_child_budget("p", "c", parent, BudgetBoundaryKind::ParentToChildExtension)
        .unwrap();
    let e = &v.events()[0];
    assert_eq!(e.parent_before_ms, parent);
    assert!(e.parent_after_ms <= parent);
    assert_eq!(e.derived_ms + e.parent_after_ms, parent);
}

#[test]
fn enrichment_event_failure_parent_after_equals_before() {
    let mut v = default_validator();
    let _ = v.derive_child_budget("p", "c", 0, BudgetBoundaryKind::ParentToChildExtension);
    let e = &v.events()[0];
    assert_eq!(e.parent_before_ms, 0);
    assert_eq!(e.parent_after_ms, 0);
}
