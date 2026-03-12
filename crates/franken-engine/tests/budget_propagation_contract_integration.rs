//! Integration tests for budget_propagation_contract module.

use frankenengine_engine::budget_propagation_contract::{
    BudgetBoundaryKind, BudgetDerivationResult, BudgetDerivationStrategy, BudgetPropagationError,
    BudgetPropagationEvent, BudgetPropagationPolicy, BudgetPropagationReport,
    BudgetPropagationValidator, ChildBudgetRule, CleanupBudgetAllocation, CleanupBudgetPolicy,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Strategy derivation integration
// ---------------------------------------------------------------------------

#[test]
fn integration_fraction_derivation_various_parents() {
    let strat = BudgetDerivationStrategy::FractionOfRemaining {
        fraction_millionths: 500_000,
    };
    let test_cases = [
        (0, 0),
        (1, 0),
        (2, 1),
        (100, 50),
        (1_000, 500),
        (10_000, 5_000),
        (100_000, 50_000),
    ];
    for (parent, expected) in test_cases {
        assert_eq!(strat.derive(parent), expected, "parent={}", parent);
    }
}

#[test]
fn integration_bounded_fraction_clamps_correctly() {
    let strat = BudgetDerivationStrategy::BoundedFraction {
        fraction_millionths: 100_000, // 10%
        min_ms: 100,
        max_ms: 1000,
    };

    // 10% of 500 = 50, floored to 100
    assert_eq!(strat.derive(500), 100);
    // 10% of 5000 = 500, within bounds
    assert_eq!(strat.derive(5_000), 500);
    // 10% of 50000 = 5000, capped to 1000
    assert_eq!(strat.derive(50_000), 1_000);
    // Parent smaller than min: capped by parent
    assert_eq!(strat.derive(50), 50);
}

#[test]
fn integration_fixed_amount_capped_by_parent() {
    let strat = BudgetDerivationStrategy::FixedAmount { amount_ms: 5_000 };
    assert_eq!(strat.derive(10_000), 5_000);
    assert_eq!(strat.derive(3_000), 3_000);
    assert_eq!(strat.derive(0), 0);
}

// ---------------------------------------------------------------------------
// Cleanup budget allocation integration
// ---------------------------------------------------------------------------

#[test]
fn integration_cleanup_policy_large_parent() {
    let policy = CleanupBudgetPolicy::default();
    let alloc = policy.compute_allocation(100_000);
    // 10% of 100k = 10k, bounded at [50, 30000]
    assert!(alloc.drain_budget_ms >= 50);
    assert!(alloc.drain_budget_ms <= 30_000);
    assert_eq!(alloc.finalize_budget_ms, 500);
    assert!(alloc.total_cleanup_ms <= 100_000);
    assert!(alloc.carved_from_parent);
    assert!(alloc.parent_remaining_after_ms < 100_000);
}

#[test]
fn integration_cleanup_policy_tiny_parent() {
    let policy = CleanupBudgetPolicy::default();
    let alloc = policy.compute_allocation(10);
    assert!(alloc.total_cleanup_ms <= 10);
}

#[test]
fn integration_cleanup_not_carved() {
    let policy = CleanupBudgetPolicy {
        drain_strategy: BudgetDerivationStrategy::FixedAmount { amount_ms: 200 },
        finalize_budget_ms: 100,
        carved_from_parent: false,
    };
    let alloc = policy.compute_allocation(1_000);
    assert_eq!(alloc.drain_budget_ms, 200);
    assert_eq!(alloc.finalize_budget_ms, 100);
    assert_eq!(alloc.parent_remaining_after_ms, 1_000); // unchanged
}

// ---------------------------------------------------------------------------
// Child budget rule defaults integration
// ---------------------------------------------------------------------------

#[test]
fn integration_child_rules_produce_valid_budgets() {
    let rules = vec![
        ChildBudgetRule::default_extension(),
        ChildBudgetRule::default_session(),
        ChildBudgetRule::default_delegate(),
    ];

    for rule in rules {
        let derived = rule.derivation.derive(10_000);
        assert!(
            derived >= rule.minimum_ms,
            "rule for {:?}: derived {} < minimum {}",
            rule.boundary_kind,
            derived,
            rule.minimum_ms
        );
        assert!(derived <= 10_000);
    }
}

#[test]
fn integration_delegate_fraction_is_half() {
    let del = ChildBudgetRule::default_delegate();
    assert_eq!(del.derivation.derive(10_000), 5_000);
}

// ---------------------------------------------------------------------------
// Validator end-to-end integration
// ---------------------------------------------------------------------------

#[test]
fn integration_validator_full_lifecycle() {
    let mut validator = BudgetPropagationValidator::with_defaults();
    let mut parent_remaining = 50_000u64;

    // Derive 3 extension children
    for i in 0..3 {
        let result = validator
            .derive_child_budget(
                "orchestrator",
                &format!("ext-{}", i),
                parent_remaining,
                BudgetBoundaryKind::ParentToChildExtension,
            )
            .unwrap();
        assert!(result.derived_budget_ms > 0);
        assert!(result.derived_budget_ms <= parent_remaining);
        if result.carved_from_parent {
            parent_remaining = result.parent_remaining_after_ms;
        }
    }

    // Validate cleanup
    let cleanup = validator
        .validate_cleanup("orchestrator", parent_remaining)
        .unwrap();
    assert!(cleanup.total_cleanup_ms <= parent_remaining);

    // Build report
    let report = validator.build_report();
    assert!(report.is_clean());
    assert_eq!(report.successful_derivations, 4); // 3 children + 1 cleanup
    assert_eq!(report.failed_derivations, 0);
    assert!(report.total_budget_derived_ms > 0);
}

#[test]
fn integration_validator_exhaustion_cascading() {
    let mut validator = BudgetPropagationValidator::with_defaults();

    // Start with small budget
    let mut remaining = 100u64;

    // First child takes most
    let r1 = validator
        .derive_child_budget(
            "parent",
            "child-1",
            remaining,
            BudgetBoundaryKind::ParentToChildExtension,
        )
        .unwrap();
    remaining = r1.parent_remaining_after_ms;

    // Second child may fail due to insufficient budget
    let r2 = validator.derive_child_budget(
        "parent",
        "child-2",
        remaining,
        BudgetBoundaryKind::ParentToChildExtension,
    );

    // At least one derivation succeeded
    assert!(r1.derived_budget_ms > 0);

    // Build report shows correct counts
    let report = validator.build_report();
    if r2.is_err() {
        assert_eq!(report.failed_derivations, 1);
    }
}

#[test]
fn integration_validator_boundary_event_counts() {
    let mut validator = BudgetPropagationValidator::with_defaults();

    let _ = validator.derive_child_budget(
        "p",
        "c1",
        10_000,
        BudgetBoundaryKind::ParentToChildExtension,
    );
    let _ =
        validator.derive_child_budget("p", "c2", 8_000, BudgetBoundaryKind::ParentToChildSession);
    let _ =
        validator.derive_child_budget("p", "c3", 6_000, BudgetBoundaryKind::ParentToChildDelegate);
    let _ = validator.validate_cleanup("p", 4_000);

    let report = validator.build_report();
    assert_eq!(report.total_events, 4);

    // Should have entries for each boundary type
    assert!(
        report
            .boundary_event_counts
            .contains_key("parent_to_child_extension")
    );
    assert!(
        report
            .boundary_event_counts
            .contains_key("parent_to_child_session")
    );
    assert!(
        report
            .boundary_event_counts
            .contains_key("parent_to_child_delegate")
    );
    assert!(
        report
            .boundary_event_counts
            .contains_key("execution_to_cleanup")
    );
}

#[test]
fn integration_validator_fail_closed_unknown_boundary() {
    let policy = BudgetPropagationPolicy {
        child_rules: BTreeMap::new(), // no rules at all
        cleanup_policy: CleanupBudgetPolicy::default(),
        fail_closed_on_missing_rule: true,
        min_parent_reserve_ms: 0,
        epoch: SecurityEpoch::from_raw(1),
    };
    let mut validator = BudgetPropagationValidator::new(policy);

    let result = validator.derive_child_budget(
        "parent",
        "child",
        10_000,
        BudgetBoundaryKind::ParentToChildExtension,
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        BudgetPropagationError::NoRuleForBoundary { boundary } => {
            assert_eq!(boundary, BudgetBoundaryKind::ParentToChildExtension);
        }
        other => panic!("expected NoRuleForBoundary, got {:?}", other),
    }
}

#[test]
fn integration_validator_fail_open_unknown_boundary() {
    let policy = BudgetPropagationPolicy {
        child_rules: BTreeMap::new(),
        cleanup_policy: CleanupBudgetPolicy::default(),
        fail_closed_on_missing_rule: false,
        min_parent_reserve_ms: 0,
        epoch: SecurityEpoch::from_raw(1),
    };
    let mut validator = BudgetPropagationValidator::new(policy);

    let result = validator
        .derive_child_budget(
            "parent",
            "child",
            10_000,
            BudgetBoundaryKind::ParentToChildExtension,
        )
        .unwrap();

    assert_eq!(result.derived_budget_ms, 10_000);
    assert!(!validator.has_violations());
}

#[test]
fn integration_validator_parent_reserve_enforced() {
    let policy = BudgetPropagationPolicy {
        min_parent_reserve_ms: 8_000, // high reserve
        ..Default::default()
    };

    let mut validator = BudgetPropagationValidator::new(policy);
    let result = validator
        .derive_child_budget("p", "c", 10_000, BudgetBoundaryKind::ParentToChildExtension)
        .unwrap();

    // Child should be capped to maintain 8k reserve
    assert!(result.parent_remaining_after_ms >= 8_000 || !result.carved_from_parent);
    assert!(result.derived_budget_ms <= 2_000);
}

// ---------------------------------------------------------------------------
// Determinism integration
// ---------------------------------------------------------------------------

#[test]
fn integration_derivation_deterministic_across_runs() {
    let derive = |parent_ms: u64| {
        let mut v = BudgetPropagationValidator::with_defaults();
        let r = v
            .derive_child_budget(
                "p",
                "c",
                parent_ms,
                BudgetBoundaryKind::ParentToChildExtension,
            )
            .unwrap();
        (r.derived_budget_ms, r.parent_remaining_after_ms)
    };

    let (d1, p1) = derive(10_000);
    let (d2, p2) = derive(10_000);
    assert_eq!(d1, d2);
    assert_eq!(p1, p2);
}

#[test]
fn integration_report_hash_deterministic() {
    let make_report = || {
        let mut v = BudgetPropagationValidator::with_defaults();
        let _ = v.derive_child_budget("p", "c", 10_000, BudgetBoundaryKind::ParentToChildExtension);
        let _ = v.validate_cleanup("p", 8_000);
        v.build_report()
    };

    let r1 = make_report();
    let r2 = make_report();
    assert_eq!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// Serde integration
// ---------------------------------------------------------------------------

#[test]
fn integration_policy_json_roundtrip() {
    let policy = BudgetPropagationPolicy::default();
    let json = serde_json::to_string_pretty(&policy).unwrap();
    let round: BudgetPropagationPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, round);
}

#[test]
fn integration_report_json_roundtrip() {
    let mut v = BudgetPropagationValidator::with_defaults();
    let _ = v.derive_child_budget(
        "p",
        "c1",
        10_000,
        BudgetBoundaryKind::ParentToChildExtension,
    );
    let _ = v.derive_child_budget("p", "c2", 8_000, BudgetBoundaryKind::ParentToChildSession);
    let _ = v.validate_cleanup("p", 6_000);
    let report = v.build_report();

    let json = serde_json::to_string_pretty(&report).unwrap();
    let round: BudgetPropagationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, round);
}

#[test]
fn integration_events_json_roundtrip() {
    let mut v = BudgetPropagationValidator::with_defaults();
    let _ = v.derive_child_budget("p", "c", 10_000, BudgetBoundaryKind::ParentToChildExtension);

    for event in v.events() {
        let json = serde_json::to_string(event).unwrap();
        let round: BudgetPropagationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(*event, round);
    }
}

#[test]
fn integration_error_json_roundtrip() {
    let errors = vec![
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
            cleanup_total_ms: 5000,
            parent_remaining_ms: 1000,
        },
        BudgetPropagationError::ChildExceedsParent {
            child_ms: 200,
            parent_ms: 100,
        },
    ];

    for err in errors {
        let json = serde_json::to_string(&err).unwrap();
        let round: BudgetPropagationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, round);
    }
}

// ---------------------------------------------------------------------------
// Boundary kind coverage
// ---------------------------------------------------------------------------

#[test]
fn integration_all_boundary_kinds_have_labels() {
    let kinds = [
        BudgetBoundaryKind::ParentToChildExtension,
        BudgetBoundaryKind::ParentToChildSession,
        BudgetBoundaryKind::ParentToChildDelegate,
        BudgetBoundaryKind::ExecutionToCleanup,
        BudgetBoundaryKind::CleanupToFinalize,
        BudgetBoundaryKind::OrchestratorToCellClose,
    ];

    let mut labels = std::collections::BTreeSet::new();
    for kind in kinds {
        let label = kind.as_str();
        assert!(!label.is_empty());
        assert!(labels.insert(label), "duplicate label: {}", label);
    }
}

#[test]
fn integration_boundary_kind_serde_roundtrip() {
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
        let round: BudgetBoundaryKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, round);
    }
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn integration_zero_parent_budget_always_fails() {
    let mut validator = BudgetPropagationValidator::with_defaults();
    for kind in [
        BudgetBoundaryKind::ParentToChildExtension,
        BudgetBoundaryKind::ParentToChildSession,
        BudgetBoundaryKind::ParentToChildDelegate,
    ] {
        let result = validator.derive_child_budget("p", "c", 0, kind);
        assert!(result.is_err(), "should fail for {:?} with 0 parent", kind);
    }
}

#[test]
fn integration_large_budget_no_overflow() {
    let mut validator = BudgetPropagationValidator::with_defaults();
    let result = validator
        .derive_child_budget(
            "p",
            "c",
            u64::MAX / 2,
            BudgetBoundaryKind::ParentToChildExtension,
        )
        .unwrap();
    assert!(result.derived_budget_ms > 0);
    assert!(result.derived_budget_ms <= u64::MAX / 2);
}

#[test]
fn integration_cleanup_allocation_serde_roundtrip() {
    let policy = CleanupBudgetPolicy::default();
    let alloc = policy.compute_allocation(10_000);
    let json = serde_json::to_string(&alloc).unwrap();
    let round: CleanupBudgetAllocation = serde_json::from_str(&json).unwrap();
    assert_eq!(alloc, round);
}

#[test]
fn integration_derivation_result_serde_roundtrip() {
    let result = BudgetDerivationResult {
        derived_budget_ms: 8_000,
        parent_remaining_after_ms: 2_000,
        boundary_kind: BudgetBoundaryKind::ParentToChildExtension,
        carved_from_parent: true,
    };
    let json = serde_json::to_string(&result).unwrap();
    let round: BudgetDerivationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, round);
}

// ---------------------------------------------------------------------------
// Display integration
// ---------------------------------------------------------------------------

#[test]
fn integration_boundary_kind_display() {
    let kinds = [
        BudgetBoundaryKind::ParentToChildExtension,
        BudgetBoundaryKind::ParentToChildSession,
        BudgetBoundaryKind::ParentToChildDelegate,
        BudgetBoundaryKind::ExecutionToCleanup,
        BudgetBoundaryKind::CleanupToFinalize,
        BudgetBoundaryKind::OrchestratorToCellClose,
    ];
    let mut seen = std::collections::BTreeSet::new();
    for kind in kinds {
        let s = format!("{:?}", kind);
        assert!(!s.is_empty());
        assert!(seen.insert(s), "duplicate display for {:?}", kind);
    }
}

#[test]
fn integration_boundary_kind_is_child_derivation() {
    assert!(BudgetBoundaryKind::ParentToChildExtension.is_child_derivation());
    assert!(BudgetBoundaryKind::ParentToChildSession.is_child_derivation());
    assert!(BudgetBoundaryKind::ParentToChildDelegate.is_child_derivation());
    assert!(!BudgetBoundaryKind::ExecutionToCleanup.is_child_derivation());
    assert!(!BudgetBoundaryKind::CleanupToFinalize.is_child_derivation());
    assert!(!BudgetBoundaryKind::OrchestratorToCellClose.is_child_derivation());
}

#[test]
fn integration_error_display_all_variants() {
    let errors: Vec<BudgetPropagationError> = vec![
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
            cleanup_total_ms: 5000,
            parent_remaining_ms: 1000,
        },
        BudgetPropagationError::ChildExceedsParent {
            child_ms: 200,
            parent_ms: 100,
        },
    ];
    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.is_empty(), "empty display for {:?}", err);
    }
    // Check specific content
    assert!(errors[0].to_string().contains("insufficient"));
    assert!(errors[1].to_string().contains("no propagation rule"));
    assert!(errors[2].to_string().contains("exhausted"));
    assert!(errors[3].to_string().contains("cleanup"));
    assert!(errors[4].to_string().contains("exceeds parent"));
}

// ---------------------------------------------------------------------------
// Strategy edge cases
// ---------------------------------------------------------------------------

#[test]
fn integration_all_remaining_strategy() {
    let strat = BudgetDerivationStrategy::AllRemaining;
    assert_eq!(strat.derive(0), 0);
    assert_eq!(strat.derive(1), 1);
    assert_eq!(strat.derive(100_000), 100_000);
    assert_eq!(strat.derive(u64::MAX / 2), u64::MAX / 2);
}

#[test]
fn integration_bounded_fraction_min_equals_max() {
    let strat = BudgetDerivationStrategy::BoundedFraction {
        fraction_millionths: 500_000, // 50%
        min_ms: 100,
        max_ms: 100,
    };
    // 50% of 1000 = 500, capped to max 100
    assert_eq!(strat.derive(1_000), 100);
    // 50% of 50 = 25, floored to min 100, capped by parent 50
    assert_eq!(strat.derive(50), 50);
    // 50% of 200 = 100, exactly at bounds
    assert_eq!(strat.derive(200), 100);
}

#[test]
fn integration_full_fraction_returns_entire_parent() {
    let strat = BudgetDerivationStrategy::FractionOfRemaining {
        fraction_millionths: 1_000_000, // 100%
    };
    assert_eq!(strat.derive(5_000), 5_000);
    assert_eq!(strat.derive(1), 1);
}

// ---------------------------------------------------------------------------
// Serde integration (additional types)
// ---------------------------------------------------------------------------

#[test]
fn integration_derivation_strategy_all_variants_serde() {
    let strategies = vec![
        BudgetDerivationStrategy::FractionOfRemaining {
            fraction_millionths: 500_000,
        },
        BudgetDerivationStrategy::FixedAmount { amount_ms: 1_000 },
        BudgetDerivationStrategy::BoundedFraction {
            fraction_millionths: 100_000,
            min_ms: 50,
            max_ms: 500,
        },
        BudgetDerivationStrategy::AllRemaining,
    ];
    for strat in &strategies {
        let json = serde_json::to_string(strat).unwrap();
        let round: BudgetDerivationStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(*strat, round, "serde mismatch for {:?}", strat);
    }
}

#[test]
fn integration_child_budget_rule_serde_roundtrip() {
    let rules = vec![
        ChildBudgetRule::default_extension(),
        ChildBudgetRule::default_session(),
        ChildBudgetRule::default_delegate(),
    ];
    for rule in &rules {
        let json = serde_json::to_string(rule).unwrap();
        let round: ChildBudgetRule = serde_json::from_str(&json).unwrap();
        assert_eq!(*rule, round, "serde mismatch for {:?}", rule.boundary_kind);
    }
}

#[test]
fn integration_cleanup_budget_policy_serde_roundtrip() {
    let policy = CleanupBudgetPolicy::default();
    let json = serde_json::to_string(&policy).unwrap();
    let round: CleanupBudgetPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, round);
}

#[test]
fn integration_validator_serde_roundtrip() {
    let mut v = BudgetPropagationValidator::with_defaults();
    let _ = v.derive_child_budget("p", "c", 10_000, BudgetBoundaryKind::ParentToChildExtension);
    let _ = v.validate_cleanup("p", 8_000);
    let json = serde_json::to_string(&v).unwrap();
    let round: BudgetPropagationValidator = serde_json::from_str(&json).unwrap();
    assert_eq!(v.events().len(), round.events().len());
    assert_eq!(v.violations().len(), round.violations().len());
}

// ---------------------------------------------------------------------------
// Validator error paths
// ---------------------------------------------------------------------------

#[test]
fn integration_cleanup_zero_parent() {
    let mut v = BudgetPropagationValidator::with_defaults();
    let alloc = v.validate_cleanup("p", 0).unwrap();
    assert_eq!(alloc.drain_budget_ms, 0);
    assert_eq!(alloc.finalize_budget_ms, 0);
    assert_eq!(alloc.total_cleanup_ms, 0);
}

#[test]
fn integration_violations_accessor() {
    let mut v = BudgetPropagationValidator::with_defaults();
    assert!(!v.has_violations());
    assert!(v.violations().is_empty());

    // Trigger a violation
    let _ = v.derive_child_budget("p", "c", 0, BudgetBoundaryKind::ParentToChildExtension);
    assert!(v.has_violations());
    assert_eq!(v.violations().len(), 1);
    match &v.violations()[0] {
        BudgetPropagationError::ParentExhausted { .. } => {}
        other => panic!("expected ParentExhausted, got {:?}", other),
    }
}

#[test]
fn integration_event_sequence_monotonic() {
    let mut v = BudgetPropagationValidator::with_defaults();
    let _ = v.derive_child_budget(
        "p",
        "c1",
        10_000,
        BudgetBoundaryKind::ParentToChildExtension,
    );
    let _ = v.derive_child_budget("p", "c2", 8_000, BudgetBoundaryKind::ParentToChildSession);
    let _ = v.derive_child_budget("p", "c3", 6_000, BudgetBoundaryKind::ParentToChildDelegate);
    let _ = v.validate_cleanup("p", 4_000);

    let events = v.events();
    for window in events.windows(2) {
        assert!(
            window[1].sequence > window[0].sequence,
            "non-monotonic sequence: {} then {}",
            window[0].sequence,
            window[1].sequence
        );
    }
}

#[test]
fn integration_report_not_clean_with_violations() {
    let mut v = BudgetPropagationValidator::with_defaults();
    let _ = v.derive_child_budget("p", "c", 0, BudgetBoundaryKind::ParentToChildExtension);
    let report = v.build_report();
    assert!(!report.is_clean());
    assert_eq!(report.failed_derivations, 1);
    assert!(!report.violations.is_empty());
}

#[test]
fn integration_report_hash_changes_with_different_inputs() {
    let make_report = |parent_ms: u64| {
        let mut v = BudgetPropagationValidator::with_defaults();
        let _ = v.derive_child_budget(
            "p",
            "c",
            parent_ms,
            BudgetBoundaryKind::ParentToChildExtension,
        );
        v.build_report()
    };

    let r1 = make_report(10_000);
    let r2 = make_report(20_000);
    assert_ne!(
        r1.content_hash, r2.content_hash,
        "different inputs should produce different hashes"
    );
}

#[test]
fn integration_report_epoch_matches_policy() {
    let epoch = SecurityEpoch::from_raw(42);
    let policy = BudgetPropagationPolicy {
        epoch,
        ..Default::default()
    };
    let mut v = BudgetPropagationValidator::new(policy);
    let _ = v.derive_child_budget("p", "c", 10_000, BudgetBoundaryKind::ParentToChildExtension);
    let report = v.build_report();
    assert_eq!(report.epoch, epoch);
}

// ---------------------------------------------------------------------------
// Policy rule_for integration
// ---------------------------------------------------------------------------

#[test]
fn integration_policy_rule_for_missing_returns_none() {
    let policy = BudgetPropagationPolicy::default();
    assert!(
        policy
            .rule_for(BudgetBoundaryKind::ExecutionToCleanup)
            .is_none()
    );
    assert!(
        policy
            .rule_for(BudgetBoundaryKind::CleanupToFinalize)
            .is_none()
    );
    assert!(
        policy
            .rule_for(BudgetBoundaryKind::OrchestratorToCellClose)
            .is_none()
    );
}

#[test]
fn integration_reserve_forces_bounded_by_reserve_path() {
    let policy = BudgetPropagationPolicy {
        min_parent_reserve_ms: 9_000,
        ..Default::default()
    };
    let mut v = BudgetPropagationValidator::new(policy);

    // With 10k parent, 80% = 8k, but reserve is 9k → max child = 1k
    let r = v
        .derive_child_budget("p", "c", 10_000, BudgetBoundaryKind::ParentToChildExtension)
        .unwrap();
    assert!(r.derived_budget_ms <= 1_000);
    assert!(r.parent_remaining_after_ms >= 9_000);

    // Event should record bounded_by_reserve strategy
    let events = v.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].strategy_used, "bounded_by_reserve");
}

use std::collections::BTreeMap;

#[test]
fn integration_custom_policy_with_all_fixed_amounts() {
    let mut rules = BTreeMap::new();
    rules.insert(
        BudgetBoundaryKind::ParentToChildExtension
            .as_str()
            .to_owned(),
        ChildBudgetRule {
            boundary_kind: BudgetBoundaryKind::ParentToChildExtension,
            derivation: BudgetDerivationStrategy::FixedAmount { amount_ms: 1_000 },
            minimum_ms: 100,
            carved_from_parent: true,
        },
    );

    let policy = BudgetPropagationPolicy {
        child_rules: rules,
        cleanup_policy: CleanupBudgetPolicy {
            drain_strategy: BudgetDerivationStrategy::FixedAmount { amount_ms: 500 },
            finalize_budget_ms: 200,
            carved_from_parent: true,
        },
        fail_closed_on_missing_rule: true,
        min_parent_reserve_ms: 0,
        epoch: SecurityEpoch::from_raw(2),
    };

    let mut v = BudgetPropagationValidator::new(policy);
    let r = v
        .derive_child_budget("p", "c", 5_000, BudgetBoundaryKind::ParentToChildExtension)
        .unwrap();
    assert_eq!(r.derived_budget_ms, 1_000);
    assert_eq!(r.parent_remaining_after_ms, 4_000);

    let cleanup = v.validate_cleanup("p", 4_000).unwrap();
    assert_eq!(cleanup.drain_budget_ms, 500);
    assert_eq!(cleanup.finalize_budget_ms, 200);
}

#[test]
fn integration_multiple_children_budget_monotonically_decreases() {
    let mut validator = BudgetPropagationValidator::with_defaults();
    let mut remaining = 50_000u64;
    let mut prev_derived = u64::MAX;

    for i in 0..10 {
        let result = validator.derive_child_budget(
            "parent",
            &format!("child-{}", i),
            remaining,
            BudgetBoundaryKind::ParentToChildSession,
        );

        match result {
            Ok(r) => {
                // Each child gets less because parent remaining decreases
                if r.carved_from_parent {
                    assert!(r.derived_budget_ms <= prev_derived || prev_derived == u64::MAX);
                    prev_derived = r.derived_budget_ms;
                    remaining = r.parent_remaining_after_ms;
                }
            }
            Err(_) => break, // budget exhausted
        }
    }
}
