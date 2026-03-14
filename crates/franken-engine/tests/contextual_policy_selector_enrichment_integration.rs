#![forbid(unsafe_code)]

//! Enrichment integration tests for the contextual_policy_selector module.

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

use frankenengine_engine::contextual_policy_selector::{
    BEAD_ID, COMPONENT, ContextualSelector, DEFAULT_EXPLORATION_BUDGET, FeatureKey,
    MAX_REGRET_BUDGET, MAX_STRATEGIES, OptimizationStrategy, POLICY_ID, PolicyConstraint,
    SCHEMA_VERSION, SelectionReason, StrategyKind, WorkloadContext,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_context() -> WorkloadContext {
    let mut features = BTreeMap::new();
    features.insert(FeatureKey::RequestRate, 1000);
    features.insert(FeatureKey::PayloadSize, 512);
    features.insert(FeatureKey::ConcurrencyLevel, 8);
    WorkloadContext::new(features)
}

fn make_strategy(id: &str, kind: StrategyKind, reward: u64, cost: u64) -> OptimizationStrategy {
    OptimizationStrategy {
        strategy_id: id.to_string(),
        kind,
        name: format!("Strategy {}", id),
        expected_reward_millionths: reward,
        cost_millionths: cost,
        worst_case_regret_millionths: cost / 2,
        required_features: BTreeSet::new(),
    }
}

fn make_selector() -> ContextualSelector {
    let strategies = vec![
        make_strategy("s1", StrategyKind::Tiering, 100_000, 20_000),
        make_strategy("s2", StrategyKind::CachePolicy, 80_000, 10_000),
    ];
    ContextualSelector::with_defaults(strategies, vec![])
}

// ---------------------------------------------------------------------------
// FeatureKey — Copy / BTreeSet / Clone / Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_feature_key_copy_semantics() {
    let a = FeatureKey::RequestRate;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_feature_key_btreeset_dedup_8() {
    let mut set = BTreeSet::new();
    for k in FeatureKey::ALL {
        set.insert(*k);
    }
    set.insert(FeatureKey::RequestRate);
    assert_eq!(set.len(), 8);
}

#[test]
fn enrichment_feature_key_clone_independence() {
    let a = FeatureKey::MemoryPressure;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_feature_key_debug_all_unique() {
    let dbgs: BTreeSet<String> = FeatureKey::ALL.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), 8);
}

// ---------------------------------------------------------------------------
// StrategyKind — Copy / BTreeSet / Clone / Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_strategy_kind_copy_semantics() {
    let a = StrategyKind::Tiering;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_strategy_kind_btreeset_dedup_6() {
    let mut set = BTreeSet::new();
    for k in StrategyKind::ALL {
        set.insert(*k);
    }
    set.insert(StrategyKind::Default);
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_strategy_kind_clone_independence() {
    let a = StrategyKind::CachePolicy;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_strategy_kind_debug_all_unique() {
    let dbgs: BTreeSet<String> = StrategyKind::ALL
        .iter()
        .map(|v| format!("{:?}", v))
        .collect();
    assert_eq!(dbgs.len(), 6);
}

// ---------------------------------------------------------------------------
// PolicyConstraint — Clone / BTreeSet / Debug / tag
// ---------------------------------------------------------------------------

#[test]
fn enrichment_policy_constraint_clone_independence() {
    let a = PolicyConstraint::MaxCost {
        limit_millionths: 50_000,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_policy_constraint_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(PolicyConstraint::MaxCost {
        limit_millionths: 50_000,
    });
    set.insert(PolicyConstraint::MaxRegret {
        limit_millionths: 30_000,
    });
    set.insert(PolicyConstraint::MinReward {
        threshold_millionths: 10_000,
    });
    set.insert(PolicyConstraint::MaxCost {
        limit_millionths: 50_000,
    });
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_policy_constraint_debug_nonempty() {
    let c = PolicyConstraint::ForceStrategy {
        strategy_id: "s1".to_string(),
    };
    assert!(!format!("{:?}", c).is_empty());
}

#[test]
fn enrichment_policy_constraint_serde_roundtrip_all() {
    let constraints = vec![
        PolicyConstraint::AllowedKinds {
            kinds: BTreeSet::from([StrategyKind::Tiering]),
        },
        PolicyConstraint::ForbiddenStrategies {
            strategy_ids: BTreeSet::from(["x".to_string()]),
        },
        PolicyConstraint::MaxCost {
            limit_millionths: 50_000,
        },
        PolicyConstraint::MaxRegret {
            limit_millionths: 30_000,
        },
        PolicyConstraint::MinReward {
            threshold_millionths: 10_000,
        },
        PolicyConstraint::ForceStrategy {
            strategy_id: "s1".to_string(),
        },
    ];
    for c in &constraints {
        let json = serde_json::to_string(c).unwrap();
        let rt: PolicyConstraint = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, rt);
    }
}

// ---------------------------------------------------------------------------
// SelectionReason — Clone / Debug / is_acceptance / tag
// ---------------------------------------------------------------------------

#[test]
fn enrichment_selection_reason_clone_independence() {
    let a = SelectionReason::FallbackToDefault;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_selection_reason_debug_nonempty() {
    let r = SelectionReason::HighestNetValue {
        net_value_millionths: 100_000,
    };
    assert!(!format!("{:?}", r).is_empty());
}

#[test]
fn enrichment_selection_reason_is_acceptance_includes_fallback() {
    let acceptance = [
        SelectionReason::HighestNetValue {
            net_value_millionths: 1,
        },
        SelectionReason::OperatorOverride {
            strategy_id: "x".to_string(),
        },
        SelectionReason::FallbackToDefault,
    ];
    for r in &acceptance {
        assert!(r.is_acceptance(), "should be acceptance: {:?}", r);
    }
    let non_acceptance = [
        SelectionReason::KindNotAllowed,
        SelectionReason::Forbidden,
        SelectionReason::CostExceeded { cost: 1, limit: 0 },
        SelectionReason::RegretExceeded {
            regret: 1,
            budget: 0,
        },
        SelectionReason::RewardBelowThreshold {
            reward: 0,
            threshold: 1,
        },
        SelectionReason::MissingFeatures {
            missing: BTreeSet::new(),
        },
    ];
    for r in &non_acceptance {
        assert!(!r.is_acceptance(), "should not be acceptance: {:?}", r);
    }
}

#[test]
fn enrichment_selection_reason_tags_all_unique() {
    let reasons = [
        SelectionReason::HighestNetValue {
            net_value_millionths: 1,
        },
        SelectionReason::OperatorOverride {
            strategy_id: "x".to_string(),
        },
        SelectionReason::FallbackToDefault,
        SelectionReason::KindNotAllowed,
        SelectionReason::Forbidden,
        SelectionReason::CostExceeded { cost: 1, limit: 0 },
        SelectionReason::RegretExceeded {
            regret: 1,
            budget: 0,
        },
        SelectionReason::RewardBelowThreshold {
            reward: 0,
            threshold: 1,
        },
        SelectionReason::MissingFeatures {
            missing: BTreeSet::new(),
        },
    ];
    let tags: BTreeSet<&str> = reasons.iter().map(|r| r.tag()).collect();
    assert_eq!(tags.len(), 9);
}

// ---------------------------------------------------------------------------
// WorkloadContext — Clone / Debug / JSON fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_workload_context_clone_independence() {
    let a = make_context();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_workload_context_debug_nonempty() {
    assert!(!format!("{:?}", make_context()).is_empty());
}

#[test]
fn enrichment_workload_context_json_field_names() {
    let ctx = make_context();
    let json = serde_json::to_string(&ctx).unwrap();
    assert!(json.contains("\"features\""));
    assert!(json.contains("\"label\""));
}

#[test]
fn enrichment_workload_context_feature_count() {
    let ctx = make_context();
    assert_eq!(ctx.feature_count(), 3);
}

// ---------------------------------------------------------------------------
// OptimizationStrategy — Clone / Debug / JSON fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_optimization_strategy_clone_independence() {
    let a = make_strategy("s1", StrategyKind::Tiering, 100_000, 20_000);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_optimization_strategy_debug_nonempty() {
    assert!(
        !format!(
            "{:?}",
            make_strategy("s1", StrategyKind::Tiering, 100_000, 20_000)
        )
        .is_empty()
    );
}

#[test]
fn enrichment_optimization_strategy_json_field_names() {
    let s = make_strategy("s1", StrategyKind::Tiering, 100_000, 20_000);
    let json = serde_json::to_string(&s).unwrap();
    for field in &[
        "strategy_id",
        "kind",
        "name",
        "expected_reward_millionths",
        "cost_millionths",
        "worst_case_regret_millionths",
        "required_features",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

// ---------------------------------------------------------------------------
// SelectionDecision — Clone / Debug / JSON fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_selection_decision_clone_independence() {
    let selector = make_selector();
    let ctx = make_context();
    let dec = selector.select(&ctx, SecurityEpoch::from_raw(1));
    let dec2 = dec.clone();
    assert_eq!(dec, dec2);
}

#[test]
fn enrichment_selection_decision_debug_nonempty() {
    let selector = make_selector();
    let ctx = make_context();
    let dec = selector.select(&ctx, SecurityEpoch::from_raw(1));
    assert!(!format!("{:?}", dec).is_empty());
}

#[test]
fn enrichment_selection_decision_json_field_names() {
    let selector = make_selector();
    let ctx = make_context();
    let dec = selector.select(&ctx, SecurityEpoch::from_raw(1));
    let json = serde_json::to_string(&dec).unwrap();
    for field in &[
        "schema_version",
        "epoch",
        "selected_strategy_id",
        "selected_kind",
        "reason",
        "candidate_evaluations",
        "feasible_count",
        "infeasible_count",
        "content_hash",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_selection_decision_has_selection() {
    let selector = make_selector();
    let ctx = make_context();
    let dec = selector.select(&ctx, SecurityEpoch::from_raw(1));
    assert!(dec.has_selection());
}

#[test]
fn enrichment_selection_decision_not_fallback_when_strategy_available() {
    let selector = make_selector();
    let ctx = make_context();
    let dec = selector.select(&ctx, SecurityEpoch::from_raw(1));
    assert!(!dec.is_fallback());
}

#[test]
fn enrichment_selection_decision_is_fallback_when_empty() {
    let selector = ContextualSelector::with_defaults(vec![], vec![]);
    let ctx = make_context();
    let dec = selector.select(&ctx, SecurityEpoch::from_raw(1));
    assert!(dec.is_fallback());
    assert!(!dec.has_selection());
}

// ---------------------------------------------------------------------------
// ContextualSelector — Clone / Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_contextual_selector_clone_independence() {
    let a = make_selector();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_contextual_selector_debug_nonempty() {
    assert!(!format!("{:?}", make_selector()).is_empty());
}

#[test]
fn enrichment_contextual_selector_with_defaults_budget() {
    let sel = ContextualSelector::with_defaults(vec![], vec![]);
    assert_eq!(sel.exploration_budget, DEFAULT_EXPLORATION_BUDGET);
}

// ---------------------------------------------------------------------------
// Constants stability
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_exact_values() {
    assert_eq!(
        SCHEMA_VERSION,
        "franken-engine.contextual-policy-selector.v1"
    );
    assert_eq!(COMPONENT, "contextual_policy_selector");
    assert_eq!(BEAD_ID, "bd-1lsy.7.8.1");
    assert_eq!(POLICY_ID, "RGC-608A");
    assert_eq!(MAX_STRATEGIES, 32);
    assert_eq!(DEFAULT_EXPLORATION_BUDGET, 50_000);
    assert_eq!(MAX_REGRET_BUDGET, 100_000);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_five_run_determinism_select() {
    let selector = make_selector();
    let ctx = make_context();
    let hashes: BTreeSet<String> = (0..5)
        .map(|_| {
            let dec = selector.select(&ctx, SecurityEpoch::from_raw(1));
            serde_json::to_string(&dec).unwrap()
        })
        .collect();
    assert_eq!(hashes.len(), 1, "select should be deterministic");
}

// ---------------------------------------------------------------------------
// Cross-cutting invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cross_cutting_highest_net_value_wins() {
    let strategies = vec![
        make_strategy("low", StrategyKind::Tiering, 50_000, 10_000),
        make_strategy("high", StrategyKind::CachePolicy, 200_000, 10_000),
    ];
    let selector = ContextualSelector::with_defaults(strategies, vec![]);
    let ctx = make_context();
    let dec = selector.select(&ctx, SecurityEpoch::from_raw(1));
    assert_eq!(dec.selected_strategy_id.as_deref(), Some("high"));
}

#[test]
fn enrichment_cross_cutting_constraint_reduces_feasible() {
    let strategies = vec![
        make_strategy("s1", StrategyKind::Tiering, 100_000, 20_000),
        make_strategy("s2", StrategyKind::CachePolicy, 80_000, 10_000),
    ];
    let constraints = vec![PolicyConstraint::AllowedKinds {
        kinds: BTreeSet::from([StrategyKind::CachePolicy]),
    }];
    let selector = ContextualSelector::with_defaults(strategies, constraints);
    let ctx = make_context();
    let dec = selector.select(&ctx, SecurityEpoch::from_raw(1));
    assert_eq!(dec.selected_strategy_id.as_deref(), Some("s2"));
}

#[test]
fn enrichment_cross_cutting_feasible_plus_infeasible_equals_total() {
    let strategies = vec![
        make_strategy("s1", StrategyKind::Tiering, 100_000, 20_000),
        make_strategy("s2", StrategyKind::CachePolicy, 80_000, 10_000),
    ];
    let constraints = vec![PolicyConstraint::MaxCost {
        limit_millionths: 15_000,
    }];
    let selector = ContextualSelector::with_defaults(strategies, constraints);
    let ctx = make_context();
    let dec = selector.select(&ctx, SecurityEpoch::from_raw(1));
    assert_eq!(dec.feasible_count + dec.infeasible_count, 2);
}

#[test]
fn enrichment_cross_cutting_schema_version_in_decision() {
    let selector = make_selector();
    let ctx = make_context();
    let dec = selector.select(&ctx, SecurityEpoch::from_raw(1));
    assert_eq!(dec.schema_version, SCHEMA_VERSION);
}

// ===== PearlTower enrichment batch 2 — 2026-03-14 =====

// ---------------------------------------------------------------------------
// OptimizationStrategy — net_value / within_regret_budget / context_satisfies
// ---------------------------------------------------------------------------

#[test]
fn enrichment_strategy_net_value_reward_minus_cost() {
    let s = make_strategy("s-nv", StrategyKind::Tiering, 100_000, 20_000);
    assert_eq!(s.net_value(), 80_000);
}

#[test]
fn enrichment_strategy_net_value_zero_when_cost_exceeds_reward() {
    let s = make_strategy("s-neg", StrategyKind::Tiering, 10_000, 50_000);
    // saturating_sub means no underflow
    assert_eq!(s.net_value(), 0);
}

#[test]
fn enrichment_strategy_within_regret_budget_true() {
    let s = make_strategy("s-rb", StrategyKind::CachePolicy, 100_000, 20_000);
    // worst_case_regret = cost / 2 = 10_000
    assert!(s.within_regret_budget(10_000));
    assert!(s.within_regret_budget(20_000));
}

#[test]
fn enrichment_strategy_within_regret_budget_false() {
    let s = make_strategy("s-rb2", StrategyKind::CachePolicy, 100_000, 40_000);
    // worst_case_regret = 20_000
    assert!(!s.within_regret_budget(10_000));
}

#[test]
fn enrichment_strategy_context_satisfies_no_requirements() {
    let s = make_strategy("s-ctx", StrategyKind::Tiering, 100_000, 20_000);
    let ctx = make_context();
    assert!(
        s.context_satisfies(&ctx),
        "empty required_features should always be satisfied"
    );
}

#[test]
fn enrichment_strategy_context_satisfies_with_features() {
    let mut s = make_strategy("s-ctx2", StrategyKind::Tiering, 100_000, 20_000);
    s.required_features = BTreeSet::from([FeatureKey::RequestRate]);
    let ctx = make_context();
    assert!(s.context_satisfies(&ctx));
}

#[test]
fn enrichment_strategy_context_not_satisfied_missing_feature() {
    let mut s = make_strategy("s-ctx3", StrategyKind::Tiering, 100_000, 20_000);
    s.required_features = BTreeSet::from([FeatureKey::GcPauseFrequency]);
    let ctx = make_context();
    assert!(
        !s.context_satisfies(&ctx),
        "GcPauseFrequency not in context, should fail"
    );
}

// ---------------------------------------------------------------------------
// WorkloadContext — with_label / get
// ---------------------------------------------------------------------------

#[test]
fn enrichment_workload_context_with_label() {
    let features = BTreeMap::from([(FeatureKey::RequestRate, 500)]);
    let ctx = WorkloadContext::with_label(features, "high-traffic");
    assert_eq!(ctx.label.as_deref(), Some("high-traffic"));
    assert_eq!(ctx.get(FeatureKey::RequestRate), Some(500));
}

#[test]
fn enrichment_workload_context_get_present() {
    let ctx = make_context();
    assert_eq!(ctx.get(FeatureKey::RequestRate), Some(1000));
    assert_eq!(ctx.get(FeatureKey::PayloadSize), Some(512));
}

#[test]
fn enrichment_workload_context_get_absent() {
    let ctx = make_context();
    assert_eq!(ctx.get(FeatureKey::GcPauseFrequency), None);
}

#[test]
fn enrichment_workload_context_serde_roundtrip() {
    let ctx = make_context();
    let json = serde_json::to_string(&ctx).unwrap();
    let restored: WorkloadContext = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx, restored);
}

// ---------------------------------------------------------------------------
// PolicyConstraint::tag() — all unique
// ---------------------------------------------------------------------------

#[test]
fn enrichment_policy_constraint_tags_all_unique() {
    let constraints = [
        PolicyConstraint::AllowedKinds {
            kinds: BTreeSet::new(),
        },
        PolicyConstraint::ForbiddenStrategies {
            strategy_ids: BTreeSet::new(),
        },
        PolicyConstraint::MaxCost {
            limit_millionths: 0,
        },
        PolicyConstraint::MaxRegret {
            limit_millionths: 0,
        },
        PolicyConstraint::MinReward {
            threshold_millionths: 0,
        },
        PolicyConstraint::ForceStrategy {
            strategy_id: "x".to_string(),
        },
    ];
    let tags: BTreeSet<&str> = constraints.iter().map(|c| c.tag()).collect();
    assert_eq!(
        tags.len(),
        6,
        "each constraint variant must have a unique tag"
    );
}

// ---------------------------------------------------------------------------
// SelectionDecision::is_override
// ---------------------------------------------------------------------------

#[test]
fn enrichment_selection_decision_is_override_with_force() {
    let strategies = vec![make_strategy("s1", StrategyKind::Tiering, 100_000, 20_000)];
    let constraints = vec![PolicyConstraint::ForceStrategy {
        strategy_id: "s1".to_string(),
    }];
    let selector = ContextualSelector::with_defaults(strategies, constraints);
    let ctx = make_context();
    let dec = selector.select(&ctx, SecurityEpoch::from_raw(1));
    assert!(dec.is_override(), "ForceStrategy should produce override");
    assert_eq!(dec.selected_strategy_id.as_deref(), Some("s1"));
}

// ---------------------------------------------------------------------------
// ForbiddenStrategies constraint
// ---------------------------------------------------------------------------

#[test]
fn enrichment_forbidden_strategy_excluded() {
    let strategies = vec![
        make_strategy("good", StrategyKind::CachePolicy, 200_000, 10_000),
        make_strategy("bad", StrategyKind::Tiering, 300_000, 5_000),
    ];
    let constraints = vec![PolicyConstraint::ForbiddenStrategies {
        strategy_ids: BTreeSet::from(["bad".to_string()]),
    }];
    let selector = ContextualSelector::with_defaults(strategies, constraints);
    let ctx = make_context();
    let dec = selector.select(&ctx, SecurityEpoch::from_raw(1));
    assert_eq!(
        dec.selected_strategy_id.as_deref(),
        Some("good"),
        "forbidden strategy should be excluded despite higher net value"
    );
}

// ---------------------------------------------------------------------------
// MinReward constraint filters low-reward strategies
// ---------------------------------------------------------------------------

#[test]
fn enrichment_min_reward_filters_low_reward() {
    let strategies = vec![
        make_strategy("low", StrategyKind::Tiering, 5_000, 1_000),
        make_strategy("high", StrategyKind::CachePolicy, 200_000, 10_000),
    ];
    let constraints = vec![PolicyConstraint::MinReward {
        threshold_millionths: 100_000,
    }];
    let selector = ContextualSelector::with_defaults(strategies, constraints);
    let ctx = make_context();
    let dec = selector.select(&ctx, SecurityEpoch::from_raw(1));
    assert_eq!(
        dec.selected_strategy_id.as_deref(),
        Some("high"),
        "low-reward strategy should be filtered"
    );
}

// ---------------------------------------------------------------------------
// MaxRegret constraint
// ---------------------------------------------------------------------------

#[test]
fn enrichment_max_regret_filters_risky() {
    let mut risky = make_strategy("risky", StrategyKind::Tiering, 500_000, 400_000);
    risky.worst_case_regret_millionths = 90_000;
    let safe = make_strategy("safe", StrategyKind::CachePolicy, 100_000, 10_000);
    let constraints = vec![PolicyConstraint::MaxRegret {
        limit_millionths: 50_000,
    }];
    let selector = ContextualSelector::with_defaults(vec![risky, safe], constraints);
    let ctx = make_context();
    let dec = selector.select(&ctx, SecurityEpoch::from_raw(1));
    assert_eq!(dec.selected_strategy_id.as_deref(), Some("safe"));
}

// ---------------------------------------------------------------------------
// ContextualSelector — strategy_count / new with custom budget
// ---------------------------------------------------------------------------

#[test]
fn enrichment_selector_strategy_count() {
    let selector = make_selector();
    assert_eq!(selector.strategy_count(), 2);
}

#[test]
fn enrichment_selector_strategy_count_empty() {
    let selector = ContextualSelector::with_defaults(vec![], vec![]);
    assert_eq!(selector.strategy_count(), 0);
}

#[test]
fn enrichment_selector_new_custom_budget() {
    let selector = ContextualSelector::new(vec![], vec![], 99_000);
    assert_eq!(selector.exploration_budget, 99_000);
}

// ---------------------------------------------------------------------------
// Serde roundtrips for OptimizationStrategy, SelectionDecision
// ---------------------------------------------------------------------------

#[test]
fn enrichment_optimization_strategy_serde_roundtrip() {
    let s = make_strategy("s-rt", StrategyKind::Tiering, 100_000, 20_000);
    let json = serde_json::to_string(&s).unwrap();
    let restored: OptimizationStrategy = serde_json::from_str(&json).unwrap();
    assert_eq!(s, restored);
}

#[test]
fn enrichment_selection_decision_serde_roundtrip() {
    let selector = make_selector();
    let ctx = make_context();
    let dec = selector.select(&ctx, SecurityEpoch::from_raw(1));
    let json = serde_json::to_string(&dec).unwrap();
    let restored: frankenengine_engine::contextual_policy_selector::SelectionDecision =
        serde_json::from_str(&json).unwrap();
    assert_eq!(dec, restored);
}

// ---------------------------------------------------------------------------
// FeatureKey::as_str — all unique non-empty
// ---------------------------------------------------------------------------

#[test]
fn enrichment_feature_key_as_str_all_unique() {
    let strs: BTreeSet<&str> = FeatureKey::ALL.iter().map(|k| k.as_str()).collect();
    assert_eq!(strs.len(), FeatureKey::ALL.len());
    for s in &strs {
        assert!(!s.is_empty());
    }
}

// ---------------------------------------------------------------------------
// StrategyKind::as_str — all unique non-empty
// ---------------------------------------------------------------------------

#[test]
fn enrichment_strategy_kind_as_str_all_unique() {
    let strs: BTreeSet<&str> = StrategyKind::ALL.iter().map(|k| k.as_str()).collect();
    assert_eq!(strs.len(), StrategyKind::ALL.len());
    for s in &strs {
        assert!(!s.is_empty());
    }
}

// ---------------------------------------------------------------------------
// ContextualSelector serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_contextual_selector_serde_roundtrip() {
    let selector = make_selector();
    let json = serde_json::to_string(&selector).unwrap();
    let restored: ContextualSelector = serde_json::from_str(&json).unwrap();
    assert_eq!(selector, restored);
}

// ---------------------------------------------------------------------------
// MaxCost constraint filters expensive strategies
// ---------------------------------------------------------------------------

#[test]
fn enrichment_max_cost_filters_expensive() {
    let strategies = vec![
        make_strategy("cheap", StrategyKind::Tiering, 50_000, 5_000),
        make_strategy("expensive", StrategyKind::CachePolicy, 200_000, 100_000),
    ];
    let constraints = vec![PolicyConstraint::MaxCost {
        limit_millionths: 10_000,
    }];
    let selector = ContextualSelector::with_defaults(strategies, constraints);
    let ctx = make_context();
    let dec = selector.select(&ctx, SecurityEpoch::from_raw(1));
    assert_eq!(
        dec.selected_strategy_id.as_deref(),
        Some("cheap"),
        "expensive strategy should be filtered by MaxCost"
    );
}

// ---------------------------------------------------------------------------
// Missing features produces MissingFeatures reason
// ---------------------------------------------------------------------------

#[test]
fn enrichment_missing_features_filters_strategy() {
    let mut s = make_strategy("needs-gc", StrategyKind::Tiering, 500_000, 10_000);
    s.required_features = BTreeSet::from([FeatureKey::GcPauseFrequency, FeatureKey::ModuleCount]);
    let fallback = make_strategy("basic", StrategyKind::Default, 10_000, 1_000);
    let selector = ContextualSelector::with_defaults(vec![s, fallback], vec![]);
    let ctx = make_context(); // does not have GcPauseFrequency or ModuleCount
    let dec = selector.select(&ctx, SecurityEpoch::from_raw(1));
    // The strategy needing missing features should be filtered; basic should win
    assert_eq!(dec.selected_strategy_id.as_deref(), Some("basic"));
}
