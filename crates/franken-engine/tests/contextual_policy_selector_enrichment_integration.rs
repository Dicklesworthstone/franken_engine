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
