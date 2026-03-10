//! Integration tests for `contextual_policy_selector` module.
//!
//! Validates public API, serde contracts, determinism, selection logic,
//! constraint enforcement, and operator overrides.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::contextual_policy_selector::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(600)
}

fn ctx_full() -> WorkloadContext {
    let mut features = BTreeMap::new();
    features.insert(FeatureKey::RequestRate, 500_000);
    features.insert(FeatureKey::MemoryPressure, 300_000);
    features.insert(FeatureKey::CacheHitRatio, 800_000);
    features.insert(FeatureKey::HotFunctionCount, 100_000);
    WorkloadContext::new(features)
}

fn ctx_minimal() -> WorkloadContext {
    let mut features = BTreeMap::new();
    features.insert(FeatureKey::RequestRate, 500_000);
    WorkloadContext::new(features)
}

fn strategy_tier() -> OptimizationStrategy {
    OptimizationStrategy {
        strategy_id: "tier-opt".into(),
        kind: StrategyKind::Tiering,
        name: "Aggressive tiering".into(),
        expected_reward_millionths: 200_000,
        cost_millionths: 50_000,
        worst_case_regret_millionths: 80_000,
        required_features: BTreeSet::from([FeatureKey::RequestRate]),
    }
}

fn strategy_cache() -> OptimizationStrategy {
    OptimizationStrategy {
        strategy_id: "cache-opt".into(),
        kind: StrategyKind::CachePolicy,
        name: "Smart cache".into(),
        expected_reward_millionths: 150_000,
        cost_millionths: 20_000,
        worst_case_regret_millionths: 40_000,
        required_features: BTreeSet::from([FeatureKey::CacheHitRatio]),
    }
}

fn strategy_spec() -> OptimizationStrategy {
    OptimizationStrategy {
        strategy_id: "spec-opt".into(),
        kind: StrategyKind::Specialization,
        name: "Specialization".into(),
        expected_reward_millionths: 300_000,
        cost_millionths: 100_000,
        worst_case_regret_millionths: 150_000,
        required_features: BTreeSet::from([FeatureKey::HotFunctionCount]),
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_format() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn component_name() {
    assert_eq!(COMPONENT, "contextual_policy_selector");
}

#[test]
fn bead_id_format() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn policy_id_format() {
    assert!(POLICY_ID.starts_with("RGC-"));
}

#[test]
fn budget_constraints() {
    assert!(DEFAULT_EXPLORATION_BUDGET > 0);
    assert!(MAX_REGRET_BUDGET > DEFAULT_EXPLORATION_BUDGET);
}

// ---------------------------------------------------------------------------
// FeatureKey
// ---------------------------------------------------------------------------

#[test]
fn feature_key_all_length() {
    assert_eq!(FeatureKey::ALL.len(), 8);
}

#[test]
fn feature_key_names_unique() {
    let names: BTreeSet<&str> = FeatureKey::ALL.iter().map(|k| k.as_str()).collect();
    assert_eq!(names.len(), FeatureKey::ALL.len());
}

#[test]
fn feature_key_display_matches_as_str() {
    for k in FeatureKey::ALL {
        assert_eq!(k.to_string(), k.as_str());
    }
}

#[test]
fn feature_key_serde_all() {
    for k in FeatureKey::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: FeatureKey = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

// ---------------------------------------------------------------------------
// StrategyKind
// ---------------------------------------------------------------------------

#[test]
fn strategy_kind_all_length() {
    assert_eq!(StrategyKind::ALL.len(), 6);
}

#[test]
fn strategy_kind_names_unique() {
    let names: BTreeSet<&str> = StrategyKind::ALL.iter().map(|k| k.as_str()).collect();
    assert_eq!(names.len(), StrategyKind::ALL.len());
}

#[test]
fn strategy_kind_display_matches_as_str() {
    for k in StrategyKind::ALL {
        assert_eq!(k.to_string(), k.as_str());
    }
}

#[test]
fn strategy_kind_serde_all() {
    for k in StrategyKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: StrategyKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

// ---------------------------------------------------------------------------
// WorkloadContext
// ---------------------------------------------------------------------------

#[test]
fn context_creation() {
    let ctx = ctx_full();
    assert_eq!(ctx.feature_count(), 4);
    assert_eq!(ctx.get(FeatureKey::RequestRate), Some(500_000));
}

#[test]
fn context_missing_feature() {
    let ctx = ctx_minimal();
    assert!(ctx.get(FeatureKey::CacheHitRatio).is_none());
}

#[test]
fn context_with_label() {
    let ctx = WorkloadContext::with_label(BTreeMap::new(), "test-workload");
    assert_eq!(ctx.label.as_deref(), Some("test-workload"));
    assert_eq!(ctx.feature_count(), 0);
}

#[test]
fn context_serde_roundtrip() {
    let ctx = ctx_full();
    let json = serde_json::to_string(&ctx).unwrap();
    let back: WorkloadContext = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx, back);
}

// ---------------------------------------------------------------------------
// OptimizationStrategy
// ---------------------------------------------------------------------------

#[test]
fn strategy_net_value() {
    let s = strategy_tier();
    assert_eq!(s.net_value(), 150_000);
}

#[test]
fn strategy_regret_budget_check() {
    let s = strategy_tier();
    assert!(s.within_regret_budget(100_000));
    assert!(!s.within_regret_budget(50_000));
}

#[test]
fn strategy_context_satisfies_full() {
    let s = strategy_tier();
    assert!(s.context_satisfies(&ctx_full()));
}

#[test]
fn strategy_context_missing_required() {
    let s = strategy_cache();
    assert!(!s.context_satisfies(&ctx_minimal()));
}

#[test]
fn strategy_serde_roundtrip() {
    let s = strategy_spec();
    let json = serde_json::to_string(&s).unwrap();
    let back: OptimizationStrategy = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ---------------------------------------------------------------------------
// PolicyConstraint
// ---------------------------------------------------------------------------

#[test]
fn constraint_tags_unique() {
    let constraints = vec![
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
            strategy_id: "x".into(),
        },
    ];
    let tags: BTreeSet<&str> = constraints.iter().map(|c| c.tag()).collect();
    assert_eq!(tags.len(), 6);
}

#[test]
fn constraint_display_content() {
    let c = PolicyConstraint::MaxCost {
        limit_millionths: 50_000,
    };
    assert!(c.to_string().contains("50000"));
}

#[test]
fn constraint_serde_roundtrip() {
    let c = PolicyConstraint::AllowedKinds {
        kinds: BTreeSet::from([StrategyKind::Tiering, StrategyKind::CachePolicy]),
    };
    let json = serde_json::to_string(&c).unwrap();
    let back: PolicyConstraint = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// SelectionReason
// ---------------------------------------------------------------------------

#[test]
fn reason_acceptance_semantics() {
    assert!(
        SelectionReason::HighestNetValue {
            net_value_millionths: 100
        }
        .is_acceptance()
    );
    assert!(
        SelectionReason::OperatorOverride {
            strategy_id: "x".into()
        }
        .is_acceptance()
    );
    assert!(SelectionReason::FallbackToDefault.is_acceptance());
    assert!(!SelectionReason::KindNotAllowed.is_acceptance());
    assert!(!SelectionReason::Forbidden.is_acceptance());
    assert!(!SelectionReason::CostExceeded { cost: 0, limit: 0 }.is_acceptance());
}

#[test]
fn reason_tags_unique() {
    let reasons = vec![
        SelectionReason::HighestNetValue {
            net_value_millionths: 0,
        },
        SelectionReason::OperatorOverride {
            strategy_id: "x".into(),
        },
        SelectionReason::FallbackToDefault,
        SelectionReason::KindNotAllowed,
        SelectionReason::Forbidden,
        SelectionReason::CostExceeded { cost: 0, limit: 0 },
        SelectionReason::RegretExceeded {
            regret: 0,
            budget: 0,
        },
        SelectionReason::RewardBelowThreshold {
            reward: 0,
            threshold: 0,
        },
        SelectionReason::MissingFeatures {
            missing: BTreeSet::new(),
        },
    ];
    let tags: BTreeSet<&str> = reasons.iter().map(|r| r.tag()).collect();
    assert_eq!(tags.len(), 9);
}

// ---------------------------------------------------------------------------
// Selection — basic
// ---------------------------------------------------------------------------

#[test]
fn select_empty_strategies_fallback() {
    let sel = ContextualSelector::with_defaults(Vec::new(), Vec::new());
    let d = sel.select(&ctx_full(), epoch());
    assert!(d.is_fallback());
    assert!(!d.has_selection());
}

#[test]
fn select_single_strategy() {
    let sel = ContextualSelector::with_defaults(vec![strategy_tier()], Vec::new());
    let d = sel.select(&ctx_full(), epoch());
    assert!(d.has_selection());
    assert_eq!(d.selected_strategy_id.as_deref(), Some("tier-opt"));
}

#[test]
fn select_highest_net_value() {
    let sel = ContextualSelector::with_defaults(
        vec![strategy_tier(), strategy_cache(), strategy_spec()],
        Vec::new(),
    );
    let d = sel.select(&ctx_full(), epoch());
    // spec has highest net value: 300k-100k = 200k > tier 150k > cache 130k
    assert_eq!(d.selected_strategy_id.as_deref(), Some("spec-opt"));
}

// ---------------------------------------------------------------------------
// Selection — constraints
// ---------------------------------------------------------------------------

#[test]
fn select_cost_constraint_filters() {
    let sel = ContextualSelector::with_defaults(
        vec![strategy_tier(), strategy_cache()],
        vec![PolicyConstraint::MaxCost {
            limit_millionths: 30_000,
        }],
    );
    let d = sel.select(&ctx_full(), epoch());
    // tier costs 50k > 30k limit, only cache (20k) feasible
    assert_eq!(d.selected_strategy_id.as_deref(), Some("cache-opt"));
}

#[test]
fn select_regret_constraint_filters() {
    let sel = ContextualSelector::with_defaults(
        vec![strategy_tier(), strategy_cache()],
        vec![PolicyConstraint::MaxRegret {
            limit_millionths: 50_000,
        }],
    );
    let d = sel.select(&ctx_full(), epoch());
    // tier regret 80k > 50k, only cache (40k) feasible
    assert_eq!(d.selected_strategy_id.as_deref(), Some("cache-opt"));
}

#[test]
fn select_kind_constraint_filters() {
    let sel = ContextualSelector::with_defaults(
        vec![strategy_tier(), strategy_cache()],
        vec![PolicyConstraint::AllowedKinds {
            kinds: BTreeSet::from([StrategyKind::CachePolicy]),
        }],
    );
    let d = sel.select(&ctx_full(), epoch());
    assert_eq!(d.selected_strategy_id.as_deref(), Some("cache-opt"));
}

#[test]
fn select_forbidden_constraint() {
    let sel = ContextualSelector::with_defaults(
        vec![strategy_tier(), strategy_cache()],
        vec![PolicyConstraint::ForbiddenStrategies {
            strategy_ids: BTreeSet::from(["tier-opt".to_string()]),
        }],
    );
    let d = sel.select(&ctx_full(), epoch());
    assert_eq!(d.selected_strategy_id.as_deref(), Some("cache-opt"));
}

#[test]
fn select_min_reward_constraint() {
    let sel = ContextualSelector::with_defaults(
        vec![strategy_tier(), strategy_cache()],
        vec![PolicyConstraint::MinReward {
            threshold_millionths: 180_000,
        }],
    );
    let d = sel.select(&ctx_full(), epoch());
    // cache reward 150k < 180k threshold, only tier (200k) feasible
    assert_eq!(d.selected_strategy_id.as_deref(), Some("tier-opt"));
}

#[test]
fn select_all_constrained_out_fallback() {
    let sel = ContextualSelector::with_defaults(
        vec![strategy_tier(), strategy_cache()],
        vec![PolicyConstraint::MaxCost {
            limit_millionths: 10_000,
        }],
    );
    let d = sel.select(&ctx_full(), epoch());
    // Both exceed 10k cost limit
    assert!(d.is_fallback());
}

// ---------------------------------------------------------------------------
// Selection — operator override
// ---------------------------------------------------------------------------

#[test]
fn select_operator_override() {
    let sel = ContextualSelector::with_defaults(
        vec![strategy_tier(), strategy_cache()],
        vec![PolicyConstraint::ForceStrategy {
            strategy_id: "cache-opt".into(),
        }],
    );
    let d = sel.select(&ctx_full(), epoch());
    assert!(d.is_override());
    assert_eq!(d.selected_strategy_id.as_deref(), Some("cache-opt"));
}

#[test]
fn select_override_ignores_other_constraints() {
    let sel = ContextualSelector::with_defaults(
        vec![strategy_tier()],
        vec![
            PolicyConstraint::ForceStrategy {
                strategy_id: "tier-opt".into(),
            },
            PolicyConstraint::MaxCost {
                limit_millionths: 1,
            },
        ],
    );
    let d = sel.select(&ctx_full(), epoch());
    // ForceStrategy takes precedence over cost constraint
    assert!(d.is_override());
    assert_eq!(d.selected_strategy_id.as_deref(), Some("tier-opt"));
}

// ---------------------------------------------------------------------------
// Selection — missing features
// ---------------------------------------------------------------------------

#[test]
fn select_missing_features_skips_strategy() {
    let sel = ContextualSelector::with_defaults(
        vec![strategy_spec()], // requires HotFunctionCount
        Vec::new(),
    );
    let d = sel.select(&ctx_minimal(), epoch());
    // ctx_minimal doesn't have HotFunctionCount
    assert!(d.is_fallback());
}

#[test]
fn select_partial_features_picks_feasible() {
    let sel = ContextualSelector::with_defaults(vec![strategy_tier(), strategy_spec()], Vec::new());
    let d = sel.select(&ctx_minimal(), epoch());
    // tier requires RequestRate (present), spec requires HotFunctionCount (missing)
    assert_eq!(d.selected_strategy_id.as_deref(), Some("tier-opt"));
}

// ---------------------------------------------------------------------------
// Decision properties
// ---------------------------------------------------------------------------

#[test]
fn decision_hash_deterministic() {
    let sel = ContextualSelector::with_defaults(vec![strategy_tier()], Vec::new());
    let d1 = sel.select(&ctx_full(), epoch());
    let d2 = sel.select(&ctx_full(), epoch());
    assert_eq!(d1.content_hash, d2.content_hash);
}

#[test]
fn decision_feasible_count() {
    let sel = ContextualSelector::with_defaults(
        vec![strategy_tier(), strategy_cache(), strategy_spec()],
        Vec::new(),
    );
    let d = sel.select(&ctx_full(), epoch());
    assert_eq!(d.feasible_count, 3);
    assert_eq!(d.infeasible_count, 0);
}

#[test]
fn decision_serde_roundtrip() {
    let sel =
        ContextualSelector::with_defaults(vec![strategy_tier(), strategy_cache()], Vec::new());
    let d = sel.select(&ctx_full(), epoch());
    let json = serde_json::to_string(&d).unwrap();
    let back: SelectionDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

// ---------------------------------------------------------------------------
// Selector serde
// ---------------------------------------------------------------------------

#[test]
fn selector_serde_roundtrip() {
    let sel = ContextualSelector::with_defaults(
        vec![strategy_tier(), strategy_cache()],
        vec![PolicyConstraint::MaxCost {
            limit_millionths: 100_000,
        }],
    );
    let json = serde_json::to_string(&sel).unwrap();
    let back: ContextualSelector = serde_json::from_str(&json).unwrap();
    assert_eq!(sel, back);
}

#[test]
fn selector_strategy_count() {
    let sel = ContextualSelector::with_defaults(
        vec![strategy_tier(), strategy_cache(), strategy_spec()],
        Vec::new(),
    );
    assert_eq!(sel.strategy_count(), 3);
}
