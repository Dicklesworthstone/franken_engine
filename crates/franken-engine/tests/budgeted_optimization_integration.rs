//! Integration tests for the `budgeted_optimization` module.
//!
//! Exercises the public API from outside the crate boundary:
//! RewriteFamily, RewriteRule, BudgetKind, BudgetLimit, BudgetEnvelope,
//! SaturationOutcome, EGraphSnapshot, ExtractionPolicy, ExtractionResult,
//! InterferenceKind, InterferenceCheck, RollbackArtifact, CampaignStatus,
//! OptimizationCampaign, OptimizationError, OptimizationEventKind,
//! BudgetedOptimizationStack, OptimizationSummary.

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

use frankenengine_engine::budgeted_optimization::{
    BudgetEnvelope, BudgetKind, BudgetLimit, BudgetedOptimizationStack, CampaignStatus,
    EGraphSnapshot, EGraphSnapshotParts, ExtractionPolicy, ExtractionResult, InterferenceCheck, InterferenceKind,
    OPTIMIZATION_SCHEMA_VERSION, OptimizationCampaign, OptimizationError, OptimizationEventKind,
    OptimizationSummary, RewriteFamily, RewriteRule, RollbackArtifact, SaturationOutcome,
};
use frankenengine_engine::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_rule(id: &str, family: RewriteFamily, sound: bool) -> RewriteRule {
    RewriteRule {
        id: id.into(),
        family,
        description: format!("test rule {id}"),
        pattern_hash: ContentHash::compute(format!("pattern_{id}").as_bytes()),
        replacement_hash: ContentHash::compute(format!("replacement_{id}").as_bytes()),
        proof_obligations: vec!["po1".into()],
        metamorphic_checks: vec!["mc1".into()],
        sound,
        priority_millionths: 500_000,
        enabled: true,
    }
}

fn make_campaign(id: &str) -> OptimizationCampaign {
    OptimizationCampaign::new(
        id,
        &format!("campaign {id}"),
        ContentHash::compute(id.as_bytes()),
    )
}

fn make_egraph_snapshot() -> EGraphSnapshot {
    EGraphSnapshot {
        class_count: 100,
        node_count: 500,
        iteration_count: 10,
        rewrite_count: 50,
        outcome: SaturationOutcome::Saturated,
        state_hash: ContentHash::compute(b"egraph_state"),
        elapsed_ms: 200,
        peak_memory_bytes: 1024 * 1024,
    }
}

fn make_extraction_result() -> ExtractionResult {
    ExtractionResult {
        policy: ExtractionPolicy::MinCost,
        total_cost_millionths: 800_000,
        extracted_node_count: 50,
        proven_rewrite_count: 30,
        output_hash: ContentHash::compute(b"extracted"),
        families_used: {
            let mut s = BTreeSet::new();
            s.insert(RewriteFamily::AlgebraicSimplification);
            s.insert(RewriteFamily::DeadCodeElimination);
            s
        },
    }
}

fn make_rollback() -> RollbackArtifact {
    RollbackArtifact {
        campaign_id: "c1".into(),
        pre_optimization_hash: ContentHash::compute(b"pre"),
        post_optimization_hash: ContentHash::compute(b"post"),
        applied_rules: vec!["r1".into(), "r2".into()],
        rollback_tested: true,
        artifact_hash: ContentHash::compute(b"rollback"),
    }
}

// =========================================================================
// Constants
// =========================================================================

#[test]
fn schema_version_present() {
    assert!(!OPTIMIZATION_SCHEMA_VERSION.is_empty());
    assert!(OPTIMIZATION_SCHEMA_VERSION.contains("budgeted-optimization"));
}

// =========================================================================
// RewriteFamily
// =========================================================================

#[test]
fn rewrite_family_display() {
    assert_eq!(
        RewriteFamily::AlgebraicSimplification.to_string(),
        "algebraic_simplification"
    );
    assert_eq!(
        RewriteFamily::DeadCodeElimination.to_string(),
        "dead_code_elimination"
    );
    assert_eq!(
        RewriteFamily::CommonSubexpression.to_string(),
        "common_subexpression"
    );
    assert_eq!(
        RewriteFamily::PartialEvaluation.to_string(),
        "partial_evaluation"
    );
    assert_eq!(RewriteFamily::Custom.to_string(), "custom");
}

#[test]
fn rewrite_family_serde_roundtrip() {
    let families = [
        RewriteFamily::AlgebraicSimplification,
        RewriteFamily::DeadCodeElimination,
        RewriteFamily::CommonSubexpression,
        RewriteFamily::PartialEvaluation,
        RewriteFamily::MemoizationBoundary,
        RewriteFamily::EffectHoisting,
        RewriteFamily::HookSlotFusion,
        RewriteFamily::SignalGraphOptimization,
        RewriteFamily::Incrementalization,
        RewriteFamily::DomUpdateBatching,
        RewriteFamily::Custom,
    ];
    for f in &families {
        let json = serde_json::to_string(f).unwrap();
        let restored: RewriteFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*f, restored);
    }
}

// =========================================================================
// RewriteRule
// =========================================================================

#[test]
fn rewrite_rule_is_ready() {
    let rule = make_rule("r1", RewriteFamily::AlgebraicSimplification, true);
    assert!(rule.is_ready());

    let unsound = make_rule("r2", RewriteFamily::AlgebraicSimplification, false);
    assert!(!unsound.is_ready());

    let mut disabled = make_rule("r3", RewriteFamily::AlgebraicSimplification, true);
    disabled.enabled = false;
    assert!(!disabled.is_ready());
}

#[test]
fn rewrite_rule_serde_roundtrip() {
    let rule = make_rule("r1", RewriteFamily::PartialEvaluation, true);
    let json = serde_json::to_string(&rule).unwrap();
    let restored: RewriteRule = serde_json::from_str(&json).unwrap();
    assert_eq!(rule, restored);
}

// =========================================================================
// BudgetKind
// =========================================================================

#[test]
fn budget_kind_display() {
    assert_eq!(BudgetKind::TimeMs.to_string(), "time_ms");
    assert_eq!(BudgetKind::EgraphNodes.to_string(), "egraph_nodes");
    assert_eq!(BudgetKind::MemoryBytes.to_string(), "memory_bytes");
    assert_eq!(
        BudgetKind::RewriteApplications.to_string(),
        "rewrite_applications"
    );
    assert_eq!(
        BudgetKind::SaturationIterations.to_string(),
        "saturation_iterations"
    );
}

#[test]
fn budget_kind_serde_roundtrip() {
    for kind in &[
        BudgetKind::TimeMs,
        BudgetKind::EgraphNodes,
        BudgetKind::MemoryBytes,
        BudgetKind::RewriteApplications,
        BudgetKind::SaturationIterations,
    ] {
        let json = serde_json::to_string(kind).unwrap();
        let restored: BudgetKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, restored);
    }
}

// =========================================================================
// BudgetLimit
// =========================================================================

#[test]
fn budget_limit_new() {
    let limit = BudgetLimit::new(BudgetKind::TimeMs, 5_000);
    assert_eq!(limit.kind, BudgetKind::TimeMs);
    assert_eq!(limit.max_value, 5_000);
    assert_eq!(limit.current_value, 0);
    assert!(!limit.is_exhausted());
    assert_eq!(limit.remaining(), 5_000);
    assert_eq!(limit.utilization_millionths(), 0);
}

#[test]
fn budget_limit_consume() {
    let mut limit = BudgetLimit::new(BudgetKind::EgraphNodes, 100);
    assert!(limit.consume(50)); // Within limits
    assert_eq!(limit.current_value, 50);
    assert_eq!(limit.remaining(), 50);
    assert_eq!(limit.utilization_millionths(), 500_000);
    assert!(!limit.is_exhausted());

    assert!(limit.consume(50)); // Exactly at limit
    assert!(limit.is_exhausted());
    assert_eq!(limit.remaining(), 0);
}

#[test]
fn budget_limit_consume_over() {
    let mut limit = BudgetLimit::new(BudgetKind::TimeMs, 100);
    assert!(!limit.consume(200)); // Exceeds
    assert!(limit.is_exhausted());
}

#[test]
fn budget_limit_zero_max() {
    let limit = BudgetLimit::new(BudgetKind::TimeMs, 0);
    assert!(limit.is_exhausted());
    assert_eq!(limit.utilization_millionths(), 1_000_000);
}

#[test]
fn budget_limit_serde_roundtrip() {
    let mut limit = BudgetLimit::new(BudgetKind::MemoryBytes, 256_000_000);
    limit.consume(128_000_000);
    let json = serde_json::to_string(&limit).unwrap();
    let restored: BudgetLimit = serde_json::from_str(&json).unwrap();
    assert_eq!(limit, restored);
}

// =========================================================================
// BudgetEnvelope
// =========================================================================

#[test]
fn budget_envelope_production() {
    let env = BudgetEnvelope::production();
    assert!(!env.any_exhausted());
    assert!(env.get(BudgetKind::TimeMs).is_some());
    assert!(env.get(BudgetKind::EgraphNodes).is_some());
    assert!(env.get(BudgetKind::MemoryBytes).is_some());
    assert!(env.get(BudgetKind::RewriteApplications).is_some());
    assert!(env.get(BudgetKind::SaturationIterations).is_some());
}

#[test]
fn budget_envelope_default_is_production() {
    let default_env = BudgetEnvelope::default();
    let prod_env = BudgetEnvelope::production();
    assert_eq!(default_env, prod_env);
}

#[test]
fn budget_envelope_consume() {
    let mut env = BudgetEnvelope::production();
    assert!(env.consume(BudgetKind::TimeMs, 100));
    let time = env.get(BudgetKind::TimeMs).unwrap();
    assert_eq!(time.current_value, 100);
}

#[test]
fn budget_envelope_consume_unknown() {
    let mut env = BudgetEnvelope {
        limits: Default::default(),
    };
    // Consuming an unregistered kind returns true (unlimited)
    assert!(env.consume(BudgetKind::TimeMs, 999_999));
}

#[test]
fn budget_envelope_most_constrained() {
    let mut env = BudgetEnvelope::production();
    env.consume(BudgetKind::TimeMs, 4_999); // almost exhausted
    let most = env.most_constrained().unwrap();
    assert_eq!(most.kind, BudgetKind::TimeMs);
}

#[test]
fn budget_envelope_serde_roundtrip() {
    let env = BudgetEnvelope::production();
    let json = serde_json::to_string(&env).unwrap();
    let restored: BudgetEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(env, restored);
}

// =========================================================================
// SaturationOutcome
// =========================================================================

#[test]
fn saturation_outcome_display() {
    assert_eq!(SaturationOutcome::Saturated.to_string(), "saturated");
    assert_eq!(
        SaturationOutcome::BudgetExhausted.to_string(),
        "budget_exhausted"
    );
    assert_eq!(
        SaturationOutcome::NodeLimitReached.to_string(),
        "node_limit_reached"
    );
    assert_eq!(
        SaturationOutcome::IterationLimitReached.to_string(),
        "iteration_limit_reached"
    );
    assert_eq!(
        SaturationOutcome::PolicyStopped.to_string(),
        "policy_stopped"
    );
}

#[test]
fn saturation_outcome_serde_roundtrip() {
    for o in &[
        SaturationOutcome::Saturated,
        SaturationOutcome::BudgetExhausted,
        SaturationOutcome::NodeLimitReached,
        SaturationOutcome::IterationLimitReached,
        SaturationOutcome::PolicyStopped,
    ] {
        let json = serde_json::to_string(o).unwrap();
        let restored: SaturationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*o, restored);
    }
}

// =========================================================================
// EGraphSnapshot
// =========================================================================

#[test]
fn egraph_snapshot_serde_roundtrip() {
    let snap = make_egraph_snapshot();
    let json = serde_json::to_string(&snap).unwrap();
    let restored: EGraphSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snap, restored);
}

// =========================================================================
// ExtractionPolicy
// =========================================================================

#[test]
fn extraction_policy_default() {
    let policy = ExtractionPolicy::default();
    assert_eq!(policy, ExtractionPolicy::MinCost);
}

#[test]
fn extraction_policy_display() {
    assert_eq!(ExtractionPolicy::MinCost.to_string(), "min_cost");
    assert_eq!(ExtractionPolicy::MinSize.to_string(), "min_size");
    assert_eq!(
        ExtractionPolicy::MaxPerformance.to_string(),
        "max_performance"
    );
    assert_eq!(
        ExtractionPolicy::ProofAware {
            proof_weight_millionths: 500_000
        }
        .to_string(),
        "proof_aware"
    );
    assert_eq!(
        ExtractionPolicy::Custom {
            name: "my_cost".into()
        }
        .to_string(),
        "custom:my_cost"
    );
}

#[test]
fn extraction_policy_serde_roundtrip() {
    let policies = vec![
        ExtractionPolicy::MinCost,
        ExtractionPolicy::MinSize,
        ExtractionPolicy::MaxPerformance,
        ExtractionPolicy::ProofAware {
            proof_weight_millionths: 700_000,
        },
        ExtractionPolicy::Custom {
            name: "custom_fn".into(),
        },
    ];
    for p in &policies {
        let json = serde_json::to_string(p).unwrap();
        let restored: ExtractionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(*p, restored);
    }
}

// =========================================================================
// ExtractionResult
// =========================================================================

#[test]
fn extraction_result_serde_roundtrip() {
    let result = make_extraction_result();
    let json = serde_json::to_string(&result).unwrap();
    let restored: ExtractionResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

// =========================================================================
// InterferenceKind
// =========================================================================

#[test]
fn interference_kind_display() {
    assert_eq!(InterferenceKind::None.to_string(), "none");
    assert_eq!(
        InterferenceKind::RewriteConflict.to_string(),
        "rewrite_conflict"
    );
    assert_eq!(
        InterferenceKind::BudgetContention.to_string(),
        "budget_contention"
    );
    assert_eq!(
        InterferenceKind::SemanticInterference.to_string(),
        "semantic_interference"
    );
    assert_eq!(
        InterferenceKind::OrderDependence.to_string(),
        "order_dependence"
    );
}

// =========================================================================
// InterferenceCheck
// =========================================================================

#[test]
fn interference_check_serde_roundtrip() {
    let check = InterferenceCheck {
        campaign_a: "c1".into(),
        campaign_b: "c2".into(),
        kind: InterferenceKind::RewriteConflict,
        detail: "overlapping families".into(),
        blocking: true,
    };
    let json = serde_json::to_string(&check).unwrap();
    let restored: InterferenceCheck = serde_json::from_str(&json).unwrap();
    assert_eq!(check, restored);
}

// =========================================================================
// RollbackArtifact
// =========================================================================

#[test]
fn rollback_artifact_is_viable() {
    let rb = make_rollback();
    assert!(rb.is_viable());

    let not_tested = RollbackArtifact {
        rollback_tested: false,
        ..make_rollback()
    };
    assert!(!not_tested.is_viable());
}

#[test]
fn rollback_artifact_serde_roundtrip() {
    let rb = make_rollback();
    let json = serde_json::to_string(&rb).unwrap();
    let restored: RollbackArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(rb, restored);
}

// =========================================================================
// CampaignStatus
// =========================================================================

#[test]
fn campaign_status_display() {
    assert_eq!(CampaignStatus::Pending.to_string(), "pending");
    assert_eq!(CampaignStatus::Saturating.to_string(), "saturating");
    assert_eq!(CampaignStatus::Extracting.to_string(), "extracting");
    assert_eq!(CampaignStatus::Completed.to_string(), "completed");
    assert_eq!(CampaignStatus::Failed.to_string(), "failed");
    assert_eq!(CampaignStatus::RolledBack.to_string(), "rolled_back");
}

#[test]
fn campaign_status_serde_roundtrip() {
    for s in &[
        CampaignStatus::Pending,
        CampaignStatus::Saturating,
        CampaignStatus::Extracting,
        CampaignStatus::Completed,
        CampaignStatus::Failed,
        CampaignStatus::RolledBack,
    ] {
        let json = serde_json::to_string(s).unwrap();
        let restored: CampaignStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, restored);
    }
}

// =========================================================================
// OptimizationCampaign
// =========================================================================

#[test]
fn campaign_new() {
    let c = make_campaign("c1");
    assert_eq!(c.id, "c1");
    assert_eq!(c.status, CampaignStatus::Pending);
    assert!(!c.is_successful());
    assert_eq!(c.ready_rule_count(), 0);
}

#[test]
fn campaign_add_rule() {
    let mut c = make_campaign("c1");
    c.add_rule(make_rule(
        "r1",
        RewriteFamily::AlgebraicSimplification,
        true,
    ))
    .unwrap();
    assert_eq!(c.rules.len(), 1);
    assert_eq!(c.ready_rule_count(), 1);
}

#[test]
fn campaign_add_duplicate_rule_fails() {
    let mut c = make_campaign("c1");
    c.add_rule(make_rule(
        "r1",
        RewriteFamily::AlgebraicSimplification,
        true,
    ))
    .unwrap();
    let result = c.add_rule(make_rule("r1", RewriteFamily::DeadCodeElimination, true));
    assert!(matches!(result, Err(OptimizationError::DuplicateRule(_))));
}

#[test]
fn campaign_families() {
    let mut c = make_campaign("c1");
    c.add_rule(make_rule(
        "r1",
        RewriteFamily::AlgebraicSimplification,
        true,
    ))
    .unwrap();
    c.add_rule(make_rule("r2", RewriteFamily::DeadCodeElimination, true))
        .unwrap();
    let families = c.families();
    assert!(families.contains(&RewriteFamily::AlgebraicSimplification));
    assert!(families.contains(&RewriteFamily::DeadCodeElimination));
    assert_eq!(families.len(), 2);
}

#[test]
fn campaign_lifecycle_saturation_extraction() {
    let mut c = make_campaign("c1");
    c.add_rule(make_rule(
        "r1",
        RewriteFamily::AlgebraicSimplification,
        true,
    ))
    .unwrap();

    assert_eq!(c.status, CampaignStatus::Pending);

    c.record_saturation(make_egraph_snapshot());
    assert_eq!(c.status, CampaignStatus::Extracting);
    assert!(c.egraph_snapshot.is_some());

    c.record_extraction(make_extraction_result());
    assert_eq!(c.status, CampaignStatus::Completed);
    assert!(c.extraction_result.is_some());
    assert!(c.is_successful());
}

#[test]
fn campaign_failure() {
    let mut c = make_campaign("c1");
    c.record_failure();
    assert_eq!(c.status, CampaignStatus::Failed);
    assert!(!c.is_successful());
}

#[test]
fn campaign_rollback() {
    let mut c = make_campaign("c1");
    c.record_rollback(make_rollback());
    assert_eq!(c.status, CampaignStatus::RolledBack);
    assert!(c.rollback.is_some());
}

#[test]
fn campaign_serde_roundtrip() {
    let mut c = make_campaign("c1");
    c.add_rule(make_rule("r1", RewriteFamily::PartialEvaluation, true))
        .unwrap();
    c.record_saturation(make_egraph_snapshot());

    let json = serde_json::to_string(&c).unwrap();
    let restored: OptimizationCampaign = serde_json::from_str(&json).unwrap();
    assert_eq!(c, restored);
}

// =========================================================================
// OptimizationError
// =========================================================================

#[test]
fn optimization_error_display() {
    assert!(
        OptimizationError::RuleLimitExceeded {
            count: 1025,
            max: 1024
        }
        .to_string()
        .contains("1025")
    );
    assert!(
        OptimizationError::DuplicateRule("r1".into())
            .to_string()
            .contains("r1")
    );
    assert!(
        OptimizationError::DuplicateCampaign("c1".into())
            .to_string()
            .contains("c1")
    );
    assert!(
        OptimizationError::BudgetExhausted {
            kind: BudgetKind::TimeMs
        }
        .to_string()
        .contains("time_ms")
    );
    assert!(
        OptimizationError::UnsoundRewrite {
            rule_id: "bad".into()
        }
        .to_string()
        .contains("bad")
    );
}

#[test]
fn optimization_error_serde_roundtrip() {
    let err = OptimizationError::DuplicateRule("r1".into());
    let json = serde_json::to_string(&err).unwrap();
    let restored: OptimizationError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

// =========================================================================
// OptimizationEventKind
// =========================================================================

#[test]
fn event_kind_display() {
    assert_eq!(
        OptimizationEventKind::CampaignRegistered.to_string(),
        "campaign_registered"
    );
    assert_eq!(
        OptimizationEventKind::SaturationCompleted.to_string(),
        "saturation_completed"
    );
    assert_eq!(
        OptimizationEventKind::ExtractionCompleted.to_string(),
        "extraction_completed"
    );
    assert_eq!(
        OptimizationEventKind::InterferenceChecked.to_string(),
        "interference_checked"
    );
    assert_eq!(
        OptimizationEventKind::CampaignRolledBack.to_string(),
        "campaign_rolled_back"
    );
}

// =========================================================================
// BudgetedOptimizationStack — construction
// =========================================================================

#[test]
fn stack_new() {
    let stack = BudgetedOptimizationStack::new();
    assert_eq!(stack.schema_version, OPTIMIZATION_SCHEMA_VERSION);
    assert_eq!(stack.campaign_count(), 0);
    assert!(stack.campaign_ids().is_empty());
    assert!(stack.events().is_empty());
    assert!(stack.interference_checks().is_empty());
}

#[test]
fn stack_default_is_new() {
    let default_stack = BudgetedOptimizationStack::default();
    let new_stack = BudgetedOptimizationStack::new();
    assert_eq!(default_stack, new_stack);
}

#[test]
fn stack_with_budget() {
    let mut env = BudgetEnvelope::production();
    env.consume(BudgetKind::TimeMs, 1000);
    let stack = BudgetedOptimizationStack::with_budget(env.clone());
    assert_eq!(*stack.global_budget(), env);
}

// =========================================================================
// BudgetedOptimizationStack — register campaign
// =========================================================================

#[test]
fn stack_register_campaign() {
    let mut stack = BudgetedOptimizationStack::new();
    let c = make_campaign("c1");
    stack.register_campaign(c).unwrap();
    assert_eq!(stack.campaign_count(), 1);
    assert!(stack.get_campaign("c1").is_some());
    assert_eq!(stack.campaign_ids(), vec!["c1".to_string()]);
    // Should emit CampaignRegistered event
    assert_eq!(stack.events().len(), 1);
    assert_eq!(
        stack.events()[0].kind,
        OptimizationEventKind::CampaignRegistered
    );
}

#[test]
fn stack_register_duplicate_campaign_fails() {
    let mut stack = BudgetedOptimizationStack::new();
    stack.register_campaign(make_campaign("c1")).unwrap();
    let result = stack.register_campaign(make_campaign("c1"));
    assert!(matches!(
        result,
        Err(OptimizationError::DuplicateCampaign(_))
    ));
}

// =========================================================================
// BudgetedOptimizationStack — saturation + extraction
// =========================================================================

#[test]
fn stack_record_saturation() {
    let mut stack = BudgetedOptimizationStack::new();
    stack.register_campaign(make_campaign("c1")).unwrap();

    stack
        .record_saturation("c1", make_egraph_snapshot())
        .unwrap();

    let c = stack.get_campaign("c1").unwrap();
    assert_eq!(c.status, CampaignStatus::Extracting);
    // Global budget should have been consumed
    let time = stack.global_budget().get(BudgetKind::TimeMs).unwrap();
    assert_eq!(time.current_value, 200); // elapsed_ms from snapshot
}

#[test]
fn stack_record_extraction() {
    let mut stack = BudgetedOptimizationStack::new();
    stack.register_campaign(make_campaign("c1")).unwrap();
    stack
        .record_saturation("c1", make_egraph_snapshot())
        .unwrap();
    stack
        .record_extraction("c1", make_extraction_result())
        .unwrap();

    let c = stack.get_campaign("c1").unwrap();
    assert_eq!(c.status, CampaignStatus::Completed);
    assert!(c.is_successful());
}

#[test]
fn stack_record_for_unknown_campaign() {
    let mut stack = BudgetedOptimizationStack::new();
    let result = stack.record_saturation("unknown", make_egraph_snapshot());
    assert!(result.is_err());
}

// =========================================================================
// BudgetedOptimizationStack — interference check
// =========================================================================

#[test]
fn stack_interference_no_overlap() {
    let mut stack = BudgetedOptimizationStack::new();

    let mut c1 = make_campaign("c1");
    c1.add_rule(make_rule(
        "r1",
        RewriteFamily::AlgebraicSimplification,
        true,
    ))
    .unwrap();
    stack.register_campaign(c1).unwrap();

    let mut c2 = make_campaign("c2");
    c2.add_rule(make_rule("r2", RewriteFamily::DeadCodeElimination, true))
        .unwrap();
    stack.register_campaign(c2).unwrap();

    let check = stack.check_interference("c1", "c2");
    assert_eq!(check.kind, InterferenceKind::None);
    assert!(!check.blocking);
}

#[test]
fn stack_interference_overlap() {
    let mut stack = BudgetedOptimizationStack::new();

    let mut c1 = make_campaign("c1");
    c1.add_rule(make_rule(
        "r1",
        RewriteFamily::AlgebraicSimplification,
        true,
    ))
    .unwrap();
    stack.register_campaign(c1).unwrap();

    let mut c2 = make_campaign("c2");
    c2.add_rule(make_rule(
        "r2",
        RewriteFamily::AlgebraicSimplification,
        true,
    ))
    .unwrap();
    stack.register_campaign(c2).unwrap();

    let check = stack.check_interference("c1", "c2");
    assert_eq!(check.kind, InterferenceKind::RewriteConflict);
    assert!(check.blocking);
    assert!(check.detail.contains("algebraic_simplification"));
}

// =========================================================================
// BudgetedOptimizationStack — rollback
// =========================================================================

#[test]
fn stack_rollback() {
    let mut stack = BudgetedOptimizationStack::new();
    stack.register_campaign(make_campaign("c1")).unwrap();
    stack.record_rollback("c1", make_rollback()).unwrap();

    let c = stack.get_campaign("c1").unwrap();
    assert_eq!(c.status, CampaignStatus::RolledBack);
}

// =========================================================================
// BudgetedOptimizationStack — query
// =========================================================================

#[test]
fn stack_campaigns_by_status() {
    let mut stack = BudgetedOptimizationStack::new();
    stack.register_campaign(make_campaign("c1")).unwrap();
    stack.register_campaign(make_campaign("c2")).unwrap();

    // Both pending
    assert_eq!(stack.campaigns_by_status(CampaignStatus::Pending).len(), 2);
    assert_eq!(
        stack.campaigns_by_status(CampaignStatus::Completed).len(),
        0
    );

    // Complete one
    stack
        .record_saturation("c1", make_egraph_snapshot())
        .unwrap();
    stack
        .record_extraction("c1", make_extraction_result())
        .unwrap();

    assert_eq!(stack.campaigns_by_status(CampaignStatus::Pending).len(), 1);
    assert_eq!(
        stack.campaigns_by_status(CampaignStatus::Completed).len(),
        1
    );
}

// =========================================================================
// OptimizationSummary
// =========================================================================

#[test]
fn stack_summary_empty() {
    let stack = BudgetedOptimizationStack::new();
    let summary = stack.summary();
    assert_eq!(summary.total_campaigns, 0);
    assert_eq!(summary.completed_campaigns, 0);
    assert_eq!(summary.failed_campaigns, 0);
    assert_eq!(summary.rolled_back_campaigns, 0);
    assert_eq!(summary.total_rules, 0);
    assert_eq!(summary.total_rewrites_applied, 0);
    assert_eq!(summary.total_gain_millionths, 0);
    assert_eq!(summary.blocking_interference_count, 0);
}

#[test]
fn stack_summary_with_campaigns() {
    let mut stack = BudgetedOptimizationStack::new();

    let mut c1 = make_campaign("c1");
    c1.add_rule(make_rule(
        "r1",
        RewriteFamily::AlgebraicSimplification,
        true,
    ))
    .unwrap();
    c1.add_rule(make_rule("r2", RewriteFamily::DeadCodeElimination, true))
        .unwrap();
    c1.expected_gain_millionths = 100_000;
    stack.register_campaign(c1).unwrap();

    stack
        .record_saturation("c1", make_egraph_snapshot())
        .unwrap();
    stack
        .record_extraction("c1", make_extraction_result())
        .unwrap();

    stack.register_campaign(make_campaign("c2")).unwrap();

    let summary = stack.summary();
    assert_eq!(summary.total_campaigns, 2);
    assert_eq!(summary.completed_campaigns, 1);
    assert_eq!(summary.total_rules, 2);
    assert_eq!(summary.total_rewrites_applied, 50); // from egraph snapshot
    assert_eq!(summary.total_gain_millionths, 100_000);
}

#[test]
fn optimization_summary_serde_roundtrip() {
    let summary = OptimizationSummary {
        total_campaigns: 5,
        completed_campaigns: 3,
        failed_campaigns: 1,
        rolled_back_campaigns: 1,
        total_rules: 20,
        total_rewrites_applied: 1000,
        total_gain_millionths: 500_000,
        blocking_interference_count: 2,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let restored: OptimizationSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, restored);
}

// =========================================================================
// Stack serde roundtrip
// =========================================================================

#[test]
fn stack_serde_roundtrip() {
    let mut stack = BudgetedOptimizationStack::new();

    let mut c1 = make_campaign("c1");
    c1.add_rule(make_rule(
        "r1",
        RewriteFamily::AlgebraicSimplification,
        true,
    ))
    .unwrap();
    stack.register_campaign(c1).unwrap();
    stack
        .record_saturation("c1", make_egraph_snapshot())
        .unwrap();

    let json = serde_json::to_string(&stack).unwrap();
    let restored: BudgetedOptimizationStack = serde_json::from_str(&json).unwrap();
    assert_eq!(stack, restored);
}

// =========================================================================
// Full lifecycle
// =========================================================================

#[test]
fn full_lifecycle() {
    let mut stack = BudgetedOptimizationStack::new();

    // Register two campaigns with different families
    let mut c1 = make_campaign("c1");
    c1.add_rule(make_rule(
        "r1",
        RewriteFamily::AlgebraicSimplification,
        true,
    ))
    .unwrap();
    c1.add_rule(make_rule("r2", RewriteFamily::DeadCodeElimination, true))
        .unwrap();
    c1.expected_gain_millionths = 200_000;
    stack.register_campaign(c1).unwrap();

    let mut c2 = make_campaign("c2");
    c2.add_rule(make_rule("r3", RewriteFamily::PartialEvaluation, true))
        .unwrap();
    c2.expected_gain_millionths = 150_000;
    stack.register_campaign(c2).unwrap();

    // Check interference — no overlap
    let check = stack.check_interference("c1", "c2");
    assert_eq!(check.kind, InterferenceKind::None);
    assert!(!check.blocking);

    // Complete c1 (saturation + extraction)
    stack
        .record_saturation("c1", make_egraph_snapshot())
        .unwrap();
    stack
        .record_extraction("c1", make_extraction_result())
        .unwrap();

    // Fail c2
    {
        let c2 = stack.get_campaign("c2").unwrap();
        assert_eq!(c2.status, CampaignStatus::Pending);
    }

    // Summary
    let summary = stack.summary();
    assert_eq!(summary.total_campaigns, 2);
    assert_eq!(summary.completed_campaigns, 1);
    assert_eq!(summary.total_rules, 3);
    assert_eq!(summary.total_gain_millionths, 200_000);

    // Events should include: 2 registrations + 1 saturation + 1 extraction + 1 interference
    assert_eq!(stack.events().len(), 5);

    // Serde round-trip
    let json = serde_json::to_string(&stack).unwrap();
    let restored: BudgetedOptimizationStack = serde_json::from_str(&json).unwrap();
    assert_eq!(stack, restored);
}

// =========================================================================
// EGraphSnapshot — pathological growth detection
// =========================================================================

#[test]
fn egraph_snapshot_new_constructor() {
    let snapshot = EGraphSnapshot::new(EGraphSnapshotParts {
        class_count: 100,
        node_count: 500,
        iteration_count: 10,
        rewrite_count: 50,
        outcome: SaturationOutcome::Saturated,
        state_hash: ContentHash::compute(b"state"),
        elapsed_ms: 200,
        peak_memory_bytes: 1024 * 1024,
    });

    assert_eq!(snapshot.class_count, 100);
    assert_eq!(snapshot.node_count, 500);
    assert_eq!(snapshot.iteration_count, 10);
    assert_eq!(snapshot.rewrite_count, 50);
    assert_eq!(snapshot.outcome, SaturationOutcome::Saturated);
    assert_eq!(snapshot.elapsed_ms, 200);
    assert_eq!(snapshot.peak_memory_bytes, 1024 * 1024);
}

#[test]
fn egraph_snapshot_pathological_growth_detection() {
    let baseline = EGraphSnapshot::new(EGraphSnapshotParts {
        class_count: 50,
        node_count: 100,
        iteration_count: 5,
        rewrite_count: 20,
        outcome: SaturationOutcome::Saturated,
        state_hash: ContentHash::compute(b"baseline"),
        elapsed_ms: 100,
        peak_memory_bytes: 512 * 1024,
    });

    // Normal growth: 400 nodes / 5 iterations = 80 nodes/iter (below threshold)
    let normal_growth = EGraphSnapshot::new(EGraphSnapshotParts {
        class_count: 100,
        node_count: 500, // 400 node increase
        iteration_count: 10, // 5 iter increase
        rewrite_count: 60,
        outcome: SaturationOutcome::Saturated,
        state_hash: ContentHash::compute(b"normal"),
        elapsed_ms: 200,
        peak_memory_bytes: 1024 * 1024,
    });

    assert!(!normal_growth.is_pathological_growth(&baseline));
    assert_eq!(normal_growth.node_growth_rate(&baseline), 80);

    // Pathological growth: 50,005 nodes / 5 iterations = 10,001 nodes/iter (above threshold)
    let pathological_growth = EGraphSnapshot::new(EGraphSnapshotParts {
        class_count: 5000,
        node_count: 50_105, // 50,005 node increase
        iteration_count: 10, // 5 iter increase
        rewrite_count: 500,
        outcome: SaturationOutcome::NodeLimitReached,
        state_hash: ContentHash::compute(b"pathological"),
        elapsed_ms: 1000,
        peak_memory_bytes: 10 * 1024 * 1024,
    });

    assert!(pathological_growth.is_pathological_growth(&baseline));
    assert_eq!(pathological_growth.node_growth_rate(&baseline), 10_001);
}

#[test]
fn egraph_snapshot_growth_edge_cases() {
    let baseline = EGraphSnapshot::new(EGraphSnapshotParts {
        class_count: 50,
        node_count: 100,
        iteration_count: 5,
        rewrite_count: 20,
        outcome: SaturationOutcome::Saturated,
        state_hash: ContentHash::compute(b"baseline"),
        elapsed_ms: 100,
        peak_memory_bytes: 512 * 1024,
    });

    // Zero iteration delta
    let same_iterations = EGraphSnapshot::new(EGraphSnapshotParts {
        class_count: 60,
        node_count: 200,
        iteration_count: 5, // same iteration_count as baseline
        rewrite_count: 30,
        outcome: SaturationOutcome::Saturated,
        state_hash: ContentHash::compute(b"same"),
        elapsed_ms: 150,
        peak_memory_bytes: 768 * 1024,
    });

    assert!(!same_iterations.is_pathological_growth(&baseline));
    assert_eq!(same_iterations.node_growth_rate(&baseline), 0);

    // Negative node growth (nodes decreased)
    let negative_growth = EGraphSnapshot::new(EGraphSnapshotParts {
        class_count: 40,
        node_count: 50, // fewer nodes than baseline
        iteration_count: 10,
        rewrite_count: 25,
        outcome: SaturationOutcome::Saturated,
        state_hash: ContentHash::compute(b"negative"),
        elapsed_ms: 200,
        peak_memory_bytes: 1024 * 1024,
    });

    assert!(!negative_growth.is_pathological_growth(&baseline));
    assert_eq!(negative_growth.node_growth_rate(&baseline), 0); // saturating_sub gives 0

    // Exactly at threshold: 10,000 nodes / 1 iteration = 10,000 (not above threshold)
    let at_threshold = EGraphSnapshot::new(EGraphSnapshotParts {
        class_count: 1000,
        node_count: 10_100, // 10,000 node increase, 1 iteration increase
        iteration_count: 6,
        rewrite_count: 100,
        outcome: SaturationOutcome::Saturated,
        state_hash: ContentHash::compute(b"threshold"),
        elapsed_ms: 300,
        peak_memory_bytes: 2 * 1024 * 1024,
    });

    assert!(!at_threshold.is_pathological_growth(&baseline));
    assert_eq!(at_threshold.node_growth_rate(&baseline), 10_000);

    // Just over threshold: 10,001 nodes / 1 iteration = 10,001 (above threshold)
    let over_threshold = EGraphSnapshot::new(EGraphSnapshotParts {
        class_count: 1000,
        node_count: 10_101, // 10,001 node increase, 1 iteration increase
        iteration_count: 6,
        rewrite_count: 100,
        outcome: SaturationOutcome::NodeLimitReached,
        state_hash: ContentHash::compute(b"over_threshold"),
        elapsed_ms: 400,
        peak_memory_bytes: 3 * 1024 * 1024,
    });

    assert!(over_threshold.is_pathological_growth(&baseline));
    assert_eq!(over_threshold.node_growth_rate(&baseline), 10_001);
}
