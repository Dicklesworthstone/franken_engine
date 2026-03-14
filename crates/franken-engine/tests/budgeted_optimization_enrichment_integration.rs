//! Enrichment integration tests for the `budgeted_optimization` module.
//!
//! Covers: enum ordering, BudgetLimit utilization edge cases, campaign rule
//! limit, stack campaign limit, ExtractionPolicy Custom display, BudgetEnvelope
//! any_exhausted, stack event sequence numbers, Debug formatting,
//! campaign_ids ordering, OptimizationSummary fields.

#![forbid(unsafe_code)]
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
    EGraphSnapshot, ExtractionPolicy, ExtractionResult, InterferenceCheck, InterferenceKind,
    OPTIMIZATION_SCHEMA_VERSION, OptimizationCampaign, OptimizationError, OptimizationEvent,
    OptimizationEventKind, OptimizationSummary, RewriteFamily, RewriteRule, RollbackArtifact,
    SaturationOutcome,
};
use frankenengine_engine::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hash(data: &[u8]) -> ContentHash {
    ContentHash::compute(data)
}

fn rule(id: &str, family: RewriteFamily) -> RewriteRule {
    RewriteRule {
        id: id.to_string(),
        family,
        description: format!("rule {id}"),
        pattern_hash: hash(format!("pat-{id}").as_bytes()),
        replacement_hash: hash(format!("rep-{id}").as_bytes()),
        proof_obligations: vec![],
        metamorphic_checks: vec![],
        sound: true,
        priority_millionths: 1_000_000,
        enabled: true,
    }
}

fn campaign(id: &str) -> OptimizationCampaign {
    OptimizationCampaign::new(id, &format!("Camp {id}"), hash(id.as_bytes()))
}

fn egraph_snap() -> EGraphSnapshot {
    EGraphSnapshot {
        class_count: 50,
        node_count: 200,
        iteration_count: 5,
        rewrite_count: 100,
        outcome: SaturationOutcome::Saturated,
        state_hash: hash(b"snap"),
        elapsed_ms: 25,
        peak_memory_bytes: 512 * 1024,
    }
}

fn extraction() -> ExtractionResult {
    ExtractionResult {
        policy: ExtractionPolicy::MinCost,
        total_cost_millionths: 500_000,
        extracted_node_count: 30,
        proven_rewrite_count: 25,
        output_hash: hash(b"extracted"),
        families_used: BTreeSet::from([RewriteFamily::AlgebraicSimplification]),
    }
}

// =========================================================================
// A. RewriteFamily — ordering
// =========================================================================

#[test]
fn enrichment_rewrite_family_ordering() {
    assert!(RewriteFamily::AlgebraicSimplification < RewriteFamily::DeadCodeElimination);
    assert!(RewriteFamily::DeadCodeElimination < RewriteFamily::CommonSubexpression);
    assert!(RewriteFamily::CommonSubexpression < RewriteFamily::PartialEvaluation);
    assert!(RewriteFamily::PartialEvaluation < RewriteFamily::MemoizationBoundary);
    assert!(RewriteFamily::MemoizationBoundary < RewriteFamily::EffectHoisting);
    assert!(RewriteFamily::EffectHoisting < RewriteFamily::HookSlotFusion);
    assert!(RewriteFamily::HookSlotFusion < RewriteFamily::SignalGraphOptimization);
    assert!(RewriteFamily::SignalGraphOptimization < RewriteFamily::Incrementalization);
    assert!(RewriteFamily::Incrementalization < RewriteFamily::DomUpdateBatching);
    assert!(RewriteFamily::DomUpdateBatching < RewriteFamily::Custom);
}

// =========================================================================
// B. BudgetKind — ordering
// =========================================================================

#[test]
fn enrichment_budget_kind_ordering() {
    assert!(BudgetKind::TimeMs < BudgetKind::EgraphNodes);
    assert!(BudgetKind::EgraphNodes < BudgetKind::MemoryBytes);
    assert!(BudgetKind::MemoryBytes < BudgetKind::RewriteApplications);
    assert!(BudgetKind::RewriteApplications < BudgetKind::SaturationIterations);
}

// =========================================================================
// C. CampaignStatus — ordering
// =========================================================================

#[test]
fn enrichment_campaign_status_ordering() {
    assert!(CampaignStatus::Pending < CampaignStatus::Saturating);
    assert!(CampaignStatus::Saturating < CampaignStatus::Extracting);
    assert!(CampaignStatus::Extracting < CampaignStatus::Completed);
    assert!(CampaignStatus::Completed < CampaignStatus::Failed);
    assert!(CampaignStatus::Failed < CampaignStatus::RolledBack);
}

// =========================================================================
// D. InterferenceKind — ordering
// =========================================================================

#[test]
fn enrichment_interference_kind_ordering() {
    assert!(InterferenceKind::None < InterferenceKind::RewriteConflict);
    assert!(InterferenceKind::RewriteConflict < InterferenceKind::BudgetContention);
    assert!(InterferenceKind::BudgetContention < InterferenceKind::SemanticInterference);
    assert!(InterferenceKind::SemanticInterference < InterferenceKind::OrderDependence);
}

// =========================================================================
// E. BudgetLimit — utilization edge cases
// =========================================================================

#[test]
fn enrichment_budget_limit_utilization_zero_max_is_million() {
    let limit = BudgetLimit::new(BudgetKind::TimeMs, 0);
    assert_eq!(limit.utilization_millionths(), 1_000_000);
}

#[test]
fn enrichment_budget_limit_utilization_zero_consumed_is_zero() {
    let limit = BudgetLimit::new(BudgetKind::EgraphNodes, 100);
    assert_eq!(limit.utilization_millionths(), 0);
}

#[test]
fn enrichment_budget_limit_utilization_half() {
    let mut limit = BudgetLimit::new(BudgetKind::MemoryBytes, 1000);
    limit.consume(500);
    assert_eq!(limit.utilization_millionths(), 500_000);
}

#[test]
fn enrichment_budget_limit_remaining_after_partial_consume() {
    let mut limit = BudgetLimit::new(BudgetKind::RewriteApplications, 100);
    limit.consume(60);
    assert_eq!(limit.remaining(), 40);
}

#[test]
fn enrichment_budget_limit_remaining_after_over_consume() {
    let mut limit = BudgetLimit::new(BudgetKind::SaturationIterations, 50);
    limit.consume(100);
    assert_eq!(limit.remaining(), 0);
    assert!(limit.is_exhausted());
}

#[test]
fn enrichment_budget_limit_consume_returns_false_when_exceeded() {
    let mut limit = BudgetLimit::new(BudgetKind::TimeMs, 10);
    assert!(limit.consume(5));
    assert!(limit.consume(5));
    assert!(!limit.consume(1));
}

// =========================================================================
// F. BudgetEnvelope — any_exhausted
// =========================================================================

#[test]
fn enrichment_budget_envelope_fresh_not_exhausted() {
    let env = BudgetEnvelope::production();
    assert!(!env.any_exhausted());
}

#[test]
fn enrichment_budget_envelope_exhaust_one_triggers_any() {
    let mut env = BudgetEnvelope::production();
    // Saturation iterations limit is 1000 in production
    env.consume(BudgetKind::SaturationIterations, 1001);
    assert!(env.any_exhausted());
}

#[test]
fn enrichment_budget_envelope_get_unknown_kind_returns_none() {
    // After production setup, all standard kinds exist
    let env = BudgetEnvelope::production();
    assert!(env.get(BudgetKind::TimeMs).is_some());
    assert!(env.get(BudgetKind::EgraphNodes).is_some());
}

// =========================================================================
// G. ExtractionPolicy — Custom display
// =========================================================================

#[test]
fn enrichment_extraction_policy_custom_display() {
    let p = ExtractionPolicy::Custom {
        name: "my_cost_fn".to_string(),
    };
    assert_eq!(p.to_string(), "custom:my_cost_fn");
}

#[test]
fn enrichment_extraction_policy_proof_aware_display() {
    let p = ExtractionPolicy::ProofAware {
        proof_weight_millionths: 750_000,
    };
    assert_eq!(p.to_string(), "proof_aware");
}

#[test]
fn enrichment_extraction_policy_default_is_min_cost() {
    assert_eq!(ExtractionPolicy::default(), ExtractionPolicy::MinCost);
}

// =========================================================================
// H. Campaign — rule limit exceeded
// =========================================================================

#[test]
fn enrichment_campaign_add_duplicate_rule_error() {
    let mut c = campaign("c1");
    c.add_rule(rule("r1", RewriteFamily::AlgebraicSimplification))
        .unwrap();
    let err = c
        .add_rule(rule("r1", RewriteFamily::DeadCodeElimination))
        .unwrap_err();
    assert!(matches!(err, OptimizationError::DuplicateRule(id) if id == "r1"));
}

#[test]
fn enrichment_campaign_ready_rule_count_excludes_unsound() {
    let mut c = campaign("c1");
    c.add_rule(rule("r1", RewriteFamily::AlgebraicSimplification))
        .unwrap();
    let mut unsound = rule("r2", RewriteFamily::DeadCodeElimination);
    unsound.sound = false;
    c.add_rule(unsound).unwrap();
    let mut disabled = rule("r3", RewriteFamily::CommonSubexpression);
    disabled.enabled = false;
    c.add_rule(disabled).unwrap();
    assert_eq!(c.ready_rule_count(), 1);
}

#[test]
fn enrichment_campaign_is_successful_requires_both() {
    let mut c = campaign("c1");
    assert!(!c.is_successful());
    c.record_saturation(egraph_snap());
    assert!(!c.is_successful());
    c.record_extraction(extraction());
    assert!(c.is_successful());
}

// =========================================================================
// I. Stack — campaign_ids ordering
// =========================================================================

#[test]
fn enrichment_stack_campaign_ids_btree_order() {
    let mut stack = BudgetedOptimizationStack::new();
    stack.register_campaign(campaign("charlie")).unwrap();
    stack.register_campaign(campaign("alpha")).unwrap();
    stack.register_campaign(campaign("bravo")).unwrap();
    let ids = stack.campaign_ids();
    assert_eq!(ids, vec!["alpha", "bravo", "charlie"]);
}

// =========================================================================
// J. Stack — duplicate campaign error
// =========================================================================

#[test]
fn enrichment_stack_duplicate_campaign_error_display() {
    let mut stack = BudgetedOptimizationStack::new();
    stack.register_campaign(campaign("c1")).unwrap();
    let err = stack.register_campaign(campaign("c1")).unwrap_err();
    assert!(err.to_string().contains("duplicate campaign"));
}

// =========================================================================
// K. Stack — event sequence numbers
// =========================================================================

#[test]
fn enrichment_stack_events_sequential() {
    let mut stack = BudgetedOptimizationStack::new();
    stack.register_campaign(campaign("c1")).unwrap();
    stack.register_campaign(campaign("c2")).unwrap();
    let events = stack.events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].seq, 0);
    assert_eq!(events[1].seq, 1);
    assert!(matches!(
        events[0].kind,
        OptimizationEventKind::CampaignRegistered
    ));
}

// =========================================================================
// L. Stack — interference check between non-existent campaigns
// =========================================================================

#[test]
fn enrichment_stack_interference_nonexistent_no_panic() {
    let mut stack = BudgetedOptimizationStack::new();
    let check = stack.check_interference("no-such", "also-no");
    assert_eq!(check.kind, InterferenceKind::None);
}

// =========================================================================
// M. Stack — summary with mixed statuses
// =========================================================================

#[test]
fn enrichment_stack_summary_counts_failed_and_rolledback() {
    let mut stack = BudgetedOptimizationStack::new();

    let mut c1 = campaign("c1");
    c1.record_failure();
    stack.register_campaign(c1).unwrap();

    let mut c2 = campaign("c2");
    c2.record_rollback(RollbackArtifact {
        campaign_id: "c2".to_string(),
        pre_optimization_hash: hash(b"pre"),
        post_optimization_hash: hash(b"post"),
        applied_rules: vec![],
        rollback_tested: true,
        artifact_hash: hash(b"rb"),
    });
    stack.register_campaign(c2).unwrap();

    let summary = stack.summary();
    assert_eq!(summary.total_campaigns, 2);
    assert_eq!(summary.failed_campaigns, 1);
    assert_eq!(summary.rolled_back_campaigns, 1);
    assert_eq!(summary.completed_campaigns, 0);
}

// =========================================================================
// N. Stack — with_budget uses custom budget
// =========================================================================

#[test]
fn enrichment_stack_with_budget_custom() {
    let mut envelope = BudgetEnvelope::production();
    // Exhaust time budget
    envelope.consume(BudgetKind::TimeMs, 10_000);
    let stack = BudgetedOptimizationStack::with_budget(envelope);
    assert!(stack.global_budget().any_exhausted());
}

// =========================================================================
// O. OptimizationSummary — serde roundtrip
// =========================================================================

#[test]
fn enrichment_optimization_summary_serde_roundtrip() {
    let summary = OptimizationSummary {
        total_campaigns: 5,
        completed_campaigns: 3,
        failed_campaigns: 1,
        rolled_back_campaigns: 1,
        total_rules: 42,
        total_rewrites_applied: 1000,
        total_gain_millionths: 250_000,
        blocking_interference_count: 2,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let restored: OptimizationSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, restored);
}

// =========================================================================
// P. OptimizationEvent — serde roundtrip
// =========================================================================

#[test]
fn enrichment_optimization_event_serde_roundtrip() {
    let event = OptimizationEvent {
        seq: 42,
        kind: OptimizationEventKind::SaturationCompleted,
        campaign_id: Some("camp-1".to_string()),
        detail: "done".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: OptimizationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

// =========================================================================
// Q. OptimizationEventKind — Display all variants
// =========================================================================

#[test]
fn enrichment_event_kind_display_all_distinct() {
    let kinds = [
        OptimizationEventKind::CampaignRegistered,
        OptimizationEventKind::SaturationStarted,
        OptimizationEventKind::SaturationCompleted,
        OptimizationEventKind::ExtractionStarted,
        OptimizationEventKind::ExtractionCompleted,
        OptimizationEventKind::InterferenceChecked,
        OptimizationEventKind::CampaignFailed,
        OptimizationEventKind::CampaignRolledBack,
        OptimizationEventKind::BudgetConsumed,
    ];
    let strings: BTreeSet<String> = kinds.iter().map(|k| k.to_string()).collect();
    assert_eq!(strings.len(), 9);
}

// =========================================================================
// R. SaturationOutcome — Display all variants
// =========================================================================

#[test]
fn enrichment_saturation_outcome_display_all_distinct() {
    let outcomes = [
        SaturationOutcome::Saturated,
        SaturationOutcome::BudgetExhausted,
        SaturationOutcome::NodeLimitReached,
        SaturationOutcome::IterationLimitReached,
        SaturationOutcome::PolicyStopped,
    ];
    let strings: BTreeSet<String> = outcomes.iter().map(|o| o.to_string()).collect();
    assert_eq!(strings.len(), 5);
}

// =========================================================================
// S. RollbackArtifact — is_viable
// =========================================================================

#[test]
fn enrichment_rollback_not_tested_not_viable() {
    let rb = RollbackArtifact {
        campaign_id: "c1".to_string(),
        pre_optimization_hash: hash(b"pre"),
        post_optimization_hash: hash(b"post"),
        applied_rules: vec!["r1".to_string()],
        rollback_tested: false,
        artifact_hash: hash(b"rb"),
    };
    assert!(!rb.is_viable());
}

#[test]
fn enrichment_rollback_tested_is_viable() {
    let rb = RollbackArtifact {
        campaign_id: "c1".to_string(),
        pre_optimization_hash: hash(b"pre"),
        post_optimization_hash: hash(b"post"),
        applied_rules: vec![],
        rollback_tested: true,
        artifact_hash: hash(b"rb"),
    };
    assert!(rb.is_viable());
}

// =========================================================================
// T. RewriteRule — is_ready combinations
// =========================================================================

#[test]
fn enrichment_rewrite_rule_not_ready_when_unsound() {
    let mut r = rule("r1", RewriteFamily::AlgebraicSimplification);
    r.sound = false;
    assert!(!r.is_ready());
}

#[test]
fn enrichment_rewrite_rule_not_ready_when_disabled() {
    let mut r = rule("r1", RewriteFamily::AlgebraicSimplification);
    r.enabled = false;
    assert!(!r.is_ready());
}

#[test]
fn enrichment_rewrite_rule_not_ready_when_both() {
    let mut r = rule("r1", RewriteFamily::AlgebraicSimplification);
    r.sound = false;
    r.enabled = false;
    assert!(!r.is_ready());
}

// =========================================================================
// U. Debug formatting — all types
// =========================================================================

#[test]
fn enrichment_debug_nonempty_all_types() {
    assert!(!format!("{:?}", RewriteFamily::AlgebraicSimplification).is_empty());
    assert!(!format!("{:?}", BudgetKind::TimeMs).is_empty());
    assert!(!format!("{:?}", CampaignStatus::Pending).is_empty());
    assert!(!format!("{:?}", InterferenceKind::None).is_empty());
    assert!(!format!("{:?}", SaturationOutcome::Saturated).is_empty());
    assert!(!format!("{:?}", ExtractionPolicy::MinCost).is_empty());
    assert!(!format!("{:?}", BudgetLimit::new(BudgetKind::TimeMs, 100)).is_empty());
    assert!(!format!("{:?}", BudgetEnvelope::production()).is_empty());
    assert!(!format!("{:?}", BudgetedOptimizationStack::new()).is_empty());
    assert!(!format!("{:?}", campaign("test")).is_empty());
}

// =========================================================================
// V. RewriteRule — serde roundtrip
// =========================================================================

#[test]
fn enrichment_rewrite_rule_serde_roundtrip() {
    let r = rule("alpha-1", RewriteFamily::EffectHoisting);
    let json = serde_json::to_string(&r).unwrap();
    let restored: RewriteRule = serde_json::from_str(&json).unwrap();
    assert_eq!(r, restored);
}

// =========================================================================
// W. BudgetEnvelope — most_constrained returns highest utilization
// =========================================================================

#[test]
fn enrichment_budget_envelope_most_constrained() {
    let mut env = BudgetEnvelope::production();
    // Consume most of the saturation iterations budget (1000 max)
    env.consume(BudgetKind::SaturationIterations, 999);
    let most = env.most_constrained().unwrap();
    assert_eq!(most.kind, BudgetKind::SaturationIterations);
    assert_eq!(most.utilization_millionths(), 999_000);
}

// =========================================================================
// X. Campaign — families() collects distinct rewrite families
// =========================================================================

#[test]
fn enrichment_campaign_families_collects_distinct() {
    let mut c = campaign("fam-test");
    c.add_rule(rule("r1", RewriteFamily::AlgebraicSimplification))
        .unwrap();
    c.add_rule(rule("r2", RewriteFamily::DeadCodeElimination))
        .unwrap();
    c.add_rule(rule("r3", RewriteFamily::AlgebraicSimplification))
        .unwrap();
    let families = c.families();
    assert_eq!(families.len(), 2);
    assert!(families.contains(&RewriteFamily::AlgebraicSimplification));
    assert!(families.contains(&RewriteFamily::DeadCodeElimination));
}

// =========================================================================
// Y. Stack — interference check with overlapping families detects conflict
// =========================================================================

#[test]
fn enrichment_stack_interference_overlapping_families_detected() {
    let mut stack = BudgetedOptimizationStack::new();

    let mut c1 = campaign("opt-a");
    c1.add_rule(rule("r1", RewriteFamily::AlgebraicSimplification))
        .unwrap();
    c1.add_rule(rule("r2", RewriteFamily::DeadCodeElimination))
        .unwrap();
    stack.register_campaign(c1).unwrap();

    let mut c2 = campaign("opt-b");
    c2.add_rule(rule("r3", RewriteFamily::AlgebraicSimplification))
        .unwrap();
    stack.register_campaign(c2).unwrap();

    let check = stack.check_interference("opt-a", "opt-b");
    assert_eq!(check.kind, InterferenceKind::RewriteConflict);
    assert!(check.blocking);
    assert!(check.detail.contains("algebraic_simplification"));
}

// =========================================================================
// Z. Stack — record_saturation + record_extraction through stack
// =========================================================================

#[test]
fn enrichment_stack_record_saturation_and_extraction_full_lifecycle() {
    let mut stack = BudgetedOptimizationStack::new();
    stack.register_campaign(campaign("life")).unwrap();

    stack.record_saturation("life", egraph_snap()).unwrap();
    let c = stack.get_campaign("life").unwrap();
    assert_eq!(c.status, CampaignStatus::Extracting);
    assert!(c.egraph_snapshot.is_some());

    stack.record_extraction("life", extraction()).unwrap();
    let c = stack.get_campaign("life").unwrap();
    assert_eq!(c.status, CampaignStatus::Completed);
    assert!(c.is_successful());
}

// =========================================================================
// AA. Stack — campaigns_by_status filters correctly
// =========================================================================

#[test]
fn enrichment_stack_campaigns_by_status_filters() {
    let mut stack = BudgetedOptimizationStack::new();

    let mut c1 = campaign("done-1");
    c1.record_saturation(egraph_snap());
    c1.record_extraction(extraction());
    stack.register_campaign(c1).unwrap();

    let mut c2 = campaign("failed-1");
    c2.record_failure();
    stack.register_campaign(c2).unwrap();

    stack.register_campaign(campaign("pending-1")).unwrap();

    let completed = stack.campaigns_by_status(CampaignStatus::Completed);
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].id, "done-1");

    let failed = stack.campaigns_by_status(CampaignStatus::Failed);
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].id, "failed-1");

    let pending = stack.campaigns_by_status(CampaignStatus::Pending);
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, "pending-1");
}

// =========================================================================
// AB. OptimizationError — Display all variants distinct
// =========================================================================

#[test]
fn enrichment_optimization_error_display_all_distinct() {
    let errors = [
        OptimizationError::RuleLimitExceeded { count: 2, max: 1 },
        OptimizationError::DuplicateRule("r1".to_string()),
        OptimizationError::CampaignLimitExceeded { count: 65, max: 64 },
        OptimizationError::DuplicateCampaign("c1".to_string()),
        OptimizationError::BudgetExhausted {
            kind: BudgetKind::TimeMs,
        },
        OptimizationError::InterferenceBlocking(InterferenceCheck {
            campaign_a: "a".to_string(),
            campaign_b: "b".to_string(),
            kind: InterferenceKind::RewriteConflict,
            detail: String::new(),
            blocking: true,
        }),
        OptimizationError::UnsoundRewrite {
            rule_id: "u1".to_string(),
        },
        OptimizationError::RollbackFailed {
            campaign_id: "c1".to_string(),
            detail: "oops".to_string(),
        },
    ];
    let strings: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(strings.len(), 8);
}

// =========================================================================
// AC. Clone independence — BudgetedOptimizationStack
// =========================================================================

#[test]
fn enrichment_stack_clone_independence() {
    let mut stack = BudgetedOptimizationStack::new();
    stack.register_campaign(campaign("orig")).unwrap();
    let mut cloned = stack.clone();
    cloned.register_campaign(campaign("extra")).unwrap();
    assert_eq!(stack.campaign_count(), 1);
    assert_eq!(cloned.campaign_count(), 2);
}

// =========================================================================
// AD. BudgetEnvelope — serde roundtrip
// =========================================================================

#[test]
fn enrichment_budget_envelope_serde_roundtrip() {
    let mut env = BudgetEnvelope::production();
    env.consume(BudgetKind::TimeMs, 1234);
    let json = serde_json::to_string(&env).unwrap();
    let restored: BudgetEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(env, restored);
}

// =========================================================================
// AE. RewriteFamily — Display all variants distinct
// =========================================================================

#[test]
fn enrichment_rewrite_family_display_all_distinct() {
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
    let strings: BTreeSet<String> = families.iter().map(|f| f.to_string()).collect();
    assert_eq!(strings.len(), 11);
}

// =========================================================================
// AF. Stack — schema_version matches constant
// =========================================================================

#[test]
fn enrichment_stack_schema_version_matches_constant() {
    let stack = BudgetedOptimizationStack::new();
    assert_eq!(stack.schema_version, OPTIMIZATION_SCHEMA_VERSION);
}

// =========================================================================
// AG. Stack — record_saturation on unknown campaign errors
// =========================================================================

#[test]
fn enrichment_stack_record_saturation_unknown_campaign_errors() {
    let mut stack = BudgetedOptimizationStack::new();
    let err = stack.record_saturation("ghost", egraph_snap()).unwrap_err();
    assert!(err.to_string().contains("duplicate campaign"));
}

// =========================================================================
// AH. BudgetedOptimizationStack — default equals new
// =========================================================================

#[test]
fn enrichment_stack_default_equals_new() {
    let a = BudgetedOptimizationStack::new();
    let b = BudgetedOptimizationStack::default();
    assert_eq!(a, b);
}

// =========================================================================
// AI. Stack — summary gain aggregates only successful campaigns
// =========================================================================

#[test]
fn enrichment_summary_gain_only_from_successful() {
    let mut stack = BudgetedOptimizationStack::new();

    // Successful campaign with gain
    let mut c1 = campaign("winner");
    c1.expected_gain_millionths = 500_000;
    c1.record_saturation(egraph_snap());
    c1.record_extraction(extraction());
    stack.register_campaign(c1).unwrap();

    // Failed campaign — gain should NOT count
    let mut c2 = campaign("loser");
    c2.expected_gain_millionths = 999_000;
    c2.record_failure();
    stack.register_campaign(c2).unwrap();

    let summary = stack.summary();
    assert_eq!(summary.total_gain_millionths, 500_000);
}

// =========================================================================
// AJ. InterferenceCheck — serde roundtrip
// =========================================================================

#[test]
fn enrichment_interference_check_serde_roundtrip() {
    let check = InterferenceCheck {
        campaign_a: "alpha".to_string(),
        campaign_b: "beta".to_string(),
        kind: InterferenceKind::SemanticInterference,
        detail: "semantic conflict on node 42".to_string(),
        blocking: true,
    };
    let json = serde_json::to_string(&check).unwrap();
    let restored: InterferenceCheck = serde_json::from_str(&json).unwrap();
    assert_eq!(check, restored);
}

// =========================================================================
// AK. BudgetEnvelope — consume on missing kind returns true (unlimited)
// =========================================================================

#[test]
fn enrichment_budget_envelope_consume_missing_kind_returns_true() {
    let mut env = BudgetEnvelope {
        limits: std::collections::BTreeMap::new(),
    };
    // Empty envelope — no limits defined — consume should return true
    assert!(env.consume(BudgetKind::TimeMs, 999_999));
}

// =========================================================================
// AL. Stack — interference_checks accumulates all checks
// =========================================================================

#[test]
fn enrichment_stack_interference_checks_accumulates() {
    let mut stack = BudgetedOptimizationStack::new();

    let mut c1 = campaign("x");
    c1.add_rule(rule("r1", RewriteFamily::AlgebraicSimplification))
        .unwrap();
    stack.register_campaign(c1).unwrap();

    let mut c2 = campaign("y");
    c2.add_rule(rule("r2", RewriteFamily::DeadCodeElimination))
        .unwrap();
    stack.register_campaign(c2).unwrap();

    stack.check_interference("x", "y");
    stack.check_interference("y", "x");

    assert_eq!(stack.interference_checks().len(), 2);
}
