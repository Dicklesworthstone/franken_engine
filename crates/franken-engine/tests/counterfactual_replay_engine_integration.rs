#![forbid(unsafe_code)]
//! Integration tests for the `counterfactual_replay_engine` module.
//!
//! Exercises AlternatePolicy, ReplayScope, AssumptionCategory, AssumptionCard,
//! DecisionComparison, PolicyComparisonReport, ReplayComparisonResult,
//! Recommendation, ReplayEngineError, ReplayEngineConfig,
//! CounterfactualReplayEngine (compare, replay_count), and serde round-trips.

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

use std::collections::BTreeMap;

use frankenengine_engine::causal_replay::{
    CounterfactualConfig, DecisionSnapshot, RecorderConfig, RecordingMode, TraceRecord,
    TraceRecorder,
};
use frankenengine_engine::counterfactual_evaluator::{EnvelopeStatus, EstimatorKind, PolicyId};
use frankenengine_engine::counterfactual_replay_engine::{
    AlternatePolicy, AssumptionCard, AssumptionCategory, CounterfactualReplayEngine,
    DecisionComparison, PolicyComparisonReport, REPLAY_ENGINE_SCHEMA_VERSION, Recommendation,
    ReplayComparisonResult, ReplayEngineConfig, ReplayEngineError, ReplayScope,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::runtime_decision_theory::LaneAction;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn make_decision(index: u64, action: &str, outcome: i64) -> DecisionSnapshot {
    let mut loss_matrix = BTreeMap::new();
    loss_matrix.insert("native".to_string(), 100_000);
    loss_matrix.insert("wasm".to_string(), 200_000);

    DecisionSnapshot {
        decision_index: index,
        trace_id: "test-trace".to_string(),
        decision_id: format!("decision-{index}"),
        policy_id: "baseline".to_string(),
        policy_version: 1,
        epoch: test_epoch(),
        tick: 100 + index,
        threshold_millionths: 500_000,
        loss_matrix,
        evidence_hashes: vec![ContentHash::compute(b"evidence")],
        chosen_action: action.to_string(),
        outcome_millionths: outcome,
        extension_id: "ext-1".to_string(),
        nondeterminism_range: (0, 0),
    }
}

fn make_trace(decisions: Vec<DecisionSnapshot>) -> TraceRecord {
    let mut recorder = TraceRecorder::new(RecorderConfig {
        trace_id: "test-trace".to_string(),
        recording_mode: RecordingMode::Full,
        epoch: test_epoch(),
        start_tick: 100,
        signing_key: b"test-key".to_vec(),
    });

    for d in decisions {
        recorder.record_decision(d);
    }

    recorder.finalize()
}

fn make_alternate_policy(id: &str, desc: &str) -> AlternatePolicy {
    AlternatePolicy {
        policy_id: PolicyId(id.to_string()),
        description: desc.to_string(),
        counterfactual_config: CounterfactualConfig {
            branch_id: format!("branch-{id}"),
            threshold_override_millionths: Some(600_000),
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        },
        default_action: None,
    }
}

fn make_override_policy(id: &str, action: LaneAction) -> AlternatePolicy {
    AlternatePolicy {
        policy_id: PolicyId(id.to_string()),
        description: format!("Force {action}"),
        counterfactual_config: CounterfactualConfig {
            branch_id: format!("branch-{id}"),
            threshold_override_millionths: None,
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        },
        default_action: Some(action),
    }
}

fn default_scope() -> ReplayScope {
    ReplayScope::default()
}

fn default_engine() -> CounterfactualReplayEngine {
    CounterfactualReplayEngine::new(ReplayEngineConfig::default())
}

fn simple_trace() -> TraceRecord {
    make_trace(vec![
        make_decision(0, "native", 800_000),
        make_decision(1, "wasm", 600_000),
        make_decision(2, "native", 900_000),
    ])
}

// ===========================================================================
// 1. Constants
// ===========================================================================

#[test]
fn schema_version_nonempty() {
    assert!(!REPLAY_ENGINE_SCHEMA_VERSION.is_empty());
    assert!(REPLAY_ENGINE_SCHEMA_VERSION.contains("counterfactual-replay-engine"));
}

// ===========================================================================
// 2. AlternatePolicy
// ===========================================================================

#[test]
fn alternate_policy_display() {
    let ap = make_alternate_policy("alt-1", "Alternative One");
    let display = ap.to_string();
    assert!(display.contains("alt-1"));
    assert!(display.contains("Alternative One"));
}

#[test]
fn alternate_policy_serde() {
    let ap = make_alternate_policy("alt-1", "Test");
    let json = serde_json::to_string(&ap).unwrap();
    let back: AlternatePolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ap);
}

// ===========================================================================
// 3. ReplayScope
// ===========================================================================

#[test]
fn replay_scope_default() {
    let scope = ReplayScope::default();
    assert_eq!(scope.start_epoch, SecurityEpoch::GENESIS);
    assert_eq!(scope.start_tick, 0);
    assert!(scope.incident_filter.is_empty());
    assert_eq!(scope.min_decisions, 1);
}

#[test]
fn replay_scope_serde() {
    let scope = default_scope();
    let json = serde_json::to_string(&scope).unwrap();
    let back: ReplayScope = serde_json::from_str(&json).unwrap();
    assert_eq!(back, scope);
}

// ===========================================================================
// 4. AssumptionCategory
// ===========================================================================

#[test]
fn assumption_category_display() {
    assert_eq!(
        AssumptionCategory::NoUnmeasuredConfounding.to_string(),
        "no-unmeasured-confounding"
    );
    assert_eq!(AssumptionCategory::Positivity.to_string(), "positivity");
    assert_eq!(AssumptionCategory::Consistency.to_string(), "consistency");
    assert_eq!(AssumptionCategory::Sutva.to_string(), "sutva");
    assert_eq!(
        AssumptionCategory::ModelSpecification.to_string(),
        "model-specification"
    );
    assert_eq!(
        AssumptionCategory::TemporalStability.to_string(),
        "temporal-stability"
    );
}

#[test]
fn assumption_category_serde() {
    for cat in [
        AssumptionCategory::NoUnmeasuredConfounding,
        AssumptionCategory::Positivity,
        AssumptionCategory::Consistency,
        AssumptionCategory::Sutva,
        AssumptionCategory::ModelSpecification,
        AssumptionCategory::TemporalStability,
    ] {
        let json = serde_json::to_string(&cat).unwrap();
        let back: AssumptionCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cat);
    }
}

// ===========================================================================
// 5. ReplayEngineError
// ===========================================================================

#[test]
fn replay_engine_error_display() {
    let errors: Vec<ReplayEngineError> = vec![
        ReplayEngineError::NoTraces,
        ReplayEngineError::NoPolicies,
        ReplayEngineError::TooManyPolicies {
            count: 100,
            max: 64,
        },
        ReplayEngineError::TooManyDecisions {
            count: 200_000,
            max: 100_000,
        },
        ReplayEngineError::InsufficientDecisions {
            found: 1,
            required: 10,
        },
        ReplayEngineError::TraceIntegrityFailure {
            trace_id: "t1".into(),
            detail: "bad chain".into(),
        },
        ReplayEngineError::IdDerivation("id error".into()),
        ReplayEngineError::EmptyScope,
        ReplayEngineError::DuplicatePolicy {
            policy_id: "dup".into(),
        },
    ];
    for e in &errors {
        assert!(!e.to_string().is_empty());
    }
}

#[test]
fn replay_engine_error_serde() {
    let err = ReplayEngineError::NoTraces;
    let json = serde_json::to_string(&err).unwrap();
    let back: ReplayEngineError = serde_json::from_str(&json).unwrap();
    assert_eq!(back, err);
}

// ===========================================================================
// 6. ReplayEngineConfig
// ===========================================================================

#[test]
fn config_default() {
    let config = ReplayEngineConfig::default();
    assert_eq!(config.baseline_policy_id, PolicyId("baseline".to_string()));
    assert_eq!(config.estimator, EstimatorKind::DoublyRobust);
    assert!(config.regime_breakdown);
    assert!(config.record_divergences);
    assert!(config.verify_integrity);
}

#[test]
fn config_serde() {
    let config = ReplayEngineConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: ReplayEngineConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, config);
}

// ===========================================================================
// 7. CounterfactualReplayEngine — construction
// ===========================================================================

#[test]
fn engine_new_initial_state() {
    let engine = default_engine();
    assert_eq!(engine.replay_count(), 0);
    assert_eq!(
        engine.config().baseline_policy_id,
        PolicyId("baseline".to_string())
    );
}

// ===========================================================================
// 8. CounterfactualReplayEngine — compare: error paths
// ===========================================================================

#[test]
fn compare_no_traces_error() {
    let mut engine = default_engine();
    let result = engine.compare(
        &[],
        &[make_alternate_policy("alt", "d")],
        &default_scope(),
        None,
    );
    assert!(matches!(result, Err(ReplayEngineError::NoTraces)));
}

#[test]
fn compare_no_policies_error() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let result = engine.compare(&[trace], &[], &default_scope(), None);
    assert!(matches!(result, Err(ReplayEngineError::NoPolicies)));
}

#[test]
fn compare_duplicate_policy_error() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let policies = vec![
        make_alternate_policy("same-id", "first"),
        make_alternate_policy("same-id", "second"),
    ];
    let result = engine.compare(&[trace], &policies, &default_scope(), None);
    assert!(matches!(
        result,
        Err(ReplayEngineError::DuplicatePolicy { .. })
    ));
}

#[test]
fn compare_insufficient_decisions_error() {
    let mut engine = default_engine();
    let trace = simple_trace(); // 3 decisions
    let mut scope = default_scope();
    scope.min_decisions = 1000; // require more than we have
    let result = engine.compare(&[trace], &[make_alternate_policy("alt", "d")], &scope, None);
    assert!(matches!(
        result,
        Err(ReplayEngineError::InsufficientDecisions { .. })
    ));
}

// ===========================================================================
// 9. CounterfactualReplayEngine — compare: success
// ===========================================================================

#[test]
fn compare_single_policy_success() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let policies = vec![make_alternate_policy("alt-threshold", "Higher threshold")];
    let result = engine
        .compare(&[trace], &policies, &default_scope(), None)
        .unwrap();

    assert_eq!(result.schema_version, REPLAY_ENGINE_SCHEMA_VERSION);
    assert_eq!(result.trace_count, 1);
    assert_eq!(result.total_decisions, 3);
    assert_eq!(result.policy_reports.len(), 1);
    assert_eq!(result.ranked_recommendations.len(), 1);
    assert!(!result.global_assumptions.is_empty());
}

#[test]
fn compare_increments_replay_count() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let policies = vec![make_alternate_policy("alt", "d")];
    engine
        .compare(
            std::slice::from_ref(&trace),
            &policies,
            &default_scope(),
            None,
        )
        .unwrap();
    assert_eq!(engine.replay_count(), 1);
    engine
        .compare(
            std::slice::from_ref(&trace),
            &policies,
            &default_scope(),
            None,
        )
        .unwrap();
    assert_eq!(engine.replay_count(), 2);
}

#[test]
fn compare_multiple_policies() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let policies = vec![
        make_alternate_policy("alt-1", "Policy 1"),
        make_alternate_policy("alt-2", "Policy 2"),
        make_override_policy("force-safe", LaneAction::FallbackSafe),
    ];
    let result = engine
        .compare(&[trace], &policies, &default_scope(), None)
        .unwrap();

    assert_eq!(result.policy_reports.len(), 3);
    assert_eq!(result.ranked_recommendations.len(), 3);
    // Recommendations should be ranked 1, 2, 3
    assert_eq!(result.ranked_recommendations[0].rank, 1);
    assert_eq!(result.ranked_recommendations[1].rank, 2);
    assert_eq!(result.ranked_recommendations[2].rank, 3);
}

// ===========================================================================
// 10. PolicyComparisonReport
// ===========================================================================

#[test]
fn policy_report_fields() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let policies = vec![make_alternate_policy("alt", "d")];
    let result = engine
        .compare(&[trace], &policies, &default_scope(), None)
        .unwrap();
    let report = &result.policy_reports[0];

    assert_eq!(report.schema_version, REPLAY_ENGINE_SCHEMA_VERSION);
    assert_eq!(report.baseline_policy_id, PolicyId("baseline".into()));
    assert_eq!(report.alternate_policy_id, PolicyId("alt".into()));
    assert_eq!(report.decisions_evaluated, 3);
    assert!(!report.assumptions.is_empty());
}

#[test]
fn policy_report_divergence_rate() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let policies = vec![make_override_policy("force-safe", LaneAction::FallbackSafe)];
    let result = engine
        .compare(&[trace], &policies, &default_scope(), None)
        .unwrap();
    let report = &result.policy_reports[0];
    // With FallbackSafe override, all actions should diverge
    let rate = report.divergence_rate_millionths();
    assert!(
        rate > 0,
        "expected some divergences with forced action override"
    );
}

#[test]
fn policy_report_serde() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let policies = vec![make_alternate_policy("alt", "d")];
    let result = engine
        .compare(&[trace], &policies, &default_scope(), None)
        .unwrap();
    let report = &result.policy_reports[0];

    let json = serde_json::to_string(report).unwrap();
    let back: PolicyComparisonReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back, *report);
}

// ===========================================================================
// 11. Recommendation
// ===========================================================================

#[test]
fn recommendation_display() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let policies = vec![make_alternate_policy("alt-x", "d")];
    let result = engine
        .compare(&[trace], &policies, &default_scope(), None)
        .unwrap();

    let rec = &result.ranked_recommendations[0];
    let display = rec.to_string();
    assert!(display.contains("alt-x"));
    assert!(display.contains("#1"));
}

#[test]
fn recommendation_serde() {
    let rec = Recommendation {
        rank: 1,
        policy_id: PolicyId("alt-1".into()),
        expected_improvement_millionths: 100_000,
        confidence_millionths: 950_000,
        safety_status: EnvelopeStatus::Safe,
        rationale: "test".into(),
    };
    let json = serde_json::to_string(&rec).unwrap();
    let back: Recommendation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, rec);
}

// ===========================================================================
// 12. AssumptionCard
// ===========================================================================

#[test]
fn assumption_card_serde() {
    let card = AssumptionCard {
        assumption_id: "test".into(),
        category: AssumptionCategory::Consistency,
        description: "test assumption".into(),
        testable: false,
        test_passed: None,
        sensitivity_bound_millionths: 0,
    };
    let json = serde_json::to_string(&card).unwrap();
    let back: AssumptionCard = serde_json::from_str(&json).unwrap();
    assert_eq!(back, card);
}

// ===========================================================================
// 13. DecisionComparison
// ===========================================================================

#[test]
fn decision_comparison_serde() {
    let dc = DecisionComparison {
        decision_index: 0,
        tick: 100,
        epoch: test_epoch(),
        original_action: "native".into(),
        alternate_action: "wasm".into(),
        original_outcome_millionths: 800_000,
        counterfactual_outcome_millionths: 600_000,
        diverged: true,
        regime: "normal".into(),
    };
    let json = serde_json::to_string(&dc).unwrap();
    let back: DecisionComparison = serde_json::from_str(&json).unwrap();
    assert_eq!(back, dc);
}

// ===========================================================================
// 14. ReplayComparisonResult
// ===========================================================================

#[test]
fn comparison_result_serde() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let policies = vec![make_alternate_policy("alt", "d")];
    let result = engine
        .compare(&[trace], &policies, &default_scope(), None)
        .unwrap();

    let json = serde_json::to_string(&result).unwrap();
    let back: ReplayComparisonResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, result);
}

#[test]
fn comparison_result_artifact_hash_deterministic() {
    let mut engine1 = default_engine();
    let mut engine2 = default_engine();
    let trace = simple_trace();
    let policies = vec![make_alternate_policy("alt", "d")];
    let scope = default_scope();

    let r1 = engine1
        .compare(std::slice::from_ref(&trace), &policies, &scope, None)
        .unwrap();
    let r2 = engine2
        .compare(std::slice::from_ref(&trace), &policies, &scope, None)
        .unwrap();
    assert_eq!(r1.artifact_hash, r2.artifact_hash);
}

#[test]
fn policy_report_artifact_hash_tracks_public_report_content() {
    let trace = simple_trace();
    let mut engine_a = default_engine();
    let mut engine_b = default_engine();
    let policy_a = vec![make_alternate_policy("alt", "description-a")];
    let policy_b = vec![make_alternate_policy("alt", "description-b")];

    let result_a = engine_a
        .compare(
            std::slice::from_ref(&trace),
            &policy_a,
            &default_scope(),
            None,
        )
        .unwrap();
    let result_b = engine_b
        .compare(
            std::slice::from_ref(&trace),
            &policy_b,
            &default_scope(),
            None,
        )
        .unwrap();

    assert_ne!(
        result_a.policy_reports[0].alternate_description,
        result_b.policy_reports[0].alternate_description
    );
    assert_ne!(
        result_a.policy_reports[0].artifact_hash,
        result_b.policy_reports[0].artifact_hash
    );
}

#[test]
fn comparison_result_artifact_hash_tracks_scope_payload() {
    let trace = simple_trace();
    let policies = vec![make_alternate_policy("alt", "d")];
    let mut engine_a = default_engine();
    let mut engine_b = default_engine();
    let scope_a = default_scope();
    let mut scope_b = default_scope();
    scope_b.start_tick = 100;

    let result_a = engine_a
        .compare(std::slice::from_ref(&trace), &policies, &scope_a, None)
        .unwrap();
    let result_b = engine_b
        .compare(&[trace], &policies, &scope_b, None)
        .unwrap();

    assert_eq!(result_a.total_decisions, result_b.total_decisions);
    assert_eq!(result_a.trace_count, result_b.trace_count);
    assert_eq!(result_a.policy_reports, result_b.policy_reports);
    assert_ne!(result_a.scope, result_b.scope);
    assert_ne!(result_a.artifact_hash, result_b.artifact_hash);
}

// ===========================================================================
// 15. Scoped replay
// ===========================================================================

#[test]
fn compare_with_epoch_scope() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let mut scope = default_scope();
    scope.start_epoch = test_epoch();
    scope.end_epoch = test_epoch();
    let policies = vec![make_alternate_policy("alt", "d")];
    let result = engine.compare(&[trace], &policies, &scope, None).unwrap();
    assert_eq!(result.total_decisions, 3);
}

#[test]
fn compare_with_empty_scope_error() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let mut scope = default_scope();
    // Set scope to an epoch range that excludes all decisions
    scope.start_epoch = SecurityEpoch::from_raw(999);
    scope.end_epoch = SecurityEpoch::from_raw(1000);
    let policies = vec![make_alternate_policy("alt", "d")];
    let result = engine.compare(&[trace], &policies, &scope, None);
    assert!(matches!(result, Err(ReplayEngineError::EmptyScope)));
}

// ===========================================================================
// 16. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_compare_rank_serialize() {
    // 1. Build traces
    let trace = make_trace(vec![
        make_decision(0, "native", 800_000),
        make_decision(1, "native", 900_000),
        make_decision(2, "wasm", 600_000),
        make_decision(3, "native", 700_000),
        make_decision(4, "native", 850_000),
    ]);

    // 2. Define alternate policies
    let policies = vec![
        make_alternate_policy("higher-threshold", "Raise threshold to 600k"),
        make_override_policy("force-safe", LaneAction::FallbackSafe),
    ];

    // 3. Run comparison
    let mut engine = default_engine();
    let result = engine
        .compare(&[trace], &policies, &default_scope(), None)
        .unwrap();

    // 4. Verify structure
    assert_eq!(result.trace_count, 1);
    assert_eq!(result.total_decisions, 5);
    assert_eq!(result.policy_reports.len(), 2);
    assert_eq!(result.ranked_recommendations.len(), 2);
    assert!(!result.global_assumptions.is_empty());

    // 5. Verify ranking order
    let recs = &result.ranked_recommendations;
    assert_eq!(recs[0].rank, 1);
    assert_eq!(recs[1].rank, 2);
    // Best recommendation should have higher improvement
    assert!(recs[0].expected_improvement_millionths >= recs[1].expected_improvement_millionths);

    // 6. Verify reports have assumptions
    for report in &result.policy_reports {
        assert!(!report.assumptions.is_empty());
        assert_eq!(report.decisions_evaluated, 5);
    }

    // 7. Serde round-trip
    let json = serde_json::to_string(&result).unwrap();
    let back: ReplayComparisonResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, result);

    // 8. Engine state
    assert_eq!(engine.replay_count(), 1);
}

// ===========================================================================
// 17. PolicyComparisonReport edge cases
// ===========================================================================

#[test]
fn policy_report_is_confident_improvement() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let policies = vec![make_alternate_policy("alt", "d")];
    let result = engine
        .compare(&[trace], &policies, &default_scope(), None)
        .unwrap();
    let report = &result.policy_reports[0];
    // is_confident_improvement depends on safety_status == Safe AND net > 0
    let expected =
        report.safety_status == EnvelopeStatus::Safe && report.net_improvement_millionths > 0;
    assert_eq!(report.is_confident_improvement(), expected);
}

#[test]
fn policy_report_divergence_rate_zero_decisions() {
    // A manually constructed report with zero decisions
    let report = PolicyComparisonReport {
        schema_version: REPLAY_ENGINE_SCHEMA_VERSION.to_string(),
        baseline_policy_id: PolicyId("base".to_string()),
        alternate_policy_id: PolicyId("alt".to_string()),
        alternate_description: "test".to_string(),
        decisions_evaluated: 0,
        divergence_count: 0,
        total_original_outcome_millionths: 0,
        total_counterfactual_outcome_millionths: 0,
        net_improvement_millionths: 0,
        regime_breakdown: BTreeMap::new(),
        confidence_envelope: frankenengine_engine::counterfactual_evaluator::ConfidenceEnvelope {
            estimate_millionths: 0,
            lower_millionths: 0,
            upper_millionths: 0,
            confidence_millionths: 950_000,
            effective_samples: 0,
        },
        safety_status: EnvelopeStatus::Inconclusive,
        divergent_decisions: vec![],
        assumptions: vec![],
        artifact_hash: ContentHash::compute(b"test"),
    };
    assert_eq!(report.divergence_rate_millionths(), 0);
}

// ===========================================================================
// 18. ReplayEngineError additional coverage
// ===========================================================================

#[test]
fn replay_engine_error_is_std_error() {
    let err = ReplayEngineError::NoTraces;
    let _: &dyn std::error::Error = &err;
}

#[test]
fn replay_engine_error_all_variants_serde() {
    let errors = vec![
        ReplayEngineError::NoTraces,
        ReplayEngineError::NoPolicies,
        ReplayEngineError::TooManyPolicies {
            count: 100,
            max: 64,
        },
        ReplayEngineError::TooManyDecisions {
            count: 200_000,
            max: 100_000,
        },
        ReplayEngineError::InsufficientDecisions {
            found: 1,
            required: 10,
        },
        ReplayEngineError::TraceIntegrityFailure {
            trace_id: "t1".into(),
            detail: "bad".into(),
        },
        ReplayEngineError::IdDerivation("id err".into()),
        ReplayEngineError::EmptyScope,
        ReplayEngineError::DuplicatePolicy {
            policy_id: "dup".into(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ReplayEngineError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ===========================================================================
// 19. Multiple traces
// ===========================================================================

#[test]
fn compare_multiple_traces() {
    let mut engine = default_engine();
    let trace1 = make_trace(vec![
        make_decision(0, "native", 800_000),
        make_decision(1, "wasm", 600_000),
    ]);
    let trace2 = make_trace(vec![
        make_decision(0, "native", 700_000),
        make_decision(1, "native", 900_000),
        make_decision(2, "wasm", 500_000),
    ]);
    let policies = vec![make_alternate_policy("alt", "d")];
    let result = engine
        .compare(&[trace1, trace2], &policies, &default_scope(), None)
        .unwrap();
    assert_eq!(result.trace_count, 2);
    assert_eq!(result.total_decisions, 5);
}

// ===========================================================================
// 20. AssumptionCard with testable fields
// ===========================================================================

#[test]
fn assumption_card_testable_with_result() {
    let card = AssumptionCard {
        assumption_id: "test-pass".into(),
        category: AssumptionCategory::Positivity,
        description: "positivity holds".into(),
        testable: true,
        test_passed: Some(true),
        sensitivity_bound_millionths: 50_000,
    };
    let json = serde_json::to_string(&card).unwrap();
    let back: AssumptionCard = serde_json::from_str(&json).unwrap();
    assert_eq!(back, card);
    assert!(back.testable);
    assert_eq!(back.test_passed, Some(true));
}

#[test]
fn assumption_card_testable_failed() {
    let card = AssumptionCard {
        assumption_id: "test-fail".into(),
        category: AssumptionCategory::Sutva,
        description: "SUTVA violated".into(),
        testable: true,
        test_passed: Some(false),
        sensitivity_bound_millionths: 200_000,
    };
    let json = serde_json::to_string(&card).unwrap();
    let back: AssumptionCard = serde_json::from_str(&json).unwrap();
    assert_eq!(back.test_passed, Some(false));
}

// ===========================================================================
// 21. Config with non-default settings
// ===========================================================================

#[test]
fn config_non_default_settings() {
    let config = ReplayEngineConfig {
        baseline_policy_id: PolicyId("custom-baseline".to_string()),
        baseline_action: LaneAction::SuspendAdaptive,
        estimator: EstimatorKind::Ips,
        confidence_millionths: 990_000,
        regime_breakdown: false,
        record_divergences: false,
        max_divergences_per_policy: 10,
        verify_integrity: false,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: ReplayEngineConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, config);
    assert!(!back.regime_breakdown);
    assert!(!back.record_divergences);
}

// ===========================================================================
// 22. ReplayScope with incident filter
// ===========================================================================

#[test]
fn replay_scope_with_incident_filter_serde() {
    let mut scope = ReplayScope::default();
    scope.incident_filter.insert("incident-1".to_string());
    scope.incident_filter.insert("incident-2".to_string());
    scope.min_decisions = 5;
    let json = serde_json::to_string(&scope).unwrap();
    let back: ReplayScope = serde_json::from_str(&json).unwrap();
    assert_eq!(back, scope);
    assert_eq!(back.incident_filter.len(), 2);
}

// ===========================================================================
// 23. Ranked recommendations ordering
// ===========================================================================

#[test]
fn recommendations_ranked_by_improvement() {
    let mut engine = default_engine();
    let trace = make_trace(vec![
        make_decision(0, "native", 800_000),
        make_decision(1, "wasm", 600_000),
        make_decision(2, "native", 900_000),
        make_decision(3, "wasm", 400_000),
    ]);
    let policies = vec![
        make_alternate_policy("alt-1", "d1"),
        make_alternate_policy("alt-2", "d2"),
        make_override_policy("force-safe", LaneAction::FallbackSafe),
    ];
    let result = engine
        .compare(&[trace], &policies, &default_scope(), None)
        .unwrap();
    let recs = &result.ranked_recommendations;
    // Ranks should be monotonically increasing
    for window in recs.windows(2) {
        assert!(window[0].rank < window[1].rank);
    }
}

// ===========================================================================
// 24. Global assumptions present
// ===========================================================================

#[test]
fn global_assumptions_non_empty() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let policies = vec![make_alternate_policy("alt", "d")];
    let result = engine
        .compare(&[trace], &policies, &default_scope(), None)
        .unwrap();
    assert!(!result.global_assumptions.is_empty());
    for a in &result.global_assumptions {
        assert!(!a.assumption_id.is_empty());
        assert!(!a.description.is_empty());
    }
}
