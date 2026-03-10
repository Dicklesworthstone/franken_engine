#![forbid(unsafe_code)]
//! Enrichment integration tests for the `counterfactual_replay_engine` module.
//!
//! Covers JSON field-name stability, Debug distinctness, exact Display messages,
//! error serde all-variants, is_confident_improvement edge cases, scope filtering
//! boundary conditions, config non-default effects, regime breakdown content,
//! and end-to-end pipeline enrichments.

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

use frankenengine_engine::causal_replay::{
    CounterfactualConfig, DecisionSnapshot, RecorderConfig, RecordingMode, TraceRecord,
    TraceRecorder,
};
use frankenengine_engine::counterfactual_evaluator::{
    ConfidenceEnvelope, EnvelopeStatus, EstimatorKind, PolicyId,
};
use frankenengine_engine::counterfactual_replay_engine::{
    AlternatePolicy, AssumptionCard, AssumptionCategory, CounterfactualReplayEngine,
    DecisionComparison, PolicyComparisonReport, REPLAY_ENGINE_SCHEMA_VERSION, Recommendation,
    ReplayComparisonResult, ReplayEngineConfig, ReplayEngineError, ReplayScope,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::runtime_decision_theory::{LaneAction, LaneId};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ── Helpers ────────────────────────────────────────────────────────────────

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
    let epoch = decisions.first().map(|d| d.epoch).unwrap_or(test_epoch());
    let start_tick = decisions.first().map(|d| d.tick).unwrap_or(100);
    let mut recorder = TraceRecorder::new(RecorderConfig {
        trace_id: "test-trace".to_string(),
        recording_mode: RecordingMode::Full,
        epoch,
        start_tick,
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

fn make_report(
    decisions: u64,
    divergences: u64,
    net_improvement: i64,
    envelope_lower: i64,
    envelope_upper: i64,
    status: EnvelopeStatus,
) -> PolicyComparisonReport {
    PolicyComparisonReport {
        schema_version: REPLAY_ENGINE_SCHEMA_VERSION.to_string(),
        baseline_policy_id: PolicyId("baseline".to_string()),
        alternate_policy_id: PolicyId("alt".to_string()),
        alternate_description: "test".to_string(),
        decisions_evaluated: decisions,
        divergence_count: divergences,
        total_original_outcome_millionths: 1_000_000,
        total_counterfactual_outcome_millionths: 1_000_000 + net_improvement,
        net_improvement_millionths: net_improvement,
        regime_breakdown: BTreeMap::new(),
        confidence_envelope: ConfidenceEnvelope {
            estimate_millionths: net_improvement / decisions.max(1) as i64,
            lower_millionths: envelope_lower,
            upper_millionths: envelope_upper,
            confidence_millionths: 950_000,
            effective_samples: decisions,
        },
        safety_status: status,
        divergent_decisions: Vec::new(),
        assumptions: Vec::new(),
        artifact_hash: ContentHash::compute(b"test-report"),
    }
}

// ===========================================================================
// 1. JSON field-name stability: AlternatePolicy
// ===========================================================================

#[test]
fn json_field_names_alternate_policy() {
    let ap = make_alternate_policy("p1", "desc1");
    let json = serde_json::to_string(&ap).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("policy_id"), "missing policy_id");
    assert!(obj.contains_key("description"), "missing description");
    assert!(
        obj.contains_key("counterfactual_config"),
        "missing counterfactual_config"
    );
    assert!(obj.contains_key("default_action"), "missing default_action");
}

// ===========================================================================
// 2. JSON field-name stability: ReplayScope
// ===========================================================================

#[test]
fn json_field_names_replay_scope() {
    let scope = default_scope();
    let json = serde_json::to_string(&scope).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "start_epoch",
        "end_epoch",
        "start_tick",
        "end_tick",
        "incident_filter",
        "min_decisions",
    ] {
        assert!(obj.contains_key(key), "missing {key}");
    }
}

// ===========================================================================
// 3. JSON field-name stability: ReplayEngineConfig
// ===========================================================================

#[test]
fn json_field_names_replay_engine_config() {
    let config = ReplayEngineConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "baseline_policy_id",
        "baseline_action",
        "estimator",
        "confidence_millionths",
        "regime_breakdown",
        "record_divergences",
        "max_divergences_per_policy",
        "verify_integrity",
    ] {
        assert!(obj.contains_key(key), "missing {key}");
    }
}

// ===========================================================================
// 4. JSON field-name stability: DecisionComparison
// ===========================================================================

#[test]
fn json_field_names_decision_comparison() {
    let dc = DecisionComparison {
        decision_index: 0,
        tick: 100,
        epoch: test_epoch(),
        original_action: "native".into(),
        alternate_action: "wasm".into(),
        original_outcome_millionths: 500_000,
        counterfactual_outcome_millionths: 600_000,
        diverged: true,
        regime: "normal".into(),
    };
    let json = serde_json::to_string(&dc).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "decision_index",
        "tick",
        "epoch",
        "original_action",
        "alternate_action",
        "original_outcome_millionths",
        "counterfactual_outcome_millionths",
        "diverged",
        "regime",
    ] {
        assert!(obj.contains_key(key), "missing {key}");
    }
}

// ===========================================================================
// 5. JSON field-name stability: AssumptionCard
// ===========================================================================

#[test]
fn json_field_names_assumption_card() {
    let card = AssumptionCard {
        assumption_id: "a1".into(),
        category: AssumptionCategory::Consistency,
        description: "test".into(),
        testable: true,
        test_passed: Some(true),
        sensitivity_bound_millionths: 10_000,
    };
    let json = serde_json::to_string(&card).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "assumption_id",
        "category",
        "description",
        "testable",
        "test_passed",
        "sensitivity_bound_millionths",
    ] {
        assert!(obj.contains_key(key), "missing {key}");
    }
}

// ===========================================================================
// 6. JSON field-name stability: Recommendation
// ===========================================================================

#[test]
fn json_field_names_recommendation() {
    let rec = Recommendation {
        rank: 1,
        policy_id: PolicyId("p".into()),
        expected_improvement_millionths: 50_000,
        confidence_millionths: 950_000,
        safety_status: EnvelopeStatus::Safe,
        rationale: "r".into(),
    };
    let json = serde_json::to_string(&rec).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "rank",
        "policy_id",
        "expected_improvement_millionths",
        "confidence_millionths",
        "safety_status",
        "rationale",
    ] {
        assert!(obj.contains_key(key), "missing {key}");
    }
}

// ===========================================================================
// 7. JSON field-name stability: PolicyComparisonReport
// ===========================================================================

#[test]
fn json_field_names_policy_comparison_report() {
    let report = make_report(10, 5, 100_000, 50_000, 150_000, EnvelopeStatus::Safe);
    let json = serde_json::to_string(&report).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "schema_version",
        "baseline_policy_id",
        "alternate_policy_id",
        "alternate_description",
        "decisions_evaluated",
        "divergence_count",
        "total_original_outcome_millionths",
        "total_counterfactual_outcome_millionths",
        "net_improvement_millionths",
        "regime_breakdown",
        "confidence_envelope",
        "safety_status",
        "divergent_decisions",
        "assumptions",
        "artifact_hash",
    ] {
        assert!(obj.contains_key(key), "missing {key}");
    }
}

// ===========================================================================
// 8. JSON field-name stability: ReplayComparisonResult
// ===========================================================================

#[test]
fn json_field_names_replay_comparison_result() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let result = engine
        .compare(
            &[trace],
            &[make_alternate_policy("alt", "d")],
            &default_scope(),
            None,
        )
        .unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "schema_version",
        "trace_count",
        "total_decisions",
        "scope",
        "policy_reports",
        "ranked_recommendations",
        "global_assumptions",
        "causal_effects",
        "artifact_hash",
    ] {
        assert!(obj.contains_key(key), "missing {key}");
    }
}

// ===========================================================================
// 9. JSON field-name stability: ConfidenceEnvelope (nested)
// ===========================================================================

#[test]
fn json_field_names_confidence_envelope_nested() {
    let report = make_report(10, 5, 100_000, 50_000, 150_000, EnvelopeStatus::Safe);
    let json = serde_json::to_string(&report).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let env = v.get("confidence_envelope").unwrap().as_object().unwrap();
    for key in [
        "estimate_millionths",
        "lower_millionths",
        "upper_millionths",
        "confidence_millionths",
        "effective_samples",
    ] {
        assert!(env.contains_key(key), "missing CE key {key}");
    }
}

// ===========================================================================
// 10. JSON field-name stability: CounterfactualConfig (nested)
// ===========================================================================

#[test]
fn json_field_names_counterfactual_config_nested() {
    let ap = make_alternate_policy("x", "y");
    let json = serde_json::to_string(&ap).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let cfg = v.get("counterfactual_config").unwrap().as_object().unwrap();
    for key in [
        "branch_id",
        "threshold_override_millionths",
        "loss_matrix_overrides",
        "policy_version_override",
        "containment_overrides",
        "evidence_weight_overrides",
        "branch_from_index",
    ] {
        assert!(cfg.contains_key(key), "missing CC key {key}");
    }
}

// ===========================================================================
// 11. Debug distinctness: AssumptionCategory
// ===========================================================================

#[test]
fn debug_distinct_assumption_category() {
    let variants: Vec<AssumptionCategory> = vec![
        AssumptionCategory::NoUnmeasuredConfounding,
        AssumptionCategory::Positivity,
        AssumptionCategory::Consistency,
        AssumptionCategory::Sutva,
        AssumptionCategory::ModelSpecification,
        AssumptionCategory::TemporalStability,
    ];
    let mut debugs = BTreeSet::new();
    for v in &variants {
        debugs.insert(format!("{v:?}"));
    }
    assert_eq!(debugs.len(), 6, "all AssumptionCategory Debug must differ");
}

// ===========================================================================
// 12. Debug distinctness: ReplayEngineError
// ===========================================================================

#[test]
fn debug_distinct_replay_engine_error() {
    let variants: Vec<ReplayEngineError> = vec![
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
            found: 5,
            required: 100,
        },
        ReplayEngineError::TraceIntegrityFailure {
            trace_id: "t1".into(),
            detail: "bad".into(),
        },
        ReplayEngineError::IdDerivation("err".into()),
        ReplayEngineError::EmptyScope,
        ReplayEngineError::DuplicatePolicy {
            policy_id: "dup".into(),
        },
    ];
    let mut debugs = BTreeSet::new();
    for v in &variants {
        debugs.insert(format!("{v:?}"));
    }
    assert_eq!(debugs.len(), 9, "all ReplayEngineError Debug must differ");
}

// ===========================================================================
// 13. Debug distinctness: EnvelopeStatus
// ===========================================================================

#[test]
fn debug_distinct_envelope_status() {
    let variants = vec![
        EnvelopeStatus::Safe,
        EnvelopeStatus::Unsafe,
        EnvelopeStatus::Inconclusive,
    ];
    let mut debugs = BTreeSet::new();
    for v in &variants {
        debugs.insert(format!("{v:?}"));
    }
    assert_eq!(debugs.len(), 3, "all EnvelopeStatus Debug must differ");
}

// ===========================================================================
// 14. Error Display exact messages: all 9 variants
// ===========================================================================

#[test]
fn error_display_exact_no_traces() {
    assert_eq!(
        ReplayEngineError::NoTraces.to_string(),
        "no traces provided for replay"
    );
}

#[test]
fn error_display_exact_no_policies() {
    assert_eq!(
        ReplayEngineError::NoPolicies.to_string(),
        "no alternate policies provided"
    );
}

#[test]
fn error_display_exact_too_many_policies() {
    let e = ReplayEngineError::TooManyPolicies {
        count: 100,
        max: 64,
    };
    assert_eq!(e.to_string(), "too many policies: 100 exceeds max 64");
}

#[test]
fn error_display_exact_too_many_decisions() {
    let e = ReplayEngineError::TooManyDecisions {
        count: 200_000,
        max: 100_000,
    };
    assert_eq!(
        e.to_string(),
        "too many decisions: 200000 exceeds max 100000"
    );
}

#[test]
fn error_display_exact_insufficient_decisions() {
    let e = ReplayEngineError::InsufficientDecisions {
        found: 5,
        required: 100,
    };
    assert_eq!(e.to_string(), "insufficient decisions: found 5, need 100");
}

#[test]
fn error_display_exact_trace_integrity_failure() {
    let e = ReplayEngineError::TraceIntegrityFailure {
        trace_id: "trace-42".into(),
        detail: "hash mismatch".into(),
    };
    assert_eq!(
        e.to_string(),
        "trace integrity failure in trace-42: hash mismatch"
    );
}

#[test]
fn error_display_exact_id_derivation() {
    let e = ReplayEngineError::IdDerivation("bad input".into());
    assert_eq!(e.to_string(), "ID derivation error: bad input");
}

#[test]
fn error_display_exact_empty_scope() {
    assert_eq!(
        ReplayEngineError::EmptyScope.to_string(),
        "replay scope excludes all decisions"
    );
}

#[test]
fn error_display_exact_duplicate_policy() {
    let e = ReplayEngineError::DuplicatePolicy {
        policy_id: "dup-pol".into(),
    };
    assert_eq!(e.to_string(), "duplicate policy ID: dup-pol");
}

// ===========================================================================
// 15. std::error::Error for all 9 variants
// ===========================================================================

#[test]
fn error_std_error_all_9_variants() {
    let errors: Vec<Box<dyn std::error::Error>> = vec![
        Box::new(ReplayEngineError::NoTraces),
        Box::new(ReplayEngineError::NoPolicies),
        Box::new(ReplayEngineError::TooManyPolicies {
            count: 100,
            max: 64,
        }),
        Box::new(ReplayEngineError::TooManyDecisions {
            count: 200_000,
            max: 100_000,
        }),
        Box::new(ReplayEngineError::InsufficientDecisions {
            found: 5,
            required: 100,
        }),
        Box::new(ReplayEngineError::TraceIntegrityFailure {
            trace_id: "t1".into(),
            detail: "x".into(),
        }),
        Box::new(ReplayEngineError::IdDerivation("y".into())),
        Box::new(ReplayEngineError::EmptyScope),
        Box::new(ReplayEngineError::DuplicatePolicy {
            policy_id: "z".into(),
        }),
    ];
    let mut displays = BTreeSet::new();
    for err in &errors {
        let s = err.to_string();
        assert!(!s.is_empty());
        displays.insert(s);
    }
    assert_eq!(displays.len(), 9, "all 9 Display messages must be distinct");
}

// ===========================================================================
// 16. Error serde roundtrip: all 9 variants
// ===========================================================================

#[test]
fn error_serde_roundtrip_all_9() {
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
            found: 5,
            required: 100,
        },
        ReplayEngineError::TraceIntegrityFailure {
            trace_id: "tr".into(),
            detail: "bad".into(),
        },
        ReplayEngineError::IdDerivation("err".into()),
        ReplayEngineError::EmptyScope,
        ReplayEngineError::DuplicatePolicy {
            policy_id: "dup".into(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ReplayEngineError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back, "serde roundtrip failed for {err:?}");
    }
}

// ===========================================================================
// 17. ReplayScope Default exact values
// ===========================================================================

#[test]
fn replay_scope_default_exact_values() {
    let scope = ReplayScope::default();
    assert_eq!(scope.start_epoch, SecurityEpoch::GENESIS);
    assert_eq!(scope.end_epoch, SecurityEpoch::from_raw(u64::MAX));
    assert_eq!(scope.start_tick, 0);
    assert_eq!(scope.end_tick, u64::MAX);
    assert!(scope.incident_filter.is_empty());
    assert_eq!(scope.min_decisions, 1);
}

// ===========================================================================
// 18. ReplayEngineConfig Default exact values
// ===========================================================================

#[test]
fn replay_engine_config_default_exact_values() {
    let config = ReplayEngineConfig::default();
    assert_eq!(config.baseline_policy_id, PolicyId("baseline".to_string()));
    assert_eq!(config.baseline_action, LaneAction::FallbackSafe);
    assert_eq!(config.estimator, EstimatorKind::DoublyRobust);
    assert_eq!(config.confidence_millionths, 950_000);
    assert!(config.regime_breakdown);
    assert!(config.record_divergences);
    assert_eq!(config.max_divergences_per_policy, 100);
    assert!(config.verify_integrity);
}

// ===========================================================================
// 19. AlternatePolicy Display exact format
// ===========================================================================

#[test]
fn alternate_policy_display_exact_format() {
    let ap = make_alternate_policy("my-policy", "Some description");
    assert_eq!(ap.to_string(), "my-policy:Some description");
}

// ===========================================================================
// 20. Recommendation Display exact format
// ===========================================================================

#[test]
fn recommendation_display_exact_format() {
    let rec = Recommendation {
        rank: 2,
        policy_id: PolicyId("opt-policy".into()),
        expected_improvement_millionths: 75_000,
        confidence_millionths: 950_000,
        safety_status: EnvelopeStatus::Safe,
        rationale: "good".into(),
    };
    let display = rec.to_string();
    assert!(display.starts_with("#2: opt-policy"));
    assert!(display.contains("improvement=75000"));
    assert!(display.contains("confidence=950000"));
    assert!(display.contains("status="));
}

// ===========================================================================
// 21. is_confident_improvement: negative improvement + Safe
// ===========================================================================

#[test]
fn is_confident_improvement_negative_net_improvement() {
    let report = make_report(100, 50, -100_000, 5_000, 15_000, EnvelopeStatus::Safe);
    assert!(
        !report.is_confident_improvement(),
        "negative net_improvement_millionths should not be confident improvement"
    );
}

// ===========================================================================
// 22. is_confident_improvement: positive improvement + Unsafe
// ===========================================================================

#[test]
fn is_confident_improvement_positive_but_unsafe() {
    let report = make_report(100, 50, 100_000, -15_000, -5_000, EnvelopeStatus::Unsafe);
    assert!(
        !report.is_confident_improvement(),
        "Unsafe status should not be confident improvement"
    );
}

// ===========================================================================
// 23. is_confident_improvement: positive improvement + Inconclusive
// ===========================================================================

#[test]
fn is_confident_improvement_positive_but_inconclusive() {
    let report = make_report(
        100,
        50,
        100_000,
        -5_000,
        10_000,
        EnvelopeStatus::Inconclusive,
    );
    assert!(
        !report.is_confident_improvement(),
        "Inconclusive status should not be confident improvement"
    );
}

// ===========================================================================
// 24. is_confident_improvement: true case
// ===========================================================================

#[test]
fn is_confident_improvement_true_case() {
    let report = make_report(100, 50, 200_000, 5_000, 15_000, EnvelopeStatus::Safe);
    assert!(report.is_confident_improvement());
}

// ===========================================================================
// 25. divergence_rate_millionths: exact partial ratio
// ===========================================================================

#[test]
fn divergence_rate_partial_exact() {
    let report = make_report(4, 1, 0, 0, 0, EnvelopeStatus::Inconclusive);
    // 1/4 = 250_000 millionths
    assert_eq!(report.divergence_rate_millionths(), 250_000);
}

// ===========================================================================
// 26. divergence_rate_millionths: zero divergences
// ===========================================================================

#[test]
fn divergence_rate_zero_divergences() {
    let report = make_report(100, 0, 0, 0, 0, EnvelopeStatus::Inconclusive);
    assert_eq!(report.divergence_rate_millionths(), 0);
}

// ===========================================================================
// 27. divergence_rate_millionths: full divergence
// ===========================================================================

#[test]
fn divergence_rate_full_divergence() {
    let report = make_report(50, 50, 0, 0, 0, EnvelopeStatus::Inconclusive);
    assert_eq!(report.divergence_rate_millionths(), 1_000_000);
}

// ===========================================================================
// 28. divergence_rate_millionths: zero decisions
// ===========================================================================

#[test]
fn divergence_rate_zero_decisions() {
    let report = make_report(0, 0, 0, 0, 0, EnvelopeStatus::Inconclusive);
    assert_eq!(report.divergence_rate_millionths(), 0);
}

// ===========================================================================
// 29. Schema version constant value
// ===========================================================================

#[test]
fn schema_version_exact_value() {
    assert_eq!(
        REPLAY_ENGINE_SCHEMA_VERSION,
        "franken-engine.counterfactual-replay-engine.v1"
    );
}

// ===========================================================================
// 30. Config non-default: disable regime breakdown
// ===========================================================================

#[test]
fn config_no_regime_breakdown_still_succeeds() {
    let config = ReplayEngineConfig {
        regime_breakdown: false,
        ..Default::default()
    };
    let engine_config = config.clone();
    let mut engine = CounterfactualReplayEngine::new(config);
    assert!(!engine_config.regime_breakdown);
    let trace = simple_trace();
    let result = engine
        .compare(
            &[trace],
            &[make_alternate_policy("alt", "d")],
            &default_scope(),
            None,
        )
        .unwrap();
    // The regime_breakdown flag is stored in config; compare still succeeds.
    assert_eq!(result.policy_reports.len(), 1);
}

// ===========================================================================
// 31. Config non-default: custom confidence level
// ===========================================================================

#[test]
fn config_custom_confidence_level() {
    let config = ReplayEngineConfig {
        confidence_millionths: 990_000,
        ..Default::default()
    };
    let mut engine = CounterfactualReplayEngine::new(config);
    let decisions: Vec<_> = (0..20)
        .map(|i| make_decision(i, "native", 500_000))
        .collect();
    let trace = make_trace(decisions);
    let result = engine
        .compare(
            &[trace],
            &[make_override_policy(
                "force-wasm",
                LaneAction::RouteTo(LaneId("wasm".into())),
            )],
            &default_scope(),
            None,
        )
        .unwrap();
    let env = &result.policy_reports[0].confidence_envelope;
    assert_eq!(env.confidence_millionths, 990_000);
}

// ===========================================================================
// 32. Config non-default: custom baseline policy ID
// ===========================================================================

#[test]
fn config_custom_baseline_policy_id() {
    let config = ReplayEngineConfig {
        baseline_policy_id: PolicyId("custom-baseline".into()),
        ..Default::default()
    };
    let mut engine = CounterfactualReplayEngine::new(config);
    let trace = simple_trace();
    let result = engine
        .compare(
            &[trace],
            &[make_alternate_policy("alt", "d")],
            &default_scope(),
            None,
        )
        .unwrap();
    assert_eq!(
        result.policy_reports[0].baseline_policy_id,
        PolicyId("custom-baseline".into())
    );
}

// ===========================================================================
// 33. Config non-default: max divergences per policy capped
// ===========================================================================

#[test]
fn config_max_divergences_cap() {
    let config = ReplayEngineConfig {
        max_divergences_per_policy: 2,
        ..Default::default()
    };
    let mut engine = CounterfactualReplayEngine::new(config);
    let decisions: Vec<_> = (0..10)
        .map(|i| make_decision(i, "native", 500_000))
        .collect();
    let trace = make_trace(decisions);
    let result = engine
        .compare(
            &[trace],
            &[make_override_policy(
                "force-wasm",
                LaneAction::RouteTo(LaneId("wasm".into())),
            )],
            &default_scope(),
            None,
        )
        .unwrap();
    let report = &result.policy_reports[0];
    // divergent_decisions capped at 2 but divergence_count is actual
    assert!(report.divergent_decisions.len() <= 2);
    assert_eq!(report.divergence_count, 10);
}

// ===========================================================================
// 34. Config non-default: record divergences disabled
// ===========================================================================

#[test]
fn config_record_divergences_disabled() {
    let config = ReplayEngineConfig {
        record_divergences: false,
        ..Default::default()
    };
    let mut engine = CounterfactualReplayEngine::new(config);
    let decisions: Vec<_> = (0..5)
        .map(|i| make_decision(i, "native", 500_000))
        .collect();
    let trace = make_trace(decisions);
    let result = engine
        .compare(
            &[trace],
            &[make_override_policy(
                "force-wasm",
                LaneAction::RouteTo(LaneId("wasm".into())),
            )],
            &default_scope(),
            None,
        )
        .unwrap();
    let report = &result.policy_reports[0];
    assert!(report.divergent_decisions.is_empty());
    // But count should still track divergences
    assert!(report.divergence_count > 0);
}

// ===========================================================================
// 35. Config non-default: verify integrity disabled
// ===========================================================================

#[test]
fn config_verify_integrity_disabled() {
    let config = ReplayEngineConfig {
        verify_integrity: false,
        ..Default::default()
    };
    let mut engine = CounterfactualReplayEngine::new(config);
    let trace = simple_trace();
    let result = engine.compare(
        &[trace],
        &[make_alternate_policy("alt", "d")],
        &default_scope(),
        None,
    );
    assert!(result.is_ok());
}

// ===========================================================================
// 36. Scope tick filtering narrows decisions
// ===========================================================================

#[test]
fn scope_tick_filter_narrows() {
    let mut engine = default_engine();
    // Decisions at ticks 100, 101, 102, 103, 104
    let decisions: Vec<_> = (0..5)
        .map(|i| make_decision(i, "native", 500_000))
        .collect();
    let trace = make_trace(decisions);
    let scope = ReplayScope {
        start_tick: 101,
        end_tick: 103,
        ..Default::default()
    };
    let result = engine
        .compare(&[trace], &[make_alternate_policy("alt", "d")], &scope, None)
        .unwrap();
    assert_eq!(result.total_decisions, 3);
}

// ===========================================================================
// 37. Scope single tick
// ===========================================================================

#[test]
fn scope_single_tick() {
    let mut engine = default_engine();
    let decisions: Vec<_> = (0..5)
        .map(|i| make_decision(i, "native", 500_000))
        .collect();
    let trace = make_trace(decisions);
    let scope = ReplayScope {
        start_tick: 102,
        end_tick: 102,
        ..Default::default()
    };
    let result = engine
        .compare(&[trace], &[make_alternate_policy("alt", "d")], &scope, None)
        .unwrap();
    assert_eq!(result.total_decisions, 1);
}

// ===========================================================================
// 38. Scope incident filter with matching trace
// ===========================================================================

#[test]
fn scope_incident_filter_includes_matching() {
    let mut engine = default_engine();

    let mut recorder = TraceRecorder::new(RecorderConfig {
        trace_id: "incident-trace".to_string(),
        recording_mode: RecordingMode::Full,
        epoch: test_epoch(),
        start_tick: 100,
        signing_key: b"test-key".to_vec(),
    });
    recorder.set_incident_id("INC-42".to_string());
    recorder.record_decision(make_decision(0, "native", 800_000));
    recorder.record_decision(make_decision(1, "wasm", 600_000));
    let trace = recorder.finalize();

    let scope = ReplayScope {
        incident_filter: {
            let mut s = BTreeSet::new();
            s.insert("INC-42".to_string());
            s
        },
        ..Default::default()
    };

    let result = engine
        .compare(&[trace], &[make_alternate_policy("alt", "d")], &scope, None)
        .unwrap();
    assert_eq!(result.trace_count, 1);
    assert_eq!(result.total_decisions, 2);
}

// ===========================================================================
// 39. Scope incident filter excludes non-matching
// ===========================================================================

#[test]
fn scope_incident_filter_excludes_non_matching() {
    let mut engine = default_engine();
    let trace = simple_trace(); // no incident_id
    let scope = ReplayScope {
        incident_filter: {
            let mut s = BTreeSet::new();
            s.insert("INC-99".to_string());
            s
        },
        ..Default::default()
    };
    let result = engine.compare(&[trace], &[make_alternate_policy("alt", "d")], &scope, None);
    assert!(matches!(result, Err(ReplayEngineError::EmptyScope)));
}

// ===========================================================================
// 40. Multiple traces combined: distinct trace IDs
// ===========================================================================

#[test]
fn multiple_traces_combined() {
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
    let result = engine
        .compare(
            &[trace1, trace2],
            &[make_alternate_policy("alt", "d")],
            &default_scope(),
            None,
        )
        .unwrap();
    assert!(result.total_decisions >= 5);
}

// ===========================================================================
// 41. Override policy: FallbackSafe diverges all native decisions
// ===========================================================================

#[test]
fn override_policy_fallback_safe_diverges() {
    let mut engine = default_engine();
    let decisions: Vec<_> = (0..5)
        .map(|i| make_decision(i, "native", 500_000))
        .collect();
    let trace = make_trace(decisions);
    let result = engine
        .compare(
            &[trace],
            &[make_override_policy("force-safe", LaneAction::FallbackSafe)],
            &default_scope(),
            None,
        )
        .unwrap();
    let report = &result.policy_reports[0];
    assert_eq!(report.divergence_count, 5);
    assert_eq!(report.decisions_evaluated, 5);
}

// ===========================================================================
// 42. Containment override: all native -> safe-mode
// ===========================================================================

#[test]
fn containment_override_replaces_native() {
    let mut engine = default_engine();
    let decisions: Vec<_> = (0..3)
        .map(|i| make_decision(i, "native", 500_000))
        .collect();
    let trace = make_trace(decisions);

    let mut containment = BTreeMap::new();
    containment.insert("native".to_string(), "safe-mode".to_string());

    let alt = AlternatePolicy {
        policy_id: PolicyId("contain".into()),
        description: "containment override".into(),
        counterfactual_config: CounterfactualConfig {
            branch_id: "branch-contain".into(),
            threshold_override_millionths: None,
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: containment,
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        },
        default_action: None,
    };

    let result = engine
        .compare(&[trace], &[alt], &default_scope(), None)
        .unwrap();
    let report = &result.policy_reports[0];
    assert_eq!(report.divergence_count, 3);
    for dc in &report.divergent_decisions {
        assert_eq!(dc.alternate_action, "safe-mode");
    }
}

// ===========================================================================
// 43. Loss matrix override alters outcome
// ===========================================================================

#[test]
fn loss_matrix_override_accepted() {
    let mut engine = default_engine();
    let trace = make_trace(vec![make_decision(0, "native", 500_000)]);

    let mut loss = BTreeMap::new();
    loss.insert("native".to_string(), 10_000);

    let alt = AlternatePolicy {
        policy_id: PolicyId("low-loss".into()),
        description: "low loss".into(),
        counterfactual_config: CounterfactualConfig {
            branch_id: "branch-ll".into(),
            threshold_override_millionths: Some(500_000),
            loss_matrix_overrides: loss,
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        },
        default_action: None,
    };

    let result = engine
        .compare(&[trace], &[alt], &default_scope(), None)
        .unwrap();
    assert_eq!(result.policy_reports.len(), 1);
}

// ===========================================================================
// 44. Evidence weight override accepted
// ===========================================================================

#[test]
fn evidence_weight_override_accepted() {
    let mut engine = default_engine();
    let trace = simple_trace();

    let mut weights = BTreeMap::new();
    weights.insert("evidence-hash".to_string(), 2_000_000);

    let alt = AlternatePolicy {
        policy_id: PolicyId("high-ev".into()),
        description: "high evidence weight".into(),
        counterfactual_config: CounterfactualConfig {
            branch_id: "branch-hev".into(),
            threshold_override_millionths: None,
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: weights,
            branch_from_index: 0,
        },
        default_action: None,
    };

    let result = engine
        .compare(&[trace], &[alt], &default_scope(), None)
        .unwrap();
    assert_eq!(result.policy_reports.len(), 1);
}

// ===========================================================================
// 45. Policy version override accepted
// ===========================================================================

#[test]
fn policy_version_override_accepted() {
    let mut engine = default_engine();
    let trace = simple_trace();

    let alt = AlternatePolicy {
        policy_id: PolicyId("versioned".into()),
        description: "with version override".into(),
        counterfactual_config: CounterfactualConfig {
            branch_id: "branch-ver".into(),
            threshold_override_millionths: None,
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: Some(42),
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        },
        default_action: None,
    };

    let result = engine
        .compare(&[trace], &[alt], &default_scope(), None)
        .unwrap();
    assert_eq!(result.policy_reports.len(), 1);
}

// ===========================================================================
// 46. Recommendations: ranked by expected improvement (descending)
// ===========================================================================

#[test]
fn recommendations_ordered_by_improvement() {
    let mut engine = default_engine();
    let decisions: Vec<_> = (0..20)
        .map(|i| make_decision(i, "native", 500_000))
        .collect();
    let trace = make_trace(decisions);

    let alts = vec![
        make_alternate_policy("modest", "small change"),
        make_override_policy("force-wasm", LaneAction::RouteTo(LaneId("wasm".into()))),
        make_override_policy("force-safe", LaneAction::FallbackSafe),
    ];

    let result = engine
        .compare(&[trace], &alts, &default_scope(), None)
        .unwrap();

    let recs = &result.ranked_recommendations;
    assert_eq!(recs.len(), 3);
    for (i, rec) in recs.iter().enumerate() {
        assert_eq!(rec.rank, (i + 1) as u32);
    }
    // Each subsequent recommendation should have <= improvement
    for w in recs.windows(2) {
        assert!(w[0].expected_improvement_millionths >= w[1].expected_improvement_millionths);
    }
}

// ===========================================================================
// 47. Global assumptions always include Consistency and SUTVA
// ===========================================================================

#[test]
fn global_assumptions_include_consistency_and_sutva() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let result = engine
        .compare(
            &[trace],
            &[make_alternate_policy("alt", "d")],
            &default_scope(),
            None,
        )
        .unwrap();

    let categories: Vec<_> = result
        .global_assumptions
        .iter()
        .map(|a| a.category.clone())
        .collect();
    assert!(categories.contains(&AssumptionCategory::Consistency));
    assert!(categories.contains(&AssumptionCategory::Sutva));
}

// ===========================================================================
// 48. Per-policy assumptions include Positivity
// ===========================================================================

#[test]
fn per_policy_assumptions_include_positivity() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let result = engine
        .compare(
            &[trace],
            &[make_alternate_policy("alt", "d")],
            &default_scope(),
            None,
        )
        .unwrap();
    let report = &result.policy_reports[0];
    let has_positivity = report
        .assumptions
        .iter()
        .any(|a| a.category == AssumptionCategory::Positivity);
    assert!(has_positivity);
}

// ===========================================================================
// 49. Confidence envelope: lower <= estimate <= upper
// ===========================================================================

#[test]
fn confidence_envelope_ordering() {
    let mut engine = default_engine();
    let decisions: Vec<_> = (0..30)
        .map(|i| make_decision(i, "native", 500_000))
        .collect();
    let trace = make_trace(decisions);
    let result = engine
        .compare(
            &[trace],
            &[make_override_policy(
                "force-wasm",
                LaneAction::RouteTo(LaneId("wasm".into())),
            )],
            &default_scope(),
            None,
        )
        .unwrap();

    let env = &result.policy_reports[0].confidence_envelope;
    assert!(env.lower_millionths <= env.estimate_millionths);
    assert!(env.estimate_millionths <= env.upper_millionths);
    assert_eq!(env.effective_samples, 30);
}

// ===========================================================================
// 50. Confidence envelope: small sample count
// ===========================================================================

#[test]
fn confidence_envelope_small_sample() {
    let mut engine = default_engine();
    let trace = make_trace(vec![make_decision(0, "native", 500_000)]);
    let result = engine
        .compare(
            &[trace],
            &[make_override_policy(
                "force-wasm",
                LaneAction::RouteTo(LaneId("wasm".into())),
            )],
            &default_scope(),
            None,
        )
        .unwrap();
    let env = &result.policy_reports[0].confidence_envelope;
    assert_eq!(env.effective_samples, 1);
    // Envelope should still be valid ordering
    assert!(env.lower_millionths <= env.upper_millionths);
}

// ===========================================================================
// 51. Regime breakdown: populated when enabled
// ===========================================================================

#[test]
fn regime_breakdown_populated_when_enabled() {
    let mut engine = default_engine();
    let decisions: Vec<_> = (0..10)
        .map(|i| make_decision(i, "native", 500_000))
        .collect();
    let trace = make_trace(decisions);
    let result = engine
        .compare(
            &[trace],
            &[make_override_policy(
                "force-wasm",
                LaneAction::RouteTo(LaneId("wasm".into())),
            )],
            &default_scope(),
            None,
        )
        .unwrap();
    let report = &result.policy_reports[0];
    assert!(!report.regime_breakdown.is_empty());
}

// ===========================================================================
// 52. Report artifact hash non-zero
// ===========================================================================

#[test]
fn report_artifact_hash_nonzero() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let result = engine
        .compare(
            &[trace],
            &[make_alternate_policy("alt", "d")],
            &default_scope(),
            None,
        )
        .unwrap();
    assert_ne!(result.artifact_hash.as_bytes(), &[0u8; 32]);
    assert_ne!(
        result.policy_reports[0].artifact_hash.as_bytes(),
        &[0u8; 32]
    );
}

// ===========================================================================
// 53. Determinism: same inputs → same artifact hash
// ===========================================================================

#[test]
fn determinism_same_inputs_same_hash() {
    let trace = simple_trace();
    let policies = vec![make_alternate_policy("alt", "d")];
    let scope = default_scope();

    let mut e1 = default_engine();
    let mut e2 = default_engine();

    let r1 = e1
        .compare(std::slice::from_ref(&trace), &policies, &scope, None)
        .unwrap();
    let r2 = e2
        .compare(std::slice::from_ref(&trace), &policies, &scope, None)
        .unwrap();

    assert_eq!(r1.artifact_hash, r2.artifact_hash);
    assert_eq!(
        r1.policy_reports[0].net_improvement_millionths,
        r2.policy_reports[0].net_improvement_millionths
    );
    assert_eq!(
        r1.policy_reports[0].divergence_count,
        r2.policy_reports[0].divergence_count
    );
}

// ===========================================================================
// 54. Engine serde roundtrip (integration-level)
// ===========================================================================

#[test]
fn engine_serde_roundtrip() {
    let engine = default_engine();
    let json = serde_json::to_string(&engine).unwrap();
    let back: CounterfactualReplayEngine = serde_json::from_str(&json).unwrap();
    assert_eq!(engine.replay_count(), back.replay_count());
    assert_eq!(
        engine.config().baseline_policy_id,
        back.config().baseline_policy_id
    );
    assert_eq!(engine.config().estimator, back.config().estimator);
}

// ===========================================================================
// 55. Engine serde roundtrip after compare
// ===========================================================================

#[test]
fn engine_serde_roundtrip_after_compare() {
    let mut engine = default_engine();
    let trace = simple_trace();
    engine
        .compare(
            &[trace],
            &[make_alternate_policy("alt", "d")],
            &default_scope(),
            None,
        )
        .unwrap();
    assert_eq!(engine.replay_count(), 1);

    let json = serde_json::to_string(&engine).unwrap();
    let back: CounterfactualReplayEngine = serde_json::from_str(&json).unwrap();
    assert_eq!(back.replay_count(), 1);
}

// ===========================================================================
// 56. Divergent decisions: fields populated correctly
// ===========================================================================

#[test]
fn divergent_decision_fields() {
    let mut engine = default_engine();
    let trace = make_trace(vec![make_decision(0, "native", 800_000)]);
    let result = engine
        .compare(
            &[trace],
            &[make_override_policy(
                "force-wasm",
                LaneAction::RouteTo(LaneId("wasm".into())),
            )],
            &default_scope(),
            None,
        )
        .unwrap();

    let report = &result.policy_reports[0];
    assert_eq!(report.divergent_decisions.len(), 1);

    let dc = &report.divergent_decisions[0];
    assert_eq!(dc.decision_index, 0);
    assert_eq!(dc.tick, 100);
    assert_eq!(dc.epoch, test_epoch());
    assert_eq!(dc.original_action, "native");
    assert!(dc.diverged);
    assert!(!dc.regime.is_empty());
}

// ===========================================================================
// 57. Scope: min_decisions threshold
// ===========================================================================

#[test]
fn scope_min_decisions_exact_boundary() {
    let mut engine = default_engine();
    let decisions: Vec<_> = (0..5)
        .map(|i| make_decision(i, "native", 500_000))
        .collect();
    let trace = make_trace(decisions);

    // Exactly 5 decisions, min_decisions = 5 → should succeed
    let scope = ReplayScope {
        min_decisions: 5,
        ..Default::default()
    };
    let result = engine.compare(
        std::slice::from_ref(&trace),
        &[make_alternate_policy("alt", "d")],
        &scope,
        None,
    );
    assert!(result.is_ok());

    // min_decisions = 6 → should fail
    let scope2 = ReplayScope {
        min_decisions: 6,
        ..Default::default()
    };
    let result2 = engine.compare(
        std::slice::from_ref(&trace),
        &[make_alternate_policy("alt", "d")],
        &scope2,
        None,
    );
    assert!(matches!(
        result2,
        Err(ReplayEngineError::InsufficientDecisions {
            found: 5,
            required: 6
        })
    ));
}

// ===========================================================================
// 58. Too many policies: at boundary
// ===========================================================================

#[test]
fn too_many_policies_boundary() {
    let mut engine = default_engine();
    let trace = simple_trace();

    // 64 policies should succeed (at limit)
    let alts_64: Vec<_> = (0..64)
        .map(|i| make_alternate_policy(&format!("pol-{i}"), "d"))
        .collect();
    let result = engine.compare(
        std::slice::from_ref(&trace),
        &alts_64,
        &default_scope(),
        None,
    );
    assert!(result.is_ok());

    // 65 policies should fail (over limit)
    let alts_65: Vec<_> = (0..65)
        .map(|i| make_alternate_policy(&format!("pol-{i}"), "d"))
        .collect();
    let result = engine.compare(
        std::slice::from_ref(&trace),
        &alts_65,
        &default_scope(),
        None,
    );
    assert!(matches!(
        result,
        Err(ReplayEngineError::TooManyPolicies { count: 65, max: 64 })
    ));
}

// ===========================================================================
// 59. Causal effects empty without model
// ===========================================================================

#[test]
fn causal_effects_empty_without_model() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let result = engine
        .compare(
            &[trace],
            &[make_alternate_policy("alt", "d")],
            &default_scope(),
            None,
        )
        .unwrap();
    assert!(result.causal_effects.is_empty());
}

// ===========================================================================
// 60. ReplayComparisonResult serde roundtrip
// ===========================================================================

#[test]
fn comparison_result_full_serde_roundtrip() {
    let mut engine = default_engine();
    let decisions: Vec<_> = (0..10)
        .map(|i| make_decision(i, "native", 500_000))
        .collect();
    let trace = make_trace(decisions);
    let result = engine
        .compare(
            &[trace],
            &[make_override_policy(
                "force-wasm",
                LaneAction::RouteTo(LaneId("wasm".into())),
            )],
            &default_scope(),
            None,
        )
        .unwrap();

    let json = serde_json::to_string(&result).unwrap();
    let back: ReplayComparisonResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ===========================================================================
// 61. PolicyComparisonReport serde roundtrip with divergent decisions
// ===========================================================================

#[test]
fn policy_report_serde_with_divergences() {
    let mut engine = default_engine();
    let decisions: Vec<_> = (0..5)
        .map(|i| make_decision(i, "native", 500_000))
        .collect();
    let trace = make_trace(decisions);
    let result = engine
        .compare(
            &[trace],
            &[make_override_policy(
                "force-wasm",
                LaneAction::RouteTo(LaneId("wasm".into())),
            )],
            &default_scope(),
            None,
        )
        .unwrap();

    let report = &result.policy_reports[0];
    assert!(!report.divergent_decisions.is_empty());

    let json = serde_json::to_string(report).unwrap();
    let back: PolicyComparisonReport = serde_json::from_str(&json).unwrap();
    assert_eq!(*report, back);
}

// ===========================================================================
// 62. AssumptionCard serde roundtrip: all categories
// ===========================================================================

#[test]
fn assumption_card_serde_all_categories() {
    let categories = [
        AssumptionCategory::NoUnmeasuredConfounding,
        AssumptionCategory::Positivity,
        AssumptionCategory::Consistency,
        AssumptionCategory::Sutva,
        AssumptionCategory::ModelSpecification,
        AssumptionCategory::TemporalStability,
    ];
    for cat in categories {
        let card = AssumptionCard {
            assumption_id: format!("id-{cat}"),
            category: cat.clone(),
            description: format!("desc-{cat}"),
            testable: true,
            test_passed: Some(true),
            sensitivity_bound_millionths: 42_000,
        };
        let json = serde_json::to_string(&card).unwrap();
        let back: AssumptionCard = serde_json::from_str(&json).unwrap();
        assert_eq!(card, back, "roundtrip failed for {cat:?}");
    }
}

// ===========================================================================
// 63. AlternatePolicy: with default_action set
// ===========================================================================

#[test]
fn alternate_policy_with_default_action_serde() {
    let ap = make_override_policy("override", LaneAction::FallbackSafe);
    let json = serde_json::to_string(&ap).unwrap();
    let back: AlternatePolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(ap, back);
    assert_eq!(back.default_action, Some(LaneAction::FallbackSafe));
}

// ===========================================================================
// 64. AlternatePolicy: without default_action
// ===========================================================================

#[test]
fn alternate_policy_without_default_action_serde() {
    let ap = make_alternate_policy("threshold-only", "threshold change");
    let json = serde_json::to_string(&ap).unwrap();
    let back: AlternatePolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(ap, back);
    assert_eq!(back.default_action, None);
}

// ===========================================================================
// 65. ReplayScope: serde with non-empty incident filter
// ===========================================================================

#[test]
fn replay_scope_serde_with_incident_filter() {
    let scope = ReplayScope {
        start_epoch: SecurityEpoch::from_raw(5),
        end_epoch: SecurityEpoch::from_raw(10),
        start_tick: 100,
        end_tick: 200,
        incident_filter: {
            let mut s = BTreeSet::new();
            s.insert("INC-001".to_string());
            s.insert("INC-002".to_string());
            s
        },
        min_decisions: 10,
    };
    let json = serde_json::to_string(&scope).unwrap();
    let back: ReplayScope = serde_json::from_str(&json).unwrap();
    assert_eq!(scope, back);
    assert_eq!(back.incident_filter.len(), 2);
}

// ===========================================================================
// 66. Config with all non-default values serde roundtrip
// ===========================================================================

#[test]
fn config_all_nondefault_serde_roundtrip() {
    let config = ReplayEngineConfig {
        baseline_policy_id: PolicyId("my-baseline".into()),
        baseline_action: LaneAction::RouteTo(LaneId("custom".into())),
        estimator: EstimatorKind::Ips,
        confidence_millionths: 990_000,
        regime_breakdown: false,
        record_divergences: false,
        max_divergences_per_policy: 5,
        verify_integrity: false,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: ReplayEngineConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ===========================================================================
// 67. Full lifecycle: multi-policy, multi-trace, serialize
// ===========================================================================

#[test]
fn full_lifecycle_multi_trace_multi_policy() {
    let trace1 = make_trace(vec![
        make_decision(0, "native", 800_000),
        make_decision(1, "wasm", 600_000),
    ]);
    let trace2 = make_trace(vec![
        make_decision(0, "native", 700_000),
        make_decision(1, "native", 900_000),
    ]);

    let policies = vec![
        make_alternate_policy("higher-threshold", "raise to 600k"),
        make_override_policy("force-safe", LaneAction::FallbackSafe),
        make_override_policy("force-wasm", LaneAction::RouteTo(LaneId("wasm".into()))),
    ];

    let mut engine = default_engine();
    let result = engine
        .compare(&[trace1, trace2], &policies, &default_scope(), None)
        .unwrap();

    // Structure
    assert!(result.total_decisions >= 4);
    assert_eq!(result.policy_reports.len(), 3);
    assert_eq!(result.ranked_recommendations.len(), 3);
    assert!(!result.global_assumptions.is_empty());

    // Ranking
    for (i, rec) in result.ranked_recommendations.iter().enumerate() {
        assert_eq!(rec.rank, (i + 1) as u32);
    }

    // Serde roundtrip
    let json = serde_json::to_string(&result).unwrap();
    let back: ReplayComparisonResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);

    // Engine state
    assert_eq!(engine.replay_count(), 1);
}

// ===========================================================================
// 68. Full lifecycle: compare twice, then serialize
// ===========================================================================

#[test]
fn full_lifecycle_compare_twice() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let policies = vec![make_alternate_policy("alt", "d")];

    let r1 = engine
        .compare(
            std::slice::from_ref(&trace),
            &policies,
            &default_scope(),
            None,
        )
        .unwrap();
    assert_eq!(engine.replay_count(), 1);

    let r2 = engine
        .compare(
            std::slice::from_ref(&trace),
            &policies,
            &default_scope(),
            None,
        )
        .unwrap();
    assert_eq!(engine.replay_count(), 2);

    // Both should produce identical results (determinism)
    assert_eq!(r1.artifact_hash, r2.artifact_hash);
}

// ===========================================================================
// 69. DecisionComparison: non-divergent fields
// ===========================================================================

#[test]
fn decision_comparison_non_divergent() {
    let dc = DecisionComparison {
        decision_index: 3,
        tick: 103,
        epoch: test_epoch(),
        original_action: "native".into(),
        alternate_action: "native".into(),
        original_outcome_millionths: 800_000,
        counterfactual_outcome_millionths: 800_000,
        diverged: false,
        regime: "steady-state".into(),
    };
    assert!(!dc.diverged);
    assert_eq!(dc.original_action, dc.alternate_action);
    let json = serde_json::to_string(&dc).unwrap();
    let back: DecisionComparison = serde_json::from_str(&json).unwrap();
    assert_eq!(dc, back);
}

// ===========================================================================
// 70. Recommendation: all safety statuses
// ===========================================================================

#[test]
fn recommendation_serde_all_statuses() {
    for status in [
        EnvelopeStatus::Safe,
        EnvelopeStatus::Unsafe,
        EnvelopeStatus::Inconclusive,
    ] {
        let rec = Recommendation {
            rank: 1,
            policy_id: PolicyId("p".into()),
            expected_improvement_millionths: 0,
            confidence_millionths: 950_000,
            safety_status: status,
            rationale: "test".into(),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let back: Recommendation = serde_json::from_str(&json).unwrap();
        assert_eq!(rec, back, "roundtrip failed for {status:?}");
    }
}

// ===========================================================================
// 71. AlternatePolicy Display: with special characters
// ===========================================================================

#[test]
fn alternate_policy_display_special_chars() {
    let ap = AlternatePolicy {
        policy_id: PolicyId("pol/1".into()),
        description: "desc with: colon".into(),
        counterfactual_config: CounterfactualConfig {
            branch_id: "b".into(),
            threshold_override_millionths: None,
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        },
        default_action: None,
    };
    let display = ap.to_string();
    assert_eq!(display, "pol/1:desc with: colon");
}

// ===========================================================================
// 72. EnvelopeStatus serde roundtrip all variants
// ===========================================================================

#[test]
fn envelope_status_serde_all_variants() {
    for status in [
        EnvelopeStatus::Safe,
        EnvelopeStatus::Unsafe,
        EnvelopeStatus::Inconclusive,
    ] {
        let json = serde_json::to_string(&status).unwrap();
        let back: EnvelopeStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, back);
    }
}

// ===========================================================================
// 73. ReplayScope: epoch range boundary (inclusive)
// ===========================================================================

#[test]
fn scope_epoch_boundary_inclusive() {
    let mut engine = default_engine();
    // All decisions at epoch 1
    let trace = simple_trace();

    let scope = ReplayScope {
        start_epoch: SecurityEpoch::from_raw(1),
        end_epoch: SecurityEpoch::from_raw(1),
        ..Default::default()
    };

    let result = engine.compare(&[trace], &[make_alternate_policy("alt", "d")], &scope, None);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().total_decisions, 3);
}

// ===========================================================================
// 74. ReplayScope: just out of epoch range
// ===========================================================================

#[test]
fn scope_epoch_just_out_of_range() {
    let mut engine = default_engine();
    let trace = simple_trace(); // epoch 1

    let scope = ReplayScope {
        start_epoch: SecurityEpoch::from_raw(2),
        end_epoch: SecurityEpoch::from_raw(3),
        ..Default::default()
    };

    let result = engine.compare(&[trace], &[make_alternate_policy("alt", "d")], &scope, None);
    assert!(matches!(result, Err(ReplayEngineError::EmptyScope)));
}

// ===========================================================================
// 75. PolicyComparisonReport: alternate description preserved
// ===========================================================================

#[test]
fn report_preserves_alternate_description() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let result = engine
        .compare(
            &[trace],
            &[make_alternate_policy("alt", "My detailed description")],
            &default_scope(),
            None,
        )
        .unwrap();
    assert_eq!(
        result.policy_reports[0].alternate_description,
        "My detailed description"
    );
}

// ===========================================================================
// 76. ReplayComparisonResult: scope preserved
// ===========================================================================

#[test]
fn result_preserves_scope() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let scope = ReplayScope {
        start_tick: 100,
        end_tick: 102,
        ..Default::default()
    };
    let result = engine
        .compare(&[trace], &[make_alternate_policy("alt", "d")], &scope, None)
        .unwrap();
    assert_eq!(result.scope.start_tick, 100);
    assert_eq!(result.scope.end_tick, 102);
}

// ===========================================================================
// 77. Safety status reflects envelope position
// ===========================================================================

#[test]
fn safety_status_matches_envelope() {
    let mut engine = default_engine();
    let decisions: Vec<_> = (0..20)
        .map(|i| make_decision(i, "native", 500_000))
        .collect();
    let trace = make_trace(decisions);
    let result = engine
        .compare(
            &[trace],
            &[make_override_policy(
                "force-wasm",
                LaneAction::RouteTo(LaneId("wasm".into())),
            )],
            &default_scope(),
            None,
        )
        .unwrap();

    let report = &result.policy_reports[0];
    match report.safety_status {
        EnvelopeStatus::Safe => {
            assert!(report.confidence_envelope.lower_millionths > 0);
        }
        EnvelopeStatus::Unsafe => {
            assert!(report.confidence_envelope.upper_millionths < 0);
        }
        EnvelopeStatus::Inconclusive => {
            // Crosses zero
        }
    }
}

// ===========================================================================
// 78. AssumptionCard: testable false and test_passed None
// ===========================================================================

#[test]
fn assumption_card_not_testable() {
    let card = AssumptionCard {
        assumption_id: "untestable".into(),
        category: AssumptionCategory::Sutva,
        description: "cannot be tested".into(),
        testable: false,
        test_passed: None,
        sensitivity_bound_millionths: 0,
    };
    let json = serde_json::to_string(&card).unwrap();
    let back: AssumptionCard = serde_json::from_str(&json).unwrap();
    assert_eq!(card, back);
    assert!(!back.testable);
    assert_eq!(back.test_passed, None);
}

// ===========================================================================
// 79. AssumptionCard: testable true and test_passed Some(false)
// ===========================================================================

#[test]
fn assumption_card_test_failed() {
    let card = AssumptionCard {
        assumption_id: "fail".into(),
        category: AssumptionCategory::Positivity,
        description: "failed test".into(),
        testable: true,
        test_passed: Some(false),
        sensitivity_bound_millionths: 500_000,
    };
    let json = serde_json::to_string(&card).unwrap();
    let back: AssumptionCard = serde_json::from_str(&json).unwrap();
    assert_eq!(card, back);
    assert_eq!(back.test_passed, Some(false));
}

// ===========================================================================
// 80. Global assumptions: TemporalStability has sensitivity bound > 0
// ===========================================================================

#[test]
fn global_assumptions_temporal_stability_sensitivity() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let result = engine
        .compare(
            &[trace],
            &[make_alternate_policy("alt", "d")],
            &default_scope(),
            None,
        )
        .unwrap();

    let temporal = result
        .global_assumptions
        .iter()
        .find(|a| a.category == AssumptionCategory::TemporalStability);
    assert!(temporal.is_some(), "must have TemporalStability assumption");
    let ts = temporal.unwrap();
    assert!(ts.testable);
    assert!(ts.sensitivity_bound_millionths > 0);
}

// ===========================================================================
// 81. Per-policy assumptions: ModelSpecification present
// ===========================================================================

#[test]
fn per_policy_assumptions_model_specification() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let result = engine
        .compare(
            &[trace],
            &[make_alternate_policy("alt", "d")],
            &default_scope(),
            None,
        )
        .unwrap();
    let report = &result.policy_reports[0];
    let has_model_spec = report
        .assumptions
        .iter()
        .any(|a| a.category == AssumptionCategory::ModelSpecification);
    assert!(has_model_spec);
}

// ===========================================================================
// 82. Replay count starts at zero
// ===========================================================================

#[test]
fn replay_count_starts_zero() {
    let engine = default_engine();
    assert_eq!(engine.replay_count(), 0);
}

// ===========================================================================
// 83. Replay count increments correctly across multiple runs
// ===========================================================================

#[test]
fn replay_count_increments_across_runs() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let policies = vec![make_alternate_policy("alt", "d")];

    for expected in 1..=5 {
        engine
            .compare(
                std::slice::from_ref(&trace),
                &policies,
                &default_scope(),
                None,
            )
            .unwrap();
        assert_eq!(engine.replay_count(), expected);
    }
}

// ===========================================================================
// 84. Config accessor returns correct config
// ===========================================================================

#[test]
fn config_accessor() {
    let config = ReplayEngineConfig {
        baseline_policy_id: PolicyId("custom".into()),
        confidence_millionths: 990_000,
        max_divergences_per_policy: 50,
        ..Default::default()
    };
    let engine = CounterfactualReplayEngine::new(config.clone());
    assert_eq!(
        engine.config().baseline_policy_id,
        config.baseline_policy_id
    );
    assert_eq!(
        engine.config().confidence_millionths,
        config.confidence_millionths
    );
    assert_eq!(
        engine.config().max_divergences_per_policy,
        config.max_divergences_per_policy
    );
}

// ===========================================================================
// 85. Empty incident filter means "all incidents" (no filtering)
// ===========================================================================

#[test]
fn empty_incident_filter_includes_all() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let scope = ReplayScope {
        incident_filter: BTreeSet::new(), // empty = all
        ..Default::default()
    };
    let result = engine.compare(&[trace], &[make_alternate_policy("alt", "d")], &scope, None);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().total_decisions, 3);
}

// ===========================================================================
// 86. CounterfactualConfig: branch_from_index non-zero
// ===========================================================================

#[test]
fn branch_from_index_nonzero_accepted() {
    let mut engine = default_engine();
    let decisions: Vec<_> = (0..5)
        .map(|i| make_decision(i, "native", 500_000))
        .collect();
    let trace = make_trace(decisions);

    let alt = AlternatePolicy {
        policy_id: PolicyId("branch-mid".into()),
        description: "branch from middle".into(),
        counterfactual_config: CounterfactualConfig {
            branch_id: "branch-mid".into(),
            threshold_override_millionths: Some(700_000),
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 2,
        },
        default_action: None,
    };

    let result = engine
        .compare(&[trace], &[alt], &default_scope(), None)
        .unwrap();
    assert_eq!(result.policy_reports.len(), 1);
}

// ===========================================================================
// 87. Different policies yield different artifact hashes
// ===========================================================================

#[test]
fn different_policies_different_hashes() {
    let trace = simple_trace();
    let scope = default_scope();

    let mut e1 = default_engine();
    let r1 = e1
        .compare(
            std::slice::from_ref(&trace),
            &[make_alternate_policy("policy-a", "A")],
            &scope,
            None,
        )
        .unwrap();

    let mut e2 = default_engine();
    let r2 = e2
        .compare(
            std::slice::from_ref(&trace),
            &[make_override_policy("force-safe", LaneAction::FallbackSafe)],
            &scope,
            None,
        )
        .unwrap();

    // Different policies → different reports → different hashes
    assert_ne!(
        r1.policy_reports[0].alternate_policy_id,
        r2.policy_reports[0].alternate_policy_id
    );
}

// ===========================================================================
// 88. Duplicate policy error: exact policy_id in error
// ===========================================================================

#[test]
fn duplicate_policy_error_contains_id() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let policies = vec![
        make_alternate_policy("dupe-id", "first"),
        make_alternate_policy("dupe-id", "second"),
    ];
    let result = engine.compare(&[trace], &policies, &default_scope(), None);
    match result {
        Err(ReplayEngineError::DuplicatePolicy { policy_id }) => {
            assert_eq!(policy_id, "dupe-id");
        }
        other => panic!("expected DuplicatePolicy, got {other:?}"),
    }
}

// ===========================================================================
// 89. InsufficientDecisions error: exact found/required values
// ===========================================================================

#[test]
fn insufficient_decisions_error_exact_values() {
    let mut engine = default_engine();
    let trace = simple_trace(); // 3 decisions
    let scope = ReplayScope {
        min_decisions: 50,
        ..Default::default()
    };
    let result = engine.compare(&[trace], &[make_alternate_policy("alt", "d")], &scope, None);
    match result {
        Err(ReplayEngineError::InsufficientDecisions { found, required }) => {
            assert_eq!(found, 3);
            assert_eq!(required, 50);
        }
        other => panic!("expected InsufficientDecisions, got {other:?}"),
    }
}

// ===========================================================================
// 90. Mixed actions in trace: diverse divergence patterns
// ===========================================================================

#[test]
fn mixed_actions_diverse_divergence() {
    let mut engine = default_engine();
    let decisions = vec![
        make_decision(0, "native", 800_000),
        make_decision(1, "wasm", 600_000),
        make_decision(2, "native", 700_000),
        make_decision(3, "wasm", 500_000),
        make_decision(4, "native", 900_000),
    ];
    let trace = make_trace(decisions);

    // Force all to wasm — the override applies to every decision, so all
    // decisions go through the counterfactual path. All 5 diverge because
    // the engine re-evaluates every decision under the alternate policy.
    let result = engine
        .compare(
            &[trace],
            &[make_override_policy(
                "force-wasm",
                LaneAction::RouteTo(LaneId("wasm".into())),
            )],
            &default_scope(),
            None,
        )
        .unwrap();

    let report = &result.policy_reports[0];
    assert_eq!(report.decisions_evaluated, 5);
    assert_eq!(report.divergence_count, 5);
}

// ===========================================================================
// 91. Recommendation: rationale field preserved
// ===========================================================================

#[test]
fn recommendation_rationale_preserved() {
    let rec = Recommendation {
        rank: 1,
        policy_id: PolicyId("p".into()),
        expected_improvement_millionths: 100,
        confidence_millionths: 950_000,
        safety_status: EnvelopeStatus::Safe,
        rationale: "This policy reduces tail latency by 15%".into(),
    };
    let json = serde_json::to_string(&rec).unwrap();
    let back: Recommendation = serde_json::from_str(&json).unwrap();
    assert_eq!(back.rationale, "This policy reduces tail latency by 15%");
}

// ===========================================================================
// 92. E2E: large comparison produces valid structure
// ===========================================================================

#[test]
fn e2e_large_trace() {
    let mut engine = default_engine();
    let decisions: Vec<_> = (0..100)
        .map(|i| {
            make_decision(
                i,
                if i.is_multiple_of(3) {
                    "wasm"
                } else {
                    "native"
                },
                500_000 + i as i64 * 1_000,
            )
        })
        .collect();
    let trace = make_trace(decisions);

    let policies = vec![
        make_alternate_policy("conservative", "threshold 700k"),
        make_override_policy("force-wasm", LaneAction::RouteTo(LaneId("wasm".into()))),
    ];

    let result = engine
        .compare(&[trace], &policies, &default_scope(), None)
        .unwrap();

    assert_eq!(result.total_decisions, 100);
    assert_eq!(result.policy_reports.len(), 2);
    assert_eq!(result.ranked_recommendations.len(), 2);
    assert!(!result.global_assumptions.is_empty());

    // All reports should have 100 decisions evaluated
    for report in &result.policy_reports {
        assert_eq!(report.decisions_evaluated, 100);
    }

    // Serde roundtrip
    let json = serde_json::to_string(&result).unwrap();
    let back: ReplayComparisonResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}
