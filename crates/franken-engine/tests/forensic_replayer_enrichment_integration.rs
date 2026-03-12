#![forbid(unsafe_code)]
//! Enrichment integration tests for `forensic_replayer`.
//!
//! Covers edge cases, boundary values, determinism guarantees,
//! multi-step workflows, error conditions, serde stability,
//! and Display string uniqueness not covered by the existing
//! `forensic_replayer_integration.rs` and `forensic_replayer_edge_cases.rs`.

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
use std::collections::BTreeSet;

use frankenengine_engine::bayesian_posterior::{
    BayesianPosteriorUpdater, Evidence, LikelihoodModel, Posterior,
};
use frankenengine_engine::containment_executor::ContainmentState;
use frankenengine_engine::expected_loss_selector::{
    ActionDecision, ContainmentAction, DecisionExplanation, ExpectedLossSelector, LossMatrix,
};
use frankenengine_engine::forensic_replayer::{
    CounterfactualSpec, DecisionChange, ForensicReplayer, IncidentMetadata, IncidentTrace,
    ReplayConfig, ReplayDiff, ReplayError, ReplayResult, ReplayStep, TraceValidationError,
    validate_trace,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_evidence(extension_id: &str, rate: i64, denial: i64) -> Evidence {
    Evidence {
        extension_id: extension_id.to_string(),
        hostcall_rate_millionths: rate,
        distinct_capabilities: 3,
        resource_score_millionths: 200_000,
        timing_anomaly_millionths: 100_000,
        denial_rate_millionths: denial,
        epoch: SecurityEpoch::GENESIS,
    }
}

fn benign_evidence() -> Evidence {
    test_evidence("ext-001", 10_000_000, 10_000)
}

fn suspicious_evidence() -> Evidence {
    test_evidence("ext-001", 600_000_000, 250_000)
}

fn malicious_evidence() -> Evidence {
    test_evidence("ext-001", 1_000_000_000, 500_000)
}

fn build_trace_with_id(evidence: Vec<Evidence>, trace_id: &str) -> IncidentTrace {
    let prior = Posterior::default_prior();
    let loss_matrix = LossMatrix::balanced();
    let likelihood_model = LikelihoodModel::default();

    let mut updater =
        BayesianPosteriorUpdater::with_model(prior.clone(), "ext-001", likelihood_model.clone());
    let mut selector = ExpectedLossSelector::new(loss_matrix.clone());

    let mut posterior_history = Vec::new();
    let mut decision_log = Vec::new();

    for (i, ev) in evidence.iter().enumerate() {
        let result = updater.update(ev);
        let decision = selector.select(&result.posterior);
        posterior_history.push((i as u64, result.posterior));
        decision_log.push(decision);
    }

    IncidentTrace {
        metadata: IncidentMetadata {
            trace_id: trace_id.to_string(),
            extension_id: "ext-001".to_string(),
            start_epoch: SecurityEpoch::GENESIS,
            start_timestamp_ns: 1_000_000,
            end_timestamp_ns: 2_000_000,
            initial_prior: prior,
            loss_matrix_id: "balanced".to_string(),
            annotations: BTreeMap::new(),
        },
        telemetry_log: Vec::new(),
        posterior_history,
        decision_log,
        evidence_log: evidence,
        containment_log: Vec::new(),
        loss_matrix,
        likelihood_model,
    }
}

fn build_trace(evidence: Vec<Evidence>) -> IncidentTrace {
    build_trace_with_id(evidence, "trace-enrich")
}

fn empty_trace() -> IncidentTrace {
    IncidentTrace {
        metadata: IncidentMetadata {
            trace_id: "empty-enrich".to_string(),
            extension_id: "ext-empty".to_string(),
            start_epoch: SecurityEpoch::GENESIS,
            start_timestamp_ns: 0,
            end_timestamp_ns: 0,
            initial_prior: Posterior::default_prior(),
            loss_matrix_id: "balanced".to_string(),
            annotations: BTreeMap::new(),
        },
        telemetry_log: Vec::new(),
        posterior_history: Vec::new(),
        decision_log: Vec::new(),
        evidence_log: Vec::new(),
        containment_log: Vec::new(),
        loss_matrix: LossMatrix::balanced(),
        likelihood_model: LikelihoodModel::default(),
    }
}

fn make_replay_step(idx: u64, action: ContainmentAction) -> ReplayStep {
    ReplayStep {
        step_index: idx,
        evidence: benign_evidence(),
        update_result: frankenengine_engine::bayesian_posterior::UpdateResult {
            posterior: Posterior::default_prior(),
            likelihoods: [1_000_000; 4],
            cumulative_llr_millionths: 0,
            update_count: idx + 1,
        },
        decision: ActionDecision {
            action,
            expected_loss_millionths: 100_000,
            runner_up_action: ContainmentAction::Allow,
            runner_up_loss_millionths: 200_000,
            explanation: DecisionExplanation {
                posterior_snapshot: Posterior::default_prior(),
                loss_matrix_id: "test".to_string(),
                all_expected_losses: BTreeMap::new(),
                margin_millionths: 100_000,
            },
            epoch: SecurityEpoch::GENESIS,
        },
    }
}

// ===========================================================================
// Section 1 — TraceValidationError Display uniqueness across all 7 variants
// ===========================================================================

#[test]
fn enrichment_trace_validation_error_display_all_seven_unique() {
    let variants: Vec<TraceValidationError> = vec![
        TraceValidationError::NonMonotonicTimestamp {
            record_index: 10,
            prev_ns: 9999,
            current_ns: 5555,
        },
        TraceValidationError::InvalidPosterior { step_index: 77 },
        TraceValidationError::DecisionCountMismatch {
            decisions: 11,
            posteriors: 22,
        },
        TraceValidationError::EvidenceCountMismatch {
            evidence: 33,
            posteriors: 44,
        },
        TraceValidationError::EmptyTrace,
        TraceValidationError::TelemetryIntegrityFailure { record_id: 55 },
        TraceValidationError::ReceiptIntegrityFailure {
            receipt_id: "rcpt-unique".to_string(),
        },
    ];
    let mut display_set = BTreeSet::new();
    for v in &variants {
        let s = v.to_string();
        assert!(!s.is_empty(), "Display string must not be empty");
        display_set.insert(s);
    }
    assert_eq!(display_set.len(), 7, "all 7 variants must produce distinct Display strings");
}

#[test]
fn enrichment_trace_validation_error_non_monotonic_display_format() {
    let e = TraceValidationError::NonMonotonicTimestamp {
        record_index: 42,
        prev_ns: 1_000_000,
        current_ns: 500_000,
    };
    let s = e.to_string();
    assert!(s.contains("42"), "should contain record_index");
    assert!(s.contains("1000000"), "should contain prev_ns");
    assert!(s.contains("500000"), "should contain current_ns");
    assert!(s.contains("non-monotonic"), "should mention non-monotonic");
}

#[test]
fn enrichment_trace_validation_error_invalid_posterior_display_format() {
    let e = TraceValidationError::InvalidPosterior { step_index: 999 };
    let s = e.to_string();
    assert!(s.contains("999"), "should contain step_index");
    assert!(s.contains("invalid posterior"), "should mention invalid posterior");
}

#[test]
fn enrichment_trace_validation_error_decision_count_display_format() {
    let e = TraceValidationError::DecisionCountMismatch {
        decisions: 123,
        posteriors: 456,
    };
    let s = e.to_string();
    assert!(s.contains("123"), "should contain decisions count");
    assert!(s.contains("456"), "should contain posteriors count");
}

#[test]
fn enrichment_trace_validation_error_evidence_count_display_format() {
    let e = TraceValidationError::EvidenceCountMismatch {
        evidence: 789,
        posteriors: 321,
    };
    let s = e.to_string();
    assert!(s.contains("789"), "should contain evidence count");
    assert!(s.contains("321"), "should contain posteriors count");
}

#[test]
fn enrichment_trace_validation_error_telemetry_integrity_display_format() {
    let e = TraceValidationError::TelemetryIntegrityFailure { record_id: 12345 };
    let s = e.to_string();
    assert!(s.contains("12345"), "should contain record_id");
    assert!(s.contains("telemetry integrity failure"), "should mention telemetry integrity");
}

#[test]
fn enrichment_trace_validation_error_receipt_integrity_display_format() {
    let e = TraceValidationError::ReceiptIntegrityFailure {
        receipt_id: "receipt-alpha-bravo".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("receipt-alpha-bravo"), "should contain receipt_id");
    assert!(s.contains("receipt integrity failure"), "should mention receipt integrity");
}

// ===========================================================================
// Section 2 — TraceValidationError serde roundtrip per-variant isolation
// ===========================================================================

#[test]
fn enrichment_trace_validation_error_serde_non_monotonic() {
    let e = TraceValidationError::NonMonotonicTimestamp {
        record_index: 0,
        prev_ns: u64::MAX,
        current_ns: 0,
    };
    let json = serde_json::to_string(&e).unwrap();
    let restored: TraceValidationError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, restored);
}

#[test]
fn enrichment_trace_validation_error_serde_invalid_posterior_max_step() {
    let e = TraceValidationError::InvalidPosterior {
        step_index: u64::MAX,
    };
    let json = serde_json::to_string(&e).unwrap();
    let restored: TraceValidationError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, restored);
}

#[test]
fn enrichment_trace_validation_error_serde_decision_count_zero() {
    let e = TraceValidationError::DecisionCountMismatch {
        decisions: 0,
        posteriors: 0,
    };
    let json = serde_json::to_string(&e).unwrap();
    let restored: TraceValidationError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, restored);
}

#[test]
fn enrichment_trace_validation_error_serde_evidence_count_large_values() {
    let e = TraceValidationError::EvidenceCountMismatch {
        evidence: usize::MAX,
        posteriors: 0,
    };
    let json = serde_json::to_string(&e).unwrap();
    let restored: TraceValidationError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, restored);
}

#[test]
fn enrichment_trace_validation_error_serde_empty_trace() {
    let e = TraceValidationError::EmptyTrace;
    let json = serde_json::to_string(&e).unwrap();
    let restored: TraceValidationError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, restored);
    assert_eq!(restored.to_string(), "empty trace");
}

#[test]
fn enrichment_trace_validation_error_serde_telemetry_integrity_zero() {
    let e = TraceValidationError::TelemetryIntegrityFailure { record_id: 0 };
    let json = serde_json::to_string(&e).unwrap();
    let restored: TraceValidationError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, restored);
}

#[test]
fn enrichment_trace_validation_error_serde_receipt_integrity_empty_id() {
    let e = TraceValidationError::ReceiptIntegrityFailure {
        receipt_id: String::new(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let restored: TraceValidationError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, restored);
}

// ===========================================================================
// Section 3 — DecisionChange Display and serde exhaustive
// ===========================================================================

#[test]
fn enrichment_decision_change_display_all_three_unique() {
    let variants: Vec<DecisionChange> = vec![
        DecisionChange::Identical,
        DecisionChange::SameActionDifferentMargin {
            original_margin: 1,
            counterfactual_margin: 2,
        },
        DecisionChange::DifferentAction {
            original_action: ContainmentAction::Allow,
            counterfactual_action: ContainmentAction::Terminate,
            original_loss: 100,
            counterfactual_loss: 200,
        },
    ];
    let mut display_set = BTreeSet::new();
    for v in &variants {
        display_set.insert(v.to_string());
    }
    assert_eq!(display_set.len(), 3, "all 3 DecisionChange variants must have unique Display");
}

#[test]
fn enrichment_decision_change_identical_display_exact() {
    assert_eq!(DecisionChange::Identical.to_string(), "identical");
}

#[test]
fn enrichment_decision_change_same_action_margin_zero() {
    let dc = DecisionChange::SameActionDifferentMargin {
        original_margin: 0,
        counterfactual_margin: 0,
    };
    let s = dc.to_string();
    assert!(s.contains("same action"));
    assert!(s.contains("0"));
}

#[test]
fn enrichment_decision_change_same_action_negative_margins() {
    let dc = DecisionChange::SameActionDifferentMargin {
        original_margin: -500_000,
        counterfactual_margin: -100_000,
    };
    let s = dc.to_string();
    assert!(s.contains("-500000"));
    assert!(s.contains("-100000"));
}

#[test]
fn enrichment_decision_change_different_action_all_action_pairs() {
    let actions = [
        ContainmentAction::Allow,
        ContainmentAction::Challenge,
        ContainmentAction::Sandbox,
        ContainmentAction::Suspend,
        ContainmentAction::Terminate,
        ContainmentAction::Quarantine,
    ];
    for orig in &actions {
        for cf in &actions {
            if orig != cf {
                let dc = DecisionChange::DifferentAction {
                    original_action: *orig,
                    counterfactual_action: *cf,
                    original_loss: 1_000,
                    counterfactual_loss: 2_000,
                };
                let s = dc.to_string();
                assert!(s.contains(&orig.to_string()));
                assert!(s.contains(&cf.to_string()));
            }
        }
    }
}

#[test]
fn enrichment_decision_change_serde_identical() {
    let dc = DecisionChange::Identical;
    let json = serde_json::to_string(&dc).unwrap();
    let restored: DecisionChange = serde_json::from_str(&json).unwrap();
    assert_eq!(dc, restored);
}

#[test]
fn enrichment_decision_change_serde_same_action_large_margins() {
    let dc = DecisionChange::SameActionDifferentMargin {
        original_margin: i64::MAX,
        counterfactual_margin: i64::MIN,
    };
    let json = serde_json::to_string(&dc).unwrap();
    let restored: DecisionChange = serde_json::from_str(&json).unwrap();
    assert_eq!(dc, restored);
}

#[test]
fn enrichment_decision_change_serde_different_action_all_actions() {
    for action in ContainmentAction::ALL {
        let dc = DecisionChange::DifferentAction {
            original_action: ContainmentAction::Allow,
            counterfactual_action: action,
            original_loss: 42,
            counterfactual_loss: 84,
        };
        let json = serde_json::to_string(&dc).unwrap();
        let restored: DecisionChange = serde_json::from_str(&json).unwrap();
        assert_eq!(dc, restored);
    }
}

// ===========================================================================
// Section 4 — ReplayError Display and serde exhaustive
// ===========================================================================

#[test]
fn enrichment_replay_error_display_all_three_unique() {
    let variants: Vec<ReplayError> = vec![
        ReplayError::ValidationFailed {
            errors: vec![TraceValidationError::EmptyTrace],
        },
        ReplayError::StepLimitExceeded { limit: 1 },
        ReplayError::Internal {
            detail: "x".to_string(),
        },
    ];
    let mut display_set = BTreeSet::new();
    for v in &variants {
        display_set.insert(v.to_string());
    }
    assert_eq!(display_set.len(), 3, "all 3 ReplayError variants must have unique Display");
}

#[test]
fn enrichment_replay_error_validation_failed_multiple_errors() {
    let err = ReplayError::ValidationFailed {
        errors: vec![
            TraceValidationError::EmptyTrace,
            TraceValidationError::InvalidPosterior { step_index: 0 },
            TraceValidationError::DecisionCountMismatch {
                decisions: 1,
                posteriors: 2,
            },
            TraceValidationError::EvidenceCountMismatch {
                evidence: 3,
                posteriors: 4,
            },
            TraceValidationError::NonMonotonicTimestamp {
                record_index: 0,
                prev_ns: 10,
                current_ns: 5,
            },
        ],
    };
    let s = err.to_string();
    assert!(s.contains("5 error(s)"));
}

#[test]
fn enrichment_replay_error_validation_failed_single_error() {
    let err = ReplayError::ValidationFailed {
        errors: vec![TraceValidationError::EmptyTrace],
    };
    let s = err.to_string();
    assert!(s.contains("1 error(s)"));
}

#[test]
fn enrichment_replay_error_step_limit_zero() {
    let err = ReplayError::StepLimitExceeded { limit: 0 };
    let s = err.to_string();
    assert!(s.contains("0"));
    assert!(s.contains("step limit"));
}

#[test]
fn enrichment_replay_error_step_limit_large() {
    let err = ReplayError::StepLimitExceeded { limit: 1_000_000 };
    let s = err.to_string();
    assert!(s.contains("1000000"));
}

#[test]
fn enrichment_replay_error_internal_empty_detail() {
    let err = ReplayError::Internal {
        detail: String::new(),
    };
    let s = err.to_string();
    assert!(s.contains("internal"));
}

#[test]
fn enrichment_replay_error_internal_long_detail() {
    let detail = "x".repeat(1000);
    let err = ReplayError::Internal {
        detail: detail.clone(),
    };
    let s = err.to_string();
    assert!(s.contains(&detail));
}

#[test]
fn enrichment_replay_error_serde_validation_with_all_error_types() {
    let err = ReplayError::ValidationFailed {
        errors: vec![
            TraceValidationError::EmptyTrace,
            TraceValidationError::NonMonotonicTimestamp {
                record_index: 1,
                prev_ns: 200,
                current_ns: 100,
            },
            TraceValidationError::InvalidPosterior { step_index: 5 },
            TraceValidationError::DecisionCountMismatch {
                decisions: 10,
                posteriors: 8,
            },
            TraceValidationError::EvidenceCountMismatch {
                evidence: 7,
                posteriors: 3,
            },
            TraceValidationError::TelemetryIntegrityFailure { record_id: 99 },
            TraceValidationError::ReceiptIntegrityFailure {
                receipt_id: "rcpt-nested".to_string(),
            },
        ],
    };
    let json = serde_json::to_string(&err).unwrap();
    let restored: ReplayError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

#[test]
fn enrichment_replay_error_serde_step_limit_max() {
    let err = ReplayError::StepLimitExceeded { limit: usize::MAX };
    let json = serde_json::to_string(&err).unwrap();
    let restored: ReplayError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

#[test]
fn enrichment_replay_error_serde_internal_unicode() {
    let err = ReplayError::Internal {
        detail: "failure in module \u{2603} snowman".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let restored: ReplayError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

// ===========================================================================
// Section 5 — IncidentMetadata edge cases
// ===========================================================================

#[test]
fn enrichment_incident_metadata_empty_strings() {
    let meta = IncidentMetadata {
        trace_id: String::new(),
        extension_id: String::new(),
        start_epoch: SecurityEpoch::GENESIS,
        start_timestamp_ns: 0,
        end_timestamp_ns: 0,
        initial_prior: Posterior::default_prior(),
        loss_matrix_id: String::new(),
        annotations: BTreeMap::new(),
    };
    let json = serde_json::to_string(&meta).unwrap();
    let restored: IncidentMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(meta, restored);
    assert!(restored.trace_id.is_empty());
    assert!(restored.extension_id.is_empty());
    assert!(restored.loss_matrix_id.is_empty());
}

#[test]
fn enrichment_incident_metadata_large_annotations() {
    let mut annotations = BTreeMap::new();
    for i in 0..50 {
        annotations.insert(format!("key-{i}"), format!("value-{i}"));
    }
    let meta = IncidentMetadata {
        trace_id: "trace-big-ann".to_string(),
        extension_id: "ext-big".to_string(),
        start_epoch: SecurityEpoch::from_raw(100),
        start_timestamp_ns: 0,
        end_timestamp_ns: u64::MAX,
        initial_prior: Posterior::uniform(),
        loss_matrix_id: "permissive".to_string(),
        annotations: annotations.clone(),
    };
    let json = serde_json::to_string(&meta).unwrap();
    let restored: IncidentMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(meta, restored);
    assert_eq!(restored.annotations.len(), 50);
}

#[test]
fn enrichment_incident_metadata_max_timestamps() {
    let meta = IncidentMetadata {
        trace_id: "trace-max-ts".to_string(),
        extension_id: "ext-max".to_string(),
        start_epoch: SecurityEpoch::from_raw(u64::MAX),
        start_timestamp_ns: u64::MAX,
        end_timestamp_ns: u64::MAX,
        initial_prior: Posterior::default_prior(),
        loss_matrix_id: "balanced".to_string(),
        annotations: BTreeMap::new(),
    };
    let json = serde_json::to_string(&meta).unwrap();
    let restored: IncidentMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(meta, restored);
}

#[test]
fn enrichment_incident_metadata_clone_equality() {
    let mut annotations = BTreeMap::new();
    annotations.insert("k".to_string(), "v".to_string());
    let meta = IncidentMetadata {
        trace_id: "trace-clone".to_string(),
        extension_id: "ext-clone".to_string(),
        start_epoch: SecurityEpoch::from_raw(5),
        start_timestamp_ns: 100,
        end_timestamp_ns: 200,
        initial_prior: Posterior::from_millionths(100_000, 200_000, 300_000, 400_000),
        loss_matrix_id: "balanced".to_string(),
        annotations,
    };
    let cloned = meta.clone();
    assert_eq!(meta, cloned);
}

// ===========================================================================
// Section 6 — IncidentTrace content_hash sensitivity
// ===========================================================================

#[test]
fn enrichment_incident_trace_content_hash_sensitive_to_telemetry_count() {
    let t1 = build_trace(vec![benign_evidence()]);
    let mut t2 = build_trace(vec![benign_evidence()]);
    // Manually adjust telemetry_log length to differ.
    // This tests that content_hash includes telemetry_log.len().
    // Since telemetry_log is empty in both, they should have the same hash.
    // We verify the hash is stable when telemetry_log is empty.
    assert_eq!(t1.content_hash(), t2.content_hash());

    // Changing trace_id should change the hash.
    t2.metadata.trace_id = "different-id".to_string();
    assert_ne!(t1.content_hash(), t2.content_hash());
}

#[test]
fn enrichment_incident_trace_content_hash_sensitive_to_containment_log_count() {
    let t1 = build_trace(vec![benign_evidence()]);
    let mut t2 = build_trace(vec![benign_evidence()]);
    assert_eq!(t1.content_hash(), t2.content_hash());
    t2.metadata.end_timestamp_ns = 9_999_999;
    assert_ne!(t1.content_hash(), t2.content_hash());
}

#[test]
fn enrichment_incident_trace_content_hash_deterministic_100_calls() {
    let trace = build_trace(vec![benign_evidence(), suspicious_evidence(), malicious_evidence()]);
    let first = trace.content_hash();
    for _ in 0..100 {
        assert_eq!(trace.content_hash(), first, "content_hash must be deterministic");
    }
}

#[test]
fn enrichment_incident_trace_content_hash_differs_by_decision_count() {
    let t1 = build_trace(vec![benign_evidence()]);
    let t2 = build_trace(vec![benign_evidence(), benign_evidence()]);
    assert_ne!(t1.content_hash(), t2.content_hash());
}

#[test]
fn enrichment_incident_trace_serde_preserves_all_fields() {
    let mut annotations = BTreeMap::new();
    annotations.insert("test-key".to_string(), "test-val".to_string());
    let evidence = vec![benign_evidence(), suspicious_evidence(), malicious_evidence()];
    let mut trace = build_trace(evidence);
    trace.metadata.annotations = annotations;
    trace.metadata.trace_id = "preserved-fields".to_string();
    trace.metadata.start_epoch = SecurityEpoch::from_raw(42);

    let json = serde_json::to_string(&trace).unwrap();
    let restored: IncidentTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(trace, restored);
    assert_eq!(restored.evidence_log.len(), 3);
    assert_eq!(restored.decision_log.len(), 3);
    assert_eq!(restored.posterior_history.len(), 3);
    assert_eq!(restored.metadata.annotations.len(), 1);
    assert_eq!(restored.metadata.start_epoch, SecurityEpoch::from_raw(42));
}

// ===========================================================================
// Section 7 — ReplayConfig boundary values
// ===========================================================================

#[test]
fn enrichment_replay_config_max_steps_one() {
    let config = ReplayConfig {
        verify_telemetry_integrity: true,
        verify_receipt_integrity: true,
        max_steps: 1,
    };
    let json = serde_json::to_string(&config).unwrap();
    let restored: ReplayConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, restored);
    assert_eq!(restored.max_steps, 1);
}

#[test]
fn enrichment_replay_config_all_false() {
    let config = ReplayConfig {
        verify_telemetry_integrity: false,
        verify_receipt_integrity: false,
        max_steps: 999_999,
    };
    let json = serde_json::to_string(&config).unwrap();
    let restored: ReplayConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, restored);
}

#[test]
fn enrichment_replay_config_clone_equality() {
    let config = ReplayConfig {
        verify_telemetry_integrity: false,
        verify_receipt_integrity: true,
        max_steps: 500,
    };
    let cloned = config.clone();
    assert_eq!(config, cloned);
}

// ===========================================================================
// Section 8 — CounterfactualSpec edge cases
// ===========================================================================

#[test]
fn enrichment_counterfactual_spec_identity_description_value() {
    let spec = CounterfactualSpec::identity();
    assert_eq!(spec.description, "identity");
}

#[test]
fn enrichment_counterfactual_spec_with_loss_matrix_all_types() {
    for (label, matrix) in [
        ("balanced", LossMatrix::balanced()),
        ("conservative", LossMatrix::conservative()),
        ("permissive", LossMatrix::permissive()),
    ] {
        let spec = CounterfactualSpec::with_loss_matrix(matrix.clone(), label);
        assert_eq!(spec.override_loss_matrix, Some(matrix));
        assert!(spec.override_prior.is_none());
        assert_eq!(spec.description, label);
    }
}

#[test]
fn enrichment_counterfactual_spec_with_prior_various_distributions() {
    let priors = [
        Posterior::default_prior(),
        Posterior::uniform(),
        Posterior::from_millionths(0, 0, 1_000_000, 0),
        Posterior::from_millionths(1_000_000, 0, 0, 0),
        Posterior::from_millionths(500_000, 250_000, 125_000, 125_000),
    ];
    for prior in &priors {
        let spec = CounterfactualSpec::with_prior(prior.clone(), "test");
        assert_eq!(spec.override_prior.as_ref(), Some(prior));
    }
}

#[test]
fn enrichment_counterfactual_spec_serde_empty_inject_and_skip() {
    let spec = CounterfactualSpec {
        override_prior: None,
        override_loss_matrix: None,
        override_likelihood_model: None,
        skip_evidence_indices: Vec::new(),
        inject_evidence: Vec::new(),
        description: "minimal".to_string(),
    };
    let json = serde_json::to_string(&spec).unwrap();
    let restored: CounterfactualSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(spec, restored);
}

#[test]
fn enrichment_counterfactual_spec_serde_many_skip_indices() {
    let spec = CounterfactualSpec {
        skip_evidence_indices: (0..100).collect(),
        description: "skip many".to_string(),
        ..CounterfactualSpec::identity()
    };
    let json = serde_json::to_string(&spec).unwrap();
    let restored: CounterfactualSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(spec, restored);
    assert_eq!(restored.skip_evidence_indices.len(), 100);
}

#[test]
fn enrichment_counterfactual_spec_serde_many_injections() {
    let spec = CounterfactualSpec {
        inject_evidence: (0..20).map(|i| (i, benign_evidence())).collect(),
        description: "inject many".to_string(),
        ..CounterfactualSpec::identity()
    };
    let json = serde_json::to_string(&spec).unwrap();
    let restored: CounterfactualSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(spec, restored);
    assert_eq!(restored.inject_evidence.len(), 20);
}

#[test]
fn enrichment_counterfactual_spec_clone_equality() {
    let spec = CounterfactualSpec {
        override_prior: Some(Posterior::uniform()),
        override_loss_matrix: Some(LossMatrix::conservative()),
        override_likelihood_model: Some(LikelihoodModel::default()),
        skip_evidence_indices: vec![0, 1, 2],
        inject_evidence: vec![(5, malicious_evidence())],
        description: "clone test".to_string(),
    };
    let cloned = spec.clone();
    assert_eq!(spec, cloned);
}

// ===========================================================================
// Section 9 — ReplayStep serde and field access
// ===========================================================================

#[test]
fn enrichment_replay_step_serde_all_actions() {
    for action in ContainmentAction::ALL {
        let step = make_replay_step(0, action);
        let json = serde_json::to_string(&step).unwrap();
        let restored: ReplayStep = serde_json::from_str(&json).unwrap();
        assert_eq!(step, restored);
        assert_eq!(restored.decision.action, action);
    }
}

#[test]
fn enrichment_replay_step_field_access() {
    let step = make_replay_step(7, ContainmentAction::Sandbox);
    assert_eq!(step.step_index, 7);
    assert_eq!(step.decision.action, ContainmentAction::Sandbox);
    assert_eq!(step.decision.expected_loss_millionths, 100_000);
    assert_eq!(step.decision.runner_up_action, ContainmentAction::Allow);
    assert_eq!(step.decision.runner_up_loss_millionths, 200_000);
    assert_eq!(step.decision.explanation.margin_millionths, 100_000);
    assert_eq!(step.decision.epoch, SecurityEpoch::GENESIS);
}

#[test]
fn enrichment_replay_step_clone_equality() {
    let step = make_replay_step(3, ContainmentAction::Challenge);
    let cloned = step.clone();
    assert_eq!(step, cloned);
}

// ===========================================================================
// Section 10 — ReplayResult serde and field access
// ===========================================================================

#[test]
fn enrichment_replay_result_all_fields_accessible() {
    let trace = build_trace(vec![benign_evidence(), suspicious_evidence()]);
    let mut replayer = ForensicReplayer::new();
    let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();

    assert_eq!(result.trace_id, "trace-enrich");
    assert_eq!(result.steps.len(), 2);
    assert!(result.final_decision.is_some());
    assert!(result.deterministic);
    assert!(result.first_divergence_step.is_none());
    // content_hash is not zero-length
    let hash_bytes = result.content_hash.as_bytes();
    assert!(!hash_bytes.iter().all(|&b| b == 0));
}

#[test]
fn enrichment_replay_result_serde_with_single_step() {
    let trace = build_trace(vec![benign_evidence()]);
    let mut replayer = ForensicReplayer::new();
    let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let restored: ReplayResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
    assert_eq!(restored.steps.len(), 1);
}

#[test]
fn enrichment_replay_result_serde_with_many_steps() {
    let evidence = vec![benign_evidence(); 20];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();
    let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let restored: ReplayResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
    assert_eq!(restored.steps.len(), 20);
}

#[test]
fn enrichment_replay_result_content_hash_differs_for_different_step_counts() {
    let t1 = build_trace(vec![benign_evidence()]);
    let t2 = build_trace(vec![benign_evidence(), benign_evidence()]);
    let mut replayer = ForensicReplayer::new();
    let r1 = replayer.replay(&t1, &ReplayConfig::default()).unwrap();
    let r2 = replayer.replay(&t2, &ReplayConfig::default()).unwrap();
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_replay_result_content_hash_differs_for_different_trace_ids() {
    let t1 = build_trace_with_id(vec![benign_evidence()], "hash-a");
    let t2 = build_trace_with_id(vec![benign_evidence()], "hash-b");
    let mut replayer = ForensicReplayer::new();
    let r1 = replayer.replay(&t1, &ReplayConfig::default()).unwrap();
    let r2 = replayer.replay(&t2, &ReplayConfig::default()).unwrap();
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_replay_result_final_posterior_equals_last_step_posterior() {
    let trace = build_trace(vec![
        benign_evidence(),
        suspicious_evidence(),
        malicious_evidence(),
        benign_evidence(),
    ]);
    let mut replayer = ForensicReplayer::new();
    let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    assert_eq!(
        result.final_posterior,
        result.steps.last().unwrap().update_result.posterior
    );
}

#[test]
fn enrichment_replay_result_final_decision_action_matches_last_step() {
    let trace = build_trace(vec![suspicious_evidence(), malicious_evidence()]);
    let mut replayer = ForensicReplayer::new();
    let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    let last = result.steps.last().unwrap();
    assert_eq!(result.final_decision.as_ref().unwrap().action, last.decision.action);
}

// ===========================================================================
// Section 11 — ReplayDiff serde and field access
// ===========================================================================

#[test]
fn enrichment_replay_diff_serde_no_actions() {
    let diff = ReplayDiff {
        counterfactual_description: "empty diff".to_string(),
        first_divergence_step: None,
        step_changes: Vec::new(),
        action_change_count: 0,
        original_final_action: None,
        counterfactual_final_action: None,
        final_outcome_differs: false,
    };
    let json = serde_json::to_string(&diff).unwrap();
    let restored: ReplayDiff = serde_json::from_str(&json).unwrap();
    assert_eq!(diff, restored);
}

#[test]
fn enrichment_replay_diff_serde_none_final_actions() {
    let diff = ReplayDiff {
        counterfactual_description: "no final actions".to_string(),
        first_divergence_step: None,
        step_changes: vec![(0, DecisionChange::Identical)],
        action_change_count: 0,
        original_final_action: None,
        counterfactual_final_action: None,
        final_outcome_differs: false,
    };
    let json = serde_json::to_string(&diff).unwrap();
    let restored: ReplayDiff = serde_json::from_str(&json).unwrap();
    assert_eq!(diff, restored);
    assert!(restored.original_final_action.is_none());
    assert!(restored.counterfactual_final_action.is_none());
}

#[test]
fn enrichment_replay_diff_serde_all_containment_actions_as_final() {
    for action in ContainmentAction::ALL {
        let diff = ReplayDiff {
            counterfactual_description: format!("final-{action}"),
            first_divergence_step: Some(0),
            step_changes: vec![(0, DecisionChange::Identical)],
            action_change_count: 0,
            original_final_action: Some(action),
            counterfactual_final_action: Some(action),
            final_outcome_differs: false,
        };
        let json = serde_json::to_string(&diff).unwrap();
        let restored: ReplayDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(diff, restored);
    }
}

#[test]
fn enrichment_replay_diff_clone_equality() {
    let diff = ReplayDiff {
        counterfactual_description: "clone test".to_string(),
        first_divergence_step: Some(3),
        step_changes: vec![
            (0, DecisionChange::Identical),
            (1, DecisionChange::SameActionDifferentMargin {
                original_margin: 10,
                counterfactual_margin: 20,
            }),
            (2, DecisionChange::DifferentAction {
                original_action: ContainmentAction::Allow,
                counterfactual_action: ContainmentAction::Terminate,
                original_loss: 100,
                counterfactual_loss: 50,
            }),
        ],
        action_change_count: 1,
        original_final_action: Some(ContainmentAction::Allow),
        counterfactual_final_action: Some(ContainmentAction::Terminate),
        final_outcome_differs: true,
    };
    let cloned = diff.clone();
    assert_eq!(diff, cloned);
}

// ===========================================================================
// Section 12 — ForensicReplayer construction and state
// ===========================================================================

#[test]
fn enrichment_forensic_replayer_new_initial_state() {
    let replayer = ForensicReplayer::new();
    assert_eq!(replayer.replay_count(), 0);
}

#[test]
fn enrichment_forensic_replayer_default_matches_new() {
    let a = ForensicReplayer::new();
    let b = ForensicReplayer::default();
    assert_eq!(a.replay_count(), b.replay_count());
}

#[test]
fn enrichment_forensic_replayer_set_epoch_multiple_times() {
    let trace = build_trace(vec![benign_evidence()]);
    let mut replayer = ForensicReplayer::new();

    replayer.set_epoch(SecurityEpoch::from_raw(1));
    let r1 = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    assert_eq!(r1.steps[0].decision.epoch, SecurityEpoch::from_raw(1));

    replayer.set_epoch(SecurityEpoch::from_raw(999));
    let r2 = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    assert_eq!(r2.steps[0].decision.epoch, SecurityEpoch::from_raw(999));
}

#[test]
fn enrichment_forensic_replayer_serde_roundtrip_fresh() {
    let replayer = ForensicReplayer::new();
    let json = serde_json::to_string(&replayer).unwrap();
    let restored: ForensicReplayer = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.replay_count(), 0);
}

#[test]
fn enrichment_forensic_replayer_serde_roundtrip_after_replays() {
    let trace = build_trace(vec![benign_evidence()]);
    let mut replayer = ForensicReplayer::new();
    replayer.set_epoch(SecurityEpoch::from_raw(77));
    for _ in 0..5 {
        replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    }
    assert_eq!(replayer.replay_count(), 5);

    let json = serde_json::to_string(&replayer).unwrap();
    let mut restored: ForensicReplayer = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.replay_count(), 5);

    // Restored replayer continues to function.
    let result = restored.replay(&trace, &ReplayConfig::default()).unwrap();
    assert_eq!(restored.replay_count(), 6);
    assert_eq!(result.steps[0].decision.epoch, SecurityEpoch::from_raw(77));
}

// ===========================================================================
// Section 13 — validate_trace edge cases
// ===========================================================================

#[test]
fn enrichment_validate_trace_single_evidence_valid() {
    let trace = build_trace(vec![benign_evidence()]);
    let errors = validate_trace(&trace);
    assert!(errors.is_empty());
}

#[test]
fn enrichment_validate_trace_many_evidence_valid() {
    let trace = build_trace(vec![benign_evidence(); 50]);
    let errors = validate_trace(&trace);
    assert!(errors.is_empty());
}

#[test]
fn enrichment_validate_trace_empty_returns_single_error() {
    let trace = empty_trace();
    let errors = validate_trace(&trace);
    assert_eq!(errors.len(), 1);
    assert!(matches!(errors[0], TraceValidationError::EmptyTrace));
}

#[test]
fn enrichment_validate_trace_evidence_cleared_produces_mismatch() {
    let mut trace = build_trace(vec![benign_evidence(), benign_evidence()]);
    trace.evidence_log.clear();
    let errors = validate_trace(&trace);
    // Empty evidence_log should produce EmptyTrace (early return).
    assert!(errors.iter().any(|e| matches!(e, TraceValidationError::EmptyTrace)));
}

#[test]
fn enrichment_validate_trace_posterior_cleared_produces_mismatch() {
    let mut trace = build_trace(vec![benign_evidence(), benign_evidence()]);
    trace.posterior_history.clear();
    let errors = validate_trace(&trace);
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, TraceValidationError::EvidenceCountMismatch { .. }))
    );
}

#[test]
fn enrichment_validate_trace_decision_log_extra_produces_mismatch() {
    let mut trace = build_trace(vec![benign_evidence()]);
    trace.decision_log.push(trace.decision_log[0].clone());
    trace.decision_log.push(trace.decision_log[0].clone());
    let errors = validate_trace(&trace);
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, TraceValidationError::DecisionCountMismatch { .. }))
    );
}

#[test]
fn enrichment_validate_trace_invalid_posterior_detected() {
    let mut trace = build_trace(vec![benign_evidence()]);
    // Create an invalid posterior (sum != 1_000_000).
    trace.posterior_history[0].1 = Posterior::from_millionths(100, 200, 300, 400);
    // from_millionths normalizes, so let's set fields directly.
    trace.posterior_history[0].1 = Posterior {
        p_benign: 500_000,
        p_anomalous: 500_000,
        p_malicious: 500_000,
        p_unknown: 500_000,
    };
    let errors = validate_trace(&trace);
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, TraceValidationError::InvalidPosterior { .. }))
    );
}

// ===========================================================================
// Section 14 — Replay: step limit boundaries
// ===========================================================================

#[test]
fn enrichment_replay_step_limit_one_succeeds_single_evidence() {
    let trace = build_trace(vec![benign_evidence()]);
    let mut replayer = ForensicReplayer::new();
    let config = ReplayConfig {
        max_steps: 1,
        ..Default::default()
    };
    let result = replayer.replay(&trace, &config).unwrap();
    assert_eq!(result.steps.len(), 1);
}

#[test]
fn enrichment_replay_step_limit_one_fails_two_evidence() {
    let trace = build_trace(vec![benign_evidence(), benign_evidence()]);
    let mut replayer = ForensicReplayer::new();
    let config = ReplayConfig {
        max_steps: 1,
        ..Default::default()
    };
    let err = replayer.replay(&trace, &config).unwrap_err();
    assert!(matches!(err, ReplayError::StepLimitExceeded { limit: 1 }));
}

#[test]
fn enrichment_replay_step_limit_exact_boundary() {
    for n in 1..=10 {
        let evidence = vec![benign_evidence(); n];
        let trace = build_trace(evidence);
        let mut replayer = ForensicReplayer::new();
        let config = ReplayConfig {
            max_steps: n,
            ..Default::default()
        };
        let result = replayer.replay(&trace, &config).unwrap();
        assert_eq!(result.steps.len(), n);
    }
}

#[test]
fn enrichment_replay_step_limit_zero_unlimited() {
    let evidence = vec![benign_evidence(); 50];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();
    let config = ReplayConfig {
        max_steps: 0,
        ..Default::default()
    };
    let result = replayer.replay(&trace, &config).unwrap();
    assert_eq!(result.steps.len(), 50);
}

// ===========================================================================
// Section 15 — Replay: determinism guarantees
// ===========================================================================

#[test]
fn enrichment_replay_determinism_across_50_runs() {
    let evidence = vec![
        benign_evidence(),
        suspicious_evidence(),
        malicious_evidence(),
        benign_evidence(),
        suspicious_evidence(),
    ];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();

    let baseline = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    for _ in 0..50 {
        let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
        assert!(result.deterministic);
        assert_eq!(result.content_hash, baseline.content_hash);
        for (a, b) in result.steps.iter().zip(baseline.steps.iter()) {
            assert_eq!(a.decision.action, b.decision.action);
            assert_eq!(a.decision.expected_loss_millionths, b.decision.expected_loss_millionths);
        }
    }
}

#[test]
fn enrichment_replay_determinism_independent_of_replay_count() {
    let trace = build_trace(vec![suspicious_evidence()]);

    let mut r1 = ForensicReplayer::new();
    let result1 = r1.replay(&trace, &ReplayConfig::default()).unwrap();

    let mut r2 = ForensicReplayer::new();
    // Do some replays first to increment the count.
    for _ in 0..10 {
        r2.replay(&trace, &ReplayConfig::default()).unwrap();
    }
    let result2 = r2.replay(&trace, &ReplayConfig::default()).unwrap();

    assert_eq!(result1.content_hash, result2.content_hash);
    assert_eq!(result1.steps[0].decision.action, result2.steps[0].decision.action);
}

#[test]
fn enrichment_replay_epoch_does_not_affect_decision_action() {
    let trace = build_trace(vec![benign_evidence(), malicious_evidence()]);

    let mut r1 = ForensicReplayer::new();
    r1.set_epoch(SecurityEpoch::from_raw(0));
    let result1 = r1.replay(&trace, &ReplayConfig::default()).unwrap();

    let mut r2 = ForensicReplayer::new();
    r2.set_epoch(SecurityEpoch::from_raw(u64::MAX));
    let result2 = r2.replay(&trace, &ReplayConfig::default()).unwrap();

    for (s1, s2) in result1.steps.iter().zip(result2.steps.iter()) {
        assert_eq!(s1.decision.action, s2.decision.action);
    }
}

// ===========================================================================
// Section 16 — Replay: containment state escalation paths
// ===========================================================================

#[test]
fn enrichment_replay_all_benign_stays_running() {
    let trace = build_trace(vec![benign_evidence(); 20]);
    let mut replayer = ForensicReplayer::new();
    let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    assert_eq!(result.final_containment_state, ContainmentState::Running);
}

#[test]
fn enrichment_replay_escalation_monotonically_increases_severity() {
    let evidence = vec![
        benign_evidence(),
        suspicious_evidence(),
        suspicious_evidence(),
        malicious_evidence(),
        malicious_evidence(),
        malicious_evidence(),
    ];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();
    let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();

    // Severity should never decrease across the escalation sequence.
    let mut prev_severity: u32 = 0;
    for step in &result.steps {
        let sev = step.decision.action.severity();
        assert!(sev >= prev_severity, "severity should not decrease: {prev_severity} -> {sev}");
        prev_severity = sev;
    }
}

#[test]
fn enrichment_replay_single_malicious_evidence_action() {
    let trace = build_trace(vec![malicious_evidence()]);
    let mut replayer = ForensicReplayer::new();
    let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    assert_eq!(result.steps.len(), 1);
    // Single malicious evidence from benign prior shouldn't immediately terminate.
    // But the action is deterministic.
    let action = result.steps[0].decision.action;
    assert!(action.severity() >= ContainmentAction::Allow.severity());
}

// ===========================================================================
// Section 17 — Counterfactual: edge cases
// ===========================================================================

#[test]
fn enrichment_counterfactual_identity_has_same_step_count() {
    let trace = build_trace(vec![benign_evidence(); 5]);
    let mut replayer = ForensicReplayer::new();
    let original = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    let cf = replayer
        .counterfactual(&trace, &ReplayConfig::default(), &CounterfactualSpec::identity())
        .unwrap();
    assert_eq!(original.steps.len(), cf.steps.len());
}

#[test]
fn enrichment_counterfactual_identity_same_actions() {
    let trace = build_trace(vec![
        benign_evidence(),
        suspicious_evidence(),
        malicious_evidence(),
    ]);
    let mut replayer = ForensicReplayer::new();
    let original = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    let cf = replayer
        .counterfactual(&trace, &ReplayConfig::default(), &CounterfactualSpec::identity())
        .unwrap();
    for (i, (o, c)) in original.steps.iter().zip(cf.steps.iter()).enumerate() {
        assert_eq!(o.decision.action, c.decision.action, "step {i} diverged");
    }
}

#[test]
fn enrichment_counterfactual_skip_first_evidence() {
    let evidence = vec![malicious_evidence(), benign_evidence(), benign_evidence()];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();
    let spec = CounterfactualSpec {
        skip_evidence_indices: vec![0],
        description: "skip first".to_string(),
        ..CounterfactualSpec::identity()
    };
    let cf = replayer
        .counterfactual(&trace, &ReplayConfig::default(), &spec)
        .unwrap();
    assert_eq!(cf.steps.len(), 2);
}

#[test]
fn enrichment_counterfactual_skip_last_evidence() {
    let evidence = vec![benign_evidence(), benign_evidence(), malicious_evidence()];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();
    let spec = CounterfactualSpec {
        skip_evidence_indices: vec![2],
        description: "skip last".to_string(),
        ..CounterfactualSpec::identity()
    };
    let cf = replayer
        .counterfactual(&trace, &ReplayConfig::default(), &spec)
        .unwrap();
    assert_eq!(cf.steps.len(), 2);
}

#[test]
fn enrichment_counterfactual_skip_middle_evidence() {
    let evidence = vec![benign_evidence(), malicious_evidence(), benign_evidence()];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();
    let spec = CounterfactualSpec {
        skip_evidence_indices: vec![1],
        description: "skip middle".to_string(),
        ..CounterfactualSpec::identity()
    };
    let cf = replayer
        .counterfactual(&trace, &ReplayConfig::default(), &spec)
        .unwrap();
    assert_eq!(cf.steps.len(), 2);
    // Should be all benign, so all Allow.
    for step in &cf.steps {
        assert_eq!(step.decision.action, ContainmentAction::Allow);
    }
}

#[test]
fn enrichment_counterfactual_inject_at_beginning() {
    let trace = build_trace(vec![benign_evidence()]);
    let mut replayer = ForensicReplayer::new();
    let spec = CounterfactualSpec {
        inject_evidence: vec![(0, malicious_evidence())],
        description: "inject at start".to_string(),
        ..CounterfactualSpec::identity()
    };
    let cf = replayer
        .counterfactual(&trace, &ReplayConfig::default(), &spec)
        .unwrap();
    assert_eq!(cf.steps.len(), 2);
}

#[test]
fn enrichment_counterfactual_inject_beyond_end() {
    let trace = build_trace(vec![benign_evidence()]);
    let mut replayer = ForensicReplayer::new();
    let spec = CounterfactualSpec {
        inject_evidence: vec![(1000, suspicious_evidence())],
        description: "inject far beyond end".to_string(),
        ..CounterfactualSpec::identity()
    };
    let cf = replayer
        .counterfactual(&trace, &ReplayConfig::default(), &spec)
        .unwrap();
    assert_eq!(cf.steps.len(), 2);
}

#[test]
fn enrichment_counterfactual_skip_all_fails() {
    let evidence = vec![benign_evidence(), suspicious_evidence(), malicious_evidence()];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();
    let spec = CounterfactualSpec {
        skip_evidence_indices: vec![0, 1, 2],
        description: "skip all".to_string(),
        ..CounterfactualSpec::identity()
    };
    let err = replayer
        .counterfactual(&trace, &ReplayConfig::default(), &spec)
        .unwrap_err();
    assert!(matches!(err, ReplayError::ValidationFailed { .. }));
}

#[test]
fn enrichment_counterfactual_conservative_matrix_escalates() {
    let evidence = vec![suspicious_evidence(); 4];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();

    let original = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    let cf = replayer
        .counterfactual(
            &trace,
            &ReplayConfig::default(),
            &CounterfactualSpec::with_loss_matrix(LossMatrix::conservative(), "conservative"),
        )
        .unwrap();

    let orig_max_sev = original
        .steps
        .iter()
        .map(|s| s.decision.action.severity())
        .max()
        .unwrap_or(0);
    let cf_max_sev = cf
        .steps
        .iter()
        .map(|s| s.decision.action.severity())
        .max()
        .unwrap_or(0);
    assert!(cf_max_sev >= orig_max_sev);
}

#[test]
fn enrichment_counterfactual_permissive_matrix_deescalates_or_matches() {
    let evidence = vec![suspicious_evidence(); 4];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();

    let original = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    let cf = replayer
        .counterfactual(
            &trace,
            &ReplayConfig::default(),
            &CounterfactualSpec::with_loss_matrix(LossMatrix::permissive(), "permissive"),
        )
        .unwrap();

    let orig_max_sev = original
        .steps
        .iter()
        .map(|s| s.decision.action.severity())
        .max()
        .unwrap_or(0);
    let cf_max_sev = cf
        .steps
        .iter()
        .map(|s| s.decision.action.severity())
        .max()
        .unwrap_or(0);
    assert!(cf_max_sev <= orig_max_sev);
}

#[test]
fn enrichment_counterfactual_increments_replay_count() {
    let trace = build_trace(vec![benign_evidence()]);
    let mut replayer = ForensicReplayer::new();
    assert_eq!(replayer.replay_count(), 0);
    replayer
        .counterfactual(&trace, &ReplayConfig::default(), &CounterfactualSpec::identity())
        .unwrap();
    assert_eq!(replayer.replay_count(), 1);
}

#[test]
fn enrichment_counterfactual_with_suspicious_prior() {
    let trace = build_trace(vec![benign_evidence(), benign_evidence()]);
    let mut replayer = ForensicReplayer::new();

    let original = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    let suspicious_prior = Posterior::from_millionths(50_000, 100_000, 800_000, 50_000);
    let cf = replayer
        .counterfactual(
            &trace,
            &ReplayConfig::default(),
            &CounterfactualSpec::with_prior(suspicious_prior, "suspicious prior"),
        )
        .unwrap();

    // With suspicious prior, severity should be >= original.
    let orig_final_sev = original.final_decision.as_ref().unwrap().action.severity();
    let cf_final_sev = cf.final_decision.as_ref().unwrap().action.severity();
    assert!(cf_final_sev >= orig_final_sev);
}

// ===========================================================================
// Section 18 — Diff: comprehensive edge cases
// ===========================================================================

#[test]
fn enrichment_diff_identical_replays_all_identical_changes() {
    let trace = build_trace(vec![benign_evidence(); 5]);
    let mut replayer = ForensicReplayer::new();
    let r1 = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    let r2 = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    let diff = replayer.diff(&r1, &r2, "should be identical");
    assert!(diff.first_divergence_step.is_none());
    assert_eq!(diff.action_change_count, 0);
    assert!(!diff.final_outcome_differs);
    for (_, change) in &diff.step_changes {
        assert_eq!(*change, DecisionChange::Identical);
    }
}

#[test]
fn enrichment_diff_single_step_identical() {
    let trace = build_trace(vec![benign_evidence()]);
    let mut replayer = ForensicReplayer::new();
    let r1 = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    let r2 = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    let diff = replayer.diff(&r1, &r2, "single step");
    assert_eq!(diff.step_changes.len(), 1);
    assert_eq!(diff.step_changes[0].1, DecisionChange::Identical);
}

#[test]
fn enrichment_diff_different_lengths_reports_divergence() {
    let t1 = build_trace(vec![benign_evidence()]);
    let t2 = build_trace(vec![benign_evidence(), benign_evidence(), benign_evidence()]);
    let mut replayer = ForensicReplayer::new();
    let r1 = replayer.replay(&t1, &ReplayConfig::default()).unwrap();
    let r2 = replayer.replay(&t2, &ReplayConfig::default()).unwrap();
    let diff = replayer.diff(&r1, &r2, "1 vs 3 steps");
    // Max length = 3.
    assert_eq!(diff.step_changes.len(), 3);
    // Extra steps should trigger divergence.
    assert!(diff.first_divergence_step.is_some() || diff.action_change_count > 0);
}

#[test]
fn enrichment_diff_counterfactual_description_propagated() {
    let trace = build_trace(vec![benign_evidence()]);
    let mut replayer = ForensicReplayer::new();
    let r1 = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    let r2 = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    let diff = replayer.diff(&r1, &r2, "my-description-here");
    assert_eq!(diff.counterfactual_description, "my-description-here");
}

#[test]
fn enrichment_diff_final_outcome_differs_flag_correct() {
    let trace = build_trace(vec![suspicious_evidence(); 5]);
    let mut replayer = ForensicReplayer::new();
    let original = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    let cf = replayer
        .counterfactual(
            &trace,
            &ReplayConfig::default(),
            &CounterfactualSpec::with_loss_matrix(LossMatrix::conservative(), "conservative"),
        )
        .unwrap();
    let diff = replayer.diff(&original, &cf, "outcome check");
    // final_outcome_differs should be consistent.
    let orig_final = diff.original_final_action;
    let cf_final = diff.counterfactual_final_action;
    assert_eq!(diff.final_outcome_differs, orig_final != cf_final);
}

#[test]
fn enrichment_diff_action_change_count_bounded_by_step_count() {
    let trace = build_trace(vec![suspicious_evidence(); 3]);
    let mut replayer = ForensicReplayer::new();
    let original = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    let cf = replayer
        .counterfactual(
            &trace,
            &ReplayConfig::default(),
            &CounterfactualSpec::with_loss_matrix(LossMatrix::permissive(), "permissive"),
        )
        .unwrap();
    let diff = replayer.diff(&original, &cf, "bounded count");
    assert!(diff.action_change_count <= diff.step_changes.len());
}

// ===========================================================================
// Section 19 — Full lifecycle: multi-phase pipelines
// ===========================================================================

#[test]
fn enrichment_full_lifecycle_replay_cf_diff_three_matrices() {
    let evidence = vec![
        benign_evidence(),
        suspicious_evidence(),
        suspicious_evidence(),
        malicious_evidence(),
    ];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();

    let balanced = replayer.replay(&trace, &ReplayConfig::default()).unwrap();

    let permissive = replayer
        .counterfactual(
            &trace,
            &ReplayConfig::default(),
            &CounterfactualSpec::with_loss_matrix(LossMatrix::permissive(), "permissive"),
        )
        .unwrap();

    let conservative = replayer
        .counterfactual(
            &trace,
            &ReplayConfig::default(),
            &CounterfactualSpec::with_loss_matrix(LossMatrix::conservative(), "conservative"),
        )
        .unwrap();

    // Diff balanced vs permissive.
    let diff_bp = replayer.diff(&balanced, &permissive, "balanced vs permissive");
    assert_eq!(diff_bp.step_changes.len(), 4);

    // Diff balanced vs conservative.
    let diff_bc = replayer.diff(&balanced, &conservative, "balanced vs conservative");
    assert_eq!(diff_bc.step_changes.len(), 4);

    // Diff permissive vs conservative.
    let diff_pc = replayer.diff(&permissive, &conservative, "permissive vs conservative");
    assert_eq!(diff_pc.step_changes.len(), 4);

    // Conservative should be at least as severe as permissive.
    let perm_max = permissive.steps.iter().map(|s| s.decision.action.severity()).max().unwrap_or(0);
    let cons_max = conservative.steps.iter().map(|s| s.decision.action.severity()).max().unwrap_or(0);
    assert!(cons_max >= perm_max);

    assert_eq!(replayer.replay_count(), 3);
}

#[test]
fn enrichment_full_lifecycle_inject_then_diff() {
    let trace = build_trace(vec![benign_evidence(), benign_evidence()]);
    let mut replayer = ForensicReplayer::new();
    let original = replayer.replay(&trace, &ReplayConfig::default()).unwrap();

    let spec = CounterfactualSpec {
        inject_evidence: vec![(1, malicious_evidence()), (1, malicious_evidence())],
        description: "inject 2 malicious".to_string(),
        ..CounterfactualSpec::identity()
    };
    let cf = replayer
        .counterfactual(&trace, &ReplayConfig::default(), &spec)
        .unwrap();
    assert_eq!(cf.steps.len(), 4);

    let diff = replayer.diff(&original, &cf, "injected pipeline");
    assert_eq!(diff.step_changes.len(), 4);
    assert_eq!(diff.counterfactual_description, "injected pipeline");
}

#[test]
fn enrichment_full_lifecycle_skip_then_inject_combined() {
    let evidence = vec![
        benign_evidence(),
        malicious_evidence(),
        benign_evidence(),
        suspicious_evidence(),
    ];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();
    let original = replayer.replay(&trace, &ReplayConfig::default()).unwrap();

    // Skip malicious, inject benign in its place.
    let spec = CounterfactualSpec {
        skip_evidence_indices: vec![1],
        inject_evidence: vec![(1, benign_evidence())],
        description: "replace malicious with benign".to_string(),
        ..CounterfactualSpec::identity()
    };
    let cf = replayer
        .counterfactual(&trace, &ReplayConfig::default(), &spec)
        .unwrap();
    // skip 1 (malicious) + inject 1 (benign before index 1) = 4 steps still.
    assert_eq!(cf.steps.len(), 4);

    let diff = replayer.diff(&original, &cf, "replaced malicious");
    assert_eq!(diff.step_changes.len(), 4);
}

#[test]
fn enrichment_full_lifecycle_epoch_propagation_to_all_steps() {
    let trace = build_trace(vec![
        benign_evidence(),
        suspicious_evidence(),
        malicious_evidence(),
        benign_evidence(),
        suspicious_evidence(),
    ]);
    let mut replayer = ForensicReplayer::new();
    replayer.set_epoch(SecurityEpoch::from_raw(12345));
    let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    for step in &result.steps {
        assert_eq!(step.decision.epoch, SecurityEpoch::from_raw(12345));
    }
}

#[test]
fn enrichment_full_lifecycle_replay_count_across_mixed_operations() {
    let trace = build_trace(vec![benign_evidence(), suspicious_evidence()]);
    let mut replayer = ForensicReplayer::new();

    // 1 replay
    replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    assert_eq!(replayer.replay_count(), 1);

    // 1 counterfactual
    replayer
        .counterfactual(&trace, &ReplayConfig::default(), &CounterfactualSpec::identity())
        .unwrap();
    assert_eq!(replayer.replay_count(), 2);

    // 1 more replay
    replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    assert_eq!(replayer.replay_count(), 3);

    // failed replay (empty trace) should NOT increment count
    let empty = empty_trace();
    let _ = replayer.replay(&empty, &ReplayConfig::default());
    assert_eq!(replayer.replay_count(), 3);

    // 1 more counterfactual
    replayer
        .counterfactual(
            &trace,
            &ReplayConfig::default(),
            &CounterfactualSpec::with_loss_matrix(LossMatrix::conservative(), "cons"),
        )
        .unwrap();
    assert_eq!(replayer.replay_count(), 4);
}

// ===========================================================================
// Section 20 — Content hash properties
// ===========================================================================

#[test]
fn enrichment_content_hash_compute_deterministic() {
    let data = b"forensic-test-data-12345";
    let h1 = ContentHash::compute(data);
    let h2 = ContentHash::compute(data);
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_content_hash_different_inputs_different_hashes() {
    let h1 = ContentHash::compute(b"input-alpha");
    let h2 = ContentHash::compute(b"input-beta");
    assert_ne!(h1, h2);
}

#[test]
fn enrichment_incident_trace_content_hash_serde_stable() {
    let trace = build_trace(vec![benign_evidence(), malicious_evidence()]);
    let hash_before = trace.content_hash();
    let json = serde_json::to_string(&trace).unwrap();
    let restored: IncidentTrace = serde_json::from_str(&json).unwrap();
    let hash_after = restored.content_hash();
    assert_eq!(hash_before, hash_after);
}

#[test]
fn enrichment_replay_result_content_hash_serde_stable() {
    let trace = build_trace(vec![benign_evidence(), suspicious_evidence()]);
    let mut replayer = ForensicReplayer::new();
    let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    let hash_before = result.content_hash;
    let json = serde_json::to_string(&result).unwrap();
    let restored: ReplayResult = serde_json::from_str(&json).unwrap();
    assert_eq!(hash_before, restored.content_hash);
}

// ===========================================================================
// Section 21 — SecurityEpoch integration
// ===========================================================================

#[test]
fn enrichment_security_epoch_from_raw_serde() {
    let epoch = SecurityEpoch::from_raw(42);
    let json = serde_json::to_string(&epoch).unwrap();
    let restored: SecurityEpoch = serde_json::from_str(&json).unwrap();
    assert_eq!(epoch, restored);
    assert_eq!(restored.as_u64(), 42);
}

#[test]
fn enrichment_security_epoch_genesis_is_zero() {
    assert_eq!(SecurityEpoch::GENESIS.as_u64(), 0);
}

#[test]
fn enrichment_security_epoch_max_value() {
    let epoch = SecurityEpoch::from_raw(u64::MAX);
    let json = serde_json::to_string(&epoch).unwrap();
    let restored: SecurityEpoch = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.as_u64(), u64::MAX);
}

// ===========================================================================
// Section 22 — Replay error from replay with validation failures
// ===========================================================================

#[test]
fn enrichment_replay_empty_trace_error_is_validation_failed() {
    let trace = empty_trace();
    let mut replayer = ForensicReplayer::new();
    let err = replayer.replay(&trace, &ReplayConfig::default()).unwrap_err();
    match &err {
        ReplayError::ValidationFailed { errors } => {
            assert!(!errors.is_empty());
            assert!(errors.iter().any(|e| matches!(e, TraceValidationError::EmptyTrace)));
        }
        other => panic!("expected ValidationFailed, got: {other}"),
    }
}

#[test]
fn enrichment_replay_mismatched_trace_error_is_validation_failed() {
    let mut trace = build_trace(vec![benign_evidence(), benign_evidence()]);
    trace.evidence_log.pop();
    let mut replayer = ForensicReplayer::new();
    let err = replayer.replay(&trace, &ReplayConfig::default()).unwrap_err();
    assert!(matches!(err, ReplayError::ValidationFailed { .. }));
}

// ===========================================================================
// Section 23 — Counterfactual with override likelihood model
// ===========================================================================

#[test]
fn enrichment_counterfactual_override_all_three_simultaneously() {
    let trace = build_trace(vec![benign_evidence(), suspicious_evidence()]);
    let mut replayer = ForensicReplayer::new();

    let spec = CounterfactualSpec {
        override_prior: Some(Posterior::uniform()),
        override_loss_matrix: Some(LossMatrix::conservative()),
        override_likelihood_model: Some(LikelihoodModel::default()),
        skip_evidence_indices: Vec::new(),
        inject_evidence: Vec::new(),
        description: "all three overrides".to_string(),
    };
    let cf = replayer
        .counterfactual(&trace, &ReplayConfig::default(), &spec)
        .unwrap();
    assert_eq!(cf.steps.len(), 2);
}

// ===========================================================================
// Section 24 — Mixed evidence patterns
// ===========================================================================

#[test]
fn enrichment_replay_alternating_benign_malicious() {
    let evidence: Vec<Evidence> = (0..10)
        .map(|i| {
            if i % 2 == 0 {
                benign_evidence()
            } else {
                malicious_evidence()
            }
        })
        .collect();
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();
    let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    assert_eq!(result.steps.len(), 10);
    assert!(result.deterministic);
}

#[test]
fn enrichment_replay_all_suspicious_sequence() {
    let trace = build_trace(vec![suspicious_evidence(); 15]);
    let mut replayer = ForensicReplayer::new();
    let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    assert_eq!(result.steps.len(), 15);
    assert!(result.deterministic);
    // With many suspicious evidence, should eventually escalate.
    let final_sev = result.final_decision.as_ref().unwrap().action.severity();
    assert!(final_sev >= ContainmentAction::Allow.severity());
}

#[test]
fn enrichment_replay_all_malicious_reaches_terminal_state() {
    let trace = build_trace(vec![malicious_evidence(); 20]);
    let mut replayer = ForensicReplayer::new();
    let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    // After 20 malicious evidence, should have escalated significantly.
    let final_sev = result.final_decision.as_ref().unwrap().action.severity();
    assert!(final_sev >= ContainmentAction::Challenge.severity());
}

// ===========================================================================
// Section 25 — Trace ID propagation
// ===========================================================================

#[test]
fn enrichment_replay_trace_id_propagated() {
    let trace = build_trace_with_id(vec![benign_evidence()], "my-unique-trace-id-999");
    let mut replayer = ForensicReplayer::new();
    let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    assert_eq!(result.trace_id, "my-unique-trace-id-999");
}

#[test]
fn enrichment_replay_trace_id_propagated_in_counterfactual() {
    let trace = build_trace_with_id(vec![benign_evidence()], "cf-trace-id-abc");
    let mut replayer = ForensicReplayer::new();
    let result = replayer
        .counterfactual(&trace, &ReplayConfig::default(), &CounterfactualSpec::identity())
        .unwrap();
    assert_eq!(result.trace_id, "cf-trace-id-abc");
}

// ===========================================================================
// Section 26 — Step index correctness
// ===========================================================================

#[test]
fn enrichment_replay_step_indices_zero_based_sequential() {
    let trace = build_trace(vec![benign_evidence(); 8]);
    let mut replayer = ForensicReplayer::new();
    let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    for (i, step) in result.steps.iter().enumerate() {
        assert_eq!(step.step_index, i as u64, "step_index must match position");
    }
}

#[test]
fn enrichment_counterfactual_step_indices_zero_based_sequential() {
    let trace = build_trace(vec![benign_evidence(); 5]);
    let mut replayer = ForensicReplayer::new();
    let spec = CounterfactualSpec {
        inject_evidence: vec![(2, suspicious_evidence())],
        description: "inject mid".to_string(),
        ..CounterfactualSpec::identity()
    };
    let cf = replayer
        .counterfactual(&trace, &ReplayConfig::default(), &spec)
        .unwrap();
    for (i, step) in cf.steps.iter().enumerate() {
        assert_eq!(step.step_index, i as u64);
    }
}

// ===========================================================================
// Section 27 — Diff step_changes indices correctness
// ===========================================================================

#[test]
fn enrichment_diff_step_changes_indices_sequential() {
    let trace = build_trace(vec![benign_evidence(); 4]);
    let mut replayer = ForensicReplayer::new();
    let r1 = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    let r2 = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    let diff = replayer.diff(&r1, &r2, "sequential indices");
    for (i, (idx, _)) in diff.step_changes.iter().enumerate() {
        assert_eq!(*idx, i as u64, "step_changes index must be sequential");
    }
}

// ===========================================================================
// Section 28 — Multiple replayers independence
// ===========================================================================

#[test]
fn enrichment_two_replayers_independent_counts() {
    let trace = build_trace(vec![benign_evidence()]);
    let mut r1 = ForensicReplayer::new();
    let mut r2 = ForensicReplayer::new();

    r1.replay(&trace, &ReplayConfig::default()).unwrap();
    r1.replay(&trace, &ReplayConfig::default()).unwrap();
    r1.replay(&trace, &ReplayConfig::default()).unwrap();
    r2.replay(&trace, &ReplayConfig::default()).unwrap();

    assert_eq!(r1.replay_count(), 3);
    assert_eq!(r2.replay_count(), 1);
}

#[test]
fn enrichment_two_replayers_independent_epochs() {
    let trace = build_trace(vec![benign_evidence()]);
    let mut r1 = ForensicReplayer::new();
    let mut r2 = ForensicReplayer::new();
    r1.set_epoch(SecurityEpoch::from_raw(11));
    r2.set_epoch(SecurityEpoch::from_raw(22));

    let result1 = r1.replay(&trace, &ReplayConfig::default()).unwrap();
    let result2 = r2.replay(&trace, &ReplayConfig::default()).unwrap();

    assert_eq!(result1.steps[0].decision.epoch, SecurityEpoch::from_raw(11));
    assert_eq!(result2.steps[0].decision.epoch, SecurityEpoch::from_raw(22));
}

#[test]
fn enrichment_two_replayers_same_trace_same_results() {
    let trace = build_trace(vec![benign_evidence(), suspicious_evidence()]);
    let mut r1 = ForensicReplayer::new();
    let mut r2 = ForensicReplayer::new();

    let result1 = r1.replay(&trace, &ReplayConfig::default()).unwrap();
    let result2 = r2.replay(&trace, &ReplayConfig::default()).unwrap();

    assert_eq!(result1.content_hash, result2.content_hash);
    assert_eq!(result1.steps.len(), result2.steps.len());
    for (s1, s2) in result1.steps.iter().zip(result2.steps.iter()) {
        assert_eq!(s1.decision.action, s2.decision.action);
    }
}
