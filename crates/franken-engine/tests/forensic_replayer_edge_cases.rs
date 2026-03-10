//! Integration tests for `forensic_replayer` — edge cases and gaps
//! not covered by inline unit tests.

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

use frankenengine_engine::bayesian_posterior::{
    BayesianPosteriorUpdater, Evidence, LikelihoodModel, Posterior, UpdateResult,
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
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn benign_evidence() -> Evidence {
    Evidence {
        extension_id: "ext-001".to_string(),
        hostcall_rate_millionths: 10_000_000,
        distinct_capabilities: 3,
        resource_score_millionths: 200_000,
        timing_anomaly_millionths: 100_000,
        denial_rate_millionths: 10_000,
        epoch: SecurityEpoch::GENESIS,
    }
}

fn suspicious_evidence() -> Evidence {
    Evidence {
        extension_id: "ext-001".to_string(),
        hostcall_rate_millionths: 600_000_000,
        distinct_capabilities: 3,
        resource_score_millionths: 200_000,
        timing_anomaly_millionths: 100_000,
        denial_rate_millionths: 250_000,
        epoch: SecurityEpoch::GENESIS,
    }
}

fn malicious_evidence() -> Evidence {
    Evidence {
        extension_id: "ext-001".to_string(),
        hostcall_rate_millionths: 1_000_000_000,
        distinct_capabilities: 3,
        resource_score_millionths: 200_000,
        timing_anomaly_millionths: 100_000,
        denial_rate_millionths: 500_000,
        epoch: SecurityEpoch::GENESIS,
    }
}

fn build_trace(evidence: Vec<Evidence>) -> IncidentTrace {
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
            trace_id: "trace-001".to_string(),
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

// ===========================================================================
// TraceValidationError — serde all variants
// ===========================================================================

#[test]
fn trace_validation_error_serde_all_variants() {
    let variants: Vec<TraceValidationError> = vec![
        TraceValidationError::NonMonotonicTimestamp {
            record_index: 5,
            prev_ns: 100,
            current_ns: 50,
        },
        TraceValidationError::InvalidPosterior { step_index: 3 },
        TraceValidationError::DecisionCountMismatch {
            decisions: 5,
            posteriors: 3,
        },
        TraceValidationError::EvidenceCountMismatch {
            evidence: 4,
            posteriors: 6,
        },
        TraceValidationError::EmptyTrace,
        TraceValidationError::TelemetryIntegrityFailure { record_id: 42 },
        TraceValidationError::ReceiptIntegrityFailure {
            receipt_id: "rcpt-001".to_string(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: TraceValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

#[test]
fn trace_validation_error_display_all_variants() {
    let variants: Vec<TraceValidationError> = vec![
        TraceValidationError::NonMonotonicTimestamp {
            record_index: 2,
            prev_ns: 200,
            current_ns: 100,
        },
        TraceValidationError::InvalidPosterior { step_index: 7 },
        TraceValidationError::DecisionCountMismatch {
            decisions: 3,
            posteriors: 5,
        },
        TraceValidationError::EvidenceCountMismatch {
            evidence: 2,
            posteriors: 4,
        },
        TraceValidationError::EmptyTrace,
        TraceValidationError::TelemetryIntegrityFailure { record_id: 99 },
        TraceValidationError::ReceiptIntegrityFailure {
            receipt_id: "r1".to_string(),
        },
    ];
    for v in &variants {
        let s = v.to_string();
        assert!(!s.is_empty());
    }
    assert!(variants[0].to_string().contains("non-monotonic"));
    assert!(variants[1].to_string().contains("7"));
    assert!(variants[2].to_string().contains("3"));
    assert!(variants[3].to_string().contains("2"));
    assert_eq!(variants[4].to_string(), "empty trace");
    assert!(variants[5].to_string().contains("99"));
    assert!(variants[6].to_string().contains("r1"));
}

// ===========================================================================
// ReplayError — serde all variants
// ===========================================================================

#[test]
fn replay_error_serde_all_variants() {
    let variants: Vec<ReplayError> = vec![
        ReplayError::ValidationFailed {
            errors: vec![TraceValidationError::EmptyTrace],
        },
        ReplayError::StepLimitExceeded { limit: 100 },
        ReplayError::Internal {
            detail: "something broke".to_string(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: ReplayError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

#[test]
fn replay_error_display_all_variants() {
    assert!(
        ReplayError::ValidationFailed {
            errors: vec![
                TraceValidationError::EmptyTrace,
                TraceValidationError::InvalidPosterior { step_index: 0 },
            ],
        }
        .to_string()
        .contains("2 error(s)")
    );
    assert!(
        ReplayError::StepLimitExceeded { limit: 999 }
            .to_string()
            .contains("999")
    );
    assert!(
        ReplayError::Internal {
            detail: "boom".to_string()
        }
        .to_string()
        .contains("boom")
    );
}

// ===========================================================================
// DecisionChange — serde all variants, display
// ===========================================================================

#[test]
fn decision_change_serde_all_variants() {
    let variants: Vec<DecisionChange> = vec![
        DecisionChange::Identical,
        DecisionChange::SameActionDifferentMargin {
            original_margin: 100_000,
            counterfactual_margin: 200_000,
        },
        DecisionChange::DifferentAction {
            original_action: ContainmentAction::Allow,
            counterfactual_action: ContainmentAction::Terminate,
            original_loss: 10_000,
            counterfactual_loss: 5_000,
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: DecisionChange = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

#[test]
fn decision_change_display_same_action_different_margin() {
    let dc = DecisionChange::SameActionDifferentMargin {
        original_margin: 100,
        counterfactual_margin: 200,
    };
    let s = dc.to_string();
    assert!(s.contains("100"));
    assert!(s.contains("200"));
    assert!(s.contains("same action"));
}

// ===========================================================================
// ReplayConfig — serde roundtrip, custom values
// ===========================================================================

#[test]
fn replay_config_serde_roundtrip() {
    let config = ReplayConfig {
        verify_telemetry_integrity: false,
        verify_receipt_integrity: false,
        max_steps: 42,
    };
    let json = serde_json::to_string(&config).unwrap();
    let restored: ReplayConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, restored);
}

#[test]
fn replay_config_default_values() {
    let config = ReplayConfig::default();
    assert!(config.verify_telemetry_integrity);
    assert!(config.verify_receipt_integrity);
    assert_eq!(config.max_steps, 0);
}

// ===========================================================================
// CounterfactualSpec — constructors and serde
// ===========================================================================

#[test]
fn counterfactual_spec_identity_fields() {
    let spec = CounterfactualSpec::identity();
    assert!(spec.override_prior.is_none());
    assert!(spec.override_loss_matrix.is_none());
    assert!(spec.override_likelihood_model.is_none());
    assert!(spec.skip_evidence_indices.is_empty());
    assert!(spec.inject_evidence.is_empty());
    assert_eq!(spec.description, "identity");
}

#[test]
fn counterfactual_spec_with_loss_matrix_fields() {
    let matrix = LossMatrix::conservative();
    let spec = CounterfactualSpec::with_loss_matrix(matrix.clone(), "test conservative");
    assert!(spec.override_prior.is_none());
    assert_eq!(spec.override_loss_matrix, Some(matrix));
    assert!(spec.override_likelihood_model.is_none());
    assert_eq!(spec.description, "test conservative");
}

#[test]
fn counterfactual_spec_with_prior_fields() {
    let prior = Posterior::uniform();
    let spec = CounterfactualSpec::with_prior(prior.clone(), "uniform start");
    assert_eq!(spec.override_prior, Some(prior));
    assert!(spec.override_loss_matrix.is_none());
    assert_eq!(spec.description, "uniform start");
}

#[test]
fn counterfactual_spec_full_serde() {
    let spec = CounterfactualSpec {
        override_prior: Some(Posterior::uniform()),
        override_loss_matrix: Some(LossMatrix::permissive()),
        override_likelihood_model: Some(LikelihoodModel::default()),
        skip_evidence_indices: vec![0, 2, 4],
        inject_evidence: vec![(1, benign_evidence()), (3, malicious_evidence())],
        description: "full spec".to_string(),
    };
    let json = serde_json::to_string(&spec).unwrap();
    let restored: CounterfactualSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(spec, restored);
}

// ===========================================================================
// IncidentMetadata — serde with annotations
// ===========================================================================

#[test]
fn incident_metadata_serde_with_annotations() {
    let mut annotations = BTreeMap::new();
    annotations.insert("operator".to_string(), "agent-007".to_string());
    annotations.insert("severity".to_string(), "critical".to_string());
    let meta = IncidentMetadata {
        trace_id: "trace-annotated".to_string(),
        extension_id: "ext-002".to_string(),
        start_epoch: SecurityEpoch::from_raw(5),
        start_timestamp_ns: 100_000,
        end_timestamp_ns: 200_000,
        initial_prior: Posterior::uniform(),
        loss_matrix_id: "conservative".to_string(),
        annotations,
    };
    let json = serde_json::to_string(&meta).unwrap();
    let restored: IncidentMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(meta, restored);
    assert_eq!(restored.annotations.len(), 2);
    assert_eq!(restored.annotations["operator"], "agent-007");
}

// ===========================================================================
// IncidentTrace — content hash, serde
// ===========================================================================

#[test]
fn incident_trace_content_hash_differs_by_trace_id() {
    let mut t1 = build_trace(vec![benign_evidence()]);
    let mut t2 = build_trace(vec![benign_evidence()]);
    t1.metadata.trace_id = "trace-A".to_string();
    t2.metadata.trace_id = "trace-B".to_string();
    assert_ne!(t1.content_hash(), t2.content_hash());
}

#[test]
fn incident_trace_content_hash_differs_by_extension_id() {
    let mut t1 = build_trace(vec![benign_evidence()]);
    let mut t2 = build_trace(vec![benign_evidence()]);
    t1.metadata.extension_id = "ext-A".to_string();
    t2.metadata.extension_id = "ext-B".to_string();
    assert_ne!(t1.content_hash(), t2.content_hash());
}

#[test]
fn incident_trace_content_hash_differs_by_timestamps() {
    let t1 = build_trace(vec![benign_evidence()]);
    let mut t2 = build_trace(vec![benign_evidence()]);
    t2.metadata.start_timestamp_ns = 999_999;
    assert_ne!(t1.content_hash(), t2.content_hash());
}

#[test]
fn incident_trace_serde_roundtrip() {
    let trace = build_trace(vec![benign_evidence(), suspicious_evidence()]);
    let json = serde_json::to_string(&trace).unwrap();
    let restored: IncidentTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(trace, restored);
}

// ===========================================================================
// ReplayStep — serde
// ===========================================================================

#[test]
fn replay_step_serde_with_malicious_decision() {
    let step = ReplayStep {
        step_index: 5,
        evidence: malicious_evidence(),
        update_result: UpdateResult {
            posterior: Posterior::from_millionths(50_000, 100_000, 800_000, 50_000),
            likelihoods: [100_000, 200_000, 600_000, 100_000],
            cumulative_llr_millionths: 5_000_000,
            update_count: 6,
        },
        decision: ActionDecision {
            action: ContainmentAction::Terminate,
            expected_loss_millionths: 5_000,
            runner_up_action: ContainmentAction::Quarantine,
            runner_up_loss_millionths: 8_000,
            explanation: DecisionExplanation {
                posterior_snapshot: Posterior::from_millionths(50_000, 100_000, 800_000, 50_000),
                loss_matrix_id: "balanced".to_string(),
                all_expected_losses: BTreeMap::new(),
                margin_millionths: 3_000,
            },
            epoch: SecurityEpoch::GENESIS,
        },
    };
    let json = serde_json::to_string(&step).unwrap();
    let restored: ReplayStep = serde_json::from_str(&json).unwrap();
    assert_eq!(step, restored);
}

// ===========================================================================
// ReplayResult — serde
// ===========================================================================

#[test]
fn replay_result_serde_with_divergence() {
    let trace = build_trace(vec![benign_evidence(), suspicious_evidence()]);
    let mut replayer = ForensicReplayer::new();
    let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let restored: ReplayResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
    assert_eq!(result.trace_id, "trace-001");
}

// ===========================================================================
// ReplayDiff — serde with various shapes
// ===========================================================================

#[test]
fn replay_diff_serde_no_divergence() {
    let diff = ReplayDiff {
        counterfactual_description: "no change".to_string(),
        first_divergence_step: None,
        step_changes: vec![
            (0, DecisionChange::Identical),
            (1, DecisionChange::Identical),
        ],
        action_change_count: 0,
        original_final_action: Some(ContainmentAction::Allow),
        counterfactual_final_action: Some(ContainmentAction::Allow),
        final_outcome_differs: false,
    };
    let json = serde_json::to_string(&diff).unwrap();
    let restored: ReplayDiff = serde_json::from_str(&json).unwrap();
    assert_eq!(diff, restored);
}

#[test]
fn replay_diff_serde_with_all_change_types() {
    let diff = ReplayDiff {
        counterfactual_description: "mixed changes".to_string(),
        first_divergence_step: Some(1),
        step_changes: vec![
            (0, DecisionChange::Identical),
            (
                1,
                DecisionChange::SameActionDifferentMargin {
                    original_margin: 50_000,
                    counterfactual_margin: 80_000,
                },
            ),
            (
                2,
                DecisionChange::DifferentAction {
                    original_action: ContainmentAction::Challenge,
                    counterfactual_action: ContainmentAction::Sandbox,
                    original_loss: 30_000,
                    counterfactual_loss: 20_000,
                },
            ),
        ],
        action_change_count: 1,
        original_final_action: Some(ContainmentAction::Challenge),
        counterfactual_final_action: Some(ContainmentAction::Sandbox),
        final_outcome_differs: true,
    };
    let json = serde_json::to_string(&diff).unwrap();
    let restored: ReplayDiff = serde_json::from_str(&json).unwrap();
    assert_eq!(diff, restored);
}

// ===========================================================================
// ForensicReplayer — replay count accumulation
// ===========================================================================

#[test]
fn replayer_replay_count_accumulates_across_traces() {
    let t1 = build_trace(vec![benign_evidence()]);
    let t2 = build_trace(vec![suspicious_evidence()]);
    let mut replayer = ForensicReplayer::new();

    assert_eq!(replayer.replay_count(), 0);
    replayer.replay(&t1, &ReplayConfig::default()).unwrap();
    assert_eq!(replayer.replay_count(), 1);
    replayer.replay(&t2, &ReplayConfig::default()).unwrap();
    assert_eq!(replayer.replay_count(), 2);
    replayer
        .counterfactual(
            &t1,
            &ReplayConfig::default(),
            &CounterfactualSpec::identity(),
        )
        .unwrap();
    assert_eq!(replayer.replay_count(), 3);
}

#[test]
fn replayer_default_epoch_is_genesis() {
    let replayer = ForensicReplayer::default();
    assert_eq!(replayer.replay_count(), 0);
    // Check that epoch defaults to GENESIS by running a replay.
    let trace = build_trace(vec![benign_evidence()]);
    let mut replayer = replayer;
    let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    assert_eq!(result.steps[0].decision.epoch, SecurityEpoch::GENESIS);
}

#[test]
fn replayer_serde_preserves_replay_count() {
    let mut replayer = ForensicReplayer::new();
    let trace = build_trace(vec![benign_evidence()]);
    replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    assert_eq!(replayer.replay_count(), 2);

    let json = serde_json::to_string(&replayer).unwrap();
    let restored: ForensicReplayer = serde_json::from_str(&json).unwrap();
    // Serde preserves the count field.
    assert_eq!(restored.replay_count(), 2);
}

// ===========================================================================
// validate_trace — additional edge cases
// ===========================================================================

#[test]
fn validate_trace_multiple_errors() {
    let mut trace = build_trace(vec![benign_evidence(), benign_evidence()]);
    // Create mismatches by clearing posteriors AND adding extra decisions.
    trace.posterior_history.clear();
    trace.decision_log.push(trace.decision_log[0].clone());
    let errors = validate_trace(&trace);
    // Should have at least EvidenceCountMismatch and DecisionCountMismatch.
    assert!(errors.len() >= 2);
}

#[test]
fn validate_trace_single_evidence_valid() {
    let trace = build_trace(vec![benign_evidence()]);
    let errors = validate_trace(&trace);
    assert!(errors.is_empty());
}

// ===========================================================================
// Replay — step limit edge cases
// ===========================================================================

#[test]
fn replay_step_limit_exact_boundary_passes() {
    let evidence = vec![benign_evidence(); 5];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();
    let config = ReplayConfig {
        max_steps: 5,
        ..Default::default()
    };
    let result = replayer.replay(&trace, &config).unwrap();
    assert_eq!(result.steps.len(), 5);
}

#[test]
fn replay_step_limit_one_over_fails() {
    let evidence = vec![benign_evidence(); 6];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();
    let config = ReplayConfig {
        max_steps: 5,
        ..Default::default()
    };
    let err = replayer.replay(&trace, &config).unwrap_err();
    assert!(matches!(err, ReplayError::StepLimitExceeded { limit: 5 }));
}

#[test]
fn replay_step_limit_zero_means_unlimited() {
    let evidence = vec![benign_evidence(); 20];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();
    let config = ReplayConfig {
        max_steps: 0,
        ..Default::default()
    };
    let result = replayer.replay(&trace, &config).unwrap();
    assert_eq!(result.steps.len(), 20);
}

// ===========================================================================
// Counterfactual — multiple skips and injections
// ===========================================================================

#[test]
fn counterfactual_multiple_skips() {
    let evidence = vec![
        benign_evidence(),
        suspicious_evidence(),
        benign_evidence(),
        malicious_evidence(),
    ];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();

    let spec = CounterfactualSpec {
        skip_evidence_indices: vec![1, 3], // Skip suspicious and malicious.
        description: "skip bad evidence".to_string(),
        ..CounterfactualSpec::identity()
    };

    let cf = replayer
        .counterfactual(&trace, &ReplayConfig::default(), &spec)
        .unwrap();
    assert_eq!(cf.steps.len(), 2); // Only the two benign.
}

#[test]
fn counterfactual_inject_at_same_index() {
    let evidence = vec![benign_evidence()];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();

    let spec = CounterfactualSpec {
        inject_evidence: vec![(0, suspicious_evidence()), (0, malicious_evidence())],
        description: "inject two at index 0".to_string(),
        ..CounterfactualSpec::identity()
    };

    let cf = replayer
        .counterfactual(&trace, &ReplayConfig::default(), &spec)
        .unwrap();
    // 2 injected before index 0 + 1 original = 3.
    assert_eq!(cf.steps.len(), 3);
}

#[test]
fn counterfactual_skip_and_inject_combined() {
    let evidence = vec![
        benign_evidence(),
        suspicious_evidence(),
        malicious_evidence(),
    ];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();

    let spec = CounterfactualSpec {
        skip_evidence_indices: vec![1],                // Remove suspicious.
        inject_evidence: vec![(1, benign_evidence())], // Add benign in its place.
        description: "replace suspicious with benign".to_string(),
        ..CounterfactualSpec::identity()
    };

    let cf = replayer
        .counterfactual(&trace, &ReplayConfig::default(), &spec)
        .unwrap();
    // Injection at index 1 happens before index 1, then index 1 is skipped,
    // then index 2 (malicious) is included: injected_benign + original_benign + malicious = 3.
    assert_eq!(cf.steps.len(), 3);
}

// ===========================================================================
// Counterfactual — with overridden likelihood model
// ===========================================================================

#[test]
fn counterfactual_with_override_likelihood_model() {
    let evidence = vec![benign_evidence(), suspicious_evidence()];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();

    let spec = CounterfactualSpec {
        override_likelihood_model: Some(LikelihoodModel::default()),
        description: "same model but explicit".to_string(),
        ..CounterfactualSpec::identity()
    };

    let cf = replayer
        .counterfactual(&trace, &ReplayConfig::default(), &spec)
        .unwrap();
    assert_eq!(cf.steps.len(), 2);
}

// ===========================================================================
// Diff — edge cases
// ===========================================================================

#[test]
fn diff_only_margin_differences() {
    let evidence = vec![benign_evidence(), benign_evidence()];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();

    let original = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    // Identity counterfactual should produce identical results.
    let cf = replayer
        .counterfactual(
            &trace,
            &ReplayConfig::default(),
            &CounterfactualSpec::identity(),
        )
        .unwrap();

    let diff = replayer.diff(&original, &cf, "should be identical");
    assert_eq!(diff.action_change_count, 0);
    assert!(!diff.final_outcome_differs);
    // All steps should be Identical.
    for (_, change) in &diff.step_changes {
        assert_eq!(*change, DecisionChange::Identical);
    }
}

#[test]
fn diff_empty_original_vs_nonempty_counterfactual() {
    let evidence1 = vec![benign_evidence()];
    let evidence2 = vec![benign_evidence(), benign_evidence(), benign_evidence()];
    let trace1 = build_trace(evidence1);
    let trace2 = build_trace(evidence2);
    let mut replayer = ForensicReplayer::new();

    let r1 = replayer.replay(&trace1, &ReplayConfig::default()).unwrap();
    let r2 = replayer.replay(&trace2, &ReplayConfig::default()).unwrap();

    let diff = replayer.diff(&r1, &r2, "1 step vs 3 steps");
    // Should have max(1,3)=3 step changes.
    assert_eq!(diff.step_changes.len(), 3);
}

// ===========================================================================
// Containment state — escalation paths
// ===========================================================================

#[test]
fn replay_many_malicious_reaches_high_severity() {
    let evidence = vec![malicious_evidence(); 10];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();
    let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();

    // With 10 malicious evidence packets, should escalate beyond Running.
    let final_severity = result
        .final_decision
        .as_ref()
        .map(|d| d.action.severity())
        .unwrap_or(0);
    assert!(
        final_severity >= ContainmentAction::Challenge.severity(),
        "expected escalation with malicious evidence, got severity {final_severity}"
    );
}

#[test]
fn replay_all_benign_stays_running() {
    let evidence = vec![benign_evidence(); 10];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();
    let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    assert_eq!(result.final_containment_state, ContainmentState::Running);
}

// ===========================================================================
// Replay — epoch propagation
// ===========================================================================

#[test]
fn replayer_epoch_propagates_to_all_steps() {
    let evidence = vec![
        benign_evidence(),
        suspicious_evidence(),
        malicious_evidence(),
    ];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();
    replayer.set_epoch(SecurityEpoch::from_raw(42));

    let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    for step in &result.steps {
        assert_eq!(step.decision.epoch, SecurityEpoch::from_raw(42));
    }
}

// ===========================================================================
// Replay — determinism across epoch changes
// ===========================================================================

#[test]
fn replay_determinism_unaffected_by_epoch() {
    let evidence = vec![benign_evidence(), suspicious_evidence()];
    let trace = build_trace(evidence);

    let mut r1 = ForensicReplayer::new();
    r1.set_epoch(SecurityEpoch::from_raw(1));
    let result1 = r1.replay(&trace, &ReplayConfig::default()).unwrap();

    let mut r2 = ForensicReplayer::new();
    r2.set_epoch(SecurityEpoch::from_raw(99));
    let result2 = r2.replay(&trace, &ReplayConfig::default()).unwrap();

    // Actions should be the same regardless of epoch.
    assert_eq!(result1.steps.len(), result2.steps.len());
    for (s1, s2) in result1.steps.iter().zip(result2.steps.iter()) {
        assert_eq!(s1.decision.action, s2.decision.action);
    }
}

// ===========================================================================
// Integration — replay + counterfactual + diff pipeline
// ===========================================================================

#[test]
fn integration_full_pipeline_replay_counterfactual_diff() {
    let evidence = vec![
        benign_evidence(),
        benign_evidence(),
        suspicious_evidence(),
        malicious_evidence(),
    ];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();

    // Replay.
    let original = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    assert!(original.deterministic);
    assert_eq!(original.steps.len(), 4);

    // Counterfactual: remove malicious evidence.
    let spec = CounterfactualSpec {
        skip_evidence_indices: vec![3],
        description: "remove malicious".to_string(),
        ..CounterfactualSpec::identity()
    };
    let cf = replayer
        .counterfactual(&trace, &ReplayConfig::default(), &spec)
        .unwrap();
    assert_eq!(cf.steps.len(), 3);

    // Diff.
    let diff = replayer.diff(&original, &cf, "without malicious");
    // Extra steps from the original (longer) side are only included in step_changes
    // if they come from the counterfactual; since CF is shorter, step_changes = 3.
    assert_eq!(diff.step_changes.len(), 3);
    assert_eq!(diff.counterfactual_description, "without malicious");
}

#[test]
fn integration_permissive_vs_conservative_matrix() {
    let evidence = vec![suspicious_evidence(); 5];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();

    let original = replayer.replay(&trace, &ReplayConfig::default()).unwrap();

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

    // Conservative should be at least as severe as permissive.
    let perm_max = permissive
        .steps
        .iter()
        .map(|s| s.decision.action.severity())
        .max()
        .unwrap_or(0);
    let cons_max = conservative
        .steps
        .iter()
        .map(|s| s.decision.action.severity())
        .max()
        .unwrap_or(0);
    assert!(
        cons_max >= perm_max,
        "conservative ({cons_max}) should be >= permissive ({perm_max})"
    );

    // Diff between permissive and conservative.
    let diff = replayer.diff(&permissive, &conservative, "perm vs cons");
    assert_eq!(diff.step_changes.len(), 5);

    // Total replay count: 1 replay + 2 counterfactuals = 3.
    assert_eq!(replayer.replay_count(), 3);

    let _ = original; // use original to suppress warnings
}

#[test]
fn integration_content_hash_stable_across_replays() {
    let evidence = vec![benign_evidence(), suspicious_evidence()];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();

    let r1 = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    let r2 = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    assert_eq!(r1.content_hash, r2.content_hash);
    assert_eq!(r1.steps.len(), r2.steps.len());
    assert!(r1.deterministic);
    assert!(r2.deterministic);
}
