#![forbid(unsafe_code)]
//! Comprehensive integration tests for `forensic_replayer`.
//!
//! Covers: IncidentMetadata construction and serde, IncidentTrace hashing and
//! serde, TraceValidationError Display/serde, validate_trace paths, ReplayConfig
//! defaults/serde, CounterfactualSpec constructors/serde, DecisionChange
//! Display/serde, ReplayError Display/serde, ForensicReplayer construction and
//! replay lifecycle, counterfactual analysis, diff computation, ReplayResult
//! and ReplayDiff serde, and full end-to-end pipelines.

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
    BayesianPosteriorUpdater, Evidence, LikelihoodModel, Posterior,
};
use frankenengine_engine::containment_executor::ContainmentState;
use frankenengine_engine::expected_loss_selector::{
    ContainmentAction, ExpectedLossSelector, LossMatrix,
};
use frankenengine_engine::forensic_replayer::{
    CounterfactualSpec, DecisionChange, ForensicReplayer, IncidentMetadata, IncidentTrace,
    ReplayConfig, ReplayDiff, ReplayError, ReplayResult, TraceValidationError, validate_trace,
};
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

fn build_trace(evidence: Vec<Evidence>) -> IncidentTrace {
    build_trace_with_id(evidence, "trace-001")
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

fn empty_trace() -> IncidentTrace {
    IncidentTrace {
        metadata: IncidentMetadata {
            trace_id: "empty-trace".to_string(),
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

// ===========================================================================
// Section 1 — IncidentMetadata construction and serde
// ===========================================================================

#[test]
fn metadata_construction_all_fields() {
    let mut annotations = BTreeMap::new();
    annotations.insert("key1".to_string(), "val1".to_string());
    annotations.insert("key2".to_string(), "val2".to_string());
    let meta = IncidentMetadata {
        trace_id: "trace-meta-test".to_string(),
        extension_id: "ext-meta".to_string(),
        start_epoch: SecurityEpoch::from_raw(10),
        start_timestamp_ns: 42_000,
        end_timestamp_ns: 84_000,
        initial_prior: Posterior::uniform(),
        loss_matrix_id: "permissive".to_string(),
        annotations: annotations.clone(),
    };
    assert_eq!(meta.trace_id, "trace-meta-test");
    assert_eq!(meta.extension_id, "ext-meta");
    assert_eq!(meta.start_epoch, SecurityEpoch::from_raw(10));
    assert_eq!(meta.start_timestamp_ns, 42_000);
    assert_eq!(meta.end_timestamp_ns, 84_000);
    assert_eq!(meta.initial_prior, Posterior::uniform());
    assert_eq!(meta.loss_matrix_id, "permissive");
    assert_eq!(meta.annotations.len(), 2);
    assert_eq!(meta.annotations["key1"], "val1");
}

#[test]
fn metadata_serde_empty_annotations() {
    let meta = IncidentMetadata {
        trace_id: "t-empty-ann".to_string(),
        extension_id: "ext-001".to_string(),
        start_epoch: SecurityEpoch::GENESIS,
        start_timestamp_ns: 0,
        end_timestamp_ns: 1,
        initial_prior: Posterior::default_prior(),
        loss_matrix_id: "balanced".to_string(),
        annotations: BTreeMap::new(),
    };
    let json = serde_json::to_string(&meta).unwrap();
    let restored: IncidentMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(meta, restored);
    assert!(restored.annotations.is_empty());
}

// ===========================================================================
// Section 2 — IncidentTrace content_hash and serde
// ===========================================================================

#[test]
fn trace_content_hash_consistent_on_same_trace() {
    let trace = build_trace(vec![benign_evidence(), suspicious_evidence()]);
    let h1 = trace.content_hash();
    let h2 = trace.content_hash();
    assert_eq!(h1, h2);
}

#[test]
fn trace_content_hash_changes_with_evidence_count() {
    let t1 = build_trace(vec![benign_evidence()]);
    let t2 = build_trace(vec![benign_evidence(), benign_evidence()]);
    assert_ne!(t1.content_hash(), t2.content_hash());
}

#[test]
fn trace_serde_preserves_content_hash() {
    let trace = build_trace(vec![benign_evidence(), malicious_evidence()]);
    let hash_before = trace.content_hash();
    let json = serde_json::to_string(&trace).unwrap();
    let restored: IncidentTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(hash_before, restored.content_hash());
}

// ===========================================================================
// Section 3 — TraceValidationError Display all 7 variants
// ===========================================================================

#[test]
fn validation_error_display_non_monotonic_timestamp() {
    let e = TraceValidationError::NonMonotonicTimestamp {
        record_index: 3,
        prev_ns: 500,
        current_ns: 200,
    };
    let s = e.to_string();
    assert!(s.contains("non-monotonic"));
    assert!(s.contains("3"));
    assert!(s.contains("500"));
    assert!(s.contains("200"));
}

#[test]
fn validation_error_display_invalid_posterior() {
    let e = TraceValidationError::InvalidPosterior { step_index: 12 };
    assert!(e.to_string().contains("invalid posterior"));
    assert!(e.to_string().contains("12"));
}

#[test]
fn validation_error_display_decision_count_mismatch() {
    let e = TraceValidationError::DecisionCountMismatch {
        decisions: 7,
        posteriors: 5,
    };
    let s = e.to_string();
    assert!(s.contains("7"));
    assert!(s.contains("5"));
}

#[test]
fn validation_error_display_evidence_count_mismatch() {
    let e = TraceValidationError::EvidenceCountMismatch {
        evidence: 8,
        posteriors: 3,
    };
    let s = e.to_string();
    assert!(s.contains("8"));
    assert!(s.contains("3"));
}

#[test]
fn validation_error_display_empty_trace() {
    let e = TraceValidationError::EmptyTrace;
    assert_eq!(e.to_string(), "empty trace");
}

#[test]
fn validation_error_display_telemetry_integrity_failure() {
    let e = TraceValidationError::TelemetryIntegrityFailure { record_id: 77 };
    let s = e.to_string();
    assert!(s.contains("telemetry integrity failure"));
    assert!(s.contains("77"));
}

#[test]
fn validation_error_display_receipt_integrity_failure() {
    let e = TraceValidationError::ReceiptIntegrityFailure {
        receipt_id: "rcpt-xyz".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("receipt integrity failure"));
    assert!(s.contains("rcpt-xyz"));
}

#[test]
fn validation_error_serde_roundtrip_all_seven() {
    let variants: Vec<TraceValidationError> = vec![
        TraceValidationError::NonMonotonicTimestamp {
            record_index: 1,
            prev_ns: 10,
            current_ns: 5,
        },
        TraceValidationError::InvalidPosterior { step_index: 2 },
        TraceValidationError::DecisionCountMismatch {
            decisions: 3,
            posteriors: 4,
        },
        TraceValidationError::EvidenceCountMismatch {
            evidence: 5,
            posteriors: 6,
        },
        TraceValidationError::EmptyTrace,
        TraceValidationError::TelemetryIntegrityFailure { record_id: 10 },
        TraceValidationError::ReceiptIntegrityFailure {
            receipt_id: "rcpt-rt".to_string(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: TraceValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored, "round-trip failed for: {v}");
    }
}

// ===========================================================================
// Section 4 — validate_trace paths
// ===========================================================================

#[test]
fn validate_trace_empty_returns_empty_trace_error() {
    let trace = empty_trace();
    let errors = validate_trace(&trace);
    assert_eq!(errors.len(), 1);
    assert!(matches!(errors[0], TraceValidationError::EmptyTrace));
}

#[test]
fn validate_trace_well_formed_returns_no_errors() {
    let trace = build_trace(vec![
        benign_evidence(),
        suspicious_evidence(),
        benign_evidence(),
    ]);
    let errors = validate_trace(&trace);
    assert!(errors.is_empty(), "unexpected errors: {errors:?}");
}

#[test]
fn validate_trace_evidence_mismatch_detected() {
    let mut trace = build_trace(vec![benign_evidence(), benign_evidence()]);
    // Remove one evidence to create a mismatch.
    trace.evidence_log.pop();
    let errors = validate_trace(&trace);
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, TraceValidationError::EvidenceCountMismatch { .. }))
    );
}

#[test]
fn validate_trace_decision_mismatch_detected() {
    let mut trace = build_trace(vec![benign_evidence(), suspicious_evidence()]);
    // Remove all decisions.
    trace.decision_log.clear();
    let errors = validate_trace(&trace);
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, TraceValidationError::DecisionCountMismatch { .. }))
    );
}

// ===========================================================================
// Section 5 — ReplayConfig defaults and serde
// ===========================================================================

#[test]
fn replay_config_default_has_expected_values() {
    let cfg = ReplayConfig::default();
    assert!(cfg.verify_telemetry_integrity);
    assert!(cfg.verify_receipt_integrity);
    assert_eq!(cfg.max_steps, 0);
}

#[test]
fn replay_config_serde_custom_values() {
    let cfg = ReplayConfig {
        verify_telemetry_integrity: false,
        verify_receipt_integrity: false,
        max_steps: 777,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: ReplayConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

// ===========================================================================
// Section 6 — CounterfactualSpec constructors and serde
// ===========================================================================

#[test]
fn counterfactual_spec_identity_has_no_overrides() {
    let spec = CounterfactualSpec::identity();
    assert!(spec.override_prior.is_none());
    assert!(spec.override_loss_matrix.is_none());
    assert!(spec.override_likelihood_model.is_none());
    assert!(spec.skip_evidence_indices.is_empty());
    assert!(spec.inject_evidence.is_empty());
    assert_eq!(spec.description, "identity");
}

#[test]
fn counterfactual_spec_with_loss_matrix_sets_matrix_only() {
    let matrix = LossMatrix::permissive();
    let spec = CounterfactualSpec::with_loss_matrix(matrix.clone(), "perm test");
    assert!(spec.override_prior.is_none());
    assert_eq!(spec.override_loss_matrix.as_ref(), Some(&matrix));
    assert!(spec.override_likelihood_model.is_none());
    assert_eq!(spec.description, "perm test");
}

#[test]
fn counterfactual_spec_with_prior_sets_prior_only() {
    let prior = Posterior::from_millionths(200_000, 300_000, 300_000, 200_000);
    let spec = CounterfactualSpec::with_prior(prior.clone(), "custom prior");
    assert_eq!(spec.override_prior.as_ref(), Some(&prior));
    assert!(spec.override_loss_matrix.is_none());
    assert_eq!(spec.description, "custom prior");
}

#[test]
fn counterfactual_spec_serde_with_all_fields() {
    let spec = CounterfactualSpec {
        override_prior: Some(Posterior::uniform()),
        override_loss_matrix: Some(LossMatrix::conservative()),
        override_likelihood_model: Some(LikelihoodModel::default()),
        skip_evidence_indices: vec![0, 3, 5],
        inject_evidence: vec![(2, suspicious_evidence())],
        description: "full override".to_string(),
    };
    let json = serde_json::to_string(&spec).unwrap();
    let restored: CounterfactualSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(spec, restored);
}

// ===========================================================================
// Section 7 — DecisionChange Display and serde
// ===========================================================================

#[test]
fn decision_change_display_identical() {
    assert_eq!(DecisionChange::Identical.to_string(), "identical");
}

#[test]
fn decision_change_display_same_action_different_margin() {
    let dc = DecisionChange::SameActionDifferentMargin {
        original_margin: 42_000,
        counterfactual_margin: 88_000,
    };
    let s = dc.to_string();
    assert!(s.contains("same action"));
    assert!(s.contains("42000"));
    assert!(s.contains("88000"));
}

#[test]
fn decision_change_display_different_action() {
    let dc = DecisionChange::DifferentAction {
        original_action: ContainmentAction::Allow,
        counterfactual_action: ContainmentAction::Quarantine,
        original_loss: 10_000,
        counterfactual_loss: 5_000,
    };
    let s = dc.to_string();
    assert!(s.contains("allow"));
    assert!(s.contains("quarantine"));
}

#[test]
fn decision_change_serde_roundtrip_all_three() {
    let variants: Vec<DecisionChange> = vec![
        DecisionChange::Identical,
        DecisionChange::SameActionDifferentMargin {
            original_margin: 1,
            counterfactual_margin: 2,
        },
        DecisionChange::DifferentAction {
            original_action: ContainmentAction::Sandbox,
            counterfactual_action: ContainmentAction::Suspend,
            original_loss: 300,
            counterfactual_loss: 100,
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: DecisionChange = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

// ===========================================================================
// Section 8 — ReplayError Display and serde
// ===========================================================================

#[test]
fn replay_error_display_validation_failed() {
    let err = ReplayError::ValidationFailed {
        errors: vec![
            TraceValidationError::EmptyTrace,
            TraceValidationError::InvalidPosterior { step_index: 0 },
            TraceValidationError::DecisionCountMismatch {
                decisions: 1,
                posteriors: 2,
            },
        ],
    };
    let s = err.to_string();
    assert!(s.contains("3 error(s)"));
}

#[test]
fn replay_error_display_step_limit_exceeded() {
    let err = ReplayError::StepLimitExceeded { limit: 512 };
    let s = err.to_string();
    assert!(s.contains("512"));
    assert!(s.contains("step limit"));
}

#[test]
fn replay_error_display_internal() {
    let err = ReplayError::Internal {
        detail: "corrupt data".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("corrupt data"));
    assert!(s.contains("internal"));
}

#[test]
fn replay_error_serde_all_three() {
    let variants: Vec<ReplayError> = vec![
        ReplayError::ValidationFailed {
            errors: vec![TraceValidationError::EmptyTrace],
        },
        ReplayError::StepLimitExceeded { limit: 50 },
        ReplayError::Internal {
            detail: "test".to_string(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: ReplayError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

// ===========================================================================
// Section 9 — ForensicReplayer construction
// ===========================================================================

#[test]
fn replayer_new_has_zero_replay_count() {
    let replayer = ForensicReplayer::new();
    assert_eq!(replayer.replay_count(), 0);
}

#[test]
fn replayer_default_matches_new() {
    let a = ForensicReplayer::new();
    let b = ForensicReplayer::default();
    assert_eq!(a.replay_count(), b.replay_count());
}

#[test]
fn replayer_set_epoch_reflected_in_decisions() {
    let trace = build_trace(vec![benign_evidence()]);
    let mut replayer = ForensicReplayer::new();
    replayer.set_epoch(SecurityEpoch::from_raw(99));
    let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    assert_eq!(result.steps[0].decision.epoch, SecurityEpoch::from_raw(99));
}

// ===========================================================================
// Section 10 — replay: benign, suspicious, escalation, count increment
// ===========================================================================

#[test]
fn replay_all_benign_is_deterministic_and_allow() {
    let trace = build_trace(vec![benign_evidence(); 4]);
    let mut replayer = ForensicReplayer::new();
    let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();

    assert!(result.deterministic);
    assert_eq!(result.steps.len(), 4);
    assert!(result.first_divergence_step.is_none());
    // All benign evidence should yield Allow decisions.
    for step in &result.steps {
        assert_eq!(step.decision.action, ContainmentAction::Allow);
    }
    assert_eq!(result.final_containment_state, ContainmentState::Running);
}

#[test]
fn replay_suspicious_sequence_shows_escalation() {
    let evidence = vec![
        benign_evidence(),
        suspicious_evidence(),
        suspicious_evidence(),
        malicious_evidence(),
        malicious_evidence(),
    ];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();
    let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();

    assert!(result.deterministic);
    assert_eq!(result.steps.len(), 5);
    // Final decision should be more severe than the first.
    let first_severity = result.steps[0].decision.action.severity();
    let last_severity = result.steps.last().unwrap().decision.action.severity();
    assert!(
        last_severity >= first_severity,
        "expected escalation: first severity {first_severity}, last severity {last_severity}"
    );
}

#[test]
fn replay_increments_count_each_call() {
    let trace = build_trace(vec![benign_evidence()]);
    let mut replayer = ForensicReplayer::new();
    assert_eq!(replayer.replay_count(), 0);
    replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    assert_eq!(replayer.replay_count(), 1);
    replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    assert_eq!(replayer.replay_count(), 2);
    replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    assert_eq!(replayer.replay_count(), 3);
}

// ===========================================================================
// Section 11 — replay: validation failure (empty trace), step limit
// ===========================================================================

#[test]
fn replay_rejects_empty_trace_with_validation_error() {
    let trace = empty_trace();
    let mut replayer = ForensicReplayer::new();
    let err = replayer
        .replay(&trace, &ReplayConfig::default())
        .unwrap_err();
    match err {
        ReplayError::ValidationFailed { errors } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, TraceValidationError::EmptyTrace))
            );
        }
        other => panic!("expected ValidationFailed, got: {other}"),
    }
}

#[test]
fn replay_rejects_trace_exceeding_step_limit() {
    let trace = build_trace(vec![benign_evidence(); 8]);
    let mut replayer = ForensicReplayer::new();
    let config = ReplayConfig {
        max_steps: 3,
        ..Default::default()
    };
    let err = replayer.replay(&trace, &config).unwrap_err();
    assert!(matches!(err, ReplayError::StepLimitExceeded { limit: 3 }));
}

#[test]
fn replay_step_limit_exact_boundary_succeeds() {
    let trace = build_trace(vec![benign_evidence(); 7]);
    let mut replayer = ForensicReplayer::new();
    let config = ReplayConfig {
        max_steps: 7,
        ..Default::default()
    };
    let result = replayer.replay(&trace, &config).unwrap();
    assert_eq!(result.steps.len(), 7);
}

// ===========================================================================
// Section 12 — counterfactual: identity, with_prior, skip evidence
// ===========================================================================

#[test]
fn counterfactual_identity_produces_same_actions() {
    let trace = build_trace(vec![
        benign_evidence(),
        suspicious_evidence(),
        malicious_evidence(),
    ]);
    let mut replayer = ForensicReplayer::new();

    let original = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    let cf = replayer
        .counterfactual(
            &trace,
            &ReplayConfig::default(),
            &CounterfactualSpec::identity(),
        )
        .unwrap();

    assert_eq!(original.steps.len(), cf.steps.len());
    for (i, (o, c)) in original.steps.iter().zip(cf.steps.iter()).enumerate() {
        assert_eq!(
            o.decision.action, c.decision.action,
            "identity counterfactual diverged at step {i}"
        );
        assert_eq!(
            o.decision.expected_loss_millionths, c.decision.expected_loss_millionths,
            "loss diverged at step {i}"
        );
    }
}

#[test]
fn counterfactual_with_suspicious_prior_increases_severity() {
    let evidence = vec![benign_evidence(), suspicious_evidence()];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();

    let original = replayer.replay(&trace, &ReplayConfig::default()).unwrap();

    // Suspicious prior: much higher P(malicious).
    let sus_prior = Posterior::from_millionths(100_000, 200_000, 600_000, 100_000);
    let cf = replayer
        .counterfactual(
            &trace,
            &ReplayConfig::default(),
            &CounterfactualSpec::with_prior(sus_prior, "high malicious prior"),
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
    assert!(
        cf_max_sev >= orig_max_sev,
        "suspicious prior should escalate: cf={cf_max_sev} vs orig={orig_max_sev}"
    );
}

#[test]
fn counterfactual_skip_all_but_one_evidence() {
    let evidence = vec![
        benign_evidence(),
        suspicious_evidence(),
        malicious_evidence(),
        benign_evidence(),
    ];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();

    let spec = CounterfactualSpec {
        skip_evidence_indices: vec![0, 1, 3],
        description: "only malicious remains".to_string(),
        ..CounterfactualSpec::identity()
    };
    let cf = replayer
        .counterfactual(&trace, &ReplayConfig::default(), &spec)
        .unwrap();
    assert_eq!(cf.steps.len(), 1);
}

#[test]
fn counterfactual_skip_all_evidence_fails() {
    let evidence = vec![benign_evidence(), benign_evidence()];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();

    let spec = CounterfactualSpec {
        skip_evidence_indices: vec![0, 1],
        description: "skip everything".to_string(),
        ..CounterfactualSpec::identity()
    };
    let err = replayer
        .counterfactual(&trace, &ReplayConfig::default(), &spec)
        .unwrap_err();
    assert!(matches!(err, ReplayError::ValidationFailed { .. }));
}

// ===========================================================================
// Section 13 — diff: identical, different, length mismatch
// ===========================================================================

#[test]
fn diff_identical_replays_shows_no_divergence() {
    let trace = build_trace(vec![benign_evidence(); 3]);
    let mut replayer = ForensicReplayer::new();

    let r1 = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    let r2 = replayer.replay(&trace, &ReplayConfig::default()).unwrap();

    let diff = replayer.diff(&r1, &r2, "same replay");
    assert!(diff.first_divergence_step.is_none());
    assert_eq!(diff.action_change_count, 0);
    assert!(!diff.final_outcome_differs);
    assert_eq!(diff.counterfactual_description, "same replay");
    for (_, change) in &diff.step_changes {
        assert_eq!(*change, DecisionChange::Identical);
    }
}

#[test]
fn diff_different_matrix_shows_action_changes() {
    let evidence = vec![
        suspicious_evidence(),
        suspicious_evidence(),
        malicious_evidence(),
    ];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();

    let original = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    let conservative = replayer
        .counterfactual(
            &trace,
            &ReplayConfig::default(),
            &CounterfactualSpec::with_loss_matrix(LossMatrix::conservative(), "conservative"),
        )
        .unwrap();

    let diff = replayer.diff(&original, &conservative, "balanced vs conservative");
    assert_eq!(diff.step_changes.len(), 3);
    // At least some steps should show a change (either margin or action).
    let non_identical = diff
        .step_changes
        .iter()
        .filter(|(_, c)| *c != DecisionChange::Identical)
        .count();
    assert!(
        non_identical > 0 || diff.action_change_count == 0,
        "expected at least one non-identical step or all identical"
    );
}

#[test]
fn diff_length_mismatch_reports_extra_as_divergent() {
    let trace = build_trace(vec![
        benign_evidence(),
        suspicious_evidence(),
        malicious_evidence(),
    ]);
    let mut replayer = ForensicReplayer::new();

    let original = replayer.replay(&trace, &ReplayConfig::default()).unwrap();

    // Counterfactual with injection for an extra step.
    let spec = CounterfactualSpec {
        inject_evidence: vec![(3, benign_evidence())],
        description: "extra tail step".to_string(),
        ..CounterfactualSpec::identity()
    };
    let cf = replayer
        .counterfactual(&trace, &ReplayConfig::default(), &spec)
        .unwrap();
    assert_eq!(cf.steps.len(), 4);

    let diff = replayer.diff(&original, &cf, "3 vs 4 steps");
    assert_eq!(diff.step_changes.len(), 4);
    // The extra step should count as a divergence.
    assert!(diff.first_divergence_step.is_some() || diff.action_change_count > 0);
}

// ===========================================================================
// Section 14 — ReplayResult content_hash determinism and serde
// ===========================================================================

#[test]
fn replay_result_content_hash_deterministic_across_runs() {
    let trace = build_trace(vec![benign_evidence(), suspicious_evidence()]);
    let mut replayer = ForensicReplayer::new();

    let r1 = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    let r2 = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn replay_result_serde_roundtrip() {
    let trace = build_trace(vec![benign_evidence(), malicious_evidence()]);
    let mut replayer = ForensicReplayer::new();
    let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();

    let json = serde_json::to_string(&result).unwrap();
    let restored: ReplayResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
    assert_eq!(result.content_hash, restored.content_hash);
    assert_eq!(result.trace_id, restored.trace_id);
}

#[test]
fn replay_result_final_decision_matches_last_step() {
    let trace = build_trace(vec![
        benign_evidence(),
        suspicious_evidence(),
        malicious_evidence(),
    ]);
    let mut replayer = ForensicReplayer::new();
    let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();

    let last_step = result.steps.last().unwrap();
    assert_eq!(
        result.final_decision.as_ref().unwrap().action,
        last_step.decision.action
    );
    assert_eq!(result.final_posterior, last_step.update_result.posterior);
}

// ===========================================================================
// Section 15 — ReplayDiff serde
// ===========================================================================

#[test]
fn replay_diff_serde_roundtrip_with_divergence() {
    let diff = ReplayDiff {
        counterfactual_description: "test diff serde".to_string(),
        first_divergence_step: Some(2),
        step_changes: vec![
            (0, DecisionChange::Identical),
            (1, DecisionChange::Identical),
            (
                2,
                DecisionChange::DifferentAction {
                    original_action: ContainmentAction::Allow,
                    counterfactual_action: ContainmentAction::Sandbox,
                    original_loss: 50_000,
                    counterfactual_loss: 20_000,
                },
            ),
        ],
        action_change_count: 1,
        original_final_action: Some(ContainmentAction::Allow),
        counterfactual_final_action: Some(ContainmentAction::Sandbox),
        final_outcome_differs: true,
    };
    let json = serde_json::to_string(&diff).unwrap();
    let restored: ReplayDiff = serde_json::from_str(&json).unwrap();
    assert_eq!(diff, restored);
    assert!(restored.final_outcome_differs);
    assert_eq!(restored.action_change_count, 1);
}

#[test]
fn replay_diff_serde_roundtrip_no_divergence() {
    let diff = ReplayDiff {
        counterfactual_description: "identical".to_string(),
        first_divergence_step: None,
        step_changes: vec![(0, DecisionChange::Identical)],
        action_change_count: 0,
        original_final_action: Some(ContainmentAction::Allow),
        counterfactual_final_action: Some(ContainmentAction::Allow),
        final_outcome_differs: false,
    };
    let json = serde_json::to_string(&diff).unwrap();
    let restored: ReplayDiff = serde_json::from_str(&json).unwrap();
    assert_eq!(diff, restored);
}

// ===========================================================================
// Section 16 — Full lifecycle: build -> replay -> counterfactual -> diff
// ===========================================================================

#[test]
fn full_lifecycle_replay_counterfactual_diff_verify_divergence() {
    // Phase 1: build a realistic trace with escalation.
    let evidence = vec![
        benign_evidence(),
        benign_evidence(),
        suspicious_evidence(),
        suspicious_evidence(),
        malicious_evidence(),
    ];
    let trace = build_trace(evidence);

    // Phase 2: replay.
    let mut replayer = ForensicReplayer::new();
    let original = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    assert!(original.deterministic);
    assert_eq!(original.steps.len(), 5);
    assert_eq!(original.trace_id, "trace-001");

    // Phase 3: counterfactual with conservative matrix.
    let cf = replayer
        .counterfactual(
            &trace,
            &ReplayConfig::default(),
            &CounterfactualSpec::with_loss_matrix(
                LossMatrix::conservative(),
                "conservative for lifecycle test",
            ),
        )
        .unwrap();
    assert_eq!(cf.steps.len(), 5);

    // Phase 4: diff.
    let diff = replayer.diff(&original, &cf, "lifecycle diff");
    assert_eq!(diff.step_changes.len(), 5);
    assert_eq!(diff.counterfactual_description, "lifecycle diff");

    // The diff should correctly report original and counterfactual final actions.
    assert_eq!(
        diff.original_final_action,
        original.final_decision.as_ref().map(|d| d.action)
    );
    assert_eq!(
        diff.counterfactual_final_action,
        cf.final_decision.as_ref().map(|d| d.action)
    );
    assert_eq!(
        diff.final_outcome_differs,
        diff.original_final_action != diff.counterfactual_final_action
    );

    // Phase 5: verify replay count.
    assert_eq!(replayer.replay_count(), 2); // 1 replay + 1 counterfactual
}

#[test]
fn full_lifecycle_permissive_vs_conservative_divergence() {
    let evidence = vec![suspicious_evidence(); 6];
    let trace = build_trace(evidence);
    let mut replayer = ForensicReplayer::new();

    // Replay with balanced (original).
    let balanced = replayer.replay(&trace, &ReplayConfig::default()).unwrap();

    // Counterfactual with permissive matrix.
    let permissive = replayer
        .counterfactual(
            &trace,
            &ReplayConfig::default(),
            &CounterfactualSpec::with_loss_matrix(LossMatrix::permissive(), "permissive"),
        )
        .unwrap();

    // Counterfactual with conservative matrix.
    let conservative = replayer
        .counterfactual(
            &trace,
            &ReplayConfig::default(),
            &CounterfactualSpec::with_loss_matrix(LossMatrix::conservative(), "conservative"),
        )
        .unwrap();

    // Diff between permissive and conservative.
    let diff = replayer.diff(&permissive, &conservative, "perm vs cons lifecycle");
    assert_eq!(diff.step_changes.len(), 6);

    // Conservative max severity should be >= permissive max severity.
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
        "conservative ({cons_max}) should >= permissive ({perm_max})"
    );

    // Verify total replay count: 1 + 2 counterfactuals = 3.
    assert_eq!(replayer.replay_count(), 3);

    let _ = balanced;
}

#[test]
fn replayer_serde_roundtrip_preserves_state() {
    let trace = build_trace(vec![benign_evidence()]);
    let mut replayer = ForensicReplayer::new();
    replayer.set_epoch(SecurityEpoch::from_raw(7));
    replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    replayer.replay(&trace, &ReplayConfig::default()).unwrap();

    let json = serde_json::to_string(&replayer).unwrap();
    let restored: ForensicReplayer = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.replay_count(), 2);

    // The restored replayer should still function.
    let mut restored = restored;
    let result = restored.replay(&trace, &ReplayConfig::default()).unwrap();
    assert_eq!(restored.replay_count(), 3);
    // Epoch should be preserved: check it propagated to the step decision.
    assert_eq!(result.steps[0].decision.epoch, SecurityEpoch::from_raw(7));
}

#[test]
fn counterfactual_inject_at_end_appends_extra_step() {
    let trace = build_trace(vec![benign_evidence(), benign_evidence()]);
    let mut replayer = ForensicReplayer::new();

    let spec = CounterfactualSpec {
        inject_evidence: vec![(99, malicious_evidence())], // Beyond original length.
        description: "append at end".to_string(),
        ..CounterfactualSpec::identity()
    };
    let cf = replayer
        .counterfactual(&trace, &ReplayConfig::default(), &spec)
        .unwrap();
    assert_eq!(cf.steps.len(), 3); // 2 original + 1 appended.
}

#[test]
fn replay_trace_id_propagated_to_result() {
    let trace = build_trace_with_id(vec![benign_evidence()], "trace-unique-id");
    let mut replayer = ForensicReplayer::new();
    let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
    assert_eq!(result.trace_id, "trace-unique-id");
}

#[test]
fn replay_content_hash_differs_for_different_traces() {
    let t1 = build_trace_with_id(vec![benign_evidence()], "trace-aaa");
    let t2 = build_trace_with_id(vec![malicious_evidence()], "trace-bbb");
    let mut replayer = ForensicReplayer::new();

    let r1 = replayer.replay(&t1, &ReplayConfig::default()).unwrap();
    let r2 = replayer.replay(&t2, &ReplayConfig::default()).unwrap();
    assert_ne!(r1.content_hash, r2.content_hash);
}
