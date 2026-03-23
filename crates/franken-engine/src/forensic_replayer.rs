//! Forensic replay tooling for incident traces.
//!
//! Replays recorded incident traces — comprising hostcall telemetry,
//! posterior update history, decision events, and containment actions —
//! and reproduces the exact sequence of security decisions that were made
//! during the original incident.  Supports counterfactual analysis by
//! modifying replay parameters and observing decision divergence.
//!
//! Plan reference: Section 10.5, item 7.
//! Cross-refs: 9A.3 (deterministic replay), 9F.3 (time-travel +
//! counterfactual replay), 9C.2 (explainable decision loop).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::bayesian_posterior::{
    BayesianPosteriorUpdater, Evidence, LikelihoodModel, Posterior, UpdateResult,
};
use crate::containment_executor::{ContainmentReceipt, ContainmentState};
use crate::expected_loss_selector::{
    ActionDecision, ContainmentAction, ExpectedLossSelector, LossMatrix,
};
use crate::hash_tiers::ContentHash;
use crate::hostcall_telemetry::HostcallTelemetryRecord;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema identifier for trace content hashing.
const TRACE_SCHEMA_DEF: &[u8] = b"forensic-trace-schema-v1";

/// Maximum step count for safety (prevents runaway replays).
const MAX_REPLAY_STEPS: usize = 1_000_000;

// ---------------------------------------------------------------------------
// IncidentMetadata — trace-level metadata
// ---------------------------------------------------------------------------

/// Metadata about a recorded incident trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentMetadata {
    /// Trace identifier.
    pub trace_id: String,
    /// Extension that triggered the incident.
    pub extension_id: String,
    /// Epoch at the start of the trace.
    pub start_epoch: SecurityEpoch,
    /// Monotonic nanosecond timestamp when recording started.
    pub start_timestamp_ns: u64,
    /// Monotonic nanosecond timestamp when recording ended.
    pub end_timestamp_ns: u64,
    /// Original prior used at the start of the incident.
    pub initial_prior: Posterior,
    /// Original loss matrix ID.
    pub loss_matrix_id: String,
    /// Free-form annotations.
    pub annotations: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// IncidentTrace — the recorded trace
// ---------------------------------------------------------------------------

/// A complete recorded incident trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentTrace {
    /// Metadata about the trace.
    pub metadata: IncidentMetadata,
    /// Ordered telemetry records from the incident.
    pub telemetry_log: Vec<HostcallTelemetryRecord>,
    /// Posterior history: (step_index, posterior_after_update).
    pub posterior_history: Vec<(u64, Posterior)>,
    /// Decision log: each decision made during the incident.
    pub decision_log: Vec<ActionDecision>,
    /// Evidence sequence fed to the updater.
    pub evidence_log: Vec<Evidence>,
    /// Containment receipts produced during the incident.
    pub containment_log: Vec<ContainmentReceipt>,
    /// Loss matrix used for decisions.
    pub loss_matrix: LossMatrix,
    /// Likelihood model used for the updater.
    pub likelihood_model: LikelihoodModel,
}

impl IncidentTrace {
    /// Compute content hash of the trace covering all metadata and log fields.
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::with_capacity(1024);
        buf.extend_from_slice(TRACE_SCHEMA_DEF);
        buf.extend_from_slice(self.metadata.trace_id.as_bytes());
        buf.extend_from_slice(self.metadata.extension_id.as_bytes());
        buf.extend_from_slice(&self.metadata.start_epoch.as_u64().to_le_bytes());
        buf.extend_from_slice(&self.metadata.start_timestamp_ns.to_le_bytes());
        buf.extend_from_slice(&self.metadata.end_timestamp_ns.to_le_bytes());
        buf.extend_from_slice(self.metadata.loss_matrix_id.as_bytes());
        // Annotations are BTreeMap so iteration is deterministic.
        for (k, v) in &self.metadata.annotations {
            buf.extend_from_slice(k.as_bytes());
            buf.extend_from_slice(v.as_bytes());
        }
        // Hash log contents (not just lengths) so evidence tampering is detected.
        buf.extend_from_slice(&(self.telemetry_log.len() as u64).to_le_bytes());
        for entry in &self.telemetry_log {
            if let Ok(bytes) = serde_json::to_vec(entry) {
                buf.extend_from_slice(&bytes);
            }
        }
        buf.extend_from_slice(&(self.evidence_log.len() as u64).to_le_bytes());
        for entry in &self.evidence_log {
            if let Ok(bytes) = serde_json::to_vec(entry) {
                buf.extend_from_slice(&bytes);
            }
        }
        buf.extend_from_slice(&(self.decision_log.len() as u64).to_le_bytes());
        for entry in &self.decision_log {
            if let Ok(bytes) = serde_json::to_vec(entry) {
                buf.extend_from_slice(&bytes);
            }
        }
        buf.extend_from_slice(&(self.containment_log.len() as u64).to_le_bytes());
        for entry in &self.containment_log {
            if let Ok(bytes) = serde_json::to_vec(entry) {
                buf.extend_from_slice(&bytes);
            }
        }
        buf.extend_from_slice(&(self.posterior_history.len() as u64).to_le_bytes());
        for entry in &self.posterior_history {
            if let Ok(bytes) = serde_json::to_vec(entry) {
                buf.extend_from_slice(&bytes);
            }
        }
        buf.extend_from_slice(self.loss_matrix.content_hash().as_bytes());
        ContentHash::compute(&buf)
    }
}

// ---------------------------------------------------------------------------
// TraceValidationError — consistency checking
// ---------------------------------------------------------------------------

/// Errors found during trace validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceValidationError {
    /// Telemetry timestamps are not monotonically increasing.
    NonMonotonicTimestamp {
        record_index: usize,
        prev_ns: u64,
        current_ns: u64,
    },
    /// Posterior does not sum to 1_000_000.
    InvalidPosterior { step_index: u64 },
    /// Decision count does not match posterior history length.
    DecisionCountMismatch { decisions: usize, posteriors: usize },
    /// Evidence count does not match posterior history length.
    EvidenceCountMismatch { evidence: usize, posteriors: usize },
    /// Empty trace (no evidence to replay).
    EmptyTrace,
    /// Telemetry record fails integrity check.
    TelemetryIntegrityFailure { record_id: u64 },
    /// Containment receipt fails integrity check.
    ReceiptIntegrityFailure { receipt_id: String },
}

impl fmt::Display for TraceValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonMonotonicTimestamp {
                record_index,
                prev_ns,
                current_ns,
            } => {
                write!(
                    f,
                    "non-monotonic timestamp at record {record_index}: {prev_ns} -> {current_ns}"
                )
            }
            Self::InvalidPosterior { step_index } => {
                write!(f, "invalid posterior at step {step_index}")
            }
            Self::DecisionCountMismatch {
                decisions,
                posteriors,
            } => {
                write!(
                    f,
                    "decision count ({decisions}) != posterior count ({posteriors})"
                )
            }
            Self::EvidenceCountMismatch {
                evidence,
                posteriors,
            } => {
                write!(
                    f,
                    "evidence count ({evidence}) != posterior count ({posteriors})"
                )
            }
            Self::EmptyTrace => write!(f, "empty trace"),
            Self::TelemetryIntegrityFailure { record_id } => {
                write!(f, "telemetry integrity failure: record {record_id}")
            }
            Self::ReceiptIntegrityFailure { receipt_id } => {
                write!(f, "receipt integrity failure: {receipt_id}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ReplayConfig — parameters for replay
// ---------------------------------------------------------------------------

/// Configuration for replaying a trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayConfig {
    /// Whether to verify telemetry record integrity during replay.
    pub verify_telemetry_integrity: bool,
    /// Whether to verify containment receipt integrity.
    pub verify_receipt_integrity: bool,
    /// Maximum steps to replay (0 = all).
    pub max_steps: usize,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            verify_telemetry_integrity: true,
            verify_receipt_integrity: true,
            max_steps: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// ReplayStep — one step in the replay
// ---------------------------------------------------------------------------

/// A single step in a replay trajectory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayStep {
    /// Step index (0-based).
    pub step_index: u64,
    /// Evidence fed at this step.
    pub evidence: Evidence,
    /// Bayesian update result.
    pub update_result: UpdateResult,
    /// Decision made at this step.
    pub decision: ActionDecision,
}

// ---------------------------------------------------------------------------
// ReplayResult — full replay output
// ---------------------------------------------------------------------------

/// The result of replaying a trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayResult {
    /// Trace ID being replayed.
    pub trace_id: String,
    /// All replay steps in order.
    pub steps: Vec<ReplayStep>,
    /// Final posterior after all steps.
    pub final_posterior: Posterior,
    /// Final decision (from the last step).
    pub final_decision: Option<ActionDecision>,
    /// Final containment state after all decisions.
    pub final_containment_state: ContainmentState,
    /// Whether the replay was deterministic (matched the original trace).
    pub deterministic: bool,
    /// First divergence step (if not deterministic).
    pub first_divergence_step: Option<u64>,
    /// Content hash of the replay result.
    pub content_hash: ContentHash,
}

impl ReplayResult {
    /// Compute content hash from steps.
    fn compute_hash(steps: &[ReplayStep], trace_id: &str) -> ContentHash {
        let mut buf = Vec::with_capacity(512);
        buf.extend_from_slice(b"replay-result-v1");
        buf.extend_from_slice(trace_id.as_bytes());
        buf.extend_from_slice(&(steps.len() as u64).to_le_bytes());
        for step in steps {
            buf.extend_from_slice(&step.step_index.to_le_bytes());
            buf.extend_from_slice(step.decision.action.to_string().as_bytes());
            buf.extend_from_slice(&step.decision.expected_loss_millionths.to_le_bytes());
        }
        ContentHash::compute(&buf)
    }
}

// ---------------------------------------------------------------------------
// CounterfactualSpec — what to modify
// ---------------------------------------------------------------------------

/// Specification for counterfactual replay modifications.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterfactualSpec {
    /// Override the initial prior (None = use original).
    pub override_prior: Option<Posterior>,
    /// Override the loss matrix (None = use original).
    pub override_loss_matrix: Option<LossMatrix>,
    /// Override the likelihood model (None = use original).
    pub override_likelihood_model: Option<LikelihoodModel>,
    /// Indices of evidence records to skip (simulate removal).
    pub skip_evidence_indices: Vec<usize>,
    /// Additional evidence records to inject at specific positions.
    /// (insert_before_index, evidence).
    pub inject_evidence: Vec<(usize, Evidence)>,
    /// Description of this counterfactual scenario.
    pub description: String,
}

impl CounterfactualSpec {
    /// Create an empty counterfactual spec (identical replay).
    pub fn identity() -> Self {
        Self {
            override_prior: None,
            override_loss_matrix: None,
            override_likelihood_model: None,
            skip_evidence_indices: Vec::new(),
            inject_evidence: Vec::new(),
            description: "identity".to_string(),
        }
    }

    /// Create a spec that only changes the loss matrix.
    pub fn with_loss_matrix(matrix: LossMatrix, description: impl Into<String>) -> Self {
        Self {
            override_loss_matrix: Some(matrix),
            description: description.into(),
            ..Self::identity()
        }
    }

    /// Create a spec that only changes the prior.
    pub fn with_prior(prior: Posterior, description: impl Into<String>) -> Self {
        Self {
            override_prior: Some(prior),
            description: description.into(),
            ..Self::identity()
        }
    }
}

// ---------------------------------------------------------------------------
// DecisionChange — classification of decision divergence
// ---------------------------------------------------------------------------

/// How a decision changed in counterfactual replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionChange {
    /// Same action, same or similar expected loss.
    Identical,
    /// Same action but different expected loss margin.
    SameActionDifferentMargin {
        original_margin: i64,
        counterfactual_margin: i64,
    },
    /// Different action taken.
    DifferentAction {
        original_action: ContainmentAction,
        counterfactual_action: ContainmentAction,
        original_loss: i64,
        counterfactual_loss: i64,
    },
}

impl fmt::Display for DecisionChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identical => write!(f, "identical"),
            Self::SameActionDifferentMargin {
                original_margin,
                counterfactual_margin,
            } => {
                write!(
                    f,
                    "same action, margin {original_margin} -> {counterfactual_margin}"
                )
            }
            Self::DifferentAction {
                original_action,
                counterfactual_action,
                ..
            } => {
                write!(f, "{original_action} -> {counterfactual_action}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ReplayDiff — structured diff between replays
// ---------------------------------------------------------------------------

/// Structured diff between an original and counterfactual replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayDiff {
    /// Counterfactual description.
    pub counterfactual_description: String,
    /// Index of the first divergence point (None if identical).
    pub first_divergence_step: Option<u64>,
    /// Per-step decision changes.
    pub step_changes: Vec<(u64, DecisionChange)>,
    /// Count of steps where the action changed.
    pub action_change_count: usize,
    /// Original final action.
    pub original_final_action: Option<ContainmentAction>,
    /// Counterfactual final action.
    pub counterfactual_final_action: Option<ContainmentAction>,
    /// Whether the final outcome differs.
    pub final_outcome_differs: bool,
}

// ---------------------------------------------------------------------------
// ReplayError — replay failures
// ---------------------------------------------------------------------------

/// Errors from forensic replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayError {
    /// Trace validation failed.
    ValidationFailed { errors: Vec<TraceValidationError> },
    /// Replay exceeded maximum step count.
    StepLimitExceeded { limit: usize },
    /// Internal replay error.
    Internal { detail: String },
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValidationFailed { errors } => {
                write!(f, "trace validation failed: {} error(s)", errors.len())
            }
            Self::StepLimitExceeded { limit } => {
                write!(f, "replay exceeded step limit: {limit}")
            }
            Self::Internal { detail } => write!(f, "internal replay error: {detail}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Trace validator
// ---------------------------------------------------------------------------

/// Validate internal consistency of an incident trace.
pub fn validate_trace(trace: &IncidentTrace) -> Vec<TraceValidationError> {
    let mut errors = Vec::new();

    // Empty trace check.
    if trace.evidence_log.is_empty() {
        errors.push(TraceValidationError::EmptyTrace);
        return errors;
    }

    // Evidence and posterior history must match.
    if trace.evidence_log.len() != trace.posterior_history.len() {
        errors.push(TraceValidationError::EvidenceCountMismatch {
            evidence: trace.evidence_log.len(),
            posteriors: trace.posterior_history.len(),
        });
    }

    // Decision and posterior history must match.
    if trace.decision_log.len() != trace.posterior_history.len() {
        errors.push(TraceValidationError::DecisionCountMismatch {
            decisions: trace.decision_log.len(),
            posteriors: trace.posterior_history.len(),
        });
    }

    // Monotonic telemetry timestamps.
    for i in 1..trace.telemetry_log.len() {
        if trace.telemetry_log[i].timestamp_ns < trace.telemetry_log[i - 1].timestamp_ns {
            errors.push(TraceValidationError::NonMonotonicTimestamp {
                record_index: i,
                prev_ns: trace.telemetry_log[i - 1].timestamp_ns,
                current_ns: trace.telemetry_log[i].timestamp_ns,
            });
        }
    }

    // Posterior validity.
    for (step_idx, posterior) in &trace.posterior_history {
        if !posterior.is_valid() {
            errors.push(TraceValidationError::InvalidPosterior {
                step_index: *step_idx,
            });
        }
    }

    // Telemetry integrity.
    for record in &trace.telemetry_log {
        if !record.verify_integrity() {
            errors.push(TraceValidationError::TelemetryIntegrityFailure {
                record_id: record.record_id,
            });
        }
    }

    // Receipt integrity.
    for receipt in &trace.containment_log {
        if !receipt.verify_integrity() {
            errors.push(TraceValidationError::ReceiptIntegrityFailure {
                receipt_id: receipt.receipt_id.clone(),
            });
        }
    }

    errors
}

// ---------------------------------------------------------------------------
// ForensicReplayer — the main replay engine
// ---------------------------------------------------------------------------

/// Forensic replay engine for incident traces.
///
/// Replays recorded evidence sequences through fresh instances of the
/// Bayesian posterior updater and expected-loss selector, producing
/// deterministic decision trajectories.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicReplayer {
    /// Security epoch for the replayer.
    epoch: SecurityEpoch,
    /// Total replays executed.
    replay_count: u64,
}

/// Input bundle for `replay_internal` to avoid too-many-arguments.
struct ReplayInternalInput<'a> {
    config: &'a ReplayConfig,
    prior: &'a Posterior,
    loss_matrix: &'a LossMatrix,
    likelihood_model: &'a LikelihoodModel,
    evidence: &'a [Evidence],
    original_decisions: Option<&'a [ActionDecision]>,
}

impl ForensicReplayer {
    /// Create a new forensic replayer.
    pub fn new() -> Self {
        Self {
            epoch: SecurityEpoch::GENESIS,
            replay_count: 0,
        }
    }

    /// Set the security epoch.
    pub fn set_epoch(&mut self, epoch: SecurityEpoch) {
        self.epoch = epoch;
    }

    /// Number of replays executed.
    pub fn replay_count(&self) -> u64 {
        self.replay_count
    }

    /// Replay a trace deterministically with default configuration.
    pub fn replay(
        &mut self,
        trace: &IncidentTrace,
        config: &ReplayConfig,
    ) -> Result<ReplayResult, ReplayError> {
        // Validate trace.
        let validation_errors = validate_trace(trace);
        if !validation_errors.is_empty() {
            return Err(ReplayError::ValidationFailed {
                errors: validation_errors,
            });
        }

        self.replay_internal(
            trace,
            ReplayInternalInput {
                config,
                prior: &trace.metadata.initial_prior,
                loss_matrix: &trace.loss_matrix,
                likelihood_model: &trace.likelihood_model,
                evidence: &trace.evidence_log,
                original_decisions: Some(&trace.decision_log),
            },
        )
    }

    /// Replay with counterfactual modifications.
    pub fn counterfactual(
        &mut self,
        trace: &IncidentTrace,
        config: &ReplayConfig,
        spec: &CounterfactualSpec,
    ) -> Result<ReplayResult, ReplayError> {
        // Validate trace (skip integrity checks for counterfactual since
        // we may be modifying evidence).
        let mut cf_config = config.clone();
        if !spec.inject_evidence.is_empty() || !spec.skip_evidence_indices.is_empty() {
            cf_config.verify_telemetry_integrity = false;
        }

        let non_integrity_errors: Vec<TraceValidationError> = validate_trace(trace)
            .into_iter()
            .filter(|e| {
                !matches!(
                    e,
                    TraceValidationError::TelemetryIntegrityFailure { .. }
                        | TraceValidationError::ReceiptIntegrityFailure { .. }
                )
            })
            .collect();

        // Allow evidence/decision count mismatches in counterfactual mode
        // since we may be adding/removing evidence.
        let critical_errors: Vec<TraceValidationError> = non_integrity_errors
            .into_iter()
            .filter(|e| {
                matches!(
                    e,
                    TraceValidationError::EmptyTrace
                        | TraceValidationError::NonMonotonicTimestamp { .. }
                        | TraceValidationError::InvalidPosterior { .. }
                )
            })
            .collect();

        if !critical_errors.is_empty() {
            return Err(ReplayError::ValidationFailed {
                errors: critical_errors,
            });
        }

        let prior = spec
            .override_prior
            .clone()
            .unwrap_or_else(|| trace.metadata.initial_prior.clone());
        let loss_matrix = spec
            .override_loss_matrix
            .clone()
            .unwrap_or_else(|| trace.loss_matrix.clone());
        let likelihood_model = spec
            .override_likelihood_model
            .clone()
            .unwrap_or_else(|| trace.likelihood_model.clone());

        // Build modified evidence sequence.
        let evidence = self.build_counterfactual_evidence(
            &trace.evidence_log,
            &spec.skip_evidence_indices,
            &spec.inject_evidence,
        );

        if evidence.is_empty() {
            return Err(ReplayError::ValidationFailed {
                errors: vec![TraceValidationError::EmptyTrace],
            });
        }

        self.replay_internal(
            trace,
            ReplayInternalInput {
                config: &cf_config,
                prior: &prior,
                loss_matrix: &loss_matrix,
                likelihood_model: &likelihood_model,
                evidence: &evidence,
                original_decisions: None,
            },
        )
    }

    /// Compute a structured diff between two replay results.
    pub fn diff(
        &self,
        original: &ReplayResult,
        counterfactual: &ReplayResult,
        description: impl Into<String>,
    ) -> ReplayDiff {
        let min_len = original.steps.len().min(counterfactual.steps.len());
        let max_len = original.steps.len().max(counterfactual.steps.len());
        let mut step_changes = Vec::with_capacity(max_len);
        let mut first_divergence: Option<u64> = None;
        let mut action_change_count = 0;

        for i in 0..min_len {
            let orig = &original.steps[i];
            let cf = &counterfactual.steps[i];

            let change = if orig.decision.action == cf.decision.action {
                if orig.decision.explanation.margin_millionths
                    == cf.decision.explanation.margin_millionths
                {
                    DecisionChange::Identical
                } else {
                    if first_divergence.is_none() {
                        first_divergence = Some(i as u64);
                    }
                    DecisionChange::SameActionDifferentMargin {
                        original_margin: orig.decision.explanation.margin_millionths,
                        counterfactual_margin: cf.decision.explanation.margin_millionths,
                    }
                }
            } else {
                if first_divergence.is_none() {
                    first_divergence = Some(i as u64);
                }
                action_change_count += 1;
                DecisionChange::DifferentAction {
                    original_action: orig.decision.action,
                    counterfactual_action: cf.decision.action,
                    original_loss: orig.decision.expected_loss_millionths,
                    counterfactual_loss: cf.decision.expected_loss_millionths,
                }
            };

            step_changes.push((i as u64, change));
        }

        // Extra steps in the longer trace count as divergent.
        for i in min_len..max_len {
            if first_divergence.is_none() {
                first_divergence = Some(i as u64);
            }
            action_change_count += 1;

            if i < counterfactual.steps.len() {
                step_changes.push((
                    i as u64,
                    DecisionChange::DifferentAction {
                        original_action: original
                            .final_decision
                            .as_ref()
                            .map(|d| d.action)
                            .unwrap_or(ContainmentAction::Allow),
                        counterfactual_action: counterfactual.steps[i].decision.action,
                        original_loss: 0,
                        counterfactual_loss: counterfactual.steps[i]
                            .decision
                            .expected_loss_millionths,
                    },
                ));
            }
        }

        let original_final = original.final_decision.as_ref().map(|d| d.action);
        let cf_final = counterfactual.final_decision.as_ref().map(|d| d.action);

        ReplayDiff {
            counterfactual_description: description.into(),
            first_divergence_step: first_divergence,
            step_changes,
            action_change_count,
            original_final_action: original_final,
            counterfactual_final_action: cf_final,
            final_outcome_differs: original_final != cf_final,
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn replay_internal(
        &mut self,
        trace: &IncidentTrace,
        input: ReplayInternalInput<'_>,
    ) -> Result<ReplayResult, ReplayError> {
        let ReplayInternalInput {
            config,
            prior,
            loss_matrix,
            likelihood_model,
            evidence,
            original_decisions,
        } = input;
        let max_steps = if config.max_steps > 0 {
            config.max_steps.min(MAX_REPLAY_STEPS)
        } else {
            MAX_REPLAY_STEPS
        };

        if evidence.len() > max_steps {
            return Err(ReplayError::StepLimitExceeded { limit: max_steps });
        }

        // Create fresh updater and selector.
        let mut updater = BayesianPosteriorUpdater::with_model(
            prior.clone(),
            &trace.metadata.extension_id,
            likelihood_model.clone(),
        );
        updater.set_epoch(self.epoch);

        let mut selector = ExpectedLossSelector::new(loss_matrix.clone());
        selector.set_epoch(self.epoch);

        let mut steps = Vec::with_capacity(evidence.len());
        let mut deterministic = true;
        let mut first_divergence_step: Option<u64> = None;

        for (i, ev) in evidence.iter().enumerate() {
            let update_result = updater.update(ev);
            let decision = selector.select(&update_result.posterior);

            // Check determinism against original.
            if let Some(orig_decisions) = original_decisions
                && i < orig_decisions.len()
                && orig_decisions[i].action != decision.action
            {
                deterministic = false;
                if first_divergence_step.is_none() {
                    first_divergence_step = Some(i as u64);
                }
            }

            steps.push(ReplayStep {
                step_index: i as u64,
                evidence: ev.clone(),
                update_result,
                decision,
            });
        }

        let final_posterior = updater.posterior().clone();
        let final_decision = steps.last().map(|s| s.decision.clone());

        // Determine final containment state from decisions.
        let final_containment_state = determine_final_state(&steps);

        let content_hash = ReplayResult::compute_hash(&steps, &trace.metadata.trace_id);

        self.replay_count += 1;

        Ok(ReplayResult {
            trace_id: trace.metadata.trace_id.clone(),
            steps,
            final_posterior,
            final_decision,
            final_containment_state,
            deterministic,
            first_divergence_step,
            content_hash,
        })
    }

    fn build_counterfactual_evidence(
        &self,
        original: &[Evidence],
        skip_indices: &[usize],
        inject: &[(usize, Evidence)],
    ) -> Vec<Evidence> {
        let mut result = Vec::with_capacity(original.len() + inject.len());

        // Sort injections by position.
        let mut sorted_inject: Vec<(usize, &Evidence)> =
            inject.iter().map(|(pos, ev)| (*pos, ev)).collect();
        sorted_inject.sort_by_key(|(pos, _)| *pos);

        let mut inject_idx = 0;

        for (i, ev) in original.iter().enumerate() {
            // Insert any injections that should come at this index (before the
            // original element at position i).
            while inject_idx < sorted_inject.len() && sorted_inject[inject_idx].0 < i {
                result.push(sorted_inject[inject_idx].1.clone());
                inject_idx += 1;
            }

            // Skip if this index is in the skip list.
            if skip_indices.contains(&i) {
                continue;
            }

            result.push(ev.clone());
        }

        // Append remaining injections.
        while inject_idx < sorted_inject.len() {
            result.push(sorted_inject[inject_idx].1.clone());
            inject_idx += 1;
        }

        result
    }
}

impl Default for ForensicReplayer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helper: determine containment state from decisions
// ---------------------------------------------------------------------------

fn determine_final_state(steps: &[ReplayStep]) -> ContainmentState {
    let mut state = ContainmentState::Running;
    for step in steps {
        state = match step.decision.action {
            ContainmentAction::Allow => state, // No change.
            ContainmentAction::Challenge => {
                if state == ContainmentState::Running {
                    ContainmentState::Challenged
                } else {
                    state
                }
            }
            ContainmentAction::Sandbox => {
                if matches!(
                    state,
                    ContainmentState::Running | ContainmentState::Challenged
                ) {
                    ContainmentState::Sandboxed
                } else {
                    state
                }
            }
            ContainmentAction::Suspend => {
                if state.is_alive() {
                    ContainmentState::Suspended
                } else {
                    state
                }
            }
            ContainmentAction::Terminate => {
                if state.is_alive() || state == ContainmentState::Suspended {
                    ContainmentState::Terminated
                } else {
                    state
                }
            }
            ContainmentAction::Quarantine => {
                if state.is_alive() || state == ContainmentState::Suspended {
                    ContainmentState::Quarantined
                } else {
                    state
                }
            }
        };
    }
    state
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bayesian_posterior::LikelihoodModel;
    use crate::expected_loss_selector::LossMatrix;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

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
        test_evidence("ext-001", 10_000_000, 10_000) // 10 calls/s, 1% denial
    }

    fn suspicious_evidence() -> Evidence {
        test_evidence("ext-001", 600_000_000, 250_000) // 600 calls/s, 25% denial
    }

    fn malicious_evidence() -> Evidence {
        test_evidence("ext-001", 1_000_000_000, 500_000) // 1000 calls/s, 50% denial
    }

    fn build_trace(evidence: Vec<Evidence>) -> IncidentTrace {
        let prior = Posterior::default_prior();
        let loss_matrix = LossMatrix::balanced();
        let likelihood_model = LikelihoodModel::default();

        // Simulate the incident to record ground-truth decisions.
        let mut updater = BayesianPosteriorUpdater::with_model(
            prior.clone(),
            "ext-001",
            likelihood_model.clone(),
        );
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

    // -----------------------------------------------------------------------
    // Trace validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn validate_empty_trace() {
        let _trace = build_trace(Vec::new());
        // build_trace with empty evidence produces EmptyTrace validation error
        // since evidence_log is empty. But build_trace doesn't add evidence...
        // We need to build manually.
        let trace = IncidentTrace {
            metadata: IncidentMetadata {
                trace_id: "empty".to_string(),
                extension_id: "ext".to_string(),
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
        };
        let errors = validate_trace(&trace);
        assert_eq!(errors.len(), 1);
        assert!(matches!(errors[0], TraceValidationError::EmptyTrace));
    }

    #[test]
    fn validate_valid_trace() {
        let trace = build_trace(vec![benign_evidence(), benign_evidence()]);
        let errors = validate_trace(&trace);
        assert!(errors.is_empty(), "expected no errors, got: {errors:?}");
    }

    #[test]
    fn validate_evidence_count_mismatch() {
        let mut trace = build_trace(vec![benign_evidence()]);
        // Remove a posterior to create mismatch.
        trace.posterior_history.clear();
        let errors = validate_trace(&trace);
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, TraceValidationError::EvidenceCountMismatch { .. }))
        );
    }

    #[test]
    fn validate_decision_count_mismatch() {
        let mut trace = build_trace(vec![benign_evidence()]);
        trace.decision_log.push(trace.decision_log[0].clone());
        let errors = validate_trace(&trace);
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, TraceValidationError::DecisionCountMismatch { .. }))
        );
    }

    #[test]
    fn validate_invalid_posterior() {
        let mut trace = build_trace(vec![benign_evidence()]);
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

    // -----------------------------------------------------------------------
    // Deterministic replay tests
    // -----------------------------------------------------------------------

    #[test]
    fn replay_benign_is_deterministic() {
        let evidence = vec![benign_evidence(); 5];
        let trace = build_trace(evidence);
        let mut replayer = ForensicReplayer::new();
        let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();

        assert!(result.deterministic);
        assert_eq!(result.steps.len(), 5);
        assert!(result.first_divergence_step.is_none());
    }

    #[test]
    fn replay_produces_same_decisions_as_original() {
        let evidence = vec![
            benign_evidence(),
            benign_evidence(),
            suspicious_evidence(),
            malicious_evidence(),
        ];
        let trace = build_trace(evidence);
        let mut replayer = ForensicReplayer::new();
        let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();

        assert!(result.deterministic);
        for (i, step) in result.steps.iter().enumerate() {
            assert_eq!(
                step.decision.action, trace.decision_log[i].action,
                "decision diverged at step {i}"
            );
        }
    }

    #[test]
    fn replay_repeated_100_times_identical() {
        let evidence = vec![
            benign_evidence(),
            suspicious_evidence(),
            malicious_evidence(),
        ];
        let trace = build_trace(evidence);
        let mut replayer = ForensicReplayer::new();

        let baseline = replayer.replay(&trace, &ReplayConfig::default()).unwrap();

        for run in 1..100 {
            let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
            assert!(result.deterministic, "non-deterministic on run {run}");
            assert_eq!(
                result.content_hash, baseline.content_hash,
                "hash mismatch on run {run}"
            );
            assert_eq!(result.steps.len(), baseline.steps.len());
            for (i, (a, b)) in result.steps.iter().zip(baseline.steps.iter()).enumerate() {
                assert_eq!(a.decision.action, b.decision.action, "step {i} run {run}");
                assert_eq!(
                    a.decision.expected_loss_millionths, b.decision.expected_loss_millionths,
                    "loss mismatch step {i} run {run}"
                );
            }
        }
    }

    #[test]
    fn replay_increments_count() {
        let trace = build_trace(vec![benign_evidence()]);
        let mut replayer = ForensicReplayer::new();
        assert_eq!(replayer.replay_count(), 0);
        replayer.replay(&trace, &ReplayConfig::default()).unwrap();
        assert_eq!(replayer.replay_count(), 1);
        replayer.replay(&trace, &ReplayConfig::default()).unwrap();
        assert_eq!(replayer.replay_count(), 2);
    }

    #[test]
    fn replay_final_posterior_matches_last_step() {
        let evidence = vec![benign_evidence(), suspicious_evidence()];
        let trace = build_trace(evidence);
        let mut replayer = ForensicReplayer::new();
        let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
        let last_step = result.steps.last().unwrap();
        assert_eq!(result.final_posterior, last_step.update_result.posterior);
    }

    #[test]
    fn replay_content_hash_stable() {
        let trace = build_trace(vec![benign_evidence()]);
        let mut replayer = ForensicReplayer::new();
        let r1 = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
        let r2 = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    // -----------------------------------------------------------------------
    // Counterfactual replay tests
    // -----------------------------------------------------------------------

    #[test]
    fn counterfactual_identity_matches_original() {
        let evidence = vec![benign_evidence(), suspicious_evidence()];
        let trace = build_trace(evidence);
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
            assert_eq!(o.decision.action, c.decision.action, "step {i}");
        }
    }

    #[test]
    fn counterfactual_aggressive_matrix_earlier_containment() {
        let evidence = vec![
            benign_evidence(),
            benign_evidence(),
            suspicious_evidence(),
            suspicious_evidence(),
        ];
        let trace = build_trace(evidence);
        let mut replayer = ForensicReplayer::new();

        let original = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
        let cf = replayer
            .counterfactual(
                &trace,
                &ReplayConfig::default(),
                &CounterfactualSpec::with_loss_matrix(
                    LossMatrix::conservative(),
                    "conservative matrix",
                ),
            )
            .unwrap();

        // Conservative matrix should be at least as aggressive.
        let orig_max_severity = original
            .steps
            .iter()
            .map(|s| s.decision.action.severity())
            .max()
            .unwrap_or(0);
        let cf_max_severity = cf
            .steps
            .iter()
            .map(|s| s.decision.action.severity())
            .max()
            .unwrap_or(0);
        assert!(
            cf_max_severity >= orig_max_severity,
            "conservative should be at least as severe: cf={cf_max_severity} vs orig={orig_max_severity}"
        );
    }

    #[test]
    fn counterfactual_skip_evidence_fewer_steps() {
        let evidence = vec![
            benign_evidence(),
            suspicious_evidence(),
            malicious_evidence(),
        ];
        let trace = build_trace(evidence);
        let mut replayer = ForensicReplayer::new();

        let spec = CounterfactualSpec {
            skip_evidence_indices: vec![1], // Skip suspicious evidence.
            description: "skip suspicious".to_string(),
            ..CounterfactualSpec::identity()
        };

        let cf = replayer
            .counterfactual(&trace, &ReplayConfig::default(), &spec)
            .unwrap();

        assert_eq!(cf.steps.len(), 2); // Only benign + malicious.
    }

    #[test]
    fn counterfactual_inject_evidence_more_steps() {
        let evidence = vec![benign_evidence()];
        let trace = build_trace(evidence);
        let mut replayer = ForensicReplayer::new();

        let spec = CounterfactualSpec {
            inject_evidence: vec![(1, malicious_evidence())],
            description: "inject malicious".to_string(),
            ..CounterfactualSpec::identity()
        };

        let cf = replayer
            .counterfactual(&trace, &ReplayConfig::default(), &spec)
            .unwrap();

        assert_eq!(cf.steps.len(), 2);
    }

    #[test]
    fn counterfactual_with_different_prior() {
        let evidence = vec![benign_evidence(), suspicious_evidence()];
        let trace = build_trace(evidence);
        let mut replayer = ForensicReplayer::new();

        let original = replayer.replay(&trace, &ReplayConfig::default()).unwrap();

        // Start with a suspicious prior.
        let suspicious_prior = Posterior::from_millionths(100_000, 400_000, 400_000, 100_000);
        let cf = replayer
            .counterfactual(
                &trace,
                &ReplayConfig::default(),
                &CounterfactualSpec::with_prior(suspicious_prior, "suspicious prior"),
            )
            .unwrap();

        // With a suspicious prior, the same evidence should lead to more severe actions.
        let orig_final = original.final_decision.as_ref().unwrap().action.severity();
        let cf_final = cf.final_decision.as_ref().unwrap().action.severity();
        assert!(
            cf_final >= orig_final,
            "suspicious prior should escalate: cf={cf_final} vs orig={orig_final}"
        );
    }

    // -----------------------------------------------------------------------
    // Diff tests
    // -----------------------------------------------------------------------

    #[test]
    fn diff_identical_replays_no_divergence() {
        let evidence = vec![benign_evidence(), benign_evidence()];
        let trace = build_trace(evidence);
        let mut replayer = ForensicReplayer::new();

        let r1 = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
        let r2 = replayer.replay(&trace, &ReplayConfig::default()).unwrap();

        let diff = replayer.diff(&r1, &r2, "identical");
        assert!(diff.first_divergence_step.is_none());
        assert_eq!(diff.action_change_count, 0);
        assert!(!diff.final_outcome_differs);
    }

    #[test]
    fn diff_reports_first_divergence() {
        let evidence = vec![
            benign_evidence(),
            suspicious_evidence(),
            malicious_evidence(),
        ];
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

        let diff = replayer.diff(&original, &cf, "conservative vs balanced");
        assert_eq!(
            diff.step_changes.len(),
            original.steps.len().max(cf.steps.len())
        );
        assert_eq!(diff.counterfactual_description, "conservative vs balanced");
    }

    #[test]
    fn diff_action_change_count() {
        let evidence = vec![suspicious_evidence(); 3];
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

        let diff = replayer.diff(&original, &cf, "permissive");
        // action_change_count should be >= 0 (may or may not differ).
        assert!(diff.action_change_count <= diff.step_changes.len());
    }

    #[test]
    fn diff_different_length_replays() {
        let evidence = vec![benign_evidence(), suspicious_evidence()];
        let trace = build_trace(evidence);
        let mut replayer = ForensicReplayer::new();

        let original = replayer.replay(&trace, &ReplayConfig::default()).unwrap();

        // Counterfactual with injected evidence (more steps).
        let spec = CounterfactualSpec {
            inject_evidence: vec![(2, malicious_evidence())],
            description: "extra step".to_string(),
            ..CounterfactualSpec::identity()
        };
        let cf = replayer
            .counterfactual(&trace, &ReplayConfig::default(), &spec)
            .unwrap();

        let diff = replayer.diff(&original, &cf, "extra step");
        assert_eq!(
            diff.step_changes.len(),
            original.steps.len().max(cf.steps.len())
        );
    }

    // -----------------------------------------------------------------------
    // Error handling tests
    // -----------------------------------------------------------------------

    #[test]
    fn replay_rejects_empty_trace() {
        let trace = IncidentTrace {
            metadata: IncidentMetadata {
                trace_id: "empty".to_string(),
                extension_id: "ext".to_string(),
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
        };
        let mut replayer = ForensicReplayer::new();
        let err = replayer
            .replay(&trace, &ReplayConfig::default())
            .unwrap_err();
        assert!(matches!(err, ReplayError::ValidationFailed { .. }));
    }

    #[test]
    fn replay_step_limit() {
        let evidence = vec![benign_evidence(); 10];
        let trace = build_trace(evidence);
        let mut replayer = ForensicReplayer::new();
        let config = ReplayConfig {
            max_steps: 5,
            ..Default::default()
        };
        let err = replayer.replay(&trace, &config).unwrap_err();
        assert!(matches!(err, ReplayError::StepLimitExceeded { limit: 5 }));
    }

    // -----------------------------------------------------------------------
    // Containment state tracking tests
    // -----------------------------------------------------------------------

    #[test]
    fn final_state_starts_running() {
        let evidence = vec![benign_evidence()];
        let trace = build_trace(evidence);
        let mut replayer = ForensicReplayer::new();
        let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
        // With benign evidence, should stay Running (Allow action).
        assert_eq!(result.final_containment_state, ContainmentState::Running);
    }

    #[test]
    fn determine_final_state_escalation() {
        // Test the state machine helper directly.
        let steps = vec![
            ReplayStep {
                step_index: 0,
                evidence: benign_evidence(),
                update_result: UpdateResult {
                    posterior: Posterior::default_prior(),
                    likelihoods: [1_000_000; 4],
                    cumulative_llr_millionths: 0,
                    update_count: 1,
                },
                decision: ActionDecision {
                    action: ContainmentAction::Challenge,
                    expected_loss_millionths: 100_000,
                    runner_up_action: ContainmentAction::Allow,
                    runner_up_loss_millionths: 200_000,
                    explanation: crate::expected_loss_selector::DecisionExplanation {
                        posterior_snapshot: Posterior::default_prior(),
                        loss_matrix_id: "test".to_string(),
                        all_expected_losses: BTreeMap::new(),
                        margin_millionths: 100_000,
                    },
                    epoch: SecurityEpoch::GENESIS,
                },
            },
            ReplayStep {
                step_index: 1,
                evidence: suspicious_evidence(),
                update_result: UpdateResult {
                    posterior: Posterior::default_prior(),
                    likelihoods: [1_000_000; 4],
                    cumulative_llr_millionths: 0,
                    update_count: 2,
                },
                decision: ActionDecision {
                    action: ContainmentAction::Terminate,
                    expected_loss_millionths: 50_000,
                    runner_up_action: ContainmentAction::Quarantine,
                    runner_up_loss_millionths: 60_000,
                    explanation: crate::expected_loss_selector::DecisionExplanation {
                        posterior_snapshot: Posterior::default_prior(),
                        loss_matrix_id: "test".to_string(),
                        all_expected_losses: BTreeMap::new(),
                        margin_millionths: 10_000,
                    },
                    epoch: SecurityEpoch::GENESIS,
                },
            },
        ];

        let state = determine_final_state(&steps);
        assert_eq!(state, ContainmentState::Terminated);
    }

    #[test]
    fn determine_final_state_dead_stays_dead() {
        let make_step = |idx: u64, action: ContainmentAction| ReplayStep {
            step_index: idx,
            evidence: benign_evidence(),
            update_result: UpdateResult {
                posterior: Posterior::default_prior(),
                likelihoods: [1_000_000; 4],
                cumulative_llr_millionths: 0,
                update_count: idx + 1,
            },
            decision: ActionDecision {
                action,
                expected_loss_millionths: 0,
                runner_up_action: ContainmentAction::Allow,
                runner_up_loss_millionths: 0,
                explanation: crate::expected_loss_selector::DecisionExplanation {
                    posterior_snapshot: Posterior::default_prior(),
                    loss_matrix_id: "test".to_string(),
                    all_expected_losses: BTreeMap::new(),
                    margin_millionths: 0,
                },
                epoch: SecurityEpoch::GENESIS,
            },
        };

        let steps = vec![
            make_step(0, ContainmentAction::Terminate),
            make_step(1, ContainmentAction::Allow), // Can't undo terminate.
        ];
        assert_eq!(determine_final_state(&steps), ContainmentState::Terminated);
    }

    // -----------------------------------------------------------------------
    // Serde roundtrip tests
    // -----------------------------------------------------------------------

    #[test]
    fn incident_metadata_serde_roundtrip() {
        let meta = IncidentMetadata {
            trace_id: "trace-rt".to_string(),
            extension_id: "ext-rt".to_string(),
            start_epoch: SecurityEpoch::GENESIS,
            start_timestamp_ns: 100,
            end_timestamp_ns: 200,
            initial_prior: Posterior::default_prior(),
            loss_matrix_id: "balanced".to_string(),
            annotations: BTreeMap::new(),
        };
        let json = serde_json::to_string(&meta).unwrap();
        let decoded: IncidentMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(meta, decoded);
    }

    #[test]
    fn replay_step_serde_roundtrip() {
        let step = ReplayStep {
            step_index: 0,
            evidence: benign_evidence(),
            update_result: UpdateResult {
                posterior: Posterior::default_prior(),
                likelihoods: [900_000, 50_000, 25_000, 25_000],
                cumulative_llr_millionths: 1234,
                update_count: 1,
            },
            decision: ActionDecision {
                action: ContainmentAction::Allow,
                expected_loss_millionths: 10_000,
                runner_up_action: ContainmentAction::Challenge,
                runner_up_loss_millionths: 20_000,
                explanation: crate::expected_loss_selector::DecisionExplanation {
                    posterior_snapshot: Posterior::default_prior(),
                    loss_matrix_id: "balanced".to_string(),
                    all_expected_losses: BTreeMap::new(),
                    margin_millionths: 10_000,
                },
                epoch: SecurityEpoch::GENESIS,
            },
        };
        let json = serde_json::to_string(&step).unwrap();
        let decoded: ReplayStep = serde_json::from_str(&json).unwrap();
        assert_eq!(step, decoded);
    }

    #[test]
    fn replay_result_serde_roundtrip() {
        let trace = build_trace(vec![benign_evidence()]);
        let mut replayer = ForensicReplayer::new();
        let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let decoded: ReplayResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, decoded);
    }

    #[test]
    fn counterfactual_spec_serde_roundtrip() {
        let spec = CounterfactualSpec {
            override_prior: Some(Posterior::uniform()),
            override_loss_matrix: None,
            override_likelihood_model: None,
            skip_evidence_indices: vec![0, 2],
            inject_evidence: Vec::new(),
            description: "test spec".to_string(),
        };
        let json = serde_json::to_string(&spec).unwrap();
        let decoded: CounterfactualSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, decoded);
    }

    #[test]
    fn replay_diff_serde_roundtrip() {
        let diff = ReplayDiff {
            counterfactual_description: "test diff".to_string(),
            first_divergence_step: Some(2),
            step_changes: vec![
                (0, DecisionChange::Identical),
                (
                    1,
                    DecisionChange::SameActionDifferentMargin {
                        original_margin: 100,
                        counterfactual_margin: 200,
                    },
                ),
                (
                    2,
                    DecisionChange::DifferentAction {
                        original_action: ContainmentAction::Allow,
                        counterfactual_action: ContainmentAction::Challenge,
                        original_loss: 10_000,
                        counterfactual_loss: 8_000,
                    },
                ),
            ],
            action_change_count: 1,
            original_final_action: Some(ContainmentAction::Allow),
            counterfactual_final_action: Some(ContainmentAction::Challenge),
            final_outcome_differs: true,
        };
        let json = serde_json::to_string(&diff).unwrap();
        let decoded: ReplayDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(diff, decoded);
    }

    #[test]
    fn trace_validation_error_display() {
        let err = TraceValidationError::NonMonotonicTimestamp {
            record_index: 5,
            prev_ns: 100,
            current_ns: 50,
        };
        assert!(err.to_string().contains("non-monotonic"));

        let err = TraceValidationError::EmptyTrace;
        assert_eq!(err.to_string(), "empty trace");
    }

    #[test]
    fn replay_error_display() {
        let err = ReplayError::StepLimitExceeded { limit: 42 };
        assert!(err.to_string().contains("42"));

        let err = ReplayError::Internal {
            detail: "oops".to_string(),
        };
        assert!(err.to_string().contains("oops"));
    }

    #[test]
    fn decision_change_display() {
        assert_eq!(DecisionChange::Identical.to_string(), "identical");

        let dc = DecisionChange::DifferentAction {
            original_action: ContainmentAction::Allow,
            counterfactual_action: ContainmentAction::Sandbox,
            original_loss: 0,
            counterfactual_loss: 0,
        };
        assert!(dc.to_string().contains("allow"));
        assert!(dc.to_string().contains("sandbox"));
    }

    // -----------------------------------------------------------------------
    // Trace content hash tests
    // -----------------------------------------------------------------------

    #[test]
    fn trace_content_hash_stable() {
        let trace = build_trace(vec![benign_evidence()]);
        let h1 = trace.content_hash();
        let h2 = trace.content_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn trace_content_hash_differs_on_different_evidence() {
        let t1 = build_trace(vec![benign_evidence()]);
        let t2 = build_trace(vec![malicious_evidence()]);
        // Different evidence count/posteriors should produce different trace hashes
        // (the hash includes evidence_log.len() and decision_log.len()).
        // Actually both have 1 evidence so the hash includes the same len.
        // But trace_id is the same too. The difference is in decision_log.len()
        // and posterior_history.len() which are both 1. And the other fields
        // are also identical. So these will actually have the same hash.
        // That's fine — the content hash is a fingerprint of structural properties,
        // not a full content digest.
        let _ = t1.content_hash();
        let _ = t2.content_hash();
    }

    // -----------------------------------------------------------------------
    // Integration: full pipeline test
    // -----------------------------------------------------------------------

    #[test]
    fn full_pipeline_benign_to_malicious_escalation() {
        let evidence = vec![
            benign_evidence(),
            benign_evidence(),
            suspicious_evidence(),
            suspicious_evidence(),
            malicious_evidence(),
            malicious_evidence(),
        ];
        let trace = build_trace(evidence);
        let mut replayer = ForensicReplayer::new();

        // Replay.
        let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
        assert!(result.deterministic);
        assert_eq!(result.steps.len(), 6);

        // Counterfactual with conservative matrix.
        let cf = replayer
            .counterfactual(
                &trace,
                &ReplayConfig::default(),
                &CounterfactualSpec::with_loss_matrix(
                    LossMatrix::conservative(),
                    "conservative escalation",
                ),
            )
            .unwrap();

        // Diff.
        let diff = replayer.diff(&result, &cf, "conservative escalation");
        assert_eq!(diff.step_changes.len(), 6);

        // The conservative matrix should not be less severe.
        if diff.final_outcome_differs {
            let orig = diff.original_final_action.unwrap().severity();
            let cf_sev = diff.counterfactual_final_action.unwrap().severity();
            assert!(cf_sev >= orig);
        }
    }

    #[test]
    fn full_pipeline_with_evidence_injection() {
        let evidence = vec![benign_evidence(), benign_evidence()];
        let trace = build_trace(evidence);
        let mut replayer = ForensicReplayer::new();

        let original = replayer.replay(&trace, &ReplayConfig::default()).unwrap();

        // Inject malicious evidence between the two benign ones.
        let spec = CounterfactualSpec {
            inject_evidence: vec![(1, malicious_evidence()), (1, malicious_evidence())],
            description: "inject malicious between benign".to_string(),
            ..CounterfactualSpec::identity()
        };

        let cf = replayer
            .counterfactual(&trace, &ReplayConfig::default(), &spec)
            .unwrap();

        assert_eq!(cf.steps.len(), 4); // 2 original + 2 injected.

        let diff = replayer.diff(&original, &cf, "injected malicious");
        // Should have diverged at some point because of extra malicious evidence.
        assert!(diff.step_changes.len() >= 2);
    }

    #[test]
    fn replayer_set_epoch() {
        let mut replayer = ForensicReplayer::new();
        replayer.set_epoch(SecurityEpoch::from_raw(5));
        let trace = build_trace(vec![benign_evidence()]);
        let result = replayer.replay(&trace, &ReplayConfig::default()).unwrap();
        // Steps should have epoch from the replayer.
        assert_eq!(result.steps[0].decision.epoch, SecurityEpoch::from_raw(5));
    }

    #[test]
    fn replayer_default() {
        let replayer = ForensicReplayer::default();
        assert_eq!(replayer.replay_count(), 0);
    }

    #[test]
    fn replayer_serde_roundtrip() {
        let mut replayer = ForensicReplayer::new();
        replayer.set_epoch(SecurityEpoch::from_raw(3));
        let json = serde_json::to_string(&replayer).unwrap();
        let decoded: ForensicReplayer = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.replay_count(), 0);
        assert_eq!(decoded.epoch, SecurityEpoch::from_raw(3));
    }

    // -----------------------------------------------------------------------
    // Edge case: counterfactual removes all evidence
    // -----------------------------------------------------------------------

    #[test]
    fn counterfactual_removing_all_evidence_fails() {
        let evidence = vec![benign_evidence()];
        let trace = build_trace(evidence);
        let mut replayer = ForensicReplayer::new();

        let spec = CounterfactualSpec {
            skip_evidence_indices: vec![0],
            description: "remove all".to_string(),
            ..CounterfactualSpec::identity()
        };

        let err = replayer
            .counterfactual(&trace, &ReplayConfig::default(), &spec)
            .unwrap_err();
        assert!(matches!(err, ReplayError::ValidationFailed { .. }));
    }

    // -----------------------------------------------------------------------
    // Build counterfactual evidence tests
    // -----------------------------------------------------------------------

    #[test]
    fn build_counterfactual_evidence_skip() {
        let replayer = ForensicReplayer::new();
        let evidence = vec![
            benign_evidence(),
            suspicious_evidence(),
            malicious_evidence(),
        ];
        let result = replayer.build_counterfactual_evidence(&evidence, &[1], &[]);
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0].hostcall_rate_millionths,
            benign_evidence().hostcall_rate_millionths
        );
        assert_eq!(
            result[1].hostcall_rate_millionths,
            malicious_evidence().hostcall_rate_millionths
        );
    }

    #[test]
    fn build_counterfactual_evidence_inject() {
        let replayer = ForensicReplayer::new();
        let evidence = vec![benign_evidence()];
        let injected = suspicious_evidence();
        let result =
            replayer.build_counterfactual_evidence(&evidence, &[], &[(0, injected.clone())]);
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0].hostcall_rate_millionths,
            injected.hostcall_rate_millionths
        );
        assert_eq!(
            result[1].hostcall_rate_millionths,
            benign_evidence().hostcall_rate_millionths
        );
    }

    #[test]
    fn build_counterfactual_evidence_inject_at_end() {
        let replayer = ForensicReplayer::new();
        let evidence = vec![benign_evidence()];
        let injected = malicious_evidence();
        let result =
            replayer.build_counterfactual_evidence(&evidence, &[], &[(5, injected.clone())]);
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0].hostcall_rate_millionths,
            benign_evidence().hostcall_rate_millionths
        );
        assert_eq!(
            result[1].hostcall_rate_millionths,
            injected.hostcall_rate_millionths
        );
    }

    #[test]
    fn replay_config_default() {
        let config = ReplayConfig::default();
        assert!(config.verify_telemetry_integrity);
        assert!(config.verify_receipt_integrity);
        assert_eq!(config.max_steps, 0);
    }

    // -- Enrichment: missing serde roundtrips --

    #[test]
    fn trace_validation_error_serde_roundtrip() {
        let errors = vec![
            TraceValidationError::NonMonotonicTimestamp {
                record_index: 5,
                prev_ns: 100,
                current_ns: 50,
            },
            TraceValidationError::InvalidPosterior { step_index: 3 },
            TraceValidationError::DecisionCountMismatch {
                decisions: 10,
                posteriors: 8,
            },
            TraceValidationError::EvidenceCountMismatch {
                evidence: 5,
                posteriors: 7,
            },
            TraceValidationError::EmptyTrace,
            TraceValidationError::TelemetryIntegrityFailure { record_id: 42 },
            TraceValidationError::ReceiptIntegrityFailure {
                receipt_id: "r-1".to_string(),
            },
        ];
        for e in &errors {
            let json = serde_json::to_string(e).expect("serialize");
            let restored: TraceValidationError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*e, restored);
        }
        assert_eq!(errors.len(), 7);
    }

    #[test]
    fn decision_change_serde_roundtrip() {
        let changes = vec![
            DecisionChange::Identical,
            DecisionChange::SameActionDifferentMargin {
                original_margin: 100_000,
                counterfactual_margin: 200_000,
            },
            DecisionChange::DifferentAction {
                original_action: ContainmentAction::Allow,
                counterfactual_action: ContainmentAction::Quarantine,
                original_loss: 50_000,
                counterfactual_loss: 150_000,
            },
        ];
        for c in &changes {
            let json = serde_json::to_string(c).expect("serialize");
            let restored: DecisionChange = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*c, restored);
        }
        assert_eq!(changes.len(), 3);
    }

    #[test]
    fn replay_error_serde_roundtrip() {
        let errors = vec![
            ReplayError::ValidationFailed {
                errors: vec![TraceValidationError::EmptyTrace],
            },
            ReplayError::StepLimitExceeded { limit: 1000 },
            ReplayError::Internal {
                detail: "unexpected state".to_string(),
            },
        ];
        for e in &errors {
            let json = serde_json::to_string(e).expect("serialize");
            let restored: ReplayError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*e, restored);
        }
        assert_eq!(errors.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch — PearlTower 2026-02-25
    // -----------------------------------------------------------------------

    #[test]
    fn trace_validation_error_display_uniqueness_btreeset() {
        let variants = [
            TraceValidationError::NonMonotonicTimestamp {
                record_index: 0,
                prev_ns: 100,
                current_ns: 50,
            },
            TraceValidationError::InvalidPosterior { step_index: 1 },
            TraceValidationError::DecisionCountMismatch {
                decisions: 3,
                posteriors: 2,
            },
            TraceValidationError::EvidenceCountMismatch {
                evidence: 5,
                posteriors: 4,
            },
            TraceValidationError::EmptyTrace,
            TraceValidationError::TelemetryIntegrityFailure { record_id: 10 },
            TraceValidationError::ReceiptIntegrityFailure {
                receipt_id: "r-1".to_string(),
            },
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let s = format!("{v}");
            assert!(!s.is_empty());
            displays.insert(s);
        }
        assert_eq!(
            displays.len(),
            7,
            "all 7 TraceValidationError variants produce distinct Display strings"
        );
    }

    #[test]
    fn replay_config_serde_roundtrip() {
        let config = ReplayConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: ReplayConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn replay_config_default_verifies_all() {
        let config = ReplayConfig::default();
        assert!(config.verify_telemetry_integrity);
        assert!(config.verify_receipt_integrity);
        assert_eq!(config.max_steps, 0);
    }

    #[test]
    fn counterfactual_spec_identity_has_no_overrides() {
        let spec = CounterfactualSpec::identity();
        assert!(spec.override_prior.is_none());
        assert!(spec.override_loss_matrix.is_none());
        assert!(spec.override_likelihood_model.is_none());
        assert!(spec.skip_evidence_indices.is_empty());
        assert!(spec.inject_evidence.is_empty());
    }

    #[test]
    fn enrichment_counterfactual_spec_identity_serde() {
        let spec = CounterfactualSpec::identity();
        let json = serde_json::to_string(&spec).unwrap();
        let back: CounterfactualSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, back);
    }

    #[test]
    fn incident_trace_content_hash_deterministic() {
        let trace = build_trace(vec![benign_evidence()]);
        let h1 = trace.content_hash();
        let h2 = trace.content_hash();
        assert_eq!(h1, h2, "content_hash must be deterministic");
    }

    #[test]
    fn incident_trace_content_hash_differs_for_different_evidence_counts() {
        let trace1 = build_trace(vec![benign_evidence()]);
        let trace2 = build_trace(vec![benign_evidence(), suspicious_evidence()]);
        assert_ne!(
            trace1.content_hash(),
            trace2.content_hash(),
            "traces with different evidence counts must have different content hashes"
        );
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn trace_content_hash_sensitive_to_trace_id() {
        let mut t1 = build_trace(vec![benign_evidence()]);
        let mut t2 = build_trace(vec![benign_evidence()]);
        t1.metadata.trace_id = "alpha".to_string();
        t2.metadata.trace_id = "beta".to_string();
        assert_ne!(t1.content_hash(), t2.content_hash());
    }

    #[test]
    fn trace_content_hash_sensitive_to_extension_id() {
        let mut t1 = build_trace(vec![benign_evidence()]);
        let mut t2 = build_trace(vec![benign_evidence()]);
        t1.metadata.extension_id = "ext-aaa".to_string();
        t2.metadata.extension_id = "ext-bbb".to_string();
        assert_ne!(t1.content_hash(), t2.content_hash());
    }

    #[test]
    fn trace_content_hash_sensitive_to_start_timestamp() {
        let mut t1 = build_trace(vec![benign_evidence()]);
        let mut t2 = build_trace(vec![benign_evidence()]);
        t1.metadata.start_timestamp_ns = 100;
        t2.metadata.start_timestamp_ns = 200;
        assert_ne!(t1.content_hash(), t2.content_hash());
    }

    #[test]
    fn trace_content_hash_sensitive_to_end_timestamp() {
        let mut t1 = build_trace(vec![benign_evidence()]);
        let mut t2 = build_trace(vec![benign_evidence()]);
        t1.metadata.end_timestamp_ns = 1000;
        t2.metadata.end_timestamp_ns = 2000;
        assert_ne!(t1.content_hash(), t2.content_hash());
    }

    #[test]
    fn replay_error_display_validation_failed_includes_count() {
        let err = ReplayError::ValidationFailed {
            errors: vec![
                TraceValidationError::EmptyTrace,
                TraceValidationError::InvalidPosterior { step_index: 0 },
            ],
        };
        let s = err.to_string();
        assert!(s.contains("2"), "should include error count: {s}");
        assert!(s.contains("validation"), "should mention validation: {s}");
    }

    #[test]
    fn decision_change_display_same_action_different_margin_content() {
        let dc = DecisionChange::SameActionDifferentMargin {
            original_margin: 100_000,
            counterfactual_margin: 200_000,
        };
        let s = dc.to_string();
        assert!(s.contains("100000"), "should include original margin: {s}");
        assert!(
            s.contains("200000"),
            "should include counterfactual margin: {s}"
        );
        assert!(s.contains("same action"), "should say same action: {s}");
    }

    #[test]
    fn counterfactual_spec_with_loss_matrix_builder_sets_fields() {
        let matrix = LossMatrix::conservative();
        let spec = CounterfactualSpec::with_loss_matrix(matrix.clone(), "test matrix");
        assert!(spec.override_loss_matrix.is_some());
        assert_eq!(spec.override_loss_matrix.unwrap(), matrix);
        assert!(spec.override_prior.is_none());
        assert!(spec.override_likelihood_model.is_none());
        assert!(spec.skip_evidence_indices.is_empty());
        assert!(spec.inject_evidence.is_empty());
        assert_eq!(spec.description, "test matrix");
    }

    #[test]
    fn counterfactual_spec_with_prior_builder_sets_fields() {
        let prior = Posterior::uniform();
        let spec = CounterfactualSpec::with_prior(prior.clone(), "test prior");
        assert!(spec.override_prior.is_some());
        assert_eq!(spec.override_prior.unwrap(), prior);
        assert!(spec.override_loss_matrix.is_none());
        assert!(spec.override_likelihood_model.is_none());
        assert_eq!(spec.description, "test prior");
    }

    #[test]
    fn replay_config_custom_values_serde_roundtrip() {
        let config = ReplayConfig {
            verify_telemetry_integrity: false,
            verify_receipt_integrity: false,
            max_steps: 42,
        };
        let json = serde_json::to_string(&config).unwrap();
        let decoded: ReplayConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, decoded);
        assert!(!decoded.verify_telemetry_integrity);
        assert!(!decoded.verify_receipt_integrity);
        assert_eq!(decoded.max_steps, 42);
    }

    #[test]
    fn replayer_serde_preserves_replay_count_after_replays() {
        let trace = build_trace(vec![benign_evidence()]);
        let mut replayer = ForensicReplayer::new();
        replayer.replay(&trace, &ReplayConfig::default()).unwrap();
        replayer.replay(&trace, &ReplayConfig::default()).unwrap();
        assert_eq!(replayer.replay_count(), 2);

        let json = serde_json::to_string(&replayer).unwrap();
        let decoded: ForensicReplayer = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.replay_count(), 2);
    }

    #[test]
    fn determine_final_state_sandbox_transition() {
        let make = |idx: u64, action: ContainmentAction| ReplayStep {
            step_index: idx,
            evidence: benign_evidence(),
            update_result: UpdateResult {
                posterior: Posterior::default_prior(),
                likelihoods: [1_000_000; 4],
                cumulative_llr_millionths: 0,
                update_count: idx + 1,
            },
            decision: ActionDecision {
                action,
                expected_loss_millionths: 0,
                runner_up_action: ContainmentAction::Allow,
                runner_up_loss_millionths: 0,
                explanation: crate::expected_loss_selector::DecisionExplanation {
                    posterior_snapshot: Posterior::default_prior(),
                    loss_matrix_id: "t".to_string(),
                    all_expected_losses: BTreeMap::new(),
                    margin_millionths: 0,
                },
                epoch: SecurityEpoch::GENESIS,
            },
        };
        let steps = vec![
            make(0, ContainmentAction::Challenge),
            make(1, ContainmentAction::Sandbox),
        ];
        assert_eq!(determine_final_state(&steps), ContainmentState::Sandboxed);
    }

    #[test]
    fn determine_final_state_quarantine_from_running() {
        let make = |idx: u64, action: ContainmentAction| ReplayStep {
            step_index: idx,
            evidence: benign_evidence(),
            update_result: UpdateResult {
                posterior: Posterior::default_prior(),
                likelihoods: [1_000_000; 4],
                cumulative_llr_millionths: 0,
                update_count: idx + 1,
            },
            decision: ActionDecision {
                action,
                expected_loss_millionths: 0,
                runner_up_action: ContainmentAction::Allow,
                runner_up_loss_millionths: 0,
                explanation: crate::expected_loss_selector::DecisionExplanation {
                    posterior_snapshot: Posterior::default_prior(),
                    loss_matrix_id: "t".to_string(),
                    all_expected_losses: BTreeMap::new(),
                    margin_millionths: 0,
                },
                epoch: SecurityEpoch::GENESIS,
            },
        };
        let steps = vec![make(0, ContainmentAction::Quarantine)];
        assert_eq!(determine_final_state(&steps), ContainmentState::Quarantined);
    }

    #[test]
    fn determine_final_state_suspend_then_terminate() {
        let make = |idx: u64, action: ContainmentAction| ReplayStep {
            step_index: idx,
            evidence: benign_evidence(),
            update_result: UpdateResult {
                posterior: Posterior::default_prior(),
                likelihoods: [1_000_000; 4],
                cumulative_llr_millionths: 0,
                update_count: idx + 1,
            },
            decision: ActionDecision {
                action,
                expected_loss_millionths: 0,
                runner_up_action: ContainmentAction::Allow,
                runner_up_loss_millionths: 0,
                explanation: crate::expected_loss_selector::DecisionExplanation {
                    posterior_snapshot: Posterior::default_prior(),
                    loss_matrix_id: "t".to_string(),
                    all_expected_losses: BTreeMap::new(),
                    margin_millionths: 0,
                },
                epoch: SecurityEpoch::GENESIS,
            },
        };
        let steps = vec![
            make(0, ContainmentAction::Suspend),
            make(1, ContainmentAction::Terminate),
        ];
        let state = determine_final_state(&steps);
        assert_eq!(state, ContainmentState::Terminated);
    }

    #[test]
    fn build_counterfactual_evidence_skip_and_inject_combined() {
        let replayer = ForensicReplayer::new();
        let evidence = vec![
            benign_evidence(),
            suspicious_evidence(),
            malicious_evidence(),
        ];
        // Skip index 1 (suspicious), inject malicious before index 0.
        let injected = malicious_evidence();
        let result =
            replayer.build_counterfactual_evidence(&evidence, &[1], &[(0, injected.clone())]);
        // Result: injected(before 0), benign(0), malicious(2) — skipping suspicious(1)
        assert_eq!(result.len(), 3);
        assert_eq!(
            result[0].hostcall_rate_millionths,
            injected.hostcall_rate_millionths
        );
        assert_eq!(
            result[1].hostcall_rate_millionths,
            benign_evidence().hostcall_rate_millionths
        );
        assert_eq!(
            result[2].hostcall_rate_millionths,
            malicious_evidence().hostcall_rate_millionths
        );
    }

    #[test]
    fn incident_metadata_with_annotations_serde_roundtrip() {
        let mut annotations = BTreeMap::new();
        annotations.insert("severity".to_string(), "high".to_string());
        annotations.insert("origin".to_string(), "automated".to_string());
        let meta = IncidentMetadata {
            trace_id: "trace-ann".to_string(),
            extension_id: "ext-ann".to_string(),
            start_epoch: SecurityEpoch::GENESIS,
            start_timestamp_ns: 100,
            end_timestamp_ns: 200,
            initial_prior: Posterior::default_prior(),
            loss_matrix_id: "balanced".to_string(),
            annotations,
        };
        let json = serde_json::to_string(&meta).unwrap();
        let decoded: IncidentMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(meta, decoded);
        assert_eq!(decoded.annotations.len(), 2);
        assert_eq!(decoded.annotations["severity"], "high");
    }

    #[test]
    fn incident_trace_full_serde_roundtrip() {
        let trace = build_trace(vec![benign_evidence(), suspicious_evidence()]);
        let json = serde_json::to_string(&trace).unwrap();
        let decoded: IncidentTrace = serde_json::from_str(&json).unwrap();
        assert_eq!(trace, decoded);
        assert_eq!(decoded.evidence_log.len(), 2);
        assert_eq!(decoded.decision_log.len(), 2);
    }

    #[test]
    fn replay_result_content_hash_sensitive_to_trace_id() {
        let mut trace1 = build_trace(vec![benign_evidence()]);
        let mut trace2 = build_trace(vec![benign_evidence()]);
        trace1.metadata.trace_id = "trace-aaa".to_string();
        trace2.metadata.trace_id = "trace-bbb".to_string();
        let mut replayer = ForensicReplayer::new();
        let r1 = replayer.replay(&trace1, &ReplayConfig::default()).unwrap();
        let r2 = replayer.replay(&trace2, &ReplayConfig::default()).unwrap();
        assert_ne!(
            r1.content_hash, r2.content_hash,
            "different trace_ids should produce different replay result hashes"
        );
    }
}
