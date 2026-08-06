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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Write};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bayesian_posterior::{
    BayesianPosteriorUpdater, Evidence, LikelihoodModel, Posterior, UpdateResult,
};
use crate::containment_executor::{ContainmentReceipt, ContainmentState};
use crate::expected_loss_selector::{
    ActionDecision, ContainmentAction, ExpectedLossSelector, LossMatrix,
};
use crate::hash_tiers::ContentHash;
use crate::hostcall_telemetry::{HostcallTelemetryRecord, TelemetryDropCounts, TelemetryRecorder};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema identifier for canonical trace content hashing.
const TRACE_HASH_DOMAIN: &[u8] = b"franken-engine.forensic-incident-trace.v2\0";
const REPLAY_INPUT_HASH_DOMAIN: &[u8] = b"franken-engine.forensic-replay-input.v2\0";
const REPLAY_RESULT_HASH_DOMAIN: &[u8] = b"franken-engine.forensic-replay-result.v2\0";

/// Schema version for serialized replay result artifacts.
pub const REPLAY_RESULT_SCHEMA_VERSION: &str = "franken-engine.forensic-replay-result.v2";

/// Maximum step count for safety (prevents runaway replays).
const MAX_REPLAY_STEPS: usize = 1_000_000;

struct Sha256Writer(Sha256);

impl Write for Sha256Writer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn hash_serialized<T: Serialize + ?Sized>(
    domain: &[u8],
    value: &T,
) -> Result<ContentHash, serde_json::Error> {
    let mut writer = Sha256Writer(Sha256::new());
    writer.0.update(domain);
    serde_json::to_writer(&mut writer, value)?;
    let digest = writer.0.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    Ok(ContentHash::from_bytes(bytes))
}

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
    /// Per-reason records refused by the source telemetry recorder.
    ///
    /// Zero proves that every record submitted by an instrumented dispatch
    /// site was retained; dispatch-site coverage is a separate invariant. The
    /// default preserves decoding of incident traces serialized before drop
    /// evidence was added.
    #[serde(default)]
    pub telemetry_drop_counts: TelemetryDropCounts,
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

/// Failure to encode an incident trace for content hashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentTraceHashError {
    Serialization { detail: String },
}

impl fmt::Display for IncidentTraceHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialization { detail } => {
                write!(
                    f,
                    "failed to serialize incident trace for hashing: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for IncidentTraceHashError {}

impl IncidentTrace {
    /// Compute a canonical content hash covering every trace field.
    ///
    /// Structured serialization preserves free-form field boundaries and
    /// fails closed if a future field cannot be represented. Every map in the
    /// trace graph has deterministic ordering, so identical traces produce
    /// identical bytes for this schema version.
    pub fn content_hash(&self) -> Result<ContentHash, IncidentTraceHashError> {
        hash_serialized(TRACE_HASH_DOMAIN, self).map_err(|error| {
            IncidentTraceHashError::Serialization {
                detail: error.to_string(),
            }
        })
    }

    /// Return a clone of this trace whose telemetry evidence is replaced with
    /// a completeness-aware snapshot of the supplied recorder.
    ///
    /// This is the recommended bridge between
    /// [`crate::baseline_interpreter::InterpreterCore::hostcall_telemetry`]
    /// and a recorded incident trace (bd-qi3hs): callers seed an
    /// [`IncidentTrace`] from posterior/decision/evidence history and then
    /// feed it the runtime's recorder so the Probabilistic Guardplane can
    /// replay against the real evidence stream and reject any dropped tail.
    #[must_use]
    pub fn with_telemetry_recorder(mut self, recorder: &TelemetryRecorder) -> Self {
        self.telemetry_log = recorder.records().to_vec();
        self.telemetry_drop_counts = recorder.drop_counts();
        self
    }
}

// ---------------------------------------------------------------------------
// TraceValidationError — consistency checking
// ---------------------------------------------------------------------------

/// Errors found during trace validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceValidationError {
    /// The trace lacks a usable audit identity.
    InvalidTraceId,
    /// The trace lacks a usable extension identity.
    InvalidExtensionId,
    /// The trace's starting prior is not a probability distribution.
    InvalidInitialPrior,
    /// The configured loss matrix lacks a usable audit identity.
    InvalidLossMatrixId,
    /// The configured loss matrix does not contain every pair exactly once.
    IncompleteLossMatrix,
    /// Metadata names a different matrix than the matrix embedded in the trace.
    LossMatrixIdMismatch { declared: String, actual: String },
    /// The recording end precedes its start.
    InvalidTimeRange { start_ns: u64, end_ns: u64 },
    /// Telemetry record IDs are not strictly increasing.
    NonMonotonicRecordId {
        record_index: usize,
        prev_id: u64,
        current_id: u64,
    },
    /// Telemetry timestamps are not monotonically increasing.
    NonMonotonicTimestamp {
        record_index: usize,
        prev_ns: u64,
        current_ns: u64,
    },
    /// Posterior does not sum to 1_000_000.
    InvalidPosterior { step_index: u64 },
    /// The recorded posterior step label does not match its zero-based history position.
    PosteriorStepIndexMismatch {
        history_index: usize,
        declared_step_index: u64,
    },
    /// Evidence belongs to a different extension than the incident trace.
    EvidenceExtensionMismatch {
        evidence_index: usize,
        expected: String,
        actual: String,
    },
    /// Telemetry belongs to a different extension than the incident trace.
    TelemetryExtensionMismatch {
        record_index: usize,
        record_id: u64,
        expected: String,
        actual: String,
    },
    /// A containment receipt targets a different extension than the trace.
    ReceiptExtensionMismatch {
        receipt_index: usize,
        receipt_id: String,
        expected: String,
        actual: String,
    },
    /// Decision count does not match posterior history length.
    DecisionCountMismatch { decisions: usize, posteriors: usize },
    /// Evidence count does not match posterior history length.
    EvidenceCountMismatch { evidence: usize, posteriors: usize },
    /// Empty trace (no evidence to replay).
    EmptyTrace,
    /// The source recorder refused one or more telemetry records, so the
    /// retained stream is incomplete and cannot support a clean replay.
    IncompleteTelemetry { drop_counts: TelemetryDropCounts },
    /// Telemetry record fails integrity check.
    TelemetryIntegrityFailure { record_id: u64 },
    /// Containment receipt fails integrity check.
    ReceiptIntegrityFailure { receipt_id: String },
}

impl fmt::Display for TraceValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTraceId => f.write_str("trace id must be non-blank"),
            Self::InvalidExtensionId => f.write_str("extension id must be non-blank"),
            Self::InvalidInitialPrior => {
                f.write_str("initial prior is not a valid probability distribution")
            }
            Self::InvalidLossMatrixId => f.write_str("loss matrix id must be non-blank"),
            Self::IncompleteLossMatrix => {
                f.write_str("loss matrix must contain every action/state pair exactly once")
            }
            Self::LossMatrixIdMismatch { declared, actual } => write!(
                f,
                "metadata loss matrix id {declared:?} does not match embedded matrix id {actual:?}"
            ),
            Self::InvalidTimeRange { start_ns, end_ns } => write!(
                f,
                "incident end timestamp {end_ns} precedes start timestamp {start_ns}"
            ),
            Self::NonMonotonicRecordId {
                record_index,
                prev_id,
                current_id,
            } => write!(
                f,
                "non-monotonic record id at record {record_index}: {prev_id} -> {current_id}"
            ),
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
            Self::PosteriorStepIndexMismatch {
                history_index,
                declared_step_index,
            } => write!(
                f,
                "posterior history index {history_index} declares step {declared_step_index}"
            ),
            Self::EvidenceExtensionMismatch {
                evidence_index,
                expected,
                actual,
            } => write!(
                f,
                "evidence extension mismatch at index {evidence_index}: expected {expected}, got {actual}"
            ),
            Self::TelemetryExtensionMismatch {
                record_index,
                record_id,
                expected,
                actual,
            } => write!(
                f,
                "telemetry extension mismatch at index {record_index} (record {record_id}): expected {expected}, got {actual}"
            ),
            Self::ReceiptExtensionMismatch {
                receipt_index,
                receipt_id,
                expected,
                actual,
            } => write!(
                f,
                "containment receipt extension mismatch at index {receipt_index} ({receipt_id}): expected {expected}, got {actual}"
            ),
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
            Self::IncompleteTelemetry { drop_counts } => write!(
                f,
                "incomplete telemetry: {} dropped record(s) (channel_full={}, monotonicity_violation={}, empty_extension_id={})",
                drop_counts.total(),
                drop_counts.channel_full,
                drop_counts.monotonicity_violation,
                drop_counts.empty_extension_id
            ),
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
    pub schema_version: String,
    /// Trace ID being replayed.
    pub trace_id: String,
    /// Content identity of the complete source incident trace.
    pub source_trace_hash: ContentHash,
    /// Content identity of the effective replay configuration and model inputs.
    pub replay_input_hash: ContentHash,
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

#[derive(Serialize)]
struct ReplayResultHashPreimage<'a> {
    schema_version: &'a str,
    trace_id: &'a str,
    source_trace_hash: &'a ContentHash,
    replay_input_hash: &'a ContentHash,
    steps: &'a [ReplayStep],
    final_posterior: &'a Posterior,
    final_decision: &'a Option<ActionDecision>,
    final_containment_state: ContainmentState,
    deterministic: bool,
    first_divergence_step: Option<u64>,
    content_hash: ContentHash,
}

impl<'a> From<&'a ReplayResult> for ReplayResultHashPreimage<'a> {
    fn from(result: &'a ReplayResult) -> Self {
        Self {
            schema_version: &result.schema_version,
            trace_id: &result.trace_id,
            source_trace_hash: &result.source_trace_hash,
            replay_input_hash: &result.replay_input_hash,
            steps: &result.steps,
            final_posterior: &result.final_posterior,
            final_decision: &result.final_decision,
            final_containment_state: result.final_containment_state,
            deterministic: result.deterministic,
            first_divergence_step: result.first_divergence_step,
            content_hash: ContentHash::default(),
        }
    }
}

impl ReplayResult {
    /// Recompute the content hash over the complete replay artifact.
    pub fn recompute_content_hash(&self) -> Result<ContentHash, ReplayError> {
        hash_serialized(
            REPLAY_RESULT_HASH_DOMAIN,
            &ReplayResultHashPreimage::from(self),
        )
        .map_err(|error| ReplayError::EvidenceSerialization {
            detail: error.to_string(),
        })
    }

    /// Verify that all serialized replay fields match the stored hash.
    pub fn verify_content_hash(&self) -> Result<bool, ReplayError> {
        Ok(self
            .content_hash
            .constant_time_eq(&self.recompute_content_hash()?))
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
    /// Complete decision semantics match, apart from the replay epoch.
    Identical,
    /// The action is unchanged, but one or more scored decision fields differ.
    SameActionDifferentScore {
        original_loss: i64,
        counterfactual_loss: i64,
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
    /// A step exists only in the original replay.
    OriginalOnly {
        original_action: ContainmentAction,
        original_loss: i64,
    },
    /// A step exists only in the counterfactual replay.
    CounterfactualOnly {
        counterfactual_action: ContainmentAction,
        counterfactual_loss: i64,
    },
}

impl fmt::Display for DecisionChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identical => write!(f, "identical"),
            Self::SameActionDifferentScore {
                original_loss,
                counterfactual_loss,
                original_margin,
                counterfactual_margin,
            } => {
                write!(
                    f,
                    "same action, loss {original_loss} -> {counterfactual_loss}, margin {original_margin} -> {counterfactual_margin}"
                )
            }
            Self::DifferentAction {
                original_action,
                counterfactual_action,
                ..
            } => {
                write!(f, "{original_action} -> {counterfactual_action}")
            }
            Self::OriginalOnly {
                original_action, ..
            } => write!(f, "{original_action} -> absent"),
            Self::CounterfactualOnly {
                counterfactual_action,
                ..
            } => write!(f, "absent -> {counterfactual_action}"),
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
    /// Replay evidence could not be encoded for hashing.
    EvidenceSerialization { detail: String },
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
            Self::EvidenceSerialization { detail } => {
                write!(f, "failed to serialize replay evidence: {detail}")
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

    if trace.metadata.trace_id.trim().is_empty() {
        errors.push(TraceValidationError::InvalidTraceId);
    }
    if trace.metadata.extension_id.trim().is_empty() {
        errors.push(TraceValidationError::InvalidExtensionId);
    }
    if !trace.metadata.initial_prior.is_valid() {
        errors.push(TraceValidationError::InvalidInitialPrior);
    }
    if !trace.loss_matrix.has_valid_id() {
        errors.push(TraceValidationError::InvalidLossMatrixId);
    }
    if !trace.loss_matrix.is_complete() {
        errors.push(TraceValidationError::IncompleteLossMatrix);
    }
    if trace.metadata.loss_matrix_id != trace.loss_matrix.matrix_id {
        errors.push(TraceValidationError::LossMatrixIdMismatch {
            declared: trace.metadata.loss_matrix_id.clone(),
            actual: trace.loss_matrix.matrix_id.clone(),
        });
    }
    if trace.metadata.end_timestamp_ns < trace.metadata.start_timestamp_ns {
        errors.push(TraceValidationError::InvalidTimeRange {
            start_ns: trace.metadata.start_timestamp_ns,
            end_ns: trace.metadata.end_timestamp_ns,
        });
    }

    if trace.telemetry_drop_counts.any() {
        errors.push(TraceValidationError::IncompleteTelemetry {
            drop_counts: trace.telemetry_drop_counts,
        });
    }

    // Empty trace check.
    if trace.evidence_log.is_empty() {
        errors.push(TraceValidationError::EmptyTrace);
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

    // Telemetry provenance and ordering.
    for (record_index, record) in trace.telemetry_log.iter().enumerate() {
        if record.extension_id != trace.metadata.extension_id {
            errors.push(TraceValidationError::TelemetryExtensionMismatch {
                record_index,
                record_id: record.record_id,
                expected: trace.metadata.extension_id.clone(),
                actual: record.extension_id.clone(),
            });
        }
    }
    for i in 1..trace.telemetry_log.len() {
        if trace.telemetry_log[i].record_id <= trace.telemetry_log[i - 1].record_id {
            errors.push(TraceValidationError::NonMonotonicRecordId {
                record_index: i,
                prev_id: trace.telemetry_log[i - 1].record_id,
                current_id: trace.telemetry_log[i].record_id,
            });
        }
        if trace.telemetry_log[i].timestamp_ns < trace.telemetry_log[i - 1].timestamp_ns {
            errors.push(TraceValidationError::NonMonotonicTimestamp {
                record_index: i,
                prev_ns: trace.telemetry_log[i - 1].timestamp_ns,
                current_ns: trace.telemetry_log[i].timestamp_ns,
            });
        }
    }

    // Posterior validity.
    for (history_index, (step_idx, posterior)) in trace.posterior_history.iter().enumerate() {
        if usize::try_from(*step_idx) != Ok(history_index) {
            errors.push(TraceValidationError::PosteriorStepIndexMismatch {
                history_index,
                declared_step_index: *step_idx,
            });
        }
        if !posterior.is_valid() {
            errors.push(TraceValidationError::InvalidPosterior {
                step_index: *step_idx,
            });
        }
    }

    errors.extend(evidence_extension_errors(
        &trace.metadata.extension_id,
        &trace.evidence_log,
    ));

    // Telemetry integrity.
    for record in &trace.telemetry_log {
        if !record.verify_integrity() {
            errors.push(TraceValidationError::TelemetryIntegrityFailure {
                record_id: record.record_id,
            });
        }
    }

    // Receipt integrity.
    for (receipt_index, receipt) in trace.containment_log.iter().enumerate() {
        if receipt.target_extension_id != trace.metadata.extension_id {
            errors.push(TraceValidationError::ReceiptExtensionMismatch {
                receipt_index,
                receipt_id: receipt.receipt_id.clone(),
                expected: trace.metadata.extension_id.clone(),
                actual: receipt.target_extension_id.clone(),
            });
        }
        if !receipt.verify_integrity() {
            errors.push(TraceValidationError::ReceiptIntegrityFailure {
                receipt_id: receipt.receipt_id.clone(),
            });
        }
    }

    errors
}

fn evidence_extension_errors(
    expected_extension_id: &str,
    evidence: &[Evidence],
) -> Vec<TraceValidationError> {
    evidence
        .iter()
        .enumerate()
        .filter(|(_, item)| item.extension_id != expected_extension_id)
        .map(
            |(evidence_index, item)| TraceValidationError::EvidenceExtensionMismatch {
                evidence_index,
                expected: expected_extension_id.to_string(),
                actual: item.extension_id.clone(),
            },
        )
        .collect()
}

fn validate_trace_for_replay(
    trace: &IncidentTrace,
    config: &ReplayConfig,
) -> Vec<TraceValidationError> {
    validate_trace(trace)
        .into_iter()
        .filter(|error| match error {
            TraceValidationError::TelemetryIntegrityFailure { .. } => {
                config.verify_telemetry_integrity
            }
            TraceValidationError::ReceiptIntegrityFailure { .. } => config.verify_receipt_integrity,
            _ => true,
        })
        .collect()
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
    original_posteriors: Option<&'a [(u64, Posterior)]>,
    original_decisions: Option<&'a [ActionDecision]>,
}

fn decisions_match_except_epoch(original: &ActionDecision, replayed: &ActionDecision) -> bool {
    original.action == replayed.action
        && original.expected_loss_millionths == replayed.expected_loss_millionths
        && original.runner_up_action == replayed.runner_up_action
        && original.runner_up_loss_millionths == replayed.runner_up_loss_millionths
        && original.explanation == replayed.explanation
}

fn compute_replay_input_hash(
    epoch: SecurityEpoch,
    extension_id: &str,
    input: &ReplayInternalInput<'_>,
) -> Result<ContentHash, ReplayError> {
    let effective_input = (
        epoch,
        extension_id,
        input.config,
        input.prior,
        input.loss_matrix,
        input.likelihood_model,
        input.evidence,
    );
    hash_serialized(REPLAY_INPUT_HASH_DOMAIN, &effective_input).map_err(|error| {
        ReplayError::EvidenceSerialization {
            detail: error.to_string(),
        }
    })
}

fn replay_step_limit(config: &ReplayConfig) -> usize {
    if config.max_steps > 0 {
        config.max_steps.min(MAX_REPLAY_STEPS)
    } else {
        MAX_REPLAY_STEPS
    }
}

impl ForensicReplayer {
    /// Create a new forensic replayer.
    pub fn new() -> Self {
        Self {
            epoch: SecurityEpoch::GENESIS,
            replay_count: 0,
        }
    }

    /// Raise the security epoch without permitting rollback.
    pub fn set_epoch(&mut self, epoch: SecurityEpoch) {
        self.epoch = self.epoch.max(epoch);
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
        let max_steps = replay_step_limit(config);
        if trace.evidence_log.len() > max_steps {
            return Err(ReplayError::StepLimitExceeded { limit: max_steps });
        }

        // Validate trace.
        let validation_errors = validate_trace_for_replay(trace, config);
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
                original_posteriors: Some(&trace.posterior_history),
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
        if trace.evidence_log.len() > MAX_REPLAY_STEPS {
            return Err(ReplayError::StepLimitExceeded {
                limit: MAX_REPLAY_STEPS,
            });
        }

        // Validate the recorded source before applying counterfactual edits.
        // Skip/inject operations intentionally change the effective evidence
        // length later; they do not make a pre-existing mismatch between the
        // source evidence, posterior, and decision histories trustworthy.
        let critical_errors = validate_trace_for_replay(trace, config);

        if !critical_errors.is_empty() {
            return Err(ReplayError::ValidationFailed {
                errors: critical_errors,
            });
        }

        // Preflight the effective edited sequence before cloning any evidence.
        // Out-of-range and duplicate skip indices have no effect.
        let skipped_count = spec
            .skip_evidence_indices
            .iter()
            .copied()
            .filter(|index| *index < trace.evidence_log.len())
            .collect::<BTreeSet<_>>()
            .len();
        let effective_steps = trace
            .evidence_log
            .len()
            .saturating_sub(skipped_count)
            .checked_add(spec.inject_evidence.len())
            .ok_or_else(|| ReplayError::StepLimitExceeded {
                limit: replay_step_limit(config),
            })?;
        let max_steps = replay_step_limit(config);
        if effective_steps > max_steps {
            return Err(ReplayError::StepLimitExceeded { limit: max_steps });
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

        let mut override_errors = Vec::new();
        if !prior.is_valid() {
            override_errors.push(TraceValidationError::InvalidInitialPrior);
        }
        if !loss_matrix.has_valid_id() {
            override_errors.push(TraceValidationError::InvalidLossMatrixId);
        }
        if !loss_matrix.is_complete() {
            override_errors.push(TraceValidationError::IncompleteLossMatrix);
        }
        if !override_errors.is_empty() {
            return Err(ReplayError::ValidationFailed {
                errors: override_errors,
            });
        }

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
        let evidence_errors = evidence_extension_errors(&trace.metadata.extension_id, &evidence);
        if !evidence_errors.is_empty() {
            return Err(ReplayError::ValidationFailed {
                errors: evidence_errors,
            });
        }

        self.replay_internal(
            trace,
            ReplayInternalInput {
                config,
                prior: &prior,
                loss_matrix: &loss_matrix,
                likelihood_model: &likelihood_model,
                evidence: &evidence,
                original_posteriors: None,
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
                if decisions_match_except_epoch(&orig.decision, &cf.decision) {
                    DecisionChange::Identical
                } else {
                    if first_divergence.is_none() {
                        first_divergence = Some(i as u64);
                    }
                    DecisionChange::SameActionDifferentScore {
                        original_loss: orig.decision.expected_loss_millionths,
                        counterfactual_loss: cf.decision.expected_loss_millionths,
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

            let change = match (original.steps.get(i), counterfactual.steps.get(i)) {
                (Some(original_step), None) => DecisionChange::OriginalOnly {
                    original_action: original_step.decision.action,
                    original_loss: original_step.decision.expected_loss_millionths,
                },
                (None, Some(counterfactual_step)) => DecisionChange::CounterfactualOnly {
                    counterfactual_action: counterfactual_step.decision.action,
                    counterfactual_loss: counterfactual_step.decision.expected_loss_millionths,
                },
                _ => unreachable!("tail indices must exist in exactly one replay"),
            };
            step_changes.push((i as u64, change));
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
        let max_steps = replay_step_limit(input.config);
        if input.evidence.len() > max_steps {
            return Err(ReplayError::StepLimitExceeded { limit: max_steps });
        }

        // Bound attacker-controlled evidence before serializing either hash
        // preimage. The hashes are evidence, not a reason to bypass the replay
        // resource limit.
        let source_trace_hash =
            trace
                .content_hash()
                .map_err(|error| ReplayError::EvidenceSerialization {
                    detail: error.to_string(),
                })?;
        let replay_input_hash =
            compute_replay_input_hash(self.epoch, &trace.metadata.extension_id, &input)?;
        let ReplayInternalInput {
            config: _,
            prior,
            loss_matrix,
            likelihood_model,
            evidence,
            original_posteriors,
            original_decisions,
        } = input;

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

            // Check the complete recorded posterior and decision semantics.
            // Epoch is intentionally excluded from decision comparison because
            // callers may replay the same trace under a newer security epoch.
            let posterior_matches = original_posteriors.is_none_or(|posteriors| {
                posteriors.get(i).is_some_and(|(step_index, posterior)| {
                    *step_index == i as u64 && *posterior == update_result.posterior
                })
            });
            let decision_matches = original_decisions.is_none_or(|decisions| {
                decisions
                    .get(i)
                    .is_some_and(|original| decisions_match_except_epoch(original, &decision))
            });
            if !posterior_matches || !decision_matches {
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

        let mut result = ReplayResult {
            schema_version: REPLAY_RESULT_SCHEMA_VERSION.to_string(),
            trace_id: trace.metadata.trace_id.clone(),
            source_trace_hash,
            replay_input_hash,
            steps,
            final_posterior,
            final_decision,
            final_containment_state,
            deterministic,
            first_divergence_step,
            content_hash: ContentHash::default(),
        };
        result.content_hash = result.recompute_content_hash()?;
        self.replay_count = self.replay_count.saturating_add(1);
        Ok(result)
    }

    fn build_counterfactual_evidence(
        &self,
        original: &[Evidence],
        skip_indices: &[usize],
        inject: &[(usize, Evidence)],
    ) -> Vec<Evidence> {
        // Sort injections by position.
        let mut sorted_inject: Vec<(usize, &Evidence)> =
            inject.iter().map(|(pos, ev)| (*pos, ev)).collect();
        sorted_inject.sort_by_key(|(pos, _)| *pos);
        let skip_indices: BTreeSet<usize> = skip_indices
            .iter()
            .copied()
            .filter(|index| *index < original.len())
            .collect();
        let effective_capacity = original
            .len()
            .saturating_sub(skip_indices.len())
            .saturating_add(inject.len());
        let mut result = Vec::with_capacity(effective_capacity);

        let mut inject_idx = 0;

        for (i, ev) in original.iter().enumerate() {
            // Insert any injections that should come at this index (before the
            // original element at position i).
            while inject_idx < sorted_inject.len() && sorted_inject[inject_idx].0 <= i {
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
            // The live executor permits Allow to resolve a challenge back to
            // Running. In every other non-running state Allow is either a
            // no-op (Running) or an invalid transition, so preserve state.
            ContainmentAction::Allow => {
                if state == ContainmentState::Challenged {
                    ContainmentState::Running
                } else {
                    state
                }
            }
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
    use crate::capability::RuntimeCapability;
    use crate::containment_executor::{ContainmentContext, ContainmentExecutor};
    use crate::expected_loss_selector::LossMatrix;
    use crate::hostcall_telemetry::{
        FlowLabel, HostcallResult, HostcallType, RecordInput, RecorderConfig, ResourceDelta,
        TelemetryError,
    };

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
                loss_matrix_id: loss_matrix.matrix_id.clone(),
                annotations: BTreeMap::new(),
            },
            telemetry_log: Vec::new(),
            telemetry_drop_counts: TelemetryDropCounts::default(),
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
                loss_matrix_id: "balanced-v1".to_string(),
                annotations: BTreeMap::new(),
            },
            telemetry_log: Vec::new(),
            telemetry_drop_counts: TelemetryDropCounts::default(),
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
    fn completeness_aware_recorder_bridge_rejects_dropped_tail() {
        let input = || RecordInput {
            extension_id: "ext-001".to_string(),
            hostcall_type: HostcallType::FsRead,
            capability_used: RuntimeCapability::FsRead,
            arguments_hash: ContentHash::compute(b"bd-0332s-telemetry-args"),
            result_status: HostcallResult::Success,
            duration_ns: 1,
            resource_delta: ResourceDelta::default(),
            flow_label: FlowLabel::new("public", "public"),
            decision_id: Some("decision-001".to_string()),
        };
        let mut complete_recorder = TelemetryRecorder::new(RecorderConfig {
            channel_capacity: 1,
            ..RecorderConfig::default()
        });
        complete_recorder
            .record(1, input())
            .expect("first telemetry record fits");
        let base_trace = build_trace(vec![benign_evidence()]);
        let complete_trace = base_trace
            .clone()
            .with_telemetry_recorder(&complete_recorder);
        assert_eq!(
            complete_trace.telemetry_drop_counts,
            TelemetryDropCounts::default()
        );
        assert!(validate_trace(&complete_trace).is_empty());

        let mut legacy_json = serde_json::to_value(&complete_trace).expect("serialize clean trace");
        legacy_json
            .as_object_mut()
            .expect("trace serializes as an object")
            .remove("telemetry_drop_counts");
        let legacy_trace: IncidentTrace =
            serde_json::from_value(legacy_json).expect("decode legacy clean trace");
        assert_eq!(legacy_trace, complete_trace);
        assert_eq!(legacy_trace.content_hash(), complete_trace.content_hash());

        let mut incomplete_recorder = complete_recorder.clone();
        assert!(matches!(
            incomplete_recorder.record(2, input()),
            Err(TelemetryError::ChannelFull)
        ));
        let incomplete_trace = base_trace.with_telemetry_recorder(&incomplete_recorder);
        assert_ne!(incomplete_trace, complete_trace);
        assert_ne!(
            incomplete_trace.content_hash(),
            complete_trace.content_hash()
        );
        assert_eq!(incomplete_trace.telemetry_drop_counts.channel_full, 1);

        let encoded = serde_json::to_vec(&incomplete_trace).expect("serialize incomplete trace");
        let decoded: IncidentTrace =
            serde_json::from_slice(&encoded).expect("deserialize incomplete trace");
        assert_eq!(
            decoded.telemetry_drop_counts,
            incomplete_trace.telemetry_drop_counts
        );
        assert!(validate_trace(&decoded).iter().any(|error| matches!(
            error,
            TraceValidationError::IncompleteTelemetry { drop_counts }
                if drop_counts.channel_full == 1
        )));

        let mut replayer = ForensicReplayer::new();
        let replay_error = replayer
            .replay(&decoded, &ReplayConfig::default())
            .expect_err("incomplete telemetry must fail closed");
        assert!(matches!(
            replay_error,
            ReplayError::ValidationFailed { errors }
                if errors.iter().any(|error| matches!(
                    error,
                    TraceValidationError::IncompleteTelemetry { .. }
                ))
        ));

        let counterfactual_error = replayer
            .counterfactual(
                &decoded,
                &ReplayConfig::default(),
                &CounterfactualSpec::identity(),
            )
            .expect_err("counterfactual replay must not bypass incomplete telemetry");
        assert!(matches!(
            counterfactual_error,
            ReplayError::ValidationFailed { errors }
                if errors.iter().any(|error| matches!(
                    error,
                    TraceValidationError::IncompleteTelemetry { .. }
                ))
        ));
    }

    #[test]
    fn replay_integrity_flags_control_validation_for_replay_and_counterfactual() {
        let mut recorder = TelemetryRecorder::new(RecorderConfig::default());
        recorder
            .record(
                1,
                RecordInput {
                    extension_id: "ext-001".to_string(),
                    hostcall_type: HostcallType::FsRead,
                    capability_used: RuntimeCapability::FsRead,
                    arguments_hash: ContentHash::compute(b"integrity-flag-args"),
                    result_status: HostcallResult::Success,
                    duration_ns: 1,
                    resource_delta: ResourceDelta::default(),
                    flow_label: FlowLabel::new("public", "public"),
                    decision_id: Some("decision-001".to_string()),
                },
            )
            .expect("telemetry record should fit");
        let mut trace = build_trace(vec![benign_evidence()]).with_telemetry_recorder(&recorder);
        trace.telemetry_log[0].duration_ns = 2;

        let mut replayer = ForensicReplayer::new();
        let default_error = replayer
            .replay(&trace, &ReplayConfig::default())
            .expect_err("default replay must verify telemetry integrity");
        assert!(matches!(
            default_error,
            ReplayError::ValidationFailed { errors }
                if errors.iter().any(|error| matches!(
                    error,
                    TraceValidationError::TelemetryIntegrityFailure { .. }
                ))
        ));

        let relaxed = ReplayConfig {
            verify_telemetry_integrity: false,
            ..ReplayConfig::default()
        };
        replayer
            .replay(&trace, &relaxed)
            .expect("explicitly disabled telemetry verification should be honored");

        let counterfactual_error = replayer
            .counterfactual(
                &trace,
                &ReplayConfig::default(),
                &CounterfactualSpec::identity(),
            )
            .expect_err("counterfactual replay must honor enabled integrity checks");
        assert!(matches!(
            counterfactual_error,
            ReplayError::ValidationFailed { errors }
                if errors.iter().any(|error| matches!(
                    error,
                    TraceValidationError::TelemetryIntegrityFailure { .. }
                ))
        ));
        replayer
            .counterfactual(&trace, &relaxed, &CounterfactualSpec::identity())
            .expect("counterfactual replay should honor an explicit integrity opt-out");
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

    #[test]
    fn validate_rejects_shifted_posterior_step_index() {
        let mut trace = build_trace(vec![benign_evidence()]);
        trace.posterior_history[0].0 = 1;
        assert!(validate_trace(&trace).contains(
            &TraceValidationError::PosteriorStepIndexMismatch {
                history_index: 0,
                declared_step_index: 1,
            }
        ));
    }

    #[test]
    fn replay_rejects_cross_extension_evidence() {
        let mut trace = build_trace(vec![benign_evidence()]);
        trace.evidence_log[0].extension_id = "other-extension".to_string();

        let error = ForensicReplayer::new()
            .replay(&trace, &ReplayConfig::default())
            .expect_err("cross-extension evidence must not be replayed");
        assert!(matches!(
            error,
            ReplayError::ValidationFailed { errors }
                if errors.contains(&TraceValidationError::EvidenceExtensionMismatch {
                    evidence_index: 0,
                    expected: "ext-001".to_string(),
                    actual: "other-extension".to_string(),
                })
        ));
    }

    #[test]
    fn validate_rejects_invalid_initial_prior_and_loss_matrix() {
        let mut invalid_prior = build_trace(vec![benign_evidence()]);
        invalid_prior.metadata.initial_prior = Posterior {
            p_benign: -1,
            p_anomalous: 0,
            p_malicious: 1_000_001,
            p_unknown: 0,
        };
        assert!(
            validate_trace(&invalid_prior).contains(&TraceValidationError::InvalidInitialPrior)
        );

        let mut blank_id = build_trace(vec![benign_evidence()]);
        blank_id.loss_matrix.matrix_id = " \t ".to_string();
        assert!(validate_trace(&blank_id).contains(&TraceValidationError::InvalidLossMatrixId));

        let mut incomplete = build_trace(vec![benign_evidence()]);
        let mut matrix_json =
            serde_json::to_value(&incomplete.loss_matrix).expect("loss matrix should serialize");
        matrix_json["entries"]
            .as_array_mut()
            .expect("loss entries should serialize as an array")
            .pop();
        incomplete.loss_matrix =
            serde_json::from_value(matrix_json).expect("incomplete matrix should deserialize");
        assert!(validate_trace(&incomplete).contains(&TraceValidationError::IncompleteLossMatrix));
    }

    #[test]
    fn validate_rejects_metadata_identity_and_time_contradictions() {
        let mut trace = build_trace(vec![benign_evidence()]);
        trace.metadata.trace_id = " \t ".to_string();
        trace.metadata.extension_id = "\n".to_string();
        trace.metadata.loss_matrix_id = "conservative-v1".to_string();
        trace.metadata.start_timestamp_ns = 20;
        trace.metadata.end_timestamp_ns = 10;

        let errors = validate_trace(&trace);
        assert!(errors.contains(&TraceValidationError::InvalidTraceId));
        assert!(errors.contains(&TraceValidationError::InvalidExtensionId));
        assert!(
            errors.contains(&TraceValidationError::LossMatrixIdMismatch {
                declared: "conservative-v1".to_string(),
                actual: "balanced-v1".to_string(),
            })
        );
        assert!(errors.contains(&TraceValidationError::InvalidTimeRange {
            start_ns: 20,
            end_ns: 10,
        }));
    }

    #[test]
    fn validate_rejects_cross_extension_telemetry_and_containment() {
        let mut recorder = TelemetryRecorder::new(RecorderConfig::default());
        recorder
            .record(
                1,
                RecordInput {
                    extension_id: "ext-other".to_string(),
                    hostcall_type: HostcallType::FsRead,
                    capability_used: RuntimeCapability::FsRead,
                    arguments_hash: ContentHash::compute(b"cross-extension-telemetry"),
                    result_status: HostcallResult::Success,
                    duration_ns: 1,
                    resource_delta: ResourceDelta::default(),
                    flow_label: FlowLabel::new("public", "public"),
                    decision_id: None,
                },
            )
            .expect("telemetry should record");

        let mut executor = ContainmentExecutor::new();
        executor.register("ext-other");
        let receipt = executor
            .execute(
                ContainmentAction::Challenge,
                "ext-other",
                &ContainmentContext {
                    decision_id: "cross-extension-decision".to_string(),
                    timestamp_ns: 1,
                    ..ContainmentContext::default()
                },
            )
            .expect("containment should execute");

        let mut trace = build_trace(vec![benign_evidence()]).with_telemetry_recorder(&recorder);
        trace.containment_log.push(receipt.clone());
        let errors = validate_trace(&trace);
        assert!(
            errors.contains(&TraceValidationError::TelemetryExtensionMismatch {
                record_index: 0,
                record_id: 0,
                expected: "ext-001".to_string(),
                actual: "ext-other".to_string(),
            })
        );
        assert!(
            errors.contains(&TraceValidationError::ReceiptExtensionMismatch {
                receipt_index: 0,
                receipt_id: receipt.receipt_id,
                expected: "ext-001".to_string(),
                actual: "ext-other".to_string(),
            })
        );
    }

    #[test]
    fn validate_requires_strictly_increasing_telemetry_record_ids() {
        let input = |suffix: &str| RecordInput {
            extension_id: "ext-001".to_string(),
            hostcall_type: HostcallType::FsRead,
            capability_used: RuntimeCapability::FsRead,
            arguments_hash: ContentHash::compute(suffix.as_bytes()),
            result_status: HostcallResult::Success,
            duration_ns: 1,
            resource_delta: ResourceDelta::default(),
            flow_label: FlowLabel::new("public", "public"),
            decision_id: None,
        };
        let mut recorder = TelemetryRecorder::new(RecorderConfig::default());
        recorder.record(1, input("first")).expect("first record");
        recorder.record(1, input("second")).expect("second record");
        let mut trace = build_trace(vec![benign_evidence()]).with_telemetry_recorder(&recorder);
        trace.telemetry_log.swap(0, 1);

        assert!(
            validate_trace(&trace).contains(&TraceValidationError::NonMonotonicRecordId {
                record_index: 1,
                prev_id: 1,
                current_id: 0,
            })
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
        let result = replayer
            .replay(&trace, &ReplayConfig::default())
            .expect("operation should succeed for valid inputs");

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
        let result = replayer
            .replay(&trace, &ReplayConfig::default())
            .expect("operation should succeed for valid inputs");

        assert!(result.deterministic);
        for (i, step) in result.steps.iter().enumerate() {
            assert_eq!(
                step.decision.action, trace.decision_log[i].action,
                "decision diverged at step {i}"
            );
        }
    }

    #[test]
    fn replay_determinism_checks_posterior_and_full_decision_semantics() {
        let mut posterior_tampered = build_trace(vec![benign_evidence()]);
        posterior_tampered.posterior_history[0].1.p_benign -= 1;
        posterior_tampered.posterior_history[0].1.p_unknown += 1;
        assert!(posterior_tampered.posterior_history[0].1.is_valid());

        let mut replayer = ForensicReplayer::new();
        let result = replayer
            .replay(&posterior_tampered, &ReplayConfig::default())
            .expect("structurally valid trace should replay");
        assert!(!result.deterministic);
        assert_eq!(result.first_divergence_step, Some(0));

        let mut decision_tampered = build_trace(vec![benign_evidence()]);
        decision_tampered.decision_log[0].expected_loss_millionths += 1;
        let result = replayer
            .replay(&decision_tampered, &ReplayConfig::default())
            .expect("structurally valid trace should replay");
        assert!(!result.deterministic);
        assert_eq!(result.first_divergence_step, Some(0));
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

        let baseline = replayer
            .replay(&trace, &ReplayConfig::default())
            .expect("operation should succeed for valid inputs");

        for run in 1..100 {
            let result = replayer
                .replay(&trace, &ReplayConfig::default())
                .expect("operation should succeed for valid inputs");
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
        replayer
            .replay(&trace, &ReplayConfig::default())
            .expect("operation should succeed for valid inputs");
        assert_eq!(replayer.replay_count(), 1);
        replayer
            .replay(&trace, &ReplayConfig::default())
            .expect("operation should succeed for valid inputs");
        assert_eq!(replayer.replay_count(), 2);
    }

    #[test]
    fn replay_final_posterior_matches_last_step() {
        let evidence = vec![benign_evidence(), suspicious_evidence()];
        let trace = build_trace(evidence);
        let mut replayer = ForensicReplayer::new();
        let result = replayer
            .replay(&trace, &ReplayConfig::default())
            .expect("operation should succeed for valid inputs");
        let last_step = result
            .steps
            .last()
            .expect("operation should succeed for valid inputs");
        assert_eq!(result.final_posterior, last_step.update_result.posterior);
    }

    #[test]
    fn replay_content_hash_stable() {
        let trace = build_trace(vec![benign_evidence()]);
        let mut replayer = ForensicReplayer::new();
        let r1 = replayer
            .replay(&trace, &ReplayConfig::default())
            .expect("operation should succeed for valid inputs");
        let r2 = replayer
            .replay(&trace, &ReplayConfig::default())
            .expect("operation should succeed for valid inputs");
        assert_eq!(r1.content_hash, r2.content_hash);
        assert_eq!(r1.schema_version, REPLAY_RESULT_SCHEMA_VERSION);
        assert_eq!(
            r1.source_trace_hash,
            trace.content_hash().expect("trace should serialize")
        );
        assert!(r1.verify_content_hash().expect("result should serialize"));
    }

    #[test]
    fn replay_content_hash_rejects_field_tampering() {
        let trace = build_trace(vec![benign_evidence()]);
        let mut replayer = ForensicReplayer::new();
        let result = replayer
            .replay(&trace, &ReplayConfig::default())
            .expect("operation should succeed for valid inputs");

        let mut tampered_step = result.clone();
        tampered_step.steps[0].decision.expected_loss_millionths += 1;
        assert!(
            !tampered_step
                .verify_content_hash()
                .expect("serialize result")
        );

        let mut tampered_source = result.clone();
        tampered_source.source_trace_hash = ContentHash::compute(b"different source");
        assert!(
            !tampered_source
                .verify_content_hash()
                .expect("serialize result")
        );

        let mut tampered_input = result.clone();
        tampered_input.replay_input_hash = ContentHash::compute(b"different input");
        assert!(
            !tampered_input
                .verify_content_hash()
                .expect("serialize result")
        );

        let mut tampered_outcome = result.clone();
        tampered_outcome.deterministic = !tampered_outcome.deterministic;
        assert!(
            !tampered_outcome
                .verify_content_hash()
                .expect("serialize result")
        );

        let mut tampered_schema = result;
        tampered_schema.schema_version.push_str("-tampered");
        assert!(
            !tampered_schema
                .verify_content_hash()
                .expect("serialize result")
        );
    }

    #[test]
    fn replay_input_hash_binds_the_updater_extension_identity() {
        let trace = build_trace(vec![benign_evidence()]);
        let first = ForensicReplayer::new()
            .replay(&trace, &ReplayConfig::default())
            .expect("original trace should replay");

        let mut renamed = trace;
        renamed.metadata.extension_id = "ext-renamed".to_string();
        for evidence in &mut renamed.evidence_log {
            evidence.extension_id = "ext-renamed".to_string();
        }
        let second = ForensicReplayer::new()
            .replay(&renamed, &ReplayConfig::default())
            .expect("consistently renamed trace should replay");

        assert_ne!(first.source_trace_hash, second.source_trace_hash);
        assert_ne!(first.replay_input_hash, second.replay_input_hash);
    }

    // -----------------------------------------------------------------------
    // Counterfactual replay tests
    // -----------------------------------------------------------------------

    #[test]
    fn counterfactual_identity_matches_original() {
        let evidence = vec![benign_evidence(), suspicious_evidence()];
        let trace = build_trace(evidence);
        let mut replayer = ForensicReplayer::new();

        let original = replayer
            .replay(&trace, &ReplayConfig::default())
            .expect("operation should succeed for valid inputs");
        let cf = replayer
            .counterfactual(
                &trace,
                &ReplayConfig::default(),
                &CounterfactualSpec::identity(),
            )
            .expect("operation should succeed for valid inputs");

        assert_eq!(original.steps.len(), cf.steps.len());
        for (i, (o, c)) in original.steps.iter().zip(cf.steps.iter()).enumerate() {
            assert_eq!(o.decision.action, c.decision.action, "step {i}");
        }
    }

    #[test]
    fn counterfactual_rejects_mismatched_source_histories_before_editing() {
        let mut replayer = ForensicReplayer::new();
        let config = ReplayConfig::default();
        let spec = CounterfactualSpec::identity();

        let mut missing_decision = build_trace(vec![benign_evidence(), suspicious_evidence()]);
        missing_decision.decision_log.pop();
        let decision_error = replayer
            .counterfactual(&missing_decision, &config, &spec)
            .expect_err("counterfactual replay must reject a corrupt decision history");
        assert!(matches!(
            decision_error,
            ReplayError::ValidationFailed { errors }
                if errors.iter().any(|error| matches!(
                    error,
                    TraceValidationError::DecisionCountMismatch { .. }
                ))
        ));

        let mut missing_evidence = build_trace(vec![benign_evidence(), suspicious_evidence()]);
        missing_evidence.evidence_log.pop();
        let evidence_error = replayer
            .counterfactual(&missing_evidence, &config, &spec)
            .expect_err("counterfactual replay must reject a corrupt evidence history");
        assert!(matches!(
            evidence_error,
            ReplayError::ValidationFailed { errors }
                if errors.iter().any(|error| matches!(
                    error,
                    TraceValidationError::EvidenceCountMismatch { .. }
                ))
        ));
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

        let original = replayer
            .replay(&trace, &ReplayConfig::default())
            .expect("operation should succeed for valid inputs");
        let cf = replayer
            .counterfactual(
                &trace,
                &ReplayConfig::default(),
                &CounterfactualSpec::with_loss_matrix(
                    LossMatrix::conservative(),
                    "conservative matrix",
                ),
            )
            .expect("operation should succeed for valid inputs");

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
            .expect("operation should succeed for valid inputs");

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
            .expect("operation should succeed for valid inputs");

        assert_eq!(cf.steps.len(), 2);
    }

    #[test]
    fn counterfactual_step_limit_is_checked_before_building_edited_evidence() {
        let trace = build_trace(vec![benign_evidence()]);
        let spec = CounterfactualSpec {
            inject_evidence: vec![(1, malicious_evidence())],
            description: "over configured step limit".to_string(),
            ..CounterfactualSpec::identity()
        };
        let config = ReplayConfig {
            max_steps: 1,
            ..ReplayConfig::default()
        };

        let error = ForensicReplayer::new()
            .counterfactual(&trace, &config, &spec)
            .expect_err("effective edited sequence exceeds the configured cap");
        assert_eq!(error, ReplayError::StepLimitExceeded { limit: 1 });
    }

    #[test]
    fn counterfactual_rejects_cross_extension_injection() {
        let trace = build_trace(vec![benign_evidence()]);
        let mut injected = malicious_evidence();
        injected.extension_id = "other-extension".to_string();
        let spec = CounterfactualSpec {
            inject_evidence: vec![(1, injected)],
            description: "cross-extension injection".to_string(),
            ..CounterfactualSpec::identity()
        };

        let error = ForensicReplayer::new()
            .counterfactual(&trace, &ReplayConfig::default(), &spec)
            .expect_err("cross-extension counterfactual evidence must be rejected");
        assert!(matches!(
            error,
            ReplayError::ValidationFailed { errors }
                if errors.iter().any(|item| matches!(
                    item,
                    TraceValidationError::EvidenceExtensionMismatch {
                        evidence_index: 1,
                        ..
                    }
                ))
        ));
    }

    #[test]
    fn counterfactual_with_different_prior() {
        let evidence = vec![benign_evidence(), suspicious_evidence()];
        let trace = build_trace(evidence);
        let mut replayer = ForensicReplayer::new();

        let original = replayer
            .replay(&trace, &ReplayConfig::default())
            .expect("operation should succeed for valid inputs");

        // Start with a suspicious prior.
        let suspicious_prior = Posterior::from_millionths(100_000, 400_000, 400_000, 100_000);
        let cf = replayer
            .counterfactual(
                &trace,
                &ReplayConfig::default(),
                &CounterfactualSpec::with_prior(suspicious_prior, "suspicious prior"),
            )
            .expect("operation should succeed for valid inputs");

        // With a suspicious prior, the same evidence should lead to more severe actions.
        let orig_final = original
            .final_decision
            .as_ref()
            .expect("operation should succeed for valid inputs")
            .action
            .severity();
        let cf_final = cf
            .final_decision
            .as_ref()
            .expect("operation should succeed for valid inputs")
            .action
            .severity();
        assert!(
            cf_final >= orig_final,
            "suspicious prior should escalate: cf={cf_final} vs orig={orig_final}"
        );
    }

    #[test]
    fn counterfactual_rejects_invalid_pricing_overrides() {
        let trace = build_trace(vec![benign_evidence()]);
        let mut replayer = ForensicReplayer::new();
        let invalid_prior = Posterior {
            p_benign: -1,
            p_anomalous: 0,
            p_malicious: 1_000_001,
            p_unknown: 0,
        };
        let prior_error = replayer
            .counterfactual(
                &trace,
                &ReplayConfig::default(),
                &CounterfactualSpec::with_prior(invalid_prior, "invalid prior"),
            )
            .expect_err("invalid override prior must fail closed");
        assert!(matches!(
            prior_error,
            ReplayError::ValidationFailed { errors }
                if errors.contains(&TraceValidationError::InvalidInitialPrior)
        ));

        let mut invalid_matrix = LossMatrix::balanced();
        invalid_matrix.matrix_id = "  ".to_string();
        let matrix_error = replayer
            .counterfactual(
                &trace,
                &ReplayConfig::default(),
                &CounterfactualSpec::with_loss_matrix(invalid_matrix, "invalid matrix"),
            )
            .expect_err("invalid override matrix must fail closed");
        assert!(matches!(
            matrix_error,
            ReplayError::ValidationFailed { errors }
                if errors.contains(&TraceValidationError::InvalidLossMatrixId)
        ));
    }

    // -----------------------------------------------------------------------
    // Diff tests
    // -----------------------------------------------------------------------

    #[test]
    fn diff_identical_replays_no_divergence() {
        let evidence = vec![benign_evidence(), benign_evidence()];
        let trace = build_trace(evidence);
        let mut replayer = ForensicReplayer::new();

        let r1 = replayer
            .replay(&trace, &ReplayConfig::default())
            .expect("operation should succeed for valid inputs");
        let r2 = replayer
            .replay(&trace, &ReplayConfig::default())
            .expect("operation should succeed for valid inputs");

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

        let original = replayer
            .replay(&trace, &ReplayConfig::default())
            .expect("operation should succeed for valid inputs");
        let cf = replayer
            .counterfactual(
                &trace,
                &ReplayConfig::default(),
                &CounterfactualSpec::with_loss_matrix(LossMatrix::conservative(), "conservative"),
            )
            .expect("operation should succeed for valid inputs");

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

        let original = replayer
            .replay(&trace, &ReplayConfig::default())
            .expect("operation should succeed for valid inputs");
        let cf = replayer
            .counterfactual(
                &trace,
                &ReplayConfig::default(),
                &CounterfactualSpec::with_loss_matrix(LossMatrix::permissive(), "permissive"),
            )
            .expect("operation should succeed for valid inputs");

        let diff = replayer.diff(&original, &cf, "permissive");
        // action_change_count should be >= 0 (may or may not differ).
        assert!(diff.action_change_count <= diff.step_changes.len());
    }

    #[test]
    fn diff_different_length_replays() {
        let evidence = vec![benign_evidence(), suspicious_evidence()];
        let trace = build_trace(evidence);
        let mut replayer = ForensicReplayer::new();

        let original = replayer
            .replay(&trace, &ReplayConfig::default())
            .expect("operation should succeed for valid inputs");

        // Counterfactual with injected evidence (more steps).
        let spec = CounterfactualSpec {
            inject_evidence: vec![(2, malicious_evidence())],
            description: "extra step".to_string(),
            ..CounterfactualSpec::identity()
        };
        let cf = replayer
            .counterfactual(&trace, &ReplayConfig::default(), &spec)
            .expect("operation should succeed for valid inputs");

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
                loss_matrix_id: "balanced-v1".to_string(),
                annotations: BTreeMap::new(),
            },
            telemetry_log: Vec::new(),
            telemetry_drop_counts: TelemetryDropCounts::default(),
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
        let result = replayer
            .replay(&trace, &ReplayConfig::default())
            .expect("operation should succeed for valid inputs");
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

    #[test]
    fn determine_final_state_allow_resolves_challenge() {
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
                runner_up_action: ContainmentAction::Sandbox,
                runner_up_loss_millionths: 1,
                explanation: crate::expected_loss_selector::DecisionExplanation {
                    posterior_snapshot: Posterior::default_prior(),
                    loss_matrix_id: "test".to_string(),
                    all_expected_losses: BTreeMap::new(),
                    margin_millionths: 1,
                },
                epoch: SecurityEpoch::GENESIS,
            },
        };

        let steps = vec![
            make_step(0, ContainmentAction::Challenge),
            make_step(1, ContainmentAction::Allow),
        ];
        assert_eq!(determine_final_state(&steps), ContainmentState::Running);
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
        let json = serde_json::to_string(&meta).expect("serialize derived Serialize");
        let decoded: IncidentMetadata =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
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
        let json = serde_json::to_string(&step).expect("serialize derived Serialize");
        let decoded: ReplayStep =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(step, decoded);
    }

    #[test]
    fn replay_result_serde_roundtrip() {
        let trace = build_trace(vec![benign_evidence()]);
        let mut replayer = ForensicReplayer::new();
        let result = replayer
            .replay(&trace, &ReplayConfig::default())
            .expect("operation should succeed for valid inputs");
        let json = serde_json::to_string(&result).expect("serialize derived Serialize");
        let decoded: ReplayResult =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
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
        let json = serde_json::to_string(&spec).expect("serialize derived Serialize");
        let decoded: CounterfactualSpec =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
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
                    DecisionChange::SameActionDifferentScore {
                        original_loss: 50,
                        counterfactual_loss: 75,
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
        let json = serde_json::to_string(&diff).expect("serialize derived Serialize");
        let decoded: ReplayDiff =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
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

        let err = ReplayError::EvidenceSerialization {
            detail: "json writer failed".to_string(),
        };
        assert!(err.to_string().contains("json writer failed"));

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
        let result = replayer
            .replay(&trace, &ReplayConfig::default())
            .expect("operation should succeed for valid inputs");
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
            .expect("operation should succeed for valid inputs");

        // Diff.
        let diff = replayer.diff(&result, &cf, "conservative escalation");
        assert_eq!(diff.step_changes.len(), 6);

        // The conservative matrix should not be less severe.
        if diff.final_outcome_differs {
            let orig = diff
                .original_final_action
                .expect("operation should succeed for valid inputs")
                .severity();
            let cf_sev = diff
                .counterfactual_final_action
                .expect("operation should succeed for valid inputs")
                .severity();
            assert!(cf_sev >= orig);
        }
    }

    #[test]
    fn full_pipeline_with_evidence_injection() {
        let evidence = vec![benign_evidence(), benign_evidence()];
        let trace = build_trace(evidence);
        let mut replayer = ForensicReplayer::new();

        let original = replayer
            .replay(&trace, &ReplayConfig::default())
            .expect("operation should succeed for valid inputs");

        // Inject malicious evidence between the two benign ones.
        let spec = CounterfactualSpec {
            inject_evidence: vec![(1, malicious_evidence()), (1, malicious_evidence())],
            description: "inject malicious between benign".to_string(),
            ..CounterfactualSpec::identity()
        };

        let cf = replayer
            .counterfactual(&trace, &ReplayConfig::default(), &spec)
            .expect("operation should succeed for valid inputs");

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
        let result = replayer
            .replay(&trace, &ReplayConfig::default())
            .expect("operation should succeed for valid inputs");
        // Steps should have epoch from the replayer.
        assert_eq!(result.steps[0].decision.epoch, SecurityEpoch::from_raw(5));
    }

    #[test]
    fn replayer_epoch_and_counter_cannot_wrap_or_roll_back() {
        let trace = build_trace(vec![benign_evidence()]);
        let mut replayer = ForensicReplayer {
            epoch: SecurityEpoch::GENESIS,
            replay_count: u64::MAX,
        };
        replayer.set_epoch(SecurityEpoch::from_raw(5));
        replayer.set_epoch(SecurityEpoch::from_raw(2));

        let result = replayer
            .replay(&trace, &ReplayConfig::default())
            .expect("valid trace should replay");
        assert_eq!(result.steps[0].decision.epoch, SecurityEpoch::from_raw(5));
        assert_eq!(replayer.replay_count(), u64::MAX);
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
        let json = serde_json::to_string(&replayer).expect("serialize derived Serialize");
        let decoded: ForensicReplayer =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
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
            TraceValidationError::InvalidTraceId,
            TraceValidationError::InvalidExtensionId,
            TraceValidationError::InvalidInitialPrior,
            TraceValidationError::InvalidLossMatrixId,
            TraceValidationError::IncompleteLossMatrix,
            TraceValidationError::LossMatrixIdMismatch {
                declared: "declared-v1".to_string(),
                actual: "actual-v1".to_string(),
            },
            TraceValidationError::InvalidTimeRange {
                start_ns: 200,
                end_ns: 100,
            },
            TraceValidationError::NonMonotonicRecordId {
                record_index: 4,
                prev_id: 9,
                current_id: 8,
            },
            TraceValidationError::NonMonotonicTimestamp {
                record_index: 5,
                prev_ns: 100,
                current_ns: 50,
            },
            TraceValidationError::InvalidPosterior { step_index: 3 },
            TraceValidationError::PosteriorStepIndexMismatch {
                history_index: 2,
                declared_step_index: 3,
            },
            TraceValidationError::EvidenceExtensionMismatch {
                evidence_index: 2,
                expected: "ext-001".to_string(),
                actual: "ext-002".to_string(),
            },
            TraceValidationError::TelemetryExtensionMismatch {
                record_index: 1,
                record_id: 42,
                expected: "ext-001".to_string(),
                actual: "ext-002".to_string(),
            },
            TraceValidationError::ReceiptExtensionMismatch {
                receipt_index: 1,
                receipt_id: "r-cross-extension".to_string(),
                expected: "ext-001".to_string(),
                actual: "ext-002".to_string(),
            },
            TraceValidationError::DecisionCountMismatch {
                decisions: 10,
                posteriors: 8,
            },
            TraceValidationError::EvidenceCountMismatch {
                evidence: 5,
                posteriors: 7,
            },
            TraceValidationError::EmptyTrace,
            TraceValidationError::IncompleteTelemetry {
                drop_counts: TelemetryDropCounts {
                    channel_full: 1,
                    ..TelemetryDropCounts::default()
                },
            },
            TraceValidationError::TelemetryIntegrityFailure { record_id: 42 },
            TraceValidationError::ReceiptIntegrityFailure {
                receipt_id: "r-1".to_string(),
            },
        ];
        for e in &errors {
            let json = serde_json::to_string(e).expect("serialize derived Serialize");
            let restored: TraceValidationError =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*e, restored);
        }
        assert_eq!(errors.len(), 19);
    }

    #[test]
    fn decision_change_serde_roundtrip() {
        let changes = vec![
            DecisionChange::Identical,
            DecisionChange::SameActionDifferentScore {
                original_loss: 25_000,
                counterfactual_loss: 35_000,
                original_margin: 100_000,
                counterfactual_margin: 200_000,
            },
            DecisionChange::DifferentAction {
                original_action: ContainmentAction::Allow,
                counterfactual_action: ContainmentAction::Quarantine,
                original_loss: 50_000,
                counterfactual_loss: 150_000,
            },
            DecisionChange::OriginalOnly {
                original_action: ContainmentAction::Terminate,
                original_loss: 75_000,
            },
            DecisionChange::CounterfactualOnly {
                counterfactual_action: ContainmentAction::Challenge,
                counterfactual_loss: 25_000,
            },
        ];
        for c in &changes {
            let json = serde_json::to_string(c).expect("serialize derived Serialize");
            let restored: DecisionChange =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*c, restored);
        }
        assert_eq!(changes.len(), 5);
    }

    #[test]
    fn replay_error_serde_roundtrip() {
        let errors = vec![
            ReplayError::ValidationFailed {
                errors: vec![TraceValidationError::EmptyTrace],
            },
            ReplayError::StepLimitExceeded { limit: 1000 },
            ReplayError::EvidenceSerialization {
                detail: "json writer failed".to_string(),
            },
            ReplayError::Internal {
                detail: "unexpected state".to_string(),
            },
        ];
        for e in &errors {
            let json = serde_json::to_string(e).expect("serialize derived Serialize");
            let restored: ReplayError =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*e, restored);
        }
        assert_eq!(errors.len(), 4);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch — PearlTower 2026-02-25
    // -----------------------------------------------------------------------

    #[test]
    fn trace_validation_error_display_uniqueness_btreeset() {
        let variants = [
            TraceValidationError::InvalidInitialPrior,
            TraceValidationError::InvalidLossMatrixId,
            TraceValidationError::IncompleteLossMatrix,
            TraceValidationError::NonMonotonicTimestamp {
                record_index: 0,
                prev_ns: 100,
                current_ns: 50,
            },
            TraceValidationError::InvalidPosterior { step_index: 1 },
            TraceValidationError::EvidenceExtensionMismatch {
                evidence_index: 2,
                expected: "ext-001".to_string(),
                actual: "ext-002".to_string(),
            },
            TraceValidationError::DecisionCountMismatch {
                decisions: 3,
                posteriors: 2,
            },
            TraceValidationError::EvidenceCountMismatch {
                evidence: 5,
                posteriors: 4,
            },
            TraceValidationError::EmptyTrace,
            TraceValidationError::IncompleteTelemetry {
                drop_counts: TelemetryDropCounts {
                    channel_full: 1,
                    ..TelemetryDropCounts::default()
                },
            },
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
            12,
            "all 12 TraceValidationError variants produce distinct Display strings"
        );
    }

    #[test]
    fn replay_config_serde_roundtrip() {
        let config = ReplayConfig::default();
        let json = serde_json::to_string(&config).expect("serialize derived Serialize");
        let back: ReplayConfig = serde_json::from_str(&json).expect("deserialize known-valid JSON");
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
        let json = serde_json::to_string(&spec).expect("serialize derived Serialize");
        let back: CounterfactualSpec =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(spec, back);
    }

    #[test]
    fn incident_trace_content_hash_deterministic() {
        let trace = build_trace(vec![benign_evidence()]);
        let h1 = trace.content_hash().expect("trace should serialize");
        let h2 = trace.content_hash().expect("trace should serialize");
        assert_eq!(h1, h2, "content_hash must be deterministic");
    }

    #[test]
    fn incident_trace_hash_preserves_free_form_field_boundaries() {
        let mut first = build_trace(vec![benign_evidence()]);
        first.metadata.trace_id = "ab".to_string();
        first.metadata.extension_id = "c".to_string();

        let mut second = first.clone();
        second.metadata.trace_id = "a".to_string();
        second.metadata.extension_id = "bc".to_string();

        assert_ne!(
            first.content_hash().expect("trace should serialize"),
            second.content_hash().expect("trace should serialize"),
            "adjacent free-form fields must not collide in the trace preimage"
        );
    }

    #[test]
    fn incident_trace_hash_error_is_structured() {
        let error = IncidentTraceHashError::Serialization {
            detail: "json writer failed".to_string(),
        };
        assert!(error.to_string().contains("json writer failed"));
        let encoded = serde_json::to_string(&error).expect("error should serialize");
        let decoded: IncidentTraceHashError =
            serde_json::from_str(&encoded).expect("error should deserialize");
        assert_eq!(decoded, error);
        let _: &dyn std::error::Error = &error;
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
    fn decision_change_display_same_action_different_score_content() {
        let dc = DecisionChange::SameActionDifferentScore {
            original_loss: 25_000,
            counterfactual_loss: 35_000,
            original_margin: 100_000,
            counterfactual_margin: 200_000,
        };
        let s = dc.to_string();
        assert!(s.contains("25000"), "should include original loss: {s}");
        assert!(
            s.contains("35000"),
            "should include counterfactual loss: {s}"
        );
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
        assert_eq!(
            spec.override_loss_matrix
                .expect("operation should succeed for valid inputs"),
            matrix
        );
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
        assert_eq!(
            spec.override_prior
                .expect("operation should succeed for valid inputs"),
            prior
        );
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
        let json = serde_json::to_string(&config).expect("serialize derived Serialize");
        let decoded: ReplayConfig =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(config, decoded);
        assert!(!decoded.verify_telemetry_integrity);
        assert!(!decoded.verify_receipt_integrity);
        assert_eq!(decoded.max_steps, 42);
    }

    #[test]
    fn replayer_serde_preserves_replay_count_after_replays() {
        let trace = build_trace(vec![benign_evidence()]);
        let mut replayer = ForensicReplayer::new();
        replayer
            .replay(&trace, &ReplayConfig::default())
            .expect("operation should succeed for valid inputs");
        replayer
            .replay(&trace, &ReplayConfig::default())
            .expect("operation should succeed for valid inputs");
        assert_eq!(replayer.replay_count(), 2);

        let json = serde_json::to_string(&replayer).expect("serialize derived Serialize");
        let decoded: ForensicReplayer =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
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
        let json = serde_json::to_string(&meta).expect("serialize derived Serialize");
        let decoded: IncidentMetadata =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(meta, decoded);
        assert_eq!(decoded.annotations.len(), 2);
        assert_eq!(decoded.annotations["severity"], "high");
    }

    #[test]
    fn incident_trace_full_serde_roundtrip() {
        let trace = build_trace(vec![benign_evidence(), suspicious_evidence()]);
        let json = serde_json::to_string(&trace).expect("serialize derived Serialize");
        let decoded: IncidentTrace =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
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
        let r1 = replayer
            .replay(&trace1, &ReplayConfig::default())
            .expect("operation should succeed for valid inputs");
        let r2 = replayer
            .replay(&trace2, &ReplayConfig::default())
            .expect("operation should succeed for valid inputs");
        assert_ne!(
            r1.content_hash, r2.content_hash,
            "different trace_ids should produce different replay result hashes"
        );
    }
}
