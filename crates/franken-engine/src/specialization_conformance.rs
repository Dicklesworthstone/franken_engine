//! Specialization-conformance suite: validates semantic equivalence between
//! proof-specialized and unspecialized execution paths.
//!
//! Ensures that security-proof-guided optimization never changes observable
//! behavior, including across policy/proof epoch transitions that invalidate
//! specializations. Each specialization is run twice (specialized and
//! unspecialized baseline), with full comparison of outputs, side-effect
//! traces, and evidence entries.
//!
//! Plan reference: Section 10.7 item 9, bd-2pv.
//! Related: 9I.8 (Security-Proof-Guided Specialization), 10.6 (Performance
//! Program), 10.9 release gate (proof-specialized lanes require 100%
//! specialization-receipt coverage and deterministic fallback correctness).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::EngineObjectId;
use crate::hash_tiers::ContentHash;
use crate::proof_specialization_receipt::{
    OptimizationClass, ProofInput, ReceiptSchemaVersion, SpecializationReceipt,
};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Fixed-point unit: 1_000_000 = 1.0.
const MILLIONTHS: u64 = 1_000_000;

/// Minimum workloads per specialization for semantic parity testing.
const MIN_PARITY_WORKLOADS: usize = 30;

/// Minimum edge-case workloads per specialization.
const MIN_EDGE_CASE_WORKLOADS: usize = 10;

/// Minimum epoch-transition workloads per specialization.
const MIN_EPOCH_TRANSITION_WORKLOADS: usize = 5;

/// Determinism repetitions for confirming identical outcomes.
#[cfg(test)]
const DETERMINISM_REPETITIONS: usize = 5;

// ---------------------------------------------------------------------------
// TransformationType — mirrors OptimizationClass for workload descriptors
// ---------------------------------------------------------------------------

/// The type of specialization transformation applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TransformationType {
    /// Hostcall dispatch elision: proven-unreachable hostcall path removed.
    HostcallDispatchElision,
    /// IFC label check elision: proven-static flow check removed.
    LabelCheckElision,
    /// Dead path removal: unreachable code path eliminated.
    PathRemoval,
    /// Superinstruction fusion: adjacent operations fused.
    SuperinstructionFusion,
}

impl TransformationType {
    /// Map from OptimizationClass to TransformationType.
    pub fn from_optimization_class(class: OptimizationClass) -> Self {
        match class {
            OptimizationClass::HostcallDispatchSpecialization => Self::HostcallDispatchElision,
            OptimizationClass::IfcCheckElision => Self::LabelCheckElision,
            OptimizationClass::PathElimination => Self::PathRemoval,
            OptimizationClass::SuperinstructionFusion => Self::SuperinstructionFusion,
        }
    }

    /// All variants for exhaustive iteration.
    pub const ALL: &'static [TransformationType] = &[
        TransformationType::HostcallDispatchElision,
        TransformationType::LabelCheckElision,
        TransformationType::PathRemoval,
        TransformationType::SuperinstructionFusion,
    ];

    /// Stable string tag for structured logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HostcallDispatchElision => "hostcall_dispatch_elision",
            Self::LabelCheckElision => "label_check_elision",
            Self::PathRemoval => "path_removal",
            Self::SuperinstructionFusion => "superinstruction_fusion",
        }
    }
}

impl fmt::Display for TransformationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// CorpusCategory — workload category classification
// ---------------------------------------------------------------------------

/// Category of a conformance workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CorpusCategory {
    /// Semantic parity workload: exercises specialized code path.
    SemanticParity,
    /// Edge case: boundary inputs at specialization proof validity limits.
    EdgeCase,
    /// Epoch transition: validates fallback during/after epoch change.
    EpochTransition,
}

impl CorpusCategory {
    /// Stable string tag for structured logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SemanticParity => "semantic_parity",
            Self::EdgeCase => "edge_case",
            Self::EpochTransition => "epoch_transition",
        }
    }

    /// Minimum workload count required for this category.
    pub fn min_count(&self) -> usize {
        match self {
            Self::SemanticParity => MIN_PARITY_WORKLOADS,
            Self::EdgeCase => MIN_EDGE_CASE_WORKLOADS,
            Self::EpochTransition => MIN_EPOCH_TRANSITION_WORKLOADS,
        }
    }
}

impl fmt::Display for CorpusCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// WorkloadOutcome — observable execution result
// ---------------------------------------------------------------------------

/// Observable outcome of a single execution (specialized or unspecialized).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadOutcome {
    /// Return value (deterministic serialization).
    pub return_value: String,
    /// Ordered side-effect trace (hostcalls issued, state mutations).
    pub side_effect_trace: Vec<SideEffect>,
    /// Exceptions thrown (in order).
    pub exceptions: Vec<String>,
    /// Evidence entries emitted (in order).
    pub evidence_entries: Vec<String>,
}

impl WorkloadOutcome {
    /// Compute a content hash over the deterministic canonical form.
    pub fn content_hash(&self) -> ContentHash {
        let canonical = serde_json::to_vec(self).unwrap_or_default();
        ContentHash::compute(&canonical)
    }
}

/// A single observable side effect.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SideEffect {
    /// Type of side effect.
    pub effect_type: String,
    /// Deterministic description.
    pub description: String,
    /// Ordered position in trace.
    pub sequence: u64,
}

// ---------------------------------------------------------------------------
// SpecializationWorkload — a single test workload
// ---------------------------------------------------------------------------

/// A test workload for specialization conformance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecializationWorkload {
    /// Unique workload identifier.
    pub workload_id: String,
    /// Corpus category.
    pub category: CorpusCategory,
    /// Input data (deterministic).
    pub input: String,
    /// Expected output (deterministic).
    pub expected_output: String,
    /// Expected side effects.
    pub expected_side_effects: Vec<SideEffect>,
}

// ---------------------------------------------------------------------------
// SpecializationInventoryEntry — a specialization under test
// ---------------------------------------------------------------------------

/// Inventory entry for a specialization to be tested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecializationInventoryEntry {
    /// Specialization identifier (receipt ID).
    pub specialization_id: EngineObjectId,
    /// Slot or extension that owns this specialization.
    pub slot_id: String,
    /// Proof inputs justifying the specialization.
    pub proof_inputs: Vec<ProofInput>,
    /// The transformation type applied.
    pub transformation_type: TransformationType,
    /// Optimization receipt content hash.
    pub optimization_receipt_hash: ContentHash,
    /// Rollback token hash for reverting to baseline.
    pub rollback_token_hash: ContentHash,
    /// Validity epoch of this specialization.
    pub validity_epoch: SecurityEpoch,
    /// Reference to the unspecialized fallback path.
    pub fallback_path: String,
}

// ---------------------------------------------------------------------------
// DifferentialOutcome — per-workload comparison result
// ---------------------------------------------------------------------------

/// Verdict for a single workload comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ComparisonVerdict {
    /// Specialized and unspecialized outputs are identical.
    Match,
    /// Semantic divergence detected (P0 bug).
    Diverge,
}

impl ComparisonVerdict {
    pub fn is_match(&self) -> bool {
        matches!(self, Self::Match)
    }

    pub fn is_diverge(&self) -> bool {
        matches!(self, Self::Diverge)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Match => "match",
            Self::Diverge => "diverge",
        }
    }
}

impl fmt::Display for ComparisonVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Result of running a workload in both specialized and unspecialized modes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialResult {
    /// Trace identifier for this execution pair.
    pub trace_id: String,
    /// Specialization being tested.
    pub specialization_id: EngineObjectId,
    /// Workload identifier.
    pub workload_id: String,
    /// Corpus category.
    pub corpus_category: CorpusCategory,
    /// Comparison verdict.
    pub outcome: ComparisonVerdict,
    /// Specialized path execution time (microseconds).
    pub specialized_duration_us: u64,
    /// Unspecialized path execution time (microseconds).
    pub unspecialized_duration_us: u64,
    /// Whether epoch transition was tested.
    pub epoch_transition_tested: bool,
    /// Fallback outcome (only set if epoch transition tested).
    pub fallback_outcome: Option<FallbackOutcome>,
    /// Receipt validation result.
    pub receipt_valid: bool,
    /// Divergence detail (only set if divergence detected).
    pub divergence_detail: Option<DivergenceDetail>,
}

/// Detail about a semantic divergence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceDetail {
    /// Which component diverged.
    pub divergence_kind: DivergenceKind,
    /// Specialized output summary.
    pub specialized_summary: String,
    /// Unspecialized output summary.
    pub unspecialized_summary: String,
}

/// Classification of divergence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DivergenceKind {
    /// Return values differ.
    ReturnValue,
    /// Side-effect traces differ.
    SideEffectTrace,
    /// Exception sequences differ.
    ExceptionSequence,
    /// Evidence emission differs.
    EvidenceEmission,
}

impl DivergenceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReturnValue => "return_value",
            Self::SideEffectTrace => "side_effect_trace",
            Self::ExceptionSequence => "exception_sequence",
            Self::EvidenceEmission => "evidence_emission",
        }
    }
}

impl fmt::Display for DivergenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// FallbackOutcome — epoch transition fallback result
// ---------------------------------------------------------------------------

/// Outcome of the epoch-transition fallback validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FallbackOutcome {
    /// Successful deterministic fallback to unspecialized path.
    Success {
        /// Evidence entry emitted by the fallback.
        invalidation_evidence_id: String,
    },
    /// Fallback failed: crash, incorrect output, or capability leak.
    Failure {
        /// Reason the fallback failed.
        reason: String,
    },
}

impl FallbackOutcome {
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success { .. })
    }

    pub fn is_failure(&self) -> bool {
        matches!(self, Self::Failure { .. })
    }
}

// ---------------------------------------------------------------------------
// CompareOutcomesInput — input struct for differential comparison
// ---------------------------------------------------------------------------

/// Input parameters for a single differential-execution comparison.
/// Extracted from `compare_outcomes` to satisfy the 7-argument limit.
#[derive(Debug, Clone)]
pub struct CompareOutcomesInput<'a> {
    pub specialization_id: &'a EngineObjectId,
    pub workload_id: &'a str,
    pub category: CorpusCategory,
    pub specialized: &'a WorkloadOutcome,
    pub unspecialized: &'a WorkloadOutcome,
    pub specialized_duration_us: u64,
    pub unspecialized_duration_us: u64,
    pub epoch_transition_tested: bool,
    pub fallback_outcome: Option<FallbackOutcome>,
    pub receipt_valid: bool,
}

// ---------------------------------------------------------------------------
// EpochTransitionSimulation — simulated epoch change parameters
// ---------------------------------------------------------------------------

/// Parameters for simulating a policy/proof epoch transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochTransitionSimulation {
    /// Old epoch (before transition).
    pub old_epoch: SecurityEpoch,
    /// New epoch (after transition).
    pub new_epoch: SecurityEpoch,
    /// Specialization IDs to invalidate.
    pub invalidated_specialization_ids: Vec<EngineObjectId>,
    /// Whether proof artifacts were revoked.
    pub proof_revoked: bool,
    /// Timestamp of the simulated transition.
    pub transition_timestamp_ns: u64,
}

// ---------------------------------------------------------------------------
// InvalidationEvidence — epoch-transition evidence entry
// ---------------------------------------------------------------------------

/// Evidence entry emitted when a specialization is invalidated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidationEvidence {
    /// Specialization that was invalidated.
    pub specialization_id: EngineObjectId,
    /// Reason for invalidation.
    pub invalidation_reason: String,
    /// Old epoch.
    pub epoch_old: SecurityEpoch,
    /// New epoch.
    pub epoch_new: SecurityEpoch,
    /// Rollback token hash used to revert.
    pub rollback_token: ContentHash,
    /// Outcome of the fallback execution.
    pub fallback_outcome: FallbackOutcome,
}

// ---------------------------------------------------------------------------
// ReceiptValidationResult — optimization receipt check
// ---------------------------------------------------------------------------

/// Result of validating a specialization's optimization receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptValidationResult {
    /// Receipt ID validated.
    pub receipt_id: EngineObjectId,
    /// Whether the receipt is well-formed.
    pub well_formed: bool,
    /// Whether the equivalence evidence hash matches.
    pub equivalence_hash_matches: bool,
    /// Whether the rollback token is validated.
    pub rollback_validated: bool,
    /// Whether the proof inputs are consistent.
    pub proof_inputs_consistent: bool,
    /// Schema version of the receipt.
    pub schema_version: ReceiptSchemaVersion,
    /// Overall pass/fail.
    pub valid: bool,
    /// Failure reasons (empty if valid).
    pub failure_reasons: Vec<String>,
}

impl ReceiptValidationResult {
    /// Returns true only if all checks pass.
    pub fn is_valid(&self) -> bool {
        self.valid
    }
}

// ---------------------------------------------------------------------------
// PerSpecializationVerdict — aggregate per-specialization result
// ---------------------------------------------------------------------------

/// Aggregate verdict for one specialization across all workloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerSpecializationVerdict {
    /// Specialization tested.
    pub specialization_id: EngineObjectId,
    /// Number of semantic parity workloads run.
    pub parity_workloads_run: usize,
    /// Number of edge case workloads run.
    pub edge_case_workloads_run: usize,
    /// Number of epoch transition workloads run.
    pub epoch_transition_workloads_run: usize,
    /// Total divergences detected.
    pub divergence_count: usize,
    /// Epoch transition fallback failures.
    pub fallback_failures: usize,
    /// Receipt validation result.
    pub receipt_validation: ReceiptValidationResult,
    /// Overall pass/fail.
    pub passed: bool,
}

impl PerSpecializationVerdict {
    /// True if all checks passed.
    pub fn is_passed(&self) -> bool {
        self.passed
    }

    /// True if corpus coverage meets minimums.
    pub fn corpus_coverage_sufficient(&self) -> bool {
        self.parity_workloads_run >= MIN_PARITY_WORKLOADS
            && self.edge_case_workloads_run >= MIN_EDGE_CASE_WORKLOADS
            && self.epoch_transition_workloads_run >= MIN_EPOCH_TRANSITION_WORKLOADS
    }
}

// ---------------------------------------------------------------------------
// ConformanceEvidenceArtifact — final output artifact
// ---------------------------------------------------------------------------

/// Final evidence artifact produced by the conformance suite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceEvidenceArtifact {
    /// Suite run identifier.
    pub run_id: String,
    /// Policy ID active during the run.
    pub policy_id: String,
    /// Current security epoch at run time.
    pub epoch: SecurityEpoch,
    /// Per-specialization verdicts.
    pub verdicts: Vec<PerSpecializationVerdict>,
    /// Total specializations tested.
    pub total_specializations: usize,
    /// Total workloads executed.
    pub total_workloads: usize,
    /// Total divergences across all specializations.
    pub total_divergences: usize,
    /// Total fallback failures.
    pub total_fallback_failures: usize,
    /// Total receipt validation failures.
    pub total_receipt_failures: usize,
    /// Specialization registry content hash at run time.
    pub registry_hash: ContentHash,
    /// Environment fingerprint for reproducibility.
    pub environment_fingerprint: String,
    /// Overall CI gate pass/fail.
    pub ci_gate_passed: bool,
    /// Timestamp of the run.
    pub timestamp_ns: u64,
}

impl ConformanceEvidenceArtifact {
    /// True if the suite passed all checks.
    pub fn is_passed(&self) -> bool {
        self.ci_gate_passed
    }

    /// Number of specializations that failed.
    pub fn failed_specialization_count(&self) -> usize {
        self.verdicts.iter().filter(|v| !v.passed).count()
    }

    /// Serialize to deterministic JSONL.
    pub fn to_jsonl(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// ConformanceLog — per-workload structured log entry
// ---------------------------------------------------------------------------

/// Structured log entry for conformance suite (stable keys).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceLog {
    pub trace_id: String,
    pub specialization_id: String,
    pub workload_id: String,
    pub corpus_category: CorpusCategory,
    pub outcome: ComparisonVerdict,
    pub specialized_duration_us: u64,
    pub unspecialized_duration_us: u64,
    pub epoch_transition_tested: bool,
    pub fallback_outcome: Option<String>,
    pub receipt_valid: bool,
}

// ---------------------------------------------------------------------------
// ConformanceError — suite errors
// ---------------------------------------------------------------------------

/// Errors that can occur during conformance suite execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConformanceError {
    /// Insufficient workloads for a corpus category.
    InsufficientCorpus {
        specialization_id: String,
        category: CorpusCategory,
        required: usize,
        found: usize,
    },
    /// Missing specialization in registry.
    SpecializationNotFound { specialization_id: String },
    /// Receipt validation failed.
    ReceiptInvalid {
        receipt_id: String,
        reasons: Vec<String>,
    },
    /// Registry sync error: new specialization without test corpus.
    MissingCorpus { specialization_id: String },
    /// Internal execution error.
    ExecutionError { message: String },
}

impl fmt::Display for ConformanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientCorpus {
                specialization_id,
                category,
                required,
                found,
            } => write!(
                f,
                "insufficient corpus for {specialization_id}/{category}: need {required}, found {found}"
            ),
            Self::SpecializationNotFound { specialization_id } => {
                write!(f, "specialization not found: {specialization_id}")
            }
            Self::ReceiptInvalid {
                receipt_id,
                reasons,
            } => write!(
                f,
                "receipt invalid for {receipt_id}: {}",
                reasons.join("; ")
            ),
            Self::MissingCorpus { specialization_id } => {
                write!(f, "missing test corpus for: {specialization_id}")
            }
            Self::ExecutionError { message } => write!(f, "execution error: {message}"),
        }
    }
}

// ---------------------------------------------------------------------------
// SpecializationConformanceEngine — main engine
// ---------------------------------------------------------------------------

/// Main engine for running specialization-conformance validation.
///
/// Implements the differential execution pattern: for each specialization,
/// run workloads with specialization active vs disabled, compare outputs.
pub struct SpecializationConformanceEngine {
    /// Policy ID for structured logging.
    policy_id: String,
    /// Current security epoch.
    current_epoch: SecurityEpoch,
    /// Registered specialization inventory.
    inventory: BTreeMap<String, SpecializationInventoryEntry>,
    /// Per-specialization test corpora.
    corpora: BTreeMap<String, Vec<SpecializationWorkload>>,
    /// Collected differential results.
    results: Vec<DifferentialResult>,
    /// Collected conformance log entries.
    logs: Vec<ConformanceLog>,
    /// Errors encountered during execution.
    errors: Vec<ConformanceError>,
    /// Next trace sequence.
    trace_seq: u64,
}

impl SpecializationConformanceEngine {
    /// Create a new conformance engine.
    pub fn new(policy_id: impl Into<String>, epoch: SecurityEpoch) -> Self {
        Self {
            policy_id: policy_id.into(),
            current_epoch: epoch,
            inventory: BTreeMap::new(),
            corpora: BTreeMap::new(),
            results: Vec::new(),
            logs: Vec::new(),
            errors: Vec::new(),
            trace_seq: 0,
        }
    }

    // --- Accessors ---

    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    pub fn current_epoch(&self) -> SecurityEpoch {
        self.current_epoch
    }

    pub fn inventory(&self) -> &BTreeMap<String, SpecializationInventoryEntry> {
        &self.inventory
    }

    pub fn results(&self) -> &[DifferentialResult] {
        &self.results
    }

    pub fn logs(&self) -> &[ConformanceLog] {
        &self.logs
    }

    pub fn errors(&self) -> &[ConformanceError] {
        &self.errors
    }

    pub fn specialization_count(&self) -> usize {
        self.inventory.len()
    }

    pub fn total_workloads_run(&self) -> usize {
        self.results.len()
    }

    pub fn total_divergences(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.outcome.is_diverge())
            .count()
    }

    pub fn total_matches(&self) -> usize {
        self.results.iter().filter(|r| r.outcome.is_match()).count()
    }

    // --- Registration ---

    /// Register a specialization in the inventory.
    pub fn register_specialization(&mut self, entry: SpecializationInventoryEntry) {
        let key = format!("{}", entry.specialization_id);
        self.inventory.insert(key, entry);
    }

    /// Register a test corpus for a specialization.
    pub fn register_corpus(
        &mut self,
        specialization_id: &str,
        workloads: Vec<SpecializationWorkload>,
    ) {
        self.corpora
            .insert(specialization_id.to_string(), workloads);
    }

    // --- Next trace ID ---

    fn next_trace_id(&mut self) -> String {
        self.trace_seq += 1;
        format!("conformance-{}", self.trace_seq)
    }

    // --- Differential execution ---

    /// Compare two workload outcomes and produce a differential result.
    pub fn compare_outcomes(&mut self, input: &CompareOutcomesInput<'_>) -> DifferentialResult {
        let trace_id = self.next_trace_id();
        let specialization_id = input.specialization_id;
        let workload_id = input.workload_id;
        let category = input.category;
        let specialized = input.specialized;
        let unspecialized = input.unspecialized;
        let specialized_duration_us = input.specialized_duration_us;
        let unspecialized_duration_us = input.unspecialized_duration_us;
        let epoch_transition_tested = input.epoch_transition_tested;
        let fallback_outcome = input.fallback_outcome.clone();
        let receipt_valid = input.receipt_valid;

        let divergence_detail = if specialized.return_value != unspecialized.return_value {
            Some(DivergenceDetail {
                divergence_kind: DivergenceKind::ReturnValue,
                specialized_summary: specialized.return_value.clone(),
                unspecialized_summary: unspecialized.return_value.clone(),
            })
        } else if specialized.side_effect_trace != unspecialized.side_effect_trace {
            Some(DivergenceDetail {
                divergence_kind: DivergenceKind::SideEffectTrace,
                specialized_summary: format!("{} effects", specialized.side_effect_trace.len()),
                unspecialized_summary: format!("{} effects", unspecialized.side_effect_trace.len()),
            })
        } else if specialized.exceptions != unspecialized.exceptions {
            Some(DivergenceDetail {
                divergence_kind: DivergenceKind::ExceptionSequence,
                specialized_summary: format!("{} exceptions", specialized.exceptions.len()),
                unspecialized_summary: format!("{} exceptions", unspecialized.exceptions.len()),
            })
        } else if specialized.evidence_entries != unspecialized.evidence_entries {
            Some(DivergenceDetail {
                divergence_kind: DivergenceKind::EvidenceEmission,
                specialized_summary: format!("{} entries", specialized.evidence_entries.len()),
                unspecialized_summary: format!("{} entries", unspecialized.evidence_entries.len()),
            })
        } else {
            None
        };

        let outcome = if divergence_detail.is_some() {
            ComparisonVerdict::Diverge
        } else {
            ComparisonVerdict::Match
        };

        let result = DifferentialResult {
            trace_id: trace_id.clone(),
            specialization_id: specialization_id.clone(),
            workload_id: workload_id.to_string(),
            corpus_category: category,
            outcome,
            specialized_duration_us,
            unspecialized_duration_us,
            epoch_transition_tested,
            fallback_outcome,
            receipt_valid,
            divergence_detail,
        };

        // Log entry
        self.logs.push(ConformanceLog {
            trace_id,
            specialization_id: format!("{}", specialization_id),
            workload_id: workload_id.to_string(),
            corpus_category: category,
            outcome,
            specialized_duration_us,
            unspecialized_duration_us,
            epoch_transition_tested,
            fallback_outcome: Some(result.fallback_outcome.as_ref().map_or_else(
                || "not_tested".to_string(),
                |fo| match fo {
                    FallbackOutcome::Success { .. } => "success".to_string(),
                    FallbackOutcome::Failure { reason } => format!("failure:{reason}"),
                },
            )),
            receipt_valid,
        });

        self.results.push(result.clone());
        result
    }

    // --- Corpus validation ---

    /// Validate that the corpus for a specialization meets minimum requirements.
    pub fn validate_corpus(&self, specialization_id: &str) -> Vec<ConformanceError> {
        let mut errors = Vec::new();

        let workloads = match self.corpora.get(specialization_id) {
            Some(w) => w,
            None => {
                errors.push(ConformanceError::MissingCorpus {
                    specialization_id: specialization_id.to_string(),
                });
                return errors;
            }
        };

        let parity_count = workloads
            .iter()
            .filter(|w| w.category == CorpusCategory::SemanticParity)
            .count();
        let edge_count = workloads
            .iter()
            .filter(|w| w.category == CorpusCategory::EdgeCase)
            .count();
        let epoch_count = workloads
            .iter()
            .filter(|w| w.category == CorpusCategory::EpochTransition)
            .count();

        if parity_count < MIN_PARITY_WORKLOADS {
            errors.push(ConformanceError::InsufficientCorpus {
                specialization_id: specialization_id.to_string(),
                category: CorpusCategory::SemanticParity,
                required: MIN_PARITY_WORKLOADS,
                found: parity_count,
            });
        }
        if edge_count < MIN_EDGE_CASE_WORKLOADS {
            errors.push(ConformanceError::InsufficientCorpus {
                specialization_id: specialization_id.to_string(),
                category: CorpusCategory::EdgeCase,
                required: MIN_EDGE_CASE_WORKLOADS,
                found: edge_count,
            });
        }
        if epoch_count < MIN_EPOCH_TRANSITION_WORKLOADS {
            errors.push(ConformanceError::InsufficientCorpus {
                specialization_id: specialization_id.to_string(),
                category: CorpusCategory::EpochTransition,
                required: MIN_EPOCH_TRANSITION_WORKLOADS,
                found: epoch_count,
            });
        }

        errors
    }

    // --- Receipt validation ---

    /// Validate a specialization receipt's structural integrity.
    pub fn validate_receipt(
        &self,
        receipt: &SpecializationReceipt,
        equivalence_evidence_hash: &ContentHash,
    ) -> ReceiptValidationResult {
        let mut failure_reasons = Vec::new();

        // Schema version compatibility
        let schema_ok = ReceiptSchemaVersion::CURRENT.is_compatible_with(&receipt.schema_version);
        if !schema_ok {
            failure_reasons.push(format!(
                "incompatible schema version: {}",
                receipt.schema_version
            ));
        }

        // Receipt well-formedness
        let well_formed =
            !receipt.proof_inputs.is_empty() && receipt.validity_epoch == self.current_epoch;
        if receipt.proof_inputs.is_empty() {
            failure_reasons.push("empty proof inputs".to_string());
        }
        if receipt.validity_epoch != self.current_epoch {
            failure_reasons.push(format!(
                "epoch mismatch: receipt={}, current={}",
                receipt.validity_epoch.as_u64(),
                self.current_epoch.as_u64()
            ));
        }

        // Equivalence evidence hash match: compare against the first
        // differential-test hash (the canonical evidence hash for this suite).
        let equiv_hash_matches = receipt
            .equivalence_evidence
            .differential_test_hashes
            .first()
            .is_some_and(|h| h == equivalence_evidence_hash);
        if !equiv_hash_matches {
            failure_reasons.push("equivalence evidence hash mismatch".to_string());
        }

        // Rollback token validated
        let rollback_validated = receipt.rollback_token.validated;
        if !rollback_validated {
            failure_reasons.push("rollback token not validated".to_string());
        }

        // Proof inputs consistency
        let proof_inputs_consistent = receipt
            .proof_inputs
            .iter()
            .all(|p| p.proof_epoch == receipt.validity_epoch && p.validity_window_ticks > 0);
        if !proof_inputs_consistent {
            failure_reasons.push("proof inputs inconsistent with receipt epoch".to_string());
        }

        let valid = failure_reasons.is_empty();

        ReceiptValidationResult {
            receipt_id: receipt.receipt_id.clone(),
            well_formed,
            equivalence_hash_matches: equiv_hash_matches,
            rollback_validated,
            proof_inputs_consistent,
            schema_version: receipt.schema_version,
            valid,
            failure_reasons,
        }
    }

    // --- Epoch transition simulation ---

    /// Simulate an epoch transition and validate fallback behavior.
    pub fn simulate_epoch_transition(
        &mut self,
        simulation: &EpochTransitionSimulation,
    ) -> Vec<InvalidationEvidence> {
        let mut evidence = Vec::new();

        for spec_id in &simulation.invalidated_specialization_ids {
            let key = format!("{}", spec_id);
            let entry = self.inventory.get(&key);

            let fallback_outcome = if let Some(inv_entry) = entry {
                if inv_entry.validity_epoch == simulation.old_epoch {
                    FallbackOutcome::Success {
                        invalidation_evidence_id: format!(
                            "inv-{}-{}",
                            spec_id, simulation.transition_timestamp_ns
                        ),
                    }
                } else {
                    FallbackOutcome::Failure {
                        reason: format!(
                            "epoch mismatch: entry={}, old={}",
                            inv_entry.validity_epoch.as_u64(),
                            simulation.old_epoch.as_u64()
                        ),
                    }
                }
            } else {
                FallbackOutcome::Failure {
                    reason: format!("specialization not in inventory: {spec_id}"),
                }
            };

            let rollback_token = entry
                .map(|e| e.rollback_token_hash)
                .unwrap_or_else(|| ContentHash::compute(b"missing"));

            evidence.push(InvalidationEvidence {
                specialization_id: spec_id.clone(),
                invalidation_reason: if simulation.proof_revoked {
                    "proof_revoked".to_string()
                } else {
                    "epoch_change".to_string()
                },
                epoch_old: simulation.old_epoch,
                epoch_new: simulation.new_epoch,
                rollback_token,
                fallback_outcome,
            });
        }

        // Update current epoch
        self.current_epoch = simulation.new_epoch;

        evidence
    }

    // --- Registry sync check ---

    /// Check that every specialization in the inventory has a corresponding
    /// test corpus. Returns errors for missing corpora.
    pub fn check_registry_sync(&self) -> Vec<ConformanceError> {
        let mut errors = Vec::new();
        for key in self.inventory.keys() {
            if !self.corpora.contains_key(key) {
                errors.push(ConformanceError::MissingCorpus {
                    specialization_id: key.clone(),
                });
            }
        }
        errors
    }

    // --- Evidence artifact production ---

    /// Produce the final conformance evidence artifact.
    pub fn produce_evidence(
        &self,
        run_id: impl Into<String>,
        registry_hash: ContentHash,
        environment_fingerprint: impl Into<String>,
        timestamp_ns: u64,
    ) -> ConformanceEvidenceArtifact {
        let mut verdicts = Vec::new();

        for (key, _entry) in &self.inventory {
            let spec_results: Vec<&DifferentialResult> = self
                .results
                .iter()
                .filter(|r| format!("{}", r.specialization_id) == *key)
                .collect();

            let parity_run = spec_results
                .iter()
                .filter(|r| r.corpus_category == CorpusCategory::SemanticParity)
                .count();
            let edge_run = spec_results
                .iter()
                .filter(|r| r.corpus_category == CorpusCategory::EdgeCase)
                .count();
            let epoch_run = spec_results
                .iter()
                .filter(|r| r.corpus_category == CorpusCategory::EpochTransition)
                .count();

            let divergence_count = spec_results
                .iter()
                .filter(|r| r.outcome.is_diverge())
                .count();
            let fallback_failures = spec_results
                .iter()
                .filter(|r| {
                    r.fallback_outcome
                        .as_ref()
                        .is_some_and(|fo| fo.is_failure())
                })
                .count();

            // Default receipt validation: look for any result with receipt info
            let receipt_valid = spec_results.iter().all(|r| r.receipt_valid);

            let receipt_validation = ReceiptValidationResult {
                receipt_id: _entry.specialization_id.clone(),
                well_formed: receipt_valid,
                equivalence_hash_matches: receipt_valid,
                rollback_validated: receipt_valid,
                proof_inputs_consistent: receipt_valid,
                schema_version: ReceiptSchemaVersion::CURRENT,
                valid: receipt_valid,
                failure_reasons: if receipt_valid {
                    Vec::new()
                } else {
                    vec!["receipt validation failed in differential results".to_string()]
                },
            };

            let passed = divergence_count == 0 && fallback_failures == 0 && receipt_valid;

            verdicts.push(PerSpecializationVerdict {
                specialization_id: _entry.specialization_id.clone(),
                parity_workloads_run: parity_run,
                edge_case_workloads_run: edge_run,
                epoch_transition_workloads_run: epoch_run,
                divergence_count,
                fallback_failures,
                receipt_validation,
                passed,
            });
        }

        let total_divergences = self.total_divergences();
        let total_fallback_failures = verdicts.iter().map(|v| v.fallback_failures).sum::<usize>();
        let total_receipt_failures = verdicts
            .iter()
            .filter(|v| !v.receipt_validation.valid)
            .count();
        let ci_gate_passed =
            total_divergences == 0 && total_fallback_failures == 0 && total_receipt_failures == 0;

        ConformanceEvidenceArtifact {
            run_id: run_id.into(),
            policy_id: self.policy_id.clone(),
            epoch: self.current_epoch,
            total_specializations: self.inventory.len(),
            total_workloads: self.results.len(),
            total_divergences,
            total_fallback_failures,
            total_receipt_failures,
            verdicts,
            registry_hash,
            environment_fingerprint: environment_fingerprint.into(),
            ci_gate_passed,
            timestamp_ns,
        }
    }

    // --- Determinism check ---

    /// Run the same workload N times and confirm identical outcomes.
    pub fn check_determinism(outcomes: &[WorkloadOutcome]) -> bool {
        if outcomes.len() < 2 {
            return true;
        }
        let first_hash = outcomes[0].content_hash();
        outcomes
            .iter()
            .skip(1)
            .all(|o| o.content_hash() == first_hash)
    }

    // --- Performance delta tracking ---

    /// Compute performance delta between specialized and unspecialized runs.
    pub fn compute_performance_delta(
        specialized_duration_us: u64,
        unspecialized_duration_us: u64,
    ) -> PerformanceDelta {
        let speedup_millionths = if unspecialized_duration_us > 0 {
            ((unspecialized_duration_us as i128 - specialized_duration_us as i128)
                * MILLIONTHS as i128
                / unspecialized_duration_us as i128) as i64
        } else {
            0
        };

        PerformanceDelta {
            specialized_duration_us,
            unspecialized_duration_us,
            speedup_millionths,
        }
    }
}

// ---------------------------------------------------------------------------
// PerformanceDelta — performance tracking (not gating)
// ---------------------------------------------------------------------------

/// Performance delta between specialized and unspecialized execution.
///
/// Positive speedup_millionths indicates specialization is faster.
/// This is tracked but NOT gated on by this suite (10.6's responsibility).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceDelta {
    /// Specialized path duration (microseconds).
    pub specialized_duration_us: u64,
    /// Unspecialized path duration (microseconds).
    pub unspecialized_duration_us: u64,
    /// Speedup in millionths (positive = faster). 500_000 = 50% speedup.
    pub speedup_millionths: i64,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_object_id::{self, ObjectDomain, SchemaId};
    use crate::proof_specialization_receipt::ProofType;

    fn schema_id() -> SchemaId {
        SchemaId::from_definition(b"SpecializationConformance.v1")
    }

    fn test_id(tag: &str) -> EngineObjectId {
        engine_object_id::derive_id(
            ObjectDomain::PolicyObject,
            "conformance-test",
            &schema_id(),
            tag.as_bytes(),
        )
        .unwrap()
    }

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(10)
    }

    fn test_proof_input(tag: &str) -> ProofInput {
        ProofInput {
            proof_type: ProofType::CapabilityWitness,
            proof_id: test_id(&format!("proof-{tag}")),
            proof_epoch: test_epoch(),
            validity_window_ticks: 10_000,
        }
    }

    fn make_inventory_entry(tag: &str) -> SpecializationInventoryEntry {
        SpecializationInventoryEntry {
            specialization_id: test_id(&format!("spec-{tag}")),
            slot_id: format!("slot-{tag}"),
            proof_inputs: vec![test_proof_input(tag)],
            transformation_type: TransformationType::HostcallDispatchElision,
            optimization_receipt_hash: ContentHash::compute(format!("receipt-{tag}").as_bytes()),
            rollback_token_hash: ContentHash::compute(format!("rollback-{tag}").as_bytes()),
            validity_epoch: test_epoch(),
            fallback_path: format!("fallback-{tag}"),
        }
    }

    fn make_workload(id: &str, category: CorpusCategory) -> SpecializationWorkload {
        SpecializationWorkload {
            workload_id: id.to_string(),
            category,
            input: format!("input-{id}"),
            expected_output: format!("output-{id}"),
            expected_side_effects: vec![SideEffect {
                effect_type: "hostcall".to_string(),
                description: format!("effect-{id}"),
                sequence: 0,
            }],
        }
    }

    fn matching_outcome() -> WorkloadOutcome {
        WorkloadOutcome {
            return_value: "42".to_string(),
            side_effect_trace: vec![SideEffect {
                effect_type: "hostcall".to_string(),
                description: "call-1".to_string(),
                sequence: 0,
            }],
            exceptions: vec![],
            evidence_entries: vec!["ev-1".to_string()],
        }
    }

    fn diverging_outcome() -> WorkloadOutcome {
        WorkloadOutcome {
            return_value: "99".to_string(),
            side_effect_trace: vec![],
            exceptions: vec![],
            evidence_entries: vec![],
        }
    }

    // -----------------------------------------------------------------------
    // TransformationType tests
    // -----------------------------------------------------------------------

    #[test]
    fn transformation_type_from_optimization_class() {
        assert_eq!(
            TransformationType::from_optimization_class(
                OptimizationClass::HostcallDispatchSpecialization
            ),
            TransformationType::HostcallDispatchElision
        );
        assert_eq!(
            TransformationType::from_optimization_class(OptimizationClass::IfcCheckElision),
            TransformationType::LabelCheckElision
        );
        assert_eq!(
            TransformationType::from_optimization_class(OptimizationClass::PathElimination),
            TransformationType::PathRemoval
        );
        assert_eq!(
            TransformationType::from_optimization_class(OptimizationClass::SuperinstructionFusion),
            TransformationType::SuperinstructionFusion
        );
    }

    #[test]
    fn transformation_type_all_variants() {
        assert_eq!(TransformationType::ALL.len(), 4);
    }

    #[test]
    fn transformation_type_display() {
        assert_eq!(
            TransformationType::HostcallDispatchElision.to_string(),
            "hostcall_dispatch_elision"
        );
        assert_eq!(
            TransformationType::SuperinstructionFusion.to_string(),
            "superinstruction_fusion"
        );
    }

    #[test]
    fn transformation_type_serde_round_trip() {
        for tt in TransformationType::ALL {
            let json = serde_json::to_string(tt).unwrap();
            let back: TransformationType = serde_json::from_str(&json).unwrap();
            assert_eq!(*tt, back);
        }
    }

    // -----------------------------------------------------------------------
    // CorpusCategory tests
    // -----------------------------------------------------------------------

    #[test]
    fn corpus_category_min_counts() {
        assert_eq!(CorpusCategory::SemanticParity.min_count(), 30);
        assert_eq!(CorpusCategory::EdgeCase.min_count(), 10);
        assert_eq!(CorpusCategory::EpochTransition.min_count(), 5);
    }

    #[test]
    fn corpus_category_display() {
        assert_eq!(
            CorpusCategory::SemanticParity.to_string(),
            "semantic_parity"
        );
        assert_eq!(CorpusCategory::EdgeCase.to_string(), "edge_case");
        assert_eq!(
            CorpusCategory::EpochTransition.to_string(),
            "epoch_transition"
        );
    }

    #[test]
    fn corpus_category_serde_round_trip() {
        let categories = [
            CorpusCategory::SemanticParity,
            CorpusCategory::EdgeCase,
            CorpusCategory::EpochTransition,
        ];
        for cat in &categories {
            let json = serde_json::to_string(cat).unwrap();
            let back: CorpusCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(*cat, back);
        }
    }

    // -----------------------------------------------------------------------
    // ComparisonVerdict tests
    // -----------------------------------------------------------------------

    #[test]
    fn comparison_verdict_match() {
        let v = ComparisonVerdict::Match;
        assert!(v.is_match());
        assert!(!v.is_diverge());
        assert_eq!(v.as_str(), "match");
        assert_eq!(v.to_string(), "match");
    }

    #[test]
    fn comparison_verdict_diverge() {
        let v = ComparisonVerdict::Diverge;
        assert!(!v.is_match());
        assert!(v.is_diverge());
        assert_eq!(v.as_str(), "diverge");
        assert_eq!(v.to_string(), "diverge");
    }

    #[test]
    fn comparison_verdict_serde_round_trip() {
        for v in [ComparisonVerdict::Match, ComparisonVerdict::Diverge] {
            let json = serde_json::to_string(&v).unwrap();
            let back: ComparisonVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    // -----------------------------------------------------------------------
    // DivergenceKind tests
    // -----------------------------------------------------------------------

    #[test]
    fn divergence_kind_all_variants() {
        let kinds = [
            DivergenceKind::ReturnValue,
            DivergenceKind::SideEffectTrace,
            DivergenceKind::ExceptionSequence,
            DivergenceKind::EvidenceEmission,
        ];
        let expected_strs = [
            "return_value",
            "side_effect_trace",
            "exception_sequence",
            "evidence_emission",
        ];
        for (k, s) in kinds.iter().zip(expected_strs.iter()) {
            assert_eq!(k.as_str(), *s);
            assert_eq!(k.to_string(), *s);
        }
    }

    #[test]
    fn divergence_kind_serde_round_trip() {
        let kinds = [
            DivergenceKind::ReturnValue,
            DivergenceKind::SideEffectTrace,
            DivergenceKind::ExceptionSequence,
            DivergenceKind::EvidenceEmission,
        ];
        for k in &kinds {
            let json = serde_json::to_string(k).unwrap();
            let back: DivergenceKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*k, back);
        }
    }

    // -----------------------------------------------------------------------
    // FallbackOutcome tests
    // -----------------------------------------------------------------------

    #[test]
    fn fallback_outcome_success() {
        let fo = FallbackOutcome::Success {
            invalidation_evidence_id: "inv-1".to_string(),
        };
        assert!(fo.is_success());
        assert!(!fo.is_failure());
    }

    #[test]
    fn fallback_outcome_failure() {
        let fo = FallbackOutcome::Failure {
            reason: "crash".to_string(),
        };
        assert!(!fo.is_success());
        assert!(fo.is_failure());
    }

    #[test]
    fn fallback_outcome_serde_round_trip() {
        let variants = [
            FallbackOutcome::Success {
                invalidation_evidence_id: "ev-1".to_string(),
            },
            FallbackOutcome::Failure {
                reason: "test".to_string(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: FallbackOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // -----------------------------------------------------------------------
    // WorkloadOutcome tests
    // -----------------------------------------------------------------------

    #[test]
    fn workload_outcome_content_hash_deterministic() {
        let o1 = matching_outcome();
        let o2 = matching_outcome();
        assert_eq!(o1.content_hash(), o2.content_hash());
    }

    #[test]
    fn workload_outcome_content_hash_differs_on_change() {
        let o1 = matching_outcome();
        let o2 = diverging_outcome();
        assert_ne!(o1.content_hash(), o2.content_hash());
    }

    #[test]
    fn workload_outcome_serde_round_trip() {
        let o = matching_outcome();
        let json = serde_json::to_string(&o).unwrap();
        let back: WorkloadOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(o, back);
    }

    // -----------------------------------------------------------------------
    // Engine: registration
    // -----------------------------------------------------------------------

    #[test]
    fn engine_new_and_accessors() {
        let engine = SpecializationConformanceEngine::new("policy-1", test_epoch());
        assert_eq!(engine.policy_id(), "policy-1");
        assert_eq!(engine.current_epoch(), test_epoch());
        assert_eq!(engine.specialization_count(), 0);
        assert_eq!(engine.total_workloads_run(), 0);
        assert_eq!(engine.total_divergences(), 0);
        assert_eq!(engine.total_matches(), 0);
        assert!(engine.results().is_empty());
        assert!(engine.logs().is_empty());
        assert!(engine.errors().is_empty());
    }

    #[test]
    fn engine_register_specialization() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        engine.register_specialization(make_inventory_entry("a"));
        engine.register_specialization(make_inventory_entry("b"));
        assert_eq!(engine.specialization_count(), 2);
    }

    #[test]
    fn engine_register_corpus() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        engine.register_corpus(
            "spec-a",
            vec![make_workload("w1", CorpusCategory::SemanticParity)],
        );
        // Corpus is stored
        assert!(engine.corpora.contains_key("spec-a"));
    }

    // -----------------------------------------------------------------------
    // Engine: compare_outcomes — match
    // -----------------------------------------------------------------------

    #[test]
    fn compare_outcomes_identical_yields_match() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let spec_id = test_id("spec-1");
        let specialized = matching_outcome();
        let unspecialized = matching_outcome();

        let result = engine.compare_outcomes(&CompareOutcomesInput {
            specialization_id: &spec_id,
            workload_id: "w1",
            category: CorpusCategory::SemanticParity,
            specialized: &specialized,
            unspecialized: &unspecialized,
            specialized_duration_us: 100,
            unspecialized_duration_us: 150,
            epoch_transition_tested: false,
            fallback_outcome: None,
            receipt_valid: true,
        });

        assert!(result.outcome.is_match());
        assert!(result.divergence_detail.is_none());
        assert_eq!(result.specialized_duration_us, 100);
        assert_eq!(result.unspecialized_duration_us, 150);
        assert!(result.receipt_valid);
        assert_eq!(engine.total_matches(), 1);
        assert_eq!(engine.total_divergences(), 0);
        assert_eq!(engine.logs().len(), 1);
    }

    // -----------------------------------------------------------------------
    // Engine: compare_outcomes — return value divergence
    // -----------------------------------------------------------------------

    #[test]
    fn compare_outcomes_return_divergence() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let spec_id = test_id("spec-2");
        let specialized = matching_outcome();
        let unspecialized = diverging_outcome();

        let result = engine.compare_outcomes(&CompareOutcomesInput {
            specialization_id: &spec_id,
            workload_id: "w2",
            category: CorpusCategory::SemanticParity,
            specialized: &specialized,
            unspecialized: &unspecialized,
            specialized_duration_us: 100,
            unspecialized_duration_us: 100,
            epoch_transition_tested: false,
            fallback_outcome: None,
            receipt_valid: true,
        });

        assert!(result.outcome.is_diverge());
        let detail = result.divergence_detail.as_ref().unwrap();
        assert_eq!(detail.divergence_kind, DivergenceKind::ReturnValue);
        assert_eq!(detail.specialized_summary, "42");
        assert_eq!(detail.unspecialized_summary, "99");
        assert_eq!(engine.total_divergences(), 1);
    }

    // -----------------------------------------------------------------------
    // Engine: compare_outcomes — side effect divergence
    // -----------------------------------------------------------------------

    #[test]
    fn compare_outcomes_side_effect_divergence() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let spec_id = test_id("spec-3");
        let specialized = matching_outcome();
        let mut unspecialized = matching_outcome();
        unspecialized.side_effect_trace.push(SideEffect {
            effect_type: "extra".to_string(),
            description: "extra-effect".to_string(),
            sequence: 1,
        });

        let result = engine.compare_outcomes(&CompareOutcomesInput {
            specialization_id: &spec_id,
            workload_id: "w3",
            category: CorpusCategory::EdgeCase,
            specialized: &specialized,
            unspecialized: &unspecialized,
            specialized_duration_us: 50,
            unspecialized_duration_us: 60,
            epoch_transition_tested: false,
            fallback_outcome: None,
            receipt_valid: true,
        });

        assert!(result.outcome.is_diverge());
        let detail = result.divergence_detail.as_ref().unwrap();
        assert_eq!(detail.divergence_kind, DivergenceKind::SideEffectTrace);
    }

    // -----------------------------------------------------------------------
    // Engine: compare_outcomes — exception divergence
    // -----------------------------------------------------------------------

    #[test]
    fn compare_outcomes_exception_divergence() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let spec_id = test_id("spec-4");
        let specialized = matching_outcome();
        let mut unspecialized = matching_outcome();
        unspecialized.exceptions.push("TypeError".to_string());

        let result = engine.compare_outcomes(&CompareOutcomesInput {
            specialization_id: &spec_id,
            workload_id: "w4",
            category: CorpusCategory::SemanticParity,
            specialized: &specialized,
            unspecialized: &unspecialized,
            specialized_duration_us: 30,
            unspecialized_duration_us: 35,
            epoch_transition_tested: false,
            fallback_outcome: None,
            receipt_valid: true,
        });

        assert!(result.outcome.is_diverge());
        let detail = result.divergence_detail.as_ref().unwrap();
        assert_eq!(detail.divergence_kind, DivergenceKind::ExceptionSequence);
    }

    // -----------------------------------------------------------------------
    // Engine: compare_outcomes — evidence emission divergence
    // -----------------------------------------------------------------------

    #[test]
    fn compare_outcomes_evidence_divergence() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let spec_id = test_id("spec-5");
        let specialized = matching_outcome();
        let mut unspecialized = matching_outcome();
        unspecialized.evidence_entries.push("ev-extra".to_string());

        let result = engine.compare_outcomes(&CompareOutcomesInput {
            specialization_id: &spec_id,
            workload_id: "w5",
            category: CorpusCategory::SemanticParity,
            specialized: &specialized,
            unspecialized: &unspecialized,
            specialized_duration_us: 20,
            unspecialized_duration_us: 25,
            epoch_transition_tested: false,
            fallback_outcome: None,
            receipt_valid: true,
        });

        assert!(result.outcome.is_diverge());
        let detail = result.divergence_detail.as_ref().unwrap();
        assert_eq!(detail.divergence_kind, DivergenceKind::EvidenceEmission);
    }

    // -----------------------------------------------------------------------
    // Engine: compare_outcomes — with fallback
    // -----------------------------------------------------------------------

    #[test]
    fn compare_outcomes_with_successful_fallback() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let spec_id = test_id("spec-6");
        let outcome = matching_outcome();
        let fb = FallbackOutcome::Success {
            invalidation_evidence_id: "inv-1".to_string(),
        };

        let result = engine.compare_outcomes(&CompareOutcomesInput {
            specialization_id: &spec_id,
            workload_id: "w6",
            category: CorpusCategory::EpochTransition,
            specialized: &outcome,
            unspecialized: &outcome,
            specialized_duration_us: 100,
            unspecialized_duration_us: 100,
            epoch_transition_tested: true,
            fallback_outcome: Some(fb),
            receipt_valid: true,
        });

        assert!(result.outcome.is_match());
        assert!(result.epoch_transition_tested);
        assert!(result.fallback_outcome.as_ref().unwrap().is_success());
    }

    #[test]
    fn compare_outcomes_with_failed_fallback() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let spec_id = test_id("spec-7");
        let outcome = matching_outcome();
        let fb = FallbackOutcome::Failure {
            reason: "crash".to_string(),
        };

        let result = engine.compare_outcomes(&CompareOutcomesInput {
            specialization_id: &spec_id,
            workload_id: "w7",
            category: CorpusCategory::EpochTransition,
            specialized: &outcome,
            unspecialized: &outcome,
            specialized_duration_us: 100,
            unspecialized_duration_us: 100,
            epoch_transition_tested: true,
            fallback_outcome: Some(fb),
            receipt_valid: true,
        });

        assert!(result.outcome.is_match()); // Outcomes match but fallback failed
        assert!(result.fallback_outcome.as_ref().unwrap().is_failure());
    }

    // -----------------------------------------------------------------------
    // Corpus validation
    // -----------------------------------------------------------------------

    #[test]
    fn validate_corpus_missing() {
        let engine = SpecializationConformanceEngine::new("p", test_epoch());
        let errors = engine.validate_corpus("nonexistent");
        assert_eq!(errors.len(), 1);
        assert!(matches!(&errors[0], ConformanceError::MissingCorpus { .. }));
    }

    #[test]
    fn validate_corpus_insufficient_parity() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let workloads: Vec<_> = (0..5)
            .map(|i| make_workload(&format!("w{i}"), CorpusCategory::SemanticParity))
            .collect();
        engine.register_corpus("spec-x", workloads);

        let errors = engine.validate_corpus("spec-x");
        assert!(!errors.is_empty());
        // Should flag insufficient parity (5 < 30) and missing edge/epoch
    }

    #[test]
    fn validate_corpus_sufficient_all_categories() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let mut workloads = Vec::new();
        for i in 0..30 {
            workloads.push(make_workload(
                &format!("p{i}"),
                CorpusCategory::SemanticParity,
            ));
        }
        for i in 0..10 {
            workloads.push(make_workload(&format!("e{i}"), CorpusCategory::EdgeCase));
        }
        for i in 0..5 {
            workloads.push(make_workload(
                &format!("t{i}"),
                CorpusCategory::EpochTransition,
            ));
        }
        engine.register_corpus("spec-y", workloads);

        let errors = engine.validate_corpus("spec-y");
        assert!(errors.is_empty());
    }

    // -----------------------------------------------------------------------
    // Epoch transition simulation
    // -----------------------------------------------------------------------

    #[test]
    fn simulate_epoch_transition_success() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let entry = make_inventory_entry("a");
        let spec_id = entry.specialization_id.clone();
        engine.register_specialization(entry);

        let simulation = EpochTransitionSimulation {
            old_epoch: test_epoch(),
            new_epoch: SecurityEpoch::from_raw(11),
            invalidated_specialization_ids: vec![spec_id.clone()],
            proof_revoked: false,
            transition_timestamp_ns: 1_000_000,
        };

        let evidence = engine.simulate_epoch_transition(&simulation);
        assert_eq!(evidence.len(), 1);
        assert!(evidence[0].fallback_outcome.is_success());
        assert_eq!(evidence[0].invalidation_reason, "epoch_change");
        assert_eq!(evidence[0].epoch_old, test_epoch());
        assert_eq!(evidence[0].epoch_new, SecurityEpoch::from_raw(11));
        assert_eq!(engine.current_epoch(), SecurityEpoch::from_raw(11));
    }

    #[test]
    fn simulate_epoch_transition_proof_revoked() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let entry = make_inventory_entry("b");
        let spec_id = entry.specialization_id.clone();
        engine.register_specialization(entry);

        let simulation = EpochTransitionSimulation {
            old_epoch: test_epoch(),
            new_epoch: SecurityEpoch::from_raw(11),
            invalidated_specialization_ids: vec![spec_id],
            proof_revoked: true,
            transition_timestamp_ns: 2_000_000,
        };

        let evidence = engine.simulate_epoch_transition(&simulation);
        assert_eq!(evidence[0].invalidation_reason, "proof_revoked");
    }

    #[test]
    fn simulate_epoch_transition_missing_spec() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let missing_id = test_id("nonexistent");

        let simulation = EpochTransitionSimulation {
            old_epoch: test_epoch(),
            new_epoch: SecurityEpoch::from_raw(11),
            invalidated_specialization_ids: vec![missing_id],
            proof_revoked: false,
            transition_timestamp_ns: 3_000_000,
        };

        let evidence = engine.simulate_epoch_transition(&simulation);
        assert_eq!(evidence.len(), 1);
        assert!(evidence[0].fallback_outcome.is_failure());
    }

    #[test]
    fn simulate_epoch_transition_epoch_mismatch() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let entry = make_inventory_entry("c");
        let spec_id = entry.specialization_id.clone();
        engine.register_specialization(entry);

        // Simulate with wrong old_epoch
        let simulation = EpochTransitionSimulation {
            old_epoch: SecurityEpoch::from_raw(99),
            new_epoch: SecurityEpoch::from_raw(100),
            invalidated_specialization_ids: vec![spec_id],
            proof_revoked: false,
            transition_timestamp_ns: 4_000_000,
        };

        let evidence = engine.simulate_epoch_transition(&simulation);
        assert!(evidence[0].fallback_outcome.is_failure());
    }

    // -----------------------------------------------------------------------
    // Registry sync check
    // -----------------------------------------------------------------------

    #[test]
    fn check_registry_sync_all_covered() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let entry = make_inventory_entry("a");
        let key = format!("{}", entry.specialization_id);
        engine.register_specialization(entry);
        engine.register_corpus(&key, vec![]);

        let errors = engine.check_registry_sync();
        assert!(errors.is_empty());
    }

    #[test]
    fn check_registry_sync_missing_corpus() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        engine.register_specialization(make_inventory_entry("a"));

        let errors = engine.check_registry_sync();
        assert_eq!(errors.len(), 1);
        assert!(matches!(&errors[0], ConformanceError::MissingCorpus { .. }));
    }

    // -----------------------------------------------------------------------
    // Evidence artifact production
    // -----------------------------------------------------------------------

    #[test]
    fn produce_evidence_empty_run() {
        let engine = SpecializationConformanceEngine::new("p", test_epoch());
        let artifact = engine.produce_evidence(
            "run-1",
            ContentHash::compute(b"registry"),
            "test-env",
            1_000_000,
        );

        assert_eq!(artifact.run_id, "run-1");
        assert_eq!(artifact.policy_id, "p");
        assert_eq!(artifact.epoch, test_epoch());
        assert_eq!(artifact.total_specializations, 0);
        assert_eq!(artifact.total_workloads, 0);
        assert_eq!(artifact.total_divergences, 0);
        assert!(artifact.ci_gate_passed);
        assert!(artifact.verdicts.is_empty());
    }

    #[test]
    fn produce_evidence_with_match_results() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let entry = make_inventory_entry("a");
        let spec_id = entry.specialization_id.clone();
        engine.register_specialization(entry);

        let outcome = matching_outcome();
        engine.compare_outcomes(&CompareOutcomesInput {
            specialization_id: &spec_id,
            workload_id: "w1",
            category: CorpusCategory::SemanticParity,
            specialized: &outcome,
            unspecialized: &outcome,
            specialized_duration_us: 100,
            unspecialized_duration_us: 150,
            epoch_transition_tested: false,
            fallback_outcome: None,
            receipt_valid: true,
        });

        let artifact =
            engine.produce_evidence("run-2", ContentHash::compute(b"reg"), "env", 2_000_000);

        assert_eq!(artifact.total_specializations, 1);
        assert_eq!(artifact.total_workloads, 1);
        assert_eq!(artifact.total_divergences, 0);
        assert!(artifact.ci_gate_passed);
        assert_eq!(artifact.verdicts.len(), 1);
        assert!(artifact.verdicts[0].passed);
    }

    #[test]
    fn produce_evidence_with_divergence_fails_gate() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let entry = make_inventory_entry("a");
        let spec_id = entry.specialization_id.clone();
        engine.register_specialization(entry);

        let specialized = matching_outcome();
        let unspecialized = diverging_outcome();
        engine.compare_outcomes(&CompareOutcomesInput {
            specialization_id: &spec_id,
            workload_id: "w1",
            category: CorpusCategory::SemanticParity,
            specialized: &specialized,
            unspecialized: &unspecialized,
            specialized_duration_us: 100,
            unspecialized_duration_us: 100,
            epoch_transition_tested: false,
            fallback_outcome: None,
            receipt_valid: true,
        });

        let artifact =
            engine.produce_evidence("run-3", ContentHash::compute(b"reg"), "env", 3_000_000);

        assert!(!artifact.ci_gate_passed);
        assert_eq!(artifact.total_divergences, 1);
        assert_eq!(artifact.failed_specialization_count(), 1);
    }

    #[test]
    fn produce_evidence_with_fallback_failure_fails_gate() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let entry = make_inventory_entry("a");
        let spec_id = entry.specialization_id.clone();
        engine.register_specialization(entry);

        let outcome = matching_outcome();
        let fb = FallbackOutcome::Failure {
            reason: "crash".to_string(),
        };
        engine.compare_outcomes(&CompareOutcomesInput {
            specialization_id: &spec_id,
            workload_id: "w1",
            category: CorpusCategory::EpochTransition,
            specialized: &outcome,
            unspecialized: &outcome,
            specialized_duration_us: 100,
            unspecialized_duration_us: 100,
            epoch_transition_tested: true,
            fallback_outcome: Some(fb),
            receipt_valid: true,
        });

        let artifact =
            engine.produce_evidence("run-4", ContentHash::compute(b"reg"), "env", 4_000_000);

        assert!(!artifact.ci_gate_passed);
        assert_eq!(artifact.total_fallback_failures, 1);
    }

    #[test]
    fn produce_evidence_with_receipt_failure_fails_gate() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let entry = make_inventory_entry("a");
        let spec_id = entry.specialization_id.clone();
        engine.register_specialization(entry);

        let outcome = matching_outcome();
        engine.compare_outcomes(&CompareOutcomesInput {
            specialization_id: &spec_id,
            workload_id: "w1",
            category: CorpusCategory::SemanticParity,
            specialized: &outcome,
            unspecialized: &outcome,
            specialized_duration_us: 100,
            unspecialized_duration_us: 100,
            epoch_transition_tested: false,
            fallback_outcome: None,
            receipt_valid: false,
        });

        let artifact =
            engine.produce_evidence("run-5", ContentHash::compute(b"reg"), "env", 5_000_000);

        assert!(!artifact.ci_gate_passed);
        assert_eq!(artifact.total_receipt_failures, 1);
    }

    // -----------------------------------------------------------------------
    // Evidence artifact serialization
    // -----------------------------------------------------------------------

    #[test]
    fn evidence_artifact_to_jsonl() {
        let engine = SpecializationConformanceEngine::new("p", test_epoch());
        let artifact = engine.produce_evidence("run-1", ContentHash::compute(b"reg"), "env", 1_000);
        let jsonl = artifact.to_jsonl();
        assert!(!jsonl.is_empty());
        let back: ConformanceEvidenceArtifact = serde_json::from_str(&jsonl).unwrap();
        assert_eq!(back.run_id, "run-1");
    }

    // -----------------------------------------------------------------------
    // Determinism check
    // -----------------------------------------------------------------------

    #[test]
    fn check_determinism_identical_outcomes() {
        let outcomes = vec![matching_outcome(); 5];
        assert!(SpecializationConformanceEngine::check_determinism(
            &outcomes
        ));
    }

    #[test]
    fn check_determinism_divergent_outcomes() {
        let outcomes = vec![matching_outcome(), diverging_outcome()];
        assert!(!SpecializationConformanceEngine::check_determinism(
            &outcomes
        ));
    }

    #[test]
    fn check_determinism_single_outcome() {
        let outcomes = vec![matching_outcome()];
        assert!(SpecializationConformanceEngine::check_determinism(
            &outcomes
        ));
    }

    #[test]
    fn check_determinism_empty() {
        let outcomes: Vec<WorkloadOutcome> = vec![];
        assert!(SpecializationConformanceEngine::check_determinism(
            &outcomes
        ));
    }

    // -----------------------------------------------------------------------
    // Performance delta
    // -----------------------------------------------------------------------

    #[test]
    fn performance_delta_speedup() {
        let delta = SpecializationConformanceEngine::compute_performance_delta(80, 100);
        assert_eq!(delta.specialized_duration_us, 80);
        assert_eq!(delta.unspecialized_duration_us, 100);
        assert_eq!(delta.speedup_millionths, 200_000); // 20% speedup
    }

    #[test]
    fn performance_delta_slowdown() {
        let delta = SpecializationConformanceEngine::compute_performance_delta(120, 100);
        assert_eq!(delta.speedup_millionths, -200_000); // 20% slower
    }

    #[test]
    fn performance_delta_zero_baseline() {
        let delta = SpecializationConformanceEngine::compute_performance_delta(50, 0);
        assert_eq!(delta.speedup_millionths, 0);
    }

    #[test]
    fn performance_delta_equal() {
        let delta = SpecializationConformanceEngine::compute_performance_delta(100, 100);
        assert_eq!(delta.speedup_millionths, 0);
    }

    // -----------------------------------------------------------------------
    // ConformanceError display
    // -----------------------------------------------------------------------

    #[test]
    fn conformance_error_display_insufficient() {
        let e = ConformanceError::InsufficientCorpus {
            specialization_id: "spec-1".into(),
            category: CorpusCategory::SemanticParity,
            required: 30,
            found: 5,
        };
        let s = e.to_string();
        assert!(s.contains("insufficient corpus"));
        assert!(s.contains("30"));
        assert!(s.contains("5"));
    }

    #[test]
    fn conformance_error_display_not_found() {
        let e = ConformanceError::SpecializationNotFound {
            specialization_id: "spec-x".into(),
        };
        assert!(e.to_string().contains("not found"));
    }

    #[test]
    fn conformance_error_display_receipt_invalid() {
        let e = ConformanceError::ReceiptInvalid {
            receipt_id: "rcpt-1".into(),
            reasons: vec!["bad hash".into()],
        };
        assert!(e.to_string().contains("bad hash"));
    }

    #[test]
    fn conformance_error_display_missing_corpus() {
        let e = ConformanceError::MissingCorpus {
            specialization_id: "spec-m".into(),
        };
        assert!(e.to_string().contains("missing test corpus"));
    }

    #[test]
    fn conformance_error_display_execution() {
        let e = ConformanceError::ExecutionError {
            message: "timeout".into(),
        };
        assert!(e.to_string().contains("timeout"));
    }

    // -----------------------------------------------------------------------
    // InventoryEntry serde round trip
    // -----------------------------------------------------------------------

    #[test]
    fn inventory_entry_serde_round_trip() {
        let entry = make_inventory_entry("x");
        let json = serde_json::to_string(&entry).unwrap();
        let back: SpecializationInventoryEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    // -----------------------------------------------------------------------
    // DifferentialResult serde round trip
    // -----------------------------------------------------------------------

    #[test]
    fn differential_result_serde_round_trip() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let spec_id = test_id("spec-1");
        let outcome = matching_outcome();
        let result = engine.compare_outcomes(&CompareOutcomesInput {
            specialization_id: &spec_id,
            workload_id: "w1",
            category: CorpusCategory::SemanticParity,
            specialized: &outcome,
            unspecialized: &outcome,
            specialized_duration_us: 100,
            unspecialized_duration_us: 150,
            epoch_transition_tested: false,
            fallback_outcome: None,
            receipt_valid: true,
        });

        let json = serde_json::to_string(&result).unwrap();
        let back: DifferentialResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    // -----------------------------------------------------------------------
    // ConformanceLog serde round trip
    // -----------------------------------------------------------------------

    #[test]
    fn conformance_log_serde_round_trip() {
        let log = ConformanceLog {
            trace_id: "t1".into(),
            specialization_id: "s1".into(),
            workload_id: "w1".into(),
            corpus_category: CorpusCategory::SemanticParity,
            outcome: ComparisonVerdict::Match,
            specialized_duration_us: 100,
            unspecialized_duration_us: 150,
            epoch_transition_tested: false,
            fallback_outcome: None,
            receipt_valid: true,
        };
        let json = serde_json::to_string(&log).unwrap();
        let back: ConformanceLog = serde_json::from_str(&json).unwrap();
        assert_eq!(log, back);
    }

    // -----------------------------------------------------------------------
    // EpochTransitionSimulation serde round trip
    // -----------------------------------------------------------------------

    #[test]
    fn epoch_transition_simulation_serde() {
        let sim = EpochTransitionSimulation {
            old_epoch: SecurityEpoch::from_raw(5),
            new_epoch: SecurityEpoch::from_raw(6),
            invalidated_specialization_ids: vec![test_id("spec-1")],
            proof_revoked: true,
            transition_timestamp_ns: 999_999,
        };
        let json = serde_json::to_string(&sim).unwrap();
        let back: EpochTransitionSimulation = serde_json::from_str(&json).unwrap();
        assert_eq!(sim, back);
    }

    // -----------------------------------------------------------------------
    // InvalidationEvidence serde round trip
    // -----------------------------------------------------------------------

    #[test]
    fn invalidation_evidence_serde() {
        let ev = InvalidationEvidence {
            specialization_id: test_id("spec-1"),
            invalidation_reason: "epoch_change".into(),
            epoch_old: SecurityEpoch::from_raw(5),
            epoch_new: SecurityEpoch::from_raw(6),
            rollback_token: ContentHash::compute(b"rollback"),
            fallback_outcome: FallbackOutcome::Success {
                invalidation_evidence_id: "inv-1".into(),
            },
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: InvalidationEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    // -----------------------------------------------------------------------
    // PerSpecializationVerdict
    // -----------------------------------------------------------------------

    #[test]
    fn per_specialization_verdict_passed() {
        let v = PerSpecializationVerdict {
            specialization_id: test_id("spec-1"),
            parity_workloads_run: 30,
            edge_case_workloads_run: 10,
            epoch_transition_workloads_run: 5,
            divergence_count: 0,
            fallback_failures: 0,
            receipt_validation: ReceiptValidationResult {
                receipt_id: test_id("rcpt-1"),
                well_formed: true,
                equivalence_hash_matches: true,
                rollback_validated: true,
                proof_inputs_consistent: true,
                schema_version: ReceiptSchemaVersion::CURRENT,
                valid: true,
                failure_reasons: vec![],
            },
            passed: true,
        };
        assert!(v.is_passed());
        assert!(v.corpus_coverage_sufficient());
    }

    #[test]
    fn per_specialization_verdict_insufficient_corpus() {
        let v = PerSpecializationVerdict {
            specialization_id: test_id("spec-1"),
            parity_workloads_run: 5,
            edge_case_workloads_run: 3,
            epoch_transition_workloads_run: 1,
            divergence_count: 0,
            fallback_failures: 0,
            receipt_validation: ReceiptValidationResult {
                receipt_id: test_id("rcpt-1"),
                well_formed: true,
                equivalence_hash_matches: true,
                rollback_validated: true,
                proof_inputs_consistent: true,
                schema_version: ReceiptSchemaVersion::CURRENT,
                valid: true,
                failure_reasons: vec![],
            },
            passed: true,
        };
        assert!(!v.corpus_coverage_sufficient());
    }

    // -----------------------------------------------------------------------
    // ReceiptValidationResult
    // -----------------------------------------------------------------------

    #[test]
    fn receipt_validation_result_valid() {
        let r = ReceiptValidationResult {
            receipt_id: test_id("rcpt-1"),
            well_formed: true,
            equivalence_hash_matches: true,
            rollback_validated: true,
            proof_inputs_consistent: true,
            schema_version: ReceiptSchemaVersion::CURRENT,
            valid: true,
            failure_reasons: vec![],
        };
        assert!(r.is_valid());
    }

    #[test]
    fn receipt_validation_result_invalid() {
        let r = ReceiptValidationResult {
            receipt_id: test_id("rcpt-2"),
            well_formed: false,
            equivalence_hash_matches: false,
            rollback_validated: false,
            proof_inputs_consistent: false,
            schema_version: ReceiptSchemaVersion::CURRENT,
            valid: false,
            failure_reasons: vec!["bad".into()],
        };
        assert!(!r.is_valid());
    }

    // -----------------------------------------------------------------------
    // Multiple specializations in one run
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_specializations_mixed_verdicts() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());

        let entry_a = make_inventory_entry("a");
        let spec_id_a = entry_a.specialization_id.clone();
        engine.register_specialization(entry_a);

        let entry_b = make_inventory_entry("b");
        let spec_id_b = entry_b.specialization_id.clone();
        engine.register_specialization(entry_b);

        // spec_a: all match
        let ok = matching_outcome();
        engine.compare_outcomes(&CompareOutcomesInput {
            specialization_id: &spec_id_a,
            workload_id: "w1",
            category: CorpusCategory::SemanticParity,
            specialized: &ok,
            unspecialized: &ok,
            specialized_duration_us: 100,
            unspecialized_duration_us: 100,
            epoch_transition_tested: false,
            fallback_outcome: None,
            receipt_valid: true,
        });

        // spec_b: diverge
        let bad = diverging_outcome();
        engine.compare_outcomes(&CompareOutcomesInput {
            specialization_id: &spec_id_b,
            workload_id: "w2",
            category: CorpusCategory::SemanticParity,
            specialized: &ok,
            unspecialized: &bad,
            specialized_duration_us: 100,
            unspecialized_duration_us: 100,
            epoch_transition_tested: false,
            fallback_outcome: None,
            receipt_valid: true,
        });

        let artifact =
            engine.produce_evidence("run-multi", ContentHash::compute(b"reg"), "env", 6_000_000);

        assert_eq!(artifact.total_specializations, 2);
        assert_eq!(artifact.total_workloads, 2);
        assert_eq!(artifact.total_divergences, 1);
        assert!(!artifact.ci_gate_passed);
        assert_eq!(artifact.failed_specialization_count(), 1);
    }

    // -----------------------------------------------------------------------
    // Meta-test: intentional divergence injection
    // -----------------------------------------------------------------------

    #[test]
    fn meta_test_divergence_injection_detected() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let entry = make_inventory_entry("meta");
        let spec_id = entry.specialization_id.clone();
        engine.register_specialization(entry);

        // Intentionally produce different results
        let specialized = WorkloadOutcome {
            return_value: "correct".into(),
            side_effect_trace: vec![],
            exceptions: vec![],
            evidence_entries: vec![],
        };
        let unspecialized = WorkloadOutcome {
            return_value: "wrong".into(),
            side_effect_trace: vec![],
            exceptions: vec![],
            evidence_entries: vec![],
        };

        let result = engine.compare_outcomes(&CompareOutcomesInput {
            specialization_id: &spec_id,
            workload_id: "meta-w1",
            category: CorpusCategory::SemanticParity,
            specialized: &specialized,
            unspecialized: &unspecialized,
            specialized_duration_us: 50,
            unspecialized_duration_us: 50,
            epoch_transition_tested: false,
            fallback_outcome: None,
            receipt_valid: true,
        });

        assert!(result.outcome.is_diverge());
        let artifact =
            engine.produce_evidence("meta-run", ContentHash::compute(b"reg"), "env", 7_000_000);
        assert!(!artifact.ci_gate_passed);
    }

    // -----------------------------------------------------------------------
    // Meta-test: faulty fallback detection
    // -----------------------------------------------------------------------

    #[test]
    fn meta_test_faulty_fallback_detected() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let entry = make_inventory_entry("meta-fb");
        let spec_id = entry.specialization_id.clone();
        engine.register_specialization(entry);

        let outcome = matching_outcome();
        let fb = FallbackOutcome::Failure {
            reason: "wrong output after invalidation".into(),
        };

        engine.compare_outcomes(&CompareOutcomesInput {
            specialization_id: &spec_id,
            workload_id: "meta-w2",
            category: CorpusCategory::EpochTransition,
            specialized: &outcome,
            unspecialized: &outcome,
            specialized_duration_us: 50,
            unspecialized_duration_us: 50,
            epoch_transition_tested: true,
            fallback_outcome: Some(fb),
            receipt_valid: true,
        });

        let artifact = engine.produce_evidence(
            "meta-fb-run",
            ContentHash::compute(b"reg"),
            "env",
            8_000_000,
        );
        assert!(!artifact.ci_gate_passed);
        assert_eq!(artifact.total_fallback_failures, 1);
    }

    // -----------------------------------------------------------------------
    // Meta-test: receipt validation failure detection
    // -----------------------------------------------------------------------

    #[test]
    fn meta_test_receipt_failure_detected() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let entry = make_inventory_entry("meta-rcpt");
        let spec_id = entry.specialization_id.clone();
        engine.register_specialization(entry);

        let outcome = matching_outcome();
        engine.compare_outcomes(&CompareOutcomesInput {
            specialization_id: &spec_id,
            workload_id: "meta-w3",
            category: CorpusCategory::SemanticParity,
            specialized: &outcome,
            unspecialized: &outcome,
            specialized_duration_us: 50,
            unspecialized_duration_us: 50,
            epoch_transition_tested: false,
            fallback_outcome: None,
            receipt_valid: false,
        });

        let artifact = engine.produce_evidence(
            "meta-rcpt-run",
            ContentHash::compute(b"reg"),
            "env",
            9_000_000,
        );
        assert!(!artifact.ci_gate_passed);
        assert_eq!(artifact.total_receipt_failures, 1);
    }

    // -----------------------------------------------------------------------
    // Meta-test: determinism across 5 runs
    // -----------------------------------------------------------------------

    #[test]
    fn meta_test_determinism_5_runs() {
        let outcome = matching_outcome();
        let outcomes = vec![outcome; DETERMINISM_REPETITIONS];
        assert!(SpecializationConformanceEngine::check_determinism(
            &outcomes
        ));
    }

    #[test]
    fn transformation_type_ord() {
        assert!(
            TransformationType::HostcallDispatchElision < TransformationType::LabelCheckElision
        );
        assert!(TransformationType::LabelCheckElision < TransformationType::PathRemoval);
        assert!(TransformationType::PathRemoval < TransformationType::SuperinstructionFusion);
    }

    #[test]
    fn corpus_category_ord() {
        assert!(CorpusCategory::SemanticParity < CorpusCategory::EdgeCase);
        assert!(CorpusCategory::EdgeCase < CorpusCategory::EpochTransition);
    }

    #[test]
    fn comparison_verdict_ord() {
        assert!(ComparisonVerdict::Match < ComparisonVerdict::Diverge);
    }

    #[test]
    fn divergence_kind_ord() {
        assert!(DivergenceKind::ReturnValue < DivergenceKind::SideEffectTrace);
        assert!(DivergenceKind::SideEffectTrace < DivergenceKind::ExceptionSequence);
        assert!(DivergenceKind::ExceptionSequence < DivergenceKind::EvidenceEmission);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn performance_delta_serde_round_trip() {
        let delta = SpecializationConformanceEngine::compute_performance_delta(80, 100);
        let json = serde_json::to_string(&delta).unwrap();
        let back: PerformanceDelta = serde_json::from_str(&json).unwrap();
        assert_eq!(delta, back);
    }

    #[test]
    fn divergence_detail_serde_round_trip() {
        let detail = DivergenceDetail {
            divergence_kind: DivergenceKind::SideEffectTrace,
            specialized_summary: "1 effects".to_string(),
            unspecialized_summary: "3 effects".to_string(),
        };
        let json = serde_json::to_string(&detail).unwrap();
        let back: DivergenceDetail = serde_json::from_str(&json).unwrap();
        assert_eq!(detail, back);
    }

    #[test]
    fn receipt_validation_result_serde_round_trip() {
        let r = ReceiptValidationResult {
            receipt_id: test_id("rcpt-serde"),
            well_formed: true,
            equivalence_hash_matches: false,
            rollback_validated: true,
            proof_inputs_consistent: false,
            schema_version: ReceiptSchemaVersion::CURRENT,
            valid: false,
            failure_reasons: vec![
                "hash mismatch".to_string(),
                "inconsistent proofs".to_string(),
            ],
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: ReceiptValidationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn per_specialization_verdict_serde_round_trip() {
        let v = PerSpecializationVerdict {
            specialization_id: test_id("spec-serde"),
            parity_workloads_run: 30,
            edge_case_workloads_run: 10,
            epoch_transition_workloads_run: 5,
            divergence_count: 1,
            fallback_failures: 0,
            receipt_validation: ReceiptValidationResult {
                receipt_id: test_id("rcpt-serde"),
                well_formed: true,
                equivalence_hash_matches: true,
                rollback_validated: true,
                proof_inputs_consistent: true,
                schema_version: ReceiptSchemaVersion::CURRENT,
                valid: true,
                failure_reasons: vec![],
            },
            passed: false,
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: PerSpecializationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn conformance_error_serde_all_variants() {
        let variants: Vec<ConformanceError> = vec![
            ConformanceError::InsufficientCorpus {
                specialization_id: "spec-1".into(),
                category: CorpusCategory::SemanticParity,
                required: 30,
                found: 5,
            },
            ConformanceError::SpecializationNotFound {
                specialization_id: "spec-x".into(),
            },
            ConformanceError::ReceiptInvalid {
                receipt_id: "rcpt-1".into(),
                reasons: vec!["bad hash".into()],
            },
            ConformanceError::MissingCorpus {
                specialization_id: "spec-m".into(),
            },
            ConformanceError::ExecutionError {
                message: "timeout".into(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ConformanceError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn side_effect_serde_round_trip() {
        let effect = SideEffect {
            effect_type: "hostcall".to_string(),
            description: "call-logger".to_string(),
            sequence: 42,
        };
        let json = serde_json::to_string(&effect).unwrap();
        let back: SideEffect = serde_json::from_str(&json).unwrap();
        assert_eq!(effect, back);
    }

    #[test]
    fn specialization_workload_serde_round_trip() {
        let w = make_workload("w-serde", CorpusCategory::EdgeCase);
        let json = serde_json::to_string(&w).unwrap();
        let back: SpecializationWorkload = serde_json::from_str(&json).unwrap();
        assert_eq!(w, back);
    }

    #[test]
    fn workload_outcome_empty_fields() {
        let outcome = WorkloadOutcome {
            return_value: String::new(),
            side_effect_trace: vec![],
            exceptions: vec![],
            evidence_entries: vec![],
        };
        let json = serde_json::to_string(&outcome).unwrap();
        let back: WorkloadOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, back);
        // Empty outcomes still produce a deterministic hash
        let h1 = outcome.content_hash();
        let h2 = back.content_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn compare_outcomes_trace_id_increments() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let spec_id = test_id("spec-seq");
        let outcome = matching_outcome();
        let r1 = engine.compare_outcomes(&CompareOutcomesInput {
            specialization_id: &spec_id,
            workload_id: "w1",
            category: CorpusCategory::SemanticParity,
            specialized: &outcome,
            unspecialized: &outcome,
            specialized_duration_us: 100,
            unspecialized_duration_us: 100,
            epoch_transition_tested: false,
            fallback_outcome: None,
            receipt_valid: true,
        });
        let r2 = engine.compare_outcomes(&CompareOutcomesInput {
            specialization_id: &spec_id,
            workload_id: "w2",
            category: CorpusCategory::SemanticParity,
            specialized: &outcome,
            unspecialized: &outcome,
            specialized_duration_us: 100,
            unspecialized_duration_us: 100,
            epoch_transition_tested: false,
            fallback_outcome: None,
            receipt_valid: true,
        });
        assert_eq!(r1.trace_id, "conformance-1");
        assert_eq!(r2.trace_id, "conformance-2");
    }

    #[test]
    fn transformation_type_as_str_all_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for tt in TransformationType::ALL {
            assert!(
                seen.insert(tt.as_str()),
                "duplicate as_str: {}",
                tt.as_str()
            );
        }
    }

    #[test]
    fn evidence_artifact_full_serde_round_trip() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let entry = make_inventory_entry("serde-test");
        let spec_id = entry.specialization_id.clone();
        engine.register_specialization(entry);
        let outcome = matching_outcome();
        engine.compare_outcomes(&CompareOutcomesInput {
            specialization_id: &spec_id,
            workload_id: "w1",
            category: CorpusCategory::SemanticParity,
            specialized: &outcome,
            unspecialized: &outcome,
            specialized_duration_us: 100,
            unspecialized_duration_us: 150,
            epoch_transition_tested: false,
            fallback_outcome: None,
            receipt_valid: true,
        });
        let artifact = engine.produce_evidence(
            "run-serde",
            ContentHash::compute(b"reg"),
            "env-serde",
            42_000,
        );
        let json = serde_json::to_string(&artifact).unwrap();
        let back: ConformanceEvidenceArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(artifact, back);
    }

    #[test]
    fn epoch_transition_simulation_empty_ids() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let simulation = EpochTransitionSimulation {
            old_epoch: test_epoch(),
            new_epoch: SecurityEpoch::from_raw(11),
            invalidated_specialization_ids: vec![],
            proof_revoked: false,
            transition_timestamp_ns: 1_000,
        };
        let evidence = engine.simulate_epoch_transition(&simulation);
        assert!(evidence.is_empty());
        assert_eq!(engine.current_epoch(), SecurityEpoch::from_raw(11));
    }

    #[test]
    fn conformance_log_fallback_status_formats() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let spec_id = test_id("spec-fb-log");
        let outcome = matching_outcome();

        // No fallback
        engine.compare_outcomes(&CompareOutcomesInput {
            specialization_id: &spec_id,
            workload_id: "w-no-fb",
            category: CorpusCategory::SemanticParity,
            specialized: &outcome,
            unspecialized: &outcome,
            specialized_duration_us: 50,
            unspecialized_duration_us: 50,
            epoch_transition_tested: false,
            fallback_outcome: None,
            receipt_valid: true,
        });
        let log_no_fb = &engine.logs()[0];
        assert_eq!(log_no_fb.fallback_outcome.as_deref(), Some("not_tested"));

        // Success fallback
        engine.compare_outcomes(&CompareOutcomesInput {
            specialization_id: &spec_id,
            workload_id: "w-fb-ok",
            category: CorpusCategory::EpochTransition,
            specialized: &outcome,
            unspecialized: &outcome,
            specialized_duration_us: 50,
            unspecialized_duration_us: 50,
            epoch_transition_tested: true,
            fallback_outcome: Some(FallbackOutcome::Success {
                invalidation_evidence_id: "inv-log".to_string(),
            }),
            receipt_valid: true,
        });
        let log_ok = &engine.logs()[1];
        assert_eq!(log_ok.fallback_outcome.as_deref(), Some("success"));

        // Failure fallback
        engine.compare_outcomes(&CompareOutcomesInput {
            specialization_id: &spec_id,
            workload_id: "w-fb-fail",
            category: CorpusCategory::EpochTransition,
            specialized: &outcome,
            unspecialized: &outcome,
            specialized_duration_us: 50,
            unspecialized_duration_us: 50,
            epoch_transition_tested: true,
            fallback_outcome: Some(FallbackOutcome::Failure {
                reason: "crash".to_string(),
            }),
            receipt_valid: true,
        });
        let log_fail = &engine.logs()[2];
        assert!(
            log_fail
                .fallback_outcome
                .as_deref()
                .unwrap()
                .starts_with("failure:")
        );
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn transformation_type_display_all_4_variants() {
        let expected = [
            (
                TransformationType::HostcallDispatchElision,
                "hostcall_dispatch_elision",
            ),
            (TransformationType::LabelCheckElision, "label_check_elision"),
            (TransformationType::PathRemoval, "path_removal"),
            (
                TransformationType::SuperinstructionFusion,
                "superinstruction_fusion",
            ),
        ];
        for (tt, label) in expected {
            assert_eq!(tt.to_string(), label);
        }
    }

    #[test]
    fn conformance_error_display_exact_formats() {
        assert_eq!(
            ConformanceError::InsufficientCorpus {
                specialization_id: "s1".into(),
                category: CorpusCategory::EdgeCase,
                required: 10,
                found: 3,
            }
            .to_string(),
            "insufficient corpus for s1/edge_case: need 10, found 3"
        );
        assert_eq!(
            ConformanceError::SpecializationNotFound {
                specialization_id: "s2".into(),
            }
            .to_string(),
            "specialization not found: s2"
        );
        assert_eq!(
            ConformanceError::MissingCorpus {
                specialization_id: "s3".into(),
            }
            .to_string(),
            "missing test corpus for: s3"
        );
        assert_eq!(
            ConformanceError::ExecutionError {
                message: "timeout".into(),
            }
            .to_string(),
            "execution error: timeout"
        );
        assert_eq!(
            ConformanceError::ReceiptInvalid {
                receipt_id: "r1".into(),
                reasons: vec!["a".into(), "b".into()],
            }
            .to_string(),
            "receipt invalid for r1: a; b"
        );
    }

    #[test]
    fn evidence_artifact_is_passed_accessor() {
        let engine = SpecializationConformanceEngine::new("p", test_epoch());
        let artifact = engine.produce_evidence("r1", ContentHash::compute(b"reg"), "env", 1000);
        assert!(artifact.is_passed());
        assert_eq!(artifact.failed_specialization_count(), 0);
    }

    #[test]
    fn per_specialization_verdict_not_passed() {
        let v = PerSpecializationVerdict {
            specialization_id: test_id("spec-fail"),
            parity_workloads_run: 30,
            edge_case_workloads_run: 10,
            epoch_transition_workloads_run: 5,
            divergence_count: 2,
            fallback_failures: 1,
            receipt_validation: ReceiptValidationResult {
                receipt_id: test_id("rcpt-fail"),
                well_formed: false,
                equivalence_hash_matches: false,
                rollback_validated: false,
                proof_inputs_consistent: false,
                schema_version: ReceiptSchemaVersion::CURRENT,
                valid: false,
                failure_reasons: vec!["broken".to_string()],
            },
            passed: false,
        };
        assert!(!v.is_passed());
        assert!(v.corpus_coverage_sufficient());
    }

    #[test]
    fn corpus_coverage_borderline_one_below() {
        let v = PerSpecializationVerdict {
            specialization_id: test_id("spec-border"),
            parity_workloads_run: 29, // one below 30
            edge_case_workloads_run: 10,
            epoch_transition_workloads_run: 5,
            divergence_count: 0,
            fallback_failures: 0,
            receipt_validation: ReceiptValidationResult {
                receipt_id: test_id("rcpt-border"),
                well_formed: true,
                equivalence_hash_matches: true,
                rollback_validated: true,
                proof_inputs_consistent: true,
                schema_version: ReceiptSchemaVersion::CURRENT,
                valid: true,
                failure_reasons: vec![],
            },
            passed: true,
        };
        assert!(!v.corpus_coverage_sufficient());
    }

    #[test]
    fn validate_receipt_valid() {
        use crate::proof_specialization_receipt::{
            EquivalenceEvidence, EquivalenceMethod, RollbackToken, SpecializationReceipt,
            TransformationWitness,
        };

        let equiv_hash = ContentHash::compute(b"equiv-evidence");
        let receipt = SpecializationReceipt {
            receipt_id: test_id("rcpt-valid"),
            schema_version: ReceiptSchemaVersion::CURRENT,
            proof_inputs: vec![test_proof_input("valid")],
            optimization_class: OptimizationClass::HostcallDispatchSpecialization,
            transformation_witness: TransformationWitness {
                description: "elide hostcall".to_string(),
                before_ir_digest: ContentHash::compute(b"before"),
                after_ir_digest: ContentHash::compute(b"after"),
            },
            equivalence_evidence: EquivalenceEvidence {
                method: EquivalenceMethod::DifferentialTesting,
                differential_test_hashes: vec![equiv_hash],
                test_count: 100,
                pass_rate_millionths: 1_000_000,
            },
            rollback_token: RollbackToken {
                baseline_hash: ContentHash::compute(b"baseline"),
                rollback_procedure_hash: ContentHash::compute(b"rollback"),
                validated: true,
            },
            validity_epoch: test_epoch(),
            fallback_path: "baseline/path".to_string(),
            performance_delta: crate::proof_specialization_receipt::PerformanceDelta {
                latency_reduction_millionths: 200_000,
                throughput_increase_millionths: 100_000,
                sample_count: 50,
            },
            timestamp_ns: 1_000_000,
            signature: crate::signature_preimage::Signature::from_bytes(
                crate::signature_preimage::SIGNATURE_SENTINEL,
            ),
            metadata: BTreeMap::new(),
        };

        let engine = SpecializationConformanceEngine::new("p", test_epoch());
        let result = engine.validate_receipt(&receipt, &equiv_hash);
        assert!(result.is_valid());
        assert!(result.well_formed);
        assert!(result.equivalence_hash_matches);
        assert!(result.rollback_validated);
        assert!(result.proof_inputs_consistent);
        assert!(result.failure_reasons.is_empty());
    }

    #[test]
    fn validate_receipt_empty_proof_inputs() {
        use crate::proof_specialization_receipt::{
            EquivalenceEvidence, EquivalenceMethod, RollbackToken, SpecializationReceipt,
            TransformationWitness,
        };

        let equiv_hash = ContentHash::compute(b"equiv");
        let receipt = SpecializationReceipt {
            receipt_id: test_id("rcpt-empty-proofs"),
            schema_version: ReceiptSchemaVersion::CURRENT,
            proof_inputs: vec![], // empty!
            optimization_class: OptimizationClass::PathElimination,
            transformation_witness: TransformationWitness {
                description: "remove path".to_string(),
                before_ir_digest: ContentHash::compute(b"b"),
                after_ir_digest: ContentHash::compute(b"a"),
            },
            equivalence_evidence: EquivalenceEvidence {
                method: EquivalenceMethod::DifferentialTesting,
                differential_test_hashes: vec![equiv_hash],
                test_count: 50,
                pass_rate_millionths: 1_000_000,
            },
            rollback_token: RollbackToken {
                baseline_hash: ContentHash::compute(b"bl"),
                rollback_procedure_hash: ContentHash::compute(b"rb"),
                validated: true,
            },
            validity_epoch: test_epoch(),
            fallback_path: "baseline".to_string(),
            performance_delta: crate::proof_specialization_receipt::PerformanceDelta {
                latency_reduction_millionths: 200_000,
                throughput_increase_millionths: 100_000,
                sample_count: 50,
            },
            timestamp_ns: 1_000_000,
            signature: crate::signature_preimage::Signature::from_bytes(
                crate::signature_preimage::SIGNATURE_SENTINEL,
            ),
            metadata: BTreeMap::new(),
        };

        let engine = SpecializationConformanceEngine::new("p", test_epoch());
        let result = engine.validate_receipt(&receipt, &equiv_hash);
        assert!(!result.is_valid());
        assert!(!result.well_formed);
        assert!(
            result
                .failure_reasons
                .iter()
                .any(|r| r.contains("empty proof inputs"))
        );
    }

    #[test]
    fn validate_receipt_epoch_mismatch() {
        use crate::proof_specialization_receipt::{
            EquivalenceEvidence, EquivalenceMethod, RollbackToken, SpecializationReceipt,
            TransformationWitness,
        };

        let equiv_hash = ContentHash::compute(b"equiv");
        let receipt = SpecializationReceipt {
            receipt_id: test_id("rcpt-epoch"),
            schema_version: ReceiptSchemaVersion::CURRENT,
            proof_inputs: vec![test_proof_input("ep")],
            optimization_class: OptimizationClass::IfcCheckElision,
            transformation_witness: TransformationWitness {
                description: "elide check".to_string(),
                before_ir_digest: ContentHash::compute(b"b"),
                after_ir_digest: ContentHash::compute(b"a"),
            },
            equivalence_evidence: EquivalenceEvidence {
                method: EquivalenceMethod::DifferentialTesting,
                differential_test_hashes: vec![equiv_hash],
                test_count: 50,
                pass_rate_millionths: 1_000_000,
            },
            rollback_token: RollbackToken {
                baseline_hash: ContentHash::compute(b"bl"),
                rollback_procedure_hash: ContentHash::compute(b"rb"),
                validated: true,
            },
            validity_epoch: SecurityEpoch::from_raw(999), // mismatch with engine epoch=10
            fallback_path: "baseline".to_string(),
            performance_delta: crate::proof_specialization_receipt::PerformanceDelta {
                latency_reduction_millionths: 200_000,
                throughput_increase_millionths: 100_000,
                sample_count: 50,
            },
            timestamp_ns: 1_000_000,
            signature: crate::signature_preimage::Signature::from_bytes(
                crate::signature_preimage::SIGNATURE_SENTINEL,
            ),
            metadata: BTreeMap::new(),
        };

        let engine = SpecializationConformanceEngine::new("p", test_epoch());
        let result = engine.validate_receipt(&receipt, &equiv_hash);
        assert!(!result.is_valid());
        assert!(
            result
                .failure_reasons
                .iter()
                .any(|r| r.contains("epoch mismatch"))
        );
    }

    #[test]
    fn validate_receipt_hash_mismatch() {
        use crate::proof_specialization_receipt::{
            EquivalenceEvidence, EquivalenceMethod, RollbackToken, SpecializationReceipt,
            TransformationWitness,
        };

        let receipt = SpecializationReceipt {
            receipt_id: test_id("rcpt-hash"),
            schema_version: ReceiptSchemaVersion::CURRENT,
            proof_inputs: vec![test_proof_input("hm")],
            optimization_class: OptimizationClass::SuperinstructionFusion,
            transformation_witness: TransformationWitness {
                description: "fuse".to_string(),
                before_ir_digest: ContentHash::compute(b"b"),
                after_ir_digest: ContentHash::compute(b"a"),
            },
            equivalence_evidence: EquivalenceEvidence {
                method: EquivalenceMethod::DifferentialTesting,
                differential_test_hashes: vec![ContentHash::compute(b"stored-hash")],
                test_count: 50,
                pass_rate_millionths: 1_000_000,
            },
            rollback_token: RollbackToken {
                baseline_hash: ContentHash::compute(b"bl"),
                rollback_procedure_hash: ContentHash::compute(b"rb"),
                validated: true,
            },
            validity_epoch: test_epoch(),
            fallback_path: "baseline".to_string(),
            performance_delta: crate::proof_specialization_receipt::PerformanceDelta {
                latency_reduction_millionths: 200_000,
                throughput_increase_millionths: 100_000,
                sample_count: 50,
            },
            timestamp_ns: 1_000_000,
            signature: crate::signature_preimage::Signature::from_bytes(
                crate::signature_preimage::SIGNATURE_SENTINEL,
            ),
            metadata: BTreeMap::new(),
        };

        let wrong_hash = ContentHash::compute(b"different-hash");
        let engine = SpecializationConformanceEngine::new("p", test_epoch());
        let result = engine.validate_receipt(&receipt, &wrong_hash);
        assert!(!result.is_valid());
        assert!(
            result
                .failure_reasons
                .iter()
                .any(|r| r.contains("equivalence evidence hash mismatch"))
        );
    }

    #[test]
    fn validate_receipt_rollback_not_validated() {
        use crate::proof_specialization_receipt::{
            EquivalenceEvidence, EquivalenceMethod, RollbackToken, SpecializationReceipt,
            TransformationWitness,
        };

        let equiv_hash = ContentHash::compute(b"equiv");
        let receipt = SpecializationReceipt {
            receipt_id: test_id("rcpt-rb"),
            schema_version: ReceiptSchemaVersion::CURRENT,
            proof_inputs: vec![test_proof_input("rb")],
            optimization_class: OptimizationClass::PathElimination,
            transformation_witness: TransformationWitness {
                description: "remove".to_string(),
                before_ir_digest: ContentHash::compute(b"b"),
                after_ir_digest: ContentHash::compute(b"a"),
            },
            equivalence_evidence: EquivalenceEvidence {
                method: EquivalenceMethod::DifferentialTesting,
                differential_test_hashes: vec![equiv_hash],
                test_count: 50,
                pass_rate_millionths: 1_000_000,
            },
            rollback_token: RollbackToken {
                baseline_hash: ContentHash::compute(b"bl"),
                rollback_procedure_hash: ContentHash::compute(b"rb"),
                validated: false, // not validated!
            },
            validity_epoch: test_epoch(),
            fallback_path: "baseline".to_string(),
            performance_delta: crate::proof_specialization_receipt::PerformanceDelta {
                latency_reduction_millionths: 200_000,
                throughput_increase_millionths: 100_000,
                sample_count: 50,
            },
            timestamp_ns: 1_000_000,
            signature: crate::signature_preimage::Signature::from_bytes(
                crate::signature_preimage::SIGNATURE_SENTINEL,
            ),
            metadata: BTreeMap::new(),
        };

        let engine = SpecializationConformanceEngine::new("p", test_epoch());
        let result = engine.validate_receipt(&receipt, &equiv_hash);
        assert!(!result.is_valid());
        assert!(
            result
                .failure_reasons
                .iter()
                .any(|r| r.contains("rollback token not validated"))
        );
    }

    #[test]
    fn multiple_epoch_transitions_in_sequence() {
        let mut engine = SpecializationConformanceEngine::new("p", SecurityEpoch::from_raw(1));
        let entry = make_inventory_entry("seq");
        engine.register_specialization(entry);

        // First transition: 1 -> 2
        let sim1 = EpochTransitionSimulation {
            old_epoch: SecurityEpoch::from_raw(1),
            new_epoch: SecurityEpoch::from_raw(2),
            invalidated_specialization_ids: vec![],
            proof_revoked: false,
            transition_timestamp_ns: 1000,
        };
        engine.simulate_epoch_transition(&sim1);
        assert_eq!(engine.current_epoch(), SecurityEpoch::from_raw(2));

        // Second transition: 2 -> 3
        let sim2 = EpochTransitionSimulation {
            old_epoch: SecurityEpoch::from_raw(2),
            new_epoch: SecurityEpoch::from_raw(3),
            invalidated_specialization_ids: vec![],
            proof_revoked: false,
            transition_timestamp_ns: 2000,
        };
        engine.simulate_epoch_transition(&sim2);
        assert_eq!(engine.current_epoch(), SecurityEpoch::from_raw(3));
    }

    #[test]
    fn invalidation_evidence_multiple_specs() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let entry_a = make_inventory_entry("multi-a");
        let id_a = entry_a.specialization_id.clone();
        engine.register_specialization(entry_a);
        let entry_b = make_inventory_entry("multi-b");
        let id_b = entry_b.specialization_id.clone();
        engine.register_specialization(entry_b);

        let simulation = EpochTransitionSimulation {
            old_epoch: test_epoch(),
            new_epoch: SecurityEpoch::from_raw(11),
            invalidated_specialization_ids: vec![id_a.clone(), id_b.clone()],
            proof_revoked: true,
            transition_timestamp_ns: 5000,
        };

        let evidence = engine.simulate_epoch_transition(&simulation);
        assert_eq!(evidence.len(), 2);
        assert_eq!(evidence[0].specialization_id, id_a);
        assert_eq!(evidence[1].specialization_id, id_b);
        assert!(
            evidence
                .iter()
                .all(|e| e.invalidation_reason == "proof_revoked")
        );
        assert!(evidence.iter().all(|e| e.fallback_outcome.is_success()));
    }

    #[test]
    fn compare_outcomes_return_divergence_takes_priority() {
        // When both return_value and side_effect_trace differ,
        // return_value divergence should be reported (first check wins)
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let spec_id = test_id("spec-priority");
        let specialized = WorkloadOutcome {
            return_value: "100".to_string(),
            side_effect_trace: vec![SideEffect {
                effect_type: "a".to_string(),
                description: "x".to_string(),
                sequence: 0,
            }],
            exceptions: vec![],
            evidence_entries: vec![],
        };
        let unspecialized = WorkloadOutcome {
            return_value: "200".to_string(),
            side_effect_trace: vec![],                // also different
            exceptions: vec!["err".to_string()],      // also different
            evidence_entries: vec!["ev".to_string()], // also different
        };

        let result = engine.compare_outcomes(&CompareOutcomesInput {
            specialization_id: &spec_id,
            workload_id: "w-prio",
            category: CorpusCategory::SemanticParity,
            specialized: &specialized,
            unspecialized: &unspecialized,
            specialized_duration_us: 50,
            unspecialized_duration_us: 50,
            epoch_transition_tested: false,
            fallback_outcome: None,
            receipt_valid: true,
        });

        assert!(result.outcome.is_diverge());
        let detail = result.divergence_detail.as_ref().unwrap();
        // ReturnValue check fires first
        assert_eq!(detail.divergence_kind, DivergenceKind::ReturnValue);
    }

    #[test]
    fn performance_delta_large_speedup() {
        // 10us specialized vs 1000us unspecialized = 99% speedup
        let delta = SpecializationConformanceEngine::compute_performance_delta(10, 1000);
        assert_eq!(delta.speedup_millionths, 990_000); // 99%
    }

    #[test]
    fn engine_inventory_accessor() {
        let mut engine = SpecializationConformanceEngine::new("p", test_epoch());
        let entry = make_inventory_entry("inv-acc");
        let key = format!("{}", entry.specialization_id);
        engine.register_specialization(entry);
        assert!(engine.inventory().contains_key(&key));
    }
}
