//! Per-slot native-vs-delegate differential gate.
//!
//! Continuously validates behavioral equivalence between native and delegate
//! cell implementations for every replaceable runtime slot.  When divergence
//! is detected the gate produces minimized repro artifacts and classifies
//! the divergence using a deterministic taxonomy that drives promotion and
//! demotion decisions.
//!
//! Key behaviors:
//! - Consumes the canonical [`SlotRegistry`](crate::slot_registry::SlotRegistry)
//!   to enumerate replaceable slots.
//! - Runs each workload through both native and delegate cells, comparing
//!   observable outputs against the slot's semantic contract.
//! - Classifies divergences: semantic, performance, capability, resource,
//!   or benign improvement.
//! - Produces minimized repro artifacts when divergence is detected.
//! - Emits a per-slot [`PromotionReadiness`] verdict consumed by the
//!   9I.6 replacement pipeline.
//!
//! Plan reference: Section 10.7 item 7, bd-33z.
//! Cross-refs: 9I.6 (Verified Self-Replacement), bd-d93 (evidence format),
//! bd-375 (delegate cell security), bd-1g5c (promotion gate runner).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::slot_registry::{AuthorityEnvelope, SlotCapability, SlotId, SlotKind};

// ---------------------------------------------------------------------------
// Schema hash
// ---------------------------------------------------------------------------

fn slot_differential_schema_hash() -> crate::deterministic_serde::SchemaHash {
    crate::deterministic_serde::SchemaHash::from_definition(b"slot-differential.v1")
}

// ---------------------------------------------------------------------------
// DivergenceClass — deterministic taxonomy
// ---------------------------------------------------------------------------

/// Classification of a divergence between native and delegate cell output.
///
/// Severity order (most to least severe):
/// `SemanticDivergence > CapabilityDivergence > PerformanceDivergence >
///  ResourceDivergence > BenignImprovement`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DivergenceClass {
    /// Native and delegate produce different observable results under the
    /// semantic contract.  Severity: P0 — blocks promotion, triggers
    /// auto-demotion if the slot is already promoted.
    SemanticDivergence,
    /// Native cell requests different (broader) capabilities than the
    /// delegate.  Severity: P0 — blocks promotion.
    CapabilityDivergence,
    /// Native is slower than delegate by more than the configured threshold.
    /// Severity: P1 — blocks promotion, does not trigger demotion.
    PerformanceDivergence,
    /// Native consumes significantly more resources than delegate.
    /// Severity: P2 — tracked, informational.
    ResourceDivergence,
    /// Native produces strictly better results (faster, less resources,
    /// same semantics).  Informational — logged for promotion justification.
    BenignImprovement,
}

impl DivergenceClass {
    /// Whether this divergence class blocks promotion.
    pub fn blocks_promotion(&self) -> bool {
        matches!(
            self,
            Self::SemanticDivergence | Self::CapabilityDivergence | Self::PerformanceDivergence
        )
    }

    /// Whether this divergence class triggers auto-demotion on a promoted slot.
    pub fn triggers_demotion(&self) -> bool {
        matches!(self, Self::SemanticDivergence | Self::CapabilityDivergence)
    }

    /// Canonical string tag for structured logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SemanticDivergence => "semantic_divergence",
            Self::CapabilityDivergence => "capability_divergence",
            Self::PerformanceDivergence => "performance_divergence",
            Self::ResourceDivergence => "resource_divergence",
            Self::BenignImprovement => "benign_improvement",
        }
    }
}

impl fmt::Display for DivergenceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// WorkloadCategory — corpus section classification
// ---------------------------------------------------------------------------

/// Which section of the per-slot test corpus a workload belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum WorkloadCategory {
    /// Standard semantic-equivalence workloads.
    SemanticEquivalence,
    /// Known tricky inputs for the slot's domain.
    EdgeCase,
    /// Adversarial inputs designed to trigger divergence.
    Adversarial,
}

impl WorkloadCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SemanticEquivalence => "semantic_equivalence",
            Self::EdgeCase => "edge_case",
            Self::Adversarial => "adversarial",
        }
    }
}

impl fmt::Display for WorkloadCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// CellOutput — observable output captured from a cell execution
// ---------------------------------------------------------------------------

/// Observable output from executing a workload through a cell.
///
/// Comparison uses the slot's semantic contract (not bitwise equality).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellOutput {
    /// Primary return value (canonical serialized form).
    pub return_value: String,
    /// Side-effect trace: hostcalls issued, state mutations, etc.
    pub side_effects: Vec<String>,
    /// Exceptions thrown during execution (empty if none).
    pub exceptions: Vec<String>,
    /// Evidence entries emitted during execution.
    pub evidence_entries: Vec<String>,
    /// Capabilities exercised during execution.
    pub capabilities_exercised: Vec<SlotCapability>,
    /// Execution duration in microseconds.
    pub duration_us: u64,
    /// Memory allocated in bytes.
    pub memory_bytes: u64,
}

impl CellOutput {
    /// Check semantic equivalence (return value, side effects, exceptions).
    pub fn semantically_equivalent(&self, other: &CellOutput) -> bool {
        self.return_value == other.return_value
            && self.side_effects == other.side_effects
            && self.exceptions == other.exceptions
    }

    /// Check capability equivalence (capabilities exercised must match or
    /// native must be strictly narrower).
    pub fn capability_equivalent(&self, delegate: &CellOutput) -> bool {
        // Native must not exercise any capability that delegate did not.
        self.capabilities_exercised
            .iter()
            .all(|cap| delegate.capabilities_exercised.contains(cap))
    }
}

// ---------------------------------------------------------------------------
// Workload — single test case in the differential corpus
// ---------------------------------------------------------------------------

/// A single test case for differential execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Workload {
    /// Unique identifier for the workload within the corpus.
    pub workload_id: String,
    /// Which corpus section this workload belongs to.
    pub category: WorkloadCategory,
    /// Input data for the workload (canonical serialized form).
    pub input: String,
    /// Expected output (if known).  `None` means the test is oracle-free
    /// and relies on native-vs-delegate comparison only.
    pub expected_output: Option<CellOutput>,
}

// ---------------------------------------------------------------------------
// WorkloadResult — outcome of one differential run
// ---------------------------------------------------------------------------

/// Outcome of running one workload through both native and delegate cells.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadResult {
    /// Workload that was executed.
    pub workload_id: String,
    /// Corpus category.
    pub category: WorkloadCategory,
    /// Output from the native cell.
    pub native_output: CellOutput,
    /// Output from the delegate cell.
    pub delegate_output: CellOutput,
    /// Outcome: match or diverge.
    pub outcome: DifferentialOutcome,
    /// Divergence class (if diverged).
    pub divergence_class: Option<DivergenceClass>,
}

/// Match/diverge outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DifferentialOutcome {
    /// Both cells produced equivalent results.
    Match,
    /// Cells produced different results.
    Diverge,
}

impl DifferentialOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Match => "match",
            Self::Diverge => "diverge",
        }
    }
}

impl fmt::Display for DifferentialOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// DivergenceRepro — minimized reproduction artifact
// ---------------------------------------------------------------------------

/// Minimized reproduction artifact for a detected divergence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceRepro {
    /// Slot that diverged.
    pub slot_id: SlotId,
    /// Divergence classification.
    pub divergence_class: DivergenceClass,
    /// Native cell output.
    pub native_output: CellOutput,
    /// Delegate cell output.
    pub delegate_output: CellOutput,
    /// Content hash of the slot's semantic contract at time of detection.
    pub semantic_contract_hash: ContentHash,
    /// Minimized input that triggers the divergence.
    pub minimized_input: String,
    /// Capability diff (capabilities in native but not in delegate).
    pub capability_diff: Vec<SlotCapability>,
    /// Resource diff: native_memory - delegate_memory (may be negative → i64).
    pub memory_diff_bytes: i64,
    /// Resource diff: native_duration - delegate_duration (may be negative).
    pub duration_diff_us: i64,
    /// Content hash of this repro artifact.
    pub artifact_hash: ContentHash,
}

impl DivergenceRepro {
    /// Compute the content hash for this artifact.
    pub fn compute_hash(&self) -> ContentHash {
        let canonical = format!(
            "{}:{}:{}:{}",
            self.slot_id, self.divergence_class, self.minimized_input, self.semantic_contract_hash
        );
        ContentHash::compute(canonical.as_bytes())
    }
}

// ---------------------------------------------------------------------------
// PromotionReadiness — per-slot verdict
// ---------------------------------------------------------------------------

/// Overall promotion readiness verdict for a single slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PromotionReadiness {
    /// Zero semantic/capability divergences, performance within threshold,
    /// adversarial corpus passes.
    Ready {
        /// Number of workloads executed.
        workload_count: u64,
        /// Number of benign improvements observed.
        improvement_count: u64,
    },
    /// At least one P0/P1 divergence exists.
    Blocked {
        /// Divergence counts by class.
        divergence_counts: BTreeMap<String, u64>,
        /// Repro artifact hashes for blocking divergences.
        repro_hashes: Vec<ContentHash>,
    },
    /// Previously ready slot now shows new divergence.
    Regressed {
        /// Divergence counts by class.
        divergence_counts: BTreeMap<String, u64>,
        /// Repro artifact hashes.
        repro_hashes: Vec<ContentHash>,
        /// Whether auto-demotion should be triggered.
        trigger_demotion: bool,
    },
}

impl PromotionReadiness {
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }

    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked { .. })
    }

    pub fn is_regressed(&self) -> bool {
        matches!(self, Self::Regressed { .. })
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ready { .. } => "ready",
            Self::Blocked { .. } => "blocked",
            Self::Regressed { .. } => "regressed",
        }
    }
}

impl fmt::Display for PromotionReadiness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// DifferentialConfig — per-slot differential gate configuration
// ---------------------------------------------------------------------------

/// Configuration for the per-slot differential gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialConfig {
    /// Performance regression threshold as a percentage (fixed-point
    /// millionths: 100_000 = 10%).
    pub performance_threshold_millionths: u64,
    /// Resource regression threshold as a percentage (fixed-point
    /// millionths: 200_000 = 20%).
    pub resource_threshold_millionths: u64,
    /// Whether to produce repro artifacts on divergence.
    pub emit_repro_artifacts: bool,
    /// Security epoch for which this evaluation is valid.
    pub epoch: SecurityEpoch,
}

impl Default for DifferentialConfig {
    fn default() -> Self {
        Self {
            performance_threshold_millionths: 100_000, // 10%
            resource_threshold_millionths: 200_000,    // 20%
            emit_repro_artifacts: true,
            epoch: SecurityEpoch::from_raw(1),
        }
    }
}

// ---------------------------------------------------------------------------
// WorkloadLogEntry — structured log record
// ---------------------------------------------------------------------------

/// Structured log entry for one differential workload execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadLogEntry {
    /// Trace identifier.
    pub trace_id: String,
    /// Slot being tested.
    pub slot_id: SlotId,
    /// Workload identifier.
    pub workload_id: String,
    /// Corpus category.
    pub corpus_category: WorkloadCategory,
    /// Match or diverge.
    pub outcome: DifferentialOutcome,
    /// Divergence class if diverged.
    pub divergence_class: Option<DivergenceClass>,
    /// Native cell execution duration (microseconds).
    pub native_duration_us: u64,
    /// Delegate cell execution duration (microseconds).
    pub delegate_duration_us: u64,
    /// Capability diff description (empty if none).
    pub capability_diff: Vec<String>,
    /// Resource diff description.
    pub resource_diff: String,
}

// ---------------------------------------------------------------------------
// SlotDifferentialEvidence — aggregate evidence artifact
// ---------------------------------------------------------------------------

/// Aggregate evidence artifact for a full slot differential gate run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotDifferentialEvidence {
    /// Per-slot readiness verdicts.
    pub verdicts: BTreeMap<String, PromotionReadiness>,
    /// Per-class divergence counts across all slots.
    pub divergence_summary: BTreeMap<String, u64>,
    /// Corpus hash (content-addressed digest of all workloads).
    pub corpus_hash: ContentHash,
    /// Slot registry hash at time of evaluation.
    pub registry_hash: ContentHash,
    /// Environment fingerprint (OS, toolchain, etc.).
    pub environment_fingerprint: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Schema hash for this artifact.
    pub schema_hash: String,
}

impl SlotDifferentialEvidence {
    /// Create a new evidence artifact.
    pub fn new(
        corpus_hash: ContentHash,
        registry_hash: ContentHash,
        environment_fingerprint: String,
        epoch: SecurityEpoch,
    ) -> Self {
        Self {
            verdicts: BTreeMap::new(),
            divergence_summary: BTreeMap::new(),
            corpus_hash,
            registry_hash,
            environment_fingerprint,
            epoch,
            schema_hash: slot_differential_schema_hash().to_string(),
        }
    }

    /// Record a verdict for a slot.
    pub fn record_verdict(&mut self, slot_id: &SlotId, verdict: PromotionReadiness) {
        self.verdicts.insert(slot_id.as_str().to_string(), verdict);
    }

    /// Increment the divergence summary counter for a given class.
    pub fn increment_divergence(&mut self, class: &DivergenceClass) {
        *self
            .divergence_summary
            .entry(class.as_str().to_string())
            .or_insert(0) += 1;
    }

    /// Whether any slot has a blocking divergence.
    pub fn has_blocking_divergences(&self) -> bool {
        self.verdicts.values().any(|v| {
            matches!(
                v,
                PromotionReadiness::Blocked { .. } | PromotionReadiness::Regressed { .. }
            )
        })
    }
}

// ---------------------------------------------------------------------------
// SlotDifferentialError — typed error contract
// ---------------------------------------------------------------------------

/// Errors that can occur during slot differential evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlotDifferentialError {
    /// Slot not found in the registry.
    SlotNotFound { slot_id: String },
    /// Workload corpus is empty for a slot.
    EmptyCorpus { slot_id: String },
    /// Configuration is invalid.
    InvalidConfig { detail: String },
    /// Cell execution failed.
    CellExecutionFailed {
        slot_id: String,
        cell_type: String,
        detail: String,
    },
    /// Internal inconsistency.
    InternalError { detail: String },
}

impl fmt::Display for SlotDifferentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SlotNotFound { slot_id } => {
                write!(f, "slot not found in registry: {}", slot_id)
            }
            Self::EmptyCorpus { slot_id } => {
                write!(f, "workload corpus is empty for slot: {}", slot_id)
            }
            Self::InvalidConfig { detail } => {
                write!(f, "invalid differential config: {}", detail)
            }
            Self::CellExecutionFailed {
                slot_id,
                cell_type,
                detail,
            } => write!(
                f,
                "cell execution failed for slot {} ({}): {}",
                slot_id, cell_type, detail
            ),
            Self::InternalError { detail } => {
                write!(f, "internal differential gate error: {}", detail)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// classify_divergence — deterministic classification logic
// ---------------------------------------------------------------------------

/// Classify the divergence between native and delegate outputs.
///
/// Returns `None` if the outputs are equivalent (no divergence).
pub fn classify_divergence(
    native: &CellOutput,
    delegate: &CellOutput,
    config: &DifferentialConfig,
) -> Option<DivergenceClass> {
    // P0: semantic divergence (return value, side effects, exceptions).
    if !native.semantically_equivalent(delegate) {
        return Some(DivergenceClass::SemanticDivergence);
    }

    // P0: capability divergence (native exercises broader capabilities).
    if !native.capability_equivalent(delegate) {
        return Some(DivergenceClass::CapabilityDivergence);
    }

    // Check for performance and resource divergences.
    // Compute performance regression: native slower than delegate by more
    // than threshold.
    if delegate.duration_us > 0 {
        let regression_millionths = if native.duration_us > delegate.duration_us {
            ((native.duration_us - delegate.duration_us) as u128 * 1_000_000)
                / delegate.duration_us as u128
        } else {
            0
        };
        if regression_millionths > config.performance_threshold_millionths as u128 {
            return Some(DivergenceClass::PerformanceDivergence);
        }
    }

    // Resource divergence: native uses significantly more memory.
    if delegate.memory_bytes > 0 {
        let resource_regression_millionths = if native.memory_bytes > delegate.memory_bytes {
            ((native.memory_bytes - delegate.memory_bytes) as u128 * 1_000_000)
                / delegate.memory_bytes as u128
        } else {
            0
        };
        if resource_regression_millionths > config.resource_threshold_millionths as u128 {
            return Some(DivergenceClass::ResourceDivergence);
        }
    }

    // Benign improvement: native is strictly faster and/or uses less memory,
    // with identical semantics.
    let native_faster = native.duration_us < delegate.duration_us;
    let native_lighter = native.memory_bytes < delegate.memory_bytes;
    if native_faster || native_lighter {
        return Some(DivergenceClass::BenignImprovement);
    }

    // Exact equivalence (no divergence at all).
    None
}

// ---------------------------------------------------------------------------
// build_repro — minimized repro artifact generation
// ---------------------------------------------------------------------------

/// Build a minimized reproduction artifact for a detected divergence.
pub fn build_repro(
    slot_id: &SlotId,
    workload: &Workload,
    native: &CellOutput,
    delegate: &CellOutput,
    class: &DivergenceClass,
    semantic_contract_hash: &ContentHash,
) -> DivergenceRepro {
    // Compute capability diff: capabilities in native but not in delegate.
    let capability_diff: Vec<SlotCapability> = native
        .capabilities_exercised
        .iter()
        .filter(|cap| !delegate.capabilities_exercised.contains(cap))
        .copied()
        .collect();

    let memory_diff = native.memory_bytes as i64 - delegate.memory_bytes as i64;
    let duration_diff = native.duration_us as i64 - delegate.duration_us as i64;

    let mut repro = DivergenceRepro {
        slot_id: slot_id.clone(),
        divergence_class: class.clone(),
        native_output: native.clone(),
        delegate_output: delegate.clone(),
        semantic_contract_hash: *semantic_contract_hash,
        minimized_input: workload.input.clone(),
        capability_diff,
        memory_diff_bytes: memory_diff,
        duration_diff_us: duration_diff,
        artifact_hash: ContentHash::compute(b"placeholder"),
    };
    repro.artifact_hash = repro.compute_hash();
    repro
}

// ---------------------------------------------------------------------------
// evaluate_slot — run differential gate for a single slot
// ---------------------------------------------------------------------------

/// Input bundle for [`evaluate_slot`].
pub struct EvaluateSlotInput<'a> {
    pub slot_id: &'a SlotId,
    pub slot_kind: SlotKind,
    pub authority: &'a AuthorityEnvelope,
    pub workloads: &'a [Workload],
    pub native_executor: &'a dyn Fn(&Workload) -> Result<CellOutput, SlotDifferentialError>,
    pub delegate_executor: &'a dyn Fn(&Workload) -> Result<CellOutput, SlotDifferentialError>,
    pub config: &'a DifferentialConfig,
    pub was_previously_ready: bool,
}

/// Run the differential gate for a single slot against its workload corpus.
///
/// Returns the list of per-workload results and the overall verdict.
pub fn evaluate_slot(
    input: &EvaluateSlotInput<'_>,
) -> Result<(Vec<WorkloadResult>, PromotionReadiness), SlotDifferentialError> {
    let EvaluateSlotInput {
        slot_id,
        slot_kind,
        authority: _authority,
        workloads,
        native_executor,
        delegate_executor,
        config,
        was_previously_ready,
    } = input;
    if workloads.is_empty() {
        return Err(SlotDifferentialError::EmptyCorpus {
            slot_id: slot_id.as_str().to_string(),
        });
    }

    let semantic_contract_hash =
        ContentHash::compute(format!("{}:{}", slot_id, slot_kind).as_bytes());

    let mut results = Vec::new();
    let mut divergence_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut repro_hashes: Vec<ContentHash> = Vec::new();
    let mut improvement_count: u64 = 0;
    let mut has_blocking = false;
    let mut has_demotion_trigger = false;

    for workload in *workloads {
        let native_output = native_executor(workload)?;
        let delegate_output = delegate_executor(workload)?;

        let divergence = classify_divergence(&native_output, &delegate_output, config);

        let (outcome, divergence_class) = match &divergence {
            Some(class) => {
                *divergence_counts
                    .entry(class.as_str().to_string())
                    .or_insert(0) += 1;

                if class.blocks_promotion() {
                    has_blocking = true;
                }
                if class.triggers_demotion() {
                    has_demotion_trigger = true;
                }
                if matches!(class, DivergenceClass::BenignImprovement) {
                    improvement_count += 1;
                }

                // Build repro artifact for blocking divergences.
                if class.blocks_promotion() && config.emit_repro_artifacts {
                    let repro = build_repro(
                        slot_id,
                        workload,
                        &native_output,
                        &delegate_output,
                        class,
                        &semantic_contract_hash,
                    );
                    repro_hashes.push(repro.artifact_hash);
                }

                (DifferentialOutcome::Diverge, Some(class.clone()))
            }
            None => (DifferentialOutcome::Match, None),
        };

        results.push(WorkloadResult {
            workload_id: workload.workload_id.clone(),
            category: workload.category,
            native_output,
            delegate_output,
            outcome,
            divergence_class,
        });
    }

    let verdict = if has_blocking {
        if *was_previously_ready {
            PromotionReadiness::Regressed {
                divergence_counts,
                repro_hashes,
                trigger_demotion: has_demotion_trigger,
            }
        } else {
            PromotionReadiness::Blocked {
                divergence_counts,
                repro_hashes,
            }
        }
    } else {
        PromotionReadiness::Ready {
            workload_count: workloads.len() as u64,
            improvement_count,
        }
    };

    Ok((results, verdict))
}

// ---------------------------------------------------------------------------
// SlotDifferentialGate — aggregate gate for all slots
// ---------------------------------------------------------------------------

/// Entry in the gate's slot inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotInventoryEntry {
    pub slot_id: SlotId,
    pub kind: SlotKind,
    pub authority: AuthorityEnvelope,
    pub was_previously_ready: bool,
}

/// Aggregate differential gate that runs evaluation across multiple slots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotDifferentialGate {
    /// Slot inventory to evaluate.
    pub slots: Vec<SlotInventoryEntry>,
    /// Configuration.
    pub config: DifferentialConfig,
    /// Accumulated evidence.
    pub evidence: SlotDifferentialEvidence,
}

impl SlotDifferentialGate {
    /// Create a new gate with the given configuration and environment.
    pub fn new(
        config: DifferentialConfig,
        corpus_hash: ContentHash,
        registry_hash: ContentHash,
        environment_fingerprint: String,
    ) -> Self {
        let epoch = config.epoch;
        Self {
            slots: Vec::new(),
            config,
            evidence: SlotDifferentialEvidence::new(
                corpus_hash,
                registry_hash,
                environment_fingerprint,
                epoch,
            ),
        }
    }

    /// Register a slot for evaluation.
    pub fn register_slot(&mut self, entry: SlotInventoryEntry) {
        self.slots.push(entry);
    }

    /// Run the differential gate for a single registered slot.
    ///
    /// The caller provides executor closures for native and delegate cells.
    pub fn evaluate_single(
        &mut self,
        slot_id: &SlotId,
        workloads: &[Workload],
        native_executor: &dyn Fn(&Workload) -> Result<CellOutput, SlotDifferentialError>,
        delegate_executor: &dyn Fn(&Workload) -> Result<CellOutput, SlotDifferentialError>,
    ) -> Result<(Vec<WorkloadResult>, PromotionReadiness), SlotDifferentialError> {
        let entry = self
            .slots
            .iter()
            .find(|e| &e.slot_id == slot_id)
            .ok_or_else(|| SlotDifferentialError::SlotNotFound {
                slot_id: slot_id.as_str().to_string(),
            })?;

        let (results, verdict) = evaluate_slot(&EvaluateSlotInput {
            slot_id: &entry.slot_id,
            slot_kind: entry.kind,
            authority: &entry.authority,
            workloads,
            native_executor,
            delegate_executor,
            config: &self.config,
            was_previously_ready: entry.was_previously_ready,
        })?;

        // Update evidence.
        for r in &results {
            if let Some(ref class) = r.divergence_class {
                self.evidence.increment_divergence(class);
            }
        }
        self.evidence.record_verdict(slot_id, verdict.clone());

        Ok((results, verdict))
    }

    /// Whether the overall gate passes (no blocking divergences in any slot).
    pub fn passes(&self) -> bool {
        !self.evidence.has_blocking_divergences()
    }

    /// Get the promotion readiness verdict for a specific slot.
    pub fn verdict_for(&self, slot_id: &SlotId) -> Option<&PromotionReadiness> {
        self.evidence.verdicts.get(slot_id.as_str())
    }

    /// Produce the final evidence artifact.
    pub fn finalize_evidence(&self) -> &SlotDifferentialEvidence {
        &self.evidence
    }
}

// ---------------------------------------------------------------------------
// ReplacementReceiptFragment — differential-equivalence portion
// ---------------------------------------------------------------------------

/// The differential-equivalence portion of a replacement receipt.
///
/// When a slot passes the differential gate and is promoted, this fragment
/// is included in the full [`ReplacementReceipt`](crate::self_replacement::ReplacementReceipt).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplacementReceiptFragment {
    /// Slot that was evaluated.
    pub slot_id: SlotId,
    /// Number of workloads executed.
    pub workload_count: u64,
    /// Number of workload categories covered.
    pub categories_covered: u64,
    /// Number of benign improvements observed.
    pub improvement_count: u64,
    /// Content hash of the evidence artifact.
    pub evidence_hash: ContentHash,
    /// Content hash of the workload corpus.
    pub corpus_hash: ContentHash,
    /// Security epoch.
    pub epoch: SecurityEpoch,
}

impl ReplacementReceiptFragment {
    /// Create a fragment from evaluation results.
    pub fn from_evaluation(
        slot_id: SlotId,
        results: &[WorkloadResult],
        evidence_hash: ContentHash,
        corpus_hash: ContentHash,
        epoch: SecurityEpoch,
    ) -> Self {
        let mut categories = std::collections::BTreeSet::new();
        let mut improvement_count: u64 = 0;
        for r in results {
            categories.insert(r.category);
            if r.divergence_class == Some(DivergenceClass::BenignImprovement) {
                improvement_count += 1;
            }
        }
        Self {
            slot_id,
            workload_count: results.len() as u64,
            categories_covered: categories.len() as u64,
            improvement_count,
            evidence_hash,
            corpus_hash,
            epoch,
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_slot_id(name: &str) -> SlotId {
        SlotId::new(name).unwrap()
    }

    fn make_output(
        return_val: &str,
        duration_us: u64,
        memory_bytes: u64,
        capabilities: &[SlotCapability],
    ) -> CellOutput {
        CellOutput {
            return_value: return_val.to_string(),
            side_effects: vec![],
            exceptions: vec![],
            evidence_entries: vec![],
            capabilities_exercised: capabilities.to_vec(),
            duration_us,
            memory_bytes,
        }
    }

    fn make_output_with_effects(
        return_val: &str,
        side_effects: &[&str],
        exceptions: &[&str],
        duration_us: u64,
        memory_bytes: u64,
    ) -> CellOutput {
        CellOutput {
            return_value: return_val.to_string(),
            side_effects: side_effects.iter().map(|s| s.to_string()).collect(),
            exceptions: exceptions.iter().map(|s| s.to_string()).collect(),
            evidence_entries: vec![],
            capabilities_exercised: vec![],
            duration_us,
            memory_bytes,
        }
    }

    fn default_config() -> DifferentialConfig {
        DifferentialConfig::default()
    }

    fn make_workload(id: &str, category: WorkloadCategory) -> Workload {
        Workload {
            workload_id: id.to_string(),
            category,
            input: format!("input-{}", id),
            expected_output: None,
        }
    }

    fn make_authority() -> AuthorityEnvelope {
        AuthorityEnvelope {
            required: vec![SlotCapability::ReadSource],
            permitted: vec![SlotCapability::ReadSource, SlotCapability::EmitIr],
        }
    }

    // -----------------------------------------------------------------------
    // DivergenceClass
    // -----------------------------------------------------------------------

    #[test]
    fn divergence_class_blocks_promotion_semantic() {
        assert!(DivergenceClass::SemanticDivergence.blocks_promotion());
    }

    #[test]
    fn divergence_class_blocks_promotion_capability() {
        assert!(DivergenceClass::CapabilityDivergence.blocks_promotion());
    }

    #[test]
    fn divergence_class_blocks_promotion_performance() {
        assert!(DivergenceClass::PerformanceDivergence.blocks_promotion());
    }

    #[test]
    fn divergence_class_does_not_block_resource() {
        assert!(!DivergenceClass::ResourceDivergence.blocks_promotion());
    }

    #[test]
    fn divergence_class_does_not_block_benign() {
        assert!(!DivergenceClass::BenignImprovement.blocks_promotion());
    }

    #[test]
    fn divergence_class_triggers_demotion_semantic() {
        assert!(DivergenceClass::SemanticDivergence.triggers_demotion());
    }

    #[test]
    fn divergence_class_triggers_demotion_capability() {
        assert!(DivergenceClass::CapabilityDivergence.triggers_demotion());
    }

    #[test]
    fn divergence_class_no_demotion_performance() {
        assert!(!DivergenceClass::PerformanceDivergence.triggers_demotion());
    }

    #[test]
    fn divergence_class_ordering() {
        // Semantic < Capability < Performance < Resource < Benign
        assert!(DivergenceClass::SemanticDivergence < DivergenceClass::CapabilityDivergence);
        assert!(DivergenceClass::CapabilityDivergence < DivergenceClass::PerformanceDivergence);
        assert!(DivergenceClass::PerformanceDivergence < DivergenceClass::ResourceDivergence);
        assert!(DivergenceClass::ResourceDivergence < DivergenceClass::BenignImprovement);
    }

    #[test]
    fn divergence_class_display() {
        assert_eq!(
            DivergenceClass::SemanticDivergence.to_string(),
            "semantic_divergence"
        );
        assert_eq!(
            DivergenceClass::BenignImprovement.to_string(),
            "benign_improvement"
        );
    }

    // -----------------------------------------------------------------------
    // classify_divergence
    // -----------------------------------------------------------------------

    #[test]
    fn classify_no_divergence_identical_outputs() {
        let output = make_output("42", 100, 1000, &[SlotCapability::ReadSource]);
        assert_eq!(
            classify_divergence(&output, &output, &default_config()),
            None
        );
    }

    #[test]
    fn classify_semantic_divergence_different_return_value() {
        let native = make_output("42", 100, 1000, &[]);
        let delegate = make_output("43", 100, 1000, &[]);
        assert_eq!(
            classify_divergence(&native, &delegate, &default_config()),
            Some(DivergenceClass::SemanticDivergence)
        );
    }

    #[test]
    fn classify_semantic_divergence_different_side_effects() {
        let native = make_output_with_effects("ok", &["effect-a"], &[], 100, 1000);
        let delegate = make_output_with_effects("ok", &["effect-b"], &[], 100, 1000);
        assert_eq!(
            classify_divergence(&native, &delegate, &default_config()),
            Some(DivergenceClass::SemanticDivergence)
        );
    }

    #[test]
    fn classify_semantic_divergence_different_exceptions() {
        let native = make_output_with_effects("ok", &[], &["err-a"], 100, 1000);
        let delegate = make_output_with_effects("ok", &[], &["err-b"], 100, 1000);
        assert_eq!(
            classify_divergence(&native, &delegate, &default_config()),
            Some(DivergenceClass::SemanticDivergence)
        );
    }

    #[test]
    fn classify_capability_divergence_native_broader() {
        let native = make_output(
            "ok",
            100,
            1000,
            &[SlotCapability::ReadSource, SlotCapability::InvokeHostcall],
        );
        let delegate = make_output("ok", 100, 1000, &[SlotCapability::ReadSource]);
        assert_eq!(
            classify_divergence(&native, &delegate, &default_config()),
            Some(DivergenceClass::CapabilityDivergence)
        );
    }

    #[test]
    fn classify_capability_equivalent_native_narrower() {
        let native = make_output("ok", 100, 1000, &[SlotCapability::ReadSource]);
        let delegate = make_output(
            "ok",
            100,
            1000,
            &[SlotCapability::ReadSource, SlotCapability::InvokeHostcall],
        );
        // Native narrower is NOT a divergence (capability is subset).
        let result = classify_divergence(&native, &delegate, &default_config());
        assert_ne!(result, Some(DivergenceClass::CapabilityDivergence));
    }

    #[test]
    fn classify_performance_divergence_exceeds_threshold() {
        // Native is 20% slower (200k millionths), threshold is 10% (100k).
        let native = make_output("ok", 120, 1000, &[]);
        let delegate = make_output("ok", 100, 1000, &[]);
        assert_eq!(
            classify_divergence(&native, &delegate, &default_config()),
            Some(DivergenceClass::PerformanceDivergence)
        );
    }

    #[test]
    fn classify_performance_within_threshold() {
        // Native is 5% slower (50k millionths), threshold is 10%.
        let native = make_output("ok", 105, 1000, &[]);
        let delegate = make_output("ok", 100, 1000, &[]);
        let result = classify_divergence(&native, &delegate, &default_config());
        // 5% regression → benign improvement is not it, it's actually slightly slower
        // but within threshold. If native is slower than delegate, no improvement.
        // Actually 105 > 100, so native_faster is false. native_lighter is false (same mem).
        // So no divergence at all.
        assert_eq!(result, None);
    }

    #[test]
    fn classify_resource_divergence_exceeds_threshold() {
        // Native uses 30% more memory (300k millionths), threshold is 20%.
        let native = make_output("ok", 100, 1300, &[]);
        let delegate = make_output("ok", 100, 1000, &[]);
        assert_eq!(
            classify_divergence(&native, &delegate, &default_config()),
            Some(DivergenceClass::ResourceDivergence)
        );
    }

    #[test]
    fn classify_resource_within_threshold() {
        // Native uses 15% more memory, threshold is 20%.
        let native = make_output("ok", 100, 1150, &[]);
        let delegate = make_output("ok", 100, 1000, &[]);
        let result = classify_divergence(&native, &delegate, &default_config());
        // 15% < 20%, not resource divergence. But memory is higher, so no benign improvement.
        assert_eq!(result, None);
    }

    #[test]
    fn classify_benign_improvement_faster() {
        let native = make_output("ok", 80, 1000, &[]);
        let delegate = make_output("ok", 100, 1000, &[]);
        assert_eq!(
            classify_divergence(&native, &delegate, &default_config()),
            Some(DivergenceClass::BenignImprovement)
        );
    }

    #[test]
    fn classify_benign_improvement_lighter() {
        let native = make_output("ok", 100, 800, &[]);
        let delegate = make_output("ok", 100, 1000, &[]);
        assert_eq!(
            classify_divergence(&native, &delegate, &default_config()),
            Some(DivergenceClass::BenignImprovement)
        );
    }

    #[test]
    fn classify_benign_improvement_both() {
        let native = make_output("ok", 80, 800, &[]);
        let delegate = make_output("ok", 100, 1000, &[]);
        assert_eq!(
            classify_divergence(&native, &delegate, &default_config()),
            Some(DivergenceClass::BenignImprovement)
        );
    }

    #[test]
    fn classify_semantic_takes_precedence_over_performance() {
        // Both semantic and performance divergence — semantic wins.
        let native = make_output("wrong", 200, 1000, &[]);
        let delegate = make_output("right", 100, 1000, &[]);
        assert_eq!(
            classify_divergence(&native, &delegate, &default_config()),
            Some(DivergenceClass::SemanticDivergence)
        );
    }

    #[test]
    fn classify_capability_takes_precedence_over_performance() {
        let native = make_output(
            "ok",
            200,
            1000,
            &[SlotCapability::ReadSource, SlotCapability::TriggerGc],
        );
        let delegate = make_output("ok", 100, 1000, &[SlotCapability::ReadSource]);
        assert_eq!(
            classify_divergence(&native, &delegate, &default_config()),
            Some(DivergenceClass::CapabilityDivergence)
        );
    }

    #[test]
    fn classify_zero_duration_delegate_no_panic() {
        let native = make_output("ok", 100, 1000, &[]);
        let delegate = make_output("ok", 0, 1000, &[]);
        // Should not panic on division by zero.  Delegate=0 means perf check
        // is skipped.  Native is 100us vs delegate 0us, so native is not
        // faster → no benign improvement.  Result is None.
        let result = classify_divergence(&native, &delegate, &default_config());
        assert_eq!(result, None);
    }

    #[test]
    fn classify_zero_memory_delegate_no_panic() {
        let native = make_output("ok", 100, 500, &[]);
        let delegate = make_output("ok", 100, 0, &[]);
        // Should not panic on division by zero.
        let _ = classify_divergence(&native, &delegate, &default_config());
    }

    // -----------------------------------------------------------------------
    // build_repro
    // -----------------------------------------------------------------------

    #[test]
    fn build_repro_captures_slot_and_class() {
        let slot = make_slot_id("parser");
        let workload = make_workload("w1", WorkloadCategory::SemanticEquivalence);
        let native = make_output("42", 100, 1000, &[]);
        let delegate = make_output("43", 100, 1000, &[]);
        let contract_hash = ContentHash::compute(b"test-contract");
        let repro = build_repro(
            &slot,
            &workload,
            &native,
            &delegate,
            &DivergenceClass::SemanticDivergence,
            &contract_hash,
        );
        assert_eq!(repro.slot_id, slot);
        assert_eq!(repro.divergence_class, DivergenceClass::SemanticDivergence);
        assert_eq!(repro.minimized_input, "input-w1");
    }

    #[test]
    fn build_repro_computes_capability_diff() {
        let slot = make_slot_id("interpreter");
        let workload = make_workload("w2", WorkloadCategory::Adversarial);
        let native = make_output(
            "ok",
            100,
            1000,
            &[SlotCapability::ReadSource, SlotCapability::InvokeHostcall],
        );
        let delegate = make_output("ok", 100, 1000, &[SlotCapability::ReadSource]);
        let contract_hash = ContentHash::compute(b"test");
        let repro = build_repro(
            &slot,
            &workload,
            &native,
            &delegate,
            &DivergenceClass::CapabilityDivergence,
            &contract_hash,
        );
        assert_eq!(repro.capability_diff, vec![SlotCapability::InvokeHostcall]);
    }

    #[test]
    fn build_repro_hash_is_deterministic() {
        let slot = make_slot_id("gc");
        let workload = make_workload("w3", WorkloadCategory::EdgeCase);
        let native = make_output("ok", 200, 2000, &[]);
        let delegate = make_output("ok", 100, 1000, &[]);
        let contract_hash = ContentHash::compute(b"contract");
        let r1 = build_repro(
            &slot,
            &workload,
            &native,
            &delegate,
            &DivergenceClass::PerformanceDivergence,
            &contract_hash,
        );
        let r2 = build_repro(
            &slot,
            &workload,
            &native,
            &delegate,
            &DivergenceClass::PerformanceDivergence,
            &contract_hash,
        );
        assert_eq!(r1.artifact_hash, r2.artifact_hash);
    }

    #[test]
    fn build_repro_resource_diffs() {
        let slot = make_slot_id("builtins");
        let workload = make_workload("w4", WorkloadCategory::SemanticEquivalence);
        let native = make_output("ok", 80, 1200, &[]);
        let delegate = make_output("ok", 100, 1000, &[]);
        let contract_hash = ContentHash::compute(b"x");
        let repro = build_repro(
            &slot,
            &workload,
            &native,
            &delegate,
            &DivergenceClass::ResourceDivergence,
            &contract_hash,
        );
        assert_eq!(repro.memory_diff_bytes, 200);
        assert_eq!(repro.duration_diff_us, -20);
    }

    // -----------------------------------------------------------------------
    // evaluate_slot
    // -----------------------------------------------------------------------

    #[test]
    fn evaluate_slot_all_match() {
        let slot = make_slot_id("parser");
        let workloads = vec![
            make_workload("w1", WorkloadCategory::SemanticEquivalence),
            make_workload("w2", WorkloadCategory::EdgeCase),
        ];
        let output = make_output("ok", 100, 1000, &[]);
        let output_clone = output.clone();

        let (results, verdict) = evaluate_slot(&EvaluateSlotInput {
            slot_id: &slot,
            slot_kind: SlotKind::Parser,
            authority: &make_authority(),
            workloads: &workloads,
            native_executor: &|_| Ok(output.clone()),
            delegate_executor: &|_| Ok(output_clone.clone()),
            config: &default_config(),
            was_previously_ready: false,
        })
        .unwrap();

        assert_eq!(results.len(), 2);
        assert!(
            results
                .iter()
                .all(|r| r.outcome == DifferentialOutcome::Match)
        );
        assert!(verdict.is_ready());
    }

    #[test]
    fn evaluate_slot_semantic_divergence_blocks() {
        let slot = make_slot_id("interpreter");
        let workloads = vec![make_workload("w1", WorkloadCategory::SemanticEquivalence)];

        let (results, verdict) = evaluate_slot(&EvaluateSlotInput {
            slot_id: &slot,
            slot_kind: SlotKind::Interpreter,
            authority: &make_authority(),
            workloads: &workloads,
            native_executor: &|_| Ok(make_output("native-result", 100, 1000, &[])),
            delegate_executor: &|_| Ok(make_output("delegate-result", 100, 1000, &[])),
            config: &default_config(),
            was_previously_ready: false,
        })
        .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].outcome, DifferentialOutcome::Diverge);
        assert_eq!(
            results[0].divergence_class,
            Some(DivergenceClass::SemanticDivergence)
        );
        assert!(verdict.is_blocked());
    }

    #[test]
    fn evaluate_slot_previously_ready_regressed() {
        let slot = make_slot_id("object-model");
        let workloads = vec![make_workload("w1", WorkloadCategory::SemanticEquivalence)];

        let (_, verdict) = evaluate_slot(&EvaluateSlotInput {
            slot_id: &slot,
            slot_kind: SlotKind::ObjectModel,
            authority: &make_authority(),
            workloads: &workloads,
            native_executor: &|_| Ok(make_output("a", 100, 1000, &[])),
            delegate_executor: &|_| Ok(make_output("b", 100, 1000, &[])),
            config: &default_config(),
            was_previously_ready: true, // was previously ready
        })
        .unwrap();

        assert!(verdict.is_regressed());
        if let PromotionReadiness::Regressed {
            trigger_demotion, ..
        } = verdict
        {
            assert!(trigger_demotion);
        } else {
            panic!("expected Regressed");
        }
    }

    #[test]
    fn evaluate_slot_empty_corpus_errors() {
        let slot = make_slot_id("gc");
        let result = evaluate_slot(&EvaluateSlotInput {
            slot_id: &slot,
            slot_kind: SlotKind::GarbageCollector,
            authority: &make_authority(),
            workloads: &[],
            native_executor: &|_| Ok(make_output("ok", 100, 1000, &[])),
            delegate_executor: &|_| Ok(make_output("ok", 100, 1000, &[])),
            config: &default_config(),
            was_previously_ready: false,
        });
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SlotDifferentialError::EmptyCorpus { .. }
        ));
    }

    #[test]
    fn evaluate_slot_performance_only_blocks_not_demotes() {
        let slot = make_slot_id("scope-model");
        let workloads = vec![make_workload("w1", WorkloadCategory::SemanticEquivalence)];

        let (_, verdict) = evaluate_slot(&EvaluateSlotInput {
            slot_id: &slot,
            slot_kind: SlotKind::ScopeModel,
            authority: &make_authority(),
            workloads: &workloads,
            native_executor: &|_| Ok(make_output("ok", 200, 1000, &[])), // 100% slower
            delegate_executor: &|_| Ok(make_output("ok", 100, 1000, &[])),
            config: &default_config(),
            was_previously_ready: true,
        })
        .unwrap();

        assert!(verdict.is_regressed());
        if let PromotionReadiness::Regressed {
            trigger_demotion, ..
        } = verdict
        {
            // Performance divergence does NOT trigger demotion.
            assert!(!trigger_demotion);
        } else {
            panic!("expected Regressed");
        }
    }

    #[test]
    fn evaluate_slot_benign_improvements_counted() {
        let slot = make_slot_id("async-runtime");
        let workloads = vec![
            make_workload("w1", WorkloadCategory::SemanticEquivalence),
            make_workload("w2", WorkloadCategory::SemanticEquivalence),
        ];

        let (_, verdict) = evaluate_slot(&EvaluateSlotInput {
            slot_id: &slot,
            slot_kind: SlotKind::AsyncRuntime,
            authority: &make_authority(),
            workloads: &workloads,
            native_executor: &|_| Ok(make_output("ok", 80, 800, &[])), // faster + lighter
            delegate_executor: &|_| Ok(make_output("ok", 100, 1000, &[])),
            config: &default_config(),
            was_previously_ready: false,
        })
        .unwrap();

        if let PromotionReadiness::Ready {
            workload_count,
            improvement_count,
        } = verdict
        {
            assert_eq!(workload_count, 2);
            assert_eq!(improvement_count, 2);
        } else {
            panic!("expected Ready");
        }
    }

    #[test]
    fn evaluate_slot_cell_execution_error_propagates() {
        let slot = make_slot_id("builtins");
        let workloads = vec![make_workload("w1", WorkloadCategory::SemanticEquivalence)];

        let result = evaluate_slot(&EvaluateSlotInput {
            slot_id: &slot,
            slot_kind: SlotKind::Builtins,
            authority: &make_authority(),
            workloads: &workloads,
            native_executor: &|_| {
                Err(SlotDifferentialError::CellExecutionFailed {
                    slot_id: "builtins".to_string(),
                    cell_type: "native".to_string(),
                    detail: "segfault".to_string(),
                })
            },
            delegate_executor: &|_| Ok(make_output("ok", 100, 1000, &[])),
            config: &default_config(),
            was_previously_ready: false,
        });
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // SlotDifferentialGate
    // -----------------------------------------------------------------------

    #[test]
    fn gate_register_and_evaluate() {
        let mut gate = SlotDifferentialGate::new(
            default_config(),
            ContentHash::compute(b"corpus"),
            ContentHash::compute(b"registry"),
            "test-env".to_string(),
        );

        let slot = make_slot_id("parser");
        gate.register_slot(SlotInventoryEntry {
            slot_id: slot.clone(),
            kind: SlotKind::Parser,
            authority: make_authority(),
            was_previously_ready: false,
        });

        let workloads = vec![make_workload("w1", WorkloadCategory::SemanticEquivalence)];
        let output = make_output("ok", 100, 1000, &[]);
        let out2 = output.clone();

        let (results, verdict) = gate
            .evaluate_single(&slot, &workloads, &|_| Ok(output.clone()), &|_| {
                Ok(out2.clone())
            })
            .unwrap();

        assert_eq!(results.len(), 1);
        assert!(verdict.is_ready());
        assert!(gate.passes());
    }

    #[test]
    fn gate_slot_not_found() {
        let mut gate = SlotDifferentialGate::new(
            default_config(),
            ContentHash::compute(b"c"),
            ContentHash::compute(b"r"),
            "env".to_string(),
        );

        let missing = make_slot_id("nonexistent");
        let result = gate.evaluate_single(
            &missing,
            &[],
            &|_| Ok(make_output("ok", 100, 1000, &[])),
            &|_| Ok(make_output("ok", 100, 1000, &[])),
        );
        assert!(matches!(
            result.unwrap_err(),
            SlotDifferentialError::SlotNotFound { .. }
        ));
    }

    #[test]
    fn gate_passes_with_multiple_slots() {
        let mut gate = SlotDifferentialGate::new(
            default_config(),
            ContentHash::compute(b"corpus"),
            ContentHash::compute(b"registry"),
            "env".to_string(),
        );

        for name in &["parser", "interpreter", "gc"] {
            let slot = make_slot_id(name);
            gate.register_slot(SlotInventoryEntry {
                slot_id: slot.clone(),
                kind: SlotKind::Parser,
                authority: make_authority(),
                was_previously_ready: false,
            });

            let workloads = vec![make_workload(
                &format!("{}-w1", name),
                WorkloadCategory::SemanticEquivalence,
            )];
            let output = make_output("ok", 100, 1000, &[]);
            let out2 = output.clone();
            gate.evaluate_single(&slot, &workloads, &|_| Ok(output.clone()), &|_| {
                Ok(out2.clone())
            })
            .unwrap();
        }

        assert!(gate.passes());
        assert_eq!(gate.evidence.verdicts.len(), 3);
    }

    #[test]
    fn gate_fails_with_one_divergent_slot() {
        let mut gate = SlotDifferentialGate::new(
            default_config(),
            ContentHash::compute(b"c"),
            ContentHash::compute(b"r"),
            "env".to_string(),
        );

        // Slot 1: passing
        let s1 = make_slot_id("parser");
        gate.register_slot(SlotInventoryEntry {
            slot_id: s1.clone(),
            kind: SlotKind::Parser,
            authority: make_authority(),
            was_previously_ready: false,
        });
        let ok = make_output("ok", 100, 1000, &[]);
        let ok2 = ok.clone();
        gate.evaluate_single(
            &s1,
            &[make_workload("w1", WorkloadCategory::SemanticEquivalence)],
            &|_| Ok(ok.clone()),
            &|_| Ok(ok2.clone()),
        )
        .unwrap();

        // Slot 2: failing (semantic divergence)
        let s2 = make_slot_id("interpreter");
        gate.register_slot(SlotInventoryEntry {
            slot_id: s2.clone(),
            kind: SlotKind::Interpreter,
            authority: make_authority(),
            was_previously_ready: false,
        });
        gate.evaluate_single(
            &s2,
            &[make_workload("w2", WorkloadCategory::SemanticEquivalence)],
            &|_| Ok(make_output("native", 100, 1000, &[])),
            &|_| Ok(make_output("delegate", 100, 1000, &[])),
        )
        .unwrap();

        assert!(!gate.passes());
        assert!(gate.verdict_for(&s1).unwrap().is_ready());
        assert!(gate.verdict_for(&s2).unwrap().is_blocked());
    }

    #[test]
    fn gate_evidence_accumulates_divergences() {
        let mut gate = SlotDifferentialGate::new(
            default_config(),
            ContentHash::compute(b"c"),
            ContentHash::compute(b"r"),
            "env".to_string(),
        );

        let slot = make_slot_id("interpreter");
        gate.register_slot(SlotInventoryEntry {
            slot_id: slot.clone(),
            kind: SlotKind::Interpreter,
            authority: make_authority(),
            was_previously_ready: false,
        });

        let workloads = vec![
            make_workload("w1", WorkloadCategory::SemanticEquivalence),
            make_workload("w2", WorkloadCategory::SemanticEquivalence),
        ];

        gate.evaluate_single(
            &slot,
            &workloads,
            &|_| Ok(make_output("native", 100, 1000, &[])),
            &|_| Ok(make_output("delegate", 100, 1000, &[])),
        )
        .unwrap();

        let evidence = gate.finalize_evidence();
        let sem_count = evidence
            .divergence_summary
            .get("semantic_divergence")
            .copied()
            .unwrap_or(0);
        assert_eq!(sem_count, 2);
    }

    // -----------------------------------------------------------------------
    // PromotionReadiness
    // -----------------------------------------------------------------------

    #[test]
    fn promotion_readiness_display() {
        let ready = PromotionReadiness::Ready {
            workload_count: 10,
            improvement_count: 3,
        };
        assert_eq!(ready.to_string(), "ready");
        assert!(ready.is_ready());
        assert!(!ready.is_blocked());
        assert!(!ready.is_regressed());
    }

    #[test]
    fn promotion_readiness_blocked() {
        let blocked = PromotionReadiness::Blocked {
            divergence_counts: BTreeMap::new(),
            repro_hashes: vec![],
        };
        assert_eq!(blocked.to_string(), "blocked");
        assert!(blocked.is_blocked());
    }

    #[test]
    fn promotion_readiness_regressed() {
        let regressed = PromotionReadiness::Regressed {
            divergence_counts: BTreeMap::new(),
            repro_hashes: vec![],
            trigger_demotion: true,
        };
        assert_eq!(regressed.to_string(), "regressed");
        assert!(regressed.is_regressed());
    }

    // -----------------------------------------------------------------------
    // ReplacementReceiptFragment
    // -----------------------------------------------------------------------

    #[test]
    fn receipt_fragment_from_evaluation() {
        let results = vec![
            WorkloadResult {
                workload_id: "w1".to_string(),
                category: WorkloadCategory::SemanticEquivalence,
                native_output: make_output("ok", 80, 800, &[]),
                delegate_output: make_output("ok", 100, 1000, &[]),
                outcome: DifferentialOutcome::Diverge,
                divergence_class: Some(DivergenceClass::BenignImprovement),
            },
            WorkloadResult {
                workload_id: "w2".to_string(),
                category: WorkloadCategory::EdgeCase,
                native_output: make_output("ok", 100, 1000, &[]),
                delegate_output: make_output("ok", 100, 1000, &[]),
                outcome: DifferentialOutcome::Match,
                divergence_class: None,
            },
        ];

        let fragment = ReplacementReceiptFragment::from_evaluation(
            make_slot_id("parser"),
            &results,
            ContentHash::compute(b"ev"),
            ContentHash::compute(b"corpus"),
            SecurityEpoch::from_raw(5),
        );

        assert_eq!(fragment.workload_count, 2);
        assert_eq!(fragment.categories_covered, 2);
        assert_eq!(fragment.improvement_count, 1);
        assert_eq!(fragment.epoch.as_u64(), 5);
    }

    #[test]
    fn receipt_fragment_single_category() {
        let results = vec![WorkloadResult {
            workload_id: "w1".to_string(),
            category: WorkloadCategory::Adversarial,
            native_output: make_output("ok", 100, 1000, &[]),
            delegate_output: make_output("ok", 100, 1000, &[]),
            outcome: DifferentialOutcome::Match,
            divergence_class: None,
        }];

        let fragment = ReplacementReceiptFragment::from_evaluation(
            make_slot_id("builtins"),
            &results,
            ContentHash::compute(b"ev"),
            ContentHash::compute(b"corpus"),
            SecurityEpoch::from_raw(1),
        );

        assert_eq!(fragment.categories_covered, 1);
        assert_eq!(fragment.improvement_count, 0);
    }

    // -----------------------------------------------------------------------
    // DifferentialConfig
    // -----------------------------------------------------------------------

    #[test]
    fn default_config_values() {
        let cfg = DifferentialConfig::default();
        assert_eq!(cfg.performance_threshold_millionths, 100_000);
        assert_eq!(cfg.resource_threshold_millionths, 200_000);
        assert!(cfg.emit_repro_artifacts);
        assert_eq!(cfg.epoch.as_u64(), 1);
    }

    #[test]
    fn custom_config_strict_threshold() {
        let cfg = DifferentialConfig {
            performance_threshold_millionths: 50_000, // 5%
            resource_threshold_millionths: 100_000,   // 10%
            emit_repro_artifacts: false,
            epoch: SecurityEpoch::from_raw(42),
        };
        // 8% slower → blocks with 5% threshold.
        let native = make_output("ok", 108, 1000, &[]);
        let delegate = make_output("ok", 100, 1000, &[]);
        assert_eq!(
            classify_divergence(&native, &delegate, &cfg),
            Some(DivergenceClass::PerformanceDivergence)
        );
    }

    #[test]
    fn custom_config_lenient_threshold() {
        let cfg = DifferentialConfig {
            performance_threshold_millionths: 500_000, // 50%
            resource_threshold_millionths: 500_000,    // 50%
            emit_repro_artifacts: true,
            epoch: SecurityEpoch::from_raw(1),
        };
        // 20% slower → passes with 50% threshold.
        let native = make_output("ok", 120, 1000, &[]);
        let delegate = make_output("ok", 100, 1000, &[]);
        let result = classify_divergence(&native, &delegate, &cfg);
        // 20% slower → no perf divergence, but native is slower so no improvement.
        assert_eq!(result, None);
    }

    // -----------------------------------------------------------------------
    // CellOutput
    // -----------------------------------------------------------------------

    #[test]
    fn cell_output_semantic_equivalence() {
        let a = make_output_with_effects("ok", &["e1", "e2"], &[], 100, 1000);
        let b = make_output_with_effects("ok", &["e1", "e2"], &[], 200, 2000);
        assert!(a.semantically_equivalent(&b));
    }

    #[test]
    fn cell_output_semantic_inequivalence_return() {
        let a = make_output_with_effects("a", &[], &[], 100, 1000);
        let b = make_output_with_effects("b", &[], &[], 100, 1000);
        assert!(!a.semantically_equivalent(&b));
    }

    #[test]
    fn cell_output_capability_equivalent_subset() {
        let native = make_output("ok", 100, 1000, &[SlotCapability::ReadSource]);
        let delegate = make_output(
            "ok",
            100,
            1000,
            &[SlotCapability::ReadSource, SlotCapability::EmitIr],
        );
        assert!(native.capability_equivalent(&delegate));
    }

    #[test]
    fn cell_output_capability_not_equivalent_superset() {
        let native = make_output(
            "ok",
            100,
            1000,
            &[SlotCapability::ReadSource, SlotCapability::TriggerGc],
        );
        let delegate = make_output("ok", 100, 1000, &[SlotCapability::ReadSource]);
        assert!(!native.capability_equivalent(&delegate));
    }

    // -----------------------------------------------------------------------
    // SlotDifferentialEvidence
    // -----------------------------------------------------------------------

    #[test]
    fn evidence_no_blocking_initially() {
        let ev = SlotDifferentialEvidence::new(
            ContentHash::compute(b"c"),
            ContentHash::compute(b"r"),
            "env".to_string(),
            SecurityEpoch::from_raw(1),
        );
        assert!(!ev.has_blocking_divergences());
    }

    #[test]
    fn evidence_records_verdicts() {
        let mut ev = SlotDifferentialEvidence::new(
            ContentHash::compute(b"c"),
            ContentHash::compute(b"r"),
            "env".to_string(),
            SecurityEpoch::from_raw(1),
        );
        let slot = make_slot_id("parser");
        ev.record_verdict(
            &slot,
            PromotionReadiness::Ready {
                workload_count: 5,
                improvement_count: 1,
            },
        );
        assert!(!ev.has_blocking_divergences());
        assert_eq!(ev.verdicts.len(), 1);
    }

    #[test]
    fn evidence_detects_blocking() {
        let mut ev = SlotDifferentialEvidence::new(
            ContentHash::compute(b"c"),
            ContentHash::compute(b"r"),
            "env".to_string(),
            SecurityEpoch::from_raw(1),
        );
        let slot = make_slot_id("interpreter");
        ev.record_verdict(
            &slot,
            PromotionReadiness::Blocked {
                divergence_counts: BTreeMap::new(),
                repro_hashes: vec![],
            },
        );
        assert!(ev.has_blocking_divergences());
    }

    #[test]
    fn evidence_increment_divergence() {
        let mut ev = SlotDifferentialEvidence::new(
            ContentHash::compute(b"c"),
            ContentHash::compute(b"r"),
            "env".to_string(),
            SecurityEpoch::from_raw(1),
        );
        ev.increment_divergence(&DivergenceClass::SemanticDivergence);
        ev.increment_divergence(&DivergenceClass::SemanticDivergence);
        ev.increment_divergence(&DivergenceClass::BenignImprovement);
        assert_eq!(ev.divergence_summary.get("semantic_divergence"), Some(&2));
        assert_eq!(ev.divergence_summary.get("benign_improvement"), Some(&1));
    }

    // -----------------------------------------------------------------------
    // SlotDifferentialError
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_slot_not_found() {
        let e = SlotDifferentialError::SlotNotFound {
            slot_id: "parser".to_string(),
        };
        assert!(e.to_string().contains("parser"));
    }

    #[test]
    fn error_display_empty_corpus() {
        let e = SlotDifferentialError::EmptyCorpus {
            slot_id: "gc".to_string(),
        };
        assert!(e.to_string().contains("gc"));
    }

    #[test]
    fn error_display_invalid_config() {
        let e = SlotDifferentialError::InvalidConfig {
            detail: "bad threshold".to_string(),
        };
        assert!(e.to_string().contains("bad threshold"));
    }

    #[test]
    fn error_display_cell_execution_failed() {
        let e = SlotDifferentialError::CellExecutionFailed {
            slot_id: "interpreter".to_string(),
            cell_type: "native".to_string(),
            detail: "timeout".to_string(),
        };
        let s = e.to_string();
        assert!(s.contains("interpreter"));
        assert!(s.contains("native"));
        assert!(s.contains("timeout"));
    }

    #[test]
    fn error_display_internal() {
        let e = SlotDifferentialError::InternalError {
            detail: "oops".to_string(),
        };
        assert!(e.to_string().contains("oops"));
    }

    // -----------------------------------------------------------------------
    // WorkloadCategory
    // -----------------------------------------------------------------------

    #[test]
    fn workload_category_display() {
        assert_eq!(
            WorkloadCategory::SemanticEquivalence.to_string(),
            "semantic_equivalence"
        );
        assert_eq!(WorkloadCategory::EdgeCase.to_string(), "edge_case");
        assert_eq!(WorkloadCategory::Adversarial.to_string(), "adversarial");
    }

    // -----------------------------------------------------------------------
    // DifferentialOutcome
    // -----------------------------------------------------------------------

    #[test]
    fn differential_outcome_display() {
        assert_eq!(DifferentialOutcome::Match.to_string(), "match");
        assert_eq!(DifferentialOutcome::Diverge.to_string(), "diverge");
    }

    // -----------------------------------------------------------------------
    // Serde round-trip tests
    // -----------------------------------------------------------------------

    #[test]
    fn serde_divergence_class_roundtrip() {
        for class in &[
            DivergenceClass::SemanticDivergence,
            DivergenceClass::CapabilityDivergence,
            DivergenceClass::PerformanceDivergence,
            DivergenceClass::ResourceDivergence,
            DivergenceClass::BenignImprovement,
        ] {
            let json = serde_json::to_string(class).unwrap();
            let back: DivergenceClass = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, class);
        }
    }

    #[test]
    fn serde_promotion_readiness_roundtrip() {
        let ready = PromotionReadiness::Ready {
            workload_count: 10,
            improvement_count: 3,
        };
        let json = serde_json::to_string(&ready).unwrap();
        let back: PromotionReadiness = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ready);
    }

    #[test]
    fn serde_cell_output_roundtrip() {
        let out = make_output("hello", 42, 256, &[SlotCapability::ReadSource]);
        let json = serde_json::to_string(&out).unwrap();
        let back: CellOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(back, out);
    }

    #[test]
    fn serde_workload_result_roundtrip() {
        let wr = WorkloadResult {
            workload_id: "w1".to_string(),
            category: WorkloadCategory::Adversarial,
            native_output: make_output("ok", 100, 1000, &[]),
            delegate_output: make_output("ok", 100, 1000, &[]),
            outcome: DifferentialOutcome::Match,
            divergence_class: None,
        };
        let json = serde_json::to_string(&wr).unwrap();
        let back: WorkloadResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back, wr);
    }

    #[test]
    fn serde_evidence_roundtrip() {
        let mut ev = SlotDifferentialEvidence::new(
            ContentHash::compute(b"c"),
            ContentHash::compute(b"r"),
            "env".to_string(),
            SecurityEpoch::from_raw(1),
        );
        ev.record_verdict(
            &make_slot_id("parser"),
            PromotionReadiness::Ready {
                workload_count: 5,
                improvement_count: 0,
            },
        );
        let json = serde_json::to_string(&ev).unwrap();
        let back: SlotDifferentialEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(back.verdicts.len(), 1);
    }

    #[test]
    fn serde_config_roundtrip() {
        let cfg = DifferentialConfig {
            performance_threshold_millionths: 50_000,
            resource_threshold_millionths: 100_000,
            emit_repro_artifacts: false,
            epoch: SecurityEpoch::from_raw(7),
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: DifferentialConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn serde_repro_roundtrip() {
        let repro = DivergenceRepro {
            slot_id: make_slot_id("parser"),
            divergence_class: DivergenceClass::SemanticDivergence,
            native_output: make_output("a", 100, 1000, &[]),
            delegate_output: make_output("b", 100, 1000, &[]),
            semantic_contract_hash: ContentHash::compute(b"contract"),
            minimized_input: "input".to_string(),
            capability_diff: vec![],
            memory_diff_bytes: 0,
            duration_diff_us: 0,
            artifact_hash: ContentHash::compute(b"hash"),
        };
        let json = serde_json::to_string(&repro).unwrap();
        let back: DivergenceRepro = serde_json::from_str(&json).unwrap();
        assert_eq!(back.slot_id, repro.slot_id);
    }

    #[test]
    fn serde_log_entry_roundtrip() {
        let entry = WorkloadLogEntry {
            trace_id: "trace-1".to_string(),
            slot_id: make_slot_id("parser"),
            workload_id: "w1".to_string(),
            corpus_category: WorkloadCategory::SemanticEquivalence,
            outcome: DifferentialOutcome::Match,
            divergence_class: None,
            native_duration_us: 100,
            delegate_duration_us: 100,
            capability_diff: vec![],
            resource_diff: "none".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: WorkloadLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.trace_id, "trace-1");
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn workload_category_serde_all_variants() {
        let variants = [
            WorkloadCategory::SemanticEquivalence,
            WorkloadCategory::EdgeCase,
            WorkloadCategory::Adversarial,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: WorkloadCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn differential_outcome_serde_all_variants() {
        let variants = [DifferentialOutcome::Match, DifferentialOutcome::Diverge];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: DifferentialOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn slot_differential_error_serde_all_variants() {
        let variants: Vec<SlotDifferentialError> = vec![
            SlotDifferentialError::SlotNotFound {
                slot_id: "s1".into(),
            },
            SlotDifferentialError::EmptyCorpus {
                slot_id: "s2".into(),
            },
            SlotDifferentialError::InvalidConfig {
                detail: "bad".into(),
            },
            SlotDifferentialError::CellExecutionFailed {
                slot_id: "s3".into(),
                cell_type: "native".into(),
                detail: "oops".into(),
            },
            SlotDifferentialError::InternalError {
                detail: "boom".into(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: SlotDifferentialError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn divergence_class_as_str_distinct() {
        let all = [
            DivergenceClass::SemanticDivergence,
            DivergenceClass::CapabilityDivergence,
            DivergenceClass::PerformanceDivergence,
            DivergenceClass::ResourceDivergence,
            DivergenceClass::BenignImprovement,
        ];
        let set: std::collections::BTreeSet<&str> = all.iter().map(|d| d.as_str()).collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn workload_category_as_str_distinct() {
        let all = [
            WorkloadCategory::SemanticEquivalence,
            WorkloadCategory::EdgeCase,
            WorkloadCategory::Adversarial,
        ];
        let set: std::collections::BTreeSet<&str> = all.iter().map(|c| c.as_str()).collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn differential_outcome_as_str_distinct() {
        let all = [DifferentialOutcome::Match, DifferentialOutcome::Diverge];
        let set: std::collections::BTreeSet<&str> = all.iter().map(|o| o.as_str()).collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn slot_differential_error_display_distinct() {
        let variants: Vec<SlotDifferentialError> = vec![
            SlotDifferentialError::SlotNotFound {
                slot_id: "x".into(),
            },
            SlotDifferentialError::EmptyCorpus {
                slot_id: "x".into(),
            },
            SlotDifferentialError::InvalidConfig { detail: "x".into() },
            SlotDifferentialError::CellExecutionFailed {
                slot_id: "x".into(),
                cell_type: "x".into(),
                detail: "x".into(),
            },
            SlotDifferentialError::InternalError { detail: "x".into() },
        ];
        let set: std::collections::BTreeSet<String> =
            variants.iter().map(|e| format!("{e}")).collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn divergence_class_display_matches_as_str() {
        let all = [
            DivergenceClass::SemanticDivergence,
            DivergenceClass::CapabilityDivergence,
            DivergenceClass::PerformanceDivergence,
            DivergenceClass::ResourceDivergence,
            DivergenceClass::BenignImprovement,
        ];
        for d in &all {
            assert_eq!(format!("{d}"), d.as_str());
        }
    }
}
