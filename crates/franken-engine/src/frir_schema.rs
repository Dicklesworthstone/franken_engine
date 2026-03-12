//! FRIR schema and proof-bearing lowering pipeline.
//!
//! Defines FRIR (FrankenReact Intermediate Representation) as a proof-carrying
//! reactive IR where every non-trivial lowering step produces verifiable
//! semantic linkage artifacts.
//!
//! Design requirements (FRX-03.3):
//! - Canonical FRIR schema with deterministic serialization.
//! - Pass witness chain: input hash → output hash, invariants checked,
//!   obligations touched, assumption references.
//! - Typed effect/capability annotations for JS and WASM lanes.
//! - Equivalence witness hooks for metamorphic/differential oracle.
//! - Offline-heavy / online-light split.
//! - Fail-closed to conservative lowering on missing/invalid witness.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//! Collections use BTreeMap/BTreeSet for deterministic iteration.
//!
//! Plan references: FRX-03.3, FRX-03 (Compiler Architecture).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::ir_contract::EffectBoundary;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for FRIR artifacts.
pub const FRIR_SCHEMA_VERSION: &str = "franken-engine.frir-schema.v1";

/// Maximum lowering passes in a single pipeline.
const MAX_PASSES: usize = 64;

/// Maximum obligations per witness.
const MAX_OBLIGATIONS: usize = 512;

/// Maximum assumptions per witness.
const MAX_ASSUMPTIONS: usize = 256;

// ---------------------------------------------------------------------------
// FrirVersion — schema version for FRIR artifacts
// ---------------------------------------------------------------------------

/// Version of the FRIR schema for forward-compatible deserialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FrirVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl FrirVersion {
    pub const CURRENT: Self = Self {
        major: 0,
        minor: 1,
        patch: 0,
    };

    /// Check forward compatibility: a reader at `self` can read artifacts at `other`.
    pub fn can_read(&self, other: &Self) -> bool {
        self.major == other.major && self.minor >= other.minor
    }
}

impl fmt::Display for FrirVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ---------------------------------------------------------------------------
// LaneTarget — JS vs WASM execution lane
// ---------------------------------------------------------------------------

/// Target execution lane for lowered FRIR output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LaneTarget {
    /// JavaScript execution lane (fine-grained DOM updates).
    Js,
    /// WebAssembly execution lane (signal graph + deterministic scheduler).
    Wasm,
    /// Baseline/conservative lane (interpreter fallback).
    Baseline,
}

impl fmt::Display for LaneTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Js => "js",
            Self::Wasm => "wasm",
            Self::Baseline => "baseline",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// PassKind — classification of lowering passes
// ---------------------------------------------------------------------------

/// Kind of lowering pass in the FRIR pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PassKind {
    /// Parsing: source → IR0.
    Parse,
    /// Scope/binding resolution: IR0 → IR1.
    ScopeResolve,
    /// Capability annotation: IR1 → IR2.
    CapabilityAnnotate,
    /// Effect analysis pass.
    EffectAnalysis,
    /// Hook slot numbering and validation.
    HookSlotValidation,
    /// Component dependency graph construction.
    DependencyGraph,
    /// Dead code / dead component elimination.
    DeadCodeElimination,
    /// Memoization boundary insertion.
    MemoizationBoundary,
    /// Signal graph extraction (WASM lane).
    SignalGraphExtraction,
    /// Fine-grained DOM update planning (JS lane).
    DomUpdatePlanning,
    /// E-graph based optimization.
    EGraphOptimization,
    /// Partial evaluation.
    PartialEvaluation,
    /// Incrementalization (caching/reuse of prior results).
    Incrementalization,
    /// Final code generation.
    CodeGeneration,
    /// Custom/extension pass.
    Custom,
}

impl fmt::Display for PassKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Parse => "parse",
            Self::ScopeResolve => "scope_resolve",
            Self::CapabilityAnnotate => "capability_annotate",
            Self::EffectAnalysis => "effect_analysis",
            Self::HookSlotValidation => "hook_slot_validation",
            Self::DependencyGraph => "dependency_graph",
            Self::DeadCodeElimination => "dead_code_elimination",
            Self::MemoizationBoundary => "memoization_boundary",
            Self::SignalGraphExtraction => "signal_graph_extraction",
            Self::DomUpdatePlanning => "dom_update_planning",
            Self::EGraphOptimization => "egraph_optimization",
            Self::PartialEvaluation => "partial_evaluation",
            Self::Incrementalization => "incrementalization",
            Self::CodeGeneration => "code_generation",
            Self::Custom => "custom",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// WitnessVerdict — outcome of witness verification
// ---------------------------------------------------------------------------

/// Verdict after verifying a pass witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum WitnessVerdict {
    /// Witness is valid: all invariants hold, obligations discharged.
    Valid,
    /// Witness is invalid: at least one invariant or obligation failed.
    Invalid,
    /// Witness is missing entirely.
    Missing,
    /// Witness is stale (input hash mismatch).
    Stale,
    /// Verification timed out (budget exceeded).
    TimedOut,
}

impl fmt::Display for WitnessVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Missing => "missing",
            Self::Stale => "stale",
            Self::TimedOut => "timed_out",
        };
        f.write_str(s)
    }
}

impl WitnessVerdict {
    /// Whether this verdict allows proceeding with the optimized path.
    pub fn allows_optimized_path(&self) -> bool {
        *self == Self::Valid
    }
}

// ---------------------------------------------------------------------------
// FallbackReason — why we fell back to conservative lowering
// ---------------------------------------------------------------------------

/// Reason for falling back to conservative lowering path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FallbackReason {
    /// A pass witness was missing.
    MissingWitness {
        pass_index: usize,
        pass_kind: PassKind,
    },
    /// A pass witness was invalid.
    InvalidWitness {
        pass_index: usize,
        pass_kind: PassKind,
        detail: String,
    },
    /// A pass witness was stale (input changed since witness was computed).
    StaleWitness {
        pass_index: usize,
        pass_kind: PassKind,
    },
    /// Verification budget exceeded.
    VerificationBudgetExceeded { elapsed_ms: u64, budget_ms: u64 },
    /// An obligation was not discharged.
    UnfulfilledObligation {
        obligation_id: String,
        pass_index: usize,
    },
    /// Explicit opt-out (e.g., debug mode).
    ExplicitOptOut { reason: String },
}

impl fmt::Display for FallbackReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingWitness {
                pass_index,
                pass_kind,
            } => write!(f, "missing witness at pass {pass_index} ({pass_kind})"),
            Self::InvalidWitness {
                pass_index,
                pass_kind,
                detail,
            } => write!(
                f,
                "invalid witness at pass {pass_index} ({pass_kind}): {detail}"
            ),
            Self::StaleWitness {
                pass_index,
                pass_kind,
            } => write!(f, "stale witness at pass {pass_index} ({pass_kind})"),
            Self::VerificationBudgetExceeded {
                elapsed_ms,
                budget_ms,
            } => write!(
                f,
                "verification budget exceeded: {elapsed_ms}ms > {budget_ms}ms"
            ),
            Self::UnfulfilledObligation {
                obligation_id,
                pass_index,
            } => write!(
                f,
                "unfulfilled obligation {obligation_id} at pass {pass_index}"
            ),
            Self::ExplicitOptOut { reason } => write!(f, "explicit opt-out: {reason}"),
        }
    }
}

// ---------------------------------------------------------------------------
// InvariantKind — types of invariants that can be checked
// ---------------------------------------------------------------------------

/// Classification of invariants checked by a lowering pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum InvariantKind {
    /// Semantic equivalence (output behaves identically to input).
    SemanticEquivalence,
    /// Type safety (no type errors introduced).
    TypeSafety,
    /// Effect containment (no new effects introduced).
    EffectContainment,
    /// Hook ordering preservation (React rules of hooks).
    HookOrdering,
    /// Capability monotonicity (capabilities only decrease).
    CapabilityMonotonicity,
    /// Determinism (output is deterministic given input).
    Determinism,
    /// Resource bound (output respects resource budgets).
    ResourceBound,
    /// Custom invariant.
    Custom,
}

impl fmt::Display for InvariantKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::SemanticEquivalence => "semantic_equivalence",
            Self::TypeSafety => "type_safety",
            Self::EffectContainment => "effect_containment",
            Self::HookOrdering => "hook_ordering",
            Self::CapabilityMonotonicity => "capability_monotonicity",
            Self::Determinism => "determinism",
            Self::ResourceBound => "resource_bound",
            Self::Custom => "custom",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// InvariantCheck — a single invariant check result
// ---------------------------------------------------------------------------

/// Result of checking a single invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantCheck {
    /// Kind of invariant checked.
    pub kind: InvariantKind,
    /// Whether the check passed.
    pub passed: bool,
    /// Human-readable description.
    pub description: String,
    /// Evidence hash (for audit trail).
    pub evidence_hash: Option<ContentHash>,
}

// ---------------------------------------------------------------------------
// ObligationRef — reference to a proof obligation
// ---------------------------------------------------------------------------

/// Reference to a proof obligation that must be discharged.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ObligationRef {
    /// Unique obligation identifier.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Whether this obligation has been discharged.
    pub discharged: bool,
    /// Hash of the discharge evidence (if discharged).
    pub discharge_evidence: Option<ContentHash>,
}

// ---------------------------------------------------------------------------
// AssumptionRef — reference to an assumption relied upon
// ---------------------------------------------------------------------------

/// Reference to an assumption relied upon by a lowering pass.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AssumptionRef {
    /// Unique assumption identifier.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Whether this assumption has been validated.
    pub validated: bool,
    /// The pass that established this assumption (if known).
    pub established_by_pass: Option<usize>,
}

// ---------------------------------------------------------------------------
// EffectAnnotation — typed effect/capability annotation
// ---------------------------------------------------------------------------

/// Typed effect and capability annotation for an FRIR node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectAnnotation {
    /// IR-level effect boundary classification.
    pub boundary: EffectBoundary,
    /// Required capability tags.
    pub required_capabilities: BTreeSet<String>,
    /// Compatible execution lanes.
    pub compatible_lanes: BTreeSet<LaneTarget>,
    /// Whether this effect is safe for WASM execution.
    pub wasm_safe: bool,
    /// Whether this effect requires DOM access (JS only).
    pub requires_dom: bool,
}

impl EffectAnnotation {
    /// Create a pure annotation (no effects, all lanes).
    pub fn pure_annotation() -> Self {
        let mut lanes = BTreeSet::new();
        lanes.insert(LaneTarget::Js);
        lanes.insert(LaneTarget::Wasm);
        lanes.insert(LaneTarget::Baseline);
        Self {
            boundary: EffectBoundary::Pure,
            required_capabilities: BTreeSet::new(),
            compatible_lanes: lanes,
            wasm_safe: true,
            requires_dom: false,
        }
    }

    /// Check if this annotation is compatible with a target lane.
    pub fn is_compatible(&self, lane: LaneTarget) -> bool {
        self.compatible_lanes.contains(&lane)
    }
}

// ---------------------------------------------------------------------------
// PassWitness — proof artifact for a single lowering pass
// ---------------------------------------------------------------------------

/// Proof artifact produced by a single lowering pass.
///
/// This is the core of the proof-carrying IR: every non-trivial lowering
/// step produces a witness that can be independently verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassWitness {
    /// Index of this pass in the pipeline (0-based).
    pub pass_index: usize,
    /// Kind of lowering pass.
    pub pass_kind: PassKind,
    /// Content hash of the input artifact.
    pub input_hash: ContentHash,
    /// Content hash of the output artifact.
    pub output_hash: ContentHash,
    /// Invariants checked during this pass.
    pub invariants_checked: Vec<InvariantCheck>,
    /// Obligations touched (created or discharged) by this pass.
    pub obligations_touched: Vec<ObligationRef>,
    /// Assumptions relied upon by this pass.
    pub assumptions: Vec<AssumptionRef>,
    /// Effect annotations produced by this pass.
    pub effect_annotations: Vec<EffectAnnotation>,
    /// Target lane for this pass's output.
    pub target_lane: LaneTarget,
    /// Whether this witness was computed offline (expensive) or online (cheap).
    pub computed_offline: bool,
    /// Computation cost in millionths of seconds.
    pub computation_cost_millionths: i64,
    /// Content hash of the witness itself (for chain linking).
    pub witness_hash: ContentHash,
}

impl PassWitness {
    /// Check if all invariants passed.
    pub fn all_invariants_hold(&self) -> bool {
        self.invariants_checked.iter().all(|c| c.passed)
    }

    /// Check if all obligations are discharged.
    pub fn all_obligations_discharged(&self) -> bool {
        self.obligations_touched.iter().all(|o| o.discharged)
    }

    /// Count of failed invariants.
    pub fn failed_invariant_count(&self) -> usize {
        self.invariants_checked.iter().filter(|c| !c.passed).count()
    }

    /// Count of undischarged obligations.
    pub fn undischarged_obligation_count(&self) -> usize {
        self.obligations_touched
            .iter()
            .filter(|o| !o.discharged)
            .count()
    }

    /// Verify the witness chain link: output of previous pass must match input.
    pub fn chain_links_to(&self, previous_output_hash: &ContentHash) -> bool {
        self.input_hash == *previous_output_hash
    }

    /// Compute a combined verdict for this witness.
    pub fn verdict(&self) -> WitnessVerdict {
        if !self.all_invariants_hold() || !self.all_obligations_discharged() {
            WitnessVerdict::Invalid
        } else {
            WitnessVerdict::Valid
        }
    }
}

// ---------------------------------------------------------------------------
// WitnessChain — the full chain of pass witnesses
// ---------------------------------------------------------------------------

/// A chain of pass witnesses for a complete lowering pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessChain {
    /// Schema version.
    pub schema_version: String,
    /// FRIR version.
    pub frir_version: FrirVersion,
    /// Ordered list of pass witnesses (index = pass order).
    pub passes: Vec<PassWitness>,
    /// Content hash of the original source input.
    pub source_hash: ContentHash,
    /// Content hash of the final output.
    pub final_output_hash: ContentHash,
    /// Target execution lane.
    pub target_lane: LaneTarget,
    /// Whether the chain is complete (all passes present).
    pub complete: bool,
    /// Content hash of the entire chain (for integrity).
    pub chain_hash: ContentHash,
}

impl WitnessChain {
    /// Verify the entire witness chain.
    pub fn verify(&self) -> ChainVerification {
        let mut errors: Vec<String> = Vec::new();

        // Check chain is non-empty
        if self.passes.is_empty() {
            errors.push("empty witness chain".to_string());
            return ChainVerification {
                valid: false,
                errors,
                pass_verdicts: Vec::new(),
            };
        }

        let mut pass_verdicts: Vec<WitnessVerdict> = Vec::new();

        // Verify first pass links to source
        if self.passes[0].input_hash != self.source_hash {
            errors.push("first pass input hash does not match source hash".to_string());
        }

        // Verify chain links
        for i in 1..self.passes.len() {
            if !self.passes[i].chain_links_to(&self.passes[i - 1].output_hash) {
                errors.push(format!(
                    "pass {i} input hash does not match pass {} output hash",
                    i - 1
                ));
            }
        }

        // Verify last pass output matches final hash
        if let Some(last) = self.passes.last()
            && last.output_hash != self.final_output_hash
        {
            errors.push("last pass output hash does not match final output hash".to_string());
        }

        // Verify individual witnesses
        for pass in &self.passes {
            let verdict = pass.verdict();
            if verdict != WitnessVerdict::Valid {
                errors.push(format!(
                    "pass {} ({}) has verdict: {verdict}",
                    pass.pass_index, pass.pass_kind
                ));
            }
            pass_verdicts.push(verdict);
        }

        ChainVerification {
            valid: errors.is_empty(),
            errors,
            pass_verdicts,
        }
    }

    /// Total computation cost in millionths of seconds.
    pub fn total_cost_millionths(&self) -> i64 {
        self.passes
            .iter()
            .map(|p| p.computation_cost_millionths)
            .sum()
    }

    /// Count of offline-computed passes.
    pub fn offline_pass_count(&self) -> usize {
        self.passes.iter().filter(|p| p.computed_offline).count()
    }

    /// Count of online-computed passes.
    pub fn online_pass_count(&self) -> usize {
        self.passes.iter().filter(|p| !p.computed_offline).count()
    }
}

// ---------------------------------------------------------------------------
// ChainVerification — result of verifying a witness chain
// ---------------------------------------------------------------------------

/// Result of verifying a full witness chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainVerification {
    /// Whether the entire chain is valid.
    pub valid: bool,
    /// List of errors found (empty if valid).
    pub errors: Vec<String>,
    /// Per-pass verdicts.
    pub pass_verdicts: Vec<WitnessVerdict>,
}

// ---------------------------------------------------------------------------
// EquivalenceWitness — metamorphic/differential oracle hook
// ---------------------------------------------------------------------------

/// Equivalence witness for metamorphic and differential oracle consumption.
///
/// Produced during offline analysis to prove that two representations
/// (e.g., original and optimized) are semantically equivalent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivalenceWitness {
    /// Hash of the first (reference) representation.
    pub reference_hash: ContentHash,
    /// Hash of the second (optimized) representation.
    pub optimized_hash: ContentHash,
    /// Kind of equivalence proven.
    pub equivalence_kind: EquivalenceKind,
    /// Test inputs used for differential checking.
    pub test_input_count: u64,
    /// Whether all test inputs produced identical outputs.
    pub all_outputs_matched: bool,
    /// Counterexample hash (if any output diverged).
    pub counterexample_hash: Option<ContentHash>,
    /// Invariants preserved across the transformation.
    pub preserved_invariants: Vec<InvariantKind>,
    /// Content hash of the witness.
    pub witness_hash: ContentHash,
}

impl EquivalenceWitness {
    /// Check if the equivalence was successfully proven.
    pub fn is_proven(&self) -> bool {
        self.all_outputs_matched && self.counterexample_hash.is_none()
    }
}

// ---------------------------------------------------------------------------
// EquivalenceKind — type of equivalence
// ---------------------------------------------------------------------------

/// Kind of semantic equivalence proven by an equivalence witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EquivalenceKind {
    /// Full observational equivalence (all observable behaviors match).
    Observational,
    /// Trace equivalence (execution traces match).
    Trace,
    /// Effect equivalence (same side effects in same order).
    Effect,
    /// Output equivalence (same final output, possibly different path).
    Output,
    /// Approximate equivalence (within tolerance bounds).
    Approximate,
}

impl fmt::Display for EquivalenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Observational => "observational",
            Self::Trace => "trace",
            Self::Effect => "effect",
            Self::Output => "output",
            Self::Approximate => "approximate",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// FrirArtifact — a complete FRIR artifact
// ---------------------------------------------------------------------------

/// A complete FRIR artifact: the lowered output plus its proof chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrirArtifact {
    /// Schema version.
    pub schema_version: String,
    /// FRIR version.
    pub frir_version: FrirVersion,
    /// Content hash of the original source.
    pub source_hash: ContentHash,
    /// Target execution lane.
    pub target_lane: LaneTarget,
    /// The complete witness chain.
    pub witness_chain: WitnessChain,
    /// Equivalence witnesses (from offline analysis).
    pub equivalence_witnesses: Vec<EquivalenceWitness>,
    /// Effect annotations aggregated across all passes.
    pub aggregated_effects: Vec<EffectAnnotation>,
    /// Required capabilities for execution.
    pub required_capabilities: BTreeSet<String>,
    /// Content hash of the final output.
    pub output_hash: ContentHash,
}

impl FrirArtifact {
    /// Check if this artifact has a valid witness chain.
    pub fn is_valid(&self) -> bool {
        self.witness_chain.verify().valid
    }

    /// Check if all equivalence witnesses are proven.
    pub fn all_equivalences_proven(&self) -> bool {
        self.equivalence_witnesses.iter().all(|w| w.is_proven())
    }
}

// ---------------------------------------------------------------------------
// PipelineConfig — configuration for the lowering pipeline
// ---------------------------------------------------------------------------

/// Configuration for the FRIR lowering pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineConfig {
    /// Target execution lane.
    pub target_lane: LaneTarget,
    /// Maximum computation budget in milliseconds.
    pub budget_ms: u64,
    /// Whether to compute offline witnesses (expensive).
    pub enable_offline_witnesses: bool,
    /// Whether to compute equivalence witnesses.
    pub enable_equivalence_witnesses: bool,
    /// Required invariant kinds (pipeline fails if these don't hold).
    pub required_invariants: BTreeSet<InvariantKind>,
    /// Maximum passes allowed.
    pub max_passes: usize,
}

impl PipelineConfig {
    /// Default configuration for production (conservative).
    pub fn production() -> Self {
        let mut invariants = BTreeSet::new();
        invariants.insert(InvariantKind::SemanticEquivalence);
        invariants.insert(InvariantKind::HookOrdering);
        invariants.insert(InvariantKind::Determinism);
        Self {
            target_lane: LaneTarget::Js,
            budget_ms: 5_000,
            enable_offline_witnesses: false,
            enable_equivalence_witnesses: false,
            required_invariants: invariants,
            max_passes: MAX_PASSES,
        }
    }

    /// Configuration for offline analysis (expensive but thorough).
    pub fn offline_analysis() -> Self {
        let mut invariants = BTreeSet::new();
        for kind in [
            InvariantKind::SemanticEquivalence,
            InvariantKind::TypeSafety,
            InvariantKind::EffectContainment,
            InvariantKind::HookOrdering,
            InvariantKind::CapabilityMonotonicity,
            InvariantKind::Determinism,
            InvariantKind::ResourceBound,
        ] {
            invariants.insert(kind);
        }
        Self {
            target_lane: LaneTarget::Js,
            budget_ms: 300_000,
            enable_offline_witnesses: true,
            enable_equivalence_witnesses: true,
            required_invariants: invariants,
            max_passes: MAX_PASSES,
        }
    }
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self::production()
    }
}

// ---------------------------------------------------------------------------
// FrirPipelineError — errors from the pipeline
// ---------------------------------------------------------------------------

/// Errors that can occur in the FRIR lowering pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrirPipelineError {
    /// Pass limit exceeded.
    PassLimitExceeded { count: usize, max: usize },
    /// Obligation limit exceeded.
    ObligationLimitExceeded { count: usize, max: usize },
    /// Assumption limit exceeded.
    AssumptionLimitExceeded { count: usize, max: usize },
    /// Witness chain broken.
    BrokenChain { pass_index: usize, detail: String },
    /// Required invariant failed.
    InvariantFailed {
        kind: InvariantKind,
        pass_index: usize,
        detail: String,
    },
    /// Budget exceeded.
    BudgetExceeded { elapsed_ms: u64, budget_ms: u64 },
    /// Duplicate pass index.
    DuplicatePassIndex(usize),
}

impl fmt::Display for FrirPipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PassLimitExceeded { count, max } => {
                write!(f, "pass limit exceeded: {count} > {max}")
            }
            Self::ObligationLimitExceeded { count, max } => {
                write!(f, "obligation limit exceeded: {count} > {max}")
            }
            Self::AssumptionLimitExceeded { count, max } => {
                write!(f, "assumption limit exceeded: {count} > {max}")
            }
            Self::BrokenChain { pass_index, detail } => {
                write!(f, "broken chain at pass {pass_index}: {detail}")
            }
            Self::InvariantFailed {
                kind,
                pass_index,
                detail,
            } => {
                write!(f, "invariant {kind} failed at pass {pass_index}: {detail}")
            }
            Self::BudgetExceeded {
                elapsed_ms,
                budget_ms,
            } => {
                write!(f, "budget exceeded: {elapsed_ms}ms > {budget_ms}ms")
            }
            Self::DuplicatePassIndex(idx) => {
                write!(f, "duplicate pass index: {idx}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FrirPipelineEvent — audit event
// ---------------------------------------------------------------------------

/// Kind of pipeline event for the audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrirPipelineEventKind {
    /// Pipeline started.
    PipelineStarted,
    /// A pass was executed.
    PassExecuted,
    /// A witness was produced.
    WitnessProduced,
    /// A witness was verified.
    WitnessVerified,
    /// Fallback to conservative lowering.
    FallbackTriggered,
    /// Equivalence witness produced.
    EquivalenceWitnessProduced,
    /// Pipeline completed.
    PipelineCompleted,
}

impl fmt::Display for FrirPipelineEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::PipelineStarted => "pipeline_started",
            Self::PassExecuted => "pass_executed",
            Self::WitnessProduced => "witness_produced",
            Self::WitnessVerified => "witness_verified",
            Self::FallbackTriggered => "fallback_triggered",
            Self::EquivalenceWitnessProduced => "equivalence_witness_produced",
            Self::PipelineCompleted => "pipeline_completed",
        };
        f.write_str(s)
    }
}

/// An event in the pipeline audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrirPipelineEvent {
    /// Sequence number.
    pub seq: u64,
    /// Event kind.
    pub kind: FrirPipelineEventKind,
    /// Associated pass index (if relevant).
    pub pass_index: Option<usize>,
    /// Detail message.
    pub detail: String,
}

// ---------------------------------------------------------------------------
// FrirLoweringPipeline — the orchestrator
// ---------------------------------------------------------------------------

/// FRIR lowering pipeline: orchestrates proof-bearing lowering passes.
///
/// Fail-closed: any missing or invalid witness triggers fallback to
/// conservative lowering path or baseline execution lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrirLoweringPipeline {
    /// Pipeline configuration.
    pub config: PipelineConfig,
    /// Pass witnesses collected so far.
    witnesses: Vec<PassWitness>,
    /// Equivalence witnesses collected.
    equivalence_witnesses: Vec<EquivalenceWitness>,
    /// Current pass index.
    current_pass: usize,
    /// Elapsed budget in milliseconds.
    elapsed_ms: u64,
    /// Whether the pipeline has fallen back to conservative lowering.
    fallen_back: bool,
    /// Fallback reasons (if any).
    fallback_reasons: Vec<FallbackReason>,
    /// Event log.
    events: Vec<FrirPipelineEvent>,
    /// Next event sequence number.
    next_event_seq: u64,
    /// Accumulated obligations across all passes.
    all_obligations: Vec<ObligationRef>,
    /// Accumulated assumptions across all passes.
    all_assumptions: Vec<AssumptionRef>,
}

impl FrirLoweringPipeline {
    /// Create a new pipeline with the given configuration.
    pub fn new(config: PipelineConfig) -> Self {
        let mut pipeline = Self {
            config,
            witnesses: Vec::new(),
            equivalence_witnesses: Vec::new(),
            current_pass: 0,
            elapsed_ms: 0,
            fallen_back: false,
            fallback_reasons: Vec::new(),
            events: Vec::new(),
            next_event_seq: 0,
            all_obligations: Vec::new(),
            all_assumptions: Vec::new(),
        };
        pipeline.emit_event(FrirPipelineEventKind::PipelineStarted, None, "");
        pipeline
    }

    /// Record a pass witness from a lowering pass.
    pub fn record_pass(&mut self, witness: PassWitness) -> Result<(), FrirPipelineError> {
        // Check pass limit
        if self.witnesses.len() >= self.config.max_passes {
            return Err(FrirPipelineError::PassLimitExceeded {
                count: self.witnesses.len() + 1,
                max: self.config.max_passes,
            });
        }

        // Check obligation limit
        let total_obligations = self.all_obligations.len() + witness.obligations_touched.len();
        if total_obligations > MAX_OBLIGATIONS {
            return Err(FrirPipelineError::ObligationLimitExceeded {
                count: total_obligations,
                max: MAX_OBLIGATIONS,
            });
        }

        // Check assumption limit
        let total_assumptions = self.all_assumptions.len() + witness.assumptions.len();
        if total_assumptions > MAX_ASSUMPTIONS {
            return Err(FrirPipelineError::AssumptionLimitExceeded {
                count: total_assumptions,
                max: MAX_ASSUMPTIONS,
            });
        }

        // Check for duplicate pass index
        if self
            .witnesses
            .iter()
            .any(|w| w.pass_index == witness.pass_index)
        {
            return Err(FrirPipelineError::DuplicatePassIndex(witness.pass_index));
        }

        // Check chain continuity
        if !self.witnesses.is_empty() {
            let last = self.witnesses.last().unwrap();
            if !witness.chain_links_to(&last.output_hash) {
                return Err(FrirPipelineError::BrokenChain {
                    pass_index: witness.pass_index,
                    detail: "input hash does not match previous output hash".to_string(),
                });
            }
        }

        // Check budget
        self.elapsed_ms = self
            .elapsed_ms
            .saturating_add(witness.computation_cost_millionths as u64 / 1_000);
        if self.elapsed_ms > self.config.budget_ms {
            self.trigger_fallback(FallbackReason::VerificationBudgetExceeded {
                elapsed_ms: self.elapsed_ms,
                budget_ms: self.config.budget_ms,
            });
            return Err(FrirPipelineError::BudgetExceeded {
                elapsed_ms: self.elapsed_ms,
                budget_ms: self.config.budget_ms,
            });
        }

        // Verify required invariants (clone set to avoid borrow conflict with trigger_fallback)
        let required_invariants: Vec<InvariantKind> =
            self.config.required_invariants.iter().copied().collect();
        for required in &required_invariants {
            let check = witness
                .invariants_checked
                .iter()
                .find(|c| c.kind == *required);
            if let Some(check) = check
                && !check.passed
            {
                self.trigger_fallback(FallbackReason::InvalidWitness {
                    pass_index: witness.pass_index,
                    pass_kind: witness.pass_kind,
                    detail: format!("invariant {required} failed"),
                });
                return Err(FrirPipelineError::InvariantFailed {
                    kind: *required,
                    pass_index: witness.pass_index,
                    detail: format!("invariant {required} failed"),
                });
            }
        }

        // Accumulate obligations and assumptions
        for ob in &witness.obligations_touched {
            self.all_obligations.push(ob.clone());
        }
        for assumption in &witness.assumptions {
            self.all_assumptions.push(assumption.clone());
        }

        self.emit_event(
            FrirPipelineEventKind::PassExecuted,
            Some(witness.pass_index),
            &format!("{}", witness.pass_kind),
        );
        self.emit_event(
            FrirPipelineEventKind::WitnessProduced,
            Some(witness.pass_index),
            "",
        );

        self.witnesses.push(witness);
        self.current_pass += 1;
        Ok(())
    }

    /// Record an equivalence witness.
    pub fn record_equivalence_witness(&mut self, witness: EquivalenceWitness) {
        self.emit_event(
            FrirPipelineEventKind::EquivalenceWitnessProduced,
            None,
            &format!("{}", witness.equivalence_kind),
        );
        self.equivalence_witnesses.push(witness);
    }

    /// Trigger a fallback to conservative lowering.
    pub fn trigger_fallback(&mut self, reason: FallbackReason) {
        self.emit_event(
            FrirPipelineEventKind::FallbackTriggered,
            None,
            &format!("{reason}"),
        );
        self.fallen_back = true;
        self.fallback_reasons.push(reason);
    }

    /// Finalize the pipeline and produce a complete FRIR artifact.
    pub fn finalize(
        &mut self,
        source_hash: ContentHash,
    ) -> Result<FrirArtifact, FrirPipelineError> {
        self.emit_event(FrirPipelineEventKind::PipelineCompleted, None, "");

        let final_output_hash = self
            .witnesses
            .last()
            .map(|w| w.output_hash)
            .unwrap_or_else(|| ContentHash::compute(b"empty"));

        // Compute chain hash from all witness hashes
        let mut chain_hash_input = Vec::new();
        for w in &self.witnesses {
            chain_hash_input.extend_from_slice(w.witness_hash.as_bytes());
        }
        let chain_hash = ContentHash::compute(&chain_hash_input);

        let witness_chain = WitnessChain {
            schema_version: FRIR_SCHEMA_VERSION.to_string(),
            frir_version: FrirVersion::CURRENT,
            passes: self.witnesses.clone(),
            source_hash,
            final_output_hash,
            target_lane: self.config.target_lane,
            complete: !self.fallen_back,
            chain_hash,
        };

        // Aggregate effects
        let aggregated_effects: Vec<EffectAnnotation> = self
            .witnesses
            .iter()
            .flat_map(|w| w.effect_annotations.clone())
            .collect();

        // Aggregate required capabilities
        let required_capabilities: BTreeSet<String> = aggregated_effects
            .iter()
            .flat_map(|e| e.required_capabilities.clone())
            .collect();

        Ok(FrirArtifact {
            schema_version: FRIR_SCHEMA_VERSION.to_string(),
            frir_version: FrirVersion::CURRENT,
            source_hash,
            target_lane: self.config.target_lane,
            witness_chain,
            equivalence_witnesses: self.equivalence_witnesses.clone(),
            aggregated_effects,
            required_capabilities,
            output_hash: final_output_hash,
        })
    }

    // -- Query --

    /// Number of recorded passes.
    pub fn pass_count(&self) -> usize {
        self.witnesses.len()
    }

    /// Whether the pipeline has fallen back.
    pub fn has_fallen_back(&self) -> bool {
        self.fallen_back
    }

    /// Fallback reasons.
    pub fn fallback_reasons(&self) -> &[FallbackReason] {
        &self.fallback_reasons
    }

    /// Events.
    pub fn events(&self) -> &[FrirPipelineEvent] {
        &self.events
    }

    /// All accumulated obligations.
    pub fn obligations(&self) -> &[ObligationRef] {
        &self.all_obligations
    }

    /// All accumulated assumptions.
    pub fn assumptions(&self) -> &[AssumptionRef] {
        &self.all_assumptions
    }

    /// Check if all obligations are discharged.
    pub fn all_obligations_discharged(&self) -> bool {
        self.all_obligations.iter().all(|o| o.discharged)
    }

    /// Undischarged obligations.
    pub fn undischarged_obligations(&self) -> Vec<&ObligationRef> {
        self.all_obligations
            .iter()
            .filter(|o| !o.discharged)
            .collect()
    }

    // -- Internal --

    fn emit_event(&mut self, kind: FrirPipelineEventKind, pass_index: Option<usize>, detail: &str) {
        let seq = self.next_event_seq;
        self.next_event_seq += 1;
        self.events.push(FrirPipelineEvent {
            seq,
            kind,
            pass_index,
            detail: detail.to_string(),
        });
    }
}

impl Default for FrirLoweringPipeline {
    fn default() -> Self {
        Self::new(PipelineConfig::default())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helpers --

    fn make_hash(data: &[u8]) -> ContentHash {
        ContentHash::compute(data)
    }

    fn make_invariant(kind: InvariantKind, passed: bool) -> InvariantCheck {
        InvariantCheck {
            kind,
            passed,
            description: format!("{kind}"),
            evidence_hash: Some(make_hash(format!("evidence_{kind}").as_bytes())),
        }
    }

    fn make_obligation(id: &str, discharged: bool) -> ObligationRef {
        ObligationRef {
            id: id.to_string(),
            description: format!("obligation {id}"),
            discharged,
            discharge_evidence: if discharged {
                Some(make_hash(format!("discharge_{id}").as_bytes()))
            } else {
                None
            },
        }
    }

    fn make_assumption(id: &str, validated: bool) -> AssumptionRef {
        AssumptionRef {
            id: id.to_string(),
            description: format!("assumption {id}"),
            validated,
            established_by_pass: None,
        }
    }

    fn make_witness(index: usize, kind: PassKind, input: &[u8], output: &[u8]) -> PassWitness {
        let input_hash = make_hash(input);
        let output_hash = make_hash(output);
        let witness_hash = make_hash(&[input, output].concat());
        PassWitness {
            pass_index: index,
            pass_kind: kind,
            input_hash,
            output_hash,
            invariants_checked: vec![
                make_invariant(InvariantKind::SemanticEquivalence, true),
                make_invariant(InvariantKind::Determinism, true),
            ],
            obligations_touched: vec![make_obligation(&format!("ob_{index}"), true)],
            assumptions: vec![make_assumption(&format!("asm_{index}"), true)],
            effect_annotations: vec![EffectAnnotation::pure_annotation()],
            target_lane: LaneTarget::Js,
            computed_offline: false,
            computation_cost_millionths: 100_000, // 0.1s
            witness_hash,
        }
    }

    /// Create a two-pass chain where output of pass 0 = input of pass 1.
    fn make_chained_witnesses() -> (PassWitness, PassWitness) {
        let w0 = make_witness(0, PassKind::Parse, b"source", b"ir0");
        let mut w1 = make_witness(1, PassKind::ScopeResolve, b"ir0", b"ir1");
        w1.input_hash = w0.output_hash;
        (w0, w1)
    }

    // -- FrirVersion tests --

    #[test]
    fn frir_version_display() {
        assert_eq!(format!("{}", FrirVersion::CURRENT), "0.1.0");
    }

    #[test]
    fn frir_version_can_read_same() {
        assert!(FrirVersion::CURRENT.can_read(&FrirVersion::CURRENT));
    }

    #[test]
    fn frir_version_can_read_older_minor() {
        let current = FrirVersion {
            major: 0,
            minor: 2,
            patch: 0,
        };
        let older = FrirVersion {
            major: 0,
            minor: 1,
            patch: 5,
        };
        assert!(current.can_read(&older));
    }

    #[test]
    fn frir_version_cannot_read_newer_minor() {
        let current = FrirVersion {
            major: 0,
            minor: 1,
            patch: 0,
        };
        let newer = FrirVersion {
            major: 0,
            minor: 2,
            patch: 0,
        };
        assert!(!current.can_read(&newer));
    }

    #[test]
    fn frir_version_cannot_read_different_major() {
        let v1 = FrirVersion {
            major: 1,
            minor: 0,
            patch: 0,
        };
        let v2 = FrirVersion {
            major: 2,
            minor: 0,
            patch: 0,
        };
        assert!(!v1.can_read(&v2));
    }

    #[test]
    fn frir_version_serde_roundtrip() {
        let v = FrirVersion::CURRENT;
        let json = serde_json::to_string(&v).unwrap();
        let back: FrirVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    // -- LaneTarget tests --

    #[test]
    fn lane_target_display() {
        assert_eq!(format!("{}", LaneTarget::Js), "js");
        assert_eq!(format!("{}", LaneTarget::Wasm), "wasm");
        assert_eq!(format!("{}", LaneTarget::Baseline), "baseline");
    }

    #[test]
    fn lane_target_serde_roundtrip() {
        for lane in [LaneTarget::Js, LaneTarget::Wasm, LaneTarget::Baseline] {
            let json = serde_json::to_string(&lane).unwrap();
            let back: LaneTarget = serde_json::from_str(&json).unwrap();
            assert_eq!(lane, back);
        }
    }

    // -- PassKind tests --

    #[test]
    fn pass_kind_display() {
        assert_eq!(format!("{}", PassKind::Parse), "parse");
        assert_eq!(format!("{}", PassKind::ScopeResolve), "scope_resolve");
        assert_eq!(
            format!("{}", PassKind::EGraphOptimization),
            "egraph_optimization"
        );
        assert_eq!(format!("{}", PassKind::CodeGeneration), "code_generation");
    }

    #[test]
    fn pass_kind_serde_roundtrip() {
        for kind in [
            PassKind::Parse,
            PassKind::ScopeResolve,
            PassKind::CapabilityAnnotate,
            PassKind::EffectAnalysis,
            PassKind::HookSlotValidation,
            PassKind::DependencyGraph,
            PassKind::DeadCodeElimination,
            PassKind::MemoizationBoundary,
            PassKind::SignalGraphExtraction,
            PassKind::DomUpdatePlanning,
            PassKind::EGraphOptimization,
            PassKind::PartialEvaluation,
            PassKind::Incrementalization,
            PassKind::CodeGeneration,
            PassKind::Custom,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: PassKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    // -- WitnessVerdict tests --

    #[test]
    fn witness_verdict_display() {
        assert_eq!(format!("{}", WitnessVerdict::Valid), "valid");
        assert_eq!(format!("{}", WitnessVerdict::Invalid), "invalid");
        assert_eq!(format!("{}", WitnessVerdict::Missing), "missing");
        assert_eq!(format!("{}", WitnessVerdict::Stale), "stale");
        assert_eq!(format!("{}", WitnessVerdict::TimedOut), "timed_out");
    }

    #[test]
    fn witness_verdict_optimized_path() {
        assert!(WitnessVerdict::Valid.allows_optimized_path());
        assert!(!WitnessVerdict::Invalid.allows_optimized_path());
        assert!(!WitnessVerdict::Missing.allows_optimized_path());
        assert!(!WitnessVerdict::Stale.allows_optimized_path());
        assert!(!WitnessVerdict::TimedOut.allows_optimized_path());
    }

    // -- InvariantKind tests --

    #[test]
    fn invariant_kind_display() {
        assert_eq!(
            format!("{}", InvariantKind::SemanticEquivalence),
            "semantic_equivalence"
        );
        assert_eq!(format!("{}", InvariantKind::TypeSafety), "type_safety");
        assert_eq!(format!("{}", InvariantKind::HookOrdering), "hook_ordering");
    }

    // -- EffectAnnotation tests --

    #[test]
    fn effect_annotation_pure() {
        let ann = EffectAnnotation::pure_annotation();
        assert!(ann.is_compatible(LaneTarget::Js));
        assert!(ann.is_compatible(LaneTarget::Wasm));
        assert!(ann.is_compatible(LaneTarget::Baseline));
        assert!(ann.wasm_safe);
        assert!(!ann.requires_dom);
    }

    #[test]
    fn effect_annotation_dom_only() {
        let ann = EffectAnnotation {
            boundary: EffectBoundary::WriteEffect,
            required_capabilities: {
                let mut s = BTreeSet::new();
                s.insert("dom".to_string());
                s
            },
            compatible_lanes: {
                let mut s = BTreeSet::new();
                s.insert(LaneTarget::Js);
                s
            },
            wasm_safe: false,
            requires_dom: true,
        };
        assert!(ann.is_compatible(LaneTarget::Js));
        assert!(!ann.is_compatible(LaneTarget::Wasm));
    }

    #[test]
    fn effect_annotation_serde_roundtrip() {
        let ann = EffectAnnotation::pure_annotation();
        let json = serde_json::to_string(&ann).unwrap();
        let back: EffectAnnotation = serde_json::from_str(&json).unwrap();
        assert_eq!(ann, back);
    }

    // -- PassWitness tests --

    #[test]
    fn pass_witness_all_valid() {
        let w = make_witness(0, PassKind::Parse, b"source", b"ir0");
        assert!(w.all_invariants_hold());
        assert!(w.all_obligations_discharged());
        assert_eq!(w.verdict(), WitnessVerdict::Valid);
        assert_eq!(w.failed_invariant_count(), 0);
        assert_eq!(w.undischarged_obligation_count(), 0);
    }

    #[test]
    fn pass_witness_failed_invariant() {
        let mut w = make_witness(0, PassKind::Parse, b"source", b"ir0");
        w.invariants_checked
            .push(make_invariant(InvariantKind::TypeSafety, false));
        assert!(!w.all_invariants_hold());
        assert_eq!(w.verdict(), WitnessVerdict::Invalid);
        assert_eq!(w.failed_invariant_count(), 1);
    }

    #[test]
    fn pass_witness_undischarged_obligation() {
        let mut w = make_witness(0, PassKind::Parse, b"source", b"ir0");
        w.obligations_touched
            .push(make_obligation("ob_pending", false));
        assert!(!w.all_obligations_discharged());
        assert_eq!(w.verdict(), WitnessVerdict::Invalid);
        assert_eq!(w.undischarged_obligation_count(), 1);
    }

    #[test]
    fn pass_witness_chain_links() {
        let (w0, w1) = make_chained_witnesses();
        assert!(w1.chain_links_to(&w0.output_hash));
    }

    #[test]
    fn pass_witness_chain_does_not_link() {
        let w0 = make_witness(0, PassKind::Parse, b"source", b"ir0");
        let w1 = make_witness(1, PassKind::ScopeResolve, b"wrong", b"ir1");
        assert!(!w1.chain_links_to(&w0.output_hash));
    }

    #[test]
    fn pass_witness_serde_roundtrip() {
        let w = make_witness(0, PassKind::Parse, b"source", b"ir0");
        let json = serde_json::to_string(&w).unwrap();
        let back: PassWitness = serde_json::from_str(&json).unwrap();
        assert_eq!(w, back);
    }

    // -- WitnessChain tests --

    #[test]
    fn witness_chain_verify_valid() {
        let (w0, w1) = make_chained_witnesses();
        let chain = WitnessChain {
            schema_version: FRIR_SCHEMA_VERSION.to_string(),
            frir_version: FrirVersion::CURRENT,
            passes: vec![w0.clone(), w1.clone()],
            source_hash: w0.input_hash,
            final_output_hash: w1.output_hash,
            target_lane: LaneTarget::Js,
            complete: true,
            chain_hash: make_hash(b"chain"),
        };
        let verification = chain.verify();
        assert!(verification.valid);
        assert!(verification.errors.is_empty());
    }

    #[test]
    fn witness_chain_verify_broken_link() {
        let w0 = make_witness(0, PassKind::Parse, b"source", b"ir0");
        let w1 = make_witness(1, PassKind::ScopeResolve, b"wrong", b"ir1");
        let chain = WitnessChain {
            schema_version: FRIR_SCHEMA_VERSION.to_string(),
            frir_version: FrirVersion::CURRENT,
            passes: vec![w0.clone(), w1.clone()],
            source_hash: w0.input_hash,
            final_output_hash: w1.output_hash,
            target_lane: LaneTarget::Js,
            complete: true,
            chain_hash: make_hash(b"chain"),
        };
        let verification = chain.verify();
        assert!(!verification.valid);
        assert!(!verification.errors.is_empty());
    }

    #[test]
    fn witness_chain_verify_source_mismatch() {
        let w0 = make_witness(0, PassKind::Parse, b"source", b"ir0");
        let chain = WitnessChain {
            schema_version: FRIR_SCHEMA_VERSION.to_string(),
            frir_version: FrirVersion::CURRENT,
            passes: vec![w0.clone()],
            source_hash: make_hash(b"wrong_source"),
            final_output_hash: w0.output_hash,
            target_lane: LaneTarget::Js,
            complete: true,
            chain_hash: make_hash(b"chain"),
        };
        let verification = chain.verify();
        assert!(!verification.valid);
    }

    #[test]
    fn witness_chain_verify_empty() {
        let chain = WitnessChain {
            schema_version: FRIR_SCHEMA_VERSION.to_string(),
            frir_version: FrirVersion::CURRENT,
            passes: Vec::new(),
            source_hash: make_hash(b"source"),
            final_output_hash: make_hash(b"output"),
            target_lane: LaneTarget::Js,
            complete: false,
            chain_hash: make_hash(b"chain"),
        };
        let verification = chain.verify();
        assert!(!verification.valid);
    }

    #[test]
    fn witness_chain_cost() {
        let (w0, w1) = make_chained_witnesses();
        let chain = WitnessChain {
            schema_version: FRIR_SCHEMA_VERSION.to_string(),
            frir_version: FrirVersion::CURRENT,
            passes: vec![w0, w1],
            source_hash: make_hash(b"source"),
            final_output_hash: make_hash(b"ir1"),
            target_lane: LaneTarget::Js,
            complete: true,
            chain_hash: make_hash(b"chain"),
        };
        assert_eq!(chain.total_cost_millionths(), 200_000); // 2 * 100_000
    }

    #[test]
    fn witness_chain_offline_online_counts() {
        let mut w0 = make_witness(0, PassKind::Parse, b"source", b"ir0");
        w0.computed_offline = true;
        let mut w1 = make_witness(1, PassKind::ScopeResolve, b"ir0", b"ir1");
        w1.input_hash = w0.output_hash;
        let chain = WitnessChain {
            schema_version: FRIR_SCHEMA_VERSION.to_string(),
            frir_version: FrirVersion::CURRENT,
            passes: vec![w0, w1],
            source_hash: make_hash(b"source"),
            final_output_hash: make_hash(b"ir1"),
            target_lane: LaneTarget::Js,
            complete: true,
            chain_hash: make_hash(b"chain"),
        };
        assert_eq!(chain.offline_pass_count(), 1);
        assert_eq!(chain.online_pass_count(), 1);
    }

    #[test]
    fn witness_chain_serde_roundtrip() {
        let (w0, w1) = make_chained_witnesses();
        let chain = WitnessChain {
            schema_version: FRIR_SCHEMA_VERSION.to_string(),
            frir_version: FrirVersion::CURRENT,
            passes: vec![w0.clone(), w1.clone()],
            source_hash: w0.input_hash,
            final_output_hash: w1.output_hash,
            target_lane: LaneTarget::Js,
            complete: true,
            chain_hash: make_hash(b"chain"),
        };
        let json = serde_json::to_string(&chain).unwrap();
        let back: WitnessChain = serde_json::from_str(&json).unwrap();
        assert_eq!(chain, back);
    }

    // -- EquivalenceWitness tests --

    #[test]
    fn equivalence_witness_proven() {
        let ew = EquivalenceWitness {
            reference_hash: make_hash(b"ref"),
            optimized_hash: make_hash(b"opt"),
            equivalence_kind: EquivalenceKind::Observational,
            test_input_count: 1000,
            all_outputs_matched: true,
            counterexample_hash: None,
            preserved_invariants: vec![InvariantKind::SemanticEquivalence],
            witness_hash: make_hash(b"eq_witness"),
        };
        assert!(ew.is_proven());
    }

    #[test]
    fn equivalence_witness_disproven() {
        let ew = EquivalenceWitness {
            reference_hash: make_hash(b"ref"),
            optimized_hash: make_hash(b"opt"),
            equivalence_kind: EquivalenceKind::Observational,
            test_input_count: 1000,
            all_outputs_matched: false,
            counterexample_hash: Some(make_hash(b"counterexample")),
            preserved_invariants: Vec::new(),
            witness_hash: make_hash(b"eq_witness"),
        };
        assert!(!ew.is_proven());
    }

    #[test]
    fn equivalence_witness_serde_roundtrip() {
        let ew = EquivalenceWitness {
            reference_hash: make_hash(b"ref"),
            optimized_hash: make_hash(b"opt"),
            equivalence_kind: EquivalenceKind::Trace,
            test_input_count: 500,
            all_outputs_matched: true,
            counterexample_hash: None,
            preserved_invariants: vec![InvariantKind::Determinism],
            witness_hash: make_hash(b"eq_witness"),
        };
        let json = serde_json::to_string(&ew).unwrap();
        let back: EquivalenceWitness = serde_json::from_str(&json).unwrap();
        assert_eq!(ew, back);
    }

    // -- EquivalenceKind tests --

    #[test]
    fn equivalence_kind_display() {
        assert_eq!(
            format!("{}", EquivalenceKind::Observational),
            "observational"
        );
        assert_eq!(format!("{}", EquivalenceKind::Trace), "trace");
        assert_eq!(format!("{}", EquivalenceKind::Effect), "effect");
        assert_eq!(format!("{}", EquivalenceKind::Output), "output");
        assert_eq!(format!("{}", EquivalenceKind::Approximate), "approximate");
    }

    // -- FallbackReason tests --

    #[test]
    fn fallback_reason_display() {
        let r = FallbackReason::MissingWitness {
            pass_index: 3,
            pass_kind: PassKind::EffectAnalysis,
        };
        assert_eq!(
            format!("{r}"),
            "missing witness at pass 3 (effect_analysis)"
        );
    }

    #[test]
    fn fallback_reason_serde_roundtrip() {
        let r = FallbackReason::InvalidWitness {
            pass_index: 1,
            pass_kind: PassKind::ScopeResolve,
            detail: "type error".to_string(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: FallbackReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // -- PipelineConfig tests --

    #[test]
    fn pipeline_config_production() {
        let config = PipelineConfig::production();
        assert_eq!(config.target_lane, LaneTarget::Js);
        assert!(!config.enable_offline_witnesses);
        assert!(!config.enable_equivalence_witnesses);
        assert!(
            config
                .required_invariants
                .contains(&InvariantKind::SemanticEquivalence)
        );
        assert!(
            config
                .required_invariants
                .contains(&InvariantKind::HookOrdering)
        );
        assert!(
            config
                .required_invariants
                .contains(&InvariantKind::Determinism)
        );
    }

    #[test]
    fn pipeline_config_offline() {
        let config = PipelineConfig::offline_analysis();
        assert!(config.enable_offline_witnesses);
        assert!(config.enable_equivalence_witnesses);
        assert_eq!(config.required_invariants.len(), 7);
        assert_eq!(config.budget_ms, 300_000);
    }

    #[test]
    fn pipeline_config_default() {
        let config = PipelineConfig::default();
        assert_eq!(config, PipelineConfig::production());
    }

    #[test]
    fn pipeline_config_serde_roundtrip() {
        let config = PipelineConfig::production();
        let json = serde_json::to_string(&config).unwrap();
        let back: PipelineConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    // -- FrirPipelineError tests --

    #[test]
    fn pipeline_error_display() {
        let e = FrirPipelineError::PassLimitExceeded { count: 65, max: 64 };
        assert_eq!(format!("{e}"), "pass limit exceeded: 65 > 64");

        let e = FrirPipelineError::InvariantFailed {
            kind: InvariantKind::TypeSafety,
            pass_index: 2,
            detail: "type error".to_string(),
        };
        assert_eq!(
            format!("{e}"),
            "invariant type_safety failed at pass 2: type error"
        );
    }

    #[test]
    fn pipeline_error_serde_roundtrip() {
        let e = FrirPipelineError::BrokenChain {
            pass_index: 3,
            detail: "hash mismatch".to_string(),
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: FrirPipelineError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // -- FrirPipelineEventKind tests --

    #[test]
    fn pipeline_event_kind_display() {
        assert_eq!(
            format!("{}", FrirPipelineEventKind::PipelineStarted),
            "pipeline_started"
        );
        assert_eq!(
            format!("{}", FrirPipelineEventKind::FallbackTriggered),
            "fallback_triggered"
        );
    }

    // -- FrirLoweringPipeline tests --

    #[test]
    fn pipeline_new() {
        let p = FrirLoweringPipeline::new(PipelineConfig::production());
        assert_eq!(p.pass_count(), 0);
        assert!(!p.has_fallen_back());
        assert!(!p.events().is_empty()); // PipelineStarted
    }

    #[test]
    fn pipeline_default() {
        let p = FrirLoweringPipeline::default();
        assert_eq!(p.config, PipelineConfig::production());
    }

    #[test]
    fn pipeline_record_single_pass() {
        let mut p = FrirLoweringPipeline::new(PipelineConfig::production());
        let w = make_witness(0, PassKind::Parse, b"source", b"ir0");
        p.record_pass(w).unwrap();
        assert_eq!(p.pass_count(), 1);
        assert!(!p.has_fallen_back());
    }

    #[test]
    fn pipeline_record_chained_passes() {
        let mut p = FrirLoweringPipeline::new(PipelineConfig::production());
        let (w0, w1) = make_chained_witnesses();
        p.record_pass(w0).unwrap();
        p.record_pass(w1).unwrap();
        assert_eq!(p.pass_count(), 2);
    }

    #[test]
    fn pipeline_broken_chain_fails() {
        let mut p = FrirLoweringPipeline::new(PipelineConfig::production());
        let w0 = make_witness(0, PassKind::Parse, b"source", b"ir0");
        let w1 = make_witness(1, PassKind::ScopeResolve, b"wrong", b"ir1");
        p.record_pass(w0).unwrap();
        let err = p.record_pass(w1).unwrap_err();
        assert!(matches!(err, FrirPipelineError::BrokenChain { .. }));
    }

    #[test]
    fn pipeline_duplicate_pass_index_fails() {
        let mut p = FrirLoweringPipeline::new(PipelineConfig::production());
        let w0 = make_witness(0, PassKind::Parse, b"source", b"ir0");
        let mut w0_dup = make_witness(0, PassKind::Parse, b"source2", b"ir0_2");
        w0_dup.input_hash = w0.output_hash;
        p.record_pass(w0).unwrap();
        let err = p.record_pass(w0_dup).unwrap_err();
        assert!(matches!(err, FrirPipelineError::DuplicatePassIndex(0)));
    }

    #[test]
    fn pipeline_invariant_failure_triggers_fallback() {
        let mut config = PipelineConfig::production();
        config.required_invariants.insert(InvariantKind::TypeSafety);
        let mut p = FrirLoweringPipeline::new(config);
        let mut w = make_witness(0, PassKind::Parse, b"source", b"ir0");
        w.invariants_checked
            .push(make_invariant(InvariantKind::TypeSafety, false));
        let err = p.record_pass(w).unwrap_err();
        assert!(matches!(err, FrirPipelineError::InvariantFailed { .. }));
        assert!(p.has_fallen_back());
    }

    #[test]
    fn pipeline_budget_exceeded() {
        let mut config = PipelineConfig::production();
        config.budget_ms = 0; // Zero budget
        let mut p = FrirLoweringPipeline::new(config);
        let w = make_witness(0, PassKind::Parse, b"source", b"ir0");
        let err = p.record_pass(w).unwrap_err();
        assert!(matches!(err, FrirPipelineError::BudgetExceeded { .. }));
        assert!(p.has_fallen_back());
    }

    #[test]
    fn pipeline_fallback_manual() {
        let mut p = FrirLoweringPipeline::new(PipelineConfig::production());
        p.trigger_fallback(FallbackReason::ExplicitOptOut {
            reason: "debug mode".to_string(),
        });
        assert!(p.has_fallen_back());
        assert_eq!(p.fallback_reasons().len(), 1);
    }

    #[test]
    fn pipeline_obligations_tracking() {
        let mut p = FrirLoweringPipeline::new(PipelineConfig::production());
        let w = make_witness(0, PassKind::Parse, b"source", b"ir0");
        p.record_pass(w).unwrap();
        assert_eq!(p.obligations().len(), 1);
        assert!(p.all_obligations_discharged());
        assert!(p.undischarged_obligations().is_empty());
    }

    #[test]
    fn pipeline_undischarged_obligations() {
        let mut p = FrirLoweringPipeline::new(PipelineConfig::production());
        let mut w = make_witness(0, PassKind::Parse, b"source", b"ir0");
        w.obligations_touched
            .push(make_obligation("pending_ob", false));
        p.record_pass(w).unwrap();
        assert!(!p.all_obligations_discharged());
        assert_eq!(p.undischarged_obligations().len(), 1);
    }

    #[test]
    fn pipeline_assumptions_tracking() {
        let mut p = FrirLoweringPipeline::new(PipelineConfig::production());
        let w = make_witness(0, PassKind::Parse, b"source", b"ir0");
        p.record_pass(w).unwrap();
        assert_eq!(p.assumptions().len(), 1);
    }

    #[test]
    fn pipeline_record_equivalence_witness() {
        let mut p = FrirLoweringPipeline::new(PipelineConfig::production());
        let ew = EquivalenceWitness {
            reference_hash: make_hash(b"ref"),
            optimized_hash: make_hash(b"opt"),
            equivalence_kind: EquivalenceKind::Observational,
            test_input_count: 100,
            all_outputs_matched: true,
            counterexample_hash: None,
            preserved_invariants: vec![InvariantKind::SemanticEquivalence],
            witness_hash: make_hash(b"eq"),
        };
        p.record_equivalence_witness(ew);
        // Check event was emitted
        assert!(
            p.events()
                .iter()
                .any(|e| e.kind == FrirPipelineEventKind::EquivalenceWitnessProduced)
        );
    }

    #[test]
    fn pipeline_finalize_success() {
        let mut p = FrirLoweringPipeline::new(PipelineConfig::production());
        let (w0, w1) = make_chained_witnesses();
        let source_hash = w0.input_hash;
        p.record_pass(w0).unwrap();
        p.record_pass(w1).unwrap();
        let artifact = p.finalize(source_hash).unwrap();
        assert!(artifact.is_valid());
        assert_eq!(artifact.witness_chain.passes.len(), 2);
        assert_eq!(artifact.target_lane, LaneTarget::Js);
    }

    #[test]
    fn pipeline_finalize_with_equivalence() {
        let mut p = FrirLoweringPipeline::new(PipelineConfig::production());
        let w0 = make_witness(0, PassKind::Parse, b"source", b"ir0");
        let source_hash = w0.input_hash;
        p.record_pass(w0).unwrap();
        let ew = EquivalenceWitness {
            reference_hash: make_hash(b"ref"),
            optimized_hash: make_hash(b"opt"),
            equivalence_kind: EquivalenceKind::Output,
            test_input_count: 50,
            all_outputs_matched: true,
            counterexample_hash: None,
            preserved_invariants: vec![InvariantKind::SemanticEquivalence],
            witness_hash: make_hash(b"eq"),
        };
        p.record_equivalence_witness(ew);
        let artifact = p.finalize(source_hash).unwrap();
        assert_eq!(artifact.equivalence_witnesses.len(), 1);
        assert!(artifact.all_equivalences_proven());
    }

    #[test]
    fn pipeline_events_audit_trail() {
        let mut p = FrirLoweringPipeline::new(PipelineConfig::production());
        let w0 = make_witness(0, PassKind::Parse, b"source", b"ir0");
        let source_hash = w0.input_hash;
        p.record_pass(w0).unwrap();
        p.finalize(source_hash).unwrap();
        let events = p.events();
        // PipelineStarted, PassExecuted, WitnessProduced, PipelineCompleted
        assert!(events.len() >= 4);
        assert_eq!(events[0].kind, FrirPipelineEventKind::PipelineStarted);
    }

    #[test]
    fn pipeline_serde_roundtrip() {
        let mut p = FrirLoweringPipeline::new(PipelineConfig::production());
        let w0 = make_witness(0, PassKind::Parse, b"source", b"ir0");
        p.record_pass(w0).unwrap();
        let json = serde_json::to_string(&p).unwrap();
        let back: FrirLoweringPipeline = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    // -- FrirArtifact tests --

    #[test]
    fn frir_artifact_serde_roundtrip() {
        let mut p = FrirLoweringPipeline::new(PipelineConfig::production());
        let w0 = make_witness(0, PassKind::Parse, b"source", b"ir0");
        let source_hash = w0.input_hash;
        p.record_pass(w0).unwrap();
        let artifact = p.finalize(source_hash).unwrap();
        let json = serde_json::to_string(&artifact).unwrap();
        let back: FrirArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(artifact, back);
    }

    // -- ObligationRef tests --

    #[test]
    fn obligation_ref_serde_roundtrip() {
        let ob = make_obligation("ob_1", true);
        let json = serde_json::to_string(&ob).unwrap();
        let back: ObligationRef = serde_json::from_str(&json).unwrap();
        assert_eq!(ob, back);
    }

    // -- AssumptionRef tests --

    #[test]
    fn assumption_ref_serde_roundtrip() {
        let asm = make_assumption("asm_1", true);
        let json = serde_json::to_string(&asm).unwrap();
        let back: AssumptionRef = serde_json::from_str(&json).unwrap();
        assert_eq!(asm, back);
    }

    // -- ChainVerification tests --

    #[test]
    fn chain_verification_serde_roundtrip() {
        let cv = ChainVerification {
            valid: true,
            errors: Vec::new(),
            pass_verdicts: vec![WitnessVerdict::Valid, WitnessVerdict::Valid],
        };
        let json = serde_json::to_string(&cv).unwrap();
        let back: ChainVerification = serde_json::from_str(&json).unwrap();
        assert_eq!(cv, back);
    }

    // -- InvariantCheck tests --

    #[test]
    fn invariant_check_serde_roundtrip() {
        let ic = make_invariant(InvariantKind::SemanticEquivalence, true);
        let json = serde_json::to_string(&ic).unwrap();
        let back: InvariantCheck = serde_json::from_str(&json).unwrap();
        assert_eq!(ic, back);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn witness_verdict_serde_roundtrip() {
        let variants = [
            WitnessVerdict::Valid,
            WitnessVerdict::Invalid,
            WitnessVerdict::Missing,
            WitnessVerdict::Stale,
            WitnessVerdict::TimedOut,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: WitnessVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn invariant_kind_serde_roundtrip() {
        let variants = [
            InvariantKind::SemanticEquivalence,
            InvariantKind::TypeSafety,
            InvariantKind::EffectContainment,
            InvariantKind::HookOrdering,
            InvariantKind::CapabilityMonotonicity,
            InvariantKind::Determinism,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: InvariantKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn equivalence_kind_serde_roundtrip() {
        let variants = [
            EquivalenceKind::Observational,
            EquivalenceKind::Trace,
            EquivalenceKind::Effect,
            EquivalenceKind::Output,
            EquivalenceKind::Approximate,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: EquivalenceKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn frir_pipeline_event_kind_serde_roundtrip() {
        let variants = [
            FrirPipelineEventKind::PipelineStarted,
            FrirPipelineEventKind::PassExecuted,
            FrirPipelineEventKind::WitnessProduced,
            FrirPipelineEventKind::WitnessVerified,
            FrirPipelineEventKind::FallbackTriggered,
            FrirPipelineEventKind::EquivalenceWitnessProduced,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: FrirPipelineEventKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn witness_verdict_display_all_distinct() {
        let variants = [
            WitnessVerdict::Valid,
            WitnessVerdict::Invalid,
            WitnessVerdict::Missing,
            WitnessVerdict::Stale,
            WitnessVerdict::TimedOut,
        ];
        let mut set = std::collections::BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn invariant_kind_display_all_distinct() {
        let variants = [
            InvariantKind::SemanticEquivalence,
            InvariantKind::TypeSafety,
            InvariantKind::EffectContainment,
            InvariantKind::HookOrdering,
            InvariantKind::CapabilityMonotonicity,
            InvariantKind::Determinism,
        ];
        let mut set = std::collections::BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn equivalence_kind_display_all_distinct() {
        let variants = [
            EquivalenceKind::Observational,
            EquivalenceKind::Trace,
            EquivalenceKind::Effect,
            EquivalenceKind::Output,
            EquivalenceKind::Approximate,
        ];
        let mut set = std::collections::BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn lane_target_display_all_distinct() {
        let variants = [LaneTarget::Js, LaneTarget::Wasm, LaneTarget::Baseline];
        let mut set = std::collections::BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn pass_kind_display_all_distinct() {
        let variants = [
            PassKind::Parse,
            PassKind::ScopeResolve,
            PassKind::CapabilityAnnotate,
            PassKind::EffectAnalysis,
            PassKind::HookSlotValidation,
            PassKind::DependencyGraph,
        ];
        let mut set = std::collections::BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), variants.len());
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn frir_pipeline_error_display_non_empty_all() {
        let variants: Vec<FrirPipelineError> = vec![
            FrirPipelineError::PassLimitExceeded { count: 70, max: 64 },
            FrirPipelineError::ObligationLimitExceeded {
                count: 600,
                max: 512,
            },
            FrirPipelineError::AssumptionLimitExceeded {
                count: 300,
                max: 256,
            },
            FrirPipelineError::BrokenChain {
                pass_index: 3,
                detail: "hash mismatch".into(),
            },
            FrirPipelineError::InvariantFailed {
                kind: InvariantKind::TypeSafety,
                pass_index: 2,
                detail: "x".into(),
            },
            FrirPipelineError::BudgetExceeded {
                elapsed_ms: 5000,
                budget_ms: 1000,
            },
            FrirPipelineError::DuplicatePassIndex(4),
        ];
        for v in &variants {
            assert!(
                !v.to_string().is_empty(),
                "expected non-empty Display for {v:?}"
            );
        }
        assert_eq!(variants.len(), 7);
    }

    #[test]
    fn frir_pipeline_error_display_exact_all_7() {
        assert_eq!(
            FrirPipelineError::PassLimitExceeded { count: 70, max: 64 }.to_string(),
            "pass limit exceeded: 70 > 64"
        );
        assert_eq!(
            FrirPipelineError::ObligationLimitExceeded {
                count: 600,
                max: 512
            }
            .to_string(),
            "obligation limit exceeded: 600 > 512"
        );
        assert_eq!(
            FrirPipelineError::AssumptionLimitExceeded {
                count: 300,
                max: 256
            }
            .to_string(),
            "assumption limit exceeded: 300 > 256"
        );
        assert_eq!(
            FrirPipelineError::BrokenChain {
                pass_index: 3,
                detail: "bad".into()
            }
            .to_string(),
            "broken chain at pass 3: bad"
        );
        assert_eq!(
            FrirPipelineError::InvariantFailed {
                kind: InvariantKind::Determinism,
                pass_index: 0,
                detail: "nondeterministic".into(),
            }
            .to_string(),
            "invariant determinism failed at pass 0: nondeterministic"
        );
        assert_eq!(
            FrirPipelineError::BudgetExceeded {
                elapsed_ms: 5000,
                budget_ms: 1000
            }
            .to_string(),
            "budget exceeded: 5000ms > 1000ms"
        );
        assert_eq!(
            FrirPipelineError::DuplicatePassIndex(7).to_string(),
            "duplicate pass index: 7"
        );
    }

    #[test]
    fn frir_pipeline_error_serde_roundtrip_all() {
        let variants: Vec<FrirPipelineError> = vec![
            FrirPipelineError::PassLimitExceeded { count: 70, max: 64 },
            FrirPipelineError::ObligationLimitExceeded {
                count: 600,
                max: 512,
            },
            FrirPipelineError::AssumptionLimitExceeded {
                count: 300,
                max: 256,
            },
            FrirPipelineError::BrokenChain {
                pass_index: 3,
                detail: "hash".into(),
            },
            FrirPipelineError::InvariantFailed {
                kind: InvariantKind::EffectContainment,
                pass_index: 1,
                detail: "leak".into(),
            },
            FrirPipelineError::BudgetExceeded {
                elapsed_ms: 5000,
                budget_ms: 1000,
            },
            FrirPipelineError::DuplicatePassIndex(2),
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: FrirPipelineError = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn fallback_reason_serde_roundtrip_all() {
        let variants: Vec<FallbackReason> = vec![
            FallbackReason::MissingWitness {
                pass_index: 0,
                pass_kind: PassKind::Parse,
            },
            FallbackReason::InvalidWitness {
                pass_index: 1,
                pass_kind: PassKind::ScopeResolve,
                detail: "bad".into(),
            },
            FallbackReason::StaleWitness {
                pass_index: 2,
                pass_kind: PassKind::EffectAnalysis,
            },
            FallbackReason::VerificationBudgetExceeded {
                elapsed_ms: 10_000,
                budget_ms: 5_000,
            },
            FallbackReason::UnfulfilledObligation {
                obligation_id: "obl-1".into(),
                pass_index: 3,
            },
            FallbackReason::ExplicitOptOut {
                reason: "debug mode".into(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: FallbackReason = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
        assert_eq!(variants.len(), 6);
    }

    #[test]
    fn fallback_reason_display_exact() {
        assert_eq!(
            FallbackReason::MissingWitness {
                pass_index: 0,
                pass_kind: PassKind::Parse
            }
            .to_string(),
            "missing witness at pass 0 (parse)"
        );
        assert_eq!(
            FallbackReason::InvalidWitness {
                pass_index: 1,
                pass_kind: PassKind::ScopeResolve,
                detail: "x".into()
            }
            .to_string(),
            "invalid witness at pass 1 (scope_resolve): x"
        );
        assert_eq!(
            FallbackReason::StaleWitness {
                pass_index: 2,
                pass_kind: PassKind::EffectAnalysis
            }
            .to_string(),
            "stale witness at pass 2 (effect_analysis)"
        );
        assert_eq!(
            FallbackReason::VerificationBudgetExceeded {
                elapsed_ms: 10_000,
                budget_ms: 5_000
            }
            .to_string(),
            "verification budget exceeded: 10000ms > 5000ms"
        );
        assert_eq!(
            FallbackReason::UnfulfilledObligation {
                obligation_id: "obl-1".into(),
                pass_index: 3
            }
            .to_string(),
            "unfulfilled obligation obl-1 at pass 3"
        );
        assert_eq!(
            FallbackReason::ExplicitOptOut {
                reason: "debug".into()
            }
            .to_string(),
            "explicit opt-out: debug"
        );
    }

    #[test]
    fn pass_kind_serde_roundtrip_all_15() {
        let variants = [
            PassKind::Parse,
            PassKind::ScopeResolve,
            PassKind::CapabilityAnnotate,
            PassKind::EffectAnalysis,
            PassKind::HookSlotValidation,
            PassKind::DependencyGraph,
            PassKind::DeadCodeElimination,
            PassKind::MemoizationBoundary,
            PassKind::SignalGraphExtraction,
            PassKind::DomUpdatePlanning,
            PassKind::EGraphOptimization,
            PassKind::PartialEvaluation,
            PassKind::Incrementalization,
            PassKind::CodeGeneration,
            PassKind::Custom,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: PassKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
        assert_eq!(variants.len(), 15);
    }

    #[test]
    fn lane_target_serde_roundtrip_all() {
        let variants = [LaneTarget::Js, LaneTarget::Wasm, LaneTarget::Baseline];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: LaneTarget = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
        assert_eq!(variants.len(), 3);
    }

    #[test]
    fn frir_pipeline_event_kind_serde_includes_pipeline_completed() {
        let v = FrirPipelineEventKind::PipelineCompleted;
        let json = serde_json::to_string(&v).unwrap();
        let back: FrirPipelineEventKind = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
        assert_eq!(v.to_string(), "pipeline_completed");
    }

    #[test]
    fn frir_version_display_format() {
        assert_eq!(FrirVersion::CURRENT.to_string(), "0.1.0");
        let custom = FrirVersion {
            major: 2,
            minor: 3,
            patch: 7,
        };
        assert_eq!(custom.to_string(), "2.3.7");
    }

    #[test]
    fn frir_version_can_read_same_minor_different_patch() {
        let reader = FrirVersion {
            major: 0,
            minor: 1,
            patch: 5,
        };
        let artifact = FrirVersion {
            major: 0,
            minor: 1,
            patch: 0,
        };
        assert!(reader.can_read(&artifact));
        assert!(artifact.can_read(&reader));
    }

    #[test]
    fn frir_version_cannot_read_higher_minor() {
        let reader = FrirVersion {
            major: 0,
            minor: 1,
            patch: 0,
        };
        let artifact = FrirVersion {
            major: 0,
            minor: 2,
            patch: 0,
        };
        assert!(!reader.can_read(&artifact));
    }

    #[test]
    fn frir_version_cannot_read_cross_major() {
        let reader = FrirVersion {
            major: 1,
            minor: 1,
            patch: 0,
        };
        let artifact = FrirVersion {
            major: 0,
            minor: 1,
            patch: 0,
        };
        assert!(!reader.can_read(&artifact));
        assert!(!artifact.can_read(&reader));
    }

    #[test]
    fn witness_verdict_allows_optimized_path_only_valid() {
        assert!(WitnessVerdict::Valid.allows_optimized_path());
        assert!(!WitnessVerdict::Invalid.allows_optimized_path());
        assert!(!WitnessVerdict::Missing.allows_optimized_path());
        assert!(!WitnessVerdict::Stale.allows_optimized_path());
        assert!(!WitnessVerdict::TimedOut.allows_optimized_path());
    }

    #[test]
    fn frir_pipeline_event_serde_roundtrip() {
        let event = FrirPipelineEvent {
            seq: 42,
            kind: FrirPipelineEventKind::WitnessVerified,
            pass_index: Some(3),
            detail: "pass 3 verified".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: FrirPipelineEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn frir_pipeline_event_serde_no_pass_index() {
        let event = FrirPipelineEvent {
            seq: 1,
            kind: FrirPipelineEventKind::PipelineStarted,
            pass_index: None,
            detail: "started".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: FrirPipelineEvent = serde_json::from_str(&json).unwrap();
        assert!(back.pass_index.is_none());
    }
}
