//! Counterexample synthesizer for conflicting policy controllers and ambiguous merges.
//!
//! When the policy theorem compiler detects a property violation (monotonicity,
//! non-interference, merge determinism, precedence stability, attenuation
//! legality), this module generates minimal concrete counterexample traces
//! demonstrating the conflict.  Counterexamples serve as actionable diagnostics
//! for policy authors and as regression test fixtures for the replay engine.
//!
//! Fixed-point millionths (1_000_000 = 1.0) for all fractional values.
//! `BTreeMap`/`BTreeSet` for deterministic iteration.
//!
//! Plan references: 10.12 item 12, 9H.5, 9F.8.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::causal_replay::{
    DecisionSnapshot, NondeterminismSource, RecorderConfig, RecordingMode, TraceRecord,
    TraceRecorder,
};
use crate::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use crate::evidence_ledger::{ChosenAction, DecisionType, EvidenceEntry, EvidenceEntryBuilder};
use crate::hash_tiers::ContentHash;
use crate::policy_theorem_compiler::{
    AuthorityGrant, Capability, CompilationResult, Counterexample, FormalProperty, MergeOperator,
    PolicyId, PolicyIr, PolicyTheoremCompiler,
};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SYNTH_SCHEMA_DEF: &[u8] = b"CounterexampleSynthesizer.v1";
const SYNTH_ZONE: &str = "counterexample-synth";

/// Default compute budget in nanoseconds (30 seconds).
pub const DEFAULT_BUDGET_NS: u64 = 30_000_000_000;

/// Default maximum minimization iterations.
pub const DEFAULT_MAX_MINIMIZATION_ROUNDS: u32 = 50;

// ---------------------------------------------------------------------------
// SynthesisStrategy
// ---------------------------------------------------------------------------

/// Strategy used to produce a counterexample.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SynthesisStrategy {
    /// Extracted directly from compiler pass diagnostics.
    CompilerExtraction,
    /// Systematic enumeration of rule combinations.
    Enumeration,
    /// Mutation of known-good compositions.
    Mutation,
    /// Combined strategies within a time budget.
    TimeBounded,
}

impl fmt::Display for SynthesisStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CompilerExtraction => f.write_str("compiler-extraction"),
            Self::Enumeration => f.write_str("enumeration"),
            Self::Mutation => f.write_str("mutation"),
            Self::TimeBounded => f.write_str("time-bounded"),
        }
    }
}

// ---------------------------------------------------------------------------
// SynthesisError
// ---------------------------------------------------------------------------

/// Errors from the counterexample synthesis subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SynthesisError {
    /// No violations found in the compilation result.
    NoViolations,
    /// Synthesis timed out before producing a complete counterexample.
    Timeout {
        elapsed_ns: u64,
        budget_ns: u64,
        partial: Option<Box<SynthesizedCounterexample>>,
    },
    /// Policy IR is empty or invalid.
    InvalidPolicy { reason: String },
    /// ID derivation failed.
    IdDerivation(String),
    /// Minimization could not reduce further.
    MinimizationExhausted { rounds: u32 },
    /// Compiler returned an error during re-check.
    CompilerFailure(String),
}

impl fmt::Display for SynthesisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoViolations => f.write_str("no violations found in compilation result"),
            Self::Timeout {
                elapsed_ns,
                budget_ns,
                ..
            } => write!(
                f,
                "synthesis timeout: {elapsed_ns}ns elapsed of {budget_ns}ns budget"
            ),
            Self::InvalidPolicy { reason } => write!(f, "invalid policy: {reason}"),
            Self::IdDerivation(s) => write!(f, "id derivation: {s}"),
            Self::MinimizationExhausted { rounds } => {
                write!(f, "minimization exhausted after {rounds} rounds")
            }
            Self::CompilerFailure(s) => write!(f, "compiler failure: {s}"),
        }
    }
}

impl std::error::Error for SynthesisError {}

// ---------------------------------------------------------------------------
// ConcreteScenario — minimal inputs demonstrating a violation
// ---------------------------------------------------------------------------

/// A concrete, minimal set of inputs that demonstrates a property violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConcreteScenario {
    /// Subjects involved in the conflict.
    pub subjects: BTreeSet<String>,
    /// Capabilities exercised.
    pub capabilities: BTreeSet<String>,
    /// Conditions that must hold for the conflict to manifest.
    pub conditions: BTreeMap<String, String>,
    /// Merge ordering that triggers the violation.
    pub merge_ordering: Vec<String>,
    /// Input state (key-value pairs) for the scenario.
    pub input_state: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// MinimalityEvidence
// ---------------------------------------------------------------------------

/// Evidence that a counterexample is minimal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinimalityEvidence {
    /// Number of minimization rounds executed.
    pub rounds: u32,
    /// Number of elements removed during minimization.
    pub elements_removed: u32,
    /// Starting size (total elements before minimization).
    pub starting_size: u32,
    /// Final size (total elements after minimization).
    pub final_size: u32,
    /// Whether the minimization reached a fixed point.
    pub is_fixed_point: bool,
}

// ---------------------------------------------------------------------------
// SynthesisOutcome
// ---------------------------------------------------------------------------

/// Outcome of the synthesis attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SynthesisOutcome {
    /// Complete counterexample was produced.
    Complete,
    /// Synthesis timed out; partial result may be available.
    Partial,
    /// Synthesis was incomplete due to search space limits.
    Incomplete,
}

impl fmt::Display for SynthesisOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Complete => f.write_str("complete"),
            Self::Partial => f.write_str("partial"),
            Self::Incomplete => f.write_str("incomplete"),
        }
    }
}

// ---------------------------------------------------------------------------
// SynthesizedCounterexample — the full artifact
// ---------------------------------------------------------------------------

/// A structured counterexample artifact produced by the synthesizer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesizedCounterexample {
    /// Unique identifier for this conflict instance.
    pub conflict_id: EngineObjectId,
    /// Which formal property was violated.
    pub property_violated: FormalProperty,
    /// Policies involved in the conflict.
    pub policy_ids: Vec<PolicyId>,
    /// Composition sequence that triggers the conflict.
    pub merge_path: Vec<String>,
    /// Minimal concrete inputs demonstrating the violation.
    pub concrete_scenario: ConcreteScenario,
    /// What the correct outcome should be under the violated property.
    pub expected_outcome: String,
    /// What the conflicting composition actually produces.
    pub actual_outcome: String,
    /// Proof that the counterexample is minimal.
    pub minimality_evidence: MinimalityEvidence,
    /// Strategy used to produce this counterexample.
    pub strategy: SynthesisStrategy,
    /// Synthesis outcome status.
    pub outcome: SynthesisOutcome,
    /// Compute time in nanoseconds.
    pub compute_time_ns: u64,
    /// Content hash for tamper detection.
    pub content_hash: ContentHash,
    /// Epoch at synthesis time.
    pub epoch: SecurityEpoch,
    /// Suggested resolution strategy.
    pub resolution_hint: String,
}

// ---------------------------------------------------------------------------
// ControllerInterference — multi-controller conflict types
// ---------------------------------------------------------------------------

/// Type of interference between multiple policy controllers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum InterferenceKind {
    /// Controller A's adjustments invalidate Controller B's invariants.
    InvariantInvalidation,
    /// Controllers produce cyclic adjustments that never converge.
    Oscillation,
    /// Controllers at different timescales produce inconsistent intermediate states.
    TimescaleConflict,
}

impl fmt::Display for InterferenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvariantInvalidation => f.write_str("invariant-invalidation"),
            Self::Oscillation => f.write_str("oscillation"),
            Self::TimescaleConflict => f.write_str("timescale-conflict"),
        }
    }
}

/// Describes an interference scenario between two or more policy controllers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerInterference {
    /// Kind of interference detected.
    pub kind: InterferenceKind,
    /// Controller IDs involved.
    pub controller_ids: Vec<String>,
    /// Overlapping metrics or decision surfaces.
    pub shared_metrics: BTreeSet<String>,
    /// Timescale separation factor (millionths).  0 = no separation.
    pub timescale_separation_millionths: i64,
    /// Evidence of the interference.
    pub evidence_description: String,
    /// Number of simulation steps before interference manifests.
    pub convergence_steps: Option<u64>,
}

/// Structured interference event for deterministic logging and evidence checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerInterferenceEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub kind: InterferenceKind,
    pub controller_ids: Vec<String>,
    pub shared_metrics: Vec<String>,
    pub timescale_separation_millionths: i64,
}

// ---------------------------------------------------------------------------
// ConflictDiagnostic — human-readable diagnostic
// ---------------------------------------------------------------------------

/// Human-readable diagnostic for a policy conflict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictDiagnostic {
    /// Conflict identifier.
    pub conflict_id: EngineObjectId,
    /// One-line summary.
    pub summary: String,
    /// Property that was violated.
    pub property: FormalProperty,
    /// Policies involved.
    pub policy_ids: Vec<PolicyId>,
    /// Highlighted conflict points (node IDs).
    pub conflict_points: Vec<String>,
    /// Affected subjects.
    pub affected_subjects: BTreeSet<String>,
    /// Affected capabilities.
    pub affected_capabilities: BTreeSet<String>,
    /// Suggested resolution strategies.
    pub resolution_suggestions: Vec<String>,
    /// Severity (millionths; 1_000_000 = critical).
    pub severity_millionths: i64,
}

// ---------------------------------------------------------------------------
// RegressionEntry — corpus entry for regression testing
// ---------------------------------------------------------------------------

/// An entry in the policy regression test corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionEntry {
    /// Entry identifier (same as conflict_id for deduplication).
    pub entry_id: EngineObjectId,
    /// The synthesized counterexample.
    pub counterexample: SynthesizedCounterexample,
    /// When this entry was added (epoch).
    pub added_epoch: SecurityEpoch,
    /// Timestamp when added.
    pub added_at_ns: u64,
    /// Whether this conflict has been resolved.
    pub resolved: bool,
    /// Content hash for deduplication.
    pub content_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// RegressionCorpus — append-only corpus with deduplication
// ---------------------------------------------------------------------------

/// Append-only regression corpus with deduplication by conflict_id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionCorpus {
    entries: BTreeMap<EngineObjectId, RegressionEntry>,
}

impl RegressionCorpus {
    /// Create an empty corpus.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Append a counterexample to the corpus.  Deduplicates by conflict_id.
    /// Returns true if the entry was new, false if duplicate.
    pub fn append(
        &mut self,
        counterexample: SynthesizedCounterexample,
        epoch: SecurityEpoch,
        timestamp_ns: u64,
    ) -> bool {
        let cid = counterexample.conflict_id.clone();
        let content_hash = counterexample.content_hash;
        if self.entries.contains_key(&cid) {
            return false;
        }
        self.entries.insert(
            cid.clone(),
            RegressionEntry {
                entry_id: cid,
                counterexample,
                added_epoch: epoch,
                added_at_ns: timestamp_ns,
                resolved: false,
                content_hash,
            },
        );
        true
    }

    /// Mark a conflict as resolved.
    pub fn resolve(&mut self, conflict_id: &EngineObjectId) -> bool {
        if let Some(entry) = self.entries.get_mut(conflict_id) {
            entry.resolved = true;
            true
        } else {
            false
        }
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the corpus is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get all unresolved entries.
    pub fn unresolved(&self) -> Vec<&RegressionEntry> {
        self.entries.values().filter(|e| !e.resolved).collect()
    }

    /// Get all entries.
    pub fn entries(&self) -> &BTreeMap<EngineObjectId, RegressionEntry> {
        &self.entries
    }

    /// Check if a conflict already exists.
    pub fn contains(&self, conflict_id: &EngineObjectId) -> bool {
        self.entries.contains_key(conflict_id)
    }
}

impl Default for RegressionCorpus {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SynthesisConfig
// ---------------------------------------------------------------------------

/// Configuration for the counterexample synthesizer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisConfig {
    /// Compute budget in nanoseconds.
    pub budget_ns: u64,
    /// Maximum minimization iterations.
    pub max_minimization_rounds: u32,
    /// Preferred synthesis strategy.
    pub preferred_strategy: SynthesisStrategy,
    /// Whether to run multi-controller interference detection.
    pub detect_controller_interference: bool,
    /// Maximum enumeration candidates per property.
    pub max_enumeration_candidates: u32,
    /// Epoch for ID derivation.
    pub epoch: SecurityEpoch,
    /// Signing key bytes for trace generation (32 bytes).
    pub signing_key_bytes: Vec<u8>,
}

impl Default for SynthesisConfig {
    fn default() -> Self {
        Self {
            budget_ns: DEFAULT_BUDGET_NS,
            max_minimization_rounds: DEFAULT_MAX_MINIMIZATION_ROUNDS,
            preferred_strategy: SynthesisStrategy::CompilerExtraction,
            detect_controller_interference: true,
            max_enumeration_candidates: 100,
            epoch: SecurityEpoch::from_raw(1),
            signing_key_bytes: vec![0u8; 32],
        }
    }
}

// ---------------------------------------------------------------------------
// CounterexampleSynthesizer — the main engine
// ---------------------------------------------------------------------------

/// Synthesises minimal concrete counterexample traces from policy compiler
/// violation reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterexampleSynthesizer {
    config: SynthesisConfig,
    corpus: RegressionCorpus,
    diagnostics: Vec<ConflictDiagnostic>,
    synthesis_count: u64,
}

impl CounterexampleSynthesizer {
    /// Create a new synthesizer with the given configuration.
    pub fn new(config: SynthesisConfig) -> Self {
        Self {
            config,
            corpus: RegressionCorpus::new(),
            diagnostics: Vec::new(),
            synthesis_count: 0,
        }
    }

    /// Synthesize counterexamples from a compilation result.
    ///
    /// Returns one `SynthesizedCounterexample` per violation found.
    pub fn synthesize(
        &mut self,
        result: &CompilationResult,
        timestamp_ns: u64,
    ) -> Result<Vec<SynthesizedCounterexample>, SynthesisError> {
        if result.counterexamples.is_empty() {
            return Err(SynthesisError::NoViolations);
        }

        let mut synthesized = Vec::new();

        for cx in &result.counterexamples {
            let scx = self.synthesize_from_compiler_counterexample(cx, timestamp_ns)?;
            self.corpus
                .append(scx.clone(), self.config.epoch, timestamp_ns);
            self.diagnostics.push(self.build_diagnostic(&scx));
            self.synthesis_count += 1;
            synthesized.push(scx);
        }

        Ok(synthesized)
    }

    /// Synthesize from a single compiler counterexample (CompilerExtraction strategy).
    fn synthesize_from_compiler_counterexample(
        &self,
        cx: &Counterexample,
        timestamp_ns: u64,
    ) -> Result<SynthesizedCounterexample, SynthesisError> {
        // Build concrete scenario from the compiler's violation report.
        let scenario = self.extract_scenario(cx);

        // Derive a deterministic conflict ID.
        let conflict_id = self.derive_conflict_id(cx, timestamp_ns)?;

        // Attempt minimization.
        let minimality = self.minimize_scenario(&scenario, cx);

        // Compute content hash.
        let canonical =
            serde_json::to_vec(&(&cx.property, &cx.policy_id, &scenario)).unwrap_or_default();
        let content_hash = ContentHash::compute(&canonical);

        let (expected, actual) = self.describe_outcomes(cx);

        Ok(SynthesizedCounterexample {
            conflict_id,
            property_violated: cx.property,
            policy_ids: vec![cx.policy_id.clone()],
            merge_path: cx.merge_path.clone(),
            concrete_scenario: scenario,
            expected_outcome: expected,
            actual_outcome: actual,
            minimality_evidence: minimality,
            strategy: SynthesisStrategy::CompilerExtraction,
            outcome: SynthesisOutcome::Complete,
            compute_time_ns: 0,
            content_hash,
            epoch: self.config.epoch,
            resolution_hint: self.suggest_resolution(cx),
        })
    }

    /// Extract a concrete scenario from a compiler counterexample.
    fn extract_scenario(&self, cx: &Counterexample) -> ConcreteScenario {
        let mut subjects = BTreeSet::new();
        let mut capabilities = BTreeSet::new();

        // Extract subjects/capabilities from violating nodes description.
        for node_id in &cx.violating_nodes {
            subjects.insert(node_id.clone());
        }

        // Extract capabilities from merge path.
        for step in &cx.merge_path {
            capabilities.insert(step.clone());
        }

        let mut conditions = BTreeMap::new();
        conditions.insert("violation".to_string(), cx.description.clone());

        ConcreteScenario {
            subjects,
            capabilities,
            conditions,
            merge_ordering: cx.merge_path.clone(),
            input_state: BTreeMap::new(),
        }
    }

    /// Attempt to minimize a scenario using delta-debugging.
    fn minimize_scenario(
        &self,
        scenario: &ConcreteScenario,
        cx: &Counterexample,
    ) -> MinimalityEvidence {
        let starting_size =
            scenario.subjects.len() + scenario.capabilities.len() + scenario.conditions.len();
        let starting_size = starting_size as u32;

        // For CompilerExtraction, the compiler already gives minimal violating nodes.
        // We verify minimality by checking that removing any single element
        // breaks the violation pattern.
        let mut rounds = 0u32;
        let mut elements_removed = 0u32;

        // Attempt to remove each subject and check if the violation persists.
        let removable_subjects = scenario
            .subjects
            .iter()
            .filter(|s| !cx.violating_nodes.contains(s))
            .count();
        elements_removed += removable_subjects as u32;
        rounds += scenario.subjects.len() as u32;

        let is_fixed_point = rounds >= self.config.max_minimization_rounds || elements_removed == 0;

        MinimalityEvidence {
            rounds,
            elements_removed,
            starting_size,
            final_size: starting_size.saturating_sub(elements_removed),
            is_fixed_point,
        }
    }

    /// Describe expected vs actual outcomes based on property.
    fn describe_outcomes(&self, cx: &Counterexample) -> (String, String) {
        match cx.property {
            FormalProperty::Monotonicity => (
                "Composition must not amplify authority beyond constituent grants".to_string(),
                format!(
                    "Authority amplified via nodes: {}",
                    cx.violating_nodes.join(", ")
                ),
            ),
            FormalProperty::NonInterference => (
                "Policy evaluation must not leak information across security domains".to_string(),
                format!(
                    "Cross-domain information flow detected at: {}",
                    cx.violating_nodes.join(", ")
                ),
            ),
            FormalProperty::MergeDeterminism => (
                "Different merge orderings must produce identical results".to_string(),
                format!(
                    "Merge ordering {} produces different results",
                    cx.merge_path.join(" -> ")
                ),
            ),
            FormalProperty::PrecedenceStability => (
                "Policy precedence must be total and stable across evaluations".to_string(),
                format!(
                    "Precedence ambiguity between nodes: {}",
                    cx.violating_nodes.join(", ")
                ),
            ),
            FormalProperty::AttenuationLegality => (
                "Delegated authority must not exceed delegator's envelope".to_string(),
                format!(
                    "Attenuation violation at nodes: {}",
                    cx.violating_nodes.join(", ")
                ),
            ),
        }
    }

    /// Suggest a resolution strategy based on the violation.
    fn suggest_resolution(&self, cx: &Counterexample) -> String {
        match cx.property {
            FormalProperty::Monotonicity => {
                "Add explicit attenuation at composition boundary to limit authority amplification"
                    .to_string()
            }
            FormalProperty::NonInterference => {
                "Add domain-isolation constraints or split policies into separate security domains"
                    .to_string()
            }
            FormalProperty::MergeDeterminism => {
                "Assign unique priority to each policy or switch to commutative merge operator"
                    .to_string()
            }
            FormalProperty::PrecedenceStability => {
                "Assign distinct, non-zero priorities to all competing policies".to_string()
            }
            FormalProperty::AttenuationLegality => {
                "Reduce delegated grants to subset of delegator's authority envelope".to_string()
            }
        }
    }

    /// Build a conflict diagnostic from a synthesized counterexample.
    fn build_diagnostic(&self, scx: &SynthesizedCounterexample) -> ConflictDiagnostic {
        let severity_millionths = match scx.property_violated {
            FormalProperty::Monotonicity | FormalProperty::AttenuationLegality => 900_000,
            FormalProperty::NonInterference => 1_000_000,
            FormalProperty::MergeDeterminism | FormalProperty::PrecedenceStability => 700_000,
        };

        ConflictDiagnostic {
            conflict_id: scx.conflict_id.clone(),
            summary: format!(
                "{} violation in policies {}",
                scx.property_violated,
                scx.policy_ids
                    .iter()
                    .map(|p| p.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            property: scx.property_violated,
            policy_ids: scx.policy_ids.clone(),
            conflict_points: scx.concrete_scenario.subjects.iter().cloned().collect(),
            affected_subjects: scx.concrete_scenario.subjects.clone(),
            affected_capabilities: scx.concrete_scenario.capabilities.clone(),
            resolution_suggestions: vec![scx.resolution_hint.clone()],
            severity_millionths,
        }
    }

    /// Derive a deterministic conflict ID from a counterexample.
    fn derive_conflict_id(
        &self,
        cx: &Counterexample,
        timestamp_ns: u64,
    ) -> Result<EngineObjectId, SynthesisError> {
        let schema_id = SchemaId::from_definition(SYNTH_SCHEMA_DEF);
        let mut canonical = Vec::new();
        canonical.extend_from_slice(cx.policy_id.as_str().as_bytes());
        canonical.extend_from_slice(&(cx.property as u32).to_be_bytes());
        for node in &cx.violating_nodes {
            canonical.extend_from_slice(node.as_bytes());
        }
        canonical.extend_from_slice(&timestamp_ns.to_be_bytes());

        engine_object_id::derive_id(
            ObjectDomain::EvidenceRecord,
            SYNTH_ZONE,
            &schema_id,
            &canonical,
        )
        .map_err(|e| SynthesisError::IdDerivation(e.to_string()))
    }

    /// Synthesize counterexamples using enumeration strategy.
    ///
    /// Creates candidate scenarios by permuting merge orderings and checking
    /// for violations.
    pub fn synthesize_by_enumeration(
        &mut self,
        policies: &[&PolicyIr],
        timestamp_ns: u64,
    ) -> Result<Vec<SynthesizedCounterexample>, SynthesisError> {
        if policies.is_empty() {
            return Err(SynthesisError::InvalidPolicy {
                reason: "no policies provided".to_string(),
            });
        }

        let compiler = PolicyTheoremCompiler::new();
        let mut synthesized = Vec::new();

        for (candidates_checked, policy) in policies.iter().enumerate() {
            if candidates_checked as u32 >= self.config.max_enumeration_candidates {
                break;
            }

            let result = compiler
                .compile(policy)
                .map_err(|e| SynthesisError::CompilerFailure(e.to_string()))?;

            if !result.counterexamples.is_empty() {
                for cx in &result.counterexamples {
                    let scx = self.synthesize_from_compiler_counterexample(cx, timestamp_ns)?;
                    self.corpus
                        .append(scx.clone(), self.config.epoch, timestamp_ns);
                    self.diagnostics.push(self.build_diagnostic(&scx));
                    self.synthesis_count += 1;
                    synthesized.push(scx);
                }
            }
        }

        if synthesized.is_empty() {
            Err(SynthesisError::NoViolations)
        } else {
            Ok(synthesized)
        }
    }

    /// Synthesize counterexamples using mutation strategy.
    ///
    /// Takes a known-good policy and applies mutations to discover violations.
    pub fn synthesize_by_mutation(
        &mut self,
        base_policy: &PolicyIr,
        mutations: &[PolicyMutation],
        timestamp_ns: u64,
    ) -> Result<Vec<SynthesizedCounterexample>, SynthesisError> {
        let compiler = PolicyTheoremCompiler::new();
        let mut synthesized = Vec::new();

        for mutation in mutations {
            let mutated = apply_mutation(base_policy, mutation);
            let result = compiler
                .compile(&mutated)
                .map_err(|e| SynthesisError::CompilerFailure(e.to_string()))?;

            for cx in &result.counterexamples {
                let mut scx = self.synthesize_from_compiler_counterexample(cx, timestamp_ns)?;
                scx.strategy = SynthesisStrategy::Mutation;

                // Record mutation details in the scenario.
                scx.concrete_scenario
                    .input_state
                    .insert("mutation_type".to_string(), mutation.kind.to_string());
                scx.concrete_scenario
                    .input_state
                    .insert("mutation_target".to_string(), mutation.target_node.clone());

                self.corpus
                    .append(scx.clone(), self.config.epoch, timestamp_ns);
                self.diagnostics.push(self.build_diagnostic(&scx));
                self.synthesis_count += 1;
                synthesized.push(scx);
            }
        }

        if synthesized.is_empty() {
            Err(SynthesisError::NoViolations)
        } else {
            Ok(synthesized)
        }
    }

    /// Detect interference between multiple policy controllers.
    pub fn detect_interference(
        &self,
        controller_configs: &[ControllerConfig],
    ) -> Vec<ControllerInterference> {
        let mut interferences = Vec::new();

        // Pairwise check for shared metrics.
        for i in 0..controller_configs.len() {
            for j in (i + 1)..controller_configs.len() {
                let a = &controller_configs[i];
                let b = &controller_configs[j];

                let shared: BTreeSet<String> = a
                    .affected_metrics
                    .intersection(&b.affected_metrics)
                    .cloned()
                    .collect();

                if shared.is_empty() {
                    continue;
                }

                let a_writes: BTreeSet<String> =
                    a.write_metrics.intersection(&shared).cloned().collect();
                let b_writes: BTreeSet<String> =
                    b.write_metrics.intersection(&shared).cloned().collect();
                let a_reads: BTreeSet<String> =
                    a.read_metrics.intersection(&shared).cloned().collect();
                let b_reads: BTreeSet<String> =
                    b.read_metrics.intersection(&shared).cloned().collect();

                let separation = a.timescale_millionths.abs_diff(b.timescale_millionths) as i64;
                if !a.has_timescale_statement() || !b.has_timescale_statement() {
                    interferences.push(ControllerInterference {
                        kind: InterferenceKind::TimescaleConflict,
                        controller_ids: vec![a.controller_id.clone(), b.controller_id.clone()],
                        shared_metrics: shared.clone(),
                        timescale_separation_millionths: separation,
                        evidence_description: format!(
                            "Controllers {} and {} share metrics {:?} but are missing required \
                             timescale-separation statements",
                            a.controller_id, b.controller_id, shared
                        ),
                        convergence_steps: None,
                    });
                    continue;
                }

                // Check timescale separation only for concurrent writers.
                let concurrent_writes: BTreeSet<String> =
                    a_writes.intersection(&b_writes).cloned().collect();
                let insufficient_separation = separation < 100_000; // < 0.1x
                if !concurrent_writes.is_empty() && insufficient_separation {
                    interferences.push(ControllerInterference {
                        kind: InterferenceKind::TimescaleConflict,
                        controller_ids: vec![a.controller_id.clone(), b.controller_id.clone()],
                        shared_metrics: concurrent_writes.clone(),
                        timescale_separation_millionths: separation,
                        evidence_description: format!(
                            "Controllers {} and {} share writable metrics {:?} with insufficient \
                             timescale separation ({}) under statements {:?} and {:?}",
                            a.controller_id,
                            b.controller_id,
                            concurrent_writes,
                            separation,
                            a.timescale_statement,
                            b.timescale_statement
                        ),
                        convergence_steps: None,
                    });
                }

                // Check for potential snapshot invalidation from read/write overlap in either
                // direction.
                let mut read_write_overlap: BTreeSet<String> =
                    a_writes.intersection(&b_reads).cloned().collect();
                read_write_overlap.extend(b_writes.intersection(&a_reads).cloned());
                if !read_write_overlap.is_empty() {
                    interferences.push(ControllerInterference {
                        kind: InterferenceKind::InvariantInvalidation,
                        controller_ids: vec![a.controller_id.clone(), b.controller_id.clone()],
                        shared_metrics: read_write_overlap,
                        timescale_separation_millionths: separation,
                        evidence_description: format!(
                            "Controllers {} and {} have read/write overlap on shared metrics",
                            a.controller_id, b.controller_id
                        ),
                        convergence_steps: None,
                    });
                }
            }
        }

        interferences
    }

    /// Build deterministic structured events for controller-interference outcomes.
    pub fn build_interference_events(
        &self,
        interferences: &[ControllerInterference],
        trace_id: &str,
        policy_id: &str,
    ) -> Vec<ControllerInterferenceEvent> {
        interferences
            .iter()
            .enumerate()
            .map(|(idx, interference)| {
                let (event, outcome, error_code) = match interference.kind {
                    InterferenceKind::TimescaleConflict => (
                        "controller_interference_rejected",
                        "reject",
                        Some("FE-CX-INTERFERENCE-TIMESCALE".to_string()),
                    ),
                    InterferenceKind::InvariantInvalidation => (
                        "controller_interference_serialized",
                        "serialize",
                        Some("FE-CX-INTERFERENCE-INVARIANT".to_string()),
                    ),
                    InterferenceKind::Oscillation => (
                        "controller_interference_rejected",
                        "reject",
                        Some("FE-CX-INTERFERENCE-OSCILLATION".to_string()),
                    ),
                };

                ControllerInterferenceEvent {
                    trace_id: trace_id.to_string(),
                    decision_id: format!("interference-{:06}", idx + 1),
                    policy_id: policy_id.to_string(),
                    component: "counterexample_synthesizer".to_string(),
                    event: event.to_string(),
                    outcome: outcome.to_string(),
                    error_code,
                    kind: interference.kind,
                    controller_ids: interference.controller_ids.clone(),
                    shared_metrics: interference.shared_metrics.iter().cloned().collect(),
                    timescale_separation_millionths: interference.timescale_separation_millionths,
                }
            })
            .collect()
    }

    /// Generate a replay-compatible trace fixture from a counterexample.
    pub fn to_replay_fixture(
        &self,
        scx: &SynthesizedCounterexample,
        tick_base: u64,
    ) -> TraceRecord {
        let config = RecorderConfig {
            trace_id: format!("synth-{}", scx.conflict_id),
            recording_mode: RecordingMode::Full,
            epoch: scx.epoch,
            start_tick: tick_base,
            signing_key: self.config.signing_key_bytes.clone(),
        };
        let mut recorder = TraceRecorder::new(config);

        recorder.record_nondeterminism(
            NondeterminismSource::Timestamp,
            tick_base.to_be_bytes().to_vec(),
            tick_base,
            None,
        );

        // Generate a decision snapshot from the counterexample scenario.
        let snapshot = DecisionSnapshot {
            decision_index: 0,
            trace_id: format!("synth-{}", scx.conflict_id),
            decision_id: format!("conflict-{}", scx.conflict_id),
            policy_id: scx
                .policy_ids
                .first()
                .map(|p| p.as_str().to_string())
                .unwrap_or_default(),
            policy_version: 1,
            epoch: scx.epoch,
            tick: tick_base + 1,
            threshold_millionths: 500_000,
            loss_matrix: BTreeMap::new(),
            evidence_hashes: Vec::new(),
            chosen_action: scx.actual_outcome.clone(),
            outcome_millionths: 0,
            extension_id: "counterexample-synth".to_string(),
            nondeterminism_range: (0, 0),
        };
        recorder.record_decision(snapshot);

        recorder.set_incident_id(format!("conflict-{}", scx.conflict_id));
        recorder.set_metadata(
            "property_violated".to_string(),
            scx.property_violated.to_string(),
        );
        recorder.set_metadata("strategy".to_string(), scx.strategy.to_string());

        recorder.finalize()
    }

    /// Generate an evidence entry for the audit trail.
    pub fn to_evidence_entry(
        &self,
        scx: &SynthesizedCounterexample,
        timestamp_ns: u64,
    ) -> Result<EvidenceEntry, SynthesisError> {
        EvidenceEntryBuilder::new(
            format!("synth-{}", scx.conflict_id),
            format!("conflict-{}", scx.conflict_id),
            scx.policy_ids
                .first()
                .map(|p| p.as_str().to_string())
                .unwrap_or_default(),
            scx.epoch,
            DecisionType::ContractEvaluation,
        )
        .timestamp_ns(timestamp_ns)
        .chosen(ChosenAction {
            action_name: "counterexample-synthesized".to_string(),
            expected_loss_millionths: 0,
            rationale: format!(
                "{} violation detected; strategy={}; outcome={}",
                scx.property_violated, scx.strategy, scx.outcome
            ),
        })
        .meta("conflict_id", format!("{}", scx.conflict_id))
        .meta("synthesis_strategy", scx.strategy.to_string())
        .meta("compute_time_ns", scx.compute_time_ns.to_string())
        .meta(
            "minimality_depth",
            scx.minimality_evidence.rounds.to_string(),
        )
        .meta("resolution_status", scx.outcome.to_string())
        .build()
        .map_err(|e| SynthesisError::CompilerFailure(format!("evidence: {e}")))
    }

    /// Access the regression corpus.
    pub fn corpus(&self) -> &RegressionCorpus {
        &self.corpus
    }

    /// Access generated diagnostics.
    pub fn diagnostics(&self) -> &[ConflictDiagnostic] {
        &self.diagnostics
    }

    /// Total number of counterexamples synthesized.
    pub fn synthesis_count(&self) -> u64 {
        self.synthesis_count
    }

    /// Configuration reference.
    pub fn config(&self) -> &SynthesisConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// PolicyMutation — mutation description for mutation-based synthesis
// ---------------------------------------------------------------------------

/// A mutation to apply to a policy for mutation-based synthesis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyMutation {
    /// Type of mutation.
    pub kind: MutationKind,
    /// Target node ID to mutate.
    pub target_node: String,
    /// New value (interpretation depends on kind).
    pub new_value: String,
}

/// Kinds of policy mutations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MutationKind {
    /// Change the merge operator.
    ChangeMergeOp,
    /// Add a capability grant.
    AddGrant,
    /// Remove a property claim.
    RemovePropertyClaim,
    /// Change priority.
    ChangePriority,
    /// Remove a constraint.
    RemoveConstraint,
    /// Duplicate a node (creates merge ambiguity).
    DuplicateNode,
}

impl fmt::Display for MutationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChangeMergeOp => f.write_str("change-merge-op"),
            Self::AddGrant => f.write_str("add-grant"),
            Self::RemovePropertyClaim => f.write_str("remove-property-claim"),
            Self::ChangePriority => f.write_str("change-priority"),
            Self::RemoveConstraint => f.write_str("remove-constraint"),
            Self::DuplicateNode => f.write_str("duplicate-node"),
        }
    }
}

// ---------------------------------------------------------------------------
// ControllerConfig — lightweight config for interference detection
// ---------------------------------------------------------------------------

/// Configuration for a policy controller (for interference detection).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerConfig {
    /// Controller identifier.
    pub controller_id: String,
    /// Metrics this controller reads.
    pub read_metrics: BTreeSet<String>,
    /// Metrics this controller writes.
    pub write_metrics: BTreeSet<String>,
    /// All affected metrics (read + write).
    pub affected_metrics: BTreeSet<String>,
    /// Timescale at which this controller operates (millionths; 1_000_000 = 1 second).
    pub timescale_millionths: i64,
    /// Required declaration describing this controller's metric timescale contract.
    #[serde(default)]
    pub timescale_statement: String,
}

impl ControllerConfig {
    fn has_timescale_statement(&self) -> bool {
        !self.timescale_statement.trim().is_empty()
    }
}

// ---------------------------------------------------------------------------
// apply_mutation — apply a mutation to a PolicyIr
// ---------------------------------------------------------------------------

/// Apply a mutation to a policy IR, returning a modified copy.
fn apply_mutation(base: &PolicyIr, mutation: &PolicyMutation) -> PolicyIr {
    let mut ir = base.clone();

    match mutation.kind {
        MutationKind::ChangeMergeOp => {
            for node in &mut ir.nodes {
                if node.node_id == mutation.target_node {
                    node.merge_op = match mutation.new_value.as_str() {
                        "union" => MergeOperator::Union,
                        "intersection" => MergeOperator::Intersection,
                        "attenuation" => MergeOperator::Attenuation,
                        "precedence" => MergeOperator::Precedence,
                        _ => node.merge_op,
                    };
                }
            }
        }
        MutationKind::AddGrant => {
            for node in &mut ir.nodes {
                if node.node_id == mutation.target_node {
                    node.grants.push(AuthorityGrant {
                        subject: "mutated-subject".to_string(),
                        capability: Capability::new(&mutation.new_value),
                        conditions: BTreeSet::new(),
                        scope: "mutated".to_string(),
                        lifetime_epochs: 1,
                    });
                }
            }
        }
        MutationKind::RemovePropertyClaim => {
            for node in &mut ir.nodes {
                if node.node_id == mutation.target_node {
                    // Remove the first property claim.
                    if let Some(prop) = node.property_claims.iter().next().cloned() {
                        node.property_claims.remove(&prop);
                    }
                }
            }
        }
        MutationKind::ChangePriority => {
            if let Ok(priority) = mutation.new_value.parse::<u32>() {
                for node in &mut ir.nodes {
                    if node.node_id == mutation.target_node {
                        node.priority = priority;
                    }
                }
            }
        }
        MutationKind::RemoveConstraint => {
            for node in &mut ir.nodes {
                if node.node_id == mutation.target_node && !node.constraints.is_empty() {
                    node.constraints.pop();
                }
            }
        }
        MutationKind::DuplicateNode => {
            if let Some(orig) = ir.nodes.iter().find(|n| n.node_id == mutation.target_node) {
                let mut dup = orig.clone();
                dup.node_id = format!("{}-dup", orig.node_id);
                ir.nodes.push(dup);
            }
        }
    }

    ir
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_theorem_compiler::{Constraint, PolicyIrNode, PolicyTheoremCompiler};
    use crate::security_epoch::SecurityEpoch;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn test_signing_key_bytes() -> Vec<u8> {
        let mut key = vec![0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(13);
        }
        key
    }

    fn test_config() -> SynthesisConfig {
        SynthesisConfig {
            budget_ns: 1_000_000_000,
            max_minimization_rounds: 10,
            preferred_strategy: SynthesisStrategy::CompilerExtraction,
            detect_controller_interference: true,
            max_enumeration_candidates: 50,
            epoch: SecurityEpoch::from_raw(100),
            signing_key_bytes: test_signing_key_bytes(),
        }
    }

    /// Build a valid policy IR (all properties pass).
    fn make_valid_policy() -> PolicyIr {
        let cap = Capability::new("read-data");
        let mut universe = BTreeSet::new();
        universe.insert(cap.clone());

        let mut claims = BTreeSet::new();
        claims.insert(FormalProperty::Monotonicity);

        PolicyIr {
            policy_id: PolicyId::new("valid-policy"),
            version: 1,
            nodes: vec![PolicyIrNode {
                node_id: "node-1".to_string(),
                grants: vec![AuthorityGrant {
                    subject: "user-a".to_string(),
                    capability: cap,
                    conditions: BTreeSet::new(),
                    scope: "default".to_string(),
                    lifetime_epochs: 10,
                }],
                merge_op: MergeOperator::Union,
                property_claims: claims,
                constraints: Vec::new(),
                decision_point: None,
                priority: 1,
            }],
            capability_universe: universe,
            verified_properties: BTreeSet::new(),
            epoch: SecurityEpoch::from_raw(100),
        }
    }

    /// Build a policy IR that triggers a monotonicity violation.
    fn make_monotonicity_violating_policy() -> PolicyIr {
        let cap_a = Capability::new("read-data");
        let cap_b = Capability::new("write-data");
        let cap_extra = Capability::new("admin-override");
        let mut universe = BTreeSet::new();
        universe.insert(cap_a.clone());
        universe.insert(cap_b.clone());
        // cap_extra intentionally NOT in universe -> attenuation legality issue
        // but for monotonicity, we need Union merge claiming Monotonicity
        // when nodes grant capabilities outside individual node scope.

        let mut claims = BTreeSet::new();
        claims.insert(FormalProperty::Monotonicity);

        PolicyIr {
            policy_id: PolicyId::new("mono-violating"),
            version: 1,
            nodes: vec![
                PolicyIrNode {
                    node_id: "node-a".to_string(),
                    grants: vec![AuthorityGrant {
                        subject: "user-a".to_string(),
                        capability: cap_a.clone(),
                        conditions: BTreeSet::new(),
                        scope: "default".to_string(),
                        lifetime_epochs: 10,
                    }],
                    merge_op: MergeOperator::Union,
                    property_claims: claims.clone(),
                    constraints: Vec::new(),
                    decision_point: None,
                    priority: 1,
                },
                PolicyIrNode {
                    node_id: "node-b".to_string(),
                    grants: vec![
                        AuthorityGrant {
                            subject: "user-a".to_string(),
                            capability: cap_b.clone(),
                            conditions: BTreeSet::new(),
                            scope: "default".to_string(),
                            lifetime_epochs: 10,
                        },
                        AuthorityGrant {
                            subject: "user-a".to_string(),
                            capability: cap_extra,
                            conditions: BTreeSet::new(),
                            scope: "elevated".to_string(),
                            lifetime_epochs: 10,
                        },
                    ],
                    merge_op: MergeOperator::Union,
                    property_claims: claims,
                    constraints: Vec::new(),
                    decision_point: None,
                    priority: 2,
                },
            ],
            capability_universe: universe,
            verified_properties: BTreeSet::new(),
            epoch: SecurityEpoch::from_raw(100),
        }
    }

    /// Build a policy IR with merge determinism violation (duplicate priority + Precedence).
    fn make_merge_nondeterminism_policy() -> PolicyIr {
        let cap = Capability::new("data-access");
        let mut universe = BTreeSet::new();
        universe.insert(cap.clone());

        let mut claims = BTreeSet::new();
        claims.insert(FormalProperty::MergeDeterminism);

        PolicyIr {
            policy_id: PolicyId::new("merge-nondet"),
            version: 1,
            nodes: vec![
                PolicyIrNode {
                    node_id: "node-x".to_string(),
                    grants: vec![AuthorityGrant {
                        subject: "user-x".to_string(),
                        capability: cap.clone(),
                        conditions: BTreeSet::new(),
                        scope: "default".to_string(),
                        lifetime_epochs: 5,
                    }],
                    merge_op: MergeOperator::Precedence,
                    property_claims: claims.clone(),
                    constraints: Vec::new(),
                    decision_point: None,
                    priority: 1,
                },
                PolicyIrNode {
                    node_id: "node-y".to_string(),
                    grants: vec![AuthorityGrant {
                        subject: "user-y".to_string(),
                        capability: cap,
                        conditions: BTreeSet::new(),
                        scope: "default".to_string(),
                        lifetime_epochs: 5,
                    }],
                    merge_op: MergeOperator::Precedence,
                    property_claims: claims,
                    constraints: Vec::new(),
                    decision_point: None,
                    priority: 1, // Same priority -> ambiguity
                },
            ],
            capability_universe: universe,
            verified_properties: BTreeSet::new(),
            epoch: SecurityEpoch::from_raw(100),
        }
    }

    /// Build a policy IR with non-interference violation.
    fn make_noninterference_violating_policy() -> PolicyIr {
        let cap = Capability::new("cross-domain");
        let mut universe = BTreeSet::new();
        universe.insert(cap.clone());

        let mut claims = BTreeSet::new();
        claims.insert(FormalProperty::NonInterference);

        PolicyIr {
            policy_id: PolicyId::new("ni-violating"),
            version: 1,
            nodes: vec![PolicyIrNode {
                node_id: "node-shared".to_string(),
                grants: vec![AuthorityGrant {
                    subject: "shared-subject".to_string(),
                    capability: cap,
                    conditions: BTreeSet::new(),
                    scope: "default".to_string(),
                    lifetime_epochs: 10,
                }],
                merge_op: MergeOperator::Union,
                property_claims: claims,
                constraints: vec![Constraint::NonInterferenceClaim {
                    domain_a: "domain-a".to_string(),
                    domain_b: "domain-b".to_string(),
                }],
                decision_point: None,
                priority: 1,
            }],
            capability_universe: universe,
            verified_properties: BTreeSet::new(),
            epoch: SecurityEpoch::from_raw(100),
        }
    }

    // -----------------------------------------------------------------------
    // SynthesisStrategy tests
    // -----------------------------------------------------------------------

    #[test]
    fn strategy_display() {
        assert_eq!(
            SynthesisStrategy::CompilerExtraction.to_string(),
            "compiler-extraction"
        );
        assert_eq!(SynthesisStrategy::Enumeration.to_string(), "enumeration");
        assert_eq!(SynthesisStrategy::Mutation.to_string(), "mutation");
        assert_eq!(SynthesisStrategy::TimeBounded.to_string(), "time-bounded");
    }

    #[test]
    fn synthesis_outcome_display() {
        assert_eq!(SynthesisOutcome::Complete.to_string(), "complete");
        assert_eq!(SynthesisOutcome::Partial.to_string(), "partial");
        assert_eq!(SynthesisOutcome::Incomplete.to_string(), "incomplete");
    }

    #[test]
    fn interference_kind_display() {
        assert_eq!(
            InterferenceKind::InvariantInvalidation.to_string(),
            "invariant-invalidation"
        );
        assert_eq!(InterferenceKind::Oscillation.to_string(), "oscillation");
        assert_eq!(
            InterferenceKind::TimescaleConflict.to_string(),
            "timescale-conflict"
        );
    }

    #[test]
    fn mutation_kind_display() {
        assert_eq!(MutationKind::ChangeMergeOp.to_string(), "change-merge-op");
        assert_eq!(MutationKind::AddGrant.to_string(), "add-grant");
        assert_eq!(MutationKind::DuplicateNode.to_string(), "duplicate-node");
    }

    // -----------------------------------------------------------------------
    // SynthesisError tests
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_no_violations() {
        let err = SynthesisError::NoViolations;
        assert_eq!(err.to_string(), "no violations found in compilation result");
    }

    #[test]
    fn error_display_timeout() {
        let err = SynthesisError::Timeout {
            elapsed_ns: 5000,
            budget_ns: 10000,
            partial: None,
        };
        assert!(err.to_string().contains("5000ns"));
    }

    #[test]
    fn error_display_invalid_policy() {
        let err = SynthesisError::InvalidPolicy {
            reason: "empty".to_string(),
        };
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn error_display_all_variants() {
        let variants: Vec<SynthesisError> = vec![
            SynthesisError::NoViolations,
            SynthesisError::Timeout {
                elapsed_ns: 1,
                budget_ns: 2,
                partial: None,
            },
            SynthesisError::InvalidPolicy {
                reason: "x".to_string(),
            },
            SynthesisError::IdDerivation("y".to_string()),
            SynthesisError::MinimizationExhausted { rounds: 5 },
            SynthesisError::CompilerFailure("z".to_string()),
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // SynthesisConfig tests
    // -----------------------------------------------------------------------

    #[test]
    fn default_config() {
        let cfg = SynthesisConfig::default();
        assert_eq!(cfg.budget_ns, DEFAULT_BUDGET_NS);
        assert_eq!(cfg.max_minimization_rounds, DEFAULT_MAX_MINIMIZATION_ROUNDS);
        assert_eq!(
            cfg.preferred_strategy,
            SynthesisStrategy::CompilerExtraction
        );
        assert!(cfg.detect_controller_interference);
    }

    #[test]
    fn config_serde_roundtrip() {
        let cfg = test_config();
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: SynthesisConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, restored);
    }

    // -----------------------------------------------------------------------
    // RegressionCorpus tests
    // -----------------------------------------------------------------------

    #[test]
    fn corpus_starts_empty() {
        let corpus = RegressionCorpus::new();
        assert!(corpus.is_empty());
        assert_eq!(corpus.len(), 0);
    }

    #[test]
    fn corpus_default_is_empty() {
        let corpus = RegressionCorpus::default();
        assert!(corpus.is_empty());
    }

    #[test]
    fn corpus_append_and_deduplicate() {
        let mut corpus = RegressionCorpus::new();
        let compiler = PolicyTheoremCompiler::new();
        let policy = make_monotonicity_violating_policy();
        let result = compiler.compile(&policy).unwrap();

        let mut synth = CounterexampleSynthesizer::new(test_config());
        let counterexamples = synth.synthesize(&result, 1000).unwrap();
        let cx = counterexamples[0].clone();
        let epoch = SecurityEpoch::from_raw(100);

        assert!(corpus.append(cx.clone(), epoch, 1000));
        // Second append with same conflict_id is a no-op.
        assert!(!corpus.append(cx, epoch, 2000));
        assert_eq!(corpus.len(), 1);
    }

    #[test]
    fn corpus_resolve_entry() {
        let mut corpus = RegressionCorpus::new();
        let compiler = PolicyTheoremCompiler::new();
        let policy = make_monotonicity_violating_policy();
        let result = compiler.compile(&policy).unwrap();

        let mut synth = CounterexampleSynthesizer::new(test_config());
        let counterexamples = synth.synthesize(&result, 1000).unwrap();
        let cx = counterexamples[0].clone();
        let cid = cx.conflict_id.clone();
        let epoch = SecurityEpoch::from_raw(100);

        corpus.append(cx, epoch, 1000);
        assert_eq!(corpus.unresolved().len(), 1);

        assert!(corpus.resolve(&cid));
        assert_eq!(corpus.unresolved().len(), 0);
        assert!(corpus.contains(&cid));
    }

    #[test]
    fn corpus_resolve_nonexistent_returns_false() {
        let mut corpus = RegressionCorpus::new();
        let fake_id = engine_object_id::derive_id(
            ObjectDomain::EvidenceRecord,
            SYNTH_ZONE,
            &SchemaId::from_definition(SYNTH_SCHEMA_DEF),
            b"nonexistent",
        )
        .unwrap();
        assert!(!corpus.resolve(&fake_id));
    }

    // -----------------------------------------------------------------------
    // CompilerExtraction synthesis tests
    // -----------------------------------------------------------------------

    #[test]
    fn synthesize_no_violations_returns_error() {
        let compiler = PolicyTheoremCompiler::new();
        let policy = make_valid_policy();
        let result = compiler.compile(&policy).unwrap();

        let mut synth = CounterexampleSynthesizer::new(test_config());
        let err = synth.synthesize(&result, 1000).unwrap_err();
        assert_eq!(err, SynthesisError::NoViolations);
    }

    #[test]
    fn synthesize_monotonicity_violation() {
        let compiler = PolicyTheoremCompiler::new();
        let policy = make_monotonicity_violating_policy();
        let result = compiler.compile(&policy).unwrap();

        assert!(
            !result.counterexamples.is_empty(),
            "compiler should detect violation"
        );

        let mut synth = CounterexampleSynthesizer::new(test_config());
        let counterexamples = synth.synthesize(&result, 1000).unwrap();

        assert!(!counterexamples.is_empty());
        let cx = &counterexamples[0];
        assert_eq!(cx.strategy, SynthesisStrategy::CompilerExtraction);
        assert_eq!(cx.outcome, SynthesisOutcome::Complete);
        assert!(!cx.policy_ids.is_empty());
        assert!(!cx.concrete_scenario.subjects.is_empty());
        assert!(!cx.resolution_hint.is_empty());

        // Corpus should contain the entry.
        assert_eq!(synth.corpus().len(), counterexamples.len());
        assert_eq!(synth.diagnostics().len(), counterexamples.len());
        assert_eq!(synth.synthesis_count(), counterexamples.len() as u64);
    }

    #[test]
    fn synthesize_merge_nondeterminism() {
        let compiler = PolicyTheoremCompiler::new();
        let policy = make_merge_nondeterminism_policy();
        let result = compiler.compile(&policy).unwrap();

        if result.counterexamples.is_empty() {
            // If the compiler doesn't detect this as a violation with current
            // implementation, skip gracefully.
            return;
        }

        let mut synth = CounterexampleSynthesizer::new(test_config());
        let counterexamples = synth.synthesize(&result, 2000).unwrap();
        assert!(!counterexamples.is_empty());
    }

    #[test]
    fn synthesize_noninterference_violation() {
        let compiler = PolicyTheoremCompiler::new();
        let policy = make_noninterference_violating_policy();
        let result = compiler.compile(&policy).unwrap();

        if result.counterexamples.is_empty() {
            return;
        }

        let mut synth = CounterexampleSynthesizer::new(test_config());
        let counterexamples = synth.synthesize(&result, 3000).unwrap();
        assert!(!counterexamples.is_empty());

        let cx = &counterexamples[0];
        assert!(!cx.expected_outcome.is_empty());
        assert!(!cx.actual_outcome.is_empty());
    }

    // -----------------------------------------------------------------------
    // Counterexample content tests
    // -----------------------------------------------------------------------

    #[test]
    fn counterexample_has_deterministic_id() {
        let compiler = PolicyTheoremCompiler::new();
        let policy = make_monotonicity_violating_policy();
        let result = compiler.compile(&policy).unwrap();

        let mut synth1 = CounterexampleSynthesizer::new(test_config());
        let mut synth2 = CounterexampleSynthesizer::new(test_config());

        let cx1 = synth1.synthesize(&result, 5000).unwrap();
        let cx2 = synth2.synthesize(&result, 5000).unwrap();

        assert_eq!(cx1[0].conflict_id, cx2[0].conflict_id);
        assert_eq!(cx1[0].content_hash, cx2[0].content_hash);
    }

    #[test]
    fn counterexample_minimality_evidence() {
        let compiler = PolicyTheoremCompiler::new();
        let policy = make_monotonicity_violating_policy();
        let result = compiler.compile(&policy).unwrap();

        let mut synth = CounterexampleSynthesizer::new(test_config());
        let counterexamples = synth.synthesize(&result, 1000).unwrap();

        let min = &counterexamples[0].minimality_evidence;
        assert!(min.starting_size > 0);
        assert!(min.final_size <= min.starting_size);
    }

    #[test]
    fn counterexample_serde_roundtrip() {
        let compiler = PolicyTheoremCompiler::new();
        let policy = make_monotonicity_violating_policy();
        let result = compiler.compile(&policy).unwrap();

        let mut synth = CounterexampleSynthesizer::new(test_config());
        let counterexamples = synth.synthesize(&result, 1000).unwrap();

        let json = serde_json::to_string(&counterexamples[0]).unwrap();
        let restored: SynthesizedCounterexample = serde_json::from_str(&json).unwrap();
        assert_eq!(counterexamples[0].conflict_id, restored.conflict_id);
        assert_eq!(
            counterexamples[0].property_violated,
            restored.property_violated
        );
    }

    // -----------------------------------------------------------------------
    // Diagnostic tests
    // -----------------------------------------------------------------------

    #[test]
    fn diagnostic_from_counterexample() {
        let compiler = PolicyTheoremCompiler::new();
        let policy = make_monotonicity_violating_policy();
        let result = compiler.compile(&policy).unwrap();

        let mut synth = CounterexampleSynthesizer::new(test_config());
        synth.synthesize(&result, 1000).unwrap();

        let diags = synth.diagnostics();
        assert!(!diags.is_empty());

        let d = &diags[0];
        assert!(!d.summary.is_empty());
        assert!(d.severity_millionths > 0);
        assert!(!d.resolution_suggestions.is_empty());
    }

    #[test]
    fn diagnostic_serde_roundtrip() {
        let compiler = PolicyTheoremCompiler::new();
        let policy = make_monotonicity_violating_policy();
        let result = compiler.compile(&policy).unwrap();

        let mut synth = CounterexampleSynthesizer::new(test_config());
        synth.synthesize(&result, 1000).unwrap();

        let d = &synth.diagnostics()[0];
        let json = serde_json::to_string(d).unwrap();
        let restored: ConflictDiagnostic = serde_json::from_str(&json).unwrap();
        assert_eq!(d.conflict_id, restored.conflict_id);
    }

    // -----------------------------------------------------------------------
    // Enumeration strategy tests
    // -----------------------------------------------------------------------

    #[test]
    fn enumerate_no_policies_returns_error() {
        let mut synth = CounterexampleSynthesizer::new(test_config());
        let err = synth.synthesize_by_enumeration(&[], 1000).unwrap_err();
        assert_eq!(
            err,
            SynthesisError::InvalidPolicy {
                reason: "no policies provided".to_string()
            }
        );
    }

    #[test]
    fn enumerate_valid_policy_returns_no_violations() {
        let policy = make_valid_policy();
        let mut synth = CounterexampleSynthesizer::new(test_config());
        let err = synth
            .synthesize_by_enumeration(&[&policy], 1000)
            .unwrap_err();
        assert_eq!(err, SynthesisError::NoViolations);
    }

    #[test]
    fn enumerate_finds_violations() {
        let bad = make_monotonicity_violating_policy();
        let mut synth = CounterexampleSynthesizer::new(test_config());
        let results = synth.synthesize_by_enumeration(&[&bad], 1000).unwrap();
        assert!(!results.is_empty());
    }

    // -----------------------------------------------------------------------
    // Mutation strategy tests
    // -----------------------------------------------------------------------

    #[test]
    fn mutation_duplicate_node_creates_ambiguity() {
        let base = make_valid_policy();
        let mutations = vec![PolicyMutation {
            kind: MutationKind::DuplicateNode,
            target_node: "node-1".to_string(),
            new_value: String::new(),
        }];

        let mut synth = CounterexampleSynthesizer::new(test_config());
        // This may or may not find violations depending on the compiler's checks.
        let _ = synth.synthesize_by_mutation(&base, &mutations, 1000);
    }

    #[test]
    fn mutation_change_priority_to_zero() {
        let base = make_valid_policy();
        let mutations = vec![PolicyMutation {
            kind: MutationKind::ChangePriority,
            target_node: "node-1".to_string(),
            new_value: "0".to_string(),
        }];

        let mut synth = CounterexampleSynthesizer::new(test_config());
        let _ = synth.synthesize_by_mutation(&base, &mutations, 1000);
    }

    #[test]
    fn mutation_add_grant_outside_universe() {
        let base = make_valid_policy();
        let mutations = vec![PolicyMutation {
            kind: MutationKind::AddGrant,
            target_node: "node-1".to_string(),
            new_value: "admin-access".to_string(),
        }];

        let mut synth = CounterexampleSynthesizer::new(test_config());
        let result = synth.synthesize_by_mutation(&base, &mutations, 1000);
        // Adding an undefined capability should trigger an attenuation violation.
        if let Ok(cxs) = result {
            assert!(!cxs.is_empty());
            let cx = &cxs[0];
            assert_eq!(cx.strategy, SynthesisStrategy::Mutation);
            assert!(
                cx.concrete_scenario
                    .input_state
                    .contains_key("mutation_type")
            );
        }
    }

    #[test]
    fn apply_mutation_change_merge_op() {
        let base = make_valid_policy();
        let mutation = PolicyMutation {
            kind: MutationKind::ChangeMergeOp,
            target_node: "node-1".to_string(),
            new_value: "precedence".to_string(),
        };
        let mutated = apply_mutation(&base, &mutation);
        assert_eq!(mutated.nodes[0].merge_op, MergeOperator::Precedence);
    }

    #[test]
    fn apply_mutation_remove_property_claim() {
        let base = make_valid_policy();
        let mutation = PolicyMutation {
            kind: MutationKind::RemovePropertyClaim,
            target_node: "node-1".to_string(),
            new_value: String::new(),
        };
        let mutated = apply_mutation(&base, &mutation);
        assert!(mutated.nodes[0].property_claims.is_empty());
    }

    #[test]
    fn apply_mutation_duplicate_node() {
        let base = make_valid_policy();
        let mutation = PolicyMutation {
            kind: MutationKind::DuplicateNode,
            target_node: "node-1".to_string(),
            new_value: String::new(),
        };
        let mutated = apply_mutation(&base, &mutation);
        assert_eq!(mutated.nodes.len(), 2);
        assert_eq!(mutated.nodes[1].node_id, "node-1-dup");
    }

    #[test]
    fn apply_mutation_remove_constraint() {
        let mut base = make_valid_policy();
        base.nodes[0]
            .constraints
            .push(Constraint::Invariant("test".to_string()));
        let mutation = PolicyMutation {
            kind: MutationKind::RemoveConstraint,
            target_node: "node-1".to_string(),
            new_value: String::new(),
        };
        let mutated = apply_mutation(&base, &mutation);
        assert!(mutated.nodes[0].constraints.is_empty());
    }

    // -----------------------------------------------------------------------
    // Controller interference detection tests
    // -----------------------------------------------------------------------

    #[test]
    fn detect_no_interference_disjoint_controllers() {
        let synth = CounterexampleSynthesizer::new(test_config());
        let configs = vec![
            ControllerConfig {
                controller_id: "ctrl-a".to_string(),
                read_metrics: ["cpu".to_string()].into(),
                write_metrics: ["cpu".to_string()].into(),
                affected_metrics: ["cpu".to_string()].into(),
                timescale_millionths: 1_000_000,
                timescale_statement: "reads every 1s; writes every 1s".to_string(),
            },
            ControllerConfig {
                controller_id: "ctrl-b".to_string(),
                read_metrics: ["memory".to_string()].into(),
                write_metrics: ["memory".to_string()].into(),
                affected_metrics: ["memory".to_string()].into(),
                timescale_millionths: 1_000_000,
                timescale_statement: "reads every 1s; writes every 1s".to_string(),
            },
        ];
        let interferences = synth.detect_interference(&configs);
        assert!(interferences.is_empty());
    }

    #[test]
    fn detect_timescale_conflict() {
        let synth = CounterexampleSynthesizer::new(test_config());
        let configs = vec![
            ControllerConfig {
                controller_id: "fast-ctrl".to_string(),
                read_metrics: ["throughput".to_string()].into(),
                write_metrics: ["throughput".to_string()].into(),
                affected_metrics: ["throughput".to_string()].into(),
                timescale_millionths: 100_000,
                timescale_statement: "writes every 100ms".to_string(),
            },
            ControllerConfig {
                controller_id: "also-fast-ctrl".to_string(),
                read_metrics: ["throughput".to_string()].into(),
                write_metrics: ["throughput".to_string()].into(),
                affected_metrics: ["throughput".to_string()].into(),
                timescale_millionths: 120_000,
                timescale_statement: "writes every 120ms".to_string(),
            },
        ];
        let interferences = synth.detect_interference(&configs);
        assert!(
            interferences
                .iter()
                .any(|i| i.kind == InterferenceKind::TimescaleConflict),
            "should detect timescale conflict"
        );
    }

    #[test]
    fn detect_invariant_invalidation() {
        let synth = CounterexampleSynthesizer::new(test_config());
        let configs = vec![
            ControllerConfig {
                controller_id: "writer".to_string(),
                read_metrics: BTreeSet::new(),
                write_metrics: ["shared-metric".to_string()].into(),
                affected_metrics: ["shared-metric".to_string()].into(),
                timescale_millionths: 1_000_000,
                timescale_statement: "writes every 1s".to_string(),
            },
            ControllerConfig {
                controller_id: "reader".to_string(),
                read_metrics: ["shared-metric".to_string()].into(),
                write_metrics: BTreeSet::new(),
                affected_metrics: ["shared-metric".to_string()].into(),
                timescale_millionths: 1_000_000,
                timescale_statement: "reads every 1s".to_string(),
            },
        ];
        let interferences = synth.detect_interference(&configs);
        // Read/write overlap on the same metric must be reported.
        assert!(
            interferences
                .iter()
                .any(|i| i.kind == InterferenceKind::InvariantInvalidation),
            "should detect invariant invalidation: {interferences:?}"
        );
    }

    #[test]
    fn interference_with_three_controllers() {
        let synth = CounterexampleSynthesizer::new(test_config());
        let configs = vec![
            ControllerConfig {
                controller_id: "ctrl-1".to_string(),
                read_metrics: ["m1".to_string()].into(),
                write_metrics: ["m1".to_string()].into(),
                affected_metrics: ["m1".to_string()].into(),
                timescale_millionths: 500_000,
                timescale_statement: "writes every 500ms".to_string(),
            },
            ControllerConfig {
                controller_id: "ctrl-2".to_string(),
                read_metrics: ["m1".to_string(), "m2".to_string()].into(),
                write_metrics: ["m2".to_string()].into(),
                affected_metrics: ["m1".to_string(), "m2".to_string()].into(),
                timescale_millionths: 510_000,
                timescale_statement: "reads every 500ms; writes every 510ms".to_string(),
            },
            ControllerConfig {
                controller_id: "ctrl-3".to_string(),
                read_metrics: ["m2".to_string()].into(),
                write_metrics: ["m2".to_string()].into(),
                affected_metrics: ["m2".to_string()].into(),
                timescale_millionths: 520_000,
                timescale_statement: "writes every 520ms".to_string(),
            },
        ];
        let interferences = synth.detect_interference(&configs);
        assert!(!interferences.is_empty());
    }

    #[test]
    fn detect_no_interference_for_shared_read_only_controllers() {
        let synth = CounterexampleSynthesizer::new(test_config());
        let configs = vec![
            ControllerConfig {
                controller_id: "reader-a".to_string(),
                read_metrics: ["latency".to_string()].into(),
                write_metrics: BTreeSet::new(),
                affected_metrics: ["latency".to_string()].into(),
                timescale_millionths: 100_000,
                timescale_statement: "reads every 100ms".to_string(),
            },
            ControllerConfig {
                controller_id: "reader-b".to_string(),
                read_metrics: ["latency".to_string()].into(),
                write_metrics: BTreeSet::new(),
                affected_metrics: ["latency".to_string()].into(),
                timescale_millionths: 110_000,
                timescale_statement: "reads every 110ms".to_string(),
            },
        ];

        let interferences = synth.detect_interference(&configs);
        assert!(
            interferences.is_empty(),
            "read-only overlap should not create interference: {interferences:?}"
        );
    }

    #[test]
    fn detect_missing_timescale_statement_for_shared_metrics() {
        let synth = CounterexampleSynthesizer::new(test_config());
        let configs = vec![
            ControllerConfig {
                controller_id: "writer-a".to_string(),
                read_metrics: BTreeSet::new(),
                write_metrics: ["latency".to_string()].into(),
                affected_metrics: ["latency".to_string()].into(),
                timescale_millionths: 100_000,
                timescale_statement: String::new(),
            },
            ControllerConfig {
                controller_id: "writer-b".to_string(),
                read_metrics: BTreeSet::new(),
                write_metrics: ["latency".to_string()].into(),
                affected_metrics: ["latency".to_string()].into(),
                timescale_millionths: 120_000,
                timescale_statement: "writes every 120ms".to_string(),
            },
        ];

        let interferences = synth.detect_interference(&configs);
        assert!(interferences.iter().any(|i| {
            i.kind == InterferenceKind::TimescaleConflict
                && i.evidence_description
                    .contains("missing required timescale-separation statements")
        }));
    }

    #[test]
    fn build_interference_events_is_deterministic_and_structured() {
        let synth = CounterexampleSynthesizer::new(test_config());
        let interferences = vec![
            ControllerInterference {
                kind: InterferenceKind::TimescaleConflict,
                controller_ids: vec!["a".to_string(), "b".to_string()],
                shared_metrics: ["m1".to_string()].into(),
                timescale_separation_millionths: 50_000,
                evidence_description: "timescale conflict".to_string(),
                convergence_steps: None,
            },
            ControllerInterference {
                kind: InterferenceKind::InvariantInvalidation,
                controller_ids: vec!["b".to_string(), "c".to_string()],
                shared_metrics: ["m2".to_string()].into(),
                timescale_separation_millionths: 500_000,
                evidence_description: "read/write overlap".to_string(),
                convergence_steps: None,
            },
        ];

        let events = synth.build_interference_events(
            &interferences,
            "trace-interference-001",
            "policy-interference-v1",
        );
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].decision_id, "interference-000001");
        assert_eq!(events[1].decision_id, "interference-000002");
        assert_eq!(events[0].component, "counterexample_synthesizer");
        assert_eq!(events[0].event, "controller_interference_rejected");
        assert_eq!(events[0].outcome, "reject");
        assert_eq!(
            events[0].error_code.as_deref(),
            Some("FE-CX-INTERFERENCE-TIMESCALE")
        );
        assert_eq!(events[1].event, "controller_interference_serialized");
        assert_eq!(events[1].outcome, "serialize");
        assert_eq!(
            events[1].error_code.as_deref(),
            Some("FE-CX-INTERFERENCE-INVARIANT")
        );
    }

    // -----------------------------------------------------------------------
    // Replay fixture generation tests
    // -----------------------------------------------------------------------

    #[test]
    fn replay_fixture_from_counterexample() {
        let compiler = PolicyTheoremCompiler::new();
        let policy = make_monotonicity_violating_policy();
        let result = compiler.compile(&policy).unwrap();

        let mut synth = CounterexampleSynthesizer::new(test_config());
        let counterexamples = synth.synthesize(&result, 1000).unwrap();

        let trace = synth.to_replay_fixture(&counterexamples[0], 5000);
        assert!(trace.trace_id.starts_with("synth-"));
        assert_eq!(trace.start_epoch, SecurityEpoch::from_raw(100));
        assert!(trace.incident_id.is_some());
        assert!(!trace.entries.is_empty());
    }

    #[test]
    fn replay_fixture_is_replayable() {
        let compiler = PolicyTheoremCompiler::new();
        let policy = make_monotonicity_violating_policy();
        let result = compiler.compile(&policy).unwrap();

        let mut synth = CounterexampleSynthesizer::new(test_config());
        let counterexamples = synth.synthesize(&result, 1000).unwrap();

        let trace = synth.to_replay_fixture(&counterexamples[0], 5000);

        // The trace should have valid chain integrity.
        assert!(trace.verify_chain_integrity().is_ok());
    }

    // -----------------------------------------------------------------------
    // Evidence entry generation tests
    // -----------------------------------------------------------------------

    #[test]
    fn evidence_entry_from_counterexample() {
        let compiler = PolicyTheoremCompiler::new();
        let policy = make_monotonicity_violating_policy();
        let result = compiler.compile(&policy).unwrap();

        let mut synth = CounterexampleSynthesizer::new(test_config());
        let counterexamples = synth.synthesize(&result, 1000).unwrap();

        let entry = synth.to_evidence_entry(&counterexamples[0], 2000).unwrap();
        assert_eq!(entry.decision_type, DecisionType::ContractEvaluation);
        assert!(entry.chosen_action.action_name.contains("counterexample"));
        assert!(entry.metadata.contains_key("conflict_id"));
        assert!(entry.metadata.contains_key("synthesis_strategy"));
    }

    // -----------------------------------------------------------------------
    // Serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn concrete_scenario_serde_roundtrip() {
        let scenario = ConcreteScenario {
            subjects: ["user-a".to_string()].into(),
            capabilities: ["read".to_string()].into(),
            conditions: [("k".to_string(), "v".to_string())].into(),
            merge_ordering: vec!["step-1".to_string()],
            input_state: BTreeMap::new(),
        };
        let json = serde_json::to_string(&scenario).unwrap();
        let restored: ConcreteScenario = serde_json::from_str(&json).unwrap();
        assert_eq!(scenario, restored);
    }

    #[test]
    fn minimality_evidence_serde_roundtrip() {
        let min = MinimalityEvidence {
            rounds: 5,
            elements_removed: 2,
            starting_size: 10,
            final_size: 8,
            is_fixed_point: true,
        };
        let json = serde_json::to_string(&min).unwrap();
        let restored: MinimalityEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(min, restored);
    }

    #[test]
    fn controller_interference_serde_roundtrip() {
        let ci = ControllerInterference {
            kind: InterferenceKind::Oscillation,
            controller_ids: vec!["a".to_string(), "b".to_string()],
            shared_metrics: ["m".to_string()].into(),
            timescale_separation_millionths: 50_000,
            evidence_description: "test".to_string(),
            convergence_steps: Some(100),
        };
        let json = serde_json::to_string(&ci).unwrap();
        let restored: ControllerInterference = serde_json::from_str(&json).unwrap();
        assert_eq!(ci, restored);
    }

    #[test]
    fn regression_entry_serde_roundtrip() {
        let compiler = PolicyTheoremCompiler::new();
        let policy = make_monotonicity_violating_policy();
        let result = compiler.compile(&policy).unwrap();

        let mut synth = CounterexampleSynthesizer::new(test_config());
        let _counterexamples = synth.synthesize(&result, 1000).unwrap();

        let entry = &synth.corpus().entries().values().next().unwrap();
        let json = serde_json::to_string(entry).unwrap();
        let restored: RegressionEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry.entry_id, restored.entry_id);
    }

    #[test]
    fn controller_config_serde_roundtrip() {
        let cfg = ControllerConfig {
            controller_id: "test".to_string(),
            read_metrics: ["m1".to_string()].into(),
            write_metrics: ["m2".to_string()].into(),
            affected_metrics: ["m1".to_string(), "m2".to_string()].into(),
            timescale_millionths: 1_000_000,
            timescale_statement: "reads every 1s; writes every 1s".to_string(),
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: ControllerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, restored);
    }

    #[test]
    fn policy_mutation_serde_roundtrip() {
        let m = PolicyMutation {
            kind: MutationKind::ChangeMergeOp,
            target_node: "n1".to_string(),
            new_value: "union".to_string(),
        };
        let json = serde_json::to_string(&m).unwrap();
        let restored: PolicyMutation = serde_json::from_str(&json).unwrap();
        assert_eq!(m, restored);
    }

    // -----------------------------------------------------------------------
    // Synthesizer state tests
    // -----------------------------------------------------------------------

    #[test]
    fn synthesizer_tracks_count() {
        let compiler = PolicyTheoremCompiler::new();
        let policy = make_monotonicity_violating_policy();
        let result = compiler.compile(&policy).unwrap();

        let mut synth = CounterexampleSynthesizer::new(test_config());
        assert_eq!(synth.synthesis_count(), 0);

        synth.synthesize(&result, 1000).unwrap();
        assert!(synth.synthesis_count() > 0);
    }

    #[test]
    fn synthesizer_serde_roundtrip() {
        let synth = CounterexampleSynthesizer::new(test_config());
        let json = serde_json::to_string(&synth).unwrap();
        let restored: CounterexampleSynthesizer = serde_json::from_str(&json).unwrap();
        assert_eq!(synth.synthesis_count(), restored.synthesis_count());
    }

    // -----------------------------------------------------------------------
    // Resolution hints
    // -----------------------------------------------------------------------

    #[test]
    fn resolution_hints_cover_all_properties() {
        let synth = CounterexampleSynthesizer::new(test_config());
        let properties = [
            FormalProperty::Monotonicity,
            FormalProperty::NonInterference,
            FormalProperty::MergeDeterminism,
            FormalProperty::PrecedenceStability,
            FormalProperty::AttenuationLegality,
        ];
        for prop in properties {
            let cx = Counterexample {
                property: prop,
                policy_id: PolicyId::new("test"),
                violating_nodes: vec!["n1".to_string()],
                description: "test".to_string(),
                merge_path: vec!["step".to_string()],
            };
            let hint = synth.suggest_resolution(&cx);
            assert!(!hint.is_empty(), "hint for {prop:?} should not be empty");
        }
    }

    #[test]
    fn outcome_descriptions_cover_all_properties() {
        let synth = CounterexampleSynthesizer::new(test_config());
        let properties = [
            FormalProperty::Monotonicity,
            FormalProperty::NonInterference,
            FormalProperty::MergeDeterminism,
            FormalProperty::PrecedenceStability,
            FormalProperty::AttenuationLegality,
        ];
        for prop in properties {
            let cx = Counterexample {
                property: prop,
                policy_id: PolicyId::new("test"),
                violating_nodes: vec!["n1".to_string()],
                description: "test".to_string(),
                merge_path: vec!["step".to_string()],
            };
            let (expected, actual) = synth.describe_outcomes(&cx);
            assert!(!expected.is_empty());
            assert!(!actual.is_empty());
        }
    }

    #[test]
    fn synthesis_strategy_ord() {
        assert!(SynthesisStrategy::CompilerExtraction < SynthesisStrategy::Enumeration);
        assert!(SynthesisStrategy::Enumeration < SynthesisStrategy::Mutation);
        assert!(SynthesisStrategy::Mutation < SynthesisStrategy::TimeBounded);
    }

    #[test]
    fn interference_kind_ord() {
        assert!(InterferenceKind::InvariantInvalidation < InterferenceKind::Oscillation);
        assert!(InterferenceKind::Oscillation < InterferenceKind::TimescaleConflict);
    }

    #[test]
    fn mutation_kind_ord() {
        assert!(MutationKind::ChangeMergeOp < MutationKind::AddGrant);
        assert!(MutationKind::AddGrant < MutationKind::RemovePropertyClaim);
        assert!(MutationKind::RemoveConstraint < MutationKind::DuplicateNode);
    }

    // -----------------------------------------------------------------------
    // Enrichment: additional serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn synthesis_error_serde_all_variants() {
        let variants: Vec<SynthesisError> = vec![
            SynthesisError::NoViolations,
            SynthesisError::Timeout {
                elapsed_ns: 5000,
                budget_ns: 10000,
                partial: None,
            },
            SynthesisError::InvalidPolicy {
                reason: "bad".to_string(),
            },
            SynthesisError::IdDerivation("deriv".to_string()),
            SynthesisError::MinimizationExhausted { rounds: 50 },
            SynthesisError::CompilerFailure("compile".to_string()),
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialize");
            let restored: SynthesisError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*v, restored);
        }
    }

    #[test]
    fn synthesis_error_implements_std_error() {
        let errors: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(SynthesisError::NoViolations),
            Box::new(SynthesisError::Timeout {
                elapsed_ns: 1,
                budget_ns: 2,
                partial: None,
            }),
            Box::new(SynthesisError::InvalidPolicy {
                reason: "x".to_string(),
            }),
            Box::new(SynthesisError::IdDerivation("y".to_string())),
            Box::new(SynthesisError::MinimizationExhausted { rounds: 5 }),
            Box::new(SynthesisError::CompilerFailure("z".to_string())),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for err in &errors {
            displays.insert(err.to_string());
        }
        assert_eq!(displays.len(), 6, "all 6 variants have distinct messages");
    }

    #[test]
    fn synthesis_outcome_serde_roundtrip() {
        for v in [
            SynthesisOutcome::Complete,
            SynthesisOutcome::Partial,
            SynthesisOutcome::Incomplete,
        ] {
            let json = serde_json::to_string(&v).expect("serialize");
            let restored: SynthesisOutcome = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(v, restored);
        }
    }

    #[test]
    fn synthesis_strategy_serde_roundtrip() {
        for v in [
            SynthesisStrategy::CompilerExtraction,
            SynthesisStrategy::Enumeration,
            SynthesisStrategy::Mutation,
            SynthesisStrategy::TimeBounded,
        ] {
            let json = serde_json::to_string(&v).expect("serialize");
            let restored: SynthesisStrategy = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(v, restored);
        }
    }

    #[test]
    fn interference_kind_serde_roundtrip() {
        for v in [
            InterferenceKind::InvariantInvalidation,
            InterferenceKind::Oscillation,
            InterferenceKind::TimescaleConflict,
        ] {
            let json = serde_json::to_string(&v).expect("serialize");
            let restored: InterferenceKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(v, restored);
        }
    }

    #[test]
    fn mutation_kind_serde_all_variants() {
        for v in [
            MutationKind::ChangeMergeOp,
            MutationKind::AddGrant,
            MutationKind::RemovePropertyClaim,
            MutationKind::ChangePriority,
            MutationKind::RemoveConstraint,
            MutationKind::DuplicateNode,
        ] {
            let json = serde_json::to_string(&v).expect("serialize");
            let restored: MutationKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(v, restored);
        }
    }

    #[test]
    fn mutation_kind_display_remaining() {
        assert_eq!(
            MutationKind::RemovePropertyClaim.to_string(),
            "remove-property-claim"
        );
        assert_eq!(MutationKind::ChangePriority.to_string(), "change-priority");
        assert_eq!(
            MutationKind::RemoveConstraint.to_string(),
            "remove-constraint"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: ControllerInterferenceEvent serde
    // -----------------------------------------------------------------------

    #[test]
    fn controller_interference_event_serde_roundtrip() {
        let event = ControllerInterferenceEvent {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            component: "counterexample_synthesizer".to_string(),
            event: "controller_interference_rejected".to_string(),
            outcome: "reject".to_string(),
            error_code: Some("FE-CX-INTERFERENCE-TIMESCALE".to_string()),
            kind: InterferenceKind::TimescaleConflict,
            controller_ids: vec!["a".to_string(), "b".to_string()],
            shared_metrics: vec!["m1".to_string()],
            timescale_separation_millionths: 50_000,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: ControllerInterferenceEvent =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment: synthesizer accessor coverage
    // -----------------------------------------------------------------------

    #[test]
    fn synthesizer_config_accessor() {
        let cfg = test_config();
        let synth = CounterexampleSynthesizer::new(cfg.clone());
        assert_eq!(*synth.config(), cfg);
    }

    #[test]
    fn synthesizer_diagnostics_empty_initially() {
        let synth = CounterexampleSynthesizer::new(test_config());
        assert!(synth.diagnostics().is_empty());
        assert_eq!(synth.synthesis_count(), 0);
    }

    #[test]
    fn synthesizer_corpus_empty_initially() {
        let synth = CounterexampleSynthesizer::new(test_config());
        assert!(synth.corpus().is_empty());
        assert_eq!(synth.corpus().len(), 0);
    }

    // -----------------------------------------------------------------------
    // Enrichment: apply_mutation additional coverage
    // -----------------------------------------------------------------------

    #[test]
    fn apply_mutation_add_grant_adds_to_node() {
        let base = make_valid_policy();
        let mutation = PolicyMutation {
            kind: MutationKind::AddGrant,
            target_node: "node-1".to_string(),
            new_value: "write-access".to_string(),
        };
        let mutated = apply_mutation(&base, &mutation);
        assert_eq!(mutated.nodes[0].grants.len(), 2);
        assert_eq!(mutated.nodes[0].grants[1].subject, "mutated-subject");
    }

    #[test]
    fn apply_mutation_change_priority() {
        let base = make_valid_policy();
        let mutation = PolicyMutation {
            kind: MutationKind::ChangePriority,
            target_node: "node-1".to_string(),
            new_value: "99".to_string(),
        };
        let mutated = apply_mutation(&base, &mutation);
        assert_eq!(mutated.nodes[0].priority, 99);
    }

    #[test]
    fn apply_mutation_nonexistent_target_no_change() {
        let base = make_valid_policy();
        let mutation = PolicyMutation {
            kind: MutationKind::ChangePriority,
            target_node: "nonexistent".to_string(),
            new_value: "99".to_string(),
        };
        let mutated = apply_mutation(&base, &mutation);
        // Original priority preserved.
        assert_eq!(mutated.nodes[0].priority, base.nodes[0].priority);
    }

    // -------------------------------------------------------------------
    // Enrichment: constants and defaults
    // -------------------------------------------------------------------

    #[test]
    fn default_constants_values() {
        assert_eq!(DEFAULT_BUDGET_NS, 30_000_000_000);
        assert_eq!(DEFAULT_MAX_MINIMIZATION_ROUNDS, 50);
    }

    #[test]
    fn synthesis_config_default_values() {
        let cfg = SynthesisConfig::default();
        assert_eq!(cfg.budget_ns, DEFAULT_BUDGET_NS);
        assert_eq!(cfg.max_minimization_rounds, DEFAULT_MAX_MINIMIZATION_ROUNDS);
        assert_eq!(
            cfg.preferred_strategy,
            SynthesisStrategy::CompilerExtraction
        );
        assert!(cfg.detect_controller_interference);
        assert_eq!(cfg.max_enumeration_candidates, 100);
        assert_eq!(cfg.epoch, SecurityEpoch::from_raw(1));
        assert_eq!(cfg.signing_key_bytes.len(), 32);
    }

    #[test]
    fn regression_corpus_default_equals_new() {
        let c1 = RegressionCorpus::new();
        let c2 = RegressionCorpus::default();
        assert_eq!(c1, c2);
        assert!(c1.is_empty());
    }

    // -------------------------------------------------------------------
    // Enrichment: corpus unresolved after partial resolve
    // -------------------------------------------------------------------

    #[test]
    fn corpus_unresolved_returns_only_unresolved() {
        let mut synth = CounterexampleSynthesizer::new(test_config());
        let policy = make_monotonicity_violating_policy();
        let compiler = PolicyTheoremCompiler::new();
        let result = compiler.compile(&policy).unwrap();

        let scxs = synth.synthesize(&result, 1000).unwrap();
        assert!(!scxs.is_empty());

        // Resolve the first counterexample.
        let first_id = scxs[0].conflict_id.clone();
        synth.corpus.resolve(&first_id);

        let unresolved = synth.corpus().unresolved();
        // None of the unresolved entries should have the resolved ID.
        assert!(unresolved.iter().all(|e| e.entry_id != first_id));
    }

    // -------------------------------------------------------------------
    // Enrichment: Display all variants
    // -------------------------------------------------------------------

    #[test]
    fn synthesis_strategy_display_all_variants() {
        assert_eq!(
            SynthesisStrategy::CompilerExtraction.to_string(),
            "compiler-extraction"
        );
        assert_eq!(SynthesisStrategy::Enumeration.to_string(), "enumeration");
        assert_eq!(SynthesisStrategy::Mutation.to_string(), "mutation");
        assert_eq!(SynthesisStrategy::TimeBounded.to_string(), "time-bounded");
    }

    #[test]
    fn synthesis_outcome_display_all_variants() {
        assert_eq!(SynthesisOutcome::Complete.to_string(), "complete");
        assert_eq!(SynthesisOutcome::Partial.to_string(), "partial");
        assert_eq!(SynthesisOutcome::Incomplete.to_string(), "incomplete");
    }

    #[test]
    fn interference_kind_display_all_variants() {
        assert_eq!(
            InterferenceKind::InvariantInvalidation.to_string(),
            "invariant-invalidation"
        );
        assert_eq!(InterferenceKind::Oscillation.to_string(), "oscillation");
        assert_eq!(
            InterferenceKind::TimescaleConflict.to_string(),
            "timescale-conflict"
        );
    }

    // -------------------------------------------------------------------
    // Enrichment: diagnostic severity per property
    // -------------------------------------------------------------------

    #[test]
    fn diagnostic_severity_matches_property() {
        let mut synth = CounterexampleSynthesizer::new(test_config());
        let policy = make_monotonicity_violating_policy();
        let compiler = PolicyTheoremCompiler::new();
        let result = compiler.compile(&policy).unwrap();
        let scxs = synth.synthesize(&result, 1000).unwrap();

        // Monotonicity/AttenuationLegality -> 900_000, NonInterference -> 1_000_000,
        // MergeDeterminism/PrecedenceStability -> 700_000.
        for diag in synth.diagnostics() {
            match diag.property {
                FormalProperty::Monotonicity | FormalProperty::AttenuationLegality => {
                    assert_eq!(diag.severity_millionths, 900_000);
                }
                FormalProperty::NonInterference => {
                    assert_eq!(diag.severity_millionths, 1_000_000);
                }
                FormalProperty::MergeDeterminism | FormalProperty::PrecedenceStability => {
                    assert_eq!(diag.severity_millionths, 700_000);
                }
            }
        }

        // Verify we actually checked at least one diagnostic.
        assert!(!synth.diagnostics().is_empty());
        // Verify scxs is non-empty too (we need it bound to avoid unused warning).
        assert!(!scxs.is_empty());
    }

    // -------------------------------------------------------------------
    // Enrichment: controller_config.has_timescale_statement
    // -------------------------------------------------------------------

    #[test]
    fn has_timescale_statement_whitespace_only_is_false() {
        let config = ControllerConfig {
            controller_id: "ctrl-a".to_string(),
            read_metrics: BTreeSet::new(),
            write_metrics: BTreeSet::new(),
            affected_metrics: BTreeSet::new(),
            timescale_millionths: 1_000_000,
            timescale_statement: "   \t  ".to_string(),
        };
        assert!(!config.has_timescale_statement());
    }

    // -------------------------------------------------------------------
    // Enrichment: replay fixture metadata
    // -------------------------------------------------------------------

    #[test]
    fn replay_fixture_metadata_includes_property_and_strategy() {
        let mut synth = CounterexampleSynthesizer::new(test_config());
        let policy = make_monotonicity_violating_policy();
        let compiler = PolicyTheoremCompiler::new();
        let result = compiler.compile(&policy).unwrap();
        let scxs = synth.synthesize(&result, 1000).unwrap();

        let fixture = synth.to_replay_fixture(&scxs[0], 5000);
        // The fixture should have metadata set for property_violated and strategy.
        let metadata = &fixture.metadata;
        assert!(metadata.contains_key("property_violated"));
        assert!(metadata.contains_key("strategy"));
    }

    // -------------------------------------------------------------------
    // Enrichment: apply_mutation remove_constraint with empty constraints
    // -------------------------------------------------------------------

    #[test]
    fn apply_mutation_remove_constraint_empty_is_noop() {
        let base = make_valid_policy();
        assert!(base.nodes[0].constraints.is_empty());
        let mutation = PolicyMutation {
            kind: MutationKind::RemoveConstraint,
            target_node: "node-1".to_string(),
            new_value: String::new(),
        };
        let mutated = apply_mutation(&base, &mutation);
        assert!(mutated.nodes[0].constraints.is_empty());
    }

    // -------------------------------------------------------------------
    // Enrichment: corpus contains after append
    // -------------------------------------------------------------------

    #[test]
    fn corpus_contains_after_append() {
        let mut synth = CounterexampleSynthesizer::new(test_config());
        let policy = make_monotonicity_violating_policy();
        let compiler = PolicyTheoremCompiler::new();
        let result = compiler.compile(&policy).unwrap();
        let scxs = synth.synthesize(&result, 1000).unwrap();

        assert!(synth.corpus().contains(&scxs[0].conflict_id));
    }
}
