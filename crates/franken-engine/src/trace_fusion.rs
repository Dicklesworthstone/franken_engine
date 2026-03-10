//! Proof-guided trace fusion and superinstructions for policy-legal motifs.
//!
//! This module fuses repeated policy-legal hostcall and effect motifs into
//! trace/superinstruction paths with deterministic side-exit behavior, explicit
//! proof lineage, and supportable disable semantics.
//!
//! Builds on:
//! - [`capability_pruned_dispatch`]: capability proofs and IFC flow evidence
//! - [`superblock_formation`]: superblock and trace tree infrastructure
//! - [`quickening_feedback_lattice`]: type feedback and quickening levels
//! - [`versioned_rewrite_pack`]: rewrite rules and cost models

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Schema version for trace-fusion artifacts.
pub const TRACE_FUSION_SCHEMA_VERSION: &str = "franken-engine.trace-fusion.v1";

// ---------------------------------------------------------------------------
// Motif classification
// ---------------------------------------------------------------------------

/// Kind of repeatable instruction motif eligible for fusion.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MotifKind {
    /// Consecutive hostcall invocations that share a capability envelope.
    HostcallSequence,
    /// Linear arithmetic chain (add, sub, mul, etc.) with no side effects.
    ArithmeticChain,
    /// Property-load chain on a stable shape (obj.a.b.c).
    PropertyChain,
    /// Guard-elided region authorized by capability proofs.
    GuardElidedRegion,
    /// Comparison-and-branch idiom (cmp + conditional jump).
    ComparisonBranch,
    /// Allocation + initialization sequence (NewObject + SetProperty*).
    AllocationInit,
    /// String concatenation / template literal fusion.
    StringConcat,
    /// Loop-invariant code motion candidate.
    LoopInvariant,
}

impl MotifKind {
    /// Minimum instruction count for this motif kind to be fusible.
    pub fn min_instructions(&self) -> usize {
        match self {
            Self::HostcallSequence => 2,
            Self::ArithmeticChain => 3,
            Self::PropertyChain => 2,
            Self::GuardElidedRegion => 2,
            Self::ComparisonBranch => 2,
            Self::AllocationInit => 2,
            Self::StringConcat => 2,
            Self::LoopInvariant => 1,
        }
    }
}

// ---------------------------------------------------------------------------
// Motif matching
// ---------------------------------------------------------------------------

/// A recognized pattern of instructions that can be fused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FusionMotif {
    /// Content-addressed motif identifier.
    pub motif_id: String,
    /// Kind of motif.
    pub kind: MotifKind,
    /// Opcode sequence that defines this motif.
    pub opcode_pattern: Vec<String>,
    /// Bytecode offset of the first instruction in the source.
    pub start_offset: u32,
    /// Bytecode offset of the last instruction in the source.
    pub end_offset: u32,
    /// Number of times this motif was observed in profiling traces.
    pub observation_count: u64,
    /// Minimum type stability (millionths) observed for operands.
    pub min_stability_millionths: u64,
    /// Whether all instructions in the motif are side-effect free.
    pub side_effect_free: bool,
    /// Capabilities required for this motif (if hostcall-related).
    pub required_capabilities: BTreeSet<String>,
}

impl FusionMotif {
    /// Create a new motif.
    pub fn new(kind: MotifKind, opcodes: Vec<String>, start: u32, end: u32) -> Self {
        let pattern_bytes = opcodes.join(",");
        let hash = ContentHash::compute(pattern_bytes.as_bytes());
        let motif_id = format!("motif-{}", &hash.to_hex()[..16]);
        Self {
            motif_id,
            kind,
            opcode_pattern: opcodes,
            start_offset: start,
            end_offset: end,
            observation_count: 0,
            min_stability_millionths: 0,
            side_effect_free: true,
            required_capabilities: BTreeSet::new(),
        }
    }

    /// Record an observation of this motif.
    pub fn record_observation(&mut self) {
        self.observation_count += 1;
    }

    /// Mark this motif as having side effects.
    pub fn mark_effectful(&mut self) {
        self.side_effect_free = false;
    }

    /// Add a required capability.
    pub fn require_capability(&mut self, cap: &str) {
        self.required_capabilities.insert(cap.to_string());
    }

    /// Instruction count in this motif.
    pub fn instruction_count(&self) -> usize {
        self.opcode_pattern.len()
    }

    /// Whether this motif meets the minimum instruction count for its kind.
    pub fn meets_minimum(&self) -> bool {
        self.instruction_count() >= self.kind.min_instructions()
    }

    /// Content hash of this motif for deterministic identity.
    pub fn content_hash(&self) -> ContentHash {
        let mut data = Vec::new();
        data.extend_from_slice(format!("{:?}", self.kind).as_bytes());
        for op in &self.opcode_pattern {
            data.extend_from_slice(op.as_bytes());
            data.push(b'|');
        }
        data.extend_from_slice(&self.start_offset.to_le_bytes());
        data.extend_from_slice(&self.end_offset.to_le_bytes());
        ContentHash::compute(&data)
    }
}

// ---------------------------------------------------------------------------
// Proof lineage
// ---------------------------------------------------------------------------

/// Evidence that authorizes a specific fusion decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FusionProofLineage {
    /// Unique lineage identifier.
    pub lineage_id: String,
    /// Capability proof IDs that authorize this fusion.
    pub capability_proof_ids: Vec<String>,
    /// IFC flow proof IDs that authorize effect elision.
    pub flow_proof_ids: Vec<String>,
    /// Security epoch when this lineage was established.
    pub epoch: SecurityEpoch,
    /// Content hash of the combined evidence.
    pub evidence_hash: ContentHash,
    /// Whether all proofs are still active (not revoked).
    pub all_proofs_active: bool,
}

impl FusionProofLineage {
    /// Create a new proof lineage.
    pub fn new(
        capability_proofs: Vec<String>,
        flow_proofs: Vec<String>,
        epoch: SecurityEpoch,
    ) -> Self {
        let mut data = Vec::new();
        for p in &capability_proofs {
            data.extend_from_slice(p.as_bytes());
            data.push(b'|');
        }
        data.push(b'#');
        for p in &flow_proofs {
            data.extend_from_slice(p.as_bytes());
            data.push(b'|');
        }
        data.extend_from_slice(&epoch.as_u64().to_le_bytes());
        let evidence_hash = ContentHash::compute(&data);
        let lineage_id = format!("lineage-{}", &evidence_hash.to_hex()[..16]);
        Self {
            lineage_id,
            capability_proof_ids: capability_proofs,
            flow_proof_ids: flow_proofs,
            epoch,
            evidence_hash,
            all_proofs_active: true,
        }
    }

    /// Invalidate this lineage (e.g., when a proof is revoked).
    pub fn invalidate(&mut self) {
        self.all_proofs_active = false;
    }

    /// Whether this lineage is valid for the given epoch.
    pub fn is_valid_at(&self, epoch: SecurityEpoch) -> bool {
        self.all_proofs_active && self.epoch.as_u64() <= epoch.as_u64()
    }

    /// Total proof count.
    pub fn proof_count(&self) -> usize {
        self.capability_proof_ids.len() + self.flow_proof_ids.len()
    }
}

// ---------------------------------------------------------------------------
// Fused instruction
// ---------------------------------------------------------------------------

/// A single instruction within a fused trace, potentially a superinstruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FusedInstruction {
    /// Position within the fused trace.
    pub position: u32,
    /// Original bytecode offsets that were fused into this instruction.
    pub source_offsets: Vec<u32>,
    /// Opcode name of the superinstruction (or original opcode if unfused).
    pub opcode: String,
    /// Whether this is a fused superinstruction (vs. a pass-through).
    pub is_super: bool,
    /// Cost in millionths (from deterministic cost model).
    pub cost_millionths: i64,
    /// Guard required before this instruction (if any).
    pub guard: Option<FusionGuard>,
}

impl FusedInstruction {
    /// Create a pass-through (unfused) instruction.
    pub fn passthrough(position: u32, source_offset: u32, opcode: &str) -> Self {
        Self {
            position,
            source_offsets: vec![source_offset],
            opcode: opcode.to_string(),
            is_super: false,
            cost_millionths: 0,
            guard: None,
        }
    }

    /// Create a superinstruction from fused source offsets.
    pub fn super_instruction(
        position: u32,
        source_offsets: Vec<u32>,
        opcode: &str,
        cost_millionths: i64,
    ) -> Self {
        Self {
            position,
            source_offsets,
            opcode: opcode.to_string(),
            is_super: true,
            cost_millionths,
            guard: None,
        }
    }

    /// Attach a guard to this instruction.
    pub fn with_guard(mut self, guard: FusionGuard) -> Self {
        self.guard = Some(guard);
        self
    }

    /// How many source instructions were fused.
    pub fn fusion_factor(&self) -> usize {
        self.source_offsets.len()
    }
}

// ---------------------------------------------------------------------------
// Guards
// ---------------------------------------------------------------------------

/// Guard protecting a fused instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FusionGuard {
    /// Guard identifier.
    pub guard_id: String,
    /// Kind of guard.
    pub kind: FusionGuardKind,
    /// Side-exit target on guard failure.
    pub side_exit_offset: u32,
    /// Whether this guard has been factored with other guards.
    pub factored: bool,
}

/// Kind of guard on a fused instruction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FusionGuardKind {
    /// Type stability check.
    TypeStability { expected_type: String },
    /// Shape check for property chains.
    ShapeCheck { expected_shape_id: String },
    /// Capability validity check.
    CapabilityValid { capability_name: String },
    /// Monotone level check (quickening level hasn't regressed).
    LevelCheck { min_level: u32 },
    /// Proof-lineage validity check.
    ProofValid { lineage_id: String },
}

impl FusionGuard {
    /// Create a new guard.
    pub fn new(kind: FusionGuardKind, side_exit_offset: u32) -> Self {
        let kind_bytes = format!("{kind:?}");
        let hash = ContentHash::compute(kind_bytes.as_bytes());
        Self {
            guard_id: format!("fg-{}", &hash.to_hex()[..12]),
            kind,
            side_exit_offset,
            factored: false,
        }
    }

    /// Mark this guard as factored.
    pub fn mark_factored(&mut self) {
        self.factored = true;
    }
}

// ---------------------------------------------------------------------------
// Fused trace
// ---------------------------------------------------------------------------

/// A fused trace: a superinstruction path produced by trace fusion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FusedTrace {
    /// Content-addressed trace identifier.
    pub trace_id: String,
    /// Schema version.
    pub schema_version: String,
    /// Function this trace belongs to.
    pub function_id: String,
    /// Superblock ID this was derived from (if any).
    pub source_superblock_id: Option<String>,
    /// Fused instructions in execution order.
    pub instructions: Vec<FusedInstruction>,
    /// Motifs that were recognized and fused.
    pub fused_motifs: Vec<String>,
    /// Proof lineage authorizing this fusion.
    pub proof_lineage: Option<FusionProofLineage>,
    /// Whether this trace is currently enabled.
    pub enabled: bool,
    /// Epoch when this trace was formed.
    pub formation_epoch: SecurityEpoch,
    /// Total cost savings in millionths.
    pub cost_savings_millionths: i64,
    /// Reason this trace was disabled (if applicable).
    pub disable_reason: Option<FusionDisableReason>,
    /// Execution count since formation.
    pub execution_count: u64,
    /// Side-exit count since formation.
    pub side_exit_count: u64,
}

impl FusedTrace {
    /// Create a new fused trace.
    pub fn new(function_id: &str, epoch: SecurityEpoch) -> Self {
        let hash = ContentHash::compute(format!("{function_id}:{}", epoch.as_u64()).as_bytes());
        Self {
            trace_id: format!("ft-{}", &hash.to_hex()[..16]),
            schema_version: TRACE_FUSION_SCHEMA_VERSION.to_string(),
            function_id: function_id.to_string(),
            source_superblock_id: None,
            instructions: Vec::new(),
            fused_motifs: Vec::new(),
            proof_lineage: None,
            enabled: true,
            formation_epoch: epoch,
            cost_savings_millionths: 0,
            disable_reason: None,
            execution_count: 0,
            side_exit_count: 0,
        }
    }

    /// Set the source superblock.
    pub fn with_superblock(mut self, superblock_id: &str) -> Self {
        self.source_superblock_id = Some(superblock_id.to_string());
        self
    }

    /// Add a fused instruction.
    pub fn add_instruction(&mut self, instr: FusedInstruction) {
        self.instructions.push(instr);
    }

    /// Record a motif that was fused.
    pub fn record_fused_motif(&mut self, motif_id: &str) {
        self.fused_motifs.push(motif_id.to_string());
    }

    /// Set proof lineage.
    pub fn set_proof_lineage(&mut self, lineage: FusionProofLineage) {
        self.proof_lineage = Some(lineage);
    }

    /// Disable this trace with a reason.
    pub fn disable(&mut self, reason: FusionDisableReason) {
        self.enabled = false;
        self.disable_reason = Some(reason);
    }

    /// Re-enable this trace (clears disable reason).
    pub fn enable(&mut self) {
        self.enabled = true;
        self.disable_reason = None;
    }

    /// Record an execution.
    pub fn record_execution(&mut self) {
        self.execution_count += 1;
    }

    /// Record a side exit.
    pub fn record_side_exit(&mut self) {
        self.side_exit_count += 1;
    }

    /// Total instruction count.
    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    /// Number of superinstructions (fused).
    pub fn super_instruction_count(&self) -> usize {
        self.instructions.iter().filter(|i| i.is_super).count()
    }

    /// Total source instructions covered by superinstructions.
    pub fn fused_source_count(&self) -> usize {
        self.instructions
            .iter()
            .filter(|i| i.is_super)
            .map(|i| i.fusion_factor())
            .sum()
    }

    /// Guard count.
    pub fn guard_count(&self) -> usize {
        self.instructions
            .iter()
            .filter(|i| i.guard.is_some())
            .count()
    }

    /// Side-exit ratio in millionths (exits / executions).
    pub fn side_exit_ratio_millionths(&self) -> u64 {
        if self.execution_count == 0 {
            return 0;
        }
        self.side_exit_count
            .saturating_mul(1_000_000)
            .checked_div(self.execution_count)
            .unwrap_or(0)
    }

    /// Whether this trace has degraded (high side-exit ratio).
    pub fn is_degraded(&self, max_exit_ratio_millionths: u64) -> bool {
        self.execution_count > 0 && self.side_exit_ratio_millionths() > max_exit_ratio_millionths
    }

    /// Content hash of this trace for deterministic identity.
    pub fn content_hash(&self) -> ContentHash {
        let mut data = Vec::new();
        data.extend_from_slice(self.function_id.as_bytes());
        data.push(b'|');
        for instr in &self.instructions {
            data.extend_from_slice(instr.opcode.as_bytes());
            data.push(b':');
            for off in &instr.source_offsets {
                data.extend_from_slice(&off.to_le_bytes());
            }
            data.push(b'|');
        }
        data.extend_from_slice(&self.formation_epoch.as_u64().to_le_bytes());
        ContentHash::compute(&data)
    }

    /// Produce a diagnostics summary.
    pub fn summary(&self) -> FusedTraceSummary {
        FusedTraceSummary {
            trace_id: self.trace_id.clone(),
            function_id: self.function_id.clone(),
            instruction_count: self.instruction_count() as u32,
            super_instruction_count: self.super_instruction_count() as u32,
            fused_source_count: self.fused_source_count() as u32,
            guard_count: self.guard_count() as u32,
            motif_count: self.fused_motifs.len() as u32,
            enabled: self.enabled,
            cost_savings_millionths: self.cost_savings_millionths,
            execution_count: self.execution_count,
            side_exit_ratio_millionths: self.side_exit_ratio_millionths(),
        }
    }
}

/// Diagnostics summary for a fused trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FusedTraceSummary {
    pub trace_id: String,
    pub function_id: String,
    pub instruction_count: u32,
    pub super_instruction_count: u32,
    pub fused_source_count: u32,
    pub guard_count: u32,
    pub motif_count: u32,
    pub enabled: bool,
    pub cost_savings_millionths: i64,
    pub execution_count: u64,
    pub side_exit_ratio_millionths: u64,
}

// ---------------------------------------------------------------------------
// Disable semantics
// ---------------------------------------------------------------------------

/// Why a fused trace was disabled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FusionDisableReason {
    /// Proof lineage was invalidated (capability revoked or IFC flow broken).
    ProofInvalidated { lineage_id: String },
    /// Side-exit ratio exceeded threshold.
    ExcessiveSideExits {
        ratio_millionths: u64,
        threshold_millionths: u64,
    },
    /// Security epoch advanced past formation epoch.
    EpochAdvanced { formation: u64, current: u64 },
    /// Operator manually disabled this trace.
    OperatorDisabled { reason: String },
    /// Underlying superblock was invalidated.
    SuperblockInvalidated { superblock_id: String },
    /// Shape or type assumption changed.
    TypeAssumptionBroken { detail: String },
    /// Cost model showed negative net gain after accounting for guards.
    NegativeNetGain { net_gain_millionths: i64 },
    /// Interference with another active fusion.
    InterferenceDetected { other_trace_id: String },
}

// ---------------------------------------------------------------------------
// Fusion policy
// ---------------------------------------------------------------------------

/// Policy governing trace fusion decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FusionPolicy {
    /// Minimum observation count for a motif to be fusible.
    pub min_observation_count: u64,
    /// Minimum type stability in millionths for fusion.
    pub min_type_stability_millionths: u64,
    /// Maximum number of fused instructions per trace.
    pub max_fused_instructions: usize,
    /// Maximum number of superinstructions per trace.
    pub max_super_instructions: usize,
    /// Maximum number of guards per trace.
    pub max_guards: usize,
    /// Side-exit ratio threshold (millionths) above which trace is disabled.
    pub max_exit_ratio_millionths: u64,
    /// Minimum net cost savings (millionths) for fusion to be worthwhile.
    pub min_net_savings_millionths: i64,
    /// Whether to require proof lineage for all fusions.
    pub require_proof_lineage: bool,
    /// Whether to allow fusion of effectful motifs.
    pub allow_effectful_fusion: bool,
    /// Maximum number of active traces per function.
    pub max_traces_per_function: usize,
    /// Maximum number of motifs recognized per trace.
    pub max_motifs_per_trace: usize,
}

impl Default for FusionPolicy {
    fn default() -> Self {
        Self {
            min_observation_count: 100,
            min_type_stability_millionths: 900_000, // 90%
            max_fused_instructions: 64,
            max_super_instructions: 16,
            max_guards: 8,
            max_exit_ratio_millionths: 200_000, // 20%
            min_net_savings_millionths: 50_000, // 5%
            require_proof_lineage: true,
            allow_effectful_fusion: false,
            max_traces_per_function: 4,
            max_motifs_per_trace: 8,
        }
    }
}

impl FusionPolicy {
    /// Policy hash for deterministic comparison.
    pub fn policy_hash(&self) -> String {
        let data = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.min_observation_count,
            self.min_type_stability_millionths,
            self.max_fused_instructions,
            self.max_super_instructions,
            self.max_guards,
            self.max_exit_ratio_millionths,
            self.min_net_savings_millionths,
            self.require_proof_lineage,
            self.allow_effectful_fusion,
            self.max_traces_per_function,
            self.max_motifs_per_trace,
        );
        let hash = ContentHash::compute(data.as_bytes());
        hash.to_hex()[..16].to_string()
    }

    /// Validate a motif against this policy.
    pub fn validate_motif(&self, motif: &FusionMotif) -> MotifValidation {
        if !motif.meets_minimum() {
            return MotifValidation::Rejected(MotifRejectionReason::InsufficientInstructions);
        }
        if motif.observation_count < self.min_observation_count {
            return MotifValidation::Rejected(MotifRejectionReason::InsufficientObservations);
        }
        if motif.min_stability_millionths < self.min_type_stability_millionths {
            return MotifValidation::Rejected(MotifRejectionReason::InsufficientStability);
        }
        if !self.allow_effectful_fusion && !motif.side_effect_free {
            return MotifValidation::Rejected(MotifRejectionReason::EffectfulMotif);
        }
        MotifValidation::Accepted
    }
}

/// Result of validating a motif against fusion policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MotifValidation {
    /// Motif accepted for fusion.
    Accepted,
    /// Motif rejected with reason.
    Rejected(MotifRejectionReason),
}

/// Why a motif was rejected for fusion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MotifRejectionReason {
    /// Fewer instructions than required minimum.
    InsufficientInstructions,
    /// Not enough observations in profiling.
    InsufficientObservations,
    /// Type stability below threshold.
    InsufficientStability,
    /// Motif has side effects and policy forbids effectful fusion.
    EffectfulMotif,
    /// Capabilities not authorized by proof lineage.
    UnauthorizedCapabilities,
    /// Would exceed maximum motifs per trace.
    MotifLimitExceeded,
}

// ---------------------------------------------------------------------------
// Fusion outcome
// ---------------------------------------------------------------------------

/// Result of attempting a trace fusion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FusionOutcome {
    /// Fusion succeeded, trace was formed.
    Formed,
    /// No fusible motifs were found.
    NoFusibleMotifs,
    /// All motifs were rejected by policy.
    AllMotifsRejected,
    /// Net savings below threshold.
    InsufficientSavings { net_millionths: i64 },
    /// Exceeded maximum traces per function.
    TraceLimitExceeded { function_id: String },
    /// Proof lineage was required but not available.
    MissingProofLineage,
    /// Would interfere with existing active trace.
    InterferenceBlocked { existing_trace_id: String },
}

// ---------------------------------------------------------------------------
// Fusion record (audit trail)
// ---------------------------------------------------------------------------

/// Record of a fusion attempt for audit and replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FusionRecord {
    /// Unique record identifier.
    pub record_id: String,
    /// Function targeted for fusion.
    pub function_id: String,
    /// Motifs that were considered.
    pub considered_motifs: Vec<String>,
    /// Motifs that were accepted.
    pub accepted_motifs: Vec<String>,
    /// Motifs that were rejected with reasons.
    pub rejected_motifs: Vec<(String, MotifRejectionReason)>,
    /// Outcome of the fusion attempt.
    pub outcome: FusionOutcome,
    /// Resulting trace ID (if formed).
    pub trace_id: Option<String>,
    /// Epoch when fusion was attempted.
    pub epoch: SecurityEpoch,
    /// Cost savings achieved (millionths).
    pub cost_savings_millionths: i64,
}

impl FusionRecord {
    /// Create a new fusion record.
    pub fn new(function_id: &str, epoch: SecurityEpoch) -> Self {
        let hash = ContentHash::compute(format!("{function_id}:rec:{}", epoch.as_u64()).as_bytes());
        Self {
            record_id: format!("fr-{}", &hash.to_hex()[..16]),
            function_id: function_id.to_string(),
            considered_motifs: Vec::new(),
            accepted_motifs: Vec::new(),
            rejected_motifs: Vec::new(),
            outcome: FusionOutcome::NoFusibleMotifs,
            trace_id: None,
            epoch,
            cost_savings_millionths: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Motif recognizer
// ---------------------------------------------------------------------------

/// Instruction entry for motif recognition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstructionEntry {
    /// Bytecode offset.
    pub offset: u32,
    /// Opcode name.
    pub opcode: String,
    /// Execution count from profiling.
    pub execution_count: u64,
    /// Type stability in millionths.
    pub type_stability_millionths: u64,
    /// Whether this instruction has side effects.
    pub has_side_effects: bool,
    /// Required capabilities (for hostcall instructions).
    pub capabilities: BTreeSet<String>,
}

/// Recognize fusible motifs in an instruction stream.
pub struct MotifRecognizer {
    /// Accumulated instruction entries.
    entries: Vec<InstructionEntry>,
}

impl MotifRecognizer {
    /// Create a new recognizer.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add an instruction entry.
    pub fn add_entry(&mut self, entry: InstructionEntry) {
        self.entries.push(entry);
    }

    /// Number of entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Recognize all fusible motifs in the instruction stream.
    pub fn recognize(&self) -> Vec<FusionMotif> {
        let mut motifs = Vec::new();
        motifs.extend(self.recognize_arithmetic_chains());
        motifs.extend(self.recognize_property_chains());
        motifs.extend(self.recognize_hostcall_sequences());
        motifs.extend(self.recognize_comparison_branches());
        motifs.extend(self.recognize_allocation_inits());
        motifs.extend(self.recognize_string_concats());
        motifs
    }

    fn recognize_arithmetic_chains(&self) -> Vec<FusionMotif> {
        let arith_ops: BTreeSet<&str> = ["Add", "Sub", "Mul", "Div", "Mod", "Exp"]
            .iter()
            .copied()
            .collect();
        self.recognize_consecutive_pattern(&arith_ops, MotifKind::ArithmeticChain, 3)
    }

    fn recognize_property_chains(&self) -> Vec<FusionMotif> {
        let prop_ops: BTreeSet<&str> = ["GetProperty", "SetProperty"].iter().copied().collect();
        self.recognize_consecutive_pattern(&prop_ops, MotifKind::PropertyChain, 2)
    }

    fn recognize_hostcall_sequences(&self) -> Vec<FusionMotif> {
        let hostcall_ops: BTreeSet<&str> = ["HostCall"].iter().copied().collect();
        self.recognize_consecutive_pattern(&hostcall_ops, MotifKind::HostcallSequence, 2)
    }

    fn recognize_comparison_branches(&self) -> Vec<FusionMotif> {
        let mut motifs = Vec::new();
        let cmp_ops: BTreeSet<&str> = [
            "Lt",
            "Lte",
            "Gt",
            "Gte",
            "Eq",
            "StrictEq",
            "NotEq",
            "StrictNotEq",
        ]
        .iter()
        .copied()
        .collect();

        for i in 0..self.entries.len().saturating_sub(1) {
            if cmp_ops.contains(self.entries[i].opcode.as_str())
                && self.entries[i + 1].opcode == "JumpIf"
            {
                let opcodes = vec![
                    self.entries[i].opcode.clone(),
                    self.entries[i + 1].opcode.clone(),
                ];
                let mut motif = FusionMotif::new(
                    MotifKind::ComparisonBranch,
                    opcodes,
                    self.entries[i].offset,
                    self.entries[i + 1].offset,
                );
                motif.observation_count = self.entries[i]
                    .execution_count
                    .min(self.entries[i + 1].execution_count);
                motif.min_stability_millionths = self.entries[i]
                    .type_stability_millionths
                    .min(self.entries[i + 1].type_stability_millionths);
                if self.entries[i].has_side_effects || self.entries[i + 1].has_side_effects {
                    motif.mark_effectful();
                }
                motifs.push(motif);
            }
        }
        motifs
    }

    fn recognize_allocation_inits(&self) -> Vec<FusionMotif> {
        let mut motifs = Vec::new();
        let mut i = 0;
        while i < self.entries.len() {
            if self.entries[i].opcode == "NewObject" || self.entries[i].opcode == "NewArray" {
                let start = i;
                let mut j = i + 1;
                while j < self.entries.len() && self.entries[j].opcode == "SetProperty" {
                    j += 1;
                }
                if j > start + 1 {
                    let opcodes: Vec<String> = self.entries[start..j]
                        .iter()
                        .map(|e| e.opcode.clone())
                        .collect();
                    let mut motif = FusionMotif::new(
                        MotifKind::AllocationInit,
                        opcodes,
                        self.entries[start].offset,
                        self.entries[j - 1].offset,
                    );
                    let min_count = self.entries[start..j]
                        .iter()
                        .map(|e| e.execution_count)
                        .min()
                        .unwrap_or(0);
                    motif.observation_count = min_count;
                    let min_stab = self.entries[start..j]
                        .iter()
                        .map(|e| e.type_stability_millionths)
                        .min()
                        .unwrap_or(0);
                    motif.min_stability_millionths = min_stab;
                    motifs.push(motif);
                    i = j;
                    continue;
                }
            }
            i += 1;
        }
        motifs
    }

    fn recognize_string_concats(&self) -> Vec<FusionMotif> {
        let string_ops: BTreeSet<&str> = ["TemplateLiteral"].iter().copied().collect();
        self.recognize_consecutive_pattern(&string_ops, MotifKind::StringConcat, 2)
    }

    fn recognize_consecutive_pattern(
        &self,
        ops: &BTreeSet<&str>,
        kind: MotifKind,
        min_len: usize,
    ) -> Vec<FusionMotif> {
        let mut motifs = Vec::new();
        let mut run_start = None;
        for (i, entry) in self.entries.iter().enumerate() {
            if ops.contains(entry.opcode.as_str()) {
                if run_start.is_none() {
                    run_start = Some(i);
                }
            } else if let Some(start) = run_start {
                if i - start >= min_len {
                    let opcodes: Vec<String> = self.entries[start..i]
                        .iter()
                        .map(|e| e.opcode.clone())
                        .collect();
                    let mut motif = FusionMotif::new(
                        kind.clone(),
                        opcodes,
                        self.entries[start].offset,
                        self.entries[i - 1].offset,
                    );
                    let min_count = self.entries[start..i]
                        .iter()
                        .map(|e| e.execution_count)
                        .min()
                        .unwrap_or(0);
                    motif.observation_count = min_count;
                    let min_stab = self.entries[start..i]
                        .iter()
                        .map(|e| e.type_stability_millionths)
                        .min()
                        .unwrap_or(0);
                    motif.min_stability_millionths = min_stab;
                    let any_effects = self.entries[start..i].iter().any(|e| e.has_side_effects);
                    if any_effects {
                        motif.mark_effectful();
                    }
                    for e in &self.entries[start..i] {
                        for cap in &e.capabilities {
                            motif.require_capability(cap);
                        }
                    }
                    motifs.push(motif);
                }
                run_start = None;
            }
        }
        // Handle run at end of stream.
        if let Some(start) = run_start {
            let end = self.entries.len();
            if end - start >= min_len {
                let opcodes: Vec<String> = self.entries[start..end]
                    .iter()
                    .map(|e| e.opcode.clone())
                    .collect();
                let mut motif = FusionMotif::new(
                    kind,
                    opcodes,
                    self.entries[start].offset,
                    self.entries[end - 1].offset,
                );
                let min_count = self.entries[start..end]
                    .iter()
                    .map(|e| e.execution_count)
                    .min()
                    .unwrap_or(0);
                motif.observation_count = min_count;
                let min_stab = self.entries[start..end]
                    .iter()
                    .map(|e| e.type_stability_millionths)
                    .min()
                    .unwrap_or(0);
                motif.min_stability_millionths = min_stab;
                let any_effects = self.entries[start..end].iter().any(|e| e.has_side_effects);
                if any_effects {
                    motif.mark_effectful();
                }
                for e in &self.entries[start..end] {
                    for cap in &e.capabilities {
                        motif.require_capability(cap);
                    }
                }
                motifs.push(motif);
            }
        }
        motifs
    }
}

impl Default for MotifRecognizer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Superinstruction catalog (fusion-specific)
// ---------------------------------------------------------------------------

/// Template defining a superinstruction opcode from a motif fusion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuperInstructionTemplate {
    /// Superinstruction opcode name.
    pub opcode: String,
    /// Motif kind this template handles.
    pub motif_kind: MotifKind,
    /// Minimum opcodes in the motif for this template.
    pub min_opcodes: usize,
    /// Maximum opcodes in the motif for this template.
    pub max_opcodes: usize,
    /// Cost savings per application in millionths.
    pub savings_millionths: i64,
    /// Guard kind required (if any).
    pub required_guard: Option<FusionGuardKind>,
}

/// Registry of available superinstruction templates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FusionTemplateCatalog {
    /// Available templates, keyed by motif kind.
    pub templates: BTreeMap<String, SuperInstructionTemplate>,
    /// Schema version.
    pub schema_version: String,
}

impl FusionTemplateCatalog {
    /// Create a new catalog with default templates.
    pub fn new() -> Self {
        let mut catalog = Self {
            templates: BTreeMap::new(),
            schema_version: TRACE_FUSION_SCHEMA_VERSION.to_string(),
        };
        catalog.register_defaults();
        catalog
    }

    fn register_defaults(&mut self) {
        self.register(SuperInstructionTemplate {
            opcode: "SuperArithChain".to_string(),
            motif_kind: MotifKind::ArithmeticChain,
            min_opcodes: 3,
            max_opcodes: 16,
            savings_millionths: 150_000,
            required_guard: Some(FusionGuardKind::TypeStability {
                expected_type: "Integer".to_string(),
            }),
        });
        self.register(SuperInstructionTemplate {
            opcode: "SuperPropChain".to_string(),
            motif_kind: MotifKind::PropertyChain,
            min_opcodes: 2,
            max_opcodes: 8,
            savings_millionths: 200_000,
            required_guard: Some(FusionGuardKind::ShapeCheck {
                expected_shape_id: String::new(),
            }),
        });
        self.register(SuperInstructionTemplate {
            opcode: "SuperHostcallBatch".to_string(),
            motif_kind: MotifKind::HostcallSequence,
            min_opcodes: 2,
            max_opcodes: 8,
            savings_millionths: 300_000,
            required_guard: Some(FusionGuardKind::CapabilityValid {
                capability_name: String::new(),
            }),
        });
        self.register(SuperInstructionTemplate {
            opcode: "SuperCmpBranch".to_string(),
            motif_kind: MotifKind::ComparisonBranch,
            min_opcodes: 2,
            max_opcodes: 2,
            savings_millionths: 100_000,
            required_guard: Some(FusionGuardKind::TypeStability {
                expected_type: "Integer".to_string(),
            }),
        });
        self.register(SuperInstructionTemplate {
            opcode: "SuperAllocInit".to_string(),
            motif_kind: MotifKind::AllocationInit,
            min_opcodes: 2,
            max_opcodes: 16,
            savings_millionths: 250_000,
            required_guard: None,
        });
        self.register(SuperInstructionTemplate {
            opcode: "SuperStrConcat".to_string(),
            motif_kind: MotifKind::StringConcat,
            min_opcodes: 2,
            max_opcodes: 8,
            savings_millionths: 180_000,
            required_guard: None,
        });
    }

    /// Register a template.
    pub fn register(&mut self, template: SuperInstructionTemplate) {
        self.templates.insert(template.opcode.clone(), template);
    }

    /// Find a template for a given motif.
    pub fn find_template(&self, motif: &FusionMotif) -> Option<&SuperInstructionTemplate> {
        self.templates.values().find(|t| {
            t.motif_kind == motif.kind
                && motif.instruction_count() >= t.min_opcodes
                && motif.instruction_count() <= t.max_opcodes
        })
    }

    /// Template count.
    pub fn template_count(&self) -> usize {
        self.templates.len()
    }
}

impl Default for FusionTemplateCatalog {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Trace fusion engine
// ---------------------------------------------------------------------------

/// Main trace fusion engine: recognizes motifs, validates them, and forms
/// fused traces with superinstructions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceFusionEngine {
    /// Fusion policy.
    pub policy: FusionPolicy,
    /// Template catalog.
    pub catalog: FusionTemplateCatalog,
    /// Active fused traces, keyed by trace_id.
    pub active_traces: BTreeMap<String, FusedTrace>,
    /// Per-function trace count.
    function_trace_counts: BTreeMap<String, usize>,
    /// Fusion records (audit trail).
    pub records: Vec<FusionRecord>,
    /// Current security epoch.
    pub epoch: SecurityEpoch,
}

impl TraceFusionEngine {
    /// Create a new engine with default policy and catalog.
    pub fn new(epoch: SecurityEpoch) -> Self {
        Self {
            policy: FusionPolicy::default(),
            catalog: FusionTemplateCatalog::new(),
            active_traces: BTreeMap::new(),
            function_trace_counts: BTreeMap::new(),
            records: Vec::new(),
            epoch,
        }
    }

    /// Create with a custom policy.
    pub fn with_policy(policy: FusionPolicy, epoch: SecurityEpoch) -> Self {
        Self {
            policy,
            catalog: FusionTemplateCatalog::new(),
            active_traces: BTreeMap::new(),
            function_trace_counts: BTreeMap::new(),
            records: Vec::new(),
            epoch,
        }
    }

    /// Attempt to fuse a recognized set of instruction entries for a function.
    pub fn fuse(
        &mut self,
        function_id: &str,
        entries: &[InstructionEntry],
        proof_lineage: Option<FusionProofLineage>,
    ) -> FusionOutcome {
        let mut record = FusionRecord::new(function_id, self.epoch);

        // Check per-function trace limit.
        let current_count = self
            .function_trace_counts
            .get(function_id)
            .copied()
            .unwrap_or(0);
        if current_count >= self.policy.max_traces_per_function {
            record.outcome = FusionOutcome::TraceLimitExceeded {
                function_id: function_id.to_string(),
            };
            self.records.push(record);
            return FusionOutcome::TraceLimitExceeded {
                function_id: function_id.to_string(),
            };
        }

        // Check proof lineage requirement.
        if self.policy.require_proof_lineage && proof_lineage.is_none() {
            record.outcome = FusionOutcome::MissingProofLineage;
            self.records.push(record);
            return FusionOutcome::MissingProofLineage;
        }

        // Recognize motifs.
        let mut recognizer = MotifRecognizer::new();
        for entry in entries {
            recognizer.add_entry(entry.clone());
        }
        let motifs = recognizer.recognize();

        if motifs.is_empty() {
            record.outcome = FusionOutcome::NoFusibleMotifs;
            self.records.push(record);
            return FusionOutcome::NoFusibleMotifs;
        }

        // Validate motifs against policy.
        let mut accepted = Vec::new();
        for motif in &motifs {
            record.considered_motifs.push(motif.motif_id.clone());
            match self.policy.validate_motif(motif) {
                MotifValidation::Accepted => {
                    if accepted.len() < self.policy.max_motifs_per_trace {
                        accepted.push(motif.clone());
                        record.accepted_motifs.push(motif.motif_id.clone());
                    } else {
                        record.rejected_motifs.push((
                            motif.motif_id.clone(),
                            MotifRejectionReason::MotifLimitExceeded,
                        ));
                    }
                }
                MotifValidation::Rejected(reason) => {
                    record
                        .rejected_motifs
                        .push((motif.motif_id.clone(), reason));
                }
            }
        }

        if accepted.is_empty() {
            record.outcome = FusionOutcome::AllMotifsRejected;
            self.records.push(record);
            return FusionOutcome::AllMotifsRejected;
        }

        // Build fused trace.
        let mut trace = FusedTrace::new(function_id, self.epoch);
        let mut total_savings: i64 = 0;
        let mut position: u32 = 0;

        // Build a set of fused offset ranges.
        let mut fused_ranges: BTreeMap<u32, (u32, String, i64)> = BTreeMap::new();
        for motif in &accepted {
            if let Some(template) = self.catalog.find_template(motif) {
                let offsets: Vec<u32> = entries
                    .iter()
                    .filter(|e| e.offset >= motif.start_offset && e.offset <= motif.end_offset)
                    .map(|e| e.offset)
                    .collect();
                if !offsets.is_empty() {
                    fused_ranges.insert(
                        motif.start_offset,
                        (
                            motif.end_offset,
                            template.opcode.clone(),
                            template.savings_millionths,
                        ),
                    );
                    total_savings += template.savings_millionths;
                    trace.record_fused_motif(&motif.motif_id);
                }
            }
        }

        // Check net savings threshold.
        if total_savings < self.policy.min_net_savings_millionths {
            record.outcome = FusionOutcome::InsufficientSavings {
                net_millionths: total_savings,
            };
            self.records.push(record);
            return FusionOutcome::InsufficientSavings {
                net_millionths: total_savings,
            };
        }

        // Check for interference with existing traces.
        for (existing_id, existing_trace) in &self.active_traces {
            if existing_trace.function_id == function_id && existing_trace.enabled {
                // Check overlap in source offsets.
                let existing_offsets: BTreeSet<u32> = existing_trace
                    .instructions
                    .iter()
                    .flat_map(|i| i.source_offsets.iter().copied())
                    .collect();
                let new_offsets: BTreeSet<u32> = entries.iter().map(|e| e.offset).collect();
                if !existing_offsets.is_disjoint(&new_offsets) {
                    record.outcome = FusionOutcome::InterferenceBlocked {
                        existing_trace_id: existing_id.clone(),
                    };
                    self.records.push(record);
                    return FusionOutcome::InterferenceBlocked {
                        existing_trace_id: existing_id.clone(),
                    };
                }
            }
        }

        // Emit instructions: fused where motifs matched, passthrough elsewhere.
        let mut guard_count = 0;
        let mut i = 0;
        while i < entries.len() {
            let entry = &entries[i];
            if let Some((end_offset, ref super_opcode, cost_savings)) =
                fused_ranges.get(&entry.offset).cloned()
            {
                // Collect all entries in this fused range.
                let mut fused_offsets = Vec::new();
                let mut j = i;
                while j < entries.len() && entries[j].offset <= end_offset {
                    fused_offsets.push(entries[j].offset);
                    j += 1;
                }
                let mut instr = FusedInstruction::super_instruction(
                    position,
                    fused_offsets,
                    super_opcode,
                    cost_savings,
                );
                // Add guard if template requires one and we haven't hit guard limit.
                if guard_count < self.policy.max_guards {
                    let guard = FusionGuard::new(
                        FusionGuardKind::TypeStability {
                            expected_type: "Integer".to_string(),
                        },
                        entry.offset,
                    );
                    instr = instr.with_guard(guard);
                    guard_count += 1;
                }
                trace.add_instruction(instr);
                position += 1;
                i = j;
            } else {
                trace.add_instruction(FusedInstruction::passthrough(
                    position,
                    entry.offset,
                    &entry.opcode,
                ));
                position += 1;
                i += 1;
            }
        }

        trace.cost_savings_millionths = total_savings;
        if let Some(lineage) = proof_lineage {
            trace.set_proof_lineage(lineage);
        }

        // Recompute trace ID based on final content.
        let content = trace.content_hash();
        trace.trace_id = format!("ft-{}", &content.to_hex()[..16]);

        record.outcome = FusionOutcome::Formed;
        record.trace_id = Some(trace.trace_id.clone());
        record.cost_savings_millionths = total_savings;

        // Register trace.
        let trace_id = trace.trace_id.clone();
        self.active_traces.insert(trace_id, trace);
        *self
            .function_trace_counts
            .entry(function_id.to_string())
            .or_insert(0) += 1;
        self.records.push(record);

        FusionOutcome::Formed
    }

    /// Disable a trace by ID.
    pub fn disable_trace(&mut self, trace_id: &str, reason: FusionDisableReason) -> bool {
        if let Some(trace) = self.active_traces.get_mut(trace_id) {
            trace.disable(reason);
            true
        } else {
            false
        }
    }

    /// Re-enable a previously disabled trace.
    pub fn enable_trace(&mut self, trace_id: &str) -> bool {
        if let Some(trace) = self.active_traces.get_mut(trace_id) {
            trace.enable();
            true
        } else {
            false
        }
    }

    /// Record an execution for a trace.
    pub fn record_execution(&mut self, trace_id: &str) -> bool {
        if let Some(trace) = self.active_traces.get_mut(trace_id) {
            trace.record_execution();
            true
        } else {
            false
        }
    }

    /// Record a side exit for a trace and auto-disable if degraded.
    pub fn record_side_exit(&mut self, trace_id: &str) -> bool {
        let max_ratio = self.policy.max_exit_ratio_millionths;
        if let Some(trace) = self.active_traces.get_mut(trace_id) {
            trace.record_side_exit();
            if trace.is_degraded(max_ratio) {
                let ratio = trace.side_exit_ratio_millionths();
                trace.disable(FusionDisableReason::ExcessiveSideExits {
                    ratio_millionths: ratio,
                    threshold_millionths: max_ratio,
                });
            }
            true
        } else {
            false
        }
    }

    /// Invalidate all traces whose proof lineage includes a revoked proof.
    pub fn invalidate_proof(&mut self, proof_id: &str) {
        let trace_ids: Vec<String> = self
            .active_traces
            .iter()
            .filter(|(_, t)| {
                if let Some(ref lineage) = t.proof_lineage {
                    lineage.capability_proof_ids.contains(&proof_id.to_string())
                        || lineage.flow_proof_ids.contains(&proof_id.to_string())
                } else {
                    false
                }
            })
            .map(|(id, _)| id.clone())
            .collect();

        for trace_id in trace_ids {
            if let Some(trace) = self.active_traces.get_mut(&trace_id)
                && let Some(ref lineage) = trace.proof_lineage
            {
                let lid = lineage.lineage_id.clone();
                trace.disable(FusionDisableReason::ProofInvalidated { lineage_id: lid });
            }
        }
    }

    /// Advance epoch and disable traces formed in earlier epochs.
    pub fn advance_epoch(&mut self, new_epoch: SecurityEpoch) {
        self.epoch = new_epoch;

        let trace_ids: Vec<String> = self
            .active_traces
            .iter()
            .filter(|(_, t)| t.enabled && t.formation_epoch.as_u64() < new_epoch.as_u64())
            .map(|(id, _)| id.clone())
            .collect();

        for trace_id in trace_ids {
            if let Some(trace) = self.active_traces.get_mut(&trace_id) {
                trace.disable(FusionDisableReason::EpochAdvanced {
                    formation: trace.formation_epoch.as_u64(),
                    current: new_epoch.as_u64(),
                });
            }
        }
    }

    /// Get a trace by ID.
    pub fn get_trace(&self, trace_id: &str) -> Option<&FusedTrace> {
        self.active_traces.get(trace_id)
    }

    /// Get all traces for a function.
    pub fn traces_for_function(&self, function_id: &str) -> Vec<&FusedTrace> {
        self.active_traces
            .values()
            .filter(|t| t.function_id == function_id)
            .collect()
    }

    /// Active (enabled) trace count.
    pub fn active_count(&self) -> usize {
        self.active_traces.values().filter(|t| t.enabled).count()
    }

    /// Total trace count (including disabled).
    pub fn total_count(&self) -> usize {
        self.active_traces.len()
    }

    /// Fusion record count.
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Summaries of all active traces.
    pub fn active_summaries(&self) -> Vec<FusedTraceSummary> {
        self.active_traces
            .values()
            .filter(|t| t.enabled)
            .map(|t| t.summary())
            .collect()
    }

    /// Summaries of all traces.
    pub fn all_summaries(&self) -> Vec<FusedTraceSummary> {
        self.active_traces.values().map(|t| t.summary()).collect()
    }

    /// Engine diagnostics.
    pub fn diagnostics(&self) -> TraceFusionDiagnostics {
        let total = self.active_traces.len() as u32;
        let active = self.active_count() as u32;
        let disabled = total - active;
        let total_savings: i64 = self
            .active_traces
            .values()
            .filter(|t| t.enabled)
            .map(|t| t.cost_savings_millionths)
            .sum();
        let total_executions: u64 = self.active_traces.values().map(|t| t.execution_count).sum();
        let total_exits: u64 = self.active_traces.values().map(|t| t.side_exit_count).sum();
        let formed_count = self
            .records
            .iter()
            .filter(|r| matches!(r.outcome, FusionOutcome::Formed))
            .count() as u32;
        let rejected_count = self.records.len() as u32 - formed_count;

        TraceFusionDiagnostics {
            total_traces: total,
            active_traces: active,
            disabled_traces: disabled,
            total_cost_savings_millionths: total_savings,
            total_executions,
            total_side_exits: total_exits,
            fusion_attempts: self.records.len() as u32,
            fusion_successes: formed_count,
            fusion_rejections: rejected_count,
            policy_hash: self.policy.policy_hash(),
        }
    }
}

/// Diagnostics snapshot for the fusion engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceFusionDiagnostics {
    pub total_traces: u32,
    pub active_traces: u32,
    pub disabled_traces: u32,
    pub total_cost_savings_millionths: i64,
    pub total_executions: u64,
    pub total_side_exits: u64,
    pub fusion_attempts: u32,
    pub fusion_successes: u32,
    pub fusion_rejections: u32,
    pub policy_hash: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    fn arith_entries(count: usize, exec_count: u64) -> Vec<InstructionEntry> {
        let ops = ["Add", "Sub", "Mul", "Div"];
        (0..count)
            .map(|i| InstructionEntry {
                offset: i as u32 * 4,
                opcode: ops[i % ops.len()].to_string(),
                execution_count: exec_count,
                type_stability_millionths: 950_000,
                has_side_effects: false,
                capabilities: BTreeSet::new(),
            })
            .collect()
    }

    fn prop_chain_entries(count: usize, exec_count: u64) -> Vec<InstructionEntry> {
        (0..count)
            .map(|i| InstructionEntry {
                offset: i as u32 * 4,
                opcode: "GetProperty".to_string(),
                execution_count: exec_count,
                type_stability_millionths: 960_000,
                has_side_effects: false,
                capabilities: BTreeSet::new(),
            })
            .collect()
    }

    fn hostcall_entries(count: usize, exec_count: u64) -> Vec<InstructionEntry> {
        (0..count)
            .map(|i| {
                let mut caps = BTreeSet::new();
                caps.insert("fs.read".to_string());
                InstructionEntry {
                    offset: i as u32 * 4,
                    opcode: "HostCall".to_string(),
                    execution_count: exec_count,
                    type_stability_millionths: 1_000_000,
                    has_side_effects: true,
                    capabilities: caps,
                }
            })
            .collect()
    }

    fn proof_lineage() -> FusionProofLineage {
        FusionProofLineage::new(
            vec!["cap-proof-1".to_string()],
            vec!["flow-proof-1".to_string()],
            test_epoch(),
        )
    }

    // --- MotifKind tests ---

    #[test]
    fn test_motif_kind_min_instructions() {
        assert_eq!(MotifKind::HostcallSequence.min_instructions(), 2);
        assert_eq!(MotifKind::ArithmeticChain.min_instructions(), 3);
        assert_eq!(MotifKind::PropertyChain.min_instructions(), 2);
        assert_eq!(MotifKind::GuardElidedRegion.min_instructions(), 2);
        assert_eq!(MotifKind::ComparisonBranch.min_instructions(), 2);
        assert_eq!(MotifKind::AllocationInit.min_instructions(), 2);
        assert_eq!(MotifKind::StringConcat.min_instructions(), 2);
        assert_eq!(MotifKind::LoopInvariant.min_instructions(), 1);
    }

    // --- FusionMotif tests ---

    #[test]
    fn test_motif_new_and_id() {
        let motif = FusionMotif::new(
            MotifKind::ArithmeticChain,
            vec!["Add".into(), "Sub".into(), "Mul".into()],
            0,
            8,
        );
        assert!(motif.motif_id.starts_with("motif-"));
        assert_eq!(motif.kind, MotifKind::ArithmeticChain);
        assert_eq!(motif.instruction_count(), 3);
        assert!(motif.meets_minimum());
    }

    #[test]
    fn test_motif_below_minimum() {
        let motif = FusionMotif::new(
            MotifKind::ArithmeticChain,
            vec!["Add".into(), "Sub".into()],
            0,
            4,
        );
        assert!(!motif.meets_minimum()); // ArithmeticChain requires 3.
    }

    #[test]
    fn test_motif_record_observation() {
        let mut motif = FusionMotif::new(
            MotifKind::PropertyChain,
            vec!["GetProperty".into(), "GetProperty".into()],
            0,
            4,
        );
        assert_eq!(motif.observation_count, 0);
        motif.record_observation();
        motif.record_observation();
        assert_eq!(motif.observation_count, 2);
    }

    #[test]
    fn test_motif_effectful() {
        let mut motif = FusionMotif::new(
            MotifKind::HostcallSequence,
            vec!["HostCall".into(), "HostCall".into()],
            0,
            4,
        );
        assert!(motif.side_effect_free);
        motif.mark_effectful();
        assert!(!motif.side_effect_free);
    }

    #[test]
    fn test_motif_capabilities() {
        let mut motif = FusionMotif::new(
            MotifKind::HostcallSequence,
            vec!["HostCall".into(), "HostCall".into()],
            0,
            4,
        );
        motif.require_capability("fs.read");
        motif.require_capability("net.connect");
        assert_eq!(motif.required_capabilities.len(), 2);
    }

    #[test]
    fn test_motif_content_hash_deterministic() {
        let m1 = FusionMotif::new(
            MotifKind::ArithmeticChain,
            vec!["Add".into(), "Sub".into(), "Mul".into()],
            0,
            8,
        );
        let m2 = FusionMotif::new(
            MotifKind::ArithmeticChain,
            vec!["Add".into(), "Sub".into(), "Mul".into()],
            0,
            8,
        );
        assert_eq!(m1.content_hash(), m2.content_hash());
    }

    #[test]
    fn test_motif_different_offsets_different_hash() {
        let m1 = FusionMotif::new(
            MotifKind::ArithmeticChain,
            vec!["Add".into(), "Sub".into(), "Mul".into()],
            0,
            8,
        );
        let m2 = FusionMotif::new(
            MotifKind::ArithmeticChain,
            vec!["Add".into(), "Sub".into(), "Mul".into()],
            4,
            12,
        );
        assert_ne!(m1.content_hash(), m2.content_hash());
    }

    // --- FusionProofLineage tests ---

    #[test]
    fn test_proof_lineage_creation() {
        let lineage = proof_lineage();
        assert!(lineage.lineage_id.starts_with("lineage-"));
        assert!(lineage.all_proofs_active);
        assert_eq!(lineage.proof_count(), 2);
    }

    #[test]
    fn test_proof_lineage_invalidate() {
        let mut lineage = proof_lineage();
        assert!(lineage.is_valid_at(test_epoch()));
        lineage.invalidate();
        assert!(!lineage.is_valid_at(test_epoch()));
    }

    #[test]
    fn test_proof_lineage_epoch_check() {
        let lineage =
            FusionProofLineage::new(vec!["p1".into()], vec![], SecurityEpoch::from_raw(5));
        assert!(!lineage.is_valid_at(SecurityEpoch::from_raw(3)));
        assert!(lineage.is_valid_at(SecurityEpoch::from_raw(5)));
        assert!(lineage.is_valid_at(SecurityEpoch::from_raw(10)));
    }

    // --- FusedInstruction tests ---

    #[test]
    fn test_passthrough_instruction() {
        let instr = FusedInstruction::passthrough(0, 100, "Add");
        assert!(!instr.is_super);
        assert_eq!(instr.fusion_factor(), 1);
        assert_eq!(instr.opcode, "Add");
        assert!(instr.guard.is_none());
    }

    #[test]
    fn test_super_instruction() {
        let instr =
            FusedInstruction::super_instruction(0, vec![0, 4, 8], "SuperArithChain", 150_000);
        assert!(instr.is_super);
        assert_eq!(instr.fusion_factor(), 3);
        assert_eq!(instr.cost_millionths, 150_000);
    }

    #[test]
    fn test_instruction_with_guard() {
        let guard = FusionGuard::new(
            FusionGuardKind::TypeStability {
                expected_type: "Integer".into(),
            },
            0,
        );
        let instr = FusedInstruction::passthrough(0, 0, "Add").with_guard(guard);
        assert!(instr.guard.is_some());
    }

    // --- FusionGuard tests ---

    #[test]
    fn test_guard_creation() {
        let guard = FusionGuard::new(
            FusionGuardKind::ShapeCheck {
                expected_shape_id: "shape-abc".into(),
            },
            42,
        );
        assert!(guard.guard_id.starts_with("fg-"));
        assert_eq!(guard.side_exit_offset, 42);
        assert!(!guard.factored);
    }

    #[test]
    fn test_guard_factored() {
        let mut guard = FusionGuard::new(
            FusionGuardKind::CapabilityValid {
                capability_name: "fs.read".into(),
            },
            0,
        );
        guard.mark_factored();
        assert!(guard.factored);
    }

    // --- FusedTrace tests ---

    #[test]
    fn test_trace_creation() {
        let trace = FusedTrace::new("fn_main", test_epoch());
        assert!(trace.trace_id.starts_with("ft-"));
        assert!(trace.enabled);
        assert_eq!(trace.function_id, "fn_main");
        assert_eq!(trace.instruction_count(), 0);
    }

    #[test]
    fn test_trace_add_instructions() {
        let mut trace = FusedTrace::new("fn_test", test_epoch());
        trace.add_instruction(FusedInstruction::passthrough(0, 0, "LoadInt"));
        trace.add_instruction(FusedInstruction::super_instruction(
            1,
            vec![4, 8, 12],
            "SuperArithChain",
            150_000,
        ));
        assert_eq!(trace.instruction_count(), 2);
        assert_eq!(trace.super_instruction_count(), 1);
        assert_eq!(trace.fused_source_count(), 3);
    }

    #[test]
    fn test_trace_disable_enable() {
        let mut trace = FusedTrace::new("fn_test", test_epoch());
        assert!(trace.enabled);
        trace.disable(FusionDisableReason::OperatorDisabled {
            reason: "testing".into(),
        });
        assert!(!trace.enabled);
        assert!(trace.disable_reason.is_some());
        trace.enable();
        assert!(trace.enabled);
        assert!(trace.disable_reason.is_none());
    }

    #[test]
    fn test_trace_side_exit_ratio() {
        let mut trace = FusedTrace::new("fn_test", test_epoch());
        assert_eq!(trace.side_exit_ratio_millionths(), 0);
        for _ in 0..100 {
            trace.record_execution();
        }
        for _ in 0..10 {
            trace.record_side_exit();
        }
        assert_eq!(trace.side_exit_ratio_millionths(), 100_000); // 10%
    }

    #[test]
    fn test_trace_degradation() {
        let mut trace = FusedTrace::new("fn_test", test_epoch());
        for _ in 0..100 {
            trace.record_execution();
        }
        for _ in 0..30 {
            trace.record_side_exit();
        }
        assert!(trace.is_degraded(200_000)); // 30% > 20% threshold
        assert!(!trace.is_degraded(400_000)); // 30% < 40% threshold
    }

    #[test]
    fn test_trace_content_hash_deterministic() {
        let mut t1 = FusedTrace::new("fn_test", test_epoch());
        t1.add_instruction(FusedInstruction::passthrough(0, 0, "Add"));
        let mut t2 = FusedTrace::new("fn_test", test_epoch());
        t2.add_instruction(FusedInstruction::passthrough(0, 0, "Add"));
        assert_eq!(t1.content_hash(), t2.content_hash());
    }

    #[test]
    fn test_trace_summary() {
        let mut trace = FusedTrace::new("fn_test", test_epoch());
        trace.add_instruction(FusedInstruction::passthrough(0, 0, "LoadInt"));
        trace.add_instruction(FusedInstruction::super_instruction(
            1,
            vec![4, 8, 12],
            "SuperArithChain",
            150_000,
        ));
        trace.cost_savings_millionths = 150_000;
        let summary = trace.summary();
        assert_eq!(summary.instruction_count, 2);
        assert_eq!(summary.super_instruction_count, 1);
        assert_eq!(summary.cost_savings_millionths, 150_000);
    }

    #[test]
    fn test_trace_with_superblock() {
        let trace = FusedTrace::new("fn_test", test_epoch()).with_superblock("sb-abc123");
        assert_eq!(trace.source_superblock_id, Some("sb-abc123".to_string()));
    }

    // --- FusionPolicy tests ---

    #[test]
    fn test_default_policy() {
        let policy = FusionPolicy::default();
        assert_eq!(policy.min_observation_count, 100);
        assert_eq!(policy.min_type_stability_millionths, 900_000);
        assert!(policy.require_proof_lineage);
        assert!(!policy.allow_effectful_fusion);
    }

    #[test]
    fn test_policy_hash_deterministic() {
        let p1 = FusionPolicy::default();
        let p2 = FusionPolicy::default();
        assert_eq!(p1.policy_hash(), p2.policy_hash());
    }

    #[test]
    fn test_policy_validate_accepted() {
        let policy = FusionPolicy::default();
        let mut motif = FusionMotif::new(
            MotifKind::ArithmeticChain,
            vec!["Add".into(), "Sub".into(), "Mul".into()],
            0,
            8,
        );
        motif.observation_count = 200;
        motif.min_stability_millionths = 950_000;
        assert_eq!(policy.validate_motif(&motif), MotifValidation::Accepted);
    }

    #[test]
    fn test_policy_reject_insufficient_observations() {
        let policy = FusionPolicy::default();
        let mut motif = FusionMotif::new(
            MotifKind::ArithmeticChain,
            vec!["Add".into(), "Sub".into(), "Mul".into()],
            0,
            8,
        );
        motif.observation_count = 50;
        motif.min_stability_millionths = 950_000;
        assert_eq!(
            policy.validate_motif(&motif),
            MotifValidation::Rejected(MotifRejectionReason::InsufficientObservations)
        );
    }

    #[test]
    fn test_policy_reject_insufficient_stability() {
        let policy = FusionPolicy::default();
        let mut motif = FusionMotif::new(
            MotifKind::ArithmeticChain,
            vec!["Add".into(), "Sub".into(), "Mul".into()],
            0,
            8,
        );
        motif.observation_count = 200;
        motif.min_stability_millionths = 800_000;
        assert_eq!(
            policy.validate_motif(&motif),
            MotifValidation::Rejected(MotifRejectionReason::InsufficientStability)
        );
    }

    #[test]
    fn test_policy_reject_effectful() {
        let policy = FusionPolicy::default();
        let mut motif = FusionMotif::new(
            MotifKind::HostcallSequence,
            vec!["HostCall".into(), "HostCall".into()],
            0,
            4,
        );
        motif.observation_count = 200;
        motif.min_stability_millionths = 950_000;
        motif.mark_effectful();
        assert_eq!(
            policy.validate_motif(&motif),
            MotifValidation::Rejected(MotifRejectionReason::EffectfulMotif)
        );
    }

    #[test]
    fn test_policy_allow_effectful() {
        let policy = FusionPolicy {
            allow_effectful_fusion: true,
            ..Default::default()
        };
        let mut motif = FusionMotif::new(
            MotifKind::HostcallSequence,
            vec!["HostCall".into(), "HostCall".into()],
            0,
            4,
        );
        motif.observation_count = 200;
        motif.min_stability_millionths = 950_000;
        motif.mark_effectful();
        assert_eq!(policy.validate_motif(&motif), MotifValidation::Accepted);
    }

    // --- MotifRecognizer tests ---

    #[test]
    fn test_recognize_arithmetic_chain() {
        let mut rec = MotifRecognizer::new();
        for (i, op) in ["Add", "Sub", "Mul", "Div"].iter().enumerate() {
            rec.add_entry(InstructionEntry {
                offset: i as u32 * 4,
                opcode: op.to_string(),
                execution_count: 200,
                type_stability_millionths: 950_000,
                has_side_effects: false,
                capabilities: BTreeSet::new(),
            });
        }
        let motifs = rec.recognize();
        let arith: Vec<_> = motifs
            .iter()
            .filter(|m| m.kind == MotifKind::ArithmeticChain)
            .collect();
        assert_eq!(arith.len(), 1);
        assert_eq!(arith[0].instruction_count(), 4);
    }

    #[test]
    fn test_recognize_property_chain() {
        let mut rec = MotifRecognizer::new();
        for i in 0..3 {
            rec.add_entry(InstructionEntry {
                offset: i * 4,
                opcode: "GetProperty".to_string(),
                execution_count: 150,
                type_stability_millionths: 980_000,
                has_side_effects: false,
                capabilities: BTreeSet::new(),
            });
        }
        let motifs = rec.recognize();
        let props: Vec<_> = motifs
            .iter()
            .filter(|m| m.kind == MotifKind::PropertyChain)
            .collect();
        assert_eq!(props.len(), 1);
        assert_eq!(props[0].instruction_count(), 3);
    }

    #[test]
    fn test_recognize_comparison_branch() {
        let mut rec = MotifRecognizer::new();
        rec.add_entry(InstructionEntry {
            offset: 0,
            opcode: "Lt".to_string(),
            execution_count: 300,
            type_stability_millionths: 990_000,
            has_side_effects: false,
            capabilities: BTreeSet::new(),
        });
        rec.add_entry(InstructionEntry {
            offset: 4,
            opcode: "JumpIf".to_string(),
            execution_count: 300,
            type_stability_millionths: 1_000_000,
            has_side_effects: false,
            capabilities: BTreeSet::new(),
        });
        let motifs = rec.recognize();
        let cmps: Vec<_> = motifs
            .iter()
            .filter(|m| m.kind == MotifKind::ComparisonBranch)
            .collect();
        assert_eq!(cmps.len(), 1);
    }

    #[test]
    fn test_recognize_allocation_init() {
        let mut rec = MotifRecognizer::new();
        rec.add_entry(InstructionEntry {
            offset: 0,
            opcode: "NewObject".to_string(),
            execution_count: 200,
            type_stability_millionths: 1_000_000,
            has_side_effects: false,
            capabilities: BTreeSet::new(),
        });
        for i in 1..4 {
            rec.add_entry(InstructionEntry {
                offset: i * 4,
                opcode: "SetProperty".to_string(),
                execution_count: 200,
                type_stability_millionths: 1_000_000,
                has_side_effects: false,
                capabilities: BTreeSet::new(),
            });
        }
        let motifs = rec.recognize();
        let allocs: Vec<_> = motifs
            .iter()
            .filter(|m| m.kind == MotifKind::AllocationInit)
            .collect();
        assert_eq!(allocs.len(), 1);
        assert_eq!(allocs[0].instruction_count(), 4);
    }

    #[test]
    fn test_recognize_no_motifs_mixed_stream() {
        let mut rec = MotifRecognizer::new();
        rec.add_entry(InstructionEntry {
            offset: 0,
            opcode: "Add".to_string(),
            execution_count: 200,
            type_stability_millionths: 950_000,
            has_side_effects: false,
            capabilities: BTreeSet::new(),
        });
        rec.add_entry(InstructionEntry {
            offset: 4,
            opcode: "LoadInt".to_string(),
            execution_count: 200,
            type_stability_millionths: 950_000,
            has_side_effects: false,
            capabilities: BTreeSet::new(),
        });
        rec.add_entry(InstructionEntry {
            offset: 8,
            opcode: "Return".to_string(),
            execution_count: 200,
            type_stability_millionths: 950_000,
            has_side_effects: false,
            capabilities: BTreeSet::new(),
        });
        let motifs = rec.recognize();
        assert!(motifs.is_empty());
    }

    #[test]
    fn test_recognizer_entry_count() {
        let mut rec = MotifRecognizer::new();
        assert_eq!(rec.entry_count(), 0);
        rec.add_entry(InstructionEntry {
            offset: 0,
            opcode: "Add".into(),
            execution_count: 1,
            type_stability_millionths: 1_000_000,
            has_side_effects: false,
            capabilities: BTreeSet::new(),
        });
        assert_eq!(rec.entry_count(), 1);
    }

    #[test]
    fn test_recognize_hostcall_capabilities() {
        let mut rec = MotifRecognizer::new();
        for i in 0..3 {
            let mut caps = BTreeSet::new();
            caps.insert("fs.read".to_string());
            rec.add_entry(InstructionEntry {
                offset: i * 4,
                opcode: "HostCall".to_string(),
                execution_count: 200,
                type_stability_millionths: 1_000_000,
                has_side_effects: true,
                capabilities: caps,
            });
        }
        let motifs = rec.recognize();
        let hc: Vec<_> = motifs
            .iter()
            .filter(|m| m.kind == MotifKind::HostcallSequence)
            .collect();
        assert_eq!(hc.len(), 1);
        assert!(hc[0].required_capabilities.contains("fs.read"));
    }

    // --- FusionTemplateCatalog tests ---

    #[test]
    fn test_default_catalog() {
        let catalog = FusionTemplateCatalog::new();
        assert!(catalog.template_count() >= 6);
    }

    #[test]
    fn test_find_template_arithmetic() {
        let catalog = FusionTemplateCatalog::new();
        let motif = FusionMotif::new(
            MotifKind::ArithmeticChain,
            vec!["Add".into(), "Sub".into(), "Mul".into()],
            0,
            8,
        );
        let template = catalog.find_template(&motif);
        assert!(template.is_some());
        assert_eq!(template.unwrap().opcode, "SuperArithChain");
    }

    #[test]
    fn test_find_template_property() {
        let catalog = FusionTemplateCatalog::new();
        let motif = FusionMotif::new(
            MotifKind::PropertyChain,
            vec!["GetProperty".into(), "GetProperty".into()],
            0,
            4,
        );
        let template = catalog.find_template(&motif);
        assert!(template.is_some());
        assert_eq!(template.unwrap().opcode, "SuperPropChain");
    }

    #[test]
    fn test_register_custom_template() {
        let mut catalog = FusionTemplateCatalog::new();
        let initial = catalog.template_count();
        catalog.register(SuperInstructionTemplate {
            opcode: "CustomFusion".into(),
            motif_kind: MotifKind::LoopInvariant,
            min_opcodes: 1,
            max_opcodes: 4,
            savings_millionths: 120_000,
            required_guard: None,
        });
        assert_eq!(catalog.template_count(), initial + 1);
    }

    // --- TraceFusionEngine tests ---

    #[test]
    fn test_engine_creation() {
        let engine = TraceFusionEngine::new(test_epoch());
        assert_eq!(engine.total_count(), 0);
        assert_eq!(engine.active_count(), 0);
        assert_eq!(engine.record_count(), 0);
    }

    #[test]
    fn test_engine_fuse_arithmetic() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        engine.policy.require_proof_lineage = false;
        let entries = arith_entries(4, 200);
        let outcome = engine.fuse("fn_test", &entries, None);
        assert_eq!(outcome, FusionOutcome::Formed);
        assert_eq!(engine.total_count(), 1);
        assert_eq!(engine.active_count(), 1);
    }

    #[test]
    fn test_engine_fuse_with_proof() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        let entries = arith_entries(4, 200);
        let outcome = engine.fuse("fn_test", &entries, Some(proof_lineage()));
        assert_eq!(outcome, FusionOutcome::Formed);
    }

    #[test]
    fn test_engine_missing_proof() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        let entries = arith_entries(4, 200);
        let outcome = engine.fuse("fn_test", &entries, None);
        assert_eq!(outcome, FusionOutcome::MissingProofLineage);
    }

    #[test]
    fn test_engine_no_fusible_motifs() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        engine.policy.require_proof_lineage = false;
        let entries = vec![InstructionEntry {
            offset: 0,
            opcode: "Return".into(),
            execution_count: 200,
            type_stability_millionths: 950_000,
            has_side_effects: false,
            capabilities: BTreeSet::new(),
        }];
        let outcome = engine.fuse("fn_test", &entries, None);
        assert_eq!(outcome, FusionOutcome::NoFusibleMotifs);
    }

    #[test]
    fn test_engine_all_motifs_rejected() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        engine.policy.require_proof_lineage = false;
        // Low observation count.
        let entries: Vec<InstructionEntry> = (0..4)
            .map(|i| InstructionEntry {
                offset: i * 4,
                opcode: "Add".into(),
                execution_count: 5, // Below threshold.
                type_stability_millionths: 950_000,
                has_side_effects: false,
                capabilities: BTreeSet::new(),
            })
            .collect();
        let outcome = engine.fuse("fn_test", &entries, None);
        assert_eq!(outcome, FusionOutcome::AllMotifsRejected);
    }

    #[test]
    fn test_engine_trace_limit() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        engine.policy.require_proof_lineage = false;
        engine.policy.max_traces_per_function = 1;
        let entries = arith_entries(4, 200);
        let outcome1 = engine.fuse("fn_test", &entries, None);
        assert_eq!(outcome1, FusionOutcome::Formed);

        // Different offsets to avoid interference.
        let entries2: Vec<InstructionEntry> = (0..4)
            .map(|i| InstructionEntry {
                offset: (i + 100) as u32 * 4,
                opcode: ["Add", "Sub", "Mul", "Div"][i % 4].to_string(),
                execution_count: 200,
                type_stability_millionths: 950_000,
                has_side_effects: false,
                capabilities: BTreeSet::new(),
            })
            .collect();
        let outcome2 = engine.fuse("fn_test", &entries2, None);
        assert!(matches!(outcome2, FusionOutcome::TraceLimitExceeded { .. }));
    }

    #[test]
    fn test_engine_disable_trace() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        engine.policy.require_proof_lineage = false;
        let entries = arith_entries(4, 200);
        engine.fuse("fn_test", &entries, None);
        let trace_id = engine.active_traces.keys().next().unwrap().clone();
        assert!(engine.disable_trace(
            &trace_id,
            FusionDisableReason::OperatorDisabled {
                reason: "test".into()
            },
        ));
        assert_eq!(engine.active_count(), 0);
    }

    #[test]
    fn test_engine_enable_trace() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        engine.policy.require_proof_lineage = false;
        let entries = arith_entries(4, 200);
        engine.fuse("fn_test", &entries, None);
        let trace_id = engine.active_traces.keys().next().unwrap().clone();
        engine.disable_trace(
            &trace_id,
            FusionDisableReason::OperatorDisabled {
                reason: "test".into(),
            },
        );
        assert!(engine.enable_trace(&trace_id));
        assert_eq!(engine.active_count(), 1);
    }

    #[test]
    fn test_engine_record_execution() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        engine.policy.require_proof_lineage = false;
        let entries = arith_entries(4, 200);
        engine.fuse("fn_test", &entries, None);
        let trace_id = engine.active_traces.keys().next().unwrap().clone();
        assert!(engine.record_execution(&trace_id));
        assert!(engine.record_execution(&trace_id));
        let trace = engine.get_trace(&trace_id).unwrap();
        assert_eq!(trace.execution_count, 2);
    }

    #[test]
    fn test_engine_side_exit_auto_disable() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        engine.policy.require_proof_lineage = false;
        engine.policy.max_exit_ratio_millionths = 200_000;
        let entries = arith_entries(4, 200);
        engine.fuse("fn_test", &entries, None);
        let trace_id = engine.active_traces.keys().next().unwrap().clone();

        // 3 executions, 1 exit = 33% > 20%.
        engine.record_execution(&trace_id);
        engine.record_execution(&trace_id);
        engine.record_execution(&trace_id);
        engine.record_side_exit(&trace_id);

        let trace = engine.get_trace(&trace_id).unwrap();
        assert!(!trace.enabled);
    }

    #[test]
    fn test_engine_invalidate_proof() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        let entries = arith_entries(4, 200);
        engine.fuse("fn_test", &entries, Some(proof_lineage()));
        let trace_id = engine.active_traces.keys().next().unwrap().clone();

        engine.invalidate_proof("cap-proof-1");
        let trace = engine.get_trace(&trace_id).unwrap();
        assert!(!trace.enabled);
        assert!(matches!(
            trace.disable_reason,
            Some(FusionDisableReason::ProofInvalidated { .. })
        ));
    }

    #[test]
    fn test_engine_advance_epoch() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        engine.policy.require_proof_lineage = false;
        let entries = arith_entries(4, 200);
        engine.fuse("fn_test", &entries, None);

        engine.advance_epoch(SecurityEpoch::from_raw(5));
        let trace = engine.active_traces.values().next().unwrap();
        assert!(!trace.enabled);
    }

    #[test]
    fn test_engine_traces_for_function() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        engine.policy.require_proof_lineage = false;
        let entries = arith_entries(4, 200);
        engine.fuse("fn_a", &entries, None);

        let entries2 = prop_chain_entries(3, 200);
        engine.fuse("fn_b", &entries2, None);

        assert_eq!(engine.traces_for_function("fn_a").len(), 1);
        assert_eq!(engine.traces_for_function("fn_b").len(), 1);
        assert_eq!(engine.traces_for_function("fn_c").len(), 0);
    }

    #[test]
    fn test_engine_diagnostics() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        engine.policy.require_proof_lineage = false;
        let entries = arith_entries(4, 200);
        engine.fuse("fn_test", &entries, None);
        let diag = engine.diagnostics();
        assert_eq!(diag.total_traces, 1);
        assert_eq!(diag.active_traces, 1);
        assert_eq!(diag.fusion_attempts, 1);
        assert_eq!(diag.fusion_successes, 1);
    }

    #[test]
    fn test_engine_interference_detection() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        engine.policy.require_proof_lineage = false;
        engine.policy.max_traces_per_function = 10;
        let entries = arith_entries(4, 200);
        let outcome1 = engine.fuse("fn_test", &entries, None);
        assert_eq!(outcome1, FusionOutcome::Formed);

        // Same offsets = interference.
        let outcome2 = engine.fuse("fn_test", &entries, None);
        assert!(matches!(
            outcome2,
            FusionOutcome::InterferenceBlocked { .. }
        ));
    }

    #[test]
    fn test_engine_custom_policy() {
        let policy = FusionPolicy {
            min_observation_count: 50,
            require_proof_lineage: false,
            ..Default::default()
        };
        let mut engine = TraceFusionEngine::with_policy(policy, test_epoch());
        let entries = arith_entries(4, 60);
        let outcome = engine.fuse("fn_test", &entries, None);
        assert_eq!(outcome, FusionOutcome::Formed);
    }

    #[test]
    fn test_engine_get_nonexistent_trace() {
        let engine = TraceFusionEngine::new(test_epoch());
        assert!(engine.get_trace("nonexistent").is_none());
    }

    #[test]
    fn test_engine_disable_nonexistent() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        assert!(!engine.disable_trace(
            "nonexistent",
            FusionDisableReason::OperatorDisabled {
                reason: "test".into()
            },
        ));
    }

    #[test]
    fn test_engine_record_execution_nonexistent() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        assert!(!engine.record_execution("nonexistent"));
    }

    #[test]
    fn test_engine_record_side_exit_nonexistent() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        assert!(!engine.record_side_exit("nonexistent"));
    }

    #[test]
    fn test_engine_all_summaries() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        engine.policy.require_proof_lineage = false;
        let entries = arith_entries(4, 200);
        engine.fuse("fn_test", &entries, None);
        let summaries = engine.all_summaries();
        assert_eq!(summaries.len(), 1);
    }

    #[test]
    fn test_engine_active_summaries_excludes_disabled() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        engine.policy.require_proof_lineage = false;
        let entries = arith_entries(4, 200);
        engine.fuse("fn_test", &entries, None);
        let trace_id = engine.active_traces.keys().next().unwrap().clone();
        engine.disable_trace(
            &trace_id,
            FusionDisableReason::OperatorDisabled {
                reason: "test".into(),
            },
        );
        assert_eq!(engine.active_summaries().len(), 0);
        assert_eq!(engine.all_summaries().len(), 1);
    }

    // --- Serialization tests ---

    #[test]
    fn test_motif_kind_serde() {
        let kind = MotifKind::ArithmeticChain;
        let json = serde_json::to_string(&kind).unwrap();
        let decoded: MotifKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, decoded);
    }

    #[test]
    fn test_fusion_motif_serde() {
        let mut motif = FusionMotif::new(
            MotifKind::PropertyChain,
            vec!["GetProperty".into(), "GetProperty".into()],
            0,
            4,
        );
        motif.observation_count = 100;
        let json = serde_json::to_string(&motif).unwrap();
        let decoded: FusionMotif = serde_json::from_str(&json).unwrap();
        assert_eq!(motif, decoded);
    }

    #[test]
    fn test_proof_lineage_serde() {
        let lineage = proof_lineage();
        let json = serde_json::to_string(&lineage).unwrap();
        let decoded: FusionProofLineage = serde_json::from_str(&json).unwrap();
        assert_eq!(lineage, decoded);
    }

    #[test]
    fn test_fused_trace_serde() {
        let mut trace = FusedTrace::new("fn_test", test_epoch());
        trace.add_instruction(FusedInstruction::passthrough(0, 0, "Add"));
        let json = serde_json::to_string(&trace).unwrap();
        let decoded: FusedTrace = serde_json::from_str(&json).unwrap();
        assert_eq!(trace, decoded);
    }

    #[test]
    fn test_fusion_policy_serde() {
        let policy = FusionPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let decoded: FusionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, decoded);
    }

    #[test]
    fn test_fusion_outcome_serde() {
        let outcomes = vec![
            FusionOutcome::Formed,
            FusionOutcome::NoFusibleMotifs,
            FusionOutcome::AllMotifsRejected,
            FusionOutcome::InsufficientSavings {
                net_millionths: 10_000,
            },
            FusionOutcome::MissingProofLineage,
        ];
        for outcome in outcomes {
            let json = serde_json::to_string(&outcome).unwrap();
            let decoded: FusionOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(outcome, decoded);
        }
    }

    #[test]
    fn test_disable_reason_serde() {
        let reasons = vec![
            FusionDisableReason::ProofInvalidated {
                lineage_id: "l1".into(),
            },
            FusionDisableReason::ExcessiveSideExits {
                ratio_millionths: 300_000,
                threshold_millionths: 200_000,
            },
            FusionDisableReason::EpochAdvanced {
                formation: 1,
                current: 5,
            },
            FusionDisableReason::OperatorDisabled {
                reason: "manual".into(),
            },
        ];
        for reason in reasons {
            let json = serde_json::to_string(&reason).unwrap();
            let decoded: FusionDisableReason = serde_json::from_str(&json).unwrap();
            assert_eq!(reason, decoded);
        }
    }

    #[test]
    fn test_fusion_guard_kind_serde() {
        let kinds = vec![
            FusionGuardKind::TypeStability {
                expected_type: "Integer".into(),
            },
            FusionGuardKind::ShapeCheck {
                expected_shape_id: "s1".into(),
            },
            FusionGuardKind::CapabilityValid {
                capability_name: "fs.read".into(),
            },
            FusionGuardKind::LevelCheck { min_level: 2 },
            FusionGuardKind::ProofValid {
                lineage_id: "l1".into(),
            },
        ];
        for kind in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            let decoded: FusionGuardKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, decoded);
        }
    }

    #[test]
    fn test_fusion_record_serde() {
        let record = FusionRecord::new("fn_test", test_epoch());
        let json = serde_json::to_string(&record).unwrap();
        let decoded: FusionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record.function_id, decoded.function_id);
    }

    #[test]
    fn test_diagnostics_serde() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        engine.policy.require_proof_lineage = false;
        let entries = arith_entries(4, 200);
        engine.fuse("fn_test", &entries, None);
        let diag = engine.diagnostics();
        let json = serde_json::to_string(&diag).unwrap();
        let decoded: TraceFusionDiagnostics = serde_json::from_str(&json).unwrap();
        assert_eq!(diag, decoded);
    }

    // --- Edge case tests ---

    #[test]
    fn test_empty_entries() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        engine.policy.require_proof_lineage = false;
        let outcome = engine.fuse("fn_test", &[], None);
        assert_eq!(outcome, FusionOutcome::NoFusibleMotifs);
    }

    #[test]
    fn test_single_instruction() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        engine.policy.require_proof_lineage = false;
        let entries = vec![InstructionEntry {
            offset: 0,
            opcode: "Add".into(),
            execution_count: 200,
            type_stability_millionths: 950_000,
            has_side_effects: false,
            capabilities: BTreeSet::new(),
        }];
        let outcome = engine.fuse("fn_test", &entries, None);
        assert_eq!(outcome, FusionOutcome::NoFusibleMotifs);
    }

    #[test]
    fn test_property_chain_fusion() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        engine.policy.require_proof_lineage = false;
        let entries = prop_chain_entries(4, 200);
        let outcome = engine.fuse("fn_test", &entries, None);
        assert_eq!(outcome, FusionOutcome::Formed);
        let trace = engine.active_traces.values().next().unwrap();
        assert!(trace.super_instruction_count() > 0);
    }

    #[test]
    fn test_hostcall_fusion_rejected_effectful() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        engine.policy.require_proof_lineage = false;
        let entries = hostcall_entries(3, 200);
        let outcome = engine.fuse("fn_test", &entries, None);
        assert_eq!(outcome, FusionOutcome::AllMotifsRejected);
    }

    #[test]
    fn test_hostcall_fusion_with_effectful_allowed() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        engine.policy.require_proof_lineage = false;
        engine.policy.allow_effectful_fusion = true;
        let entries = hostcall_entries(3, 200);
        let outcome = engine.fuse("fn_test", &entries, None);
        assert_eq!(outcome, FusionOutcome::Formed);
    }

    #[test]
    fn test_mixed_instructions_partial_fusion() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        engine.policy.require_proof_lineage = false;
        let mut entries = vec![];
        // prefix: LoadInt
        entries.push(InstructionEntry {
            offset: 0,
            opcode: "LoadInt".into(),
            execution_count: 200,
            type_stability_millionths: 1_000_000,
            has_side_effects: false,
            capabilities: BTreeSet::new(),
        });
        // arith chain
        for i in 1..=4 {
            entries.push(InstructionEntry {
                offset: i * 4,
                opcode: ["Add", "Sub", "Mul", "Div"][(i - 1) as usize % 4].into(),
                execution_count: 200,
                type_stability_millionths: 950_000,
                has_side_effects: false,
                capabilities: BTreeSet::new(),
            });
        }
        // suffix: Return
        entries.push(InstructionEntry {
            offset: 20,
            opcode: "Return".into(),
            execution_count: 200,
            type_stability_millionths: 1_000_000,
            has_side_effects: false,
            capabilities: BTreeSet::new(),
        });

        let outcome = engine.fuse("fn_test", &entries, None);
        assert_eq!(outcome, FusionOutcome::Formed);
        let trace = engine.active_traces.values().next().unwrap();
        // Should have some passthrough + some fused.
        assert!(trace.instruction_count() < entries.len());
        assert!(trace.super_instruction_count() > 0);
    }

    #[test]
    fn test_insufficient_savings() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        engine.policy.require_proof_lineage = false;
        engine.policy.min_net_savings_millionths = 999_999_999;
        let entries = arith_entries(4, 200);
        let outcome = engine.fuse("fn_test", &entries, None);
        assert!(matches!(outcome, FusionOutcome::InsufficientSavings { .. }));
    }

    #[test]
    fn test_multiple_functions_independent() {
        let mut engine = TraceFusionEngine::new(test_epoch());
        engine.policy.require_proof_lineage = false;
        let entries_a = arith_entries(4, 200);
        let entries_b = prop_chain_entries(3, 200);
        engine.fuse("fn_a", &entries_a, None);
        engine.fuse("fn_b", &entries_b, None);
        assert_eq!(engine.total_count(), 2);
        assert_eq!(engine.active_count(), 2);
    }

    #[test]
    fn test_recognizer_default() {
        let rec = MotifRecognizer::default();
        assert_eq!(rec.entry_count(), 0);
    }

    #[test]
    fn test_catalog_default() {
        let cat = FusionTemplateCatalog::default();
        assert!(cat.template_count() >= 6);
    }

    #[test]
    fn test_trace_guard_count() {
        let mut trace = FusedTrace::new("fn_test", test_epoch());
        let guard = FusionGuard::new(
            FusionGuardKind::TypeStability {
                expected_type: "Integer".into(),
            },
            0,
        );
        trace.add_instruction(FusedInstruction::passthrough(0, 0, "Add").with_guard(guard));
        trace.add_instruction(FusedInstruction::passthrough(1, 4, "Sub"));
        assert_eq!(trace.guard_count(), 1);
    }

    #[test]
    fn test_proof_lineage_empty() {
        let lineage = FusionProofLineage::new(vec![], vec![], test_epoch());
        assert_eq!(lineage.proof_count(), 0);
        assert!(lineage.is_valid_at(test_epoch()));
    }

    #[test]
    fn test_schema_version_constant() {
        assert_eq!(
            TRACE_FUSION_SCHEMA_VERSION,
            "franken-engine.trace-fusion.v1"
        );
    }
}
