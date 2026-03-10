//! Superblock formation and deterministic trace-tree construction.
//!
//! This module implements the superblock and trace-tree pipeline for the
//! optimizing compiler tier. It consumes quickening profiles to identify
//! hot instruction sequences, forms superblocks with guard factoring,
//! and constructs trace trees with deterministic side-exit stitching.
//!
//! Key invariants:
//! - Superblock boundaries are deterministic given the same input profile
//! - Guard factoring merges redundant guards without altering observable behavior
//! - Side exits are totally ordered and content-addressed for replay stability
//! - Tail duplication is bounded by a configurable budget

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::quickening_feedback_lattice::{QuickeningLevel, QuickeningProfile};
use crate::stage_envelope_certificate::ExecutionStage;
use crate::tier_up_profiler::{TierUpCandidate, TierUpDecision};

pub const COMPONENT: &str = "superblock_formation";
pub const SUPERBLOCK_SCHEMA_VERSION: &str = "franken-engine.superblock.v1";
pub const TRACE_TREE_SCHEMA_VERSION: &str = "franken-engine.trace-tree.v1";
pub const OPTIMIZED_TIER_PLAN_SCHEMA_VERSION: &str = "franken-engine.optimized-tier-plan.v1";

// ---------------------------------------------------------------------------
// SuperblockPolicy — formation thresholds
// ---------------------------------------------------------------------------

/// Policy parameters governing superblock formation and trace-tree depth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuperblockPolicy {
    /// Minimum quickening level to include an instruction in a superblock.
    pub min_level: QuickeningLevel,
    /// Maximum instructions in a single superblock.
    pub max_block_length: usize,
    /// Maximum tail-duplication budget (instruction copies allowed).
    pub max_tail_duplication: usize,
    /// Maximum depth of a trace tree.
    pub max_trace_depth: usize,
    /// Maximum number of side exits per superblock.
    pub max_side_exits: usize,
    /// Minimum execution count to consider an instruction for inclusion.
    pub min_execution_count: u64,
    /// Whether to enable guard factoring (merge redundant guards).
    pub enable_guard_factoring: bool,
}

impl Default for SuperblockPolicy {
    fn default() -> Self {
        Self {
            min_level: QuickeningLevel::Hot,
            max_block_length: 64,
            max_tail_duplication: 32,
            max_trace_depth: 8,
            max_side_exits: 16,
            min_execution_count: 32,
            enable_guard_factoring: true,
        }
    }
}

impl SuperblockPolicy {
    pub fn policy_hash(&self) -> String {
        let payload = serde_json::to_vec(self).expect("policy must serialize");
        let digest = Sha256::digest(payload);
        hex::encode(digest)
    }
}

// ---------------------------------------------------------------------------
// GuardKind — types of deopt guards
// ---------------------------------------------------------------------------

/// Kind of guard that protects a specialized superblock.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GuardKind {
    /// Shape check: object must have the expected hidden class.
    ShapeCheck { expected_shape_id: String },
    /// Type check: operand must be the expected type.
    TypeCheck { expected_type: String },
    /// Range check: index must be within bounds.
    RangeCheck { lower: i64, upper: i64 },
    /// IC stability: inline cache must still be monomorphic.
    IcStability { ic_offset: u32 },
    /// Overflow check: arithmetic must not overflow.
    OverflowCheck,
    /// Prototype chain: prototype must not have changed.
    PrototypeChain { expected_hash: String },
}

impl fmt::Display for GuardKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShapeCheck { expected_shape_id } => {
                write!(f, "shape-check({})", expected_shape_id)
            }
            Self::TypeCheck { expected_type } => write!(f, "type-check({})", expected_type),
            Self::RangeCheck { lower, upper } => write!(f, "range-check([{}, {}])", lower, upper),
            Self::IcStability { ic_offset } => write!(f, "ic-stability(@{})", ic_offset),
            Self::OverflowCheck => write!(f, "overflow-check"),
            Self::PrototypeChain { expected_hash } => {
                write!(f, "proto-chain({})", expected_hash)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SuperblockGuard — positioned guard within a superblock
// ---------------------------------------------------------------------------

/// A guard at a specific position within a superblock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuperblockGuard {
    /// Position within the superblock (instruction index).
    pub position: u32,
    /// Original bytecode offset this guard corresponds to.
    pub source_offset: u32,
    /// The kind of guard.
    pub kind: GuardKind,
    /// Side-exit ID if this guard fails.
    pub side_exit_id: String,
    /// Whether this guard has been factored (merged with another).
    pub factored: bool,
}

impl SuperblockGuard {
    pub fn new(position: u32, source_offset: u32, kind: GuardKind, side_exit_id: String) -> Self {
        Self {
            position,
            source_offset,
            kind,
            side_exit_id,
            factored: false,
        }
    }
}

impl fmt::Display for SuperblockGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tag = if self.factored { " [factored]" } else { "" };
        write!(
            f,
            "guard@{} (src={}): {} → exit:{}{}",
            self.position, self.source_offset, self.kind, self.side_exit_id, tag
        )
    }
}

// ---------------------------------------------------------------------------
// SideExit — deterministic side-exit descriptor
// ---------------------------------------------------------------------------

/// A side exit from a superblock back to the interpreter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SideExit {
    /// Content-addressed unique ID.
    pub exit_id: String,
    /// Bytecode offset to resume at.
    pub resume_offset: u32,
    /// Guard position that triggers this exit.
    pub guard_position: u32,
    /// Reason for the exit (for diagnostics).
    pub reason: SideExitReason,
    /// Number of times this exit has been taken (for trace tree growth).
    pub taken_count: u64,
    /// Whether this exit has been compiled into a trace branch.
    pub compiled_branch: bool,
}

impl SideExit {
    pub fn new(resume_offset: u32, guard_position: u32, reason: SideExitReason) -> Self {
        let exit_id = Self::compute_id(resume_offset, guard_position, &reason);
        Self {
            exit_id,
            resume_offset,
            guard_position,
            reason,
            taken_count: 0,
            compiled_branch: false,
        }
    }

    fn compute_id(resume_offset: u32, guard_position: u32, reason: &SideExitReason) -> String {
        let mut hasher = Sha256::new();
        hasher.update(resume_offset.to_le_bytes());
        hasher.update(guard_position.to_le_bytes());
        let reason_bytes = serde_json::to_vec(reason).expect("reason must serialize");
        hasher.update(&reason_bytes);
        let digest = hasher.finalize();
        format!("exit-{}", &hex::encode(digest)[..16])
    }

    pub fn record_taken(&mut self) {
        self.taken_count = self.taken_count.saturating_add(1);
    }

    /// Whether this exit is hot enough to warrant trace extension.
    pub fn is_hot(&self, threshold: u64) -> bool {
        self.taken_count >= threshold
    }
}

impl fmt::Display for SideExit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: resume@{} (guard@{}, {}, taken={})",
            self.exit_id, self.resume_offset, self.guard_position, self.reason, self.taken_count
        )
    }
}

/// Reason a side exit was taken.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SideExitReason {
    GuardFailure,
    OverflowDetected,
    TypeMismatch,
    ShapeMismatch,
    IcMegamorphic,
    PrototypeInvalidated,
    UnexpectedControlFlow,
}

impl fmt::Display for SideExitReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GuardFailure => write!(f, "guard-failure"),
            Self::OverflowDetected => write!(f, "overflow"),
            Self::TypeMismatch => write!(f, "type-mismatch"),
            Self::ShapeMismatch => write!(f, "shape-mismatch"),
            Self::IcMegamorphic => write!(f, "ic-megamorphic"),
            Self::PrototypeInvalidated => write!(f, "proto-invalidated"),
            Self::UnexpectedControlFlow => write!(f, "unexpected-cf"),
        }
    }
}

// ---------------------------------------------------------------------------
// Optimized-tier planning artifacts
// ---------------------------------------------------------------------------

/// Backend selected for optimized tier compilation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptimizedTierBackend {
    Cranelift,
}

impl fmt::Display for OptimizedTierBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cranelift => write!(f, "cranelift"),
        }
    }
}

/// Runtime tier used when a guard fails and optimized execution must resume safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackTier {
    BaselineInterpreter,
}

impl fmt::Display for FallbackTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BaselineInterpreter => write!(f, "baseline_interpreter"),
        }
    }
}

/// Deterministic continuation point when an optimized guard fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeoptContinuation {
    pub checkpoint_id: String,
    pub guard_position: u32,
    pub source_offset: u32,
    pub guard_kind: GuardKind,
    pub side_exit_id: String,
    pub resume_offset: u32,
    pub fallback_tier: FallbackTier,
    pub reason: SideExitReason,
    pub factored: bool,
}

impl DeoptContinuation {
    fn from_guard(guard: &SuperblockGuard, exit: &SideExit) -> Self {
        #[derive(Serialize)]
        struct CheckpointEnvelope<'a> {
            guard_position: u32,
            source_offset: u32,
            guard_kind: &'a GuardKind,
            side_exit_id: &'a str,
            resume_offset: u32,
            reason: &'a SideExitReason,
            factored: bool,
        }

        let digest = Sha256::digest(
            serde_json::to_vec(&CheckpointEnvelope {
                guard_position: guard.position,
                source_offset: guard.source_offset,
                guard_kind: &guard.kind,
                side_exit_id: &guard.side_exit_id,
                resume_offset: exit.resume_offset,
                reason: &exit.reason,
                factored: guard.factored,
            })
            .expect("deopt checkpoint payload must serialize"),
        );

        Self {
            checkpoint_id: format!("deopt-{}", &hex::encode(digest)[..16]),
            guard_position: guard.position,
            source_offset: guard.source_offset,
            guard_kind: guard.kind.clone(),
            side_exit_id: guard.side_exit_id.clone(),
            resume_offset: exit.resume_offset,
            fallback_tier: FallbackTier::BaselineInterpreter,
            reason: exit.reason.clone(),
            factored: guard.factored,
        }
    }
}

/// Reason an optimized compilation candidate was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompilationRejectReason {
    TierUpIneligible,
    SuperblockFormationRejected,
    DuplicateCandidateOffset,
}

/// Deterministic rejection record for one compilation candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizedCompilationReject {
    pub candidate_id: String,
    pub candidate: TierUpCandidate,
    pub reason: CompilationRejectReason,
    pub formation_outcome: Option<FormationOutcome>,
    pub detail: String,
}

/// One optimized compilation unit ready for backend lowering and validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizedCompilationUnit {
    pub compilation_unit_id: String,
    pub candidate_id: String,
    pub backend: OptimizedTierBackend,
    pub stage: ExecutionStage,
    pub candidate: TierUpCandidate,
    pub block: Superblock,
    pub deopt_continuations: Vec<DeoptContinuation>,
    pub requires_differential_equivalence: bool,
}

impl OptimizedCompilationUnit {
    fn from_candidate(trace_id: &str, candidate: TierUpCandidate, block: Superblock) -> Self {
        #[derive(Serialize)]
        struct UnitEnvelope<'a> {
            trace_id: &'a str,
            candidate_id: &'a str,
            block_id: &'a str,
            backend: OptimizedTierBackend,
            stage: ExecutionStage,
        }

        let candidate_id = candidate.candidate_id(trace_id);
        let digest = Sha256::digest(
            serde_json::to_vec(&UnitEnvelope {
                trace_id,
                candidate_id: &candidate_id,
                block_id: &block.block_id,
                backend: OptimizedTierBackend::Cranelift,
                stage: ExecutionStage::CompileOptimized,
            })
            .expect("optimized compilation unit payload must serialize"),
        );

        Self {
            compilation_unit_id: format!("ocu-{}", &hex::encode(digest)[..16]),
            candidate_id,
            backend: OptimizedTierBackend::Cranelift,
            stage: ExecutionStage::CompileOptimized,
            deopt_continuations: block.deopt_continuations(),
            candidate,
            block,
            requires_differential_equivalence: true,
        }
    }
}

/// End-to-end optimized-tier plan tying tier-up to backend compilation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizedTierCompilationPlan {
    pub schema_version: String,
    pub trace_id: String,
    pub function_id: String,
    pub tier_up_eligible: bool,
    pub backend: OptimizedTierBackend,
    pub stage: ExecutionStage,
    pub tier_up_decision_hash: String,
    pub tier_up_policy_hash: String,
    pub superblock_policy_hash: String,
    pub formation_epoch: u64,
    pub units: Vec<OptimizedCompilationUnit>,
    pub rejected_candidates: Vec<OptimizedCompilationReject>,
    pub requires_differential_equivalence: bool,
    pub plan_hash: String,
}

impl OptimizedTierCompilationPlan {
    pub fn build(
        decision: &TierUpDecision,
        profile: &QuickeningProfile,
        policy: &SuperblockPolicy,
        formation_epoch: u64,
    ) -> Self {
        let mut units = Vec::new();
        let mut rejected_candidates = Vec::new();
        let mut seen_offsets = BTreeSet::new();

        if decision.eligible {
            for candidate in &decision.selected_candidates {
                let candidate_id = candidate.candidate_id(&decision.trace_id);
                if !seen_offsets.insert(candidate.ip) {
                    rejected_candidates.push(OptimizedCompilationReject {
                        candidate_id,
                        candidate: candidate.clone(),
                        reason: CompilationRejectReason::DuplicateCandidateOffset,
                        formation_outcome: None,
                        detail: format!("duplicate candidate offset {}", candidate.ip),
                    });
                    continue;
                }

                let record = form_superblock(profile, candidate.ip, policy, formation_epoch);
                match record.outcome {
                    FormationOutcome::Formed => {
                        let block = record
                            .block
                            .expect("formed superblock records must include a block");
                        units.push(OptimizedCompilationUnit::from_candidate(
                            &decision.trace_id,
                            candidate.clone(),
                            block,
                        ));
                    }
                    outcome => {
                        rejected_candidates.push(OptimizedCompilationReject {
                            candidate_id,
                            candidate: candidate.clone(),
                            reason: CompilationRejectReason::SuperblockFormationRejected,
                            formation_outcome: Some(outcome.clone()),
                            detail: format!(
                                "candidate entry@{} rejected during superblock formation: {}",
                                candidate.ip, outcome
                            ),
                        });
                    }
                }
            }
        } else {
            rejected_candidates.extend(decision.selected_candidates.iter().cloned().map(
                |candidate| OptimizedCompilationReject {
                    candidate_id: candidate.candidate_id(&decision.trace_id),
                    candidate,
                    reason: CompilationRejectReason::TierUpIneligible,
                    formation_outcome: None,
                    detail: "tier-up decision was not eligible".to_string(),
                },
            ));
        }

        let mut plan = Self {
            schema_version: OPTIMIZED_TIER_PLAN_SCHEMA_VERSION.to_string(),
            trace_id: decision.trace_id.clone(),
            function_id: profile.function_id.clone(),
            tier_up_eligible: decision.eligible,
            backend: OptimizedTierBackend::Cranelift,
            stage: ExecutionStage::CompileOptimized,
            tier_up_decision_hash: decision.decision_hash.clone(),
            tier_up_policy_hash: decision.policy_hash.clone(),
            superblock_policy_hash: policy.policy_hash(),
            formation_epoch,
            units,
            rejected_candidates,
            requires_differential_equivalence: true,
            plan_hash: String::new(),
        };
        plan.plan_hash = compute_optimized_tier_plan_hash(&plan);
        plan
    }

    pub fn compilable_unit_count(&self) -> usize {
        self.units.len()
    }
}

// ---------------------------------------------------------------------------
// SuperblockEntry — instruction within a superblock
// ---------------------------------------------------------------------------

/// An instruction entry within a formed superblock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuperblockEntry {
    /// Position within the superblock.
    pub position: u32,
    /// Original bytecode offset.
    pub source_offset: u32,
    /// Opcode name.
    pub opcode: String,
    /// Whether this entry is a tail-duplicated copy.
    pub is_tail_duplicate: bool,
    /// Execution count from profiling.
    pub execution_count: u64,
}

// ---------------------------------------------------------------------------
// Superblock — formed hot region
// ---------------------------------------------------------------------------

/// A formed superblock: a linear sequence of hot instructions with guards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Superblock {
    /// Content-addressed superblock ID.
    pub block_id: String,
    /// Function this superblock belongs to.
    pub function_id: String,
    /// Entry offset (first instruction's bytecode offset).
    pub entry_offset: u32,
    /// Ordered instruction entries.
    pub entries: Vec<SuperblockEntry>,
    /// Guards protecting this superblock.
    pub guards: Vec<SuperblockGuard>,
    /// Side exits from this superblock.
    pub side_exits: Vec<SideExit>,
    /// Number of instructions that are tail duplicates.
    pub tail_duplication_count: u32,
    /// Formation epoch (increases on rebuild).
    pub formation_epoch: u64,
}

impl Superblock {
    pub fn instruction_count(&self) -> usize {
        self.entries.len()
    }

    pub fn guard_count(&self) -> usize {
        self.guards.len()
    }

    pub fn side_exit_count(&self) -> usize {
        self.side_exits.len()
    }

    pub fn factored_guard_count(&self) -> usize {
        self.guards.iter().filter(|g| g.factored).count()
    }

    /// Compute content-addressed block ID from entries.
    pub fn compute_block_id(function_id: &str, entries: &[SuperblockEntry]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(function_id.as_bytes());
        for entry in entries {
            hasher.update(entry.source_offset.to_le_bytes());
            hasher.update(entry.opcode.as_bytes());
        }
        let digest = hasher.finalize();
        format!("sb-{}", &hex::encode(digest)[..16])
    }

    /// Record a side exit taken and return whether the exit is now hot.
    pub fn record_side_exit(&mut self, exit_id: &str, hot_threshold: u64) -> bool {
        if let Some(exit) = self.side_exits.iter_mut().find(|e| e.exit_id == exit_id) {
            exit.record_taken();
            exit.is_hot(hot_threshold)
        } else {
            false
        }
    }

    /// Get all hot side exits above the given threshold.
    pub fn hot_side_exits(&self, threshold: u64) -> Vec<&SideExit> {
        self.side_exits
            .iter()
            .filter(|e| e.is_hot(threshold))
            .collect()
    }

    /// Ordered deoptimization continuations derived from guards and side exits.
    pub fn deopt_continuations(&self) -> Vec<DeoptContinuation> {
        let mut continuations = self
            .guards
            .iter()
            .filter_map(|guard| {
                self.side_exits
                    .iter()
                    .find(|exit| exit.exit_id == guard.side_exit_id)
                    .map(|exit| DeoptContinuation::from_guard(guard, exit))
            })
            .collect::<Vec<_>>();

        continuations.sort_by(|left, right| {
            left.guard_position
                .cmp(&right.guard_position)
                .then_with(|| left.resume_offset.cmp(&right.resume_offset))
                .then_with(|| left.checkpoint_id.cmp(&right.checkpoint_id))
        });
        continuations
    }
}

impl fmt::Display for Superblock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "superblock {} (fn={}, entry@{}, {} instrs, {} guards, {} exits, {} tail-dups)",
            self.block_id,
            self.function_id,
            self.entry_offset,
            self.instruction_count(),
            self.guard_count(),
            self.side_exit_count(),
            self.tail_duplication_count
        )
    }
}

// ---------------------------------------------------------------------------
// TraceTreeNode — node in a trace tree
// ---------------------------------------------------------------------------

/// A node in the trace tree. Each node contains a superblock plus
/// branching information for trace-tree growth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceTreeNode {
    /// Superblock at this node.
    pub block: Superblock,
    /// Depth in the trace tree (root = 0).
    pub depth: u32,
    /// Children indexed by side-exit ID.
    pub children: BTreeMap<String, usize>,
}

/// A trace tree: a tree of superblocks connected by compiled side exits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceTree {
    /// Content-addressed trace tree ID.
    pub tree_id: String,
    /// Schema version.
    pub schema_version: String,
    /// Function this trace tree covers.
    pub function_id: String,
    /// Nodes in pre-order (index 0 = root).
    pub nodes: Vec<TraceTreeNode>,
    /// Maximum depth reached.
    pub max_depth: u32,
    /// Formation epoch.
    pub formation_epoch: u64,
}

impl TraceTree {
    pub fn new(function_id: impl Into<String>, root_block: Superblock) -> Self {
        let function_id = function_id.into();
        let root = TraceTreeNode {
            block: root_block,
            depth: 0,
            children: BTreeMap::new(),
        };
        let tree_id = Self::compute_tree_id(&function_id, &[&root]);
        Self {
            tree_id,
            schema_version: TRACE_TREE_SCHEMA_VERSION.to_string(),
            function_id,
            nodes: vec![root],
            max_depth: 0,
            formation_epoch: 1,
        }
    }

    fn compute_tree_id(function_id: &str, nodes: &[&TraceTreeNode]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(function_id.as_bytes());
        for node in nodes {
            hasher.update(node.block.block_id.as_bytes());
            hasher.update(node.depth.to_le_bytes());
        }
        let digest = hasher.finalize();
        format!("tt-{}", &hex::encode(digest)[..16])
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn root(&self) -> Option<&TraceTreeNode> {
        self.nodes.first()
    }

    /// Extend the trace tree at a hot side exit.
    /// Returns true if the extension was added.
    pub fn extend_at_exit(
        &mut self,
        parent_index: usize,
        exit_id: &str,
        new_block: Superblock,
        policy: &SuperblockPolicy,
    ) -> bool {
        let parent_depth = match self.nodes.get(parent_index) {
            Some(n) => n.depth,
            None => return false,
        };

        if parent_depth as usize >= policy.max_trace_depth {
            return false;
        }

        let new_depth = parent_depth + 1;
        let new_index = self.nodes.len();

        let child = TraceTreeNode {
            block: new_block,
            depth: new_depth,
            children: BTreeMap::new(),
        };

        self.nodes.push(child);

        if let Some(parent) = self.nodes.get_mut(parent_index) {
            parent.children.insert(exit_id.to_string(), new_index);
        }

        if new_depth > self.max_depth {
            self.max_depth = new_depth;
        }

        self.formation_epoch = self.formation_epoch.saturating_add(1);
        self.tree_id =
            Self::compute_tree_id(&self.function_id, &self.nodes.iter().collect::<Vec<_>>());

        true
    }

    /// Get a node by index.
    pub fn get_node(&self, index: usize) -> Option<&TraceTreeNode> {
        self.nodes.get(index)
    }

    /// Total instruction count across all nodes.
    pub fn total_instructions(&self) -> usize {
        self.nodes.iter().map(|n| n.block.instruction_count()).sum()
    }

    /// Total guard count across all nodes.
    pub fn total_guards(&self) -> usize {
        self.nodes.iter().map(|n| n.block.guard_count()).sum()
    }

    /// Summary of the trace tree.
    pub fn summary(&self) -> TraceTreeSummary {
        TraceTreeSummary {
            tree_id: self.tree_id.clone(),
            function_id: self.function_id.clone(),
            node_count: self.nodes.len() as u32,
            max_depth: self.max_depth,
            total_instructions: self.total_instructions() as u32,
            total_guards: self.total_guards() as u32,
            formation_epoch: self.formation_epoch,
        }
    }
}

impl fmt::Display for TraceTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "trace-tree {} (fn={}, {} nodes, depth={}, {} instrs, epoch={})",
            self.tree_id,
            self.function_id,
            self.node_count(),
            self.max_depth,
            self.total_instructions(),
            self.formation_epoch
        )
    }
}

/// Summary of a trace tree for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceTreeSummary {
    pub tree_id: String,
    pub function_id: String,
    pub node_count: u32,
    pub max_depth: u32,
    pub total_instructions: u32,
    pub total_guards: u32,
    pub formation_epoch: u64,
}

// ---------------------------------------------------------------------------
// SuperblockFormationResult — outcome of superblock formation
// ---------------------------------------------------------------------------

/// Result of attempting to form a superblock from profiling data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FormationOutcome {
    /// Superblock was successfully formed.
    Formed,
    /// Rejected: not enough hot instructions.
    InsufficientHotInstructions,
    /// Rejected: block would exceed size limit.
    ExceedsBlockSize,
    /// Rejected: too many guards needed.
    ExcessiveGuards,
    /// Rejected: no eligible instructions found.
    NoEligibleInstructions,
}

impl fmt::Display for FormationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Formed => write!(f, "formed"),
            Self::InsufficientHotInstructions => write!(f, "insufficient-hot"),
            Self::ExceedsBlockSize => write!(f, "exceeds-block-size"),
            Self::ExcessiveGuards => write!(f, "excessive-guards"),
            Self::NoEligibleInstructions => write!(f, "no-eligible"),
        }
    }
}

/// Record of a superblock formation attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormationRecord {
    pub function_id: String,
    pub entry_offset: u32,
    pub outcome: FormationOutcome,
    pub instructions_considered: u32,
    pub instructions_included: u32,
    pub guards_generated: u32,
    pub tail_duplications: u32,
    pub block: Option<Superblock>,
}

// ---------------------------------------------------------------------------
// Formation engine — the core algorithm
// ---------------------------------------------------------------------------

/// Form a superblock from a quickening profile starting at a given offset.
///
/// This scans forward from `start_offset` through the profile, collecting
/// hot instructions into a linear superblock. Guards are inserted at
/// type-check and IC-check boundaries.
pub fn form_superblock(
    profile: &QuickeningProfile,
    start_offset: u32,
    policy: &SuperblockPolicy,
    formation_epoch: u64,
) -> FormationRecord {
    let mut entries = Vec::new();
    let mut guards = Vec::new();
    let mut side_exits = Vec::new();
    let mut current_offset = start_offset;
    let mut instructions_considered: u32 = 0;
    let mut tail_duplications: u32 = 0;
    let mut seen_offsets = BTreeSet::new();

    // Scan forward collecting hot instructions
    loop {
        if entries.len() >= policy.max_block_length {
            break;
        }

        let feedback = match profile.get(current_offset) {
            Some(fb) => fb,
            None => break,
        };

        instructions_considered = instructions_considered.saturating_add(1);

        // Check minimum level
        if feedback.level < policy.min_level {
            break;
        }

        // Check minimum execution count
        if feedback.execution_count < policy.min_execution_count {
            break;
        }

        let is_duplicate = seen_offsets.contains(&current_offset);
        if is_duplicate {
            if tail_duplications as usize >= policy.max_tail_duplication {
                break;
            }
            tail_duplications = tail_duplications.saturating_add(1);
        }
        seen_offsets.insert(current_offset);

        let position = entries.len() as u32;

        // Generate type guards for type-constrained slots
        for slot in &feedback.type_slots {
            if slot.is_monomorphic()
                && let Some(mono_type) = slot.monomorphic_type()
            {
                let guard_kind = GuardKind::TypeCheck {
                    expected_type: format!("{}", mono_type),
                };
                let exit = SideExit::new(current_offset, position, SideExitReason::TypeMismatch);
                let guard = SuperblockGuard::new(
                    position,
                    current_offset,
                    guard_kind,
                    exit.exit_id.clone(),
                );
                if side_exits.len() < policy.max_side_exits {
                    side_exits.push(exit);
                    guards.push(guard);
                }
            }
        }

        // Generate IC stability guard if IC hit rate is high
        if feedback.ic_hit_rate_millionths >= 900_000 {
            let guard_kind = GuardKind::IcStability {
                ic_offset: current_offset,
            };
            let exit = SideExit::new(current_offset, position, SideExitReason::IcMegamorphic);
            let guard =
                SuperblockGuard::new(position, current_offset, guard_kind, exit.exit_id.clone());
            if side_exits.len() < policy.max_side_exits {
                side_exits.push(exit);
                guards.push(guard);
            }
        }

        entries.push(SuperblockEntry {
            position,
            source_offset: current_offset,
            opcode: feedback.opcode.clone(),
            is_tail_duplicate: is_duplicate,
            execution_count: feedback.execution_count,
        });

        // Advance to next offset (assuming 4-byte instruction width)
        current_offset = current_offset.saturating_add(4);
    }

    if entries.is_empty() {
        return FormationRecord {
            function_id: profile.function_id.clone(),
            entry_offset: start_offset,
            outcome: FormationOutcome::NoEligibleInstructions,
            instructions_considered,
            instructions_included: 0,
            guards_generated: 0,
            tail_duplications,
            block: None,
        };
    }

    if entries.len() < 2 {
        return FormationRecord {
            function_id: profile.function_id.clone(),
            entry_offset: start_offset,
            outcome: FormationOutcome::InsufficientHotInstructions,
            instructions_considered,
            instructions_included: entries.len() as u32,
            guards_generated: guards.len() as u32,
            tail_duplications,
            block: None,
        };
    }

    // Factor guards if enabled
    if policy.enable_guard_factoring {
        factor_guards(&mut guards);
    }

    let block_id = Superblock::compute_block_id(&profile.function_id, &entries);
    let instructions_included = entries.len() as u32;
    let guards_generated = guards.len() as u32;

    let block = Superblock {
        block_id,
        function_id: profile.function_id.clone(),
        entry_offset: start_offset,
        entries,
        guards,
        side_exits,
        tail_duplication_count: tail_duplications,
        formation_epoch,
    };

    FormationRecord {
        function_id: profile.function_id.clone(),
        entry_offset: start_offset,
        outcome: FormationOutcome::Formed,
        instructions_considered,
        instructions_included,
        guards_generated,
        tail_duplications,
        block: Some(block),
    }
}

/// Factor guards by merging adjacent guards of the same kind.
///
/// When two consecutive guards check the same property (e.g., same type check
/// at adjacent positions), the earlier one is marked as factored and its
/// side exit is redirected to the later guard's exit.
fn factor_guards(guards: &mut [SuperblockGuard]) {
    if guards.len() < 2 {
        return;
    }

    for i in 0..guards.len() - 1 {
        // Check if adjacent guards are of the same kind
        if guards[i].kind == guards[i + 1].kind && !guards[i].factored {
            guards[i].factored = true;
            guards[i].side_exit_id = guards[i + 1].side_exit_id.clone();
        }
    }
}

/// Form all superblocks for a function from its quickening profile.
pub fn form_all_superblocks(
    profile: &QuickeningProfile,
    policy: &SuperblockPolicy,
    formation_epoch: u64,
) -> Vec<FormationRecord> {
    let hot_offsets = profile.instructions_at_level(policy.min_level);
    let mut records = Vec::new();
    let mut covered_offsets = BTreeSet::new();

    for offset in hot_offsets {
        if covered_offsets.contains(&offset) {
            continue;
        }

        let record = form_superblock(profile, offset, policy, formation_epoch);

        if let Some(block) = &record.block {
            for entry in &block.entries {
                covered_offsets.insert(entry.source_offset);
            }
        }

        records.push(record);
    }

    records
}

/// Build a trace tree from an initial superblock.
pub fn build_trace_tree(function_id: impl Into<String>, root_block: Superblock) -> TraceTree {
    TraceTree::new(function_id, root_block)
}

/// Emit a formation decision record with content-addressed hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormationDecision {
    pub schema_version: String,
    pub function_id: String,
    pub policy_hash: String,
    pub formation_epoch: u64,
    pub records: Vec<FormationRecord>,
    pub trace_tree_summary: Option<TraceTreeSummary>,
    pub decision_hash: String,
}

impl FormationDecision {
    pub fn build(
        function_id: impl Into<String>,
        policy: &SuperblockPolicy,
        formation_epoch: u64,
        records: Vec<FormationRecord>,
        trace_tree: Option<&TraceTree>,
    ) -> Self {
        let mut decision = Self {
            schema_version: SUPERBLOCK_SCHEMA_VERSION.to_string(),
            function_id: function_id.into(),
            policy_hash: policy.policy_hash(),
            formation_epoch,
            records,
            trace_tree_summary: trace_tree.map(|t| t.summary()),
            decision_hash: String::new(),
        };
        let payload = serde_json::to_vec(&decision).expect("decision must serialize");
        let digest = Sha256::digest(payload);
        decision.decision_hash = hex::encode(digest);
        decision
    }

    pub fn formed_count(&self) -> usize {
        self.records
            .iter()
            .filter(|r| r.outcome == FormationOutcome::Formed)
            .count()
    }

    pub fn rejected_count(&self) -> usize {
        self.records
            .iter()
            .filter(|r| r.outcome != FormationOutcome::Formed)
            .count()
    }
}

fn compute_optimized_tier_plan_hash(plan: &OptimizedTierCompilationPlan) -> String {
    #[derive(Serialize)]
    struct PlanEnvelope<'a> {
        schema_version: &'a str,
        trace_id: &'a str,
        function_id: &'a str,
        tier_up_eligible: bool,
        backend: OptimizedTierBackend,
        stage: ExecutionStage,
        tier_up_decision_hash: &'a str,
        tier_up_policy_hash: &'a str,
        superblock_policy_hash: &'a str,
        formation_epoch: u64,
        units: &'a [OptimizedCompilationUnit],
        rejected_candidates: &'a [OptimizedCompilationReject],
        requires_differential_equivalence: bool,
    }

    let digest = Sha256::digest(
        serde_json::to_vec(&PlanEnvelope {
            schema_version: &plan.schema_version,
            trace_id: &plan.trace_id,
            function_id: &plan.function_id,
            tier_up_eligible: plan.tier_up_eligible,
            backend: plan.backend,
            stage: plan.stage,
            tier_up_decision_hash: &plan.tier_up_decision_hash,
            tier_up_policy_hash: &plan.tier_up_policy_hash,
            superblock_policy_hash: &plan.superblock_policy_hash,
            formation_epoch: plan.formation_epoch,
            units: &plan.units,
            rejected_candidates: &plan.rejected_candidates,
            requires_differential_equivalence: plan.requires_differential_equivalence,
        })
        .expect("optimized tier plan payload must serialize"),
    );
    hex::encode(digest)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quickening_feedback_lattice::{
        ObservedType, QuickeningPolicy as QPolicy, QuickeningProfile,
    };
    use crate::tier_up_profiler::HotPathProfile;

    fn make_hot_profile() -> (QuickeningProfile, QPolicy) {
        let qpolicy = QPolicy {
            warm_threshold: 2,
            hot_threshold: 4,
            min_stability_millionths: 0,
            min_ic_hit_rate_millionths: 0,
            max_polymorphic_types: 5,
            deopt_resets_to_cold: true,
        };
        let mut profile = QuickeningProfile::new("test_fn");

        // Create a sequence of hot instructions at offsets 0, 4, 8, 12, 16
        for offset in (0..20).step_by(4) {
            for _ in 0..100 {
                profile.record_execution(offset, &format!("op_{}", offset));
            }
            profile.record_type(offset, &format!("op_{}", offset), 0, ObservedType::Integer);
        }

        // Evaluate to get them to Hot level
        profile.evaluate_all(&qpolicy);
        profile.evaluate_all(&qpolicy);

        (profile, qpolicy)
    }

    #[test]
    fn guard_kind_display() {
        assert_eq!(
            format!(
                "{}",
                GuardKind::ShapeCheck {
                    expected_shape_id: "s1".into()
                }
            ),
            "shape-check(s1)"
        );
        assert_eq!(
            format!(
                "{}",
                GuardKind::TypeCheck {
                    expected_type: "int".into()
                }
            ),
            "type-check(int)"
        );
        assert_eq!(
            format!(
                "{}",
                GuardKind::RangeCheck {
                    lower: 0,
                    upper: 10
                }
            ),
            "range-check([0, 10])"
        );
        assert_eq!(
            format!("{}", GuardKind::IcStability { ic_offset: 42 }),
            "ic-stability(@42)"
        );
        assert_eq!(format!("{}", GuardKind::OverflowCheck), "overflow-check");
    }

    #[test]
    fn guard_kind_serde_roundtrip() {
        let kinds = vec![
            GuardKind::ShapeCheck {
                expected_shape_id: "shape_1".into(),
            },
            GuardKind::TypeCheck {
                expected_type: "int".into(),
            },
            GuardKind::RangeCheck {
                lower: -5,
                upper: 100,
            },
            GuardKind::IcStability { ic_offset: 8 },
            GuardKind::OverflowCheck,
            GuardKind::PrototypeChain {
                expected_hash: "abc".into(),
            },
        ];
        for kind in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            let back: GuardKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    #[test]
    fn guard_kind_ordering() {
        let a = GuardKind::OverflowCheck;
        let b = GuardKind::TypeCheck {
            expected_type: "int".into(),
        };
        // Verify Ord is implemented and gives consistent results
        let _ordering = a.cmp(&b);
        assert_eq!(a.cmp(&a), std::cmp::Ordering::Equal);
    }

    #[test]
    fn side_exit_reason_display() {
        assert_eq!(format!("{}", SideExitReason::GuardFailure), "guard-failure");
        assert_eq!(format!("{}", SideExitReason::OverflowDetected), "overflow");
        assert_eq!(format!("{}", SideExitReason::TypeMismatch), "type-mismatch");
    }

    #[test]
    fn side_exit_reason_serde() {
        for reason in [
            SideExitReason::GuardFailure,
            SideExitReason::OverflowDetected,
            SideExitReason::TypeMismatch,
            SideExitReason::ShapeMismatch,
            SideExitReason::IcMegamorphic,
            SideExitReason::PrototypeInvalidated,
            SideExitReason::UnexpectedControlFlow,
        ] {
            let json = serde_json::to_string(&reason).unwrap();
            let back: SideExitReason = serde_json::from_str(&json).unwrap();
            assert_eq!(reason, back);
        }
    }

    #[test]
    fn side_exit_new_has_deterministic_id() {
        let e1 = SideExit::new(10, 2, SideExitReason::GuardFailure);
        let e2 = SideExit::new(10, 2, SideExitReason::GuardFailure);
        assert_eq!(e1.exit_id, e2.exit_id);
    }

    #[test]
    fn side_exit_different_inputs_different_id() {
        let e1 = SideExit::new(10, 2, SideExitReason::GuardFailure);
        let e2 = SideExit::new(10, 2, SideExitReason::TypeMismatch);
        assert_ne!(e1.exit_id, e2.exit_id);
    }

    #[test]
    fn side_exit_record_taken() {
        let mut exit = SideExit::new(0, 0, SideExitReason::GuardFailure);
        assert_eq!(exit.taken_count, 0);
        assert!(!exit.is_hot(10));

        for _ in 0..10 {
            exit.record_taken();
        }
        assert_eq!(exit.taken_count, 10);
        assert!(exit.is_hot(10));
    }

    #[test]
    fn side_exit_display() {
        let exit = SideExit::new(100, 5, SideExitReason::TypeMismatch);
        let display = format!("{exit}");
        assert!(display.contains("100"));
        assert!(display.contains("type-mismatch"));
    }

    #[test]
    fn superblock_guard_new() {
        let guard = SuperblockGuard::new(
            0,
            10,
            GuardKind::TypeCheck {
                expected_type: "int".into(),
            },
            "exit-1".into(),
        );
        assert_eq!(guard.position, 0);
        assert_eq!(guard.source_offset, 10);
        assert!(!guard.factored);
    }

    #[test]
    fn superblock_guard_display() {
        let mut guard = SuperblockGuard::new(3, 20, GuardKind::OverflowCheck, "exit-abc".into());
        let display = format!("{guard}");
        assert!(display.contains("guard@3"));
        assert!(display.contains("overflow-check"));
        assert!(!display.contains("[factored]"));

        guard.factored = true;
        let display2 = format!("{guard}");
        assert!(display2.contains("[factored]"));
    }

    #[test]
    fn superblock_guard_serde() {
        let guard = SuperblockGuard::new(
            1,
            8,
            GuardKind::ShapeCheck {
                expected_shape_id: "s42".into(),
            },
            "exit-xyz".into(),
        );
        let json = serde_json::to_string(&guard).unwrap();
        let back: SuperblockGuard = serde_json::from_str(&json).unwrap();
        assert_eq!(guard, back);
    }

    #[test]
    fn superblock_compute_block_id_deterministic() {
        let entries = vec![
            SuperblockEntry {
                position: 0,
                source_offset: 0,
                opcode: "add".into(),
                is_tail_duplicate: false,
                execution_count: 100,
            },
            SuperblockEntry {
                position: 1,
                source_offset: 4,
                opcode: "sub".into(),
                is_tail_duplicate: false,
                execution_count: 100,
            },
        ];
        let id1 = Superblock::compute_block_id("fn_a", &entries);
        let id2 = Superblock::compute_block_id("fn_a", &entries);
        assert_eq!(id1, id2);
        assert!(id1.starts_with("sb-"));
    }

    #[test]
    fn superblock_compute_block_id_varies_with_function() {
        let entries = vec![SuperblockEntry {
            position: 0,
            source_offset: 0,
            opcode: "add".into(),
            is_tail_duplicate: false,
            execution_count: 100,
        }];
        let id1 = Superblock::compute_block_id("fn_a", &entries);
        let id2 = Superblock::compute_block_id("fn_b", &entries);
        assert_ne!(id1, id2);
    }

    #[test]
    fn superblock_display() {
        let block = Superblock {
            block_id: "sb-test".into(),
            function_id: "fn_x".into(),
            entry_offset: 0,
            entries: vec![SuperblockEntry {
                position: 0,
                source_offset: 0,
                opcode: "add".into(),
                is_tail_duplicate: false,
                execution_count: 50,
            }],
            guards: vec![],
            side_exits: vec![],
            tail_duplication_count: 0,
            formation_epoch: 1,
        };
        let display = format!("{block}");
        assert!(display.contains("sb-test"));
        assert!(display.contains("fn_x"));
    }

    #[test]
    fn superblock_record_side_exit() {
        let exit = SideExit::new(10, 0, SideExitReason::GuardFailure);
        let exit_id = exit.exit_id.clone();

        let mut block = Superblock {
            block_id: "sb-1".into(),
            function_id: "fn_1".into(),
            entry_offset: 0,
            entries: vec![],
            guards: vec![],
            side_exits: vec![exit],
            tail_duplication_count: 0,
            formation_epoch: 1,
        };

        assert!(!block.record_side_exit(&exit_id, 5));
        for _ in 0..4 {
            block.record_side_exit(&exit_id, 5);
        }
        assert!(block.record_side_exit(&exit_id, 5));
    }

    #[test]
    fn superblock_hot_side_exits() {
        let mut e1 = SideExit::new(10, 0, SideExitReason::GuardFailure);
        let e2 = SideExit::new(20, 1, SideExitReason::TypeMismatch);

        for _ in 0..10 {
            e1.record_taken();
        }

        let block = Superblock {
            block_id: "sb-2".into(),
            function_id: "fn_2".into(),
            entry_offset: 0,
            entries: vec![],
            guards: vec![],
            side_exits: vec![e1, e2],
            tail_duplication_count: 0,
            formation_epoch: 1,
        };

        let hot = block.hot_side_exits(5);
        assert_eq!(hot.len(), 1);
    }

    #[test]
    fn superblock_serde() {
        let block = Superblock {
            block_id: "sb-serde".into(),
            function_id: "fn_serde".into(),
            entry_offset: 0,
            entries: vec![SuperblockEntry {
                position: 0,
                source_offset: 0,
                opcode: "nop".into(),
                is_tail_duplicate: false,
                execution_count: 1,
            }],
            guards: vec![],
            side_exits: vec![],
            tail_duplication_count: 0,
            formation_epoch: 1,
        };
        let json = serde_json::to_string(&block).unwrap();
        let back: Superblock = serde_json::from_str(&json).unwrap();
        assert_eq!(block, back);
    }

    #[test]
    fn trace_tree_new_single_node() {
        let block = Superblock {
            block_id: "sb-root".into(),
            function_id: "fn_tree".into(),
            entry_offset: 0,
            entries: vec![],
            guards: vec![],
            side_exits: vec![],
            tail_duplication_count: 0,
            formation_epoch: 1,
        };
        let tree = TraceTree::new("fn_tree", block);
        assert_eq!(tree.node_count(), 1);
        assert_eq!(tree.max_depth, 0);
        assert!(tree.tree_id.starts_with("tt-"));
    }

    #[test]
    fn trace_tree_extend_at_exit() {
        let root = Superblock {
            block_id: "sb-root".into(),
            function_id: "fn_ext".into(),
            entry_offset: 0,
            entries: vec![],
            guards: vec![],
            side_exits: vec![],
            tail_duplication_count: 0,
            formation_epoch: 1,
        };
        let child = Superblock {
            block_id: "sb-child".into(),
            function_id: "fn_ext".into(),
            entry_offset: 100,
            entries: vec![],
            guards: vec![],
            side_exits: vec![],
            tail_duplication_count: 0,
            formation_epoch: 1,
        };
        let policy = SuperblockPolicy::default();
        let mut tree = TraceTree::new("fn_ext", root);

        let extended = tree.extend_at_exit(0, "exit-1", child, &policy);
        assert!(extended);
        assert_eq!(tree.node_count(), 2);
        assert_eq!(tree.max_depth, 1);
    }

    #[test]
    fn trace_tree_respects_depth_limit() {
        let policy = SuperblockPolicy {
            max_trace_depth: 1,
            ..SuperblockPolicy::default()
        };
        let root = Superblock {
            block_id: "sb-r".into(),
            function_id: "fn_d".into(),
            entry_offset: 0,
            entries: vec![],
            guards: vec![],
            side_exits: vec![],
            tail_duplication_count: 0,
            formation_epoch: 1,
        };
        let child1 = root.clone();
        let child2 = root.clone();

        let mut tree = TraceTree::new("fn_d", root);
        assert!(tree.extend_at_exit(0, "exit-a", child1, &policy));
        // Index 1 is at depth 1, which equals max_trace_depth
        assert!(!tree.extend_at_exit(1, "exit-b", child2, &policy));
    }

    #[test]
    fn trace_tree_summary() {
        let root = Superblock {
            block_id: "sb-s".into(),
            function_id: "fn_s".into(),
            entry_offset: 0,
            entries: vec![
                SuperblockEntry {
                    position: 0,
                    source_offset: 0,
                    opcode: "add".into(),
                    is_tail_duplicate: false,
                    execution_count: 10,
                },
                SuperblockEntry {
                    position: 1,
                    source_offset: 4,
                    opcode: "sub".into(),
                    is_tail_duplicate: false,
                    execution_count: 10,
                },
            ],
            guards: vec![SuperblockGuard::new(
                0,
                0,
                GuardKind::OverflowCheck,
                "exit-x".into(),
            )],
            side_exits: vec![],
            tail_duplication_count: 0,
            formation_epoch: 1,
        };
        let tree = TraceTree::new("fn_s", root);
        let summary = tree.summary();
        assert_eq!(summary.total_instructions, 2);
        assert_eq!(summary.total_guards, 1);
        assert_eq!(summary.node_count, 1);
    }

    #[test]
    fn trace_tree_display() {
        let root = Superblock {
            block_id: "sb-d".into(),
            function_id: "fn_d".into(),
            entry_offset: 0,
            entries: vec![],
            guards: vec![],
            side_exits: vec![],
            tail_duplication_count: 0,
            formation_epoch: 1,
        };
        let tree = TraceTree::new("fn_d", root);
        let display = format!("{tree}");
        assert!(display.contains("trace-tree"));
        assert!(display.contains("fn_d"));
    }

    #[test]
    fn trace_tree_serde() {
        let root = Superblock {
            block_id: "sb-ser".into(),
            function_id: "fn_ser".into(),
            entry_offset: 0,
            entries: vec![],
            guards: vec![],
            side_exits: vec![],
            tail_duplication_count: 0,
            formation_epoch: 1,
        };
        let tree = TraceTree::new("fn_ser", root);
        let json = serde_json::to_string(&tree).unwrap();
        let back: TraceTree = serde_json::from_str(&json).unwrap();
        assert_eq!(tree.tree_id, back.tree_id);
        assert_eq!(tree.node_count(), back.node_count());
    }

    #[test]
    fn superblock_policy_default() {
        let policy = SuperblockPolicy::default();
        assert_eq!(policy.max_block_length, 64);
        assert_eq!(policy.max_trace_depth, 8);
        assert!(policy.enable_guard_factoring);
    }

    #[test]
    fn superblock_policy_hash_deterministic() {
        let p1 = SuperblockPolicy::default();
        let p2 = SuperblockPolicy::default();
        assert_eq!(p1.policy_hash(), p2.policy_hash());
    }

    #[test]
    fn formation_outcome_display() {
        assert_eq!(format!("{}", FormationOutcome::Formed), "formed");
        assert_eq!(
            format!("{}", FormationOutcome::InsufficientHotInstructions),
            "insufficient-hot"
        );
        assert_eq!(
            format!("{}", FormationOutcome::NoEligibleInstructions),
            "no-eligible"
        );
    }

    #[test]
    fn form_superblock_from_hot_profile() {
        let (profile, _qp) = make_hot_profile();
        let policy = SuperblockPolicy {
            min_execution_count: 4,
            ..SuperblockPolicy::default()
        };

        let record = form_superblock(&profile, 0, &policy, 1);
        assert_eq!(record.outcome, FormationOutcome::Formed);
        assert!(record.block.is_some());

        let block = record.block.unwrap();
        assert!(block.instruction_count() >= 2);
        assert!(block.block_id.starts_with("sb-"));
    }

    #[test]
    fn form_superblock_empty_profile_yields_no_eligible() {
        let profile = QuickeningProfile::new("empty_fn");
        let policy = SuperblockPolicy::default();

        let record = form_superblock(&profile, 0, &policy, 1);
        assert_eq!(record.outcome, FormationOutcome::NoEligibleInstructions);
        assert!(record.block.is_none());
    }

    #[test]
    fn form_superblock_cold_profile_yields_no_eligible() {
        let mut profile = QuickeningProfile::new("cold_fn");
        profile.record_execution(0, "add");
        let policy = SuperblockPolicy::default();

        let record = form_superblock(&profile, 0, &policy, 1);
        assert_eq!(record.outcome, FormationOutcome::NoEligibleInstructions);
    }

    #[test]
    fn form_superblock_respects_max_block_length() {
        let (profile, _qp) = make_hot_profile();
        let policy = SuperblockPolicy {
            max_block_length: 2,
            min_execution_count: 4,
            ..SuperblockPolicy::default()
        };

        let record = form_superblock(&profile, 0, &policy, 1);
        assert_eq!(record.outcome, FormationOutcome::Formed);
        assert_eq!(record.block.unwrap().instruction_count(), 2);
    }

    #[test]
    fn form_superblock_generates_type_guards() {
        let (profile, _qp) = make_hot_profile();
        let policy = SuperblockPolicy {
            min_execution_count: 4,
            ..SuperblockPolicy::default()
        };

        let record = form_superblock(&profile, 0, &policy, 1);
        let block = record.block.unwrap();
        // Each monomorphic instruction should get a type guard
        assert!(block.guard_count() > 0);
    }

    #[test]
    fn form_all_superblocks_covers_hot_instructions() {
        let (profile, _qp) = make_hot_profile();
        let policy = SuperblockPolicy {
            min_execution_count: 4,
            ..SuperblockPolicy::default()
        };

        let records = form_all_superblocks(&profile, &policy, 1);
        assert!(!records.is_empty());
        let formed: Vec<_> = records
            .iter()
            .filter(|r| r.outcome == FormationOutcome::Formed)
            .collect();
        assert!(!formed.is_empty());
    }

    #[test]
    fn factor_guards_merges_adjacent_same_kind() {
        let mut guards = vec![
            SuperblockGuard::new(
                0,
                0,
                GuardKind::TypeCheck {
                    expected_type: "int".into(),
                },
                "exit-a".into(),
            ),
            SuperblockGuard::new(
                1,
                4,
                GuardKind::TypeCheck {
                    expected_type: "int".into(),
                },
                "exit-b".into(),
            ),
        ];

        factor_guards(&mut guards);
        assert!(guards[0].factored);
        assert_eq!(guards[0].side_exit_id, "exit-b");
        assert!(!guards[1].factored);
    }

    #[test]
    fn factor_guards_does_not_merge_different_kinds() {
        let mut guards = vec![
            SuperblockGuard::new(
                0,
                0,
                GuardKind::TypeCheck {
                    expected_type: "int".into(),
                },
                "exit-a".into(),
            ),
            SuperblockGuard::new(1, 4, GuardKind::OverflowCheck, "exit-b".into()),
        ];

        factor_guards(&mut guards);
        assert!(!guards[0].factored);
        assert!(!guards[1].factored);
    }

    #[test]
    fn formation_decision_build() {
        let policy = SuperblockPolicy::default();
        let decision = FormationDecision::build("fn_dec", &policy, 1, vec![], None);
        assert!(!decision.decision_hash.is_empty());
        assert_eq!(decision.formed_count(), 0);
        assert_eq!(decision.rejected_count(), 0);
    }

    #[test]
    fn formation_decision_counts() {
        let policy = SuperblockPolicy::default();
        let records = vec![
            FormationRecord {
                function_id: "fn_c".into(),
                entry_offset: 0,
                outcome: FormationOutcome::Formed,
                instructions_considered: 5,
                instructions_included: 5,
                guards_generated: 2,
                tail_duplications: 0,
                block: None,
            },
            FormationRecord {
                function_id: "fn_c".into(),
                entry_offset: 100,
                outcome: FormationOutcome::NoEligibleInstructions,
                instructions_considered: 0,
                instructions_included: 0,
                guards_generated: 0,
                tail_duplications: 0,
                block: None,
            },
        ];
        let decision = FormationDecision::build("fn_c", &policy, 1, records, None);
        assert_eq!(decision.formed_count(), 1);
        assert_eq!(decision.rejected_count(), 1);
    }

    #[test]
    fn formation_decision_serde() {
        let policy = SuperblockPolicy::default();
        let decision = FormationDecision::build("fn_ser", &policy, 1, vec![], None);
        let json = serde_json::to_string(&decision).unwrap();
        let back: FormationDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, back);
    }

    #[test]
    fn formation_decision_hash_deterministic() {
        let policy = SuperblockPolicy::default();
        let d1 = FormationDecision::build("fn_h", &policy, 1, vec![], None);
        let d2 = FormationDecision::build("fn_h", &policy, 1, vec![], None);
        assert_eq!(d1.decision_hash, d2.decision_hash);
    }

    #[test]
    fn trace_tree_total_instructions() {
        let entries = vec![
            SuperblockEntry {
                position: 0,
                source_offset: 0,
                opcode: "a".into(),
                is_tail_duplicate: false,
                execution_count: 1,
            },
            SuperblockEntry {
                position: 1,
                source_offset: 4,
                opcode: "b".into(),
                is_tail_duplicate: false,
                execution_count: 1,
            },
        ];
        let root = Superblock {
            block_id: "sb-ti".into(),
            function_id: "fn_ti".into(),
            entry_offset: 0,
            entries,
            guards: vec![],
            side_exits: vec![],
            tail_duplication_count: 0,
            formation_epoch: 1,
        };
        let child = Superblock {
            block_id: "sb-ti2".into(),
            function_id: "fn_ti".into(),
            entry_offset: 100,
            entries: vec![SuperblockEntry {
                position: 0,
                source_offset: 100,
                opcode: "c".into(),
                is_tail_duplicate: false,
                execution_count: 1,
            }],
            guards: vec![],
            side_exits: vec![],
            tail_duplication_count: 0,
            formation_epoch: 1,
        };
        let policy = SuperblockPolicy::default();
        let mut tree = TraceTree::new("fn_ti", root);
        tree.extend_at_exit(0, "exit-x", child, &policy);
        assert_eq!(tree.total_instructions(), 3);
    }

    #[test]
    fn superblock_entry_serde() {
        let entry = SuperblockEntry {
            position: 3,
            source_offset: 12,
            opcode: "load".into(),
            is_tail_duplicate: true,
            execution_count: 42,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: SuperblockEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn trace_tree_summary_serde() {
        let summary = TraceTreeSummary {
            tree_id: "tt-test".into(),
            function_id: "fn_test".into(),
            node_count: 3,
            max_depth: 2,
            total_instructions: 15,
            total_guards: 5,
            formation_epoch: 1,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: TraceTreeSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }

    #[test]
    fn optimized_tier_plan_builds_cranelift_unit() {
        let (profile, _qp) = make_hot_profile();
        let decision = TierUpDecision {
            schema_version: "franken-engine.tier-up-policy.v1".into(),
            trace_id: "trace-opt".into(),
            policy_hash: "policy-hash".into(),
            eligible: true,
            selected_candidates: vec![TierUpCandidate {
                ip: 0,
                opcode: "op_0".into(),
                invocations: 100,
                cache_hit_rate_millionths: 950_000,
                rationale: "hot_path_meets_tier_up_thresholds".into(),
            }],
            rejected_paths: Vec::new(),
            profile: HotPathProfile {
                trace_id: "trace-opt".into(),
                total_steps: 100,
                observed_instruction_events: 100,
                top_paths: Vec::new(),
                profile_hash: "profile-hash".into(),
            },
            decision_hash: "decision-hash".into(),
            events: Vec::new(),
        };

        let plan = OptimizedTierCompilationPlan::build(
            &decision,
            &profile,
            &SuperblockPolicy::default(),
            9,
        );
        assert_eq!(plan.compilable_unit_count(), 1);
        assert!(plan.rejected_candidates.is_empty());
        assert_eq!(plan.backend, OptimizedTierBackend::Cranelift);
        assert_eq!(plan.stage, ExecutionStage::CompileOptimized);
        assert!(plan.requires_differential_equivalence);
        assert!(!plan.plan_hash.is_empty());

        let unit = &plan.units[0];
        assert_eq!(
            unit.candidate_id,
            decision.selected_candidates[0].candidate_id("trace-opt")
        );
        assert!(!unit.deopt_continuations.is_empty());
        assert!(
            unit.deopt_continuations
                .windows(2)
                .all(|pair| pair[0].guard_position <= pair[1].guard_position)
        );
    }

    #[test]
    fn optimized_tier_plan_rejects_unformable_candidate() {
        let profile = QuickeningProfile::new("cold_fn");
        let decision = TierUpDecision {
            schema_version: "franken-engine.tier-up-policy.v1".into(),
            trace_id: "trace-cold".into(),
            policy_hash: "policy-hash".into(),
            eligible: true,
            selected_candidates: vec![TierUpCandidate {
                ip: 0,
                opcode: "cold_op".into(),
                invocations: 100,
                cache_hit_rate_millionths: 950_000,
                rationale: "hot_path_meets_tier_up_thresholds".into(),
            }],
            rejected_paths: Vec::new(),
            profile: HotPathProfile {
                trace_id: "trace-cold".into(),
                total_steps: 100,
                observed_instruction_events: 100,
                top_paths: Vec::new(),
                profile_hash: "profile-hash".into(),
            },
            decision_hash: "decision-hash".into(),
            events: Vec::new(),
        };

        let plan = OptimizedTierCompilationPlan::build(
            &decision,
            &profile,
            &SuperblockPolicy::default(),
            1,
        );
        assert!(plan.units.is_empty());
        assert_eq!(plan.rejected_candidates.len(), 1);
        assert_eq!(
            plan.rejected_candidates[0].reason,
            CompilationRejectReason::SuperblockFormationRejected
        );
        assert_eq!(
            plan.rejected_candidates[0].formation_outcome,
            Some(FormationOutcome::NoEligibleInstructions)
        );
    }

    #[test]
    fn constants_defined() {
        assert!(!COMPONENT.is_empty());
        assert!(SUPERBLOCK_SCHEMA_VERSION.contains("superblock"));
        assert!(TRACE_TREE_SCHEMA_VERSION.contains("trace-tree"));
        assert!(OPTIMIZED_TIER_PLAN_SCHEMA_VERSION.contains("optimized-tier-plan"));
    }
}
