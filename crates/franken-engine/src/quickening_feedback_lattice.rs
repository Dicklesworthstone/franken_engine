//! Quickening feedback lattice and versioned superinstruction catalog.
//!
//! This module implements the deterministic quickening pipeline for the
//! bytecode interpreter. It tracks per-instruction type feedback, maintains
//! a monotone warmth lattice for each instruction site, and provides a
//! versioned catalog of superinstructions that the interpreter can use
//! for fused dispatch.
//!
//! Key invariants:
//! - Feedback state transitions are monotone (never regress except via explicit reset)
//! - All state is serializable for deterministic replay
//! - Superinstruction formation is pure: same input → same catalog version
//! - Integration with `shape_transition_algebra::InlineCacheState` for IC-driven decisions

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const COMPONENT: &str = "quickening_feedback_lattice";
pub const QUICKENING_SCHEMA_VERSION: &str = "franken-engine.quickening-feedback.v1";
pub const SUPERINSTRUCTION_CATALOG_SCHEMA_VERSION: &str =
    "franken-engine.superinstruction-catalog.v1";

// ---------------------------------------------------------------------------
// QuickeningLevel — monotone warmth lattice
// ---------------------------------------------------------------------------

/// Monotone warmth level for a bytecode instruction site.
///
/// Transitions are strictly upward: Cold → Warm → Hot → Quickened.
/// Once quickened, a site stays quickened unless explicitly reset via
/// a deopt event.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub enum QuickeningLevel {
    /// Not yet profiled. Default for new instruction sites.
    #[default]
    Cold,
    /// Has seen some executions but below the hot threshold.
    Warm,
    /// Exceeds the hot threshold and is eligible for quickening.
    Hot,
    /// Has been quickened — the interpreter can use the specialized form.
    Quickened,
}

impl QuickeningLevel {
    /// Attempt to advance to the next level. Returns None if already at max.
    pub fn advance(&self) -> Option<Self> {
        match self {
            Self::Cold => Some(Self::Warm),
            Self::Warm => Some(Self::Hot),
            Self::Hot => Some(Self::Quickened),
            Self::Quickened => None,
        }
    }

    /// Whether the site is eligible for quickening (Hot or above).
    pub fn is_quickening_eligible(&self) -> bool {
        matches!(self, Self::Hot | Self::Quickened)
    }

    /// Whether the site has been quickened.
    pub fn is_quickened(&self) -> bool {
        matches!(self, Self::Quickened)
    }

    /// Reset to Cold (used after deopt).
    pub fn reset(&self) -> Self {
        Self::Cold
    }

    /// Numeric rank for lattice comparisons (0=Cold, 3=Quickened).
    pub fn rank(&self) -> u32 {
        match self {
            Self::Cold => 0,
            Self::Warm => 1,
            Self::Hot => 2,
            Self::Quickened => 3,
        }
    }
}

impl fmt::Display for QuickeningLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cold => write!(f, "cold"),
            Self::Warm => write!(f, "warm"),
            Self::Hot => write!(f, "hot"),
            Self::Quickened => write!(f, "quickened"),
        }
    }
}

// ---------------------------------------------------------------------------
// ObservedType — type feedback lattice element
// ---------------------------------------------------------------------------

/// Type tag observed at an operand position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ObservedType {
    Undefined,
    Null,
    Boolean,
    Integer,
    Float,
    String,
    Object,
    Symbol,
    BigInt,
}

impl fmt::Display for ObservedType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Undefined => write!(f, "undefined"),
            Self::Null => write!(f, "null"),
            Self::Boolean => write!(f, "boolean"),
            Self::Integer => write!(f, "int"),
            Self::Float => write!(f, "float"),
            Self::String => write!(f, "string"),
            Self::Object => write!(f, "object"),
            Self::Symbol => write!(f, "symbol"),
            Self::BigInt => write!(f, "bigint"),
        }
    }
}

// ---------------------------------------------------------------------------
// TypeFeedbackSlot — per-instruction type observation
// ---------------------------------------------------------------------------

/// Tracks observed types at a specific instruction site operand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeFeedbackSlot {
    pub instruction_offset: u32,
    pub operand_index: u8,
    pub observed_types: BTreeSet<ObservedType>,
    pub observation_count: u64,
}

impl TypeFeedbackSlot {
    pub fn new(instruction_offset: u32, operand_index: u8) -> Self {
        Self {
            instruction_offset,
            operand_index,
            observed_types: BTreeSet::new(),
            observation_count: 0,
        }
    }

    /// Record an observed type for this operand.
    pub fn record(&mut self, observed: ObservedType) {
        self.observed_types.insert(observed);
        self.observation_count = self.observation_count.saturating_add(1);
    }

    /// Whether this slot is monomorphic (exactly one type observed).
    pub fn is_monomorphic(&self) -> bool {
        self.observed_types.len() == 1
    }

    /// Whether this slot is polymorphic (2+ types observed).
    pub fn is_polymorphic(&self) -> bool {
        self.observed_types.len() > 1
    }

    /// Whether this slot has seen no observations.
    pub fn is_unobserved(&self) -> bool {
        self.observed_types.is_empty()
    }

    /// Get the single observed type if monomorphic.
    pub fn monomorphic_type(&self) -> Option<ObservedType> {
        if self.observed_types.len() == 1 {
            self.observed_types.iter().next().copied()
        } else {
            None
        }
    }

    /// Stability score in millionths. 1_000_000 = fully monomorphic.
    pub fn stability_millionths(&self) -> u64 {
        if self.observation_count == 0 || self.observed_types.is_empty() {
            return 0;
        }
        // Monomorphic = 1M, polymorphic scales down by type count
        1_000_000 / self.observed_types.len() as u64
    }
}

impl fmt::Display for TypeFeedbackSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let types: Vec<String> = self.observed_types.iter().map(|t| format!("{t}")).collect();
        write!(
            f,
            "feedback@{}[{}]: {{{}}} (n={})",
            self.instruction_offset,
            self.operand_index,
            types.join(", "),
            self.observation_count
        )
    }
}

// ---------------------------------------------------------------------------
// QuickeningPolicy — thresholds for level transitions
// ---------------------------------------------------------------------------

/// Policy parameters governing quickening transitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuickeningPolicy {
    /// Minimum executions to transition Cold → Warm.
    pub warm_threshold: u64,
    /// Minimum executions to transition Warm → Hot.
    pub hot_threshold: u64,
    /// Minimum type stability (millionths) for quickening.
    pub min_stability_millionths: u64,
    /// Minimum IC hit rate (millionths) for quickening.
    pub min_ic_hit_rate_millionths: u64,
    /// Maximum polymorphic types before disqualification.
    pub max_polymorphic_types: usize,
    /// Whether deopt resets to Cold (true) or Warm (false).
    pub deopt_resets_to_cold: bool,
}

impl Default for QuickeningPolicy {
    fn default() -> Self {
        Self {
            warm_threshold: 8,
            hot_threshold: 64,
            min_stability_millionths: 500_000,
            min_ic_hit_rate_millionths: 600_000,
            max_polymorphic_types: 3,
            deopt_resets_to_cold: true,
        }
    }
}

impl QuickeningPolicy {
    pub fn policy_hash(&self) -> String {
        let payload = serde_json::to_vec(self).expect("policy must serialize");
        let digest = Sha256::digest(payload);
        hex::encode(digest)
    }
}

// ---------------------------------------------------------------------------
// InstructionFeedback — per-instruction aggregate state
// ---------------------------------------------------------------------------

/// Aggregate feedback state for a single instruction site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstructionFeedback {
    pub instruction_offset: u32,
    pub opcode: String,
    pub level: QuickeningLevel,
    pub execution_count: u64,
    pub type_slots: Vec<TypeFeedbackSlot>,
    pub ic_hit_rate_millionths: u64,
    pub deopt_count: u32,
    pub quickened_opcode: Option<String>,
}

impl InstructionFeedback {
    pub fn new(instruction_offset: u32, opcode: impl Into<String>) -> Self {
        Self {
            instruction_offset,
            opcode: opcode.into(),
            level: QuickeningLevel::Cold,
            execution_count: 0,
            type_slots: Vec::new(),
            ic_hit_rate_millionths: 0,
            deopt_count: 0,
            quickened_opcode: None,
        }
    }

    /// Record one execution of this instruction.
    pub fn record_execution(&mut self) {
        self.execution_count = self.execution_count.saturating_add(1);
    }

    /// Record a type observation on a specific operand.
    pub fn record_type(&mut self, operand_index: u8, observed: ObservedType) {
        let slot = self
            .type_slots
            .iter()
            .position(|s| s.operand_index == operand_index);
        if let Some(idx) = slot {
            self.type_slots[idx].record(observed);
        } else {
            let mut new_slot = TypeFeedbackSlot::new(self.instruction_offset, operand_index);
            new_slot.record(observed);
            self.type_slots.push(new_slot);
        }
    }

    /// Update the IC hit rate from an external source.
    pub fn update_ic_hit_rate(&mut self, rate_millionths: u64) {
        self.ic_hit_rate_millionths = rate_millionths;
    }

    /// Evaluate whether this instruction should advance its quickening level.
    pub fn evaluate(&mut self, policy: &QuickeningPolicy) -> QuickeningTransition {
        let old_level = self.level;

        match self.level {
            QuickeningLevel::Cold => {
                if self.execution_count >= policy.warm_threshold {
                    self.level = QuickeningLevel::Warm;
                }
            }
            QuickeningLevel::Warm => {
                if self.execution_count >= policy.hot_threshold {
                    self.level = QuickeningLevel::Hot;
                }
            }
            QuickeningLevel::Hot => {
                let stable = self.type_slots.iter().all(|s| {
                    s.stability_millionths() >= policy.min_stability_millionths
                        && s.observed_types.len() <= policy.max_polymorphic_types
                });
                let ic_ok = self.ic_hit_rate_millionths >= policy.min_ic_hit_rate_millionths
                    || self.type_slots.is_empty();
                if stable && ic_ok {
                    self.level = QuickeningLevel::Quickened;
                }
            }
            QuickeningLevel::Quickened => {}
        }

        QuickeningTransition {
            instruction_offset: self.instruction_offset,
            from: old_level,
            to: self.level,
            execution_count: self.execution_count,
            advanced: old_level != self.level,
        }
    }

    /// Handle a deopt event on this instruction.
    pub fn record_deopt(&mut self, policy: &QuickeningPolicy) {
        self.deopt_count = self.deopt_count.saturating_add(1);
        if policy.deopt_resets_to_cold {
            self.level = QuickeningLevel::Cold;
        } else {
            self.level = QuickeningLevel::Warm;
        }
        self.quickened_opcode = None;
    }

    /// Minimum stability across all type slots (millionths).
    pub fn min_stability_millionths(&self) -> u64 {
        self.type_slots
            .iter()
            .map(|s| s.stability_millionths())
            .min()
            .unwrap_or(0)
    }
}

impl fmt::Display for InstructionFeedback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}@{}: level={}, execs={}, deopts={}, ic_rate={}",
            self.opcode,
            self.instruction_offset,
            self.level,
            self.execution_count,
            self.deopt_count,
            self.ic_hit_rate_millionths
        )
    }
}

/// Record of a quickening level transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuickeningTransition {
    pub instruction_offset: u32,
    pub from: QuickeningLevel,
    pub to: QuickeningLevel,
    pub execution_count: u64,
    pub advanced: bool,
}

// ---------------------------------------------------------------------------
// SuperInstructionPattern — fused instruction template
// ---------------------------------------------------------------------------

/// Pattern describing a sequence of instructions that can be fused.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SuperInstructionPattern {
    /// Unique identifier for this pattern.
    pub pattern_id: String,
    /// Opcode names in sequence (e.g., ["load_prop_cached", "add"]).
    pub opcode_sequence: Vec<String>,
    /// Name of the fused superinstruction opcode.
    pub fused_opcode: String,
    /// Required type constraints for fusion (operand index → type).
    pub type_constraints: BTreeMap<u8, ObservedType>,
    /// Whether this pattern requires monomorphic IC state.
    pub requires_monomorphic_ic: bool,
    /// Estimated speedup in millionths (e.g., 1_500_000 = 1.5x).
    pub estimated_speedup_millionths: u64,
}

impl SuperInstructionPattern {
    pub fn sequence_length(&self) -> usize {
        self.opcode_sequence.len()
    }

    pub fn pattern_hash(&self) -> String {
        let payload = serde_json::to_vec(self).expect("pattern must serialize");
        let digest = Sha256::digest(payload);
        hex::encode(digest)
    }
}

impl fmt::Display for SuperInstructionPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} = [{}] (speedup={}.{}x)",
            self.fused_opcode,
            self.opcode_sequence.join(" → "),
            self.estimated_speedup_millionths / 1_000_000,
            (self.estimated_speedup_millionths % 1_000_000) / 1_000,
        )
    }
}

// ---------------------------------------------------------------------------
// SuperInstructionCatalog — versioned registry
// ---------------------------------------------------------------------------

/// Versioned catalog of superinstruction patterns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuperInstructionCatalog {
    pub schema_version: String,
    pub catalog_version: u32,
    pub patterns: Vec<SuperInstructionPattern>,
    pub catalog_hash: String,
}

impl SuperInstructionCatalog {
    pub fn new(patterns: Vec<SuperInstructionPattern>) -> Self {
        let catalog_hash = Self::compute_hash(&patterns);
        Self {
            schema_version: SUPERINSTRUCTION_CATALOG_SCHEMA_VERSION.to_string(),
            catalog_version: 1,
            patterns,
            catalog_hash,
        }
    }

    fn compute_hash(patterns: &[SuperInstructionPattern]) -> String {
        let payload = serde_json::to_vec(patterns).expect("patterns must serialize");
        let digest = Sha256::digest(payload);
        hex::encode(digest)
    }

    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Look up patterns that match a given opcode sequence prefix.
    pub fn find_matching(&self, opcodes: &[&str]) -> Vec<&SuperInstructionPattern> {
        self.patterns
            .iter()
            .filter(|p| {
                p.opcode_sequence.len() == opcodes.len()
                    && p.opcode_sequence
                        .iter()
                        .zip(opcodes.iter())
                        .all(|(a, b)| a == b)
            })
            .collect()
    }

    /// Get all patterns that start with a given opcode.
    pub fn patterns_starting_with(&self, opcode: &str) -> Vec<&SuperInstructionPattern> {
        self.patterns
            .iter()
            .filter(|p| p.opcode_sequence.first().is_some_and(|o| o == opcode))
            .collect()
    }

    /// Add a pattern to the catalog and bump version.
    pub fn add_pattern(&mut self, pattern: SuperInstructionPattern) {
        self.patterns.push(pattern);
        self.patterns.sort();
        self.catalog_version = self.catalog_version.saturating_add(1);
        self.catalog_hash = Self::compute_hash(&self.patterns);
    }
}

impl Default for SuperInstructionCatalog {
    fn default() -> Self {
        Self::new(default_superinstruction_patterns())
    }
}

/// Default set of superinstruction patterns for the bytecode VM.
pub fn default_superinstruction_patterns() -> Vec<SuperInstructionPattern> {
    vec![
        SuperInstructionPattern {
            pattern_id: "si-load-add".into(),
            opcode_sequence: vec!["load_prop_cached".into(), "add".into()],
            fused_opcode: "load_prop_and_add".into(),
            type_constraints: BTreeMap::new(),
            requires_monomorphic_ic: true,
            estimated_speedup_millionths: 1_300_000,
        },
        SuperInstructionPattern {
            pattern_id: "si-load-sub".into(),
            opcode_sequence: vec!["load_prop_cached".into(), "sub".into()],
            fused_opcode: "load_prop_and_sub".into(),
            type_constraints: BTreeMap::new(),
            requires_monomorphic_ic: true,
            estimated_speedup_millionths: 1_300_000,
        },
        SuperInstructionPattern {
            pattern_id: "si-store-jump".into(),
            opcode_sequence: vec!["store_prop".into(), "jump".into()],
            fused_opcode: "store_prop_and_jump".into(),
            type_constraints: BTreeMap::new(),
            requires_monomorphic_ic: false,
            estimated_speedup_millionths: 1_200_000,
        },
        SuperInstructionPattern {
            pattern_id: "si-add-jump-if-false".into(),
            opcode_sequence: vec!["add".into(), "jump_if_false".into()],
            fused_opcode: "add_and_branch".into(),
            type_constraints: {
                let mut m = BTreeMap::new();
                m.insert(0, ObservedType::Integer);
                m
            },
            requires_monomorphic_ic: false,
            estimated_speedup_millionths: 1_400_000,
        },
        SuperInstructionPattern {
            pattern_id: "si-load-load".into(),
            opcode_sequence: vec!["load_prop_cached".into(), "load_prop_cached".into()],
            fused_opcode: "load_prop_pair".into(),
            type_constraints: BTreeMap::new(),
            requires_monomorphic_ic: true,
            estimated_speedup_millionths: 1_500_000,
        },
    ]
}

// ---------------------------------------------------------------------------
// QuickeningProfile — per-function feedback state
// ---------------------------------------------------------------------------

/// Aggregate quickening state for a function's instruction stream.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuickeningProfile {
    pub function_id: String,
    entries: BTreeMap<u32, InstructionFeedback>,
    pub total_executions: u64,
    pub total_quickened: u32,
    pub total_deopts: u32,
    pub evaluation_epoch: u64,
}

impl QuickeningProfile {
    pub fn new(function_id: impl Into<String>) -> Self {
        Self {
            function_id: function_id.into(),
            entries: BTreeMap::new(),
            total_executions: 0,
            total_quickened: 0,
            total_deopts: 0,
            evaluation_epoch: 0,
        }
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Get or create feedback for an instruction offset.
    pub fn get_or_create(&mut self, offset: u32, opcode: &str) -> &mut InstructionFeedback {
        self.entries
            .entry(offset)
            .or_insert_with(|| InstructionFeedback::new(offset, opcode))
    }

    /// Record execution of an instruction.
    pub fn record_execution(&mut self, offset: u32, opcode: &str) {
        self.get_or_create(offset, opcode).record_execution();
        self.total_executions = self.total_executions.saturating_add(1);
    }

    /// Record a type observation.
    pub fn record_type(
        &mut self,
        offset: u32,
        opcode: &str,
        operand_index: u8,
        observed: ObservedType,
    ) {
        self.get_or_create(offset, opcode)
            .record_type(operand_index, observed);
    }

    /// Record a deopt at a specific instruction.
    pub fn record_deopt(&mut self, offset: u32, policy: &QuickeningPolicy) {
        if let Some(entry) = self.entries.get_mut(&offset) {
            entry.record_deopt(policy);
            self.total_deopts = self.total_deopts.saturating_add(1);
        }
    }

    /// Evaluate all instructions against the policy.
    pub fn evaluate_all(&mut self, policy: &QuickeningPolicy) -> Vec<QuickeningTransition> {
        self.evaluation_epoch = self.evaluation_epoch.saturating_add(1);
        let mut transitions = Vec::new();
        let mut quickened_count: u32 = 0;

        for entry in self.entries.values_mut() {
            let t = entry.evaluate(policy);
            if t.advanced {
                transitions.push(t);
            }
            if entry.level.is_quickened() {
                quickened_count = quickened_count.saturating_add(1);
            }
        }
        self.total_quickened = quickened_count;
        transitions
    }

    /// Get instructions at a specific quickening level.
    pub fn instructions_at_level(&self, level: QuickeningLevel) -> Vec<u32> {
        self.entries
            .iter()
            .filter(|(_, fb)| fb.level == level)
            .map(|(offset, _)| *offset)
            .collect()
    }

    /// Get the feedback entry for a specific offset.
    pub fn get(&self, offset: u32) -> Option<&InstructionFeedback> {
        self.entries.get(&offset)
    }

    /// Compute a summary of quickening state.
    pub fn summary(&self) -> QuickeningSummary {
        let (mut cold, mut warm, mut hot, mut quickened) = (0u32, 0u32, 0u32, 0u32);
        for entry in self.entries.values() {
            match entry.level {
                QuickeningLevel::Cold => cold += 1,
                QuickeningLevel::Warm => warm += 1,
                QuickeningLevel::Hot => hot += 1,
                QuickeningLevel::Quickened => quickened += 1,
            }
        }
        QuickeningSummary {
            total_sites: self.entries.len() as u32,
            cold_count: cold,
            warm_count: warm,
            hot_count: hot,
            quickened_count: quickened,
            total_executions: self.total_executions,
            total_deopts: self.total_deopts,
            evaluation_epoch: self.evaluation_epoch,
        }
    }

    /// Profile content hash for deterministic replay.
    pub fn profile_hash(&self) -> String {
        let payload = serde_json::to_vec(&self).expect("profile must serialize");
        let digest = Sha256::digest(payload);
        hex::encode(digest)
    }

    /// Find superinstruction candidates from a sequence of opcodes and feedback.
    pub fn find_superinstruction_candidates(
        &self,
        catalog: &SuperInstructionCatalog,
    ) -> Vec<SuperInstructionCandidate> {
        let offsets: Vec<u32> = self.entries.keys().copied().collect();
        let mut candidates = Vec::new();

        for (i, &offset) in offsets.iter().enumerate() {
            let entry = &self.entries[&offset];
            if !entry.level.is_quickening_eligible() {
                continue;
            }

            // Try each catalog pattern
            for pattern in &catalog.patterns {
                let seq_len = pattern.sequence_length();
                if i + seq_len > offsets.len() {
                    continue;
                }

                // Check opcode sequence match
                let mut matched = true;
                for (j, expected_opcode) in pattern.opcode_sequence.iter().enumerate() {
                    let check_offset = offsets[i + j];
                    if let Some(fb) = self.entries.get(&check_offset) {
                        if fb.opcode != *expected_opcode {
                            matched = false;
                            break;
                        }
                        // Check type constraints
                        for (&operand_idx, required_type) in &pattern.type_constraints {
                            if let Some(slot) = fb
                                .type_slots
                                .iter()
                                .find(|s| s.operand_index == operand_idx)
                            {
                                if let Some(mono_type) = slot.monomorphic_type() {
                                    if mono_type != *required_type {
                                        matched = false;
                                        break;
                                    }
                                } else {
                                    matched = false;
                                    break;
                                }
                            }
                        }
                    } else {
                        matched = false;
                        break;
                    }
                    if !matched {
                        break;
                    }
                }

                if matched {
                    // Check IC requirement
                    let ic_ok = if pattern.requires_monomorphic_ic {
                        entry.ic_hit_rate_millionths >= 900_000
                    } else {
                        true
                    };

                    if ic_ok {
                        candidates.push(SuperInstructionCandidate {
                            start_offset: offset,
                            pattern_id: pattern.pattern_id.clone(),
                            fused_opcode: pattern.fused_opcode.clone(),
                            estimated_speedup_millionths: pattern.estimated_speedup_millionths,
                        });
                    }
                }
            }
        }

        candidates
    }
}

/// Candidate for superinstruction formation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuperInstructionCandidate {
    pub start_offset: u32,
    pub pattern_id: String,
    pub fused_opcode: String,
    pub estimated_speedup_millionths: u64,
}

/// Summary of quickening state across a profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuickeningSummary {
    pub total_sites: u32,
    pub cold_count: u32,
    pub warm_count: u32,
    pub hot_count: u32,
    pub quickened_count: u32,
    pub total_executions: u64,
    pub total_deopts: u32,
    pub evaluation_epoch: u64,
}

// ---------------------------------------------------------------------------
// QuickeningDecision — auditable quickening outcome
// ---------------------------------------------------------------------------

/// Auditable decision record for a quickening evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuickeningDecision {
    pub schema_version: String,
    pub function_id: String,
    pub policy_hash: String,
    pub evaluation_epoch: u64,
    pub transitions: Vec<QuickeningTransition>,
    pub superinstruction_candidates: Vec<SuperInstructionCandidate>,
    pub summary: QuickeningSummary,
    pub decision_hash: String,
}

impl QuickeningDecision {
    pub fn build(
        profile: &QuickeningProfile,
        policy: &QuickeningPolicy,
        transitions: Vec<QuickeningTransition>,
        candidates: Vec<SuperInstructionCandidate>,
    ) -> Self {
        let summary = profile.summary();
        let mut decision = Self {
            schema_version: QUICKENING_SCHEMA_VERSION.to_string(),
            function_id: profile.function_id.clone(),
            policy_hash: policy.policy_hash(),
            evaluation_epoch: profile.evaluation_epoch,
            transitions,
            superinstruction_candidates: candidates,
            summary,
            decision_hash: String::new(),
        };
        let payload = serde_json::to_vec(&decision).expect("decision must serialize");
        let digest = Sha256::digest(payload);
        decision.decision_hash = hex::encode(digest);
        decision
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quickening_level_ordering() {
        assert!(QuickeningLevel::Cold < QuickeningLevel::Warm);
        assert!(QuickeningLevel::Warm < QuickeningLevel::Hot);
        assert!(QuickeningLevel::Hot < QuickeningLevel::Quickened);
    }

    #[test]
    fn quickening_level_advance() {
        assert_eq!(QuickeningLevel::Cold.advance(), Some(QuickeningLevel::Warm));
        assert_eq!(QuickeningLevel::Warm.advance(), Some(QuickeningLevel::Hot));
        assert_eq!(
            QuickeningLevel::Hot.advance(),
            Some(QuickeningLevel::Quickened)
        );
        assert_eq!(QuickeningLevel::Quickened.advance(), None);
    }

    #[test]
    fn quickening_level_eligibility() {
        assert!(!QuickeningLevel::Cold.is_quickening_eligible());
        assert!(!QuickeningLevel::Warm.is_quickening_eligible());
        assert!(QuickeningLevel::Hot.is_quickening_eligible());
        assert!(QuickeningLevel::Quickened.is_quickening_eligible());
    }

    #[test]
    fn quickening_level_rank() {
        assert_eq!(QuickeningLevel::Cold.rank(), 0);
        assert_eq!(QuickeningLevel::Warm.rank(), 1);
        assert_eq!(QuickeningLevel::Hot.rank(), 2);
        assert_eq!(QuickeningLevel::Quickened.rank(), 3);
    }

    #[test]
    fn quickening_level_display() {
        assert_eq!(format!("{}", QuickeningLevel::Cold), "cold");
        assert_eq!(format!("{}", QuickeningLevel::Warm), "warm");
        assert_eq!(format!("{}", QuickeningLevel::Hot), "hot");
        assert_eq!(format!("{}", QuickeningLevel::Quickened), "quickened");
    }

    #[test]
    fn quickening_level_reset() {
        assert_eq!(QuickeningLevel::Quickened.reset(), QuickeningLevel::Cold);
        assert_eq!(QuickeningLevel::Hot.reset(), QuickeningLevel::Cold);
    }

    #[test]
    fn quickening_level_default() {
        assert_eq!(QuickeningLevel::default(), QuickeningLevel::Cold);
    }

    #[test]
    fn quickening_level_serde_roundtrip() {
        for level in [
            QuickeningLevel::Cold,
            QuickeningLevel::Warm,
            QuickeningLevel::Hot,
            QuickeningLevel::Quickened,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let back: QuickeningLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, back);
        }
    }

    #[test]
    fn observed_type_display() {
        assert_eq!(format!("{}", ObservedType::Integer), "int");
        assert_eq!(format!("{}", ObservedType::Object), "object");
    }

    #[test]
    fn type_feedback_slot_monomorphic() {
        let mut slot = TypeFeedbackSlot::new(0, 0);
        assert!(slot.is_unobserved());

        slot.record(ObservedType::Integer);
        assert!(slot.is_monomorphic());
        assert_eq!(slot.monomorphic_type(), Some(ObservedType::Integer));
        assert_eq!(slot.stability_millionths(), 1_000_000);

        slot.record(ObservedType::Float);
        assert!(slot.is_polymorphic());
        assert_eq!(slot.monomorphic_type(), None);
        assert_eq!(slot.stability_millionths(), 500_000);
    }

    #[test]
    fn type_feedback_slot_display() {
        let mut slot = TypeFeedbackSlot::new(10, 1);
        slot.record(ObservedType::Integer);
        let display = format!("{slot}");
        assert!(display.contains("10"));
        assert!(display.contains("int"));
    }

    #[test]
    fn type_feedback_slot_serde() {
        let mut slot = TypeFeedbackSlot::new(5, 0);
        slot.record(ObservedType::String);
        let json = serde_json::to_string(&slot).unwrap();
        let back: TypeFeedbackSlot = serde_json::from_str(&json).unwrap();
        assert_eq!(slot, back);
    }

    #[test]
    fn instruction_feedback_lifecycle() {
        let policy = QuickeningPolicy::default();
        let mut fb = InstructionFeedback::new(0, "add");
        assert_eq!(fb.level, QuickeningLevel::Cold);

        // Execute enough to go warm
        for _ in 0..8 {
            fb.record_execution();
        }
        let t = fb.evaluate(&policy);
        assert!(t.advanced);
        assert_eq!(fb.level, QuickeningLevel::Warm);

        // Execute enough to go hot
        for _ in 0..56 {
            fb.record_execution();
        }
        let t = fb.evaluate(&policy);
        assert!(t.advanced);
        assert_eq!(fb.level, QuickeningLevel::Hot);
    }

    #[test]
    fn instruction_feedback_quickening_with_types() {
        let policy = QuickeningPolicy::default();
        let mut fb = InstructionFeedback::new(0, "add");
        for _ in 0..100 {
            fb.record_execution();
            fb.record_type(0, ObservedType::Integer);
        }
        fb.update_ic_hit_rate(900_000);

        fb.evaluate(&policy); // Cold → Warm
        fb.evaluate(&policy); // Warm → Hot
        let t = fb.evaluate(&policy); // Hot → Quickened
        assert!(t.advanced);
        assert_eq!(fb.level, QuickeningLevel::Quickened);
    }

    #[test]
    fn instruction_feedback_deopt_reset() {
        let policy = QuickeningPolicy::default();
        let mut fb = InstructionFeedback::new(0, "add");
        for _ in 0..100 {
            fb.record_execution();
        }
        fb.evaluate(&policy);
        fb.evaluate(&policy);
        assert_eq!(fb.level, QuickeningLevel::Hot);

        fb.record_deopt(&policy);
        assert_eq!(fb.level, QuickeningLevel::Cold);
        assert_eq!(fb.deopt_count, 1);
    }

    #[test]
    fn instruction_feedback_display() {
        let fb = InstructionFeedback::new(42, "load_const");
        let display = format!("{fb}");
        assert!(display.contains("load_const"));
        assert!(display.contains("42"));
    }

    #[test]
    fn quickening_policy_hash_deterministic() {
        let p1 = QuickeningPolicy::default();
        let p2 = QuickeningPolicy::default();
        assert_eq!(p1.policy_hash(), p2.policy_hash());
    }

    #[test]
    fn superinstruction_pattern_display() {
        let pattern = SuperInstructionPattern {
            pattern_id: "test".into(),
            opcode_sequence: vec!["load_prop_cached".into(), "add".into()],
            fused_opcode: "load_and_add".into(),
            type_constraints: BTreeMap::new(),
            requires_monomorphic_ic: true,
            estimated_speedup_millionths: 1_300_000,
        };
        let display = format!("{pattern}");
        assert!(display.contains("load_and_add"));
    }

    #[test]
    fn superinstruction_pattern_hash() {
        let p = SuperInstructionPattern {
            pattern_id: "test".into(),
            opcode_sequence: vec!["add".into()],
            fused_opcode: "fast_add".into(),
            type_constraints: BTreeMap::new(),
            requires_monomorphic_ic: false,
            estimated_speedup_millionths: 1_100_000,
        };
        let h1 = p.pattern_hash();
        let h2 = p.pattern_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn superinstruction_catalog_default() {
        let catalog = SuperInstructionCatalog::default();
        assert!(catalog.pattern_count() >= 5);
    }

    #[test]
    fn superinstruction_catalog_find_matching() {
        let catalog = SuperInstructionCatalog::default();
        let matches = catalog.find_matching(&["load_prop_cached", "add"]);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].fused_opcode, "load_prop_and_add");
    }

    #[test]
    fn superinstruction_catalog_patterns_starting_with() {
        let catalog = SuperInstructionCatalog::default();
        let matches = catalog.patterns_starting_with("load_prop_cached");
        assert!(matches.len() >= 2); // load+add, load+sub, load+load
    }

    #[test]
    fn superinstruction_catalog_add_pattern() {
        let mut catalog = SuperInstructionCatalog::default();
        let old_hash = catalog.catalog_hash.clone();
        let old_version = catalog.catalog_version;

        catalog.add_pattern(SuperInstructionPattern {
            pattern_id: "si-custom".into(),
            opcode_sequence: vec!["mul".into(), "return".into()],
            fused_opcode: "mul_and_return".into(),
            type_constraints: BTreeMap::new(),
            requires_monomorphic_ic: false,
            estimated_speedup_millionths: 1_200_000,
        });

        assert_eq!(catalog.catalog_version, old_version + 1);
        assert_ne!(catalog.catalog_hash, old_hash);
    }

    #[test]
    fn superinstruction_catalog_serde() {
        let catalog = SuperInstructionCatalog::default();
        let json = serde_json::to_string(&catalog).unwrap();
        let back: SuperInstructionCatalog = serde_json::from_str(&json).unwrap();
        assert_eq!(catalog, back);
    }

    #[test]
    fn quickening_profile_record_and_evaluate() {
        let policy = QuickeningPolicy::default();
        let mut profile = QuickeningProfile::new("test_fn");

        // Record 100 executions of instruction at offset 0
        for _ in 0..100 {
            profile.record_execution(0, "add");
        }
        assert_eq!(profile.total_executions, 100);

        let transitions = profile.evaluate_all(&policy);
        // Should have gone Cold → Warm → Hot (two transitions)
        // Actually it evaluates each entry once per call, so:
        // First evaluate: Cold→Warm (exec >= 8)
        assert!(!transitions.is_empty());
    }

    #[test]
    fn quickening_profile_full_lifecycle() {
        let policy = QuickeningPolicy {
            warm_threshold: 2,
            hot_threshold: 5,
            min_stability_millionths: 500_000,
            min_ic_hit_rate_millionths: 0,
            max_polymorphic_types: 3,
            deopt_resets_to_cold: true,
        };
        let mut profile = QuickeningProfile::new("fn_lifecycle");

        // Record enough executions
        for _ in 0..10 {
            profile.record_execution(0, "add");
            profile.record_type(0, "add", 0, ObservedType::Integer);
        }

        // Evaluate: Cold → Warm
        let t1 = profile.evaluate_all(&policy);
        assert_eq!(t1.len(), 1);
        assert_eq!(profile.get(0).unwrap().level, QuickeningLevel::Warm);

        // Evaluate again: Warm → Hot
        let t2 = profile.evaluate_all(&policy);
        assert_eq!(t2.len(), 1);
        assert_eq!(profile.get(0).unwrap().level, QuickeningLevel::Hot);

        // Evaluate again: Hot → Quickened (types are monomorphic)
        let t3 = profile.evaluate_all(&policy);
        assert_eq!(t3.len(), 1);
        assert_eq!(profile.get(0).unwrap().level, QuickeningLevel::Quickened);
        assert_eq!(profile.total_quickened, 1);
    }

    #[test]
    fn quickening_profile_deopt() {
        let policy = QuickeningPolicy {
            warm_threshold: 1,
            hot_threshold: 2,
            ..QuickeningPolicy::default()
        };
        let mut profile = QuickeningProfile::new("fn_deopt");
        for _ in 0..10 {
            profile.record_execution(0, "add");
        }
        profile.evaluate_all(&policy);
        profile.evaluate_all(&policy);
        assert_eq!(profile.get(0).unwrap().level, QuickeningLevel::Hot);

        profile.record_deopt(0, &policy);
        assert_eq!(profile.get(0).unwrap().level, QuickeningLevel::Cold);
        assert_eq!(profile.total_deopts, 1);
    }

    #[test]
    fn quickening_profile_summary() {
        let policy = QuickeningPolicy {
            warm_threshold: 1,
            hot_threshold: 2,
            ..QuickeningPolicy::default()
        };
        let mut profile = QuickeningProfile::new("fn_summary");

        // Cold site
        profile.record_execution(0, "add");
        // Warm site
        for _ in 0..3 {
            profile.record_execution(4, "sub");
        }
        profile.evaluate_all(&policy);

        let summary = profile.summary();
        assert_eq!(summary.total_sites, 2);
        // add@0 went Cold→Warm (1 >= 1)
        // sub@4 went Cold→Warm then Warm→Hot (3 >= 2)
        assert!(summary.warm_count + summary.hot_count > 0);
    }

    #[test]
    fn quickening_profile_superinstruction_candidates() {
        let policy = QuickeningPolicy {
            warm_threshold: 1,
            hot_threshold: 2,
            min_stability_millionths: 0,
            min_ic_hit_rate_millionths: 0,
            max_polymorphic_types: 5,
            deopt_resets_to_cold: true,
        };
        let catalog = SuperInstructionCatalog::default();
        let mut profile = QuickeningProfile::new("fn_super");

        // Two consecutive instructions matching load+add pattern
        for _ in 0..10 {
            profile.record_execution(0, "load_prop_cached");
            profile.record_execution(4, "add");
        }
        // Make them hot and IC-friendly
        if let Some(fb) = profile.entries.get_mut(&0) {
            fb.update_ic_hit_rate(950_000);
        }

        // Evaluate to get them to Hot
        profile.evaluate_all(&policy);
        profile.evaluate_all(&policy);

        let candidates = profile.find_superinstruction_candidates(&catalog);
        assert!(
            !candidates.is_empty(),
            "should find load_prop_and_add candidate"
        );
        assert_eq!(candidates[0].fused_opcode, "load_prop_and_add");
    }

    #[test]
    fn quickening_profile_hash_deterministic() {
        let mut p1 = QuickeningProfile::new("fn_hash");
        let mut p2 = QuickeningProfile::new("fn_hash");
        p1.record_execution(0, "add");
        p2.record_execution(0, "add");
        assert_eq!(p1.profile_hash(), p2.profile_hash());
    }

    #[test]
    fn quickening_profile_serde() {
        let mut profile = QuickeningProfile::new("fn_serde");
        profile.record_execution(0, "add");
        profile.record_type(0, "add", 0, ObservedType::Integer);
        let json = serde_json::to_string(&profile).unwrap();
        let back: QuickeningProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(profile.function_id, back.function_id);
        assert_eq!(profile.total_executions, back.total_executions);
    }

    #[test]
    fn quickening_decision_build() {
        let policy = QuickeningPolicy::default();
        let profile = QuickeningProfile::new("fn_decision");
        let decision = QuickeningDecision::build(&profile, &policy, vec![], vec![]);
        assert!(!decision.decision_hash.is_empty());
        assert_eq!(decision.function_id, "fn_decision");
    }

    #[test]
    fn quickening_decision_serde() {
        let policy = QuickeningPolicy::default();
        let profile = QuickeningProfile::new("fn_decision_serde");
        let decision = QuickeningDecision::build(&profile, &policy, vec![], vec![]);
        let json = serde_json::to_string(&decision).unwrap();
        let back: QuickeningDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, back);
    }

    #[test]
    fn quickening_profile_instructions_at_level() {
        let policy = QuickeningPolicy {
            warm_threshold: 1,
            ..QuickeningPolicy::default()
        };
        let mut profile = QuickeningProfile::new("fn_levels");
        profile.record_execution(0, "add");
        profile.record_execution(0, "add");
        profile.record_execution(4, "sub");

        profile.evaluate_all(&policy);

        let warm = profile.instructions_at_level(QuickeningLevel::Warm);
        // Both should be warm (2 >= 1 and 1 >= 1)
        assert!(warm.contains(&0));
        assert!(warm.contains(&4));
    }

    // -----------------------------------------------------------------------
    // Deep tests: enum variant serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn observed_type_serde_roundtrip_all_variants() {
        let all = [
            ObservedType::Undefined,
            ObservedType::Null,
            ObservedType::Boolean,
            ObservedType::Integer,
            ObservedType::Float,
            ObservedType::String,
            ObservedType::Object,
            ObservedType::Symbol,
            ObservedType::BigInt,
        ];
        for variant in &all {
            let json = serde_json::to_string(variant).unwrap();
            let back: ObservedType = serde_json::from_str(&json).unwrap();
            assert_eq!(*variant, back, "roundtrip failed for {variant}");
        }
    }

    // -----------------------------------------------------------------------
    // Deep tests: Display / as_str consistency
    // -----------------------------------------------------------------------

    #[test]
    fn observed_type_display_all_variants() {
        assert_eq!(format!("{}", ObservedType::Undefined), "undefined");
        assert_eq!(format!("{}", ObservedType::Null), "null");
        assert_eq!(format!("{}", ObservedType::Boolean), "boolean");
        assert_eq!(format!("{}", ObservedType::Integer), "int");
        assert_eq!(format!("{}", ObservedType::Float), "float");
        assert_eq!(format!("{}", ObservedType::String), "string");
        assert_eq!(format!("{}", ObservedType::Object), "object");
        assert_eq!(format!("{}", ObservedType::Symbol), "symbol");
        assert_eq!(format!("{}", ObservedType::BigInt), "bigint");
    }

    #[test]
    fn quickening_level_is_quickened_all_variants() {
        assert!(!QuickeningLevel::Cold.is_quickened());
        assert!(!QuickeningLevel::Warm.is_quickened());
        assert!(!QuickeningLevel::Hot.is_quickened());
        assert!(QuickeningLevel::Quickened.is_quickened());
    }

    // -----------------------------------------------------------------------
    // Deep tests: TypeFeedbackSlot edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn type_feedback_slot_stability_zero_observations() {
        let slot = TypeFeedbackSlot::new(0, 0);
        assert_eq!(slot.stability_millionths(), 0);
        assert!(slot.is_unobserved());
        assert!(!slot.is_monomorphic());
        assert!(!slot.is_polymorphic());
        assert_eq!(slot.monomorphic_type(), None);
    }

    #[test]
    fn type_feedback_slot_stability_scales_with_type_count() {
        let mut slot = TypeFeedbackSlot::new(0, 0);
        slot.record(ObservedType::Integer);
        assert_eq!(slot.stability_millionths(), 1_000_000);

        slot.record(ObservedType::Float);
        assert_eq!(slot.stability_millionths(), 500_000);

        slot.record(ObservedType::String);
        assert_eq!(slot.stability_millionths(), 333_333);

        slot.record(ObservedType::Object);
        assert_eq!(slot.stability_millionths(), 250_000);
    }

    #[test]
    fn type_feedback_slot_duplicate_type_does_not_increase_type_count() {
        let mut slot = TypeFeedbackSlot::new(0, 0);
        slot.record(ObservedType::Integer);
        slot.record(ObservedType::Integer);
        slot.record(ObservedType::Integer);
        assert!(slot.is_monomorphic());
        assert_eq!(slot.observation_count, 3);
        assert_eq!(slot.observed_types.len(), 1);
        assert_eq!(slot.stability_millionths(), 1_000_000);
    }

    #[test]
    fn type_feedback_slot_observation_count_saturates() {
        let mut slot = TypeFeedbackSlot::new(0, 0);
        slot.observation_count = u64::MAX;
        slot.record(ObservedType::Integer);
        assert_eq!(slot.observation_count, u64::MAX);
    }

    #[test]
    fn type_feedback_slot_display_empty() {
        let slot = TypeFeedbackSlot::new(42, 3);
        let display = format!("{slot}");
        assert!(display.contains("42"));
        assert!(display.contains("3"));
        assert!(display.contains("n=0"));
        assert!(display.contains("{}"));
    }

    #[test]
    fn type_feedback_slot_display_polymorphic() {
        let mut slot = TypeFeedbackSlot::new(0, 0);
        slot.record(ObservedType::Integer);
        slot.record(ObservedType::Float);
        let display = format!("{slot}");
        assert!(display.contains("int"));
        assert!(display.contains("float"));
        assert!(display.contains("n=2"));
    }

    // -----------------------------------------------------------------------
    // Deep tests: QuickeningPolicy edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn quickening_policy_different_configs_different_hashes() {
        let p1 = QuickeningPolicy::default();
        let p2 = QuickeningPolicy {
            warm_threshold: 100,
            ..QuickeningPolicy::default()
        };
        assert_ne!(p1.policy_hash(), p2.policy_hash());
    }

    #[test]
    fn quickening_policy_serde_roundtrip() {
        let policy = QuickeningPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let back: QuickeningPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }

    // -----------------------------------------------------------------------
    // Deep tests: InstructionFeedback edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn instruction_feedback_deopt_resets_to_warm_when_configured() {
        let policy = QuickeningPolicy {
            deopt_resets_to_cold: false,
            warm_threshold: 1,
            hot_threshold: 2,
            ..QuickeningPolicy::default()
        };
        let mut fb = InstructionFeedback::new(0, "add");
        for _ in 0..10 {
            fb.record_execution();
        }
        fb.evaluate(&policy); // Cold -> Warm
        fb.evaluate(&policy); // Warm -> Hot

        fb.quickened_opcode = Some("fast_add".to_string());
        fb.record_deopt(&policy);
        assert_eq!(fb.level, QuickeningLevel::Warm);
        assert!(fb.quickened_opcode.is_none());
        assert_eq!(fb.deopt_count, 1);
    }

    #[test]
    fn instruction_feedback_quickening_blocked_by_polymorphism() {
        let policy = QuickeningPolicy {
            warm_threshold: 1,
            hot_threshold: 2,
            min_stability_millionths: 500_000,
            min_ic_hit_rate_millionths: 0,
            max_polymorphic_types: 1,
            deopt_resets_to_cold: true,
        };
        let mut fb = InstructionFeedback::new(0, "add");
        for _ in 0..10 {
            fb.record_execution();
        }
        // Record multiple types so stability is low and types exceed max
        fb.record_type(0, ObservedType::Integer);
        fb.record_type(0, ObservedType::Float);

        fb.evaluate(&policy); // Cold -> Warm
        fb.evaluate(&policy); // Warm -> Hot
        let t = fb.evaluate(&policy); // Hot -> should NOT advance
        assert!(!t.advanced);
        assert_eq!(fb.level, QuickeningLevel::Hot);
    }

    #[test]
    fn instruction_feedback_quickening_blocked_by_low_ic_hit_rate() {
        let policy = QuickeningPolicy {
            warm_threshold: 1,
            hot_threshold: 2,
            min_stability_millionths: 0,
            min_ic_hit_rate_millionths: 900_000,
            max_polymorphic_types: 5,
            deopt_resets_to_cold: true,
        };
        let mut fb = InstructionFeedback::new(0, "add");
        for _ in 0..10 {
            fb.record_execution();
            fb.record_type(0, ObservedType::Integer);
        }
        fb.update_ic_hit_rate(100_000); // Low IC rate

        fb.evaluate(&policy); // Cold -> Warm
        fb.evaluate(&policy); // Warm -> Hot
        let t = fb.evaluate(&policy); // Hot -> should NOT advance
        assert!(!t.advanced);
        assert_eq!(fb.level, QuickeningLevel::Hot);
    }

    #[test]
    fn instruction_feedback_hot_to_quickened_with_no_type_slots() {
        let policy = QuickeningPolicy {
            warm_threshold: 1,
            hot_threshold: 2,
            min_stability_millionths: 500_000,
            min_ic_hit_rate_millionths: 900_000,
            max_polymorphic_types: 3,
            deopt_resets_to_cold: true,
        };
        let mut fb = InstructionFeedback::new(0, "nop");
        for _ in 0..10 {
            fb.record_execution();
        }

        fb.evaluate(&policy); // Cold -> Warm
        fb.evaluate(&policy); // Warm -> Hot
        let t = fb.evaluate(&policy); // Hot -> Quickened
        assert!(t.advanced);
        assert_eq!(fb.level, QuickeningLevel::Quickened);
    }

    #[test]
    fn instruction_feedback_execution_count_saturates() {
        let mut fb = InstructionFeedback::new(0, "add");
        fb.execution_count = u64::MAX;
        fb.record_execution();
        assert_eq!(fb.execution_count, u64::MAX);
    }

    #[test]
    fn instruction_feedback_deopt_count_saturates() {
        let policy = QuickeningPolicy::default();
        let mut fb = InstructionFeedback::new(0, "add");
        fb.deopt_count = u32::MAX;
        fb.record_deopt(&policy);
        assert_eq!(fb.deopt_count, u32::MAX);
    }

    #[test]
    fn instruction_feedback_min_stability_with_multiple_slots() {
        let mut fb = InstructionFeedback::new(0, "add");
        fb.record_type(0, ObservedType::Integer);
        fb.record_type(1, ObservedType::Integer);
        fb.record_type(1, ObservedType::Float);

        assert_eq!(fb.min_stability_millionths(), 500_000);
    }

    #[test]
    fn instruction_feedback_min_stability_no_slots() {
        let fb = InstructionFeedback::new(0, "add");
        assert_eq!(fb.min_stability_millionths(), 0);
    }

    #[test]
    fn instruction_feedback_record_type_creates_new_slot() {
        let mut fb = InstructionFeedback::new(0, "add");
        assert!(fb.type_slots.is_empty());

        fb.record_type(0, ObservedType::Integer);
        assert_eq!(fb.type_slots.len(), 1);
        assert_eq!(fb.type_slots[0].operand_index, 0);

        fb.record_type(1, ObservedType::Float);
        assert_eq!(fb.type_slots.len(), 2);
        assert_eq!(fb.type_slots[1].operand_index, 1);
    }

    #[test]
    fn instruction_feedback_record_type_updates_existing_slot() {
        let mut fb = InstructionFeedback::new(0, "add");
        fb.record_type(0, ObservedType::Integer);
        fb.record_type(0, ObservedType::Float);
        assert_eq!(fb.type_slots.len(), 1);
        assert!(fb.type_slots[0].is_polymorphic());
        assert_eq!(fb.type_slots[0].observation_count, 2);
    }

    #[test]
    fn instruction_feedback_evaluate_no_advance_from_cold_below_threshold() {
        let policy = QuickeningPolicy::default();
        let mut fb = InstructionFeedback::new(0, "add");
        for _ in 0..7 {
            fb.record_execution();
        }
        let t = fb.evaluate(&policy);
        assert!(!t.advanced);
        assert_eq!(fb.level, QuickeningLevel::Cold);
    }

    #[test]
    fn instruction_feedback_evaluate_stays_quickened() {
        let policy = QuickeningPolicy {
            warm_threshold: 1,
            hot_threshold: 2,
            min_stability_millionths: 0,
            min_ic_hit_rate_millionths: 0,
            max_polymorphic_types: 10,
            deopt_resets_to_cold: true,
        };
        let mut fb = InstructionFeedback::new(0, "nop");
        for _ in 0..10 {
            fb.record_execution();
        }
        fb.evaluate(&policy);
        fb.evaluate(&policy);
        fb.evaluate(&policy);

        let t = fb.evaluate(&policy);
        assert!(!t.advanced);
        assert_eq!(t.from, QuickeningLevel::Quickened);
        assert_eq!(t.to, QuickeningLevel::Quickened);
    }

    #[test]
    fn instruction_feedback_serde_roundtrip() {
        let mut fb = InstructionFeedback::new(42, "load_const");
        fb.record_execution();
        fb.record_type(0, ObservedType::Integer);
        fb.update_ic_hit_rate(750_000);
        fb.quickened_opcode = Some("fast_load_const".to_string());
        fb.deopt_count = 3;

        let json = serde_json::to_string(&fb).unwrap();
        let back: InstructionFeedback = serde_json::from_str(&json).unwrap();
        assert_eq!(fb, back);
    }

    #[test]
    fn instruction_feedback_display_format() {
        let mut fb = InstructionFeedback::new(10, "sub");
        fb.execution_count = 50;
        fb.deopt_count = 2;
        fb.ic_hit_rate_millionths = 800_000;
        fb.level = QuickeningLevel::Hot;

        let display = format!("{fb}");
        assert!(display.contains("sub@10"));
        assert!(display.contains("level=hot"));
        assert!(display.contains("execs=50"));
        assert!(display.contains("deopts=2"));
        assert!(display.contains("ic_rate=800000"));
    }

    // -----------------------------------------------------------------------
    // Deep tests: SuperInstructionPattern edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn superinstruction_pattern_sequence_length() {
        let p = SuperInstructionPattern {
            pattern_id: "test".into(),
            opcode_sequence: vec!["a".into(), "b".into(), "c".into()],
            fused_opcode: "abc".into(),
            type_constraints: BTreeMap::new(),
            requires_monomorphic_ic: false,
            estimated_speedup_millionths: 1_000_000,
        };
        assert_eq!(p.sequence_length(), 3);
    }

    #[test]
    fn superinstruction_pattern_serde_roundtrip_with_type_constraints() {
        let mut constraints = BTreeMap::new();
        constraints.insert(0, ObservedType::Integer);
        constraints.insert(1, ObservedType::Float);

        let p = SuperInstructionPattern {
            pattern_id: "test-typed".into(),
            opcode_sequence: vec!["add".into(), "store".into()],
            fused_opcode: "add_and_store".into(),
            type_constraints: constraints,
            requires_monomorphic_ic: true,
            estimated_speedup_millionths: 1_600_000,
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: SuperInstructionPattern = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn superinstruction_pattern_display_speedup_formatting() {
        let p = SuperInstructionPattern {
            pattern_id: "test".into(),
            opcode_sequence: vec!["a".into(), "b".into()],
            fused_opcode: "fused_ab".into(),
            type_constraints: BTreeMap::new(),
            requires_monomorphic_ic: false,
            estimated_speedup_millionths: 2_750_000,
        };
        let display = format!("{p}");
        assert!(display.contains("fused_ab"));
        assert!(display.contains("2.750x"));
    }

    #[test]
    fn superinstruction_pattern_hash_differs_for_different_patterns() {
        let p1 = SuperInstructionPattern {
            pattern_id: "p1".into(),
            opcode_sequence: vec!["add".into()],
            fused_opcode: "fast_add".into(),
            type_constraints: BTreeMap::new(),
            requires_monomorphic_ic: false,
            estimated_speedup_millionths: 1_100_000,
        };
        let p2 = SuperInstructionPattern {
            pattern_id: "p2".into(),
            opcode_sequence: vec!["sub".into()],
            fused_opcode: "fast_sub".into(),
            type_constraints: BTreeMap::new(),
            requires_monomorphic_ic: false,
            estimated_speedup_millionths: 1_100_000,
        };
        assert_ne!(p1.pattern_hash(), p2.pattern_hash());
    }

    // -----------------------------------------------------------------------
    // Deep tests: SuperInstructionCatalog edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn superinstruction_catalog_empty() {
        let catalog = SuperInstructionCatalog::new(vec![]);
        assert_eq!(catalog.pattern_count(), 0);
        assert!(catalog.find_matching(&["add"]).is_empty());
        assert!(catalog.patterns_starting_with("add").is_empty());
    }

    #[test]
    fn superinstruction_catalog_find_matching_no_match() {
        let catalog = SuperInstructionCatalog::default();
        let matches = catalog.find_matching(&["nonexistent_opcode", "another"]);
        assert!(matches.is_empty());
    }

    #[test]
    fn superinstruction_catalog_find_matching_length_mismatch() {
        let catalog = SuperInstructionCatalog::default();
        let matches = catalog.find_matching(&["load_prop_cached"]);
        assert!(matches.is_empty());
        let matches = catalog.find_matching(&["load_prop_cached", "add", "store"]);
        assert!(matches.is_empty());
    }

    #[test]
    fn superinstruction_catalog_add_pattern_sorts_and_rehashes() {
        let mut catalog = SuperInstructionCatalog::new(vec![]);
        let hash_empty = catalog.catalog_hash.clone();

        catalog.add_pattern(SuperInstructionPattern {
            pattern_id: "z-last".into(),
            opcode_sequence: vec!["z".into()],
            fused_opcode: "fused_z".into(),
            type_constraints: BTreeMap::new(),
            requires_monomorphic_ic: false,
            estimated_speedup_millionths: 1_000_000,
        });
        catalog.add_pattern(SuperInstructionPattern {
            pattern_id: "a-first".into(),
            opcode_sequence: vec!["a".into()],
            fused_opcode: "fused_a".into(),
            type_constraints: BTreeMap::new(),
            requires_monomorphic_ic: false,
            estimated_speedup_millionths: 1_000_000,
        });

        assert_eq!(catalog.patterns[0].pattern_id, "a-first");
        assert_eq!(catalog.patterns[1].pattern_id, "z-last");
        assert_ne!(catalog.catalog_hash, hash_empty);
        assert_eq!(catalog.catalog_version, 3);
    }

    #[test]
    fn superinstruction_catalog_hash_deterministic() {
        let c1 = SuperInstructionCatalog::default();
        let c2 = SuperInstructionCatalog::default();
        assert_eq!(c1.catalog_hash, c2.catalog_hash);
    }

    #[test]
    fn superinstruction_catalog_schema_version() {
        let catalog = SuperInstructionCatalog::default();
        assert_eq!(
            catalog.schema_version,
            SUPERINSTRUCTION_CATALOG_SCHEMA_VERSION
        );
    }

    // -----------------------------------------------------------------------
    // Deep tests: QuickeningProfile edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn quickening_profile_empty_summary() {
        let profile = QuickeningProfile::new("empty");
        let summary = profile.summary();
        assert_eq!(summary.total_sites, 0);
        assert_eq!(summary.cold_count, 0);
        assert_eq!(summary.warm_count, 0);
        assert_eq!(summary.hot_count, 0);
        assert_eq!(summary.quickened_count, 0);
        assert_eq!(summary.total_executions, 0);
        assert_eq!(summary.total_deopts, 0);
        assert_eq!(summary.evaluation_epoch, 0);
    }

    #[test]
    fn quickening_profile_evaluation_epoch_increments() {
        let policy = QuickeningPolicy::default();
        let mut profile = QuickeningProfile::new("epoch_test");
        assert_eq!(profile.evaluation_epoch, 0);

        profile.evaluate_all(&policy);
        assert_eq!(profile.evaluation_epoch, 1);

        profile.evaluate_all(&policy);
        assert_eq!(profile.evaluation_epoch, 2);

        profile.evaluate_all(&policy);
        assert_eq!(profile.evaluation_epoch, 3);
    }

    #[test]
    fn quickening_profile_deopt_on_nonexistent_offset() {
        let policy = QuickeningPolicy::default();
        let mut profile = QuickeningProfile::new("no_offset");
        profile.record_deopt(999, &policy);
        assert_eq!(profile.total_deopts, 0);
    }

    #[test]
    fn quickening_profile_get_or_create_idempotent_opcode() {
        let mut profile = QuickeningProfile::new("idempotent");
        profile.get_or_create(0, "add");
        profile.get_or_create(0, "add");
        assert_eq!(profile.entry_count(), 1);
    }

    #[test]
    fn quickening_profile_multiple_instructions_different_levels() {
        let policy = QuickeningPolicy {
            warm_threshold: 1,
            hot_threshold: 5,
            min_stability_millionths: 0,
            min_ic_hit_rate_millionths: 0,
            max_polymorphic_types: 10,
            deopt_resets_to_cold: true,
        };
        let mut profile = QuickeningProfile::new("multi");

        profile.record_execution(0, "add");

        for _ in 0..10 {
            profile.record_execution(4, "sub");
        }

        let t1 = profile.evaluate_all(&policy);
        assert_eq!(t1.len(), 2);

        let t2 = profile.evaluate_all(&policy);
        assert_eq!(t2.len(), 1);
        assert_eq!(profile.get(4).unwrap().level, QuickeningLevel::Hot);
        assert_eq!(profile.get(0).unwrap().level, QuickeningLevel::Warm);

        let t3 = profile.evaluate_all(&policy);
        assert_eq!(t3.len(), 1);
        assert_eq!(profile.get(4).unwrap().level, QuickeningLevel::Quickened);
        assert_eq!(profile.total_quickened, 1);

        let summary = profile.summary();
        assert_eq!(summary.warm_count, 1);
        assert_eq!(summary.quickened_count, 1);
    }

    #[test]
    fn quickening_profile_total_executions_saturates() {
        let mut profile = QuickeningProfile::new("saturate");
        profile.total_executions = u64::MAX;
        profile.record_execution(0, "add");
        assert_eq!(profile.total_executions, u64::MAX);
    }

    #[test]
    fn quickening_profile_get_returns_none_for_missing() {
        let profile = QuickeningProfile::new("empty");
        assert!(profile.get(42).is_none());
    }

    #[test]
    fn quickening_profile_instructions_at_level_empty() {
        let profile = QuickeningProfile::new("empty");
        assert!(
            profile
                .instructions_at_level(QuickeningLevel::Cold)
                .is_empty()
        );
        assert!(
            profile
                .instructions_at_level(QuickeningLevel::Quickened)
                .is_empty()
        );
    }

    // -----------------------------------------------------------------------
    // Deep tests: SuperInstruction candidates with type constraints
    // -----------------------------------------------------------------------

    #[test]
    fn superinstruction_candidates_type_constraint_mismatch() {
        let policy = QuickeningPolicy {
            warm_threshold: 1,
            hot_threshold: 2,
            min_stability_millionths: 0,
            min_ic_hit_rate_millionths: 0,
            max_polymorphic_types: 5,
            deopt_resets_to_cold: true,
        };

        let catalog = SuperInstructionCatalog::new(vec![SuperInstructionPattern {
            pattern_id: "si-add-branch-typed".into(),
            opcode_sequence: vec!["add".into(), "jump_if_false".into()],
            fused_opcode: "add_and_branch".into(),
            type_constraints: {
                let mut m = BTreeMap::new();
                m.insert(0, ObservedType::Integer);
                m
            },
            requires_monomorphic_ic: false,
            estimated_speedup_millionths: 1_400_000,
        }]);

        let mut profile = QuickeningProfile::new("type_mismatch");
        for _ in 0..10 {
            profile.record_execution(0, "add");
            profile.record_execution(4, "jump_if_false");
        }
        profile.record_type(0, "add", 0, ObservedType::Float);

        profile.evaluate_all(&policy);
        profile.evaluate_all(&policy);

        let candidates = profile.find_superinstruction_candidates(&catalog);
        assert!(
            candidates.is_empty(),
            "should not match due to type constraint mismatch"
        );
    }

    #[test]
    fn superinstruction_candidates_ic_requirement_blocks() {
        let policy = QuickeningPolicy {
            warm_threshold: 1,
            hot_threshold: 2,
            min_stability_millionths: 0,
            min_ic_hit_rate_millionths: 0,
            max_polymorphic_types: 5,
            deopt_resets_to_cold: true,
        };

        let catalog = SuperInstructionCatalog::default();
        let mut profile = QuickeningProfile::new("ic_block");
        for _ in 0..10 {
            profile.record_execution(0, "load_prop_cached");
            profile.record_execution(4, "add");
        }

        profile.evaluate_all(&policy);
        profile.evaluate_all(&policy);

        // After getting to Hot, set low IC hit rate
        profile
            .get_or_create(0, "load_prop_cached")
            .update_ic_hit_rate(500_000);

        let candidates = profile.find_superinstruction_candidates(&catalog);
        let load_add: Vec<_> = candidates
            .iter()
            .filter(|c| c.fused_opcode == "load_prop_and_add")
            .collect();
        assert!(
            load_add.is_empty(),
            "should be blocked by low IC hit rate for monomorphic IC pattern"
        );
    }

    #[test]
    fn superinstruction_candidates_not_eligible_when_cold() {
        let policy = QuickeningPolicy::default();
        let catalog = SuperInstructionCatalog::default();
        let mut profile = QuickeningProfile::new("cold_check");

        profile.record_execution(0, "load_prop_cached");
        profile.record_execution(4, "add");

        let candidates = profile.find_superinstruction_candidates(&catalog);
        assert!(
            candidates.is_empty(),
            "cold instructions should not be candidates"
        );
    }

    // -----------------------------------------------------------------------
    // Deep tests: serde roundtrips for remaining types
    // -----------------------------------------------------------------------

    #[test]
    fn quickening_transition_serde_roundtrip() {
        let t = QuickeningTransition {
            instruction_offset: 42,
            from: QuickeningLevel::Warm,
            to: QuickeningLevel::Hot,
            execution_count: 999,
            advanced: true,
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: QuickeningTransition = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn superinstruction_candidate_serde_roundtrip() {
        let c = SuperInstructionCandidate {
            start_offset: 10,
            pattern_id: "si-load-add".into(),
            fused_opcode: "load_prop_and_add".into(),
            estimated_speedup_millionths: 1_300_000,
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: SuperInstructionCandidate = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn quickening_summary_serde_roundtrip() {
        let s = QuickeningSummary {
            total_sites: 10,
            cold_count: 3,
            warm_count: 2,
            hot_count: 4,
            quickened_count: 1,
            total_executions: 1000,
            total_deopts: 5,
            evaluation_epoch: 7,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: QuickeningSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // -----------------------------------------------------------------------
    // Deep tests: QuickeningDecision determinism and hash
    // -----------------------------------------------------------------------

    #[test]
    fn quickening_decision_hash_deterministic() {
        let policy = QuickeningPolicy::default();
        let profile = QuickeningProfile::new("fn_det");
        let d1 = QuickeningDecision::build(&profile, &policy, vec![], vec![]);
        let d2 = QuickeningDecision::build(&profile, &policy, vec![], vec![]);
        assert_eq!(d1.decision_hash, d2.decision_hash);
    }

    #[test]
    fn quickening_decision_schema_version() {
        let policy = QuickeningPolicy::default();
        let profile = QuickeningProfile::new("fn_schema");
        let decision = QuickeningDecision::build(&profile, &policy, vec![], vec![]);
        assert_eq!(decision.schema_version, QUICKENING_SCHEMA_VERSION);
    }

    #[test]
    fn quickening_decision_includes_transitions_and_candidates() {
        let policy = QuickeningPolicy::default();
        let profile = QuickeningProfile::new("fn_full");
        let transitions = vec![QuickeningTransition {
            instruction_offset: 0,
            from: QuickeningLevel::Cold,
            to: QuickeningLevel::Warm,
            execution_count: 10,
            advanced: true,
        }];
        let candidates = vec![SuperInstructionCandidate {
            start_offset: 0,
            pattern_id: "si-load-add".into(),
            fused_opcode: "load_prop_and_add".into(),
            estimated_speedup_millionths: 1_300_000,
        }];
        let decision =
            QuickeningDecision::build(&profile, &policy, transitions.clone(), candidates.clone());
        assert_eq!(decision.transitions, transitions);
        assert_eq!(decision.superinstruction_candidates, candidates);
    }

    // -----------------------------------------------------------------------
    // Deep tests: Constants
    // -----------------------------------------------------------------------

    #[test]
    fn constants_are_well_formed() {
        assert_eq!(COMPONENT, "quickening_feedback_lattice");
        assert!(QUICKENING_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(SUPERINSTRUCTION_CATALOG_SCHEMA_VERSION.starts_with("franken-engine."));
    }

    // -----------------------------------------------------------------------
    // Deep tests: default_superinstruction_patterns coverage
    // -----------------------------------------------------------------------

    #[test]
    fn default_patterns_cover_expected_fusions() {
        let patterns = default_superinstruction_patterns();
        let fused_opcodes: BTreeSet<String> =
            patterns.iter().map(|p| p.fused_opcode.clone()).collect();
        assert!(fused_opcodes.contains("load_prop_and_add"));
        assert!(fused_opcodes.contains("load_prop_and_sub"));
        assert!(fused_opcodes.contains("store_prop_and_jump"));
        assert!(fused_opcodes.contains("add_and_branch"));
        assert!(fused_opcodes.contains("load_prop_pair"));
    }

    #[test]
    fn default_patterns_all_have_positive_speedup() {
        for p in default_superinstruction_patterns() {
            assert!(
                p.estimated_speedup_millionths > 1_000_000,
                "pattern {} speedup should be > 1.0x",
                p.pattern_id
            );
        }
    }

    #[test]
    fn default_patterns_all_have_nonempty_sequences() {
        for p in default_superinstruction_patterns() {
            assert!(
                p.sequence_length() >= 2,
                "pattern {} should have at least 2 opcodes",
                p.pattern_id
            );
        }
    }

    // -----------------------------------------------------------------------
    // Deep tests: observed type ordering (BTreeSet determinism)
    // -----------------------------------------------------------------------

    #[test]
    fn observed_type_ordering_deterministic() {
        let mut set1 = BTreeSet::new();
        set1.insert(ObservedType::Float);
        set1.insert(ObservedType::Integer);
        set1.insert(ObservedType::Undefined);

        let mut set2 = BTreeSet::new();
        set2.insert(ObservedType::Integer);
        set2.insert(ObservedType::Undefined);
        set2.insert(ObservedType::Float);

        let v1: Vec<_> = set1.iter().collect();
        let v2: Vec<_> = set2.iter().collect();
        assert_eq!(v1, v2, "BTreeSet iteration order should be deterministic");
    }

    // -----------------------------------------------------------------------
    // Deep tests: quickening level lattice monotonicity
    // -----------------------------------------------------------------------

    #[test]
    fn quickening_level_full_advance_chain() {
        let mut level = QuickeningLevel::Cold;
        let mut ranks = vec![level.rank()];
        while let Some(next) = level.advance() {
            level = next;
            ranks.push(level.rank());
        }
        assert_eq!(ranks, vec![0, 1, 2, 3]);
        assert_eq!(level, QuickeningLevel::Quickened);
    }

    #[test]
    fn quickening_level_reset_always_returns_cold() {
        for level in [
            QuickeningLevel::Cold,
            QuickeningLevel::Warm,
            QuickeningLevel::Hot,
            QuickeningLevel::Quickened,
        ] {
            assert_eq!(level.reset(), QuickeningLevel::Cold);
        }
    }

    // -----------------------------------------------------------------------
    // Additional tests: lattice operations, edge cases, and determinism
    // -----------------------------------------------------------------------

    #[test]
    fn quickening_level_advance_is_strictly_monotone() {
        let levels = [
            QuickeningLevel::Cold,
            QuickeningLevel::Warm,
            QuickeningLevel::Hot,
        ];
        for level in levels {
            let next = level.advance().unwrap();
            assert!(
                next.rank() > level.rank(),
                "advance from {level} should produce a strictly higher rank"
            );
        }
    }

    #[test]
    fn quickening_level_hash_consistency() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        QuickeningLevel::Hot.hash(&mut h1);
        QuickeningLevel::Hot.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
        let mut h3 = DefaultHasher::new();
        let mut h4 = DefaultHasher::new();
        QuickeningLevel::Cold.hash(&mut h3);
        QuickeningLevel::Quickened.hash(&mut h4);
        assert_ne!(h3.finish(), h4.finish());
    }

    #[test]
    fn observed_type_hash_determinism() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let types = [
            ObservedType::Undefined,
            ObservedType::Null,
            ObservedType::Boolean,
            ObservedType::Integer,
            ObservedType::Float,
            ObservedType::String,
            ObservedType::Object,
            ObservedType::Symbol,
            ObservedType::BigInt,
        ];
        for ty in &types {
            let mut h1 = DefaultHasher::new();
            let mut h2 = DefaultHasher::new();
            ty.hash(&mut h1);
            ty.hash(&mut h2);
            assert_eq!(h1.finish(), h2.finish(), "hash should be stable for {ty}");
        }
    }

    #[test]
    fn type_feedback_slot_all_nine_types_recorded() {
        let mut slot = TypeFeedbackSlot::new(0, 0);
        let all_types = [
            ObservedType::Undefined,
            ObservedType::Null,
            ObservedType::Boolean,
            ObservedType::Integer,
            ObservedType::Float,
            ObservedType::String,
            ObservedType::Object,
            ObservedType::Symbol,
            ObservedType::BigInt,
        ];
        for ty in &all_types {
            slot.record(*ty);
        }
        assert_eq!(slot.observed_types.len(), 9);
        assert_eq!(slot.observation_count, 9);
        assert!(slot.is_polymorphic());
        assert!(!slot.is_monomorphic());
        assert_eq!(slot.monomorphic_type(), None);
        assert_eq!(slot.stability_millionths(), 111_111);
    }

    #[test]
    fn type_feedback_slot_serde_roundtrip_polymorphic() {
        let mut slot = TypeFeedbackSlot::new(100, 2);
        slot.record(ObservedType::Integer);
        slot.record(ObservedType::Float);
        slot.record(ObservedType::String);
        slot.record(ObservedType::Integer);
        assert_eq!(slot.observation_count, 4);
        assert_eq!(slot.observed_types.len(), 3);
        let json = serde_json::to_string(&slot).unwrap();
        let back: TypeFeedbackSlot = serde_json::from_str(&json).unwrap();
        assert_eq!(slot, back);
        assert_eq!(back.observation_count, 4);
        assert_eq!(back.observed_types.len(), 3);
    }

    #[test]
    fn type_feedback_slot_display_multiple_types_ordered() {
        let mut slot = TypeFeedbackSlot::new(5, 0);
        slot.record(ObservedType::Object);
        slot.record(ObservedType::Null);
        slot.record(ObservedType::Boolean);
        let display = format!("{slot}");
        assert!(display.contains("null"));
        assert!(display.contains("boolean"));
        assert!(display.contains("object"));
        assert!(display.contains("n=3"));
    }

    #[test]
    fn instruction_feedback_evaluate_exact_warm_threshold_boundary() {
        let policy = QuickeningPolicy {
            warm_threshold: 10,
            ..QuickeningPolicy::default()
        };
        let mut fb = InstructionFeedback::new(0, "add");
        for _ in 0..9 {
            fb.record_execution();
        }
        let t = fb.evaluate(&policy);
        assert!(!t.advanced);
        assert_eq!(fb.level, QuickeningLevel::Cold);
        fb.record_execution();
        let t = fb.evaluate(&policy);
        assert!(t.advanced);
        assert_eq!(fb.level, QuickeningLevel::Warm);
    }

    #[test]
    fn instruction_feedback_evaluate_exact_hot_threshold_boundary() {
        let policy = QuickeningPolicy {
            warm_threshold: 1,
            hot_threshold: 50,
            ..QuickeningPolicy::default()
        };
        let mut fb = InstructionFeedback::new(0, "add");
        for _ in 0..49 {
            fb.record_execution();
        }
        fb.evaluate(&policy);
        let t = fb.evaluate(&policy);
        assert!(!t.advanced);
        assert_eq!(fb.level, QuickeningLevel::Warm);
        fb.record_execution();
        let t = fb.evaluate(&policy);
        assert!(t.advanced);
        assert_eq!(fb.level, QuickeningLevel::Hot);
    }

    #[test]
    fn instruction_feedback_quickening_blocked_by_stability_boundary() {
        let policy = QuickeningPolicy {
            warm_threshold: 1,
            hot_threshold: 2,
            min_stability_millionths: 500_001,
            min_ic_hit_rate_millionths: 0,
            max_polymorphic_types: 5,
            deopt_resets_to_cold: true,
        };
        let mut fb = InstructionFeedback::new(0, "add");
        for _ in 0..10 {
            fb.record_execution();
        }
        fb.record_type(0, ObservedType::Integer);
        fb.record_type(0, ObservedType::Float);
        fb.evaluate(&policy);
        fb.evaluate(&policy);
        let t = fb.evaluate(&policy);
        assert!(!t.advanced);
        assert_eq!(fb.level, QuickeningLevel::Hot);
    }

    #[test]
    fn instruction_feedback_quickening_passes_exact_stability_boundary() {
        let policy = QuickeningPolicy {
            warm_threshold: 1,
            hot_threshold: 2,
            min_stability_millionths: 500_000,
            min_ic_hit_rate_millionths: 0,
            max_polymorphic_types: 5,
            deopt_resets_to_cold: true,
        };
        let mut fb = InstructionFeedback::new(0, "add");
        for _ in 0..10 {
            fb.record_execution();
        }
        fb.record_type(0, ObservedType::Integer);
        fb.record_type(0, ObservedType::Float);
        fb.evaluate(&policy);
        fb.evaluate(&policy);
        let t = fb.evaluate(&policy);
        assert!(t.advanced);
        assert_eq!(fb.level, QuickeningLevel::Quickened);
    }

    #[test]
    fn instruction_feedback_max_polymorphic_types_exact_boundary() {
        let policy = QuickeningPolicy {
            warm_threshold: 1,
            hot_threshold: 2,
            min_stability_millionths: 0,
            min_ic_hit_rate_millionths: 0,
            max_polymorphic_types: 2,
            deopt_resets_to_cold: true,
        };
        let mut fb = InstructionFeedback::new(0, "add");
        for _ in 0..10 {
            fb.record_execution();
        }
        fb.record_type(0, ObservedType::Integer);
        fb.record_type(0, ObservedType::Float);
        fb.evaluate(&policy);
        fb.evaluate(&policy);
        let t = fb.evaluate(&policy);
        assert!(t.advanced);
        assert_eq!(fb.level, QuickeningLevel::Quickened);

        let mut fb2 = InstructionFeedback::new(0, "add");
        for _ in 0..10 {
            fb2.record_execution();
        }
        fb2.record_type(0, ObservedType::Integer);
        fb2.record_type(0, ObservedType::Float);
        fb2.record_type(0, ObservedType::String);
        fb2.evaluate(&policy);
        fb2.evaluate(&policy);
        let t2 = fb2.evaluate(&policy);
        assert!(!t2.advanced);
        assert_eq!(fb2.level, QuickeningLevel::Hot);
    }

    #[test]
    fn instruction_feedback_multiple_deopts_accumulate() {
        let policy = QuickeningPolicy::default();
        let mut fb = InstructionFeedback::new(0, "add");
        fb.record_deopt(&policy);
        fb.record_deopt(&policy);
        fb.record_deopt(&policy);
        assert_eq!(fb.deopt_count, 3);
    }

    #[test]
    fn instruction_feedback_deopt_clears_quickened_opcode() {
        let policy = QuickeningPolicy::default();
        let mut fb = InstructionFeedback::new(0, "add");
        fb.quickened_opcode = Some("fast_add".to_string());
        fb.record_deopt(&policy);
        assert!(fb.quickened_opcode.is_none());
    }

    #[test]
    fn instruction_feedback_evaluate_transition_fields_correct() {
        let policy = QuickeningPolicy {
            warm_threshold: 5,
            ..QuickeningPolicy::default()
        };
        let mut fb = InstructionFeedback::new(42, "load");
        for _ in 0..10 {
            fb.record_execution();
        }
        let t = fb.evaluate(&policy);
        assert!(t.advanced);
        assert_eq!(t.instruction_offset, 42);
        assert_eq!(t.from, QuickeningLevel::Cold);
        assert_eq!(t.to, QuickeningLevel::Warm);
        assert_eq!(t.execution_count, 10);
    }

    #[test]
    fn instruction_feedback_serde_with_all_fields_populated() {
        let mut fb = InstructionFeedback::new(99, "complex_op");
        for _ in 0..50 {
            fb.record_execution();
        }
        fb.record_type(0, ObservedType::Integer);
        fb.record_type(1, ObservedType::String);
        fb.record_type(1, ObservedType::Object);
        fb.update_ic_hit_rate(850_000);
        fb.quickened_opcode = Some("fast_complex_op".to_string());
        fb.deopt_count = 7;
        fb.level = QuickeningLevel::Quickened;
        let json = serde_json::to_string(&fb).unwrap();
        let back: InstructionFeedback = serde_json::from_str(&json).unwrap();
        assert_eq!(fb, back);
        assert_eq!(back.type_slots.len(), 2);
        assert_eq!(back.type_slots[0].observed_types.len(), 1);
        assert_eq!(back.type_slots[1].observed_types.len(), 2);
    }

    #[test]
    fn quickening_policy_hash_changes_with_each_field() {
        let base = QuickeningPolicy::default();
        let base_hash = base.policy_hash();
        let p1 = QuickeningPolicy {
            warm_threshold: base.warm_threshold + 1,
            ..base.clone()
        };
        assert_ne!(p1.policy_hash(), base_hash);
        let p2 = QuickeningPolicy {
            hot_threshold: base.hot_threshold + 1,
            ..base.clone()
        };
        assert_ne!(p2.policy_hash(), base_hash);
        let p3 = QuickeningPolicy {
            min_stability_millionths: base.min_stability_millionths + 1,
            ..base.clone()
        };
        assert_ne!(p3.policy_hash(), base_hash);
        let p4 = QuickeningPolicy {
            min_ic_hit_rate_millionths: base.min_ic_hit_rate_millionths + 1,
            ..base.clone()
        };
        assert_ne!(p4.policy_hash(), base_hash);
        let p5 = QuickeningPolicy {
            max_polymorphic_types: base.max_polymorphic_types + 1,
            ..base.clone()
        };
        assert_ne!(p5.policy_hash(), base_hash);
        let p6 = QuickeningPolicy {
            deopt_resets_to_cold: !base.deopt_resets_to_cold,
            ..base.clone()
        };
        assert_ne!(p6.policy_hash(), base_hash);
    }

    #[test]
    fn quickening_profile_hash_changes_with_state() {
        let mut p1 = QuickeningProfile::new("fn_a");
        let hash_empty = p1.profile_hash();
        p1.record_execution(0, "add");
        let hash_one = p1.profile_hash();
        assert_ne!(hash_empty, hash_one);
        p1.record_type(0, "add", 0, ObservedType::Integer);
        let hash_with_type = p1.profile_hash();
        assert_ne!(hash_one, hash_with_type);
    }

    #[test]
    fn quickening_profile_different_function_ids_different_hashes() {
        let p1 = QuickeningProfile::new("fn_alpha");
        let p2 = QuickeningProfile::new("fn_beta");
        assert_ne!(p1.profile_hash(), p2.profile_hash());
    }

    #[test]
    fn quickening_profile_superinstruction_store_jump_no_ic_needed() {
        let policy = QuickeningPolicy {
            warm_threshold: 1,
            hot_threshold: 2,
            min_stability_millionths: 0,
            min_ic_hit_rate_millionths: 0,
            max_polymorphic_types: 5,
            deopt_resets_to_cold: true,
        };
        let catalog = SuperInstructionCatalog::default();
        let mut profile = QuickeningProfile::new("store_jump_test");
        for _ in 0..10 {
            profile.record_execution(0, "store_prop");
            profile.record_execution(4, "jump");
        }
        profile.evaluate_all(&policy);
        profile.evaluate_all(&policy);
        let candidates = profile.find_superinstruction_candidates(&catalog);
        let store_jump: Vec<_> = candidates
            .iter()
            .filter(|c| c.fused_opcode == "store_prop_and_jump")
            .collect();
        assert!(
            !store_jump.is_empty(),
            "store_prop_and_jump should be found without IC requirement"
        );
    }

    #[test]
    fn quickening_profile_evaluate_all_returns_only_advances() {
        let policy = QuickeningPolicy {
            warm_threshold: 1,
            hot_threshold: 100,
            ..QuickeningPolicy::default()
        };
        let mut profile = QuickeningProfile::new("only_advances");
        for _ in 0..5 {
            profile.record_execution(0, "add");
        }
        let t1 = profile.evaluate_all(&policy);
        assert_eq!(t1.len(), 1);
        assert!(t1[0].advanced);
        let t2 = profile.evaluate_all(&policy);
        assert!(t2.is_empty());
    }

    #[test]
    fn quickening_profile_summary_after_deopt_and_re_evaluation() {
        let policy = QuickeningPolicy {
            warm_threshold: 1,
            hot_threshold: 2,
            min_stability_millionths: 0,
            min_ic_hit_rate_millionths: 0,
            max_polymorphic_types: 10,
            deopt_resets_to_cold: true,
        };
        let mut profile = QuickeningProfile::new("deopt_and_re_eval");
        for _ in 0..10 {
            profile.record_execution(0, "add");
        }
        profile.evaluate_all(&policy);
        profile.evaluate_all(&policy);
        profile.evaluate_all(&policy);
        let s1 = profile.summary();
        assert_eq!(s1.quickened_count, 1);
        profile.record_deopt(0, &policy);
        let s2 = profile.summary();
        assert_eq!(s2.quickened_count, 0);
        assert_eq!(s2.cold_count, 1);
        assert_eq!(s2.total_deopts, 1);
    }

    #[test]
    fn quickening_profile_serde_roundtrip_full() {
        let policy = QuickeningPolicy {
            warm_threshold: 1,
            hot_threshold: 2,
            min_stability_millionths: 0,
            min_ic_hit_rate_millionths: 0,
            max_polymorphic_types: 10,
            deopt_resets_to_cold: true,
        };
        let mut profile = QuickeningProfile::new("full_serde");
        for _ in 0..10 {
            profile.record_execution(0, "add");
            profile.record_execution(4, "sub");
        }
        profile.record_type(0, "add", 0, ObservedType::Integer);
        profile.record_type(4, "sub", 0, ObservedType::Float);
        profile.record_type(4, "sub", 0, ObservedType::String);
        profile.evaluate_all(&policy);
        profile.evaluate_all(&policy);
        profile.record_deopt(4, &policy);
        let json = serde_json::to_string(&profile).unwrap();
        let back: QuickeningProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(profile.function_id, back.function_id);
        assert_eq!(profile.total_executions, back.total_executions);
        assert_eq!(profile.total_deopts, back.total_deopts);
        assert_eq!(profile.evaluation_epoch, back.evaluation_epoch);
        assert_eq!(profile.entry_count(), back.entry_count());
        assert_eq!(profile.profile_hash(), back.profile_hash());
    }

    #[test]
    fn quickening_decision_hash_changes_with_transitions() {
        let policy = QuickeningPolicy::default();
        let profile = QuickeningProfile::new("fn_dec_diff");
        let d1 = QuickeningDecision::build(&profile, &policy, vec![], vec![]);
        let d2 = QuickeningDecision::build(
            &profile,
            &policy,
            vec![QuickeningTransition {
                instruction_offset: 0,
                from: QuickeningLevel::Cold,
                to: QuickeningLevel::Warm,
                execution_count: 10,
                advanced: true,
            }],
            vec![],
        );
        assert_ne!(d1.decision_hash, d2.decision_hash);
    }

    #[test]
    fn quickening_decision_serde_roundtrip_with_content() {
        let policy = QuickeningPolicy::default();
        let profile = QuickeningProfile::new("fn_full_dec");
        let transitions = vec![
            QuickeningTransition {
                instruction_offset: 0,
                from: QuickeningLevel::Cold,
                to: QuickeningLevel::Warm,
                execution_count: 8,
                advanced: true,
            },
            QuickeningTransition {
                instruction_offset: 4,
                from: QuickeningLevel::Warm,
                to: QuickeningLevel::Hot,
                execution_count: 64,
                advanced: true,
            },
        ];
        let candidates = vec![SuperInstructionCandidate {
            start_offset: 0,
            pattern_id: "si-load-add".into(),
            fused_opcode: "load_prop_and_add".into(),
            estimated_speedup_millionths: 1_300_000,
        }];
        let decision =
            QuickeningDecision::build(&profile, &policy, transitions, candidates);
        let json = serde_json::to_string(&decision).unwrap();
        let back: QuickeningDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, back);
        assert_eq!(back.transitions.len(), 2);
        assert_eq!(back.superinstruction_candidates.len(), 1);
    }

    #[test]
    fn superinstruction_pattern_display_arrow_separator() {
        let p = SuperInstructionPattern {
            pattern_id: "test".into(),
            opcode_sequence: vec!["load".into(), "add".into(), "store".into()],
            fused_opcode: "fused_las".into(),
            type_constraints: BTreeMap::new(),
            requires_monomorphic_ic: false,
            estimated_speedup_millionths: 1_000_000,
        };
        let display = format!("{p}");
        assert!(
            display.contains("load \u{2192} add \u{2192} store"),
            "display should show arrow-separated opcodes, got: {display}"
        );
    }

    #[test]
    fn superinstruction_pattern_display_speedup_exactly_1x() {
        let p = SuperInstructionPattern {
            pattern_id: "test".into(),
            opcode_sequence: vec!["a".into(), "b".into()],
            fused_opcode: "fused_ab".into(),
            type_constraints: BTreeMap::new(),
            requires_monomorphic_ic: false,
            estimated_speedup_millionths: 1_000_000,
        };
        let display = format!("{p}");
        assert!(display.contains("1.0x"), "expected 1.0x, got: {display}");
    }

    #[test]
    fn superinstruction_catalog_version_starts_at_one() {
        let catalog = SuperInstructionCatalog::new(vec![]);
        assert_eq!(catalog.catalog_version, 1);
    }

    #[test]
    fn superinstruction_catalog_version_saturates() {
        let mut catalog = SuperInstructionCatalog::new(vec![]);
        catalog.catalog_version = u32::MAX;
        catalog.add_pattern(SuperInstructionPattern {
            pattern_id: "overflow".into(),
            opcode_sequence: vec!["a".into()],
            fused_opcode: "fused_a".into(),
            type_constraints: BTreeMap::new(),
            requires_monomorphic_ic: false,
            estimated_speedup_millionths: 1_000_000,
        });
        assert_eq!(catalog.catalog_version, u32::MAX);
    }

    #[test]
    fn quickening_profile_entry_count_tracks_distinct_offsets() {
        let mut profile = QuickeningProfile::new("entry_count");
        assert_eq!(profile.entry_count(), 0);
        profile.record_execution(0, "add");
        assert_eq!(profile.entry_count(), 1);
        profile.record_execution(0, "add");
        assert_eq!(profile.entry_count(), 1);
        profile.record_execution(4, "sub");
        assert_eq!(profile.entry_count(), 2);
        profile.record_execution(8, "mul");
        assert_eq!(profile.entry_count(), 3);
    }

    #[test]
    fn quickening_profile_candidates_not_found_for_partial_sequence() {
        let policy = QuickeningPolicy {
            warm_threshold: 1,
            hot_threshold: 2,
            min_stability_millionths: 0,
            min_ic_hit_rate_millionths: 0,
            max_polymorphic_types: 5,
            deopt_resets_to_cold: true,
        };
        let catalog = SuperInstructionCatalog::default();
        let mut profile = QuickeningProfile::new("partial");
        for _ in 0..10 {
            profile.record_execution(0, "load_prop_cached");
        }
        if let Some(fb) = profile.entries.get_mut(&0) {
            fb.update_ic_hit_rate(950_000);
        }
        profile.evaluate_all(&policy);
        profile.evaluate_all(&policy);
        let candidates = profile.find_superinstruction_candidates(&catalog);
        let load_patterns: Vec<_> = candidates
            .iter()
            .filter(|c| c.fused_opcode.starts_with("load_prop"))
            .collect();
        assert!(load_patterns.is_empty());
    }

    #[test]
    fn quickening_transition_not_advanced_has_same_from_and_to() {
        let policy = QuickeningPolicy::default();
        let mut fb = InstructionFeedback::new(0, "nop");
        let t = fb.evaluate(&policy);
        assert!(!t.advanced);
        assert_eq!(t.from, QuickeningLevel::Cold);
        assert_eq!(t.to, QuickeningLevel::Cold);
    }

    #[test]
    fn quickening_profile_deopt_resets_to_warm_policy() {
        let policy = QuickeningPolicy {
            warm_threshold: 1,
            hot_threshold: 2,
            min_stability_millionths: 0,
            min_ic_hit_rate_millionths: 0,
            max_polymorphic_types: 10,
            deopt_resets_to_cold: false,
        };
        let mut profile = QuickeningProfile::new("warm_deopt");
        for _ in 0..10 {
            profile.record_execution(0, "add");
        }
        profile.evaluate_all(&policy);
        profile.evaluate_all(&policy);
        profile.evaluate_all(&policy);
        assert_eq!(
            profile.get(0).unwrap().level,
            QuickeningLevel::Quickened
        );
        profile.record_deopt(0, &policy);
        assert_eq!(profile.get(0).unwrap().level, QuickeningLevel::Warm);
    }

    #[test]
    fn quickening_summary_serde_all_zero() {
        let s = QuickeningSummary {
            total_sites: 0,
            cold_count: 0,
            warm_count: 0,
            hot_count: 0,
            quickened_count: 0,
            total_executions: 0,
            total_deopts: 0,
            evaluation_epoch: 0,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: QuickeningSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn default_patterns_unique_pattern_ids() {
        let patterns = default_superinstruction_patterns();
        let ids: BTreeSet<&str> = patterns.iter().map(|p| p.pattern_id.as_str()).collect();
        assert_eq!(ids.len(), patterns.len(), "all pattern IDs should be unique");
    }

    #[test]
    fn default_patterns_unique_fused_opcodes() {
        let patterns = default_superinstruction_patterns();
        let fused: BTreeSet<&str> =
            patterns.iter().map(|p| p.fused_opcode.as_str()).collect();
        assert_eq!(
            fused.len(),
            patterns.len(),
            "all fused opcodes should be unique"
        );
    }

    #[test]
    fn instruction_feedback_ic_hit_rate_boundary_for_quickening() {
        let policy = QuickeningPolicy {
            warm_threshold: 1,
            hot_threshold: 2,
            min_stability_millionths: 0,
            min_ic_hit_rate_millionths: 600_000,
            max_polymorphic_types: 5,
            deopt_resets_to_cold: true,
        };
        let mut fb = InstructionFeedback::new(0, "add");
        for _ in 0..10 {
            fb.record_execution();
            fb.record_type(0, ObservedType::Integer);
        }
        fb.update_ic_hit_rate(600_000);
        fb.evaluate(&policy);
        fb.evaluate(&policy);
        let t = fb.evaluate(&policy);
        assert!(t.advanced);
        assert_eq!(fb.level, QuickeningLevel::Quickened);

        let mut fb2 = InstructionFeedback::new(0, "add");
        for _ in 0..10 {
            fb2.record_execution();
            fb2.record_type(0, ObservedType::Integer);
        }
        fb2.update_ic_hit_rate(599_999);
        fb2.evaluate(&policy);
        fb2.evaluate(&policy);
        let t2 = fb2.evaluate(&policy);
        assert!(!t2.advanced);
        assert_eq!(fb2.level, QuickeningLevel::Hot);
    }
}
