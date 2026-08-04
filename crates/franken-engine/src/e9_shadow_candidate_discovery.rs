//! E9.T1 — Shadow-mode specialization candidate discovery + deterministic
//! baseline cost attribution (bd-fqlfw.9.1).
//!
//! Identifies candidate hot IR3 regions from an executed baseline run and
//! records their baseline cost, emitting candidate specialization receipts
//! into the specialization index — WITHOUT changing execution. This module is
//! a pure, post-hoc function over the lowered [`Ir3Module`] and run facts the
//! orchestrator already records; it takes `&Ir3Module` (never `&mut`), adds
//! no interpreter instrumentation, and therefore cannot perturb runtime
//! semantics, the deterministic tick clock, or replay identity.
//!
//! Shadow-first posture (E9 epic contract):
//! - v1 produces SHADOW evidence only; [`E9_ACTIVATION_ALLOWED`] is pinned
//!   `false` and serialized into every receipt.
//! - Discovery NEVER proposes `IfcCheckElision`: dominant families whose
//!   label-propagation lanes are unproven (iterator protocol, async/generator
//!   resumption, module graph, exception unwinding) are skipped outright,
//!   mirroring the E8 analyzed-subset boundary.
//! - Cost attribution is deterministic: per-op weights are the exact
//!   schedule-cost model behind `OrchestratorResult::ir3_schedule_cost`
//!   (shared via `ExecutionOrchestrator::instruction_cost`), and the run-level
//!   baseline cost is the interpreter's `instructions_executed` tick count —
//!   the engine-lane measurement the E2 differential-oracle harness records.
//!   Wall-clock denominators (E2 perf arm) are activation-benchmark scope
//!   (E9.T4), not shadow-discovery scope.
//!
//! Candidate identity is content-derived from the construct only (IR3 hash +
//! region + policy), never from run identity, so the same program region keeps
//! a stable `candidate_id` across runs — the dedup handle E9.T2 joins proofs
//! and benchmarks onto. The per-run receipt binding (trace/decision/tick
//! facts) lives in the receipt body and in the `EngineObjectId` used for
//! index insertion.
//!
//! All ratios are fixed-point millionths (1_000_000 = 1.0).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::{EngineObjectId, IdError, ObjectDomain, SchemaId, derive_id};
use crate::execution_orchestrator::ExecutionOrchestrator;
use crate::hash_tiers::ContentHash;
use crate::ir_contract::{Ir3Instruction, Ir3Module};
use crate::proof_specialization_receipt::OptimizationClass;
use crate::security_epoch::SecurityEpoch;
use crate::specialization_index::{
    SpecializationIndex, SpecializationIndexError, SpecializationRecord,
};
use crate::storage_adapter::StorageAdapter;

pub const E9_SHADOW_CANDIDATE_SCHEMA_VERSION: &str = "franken-engine.e9-shadow-candidate.v1";
pub const E9_SHADOW_DISCOVERY_REPORT_SCHEMA_VERSION: &str =
    "franken-engine.e9-shadow-discovery-report.v1";
pub const E9_SHADOW_POLICY_SCHEMA_VERSION: &str = "franken-engine.e9-shadow-discovery-policy.v1";
/// The discovery mode this module implements. Execution stays on the
/// baseline path; receipts are evidence, not activation.
pub const E9_SHADOW_MODE: &str = "shadow_v1";
/// Schema-pinned: a shadow candidate receipt can never authorize activation.
pub const E9_ACTIVATION_ALLOWED: bool = false;
/// Zone string for candidate receipt `EngineObjectId` derivation.
pub const E9_CANDIDATE_ID_ZONE: &str = "e9.shadow-candidate.v1";

const MILLIONTHS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// Op families
// ---------------------------------------------------------------------------

/// Coarse IR3 op families used for hot-region attribution.
///
/// Families in [`OpFamily::is_specializable`] may be proposed for a (shadow)
/// specialization class; the remainder are the unproven/hard lanes that the
/// E9 epic explicitly keeps out of v1 (they can still appear in histograms,
/// but a region they dominate is never proposed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpFamily {
    LoadImmediate,
    Arithmetic,
    Comparison,
    Bitwise,
    PropertyAccess,
    HeapAlloc,
    Call,
    HostCall,
    ControlFlow,
    ScopeBinding,
    IteratorProtocol,
    Exception,
    AsyncGenerator,
    ModuleGraph,
    Other,
}

impl OpFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LoadImmediate => "load_immediate",
            Self::Arithmetic => "arithmetic",
            Self::Comparison => "comparison",
            Self::Bitwise => "bitwise",
            Self::PropertyAccess => "property_access",
            Self::HeapAlloc => "heap_alloc",
            Self::Call => "call",
            Self::HostCall => "host_call",
            Self::ControlFlow => "control_flow",
            Self::ScopeBinding => "scope_binding",
            Self::IteratorProtocol => "iterator_protocol",
            Self::Exception => "exception",
            Self::AsyncGenerator => "async_generator",
            Self::ModuleGraph => "module_graph",
            Self::Other => "other",
        }
    }

    /// Whether a region dominated by this family may be proposed as a shadow
    /// specialization candidate in v1.
    pub fn is_specializable(self) -> bool {
        !matches!(
            self,
            Self::IteratorProtocol
                | Self::Exception
                | Self::AsyncGenerator
                | Self::ModuleGraph
                | Self::Other
        )
    }

    /// The optimization class a dominant family proposes.
    ///
    /// NEVER `IfcCheckElision`: security-check elision is out of scope for
    /// the entire shadow lane, and non-specializable families return `None`.
    pub fn proposed_class(self) -> Option<OptimizationClass> {
        if !self.is_specializable() {
            return None;
        }
        Some(match self {
            Self::HostCall => OptimizationClass::HostcallDispatchSpecialization,
            Self::ControlFlow => OptimizationClass::PathElimination,
            _ => OptimizationClass::SuperinstructionFusion,
        })
    }
}

/// Map a canonical IR3 mnemonic (as produced by
/// `ExecutionOrchestrator::instruction_mnemonic`) to its op family.
pub fn op_family_for_mnemonic(mnemonic: &str) -> OpFamily {
    match mnemonic {
        "load_int" | "load_bigint" | "load_float" | "load_str" | "load_bool" | "load_null"
        | "load_undefined" => OpFamily::LoadImmediate,
        "add" | "sub" | "mul" | "div" | "mod" | "exp" | "unary_neg" | "unary_plus"
        | "logical_not" | "typeof" | "void" => OpFamily::Arithmetic,
        "lt" | "lte" | "gt" | "gte" | "eq" | "strict_eq" | "not_eq" | "strict_not_eq"
        | "instance_of" | "in_op" => OpFamily::Comparison,
        "bit_and" | "bit_or" | "bit_xor" | "bit_not" | "shl" | "shr" | "ushr" => OpFamily::Bitwise,
        "get_property" | "set_property" | "define_accessor" | "delete_property" => {
            OpFamily::PropertyAccess
        }
        "new_object" | "new_array" | "array_push" | "array_slice" | "spread_into_array"
        | "spread_into_object" | "template_literal" => OpFamily::HeapAlloc,
        "call" | "call_method" | "construct" | "return" => OpFamily::Call,
        "host_call" => OpFamily::HostCall,
        "jump" | "jump_if" | "jump_if_nullish" | "halt" | "discard_abrupt_completion" => {
            OpFamily::ControlFlow
        }
        "move" | "push_scope" | "pop_scope" | "declare_binding" | "load_scoped"
        | "store_scoped" | "init_binding" | "create_closure" | "push_capture" | "load_this"
        | "load_new_target" | "load_super" => OpFamily::ScopeBinding,
        "for_in_init" | "for_in_next" | "for_of_init" | "for_of_next" | "iterator_close" => {
            OpFamily::IteratorProtocol
        }
        "begin_try" | "end_try" | "throw" | "enter_catch" | "enter_finally" | "end_finally" => {
            OpFamily::Exception
        }
        "generator_op"
        | "create_async_function"
        | "await_value"
        | "async_return"
        | "async_throw"
        | "create_async_generator" => OpFamily::AsyncGenerator,
        "import_module" | "export_binding" => OpFamily::ModuleGraph,
        _ => OpFamily::Other,
    }
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// Deterministic thresholds for shadow candidate discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowDiscoveryPolicy {
    pub schema_version: String,
    pub policy_id: String,
    /// Keep at most this many top-ranked candidates.
    pub max_candidates: usize,
    /// Regions with fewer instructions than this are noise.
    pub min_region_instructions: usize,
    /// Regions whose static cost is below this are not worth a receipt.
    pub min_region_static_cost: u64,
    /// The dominant family must hold at least this share of the region's
    /// static cost (millionths).
    pub min_dominance_millionths: u64,
}

impl Default for ShadowDiscoveryPolicy {
    fn default() -> Self {
        Self {
            schema_version: E9_SHADOW_POLICY_SCHEMA_VERSION.to_string(),
            policy_id: "policy-e9-shadow-discovery-v1".to_string(),
            max_candidates: 8,
            min_region_instructions: 3,
            min_region_static_cost: 4,
            min_dominance_millionths: 300_000,
        }
    }
}

impl ShadowDiscoveryPolicy {
    /// Content hash binding receipts to the exact thresholds that produced
    /// them.
    pub fn policy_hash_hex(&self) -> String {
        let bytes =
            serde_json::to_vec(self).expect("shadow discovery policy serialization should succeed");
        ContentHash::compute(&bytes).to_hex()
    }
}

// ---------------------------------------------------------------------------
// Regions and receipts
// ---------------------------------------------------------------------------

/// The kind of IR3 region a candidate covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionKind {
    /// A backward-jump loop body `[head, tail]`.
    LoopBody,
    /// A whole function body window.
    FunctionBody,
    /// The top-level instruction window before the first function entry.
    TopLevel,
}

impl RegionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LoopBody => "loop_body",
            Self::FunctionBody => "function_body",
            Self::TopLevel => "top_level",
        }
    }
}

/// A half-open candidate region `[start_index, end_index)` over the flat IR3
/// instruction stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateRegion {
    pub kind: RegionKind,
    pub start_index: u32,
    pub end_index: u32,
    /// Index into `Ir3Module::function_table` when the region sits inside a
    /// declared function window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_name: Option<String>,
    /// Number of enclosing loop regions (0 = not nested inside another loop).
    pub loop_depth: u32,
}

impl CandidateRegion {
    pub fn instruction_count(&self) -> usize {
        self.end_index.saturating_sub(self.start_index) as usize
    }
}

/// Deterministic binding of the discovery pass to the baseline run whose
/// facts it attributes. All fields are already recorded by the orchestrator;
/// nothing here adds instrumentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineRunFacts {
    pub trace_id: String,
    pub decision_id: String,
    pub extension_id: String,
    pub policy_epoch: u64,
    /// The interpreter's deterministic tick count for the whole run — the
    /// engine-lane baseline cost measurement (same counter the E2
    /// differential-oracle instruction budget meters).
    pub instructions_executed: u64,
}

/// One shadow specialization candidate: a region, its op-family histogram,
/// and its deterministic baseline cost attribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowCandidateReceipt {
    pub schema_version: String,
    pub mode: String,
    /// Pinned `false` for every shadow receipt; a consumer that sees `true`
    /// here is looking at a forged or future-schema artifact.
    pub activation_allowed: bool,
    /// Stable construct identity: content hash over (schema, IR3 hash,
    /// region, policy hash). Run-independent by construction.
    pub candidate_id: String,
    pub region: CandidateRegion,
    /// Static op counts per family inside the region.
    pub op_family_histogram: BTreeMap<String, u64>,
    pub dominant_family: String,
    /// Dominant family's share of the region's static cost (millionths).
    pub dominance_millionths: u64,
    /// Sum of deterministic per-op weights over the region (the schedule-cost
    /// model's weights).
    pub region_static_cost: u64,
    /// Same sum over the whole program.
    pub program_static_cost: u64,
    /// Region share of program static cost (millionths).
    pub static_cost_share_millionths: u64,
    /// The shadow-proposed optimization class (Display form). Never
    /// `ifc_check_elision`.
    pub proposed_optimization_class: String,
    /// IR3 program identity the region indexes into.
    pub ir3_content_hash_hex: String,
    pub baseline: BaselineRunFacts,
    pub policy_id: String,
    pub policy_hash_hex: String,
}

/// The full discovery pass output for one run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowDiscoveryReport {
    pub schema_version: String,
    pub mode: String,
    pub ir3_content_hash_hex: String,
    pub program_instruction_count: u64,
    pub program_static_cost: u64,
    pub policy_id: String,
    pub policy_hash_hex: String,
    pub baseline: BaselineRunFacts,
    /// Top-ranked candidates, highest rank weight first.
    pub candidates: Vec<ShadowCandidateReceipt>,
    /// Regions whose dominant family is not specializable in v1.
    pub skipped_non_specializable: u64,
    /// Regions filtered by size/cost/dominance thresholds.
    pub filtered_below_thresholds: u64,
    /// Regions dropped only by the `max_candidates` cap (so truncation is
    /// never silent).
    pub truncated_by_cap: u64,
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

fn mnemonic(instr: &Ir3Instruction) -> &'static str {
    ExecutionOrchestrator::instruction_mnemonic(instr)
}

fn op_cost(instr: &Ir3Instruction) -> u64 {
    // The schedule-cost model returns small positive i64 weights.
    u64::try_from(ExecutionOrchestrator::instruction_cost(instr)).unwrap_or(1)
}

/// Function windows over the flat instruction stream, sorted by entry.
/// Returns `(start, end, function_index, name)` half-open windows.
fn function_windows(module: &Ir3Module) -> Vec<(u32, u32, Option<u32>, Option<String>)> {
    let len = module.instructions.len() as u32;
    let mut entries: Vec<(u32, u32)> = module
        .function_table
        .iter()
        .enumerate()
        .map(|(idx, desc)| (desc.entry, idx as u32))
        .collect();
    entries.sort_unstable();

    let mut windows = Vec::new();
    if let Some(&(first_entry, _)) = entries.first() {
        if first_entry > 0 {
            windows.push((0, first_entry, None, None));
        }
    } else if len > 0 {
        windows.push((0, len, None, None));
    }
    for (pos, &(entry, table_index)) in entries.iter().enumerate() {
        let end = entries
            .get(pos + 1)
            .map(|&(next_entry, _)| next_entry)
            .unwrap_or(len);
        if entry >= end {
            continue;
        }
        let name = module
            .function_table
            .get(table_index as usize)
            .and_then(|desc| desc.name.clone());
        windows.push((entry, end, Some(table_index), name));
    }
    windows
}

/// Backward-jump loop regions inside a window: every `Jump`/`JumpIf`/
/// `JumpIfNullish` at `idx` whose target `t <= idx` and `t >= window start`
/// defines the closed loop body `[t, idx]`, recorded half-open as
/// `[t, idx + 1)`.
fn loop_regions_in_window(
    module: &Ir3Module,
    window_start: u32,
    window_end: u32,
) -> Vec<(u32, u32)> {
    let mut regions = Vec::new();
    for idx in window_start..window_end {
        let instr = &module.instructions[idx as usize];
        let target = match instr {
            Ir3Instruction::Jump { target } => Some(*target),
            Ir3Instruction::JumpIf { target, .. } => Some(*target),
            Ir3Instruction::JumpIfNullish { target, .. } => Some(*target),
            _ => None,
        };
        if let Some(target) = target
            && target <= idx
            && target >= window_start
        {
            regions.push((target, idx + 1));
        }
    }
    regions.sort_unstable();
    regions.dedup();
    regions
}

fn loop_depth(regions: &[(u32, u32)], region: (u32, u32)) -> u32 {
    regions
        .iter()
        .filter(|&&other| other != region && other.0 <= region.0 && region.1 <= other.1)
        .count() as u32
}

struct RegionFacts {
    region: CandidateRegion,
    histogram: BTreeMap<String, u64>,
    dominant_family: OpFamily,
    dominance_millionths: u64,
    static_cost: u64,
}

fn analyze_region(module: &Ir3Module, region: CandidateRegion) -> RegionFacts {
    let mut histogram: BTreeMap<String, u64> = BTreeMap::new();
    let mut family_cost: BTreeMap<OpFamily, u64> = BTreeMap::new();
    let mut static_cost: u64 = 0;
    for idx in region.start_index..region.end_index {
        let instr = &module.instructions[idx as usize];
        let family = op_family_for_mnemonic(mnemonic(instr));
        let cost = op_cost(instr);
        static_cost = static_cost.saturating_add(cost);
        *histogram.entry(family.as_str().to_string()).or_insert(0) += 1;
        *family_cost.entry(family).or_insert(0) += cost;
    }
    // Deterministic dominant pick: highest cost, then family order.
    let dominant_family = family_cost
        .iter()
        .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
        .map(|(family, _)| *family)
        .unwrap_or(OpFamily::Other);
    let dominant_cost = family_cost.get(&dominant_family).copied().unwrap_or(0);
    let dominance_millionths = dominant_cost
        .saturating_mul(MILLIONTHS)
        .checked_div(static_cost)
        .unwrap_or(0);
    RegionFacts {
        region,
        histogram,
        dominant_family,
        dominance_millionths,
        static_cost,
    }
}

fn candidate_id(
    ir3_content_hash_hex: &str,
    region: &CandidateRegion,
    policy_hash_hex: &str,
) -> String {
    // Length-prefixed field mixing so distinct decompositions cannot collide.
    let mut seed: Vec<u8> = Vec::new();
    for field in [
        E9_SHADOW_CANDIDATE_SCHEMA_VERSION,
        ir3_content_hash_hex,
        region.kind.as_str(),
        &region.start_index.to_string(),
        &region.end_index.to_string(),
        policy_hash_hex,
    ] {
        seed.extend_from_slice(&(field.len() as u64).to_be_bytes());
        seed.extend_from_slice(field.as_bytes());
    }
    ContentHash::compute(&seed).to_hex()
}

/// Run shadow-mode candidate discovery over an executed IR3 program.
///
/// Pure and deterministic: same module + facts + policy always yield the same
/// report. Takes the module by shared reference and performs no execution.
pub fn discover_candidates(
    module: &Ir3Module,
    facts: &BaselineRunFacts,
    policy: &ShadowDiscoveryPolicy,
) -> ShadowDiscoveryReport {
    let ir3_content_hash_hex = module.content_hash().to_hex();
    let policy_hash_hex = policy.policy_hash_hex();
    let program_static_cost: u64 = module.instructions.iter().map(op_cost).sum();

    // Collect regions: loop bodies (per window) + function windows + top level.
    let mut regions: Vec<CandidateRegion> = Vec::new();
    for (start, end, function_index, function_name) in function_windows(module) {
        let loops = loop_regions_in_window(module, start, end);
        for &(head, tail) in &loops {
            regions.push(CandidateRegion {
                kind: RegionKind::LoopBody,
                start_index: head,
                end_index: tail,
                function_index,
                function_name: function_name.clone(),
                loop_depth: loop_depth(&loops, (head, tail)),
            });
        }
        regions.push(CandidateRegion {
            kind: match function_index {
                Some(_) => RegionKind::FunctionBody,
                None => RegionKind::TopLevel,
            },
            start_index: start,
            end_index: end,
            function_index,
            function_name,
            loop_depth: 0,
        });
    }

    let mut skipped_non_specializable = 0u64;
    let mut filtered_below_thresholds = 0u64;
    let mut ranked: Vec<(u64, RegionFacts)> = Vec::new();
    for region in regions {
        let facts_for_region = analyze_region(module, region);
        if facts_for_region.region.instruction_count() < policy.min_region_instructions
            || facts_for_region.static_cost < policy.min_region_static_cost
            || facts_for_region.dominance_millionths < policy.min_dominance_millionths
        {
            filtered_below_thresholds += 1;
            continue;
        }
        if facts_for_region.dominant_family.proposed_class().is_none() {
            skipped_non_specializable += 1;
            continue;
        }
        // Loop bodies execute repeatedly per window entry, so they carry an
        // inherent iteration weight (deeper nesting weighs more); flat
        // windows run once per entry.
        let iteration_weight = match facts_for_region.region.kind {
            RegionKind::LoopBody => u64::from(facts_for_region.region.loop_depth) + 2,
            RegionKind::FunctionBody | RegionKind::TopLevel => 1,
        };
        let rank_weight = facts_for_region
            .static_cost
            .saturating_mul(iteration_weight);
        ranked.push((rank_weight, facts_for_region));
    }

    // Highest rank first; deterministic tie-breaks on position and kind.
    ranked.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| a.1.region.start_index.cmp(&b.1.region.start_index))
            .then_with(|| a.1.region.end_index.cmp(&b.1.region.end_index))
            .then_with(|| a.1.region.kind.cmp(&b.1.region.kind))
    });
    let truncated_by_cap = ranked.len().saturating_sub(policy.max_candidates) as u64;
    ranked.truncate(policy.max_candidates);

    let candidates = ranked
        .into_iter()
        .map(|(_, region_facts)| {
            let proposed = region_facts
                .dominant_family
                .proposed_class()
                .expect("non-specializable regions were skipped before ranking");
            ShadowCandidateReceipt {
                schema_version: E9_SHADOW_CANDIDATE_SCHEMA_VERSION.to_string(),
                mode: E9_SHADOW_MODE.to_string(),
                activation_allowed: E9_ACTIVATION_ALLOWED,
                candidate_id: candidate_id(
                    &ir3_content_hash_hex,
                    &region_facts.region,
                    &policy_hash_hex,
                ),
                region: region_facts.region,
                op_family_histogram: region_facts.histogram,
                dominant_family: region_facts.dominant_family.as_str().to_string(),
                dominance_millionths: region_facts.dominance_millionths,
                region_static_cost: region_facts.static_cost,
                program_static_cost,
                static_cost_share_millionths: region_facts
                    .static_cost
                    .saturating_mul(MILLIONTHS)
                    .checked_div(program_static_cost)
                    .unwrap_or(0),
                proposed_optimization_class: proposed.to_string(),
                ir3_content_hash_hex: ir3_content_hash_hex.clone(),
                baseline: facts.clone(),
                policy_id: policy.policy_id.clone(),
                policy_hash_hex: policy_hash_hex.clone(),
            }
        })
        .collect();

    ShadowDiscoveryReport {
        schema_version: E9_SHADOW_DISCOVERY_REPORT_SCHEMA_VERSION.to_string(),
        mode: E9_SHADOW_MODE.to_string(),
        ir3_content_hash_hex,
        program_instruction_count: module.instructions.len() as u64,
        program_static_cost,
        policy_id: policy.policy_id.clone(),
        policy_hash_hex,
        baseline: facts.clone(),
        candidates,
        skipped_non_specializable,
        filtered_below_thresholds,
        truncated_by_cap,
    }
}

// ---------------------------------------------------------------------------
// Index emission
// ---------------------------------------------------------------------------

/// Outcome of emitting one candidate receipt into the specialization index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateEmissionOutcome {
    pub candidate_id: String,
    pub receipt_id_hex: String,
    /// `inserted` or `duplicate_skipped` (same run re-emitted).
    pub outcome: String,
}

/// Errors from the emission lane.
#[derive(Debug)]
pub enum ShadowEmissionError {
    Id(IdError),
    Index(SpecializationIndexError),
    Serialization(String),
}

impl std::fmt::Display for ShadowEmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Id(err) => write!(f, "candidate receipt id derivation failed: {err:?}"),
            Self::Index(err) => write!(f, "specialization index rejected candidate: {err}"),
            Self::Serialization(detail) => write!(f, "candidate serialization failed: {detail}"),
        }
    }
}

impl std::error::Error for ShadowEmissionError {}

fn candidate_receipt_object_id(
    receipt: &ShadowCandidateReceipt,
) -> Result<EngineObjectId, ShadowEmissionError> {
    let canonical = serde_json::to_vec(receipt)
        .map_err(|err| ShadowEmissionError::Serialization(err.to_string()))?;
    derive_id(
        ObjectDomain::PolicyObject,
        E9_CANDIDATE_ID_ZONE,
        &SchemaId::from_definition(E9_SHADOW_CANDIDATE_SCHEMA_VERSION.as_bytes()),
        &canonical,
    )
    .map_err(ShadowEmissionError::Id)
}

/// Emit every candidate in the report into the specialization index as an
/// inactive (`active: false`) receipt with an empty proof set — the first
/// link of the proof → spec → benchmark audit chain that E9.T2 extends.
///
/// The record's deterministic logical timestamp is the run's tick count (the
/// interpreter's `timestamp_ns == instructions_executed` convention), so
/// emission never reads a wall clock. Re-emitting the same report is
/// idempotent: duplicates are reported as `duplicate_skipped`, never silently
/// dropped and never an error.
pub fn emit_candidates_into_index<S: StorageAdapter>(
    index: &mut SpecializationIndex<S>,
    report: &ShadowDiscoveryReport,
) -> Result<Vec<CandidateEmissionOutcome>, ShadowEmissionError> {
    let mut outcomes = Vec::with_capacity(report.candidates.len());
    for candidate in &report.candidates {
        let receipt_id = candidate_receipt_object_id(candidate)?;
        let optimization_class = match candidate.proposed_optimization_class.as_str() {
            "hostcall_dispatch_specialization" => OptimizationClass::HostcallDispatchSpecialization,
            "path_elimination" => OptimizationClass::PathElimination,
            "superinstruction_fusion" => OptimizationClass::SuperinstructionFusion,
            other => {
                return Err(ShadowEmissionError::Serialization(format!(
                    "shadow candidate proposed unexpected optimization class `{other}`"
                )));
            }
        };
        let record = SpecializationRecord {
            receipt_id,
            proof_input_ids: Vec::new(),
            proof_types: Vec::new(),
            optimization_class,
            extension_id: report.baseline.extension_id.clone(),
            epoch: SecurityEpoch::from_raw(report.baseline.policy_epoch),
            timestamp_ns: report.baseline.instructions_executed,
            active: false,
        };
        let outcome = match index.insert_receipt(&record, &report.baseline.trace_id) {
            Ok(()) => "inserted",
            Err(SpecializationIndexError::DuplicateReceipt { .. }) => "duplicate_skipped",
            Err(err) => return Err(ShadowEmissionError::Index(err)),
        };
        outcomes.push(CandidateEmissionOutcome {
            candidate_id: candidate.candidate_id.clone(),
            receipt_id_hex: record.receipt_id.to_hex(),
            outcome: outcome.to_string(),
        });
    }
    Ok(outcomes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir_contract::{
        Ir3FunctionDesc, Ir3Module, IrHeader, IrLevel, IrSchemaVersion, IteratorCloseReason,
    };
    use crate::storage_adapter::InMemoryStorageAdapter;

    fn header() -> IrHeader {
        IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir3,
            source_hash: None,
            source_label: "e9_test.js".to_string(),
        }
    }

    fn module_with(instructions: Vec<Ir3Instruction>) -> Ir3Module {
        Ir3Module {
            header: header(),
            instructions,
            constant_pool: Vec::new(),
            function_table: Vec::new(),
            specialization: None,
            required_capabilities: Vec::new(),
        }
    }

    fn facts() -> BaselineRunFacts {
        BaselineRunFacts {
            trace_id: "trace-e9-test".to_string(),
            decision_id: "decision-e9-test".to_string(),
            extension_id: "ext-e9-test".to_string(),
            policy_epoch: 1,
            instructions_executed: 420,
        }
    }

    fn add(dst: u32) -> Ir3Instruction {
        Ir3Instruction::Add {
            dst,
            lhs: 0,
            rhs: 1,
        }
    }

    fn arithmetic_loop_module() -> Ir3Module {
        // 0..=3 arithmetic body, 4 backward jump to 0, 5 halt.
        module_with(vec![
            add(2),
            add(3),
            Ir3Instruction::Mul {
                dst: 4,
                lhs: 2,
                rhs: 3,
            },
            Ir3Instruction::Sub {
                dst: 5,
                lhs: 4,
                rhs: 2,
            },
            Ir3Instruction::Jump { target: 0 },
            Ir3Instruction::Halt,
        ])
    }

    // -- op family mapping --------------------------------------------------

    #[test]
    fn arithmetic_mnemonics_map_to_arithmetic() {
        for m in ["add", "sub", "mul", "div", "mod", "exp"] {
            assert_eq!(op_family_for_mnemonic(m), OpFamily::Arithmetic, "{m}");
        }
    }

    #[test]
    fn membrane_and_call_families_are_distinct() {
        assert_eq!(op_family_for_mnemonic("host_call"), OpFamily::HostCall);
        assert_eq!(op_family_for_mnemonic("call"), OpFamily::Call);
        assert_eq!(op_family_for_mnemonic("call_method"), OpFamily::Call);
    }

    #[test]
    fn unproven_lanes_map_to_non_specializable_families() {
        for m in [
            "for_of_next",
            "iterator_close",
            "await_value",
            "import_module",
            "throw",
        ] {
            assert!(
                !op_family_for_mnemonic(m).is_specializable(),
                "{m} must not be specializable in shadow v1"
            );
        }
    }

    #[test]
    fn unknown_mnemonic_maps_to_other_and_is_not_specializable() {
        let family = op_family_for_mnemonic("mystery_future_op");
        assert_eq!(family, OpFamily::Other);
        assert!(!family.is_specializable());
        assert_eq!(family.proposed_class(), None);
    }

    #[test]
    fn no_family_ever_proposes_ifc_check_elision() {
        let all = [
            OpFamily::LoadImmediate,
            OpFamily::Arithmetic,
            OpFamily::Comparison,
            OpFamily::Bitwise,
            OpFamily::PropertyAccess,
            OpFamily::HeapAlloc,
            OpFamily::Call,
            OpFamily::HostCall,
            OpFamily::ControlFlow,
            OpFamily::ScopeBinding,
            OpFamily::IteratorProtocol,
            OpFamily::Exception,
            OpFamily::AsyncGenerator,
            OpFamily::ModuleGraph,
            OpFamily::Other,
        ];
        for family in all {
            assert_ne!(
                family.proposed_class(),
                Some(OptimizationClass::IfcCheckElision),
                "{family:?} proposed IFC-check elision"
            );
        }
    }

    #[test]
    fn hostcall_family_proposes_dispatch_specialization() {
        assert_eq!(
            OpFamily::HostCall.proposed_class(),
            Some(OptimizationClass::HostcallDispatchSpecialization)
        );
        assert_eq!(
            OpFamily::ControlFlow.proposed_class(),
            Some(OptimizationClass::PathElimination)
        );
        assert_eq!(
            OpFamily::Arithmetic.proposed_class(),
            Some(OptimizationClass::SuperinstructionFusion)
        );
    }

    // -- policy ---------------------------------------------------------------

    #[test]
    fn default_policy_hash_is_stable_across_calls() {
        let policy = ShadowDiscoveryPolicy::default();
        assert_eq!(policy.policy_hash_hex(), policy.policy_hash_hex());
    }

    #[test]
    fn policy_hash_changes_when_thresholds_change() {
        let base = ShadowDiscoveryPolicy::default();
        let mut looser = base.clone();
        looser.min_dominance_millionths = 0;
        assert_ne!(base.policy_hash_hex(), looser.policy_hash_hex());
    }

    // -- region discovery -----------------------------------------------------

    #[test]
    fn backward_jump_defines_a_loop_region() {
        let module = arithmetic_loop_module();
        let loops = loop_regions_in_window(&module, 0, module.instructions.len() as u32);
        assert_eq!(loops, vec![(0, 5)]);
    }

    #[test]
    fn forward_jump_is_not_a_loop() {
        let module = module_with(vec![
            Ir3Instruction::Jump { target: 2 },
            add(2),
            Ir3Instruction::Halt,
        ]);
        let loops = loop_regions_in_window(&module, 0, 3);
        assert!(loops.is_empty());
    }

    #[test]
    fn nested_loops_report_depth() {
        // outer: 0..=5 (jump at 5 -> 0); inner: 1..=3 (jump at 3 -> 1).
        let module = module_with(vec![
            add(2),
            add(3),
            add(4),
            Ir3Instruction::JumpIf { cond: 0, target: 1 },
            add(5),
            Ir3Instruction::Jump { target: 0 },
            Ir3Instruction::Halt,
        ]);
        let loops = loop_regions_in_window(&module, 0, 7);
        assert_eq!(loops, vec![(0, 6), (1, 4)]);
        assert_eq!(loop_depth(&loops, (0, 6)), 0);
        assert_eq!(loop_depth(&loops, (1, 4)), 1);
    }

    #[test]
    fn function_windows_cover_top_level_and_bodies() {
        let mut module = module_with(vec![
            add(2),
            Ir3Instruction::Halt,
            add(3),
            Ir3Instruction::Return { value: 3 },
            add(4),
            Ir3Instruction::Return { value: 4 },
        ]);
        module.function_table = vec![
            Ir3FunctionDesc {
                entry: 2,
                arity: 0,
                frame_size: 4,
                name: Some("f".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
            Ir3FunctionDesc {
                entry: 4,
                arity: 0,
                frame_size: 4,
                name: Some("g".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
        ];
        let windows = function_windows(&module);
        assert_eq!(windows.len(), 3);
        assert_eq!(windows[0], (0, 2, None, None));
        assert_eq!(windows[1], (2, 4, Some(0), Some("f".to_string())));
        assert_eq!(windows[2], (4, 6, Some(1), Some("g".to_string())));
    }

    #[test]
    fn module_without_functions_is_one_top_level_window() {
        let module = arithmetic_loop_module();
        let windows = function_windows(&module);
        assert_eq!(windows, vec![(0, 6, None, None)]);
    }

    #[test]
    fn empty_module_yields_empty_report() {
        let module = module_with(Vec::new());
        let report = discover_candidates(&module, &facts(), &ShadowDiscoveryPolicy::default());
        assert!(report.candidates.is_empty());
        assert_eq!(report.program_instruction_count, 0);
        assert_eq!(report.program_static_cost, 0);
    }

    // -- cost model -----------------------------------------------------------

    #[test]
    fn static_cost_uses_the_schedule_cost_weights() {
        // host_call = 4, call = 3, mul = 2, add = 1 (the orchestrator model).
        let module = module_with(vec![
            Ir3Instruction::Mul {
                dst: 2,
                lhs: 0,
                rhs: 1,
            },
            add(3),
        ]);
        let report = discover_candidates(
            &module,
            &facts(),
            &ShadowDiscoveryPolicy {
                min_region_instructions: 1,
                min_region_static_cost: 1,
                min_dominance_millionths: 0,
                ..ShadowDiscoveryPolicy::default()
            },
        );
        assert_eq!(report.program_static_cost, 3);
    }

    #[test]
    fn dominance_and_share_are_millionths() {
        let module = arithmetic_loop_module();
        let policy = ShadowDiscoveryPolicy {
            min_dominance_millionths: 0,
            ..ShadowDiscoveryPolicy::default()
        };
        let report = discover_candidates(&module, &facts(), &policy);
        let loop_candidate = report
            .candidates
            .iter()
            .find(|c| c.region.kind == RegionKind::LoopBody)
            .expect("loop candidate expected");
        // Loop body [0,5): add,add,mul,sub,jump = costs 1+1+2+1+1 = 6,
        // arithmetic cost 5 => dominance 5/6.
        assert_eq!(loop_candidate.region_static_cost, 6);
        assert_eq!(loop_candidate.dominance_millionths, 833_333);
        // Program cost = 6 + halt(1) = 7 => share 6/7.
        assert_eq!(loop_candidate.program_static_cost, 7);
        assert_eq!(loop_candidate.static_cost_share_millionths, 857_142);
        assert_eq!(loop_candidate.dominant_family, "arithmetic");
    }

    // -- ranking + filters ------------------------------------------------------

    #[test]
    fn loop_regions_outrank_flat_regions_of_equal_cost() {
        let module = arithmetic_loop_module();
        let policy = ShadowDiscoveryPolicy {
            min_dominance_millionths: 0,
            ..ShadowDiscoveryPolicy::default()
        };
        let report = discover_candidates(&module, &facts(), &policy);
        assert!(!report.candidates.is_empty());
        assert_eq!(report.candidates[0].region.kind, RegionKind::LoopBody);
    }

    #[test]
    fn max_candidates_cap_is_reported_not_silent() {
        let module = arithmetic_loop_module();
        let policy = ShadowDiscoveryPolicy {
            max_candidates: 1,
            min_dominance_millionths: 0,
            ..ShadowDiscoveryPolicy::default()
        };
        let report = discover_candidates(&module, &facts(), &policy);
        assert_eq!(report.candidates.len(), 1);
        assert_eq!(report.truncated_by_cap, 1);
    }

    #[test]
    fn small_regions_are_filtered() {
        let module = module_with(vec![add(2), Ir3Instruction::Halt]);
        let policy = ShadowDiscoveryPolicy::default();
        let report = discover_candidates(&module, &facts(), &policy);
        assert!(report.candidates.is_empty());
        assert!(report.filtered_below_thresholds > 0);
    }

    #[test]
    fn iterator_dominated_region_is_skipped_not_proposed() {
        let module = module_with(vec![
            Ir3Instruction::ForOfInit { src: 0, dst: 1 },
            Ir3Instruction::ForOfNext {
                iterator: 1,
                value_dst: 2,
                done_target: 5,
            },
            add(3),
            Ir3Instruction::Jump { target: 1 },
            Ir3Instruction::IteratorClose {
                iterator: 1,
                reason: IteratorCloseReason::Break,
            },
            Ir3Instruction::Halt,
        ]);
        let policy = ShadowDiscoveryPolicy {
            min_dominance_millionths: 0,
            min_region_static_cost: 1,
            ..ShadowDiscoveryPolicy::default()
        };
        let report = discover_candidates(&module, &facts(), &policy);
        assert!(report.skipped_non_specializable > 0);
        for candidate in &report.candidates {
            assert_ne!(candidate.dominant_family, "iterator_protocol");
        }
    }

    // -- receipts + determinism -------------------------------------------------

    #[test]
    fn discovery_is_deterministic() {
        let module = arithmetic_loop_module();
        let policy = ShadowDiscoveryPolicy {
            min_dominance_millionths: 0,
            ..ShadowDiscoveryPolicy::default()
        };
        let first = discover_candidates(&module, &facts(), &policy);
        let second = discover_candidates(&module, &facts(), &policy);
        assert_eq!(first, second);
    }

    #[test]
    fn candidate_id_is_run_independent() {
        let module = arithmetic_loop_module();
        let policy = ShadowDiscoveryPolicy {
            min_dominance_millionths: 0,
            ..ShadowDiscoveryPolicy::default()
        };
        let mut other_run = facts();
        other_run.trace_id = "trace-e9-other".to_string();
        other_run.instructions_executed = 999;
        let first = discover_candidates(&module, &facts(), &policy);
        let second = discover_candidates(&module, &other_run, &policy);
        let first_ids: Vec<_> = first.candidates.iter().map(|c| &c.candidate_id).collect();
        let second_ids: Vec<_> = second.candidates.iter().map(|c| &c.candidate_id).collect();
        assert_eq!(first_ids, second_ids);
        assert_ne!(
            first.candidates[0].baseline.trace_id,
            second.candidates[0].baseline.trace_id
        );
    }

    #[test]
    fn candidate_id_changes_with_program_content() {
        let module = arithmetic_loop_module();
        let mut other = arithmetic_loop_module();
        other.instructions[0] = Ir3Instruction::Sub {
            dst: 2,
            lhs: 0,
            rhs: 1,
        };
        let policy = ShadowDiscoveryPolicy {
            min_dominance_millionths: 0,
            ..ShadowDiscoveryPolicy::default()
        };
        let first = discover_candidates(&module, &facts(), &policy);
        let second = discover_candidates(&other, &facts(), &policy);
        assert_ne!(
            first.candidates[0].candidate_id,
            second.candidates[0].candidate_id
        );
    }

    #[test]
    fn receipts_pin_shadow_mode_and_never_allow_activation() {
        let module = arithmetic_loop_module();
        let policy = ShadowDiscoveryPolicy {
            min_dominance_millionths: 0,
            ..ShadowDiscoveryPolicy::default()
        };
        let report = discover_candidates(&module, &facts(), &policy);
        assert_eq!(report.mode, E9_SHADOW_MODE);
        for candidate in &report.candidates {
            assert!(!candidate.activation_allowed);
            assert_eq!(candidate.mode, E9_SHADOW_MODE);
            assert_ne!(candidate.proposed_optimization_class, "ifc_check_elision");
            let json = serde_json::to_string(candidate).expect("receipt serializes");
            assert!(json.contains("\"activation_allowed\":false"));
        }
    }

    #[test]
    fn baseline_facts_are_bound_into_every_receipt() {
        let module = arithmetic_loop_module();
        let policy = ShadowDiscoveryPolicy {
            min_dominance_millionths: 0,
            ..ShadowDiscoveryPolicy::default()
        };
        let report = discover_candidates(&module, &facts(), &policy);
        for candidate in &report.candidates {
            assert_eq!(candidate.baseline.instructions_executed, 420);
            assert_eq!(candidate.baseline.trace_id, "trace-e9-test");
            assert_eq!(candidate.ir3_content_hash_hex, report.ir3_content_hash_hex);
        }
    }

    // -- index emission -----------------------------------------------------------

    fn make_index() -> SpecializationIndex<InMemoryStorageAdapter> {
        SpecializationIndex::new(InMemoryStorageAdapter::new(), "policy-e9-test")
    }

    #[test]
    fn emission_inserts_inactive_records_with_empty_proofs() {
        let module = arithmetic_loop_module();
        let policy = ShadowDiscoveryPolicy {
            min_dominance_millionths: 0,
            ..ShadowDiscoveryPolicy::default()
        };
        let report = discover_candidates(&module, &facts(), &policy);
        assert!(!report.candidates.is_empty());

        let mut index = make_index();
        let outcomes = emit_candidates_into_index(&mut index, &report).expect("emission succeeds");
        assert_eq!(outcomes.len(), report.candidates.len());
        for outcome in &outcomes {
            assert_eq!(outcome.outcome, "inserted");
            let receipt_id =
                EngineObjectId::from_hex(&outcome.receipt_id_hex).expect("receipt id round-trips");
            let stored = index
                .get_receipt(&receipt_id, "trace-e9-test")
                .expect("lookup succeeds")
                .expect("record present");
            assert!(!stored.active, "shadow candidates must never be active");
            assert!(stored.proof_input_ids.is_empty());
            assert!(stored.proof_types.is_empty());
            assert_eq!(stored.extension_id, "ext-e9-test");
            assert_eq!(stored.timestamp_ns, 420);
        }
    }

    #[test]
    fn re_emission_is_idempotent_via_duplicate_skipped() {
        let module = arithmetic_loop_module();
        let policy = ShadowDiscoveryPolicy {
            min_dominance_millionths: 0,
            ..ShadowDiscoveryPolicy::default()
        };
        let report = discover_candidates(&module, &facts(), &policy);
        let mut index = make_index();
        emit_candidates_into_index(&mut index, &report).expect("first emission");
        let second = emit_candidates_into_index(&mut index, &report).expect("second emission");
        assert!(second.iter().all(|o| o.outcome == "duplicate_skipped"));
    }

    #[test]
    fn distinct_runs_of_same_program_emit_distinct_receipts() {
        let module = arithmetic_loop_module();
        let policy = ShadowDiscoveryPolicy {
            min_dominance_millionths: 0,
            ..ShadowDiscoveryPolicy::default()
        };
        let first_report = discover_candidates(&module, &facts(), &policy);
        let mut other_run = facts();
        other_run.trace_id = "trace-e9-other".to_string();
        other_run.decision_id = "decision-e9-other".to_string();
        let second_report = discover_candidates(&module, &other_run, &policy);

        let mut index = make_index();
        let first = emit_candidates_into_index(&mut index, &first_report).expect("first");
        let second = emit_candidates_into_index(&mut index, &second_report).expect("second");
        assert!(first.iter().all(|o| o.outcome == "inserted"));
        assert!(second.iter().all(|o| o.outcome == "inserted"));
        // Same construct identity, distinct run receipts.
        assert_eq!(first[0].candidate_id, second[0].candidate_id);
        assert_ne!(first[0].receipt_id_hex, second[0].receipt_id_hex);
    }

    #[test]
    fn discovery_takes_shared_module_reference() {
        // Compile-time posture check: discovery consumes &Ir3Module and the
        // module is untouched (usable afterwards).
        let module = arithmetic_loop_module();
        let policy = ShadowDiscoveryPolicy::default();
        let _ = discover_candidates(&module, &facts(), &policy);
        assert_eq!(module.instructions.len(), 6);
    }
}
