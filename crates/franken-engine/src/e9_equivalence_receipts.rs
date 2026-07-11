//! E9.T2 (bd-fqlfw.9.2): equivalence receipts + proof->spec->benchmark
//! persistence for shadow-mode specialization candidates.
//!
//! For every candidate discovered by the E9.T1 shadow pass
//! (`e9_shadow_candidate_discovery`), this lane:
//!
//! 1. Derives a **fail-closed equivalence verdict** from differential run
//!    facts (execution-value hash, deterministic tick count, and
//!    nondeterminism-trace hash of a baseline run vs. a shadow re-run).
//!    Only affirmatively complete AND byte-identical evidence yields
//!    `Proven`; any divergence is `Disproven`; anything incomplete or
//!    mismatched with the discovery run is `Inconclusive`. Nothing defaults
//!    to proven.
//! 2. Emits one signed `TranslationValidationReceipt` per candidate through
//!    the existing `ValidationReceiptEmitter` (chain integrity, quarantine),
//!    so equivalence verdicts reuse the fail-closed translation-validation
//!    machinery instead of a parallel implementation.
//! 3. Persists the audit chain **security proof -> specialization receipt ->
//!    benchmark outcome** into the `SpecializationIndex`: a proof-carrying
//!    `SpecializationRecord` for every candidate (always `active: false` in
//!    shadow mode) plus, for proven candidates only, an honest zero-delta
//!    `BenchmarkOutcome` (the shadow lane validates the identity
//!    specialization, so the measured delta is exactly zero).
//! 4. Wires the four invalidation reasons the index supports (epoch change,
//!    proof expiry, proof revocation, manual revocation) into lane-level
//!    helpers so E9.T3 can invalidate chains deterministically.
//!
//! Shadow-first invariants (test-pinned):
//! - `activation_allowed` is pinned `false` in every receipt and report;
//!   `activation_eligible` returns `false` in v1 even for proven receipts.
//! - Disproven candidates are quarantined by the emitter; inconclusive
//!   candidates are quarantined by the lane (config default). A quarantined
//!   candidate never receives a benchmark link.
//! - In shadow v1 the validated artifact is the *identity* specialization
//!   (`optimized_ir_hash == baseline_ir_hash`, zero applied rules, zero cost
//!   delta). E9.T4 feeds a real optimized artifact hash through the same
//!   lane via `EquivalenceLaneConfig::optimized_ir_hash_hex`.
//! - All timestamps are the deterministic logical clock
//!   (`instructions_executed`), never wall clock.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::e9_shadow_candidate_discovery::{
    E9_ACTIVATION_ALLOWED, E9_SHADOW_MODE, ShadowDiscoveryReport,
};
use crate::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use crate::execution_orchestrator::OrchestratorResult;
use crate::hash_tiers::ContentHash;
use crate::proof_specialization_receipt::{OptimizationClass, ProofType};
use crate::security_epoch::SecurityEpoch;
use crate::specialization_index::{
    BenchmarkOutcome, InvalidationEntry, InvalidationReason, SpecializationIndex,
    SpecializationIndexError, SpecializationRecord,
};
use crate::storage_adapter::StorageAdapter;
use crate::translation_validation_receipt::{
    EmitInput, EmitResult, EmitterConfig, ProofEvidence, ProofMode, RECEIPT_SCHEMA_VERSION,
    ReceiptChain, ReceiptSummary, ReceiptVerdict, ValidationReceiptEmitter,
};

// ---------------------------------------------------------------------------
// Schema versions and lane constants
// ---------------------------------------------------------------------------

/// Schema version for a single per-candidate equivalence receipt.
pub const E9_EQUIVALENCE_RECEIPT_SCHEMA_VERSION: &str = "franken-engine.e9-equivalence-receipt.v1";

/// Schema version for the lane-level equivalence report.
pub const E9_EQUIVALENCE_REPORT_SCHEMA_VERSION: &str = "franken-engine.e9-equivalence-report.v1";

/// Schema version for differential run facts.
pub const E9_DIFFERENTIAL_FACTS_SCHEMA_VERSION: &str = "franken-engine.e9-differential-facts.v1";

/// Schema version for the lane configuration.
pub const E9_EQUIVALENCE_LANE_CONFIG_SCHEMA_VERSION: &str =
    "franken-engine.e9-equivalence-lane-config.v1";

/// Zone for chain (proof-carrying) specialization receipt object ids.
pub const E9_CHAIN_RECEIPT_ZONE: &str = "e9.equivalence-chain.v1";

/// Zone for equivalence proof object ids (derived from TV receipt hashes).
pub const E9_EQUIVALENCE_PROOF_ZONE: &str = "e9.equivalence-proof.v1";

/// Canonical verdict strings (bead vocabulary, snake_case).
pub const VERDICT_PROVEN: &str = "proven";
pub const VERDICT_DISPROVEN: &str = "disproven";
pub const VERDICT_INCONCLUSIVE: &str = "inconclusive";

/// Canonical proof-type string persisted alongside the chain record.
///
/// Differential-trace equivalence evidence is replay-shaped: it proves the
/// shadow lane reproduces the baseline byte-for-byte, which is exactly the
/// replay-motif proof family (never a capability witness or flow proof).
pub const E9_EQUIVALENCE_PROOF_TYPE: &str = "replay_motif";

// ---------------------------------------------------------------------------
// Differential run facts
// ---------------------------------------------------------------------------

/// Content-hashed observable facts from one deterministic engine run,
/// sufficient to compare two runs for byte-level equivalence without
/// retaining the runs themselves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialRunFacts {
    /// Schema version pin.
    pub schema_version: String,
    /// Trace identifier of the run these facts were captured from.
    pub trace_id: String,
    /// Content hash (hex) of the run's execution value.
    pub execution_value_hash_hex: String,
    /// Deterministic instruction tick count of the run.
    pub instructions_executed: u64,
    /// Content hash (hex) of the run's serialized nondeterminism trace.
    pub nondeterminism_trace_hash_hex: String,
}

impl DifferentialRunFacts {
    /// Capture differential facts from an orchestrator result.
    ///
    /// Pure read-only projection: hashing the already-recorded execution
    /// value and nondeterminism trace cannot perturb execution or replay.
    pub fn from_result(result: &OrchestratorResult) -> Result<Self, E9EquivalenceError> {
        let trace_bytes = serde_json::to_vec(&result.nondeterminism_trace)
            .map_err(|err| E9EquivalenceError::Serialization(err.to_string()))?;
        Ok(Self {
            schema_version: E9_DIFFERENTIAL_FACTS_SCHEMA_VERSION.to_string(),
            trace_id: result.trace_id.clone(),
            execution_value_hash_hex: ContentHash::compute(result.execution_value.as_bytes())
                .to_hex(),
            instructions_executed: result.instructions_executed,
            nondeterminism_trace_hash_hex: ContentHash::compute(&trace_bytes).to_hex(),
        })
    }

    fn is_complete(&self) -> bool {
        !self.execution_value_hash_hex.is_empty()
            && !self.nondeterminism_trace_hash_hex.is_empty()
            && self.instructions_executed > 0
    }
}

// ---------------------------------------------------------------------------
// Lane configuration
// ---------------------------------------------------------------------------

/// Configuration for the equivalence-receipt lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivalenceLaneConfig {
    /// Schema version pin.
    pub schema_version: String,
    /// Lane policy identifier (recorded in every receipt).
    pub policy_id: String,
    /// Cost model identifier recorded in the TV receipts. Matches the
    /// deterministic IR3 schedule-cost model the discovery pass attributes
    /// costs with.
    pub cost_model_id: String,
    /// Proof budget in deterministic ticks for inconclusive accounting.
    pub proof_budget_ticks: u64,
    /// Quarantine inconclusive candidates as well as disproven ones.
    ///
    /// Fail-closed default: `true`. The E9 capstone contract
    /// (bd-fqlfw.9.6) requires that an inconclusive/disproven candidate is
    /// quarantined, never activated.
    pub quarantine_inconclusive: bool,
    /// Optional optimized artifact hash (hex). `None` selects the shadow-v1
    /// identity specialization (`optimized == baseline`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optimized_ir_hash_hex: Option<String>,
    /// Keyed-authenticity signing key for TV receipts (lane-scoped MAC key,
    /// not PKI; mirrors `translation_validation_receipt` semantics).
    pub signing_key: Vec<u8>,
}

impl Default for EquivalenceLaneConfig {
    fn default() -> Self {
        Self {
            schema_version: E9_EQUIVALENCE_LANE_CONFIG_SCHEMA_VERSION.to_string(),
            policy_id: "policy-e9-equivalence-v1".to_string(),
            cost_model_id: "ir3-schedule-cost-v1".to_string(),
            proof_budget_ticks: 10_000_000,
            quarantine_inconclusive: true,
            optimized_ir_hash_hex: None,
            signing_key: ContentHash::compute(b"franken-engine.e9-equivalence-lane.v1")
                .as_bytes()
                .to_vec(),
        }
    }
}

impl EquivalenceLaneConfig {
    /// Content hash (hex) of this configuration.
    pub fn policy_hash_hex(&self) -> String {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        ContentHash::compute(&bytes).to_hex()
    }
}

// ---------------------------------------------------------------------------
// Per-candidate receipt and lane report
// ---------------------------------------------------------------------------

/// Per-candidate equivalence receipt: the E9.T2 link between a discovered
/// shadow candidate, its translation-validation verdict, and the persisted
/// proof -> spec -> benchmark chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct E9EquivalenceReceipt {
    /// Schema version pin.
    pub schema_version: String,
    /// Lane mode; always [`E9_SHADOW_MODE`] in v1.
    pub mode: String,
    /// Pinned `false` in v1: shadow evidence only.
    pub activation_allowed: bool,
    /// Run-independent candidate identity (join handle to E9.T1).
    pub candidate_id: String,
    /// Proposed optimization class (snake_case string; never
    /// `ifc_check_elision`).
    pub optimization_class: String,
    /// Extension the candidate belongs to.
    pub extension_id: String,
    /// Trace id of the baseline run the verdict is anchored to.
    pub trace_id: String,
    /// Policy epoch of the baseline run.
    pub policy_epoch: u64,
    /// Deterministic logical timestamp (baseline instruction ticks).
    pub timestamp_ns: u64,
    /// Baseline IR3 content hash (hex).
    pub baseline_ir_hash_hex: String,
    /// Optimized artifact hash (hex); equals baseline in shadow v1.
    pub optimized_ir_hash_hex: String,
    /// Content hash (hex) of the signed translation-validation receipt.
    pub tv_receipt_content_hash_hex: String,
    /// Sequence of the TV receipt within the lane chain.
    pub tv_receipt_sequence: u64,
    /// Engine object id (hex) of the equivalence proof reference.
    pub proof_id_hex: String,
    /// Proof type persisted with the chain record.
    pub proof_type: String,
    /// Fail-closed verdict: `proven`, `disproven`, or `inconclusive`.
    pub verdict: String,
    /// Human-auditable verdict detail (divergence or reason).
    pub verdict_detail: String,
    /// Whether the candidate is quarantined (disproven, or inconclusive
    /// under the fail-closed default).
    pub quarantined: bool,
    /// Lane policy id.
    pub lane_policy_id: String,
    /// Lane policy hash (hex).
    pub lane_policy_hash_hex: String,
}

/// Lane-level report: every candidate's receipt plus the signed TV chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct E9EquivalenceReport {
    /// Schema version pin.
    pub schema_version: String,
    /// Lane mode; always [`E9_SHADOW_MODE`] in v1.
    pub mode: String,
    /// Pinned `false` in v1.
    pub activation_allowed: bool,
    /// Baseline IR3 content hash (hex) from the discovery report.
    pub ir3_content_hash_hex: String,
    /// Extension identity from the discovery baseline.
    pub extension_id: String,
    /// Baseline trace id.
    pub trace_id: String,
    /// Baseline policy epoch.
    pub policy_epoch: u64,
    /// Deterministic logical timestamp (baseline instruction ticks).
    pub timestamp_ns: u64,
    /// Lane policy id.
    pub lane_policy_id: String,
    /// Lane policy hash (hex).
    pub lane_policy_hash_hex: String,
    /// Per-candidate equivalence receipts (discovery ranking order).
    pub receipts: Vec<E9EquivalenceReceipt>,
    /// Count of proven candidates.
    pub proven_count: u64,
    /// Count of disproven candidates.
    pub disproven_count: u64,
    /// Count of inconclusive candidates.
    pub inconclusive_count: u64,
    /// Sorted candidate ids currently quarantined by this lane run.
    pub quarantined_candidate_ids: Vec<String>,
    /// The signed translation-validation receipt chain (incl. failures).
    pub chain: ReceiptChain,
    /// Emitter summary for the chain.
    pub chain_summary: ReceiptSummary,
}

/// Whether a receipt is eligible for activation.
///
/// Shadow-first contract: in v1 this is `false` for every receipt because
/// `activation_allowed` is pinned `false` — even a proven, unquarantined
/// candidate stays shadow. E9.T3/T4 build the activation gate on top of
/// this predicate.
pub fn activation_eligible(receipt: &E9EquivalenceReceipt) -> bool {
    receipt.activation_allowed && receipt.verdict == VERDICT_PROVEN && !receipt.quarantined
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from the equivalence lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum E9EquivalenceError {
    /// Object-id derivation failed.
    Id(String),
    /// Specialization-index operation failed.
    Index(SpecializationIndexError),
    /// Canonical serialization failed.
    Serialization(String),
    /// Lane-level invariant violation (fail-closed).
    Lane(String),
}

impl std::fmt::Display for E9EquivalenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Id(err) => write!(f, "id derivation failed: {err}"),
            Self::Index(err) => write!(f, "specialization index error: {err}"),
            Self::Serialization(err) => write!(f, "serialization failed: {err}"),
            Self::Lane(err) => write!(f, "equivalence lane invariant violated: {err}"),
        }
    }
}

impl std::error::Error for E9EquivalenceError {}

// ---------------------------------------------------------------------------
// Verdict derivation (fail-closed)
// ---------------------------------------------------------------------------

/// Length-prefixed (big-endian, matching the E9.T1 candidate-id discipline)
/// content hash over a field list.
fn length_prefixed_hash(fields: &[&str]) -> ContentHash {
    let mut seed = Vec::new();
    for field in fields {
        seed.extend_from_slice(&(field.len() as u64).to_be_bytes());
        seed.extend_from_slice(field.as_bytes());
    }
    ContentHash::compute(&seed)
}

fn differential_pair_hash(
    baseline: &DifferentialRunFacts,
    shadow: &DifferentialRunFacts,
) -> ContentHash {
    let baseline_ticks = baseline.instructions_executed.to_string();
    let shadow_ticks = shadow.instructions_executed.to_string();
    length_prefixed_hash(&[
        E9_EQUIVALENCE_RECEIPT_SCHEMA_VERSION,
        &baseline.execution_value_hash_hex,
        &baseline_ticks,
        &baseline.nondeterminism_trace_hash_hex,
        &shadow.execution_value_hash_hex,
        &shadow_ticks,
        &shadow.nondeterminism_trace_hash_hex,
    ])
}

/// Derive the fail-closed equivalence verdict for a differential run pair.
///
/// `Proven` requires complete facts on both sides, a baseline that matches
/// the discovery run, and byte-identical execution value, tick count, and
/// nondeterminism trace. Every other state is `Inconclusive` (insufficient
/// or mismatched evidence) or `Disproven` (affirmative divergence).
fn derive_verdict(
    discovery: &ShadowDiscoveryReport,
    baseline: &DifferentialRunFacts,
    shadow: &DifferentialRunFacts,
    budget_limit_ticks: u64,
) -> ReceiptVerdict {
    if !baseline.is_complete() || !shadow.is_complete() {
        return ReceiptVerdict::Inconclusive {
            reason: "differential facts incomplete: empty hash or zero tick count".to_string(),
            budget_consumed_ticks: 0,
            budget_limit_ticks,
        };
    }
    if baseline.trace_id != discovery.baseline.trace_id
        || baseline.instructions_executed != discovery.baseline.instructions_executed
    {
        return ReceiptVerdict::Inconclusive {
            reason: "baseline differential facts do not match the discovery run".to_string(),
            budget_consumed_ticks: 0,
            budget_limit_ticks,
        };
    }

    let mut divergences: Vec<&str> = Vec::new();
    if baseline.execution_value_hash_hex != shadow.execution_value_hash_hex {
        divergences.push("execution_value");
    }
    if baseline.instructions_executed != shadow.instructions_executed {
        divergences.push("instructions_executed");
    }
    if baseline.nondeterminism_trace_hash_hex != shadow.nondeterminism_trace_hash_hex {
        divergences.push("nondeterminism_trace");
    }

    if divergences.is_empty() {
        let evidence = ProofEvidence::new(
            ProofMode::DifferentialTrace,
            differential_pair_hash(baseline, shadow),
            3,
            baseline
                .instructions_executed
                .saturating_add(shadow.instructions_executed),
        )
        .with_metadata("baseline_trace_id", &baseline.trace_id)
        .with_metadata("shadow_trace_id", &shadow.trace_id)
        .with_metadata(
            "compared_dimensions",
            "execution_value,instructions_executed,nondeterminism_trace",
        );
        ReceiptVerdict::Proven { evidence }
    } else {
        ReceiptVerdict::Disproven {
            counterexample_hash: differential_pair_hash(baseline, shadow),
            divergence: divergences.join(","),
        }
    }
}

fn verdict_string(verdict: &ReceiptVerdict) -> (&'static str, String) {
    match verdict {
        ReceiptVerdict::Proven { .. } => (
            VERDICT_PROVEN,
            "differential_trace: execution value, tick count, and nondeterminism trace \
             byte-identical across baseline and shadow runs"
                .to_string(),
        ),
        ReceiptVerdict::Disproven { divergence, .. } => {
            (VERDICT_DISPROVEN, format!("divergence in: {divergence}"))
        }
        ReceiptVerdict::Inconclusive { reason, .. } => (VERDICT_INCONCLUSIVE, reason.clone()),
    }
}

fn content_hash_from_hex(hex_str: &str) -> Result<ContentHash, E9EquivalenceError> {
    let bytes = hex::decode(hex_str)
        .map_err(|err| E9EquivalenceError::Serialization(format!("invalid hash hex: {err}")))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        E9EquivalenceError::Serialization("hash hex must decode to 32 bytes".to_string())
    })?;
    Ok(ContentHash::from_bytes(arr))
}

fn optimization_class_from_str(value: &str) -> Result<OptimizationClass, E9EquivalenceError> {
    // NEVER maps to `IfcCheckElision`: the shadow lane refuses to carry the
    // one class whose wrong proof would be a containment bypass.
    match value {
        "hostcall_dispatch_specialization" => Ok(OptimizationClass::HostcallDispatchSpecialization),
        "path_elimination" => Ok(OptimizationClass::PathElimination),
        "superinstruction_fusion" => Ok(OptimizationClass::SuperinstructionFusion),
        other => Err(E9EquivalenceError::Serialization(format!(
            "unexpected optimization class for shadow candidate: {other}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Lane entry point: validate candidates
// ---------------------------------------------------------------------------

/// Run the equivalence lane over a discovery report.
///
/// Pure with respect to execution: consumes already-recorded run facts and
/// the discovery report; never executes or mutates a program. Every
/// candidate receives exactly one signed TV receipt and one lane receipt
/// with a fail-closed verdict; disproven candidates are quarantined by the
/// emitter and inconclusive candidates by the lane (config default).
pub fn validate_candidates(
    discovery: &ShadowDiscoveryReport,
    baseline_run: &DifferentialRunFacts,
    shadow_run: &DifferentialRunFacts,
    config: &EquivalenceLaneConfig,
) -> Result<E9EquivalenceReport, E9EquivalenceError> {
    let baseline_ir_hash = content_hash_from_hex(&discovery.ir3_content_hash_hex)?;
    let optimized_ir_hash = match &config.optimized_ir_hash_hex {
        Some(hex_str) => content_hash_from_hex(hex_str)?,
        None => baseline_ir_hash,
    };
    let optimized_ir_hash_hex = optimized_ir_hash.to_hex();
    let lane_policy_hash_hex = config.policy_hash_hex();

    let chain_id = format!(
        "e9-equivalence-{}",
        discovery
            .ir3_content_hash_hex
            .get(..16)
            .unwrap_or(&discovery.ir3_content_hash_hex)
    );
    let emitter_config = EmitterConfig {
        chain_id,
        signing_key: config.signing_key.clone(),
        quarantine_on_first_failure: true,
        proof_budget_ticks: config.proof_budget_ticks,
        default_cost_model_id: config.cost_model_id.clone(),
        ..EmitterConfig::default()
    };
    let mut emitter = ValidationReceiptEmitter::new(
        emitter_config,
        SecurityEpoch::from_raw(discovery.baseline.policy_epoch),
    );
    // Deterministic logical clock: the baseline run's tick count.
    emitter.tick(discovery.baseline.instructions_executed);

    let verdict = derive_verdict(
        discovery,
        baseline_run,
        shadow_run,
        config.proof_budget_ticks,
    );
    let (verdict_str, verdict_detail) = verdict_string(&verdict);

    let proof_schema = SchemaId::from_definition(RECEIPT_SCHEMA_VERSION.as_bytes());
    let mut receipts = Vec::with_capacity(discovery.candidates.len());
    let mut quarantined: BTreeSet<String> = BTreeSet::new();
    let (mut proven_count, mut disproven_count, mut inconclusive_count) = (0u64, 0u64, 0u64);

    for candidate in &discovery.candidates {
        let emit_input = EmitInput {
            optimization_id: candidate.candidate_id.clone(),
            baseline_ir_hash,
            optimized_ir_hash,
            applied_rules: Vec::new(),
            verdict: verdict.clone(),
            cost_model_id: None,
        };
        let tv_receipt = match emitter.emit(emit_input) {
            EmitResult::Approved { receipt } | EmitResult::Rejected { receipt, .. } => receipt,
            EmitResult::Quarantined {
                optimization_id,
                reason,
            } => {
                return Err(E9EquivalenceError::Lane(format!(
                    "candidate {optimization_id} rejected before verdict emission: {reason}"
                )));
            }
        };

        match verdict_str {
            VERDICT_PROVEN => proven_count += 1,
            VERDICT_DISPROVEN => disproven_count += 1,
            _ => {
                inconclusive_count += 1;
                if config.quarantine_inconclusive {
                    emitter.quarantine_optimization(&candidate.candidate_id);
                }
            }
        }
        let is_quarantined = emitter.is_quarantined(&candidate.candidate_id);
        if is_quarantined {
            quarantined.insert(candidate.candidate_id.clone());
        }

        let proof_id = derive_id(
            ObjectDomain::PolicyObject,
            E9_EQUIVALENCE_PROOF_ZONE,
            &proof_schema,
            tv_receipt.content_hash.as_bytes(),
        )
        .map_err(|err| E9EquivalenceError::Id(err.to_string()))?;

        receipts.push(E9EquivalenceReceipt {
            schema_version: E9_EQUIVALENCE_RECEIPT_SCHEMA_VERSION.to_string(),
            mode: E9_SHADOW_MODE.to_string(),
            activation_allowed: E9_ACTIVATION_ALLOWED,
            candidate_id: candidate.candidate_id.clone(),
            optimization_class: candidate.proposed_optimization_class.clone(),
            extension_id: discovery.baseline.extension_id.clone(),
            trace_id: discovery.baseline.trace_id.clone(),
            policy_epoch: discovery.baseline.policy_epoch,
            timestamp_ns: discovery.baseline.instructions_executed,
            baseline_ir_hash_hex: discovery.ir3_content_hash_hex.clone(),
            optimized_ir_hash_hex: optimized_ir_hash_hex.clone(),
            tv_receipt_content_hash_hex: tv_receipt.content_hash.to_hex(),
            tv_receipt_sequence: tv_receipt.sequence,
            proof_id_hex: proof_id.to_hex(),
            proof_type: E9_EQUIVALENCE_PROOF_TYPE.to_string(),
            verdict: verdict_str.to_string(),
            verdict_detail: verdict_detail.clone(),
            quarantined: is_quarantined,
            lane_policy_id: config.policy_id.clone(),
            lane_policy_hash_hex: lane_policy_hash_hex.clone(),
        });
    }

    let chain_summary = emitter.summary();
    Ok(E9EquivalenceReport {
        schema_version: E9_EQUIVALENCE_REPORT_SCHEMA_VERSION.to_string(),
        mode: E9_SHADOW_MODE.to_string(),
        activation_allowed: E9_ACTIVATION_ALLOWED,
        ir3_content_hash_hex: discovery.ir3_content_hash_hex.clone(),
        extension_id: discovery.baseline.extension_id.clone(),
        trace_id: discovery.baseline.trace_id.clone(),
        policy_epoch: discovery.baseline.policy_epoch,
        timestamp_ns: discovery.baseline.instructions_executed,
        lane_policy_id: config.policy_id.clone(),
        lane_policy_hash_hex,
        receipts,
        proven_count,
        disproven_count,
        inconclusive_count,
        quarantined_candidate_ids: quarantined.into_iter().collect(),
        chain: emitter.chain.clone(),
        chain_summary,
    })
}

// ---------------------------------------------------------------------------
// Persistence: proof -> spec -> benchmark chain
// ---------------------------------------------------------------------------

/// Outcome of persisting one candidate's chain into the index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainPersistenceOutcome {
    /// Candidate the chain belongs to.
    pub candidate_id: String,
    /// Engine object id (hex) of the persisted chain receipt.
    pub chain_receipt_id_hex: String,
    /// `inserted` or `duplicate_skipped`.
    pub record_outcome: String,
    /// Deterministic benchmark id, present only for proven candidates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub benchmark_id: Option<String>,
    /// `inserted` or `duplicate_skipped`, present only for proven candidates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub benchmark_outcome: Option<String>,
    /// Whether the candidate was quarantined at validation time.
    pub quarantined: bool,
}

fn chain_receipt_object_id(
    receipt: &E9EquivalenceReceipt,
) -> Result<EngineObjectId, E9EquivalenceError> {
    let canonical = serde_json::to_vec(receipt)
        .map_err(|err| E9EquivalenceError::Serialization(err.to_string()))?;
    derive_id(
        ObjectDomain::PolicyObject,
        E9_CHAIN_RECEIPT_ZONE,
        &SchemaId::from_definition(E9_EQUIVALENCE_RECEIPT_SCHEMA_VERSION.as_bytes()),
        &canonical,
    )
    .map_err(|err| E9EquivalenceError::Id(err.to_string()))
}

fn benchmark_id_for(receipt: &E9EquivalenceReceipt) -> String {
    let digest = length_prefixed_hash(&[
        E9_EQUIVALENCE_RECEIPT_SCHEMA_VERSION,
        &receipt.candidate_id,
        &receipt.trace_id,
        &receipt.tv_receipt_content_hash_hex,
    ])
    .to_hex();
    format!("e9-diff-{}", digest.get(..16).unwrap_or(&digest))
}

/// Persist the proof -> specialization receipt -> benchmark chain for every
/// candidate in an equivalence report.
///
/// Every candidate gets a proof-carrying `SpecializationRecord` (always
/// `active: false` in shadow mode; the proof reference points at the TV
/// receipt evidence, whatever its verdict, so disproven chains stay
/// auditable). Only proven, unquarantined candidates additionally get a
/// zero-delta `BenchmarkOutcome` completing the chain: the shadow lane
/// validates the identity specialization, so the honest measured delta is
/// exactly zero (`sample_count = 2` for the two compared runs).
/// Re-persisting the same report is idempotent (`duplicate_skipped`).
pub fn persist_equivalence_chain<S: StorageAdapter>(
    index: &mut SpecializationIndex<S>,
    report: &E9EquivalenceReport,
) -> Result<Vec<ChainPersistenceOutcome>, E9EquivalenceError> {
    let mut outcomes = Vec::with_capacity(report.receipts.len());
    for receipt in &report.receipts {
        let chain_receipt_id = chain_receipt_object_id(receipt)?;
        let proof_id = EngineObjectId::from_hex(&receipt.proof_id_hex)
            .map_err(|err| E9EquivalenceError::Id(err.to_string()))?;
        let record = SpecializationRecord {
            receipt_id: chain_receipt_id.clone(),
            proof_input_ids: vec![proof_id],
            proof_types: vec![ProofType::ReplayMotif],
            optimization_class: optimization_class_from_str(&receipt.optimization_class)?,
            extension_id: receipt.extension_id.clone(),
            epoch: SecurityEpoch::from_raw(receipt.policy_epoch),
            timestamp_ns: receipt.timestamp_ns,
            // Shadow-first: chain records are NEVER active in v1.
            active: false,
        };
        let record_outcome = match index.insert_receipt(&record, &receipt.trace_id) {
            Ok(()) => "inserted",
            Err(SpecializationIndexError::DuplicateReceipt { .. }) => "duplicate_skipped",
            Err(err) => return Err(E9EquivalenceError::Index(err)),
        };

        let (benchmark_id, benchmark_outcome) =
            if receipt.verdict == VERDICT_PROVEN && !receipt.quarantined {
                let benchmark_id = benchmark_id_for(receipt);
                let outcome = BenchmarkOutcome {
                    benchmark_id: benchmark_id.clone(),
                    receipt_id: chain_receipt_id.clone(),
                    // Identity specialization: honest zero delta.
                    latency_reduction_millionths: 0,
                    throughput_increase_millionths: 0,
                    sample_count: 2,
                    timestamp_ns: receipt.timestamp_ns,
                };
                let benchmark_outcome = match index.insert_benchmark(&outcome, &receipt.trace_id) {
                    Ok(()) => "inserted",
                    Err(SpecializationIndexError::DuplicateBenchmark { .. }) => "duplicate_skipped",
                    Err(err) => return Err(E9EquivalenceError::Index(err)),
                };
                (Some(benchmark_id), Some(benchmark_outcome.to_string()))
            } else {
                (None, None)
            };

        outcomes.push(ChainPersistenceOutcome {
            candidate_id: receipt.candidate_id.clone(),
            chain_receipt_id_hex: chain_receipt_id.to_hex(),
            record_outcome: record_outcome.to_string(),
            benchmark_id,
            benchmark_outcome,
            quarantined: receipt.quarantined,
        });
    }
    Ok(outcomes)
}

// ---------------------------------------------------------------------------
// Invalidation wiring (epoch change, proof expiry/revocation, manual)
// ---------------------------------------------------------------------------

/// Outcome of one chain-record invalidation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainInvalidationOutcome {
    /// Receipt id (hex) the invalidation applies to.
    pub receipt_id_hex: String,
    /// `invalidated` or `already_invalidated`.
    pub outcome: String,
    /// Reason recorded in the invalidation log.
    pub reason: InvalidationReason,
}

/// Invalidate a single chain record with an explicit reason (proof expiry,
/// proof revocation, or manual revocation).
///
/// `fallback_confirmed` is always `true`: in shadow mode the baseline lane
/// is the only executing path, so the fallback is trivially in effect.
pub fn invalidate_chain_record<S: StorageAdapter>(
    index: &mut SpecializationIndex<S>,
    receipt_id: &EngineObjectId,
    reason: InvalidationReason,
    timestamp_ns: u64,
    trace_id: &str,
) -> Result<(), E9EquivalenceError> {
    let entry = InvalidationEntry {
        receipt_id: receipt_id.clone(),
        reason,
        timestamp_ns,
        fallback_confirmed: true,
    };
    index
        .record_invalidation(&entry, trace_id)
        .map_err(E9EquivalenceError::Index)
}

/// Sweep the index on a security-epoch transition: every record whose epoch
/// differs from `new_epoch` and is not already invalidated gets an
/// `EpochChange` invalidation entry.
pub fn invalidate_chain_on_epoch_change<S: StorageAdapter>(
    index: &mut SpecializationIndex<S>,
    new_epoch: SecurityEpoch,
    timestamp_ns: u64,
    trace_id: &str,
) -> Result<Vec<ChainInvalidationOutcome>, E9EquivalenceError> {
    let already_invalidated: BTreeSet<String> = index
        .query_invalidations(None, None, trace_id)
        .map_err(E9EquivalenceError::Index)?
        .into_iter()
        .map(|entry| entry.receipt_id.to_hex())
        .collect();
    let records = index
        .query_receipts(None, trace_id)
        .map_err(E9EquivalenceError::Index)?;

    let mut outcomes = Vec::new();
    for record in records {
        if record.epoch == new_epoch {
            continue;
        }
        let receipt_id_hex = record.receipt_id.to_hex();
        let reason = InvalidationReason::EpochChange {
            old_epoch: record.epoch.as_u64(),
            new_epoch: new_epoch.as_u64(),
        };
        if already_invalidated.contains(&receipt_id_hex) {
            outcomes.push(ChainInvalidationOutcome {
                receipt_id_hex,
                outcome: "already_invalidated".to_string(),
                reason,
            });
            continue;
        }
        invalidate_chain_record(
            index,
            &record.receipt_id,
            reason.clone(),
            timestamp_ns,
            trace_id,
        )?;
        outcomes.push(ChainInvalidationOutcome {
            receipt_id_hex,
            outcome: "invalidated".to_string(),
            reason,
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
    use crate::e9_shadow_candidate_discovery::{
        BaselineRunFacts, CandidateRegion, RegionKind, ShadowCandidateReceipt,
    };
    use crate::storage_adapter::InMemoryStorageAdapter;
    use std::collections::BTreeMap;

    const IR3_HASH_HEX: &str = "0101010101010101010101010101010101010101010101010101010101010101";
    const TRACE_ID: &str = "trace-e9-t2";
    const EXTENSION_ID: &str = "ext-e9-t2";
    const TICKS: u64 = 420;

    fn candidate(id_suffix: &str, class: &str, start: u32, end: u32) -> ShadowCandidateReceipt {
        ShadowCandidateReceipt {
            schema_version: "franken-engine.e9-shadow-candidate.v1".to_string(),
            mode: E9_SHADOW_MODE.to_string(),
            activation_allowed: false,
            candidate_id: format!("candidate-{id_suffix}"),
            region: CandidateRegion {
                kind: RegionKind::LoopBody,
                start_index: start,
                end_index: end,
                function_index: None,
                function_name: None,
                loop_depth: 0,
            },
            op_family_histogram: BTreeMap::new(),
            dominant_family: "arithmetic".to_string(),
            dominance_millionths: 1_000_000,
            region_static_cost: 10,
            program_static_cost: 20,
            static_cost_share_millionths: 500_000,
            proposed_optimization_class: class.to_string(),
            ir3_content_hash_hex: IR3_HASH_HEX.to_string(),
            baseline: baseline_facts(),
            policy_id: "policy-e9-shadow-discovery-v1".to_string(),
            policy_hash_hex: "feed".to_string(),
        }
    }

    fn baseline_facts() -> BaselineRunFacts {
        BaselineRunFacts {
            trace_id: TRACE_ID.to_string(),
            decision_id: "decision-e9-t2".to_string(),
            extension_id: EXTENSION_ID.to_string(),
            policy_epoch: 7,
            instructions_executed: TICKS,
        }
    }

    fn discovery_report(candidates: Vec<ShadowCandidateReceipt>) -> ShadowDiscoveryReport {
        ShadowDiscoveryReport {
            schema_version: "franken-engine.e9-shadow-discovery-report.v1".to_string(),
            mode: E9_SHADOW_MODE.to_string(),
            ir3_content_hash_hex: IR3_HASH_HEX.to_string(),
            program_instruction_count: 32,
            program_static_cost: 40,
            policy_id: "policy-e9-shadow-discovery-v1".to_string(),
            policy_hash_hex: "feed".to_string(),
            baseline: baseline_facts(),
            candidates,
            skipped_non_specializable: 0,
            filtered_below_thresholds: 0,
            truncated_by_cap: 0,
        }
    }

    fn default_report() -> ShadowDiscoveryReport {
        discovery_report(vec![
            candidate("a", "superinstruction_fusion", 2, 8),
            candidate("b", "hostcall_dispatch_specialization", 10, 16),
        ])
    }

    fn run_facts(value: &str, ticks: u64, trace: &str) -> DifferentialRunFacts {
        DifferentialRunFacts {
            schema_version: E9_DIFFERENTIAL_FACTS_SCHEMA_VERSION.to_string(),
            trace_id: TRACE_ID.to_string(),
            execution_value_hash_hex: value.to_string(),
            instructions_executed: ticks,
            nondeterminism_trace_hash_hex: trace.to_string(),
        }
    }

    fn matching_pair() -> (DifferentialRunFacts, DifferentialRunFacts) {
        let baseline = run_facts("aa", TICKS, "bb");
        let mut shadow = baseline.clone();
        shadow.trace_id = "trace-e9-t2-shadow".to_string();
        (baseline, shadow)
    }

    fn validate_default() -> E9EquivalenceReport {
        let (baseline, shadow) = matching_pair();
        validate_candidates(
            &default_report(),
            &baseline,
            &shadow,
            &EquivalenceLaneConfig::default(),
        )
        .expect("lane validates")
    }

    fn index() -> SpecializationIndex<InMemoryStorageAdapter> {
        SpecializationIndex::new(InMemoryStorageAdapter::new(), "policy-e9-t2")
    }

    // -- config + schema pins ------------------------------------------------

    #[test]
    fn default_config_is_fail_closed() {
        let config = EquivalenceLaneConfig::default();
        assert!(config.quarantine_inconclusive, "fail-closed default");
        assert!(config.optimized_ir_hash_hex.is_none(), "identity shadow v1");
        assert_eq!(
            config.schema_version,
            E9_EQUIVALENCE_LANE_CONFIG_SCHEMA_VERSION
        );
        assert_eq!(config.signing_key.len(), 32);
    }

    #[test]
    fn config_policy_hash_is_deterministic() {
        let a = EquivalenceLaneConfig::default().policy_hash_hex();
        let b = EquivalenceLaneConfig::default().policy_hash_hex();
        assert_eq!(a, b);
        let altered = EquivalenceLaneConfig {
            policy_id: "other".to_string(),
            ..EquivalenceLaneConfig::default()
        };
        assert_ne!(a, altered.policy_hash_hex());
    }

    // -- verdict derivation --------------------------------------------------

    #[test]
    fn identical_runs_prove_equivalence() {
        let report = validate_default();
        assert_eq!(report.proven_count, 2);
        assert_eq!(report.disproven_count, 0);
        assert_eq!(report.inconclusive_count, 0);
        for receipt in &report.receipts {
            assert_eq!(receipt.verdict, VERDICT_PROVEN);
            assert!(!receipt.quarantined);
        }
        assert!(report.quarantined_candidate_ids.is_empty());
    }

    #[test]
    fn value_divergence_disproves() {
        let (baseline, mut shadow) = matching_pair();
        shadow.execution_value_hash_hex = "cc".to_string();
        let report = validate_candidates(
            &default_report(),
            &baseline,
            &shadow,
            &EquivalenceLaneConfig::default(),
        )
        .expect("lane validates");
        assert_eq!(report.disproven_count, 2);
        for receipt in &report.receipts {
            assert_eq!(receipt.verdict, VERDICT_DISPROVEN);
            assert!(receipt.verdict_detail.contains("execution_value"));
        }
    }

    #[test]
    fn tick_divergence_disproves() {
        let (baseline, mut shadow) = matching_pair();
        shadow.instructions_executed = TICKS + 1;
        let report = validate_candidates(
            &default_report(),
            &baseline,
            &shadow,
            &EquivalenceLaneConfig::default(),
        )
        .expect("lane validates");
        assert_eq!(report.disproven_count, 2);
        assert!(
            report.receipts[0]
                .verdict_detail
                .contains("instructions_executed")
        );
    }

    #[test]
    fn trace_divergence_disproves() {
        let (baseline, mut shadow) = matching_pair();
        shadow.nondeterminism_trace_hash_hex = "dd".to_string();
        let report = validate_candidates(
            &default_report(),
            &baseline,
            &shadow,
            &EquivalenceLaneConfig::default(),
        )
        .expect("lane validates");
        assert_eq!(report.disproven_count, 2);
        assert!(
            report.receipts[0]
                .verdict_detail
                .contains("nondeterminism_trace")
        );
    }

    #[test]
    fn incomplete_facts_are_inconclusive() {
        let (baseline, mut shadow) = matching_pair();
        shadow.execution_value_hash_hex = String::new();
        let report = validate_candidates(
            &default_report(),
            &baseline,
            &shadow,
            &EquivalenceLaneConfig::default(),
        )
        .expect("lane validates");
        assert_eq!(report.inconclusive_count, 2);
        for receipt in &report.receipts {
            assert_eq!(receipt.verdict, VERDICT_INCONCLUSIVE);
            assert!(receipt.verdict_detail.contains("incomplete"));
        }
    }

    #[test]
    fn zero_tick_run_is_inconclusive() {
        let (mut baseline, shadow) = matching_pair();
        baseline.instructions_executed = 0;
        let report = validate_candidates(
            &default_report(),
            &baseline,
            &shadow,
            &EquivalenceLaneConfig::default(),
        )
        .expect("lane validates");
        assert_eq!(report.inconclusive_count, 2);
    }

    #[test]
    fn baseline_mismatched_with_discovery_run_is_inconclusive() {
        let (mut baseline, shadow) = matching_pair();
        baseline.trace_id = "trace-other-run".to_string();
        let report = validate_candidates(
            &default_report(),
            &baseline,
            &shadow,
            &EquivalenceLaneConfig::default(),
        )
        .expect("lane validates");
        assert_eq!(report.inconclusive_count, 2);
        assert!(
            report.receipts[0]
                .verdict_detail
                .contains("do not match the discovery run")
        );
    }

    #[test]
    fn nothing_defaults_to_proven_without_candidates_evidence() {
        // Both sides incomplete: still inconclusive, never proven.
        let baseline = run_facts("", 0, "");
        let shadow = run_facts("", 0, "");
        let report = validate_candidates(
            &default_report(),
            &baseline,
            &shadow,
            &EquivalenceLaneConfig::default(),
        )
        .expect("lane validates");
        assert_eq!(report.proven_count, 0);
        assert_eq!(report.inconclusive_count, 2);
    }

    // -- quarantine (fail-closed) ---------------------------------------------

    #[test]
    fn disproven_candidates_are_quarantined() {
        let (baseline, mut shadow) = matching_pair();
        shadow.execution_value_hash_hex = "cc".to_string();
        let report = validate_candidates(
            &default_report(),
            &baseline,
            &shadow,
            &EquivalenceLaneConfig::default(),
        )
        .expect("lane validates");
        assert_eq!(report.quarantined_candidate_ids.len(), 2);
        assert!(report.receipts.iter().all(|r| r.quarantined));
    }

    #[test]
    fn inconclusive_candidates_are_quarantined_by_default() {
        let (baseline, mut shadow) = matching_pair();
        shadow.execution_value_hash_hex = String::new();
        let report = validate_candidates(
            &default_report(),
            &baseline,
            &shadow,
            &EquivalenceLaneConfig::default(),
        )
        .expect("lane validates");
        assert_eq!(report.quarantined_candidate_ids.len(), 2);
        assert!(report.receipts.iter().all(|r| r.quarantined));
    }

    #[test]
    fn inconclusive_quarantine_can_be_disabled_but_never_activates() {
        let (baseline, mut shadow) = matching_pair();
        shadow.execution_value_hash_hex = String::new();
        let config = EquivalenceLaneConfig {
            quarantine_inconclusive: false,
            ..EquivalenceLaneConfig::default()
        };
        let report = validate_candidates(&default_report(), &baseline, &shadow, &config)
            .expect("lane validates");
        assert!(report.quarantined_candidate_ids.is_empty());
        for receipt in &report.receipts {
            assert!(!receipt.quarantined);
            assert!(
                !activation_eligible(receipt),
                "inconclusive receipts are never activation-eligible"
            );
        }
    }

    #[test]
    fn quarantined_ids_are_sorted_and_deterministic() {
        let (baseline, mut shadow) = matching_pair();
        shadow.execution_value_hash_hex = "cc".to_string();
        let report = validate_candidates(
            &default_report(),
            &baseline,
            &shadow,
            &EquivalenceLaneConfig::default(),
        )
        .expect("lane validates");
        let mut sorted = report.quarantined_candidate_ids.clone();
        sorted.sort();
        assert_eq!(report.quarantined_candidate_ids, sorted);
    }

    // -- shadow-first activation invariants ------------------------------------

    #[test]
    fn activation_is_pinned_off_even_for_proven_receipts() {
        let report = validate_default();
        assert!(!report.activation_allowed);
        for receipt in &report.receipts {
            assert_eq!(receipt.verdict, VERDICT_PROVEN);
            assert!(!receipt.activation_allowed);
            assert!(
                !activation_eligible(receipt),
                "shadow v1 never activates, even proven candidates"
            );
        }
    }

    #[test]
    fn report_and_receipts_carry_shadow_mode() {
        let report = validate_default();
        assert_eq!(report.mode, E9_SHADOW_MODE);
        assert!(report.receipts.iter().all(|r| r.mode == E9_SHADOW_MODE));
    }

    #[test]
    fn identity_lane_uses_baseline_hash_for_optimized_artifact() {
        let report = validate_default();
        for receipt in &report.receipts {
            assert_eq!(receipt.baseline_ir_hash_hex, IR3_HASH_HEX);
            assert_eq!(receipt.optimized_ir_hash_hex, IR3_HASH_HEX);
        }
    }

    #[test]
    fn explicit_optimized_hash_overrides_identity() {
        let optimized_hex = "0202020202020202020202020202020202020202020202020202020202020202";
        let config = EquivalenceLaneConfig {
            optimized_ir_hash_hex: Some(optimized_hex.to_string()),
            ..EquivalenceLaneConfig::default()
        };
        let (baseline, shadow) = matching_pair();
        let report = validate_candidates(&default_report(), &baseline, &shadow, &config)
            .expect("lane validates");
        assert_eq!(report.receipts[0].optimized_ir_hash_hex, optimized_hex);
    }

    #[test]
    fn malformed_ir_hash_fails_closed() {
        let mut discovery = default_report();
        discovery.ir3_content_hash_hex = "not-hex".to_string();
        let (baseline, shadow) = matching_pair();
        let err = validate_candidates(
            &discovery,
            &baseline,
            &shadow,
            &EquivalenceLaneConfig::default(),
        )
        .expect_err("malformed hash must fail closed");
        assert!(matches!(err, E9EquivalenceError::Serialization(_)));
    }

    // -- TV chain integration ---------------------------------------------------

    #[test]
    fn one_signed_tv_receipt_per_candidate_and_chain_is_valid() {
        let report = validate_default();
        assert_eq!(report.chain.receipts.len(), 2);
        let integrity = report.chain.verify_integrity();
        assert!(integrity.valid, "chain integrity: {:?}", integrity.issues);
        let sequences: Vec<u64> = report
            .receipts
            .iter()
            .map(|r| r.tv_receipt_sequence)
            .collect();
        assert_eq!(sequences, vec![1, 2]);
    }

    #[test]
    fn disproven_verdicts_record_failure_receipts_in_chain() {
        let (baseline, mut shadow) = matching_pair();
        shadow.execution_value_hash_hex = "cc".to_string();
        let report = validate_candidates(
            &default_report(),
            &baseline,
            &shadow,
            &EquivalenceLaneConfig::default(),
        )
        .expect("lane validates");
        assert_eq!(report.chain.failures.len(), 2);
        assert!(report.chain.failures.iter().all(|f| f.quarantined));
        assert_eq!(report.chain_summary.total_disproven, 2);
    }

    #[test]
    fn verdict_strings_are_pinned_snake_case() {
        assert_eq!(VERDICT_PROVEN, "proven");
        assert_eq!(VERDICT_DISPROVEN, "disproven");
        assert_eq!(VERDICT_INCONCLUSIVE, "inconclusive");
    }

    #[test]
    fn lane_is_deterministic_for_identical_inputs() {
        let a = validate_default();
        let b = validate_default();
        assert_eq!(a, b);
        let a_bytes = serde_json::to_vec(&a).expect("report serializes");
        let b_bytes = serde_json::to_vec(&b).expect("report serializes");
        assert_eq!(a_bytes, b_bytes, "byte-identical lane output");
    }

    #[test]
    fn empty_candidate_list_yields_empty_report() {
        let discovery = discovery_report(Vec::new());
        let (baseline, shadow) = matching_pair();
        let report = validate_candidates(
            &discovery,
            &baseline,
            &shadow,
            &EquivalenceLaneConfig::default(),
        )
        .expect("lane validates");
        assert!(report.receipts.is_empty());
        assert_eq!(report.proven_count, 0);
        assert!(report.chain.receipts.is_empty());
        assert!(report.chain.verify_integrity().valid);
    }

    #[test]
    fn counts_match_receipt_verdicts() {
        let report = validate_default();
        let proven = report
            .receipts
            .iter()
            .filter(|r| r.verdict == VERDICT_PROVEN)
            .count() as u64;
        assert_eq!(report.proven_count, proven);
        assert_eq!(
            report.proven_count + report.disproven_count + report.inconclusive_count,
            report.receipts.len() as u64
        );
    }

    // -- persistence: proof -> spec -> benchmark ---------------------------------

    #[test]
    fn proven_candidates_persist_full_chain_with_benchmark() {
        let report = validate_default();
        let mut index = index();
        let outcomes = persist_equivalence_chain(&mut index, &report).expect("persists");
        assert_eq!(outcomes.len(), 2);
        for outcome in &outcomes {
            assert_eq!(outcome.record_outcome, "inserted");
            assert_eq!(outcome.benchmark_outcome.as_deref(), Some("inserted"));
            let receipt_id =
                EngineObjectId::from_hex(&outcome.chain_receipt_id_hex).expect("id parses");
            let stored = index
                .get_receipt(&receipt_id, TRACE_ID)
                .expect("lookup succeeds")
                .expect("record present");
            assert!(!stored.active, "shadow chain records are never active");
            assert_eq!(stored.proof_input_ids.len(), 1);
            assert_eq!(stored.proof_types, vec![ProofType::ReplayMotif]);
            let benchmarks = index
                .find_benchmarks_by_receipt(&receipt_id, TRACE_ID)
                .expect("benchmark lookup succeeds");
            assert_eq!(benchmarks.len(), 1);
            assert_eq!(benchmarks[0].latency_reduction_millionths, 0);
            assert_eq!(benchmarks[0].throughput_increase_millionths, 0);
            assert_eq!(benchmarks[0].sample_count, 2);
        }
    }

    #[test]
    fn audit_chain_joins_proof_spec_and_benchmark() {
        let report = validate_default();
        let mut index = index();
        persist_equivalence_chain(&mut index, &report).expect("persists");
        let chain = index.build_audit_chain(TRACE_ID).expect("audit chain");
        assert_eq!(chain.len(), 2);
        for entry in &chain {
            assert_eq!(entry.proof_type, ProofType::ReplayMotif);
            assert!(entry.benchmark_id.is_some(), "proven chain has benchmark");
            assert_eq!(entry.latency_reduction_millionths, Some(0));
            assert_eq!(entry.epoch, SecurityEpoch::from_raw(7));
        }
    }

    #[test]
    fn quarantined_candidates_persist_chain_without_benchmark() {
        let (baseline, mut shadow) = matching_pair();
        shadow.execution_value_hash_hex = "cc".to_string();
        let report = validate_candidates(
            &default_report(),
            &baseline,
            &shadow,
            &EquivalenceLaneConfig::default(),
        )
        .expect("lane validates");
        let mut index = index();
        let outcomes = persist_equivalence_chain(&mut index, &report).expect("persists");
        for outcome in &outcomes {
            assert_eq!(outcome.record_outcome, "inserted");
            assert!(outcome.benchmark_id.is_none());
            assert!(outcome.benchmark_outcome.is_none());
            assert!(outcome.quarantined);
            let receipt_id =
                EngineObjectId::from_hex(&outcome.chain_receipt_id_hex).expect("id parses");
            let benchmarks = index
                .find_benchmarks_by_receipt(&receipt_id, TRACE_ID)
                .expect("benchmark lookup succeeds");
            assert!(benchmarks.is_empty(), "no benchmark for quarantined chain");
        }
    }

    #[test]
    fn re_persisting_is_idempotent() {
        let report = validate_default();
        let mut index = index();
        let first = persist_equivalence_chain(&mut index, &report).expect("persists");
        assert!(first.iter().all(|o| o.record_outcome == "inserted"));
        let second = persist_equivalence_chain(&mut index, &report).expect("re-persists");
        assert!(
            second
                .iter()
                .all(|o| o.record_outcome == "duplicate_skipped")
        );
        assert!(
            second
                .iter()
                .all(|o| o.benchmark_outcome.as_deref() == Some("duplicate_skipped"))
        );
    }

    #[test]
    fn chain_receipt_ids_are_distinct_per_candidate_and_stable() {
        let report = validate_default();
        let mut first_index = index();
        let outcomes = persist_equivalence_chain(&mut first_index, &report).expect("persists");
        assert_ne!(
            outcomes[0].chain_receipt_id_hex,
            outcomes[1].chain_receipt_id_hex
        );
        let mut second_index = index();
        let outcomes2 = persist_equivalence_chain(&mut second_index, &report).expect("persists");
        assert_eq!(
            outcomes[0].chain_receipt_id_hex, outcomes2[0].chain_receipt_id_hex,
            "chain receipt ids are content-derived, not allocation-dependent"
        );
    }

    // -- invalidation reasons -----------------------------------------------------

    #[test]
    fn epoch_change_sweep_invalidates_stale_records() {
        let report = validate_default();
        let mut index = index();
        persist_equivalence_chain(&mut index, &report).expect("persists");
        let outcomes =
            invalidate_chain_on_epoch_change(&mut index, SecurityEpoch::from_raw(8), 500, TRACE_ID)
                .expect("sweep succeeds");
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(|o| o.outcome == "invalidated"));
        for outcome in &outcomes {
            assert_eq!(
                outcome.reason,
                InvalidationReason::EpochChange {
                    old_epoch: 7,
                    new_epoch: 8
                }
            );
        }
        let entries = index
            .query_invalidations(None, None, TRACE_ID)
            .expect("invalidation log readable");
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|e| e.fallback_confirmed));
    }

    #[test]
    fn epoch_change_sweep_is_idempotent() {
        let report = validate_default();
        let mut index = index();
        persist_equivalence_chain(&mut index, &report).expect("persists");
        invalidate_chain_on_epoch_change(&mut index, SecurityEpoch::from_raw(8), 500, TRACE_ID)
            .expect("first sweep");
        let second =
            invalidate_chain_on_epoch_change(&mut index, SecurityEpoch::from_raw(8), 501, TRACE_ID)
                .expect("second sweep");
        assert!(second.iter().all(|o| o.outcome == "already_invalidated"));
        let entries = index
            .query_invalidations(None, None, TRACE_ID)
            .expect("invalidation log readable");
        assert_eq!(entries.len(), 2, "no duplicate invalidation entries");
    }

    #[test]
    fn epoch_change_sweep_skips_current_epoch_records() {
        let report = validate_default();
        let mut index = index();
        persist_equivalence_chain(&mut index, &report).expect("persists");
        let outcomes =
            invalidate_chain_on_epoch_change(&mut index, SecurityEpoch::from_raw(7), 500, TRACE_ID)
                .expect("sweep succeeds");
        assert!(outcomes.is_empty(), "same-epoch records are untouched");
    }

    #[test]
    fn manual_and_proof_invalidation_reasons_round_trip() {
        let report = validate_default();
        let mut index = index();
        let outcomes = persist_equivalence_chain(&mut index, &report).expect("persists");
        let first_id =
            EngineObjectId::from_hex(&outcomes[0].chain_receipt_id_hex).expect("id parses");
        let second_id =
            EngineObjectId::from_hex(&outcomes[1].chain_receipt_id_hex).expect("id parses");
        let proof_id = EngineObjectId::from_hex(&report.receipts[0].proof_id_hex).expect("proof");

        invalidate_chain_record(
            &mut index,
            &first_id,
            InvalidationReason::ManualRevocation {
                operator: "operator-e9".to_string(),
            },
            600,
            TRACE_ID,
        )
        .expect("manual revocation records");
        invalidate_chain_record(
            &mut index,
            &second_id,
            InvalidationReason::ProofRevoked {
                proof_id: proof_id.clone(),
            },
            601,
            TRACE_ID,
        )
        .expect("proof revocation records");
        invalidate_chain_record(
            &mut index,
            &first_id,
            InvalidationReason::ProofExpired { proof_id },
            602,
            TRACE_ID,
        )
        .expect("proof expiry records");

        let entries = index
            .query_invalidations(None, None, TRACE_ID)
            .expect("invalidation log readable");
        assert_eq!(entries.len(), 3);
        assert!(entries.iter().any(|e| matches!(
            &e.reason,
            InvalidationReason::ManualRevocation { operator } if operator == "operator-e9"
        )));
        assert!(
            entries
                .iter()
                .any(|e| matches!(&e.reason, InvalidationReason::ProofRevoked { .. }))
        );
        assert!(
            entries
                .iter()
                .any(|e| matches!(&e.reason, InvalidationReason::ProofExpired { .. }))
        );
    }

    // -- misc ---------------------------------------------------------------------

    #[test]
    fn proof_type_string_is_replay_motif() {
        let report = validate_default();
        assert!(
            report
                .receipts
                .iter()
                .all(|r| r.proof_type == E9_EQUIVALENCE_PROOF_TYPE)
        );
        assert_eq!(E9_EQUIVALENCE_PROOF_TYPE, "replay_motif");
    }

    #[test]
    fn unexpected_optimization_class_fails_closed() {
        let err = optimization_class_from_str("ifc_check_elision")
            .expect_err("ifc_check_elision must be refused");
        assert!(matches!(err, E9EquivalenceError::Serialization(_)));
        assert!(optimization_class_from_str("path_elimination").is_ok());
    }

    #[test]
    fn error_display_is_stable() {
        let err = E9EquivalenceError::Lane("boom".to_string());
        assert_eq!(err.to_string(), "equivalence lane invariant violated: boom");
        let err = E9EquivalenceError::Serialization("bad".to_string());
        assert!(err.to_string().contains("serialization failed"));
    }

    #[test]
    fn differential_pair_hash_is_order_sensitive_and_length_prefixed() {
        let (baseline, shadow) = matching_pair();
        let forward = differential_pair_hash(&baseline, &shadow);
        let reverse = differential_pair_hash(&shadow, &baseline);
        assert_eq!(
            forward, reverse,
            "identical facts hash identically regardless of side"
        );
        let mut altered = shadow.clone();
        altered.execution_value_hash_hex = "cc".to_string();
        assert_ne!(forward, differential_pair_hash(&baseline, &altered));
        // Length-prefix discipline: shifting bytes between adjacent fields
        // must change the hash.
        let a = length_prefixed_hash(&["ab", "c"]);
        let b = length_prefixed_hash(&["a", "bc"]);
        assert_ne!(a, b);
    }
}
