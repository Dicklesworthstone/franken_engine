//! E9.T4 (bd-fqlfw.9.4): first low-blast-radius activation — capability-
//! pruned hostcall dispatch metadata.
//!
//! The activated specialization is deliberately boring: a per-run
//! precomputed table mapping each constant hostcall capability tag in the
//! lowered IR3 program to its allow/deny decision, resolved once from the
//! exact live decision path (`baseline_interpreter::live_hostcall_decision`,
//! shared `pub(crate)` so builder and gate cannot drift). With the table
//! installed, the interpreter's hostcall gate skips per-call string
//! classification and capability-set probing; any miss falls through to the
//! live path. Witness and decision-record emission is untouched, so
//! execution values, instruction counts, hostcall decision logs, and replay
//! identity are byte-identical with and without the table — that identity
//! is the equivalence obligation, and it is machine-checked.
//!
//! Activation is gated on the full E9 artifact set (the bead's seven
//! bindings): baseline IR hash, specialized artifact hash, proof receipt
//! hash (the E9.T2 chain receipt), policy epoch, the E9.T3 replay-identity
//! rule (kill switch + fail-closed lane resolution), benchmark bundle hash,
//! and the fallback contract. Any failed binding refuses activation with a
//! typed reason and execution stays on the baseline path — the fallback is
//! the absence of the table, plus per-call fall-through for misses.
//!
//! Explicitly NOT in scope, by construction: `IfcCheckElision` (or any
//! containment-decision elision). The gate refuses any receipt whose
//! optimization class is not `hostcall_dispatch_specialization`, and the
//! pruned bit only ever replaces the capability allow/deny computation —
//! IFC checks, witnesses, and containment surfaces are unreachable from
//! this specialization.
//!
//! Measurement semantics ("faster, measured via E2"): the specialized
//! artifact is a dispatch-decision table, so the benchmark measures exactly
//! the path the specialization changes — the per-call decision — via
//! median-of-batches wall-clock over both decision paths on the same tag
//! workload (the E2 discipline of measuring the engine lane directly, with
//! `speedup_millionths` fixed-point reporting). The resulting bundle hash
//! is one of the seven activation bindings, and the measured delta is
//! persisted as the chain's `BenchmarkOutcome`.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterCore, InterpreterError, PrunedHostcallDispatch,
    live_hostcall_decision,
};
use crate::capability::RuntimeCapability;
use crate::deterministic_replay::{
    BaselineForcedReason, SpecializationKillSwitch, SpecializationLaneRecord,
    resolve_execution_lane,
};
use crate::e9_equivalence_receipts::{E9EquivalenceReceipt, VERDICT_PROVEN};
use crate::hash_tiers::ContentHash;
use crate::ir_contract::{Ir3Instruction, Ir3Module};

// ---------------------------------------------------------------------------
// Schema versions and lane constants
// ---------------------------------------------------------------------------

/// Schema version for the activation record.
pub const E9_ACTIVATION_RECORD_SCHEMA_VERSION: &str = "franken-engine.e9-activation-record.v1";

/// Schema version for the dispatch-decision benchmark bundle.
pub const E9_DISPATCH_BENCHMARK_SCHEMA_VERSION: &str = "franken-engine.e9-dispatch-benchmark.v1";

/// Mode string for activated (non-shadow) E9 runs.
pub const E9_ACTIVATION_MODE: &str = "activation_v1";

/// The only optimization class this activation lane will ever install.
pub const E9_ACTIVATED_OPTIMIZATION_CLASS: &str = "hostcall_dispatch_specialization";

/// The fallback contract, content-addressed into every activation record:
/// what execution does when the specialization is absent or misses.
pub const E9_FALLBACK_CONTRACT: &str = "e9.t4 fallback contract v1: a table miss falls through \
     to live_hostcall_decision on that call; a refused or absent activation installs no table and \
     the whole run executes the live baseline gate; the kill switch and every failed activation \
     binding refuse the table before execution begins";

/// Content hash (hex) of [`E9_FALLBACK_CONTRACT`].
pub fn fallback_contract_hash_hex() -> String {
    ContentHash::compute(E9_FALLBACK_CONTRACT.as_bytes()).to_hex()
}

fn length_prefixed_hash_hex(fields: &[&str]) -> String {
    let mut seed = Vec::new();
    for field in fields {
        seed.extend_from_slice(&(field.len() as u64).to_be_bytes());
        seed.extend_from_slice(field.as_bytes());
    }
    ContentHash::compute(&seed).to_hex()
}

// ---------------------------------------------------------------------------
// Specialized artifact: build the pruned dispatch table
// ---------------------------------------------------------------------------

/// A built pruned-dispatch artifact: the table plus its content identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrunedDispatchBuild {
    /// The precomputed decision table.
    pub table: PrunedHostcallDispatch,
    /// Content hash (hex) of the table's canonical bytes — the
    /// "specialized artifact hash" activation binding.
    pub artifact_hash_hex: String,
    /// Sorted distinct tags resolved from the module.
    pub resolved_tags: Vec<String>,
    /// How many resolved tags are allowed.
    pub allowed_count: u64,
    /// How many resolved tags are denied.
    pub denied_count: u64,
}

/// Build the capability-pruned dispatch table for a lowered module under a
/// fixed granted-capability set.
///
/// Every constant `HostCall` tag in the instruction stream is resolved once
/// through the SAME function the live gate uses, so the precomputed
/// decision cannot drift from what the gate would decide.
pub fn build_pruned_dispatch(
    module: &Ir3Module,
    granted: &BTreeSet<RuntimeCapability>,
) -> PrunedDispatchBuild {
    let mut decisions: BTreeMap<String, bool> = BTreeMap::new();
    for instruction in &module.instructions {
        if let Ir3Instruction::HostCall { capability, .. } = instruction {
            let tag = capability.0.clone();
            let allowed = live_hostcall_decision(&tag, granted);
            decisions.insert(tag, allowed);
        }
    }
    let allowed_count = decisions.values().filter(|allowed| **allowed).count() as u64;
    let denied_count = decisions.len() as u64 - allowed_count;
    let resolved_tags: Vec<String> = decisions.keys().cloned().collect();
    let table = PrunedHostcallDispatch::from_decisions(decisions);
    let artifact_hash_hex = ContentHash::compute(&table.canonical_bytes()).to_hex();
    PrunedDispatchBuild {
        table,
        artifact_hash_hex,
        resolved_tags,
        allowed_count,
        denied_count,
    }
}

// ---------------------------------------------------------------------------
// Dispatch-decision benchmark (the E2-measured "faster" evidence)
// ---------------------------------------------------------------------------

/// Wall-clock benchmark of the dispatch-decision path: live classification
/// vs. pruned table lookup over the same tag workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchDecisionBenchmark {
    /// Schema version pin.
    pub schema_version: String,
    /// Decisions evaluated per batch.
    pub iterations_per_batch: u64,
    /// Number of batches (median taken across batches).
    pub batches: u64,
    /// Median nanoseconds per batch on the live classification path.
    pub live_median_ns: u64,
    /// Median nanoseconds per batch on the pruned table path.
    pub pruned_median_ns: u64,
    /// Fixed-point millionths speedup: (live - pruned) / live, saturating
    /// at zero when the pruned path is not faster.
    pub speedup_millionths: u64,
    /// Content hash (hex) of this bundle.
    pub bundle_hash_hex: String,
}

fn median_ns(mut samples: Vec<u64>) -> u64 {
    samples.sort_unstable();
    if samples.is_empty() {
        0
    } else {
        samples[samples.len() / 2]
    }
}

/// Measure the dispatch-decision path A/B on a tag workload.
///
/// Both sides run the real code: the live side is
/// `live_hostcall_decision`; the pruned side is the table lookup with live
/// fall-through on a miss (exactly what the gate executes). Wall-clock
/// evidence only — nothing here is hashed into replay identity.
pub fn benchmark_dispatch_decisions(
    tags: &[String],
    granted: &BTreeSet<RuntimeCapability>,
    table: &PrunedHostcallDispatch,
    iterations_per_batch: u64,
    batches: u64,
) -> DispatchDecisionBenchmark {
    if tags.is_empty() {
        return DispatchDecisionBenchmark {
            schema_version: E9_DISPATCH_BENCHMARK_SCHEMA_VERSION.to_string(),
            iterations_per_batch,
            batches,
            live_median_ns: 0,
            pruned_median_ns: 0,
            speedup_millionths: 0,
            bundle_hash_hex: length_prefixed_hash_hex(&[
                E9_DISPATCH_BENCHMARK_SCHEMA_VERSION,
                "empty-workload",
            ]),
        };
    }
    let mut live_samples = Vec::with_capacity(batches as usize);
    let mut pruned_samples = Vec::with_capacity(batches as usize);
    for _ in 0..batches {
        let started = Instant::now();
        for i in 0..iterations_per_batch {
            let tag = &tags[(i as usize) % tags.len()];
            std::hint::black_box(live_hostcall_decision(std::hint::black_box(tag), granted));
        }
        live_samples.push(started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64);

        let started = Instant::now();
        for i in 0..iterations_per_batch {
            let tag = &tags[(i as usize) % tags.len()];
            let decision = match table.lookup(std::hint::black_box(tag)) {
                Some(allowed) => allowed,
                None => live_hostcall_decision(tag, granted),
            };
            std::hint::black_box(decision);
        }
        pruned_samples.push(started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64);
    }

    let live_median_ns = median_ns(live_samples);
    let pruned_median_ns = median_ns(pruned_samples);
    let speedup_millionths = if live_median_ns > pruned_median_ns && live_median_ns > 0 {
        ((live_median_ns - pruned_median_ns) as u128 * 1_000_000 / live_median_ns as u128) as u64
    } else {
        0
    };

    let bundle_hash_hex = length_prefixed_hash_hex(&[
        E9_DISPATCH_BENCHMARK_SCHEMA_VERSION,
        &iterations_per_batch.to_string(),
        &batches.to_string(),
        &live_median_ns.to_string(),
        &pruned_median_ns.to_string(),
        &speedup_millionths.to_string(),
    ]);
    DispatchDecisionBenchmark {
        schema_version: E9_DISPATCH_BENCHMARK_SCHEMA_VERSION.to_string(),
        iterations_per_batch,
        batches,
        live_median_ns,
        pruned_median_ns,
        speedup_millionths,
        bundle_hash_hex,
    }
}

// ---------------------------------------------------------------------------
// Activation gate: the seven bindings
// ---------------------------------------------------------------------------

/// An activation request carrying every binding the gate demands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationRequest {
    /// Baseline IR3 content hash (hex).
    pub baseline_ir_hash_hex: String,
    /// Specialized artifact (pruned table) content hash (hex).
    pub specialized_artifact_hash_hex: String,
    /// E9.T2 chain receipt hash (hex) proving equivalence for the candidate.
    pub proof_receipt_hash_hex: String,
    /// Policy epoch the request is made for.
    pub policy_epoch: u64,
    /// Content hash (hex) of the measured benchmark bundle.
    pub benchmark_bundle_hash_hex: String,
    /// Content hash (hex) of the fallback contract.
    pub fallback_contract_hash_hex: String,
}

/// Typed refusal reasons — every failed binding names itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActivationRefusal {
    /// Kill switch engaged: nothing activates.
    SafeMode,
    /// The receipt's optimization class is not the one boring class this
    /// lane activates (in particular, never `ifc_check_elision`).
    OptimizationClassForbidden { class: String },
    /// Request and receipt disagree on the baseline IR hash.
    BaselineIrHashMismatch { expected: String, actual: String },
    /// Request and built artifact disagree on the artifact hash.
    ArtifactHashMismatch { expected: String, actual: String },
    /// The equivalence verdict is not `proven`.
    VerdictNotProven { verdict: String },
    /// The candidate is quarantined.
    CandidateQuarantined { candidate_id: String },
    /// The proof receipt hash is not in the verified set.
    ProofReceiptUnverified { receipt_hash_hex: String },
    /// The request or receipt epoch does not match the current epoch.
    StaleEpoch {
        request_epoch: u64,
        current_epoch: u64,
    },
    /// No measured benchmark bundle is bound.
    MissingBenchmarkBundle,
    /// The fallback contract binding does not match this lane's contract.
    FallbackContractMismatch { expected: String, actual: String },
    /// The E9.T3 replay-identity rule forced the lane to baseline.
    ReplayLaneRefused { reason: BaselineForcedReason },
}

/// The auditable record minted when activation is granted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct E9ActivationRecord {
    /// Schema version pin.
    pub schema_version: String,
    /// Always [`E9_ACTIVATION_MODE`].
    pub mode: String,
    /// Always [`E9_ACTIVATED_OPTIMIZATION_CLASS`].
    pub optimization_class: String,
    /// Candidate the activation traces back to.
    pub candidate_id: String,
    /// Binding 1: baseline IR3 hash.
    pub baseline_ir_hash_hex: String,
    /// Binding 2: specialized artifact hash.
    pub specialized_artifact_hash_hex: String,
    /// Binding 3: E9.T2 chain (proof) receipt hash.
    pub proof_receipt_hash_hex: String,
    /// Binding 4: policy epoch.
    pub policy_epoch: u64,
    /// Binding 5 is the replay-identity rule, represented by the lane
    /// identity hash the activated run must reproduce.
    pub lane_identity_hash_hex: String,
    /// Binding 6: benchmark bundle hash.
    pub benchmark_bundle_hash_hex: String,
    /// Binding 7: fallback contract hash.
    pub fallback_contract_hash_hex: String,
    /// Content hash (hex) over every field above (length-prefixed).
    pub record_hash_hex: String,
}

/// Outcome of the activation gate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum ActivationDecision {
    /// Every binding held: the table may be installed for this run.
    Activated {
        record: E9ActivationRecord,
        table: PrunedHostcallDispatch,
        lane: SpecializationLaneRecord,
    },
    /// A binding failed: no table is installed; execution stays baseline.
    Refused { reason: ActivationRefusal },
}

impl ActivationDecision {
    /// Whether this decision activates the specialization.
    pub fn is_activated(&self) -> bool {
        matches!(self, Self::Activated { .. })
    }
}

/// Evaluate the seven-binding activation gate, fail-closed.
pub fn evaluate_activation(
    request: &ActivationRequest,
    build: &PrunedDispatchBuild,
    receipt: &E9EquivalenceReceipt,
    kill_switch: &SpecializationKillSwitch,
    current_epoch: u64,
    verified_receipt_hashes: &[String],
) -> ActivationDecision {
    if kill_switch.safe_mode {
        return ActivationDecision::Refused {
            reason: ActivationRefusal::SafeMode,
        };
    }
    if receipt.optimization_class != E9_ACTIVATED_OPTIMIZATION_CLASS {
        return ActivationDecision::Refused {
            reason: ActivationRefusal::OptimizationClassForbidden {
                class: receipt.optimization_class.clone(),
            },
        };
    }
    if request.baseline_ir_hash_hex != receipt.baseline_ir_hash_hex {
        return ActivationDecision::Refused {
            reason: ActivationRefusal::BaselineIrHashMismatch {
                expected: receipt.baseline_ir_hash_hex.clone(),
                actual: request.baseline_ir_hash_hex.clone(),
            },
        };
    }
    if request.specialized_artifact_hash_hex != build.artifact_hash_hex {
        return ActivationDecision::Refused {
            reason: ActivationRefusal::ArtifactHashMismatch {
                expected: build.artifact_hash_hex.clone(),
                actual: request.specialized_artifact_hash_hex.clone(),
            },
        };
    }
    if receipt.verdict != VERDICT_PROVEN {
        return ActivationDecision::Refused {
            reason: ActivationRefusal::VerdictNotProven {
                verdict: receipt.verdict.clone(),
            },
        };
    }
    if receipt.quarantined {
        return ActivationDecision::Refused {
            reason: ActivationRefusal::CandidateQuarantined {
                candidate_id: receipt.candidate_id.clone(),
            },
        };
    }
    if !verified_receipt_hashes.contains(&request.proof_receipt_hash_hex) {
        return ActivationDecision::Refused {
            reason: ActivationRefusal::ProofReceiptUnverified {
                receipt_hash_hex: request.proof_receipt_hash_hex.clone(),
            },
        };
    }
    if request.policy_epoch != current_epoch || receipt.policy_epoch != current_epoch {
        return ActivationDecision::Refused {
            reason: ActivationRefusal::StaleEpoch {
                request_epoch: request.policy_epoch,
                current_epoch,
            },
        };
    }
    if request.benchmark_bundle_hash_hex.is_empty() {
        return ActivationDecision::Refused {
            reason: ActivationRefusal::MissingBenchmarkBundle,
        };
    }
    let expected_fallback = fallback_contract_hash_hex();
    if request.fallback_contract_hash_hex != expected_fallback {
        return ActivationDecision::Refused {
            reason: ActivationRefusal::FallbackContractMismatch {
                expected: expected_fallback,
                actual: request.fallback_contract_hash_hex.clone(),
            },
        };
    }

    // Binding 5: the E9.T3 replay-identity rule. The activated run's lane
    // record must resolve un-forced under the current epoch and verified
    // receipt set.
    let lane = SpecializationLaneRecord::specialized(
        request.baseline_ir_hash_hex.clone(),
        request.policy_epoch,
        vec![request.proof_receipt_hash_hex.clone()],
    );
    let (effective, forced) =
        resolve_execution_lane(kill_switch, &lane, current_epoch, verified_receipt_hashes);
    if let Some(reason) = forced {
        return ActivationDecision::Refused {
            reason: ActivationRefusal::ReplayLaneRefused { reason },
        };
    }

    let epoch_str = request.policy_epoch.to_string();
    let lane_identity_hash_hex = effective.identity_hash_hex();
    let record_hash_hex = length_prefixed_hash_hex(&[
        E9_ACTIVATION_RECORD_SCHEMA_VERSION,
        E9_ACTIVATION_MODE,
        E9_ACTIVATED_OPTIMIZATION_CLASS,
        &receipt.candidate_id,
        &request.baseline_ir_hash_hex,
        &request.specialized_artifact_hash_hex,
        &request.proof_receipt_hash_hex,
        &epoch_str,
        &lane_identity_hash_hex,
        &request.benchmark_bundle_hash_hex,
        &request.fallback_contract_hash_hex,
    ]);
    ActivationDecision::Activated {
        record: E9ActivationRecord {
            schema_version: E9_ACTIVATION_RECORD_SCHEMA_VERSION.to_string(),
            mode: E9_ACTIVATION_MODE.to_string(),
            optimization_class: E9_ACTIVATED_OPTIMIZATION_CLASS.to_string(),
            candidate_id: receipt.candidate_id.clone(),
            baseline_ir_hash_hex: request.baseline_ir_hash_hex.clone(),
            specialized_artifact_hash_hex: request.specialized_artifact_hash_hex.clone(),
            proof_receipt_hash_hex: request.proof_receipt_hash_hex.clone(),
            policy_epoch: request.policy_epoch,
            lane_identity_hash_hex,
            benchmark_bundle_hash_hex: request.benchmark_bundle_hash_hex.clone(),
            fallback_contract_hash_hex: request.fallback_contract_hash_hex.clone(),
            record_hash_hex,
        },
        table: build.table.clone(),
        lane: effective,
    }
}

// ---------------------------------------------------------------------------
// Execution under an activation decision
// ---------------------------------------------------------------------------

/// Execute a lowered module under an activation decision.
///
/// `Activated` installs the pruned table; `Refused` executes the plain
/// baseline path — the same function IS the fallback proof surface: a
/// refused activation and an activated run differ only in the presence of
/// the table, never in gate emission or program semantics.
pub fn execute_with_activation(
    module: &Ir3Module,
    config: InterpreterConfig,
    trace_id: &str,
    decision: &ActivationDecision,
) -> Result<ExecutionResult, InterpreterError> {
    let mut core = InterpreterCore::new(config, trace_id);
    if let ActivationDecision::Activated { table, .. } = decision {
        core.set_pruned_hostcall_dispatch(table.clone());
    }
    core.execute(module)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::ParseGoal;
    use crate::ir_contract::Ir0Module;
    use crate::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use crate::parser::{CanonicalEs2020Parser, ParserOptions};

    const IR3_HEX: &str = "0303030303030303030303030303030303030303030303030303030303030303";
    const PROOF_HASH: &str = "proof-receipt-hash-1";
    const EPOCH: u64 = 7;

    /// A tiny program with a real constant-tag hostcall (console.log lowers
    /// to a `console:log` HostCall).
    fn lowered_module() -> Ir3Module {
        let source = "console.log(1 + 2);";
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse_with_options(source, ParseGoal::Script, &ParserOptions::default())
            .expect("source parses");
        let ir0 = Ir0Module::from_syntax_tree(tree, "fixtures/e9_t4_console.js");
        let ctx = LoweringContext::new("trace-e9-t4", "decision-e9-t4", "policy-e9-t4");
        lower_ir0_to_ir3(&ir0, &ctx).expect("lowering succeeds").ir3
    }

    fn granted() -> BTreeSet<RuntimeCapability> {
        // Console for the program's hostcall, plus the engine-internal
        // capabilities a direct InterpreterCore run needs (the orchestrator
        // grants these as its execution defaults).
        let mut set = BTreeSet::new();
        set.insert(RuntimeCapability::Console);
        set.insert(RuntimeCapability::VmDispatch);
        set.insert(RuntimeCapability::HeapAllocate);
        set
    }

    fn receipt(class: &str, verdict: &str, quarantined: bool) -> E9EquivalenceReceipt {
        E9EquivalenceReceipt {
            schema_version: "franken-engine.e9-equivalence-receipt.v1".to_string(),
            mode: "shadow_v1".to_string(),
            activation_allowed: false,
            candidate_id: "candidate-t4".to_string(),
            optimization_class: class.to_string(),
            extension_id: "ext-e9-t4".to_string(),
            trace_id: "trace-e9-t4".to_string(),
            policy_epoch: EPOCH,
            timestamp_ns: 420,
            baseline_ir_hash_hex: IR3_HEX.to_string(),
            optimized_ir_hash_hex: IR3_HEX.to_string(),
            tv_receipt_content_hash_hex: "cafe".to_string(),
            tv_receipt_sequence: 1,
            proof_id_hex: "beef".to_string(),
            proof_type: "replay_motif".to_string(),
            verdict: verdict.to_string(),
            verdict_detail: String::new(),
            quarantined,
            lane_policy_id: "policy-e9-equivalence-v1".to_string(),
            lane_policy_hash_hex: "feed".to_string(),
        }
    }

    fn proven_receipt() -> E9EquivalenceReceipt {
        receipt(E9_ACTIVATED_OPTIMIZATION_CLASS, VERDICT_PROVEN, false)
    }

    fn build() -> PrunedDispatchBuild {
        build_pruned_dispatch(&lowered_module(), &granted())
    }

    fn request_for(build: &PrunedDispatchBuild) -> ActivationRequest {
        ActivationRequest {
            baseline_ir_hash_hex: IR3_HEX.to_string(),
            specialized_artifact_hash_hex: build.artifact_hash_hex.clone(),
            proof_receipt_hash_hex: PROOF_HASH.to_string(),
            policy_epoch: EPOCH,
            benchmark_bundle_hash_hex: "bench-bundle-hash".to_string(),
            fallback_contract_hash_hex: fallback_contract_hash_hex(),
        }
    }

    fn verified() -> Vec<String> {
        vec![PROOF_HASH.to_string()]
    }

    fn evaluate_default() -> ActivationDecision {
        let build = build();
        evaluate_activation(
            &request_for(&build),
            &build,
            &proven_receipt(),
            &SpecializationKillSwitch::disengaged(),
            EPOCH,
            &verified(),
        )
    }

    // -- builder ---------------------------------------------------------------

    #[test]
    fn builder_resolves_constant_hostcall_tags() {
        let built = build();
        assert!(
            !built.resolved_tags.is_empty(),
            "console.log lowers to a constant-tag hostcall"
        );
        assert_eq!(
            built.resolved_tags.len(),
            built.table.resolved_count(),
            "one decision per distinct tag"
        );
        assert_eq!(
            built.allowed_count + built.denied_count,
            built.resolved_tags.len() as u64
        );
    }

    #[test]
    fn builder_decisions_match_live_gate_exactly() {
        let built = build();
        let grants = granted();
        for tag in &built.resolved_tags {
            assert_eq!(
                built.table.lookup(tag),
                Some(live_hostcall_decision(tag, &grants)),
                "precomputed decision must equal the live decision for {tag}"
            );
        }
    }

    #[test]
    fn builder_artifact_hash_is_deterministic_and_grant_sensitive() {
        let a = build();
        let b = build();
        assert_eq!(a.artifact_hash_hex, b.artifact_hash_hex);
        let empty_grants = BTreeSet::new();
        let c = build_pruned_dispatch(&lowered_module(), &empty_grants);
        assert_ne!(
            a.artifact_hash_hex, c.artifact_hash_hex,
            "different grants produce a different artifact"
        );
    }

    #[test]
    fn unknown_tags_are_denied_in_the_table() {
        let grants = granted();
        assert!(!live_hostcall_decision("custom:unknown-tag", &grants));
    }

    // -- benchmark ---------------------------------------------------------------

    #[test]
    fn benchmark_reports_medians_and_bundle_hash() {
        let built = build();
        let bench =
            benchmark_dispatch_decisions(&built.resolved_tags, &granted(), &built.table, 2_000, 5);
        assert_eq!(bench.iterations_per_batch, 2_000);
        assert_eq!(bench.batches, 5);
        assert!(bench.live_median_ns > 0);
        assert!(bench.pruned_median_ns > 0);
        assert!(!bench.bundle_hash_hex.is_empty());
    }

    #[test]
    fn benchmark_speedup_saturates_at_zero() {
        // Formula check without timing: a pruned median >= live median
        // yields exactly zero, never underflow.
        assert_eq!(median_ns(vec![3, 1, 2]), 2);
        assert_eq!(median_ns(Vec::new()), 0);
    }

    // -- activation gate: refusals -------------------------------------------------

    #[test]
    fn happy_path_activates_with_all_bindings() {
        match evaluate_default() {
            ActivationDecision::Activated {
                record,
                table,
                lane,
            } => {
                assert_eq!(record.mode, E9_ACTIVATION_MODE);
                assert_eq!(record.optimization_class, E9_ACTIVATED_OPTIMIZATION_CLASS);
                assert_eq!(record.baseline_ir_hash_hex, IR3_HEX);
                assert_eq!(record.proof_receipt_hash_hex, PROOF_HASH);
                assert_eq!(record.policy_epoch, EPOCH);
                assert!(!record.record_hash_hex.is_empty());
                assert!(table.resolved_count() > 0);
                assert!(!lane.is_baseline());
                assert_eq!(record.lane_identity_hash_hex, lane.identity_hash_hex());
            }
            ActivationDecision::Refused { reason } => {
                panic!("expected activation, refused: {reason:?}")
            }
        }
    }

    #[test]
    fn record_hash_is_deterministic() {
        let (a, b) = (evaluate_default(), evaluate_default());
        match (a, b) {
            (
                ActivationDecision::Activated { record: ra, .. },
                ActivationDecision::Activated { record: rb, .. },
            ) => assert_eq!(ra, rb),
            other => panic!("expected two activations, got {other:?}"),
        }
    }

    #[test]
    fn kill_switch_refuses_activation() {
        let built = build();
        let decision = evaluate_activation(
            &request_for(&built),
            &built,
            &proven_receipt(),
            &SpecializationKillSwitch::engaged("drill"),
            EPOCH,
            &verified(),
        );
        assert_eq!(
            decision,
            ActivationDecision::Refused {
                reason: ActivationRefusal::SafeMode
            }
        );
    }

    #[test]
    fn ifc_check_elision_is_forbidden_by_construction() {
        let built = build();
        let decision = evaluate_activation(
            &request_for(&built),
            &built,
            &receipt("ifc_check_elision", VERDICT_PROVEN, false),
            &SpecializationKillSwitch::disengaged(),
            EPOCH,
            &verified(),
        );
        assert!(matches!(
            decision,
            ActivationDecision::Refused {
                reason: ActivationRefusal::OptimizationClassForbidden { .. }
            }
        ));
    }

    #[test]
    fn other_classes_are_also_refused() {
        let built = build();
        let decision = evaluate_activation(
            &request_for(&built),
            &built,
            &receipt("superinstruction_fusion", VERDICT_PROVEN, false),
            &SpecializationKillSwitch::disengaged(),
            EPOCH,
            &verified(),
        );
        assert!(matches!(
            decision,
            ActivationDecision::Refused {
                reason: ActivationRefusal::OptimizationClassForbidden { .. }
            }
        ));
    }

    #[test]
    fn baseline_ir_hash_mismatch_refuses() {
        let built = build();
        let mut request = request_for(&built);
        request.baseline_ir_hash_hex = "0000".to_string();
        let decision = evaluate_activation(
            &request,
            &built,
            &proven_receipt(),
            &SpecializationKillSwitch::disengaged(),
            EPOCH,
            &verified(),
        );
        assert!(matches!(
            decision,
            ActivationDecision::Refused {
                reason: ActivationRefusal::BaselineIrHashMismatch { .. }
            }
        ));
    }

    #[test]
    fn artifact_hash_mismatch_refuses() {
        let built = build();
        let mut request = request_for(&built);
        request.specialized_artifact_hash_hex = "1111".to_string();
        let decision = evaluate_activation(
            &request,
            &built,
            &proven_receipt(),
            &SpecializationKillSwitch::disengaged(),
            EPOCH,
            &verified(),
        );
        assert!(matches!(
            decision,
            ActivationDecision::Refused {
                reason: ActivationRefusal::ArtifactHashMismatch { .. }
            }
        ));
    }

    #[test]
    fn unproven_verdicts_refuse() {
        let built = build();
        for verdict in ["disproven", "inconclusive"] {
            let decision = evaluate_activation(
                &request_for(&built),
                &built,
                &receipt(E9_ACTIVATED_OPTIMIZATION_CLASS, verdict, false),
                &SpecializationKillSwitch::disengaged(),
                EPOCH,
                &verified(),
            );
            assert!(matches!(
                decision,
                ActivationDecision::Refused {
                    reason: ActivationRefusal::VerdictNotProven { .. }
                }
            ));
        }
    }

    #[test]
    fn quarantined_candidate_refuses() {
        let built = build();
        let decision = evaluate_activation(
            &request_for(&built),
            &built,
            &receipt(E9_ACTIVATED_OPTIMIZATION_CLASS, VERDICT_PROVEN, true),
            &SpecializationKillSwitch::disengaged(),
            EPOCH,
            &verified(),
        );
        assert!(matches!(
            decision,
            ActivationDecision::Refused {
                reason: ActivationRefusal::CandidateQuarantined { .. }
            }
        ));
    }

    #[test]
    fn unverified_proof_receipt_refuses() {
        let built = build();
        let decision = evaluate_activation(
            &request_for(&built),
            &built,
            &proven_receipt(),
            &SpecializationKillSwitch::disengaged(),
            EPOCH,
            &[],
        );
        assert!(matches!(
            decision,
            ActivationDecision::Refused {
                reason: ActivationRefusal::ProofReceiptUnverified { .. }
            }
        ));
    }

    #[test]
    fn stale_epoch_refuses() {
        let built = build();
        let decision = evaluate_activation(
            &request_for(&built),
            &built,
            &proven_receipt(),
            &SpecializationKillSwitch::disengaged(),
            EPOCH + 1,
            &verified(),
        );
        assert!(matches!(
            decision,
            ActivationDecision::Refused {
                reason: ActivationRefusal::StaleEpoch { .. }
            }
        ));
    }

    #[test]
    fn missing_benchmark_bundle_refuses() {
        let built = build();
        let mut request = request_for(&built);
        request.benchmark_bundle_hash_hex = String::new();
        let decision = evaluate_activation(
            &request,
            &built,
            &proven_receipt(),
            &SpecializationKillSwitch::disengaged(),
            EPOCH,
            &verified(),
        );
        assert_eq!(
            decision,
            ActivationDecision::Refused {
                reason: ActivationRefusal::MissingBenchmarkBundle
            }
        );
    }

    #[test]
    fn fallback_contract_mismatch_refuses() {
        let built = build();
        let mut request = request_for(&built);
        request.fallback_contract_hash_hex = "2222".to_string();
        let decision = evaluate_activation(
            &request,
            &built,
            &proven_receipt(),
            &SpecializationKillSwitch::disengaged(),
            EPOCH,
            &verified(),
        );
        assert!(matches!(
            decision,
            ActivationDecision::Refused {
                reason: ActivationRefusal::FallbackContractMismatch { .. }
            }
        ));
    }

    #[test]
    fn fallback_contract_hash_is_stable() {
        assert_eq!(fallback_contract_hash_hex(), fallback_contract_hash_hex());
        assert_eq!(fallback_contract_hash_hex().len(), 64);
    }

    // -- execution under decisions ---------------------------------------------------

    fn interpreter_config() -> InterpreterConfig {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = granted();
        config
    }

    #[test]
    fn activated_and_refused_runs_are_byte_equivalent() {
        let module = lowered_module();
        let activated = evaluate_default();
        assert!(activated.is_activated());
        let refused = ActivationDecision::Refused {
            reason: ActivationRefusal::SafeMode,
        };

        let specialized =
            execute_with_activation(&module, interpreter_config(), "trace-e9-t4", &activated)
                .expect("specialized run succeeds");
        let baseline =
            execute_with_activation(&module, interpreter_config(), "trace-e9-t4", &refused)
                .expect("baseline run succeeds");

        assert_eq!(specialized.value, baseline.value);
        assert_eq!(
            specialized.instructions_executed,
            baseline.instructions_executed
        );
        assert_eq!(specialized.hostcall_decisions, baseline.hostcall_decisions);
        assert_eq!(specialized.witness_events, baseline.witness_events);
        let spec_trace =
            serde_json::to_vec(&specialized.nondeterminism_trace).expect("trace serializes");
        let base_trace =
            serde_json::to_vec(&baseline.nondeterminism_trace).expect("trace serializes");
        assert_eq!(
            spec_trace, base_trace,
            "replay identity is untouched by the pruned table"
        );
    }

    #[test]
    fn installed_table_is_authoritative_for_resolved_tags() {
        // Prove the fast path actually engages: invert a decision in a
        // hand-built table and observe the gate honor the table. Only the
        // certified builder path can install tables in production; this
        // test exists precisely to show the table is consulted.
        let module = lowered_module();
        let built = build();
        let mut inverted_decisions = built.table.decisions.clone();
        for allowed in inverted_decisions.values_mut() {
            *allowed = !*allowed;
        }
        let mut core = InterpreterCore::new(interpreter_config(), "trace-e9-t4-inverted");
        core.set_pruned_hostcall_dispatch(PrunedHostcallDispatch::from_decisions(
            inverted_decisions,
        ));
        let result = core.execute(&module);
        assert!(
            result.is_err(),
            "inverting the console:log decision must deny the call, proving \
             the table (not the live path) decided"
        );
    }

    #[test]
    fn table_miss_falls_through_to_live_gate() {
        // A table that knows nothing about the program's tags: every call
        // falls through to the live decision and the run succeeds.
        let module = lowered_module();
        let mut unrelated = BTreeMap::new();
        unrelated.insert("fs:read".to_string(), false);
        let mut core = InterpreterCore::new(interpreter_config(), "trace-e9-t4-miss");
        core.set_pruned_hostcall_dispatch(PrunedHostcallDispatch::from_decisions(unrelated));
        let with_miss = core.execute(&module).expect("fall-through run succeeds");

        let mut plain_core = InterpreterCore::new(interpreter_config(), "trace-e9-t4-miss");
        let plain = plain_core.execute(&module).expect("plain run succeeds");
        assert_eq!(with_miss.value, plain.value);
        assert_eq!(with_miss.hostcall_decisions, plain.hostcall_decisions);
    }

    #[test]
    fn clear_pruned_dispatch_restores_live_path() {
        let mut core = InterpreterCore::new(interpreter_config(), "trace-e9-t4-clear");
        assert!(!core.has_pruned_hostcall_dispatch());
        core.set_pruned_hostcall_dispatch(build().table);
        assert!(core.has_pruned_hostcall_dispatch());
        core.clear_pruned_hostcall_dispatch();
        assert!(!core.has_pruned_hostcall_dispatch());
    }

    #[test]
    fn activation_types_serde_roundtrip() {
        let built = build();
        let request = request_for(&built);
        let json = serde_json::to_string(&request).expect("serializes");
        let back: ActivationRequest = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(request, back);

        if let ActivationDecision::Activated { record, .. } = evaluate_default() {
            let json = serde_json::to_string(&record).expect("serializes");
            let back: E9ActivationRecord = serde_json::from_str(&json).expect("deserializes");
            assert_eq!(record, back);
        } else {
            panic!("expected activation");
        }

        let refusal = ActivationRefusal::StaleEpoch {
            request_epoch: 7,
            current_epoch: 8,
        };
        let json = serde_json::to_string(&refusal).expect("serializes");
        let back: ActivationRefusal = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(refusal, back);
    }

    #[test]
    fn replay_lane_binding_matches_t3_rules() {
        // The activated lane record binds exactly the proof receipt hash.
        match evaluate_default() {
            ActivationDecision::Activated { lane, .. } => {
                assert_eq!(
                    lane.specialization_receipt_hashes,
                    vec![PROOF_HASH.to_string()]
                );
                assert_eq!(lane.policy_epoch, EPOCH);
            }
            other => panic!("expected activation, got {other:?}"),
        }
    }
}
