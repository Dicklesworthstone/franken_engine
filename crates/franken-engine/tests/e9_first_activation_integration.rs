//! Integration tests for E9.T4 first low-blast-radius activation
//! (bd-fqlfw.9.4): a REAL discovered, equivalence-proven, chain-persisted
//! hostcall-dispatch candidate is activated through the seven-binding gate,
//! the activated path is measured faster at the dispatch-decision level and
//! byte-equivalent at the execution level, the E9.T3 replay-identity rule
//! holds for the activated lane, and every gate failure falls back safely
//! to the baseline path.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::InterpreterConfig;
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::deterministic_replay::{
    NondeterminismTrace, ReplayLaneOutcome, SpecializationKillSwitch, enforce_strict_replay_lane,
};
use frankenengine_engine::e9_equivalence_receipts::{
    DifferentialRunFacts, E9EquivalenceReceipt, EquivalenceLaneConfig, persist_equivalence_chain,
    validate_candidates,
};
use frankenengine_engine::e9_first_activation::{
    ActivationDecision, ActivationRefusal, ActivationRequest, E9_ACTIVATED_OPTIMIZATION_CLASS,
    benchmark_dispatch_decisions, build_pruned_dispatch, evaluate_activation,
    execute_with_activation, fallback_contract_hash_hex,
};
use frankenengine_engine::e9_shadow_candidate_discovery::{
    BaselineRunFacts, ShadowDiscoveryPolicy, discover_candidates,
};
use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig, OrchestratorResult,
};
use frankenengine_engine::ir_contract::Ir3Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};
use frankenengine_engine::specialization_index::{BenchmarkOutcome, SpecializationIndex};
use frankenengine_engine::storage_adapter::InMemoryStorageAdapter;

/// A hostcall-heavy loop: the hot region is cost-dominated by the
/// `console:log` hostcall family (five HostCall ops at schedule-cost 4
/// each, with literal arguments so scope-binding traffic stays small), so
/// discovery proposes `hostcall_dispatch_specialization` — the exact class
/// this activation lane installs.
const HOSTCALL_LOOP_SOURCE: &str = "let total = 0;\n\
     for (let i = 0; i < 40; i = i + 1) {\n\
       console.log(0);\n\
       console.log(0);\n\
       console.log(0);\n\
       console.log(0);\n\
       console.log(0);\n\
       total = total + 1;\n\
     }\n\
     total;";

const EXTENSION_ID: &str = "ext-e9-first-activation";

fn package() -> ExtensionPackage {
    ExtensionPackage {
        extension_id: EXTENSION_ID.to_string(),
        source: HOSTCALL_LOOP_SOURCE.to_string(),
        source_file: Some("fixtures/e9_hostcall_loop.js".to_string()),
        capabilities: vec!["console".to_string()],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    }
}

fn execute_baseline() -> OrchestratorResult {
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator
        .execute(&package())
        .expect("baseline execution succeeds")
}

fn lower_module() -> Ir3Module {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse_with_options(
            HOSTCALL_LOOP_SOURCE,
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("source parses");
    let ir0 = frankenengine_engine::ir_contract::Ir0Module::from_syntax_tree(
        tree,
        "fixtures/e9_hostcall_loop.js",
    );
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

struct PipelineArtifacts {
    module: Ir3Module,
    receipt: E9EquivalenceReceipt,
    chain_receipt_hash_hex: String,
    all_chain_hashes: Vec<String>,
    epoch: u64,
    index: SpecializationIndex<InMemoryStorageAdapter>,
    trace_id: String,
}

/// Run the full E9 pipeline (discover -> equivalence -> persist) and return
/// the artifacts for the hostcall-dispatch candidate.
fn run_pipeline() -> PipelineArtifacts {
    let baseline_run = execute_baseline();
    let shadow_run = execute_baseline();
    let module = lower_module();

    let facts = BaselineRunFacts {
        trace_id: baseline_run.trace_id.clone(),
        decision_id: baseline_run.decision_id.clone(),
        extension_id: baseline_run.extension_id.clone(),
        policy_epoch: baseline_run.epoch.as_u64(),
        instructions_executed: baseline_run.instructions_executed,
    };
    let policy = ShadowDiscoveryPolicy {
        min_dominance_millionths: 0,
        ..ShadowDiscoveryPolicy::default()
    };
    let discovery = discover_candidates(&module, &facts, &policy);
    assert!(!discovery.candidates.is_empty(), "candidates must surface");

    let report = validate_candidates(
        &discovery,
        &DifferentialRunFacts::from_result(&baseline_run).expect("baseline facts"),
        &DifferentialRunFacts::from_result(&shadow_run).expect("shadow facts"),
        &EquivalenceLaneConfig::default(),
    )
    .expect("lane validates");

    let mut index = SpecializationIndex::new(InMemoryStorageAdapter::new(), "policy-e9-t4");
    let outcomes = persist_equivalence_chain(&mut index, &report).expect("persists");

    // Pick the hostcall-dispatch candidate — the class this lane activates.
    let (receipt, outcome) = report
        .receipts
        .iter()
        .zip(outcomes.iter())
        .find(|(receipt, _)| receipt.optimization_class == E9_ACTIVATED_OPTIMIZATION_CLASS)
        .map(|(receipt, outcome)| (receipt.clone(), outcome.clone()))
        .unwrap_or_else(|| {
            let summary: Vec<(String, String, String)> = discovery
                .candidates
                .iter()
                .map(|c| {
                    (
                        c.candidate_id.clone(),
                        c.dominant_family.clone(),
                        c.proposed_optimization_class.clone(),
                    )
                })
                .collect();
            panic!(
                "a hostcall-dominated candidate must be discovered; got: {summary:?}; \
                 histograms: {:?}",
                discovery
                    .candidates
                    .iter()
                    .map(|c| c.op_family_histogram.clone())
                    .collect::<Vec<_>>()
            )
        });
    assert_eq!(receipt.verdict, "proven");

    let all_chain_hashes: Vec<String> = outcomes
        .iter()
        .map(|o| o.chain_receipt_id_hex.clone())
        .collect();
    PipelineArtifacts {
        module,
        chain_receipt_hash_hex: outcome.chain_receipt_id_hex.clone(),
        all_chain_hashes,
        epoch: report.policy_epoch,
        trace_id: report.trace_id.clone(),
        receipt,
        index,
    }
}

fn interpreter_config() -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = granted();
    config
}

fn activation_request(
    artifacts: &PipelineArtifacts,
    artifact_hash_hex: &str,
    benchmark_bundle_hash_hex: &str,
) -> ActivationRequest {
    ActivationRequest {
        baseline_ir_hash_hex: artifacts.receipt.baseline_ir_hash_hex.clone(),
        specialized_artifact_hash_hex: artifact_hash_hex.to_string(),
        proof_receipt_hash_hex: artifacts.chain_receipt_hash_hex.clone(),
        policy_epoch: artifacts.epoch,
        benchmark_bundle_hash_hex: benchmark_bundle_hash_hex.to_string(),
        fallback_contract_hash_hex: fallback_contract_hash_hex(),
    }
}

/// ACCEPTANCE (bd-fqlfw.9.4): the full pipeline activates one boring,
/// receipt-backed hostcall-dispatch specialization through all seven
/// bindings; the activated path is measured faster at the decision level;
/// execution under the activated table is byte-equivalent to baseline; and
/// the real measured delta lands in the persisted proof->spec->benchmark
/// chain.
#[test]
fn first_activation_is_gated_measured_and_equivalent() {
    let mut artifacts = run_pipeline();
    let build = build_pruned_dispatch(&artifacts.module, &granted());
    assert!(build.table.resolved_count() > 0, "constant tags resolved");

    // E2-measured: the dispatch-decision path the specialization changes.
    let bench =
        benchmark_dispatch_decisions(&build.resolved_tags, &granted(), &build.table, 100_000, 9);
    assert!(
        bench.speedup_millionths > 0,
        "pruned dispatch decision must be measurably faster: live={}ns pruned={}ns",
        bench.live_median_ns,
        bench.pruned_median_ns
    );

    let request = activation_request(&artifacts, &build.artifact_hash_hex, &bench.bundle_hash_hex);
    let decision = evaluate_activation(
        &request,
        &build,
        &artifacts.receipt,
        &SpecializationKillSwitch::disengaged(),
        artifacts.epoch,
        &artifacts.all_chain_hashes,
    );
    let (record, lane) = match &decision {
        ActivationDecision::Activated { record, lane, .. } => (record.clone(), lane.clone()),
        ActivationDecision::Refused { reason } => panic!("activation refused: {reason:?}"),
    };
    assert_eq!(record.benchmark_bundle_hash_hex, bench.bundle_hash_hex);
    assert_eq!(
        record.proof_receipt_hash_hex,
        artifacts.chain_receipt_hash_hex
    );

    // Byte-equivalence: activated vs baseline execution.
    let refused = ActivationDecision::Refused {
        reason: ActivationRefusal::SafeMode,
    };
    let specialized =
        execute_with_activation(&artifacts.module, interpreter_config(), "t4-a", &decision)
            .expect("activated run succeeds");
    let baseline =
        execute_with_activation(&artifacts.module, interpreter_config(), "t4-a", &refused)
            .expect("baseline run succeeds");
    assert_eq!(specialized.value, baseline.value);
    assert_eq!(
        specialized.instructions_executed,
        baseline.instructions_executed
    );
    assert_eq!(specialized.hostcall_decisions, baseline.hostcall_decisions);
    assert!(
        !specialized.hostcall_decisions.is_empty(),
        "the loop actually exercised the hostcall gate"
    );
    let spec_trace =
        serde_json::to_vec(&specialized.nondeterminism_trace).expect("trace serializes");
    let base_trace = serde_json::to_vec(&baseline.nondeterminism_trace).expect("trace serializes");
    assert_eq!(spec_trace, base_trace, "replay identity untouched");

    // The REAL measured delta completes the proof->spec->benchmark chain.
    let receipt_id =
        EngineObjectId::from_hex(&artifacts.chain_receipt_hash_hex).expect("id parses");
    let t4_benchmark = BenchmarkOutcome {
        benchmark_id: format!(
            "e9-t4-{}",
            bench.bundle_hash_hex.get(..16).unwrap_or("bundle")
        ),
        receipt_id: receipt_id.clone(),
        latency_reduction_millionths: bench.speedup_millionths,
        throughput_increase_millionths: 0,
        sample_count: bench.iterations_per_batch * bench.batches,
        timestamp_ns: artifacts.receipt.timestamp_ns,
    };
    artifacts
        .index
        .insert_benchmark(&t4_benchmark, &artifacts.trace_id)
        .expect("benchmark persists");
    let benchmarks = artifacts
        .index
        .find_benchmarks_by_receipt(&receipt_id, &artifacts.trace_id)
        .expect("benchmark lookup");
    assert!(
        benchmarks.iter().any(
            |b| b.latency_reduction_millionths == bench.speedup_millionths
                && b.benchmark_id.starts_with("e9-t4-")
        ),
        "measured activation benchmark joined to the chain receipt"
    );

    // E9.T3 replay-identity rule for the activated lane.
    let mut lane_trace = NondeterminismTrace::new("t4-lane");
    lane_trace.capture_specialization_lane(&lane, 1);
    lane_trace.finalise(2);
    let outcome = enforce_strict_replay_lane(
        &lane_trace,
        &lane,
        &SpecializationKillSwitch::disengaged(),
        artifacts.epoch,
        &artifacts.all_chain_hashes,
    )
    .expect("lane rule evaluates");
    match outcome {
        ReplayLaneOutcome::SameLaneReproduced { identity } => {
            assert_eq!(identity.lane_identity_hash_hex, lane.identity_hash_hex());
            assert_eq!(record.lane_identity_hash_hex, lane.identity_hash_hex());
        }
        other => panic!("expected SameLaneReproduced, got {other:?}"),
    }
}

/// ACCEPTANCE (bd-fqlfw.9.4): the activation falls back safely on any gate
/// failure — kill switch, stale epoch, and unverified proof each refuse
/// with a typed reason, and the refused run executes baseline with results
/// identical to a plain run.
#[test]
fn every_gate_failure_falls_back_to_baseline() {
    let artifacts = run_pipeline();
    let build = build_pruned_dispatch(&artifacts.module, &granted());
    let bench =
        benchmark_dispatch_decisions(&build.resolved_tags, &granted(), &build.table, 2_000, 3);
    let request = activation_request(&artifacts, &build.artifact_hash_hex, &bench.bundle_hash_hex);

    // Kill switch.
    let kill = evaluate_activation(
        &request,
        &build,
        &artifacts.receipt,
        &SpecializationKillSwitch::engaged("t4 drill"),
        artifacts.epoch,
        &artifacts.all_chain_hashes,
    );
    assert_eq!(
        kill,
        ActivationDecision::Refused {
            reason: ActivationRefusal::SafeMode
        }
    );

    // Stale epoch.
    let stale = evaluate_activation(
        &request,
        &build,
        &artifacts.receipt,
        &SpecializationKillSwitch::disengaged(),
        artifacts.epoch + 1,
        &artifacts.all_chain_hashes,
    );
    assert!(matches!(
        stale,
        ActivationDecision::Refused {
            reason: ActivationRefusal::StaleEpoch { .. }
        }
    ));

    // Unverified proof receipt.
    let unverified = evaluate_activation(
        &request,
        &build,
        &artifacts.receipt,
        &SpecializationKillSwitch::disengaged(),
        artifacts.epoch,
        &[],
    );
    assert!(matches!(
        unverified,
        ActivationDecision::Refused {
            reason: ActivationRefusal::ProofReceiptUnverified { .. }
        }
    ));

    // A refused activation executes baseline, identical to a plain run.
    let plain = execute_with_activation(
        &artifacts.module,
        interpreter_config(),
        "t4-fallback",
        &ActivationDecision::Refused {
            reason: ActivationRefusal::SafeMode,
        },
    )
    .expect("refused run succeeds");
    let reference = execute_with_activation(
        &artifacts.module,
        interpreter_config(),
        "t4-fallback",
        &kill,
    )
    .expect("kill-switch run succeeds");
    assert_eq!(plain.value, reference.value);
    assert_eq!(plain.instructions_executed, reference.instructions_executed);
    assert_eq!(plain.hostcall_decisions, reference.hostcall_decisions);
}
