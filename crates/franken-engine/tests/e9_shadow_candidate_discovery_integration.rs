//! Integration tests for E9.T1 shadow-mode candidate discovery
//! (bd-fqlfw.9.1): candidates + baseline costs are recorded from a REAL
//! lowered-and-executed program, and the discovery pass provably changes
//! nothing about runtime semantics or replay.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::e9_shadow_candidate_discovery::{
    BaselineRunFacts, E9_SHADOW_MODE, RegionKind, ShadowDiscoveryPolicy, discover_candidates,
    emit_candidates_into_index,
};
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig, OrchestratorResult,
};
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Module};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};
use frankenengine_engine::specialization_index::SpecializationIndex;
use frankenengine_engine::storage_adapter::InMemoryStorageAdapter;

/// A loop-heavy agent-shaped workload: the hot region is the `for` body.
const HOT_LOOP_SOURCE: &str = "let total = 0;\n\
     for (let i = 0; i < 100; i = i + 1) {\n\
       total = total + i * 2;\n\
     }\n\
     total;";

const EXTENSION_ID: &str = "ext-e9-shadow-discovery";

fn package() -> ExtensionPackage {
    ExtensionPackage {
        extension_id: EXTENSION_ID.to_string(),
        source: HOT_LOOP_SOURCE.to_string(),
        source_file: Some("fixtures/e9_hot_loop.js".to_string()),
        capabilities: vec![],
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

fn lower_hot_loop() -> Ir3Module {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse_with_options(
            HOT_LOOP_SOURCE,
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("source parses");
    let ir0 = Ir0Module::from_syntax_tree(tree, "fixtures/e9_hot_loop.js");
    let ctx = LoweringContext::new("trace-e9-lower", "decision-e9-lower", "policy-e9-lower");
    lower_ir0_to_ir3(&ir0, &ctx).expect("lowering succeeds").ir3
}

fn facts_from(result: &OrchestratorResult) -> BaselineRunFacts {
    BaselineRunFacts {
        trace_id: result.trace_id.clone(),
        decision_id: result.decision_id.clone(),
        extension_id: result.extension_id.clone(),
        policy_epoch: result.epoch.as_u64(),
        instructions_executed: result.instructions_executed,
    }
}

fn permissive_policy() -> ShadowDiscoveryPolicy {
    ShadowDiscoveryPolicy {
        min_dominance_millionths: 0,
        ..ShadowDiscoveryPolicy::default()
    }
}

/// ACCEPTANCE (bd-fqlfw.9.1): candidates + baseline costs are recorded for a
/// real lowered-and-executed program — the hot loop body is discovered, its
/// deterministic cost attribution is populated, and the run's tick count is
/// bound into every receipt.
#[test]
fn hot_loop_yields_shadow_candidates_with_baseline_cost() {
    let result = execute_baseline();
    assert!(result.instructions_executed > 100, "the loop actually ran");

    let module = lower_hot_loop();
    let report = discover_candidates(&module, &facts_from(&result), &permissive_policy());

    assert_eq!(report.mode, E9_SHADOW_MODE);
    assert!(!report.candidates.is_empty(), "hot loop must surface");
    assert!(
        report
            .candidates
            .iter()
            .any(|c| c.region.kind == RegionKind::LoopBody),
        "a backward-jump loop body must be among the candidates"
    );
    for candidate in &report.candidates {
        assert!(candidate.region_static_cost > 0);
        assert!(candidate.program_static_cost >= candidate.region_static_cost);
        assert_eq!(
            candidate.baseline.instructions_executed,
            result.instructions_executed
        );
        assert_eq!(candidate.baseline.trace_id, result.trace_id);
        assert!(!candidate.activation_allowed);
        assert_ne!(candidate.proposed_optimization_class, "ifc_check_elision");
    }
}

/// ACCEPTANCE (bd-fqlfw.9.1): ZERO change to runtime semantics or replay.
/// Discovery is a pure post-hoc pass: two executions of the same package —
/// one with discovery interleaved, one without — produce identical execution
/// values, identical tick counts, and byte-identical nondeterminism traces.
#[test]
fn discovery_changes_nothing_about_execution_or_replay() {
    let plain = execute_baseline();

    // Second execution with the discovery pass run in between and after.
    let module = lower_hot_loop();
    let with_discovery = {
        let before = discover_candidates(
            &module,
            &facts_from(&plain),
            &ShadowDiscoveryPolicy::default(),
        );
        let result = execute_baseline();
        let after = discover_candidates(
            &module,
            &facts_from(&result),
            &ShadowDiscoveryPolicy::default(),
        );
        // The pass itself is deterministic given the same facts.
        assert_eq!(before.policy_hash_hex, after.policy_hash_hex);
        result
    };

    assert_eq!(plain.execution_value, with_discovery.execution_value);
    assert_eq!(
        plain.instructions_executed,
        with_discovery.instructions_executed
    );
    let plain_trace = serde_json::to_vec(&plain.nondeterminism_trace).expect("trace serializes");
    let discovery_trace =
        serde_json::to_vec(&with_discovery.nondeterminism_trace).expect("trace serializes");
    assert_eq!(
        plain_trace, discovery_trace,
        "replay identity must be untouched by shadow discovery"
    );
}

/// Discovery over the same lowered program is deterministic end-to-end:
/// re-lowering and re-discovering yields an identical report (stable
/// candidate ids, stable ordering, stable costs).
#[test]
fn discovery_is_deterministic_across_relowering() {
    let result = execute_baseline();
    let facts = facts_from(&result);
    let policy = permissive_policy();

    let first = discover_candidates(&lower_hot_loop(), &facts, &policy);
    let second = discover_candidates(&lower_hot_loop(), &facts, &policy);
    assert_eq!(first, second);
}

/// ACCEPTANCE (bd-fqlfw.9.1): candidate specialization receipts land in the
/// specialization index as the first link of the proof -> spec -> benchmark
/// audit chain: inactive, empty proof set, joinable by receipt id, and
/// idempotent on re-emission.
#[test]
fn candidates_are_recorded_in_the_specialization_index() {
    let result = execute_baseline();
    let module = lower_hot_loop();
    let report = discover_candidates(&module, &facts_from(&result), &permissive_policy());
    assert!(!report.candidates.is_empty());

    let mut index = SpecializationIndex::new(InMemoryStorageAdapter::new(), "policy-e9-shadow");
    let outcomes = emit_candidates_into_index(&mut index, &report).expect("emission succeeds");
    assert_eq!(outcomes.len(), report.candidates.len());
    assert!(outcomes.iter().all(|o| o.outcome == "inserted"));

    for outcome in &outcomes {
        let receipt_id = frankenengine_engine::engine_object_id::EngineObjectId::from_hex(
            &outcome.receipt_id_hex,
        )
        .expect("receipt id parses");
        let stored = index
            .get_receipt(&receipt_id, &report.baseline.trace_id)
            .expect("index lookup succeeds")
            .expect("candidate receipt is present");
        assert!(!stored.active, "shadow candidates are never active");
        assert!(stored.proof_input_ids.is_empty(), "no proofs before E9.T2");
        assert_eq!(stored.extension_id, EXTENSION_ID);
    }

    let again = emit_candidates_into_index(&mut index, &report).expect("re-emission succeeds");
    assert!(again.iter().all(|o| o.outcome == "duplicate_skipped"));
}
