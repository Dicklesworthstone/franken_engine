//! Integration tests for E9.T2 equivalence receipts + proof->spec->benchmark
//! persistence (bd-fqlfw.9.2): every REAL discovered candidate carries a
//! fail-closed equivalence verdict anchored to real differential runs, the
//! full audit chain is persisted and joinable, disproven/inconclusive
//! candidates are quarantined, and the lane provably changes nothing about
//! execution or replay.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::e9_equivalence_receipts::{
    DifferentialRunFacts, EquivalenceLaneConfig, VERDICT_DISPROVEN, VERDICT_PROVEN,
    activation_eligible, invalidate_chain_on_epoch_change, persist_equivalence_chain,
    validate_candidates,
};
use frankenengine_engine::e9_shadow_candidate_discovery::{
    BaselineRunFacts, ShadowDiscoveryPolicy, ShadowDiscoveryReport, discover_candidates,
};
use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig, OrchestratorResult,
};
use frankenengine_engine::ir_contract::Ir3Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};
use frankenengine_engine::proof_specialization_receipt::ProofType;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::specialization_index::SpecializationIndex;
use frankenengine_engine::storage_adapter::InMemoryStorageAdapter;

/// The same loop-heavy workload the E9.T1 integration test uses: the hot
/// region is the `for` body.
const HOT_LOOP_SOURCE: &str = "let total = 0;\n\
     for (let i = 0; i < 100; i = i + 1) {\n\
       total = total + i * 2;\n\
     }\n\
     total;";

const EXTENSION_ID: &str = "ext-e9-equivalence";

fn package() -> ExtensionPackage {
    ExtensionPackage {
        extension_id: EXTENSION_ID.to_string(),
        source: HOT_LOOP_SOURCE.to_string(),
        source_file: Some("fixtures/e9_hot_loop.js".to_string()),
        module_root: None,
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
    let ir0 = frankenengine_engine::ir_contract::Ir0Module::from_syntax_tree(
        tree,
        "fixtures/e9_hot_loop.js",
    );
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

fn discover(result: &OrchestratorResult) -> ShadowDiscoveryReport {
    let module = lower_hot_loop();
    discover_candidates(&module, &facts_from(result), &permissive_policy())
}

/// ACCEPTANCE (bd-fqlfw.9.2): every candidate from a REAL lowered-and-executed
/// program carries a fail-closed equivalence verdict — here the deterministic
/// engine's baseline and shadow re-run agree byte-for-byte, so every candidate
/// is proven via real differential-trace evidence, and the signed TV chain
/// validates.
#[test]
fn real_differential_runs_prove_every_candidate() {
    let baseline_result = execute_baseline();
    let shadow_result = execute_baseline();
    let discovery = discover(&baseline_result);
    assert!(!discovery.candidates.is_empty(), "hot loop must surface");

    let baseline_facts =
        DifferentialRunFacts::from_result(&baseline_result).expect("baseline facts");
    let shadow_facts = DifferentialRunFacts::from_result(&shadow_result).expect("shadow facts");

    let report = validate_candidates(
        &discovery,
        &baseline_facts,
        &shadow_facts,
        &EquivalenceLaneConfig::default(),
    )
    .expect("lane validates");

    assert_eq!(report.receipts.len(), discovery.candidates.len());
    assert_eq!(report.proven_count, discovery.candidates.len() as u64);
    assert!(report.quarantined_candidate_ids.is_empty());
    assert!(report.chain.verify_integrity().valid);
    for receipt in &report.receipts {
        assert_eq!(receipt.verdict, VERDICT_PROVEN);
        assert!(!receipt.activation_allowed, "shadow evidence only");
        assert!(
            !activation_eligible(receipt),
            "v1 never activates, even proven candidates"
        );
        assert_ne!(receipt.optimization_class, "ifc_check_elision");
    }
}

/// ACCEPTANCE (bd-fqlfw.9.2): the full audit chain security proof ->
/// specialization receipt -> benchmark outcome is persisted and joinable in
/// the specialization index, and re-persisting is idempotent.
#[test]
fn audit_chain_persists_and_joins_end_to_end() {
    let baseline_result = execute_baseline();
    let shadow_result = execute_baseline();
    let discovery = discover(&baseline_result);
    let report = validate_candidates(
        &discovery,
        &DifferentialRunFacts::from_result(&baseline_result).expect("baseline facts"),
        &DifferentialRunFacts::from_result(&shadow_result).expect("shadow facts"),
        &EquivalenceLaneConfig::default(),
    )
    .expect("lane validates");

    let mut index = SpecializationIndex::new(InMemoryStorageAdapter::new(), "policy-e9-t2");
    let outcomes = persist_equivalence_chain(&mut index, &report).expect("persists");
    assert_eq!(outcomes.len(), report.receipts.len());
    assert!(outcomes.iter().all(|o| o.record_outcome == "inserted"));
    assert!(
        outcomes
            .iter()
            .all(|o| o.benchmark_outcome.as_deref() == Some("inserted"))
    );

    // The proof -> spec -> benchmark join is queryable.
    let audit_chain = index
        .build_audit_chain(&report.trace_id)
        .expect("audit chain builds");
    assert_eq!(audit_chain.len(), report.receipts.len());
    for entry in &audit_chain {
        assert_eq!(entry.proof_type, ProofType::ReplayMotif);
        assert!(entry.benchmark_id.is_some(), "chain reaches benchmark");
        assert_eq!(
            entry.latency_reduction_millionths,
            Some(0),
            "identity specialization has an honest zero delta"
        );
    }

    // Records are never active in shadow mode; each carries one proof.
    for outcome in &outcomes {
        let receipt_id =
            EngineObjectId::from_hex(&outcome.chain_receipt_id_hex).expect("id parses");
        let stored = index
            .get_receipt(&receipt_id, &report.trace_id)
            .expect("lookup succeeds")
            .expect("record present");
        assert!(!stored.active);
        assert_eq!(stored.proof_input_ids.len(), 1);
    }

    // Idempotency.
    let again = persist_equivalence_chain(&mut index, &report).expect("re-persists");
    assert!(
        again
            .iter()
            .all(|o| o.record_outcome == "duplicate_skipped")
    );
}

/// ACCEPTANCE (bd-fqlfw.9.2): a divergent shadow run disproves candidates,
/// which are quarantined and persist WITHOUT a benchmark link — fail-closed,
/// auditable, never activatable. An epoch change then invalidates the chain
/// with the recorded reason.
#[test]
fn divergent_run_quarantines_and_epoch_change_invalidates() {
    let baseline_result = execute_baseline();
    let discovery = discover(&baseline_result);
    let baseline_facts =
        DifferentialRunFacts::from_result(&baseline_result).expect("baseline facts");

    // Synthesize a divergent shadow run: same shape, different value hash
    // (a real divergent execution would produce exactly this fact pattern).
    let mut divergent = baseline_facts.clone();
    divergent.trace_id = format!("{}-divergent", baseline_facts.trace_id);
    divergent.execution_value_hash_hex = format!(
        "{}{}",
        &baseline_facts.execution_value_hash_hex[2..],
        &baseline_facts.execution_value_hash_hex[..2]
    );

    let report = validate_candidates(
        &discovery,
        &baseline_facts,
        &divergent,
        &EquivalenceLaneConfig::default(),
    )
    .expect("lane validates");
    assert_eq!(report.disproven_count, report.receipts.len() as u64);
    assert_eq!(
        report.quarantined_candidate_ids.len(),
        report.receipts.len()
    );
    for receipt in &report.receipts {
        assert_eq!(receipt.verdict, VERDICT_DISPROVEN);
        assert!(receipt.quarantined);
        assert!(!activation_eligible(receipt));
    }
    assert_eq!(report.chain.failures.len(), report.receipts.len());

    let mut index = SpecializationIndex::new(InMemoryStorageAdapter::new(), "policy-e9-t2");
    let outcomes = persist_equivalence_chain(&mut index, &report).expect("persists");
    assert!(outcomes.iter().all(|o| o.benchmark_id.is_none()));

    // Epoch transition invalidates the persisted chain records.
    let new_epoch = SecurityEpoch::from_raw(report.policy_epoch + 1);
    let invalidations = invalidate_chain_on_epoch_change(
        &mut index,
        new_epoch,
        report.timestamp_ns.saturating_add(1),
        &report.trace_id,
    )
    .expect("sweep succeeds");
    assert_eq!(invalidations.len(), outcomes.len());
    assert!(invalidations.iter().all(|o| o.outcome == "invalidated"));
    let log = index
        .query_invalidations(None, None, &report.trace_id)
        .expect("invalidation log readable");
    assert_eq!(log.len(), outcomes.len());
    assert!(log.iter().all(|e| e.fallback_confirmed));
}

/// ACCEPTANCE (bd-fqlfw.9.2, shadow invariant): the equivalence lane is a
/// pure post-hoc pass — running validation and persistence between two
/// executions changes nothing about execution values, tick counts, or the
/// byte-level nondeterminism trace.
#[test]
fn equivalence_lane_changes_nothing_about_execution_or_replay() {
    let plain = execute_baseline();

    let with_lane = {
        let first = execute_baseline();
        let discovery = discover(&first);
        let baseline_facts = DifferentialRunFacts::from_result(&first).expect("baseline facts");
        let report = validate_candidates(
            &discovery,
            &baseline_facts,
            &baseline_facts,
            &EquivalenceLaneConfig::default(),
        )
        .expect("lane validates");
        let mut index = SpecializationIndex::new(InMemoryStorageAdapter::new(), "policy-e9-t2");
        persist_equivalence_chain(&mut index, &report).expect("persists");
        execute_baseline()
    };

    assert_eq!(plain.execution_value, with_lane.execution_value);
    assert_eq!(plain.instructions_executed, with_lane.instructions_executed);
    let plain_trace = serde_json::to_vec(&plain.nondeterminism_trace).expect("trace serializes");
    let lane_trace = serde_json::to_vec(&with_lane.nondeterminism_trace).expect("trace serializes");
    assert_eq!(
        plain_trace, lane_trace,
        "replay identity must be untouched by the equivalence lane"
    );
}
