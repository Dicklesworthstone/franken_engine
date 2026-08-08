//! Integration tests for E9.T3 replay-identity rules + safe-mode kill
//! switch (bd-fqlfw.9.3): the replay identity of a REAL run binds the trace
//! content to the execution lane and its specialization receipt hashes;
//! strict replay either reproduces the same specialization or forces
//! baseline with output-equivalence verification (never silently a
//! different path); safe mode provably disables ALL specializations; and
//! the rules are pure read-only over existing traces.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use frankenengine_engine::deterministic_replay::{
    BaselineForcedReason, NondeterminismTrace, ReplayEngine, ReplayLaneOutcome, ReplayMode,
    SpecializationKillSwitch, SpecializationLaneRecord, compute_replay_identity,
    enforce_strict_replay_lane, resolve_execution_lane,
};
use frankenengine_engine::e9_equivalence_receipts::{
    DifferentialRunFacts, EquivalenceLaneConfig, persist_equivalence_chain, shadow_lane_record,
    validate_candidates,
};
use frankenengine_engine::e9_shadow_candidate_discovery::{
    BaselineRunFacts, ShadowDiscoveryPolicy, ShadowDiscoveryReport, discover_candidates,
};
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig, OrchestratorResult,
};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};
use frankenengine_engine::specialization_index::SpecializationIndex;
use frankenengine_engine::storage_adapter::InMemoryStorageAdapter;

const HOT_LOOP_SOURCE: &str = "let total = 0;\n\
     for (let i = 0; i < 100; i = i + 1) {\n\
       total = total + i * 2;\n\
     }\n\
     total;";

const EXTENSION_ID: &str = "ext-e9-replay-identity";

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

fn discover(result: &OrchestratorResult) -> ShadowDiscoveryReport {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse_with_options(
            HOT_LOOP_SOURCE,
            frankenengine_engine::ast::ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("source parses");
    let ir0 = frankenengine_engine::ir_contract::Ir0Module::from_syntax_tree(
        tree,
        "fixtures/e9_hot_loop.js",
    );
    let ctx = LoweringContext::new("trace-e9-lower", "decision-e9-lower", "policy-e9-lower");
    let ir3 = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering succeeds").ir3;
    let facts = BaselineRunFacts {
        trace_id: result.trace_id.clone(),
        decision_id: result.decision_id.clone(),
        extension_id: result.extension_id.clone(),
        policy_epoch: result.epoch.as_u64(),
        instructions_executed: result.instructions_executed,
    };
    let policy = ShadowDiscoveryPolicy {
        min_dominance_millionths: 0,
        ..ShadowDiscoveryPolicy::default()
    };
    discover_candidates(&ir3, &facts, &policy)
}

/// Chain receipt hashes from a REAL validated-and-persisted E9.T2 report.
fn real_chain_receipt_hashes(
    result: &OrchestratorResult,
    shadow: &OrchestratorResult,
) -> (ShadowDiscoveryReport, Vec<String>, u64, String) {
    let discovery = discover(result);
    let report = validate_candidates(
        &discovery,
        &DifferentialRunFacts::from_result(result).expect("baseline facts"),
        &DifferentialRunFacts::from_result(shadow).expect("shadow facts"),
        &EquivalenceLaneConfig::default(),
    )
    .expect("lane validates");
    let mut index = SpecializationIndex::new(InMemoryStorageAdapter::new(), "policy-e9-t3");
    let outcomes = persist_equivalence_chain(&mut index, &report).expect("persists");
    let hashes: Vec<String> = outcomes
        .iter()
        .map(|o| o.chain_receipt_id_hex.clone())
        .collect();
    (
        discovery,
        hashes,
        report.policy_epoch,
        report.ir3_content_hash_hex.clone(),
    )
}

/// ACCEPTANCE (bd-fqlfw.9.3): the replay identity of a REAL run includes the
/// specialization receipt hashes, is computable read-only over the run's
/// actual nondeterminism trace, and leaves that trace byte-identical.
#[test]
fn replay_identity_binds_real_trace_to_lane_and_receipts() {
    let result = execute_baseline();
    let shadow = execute_baseline();
    let (_discovery, receipt_hashes, epoch, ir3_hash) = real_chain_receipt_hashes(&result, &shadow);
    assert!(!receipt_hashes.is_empty());

    let trace = &result.nondeterminism_trace;
    let before = serde_json::to_vec(trace).expect("trace serializes");

    let baseline_lane = SpecializationLaneRecord::baseline(ir3_hash.clone(), epoch);
    let specialized_lane =
        SpecializationLaneRecord::specialized(ir3_hash, epoch, receipt_hashes.clone());

    let baseline_identity =
        compute_replay_identity(trace, &baseline_lane).expect("identity computes");
    let specialized_identity =
        compute_replay_identity(trace, &specialized_lane).expect("identity computes");

    // Same trace, different lane: the receipt hashes are part of the identity.
    assert_eq!(
        baseline_identity.trace_content_hash_hex,
        specialized_identity.trace_content_hash_hex
    );
    assert_ne!(
        baseline_identity.identity_hash_hex,
        specialized_identity.identity_hash_hex
    );

    // Deterministic across recomputation.
    let again = compute_replay_identity(trace, &baseline_lane).expect("identity computes");
    assert_eq!(baseline_identity, again);

    // Pure read-only: the real trace is untouched.
    let after = serde_json::to_vec(trace).expect("trace serializes");
    assert_eq!(
        before, after,
        "identity computation must not perturb the trace"
    );
}

/// ACCEPTANCE (bd-fqlfw.9.3): a replay with specialization on either
/// reproduces the SAME specialization (same receipts, same identity) or is
/// forced onto baseline — and a forced-baseline replay of a specialized run
/// demands output-equivalence verification, which the E9.T2 differential
/// machinery then proves against real runs.
#[test]
fn strict_replay_reproduces_same_specialization_or_forces_verified_baseline() {
    let result = execute_baseline();
    let shadow = execute_baseline();
    let (_discovery, receipt_hashes, epoch, ir3_hash) = real_chain_receipt_hashes(&result, &shadow);

    // A lane-aware trace recording a specialized run over the REAL receipts.
    let recorded_lane =
        SpecializationLaneRecord::specialized(ir3_hash.clone(), epoch, receipt_hashes.clone());
    let mut trace = NondeterminismTrace::new("e9-t3-specialized-run");
    trace.capture_specialization_lane(&recorded_lane, 1);
    trace.finalise(2);

    // Case 1: same lane, verified receipts -> the SAME specialization is
    // reproduced, and the lane event replays byte-identically under Strict.
    let outcome = enforce_strict_replay_lane(
        &trace,
        &recorded_lane,
        &SpecializationKillSwitch::disengaged(),
        epoch,
        &receipt_hashes,
    )
    .expect("lane rule evaluates");
    match &outcome {
        ReplayLaneOutcome::SameLaneReproduced { identity } => {
            assert_eq!(
                identity.lane_identity_hash_hex,
                recorded_lane.identity_hash_hex()
            );
        }
        other => panic!("expected SameLaneReproduced, got {other:?}"),
    }
    let mut engine = ReplayEngine::new(trace.clone(), ReplayMode::Strict);
    let replayed = engine
        .replay_next(
            frankenengine_engine::deterministic_replay::NondeterminismSource::LaneSelectionRandom,
            &recorded_lane.encode(),
        )
        .expect("byte-identical lane event replays strictly");
    assert_eq!(replayed, recorded_lane.encode());

    // Case 2: a receipt is no longer verified -> forced baseline, never a
    // silent different path, and output equivalence is REQUIRED.
    let partial: Vec<String> = receipt_hashes.iter().take(1).cloned().collect();
    let outcome = enforce_strict_replay_lane(
        &trace,
        &recorded_lane,
        &SpecializationKillSwitch::disengaged(),
        epoch,
        &partial,
    )
    .expect("lane rule evaluates");
    match outcome {
        ReplayLaneOutcome::ForcedBaseline {
            reason,
            requires_output_equivalence,
            ..
        } => {
            assert!(matches!(
                reason,
                BaselineForcedReason::MissingReceipt { .. }
            ));
            assert!(requires_output_equivalence);
        }
        other => panic!("expected ForcedBaseline, got {other:?}"),
    }

    // The demanded output-equivalence verification, done with real runs via
    // the E9.T2 differential machinery: baseline re-execution is
    // byte-equivalent to the recorded baseline behaviour.
    let baseline_facts = DifferentialRunFacts::from_result(&result).expect("baseline facts");
    let forced_baseline_facts = DifferentialRunFacts::from_result(&shadow).expect("rerun facts");
    assert_eq!(
        baseline_facts.execution_value_hash_hex,
        forced_baseline_facts.execution_value_hash_hex
    );
    assert_eq!(
        baseline_facts.instructions_executed,
        forced_baseline_facts.instructions_executed
    );
    assert_eq!(
        baseline_facts.nondeterminism_trace_hash_hex,
        forced_baseline_facts.nondeterminism_trace_hash_hex,
        "forced-baseline output equivalence verified from real runs"
    );
}

/// ACCEPTANCE (bd-fqlfw.9.3): safe mode provably disables ALL
/// specializations — even fully verified, epoch-current, real-receipt lanes
/// are forced onto baseline while the kill switch is engaged.
#[test]
fn safe_mode_disables_all_specializations() {
    let result = execute_baseline();
    let shadow = execute_baseline();
    let (_discovery, receipt_hashes, epoch, ir3_hash) = real_chain_receipt_hashes(&result, &shadow);
    let kill = SpecializationKillSwitch::engaged("e9-t3-acceptance-drill");

    let lanes = vec![
        SpecializationLaneRecord::specialized(ir3_hash.clone(), epoch, receipt_hashes.clone()),
        SpecializationLaneRecord::specialized(
            ir3_hash.clone(),
            epoch,
            receipt_hashes.iter().take(1).cloned().collect(),
        ),
        SpecializationLaneRecord::baseline(ir3_hash, epoch),
    ];
    for requested in &lanes {
        let (effective, reason) = resolve_execution_lane(&kill, requested, epoch, &receipt_hashes);
        assert!(effective.is_baseline(), "safe mode forces baseline");
        assert_eq!(reason, Some(BaselineForcedReason::SafeMode));
    }
}

/// ACCEPTANCE (bd-fqlfw.9.3): fail-closed lane resolution — missing proof,
/// stale epoch, and unknown proof state all fall back to baseline with a
/// typed reason; the shadow lane of a real E9.T2 report is baseline and
/// passes through untouched.
#[test]
fn unknown_missing_or_stale_proof_states_fall_back_to_baseline() {
    let result = execute_baseline();
    let shadow = execute_baseline();
    let discovery = discover(&result);
    let report = validate_candidates(
        &discovery,
        &DifferentialRunFacts::from_result(&result).expect("baseline facts"),
        &DifferentialRunFacts::from_result(&shadow).expect("shadow facts"),
        &EquivalenceLaneConfig::default(),
    )
    .expect("lane validates");
    let kill = SpecializationKillSwitch::disengaged();
    let epoch = report.policy_epoch;

    // The real shadow lane is baseline and passes through.
    let lane = shadow_lane_record(&report);
    assert!(lane.is_baseline(), "shadow v1 always executes baseline");
    let (effective, reason) = resolve_execution_lane(&kill, &lane, epoch, &[]);
    assert_eq!(effective, lane);
    assert!(reason.is_none());

    // Missing proof: receipts nobody verified.
    let unverified = SpecializationLaneRecord::specialized(
        report.ir3_content_hash_hex.clone(),
        epoch,
        vec!["deadbeef".to_string()],
    );
    let (effective, reason) = resolve_execution_lane(&kill, &unverified, epoch, &[]);
    assert!(effective.is_baseline());
    assert!(matches!(
        reason,
        Some(BaselineForcedReason::MissingReceipt { .. })
    ));

    // Stale epoch: proofs from a previous epoch never carry forward.
    let stale = SpecializationLaneRecord::specialized(
        report.ir3_content_hash_hex.clone(),
        epoch,
        vec!["deadbeef".to_string()],
    );
    let (effective, reason) =
        resolve_execution_lane(&kill, &stale, epoch + 1, &["deadbeef".to_string()]);
    assert!(effective.is_baseline());
    assert_eq!(
        reason,
        Some(BaselineForcedReason::StaleProofEpoch {
            lane_epoch: epoch,
            current_epoch: epoch + 1,
        })
    );

    // Unknown proof state: specialized lane with no receipts at all.
    let unknown = SpecializationLaneRecord::specialized(
        report.ir3_content_hash_hex.clone(),
        epoch,
        Vec::new(),
    );
    let (effective, reason) = resolve_execution_lane(&kill, &unknown, epoch, &[]);
    assert!(effective.is_baseline());
    assert!(matches!(
        reason,
        Some(BaselineForcedReason::UnknownProofState { .. })
    ));
}
