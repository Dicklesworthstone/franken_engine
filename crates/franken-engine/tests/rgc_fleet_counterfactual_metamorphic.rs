#![forbid(unsafe_code)]
//! Track-S S.4 — metamorphic substitution test (bd-cixqu.19.4).
//!
//! Critical correctness property for the fleet-counterfactual replay surface:
//!
//!   **counterfactual(trace, policy_original) === original_outcome**
//!
//! The fleet-counterfactual engine answers "what would the fleet have decided
//! under policy X?" by re-evaluating every captured decision under a
//! substituted policy snapshot. The load-bearing metamorphic relation is the
//! *identity*: if the substituted policy is the **original** policy (no
//! threshold/loss/containment/default-action overrides), the re-evaluation must
//! reproduce, exactly, the outcomes that were recorded in the trace. Any
//! deviation would mean the counterfactual machinery silently mutates the
//! ground truth it is supposed to hold fixed — a fail-closed correctness bug.
//!
//! This is a mechanical metamorphic test that runs as part of the Track-S
//! fleet-counterfactual-replay gate
//! (`scripts/run_rgc_fleet_counterfactual_replay.sh`). It is the runnable proof
//! of S.4 and complements the S.3 companion
//! (`rgc_fleet_counterfactual_replay.rs`).
//!
//! ## Why the recorded outcomes are not hand-picked numbers
//!
//! The load-bearing risk for this kind of metamorphic test is that the
//! recorded `outcome_millionths` are author-chosen magic numbers: then the
//! identity relation degenerates into "the engine echoes whatever integer I
//! wrote into the trace" and proves nothing about the real decision model.
//!
//! To give the relations teeth, every recorded decision's `outcome_millionths`
//! is produced by the engine's **real** outcome model
//! ([`estimate_lane_outcome_millionths`]) applied to that decision's
//! action/loss-matrix/threshold — the exact function
//! `CounterfactualReplayEngine::compute_counterfactual` uses to score
//! substituted actions. The ground-truth totals below are recomputed
//! independently through that same model (not read back from the report), and
//! the perturbation relation asserts the *exact* re-scored outcome, not merely
//! that "the number changed".
//!
//! Metamorphic relations exercised:
//!
//!   * **MR-identity** — substituting the original policy reproduces the
//!     recorded outcome for the whole fleet and for every node, with zero
//!     divergence and zero net improvement.
//!   * **MR-ground-truth** — the reproduced total equals the model-computed
//!     outcome of every captured decision (recomputed independently in-test
//!     through the real outcome model, not merely self-consistent).
//!   * **MR-round-trip** — a genuinely perturbing policy moves every decision's
//!     outcome to the exact value the real model assigns the forced action
//!     (the engine is not a no-op), yet substituting the original policy back
//!     recovers the recorded outcome exactly.
//!   * **MR-reeval-branch** — identity holds even when the re-evaluation
//!     branch is active (recorded max-loss exceeds the threshold), because the
//!     threshold delta is zero.
//!   * **MR-determinism** — identity substitution is reproducible: same input
//!     yields an identical artifact hash.
//!
//! Run via rch:
//!
//! ```text
//! cargo test --test rgc_fleet_counterfactual_metamorphic
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use frankenengine_engine::causal_replay::{
    CounterfactualConfig, DecisionSnapshot, RecorderConfig, RecordingMode, TraceRecord,
    TraceRecorder,
};
use frankenengine_engine::counterfactual_evaluator::PolicyId;
use frankenengine_engine::counterfactual_replay_engine::{
    CounterfactualReplayEngine, FLEET_COUNTERFACTUAL_SCHEMA_VERSION, ReplayEngineConfig,
    ReplayScope, SubstitutedPolicySnapshot, estimate_lane_outcome_millionths,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::runtime_decision_theory::LaneAction;
use frankenengine_engine::security_epoch::SecurityEpoch;

static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Trace construction — captured fleet with known recorded outcomes
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

/// The action recorded as "chosen" for every decision in the fleet.
const CHOSEN_ACTION: &str = "native";

/// Build the per-decision loss matrix from a recorded native-lane loss. The
/// wasm lane is twice as costly, so the chosen `native` action is the
/// loss-minimizing one and the matrix's max-loss is `2 * native_loss`.
fn loss_matrix_for(native_loss: i64) -> BTreeMap<String, i64> {
    let mut loss_matrix = BTreeMap::new();
    loss_matrix.insert("native".to_string(), native_loss);
    loss_matrix.insert("wasm".to_string(), native_loss * 2);
    loss_matrix
}

/// The recorded outcome of a decision, produced by the engine's **real**
/// outcome model — not a hand-picked number. This is the same function the
/// replay engine uses to score substituted actions, so the trace encodes a
/// model-consistent ground truth rather than an arbitrary integer.
fn recorded_outcome(native_loss: i64, threshold: i64) -> i64 {
    estimate_lane_outcome_millionths(CHOSEN_ACTION, &loss_matrix_for(native_loss), threshold)
}

/// A recorded decision whose `outcome_millionths` is derived from the real
/// outcome model applied to its `native_loss`/`threshold`. A larger
/// `native_loss` (e.g. when `2 * native_loss` exceeds `threshold`) drives the
/// node onto the re-evaluation branch of the engine under identity
/// substitution.
fn make_decision(index: u64, native_loss: i64, threshold: u64) -> DecisionSnapshot {
    let loss_matrix = loss_matrix_for(native_loss);
    let outcome = estimate_lane_outcome_millionths(CHOSEN_ACTION, &loss_matrix, threshold as i64);
    DecisionSnapshot {
        decision_index: index,
        trace_id: "metamorphic-trace".to_string(),
        decision_id: format!("metamorphic-decision-{index}"),
        policy_id: "baseline".to_string(),
        policy_version: 1,
        epoch: epoch(),
        tick: 100 + index,
        threshold_millionths: threshold as i64,
        loss_matrix,
        evidence_hashes: vec![ContentHash::compute(b"evidence")],
        chosen_action: CHOSEN_ACTION.to_string(),
        outcome_millionths: outcome,
        extension_id: "ext-1".to_string(),
        nondeterminism_range: (0, 0),
    }
}

fn make_trace(decisions: Vec<DecisionSnapshot>) -> TraceRecord {
    let trace_id = decisions
        .first()
        .map(|d| d.trace_id.clone())
        .unwrap_or_else(|| "metamorphic-trace".to_string());
    let mut recorder = TraceRecorder::new(RecorderConfig {
        trace_id,
        recording_mode: RecordingMode::Full,
        epoch: epoch(),
        start_tick: 100,
        signing_key: b"metamorphic-key".to_vec(),
    });
    for d in decisions {
        recorder.record_decision(d);
    }
    recorder.finalize()
}

/// Build a node trace whose decisions encode the model outcomes for the given
/// per-decision `native_losses` under `threshold`.
fn node_trace(node_id: &str, trace_id: &str, native_losses: &[i64], threshold: u64) -> TraceRecord {
    let decisions: Vec<DecisionSnapshot> = native_losses
        .iter()
        .enumerate()
        .map(|(index, native_loss)| {
            let mut d = make_decision(index as u64, *native_loss, threshold);
            d.trace_id = trace_id.to_string();
            d.decision_id = format!("{trace_id}-decision-{index}");
            d
        })
        .collect();
    let mut trace = make_trace(decisions);
    trace
        .metadata
        .insert("node_id".to_string(), node_id.to_string());
    trace
}

fn write_trace(root: &Path, relative: &str, trace: &TraceRecord) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&path, serde_json::to_vec(trace).unwrap()).unwrap();
}

fn unique_dir(label: &str) -> PathBuf {
    let n = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "rgc-fleet-metamorphic-{label}-{}-{n}",
        std::process::id()
    ))
}

/// Per-node recorded native-lane losses for the standard fleet. With
/// `RECORDED_THRESHOLD` = 500_000, every node's max-loss (`2 * native_loss`)
/// stays at or below the threshold, so the "else" branch of the engine returns
/// the recorded (model-derived) outcome verbatim under identity. The losses are
/// distinct so the per-decision model outcomes — and therefore the sums — are
/// distinct rather than degenerate.
const NODE_A: &[i64] = &[100_000, 150_000];
const NODE_B: &[i64] = &[120_000, 90_000];
const NODE_C: &[i64] = &[200_000, 60_000];
const RECORDED_THRESHOLD: u64 = 500_000;

/// Every recorded native loss across the standard fleet, in trace order.
fn fleet_native_losses() -> Vec<i64> {
    NODE_A.iter().chain(NODE_B).chain(NODE_C).copied().collect()
}

/// The exact fleet outcome the **real model** assigns the recorded decisions.
/// Recomputed independently in-test (not read back from the report), so the
/// identity relation proves the engine reproduces a genuine model output, not
/// an echoed magic number.
fn recorded_fleet_total() -> i64 {
    fleet_native_losses()
        .iter()
        .map(|&loss| recorded_outcome(loss, RECORDED_THRESHOLD as i64))
        .sum()
}

/// The exact fleet outcome the real model assigns when every decision is forced
/// onto the safe fallback action (the perturbing policy below). Because
/// `fallback_safe` is absent from the loss matrix, the model scores it at the
/// zero-loss ceiling, so this differs from `recorded_fleet_total()` whenever
/// the chosen action carried any loss.
fn perturbed_fleet_total() -> i64 {
    let forced = LaneAction::FallbackSafe.to_string();
    fleet_native_losses()
        .iter()
        .map(|&loss| {
            estimate_lane_outcome_millionths(
                &forced,
                &loss_matrix_for(loss),
                RECORDED_THRESHOLD as i64,
            )
        })
        .sum()
}

/// Build a three-node fleet trace directory and return its root.
fn captured_fleet() -> PathBuf {
    let root = unique_dir("fleet");
    fs::create_dir_all(&root).unwrap();
    write_trace(
        &root,
        "node-a/t1.json",
        &node_trace("node-a", "t-a-1", NODE_A, RECORDED_THRESHOLD),
    );
    write_trace(
        &root,
        "node-b/t1.json",
        &node_trace("node-b", "t-b-1", NODE_B, RECORDED_THRESHOLD),
    );
    write_trace(
        &root,
        "node-c/t1.json",
        &node_trace("node-c", "t-c-1", NODE_C, RECORDED_THRESHOLD),
    );
    root
}

// ---------------------------------------------------------------------------
// Policy snapshots
// ---------------------------------------------------------------------------

/// The **original** policy expressed as a substituted snapshot: no overrides of
/// any kind. Replaying the fleet under this snapshot must reproduce the trace's
/// recorded outcomes exactly. `policy_version_override` records the original
/// policy version for provenance; it does not influence outcome computation.
fn original_policy_snapshot() -> SubstitutedPolicySnapshot {
    SubstitutedPolicySnapshot::new(
        PolicyId("baseline".to_string()),
        "original policy (identity substitution)".to_string(),
        CounterfactualConfig {
            branch_id: "identity".to_string(),
            threshold_override_millionths: None,
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: Some(1),
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        },
        None,
        ReplayScope::default(),
        Some(ContentHash::compute(b"baseline")),
    )
}

/// The original policy, but pinning the threshold explicitly to the recorded
/// value. Because the threshold delta is zero, this is still the identity and
/// must reproduce the original outcome.
fn original_policy_explicit_threshold() -> SubstitutedPolicySnapshot {
    let mut snapshot = original_policy_snapshot();
    snapshot.counterfactual_config.threshold_override_millionths = Some(RECORDED_THRESHOLD as i64);
    snapshot.description = "original policy (explicit equal threshold)".to_string();
    snapshot
}

/// A genuinely perturbing policy: forces every decision onto a different action
/// via a default-action override. The engine must register divergence and a
/// changed outcome — proving the identity result is non-trivial.
fn perturbing_policy_snapshot() -> SubstitutedPolicySnapshot {
    SubstitutedPolicySnapshot::new(
        PolicyId("perturbed".to_string()),
        "perturbing policy (forced fallback)".to_string(),
        CounterfactualConfig {
            branch_id: "perturb".to_string(),
            threshold_override_millionths: None,
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: Some(2),
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        },
        Some(LaneAction::FallbackSafe),
        ReplayScope::default(),
        Some(ContentHash::compute(b"perturbed")),
    )
}

fn engine() -> CounterfactualReplayEngine {
    CounterfactualReplayEngine::new(ReplayEngineConfig::default())
}

// ---------------------------------------------------------------------------
// MR-identity — substituting the original policy reproduces the outcome
// ---------------------------------------------------------------------------

#[test]
fn mr_identity_reproduces_original_outcome_for_the_fleet() {
    let root = captured_fleet();
    let report = engine()
        .compare_fleet_trace_dir(&root, &original_policy_snapshot(), None)
        .expect("fleet counterfactual report under original policy");

    assert_eq!(report.schema_version, FLEET_COUNTERFACTUAL_SCHEMA_VERSION);
    assert_eq!(report.trace_count, 3);
    assert_eq!(report.node_count, 3);

    // The metamorphic relation: identity substitution reproduces the outcome.
    assert_eq!(
        report.total_counterfactual_outcome_millionths, report.total_original_outcome_millionths,
        "identity substitution must reproduce the recorded fleet outcome"
    );
    assert_eq!(
        report.net_improvement_millionths, 0,
        "identity substitution must yield zero net improvement"
    );
    assert_eq!(
        report.total_divergences, 0,
        "identity substitution must not diverge from any recorded decision"
    );
}

#[test]
fn mr_identity_reproduces_original_outcome_per_node() {
    let root = captured_fleet();
    let report = engine()
        .compare_fleet_trace_dir(&root, &original_policy_snapshot(), None)
        .expect("fleet counterfactual report under original policy");

    assert_eq!(report.node_reports.len(), 3);
    for node in &report.node_reports {
        assert_eq!(
            node.total_counterfactual_outcome_millionths, node.total_original_outcome_millionths,
            "node {} must reproduce its recorded outcome under identity",
            node.node_id
        );
        assert_eq!(
            node.net_improvement_millionths, 0,
            "node {} must show zero net improvement under identity",
            node.node_id
        );
        assert_eq!(
            node.divergence_count, 0,
            "node {} must show zero divergences under identity",
            node.node_id
        );
        assert!(
            node.divergent_decisions.is_empty(),
            "node {} must record no divergent decisions under identity",
            node.node_id
        );
    }
}

#[test]
fn mr_identity_equals_trace_encoded_ground_truth() {
    let root = captured_fleet();
    let report = engine()
        .compare_fleet_trace_dir(&root, &original_policy_snapshot(), None)
        .expect("fleet counterfactual report under original policy");

    let expected = recorded_fleet_total();
    // Not merely self-consistent: the reproduced total equals the exact sum of
    // the model-derived outcomes written into the captured traces. `expected`
    // is recomputed independently in-test through the real outcome model, so a
    // regression that mutated the carried-through outcome would be caught.
    assert_eq!(
        report.total_original_outcome_millionths, expected,
        "the recorded fleet total must match the model-derived ground truth"
    );
    assert_eq!(
        report.total_counterfactual_outcome_millionths, expected,
        "identity substitution must reproduce the model-derived ground truth"
    );

    // The ground truth is a genuine, action-sensitive model output rather than
    // a degenerate constant: the chosen action carries real loss, so it scores
    // strictly below the zero-loss fallback ceiling. A model that ignored loss
    // (returned a constant) would collapse these two totals and fail here.
    assert!(
        expected < perturbed_fleet_total(),
        "the chosen action must score below the zero-loss fallback ceiling \
         (recorded={expected}, fallback-ceiling={})",
        perturbed_fleet_total()
    );
}

#[test]
fn mr_identity_records_no_divergent_decisions_in_aggregate() {
    let root = captured_fleet();
    let report = engine()
        .compare_fleet_trace_dir(&root, &original_policy_snapshot(), None)
        .expect("fleet counterfactual report under original policy");

    let policy_report = report
        .aggregate_result
        .policy_reports
        .first()
        .expect("aggregate policy report");
    assert_eq!(policy_report.divergence_count, 0);
    assert!(
        policy_report.divergent_decisions.is_empty(),
        "no divergent decision may be recorded under identity substitution"
    );
    // Every per-decision regime delta must be zero under identity.
    for delta in policy_report.regime_breakdown.values() {
        assert_eq!(
            *delta, 0,
            "per-regime improvement must be zero under identity"
        );
    }
}

#[test]
fn mr_identity_with_explicit_equal_threshold_reproduces_outcome() {
    let root = captured_fleet();
    let report = engine()
        .compare_fleet_trace_dir(&root, &original_policy_explicit_threshold(), None)
        .expect("fleet report under explicit-equal-threshold original policy");

    // Pinning the threshold to its recorded value is still the identity: the
    // threshold delta is zero, so the reproduced outcome is unchanged.
    assert_eq!(
        report.total_counterfactual_outcome_millionths,
        recorded_fleet_total(),
        "explicit equal-threshold substitution must reproduce the outcome"
    );
    assert_eq!(report.net_improvement_millionths, 0);
    assert_eq!(report.total_divergences, 0);
}

// ---------------------------------------------------------------------------
// MR-reeval-branch — identity holds even when re-evaluation branch is active
// ---------------------------------------------------------------------------

#[test]
fn mr_identity_holds_when_reeval_branch_is_active() {
    // Record a node whose max-loss (2 * native_loss) exceeds the threshold
    // (50_000), so the engine takes the re-evaluation branch rather than the
    // verbatim branch. Under identity the threshold delta is still zero, so the
    // outcome must be reproduced exactly.
    let root = unique_dir("reeval");
    fs::create_dir_all(&root).unwrap();
    let native_losses = [40_000_i64, 35_000];
    let reeval_threshold = 50_000_u64;
    write_trace(
        &root,
        "node-low/t1.json",
        &node_trace("node-low", "t-low-1", &native_losses, reeval_threshold),
    );

    let report = engine()
        .compare_fleet_trace_dir(&root, &original_policy_snapshot(), None)
        .expect("fleet report for low-threshold node");

    let expected: i64 = native_losses
        .iter()
        .map(|&loss| recorded_outcome(loss, reeval_threshold as i64))
        .sum();
    assert_eq!(
        report.total_original_outcome_millionths, expected,
        "recorded outcome ground truth"
    );
    assert_eq!(
        report.total_counterfactual_outcome_millionths, expected,
        "identity must reproduce the outcome even on the re-evaluation branch"
    );
    assert_eq!(report.net_improvement_millionths, 0);
    assert_eq!(report.total_divergences, 0);
}

// ---------------------------------------------------------------------------
// MR-round-trip — perturb (engine moves) then restore (identity recovers)
// ---------------------------------------------------------------------------

#[test]
fn mr_perturbing_policy_actually_moves_the_outcome() {
    let root = captured_fleet();
    let report = engine()
        .compare_fleet_trace_dir(&root, &perturbing_policy_snapshot(), None)
        .expect("fleet report under perturbing policy");

    // Sanity for the round-trip: the engine is *not* a no-op. A forced
    // action override must diverge on every decision and change the outcome.
    assert!(
        report.total_divergences > 0,
        "a perturbing policy must diverge from the recorded decisions"
    );
    assert_eq!(
        report.total_divergences, report.total_decisions,
        "the forced override diverges on every recorded decision"
    );
    assert_ne!(
        report.total_counterfactual_outcome_millionths, report.total_original_outcome_millionths,
        "a perturbing policy must move the outcome away from the recorded one"
    );

    // Teeth: the perturbed outcome is not merely "different" — it is exactly the
    // value the real outcome model assigns when every decision is re-scored on
    // the forced fallback action. This proves the engine re-runs the genuine
    // model on the substituted action rather than fabricating a delta.
    assert_eq!(
        report.total_counterfactual_outcome_millionths,
        perturbed_fleet_total(),
        "the perturbed total must equal the real model's score for the forced action"
    );
    assert_eq!(
        report.total_original_outcome_millionths,
        recorded_fleet_total(),
        "the recorded column must remain the trace-encoded model ground truth"
    );
}

#[test]
fn mr_round_trip_perturb_then_restore_recovers_original_outcome() {
    let root = captured_fleet();

    // Step 1: perturb. Establish that the recorded outcome and the perturbed
    // outcome genuinely differ.
    let perturbed = engine()
        .compare_fleet_trace_dir(&root, &perturbing_policy_snapshot(), None)
        .expect("perturbed report");
    assert_ne!(
        perturbed.total_counterfactual_outcome_millionths,
        perturbed.total_original_outcome_millionths
    );

    // Step 2: restore the original policy. The counterfactual must collapse
    // back onto the recorded outcome — the metamorphic round-trip.
    let restored = engine()
        .compare_fleet_trace_dir(&root, &original_policy_snapshot(), None)
        .expect("restored report");
    assert_eq!(
        restored.total_counterfactual_outcome_millionths,
        restored.total_original_outcome_millionths,
        "restoring the original policy must recover the recorded outcome"
    );
    assert_eq!(
        restored.total_counterfactual_outcome_millionths,
        recorded_fleet_total(),
        "the recovered outcome must equal the trace-encoded ground truth"
    );
    assert_eq!(restored.total_divergences, 0);
    // The original-outcome column is invariant to which policy was substituted:
    // it is ground truth, read from the trace, not recomputed.
    assert_eq!(
        perturbed.total_original_outcome_millionths, restored.total_original_outcome_millionths,
        "the recorded-outcome column must be policy-invariant"
    );
}

// ---------------------------------------------------------------------------
// MR-determinism — identity substitution is reproducible
// ---------------------------------------------------------------------------

#[test]
fn mr_identity_substitution_is_deterministic() {
    let root = captured_fleet();
    let first = engine()
        .compare_fleet_trace_dir(&root, &original_policy_snapshot(), None)
        .expect("first identity replay");
    let second = engine()
        .compare_fleet_trace_dir(&root, &original_policy_snapshot(), None)
        .expect("second identity replay");
    assert_eq!(
        first.artifact_hash, second.artifact_hash,
        "identity substitution must be deterministic (identical artifact hash)"
    );
    assert_eq!(
        first, second,
        "the whole identity report must be reproducible"
    );
}
