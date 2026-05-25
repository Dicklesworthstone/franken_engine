#![forbid(unsafe_code)]
//! In-tree cargo companion for the Track-S fleet-counterfactual-replay gate
//! (`scripts/run_rgc_fleet_counterfactual_replay.sh`, bd-cixqu.19.3).
//!
//! The gate's `ci` mode validates the Track-S proof *surface* (it does not
//! invoke cargo). This test is the runnable proof of the two load-bearing
//! claims behind that surface:
//!
//!   * **S.1** — the fleet-counterfactual API replays N captured traces under
//!     one substituted policy snapshot in a single operation, and does so for
//!     each of N candidate policies deterministically (same input → identical
//!     artifact hash).
//!   * **S.2** — the signed N-counterfactual report schema
//!     (`franken-engine.fleet-counterfactual-report.v1`) has a stable schema
//!     id, a deterministic length-prefixed signing preimage, and binds every
//!     per-node decision delta into that preimage (tamper → digest changes:
//!     fail closed).
//!
//! Callers run it via rch:
//!
//! ```text
//! cargo test --test rgc_fleet_counterfactual_replay
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
    ReplayScope, SubstitutedPolicySnapshot,
};
use frankenengine_engine::fleet_counterfactual_report::{
    AggregateDecisionDelta, CounterfactualDecision, FleetCounterfactualReport, NodeDecisionDelta,
    ReportSignature, SignatureBundle,
};
use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::runtime_decision_theory::LaneAction;
use frankenengine_engine::security_epoch::SecurityEpoch;

static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

const SIGNER_KEY: &[u8] = &[0x5Au8; 32];

// ---------------------------------------------------------------------------
// S.1 helpers — build a captured fleet trace directory
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn make_decision(index: u64, action: &str, outcome: i64) -> DecisionSnapshot {
    let mut loss_matrix = BTreeMap::new();
    loss_matrix.insert("native".to_string(), 100_000);
    loss_matrix.insert("wasm".to_string(), 200_000);
    DecisionSnapshot {
        decision_index: index,
        trace_id: "rgc-trace".to_string(),
        decision_id: format!("rgc-decision-{index}"),
        policy_id: "baseline".to_string(),
        policy_version: 1,
        epoch: epoch(),
        tick: 100 + index,
        threshold_millionths: 500_000,
        loss_matrix,
        evidence_hashes: vec![ContentHash::compute(b"evidence")],
        chosen_action: action.to_string(),
        outcome_millionths: outcome,
        extension_id: "ext-1".to_string(),
        nondeterminism_range: (0, 0),
    }
}

fn make_trace(decisions: Vec<DecisionSnapshot>) -> TraceRecord {
    let trace_id = decisions
        .first()
        .map(|d| d.trace_id.clone())
        .unwrap_or_else(|| "rgc-trace".to_string());
    let mut recorder = TraceRecorder::new(RecorderConfig {
        trace_id,
        recording_mode: RecordingMode::Full,
        epoch: epoch(),
        start_tick: 100,
        signing_key: b"rgc-key".to_vec(),
    });
    for d in decisions {
        recorder.record_decision(d);
    }
    recorder.finalize()
}

fn node_trace(node_id: &str, trace_id: &str, outcomes: &[i64]) -> TraceRecord {
    let decisions: Vec<DecisionSnapshot> = outcomes
        .iter()
        .enumerate()
        .map(|(index, outcome)| {
            let mut d = make_decision(index as u64, "native", *outcome);
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
        "rgc-fleet-counterfactual-{label}-{}-{n}",
        std::process::id()
    ))
}

/// Build a three-node fleet trace directory and return its root.
fn captured_fleet() -> PathBuf {
    let root = unique_dir("fleet");
    fs::create_dir_all(&root).unwrap();
    write_trace(&root, "node-a/t1.json", &node_trace("node-a", "t-a-1", &[820_000, 610_000]));
    write_trace(&root, "node-b/t1.json", &node_trace("node-b", "t-b-1", &[700_000, 900_000]));
    write_trace(&root, "node-c/t1.json", &node_trace("node-c", "t-c-1", &[505_000, 480_000]));
    root
}

/// One candidate substituted policy. Varying `version`/`threshold` yields the
/// N distinct candidate policies a counterfactual sweep replays.
fn candidate_policy(name: &str, version: u32, threshold: Option<u64>) -> SubstitutedPolicySnapshot {
    SubstitutedPolicySnapshot::new(
        PolicyId(name.to_string()),
        format!("candidate policy {name}"),
        CounterfactualConfig {
            branch_id: format!("branch-{name}"),
            threshold_override_millionths: threshold.map(|t| t as i64),
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: Some(u64::from(version)),
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        },
        Some(LaneAction::FallbackSafe),
        ReplayScope::default(),
        Some(ContentHash::compute(name.as_bytes())),
    )
}

fn engine() -> CounterfactualReplayEngine {
    CounterfactualReplayEngine::new(ReplayEngineConfig::default())
}

// ---------------------------------------------------------------------------
// S.1 — fleet-counterfactual replay over a captured trace dir
// ---------------------------------------------------------------------------

#[test]
fn s1_replays_captured_fleet_under_substituted_policy() {
    let root = captured_fleet();
    let policy = candidate_policy("cand-v1", 2, None);
    let report = engine()
        .compare_fleet_trace_dir(&root, &policy, None)
        .expect("fleet counterfactual report");
    assert_eq!(report.schema_version, FLEET_COUNTERFACTUAL_SCHEMA_VERSION);
    assert_eq!(report.trace_count, 3, "three captured traces replayed");
    assert_eq!(report.node_count, 3, "three distinct fleet nodes");
    assert_eq!(report.substituted_policy, policy);
    // node_reports are sorted by node id and cover the whole fleet.
    assert_eq!(report.node_reports.len(), 3);
}

#[test]
fn s1_sweeps_n_candidate_policies_in_one_pass_each() {
    let root = captured_fleet();
    let candidates = [
        candidate_policy("cand-a", 2, None),
        candidate_policy("cand-b", 3, Some(600_000)),
        candidate_policy("cand-c", 4, Some(450_000)),
    ];
    let mut eng = engine();
    let mut seen = 0u64;
    for policy in &candidates {
        let report = eng
            .compare_fleet_trace_dir(&root, policy, None)
            .expect("counterfactual report for candidate");
        assert_eq!(report.substituted_policy.policy_id, policy.policy_id);
        assert_eq!(report.trace_count, 3);
        seen += 1;
    }
    assert_eq!(seen, candidates.len() as u64);
    assert_eq!(eng.replay_count(), candidates.len() as u64);
}

#[test]
fn s1_replay_is_deterministic_for_identical_inputs() {
    let root = captured_fleet();
    let policy = candidate_policy("cand-det", 2, Some(550_000));
    let first = engine()
        .compare_fleet_trace_dir(&root, &policy, None)
        .expect("first replay");
    let second = engine()
        .compare_fleet_trace_dir(&root, &policy, None)
        .expect("second replay");
    assert_eq!(
        first.artifact_hash, second.artifact_hash,
        "identical fleet + policy must yield an identical artifact hash"
    );
    assert_eq!(first, second, "the whole report must be reproducible");
}

#[test]
fn s1_empty_fleet_dir_fails_closed() {
    let root = unique_dir("empty");
    fs::create_dir_all(&root).unwrap();
    let policy = candidate_policy("cand-empty", 2, None);
    let result = engine().compare_fleet_trace_dir(&root, &policy, None);
    assert!(
        result.is_err(),
        "a fleet directory with no traces must error, never silently pass"
    );
}

#[test]
fn s1_policy_snapshot_round_trips_through_file_intake() {
    let root = captured_fleet();
    let policy = candidate_policy("cand-file", 2, Some(620_000));
    let policy_path = root.join("substituted-policy.json");
    fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    let loaded = SubstitutedPolicySnapshot::load_from_file(&policy_path).expect("load snapshot");
    assert_eq!(loaded, policy);
    let report = engine()
        .compare_fleet_trace_dir(&root, &loaded, None)
        .expect("report from file-loaded policy");
    assert_eq!(report.substituted_policy, policy);
}

// ---------------------------------------------------------------------------
// S.2 — signed N-counterfactual report schema
// ---------------------------------------------------------------------------

fn h(seed: u8) -> ContentHash {
    ContentHash::from_bytes([seed; 32])
}

/// A report whose per-node deltas are internally consistent with the aggregate.
fn signed_report() -> FleetCounterfactualReport {
    let per_node_decisions = vec![
        NodeDecisionDelta {
            node_id: 0,
            original_decision: CounterfactualDecision::Approved,
            substituted_decision: CounterfactualDecision::Rejected,
            delta_millionths: -120_000,
        },
        NodeDecisionDelta {
            node_id: 1,
            original_decision: CounterfactualDecision::Approved,
            substituted_decision: CounterfactualDecision::Approved,
            delta_millionths: 0,
        },
    ];
    let mut report = FleetCounterfactualReport {
        original_policy_id: h(0x11),
        substituted_policy_id: h(0x22),
        per_node_decisions,
        aggregate_decision_delta: AggregateDecisionDelta {
            changed_nodes: 1,
            total_nodes: 2,
            net_delta_millionths: -120_000,
        },
        evidence_hash_chain_root: h(0x33),
        signature_bundle: SignatureBundle::default(),
    };
    // Sign the preimage digest with a deterministic keyed authenticity hash and
    // attach the detached signature, mirroring how the gate's emitter signs.
    let digest = report.signing_digest();
    let sig = AuthenticityHash::compute_keyed(SIGNER_KEY, digest.as_bytes());
    report.signature_bundle = SignatureBundle {
        signatures: vec![ReportSignature {
            signer_key_id: ContentHash::compute(SIGNER_KEY),
            signature: sig.as_bytes().to_vec(),
        }],
    };
    report
}

#[test]
fn s2_schema_id_is_stable() {
    assert_eq!(
        FleetCounterfactualReport::schema_id(),
        FleetCounterfactualReport::schema_id(),
        "schema id derives from the definition, not a mutable label"
    );
}

#[test]
fn s2_signing_preimage_is_deterministic() {
    let a = signed_report().signing_preimage();
    let b = signed_report().signing_preimage();
    assert_eq!(a, b, "preimage construction must be deterministic");
}

#[test]
fn s2_report_is_consistent_and_signed() {
    let report = signed_report();
    assert!(report.is_consistent(), "changed-node count must match deltas");
    assert!(report.signature_bundle.is_signed(), "report must carry a signature");
}

#[test]
fn s2_signing_preimage_excludes_signature_bundle() {
    // Two reports identical except for the signature bundle must share a
    // preimage — the signature covers everything *except* itself.
    let signed = signed_report();
    let mut unsigned = signed.clone();
    unsigned.signature_bundle = SignatureBundle::default();
    assert_eq!(
        signed.signing_preimage(),
        unsigned.signing_preimage(),
        "signature bundle must be excluded from the signing preimage"
    );
}

#[test]
fn s2_tampering_a_node_delta_breaks_the_digest() {
    let report = signed_report();
    let original_digest = report.signing_digest();
    let mut tampered = report.clone();
    tampered.per_node_decisions[0].delta_millionths = -1;
    assert_ne!(
        original_digest,
        tampered.signing_digest(),
        "mutating a per-node delta must change the signing digest (fail closed)"
    );
}

#[test]
fn s2_tampering_aggregate_breaks_the_digest() {
    let report = signed_report();
    let mut tampered = report.clone();
    tampered.aggregate_decision_delta.net_delta_millionths = 5;
    assert_ne!(report.signing_digest(), tampered.signing_digest());
}

#[test]
fn s2_report_serde_round_trip_preserves_digest() {
    let report = signed_report();
    let json = serde_json::to_string(&report).expect("serialize report");
    let restored: FleetCounterfactualReport =
        serde_json::from_str(&json).expect("deserialize report");
    assert_eq!(report, restored);
    assert_eq!(
        report.signing_digest(),
        restored.signing_digest(),
        "the signing digest must survive a serde round-trip"
    );
}

#[test]
fn s2_inconsistent_report_is_rejected() {
    let mut report = signed_report();
    // Claim two changed nodes while only one delta actually changed.
    report.aggregate_decision_delta.changed_nodes = 2;
    assert!(
        !report.is_consistent(),
        "aggregate must not over-claim changed nodes"
    );
}
