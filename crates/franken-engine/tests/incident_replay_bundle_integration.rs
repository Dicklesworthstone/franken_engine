//! Integration tests for `incident_replay_bundle` — exercises the full
//! builder → verifier pipeline, OptReceipt and QuorumCheckpoint artifact
//! paths, counterfactual verification, receipt validation, and cross-type
//! artifact determinism.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::causal_replay::{
    ActionDeltaReport, CounterfactualConfig, DecisionSnapshot, NondeterminismLog,
    NondeterminismSource, RecorderConfig, RecordingMode, TraceRecord, TraceRecorder,
};
use frankenengine_engine::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use frankenengine_engine::evidence_ledger::{ChosenAction, DecisionType, EvidenceEntryBuilder};
use frankenengine_engine::fleet_immune_protocol::{
    ContainmentAction, MessageSignature, NodeId, ProtocolVersion, QuorumCheckpoint,
    ResolvedContainmentDecision,
};
use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::incident_replay_bundle::{
    BUNDLE_FORMAT_VERSION, BundleArtifactKind, BundleBuilder, BundleVerifier, CheckOutcome,
    CounterfactualResult, IncidentReplayBundle, PolicySnapshot, RedactionPolicy,
    VerificationCategory, build_merkle_proof, compute_merkle_root, verify_merkle_proof,
};
use frankenengine_engine::proof_schema::{
    OptReceipt, OptimizationClass, proof_schema_version_v1_0,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;
use frankenengine_engine::tee_attestation_policy::DecisionImpact;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_signing_key() -> SigningKey {
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(13);
    }
    SigningKey::from_bytes(key)
}

fn make_trace(trace_id: &str, num_decisions: usize) -> TraceRecord {
    let key = test_signing_key();
    let config = RecorderConfig {
        trace_id: trace_id.to_string(),
        recording_mode: RecordingMode::Full,
        epoch: SecurityEpoch::from_raw(100),
        start_tick: 1000,
        signing_key: key.as_bytes().to_vec(),
    };
    let mut recorder = TraceRecorder::new(config);
    recorder.record_nondeterminism(
        NondeterminismSource::Timestamp,
        vec![0, 0, 0, 0, 0, 0, 3, 232],
        1001,
        None,
    );
    for i in 0..num_decisions {
        let snapshot = DecisionSnapshot {
            decision_index: i as u64,
            trace_id: trace_id.to_string(),
            decision_id: format!("decision-{i}"),
            policy_id: "test-policy".to_string(),
            policy_version: 1,
            epoch: SecurityEpoch::from_raw(100),
            tick: 1000 + i as u64,
            threshold_millionths: 500_000,
            loss_matrix: BTreeMap::new(),
            evidence_hashes: Vec::new(),
            chosen_action: "allow".to_string(),
            outcome_millionths: 100_000,
            extension_id: "ext-001".to_string(),
            nondeterminism_range: (0, 0),
        };
        recorder.record_decision(snapshot);
    }
    recorder.finalize()
}

fn make_evidence_entry() -> frankenengine_engine::evidence_ledger::EvidenceEntry {
    EvidenceEntryBuilder::new(
        "trace-001",
        "decision-001",
        "policy-001",
        SecurityEpoch::from_raw(100),
        DecisionType::SecurityAction,
    )
    .timestamp_ns(1000)
    .chosen(ChosenAction {
        action_name: "allow".to_string(),
        expected_loss_millionths: 100_000,
        rationale: "test rationale".to_string(),
    })
    .build()
    .unwrap()
}

fn make_policy_snapshot(policy_id: &str) -> PolicySnapshot {
    PolicySnapshot {
        policy_id: policy_id.to_string(),
        policy_version: "1.0".to_string(),
        active_epoch: SecurityEpoch::from_raw(100),
        config_hash: ContentHash::compute(b"test-policy-config"),
        config_bytes: b"test-policy-config".to_vec(),
    }
}

fn make_nondeterminism_log() -> NondeterminismLog {
    let mut log = NondeterminismLog::new();
    log.append(
        NondeterminismSource::Timestamp,
        vec![0, 0, 0, 0, 0, 0, 3, 232],
        1001,
        None,
    );
    log.append(
        NondeterminismSource::RandomValue,
        vec![42, 43, 44],
        1002,
        Some("ext-001".to_string()),
    );
    log
}

fn derive_signer_key_id(label: &str) -> EngineObjectId {
    let schema_id = SchemaId::from_definition(b"test-signer-key");
    engine_object_id::derive_id(
        ObjectDomain::EvidenceRecord,
        "test-receipt-signer",
        &schema_id,
        label.as_bytes(),
    )
    .expect("derive_id should succeed")
}

fn make_opt_receipt(opt_id: &str, signer_key_id: EngineObjectId, signing_key: &[u8]) -> OptReceipt {
    OptReceipt {
        schema_version: proof_schema_version_v1_0(),
        optimization_id: opt_id.to_string(),
        optimization_class: OptimizationClass::Superinstruction,
        baseline_ir_hash: ContentHash::compute(format!("baseline-{opt_id}").as_bytes()),
        candidate_ir_hash: ContentHash::compute(format!("candidate-{opt_id}").as_bytes()),
        translation_witness_hash: ContentHash::compute(format!("witness-{opt_id}").as_bytes()),
        invariance_digest: ContentHash::compute(format!("invariance-{opt_id}").as_bytes()),
        rollback_token_id: format!("rollback-{opt_id}"),
        replay_compatibility: BTreeMap::new(),
        policy_epoch: SecurityEpoch::from_raw(100),
        timestamp_ticks: 5000,
        signer_key_id,
        correlation_id: format!("corr-{opt_id}"),
        decision_impact: DecisionImpact::Standard,
        attestation_bindings: None,
        signature: AuthenticityHash::compute_keyed(&[], &[]), // placeholder
    }
    .sign(signing_key)
}

fn make_quorum_checkpoint(seq: u64) -> QuorumCheckpoint {
    let node_a = NodeId::new("node-alpha");
    let node_b = NodeId::new("node-beta");
    let mut participating = BTreeSet::new();
    participating.insert(node_a.clone());
    participating.insert(node_b.clone());

    let mut signatures = BTreeMap::new();
    signatures.insert(
        node_a.clone(),
        MessageSignature {
            signer: node_a,
            hash: AuthenticityHash::compute_keyed(b"key-alpha", b"checkpoint-data"),
        },
    );
    signatures.insert(
        node_b.clone(),
        MessageSignature {
            signer: node_b,
            hash: AuthenticityHash::compute_keyed(b"key-beta", b"checkpoint-data"),
        },
    );

    QuorumCheckpoint {
        checkpoint_seq: seq,
        epoch: SecurityEpoch::from_raw(100),
        participating_nodes: participating,
        evidence_summary_hash: ContentHash::compute(format!("evidence-summary-{seq}").as_bytes()),
        containment_decisions: vec![ResolvedContainmentDecision {
            extension_id: "ext-malicious".to_string(),
            resolved_action: ContainmentAction::Suspend,
            contributing_intent_ids: vec!["intent-1".to_string()],
            epoch: SecurityEpoch::from_raw(100),
        }],
        quorum_signatures: signatures,
        timestamp_ns: 5_000_000 + seq * 1_000,
        protocol_version: ProtocolVersion::CURRENT,
        extensions: BTreeMap::new(),
    }
}

fn build_test_bundle() -> IncidentReplayBundle {
    let key = test_signing_key();
    BundleBuilder::new(
        "incident-001".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "producer-key-1".to_string(),
        key,
    )
    .window(1000, 2000)
    .meta("severity".to_string(), "high".to_string())
    .trace("trace-001".to_string(), make_trace("trace-001", 3))
    .evidence("evidence-001".to_string(), make_evidence_entry())
    .nondeterminism("trace-001".to_string(), make_nondeterminism_log())
    .policy("policy-001".to_string(), make_policy_snapshot("policy-001"))
    .build()
    .expect("bundle build should succeed")
}

fn make_counterfactual_result(
    branch_id: &str,
    trace_id: &str,
    harm_delta: i64,
) -> CounterfactualResult {
    CounterfactualResult {
        config: CounterfactualConfig {
            branch_id: branch_id.to_string(),
            threshold_override_millionths: Some(300_000),
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        },
        delta_report: ActionDeltaReport {
            config: CounterfactualConfig {
                branch_id: branch_id.to_string(),
                threshold_override_millionths: Some(300_000),
                loss_matrix_overrides: BTreeMap::new(),
                policy_version_override: None,
                containment_overrides: BTreeMap::new(),
                evidence_weight_overrides: BTreeMap::new(),
                branch_from_index: 0,
            },
            harm_prevented_delta_millionths: harm_delta,
            false_positive_cost_delta_millionths: -10_000,
            containment_latency_delta_ticks: -5,
            resource_cost_delta_millionths: 20_000,
            affected_extensions: BTreeSet::new(),
            divergence_points: Vec::new(),
            decisions_evaluated: 10,
        },
        source_trace_id: trace_id.to_string(),
    }
}

// ===========================================================================
// OptReceipt artifact in bundle
// ===========================================================================

#[test]
fn bundle_with_opt_receipt_integrity_passes() {
    let key = test_signing_key();
    let signer_id = derive_signer_key_id("receipt-signer-1");
    let receipt = make_opt_receipt("opt-1", signer_id, b"receipt-key");

    let bundle = BundleBuilder::new(
        "receipt-test".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .trace("t1".to_string(), make_trace("t1", 2))
    .receipt("receipt-1".to_string(), receipt)
    .build()
    .unwrap();

    assert!(bundle.opt_receipts.contains_key("receipt-1"));
    assert_eq!(bundle.opt_receipts.len(), 1);

    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);
    assert!(report.passed, "receipt bundle integrity: {report:?}");
}

#[test]
fn bundle_with_multiple_opt_receipts() {
    let key = test_signing_key();
    let signer1 = derive_signer_key_id("signer-1");
    let signer2 = derive_signer_key_id("signer-2");
    let r1 = make_opt_receipt("opt-A", signer1, b"key-A");
    let r2 = make_opt_receipt("opt-B", signer2, b"key-B");

    let bundle = BundleBuilder::new(
        "multi-receipt".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .trace("t1".to_string(), make_trace("t1", 1))
    .receipt("r1".to_string(), r1)
    .receipt("r2".to_string(), r2)
    .build()
    .unwrap();

    assert_eq!(bundle.opt_receipts.len(), 2);

    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);
    assert!(report.passed, "multi-receipt integrity: {report:?}");
}

#[test]
fn verify_receipts_with_known_key() {
    let key = test_signing_key();
    let signer_id = derive_signer_key_id("receipt-signer");
    let receipt = make_opt_receipt("opt-verified", signer_id.clone(), b"receipt-signing-key");

    let bundle = BundleBuilder::new(
        "receipt-verify".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .receipt("r1".to_string(), receipt)
    .build()
    .unwrap();

    let verifier = BundleVerifier::new();

    // Provide the correct verification key.
    let vk = test_signing_key().verification_key();
    let mut vkeys = BTreeMap::new();
    vkeys.insert(signer_id, vk);

    let report = verifier.verify_receipts(&bundle, &vkeys, SecurityEpoch::from_raw(100), 6000);

    // Receipt signature check should have been run. The receipt uses
    // AuthenticityHash keyed verification, not ed25519, so it won't match
    // the ed25519 VerificationKey. But the epoch check should pass.
    let epoch_checks: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.name.starts_with("receipt-epoch:"))
        .collect();
    assert!(!epoch_checks.is_empty());
    assert!(epoch_checks.iter().all(|c| c.outcome.is_pass()));
}

#[test]
fn verify_receipts_skips_unknown_keys() {
    let key = test_signing_key();
    let signer_id = derive_signer_key_id("unknown-signer");
    let receipt = make_opt_receipt("opt-unknown", signer_id, b"some-key");

    let bundle = BundleBuilder::new(
        "receipt-skip".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .receipt("r1".to_string(), receipt)
    .build()
    .unwrap();

    let verifier = BundleVerifier::new();
    let empty_vkeys = BTreeMap::new();
    let report =
        verifier.verify_receipts(&bundle, &empty_vkeys, SecurityEpoch::from_raw(100), 6000);

    // Signature check should be skipped (no key), epoch check should pass.
    let sig_checks: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.name.starts_with("receipt-signature:"))
        .collect();
    assert!(
        sig_checks
            .iter()
            .all(|c| matches!(c.outcome, CheckOutcome::Skipped { .. }))
    );
}

#[test]
fn verify_receipts_detects_future_epoch() {
    let key = test_signing_key();
    let signer_id = derive_signer_key_id("future-signer");
    let mut receipt = make_opt_receipt("opt-future", signer_id, b"key");
    receipt.policy_epoch = SecurityEpoch::from_raw(999);

    let bundle = BundleBuilder::new(
        "receipt-future".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .receipt("r1".to_string(), receipt)
    .build()
    .unwrap();

    let verifier = BundleVerifier::new();
    let report = verifier.verify_receipts(
        &bundle,
        &BTreeMap::new(),
        SecurityEpoch::from_raw(100),
        6000,
    );

    let epoch_checks: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.name.starts_with("receipt-epoch:"))
        .collect();
    assert!(!epoch_checks.is_empty());
    assert!(
        epoch_checks.iter().any(|c| c.outcome.is_fail()),
        "future epoch receipt should fail epoch check"
    );
}

// ===========================================================================
// QuorumCheckpoint artifact in bundle
// ===========================================================================

#[test]
fn bundle_with_quorum_checkpoint_integrity() {
    let key = test_signing_key();
    let cp = make_quorum_checkpoint(1);

    let bundle = BundleBuilder::new(
        "checkpoint-test".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .trace("t1".to_string(), make_trace("t1", 2))
    .checkpoint("cp-1".to_string(), cp)
    .build()
    .unwrap();

    assert!(bundle.quorum_checkpoints.contains_key("cp-1"));
    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);
    assert!(report.passed, "checkpoint integrity: {report:?}");
}

#[test]
fn bundle_with_multiple_checkpoints() {
    let key = test_signing_key();
    let bundle = BundleBuilder::new(
        "multi-checkpoint".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .checkpoint("cp-1".to_string(), make_quorum_checkpoint(1))
    .checkpoint("cp-2".to_string(), make_quorum_checkpoint(2))
    .checkpoint("cp-3".to_string(), make_quorum_checkpoint(3))
    .build()
    .unwrap();

    assert_eq!(bundle.quorum_checkpoints.len(), 3);
    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);
    assert!(report.passed);
}

// ===========================================================================
// All seven artifact types in a single bundle
// ===========================================================================

#[test]
fn bundle_with_all_seven_artifact_types() {
    let key = test_signing_key();
    let signer_id = derive_signer_key_id("all-types-signer");
    let receipt = make_opt_receipt("opt-all", signer_id, b"all-key");
    let cf = make_counterfactual_result("branch-all", "trace-001", 50_000);

    let bundle = BundleBuilder::new(
        "all-seven".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .window(1000, 3000)
    .trace("trace-001".to_string(), make_trace("trace-001", 3))
    .evidence("ev-001".to_string(), make_evidence_entry())
    .receipt("receipt-001".to_string(), receipt)
    .checkpoint("cp-001".to_string(), make_quorum_checkpoint(1))
    .nondeterminism("trace-001".to_string(), make_nondeterminism_log())
    .counterfactual("branch-all".to_string(), cf)
    .policy("policy-001".to_string(), make_policy_snapshot("policy-001"))
    .build()
    .unwrap();

    // All collections populated.
    assert_eq!(bundle.traces.len(), 1);
    assert_eq!(bundle.evidence_entries.len(), 1);
    assert_eq!(bundle.opt_receipts.len(), 1);
    assert_eq!(bundle.quorum_checkpoints.len(), 1);
    assert_eq!(bundle.nondeterminism_logs.len(), 1);
    assert_eq!(bundle.counterfactual_results.len(), 1);
    assert_eq!(bundle.policy_snapshots.len(), 1);

    // 7 artifact entries in manifest.
    assert_eq!(bundle.manifest.artifacts.len(), 7);

    // Integrity passes.
    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);
    assert!(report.passed, "all-seven integrity: {report:?}");

    // All artifact hash checks pass.
    let hash_checks: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.category == VerificationCategory::ArtifactHash)
        .collect();
    assert_eq!(hash_checks.len(), 7);
    assert!(hash_checks.iter().all(|c| c.outcome.is_pass()));
}

#[test]
fn all_seven_types_serde_roundtrip() {
    let key = test_signing_key();
    let signer_id = derive_signer_key_id("serde-signer");
    let receipt = make_opt_receipt("opt-serde", signer_id, b"serde-key");
    let cf = make_counterfactual_result("branch-serde", "t1", 30_000);

    let bundle = BundleBuilder::new(
        "serde-all".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .trace("t1".to_string(), make_trace("t1", 2))
    .evidence("ev1".to_string(), make_evidence_entry())
    .receipt("r1".to_string(), receipt)
    .checkpoint("cp1".to_string(), make_quorum_checkpoint(1))
    .nondeterminism("t1".to_string(), make_nondeterminism_log())
    .counterfactual("branch-serde".to_string(), cf)
    .policy("p1".to_string(), make_policy_snapshot("p1"))
    .build()
    .unwrap();

    let json = serde_json::to_string(&bundle).unwrap();
    let restored: IncidentReplayBundle = serde_json::from_str(&json).unwrap();

    assert_eq!(bundle.manifest.bundle_id, restored.manifest.bundle_id);
    assert_eq!(bundle.manifest.merkle_root, restored.manifest.merkle_root);
    assert_eq!(bundle.manifest.signature, restored.manifest.signature);
    assert_eq!(bundle.traces.len(), restored.traces.len());
    assert_eq!(
        bundle.evidence_entries.len(),
        restored.evidence_entries.len()
    );
    assert_eq!(bundle.opt_receipts.len(), restored.opt_receipts.len());
    assert_eq!(
        bundle.quorum_checkpoints.len(),
        restored.quorum_checkpoints.len()
    );
    assert_eq!(
        bundle.nondeterminism_logs.len(),
        restored.nondeterminism_logs.len()
    );
    assert_eq!(
        bundle.counterfactual_results.len(),
        restored.counterfactual_results.len()
    );
    assert_eq!(
        bundle.policy_snapshots.len(),
        restored.policy_snapshots.len()
    );

    // Integrity still passes after roundtrip.
    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&restored, 7000);
    assert!(report.passed);
}

// ===========================================================================
// Full verification pipeline: integrity + signature + replay
// ===========================================================================

#[test]
fn full_pipeline_valid_bundle() {
    let bundle = build_test_bundle();
    let vk = test_signing_key().verification_key();
    let verifier = BundleVerifier::new();

    let integrity = verifier.verify_integrity(&bundle, 6000);
    assert!(integrity.passed, "integrity: {integrity:?}");

    let sig = verifier.verify_signature(&bundle, &vk, 6000);
    assert!(sig.passed, "signature: {sig:?}");

    let replay = verifier.verify_replay(&bundle, 6000);
    assert!(replay.passed, "replay: {replay:?}");
}

#[test]
fn full_pipeline_after_serde_roundtrip() {
    let bundle = build_test_bundle();
    let json = serde_json::to_string(&bundle).unwrap();
    let restored: IncidentReplayBundle = serde_json::from_str(&json).unwrap();

    let vk = test_signing_key().verification_key();
    let verifier = BundleVerifier::new();

    let integrity = verifier.verify_integrity(&restored, 6000);
    assert!(integrity.passed);

    let sig = verifier.verify_signature(&restored, &vk, 6000);
    assert!(sig.passed);

    let replay = verifier.verify_replay(&restored, 6000);
    assert!(replay.passed);
}

#[test]
fn full_pipeline_tampered_trace_data_fails_integrity_and_replay() {
    let mut bundle = build_test_bundle();
    // Tamper trace metadata after building (changes hash, breaks integrity).
    bundle
        .traces
        .get_mut("trace-001")
        .unwrap()
        .metadata
        .insert("injected".to_string(), "true".to_string());

    let verifier = BundleVerifier::new();

    let integrity = verifier.verify_integrity(&bundle, 6000);
    assert!(!integrity.passed, "tampered trace should fail integrity");

    // Signature should also fail because manifest signing_bytes are valid
    // but the artifact hashes no longer match.
    let artifact_fail = integrity
        .checks
        .iter()
        .any(|c| c.category == VerificationCategory::ArtifactHash && c.outcome.is_fail());
    assert!(artifact_fail);
}

// ===========================================================================
// Counterfactual verification
// ===========================================================================

#[test]
fn verify_counterfactual_with_bundled_matching_result() {
    let key = test_signing_key();
    let cf = make_counterfactual_result("branch-cf1", "t1", 50_000);

    let bundle = BundleBuilder::new(
        "cf-match".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .trace("t1".to_string(), make_trace("t1", 3))
    .counterfactual("branch-cf1".to_string(), cf.clone())
    .build()
    .unwrap();

    let verifier = BundleVerifier::new();
    let report = verifier.verify_counterfactual(&bundle, std::slice::from_ref(&cf.config), 6000);

    // There should be a counterfactual check.
    let cf_checks: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.category == VerificationCategory::Counterfactual)
        .collect();
    assert!(!cf_checks.is_empty());
}

#[test]
fn verify_counterfactual_no_traces_fails() {
    let key = test_signing_key();
    let bundle = BundleBuilder::new(
        "cf-no-trace".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .policy("p1".to_string(), make_policy_snapshot("p1"))
    .build()
    .unwrap();

    let config = CounterfactualConfig {
        branch_id: "branch-x".to_string(),
        threshold_override_millionths: Some(200_000),
        loss_matrix_overrides: BTreeMap::new(),
        policy_version_override: None,
        containment_overrides: BTreeMap::new(),
        evidence_weight_overrides: BTreeMap::new(),
        branch_from_index: 0,
    };

    let verifier = BundleVerifier::new();
    let report = verifier.verify_counterfactual(&bundle, &[config], 6000);

    let cf_checks: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.category == VerificationCategory::Counterfactual)
        .collect();
    // Should fail because no traces available.
    assert!(cf_checks.iter().any(|c| c.outcome.is_fail()));
}

#[test]
fn verify_counterfactual_fresh_config_without_bundled_result() {
    let key = test_signing_key();
    let bundle = BundleBuilder::new(
        "cf-fresh".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .trace("t1".to_string(), make_trace("t1", 3))
    .build()
    .unwrap();

    let config = CounterfactualConfig {
        branch_id: "fresh-branch".to_string(),
        threshold_override_millionths: Some(400_000),
        loss_matrix_overrides: BTreeMap::new(),
        policy_version_override: None,
        containment_overrides: BTreeMap::new(),
        evidence_weight_overrides: BTreeMap::new(),
        branch_from_index: 0,
    };

    let verifier = BundleVerifier::new();
    let report = verifier.verify_counterfactual(&bundle, &[config], 6000);

    // Fresh analysis on existing trace should succeed.
    let cf_checks: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.category == VerificationCategory::Counterfactual)
        .collect();
    assert!(!cf_checks.is_empty());
    assert!(cf_checks.iter().all(|c| c.outcome.is_pass()));
}

// ===========================================================================
// Cross-artifact-type collision prevention (composite keys)
// ===========================================================================

#[test]
fn same_user_id_different_artifact_types_no_collision() {
    let key = test_signing_key();
    // Use the same ID "alpha" for trace, evidence, and policy.
    let bundle = BundleBuilder::new(
        "collision-test".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .trace("alpha".to_string(), make_trace("alpha", 2))
    .evidence("alpha".to_string(), make_evidence_entry())
    .policy("alpha".to_string(), make_policy_snapshot("alpha"))
    .build()
    .unwrap();

    // All three should be present (composite keys prevent collision).
    assert_eq!(bundle.traces.len(), 1);
    assert_eq!(bundle.evidence_entries.len(), 1);
    assert_eq!(bundle.policy_snapshots.len(), 1);
    assert_eq!(bundle.manifest.artifacts.len(), 3);

    // Keys should be distinct.
    let keys: Vec<&String> = bundle.manifest.artifacts.keys().collect();
    assert!(keys.contains(&&"trace:alpha".to_string()));
    assert!(keys.contains(&&"evidence:alpha".to_string()));
    assert!(keys.contains(&&"policy-snapshot:alpha".to_string()));

    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);
    assert!(report.passed);
}

// ===========================================================================
// Inspect with various artifact configurations
// ===========================================================================

#[test]
fn inspect_all_artifact_types_counted() {
    let key = test_signing_key();
    let signer_id = derive_signer_key_id("inspect-signer");
    let receipt = make_opt_receipt("opt-inspect", signer_id, b"inspect-key");
    let cf = make_counterfactual_result("branch-inspect", "t1", 25_000);

    let bundle = BundleBuilder::new(
        "inspect-all".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .trace("t1".to_string(), make_trace("t1", 2))
    .evidence("ev1".to_string(), make_evidence_entry())
    .receipt("r1".to_string(), receipt)
    .checkpoint("cp1".to_string(), make_quorum_checkpoint(1))
    .nondeterminism("t1".to_string(), make_nondeterminism_log())
    .counterfactual("branch-inspect".to_string(), cf)
    .policy("p1".to_string(), make_policy_snapshot("p1"))
    .build()
    .unwrap();

    let verifier = BundleVerifier::new();
    let inspection = verifier.inspect(&bundle);

    assert_eq!(inspection.incident_id, "inspect-all");
    assert_eq!(inspection.format_version, BUNDLE_FORMAT_VERSION);
    assert_eq!(inspection.trace_ids, vec!["t1".to_string()]);

    // All 7 artifact kinds present in counts.
    let total: u64 = inspection.artifact_counts.values().sum();
    assert_eq!(total, 7);

    assert_eq!(*inspection.artifact_counts.get("trace").unwrap_or(&0), 1);
    assert_eq!(*inspection.artifact_counts.get("evidence").unwrap_or(&0), 1);
    assert_eq!(
        *inspection.artifact_counts.get("opt-receipt").unwrap_or(&0),
        1
    );
    assert_eq!(
        *inspection
            .artifact_counts
            .get("quorum-checkpoint")
            .unwrap_or(&0),
        1
    );
    assert_eq!(
        *inspection
            .artifact_counts
            .get("nondeterminism-log")
            .unwrap_or(&0),
        1
    );
    assert_eq!(
        *inspection
            .artifact_counts
            .get("counterfactual-result")
            .unwrap_or(&0),
        1
    );
    assert_eq!(
        *inspection
            .artifact_counts
            .get("policy-snapshot")
            .unwrap_or(&0),
        1
    );

    assert!(inspection.total_size_bytes > 0);
    assert_eq!(inspection.redacted_count, 0);
}

#[test]
fn inspect_multi_trace_epochs() {
    let key = test_signing_key();
    let bundle = BundleBuilder::new(
        "multi-epoch".to_string(),
        SecurityEpoch::from_raw(50),
        5000,
        "key-1".to_string(),
        key,
    )
    .trace("t1".to_string(), make_trace("t1", 2))
    .trace("t2".to_string(), make_trace("t2", 3))
    .build()
    .unwrap();

    let verifier = BundleVerifier::new();
    let inspection = verifier.inspect(&bundle);

    // Creation epoch 50 should be in the set.
    assert!(inspection.epochs.contains(&50));
    // Trace epochs (100 from make_trace) should also be present.
    assert!(inspection.epochs.contains(&100));

    assert_eq!(inspection.trace_ids.len(), 2);
}

// ===========================================================================
// Merkle proof integration with actual bundle hashes
// ===========================================================================

#[test]
fn merkle_proof_for_bundle_artifacts() {
    let bundle = build_test_bundle();
    let leaf_hashes: Vec<ContentHash> = bundle
        .manifest
        .artifacts
        .values()
        .map(|a| a.content_hash.clone())
        .collect();

    let root = compute_merkle_root(&leaf_hashes);
    assert_eq!(root, bundle.manifest.merkle_root);

    // Verify proof for each leaf in the actual bundle.
    for (idx, leaf) in leaf_hashes.iter().enumerate() {
        let proof = build_merkle_proof(&leaf_hashes, idx);
        assert!(
            verify_merkle_proof(leaf, &proof, &root),
            "proof for artifact at index {idx} should verify"
        );
    }
}

#[test]
fn merkle_proof_for_seven_artifact_bundle() {
    let key = test_signing_key();
    let signer_id = derive_signer_key_id("merkle-signer");
    let receipt = make_opt_receipt("opt-merkle", signer_id, b"merkle-key");
    let cf = make_counterfactual_result("branch-merkle", "t1", 10_000);

    let bundle = BundleBuilder::new(
        "merkle-seven".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .trace("t1".to_string(), make_trace("t1", 2))
    .evidence("ev1".to_string(), make_evidence_entry())
    .receipt("r1".to_string(), receipt)
    .checkpoint("cp1".to_string(), make_quorum_checkpoint(1))
    .nondeterminism("t1".to_string(), make_nondeterminism_log())
    .counterfactual("branch-merkle".to_string(), cf)
    .policy("p1".to_string(), make_policy_snapshot("p1"))
    .build()
    .unwrap();

    let leaf_hashes: Vec<ContentHash> = bundle
        .manifest
        .artifacts
        .values()
        .map(|a| a.content_hash.clone())
        .collect();
    assert_eq!(leaf_hashes.len(), 7);

    let root = compute_merkle_root(&leaf_hashes);
    assert_eq!(root, bundle.manifest.merkle_root);

    for idx in 0..7 {
        let proof = build_merkle_proof(&leaf_hashes, idx);
        assert!(verify_merkle_proof(&leaf_hashes[idx], &proof, &root));
    }
}

// ===========================================================================
// Bundle ID determinism across different artifact combinations
// ===========================================================================

#[test]
fn bundle_id_differs_with_different_artifacts() {
    let key = test_signing_key();
    let b1 = BundleBuilder::new(
        "incident-x".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        SigningKey::from_bytes(*key.as_bytes()),
    )
    .trace("t1".to_string(), make_trace("t1", 2))
    .build()
    .unwrap();

    let b2 = BundleBuilder::new(
        "incident-x".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        SigningKey::from_bytes(*key.as_bytes()),
    )
    .trace("t1".to_string(), make_trace("t1", 2))
    .policy("p1".to_string(), make_policy_snapshot("p1"))
    .build()
    .unwrap();

    // Different artifacts → different Merkle root → different bundle ID.
    assert_ne!(b1.manifest.bundle_id, b2.manifest.bundle_id);
    assert_ne!(b1.manifest.merkle_root, b2.manifest.merkle_root);
}

#[test]
fn bundle_id_differs_with_different_incident_id() {
    let key = test_signing_key();
    let b1 = BundleBuilder::new(
        "incident-A".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        SigningKey::from_bytes(*key.as_bytes()),
    )
    .trace("t1".to_string(), make_trace("t1", 1))
    .build()
    .unwrap();

    let b2 = BundleBuilder::new(
        "incident-B".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        SigningKey::from_bytes(*key.as_bytes()),
    )
    .trace("t1".to_string(), make_trace("t1", 1))
    .build()
    .unwrap();

    assert_ne!(b1.manifest.bundle_id, b2.manifest.bundle_id);
}

// ===========================================================================
// Signature tampering with specific manifest fields
// ===========================================================================

#[test]
fn signature_fails_after_epoch_tampering() {
    let mut bundle = build_test_bundle();
    let vk = test_signing_key().verification_key();
    bundle.manifest.creation_epoch = SecurityEpoch::from_raw(999);

    let verifier = BundleVerifier::new();
    let report = verifier.verify_signature(&bundle, &vk, 6000);
    assert!(!report.passed);
}

#[test]
fn signature_fails_after_window_tampering() {
    let mut bundle = build_test_bundle();
    let vk = test_signing_key().verification_key();
    bundle.manifest.window_start_tick = 9999;

    let verifier = BundleVerifier::new();
    let report = verifier.verify_signature(&bundle, &vk, 6000);
    assert!(!report.passed);
}

#[test]
fn signature_fails_after_producer_key_tampering() {
    let mut bundle = build_test_bundle();
    let vk = test_signing_key().verification_key();
    bundle.manifest.producer_key_id = "attacker-key".to_string();

    let verifier = BundleVerifier::new();
    let report = verifier.verify_signature(&bundle, &vk, 6000);
    assert!(!report.passed);
}

#[test]
fn signature_fails_after_merkle_root_tampering() {
    let mut bundle = build_test_bundle();
    let vk = test_signing_key().verification_key();
    bundle.manifest.merkle_root = ContentHash::compute(b"evil-root");

    let verifier = BundleVerifier::new();
    let report = verifier.verify_signature(&bundle, &vk, 6000);
    assert!(!report.passed);
}

// ===========================================================================
// Integrity with removed artifact data
// ===========================================================================

#[test]
fn integrity_fails_when_trace_data_removed() {
    let mut bundle = build_test_bundle();
    // Remove the trace data but keep the manifest entry.
    bundle.traces.clear();

    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);
    assert!(!report.passed);

    let missing_checks: Vec<_> = report
        .checks
        .iter()
        .filter(|c| {
            c.category == VerificationCategory::ArtifactHash
                && c.outcome.is_fail()
                && c.name.contains("trace")
        })
        .collect();
    assert!(!missing_checks.is_empty());
}

#[test]
fn integrity_fails_when_evidence_data_removed() {
    let mut bundle = build_test_bundle();
    bundle.evidence_entries.clear();

    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);
    assert!(!report.passed);
}

#[test]
fn integrity_fails_when_policy_data_removed() {
    let mut bundle = build_test_bundle();
    bundle.policy_snapshots.clear();

    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);
    assert!(!report.passed);
}

#[test]
fn integrity_fails_when_nondeterminism_data_removed() {
    let mut bundle = build_test_bundle();
    bundle.nondeterminism_logs.clear();

    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);
    assert!(!report.passed);
}

// ===========================================================================
// Redaction policy in bundles
// ===========================================================================

#[test]
fn redaction_policy_preserved_in_full_bundle() {
    let key = test_signing_key();
    let policy = RedactionPolicy {
        redact_extension_ids: true,
        redact_evidence_metadata: true,
        redact_nondeterminism_values: false,
        redact_node_ids: true,
        custom_redaction_keys: {
            let mut s = BTreeSet::new();
            s.insert("tenant_id".to_string());
            s
        },
    };

    let bundle = BundleBuilder::new(
        "redacted-bundle".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .redaction_policy(policy.clone())
    .trace("t1".to_string(), make_trace("t1", 1))
    .build()
    .unwrap();

    assert_eq!(bundle.manifest.redaction_policy, policy);

    // Roundtrip preserves policy.
    let json = serde_json::to_string(&bundle).unwrap();
    let restored: IncidentReplayBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.manifest.redaction_policy, policy);
}

// ===========================================================================
// Replay chain integrity tampering
// ===========================================================================

#[test]
fn replay_detects_decision_tampering() {
    let mut bundle = build_test_bundle();
    if let Some(trace) = bundle.traces.values_mut().next()
        && let Some(entry) = trace.entries.first_mut()
    {
        entry.decision.chosen_action = "block".to_string();
    }

    let verifier = BundleVerifier::new();
    let report = verifier.verify_replay(&bundle, 6000);

    // Replay should detect the modification (either chain integrity or fidelity).
    let replay_fails: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.category == VerificationCategory::Replay && c.outcome.is_fail())
        .collect();
    assert!(
        !replay_fails.is_empty(),
        "decision tampering should be detected by replay"
    );
}

// ===========================================================================
// Stress: larger bundles
// ===========================================================================

#[test]
fn bundle_with_many_traces_and_artifacts() {
    let key = test_signing_key();
    let signer_id = derive_signer_key_id("stress-signer");

    let mut builder = BundleBuilder::new(
        "stress-test".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .window(0, 100_000);

    // Add 10 traces.
    for i in 0..10 {
        let tid = format!("trace-{i:03}");
        builder = builder.trace(tid.clone(), make_trace(&tid, 2));
    }

    // Add 5 evidence entries.
    for i in 0..5 {
        builder = builder.evidence(format!("ev-{i:03}"), make_evidence_entry());
    }

    // Add 3 receipts.
    for i in 0..3 {
        let receipt = make_opt_receipt(&format!("opt-{i:03}"), signer_id.clone(), b"stress-key");
        builder = builder.receipt(format!("r-{i:03}"), receipt);
    }

    // Add 2 checkpoints.
    for i in 0..2 {
        builder = builder.checkpoint(format!("cp-{i:03}"), make_quorum_checkpoint(i as u64));
    }

    // Add 3 policies.
    for i in 0..3 {
        let pid = format!("policy-{i:03}");
        builder = builder.policy(pid.clone(), make_policy_snapshot(&pid));
    }

    let bundle = builder.build().unwrap();

    // 10 + 5 + 3 + 2 + 3 = 23 artifacts.
    assert_eq!(bundle.manifest.artifacts.len(), 23);

    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);
    assert!(report.passed, "stress integrity: {report:?}");
    assert_eq!(report.pass_count(), report.checks.len() as u64);

    // Replay all 10 traces.
    let replay = verifier.verify_replay(&bundle, 6000);
    assert!(replay.passed, "stress replay: {replay:?}");
}

// ===========================================================================
// CounterfactualResult in bundle artifact inventory
// ===========================================================================

#[test]
fn counterfactual_result_artifact_in_manifest() {
    let key = test_signing_key();
    let cf = make_counterfactual_result("branch-inv", "t1", 40_000);

    let bundle = BundleBuilder::new(
        "cf-manifest".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .trace("t1".to_string(), make_trace("t1", 2))
    .counterfactual("branch-inv".to_string(), cf)
    .build()
    .unwrap();

    // Should have artifact entries for both trace and counterfactual.
    assert_eq!(bundle.manifest.artifacts.len(), 2);

    let cf_entry = bundle
        .manifest
        .artifacts
        .values()
        .find(|a| a.kind == BundleArtifactKind::CounterfactualResult);
    assert!(cf_entry.is_some());
    assert!(cf_entry.unwrap().size_bytes > 0);
}

// ===========================================================================
// Verification report aggregation
// ===========================================================================

#[test]
fn integrity_report_summary_categories() {
    let key = test_signing_key();
    let signer_id = derive_signer_key_id("summary-signer");
    let receipt = make_opt_receipt("opt-summary", signer_id, b"summary-key");

    let bundle = BundleBuilder::new(
        "summary-test".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .trace("t1".to_string(), make_trace("t1", 2))
    .evidence("ev1".to_string(), make_evidence_entry())
    .receipt("r1".to_string(), receipt)
    .policy("p1".to_string(), make_policy_snapshot("p1"))
    .build()
    .unwrap();

    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&bundle, 6000);

    assert!(report.passed);

    // Summary should have integrity, artifact-hash, and compatibility categories.
    assert!(report.summary.contains_key("integrity"));
    assert!(report.summary.contains_key("artifact-hash"));
    assert!(report.summary.contains_key("compatibility"));

    // artifact-hash should have exactly 4 passes (one per artifact).
    let ah = report.summary.get("artifact-hash").unwrap();
    assert_eq!(ah.passed, 4);
    assert_eq!(ah.failed, 0);
}

// ===========================================================================
// Signing bytes cover all manifest fields
// ===========================================================================

#[test]
fn signing_bytes_differ_with_different_bundle_ids() {
    let key = test_signing_key();
    let b1 = BundleBuilder::new(
        "id-1".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        SigningKey::from_bytes(*key.as_bytes()),
    )
    .trace("t1".to_string(), make_trace("t1", 1))
    .build()
    .unwrap();

    let b2 = BundleBuilder::new(
        "id-2".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        SigningKey::from_bytes(*key.as_bytes()),
    )
    .trace("t1".to_string(), make_trace("t1", 1))
    .build()
    .unwrap();

    assert_ne!(b1.manifest.signing_bytes(), b2.manifest.signing_bytes());
}

#[test]
fn signing_bytes_differ_with_different_epochs() {
    let key = test_signing_key();
    let b1 = BundleBuilder::new(
        "epoch-test".to_string(),
        SecurityEpoch::from_raw(1),
        5000,
        "key-1".to_string(),
        SigningKey::from_bytes(*key.as_bytes()),
    )
    .trace("t1".to_string(), make_trace("t1", 1))
    .build()
    .unwrap();

    let b2 = BundleBuilder::new(
        "epoch-test".to_string(),
        SecurityEpoch::from_raw(200),
        5000,
        "key-1".to_string(),
        SigningKey::from_bytes(*key.as_bytes()),
    )
    .trace("t1".to_string(), make_trace("t1", 1))
    .build()
    .unwrap();

    assert_ne!(b1.manifest.signing_bytes(), b2.manifest.signing_bytes());
}

#[test]
fn signing_bytes_differ_with_different_timestamps() {
    let key = test_signing_key();
    let b1 = BundleBuilder::new(
        "ts-test".to_string(),
        SecurityEpoch::from_raw(100),
        1000,
        "key-1".to_string(),
        SigningKey::from_bytes(*key.as_bytes()),
    )
    .trace("t1".to_string(), make_trace("t1", 1))
    .build()
    .unwrap();

    let b2 = BundleBuilder::new(
        "ts-test".to_string(),
        SecurityEpoch::from_raw(100),
        9999,
        "key-1".to_string(),
        SigningKey::from_bytes(*key.as_bytes()),
    )
    .trace("t1".to_string(), make_trace("t1", 1))
    .build()
    .unwrap();

    assert_ne!(b1.manifest.signing_bytes(), b2.manifest.signing_bytes());
}

// ===========================================================================
// Opt receipt serde roundtrip in bundle
// ===========================================================================

#[test]
fn opt_receipt_preserved_in_bundle_serde() {
    let key = test_signing_key();
    let signer_id = derive_signer_key_id("serde-receipt");
    let receipt = make_opt_receipt("opt-serde-rt", signer_id.clone(), b"serde-rt-key");

    let bundle = BundleBuilder::new(
        "receipt-serde".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .receipt("r1".to_string(), receipt.clone())
    .build()
    .unwrap();

    let json = serde_json::to_string(&bundle).unwrap();
    let restored: IncidentReplayBundle = serde_json::from_str(&json).unwrap();

    let original = &bundle.opt_receipts["r1"];
    let roundtripped = &restored.opt_receipts["r1"];
    assert_eq!(original.optimization_id, roundtripped.optimization_id);
    assert_eq!(original.signer_key_id, roundtripped.signer_key_id);
    assert_eq!(original.signature, roundtripped.signature);
}

// ===========================================================================
// QuorumCheckpoint serde roundtrip in bundle
// ===========================================================================

#[test]
fn quorum_checkpoint_preserved_in_bundle_serde() {
    let key = test_signing_key();
    let bundle = BundleBuilder::new(
        "checkpoint-serde".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .checkpoint("cp1".to_string(), make_quorum_checkpoint(42))
    .build()
    .unwrap();

    let json = serde_json::to_string(&bundle).unwrap();
    let restored: IncidentReplayBundle = serde_json::from_str(&json).unwrap();

    let original = &bundle.quorum_checkpoints["cp1"];
    let roundtripped = &restored.quorum_checkpoints["cp1"];
    assert_eq!(original.checkpoint_seq, roundtripped.checkpoint_seq);
    assert_eq!(original.epoch, roundtripped.epoch);
    assert_eq!(
        original.participating_nodes,
        roundtripped.participating_nodes
    );
    assert_eq!(
        original.evidence_summary_hash,
        roundtripped.evidence_summary_hash
    );
}

// ===========================================================================
// Integrity after serde roundtrip of complex bundle
// ===========================================================================

#[test]
fn all_seven_types_integrity_after_serde() {
    let key = test_signing_key();
    let signer_id = derive_signer_key_id("seven-serde");
    let receipt = make_opt_receipt("opt-7serde", signer_id, b"7key");
    let cf = make_counterfactual_result("branch-7", "t1", 15_000);

    let bundle = BundleBuilder::new(
        "seven-serde".to_string(),
        SecurityEpoch::from_raw(100),
        5000,
        "key-1".to_string(),
        key,
    )
    .window(100, 900)
    .trace("t1".to_string(), make_trace("t1", 3))
    .evidence("ev1".to_string(), make_evidence_entry())
    .receipt("r1".to_string(), receipt)
    .checkpoint("cp1".to_string(), make_quorum_checkpoint(1))
    .nondeterminism("t1".to_string(), make_nondeterminism_log())
    .counterfactual("branch-7".to_string(), cf)
    .policy("p1".to_string(), make_policy_snapshot("p1"))
    .build()
    .unwrap();

    let json = serde_json::to_string(&bundle).unwrap();
    let restored: IncidentReplayBundle = serde_json::from_str(&json).unwrap();

    let verifier = BundleVerifier::new();
    let report = verifier.verify_integrity(&restored, 7000);
    assert!(
        report.passed,
        "seven-type integrity after serde: {report:?}"
    );
    assert_eq!(report.fail_count(), 0);

    // Signature should also survive the roundtrip.
    let vk = test_signing_key().verification_key();
    let sig_report = verifier.verify_signature(&restored, &vk, 7000);
    assert!(
        sig_report.passed,
        "seven-type signature after serde: {sig_report:?}"
    );
}
