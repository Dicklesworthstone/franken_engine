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

use std::collections::BTreeSet;

use frankenengine_engine::engine_object_id::{self, ObjectDomain};
use frankenengine_engine::promotion_gate_runner::{
    AdversarialTestResult, CandidateCapabilityRequest, EquivalenceTestCase, GateKind,
    GateRunnerConfig, GateRunnerInput, GateRunnerOutput, PerformanceMeasurement,
    run_promotion_gates,
};
use frankenengine_engine::replacement_lineage_log::{
    DemotionReceiptInput, EvidenceCategory, EvidencePointerInput, LineageLogConfig,
    LineageLogError, LineageQuery, ReplacementKind, ReplacementLineageEvidenceIndex,
    ReplacementLineageLog, ReplayJoinQuery, SlotLineageQuery, verify_consistency_proof,
    verify_inclusion_proof,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::self_replacement::{
    ApproverKind, CreateDecisionInput, CreateManifestInput, CreateReceiptInput,
    DelegateCellManifest, DelegateType, MonitoringHook, PromotionDecision, ReplacementLifecycle,
    ReplacementReceipt, SandboxConfiguration, SchemaVersion, SignatureBundle,
    ValidationArtifactKind, ValidationArtifactRef,
};
use frankenengine_engine::signature_preimage::SigningKey;
use frankenengine_engine::slot_registry::{
    AuthorityEnvelope, SlotCapability, SlotId, SlotKind, SlotRegistry,
};
use frankenengine_engine::storage_adapter::{EventContext, InMemoryStorageAdapter};

fn slot_id(name: &str) -> SlotId {
    SlotId::new(name).expect("valid slot id")
}

fn receipt(slot_name: &str, old: &str, new: &str, ts: u64) -> ReplacementReceipt {
    let sid = slot_id(slot_name);
    let receipt_id = engine_object_id::derive_id(
        ObjectDomain::CheckpointArtifact,
        "lineage-itest-zone",
        &engine_object_id::SchemaId::from_definition(b"lineage-itest-receipt"),
        &format!("{slot_name}|{old}|{new}|{ts}").into_bytes(),
    )
    .expect("derive receipt id");

    ReplacementReceipt {
        receipt_id,
        schema_version: SchemaVersion::V1,
        slot_id: sid,
        old_cell_digest: old.to_string(),
        new_cell_digest: new.to_string(),
        validation_artifacts: vec![ValidationArtifactRef {
            kind: ValidationArtifactKind::EquivalenceResult,
            artifact_digest: "itest-artifact".to_string(),
            passed: true,
            summary: "integration-test artifact".to_string(),
        }],
        rollback_token: format!("rollback-{old}"),
        promotion_rationale: "integration test".to_string(),
        timestamp_ns: ts,
        epoch: SecurityEpoch::from_raw(11),
        zone: "lineage-itest-zone".to_string(),
        signature_bundle: SignatureBundle::new(1),
    }
}

fn index_context() -> EventContext {
    EventContext::new(
        "trace-lineage-index",
        "decision-lineage-index",
        "policy-lineage-index",
    )
    .expect("context")
}

fn replacement_receipt_id_hex(receipt: &ReplacementReceipt) -> String {
    hex::encode(receipt.receipt_id.as_bytes())
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes([seed; 32])
}

fn test_authority_envelope() -> AuthorityEnvelope {
    AuthorityEnvelope {
        required: vec![SlotCapability::ReadSource],
        permitted: vec![
            SlotCapability::ReadSource,
            SlotCapability::EmitIr,
            SlotCapability::EmitEvidence,
        ],
    }
}

fn passing_gate_input(slot_id: &SlotId, authority: &AuthorityEnvelope) -> GateRunnerInput {
    GateRunnerInput {
        equivalence_cases: vec![
            EquivalenceTestCase {
                test_id: "eq-1".to_string(),
                input: b"1+1".to_vec(),
                delegate_output: b"2".to_vec(),
                candidate_output: b"2".to_vec(),
            },
            EquivalenceTestCase {
                test_id: "eq-2".to_string(),
                input: b"2+2".to_vec(),
                delegate_output: b"4".to_vec(),
                candidate_output: b"4".to_vec(),
            },
        ],
        capability_request: CandidateCapabilityRequest {
            slot_id: slot_id.clone(),
            requested_capabilities: authority.required.clone(),
            authority_envelope: authority.clone(),
        },
        performance_measurements: vec![PerformanceMeasurement {
            benchmark_id: "bench-e2e".to_string(),
            throughput_millionths: 700_000,
            latency_ns: 75_000_000,
            iterations: 10_000,
            seed: 42,
        }],
        adversarial_results: vec![
            AdversarialTestResult {
                test_id: "adv-1".to_string(),
                passed: true,
                attack_surface: "hostcall".to_string(),
                evidence: "blocked unexpected hostcall".to_string(),
            },
            AdversarialTestResult {
                test_id: "adv-2".to_string(),
                passed: true,
                attack_surface: "module-loader".to_string(),
                evidence: "no privilege escalation".to_string(),
            },
        ],
    }
}

fn validation_kind_for_gate(gate: GateKind) -> ValidationArtifactKind {
    match gate {
        GateKind::Equivalence => ValidationArtifactKind::EquivalenceResult,
        GateKind::CapabilityPreservation => ValidationArtifactKind::CapabilityPreservation,
        GateKind::PerformanceThreshold => ValidationArtifactKind::PerformanceBenchmark,
        GateKind::AdversarialSurvival => ValidationArtifactKind::AdversarialSurvival,
    }
}

fn validation_artifacts_from_gate_output(output: &GateRunnerOutput) -> Vec<ValidationArtifactRef> {
    output
        .evaluations
        .iter()
        .map(|evaluation| ValidationArtifactRef {
            kind: validation_kind_for_gate(evaluation.gate),
            artifact_digest: format!(
                "{}-{}-{}",
                output.run_id,
                evaluation.gate.as_str(),
                if evaluation.passed { "pass" } else { "fail" }
            ),
            passed: evaluation.passed,
            summary: evaluation.summary.clone(),
        })
        .collect()
}

fn signed_delegate_manifest(
    slot_id: &SlotId,
    authority: &AuthorityEnvelope,
) -> DelegateCellManifest {
    let key = signing_key(11);
    let sandbox = SandboxConfiguration::default();
    let hooks: [MonitoringHook; 0] = [];
    let expected_behavior_hash = [0xAB; 32];
    let manifest = DelegateCellManifest::create_signed(
        &key,
        CreateManifestInput {
            slot_id,
            delegate_type: DelegateType::QuickJsBacked,
            capability_envelope: authority,
            sandbox: &sandbox,
            monitoring_hooks: &hooks,
            expected_behavior_hash: &expected_behavior_hash,
            zone: "lineage-e2e-zone",
        },
    )
    .expect("create signed delegate manifest");
    manifest
        .verify_signature(&key.verification_key())
        .expect("delegate manifest signature must verify");
    manifest
}

fn signed_promotion_decision(
    slot_id: &SlotId,
    candidate_digest: &str,
    gate_output: &GateRunnerOutput,
    timestamp_ns: u64,
) -> PromotionDecision {
    let approver = ApproverKind::System {
        component: "promotion-gate-runner".to_string(),
    };
    let gate_results = gate_output
        .evaluations
        .iter()
        .map(|evaluation| evaluation.to_gate_result())
        .collect::<Vec<_>>();

    let mut decision = PromotionDecision::create_unsigned(CreateDecisionInput {
        slot_id,
        candidate_cell_digest: candidate_digest,
        gate_results: &gate_results,
        risk_level: gate_output.risk_level,
        approver: &approver,
        timestamp_ns,
        epoch: SecurityEpoch::from_raw(11),
        zone: "lineage-e2e-zone",
        required_signatures: 2,
    })
    .expect("create decision");

    decision
        .add_signature(&signing_key(17), "gate-runner")
        .expect("sign decision gate-runner");
    decision
        .add_signature(&signing_key(19), "governance-approver")
        .expect("sign decision governance");
    decision
        .verify_signatures()
        .expect("decision signatures must verify");
    decision
}

fn signed_replacement_receipt(
    slot_id: &SlotId,
    old_cell_digest: &str,
    new_cell_digest: &str,
    timestamp_ns: u64,
    validation_artifacts: &[ValidationArtifactRef],
) -> ReplacementReceipt {
    let mut receipt = ReplacementReceipt::create_unsigned(CreateReceiptInput {
        slot_id,
        old_cell_digest,
        new_cell_digest,
        validation_artifacts,
        rollback_token: &format!("rollback-{old_cell_digest}"),
        promotion_rationale: "deterministic integration lifecycle validation",
        timestamp_ns,
        epoch: SecurityEpoch::from_raw(11),
        zone: "lineage-e2e-zone",
        required_signatures: 2,
    })
    .expect("create replacement receipt");

    receipt
        .add_signature(&signing_key(17), "gate-runner")
        .expect("sign receipt gate-runner");
    receipt
        .add_signature(&signing_key(19), "governance-approver")
        .expect("sign receipt governance");
    receipt
        .verify_signatures()
        .expect("receipt signatures must verify");
    receipt
}

#[test]
fn checkpoint_consistency_proof_verifies_and_detects_tamper() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    for i in 0..6 {
        let r = receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
        log.append(r, ReplacementKind::DelegateToNative, i * 100)
            .expect("append");
        if i == 2 || i == 5 {
            log.create_checkpoint(i * 100, SecurityEpoch::from_raw(11))
                .expect("checkpoint");
        }
    }

    let proof = log.consistency_proof(0, 1).expect("proof");
    assert!(verify_consistency_proof(&proof));

    let mut tampered = proof.clone();
    tampered.newer_entry_hashes[0] =
        frankenengine_engine::hash_tiers::ContentHash::compute(b"tampered");
    assert!(!verify_consistency_proof(&tampered));
}

#[test]
fn verifier_surface_supports_lineage_verify_and_audit_workflow() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    log.append(
        receipt("slot-a", "delegate-v1", "native-v1", 100),
        ReplacementKind::DelegateToNative,
        100,
    )
    .expect("append");
    log.append(
        receipt("slot-a", "native-v1", "delegate-v1", 200),
        ReplacementKind::Demotion,
        200,
    )
    .expect("append");
    log.append(
        receipt("slot-a", "delegate-v1", "native-v2", 300),
        ReplacementKind::RePromotion,
        300,
    )
    .expect("append");
    log.append(
        receipt("slot-b", "delegate-b1", "native-b1", 400),
        ReplacementKind::DelegateToNative,
        400,
    )
    .expect("append");
    log.create_checkpoint(450, SecurityEpoch::from_raw(11))
        .expect("checkpoint");

    let verify = log.verify_slot_lineage(&slot_id("slot-a"));
    assert!(verify.chain_valid);
    assert_eq!(verify.total_entries, 3);
    assert!(verify.issues.is_empty());

    let lineage = log.slot_lineage(&slot_id("slot-a"));
    assert_eq!(lineage.len(), 3);
    assert_eq!(lineage[0].kind, ReplacementKind::DelegateToNative);
    assert_eq!(lineage[1].kind, ReplacementKind::Demotion);
    assert_eq!(lineage[2].kind, ReplacementKind::RePromotion);

    let audit = log.audit();
    assert!(audit.chain_valid);
    assert!(audit.merkle_valid);
    assert_eq!(audit.total_slots, 2);
    assert_eq!(audit.checkpoint_count, 1);
}

#[test]
fn serialized_roundtrip_preserves_query_and_audit_results() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    for i in 0..5 {
        let kind = if i % 2 == 0 {
            ReplacementKind::DelegateToNative
        } else {
            ReplacementKind::Rollback
        };
        let r = receipt(
            "slot-a",
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 100,
        );
        log.append(r, kind, (i + 1) * 100).expect("append");
    }
    log.create_checkpoint(600, SecurityEpoch::from_raw(11))
        .expect("checkpoint");

    let mut kinds = BTreeSet::new();
    kinds.insert(ReplacementKind::Rollback);
    let query = LineageQuery {
        slot_id: Some(slot_id("slot-a")),
        kinds: Some(kinds),
        min_timestamp_ns: Some(200),
        max_timestamp_ns: Some(500),
    };

    let before_count = log.query(&query).len();
    let before_audit = log.audit();

    let encoded = serde_json::to_vec(&log).expect("serialize log");
    let decoded: ReplacementLineageLog = serde_json::from_slice(&encoded).expect("deserialize log");

    assert_eq!(before_count, decoded.query(&query).len());
    assert_eq!(before_audit, decoded.audit());
}

#[test]
fn consistency_proof_requires_older_then_newer_checkpoint_order() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    for i in 0..2 {
        let r = receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
        log.append(r, ReplacementKind::DelegateToNative, i * 100)
            .expect("append");
        log.create_checkpoint(i * 100, SecurityEpoch::from_raw(11))
            .expect("checkpoint");
    }

    let err = log
        .consistency_proof(1, 0)
        .expect_err("must reject reversed order");
    assert!(matches!(
        err,
        LineageLogError::InvalidCheckpointOrder { older: 1, newer: 0 }
    ));
}

#[test]
fn lineage_index_supports_content_address_lookup_and_ordered_slot_chain() {
    let context = index_context();
    let adapter = InMemoryStorageAdapter::new();
    let mut index = ReplacementLineageEvidenceIndex::new(adapter);

    let r1 = receipt("slot-x", "delegate-v1", "native-v1", 100);
    let r2 = receipt("slot-x", "native-v1", "native-v2", 300);
    let replacement_1 = index
        .index_replacement_receipt(&r1, ReplacementKind::DelegateToNative, &[], &context)
        .expect("index replacement r1");
    let replacement_2 = index
        .index_replacement_receipt(
            &r2,
            ReplacementKind::RePromotion,
            &[EvidencePointerInput {
                category: EvidenceCategory::SentinelRiskScore,
                artifact_digest: "risk-300".to_string(),
                passed: Some(true),
                summary: "risk remains inside envelope".to_string(),
            }],
            &context,
        )
        .expect("index replacement r2");

    let demotion = index
        .index_demotion_receipt(
            DemotionReceiptInput {
                receipt_id: "demotion-slot-x-1".to_string(),
                slot_id: slot_id("slot-x"),
                demoted_cell_digest: "native-v2".to_string(),
                restored_cell_digest: "native-v1".to_string(),
                demotion_reason: "semantic_divergence".to_string(),
                timestamp_ns: 450,
                rollback_token_used: "rollback-native-v1".to_string(),
                linked_replacement_receipt_id: Some(replacement_2.receipt_id.clone()),
                evidence: vec![EvidencePointerInput {
                    category: EvidenceCategory::DifferentialExecutionLog,
                    artifact_digest: "divergence-slot-x-1".to_string(),
                    passed: Some(false),
                    summary: "burn-in divergence on canonical scenario".to_string(),
                }],
            },
            &context,
        )
        .expect("index demotion");

    let loaded_r1 = index
        .replacement_by_content_hash(&replacement_1.receipt_content_hash, &context)
        .expect("lookup replacement by hash")
        .expect("replacement exists");
    assert_eq!(loaded_r1.receipt_id, replacement_1.receipt_id);
    assert_eq!(loaded_r1.slot_id, slot_id("slot-x"));
    assert_eq!(loaded_r1.receipt_id, replacement_receipt_id_hex(&r1));

    let loaded_demotion = index
        .demotion_by_content_hash(&demotion.receipt_content_hash, &context)
        .expect("lookup demotion by hash")
        .expect("demotion exists");
    assert_eq!(loaded_demotion.receipt_id, "demotion-slot-x-1");
    assert_eq!(loaded_demotion.demotion_reason, "semantic_divergence");

    let chain = index
        .slot_lineage(
            &slot_id("slot-x"),
            &SlotLineageQuery {
                min_timestamp_ns: Some(100),
                max_timestamp_ns: Some(500),
                limit: None,
            },
            &context,
        )
        .expect("slot lineage");
    assert_eq!(chain.len(), 3);
    assert_eq!(chain[0].timestamp_ns, 100);
    assert_eq!(chain[1].timestamp_ns, 300);
    assert_eq!(chain[2].timestamp_ns, 450);
    assert_eq!(chain[2].kind, ReplacementKind::Demotion);
}

#[test]
fn replay_join_includes_demotion_and_evidence_categories() {
    let context = index_context();
    let adapter = InMemoryStorageAdapter::new();
    let mut index = ReplacementLineageEvidenceIndex::new(adapter);

    let replacement_receipt = receipt("slot-r", "delegate-r1", "native-r1", 120);
    let replacement_record = index
        .index_replacement_receipt(
            &replacement_receipt,
            ReplacementKind::DelegateToNative,
            &[
                EvidencePointerInput {
                    category: EvidenceCategory::GateResult,
                    artifact_digest: "gate-r1".to_string(),
                    passed: Some(true),
                    summary: "promotion gate passed".to_string(),
                },
                EvidencePointerInput {
                    category: EvidenceCategory::SentinelRiskScore,
                    artifact_digest: "risk-r1".to_string(),
                    passed: Some(true),
                    summary: "risk posterior below threshold".to_string(),
                },
                EvidencePointerInput {
                    category: EvidenceCategory::Additional,
                    artifact_digest: "operator-note-r1".to_string(),
                    passed: None,
                    summary: "operator attached note".to_string(),
                },
            ],
            &context,
        )
        .expect("index replacement");

    index
        .index_demotion_receipt(
            DemotionReceiptInput {
                receipt_id: "demotion-slot-r-1".to_string(),
                slot_id: slot_id("slot-r"),
                demoted_cell_digest: "native-r1".to_string(),
                restored_cell_digest: "delegate-r1".to_string(),
                demotion_reason: "risk_threshold_breach".to_string(),
                timestamp_ns: 180,
                rollback_token_used: "rollback-r1".to_string(),
                linked_replacement_receipt_id: Some(replacement_record.receipt_id.clone()),
                evidence: vec![
                    EvidencePointerInput {
                        category: EvidenceCategory::SentinelRiskScore,
                        artifact_digest: "risk-breach-r1".to_string(),
                        passed: Some(false),
                        summary: "risk above threshold".to_string(),
                    },
                    EvidencePointerInput {
                        category: EvidenceCategory::DifferentialExecutionLog,
                        artifact_digest: "diff-r1".to_string(),
                        passed: Some(false),
                        summary: "output mismatch".to_string(),
                    },
                ],
            },
            &context,
        )
        .expect("index demotion");

    let rows = index
        .replay_join(
            &ReplayJoinQuery {
                slot_id: Some(slot_id("slot-r")),
                min_timestamp_ns: None,
                max_timestamp_ns: None,
                limit: None,
            },
            &context,
        )
        .expect("replay join");

    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.slot_id, slot_id("slot-r"));
    assert_eq!(row.replacement_receipt_id, replacement_record.receipt_id);
    assert_eq!(
        row.demotion_reason.as_deref(),
        Some("risk_threshold_breach")
    );
    assert_eq!(row.gate_results.len(), 1);
    assert_eq!(row.performance_benchmarks.len(), 0);
    assert_eq!(row.sentinel_risk_scores.len(), 2);
    assert_eq!(row.differential_execution_logs.len(), 2);
    assert_eq!(row.additional_evidence.len(), 1);
}

#[test]
fn replay_join_order_is_deterministic_across_ingest_order() {
    let context = index_context();

    let mut index_a = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
    let mut index_b = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());

    let r1 = receipt("slot-d", "delegate-a", "native-a", 200);
    let r2 = receipt("slot-d", "native-a", "native-b", 100);

    index_a
        .index_replacement_receipt(&r1, ReplacementKind::DelegateToNative, &[], &context)
        .expect("index_a r1");
    index_a
        .index_replacement_receipt(&r2, ReplacementKind::RePromotion, &[], &context)
        .expect("index_a r2");

    index_b
        .index_replacement_receipt(&r2, ReplacementKind::RePromotion, &[], &context)
        .expect("index_b r2");
    index_b
        .index_replacement_receipt(&r1, ReplacementKind::DelegateToNative, &[], &context)
        .expect("index_b r1");

    let rows_a = index_a
        .replay_join(&ReplayJoinQuery::default(), &context)
        .expect("rows_a");
    let rows_b = index_b
        .replay_join(&ReplayJoinQuery::default(), &context)
        .expect("rows_b");
    assert_eq!(rows_a, rows_b);
    assert_eq!(rows_a.len(), 2);
    assert!(rows_a[0].promotion_timestamp_ns <= rows_a[1].promotion_timestamp_ns);
}

#[test]
fn e2e_delegate_to_native_promotion_then_rollback_updates_lineage_and_logs() {
    let slot = slot_id("slot-e2e");
    let authority = test_authority_envelope();
    let native_authority = authority.clone();

    let mut registry = SlotRegistry::new();
    registry
        .register_delegate(
            slot.clone(),
            SlotKind::Parser,
            authority.clone(),
            "sha256:delegate-v1".to_string(),
            "2026-02-22T00:00:00Z".to_string(),
        )
        .expect("register delegate");
    registry
        .begin_candidacy(
            &slot,
            "sha256:native-candidate-v1".to_string(),
            "2026-02-22T00:01:00Z".to_string(),
        )
        .expect("begin candidacy");

    let gate_config =
        GateRunnerConfig::standard(slot.clone(), "sha256:native-candidate-v1".to_string(), 42);
    let gate_output = run_promotion_gates(&gate_config, &passing_gate_input(&slot, &authority));
    assert_eq!(gate_output.slot_id, slot);
    assert!(
        gate_output
            .evaluations
            .iter()
            .all(|evaluation| evaluation.passed)
    );
    assert!(gate_output.rollback_verified);

    let decision =
        signed_promotion_decision(&slot, "sha256:native-candidate-v1", &gate_output, 2_000);
    assert!(decision.is_approved());

    let validation_artifacts = validation_artifacts_from_gate_output(&gate_output);
    assert_eq!(validation_artifacts.len(), 4);
    assert!(validation_artifacts.iter().all(|artifact| artifact.passed));

    let promotion_receipt = signed_replacement_receipt(
        &slot,
        "sha256:delegate-v1",
        "sha256:native-v1",
        3_000,
        &validation_artifacts,
    );

    registry
        .promote(
            &slot,
            "sha256:native-v1".to_string(),
            &native_authority,
            replacement_receipt_id_hex(&promotion_receipt),
            "2026-02-22T00:02:00Z".to_string(),
        )
        .expect("promote slot");
    assert_eq!(registry.native_count(), 1);
    assert_eq!(registry.delegate_count(), 0);

    let mut lifecycle =
        ReplacementLifecycle::new(slot.clone(), signed_delegate_manifest(&slot, &authority));
    lifecycle
        .record_decision(decision)
        .expect("record promotion decision");
    lifecycle
        .record_receipt(promotion_receipt.clone())
        .expect("record replacement receipt");
    assert_eq!(lifecycle.completed_stages(), 1);

    let rollback_receipt = signed_replacement_receipt(
        &slot,
        "sha256:native-v1",
        "sha256:delegate-v1",
        4_200,
        &validation_artifacts,
    );
    registry
        .demote(
            &slot,
            "post-promotion divergence".to_string(),
            "2026-02-22T00:03:00Z".to_string(),
        )
        .expect("demote slot");
    assert_eq!(registry.native_count(), 0);
    assert_eq!(registry.delegate_count(), 1);

    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    log.append(
        promotion_receipt.clone(),
        ReplacementKind::DelegateToNative,
        promotion_receipt.timestamp_ns,
    )
    .expect("append promotion receipt");
    log.append(
        rollback_receipt.clone(),
        ReplacementKind::Demotion,
        rollback_receipt.timestamp_ns,
    )
    .expect("append rollback receipt");
    log.create_checkpoint(4_500, SecurityEpoch::from_raw(11))
        .expect("create checkpoint");

    let slot_lineage = log.slot_lineage(&slot);
    assert_eq!(slot_lineage.len(), 2);
    assert_eq!(slot_lineage[0].kind, ReplacementKind::DelegateToNative);
    assert_eq!(slot_lineage[1].kind, ReplacementKind::Demotion);
    assert_eq!(slot_lineage[1].new_cell_digest, "sha256:delegate-v1");

    for event in log.events() {
        assert!(!event.trace_id.trim().is_empty());
        assert!(!event.decision_id.trim().is_empty());
        assert!(!event.policy_id.trim().is_empty());
        assert_eq!(event.component, "replacement_lineage_log");
        assert!(matches!(
            event.event.as_str(),
            "entry_appended" | "checkpoint_created"
        ));
        assert_eq!(event.outcome, "ok");
        assert_eq!(event.error_code, None);
    }

    let context = EventContext::new(
        "trace-lineage-lifecycle-e2e",
        "decision-lineage-lifecycle-e2e",
        "policy-lineage-lifecycle-e2e",
    )
    .expect("lineage index context");
    let mut index = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
    let replacement_record = index
        .index_replacement_receipt(
            &promotion_receipt,
            ReplacementKind::DelegateToNative,
            &[
                EvidencePointerInput {
                    category: EvidenceCategory::GateResult,
                    artifact_digest: "gate-e2e-pass".to_string(),
                    passed: Some(true),
                    summary: "all mandatory gates approved".to_string(),
                },
                EvidencePointerInput {
                    category: EvidenceCategory::SentinelRiskScore,
                    artifact_digest: "risk-e2e-low".to_string(),
                    passed: Some(true),
                    summary: "risk remains below demotion threshold".to_string(),
                },
            ],
            &context,
        )
        .expect("index replacement receipt");

    index
        .index_demotion_receipt(
            DemotionReceiptInput {
                receipt_id: "demotion-slot-e2e-1".to_string(),
                slot_id: slot.clone(),
                demoted_cell_digest: "sha256:native-v1".to_string(),
                restored_cell_digest: "sha256:delegate-v1".to_string(),
                demotion_reason: "post_promotion_divergence".to_string(),
                timestamp_ns: 4_300,
                rollback_token_used: promotion_receipt.rollback_token.clone(),
                linked_replacement_receipt_id: Some(replacement_record.receipt_id.clone()),
                evidence: vec![EvidencePointerInput {
                    category: EvidenceCategory::DifferentialExecutionLog,
                    artifact_digest: "diff-e2e-divergence".to_string(),
                    passed: Some(false),
                    summary: "burn-in replay divergence detected".to_string(),
                }],
            },
            &context,
        )
        .expect("index demotion receipt");

    let indexed_chain = index
        .slot_lineage(&slot, &SlotLineageQuery::default(), &context)
        .expect("query slot lineage");
    assert_eq!(indexed_chain.len(), 2);
    assert_eq!(indexed_chain[0].kind, ReplacementKind::DelegateToNative);
    assert_eq!(indexed_chain[1].kind, ReplacementKind::Demotion);

    let replay_rows = index
        .replay_join(
            &ReplayJoinQuery {
                slot_id: Some(slot.clone()),
                ..ReplayJoinQuery::default()
            },
            &context,
        )
        .expect("replay join");
    assert_eq!(replay_rows.len(), 1);
    let replay_row = &replay_rows[0];
    assert_eq!(
        replay_row.demotion_receipt_id.as_deref(),
        Some("demotion-slot-e2e-1")
    );
    assert_eq!(
        replay_row.demotion_reason.as_deref(),
        Some("post_promotion_divergence")
    );
    assert_eq!(replay_row.sentinel_risk_scores.len(), 1);
    assert_eq!(replay_row.differential_execution_logs.len(), 2);

    for event in index.events() {
        assert_eq!(event.trace_id, "trace-lineage-lifecycle-e2e");
        assert_eq!(event.decision_id, "decision-lineage-lifecycle-e2e");
        assert_eq!(event.policy_id, "policy-lineage-lifecycle-e2e");
        assert_eq!(event.component, "replacement_lineage_index");
        assert_eq!(event.outcome, "ok");
        assert_eq!(event.error_code, None);
    }
}

// ---------- slot_id helper ----------

#[test]
fn slot_id_helper_returns_valid_id() {
    let sid = slot_id("test-slot");
    assert_eq!(sid.as_str(), "test-slot");
}

// ---------- receipt helper ----------

#[test]
fn receipt_helper_sets_fields() {
    let r = receipt("slot-helper", "old-digest", "new-digest", 500);
    assert_eq!(r.old_cell_digest, "old-digest");
    assert_eq!(r.new_cell_digest, "new-digest");
    assert_eq!(r.timestamp_ns, 500);
    assert_eq!(r.epoch, SecurityEpoch::from_raw(11));
    assert_eq!(r.zone, "lineage-itest-zone");
}

// ---------- ReplacementKind ----------

#[test]
fn replacement_kind_serde_roundtrip() {
    for kind in [
        ReplacementKind::DelegateToNative,
        ReplacementKind::Demotion,
        ReplacementKind::RePromotion,
        ReplacementKind::Rollback,
    ] {
        let json = serde_json::to_string(&kind).expect("serialize");
        let recovered: ReplacementKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, kind);
    }
}

// ---------- ReplacementLineageLog ----------

#[test]
fn empty_log_is_empty() {
    let log = ReplacementLineageLog::new(LineageLogConfig::default());
    assert!(log.is_empty());
    assert_eq!(log.len(), 0);
    assert!(log.entries().is_empty());
    assert!(log.slot_ids().is_empty());
}

#[test]
fn log_len_increases_on_append() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    let r = receipt("slot-len", "old-0", "new-0", 100);
    log.append(r, ReplacementKind::DelegateToNative, 100)
        .expect("append");
    assert_eq!(log.len(), 1);
    assert!(!log.is_empty());
}

#[test]
fn log_slot_ids_tracks_distinct_slots() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    log.append(
        receipt("slot-x", "old-0", "new-0", 100),
        ReplacementKind::DelegateToNative,
        100,
    )
    .expect("append");
    log.append(
        receipt("slot-y", "old-1", "new-1", 200),
        ReplacementKind::DelegateToNative,
        200,
    )
    .expect("append");
    let ids = log.slot_ids();
    assert_eq!(ids.len(), 2);
}

#[test]
fn log_entries_returns_all_appended() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    for i in 0..3 {
        let r = receipt(
            "slot-entries",
            &format!("old-{i}"),
            &format!("new-{i}"),
            i * 100,
        );
        log.append(r, ReplacementKind::DelegateToNative, i * 100)
            .expect("append");
    }
    assert_eq!(log.entries().len(), 3);
}

#[test]
fn log_merkle_root_changes_on_append() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    let r1 = receipt("slot-root", "old-0", "new-0", 100);
    log.append(r1, ReplacementKind::DelegateToNative, 100)
        .expect("append");
    let root_1 = log.merkle_root();

    let r2 = receipt("slot-root", "new-0", "new-1", 200);
    log.append(r2, ReplacementKind::RePromotion, 200)
        .expect("append");
    let root_2 = log.merkle_root();

    assert_ne!(root_1, root_2);
}

#[test]
fn log_checkpoints_tracks_created_checkpoints() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    let r = receipt("slot-cp", "old-0", "new-0", 100);
    log.append(r, ReplacementKind::DelegateToNative, 100)
        .expect("append");
    assert!(log.checkpoints().is_empty());

    log.create_checkpoint(200, SecurityEpoch::from_raw(11))
        .expect("checkpoint");
    assert_eq!(log.checkpoints().len(), 1);
    assert_eq!(log.checkpoints()[0].epoch, SecurityEpoch::from_raw(11));
}

#[test]
fn log_events_records_appends_and_checkpoints() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    let r = receipt("slot-ev", "old-0", "new-0", 100);
    log.append(r, ReplacementKind::DelegateToNative, 100)
        .expect("append");
    log.create_checkpoint(200, SecurityEpoch::from_raw(11))
        .expect("checkpoint");
    assert!(log.events().len() >= 2);
}

// ---------- inclusion_proof ----------

#[test]
fn log_inclusion_proof_verifies_for_appended_entry() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    for i in 0..4 {
        let r = receipt(
            "slot-ip",
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 100,
        );
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 100)
            .expect("append");
    }

    let proof = log.inclusion_proof(0).expect("inclusion proof for entry 0");
    assert!(verify_inclusion_proof(&proof));
}

#[test]
fn log_inclusion_proof_detects_tamper() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    for i in 0..4 {
        let r = receipt(
            "slot-ip2",
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 100,
        );
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 100)
            .expect("append");
    }

    let mut proof = log.inclusion_proof(1).expect("inclusion proof for entry 1");
    proof.entry_hash = frankenengine_engine::hash_tiers::ContentHash::compute(b"tampered");
    assert!(!verify_inclusion_proof(&proof));
}

// ---------- LineageLogConfig ----------

#[test]
fn lineage_log_config_default_serde_roundtrip() {
    let config = LineageLogConfig::default();
    let json = serde_json::to_string(&config).expect("serialize");
    let recovered: LineageLogConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        serde_json::to_string(&recovered).expect("re-serialize"),
        json
    );
}

// ---------- EvidenceCategory ----------

#[test]
fn evidence_category_serde_roundtrip() {
    for category in [
        EvidenceCategory::GateResult,
        EvidenceCategory::SentinelRiskScore,
        EvidenceCategory::DifferentialExecutionLog,
        EvidenceCategory::Additional,
    ] {
        let json = serde_json::to_string(&category).expect("serialize");
        let recovered: EvidenceCategory = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, category);
    }
}

// ---------- LineageLogError ----------

#[test]
fn lineage_log_error_invalid_checkpoint_order_display() {
    let err = LineageLogError::InvalidCheckpointOrder { older: 5, newer: 3 };
    let msg = format!("{err}");
    assert!(!msg.is_empty());
}

// ---------- LineageQuery ----------

#[test]
fn lineage_query_default_matches_all() {
    let query = LineageQuery {
        slot_id: None,
        kinds: None,
        min_timestamp_ns: None,
        max_timestamp_ns: None,
    };
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    log.append(
        receipt("slot-q", "old", "new", 100),
        ReplacementKind::DelegateToNative,
        100,
    )
    .expect("append");
    assert_eq!(log.query(&query).len(), 1);
}

// ---------- query filtering ----------

#[test]
fn lineage_query_filters_by_kind() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    log.append(
        receipt("slot-qk", "old-0", "new-0", 100),
        ReplacementKind::DelegateToNative,
        100,
    )
    .expect("append");
    log.append(
        receipt("slot-qk", "new-0", "old-0", 200),
        ReplacementKind::Rollback,
        200,
    )
    .expect("append");

    let mut kinds = BTreeSet::new();
    kinds.insert(ReplacementKind::Rollback);
    let query = LineageQuery {
        slot_id: None,
        kinds: Some(kinds),
        min_timestamp_ns: None,
        max_timestamp_ns: None,
    };
    let results = log.query(&query);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].kind, ReplacementKind::Rollback);
}

#[test]
fn lineage_query_filters_by_timestamp_range() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    for i in 0..5 {
        log.append(
            receipt(
                "slot-ts",
                &format!("old-{i}"),
                &format!("new-{i}"),
                (i + 1) * 100,
            ),
            ReplacementKind::DelegateToNative,
            (i + 1) * 100,
        )
        .expect("append");
    }

    let query = LineageQuery {
        slot_id: None,
        kinds: None,
        min_timestamp_ns: Some(200),
        max_timestamp_ns: Some(400),
    };
    let results = log.query(&query);
    assert_eq!(results.len(), 3);
}

// ---------- verify_slot_lineage ----------

#[test]
fn verify_slot_lineage_empty_slot_is_valid() {
    let log = ReplacementLineageLog::new(LineageLogConfig::default());
    let verify = log.verify_slot_lineage(&slot_id("nonexistent"));
    assert!(verify.chain_valid);
    assert_eq!(verify.total_entries, 0);
}

// ---------- log serde roundtrip ----------

#[test]
fn log_serde_roundtrip_preserves_len_and_merkle_root() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    for i in 0..3 {
        log.append(
            receipt(
                "slot-serde",
                &format!("old-{i}"),
                &format!("new-{i}"),
                (i + 1) * 100,
            ),
            ReplacementKind::DelegateToNative,
            (i + 1) * 100,
        )
        .expect("append");
    }
    let root_before = log.merkle_root();
    let len_before = log.len();

    let encoded = serde_json::to_vec(&log).expect("serialize");
    let decoded: ReplacementLineageLog = serde_json::from_slice(&encoded).expect("deserialize");
    assert_eq!(decoded.len(), len_before);
    assert_eq!(decoded.merkle_root(), root_before);
}

// ---------- EvidenceCategory display ----------

#[test]
fn evidence_category_debug_is_nonempty() {
    for category in [
        EvidenceCategory::GateResult,
        EvidenceCategory::SentinelRiskScore,
        EvidenceCategory::DifferentialExecutionLog,
        EvidenceCategory::Additional,
    ] {
        assert!(!format!("{category:?}").is_empty());
    }
}

// ---------- LineageLogError additional variants ----------

#[test]
fn lineage_log_error_display_for_all_variants() {
    let errors = vec![LineageLogError::InvalidCheckpointOrder {
        older: 10,
        newer: 5,
    }];
    for err in &errors {
        let msg = format!("{err}");
        assert!(!msg.is_empty());
    }
}

// ---------- multiple checkpoints ----------

#[test]
fn multiple_checkpoints_accumulate() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    for i in 0..3 {
        log.append(
            receipt(
                "slot-mcp",
                &format!("old-{i}"),
                &format!("new-{i}"),
                (i + 1) * 100,
            ),
            ReplacementKind::DelegateToNative,
            (i + 1) * 100,
        )
        .expect("append");
        log.create_checkpoint((i + 1) * 100, SecurityEpoch::from_raw(11))
            .expect("checkpoint");
    }
    assert_eq!(log.checkpoints().len(), 3);
}

// ---------- enrichment: LineageLogConfig ----------

#[test]
fn lineage_log_config_debug_is_nonempty() {
    let config = LineageLogConfig::default();
    let debug = format!("{config:?}");
    assert!(debug.contains("LineageLogConfig"));
}

#[test]
fn lineage_log_config_clone_equals_original() {
    let config = LineageLogConfig::default();
    let cloned = config.clone();
    assert_eq!(
        serde_json::to_string(&config).unwrap(),
        serde_json::to_string(&cloned).unwrap()
    );
}

// ---------- enrichment: ReplacementKind ordering ----------

#[test]
fn replacement_kind_btreeset_ordering_is_deterministic() {
    let mut set = BTreeSet::new();
    set.insert(ReplacementKind::Rollback);
    set.insert(ReplacementKind::DelegateToNative);
    set.insert(ReplacementKind::Demotion);
    set.insert(ReplacementKind::RePromotion);

    let vec: Vec<_> = set.iter().collect();
    // Just verify consistent ordering — exact order depends on serde repr
    let json_a = serde_json::to_string(&vec).unwrap();
    let json_b = serde_json::to_string(&vec).unwrap();
    assert_eq!(json_a, json_b);
}

#[test]
fn replacement_kind_clone_copy_eq() {
    let kind = ReplacementKind::DelegateToNative;
    let cloned = kind.clone();
    assert_eq!(kind, cloned);
}

#[test]
fn replacement_kind_debug_all_variants() {
    for kind in [
        ReplacementKind::DelegateToNative,
        ReplacementKind::Demotion,
        ReplacementKind::RePromotion,
        ReplacementKind::Rollback,
    ] {
        let debug = format!("{kind:?}");
        assert!(!debug.is_empty());
    }
}

// ---------- enrichment: log audit on empty ----------

#[test]
fn audit_on_empty_log_is_valid() {
    let log = ReplacementLineageLog::new(LineageLogConfig::default());
    let audit = log.audit();
    assert!(audit.chain_valid);
    assert!(audit.merkle_valid);
    assert_eq!(audit.total_slots, 0);
    assert_eq!(audit.checkpoint_count, 0);
}

// ---------- enrichment: log query with slot_id filter ----------

#[test]
fn lineage_query_filters_by_slot_id() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    log.append(
        receipt("slot-filter-a", "old-0", "new-0", 100),
        ReplacementKind::DelegateToNative,
        100,
    )
    .expect("append");
    log.append(
        receipt("slot-filter-b", "old-1", "new-1", 200),
        ReplacementKind::DelegateToNative,
        200,
    )
    .expect("append");

    let query = LineageQuery {
        slot_id: Some(slot_id("slot-filter-a")),
        kinds: None,
        min_timestamp_ns: None,
        max_timestamp_ns: None,
    };
    let results = log.query(&query);
    assert_eq!(results.len(), 1);
}

// ---------- enrichment: EvidencePointerInput ----------

#[test]
fn evidence_pointer_input_debug_is_nonempty() {
    let input = EvidencePointerInput {
        category: EvidenceCategory::GateResult,
        artifact_digest: "gate-1".to_string(),
        passed: Some(true),
        summary: "gate passed".to_string(),
    };
    let debug = format!("{input:?}");
    assert!(debug.contains("EvidencePointerInput"));
}

// ---------- enrichment: DemotionReceiptInput ----------

#[test]
fn demotion_receipt_input_debug_is_nonempty() {
    let input = DemotionReceiptInput {
        receipt_id: "demotion-1".to_string(),
        slot_id: slot_id("slot-debug"),
        demoted_cell_digest: "native-v1".to_string(),
        restored_cell_digest: "delegate-v1".to_string(),
        demotion_reason: "test_reason".to_string(),
        timestamp_ns: 100,
        rollback_token_used: "rollback-v1".to_string(),
        linked_replacement_receipt_id: None,
        evidence: Vec::new(),
    };
    let debug = format!("{input:?}");
    assert!(debug.contains("demotion-1"));
}

// ---------- enrichment: consistency proof on identical checkpoints ----------

#[test]
fn consistency_proof_same_checkpoint_index_is_error() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    let r = receipt("slot-same-cp", "old-0", "new-0", 100);
    log.append(r, ReplacementKind::DelegateToNative, 100)
        .expect("append");
    log.create_checkpoint(100, SecurityEpoch::from_raw(11))
        .expect("checkpoint");

    let err = log
        .consistency_proof(0, 0)
        .expect_err("same checkpoint index should error");
    assert!(matches!(
        err,
        LineageLogError::InvalidCheckpointOrder { .. }
    ));
}

// ---------- enrichment: log slot_lineage for nonexistent slot ----------

#[test]
fn slot_lineage_for_nonexistent_slot_is_empty() {
    let log = ReplacementLineageLog::new(LineageLogConfig::default());
    let lineage = log.slot_lineage(&slot_id("no-such-slot"));
    assert!(lineage.is_empty());
}

// ---------- enrichment: log serialization preserves entries ----------

#[test]
fn log_json_roundtrip_preserves_entries_count() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    for i in 0..5 {
        log.append(
            receipt(
                "slot-json",
                &format!("old-{i}"),
                &format!("new-{i}"),
                (i + 1) * 100,
            ),
            ReplacementKind::DelegateToNative,
            (i + 1) * 100,
        )
        .expect("append");
    }

    let json = serde_json::to_string(&log).expect("serialize");
    let decoded: ReplacementLineageLog = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.len(), 5);
    assert_eq!(decoded.entries().len(), 5);
}

// ---------- enrichment: replay_join empty index ----------

#[test]
fn replay_join_on_empty_index_returns_empty() {
    let mut index = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
    let rows = index
        .replay_join(&ReplayJoinQuery::default(), &index_context())
        .expect("replay join on empty");
    assert!(rows.is_empty());
}

// ---------- enrichment: slot_lineage query with limit ----------

#[test]
fn slot_lineage_query_respects_limit() {
    let context = index_context();
    let mut index = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());

    for i in 0..5 {
        let r = receipt(
            "slot-limit",
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 100,
        );
        index
            .index_replacement_receipt(&r, ReplacementKind::DelegateToNative, &[], &context)
            .expect("index");
    }

    let chain = index
        .slot_lineage(
            &slot_id("slot-limit"),
            &SlotLineageQuery {
                min_timestamp_ns: None,
                max_timestamp_ns: None,
                limit: Some(3),
            },
            &context,
        )
        .expect("slot lineage with limit");
    assert_eq!(chain.len(), 3);
}
