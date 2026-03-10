#![forbid(unsafe_code)]
//! Integration tests for the `self_replacement` module.
//!
//! Exercises delegate cell manifests, replacement receipts, promotion
//! decisions, replacement lifecycle stages, signature bundles, validation
//! artifacts, and serde round-trips from outside the crate boundary.

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

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::self_replacement::{
    ApproverKind, CreateDecisionInput, CreateManifestInput, CreateReceiptInput,
    DelegateCellManifest, DelegateType, GateResult, GateVerdict, MonitoringHook, PromotionDecision,
    ReplacementLifecycle, ReplacementReceipt, ReplacementStage, RiskLevel, SandboxConfiguration,
    SchemaVersion, SelfReplacementError, SignatureBundle, SignerEntry, ValidationArtifactKind,
    ValidationArtifactRef,
};
use frankenengine_engine::signature_preimage::{SigningKey, VerificationKey};
use frankenengine_engine::slot_registry::{AuthorityEnvelope, SlotCapability, SlotId};

// ===========================================================================
// Helpers
// ===========================================================================

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(7)
}

fn test_slot_id() -> SlotId {
    SlotId::new("parser-slot-1").unwrap()
}

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes([1u8; 32])
}

fn test_signing_key_2() -> SigningKey {
    SigningKey::from_bytes([2u8; 32])
}

fn test_behavior_hash() -> [u8; 32] {
    [0xAB; 32]
}

fn test_envelope() -> AuthorityEnvelope {
    AuthorityEnvelope {
        required: vec![SlotCapability::ReadSource, SlotCapability::EmitIr],
        permitted: vec![
            SlotCapability::ReadSource,
            SlotCapability::EmitIr,
            SlotCapability::HeapAlloc,
        ],
    }
}

fn test_sandbox() -> SandboxConfiguration {
    SandboxConfiguration {
        max_heap_bytes: 32 * 1024 * 1024,
        max_execution_ns: 2_000_000_000,
        max_hostcalls: 5_000,
        network_egress_allowed: false,
        filesystem_access_allowed: false,
    }
}

fn test_monitoring_hooks() -> Vec<MonitoringHook> {
    vec![MonitoringHook {
        hook_id: "hook-1".into(),
        trigger_event: "decision-made".into(),
        blocking: false,
    }]
}

fn create_test_manifest() -> DelegateCellManifest {
    let sk = test_signing_key();
    let sandbox = test_sandbox();
    let envelope = test_envelope();
    let hooks = test_monitoring_hooks();
    let bh = test_behavior_hash();

    DelegateCellManifest::create_signed(
        &sk,
        CreateManifestInput {
            slot_id: &test_slot_id(),
            delegate_type: DelegateType::QuickJsBacked,
            capability_envelope: &envelope,
            sandbox: &sandbox,
            monitoring_hooks: &hooks,
            expected_behavior_hash: &bh,
            zone: "zone-a",
        },
    )
    .unwrap()
}

fn test_validation_artifacts() -> Vec<ValidationArtifactRef> {
    vec![
        ValidationArtifactRef {
            kind: ValidationArtifactKind::EquivalenceResult,
            artifact_digest: "digest-equiv-001".into(),
            passed: true,
            summary: "All equivalence tests passed".into(),
        },
        ValidationArtifactRef {
            kind: ValidationArtifactKind::CapabilityPreservation,
            artifact_digest: "digest-cap-001".into(),
            passed: true,
            summary: "Capabilities preserved".into(),
        },
        ValidationArtifactRef {
            kind: ValidationArtifactKind::PerformanceBenchmark,
            artifact_digest: "digest-perf-001".into(),
            passed: true,
            summary: "Within performance budget".into(),
        },
        ValidationArtifactRef {
            kind: ValidationArtifactKind::AdversarialSurvival,
            artifact_digest: "digest-adv-001".into(),
            passed: true,
            summary: "Adversarial suite passed".into(),
        },
    ]
}

fn test_gate_results_all_pass() -> Vec<GateResult> {
    vec![
        GateResult {
            gate_name: "equivalence-gate".into(),
            passed: true,
            evidence_refs: vec!["evidence-1".into()],
            summary: "All tests passed".into(),
        },
        GateResult {
            gate_name: "performance-gate".into(),
            passed: true,
            evidence_refs: vec!["evidence-2".into()],
            summary: "Within budget".into(),
        },
    ]
}

// ===========================================================================
// 1. SchemaVersion
// ===========================================================================

#[test]
fn schema_version_display() {
    assert_eq!(SchemaVersion::V1.to_string(), "v1");
}

#[test]
fn schema_version_v1_is_current() {
    // V1 is the only version and should be usable
    let v = SchemaVersion::V1;
    assert_eq!(v, SchemaVersion::V1);
}

#[test]
fn schema_version_serde_round_trip() {
    let v = SchemaVersion::V1;
    let json = serde_json::to_string(&v).unwrap();
    let back: SchemaVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

// ===========================================================================
// 2. DelegateType
// ===========================================================================

#[test]
fn delegate_type_display() {
    assert_eq!(DelegateType::QuickJsBacked.to_string(), "quickjs-backed");
    assert_eq!(DelegateType::WasmBacked.to_string(), "wasm-backed");
    assert_eq!(
        DelegateType::ExternalProcess.to_string(),
        "external-process"
    );
}

#[test]
fn delegate_type_serde_round_trip() {
    let types = [
        DelegateType::QuickJsBacked,
        DelegateType::WasmBacked,
        DelegateType::ExternalProcess,
    ];
    for dt in &types {
        let json = serde_json::to_string(dt).unwrap();
        let back: DelegateType = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, dt);
    }
}

// ===========================================================================
// 3. ValidationArtifactKind
// ===========================================================================

#[test]
fn validation_artifact_kind_display() {
    assert_eq!(
        ValidationArtifactKind::EquivalenceResult.to_string(),
        "equivalence"
    );
    assert_eq!(
        ValidationArtifactKind::CapabilityPreservation.to_string(),
        "capability-preservation"
    );
    assert_eq!(
        ValidationArtifactKind::PerformanceBenchmark.to_string(),
        "performance-benchmark"
    );
    assert_eq!(
        ValidationArtifactKind::AdversarialSurvival.to_string(),
        "adversarial-survival"
    );
}

#[test]
fn validation_artifact_kind_serde_round_trip() {
    let kinds = [
        ValidationArtifactKind::EquivalenceResult,
        ValidationArtifactKind::CapabilityPreservation,
        ValidationArtifactKind::PerformanceBenchmark,
        ValidationArtifactKind::AdversarialSurvival,
    ];
    for k in &kinds {
        let json = serde_json::to_string(k).unwrap();
        let back: ValidationArtifactKind = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, k);
    }
}

// ===========================================================================
// 4. GateVerdict
// ===========================================================================

#[test]
fn gate_verdict_display() {
    assert_eq!(GateVerdict::Approved.to_string(), "approved");
    assert_eq!(GateVerdict::Denied.to_string(), "denied");
    assert_eq!(GateVerdict::Inconclusive.to_string(), "inconclusive");
}

#[test]
fn gate_verdict_serde_round_trip() {
    for v in [
        GateVerdict::Approved,
        GateVerdict::Denied,
        GateVerdict::Inconclusive,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }
}

// ===========================================================================
// 5. RiskLevel
// ===========================================================================

#[test]
fn risk_level_ordering() {
    assert!(RiskLevel::Low < RiskLevel::Medium);
    assert!(RiskLevel::Medium < RiskLevel::High);
    assert!(RiskLevel::High < RiskLevel::Critical);
}

#[test]
fn risk_level_display() {
    assert_eq!(RiskLevel::Low.to_string(), "low");
    assert_eq!(RiskLevel::Medium.to_string(), "medium");
    assert_eq!(RiskLevel::High.to_string(), "high");
    assert_eq!(RiskLevel::Critical.to_string(), "critical");
}

#[test]
fn risk_level_serde_round_trip() {
    for r in [
        RiskLevel::Low,
        RiskLevel::Medium,
        RiskLevel::High,
        RiskLevel::Critical,
    ] {
        let json = serde_json::to_string(&r).unwrap();
        let back: RiskLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }
}

// ===========================================================================
// 6. ApproverKind
// ===========================================================================

#[test]
fn approver_kind_display() {
    let system = ApproverKind::System {
        component: "gate-runner".into(),
    };
    assert_eq!(system.to_string(), "system:gate-runner");

    let human = ApproverKind::Human {
        operator_id: "ops-42".into(),
    };
    assert_eq!(human.to_string(), "human:ops-42");
}

#[test]
fn approver_kind_serde_round_trip() {
    let kinds = vec![
        ApproverKind::System {
            component: "auto-promoter".into(),
        },
        ApproverKind::Human {
            operator_id: "admin-1".into(),
        },
    ];
    for k in &kinds {
        let json = serde_json::to_string(k).unwrap();
        let back: ApproverKind = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, k);
    }
}

// ===========================================================================
// 7. ReplacementStage
// ===========================================================================

#[test]
fn replacement_stage_ordering() {
    assert!(ReplacementStage::Research < ReplacementStage::Shadow);
    assert!(ReplacementStage::Shadow < ReplacementStage::Canary);
    assert!(ReplacementStage::Canary < ReplacementStage::Production);
}

#[test]
fn replacement_stage_display() {
    assert_eq!(ReplacementStage::Research.to_string(), "research");
    assert_eq!(ReplacementStage::Shadow.to_string(), "shadow");
    assert_eq!(ReplacementStage::Canary.to_string(), "canary");
    assert_eq!(ReplacementStage::Production.to_string(), "production");
}

#[test]
fn replacement_stage_serde_round_trip() {
    for s in [
        ReplacementStage::Research,
        ReplacementStage::Shadow,
        ReplacementStage::Canary,
        ReplacementStage::Production,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: ReplacementStage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

// ===========================================================================
// 8. SelfReplacementError
// ===========================================================================

#[test]
fn error_insufficient_signatures_serde() {
    let err = SelfReplacementError::InsufficientSignatures {
        required: 3,
        present: 1,
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: SelfReplacementError = serde_json::from_str(&json).unwrap();
    assert_eq!(back, err);
}

#[test]
fn error_slot_mismatch_display() {
    let err = SelfReplacementError::SlotMismatch {
        expected: "slot-a".into(),
        got: "slot-b".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("slot-a") || msg.contains("slot-b"));
}

#[test]
fn error_empty_validation_artifacts() {
    let err = SelfReplacementError::EmptyValidationArtifacts;
    let json = serde_json::to_string(&err).unwrap();
    let back: SelfReplacementError = serde_json::from_str(&json).unwrap();
    assert_eq!(back, err);
}

// ===========================================================================
// 9. SandboxConfiguration
// ===========================================================================

#[test]
fn sandbox_configuration_default() {
    let sandbox = SandboxConfiguration::default();
    assert!(sandbox.max_heap_bytes > 0);
    assert!(sandbox.max_execution_ns > 0);
    assert!(sandbox.max_hostcalls > 0);
    assert!(!sandbox.network_egress_allowed);
    assert!(!sandbox.filesystem_access_allowed);
}

#[test]
fn sandbox_configuration_serde_round_trip() {
    let sandbox = test_sandbox();
    let json = serde_json::to_string(&sandbox).unwrap();
    let back: SandboxConfiguration = serde_json::from_str(&json).unwrap();
    assert_eq!(back, sandbox);
}

// ===========================================================================
// 10. MonitoringHook
// ===========================================================================

#[test]
fn monitoring_hook_serde_round_trip() {
    let hook = MonitoringHook {
        hook_id: "mon-1".into(),
        trigger_event: "slot-replaced".into(),
        blocking: true,
    };
    let json = serde_json::to_string(&hook).unwrap();
    let back: MonitoringHook = serde_json::from_str(&json).unwrap();
    assert_eq!(back, hook);
}

// ===========================================================================
// 11. SignatureBundle
// ===========================================================================

#[test]
fn signature_bundle_empty_does_not_meet_threshold() {
    let bundle = SignatureBundle::new(1);
    assert!(!bundle.meets_threshold());
}

#[test]
fn signature_bundle_meets_threshold() {
    let mut bundle = SignatureBundle::new(1);
    let sk = test_signing_key();
    let vk = sk.verification_key();
    // Sign some data manually for the entry
    use frankenengine_engine::signature_preimage::sign_preimage;
    let preimage = b"test-preimage";
    let sig = sign_preimage(&sk, preimage).unwrap();
    bundle.add_signer(SignerEntry {
        role: "gate-runner".into(),
        verification_key: vk,
        signature: sig,
    });
    assert!(bundle.meets_threshold());
}

#[test]
fn signature_bundle_verify_all_valid() {
    let mut bundle = SignatureBundle::new(1);
    let sk = test_signing_key();
    let vk = sk.verification_key();
    use frankenengine_engine::signature_preimage::sign_preimage;
    let preimage = b"verify-me";
    let sig = sign_preimage(&sk, preimage).unwrap();
    bundle.add_signer(SignerEntry {
        role: "verifier".into(),
        verification_key: vk,
        signature: sig,
    });
    assert!(bundle.verify_all(preimage).is_ok());
}

#[test]
fn signature_bundle_verify_all_invalid() {
    let mut bundle = SignatureBundle::new(1);
    let sk = test_signing_key();
    let vk = sk.verification_key();
    use frankenengine_engine::signature_preimage::sign_preimage;
    let sig = sign_preimage(&sk, b"original").unwrap();
    bundle.add_signer(SignerEntry {
        role: "verifier".into(),
        verification_key: vk,
        signature: sig,
    });
    match bundle.verify_all(b"different-preimage") {
        Err(SelfReplacementError::SignatureInvalid { .. }) => {}
        other => panic!("expected SignatureInvalid, got {other:?}"),
    }
}

// ===========================================================================
// 12. DelegateCellManifest
// ===========================================================================

#[test]
fn manifest_create_signed() {
    let manifest = create_test_manifest();
    assert_eq!(manifest.schema_version, SchemaVersion::V1);
    assert_eq!(manifest.delegate_type, DelegateType::QuickJsBacked);
    assert_eq!(manifest.zone, "zone-a");
}

#[test]
fn manifest_id_deterministic() {
    let m1 = create_test_manifest();
    let m2 = create_test_manifest();
    assert_eq!(m1.manifest_id, m2.manifest_id);
}

#[test]
fn manifest_verify_signature() {
    let manifest = create_test_manifest();
    let sk = test_signing_key();
    let vk = sk.verification_key();
    assert!(manifest.verify_signature(&vk).is_ok());
}

#[test]
fn manifest_verify_signature_wrong_key() {
    let manifest = create_test_manifest();
    let wrong_vk = VerificationKey::from_bytes([0xFF; 32]);
    assert!(manifest.verify_signature(&wrong_vk).is_err());
}

#[test]
fn manifest_serde_round_trip() {
    let manifest = create_test_manifest();
    let json = serde_json::to_string(&manifest).unwrap();
    let back: DelegateCellManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(back, manifest);
}

#[test]
fn manifest_derive_id_varies_by_type() {
    let slot_id = test_slot_id();
    let bh = test_behavior_hash();

    let id1 =
        DelegateCellManifest::derive_manifest_id(&slot_id, DelegateType::QuickJsBacked, &bh, "z")
            .unwrap();
    let id2 =
        DelegateCellManifest::derive_manifest_id(&slot_id, DelegateType::WasmBacked, &bh, "z")
            .unwrap();
    assert_ne!(id1, id2);
}

// ===========================================================================
// 13. ValidationArtifactRef
// ===========================================================================

#[test]
fn validation_artifact_ref_serde_round_trip() {
    let art = ValidationArtifactRef {
        kind: ValidationArtifactKind::PerformanceBenchmark,
        artifact_digest: "sha256-abc123".into(),
        passed: true,
        summary: "Within latency budget".into(),
    };
    let json = serde_json::to_string(&art).unwrap();
    let back: ValidationArtifactRef = serde_json::from_str(&json).unwrap();
    assert_eq!(back, art);
}

// ===========================================================================
// 14. ReplacementReceipt
// ===========================================================================

#[test]
fn receipt_create_unsigned() {
    let arts = test_validation_artifacts();
    let receipt = ReplacementReceipt::create_unsigned(CreateReceiptInput {
        slot_id: &test_slot_id(),
        old_cell_digest: "old-digest-001",
        new_cell_digest: "new-digest-001",
        validation_artifacts: &arts,
        rollback_token: "rollback-token-001",
        promotion_rationale: "Performance improved by 20%",
        timestamp_ns: 1_000_000_000,
        epoch: test_epoch(),
        zone: "zone-a",
        required_signatures: 2,
    })
    .unwrap();

    assert_eq!(receipt.schema_version, SchemaVersion::V1);
    assert_eq!(receipt.old_cell_digest, "old-digest-001");
    assert_eq!(receipt.new_cell_digest, "new-digest-001");
    assert_eq!(receipt.validation_artifacts.len(), 4);
    assert!(receipt.all_validations_passed());
}

#[test]
fn receipt_id_deterministic() {
    let slot_id = test_slot_id();
    let id1 = ReplacementReceipt::derive_receipt_id(&slot_id, "old", "new", 1000, "z").unwrap();
    let id2 = ReplacementReceipt::derive_receipt_id(&slot_id, "old", "new", 1000, "z").unwrap();
    assert_eq!(id1, id2);
}

#[test]
fn receipt_id_varies_by_digest() {
    let slot_id = test_slot_id();
    let id1 = ReplacementReceipt::derive_receipt_id(&slot_id, "old-a", "new", 1000, "z").unwrap();
    let id2 = ReplacementReceipt::derive_receipt_id(&slot_id, "old-b", "new", 1000, "z").unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn receipt_add_and_verify_signatures() {
    let arts = test_validation_artifacts();
    let mut receipt = ReplacementReceipt::create_unsigned(CreateReceiptInput {
        slot_id: &test_slot_id(),
        old_cell_digest: "old",
        new_cell_digest: "new",
        validation_artifacts: &arts,
        rollback_token: "rollback",
        promotion_rationale: "Better",
        timestamp_ns: 2_000_000_000,
        epoch: test_epoch(),
        zone: "zone-a",
        required_signatures: 2,
    })
    .unwrap();

    receipt
        .add_signature(&test_signing_key(), "gate-runner")
        .unwrap();
    receipt
        .add_signature(&test_signing_key_2(), "governance")
        .unwrap();
    assert!(receipt.verify_signatures().is_ok());
}

#[test]
fn receipt_insufficient_signatures() {
    let arts = test_validation_artifacts();
    let mut receipt = ReplacementReceipt::create_unsigned(CreateReceiptInput {
        slot_id: &test_slot_id(),
        old_cell_digest: "old",
        new_cell_digest: "new",
        validation_artifacts: &arts,
        rollback_token: "rollback",
        promotion_rationale: "Testing",
        timestamp_ns: 3_000_000_000,
        epoch: test_epoch(),
        zone: "zone-a",
        required_signatures: 2,
    })
    .unwrap();

    receipt
        .add_signature(&test_signing_key(), "gate-runner")
        .unwrap();
    // Only 1 of required 2
    match receipt.verify_signatures() {
        Err(SelfReplacementError::InsufficientSignatures { required, present }) => {
            assert_eq!(required, 2);
            assert_eq!(present, 1);
        }
        other => panic!("expected InsufficientSignatures, got {other:?}"),
    }
}

#[test]
fn receipt_empty_validation_artifacts_rejected() {
    let result = ReplacementReceipt::create_unsigned(CreateReceiptInput {
        slot_id: &test_slot_id(),
        old_cell_digest: "old",
        new_cell_digest: "new",
        validation_artifacts: &[],
        rollback_token: "rollback",
        promotion_rationale: "No artifacts",
        timestamp_ns: 4_000_000_000,
        epoch: test_epoch(),
        zone: "zone-a",
        required_signatures: 1,
    });
    match result {
        Err(SelfReplacementError::EmptyValidationArtifacts) => {}
        other => panic!("expected EmptyValidationArtifacts, got {other:?}"),
    }
}

#[test]
fn receipt_all_validations_passed_false_when_one_fails() {
    let mut arts = test_validation_artifacts();
    arts[2].passed = false; // Performance benchmark fails
    let receipt = ReplacementReceipt::create_unsigned(CreateReceiptInput {
        slot_id: &test_slot_id(),
        old_cell_digest: "old",
        new_cell_digest: "new",
        validation_artifacts: &arts,
        rollback_token: "rollback",
        promotion_rationale: "Partial",
        timestamp_ns: 5_000_000_000,
        epoch: test_epoch(),
        zone: "zone-a",
        required_signatures: 1,
    })
    .unwrap();
    assert!(!receipt.all_validations_passed());
}

#[test]
fn receipt_serde_round_trip() {
    let arts = test_validation_artifacts();
    let mut receipt = ReplacementReceipt::create_unsigned(CreateReceiptInput {
        slot_id: &test_slot_id(),
        old_cell_digest: "old",
        new_cell_digest: "new",
        validation_artifacts: &arts,
        rollback_token: "rollback",
        promotion_rationale: "Serde test",
        timestamp_ns: 6_000_000_000,
        epoch: test_epoch(),
        zone: "zone-a",
        required_signatures: 1,
    })
    .unwrap();
    receipt
        .add_signature(&test_signing_key(), "signer")
        .unwrap();

    let json = serde_json::to_string(&receipt).unwrap();
    let back: ReplacementReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(back, receipt);
}

// ===========================================================================
// 15. GateResult
// ===========================================================================

#[test]
fn gate_result_serde_round_trip() {
    let gr = GateResult {
        gate_name: "equiv-gate".into(),
        passed: true,
        evidence_refs: vec!["ref-1".into(), "ref-2".into()],
        summary: "Passed".into(),
    };
    let json = serde_json::to_string(&gr).unwrap();
    let back: GateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, gr);
}

// ===========================================================================
// 16. PromotionDecision
// ===========================================================================

#[test]
fn decision_create_unsigned_all_pass() {
    let gates = test_gate_results_all_pass();
    let approver = ApproverKind::System {
        component: "auto-gate".into(),
    };
    let decision = PromotionDecision::create_unsigned(CreateDecisionInput {
        slot_id: &test_slot_id(),
        candidate_cell_digest: "candidate-001",
        gate_results: &gates,
        risk_level: RiskLevel::Low,
        approver: &approver,
        timestamp_ns: 10_000_000_000,
        epoch: test_epoch(),
        zone: "zone-a",
        required_signatures: 1,
    })
    .unwrap();

    assert_eq!(decision.verdict, GateVerdict::Approved);
    assert!(decision.is_approved());
}

#[test]
fn decision_create_unsigned_one_fails() {
    let mut gates = test_gate_results_all_pass();
    gates[1].passed = false;
    let approver = ApproverKind::System {
        component: "auto-gate".into(),
    };
    let decision = PromotionDecision::create_unsigned(CreateDecisionInput {
        slot_id: &test_slot_id(),
        candidate_cell_digest: "candidate-002",
        gate_results: &gates,
        risk_level: RiskLevel::Medium,
        approver: &approver,
        timestamp_ns: 11_000_000_000,
        epoch: test_epoch(),
        zone: "zone-a",
        required_signatures: 1,
    })
    .unwrap();

    assert_eq!(decision.verdict, GateVerdict::Denied);
    assert!(!decision.is_approved());
}

#[test]
fn decision_create_unsigned_empty_gates() {
    let approver = ApproverKind::Human {
        operator_id: "ops-1".into(),
    };
    let decision = PromotionDecision::create_unsigned(CreateDecisionInput {
        slot_id: &test_slot_id(),
        candidate_cell_digest: "candidate-003",
        gate_results: &[],
        risk_level: RiskLevel::High,
        approver: &approver,
        timestamp_ns: 12_000_000_000,
        epoch: test_epoch(),
        zone: "zone-a",
        required_signatures: 1,
    })
    .unwrap();

    assert_eq!(decision.verdict, GateVerdict::Inconclusive);
    assert!(!decision.is_approved());
}

#[test]
fn decision_add_and_verify_signatures() {
    let gates = test_gate_results_all_pass();
    let approver = ApproverKind::System {
        component: "auto-gate".into(),
    };
    let mut decision = PromotionDecision::create_unsigned(CreateDecisionInput {
        slot_id: &test_slot_id(),
        candidate_cell_digest: "candidate-004",
        gate_results: &gates,
        risk_level: RiskLevel::Low,
        approver: &approver,
        timestamp_ns: 13_000_000_000,
        epoch: test_epoch(),
        zone: "zone-a",
        required_signatures: 1,
    })
    .unwrap();

    decision
        .add_signature(&test_signing_key(), "gate-runner")
        .unwrap();
    assert!(decision.verify_signatures().is_ok());
}

#[test]
fn decision_id_deterministic() {
    let slot_id = test_slot_id();
    let id1 = PromotionDecision::derive_decision_id(&slot_id, "candidate-x", 1000, "z").unwrap();
    let id2 = PromotionDecision::derive_decision_id(&slot_id, "candidate-x", 1000, "z").unwrap();
    assert_eq!(id1, id2);
}

#[test]
fn decision_serde_round_trip() {
    let gates = test_gate_results_all_pass();
    let approver = ApproverKind::System {
        component: "auto-gate".into(),
    };
    let mut decision = PromotionDecision::create_unsigned(CreateDecisionInput {
        slot_id: &test_slot_id(),
        candidate_cell_digest: "candidate-005",
        gate_results: &gates,
        risk_level: RiskLevel::Low,
        approver: &approver,
        timestamp_ns: 14_000_000_000,
        epoch: test_epoch(),
        zone: "zone-a",
        required_signatures: 1,
    })
    .unwrap();
    decision
        .add_signature(&test_signing_key(), "signer")
        .unwrap();

    let json = serde_json::to_string(&decision).unwrap();
    let back: PromotionDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(back, decision);
}

// ===========================================================================
// 17. ReplacementLifecycle
// ===========================================================================

#[test]
fn lifecycle_starts_at_research() {
    let manifest = create_test_manifest();
    let lifecycle = ReplacementLifecycle::new(test_slot_id(), manifest);
    assert_eq!(lifecycle.current_stage, ReplacementStage::Research);
    assert!(!lifecycle.is_production());
    assert_eq!(lifecycle.completed_stages(), 0);
    assert!(lifecycle.decisions.is_empty());
    assert!(lifecycle.receipts.is_empty());
}

#[test]
fn lifecycle_record_decision() {
    let manifest = create_test_manifest();
    let mut lifecycle = ReplacementLifecycle::new(test_slot_id(), manifest);

    let gates = test_gate_results_all_pass();
    let approver = ApproverKind::System {
        component: "auto-gate".into(),
    };
    let mut decision = PromotionDecision::create_unsigned(CreateDecisionInput {
        slot_id: &test_slot_id(),
        candidate_cell_digest: "candidate-lc",
        gate_results: &gates,
        risk_level: RiskLevel::Low,
        approver: &approver,
        timestamp_ns: 20_000_000_000,
        epoch: test_epoch(),
        zone: "zone-a",
        required_signatures: 1,
    })
    .unwrap();
    decision
        .add_signature(&test_signing_key(), "gate-runner")
        .unwrap();

    lifecycle.record_decision(decision).unwrap();
    assert_eq!(lifecycle.decisions.len(), 1);
}

#[test]
fn lifecycle_record_receipt_advances_stage() {
    let manifest = create_test_manifest();
    let mut lifecycle = ReplacementLifecycle::new(test_slot_id(), manifest);

    let arts = test_validation_artifacts();
    let mut receipt = ReplacementReceipt::create_unsigned(CreateReceiptInput {
        slot_id: &test_slot_id(),
        old_cell_digest: "old",
        new_cell_digest: "new",
        validation_artifacts: &arts,
        rollback_token: "rollback",
        promotion_rationale: "Stage advance",
        timestamp_ns: 21_000_000_000,
        epoch: test_epoch(),
        zone: "zone-a",
        required_signatures: 1,
    })
    .unwrap();
    receipt
        .add_signature(&test_signing_key(), "gate-runner")
        .unwrap();

    lifecycle.record_receipt(receipt).unwrap();
    assert_eq!(lifecycle.current_stage, ReplacementStage::Shadow);
    assert_eq!(lifecycle.completed_stages(), 1);
}

#[test]
fn lifecycle_slot_mismatch_rejected() {
    let manifest = create_test_manifest();
    let mut lifecycle = ReplacementLifecycle::new(test_slot_id(), manifest);

    let wrong_slot = SlotId::new("wrong-slot").unwrap();
    let gates = test_gate_results_all_pass();
    let approver = ApproverKind::System {
        component: "auto".into(),
    };
    let mut decision = PromotionDecision::create_unsigned(CreateDecisionInput {
        slot_id: &wrong_slot,
        candidate_cell_digest: "candidate-x",
        gate_results: &gates,
        risk_level: RiskLevel::Low,
        approver: &approver,
        timestamp_ns: 22_000_000_000,
        epoch: test_epoch(),
        zone: "zone-a",
        required_signatures: 1,
    })
    .unwrap();
    decision
        .add_signature(&test_signing_key(), "signer")
        .unwrap();

    match lifecycle.record_decision(decision) {
        Err(SelfReplacementError::SlotMismatch { .. }) => {}
        other => panic!("expected SlotMismatch, got {other:?}"),
    }
}

#[test]
fn lifecycle_serde_round_trip() {
    let manifest = create_test_manifest();
    let lifecycle = ReplacementLifecycle::new(test_slot_id(), manifest);
    let json = serde_json::to_string(&lifecycle).unwrap();
    let back: ReplacementLifecycle = serde_json::from_str(&json).unwrap();
    assert_eq!(back, lifecycle);
}

// ===========================================================================
// 18. Full lifecycle — Research → Shadow → Canary → Production
// ===========================================================================

#[test]
fn full_lifecycle_to_production() {
    let manifest = create_test_manifest();
    let mut lifecycle = ReplacementLifecycle::new(test_slot_id(), manifest);
    assert_eq!(lifecycle.current_stage, ReplacementStage::Research);

    let arts = test_validation_artifacts();
    let gates = test_gate_results_all_pass();
    let approver = ApproverKind::System {
        component: "auto-promoter".into(),
    };

    // Advance through Research → Shadow → Canary → Production (3 receipts)
    for (i, expected_next) in [
        ReplacementStage::Shadow,
        ReplacementStage::Canary,
        ReplacementStage::Production,
    ]
    .iter()
    .enumerate()
    {
        // Record a decision
        let mut decision = PromotionDecision::create_unsigned(CreateDecisionInput {
            slot_id: &test_slot_id(),
            candidate_cell_digest: &format!("candidate-{i}"),
            gate_results: &gates,
            risk_level: RiskLevel::Low,
            approver: &approver,
            timestamp_ns: (30 + i as u64) * 1_000_000_000,
            epoch: test_epoch(),
            zone: "zone-a",
            required_signatures: 1,
        })
        .unwrap();
        decision
            .add_signature(&test_signing_key(), "gate-runner")
            .unwrap();
        lifecycle.record_decision(decision).unwrap();

        // Record a receipt to advance stage
        let mut receipt = ReplacementReceipt::create_unsigned(CreateReceiptInput {
            slot_id: &test_slot_id(),
            old_cell_digest: &format!("old-{i}"),
            new_cell_digest: &format!("new-{i}"),
            validation_artifacts: &arts,
            rollback_token: &format!("rollback-{i}"),
            promotion_rationale: &format!("Stage {i} advance"),
            timestamp_ns: (31 + i as u64) * 1_000_000_000,
            epoch: test_epoch(),
            zone: "zone-a",
            required_signatures: 1,
        })
        .unwrap();
        receipt
            .add_signature(&test_signing_key(), "gate-runner")
            .unwrap();
        lifecycle.record_receipt(receipt).unwrap();

        assert_eq!(lifecycle.current_stage, *expected_next);
    }

    assert!(lifecycle.is_production());
    assert_eq!(lifecycle.completed_stages(), 3);
    assert_eq!(lifecycle.decisions.len(), 3);
    assert_eq!(lifecycle.receipts.len(), 3);

    // Serde round-trip of the full lifecycle
    let json = serde_json::to_string(&lifecycle).unwrap();
    let back: ReplacementLifecycle = serde_json::from_str(&json).unwrap();
    assert_eq!(back, lifecycle);
}
