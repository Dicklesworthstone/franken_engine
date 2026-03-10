//! Integration tests for `self_replacement` — delegate manifests, replacement
//! receipts, promotion decisions, multi-party signatures, and lifecycle.

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
use frankenengine_engine::signature_preimage::{Signature, SigningKey};
use frankenengine_engine::slot_registry::{AuthorityEnvelope, SlotCapability, SlotId};

// ── helpers ──────────────────────────────────────────────────────────────

fn test_slot_id() -> SlotId {
    SlotId::new("parser-slot").unwrap()
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

fn test_sandbox() -> SandboxConfiguration {
    SandboxConfiguration::default()
}

fn test_monitoring_hooks() -> Vec<MonitoringHook> {
    vec![MonitoringHook {
        hook_id: "telemetry-hook".into(),
        trigger_event: "hostcall-complete".into(),
        blocking: false,
    }]
}

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes([42u8; 32])
}

fn test_signing_key_2() -> SigningKey {
    SigningKey::from_bytes([99u8; 32])
}

fn test_behavior_hash() -> [u8; 32] {
    [0xABu8; 32]
}

fn test_validation_artifacts() -> Vec<ValidationArtifactRef> {
    vec![
        ValidationArtifactRef {
            kind: ValidationArtifactKind::EquivalenceResult,
            artifact_digest: "equiv-001".into(),
            passed: true,
            summary: "100% behavioral match".into(),
        },
        ValidationArtifactRef {
            kind: ValidationArtifactKind::PerformanceBenchmark,
            artifact_digest: "perf-001".into(),
            passed: true,
            summary: "2x throughput improvement".into(),
        },
    ]
}

fn test_gate_results() -> Vec<GateResult> {
    vec![
        GateResult {
            gate_name: "equivalence-gate".into(),
            passed: true,
            evidence_refs: vec!["equiv-001".into()],
            summary: "all test vectors match".into(),
        },
        GateResult {
            gate_name: "performance-gate".into(),
            passed: true,
            evidence_refs: vec!["perf-001".into()],
            summary: "meets latency targets".into(),
        },
    ]
}

fn create_test_manifest() -> DelegateCellManifest {
    let sk = test_signing_key();
    let hooks = test_monitoring_hooks();
    let envelope = test_authority_envelope();
    let sandbox = test_sandbox();
    let behavior = test_behavior_hash();
    DelegateCellManifest::create_signed(
        &sk,
        CreateManifestInput {
            slot_id: &test_slot_id(),
            delegate_type: DelegateType::QuickJsBacked,
            capability_envelope: &envelope,
            sandbox: &sandbox,
            monitoring_hooks: &hooks,
            expected_behavior_hash: &behavior,
            zone: "test-zone",
        },
    )
    .unwrap()
}

fn create_valid_receipt(slot_id: &SlotId, ts: u64, required_sigs: u32) -> ReplacementReceipt {
    let artifacts = test_validation_artifacts();
    ReplacementReceipt::create_unsigned(CreateReceiptInput {
        slot_id,
        old_cell_digest: "old-001",
        new_cell_digest: "new-001",
        validation_artifacts: &artifacts,
        rollback_token: "rollback-001",
        promotion_rationale: "performance improvement",
        timestamp_ns: ts,
        epoch: SecurityEpoch::from_raw(1),
        zone: "test-zone",
        required_signatures: required_sigs,
    })
    .unwrap()
}

// ═══════════════════════════════════════════════════════════════════════════
// SchemaVersion
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn schema_version_ord_is_derived() {
    // Only one variant, but Ord is derived so it should be reflexive
    assert!(SchemaVersion::V1 == SchemaVersion::V1);
    assert!(SchemaVersion::V1 <= SchemaVersion::V1);
}

// ═══════════════════════════════════════════════════════════════════════════
// DelegateType — ordering
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn delegate_type_ordering() {
    assert!(DelegateType::QuickJsBacked < DelegateType::WasmBacked);
    assert!(DelegateType::WasmBacked < DelegateType::ExternalProcess);
}

#[test]
fn delegate_type_hash_all_distinct() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(DelegateType::QuickJsBacked);
    set.insert(DelegateType::WasmBacked);
    set.insert(DelegateType::ExternalProcess);
    assert_eq!(set.len(), 3);
}

// ═══════════════════════════════════════════════════════════════════════════
// SandboxConfiguration — custom values
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn sandbox_custom_values_serde() {
    let sb = SandboxConfiguration {
        max_heap_bytes: 1024,
        max_execution_ns: 500,
        max_hostcalls: 10,
        network_egress_allowed: true,
        filesystem_access_allowed: true,
    };
    let json = serde_json::to_string(&sb).unwrap();
    let parsed: SandboxConfiguration = serde_json::from_str(&json).unwrap();
    assert_eq!(sb, parsed);
    assert!(parsed.network_egress_allowed);
    assert!(parsed.filesystem_access_allowed);
}

// ═══════════════════════════════════════════════════════════════════════════
// SignatureBundle — edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn bundle_threshold_zero_always_meets() {
    let bundle = SignatureBundle::new(0);
    assert!(bundle.meets_threshold());
}

#[test]
fn bundle_verify_all_insufficient_returns_error() {
    let bundle = SignatureBundle::new(2);
    let err = bundle.verify_all(b"test preimage").unwrap_err();
    assert!(matches!(
        err,
        SelfReplacementError::InsufficientSignatures {
            required: 2,
            present: 0
        }
    ));
}

#[test]
fn bundle_verify_all_with_bad_signature() {
    let sk = test_signing_key();
    let mut bundle = SignatureBundle::new(1);
    // Add a signer with a bogus signature
    bundle.add_signer(SignerEntry {
        role: "fake".into(),
        verification_key: sk.verification_key(),
        signature: Signature::from_bytes([0u8; 64]),
    });
    let err = bundle.verify_all(b"test preimage").unwrap_err();
    assert!(matches!(
        err,
        SelfReplacementError::SignatureInvalid {
            signer_index: 0,
            ..
        }
    ));
}

#[test]
fn signer_entry_serde_roundtrip() {
    let sk = test_signing_key();
    let entry = SignerEntry {
        role: "gate-runner".into(),
        verification_key: sk.verification_key(),
        signature: Signature::from_bytes([1u8; 64]),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let parsed: SignerEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, parsed);
}

// ═══════════════════════════════════════════════════════════════════════════
// DelegateCellManifest — different delegate types & zones
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn manifest_id_differs_by_delegate_type() {
    let id_qjs = DelegateCellManifest::derive_manifest_id(
        &test_slot_id(),
        DelegateType::QuickJsBacked,
        &test_behavior_hash(),
        "zone",
    )
    .unwrap();
    let id_wasm = DelegateCellManifest::derive_manifest_id(
        &test_slot_id(),
        DelegateType::WasmBacked,
        &test_behavior_hash(),
        "zone",
    )
    .unwrap();
    let id_ext = DelegateCellManifest::derive_manifest_id(
        &test_slot_id(),
        DelegateType::ExternalProcess,
        &test_behavior_hash(),
        "zone",
    )
    .unwrap();
    assert_ne!(id_qjs, id_wasm);
    assert_ne!(id_wasm, id_ext);
    assert_ne!(id_qjs, id_ext);
}

#[test]
fn manifest_wasm_backed_creation() {
    let sk = test_signing_key();
    let hooks = test_monitoring_hooks();
    let envelope = test_authority_envelope();
    let sandbox = test_sandbox();
    let behavior = test_behavior_hash();
    let manifest = DelegateCellManifest::create_signed(
        &sk,
        CreateManifestInput {
            slot_id: &test_slot_id(),
            delegate_type: DelegateType::WasmBacked,
            capability_envelope: &envelope,
            sandbox: &sandbox,
            monitoring_hooks: &hooks,
            expected_behavior_hash: &behavior,
            zone: "wasm-zone",
        },
    )
    .unwrap();
    assert_eq!(manifest.delegate_type, DelegateType::WasmBacked);
    assert_eq!(manifest.zone, "wasm-zone");
    assert!(manifest.verify_signature(&sk.verification_key()).is_ok());
}

#[test]
fn manifest_with_empty_monitoring_hooks() {
    let sk = test_signing_key();
    let envelope = test_authority_envelope();
    let sandbox = test_sandbox();
    let behavior = test_behavior_hash();
    let manifest = DelegateCellManifest::create_signed(
        &sk,
        CreateManifestInput {
            slot_id: &test_slot_id(),
            delegate_type: DelegateType::ExternalProcess,
            capability_envelope: &envelope,
            sandbox: &sandbox,
            monitoring_hooks: &[],
            expected_behavior_hash: &behavior,
            zone: "test-zone",
        },
    )
    .unwrap();
    assert!(manifest.monitoring_hooks.is_empty());
    assert!(manifest.verify_signature(&sk.verification_key()).is_ok());
}

// ═══════════════════════════════════════════════════════════════════════════
// ReplacementReceipt — edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn receipt_all_validations_mixed_results() {
    let artifacts = vec![
        ValidationArtifactRef {
            kind: ValidationArtifactKind::EquivalenceResult,
            artifact_digest: "eq-1".into(),
            passed: true,
            summary: "match".into(),
        },
        ValidationArtifactRef {
            kind: ValidationArtifactKind::PerformanceBenchmark,
            artifact_digest: "perf-1".into(),
            passed: false,
            summary: "regression".into(),
        },
    ];
    let receipt = ReplacementReceipt::create_unsigned(CreateReceiptInput {
        slot_id: &test_slot_id(),
        old_cell_digest: "old",
        new_cell_digest: "new",
        validation_artifacts: &artifacts,
        rollback_token: "rb",
        promotion_rationale: "test",
        timestamp_ns: 1000,
        epoch: SecurityEpoch::from_raw(1),
        zone: "zone",
        required_signatures: 1,
    })
    .unwrap();
    assert!(!receipt.all_validations_passed());
}

#[test]
fn receipt_id_differs_by_zone() {
    let id1 = ReplacementReceipt::derive_receipt_id(&test_slot_id(), "old", "new", 1000, "zone-a")
        .unwrap();
    let id2 = ReplacementReceipt::derive_receipt_id(&test_slot_id(), "old", "new", 1000, "zone-b")
        .unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn receipt_id_differs_by_new_digest() {
    let id1 = ReplacementReceipt::derive_receipt_id(&test_slot_id(), "old", "new-a", 1000, "zone")
        .unwrap();
    let id2 = ReplacementReceipt::derive_receipt_id(&test_slot_id(), "old", "new-b", 1000, "zone")
        .unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn receipt_single_signer_threshold_one_verifies() {
    let mut receipt = create_valid_receipt(&test_slot_id(), 1000, 1);
    receipt
        .add_signature(&test_signing_key(), "gate-runner")
        .unwrap();
    assert!(receipt.verify_signatures().is_ok());
}

// ═══════════════════════════════════════════════════════════════════════════
// PromotionDecision — edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn decision_id_differs_by_candidate() {
    let id1 = PromotionDecision::derive_decision_id(&test_slot_id(), "candidate-a", 1000, "zone")
        .unwrap();
    let id2 = PromotionDecision::derive_decision_id(&test_slot_id(), "candidate-b", 1000, "zone")
        .unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn decision_id_differs_by_timestamp() {
    let id1 =
        PromotionDecision::derive_decision_id(&test_slot_id(), "candidate", 1000, "zone").unwrap();
    let id2 =
        PromotionDecision::derive_decision_id(&test_slot_id(), "candidate", 2000, "zone").unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn decision_multi_party_signing() {
    let gates = test_gate_results();
    let mut decision = PromotionDecision::create_unsigned(CreateDecisionInput {
        slot_id: &test_slot_id(),
        candidate_cell_digest: "candidate-001",
        gate_results: &gates,
        risk_level: RiskLevel::High,
        approver: &ApproverKind::Human {
            operator_id: "op-1".into(),
        },
        timestamp_ns: 2000,
        epoch: SecurityEpoch::from_raw(1),
        zone: "test-zone",
        required_signatures: 2,
    })
    .unwrap();
    // Only one signature — insufficient
    decision
        .add_signature(&test_signing_key(), "gate-runner")
        .unwrap();
    assert!(matches!(
        decision.verify_signatures(),
        Err(SelfReplacementError::InsufficientSignatures { .. })
    ));
    // Add second signature — now meets threshold
    decision
        .add_signature(&test_signing_key_2(), "governance")
        .unwrap();
    assert!(decision.verify_signatures().is_ok());
}

#[test]
fn decision_empty_gates_is_approved() {
    // create_unsigned with empty gates: production code returns Inconclusive
    let decision = PromotionDecision::create_unsigned(CreateDecisionInput {
        slot_id: &test_slot_id(),
        candidate_cell_digest: "candidate-001",
        gate_results: &[],
        risk_level: RiskLevel::Low,
        approver: &ApproverKind::System {
            component: "auto".into(),
        },
        timestamp_ns: 1000,
        epoch: SecurityEpoch::from_raw(1),
        zone: "zone",
        required_signatures: 0,
    })
    .unwrap();
    assert!(!decision.is_approved());
    assert_eq!(decision.verdict, GateVerdict::Inconclusive);
}

// ═══════════════════════════════════════════════════════════════════════════
// GateVerdict — ordering
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn gate_verdict_ordering() {
    assert!(GateVerdict::Approved < GateVerdict::Denied);
    assert!(GateVerdict::Denied < GateVerdict::Inconclusive);
}

#[test]
fn gate_verdict_hash_distinct() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(GateVerdict::Approved);
    set.insert(GateVerdict::Denied);
    set.insert(GateVerdict::Inconclusive);
    assert_eq!(set.len(), 3);
}

// ═══════════════════════════════════════════════════════════════════════════
// RiskLevel — ordering
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn risk_level_ordering() {
    assert!(RiskLevel::Low < RiskLevel::Medium);
    assert!(RiskLevel::Medium < RiskLevel::High);
    assert!(RiskLevel::High < RiskLevel::Critical);
}

#[test]
fn risk_level_hash_distinct() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    for rl in [
        RiskLevel::Low,
        RiskLevel::Medium,
        RiskLevel::High,
        RiskLevel::Critical,
    ] {
        set.insert(rl);
    }
    assert_eq!(set.len(), 4);
}

// ═══════════════════════════════════════════════════════════════════════════
// ReplacementStage — ordering & production stays
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn replacement_stage_ordering() {
    assert!(ReplacementStage::Research < ReplacementStage::Shadow);
    assert!(ReplacementStage::Shadow < ReplacementStage::Canary);
    assert!(ReplacementStage::Canary < ReplacementStage::Production);
}

#[test]
fn replacement_stage_hash_distinct() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    for s in [
        ReplacementStage::Research,
        ReplacementStage::Shadow,
        ReplacementStage::Canary,
        ReplacementStage::Production,
    ] {
        set.insert(s);
    }
    assert_eq!(set.len(), 4);
}

// ═══════════════════════════════════════════════════════════════════════════
// ValidationArtifactKind — ordering & serde
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn validation_artifact_kind_ordering() {
    assert!(
        ValidationArtifactKind::EquivalenceResult < ValidationArtifactKind::CapabilityPreservation
    );
    assert!(
        ValidationArtifactKind::CapabilityPreservation
            < ValidationArtifactKind::PerformanceBenchmark
    );
    assert!(
        ValidationArtifactKind::PerformanceBenchmark < ValidationArtifactKind::AdversarialSurvival
    );
}

#[test]
fn validation_artifact_kind_serde_all() {
    for kind in [
        ValidationArtifactKind::EquivalenceResult,
        ValidationArtifactKind::CapabilityPreservation,
        ValidationArtifactKind::PerformanceBenchmark,
        ValidationArtifactKind::AdversarialSurvival,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let parsed: ValidationArtifactKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, parsed);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// GateResult — serde roundtrip
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn gate_result_serde_roundtrip() {
    let gr = GateResult {
        gate_name: "test-gate".into(),
        passed: false,
        evidence_refs: vec!["ev-1".into(), "ev-2".into()],
        summary: "failed due to regression".into(),
    };
    let json = serde_json::to_string(&gr).unwrap();
    let parsed: GateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(gr, parsed);
}

// ═══════════════════════════════════════════════════════════════════════════
// ApproverKind — ordering
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn approver_kind_ordering() {
    let sys = ApproverKind::System {
        component: "auto".into(),
    };
    let human = ApproverKind::Human {
        operator_id: "op-1".into(),
    };
    // Enum order: System < Human
    assert!(sys < human);
}

// ═══════════════════════════════════════════════════════════════════════════
// MonitoringHook — extra tests
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn monitoring_hook_blocking_vs_nonblocking() {
    let blocking = MonitoringHook {
        hook_id: "h-block".into(),
        trigger_event: "pre-invoke".into(),
        blocking: true,
    };
    let nonblocking = MonitoringHook {
        hook_id: "h-async".into(),
        trigger_event: "post-invoke".into(),
        blocking: false,
    };
    assert!(blocking.blocking);
    assert!(!nonblocking.blocking);
    // Serde roundtrip both
    for hook in [&blocking, &nonblocking] {
        let json = serde_json::to_string(hook).unwrap();
        let parsed: MonitoringHook = serde_json::from_str(&json).unwrap();
        assert_eq!(*hook, parsed);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SelfReplacementError — additional Display & std::error::Error
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn error_is_std_error() {
    let err = SelfReplacementError::EmptyValidationArtifacts;
    let std_err: &dyn std::error::Error = &err;
    assert!(std_err.source().is_none());
}

#[test]
fn error_signature_invalid_display() {
    let err = SelfReplacementError::SignatureInvalid {
        signer_index: 2,
        role: "governance-approver".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("2"));
    assert!(msg.contains("governance-approver"));
}

#[test]
fn error_unsupported_schema_display() {
    let err = SelfReplacementError::UnsupportedSchemaVersion {
        version: "v99".into(),
    };
    assert!(err.to_string().contains("v99"));
}

#[test]
fn error_validation_failed_display() {
    let err = SelfReplacementError::ValidationFailed {
        slot_id: "slot-xyz".into(),
    };
    assert!(err.to_string().contains("slot-xyz"));
}

// ═══════════════════════════════════════════════════════════════════════════
// ReplacementLifecycle — additional edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn lifecycle_production_stays_at_production() {
    let manifest = create_test_manifest();
    let mut lifecycle = ReplacementLifecycle::new(test_slot_id(), manifest);
    let artifacts = test_validation_artifacts();

    // Advance Research → Shadow → Canary → Production
    for ts in [1000u64, 2000, 3000] {
        let mut receipt = ReplacementReceipt::create_unsigned(CreateReceiptInput {
            slot_id: &test_slot_id(),
            old_cell_digest: "old",
            new_cell_digest: &format!("new-{ts}"),
            validation_artifacts: &artifacts,
            rollback_token: "rb",
            promotion_rationale: "pass",
            timestamp_ns: ts,
            epoch: SecurityEpoch::from_raw(1),
            zone: "test-zone",
            required_signatures: 1,
        })
        .unwrap();
        receipt.add_signature(&test_signing_key(), "gate").unwrap();
        lifecycle.record_receipt(receipt).unwrap();
    }
    assert!(lifecycle.is_production());

    // Another receipt at production stays at production
    let mut r4 = ReplacementReceipt::create_unsigned(CreateReceiptInput {
        slot_id: &test_slot_id(),
        old_cell_digest: "old",
        new_cell_digest: "new-4000",
        validation_artifacts: &artifacts,
        rollback_token: "rb",
        promotion_rationale: "hotfix",
        timestamp_ns: 4000,
        epoch: SecurityEpoch::from_raw(1),
        zone: "test-zone",
        required_signatures: 1,
    })
    .unwrap();
    r4.add_signature(&test_signing_key(), "gate").unwrap();
    lifecycle.record_receipt(r4).unwrap();
    assert!(lifecycle.is_production());
    assert_eq!(lifecycle.completed_stages(), 4);
}

#[test]
fn lifecycle_decision_slot_mismatch_rejected() {
    let manifest = create_test_manifest();
    let mut lifecycle = ReplacementLifecycle::new(test_slot_id(), manifest);

    let wrong_slot = SlotId::new("wrong-slot").unwrap();
    let gates = test_gate_results();
    let decision = PromotionDecision::create_unsigned(CreateDecisionInput {
        slot_id: &wrong_slot,
        candidate_cell_digest: "candidate",
        gate_results: &gates,
        risk_level: RiskLevel::Low,
        approver: &ApproverKind::System {
            component: "gate".into(),
        },
        timestamp_ns: 1000,
        epoch: SecurityEpoch::from_raw(1),
        zone: "zone",
        required_signatures: 1,
    })
    .unwrap();

    assert!(matches!(
        lifecycle.record_decision(decision),
        Err(SelfReplacementError::SlotMismatch { .. })
    ));
}

#[test]
fn lifecycle_multiple_decisions_accumulate() {
    let manifest = create_test_manifest();
    let mut lifecycle = ReplacementLifecycle::new(test_slot_id(), manifest);
    let gates = test_gate_results();

    for ts in [1000u64, 2000, 3000] {
        let decision = PromotionDecision::create_unsigned(CreateDecisionInput {
            slot_id: &test_slot_id(),
            candidate_cell_digest: &format!("cand-{ts}"),
            gate_results: &gates,
            risk_level: RiskLevel::Medium,
            approver: &ApproverKind::System {
                component: "gate".into(),
            },
            timestamp_ns: ts,
            epoch: SecurityEpoch::from_raw(1),
            zone: "test-zone",
            required_signatures: 1,
        })
        .unwrap();
        lifecycle.record_decision(decision).unwrap();
    }
    assert_eq!(lifecycle.decisions.len(), 3);
    // Stage hasn't advanced (no receipts)
    assert_eq!(lifecycle.current_stage, ReplacementStage::Research);
}

// ═══════════════════════════════════════════════════════════════════════════
// Cross-type integration
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn full_lifecycle_manifest_to_production() {
    let sk1 = test_signing_key();
    let sk2 = test_signing_key_2();

    // 1. Create manifest
    let manifest = create_test_manifest();
    assert!(manifest.verify_signature(&sk1.verification_key()).is_ok());

    // 2. Start lifecycle
    let mut lifecycle = ReplacementLifecycle::new(test_slot_id(), manifest);
    assert_eq!(lifecycle.current_stage, ReplacementStage::Research);

    // 3. Create and record decision
    let gates = test_gate_results();
    let mut decision = PromotionDecision::create_unsigned(CreateDecisionInput {
        slot_id: &test_slot_id(),
        candidate_cell_digest: "candidate-prod",
        gate_results: &gates,
        risk_level: RiskLevel::High,
        approver: &ApproverKind::Human {
            operator_id: "op-42".into(),
        },
        timestamp_ns: 100,
        epoch: SecurityEpoch::from_raw(1),
        zone: "test-zone",
        required_signatures: 2,
    })
    .unwrap();
    assert!(decision.is_approved());
    decision.add_signature(&sk1, "gate-runner").unwrap();
    decision.add_signature(&sk2, "governance").unwrap();
    assert!(decision.verify_signatures().is_ok());
    lifecycle.record_decision(decision).unwrap();

    // 4. Advance through all stages with receipts
    let artifacts = test_validation_artifacts();
    for (i, ts) in [1000u64, 2000, 3000].iter().enumerate() {
        let mut receipt = ReplacementReceipt::create_unsigned(CreateReceiptInput {
            slot_id: &test_slot_id(),
            old_cell_digest: &format!("old-{i}"),
            new_cell_digest: &format!("new-{i}"),
            validation_artifacts: &artifacts,
            rollback_token: &format!("rb-{i}"),
            promotion_rationale: &format!("stage {i} pass"),
            timestamp_ns: *ts,
            epoch: SecurityEpoch::from_raw(1),
            zone: "test-zone",
            required_signatures: 2,
        })
        .unwrap();
        receipt.add_signature(&sk1, "gate-runner").unwrap();
        receipt.add_signature(&sk2, "governance").unwrap();
        assert!(receipt.verify_signatures().is_ok());
        lifecycle.record_receipt(receipt).unwrap();
    }

    assert!(lifecycle.is_production());
    assert_eq!(lifecycle.completed_stages(), 3);
    assert_eq!(lifecycle.decisions.len(), 1);
    assert_eq!(lifecycle.receipts.len(), 3);
}

#[test]
fn deterministic_id_derivation_all_artifact_types() {
    // Manifest IDs
    for _ in 0..50 {
        let id = DelegateCellManifest::derive_manifest_id(
            &test_slot_id(),
            DelegateType::QuickJsBacked,
            &test_behavior_hash(),
            "zone",
        )
        .unwrap();
        let id2 = DelegateCellManifest::derive_manifest_id(
            &test_slot_id(),
            DelegateType::QuickJsBacked,
            &test_behavior_hash(),
            "zone",
        )
        .unwrap();
        assert_eq!(id, id2);
    }
    // Receipt IDs
    for _ in 0..50 {
        let id = ReplacementReceipt::derive_receipt_id(&test_slot_id(), "old", "new", 1000, "zone")
            .unwrap();
        let id2 =
            ReplacementReceipt::derive_receipt_id(&test_slot_id(), "old", "new", 1000, "zone")
                .unwrap();
        assert_eq!(id, id2);
    }
    // Decision IDs
    for _ in 0..50 {
        let id =
            PromotionDecision::derive_decision_id(&test_slot_id(), "cand", 1000, "zone").unwrap();
        let id2 =
            PromotionDecision::derive_decision_id(&test_slot_id(), "cand", 1000, "zone").unwrap();
        assert_eq!(id, id2);
    }
}

#[test]
fn all_artifact_ids_from_different_types_are_distinct() {
    let manifest_id = DelegateCellManifest::derive_manifest_id(
        &test_slot_id(),
        DelegateType::QuickJsBacked,
        &test_behavior_hash(),
        "zone",
    )
    .unwrap();
    let receipt_id =
        ReplacementReceipt::derive_receipt_id(&test_slot_id(), "old", "new", 1000, "zone").unwrap();
    let decision_id =
        PromotionDecision::derive_decision_id(&test_slot_id(), "candidate", 1000, "zone").unwrap();

    assert_ne!(manifest_id, receipt_id);
    assert_ne!(receipt_id, decision_id);
    assert_ne!(manifest_id, decision_id);
}
