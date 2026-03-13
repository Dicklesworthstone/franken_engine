#![forbid(unsafe_code)]
//! Enrichment integration tests for the `self_replacement` module.
//!
//! Covers Display uniqueness, serde roundtrips, constructor edge cases,
//! determinism, lifecycle transitions, signature bundle verification,
//! and cross-artifact ID isolation.

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

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::self_replacement::{
    ApproverKind, CreateDecisionInput, CreateManifestInput, CreateReceiptInput,
    DelegateCellManifest, DelegateType, GateResult, GateVerdict, MonitoringHook, PromotionDecision,
    ReplacementLifecycle, ReplacementReceipt, ReplacementStage, RiskLevel, SandboxConfiguration,
    SchemaVersion, SelfReplacementError, SignatureBundle, SignerEntry, ValidationArtifactKind,
    ValidationArtifactRef,
};
use frankenengine_engine::signature_preimage::{Signature, SigningKey, sign_preimage};
use frankenengine_engine::slot_registry::{AuthorityEnvelope, SlotCapability, SlotId};

// ===========================================================================
// Helpers
// ===========================================================================

fn sk1() -> SigningKey {
    SigningKey::from_bytes([10u8; 32])
}

fn sk2() -> SigningKey {
    SigningKey::from_bytes([20u8; 32])
}

fn sk3() -> SigningKey {
    SigningKey::from_bytes([30u8; 32])
}

fn slot(name: &str) -> SlotId {
    SlotId::new(name).unwrap()
}

fn default_slot() -> SlotId {
    slot("enrichment-slot")
}

fn default_envelope() -> AuthorityEnvelope {
    AuthorityEnvelope {
        required: vec![SlotCapability::ReadSource],
        permitted: vec![
            SlotCapability::ReadSource,
            SlotCapability::EmitIr,
            SlotCapability::EmitEvidence,
        ],
    }
}

fn default_sandbox() -> SandboxConfiguration {
    SandboxConfiguration::default()
}

fn default_hooks() -> Vec<MonitoringHook> {
    vec![MonitoringHook {
        hook_id: "enrich-hook".into(),
        trigger_event: "post-invoke".into(),
        blocking: false,
    }]
}

fn default_behavior_hash() -> [u8; 32] {
    [0xCD; 32]
}

fn make_manifest(
    sk: &SigningKey,
    slot_id: &SlotId,
    dtype: DelegateType,
    zone: &str,
) -> DelegateCellManifest {
    let envelope = default_envelope();
    let sandbox = default_sandbox();
    let hooks = default_hooks();
    let bh = default_behavior_hash();
    DelegateCellManifest::create_signed(
        sk,
        CreateManifestInput {
            slot_id,
            delegate_type: dtype,
            capability_envelope: &envelope,
            sandbox: &sandbox,
            monitoring_hooks: &hooks,
            expected_behavior_hash: &bh,
            zone,
        },
    )
    .unwrap()
}

fn passing_artifacts() -> Vec<ValidationArtifactRef> {
    vec![
        ValidationArtifactRef {
            kind: ValidationArtifactKind::EquivalenceResult,
            artifact_digest: "eq-enrich-001".into(),
            passed: true,
            summary: "full match".into(),
        },
        ValidationArtifactRef {
            kind: ValidationArtifactKind::CapabilityPreservation,
            artifact_digest: "cap-enrich-001".into(),
            passed: true,
            summary: "caps preserved".into(),
        },
    ]
}

fn passing_gates() -> Vec<GateResult> {
    vec![
        GateResult {
            gate_name: "equiv-gate".into(),
            passed: true,
            evidence_refs: vec!["ev-1".into()],
            summary: "ok".into(),
        },
        GateResult {
            gate_name: "perf-gate".into(),
            passed: true,
            evidence_refs: vec!["ev-2".into()],
            summary: "ok".into(),
        },
    ]
}

fn make_receipt(
    slot_id: &SlotId,
    ts: u64,
    zone: &str,
    required_signatures: u32,
) -> ReplacementReceipt {
    let arts = passing_artifacts();
    ReplacementReceipt::create_unsigned(CreateReceiptInput {
        slot_id,
        old_cell_digest: "old-enrich",
        new_cell_digest: "new-enrich",
        validation_artifacts: &arts,
        rollback_token: "rb-enrich",
        promotion_rationale: "enrichment test",
        timestamp_ns: ts,
        epoch: SecurityEpoch::from_raw(5),
        zone,
        required_signatures,
    })
    .unwrap()
}

fn make_decision(
    slot_id: &SlotId,
    ts: u64,
    zone: &str,
    gates: &[GateResult],
    risk: RiskLevel,
    approver: &ApproverKind,
    required_signatures: u32,
) -> PromotionDecision {
    PromotionDecision::create_unsigned(CreateDecisionInput {
        slot_id,
        candidate_cell_digest: "candidate-enrich",
        gate_results: gates,
        risk_level: risk,
        approver,
        timestamp_ns: ts,
        epoch: SecurityEpoch::from_raw(5),
        zone,
        required_signatures,
    })
    .unwrap()
}

// ===========================================================================
// 1. SchemaVersion enrichment
// ===========================================================================

#[test]
fn enrichment_schema_version_display_uniqueness() {
    let mut displays = BTreeSet::new();
    displays.insert(SchemaVersion::V1.to_string());
    assert_eq!(displays.len(), 1);
}

#[test]
fn enrichment_schema_version_clone_eq() {
    let v = SchemaVersion::V1;
    let v2 = v.clone();
    assert_eq!(v, v2);
}

#[test]
fn enrichment_schema_version_serde_json_shape() {
    let json = serde_json::to_string(&SchemaVersion::V1).unwrap();
    assert!(json.contains("V1"));
    let back: SchemaVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(back, SchemaVersion::V1);
}

// ===========================================================================
// 2. DelegateType enrichment
// ===========================================================================

#[test]
fn enrichment_delegate_type_display_uniqueness() {
    let mut displays = BTreeSet::new();
    displays.insert(DelegateType::QuickJsBacked.to_string());
    displays.insert(DelegateType::WasmBacked.to_string());
    displays.insert(DelegateType::ExternalProcess.to_string());
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_delegate_type_serde_all_variants() {
    let variants = [
        DelegateType::QuickJsBacked,
        DelegateType::WasmBacked,
        DelegateType::ExternalProcess,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: DelegateType = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, v);
    }
}

#[test]
fn enrichment_delegate_type_ord_total() {
    assert!(DelegateType::QuickJsBacked < DelegateType::WasmBacked);
    assert!(DelegateType::WasmBacked < DelegateType::ExternalProcess);
    assert!(DelegateType::QuickJsBacked < DelegateType::ExternalProcess);
}

#[test]
fn enrichment_delegate_type_display_no_overlap_with_other_enums() {
    let delegate_displays: BTreeSet<String> = [
        DelegateType::QuickJsBacked,
        DelegateType::WasmBacked,
        DelegateType::ExternalProcess,
    ]
    .iter()
    .map(|d| d.to_string())
    .collect();

    let verdict_displays: BTreeSet<String> = [
        GateVerdict::Approved,
        GateVerdict::Denied,
        GateVerdict::Inconclusive,
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();

    // No overlap between delegate type and gate verdict display strings.
    assert!(delegate_displays.intersection(&verdict_displays).count() == 0);
}

// ===========================================================================
// 3. ValidationArtifactKind enrichment
// ===========================================================================

#[test]
fn enrichment_validation_artifact_kind_display_uniqueness() {
    let mut displays = BTreeSet::new();
    displays.insert(ValidationArtifactKind::EquivalenceResult.to_string());
    displays.insert(ValidationArtifactKind::CapabilityPreservation.to_string());
    displays.insert(ValidationArtifactKind::PerformanceBenchmark.to_string());
    displays.insert(ValidationArtifactKind::AdversarialSurvival.to_string());
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_validation_artifact_kind_serde_all_variants() {
    let variants = [
        ValidationArtifactKind::EquivalenceResult,
        ValidationArtifactKind::CapabilityPreservation,
        ValidationArtifactKind::PerformanceBenchmark,
        ValidationArtifactKind::AdversarialSurvival,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: ValidationArtifactKind = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, v);
    }
}

#[test]
fn enrichment_validation_artifact_kind_ord_follows_declaration() {
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

// ===========================================================================
// 4. GateVerdict enrichment
// ===========================================================================

#[test]
fn enrichment_gate_verdict_display_uniqueness() {
    let mut displays = BTreeSet::new();
    displays.insert(GateVerdict::Approved.to_string());
    displays.insert(GateVerdict::Denied.to_string());
    displays.insert(GateVerdict::Inconclusive.to_string());
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_gate_verdict_serde_all_variants() {
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

#[test]
fn enrichment_gate_verdict_clone_preserves_equality() {
    let v = GateVerdict::Inconclusive;
    let v2 = v.clone();
    assert_eq!(v, v2);
}

// ===========================================================================
// 5. RiskLevel enrichment
// ===========================================================================

#[test]
fn enrichment_risk_level_display_uniqueness() {
    let mut displays = BTreeSet::new();
    displays.insert(RiskLevel::Low.to_string());
    displays.insert(RiskLevel::Medium.to_string());
    displays.insert(RiskLevel::High.to_string());
    displays.insert(RiskLevel::Critical.to_string());
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_risk_level_serde_all_variants() {
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

#[test]
fn enrichment_risk_level_full_ordering_chain() {
    let levels = [
        RiskLevel::Low,
        RiskLevel::Medium,
        RiskLevel::High,
        RiskLevel::Critical,
    ];
    for i in 0..levels.len() {
        for j in (i + 1)..levels.len() {
            assert!(levels[i] < levels[j]);
        }
    }
}

// ===========================================================================
// 6. ReplacementStage enrichment
// ===========================================================================

#[test]
fn enrichment_replacement_stage_display_uniqueness() {
    let mut displays = BTreeSet::new();
    displays.insert(ReplacementStage::Research.to_string());
    displays.insert(ReplacementStage::Shadow.to_string());
    displays.insert(ReplacementStage::Canary.to_string());
    displays.insert(ReplacementStage::Production.to_string());
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_replacement_stage_serde_all_variants() {
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

#[test]
fn enrichment_replacement_stage_full_ordering_chain() {
    let stages = [
        ReplacementStage::Research,
        ReplacementStage::Shadow,
        ReplacementStage::Canary,
        ReplacementStage::Production,
    ];
    for i in 0..stages.len() {
        for j in (i + 1)..stages.len() {
            assert!(stages[i] < stages[j]);
        }
    }
}

// ===========================================================================
// 7. ApproverKind enrichment
// ===========================================================================

#[test]
fn enrichment_approver_kind_display_system() {
    let a = ApproverKind::System {
        component: "auto-gate".into(),
    };
    assert_eq!(a.to_string(), "system:auto-gate");
}

#[test]
fn enrichment_approver_kind_display_human() {
    let a = ApproverKind::Human {
        operator_id: "ops-99".into(),
    };
    assert_eq!(a.to_string(), "human:ops-99");
}

#[test]
fn enrichment_approver_kind_display_uniqueness_across_variants() {
    let mut displays = BTreeSet::new();
    displays.insert(
        ApproverKind::System {
            component: "x".into(),
        }
        .to_string(),
    );
    displays.insert(
        ApproverKind::Human {
            operator_id: "x".into(),
        }
        .to_string(),
    );
    assert_eq!(displays.len(), 2);
}

#[test]
fn enrichment_approver_kind_serde_system() {
    let a = ApproverKind::System {
        component: "gate-runner".into(),
    };
    let json = serde_json::to_string(&a).unwrap();
    let back: ApproverKind = serde_json::from_str(&json).unwrap();
    assert_eq!(back, a);
}

#[test]
fn enrichment_approver_kind_serde_human() {
    let a = ApproverKind::Human {
        operator_id: "admin-1".into(),
    };
    let json = serde_json::to_string(&a).unwrap();
    let back: ApproverKind = serde_json::from_str(&json).unwrap();
    assert_eq!(back, a);
}

#[test]
fn enrichment_approver_kind_ord_system_before_human() {
    let sys = ApproverKind::System {
        component: "zzz".into(),
    };
    let hum = ApproverKind::Human {
        operator_id: "aaa".into(),
    };
    assert!(sys < hum);
}

// ===========================================================================
// 8. SelfReplacementError enrichment
// ===========================================================================

#[test]
fn enrichment_error_display_uniqueness() {
    let mut displays = BTreeSet::new();
    displays.insert(
        SelfReplacementError::InsufficientSignatures {
            required: 2,
            present: 1,
        }
        .to_string(),
    );
    displays.insert(
        SelfReplacementError::SignatureInvalid {
            signer_index: 0,
            role: "test".into(),
        }
        .to_string(),
    );
    displays.insert(
        SelfReplacementError::SlotMismatch {
            expected: "a".into(),
            got: "b".into(),
        }
        .to_string(),
    );
    displays.insert(SelfReplacementError::EmptyValidationArtifacts.to_string());
    displays.insert(
        SelfReplacementError::ValidationFailed {
            slot_id: "s".into(),
        }
        .to_string(),
    );
    displays.insert(
        SelfReplacementError::UnsupportedSchemaVersion {
            version: "v99".into(),
        }
        .to_string(),
    );
    assert_eq!(displays.len(), 6);
}

#[test]
fn enrichment_error_insufficient_signatures_display_values() {
    let err = SelfReplacementError::InsufficientSignatures {
        required: 5,
        present: 2,
    };
    let msg = err.to_string();
    assert!(msg.contains("2/5") || (msg.contains("2") && msg.contains("5")));
}

#[test]
fn enrichment_error_slot_mismatch_display_both_slots() {
    let err = SelfReplacementError::SlotMismatch {
        expected: "slot-alpha".into(),
        got: "slot-beta".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("slot-alpha"));
    assert!(msg.contains("slot-beta"));
}

#[test]
fn enrichment_error_serde_all_non_wrapping_variants() {
    let variants: Vec<SelfReplacementError> = vec![
        SelfReplacementError::InsufficientSignatures {
            required: 3,
            present: 1,
        },
        SelfReplacementError::SignatureInvalid {
            signer_index: 7,
            role: "auditor".into(),
        },
        SelfReplacementError::SlotMismatch {
            expected: "s1".into(),
            got: "s2".into(),
        },
        SelfReplacementError::EmptyValidationArtifacts,
        SelfReplacementError::ValidationFailed {
            slot_id: "failed-slot".into(),
        },
        SelfReplacementError::UnsupportedSchemaVersion {
            version: "v42".into(),
        },
    ];
    for err in &variants {
        let json = serde_json::to_string(err).unwrap();
        let back: SelfReplacementError = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, err);
    }
}

#[test]
fn enrichment_error_is_std_error_trait() {
    let err = SelfReplacementError::ValidationFailed {
        slot_id: "test".into(),
    };
    let dyn_err: &dyn std::error::Error = &err;
    // source() is None for this error type
    assert!(dyn_err.source().is_none());
    // Display works through trait object
    let msg = format!("{dyn_err}");
    assert!(!msg.is_empty());
}

// ===========================================================================
// 9. SandboxConfiguration enrichment
// ===========================================================================

#[test]
fn enrichment_sandbox_default_values() {
    let sb = SandboxConfiguration::default();
    assert_eq!(sb.max_heap_bytes, 64 * 1024 * 1024);
    assert_eq!(sb.max_execution_ns, 5_000_000_000);
    assert_eq!(sb.max_hostcalls, 10_000);
    assert!(!sb.network_egress_allowed);
    assert!(!sb.filesystem_access_allowed);
}

#[test]
fn enrichment_sandbox_custom_all_permissive() {
    let sb = SandboxConfiguration {
        max_heap_bytes: u64::MAX,
        max_execution_ns: u64::MAX,
        max_hostcalls: u64::MAX,
        network_egress_allowed: true,
        filesystem_access_allowed: true,
    };
    let json = serde_json::to_string(&sb).unwrap();
    let back: SandboxConfiguration = serde_json::from_str(&json).unwrap();
    assert_eq!(back, sb);
    assert!(back.network_egress_allowed);
    assert!(back.filesystem_access_allowed);
}

#[test]
fn enrichment_sandbox_minimal_values() {
    let sb = SandboxConfiguration {
        max_heap_bytes: 0,
        max_execution_ns: 0,
        max_hostcalls: 0,
        network_egress_allowed: false,
        filesystem_access_allowed: false,
    };
    let json = serde_json::to_string(&sb).unwrap();
    let back: SandboxConfiguration = serde_json::from_str(&json).unwrap();
    assert_eq!(back, sb);
}

// ===========================================================================
// 10. MonitoringHook enrichment
// ===========================================================================

#[test]
fn enrichment_monitoring_hook_serde_blocking() {
    let hook = MonitoringHook {
        hook_id: "block-hook".into(),
        trigger_event: "pre-exec".into(),
        blocking: true,
    };
    let json = serde_json::to_string(&hook).unwrap();
    let back: MonitoringHook = serde_json::from_str(&json).unwrap();
    assert_eq!(back, hook);
    assert!(back.blocking);
}

#[test]
fn enrichment_monitoring_hook_serde_nonblocking() {
    let hook = MonitoringHook {
        hook_id: "async-hook".into(),
        trigger_event: "post-exec".into(),
        blocking: false,
    };
    let json = serde_json::to_string(&hook).unwrap();
    let back: MonitoringHook = serde_json::from_str(&json).unwrap();
    assert_eq!(back, hook);
    assert!(!back.blocking);
}

// ===========================================================================
// 11. SignerEntry enrichment
// ===========================================================================

#[test]
fn enrichment_signer_entry_serde_roundtrip() {
    let entry = SignerEntry {
        role: "governance-approver".into(),
        verification_key: sk1().verification_key(),
        signature: Signature::from_bytes([0xAA; 64]),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: SignerEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, entry);
}

#[test]
fn enrichment_signer_entry_different_roles_not_equal() {
    let e1 = SignerEntry {
        role: "gate-runner".into(),
        verification_key: sk1().verification_key(),
        signature: Signature::from_bytes([0u8; 64]),
    };
    let e2 = SignerEntry {
        role: "governance".into(),
        verification_key: sk1().verification_key(),
        signature: Signature::from_bytes([0u8; 64]),
    };
    assert_ne!(e1, e2);
}

// ===========================================================================
// 12. SignatureBundle enrichment
// ===========================================================================

#[test]
fn enrichment_bundle_threshold_zero_meets_with_no_signers() {
    let bundle = SignatureBundle::new(0);
    assert!(bundle.meets_threshold());
    assert!(bundle.verify_all(b"anything").is_ok());
}

#[test]
fn enrichment_bundle_threshold_one_needs_one() {
    let mut bundle = SignatureBundle::new(1);
    assert!(!bundle.meets_threshold());
    let preimage = b"enrichment-preimage";
    let sig = sign_preimage(&sk1(), preimage).unwrap();
    bundle.add_signer(SignerEntry {
        role: "signer".into(),
        verification_key: sk1().verification_key(),
        signature: sig,
    });
    assert!(bundle.meets_threshold());
    assert!(bundle.verify_all(preimage).is_ok());
}

#[test]
fn enrichment_bundle_exceeding_threshold_still_passes() {
    let mut bundle = SignatureBundle::new(1);
    let preimage = b"over-threshold";
    for sk in [sk1(), sk2(), sk3()] {
        let sig = sign_preimage(&sk, preimage).unwrap();
        bundle.add_signer(SignerEntry {
            role: "signer".into(),
            verification_key: sk.verification_key(),
            signature: sig,
        });
    }
    assert_eq!(bundle.signers.len(), 3);
    assert!(bundle.meets_threshold());
    assert!(bundle.verify_all(preimage).is_ok());
}

#[test]
fn enrichment_bundle_verify_wrong_preimage_fails() {
    let mut bundle = SignatureBundle::new(1);
    let sig = sign_preimage(&sk1(), b"correct").unwrap();
    bundle.add_signer(SignerEntry {
        role: "signer".into(),
        verification_key: sk1().verification_key(),
        signature: sig,
    });
    let err = bundle.verify_all(b"wrong").unwrap_err();
    assert!(matches!(
        err,
        SelfReplacementError::SignatureInvalid {
            signer_index: 0,
            ..
        }
    ));
}

#[test]
fn enrichment_bundle_serde_with_signers() {
    let mut bundle = SignatureBundle::new(2);
    let preimage = b"serde-bundle";
    for sk in [sk1(), sk2()] {
        let sig = sign_preimage(&sk, preimage).unwrap();
        bundle.add_signer(SignerEntry {
            role: "party".into(),
            verification_key: sk.verification_key(),
            signature: sig,
        });
    }
    let json = serde_json::to_string(&bundle).unwrap();
    let back: SignatureBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(back, bundle);
    assert!(back.verify_all(preimage).is_ok());
}

// ===========================================================================
// 13. DelegateCellManifest enrichment
// ===========================================================================

#[test]
fn enrichment_manifest_derive_id_deterministic_100_iterations() {
    let s = default_slot();
    let bh = default_behavior_hash();
    let first =
        DelegateCellManifest::derive_manifest_id(&s, DelegateType::WasmBacked, &bh, "zone-det")
            .unwrap();
    for _ in 0..100 {
        let id =
            DelegateCellManifest::derive_manifest_id(&s, DelegateType::WasmBacked, &bh, "zone-det")
                .unwrap();
        assert_eq!(first, id);
    }
}

#[test]
fn enrichment_manifest_id_varies_by_slot() {
    let bh = default_behavior_hash();
    let id1 = DelegateCellManifest::derive_manifest_id(
        &slot("slot-a"),
        DelegateType::QuickJsBacked,
        &bh,
        "z",
    )
    .unwrap();
    let id2 = DelegateCellManifest::derive_manifest_id(
        &slot("slot-b"),
        DelegateType::QuickJsBacked,
        &bh,
        "z",
    )
    .unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn enrichment_manifest_id_varies_by_behavior_hash() {
    let s = default_slot();
    let bh1 = [0x00; 32];
    let bh2 = [0xFF; 32];
    let id1 = DelegateCellManifest::derive_manifest_id(&s, DelegateType::QuickJsBacked, &bh1, "z")
        .unwrap();
    let id2 = DelegateCellManifest::derive_manifest_id(&s, DelegateType::QuickJsBacked, &bh2, "z")
        .unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn enrichment_manifest_id_varies_by_zone() {
    let s = default_slot();
    let bh = default_behavior_hash();
    let id1 =
        DelegateCellManifest::derive_manifest_id(&s, DelegateType::QuickJsBacked, &bh, "zone-x")
            .unwrap();
    let id2 =
        DelegateCellManifest::derive_manifest_id(&s, DelegateType::QuickJsBacked, &bh, "zone-y")
            .unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn enrichment_manifest_create_signed_all_delegate_types() {
    for dtype in [
        DelegateType::QuickJsBacked,
        DelegateType::WasmBacked,
        DelegateType::ExternalProcess,
    ] {
        let m = make_manifest(&sk1(), &default_slot(), dtype, "type-zone");
        assert_eq!(m.delegate_type, dtype);
        assert!(m.verify_signature(&sk1().verification_key()).is_ok());
    }
}

#[test]
fn enrichment_manifest_verify_fails_wrong_key() {
    let m = make_manifest(&sk1(), &default_slot(), DelegateType::QuickJsBacked, "z");
    let wrong_vk = sk2().verification_key();
    assert!(m.verify_signature(&wrong_vk).is_err());
}

#[test]
fn enrichment_manifest_serde_roundtrip_preserves_all_fields() {
    let m = make_manifest(
        &sk1(),
        &default_slot(),
        DelegateType::ExternalProcess,
        "full-zone",
    );
    let json = serde_json::to_string(&m).unwrap();
    let back: DelegateCellManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(back.manifest_id, m.manifest_id);
    assert_eq!(back.schema_version, m.schema_version);
    assert_eq!(back.slot_id, m.slot_id);
    assert_eq!(back.delegate_type, m.delegate_type);
    assert_eq!(back.sandbox, m.sandbox);
    assert_eq!(back.monitoring_hooks, m.monitoring_hooks);
    assert_eq!(back.expected_behavior_hash, m.expected_behavior_hash);
    assert_eq!(back.zone, m.zone);
    assert_eq!(back.signature, m.signature);
}

#[test]
fn enrichment_manifest_empty_hooks_create_signed() {
    let envelope = default_envelope();
    let sandbox = default_sandbox();
    let bh = default_behavior_hash();
    let m = DelegateCellManifest::create_signed(
        &sk1(),
        CreateManifestInput {
            slot_id: &default_slot(),
            delegate_type: DelegateType::WasmBacked,
            capability_envelope: &envelope,
            sandbox: &sandbox,
            monitoring_hooks: &[],
            expected_behavior_hash: &bh,
            zone: "empty-hooks",
        },
    )
    .unwrap();
    assert!(m.monitoring_hooks.is_empty());
    assert!(m.verify_signature(&sk1().verification_key()).is_ok());
}

// ===========================================================================
// 14. ValidationArtifactRef enrichment
// ===========================================================================

#[test]
fn enrichment_validation_artifact_ref_serde_passed() {
    let art = ValidationArtifactRef {
        kind: ValidationArtifactKind::AdversarialSurvival,
        artifact_digest: "adv-digest".into(),
        passed: true,
        summary: "survived all adversarial tests".into(),
    };
    let json = serde_json::to_string(&art).unwrap();
    let back: ValidationArtifactRef = serde_json::from_str(&json).unwrap();
    assert_eq!(back, art);
}

#[test]
fn enrichment_validation_artifact_ref_serde_failed() {
    let art = ValidationArtifactRef {
        kind: ValidationArtifactKind::PerformanceBenchmark,
        artifact_digest: "perf-fail-digest".into(),
        passed: false,
        summary: "latency regression detected".into(),
    };
    let json = serde_json::to_string(&art).unwrap();
    let back: ValidationArtifactRef = serde_json::from_str(&json).unwrap();
    assert_eq!(back, art);
    assert!(!back.passed);
}

// ===========================================================================
// 15. GateResult enrichment
// ===========================================================================

#[test]
fn enrichment_gate_result_serde_with_multiple_evidence_refs() {
    let gr = GateResult {
        gate_name: "multi-evidence-gate".into(),
        passed: true,
        evidence_refs: vec!["ref-a".into(), "ref-b".into(), "ref-c".into()],
        summary: "all references valid".into(),
    };
    let json = serde_json::to_string(&gr).unwrap();
    let back: GateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, gr);
    assert_eq!(back.evidence_refs.len(), 3);
}

#[test]
fn enrichment_gate_result_serde_empty_evidence() {
    let gr = GateResult {
        gate_name: "no-evidence-gate".into(),
        passed: false,
        evidence_refs: vec![],
        summary: "no evidence available".into(),
    };
    let json = serde_json::to_string(&gr).unwrap();
    let back: GateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, gr);
    assert!(back.evidence_refs.is_empty());
}

// ===========================================================================
// 16. ReplacementReceipt enrichment
// ===========================================================================

#[test]
fn enrichment_receipt_empty_artifacts_rejected() {
    let result = ReplacementReceipt::create_unsigned(CreateReceiptInput {
        slot_id: &default_slot(),
        old_cell_digest: "old",
        new_cell_digest: "new",
        validation_artifacts: &[],
        rollback_token: "rb",
        promotion_rationale: "none",
        timestamp_ns: 100,
        epoch: SecurityEpoch::from_raw(1),
        zone: "z",
        required_signatures: 1,
    });
    assert!(matches!(
        result,
        Err(SelfReplacementError::EmptyValidationArtifacts)
    ));
}

#[test]
fn enrichment_receipt_id_deterministic_100_iterations() {
    let s = default_slot();
    let first = ReplacementReceipt::derive_receipt_id(&s, "old-det", "new-det", 42_000, "zone-det")
        .unwrap();
    for _ in 0..100 {
        let id =
            ReplacementReceipt::derive_receipt_id(&s, "old-det", "new-det", 42_000, "zone-det")
                .unwrap();
        assert_eq!(first, id);
    }
}

#[test]
fn enrichment_receipt_id_varies_by_old_digest() {
    let s = default_slot();
    let id1 = ReplacementReceipt::derive_receipt_id(&s, "old-a", "new", 1000, "z").unwrap();
    let id2 = ReplacementReceipt::derive_receipt_id(&s, "old-b", "new", 1000, "z").unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn enrichment_receipt_id_varies_by_new_digest() {
    let s = default_slot();
    let id1 = ReplacementReceipt::derive_receipt_id(&s, "old", "new-a", 1000, "z").unwrap();
    let id2 = ReplacementReceipt::derive_receipt_id(&s, "old", "new-b", 1000, "z").unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn enrichment_receipt_id_varies_by_timestamp() {
    let s = default_slot();
    let id1 = ReplacementReceipt::derive_receipt_id(&s, "old", "new", 1000, "z").unwrap();
    let id2 = ReplacementReceipt::derive_receipt_id(&s, "old", "new", 2000, "z").unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn enrichment_receipt_id_varies_by_zone() {
    let s = default_slot();
    let id1 = ReplacementReceipt::derive_receipt_id(&s, "old", "new", 1000, "zone-a").unwrap();
    let id2 = ReplacementReceipt::derive_receipt_id(&s, "old", "new", 1000, "zone-b").unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn enrichment_receipt_all_validations_passed_single_pass() {
    let arts = vec![ValidationArtifactRef {
        kind: ValidationArtifactKind::EquivalenceResult,
        artifact_digest: "single".into(),
        passed: true,
        summary: "ok".into(),
    }];
    let receipt = ReplacementReceipt::create_unsigned(CreateReceiptInput {
        slot_id: &default_slot(),
        old_cell_digest: "old",
        new_cell_digest: "new",
        validation_artifacts: &arts,
        rollback_token: "rb",
        promotion_rationale: "single pass",
        timestamp_ns: 500,
        epoch: SecurityEpoch::from_raw(1),
        zone: "z",
        required_signatures: 1,
    })
    .unwrap();
    assert!(receipt.all_validations_passed());
}

#[test]
fn enrichment_receipt_all_validations_false_when_all_fail() {
    let arts = vec![
        ValidationArtifactRef {
            kind: ValidationArtifactKind::EquivalenceResult,
            artifact_digest: "f1".into(),
            passed: false,
            summary: "fail".into(),
        },
        ValidationArtifactRef {
            kind: ValidationArtifactKind::PerformanceBenchmark,
            artifact_digest: "f2".into(),
            passed: false,
            summary: "fail".into(),
        },
    ];
    let receipt = ReplacementReceipt::create_unsigned(CreateReceiptInput {
        slot_id: &default_slot(),
        old_cell_digest: "old",
        new_cell_digest: "new",
        validation_artifacts: &arts,
        rollback_token: "rb",
        promotion_rationale: "all fail",
        timestamp_ns: 600,
        epoch: SecurityEpoch::from_raw(1),
        zone: "z",
        required_signatures: 1,
    })
    .unwrap();
    assert!(!receipt.all_validations_passed());
}

#[test]
fn enrichment_receipt_add_and_verify_multi_party() {
    let mut receipt = make_receipt(&default_slot(), 7000, "multi-zone", 2);
    receipt.add_signature(&sk1(), "gate-runner").unwrap();
    // Still insufficient
    assert!(matches!(
        receipt.verify_signatures(),
        Err(SelfReplacementError::InsufficientSignatures {
            required: 2,
            present: 1
        })
    ));
    receipt.add_signature(&sk2(), "governance").unwrap();
    assert!(receipt.verify_signatures().is_ok());
}

#[test]
fn enrichment_receipt_serde_roundtrip_after_signing() {
    let mut receipt = make_receipt(&default_slot(), 8000, "serde-zone", 1);
    receipt.add_signature(&sk1(), "signer").unwrap();
    let json = serde_json::to_string(&receipt).unwrap();
    let back: ReplacementReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(back, receipt);
    assert_eq!(back.old_cell_digest, "old-enrich");
    assert_eq!(back.new_cell_digest, "new-enrich");
}

// ===========================================================================
// 17. PromotionDecision enrichment
// ===========================================================================

#[test]
fn enrichment_decision_all_gates_pass_yields_approved() {
    let gates = passing_gates();
    let approver = ApproverKind::System {
        component: "auto".into(),
    };
    let d = make_decision(
        &default_slot(),
        1000,
        "z",
        &gates,
        RiskLevel::Low,
        &approver,
        1,
    );
    assert_eq!(d.verdict, GateVerdict::Approved);
    assert!(d.is_approved());
}

#[test]
fn enrichment_decision_one_gate_fails_yields_denied() {
    let mut gates = passing_gates();
    gates[1].passed = false;
    let approver = ApproverKind::System {
        component: "auto".into(),
    };
    let d = make_decision(
        &default_slot(),
        2000,
        "z",
        &gates,
        RiskLevel::Medium,
        &approver,
        1,
    );
    assert_eq!(d.verdict, GateVerdict::Denied);
    assert!(!d.is_approved());
}

#[test]
fn enrichment_decision_empty_gates_yields_inconclusive() {
    let approver = ApproverKind::Human {
        operator_id: "op-1".into(),
    };
    let d = make_decision(
        &default_slot(),
        3000,
        "z",
        &[],
        RiskLevel::High,
        &approver,
        1,
    );
    assert_eq!(d.verdict, GateVerdict::Inconclusive);
    assert!(!d.is_approved());
}

#[test]
fn enrichment_decision_id_deterministic_100_iterations() {
    let s = default_slot();
    let first = PromotionDecision::derive_decision_id(&s, "cand-det", 9999, "zone-det").unwrap();
    for _ in 0..100 {
        let id = PromotionDecision::derive_decision_id(&s, "cand-det", 9999, "zone-det").unwrap();
        assert_eq!(first, id);
    }
}

#[test]
fn enrichment_decision_id_varies_by_candidate() {
    let s = default_slot();
    let id1 = PromotionDecision::derive_decision_id(&s, "cand-a", 1000, "z").unwrap();
    let id2 = PromotionDecision::derive_decision_id(&s, "cand-b", 1000, "z").unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn enrichment_decision_id_varies_by_zone() {
    let s = default_slot();
    let id1 = PromotionDecision::derive_decision_id(&s, "cand", 1000, "zone-1").unwrap();
    let id2 = PromotionDecision::derive_decision_id(&s, "cand", 1000, "zone-2").unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn enrichment_decision_add_and_verify_signatures() {
    let gates = passing_gates();
    let approver = ApproverKind::System {
        component: "gate".into(),
    };
    let mut d = make_decision(
        &default_slot(),
        4000,
        "sig-zone",
        &gates,
        RiskLevel::Low,
        &approver,
        2,
    );
    d.add_signature(&sk1(), "gate-runner").unwrap();
    d.add_signature(&sk2(), "governance").unwrap();
    assert!(d.verify_signatures().is_ok());
}

#[test]
fn enrichment_decision_serde_roundtrip() {
    let gates = passing_gates();
    let approver = ApproverKind::Human {
        operator_id: "ops-42".into(),
    };
    let mut d = make_decision(
        &default_slot(),
        5000,
        "serde-zone",
        &gates,
        RiskLevel::Critical,
        &approver,
        1,
    );
    d.add_signature(&sk1(), "signer").unwrap();
    let json = serde_json::to_string(&d).unwrap();
    let back: PromotionDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d);
    assert_eq!(back.risk_level, RiskLevel::Critical);
    assert_eq!(back.verdict, GateVerdict::Approved);
}

// ===========================================================================
// 18. ReplacementLifecycle enrichment
// ===========================================================================

#[test]
fn enrichment_lifecycle_starts_at_research() {
    let m = make_manifest(&sk1(), &default_slot(), DelegateType::QuickJsBacked, "z");
    let lc = ReplacementLifecycle::new(default_slot(), m);
    assert_eq!(lc.current_stage, ReplacementStage::Research);
    assert!(!lc.is_production());
    assert_eq!(lc.completed_stages(), 0);
    assert!(lc.decisions.is_empty());
    assert!(lc.receipts.is_empty());
}

#[test]
fn enrichment_lifecycle_record_decision_accumulates() {
    let m = make_manifest(&sk1(), &default_slot(), DelegateType::QuickJsBacked, "z");
    let mut lc = ReplacementLifecycle::new(default_slot(), m);
    let gates = passing_gates();
    let approver = ApproverKind::System {
        component: "gate".into(),
    };
    for i in 0..5 {
        let d = make_decision(
            &default_slot(),
            1000 + i * 100,
            "z",
            &gates,
            RiskLevel::Low,
            &approver,
            1,
        );
        lc.record_decision(d).unwrap();
    }
    assert_eq!(lc.decisions.len(), 5);
    // Decisions do not advance stage
    assert_eq!(lc.current_stage, ReplacementStage::Research);
}

#[test]
fn enrichment_lifecycle_decision_slot_mismatch() {
    let m = make_manifest(&sk1(), &default_slot(), DelegateType::QuickJsBacked, "z");
    let mut lc = ReplacementLifecycle::new(default_slot(), m);
    let wrong = slot("wrong-slot");
    let gates = passing_gates();
    let approver = ApproverKind::System {
        component: "gate".into(),
    };
    let d = make_decision(&wrong, 1000, "z", &gates, RiskLevel::Low, &approver, 1);
    let err = lc.record_decision(d).unwrap_err();
    assert!(matches!(err, SelfReplacementError::SlotMismatch { .. }));
}

#[test]
fn enrichment_lifecycle_receipt_slot_mismatch() {
    let m = make_manifest(&sk1(), &default_slot(), DelegateType::QuickJsBacked, "z");
    let mut lc = ReplacementLifecycle::new(default_slot(), m);
    let wrong = slot("wrong-slot");
    let mut r = make_receipt(&wrong, 1000, "z", 1);
    r.add_signature(&sk1(), "signer").unwrap();
    let err = lc.record_receipt(r).unwrap_err();
    assert!(matches!(err, SelfReplacementError::SlotMismatch { .. }));
}

#[test]
fn enrichment_lifecycle_receipt_with_failed_validation_rejected() {
    let m = make_manifest(&sk1(), &default_slot(), DelegateType::QuickJsBacked, "z");
    let mut lc = ReplacementLifecycle::new(default_slot(), m);
    let arts = vec![ValidationArtifactRef {
        kind: ValidationArtifactKind::EquivalenceResult,
        artifact_digest: "fail-art".into(),
        passed: false,
        summary: "mismatch".into(),
    }];
    let mut receipt = ReplacementReceipt::create_unsigned(CreateReceiptInput {
        slot_id: &default_slot(),
        old_cell_digest: "old",
        new_cell_digest: "new",
        validation_artifacts: &arts,
        rollback_token: "rb",
        promotion_rationale: "fail test",
        timestamp_ns: 1000,
        epoch: SecurityEpoch::from_raw(1),
        zone: "z",
        required_signatures: 1,
    })
    .unwrap();
    receipt.add_signature(&sk1(), "signer").unwrap();
    let err = lc.record_receipt(receipt).unwrap_err();
    assert!(matches!(err, SelfReplacementError::ValidationFailed { .. }));
    // Stage should not have advanced
    assert_eq!(lc.current_stage, ReplacementStage::Research);
}

#[test]
fn enrichment_lifecycle_full_research_to_production() {
    let m = make_manifest(&sk1(), &default_slot(), DelegateType::WasmBacked, "prod-z");
    let mut lc = ReplacementLifecycle::new(default_slot(), m);

    let expected_stages = [
        ReplacementStage::Shadow,
        ReplacementStage::Canary,
        ReplacementStage::Production,
    ];
    for (i, expected) in expected_stages.iter().enumerate() {
        let mut r = make_receipt(&default_slot(), 1000 + i as u64 * 1000, "prod-z", 1);
        r.add_signature(&sk1(), "gate").unwrap();
        lc.record_receipt(r).unwrap();
        assert_eq!(lc.current_stage, *expected);
    }
    assert!(lc.is_production());
    assert_eq!(lc.completed_stages(), 3);
}

#[test]
fn enrichment_lifecycle_production_stays_at_production() {
    let m = make_manifest(&sk1(), &default_slot(), DelegateType::QuickJsBacked, "z");
    let mut lc = ReplacementLifecycle::new(default_slot(), m);

    // Advance to production (3 receipts)
    for i in 0..3 {
        let mut r = make_receipt(&default_slot(), 1000 + i * 1000, "z", 1);
        r.add_signature(&sk1(), "gate").unwrap();
        lc.record_receipt(r).unwrap();
    }
    assert!(lc.is_production());

    // Additional receipt keeps us at production
    let mut r4 = make_receipt(&default_slot(), 9999, "z", 1);
    r4.add_signature(&sk1(), "gate").unwrap();
    lc.record_receipt(r4).unwrap();
    assert!(lc.is_production());
    assert_eq!(lc.completed_stages(), 4);
}

#[test]
fn enrichment_lifecycle_serde_roundtrip_empty() {
    let m = make_manifest(&sk1(), &default_slot(), DelegateType::QuickJsBacked, "z");
    let lc = ReplacementLifecycle::new(default_slot(), m);
    let json = serde_json::to_string(&lc).unwrap();
    let back: ReplacementLifecycle = serde_json::from_str(&json).unwrap();
    assert_eq!(back, lc);
}

#[test]
fn enrichment_lifecycle_serde_roundtrip_with_decisions_and_receipts() {
    let m = make_manifest(&sk1(), &default_slot(), DelegateType::QuickJsBacked, "z");
    let mut lc = ReplacementLifecycle::new(default_slot(), m);

    // Add a decision
    let gates = passing_gates();
    let approver = ApproverKind::System {
        component: "gate".into(),
    };
    let d = make_decision(
        &default_slot(),
        500,
        "z",
        &gates,
        RiskLevel::Low,
        &approver,
        1,
    );
    lc.record_decision(d).unwrap();

    // Add a receipt to advance
    let mut r = make_receipt(&default_slot(), 600, "z", 1);
    r.add_signature(&sk1(), "gate").unwrap();
    lc.record_receipt(r).unwrap();

    let json = serde_json::to_string(&lc).unwrap();
    let back: ReplacementLifecycle = serde_json::from_str(&json).unwrap();
    assert_eq!(back, lc);
    assert_eq!(back.current_stage, ReplacementStage::Shadow);
    assert_eq!(back.decisions.len(), 1);
    assert_eq!(back.receipts.len(), 1);
}

// ===========================================================================
// 19. Cross-artifact ID isolation
// ===========================================================================

#[test]
fn enrichment_cross_artifact_ids_all_distinct() {
    let s = default_slot();
    let bh = default_behavior_hash();
    let manifest_id =
        DelegateCellManifest::derive_manifest_id(&s, DelegateType::QuickJsBacked, &bh, "cross")
            .unwrap();
    let receipt_id =
        ReplacementReceipt::derive_receipt_id(&s, "old", "new", 1000, "cross").unwrap();
    let decision_id =
        PromotionDecision::derive_decision_id(&s, "candidate", 1000, "cross").unwrap();
    let mut ids = BTreeSet::new();
    ids.insert(manifest_id.as_bytes().to_vec());
    ids.insert(receipt_id.as_bytes().to_vec());
    ids.insert(decision_id.as_bytes().to_vec());
    assert_eq!(ids.len(), 3);
}

#[test]
fn enrichment_same_slot_different_artifact_types_distinct_ids() {
    let s = slot("shared-slot");
    let bh = [0x11; 32];
    // All three artifact types for the same slot should produce different IDs
    let m_id =
        DelegateCellManifest::derive_manifest_id(&s, DelegateType::WasmBacked, &bh, "shared-zone")
            .unwrap();
    let r_id =
        ReplacementReceipt::derive_receipt_id(&s, "old", "new", 5000, "shared-zone").unwrap();
    let d_id = PromotionDecision::derive_decision_id(&s, "new", 5000, "shared-zone").unwrap();
    assert_ne!(m_id, r_id);
    assert_ne!(r_id, d_id);
    assert_ne!(m_id, d_id);
}

// ===========================================================================
// 20. Comprehensive Display + Serde sweep
// ===========================================================================

#[test]
fn enrichment_all_display_enums_produce_nonempty_strings() {
    let displays: Vec<String> = vec![
        SchemaVersion::V1.to_string(),
        DelegateType::QuickJsBacked.to_string(),
        DelegateType::WasmBacked.to_string(),
        DelegateType::ExternalProcess.to_string(),
        ValidationArtifactKind::EquivalenceResult.to_string(),
        ValidationArtifactKind::CapabilityPreservation.to_string(),
        ValidationArtifactKind::PerformanceBenchmark.to_string(),
        ValidationArtifactKind::AdversarialSurvival.to_string(),
        GateVerdict::Approved.to_string(),
        GateVerdict::Denied.to_string(),
        GateVerdict::Inconclusive.to_string(),
        RiskLevel::Low.to_string(),
        RiskLevel::Medium.to_string(),
        RiskLevel::High.to_string(),
        RiskLevel::Critical.to_string(),
        ReplacementStage::Research.to_string(),
        ReplacementStage::Shadow.to_string(),
        ReplacementStage::Canary.to_string(),
        ReplacementStage::Production.to_string(),
        ApproverKind::System {
            component: "x".into(),
        }
        .to_string(),
        ApproverKind::Human {
            operator_id: "y".into(),
        }
        .to_string(),
    ];
    for d in &displays {
        assert!(!d.is_empty(), "Display string was empty");
    }
}

#[test]
fn enrichment_all_display_enum_variants_globally_unique() {
    let mut all = BTreeSet::new();
    // Collect all variant display strings that should be unique across enum types
    for s in [
        SchemaVersion::V1.to_string(),
        DelegateType::QuickJsBacked.to_string(),
        DelegateType::WasmBacked.to_string(),
        DelegateType::ExternalProcess.to_string(),
        GateVerdict::Approved.to_string(),
        GateVerdict::Denied.to_string(),
        GateVerdict::Inconclusive.to_string(),
        RiskLevel::Low.to_string(),
        RiskLevel::Medium.to_string(),
        RiskLevel::High.to_string(),
        RiskLevel::Critical.to_string(),
        ReplacementStage::Research.to_string(),
        ReplacementStage::Shadow.to_string(),
        ReplacementStage::Canary.to_string(),
        ReplacementStage::Production.to_string(),
        ValidationArtifactKind::EquivalenceResult.to_string(),
        ValidationArtifactKind::CapabilityPreservation.to_string(),
        ValidationArtifactKind::PerformanceBenchmark.to_string(),
        ValidationArtifactKind::AdversarialSurvival.to_string(),
    ] {
        all.insert(s);
    }
    // 1 + 3 + 3 + 4 + 4 + 4 = 19 unique strings
    assert_eq!(all.len(), 19);
}
