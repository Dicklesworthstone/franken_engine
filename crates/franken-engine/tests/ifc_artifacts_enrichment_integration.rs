//! Enrichment integration tests for `ifc_artifacts`.
//!
//! Covers: IfcSchemaVersion CURRENT/new/is_compatible_with/display/serde,
//! Label level/join/meet/can_flow_to/join_all/meet_all/all_builtin/display/serde,
//! ClearanceClass level/max_receivable_label_level/can_receive/all/as_str/display/serde,
//! DeclassificationObligation conditions_satisfied/is_expired,
//! Ir2LabelSource assign_label, FlowEnvelope is_flow_authorized/content_hash,
//! FlowRule/DeclassificationRoute serde, FlowPolicy is_flow_allowed/content_hash/sign/verify,
//! FlowCheckResult serde, ProofMethod display/serde, FlowProof content_hash/sign/verify,
//! DeclassificationDecision display/serde, DeclassificationReceipt sign/verify/replay_command,
//! ClaimStrength display/serde, ConfinementClaim is_full/validate/sign/verify,
//! IfcValidationError display, and determinism checks.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use std::collections::BTreeSet;

use frankenengine_engine::ifc_artifacts::*;
use frankenengine_engine::signature_preimage::{SIGNATURE_SENTINEL, Signature, SigningKey};

// ===========================================================================
// Helpers
// ===========================================================================

fn test_key() -> SigningKey {
    SigningKey::from_bytes([42u8; 32])
}

fn sentinel_sig() -> Signature {
    Signature::from_bytes(SIGNATURE_SENTINEL)
}

fn make_policy() -> FlowPolicy {
    FlowPolicy {
        policy_id: "pol-e-001".into(),
        extension_id: "ext-e-abc".into(),
        label_classes: [Label::Public, Label::Internal, Label::Confidential]
            .into_iter()
            .collect(),
        clearance_classes: [Label::Public, Label::Internal, Label::Confidential]
            .into_iter()
            .collect(),
        allowed_flows: vec![FlowRule {
            source_label: Label::Internal,
            sink_clearance: Label::Confidential,
        }],
        prohibited_flows: vec![FlowRule {
            source_label: Label::Confidential,
            sink_clearance: Label::Public,
        }],
        declassification_routes: vec![DeclassificationRoute {
            route_id: "declass-e-1".into(),
            source_label: Label::Secret,
            target_clearance: Label::Internal,
            conditions: vec!["audit_approval".into()],
        }],
        epoch_id: 1,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: sentinel_sig(),
    }
}

fn make_proof() -> FlowProof {
    FlowProof {
        proof_id: "proof-e-001".into(),
        flow_source_label: Label::Public,
        flow_source_location: "mod::read".into(),
        flow_sink_clearance: Label::Internal,
        flow_sink_location: "mod::write".into(),
        policy_ref: "pol-e-001".into(),
        proof_method: ProofMethod::StaticAnalysis,
        proof_evidence: vec!["ir42".into()],
        timestamp_ms: 1_700_000_000_000,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: sentinel_sig(),
    }
}

fn make_receipt() -> DeclassificationReceipt {
    DeclassificationReceipt {
        receipt_id: "receipt-e-001".into(),
        source_label: Label::Secret,
        sink_clearance: Label::Internal,
        declassification_route_ref: "declass-e-1".into(),
        decision_contract_id: "dc-e-1".into(),
        policy_evaluation_summary: "approved".into(),
        loss_assessment_milli: 5000,
        decision: DeclassificationDecision::Allow,
        authorized_by: test_key().verification_key(),
        replay_linkage: "trace-e".into(),
        timestamp_ms: 1_700_000_000_000,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: sentinel_sig(),
    }
}

fn make_claim(strength: ClaimStrength) -> ConfinementClaim {
    ConfinementClaim {
        claim_id: "claim-e-001".into(),
        component_id: "comp-e".into(),
        policy_ref: "pol-e-001".into(),
        flow_proofs: vec!["proof-e-001".into()],
        uncovered_flows: if strength == ClaimStrength::Full {
            vec![]
        } else {
            vec![FlowRule {
                source_label: Label::Confidential,
                sink_clearance: Label::Internal,
            }]
        },
        claim_strength: strength,
        timestamp_ms: 1_700_000_000_000,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: sentinel_sig(),
    }
}

// ===========================================================================
// 1. IfcSchemaVersion CURRENT
// ===========================================================================

#[test]
fn schema_version_current() {
    let v = IfcSchemaVersion::CURRENT;
    assert_eq!(v.major, 1);
    assert_eq!(v.minor, 0);
    assert_eq!(v.patch, 0);
}

// ===========================================================================
// 2. IfcSchemaVersion serde roundtrip
// ===========================================================================

#[test]
fn schema_version_serde_roundtrip() {
    let v = IfcSchemaVersion::new(2, 3, 4);
    let json = serde_json::to_string(&v).unwrap();
    let back: IfcSchemaVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

// ===========================================================================
// 3. IfcSchemaVersion display
// ===========================================================================

#[test]
fn schema_version_display() {
    assert_eq!(IfcSchemaVersion::CURRENT.to_string(), "1.0.0");
    assert_eq!(IfcSchemaVersion::new(3, 1, 7).to_string(), "3.1.7");
}

// ===========================================================================
// 4. IfcSchemaVersion compatibility
// ===========================================================================

#[test]
fn schema_version_compatibility() {
    let v1_0 = IfcSchemaVersion::new(1, 0, 0);
    let v1_1 = IfcSchemaVersion::new(1, 1, 0);
    let v2_0 = IfcSchemaVersion::new(2, 0, 0);

    assert!(v1_1.is_compatible_with(&v1_0));
    assert!(!v1_0.is_compatible_with(&v1_1));
    assert!(!v2_0.is_compatible_with(&v1_0));
}

// ===========================================================================
// 5. Label levels
// ===========================================================================

#[test]
fn label_levels_ascending() {
    assert_eq!(Label::Public.level(), 0);
    assert_eq!(Label::Internal.level(), 1);
    assert_eq!(Label::Confidential.level(), 2);
    assert_eq!(Label::Secret.level(), 3);
    assert_eq!(Label::TopSecret.level(), 4);
}

// ===========================================================================
// 6. Label ordering
// ===========================================================================

#[test]
fn label_ordering() {
    assert!(Label::Public < Label::Internal);
    assert!(Label::Internal < Label::Confidential);
    assert!(Label::Confidential < Label::Secret);
    assert!(Label::Secret < Label::TopSecret);
}

// ===========================================================================
// 7. Label join
// ===========================================================================

#[test]
fn label_join() {
    assert_eq!(Label::Public.join(&Label::Secret), Label::Secret);
    assert_eq!(Label::Secret.join(&Label::Public), Label::Secret);
    assert_eq!(Label::Internal.join(&Label::Internal), Label::Internal);
}

// ===========================================================================
// 8. Label meet
// ===========================================================================

#[test]
fn label_meet() {
    assert_eq!(Label::Secret.meet(&Label::Public), Label::Public);
    assert_eq!(Label::Internal.meet(&Label::Internal), Label::Internal);
}

// ===========================================================================
// 9. Label can_flow_to
// ===========================================================================

#[test]
fn label_can_flow_to() {
    assert!(Label::Public.can_flow_to(&Label::Secret));
    assert!(Label::Public.can_flow_to(&Label::Public));
    assert!(!Label::Secret.can_flow_to(&Label::Public));
}

// ===========================================================================
// 10. Label join_all / meet_all
// ===========================================================================

#[test]
fn label_join_all_meet_all() {
    let labels = vec![Label::Public, Label::Internal, Label::Secret];
    assert_eq!(Label::join_all(labels.clone()), Some(Label::Secret));
    assert_eq!(Label::meet_all(labels), Some(Label::Public));
    assert_eq!(Label::join_all(Vec::<Label>::new()), None);
    assert_eq!(Label::meet_all(Vec::<Label>::new()), None);
}

// ===========================================================================
// 11. Label all_builtin
// ===========================================================================

#[test]
fn label_all_builtin() {
    let builtin = Label::all_builtin();
    assert_eq!(builtin.len(), 5);
    assert_eq!(builtin[0], Label::Public);
    assert_eq!(builtin[4], Label::TopSecret);
}

// ===========================================================================
// 12. Label serde roundtrip
// ===========================================================================

#[test]
fn label_serde_roundtrip() {
    for label in Label::all_builtin() {
        let json = serde_json::to_string(&label).unwrap();
        let back: Label = serde_json::from_str(&json).unwrap();
        assert_eq!(back, label);
    }
    let custom = Label::Custom {
        name: "custom_label".into(),
        level: 3,
    };
    let json = serde_json::to_string(&custom).unwrap();
    let back: Label = serde_json::from_str(&json).unwrap();
    assert_eq!(back, custom);
}

// ===========================================================================
// 13. Label Display distinct
// ===========================================================================

#[test]
fn label_display_distinct() {
    let labels: BTreeSet<String> = Label::all_builtin().iter().map(|l| l.to_string()).collect();
    assert_eq!(labels.len(), 5);
}

// ===========================================================================
// 14. ClearanceClass levels
// ===========================================================================

#[test]
fn clearance_class_levels() {
    assert_eq!(ClearanceClass::OpenSink.level(), 0);
    assert_eq!(ClearanceClass::NeverSink.level(), 4);
}

// ===========================================================================
// 15. ClearanceClass can_receive
// ===========================================================================

#[test]
fn clearance_class_can_receive() {
    assert!(ClearanceClass::OpenSink.can_receive(&Label::TopSecret));
    assert!(!ClearanceClass::NeverSink.can_receive(&Label::Internal));
    assert!(ClearanceClass::NeverSink.can_receive(&Label::Public));
}

// ===========================================================================
// 16. ClearanceClass serde roundtrip
// ===========================================================================

#[test]
fn clearance_class_serde_roundtrip() {
    for cls in ClearanceClass::all() {
        let json = serde_json::to_string(&cls).unwrap();
        let back: ClearanceClass = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cls);
    }
}

// ===========================================================================
// 17. ClearanceClass display distinct
// ===========================================================================

#[test]
fn clearance_class_display_distinct() {
    let labels: BTreeSet<String> = ClearanceClass::all()
        .iter()
        .map(|c| c.to_string())
        .collect();
    assert_eq!(labels.len(), 5);
}

// ===========================================================================
// 18. DeclassificationObligation conditions_satisfied
// ===========================================================================

#[test]
fn obligation_conditions_satisfied() {
    let ob = DeclassificationObligation {
        obligation_id: "ob-1".into(),
        source_label: Label::Secret,
        target_clearance: ClearanceClass::RestrictedSink,
        required_conditions: vec!["audit".into(), "sign_off".into()],
        max_loss_milli: 10_000,
        audit_trail_required: true,
        approval_authority: "ciso".into(),
        expiry_epoch: None,
    };
    let mut satisfied = BTreeSet::new();
    assert!(!ob.conditions_satisfied(&satisfied));
    satisfied.insert("audit".into());
    assert!(!ob.conditions_satisfied(&satisfied));
    satisfied.insert("sign_off".into());
    assert!(ob.conditions_satisfied(&satisfied));
}

// ===========================================================================
// 19. DeclassificationObligation is_expired
// ===========================================================================

#[test]
fn obligation_is_expired() {
    let ob = DeclassificationObligation {
        obligation_id: "ob-2".into(),
        source_label: Label::Secret,
        target_clearance: ClearanceClass::AuditedSink,
        required_conditions: vec![],
        max_loss_milli: 0,
        audit_trail_required: false,
        approval_authority: "admin".into(),
        expiry_epoch: Some(100),
    };
    assert!(!ob.is_expired(100)); // not past
    assert!(ob.is_expired(101)); // past

    let ob2 = DeclassificationObligation {
        expiry_epoch: None,
        ..ob
    };
    assert!(!ob2.is_expired(999)); // no expiry
}

// ===========================================================================
// 20. Ir2LabelSource assign_label
// ===========================================================================

#[test]
fn ir2_label_source_assign_label() {
    assert_eq!(Ir2LabelSource::Literal.assign_label(), Label::Public);
    assert_eq!(
        Ir2LabelSource::EnvironmentVariable.assign_label(),
        Label::Secret
    );
    assert_eq!(
        Ir2LabelSource::CredentialPath {
            is_key_material: true
        }
        .assign_label(),
        Label::TopSecret
    );
    assert_eq!(
        Ir2LabelSource::CredentialPath {
            is_key_material: false
        }
        .assign_label(),
        Label::Secret
    );
    assert_eq!(
        Ir2LabelSource::HostcallReturn {
            clearance_label: Label::Internal,
        }
        .assign_label(),
        Label::Internal
    );
    assert_eq!(
        Ir2LabelSource::Computed {
            input_labels: vec![Label::Public, Label::Confidential],
        }
        .assign_label(),
        Label::Confidential
    );
    assert_eq!(
        Ir2LabelSource::Declassified {
            receipt_ref: "r1".into(),
            effective_label: Label::Public,
        }
        .assign_label(),
        Label::Public
    );
}

// ===========================================================================
// 21. FlowPolicy is_flow_allowed
// ===========================================================================

#[test]
fn flow_policy_is_flow_allowed() {
    let policy = make_policy();
    // Explicit allowed
    assert_eq!(
        policy.is_flow_allowed(&Label::Internal, &Label::Confidential),
        FlowCheckResult::Allowed
    );
    // Explicit prohibited
    assert_eq!(
        policy.is_flow_allowed(&Label::Confidential, &Label::Public),
        FlowCheckResult::Prohibited
    );
    // Lattice allowed (Public <= Internal)
    assert_eq!(
        policy.is_flow_allowed(&Label::Public, &Label::Internal),
        FlowCheckResult::LatticeAllowed
    );
    // Declassification required
    assert!(matches!(
        policy.is_flow_allowed(&Label::Secret, &Label::Internal),
        FlowCheckResult::DeclassificationRequired { .. }
    ));
    // Denied
    assert_eq!(
        policy.is_flow_allowed(&Label::TopSecret, &Label::Public),
        FlowCheckResult::Denied
    );
}

// ===========================================================================
// 22. FlowPolicy content_hash determinism
// ===========================================================================

#[test]
fn flow_policy_content_hash_deterministic() {
    let p1 = make_policy();
    let p2 = make_policy();
    assert_eq!(p1.content_hash(), p2.content_hash());
}

// ===========================================================================
// 23. FlowPolicy serde roundtrip
// ===========================================================================

#[test]
fn flow_policy_serde_roundtrip() {
    let policy = make_policy();
    let json = serde_json::to_string(&policy).unwrap();
    let back: FlowPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(back, policy);
}

// ===========================================================================
// 24. FlowPolicy sign and verify
// ===========================================================================

#[test]
fn flow_policy_sign_verify() {
    let key = test_key();
    let mut policy = make_policy();
    policy.sign(&key).unwrap();
    let vk = key.verification_key();
    policy.verify(&vk).unwrap();
}

// ===========================================================================
// 25. ProofMethod serde roundtrip
// ===========================================================================

#[test]
fn proof_method_serde_roundtrip() {
    for pm in [
        ProofMethod::StaticAnalysis,
        ProofMethod::RuntimeCheck,
        ProofMethod::Declassification,
    ] {
        let json = serde_json::to_string(&pm).unwrap();
        let back: ProofMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(back, pm);
    }
}

// ===========================================================================
// 26. ProofMethod display distinct
// ===========================================================================

#[test]
fn proof_method_display_distinct() {
    let labels: BTreeSet<String> = [
        ProofMethod::StaticAnalysis,
        ProofMethod::RuntimeCheck,
        ProofMethod::Declassification,
    ]
    .iter()
    .map(|p| p.to_string())
    .collect();
    assert_eq!(labels.len(), 3);
}

// ===========================================================================
// 27. FlowProof content_hash determinism
// ===========================================================================

#[test]
fn flow_proof_content_hash_deterministic() {
    let p1 = make_proof();
    let p2 = make_proof();
    assert_eq!(p1.content_hash(), p2.content_hash());
}

// ===========================================================================
// 28. FlowProof serde roundtrip
// ===========================================================================

#[test]
fn flow_proof_serde_roundtrip() {
    let proof = make_proof();
    let json = serde_json::to_string(&proof).unwrap();
    let back: FlowProof = serde_json::from_str(&json).unwrap();
    assert_eq!(back, proof);
}

// ===========================================================================
// 29. FlowProof sign and verify
// ===========================================================================

#[test]
fn flow_proof_sign_verify() {
    let key = test_key();
    let mut proof = make_proof();
    proof.sign(&key).unwrap();
    let vk = key.verification_key();
    proof.verify(&vk).unwrap();
}

// ===========================================================================
// 30. DeclassificationDecision serde roundtrip
// ===========================================================================

#[test]
fn declassification_decision_serde_roundtrip() {
    for d in [
        DeclassificationDecision::Allow,
        DeclassificationDecision::Deny,
    ] {
        let json = serde_json::to_string(&d).unwrap();
        let back: DeclassificationDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);
    }
}

// ===========================================================================
// 31. DeclassificationDecision display distinct
// ===========================================================================

#[test]
fn declassification_decision_display_distinct() {
    assert_ne!(
        DeclassificationDecision::Allow.to_string(),
        DeclassificationDecision::Deny.to_string()
    );
}

// ===========================================================================
// 32. DeclassificationReceipt serde roundtrip
// ===========================================================================

#[test]
fn declassification_receipt_serde_roundtrip() {
    let r = make_receipt();
    let json = serde_json::to_string(&r).unwrap();
    let back: DeclassificationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

// ===========================================================================
// 33. DeclassificationReceipt content_hash determinism
// ===========================================================================

#[test]
fn declassification_receipt_content_hash_deterministic() {
    let r1 = make_receipt();
    let r2 = make_receipt();
    assert_eq!(r1.content_hash(), r2.content_hash());
}

// ===========================================================================
// 34. DeclassificationReceipt sign and verify
// ===========================================================================

#[test]
fn declassification_receipt_sign_verify() {
    let key = test_key();
    let mut receipt = make_receipt();
    receipt.sign(&key).unwrap();
    let vk = key.verification_key();
    receipt.verify(&vk).unwrap();
}

// ===========================================================================
// 35. DeclassificationReceipt replay_command
// ===========================================================================

#[test]
fn declassification_receipt_replay_command() {
    let receipt = make_receipt();
    let cmd = receipt.replay_command();
    assert_eq!(
        cmd,
        "frankenctl replay run --trace <trace.json> --mode strict"
    );
    assert!(!cmd.contains("frankenctl verify receipt"));
    assert!(!cmd.contains("--receipt-id"));
}

// ===========================================================================
// 36. ClaimStrength serde roundtrip
// ===========================================================================

#[test]
fn claim_strength_serde_roundtrip() {
    for cs in [ClaimStrength::Full, ClaimStrength::Partial] {
        let json = serde_json::to_string(&cs).unwrap();
        let back: ClaimStrength = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cs);
    }
}

// ===========================================================================
// 37. ClaimStrength display distinct
// ===========================================================================

#[test]
fn claim_strength_display_distinct() {
    assert_ne!(
        ClaimStrength::Full.to_string(),
        ClaimStrength::Partial.to_string()
    );
}

// ===========================================================================
// 38. ConfinementClaim is_full
// ===========================================================================

#[test]
fn confinement_claim_is_full() {
    assert!(make_claim(ClaimStrength::Full).is_full());
    assert!(!make_claim(ClaimStrength::Partial).is_full());
}

// ===========================================================================
// 39. ConfinementClaim validate
// ===========================================================================

#[test]
fn confinement_claim_validate_full_ok() {
    let claim = make_claim(ClaimStrength::Full);
    assert!(claim.validate().is_ok());
}

#[test]
fn confinement_claim_validate_full_with_uncovered() {
    let mut claim = make_claim(ClaimStrength::Full);
    claim.uncovered_flows.push(FlowRule {
        source_label: Label::Secret,
        sink_clearance: Label::Public,
    });
    assert!(matches!(
        claim.validate(),
        Err(IfcValidationError::FullClaimHasUncoveredFlows { .. })
    ));
}

#[test]
fn confinement_claim_validate_empty() {
    let mut claim = make_claim(ClaimStrength::Full);
    claim.flow_proofs.clear();
    // Full with no proofs and no uncovered should be empty claim
    assert!(matches!(
        claim.validate(),
        Err(IfcValidationError::EmptyClaim { .. })
    ));
}

// ===========================================================================
// 40. ConfinementClaim serde roundtrip
// ===========================================================================

#[test]
fn confinement_claim_serde_roundtrip() {
    let claim = make_claim(ClaimStrength::Partial);
    let json = serde_json::to_string(&claim).unwrap();
    let back: ConfinementClaim = serde_json::from_str(&json).unwrap();
    assert_eq!(back, claim);
}

// ===========================================================================
// 41. ConfinementClaim content_hash determinism
// ===========================================================================

#[test]
fn confinement_claim_content_hash_deterministic() {
    let c1 = make_claim(ClaimStrength::Full);
    let c2 = make_claim(ClaimStrength::Full);
    assert_eq!(c1.content_hash(), c2.content_hash());
}

// ===========================================================================
// 42. ConfinementClaim sign and verify
// ===========================================================================

#[test]
fn confinement_claim_sign_verify() {
    let key = test_key();
    let mut claim = make_claim(ClaimStrength::Full);
    claim.sign(&key).unwrap();
    let vk = key.verification_key();
    claim.verify(&vk).unwrap();
}

// ===========================================================================
// 43. IfcValidationError display
// ===========================================================================

#[test]
fn ifc_validation_error_display() {
    let e1 = IfcValidationError::FullClaimHasUncoveredFlows {
        claim_id: "c1".into(),
        uncovered_count: 3,
    };
    assert!(e1.to_string().contains("uncovered"));

    let e2 = IfcValidationError::EmptyClaim {
        claim_id: "c2".into(),
    };
    assert!(e2.to_string().contains("empty"));

    let e3 = IfcValidationError::IncompatibleSchema {
        expected: IfcSchemaVersion::CURRENT,
        actual: IfcSchemaVersion::new(2, 0, 0),
    };
    assert!(e3.to_string().contains("incompatible"));

    let e4 = IfcValidationError::FlowProhibited {
        source: Label::Secret,
        sink: Label::Public,
    };
    assert!(e4.to_string().contains("prohibited"));
}

// ===========================================================================
// 44. IfcValidationError serde roundtrip
// ===========================================================================

#[test]
fn ifc_validation_error_serde_roundtrip() {
    let errors = vec![
        IfcValidationError::FullClaimHasUncoveredFlows {
            claim_id: "c1".into(),
            uncovered_count: 2,
        },
        IfcValidationError::EmptyClaim {
            claim_id: "c2".into(),
        },
        IfcValidationError::IncompatibleSchema {
            expected: IfcSchemaVersion::CURRENT,
            actual: IfcSchemaVersion::new(2, 0, 0),
        },
        IfcValidationError::FlowProhibited {
            source: Label::Secret,
            sink: Label::Public,
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: IfcValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *err);
    }
}

// ===========================================================================
// 45. FlowEnvelope is_flow_authorized
// ===========================================================================

#[test]
fn flow_envelope_is_flow_authorized() {
    let envelope = FlowEnvelope {
        envelope_id: "env-1".into(),
        extension_id: "ext-1".into(),
        producible_labels: [Label::Public, Label::Internal].into_iter().collect(),
        accessible_clearances: [ClearanceClass::OpenSink, ClearanceClass::RestrictedSink]
            .into_iter()
            .collect(),
        authorized_declassifications: vec![],
        policy_ref: "pol-1".into(),
        epoch_id: 1,
        schema_version: IfcSchemaVersion::CURRENT,
    };
    // Public -> OpenSink: label in producible, clearance in accessible, can_receive
    assert!(envelope.is_flow_authorized(&Label::Public, &ClearanceClass::OpenSink));
    // Internal -> RestrictedSink: Internal(level=1) <= max_receivable(1), OK
    assert!(envelope.is_flow_authorized(&Label::Internal, &ClearanceClass::RestrictedSink));
    // Secret not in producible_labels
    assert!(!envelope.is_flow_authorized(&Label::Secret, &ClearanceClass::OpenSink));
}

// ===========================================================================
// 46. FlowEnvelope content_hash determinism
// ===========================================================================

#[test]
fn flow_envelope_content_hash_deterministic() {
    let make = || FlowEnvelope {
        envelope_id: "env-1".into(),
        extension_id: "ext-1".into(),
        producible_labels: [Label::Public].into_iter().collect(),
        accessible_clearances: [ClearanceClass::OpenSink].into_iter().collect(),
        authorized_declassifications: vec![],
        policy_ref: "pol-1".into(),
        epoch_id: 1,
        schema_version: IfcSchemaVersion::CURRENT,
    };
    assert_eq!(make().content_hash(), make().content_hash());
}

// ===========================================================================
// 47. FlowEnvelope serde roundtrip
// ===========================================================================

#[test]
fn flow_envelope_serde_roundtrip() {
    let env = FlowEnvelope {
        envelope_id: "env-1".into(),
        extension_id: "ext-1".into(),
        producible_labels: [Label::Public].into_iter().collect(),
        accessible_clearances: [ClearanceClass::OpenSink].into_iter().collect(),
        authorized_declassifications: vec![],
        policy_ref: "pol-1".into(),
        epoch_id: 1,
        schema_version: IfcSchemaVersion::CURRENT,
    };
    let json = serde_json::to_string(&env).unwrap();
    let back: FlowEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(back, env);
}

// ===========================================================================
// 48. FlowCheckResult serde roundtrip
// ===========================================================================

#[test]
fn flow_check_result_serde_roundtrip() {
    let results = vec![
        FlowCheckResult::Allowed,
        FlowCheckResult::LatticeAllowed,
        FlowCheckResult::Prohibited,
        FlowCheckResult::Denied,
        FlowCheckResult::DeclassificationRequired {
            route_id: "r1".into(),
        },
    ];
    for r in &results {
        let json = serde_json::to_string(r).unwrap();
        let back: FlowCheckResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *r);
    }
}

// ===========================================================================
// 49. Custom label ordering
// ===========================================================================

#[test]
fn custom_label_ordering() {
    let custom = Label::Custom {
        name: "mid".into(),
        level: 2,
    };
    assert!(Label::Public < custom);
    assert!(custom < Label::Secret);
    assert_eq!(custom.level(), 2);
}

// ===========================================================================
// 50. Ir2LabelSource computed empty
// ===========================================================================

#[test]
fn ir2_label_source_computed_empty() {
    let src = Ir2LabelSource::Computed {
        input_labels: vec![],
    };
    assert_eq!(src.assign_label(), Label::Public);
}
