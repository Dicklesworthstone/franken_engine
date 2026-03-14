//! Integration tests for the `ifc_artifacts` module.
//!
//! Exercises the public API from outside the crate: Label lattice operations,
//! ClearanceClass semantics, DeclassificationObligation conditions/expiry,
//! Ir2LabelSource label assignment, FlowEnvelope authorization, FlowPolicy
//! flow checks, FlowProof/DeclassificationReceipt/ConfinementClaim signing
//! and verification, IfcValidationError, serde round-trips, Display impls,
//! determinism, and edge-case/security scenarios.

#![forbid(unsafe_code)]
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

use frankenengine_engine::ifc_artifacts::{
    ClaimStrength, ClearanceClass, ConfinementClaim, DeclassificationDecision,
    DeclassificationObligation, DeclassificationReceipt, DeclassificationRoute, FlowCheckResult,
    FlowEnvelope, FlowPolicy, FlowProof, FlowRule, IfcSchemaVersion, IfcValidationError,
    Ir2LabelSource, Label, ProofMethod,
};
use frankenengine_engine::signature_preimage::{SIGNATURE_SENTINEL, Signature, SigningKey};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_key() -> SigningKey {
    SigningKey::from_bytes([42u8; 32])
}

fn sentinel_sig() -> Signature {
    Signature::from_bytes(SIGNATURE_SENTINEL)
}

fn make_flow_policy() -> FlowPolicy {
    FlowPolicy {
        policy_id: "pol-integ-001".to_string(),
        extension_id: "ext-integ-abc".to_string(),
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
            route_id: "declass-integ-1".to_string(),
            source_label: Label::Secret,
            target_clearance: Label::Internal,
            conditions: vec!["audit_approval".to_string()],
        }],
        epoch_id: 1,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: sentinel_sig(),
    }
}

fn make_flow_proof() -> FlowProof {
    FlowProof {
        proof_id: "proof-integ-001".to_string(),
        flow_source_label: Label::Public,
        flow_source_location: "module::read_data".to_string(),
        flow_sink_clearance: Label::Internal,
        flow_sink_location: "module::write_output".to_string(),
        policy_ref: "pol-integ-001".to_string(),
        proof_method: ProofMethod::StaticAnalysis,
        proof_evidence: vec!["ir_node_42".to_string(), "ir_node_43".to_string()],
        timestamp_ms: 1_700_000_000_000,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: sentinel_sig(),
    }
}

fn make_receipt() -> DeclassificationReceipt {
    DeclassificationReceipt {
        receipt_id: "receipt-integ-001".to_string(),
        source_label: Label::Secret,
        sink_clearance: Label::Internal,
        declassification_route_ref: "declass-integ-1".to_string(),
        decision_contract_id: "decision-contract-integ-1".to_string(),
        policy_evaluation_summary: "approved by security team".to_string(),
        loss_assessment_milli: 5000,
        decision: DeclassificationDecision::Allow,
        authorized_by: test_key().verification_key(),
        replay_linkage: "trace-integ-abc".to_string(),
        timestamp_ms: 1_700_000_000_000,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: sentinel_sig(),
    }
}

fn make_claim(strength: ClaimStrength) -> ConfinementClaim {
    ConfinementClaim {
        claim_id: "claim-integ-001".to_string(),
        component_id: "component-integ-abc".to_string(),
        policy_ref: "pol-integ-001".to_string(),
        flow_proofs: vec!["proof-integ-001".to_string(), "proof-integ-002".to_string()],
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

fn make_flow_envelope() -> FlowEnvelope {
    FlowEnvelope {
        envelope_id: "env-integ-001".to_string(),
        extension_id: "ext-integ-abc".to_string(),
        producible_labels: [Label::Public, Label::Internal].into_iter().collect(),
        accessible_clearances: [ClearanceClass::OpenSink, ClearanceClass::RestrictedSink]
            .into_iter()
            .collect(),
        authorized_declassifications: vec!["obl-integ-001".to_string()],
        policy_ref: "pol-integ-001".to_string(),
        epoch_id: 1,
        schema_version: IfcSchemaVersion::CURRENT,
    }
}

fn make_obligation() -> DeclassificationObligation {
    DeclassificationObligation {
        obligation_id: "obl-integ-001".to_string(),
        source_label: Label::TopSecret,
        target_clearance: ClearanceClass::SealedSink,
        required_conditions: vec!["ciso_sign_off".to_string(), "audit_approval".to_string()],
        max_loss_milli: 10_000,
        audit_trail_required: true,
        approval_authority: "security_team".to_string(),
        expiry_epoch: Some(100),
    }
}

// ===========================================================================
// 1. IfcSchemaVersion
// ===========================================================================

#[test]
fn schema_version_current_is_1_0_0() {
    let v = IfcSchemaVersion::CURRENT;
    assert_eq!(v.major, 1);
    assert_eq!(v.minor, 0);
    assert_eq!(v.patch, 0);
}

#[test]
fn schema_version_display() {
    assert_eq!(IfcSchemaVersion::CURRENT.to_string(), "1.0.0");
    assert_eq!(IfcSchemaVersion::new(2, 3, 4).to_string(), "2.3.4");
    assert_eq!(IfcSchemaVersion::new(0, 0, 0).to_string(), "0.0.0");
}

#[test]
fn schema_version_compatibility_same_major_higher_minor() {
    let v1_0 = IfcSchemaVersion::new(1, 0, 0);
    let v1_1 = IfcSchemaVersion::new(1, 1, 0);
    assert!(v1_1.is_compatible_with(&v1_0));
}

#[test]
fn schema_version_compatibility_same_major_lower_minor() {
    let v1_0 = IfcSchemaVersion::new(1, 0, 0);
    let v1_1 = IfcSchemaVersion::new(1, 1, 0);
    assert!(!v1_0.is_compatible_with(&v1_1));
}

#[test]
fn schema_version_compatibility_different_major() {
    let v1_0 = IfcSchemaVersion::new(1, 0, 0);
    let v2_0 = IfcSchemaVersion::new(2, 0, 0);
    assert!(!v2_0.is_compatible_with(&v1_0));
    assert!(!v1_0.is_compatible_with(&v2_0));
}

#[test]
fn schema_version_compatible_with_self() {
    let v = IfcSchemaVersion::new(1, 3, 7);
    assert!(v.is_compatible_with(&v));
}

#[test]
fn schema_version_serde_roundtrip() {
    let v = IfcSchemaVersion::CURRENT;
    let json = serde_json::to_string(&v).unwrap();
    let parsed: IfcSchemaVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, parsed);
}

#[test]
fn schema_version_custom_serde_roundtrip() {
    let v = IfcSchemaVersion::new(99, 88, 77);
    let json = serde_json::to_string(&v).unwrap();
    let parsed: IfcSchemaVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, parsed);
}

// ===========================================================================
// 2. Label — ordering, lattice operations, Display
// ===========================================================================

#[test]
fn label_level_ordering() {
    assert_eq!(Label::Public.level(), 0);
    assert_eq!(Label::Internal.level(), 1);
    assert_eq!(Label::Confidential.level(), 2);
    assert_eq!(Label::Secret.level(), 3);
    assert_eq!(Label::TopSecret.level(), 4);
}

#[test]
fn label_can_flow_to_upward() {
    assert!(Label::Public.can_flow_to(&Label::Internal));
    assert!(Label::Public.can_flow_to(&Label::TopSecret));
    assert!(Label::Internal.can_flow_to(&Label::Confidential));
    assert!(Label::Confidential.can_flow_to(&Label::Secret));
    assert!(Label::Secret.can_flow_to(&Label::TopSecret));
}

#[test]
fn label_can_flow_to_same() {
    for label in Label::all_builtin() {
        assert!(label.can_flow_to(&label), "{label} should flow to itself");
    }
}

#[test]
fn label_cannot_flow_downward() {
    assert!(!Label::Secret.can_flow_to(&Label::Public));
    assert!(!Label::Confidential.can_flow_to(&Label::Internal));
    assert!(!Label::TopSecret.can_flow_to(&Label::Secret));
    assert!(!Label::Internal.can_flow_to(&Label::Public));
}

#[test]
fn label_join_returns_higher() {
    assert_eq!(Label::Public.join(&Label::Secret), Label::Secret);
    assert_eq!(Label::Secret.join(&Label::Public), Label::Secret);
    assert_eq!(Label::Internal.join(&Label::Internal), Label::Internal);
    assert_eq!(Label::Secret.join(&Label::TopSecret), Label::TopSecret);
}

#[test]
fn label_meet_returns_lower() {
    assert_eq!(Label::Public.meet(&Label::Secret), Label::Public);
    assert_eq!(Label::Secret.meet(&Label::Public), Label::Public);
    assert_eq!(Label::Internal.meet(&Label::Internal), Label::Internal);
    assert_eq!(Label::TopSecret.meet(&Label::Secret), Label::Secret);
}

#[test]
fn label_custom_level() {
    let custom = Label::Custom {
        name: "ultra_secret".to_string(),
        level: 10,
    };
    assert_eq!(custom.level(), 10);
    assert!(custom.level() > Label::TopSecret.level());
    assert!(Label::Public.can_flow_to(&custom));
    assert!(!custom.can_flow_to(&Label::TopSecret));
}

#[test]
fn label_display_all_builtins() {
    assert_eq!(Label::Public.to_string(), "public");
    assert_eq!(Label::Internal.to_string(), "internal");
    assert_eq!(Label::Confidential.to_string(), "confidential");
    assert_eq!(Label::Secret.to_string(), "secret");
    assert_eq!(Label::TopSecret.to_string(), "top_secret");
}

#[test]
fn label_display_custom() {
    let custom = Label::Custom {
        name: "ts".to_string(),
        level: 5,
    };
    assert_eq!(custom.to_string(), "custom(ts, level=5)");
}

#[test]
fn label_serde_roundtrip_all_variants() {
    for label in [
        Label::Public,
        Label::Internal,
        Label::Confidential,
        Label::Secret,
        Label::TopSecret,
        Label::Custom {
            name: "test".to_string(),
            level: 7,
        },
    ] {
        let json = serde_json::to_string(&label).unwrap();
        let parsed: Label = serde_json::from_str(&json).unwrap();
        assert_eq!(label, parsed);
    }
}

#[test]
fn label_all_builtin_ascending() {
    let all = Label::all_builtin();
    assert_eq!(all.len(), 5);
    assert_eq!(all[0], Label::Public);
    assert_eq!(all[4], Label::TopSecret);
    for i in 0..all.len() - 1 {
        assert!(all[i].level() < all[i + 1].level());
    }
}

// -- Lattice algebraic properties --

#[test]
fn lattice_join_commutativity() {
    let labels = Label::all_builtin();
    for a in &labels {
        for b in &labels {
            assert_eq!(a.join(b), b.join(a));
        }
    }
}

#[test]
fn lattice_meet_commutativity() {
    let labels = Label::all_builtin();
    for a in &labels {
        for b in &labels {
            assert_eq!(a.meet(b), b.meet(a));
        }
    }
}

#[test]
fn lattice_join_associativity() {
    let labels = Label::all_builtin();
    for a in &labels {
        for b in &labels {
            for c in &labels {
                assert_eq!(a.join(b).join(c), a.join(&b.join(c)));
            }
        }
    }
}

#[test]
fn lattice_meet_associativity() {
    let labels = Label::all_builtin();
    for a in &labels {
        for b in &labels {
            for c in &labels {
                assert_eq!(a.meet(b).meet(c), a.meet(&b.meet(c)));
            }
        }
    }
}

#[test]
fn lattice_join_idempotency() {
    for a in Label::all_builtin() {
        assert_eq!(a.join(&a), a);
    }
}

#[test]
fn lattice_meet_idempotency() {
    for a in Label::all_builtin() {
        assert_eq!(a.meet(&a), a);
    }
}

#[test]
fn lattice_absorption() {
    let labels = Label::all_builtin();
    for a in &labels {
        for b in &labels {
            assert_eq!(a.join(&a.meet(b)), *a);
            assert_eq!(a.meet(&a.join(b)), *a);
        }
    }
}

#[test]
fn lattice_join_all_empty() {
    assert_eq!(Label::join_all(std::iter::empty()), None);
}

#[test]
fn lattice_join_all_single() {
    assert_eq!(Label::join_all([Label::Internal]), Some(Label::Internal));
}

#[test]
fn lattice_join_all_multiple() {
    assert_eq!(
        Label::join_all([Label::Public, Label::Secret, Label::Internal]),
        Some(Label::Secret)
    );
    assert_eq!(
        Label::join_all([Label::Confidential, Label::TopSecret, Label::Public]),
        Some(Label::TopSecret)
    );
}

#[test]
fn lattice_meet_all_empty() {
    assert_eq!(Label::meet_all(std::iter::empty()), None);
}

#[test]
fn lattice_meet_all_single() {
    assert_eq!(Label::meet_all([Label::Secret]), Some(Label::Secret));
}

#[test]
fn lattice_meet_all_multiple() {
    assert_eq!(
        Label::meet_all([Label::Secret, Label::Internal, Label::TopSecret]),
        Some(Label::Internal)
    );
    assert_eq!(
        Label::meet_all([Label::TopSecret, Label::Confidential, Label::Public]),
        Some(Label::Public)
    );
}

// ===========================================================================
// 3. ClearanceClass
// ===========================================================================

#[test]
fn clearance_class_level_ordering() {
    assert!(ClearanceClass::OpenSink.level() < ClearanceClass::RestrictedSink.level());
    assert!(ClearanceClass::RestrictedSink.level() < ClearanceClass::AuditedSink.level());
    assert!(ClearanceClass::AuditedSink.level() < ClearanceClass::SealedSink.level());
    assert!(ClearanceClass::SealedSink.level() < ClearanceClass::NeverSink.level());
}

#[test]
fn clearance_class_can_receive_open_sink() {
    assert!(ClearanceClass::OpenSink.can_receive(&Label::Public));
    assert!(ClearanceClass::OpenSink.can_receive(&Label::TopSecret));
}

#[test]
fn clearance_class_can_receive_restricted_sink() {
    assert!(ClearanceClass::RestrictedSink.can_receive(&Label::Public));
    assert!(ClearanceClass::RestrictedSink.can_receive(&Label::Internal));
    assert!(!ClearanceClass::RestrictedSink.can_receive(&Label::Confidential));
    assert!(!ClearanceClass::RestrictedSink.can_receive(&Label::Secret));
}

#[test]
fn clearance_class_can_receive_audited_sink() {
    assert!(ClearanceClass::AuditedSink.can_receive(&Label::Confidential));
    assert!(!ClearanceClass::AuditedSink.can_receive(&Label::Secret));
}

#[test]
fn clearance_class_can_receive_sealed_sink() {
    assert!(ClearanceClass::SealedSink.can_receive(&Label::Secret));
    assert!(!ClearanceClass::SealedSink.can_receive(&Label::TopSecret));
}

#[test]
fn clearance_class_can_receive_never_sink() {
    assert!(ClearanceClass::NeverSink.can_receive(&Label::Public));
    assert!(!ClearanceClass::NeverSink.can_receive(&Label::TopSecret));
}

#[test]
fn clearance_class_max_receivable_label_level() {
    assert_eq!(
        ClearanceClass::OpenSink.max_receivable_label_level(),
        Some(4)
    );
    assert_eq!(
        ClearanceClass::RestrictedSink.max_receivable_label_level(),
        Some(1)
    );
    assert_eq!(
        ClearanceClass::AuditedSink.max_receivable_label_level(),
        Some(2)
    );
    assert_eq!(
        ClearanceClass::SealedSink.max_receivable_label_level(),
        Some(3)
    );
    assert_eq!(
        ClearanceClass::NeverSink.max_receivable_label_level(),
        Some(0)
    );
}

#[test]
fn clearance_class_display() {
    assert_eq!(ClearanceClass::OpenSink.to_string(), "open_sink");
    assert_eq!(
        ClearanceClass::RestrictedSink.to_string(),
        "restricted_sink"
    );
    assert_eq!(ClearanceClass::AuditedSink.to_string(), "audited_sink");
    assert_eq!(ClearanceClass::SealedSink.to_string(), "sealed_sink");
    assert_eq!(ClearanceClass::NeverSink.to_string(), "never_sink");
}

#[test]
fn clearance_class_as_str() {
    assert_eq!(ClearanceClass::OpenSink.as_str(), "open_sink");
    assert_eq!(ClearanceClass::RestrictedSink.as_str(), "restricted_sink");
    assert_eq!(ClearanceClass::AuditedSink.as_str(), "audited_sink");
    assert_eq!(ClearanceClass::SealedSink.as_str(), "sealed_sink");
    assert_eq!(ClearanceClass::NeverSink.as_str(), "never_sink");
}

#[test]
fn clearance_class_serde_roundtrip_all() {
    for cc in ClearanceClass::all() {
        let json = serde_json::to_string(&cc).unwrap();
        let parsed: ClearanceClass = serde_json::from_str(&json).unwrap();
        assert_eq!(cc, parsed);
    }
}

#[test]
fn clearance_class_all_ascending() {
    let all = ClearanceClass::all();
    assert_eq!(all.len(), 5);
    for i in 0..all.len() - 1 {
        assert!(all[i].level() < all[i + 1].level());
    }
}

// ===========================================================================
// 4. DeclassificationObligation
// ===========================================================================

#[test]
fn obligation_serde_roundtrip() {
    let obl = make_obligation();
    let json = serde_json::to_string(&obl).unwrap();
    let parsed: DeclassificationObligation = serde_json::from_str(&json).unwrap();
    assert_eq!(obl, parsed);
}

#[test]
fn obligation_conditions_none_satisfied() {
    let obl = make_obligation();
    assert!(!obl.conditions_satisfied(&BTreeSet::new()));
}

#[test]
fn obligation_conditions_partial_satisfied() {
    let obl = make_obligation();
    let mut satisfied = BTreeSet::new();
    satisfied.insert("ciso_sign_off".to_string());
    assert!(!obl.conditions_satisfied(&satisfied));
}

#[test]
fn obligation_conditions_all_satisfied() {
    let obl = make_obligation();
    let mut satisfied = BTreeSet::new();
    satisfied.insert("ciso_sign_off".to_string());
    satisfied.insert("audit_approval".to_string());
    assert!(obl.conditions_satisfied(&satisfied));
}

#[test]
fn obligation_conditions_superset_satisfied() {
    let obl = make_obligation();
    let mut satisfied = BTreeSet::new();
    satisfied.insert("ciso_sign_off".to_string());
    satisfied.insert("audit_approval".to_string());
    satisfied.insert("extra_condition".to_string());
    assert!(obl.conditions_satisfied(&satisfied));
}

#[test]
fn obligation_conditions_empty_requirement() {
    let obl = DeclassificationObligation {
        obligation_id: "obl-empty".to_string(),
        source_label: Label::Internal,
        target_clearance: ClearanceClass::OpenSink,
        required_conditions: vec![],
        max_loss_milli: 0,
        audit_trail_required: false,
        approval_authority: "auto".to_string(),
        expiry_epoch: None,
    };
    assert!(obl.conditions_satisfied(&BTreeSet::new()));
}

#[test]
fn obligation_not_expired_before_epoch() {
    let obl = make_obligation();
    assert!(!obl.is_expired(50));
}

#[test]
fn obligation_not_expired_at_epoch() {
    let obl = make_obligation();
    assert!(!obl.is_expired(100));
}

#[test]
fn obligation_expired_after_epoch() {
    let obl = make_obligation();
    assert!(obl.is_expired(101));
}

#[test]
fn obligation_no_expiry_never_expires() {
    let obl = DeclassificationObligation {
        expiry_epoch: None,
        ..make_obligation()
    };
    assert!(!obl.is_expired(u64::MAX));
}

// ===========================================================================
// 5. Ir2LabelSource — label assignment
// ===========================================================================

#[test]
fn ir2_label_literal_is_public() {
    assert_eq!(Ir2LabelSource::Literal.assign_label(), Label::Public);
}

#[test]
fn ir2_label_env_var_is_secret() {
    assert_eq!(
        Ir2LabelSource::EnvironmentVariable.assign_label(),
        Label::Secret
    );
}

#[test]
fn ir2_label_credential_path_not_key_material_is_secret() {
    assert_eq!(
        Ir2LabelSource::CredentialPath {
            is_key_material: false
        }
        .assign_label(),
        Label::Secret
    );
}

#[test]
fn ir2_label_credential_path_key_material_is_top_secret() {
    assert_eq!(
        Ir2LabelSource::CredentialPath {
            is_key_material: true
        }
        .assign_label(),
        Label::TopSecret
    );
}

#[test]
fn ir2_label_hostcall_return_propagates_clearance() {
    assert_eq!(
        Ir2LabelSource::HostcallReturn {
            clearance_label: Label::Confidential
        }
        .assign_label(),
        Label::Confidential
    );
    assert_eq!(
        Ir2LabelSource::HostcallReturn {
            clearance_label: Label::TopSecret
        }
        .assign_label(),
        Label::TopSecret
    );
}

#[test]
fn ir2_label_computed_taint_propagation_join() {
    assert_eq!(
        Ir2LabelSource::Computed {
            input_labels: vec![Label::Public, Label::Secret]
        }
        .assign_label(),
        Label::Secret
    );
    assert_eq!(
        Ir2LabelSource::Computed {
            input_labels: vec![Label::Confidential, Label::TopSecret]
        }
        .assign_label(),
        Label::TopSecret
    );
}

#[test]
fn ir2_label_computed_empty_inputs_is_public() {
    assert_eq!(
        Ir2LabelSource::Computed {
            input_labels: vec![]
        }
        .assign_label(),
        Label::Public
    );
}

#[test]
fn ir2_label_computed_single_input() {
    assert_eq!(
        Ir2LabelSource::Computed {
            input_labels: vec![Label::Internal]
        }
        .assign_label(),
        Label::Internal
    );
}

#[test]
fn ir2_label_declassified_returns_effective() {
    assert_eq!(
        Ir2LabelSource::Declassified {
            receipt_ref: "receipt-001".to_string(),
            effective_label: Label::Internal
        }
        .assign_label(),
        Label::Internal
    );
}

#[test]
fn ir2_label_source_serde_roundtrip_all_variants() {
    let sources = vec![
        Ir2LabelSource::Literal,
        Ir2LabelSource::EnvironmentVariable,
        Ir2LabelSource::CredentialPath {
            is_key_material: true,
        },
        Ir2LabelSource::CredentialPath {
            is_key_material: false,
        },
        Ir2LabelSource::HostcallReturn {
            clearance_label: Label::Secret,
        },
        Ir2LabelSource::Computed {
            input_labels: vec![Label::Public, Label::Internal],
        },
        Ir2LabelSource::Declassified {
            receipt_ref: "r1".to_string(),
            effective_label: Label::Public,
        },
    ];
    for source in sources {
        let json = serde_json::to_string(&source).unwrap();
        let parsed: Ir2LabelSource = serde_json::from_str(&json).unwrap();
        assert_eq!(source, parsed);
    }
}

// ===========================================================================
// 6. FlowEnvelope (ifc_artifacts)
// ===========================================================================

#[test]
fn flow_envelope_serde_roundtrip() {
    let env = make_flow_envelope();
    let json = serde_json::to_string(&env).unwrap();
    let parsed: FlowEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(env, parsed);
}

#[test]
fn flow_envelope_content_hash_deterministic() {
    let e1 = make_flow_envelope();
    let e2 = make_flow_envelope();
    assert_eq!(e1.content_hash(), e2.content_hash());
}

#[test]
fn flow_envelope_content_hash_changes_on_mutation() {
    let e1 = make_flow_envelope();
    let mut e2 = make_flow_envelope();
    e2.epoch_id = 999;
    assert_ne!(e1.content_hash(), e2.content_hash());
}

#[test]
fn flow_envelope_authorized_flow_public_to_open_sink() {
    let env = make_flow_envelope();
    assert!(env.is_flow_authorized(&Label::Public, &ClearanceClass::OpenSink));
}

#[test]
fn flow_envelope_authorized_flow_internal_to_restricted_sink() {
    let env = make_flow_envelope();
    assert!(env.is_flow_authorized(&Label::Internal, &ClearanceClass::RestrictedSink));
}

#[test]
fn flow_envelope_unauthorized_label_not_in_producible() {
    let env = make_flow_envelope();
    assert!(!env.is_flow_authorized(&Label::Secret, &ClearanceClass::OpenSink));
}

#[test]
fn flow_envelope_unauthorized_clearance_not_in_accessible() {
    let env = make_flow_envelope();
    assert!(!env.is_flow_authorized(&Label::Public, &ClearanceClass::AuditedSink));
}

#[test]
fn flow_envelope_clearance_rejects_too_sensitive() {
    let env = FlowEnvelope {
        envelope_id: "env-integ-002".to_string(),
        extension_id: "ext-integ-xyz".to_string(),
        producible_labels: [Label::Secret].into_iter().collect(),
        accessible_clearances: [ClearanceClass::RestrictedSink].into_iter().collect(),
        authorized_declassifications: vec![],
        policy_ref: "pol-integ-002".to_string(),
        epoch_id: 1,
        schema_version: IfcSchemaVersion::CURRENT,
    };
    // Secret (level=3) > RestrictedSink max (level=1)
    assert!(!env.is_flow_authorized(&Label::Secret, &ClearanceClass::RestrictedSink));
}

// ===========================================================================
// 7. FlowRule and DeclassificationRoute
// ===========================================================================

#[test]
fn flow_rule_serde_roundtrip() {
    let rule = FlowRule {
        source_label: Label::Internal,
        sink_clearance: Label::Confidential,
    };
    let json = serde_json::to_string(&rule).unwrap();
    let parsed: FlowRule = serde_json::from_str(&json).unwrap();
    assert_eq!(rule, parsed);
}

#[test]
fn declassification_route_serde_roundtrip() {
    let route = DeclassificationRoute {
        route_id: "route-integ-1".to_string(),
        source_label: Label::Secret,
        target_clearance: Label::Internal,
        conditions: vec!["audit_approval".to_string(), "ciso_sign_off".to_string()],
    };
    let json = serde_json::to_string(&route).unwrap();
    let parsed: DeclassificationRoute = serde_json::from_str(&json).unwrap();
    assert_eq!(route, parsed);
}

// ===========================================================================
// 8. FlowPolicy — flow checks, signing
// ===========================================================================

#[test]
fn flow_policy_serde_roundtrip() {
    let policy = make_flow_policy();
    let json = serde_json::to_string(&policy).unwrap();
    let parsed: FlowPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, parsed);
}

#[test]
fn flow_policy_content_hash_deterministic() {
    let p1 = make_flow_policy();
    let p2 = make_flow_policy();
    assert_eq!(p1.content_hash(), p2.content_hash());
}

#[test]
fn flow_policy_content_hash_changes_on_mutation() {
    let p1 = make_flow_policy();
    let mut p2 = make_flow_policy();
    p2.epoch_id = 999;
    assert_ne!(p1.content_hash(), p2.content_hash());
}

#[test]
fn flow_policy_sign_and_verify() {
    let key = test_key();
    let mut policy = make_flow_policy();
    policy.sign(&key).unwrap();
    assert!(!policy.signature.is_sentinel());
    policy.verify(&key.verification_key()).unwrap();
}

#[test]
fn flow_policy_verify_fails_wrong_key() {
    let key = test_key();
    let wrong_key = SigningKey::from_bytes([99u8; 32]);
    let mut policy = make_flow_policy();
    policy.sign(&key).unwrap();
    assert!(policy.verify(&wrong_key.verification_key()).is_err());
}

#[test]
fn flow_check_explicitly_allowed() {
    let policy = make_flow_policy();
    assert_eq!(
        policy.is_flow_allowed(&Label::Internal, &Label::Confidential),
        FlowCheckResult::Allowed
    );
}

#[test]
fn flow_check_lattice_allowed() {
    let policy = make_flow_policy();
    assert_eq!(
        policy.is_flow_allowed(&Label::Public, &Label::Internal),
        FlowCheckResult::LatticeAllowed
    );
}

#[test]
fn flow_check_prohibited() {
    let policy = make_flow_policy();
    assert_eq!(
        policy.is_flow_allowed(&Label::Confidential, &Label::Public),
        FlowCheckResult::Prohibited
    );
}

#[test]
fn flow_check_declassification_required() {
    let policy = make_flow_policy();
    assert_eq!(
        policy.is_flow_allowed(&Label::Secret, &Label::Internal),
        FlowCheckResult::DeclassificationRequired {
            route_id: "declass-integ-1".to_string()
        }
    );
}

#[test]
fn flow_check_denied_no_rule_no_lattice_no_route() {
    let policy = make_flow_policy();
    assert_eq!(
        policy.is_flow_allowed(&Label::Secret, &Label::Public),
        FlowCheckResult::Denied
    );
}

#[test]
fn flow_check_prohibited_takes_precedence_over_lattice() {
    // Confidential -> Public is prohibited even though Public <= Confidential doesn't apply here
    // But let's test a case where both apply: if we add a prohibition for a lattice-legal flow
    let mut policy = make_flow_policy();
    policy.prohibited_flows.push(FlowRule {
        source_label: Label::Public,
        sink_clearance: Label::Internal,
    });
    // Public -> Internal is lattice-legal, but prohibition takes precedence
    assert_eq!(
        policy.is_flow_allowed(&Label::Public, &Label::Internal),
        FlowCheckResult::Prohibited
    );
}

#[test]
fn flow_check_result_serde_roundtrip_all_variants() {
    let results = vec![
        FlowCheckResult::Allowed,
        FlowCheckResult::LatticeAllowed,
        FlowCheckResult::DeclassificationRequired {
            route_id: "r1".to_string(),
        },
        FlowCheckResult::Prohibited,
        FlowCheckResult::Denied,
    ];
    for r in results {
        let json = serde_json::to_string(&r).unwrap();
        let parsed: FlowCheckResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, parsed);
    }
}

// ===========================================================================
// 9. ProofMethod
// ===========================================================================

#[test]
fn proof_method_display() {
    assert_eq!(ProofMethod::StaticAnalysis.to_string(), "static_analysis");
    assert_eq!(ProofMethod::RuntimeCheck.to_string(), "runtime_check");
    assert_eq!(
        ProofMethod::Declassification.to_string(),
        "declassification"
    );
}

#[test]
fn proof_method_serde_roundtrip_all() {
    for method in [
        ProofMethod::StaticAnalysis,
        ProofMethod::RuntimeCheck,
        ProofMethod::Declassification,
    ] {
        let json = serde_json::to_string(&method).unwrap();
        let parsed: ProofMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(method, parsed);
    }
}

// ===========================================================================
// 10. FlowProof
// ===========================================================================

#[test]
fn flow_proof_serde_roundtrip() {
    let proof = make_flow_proof();
    let json = serde_json::to_string(&proof).unwrap();
    let parsed: FlowProof = serde_json::from_str(&json).unwrap();
    assert_eq!(proof, parsed);
}

#[test]
fn flow_proof_content_hash_deterministic() {
    let p1 = make_flow_proof();
    let p2 = make_flow_proof();
    assert_eq!(p1.content_hash(), p2.content_hash());
}

#[test]
fn flow_proof_content_hash_changes_on_mutation() {
    let p1 = make_flow_proof();
    let mut p2 = make_flow_proof();
    p2.proof_id = "proof-integ-different".to_string();
    assert_ne!(p1.content_hash(), p2.content_hash());
}

#[test]
fn flow_proof_sign_and_verify() {
    let key = test_key();
    let mut proof = make_flow_proof();
    proof.sign(&key).unwrap();
    assert!(!proof.signature.is_sentinel());
    proof.verify(&key.verification_key()).unwrap();
}

#[test]
fn flow_proof_verify_fails_wrong_key() {
    let key = test_key();
    let wrong = SigningKey::from_bytes([77u8; 32]);
    let mut proof = make_flow_proof();
    proof.sign(&key).unwrap();
    assert!(proof.verify(&wrong.verification_key()).is_err());
}

// ===========================================================================
// 11. DeclassificationDecision
// ===========================================================================

#[test]
fn declassification_decision_display() {
    assert_eq!(DeclassificationDecision::Allow.to_string(), "allow");
    assert_eq!(DeclassificationDecision::Deny.to_string(), "deny");
}

#[test]
fn declassification_decision_serde_roundtrip() {
    for d in [
        DeclassificationDecision::Allow,
        DeclassificationDecision::Deny,
    ] {
        let json = serde_json::to_string(&d).unwrap();
        let parsed: DeclassificationDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, parsed);
    }
}

// ===========================================================================
// 12. DeclassificationReceipt
// ===========================================================================

#[test]
fn receipt_serde_roundtrip() {
    let receipt = make_receipt();
    let json = serde_json::to_string(&receipt).unwrap();
    let parsed: DeclassificationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, parsed);
}

#[test]
fn receipt_content_hash_deterministic() {
    let r1 = make_receipt();
    let r2 = make_receipt();
    assert_eq!(r1.content_hash(), r2.content_hash());
}

#[test]
fn receipt_content_hash_changes_on_mutation() {
    let r1 = make_receipt();
    let mut r2 = make_receipt();
    r2.receipt_id = "receipt-integ-different".to_string();
    assert_ne!(r1.content_hash(), r2.content_hash());
}

#[test]
fn receipt_sign_and_verify() {
    let key = test_key();
    let mut receipt = make_receipt();
    receipt.sign(&key).unwrap();
    assert!(!receipt.signature.is_sentinel());
    receipt.verify(&key.verification_key()).unwrap();
}

#[test]
fn receipt_verify_fails_wrong_key() {
    let key = test_key();
    let wrong = SigningKey::from_bytes([88u8; 32]);
    let mut receipt = make_receipt();
    receipt.sign(&key).unwrap();
    assert!(receipt.verify(&wrong.verification_key()).is_err());
}

// ===========================================================================
// 13. ClaimStrength
// ===========================================================================

#[test]
fn claim_strength_display() {
    assert_eq!(ClaimStrength::Full.to_string(), "full");
    assert_eq!(ClaimStrength::Partial.to_string(), "partial");
}

#[test]
fn claim_strength_serde_roundtrip() {
    for s in [ClaimStrength::Full, ClaimStrength::Partial] {
        let json = serde_json::to_string(&s).unwrap();
        let parsed: ClaimStrength = serde_json::from_str(&json).unwrap();
        assert_eq!(s, parsed);
    }
}

// ===========================================================================
// 14. ConfinementClaim
// ===========================================================================

#[test]
fn claim_full_validates() {
    let claim = make_claim(ClaimStrength::Full);
    assert!(claim.validate().is_ok());
    assert!(claim.is_full());
}

#[test]
fn claim_partial_validates() {
    let claim = make_claim(ClaimStrength::Partial);
    assert!(claim.validate().is_ok());
    assert!(!claim.is_full());
}

#[test]
fn claim_full_with_uncovered_fails_validation() {
    let mut claim = make_claim(ClaimStrength::Full);
    claim.uncovered_flows.push(FlowRule {
        source_label: Label::Secret,
        sink_clearance: Label::Public,
    });
    let err = claim.validate().unwrap_err();
    assert!(matches!(
        err,
        IfcValidationError::FullClaimHasUncoveredFlows { .. }
    ));
}

#[test]
fn claim_empty_fails_validation() {
    let claim = ConfinementClaim {
        claim_id: "claim-integ-empty".to_string(),
        component_id: "comp".to_string(),
        policy_ref: "pol".to_string(),
        flow_proofs: vec![],
        uncovered_flows: vec![],
        claim_strength: ClaimStrength::Full,
        timestamp_ms: 0,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: sentinel_sig(),
    };
    let err = claim.validate().unwrap_err();
    assert!(matches!(err, IfcValidationError::EmptyClaim { .. }));
}

#[test]
fn claim_partial_with_only_uncovered_validates() {
    let claim = ConfinementClaim {
        claim_id: "claim-integ-only-uncovered".to_string(),
        component_id: "comp".to_string(),
        policy_ref: "pol".to_string(),
        flow_proofs: vec![],
        uncovered_flows: vec![FlowRule {
            source_label: Label::Secret,
            sink_clearance: Label::Public,
        }],
        claim_strength: ClaimStrength::Partial,
        timestamp_ms: 0,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: sentinel_sig(),
    };
    assert!(claim.validate().is_ok());
    assert!(!claim.is_full());
}

#[test]
fn claim_serde_roundtrip_both_strengths() {
    for strength in [ClaimStrength::Full, ClaimStrength::Partial] {
        let claim = make_claim(strength);
        let json = serde_json::to_string(&claim).unwrap();
        let parsed: ConfinementClaim = serde_json::from_str(&json).unwrap();
        assert_eq!(claim, parsed);
    }
}

#[test]
fn claim_content_hash_deterministic() {
    let c1 = make_claim(ClaimStrength::Full);
    let c2 = make_claim(ClaimStrength::Full);
    assert_eq!(c1.content_hash(), c2.content_hash());
}

#[test]
fn claim_content_hash_changes_on_mutation() {
    let c1 = make_claim(ClaimStrength::Full);
    let mut c2 = make_claim(ClaimStrength::Full);
    c2.claim_id = "different".to_string();
    assert_ne!(c1.content_hash(), c2.content_hash());
}

#[test]
fn claim_sign_and_verify() {
    let key = test_key();
    let mut claim = make_claim(ClaimStrength::Full);
    claim.sign(&key).unwrap();
    assert!(!claim.signature.is_sentinel());
    claim.verify(&key.verification_key()).unwrap();
}

#[test]
fn claim_verify_fails_wrong_key() {
    let key = test_key();
    let wrong = SigningKey::from_bytes([66u8; 32]);
    let mut claim = make_claim(ClaimStrength::Full);
    claim.sign(&key).unwrap();
    assert!(claim.verify(&wrong.verification_key()).is_err());
}

// ===========================================================================
// 15. IfcValidationError
// ===========================================================================

#[test]
fn validation_error_full_claim_has_uncovered_display() {
    let err = IfcValidationError::FullClaimHasUncoveredFlows {
        claim_id: "c1".to_string(),
        uncovered_count: 3,
    };
    let msg = err.to_string();
    assert!(msg.contains("3 uncovered flows"));
    assert!(msg.contains("c1"));
}

#[test]
fn validation_error_empty_claim_display() {
    let err = IfcValidationError::EmptyClaim {
        claim_id: "c1".to_string(),
    };
    assert!(err.to_string().contains("empty"));
}

#[test]
fn validation_error_incompatible_schema_display() {
    let err = IfcValidationError::IncompatibleSchema {
        expected: IfcSchemaVersion::CURRENT,
        actual: IfcSchemaVersion::new(2, 0, 0),
    };
    let msg = err.to_string();
    assert!(msg.contains("incompatible"));
    assert!(msg.contains("2.0.0"));
}

#[test]
fn validation_error_flow_prohibited_display() {
    let err = IfcValidationError::FlowProhibited {
        source: Label::Secret,
        sink: Label::Public,
    };
    assert!(err.to_string().contains("prohibited"));
}

#[test]
fn validation_error_is_std_error() {
    let err = IfcValidationError::EmptyClaim {
        claim_id: "x".to_string(),
    };
    let _as_std: &dyn std::error::Error = &err;
}

#[test]
fn validation_error_serde_roundtrip_all_variants() {
    let errors = vec![
        IfcValidationError::FullClaimHasUncoveredFlows {
            claim_id: "c1".to_string(),
            uncovered_count: 2,
        },
        IfcValidationError::EmptyClaim {
            claim_id: "c2".to_string(),
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
    for err in errors {
        let json = serde_json::to_string(&err).unwrap();
        let parsed: IfcValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, parsed);
    }
}

// ===========================================================================
// 16. Full lifecycle test
// ===========================================================================

#[test]
fn full_ifc_lifecycle() {
    let key = test_key();

    // 1. Define and sign policy
    let mut policy = make_flow_policy();
    policy.sign(&key).unwrap();
    policy.verify(&key.verification_key()).unwrap();

    // 2. Prove a flow
    let mut proof = make_flow_proof();
    proof.policy_ref = policy.policy_id.clone();
    proof.sign(&key).unwrap();
    proof.verify(&key.verification_key()).unwrap();

    // 3. Issue declassification receipt
    let mut receipt = make_receipt();
    receipt.sign(&key).unwrap();
    receipt.verify(&key.verification_key()).unwrap();

    // 4. Make confinement claim
    let mut claim = ConfinementClaim {
        claim_id: "lifecycle-integ-claim".to_string(),
        component_id: "comp-integ-lifecycle".to_string(),
        policy_ref: policy.policy_id.clone(),
        flow_proofs: vec![proof.proof_id.clone()],
        uncovered_flows: vec![],
        claim_strength: ClaimStrength::Full,
        timestamp_ms: 1_700_000_001_000,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: sentinel_sig(),
    };
    claim.validate().unwrap();
    claim.sign(&key).unwrap();
    claim.verify(&key.verification_key()).unwrap();
    assert!(claim.is_full());
}

// ===========================================================================
// 17. Deterministic replay
// ===========================================================================

#[test]
fn all_artifact_hashes_are_deterministic_100_times() {
    for _ in 0..100 {
        let p1 = make_flow_policy();
        let p2 = make_flow_policy();
        assert_eq!(p1.content_hash(), p2.content_hash());

        let fp1 = make_flow_proof();
        let fp2 = make_flow_proof();
        assert_eq!(fp1.content_hash(), fp2.content_hash());

        let r1 = make_receipt();
        let r2 = make_receipt();
        assert_eq!(r1.content_hash(), r2.content_hash());

        let c1 = make_claim(ClaimStrength::Full);
        let c2 = make_claim(ClaimStrength::Full);
        assert_eq!(c1.content_hash(), c2.content_hash());
    }
}

// ===========================================================================
// 18. Exfiltration scenarios
// ===========================================================================

#[test]
fn exfiltration_scenario_blocked() {
    let api_key_label = Ir2LabelSource::EnvironmentVariable.assign_label();
    let prefix_label = Ir2LabelSource::Literal.assign_label();
    let header_label = Ir2LabelSource::Computed {
        input_labels: vec![prefix_label, api_key_label],
    }
    .assign_label();

    assert_eq!(header_label, Label::Secret);
    assert!(!ClearanceClass::NeverSink.can_receive(&header_label));
    assert!(ClearanceClass::SealedSink.can_receive(&header_label));
}

#[test]
fn exfiltration_scenario_with_declassification() {
    let key_label = Ir2LabelSource::CredentialPath {
        is_key_material: true,
    }
    .assign_label();
    assert_eq!(key_label, Label::TopSecret);

    assert!(!ClearanceClass::SealedSink.can_receive(&key_label));
    assert!(ClearanceClass::OpenSink.can_receive(&key_label));

    let obl = DeclassificationObligation {
        obligation_id: "obl-key-export-integ".to_string(),
        source_label: Label::TopSecret,
        target_clearance: ClearanceClass::SealedSink,
        required_conditions: vec!["key_export_audit".to_string()],
        max_loss_milli: 100_000,
        audit_trail_required: true,
        approval_authority: "key_management_authority".to_string(),
        expiry_epoch: Some(50),
    };

    let mut satisfied = BTreeSet::new();
    satisfied.insert("key_export_audit".to_string());
    assert!(obl.conditions_satisfied(&satisfied));
    assert!(!obl.is_expired(50));
}

// ===========================================================================
// 19. FlowPolicy with TopSecret labels
// ===========================================================================

#[test]
fn flow_policy_top_secret_lattice_legal() {
    let mut policy = make_flow_policy();
    policy.label_classes.insert(Label::TopSecret);
    policy.clearance_classes.insert(Label::TopSecret);

    assert_eq!(
        policy.is_flow_allowed(&Label::TopSecret, &Label::TopSecret),
        FlowCheckResult::LatticeAllowed
    );
}

#[test]
fn flow_policy_top_secret_downward_denied() {
    let mut policy = make_flow_policy();
    policy.label_classes.insert(Label::TopSecret);
    policy.clearance_classes.insert(Label::TopSecret);

    assert_eq!(
        policy.is_flow_allowed(&Label::TopSecret, &Label::Public),
        FlowCheckResult::Denied
    );
}

// ===========================================================================
// 20. Custom label with FlowPolicy
// ===========================================================================

#[test]
fn flow_policy_custom_label_flow_check() {
    let custom_high = Label::Custom {
        name: "ultra".to_string(),
        level: 10,
    };
    let mut policy = make_flow_policy();
    policy.label_classes.insert(custom_high.clone());
    policy.clearance_classes.insert(custom_high.clone());

    // Custom(level=10) -> Custom(level=10) is lattice-legal
    assert_eq!(
        policy.is_flow_allowed(&custom_high, &custom_high),
        FlowCheckResult::LatticeAllowed
    );

    // Custom(level=10) -> Public is denied (no route)
    assert_eq!(
        policy.is_flow_allowed(&custom_high, &Label::Public),
        FlowCheckResult::Denied
    );
}

// ===========================================================================
// 21. Edge case: multiple declassification routes
// ===========================================================================

#[test]
fn flow_policy_first_matching_route_returned() {
    let mut policy = make_flow_policy();
    policy.declassification_routes.push(DeclassificationRoute {
        route_id: "declass-integ-2".to_string(),
        source_label: Label::Secret,
        target_clearance: Label::Internal,
        conditions: vec!["different_condition".to_string()],
    });

    // First matching route should be returned
    let result = policy.is_flow_allowed(&Label::Secret, &Label::Internal);
    match result {
        FlowCheckResult::DeclassificationRequired { route_id } => {
            assert_eq!(route_id, "declass-integ-1");
        }
        _ => panic!("expected DeclassificationRequired"),
    }
}

// ===========================================================================
// 22. FlowEnvelope with all clearance classes
// ===========================================================================

#[test]
fn flow_envelope_all_clearance_classes() {
    let env = FlowEnvelope {
        envelope_id: "env-integ-all-cc".to_string(),
        extension_id: "ext-integ-all".to_string(),
        producible_labels: Label::all_builtin().into_iter().collect(),
        accessible_clearances: ClearanceClass::all().into_iter().collect(),
        authorized_declassifications: vec![],
        policy_ref: "pol-integ-all".to_string(),
        epoch_id: 1,
        schema_version: IfcSchemaVersion::CURRENT,
    };

    // Public -> OpenSink should be authorized
    assert!(env.is_flow_authorized(&Label::Public, &ClearanceClass::OpenSink));
    // Secret -> SealedSink: Secret(3) <= SealedSink max(3), authorized
    assert!(env.is_flow_authorized(&Label::Secret, &ClearanceClass::SealedSink));
    // Public -> NeverSink: NeverSink accepts only Public
    assert!(env.is_flow_authorized(&Label::Public, &ClearanceClass::NeverSink));
    // TopSecret -> NeverSink: NeverSink rejects anything above Public
    assert!(!env.is_flow_authorized(&Label::TopSecret, &ClearanceClass::NeverSink));
    // TopSecret -> SealedSink: TopSecret(4) > SealedSink max(3)
    assert!(!env.is_flow_authorized(&Label::TopSecret, &ClearanceClass::SealedSink));
}

// ===========================================================================
// 23. ConfinementClaim: partial with proofs and uncovered flows
// ===========================================================================

#[test]
fn claim_partial_with_proofs_and_uncovered() {
    let claim = ConfinementClaim {
        claim_id: "claim-integ-mixed".to_string(),
        component_id: "comp".to_string(),
        policy_ref: "pol".to_string(),
        flow_proofs: vec!["proof-a".to_string()],
        uncovered_flows: vec![FlowRule {
            source_label: Label::TopSecret,
            sink_clearance: Label::Public,
        }],
        claim_strength: ClaimStrength::Partial,
        timestamp_ms: 100,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: sentinel_sig(),
    };
    assert!(claim.validate().is_ok());
    assert!(!claim.is_full());
}

// ===========================================================================
// 24. Signing with different keys produces different signatures
// ===========================================================================

#[test]
fn different_keys_produce_different_signatures() {
    let key_a = SigningKey::from_bytes([1u8; 32]);
    let key_b = SigningKey::from_bytes([2u8; 32]);

    let mut proof_a = make_flow_proof();
    proof_a.sign(&key_a).unwrap();

    let mut proof_b = make_flow_proof();
    proof_b.sign(&key_b).unwrap();

    assert_ne!(proof_a.signature, proof_b.signature);
}

// ===========================================================================
// 25. DeclassificationObligation with millionths (fixed-point)
// ===========================================================================

#[test]
fn obligation_max_loss_millionths() {
    let obl = DeclassificationObligation {
        obligation_id: "obl-loss-integ".to_string(),
        source_label: Label::Secret,
        target_clearance: ClearanceClass::AuditedSink,
        required_conditions: vec![],
        max_loss_milli: 500_000, // 0.5 in fixed-point
        audit_trail_required: true,
        approval_authority: "risk_team".to_string(),
        expiry_epoch: None,
    };
    assert_eq!(obl.max_loss_milli, 500_000);
    // Round-trip preserves fixed-point value
    let json = serde_json::to_string(&obl).unwrap();
    let parsed: DeclassificationObligation = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.max_loss_milli, 500_000);
}

// ===========================================================================
// 26. DeclassificationReceipt with Deny decision
// ===========================================================================

#[test]
fn receipt_deny_decision_roundtrip() {
    let mut receipt = make_receipt();
    receipt.decision = DeclassificationDecision::Deny;
    let json = serde_json::to_string(&receipt).unwrap();
    let parsed: DeclassificationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.decision, DeclassificationDecision::Deny);
}

// ===========================================================================
// 27. Taint propagation chain through computed labels
// ===========================================================================

#[test]
fn taint_propagation_chain() {
    // Simulate: literal + env_var -> computed1; computed1 + credential -> computed2
    let literal_label = Ir2LabelSource::Literal.assign_label();
    assert_eq!(literal_label, Label::Public);

    let env_label = Ir2LabelSource::EnvironmentVariable.assign_label();
    assert_eq!(env_label, Label::Secret);

    let computed1 = Ir2LabelSource::Computed {
        input_labels: vec![literal_label, env_label],
    }
    .assign_label();
    assert_eq!(computed1, Label::Secret);

    let cred_label = Ir2LabelSource::CredentialPath {
        is_key_material: true,
    }
    .assign_label();
    assert_eq!(cred_label, Label::TopSecret);

    let computed2 = Ir2LabelSource::Computed {
        input_labels: vec![computed1, cred_label],
    }
    .assign_label();
    assert_eq!(computed2, Label::TopSecret);
}

// ===========================================================================
// 28. Taint propagation with declassification break
// ===========================================================================

#[test]
fn taint_propagation_with_declassification_break() {
    // TopSecret data gets declassified to Internal
    let declassified = Ir2LabelSource::Declassified {
        receipt_ref: "receipt-declass-integ".to_string(),
        effective_label: Label::Internal,
    }
    .assign_label();
    assert_eq!(declassified, Label::Internal);

    // Combining declassified (Internal) with Public stays Internal
    let combined = Ir2LabelSource::Computed {
        input_labels: vec![declassified, Label::Public],
    }
    .assign_label();
    assert_eq!(combined, Label::Internal);
}
