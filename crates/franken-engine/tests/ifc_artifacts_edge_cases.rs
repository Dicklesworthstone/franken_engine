//! Integration tests for `ifc_artifacts` — IFC lattice, policies, proofs,
//! receipts, confinement claims, and validation errors.

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

// ── helpers ──────────────────────────────────────────────────────────────

fn test_key() -> SigningKey {
    SigningKey::from_bytes([42u8; 32])
}

fn sentinel_sig() -> Signature {
    Signature::from_bytes(SIGNATURE_SENTINEL)
}

fn make_flow_policy() -> FlowPolicy {
    FlowPolicy {
        policy_id: "pol-001".into(),
        extension_id: "ext-abc".into(),
        label_classes: [Label::Internal, Label::Secret, Label::Confidential]
            .into_iter()
            .collect(),
        clearance_classes: [Label::Internal, Label::Confidential, Label::Public]
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
            route_id: "declass-1".into(),
            source_label: Label::Secret,
            target_clearance: Label::Internal,
            conditions: vec!["audit_approval".into()],
        }],
        epoch_id: 1,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: sentinel_sig(),
    }
}

fn make_flow_proof() -> FlowProof {
    FlowProof {
        proof_id: "proof-001".into(),
        flow_source_label: Label::Internal,
        flow_source_location: "mod_a::fn_x".into(),
        flow_sink_clearance: Label::Confidential,
        flow_sink_location: "mod_b::fn_y".into(),
        policy_ref: "pol-001".into(),
        proof_method: ProofMethod::StaticAnalysis,
        proof_evidence: vec!["ir_node_42".into()],
        timestamp_ms: 1_700_000_000_000,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: sentinel_sig(),
    }
}

fn make_receipt() -> DeclassificationReceipt {
    let key = test_key();
    DeclassificationReceipt {
        receipt_id: "rcpt-001".into(),
        source_label: Label::Secret,
        sink_clearance: Label::Internal,
        declassification_route_ref: "declass-1".into(),
        decision_contract_id: "decision-contract-1".into(),
        policy_evaluation_summary: "OK".into(),
        loss_assessment_milli: 500,
        decision: DeclassificationDecision::Allow,
        authorized_by: key.verification_key(),
        replay_linkage: "trace-001".into(),
        timestamp_ms: 1_700_000_000_000,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: sentinel_sig(),
    }
}

fn make_claim(strength: ClaimStrength) -> ConfinementClaim {
    let uncovered = if strength == ClaimStrength::Partial {
        vec![FlowRule {
            source_label: Label::Secret,
            sink_clearance: Label::Public,
        }]
    } else {
        vec![]
    };
    ConfinementClaim {
        claim_id: "claim-001".into(),
        component_id: "comp-xyz".into(),
        policy_ref: "pol-001".into(),
        flow_proofs: vec!["proof-001".into()],
        uncovered_flows: uncovered,
        claim_strength: strength,
        timestamp_ms: 1_700_000_000_000,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: sentinel_sig(),
    }
}

fn make_flow_envelope() -> FlowEnvelope {
    FlowEnvelope {
        envelope_id: "env-001".into(),
        extension_id: "ext-abc".into(),
        producible_labels: [Label::Public, Label::Internal].into_iter().collect(),
        accessible_clearances: [ClearanceClass::OpenSink, ClearanceClass::RestrictedSink]
            .into_iter()
            .collect(),
        authorized_declassifications: vec!["obl-001".into()],
        policy_ref: "pol-001".into(),
        epoch_id: 1,
        schema_version: IfcSchemaVersion::CURRENT,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// IfcSchemaVersion
// ═══════════════════════════════════════════════════════════════════════════

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
    assert_eq!(IfcSchemaVersion::new(2, 3, 7).to_string(), "2.3.7");
    assert_eq!(IfcSchemaVersion::new(0, 0, 0).to_string(), "0.0.0");
}

#[test]
fn schema_version_serde_roundtrip() {
    let versions = [
        IfcSchemaVersion::CURRENT,
        IfcSchemaVersion::new(2, 1, 0),
        IfcSchemaVersion::new(0, 0, 0),
    ];
    for v in versions {
        let json = serde_json::to_string(&v).unwrap();
        let parsed: IfcSchemaVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(v, parsed);
    }
}

#[test]
fn schema_version_compatibility() {
    let v1_0 = IfcSchemaVersion::new(1, 0, 0);
    let v1_1 = IfcSchemaVersion::new(1, 1, 0);
    let v2_0 = IfcSchemaVersion::new(2, 0, 0);

    // Same version is compatible
    assert!(v1_0.is_compatible_with(&v1_0));
    // Higher minor is compatible with lower minor (same major)
    assert!(v1_1.is_compatible_with(&v1_0));
    // Lower minor is NOT compatible with higher minor
    assert!(!v1_0.is_compatible_with(&v1_1));
    // Different major is never compatible
    assert!(!v2_0.is_compatible_with(&v1_0));
    assert!(!v1_0.is_compatible_with(&v2_0));
}

#[test]
fn schema_version_ordering() {
    let v0 = IfcSchemaVersion::new(0, 0, 0);
    let v1 = IfcSchemaVersion::new(1, 0, 0);
    let v1_1 = IfcSchemaVersion::new(1, 1, 0);
    let v1_1_1 = IfcSchemaVersion::new(1, 1, 1);
    let v2 = IfcSchemaVersion::new(2, 0, 0);
    assert!(v0 < v1);
    assert!(v1 < v1_1);
    assert!(v1_1 < v1_1_1);
    assert!(v1_1_1 < v2);
}

// ═══════════════════════════════════════════════════════════════════════════
// Label — custom label edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn custom_label_level_zero_same_as_public() {
    let custom_zero = Label::Custom {
        name: "zero".into(),
        level: 0,
    };
    // Same level as Public
    assert_eq!(custom_zero.level(), Label::Public.level());
    // join of same level returns first operand (self)
    assert_eq!(Label::Public.join(&custom_zero), Label::Public);
    assert_eq!(custom_zero.join(&Label::Public), custom_zero);
    // meet of same level returns first operand (self)
    assert_eq!(Label::Public.meet(&custom_zero), Label::Public);
    // can_flow_to is symmetric for same level
    assert!(custom_zero.can_flow_to(&Label::Public));
    assert!(Label::Public.can_flow_to(&custom_zero));
}

#[test]
fn custom_label_high_level_dominates_top_secret() {
    let ultra = Label::Custom {
        name: "ultra".into(),
        level: 100,
    };
    assert!(ultra.level() > Label::TopSecret.level());
    assert_eq!(Label::TopSecret.join(&ultra), ultra);
    assert_eq!(ultra.meet(&Label::TopSecret), Label::TopSecret);
    assert!(!ultra.can_flow_to(&Label::TopSecret));
    assert!(Label::TopSecret.can_flow_to(&ultra));
}

#[test]
fn custom_labels_same_level_different_names() {
    let a = Label::Custom {
        name: "alpha".into(),
        level: 3,
    };
    let b = Label::Custom {
        name: "beta".into(),
        level: 3,
    };
    // Same level but different names → not equal
    assert_ne!(a, b);
    // can_flow_to is symmetric (both level 3)
    assert!(a.can_flow_to(&b));
    assert!(b.can_flow_to(&a));
}

#[test]
fn label_hash_all_distinct() {
    use std::collections::HashSet;
    let mut hashes = HashSet::new();
    for label in Label::all_builtin() {
        assert!(hashes.insert(format!("{label:?}")));
    }
}

#[test]
fn label_join_all_single_returns_identity() {
    assert_eq!(Label::join_all([Label::Secret]), Some(Label::Secret));
}

#[test]
fn label_meet_all_single_returns_identity() {
    assert_eq!(Label::meet_all([Label::Secret]), Some(Label::Secret));
}

#[test]
fn label_can_flow_to_reflexive() {
    for label in Label::all_builtin() {
        assert!(
            label.can_flow_to(&label),
            "label {label} should flow to itself"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ClearanceClass — additional edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn clearance_as_str_matches_display() {
    for cc in ClearanceClass::all() {
        assert_eq!(cc.as_str(), cc.to_string());
    }
}

#[test]
fn clearance_hash_all_distinct() {
    use std::collections::HashSet;
    let mut hashes = HashSet::new();
    for cc in ClearanceClass::all() {
        assert!(hashes.insert(cc));
    }
    assert_eq!(hashes.len(), 5);
}

#[test]
fn clearance_custom_label_reception() {
    let custom_level_1 = Label::Custom {
        name: "low_custom".into(),
        level: 1,
    };
    let custom_level_5 = Label::Custom {
        name: "ultra_custom".into(),
        level: 5,
    };
    // RestrictedSink max=1 can receive custom level 1
    assert!(ClearanceClass::RestrictedSink.can_receive(&custom_level_1));
    // OpenSink max=4 cannot receive custom level 5
    assert!(!ClearanceClass::OpenSink.can_receive(&custom_level_5));
}

// ═══════════════════════════════════════════════════════════════════════════
// DeclassificationObligation — boundary conditions
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn obligation_expiry_exact_boundary() {
    let obl = DeclassificationObligation {
        obligation_id: "obl-boundary".into(),
        source_label: Label::Secret,
        target_clearance: ClearanceClass::AuditedSink,
        required_conditions: vec![],
        max_loss_milli: 0,
        audit_trail_required: false,
        approval_authority: "auto".into(),
        expiry_epoch: Some(100),
    };
    assert!(!obl.is_expired(99));
    assert!(!obl.is_expired(100)); // at boundary: not expired
    assert!(obl.is_expired(101)); // past boundary: expired
}

#[test]
fn obligation_no_expiry_never_expires() {
    let obl = DeclassificationObligation {
        obligation_id: "obl-forever".into(),
        source_label: Label::Internal,
        target_clearance: ClearanceClass::OpenSink,
        required_conditions: vec![],
        max_loss_milli: 0,
        audit_trail_required: false,
        approval_authority: "auto".into(),
        expiry_epoch: None,
    };
    assert!(!obl.is_expired(u64::MAX));
}

#[test]
fn obligation_serde_roundtrip() {
    let obl = DeclassificationObligation {
        obligation_id: "obl-test".into(),
        source_label: Label::TopSecret,
        target_clearance: ClearanceClass::SealedSink,
        required_conditions: vec!["ciso".into(), "audit".into()],
        max_loss_milli: 10_000,
        audit_trail_required: true,
        approval_authority: "security_team".into(),
        expiry_epoch: Some(50),
    };
    let json = serde_json::to_string(&obl).unwrap();
    let parsed: DeclassificationObligation = serde_json::from_str(&json).unwrap();
    assert_eq!(obl, parsed);
}

#[test]
fn obligation_partial_conditions() {
    let obl = DeclassificationObligation {
        obligation_id: "obl-multi".into(),
        source_label: Label::Secret,
        target_clearance: ClearanceClass::AuditedSink,
        required_conditions: vec!["a".into(), "b".into(), "c".into()],
        max_loss_milli: 0,
        audit_trail_required: false,
        approval_authority: "auto".into(),
        expiry_epoch: None,
    };
    let mut satisfied = BTreeSet::new();
    satisfied.insert("a".into());
    satisfied.insert("b".into());
    // Missing "c"
    assert!(!obl.conditions_satisfied(&satisfied));
    satisfied.insert("c".into());
    assert!(obl.conditions_satisfied(&satisfied));
}

// ═══════════════════════════════════════════════════════════════════════════
// FlowEnvelope — edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn flow_envelope_content_hash_changes_on_mutation() {
    let e1 = make_flow_envelope();
    let mut e2 = make_flow_envelope();
    e2.epoch_id = 999;
    assert_ne!(e1.content_hash(), e2.content_hash());
}

#[test]
fn flow_envelope_empty_labels_rejects_all() {
    let env = FlowEnvelope {
        envelope_id: "env-empty".into(),
        extension_id: "ext-empty".into(),
        producible_labels: BTreeSet::new(),
        accessible_clearances: BTreeSet::new(),
        authorized_declassifications: vec![],
        policy_ref: "pol-none".into(),
        epoch_id: 1,
        schema_version: IfcSchemaVersion::CURRENT,
    };
    // No labels → nothing authorized
    assert!(!env.is_flow_authorized(&Label::Public, &ClearanceClass::OpenSink));
}

#[test]
fn flow_envelope_serde_roundtrip() {
    let env = make_flow_envelope();
    let json = serde_json::to_string(&env).unwrap();
    let parsed: FlowEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(env, parsed);
}

// ═══════════════════════════════════════════════════════════════════════════
// FlowPolicy — rule priority & edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn flow_policy_prohibition_overrides_lattice() {
    // Confidential -> Public is lattice-illegal AND explicitly prohibited
    let policy = make_flow_policy();
    assert_eq!(
        policy.is_flow_allowed(&Label::Confidential, &Label::Public),
        FlowCheckResult::Prohibited
    );
}

#[test]
fn flow_policy_explicit_allowed_checked_before_lattice() {
    // Internal -> Confidential is explicitly allowed (but also lattice-legal)
    // The explicit rule returns Allowed (not LatticeAllowed)
    let policy = make_flow_policy();
    assert_eq!(
        policy.is_flow_allowed(&Label::Internal, &Label::Confidential),
        FlowCheckResult::Allowed
    );
}

#[test]
fn flow_policy_empty_rules_defaults_to_lattice() {
    let policy = FlowPolicy {
        policy_id: "pol-empty".into(),
        extension_id: "ext".into(),
        label_classes: BTreeSet::new(),
        clearance_classes: BTreeSet::new(),
        allowed_flows: vec![],
        prohibited_flows: vec![],
        declassification_routes: vec![],
        epoch_id: 1,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: sentinel_sig(),
    };
    // Lattice-legal: Public -> Secret
    assert_eq!(
        policy.is_flow_allowed(&Label::Public, &Label::Secret),
        FlowCheckResult::LatticeAllowed
    );
    // Not lattice-legal, no rules → Denied
    assert_eq!(
        policy.is_flow_allowed(&Label::Secret, &Label::Public),
        FlowCheckResult::Denied
    );
}

#[test]
fn flow_policy_multiple_declassification_routes() {
    let policy = FlowPolicy {
        policy_id: "pol-multi-declass".into(),
        extension_id: "ext".into(),
        label_classes: BTreeSet::new(),
        clearance_classes: BTreeSet::new(),
        allowed_flows: vec![],
        prohibited_flows: vec![],
        declassification_routes: vec![
            DeclassificationRoute {
                route_id: "route-a".into(),
                source_label: Label::Secret,
                target_clearance: Label::Internal,
                conditions: vec!["audit".into()],
            },
            DeclassificationRoute {
                route_id: "route-b".into(),
                source_label: Label::TopSecret,
                target_clearance: Label::Confidential,
                conditions: vec!["ciso".into()],
            },
        ],
        epoch_id: 1,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: sentinel_sig(),
    };
    // First route matches
    assert_eq!(
        policy.is_flow_allowed(&Label::Secret, &Label::Internal),
        FlowCheckResult::DeclassificationRequired {
            route_id: "route-a".into()
        }
    );
    // Second route matches
    assert_eq!(
        policy.is_flow_allowed(&Label::TopSecret, &Label::Confidential),
        FlowCheckResult::DeclassificationRequired {
            route_id: "route-b".into()
        }
    );
}

#[test]
fn flow_policy_sign_then_tamper_fails_verify() {
    let key = test_key();
    let mut policy = make_flow_policy();
    policy.sign(&key).unwrap();
    // Tamper with epoch
    policy.epoch_id = 999;
    assert!(policy.verify(&key.verification_key()).is_err());
}

#[test]
fn flow_policy_content_hash_changes_on_rule_addition() {
    let p1 = make_flow_policy();
    let mut p2 = make_flow_policy();
    p2.allowed_flows.push(FlowRule {
        source_label: Label::Public,
        sink_clearance: Label::Internal,
    });
    assert_ne!(p1.content_hash(), p2.content_hash());
}

// ═══════════════════════════════════════════════════════════════════════════
// FlowProof — mutation & verification edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn flow_proof_content_hash_changes_on_mutation() {
    let p1 = make_flow_proof();
    let mut p2 = make_flow_proof();
    p2.proof_method = ProofMethod::RuntimeCheck;
    assert_ne!(p1.content_hash(), p2.content_hash());
}

#[test]
fn flow_proof_verify_fails_wrong_key() {
    let key = test_key();
    let wrong_key = SigningKey::from_bytes([99u8; 32]);
    let mut proof = make_flow_proof();
    proof.sign(&key).unwrap();
    assert!(proof.verify(&wrong_key.verification_key()).is_err());
}

#[test]
fn flow_proof_sign_then_tamper_fails_verify() {
    let key = test_key();
    let mut proof = make_flow_proof();
    proof.sign(&key).unwrap();
    proof.timestamp_ms = 0;
    assert!(proof.verify(&key.verification_key()).is_err());
}

// ═══════════════════════════════════════════════════════════════════════════
// DeclassificationReceipt — mutation & verification edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn receipt_content_hash_changes_on_mutation() {
    let r1 = make_receipt();
    let mut r2 = make_receipt();
    r2.decision = DeclassificationDecision::Deny;
    assert_ne!(r1.content_hash(), r2.content_hash());
}

#[test]
fn receipt_verify_fails_wrong_key() {
    let key = test_key();
    let wrong_key = SigningKey::from_bytes([99u8; 32]);
    let mut receipt = make_receipt();
    receipt.sign(&key).unwrap();
    assert!(receipt.verify(&wrong_key.verification_key()).is_err());
}

#[test]
fn receipt_sign_then_tamper_fails_verify() {
    let key = test_key();
    let mut receipt = make_receipt();
    receipt.sign(&key).unwrap();
    receipt.loss_assessment_milli = 999_999;
    assert!(receipt.verify(&key.verification_key()).is_err());
}

#[test]
fn receipt_deny_decision_serde() {
    let mut receipt = make_receipt();
    receipt.decision = DeclassificationDecision::Deny;
    let json = serde_json::to_string(&receipt).unwrap();
    let parsed: DeclassificationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.decision, DeclassificationDecision::Deny);
}

// ═══════════════════════════════════════════════════════════════════════════
// ConfinementClaim — validation & verification edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn claim_partial_with_uncovered_validates_ok() {
    let claim = make_claim(ClaimStrength::Partial);
    assert!(!claim.uncovered_flows.is_empty());
    assert!(claim.validate().is_ok());
    assert!(!claim.is_full());
}

#[test]
fn claim_content_hash_changes_on_mutation() {
    let c1 = make_claim(ClaimStrength::Full);
    let mut c2 = make_claim(ClaimStrength::Full);
    c2.component_id = "different-comp".into();
    assert_ne!(c1.content_hash(), c2.content_hash());
}

#[test]
fn claim_verify_fails_wrong_key() {
    let key = test_key();
    let wrong_key = SigningKey::from_bytes([99u8; 32]);
    let mut claim = make_claim(ClaimStrength::Full);
    claim.sign(&key).unwrap();
    assert!(claim.verify(&wrong_key.verification_key()).is_err());
}

#[test]
fn claim_sign_then_tamper_fails_verify() {
    let key = test_key();
    let mut claim = make_claim(ClaimStrength::Full);
    claim.sign(&key).unwrap();
    claim.claim_strength = ClaimStrength::Partial;
    assert!(claim.verify(&key.verification_key()).is_err());
}

#[test]
fn claim_multiple_proofs_validates_full() {
    let claim = ConfinementClaim {
        claim_id: "claim-multi".into(),
        component_id: "comp".into(),
        policy_ref: "pol".into(),
        flow_proofs: vec!["proof-1".into(), "proof-2".into(), "proof-3".into()],
        uncovered_flows: vec![],
        claim_strength: ClaimStrength::Full,
        timestamp_ms: 0,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: sentinel_sig(),
    };
    assert!(claim.validate().is_ok());
    assert!(claim.is_full());
}

// ═══════════════════════════════════════════════════════════════════════════
// IfcValidationError
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn validation_error_is_std_error() {
    let err = IfcValidationError::EmptyClaim {
        claim_id: "c".into(),
    };
    // std::error::Error source returns None
    let std_err: &dyn std::error::Error = &err;
    assert!(std_err.source().is_none());
}

#[test]
fn validation_error_incompatible_schema_display() {
    let err = IfcValidationError::IncompatibleSchema {
        expected: IfcSchemaVersion::new(1, 0, 0),
        actual: IfcSchemaVersion::new(2, 0, 0),
    };
    let msg = err.to_string();
    assert!(msg.contains("2.0.0"));
    assert!(msg.contains("1.0.0"));
    assert!(msg.contains("incompatible"));
}

#[test]
fn validation_error_flow_prohibited_display() {
    let err = IfcValidationError::FlowProhibited {
        source: Label::TopSecret,
        sink: Label::Public,
    };
    let msg = err.to_string();
    assert!(msg.contains("top_secret"));
    assert!(msg.contains("public"));
    assert!(msg.contains("prohibited"));
}

#[test]
fn validation_error_full_claim_display() {
    let err = IfcValidationError::FullClaimHasUncoveredFlows {
        claim_id: "claim-x".into(),
        uncovered_count: 5,
    };
    let msg = err.to_string();
    assert!(msg.contains("claim-x"));
    assert!(msg.contains("5"));
    assert!(msg.contains("uncovered"));
}

#[test]
fn validation_error_serde_all_variants() {
    let errors = [
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
    for err in errors {
        let json = serde_json::to_string(&err).unwrap();
        let parsed: IfcValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, parsed);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// FlowRule — ordering and custom labels
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn flow_rule_ordering() {
    let r1 = FlowRule {
        source_label: Label::Internal,
        sink_clearance: Label::Confidential,
    };
    let r2 = FlowRule {
        source_label: Label::Secret,
        sink_clearance: Label::Public,
    };
    // Ordering is derived — Internal < Secret in Label Ord
    assert!(r1 < r2);
}

#[test]
fn flow_rule_with_custom_label_serde() {
    let rule = FlowRule {
        source_label: Label::Custom {
            name: "zone_a".into(),
            level: 5,
        },
        sink_clearance: Label::Custom {
            name: "zone_b".into(),
            level: 2,
        },
    };
    let json = serde_json::to_string(&rule).unwrap();
    let parsed: FlowRule = serde_json::from_str(&json).unwrap();
    assert_eq!(rule, parsed);
}

// ═══════════════════════════════════════════════════════════════════════════
// DeclassificationRoute — edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn declassification_route_empty_conditions() {
    let route = DeclassificationRoute {
        route_id: "route-auto".into(),
        source_label: Label::Internal,
        target_clearance: Label::Public,
        conditions: vec![],
    };
    let json = serde_json::to_string(&route).unwrap();
    let parsed: DeclassificationRoute = serde_json::from_str(&json).unwrap();
    assert_eq!(route, parsed);
}

#[test]
fn declassification_route_ordering() {
    let r1 = DeclassificationRoute {
        route_id: "a".into(),
        source_label: Label::Internal,
        target_clearance: Label::Public,
        conditions: vec![],
    };
    let r2 = DeclassificationRoute {
        route_id: "b".into(),
        source_label: Label::Internal,
        target_clearance: Label::Public,
        conditions: vec![],
    };
    assert!(r1 < r2); // "a" < "b"
}

// ═══════════════════════════════════════════════════════════════════════════
// FlowCheckResult — serde & equality
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn flow_check_result_declass_required_different_route_ids_differ() {
    let a = FlowCheckResult::DeclassificationRequired {
        route_id: "r1".into(),
    };
    let b = FlowCheckResult::DeclassificationRequired {
        route_id: "r2".into(),
    };
    assert_ne!(a, b);
}

#[test]
fn flow_check_result_all_variants_distinct() {
    let variants: Vec<FlowCheckResult> = vec![
        FlowCheckResult::Allowed,
        FlowCheckResult::LatticeAllowed,
        FlowCheckResult::DeclassificationRequired {
            route_id: "x".into(),
        },
        FlowCheckResult::Prohibited,
        FlowCheckResult::Denied,
    ];
    for i in 0..variants.len() {
        for j in (i + 1)..variants.len() {
            assert_ne!(variants[i], variants[j]);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ProofMethod — ordering
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn proof_method_ordering() {
    assert!(ProofMethod::StaticAnalysis < ProofMethod::RuntimeCheck);
    assert!(ProofMethod::RuntimeCheck < ProofMethod::Declassification);
}

// ═══════════════════════════════════════════════════════════════════════════
// Ir2LabelSource — additional edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn ir2_computed_single_label_returns_identity() {
    let source = Ir2LabelSource::Computed {
        input_labels: vec![Label::Confidential],
    };
    assert_eq!(source.assign_label(), Label::Confidential);
}

#[test]
fn ir2_computed_all_builtin_returns_top_secret() {
    let source = Ir2LabelSource::Computed {
        input_labels: Label::all_builtin().to_vec(),
    };
    assert_eq!(source.assign_label(), Label::TopSecret);
}

#[test]
fn ir2_computed_empty_returns_public() {
    let source = Ir2LabelSource::Computed {
        input_labels: vec![],
    };
    assert_eq!(source.assign_label(), Label::Public);
}

#[test]
fn ir2_credential_path_non_key_material() {
    let source = Ir2LabelSource::CredentialPath {
        is_key_material: false,
    };
    assert_eq!(source.assign_label(), Label::Secret);
}

#[test]
fn ir2_hostcall_return_custom_label() {
    let custom = Label::Custom {
        name: "hostcall_zone".into(),
        level: 7,
    };
    let source = Ir2LabelSource::HostcallReturn {
        clearance_label: custom.clone(),
    };
    assert_eq!(source.assign_label(), custom);
}

// ═══════════════════════════════════════════════════════════════════════════
// DeclassificationDecision
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn declassification_decision_ordering() {
    // Allow < Deny in Ord derive
    assert!(DeclassificationDecision::Allow < DeclassificationDecision::Deny);
}

#[test]
fn declassification_decision_hash_distinct() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(DeclassificationDecision::Allow);
    set.insert(DeclassificationDecision::Deny);
    assert_eq!(set.len(), 2);
}

// ═══════════════════════════════════════════════════════════════════════════
// ClaimStrength
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn claim_strength_ordering() {
    assert!(ClaimStrength::Full < ClaimStrength::Partial);
}

// ═══════════════════════════════════════════════════════════════════════════
// Cross-type integration scenarios
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn full_lifecycle_sign_and_verify_all_artifacts() {
    let key = test_key();

    // 1. Policy
    let mut policy = make_flow_policy();
    policy.sign(&key).unwrap();
    policy.verify(&key.verification_key()).unwrap();

    // 2. Proof referencing the policy
    let mut proof = make_flow_proof();
    proof.policy_ref = policy.policy_id.clone();
    proof.sign(&key).unwrap();
    proof.verify(&key.verification_key()).unwrap();

    // 3. Declassification receipt
    let mut receipt = make_receipt();
    receipt.sign(&key).unwrap();
    receipt.verify(&key.verification_key()).unwrap();

    // 4. Confinement claim
    let mut claim = ConfinementClaim {
        claim_id: "lifecycle-claim".into(),
        component_id: "comp-lifecycle".into(),
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

#[test]
fn policy_evaluation_priority_order() {
    // prohibition > allowed > lattice > declass > denied
    let policy = FlowPolicy {
        policy_id: "priority-pol".into(),
        extension_id: "ext".into(),
        label_classes: BTreeSet::new(),
        clearance_classes: BTreeSet::new(),
        // Public -> Internal is both explicitly allowed AND lattice-legal
        allowed_flows: vec![FlowRule {
            source_label: Label::Public,
            sink_clearance: Label::Internal,
        }],
        // Public -> Internal is ALSO prohibited — prohibition wins
        prohibited_flows: vec![FlowRule {
            source_label: Label::Public,
            sink_clearance: Label::Internal,
        }],
        declassification_routes: vec![],
        epoch_id: 1,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: sentinel_sig(),
    };
    // Prohibition checked first
    assert_eq!(
        policy.is_flow_allowed(&Label::Public, &Label::Internal),
        FlowCheckResult::Prohibited
    );
}

#[test]
fn exfiltration_multi_taint_propagation() {
    // Simulate: literal + env_var + credential → computed → check sinks
    let labels = vec![
        Ir2LabelSource::Literal.assign_label(),
        Ir2LabelSource::EnvironmentVariable.assign_label(),
        Ir2LabelSource::CredentialPath {
            is_key_material: false,
        }
        .assign_label(),
    ];
    let combined = Ir2LabelSource::Computed {
        input_labels: labels,
    }
    .assign_label();
    // Public(0) + Secret(3) + Secret(3) → Secret
    assert_eq!(combined, Label::Secret);
    // Cannot flow to RestrictedSink (max=1)
    assert!(!ClearanceClass::RestrictedSink.can_receive(&combined));
    // Can flow to SealedSink (max=3)
    assert!(ClearanceClass::SealedSink.can_receive(&combined));
}

#[test]
fn envelope_rejects_flow_when_clearance_cant_receive() {
    // Even if label in producible and clearance in accessible,
    // clearance.can_receive must also pass
    let env = FlowEnvelope {
        envelope_id: "env-strict".into(),
        extension_id: "ext".into(),
        producible_labels: [Label::Secret].into_iter().collect(),
        accessible_clearances: [ClearanceClass::RestrictedSink].into_iter().collect(),
        authorized_declassifications: vec![],
        policy_ref: "pol".into(),
        epoch_id: 1,
        schema_version: IfcSchemaVersion::CURRENT,
    };
    // Secret(3) > RestrictedSink max(1) → rejected
    assert!(!env.is_flow_authorized(&Label::Secret, &ClearanceClass::RestrictedSink));
}

#[test]
fn content_hash_determinism_across_100_iterations() {
    let policy_hash = make_flow_policy().content_hash();
    let proof_hash = make_flow_proof().content_hash();
    let receipt_hash = make_receipt().content_hash();
    let claim_hash = make_claim(ClaimStrength::Full).content_hash();
    let envelope_hash = make_flow_envelope().content_hash();

    for _ in 0..100 {
        assert_eq!(make_flow_policy().content_hash(), policy_hash);
        assert_eq!(make_flow_proof().content_hash(), proof_hash);
        assert_eq!(make_receipt().content_hash(), receipt_hash);
        assert_eq!(make_claim(ClaimStrength::Full).content_hash(), claim_hash);
        assert_eq!(make_flow_envelope().content_hash(), envelope_hash);
    }
}

#[test]
fn all_artifact_hashes_are_unique() {
    let hashes = [
        make_flow_policy().content_hash(),
        make_flow_proof().content_hash(),
        make_receipt().content_hash(),
        make_claim(ClaimStrength::Full).content_hash(),
        make_flow_envelope().content_hash(),
    ];
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(hashes[i], hashes[j], "hashes at {i} and {j} collide");
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Lattice properties with custom labels in integration context
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn lattice_join_meet_with_custom_labels() {
    let custom_3 = Label::Custom {
        name: "zone".into(),
        level: 3,
    };
    // Same level as Secret(3)
    assert_eq!(custom_3.level(), Label::Secret.level());
    // join of same-level returns first operand
    assert_eq!(Label::Secret.join(&custom_3), Label::Secret);
    assert_eq!(custom_3.join(&Label::Secret), custom_3);
    // meet of same-level returns first operand
    assert_eq!(Label::Secret.meet(&custom_3), Label::Secret);
    assert_eq!(custom_3.meet(&Label::Secret), custom_3);
}

#[test]
fn lattice_flow_transitivity() {
    // If A can flow to B and B can flow to C, then A can flow to C
    for a in &Label::all_builtin() {
        for b in &Label::all_builtin() {
            for c in &Label::all_builtin() {
                if a.can_flow_to(b) && b.can_flow_to(c) {
                    assert!(
                        a.can_flow_to(c),
                        "transitivity: {a} -> {b} -> {c} but {a} cannot flow to {c}"
                    );
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Large-scale / stress tests
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn policy_with_many_rules_evaluates_correctly() {
    let mut allowed = Vec::new();
    let mut prohibited = Vec::new();
    let labels = Label::all_builtin();

    // Allow all upward flows explicitly
    for i in 0..labels.len() {
        for j in i..labels.len() {
            allowed.push(FlowRule {
                source_label: labels[i].clone(),
                sink_clearance: labels[j].clone(),
            });
        }
    }
    // Prohibit Secret -> Confidential specifically
    prohibited.push(FlowRule {
        source_label: Label::Secret,
        sink_clearance: Label::Confidential,
    });

    let policy = FlowPolicy {
        policy_id: "pol-many".into(),
        extension_id: "ext".into(),
        label_classes: BTreeSet::new(),
        clearance_classes: BTreeSet::new(),
        allowed_flows: allowed,
        prohibited_flows: prohibited,
        declassification_routes: vec![],
        epoch_id: 1,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: sentinel_sig(),
    };

    // Prohibited wins
    assert_eq!(
        policy.is_flow_allowed(&Label::Secret, &Label::Confidential),
        FlowCheckResult::Prohibited
    );
    // Explicit allowed
    assert_eq!(
        policy.is_flow_allowed(&Label::Public, &Label::TopSecret),
        FlowCheckResult::Allowed
    );
}

#[test]
fn serde_roundtrip_large_flow_envelope() {
    let labels: BTreeSet<Label> = Label::all_builtin().into_iter().collect();
    let clearances: BTreeSet<ClearanceClass> = ClearanceClass::all().into_iter().collect();
    let env = FlowEnvelope {
        envelope_id: "env-large".into(),
        extension_id: "ext-big".into(),
        producible_labels: labels,
        accessible_clearances: clearances,
        authorized_declassifications: (0..20).map(|i| format!("obl-{i:03}")).collect(),
        policy_ref: "pol-big".into(),
        epoch_id: 42,
        schema_version: IfcSchemaVersion::CURRENT,
    };
    let json = serde_json::to_string(&env).unwrap();
    let parsed: FlowEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(env, parsed);
    assert_eq!(parsed.producible_labels.len(), 5);
    assert_eq!(parsed.accessible_clearances.len(), 5);
    assert_eq!(parsed.authorized_declassifications.len(), 20);
}
