#![forbid(unsafe_code)]

//! Integration tests for the `proof_schema` module.
//!
//! Covers schema version compatibility, InvarianceDigest hashing, OptReceipt
//! and RollbackToken signing/verification/validation, signer authorization,
//! serde round-trips, and Display trait outputs.

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

use std::collections::BTreeMap;

use frankenengine_engine::control_plane::SchemaVersion;
use frankenengine_engine::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::proof_schema::*;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::tee_attestation_policy::DecisionImpact;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const TEST_KEY: &[u8] = b"integration-signing-key-material!";
const WRONG_KEY: &[u8] = b"wrong-key-material-for-integ!!!!";

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn signer_key_id() -> EngineObjectId {
    let schema = SchemaId::from_definition(b"integ-signer-key");
    derive_id(
        ObjectDomain::CapabilityToken,
        "integ-zone",
        &schema,
        b"key-a",
    )
    .expect("derive id")
}

fn make_invariance_digest() -> InvarianceDigest {
    InvarianceDigest {
        schema_version: proof_schema_version_current(),
        golden_corpus_hash: ContentHash::compute(b"golden-corpus-integ"),
        trace_comparison_methodology: TraceComparisonMethodology::DeterministicReplay,
        equivalence_verdict: EquivalenceVerdict::Equivalent,
        witness_chain_root: ContentHash::compute(b"witness-chain-integ"),
    }
}

fn make_attestation_bindings() -> ReceiptAttestationBindings {
    ReceiptAttestationBindings {
        quote_digest: ContentHash::compute(b"quote-integ"),
        measurement_id: derive_id(
            ObjectDomain::Attestation,
            "integ-zone",
            &SchemaId::from_definition(b"measurement-integ"),
            b"measurement-v1",
        )
        .expect("measurement id"),
        attested_signer_key_id: signer_key_id(),
        nonce: [42u8; 32],
        validity_window: AttestationValidityWindow {
            start_timestamp_ticks: 500,
            end_timestamp_ticks: 1500,
        },
    }
}

fn unsigned_receipt() -> OptReceipt {
    let digest = make_invariance_digest();
    OptReceipt {
        schema_version: proof_schema_version_current(),
        optimization_id: "opt-integ-001".to_string(),
        optimization_class: OptimizationClass::Superinstruction,
        baseline_ir_hash: ContentHash::compute(b"baseline-ir-integ"),
        candidate_ir_hash: ContentHash::compute(b"candidate-ir-integ"),
        translation_witness_hash: ContentHash::compute(b"witness-integ"),
        invariance_digest: digest.content_hash(),
        rollback_token_id: "rtk-integ-001".to_string(),
        replay_compatibility: BTreeMap::from([
            ("engine_version".to_string(), "0.2.0".to_string()),
            ("target_arch".to_string(), "aarch64".to_string()),
        ]),
        policy_epoch: epoch(5),
        timestamp_ticks: 1000,
        signer_key_id: signer_key_id(),
        correlation_id: "corr-integ-001".to_string(),
        decision_impact: DecisionImpact::Standard,
        attestation_bindings: None,
        signature: AuthenticityHash::compute(b"placeholder"),
    }
}

fn signed_receipt() -> OptReceipt {
    unsigned_receipt().sign(TEST_KEY)
}

fn unsigned_rollback() -> RollbackToken {
    RollbackToken {
        schema_version: proof_schema_version_current(),
        token_id: "rtk-integ-001".to_string(),
        optimization_id: "opt-integ-001".to_string(),
        baseline_snapshot_hash: ContentHash::compute(b"baseline-snapshot-integ"),
        activation_stage: ActivationStage::Shadow,
        expiry_epoch: epoch(20),
        issuer_key_id: signer_key_id(),
        issuer_signature: AuthenticityHash::compute(b"placeholder"),
    }
}

fn signed_rollback() -> RollbackToken {
    unsigned_rollback().sign(TEST_KEY)
}

// ===========================================================================
// 1. Schema version compatibility
// ===========================================================================

#[test]
fn schema_v1_0_compatible_with_v1_1() {
    let v1_0 = proof_schema_version_v1_0();
    let v1_1 = proof_schema_version_v1_1();
    assert!(v1_0.is_compatible_with(&v1_1));
    assert!(v1_1.is_compatible_with(&v1_0));
}

#[test]
fn schema_v1_0_not_compatible_with_v2_0() {
    let v1_0 = proof_schema_version_v1_0();
    let v2_0 = SchemaVersion::new(2, 0, 0);
    assert!(!v1_0.is_compatible_with(&v2_0));
    assert!(!v2_0.is_compatible_with(&v1_0));
}

#[test]
fn schema_v1_0_does_not_support_attestation_bindings() {
    assert!(!proof_schema_version_v1_0().supports_attestation_bindings());
}

#[test]
fn schema_v1_1_supports_attestation_bindings() {
    assert!(proof_schema_version_v1_1().supports_attestation_bindings());
}

#[test]
fn schema_major_minor_accessors() {
    let v1_1 = proof_schema_version_v1_1();
    assert_eq!(v1_1.major_val(), 1);
    assert_eq!(v1_1.minor_val(), 1);

    let v1_0 = proof_schema_version_v1_0();
    assert_eq!(v1_0.major_val(), 1);
    assert_eq!(v1_0.minor_val(), 0);
}

#[test]
fn schema_current_returns_v1_1() {
    let current = proof_schema_version_current();
    let v1_1 = proof_schema_version_v1_1();
    assert_eq!(current, v1_1);
}

#[test]
fn schema_v2_1_supports_attestation_bindings() {
    // Any version with major >= 1 and minor >= 1 (or major > 1) should support.
    let v2_1 = SchemaVersion::new(2, 1, 0);
    assert!(v2_1.supports_attestation_bindings());
}

// ===========================================================================
// 2. InvarianceDigest
// ===========================================================================

#[test]
fn invariance_digest_content_hash_is_deterministic() {
    let d1 = make_invariance_digest();
    let d2 = make_invariance_digest();
    assert_eq!(d1.content_hash(), d2.content_hash());
}

#[test]
fn invariance_digest_different_verdict_different_hash() {
    let d1 = make_invariance_digest();
    let mut d2 = make_invariance_digest();
    d2.equivalence_verdict = EquivalenceVerdict::NonEquivalent {
        reason: "diverged on input 42".to_string(),
    };
    assert_ne!(d1.content_hash(), d2.content_hash());
}

#[test]
fn invariance_digest_different_methodology_different_hash() {
    let d1 = make_invariance_digest();
    let mut d2 = make_invariance_digest();
    d2.trace_comparison_methodology = TraceComparisonMethodology::SymbolicEquivalence;
    assert_ne!(d1.content_hash(), d2.content_hash());
}

#[test]
fn invariance_digest_different_corpus_different_hash() {
    let d1 = make_invariance_digest();
    let mut d2 = make_invariance_digest();
    d2.golden_corpus_hash = ContentHash::compute(b"different-corpus");
    assert_ne!(d1.content_hash(), d2.content_hash());
}

#[test]
fn invariance_digest_statistical_corpus_different_sizes_different_hash() {
    let mut d1 = make_invariance_digest();
    d1.trace_comparison_methodology =
        TraceComparisonMethodology::StatisticalCorpus { corpus_size: 100 };
    let mut d2 = make_invariance_digest();
    d2.trace_comparison_methodology =
        TraceComparisonMethodology::StatisticalCorpus { corpus_size: 200 };
    assert_ne!(d1.content_hash(), d2.content_hash());
}

#[test]
fn invariance_digest_inconclusive_verdict_different_hash() {
    let d1 = make_invariance_digest();
    let mut d2 = make_invariance_digest();
    d2.equivalence_verdict = EquivalenceVerdict::Inconclusive {
        reason: "timeout".to_string(),
    };
    assert_ne!(d1.content_hash(), d2.content_hash());
}

// ===========================================================================
// 3. OptReceipt signing and verification
// ===========================================================================

#[test]
fn receipt_sign_then_verify_succeeds() {
    let receipt = signed_receipt();
    assert!(receipt.verify_signature(TEST_KEY));
}

#[test]
fn receipt_wrong_key_fails_verification() {
    let receipt = signed_receipt();
    assert!(!receipt.verify_signature(WRONG_KEY));
}

#[test]
fn receipt_signatures_are_deterministic() {
    let r1 = signed_receipt();
    let r2 = signed_receipt();
    assert_eq!(r1.signature, r2.signature);
}

#[test]
fn receipt_changed_field_different_signature() {
    let r1 = signed_receipt();
    let mut r2 = unsigned_receipt();
    r2.optimization_id = "opt-integ-999".to_string();
    let r2 = r2.sign(TEST_KEY);
    assert_ne!(r1.signature, r2.signature);
}

#[test]
fn receipt_signing_preimage_is_deterministic() {
    let r1 = unsigned_receipt();
    let r2 = unsigned_receipt();
    assert_eq!(r1.signing_preimage(), r2.signing_preimage());
}

#[test]
fn receipt_object_id_is_deterministic() {
    let r1 = signed_receipt();
    let r2 = signed_receipt();
    assert_eq!(
        r1.object_id("zone-integ").unwrap(),
        r2.object_id("zone-integ").unwrap()
    );
}

#[test]
fn receipt_object_id_differs_by_zone() {
    let receipt = signed_receipt();
    assert_ne!(
        receipt.object_id("zone-alpha").unwrap(),
        receipt.object_id("zone-beta").unwrap()
    );
}

#[test]
fn receipt_v1_1_preimage_includes_attestation_fields() {
    let mut with_att = unsigned_receipt();
    with_att.decision_impact = DecisionImpact::HighImpact;
    with_att.attestation_bindings = Some(make_attestation_bindings());

    let without_att = unsigned_receipt();

    // v1.1 preimages must differ because attestation fields are included.
    assert_ne!(with_att.signing_preimage(), without_att.signing_preimage());
}

#[test]
fn receipt_v1_0_preimage_ignores_attestation_fields() {
    let mut legacy_a = unsigned_receipt();
    legacy_a.schema_version = proof_schema_version_v1_0();
    legacy_a.decision_impact = DecisionImpact::Standard;
    legacy_a.attestation_bindings = None;

    let mut legacy_b = legacy_a.clone();
    legacy_b.decision_impact = DecisionImpact::HighImpact;
    legacy_b.attestation_bindings = Some(make_attestation_bindings());

    // v1.0 preimages must be identical — attestation fields are excluded.
    assert_eq!(legacy_a.signing_preimage(), legacy_b.signing_preimage());
}

// ===========================================================================
// 4. RollbackToken
// ===========================================================================

#[test]
fn rollback_sign_then_verify_succeeds() {
    let token = signed_rollback();
    assert!(token.verify_signature(TEST_KEY));
}

#[test]
fn rollback_wrong_key_fails_verification() {
    let token = signed_rollback();
    assert!(!token.verify_signature(WRONG_KEY));
}

#[test]
fn rollback_signatures_are_deterministic() {
    let t1 = signed_rollback();
    let t2 = signed_rollback();
    assert_eq!(t1.issuer_signature, t2.issuer_signature);
}

#[test]
fn rollback_not_expired_before_expiry_epoch() {
    let token = signed_rollback();
    assert!(!token.is_expired(epoch(10)));
    assert!(!token.is_expired(epoch(20)));
}

#[test]
fn rollback_expired_after_expiry_epoch() {
    let token = signed_rollback();
    assert!(token.is_expired(epoch(21)));
    assert!(token.is_expired(epoch(100)));
}

#[test]
fn rollback_not_expired_at_exact_expiry_epoch() {
    let token = signed_rollback();
    // At the exact expiry epoch, is_expired should return false (only > triggers expiry).
    assert!(!token.is_expired(epoch(20)));
}

#[test]
fn rollback_object_id_is_deterministic() {
    let t1 = signed_rollback();
    let t2 = signed_rollback();
    assert_eq!(
        t1.object_id("zone-integ").unwrap(),
        t2.object_id("zone-integ").unwrap()
    );
}

#[test]
fn rollback_object_id_differs_by_zone() {
    let token = signed_rollback();
    assert_ne!(
        token.object_id("zone-x").unwrap(),
        token.object_id("zone-y").unwrap()
    );
}

// ===========================================================================
// 5. Receipt validation
// ===========================================================================

#[test]
fn validate_receipt_valid_passes() {
    let receipt = signed_receipt();
    assert!(validate_receipt(&receipt, TEST_KEY, epoch(5)).is_ok());
}

#[test]
fn validate_receipt_wrong_key_returns_invalid_signature() {
    let receipt = signed_receipt();
    let err = validate_receipt(&receipt, WRONG_KEY, epoch(5)).unwrap_err();
    assert!(matches!(err, ProofSchemaError::InvalidSignature { .. }));
}

#[test]
fn validate_receipt_wrong_epoch_returns_epoch_mismatch() {
    let receipt = signed_receipt();
    let err = validate_receipt(&receipt, TEST_KEY, epoch(99)).unwrap_err();
    assert!(matches!(err, ProofSchemaError::EpochMismatch { .. }));
}

#[test]
fn validate_receipt_incompatible_version_returns_error() {
    let mut receipt = unsigned_receipt();
    receipt.schema_version = SchemaVersion::new(99, 0, 0);
    let receipt = receipt.sign(TEST_KEY);
    let err = validate_receipt(&receipt, TEST_KEY, epoch(5)).unwrap_err();
    assert!(matches!(err, ProofSchemaError::IncompatibleVersion { .. }));
}

#[test]
fn validate_receipt_missing_optimization_id() {
    let mut receipt = unsigned_receipt();
    receipt.optimization_id = String::new();
    let receipt = receipt.sign(TEST_KEY);
    let err = validate_receipt(&receipt, TEST_KEY, epoch(5)).unwrap_err();
    match err {
        ProofSchemaError::MissingField { field } => assert_eq!(field, "optimization_id"),
        other => panic!("expected MissingField, got: {other:?}"),
    }
}

#[test]
fn validate_receipt_missing_rollback_token_id() {
    let mut receipt = unsigned_receipt();
    receipt.rollback_token_id = String::new();
    let receipt = receipt.sign(TEST_KEY);
    let err = validate_receipt(&receipt, TEST_KEY, epoch(5)).unwrap_err();
    match err {
        ProofSchemaError::MissingField { field } => assert_eq!(field, "rollback_token_id"),
        other => panic!("expected MissingField, got: {other:?}"),
    }
}

#[test]
fn validate_receipt_missing_correlation_id() {
    let mut receipt = unsigned_receipt();
    receipt.correlation_id = String::new();
    let receipt = receipt.sign(TEST_KEY);
    let err = validate_receipt(&receipt, TEST_KEY, epoch(5)).unwrap_err();
    match err {
        ProofSchemaError::MissingField { field } => assert_eq!(field, "correlation_id"),
        other => panic!("expected MissingField, got: {other:?}"),
    }
}

#[test]
fn validate_receipt_high_impact_without_attestation_returns_missing_attestation() {
    let mut receipt = unsigned_receipt();
    receipt.decision_impact = DecisionImpact::HighImpact;
    let receipt = receipt.sign(TEST_KEY);
    let err = validate_receipt(&receipt, TEST_KEY, epoch(5)).unwrap_err();
    assert!(matches!(
        err,
        ProofSchemaError::MissingAttestationBindings { .. }
    ));
}

#[test]
fn validate_receipt_high_impact_with_attestation_passes() {
    let mut receipt = unsigned_receipt();
    receipt.decision_impact = DecisionImpact::HighImpact;
    receipt.attestation_bindings = Some(make_attestation_bindings());
    let receipt = receipt.sign(TEST_KEY);
    assert!(validate_receipt(&receipt, TEST_KEY, epoch(5)).is_ok());
}

#[test]
fn validate_receipt_attestation_on_v1_0_returns_unexpected_attestation() {
    let mut receipt = unsigned_receipt();
    receipt.schema_version = proof_schema_version_v1_0();
    receipt.attestation_bindings = Some(make_attestation_bindings());
    let receipt = receipt.sign(TEST_KEY);
    let err = validate_receipt(&receipt, TEST_KEY, epoch(5)).unwrap_err();
    assert!(matches!(
        err,
        ProofSchemaError::UnexpectedAttestationBindingsForVersion { .. }
    ));
}

#[test]
fn validate_receipt_legacy_v1_0_high_impact_passes_with_default_policy() {
    let mut receipt = unsigned_receipt();
    receipt.schema_version = proof_schema_version_v1_0();
    receipt.decision_impact = DecisionImpact::HighImpact;
    receipt.attestation_bindings = None;
    let receipt = receipt.sign(TEST_KEY);
    // Default policy allows legacy receipts without attestation.
    assert!(validate_receipt(&receipt, TEST_KEY, epoch(5)).is_ok());
}

#[test]
fn validate_receipt_strict_policy_rejects_legacy_high_impact() {
    let mut receipt = unsigned_receipt();
    receipt.schema_version = proof_schema_version_v1_0();
    receipt.decision_impact = DecisionImpact::HighImpact;
    receipt.attestation_bindings = None;
    let receipt = receipt.sign(TEST_KEY);

    let strict_policy = AttestationRequirementPolicy {
        require_at_or_above: DecisionImpact::HighImpact,
        allow_legacy_receipts_without_attestation: false,
    };
    let err = validate_receipt_with_policy(&receipt, TEST_KEY, epoch(5), &strict_policy, None)
        .unwrap_err();
    assert!(matches!(
        err,
        ProofSchemaError::MissingAttestationBindings { .. }
    ));
}

#[test]
fn validate_receipt_nonce_replay_detected() {
    let mut nonce_registry = ReceiptNonceRegistry::new();
    let default_policy = AttestationRequirementPolicy::default();

    let mut receipt = unsigned_receipt();
    receipt.decision_impact = DecisionImpact::HighImpact;
    receipt.attestation_bindings = Some(make_attestation_bindings());
    let receipt = receipt.sign(TEST_KEY);

    // First submission succeeds.
    assert!(
        validate_receipt_with_policy(
            &receipt,
            TEST_KEY,
            epoch(5),
            &default_policy,
            Some(&mut nonce_registry),
        )
        .is_ok()
    );

    // Second submission with the same nonce fails.
    let err = validate_receipt_with_policy(
        &receipt,
        TEST_KEY,
        epoch(5),
        &default_policy,
        Some(&mut nonce_registry),
    )
    .unwrap_err();
    assert!(matches!(err, ProofSchemaError::NonceReplay { .. }));
}

// ===========================================================================
// 6. RollbackToken validation
// ===========================================================================

#[test]
fn validate_rollback_token_valid_passes() {
    let token = signed_rollback();
    assert!(validate_rollback_token(&token, TEST_KEY, epoch(5)).is_ok());
}

#[test]
fn validate_rollback_token_wrong_key_returns_invalid_signature() {
    let token = signed_rollback();
    let err = validate_rollback_token(&token, WRONG_KEY, epoch(5)).unwrap_err();
    assert!(matches!(err, ProofSchemaError::InvalidSignature { .. }));
}

#[test]
fn validate_rollback_token_expired_returns_token_expired() {
    let token = signed_rollback();
    let err = validate_rollback_token(&token, TEST_KEY, epoch(21)).unwrap_err();
    assert!(matches!(err, ProofSchemaError::TokenExpired { .. }));
}

#[test]
fn validate_rollback_token_incompatible_version_returns_error() {
    let mut token = unsigned_rollback();
    token.schema_version = SchemaVersion::new(99, 0, 0);
    let token = token.sign(TEST_KEY);
    let err = validate_rollback_token(&token, TEST_KEY, epoch(5)).unwrap_err();
    assert!(matches!(err, ProofSchemaError::IncompatibleVersion { .. }));
}

#[test]
fn validate_rollback_token_missing_token_id() {
    let mut token = unsigned_rollback();
    token.token_id = String::new();
    let token = token.sign(TEST_KEY);
    let err = validate_rollback_token(&token, TEST_KEY, epoch(5)).unwrap_err();
    match err {
        ProofSchemaError::MissingField { field } => assert_eq!(field, "token_id"),
        other => panic!("expected MissingField, got: {other:?}"),
    }
}

#[test]
fn validate_rollback_token_missing_optimization_id() {
    let mut token = unsigned_rollback();
    token.optimization_id = String::new();
    let token = token.sign(TEST_KEY);
    let err = validate_rollback_token(&token, TEST_KEY, epoch(5)).unwrap_err();
    match err {
        ProofSchemaError::MissingField { field } => assert_eq!(field, "optimization_id"),
        other => panic!("expected MissingField, got: {other:?}"),
    }
}

// ===========================================================================
// 7. Signer authorization
// ===========================================================================

#[test]
fn optimizer_subsystem_authorized_for_opt_receipt() {
    assert!(check_signer_authorization(SignerRole::OptimizerSubsystem, "OptReceipt").is_ok());
}

#[test]
fn policy_plane_not_authorized_for_opt_receipt() {
    let err = check_signer_authorization(SignerRole::PolicyPlane, "OptReceipt").unwrap_err();
    assert!(matches!(err, ProofSchemaError::UnauthorizedSigner { .. }));
}

#[test]
fn policy_plane_authorized_for_rollback_token() {
    assert!(check_signer_authorization(SignerRole::PolicyPlane, "RollbackToken").is_ok());
}

#[test]
fn attestation_cell_not_authorized_for_opt_receipt() {
    let err = check_signer_authorization(SignerRole::AttestationCell, "OptReceipt").unwrap_err();
    assert!(matches!(err, ProofSchemaError::UnauthorizedSigner { .. }));
}

#[test]
fn unknown_artifact_returns_unauthorized_signer() {
    let err =
        check_signer_authorization(SignerRole::OptimizerSubsystem, "UnknownArtifact").unwrap_err();
    assert!(matches!(err, ProofSchemaError::UnauthorizedSigner { .. }));
}

#[test]
fn optimizer_subsystem_authorized_for_invariance_digest() {
    assert!(check_signer_authorization(SignerRole::OptimizerSubsystem, "InvarianceDigest").is_ok());
}

#[test]
fn optimizer_subsystem_authorized_for_rollback_token() {
    assert!(check_signer_authorization(SignerRole::OptimizerSubsystem, "RollbackToken").is_ok());
}

// ===========================================================================
// 8. Serde round-trips
// ===========================================================================

#[test]
fn serde_opt_receipt_without_attestation() {
    let receipt = signed_receipt();
    let json = serde_json::to_string(&receipt).expect("serialize");
    let restored: OptReceipt = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(receipt, restored);
}

#[test]
fn serde_opt_receipt_with_attestation() {
    let mut receipt = unsigned_receipt();
    receipt.decision_impact = DecisionImpact::HighImpact;
    receipt.attestation_bindings = Some(make_attestation_bindings());
    let receipt = receipt.sign(TEST_KEY);
    let json = serde_json::to_string(&receipt).expect("serialize");
    let restored: OptReceipt = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(receipt, restored);
    // Verify the attestation_bindings field survived.
    assert!(restored.attestation_bindings.is_some());
}

#[test]
fn serde_rollback_token() {
    let token = signed_rollback();
    let json = serde_json::to_string(&token).expect("serialize");
    let restored: RollbackToken = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(token, restored);
}

#[test]
fn serde_invariance_digest() {
    let digest = make_invariance_digest();
    let json = serde_json::to_string(&digest).expect("serialize");
    let restored: InvarianceDigest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(digest, restored);
}

#[test]
fn serde_proof_schema_error_variants() {
    let errors: Vec<ProofSchemaError> = vec![
        ProofSchemaError::InvalidSignature {
            artifact: "OptReceipt".to_string(),
        },
        ProofSchemaError::IncompatibleVersion {
            expected_major: 1,
            actual: SchemaVersion::new(2, 0, 0),
        },
        ProofSchemaError::TokenExpired {
            token_id: "rtk-1".to_string(),
            expiry_epoch: 10,
            current_epoch: 11,
        },
        ProofSchemaError::MissingField {
            field: "optimization_id".to_string(),
        },
        ProofSchemaError::NonEquivalent {
            reason: "diverged".to_string(),
        },
        ProofSchemaError::UnauthorizedSigner {
            role: SignerRole::PolicyPlane,
            artifact: "OptReceipt".to_string(),
        },
        ProofSchemaError::EpochMismatch {
            receipt_epoch: 5,
            current_epoch: 6,
        },
        ProofSchemaError::MissingAttestationBindings {
            impact: DecisionImpact::HighImpact,
        },
        ProofSchemaError::UnexpectedAttestationBindingsForVersion {
            schema_version: proof_schema_version_v1_0(),
        },
        ProofSchemaError::InvalidAttestationBindings {
            reason: "nonce is all zeros".to_string(),
        },
        ProofSchemaError::NonceReplay {
            attested_signer_key_id: signer_key_id(),
            nonce_hex: "aa".repeat(32),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let restored: ProofSchemaError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, restored);
    }
}

#[test]
fn serde_optimization_class_all_variants() {
    let variants = [
        OptimizationClass::Superinstruction,
        OptimizationClass::TraceSpecialization,
        OptimizationClass::LayoutSpecialization,
        OptimizationClass::DevirtualizedHostcallFastPath,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialize");
        let restored: OptimizationClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, restored);
    }
}

#[test]
fn serde_activation_stage_all_variants() {
    let variants = [
        ActivationStage::Shadow,
        ActivationStage::Canary,
        ActivationStage::Ramp,
        ActivationStage::Default,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialize");
        let restored: ActivationStage = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, restored);
    }
}

#[test]
fn serde_signer_role_all_variants() {
    let variants = [
        SignerRole::OptimizerSubsystem,
        SignerRole::PolicyPlane,
        SignerRole::AttestationCell,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialize");
        let restored: SignerRole = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, restored);
    }
}

#[test]
fn serde_receipt_attestation_bindings() {
    let bindings = make_attestation_bindings();
    let json = serde_json::to_string(&bindings).expect("serialize");
    let restored: ReceiptAttestationBindings = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(bindings, restored);
}

#[test]
fn serde_equivalence_verdict_all_variants() {
    let variants: Vec<EquivalenceVerdict> = vec![
        EquivalenceVerdict::Equivalent,
        EquivalenceVerdict::NonEquivalent {
            reason: "mismatch".to_string(),
        },
        EquivalenceVerdict::Inconclusive {
            reason: "timeout".to_string(),
        },
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialize");
        let restored: EquivalenceVerdict = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, restored);
    }
}

#[test]
fn serde_trace_comparison_methodology_all_variants() {
    let variants: Vec<TraceComparisonMethodology> = vec![
        TraceComparisonMethodology::DeterministicReplay,
        TraceComparisonMethodology::SymbolicEquivalence,
        TraceComparisonMethodology::StatisticalCorpus { corpus_size: 5000 },
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialize");
        let restored: TraceComparisonMethodology =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, restored);
    }
}

// ===========================================================================
// 9. Display traits
// ===========================================================================

#[test]
fn optimization_class_display_all_variants() {
    assert_eq!(
        OptimizationClass::Superinstruction.to_string(),
        "superinstruction"
    );
    assert_eq!(
        OptimizationClass::TraceSpecialization.to_string(),
        "trace_specialization"
    );
    assert_eq!(
        OptimizationClass::LayoutSpecialization.to_string(),
        "layout_specialization"
    );
    assert_eq!(
        OptimizationClass::DevirtualizedHostcallFastPath.to_string(),
        "devirtualized_hostcall_fast_path"
    );
}

#[test]
fn activation_stage_display_all_variants() {
    assert_eq!(ActivationStage::Shadow.to_string(), "shadow");
    assert_eq!(ActivationStage::Canary.to_string(), "canary");
    assert_eq!(ActivationStage::Ramp.to_string(), "ramp");
    assert_eq!(ActivationStage::Default.to_string(), "default");
}

#[test]
fn signer_role_display_all_variants() {
    assert_eq!(
        SignerRole::OptimizerSubsystem.to_string(),
        "optimizer_subsystem"
    );
    assert_eq!(SignerRole::PolicyPlane.to_string(), "policy_plane");
    assert_eq!(SignerRole::AttestationCell.to_string(), "attestation_cell");
}

#[test]
fn proof_schema_error_display_contains_relevant_info() {
    let err = ProofSchemaError::InvalidSignature {
        artifact: "OptReceipt".to_string(),
    };
    let display = err.to_string();
    assert!(display.contains("OptReceipt"), "display: {display}");
    assert!(display.contains("signature"), "display: {display}");

    let err = ProofSchemaError::TokenExpired {
        token_id: "rtk-42".to_string(),
        expiry_epoch: 10,
        current_epoch: 11,
    };
    let display = err.to_string();
    assert!(display.contains("rtk-42"), "display: {display}");
    assert!(display.contains("10"), "display: {display}");
    assert!(display.contains("11"), "display: {display}");

    let err = ProofSchemaError::MissingField {
        field: "optimization_id".to_string(),
    };
    let display = err.to_string();
    assert!(display.contains("optimization_id"), "display: {display}");
}

// ===========================================================================
// Additional coverage: edge cases and cross-cutting
// ===========================================================================

#[test]
fn receipt_nonce_registry_allows_different_nonces_same_signer() {
    let mut registry = ReceiptNonceRegistry::new();
    let key_id = signer_key_id();
    let nonce_a = [1u8; 32];
    let nonce_b = [2u8; 32];
    assert!(registry.check_and_record(&key_id, nonce_a).is_ok());
    assert!(registry.check_and_record(&key_id, nonce_b).is_ok());
}

#[test]
fn receipt_nonce_registry_allows_same_nonce_different_signers() {
    let mut registry = ReceiptNonceRegistry::new();
    let key_a = signer_key_id();
    let key_b = derive_id(
        ObjectDomain::CapabilityToken,
        "integ-zone",
        &SchemaId::from_definition(b"integ-signer-key"),
        b"key-b",
    )
    .expect("derive id");
    let nonce = [99u8; 32];
    assert!(registry.check_and_record(&key_a, nonce).is_ok());
    assert!(registry.check_and_record(&key_b, nonce).is_ok());
}

#[test]
fn attestation_requirement_policy_default() {
    let policy = AttestationRequirementPolicy::default();
    assert_eq!(policy.require_at_or_above, DecisionImpact::HighImpact);
    assert!(policy.allow_legacy_receipts_without_attestation);
}

#[test]
fn rollback_token_signing_preimage_is_deterministic() {
    let t1 = unsigned_rollback();
    let t2 = unsigned_rollback();
    assert_eq!(t1.signing_preimage(), t2.signing_preimage());
}

#[test]
fn rollback_token_different_stage_different_preimage() {
    let t1 = unsigned_rollback();
    let mut t2 = unsigned_rollback();
    t2.activation_stage = ActivationStage::Canary;
    assert_ne!(t1.signing_preimage(), t2.signing_preimage());
}

#[test]
fn receipt_changed_replay_compatibility_different_signature() {
    let r1 = signed_receipt();
    let mut r2 = unsigned_receipt();
    r2.replay_compatibility
        .insert("extra_key".to_string(), "extra_value".to_string());
    let r2 = r2.sign(TEST_KEY);
    assert_ne!(r1.signature, r2.signature);
}

#[test]
fn validate_receipt_at_boundary_epoch_passes() {
    // Receipt epoch equals current epoch: should pass.
    let receipt = signed_receipt();
    assert!(validate_receipt(&receipt, TEST_KEY, epoch(5)).is_ok());
}

#[test]
fn validate_rollback_token_at_boundary_epoch_passes() {
    // Token expiry_epoch = 20, current = 20 -> not expired (expiry is exclusive).
    let token = signed_rollback();
    assert!(validate_rollback_token(&token, TEST_KEY, epoch(20)).is_ok());
}
