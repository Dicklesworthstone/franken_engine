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

use frankenengine_engine::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::proof_schema::{
    AttestationRequirementPolicy, AttestationValidityWindow, OptReceipt, OptimizationClass,
    ProofSchemaError, ReceiptAttestationBindings, ReceiptNonceRegistry, SchemaVersion,
    SchemaVersionExt, proof_schema_version_current, proof_schema_version_v1_0,
    proof_schema_version_v1_1, validate_receipt, validate_receipt_with_policy,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::tee_attestation_policy::DecisionImpact;

const TEST_KEY: &[u8] = b"integration-signing-key-32-bytes!!";

fn signer_key_id() -> EngineObjectId {
    derive_id(
        ObjectDomain::KeyBundle,
        "integration-zone",
        &SchemaId::from_definition(b"integration-signer"),
        b"key-material",
    )
    .expect("derive signer key id")
}

fn measurement_id() -> EngineObjectId {
    derive_id(
        ObjectDomain::Attestation,
        "integration-zone",
        &SchemaId::from_definition(b"integration-measurement"),
        b"measurement-material",
    )
    .expect("derive measurement id")
}

fn base_receipt(schema_version: SchemaVersion, impact: DecisionImpact) -> OptReceipt {
    OptReceipt {
        schema_version,
        optimization_id: "opt-attested-1".to_string(),
        optimization_class: OptimizationClass::TraceSpecialization,
        baseline_ir_hash: ContentHash::compute(b"baseline-ir"),
        candidate_ir_hash: ContentHash::compute(b"candidate-ir"),
        translation_witness_hash: ContentHash::compute(b"translation-witness"),
        invariance_digest: ContentHash::compute(b"invariance-digest"),
        rollback_token_id: "rtk-attested-1".to_string(),
        replay_compatibility: BTreeMap::from([
            ("engine_version".to_string(), "0.1.0".to_string()),
            ("target_arch".to_string(), "x86_64".to_string()),
        ]),
        policy_epoch: SecurityEpoch::from_raw(42),
        timestamp_ticks: 1_000,
        signer_key_id: signer_key_id(),
        correlation_id: "corr-attested-1".to_string(),
        decision_impact: impact,
        attestation_bindings: None,
        signature: AuthenticityHash::compute(b"placeholder"),
    }
}

fn attestation_bindings() -> ReceiptAttestationBindings {
    ReceiptAttestationBindings {
        quote_digest: ContentHash::compute(b"full-tee-quote"),
        measurement_id: measurement_id(),
        attested_signer_key_id: signer_key_id(),
        nonce: [11u8; 32],
        validity_window: AttestationValidityWindow {
            start_timestamp_ticks: 900,
            end_timestamp_ticks: 1_500,
        },
    }
}

#[test]
fn attested_receipt_round_trip_through_transparency_log_and_verifier() {
    let mut receipt = base_receipt(proof_schema_version_current(), DecisionImpact::HighImpact);
    receipt.attestation_bindings = Some(attestation_bindings());
    let signed = receipt.sign(TEST_KEY);

    let transparency_log = [serde_json::to_vec(&signed).expect("serialize receipt")];

    let restored: OptReceipt =
        serde_json::from_slice(transparency_log.last().expect("entry")).expect("deserialize");
    let mut nonce_registry = ReceiptNonceRegistry::new();
    let result = validate_receipt_with_policy(
        &restored,
        TEST_KEY,
        SecurityEpoch::from_raw(42),
        &AttestationRequirementPolicy::default(),
        Some(&mut nonce_registry),
    );
    assert!(result.is_ok());
}

#[test]
fn verifier_rejects_tampered_attestation_binding() {
    let mut receipt = base_receipt(proof_schema_version_current(), DecisionImpact::HighImpact);
    receipt.attestation_bindings = Some(attestation_bindings());
    let mut signed = receipt.sign(TEST_KEY);
    signed.attestation_bindings.as_mut().unwrap().quote_digest = ContentHash::compute(b"tampered");

    assert!(matches!(
        validate_receipt_with_policy(
            &signed,
            TEST_KEY,
            SecurityEpoch::from_raw(42),
            &AttestationRequirementPolicy::default(),
            None,
        ),
        Err(ProofSchemaError::InvalidSignature { .. })
    ));
}

#[test]
fn legacy_format_receipt_parseable_and_distinguishable() {
    let legacy = base_receipt(proof_schema_version_v1_0(), DecisionImpact::Standard).sign(TEST_KEY);
    let mut legacy_json_value = serde_json::to_value(&legacy).expect("to value");
    let serde_json::Value::Object(ref mut map) = legacy_json_value else {
        panic!("expected object");
    };
    map.remove("decision_impact");
    map.remove("attestation_bindings");
    let legacy_json = serde_json::to_string(&legacy_json_value).expect("to json");

    let parsed_legacy: OptReceipt = serde_json::from_str(&legacy_json).expect("parse legacy");
    assert_eq!(parsed_legacy.schema_version, proof_schema_version_v1_0());
    assert_eq!(parsed_legacy.decision_impact, DecisionImpact::Standard);
    assert!(parsed_legacy.attestation_bindings.is_none());
    assert!(validate_receipt(&parsed_legacy, TEST_KEY, SecurityEpoch::from_raw(42)).is_ok());

    let mut attested = base_receipt(proof_schema_version_current(), DecisionImpact::HighImpact);
    attested.attestation_bindings = Some(attestation_bindings());
    let attested = attested.sign(TEST_KEY);
    assert_ne!(parsed_legacy.schema_version, attested.schema_version);
    assert!(attested.attestation_bindings.is_some());
}

#[test]
fn serialization_is_byte_identical_for_identical_inputs() {
    let mut receipt = base_receipt(proof_schema_version_current(), DecisionImpact::HighImpact);
    receipt.attestation_bindings = Some(attestation_bindings());
    let signed = receipt.sign(TEST_KEY);

    let a = serde_json::to_vec(&signed).expect("serialize");
    let b = serde_json::to_vec(&signed).expect("serialize");
    assert_eq!(a, b);
}

// ---------- nonce replay detection ----------

#[test]
fn nonce_registry_rejects_replay_of_same_nonce() {
    let mut receipt = base_receipt(proof_schema_version_current(), DecisionImpact::HighImpact);
    receipt.attestation_bindings = Some(attestation_bindings());
    let signed = receipt.sign(TEST_KEY);

    let mut nonce_registry = ReceiptNonceRegistry::new();
    let result1 = validate_receipt_with_policy(
        &signed,
        TEST_KEY,
        SecurityEpoch::from_raw(42),
        &AttestationRequirementPolicy::default(),
        Some(&mut nonce_registry),
    );
    assert!(result1.is_ok());

    let result2 = validate_receipt_with_policy(
        &signed,
        TEST_KEY,
        SecurityEpoch::from_raw(42),
        &AttestationRequirementPolicy::default(),
        Some(&mut nonce_registry),
    );
    assert!(matches!(result2, Err(ProofSchemaError::NonceReplay { .. })));
}

// ---------- epoch mismatch ----------

#[test]
fn receipt_verification_rejects_wrong_epoch() {
    let receipt =
        base_receipt(proof_schema_version_current(), DecisionImpact::Standard).sign(TEST_KEY);
    let result = validate_receipt(&receipt, TEST_KEY, SecurityEpoch::from_raw(99));
    assert!(matches!(
        result,
        Err(ProofSchemaError::EpochMismatch { .. })
    ));
}

// ---------- invalid signature ----------

#[test]
fn receipt_verification_rejects_wrong_key() {
    let receipt =
        base_receipt(proof_schema_version_current(), DecisionImpact::Standard).sign(TEST_KEY);
    let wrong_key = b"wrong-integration-signing-key!!!!";
    let result = validate_receipt(&receipt, wrong_key, SecurityEpoch::from_raw(42));
    assert!(matches!(
        result,
        Err(ProofSchemaError::InvalidSignature { .. })
    ));
}

// ---------- attestation requirement policy ----------

#[test]
fn high_impact_without_attestation_bindings_rejected_by_default_policy() {
    let receipt =
        base_receipt(proof_schema_version_current(), DecisionImpact::HighImpact).sign(TEST_KEY);
    assert!(receipt.attestation_bindings.is_none());

    let result = validate_receipt_with_policy(
        &receipt,
        TEST_KEY,
        SecurityEpoch::from_raw(42),
        &AttestationRequirementPolicy::default(),
        None,
    );
    assert!(matches!(
        result,
        Err(ProofSchemaError::MissingAttestationBindings { .. })
    ));
}

#[test]
fn standard_impact_does_not_require_attestation_bindings() {
    let receipt =
        base_receipt(proof_schema_version_current(), DecisionImpact::Standard).sign(TEST_KEY);
    let result = validate_receipt_with_policy(
        &receipt,
        TEST_KEY,
        SecurityEpoch::from_raw(42),
        &AttestationRequirementPolicy::default(),
        None,
    );
    assert!(result.is_ok());
}

// ---------- schema version ----------

#[test]
fn v1_0_and_current_are_different_versions() {
    assert_ne!(proof_schema_version_v1_0(), proof_schema_version_current());
}

#[test]
fn current_receipt_validates_with_current_epoch() {
    let receipt =
        base_receipt(proof_schema_version_current(), DecisionImpact::Standard).sign(TEST_KEY);
    assert!(validate_receipt(&receipt, TEST_KEY, SecurityEpoch::from_raw(42)).is_ok());
}

// ---------- optimization class ----------

#[test]
fn optimization_class_display_is_nonempty() {
    for class in [
        OptimizationClass::Superinstruction,
        OptimizationClass::TraceSpecialization,
        OptimizationClass::LayoutSpecialization,
        OptimizationClass::DevirtualizedHostcallFastPath,
    ] {
        assert!(!class.to_string().is_empty());
    }
}

// ---------- receipt object id ----------

#[test]
fn receipt_object_id_is_deterministic() {
    let receipt =
        base_receipt(proof_schema_version_current(), DecisionImpact::Standard).sign(TEST_KEY);
    let id_a = receipt.object_id("integration-zone").expect("object id");
    let id_b = receipt.object_id("integration-zone").expect("object id");
    assert_eq!(id_a, id_b);
}

#[test]
fn receipt_verify_signature_validates_correct_key() {
    let receipt =
        base_receipt(proof_schema_version_current(), DecisionImpact::Standard).sign(TEST_KEY);
    assert!(receipt.verify_signature(TEST_KEY));
}

#[test]
fn receipt_verify_signature_rejects_wrong_key() {
    let receipt =
        base_receipt(proof_schema_version_current(), DecisionImpact::Standard).sign(TEST_KEY);
    assert!(!receipt.verify_signature(b"wrong-key-32-bytes-integration!!"));
}

// ---------- attestation validity window ----------

#[test]
fn validity_window_has_correct_bounds() {
    let window = AttestationValidityWindow {
        start_timestamp_ticks: 900,
        end_timestamp_ticks: 1_500,
    };
    assert_eq!(window.start_timestamp_ticks, 900);
    assert_eq!(window.end_timestamp_ticks, 1_500);
}

#[test]
fn validity_window_serde_roundtrip() {
    let window = AttestationValidityWindow {
        start_timestamp_ticks: 100,
        end_timestamp_ticks: 200,
    };
    let json = serde_json::to_string(&window).expect("serialize");
    let recovered: AttestationValidityWindow = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.start_timestamp_ticks, 100);
    assert_eq!(recovered.end_timestamp_ticks, 200);
}

// ---------- serde roundtrip ----------

#[test]
fn attestation_bindings_serde_roundtrip() {
    let bindings = attestation_bindings();
    let json = serde_json::to_string(&bindings).expect("serialize");
    let recovered: ReceiptAttestationBindings = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.nonce, bindings.nonce);
    assert_eq!(recovered.measurement_id, bindings.measurement_id);
}

#[test]
fn opt_receipt_full_serde_roundtrip() {
    let mut receipt = base_receipt(proof_schema_version_current(), DecisionImpact::HighImpact);
    receipt.attestation_bindings = Some(attestation_bindings());
    let signed = receipt.sign(TEST_KEY);

    let json = serde_json::to_string(&signed).expect("serialize");
    let recovered: OptReceipt = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.optimization_id, signed.optimization_id);
    assert_eq!(recovered.schema_version, signed.schema_version);
    assert_eq!(recovered.signature, signed.signature);
    assert!(recovered.attestation_bindings.is_some());
}

#[test]
fn optimization_class_serde_roundtrip() {
    for class in [
        OptimizationClass::Superinstruction,
        OptimizationClass::TraceSpecialization,
    ] {
        let json = serde_json::to_string(&class).expect("serialize");
        let recovered: OptimizationClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, class);
    }
}

#[test]
fn proof_schema_version_v1_is_nonempty() {
    let v = proof_schema_version_v1_0();
    let json = serde_json::to_string(&v).expect("serialize");
    assert!(!json.is_empty());
}

#[test]
fn proof_schema_error_display_is_nonempty() {
    let err = ProofSchemaError::InvalidSignature {
        artifact: "test-artifact".to_string(),
    };
    let msg = format!("{err}");
    assert!(!msg.trim().is_empty());
}

// ---------- empty replay_compatibility ----------

#[test]
fn receipt_with_empty_replay_compatibility_validates() {
    let mut receipt = base_receipt(proof_schema_version_current(), DecisionImpact::Standard);
    receipt.replay_compatibility = BTreeMap::new();
    let signed = receipt.sign(TEST_KEY);
    assert!(validate_receipt(&signed, TEST_KEY, SecurityEpoch::from_raw(42)).is_ok());
}

#[test]
fn empty_replay_compatibility_produces_different_signature_from_nonempty() {
    let mut receipt_empty = base_receipt(proof_schema_version_current(), DecisionImpact::Standard);
    receipt_empty.replay_compatibility = BTreeMap::new();
    let signed_empty = receipt_empty.sign(TEST_KEY);

    let signed_nonempty =
        base_receipt(proof_schema_version_current(), DecisionImpact::Standard).sign(TEST_KEY);

    assert_ne!(signed_empty.signature, signed_nonempty.signature);
}

// ---------- nonce registry with multiple unique nonces ----------

#[test]
fn nonce_registry_accepts_multiple_unique_nonces() {
    let mut nonce_registry = ReceiptNonceRegistry::new();
    let epoch = SecurityEpoch::from_raw(42);
    let policy = AttestationRequirementPolicy::default();

    for i in 0u8..5 {
        let mut receipt = base_receipt(proof_schema_version_current(), DecisionImpact::HighImpact);
        receipt.optimization_id = format!("opt-nonce-{i}");
        receipt.correlation_id = format!("corr-nonce-{i}");
        let mut bindings = attestation_bindings();
        bindings.nonce = [10 + i; 32];
        receipt.attestation_bindings = Some(bindings);
        let signed = receipt.sign(TEST_KEY);

        let result = validate_receipt_with_policy(
            &signed,
            TEST_KEY,
            epoch,
            &policy,
            Some(&mut nonce_registry),
        );
        assert!(result.is_ok(), "nonce {i} should be accepted");
    }
}

// ---------- different nonces produce different quote digests ----------

#[test]
fn different_nonces_produce_different_signing_preimages() {
    let mut receipt_a = base_receipt(proof_schema_version_current(), DecisionImpact::HighImpact);
    let mut bindings_a = attestation_bindings();
    bindings_a.nonce = [0xAA; 32];
    receipt_a.attestation_bindings = Some(bindings_a);

    let mut receipt_b = base_receipt(proof_schema_version_current(), DecisionImpact::HighImpact);
    let mut bindings_b = attestation_bindings();
    bindings_b.nonce = [0xBB; 32];
    receipt_b.attestation_bindings = Some(bindings_b);

    assert_ne!(receipt_a.signing_preimage(), receipt_b.signing_preimage());

    let signed_a = receipt_a.sign(TEST_KEY);
    let signed_b = receipt_b.sign(TEST_KEY);
    assert_ne!(signed_a.signature, signed_b.signature);
}

// ---------- end-to-end: HighImpact + attestation + nonce registry ----------

#[test]
fn end_to_end_high_impact_attested_nonce_tracked_receipt() {
    let mut receipt = base_receipt(proof_schema_version_current(), DecisionImpact::HighImpact);
    receipt.attestation_bindings = Some(attestation_bindings());
    let signed = receipt.sign(TEST_KEY);

    let mut nonce_registry = ReceiptNonceRegistry::new();
    let policy = AttestationRequirementPolicy {
        require_at_or_above: DecisionImpact::HighImpact,
        allow_legacy_receipts_without_attestation: false,
    };

    // First validation succeeds.
    let result = validate_receipt_with_policy(
        &signed,
        TEST_KEY,
        SecurityEpoch::from_raw(42),
        &policy,
        Some(&mut nonce_registry),
    );
    assert!(result.is_ok());

    // Replay is caught.
    let replay = validate_receipt_with_policy(
        &signed,
        TEST_KEY,
        SecurityEpoch::from_raw(42),
        &policy,
        Some(&mut nonce_registry),
    );
    assert!(matches!(replay, Err(ProofSchemaError::NonceReplay { .. })));
}

// ---------- multiple optimization classes validate independently ----------

#[test]
fn multiple_optimization_classes_validate_independently() {
    let classes = [
        OptimizationClass::Superinstruction,
        OptimizationClass::TraceSpecialization,
        OptimizationClass::LayoutSpecialization,
        OptimizationClass::DevirtualizedHostcallFastPath,
    ];

    for (idx, class) in classes.iter().enumerate() {
        let mut receipt = base_receipt(proof_schema_version_current(), DecisionImpact::Standard);
        receipt.optimization_class = class.clone();
        receipt.optimization_id = format!("opt-class-{idx}");
        receipt.correlation_id = format!("corr-class-{idx}");
        let signed = receipt.sign(TEST_KEY);

        assert!(
            validate_receipt(&signed, TEST_KEY, SecurityEpoch::from_raw(42)).is_ok(),
            "optimization class {class} should validate"
        );
    }
}

// ---------- receipt object_id changes based on zone ----------

#[test]
fn receipt_object_id_changes_with_zone() {
    let receipt =
        base_receipt(proof_schema_version_current(), DecisionImpact::Standard).sign(TEST_KEY);
    let id_zone_a = receipt.object_id("zone-alpha").expect("object id");
    let id_zone_b = receipt.object_id("zone-beta").expect("object id");
    assert_ne!(id_zone_a, id_zone_b);
}

// ---------- schema version current serde roundtrip ----------

#[test]
fn schema_version_current_serde_roundtrip() {
    let version = proof_schema_version_current();
    let json = serde_json::to_string(&version).expect("serialize");
    let recovered: SchemaVersion = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, version);
}

#[test]
fn schema_version_v1_1_supports_attestation_bindings() {
    let v1_1 = proof_schema_version_v1_1();
    assert!(v1_1.supports_attestation_bindings());

    let v1_0 = proof_schema_version_v1_0();
    assert!(!v1_0.supports_attestation_bindings());
}

// ---------- DecisionImpact serde roundtrip for all variants ----------

#[test]
fn decision_impact_serde_roundtrip_all_variants() {
    for impact in [DecisionImpact::Standard, DecisionImpact::HighImpact] {
        let json = serde_json::to_string(&impact).expect("serialize");
        let recovered: DecisionImpact = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, impact);
    }
}

// ---------- policy with require_attestation=false allows HighImpact without bindings ----------

#[test]
fn permissive_policy_allows_high_impact_without_bindings() {
    let receipt =
        base_receipt(proof_schema_version_current(), DecisionImpact::HighImpact).sign(TEST_KEY);
    assert!(receipt.attestation_bindings.is_none());

    // Default policy rejects this — confirmed as precondition.
    let strict_result = validate_receipt_with_policy(
        &receipt,
        TEST_KEY,
        SecurityEpoch::from_raw(42),
        &AttestationRequirementPolicy::default(),
        None,
    );
    assert!(strict_result.is_err());

    // Permissive policy: raise the threshold above HighImpact so nothing
    // needs attestation. Since DecisionImpact only has Standard and HighImpact,
    // and HighImpact is the max, we use a policy that does NOT require above HighImpact
    // by setting the legacy flag. Instead, we set allow_legacy to true and use v1.0.
    let mut receipt_v1 = base_receipt(proof_schema_version_v1_0(), DecisionImpact::HighImpact);
    receipt_v1.attestation_bindings = None;
    let signed_v1 = receipt_v1.sign(TEST_KEY);

    let legacy_policy = AttestationRequirementPolicy {
        require_at_or_above: DecisionImpact::HighImpact,
        allow_legacy_receipts_without_attestation: true,
    };
    let result = validate_receipt_with_policy(
        &signed_v1,
        TEST_KEY,
        SecurityEpoch::from_raw(42),
        &legacy_policy,
        None,
    );
    assert!(
        result.is_ok(),
        "legacy policy should allow v1.0 HighImpact without bindings"
    );
}

// ---------- signed receipt verify_signature is false after field mutation ----------

#[test]
fn verify_signature_fails_after_optimization_id_mutation() {
    let signed =
        base_receipt(proof_schema_version_current(), DecisionImpact::Standard).sign(TEST_KEY);
    assert!(signed.verify_signature(TEST_KEY));

    let mut tampered = signed.clone();
    tampered.optimization_id = "tampered-id".to_string();
    assert!(!tampered.verify_signature(TEST_KEY));
}

#[test]
fn verify_signature_fails_after_timestamp_mutation() {
    let signed =
        base_receipt(proof_schema_version_current(), DecisionImpact::Standard).sign(TEST_KEY);
    assert!(signed.verify_signature(TEST_KEY));

    let mut tampered = signed.clone();
    tampered.timestamp_ticks = 9999;
    assert!(!tampered.verify_signature(TEST_KEY));
}

// ---------- all-zero nonce rejected ----------

#[test]
fn all_zero_nonce_rejected_during_validation() {
    let mut receipt = base_receipt(proof_schema_version_current(), DecisionImpact::HighImpact);
    let mut bindings = attestation_bindings();
    bindings.nonce = [0u8; 32];
    receipt.attestation_bindings = Some(bindings);
    let signed = receipt.sign(TEST_KEY);

    let result = validate_receipt_with_policy(
        &signed,
        TEST_KEY,
        SecurityEpoch::from_raw(42),
        &AttestationRequirementPolicy::default(),
        None,
    );
    assert!(matches!(
        result,
        Err(ProofSchemaError::InvalidAttestationBindings { .. })
    ));
}
