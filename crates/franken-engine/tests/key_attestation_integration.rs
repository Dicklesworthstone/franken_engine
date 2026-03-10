#![forbid(unsafe_code)]
//! Integration tests for the `key_attestation` module.
//!
//! Exercises all public types, enums, struct fields, methods, error paths,
//! serde round-trips, Display impls, and deterministic replay from outside
//! the crate boundary.

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

use frankenengine_engine::capability_token::PrincipalId;
use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::key_attestation::{
    AttestationError, AttestationEvent, AttestationEventType, AttestationNonce, AttestationStore,
    CreateAttestationInput, DevicePosture, KeyAttestation, NonceRegistry, attestation_schema,
    attestation_schema_id,
};
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::principal_key_roles::KeyRole;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{SigningKey, VerificationKey};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TEST_ZONE: &str = "test-zone";

fn owner_signing_key() -> SigningKey {
    SigningKey::from_bytes([0x01; 32])
}

fn owner_vk() -> VerificationKey {
    owner_signing_key().verification_key()
}

fn attested_signing_key() -> SigningKey {
    SigningKey::from_bytes([0x02; 32])
}

fn attested_vk() -> VerificationKey {
    attested_signing_key().verification_key()
}

fn test_principal() -> PrincipalId {
    PrincipalId::from_verification_key(&owner_vk())
}

fn create_test_attestation(
    role: KeyRole,
    nonce: u64,
    issued_at: u64,
    expires_at: u64,
) -> KeyAttestation {
    KeyAttestation::create_signed(
        &owner_signing_key(),
        CreateAttestationInput {
            principal_id: test_principal(),
            attested_key: attested_vk(),
            key_role: role,
            issued_at: DeterministicTimestamp(issued_at),
            expires_at: DeterministicTimestamp(expires_at),
            epoch: SecurityEpoch::from_raw(1),
            nonce: AttestationNonce::from_counter(nonce),
            device_posture: None,
            zone: TEST_ZONE,
        },
    )
    .expect("create test attestation")
}

fn create_attestation_with_posture(
    role: KeyRole,
    nonce: u64,
    posture_type: &str,
    evidence: Vec<u8>,
) -> KeyAttestation {
    KeyAttestation::create_signed(
        &owner_signing_key(),
        CreateAttestationInput {
            principal_id: test_principal(),
            attested_key: attested_vk(),
            key_role: role,
            issued_at: DeterministicTimestamp(100),
            expires_at: DeterministicTimestamp(500),
            epoch: SecurityEpoch::from_raw(1),
            nonce: AttestationNonce::from_counter(nonce),
            device_posture: Some(DevicePosture {
                posture_type: posture_type.to_string(),
                evidence,
            }),
            zone: TEST_ZONE,
        },
    )
    .expect("create with posture")
}

// ===========================================================================
// Section 1: Schema Functions
// ===========================================================================

#[test]
fn attestation_schema_deterministic() {
    let s1 = attestation_schema();
    let s2 = attestation_schema();
    assert_eq!(s1, s2);
}

#[test]
fn attestation_schema_id_deterministic() {
    let s1 = attestation_schema_id();
    let s2 = attestation_schema_id();
    assert_eq!(s1, s2);
}

// ===========================================================================
// Section 2: AttestationNonce
// ===========================================================================

#[test]
fn nonce_from_counter_and_back() {
    let nonce = AttestationNonce::from_counter(42);
    assert_eq!(nonce.as_u64(), 42);
}

#[test]
fn nonce_zero() {
    let nonce = AttestationNonce::from_counter(0);
    assert_eq!(nonce.as_u64(), 0);
}

#[test]
fn nonce_max() {
    let nonce = AttestationNonce::from_counter(u64::MAX);
    assert_eq!(nonce.as_u64(), u64::MAX);
}

#[test]
fn nonce_equality() {
    let a = AttestationNonce::from_counter(10);
    let b = AttestationNonce::from_counter(10);
    assert_eq!(a, b);
}

#[test]
fn nonce_inequality() {
    let a = AttestationNonce::from_counter(10);
    let b = AttestationNonce::from_counter(11);
    assert_ne!(a, b);
}

#[test]
fn nonce_ordering() {
    let a = AttestationNonce::from_counter(5);
    let b = AttestationNonce::from_counter(10);
    assert!(a < b);
}

#[test]
fn nonce_display() {
    let nonce = AttestationNonce::from_counter(42);
    assert_eq!(nonce.to_string(), "nonce:42");
}

#[test]
fn nonce_display_zero() {
    let nonce = AttestationNonce::from_counter(0);
    assert_eq!(nonce.to_string(), "nonce:0");
}

#[test]
fn nonce_serde_roundtrip() {
    let nonce = AttestationNonce::from_counter(12345);
    let json = serde_json::to_string(&nonce).unwrap();
    let deser: AttestationNonce = serde_json::from_str(&json).unwrap();
    assert_eq!(nonce, deser);
}

// ===========================================================================
// Section 3: DevicePosture
// ===========================================================================

#[test]
fn device_posture_construction() {
    let posture = DevicePosture {
        posture_type: "tpm2".to_string(),
        evidence: vec![0xDE, 0xAD, 0xBE, 0xEF],
    };
    assert_eq!(posture.posture_type, "tpm2");
    assert_eq!(posture.evidence, vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn device_posture_serde_roundtrip() {
    let posture = DevicePosture {
        posture_type: "sgx".to_string(),
        evidence: vec![0x01, 0x02, 0x03],
    };
    let json = serde_json::to_string(&posture).unwrap();
    let deser: DevicePosture = serde_json::from_str(&json).unwrap();
    assert_eq!(posture, deser);
}

#[test]
fn device_posture_empty_evidence() {
    let posture = DevicePosture {
        posture_type: "none".to_string(),
        evidence: vec![],
    };
    let json = serde_json::to_string(&posture).unwrap();
    let deser: DevicePosture = serde_json::from_str(&json).unwrap();
    assert_eq!(posture, deser);
}

#[test]
fn device_posture_equality() {
    let a = DevicePosture {
        posture_type: "tpm2".to_string(),
        evidence: vec![0x01],
    };
    let b = DevicePosture {
        posture_type: "tpm2".to_string(),
        evidence: vec![0x01],
    };
    assert_eq!(a, b);
}

#[test]
fn device_posture_inequality_type() {
    let a = DevicePosture {
        posture_type: "tpm2".to_string(),
        evidence: vec![0x01],
    };
    let b = DevicePosture {
        posture_type: "sgx".to_string(),
        evidence: vec![0x01],
    };
    assert_ne!(a, b);
}

#[test]
fn device_posture_inequality_evidence() {
    let a = DevicePosture {
        posture_type: "tpm2".to_string(),
        evidence: vec![0x01],
    };
    let b = DevicePosture {
        posture_type: "tpm2".to_string(),
        evidence: vec![0x02],
    };
    assert_ne!(a, b);
}

// ===========================================================================
// Section 4: KeyAttestation Creation
// ===========================================================================

#[test]
fn create_attestation_basic_fields() {
    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    assert_eq!(att.key_role, KeyRole::Signing);
    assert_eq!(att.principal_id, test_principal());
    assert_eq!(att.attested_key, attested_vk());
    assert_eq!(att.nonce, AttestationNonce::from_counter(1));
    assert_eq!(att.zone, TEST_ZONE);
    assert_eq!(att.issued_at, DeterministicTimestamp(100));
    assert_eq!(att.expires_at, DeterministicTimestamp(200));
    assert_eq!(att.epoch, SecurityEpoch::from_raw(1));
    assert!(att.device_posture.is_none());
}

#[test]
fn create_attestation_for_each_role() {
    for role in KeyRole::ALL {
        let att = create_test_attestation(*role, 1, 100, 200);
        assert_eq!(att.key_role, *role);
    }
}

#[test]
fn create_attestation_deterministic_id() {
    let att1 = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    let att2 = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    assert_eq!(att1.attestation_id, att2.attestation_id);
}

#[test]
fn create_attestation_deterministic_signature() {
    let att1 = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    let att2 = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    assert_eq!(att1.owner_signature, att2.owner_signature);
}

#[test]
fn create_attestation_different_roles_different_ids() {
    let att_sign = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    let att_enc = create_test_attestation(KeyRole::Encryption, 1, 100, 200);
    let att_iss = create_test_attestation(KeyRole::Issuance, 1, 100, 200);
    assert_ne!(att_sign.attestation_id, att_enc.attestation_id);
    assert_ne!(att_sign.attestation_id, att_iss.attestation_id);
    assert_ne!(att_enc.attestation_id, att_iss.attestation_id);
}

#[test]
fn create_attestation_different_nonces_different_ids() {
    let att1 = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    let att2 = create_test_attestation(KeyRole::Signing, 2, 100, 200);
    assert_ne!(att1.attestation_id, att2.attestation_id);
}

#[test]
fn create_attestation_with_device_posture() {
    let att = create_attestation_with_posture(KeyRole::Signing, 1, "tpm2", vec![0xDE, 0xAD]);
    assert!(att.device_posture.is_some());
    let posture = att.device_posture.unwrap();
    assert_eq!(posture.posture_type, "tpm2");
    assert_eq!(posture.evidence, vec![0xDE, 0xAD]);
}

#[test]
fn device_posture_changes_signature() {
    let att_no = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    let att_with = create_attestation_with_posture(KeyRole::Signing, 1, "sgx", vec![0x01]);
    assert_ne!(att_no.owner_signature, att_with.owner_signature);
}

// ===========================================================================
// Section 5: Self-Attestation Rejection
// ===========================================================================

#[test]
fn self_attestation_rejected_on_creation() {
    let sk = owner_signing_key();
    let vk = sk.verification_key();
    let result = KeyAttestation::create_signed(
        &sk,
        CreateAttestationInput {
            principal_id: test_principal(),
            attested_key: vk, // Same as owner key
            key_role: KeyRole::Signing,
            issued_at: DeterministicTimestamp(100),
            expires_at: DeterministicTimestamp(200),
            epoch: SecurityEpoch::from_raw(1),
            nonce: AttestationNonce::from_counter(1),
            device_posture: None,
            zone: TEST_ZONE,
        },
    );
    assert!(matches!(
        result,
        Err(AttestationError::SelfAttestationRejected)
    ));
}

#[test]
fn self_attestation_rejected_on_verify() {
    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    let result = att.verify_owner_signature(&attested_vk());
    assert!(matches!(
        result,
        Err(AttestationError::SelfAttestationRejected)
    ));
}

// ===========================================================================
// Section 6: Expiry Validation
// ===========================================================================

#[test]
fn invalid_expiry_rejected_expires_before_issued() {
    let result = KeyAttestation::create_signed(
        &owner_signing_key(),
        CreateAttestationInput {
            principal_id: test_principal(),
            attested_key: attested_vk(),
            key_role: KeyRole::Signing,
            issued_at: DeterministicTimestamp(200),
            expires_at: DeterministicTimestamp(100),
            epoch: SecurityEpoch::from_raw(1),
            nonce: AttestationNonce::from_counter(1),
            device_posture: None,
            zone: TEST_ZONE,
        },
    );
    assert!(matches!(
        result,
        Err(AttestationError::InvalidExpiry { .. })
    ));
}

#[test]
fn invalid_expiry_rejected_equal_timestamps() {
    let result = KeyAttestation::create_signed(
        &owner_signing_key(),
        CreateAttestationInput {
            principal_id: test_principal(),
            attested_key: attested_vk(),
            key_role: KeyRole::Signing,
            issued_at: DeterministicTimestamp(100),
            expires_at: DeterministicTimestamp(100),
            epoch: SecurityEpoch::from_raw(1),
            nonce: AttestationNonce::from_counter(1),
            device_posture: None,
            zone: TEST_ZONE,
        },
    );
    assert!(matches!(
        result,
        Err(AttestationError::InvalidExpiry { .. })
    ));
}

#[test]
fn is_expired_before_expiry() {
    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    assert!(!att.is_expired(DeterministicTimestamp(150)));
    assert!(!att.is_expired(DeterministicTimestamp(199)));
}

#[test]
fn is_expired_at_expiry() {
    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    assert!(att.is_expired(DeterministicTimestamp(200)));
}

#[test]
fn is_expired_after_expiry() {
    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    assert!(att.is_expired(DeterministicTimestamp(201)));
    assert!(att.is_expired(DeterministicTimestamp(u64::MAX)));
}

#[test]
fn is_expired_at_zero() {
    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    assert!(!att.is_expired(DeterministicTimestamp(0)));
}

// ===========================================================================
// Section 7: Signature Verification
// ===========================================================================

#[test]
fn verify_owner_signature_succeeds() {
    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    att.verify_owner_signature(&owner_vk())
        .expect("valid signature");
}

#[test]
fn verify_owner_signature_wrong_key_fails() {
    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    let wrong_sk = SigningKey::from_bytes([0xFF; 32]);
    let wrong_vk = wrong_sk.verification_key();
    let result = att.verify_owner_signature(&wrong_vk);
    assert!(matches!(
        result,
        Err(AttestationError::SignatureInvalid { .. })
    ));
}

#[test]
fn verify_signature_with_device_posture() {
    let att = create_attestation_with_posture(KeyRole::Signing, 1, "tpm2", vec![0x01, 0x02]);
    att.verify_owner_signature(&owner_vk())
        .expect("valid with posture");
}

#[test]
fn verify_signature_for_all_roles() {
    for role in KeyRole::ALL {
        let att = create_test_attestation(*role, 1, 100, 200);
        att.verify_owner_signature(&owner_vk())
            .expect("valid for role");
    }
}

// ===========================================================================
// Section 8: Derive Attestation ID
// ===========================================================================

#[test]
fn derive_attestation_id_deterministic() {
    let id1 = KeyAttestation::derive_attestation_id(
        &test_principal(),
        &attested_vk(),
        KeyRole::Signing,
        AttestationNonce::from_counter(1),
        TEST_ZONE,
    )
    .unwrap();
    let id2 = KeyAttestation::derive_attestation_id(
        &test_principal(),
        &attested_vk(),
        KeyRole::Signing,
        AttestationNonce::from_counter(1),
        TEST_ZONE,
    )
    .unwrap();
    assert_eq!(id1, id2);
}

#[test]
fn derive_attestation_id_different_nonce() {
    let id1 = KeyAttestation::derive_attestation_id(
        &test_principal(),
        &attested_vk(),
        KeyRole::Signing,
        AttestationNonce::from_counter(1),
        TEST_ZONE,
    )
    .unwrap();
    let id2 = KeyAttestation::derive_attestation_id(
        &test_principal(),
        &attested_vk(),
        KeyRole::Signing,
        AttestationNonce::from_counter(2),
        TEST_ZONE,
    )
    .unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn derive_attestation_id_different_zone() {
    let id1 = KeyAttestation::derive_attestation_id(
        &test_principal(),
        &attested_vk(),
        KeyRole::Signing,
        AttestationNonce::from_counter(1),
        "zone-a",
    )
    .unwrap();
    let id2 = KeyAttestation::derive_attestation_id(
        &test_principal(),
        &attested_vk(),
        KeyRole::Signing,
        AttestationNonce::from_counter(1),
        "zone-b",
    )
    .unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn derive_attestation_id_different_role() {
    let id1 = KeyAttestation::derive_attestation_id(
        &test_principal(),
        &attested_vk(),
        KeyRole::Signing,
        AttestationNonce::from_counter(1),
        TEST_ZONE,
    )
    .unwrap();
    let id2 = KeyAttestation::derive_attestation_id(
        &test_principal(),
        &attested_vk(),
        KeyRole::Encryption,
        AttestationNonce::from_counter(1),
        TEST_ZONE,
    )
    .unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn attestation_id_hex_roundtrip() {
    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    let hex = att.attestation_id.to_hex();
    let recovered = EngineObjectId::from_hex(&hex).expect("from_hex");
    assert_eq!(att.attestation_id, recovered);
}

// ===========================================================================
// Section 9: NonceRegistry
// ===========================================================================

#[test]
fn nonce_registry_new_is_empty() {
    let registry = NonceRegistry::new();
    assert_eq!(registry.principal_count(), 0);
    assert_eq!(registry.high_water_for(&test_principal()), 0);
}

#[test]
fn nonce_registry_default_is_new() {
    let registry = NonceRegistry::default();
    assert_eq!(registry.principal_count(), 0);
}

#[test]
fn nonce_registry_accepts_first_nonce() {
    let mut registry = NonceRegistry::new();
    registry
        .check_and_record(&test_principal(), AttestationNonce::from_counter(1))
        .expect("first nonce");
    assert_eq!(registry.high_water_for(&test_principal()), 1);
    assert_eq!(registry.principal_count(), 1);
}

#[test]
fn nonce_registry_accepts_monotonic_increase() {
    let mut registry = NonceRegistry::new();
    for i in 1..=5 {
        registry
            .check_and_record(&test_principal(), AttestationNonce::from_counter(i))
            .unwrap_or_else(|_| panic!("nonce {i}"));
    }
    assert_eq!(registry.high_water_for(&test_principal()), 5);
}

#[test]
fn nonce_registry_accepts_gaps() {
    let mut registry = NonceRegistry::new();
    registry
        .check_and_record(&test_principal(), AttestationNonce::from_counter(1))
        .expect("nonce 1");
    registry
        .check_and_record(&test_principal(), AttestationNonce::from_counter(100))
        .expect("nonce 100");
    assert_eq!(registry.high_water_for(&test_principal()), 100);
}

#[test]
fn nonce_registry_rejects_replay() {
    let mut registry = NonceRegistry::new();
    registry
        .check_and_record(&test_principal(), AttestationNonce::from_counter(5))
        .expect("nonce 5");
    let result = registry.check_and_record(&test_principal(), AttestationNonce::from_counter(5));
    assert!(matches!(result, Err(AttestationError::NonceReplay { .. })));
}

#[test]
fn nonce_registry_rejects_lower_nonce() {
    let mut registry = NonceRegistry::new();
    registry
        .check_and_record(&test_principal(), AttestationNonce::from_counter(10))
        .expect("nonce 10");
    let result = registry.check_and_record(&test_principal(), AttestationNonce::from_counter(5));
    assert!(matches!(result, Err(AttestationError::NonceReplay { .. })));
}

#[test]
fn nonce_registry_rejects_zero_nonce() {
    let mut registry = NonceRegistry::new();
    let result = registry.check_and_record(&test_principal(), AttestationNonce::from_counter(0));
    assert!(matches!(result, Err(AttestationError::InvalidNonce { .. })));
}

#[test]
fn nonce_registry_per_principal_isolation() {
    let mut registry = NonceRegistry::new();
    let p1 = test_principal();
    let p2 = PrincipalId::from_bytes([0xBB; 32]);

    registry
        .check_and_record(&p1, AttestationNonce::from_counter(10))
        .expect("p1 nonce 10");
    registry
        .check_and_record(&p2, AttestationNonce::from_counter(5))
        .expect("p2 nonce 5");

    assert_eq!(registry.high_water_for(&p1), 10);
    assert_eq!(registry.high_water_for(&p2), 5);
    assert_eq!(registry.principal_count(), 2);
}

#[test]
fn nonce_registry_serde_roundtrip() {
    let mut registry = NonceRegistry::new();
    let p1 = test_principal();
    let p2 = PrincipalId::from_bytes([0xCC; 32]);
    registry
        .check_and_record(&p1, AttestationNonce::from_counter(5))
        .expect("p1");
    registry
        .check_and_record(&p2, AttestationNonce::from_counter(10))
        .expect("p2");

    let json = serde_json::to_string(&registry).unwrap();
    let restored: NonceRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.high_water_for(&p1), 5);
    assert_eq!(restored.high_water_for(&p2), 10);
    assert_eq!(restored.principal_count(), 2);
}

#[test]
fn nonce_registry_unseen_principal_returns_zero() {
    let registry = NonceRegistry::new();
    let unknown = PrincipalId::from_bytes([0xFF; 32]);
    assert_eq!(registry.high_water_for(&unknown), 0);
}

// ===========================================================================
// Section 10: AttestationStore Registration
// ===========================================================================

#[test]
fn store_register_succeeds() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    let id = store
        .register(att, &owner_vk(), DeterministicTimestamp(150), "t-reg")
        .expect("register");
    assert_eq!(store.total_count(), 1);
    assert!(store.get(&id).is_some());
}

#[test]
fn store_register_expired_rejected() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    let result = store.register(att, &owner_vk(), DeterministicTimestamp(300), "t-exp");
    assert!(matches!(result, Err(AttestationError::Expired { .. })));
    assert_eq!(store.total_count(), 0);
}

#[test]
fn store_register_zone_mismatch_rejected() {
    let mut store = AttestationStore::new("different-zone");
    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    let result = store.register(att, &owner_vk(), DeterministicTimestamp(150), "t-zone");
    assert!(matches!(result, Err(AttestationError::ZoneMismatch { .. })));
}

#[test]
fn store_register_wrong_signature_rejected() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    let wrong_sk = SigningKey::from_bytes([0xFF; 32]);
    let wrong_vk = wrong_sk.verification_key();
    let result = store.register(att, &wrong_vk, DeterministicTimestamp(150), "t-sig");
    assert!(matches!(
        result,
        Err(AttestationError::SignatureInvalid { .. })
    ));
}

#[test]
fn store_register_nonce_replay_rejected() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att1 = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    store
        .register(att1, &owner_vk(), DeterministicTimestamp(150), "t-1")
        .expect("first");

    // Same nonce, different role
    let att2 = create_test_attestation(KeyRole::Encryption, 1, 100, 200);
    let result = store.register(att2, &owner_vk(), DeterministicTimestamp(150), "t-2");
    assert!(matches!(result, Err(AttestationError::NonceReplay { .. })));
}

// ===========================================================================
// Section 11: AttestationStore Queries
// ===========================================================================

#[test]
fn store_get_returns_attestation() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    let id = store
        .register(att.clone(), &owner_vk(), DeterministicTimestamp(150), "t")
        .unwrap();
    let found = store.get(&id).unwrap();
    assert_eq!(found, &att);
}

#[test]
fn store_get_returns_none_for_missing() {
    let store = AttestationStore::new(TEST_ZONE);
    let fake_id = EngineObjectId([0xFF; 32]);
    assert!(store.get(&fake_id).is_none());
}

#[test]
fn store_active_for_principal() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att1 = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    let att2 = create_test_attestation(KeyRole::Encryption, 2, 100, 300);
    store
        .register(att1, &owner_vk(), DeterministicTimestamp(150), "t-1")
        .unwrap();
    store
        .register(att2, &owner_vk(), DeterministicTimestamp(150), "t-2")
        .unwrap();

    // Both active at 150
    let active = store.active_for_principal(&test_principal(), DeterministicTimestamp(150));
    assert_eq!(active.len(), 2);

    // At 250, first expired
    let active = store.active_for_principal(&test_principal(), DeterministicTimestamp(250));
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].key_role, KeyRole::Encryption);
}

#[test]
fn store_active_for_principal_empty_for_unknown() {
    let store = AttestationStore::new(TEST_ZONE);
    let unknown = PrincipalId::from_bytes([0xFF; 32]);
    let active = store.active_for_principal(&unknown, DeterministicTimestamp(100));
    assert!(active.is_empty());
}

#[test]
fn store_active_for_role() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att1 = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    let att2 = create_test_attestation(KeyRole::Encryption, 2, 100, 200);
    store
        .register(att1, &owner_vk(), DeterministicTimestamp(150), "t-1")
        .unwrap();
    store
        .register(att2, &owner_vk(), DeterministicTimestamp(150), "t-2")
        .unwrap();

    let signing = store.active_for_role(
        &test_principal(),
        KeyRole::Signing,
        DeterministicTimestamp(150),
    );
    assert_eq!(signing.len(), 1);
    assert_eq!(signing[0].key_role, KeyRole::Signing);

    let issuance = store.active_for_role(
        &test_principal(),
        KeyRole::Issuance,
        DeterministicTimestamp(150),
    );
    assert!(issuance.is_empty());
}

// ===========================================================================
// Section 12: AttestationStore Revocation
// ===========================================================================

#[test]
fn store_revoke_succeeds() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    let id = store
        .register(att, &owner_vk(), DeterministicTimestamp(150), "t-reg")
        .unwrap();

    store.revoke(&id, "t-revoke").expect("revoke");
    assert_eq!(store.total_count(), 0);
    assert!(store.get(&id).is_none());
}

#[test]
fn store_revoke_not_found() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let fake_id = EngineObjectId([0xFF; 32]);
    let result = store.revoke(&fake_id, "t-revoke");
    assert!(matches!(result, Err(AttestationError::NotFound { .. })));
}

#[test]
fn store_revoke_removes_from_principal_index() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    let id = store
        .register(att, &owner_vk(), DeterministicTimestamp(150), "t-reg")
        .unwrap();

    store.revoke(&id, "t-revoke").unwrap();
    let active = store.active_for_principal(&test_principal(), DeterministicTimestamp(150));
    assert!(active.is_empty());
    assert_eq!(store.principal_count(), 0);
}

// ===========================================================================
// Section 13: AttestationStore Purge Expired
// ===========================================================================

#[test]
fn store_purge_expired_removes_old() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att1 = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    let att2 = create_test_attestation(KeyRole::Encryption, 2, 100, 300);
    let att3 = create_test_attestation(KeyRole::Issuance, 3, 100, 400);
    store
        .register(att1, &owner_vk(), DeterministicTimestamp(150), "t-1")
        .unwrap();
    store
        .register(att2, &owner_vk(), DeterministicTimestamp(150), "t-2")
        .unwrap();
    store
        .register(att3, &owner_vk(), DeterministicTimestamp(150), "t-3")
        .unwrap();

    assert_eq!(store.total_count(), 3);

    let purged = store.purge_expired(DeterministicTimestamp(250), "t-purge");
    assert_eq!(purged, 1); // Only att1 expired
    assert_eq!(store.total_count(), 2);

    let purged = store.purge_expired(DeterministicTimestamp(350), "t-purge2");
    assert_eq!(purged, 1); // att2 expired
    assert_eq!(store.total_count(), 1);
}

#[test]
fn store_purge_expired_on_empty_store() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let purged = store.purge_expired(DeterministicTimestamp(1000), "t-purge");
    assert_eq!(purged, 0);
}

#[test]
fn store_purge_expired_removes_principal_index() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    store
        .register(att, &owner_vk(), DeterministicTimestamp(150), "t")
        .unwrap();
    assert_eq!(store.principal_count(), 1);

    store.purge_expired(DeterministicTimestamp(300), "t-purge");
    assert_eq!(store.total_count(), 0);
    assert_eq!(store.principal_count(), 0);
}

#[test]
fn store_purge_expired_all_at_once() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att1 = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    let att2 = create_test_attestation(KeyRole::Encryption, 2, 100, 200);
    store
        .register(att1, &owner_vk(), DeterministicTimestamp(150), "t-1")
        .unwrap();
    store
        .register(att2, &owner_vk(), DeterministicTimestamp(150), "t-2")
        .unwrap();

    let purged = store.purge_expired(DeterministicTimestamp(500), "t-purge");
    assert_eq!(purged, 2);
    assert_eq!(store.total_count(), 0);
}

// ===========================================================================
// Section 14: AttestationStore Counters
// ===========================================================================

#[test]
fn store_total_count() {
    let mut store = AttestationStore::new(TEST_ZONE);
    assert_eq!(store.total_count(), 0);

    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    store
        .register(att, &owner_vk(), DeterministicTimestamp(150), "t")
        .unwrap();
    assert_eq!(store.total_count(), 1);
}

#[test]
fn store_principal_count() {
    let mut store = AttestationStore::new(TEST_ZONE);
    assert_eq!(store.principal_count(), 0);

    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    store
        .register(att, &owner_vk(), DeterministicTimestamp(150), "t")
        .unwrap();
    assert_eq!(store.principal_count(), 1);
}

#[test]
fn empty_store_queries() {
    let store = AttestationStore::new(TEST_ZONE);
    assert_eq!(store.total_count(), 0);
    assert_eq!(store.principal_count(), 0);
    let active = store.active_for_principal(&test_principal(), DeterministicTimestamp(100));
    assert!(active.is_empty());
}

// ===========================================================================
// Section 15: Audit Events
// ===========================================================================

#[test]
fn audit_events_emitted_on_register() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    store
        .register(att, &owner_vk(), DeterministicTimestamp(150), "t-reg")
        .unwrap();

    let events = store.drain_events();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].event_type,
        AttestationEventType::Registered { .. }
    ));
    assert_eq!(events[0].zone, TEST_ZONE);
    assert_eq!(events[0].trace_id, "t-reg");
}

#[test]
fn audit_events_emitted_on_zone_rejection() {
    let mut store = AttestationStore::new("wrong-zone");
    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    let _ = store.register(att, &owner_vk(), DeterministicTimestamp(150), "t-rej");

    let events = store.drain_events();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].event_type,
        AttestationEventType::RegistrationRejected { .. }
    ));
}

#[test]
fn audit_events_emitted_on_expired_rejection() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    let _ = store.register(att, &owner_vk(), DeterministicTimestamp(300), "t-exp");

    let events = store.drain_events();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].event_type,
        AttestationEventType::RegistrationRejected { .. }
    ));
}

#[test]
fn audit_events_emitted_on_revoke() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    let id = store
        .register(att, &owner_vk(), DeterministicTimestamp(150), "t-reg")
        .unwrap();
    store.drain_events();

    store.revoke(&id, "t-revoke").unwrap();
    let events = store.drain_events();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].event_type,
        AttestationEventType::Revoked { .. }
    ));
}

#[test]
fn audit_events_emitted_on_purge() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    store
        .register(att, &owner_vk(), DeterministicTimestamp(150), "t-reg")
        .unwrap();
    store.drain_events();

    store.purge_expired(DeterministicTimestamp(300), "t-purge");
    let events = store.drain_events();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].event_type,
        AttestationEventType::ExpiredPurged { count: 1 }
    ));
}

#[test]
fn audit_events_not_emitted_on_empty_purge() {
    let mut store = AttestationStore::new(TEST_ZONE);
    store.purge_expired(DeterministicTimestamp(300), "t-purge");
    let events = store.drain_events();
    assert!(events.is_empty());
}

#[test]
fn drain_events_clears_accumulated() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    store
        .register(att, &owner_vk(), DeterministicTimestamp(150), "t")
        .unwrap();

    let events = store.drain_events();
    assert!(!events.is_empty());

    let events2 = store.drain_events();
    assert!(events2.is_empty());
}

// ===========================================================================
// Section 16: Display Impls
// ===========================================================================

#[test]
fn attestation_display_contains_key_info() {
    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    let display = att.to_string();
    assert!(display.contains("KeyAttestation"));
    assert!(display.contains("signing"));
    assert!(display.contains("nonce:1"));
}

#[test]
fn attestation_error_display_self_attestation() {
    let err = AttestationError::SelfAttestationRejected;
    assert_eq!(err.to_string(), "self-attestation rejected");
}

#[test]
fn attestation_error_display_expired() {
    let err = AttestationError::Expired {
        expires_at: DeterministicTimestamp(100),
        current_time: DeterministicTimestamp(200),
    };
    let s = err.to_string();
    assert!(s.contains("100"));
    assert!(s.contains("200"));
    assert!(s.contains("expired"));
}

#[test]
fn attestation_error_display_nonce_replay() {
    let err = AttestationError::NonceReplay {
        principal: test_principal(),
        nonce: AttestationNonce::from_counter(5),
        high_water: 10,
    };
    let s = err.to_string();
    assert!(s.contains("nonce replay"));
    assert!(s.contains("nonce:5"));
    assert!(s.contains("10"));
}

#[test]
fn attestation_error_display_invalid_nonce() {
    let err = AttestationError::InvalidNonce {
        detail: "must be > 0".to_string(),
    };
    assert!(err.to_string().contains("invalid nonce"));
}

#[test]
fn attestation_error_display_signature_invalid() {
    let err = AttestationError::SignatureInvalid {
        detail: "mismatch".to_string(),
    };
    assert!(err.to_string().contains("signature invalid"));
}

#[test]
fn attestation_error_display_signature_failed() {
    let err = AttestationError::SignatureFailed {
        detail: "internal".to_string(),
    };
    assert!(err.to_string().contains("signature failed"));
}

#[test]
fn attestation_error_display_id_derivation_failed() {
    let err = AttestationError::IdDerivationFailed {
        detail: "bad input".to_string(),
    };
    assert!(err.to_string().contains("id derivation failed"));
}

#[test]
fn attestation_error_display_invalid_expiry() {
    let err = AttestationError::InvalidExpiry {
        issued_at: DeterministicTimestamp(200),
        expires_at: DeterministicTimestamp(100),
    };
    let s = err.to_string();
    assert!(s.contains("invalid expiry"));
    assert!(s.contains("200"));
    assert!(s.contains("100"));
}

#[test]
fn attestation_error_display_zone_mismatch() {
    let err = AttestationError::ZoneMismatch {
        expected: "zone-a".to_string(),
        actual: "zone-b".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("zone mismatch"));
    assert!(s.contains("zone-a"));
    assert!(s.contains("zone-b"));
}

#[test]
fn attestation_error_display_duplicate() {
    let err = AttestationError::DuplicateAttestation {
        attestation_id: EngineObjectId([0xAA; 32]),
    };
    assert!(err.to_string().contains("duplicate attestation"));
}

#[test]
fn attestation_error_display_not_found() {
    let err = AttestationError::NotFound {
        attestation_id: EngineObjectId([0xBB; 32]),
    };
    assert!(err.to_string().contains("not found"));
}

#[test]
fn attestation_error_display_device_posture_invalid() {
    let err = AttestationError::DevicePostureInvalid {
        detail: "unknown type".to_string(),
    };
    assert!(err.to_string().contains("device posture invalid"));
}

#[test]
fn attestation_error_is_std_error() {
    let err = AttestationError::SelfAttestationRejected;
    let _: &dyn std::error::Error = &err;
}

// ===========================================================================
// Section 17: Serde Round-Trips
// ===========================================================================

#[test]
fn attestation_serde_roundtrip() {
    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    let json = serde_json::to_string(&att).unwrap();
    let deser: KeyAttestation = serde_json::from_str(&json).unwrap();
    assert_eq!(att, deser);
}

#[test]
fn attestation_with_posture_serde_roundtrip() {
    let att = create_attestation_with_posture(KeyRole::Encryption, 1, "tpm2", vec![0x01, 0x02]);
    let json = serde_json::to_string(&att).unwrap();
    let deser: KeyAttestation = serde_json::from_str(&json).unwrap();
    assert_eq!(att, deser);
}

#[test]
fn attestation_error_serde_roundtrip_all_variants() {
    let errors: Vec<AttestationError> = vec![
        AttestationError::SelfAttestationRejected,
        AttestationError::Expired {
            expires_at: DeterministicTimestamp(100),
            current_time: DeterministicTimestamp(200),
        },
        AttestationError::NonceReplay {
            principal: test_principal(),
            nonce: AttestationNonce::from_counter(5),
            high_water: 10,
        },
        AttestationError::InvalidNonce {
            detail: "test".to_string(),
        },
        AttestationError::SignatureInvalid {
            detail: "bad".to_string(),
        },
        AttestationError::SignatureFailed {
            detail: "internal".to_string(),
        },
        AttestationError::IdDerivationFailed {
            detail: "err".to_string(),
        },
        AttestationError::InvalidExpiry {
            issued_at: DeterministicTimestamp(200),
            expires_at: DeterministicTimestamp(100),
        },
        AttestationError::ZoneMismatch {
            expected: "a".to_string(),
            actual: "b".to_string(),
        },
        AttestationError::DuplicateAttestation {
            attestation_id: EngineObjectId([0xAA; 32]),
        },
        AttestationError::NotFound {
            attestation_id: EngineObjectId([0xBB; 32]),
        },
        AttestationError::DevicePostureInvalid {
            detail: "test".to_string(),
        },
    ];
    for err in errors {
        let json = serde_json::to_string(&err).unwrap();
        let deser: AttestationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, deser);
    }
}

#[test]
fn attestation_event_type_serde_roundtrip() {
    let variants = vec![
        AttestationEventType::Registered {
            attestation_id: EngineObjectId([0x01; 32]),
            principal: test_principal(),
        },
        AttestationEventType::Revoked {
            attestation_id: EngineObjectId([0x02; 32]),
            principal: test_principal(),
        },
        AttestationEventType::RegistrationRejected {
            reason: "test".to_string(),
        },
        AttestationEventType::ExpiredPurged { count: 5 },
    ];
    for variant in variants {
        let json = serde_json::to_string(&variant).unwrap();
        let deser: AttestationEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, deser);
    }
}

#[test]
fn attestation_event_serde_roundtrip() {
    let event = AttestationEvent {
        event_type: AttestationEventType::Registered {
            attestation_id: EngineObjectId([0x01; 32]),
            principal: test_principal(),
        },
        zone: TEST_ZONE.to_string(),
        trace_id: "t-test".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let deser: AttestationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, deser);
}

#[test]
fn attestation_store_contains_btreemap_engine_object_id_key() {
    // AttestationStore uses BTreeMap<EngineObjectId, _> which cannot
    // round-trip through JSON ("key must be a string"). Verify the
    // known limitation and that the store works correctly at runtime.
    let mut store = AttestationStore::new(TEST_ZONE);
    let att1 = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    let att2 = create_test_attestation(KeyRole::Encryption, 2, 100, 300);
    let id1 = store
        .register(att1, &owner_vk(), DeterministicTimestamp(150), "t-1")
        .unwrap();
    let id2 = store
        .register(att2, &owner_vk(), DeterministicTimestamp(150), "t-2")
        .unwrap();

    assert_eq!(store.total_count(), 2);
    assert_eq!(store.principal_count(), 1);
    assert!(store.get(&id1).is_some());
    assert!(store.get(&id2).is_some());

    // JSON serialization fails with "key must be a string" — this is a known
    // limitation documented in the project (use Vec<T> with linear scan for
    // JSON-serializable maps).
    let result = serde_json::to_string(&store);
    assert!(result.is_err());
}

// ===========================================================================
// Section 18: Deterministic Replay
// ===========================================================================

#[test]
fn deterministic_attestation_creation_replay() {
    let run = || {
        let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        (
            att.attestation_id.clone(),
            att.owner_signature.clone(),
            att.principal_id.clone(),
        )
    };
    let r1 = run();
    let r2 = run();
    assert_eq!(r1.0, r2.0, "attestation_id differs");
    assert_eq!(r1.1, r2.1, "owner_signature differs");
    assert_eq!(r1.2, r2.2, "principal_id differs");
}

#[test]
fn deterministic_store_lifecycle_replay() {
    let run = || {
        let mut store = AttestationStore::new(TEST_ZONE);
        let att1 = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        let att2 = create_test_attestation(KeyRole::Encryption, 2, 100, 300);
        let id1 = store
            .register(att1, &owner_vk(), DeterministicTimestamp(150), "t-1")
            .unwrap();
        let id2 = store
            .register(att2, &owner_vk(), DeterministicTimestamp(150), "t-2")
            .unwrap();
        let active = store.active_for_principal(&test_principal(), DeterministicTimestamp(250));
        let total = store.total_count();
        (id1, id2, active.len(), total)
    };
    let r1 = run();
    let r2 = run();
    assert_eq!(r1.0, r2.0);
    assert_eq!(r1.1, r2.1);
    assert_eq!(r1.2, r2.2);
    assert_eq!(r1.3, r2.3);
}

// ===========================================================================
// Section 19: Full Lifecycle Integration
// ===========================================================================

#[test]
fn full_lifecycle_create_verify_rotate_revoke() {
    let mut store = AttestationStore::new(TEST_ZONE);

    // Create and register initial attestation
    let att1 = create_test_attestation(KeyRole::Signing, 1, 100, 500);
    let id1 = store
        .register(att1, &owner_vk(), DeterministicTimestamp(150), "t-create")
        .expect("register initial");

    // Verify active
    let active = store.active_for_principal(&test_principal(), DeterministicTimestamp(200));
    assert_eq!(active.len(), 1);

    // Rotate: new attestation with different key, higher nonce
    let new_key_sk = SigningKey::from_bytes([0x03; 32]);
    let new_key_vk = new_key_sk.verification_key();
    let att2 = KeyAttestation::create_signed(
        &owner_signing_key(),
        CreateAttestationInput {
            principal_id: test_principal(),
            attested_key: new_key_vk,
            key_role: KeyRole::Signing,
            issued_at: DeterministicTimestamp(300),
            expires_at: DeterministicTimestamp(600),
            epoch: SecurityEpoch::from_raw(2),
            nonce: AttestationNonce::from_counter(2),
            device_posture: None,
            zone: TEST_ZONE,
        },
    )
    .expect("create rotation");
    let id2 = store
        .register(att2, &owner_vk(), DeterministicTimestamp(350), "t-rotate")
        .expect("register rotation");

    // Both active
    let active = store.active_for_principal(&test_principal(), DeterministicTimestamp(400));
    assert_eq!(active.len(), 2);

    // Revoke old
    store.revoke(&id1, "t-revoke-old").expect("revoke old");
    let active = store.active_for_principal(&test_principal(), DeterministicTimestamp(400));
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].attestation_id, id2);
}

#[test]
fn multi_principal_isolation() {
    let mut store = AttestationStore::new(TEST_ZONE);

    // Principal 1
    let att1 = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    store
        .register(att1, &owner_vk(), DeterministicTimestamp(150), "t-p1")
        .unwrap();

    // Principal 2
    let p2_owner_sk = SigningKey::from_bytes([0x10; 32]);
    let p2_owner_vk = p2_owner_sk.verification_key();
    let p2_principal = PrincipalId::from_verification_key(&p2_owner_vk);
    let p2_attested_sk = SigningKey::from_bytes([0x20; 32]);
    let p2_attested_vk = p2_attested_sk.verification_key();

    let att2 = KeyAttestation::create_signed(
        &p2_owner_sk,
        CreateAttestationInput {
            principal_id: p2_principal.clone(),
            attested_key: p2_attested_vk,
            key_role: KeyRole::Encryption,
            issued_at: DeterministicTimestamp(100),
            expires_at: DeterministicTimestamp(200),
            epoch: SecurityEpoch::from_raw(1),
            nonce: AttestationNonce::from_counter(1),
            device_posture: None,
            zone: TEST_ZONE,
        },
    )
    .unwrap();
    store
        .register(att2, &p2_owner_vk, DeterministicTimestamp(150), "t-p2")
        .unwrap();

    assert_eq!(store.total_count(), 2);
    assert_eq!(store.principal_count(), 2);

    let p1_active = store.active_for_principal(&test_principal(), DeterministicTimestamp(150));
    assert_eq!(p1_active.len(), 1);
    assert_eq!(p1_active[0].key_role, KeyRole::Signing);

    let p2_active = store.active_for_principal(&p2_principal, DeterministicTimestamp(150));
    assert_eq!(p2_active.len(), 1);
    assert_eq!(p2_active[0].key_role, KeyRole::Encryption);
}

#[test]
fn multi_role_registration_with_sequential_nonces() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att_sign = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    let att_enc = create_test_attestation(KeyRole::Encryption, 2, 100, 200);
    let att_iss = create_test_attestation(KeyRole::Issuance, 3, 100, 200);

    store
        .register(att_sign, &owner_vk(), DeterministicTimestamp(150), "t-1")
        .unwrap();
    store
        .register(att_enc, &owner_vk(), DeterministicTimestamp(150), "t-2")
        .unwrap();
    store
        .register(att_iss, &owner_vk(), DeterministicTimestamp(150), "t-3")
        .unwrap();

    assert_eq!(store.total_count(), 3);

    for role in KeyRole::ALL {
        let active = store.active_for_role(&test_principal(), *role, DeterministicTimestamp(150));
        assert_eq!(
            active.len(),
            1,
            "expected 1 active attestation for role {role}"
        );
    }
}

// ===========================================================================
// Section 20: Edge Cases
// ===========================================================================

#[test]
fn duplicate_registration_via_nonce_replay() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
    store
        .register(att.clone(), &owner_vk(), DeterministicTimestamp(150), "t-1")
        .unwrap();

    // Same attestation again
    let result = store.register(att, &owner_vk(), DeterministicTimestamp(150), "t-2");
    assert!(result.is_err());
}

#[test]
fn large_nonce_value() {
    let att = create_test_attestation(KeyRole::Signing, u64::MAX - 1, 100, 200);
    assert_eq!(att.nonce.as_u64(), u64::MAX - 1);
}

#[test]
fn minimal_expiry_window() {
    let att = create_test_attestation(KeyRole::Signing, 1, 100, 101);
    assert!(!att.is_expired(DeterministicTimestamp(100)));
    assert!(att.is_expired(DeterministicTimestamp(101)));
}

#[test]
fn nonce_registry_roundtrip_preserves_high_water() {
    // Instead of serializing the entire AttestationStore (which uses
    // BTreeMap<EngineObjectId, _> and fails JSON), verify that the
    // NonceRegistry alone round-trips correctly and preserves rejection.
    let mut registry = NonceRegistry::new();
    registry
        .check_and_record(&test_principal(), AttestationNonce::from_counter(5))
        .unwrap();

    let json = serde_json::to_string(&registry).unwrap();
    let mut restored: NonceRegistry = serde_json::from_str(&json).unwrap();

    // Nonce 3 is below the high water mark (5) and must be rejected.
    let result = restored.check_and_record(&test_principal(), AttestationNonce::from_counter(3));
    assert!(matches!(result, Err(AttestationError::NonceReplay { .. })));

    // Nonce 6 is above high water mark and must succeed.
    restored
        .check_and_record(&test_principal(), AttestationNonce::from_counter(6))
        .expect("nonce 6 should succeed after restore");
    assert_eq!(restored.high_water_for(&test_principal()), 6);
}

#[test]
fn multiple_attestations_same_principal_different_keys() {
    let mut store = AttestationStore::new(TEST_ZONE);

    // First with attested_vk (key [0x02])
    let att1 = create_test_attestation(KeyRole::Signing, 1, 100, 300);
    store
        .register(att1, &owner_vk(), DeterministicTimestamp(150), "t-1")
        .unwrap();

    // Second with different attested key
    let new_key_sk = SigningKey::from_bytes([0x03; 32]);
    let new_key_vk = new_key_sk.verification_key();
    let att2 = KeyAttestation::create_signed(
        &owner_signing_key(),
        CreateAttestationInput {
            principal_id: test_principal(),
            attested_key: new_key_vk,
            key_role: KeyRole::Signing,
            issued_at: DeterministicTimestamp(100),
            expires_at: DeterministicTimestamp(300),
            epoch: SecurityEpoch::from_raw(1),
            nonce: AttestationNonce::from_counter(2),
            device_posture: None,
            zone: TEST_ZONE,
        },
    )
    .unwrap();
    store
        .register(att2, &owner_vk(), DeterministicTimestamp(150), "t-2")
        .unwrap();

    assert_eq!(store.total_count(), 2);
    let active = store.active_for_principal(&test_principal(), DeterministicTimestamp(200));
    assert_eq!(active.len(), 2);
}
