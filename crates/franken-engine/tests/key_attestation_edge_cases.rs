//! Integration edge-case tests for the `key_attestation` module.
//!
//! Covers AttestationNonce, DevicePosture, KeyAttestation (create_signed,
//! verify_owner_signature, is_expired, derive_attestation_id), NonceRegistry,
//! AttestationStore (register, get, active_for_principal, active_for_role,
//! revoke, purge_expired, drain_events), AttestationError (all 12 variants,
//! Display, std::error::Error, serde), audit events, and full lifecycle.

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
use frankenengine_engine::signature_preimage::SigningKey;

// ===========================================================================
// Helpers
// ===========================================================================

const TEST_ZONE: &str = "test-zone";

fn owner_signing_key() -> SigningKey {
    SigningKey::from_bytes([0x01; 32])
}

fn owner_vk() -> frankenengine_engine::signature_preimage::VerificationKey {
    owner_signing_key().verification_key()
}

fn attested_signing_key() -> SigningKey {
    SigningKey::from_bytes([0x02; 32])
}

fn attested_vk() -> frankenengine_engine::signature_preimage::VerificationKey {
    attested_signing_key().verification_key()
}

fn test_principal() -> PrincipalId {
    PrincipalId::from_verification_key(&owner_vk())
}

fn create_attestation(
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

// ===========================================================================
// AttestationNonce — display, ordering, hash, serde
// ===========================================================================

#[test]
fn nonce_display() {
    assert_eq!(AttestationNonce::from_counter(0).to_string(), "nonce:0");
    assert_eq!(AttestationNonce::from_counter(42).to_string(), "nonce:42");
    assert_eq!(
        AttestationNonce::from_counter(u64::MAX).to_string(),
        format!("nonce:{}", u64::MAX)
    );
}

#[test]
fn nonce_ordering() {
    let a = AttestationNonce::from_counter(1);
    let b = AttestationNonce::from_counter(2);
    let c = AttestationNonce::from_counter(100);
    assert!(a < b);
    assert!(b < c);
    assert_eq!(a, AttestationNonce::from_counter(1));
}

#[test]
fn nonce_hash_distinct() {
    use std::collections::HashSet;
    let set: HashSet<AttestationNonce> = (0..10).map(AttestationNonce::from_counter).collect();
    assert_eq!(set.len(), 10);
}

#[test]
fn nonce_serde_roundtrip() {
    let nonce = AttestationNonce::from_counter(42);
    let json = serde_json::to_string(&nonce).unwrap();
    let deser: AttestationNonce = serde_json::from_str(&json).unwrap();
    assert_eq!(nonce, deser);
}

#[test]
fn nonce_as_u64() {
    assert_eq!(AttestationNonce::from_counter(99).as_u64(), 99);
    assert_eq!(AttestationNonce::from_counter(0).as_u64(), 0);
}

// ===========================================================================
// DevicePosture — serde, ordering, hash
// ===========================================================================

#[test]
fn device_posture_serde_roundtrip() {
    let dp = DevicePosture {
        posture_type: "tpm2".to_string(),
        evidence: vec![0xDE, 0xAD, 0xBE, 0xEF],
    };
    let json = serde_json::to_string(&dp).unwrap();
    let deser: DevicePosture = serde_json::from_str(&json).unwrap();
    assert_eq!(dp, deser);
}

#[test]
fn device_posture_ordering() {
    let a = DevicePosture {
        posture_type: "a_type".to_string(),
        evidence: vec![0x01],
    };
    let b = DevicePosture {
        posture_type: "b_type".to_string(),
        evidence: vec![0x01],
    };
    assert!(a < b);
}

#[test]
fn device_posture_empty_evidence() {
    let dp = DevicePosture {
        posture_type: "none".to_string(),
        evidence: Vec::new(),
    };
    let json = serde_json::to_string(&dp).unwrap();
    let deser: DevicePosture = serde_json::from_str(&json).unwrap();
    assert_eq!(dp, deser);
}

// ===========================================================================
// KeyAttestation — creation
// ===========================================================================

#[test]
fn create_attestation_succeeds() {
    let att = create_attestation(KeyRole::Signing, 1, 100, 200);
    assert_eq!(att.key_role, KeyRole::Signing);
    assert_eq!(att.principal_id, test_principal());
    assert_eq!(att.attested_key, attested_vk());
    assert_eq!(att.nonce, AttestationNonce::from_counter(1));
    assert_eq!(att.zone, TEST_ZONE);
}

#[test]
fn create_attestation_all_roles() {
    for role in KeyRole::ALL {
        let att = create_attestation(*role, 1, 100, 200);
        assert_eq!(att.key_role, *role);
    }
}

#[test]
fn create_attestation_deterministic() {
    let att1 = create_attestation(KeyRole::Signing, 1, 100, 200);
    let att2 = create_attestation(KeyRole::Signing, 1, 100, 200);
    assert_eq!(att1.attestation_id, att2.attestation_id);
    assert_eq!(att1.owner_signature, att2.owner_signature);
}

#[test]
fn create_attestation_different_roles_different_ids() {
    let a = create_attestation(KeyRole::Signing, 1, 100, 200);
    let b = create_attestation(KeyRole::Encryption, 1, 100, 200);
    let c = create_attestation(KeyRole::Issuance, 1, 100, 200);
    assert_ne!(a.attestation_id, b.attestation_id);
    assert_ne!(a.attestation_id, c.attestation_id);
    assert_ne!(b.attestation_id, c.attestation_id);
}

#[test]
fn create_attestation_different_nonces_different_ids() {
    let a = create_attestation(KeyRole::Signing, 1, 100, 200);
    let b = create_attestation(KeyRole::Signing, 2, 100, 200);
    assert_ne!(a.attestation_id, b.attestation_id);
}

#[test]
fn create_attestation_with_device_posture() {
    let posture = DevicePosture {
        posture_type: "tpm2".to_string(),
        evidence: vec![0x01, 0x02, 0x03],
    };
    let att = KeyAttestation::create_signed(
        &owner_signing_key(),
        CreateAttestationInput {
            principal_id: test_principal(),
            attested_key: attested_vk(),
            key_role: KeyRole::Signing,
            issued_at: DeterministicTimestamp(100),
            expires_at: DeterministicTimestamp(200),
            epoch: SecurityEpoch::from_raw(1),
            nonce: AttestationNonce::from_counter(1),
            device_posture: Some(posture.clone()),
            zone: TEST_ZONE,
        },
    )
    .unwrap();
    assert_eq!(att.device_posture, Some(posture));
    att.verify_owner_signature(&owner_vk()).unwrap();
}

#[test]
fn device_posture_changes_signature() {
    let att_no = create_attestation(KeyRole::Signing, 1, 100, 200);
    let att_with = KeyAttestation::create_signed(
        &owner_signing_key(),
        CreateAttestationInput {
            principal_id: test_principal(),
            attested_key: attested_vk(),
            key_role: KeyRole::Signing,
            issued_at: DeterministicTimestamp(100),
            expires_at: DeterministicTimestamp(200),
            epoch: SecurityEpoch::from_raw(1),
            nonce: AttestationNonce::from_counter(1),
            device_posture: Some(DevicePosture {
                posture_type: "sgx".to_string(),
                evidence: vec![0x42],
            }),
            zone: TEST_ZONE,
        },
    )
    .unwrap();
    assert_ne!(att_no.owner_signature, att_with.owner_signature);
}

// ===========================================================================
// Self-attestation rejection
// ===========================================================================

#[test]
fn self_attestation_rejected_on_create() {
    let sk = owner_signing_key();
    let vk = sk.verification_key();
    let err = KeyAttestation::create_signed(
        &sk,
        CreateAttestationInput {
            principal_id: test_principal(),
            attested_key: vk,
            key_role: KeyRole::Signing,
            issued_at: DeterministicTimestamp(100),
            expires_at: DeterministicTimestamp(200),
            epoch: SecurityEpoch::from_raw(1),
            nonce: AttestationNonce::from_counter(1),
            device_posture: None,
            zone: TEST_ZONE,
        },
    )
    .unwrap_err();
    assert_eq!(err, AttestationError::SelfAttestationRejected);
}

#[test]
fn self_attestation_rejected_on_verify() {
    let att = create_attestation(KeyRole::Signing, 1, 100, 200);
    let err = att.verify_owner_signature(&attested_vk()).unwrap_err();
    assert_eq!(err, AttestationError::SelfAttestationRejected);
}

// ===========================================================================
// Expiry validation
// ===========================================================================

#[test]
fn invalid_expiry_before_issued() {
    let err = KeyAttestation::create_signed(
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
    )
    .unwrap_err();
    assert!(matches!(err, AttestationError::InvalidExpiry { .. }));
}

#[test]
fn invalid_expiry_equal_to_issued() {
    let err = KeyAttestation::create_signed(
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
    )
    .unwrap_err();
    assert!(matches!(err, AttestationError::InvalidExpiry { .. }));
}

#[test]
fn is_expired_boundary() {
    let att = create_attestation(KeyRole::Signing, 1, 100, 200);
    assert!(!att.is_expired(DeterministicTimestamp(199)));
    // At exact expiry, not yet expired (strictly greater semantics).
    assert!(!att.is_expired(DeterministicTimestamp(200)));
    assert!(att.is_expired(DeterministicTimestamp(201)));
}

#[test]
fn is_expired_at_u64_max() {
    let att = create_attestation(KeyRole::Signing, 1, 100, 200);
    assert!(att.is_expired(DeterministicTimestamp(u64::MAX)));
}

#[test]
fn is_not_expired_at_zero() {
    let att = create_attestation(KeyRole::Signing, 1, 100, 200);
    assert!(!att.is_expired(DeterministicTimestamp(0)));
}

// ===========================================================================
// Signature verification
// ===========================================================================

#[test]
fn verify_owner_signature_ok() {
    let att = create_attestation(KeyRole::Signing, 1, 100, 200);
    att.verify_owner_signature(&owner_vk()).unwrap();
}

#[test]
fn verify_owner_signature_wrong_key() {
    let att = create_attestation(KeyRole::Signing, 1, 100, 200);
    let wrong = SigningKey::from_bytes([0xFF; 32]);
    let err = att
        .verify_owner_signature(&wrong.verification_key())
        .unwrap_err();
    assert!(matches!(err, AttestationError::SignatureInvalid { .. }));
}

#[test]
fn verify_after_serde_roundtrip() {
    let att = create_attestation(KeyRole::Signing, 1, 100, 200);
    let json = serde_json::to_string(&att).unwrap();
    let deser: KeyAttestation = serde_json::from_str(&json).unwrap();
    deser.verify_owner_signature(&owner_vk()).unwrap();
}

// ===========================================================================
// NonceRegistry
// ===========================================================================

#[test]
fn nonce_registry_new_default() {
    let r1 = NonceRegistry::new();
    let r2 = NonceRegistry::default();
    assert_eq!(r1.principal_count(), 0);
    assert_eq!(r2.principal_count(), 0);
}

#[test]
fn nonce_registry_high_water_for_unknown() {
    let registry = NonceRegistry::new();
    assert_eq!(registry.high_water_for(&test_principal()), 0);
}

#[test]
fn nonce_registry_accepts_monotonic() {
    let mut registry = NonceRegistry::new();
    for i in 1..=5 {
        registry
            .check_and_record(&test_principal(), AttestationNonce::from_counter(i))
            .unwrap();
    }
    assert_eq!(registry.high_water_for(&test_principal()), 5);
}

#[test]
fn nonce_registry_accepts_gaps() {
    let mut registry = NonceRegistry::new();
    registry
        .check_and_record(&test_principal(), AttestationNonce::from_counter(1))
        .unwrap();
    registry
        .check_and_record(&test_principal(), AttestationNonce::from_counter(100))
        .unwrap();
    assert_eq!(registry.high_water_for(&test_principal()), 100);
}

#[test]
fn nonce_registry_rejects_replay() {
    let mut registry = NonceRegistry::new();
    registry
        .check_and_record(&test_principal(), AttestationNonce::from_counter(5))
        .unwrap();
    let err = registry
        .check_and_record(&test_principal(), AttestationNonce::from_counter(5))
        .unwrap_err();
    assert!(matches!(err, AttestationError::NonceReplay { .. }));
}

#[test]
fn nonce_registry_rejects_lower() {
    let mut registry = NonceRegistry::new();
    registry
        .check_and_record(&test_principal(), AttestationNonce::from_counter(10))
        .unwrap();
    let err = registry
        .check_and_record(&test_principal(), AttestationNonce::from_counter(3))
        .unwrap_err();
    assert!(matches!(err, AttestationError::NonceReplay { .. }));
}

#[test]
fn nonce_registry_rejects_zero() {
    let mut registry = NonceRegistry::new();
    let err = registry
        .check_and_record(&test_principal(), AttestationNonce::from_counter(0))
        .unwrap_err();
    assert!(matches!(err, AttestationError::InvalidNonce { .. }));
}

#[test]
fn nonce_registry_per_principal_isolation() {
    let mut registry = NonceRegistry::new();
    let p1 = test_principal();
    let p2 = PrincipalId::from_bytes([0xBB; 32]);
    registry
        .check_and_record(&p1, AttestationNonce::from_counter(10))
        .unwrap();
    registry
        .check_and_record(&p2, AttestationNonce::from_counter(5))
        .unwrap();
    assert_eq!(registry.high_water_for(&p1), 10);
    assert_eq!(registry.high_water_for(&p2), 5);
    assert_eq!(registry.principal_count(), 2);
}

#[test]
fn nonce_registry_serde_roundtrip() {
    let mut registry = NonceRegistry::new();
    registry
        .check_and_record(&test_principal(), AttestationNonce::from_counter(7))
        .unwrap();
    let json = serde_json::to_string(&registry).unwrap();
    let deser: NonceRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(deser.high_water_for(&test_principal()), 7);
    assert_eq!(deser.principal_count(), 1);
}

#[test]
fn nonce_registry_serde_multi_principal() {
    let mut registry = NonceRegistry::new();
    let p1 = test_principal();
    let p2 = PrincipalId::from_bytes([0xCC; 32]);
    registry
        .check_and_record(&p1, AttestationNonce::from_counter(10))
        .unwrap();
    registry
        .check_and_record(&p2, AttestationNonce::from_counter(20))
        .unwrap();
    let json = serde_json::to_string(&registry).unwrap();
    let deser: NonceRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(deser.high_water_for(&p1), 10);
    assert_eq!(deser.high_water_for(&p2), 20);
}

// ===========================================================================
// AttestationStore — register
// ===========================================================================

#[test]
fn store_register_succeeds() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = create_attestation(KeyRole::Signing, 1, 100, 200);
    let id = store
        .register(att, &owner_vk(), DeterministicTimestamp(150), "t")
        .unwrap();
    assert_eq!(store.total_count(), 1);
    assert!(store.get(&id).is_some());
}

#[test]
fn store_register_expired_rejected() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = create_attestation(KeyRole::Signing, 1, 100, 200);
    let err = store
        .register(att, &owner_vk(), DeterministicTimestamp(300), "t")
        .unwrap_err();
    assert!(matches!(err, AttestationError::Expired { .. }));
}

#[test]
fn store_register_at_exact_expiry_accepted() {
    // At exact expiry, not yet expired (strictly greater semantics) — registration succeeds.
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = create_attestation(KeyRole::Signing, 1, 100, 200);
    let id = store
        .register(att, &owner_vk(), DeterministicTimestamp(200), "t")
        .unwrap();
    assert!(!id.as_bytes().is_empty());
}

#[test]
fn store_register_zone_mismatch() {
    let mut store = AttestationStore::new("wrong-zone");
    let att = create_attestation(KeyRole::Signing, 1, 100, 200);
    let err = store
        .register(att, &owner_vk(), DeterministicTimestamp(150), "t")
        .unwrap_err();
    match err {
        AttestationError::ZoneMismatch { expected, actual } => {
            assert_eq!(expected, "wrong-zone");
            assert_eq!(actual, TEST_ZONE);
        }
        other => panic!("expected ZoneMismatch, got {:?}", other),
    }
}

#[test]
fn store_register_nonce_replay() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att1 = create_attestation(KeyRole::Signing, 1, 100, 200);
    store
        .register(att1, &owner_vk(), DeterministicTimestamp(150), "t1")
        .unwrap();
    let att2 = create_attestation(KeyRole::Encryption, 1, 100, 200);
    let err = store
        .register(att2, &owner_vk(), DeterministicTimestamp(150), "t2")
        .unwrap_err();
    assert!(matches!(err, AttestationError::NonceReplay { .. }));
}

#[test]
fn store_register_wrong_signature() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = create_attestation(KeyRole::Signing, 1, 100, 200);
    let wrong = SigningKey::from_bytes([0xFF; 32]);
    let err = store
        .register(
            att,
            &wrong.verification_key(),
            DeterministicTimestamp(150),
            "t",
        )
        .unwrap_err();
    assert!(matches!(err, AttestationError::SignatureInvalid { .. }));
}

#[test]
fn store_register_multiple_attestations() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att1 = create_attestation(KeyRole::Signing, 1, 100, 200);
    let att2 = create_attestation(KeyRole::Encryption, 2, 100, 300);
    let att3 = create_attestation(KeyRole::Issuance, 3, 100, 400);
    store
        .register(att1, &owner_vk(), DeterministicTimestamp(150), "t1")
        .unwrap();
    store
        .register(att2, &owner_vk(), DeterministicTimestamp(150), "t2")
        .unwrap();
    store
        .register(att3, &owner_vk(), DeterministicTimestamp(150), "t3")
        .unwrap();
    assert_eq!(store.total_count(), 3);
    assert_eq!(store.principal_count(), 1);
}

// ===========================================================================
// AttestationStore — query
// ===========================================================================

#[test]
fn store_active_for_principal() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att1 = create_attestation(KeyRole::Signing, 1, 100, 200);
    let att2 = create_attestation(KeyRole::Encryption, 2, 100, 300);
    store
        .register(att1, &owner_vk(), DeterministicTimestamp(150), "t1")
        .unwrap();
    store
        .register(att2, &owner_vk(), DeterministicTimestamp(150), "t2")
        .unwrap();

    let active = store.active_for_principal(&test_principal(), DeterministicTimestamp(150));
    assert_eq!(active.len(), 2);

    let active = store.active_for_principal(&test_principal(), DeterministicTimestamp(250));
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].key_role, KeyRole::Encryption);
}

#[test]
fn store_active_for_role() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att1 = create_attestation(KeyRole::Signing, 1, 100, 200);
    let att2 = create_attestation(KeyRole::Encryption, 2, 100, 200);
    store
        .register(att1, &owner_vk(), DeterministicTimestamp(150), "t1")
        .unwrap();
    store
        .register(att2, &owner_vk(), DeterministicTimestamp(150), "t2")
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

#[test]
fn store_active_for_unknown_principal() {
    let store = AttestationStore::new(TEST_ZONE);
    let unknown = PrincipalId::from_bytes([0xFF; 32]);
    let active = store.active_for_principal(&unknown, DeterministicTimestamp(100));
    assert!(active.is_empty());
}

#[test]
fn store_get_returns_none_for_unknown() {
    let store = AttestationStore::new(TEST_ZONE);
    assert!(store.get(&EngineObjectId([0xFF; 32])).is_none());
}

// ===========================================================================
// AttestationStore — revoke
// ===========================================================================

#[test]
fn store_revoke_succeeds() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = create_attestation(KeyRole::Signing, 1, 100, 200);
    let id = store
        .register(att, &owner_vk(), DeterministicTimestamp(150), "t")
        .unwrap();
    store.revoke(&id, "t-rev").unwrap();
    assert_eq!(store.total_count(), 0);
    assert!(store.get(&id).is_none());
}

#[test]
fn store_revoke_not_found() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let fake_id = EngineObjectId([0xFF; 32]);
    let err = store.revoke(&fake_id, "t").unwrap_err();
    assert!(matches!(err, AttestationError::NotFound { .. }));
}

#[test]
fn store_revoke_cleans_principal_index() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = create_attestation(KeyRole::Signing, 1, 100, 200);
    let id = store
        .register(att, &owner_vk(), DeterministicTimestamp(150), "t")
        .unwrap();
    assert_eq!(store.principal_count(), 1);
    store.revoke(&id, "t-rev").unwrap();
    assert_eq!(store.principal_count(), 0);
}

// ===========================================================================
// AttestationStore — purge_expired
// ===========================================================================

#[test]
fn store_purge_expired_selective() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att1 = create_attestation(KeyRole::Signing, 1, 100, 200);
    let att2 = create_attestation(KeyRole::Encryption, 2, 100, 300);
    let att3 = create_attestation(KeyRole::Issuance, 3, 100, 400);
    store
        .register(att1, &owner_vk(), DeterministicTimestamp(150), "t1")
        .unwrap();
    store
        .register(att2, &owner_vk(), DeterministicTimestamp(150), "t2")
        .unwrap();
    store
        .register(att3, &owner_vk(), DeterministicTimestamp(150), "t3")
        .unwrap();

    assert_eq!(store.purge_expired(DeterministicTimestamp(250), "t"), 1);
    assert_eq!(store.total_count(), 2);

    assert_eq!(store.purge_expired(DeterministicTimestamp(350), "t"), 1);
    assert_eq!(store.total_count(), 1);

    assert_eq!(store.purge_expired(DeterministicTimestamp(450), "t"), 1);
    assert_eq!(store.total_count(), 0);
}

#[test]
fn store_purge_expired_on_empty() {
    let mut store = AttestationStore::new(TEST_ZONE);
    assert_eq!(store.purge_expired(DeterministicTimestamp(1000), "t"), 0);
}

#[test]
fn store_purge_expired_none_expired() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = create_attestation(KeyRole::Signing, 1, 100, 200);
    store
        .register(att, &owner_vk(), DeterministicTimestamp(150), "t")
        .unwrap();
    assert_eq!(store.purge_expired(DeterministicTimestamp(150), "t"), 0);
}

// ===========================================================================
// Audit events
// ===========================================================================

#[test]
fn audit_events_on_register() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = create_attestation(KeyRole::Signing, 1, 100, 200);
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
fn audit_events_on_rejection() {
    let mut store = AttestationStore::new("wrong-zone");
    let att = create_attestation(KeyRole::Signing, 1, 100, 200);
    let _ = store.register(att, &owner_vk(), DeterministicTimestamp(150), "t-rej");
    let events = store.drain_events();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].event_type,
        AttestationEventType::RegistrationRejected { .. }
    ));
}

#[test]
fn audit_events_on_revoke() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = create_attestation(KeyRole::Signing, 1, 100, 200);
    let id = store
        .register(att, &owner_vk(), DeterministicTimestamp(150), "t")
        .unwrap();
    store.drain_events();
    store.revoke(&id, "t-rev").unwrap();
    let events = store.drain_events();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].event_type,
        AttestationEventType::Revoked { .. }
    ));
}

#[test]
fn audit_events_on_purge() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = create_attestation(KeyRole::Signing, 1, 100, 200);
    store
        .register(att, &owner_vk(), DeterministicTimestamp(150), "t")
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
fn audit_drain_clears_events() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = create_attestation(KeyRole::Signing, 1, 100, 200);
    store
        .register(att, &owner_vk(), DeterministicTimestamp(150), "t")
        .unwrap();
    let first = store.drain_events();
    assert_eq!(first.len(), 1);
    let second = store.drain_events();
    assert!(second.is_empty());
}

#[test]
fn audit_event_serde_roundtrip() {
    let ev = AttestationEvent {
        event_type: AttestationEventType::Registered {
            attestation_id: EngineObjectId([0xAA; 32]),
            principal: test_principal(),
        },
        zone: "z".to_string(),
        trace_id: "t".to_string(),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let deser: AttestationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, deser);
}

#[test]
fn audit_event_type_serde_all_variants() {
    let variants: Vec<AttestationEventType> = vec![
        AttestationEventType::Registered {
            attestation_id: EngineObjectId([0x11; 32]),
            principal: test_principal(),
        },
        AttestationEventType::Revoked {
            attestation_id: EngineObjectId([0x22; 32]),
            principal: test_principal(),
        },
        AttestationEventType::RegistrationRejected {
            reason: "test reason".to_string(),
        },
        AttestationEventType::ExpiredPurged { count: 5 },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let deser: AttestationEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, deser);
    }
}

// ===========================================================================
// AttestationError — Display, std::error::Error, serde
// ===========================================================================

#[test]
fn error_display_all_variants() {
    let errors = [
        (
            AttestationError::SelfAttestationRejected,
            "self-attestation rejected",
        ),
        (
            AttestationError::InvalidNonce {
                detail: "bad".to_string(),
            },
            "invalid nonce: bad",
        ),
        (
            AttestationError::SignatureInvalid {
                detail: "wrong".to_string(),
            },
            "signature invalid: wrong",
        ),
        (
            AttestationError::SignatureFailed {
                detail: "fail".to_string(),
            },
            "signature failed: fail",
        ),
        (
            AttestationError::IdDerivationFailed {
                detail: "err".to_string(),
            },
            "id derivation failed: err",
        ),
        (
            AttestationError::DevicePostureInvalid {
                detail: "bad posture".to_string(),
            },
            "device posture invalid: bad posture",
        ),
    ];
    for (err, expected) in &errors {
        assert_eq!(err.to_string(), *expected);
    }
}

#[test]
fn error_display_expired() {
    let err = AttestationError::Expired {
        expires_at: DeterministicTimestamp(100),
        current_time: DeterministicTimestamp(200),
    };
    let s = err.to_string();
    assert!(s.contains("100"));
    assert!(s.contains("200"));
}

#[test]
fn error_display_nonce_replay() {
    let err = AttestationError::NonceReplay {
        principal: test_principal(),
        nonce: AttestationNonce::from_counter(5),
        high_water: 10,
    };
    let s = err.to_string();
    assert!(s.contains("nonce:5"));
    assert!(s.contains("10"));
}

#[test]
fn error_display_invalid_expiry() {
    let err = AttestationError::InvalidExpiry {
        issued_at: DeterministicTimestamp(200),
        expires_at: DeterministicTimestamp(100),
    };
    let s = err.to_string();
    assert!(s.contains("200"));
    assert!(s.contains("100"));
}

#[test]
fn error_display_zone_mismatch() {
    let err = AttestationError::ZoneMismatch {
        expected: "zone-a".to_string(),
        actual: "zone-b".to_string(),
    };
    assert_eq!(
        err.to_string(),
        "zone mismatch: expected=zone-a, actual=zone-b"
    );
}

#[test]
fn error_display_duplicate() {
    let err = AttestationError::DuplicateAttestation {
        attestation_id: EngineObjectId([0xAA; 32]),
    };
    assert!(err.to_string().contains("duplicate"));
}

#[test]
fn error_display_not_found() {
    let err = AttestationError::NotFound {
        attestation_id: EngineObjectId([0xBB; 32]),
    };
    assert!(err.to_string().contains("not found"));
}

#[test]
fn error_std_error_impl() {
    use std::error::Error;
    let err = AttestationError::SelfAttestationRejected;
    let _: &dyn std::error::Error = &err;
    assert!(err.source().is_none());
}

#[test]
fn error_serde_all_variants() {
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
            detail: "x".to_string(),
        },
        AttestationError::SignatureInvalid {
            detail: "y".to_string(),
        },
        AttestationError::SignatureFailed {
            detail: "z".to_string(),
        },
        AttestationError::IdDerivationFailed {
            detail: "w".to_string(),
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
            attestation_id: EngineObjectId([0x11; 32]),
        },
        AttestationError::NotFound {
            attestation_id: EngineObjectId([0x22; 32]),
        },
        AttestationError::DevicePostureInvalid {
            detail: "dp".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let deser: AttestationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, deser);
    }
}

// ===========================================================================
// KeyAttestation — serde, Display
// ===========================================================================

#[test]
fn attestation_serde_roundtrip() {
    let att = create_attestation(KeyRole::Signing, 1, 100, 200);
    let json = serde_json::to_string(&att).unwrap();
    let deser: KeyAttestation = serde_json::from_str(&json).unwrap();
    assert_eq!(att, deser);
}

#[test]
fn attestation_with_posture_serde_roundtrip() {
    let att = KeyAttestation::create_signed(
        &owner_signing_key(),
        CreateAttestationInput {
            principal_id: test_principal(),
            attested_key: attested_vk(),
            key_role: KeyRole::Encryption,
            issued_at: DeterministicTimestamp(100),
            expires_at: DeterministicTimestamp(200),
            epoch: SecurityEpoch::from_raw(2),
            nonce: AttestationNonce::from_counter(1),
            device_posture: Some(DevicePosture {
                posture_type: "tpm2".to_string(),
                evidence: vec![1, 2, 3],
            }),
            zone: TEST_ZONE,
        },
    )
    .unwrap();
    let json = serde_json::to_string(&att).unwrap();
    let deser: KeyAttestation = serde_json::from_str(&json).unwrap();
    assert_eq!(att, deser);
}

#[test]
fn attestation_display() {
    let att = create_attestation(KeyRole::Signing, 1, 100, 200);
    let s = att.to_string();
    assert!(s.contains("KeyAttestation"));
    assert!(s.contains("signing"));
    assert!(s.contains("nonce:1"));
}

// ===========================================================================
// Schema determinism
// ===========================================================================

#[test]
fn schema_deterministic() {
    let s1 = attestation_schema();
    let s2 = attestation_schema();
    assert_eq!(s1, s2);
}

#[test]
fn schema_id_deterministic() {
    let s1 = attestation_schema_id();
    let s2 = attestation_schema_id();
    assert_eq!(s1, s2);
}

// ===========================================================================
// AttestationStore — serde
// ===========================================================================

// Note: AttestationStore has BTreeMap<EngineObjectId, _> and BTreeMap<PrincipalId, _>
// which have non-string keys — JSON serde is not supported. Tested via bincode or
// similar format in the unit tests instead.

// ===========================================================================
// Integration — full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_create_verify_rotate_revoke() {
    let mut store = AttestationStore::new(TEST_ZONE);

    // Create and register initial attestation.
    let att1 = create_attestation(KeyRole::Signing, 1, 100, 500);
    let id1 = store
        .register(att1, &owner_vk(), DeterministicTimestamp(150), "t-create")
        .unwrap();
    assert_eq!(
        store
            .active_for_principal(&test_principal(), DeterministicTimestamp(200))
            .len(),
        1
    );

    // Rotate: new key, higher nonce.
    let new_key = SigningKey::from_bytes([0x03; 32]);
    let new_vk = new_key.verification_key();
    let att2 = KeyAttestation::create_signed(
        &owner_signing_key(),
        CreateAttestationInput {
            principal_id: test_principal(),
            attested_key: new_vk,
            key_role: KeyRole::Signing,
            issued_at: DeterministicTimestamp(300),
            expires_at: DeterministicTimestamp(600),
            epoch: SecurityEpoch::from_raw(2),
            nonce: AttestationNonce::from_counter(2),
            device_posture: None,
            zone: TEST_ZONE,
        },
    )
    .unwrap();
    let id2 = store
        .register(att2, &owner_vk(), DeterministicTimestamp(350), "t-rotate")
        .unwrap();
    assert_eq!(
        store
            .active_for_principal(&test_principal(), DeterministicTimestamp(400))
            .len(),
        2
    );

    // Revoke old.
    store.revoke(&id1, "t-revoke").unwrap();
    let active = store.active_for_principal(&test_principal(), DeterministicTimestamp(400));
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].attestation_id, id2);
}

#[test]
fn multiple_principals_isolated() {
    let mut store = AttestationStore::new(TEST_ZONE);

    // Principal 1.
    let att1 = create_attestation(KeyRole::Signing, 1, 100, 200);
    store
        .register(att1, &owner_vk(), DeterministicTimestamp(150), "t-p1")
        .unwrap();

    // Principal 2.
    let p2_owner = SigningKey::from_bytes([0x10; 32]);
    let p2_owner_vk = p2_owner.verification_key();
    let p2_principal = PrincipalId::from_verification_key(&p2_owner_vk);
    let p2_attested = SigningKey::from_bytes([0x20; 32]);
    let att2 = KeyAttestation::create_signed(
        &p2_owner,
        CreateAttestationInput {
            principal_id: p2_principal.clone(),
            attested_key: p2_attested.verification_key(),
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
fn deterministic_100_creations() {
    let first = create_attestation(KeyRole::Signing, 1, 100, 200);
    for _ in 0..100 {
        let att = create_attestation(KeyRole::Signing, 1, 100, 200);
        assert_eq!(att.attestation_id, first.attestation_id);
        assert_eq!(att.owner_signature, first.owner_signature);
    }
}

#[test]
fn attestation_id_hex_roundtrip() {
    let att = create_attestation(KeyRole::Signing, 1, 100, 200);
    let hex = att.attestation_id.to_hex();
    let recovered = EngineObjectId::from_hex(&hex).unwrap();
    assert_eq!(att.attestation_id, recovered);
}
