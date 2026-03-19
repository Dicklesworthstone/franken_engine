//! Enrichment integration tests for `key_attestation`.
//!
//! Covers: AttestationNonce serde/Display, DevicePosture serde/ordering,
//! KeyAttestation creation/signing/verification, NonceRegistry replay
//! detection, AttestationStore lifecycle (register/revoke/purge/epoch),
//! AttestationError serde, AttestationEvent serde, boundary conditions,
//! determinism, and full lifecycle scenarios.

#![allow(clippy::too_many_arguments)]

use frankenengine_engine::key_attestation::{
    AttestationError, AttestationEvent, AttestationEventType, AttestationNonce, AttestationStore,
    CreateAttestationInput, DevicePosture, KeyAttestation, NonceRegistry, attestation_schema,
    attestation_schema_id,
};
use frankenengine_engine::capability_token::PrincipalId;
use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::principal_key_roles::KeyRole;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{SigningKey, VerificationKey};

// ===========================================================================
// Helpers
// ===========================================================================

const TEST_ZONE: &str = "integ-zone";

fn owner_sk() -> SigningKey {
    SigningKey::from_bytes([0x11; 32])
}

fn owner_vk() -> VerificationKey {
    owner_sk().verification_key()
}

fn attested_sk() -> SigningKey {
    SigningKey::from_bytes([0x22; 32])
}

fn attested_vk() -> VerificationKey {
    attested_sk().verification_key()
}

fn principal() -> PrincipalId {
    PrincipalId::from_verification_key(&owner_vk())
}

fn make_att(role: KeyRole, nonce: u64, issued: u64, expires: u64) -> KeyAttestation {
    KeyAttestation::create_signed(
        &owner_sk(),
        CreateAttestationInput {
            principal_id: principal(),
            attested_key: attested_vk(),
            key_role: role,
            issued_at: DeterministicTimestamp(issued),
            expires_at: DeterministicTimestamp(expires),
            epoch: SecurityEpoch::from_raw(1),
            nonce: AttestationNonce::from_counter(nonce),
            device_posture: None,
            zone: TEST_ZONE,
        },
    )
    .expect("create attestation")
}

fn make_att_with_posture(nonce: u64) -> KeyAttestation {
    KeyAttestation::create_signed(
        &owner_sk(),
        CreateAttestationInput {
            principal_id: principal(),
            attested_key: attested_vk(),
            key_role: KeyRole::Signing,
            issued_at: DeterministicTimestamp(100),
            expires_at: DeterministicTimestamp(500),
            epoch: SecurityEpoch::from_raw(1),
            nonce: AttestationNonce::from_counter(nonce),
            device_posture: Some(DevicePosture {
                posture_type: "tpm2".to_string(),
                evidence: vec![0xDE, 0xAD, 0xBE, 0xEF],
            }),
            zone: TEST_ZONE,
        },
    )
    .expect("create attestation with posture")
}

// ===========================================================================
// AttestationNonce tests
// ===========================================================================

#[test]
fn integ_nonce_serde_roundtrip_boundary_values() {
    for val in [0u64, 1, u64::MAX / 2, u64::MAX] {
        let nonce = AttestationNonce::from_counter(val);
        let json = serde_json::to_string(&nonce).unwrap();
        let back: AttestationNonce = serde_json::from_str(&json).unwrap();
        assert_eq!(nonce, back);
        assert_eq!(back.as_u64(), val);
    }
}

#[test]
fn integ_nonce_display_format() {
    assert_eq!(AttestationNonce::from_counter(0).to_string(), "nonce:0");
    assert_eq!(AttestationNonce::from_counter(999).to_string(), "nonce:999");
}

#[test]
fn integ_nonce_ordering_consistent() {
    let n1 = AttestationNonce::from_counter(1);
    let n2 = AttestationNonce::from_counter(100);
    let n3 = AttestationNonce::from_counter(u64::MAX);
    assert!(n1 < n2);
    assert!(n2 < n3);
    assert!(n1 < n3);
}

// ===========================================================================
// DevicePosture tests
// ===========================================================================

#[test]
fn integ_device_posture_serde_roundtrip() {
    let dp = DevicePosture {
        posture_type: "sgx-enclave".to_string(),
        evidence: vec![0x01, 0x02, 0xFF],
    };
    let json = serde_json::to_string(&dp).unwrap();
    let back: DevicePosture = serde_json::from_str(&json).unwrap();
    assert_eq!(dp, back);
}

#[test]
fn integ_device_posture_empty_evidence() {
    let dp = DevicePosture {
        posture_type: "trustzone".to_string(),
        evidence: vec![],
    };
    let json = serde_json::to_string(&dp).unwrap();
    let back: DevicePosture = serde_json::from_str(&json).unwrap();
    assert_eq!(dp, back);
    assert!(back.evidence.is_empty());
}

#[test]
fn integ_device_posture_ordering_by_type_then_evidence() {
    let a = DevicePosture {
        posture_type: "aaa".to_string(),
        evidence: vec![0xFF],
    };
    let b = DevicePosture {
        posture_type: "zzz".to_string(),
        evidence: vec![0x00],
    };
    assert!(a < b);
}

// ===========================================================================
// KeyAttestation creation tests
// ===========================================================================

#[test]
fn integ_create_attestation_deterministic_id_and_sig() {
    let a1 = make_att(KeyRole::Signing, 1, 100, 500);
    let a2 = make_att(KeyRole::Signing, 1, 100, 500);
    assert_eq!(a1.attestation_id, a2.attestation_id);
    assert_eq!(a1.owner_signature, a2.owner_signature);
}

#[test]
fn integ_different_roles_yield_different_ids() {
    let att_sign = make_att(KeyRole::Signing, 1, 100, 500);
    let att_enc = make_att(KeyRole::Encryption, 1, 100, 500);
    assert_ne!(att_sign.attestation_id, att_enc.attestation_id);
}

#[test]
fn integ_different_nonces_yield_different_ids() {
    let a1 = make_att(KeyRole::Signing, 1, 100, 500);
    let a2 = make_att(KeyRole::Signing, 2, 100, 500);
    assert_ne!(a1.attestation_id, a2.attestation_id);
    assert_ne!(a1.owner_signature, a2.owner_signature);
}

#[test]
fn integ_create_self_attestation_rejected() {
    let sk = owner_sk();
    let vk = sk.verification_key();
    let result = KeyAttestation::create_signed(
        &sk,
        CreateAttestationInput {
            principal_id: principal(),
            attested_key: vk,
            key_role: KeyRole::Signing,
            issued_at: DeterministicTimestamp(100),
            expires_at: DeterministicTimestamp(500),
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
fn integ_invalid_expiry_rejected() {
    let result = KeyAttestation::create_signed(
        &owner_sk(),
        CreateAttestationInput {
            principal_id: principal(),
            attested_key: attested_vk(),
            key_role: KeyRole::Signing,
            issued_at: DeterministicTimestamp(500),
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
fn integ_equal_issued_and_expires_rejected() {
    let result = KeyAttestation::create_signed(
        &owner_sk(),
        CreateAttestationInput {
            principal_id: principal(),
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

// ===========================================================================
// Signature verification tests
// ===========================================================================

#[test]
fn integ_verify_owner_signature_succeeds() {
    let att = make_att(KeyRole::Signing, 1, 100, 500);
    att.verify_owner_signature(&owner_vk()).unwrap();
}

#[test]
fn integ_verify_wrong_key_fails() {
    let att = make_att(KeyRole::Signing, 1, 100, 500);
    let wrong_sk = SigningKey::from_bytes([0xCC; 32]);
    let wrong_vk = wrong_sk.verification_key();
    let result = att.verify_owner_signature(&wrong_vk);
    assert!(matches!(
        result,
        Err(AttestationError::SignatureInvalid { .. })
    ));
}

#[test]
fn integ_verify_with_attested_key_as_owner_rejected() {
    let att = make_att(KeyRole::Signing, 1, 100, 500);
    let result = att.verify_owner_signature(&attested_vk());
    assert!(matches!(
        result,
        Err(AttestationError::SelfAttestationRejected)
    ));
}

// ===========================================================================
// Expiry tests
// ===========================================================================

#[test]
fn integ_is_expired_boundary() {
    let att = make_att(KeyRole::Signing, 1, 100, 500);
    assert!(!att.is_expired(DeterministicTimestamp(499)));
    assert!(!att.is_expired(DeterministicTimestamp(500))); // at boundary
    assert!(att.is_expired(DeterministicTimestamp(501)));
}

// ===========================================================================
// KeyAttestation serde tests
// ===========================================================================

#[test]
fn integ_attestation_serde_roundtrip_no_posture() {
    let att = make_att(KeyRole::Encryption, 5, 100, 1000);
    let json = serde_json::to_string(&att).unwrap();
    let back: KeyAttestation = serde_json::from_str(&json).unwrap();
    assert_eq!(att, back);
}

#[test]
fn integ_attestation_serde_roundtrip_with_posture() {
    let att = make_att_with_posture(3);
    let json = serde_json::to_string(&att).unwrap();
    let back: KeyAttestation = serde_json::from_str(&json).unwrap();
    assert_eq!(att, back);
    assert!(back.device_posture.is_some());
}

#[test]
fn integ_attestation_json_fields_present() {
    let att = make_att(KeyRole::Signing, 1, 100, 500);
    let json: serde_json::Value = serde_json::to_value(&att).unwrap();
    for field in [
        "attestation_id",
        "principal_id",
        "attested_key",
        "key_role",
        "issued_at",
        "expires_at",
        "epoch",
        "nonce",
        "device_posture",
        "owner_signature",
        "zone",
    ] {
        assert!(json.get(field).is_some(), "missing field: {field}");
    }
}

// ===========================================================================
// NonceRegistry tests
// ===========================================================================

#[test]
fn integ_nonce_registry_fresh_accepts_nonce() {
    let mut reg = NonceRegistry::new();
    reg.check_and_record(&principal(), AttestationNonce::from_counter(1))
        .unwrap();
    assert_eq!(reg.high_water_for(&principal()), 1);
}

#[test]
fn integ_nonce_registry_monotonic_sequence() {
    let mut reg = NonceRegistry::new();
    for i in 1..=10 {
        reg.check_and_record(&principal(), AttestationNonce::from_counter(i))
            .unwrap();
    }
    assert_eq!(reg.high_water_for(&principal()), 10);
}

#[test]
fn integ_nonce_registry_gap_accepted() {
    let mut reg = NonceRegistry::new();
    reg.check_and_record(&principal(), AttestationNonce::from_counter(1))
        .unwrap();
    reg.check_and_record(&principal(), AttestationNonce::from_counter(1000))
        .unwrap();
    assert_eq!(reg.high_water_for(&principal()), 1000);
}

#[test]
fn integ_nonce_registry_replay_rejected() {
    let mut reg = NonceRegistry::new();
    reg.check_and_record(&principal(), AttestationNonce::from_counter(5))
        .unwrap();
    let err = reg
        .check_and_record(&principal(), AttestationNonce::from_counter(5))
        .unwrap_err();
    assert!(matches!(err, AttestationError::NonceReplay { .. }));
}

#[test]
fn integ_nonce_registry_lower_nonce_rejected() {
    let mut reg = NonceRegistry::new();
    reg.check_and_record(&principal(), AttestationNonce::from_counter(10))
        .unwrap();
    let err = reg
        .check_and_record(&principal(), AttestationNonce::from_counter(3))
        .unwrap_err();
    assert!(matches!(err, AttestationError::NonceReplay { .. }));
}

#[test]
fn integ_nonce_registry_zero_nonce_rejected() {
    let mut reg = NonceRegistry::new();
    let err = reg
        .check_and_record(&principal(), AttestationNonce::from_counter(0))
        .unwrap_err();
    assert!(matches!(err, AttestationError::InvalidNonce { .. }));
}

#[test]
fn integ_nonce_registry_serde_roundtrip() {
    let mut reg = NonceRegistry::new();
    let p1 = principal();
    let p2 = PrincipalId::from_bytes([0xAA; 32]);
    reg.check_and_record(&p1, AttestationNonce::from_counter(10))
        .unwrap();
    reg.check_and_record(&p2, AttestationNonce::from_counter(20))
        .unwrap();
    let json = serde_json::to_string(&reg).unwrap();
    let back: NonceRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.high_water_for(&p1), 10);
    assert_eq!(back.high_water_for(&p2), 20);
    assert_eq!(back.principal_count(), 2);
}

#[test]
fn integ_nonce_registry_per_principal_isolation() {
    let mut reg = NonceRegistry::new();
    let p1 = principal();
    let p2 = PrincipalId::from_bytes([0xBB; 32]);
    reg.check_and_record(&p1, AttestationNonce::from_counter(100))
        .unwrap();
    reg.check_and_record(&p2, AttestationNonce::from_counter(5))
        .unwrap();
    assert_eq!(reg.high_water_for(&p1), 100);
    assert_eq!(reg.high_water_for(&p2), 5);
    assert_eq!(reg.principal_count(), 2);
}

// ===========================================================================
// AttestationStore tests
// ===========================================================================

#[test]
fn integ_store_register_and_get() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = make_att(KeyRole::Signing, 1, 100, 500);
    let id = store
        .register(att.clone(), &owner_vk(), DeterministicTimestamp(150), "t")
        .unwrap();
    let got = store.get(&id).unwrap();
    assert_eq!(got.attestation_id, att.attestation_id);
    assert_eq!(store.total_count(), 1);
    assert_eq!(store.principal_count(), 1);
}

#[test]
fn integ_store_zone_mismatch_rejected() {
    let mut store = AttestationStore::new("other-zone");
    let att = make_att(KeyRole::Signing, 1, 100, 500);
    let result = store.register(att, &owner_vk(), DeterministicTimestamp(150), "t");
    assert!(matches!(result, Err(AttestationError::ZoneMismatch { .. })));
}

#[test]
fn integ_store_expired_rejected() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = make_att(KeyRole::Signing, 1, 100, 200);
    let result = store.register(att, &owner_vk(), DeterministicTimestamp(300), "t");
    assert!(matches!(result, Err(AttestationError::Expired { .. })));
}

#[test]
fn integ_store_nonce_replay_rejected() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att1 = make_att(KeyRole::Signing, 1, 100, 500);
    store
        .register(att1, &owner_vk(), DeterministicTimestamp(150), "t1")
        .unwrap();
    let att2 = make_att(KeyRole::Encryption, 1, 100, 500);
    let result = store.register(att2, &owner_vk(), DeterministicTimestamp(150), "t2");
    assert!(matches!(result, Err(AttestationError::NonceReplay { .. })));
}

#[test]
fn integ_store_active_for_principal_filters_by_expiry() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att1 = make_att(KeyRole::Signing, 1, 100, 300);
    let att2 = make_att(KeyRole::Encryption, 2, 100, 600);
    store
        .register(att1, &owner_vk(), DeterministicTimestamp(150), "t1")
        .unwrap();
    store
        .register(att2, &owner_vk(), DeterministicTimestamp(150), "t2")
        .unwrap();
    // Both active
    assert_eq!(
        store
            .active_for_principal(&principal(), DeterministicTimestamp(200))
            .len(),
        2
    );
    // Only att2 active after att1 expires
    assert_eq!(
        store
            .active_for_principal(&principal(), DeterministicTimestamp(400))
            .len(),
        1
    );
}

#[test]
fn integ_store_active_for_role() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att1 = make_att(KeyRole::Signing, 1, 100, 500);
    let att2 = make_att(KeyRole::Encryption, 2, 100, 500);
    store
        .register(att1, &owner_vk(), DeterministicTimestamp(150), "t1")
        .unwrap();
    store
        .register(att2, &owner_vk(), DeterministicTimestamp(150), "t2")
        .unwrap();

    let signing = store.active_for_role(&principal(), KeyRole::Signing, DeterministicTimestamp(200));
    assert_eq!(signing.len(), 1);
    assert_eq!(signing[0].key_role, KeyRole::Signing);

    let issuance =
        store.active_for_role(&principal(), KeyRole::Issuance, DeterministicTimestamp(200));
    assert!(issuance.is_empty());
}

#[test]
fn integ_store_revoke_removes_attestation() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = make_att(KeyRole::Signing, 1, 100, 500);
    let id = store
        .register(att, &owner_vk(), DeterministicTimestamp(150), "t")
        .unwrap();
    store.revoke(&id, "t-revoke").unwrap();
    assert_eq!(store.total_count(), 0);
    assert!(store.get(&id).is_none());
}

#[test]
fn integ_store_revoke_not_found() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let fake_id = EngineObjectId([0xFF; 32]);
    let result = store.revoke(&fake_id, "t-revoke");
    assert!(matches!(result, Err(AttestationError::NotFound { .. })));
}

#[test]
fn integ_store_purge_expired() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att1 = make_att(KeyRole::Signing, 1, 100, 200);
    let att2 = make_att(KeyRole::Encryption, 2, 100, 400);
    store
        .register(att1, &owner_vk(), DeterministicTimestamp(150), "t1")
        .unwrap();
    store
        .register(att2, &owner_vk(), DeterministicTimestamp(150), "t2")
        .unwrap();
    let purged = store.purge_expired(DeterministicTimestamp(300), "t-purge");
    assert_eq!(purged, 1); // only att1 expired
    assert_eq!(store.total_count(), 1);
}

#[test]
fn integ_store_purge_clears_principal_index() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = make_att(KeyRole::Signing, 1, 100, 200);
    store
        .register(att, &owner_vk(), DeterministicTimestamp(150), "t")
        .unwrap();
    store.purge_expired(DeterministicTimestamp(300), "t-purge");
    assert_eq!(store.principal_count(), 0);
}

// ===========================================================================
// AttestationError serde tests
// ===========================================================================

#[test]
fn integ_error_serde_all_variants() {
    let errors: Vec<AttestationError> = vec![
        AttestationError::SelfAttestationRejected,
        AttestationError::Expired {
            expires_at: DeterministicTimestamp(100),
            current_time: DeterministicTimestamp(200),
        },
        AttestationError::NonceReplay {
            principal: principal(),
            nonce: AttestationNonce::from_counter(5),
            high_water: 10,
        },
        AttestationError::InvalidNonce {
            detail: "zero".into(),
        },
        AttestationError::SignatureInvalid {
            detail: "bad".into(),
        },
        AttestationError::SignatureFailed {
            detail: "fail".into(),
        },
        AttestationError::IdDerivationFailed {
            detail: "err".into(),
        },
        AttestationError::InvalidExpiry {
            issued_at: DeterministicTimestamp(500),
            expires_at: DeterministicTimestamp(100),
        },
        AttestationError::ZoneMismatch {
            expected: "a".into(),
            actual: "b".into(),
        },
        AttestationError::DuplicateAttestation {
            attestation_id: EngineObjectId([0xAA; 32]),
        },
        AttestationError::NotFound {
            attestation_id: EngineObjectId([0xBB; 32]),
        },
        AttestationError::DevicePostureInvalid {
            detail: "bad".into(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: AttestationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn integ_error_display_all_unique() {
    let errors: Vec<AttestationError> = vec![
        AttestationError::SelfAttestationRejected,
        AttestationError::Expired {
            expires_at: DeterministicTimestamp(100),
            current_time: DeterministicTimestamp(200),
        },
        AttestationError::InvalidNonce {
            detail: "zero".into(),
        },
        AttestationError::ZoneMismatch {
            expected: "a".into(),
            actual: "b".into(),
        },
        AttestationError::NotFound {
            attestation_id: EngineObjectId([0xBB; 32]),
        },
        AttestationError::DevicePostureInvalid {
            detail: "bad".into(),
        },
    ];
    let mut displays = std::collections::BTreeSet::new();
    for err in &errors {
        displays.insert(err.to_string());
    }
    assert_eq!(displays.len(), errors.len());
}

// ===========================================================================
// AttestationEvent serde tests
// ===========================================================================

#[test]
fn integ_event_serde_all_variants() {
    let events: Vec<AttestationEventType> = vec![
        AttestationEventType::Registered {
            attestation_id: EngineObjectId([0x11; 32]),
            principal: principal(),
        },
        AttestationEventType::Revoked {
            attestation_id: EngineObjectId([0x22; 32]),
            principal: principal(),
        },
        AttestationEventType::RegistrationRejected {
            reason: "zone mismatch".into(),
        },
        AttestationEventType::ExpiredPurged { count: 5 },
    ];
    for evt in &events {
        let json = serde_json::to_string(evt).unwrap();
        let back: AttestationEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*evt, back);
    }
}

#[test]
fn integ_event_serde_full() {
    let event = AttestationEvent {
        event_type: AttestationEventType::Registered {
            attestation_id: EngineObjectId([0x33; 32]),
            principal: principal(),
        },
        zone: TEST_ZONE.to_string(),
        trace_id: "trace-42".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: AttestationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ===========================================================================
// Audit event emission tests
// ===========================================================================

#[test]
fn integ_store_events_on_register() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = make_att(KeyRole::Signing, 1, 100, 500);
    store
        .register(att, &owner_vk(), DeterministicTimestamp(150), "trace-reg")
        .unwrap();
    let events = store.drain_events();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].event_type,
        AttestationEventType::Registered { .. }
    ));
    assert_eq!(events[0].trace_id, "trace-reg");
}

#[test]
fn integ_store_events_on_zone_rejection() {
    let mut store = AttestationStore::new("wrong");
    let att = make_att(KeyRole::Signing, 1, 100, 500);
    let _ = store.register(att, &owner_vk(), DeterministicTimestamp(150), "trace-rej");
    let events = store.drain_events();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].event_type,
        AttestationEventType::RegistrationRejected { .. }
    ));
}

#[test]
fn integ_store_events_on_revoke() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = make_att(KeyRole::Signing, 1, 100, 500);
    let id = store
        .register(att, &owner_vk(), DeterministicTimestamp(150), "t")
        .unwrap();
    store.drain_events();
    store.revoke(&id, "trace-rev").unwrap();
    let events = store.drain_events();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].event_type,
        AttestationEventType::Revoked { .. }
    ));
}

#[test]
fn integ_store_events_on_purge() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = make_att(KeyRole::Signing, 1, 100, 200);
    store
        .register(att, &owner_vk(), DeterministicTimestamp(150), "t")
        .unwrap();
    store.drain_events();
    store.purge_expired(DeterministicTimestamp(300), "trace-purge");
    let events = store.drain_events();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].event_type,
        AttestationEventType::ExpiredPurged { count: 1 }
    ));
}

#[test]
fn integ_store_drain_events_clears() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att = make_att(KeyRole::Signing, 1, 100, 500);
    store
        .register(att, &owner_vk(), DeterministicTimestamp(150), "t")
        .unwrap();
    assert_eq!(store.drain_events().len(), 1);
    assert!(store.drain_events().is_empty());
}

// ===========================================================================
// Full lifecycle tests
// ===========================================================================

#[test]
fn integ_full_lifecycle_create_verify_rotate_revoke() {
    let mut store = AttestationStore::new(TEST_ZONE);

    // Register initial
    let att1 = make_att(KeyRole::Signing, 1, 100, 800);
    let id1 = store
        .register(att1, &owner_vk(), DeterministicTimestamp(150), "t1")
        .unwrap();
    assert_eq!(store.total_count(), 1);

    // Rotate with different key and higher nonce
    let new_sk = SigningKey::from_bytes([0x33; 32]);
    let new_vk = new_sk.verification_key();
    let att2 = KeyAttestation::create_signed(
        &owner_sk(),
        CreateAttestationInput {
            principal_id: principal(),
            attested_key: new_vk,
            key_role: KeyRole::Signing,
            issued_at: DeterministicTimestamp(300),
            expires_at: DeterministicTimestamp(900),
            epoch: SecurityEpoch::from_raw(2),
            nonce: AttestationNonce::from_counter(2),
            device_posture: None,
            zone: TEST_ZONE,
        },
    )
    .unwrap();
    let _id2 = store
        .register(att2, &owner_vk(), DeterministicTimestamp(350), "t2")
        .unwrap();
    assert_eq!(store.total_count(), 2);

    // Revoke old
    store.revoke(&id1, "t3").unwrap();
    assert_eq!(store.total_count(), 1);
}

#[test]
fn integ_schema_determinism() {
    let s1 = attestation_schema();
    let s2 = attestation_schema();
    assert_eq!(s1, s2);
    let id1 = attestation_schema_id();
    let id2 = attestation_schema_id();
    assert_eq!(id1, id2);
}

#[test]
fn integ_empty_store_queries() {
    let store = AttestationStore::new(TEST_ZONE);
    assert_eq!(store.total_count(), 0);
    assert_eq!(store.principal_count(), 0);
    let active = store.active_for_principal(&principal(), DeterministicTimestamp(100));
    assert!(active.is_empty());
}

#[test]
fn integ_store_clone_preserves_state() {
    let mut store = AttestationStore::new(TEST_ZONE);
    let att1 = make_att(KeyRole::Signing, 1, 100, 500);
    let att2 = make_att(KeyRole::Encryption, 2, 100, 600);
    let id1 = store
        .register(att1, &owner_vk(), DeterministicTimestamp(150), "t1")
        .unwrap();
    let id2 = store
        .register(att2, &owner_vk(), DeterministicTimestamp(150), "t2")
        .unwrap();
    let cloned = store.clone();
    assert_eq!(cloned.total_count(), 2);
    assert!(cloned.get(&id1).is_some());
    assert!(cloned.get(&id2).is_some());
}

#[test]
fn integ_attestation_display() {
    let att = make_att(KeyRole::Encryption, 7, 100, 999);
    let display = att.to_string();
    assert!(display.contains("KeyAttestation"));
    assert!(display.contains("nonce:7"));
    assert!(display.contains("999"));
}

#[test]
fn integ_attestation_id_hex_roundtrip() {
    let att = make_att(KeyRole::Signing, 1, 100, 500);
    let hex = att.attestation_id.to_hex();
    let recovered = EngineObjectId::from_hex(&hex).unwrap();
    assert_eq!(att.attestation_id, recovered);
}

#[test]
fn integ_device_posture_changes_signature() {
    let att_no = make_att(KeyRole::Signing, 1, 100, 500);
    let att_with = make_att_with_posture(1);
    assert_ne!(att_no.owner_signature, att_with.owner_signature);
}
