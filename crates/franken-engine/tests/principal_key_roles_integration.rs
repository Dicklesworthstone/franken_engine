//! Integration tests for the `principal_key_roles` module.
//!
//! Covers key-role separation, lifecycle management, owner-key bundles,
//! serde roundtrips, and adversarial role-enforcement scenarios that
//! complement the inline unit tests.

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

use frankenengine_engine::principal_key_roles::{
    self, EncryptionPrivateKey, EncryptionPublicKey, KeyRole, KeyRoleError, KeyStatus,
    OwnerKeyBundle, PrincipalKeyStore, RoleKeyEntry,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{SigningKey, VerificationKey};

// ---------------------------------------------------------------------------
// Helpers — mirror the inline test helpers using the public API
// ---------------------------------------------------------------------------

fn test_seed() -> [u8; 32] {
    [0xAA; 32]
}

fn make_signing_key(seed: &[u8; 32], epoch: SecurityEpoch) -> SigningKey {
    let derived = principal_key_roles::derive_role_key(seed, KeyRole::Signing, epoch);
    SigningKey::from_bytes(derived)
}

fn make_encryption_private(seed: &[u8; 32], epoch: SecurityEpoch) -> EncryptionPrivateKey {
    let derived = principal_key_roles::derive_role_key(seed, KeyRole::Encryption, epoch);
    EncryptionPrivateKey::from_bytes(derived)
}

fn make_issuance_key(seed: &[u8; 32], epoch: SecurityEpoch) -> SigningKey {
    let derived = principal_key_roles::derive_role_key(seed, KeyRole::Issuance, epoch);
    SigningKey::from_bytes(derived)
}

fn make_role_entry(
    role: KeyRole,
    vk: VerificationKey,
    enc_pk: Option<EncryptionPublicKey>,
    status: KeyStatus,
    epoch: SecurityEpoch,
    seq: u64,
) -> RoleKeyEntry {
    RoleKeyEntry {
        role,
        verification_key: vk,
        encryption_public_key: enc_pk,
        status,
        created_epoch: epoch,
        activated_epoch: if status == KeyStatus::Active {
            Some(epoch)
        } else {
            None
        },
        revoked_epoch: None,
        sequence: seq,
    }
}

// ---------------------------------------------------------------------------
// KeyRole serde & display
// ---------------------------------------------------------------------------

#[test]
fn key_role_serde_roundtrip_all_variants() {
    for role in KeyRole::ALL {
        let json = serde_json::to_string(role).unwrap();
        let back: KeyRole = serde_json::from_str(&json).unwrap();
        assert_eq!(*role, back);
    }
}

#[test]
fn key_role_display_all_variants() {
    assert_eq!(KeyRole::Signing.to_string(), "signing");
    assert_eq!(KeyRole::Encryption.to_string(), "encryption");
    assert_eq!(KeyRole::Issuance.to_string(), "issuance");
}

#[test]
fn key_role_all_constant_has_three_entries() {
    assert_eq!(KeyRole::ALL.len(), 3);
    assert!(KeyRole::ALL.contains(&KeyRole::Signing));
    assert!(KeyRole::ALL.contains(&KeyRole::Encryption));
    assert!(KeyRole::ALL.contains(&KeyRole::Issuance));
}

#[test]
fn key_role_derivation_domains_are_distinct() {
    let domains: Vec<&[u8]> = KeyRole::ALL.iter().map(|r| r.derivation_domain()).collect();
    for i in 0..domains.len() {
        for j in (i + 1)..domains.len() {
            assert_ne!(domains[i], domains[j], "roles {i} and {j} share a domain");
        }
    }
}

// ---------------------------------------------------------------------------
// KeyStatus serde, display, and semantics
// ---------------------------------------------------------------------------

#[test]
fn key_status_serde_roundtrip_all_variants() {
    let statuses = [
        KeyStatus::Pending,
        KeyStatus::Active,
        KeyStatus::Rotated,
        KeyStatus::Revoked,
        KeyStatus::Expired,
    ];
    for status in &statuses {
        let json = serde_json::to_string(status).unwrap();
        let back: KeyStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*status, back);
    }
}

#[test]
fn key_status_display_all_variants() {
    assert_eq!(KeyStatus::Pending.to_string(), "pending");
    assert_eq!(KeyStatus::Active.to_string(), "active");
    assert_eq!(KeyStatus::Rotated.to_string(), "rotated");
    assert_eq!(KeyStatus::Revoked.to_string(), "revoked");
    assert_eq!(KeyStatus::Expired.to_string(), "expired");
}

#[test]
fn key_status_allows_creation_only_active() {
    assert!(!KeyStatus::Pending.allows_creation());
    assert!(KeyStatus::Active.allows_creation());
    assert!(!KeyStatus::Rotated.allows_creation());
    assert!(!KeyStatus::Revoked.allows_creation());
    assert!(!KeyStatus::Expired.allows_creation());
}

#[test]
fn key_status_allows_verification_active_and_rotated() {
    assert!(!KeyStatus::Pending.allows_verification());
    assert!(KeyStatus::Active.allows_verification());
    assert!(KeyStatus::Rotated.allows_verification());
    assert!(!KeyStatus::Revoked.allows_verification());
    assert!(!KeyStatus::Expired.allows_verification());
}

// ---------------------------------------------------------------------------
// EncryptionPublicKey / EncryptionPrivateKey
// ---------------------------------------------------------------------------

#[test]
fn encryption_public_key_serde_roundtrip() {
    let pk = EncryptionPublicKey::from_bytes([0x42; 32]);
    let json = serde_json::to_string(&pk).unwrap();
    let back: EncryptionPublicKey = serde_json::from_str(&json).unwrap();
    assert_eq!(pk, back);
}

#[test]
fn encryption_public_key_display_full_hex() {
    let pk = EncryptionPublicKey::from_bytes([0xAB; 32]);
    let s = pk.to_string();
    assert_eq!(s.len(), 64); // 32 bytes × 2 hex chars
    assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(s.starts_with("abababab"));
}

#[test]
fn encryption_private_key_serde_roundtrip() {
    let sk = EncryptionPrivateKey::from_bytes([0xCD; 32]);
    let json = serde_json::to_string(&sk).unwrap();
    let back: EncryptionPrivateKey = serde_json::from_str(&json).unwrap();
    assert_eq!(sk, back);
}

#[test]
fn encryption_private_key_public_derivation_deterministic() {
    let sk = EncryptionPrivateKey::from_bytes([0x11; 32]);
    let pk1 = sk.public_key();
    let pk2 = sk.public_key();
    assert_eq!(pk1, pk2);
}

#[test]
fn different_private_keys_yield_different_public_keys() {
    let sk1 = EncryptionPrivateKey::from_bytes([0x11; 32]);
    let sk2 = EncryptionPrivateKey::from_bytes([0x22; 32]);
    assert_ne!(sk1.public_key(), sk2.public_key());
}

// ---------------------------------------------------------------------------
// derive_role_key
// ---------------------------------------------------------------------------

#[test]
fn derive_role_key_deterministic() {
    let seed = test_seed();
    let epoch = SecurityEpoch::from_raw(1);
    let k1 = principal_key_roles::derive_role_key(&seed, KeyRole::Signing, epoch);
    let k2 = principal_key_roles::derive_role_key(&seed, KeyRole::Signing, epoch);
    assert_eq!(k1, k2);
}

#[test]
fn derive_role_key_domain_separation_all_pairs() {
    let seed = test_seed();
    let epoch = SecurityEpoch::from_raw(1);
    let signing = principal_key_roles::derive_role_key(&seed, KeyRole::Signing, epoch);
    let encryption = principal_key_roles::derive_role_key(&seed, KeyRole::Encryption, epoch);
    let issuance = principal_key_roles::derive_role_key(&seed, KeyRole::Issuance, epoch);
    assert_ne!(signing, encryption);
    assert_ne!(signing, issuance);
    assert_ne!(encryption, issuance);
}

#[test]
fn derive_role_key_epoch_sensitivity() {
    let seed = test_seed();
    let k1 =
        principal_key_roles::derive_role_key(&seed, KeyRole::Signing, SecurityEpoch::from_raw(1));
    let k2 =
        principal_key_roles::derive_role_key(&seed, KeyRole::Signing, SecurityEpoch::from_raw(2));
    let k3 = principal_key_roles::derive_role_key(
        &seed,
        KeyRole::Signing,
        SecurityEpoch::from_raw(u64::MAX),
    );
    assert_ne!(k1, k2);
    assert_ne!(k2, k3);
    assert_ne!(k1, k3);
}

// ---------------------------------------------------------------------------
// RoleKeyEntry serde
// ---------------------------------------------------------------------------

#[test]
fn role_key_entry_serde_roundtrip() {
    let epoch = SecurityEpoch::from_raw(1);
    let seed = test_seed();
    let sk = make_signing_key(&seed, epoch);
    let entry = make_role_entry(
        KeyRole::Signing,
        sk.verification_key(),
        None,
        KeyStatus::Active,
        epoch,
        0,
    );
    let json = serde_json::to_string(&entry).unwrap();
    let back: RoleKeyEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn role_key_entry_with_encryption_pk_serde_roundtrip() {
    let epoch = SecurityEpoch::from_raw(1);
    let seed = test_seed();
    let enc = make_encryption_private(&seed, epoch);
    let entry = make_role_entry(
        KeyRole::Encryption,
        VerificationKey([0u8; 32]),
        Some(enc.public_key()),
        KeyStatus::Active,
        epoch,
        0,
    );
    let json = serde_json::to_string(&entry).unwrap();
    let back: RoleKeyEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
    assert!(back.encryption_public_key.is_some());
}

#[test]
fn role_key_entry_identity_bytes_differ_by_role() {
    let epoch = SecurityEpoch::from_raw(1);
    let vk = VerificationKey([0x55; 32]);
    let signing = make_role_entry(
        KeyRole::Signing,
        vk.clone(),
        None,
        KeyStatus::Active,
        epoch,
        0,
    );
    let issuance = make_role_entry(KeyRole::Issuance, vk, None, KeyStatus::Active, epoch, 0);
    assert_ne!(signing.identity_bytes(), issuance.identity_bytes());
}

// ---------------------------------------------------------------------------
// OwnerKeyBundle
// ---------------------------------------------------------------------------

#[test]
fn owner_key_bundle_create_and_verify() {
    let seed = test_seed();
    let epoch = SecurityEpoch::from_raw(1);
    let owner_sk = make_signing_key(&seed, epoch);
    let owner_vk = owner_sk.verification_key();
    let enc = make_encryption_private(&seed, epoch);
    let iss = make_issuance_key(&seed, epoch);

    let bundle = OwnerKeyBundle::create_signed(
        &owner_sk,
        owner_vk.clone(),
        enc.public_key(),
        iss.verification_key(),
        epoch,
        1,
    )
    .unwrap();

    assert!(bundle.verify(&owner_vk).is_ok());
    assert_eq!(bundle.epoch, epoch);
    assert_eq!(bundle.sequence, 1);
}

#[test]
fn owner_key_bundle_serde_roundtrip_preserves_verification() {
    let seed = test_seed();
    let epoch = SecurityEpoch::from_raw(1);
    let owner_sk = make_signing_key(&seed, epoch);
    let owner_vk = owner_sk.verification_key();
    let enc = make_encryption_private(&seed, epoch);
    let iss = make_issuance_key(&seed, epoch);

    let bundle = OwnerKeyBundle::create_signed(
        &owner_sk,
        owner_vk.clone(),
        enc.public_key(),
        iss.verification_key(),
        epoch,
        1,
    )
    .unwrap();

    let json = serde_json::to_string(&bundle).unwrap();
    let back: OwnerKeyBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, back);
    assert!(back.verify(&owner_vk).is_ok());
}

#[test]
fn owner_key_bundle_wrong_verifier_rejected() {
    let seed = test_seed();
    let epoch = SecurityEpoch::from_raw(1);
    let owner_sk = make_signing_key(&seed, epoch);
    let enc = make_encryption_private(&seed, epoch);
    let iss = make_issuance_key(&seed, epoch);

    let bundle = OwnerKeyBundle::create_signed(
        &owner_sk,
        owner_sk.verification_key(),
        enc.public_key(),
        iss.verification_key(),
        epoch,
        1,
    )
    .unwrap();

    let wrong_vk = VerificationKey([0xFF; 32]);
    assert_eq!(
        bundle.verify(&wrong_vk),
        Err(KeyRoleError::BundleSignatureInvalid)
    );
}

#[test]
fn owner_key_bundle_derive_id_deterministic() {
    let seed = test_seed();
    let epoch = SecurityEpoch::from_raw(1);
    let owner_sk = make_signing_key(&seed, epoch);
    let enc = make_encryption_private(&seed, epoch);
    let iss = make_issuance_key(&seed, epoch);

    let id1 = OwnerKeyBundle::derive_id(
        &owner_sk.verification_key(),
        &enc.public_key(),
        &iss.verification_key(),
        epoch,
        1,
    )
    .unwrap();

    let id2 = OwnerKeyBundle::derive_id(
        &owner_sk.verification_key(),
        &enc.public_key(),
        &iss.verification_key(),
        epoch,
        1,
    )
    .unwrap();

    assert_eq!(id1, id2);
}

#[test]
fn owner_key_bundle_different_sequences_produce_different_ids() {
    let seed = test_seed();
    let epoch = SecurityEpoch::from_raw(1);
    let owner_sk = make_signing_key(&seed, epoch);
    let enc = make_encryption_private(&seed, epoch);
    let iss = make_issuance_key(&seed, epoch);

    let id1 = OwnerKeyBundle::derive_id(
        &owner_sk.verification_key(),
        &enc.public_key(),
        &iss.verification_key(),
        epoch,
        1,
    )
    .unwrap();

    let id2 = OwnerKeyBundle::derive_id(
        &owner_sk.verification_key(),
        &enc.public_key(),
        &iss.verification_key(),
        epoch,
        2,
    )
    .unwrap();

    assert_ne!(id1, id2);
}

// ---------------------------------------------------------------------------
// bundle_schema / bundle_schema_id
// ---------------------------------------------------------------------------

#[test]
fn bundle_schema_deterministic() {
    let s1 = principal_key_roles::bundle_schema();
    let s2 = principal_key_roles::bundle_schema();
    assert_eq!(s1, s2);
}

#[test]
fn bundle_schema_id_deterministic() {
    let id1 = principal_key_roles::bundle_schema_id();
    let id2 = principal_key_roles::bundle_schema_id();
    assert_eq!(id1, id2);
}

// ---------------------------------------------------------------------------
// KeyRoleError serde, display, std::error
// ---------------------------------------------------------------------------

#[test]
fn key_role_error_serde_roundtrip_all_variants() {
    let errors: Vec<KeyRoleError> = vec![
        KeyRoleError::KeyRoleMismatch {
            expected: KeyRole::Signing,
            actual: KeyRole::Encryption,
        },
        KeyRoleError::KeyNotActive {
            role: KeyRole::Issuance,
            status: KeyStatus::Revoked,
        },
        KeyRoleError::NoActiveKey {
            role: KeyRole::Signing,
        },
        KeyRoleError::BundleCreationFailed,
        KeyRoleError::BundleSignatureInvalid,
        KeyRoleError::SequenceRegression {
            role: KeyRole::Encryption,
            existing: 5,
            attempted: 3,
        },
        KeyRoleError::PrincipalNotFound,
        KeyRoleError::DuplicateKey {
            role: KeyRole::Issuance,
            sequence: 7,
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: KeyRoleError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn key_role_error_display_all_variants() {
    let err = KeyRoleError::KeyRoleMismatch {
        expected: KeyRole::Signing,
        actual: KeyRole::Encryption,
    };
    let s = err.to_string();
    assert!(s.contains("mismatch"));
    assert!(s.contains("signing"));
    assert!(s.contains("encryption"));

    let err = KeyRoleError::KeyNotActive {
        role: KeyRole::Issuance,
        status: KeyStatus::Expired,
    };
    assert!(err.to_string().contains("issuance"));
    assert!(err.to_string().contains("expired"));

    let err = KeyRoleError::NoActiveKey {
        role: KeyRole::Encryption,
    };
    assert!(err.to_string().contains("encryption"));

    assert!(
        KeyRoleError::BundleCreationFailed
            .to_string()
            .contains("bundle")
    );
    assert!(
        KeyRoleError::BundleSignatureInvalid
            .to_string()
            .contains("signature")
    );

    let err = KeyRoleError::SequenceRegression {
        role: KeyRole::Signing,
        existing: 10,
        attempted: 5,
    };
    let s = err.to_string();
    assert!(s.contains("regression"));
    assert!(s.contains("10"));
    assert!(s.contains("5"));

    assert!(
        KeyRoleError::PrincipalNotFound
            .to_string()
            .contains("principal")
    );

    let err = KeyRoleError::DuplicateKey {
        role: KeyRole::Issuance,
        sequence: 3,
    };
    assert!(err.to_string().contains("duplicate"));
    assert!(err.to_string().contains("3"));
}

#[test]
fn key_role_error_implements_std_error() {
    let err = KeyRoleError::BundleCreationFailed;
    let _: &dyn std::error::Error = &err;
}

// ---------------------------------------------------------------------------
// enforce_role / enforce_active_role
// ---------------------------------------------------------------------------

#[test]
fn enforce_role_accepts_matching_role() {
    let epoch = SecurityEpoch::from_raw(1);
    let seed = test_seed();

    for role in KeyRole::ALL {
        let vk = if *role == KeyRole::Encryption {
            VerificationKey([0u8; 32])
        } else {
            let derived = principal_key_roles::derive_role_key(&seed, *role, epoch);
            SigningKey::from_bytes(derived).verification_key()
        };
        let entry = make_role_entry(*role, vk, None, KeyStatus::Active, epoch, 0);
        assert!(principal_key_roles::enforce_role(&entry, *role).is_ok());
    }
}

#[test]
fn enforce_role_rejects_all_mismatched_pairs() {
    let epoch = SecurityEpoch::from_raw(1);
    let vk = VerificationKey([0x55; 32]);

    for &actual_role in KeyRole::ALL {
        for &expected_role in KeyRole::ALL {
            if actual_role == expected_role {
                continue;
            }
            let entry = make_role_entry(actual_role, vk.clone(), None, KeyStatus::Active, epoch, 0);
            let result = principal_key_roles::enforce_role(&entry, expected_role);
            assert_eq!(
                result,
                Err(KeyRoleError::KeyRoleMismatch {
                    expected: expected_role,
                    actual: actual_role,
                })
            );
        }
    }
}

#[test]
fn enforce_active_role_rejects_all_non_active_statuses() {
    let epoch = SecurityEpoch::from_raw(1);
    let seed = test_seed();
    let sk = make_signing_key(&seed, epoch);
    let vk = sk.verification_key();

    let non_active = [
        KeyStatus::Pending,
        KeyStatus::Rotated,
        KeyStatus::Revoked,
        KeyStatus::Expired,
    ];

    for status in &non_active {
        let entry = make_role_entry(KeyRole::Signing, vk.clone(), None, *status, epoch, 0);
        let result = principal_key_roles::enforce_active_role(&entry, KeyRole::Signing);
        assert_eq!(
            result,
            Err(KeyRoleError::KeyNotActive {
                role: KeyRole::Signing,
                status: *status,
            }),
            "enforce_active_role should reject status {status}",
        );
    }
}

// ---------------------------------------------------------------------------
// PrincipalKeyStore — lifecycle & serde
// ---------------------------------------------------------------------------

#[test]
fn principal_key_store_three_roles_populated() {
    let seed = test_seed();
    let epoch = SecurityEpoch::from_raw(1);
    let sk = make_signing_key(&seed, epoch);
    let enc = make_encryption_private(&seed, epoch);
    let iss = make_issuance_key(&seed, epoch);

    let mut store = PrincipalKeyStore::new();
    store
        .register_key(make_role_entry(
            KeyRole::Signing,
            sk.verification_key(),
            None,
            KeyStatus::Active,
            epoch,
            0,
        ))
        .unwrap();
    store
        .register_key(make_role_entry(
            KeyRole::Encryption,
            VerificationKey([0u8; 32]),
            Some(enc.public_key()),
            KeyStatus::Active,
            epoch,
            0,
        ))
        .unwrap();
    store
        .register_key(make_role_entry(
            KeyRole::Issuance,
            iss.verification_key(),
            None,
            KeyStatus::Active,
            epoch,
            0,
        ))
        .unwrap();

    assert_eq!(store.total_key_count(), 3);
    assert!(store.get_active_key(KeyRole::Signing).is_ok());
    assert!(store.get_active_key(KeyRole::Encryption).is_ok());
    assert!(store.get_active_key(KeyRole::Issuance).is_ok());

    // keys_for_role returns correct count per role.
    for &role in KeyRole::ALL {
        assert_eq!(store.keys_for_role(role).len(), 1);
    }
}

#[test]
fn principal_key_store_default_is_empty() {
    let store = PrincipalKeyStore::default();
    assert_eq!(store.total_key_count(), 0);
    assert!(store.bundle().is_none());
    assert!(store.get_active_key(KeyRole::Signing).is_err());
}

#[test]
fn principal_key_store_full_three_role_lifecycle() {
    let seed = test_seed();
    let epoch1 = SecurityEpoch::from_raw(1);
    let epoch2 = SecurityEpoch::from_raw(2);

    let sk1 = make_signing_key(&seed, epoch1);
    let enc1 = make_encryption_private(&seed, epoch1);
    let iss1 = make_issuance_key(&seed, epoch1);

    let mut store = PrincipalKeyStore::new();

    // Register all three active keys.
    store
        .register_key(make_role_entry(
            KeyRole::Signing,
            sk1.verification_key(),
            None,
            KeyStatus::Active,
            epoch1,
            0,
        ))
        .unwrap();
    store
        .register_key(make_role_entry(
            KeyRole::Encryption,
            VerificationKey([0u8; 32]),
            Some(enc1.public_key()),
            KeyStatus::Active,
            epoch1,
            0,
        ))
        .unwrap();
    store
        .register_key(make_role_entry(
            KeyRole::Issuance,
            iss1.verification_key(),
            None,
            KeyStatus::Active,
            epoch1,
            0,
        ))
        .unwrap();

    assert_eq!(store.total_key_count(), 3);

    // Revoke signing, others remain active.
    store.revoke_key(KeyRole::Signing, 0, epoch2).unwrap();
    assert!(store.get_active_key(KeyRole::Signing).is_err());
    assert!(store.get_active_key(KeyRole::Encryption).is_ok());
    assert!(store.get_active_key(KeyRole::Issuance).is_ok());

    // Revoked key still counted.
    assert_eq!(store.total_key_count(), 3);

    // Keys-for-role includes revoked.
    let signing_keys = store.keys_for_role(KeyRole::Signing);
    assert_eq!(signing_keys.len(), 1);
    assert_eq!(signing_keys[0].status, KeyStatus::Revoked);
}

#[test]
fn principal_key_store_rotation_chain() {
    let seed = test_seed();
    let epoch = SecurityEpoch::from_raw(1);

    // Register 3 signing keys: seq 0 (active), 1 (pending), 2 (pending).
    let sk0 = make_signing_key(&seed, epoch);
    let sk1 = make_signing_key(&[0xBB; 32], epoch);
    let sk2 = make_signing_key(&[0xCC; 32], epoch);

    let mut store = PrincipalKeyStore::new();
    store
        .register_key(make_role_entry(
            KeyRole::Signing,
            sk0.verification_key(),
            None,
            KeyStatus::Active,
            epoch,
            0,
        ))
        .unwrap();
    store
        .register_key(make_role_entry(
            KeyRole::Signing,
            sk1.verification_key(),
            None,
            KeyStatus::Pending,
            epoch,
            1,
        ))
        .unwrap();
    store
        .register_key(make_role_entry(
            KeyRole::Signing,
            sk2.verification_key(),
            None,
            KeyStatus::Pending,
            epoch,
            2,
        ))
        .unwrap();

    // Rotate 0 → 1.
    store.rotate_key(KeyRole::Signing, 0, 1, epoch).unwrap();

    let active = store.get_active_key(KeyRole::Signing).unwrap();
    assert_eq!(active.sequence, 1);

    // Both 0 (Rotated) and 1 (Active) allow verification.
    let verifiable = store.verification_keys_for_role(KeyRole::Signing);
    assert_eq!(verifiable.len(), 2);

    // Rotate 1 → 2.
    store.rotate_key(KeyRole::Signing, 1, 2, epoch).unwrap();

    let active = store.get_active_key(KeyRole::Signing).unwrap();
    assert_eq!(active.sequence, 2);

    // All three (0=Rotated, 1=Rotated, 2=Active) allow verification.
    let verifiable = store.verification_keys_for_role(KeyRole::Signing);
    assert_eq!(verifiable.len(), 3);
}

#[test]
fn principal_key_store_verification_keys_exclude_revoked() {
    let seed = test_seed();
    let epoch1 = SecurityEpoch::from_raw(1);
    let epoch2 = SecurityEpoch::from_raw(2);

    let sk = make_signing_key(&seed, epoch1);

    let mut store = PrincipalKeyStore::new();
    store
        .register_key(make_role_entry(
            KeyRole::Signing,
            sk.verification_key(),
            None,
            KeyStatus::Active,
            epoch1,
            0,
        ))
        .unwrap();

    assert_eq!(store.verification_keys_for_role(KeyRole::Signing).len(), 1);

    store.revoke_key(KeyRole::Signing, 0, epoch2).unwrap();
    assert_eq!(store.verification_keys_for_role(KeyRole::Signing).len(), 0);
}

#[test]
fn principal_key_store_activate_pending_key() {
    let seed = test_seed();
    let epoch1 = SecurityEpoch::from_raw(1);
    let epoch2 = SecurityEpoch::from_raw(2);

    let sk = make_signing_key(&seed, epoch1);

    let mut store = PrincipalKeyStore::new();
    store
        .register_key(make_role_entry(
            KeyRole::Signing,
            sk.verification_key(),
            None,
            KeyStatus::Pending,
            epoch1,
            0,
        ))
        .unwrap();

    // No active key yet.
    assert!(store.get_active_key(KeyRole::Signing).is_err());

    // Activate it.
    store.activate_key(KeyRole::Signing, 0, epoch2).unwrap();
    let active = store.get_active_key(KeyRole::Signing).unwrap();
    assert_eq!(active.status, KeyStatus::Active);
    assert_eq!(active.activated_epoch, Some(epoch2));
}

#[test]
fn principal_key_store_activate_non_pending_fails() {
    let seed = test_seed();
    let epoch = SecurityEpoch::from_raw(1);
    let sk = make_signing_key(&seed, epoch);

    let mut store = PrincipalKeyStore::new();
    store
        .register_key(make_role_entry(
            KeyRole::Signing,
            sk.verification_key(),
            None,
            KeyStatus::Active,
            epoch,
            0,
        ))
        .unwrap();

    let result = store.activate_key(KeyRole::Signing, 0, epoch);
    assert!(result.is_err());
}

#[test]
fn principal_key_store_set_and_get_bundle() {
    let seed = test_seed();
    let epoch = SecurityEpoch::from_raw(1);
    let owner_sk = make_signing_key(&seed, epoch);
    let enc = make_encryption_private(&seed, epoch);
    let iss = make_issuance_key(&seed, epoch);

    let bundle = OwnerKeyBundle::create_signed(
        &owner_sk,
        owner_sk.verification_key(),
        enc.public_key(),
        iss.verification_key(),
        epoch,
        1,
    )
    .unwrap();

    let mut store = PrincipalKeyStore::new();
    assert!(store.bundle().is_none());

    store.set_bundle(bundle.clone());
    let retrieved = store.bundle().unwrap();
    assert_eq!(retrieved.sequence, 1);
    assert_eq!(retrieved.epoch, epoch);
}

#[test]
fn principal_key_store_bundle_attached_and_verifiable() {
    let seed = test_seed();
    let epoch = SecurityEpoch::from_raw(1);
    let owner_sk = make_signing_key(&seed, epoch);
    let enc = make_encryption_private(&seed, epoch);
    let iss = make_issuance_key(&seed, epoch);

    let bundle = OwnerKeyBundle::create_signed(
        &owner_sk,
        owner_sk.verification_key(),
        enc.public_key(),
        iss.verification_key(),
        epoch,
        1,
    )
    .unwrap();

    let mut store = PrincipalKeyStore::new();
    store
        .register_key(make_role_entry(
            KeyRole::Signing,
            owner_sk.verification_key(),
            None,
            KeyStatus::Active,
            epoch,
            0,
        ))
        .unwrap();
    store.set_bundle(bundle);

    assert_eq!(store.total_key_count(), 1);
    assert!(store.bundle().is_some());
    let retrieved = store.bundle().unwrap();
    assert!(retrieved.verify(&owner_sk.verification_key()).is_ok());
    assert_eq!(retrieved.sequence, 1);
    assert_eq!(retrieved.epoch, epoch);
}

// ---------------------------------------------------------------------------
// Adversarial scenarios
// ---------------------------------------------------------------------------

#[test]
fn adversarial_cross_role_enforcement_all_pairs() {
    let seed = test_seed();
    let epoch = SecurityEpoch::from_raw(1);
    let sk = make_signing_key(&seed, epoch);
    let iss = make_issuance_key(&seed, epoch);
    let enc = make_encryption_private(&seed, epoch);

    let mut store = PrincipalKeyStore::new();
    store
        .register_key(make_role_entry(
            KeyRole::Signing,
            sk.verification_key(),
            None,
            KeyStatus::Active,
            epoch,
            0,
        ))
        .unwrap();
    store
        .register_key(make_role_entry(
            KeyRole::Encryption,
            VerificationKey([0u8; 32]),
            Some(enc.public_key()),
            KeyStatus::Active,
            epoch,
            0,
        ))
        .unwrap();
    store
        .register_key(make_role_entry(
            KeyRole::Issuance,
            iss.verification_key(),
            None,
            KeyStatus::Active,
            epoch,
            0,
        ))
        .unwrap();

    // Each key can only be used for its designated role.
    for &role in KeyRole::ALL {
        let entry = store.get_active_key(role).unwrap();
        assert!(principal_key_roles::enforce_role(entry, role).is_ok());
        assert!(principal_key_roles::enforce_active_role(entry, role).is_ok());

        for &wrong_role in KeyRole::ALL {
            if wrong_role == role {
                continue;
            }
            assert!(principal_key_roles::enforce_role(entry, wrong_role).is_err());
        }
    }
}

#[test]
fn adversarial_sequence_regression_blocked() {
    let seed = test_seed();
    let epoch = SecurityEpoch::from_raw(1);

    let sk1 = make_signing_key(&seed, epoch);
    let sk2 = make_signing_key(&[0xBB; 32], epoch);

    let mut store = PrincipalKeyStore::new();
    store
        .register_key(make_role_entry(
            KeyRole::Signing,
            sk1.verification_key(),
            None,
            KeyStatus::Active,
            epoch,
            5,
        ))
        .unwrap();

    let result = store.register_key(make_role_entry(
        KeyRole::Signing,
        sk2.verification_key(),
        None,
        KeyStatus::Pending,
        epoch,
        3,
    ));

    assert_eq!(
        result,
        Err(KeyRoleError::SequenceRegression {
            role: KeyRole::Signing,
            existing: 5,
            attempted: 3,
        })
    );
}

#[test]
fn adversarial_duplicate_key_blocked() {
    let seed = test_seed();
    let epoch = SecurityEpoch::from_raw(1);
    let sk = make_signing_key(&seed, epoch);

    let mut store = PrincipalKeyStore::new();
    store
        .register_key(make_role_entry(
            KeyRole::Signing,
            sk.verification_key(),
            None,
            KeyStatus::Active,
            epoch,
            0,
        ))
        .unwrap();

    let result = store.register_key(make_role_entry(
        KeyRole::Signing,
        sk.verification_key(),
        None,
        KeyStatus::Pending,
        epoch,
        0,
    ));

    assert_eq!(
        result,
        Err(KeyRoleError::DuplicateKey {
            role: KeyRole::Signing,
            sequence: 0,
        })
    );
}

#[test]
fn adversarial_rotate_non_active_old_key_fails() {
    let seed = test_seed();
    let epoch = SecurityEpoch::from_raw(1);

    let sk1 = make_signing_key(&seed, epoch);
    let sk2 = make_signing_key(&[0xBB; 32], epoch);

    let mut store = PrincipalKeyStore::new();
    store
        .register_key(make_role_entry(
            KeyRole::Signing,
            sk1.verification_key(),
            None,
            KeyStatus::Pending,
            epoch,
            0,
        ))
        .unwrap();
    store
        .register_key(make_role_entry(
            KeyRole::Signing,
            sk2.verification_key(),
            None,
            KeyStatus::Pending,
            epoch,
            1,
        ))
        .unwrap();

    // Old key is Pending, not Active — rotation should fail.
    let result = store.rotate_key(KeyRole::Signing, 0, 1, epoch);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Stress test
// ---------------------------------------------------------------------------

#[test]
fn stress_many_keys_across_roles() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut store = PrincipalKeyStore::new();

    let keys_per_role = 20u64;
    for &role in KeyRole::ALL {
        for seq in 0..keys_per_role {
            let seed_byte = (role as u8).wrapping_mul(100).wrapping_add(seq as u8);
            let derived = principal_key_roles::derive_role_key(&[seed_byte; 32], role, epoch);
            let vk = if role == KeyRole::Encryption {
                VerificationKey([0u8; 32])
            } else {
                SigningKey::from_bytes(derived).verification_key()
            };
            let status = if seq == keys_per_role - 1 {
                KeyStatus::Active
            } else {
                KeyStatus::Pending
            };
            let enc_pk = if role == KeyRole::Encryption {
                Some(EncryptionPublicKey::from_bytes(derived))
            } else {
                None
            };
            store
                .register_key(make_role_entry(role, vk, enc_pk, status, epoch, seq))
                .unwrap();
        }
    }

    assert_eq!(store.total_key_count(), 60);

    // Each role has one active key (the last registered).
    for &role in KeyRole::ALL {
        let active = store.get_active_key(role).unwrap();
        assert_eq!(active.sequence, keys_per_role - 1);
        assert_eq!(active.status, KeyStatus::Active);
    }

    // Keys-for-role returns all keys for each role.
    for &role in KeyRole::ALL {
        assert_eq!(store.keys_for_role(role).len(), keys_per_role as usize);
    }
}
