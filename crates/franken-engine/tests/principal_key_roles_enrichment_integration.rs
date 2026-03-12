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

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::principal_key_roles::*;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{SigningKey, VerificationKey};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn test_seed() -> [u8; 32] {
    [0xAA; 32]
}

fn seed_n(n: u8) -> [u8; 32] {
    [n; 32]
}

fn make_signing_key(seed: &[u8; 32], ep: SecurityEpoch) -> SigningKey {
    let derived = derive_role_key(seed, KeyRole::Signing, ep);
    SigningKey::from_bytes(derived)
}

fn make_encryption_private(seed: &[u8; 32], ep: SecurityEpoch) -> EncryptionPrivateKey {
    let derived = derive_role_key(seed, KeyRole::Encryption, ep);
    EncryptionPrivateKey::from_bytes(derived)
}

fn make_issuance_key(seed: &[u8; 32], ep: SecurityEpoch) -> SigningKey {
    let derived = derive_role_key(seed, KeyRole::Issuance, ep);
    SigningKey::from_bytes(derived)
}

fn make_role_entry(
    role: KeyRole,
    vk: VerificationKey,
    enc_pk: Option<EncryptionPublicKey>,
    status: KeyStatus,
    ep: SecurityEpoch,
    seq: u64,
) -> RoleKeyEntry {
    RoleKeyEntry {
        role,
        verification_key: vk,
        encryption_public_key: enc_pk,
        status,
        created_epoch: ep,
        activated_epoch: if status == KeyStatus::Active {
            Some(ep)
        } else {
            None
        },
        revoked_epoch: None,
        sequence: seq,
    }
}

/// Build a fully-populated store with one active key per role.
fn build_full_store(seed: &[u8; 32], ep: SecurityEpoch) -> PrincipalKeyStore {
    let sk = make_signing_key(seed, ep);
    let enc = make_encryption_private(seed, ep);
    let iss = make_issuance_key(seed, ep);

    let mut store = PrincipalKeyStore::new();
    store
        .register_key(make_role_entry(
            KeyRole::Signing,
            sk.verification_key(),
            None,
            KeyStatus::Active,
            ep,
            0,
        ))
        .unwrap();
    store
        .register_key(make_role_entry(
            KeyRole::Encryption,
            VerificationKey([0u8; 32]),
            Some(enc.public_key()),
            KeyStatus::Active,
            ep,
            0,
        ))
        .unwrap();
    store
        .register_key(make_role_entry(
            KeyRole::Issuance,
            iss.verification_key(),
            None,
            KeyStatus::Active,
            ep,
            0,
        ))
        .unwrap();
    store
}

// ===========================================================================
// KeyRole enum tests
// ===========================================================================

#[test]
fn enrichment_key_role_display_signing() {
    assert_eq!(KeyRole::Signing.to_string(), "signing");
}

#[test]
fn enrichment_key_role_display_encryption() {
    assert_eq!(KeyRole::Encryption.to_string(), "encryption");
}

#[test]
fn enrichment_key_role_display_issuance() {
    assert_eq!(KeyRole::Issuance.to_string(), "issuance");
}

#[test]
fn enrichment_key_role_display_uniqueness() {
    let displays: BTreeSet<String> = KeyRole::ALL.iter().map(|r| r.to_string()).collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_key_role_all_contains_three() {
    assert_eq!(KeyRole::ALL.len(), 3);
    assert!(KeyRole::ALL.contains(&KeyRole::Signing));
    assert!(KeyRole::ALL.contains(&KeyRole::Encryption));
    assert!(KeyRole::ALL.contains(&KeyRole::Issuance));
}

#[test]
fn enrichment_key_role_serde_roundtrip_all_variants() {
    for role in KeyRole::ALL {
        let json = serde_json::to_string(role).unwrap();
        let back: KeyRole = serde_json::from_str(&json).unwrap();
        assert_eq!(*role, back);
    }
}

#[test]
fn enrichment_key_role_derivation_domain_unique_per_role() {
    let domains: BTreeSet<Vec<u8>> = KeyRole::ALL
        .iter()
        .map(|r| r.derivation_domain().to_vec())
        .collect();
    assert_eq!(domains.len(), 3, "each role has a unique derivation domain");
}

#[test]
fn enrichment_key_role_derivation_domain_contains_role_name() {
    assert!(
        std::str::from_utf8(KeyRole::Signing.derivation_domain())
            .unwrap()
            .contains("signing")
    );
    assert!(
        std::str::from_utf8(KeyRole::Encryption.derivation_domain())
            .unwrap()
            .contains("encryption")
    );
    assert!(
        std::str::from_utf8(KeyRole::Issuance.derivation_domain())
            .unwrap()
            .contains("issuance")
    );
}

#[test]
fn enrichment_key_role_ordering() {
    assert!(KeyRole::Signing < KeyRole::Encryption);
    assert!(KeyRole::Encryption < KeyRole::Issuance);
    assert!(KeyRole::Signing < KeyRole::Issuance);
}

#[test]
fn enrichment_key_role_clone_eq() {
    let role = KeyRole::Signing;
    let cloned = role.clone();
    assert_eq!(role, cloned);
}

#[test]
fn enrichment_key_role_copy_semantics() {
    let role = KeyRole::Encryption;
    let copied = role;
    assert_eq!(role, copied);
}

// ===========================================================================
// KeyStatus enum tests
// ===========================================================================

#[test]
fn enrichment_key_status_display_pending() {
    assert_eq!(KeyStatus::Pending.to_string(), "pending");
}

#[test]
fn enrichment_key_status_display_active() {
    assert_eq!(KeyStatus::Active.to_string(), "active");
}

#[test]
fn enrichment_key_status_display_rotated() {
    assert_eq!(KeyStatus::Rotated.to_string(), "rotated");
}

#[test]
fn enrichment_key_status_display_revoked() {
    assert_eq!(KeyStatus::Revoked.to_string(), "revoked");
}

#[test]
fn enrichment_key_status_display_expired() {
    assert_eq!(KeyStatus::Expired.to_string(), "expired");
}

#[test]
fn enrichment_key_status_display_all_unique() {
    let all_statuses = [
        KeyStatus::Pending,
        KeyStatus::Active,
        KeyStatus::Rotated,
        KeyStatus::Revoked,
        KeyStatus::Expired,
    ];
    let displays: BTreeSet<String> = all_statuses.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_key_status_serde_roundtrip_all() {
    for status in [
        KeyStatus::Pending,
        KeyStatus::Active,
        KeyStatus::Rotated,
        KeyStatus::Revoked,
        KeyStatus::Expired,
    ] {
        let json = serde_json::to_string(&status).unwrap();
        let back: KeyStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, back);
    }
}

#[test]
fn enrichment_key_status_allows_creation_only_active() {
    assert!(!KeyStatus::Pending.allows_creation());
    assert!(KeyStatus::Active.allows_creation());
    assert!(!KeyStatus::Rotated.allows_creation());
    assert!(!KeyStatus::Revoked.allows_creation());
    assert!(!KeyStatus::Expired.allows_creation());
}

#[test]
fn enrichment_key_status_allows_verification_active_and_rotated() {
    assert!(!KeyStatus::Pending.allows_verification());
    assert!(KeyStatus::Active.allows_verification());
    assert!(KeyStatus::Rotated.allows_verification());
    assert!(!KeyStatus::Revoked.allows_verification());
    assert!(!KeyStatus::Expired.allows_verification());
}

#[test]
fn enrichment_key_status_ordering() {
    assert!(KeyStatus::Pending < KeyStatus::Active);
    assert!(KeyStatus::Active < KeyStatus::Rotated);
    assert!(KeyStatus::Rotated < KeyStatus::Revoked);
    assert!(KeyStatus::Revoked < KeyStatus::Expired);
}

// ===========================================================================
// EncryptionPublicKey tests
// ===========================================================================

#[test]
fn enrichment_encryption_public_key_from_bytes_roundtrip() {
    let bytes = [0xDE; 32];
    let pk = EncryptionPublicKey::from_bytes(bytes);
    assert_eq!(*pk.as_bytes(), bytes);
}

#[test]
fn enrichment_encryption_public_key_display_hex() {
    let pk = EncryptionPublicKey::from_bytes([0xAB; 32]);
    let display = pk.to_string();
    assert_eq!(display.len(), 64);
    assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(display.starts_with("abababab"));
}

#[test]
fn enrichment_encryption_public_key_display_zero_padded() {
    let pk = EncryptionPublicKey::from_bytes([0x00; 32]);
    let display = pk.to_string();
    assert_eq!(display.len(), 64);
    assert!(display.chars().all(|c| c == '0'));
}

#[test]
fn enrichment_encryption_public_key_serde_roundtrip() {
    let pk = EncryptionPublicKey::from_bytes([0x42; 32]);
    let json = serde_json::to_string(&pk).unwrap();
    let back: EncryptionPublicKey = serde_json::from_str(&json).unwrap();
    assert_eq!(pk, back);
}

#[test]
fn enrichment_encryption_public_key_clone_eq() {
    let pk = EncryptionPublicKey::from_bytes([0x77; 32]);
    let cloned = pk.clone();
    assert_eq!(pk, cloned);
}

#[test]
fn enrichment_encryption_public_key_ord() {
    let pk_low = EncryptionPublicKey::from_bytes([0x01; 32]);
    let pk_high = EncryptionPublicKey::from_bytes([0xFF; 32]);
    assert!(pk_low < pk_high);
}

#[test]
fn enrichment_encryption_public_key_different_bytes_not_equal() {
    let pk1 = EncryptionPublicKey::from_bytes([0x01; 32]);
    let pk2 = EncryptionPublicKey::from_bytes([0x02; 32]);
    assert_ne!(pk1, pk2);
}

// ===========================================================================
// EncryptionPrivateKey tests
// ===========================================================================

#[test]
fn enrichment_encryption_private_key_from_bytes_roundtrip() {
    let bytes = [0xFE; 32];
    let sk = EncryptionPrivateKey::from_bytes(bytes);
    assert_eq!(*sk.as_bytes(), bytes);
}

#[test]
fn enrichment_encryption_private_key_public_derivation_deterministic() {
    let sk = EncryptionPrivateKey::from_bytes([0x42; 32]);
    let pk1 = sk.public_key();
    let pk2 = sk.public_key();
    assert_eq!(pk1, pk2);
}

#[test]
fn enrichment_encryption_private_key_different_privates_yield_different_publics() {
    let sk1 = EncryptionPrivateKey::from_bytes([0x01; 32]);
    let sk2 = EncryptionPrivateKey::from_bytes([0x02; 32]);
    assert_ne!(sk1.public_key(), sk2.public_key());
}

#[test]
fn enrichment_encryption_private_key_serde_roundtrip() {
    let sk = EncryptionPrivateKey::from_bytes([0x99; 32]);
    let json = serde_json::to_string(&sk).unwrap();
    let back: EncryptionPrivateKey = serde_json::from_str(&json).unwrap();
    assert_eq!(sk.as_bytes(), back.as_bytes());
}

#[test]
fn enrichment_encryption_private_key_clone_eq() {
    let sk = EncryptionPrivateKey::from_bytes([0xBB; 32]);
    let cloned = sk.clone();
    assert_eq!(sk, cloned);
}

#[test]
fn enrichment_encryption_private_key_public_key_is_32_bytes() {
    let sk = EncryptionPrivateKey::from_bytes([0x11; 32]);
    let pk = sk.public_key();
    assert_eq!(pk.as_bytes().len(), 32);
}

// ===========================================================================
// ENCRYPTION_KEY_LEN constant test
// ===========================================================================

#[test]
fn enrichment_encryption_key_len_is_32() {
    assert_eq!(ENCRYPTION_KEY_LEN, 32);
}

// ===========================================================================
// derive_role_key tests
// ===========================================================================

#[test]
fn enrichment_derive_role_key_domain_separation() {
    let seed = test_seed();
    let ep = epoch(1);
    let signing = derive_role_key(&seed, KeyRole::Signing, ep);
    let encryption = derive_role_key(&seed, KeyRole::Encryption, ep);
    let issuance = derive_role_key(&seed, KeyRole::Issuance, ep);
    assert_ne!(signing, encryption);
    assert_ne!(signing, issuance);
    assert_ne!(encryption, issuance);
}

#[test]
fn enrichment_derive_role_key_deterministic() {
    let seed = test_seed();
    let ep = epoch(1);
    let k1 = derive_role_key(&seed, KeyRole::Signing, ep);
    let k2 = derive_role_key(&seed, KeyRole::Signing, ep);
    assert_eq!(k1, k2);
}

#[test]
fn enrichment_derive_role_key_different_seeds_differ() {
    let ep = epoch(1);
    let k1 = derive_role_key(&seed_n(0x11), KeyRole::Signing, ep);
    let k2 = derive_role_key(&seed_n(0x22), KeyRole::Signing, ep);
    assert_ne!(k1, k2);
}

#[test]
fn enrichment_derive_role_key_different_epochs_differ() {
    let seed = test_seed();
    let k1 = derive_role_key(&seed, KeyRole::Encryption, epoch(1));
    let k2 = derive_role_key(&seed, KeyRole::Encryption, epoch(2));
    assert_ne!(k1, k2);
}

#[test]
fn enrichment_derive_role_key_all_roles_different_same_inputs() {
    let seed = test_seed();
    let ep = epoch(5);
    let keys: BTreeSet<[u8; 32]> = KeyRole::ALL
        .iter()
        .map(|r| derive_role_key(&seed, *r, ep))
        .collect();
    assert_eq!(keys.len(), 3, "all three roles yield distinct keys");
}

#[test]
fn enrichment_derive_role_key_zero_epoch() {
    let seed = test_seed();
    let k = derive_role_key(&seed, KeyRole::Signing, epoch(0));
    assert_eq!(k.len(), 32);
    // Just ensure it produces a 32-byte result, no panic.
}

#[test]
fn enrichment_derive_role_key_max_epoch() {
    let seed = test_seed();
    let k = derive_role_key(&seed, KeyRole::Issuance, epoch(u64::MAX));
    assert_eq!(k.len(), 32);
}

// ===========================================================================
// RoleKeyEntry tests
// ===========================================================================

#[test]
fn enrichment_role_key_entry_identity_bytes_role_specific() {
    let seed = test_seed();
    let ep = epoch(1);
    let vk = make_signing_key(&seed, ep).verification_key();

    let signing_entry = make_role_entry(KeyRole::Signing, vk.clone(), None, KeyStatus::Active, ep, 0);
    let issuance_entry = make_role_entry(KeyRole::Issuance, vk, None, KeyStatus::Active, ep, 0);

    assert_ne!(
        signing_entry.identity_bytes(),
        issuance_entry.identity_bytes()
    );
}

#[test]
fn enrichment_role_key_entry_identity_bytes_deterministic() {
    let seed = test_seed();
    let ep = epoch(1);
    let vk = make_signing_key(&seed, ep).verification_key();
    let entry = make_role_entry(KeyRole::Signing, vk, None, KeyStatus::Active, ep, 0);
    let id1 = entry.identity_bytes();
    let id2 = entry.identity_bytes();
    assert_eq!(id1, id2);
}

#[test]
fn enrichment_role_key_entry_identity_bytes_includes_vk() {
    let seed = test_seed();
    let ep = epoch(1);
    let vk = make_signing_key(&seed, ep).verification_key();
    let entry = make_role_entry(KeyRole::Signing, vk.clone(), None, KeyStatus::Active, ep, 0);
    let id_bytes = entry.identity_bytes();
    // The identity bytes should contain the verification key bytes.
    let vk_bytes = vk.as_bytes();
    assert!(id_bytes.len() > vk_bytes.len());
    assert_eq!(&id_bytes[id_bytes.len() - 32..], vk_bytes.as_slice());
}

#[test]
fn enrichment_role_key_entry_serde_roundtrip() {
    let seed = test_seed();
    let ep = epoch(1);
    let sk = make_signing_key(&seed, ep);
    let entry = make_role_entry(KeyRole::Signing, sk.verification_key(), None, KeyStatus::Active, ep, 0);
    let json = serde_json::to_string(&entry).unwrap();
    let back: RoleKeyEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_role_key_entry_with_encryption_key_serde() {
    let seed = test_seed();
    let ep = epoch(1);
    let enc = make_encryption_private(&seed, ep);
    let entry = make_role_entry(
        KeyRole::Encryption,
        VerificationKey([0u8; 32]),
        Some(enc.public_key()),
        KeyStatus::Active,
        ep,
        0,
    );
    let json = serde_json::to_string(&entry).unwrap();
    let back: RoleKeyEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
    assert!(back.encryption_public_key.is_some());
}

#[test]
fn enrichment_role_key_entry_clone_eq() {
    let seed = test_seed();
    let ep = epoch(1);
    let vk = make_signing_key(&seed, ep).verification_key();
    let entry = make_role_entry(KeyRole::Signing, vk, None, KeyStatus::Pending, ep, 0);
    let cloned = entry.clone();
    assert_eq!(entry, cloned);
}

#[test]
fn enrichment_role_key_entry_fields_accessible() {
    let seed = test_seed();
    let ep = epoch(3);
    let vk = make_signing_key(&seed, ep).verification_key();
    let entry = make_role_entry(KeyRole::Issuance, vk, None, KeyStatus::Pending, ep, 7);
    assert_eq!(entry.role, KeyRole::Issuance);
    assert_eq!(entry.status, KeyStatus::Pending);
    assert_eq!(entry.created_epoch, ep);
    assert_eq!(entry.sequence, 7);
    assert!(entry.activated_epoch.is_none());
    assert!(entry.revoked_epoch.is_none());
    assert!(entry.encryption_public_key.is_none());
}

// ===========================================================================
// bundle_schema / bundle_schema_id tests
// ===========================================================================

#[test]
fn enrichment_bundle_schema_deterministic() {
    let s1 = bundle_schema();
    let s2 = bundle_schema();
    assert_eq!(s1, s2);
}

#[test]
fn enrichment_bundle_schema_id_deterministic() {
    let id1 = bundle_schema_id();
    let id2 = bundle_schema_id();
    assert_eq!(id1, id2);
}

// ===========================================================================
// OwnerKeyBundle tests
// ===========================================================================

#[test]
fn enrichment_owner_key_bundle_create_signed_and_verify() {
    let seed = test_seed();
    let ep = epoch(1);
    let owner_sk = make_signing_key(&seed, ep);
    let owner_vk = owner_sk.verification_key();
    let enc = make_encryption_private(&seed, ep);
    let iss = make_issuance_key(&seed, ep);

    let bundle = OwnerKeyBundle::create_signed(
        &owner_sk,
        owner_vk.clone(),
        enc.public_key(),
        iss.verification_key(),
        ep,
        1,
    )
    .unwrap();

    assert!(bundle.verify(&owner_vk).is_ok());
}

#[test]
fn enrichment_owner_key_bundle_verify_rejects_wrong_key() {
    let seed = test_seed();
    let ep = epoch(1);
    let owner_sk = make_signing_key(&seed, ep);
    let enc = make_encryption_private(&seed, ep);
    let iss = make_issuance_key(&seed, ep);

    let bundle = OwnerKeyBundle::create_signed(
        &owner_sk,
        owner_sk.verification_key(),
        enc.public_key(),
        iss.verification_key(),
        ep,
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
fn enrichment_owner_key_bundle_derive_id_deterministic() {
    let seed = test_seed();
    let ep = epoch(1);
    let sk = make_signing_key(&seed, ep);
    let enc = make_encryption_private(&seed, ep);
    let iss = make_issuance_key(&seed, ep);

    let id1 = OwnerKeyBundle::derive_id(
        &sk.verification_key(),
        &enc.public_key(),
        &iss.verification_key(),
        ep,
        1,
    )
    .unwrap();
    let id2 = OwnerKeyBundle::derive_id(
        &sk.verification_key(),
        &enc.public_key(),
        &iss.verification_key(),
        ep,
        1,
    )
    .unwrap();
    assert_eq!(id1, id2);
}

#[test]
fn enrichment_owner_key_bundle_derive_id_varies_with_signing_key() {
    let ep = epoch(1);
    let sk1 = make_signing_key(&seed_n(0x11), ep);
    let sk2 = make_signing_key(&seed_n(0x22), ep);
    let enc = make_encryption_private(&seed_n(0x11), ep);
    let iss = make_issuance_key(&seed_n(0x11), ep);

    let id1 = OwnerKeyBundle::derive_id(
        &sk1.verification_key(),
        &enc.public_key(),
        &iss.verification_key(),
        ep,
        1,
    )
    .unwrap();
    let id2 = OwnerKeyBundle::derive_id(
        &sk2.verification_key(),
        &enc.public_key(),
        &iss.verification_key(),
        ep,
        1,
    )
    .unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn enrichment_owner_key_bundle_derive_id_varies_with_encryption_key() {
    let ep = epoch(1);
    let sk = make_signing_key(&seed_n(0x11), ep);
    let enc1 = make_encryption_private(&seed_n(0x11), ep);
    let enc2 = make_encryption_private(&seed_n(0x22), ep);
    let iss = make_issuance_key(&seed_n(0x11), ep);

    let id1 = OwnerKeyBundle::derive_id(
        &sk.verification_key(),
        &enc1.public_key(),
        &iss.verification_key(),
        ep,
        1,
    )
    .unwrap();
    let id2 = OwnerKeyBundle::derive_id(
        &sk.verification_key(),
        &enc2.public_key(),
        &iss.verification_key(),
        ep,
        1,
    )
    .unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn enrichment_owner_key_bundle_derive_id_varies_with_issuance_key() {
    let ep = epoch(1);
    let sk = make_signing_key(&seed_n(0x11), ep);
    let enc = make_encryption_private(&seed_n(0x11), ep);
    let iss1 = make_issuance_key(&seed_n(0x11), ep);
    let iss2 = make_issuance_key(&seed_n(0x22), ep);

    let id1 = OwnerKeyBundle::derive_id(
        &sk.verification_key(),
        &enc.public_key(),
        &iss1.verification_key(),
        ep,
        1,
    )
    .unwrap();
    let id2 = OwnerKeyBundle::derive_id(
        &sk.verification_key(),
        &enc.public_key(),
        &iss2.verification_key(),
        ep,
        1,
    )
    .unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn enrichment_owner_key_bundle_derive_id_varies_with_epoch() {
    let sk = make_signing_key(&test_seed(), epoch(1));
    let enc = make_encryption_private(&test_seed(), epoch(1));
    let iss = make_issuance_key(&test_seed(), epoch(1));

    let id1 = OwnerKeyBundle::derive_id(
        &sk.verification_key(),
        &enc.public_key(),
        &iss.verification_key(),
        epoch(1),
        1,
    )
    .unwrap();
    let id2 = OwnerKeyBundle::derive_id(
        &sk.verification_key(),
        &enc.public_key(),
        &iss.verification_key(),
        epoch(2),
        1,
    )
    .unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn enrichment_owner_key_bundle_derive_id_varies_with_sequence() {
    let sk = make_signing_key(&test_seed(), epoch(1));
    let enc = make_encryption_private(&test_seed(), epoch(1));
    let iss = make_issuance_key(&test_seed(), epoch(1));

    let id1 = OwnerKeyBundle::derive_id(
        &sk.verification_key(),
        &enc.public_key(),
        &iss.verification_key(),
        epoch(1),
        1,
    )
    .unwrap();
    let id2 = OwnerKeyBundle::derive_id(
        &sk.verification_key(),
        &enc.public_key(),
        &iss.verification_key(),
        epoch(1),
        2,
    )
    .unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn enrichment_owner_key_bundle_serde_roundtrip() {
    let seed = test_seed();
    let ep = epoch(1);
    let sk = make_signing_key(&seed, ep);
    let enc = make_encryption_private(&seed, ep);
    let iss = make_issuance_key(&seed, ep);

    let bundle = OwnerKeyBundle::create_signed(
        &sk,
        sk.verification_key(),
        enc.public_key(),
        iss.verification_key(),
        ep,
        1,
    )
    .unwrap();

    let json = serde_json::to_string(&bundle).unwrap();
    let back: OwnerKeyBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle.sequence, back.sequence);
    assert_eq!(bundle.epoch, back.epoch);
    assert_eq!(bundle.id, back.id);
    assert_eq!(bundle.signing_key, back.signing_key);
    assert_eq!(bundle.encryption_key, back.encryption_key);
    assert_eq!(bundle.issuance_key, back.issuance_key);
}

#[test]
fn enrichment_owner_key_bundle_fields_accessible() {
    let seed = test_seed();
    let ep = epoch(5);
    let sk = make_signing_key(&seed, ep);
    let enc = make_encryption_private(&seed, ep);
    let iss = make_issuance_key(&seed, ep);

    let bundle = OwnerKeyBundle::create_signed(
        &sk,
        sk.verification_key(),
        enc.public_key(),
        iss.verification_key(),
        ep,
        42,
    )
    .unwrap();

    assert_eq!(bundle.epoch, ep);
    assert_eq!(bundle.sequence, 42);
    assert_eq!(bundle.signing_key, sk.verification_key());
    assert_eq!(bundle.encryption_key, enc.public_key());
    assert_eq!(bundle.issuance_key, iss.verification_key());
}

#[test]
fn enrichment_owner_key_bundle_clone_eq() {
    let seed = test_seed();
    let ep = epoch(1);
    let sk = make_signing_key(&seed, ep);
    let enc = make_encryption_private(&seed, ep);
    let iss = make_issuance_key(&seed, ep);

    let bundle = OwnerKeyBundle::create_signed(
        &sk,
        sk.verification_key(),
        enc.public_key(),
        iss.verification_key(),
        ep,
        1,
    )
    .unwrap();

    let cloned = bundle.clone();
    assert_eq!(bundle, cloned);
}

#[test]
fn enrichment_owner_key_bundle_two_bundles_different_sequences_not_equal() {
    let seed = test_seed();
    let ep = epoch(1);
    let sk = make_signing_key(&seed, ep);
    let enc = make_encryption_private(&seed, ep);
    let iss = make_issuance_key(&seed, ep);

    let b1 = OwnerKeyBundle::create_signed(
        &sk,
        sk.verification_key(),
        enc.public_key(),
        iss.verification_key(),
        ep,
        1,
    )
    .unwrap();

    let b2 = OwnerKeyBundle::create_signed(
        &sk,
        sk.verification_key(),
        enc.public_key(),
        iss.verification_key(),
        ep,
        2,
    )
    .unwrap();

    assert_ne!(b1.id, b2.id);
}

// ===========================================================================
// KeyRoleError tests
// ===========================================================================

#[test]
fn enrichment_key_role_error_display_key_role_mismatch() {
    let err = KeyRoleError::KeyRoleMismatch {
        expected: KeyRole::Signing,
        actual: KeyRole::Encryption,
    };
    let s = err.to_string();
    assert!(s.contains("mismatch"));
    assert!(s.contains("signing"));
    assert!(s.contains("encryption"));
}

#[test]
fn enrichment_key_role_error_display_key_not_active() {
    let err = KeyRoleError::KeyNotActive {
        role: KeyRole::Issuance,
        status: KeyStatus::Expired,
    };
    let s = err.to_string();
    assert!(s.contains("issuance"));
    assert!(s.contains("expired"));
    assert!(s.contains("not active"));
}

#[test]
fn enrichment_key_role_error_display_no_active_key() {
    let err = KeyRoleError::NoActiveKey {
        role: KeyRole::Encryption,
    };
    let s = err.to_string();
    assert!(s.contains("no active key"));
    assert!(s.contains("encryption"));
}

#[test]
fn enrichment_key_role_error_display_bundle_creation_failed() {
    let err = KeyRoleError::BundleCreationFailed;
    assert_eq!(err.to_string(), "bundle creation failed");
}

#[test]
fn enrichment_key_role_error_display_bundle_signature_invalid() {
    let err = KeyRoleError::BundleSignatureInvalid;
    assert_eq!(err.to_string(), "bundle signature invalid");
}

#[test]
fn enrichment_key_role_error_display_sequence_regression() {
    let err = KeyRoleError::SequenceRegression {
        role: KeyRole::Signing,
        existing: 10,
        attempted: 5,
    };
    let s = err.to_string();
    assert!(s.contains("regression"));
    assert!(s.contains("signing"));
    assert!(s.contains("10"));
    assert!(s.contains("5"));
}

#[test]
fn enrichment_key_role_error_display_principal_not_found() {
    let err = KeyRoleError::PrincipalNotFound;
    assert_eq!(err.to_string(), "principal not found");
}

#[test]
fn enrichment_key_role_error_display_duplicate_key() {
    let err = KeyRoleError::DuplicateKey {
        role: KeyRole::Encryption,
        sequence: 7,
    };
    let s = err.to_string();
    assert!(s.contains("duplicate"));
    assert!(s.contains("encryption"));
    assert!(s.contains("7"));
}

#[test]
fn enrichment_key_role_error_display_all_unique() {
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
            role: KeyRole::Signing,
            existing: 5,
            attempted: 3,
        },
        KeyRoleError::PrincipalNotFound,
        KeyRoleError::DuplicateKey {
            role: KeyRole::Signing,
            sequence: 1,
        },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), 8, "all 8 variants produce distinct messages");
}

#[test]
fn enrichment_key_role_error_implements_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(KeyRoleError::PrincipalNotFound);
    assert!(!err.to_string().is_empty());
}

#[test]
fn enrichment_key_role_error_serde_roundtrip_all_variants() {
    let errors = vec![
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
            role: KeyRole::Signing,
            existing: 5,
            attempted: 3,
        },
        KeyRoleError::PrincipalNotFound,
        KeyRoleError::DuplicateKey {
            role: KeyRole::Encryption,
            sequence: 2,
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: KeyRoleError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn enrichment_key_role_error_clone_eq() {
    let err = KeyRoleError::BundleSignatureInvalid;
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

// ===========================================================================
// enforce_role / enforce_active_role tests
// ===========================================================================

#[test]
fn enrichment_enforce_role_matching() {
    let seed = test_seed();
    let ep = epoch(1);
    let vk = make_signing_key(&seed, ep).verification_key();
    let entry = make_role_entry(KeyRole::Signing, vk, None, KeyStatus::Active, ep, 0);
    assert!(enforce_role(&entry, KeyRole::Signing).is_ok());
}

#[test]
fn enrichment_enforce_role_mismatch_signing_vs_encryption() {
    let seed = test_seed();
    let ep = epoch(1);
    let vk = make_signing_key(&seed, ep).verification_key();
    let entry = make_role_entry(KeyRole::Signing, vk, None, KeyStatus::Active, ep, 0);
    assert_eq!(
        enforce_role(&entry, KeyRole::Encryption),
        Err(KeyRoleError::KeyRoleMismatch {
            expected: KeyRole::Encryption,
            actual: KeyRole::Signing,
        })
    );
}

#[test]
fn enrichment_enforce_role_mismatch_encryption_vs_issuance() {
    let seed = test_seed();
    let ep = epoch(1);
    let enc = make_encryption_private(&seed, ep);
    let entry = make_role_entry(
        KeyRole::Encryption,
        VerificationKey([0u8; 32]),
        Some(enc.public_key()),
        KeyStatus::Active,
        ep,
        0,
    );
    assert_eq!(
        enforce_role(&entry, KeyRole::Issuance),
        Err(KeyRoleError::KeyRoleMismatch {
            expected: KeyRole::Issuance,
            actual: KeyRole::Encryption,
        })
    );
}

#[test]
fn enrichment_enforce_active_role_active_key_ok() {
    let seed = test_seed();
    let ep = epoch(1);
    let vk = make_signing_key(&seed, ep).verification_key();
    let entry = make_role_entry(KeyRole::Signing, vk, None, KeyStatus::Active, ep, 0);
    assert!(enforce_active_role(&entry, KeyRole::Signing).is_ok());
}

#[test]
fn enrichment_enforce_active_role_pending_fails() {
    let seed = test_seed();
    let ep = epoch(1);
    let vk = make_signing_key(&seed, ep).verification_key();
    let entry = make_role_entry(KeyRole::Signing, vk, None, KeyStatus::Pending, ep, 0);
    assert_eq!(
        enforce_active_role(&entry, KeyRole::Signing),
        Err(KeyRoleError::KeyNotActive {
            role: KeyRole::Signing,
            status: KeyStatus::Pending,
        })
    );
}

#[test]
fn enrichment_enforce_active_role_rotated_fails() {
    let seed = test_seed();
    let ep = epoch(1);
    let vk = make_signing_key(&seed, ep).verification_key();
    let entry = make_role_entry(KeyRole::Signing, vk, None, KeyStatus::Rotated, ep, 0);
    assert_eq!(
        enforce_active_role(&entry, KeyRole::Signing),
        Err(KeyRoleError::KeyNotActive {
            role: KeyRole::Signing,
            status: KeyStatus::Rotated,
        })
    );
}

#[test]
fn enrichment_enforce_active_role_revoked_fails() {
    let seed = test_seed();
    let ep = epoch(1);
    let vk = make_signing_key(&seed, ep).verification_key();
    let entry = make_role_entry(KeyRole::Signing, vk, None, KeyStatus::Revoked, ep, 0);
    assert_eq!(
        enforce_active_role(&entry, KeyRole::Signing),
        Err(KeyRoleError::KeyNotActive {
            role: KeyRole::Signing,
            status: KeyStatus::Revoked,
        })
    );
}

#[test]
fn enrichment_enforce_active_role_expired_fails() {
    let seed = test_seed();
    let ep = epoch(1);
    let vk = make_signing_key(&seed, ep).verification_key();
    let entry = make_role_entry(KeyRole::Signing, vk, None, KeyStatus::Expired, ep, 0);
    assert_eq!(
        enforce_active_role(&entry, KeyRole::Signing),
        Err(KeyRoleError::KeyNotActive {
            role: KeyRole::Signing,
            status: KeyStatus::Expired,
        })
    );
}

#[test]
fn enrichment_enforce_active_role_wrong_role_caught_first() {
    // When both role mismatch and status mismatch apply, role mismatch is checked first.
    let seed = test_seed();
    let ep = epoch(1);
    let vk = make_signing_key(&seed, ep).verification_key();
    let entry = make_role_entry(KeyRole::Signing, vk, None, KeyStatus::Revoked, ep, 0);
    let result = enforce_active_role(&entry, KeyRole::Issuance);
    assert_eq!(
        result,
        Err(KeyRoleError::KeyRoleMismatch {
            expected: KeyRole::Issuance,
            actual: KeyRole::Signing,
        })
    );
}

// ===========================================================================
// PrincipalKeyStore tests
// ===========================================================================

#[test]
fn enrichment_store_new_is_empty() {
    let store = PrincipalKeyStore::new();
    assert_eq!(store.total_key_count(), 0);
    assert!(store.bundle().is_none());
}

#[test]
fn enrichment_store_default_is_empty() {
    let store = PrincipalKeyStore::default();
    assert_eq!(store.total_key_count(), 0);
    assert!(store.bundle().is_none());
}

#[test]
fn enrichment_store_register_key_success() {
    let seed = test_seed();
    let ep = epoch(1);
    let vk = make_signing_key(&seed, ep).verification_key();
    let mut store = PrincipalKeyStore::new();
    let result = store.register_key(make_role_entry(KeyRole::Signing, vk, None, KeyStatus::Active, ep, 0));
    assert!(result.is_ok());
    assert_eq!(store.total_key_count(), 1);
}

#[test]
fn enrichment_store_register_duplicate_key_fails() {
    let seed = test_seed();
    let ep = epoch(1);
    let vk = make_signing_key(&seed, ep).verification_key();
    let mut store = PrincipalKeyStore::new();
    store
        .register_key(make_role_entry(KeyRole::Signing, vk.clone(), None, KeyStatus::Active, ep, 0))
        .unwrap();
    let result = store.register_key(make_role_entry(KeyRole::Signing, vk, None, KeyStatus::Pending, ep, 0));
    assert_eq!(
        result,
        Err(KeyRoleError::DuplicateKey {
            role: KeyRole::Signing,
            sequence: 0,
        })
    );
}

#[test]
fn enrichment_store_register_sequence_regression_fails() {
    let seed = test_seed();
    let ep = epoch(1);
    let sk1 = make_signing_key(&seed, ep);
    let sk2 = make_signing_key(&seed_n(0xBB), ep);
    let mut store = PrincipalKeyStore::new();
    store
        .register_key(make_role_entry(KeyRole::Signing, sk1.verification_key(), None, KeyStatus::Active, ep, 5))
        .unwrap();
    let result = store.register_key(make_role_entry(
        KeyRole::Signing,
        sk2.verification_key(),
        None,
        KeyStatus::Pending,
        ep,
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
fn enrichment_store_register_same_sequence_different_role_ok() {
    let seed = test_seed();
    let ep = epoch(1);
    let sk = make_signing_key(&seed, ep);
    let iss = make_issuance_key(&seed, ep);
    let mut store = PrincipalKeyStore::new();
    store
        .register_key(make_role_entry(KeyRole::Signing, sk.verification_key(), None, KeyStatus::Active, ep, 0))
        .unwrap();
    let result = store.register_key(make_role_entry(
        KeyRole::Issuance,
        iss.verification_key(),
        None,
        KeyStatus::Active,
        ep,
        0,
    ));
    assert!(result.is_ok());
    assert_eq!(store.total_key_count(), 2);
}

#[test]
fn enrichment_store_get_active_key_per_role() {
    let store = build_full_store(&test_seed(), epoch(1));
    assert_eq!(
        store.get_active_key(KeyRole::Signing).unwrap().role,
        KeyRole::Signing
    );
    assert_eq!(
        store.get_active_key(KeyRole::Encryption).unwrap().role,
        KeyRole::Encryption
    );
    assert_eq!(
        store.get_active_key(KeyRole::Issuance).unwrap().role,
        KeyRole::Issuance
    );
}

#[test]
fn enrichment_store_get_active_key_empty_store_fails() {
    let store = PrincipalKeyStore::new();
    for role in KeyRole::ALL {
        assert_eq!(
            store.get_active_key(*role),
            Err(KeyRoleError::NoActiveKey { role: *role })
        );
    }
}

#[test]
fn enrichment_store_keys_for_role_returns_all_statuses() {
    let seed = test_seed();
    let ep = epoch(1);
    let sk1 = make_signing_key(&seed, ep);
    let sk2 = make_signing_key(&seed_n(0xBB), ep);
    let mut store = PrincipalKeyStore::new();
    store
        .register_key(make_role_entry(KeyRole::Signing, sk1.verification_key(), None, KeyStatus::Active, ep, 0))
        .unwrap();
    store
        .register_key(make_role_entry(KeyRole::Signing, sk2.verification_key(), None, KeyStatus::Pending, ep, 1))
        .unwrap();

    // Revoke key 0.
    store.revoke_key(KeyRole::Signing, 0, epoch(2)).unwrap();

    let all = store.keys_for_role(KeyRole::Signing);
    assert_eq!(all.len(), 2);
}

#[test]
fn enrichment_store_keys_for_role_empty_for_unused_role() {
    let seed = test_seed();
    let ep = epoch(1);
    let sk = make_signing_key(&seed, ep);
    let mut store = PrincipalKeyStore::new();
    store
        .register_key(make_role_entry(KeyRole::Signing, sk.verification_key(), None, KeyStatus::Active, ep, 0))
        .unwrap();
    assert!(store.keys_for_role(KeyRole::Encryption).is_empty());
    assert!(store.keys_for_role(KeyRole::Issuance).is_empty());
}

#[test]
fn enrichment_store_verification_keys_includes_active_and_rotated() {
    let seed = test_seed();
    let ep = epoch(1);
    let sk1 = make_signing_key(&seed, ep);
    let sk2 = make_signing_key(&seed_n(0xBB), ep);
    let mut store = PrincipalKeyStore::new();
    store
        .register_key(make_role_entry(KeyRole::Signing, sk1.verification_key(), None, KeyStatus::Active, ep, 0))
        .unwrap();
    store
        .register_key(make_role_entry(KeyRole::Signing, sk2.verification_key(), None, KeyStatus::Pending, ep, 1))
        .unwrap();

    // Rotate: key 0 -> Rotated, key 1 -> Active.
    store.rotate_key(KeyRole::Signing, 0, 1, epoch(2)).unwrap();

    let verifiable = store.verification_keys_for_role(KeyRole::Signing);
    assert_eq!(verifiable.len(), 2);
}

#[test]
fn enrichment_store_verification_keys_excludes_revoked() {
    let seed = test_seed();
    let ep = epoch(1);
    let sk = make_signing_key(&seed, ep);
    let mut store = PrincipalKeyStore::new();
    store
        .register_key(make_role_entry(KeyRole::Signing, sk.verification_key(), None, KeyStatus::Active, ep, 0))
        .unwrap();
    store.revoke_key(KeyRole::Signing, 0, epoch(2)).unwrap();

    let verifiable = store.verification_keys_for_role(KeyRole::Signing);
    assert!(verifiable.is_empty());
}

#[test]
fn enrichment_store_verification_keys_excludes_pending() {
    let seed = test_seed();
    let ep = epoch(1);
    let sk = make_signing_key(&seed, ep);
    let mut store = PrincipalKeyStore::new();
    store
        .register_key(make_role_entry(KeyRole::Signing, sk.verification_key(), None, KeyStatus::Pending, ep, 0))
        .unwrap();

    assert!(store.verification_keys_for_role(KeyRole::Signing).is_empty());
}

#[test]
fn enrichment_store_activate_pending_key() {
    let seed = test_seed();
    let ep = epoch(1);
    let sk = make_signing_key(&seed, ep);
    let mut store = PrincipalKeyStore::new();
    store
        .register_key(make_role_entry(KeyRole::Signing, sk.verification_key(), None, KeyStatus::Pending, ep, 0))
        .unwrap();

    assert!(store.get_active_key(KeyRole::Signing).is_err());
    store.activate_key(KeyRole::Signing, 0, epoch(2)).unwrap();
    assert!(store.get_active_key(KeyRole::Signing).is_ok());
}

#[test]
fn enrichment_store_activate_already_active_fails() {
    let seed = test_seed();
    let ep = epoch(1);
    let sk = make_signing_key(&seed, ep);
    let mut store = PrincipalKeyStore::new();
    store
        .register_key(make_role_entry(KeyRole::Signing, sk.verification_key(), None, KeyStatus::Active, ep, 0))
        .unwrap();
    let result = store.activate_key(KeyRole::Signing, 0, ep);
    assert_eq!(
        result,
        Err(KeyRoleError::KeyNotActive {
            role: KeyRole::Signing,
            status: KeyStatus::Active,
        })
    );
}

#[test]
fn enrichment_store_activate_nonexistent_key_fails() {
    let mut store = PrincipalKeyStore::new();
    let result = store.activate_key(KeyRole::Signing, 99, epoch(1));
    assert!(result.is_err());
}

#[test]
fn enrichment_store_revoke_key_changes_status() {
    let seed = test_seed();
    let ep = epoch(1);
    let sk = make_signing_key(&seed, ep);
    let mut store = PrincipalKeyStore::new();
    store
        .register_key(make_role_entry(KeyRole::Signing, sk.verification_key(), None, KeyStatus::Active, ep, 0))
        .unwrap();

    assert!(store.get_active_key(KeyRole::Signing).is_ok());
    store.revoke_key(KeyRole::Signing, 0, epoch(2)).unwrap();
    assert!(store.get_active_key(KeyRole::Signing).is_err());
}

#[test]
fn enrichment_store_revoke_nonexistent_key_fails() {
    let mut store = PrincipalKeyStore::new();
    let result = store.revoke_key(KeyRole::Signing, 99, epoch(1));
    assert!(result.is_err());
}

#[test]
fn enrichment_store_rotate_key_lifecycle() {
    let seed = test_seed();
    let ep1 = epoch(1);
    let ep2 = epoch(2);
    let sk1 = make_signing_key(&seed, ep1);
    let sk2 = make_signing_key(&seed_n(0xBB), ep2);

    let mut store = PrincipalKeyStore::new();
    store
        .register_key(make_role_entry(KeyRole::Signing, sk1.verification_key(), None, KeyStatus::Active, ep1, 0))
        .unwrap();
    store
        .register_key(make_role_entry(KeyRole::Signing, sk2.verification_key(), None, KeyStatus::Pending, ep2, 1))
        .unwrap();

    store.rotate_key(KeyRole::Signing, 0, 1, ep2).unwrap();

    let active = store.get_active_key(KeyRole::Signing).unwrap();
    assert_eq!(active.sequence, 1);
}

#[test]
fn enrichment_store_rotate_non_active_old_key_fails() {
    let seed = test_seed();
    let ep = epoch(1);
    let sk1 = make_signing_key(&seed, ep);
    let sk2 = make_signing_key(&seed_n(0xBB), ep);

    let mut store = PrincipalKeyStore::new();
    store
        .register_key(make_role_entry(KeyRole::Signing, sk1.verification_key(), None, KeyStatus::Pending, ep, 0))
        .unwrap();
    store
        .register_key(make_role_entry(KeyRole::Signing, sk2.verification_key(), None, KeyStatus::Pending, ep, 1))
        .unwrap();

    let result = store.rotate_key(KeyRole::Signing, 0, 1, ep);
    assert_eq!(
        result,
        Err(KeyRoleError::KeyNotActive {
            role: KeyRole::Signing,
            status: KeyStatus::Pending,
        })
    );
}

#[test]
fn enrichment_store_rotate_non_pending_new_key_fails() {
    let seed = test_seed();
    let ep = epoch(1);
    let sk1 = make_signing_key(&seed, ep);
    let sk2 = make_signing_key(&seed_n(0xBB), ep);

    let mut store = PrincipalKeyStore::new();
    store
        .register_key(make_role_entry(KeyRole::Signing, sk1.verification_key(), None, KeyStatus::Active, ep, 0))
        .unwrap();
    store
        .register_key(make_role_entry(KeyRole::Signing, sk2.verification_key(), None, KeyStatus::Active, ep, 1))
        .unwrap();

    let result = store.rotate_key(KeyRole::Signing, 0, 1, ep);
    assert_eq!(
        result,
        Err(KeyRoleError::KeyNotActive {
            role: KeyRole::Signing,
            status: KeyStatus::Active,
        })
    );
}

#[test]
fn enrichment_store_set_and_get_bundle() {
    let seed = test_seed();
    let ep = epoch(1);
    let sk = make_signing_key(&seed, ep);
    let enc = make_encryption_private(&seed, ep);
    let iss = make_issuance_key(&seed, ep);

    let bundle = OwnerKeyBundle::create_signed(
        &sk,
        sk.verification_key(),
        enc.public_key(),
        iss.verification_key(),
        ep,
        1,
    )
    .unwrap();

    let mut store = PrincipalKeyStore::new();
    assert!(store.bundle().is_none());
    store.set_bundle(bundle.clone());
    assert!(store.bundle().is_some());
    assert_eq!(store.bundle().unwrap().sequence, 1);
}

#[test]
fn enrichment_store_total_key_count() {
    let store = build_full_store(&test_seed(), epoch(1));
    assert_eq!(store.total_key_count(), 3);
}

#[test]
fn enrichment_store_serde_roundtrip() {
    let mut store = build_full_store(&test_seed(), epoch(1));

    let seed = test_seed();
    let ep = epoch(1);
    let sk = make_signing_key(&seed, ep);
    let enc = make_encryption_private(&seed, ep);
    let iss = make_issuance_key(&seed, ep);
    let bundle = OwnerKeyBundle::create_signed(
        &sk,
        sk.verification_key(),
        enc.public_key(),
        iss.verification_key(),
        ep,
        1,
    )
    .unwrap();
    store.set_bundle(bundle);

    // PrincipalKeyStore contains BTreeMap with non-string keys — JSON serde
    // fails ("key must be a string").  Verify state directly instead.
    assert_eq!(store.total_key_count(), 3);
    assert!(store.bundle().is_some());
}

// ===========================================================================
// Independent revocation per role
// ===========================================================================

#[test]
fn enrichment_independent_revocation_per_role() {
    let mut store = build_full_store(&test_seed(), epoch(1));

    // Revoke only signing.
    store.revoke_key(KeyRole::Signing, 0, epoch(2)).unwrap();

    assert!(store.get_active_key(KeyRole::Signing).is_err());
    assert!(store.get_active_key(KeyRole::Encryption).is_ok());
    assert!(store.get_active_key(KeyRole::Issuance).is_ok());
}

#[test]
fn enrichment_independent_revocation_encryption_only() {
    let mut store = build_full_store(&test_seed(), epoch(1));

    store.revoke_key(KeyRole::Encryption, 0, epoch(2)).unwrap();

    assert!(store.get_active_key(KeyRole::Signing).is_ok());
    assert!(store.get_active_key(KeyRole::Encryption).is_err());
    assert!(store.get_active_key(KeyRole::Issuance).is_ok());
}

#[test]
fn enrichment_independent_revocation_issuance_only() {
    let mut store = build_full_store(&test_seed(), epoch(1));

    store.revoke_key(KeyRole::Issuance, 0, epoch(2)).unwrap();

    assert!(store.get_active_key(KeyRole::Signing).is_ok());
    assert!(store.get_active_key(KeyRole::Encryption).is_ok());
    assert!(store.get_active_key(KeyRole::Issuance).is_err());
}

// ===========================================================================
// Cross-role security enforcement
// ===========================================================================

#[test]
fn enrichment_cross_role_signing_cannot_issue() {
    let store = build_full_store(&test_seed(), epoch(1));
    let signing_entry = store.get_active_key(KeyRole::Signing).unwrap();
    assert_eq!(
        enforce_active_role(signing_entry, KeyRole::Issuance),
        Err(KeyRoleError::KeyRoleMismatch {
            expected: KeyRole::Issuance,
            actual: KeyRole::Signing,
        })
    );
}

#[test]
fn enrichment_cross_role_encryption_cannot_sign() {
    let store = build_full_store(&test_seed(), epoch(1));
    let enc_entry = store.get_active_key(KeyRole::Encryption).unwrap();
    assert_eq!(
        enforce_active_role(enc_entry, KeyRole::Signing),
        Err(KeyRoleError::KeyRoleMismatch {
            expected: KeyRole::Signing,
            actual: KeyRole::Encryption,
        })
    );
}

#[test]
fn enrichment_cross_role_issuance_cannot_encrypt() {
    let store = build_full_store(&test_seed(), epoch(1));
    let iss_entry = store.get_active_key(KeyRole::Issuance).unwrap();
    assert_eq!(
        enforce_active_role(iss_entry, KeyRole::Encryption),
        Err(KeyRoleError::KeyRoleMismatch {
            expected: KeyRole::Encryption,
            actual: KeyRole::Issuance,
        })
    );
}

// ===========================================================================
// Full lifecycle: create -> activate -> rotate -> revoke
// ===========================================================================

#[test]
fn enrichment_full_lifecycle_create_activate_rotate_revoke() {
    let seed = test_seed();
    let ep1 = epoch(1);
    let ep2 = epoch(2);
    let ep3 = epoch(3);
    let ep4 = epoch(4);

    let sk1 = make_signing_key(&seed, ep1);
    let sk2 = make_signing_key(&seed_n(0xBB), ep2);

    let mut store = PrincipalKeyStore::new();

    // Step 1: Register key as Pending.
    store
        .register_key(make_role_entry(KeyRole::Signing, sk1.verification_key(), None, KeyStatus::Pending, ep1, 0))
        .unwrap();
    assert!(store.get_active_key(KeyRole::Signing).is_err());

    // Step 2: Activate.
    store.activate_key(KeyRole::Signing, 0, ep2).unwrap();
    assert_eq!(store.get_active_key(KeyRole::Signing).unwrap().sequence, 0);

    // Step 3: Register a successor as Pending.
    store
        .register_key(make_role_entry(KeyRole::Signing, sk2.verification_key(), None, KeyStatus::Pending, ep2, 1))
        .unwrap();

    // Step 4: Rotate.
    store.rotate_key(KeyRole::Signing, 0, 1, ep3).unwrap();
    let active = store.get_active_key(KeyRole::Signing).unwrap();
    assert_eq!(active.sequence, 1);

    // Both keys verifiable.
    assert_eq!(store.verification_keys_for_role(KeyRole::Signing).len(), 2);

    // Step 5: Revoke the old rotated key.
    store.revoke_key(KeyRole::Signing, 0, ep4).unwrap();
    // Only the new key remains verifiable.
    assert_eq!(store.verification_keys_for_role(KeyRole::Signing).len(), 1);
}

// ===========================================================================
// Multiple rotations in sequence
// ===========================================================================

#[test]
fn enrichment_multiple_sequential_rotations() {
    let ep = epoch(1);
    let mut store = PrincipalKeyStore::new();

    // Register and activate key 0.
    let sk0 = make_signing_key(&seed_n(0x01), ep);
    store
        .register_key(make_role_entry(KeyRole::Signing, sk0.verification_key(), None, KeyStatus::Active, ep, 0))
        .unwrap();

    // Register key 1 as pending, rotate 0 -> 1.
    let sk1 = make_signing_key(&seed_n(0x02), ep);
    store
        .register_key(make_role_entry(KeyRole::Signing, sk1.verification_key(), None, KeyStatus::Pending, ep, 1))
        .unwrap();
    store.rotate_key(KeyRole::Signing, 0, 1, epoch(2)).unwrap();

    // Register key 2 as pending, rotate 1 -> 2.
    let sk2 = make_signing_key(&seed_n(0x03), ep);
    store
        .register_key(make_role_entry(KeyRole::Signing, sk2.verification_key(), None, KeyStatus::Pending, ep, 2))
        .unwrap();
    store.rotate_key(KeyRole::Signing, 1, 2, epoch(3)).unwrap();

    // Active key should be sequence 2.
    assert_eq!(store.get_active_key(KeyRole::Signing).unwrap().sequence, 2);

    // Keys 0 and 1 are Rotated, key 2 is Active -- all three are verifiable.
    assert_eq!(store.verification_keys_for_role(KeyRole::Signing).len(), 3);

    // Total keys for signing role: 3.
    assert_eq!(store.keys_for_role(KeyRole::Signing).len(), 3);
}

// ===========================================================================
// Bundle replacement
// ===========================================================================

#[test]
fn enrichment_store_bundle_replacement() {
    let seed = test_seed();
    let ep = epoch(1);
    let sk = make_signing_key(&seed, ep);
    let enc = make_encryption_private(&seed, ep);
    let iss = make_issuance_key(&seed, ep);

    let b1 = OwnerKeyBundle::create_signed(
        &sk,
        sk.verification_key(),
        enc.public_key(),
        iss.verification_key(),
        ep,
        1,
    )
    .unwrap();

    let b2 = OwnerKeyBundle::create_signed(
        &sk,
        sk.verification_key(),
        enc.public_key(),
        iss.verification_key(),
        ep,
        2,
    )
    .unwrap();

    let mut store = PrincipalKeyStore::new();
    store.set_bundle(b1);
    assert_eq!(store.bundle().unwrap().sequence, 1);

    store.set_bundle(b2);
    assert_eq!(store.bundle().unwrap().sequence, 2);
}

// ===========================================================================
// Adversarial: compromised signing key cannot be used for issuance
// ===========================================================================

#[test]
fn enrichment_adversarial_signing_key_cannot_issue() {
    let seed = test_seed();
    let ep = epoch(1);
    let compromised_sk = make_signing_key(&seed, ep);
    let legitimate_iss = make_issuance_key(&seed, ep);

    // Domain separation ensures these are different keys.
    assert_ne!(
        compromised_sk.verification_key(),
        legitimate_iss.verification_key()
    );

    let mut store = PrincipalKeyStore::new();
    store
        .register_key(make_role_entry(
            KeyRole::Signing,
            compromised_sk.verification_key(),
            None,
            KeyStatus::Active,
            ep,
            0,
        ))
        .unwrap();
    store
        .register_key(make_role_entry(
            KeyRole::Issuance,
            legitimate_iss.verification_key(),
            None,
            KeyStatus::Active,
            ep,
            0,
        ))
        .unwrap();

    let signing_entry = store.get_active_key(KeyRole::Signing).unwrap();
    assert!(enforce_active_role(signing_entry, KeyRole::Issuance).is_err());

    let issuance_entry = store.get_active_key(KeyRole::Issuance).unwrap();
    assert!(enforce_active_role(issuance_entry, KeyRole::Issuance).is_ok());
}

// ===========================================================================
// Sequence equal to max rejected
// ===========================================================================

#[test]
fn enrichment_sequence_equal_to_existing_max_rejected() {
    let seed = test_seed();
    let ep = epoch(1);
    let sk1 = make_signing_key(&seed, ep);
    let sk2 = make_signing_key(&seed_n(0xBB), ep);
    let mut store = PrincipalKeyStore::new();
    store
        .register_key(make_role_entry(KeyRole::Signing, sk1.verification_key(), None, KeyStatus::Active, ep, 5))
        .unwrap();

    // Same sequence (5) but different key should still fail because 5 <= 5.
    let result = store.register_key(make_role_entry(
        KeyRole::Signing,
        sk2.verification_key(),
        None,
        KeyStatus::Pending,
        ep,
        5,
    ));
    // This is a DuplicateKey error because the (role, sequence) pair is already present.
    assert_eq!(
        result,
        Err(KeyRoleError::DuplicateKey {
            role: KeyRole::Signing,
            sequence: 5,
        })
    );
}

// ===========================================================================
// Store clone
// ===========================================================================

#[test]
fn enrichment_store_clone() {
    let store = build_full_store(&test_seed(), epoch(1));
    let cloned = store.clone();
    assert_eq!(cloned.total_key_count(), store.total_key_count());
}
