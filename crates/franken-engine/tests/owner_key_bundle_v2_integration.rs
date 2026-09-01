#![forbid(unsafe_code)]

use frankenengine_engine::capability_token::PrincipalId;
use frankenengine_engine::engine_object_id::ObjectIdDerivationVersion;
use frankenengine_engine::principal_key_roles::{
    verify_legacy_owner_key_bundle_strict, EncryptionPublicKey, OwnerKeyBundle, OwnerKeyBundleV2,
    OwnerKeyBundleV2Error,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{
    sign_preimage, SignaturePreimage, SigningKey,
};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes([seed; 32]).expect("valid deterministic test key")
}

fn encryption(seed: u8) -> EncryptionPublicKey {
    EncryptionPublicKey::from_bytes([seed; 32])
}

fn fresh_v2(owner: &SigningKey) -> OwnerKeyBundleV2 {
    OwnerKeyBundleV2::create_signed(
        owner,
        key(2).verification_key(),
        encryption(3),
        key(4).verification_key(),
        SecurityEpoch::GENESIS,
        1,
    )
    .expect("create v2 owner bundle")
}

fn fresh_legacy(owner: &SigningKey) -> OwnerKeyBundle {
    OwnerKeyBundle::create_signed(
        owner,
        key(2).verification_key(),
        encryption(3),
        key(4).verification_key(),
        SecurityEpoch::GENESIS,
        1,
    )
    .expect("create legacy owner bundle")
}

#[test]
fn v2_bundle_binds_owner_principal_and_sha256_identity() {
    let owner = key(1);
    let bundle = fresh_v2(&owner);
    assert_eq!(
        bundle.owner_principal,
        PrincipalId::from_verification_key(&owner.verification_key())
    );
    assert_eq!(
        bundle.id.derivation_version,
        ObjectIdDerivationVersion::Sha256V2
    );
    bundle
        .verify(&owner.verification_key())
        .expect("verify v2 bundle");
}

#[test]
fn signed_but_arbitrary_v2_id_is_rejected() {
    let owner = key(1);
    let mut bundle = fresh_v2(&owner);
    bundle.id.object_id.0[0] ^= 1;
    bundle.owner_signature =
        sign_preimage(&owner, &bundle.preimage_bytes()).expect("re-sign crafted v2 id");
    assert!(bundle.validate_identity().is_err());
}

#[test]
fn wrong_owner_key_is_rejected_even_when_role_keys_match() {
    let owner = key(1);
    let bundle = fresh_v2(&owner);
    assert!(matches!(
        bundle.verify(&key(9).verification_key()),
        Err(OwnerKeyBundleV2Error::OwnerPrincipalMismatch { .. })
    ));
}

#[test]
fn strict_legacy_verifier_rejects_resigned_arbitrary_id() {
    let owner = key(1);
    let mut legacy = fresh_legacy(&owner);
    legacy.id.0[0] ^= 1;
    legacy.owner_signature =
        sign_preimage(&owner, &legacy.preimage_bytes()).expect("re-sign crafted legacy id");

    legacy
        .verify(&owner.verification_key())
        .expect("historical signature-only verification accepts crafted id");
    assert!(matches!(
        verify_legacy_owner_key_bundle_strict(&legacy, &owner.verification_key()),
        Err(OwnerKeyBundleV2Error::LegacyIdentityMismatch)
    ));
}

#[test]
fn verified_legacy_bundle_migrates_with_owner_provenance() {
    let owner = key(1);
    let legacy = fresh_legacy(&owner);
    let migrated =
        OwnerKeyBundleV2::migrate_verified_legacy(&legacy, &owner).expect("migrate legacy bundle");
    assert!(migrated.legacy_provenance.is_some());
    assert_eq!(migrated.signing_key, legacy.signing_key);
    assert_eq!(migrated.encryption_key, legacy.encryption_key);
    assert_eq!(migrated.issuance_key, legacy.issuance_key);
    migrated
        .verify(&owner.verification_key())
        .expect("verify migrated bundle");
}

#[test]
fn migrated_semantics_cannot_diverge_from_legacy_provenance() {
    let owner = key(1);
    let legacy = fresh_legacy(&owner);
    let mut migrated =
        OwnerKeyBundleV2::migrate_verified_legacy(&legacy, &owner).expect("migrate legacy bundle");
    migrated.sequence = 2;
    assert!(matches!(
        migrated.validate_identity(),
        Err(OwnerKeyBundleV2Error::LegacyMappingMismatch("sequence"))
    ));
}
