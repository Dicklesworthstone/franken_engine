#![forbid(unsafe_code)]
//! Integration tests for the `capability_token` module.
//!
//! These tests exercise the public API from outside the crate, covering
//! token construction, builder validation, signature verification, audience
//! checking, temporal validity, checkpoint binding, revocation freshness
//! binding, determinism, serde round-trips, and Display impls.

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

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::capability_token::{
    CapabilityToken, CheckpointRef, PrincipalId, RevocationFreshnessRef, TokenBuilder, TokenError,
    TokenEvent, TokenEventType, TokenVersion, VerificationContext, token_schema, token_schema_id,
    verify_token,
};
use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{SigningKey, VerificationKey};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes([seed; 32])
}

fn make_principal(seed: u8) -> PrincipalId {
    PrincipalId::from_bytes([seed; 32])
}

fn make_checkpoint_ref(seq: u64) -> CheckpointRef {
    CheckpointRef {
        min_checkpoint_seq: seq,
        checkpoint_id: EngineObjectId([seq as u8; 32]),
    }
}

fn make_revocation_ref(seq: u64) -> RevocationFreshnessRef {
    RevocationFreshnessRef {
        min_revocation_seq: seq,
        revocation_head_hash: ContentHash::compute(&seq.to_be_bytes()),
    }
}

fn build_basic_token(sk: &SigningKey) -> CapabilityToken {
    TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-a",
    )
    .add_audience(make_principal(10))
    .add_capability(RuntimeCapability::VmDispatch)
    .build()
    .unwrap()
}

fn basic_ctx() -> VerificationContext {
    VerificationContext {
        current_tick: 500,
        verifier_checkpoint_seq: 10,
        verifier_revocation_seq: 5,
    }
}

// ---------------------------------------------------------------------------
// Schema helpers
// ---------------------------------------------------------------------------

#[test]
fn schema_hash_is_deterministic() {
    let s1 = token_schema();
    let s2 = token_schema();
    assert_eq!(s1, s2);
}

#[test]
fn schema_id_is_deterministic() {
    let id1 = token_schema_id();
    let id2 = token_schema_id();
    assert_eq!(id1, id2);
}

// ---------------------------------------------------------------------------
// PrincipalId
// ---------------------------------------------------------------------------

#[test]
fn principal_from_bytes_round_trip() {
    let bytes = [0xAB; 32];
    let p = PrincipalId::from_bytes(bytes);
    assert_eq!(*p.as_bytes(), bytes);
}

#[test]
fn principal_from_verification_key() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let p = PrincipalId::from_verification_key(&vk);
    // Same key should produce same principal.
    let p2 = PrincipalId::from_verification_key(&vk);
    assert_eq!(p, p2);
}

#[test]
fn principal_from_different_keys_differ() {
    let vk1 = make_sk(1).verification_key();
    let vk2 = make_sk(2).verification_key();
    let p1 = PrincipalId::from_verification_key(&vk1);
    let p2 = PrincipalId::from_verification_key(&vk2);
    assert_ne!(p1, p2);
}

#[test]
fn principal_to_hex_is_64_chars() {
    let p = make_principal(0xFF);
    let hex = p.to_hex();
    assert_eq!(hex.len(), 64);
    // All chars should be valid hex digits.
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn principal_display_starts_with_principal_prefix() {
    let p = make_principal(0xAB);
    let display = p.to_string();
    assert!(display.starts_with("principal:"));
    // Display uses first 8 hex chars.
    assert_eq!(display.len(), "principal:".len() + 8);
}

#[test]
fn principal_ord_is_consistent() {
    let p1 = PrincipalId::from_bytes([0x01; 32]);
    let p2 = PrincipalId::from_bytes([0x02; 32]);
    assert!(p1 < p2);
}

#[test]
fn principal_serde_round_trip() {
    let p = make_principal(0xAB);
    let json = serde_json::to_string(&p).unwrap();
    let restored: PrincipalId = serde_json::from_str(&json).unwrap();
    assert_eq!(p, restored);
}

// ---------------------------------------------------------------------------
// TokenVersion
// ---------------------------------------------------------------------------

#[test]
fn token_version_display_v2() {
    assert_eq!(TokenVersion::V2.to_string(), "v2");
}

#[test]
fn token_version_ord() {
    // Only V2 exists, but it should be comparable to itself.
    assert_eq!(TokenVersion::V2, TokenVersion::V2);
}

#[test]
fn token_version_serde_round_trip() {
    let v = TokenVersion::V2;
    let json = serde_json::to_string(&v).unwrap();
    let restored: TokenVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, restored);
}

// ---------------------------------------------------------------------------
// CheckpointRef & RevocationFreshnessRef serde
// ---------------------------------------------------------------------------

#[test]
fn checkpoint_ref_serde_round_trip() {
    let cr = make_checkpoint_ref(42);
    let json = serde_json::to_string(&cr).unwrap();
    let restored: CheckpointRef = serde_json::from_str(&json).unwrap();
    assert_eq!(cr, restored);
}

#[test]
fn revocation_freshness_ref_serde_round_trip() {
    let rr = make_revocation_ref(99);
    let json = serde_json::to_string(&rr).unwrap();
    let restored: RevocationFreshnessRef = serde_json::from_str(&json).unwrap();
    assert_eq!(rr, restored);
}

// ---------------------------------------------------------------------------
// TokenBuilder — construction
// ---------------------------------------------------------------------------

#[test]
fn builder_creates_token_with_correct_fields() {
    let sk = make_sk(1);
    let token = build_basic_token(&sk);
    assert_eq!(token.version, TokenVersion::V2);
    assert_eq!(token.issuer, sk.verification_key());
    assert_eq!(token.nbf, DeterministicTimestamp(100));
    assert_eq!(token.expiry, DeterministicTimestamp(1000));
    assert_eq!(token.epoch, SecurityEpoch::GENESIS);
    assert_eq!(token.zone, "zone-a");
    assert!(token.capabilities.contains(&RuntimeCapability::VmDispatch));
    assert!(token.audience.contains(&make_principal(10)));
    assert!(token.checkpoint_binding.is_none());
    assert!(token.revocation_freshness.is_none());
}

#[test]
fn builder_with_multiple_audience_members() {
    let sk = make_sk(1);
    let token = TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(0),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-multi",
    )
    .add_audience(make_principal(1))
    .add_audience(make_principal(2))
    .add_audience(make_principal(3))
    .add_capability(RuntimeCapability::PolicyRead)
    .build()
    .unwrap();

    assert_eq!(token.audience.len(), 3);
}

#[test]
fn builder_with_multiple_capabilities_via_add_capabilities() {
    let sk = make_sk(1);
    let caps = vec![
        RuntimeCapability::VmDispatch,
        RuntimeCapability::GcInvoke,
        RuntimeCapability::IrLowering,
        RuntimeCapability::PolicyRead,
    ];
    let token = TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(0),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-caps",
    )
    .add_audience(make_principal(1))
    .add_capabilities(caps)
    .build()
    .unwrap();

    assert_eq!(token.capabilities.len(), 4);
}

#[test]
fn builder_with_checkpoint_binding() {
    let sk = make_sk(1);
    let token = TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-a",
    )
    .add_audience(make_principal(10))
    .add_capability(RuntimeCapability::VmDispatch)
    .bind_checkpoint(make_checkpoint_ref(42))
    .build()
    .unwrap();

    let binding = token.checkpoint_binding.as_ref().unwrap();
    assert_eq!(binding.min_checkpoint_seq, 42);
}

#[test]
fn builder_with_revocation_freshness() {
    let sk = make_sk(1);
    let token = TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-a",
    )
    .add_audience(make_principal(10))
    .add_capability(RuntimeCapability::PolicyRead)
    .bind_revocation_freshness(make_revocation_ref(99))
    .build()
    .unwrap();

    let freshness = token.revocation_freshness.as_ref().unwrap();
    assert_eq!(freshness.min_revocation_seq, 99);
}

#[test]
fn builder_with_all_bindings() {
    let sk = make_sk(1);
    let token = TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(50),
        DeterministicTimestamp(9999),
        SecurityEpoch::from_raw(7),
        "zone-full",
    )
    .add_audience(make_principal(10))
    .add_audience(make_principal(20))
    .add_capability(RuntimeCapability::VmDispatch)
    .add_capability(RuntimeCapability::FsRead)
    .bind_checkpoint(make_checkpoint_ref(10))
    .bind_revocation_freshness(make_revocation_ref(5))
    .build()
    .unwrap();

    assert!(token.checkpoint_binding.is_some());
    assert!(token.revocation_freshness.is_some());
    assert_eq!(token.audience.len(), 2);
    assert_eq!(token.capabilities.len(), 2);
    assert_eq!(token.epoch, SecurityEpoch::from_raw(7));
}

#[test]
fn builder_empty_audience_is_allowed() {
    let sk = make_sk(1);
    let token = TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-a",
    )
    .add_capability(RuntimeCapability::VmDispatch)
    .build()
    .unwrap();

    assert!(token.audience.is_empty());
}

// ---------------------------------------------------------------------------
// TokenBuilder — validation errors
// ---------------------------------------------------------------------------

#[test]
fn builder_rejects_empty_capabilities() {
    let sk = make_sk(1);
    let err = TokenBuilder::new(
        sk,
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-a",
    )
    .add_audience(make_principal(10))
    .build()
    .unwrap_err();

    assert!(matches!(err, TokenError::EmptyCapabilities));
    assert!(err.to_string().contains("empty capabilities"));
}

#[test]
fn builder_rejects_inverted_temporal_window() {
    let sk = make_sk(1);
    let err = TokenBuilder::new(
        sk,
        DeterministicTimestamp(1000), // nbf > expiry
        DeterministicTimestamp(100),
        SecurityEpoch::GENESIS,
        "zone-a",
    )
    .add_audience(make_principal(10))
    .add_capability(RuntimeCapability::VmDispatch)
    .build()
    .unwrap_err();

    match &err {
        TokenError::InvertedTemporalWindow { not_before, expiry } => {
            assert_eq!(*not_before, 1000);
            assert_eq!(*expiry, 100);
        }
        other => panic!("expected InvertedTemporalWindow, got {other:?}"),
    }
}

#[test]
fn builder_allows_equal_nbf_and_expiry() {
    let sk = make_sk(1);
    let token = TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(500),
        DeterministicTimestamp(500), // nbf == expiry is allowed
        SecurityEpoch::GENESIS,
        "zone-a",
    )
    .add_capability(RuntimeCapability::VmDispatch)
    .build()
    .unwrap();

    assert_eq!(token.nbf, DeterministicTimestamp(500));
    assert_eq!(token.expiry, DeterministicTimestamp(500));
}

// ---------------------------------------------------------------------------
// Token JTI determinism
// ---------------------------------------------------------------------------

#[test]
fn jti_is_deterministic() {
    let sk = make_sk(1);
    let t1 = build_basic_token(&sk);
    let t2 = build_basic_token(&sk);
    assert_eq!(t1.jti, t2.jti);
}

#[test]
fn different_capabilities_produce_different_jti() {
    let sk = make_sk(1);
    let t1 = TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-a",
    )
    .add_audience(make_principal(10))
    .add_capability(RuntimeCapability::VmDispatch)
    .build()
    .unwrap();

    let t2 = TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-a",
    )
    .add_audience(make_principal(10))
    .add_capability(RuntimeCapability::GcInvoke)
    .build()
    .unwrap();

    assert_ne!(t1.jti, t2.jti);
}

#[test]
fn different_zones_produce_different_jti() {
    let sk = make_sk(1);
    let t1 = TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-a",
    )
    .add_capability(RuntimeCapability::VmDispatch)
    .build()
    .unwrap();

    let t2 = TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-b",
    )
    .add_capability(RuntimeCapability::VmDispatch)
    .build()
    .unwrap();

    assert_ne!(t1.jti, t2.jti);
}

#[test]
fn different_issuers_produce_different_jti() {
    let t1 = build_basic_token(&make_sk(1));
    let t2 = TokenBuilder::new(
        make_sk(2),
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-a",
    )
    .add_audience(make_principal(10))
    .add_capability(RuntimeCapability::VmDispatch)
    .build()
    .unwrap();

    assert_ne!(t1.jti, t2.jti);
}

#[test]
fn different_epochs_produce_different_jti() {
    let sk = make_sk(1);
    let t1 = TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-a",
    )
    .add_capability(RuntimeCapability::VmDispatch)
    .build()
    .unwrap();

    let t2 = TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::from_raw(5),
        "zone-a",
    )
    .add_capability(RuntimeCapability::VmDispatch)
    .build()
    .unwrap();

    assert_ne!(t1.jti, t2.jti);
}

// ---------------------------------------------------------------------------
// Preimage determinism
// ---------------------------------------------------------------------------

#[test]
fn preimage_bytes_deterministic() {
    use frankenengine_engine::signature_preimage::SignaturePreimage;
    let sk = make_sk(1);
    let t = build_basic_token(&sk);
    let p1 = t.preimage_bytes();
    let p2 = t.preimage_bytes();
    assert_eq!(p1, p2);
}

#[test]
fn same_inputs_produce_same_preimage() {
    use frankenengine_engine::signature_preimage::SignaturePreimage;
    let sk = make_sk(1);
    let t1 = build_basic_token(&sk);
    let t2 = build_basic_token(&sk);
    assert_eq!(t1.preimage_bytes(), t2.preimage_bytes());
}

// ---------------------------------------------------------------------------
// Verification — happy paths
// ---------------------------------------------------------------------------

#[test]
fn verify_succeeds_for_valid_token() {
    let sk = make_sk(1);
    let token = build_basic_token(&sk);
    let ctx = basic_ctx();
    verify_token(&token, &make_principal(10), &ctx).unwrap();
}

#[test]
fn verify_succeeds_at_exact_nbf() {
    let sk = make_sk(1);
    let token = build_basic_token(&sk);
    let ctx = VerificationContext {
        current_tick: 100, // exactly nbf
        verifier_checkpoint_seq: 10,
        verifier_revocation_seq: 5,
    };
    verify_token(&token, &make_principal(10), &ctx).unwrap();
}

#[test]
fn verify_succeeds_at_exact_expiry() {
    let sk = make_sk(1);
    let token = build_basic_token(&sk);
    let ctx = VerificationContext {
        current_tick: 1000, // exactly expiry
        verifier_checkpoint_seq: 10,
        verifier_revocation_seq: 5,
    };
    verify_token(&token, &make_principal(10), &ctx).unwrap();
}

#[test]
fn verify_empty_audience_allows_any_presenter() {
    let sk = make_sk(1);
    let token = TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-a",
    )
    .add_capability(RuntimeCapability::VmDispatch)
    .build()
    .unwrap();

    let ctx = basic_ctx();
    // Any random principal should be accepted.
    verify_token(&token, &make_principal(99), &ctx).unwrap();
    verify_token(&token, &make_principal(0), &ctx).unwrap();
    verify_token(&token, &make_principal(255), &ctx).unwrap();
}

#[test]
fn verify_with_checkpoint_binding_succeeds_when_frontier_sufficient() {
    let sk = make_sk(1);
    let token = TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-a",
    )
    .add_audience(make_principal(10))
    .add_capability(RuntimeCapability::VmDispatch)
    .bind_checkpoint(make_checkpoint_ref(10))
    .build()
    .unwrap();

    let ctx = VerificationContext {
        current_tick: 500,
        verifier_checkpoint_seq: 10, // exactly meets requirement
        verifier_revocation_seq: 5,
    };
    verify_token(&token, &make_principal(10), &ctx).unwrap();
}

#[test]
fn verify_with_checkpoint_binding_succeeds_when_frontier_exceeds() {
    let sk = make_sk(1);
    let token = TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-a",
    )
    .add_audience(make_principal(10))
    .add_capability(RuntimeCapability::VmDispatch)
    .bind_checkpoint(make_checkpoint_ref(10))
    .build()
    .unwrap();

    let ctx = VerificationContext {
        current_tick: 500,
        verifier_checkpoint_seq: 100, // well above requirement
        verifier_revocation_seq: 5,
    };
    verify_token(&token, &make_principal(10), &ctx).unwrap();
}

#[test]
fn verify_with_revocation_freshness_succeeds_when_sufficient() {
    let sk = make_sk(1);
    let token = TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-a",
    )
    .add_audience(make_principal(10))
    .add_capability(RuntimeCapability::VmDispatch)
    .bind_revocation_freshness(make_revocation_ref(5))
    .build()
    .unwrap();

    let ctx = basic_ctx(); // verifier_revocation_seq = 5
    verify_token(&token, &make_principal(10), &ctx).unwrap();
}

#[test]
fn verify_with_all_bindings_succeeds() {
    let sk = make_sk(1);
    let token = TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-a",
    )
    .add_audience(make_principal(10))
    .add_capability(RuntimeCapability::VmDispatch)
    .bind_checkpoint(make_checkpoint_ref(5))
    .bind_revocation_freshness(make_revocation_ref(3))
    .build()
    .unwrap();

    let ctx = basic_ctx();
    verify_token(&token, &make_principal(10), &ctx).unwrap();
}

// ---------------------------------------------------------------------------
// Verification — signature failures
// ---------------------------------------------------------------------------

#[test]
fn verify_fails_tampered_signature() {
    let sk = make_sk(1);
    let mut token = build_basic_token(&sk);
    token.signature.lower[0] ^= 0xFF;

    let ctx = basic_ctx();
    let err = verify_token(&token, &make_principal(10), &ctx).unwrap_err();
    assert!(matches!(err, TokenError::SignatureInvalid { .. }));
}

#[test]
fn verify_fails_wrong_issuer() {
    let sk = make_sk(1);
    let mut token = build_basic_token(&sk);
    token.issuer = VerificationKey::from_bytes([0xFF; 32]);

    let ctx = basic_ctx();
    let err = verify_token(&token, &make_principal(10), &ctx).unwrap_err();
    assert!(matches!(err, TokenError::SignatureInvalid { .. }));
}

#[test]
fn modifying_audience_invalidates_signature() {
    let sk = make_sk(1);
    let mut token = build_basic_token(&sk);
    token.audience.insert(make_principal(99));

    let ctx = basic_ctx();
    let err = verify_token(&token, &make_principal(10), &ctx).unwrap_err();
    assert!(matches!(err, TokenError::SignatureInvalid { .. }));
}

#[test]
fn modifying_capabilities_invalidates_signature() {
    let sk = make_sk(1);
    let mut token = build_basic_token(&sk);
    token.capabilities.insert(RuntimeCapability::FsWrite);

    let ctx = basic_ctx();
    let err = verify_token(&token, &make_principal(10), &ctx).unwrap_err();
    assert!(matches!(err, TokenError::SignatureInvalid { .. }));
}

#[test]
fn modifying_nbf_invalidates_signature() {
    let sk = make_sk(1);
    let mut token = build_basic_token(&sk);
    token.nbf = DeterministicTimestamp(0);

    let ctx = basic_ctx();
    let err = verify_token(&token, &make_principal(10), &ctx).unwrap_err();
    assert!(matches!(err, TokenError::SignatureInvalid { .. }));
}

#[test]
fn modifying_expiry_invalidates_signature() {
    let sk = make_sk(1);
    let mut token = build_basic_token(&sk);
    token.expiry = DeterministicTimestamp(9999);

    let ctx = basic_ctx();
    let err = verify_token(&token, &make_principal(10), &ctx).unwrap_err();
    assert!(matches!(err, TokenError::SignatureInvalid { .. }));
}

#[test]
fn modifying_zone_invalidates_signature() {
    let sk = make_sk(1);
    let mut token = build_basic_token(&sk);
    token.zone = "zone-evil".to_string();

    let ctx = basic_ctx();
    let err = verify_token(&token, &make_principal(10), &ctx).unwrap_err();
    assert!(matches!(err, TokenError::SignatureInvalid { .. }));
}

#[test]
fn modifying_epoch_invalidates_signature() {
    let sk = make_sk(1);
    let mut token = build_basic_token(&sk);
    token.epoch = SecurityEpoch::from_raw(999);

    let ctx = basic_ctx();
    let err = verify_token(&token, &make_principal(10), &ctx).unwrap_err();
    assert!(matches!(err, TokenError::SignatureInvalid { .. }));
}

// ---------------------------------------------------------------------------
// Verification — audience failures
// ---------------------------------------------------------------------------

#[test]
fn verify_fails_non_audience_presenter() {
    let sk = make_sk(1);
    let token = build_basic_token(&sk);
    let ctx = basic_ctx();

    let err = verify_token(&token, &make_principal(99), &ctx).unwrap_err();
    match &err {
        TokenError::AudienceRejected {
            presenter,
            audience_size,
        } => {
            assert_eq!(*presenter, make_principal(99));
            assert_eq!(*audience_size, 1);
        }
        other => panic!("expected AudienceRejected, got {other:?}"),
    }
}

#[test]
fn verify_multi_audience_rejects_non_member() {
    let sk = make_sk(1);
    let token = TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-a",
    )
    .add_audience(make_principal(10))
    .add_audience(make_principal(20))
    .add_audience(make_principal(30))
    .add_capability(RuntimeCapability::VmDispatch)
    .build()
    .unwrap();

    let ctx = basic_ctx();
    let err = verify_token(&token, &make_principal(99), &ctx).unwrap_err();
    match &err {
        TokenError::AudienceRejected { audience_size, .. } => {
            assert_eq!(*audience_size, 3);
        }
        other => panic!("expected AudienceRejected, got {other:?}"),
    }
}

#[test]
fn verify_multi_audience_accepts_any_member() {
    let sk = make_sk(1);
    let token = TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-a",
    )
    .add_audience(make_principal(10))
    .add_audience(make_principal(20))
    .add_audience(make_principal(30))
    .add_capability(RuntimeCapability::VmDispatch)
    .build()
    .unwrap();

    let ctx = basic_ctx();
    verify_token(&token, &make_principal(10), &ctx).unwrap();
    verify_token(&token, &make_principal(20), &ctx).unwrap();
    verify_token(&token, &make_principal(30), &ctx).unwrap();
}

// ---------------------------------------------------------------------------
// Verification — temporal failures
// ---------------------------------------------------------------------------

#[test]
fn verify_fails_not_yet_valid() {
    let sk = make_sk(1);
    let token = build_basic_token(&sk);
    let ctx = VerificationContext {
        current_tick: 50, // before nbf=100
        verifier_checkpoint_seq: 10,
        verifier_revocation_seq: 5,
    };

    let err = verify_token(&token, &make_principal(10), &ctx).unwrap_err();
    match &err {
        TokenError::NotYetValid {
            current_tick,
            not_before,
        } => {
            assert_eq!(*current_tick, 50);
            assert_eq!(*not_before, 100);
        }
        other => panic!("expected NotYetValid, got {other:?}"),
    }
}

#[test]
fn verify_fails_expired() {
    let sk = make_sk(1);
    let token = build_basic_token(&sk);
    let ctx = VerificationContext {
        current_tick: 2000, // after expiry=1000
        verifier_checkpoint_seq: 10,
        verifier_revocation_seq: 5,
    };

    let err = verify_token(&token, &make_principal(10), &ctx).unwrap_err();
    match &err {
        TokenError::Expired {
            current_tick,
            expiry,
        } => {
            assert_eq!(*current_tick, 2000);
            assert_eq!(*expiry, 1000);
        }
        other => panic!("expected Expired, got {other:?}"),
    }
}

#[test]
fn verify_fails_one_tick_before_nbf() {
    let sk = make_sk(1);
    let token = build_basic_token(&sk); // nbf=100
    let ctx = VerificationContext {
        current_tick: 99,
        verifier_checkpoint_seq: 10,
        verifier_revocation_seq: 5,
    };
    let err = verify_token(&token, &make_principal(10), &ctx).unwrap_err();
    assert!(matches!(err, TokenError::NotYetValid { .. }));
}

#[test]
fn verify_fails_one_tick_after_expiry() {
    let sk = make_sk(1);
    let token = build_basic_token(&sk); // expiry=1000
    let ctx = VerificationContext {
        current_tick: 1001,
        verifier_checkpoint_seq: 10,
        verifier_revocation_seq: 5,
    };
    let err = verify_token(&token, &make_principal(10), &ctx).unwrap_err();
    assert!(matches!(err, TokenError::Expired { .. }));
}

// ---------------------------------------------------------------------------
// Verification — checkpoint binding failures
// ---------------------------------------------------------------------------

#[test]
fn verify_fails_checkpoint_binding_frontier_too_low() {
    let sk = make_sk(1);
    let token = TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-a",
    )
    .add_audience(make_principal(10))
    .add_capability(RuntimeCapability::VmDispatch)
    .bind_checkpoint(make_checkpoint_ref(20))
    .build()
    .unwrap();

    let ctx = VerificationContext {
        current_tick: 500,
        verifier_checkpoint_seq: 15, // below required 20
        verifier_revocation_seq: 5,
    };

    let err = verify_token(&token, &make_principal(10), &ctx).unwrap_err();
    match &err {
        TokenError::CheckpointBindingFailed {
            required_seq,
            verifier_seq,
        } => {
            assert_eq!(*required_seq, 20);
            assert_eq!(*verifier_seq, 15);
        }
        other => panic!("expected CheckpointBindingFailed, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Verification — revocation freshness failures
// ---------------------------------------------------------------------------

#[test]
fn verify_fails_revocation_freshness_stale() {
    let sk = make_sk(1);
    let token = TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-a",
    )
    .add_audience(make_principal(10))
    .add_capability(RuntimeCapability::VmDispatch)
    .bind_revocation_freshness(make_revocation_ref(10))
    .build()
    .unwrap();

    let ctx = VerificationContext {
        current_tick: 500,
        verifier_checkpoint_seq: 10,
        verifier_revocation_seq: 3, // below required 10
    };

    let err = verify_token(&token, &make_principal(10), &ctx).unwrap_err();
    match &err {
        TokenError::RevocationFreshnessStale {
            required_seq,
            verifier_seq,
        } => {
            assert_eq!(*required_seq, 10);
            assert_eq!(*verifier_seq, 3);
        }
        other => panic!("expected RevocationFreshnessStale, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Verification priority ordering
// ---------------------------------------------------------------------------

#[test]
fn signature_failure_takes_priority_over_audience() {
    // A token with bad signature and bad audience should report
    // SignatureInvalid, not AudienceRejected.
    let sk = make_sk(1);
    let mut token = build_basic_token(&sk);
    token.signature.lower[0] ^= 0xFF;

    let ctx = basic_ctx();
    // make_principal(99) is not in audience, but signature fails first.
    let err = verify_token(&token, &make_principal(99), &ctx).unwrap_err();
    assert!(matches!(err, TokenError::SignatureInvalid { .. }));
}

#[test]
fn audience_failure_takes_priority_over_temporal() {
    // Token verified but presenter is not in audience, and time is before nbf.
    // Audience check happens before temporal.
    let sk = make_sk(1);
    let token = build_basic_token(&sk);
    let ctx = VerificationContext {
        current_tick: 50, // before nbf
        verifier_checkpoint_seq: 10,
        verifier_revocation_seq: 5,
    };
    let err = verify_token(&token, &make_principal(99), &ctx).unwrap_err();
    assert!(matches!(err, TokenError::AudienceRejected { .. }));
}

// ---------------------------------------------------------------------------
// Token serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn token_serde_round_trip() {
    let sk = make_sk(1);
    let token = build_basic_token(&sk);
    let json = serde_json::to_string(&token).unwrap();
    let restored: CapabilityToken = serde_json::from_str(&json).unwrap();
    assert_eq!(token, restored);
}

#[test]
fn token_with_all_bindings_serde_round_trip() {
    let sk = make_sk(1);
    let token = TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::from_raw(5),
        "zone-a",
    )
    .add_audience(make_principal(10))
    .add_audience(make_principal(20))
    .add_capability(RuntimeCapability::VmDispatch)
    .add_capability(RuntimeCapability::PolicyRead)
    .bind_checkpoint(make_checkpoint_ref(10))
    .bind_revocation_freshness(make_revocation_ref(5))
    .build()
    .unwrap();

    let json = serde_json::to_string(&token).unwrap();
    let restored: CapabilityToken = serde_json::from_str(&json).unwrap();
    assert_eq!(token, restored);
}

#[test]
fn deserialized_token_still_verifies() {
    let sk = make_sk(1);
    let token = build_basic_token(&sk);
    let json = serde_json::to_string(&token).unwrap();
    let restored: CapabilityToken = serde_json::from_str(&json).unwrap();

    let ctx = basic_ctx();
    verify_token(&restored, &make_principal(10), &ctx).unwrap();
}

#[test]
fn deterministic_serialization() {
    let sk = make_sk(1);
    let t1 = build_basic_token(&sk);
    let t2 = build_basic_token(&sk);
    assert_eq!(
        serde_json::to_string(&t1).unwrap(),
        serde_json::to_string(&t2).unwrap()
    );
}

// ---------------------------------------------------------------------------
// TokenError serde and Display
// ---------------------------------------------------------------------------

#[test]
fn token_error_serde_round_trip_all_variants() {
    let errors = vec![
        TokenError::SignatureInvalid {
            detail: "bad sig".to_string(),
        },
        TokenError::NonCanonical {
            detail: "non-canonical field".to_string(),
        },
        TokenError::AudienceRejected {
            presenter: make_principal(1),
            audience_size: 3,
        },
        TokenError::NotYetValid {
            current_tick: 50,
            not_before: 100,
        },
        TokenError::Expired {
            current_tick: 2000,
            expiry: 1000,
        },
        TokenError::CheckpointBindingFailed {
            required_seq: 20,
            verifier_seq: 15,
        },
        TokenError::RevocationFreshnessStale {
            required_seq: 10,
            verifier_seq: 3,
        },
        TokenError::UnsupportedVersion {
            version: "v99".to_string(),
        },
        TokenError::IdDerivationFailed {
            detail: "bad id".to_string(),
        },
        TokenError::InvertedTemporalWindow {
            not_before: 1000,
            expiry: 100,
        },
        TokenError::EmptyCapabilities,
    ];

    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: TokenError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored, "round-trip failed for {err:?}");
    }
}

#[test]
fn token_error_display_signature_invalid() {
    let err = TokenError::SignatureInvalid {
        detail: "wrong key".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("signature invalid"));
    assert!(s.contains("wrong key"));
}

#[test]
fn token_error_display_non_canonical() {
    let err = TokenError::NonCanonical {
        detail: "field order".to_string(),
    };
    assert!(err.to_string().contains("non-canonical"));
}

#[test]
fn token_error_display_audience_rejected() {
    let err = TokenError::AudienceRejected {
        presenter: make_principal(1),
        audience_size: 3,
    };
    let s = err.to_string();
    assert!(s.contains("audience rejected"));
    assert!(s.contains("3 audience members"));
}

#[test]
fn token_error_display_not_yet_valid() {
    let err = TokenError::NotYetValid {
        current_tick: 50,
        not_before: 100,
    };
    let s = err.to_string();
    assert!(s.contains("not yet valid"));
    assert!(s.contains("50"));
    assert!(s.contains("100"));
}

#[test]
fn token_error_display_expired() {
    let err = TokenError::Expired {
        current_tick: 2000,
        expiry: 1000,
    };
    let s = err.to_string();
    assert!(s.contains("expired"));
    assert!(s.contains("2000"));
    assert!(s.contains("1000"));
}

#[test]
fn token_error_display_checkpoint_binding_failed() {
    let err = TokenError::CheckpointBindingFailed {
        required_seq: 20,
        verifier_seq: 15,
    };
    let s = err.to_string();
    assert!(s.contains("checkpoint binding failed"));
    assert!(s.contains("20"));
    assert!(s.contains("15"));
}

#[test]
fn token_error_display_revocation_freshness_stale() {
    let err = TokenError::RevocationFreshnessStale {
        required_seq: 10,
        verifier_seq: 3,
    };
    let s = err.to_string();
    assert!(s.contains("revocation freshness stale"));
    assert!(s.contains("10"));
    assert!(s.contains("3"));
}

#[test]
fn token_error_display_unsupported_version() {
    let err = TokenError::UnsupportedVersion {
        version: "v99".to_string(),
    };
    assert!(err.to_string().contains("unsupported version"));
}

#[test]
fn token_error_display_id_derivation_failed() {
    let err = TokenError::IdDerivationFailed {
        detail: "bad id".to_string(),
    };
    assert!(err.to_string().contains("ID derivation failed"));
}

#[test]
fn token_error_display_inverted_temporal_window() {
    let err = TokenError::InvertedTemporalWindow {
        not_before: 1000,
        expiry: 100,
    };
    let s = err.to_string();
    assert!(s.contains("inverted temporal window"));
    assert!(s.contains("1000"));
    assert!(s.contains("100"));
}

#[test]
fn token_error_display_empty_capabilities() {
    let err = TokenError::EmptyCapabilities;
    assert!(err.to_string().contains("empty capabilities"));
}

#[test]
fn token_error_is_std_error() {
    let err = TokenError::EmptyCapabilities;
    let _: &dyn std::error::Error = &err;
}

// ---------------------------------------------------------------------------
// TokenEventType and TokenEvent
// ---------------------------------------------------------------------------

#[test]
fn token_event_type_issued_display() {
    let et = TokenEventType::TokenIssued {
        jti: EngineObjectId([1; 32]),
    };
    let s = et.to_string();
    assert!(s.contains("token_issued"));
}

#[test]
fn token_event_type_verified_display() {
    let et = TokenEventType::TokenVerified {
        jti: EngineObjectId([2; 32]),
    };
    assert!(et.to_string().contains("token_verified"));
}

#[test]
fn token_event_type_rejected_display() {
    let et = TokenEventType::TokenRejected {
        jti: EngineObjectId([3; 32]),
        reason: "expired".to_string(),
    };
    let s = et.to_string();
    assert!(s.contains("token_rejected"));
    assert!(s.contains("expired"));
}

#[test]
fn token_event_type_serde_round_trip() {
    let events = vec![
        TokenEventType::TokenIssued {
            jti: EngineObjectId([1; 32]),
        },
        TokenEventType::TokenVerified {
            jti: EngineObjectId([2; 32]),
        },
        TokenEventType::TokenRejected {
            jti: EngineObjectId([3; 32]),
            reason: "bad".to_string(),
        },
    ];
    for evt in &events {
        let json = serde_json::to_string(evt).unwrap();
        let restored: TokenEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*evt, restored);
    }
}

#[test]
fn token_event_serde_round_trip() {
    let event = TokenEvent {
        event_type: TokenEventType::TokenIssued {
            jti: EngineObjectId([7; 32]),
        },
        trace_id: "trace-abc-123".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: TokenEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

// ---------------------------------------------------------------------------
// BTreeSet ordering of PrincipalId
// ---------------------------------------------------------------------------

#[test]
fn principal_btreeset_deterministic_order() {
    let mut set = BTreeSet::new();
    set.insert(make_principal(3));
    set.insert(make_principal(1));
    set.insert(make_principal(2));

    let ordered: Vec<_> = set.iter().collect();
    assert!(ordered[0] < ordered[1]);
    assert!(ordered[1] < ordered[2]);
}

// ---------------------------------------------------------------------------
// Zero-length temporal window (nbf == expiry)
// ---------------------------------------------------------------------------

#[test]
fn zero_length_window_exact_tick_verifies() {
    let sk = make_sk(1);
    let token = TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(500),
        DeterministicTimestamp(500),
        SecurityEpoch::GENESIS,
        "zone-a",
    )
    .add_capability(RuntimeCapability::VmDispatch)
    .build()
    .unwrap();

    let ctx = VerificationContext {
        current_tick: 500,
        verifier_checkpoint_seq: 10,
        verifier_revocation_seq: 5,
    };
    verify_token(&token, &make_principal(99), &ctx).unwrap();
}

#[test]
fn zero_length_window_before_fails() {
    let sk = make_sk(1);
    let token = TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(500),
        DeterministicTimestamp(500),
        SecurityEpoch::GENESIS,
        "zone-a",
    )
    .add_capability(RuntimeCapability::VmDispatch)
    .build()
    .unwrap();

    let ctx = VerificationContext {
        current_tick: 499,
        verifier_checkpoint_seq: 10,
        verifier_revocation_seq: 5,
    };
    let err = verify_token(&token, &make_principal(99), &ctx).unwrap_err();
    assert!(matches!(err, TokenError::NotYetValid { .. }));
}

#[test]
fn zero_length_window_after_fails() {
    let sk = make_sk(1);
    let token = TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(500),
        DeterministicTimestamp(500),
        SecurityEpoch::GENESIS,
        "zone-a",
    )
    .add_capability(RuntimeCapability::VmDispatch)
    .build()
    .unwrap();

    let ctx = VerificationContext {
        current_tick: 501,
        verifier_checkpoint_seq: 10,
        verifier_revocation_seq: 5,
    };
    let err = verify_token(&token, &make_principal(99), &ctx).unwrap_err();
    assert!(matches!(err, TokenError::Expired { .. }));
}
