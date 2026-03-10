//! Integration tests for the `signature_preimage` module.
//!
//! Covers: SigningKey, VerificationKey, Signature, SignatureError,
//! SignaturePreimage trait, sign/verify functions, build_preimage,
//! preimage_hash, check_canonical_for_signing, SignatureContext,
//! SignatureEvent, SignatureEventType, Display impls, serde roundtrips,
//! deterministic replay, error conditions, and constant-time comparison.

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

use frankenengine_engine::deterministic_serde::{CanonicalValue, SchemaHash};
use frankenengine_engine::engine_object_id::ObjectDomain;
use frankenengine_engine::signature_preimage::{
    SIGNATURE_LEN, SIGNATURE_SENTINEL, SIGNING_KEY_LEN, Signature, SignatureContext,
    SignatureError, SignatureEvent, SignatureEventType,
    SignaturePreimage as SignaturePreimageTrait, SigningKey, VERIFICATION_KEY_LEN, VerificationKey,
    build_preimage, check_canonical_for_signing, preimage_hash, sign_object, sign_preimage,
    verify_object, verify_signature,
};

// ===========================================================================
// Helpers
// ===========================================================================

/// A test object implementing SignaturePreimage.
struct TestSignable {
    domain: ObjectDomain,
    schema: SchemaHash,
    data: CanonicalValue,
}

impl SignaturePreimageTrait for TestSignable {
    fn signature_domain(&self) -> ObjectDomain {
        self.domain
    }

    fn signature_schema(&self) -> &SchemaHash {
        &self.schema
    }

    fn unsigned_view(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("data".to_string(), self.data.clone());
        map.insert(
            "signature".to_string(),
            CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
        );
        CanonicalValue::Map(map)
    }
}

fn test_schema() -> SchemaHash {
    SchemaHash::from_definition(b"integration-test-signable-v1")
}

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ])
}

fn alt_signing_key() -> SigningKey {
    SigningKey::from_bytes([0xAA; SIGNING_KEY_LEN])
}

fn test_object() -> TestSignable {
    TestSignable {
        domain: ObjectDomain::PolicyObject,
        schema: test_schema(),
        data: CanonicalValue::U64(42),
    }
}

fn make_object_with_data(data: CanonicalValue) -> TestSignable {
    TestSignable {
        domain: ObjectDomain::PolicyObject,
        schema: test_schema(),
        data,
    }
}

// ===========================================================================
// Section 1: Constants
// ===========================================================================

#[test]
fn signing_key_len_is_32() {
    assert_eq!(SIGNING_KEY_LEN, 32);
}

#[test]
fn verification_key_len_is_32() {
    assert_eq!(VERIFICATION_KEY_LEN, 32);
}

#[test]
fn signature_len_is_64() {
    assert_eq!(SIGNATURE_LEN, 64);
}

#[test]
fn signature_sentinel_is_all_zeros() {
    assert!(SIGNATURE_SENTINEL.iter().all(|&b| b == 0));
    assert_eq!(SIGNATURE_SENTINEL.len(), SIGNATURE_LEN);
}

// ===========================================================================
// Section 2: SigningKey — construction, verification key derivation
// ===========================================================================

#[test]
fn signing_key_from_bytes_and_as_bytes_roundtrip() {
    let bytes = [0x42u8; SIGNING_KEY_LEN];
    let sk = SigningKey::from_bytes(bytes);
    assert_eq!(*sk.as_bytes(), bytes);
}

#[test]
fn verification_key_derivation_is_deterministic() {
    let sk = test_signing_key();
    let vk1 = sk.verification_key();
    let vk2 = sk.verification_key();
    assert_eq!(vk1, vk2);
}

#[test]
fn different_signing_keys_produce_different_verification_keys() {
    let sk1 = SigningKey::from_bytes([1u8; SIGNING_KEY_LEN]);
    let sk2 = SigningKey::from_bytes([2u8; SIGNING_KEY_LEN]);
    let sk3 = SigningKey::from_bytes([3u8; SIGNING_KEY_LEN]);
    let vks: BTreeSet<[u8; VERIFICATION_KEY_LEN]> = [sk1, sk2, sk3]
        .iter()
        .map(|sk| *sk.verification_key().as_bytes())
        .collect();
    assert_eq!(vks.len(), 3);
}

#[test]
fn signing_key_serde_roundtrip() {
    let sk = test_signing_key();
    let json = serde_json::to_string(&sk).expect("serialize");
    let restored: SigningKey = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(sk, restored);
}

#[test]
fn signing_key_clone_eq() {
    let sk = test_signing_key();
    let cloned = sk.clone();
    assert_eq!(sk, cloned);
}

// ===========================================================================
// Section 3: VerificationKey — construction, Display, hex, serde
// ===========================================================================

#[test]
fn verification_key_from_bytes_and_as_bytes_roundtrip() {
    let bytes = [0xBE; VERIFICATION_KEY_LEN];
    let vk = VerificationKey::from_bytes(bytes);
    assert_eq!(*vk.as_bytes(), bytes);
}

#[test]
fn verification_key_to_hex_correct_length() {
    let vk = test_signing_key().verification_key();
    let hex = vk.to_hex();
    assert_eq!(hex.len(), VERIFICATION_KEY_LEN * 2);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn verification_key_display_matches_hex() {
    let vk = test_signing_key().verification_key();
    assert_eq!(vk.to_string(), vk.to_hex());
}

#[test]
fn verification_key_serde_roundtrip() {
    let vk = test_signing_key().verification_key();
    let json = serde_json::to_string(&vk).expect("serialize");
    let restored: VerificationKey = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(vk, restored);
}

#[test]
fn verification_key_ord() {
    let vk_a = VerificationKey::from_bytes([0x01; VERIFICATION_KEY_LEN]);
    let vk_b = VerificationKey::from_bytes([0x02; VERIFICATION_KEY_LEN]);
    assert!(vk_a < vk_b);
}

// ===========================================================================
// Section 4: Signature — construction, to_bytes, is_sentinel, Display, serde
// ===========================================================================

#[test]
fn signature_from_bytes_to_bytes_roundtrip() {
    let mut bytes = [0u8; SIGNATURE_LEN];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = i as u8;
    }
    let sig = Signature::from_bytes(bytes);
    assert_eq!(sig.to_bytes(), bytes);
}

#[test]
fn signature_sentinel_detected() {
    let sig = Signature::from_bytes(SIGNATURE_SENTINEL);
    assert!(sig.is_sentinel());
}

#[test]
fn signature_non_sentinel_not_detected() {
    let sig = Signature::from_bytes([1u8; SIGNATURE_LEN]);
    assert!(!sig.is_sentinel());
}

#[test]
fn signature_partially_zero_is_not_sentinel() {
    let mut bytes = [0u8; SIGNATURE_LEN];
    bytes[63] = 1;
    let sig = Signature::from_bytes(bytes);
    assert!(!sig.is_sentinel());
}

#[test]
fn signature_display_contains_hex_and_ellipsis() {
    let sig = Signature::from_bytes([0xAB; SIGNATURE_LEN]);
    let display = sig.to_string();
    assert!(
        display.contains("..."),
        "display missing ellipsis: {display}"
    );
    // First 8 bytes of lower half
    assert!(
        display.contains("abababab"),
        "display missing hex prefix: {display}"
    );
}

#[test]
fn signature_serde_roundtrip() {
    let sig = Signature::from_bytes([0xCD; SIGNATURE_LEN]);
    let json = serde_json::to_string(&sig).expect("serialize");
    let restored: Signature = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(sig, restored);
}

#[test]
fn signature_clone_eq_ord() {
    let sig_a = Signature::from_bytes([0x01; SIGNATURE_LEN]);
    let sig_b = Signature::from_bytes([0x02; SIGNATURE_LEN]);
    let cloned = sig_a.clone();
    assert_eq!(sig_a, cloned);
    assert_ne!(sig_a, sig_b);
    // Ord is derived, just ensure it doesn't panic
    let _cmp = sig_a.cmp(&sig_b);
}

#[test]
fn signature_lower_upper_halves() {
    let mut bytes = [0u8; SIGNATURE_LEN];
    bytes[..32].copy_from_slice(&[0xAA; 32]);
    bytes[32..].copy_from_slice(&[0xBB; 32]);
    let sig = Signature::from_bytes(bytes);
    assert_eq!(sig.lower, [0xAA; 32]);
    assert_eq!(sig.upper, [0xBB; 32]);
}

// ===========================================================================
// Section 5: SignatureError — Display, std::error::Error, serde
// ===========================================================================

#[test]
fn error_display_verification_failed() {
    let vk = VerificationKey::from_bytes([1u8; VERIFICATION_KEY_LEN]);
    let err = SignatureError::VerificationFailed {
        signer: vk,
        reason: "bad signature".to_string(),
    };
    let display = err.to_string();
    assert!(
        display.contains("bad signature"),
        "missing reason: {display}"
    );
    assert!(
        display.contains("verification failed"),
        "missing prefix: {display}"
    );
}

#[test]
fn error_display_non_canonical_object() {
    let err = SignatureError::NonCanonicalObject {
        detail: "field order changed".to_string(),
    };
    assert!(err.to_string().contains("field order changed"));
}

#[test]
fn error_display_preimage_error() {
    let err = SignatureError::PreimageError {
        detail: "encoding failed".to_string(),
    };
    assert!(err.to_string().contains("encoding failed"));
}

#[test]
fn error_display_invalid_signing_key() {
    let err = SignatureError::InvalidSigningKey;
    assert_eq!(err.to_string(), "signing key is all zeros");
}

#[test]
fn error_display_invalid_verification_key() {
    let err = SignatureError::InvalidVerificationKey;
    assert_eq!(err.to_string(), "verification key is all zeros");
}

#[test]
fn error_is_std_error() {
    let err = SignatureError::InvalidSigningKey;
    let _: &dyn std::error::Error = &err;
}

#[test]
fn error_serde_roundtrip_all_variants() {
    let vk = VerificationKey::from_bytes([0x42; VERIFICATION_KEY_LEN]);
    let errors = vec![
        SignatureError::VerificationFailed {
            signer: vk,
            reason: "test".to_string(),
        },
        SignatureError::NonCanonicalObject {
            detail: "detail".to_string(),
        },
        SignatureError::PreimageError {
            detail: "fail".to_string(),
        },
        SignatureError::InvalidSigningKey,
        SignatureError::InvalidVerificationKey,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let restored: SignatureError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, restored, "roundtrip mismatch for: {err}");
    }
}

// ===========================================================================
// Section 6: SignaturePreimage trait — preimage_bytes determinism
// ===========================================================================

#[test]
fn preimage_bytes_are_deterministic() {
    let obj = test_object();
    let p1 = obj.preimage_bytes();
    let p2 = obj.preimage_bytes();
    assert_eq!(p1, p2);
}

#[test]
fn preimage_includes_domain_tag() {
    let obj = test_object();
    let preimage = obj.preimage_bytes();
    let tag = ObjectDomain::PolicyObject.tag();
    assert!(
        preimage.starts_with(tag),
        "preimage should start with domain tag"
    );
}

#[test]
fn preimage_includes_schema_hash() {
    let obj = test_object();
    let preimage = obj.preimage_bytes();
    let schema = test_schema();
    let schema_bytes = schema.as_bytes();
    let tag_len = ObjectDomain::PolicyObject.tag().len();
    // Schema hash comes right after the domain tag
    assert_eq!(
        &preimage[tag_len..tag_len + 32],
        schema_bytes,
        "schema hash not at expected position"
    );
}

#[test]
fn preimage_includes_signature_sentinel_in_unsigned_view() {
    let obj = test_object();
    let preimage = obj.preimage_bytes();
    // The sentinel should appear somewhere in the encoded canonical value
    assert!(
        preimage
            .windows(SIGNATURE_LEN)
            .any(|w| w == SIGNATURE_SENTINEL),
        "preimage should contain the zero sentinel"
    );
}

#[test]
fn different_data_produces_different_preimage() {
    let obj1 = make_object_with_data(CanonicalValue::U64(1));
    let obj2 = make_object_with_data(CanonicalValue::U64(2));
    assert_ne!(obj1.preimage_bytes(), obj2.preimage_bytes());
}

#[test]
fn different_domains_produce_different_preimage() {
    let obj1 = TestSignable {
        domain: ObjectDomain::PolicyObject,
        schema: test_schema(),
        data: CanonicalValue::U64(42),
    };
    let obj2 = TestSignable {
        domain: ObjectDomain::EvidenceRecord,
        schema: test_schema(),
        data: CanonicalValue::U64(42),
    };
    assert_ne!(obj1.preimage_bytes(), obj2.preimage_bytes());
}

#[test]
fn different_schemas_produce_different_preimage() {
    let obj1 = TestSignable {
        domain: ObjectDomain::PolicyObject,
        schema: SchemaHash::from_definition(b"schema-a"),
        data: CanonicalValue::U64(42),
    };
    let obj2 = TestSignable {
        domain: ObjectDomain::PolicyObject,
        schema: SchemaHash::from_definition(b"schema-b"),
        data: CanonicalValue::U64(42),
    };
    assert_ne!(obj1.preimage_bytes(), obj2.preimage_bytes());
}

#[test]
fn preimage_for_all_object_domains_are_unique() {
    let mut preimages = BTreeSet::new();
    for domain in ObjectDomain::ALL {
        let obj = TestSignable {
            domain: *domain,
            schema: test_schema(),
            data: CanonicalValue::U64(42),
        };
        preimages.insert(obj.preimage_bytes());
    }
    assert_eq!(preimages.len(), ObjectDomain::ALL.len());
}

// ===========================================================================
// Section 7: sign_preimage / verify_signature — round-trip
// ===========================================================================

#[test]
fn sign_verify_preimage_round_trip() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let preimage = b"test preimage data for signing";
    let sig = sign_preimage(&sk, preimage).unwrap();
    assert!(verify_signature(&vk, preimage, &sig).is_ok());
}

#[test]
fn sign_preimage_is_deterministic() {
    let sk = test_signing_key();
    let preimage = b"deterministic test";
    let sig1 = sign_preimage(&sk, preimage).unwrap();
    let sig2 = sign_preimage(&sk, preimage).unwrap();
    assert_eq!(sig1, sig2);
}

#[test]
fn sign_preimage_different_keys_different_signatures() {
    let sk1 = test_signing_key();
    let sk2 = alt_signing_key();
    let preimage = b"same preimage";
    let sig1 = sign_preimage(&sk1, preimage).unwrap();
    let sig2 = sign_preimage(&sk2, preimage).unwrap();
    assert_ne!(sig1, sig2);
}

#[test]
fn sign_preimage_different_data_different_signatures() {
    let sk = test_signing_key();
    let sig1 = sign_preimage(&sk, b"data-one").unwrap();
    let sig2 = sign_preimage(&sk, b"data-two").unwrap();
    assert_ne!(sig1, sig2);
}

#[test]
fn verify_fails_with_wrong_key() {
    let sk = test_signing_key();
    let wrong_vk = VerificationKey::from_bytes([0xFF; VERIFICATION_KEY_LEN]);
    let preimage = b"test data";
    let sig = sign_preimage(&sk, preimage).unwrap();
    let err = verify_signature(&wrong_vk, preimage, &sig).unwrap_err();
    assert!(matches!(err, SignatureError::VerificationFailed { .. }));
}

#[test]
fn verify_fails_with_tampered_signature() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let preimage = b"test data";
    let mut sig = sign_preimage(&sk, preimage).unwrap();
    sig.lower[0] ^= 0xFF;
    let err = verify_signature(&vk, preimage, &sig).unwrap_err();
    assert!(matches!(err, SignatureError::VerificationFailed { .. }));
}

#[test]
fn verify_fails_with_tampered_upper_half() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let preimage = b"test data";
    let mut sig = sign_preimage(&sk, preimage).unwrap();
    sig.upper[31] ^= 0xFF;
    let err = verify_signature(&vk, preimage, &sig).unwrap_err();
    assert!(matches!(err, SignatureError::VerificationFailed { .. }));
}

#[test]
fn verify_fails_with_different_preimage() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let sig = sign_preimage(&sk, b"original").unwrap();
    let err = verify_signature(&vk, b"modified", &sig).unwrap_err();
    assert!(matches!(err, SignatureError::VerificationFailed { .. }));
}

// ===========================================================================
// Section 8: sign_object / verify_object — round-trip
// ===========================================================================

#[test]
fn sign_verify_object_round_trip() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let obj = test_object();
    let sig = sign_object(&obj, &sk).unwrap();
    assert!(verify_object(&obj, &vk, &sig).is_ok());
}

#[test]
fn sign_object_is_deterministic() {
    let sk = test_signing_key();
    let obj = test_object();
    let sig1 = sign_object(&obj, &sk).unwrap();
    let sig2 = sign_object(&obj, &sk).unwrap();
    assert_eq!(sig1, sig2);
}

#[test]
fn verify_object_fails_with_wrong_key() {
    let sk = test_signing_key();
    let wrong_vk = VerificationKey::from_bytes([0xBB; VERIFICATION_KEY_LEN]);
    let obj = test_object();
    let sig = sign_object(&obj, &sk).unwrap();
    let err = verify_object(&obj, &wrong_vk, &sig).unwrap_err();
    assert!(matches!(err, SignatureError::VerificationFailed { .. }));
}

#[test]
fn verify_object_fails_with_different_object() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let obj1 = make_object_with_data(CanonicalValue::U64(100));
    let obj2 = make_object_with_data(CanonicalValue::U64(999));
    let sig = sign_object(&obj1, &sk).unwrap();
    let err = verify_object(&obj2, &vk, &sig).unwrap_err();
    assert!(matches!(err, SignatureError::VerificationFailed { .. }));
}

// ===========================================================================
// Section 9: Invalid key rejection
// ===========================================================================

#[test]
fn zero_signing_key_rejected() {
    let zero_sk = SigningKey::from_bytes([0u8; SIGNING_KEY_LEN]);
    let err = sign_preimage(&zero_sk, b"test").unwrap_err();
    assert_eq!(err, SignatureError::InvalidSigningKey);
}

#[test]
fn zero_verification_key_rejected() {
    let zero_vk = VerificationKey::from_bytes([0u8; VERIFICATION_KEY_LEN]);
    let sig = Signature::from_bytes([1u8; SIGNATURE_LEN]);
    let err = verify_signature(&zero_vk, b"test", &sig).unwrap_err();
    assert_eq!(err, SignatureError::InvalidVerificationKey);
}

// ===========================================================================
// Section 10: build_preimage helper
// ===========================================================================

#[test]
fn build_preimage_matches_trait_implementation() {
    let obj = test_object();
    let trait_preimage = obj.preimage_bytes();
    let helper_preimage = build_preimage(
        obj.signature_domain(),
        obj.signature_schema(),
        &obj.unsigned_view(),
    );
    assert_eq!(trait_preimage, helper_preimage);
}

#[test]
fn build_preimage_deterministic() {
    let schema = test_schema();
    let value = CanonicalValue::U64(42);
    let p1 = build_preimage(ObjectDomain::PolicyObject, &schema, &value);
    let p2 = build_preimage(ObjectDomain::PolicyObject, &schema, &value);
    assert_eq!(p1, p2);
}

#[test]
fn build_preimage_different_domains_differ() {
    let schema = test_schema();
    let value = CanonicalValue::U64(42);
    let p1 = build_preimage(ObjectDomain::PolicyObject, &schema, &value);
    let p2 = build_preimage(ObjectDomain::EvidenceRecord, &schema, &value);
    assert_ne!(p1, p2);
}

// ===========================================================================
// Section 11: preimage_hash
// ===========================================================================

#[test]
fn preimage_hash_is_deterministic() {
    let preimage = b"test preimage for hashing";
    let h1 = preimage_hash(preimage);
    let h2 = preimage_hash(preimage);
    assert_eq!(h1, h2);
}

#[test]
fn preimage_hash_different_inputs_differ() {
    let h1 = preimage_hash(b"input-one");
    let h2 = preimage_hash(b"input-two");
    assert_ne!(h1, h2);
}

// ===========================================================================
// Section 12: check_canonical_for_signing
// ===========================================================================

#[test]
fn canonical_check_passes_for_u64() {
    assert!(check_canonical_for_signing(&CanonicalValue::U64(42)).is_ok());
}

#[test]
fn canonical_check_passes_for_bool() {
    assert!(check_canonical_for_signing(&CanonicalValue::Bool(true)).is_ok());
    assert!(check_canonical_for_signing(&CanonicalValue::Bool(false)).is_ok());
}

#[test]
fn canonical_check_passes_for_null() {
    assert!(check_canonical_for_signing(&CanonicalValue::Null).is_ok());
}

#[test]
fn canonical_check_passes_for_string() {
    assert!(check_canonical_for_signing(&CanonicalValue::String("hello".to_string())).is_ok());
}

#[test]
fn canonical_check_passes_for_bytes() {
    assert!(check_canonical_for_signing(&CanonicalValue::Bytes(vec![1, 2, 3])).is_ok());
}

#[test]
fn canonical_check_passes_for_complex_nested_value() {
    let value = CanonicalValue::Map(BTreeMap::from([
        ("alpha".to_string(), CanonicalValue::U64(1)),
        (
            "beta".to_string(),
            CanonicalValue::Array(vec![
                CanonicalValue::Bool(true),
                CanonicalValue::Null,
                CanonicalValue::String("nested".to_string()),
                CanonicalValue::Bytes(vec![0xDE, 0xAD]),
            ]),
        ),
        (
            "gamma".to_string(),
            CanonicalValue::Map(BTreeMap::from([(
                "inner".to_string(),
                CanonicalValue::I64(-100),
            )])),
        ),
    ]));
    assert!(check_canonical_for_signing(&value).is_ok());
}

#[test]
fn canonical_check_passes_for_empty_array() {
    assert!(check_canonical_for_signing(&CanonicalValue::Array(vec![])).is_ok());
}

#[test]
fn canonical_check_passes_for_empty_map() {
    assert!(check_canonical_for_signing(&CanonicalValue::Map(BTreeMap::new())).is_ok());
}

// ===========================================================================
// Section 13: SignatureContext — sign, verify, event tracking
// ===========================================================================

#[test]
fn context_new_is_empty() {
    let ctx = SignatureContext::new();
    assert_eq!(ctx.sign_count(), 0);
    assert_eq!(ctx.verify_count(), 0);
    assert_eq!(ctx.failure_count(), 0);
}

#[test]
fn context_default_is_empty() {
    let ctx = SignatureContext::default();
    assert_eq!(ctx.sign_count(), 0);
    assert_eq!(ctx.verify_count(), 0);
    assert_eq!(ctx.failure_count(), 0);
}

#[test]
fn context_sign_verify_round_trip() {
    let mut ctx = SignatureContext::new();
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let obj = test_object();

    let sig = ctx.sign(&obj, &sk, "trace-001").unwrap();
    assert_eq!(ctx.sign_count(), 1);
    assert_eq!(ctx.verify_count(), 0);

    ctx.verify(&obj, &vk, &sig, "trace-002").unwrap();
    assert_eq!(ctx.verify_count(), 1);
    assert_eq!(ctx.failure_count(), 0);
}

#[test]
fn context_sign_is_deterministic() {
    let mut ctx = SignatureContext::new();
    let sk = test_signing_key();
    let obj = test_object();

    let sig1 = ctx.sign(&obj, &sk, "t-det-1").unwrap();
    let sig2 = ctx.sign(&obj, &sk, "t-det-2").unwrap();
    assert_eq!(sig1, sig2);
}

#[test]
fn context_different_keys_produce_different_signatures() {
    let mut ctx = SignatureContext::new();
    let sk1 = SigningKey::from_bytes([1u8; SIGNING_KEY_LEN]);
    let sk2 = SigningKey::from_bytes([2u8; SIGNING_KEY_LEN]);
    let obj = test_object();

    let sig1 = ctx.sign(&obj, &sk1, "t1").unwrap();
    let sig2 = ctx.sign(&obj, &sk2, "t2").unwrap();
    assert_ne!(sig1, sig2);
}

#[test]
fn context_different_data_produces_different_signatures() {
    let mut ctx = SignatureContext::new();
    let sk = test_signing_key();
    let obj1 = make_object_with_data(CanonicalValue::U64(1));
    let obj2 = make_object_with_data(CanonicalValue::U64(2));

    let sig1 = ctx.sign(&obj1, &sk, "t1").unwrap();
    let sig2 = ctx.sign(&obj2, &sk, "t2").unwrap();
    assert_ne!(sig1, sig2);
}

#[test]
fn context_tracks_verification_failure() {
    let mut ctx = SignatureContext::new();
    let sk = test_signing_key();
    let wrong_vk = VerificationKey::from_bytes([0xEE; VERIFICATION_KEY_LEN]);
    let obj = test_object();

    let sig = ctx.sign(&obj, &sk, "t-fail").unwrap();
    let err = ctx.verify(&obj, &wrong_vk, &sig, "t-fail-v").unwrap_err();
    assert!(matches!(err, SignatureError::VerificationFailed { .. }));
    assert_eq!(ctx.failure_count(), 1);
}

#[test]
fn context_event_counts_by_type() {
    let mut ctx = SignatureContext::new();
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let wrong_vk = VerificationKey::from_bytes([0xCC; VERIFICATION_KEY_LEN]);
    let obj = test_object();

    // Sign twice
    let sig = ctx.sign(&obj, &sk, "t-1").unwrap();
    ctx.sign(&obj, &sk, "t-2").unwrap();
    // Verify once (success)
    ctx.verify(&obj, &vk, &sig, "t-3").unwrap();
    // Verify once (failure)
    let _ = ctx.verify(&obj, &wrong_vk, &sig, "t-4");

    let counts = ctx.event_counts();
    assert_eq!(counts.get("signed"), Some(&2));
    assert_eq!(counts.get("verified"), Some(&1));
    assert_eq!(counts.get("verification_failed"), Some(&1));
}

#[test]
fn context_drain_events_clears() {
    let mut ctx = SignatureContext::new();
    let sk = test_signing_key();
    let obj = test_object();

    ctx.sign(&obj, &sk, "t-drain").unwrap();
    let events = ctx.drain_events();
    assert_eq!(events.len(), 1);

    // After drain, events are empty
    let events2 = ctx.drain_events();
    assert!(events2.is_empty());
}

#[test]
fn context_events_contain_correct_metadata() {
    let mut ctx = SignatureContext::new();
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let obj = test_object();

    ctx.sign(&obj, &sk, "trace-sign-001").unwrap();
    let events = ctx.drain_events();

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].trace_id, "trace-sign-001");
    assert_eq!(events[0].domain, ObjectDomain::PolicyObject);
    match &events[0].event_type {
        SignatureEventType::Signed { signer } => {
            assert_eq!(*signer, vk);
        }
        other => panic!("expected Signed event, got: {other:?}"),
    }
}

#[test]
fn context_multiple_operations_accumulate_events() {
    let mut ctx = SignatureContext::new();
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let obj = test_object();

    // 3 signs, 2 verifies, 1 failure
    let sig = ctx.sign(&obj, &sk, "s1").unwrap();
    ctx.sign(&obj, &sk, "s2").unwrap();
    ctx.sign(&obj, &sk, "s3").unwrap();
    ctx.verify(&obj, &vk, &sig, "v1").unwrap();
    ctx.verify(&obj, &vk, &sig, "v2").unwrap();
    let wrong_vk = VerificationKey::from_bytes([0xDD; VERIFICATION_KEY_LEN]);
    let _ = ctx.verify(&obj, &wrong_vk, &sig, "v3");

    assert_eq!(ctx.sign_count(), 3);
    assert_eq!(ctx.verify_count(), 2);
    assert_eq!(ctx.failure_count(), 1);
}

// ===========================================================================
// Section 14: Multi-signature — same preimage, different keys
// ===========================================================================

#[test]
fn multi_sig_same_preimage_different_signatures() {
    let sk1 = SigningKey::from_bytes([1u8; SIGNING_KEY_LEN]);
    let sk2 = SigningKey::from_bytes([2u8; SIGNING_KEY_LEN]);
    let sk3 = SigningKey::from_bytes([3u8; SIGNING_KEY_LEN]);
    let obj = test_object();

    let sig1 = sign_object(&obj, &sk1).unwrap();
    let sig2 = sign_object(&obj, &sk2).unwrap();
    let sig3 = sign_object(&obj, &sk3).unwrap();

    // All signatures should be unique
    let sigs: BTreeSet<[u8; SIGNATURE_LEN]> =
        [&sig1, &sig2, &sig3].iter().map(|s| s.to_bytes()).collect();
    assert_eq!(sigs.len(), 3);

    // Each verifies against its own key only
    assert!(verify_object(&obj, &sk1.verification_key(), &sig1).is_ok());
    assert!(verify_object(&obj, &sk2.verification_key(), &sig2).is_ok());
    assert!(verify_object(&obj, &sk3.verification_key(), &sig3).is_ok());

    // Cross-key verification fails
    assert!(verify_object(&obj, &sk1.verification_key(), &sig2).is_err());
    assert!(verify_object(&obj, &sk2.verification_key(), &sig3).is_err());
    assert!(verify_object(&obj, &sk3.verification_key(), &sig1).is_err());
}

// ===========================================================================
// Section 15: SignatureEvent / SignatureEventType — serde, Display
// ===========================================================================

#[test]
fn signature_event_serde_roundtrip() {
    let vk = test_signing_key().verification_key();
    let event = SignatureEvent {
        event_type: SignatureEventType::Signed { signer: vk.clone() },
        domain: ObjectDomain::PolicyObject,
        trace_id: "t-serde".to_string(),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let restored: SignatureEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, restored);
}

#[test]
fn signature_event_type_verified_serde_roundtrip() {
    let vk = VerificationKey::from_bytes([0x11; VERIFICATION_KEY_LEN]);
    let event = SignatureEvent {
        event_type: SignatureEventType::Verified { signer: vk },
        domain: ObjectDomain::EvidenceRecord,
        trace_id: "t-verified".to_string(),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let restored: SignatureEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, restored);
}

#[test]
fn signature_event_type_verification_failed_serde_roundtrip() {
    let vk = VerificationKey::from_bytes([0x22; VERIFICATION_KEY_LEN]);
    let event = SignatureEvent {
        event_type: SignatureEventType::VerificationFailed {
            signer: vk,
            reason: "bad sig".to_string(),
        },
        domain: ObjectDomain::Revocation,
        trace_id: "t-fail".to_string(),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let restored: SignatureEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, restored);
}

#[test]
fn signature_event_type_canonicality_failed_serde_roundtrip() {
    let event = SignatureEvent {
        event_type: SignatureEventType::CanonicalityCheckFailed {
            detail: "round-trip failed".to_string(),
        },
        domain: ObjectDomain::Attestation,
        trace_id: "t-canon".to_string(),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let restored: SignatureEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, restored);
}

#[test]
fn event_type_display_signed() {
    let vk = VerificationKey::from_bytes([1u8; VERIFICATION_KEY_LEN]);
    let evt = SignatureEventType::Signed { signer: vk };
    assert!(evt.to_string().contains("signed by"));
}

#[test]
fn event_type_display_verified() {
    let vk = VerificationKey::from_bytes([2u8; VERIFICATION_KEY_LEN]);
    let evt = SignatureEventType::Verified { signer: vk };
    assert!(evt.to_string().contains("verified for"));
}

#[test]
fn event_type_display_verification_failed() {
    let vk = VerificationKey::from_bytes([3u8; VERIFICATION_KEY_LEN]);
    let evt = SignatureEventType::VerificationFailed {
        signer: vk,
        reason: "mismatch".to_string(),
    };
    let display = evt.to_string();
    assert!(display.contains("verification failed"), "{display}");
    assert!(display.contains("mismatch"), "{display}");
}

#[test]
fn event_type_display_canonicality_check_failed() {
    let evt = SignatureEventType::CanonicalityCheckFailed {
        detail: "bad encoding".to_string(),
    };
    let display = evt.to_string();
    assert!(display.contains("canonicality check failed"), "{display}");
    assert!(display.contains("bad encoding"), "{display}");
}

// ===========================================================================
// Section 16: Deterministic replay
// ===========================================================================

#[test]
fn full_sign_verify_replay_is_deterministic() {
    let run = || {
        let sk = test_signing_key();
        let vk = sk.verification_key();
        let obj = test_object();

        let mut ctx = SignatureContext::new();
        let sig = ctx.sign(&obj, &sk, "replay-trace").unwrap();
        let result = ctx.verify(&obj, &vk, &sig, "replay-verify");
        (sig, result.is_ok(), ctx.sign_count(), ctx.verify_count())
    };

    let (sig_a, ok_a, sc_a, vc_a) = run();
    let (sig_b, ok_b, sc_b, vc_b) = run();

    assert_eq!(sig_a, sig_b);
    assert_eq!(ok_a, ok_b);
    assert_eq!(sc_a, sc_b);
    assert_eq!(vc_a, vc_b);
}

// ===========================================================================
// Section 17: Edge cases
// ===========================================================================

#[test]
fn sign_empty_preimage() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let sig = sign_preimage(&sk, b"").unwrap();
    assert!(verify_signature(&vk, b"", &sig).is_ok());
    // But should fail for non-empty
    assert!(verify_signature(&vk, b"non-empty", &sig).is_err());
}

#[test]
fn sign_large_preimage() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let large = vec![0xAB; 100_000];
    let sig = sign_preimage(&sk, &large).unwrap();
    assert!(verify_signature(&vk, &large, &sig).is_ok());
}

#[test]
fn signature_produced_is_not_sentinel() {
    // A real signature should never be the zero sentinel
    let sk = test_signing_key();
    let sig = sign_preimage(&sk, b"data").unwrap();
    assert!(!sig.is_sentinel());
}

#[test]
fn sign_object_matches_sign_preimage() {
    // sign_object should produce the same result as sign_preimage with the
    // object's preimage_bytes.
    let sk = test_signing_key();
    let obj = test_object();
    let sig_object = sign_object(&obj, &sk).unwrap();
    let sig_preimage = sign_preimage(&sk, &obj.preimage_bytes()).unwrap();
    assert_eq!(sig_object, sig_preimage);
}

#[test]
fn context_sign_matches_standalone_sign_object() {
    // SignatureContext.sign should produce the same signature as sign_object.
    let mut ctx = SignatureContext::new();
    let sk = test_signing_key();
    let obj = test_object();

    let sig_ctx = ctx.sign(&obj, &sk, "t-match").unwrap();
    let sig_standalone = sign_object(&obj, &sk).unwrap();
    assert_eq!(sig_ctx, sig_standalone);
}

#[test]
fn complex_object_sign_verify() {
    let obj = TestSignable {
        domain: ObjectDomain::Attestation,
        schema: SchemaHash::from_definition(b"complex-v2"),
        data: CanonicalValue::Map(BTreeMap::from([
            (
                "nested_array".to_string(),
                CanonicalValue::Array(vec![
                    CanonicalValue::U64(1),
                    CanonicalValue::I64(-42),
                    CanonicalValue::Bool(false),
                    CanonicalValue::Null,
                ]),
            ),
            (
                "nested_map".to_string(),
                CanonicalValue::Map(BTreeMap::from([(
                    "deep".to_string(),
                    CanonicalValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]),
                )])),
            ),
            (
                "text".to_string(),
                CanonicalValue::String("hello world".to_string()),
            ),
        ])),
    };

    let sk = test_signing_key();
    let vk = sk.verification_key();
    let sig = sign_object(&obj, &sk).unwrap();
    assert!(verify_object(&obj, &vk, &sig).is_ok());
}
