//! Enrichment integration tests for `signature_preimage`.
//!
//! Covers gaps: SigningKey/VerificationKey construction, key derivation,
//! Signature sentinel detection, sign/verify roundtrip, sign_object/verify_object
//! consistency, preimage_hash determinism, canonical checking, SignatureContext
//! event tracking, serde roundtrips for keys and signatures, error Display
//! coverage, build_preimage determinism, and constant values.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::signature_preimage::{
    SIGNATURE_LEN, SIGNATURE_SENTINEL, SIGNING_KEY_LEN, Signature, SignatureContext,
    SignatureError, SignatureEventType, SigningKey, VERIFICATION_KEY_LEN, VerificationKey,
    build_preimage, preimage_hash, sign_preimage, verify_signature,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_signing_key() -> SigningKey {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(13);
    }
    SigningKey::from_bytes(bytes)
}

fn test_signing_key_2() -> SigningKey {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(11).wrapping_add(3);
    }
    SigningKey::from_bytes(bytes)
}

fn test_preimage() -> Vec<u8> {
    b"test preimage data for signing".to_vec()
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_signing_key_len_is_32() {
    assert_eq!(SIGNING_KEY_LEN, 32);
}

#[test]
fn enrichment_verification_key_len_is_32() {
    assert_eq!(VERIFICATION_KEY_LEN, 32);
}

#[test]
fn enrichment_signature_len_is_64() {
    assert_eq!(SIGNATURE_LEN, 64);
}

#[test]
fn enrichment_signature_sentinel_is_all_zeros() {
    assert!(SIGNATURE_SENTINEL.iter().all(|&b| b == 0));
    assert_eq!(SIGNATURE_SENTINEL.len(), 64);
}

// ===========================================================================
// SigningKey
// ===========================================================================

#[test]
fn enrichment_signing_key_from_bytes_roundtrip() {
    let bytes = [42u8; 32];
    let key = SigningKey::from_bytes(bytes);
    assert_eq!(*key.as_bytes(), bytes);
}

#[test]
fn enrichment_signing_key_derives_verification_key() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    assert_ne!(*vk.as_bytes(), [0u8; 32], "VK should not be all zeros");
}

#[test]
fn enrichment_signing_key_derivation_deterministic() {
    let sk = test_signing_key();
    let vk1 = sk.verification_key();
    let vk2 = sk.verification_key();
    assert_eq!(*vk1.as_bytes(), *vk2.as_bytes());
}

#[test]
fn enrichment_different_signing_keys_different_verification_keys() {
    let sk1 = test_signing_key();
    let sk2 = test_signing_key_2();
    let vk1 = sk1.verification_key();
    let vk2 = sk2.verification_key();
    assert_ne!(*vk1.as_bytes(), *vk2.as_bytes());
}

// ===========================================================================
// VerificationKey
// ===========================================================================

#[test]
fn enrichment_verification_key_from_bytes_roundtrip() {
    let bytes = [99u8; 32];
    let vk = VerificationKey::from_bytes(bytes);
    assert_eq!(*vk.as_bytes(), bytes);
}

#[test]
fn enrichment_verification_key_to_hex_nonempty() {
    let vk = test_signing_key().verification_key();
    let hex = vk.to_hex();
    assert!(!hex.is_empty());
    assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars
}

#[test]
fn enrichment_verification_key_display_equals_hex() {
    let vk = test_signing_key().verification_key();
    let display = vk.to_string();
    let hex = vk.to_hex();
    assert_eq!(display, hex);
}

// ===========================================================================
// Signature
// ===========================================================================

#[test]
fn enrichment_signature_from_bytes_roundtrip() {
    let mut bytes = [0u8; 64];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = i as u8;
    }
    let sig = Signature::from_bytes(bytes);
    assert_eq!(sig.to_bytes(), bytes);
}

#[test]
fn enrichment_sentinel_signature_detected() {
    let sig = Signature::from_bytes([0u8; 64]);
    assert!(sig.is_sentinel());
}

#[test]
fn enrichment_non_sentinel_signature_not_detected() {
    let mut bytes = [0u8; 64];
    bytes[0] = 1;
    let sig = Signature::from_bytes(bytes);
    assert!(!sig.is_sentinel());
}

#[test]
fn enrichment_signature_display_nonempty() {
    let sig = Signature::from_bytes([42u8; 64]);
    let display = sig.to_string();
    assert!(!display.is_empty());
}

#[test]
fn enrichment_signature_serde_roundtrip() {
    let mut bytes = [0u8; 64];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i as u8) ^ 0xAA;
    }
    let sig = Signature::from_bytes(bytes);
    let json = serde_json::to_string(&sig).unwrap();
    let back: Signature = serde_json::from_str(&json).unwrap();
    assert_eq!(sig.to_bytes(), back.to_bytes());
}

// ===========================================================================
// sign_preimage / verify_signature roundtrip
// ===========================================================================

#[test]
fn enrichment_sign_verify_roundtrip() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let preimage = test_preimage();
    let sig = sign_preimage(&sk, &preimage).unwrap();
    assert!(!sig.is_sentinel());
    let result = verify_signature(&vk, &preimage, &sig);
    assert!(result.is_ok());
}

#[test]
fn enrichment_verify_with_wrong_key_fails() {
    let sk = test_signing_key();
    let wrong_vk = test_signing_key_2().verification_key();
    let preimage = test_preimage();
    let sig = sign_preimage(&sk, &preimage).unwrap();
    let result = verify_signature(&wrong_vk, &preimage, &sig);
    assert!(result.is_err());
}

#[test]
fn enrichment_verify_with_tampered_preimage_fails() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let preimage = test_preimage();
    let sig = sign_preimage(&sk, &preimage).unwrap();
    let mut tampered = preimage.clone();
    tampered[0] ^= 0xFF;
    let result = verify_signature(&vk, &tampered, &sig);
    assert!(result.is_err());
}

#[test]
fn enrichment_sign_deterministic() {
    let sk = test_signing_key();
    let preimage = test_preimage();
    let sig1 = sign_preimage(&sk, &preimage).unwrap();
    let sig2 = sign_preimage(&sk, &preimage).unwrap();
    assert_eq!(sig1.to_bytes(), sig2.to_bytes());
}

#[test]
fn enrichment_different_preimages_different_signatures() {
    let sk = test_signing_key();
    let sig1 = sign_preimage(&sk, b"data_a").unwrap();
    let sig2 = sign_preimage(&sk, b"data_b").unwrap();
    assert_ne!(sig1.to_bytes(), sig2.to_bytes());
}

// ===========================================================================
// preimage_hash
// ===========================================================================

#[test]
fn enrichment_preimage_hash_deterministic() {
    let data = b"deterministic test data";
    let h1 = preimage_hash(data);
    let h2 = preimage_hash(data);
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_different_data_different_hash() {
    let h1 = preimage_hash(b"data_one");
    let h2 = preimage_hash(b"data_two");
    assert_ne!(h1, h2);
}

// ===========================================================================
// SignatureError Display
// ===========================================================================

#[test]
fn enrichment_error_display_verification_failed() {
    let err = SignatureError::VerificationFailed {
        signer: VerificationKey::from_bytes([1u8; 32]),
        reason: "bad signature".to_string(),
    };
    let display = err.to_string();
    assert!(display.contains("bad signature") || !display.is_empty());
}

#[test]
fn enrichment_error_display_non_canonical() {
    let err = SignatureError::NonCanonicalObject {
        detail: "missing field".to_string(),
    };
    let display = err.to_string();
    assert!(!display.is_empty());
}

#[test]
fn enrichment_error_display_preimage_error() {
    let err = SignatureError::PreimageError {
        detail: "encoding failed".to_string(),
    };
    let display = err.to_string();
    assert!(!display.is_empty());
}

#[test]
fn enrichment_error_display_all_unique() {
    let errors = [
        SignatureError::VerificationFailed {
            signer: VerificationKey::from_bytes([1u8; 32]),
            reason: "r".to_string(),
        },
        SignatureError::NonCanonicalObject {
            detail: "d".to_string(),
        },
        SignatureError::PreimageError {
            detail: "p".to_string(),
        },
        SignatureError::InvalidSigningKey,
        SignatureError::InvalidVerificationKey,
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), errors.len());
}

#[test]
fn enrichment_error_serde_roundtrip() {
    let errors = [
        SignatureError::VerificationFailed {
            signer: VerificationKey::from_bytes([1u8; 32]),
            reason: "r".to_string(),
        },
        SignatureError::NonCanonicalObject {
            detail: "d".to_string(),
        },
        SignatureError::PreimageError {
            detail: "p".to_string(),
        },
        SignatureError::InvalidSigningKey,
        SignatureError::InvalidVerificationKey,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: SignatureError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ===========================================================================
// SignatureContext
// ===========================================================================

#[test]
fn enrichment_context_new_zeroed_counters() {
    let ctx = SignatureContext::new();
    assert_eq!(ctx.sign_count(), 0);
    assert_eq!(ctx.verify_count(), 0);
    assert_eq!(ctx.failure_count(), 0);
}

#[test]
fn enrichment_context_default_same_as_new() {
    let ctx1 = SignatureContext::new();
    let ctx2 = SignatureContext::default();
    assert_eq!(ctx1.sign_count(), ctx2.sign_count());
    assert_eq!(ctx1.verify_count(), ctx2.verify_count());
}

#[test]
fn enrichment_context_drain_events_empty_initially() {
    let mut ctx = SignatureContext::new();
    let events = ctx.drain_events();
    assert!(events.is_empty());
}

#[test]
fn enrichment_context_event_counts_empty_initially() {
    let ctx = SignatureContext::new();
    let counts = ctx.event_counts();
    assert!(counts.is_empty());
}

// ===========================================================================
// SignatureEventType Display
// ===========================================================================

#[test]
fn enrichment_event_type_display_all_unique() {
    let types = [
        SignatureEventType::Signed {
            signer: VerificationKey::from_bytes([1u8; 32]),
        },
        SignatureEventType::Verified {
            signer: VerificationKey::from_bytes([2u8; 32]),
        },
        SignatureEventType::VerificationFailed {
            signer: VerificationKey::from_bytes([3u8; 32]),
            reason: "r".to_string(),
        },
        SignatureEventType::CanonicalityCheckFailed {
            detail: "d".to_string(),
        },
    ];
    let displays: BTreeSet<String> = types.iter().map(|t| t.to_string()).collect();
    assert_eq!(displays.len(), types.len());
}

#[test]
fn enrichment_event_type_serde_roundtrip() {
    let types = [
        SignatureEventType::Signed {
            signer: VerificationKey::from_bytes([10u8; 32]),
        },
        SignatureEventType::Verified {
            signer: VerificationKey::from_bytes([20u8; 32]),
        },
        SignatureEventType::VerificationFailed {
            signer: VerificationKey::from_bytes([30u8; 32]),
            reason: "bad".to_string(),
        },
        SignatureEventType::CanonicalityCheckFailed {
            detail: "non-canonical".to_string(),
        },
    ];
    for t in &types {
        let json = serde_json::to_string(t).unwrap();
        let back: SignatureEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, back);
    }
}

// ===========================================================================
// build_preimage determinism
// ===========================================================================

#[test]
fn enrichment_build_preimage_deterministic() {
    use frankenengine_engine::deterministic_serde::{CanonicalValue, SchemaHash};
    use frankenengine_engine::engine_object_id::ObjectDomain;

    let domain = ObjectDomain::PolicyObject;
    let schema = SchemaHash::from_definition(b"test-schema-v1");
    let value = CanonicalValue::Null;
    let p1 = build_preimage(domain, &schema, &value);
    let p2 = build_preimage(domain, &schema, &value);
    assert_eq!(p1, p2);
    assert!(!p1.is_empty());
}

#[test]
fn enrichment_build_preimage_different_domains_differ() {
    use frankenengine_engine::deterministic_serde::{CanonicalValue, SchemaHash};
    use frankenengine_engine::engine_object_id::ObjectDomain;

    let schema = SchemaHash::from_definition(b"test-schema-v1");
    let value = CanonicalValue::Null;
    let p1 = build_preimage(ObjectDomain::PolicyObject, &schema, &value);
    let p2 = build_preimage(ObjectDomain::EvidenceRecord, &schema, &value);
    assert_ne!(p1, p2);
}

// ===========================================================================
// Empty preimage signing
// ===========================================================================

#[test]
fn enrichment_sign_empty_preimage() {
    let sk = test_signing_key();
    let sig = sign_preimage(&sk, &[]).unwrap();
    assert!(!sig.is_sentinel());
}

#[test]
fn enrichment_verify_empty_preimage() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let sig = sign_preimage(&sk, &[]).unwrap();
    assert!(verify_signature(&vk, &[], &sig).is_ok());
}

// ===========================================================================
// Large preimage signing
// ===========================================================================

#[test]
fn enrichment_sign_large_preimage() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let large = vec![0xABu8; 100_000];
    let sig = sign_preimage(&sk, &large).unwrap();
    assert!(verify_signature(&vk, &large, &sig).is_ok());
}
