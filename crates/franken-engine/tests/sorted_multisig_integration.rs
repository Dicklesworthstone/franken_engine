#![forbid(unsafe_code)]

//! Integration tests for the `sorted_multisig` module.
//!
//! Exercises the public API from outside the crate, covering:
//! - Construction of `SortedSignatureArray` (sorted and unsorted inputs)
//! - Duplicate signer detection
//! - Unsorted rejection
//! - Sorted insertion maintaining invariants
//! - Contains-signer lookups
//! - Quorum verification (success, failure, unauthorized signers)
//! - `is_sorted` standalone check
//! - `MultiSigContext` event tracking and drain semantics
//! - Display impls for `MultiSigError`, `QuorumResult`, `MultiSigEventType`
//! - Serde round-trips for all serializable types
//! - Deterministic replay: same inputs produce identical results

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

use frankenengine_engine::deterministic_serde::{CanonicalValue, SchemaHash};
use frankenengine_engine::engine_object_id::ObjectDomain;
use frankenengine_engine::signature_preimage::{
    SIGNATURE_LEN, SIGNATURE_SENTINEL, SIGNING_KEY_LEN, Signature, SignatureContext,
    SignaturePreimage, SigningKey, VerificationKey, verify_signature,
};
use frankenengine_engine::sorted_multisig::{
    MultiSigContext, MultiSigError, MultiSigEvent, MultiSigEventType, QuorumResult,
    SignerSignature, SortedSignatureArray, is_sorted,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes([seed; SIGNING_KEY_LEN])
}

fn make_sig_pair(seed: u8) -> (SigningKey, VerificationKey) {
    let sk = make_signing_key(seed);
    let vk = sk.verification_key();
    (sk, vk)
}

/// Test object for signing.
struct TestObj {
    schema: SchemaHash,
    data: u64,
}

impl SignaturePreimage for TestObj {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::PolicyObject
    }
    fn signature_schema(&self) -> &SchemaHash {
        &self.schema
    }
    fn unsigned_view(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("data".to_string(), CanonicalValue::U64(self.data));
        map.insert(
            "signature".to_string(),
            CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
        );
        CanonicalValue::Map(map)
    }
}

fn test_obj() -> TestObj {
    TestObj {
        schema: SchemaHash::from_definition(b"test-multisig-integration-v1"),
        data: 99,
    }
}

fn sign_with(sk: &SigningKey, obj: &TestObj) -> Signature {
    let mut ctx = SignatureContext::new();
    ctx.sign(obj, sk, "integration-test").unwrap()
}

// =========================================================================
// Section 1: SignerSignature construction and ordering
// =========================================================================

#[test]
fn signer_signature_new_stores_fields() {
    let (_, vk) = make_sig_pair(10);
    let sig = Signature::from_bytes([0xBB; SIGNATURE_LEN]);
    let ss = SignerSignature::new(vk.clone(), sig.clone());
    assert_eq!(ss.signer, vk);
    assert_eq!(ss.signature, sig);
}

#[test]
fn signer_signature_ord_by_key_bytes() {
    let (_, vk1) = make_sig_pair(1);
    let (_, vk2) = make_sig_pair(2);
    let sig = Signature::from_bytes([0xAA; SIGNATURE_LEN]);
    let ss1 = SignerSignature::new(vk1.clone(), sig.clone());
    let ss2 = SignerSignature::new(vk2.clone(), sig);
    // Ordering is purely by verification key bytes.
    if vk1.0 < vk2.0 {
        assert!(ss1 < ss2);
    } else {
        assert!(ss2 < ss1);
    }
}

#[test]
fn signer_signature_clone_eq() {
    let (_, vk) = make_sig_pair(5);
    let sig = Signature::from_bytes([0xCC; SIGNATURE_LEN]);
    let ss = SignerSignature::new(vk, sig);
    let cloned = ss.clone();
    assert_eq!(ss, cloned);
}

// =========================================================================
// Section 2: SortedSignatureArray construction
// =========================================================================

#[test]
fn sorted_array_from_presorted_entries() {
    let (sk1, vk1) = make_sig_pair(1);
    let (sk2, vk2) = make_sig_pair(2);
    let obj = test_obj();

    let mut entries = vec![
        SignerSignature::new(vk1, sign_with(&sk1, &obj)),
        SignerSignature::new(vk2, sign_with(&sk2, &obj)),
    ];
    entries.sort();

    let arr = SortedSignatureArray::new(entries).unwrap();
    assert_eq!(arr.len(), 2);
    assert!(!arr.is_empty());
    // Verify invariant: sorted ascending by key bytes.
    assert!(arr.entries()[0].signer.0 < arr.entries()[1].signer.0);
}

#[test]
fn from_unsorted_sorts_and_deduplicates_order() {
    let (sk1, vk1) = make_sig_pair(10);
    let (sk2, vk2) = make_sig_pair(20);
    let (sk3, vk3) = make_sig_pair(30);
    let obj = test_obj();

    // Deliberately reversed.
    let entries = vec![
        SignerSignature::new(vk3, sign_with(&sk3, &obj)),
        SignerSignature::new(vk1, sign_with(&sk1, &obj)),
        SignerSignature::new(vk2, sign_with(&sk2, &obj)),
    ];

    let arr = SortedSignatureArray::from_unsorted(entries).unwrap();
    assert_eq!(arr.len(), 3);
    for i in 1..arr.len() {
        assert!(arr.entries()[i - 1].signer.0 < arr.entries()[i].signer.0);
    }
}

#[test]
fn empty_array_rejected_new() {
    let err = SortedSignatureArray::new(vec![]).unwrap_err();
    assert!(matches!(err, MultiSigError::EmptyArray));
}

#[test]
fn empty_array_rejected_from_unsorted() {
    let err = SortedSignatureArray::from_unsorted(vec![]).unwrap_err();
    assert!(matches!(err, MultiSigError::EmptyArray));
}

#[test]
fn single_entry_array_succeeds() {
    let (sk1, vk1) = make_sig_pair(42);
    let obj = test_obj();
    let entries = vec![SignerSignature::new(vk1, sign_with(&sk1, &obj))];
    let arr = SortedSignatureArray::new(entries).unwrap();
    assert_eq!(arr.len(), 1);
}

// =========================================================================
// Section 3: Unsorted rejection
// =========================================================================

#[test]
fn unsorted_entries_rejected_by_new() {
    let (sk1, vk1) = make_sig_pair(1);
    let (sk2, vk2) = make_sig_pair(2);
    let obj = test_obj();

    let mut entries = vec![
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
        SignerSignature::new(vk2.clone(), sign_with(&sk2, &obj)),
    ];
    // Force descending order.
    if entries[0].signer.0 < entries[1].signer.0 {
        entries.swap(0, 1);
    }

    let err = SortedSignatureArray::new(entries).unwrap_err();
    assert!(matches!(err, MultiSigError::UnsortedSignatureArray { .. }));
}

// =========================================================================
// Section 4: Duplicate detection
// =========================================================================

#[test]
fn duplicate_signer_rejected_from_unsorted() {
    let (sk1, vk1) = make_sig_pair(7);
    let obj = test_obj();

    let entries = vec![
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
        SignerSignature::new(vk1, sign_with(&sk1, &obj)),
    ];

    let err = SortedSignatureArray::from_unsorted(entries).unwrap_err();
    assert!(matches!(err, MultiSigError::DuplicateSignerKey { .. }));
}

#[test]
fn duplicate_signer_rejected_on_new_presorted() {
    let (sk1, vk1) = make_sig_pair(8);
    let obj = test_obj();

    let entries = vec![
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
        SignerSignature::new(vk1, sign_with(&sk1, &obj)),
    ];

    let err = SortedSignatureArray::new(entries).unwrap_err();
    assert!(matches!(err, MultiSigError::DuplicateSignerKey { .. }));
}

#[test]
fn duplicate_signer_rejected_on_insert() {
    let (sk1, vk1) = make_sig_pair(9);
    let obj = test_obj();

    let entries = vec![SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj))];
    let mut arr = SortedSignatureArray::new(entries).unwrap();

    let err = arr
        .insert(SignerSignature::new(vk1, sign_with(&sk1, &obj)))
        .unwrap_err();
    assert!(matches!(err, MultiSigError::DuplicateSignerKey { .. }));
}

#[test]
fn duplicate_key_error_reports_positions() {
    let (sk1, vk1) = make_sig_pair(11);
    let obj = test_obj();

    let entries = vec![SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj))];
    let mut arr = SortedSignatureArray::new(entries).unwrap();

    if let Err(MultiSigError::DuplicateSignerKey { key_hex, positions }) =
        arr.insert(SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)))
    {
        assert!(!key_hex.is_empty());
        assert_eq!(positions.0, 0); // Position of existing entry.
        assert_eq!(positions.1, 1); // Position attempted.
    } else {
        panic!("expected DuplicateSignerKey");
    }
}

// =========================================================================
// Section 5: Insert maintains sorted order
// =========================================================================

#[test]
fn insert_at_beginning() {
    let (sk2, vk2) = make_sig_pair(50);
    let (sk3, vk3) = make_sig_pair(60);
    let (sk1, vk1) = make_sig_pair(40);
    let obj = test_obj();

    let entries = vec![
        SignerSignature::new(vk2.clone(), sign_with(&sk2, &obj)),
        SignerSignature::new(vk3.clone(), sign_with(&sk3, &obj)),
    ];
    let mut arr = SortedSignatureArray::from_unsorted(entries).unwrap();
    arr.insert(SignerSignature::new(vk1, sign_with(&sk1, &obj)))
        .unwrap();

    assert_eq!(arr.len(), 3);
    for i in 1..arr.len() {
        assert!(arr.entries()[i - 1].signer.0 < arr.entries()[i].signer.0);
    }
}

#[test]
fn insert_at_end() {
    let (sk1, vk1) = make_sig_pair(70);
    let (sk2, vk2) = make_sig_pair(80);
    let (sk3, vk3) = make_sig_pair(90);
    let obj = test_obj();

    let entries = vec![
        SignerSignature::new(vk1, sign_with(&sk1, &obj)),
        SignerSignature::new(vk2, sign_with(&sk2, &obj)),
    ];
    let mut arr = SortedSignatureArray::from_unsorted(entries).unwrap();
    arr.insert(SignerSignature::new(vk3, sign_with(&sk3, &obj)))
        .unwrap();

    assert_eq!(arr.len(), 3);
    for i in 1..arr.len() {
        assert!(arr.entries()[i - 1].signer.0 < arr.entries()[i].signer.0);
    }
}

#[test]
fn insert_in_middle() {
    let (sk1, vk1) = make_sig_pair(100);
    let (sk2, vk2) = make_sig_pair(110);
    let (sk3, vk3) = make_sig_pair(120);
    let obj = test_obj();

    let entries = vec![
        SignerSignature::new(vk1, sign_with(&sk1, &obj)),
        SignerSignature::new(vk3, sign_with(&sk3, &obj)),
    ];
    let mut arr = SortedSignatureArray::from_unsorted(entries).unwrap();
    arr.insert(SignerSignature::new(vk2, sign_with(&sk2, &obj)))
        .unwrap();

    assert_eq!(arr.len(), 3);
    for i in 1..arr.len() {
        assert!(arr.entries()[i - 1].signer.0 < arr.entries()[i].signer.0);
    }
}

// =========================================================================
// Section 6: contains_signer and signer_keys
// =========================================================================

#[test]
fn contains_signer_true_for_included_key() {
    let (sk1, vk1) = make_sig_pair(130);
    let obj = test_obj();
    let arr = SortedSignatureArray::new(vec![SignerSignature::new(
        vk1.clone(),
        sign_with(&sk1, &obj),
    )])
    .unwrap();
    assert!(arr.contains_signer(&vk1));
}

#[test]
fn contains_signer_false_for_absent_key() {
    let (sk1, vk1) = make_sig_pair(140);
    let (_, vk2) = make_sig_pair(150);
    let obj = test_obj();
    let arr =
        SortedSignatureArray::new(vec![SignerSignature::new(vk1, sign_with(&sk1, &obj))]).unwrap();
    assert!(!arr.contains_signer(&vk2));
}

#[test]
fn signer_keys_returns_sorted_list() {
    let (sk1, vk1) = make_sig_pair(160);
    let (sk2, vk2) = make_sig_pair(170);
    let obj = test_obj();

    let entries = vec![
        SignerSignature::new(vk2.clone(), sign_with(&sk2, &obj)),
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
    ];
    let arr = SortedSignatureArray::from_unsorted(entries).unwrap();

    let keys = arr.signer_keys();
    assert_eq!(keys.len(), 2);
    assert!(keys[0].0 < keys[1].0);
}

// =========================================================================
// Section 7: Quorum verification
// =========================================================================

#[test]
fn quorum_all_valid_meets_threshold() {
    let (sk1, vk1) = make_sig_pair(1);
    let (sk2, vk2) = make_sig_pair(2);
    let (sk3, vk3) = make_sig_pair(3);
    let obj = test_obj();

    let entries = vec![
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
        SignerSignature::new(vk2.clone(), sign_with(&sk2, &obj)),
        SignerSignature::new(vk3.clone(), sign_with(&sk3, &obj)),
    ];
    let arr = SortedSignatureArray::from_unsorted(entries).unwrap();

    let authorized = vec![vk1, vk2, vk3];
    let preimage = obj.preimage_bytes();

    let result = arr
        .verify_quorum(2, &authorized, |vk, sig| {
            verify_signature(vk, &preimage, sig)
        })
        .unwrap();

    assert!(result.quorum_met);
    assert_eq!(result.valid_count, 3);
    assert_eq!(result.invalid_count, 0);
    assert_eq!(result.unauthorized_count, 0);
    assert_eq!(result.threshold, 2);
    assert_eq!(result.total, 3);
}

#[test]
fn quorum_exact_threshold_succeeds() {
    let (sk1, vk1) = make_sig_pair(1);
    let (sk2, vk2) = make_sig_pair(2);
    let obj = test_obj();

    let entries = vec![
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
        SignerSignature::new(vk2.clone(), sign_with(&sk2, &obj)),
    ];
    let arr = SortedSignatureArray::from_unsorted(entries).unwrap();
    let preimage = obj.preimage_bytes();

    let result = arr
        .verify_quorum(2, &[vk1, vk2], |vk, sig| {
            verify_signature(vk, &preimage, sig)
        })
        .unwrap();

    assert!(result.quorum_met);
    assert_eq!(result.valid_count, 2);
}

#[test]
fn quorum_fails_when_insufficient_valid_signatures() {
    let (sk1, vk1) = make_sig_pair(1);
    let (_, vk2) = make_sig_pair(2);
    let obj = test_obj();

    // Garbage signature for vk2.
    let entries = vec![
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
        SignerSignature::new(vk2.clone(), Signature::from_bytes([0xAA; SIGNATURE_LEN])),
    ];
    let arr = SortedSignatureArray::from_unsorted(entries).unwrap();
    let preimage = obj.preimage_bytes();

    let err = arr
        .verify_quorum(2, &[vk1, vk2], |vk, sig| {
            verify_signature(vk, &preimage, sig)
        })
        .unwrap_err();

    if let MultiSigError::QuorumNotMet {
        required,
        valid,
        total,
    } = err
    {
        assert_eq!(required, 2);
        assert_eq!(valid, 1);
        assert_eq!(total, 2);
    } else {
        panic!("expected QuorumNotMet");
    }
}

#[test]
fn quorum_unauthorized_signers_skipped() {
    let (sk1, vk1) = make_sig_pair(1);
    let (sk2, vk2) = make_sig_pair(2);
    let (sk3, vk3) = make_sig_pair(3);
    let obj = test_obj();

    let entries = vec![
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
        SignerSignature::new(vk2.clone(), sign_with(&sk2, &obj)),
        SignerSignature::new(vk3.clone(), sign_with(&sk3, &obj)),
    ];
    let arr = SortedSignatureArray::from_unsorted(entries).unwrap();
    let preimage = obj.preimage_bytes();

    // Only vk1 authorized; vk2/vk3 unauthorized.
    let result = arr
        .verify_quorum(1, &[vk1], |vk, sig| verify_signature(vk, &preimage, sig))
        .unwrap();

    assert!(result.quorum_met);
    assert_eq!(result.valid_count, 1);
    assert_eq!(result.unauthorized_count, 2);
    assert_eq!(result.unauthorized_signers.len(), 2);
}

#[test]
fn quorum_all_unauthorized_fails() {
    let (sk1, vk1) = make_sig_pair(1);
    let (_, vk_other) = make_sig_pair(200);
    let obj = test_obj();

    let entries = vec![SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj))];
    let arr = SortedSignatureArray::from_unsorted(entries).unwrap();
    let preimage = obj.preimage_bytes();

    // Authorized set does not include vk1.
    let err = arr
        .verify_quorum(1, &[vk_other], |vk, sig| {
            verify_signature(vk, &preimage, sig)
        })
        .unwrap_err();

    assert!(matches!(err, MultiSigError::QuorumNotMet { .. }));
}

#[test]
fn quorum_zero_threshold_rejected() {
    let (sk1, vk1) = make_sig_pair(1);
    let obj = test_obj();

    let entries = vec![SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj))];
    let arr = SortedSignatureArray::new(entries).unwrap();

    let err = arr.verify_quorum(0, &[vk1], |_, _| Ok(())).unwrap_err();
    assert!(matches!(err, MultiSigError::ZeroQuorumThreshold));
}

#[test]
fn quorum_mixed_valid_and_invalid() {
    let (sk1, vk1) = make_sig_pair(1);
    let (sk2, vk2) = make_sig_pair(2);
    let (_, vk3) = make_sig_pair(3);
    let obj = test_obj();

    // vk1: valid signature, vk2: valid, vk3: garbage.
    let entries = vec![
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
        SignerSignature::new(vk2.clone(), sign_with(&sk2, &obj)),
        SignerSignature::new(vk3.clone(), Signature::from_bytes([0xFF; SIGNATURE_LEN])),
    ];
    let arr = SortedSignatureArray::from_unsorted(entries).unwrap();
    let preimage = obj.preimage_bytes();
    let authorized = vec![vk1, vk2, vk3];

    // Threshold of 2 should still pass (2 valid out of 3).
    let result = arr
        .verify_quorum(2, &authorized, |vk, sig| {
            verify_signature(vk, &preimage, sig)
        })
        .unwrap();

    assert!(result.quorum_met);
    assert_eq!(result.valid_count, 2);
    assert_eq!(result.invalid_count, 1);
    assert_eq!(result.invalid_signers.len(), 1);
}

// =========================================================================
// Section 8: is_sorted standalone function
// =========================================================================

#[test]
fn is_sorted_accepts_properly_sorted() {
    let (sk1, vk1) = make_sig_pair(1);
    let (sk2, vk2) = make_sig_pair(2);
    let obj = test_obj();

    let mut entries = vec![
        SignerSignature::new(vk1, sign_with(&sk1, &obj)),
        SignerSignature::new(vk2, sign_with(&sk2, &obj)),
    ];
    entries.sort();
    assert!(is_sorted(&entries).is_ok());
}

#[test]
fn is_sorted_rejects_empty() {
    let err = is_sorted(&[]).unwrap_err();
    assert!(matches!(err, MultiSigError::EmptyArray));
}

#[test]
fn is_sorted_rejects_reversed() {
    let (sk1, vk1) = make_sig_pair(1);
    let (sk2, vk2) = make_sig_pair(2);
    let obj = test_obj();

    let mut entries = vec![
        SignerSignature::new(vk1, sign_with(&sk1, &obj)),
        SignerSignature::new(vk2, sign_with(&sk2, &obj)),
    ];
    entries.sort();
    entries.reverse();
    let err = is_sorted(&entries).unwrap_err();
    assert!(matches!(err, MultiSigError::UnsortedSignatureArray { .. }));
}

#[test]
fn is_sorted_rejects_duplicates() {
    let (sk1, vk1) = make_sig_pair(1);
    let obj = test_obj();

    let entries = vec![
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
        SignerSignature::new(vk1, sign_with(&sk1, &obj)),
    ];
    let err = is_sorted(&entries).unwrap_err();
    assert!(matches!(err, MultiSigError::DuplicateSignerKey { .. }));
}

// =========================================================================
// Section 9: Display impls
// =========================================================================

#[test]
fn multisig_error_display_empty_array() {
    assert_eq!(
        MultiSigError::EmptyArray.to_string(),
        "empty signature array"
    );
}

#[test]
fn multisig_error_display_zero_quorum() {
    assert_eq!(
        MultiSigError::ZeroQuorumThreshold.to_string(),
        "quorum threshold is zero"
    );
}

#[test]
fn multisig_error_display_unsorted() {
    let err = MultiSigError::UnsortedSignatureArray {
        position: 3,
        prev_key_hex: "aabb".to_string(),
        current_key_hex: "0011".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("unsorted at position 3"));
    assert!(msg.contains("aabb"));
    assert!(msg.contains("0011"));
}

#[test]
fn multisig_error_display_duplicate() {
    let err = MultiSigError::DuplicateSignerKey {
        key_hex: "deadbeef".to_string(),
        positions: (2, 5),
    };
    let msg = err.to_string();
    assert!(msg.contains("deadbeef"));
    assert!(msg.contains("2"));
    assert!(msg.contains("5"));
}

#[test]
fn multisig_error_display_quorum_not_met() {
    let err = MultiSigError::QuorumNotMet {
        required: 3,
        valid: 1,
        total: 5,
    };
    let msg = err.to_string();
    assert!(msg.contains("1/5"));
    assert!(msg.contains("3 required"));
}

#[test]
fn multisig_error_display_threshold_exceeds() {
    let err = MultiSigError::ThresholdExceedsSignerCount {
        threshold: 10,
        signer_count: 3,
    };
    let msg = err.to_string();
    assert!(msg.contains("10"));
    assert!(msg.contains("3"));
}

#[test]
fn multisig_error_display_signature_error() {
    let err = MultiSigError::SignatureError {
        detail: "bad sig".to_string(),
    };
    assert!(err.to_string().contains("bad sig"));
}

#[test]
fn quorum_result_display_format() {
    let result = QuorumResult {
        quorum_met: true,
        valid_count: 3,
        invalid_count: 1,
        unauthorized_count: 2,
        total: 6,
        threshold: 3,
        invalid_signers: vec![],
        unauthorized_signers: vec![],
    };
    let msg = result.to_string();
    assert!(msg.contains("3/6"));
    assert!(msg.contains("threshold 3"));
    assert!(msg.contains("1 invalid"));
    assert!(msg.contains("2 unauthorized"));
}

#[test]
fn event_type_display_array_created() {
    let evt = MultiSigEventType::ArrayCreated { signer_count: 5 };
    assert!(evt.to_string().contains("5 signers"));
}

#[test]
fn event_type_display_signature_inserted() {
    let evt = MultiSigEventType::SignatureInserted {
        signer_hex: "aabbcc".to_string(),
    };
    assert!(evt.to_string().contains("aabbcc"));
}

#[test]
fn event_type_display_quorum_verified() {
    let evt = MultiSigEventType::QuorumVerified {
        valid: 3,
        threshold: 2,
        total: 4,
    };
    let msg = evt.to_string();
    assert!(msg.contains("3/4"));
    assert!(msg.contains("threshold 2"));
}

#[test]
fn event_type_display_quorum_failed() {
    let evt = MultiSigEventType::QuorumFailed {
        valid: 1,
        threshold: 3,
        total: 5,
    };
    let msg = evt.to_string();
    assert!(msg.contains("1/5"));
    assert!(msg.contains("threshold 3"));
}

#[test]
fn event_type_display_sorting_violation() {
    let evt = MultiSigEventType::SortingViolation {
        detail: "bad order".to_string(),
    };
    assert!(evt.to_string().contains("bad order"));
}

#[test]
fn event_type_display_duplicate_signer() {
    let evt = MultiSigEventType::DuplicateSigner {
        key_hex: "ff00".to_string(),
    };
    assert!(evt.to_string().contains("ff00"));
}

// =========================================================================
// Section 10: MultiSigContext event tracking
// =========================================================================

#[test]
fn context_new_has_no_events() {
    let ctx = MultiSigContext::new();
    assert_eq!(ctx.event_counts().len(), 0);
}

#[test]
fn context_default_matches_new() {
    let ctx = MultiSigContext::default();
    assert_eq!(ctx.event_counts().len(), 0);
}

#[test]
fn context_create_sorted_emits_array_created() {
    let (sk1, vk1) = make_sig_pair(1);
    let (sk2, vk2) = make_sig_pair(2);
    let obj = test_obj();

    let mut ctx = MultiSigContext::new();
    let entries = vec![
        SignerSignature::new(vk1, sign_with(&sk1, &obj)),
        SignerSignature::new(vk2, sign_with(&sk2, &obj)),
    ];
    let arr = ctx.create_sorted(entries, "trace-create").unwrap();
    assert_eq!(arr.len(), 2);

    let events = ctx.drain_events();
    assert_eq!(events.len(), 1);
    if let MultiSigEventType::ArrayCreated { signer_count } = &events[0].event_type {
        assert_eq!(*signer_count, 2);
    } else {
        panic!("expected ArrayCreated event");
    }
    assert_eq!(events[0].trace_id, "trace-create");
}

#[test]
fn context_create_sorted_emits_duplicate_on_error() {
    let (sk1, vk1) = make_sig_pair(1);
    let obj = test_obj();

    let mut ctx = MultiSigContext::new();
    let entries = vec![
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
        SignerSignature::new(vk1, sign_with(&sk1, &obj)),
    ];
    let err = ctx.create_sorted(entries, "trace-dup").unwrap_err();
    assert!(matches!(err, MultiSigError::DuplicateSignerKey { .. }));

    let events = ctx.drain_events();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].event_type,
        MultiSigEventType::DuplicateSigner { .. }
    ));
}

#[test]
fn context_create_sorted_emits_sorting_violation_for_empty() {
    let mut ctx = MultiSigContext::new();
    let err = ctx.create_sorted(vec![], "trace-empty").unwrap_err();
    assert!(matches!(err, MultiSigError::EmptyArray));

    let events = ctx.drain_events();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].event_type,
        MultiSigEventType::SortingViolation { .. }
    ));
}

#[test]
fn context_verify_quorum_emits_verified_event() {
    let (sk1, vk1) = make_sig_pair(1);
    let obj = test_obj();
    let preimage = obj.preimage_bytes();

    let mut ctx = MultiSigContext::new();
    let entries = vec![SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj))];
    let arr = ctx.create_sorted(entries, "t-q1").unwrap();

    ctx.verify_quorum(
        &arr,
        1,
        &[vk1],
        |vk, sig| verify_signature(vk, &preimage, sig),
        "t-q2",
    )
    .unwrap();

    let counts = ctx.event_counts();
    assert_eq!(counts.get("array_created"), Some(&1));
    assert_eq!(counts.get("quorum_verified"), Some(&1));
}

#[test]
fn context_verify_quorum_emits_failed_event() {
    let (sk1, vk1) = make_sig_pair(1);
    let (_, vk2) = make_sig_pair(2);
    let obj = test_obj();
    let preimage = obj.preimage_bytes();

    let mut ctx = MultiSigContext::new();
    let entries = vec![SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj))];
    let arr = ctx.create_sorted(entries, "t-f1").unwrap();

    // Require threshold 1 but only vk2 authorized (vk1 not authorized).
    let err = ctx
        .verify_quorum(
            &arr,
            1,
            &[vk2],
            |vk, sig| verify_signature(vk, &preimage, sig),
            "t-f2",
        )
        .unwrap_err();
    assert!(matches!(err, MultiSigError::QuorumNotMet { .. }));

    let counts = ctx.event_counts();
    assert_eq!(counts.get("quorum_failed"), Some(&1));
}

#[test]
fn context_drain_events_clears_list() {
    let (sk1, vk1) = make_sig_pair(1);
    let obj = test_obj();

    let mut ctx = MultiSigContext::new();
    let entries = vec![SignerSignature::new(vk1, sign_with(&sk1, &obj))];
    ctx.create_sorted(entries, "t-drain").unwrap();
    assert_eq!(ctx.drain_events().len(), 1);
    assert_eq!(ctx.drain_events().len(), 0);
}

#[test]
fn context_event_counts_accumulate() {
    let (sk1, vk1) = make_sig_pair(1);
    let (sk2, vk2) = make_sig_pair(2);
    let obj = test_obj();

    let mut ctx = MultiSigContext::new();
    let entries1 = vec![SignerSignature::new(vk1, sign_with(&sk1, &obj))];
    ctx.create_sorted(entries1, "t1").unwrap();

    let entries2 = vec![SignerSignature::new(vk2, sign_with(&sk2, &obj))];
    ctx.create_sorted(entries2, "t2").unwrap();

    let counts = ctx.event_counts();
    assert_eq!(counts.get("array_created"), Some(&2));
}

// =========================================================================
// Section 11: Serde round-trips
// =========================================================================

#[test]
fn signer_signature_serde_round_trip() {
    let (sk1, vk1) = make_sig_pair(1);
    let obj = test_obj();
    let ss = SignerSignature::new(vk1, sign_with(&sk1, &obj));

    let json = serde_json::to_string(&ss).expect("serialize");
    let restored: SignerSignature = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ss, restored);
}

#[test]
fn sorted_signature_array_serde_round_trip() {
    let (sk1, vk1) = make_sig_pair(1);
    let (sk2, vk2) = make_sig_pair(2);
    let obj = test_obj();

    let entries = vec![
        SignerSignature::new(vk1, sign_with(&sk1, &obj)),
        SignerSignature::new(vk2, sign_with(&sk2, &obj)),
    ];
    let arr = SortedSignatureArray::from_unsorted(entries).unwrap();

    let json = serde_json::to_string(&arr).expect("serialize");
    let restored: SortedSignatureArray = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(arr, restored);

    // Verify still sorted after deserialization.
    for i in 1..restored.entries().len() {
        assert!(restored.entries()[i - 1].signer.0 < restored.entries()[i].signer.0);
    }
}

#[test]
fn multisig_error_all_variants_serde_round_trip() {
    let errors = vec![
        MultiSigError::EmptyArray,
        MultiSigError::ZeroQuorumThreshold,
        MultiSigError::UnsortedSignatureArray {
            position: 1,
            prev_key_hex: "aa".to_string(),
            current_key_hex: "bb".to_string(),
        },
        MultiSigError::DuplicateSignerKey {
            key_hex: "cc".to_string(),
            positions: (0, 1),
        },
        MultiSigError::QuorumNotMet {
            required: 3,
            valid: 1,
            total: 5,
        },
        MultiSigError::ThresholdExceedsSignerCount {
            threshold: 10,
            signer_count: 3,
        },
        MultiSigError::SignatureError {
            detail: "bad sig".to_string(),
        },
    ];

    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let restored: MultiSigError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, restored);
    }
}

#[test]
fn quorum_result_serde_round_trip() {
    let (_, vk1) = make_sig_pair(1);
    let result = QuorumResult {
        quorum_met: true,
        valid_count: 2,
        invalid_count: 1,
        unauthorized_count: 0,
        total: 3,
        threshold: 2,
        invalid_signers: vec![(vk1.clone(), "bad".to_string())],
        unauthorized_signers: vec![vk1],
    };
    let json = serde_json::to_string(&result).expect("serialize");
    let restored: QuorumResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(result, restored);
}

#[test]
fn multisig_event_serde_round_trip() {
    let events = vec![
        MultiSigEvent {
            event_type: MultiSigEventType::ArrayCreated { signer_count: 3 },
            trace_id: "t-1".to_string(),
        },
        MultiSigEvent {
            event_type: MultiSigEventType::SignatureInserted {
                signer_hex: "abcd".to_string(),
            },
            trace_id: "t-2".to_string(),
        },
        MultiSigEvent {
            event_type: MultiSigEventType::QuorumVerified {
                valid: 2,
                threshold: 2,
                total: 3,
            },
            trace_id: "t-3".to_string(),
        },
        MultiSigEvent {
            event_type: MultiSigEventType::QuorumFailed {
                valid: 0,
                threshold: 2,
                total: 3,
            },
            trace_id: "t-4".to_string(),
        },
        MultiSigEvent {
            event_type: MultiSigEventType::SortingViolation {
                detail: "out of order".to_string(),
            },
            trace_id: "t-5".to_string(),
        },
        MultiSigEvent {
            event_type: MultiSigEventType::DuplicateSigner {
                key_hex: "ffee".to_string(),
            },
            trace_id: "t-6".to_string(),
        },
    ];

    for event in &events {
        let json = serde_json::to_string(event).expect("serialize");
        let restored: MultiSigEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*event, restored);
    }
}

// =========================================================================
// Section 12: Deterministic replay
// =========================================================================

#[test]
fn deterministic_replay_same_inputs_same_sorted_array() {
    let (sk1, vk1) = make_sig_pair(1);
    let (sk2, vk2) = make_sig_pair(2);
    let (sk3, vk3) = make_sig_pair(3);
    let obj = test_obj();

    let make_entries = || {
        vec![
            SignerSignature::new(vk3.clone(), sign_with(&sk3, &obj)),
            SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
            SignerSignature::new(vk2.clone(), sign_with(&sk2, &obj)),
        ]
    };

    let arr1 = SortedSignatureArray::from_unsorted(make_entries()).unwrap();
    let arr2 = SortedSignatureArray::from_unsorted(make_entries()).unwrap();

    assert_eq!(arr1, arr2);
    let json1 = serde_json::to_string(&arr1).unwrap();
    let json2 = serde_json::to_string(&arr2).unwrap();
    assert_eq!(json1, json2);
}

#[test]
fn deterministic_quorum_verification_same_result() {
    let (sk1, vk1) = make_sig_pair(1);
    let (sk2, vk2) = make_sig_pair(2);
    let obj = test_obj();
    let preimage = obj.preimage_bytes();

    let entries = vec![
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
        SignerSignature::new(vk2.clone(), sign_with(&sk2, &obj)),
    ];
    let arr = SortedSignatureArray::from_unsorted(entries).unwrap();
    let authorized = vec![vk1.clone(), vk2.clone()];

    let r1 = arr
        .verify_quorum(1, &authorized, |vk, sig| {
            verify_signature(vk, &preimage, sig)
        })
        .unwrap();
    let r2 = arr
        .verify_quorum(1, &authorized, |vk, sig| {
            verify_signature(vk, &preimage, sig)
        })
        .unwrap();

    assert_eq!(r1, r2);
}

// =========================================================================
// Section 13: Multi-signer end-to-end workflow
// =========================================================================

#[test]
fn end_to_end_multisig_workflow() {
    // 1. Setup signers.
    let (sk1, vk1) = make_sig_pair(10);
    let (sk2, vk2) = make_sig_pair(20);
    let (sk3, vk3) = make_sig_pair(30);
    let (sk4, vk4) = make_sig_pair(40);
    let (sk5, vk5) = make_sig_pair(50);
    let obj = test_obj();

    // 2. Create context.
    let mut ctx = MultiSigContext::new();

    // 3. Build sorted array from five signers (unsorted input).
    let entries = vec![
        SignerSignature::new(vk5.clone(), sign_with(&sk5, &obj)),
        SignerSignature::new(vk2.clone(), sign_with(&sk2, &obj)),
        SignerSignature::new(vk4.clone(), sign_with(&sk4, &obj)),
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
        SignerSignature::new(vk3.clone(), sign_with(&sk3, &obj)),
    ];
    let arr = ctx.create_sorted(entries, "e2e-create").unwrap();
    assert_eq!(arr.len(), 5);

    // 4. Verify sorting invariant.
    for i in 1..arr.len() {
        assert!(arr.entries()[i - 1].signer.0 < arr.entries()[i].signer.0);
    }

    // 5. All five signers authorized, require 3-of-5 quorum.
    let authorized = vec![vk1, vk2, vk3, vk4, vk5];
    let preimage = obj.preimage_bytes();

    let result = ctx
        .verify_quorum(
            &arr,
            3,
            &authorized,
            |vk, sig| verify_signature(vk, &preimage, sig),
            "e2e-quorum",
        )
        .unwrap();

    assert!(result.quorum_met);
    assert_eq!(result.valid_count, 5);
    assert_eq!(result.threshold, 3);
    assert_eq!(result.total, 5);

    // 6. Check events.
    let counts = ctx.event_counts();
    assert_eq!(counts.get("array_created"), Some(&1));
    assert_eq!(counts.get("quorum_verified"), Some(&1));
}

#[test]
fn incremental_build_via_insert() {
    let (sk1, vk1) = make_sig_pair(1);
    let (sk2, vk2) = make_sig_pair(2);
    let (sk3, vk3) = make_sig_pair(3);
    let (sk4, vk4) = make_sig_pair(4);
    let obj = test_obj();

    // Start with one entry.
    let entries = vec![SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj))];
    let mut arr = SortedSignatureArray::new(entries).unwrap();

    // Insert remaining three.
    arr.insert(SignerSignature::new(vk3.clone(), sign_with(&sk3, &obj)))
        .unwrap();
    arr.insert(SignerSignature::new(vk2.clone(), sign_with(&sk2, &obj)))
        .unwrap();
    arr.insert(SignerSignature::new(vk4.clone(), sign_with(&sk4, &obj)))
        .unwrap();

    assert_eq!(arr.len(), 4);
    for i in 1..arr.len() {
        assert!(arr.entries()[i - 1].signer.0 < arr.entries()[i].signer.0);
    }

    // All present.
    assert!(arr.contains_signer(&vk1));
    assert!(arr.contains_signer(&vk2));
    assert!(arr.contains_signer(&vk3));
    assert!(arr.contains_signer(&vk4));
}

// =========================================================================
// Section 14: Edge cases
// =========================================================================

#[test]
fn many_signers_stress_test() {
    let obj = test_obj();
    let mut entries = Vec::new();
    // Use seeds 1..=20 for 20 distinct signers.
    for seed in 1u8..=20 {
        let (sk, vk) = make_sig_pair(seed);
        entries.push(SignerSignature::new(vk, sign_with(&sk, &obj)));
    }

    let arr = SortedSignatureArray::from_unsorted(entries).unwrap();
    assert_eq!(arr.len(), 20);

    // Verify sorted.
    for i in 1..arr.len() {
        assert!(arr.entries()[i - 1].signer.0 < arr.entries()[i].signer.0);
    }
}

#[test]
fn quorum_threshold_equals_total_signers() {
    let (sk1, vk1) = make_sig_pair(1);
    let (sk2, vk2) = make_sig_pair(2);
    let obj = test_obj();
    let preimage = obj.preimage_bytes();

    let entries = vec![
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
        SignerSignature::new(vk2.clone(), sign_with(&sk2, &obj)),
    ];
    let arr = SortedSignatureArray::from_unsorted(entries).unwrap();

    // Require all signers to pass.
    let result = arr
        .verify_quorum(2, &[vk1, vk2], |vk, sig| {
            verify_signature(vk, &preimage, sig)
        })
        .unwrap();

    assert!(result.quorum_met);
    assert_eq!(result.valid_count, 2);
}

#[test]
fn quorum_with_closure_returning_error() {
    let (sk1, vk1) = make_sig_pair(1);
    let obj = test_obj();

    let entries = vec![SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj))];
    let arr = SortedSignatureArray::new(entries).unwrap();

    // Verification function that always fails.
    let err = arr
        .verify_quorum(1, std::slice::from_ref(&vk1), |_vk, _sig| {
            Err(
                frankenengine_engine::signature_preimage::SignatureError::VerificationFailed {
                    signer: vk1.clone(),
                    reason: "test failure".to_string(),
                },
            )
        })
        .unwrap_err();

    assert!(matches!(err, MultiSigError::QuorumNotMet { .. }));
}
