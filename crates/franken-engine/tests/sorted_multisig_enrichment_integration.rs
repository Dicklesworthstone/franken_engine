//! Enrichment integration tests for the `sorted_multisig` module.
//!
//! Exercises deeper edge cases: large signer sets, repeated insert/remove
//! patterns, quorum threshold boundary conditions, event tracking under
//! combined operations, serde fidelity after mutations, and determinism
//! under various ordering permutations.

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
        schema: SchemaHash::from_definition(b"enrichment-multisig-v1"),
        data: 42,
    }
}

fn sign_with(sk: &SigningKey, obj: &TestObj) -> Signature {
    let mut ctx = SignatureContext::new();
    ctx.sign(obj, sk, "enrichment-test").unwrap()
}

// ===========================================================================
// Section 1: Large signer sets
// ===========================================================================

#[test]
fn enrichment_50_signers_sorted_correctly() {
    let obj = test_obj();
    let mut entries = Vec::new();
    for seed in 1u8..=50 {
        let (sk, vk) = make_sig_pair(seed);
        entries.push(SignerSignature::new(vk, sign_with(&sk, &obj)));
    }
    let arr = SortedSignatureArray::from_unsorted(entries).unwrap();
    assert_eq!(arr.len(), 50);
    for i in 1..arr.len() {
        assert!(arr.entries()[i - 1].signer.0 < arr.entries()[i].signer.0);
    }
}

#[test]
fn enrichment_large_set_contains_all() {
    let obj = test_obj();
    let mut keys = Vec::new();
    let mut entries = Vec::new();
    for seed in 1u8..=30 {
        let (sk, vk) = make_sig_pair(seed);
        keys.push(vk.clone());
        entries.push(SignerSignature::new(vk, sign_with(&sk, &obj)));
    }
    let arr = SortedSignatureArray::from_unsorted(entries).unwrap();
    for vk in &keys {
        assert!(arr.contains_signer(vk));
    }
}

#[test]
fn enrichment_large_set_signer_keys_count() {
    let obj = test_obj();
    let mut entries = Vec::new();
    for seed in 1u8..=25 {
        let (sk, vk) = make_sig_pair(seed);
        entries.push(SignerSignature::new(vk, sign_with(&sk, &obj)));
    }
    let arr = SortedSignatureArray::from_unsorted(entries).unwrap();
    let keys = arr.signer_keys();
    assert_eq!(keys.len(), 25);
}

// ===========================================================================
// Section 2: Incremental insert ordering
// ===========================================================================

#[test]
fn enrichment_insert_maintains_order_after_many_inserts() {
    let obj = test_obj();
    let (sk1, vk1) = make_sig_pair(50);
    let entries = vec![SignerSignature::new(vk1, sign_with(&sk1, &obj))];
    let mut arr = SortedSignatureArray::new(entries).unwrap();

    for seed in [30u8, 70, 10, 90, 20, 80, 40, 60] {
        let (sk, vk) = make_sig_pair(seed);
        arr.insert(SignerSignature::new(vk, sign_with(&sk, &obj)))
            .unwrap();
    }
    assert_eq!(arr.len(), 9);
    for i in 1..arr.len() {
        assert!(arr.entries()[i - 1].signer.0 < arr.entries()[i].signer.0);
    }
}

#[test]
fn enrichment_insert_duplicate_after_growth() {
    let obj = test_obj();
    let (sk1, vk1) = make_sig_pair(1);
    let (sk2, vk2) = make_sig_pair(2);
    let entries = vec![
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
        SignerSignature::new(vk2.clone(), sign_with(&sk2, &obj)),
    ];
    let mut arr = SortedSignatureArray::from_unsorted(entries).unwrap();
    let err = arr
        .insert(SignerSignature::new(vk1, sign_with(&sk1, &obj)))
        .unwrap_err();
    assert!(matches!(err, MultiSigError::DuplicateSignerKey { .. }));
    assert_eq!(arr.len(), 2); // unchanged
}

// ===========================================================================
// Section 3: Quorum threshold boundary conditions
// ===========================================================================

#[test]
fn enrichment_quorum_threshold_one_of_many() {
    let obj = test_obj();
    let preimage = obj.preimage_bytes();
    let mut entries = Vec::new();
    let mut authorized = Vec::new();
    for seed in 1u8..=10 {
        let (sk, vk) = make_sig_pair(seed);
        authorized.push(vk.clone());
        entries.push(SignerSignature::new(vk, sign_with(&sk, &obj)));
    }
    let arr = SortedSignatureArray::from_unsorted(entries).unwrap();
    let result = arr
        .verify_quorum(1, &authorized, |vk, sig| {
            verify_signature(vk, &preimage, sig)
        })
        .unwrap();
    assert!(result.quorum_met);
    assert_eq!(result.valid_count, 10);
    assert_eq!(result.threshold, 1);
}

#[test]
fn enrichment_quorum_threshold_equals_count() {
    let obj = test_obj();
    let preimage = obj.preimage_bytes();
    let (sk1, vk1) = make_sig_pair(1);
    let (sk2, vk2) = make_sig_pair(2);
    let (sk3, vk3) = make_sig_pair(3);
    let entries = vec![
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
        SignerSignature::new(vk2.clone(), sign_with(&sk2, &obj)),
        SignerSignature::new(vk3.clone(), sign_with(&sk3, &obj)),
    ];
    let arr = SortedSignatureArray::from_unsorted(entries).unwrap();
    let result = arr
        .verify_quorum(3, &[vk1, vk2, vk3], |vk, sig| {
            verify_signature(vk, &preimage, sig)
        })
        .unwrap();
    assert!(result.quorum_met);
    assert_eq!(result.valid_count, 3);
}

#[test]
fn enrichment_quorum_fails_by_one() {
    let obj = test_obj();
    let preimage = obj.preimage_bytes();
    let (sk1, vk1) = make_sig_pair(1);
    let (_, vk2) = make_sig_pair(2);
    let entries = vec![
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
        SignerSignature::new(vk2.clone(), Signature::from_bytes([0xBB; SIGNATURE_LEN])),
    ];
    let arr = SortedSignatureArray::from_unsorted(entries).unwrap();
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
fn enrichment_quorum_with_mix_of_unauthorized_and_invalid() {
    let obj = test_obj();
    let preimage = obj.preimage_bytes();
    let (sk1, vk1) = make_sig_pair(1);
    let (_, vk2) = make_sig_pair(2); // will have bad sig
    let (sk3, vk3) = make_sig_pair(3); // unauthorized
    let entries = vec![
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
        SignerSignature::new(vk2.clone(), Signature::from_bytes([0xCC; SIGNATURE_LEN])),
        SignerSignature::new(vk3.clone(), sign_with(&sk3, &obj)),
    ];
    let arr = SortedSignatureArray::from_unsorted(entries).unwrap();
    // Only vk1 and vk2 are authorized, vk3 is not
    let result = arr
        .verify_quorum(1, &[vk1, vk2], |vk, sig| {
            verify_signature(vk, &preimage, sig)
        })
        .unwrap();
    assert!(result.quorum_met);
    assert_eq!(result.valid_count, 1);
    assert_eq!(result.invalid_count, 1);
    assert_eq!(result.unauthorized_count, 1);
}

// ===========================================================================
// Section 4: Context event tracking — combined operations
// ===========================================================================

#[test]
fn enrichment_context_multiple_creates_tracked() {
    let obj = test_obj();
    let mut ctx = MultiSigContext::new();

    for seed in [1u8, 2, 3] {
        let (sk, vk) = make_sig_pair(seed);
        let entries = vec![SignerSignature::new(vk, sign_with(&sk, &obj))];
        ctx.create_sorted(entries, &format!("t-{seed}")).unwrap();
    }
    let counts = ctx.event_counts();
    assert_eq!(counts.get("array_created"), Some(&3));
}

#[test]
fn enrichment_context_create_then_verify_tracks_both() {
    let obj = test_obj();
    let preimage = obj.preimage_bytes();
    let (sk1, vk1) = make_sig_pair(1);
    let (sk2, vk2) = make_sig_pair(2);

    let mut ctx = MultiSigContext::new();
    let entries = vec![
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
        SignerSignature::new(vk2.clone(), sign_with(&sk2, &obj)),
    ];
    let arr = ctx.create_sorted(entries, "create-trace").unwrap();
    ctx.verify_quorum(
        &arr,
        1,
        &[vk1, vk2],
        |vk, sig| verify_signature(vk, &preimage, sig),
        "verify-trace",
    )
    .unwrap();

    let counts = ctx.event_counts();
    assert_eq!(counts.get("array_created"), Some(&1));
    assert_eq!(counts.get("quorum_verified"), Some(&1));
}

#[test]
fn enrichment_context_drain_events_returns_correct_trace_ids() {
    let obj = test_obj();
    let (sk1, vk1) = make_sig_pair(1);

    let mut ctx = MultiSigContext::new();
    let entries = vec![SignerSignature::new(vk1, sign_with(&sk1, &obj))];
    ctx.create_sorted(entries, "my-trace-id").unwrap();

    let events = ctx.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].trace_id, "my-trace-id");
}

#[test]
fn enrichment_context_error_events_tracked() {
    let obj = test_obj();
    let (sk1, vk1) = make_sig_pair(1);

    let mut ctx = MultiSigContext::new();
    // Duplicate signer
    let entries = vec![
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
        SignerSignature::new(vk1, sign_with(&sk1, &obj)),
    ];
    let _ = ctx.create_sorted(entries, "dup-trace");
    let counts = ctx.event_counts();
    assert_eq!(counts.get("duplicate_signer"), Some(&1));
}

#[test]
fn enrichment_context_empty_array_emits_sorting_violation() {
    let mut ctx = MultiSigContext::new();
    let _ = ctx.create_sorted(vec![], "empty-trace");
    let counts = ctx.event_counts();
    assert_eq!(counts.get("sorting_violation"), Some(&1));
}

// ===========================================================================
// Section 5: is_sorted edge cases
// ===========================================================================

#[test]
fn enrichment_is_sorted_single_entry() {
    let obj = test_obj();
    let (sk1, vk1) = make_sig_pair(1);
    let entries = vec![SignerSignature::new(vk1, sign_with(&sk1, &obj))];
    assert!(is_sorted(&entries).is_ok());
}

#[test]
fn enrichment_is_sorted_three_entries_correct_order() {
    let obj = test_obj();
    let mut entries = Vec::new();
    for seed in [10u8, 20, 30] {
        let (sk, vk) = make_sig_pair(seed);
        entries.push(SignerSignature::new(vk, sign_with(&sk, &obj)));
    }
    entries.sort();
    assert!(is_sorted(&entries).is_ok());
}

#[test]
fn enrichment_is_sorted_detects_middle_unsorted() {
    let obj = test_obj();
    let (sk1, vk1) = make_sig_pair(10);
    let (sk2, vk2) = make_sig_pair(20);
    let (sk3, vk3) = make_sig_pair(30);
    let mut entries = vec![
        SignerSignature::new(vk1, sign_with(&sk1, &obj)),
        SignerSignature::new(vk2, sign_with(&sk2, &obj)),
        SignerSignature::new(vk3, sign_with(&sk3, &obj)),
    ];
    entries.sort();
    // Swap middle and last to create unsorted at position 2
    entries.swap(1, 2);
    let err = is_sorted(&entries).unwrap_err();
    assert!(matches!(err, MultiSigError::UnsortedSignatureArray { .. }));
}

// ===========================================================================
// Section 6: Serde roundtrips after mutations
// ===========================================================================

#[test]
fn enrichment_sorted_array_serde_after_insert() {
    let obj = test_obj();
    let (sk1, vk1) = make_sig_pair(1);
    let (sk2, vk2) = make_sig_pair(2);
    let (sk3, vk3) = make_sig_pair(3);

    let entries = vec![
        SignerSignature::new(vk1, sign_with(&sk1, &obj)),
        SignerSignature::new(vk2, sign_with(&sk2, &obj)),
    ];
    let mut arr = SortedSignatureArray::from_unsorted(entries).unwrap();
    arr.insert(SignerSignature::new(vk3, sign_with(&sk3, &obj)))
        .unwrap();

    let json = serde_json::to_string(&arr).unwrap();
    let back: SortedSignatureArray = serde_json::from_str(&json).unwrap();
    assert_eq!(arr, back);
    assert_eq!(back.len(), 3);
}

#[test]
fn enrichment_quorum_result_serde_with_invalid_signers() {
    let (_, vk1) = make_sig_pair(1);
    let (_, vk2) = make_sig_pair(2);
    let result = QuorumResult {
        quorum_met: false,
        valid_count: 0,
        invalid_count: 2,
        unauthorized_count: 0,
        total: 2,
        threshold: 2,
        invalid_signers: vec![
            (vk1.clone(), "bad sig 1".to_string()),
            (vk2.clone(), "bad sig 2".to_string()),
        ],
        unauthorized_signers: vec![],
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: QuorumResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ===========================================================================
// Section 7: Determinism under permutations
// ===========================================================================

#[test]
fn enrichment_from_unsorted_same_result_regardless_of_input_order() {
    let obj = test_obj();
    let (sk1, vk1) = make_sig_pair(10);
    let (sk2, vk2) = make_sig_pair(20);
    let (sk3, vk3) = make_sig_pair(30);

    let order1 = vec![
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
        SignerSignature::new(vk2.clone(), sign_with(&sk2, &obj)),
        SignerSignature::new(vk3.clone(), sign_with(&sk3, &obj)),
    ];
    let order2 = vec![
        SignerSignature::new(vk3.clone(), sign_with(&sk3, &obj)),
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
        SignerSignature::new(vk2.clone(), sign_with(&sk2, &obj)),
    ];
    let order3 = vec![
        SignerSignature::new(vk2.clone(), sign_with(&sk2, &obj)),
        SignerSignature::new(vk3.clone(), sign_with(&sk3, &obj)),
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
    ];

    let arr1 = SortedSignatureArray::from_unsorted(order1).unwrap();
    let arr2 = SortedSignatureArray::from_unsorted(order2).unwrap();
    let arr3 = SortedSignatureArray::from_unsorted(order3).unwrap();

    assert_eq!(arr1, arr2);
    assert_eq!(arr2, arr3);
}

#[test]
fn enrichment_quorum_deterministic_same_inputs() {
    let obj = test_obj();
    let preimage = obj.preimage_bytes();
    let (sk1, vk1) = make_sig_pair(1);
    let (sk2, vk2) = make_sig_pair(2);

    let entries = vec![
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
        SignerSignature::new(vk2.clone(), sign_with(&sk2, &obj)),
    ];
    let arr = SortedSignatureArray::from_unsorted(entries).unwrap();
    let authorized = vec![vk1.clone(), vk2.clone()];

    let r1 = arr
        .verify_quorum(2, &authorized, |vk, sig| {
            verify_signature(vk, &preimage, sig)
        })
        .unwrap();
    let r2 = arr
        .verify_quorum(2, &authorized, |vk, sig| {
            verify_signature(vk, &preimage, sig)
        })
        .unwrap();
    assert_eq!(r1, r2);
}

// ===========================================================================
// Section 8: Error Display correctness
// ===========================================================================

#[test]
fn enrichment_all_error_variants_display_nonempty() {
    let errors: Vec<MultiSigError> = vec![
        MultiSigError::EmptyArray,
        MultiSigError::ZeroQuorumThreshold,
        MultiSigError::UnsortedSignatureArray {
            position: 5,
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
            detail: "verification failed".to_string(),
        },
    ];
    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.is_empty(), "empty display for {:?}", err);
    }
}

#[test]
fn enrichment_quorum_result_display_format_values() {
    let result = QuorumResult {
        quorum_met: true,
        valid_count: 5,
        invalid_count: 2,
        unauthorized_count: 1,
        total: 8,
        threshold: 4,
        invalid_signers: vec![],
        unauthorized_signers: vec![],
    };
    let msg = result.to_string();
    assert!(msg.contains("5/8"));
    assert!(msg.contains("threshold 4"));
    assert!(msg.contains("2 invalid"));
    assert!(msg.contains("1 unauthorized"));
}

// ===========================================================================
// Section 9: MultiSigEvent type Display
// ===========================================================================

#[test]
fn enrichment_all_event_types_display_nonempty() {
    let events = vec![
        MultiSigEventType::ArrayCreated { signer_count: 10 },
        MultiSigEventType::SignatureInserted {
            signer_hex: "abcdef".to_string(),
        },
        MultiSigEventType::QuorumVerified {
            valid: 3,
            threshold: 2,
            total: 5,
        },
        MultiSigEventType::QuorumFailed {
            valid: 1,
            threshold: 3,
            total: 5,
        },
        MultiSigEventType::SortingViolation {
            detail: "wrong order".to_string(),
        },
        MultiSigEventType::DuplicateSigner {
            key_hex: "ff00".to_string(),
        },
    ];
    for evt in &events {
        let msg = evt.to_string();
        assert!(!msg.is_empty(), "empty display for {:?}", evt);
    }
}

// ===========================================================================
// Section 10: End-to-end with context and quorum
// ===========================================================================

#[test]
fn enrichment_e2e_create_insert_verify() {
    let obj = test_obj();
    let preimage = obj.preimage_bytes();
    let (sk1, vk1) = make_sig_pair(1);
    let (sk2, vk2) = make_sig_pair(2);
    let (sk3, vk3) = make_sig_pair(3);

    let mut ctx = MultiSigContext::new();
    let entries = vec![
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
        SignerSignature::new(vk2.clone(), sign_with(&sk2, &obj)),
    ];
    let mut arr = ctx.create_sorted(entries, "e2e-create").unwrap();
    arr.insert(SignerSignature::new(vk3.clone(), sign_with(&sk3, &obj)))
        .unwrap();

    let authorized = vec![vk1, vk2, vk3];
    let result = ctx
        .verify_quorum(
            &arr,
            2,
            &authorized,
            |vk, sig| verify_signature(vk, &preimage, sig),
            "e2e-verify",
        )
        .unwrap();
    assert!(result.quorum_met);
    assert_eq!(result.valid_count, 3);
    assert_eq!(result.threshold, 2);

    let counts = ctx.event_counts();
    assert_eq!(counts.get("array_created"), Some(&1));
    assert_eq!(counts.get("quorum_verified"), Some(&1));
}

#[test]
fn enrichment_e2e_multiple_failures_then_success() {
    let obj = test_obj();
    let preimage = obj.preimage_bytes();
    let (sk1, vk1) = make_sig_pair(1);
    let (sk2, vk2) = make_sig_pair(2);

    let mut ctx = MultiSigContext::new();

    // First attempt: empty array fails
    let _ = ctx.create_sorted(vec![], "fail-empty");

    // Second attempt: duplicate fails
    let dup_entries = vec![
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
    ];
    let _ = ctx.create_sorted(dup_entries, "fail-dup");

    // Third attempt: succeeds
    let good_entries = vec![
        SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
        SignerSignature::new(vk2.clone(), sign_with(&sk2, &obj)),
    ];
    let arr = ctx.create_sorted(good_entries, "success").unwrap();

    let result = ctx
        .verify_quorum(
            &arr,
            1,
            &[vk1, vk2],
            |vk, sig| verify_signature(vk, &preimage, sig),
            "verify-success",
        )
        .unwrap();
    assert!(result.quorum_met);

    let counts = ctx.event_counts();
    assert_eq!(counts.get("sorting_violation"), Some(&1));
    assert_eq!(counts.get("duplicate_signer"), Some(&1));
    assert_eq!(counts.get("array_created"), Some(&1));
    assert_eq!(counts.get("quorum_verified"), Some(&1));
}

// ===========================================================================
// Section 11: Additional serde and Display coverage
// ===========================================================================

#[test]
fn enrichment_signer_signature_serde_roundtrip() {
    let obj = test_obj();
    let (sk, vk) = make_sig_pair(42);
    let ss = SignerSignature::new(vk, sign_with(&sk, &obj));
    let json = serde_json::to_string(&ss).unwrap();
    let back: SignerSignature = serde_json::from_str(&json).unwrap();
    assert_eq!(ss, back);
}

#[test]
fn enrichment_multisig_error_serde_all_variants() {
    let variants = vec![
        MultiSigError::EmptyArray,
        MultiSigError::ZeroQuorumThreshold,
        MultiSigError::UnsortedSignatureArray {
            position: 2,
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
            detail: "bad".to_string(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: MultiSigError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_multisig_event_serde_roundtrip() {
    let event = MultiSigEvent {
        event_type: MultiSigEventType::QuorumVerified {
            valid: 2,
            threshold: 2,
            total: 3,
        },
        trace_id: "t-serde".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: MultiSigEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn enrichment_multisig_error_implements_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(MultiSigError::EmptyArray);
    assert!(!err.to_string().is_empty());
    assert!(std::error::Error::source(err.as_ref()).is_none());
}

#[test]
fn enrichment_signer_signature_ordering_by_key_only() {
    let (_, vk) = make_sig_pair(1);
    let a = SignerSignature::new(vk.clone(), Signature::from_bytes([0x00; SIGNATURE_LEN]));
    let b = SignerSignature::new(vk, Signature::from_bytes([0xFF; SIGNATURE_LEN]));
    assert_eq!(a.cmp(&b), std::cmp::Ordering::Equal);
}

#[test]
fn enrichment_context_default_has_empty_event_counts() {
    let ctx = MultiSigContext::default();
    assert!(ctx.event_counts().is_empty());
}
