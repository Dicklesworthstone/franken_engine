//! Integration edge-case tests for `revocation_chain` module.
//!
//! Covers: RevocationTargetType, RevocationReason, ChainError, ChainEventType,
//! ChainEvent, Revocation, RevocationEvent, RevocationHead, RevocationChain
//! (append, verify_chain, verify_append, verify_head_signature, rebuild,
//! is_revoked, lookup, audited lookup, audit events, drain, event_counts),
//! schema helpers, and cross-cutting integration scenarios.

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
use frankenengine_engine::engine_object_id::{self, EngineObjectId, ObjectDomain};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::revocation_chain::{
    ChainError, ChainEvent, ChainEventType, Revocation, RevocationChain, RevocationEvent,
    RevocationHead, RevocationReason, RevocationTargetType, revocation_event_schema,
    revocation_event_schema_id, revocation_head_schema, revocation_head_schema_id,
    revocation_schema, revocation_schema_id,
};
use frankenengine_engine::signature_preimage::{
    SIGNATURE_SENTINEL, Signature, SignaturePreimage, SigningKey, VerificationKey, sign_preimage,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TEST_ZONE: &str = "test-zone";

fn head_signing_key() -> SigningKey {
    SigningKey::from_bytes([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ])
}

fn revocation_signing_key() -> SigningKey {
    SigningKey::from_bytes([
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE,
        0xBF, 0xC0,
    ])
}

fn make_revocation(
    target_type: RevocationTargetType,
    reason: RevocationReason,
    target_bytes: [u8; 32],
) -> Revocation {
    let rsk = revocation_signing_key();
    let principal = PrincipalId::from_verification_key(&rsk.verification_key());
    let target_id = EngineObjectId(target_bytes);
    let revocation_id = engine_object_id::derive_id(
        ObjectDomain::Revocation,
        TEST_ZONE,
        &revocation_schema_id(),
        target_bytes.as_slice(),
    )
    .unwrap();

    let mut rev = Revocation {
        revocation_id,
        target_type,
        target_id,
        reason,
        issued_by: principal,
        issued_at: DeterministicTimestamp(1000),
        zone: TEST_ZONE.to_string(),
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };
    let preimage = rev.preimage_bytes();
    rev.signature = sign_preimage(&rsk, &preimage).unwrap();
    rev
}

fn make_revocation_in_zone(
    target_type: RevocationTargetType,
    reason: RevocationReason,
    target_bytes: [u8; 32],
    zone: &str,
) -> Revocation {
    let rsk = revocation_signing_key();
    let principal = PrincipalId::from_verification_key(&rsk.verification_key());
    let target_id = EngineObjectId(target_bytes);
    let revocation_id = engine_object_id::derive_id(
        ObjectDomain::Revocation,
        zone,
        &revocation_schema_id(),
        target_bytes.as_slice(),
    )
    .unwrap();

    let mut rev = Revocation {
        revocation_id,
        target_type,
        target_id,
        reason,
        issued_by: principal,
        issued_at: DeterministicTimestamp(2000),
        zone: zone.to_string(),
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };
    let preimage = rev.preimage_bytes();
    rev.signature = sign_preimage(&rsk, &preimage).unwrap();
    rev
}

// ===========================================================================
// Schema helpers
// ===========================================================================

#[test]
fn schema_functions_return_stable_values() {
    let s1 = revocation_schema();
    let s2 = revocation_schema();
    assert_eq!(s1.as_bytes(), s2.as_bytes());

    let s1 = revocation_event_schema();
    let s2 = revocation_event_schema();
    assert_eq!(s1.as_bytes(), s2.as_bytes());

    let s1 = revocation_head_schema();
    let s2 = revocation_head_schema();
    assert_eq!(s1.as_bytes(), s2.as_bytes());
}

#[test]
fn schema_id_functions_return_stable_values() {
    let id1 = revocation_schema_id();
    let id2 = revocation_schema_id();
    assert_eq!(id1, id2);

    let id1 = revocation_event_schema_id();
    let id2 = revocation_event_schema_id();
    assert_eq!(id1, id2);

    let id1 = revocation_head_schema_id();
    let id2 = revocation_head_schema_id();
    assert_eq!(id1, id2);
}

#[test]
fn schema_ids_are_distinct() {
    let r = revocation_schema_id();
    let e = revocation_event_schema_id();
    let h = revocation_head_schema_id();
    assert_ne!(r, e);
    assert_ne!(r, h);
    assert_ne!(e, h);
}

// ===========================================================================
// RevocationTargetType
// ===========================================================================

#[test]
fn revocation_target_type_serde_all() {
    for t in [
        RevocationTargetType::Key,
        RevocationTargetType::Token,
        RevocationTargetType::Attestation,
        RevocationTargetType::Extension,
        RevocationTargetType::Checkpoint,
    ] {
        let json = serde_json::to_string(&t).unwrap();
        let back: RevocationTargetType = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }
}

#[test]
fn revocation_target_type_display_all() {
    assert_eq!(RevocationTargetType::Key.to_string(), "key");
    assert_eq!(RevocationTargetType::Token.to_string(), "token");
    assert_eq!(RevocationTargetType::Attestation.to_string(), "attestation");
    assert_eq!(RevocationTargetType::Extension.to_string(), "extension");
    assert_eq!(RevocationTargetType::Checkpoint.to_string(), "checkpoint");
}

#[test]
fn revocation_target_type_ordering() {
    assert!(RevocationTargetType::Key < RevocationTargetType::Token);
    assert!(RevocationTargetType::Token < RevocationTargetType::Attestation);
}

#[test]
fn revocation_target_type_hash() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(RevocationTargetType::Key);
    set.insert(RevocationTargetType::Key);
    assert_eq!(set.len(), 1);
    set.insert(RevocationTargetType::Token);
    assert_eq!(set.len(), 2);
}

// ===========================================================================
// RevocationReason
// ===========================================================================

#[test]
fn revocation_reason_serde_all() {
    for r in [
        RevocationReason::Compromised,
        RevocationReason::Expired,
        RevocationReason::Superseded,
        RevocationReason::PolicyViolation,
        RevocationReason::Administrative,
    ] {
        let json = serde_json::to_string(&r).unwrap();
        let back: RevocationReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}

#[test]
fn revocation_reason_display_all() {
    assert_eq!(RevocationReason::Compromised.to_string(), "compromised");
    assert_eq!(RevocationReason::Expired.to_string(), "expired");
    assert_eq!(RevocationReason::Superseded.to_string(), "superseded");
    assert_eq!(
        RevocationReason::PolicyViolation.to_string(),
        "policy_violation"
    );
    assert_eq!(
        RevocationReason::Administrative.to_string(),
        "administrative"
    );
}

#[test]
fn revocation_reason_ordering() {
    assert!(RevocationReason::Compromised < RevocationReason::Expired);
    assert!(RevocationReason::Expired < RevocationReason::Superseded);
}

// ===========================================================================
// ChainError
// ===========================================================================

#[test]
fn chain_error_serde_all_variants() {
    let errors = [
        ChainError::HeadSequenceRegression {
            current_seq: 5,
            attempted_seq: 3,
        },
        ChainError::HashLinkMismatch {
            event_seq: 2,
            expected_prev: None,
            actual_prev: Some(EngineObjectId([0xAA; 32])),
        },
        ChainError::SequenceDiscontinuity {
            expected_seq: 3,
            actual_seq: 5,
        },
        ChainError::InvalidGenesis {
            detail: "bad genesis".into(),
        },
        ChainError::ChainIntegrity {
            detail: "hash mismatch".into(),
        },
        ChainError::SignatureInvalid {
            detail: "wrong key".into(),
        },
        ChainError::DuplicateTarget {
            target_id: EngineObjectId([0xBB; 32]),
        },
        ChainError::MutationRejected { event_seq: 7 },
        ChainError::EmptyChain,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ChainError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn chain_error_display_all_variants() {
    let err = ChainError::HeadSequenceRegression {
        current_seq: 5,
        attempted_seq: 3,
    };
    let s = err.to_string();
    assert!(s.contains("5") && s.contains("3"), "{s}");

    let err = ChainError::HashLinkMismatch {
        event_seq: 2,
        expected_prev: None,
        actual_prev: None,
    };
    let s = err.to_string();
    assert!(s.contains("2"), "{s}");

    let err = ChainError::SequenceDiscontinuity {
        expected_seq: 3,
        actual_seq: 5,
    };
    let s = err.to_string();
    assert!(s.contains("3") && s.contains("5"), "{s}");

    let s = ChainError::InvalidGenesis {
        detail: "bad".into(),
    }
    .to_string();
    assert!(s.contains("bad"), "{s}");

    let s = ChainError::ChainIntegrity {
        detail: "corrupt".into(),
    }
    .to_string();
    assert!(s.contains("corrupt"), "{s}");

    let s = ChainError::SignatureInvalid {
        detail: "wrong".into(),
    }
    .to_string();
    assert!(s.contains("wrong"), "{s}");

    let s = ChainError::DuplicateTarget {
        target_id: EngineObjectId([0; 32]),
    }
    .to_string();
    assert!(s.contains("duplicate"), "{s}");

    let s = ChainError::MutationRejected { event_seq: 7 }.to_string();
    assert!(s.contains("7"), "{s}");

    let s = ChainError::EmptyChain.to_string();
    assert!(s.contains("empty"), "{s}");
}

#[test]
fn chain_error_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(ChainError::EmptyChain);
    assert!(!err.to_string().is_empty());
}

// ===========================================================================
// ChainEventType serde
// ===========================================================================

#[test]
fn chain_event_type_serde_all_variants() {
    let types = [
        ChainEventType::RevocationAppended {
            event_seq: 0,
            target_id: EngineObjectId([1; 32]),
            target_type: RevocationTargetType::Key,
        },
        ChainEventType::HeadAdvanced {
            old_seq: 0,
            new_seq: 1,
        },
        ChainEventType::ChainVerified { chain_length: 5 },
        ChainEventType::RevocationLookup {
            target_id: EngineObjectId([2; 32]),
            is_revoked: true,
        },
        ChainEventType::AppendRejected {
            reason: "dup".into(),
        },
    ];
    for t in &types {
        let json = serde_json::to_string(t).unwrap();
        let back: ChainEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, back);
    }
}

#[test]
fn chain_event_serde() {
    let evt = ChainEvent {
        event_type: ChainEventType::ChainVerified { chain_length: 10 },
        zone: "zone-a".into(),
        trace_id: "trace-1".into(),
    };
    let json = serde_json::to_string(&evt).unwrap();
    let back: ChainEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(evt, back);
}

// ===========================================================================
// Revocation serde
// ===========================================================================

#[test]
fn revocation_serde_round_trip() {
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    let json = serde_json::to_string(&rev).unwrap();
    let back: Revocation = serde_json::from_str(&json).unwrap();
    assert_eq!(rev, back);
}

// ===========================================================================
// RevocationEvent
// ===========================================================================

#[test]
fn revocation_event_serde_round_trip() {
    let rev = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Expired,
        [5; 32],
    );
    let event = RevocationEvent {
        event_id: EngineObjectId([0xAA; 32]),
        revocation: rev,
        prev_event: None,
        event_seq: 0,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: RevocationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn revocation_event_canonical_bytes_deterministic() {
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [10; 32],
    );
    let event = RevocationEvent {
        event_id: EngineObjectId([0xBB; 32]),
        revocation: rev,
        prev_event: None,
        event_seq: 0,
    };
    let bytes1 = event.canonical_bytes();
    let bytes2 = event.canonical_bytes();
    assert_eq!(bytes1, bytes2);
}

#[test]
fn revocation_event_content_hash_deterministic() {
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [11; 32],
    );
    let event = RevocationEvent {
        event_id: EngineObjectId([0xCC; 32]),
        revocation: rev,
        prev_event: None,
        event_seq: 0,
    };
    let h1 = event.content_hash();
    let h2 = event.content_hash();
    assert_eq!(h1, h2);
}

#[test]
fn revocation_event_content_hash_changes_with_seq() {
    let rev1 = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [12; 32],
    );
    let rev2 = rev1.clone();
    let e1 = RevocationEvent {
        event_id: EngineObjectId([0xDD; 32]),
        revocation: rev1,
        prev_event: None,
        event_seq: 0,
    };
    let e2 = RevocationEvent {
        event_id: EngineObjectId([0xDD; 32]),
        revocation: rev2,
        prev_event: None,
        event_seq: 1,
    };
    assert_ne!(e1.content_hash(), e2.content_hash());
}

// ===========================================================================
// RevocationHead serde
// ===========================================================================

#[test]
fn revocation_head_serde_round_trip() {
    let head = RevocationHead {
        head_id: EngineObjectId([0x11; 32]),
        latest_event: EngineObjectId([0x22; 32]),
        head_seq: 5,
        chain_hash: ContentHash::compute(b"test"),
        zone: TEST_ZONE.into(),
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };
    let json = serde_json::to_string(&head).unwrap();
    let back: RevocationHead = serde_json::from_str(&json).unwrap();
    assert_eq!(head, back);
}

// ===========================================================================
// RevocationChain — empty chain
// ===========================================================================

#[test]
fn new_chain_is_empty() {
    let chain = RevocationChain::new(TEST_ZONE);
    assert!(chain.is_empty());
    assert_eq!(chain.len(), 0);
    assert!(chain.head().is_none());
    assert_eq!(chain.head_seq(), None);
    assert_eq!(chain.zone(), TEST_ZONE);
}

#[test]
fn empty_chain_verify_succeeds() {
    let chain = RevocationChain::new(TEST_ZONE);
    assert!(chain.verify_chain("t").is_ok());
}

#[test]
fn empty_chain_verify_head_signature_fails() {
    let chain = RevocationChain::new(TEST_ZONE);
    let vk = head_signing_key().verification_key();
    let err = chain.verify_head_signature(&vk).unwrap_err();
    assert!(matches!(err, ChainError::EmptyChain));
}

#[test]
fn empty_chain_is_revoked_false() {
    let chain = RevocationChain::new(TEST_ZONE);
    assert!(!chain.is_revoked(&EngineObjectId([99; 32])));
}

#[test]
fn empty_chain_lookup_revocation_none() {
    let chain = RevocationChain::new(TEST_ZONE);
    assert!(chain.lookup_revocation(&EngineObjectId([99; 32])).is_none());
}

#[test]
fn empty_chain_get_event_none() {
    let chain = RevocationChain::new(TEST_ZONE);
    assert!(chain.get_event(0).is_none());
}

#[test]
fn empty_chain_events_empty() {
    let chain = RevocationChain::new(TEST_ZONE);
    assert!(chain.events().is_empty());
}

// ===========================================================================
// RevocationChain — genesis append
// ===========================================================================

#[test]
fn genesis_append_creates_proper_event() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    let seq = chain.append(rev, &sk, "t-gen").unwrap();
    assert_eq!(seq, 0);
    assert_eq!(chain.len(), 1);
    assert!(!chain.is_empty());
    assert_eq!(chain.head_seq(), Some(0));

    let event = chain.get_event(0).unwrap();
    assert!(event.prev_event.is_none());
    assert_eq!(event.event_seq, 0);
}

#[test]
fn genesis_append_sets_head() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev, &sk, "t").unwrap();
    let head = chain.head().unwrap();
    assert_eq!(head.head_seq, 0);
    assert_eq!(head.zone, TEST_ZONE);
}

// ===========================================================================
// RevocationChain — multiple appends & hash linking
// ===========================================================================

#[test]
fn multiple_appends_with_hash_linking() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();

    for i in 0..5u8 {
        let rev = make_revocation(
            RevocationTargetType::Token,
            RevocationReason::Expired,
            [i + 10; 32],
        );
        let seq = chain.append(rev, &sk, &format!("t-{i}")).unwrap();
        assert_eq!(seq, i as u64);
    }

    assert_eq!(chain.len(), 5);
    assert_eq!(chain.head_seq(), Some(4));

    // Verify hash linking
    for i in 1..5u64 {
        let event = chain.get_event(i).unwrap();
        let prev = chain.get_event(i - 1).unwrap();
        assert_eq!(event.prev_event, Some(prev.event_id.clone()));
    }
}

#[test]
fn chain_hash_changes_after_each_append() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let initial_hash = chain.chain_hash().clone();

    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev, &sk, "t").unwrap();
    let hash_after_1 = chain.chain_hash().clone();
    assert_ne!(initial_hash, hash_after_1);

    let rev = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Expired,
        [2; 32],
    );
    chain.append(rev, &sk, "t").unwrap();
    let hash_after_2 = chain.chain_hash().clone();
    assert_ne!(hash_after_1, hash_after_2);
}

#[test]
fn head_seq_increases_monotonically() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let mut prev_seq = None;
    for i in 0..5u8 {
        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [i + 50; 32],
        );
        chain.append(rev, &sk, &format!("t-{i}")).unwrap();
        let current = chain.head_seq().unwrap();
        if let Some(prev) = prev_seq {
            assert!(current > prev);
        }
        prev_seq = Some(current);
    }
}

// ===========================================================================
// Revocation lookup
// ===========================================================================

#[test]
fn is_revoked_true_after_append() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let target = EngineObjectId([42; 32]);
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [42; 32],
    );
    chain.append(rev, &sk, "t").unwrap();
    assert!(chain.is_revoked(&target));
}

#[test]
fn is_revoked_false_for_nonexistent() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev, &sk, "t").unwrap();
    assert!(!chain.is_revoked(&EngineObjectId([99; 32])));
}

#[test]
fn lookup_revocation_returns_details() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let rev = make_revocation(
        RevocationTargetType::Extension,
        RevocationReason::PolicyViolation,
        [55; 32],
    );
    chain.append(rev, &sk, "t").unwrap();

    let found = chain.lookup_revocation(&EngineObjectId([55; 32])).unwrap();
    assert_eq!(found.target_type, RevocationTargetType::Extension);
    assert_eq!(found.reason, RevocationReason::PolicyViolation);
}

#[test]
fn lookup_revocation_none_for_nonexistent() {
    let chain = RevocationChain::new(TEST_ZONE);
    assert!(chain.lookup_revocation(&EngineObjectId([99; 32])).is_none());
}

#[test]
fn is_revoked_audited_emits_event() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let target = EngineObjectId([99; 32]);
    let result = chain.is_revoked_audited(&target, "t-look");
    assert!(!result);
    let counts = chain.event_counts();
    assert_eq!(counts.get("revocation_lookup"), Some(&1));
}

#[test]
fn is_revoked_audited_true_after_append() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [77; 32],
    );
    chain.append(rev, &sk, "t").unwrap();
    chain.drain_events();

    let result = chain.is_revoked_audited(&EngineObjectId([77; 32]), "t-look");
    assert!(result);
    let events = chain.drain_events();
    assert_eq!(events.len(), 1);
    match &events[0].event_type {
        ChainEventType::RevocationLookup {
            target_id,
            is_revoked,
        } => {
            assert_eq!(*target_id, EngineObjectId([77; 32]));
            assert!(*is_revoked);
        }
        other => panic!("expected RevocationLookup, got {other:?}"),
    }
}

// ===========================================================================
// Duplicate target rejection
// ===========================================================================

#[test]
fn duplicate_target_rejected() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();

    let rev1 = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev1, &sk, "t-1").unwrap();

    let rev2 = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Administrative,
        [1; 32],
    );
    let err = chain.append(rev2, &sk, "t-2").unwrap_err();
    assert!(matches!(err, ChainError::DuplicateTarget { .. }));
    assert_eq!(chain.len(), 1); // chain unchanged
}

#[test]
fn duplicate_target_emits_reject_audit() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();

    let rev1 = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev1, &sk, "t-1").unwrap();
    chain.drain_events();

    let rev2 = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    let _ = chain.append(rev2, &sk, "t-2");
    let counts = chain.event_counts();
    assert_eq!(counts.get("append_rejected"), Some(&1));
}

// ===========================================================================
// Zone mismatch rejection
// ===========================================================================

#[test]
fn zone_mismatch_rejected() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let rev = make_revocation_in_zone(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
        "wrong-zone",
    );
    let err = chain.append(rev, &sk, "t").unwrap_err();
    assert!(matches!(err, ChainError::ChainIntegrity { .. }));
}

#[test]
fn zone_mismatch_emits_reject_audit() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let rev = make_revocation_in_zone(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
        "wrong-zone",
    );
    let _ = chain.append(rev, &sk, "t");
    let counts = chain.event_counts();
    assert_eq!(counts.get("append_rejected"), Some(&1));
}

// ===========================================================================
// All target types and reasons
// ===========================================================================

#[test]
fn all_target_types_can_be_revoked() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let types = [
        RevocationTargetType::Key,
        RevocationTargetType::Token,
        RevocationTargetType::Attestation,
        RevocationTargetType::Extension,
        RevocationTargetType::Checkpoint,
    ];
    for (i, t) in types.iter().enumerate() {
        let rev = make_revocation(*t, RevocationReason::Administrative, [(i as u8) + 30; 32]);
        chain.append(rev, &sk, &format!("t-{i}")).unwrap();
    }
    assert_eq!(chain.len(), 5);
    for (i, _) in types.iter().enumerate() {
        assert!(chain.is_revoked(&EngineObjectId([(i as u8) + 30; 32])));
    }
}

#[test]
fn all_revocation_reasons_accepted() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let reasons = [
        RevocationReason::Compromised,
        RevocationReason::Expired,
        RevocationReason::Superseded,
        RevocationReason::PolicyViolation,
        RevocationReason::Administrative,
    ];
    for (i, r) in reasons.iter().enumerate() {
        let rev = make_revocation(RevocationTargetType::Key, *r, [(i as u8) + 60; 32]);
        chain.append(rev, &sk, &format!("t-{i}")).unwrap();
    }
    assert_eq!(chain.len(), 5);
}

// ===========================================================================
// Chain verification
// ===========================================================================

#[test]
fn verify_chain_after_appends() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    for i in 0..10u8 {
        let rev = make_revocation(
            RevocationTargetType::Token,
            RevocationReason::Superseded,
            [i + 100; 32],
        );
        chain.append(rev, &sk, &format!("t-{i}")).unwrap();
    }
    assert!(chain.verify_chain("t-verify").is_ok());
}

#[test]
fn verify_chain_mut_emits_audit_event() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev, &sk, "t").unwrap();
    chain.drain_events();

    chain.verify_chain_mut("t-vcm").unwrap();
    let counts = chain.event_counts();
    assert_eq!(counts.get("chain_verified"), Some(&1));
}

// ===========================================================================
// Head signature verification
// ===========================================================================

#[test]
fn verify_head_signature_succeeds() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let vk = sk.verification_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev, &sk, "t").unwrap();
    assert!(chain.verify_head_signature(&vk).is_ok());
}

#[test]
fn verify_head_signature_wrong_key() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev, &sk, "t").unwrap();

    let wrong_vk = VerificationKey::from_bytes([0xFF; 32]);
    let err = chain.verify_head_signature(&wrong_vk).unwrap_err();
    assert!(matches!(err, ChainError::SignatureInvalid { .. }));
}

// ===========================================================================
// Incremental verify_append
// ===========================================================================

#[test]
fn verify_append_accepts_valid_next_event() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev, &sk, "t").unwrap();

    let rev2 = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Expired,
        [2; 32],
    );
    let prev_id = chain.events().last().unwrap().event_id.clone();
    let next_event = RevocationEvent {
        event_id: EngineObjectId([0xAA; 32]),
        revocation: rev2,
        prev_event: Some(prev_id),
        event_seq: 1,
    };
    assert!(chain.verify_append(&next_event).is_ok());
}

#[test]
fn verify_append_rejects_wrong_seq() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev, &sk, "t").unwrap();

    let rev2 = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Expired,
        [2; 32],
    );
    let next_event = RevocationEvent {
        event_id: EngineObjectId([0xBB; 32]),
        revocation: rev2,
        prev_event: Some(chain.events().last().unwrap().event_id.clone()),
        event_seq: 99,
    };
    let err = chain.verify_append(&next_event).unwrap_err();
    assert!(matches!(err, ChainError::SequenceDiscontinuity { .. }));
}

#[test]
fn verify_append_rejects_wrong_prev_link() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev, &sk, "t").unwrap();

    let rev2 = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Expired,
        [2; 32],
    );
    let next_event = RevocationEvent {
        event_id: EngineObjectId([0xCC; 32]),
        revocation: rev2,
        prev_event: Some(EngineObjectId([0xFF; 32])),
        event_seq: 1,
    };
    let err = chain.verify_append(&next_event).unwrap_err();
    assert!(matches!(err, ChainError::HashLinkMismatch { .. }));
}

#[test]
fn verify_append_on_empty_chain_accepts_genesis() {
    let chain = RevocationChain::new(TEST_ZONE);
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    let genesis = RevocationEvent {
        event_id: EngineObjectId([0xAA; 32]),
        revocation: rev,
        prev_event: None,
        event_seq: 0,
    };
    assert!(chain.verify_append(&genesis).is_ok());
}

#[test]
fn verify_append_rejects_genesis_with_prev_event() {
    let chain = RevocationChain::new(TEST_ZONE);
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    let bad_genesis = RevocationEvent {
        event_id: EngineObjectId([0xAA; 32]),
        revocation: rev,
        prev_event: Some(EngineObjectId([0xFF; 32])),
        event_seq: 0,
    };
    let err = chain.verify_append(&bad_genesis).unwrap_err();
    // Could be HashLinkMismatch (expected None got Some) or InvalidGenesis
    assert!(
        matches!(err, ChainError::HashLinkMismatch { .. })
            || matches!(err, ChainError::InvalidGenesis { .. })
    );
}

// ===========================================================================
// Rebuild from events
// ===========================================================================

#[test]
fn rebuild_from_events_succeeds() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    for i in 0..5u8 {
        let rev = make_revocation(
            RevocationTargetType::Token,
            RevocationReason::Superseded,
            [i + 70; 32],
        );
        chain.append(rev, &sk, &format!("t-{i}")).unwrap();
    }

    let events = chain.events().to_vec();
    let head = chain.head().cloned();
    let rebuilt = RevocationChain::rebuild_from_events(TEST_ZONE, events, head).unwrap();
    assert_eq!(rebuilt.len(), 5);
    assert_eq!(rebuilt.head_seq(), Some(4));
    assert_eq!(rebuilt.chain_hash(), chain.chain_hash());
    for i in 0..5u8 {
        assert!(rebuilt.is_revoked(&EngineObjectId([i + 70; 32])));
    }
}

#[test]
fn rebuild_from_empty_events_succeeds() {
    let rebuilt = RevocationChain::rebuild_from_events(TEST_ZONE, vec![], None).unwrap();
    assert!(rebuilt.is_empty());
    assert!(rebuilt.head().is_none());
}

#[test]
fn rebuild_from_empty_events_with_head_fails() {
    let head = RevocationHead {
        head_id: EngineObjectId([0x11; 32]),
        latest_event: EngineObjectId([0x22; 32]),
        head_seq: 0,
        chain_hash: ContentHash::compute(b"fake"),
        zone: TEST_ZONE.into(),
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };
    let err = RevocationChain::rebuild_from_events(TEST_ZONE, vec![], Some(head)).unwrap_err();
    assert!(matches!(err, ChainError::ChainIntegrity { .. }));
}

#[test]
fn rebuild_detects_tampered_chain() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    for i in 0..3u8 {
        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [i + 80; 32],
        );
        chain.append(rev, &sk, &format!("t-{i}")).unwrap();
    }

    let mut events = chain.events().to_vec();
    events[1].prev_event = Some(EngineObjectId([0xFF; 32]));
    let err = RevocationChain::rebuild_from_events(TEST_ZONE, events, None).unwrap_err();
    assert!(matches!(err, ChainError::HashLinkMismatch { .. }));
}

#[test]
fn rebuild_detects_head_seq_mismatch() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [90; 32],
    );
    chain.append(rev, &sk, "t").unwrap();

    let events = chain.events().to_vec();
    let mut head = chain.head().cloned().unwrap();
    head.head_seq = 99;
    let err = RevocationChain::rebuild_from_events(TEST_ZONE, events, Some(head)).unwrap_err();
    assert!(matches!(err, ChainError::ChainIntegrity { .. }));
}

#[test]
fn rebuild_detects_head_chain_hash_mismatch() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [91; 32],
    );
    chain.append(rev, &sk, "t").unwrap();

    let events = chain.events().to_vec();
    let mut head = chain.head().cloned().unwrap();
    head.chain_hash = ContentHash::compute(b"tampered");
    let err = RevocationChain::rebuild_from_events(TEST_ZONE, events, Some(head)).unwrap_err();
    assert!(matches!(err, ChainError::ChainIntegrity { .. }));
}

#[test]
fn rebuild_detects_duplicate_target() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev, &sk, "t").unwrap();

    let mut events = chain.events().to_vec();
    // Create a second event with same target_id
    let mut dup = events[0].clone();
    dup.event_seq = 1;
    dup.prev_event = Some(events[0].event_id.clone());
    events.push(dup);

    let err = RevocationChain::rebuild_from_events(TEST_ZONE, events, None).unwrap_err();
    assert!(matches!(err, ChainError::DuplicateTarget { .. }));
}

// ===========================================================================
// Audit events
// ===========================================================================

#[test]
fn append_emits_revocation_appended_event() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev, &sk, "t-audit").unwrap();

    let events = chain.drain_events();
    assert!(events.iter().any(|e| matches!(
        &e.event_type,
        ChainEventType::RevocationAppended { event_seq: 0, .. }
    )));
    // Genesis (seq=0) should NOT emit HeadAdvanced
    assert!(
        !events
            .iter()
            .any(|e| matches!(e.event_type, ChainEventType::HeadAdvanced { .. }))
    );
}

#[test]
fn non_genesis_append_emits_head_advanced() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let rev1 = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev1, &sk, "t-1").unwrap();
    chain.drain_events();

    let rev2 = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Expired,
        [2; 32],
    );
    chain.append(rev2, &sk, "t-2").unwrap();
    let events = chain.drain_events();
    assert!(events.iter().any(|e| matches!(
        &e.event_type,
        ChainEventType::HeadAdvanced {
            old_seq: 0,
            new_seq: 1
        }
    )));
}

#[test]
fn audit_events_have_correct_zone_and_trace_id() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev, &sk, "trace-xyz").unwrap();

    let events = chain.drain_events();
    for evt in &events {
        assert_eq!(evt.zone, TEST_ZONE);
        assert_eq!(evt.trace_id, "trace-xyz");
    }
}

#[test]
fn drain_events_clears() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev, &sk, "t").unwrap();
    assert!(!chain.drain_events().is_empty());
    assert!(chain.drain_events().is_empty());
}

#[test]
fn event_counts_by_type() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();

    // Append two events (2 RevocationAppended + 1 HeadAdvanced)
    let rev1 = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev1, &sk, "t-1").unwrap();
    let rev2 = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Expired,
        [2; 32],
    );
    chain.append(rev2, &sk, "t-2").unwrap();

    // One audited lookup
    chain.is_revoked_audited(&EngineObjectId([99; 32]), "t-look");

    let counts = chain.event_counts();
    assert_eq!(counts.get("revocation_appended"), Some(&2));
    assert_eq!(counts.get("head_advanced"), Some(&1));
    assert_eq!(counts.get("revocation_lookup"), Some(&1));
}

// ===========================================================================
// Chain hash determinism
// ===========================================================================

#[test]
fn chain_hash_is_deterministic() {
    let build = || {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = head_signing_key();
        for i in 0..3u8 {
            let rev = make_revocation(
                RevocationTargetType::Key,
                RevocationReason::Compromised,
                [i + 150; 32],
            );
            chain.append(rev, &sk, &format!("t-{i}")).unwrap();
        }
        chain.chain_hash().clone()
    };
    assert_eq!(build(), build());
}

// ===========================================================================
// Large chain
// ===========================================================================

#[test]
fn large_chain_120_events_verifies() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    for i in 0..120u16 {
        let mut target = [0u8; 32];
        target[0] = (i & 0xFF) as u8;
        target[1] = (i >> 8) as u8;
        let rev = make_revocation(
            RevocationTargetType::Token,
            RevocationReason::Expired,
            target,
        );
        chain.append(rev, &sk, &format!("t-{i}")).unwrap();
    }
    assert_eq!(chain.len(), 120);
    assert!(chain.verify_chain("t-large").is_ok());

    // Spot checks
    assert!(chain.is_revoked(&EngineObjectId({
        let mut t = [0u8; 32];
        t[0] = 0;
        t
    })));
    assert!(chain.is_revoked(&EngineObjectId({
        let mut t = [0u8; 32];
        t[0] = 119;
        t
    })));
}

// ===========================================================================
// Cross-cutting integration
// ===========================================================================

#[test]
fn full_pipeline_append_verify_lookup_rebuild() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let vk = sk.verification_key();

    // Append several revocations
    for i in 0..5u8 {
        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [i; 32],
        );
        chain.append(rev, &sk, &format!("t-{i}")).unwrap();
    }

    // Verify chain
    assert!(chain.verify_chain("t-verify").is_ok());

    // Verify head signature
    assert!(chain.verify_head_signature(&vk).is_ok());

    // Lookup all
    for i in 0..5u8 {
        assert!(chain.is_revoked(&EngineObjectId([i; 32])));
    }

    // Rebuild from events
    let events = chain.events().to_vec();
    let head = chain.head().cloned();
    let rebuilt = RevocationChain::rebuild_from_events(TEST_ZONE, events, head).unwrap();
    assert_eq!(rebuilt.len(), chain.len());
    assert_eq!(rebuilt.chain_hash(), chain.chain_hash());
}

#[test]
fn different_targets_produce_different_chain_hashes() {
    let sk = head_signing_key();

    let mut chain_a = RevocationChain::new(TEST_ZONE);
    let rev_a = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain_a.append(rev_a, &sk, "t").unwrap();

    let mut chain_b = RevocationChain::new(TEST_ZONE);
    let rev_b = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [2; 32],
    );
    chain_b.append(rev_b, &sk, "t").unwrap();

    assert_ne!(chain_a.chain_hash(), chain_b.chain_hash());
}

#[test]
fn head_id_changes_with_each_append() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();

    let rev1 = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev1, &sk, "t-1").unwrap();
    let head_id_1 = chain.head().unwrap().head_id.clone();

    let rev2 = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Expired,
        [2; 32],
    );
    chain.append(rev2, &sk, "t-2").unwrap();
    let head_id_2 = chain.head().unwrap().head_id.clone();

    assert_ne!(head_id_1, head_id_2);
}

#[test]
fn rebuilt_chain_lookups_match_original() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();

    let targets: Vec<[u8; 32]> = (0..10u8).map(|i| [i + 20; 32]).collect();
    for t in &targets {
        let rev = make_revocation(
            RevocationTargetType::Extension,
            RevocationReason::Superseded,
            *t,
        );
        chain.append(rev, &sk, "t").unwrap();
    }

    let events = chain.events().to_vec();
    let head = chain.head().cloned();
    let rebuilt = RevocationChain::rebuild_from_events(TEST_ZONE, events, head).unwrap();

    for t in &targets {
        assert_eq!(
            chain.is_revoked(&EngineObjectId(*t)),
            rebuilt.is_revoked(&EngineObjectId(*t))
        );
        let orig = chain.lookup_revocation(&EngineObjectId(*t));
        let rebu = rebuilt.lookup_revocation(&EngineObjectId(*t));
        assert_eq!(orig.is_some(), rebu.is_some());
        if let (Some(o), Some(r)) = (orig, rebu) {
            assert_eq!(o.target_type, r.target_type);
            assert_eq!(o.reason, r.reason);
        }
    }
}
