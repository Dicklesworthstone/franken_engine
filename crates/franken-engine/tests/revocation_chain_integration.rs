//! Integration tests for the `revocation_chain` module.
//!
//! Covers: RevocationTargetType, RevocationReason, Revocation, RevocationEvent,
//! RevocationHead, ChainError, ChainEventType, ChainEvent, RevocationChain,
//! schema functions, chain lifecycle, rebuild, audit events, and stress scenarios.

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

const TEST_ZONE: &str = "integ-zone";

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
    let sk = revocation_signing_key();
    let principal = PrincipalId::from_verification_key(&sk.verification_key());
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
    let sig = sign_preimage(&sk, &preimage).unwrap();
    rev.signature = sig;
    rev
}

// ---------------------------------------------------------------------------
// Schema functions
// ---------------------------------------------------------------------------

#[test]
fn schema_functions_return_deterministic_values() {
    assert_eq!(revocation_schema(), revocation_schema());
    assert_eq!(revocation_schema_id(), revocation_schema_id());
    assert_eq!(revocation_event_schema(), revocation_event_schema());
    assert_eq!(revocation_event_schema_id(), revocation_event_schema_id());
    assert_eq!(revocation_head_schema(), revocation_head_schema());
    assert_eq!(revocation_head_schema_id(), revocation_head_schema_id());
}

#[test]
fn schema_functions_are_pairwise_distinct() {
    let s1 = revocation_schema();
    let s2 = revocation_event_schema();
    let s3 = revocation_head_schema();
    assert_ne!(s1, s2);
    assert_ne!(s1, s3);
    assert_ne!(s2, s3);

    let id1 = revocation_schema_id();
    let id2 = revocation_event_schema_id();
    let id3 = revocation_head_schema_id();
    assert_ne!(id1, id2);
    assert_ne!(id1, id3);
    assert_ne!(id2, id3);
}

// ---------------------------------------------------------------------------
// RevocationTargetType
// ---------------------------------------------------------------------------

#[test]
fn revocation_target_type_serde_all_variants() {
    let all = [
        RevocationTargetType::Key,
        RevocationTargetType::Token,
        RevocationTargetType::Attestation,
        RevocationTargetType::Extension,
        RevocationTargetType::Checkpoint,
    ];
    for variant in &all {
        let json = serde_json::to_string(variant).unwrap();
        let restored: RevocationTargetType = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, restored);
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

// ---------------------------------------------------------------------------
// RevocationReason
// ---------------------------------------------------------------------------

#[test]
fn revocation_reason_serde_all_variants() {
    let all = [
        RevocationReason::Compromised,
        RevocationReason::Expired,
        RevocationReason::Superseded,
        RevocationReason::PolicyViolation,
        RevocationReason::Administrative,
    ];
    for variant in &all {
        let json = serde_json::to_string(variant).unwrap();
        let restored: RevocationReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, restored);
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

// ---------------------------------------------------------------------------
// Revocation struct
// ---------------------------------------------------------------------------

#[test]
fn revocation_serde_roundtrip() {
    let rev = make_revocation(
        RevocationTargetType::Extension,
        RevocationReason::PolicyViolation,
        [0xAB; 32],
    );
    let json = serde_json::to_string(&rev).unwrap();
    let restored: Revocation = serde_json::from_str(&json).unwrap();
    assert_eq!(rev, restored);
}

#[test]
fn revocation_preimage_bytes_deterministic() {
    let rev1 = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    let rev2 = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    assert_eq!(rev1.preimage_bytes(), rev2.preimage_bytes());
}

#[test]
fn revocation_preimage_bytes_differ_for_different_targets() {
    let rev1 = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    let rev2 = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [2; 32],
    );
    assert_ne!(rev1.preimage_bytes(), rev2.preimage_bytes());
}

// ---------------------------------------------------------------------------
// RevocationEvent
// ---------------------------------------------------------------------------

#[test]
fn revocation_event_canonical_bytes_deterministic() {
    let rev = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Expired,
        [10; 32],
    );
    let event = RevocationEvent {
        event_id: EngineObjectId([0xAA; 32]),
        revocation: rev,
        prev_event: None,
        event_seq: 0,
    };
    assert_eq!(event.canonical_bytes(), event.canonical_bytes());
}

#[test]
fn revocation_event_content_hash_deterministic() {
    let rev = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Expired,
        [10; 32],
    );
    let event = RevocationEvent {
        event_id: EngineObjectId([0xBB; 32]),
        revocation: rev,
        prev_event: None,
        event_seq: 0,
    };
    assert_eq!(event.content_hash(), event.content_hash());
}

#[test]
fn revocation_event_different_seqs_produce_different_hashes() {
    let rev = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Expired,
        [10; 32],
    );
    let e1 = RevocationEvent {
        event_id: EngineObjectId([0xCC; 32]),
        revocation: rev.clone(),
        prev_event: None,
        event_seq: 0,
    };
    let e2 = RevocationEvent {
        event_id: EngineObjectId([0xCC; 32]),
        revocation: rev,
        prev_event: None,
        event_seq: 1,
    };
    assert_ne!(e1.content_hash(), e2.content_hash());
}

#[test]
fn revocation_event_serde_roundtrip() {
    let rev = make_revocation(
        RevocationTargetType::Attestation,
        RevocationReason::Superseded,
        [20; 32],
    );
    let event = RevocationEvent {
        event_id: EngineObjectId([0xDD; 32]),
        revocation: rev,
        prev_event: Some(EngineObjectId([0xEE; 32])),
        event_seq: 7,
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: RevocationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

// ---------------------------------------------------------------------------
// RevocationHead
// ---------------------------------------------------------------------------

#[test]
fn revocation_head_serde_roundtrip() {
    let head = RevocationHead {
        head_id: EngineObjectId([0x11; 32]),
        latest_event: EngineObjectId([0x22; 32]),
        head_seq: 5,
        chain_hash: ContentHash::compute(b"test-chain"),
        zone: "zone-a".to_string(),
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };
    let json = serde_json::to_string(&head).unwrap();
    let restored: RevocationHead = serde_json::from_str(&json).unwrap();
    assert_eq!(head, restored);
}

#[test]
fn revocation_head_preimage_bytes_deterministic() {
    let head = RevocationHead {
        head_id: EngineObjectId([0x33; 32]),
        latest_event: EngineObjectId([0x44; 32]),
        head_seq: 3,
        chain_hash: ContentHash::compute(b"determinism"),
        zone: "det-zone".to_string(),
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };
    assert_eq!(head.preimage_bytes(), head.preimage_bytes());
}

// ---------------------------------------------------------------------------
// ChainError
// ---------------------------------------------------------------------------

#[test]
fn chain_error_serde_all_9_variants() {
    let errors: Vec<ChainError> = vec![
        ChainError::HeadSequenceRegression {
            current_seq: 5,
            attempted_seq: 3,
        },
        ChainError::HashLinkMismatch {
            event_seq: 2,
            expected_prev: Some(EngineObjectId([0xAA; 32])),
            actual_prev: Some(EngineObjectId([0xBB; 32])),
        },
        ChainError::SequenceDiscontinuity {
            expected_seq: 4,
            actual_seq: 10,
        },
        ChainError::InvalidGenesis {
            detail: "bad genesis".to_string(),
        },
        ChainError::ChainIntegrity {
            detail: "integrity broken".to_string(),
        },
        ChainError::SignatureInvalid {
            detail: "sig bad".to_string(),
        },
        ChainError::DuplicateTarget {
            target_id: EngineObjectId([0xCC; 32]),
        },
        ChainError::MutationRejected { event_seq: 7 },
        ChainError::EmptyChain,
    ];

    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: ChainError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored);
    }
}

#[test]
fn chain_error_display_all_non_empty() {
    let errors: Vec<ChainError> = vec![
        ChainError::HeadSequenceRegression {
            current_seq: 5,
            attempted_seq: 3,
        },
        ChainError::HashLinkMismatch {
            event_seq: 2,
            expected_prev: None,
            actual_prev: Some(EngineObjectId([0xBB; 32])),
        },
        ChainError::SequenceDiscontinuity {
            expected_seq: 4,
            actual_seq: 10,
        },
        ChainError::InvalidGenesis {
            detail: "bad genesis".to_string(),
        },
        ChainError::ChainIntegrity {
            detail: "integrity broken".to_string(),
        },
        ChainError::SignatureInvalid {
            detail: "sig bad".to_string(),
        },
        ChainError::DuplicateTarget {
            target_id: EngineObjectId([0xCC; 32]),
        },
        ChainError::MutationRejected { event_seq: 7 },
        ChainError::EmptyChain,
    ];

    for err in &errors {
        let display = err.to_string();
        assert!(
            !display.is_empty(),
            "display for {:?} should not be empty",
            err
        );
    }
}

#[test]
fn chain_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(ChainError::EmptyChain);
    assert!(!err.to_string().is_empty());
}

// ---------------------------------------------------------------------------
// ChainEventType serde
// ---------------------------------------------------------------------------

#[test]
fn chain_event_type_serde_all_variants() {
    let types: Vec<ChainEventType> = vec![
        ChainEventType::RevocationAppended {
            event_seq: 0,
            target_id: EngineObjectId([0x11; 32]),
            target_type: RevocationTargetType::Key,
        },
        ChainEventType::HeadAdvanced {
            old_seq: 0,
            new_seq: 1,
        },
        ChainEventType::ChainVerified { chain_length: 5 },
        ChainEventType::RevocationLookup {
            target_id: EngineObjectId([0x22; 32]),
            is_revoked: true,
        },
        ChainEventType::AppendRejected {
            reason: "duplicate".to_string(),
        },
    ];

    for t in &types {
        let json = serde_json::to_string(t).unwrap();
        let restored: ChainEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, restored);
    }
}

#[test]
fn chain_event_serde_roundtrip() {
    let event = ChainEvent {
        event_type: ChainEventType::ChainVerified { chain_length: 10 },
        zone: "test-zone".to_string(),
        trace_id: "trace-001".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: ChainEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

// ---------------------------------------------------------------------------
// RevocationChain — basic lifecycle
// ---------------------------------------------------------------------------

#[test]
fn empty_chain_properties() {
    let chain = RevocationChain::new(TEST_ZONE);
    assert!(chain.is_empty());
    assert_eq!(chain.len(), 0);
    assert!(chain.head().is_none());
    assert_eq!(chain.head_seq(), None);
    assert_eq!(chain.zone(), TEST_ZONE);
    assert!(!chain.is_revoked(&EngineObjectId([0xFF; 32])));
    assert!(
        chain
            .lookup_revocation(&EngineObjectId([0xFF; 32]))
            .is_none()
    );
    assert!(chain.get_event(0).is_none());
    assert!(chain.events().is_empty());
}

#[test]
fn single_append_and_lookup() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );

    let seq = chain.append(rev, &sk, "t-single").unwrap();
    assert_eq!(seq, 0);
    assert_eq!(chain.len(), 1);
    assert!(!chain.is_empty());
    assert_eq!(chain.head_seq(), Some(0));

    let event = chain.get_event(0).unwrap();
    assert!(event.prev_event.is_none());
    assert_eq!(event.event_seq, 0);

    assert!(chain.is_revoked(&EngineObjectId([1; 32])));
    let found = chain.lookup_revocation(&EngineObjectId([1; 32])).unwrap();
    assert_eq!(found.target_type, RevocationTargetType::Key);
    assert_eq!(found.reason, RevocationReason::Compromised);
}

#[test]
fn multi_append_with_hash_linking() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();

    for i in 0..10u8 {
        let rev = make_revocation(
            RevocationTargetType::Token,
            RevocationReason::Expired,
            [i + 10; 32],
        );
        let seq = chain.append(rev, &sk, &format!("t-multi-{i}")).unwrap();
        assert_eq!(seq, i as u64);
    }

    assert_eq!(chain.len(), 10);
    assert_eq!(chain.head_seq(), Some(9));

    for i in 1..10u64 {
        let event = chain.get_event(i).unwrap();
        let prev = chain.get_event(i - 1).unwrap();
        assert_eq!(event.prev_event, Some(prev.event_id.clone()));
        assert_eq!(event.event_seq, i);
    }
}

// ---------------------------------------------------------------------------
// All target types × all reasons
// ---------------------------------------------------------------------------

#[test]
fn all_target_type_reason_combinations_accepted() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();

    let types = [
        RevocationTargetType::Key,
        RevocationTargetType::Token,
        RevocationTargetType::Attestation,
        RevocationTargetType::Extension,
        RevocationTargetType::Checkpoint,
    ];
    let reasons = [
        RevocationReason::Compromised,
        RevocationReason::Expired,
        RevocationReason::Superseded,
        RevocationReason::PolicyViolation,
        RevocationReason::Administrative,
    ];

    let mut idx = 0u8;
    for target_type in &types {
        for reason in &reasons {
            let mut target = [0u8; 32];
            target[0] = idx;
            let rev = make_revocation(*target_type, *reason, target);
            chain.append(rev, &sk, &format!("t-combo-{idx}")).unwrap();
            idx += 1;
        }
    }

    assert_eq!(chain.len(), 25);
    for i in 0..25u8 {
        let mut target = [0u8; 32];
        target[0] = i;
        assert!(chain.is_revoked(&EngineObjectId(target)));
    }
}

// ---------------------------------------------------------------------------
// Chain verification
// ---------------------------------------------------------------------------

#[test]
fn verify_chain_on_empty_succeeds() {
    let chain = RevocationChain::new(TEST_ZONE);
    assert!(chain.verify_chain("t-empty").is_ok());
}

#[test]
fn verify_chain_after_multi_append() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();

    for i in 0..15u8 {
        let rev = make_revocation(
            RevocationTargetType::Token,
            RevocationReason::Superseded,
            [i + 100; 32],
        );
        chain.append(rev, &sk, &format!("t-v-{i}")).unwrap();
    }

    assert!(chain.verify_chain("t-verify").is_ok());
}

#[test]
fn verify_chain_mut_emits_chain_verified_audit() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();

    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev, &sk, "t-vcm").unwrap();
    chain.drain_events();

    chain.verify_chain_mut("t-verify-mut").unwrap();
    let counts = chain.event_counts();
    assert_eq!(counts.get("chain_verified"), Some(&1));
}

// ---------------------------------------------------------------------------
// Head signature verification
// ---------------------------------------------------------------------------

#[test]
fn verify_head_signature_valid_key() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let vk = sk.verification_key();

    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev, &sk, "t-sig-ok").unwrap();
    assert!(chain.verify_head_signature(&vk).is_ok());
}

#[test]
fn verify_head_signature_wrong_key_fails() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();

    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev, &sk, "t-sig-bad").unwrap();

    let wrong_vk = VerificationKey::from_bytes([0xFF; 32]);
    let err = chain.verify_head_signature(&wrong_vk).unwrap_err();
    assert!(matches!(err, ChainError::SignatureInvalid { .. }));
}

#[test]
fn verify_head_empty_chain_returns_empty_chain_error() {
    let chain = RevocationChain::new(TEST_ZONE);
    let vk = head_signing_key().verification_key();
    let err = chain.verify_head_signature(&vk).unwrap_err();
    assert!(matches!(err, ChainError::EmptyChain));
}

// ---------------------------------------------------------------------------
// Duplicate target rejection
// ---------------------------------------------------------------------------

#[test]
fn duplicate_target_rejected_with_audit_event() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();

    let rev1 = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [42; 32],
    );
    chain.append(rev1, &sk, "t-dup-1").unwrap();

    let rev2 = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Administrative,
        [42; 32],
    );
    let err = chain.append(rev2, &sk, "t-dup-2").unwrap_err();
    assert!(matches!(err, ChainError::DuplicateTarget { .. }));

    let counts = chain.event_counts();
    assert_eq!(counts.get("append_rejected"), Some(&1));
}

// ---------------------------------------------------------------------------
// Zone mismatch rejection
// ---------------------------------------------------------------------------

#[test]
fn zone_mismatch_rejected() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();

    let mut rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    rev.zone = "wrong-zone".to_string();

    let err = chain.append(rev, &sk, "t-zone-bad").unwrap_err();
    assert!(matches!(err, ChainError::ChainIntegrity { .. }));
}

// ---------------------------------------------------------------------------
// Incremental verify_append
// ---------------------------------------------------------------------------

#[test]
fn verify_append_accepts_valid_next() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();

    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev, &sk, "t-va-0").unwrap();

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
    chain.append(rev, &sk, "t-va-seq").unwrap();

    let rev2 = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Expired,
        [2; 32],
    );
    let prev_id = chain.events().last().unwrap().event_id.clone();
    let bad_event = RevocationEvent {
        event_id: EngineObjectId([0xBB; 32]),
        revocation: rev2,
        prev_event: Some(prev_id),
        event_seq: 99,
    };

    let err = chain.verify_append(&bad_event).unwrap_err();
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
    chain.append(rev, &sk, "t-va-link").unwrap();

    let rev2 = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Expired,
        [2; 32],
    );
    let bad_event = RevocationEvent {
        event_id: EngineObjectId([0xCC; 32]),
        revocation: rev2,
        prev_event: Some(EngineObjectId([0xFF; 32])),
        event_seq: 1,
    };

    let err = chain.verify_append(&bad_event).unwrap_err();
    assert!(matches!(err, ChainError::HashLinkMismatch { .. }));
}

// ---------------------------------------------------------------------------
// Rebuild from events
// ---------------------------------------------------------------------------

#[test]
fn rebuild_from_events_preserves_state() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();

    for i in 0..8u8 {
        let rev = make_revocation(
            RevocationTargetType::Token,
            RevocationReason::Superseded,
            [i + 70; 32],
        );
        chain.append(rev, &sk, &format!("t-rb-{i}")).unwrap();
    }

    let events = chain.events().to_vec();
    let head = chain.head().cloned();
    let original_hash = chain.chain_hash().clone();

    let rebuilt = RevocationChain::rebuild_from_events(TEST_ZONE, events, head).unwrap();
    assert_eq!(rebuilt.len(), 8);
    assert_eq!(rebuilt.head_seq(), Some(7));
    assert_eq!(*rebuilt.chain_hash(), original_hash);

    for i in 0..8u8 {
        assert!(rebuilt.is_revoked(&EngineObjectId([i + 70; 32])));
    }
}

#[test]
fn rebuild_detects_tampered_hash_link() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();

    for i in 0..3u8 {
        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [i + 80; 32],
        );
        chain.append(rev, &sk, &format!("t-rt-{i}")).unwrap();
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
    chain.append(rev, &sk, "t-hm").unwrap();

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
    chain.append(rev, &sk, "t-hh").unwrap();

    let events = chain.events().to_vec();
    let mut head = chain.head().cloned().unwrap();
    head.chain_hash = ContentHash::compute(b"tampered-hash");

    let err = RevocationChain::rebuild_from_events(TEST_ZONE, events, Some(head)).unwrap_err();
    assert!(matches!(err, ChainError::ChainIntegrity { .. }));
}

#[test]
fn rebuild_detects_duplicate_target_in_events() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();

    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev, &sk, "t-rbd").unwrap();

    let mut events = chain.events().to_vec();
    let mut dup = events[0].clone();
    dup.event_seq = 1;
    dup.prev_event = Some(events[0].event_id.clone());
    events.push(dup);

    let err = RevocationChain::rebuild_from_events(TEST_ZONE, events, None).unwrap_err();
    assert!(matches!(err, ChainError::DuplicateTarget { .. }));
}

#[test]
fn rebuild_empty_events_with_head_fails() {
    let head = RevocationHead {
        head_id: EngineObjectId([0x11; 32]),
        latest_event: EngineObjectId([0x22; 32]),
        head_seq: 0,
        chain_hash: ContentHash::compute(b"test"),
        zone: TEST_ZONE.to_string(),
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };

    let err = RevocationChain::rebuild_from_events(TEST_ZONE, vec![], Some(head)).unwrap_err();
    assert!(matches!(err, ChainError::ChainIntegrity { .. }));
}

// ---------------------------------------------------------------------------
// Audit events
// ---------------------------------------------------------------------------

#[test]
fn append_emits_revocation_appended_event() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();

    let rev = make_revocation(
        RevocationTargetType::Extension,
        RevocationReason::Administrative,
        [1; 32],
    );
    chain.append(rev, &sk, "t-audit-app").unwrap();

    let events = chain.drain_events();
    assert!(events.iter().any(|e| matches!(
        e.event_type,
        ChainEventType::RevocationAppended { event_seq: 0, .. }
    )));
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
    chain.append(rev1, &sk, "t-ha-0").unwrap();
    chain.drain_events();

    let rev2 = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Expired,
        [2; 32],
    );
    chain.append(rev2, &sk, "t-ha-1").unwrap();

    let events = chain.drain_events();
    assert!(events.iter().any(|e| matches!(
        e.event_type,
        ChainEventType::HeadAdvanced {
            old_seq: 0,
            new_seq: 1
        }
    )));
}

#[test]
fn is_revoked_audited_emits_lookup_event() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let target = EngineObjectId([0xFE; 32]);

    let result = chain.is_revoked_audited(&target, "t-lookup-audit");
    assert!(!result);

    let counts = chain.event_counts();
    assert_eq!(counts.get("revocation_lookup"), Some(&1));
}

#[test]
fn drain_events_clears_audit_log() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();

    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev, &sk, "t-drain").unwrap();

    let first = chain.drain_events();
    assert!(!first.is_empty());

    let second = chain.drain_events();
    assert!(second.is_empty());
}

// ---------------------------------------------------------------------------
// Chain hash determinism
// ---------------------------------------------------------------------------

#[test]
fn chain_hash_deterministic_across_identical_builds() {
    let build = || {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = head_signing_key();

        for i in 0..5u8 {
            let rev = make_revocation(
                RevocationTargetType::Key,
                RevocationReason::Compromised,
                [i + 150; 32],
            );
            chain.append(rev, &sk, &format!("t-det-{i}")).unwrap();
        }
        chain.chain_hash().clone()
    };

    assert_eq!(build(), build());
}

#[test]
fn chain_hash_changes_with_each_append() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let mut hashes = vec![chain.chain_hash().clone()];

    for i in 0..5u8 {
        let rev = make_revocation(
            RevocationTargetType::Token,
            RevocationReason::Expired,
            [i + 160; 32],
        );
        chain.append(rev, &sk, &format!("t-hc-{i}")).unwrap();
        hashes.push(chain.chain_hash().clone());
    }

    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(hashes[i], hashes[j], "hash at {i} should differ from {j}");
        }
    }
}

// ---------------------------------------------------------------------------
// Head monotonicity
// ---------------------------------------------------------------------------

#[test]
fn head_seq_increases_monotonically() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let mut prev_seq = None;

    for i in 0..8u8 {
        let rev = make_revocation(
            RevocationTargetType::Token,
            RevocationReason::Expired,
            [i + 50; 32],
        );
        chain.append(rev, &sk, &format!("t-mono-{i}")).unwrap();
        let current = chain.head_seq().unwrap();
        if let Some(prev) = prev_seq {
            assert!(current > prev);
        }
        prev_seq = Some(current);
    }
}

// ---------------------------------------------------------------------------
// Head signature after multiple appends
// ---------------------------------------------------------------------------

#[test]
fn head_signature_valid_after_many_appends() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let vk = sk.verification_key();

    for i in 0..20u8 {
        let rev = make_revocation(
            RevocationTargetType::Attestation,
            RevocationReason::Superseded,
            [i + 170; 32],
        );
        chain.append(rev, &sk, &format!("t-hs-{i}")).unwrap();
    }

    assert!(chain.verify_head_signature(&vk).is_ok());
    assert!(chain.verify_chain("t-hs-verify").is_ok());
}

// ---------------------------------------------------------------------------
// Stress test
// ---------------------------------------------------------------------------

#[test]
fn stress_50_revocations_rebuild_and_verify() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = head_signing_key();
    let vk = sk.verification_key();

    let types = [
        RevocationTargetType::Key,
        RevocationTargetType::Token,
        RevocationTargetType::Attestation,
        RevocationTargetType::Extension,
        RevocationTargetType::Checkpoint,
    ];
    let reasons = [
        RevocationReason::Compromised,
        RevocationReason::Expired,
        RevocationReason::Superseded,
        RevocationReason::PolicyViolation,
        RevocationReason::Administrative,
    ];

    for i in 0..50u16 {
        let mut target = [0u8; 32];
        target[0] = (i & 0xFF) as u8;
        target[1] = (i >> 8) as u8;
        target[2] = 0xAA;

        let target_type = types[(i as usize) % types.len()];
        let reason = reasons[(i as usize) % reasons.len()];
        let rev = make_revocation(target_type, reason, target);
        chain.append(rev, &sk, &format!("t-stress-{i}")).unwrap();
    }

    assert_eq!(chain.len(), 50);
    assert_eq!(chain.head_seq(), Some(49));
    assert!(chain.verify_chain("t-stress-verify").is_ok());
    assert!(chain.verify_head_signature(&vk).is_ok());

    for i in 0..50u16 {
        let mut target = [0u8; 32];
        target[0] = (i & 0xFF) as u8;
        target[1] = (i >> 8) as u8;
        target[2] = 0xAA;
        assert!(chain.is_revoked(&EngineObjectId(target)));
    }

    let events = chain.events().to_vec();
    let head = chain.head().cloned();
    let original_hash = chain.chain_hash().clone();

    let rebuilt = RevocationChain::rebuild_from_events(TEST_ZONE, events, head).unwrap();
    assert_eq!(rebuilt.len(), 50);
    assert_eq!(rebuilt.head_seq(), Some(49));
    assert_eq!(*rebuilt.chain_hash(), original_hash);
    assert!(rebuilt.verify_chain("t-stress-rebuilt").is_ok());
}
