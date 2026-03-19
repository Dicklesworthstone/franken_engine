//! Enrichment integration tests (batch 2) for the `revocation_chain` module.
//!
//! Covers chain lifecycle, hash-link integrity, schema functions, rebuild
//! validation, audit events, serde round-trips, and error display.

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
    clippy::identity_op
)]

use std::collections::BTreeSet;

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
// Test helpers
// ---------------------------------------------------------------------------

const TEST_ZONE: &str = "enrichment2-zone";

fn test_signing_key() -> SigningKey {
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
        issued_at: DeterministicTimestamp(2000),
        zone: TEST_ZONE.to_string(),
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };
    let preimage = rev.preimage_bytes();
    let sig = sign_preimage(&sk, &preimage).unwrap();
    rev.signature = sig;
    rev
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_new_chain_is_empty() {
    let chain = RevocationChain::new(TEST_ZONE);
    assert!(chain.is_empty());
    assert_eq!(chain.len(), 0);
    assert!(chain.head().is_none());
    assert_eq!(chain.head_seq(), None);
    assert_eq!(chain.zone(), TEST_ZONE);
}

#[test]
fn enrichment_empty_chain_hash_is_genesis_sentinel() {
    let chain = RevocationChain::new(TEST_ZONE);
    let expected = ContentHash::compute(b"revocation-chain-genesis");
    assert_eq!(*chain.chain_hash(), expected);
}

#[test]
fn enrichment_append_genesis_event() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = test_signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    let seq = chain.append(rev, &sk, "t-genesis").unwrap();
    assert_eq!(seq, 0);
    assert_eq!(chain.len(), 1);
    assert!(!chain.is_empty());
    assert_eq!(chain.head_seq(), Some(0));
    let event = chain.get_event(0).unwrap();
    assert!(event.prev_event.is_none());
    assert_eq!(event.event_seq, 0);
}

#[test]
fn enrichment_append_multiple_events_chain_links() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = test_signing_key();
    for i in 0..5u8 {
        let rev = make_revocation(
            RevocationTargetType::Token,
            RevocationReason::Expired,
            [i + 10; 32],
        );
        chain.append(rev, &sk, &format!("t-{i}")).unwrap();
    }
    assert_eq!(chain.len(), 5);
    assert_eq!(chain.head_seq(), Some(4));
    for i in 1..5u64 {
        let event = chain.get_event(i).unwrap();
        let prev = chain.get_event(i - 1).unwrap();
        assert_eq!(event.prev_event, Some(prev.event_id.clone()));
    }
}

#[test]
fn enrichment_is_revoked_after_append() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = test_signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [42; 32],
    );
    chain.append(rev, &sk, "t").unwrap();
    assert!(chain.is_revoked(&EngineObjectId([42; 32])));
    assert!(!chain.is_revoked(&EngineObjectId([99; 32])));
}

#[test]
fn enrichment_lookup_revocation_returns_details() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = test_signing_key();
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
fn enrichment_lookup_revocation_returns_none_for_non_revoked() {
    let chain = RevocationChain::new(TEST_ZONE);
    assert!(chain.lookup_revocation(&EngineObjectId([88; 32])).is_none());
}

#[test]
fn enrichment_duplicate_target_rejected() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = test_signing_key();
    let rev1 = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev1, &sk, "t1").unwrap();
    let rev2 = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Administrative,
        [1; 32],
    );
    assert!(matches!(
        chain.append(rev2, &sk, "t2").unwrap_err(),
        ChainError::DuplicateTarget { .. }
    ));
}

#[test]
fn enrichment_zone_mismatch_rejected() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = test_signing_key();
    let mut rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    rev.zone = "wrong-zone".to_string();
    assert!(matches!(
        chain.append(rev, &sk, "t").unwrap_err(),
        ChainError::ChainIntegrity { .. }
    ));
}

#[test]
fn enrichment_verify_empty_chain_succeeds() {
    let chain = RevocationChain::new(TEST_ZONE);
    assert!(chain.verify_chain("t").is_ok());
}

#[test]
fn enrichment_verify_chain_after_appends() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = test_signing_key();
    for i in 0..10u8 {
        let rev = make_revocation(
            RevocationTargetType::Token,
            RevocationReason::Superseded,
            [i + 100; 32],
        );
        chain.append(rev, &sk, &format!("t-{i}")).unwrap();
    }
    assert!(chain.verify_chain("t").is_ok());
}

#[test]
fn enrichment_verify_head_signature() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = test_signing_key();
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
fn enrichment_verify_head_wrong_key_fails() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = test_signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev, &sk, "t").unwrap();
    let wrong_vk = VerificationKey::from_bytes([0xFF; 32]);
    assert!(matches!(
        chain.verify_head_signature(&wrong_vk).unwrap_err(),
        ChainError::SignatureInvalid { .. }
    ));
}

#[test]
fn enrichment_verify_head_empty_chain_error() {
    let chain = RevocationChain::new(TEST_ZONE);
    let vk = test_signing_key().verification_key();
    assert!(matches!(
        chain.verify_head_signature(&vk).unwrap_err(),
        ChainError::EmptyChain
    ));
}

#[test]
fn enrichment_chain_hash_deterministic() {
    let build = || {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();
        for i in 0..3u8 {
            let rev = make_revocation(
                RevocationTargetType::Key,
                RevocationReason::Compromised,
                [i + 150; 32],
            );
            chain.append(rev, &sk, &format!("t-{i}")).unwrap();
        }
        *chain.chain_hash()
    };
    assert_eq!(build(), build());
}

#[test]
fn enrichment_rebuild_from_events_preserves_chain_hash() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = test_signing_key();
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
    assert_eq!(rebuilt.chain_hash(), chain.chain_hash());
}

#[test]
fn enrichment_rebuild_empty_succeeds() {
    let chain = RevocationChain::rebuild_from_events(TEST_ZONE, vec![], None).unwrap();
    assert!(chain.is_empty());
}

#[test]
fn enrichment_rebuild_empty_with_head_fails() {
    let head = RevocationHead {
        head_id: EngineObjectId([20; 32]),
        latest_event: EngineObjectId([19; 32]),
        head_seq: 0,
        chain_hash: ContentHash::compute(b"x"),
        zone: TEST_ZONE.to_string(),
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };
    assert!(matches!(
        RevocationChain::rebuild_from_events(TEST_ZONE, vec![], Some(head)).unwrap_err(),
        ChainError::ChainIntegrity { .. }
    ));
}

#[test]
fn enrichment_all_target_types_revoked() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = test_signing_key();
    let types = [
        RevocationTargetType::Key,
        RevocationTargetType::Token,
        RevocationTargetType::Attestation,
        RevocationTargetType::Extension,
        RevocationTargetType::Checkpoint,
    ];
    for (i, tt) in types.iter().enumerate() {
        let rev = make_revocation(*tt, RevocationReason::Administrative, [(i as u8) + 30; 32]);
        chain.append(rev, &sk, &format!("t-{i}")).unwrap();
    }
    assert_eq!(chain.len(), 5);
}

#[test]
fn enrichment_target_type_display_unique() {
    let displays: BTreeSet<String> = [
        RevocationTargetType::Key,
        RevocationTargetType::Token,
        RevocationTargetType::Attestation,
        RevocationTargetType::Extension,
        RevocationTargetType::Checkpoint,
    ]
    .iter()
    .map(|t| t.to_string())
    .collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_reason_display_unique() {
    let displays: BTreeSet<String> = [
        RevocationReason::Compromised,
        RevocationReason::Expired,
        RevocationReason::Superseded,
        RevocationReason::PolicyViolation,
        RevocationReason::Administrative,
    ]
    .iter()
    .map(|r| r.to_string())
    .collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_schema_functions_deterministic() {
    assert_eq!(revocation_schema(), revocation_schema());
    assert_eq!(revocation_event_schema(), revocation_event_schema());
    assert_eq!(revocation_head_schema(), revocation_head_schema());
}

#[test]
fn enrichment_schema_hashes_distinct() {
    assert_ne!(revocation_schema(), revocation_event_schema());
    assert_ne!(revocation_event_schema(), revocation_head_schema());
    assert_ne!(revocation_schema(), revocation_head_schema());
}

#[test]
fn enrichment_schema_ids_distinct() {
    assert_ne!(revocation_schema_id(), revocation_event_schema_id());
    assert_ne!(revocation_event_schema_id(), revocation_head_schema_id());
    assert_ne!(revocation_schema_id(), revocation_head_schema_id());
}

#[test]
fn enrichment_audit_events_on_append() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = test_signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev, &sk, "t-audit").unwrap();
    let events = chain.drain_events();
    assert!(
        events
            .iter()
            .any(|e| matches!(e.event_type, ChainEventType::RevocationAppended { .. }))
    );
}

#[test]
fn enrichment_drain_events_idempotent() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = test_signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev, &sk, "t").unwrap();
    assert!(!chain.drain_events().is_empty());
    assert!(chain.drain_events().is_empty());
    assert!(chain.drain_events().is_empty());
}

#[test]
fn enrichment_verify_chain_mut_emits_audit() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = test_signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev, &sk, "t").unwrap();
    chain.drain_events();
    chain.verify_chain_mut("t-vcm").unwrap();
    assert_eq!(chain.event_counts().get("chain_verified"), Some(&1));
}

#[test]
fn enrichment_is_revoked_audited_emits_event() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    assert!(!chain.is_revoked_audited(&EngineObjectId([99; 32]), "t-look"));
    assert_eq!(chain.event_counts().get("revocation_lookup"), Some(&1));
}

#[test]
fn enrichment_chain_error_display_distinct() {
    let errors: Vec<ChainError> = vec![
        ChainError::HeadSequenceRegression {
            current_seq: 5,
            attempted_seq: 3,
        },
        ChainError::HashLinkMismatch {
            event_seq: 3,
            expected_prev: None,
            actual_prev: None,
        },
        ChainError::SequenceDiscontinuity {
            expected_seq: 5,
            actual_seq: 8,
        },
        ChainError::InvalidGenesis {
            detail: "bad".into(),
        },
        ChainError::ChainIntegrity {
            detail: "corrupt".into(),
        },
        ChainError::SignatureInvalid {
            detail: "invalid".into(),
        },
        ChainError::DuplicateTarget {
            target_id: EngineObjectId([42; 32]),
        },
        ChainError::MutationRejected { event_seq: 7 },
        ChainError::EmptyChain,
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), errors.len());
}

#[test]
fn enrichment_chain_error_serde_all() {
    let errors: Vec<ChainError> = vec![
        ChainError::HeadSequenceRegression {
            current_seq: 5,
            attempted_seq: 3,
        },
        ChainError::HashLinkMismatch {
            event_seq: 3,
            expected_prev: None,
            actual_prev: None,
        },
        ChainError::SequenceDiscontinuity {
            expected_seq: 5,
            actual_seq: 8,
        },
        ChainError::InvalidGenesis {
            detail: "bad".into(),
        },
        ChainError::ChainIntegrity {
            detail: "corrupt".into(),
        },
        ChainError::SignatureInvalid {
            detail: "invalid".into(),
        },
        ChainError::DuplicateTarget {
            target_id: EngineObjectId([42; 32]),
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
fn enrichment_revocation_serde_round_trip() {
    let rev = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Expired,
        [44; 32],
    );
    let json = serde_json::to_string(&rev).unwrap();
    let back: Revocation = serde_json::from_str(&json).unwrap();
    assert_eq!(rev, back);
}

#[test]
fn enrichment_chain_event_serde_round_trip() {
    let event = ChainEvent {
        event_type: ChainEventType::HeadAdvanced {
            old_seq: 0,
            new_seq: 1,
        },
        zone: TEST_ZONE.to_string(),
        trace_id: "t-serde".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ChainEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn enrichment_revocation_event_content_hash_deterministic() {
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [77; 32],
    );
    let event = RevocationEvent {
        event_id: EngineObjectId([11; 32]),
        revocation: rev,
        prev_event: None,
        event_seq: 0,
    };
    assert_eq!(event.content_hash(), event.content_hash());
}

#[test]
fn enrichment_get_event_out_of_range() {
    let chain = RevocationChain::new(TEST_ZONE);
    assert!(chain.get_event(0).is_none());
    assert!(chain.get_event(999).is_none());
}

#[test]
fn enrichment_events_accessor_returns_all() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = test_signing_key();
    for i in 0..3u8 {
        let rev = make_revocation(
            RevocationTargetType::Token,
            RevocationReason::Expired,
            [i + 50; 32],
        );
        chain.append(rev, &sk, &format!("t-{i}")).unwrap();
    }
    assert_eq!(chain.events().len(), 3);
}

#[test]
fn enrichment_head_advanced_emitted_on_second_append() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = test_signing_key();
    let rev1 = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [1; 32],
    );
    chain.append(rev1, &sk, "t1").unwrap();
    chain.drain_events();
    let rev2 = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Expired,
        [2; 32],
    );
    chain.append(rev2, &sk, "t2").unwrap();
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
fn enrichment_chain_hash_accessor_matches_head() {
    let mut chain = RevocationChain::new(TEST_ZONE);
    let sk = test_signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [77; 32],
    );
    chain.append(rev, &sk, "t").unwrap();
    assert_eq!(chain.chain_hash(), &chain.head().unwrap().chain_hash);
}

#[test]
fn enrichment_chain_error_implements_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(ChainError::EmptyChain);
    assert!(!err.to_string().is_empty());
}
