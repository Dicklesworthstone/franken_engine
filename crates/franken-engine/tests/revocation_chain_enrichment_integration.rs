//! Enrichment integration tests for the `revocation_chain` module.
//!
//! Covers additional edge cases for chain operations, hash linking,
//! verification, audit events, error display, and serde round-trips.

#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use frankenengine_engine::capability_token::PrincipalId;
use frankenengine_engine::engine_object_id::{self, EngineObjectId, ObjectDomain};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::revocation_chain::*;
use frankenengine_engine::signature_preimage::{
    SIGNATURE_SENTINEL, Signature, SignaturePreimage, SigningKey, VerificationKey, sign_preimage,
};

// ── Test helpers ─────────────────────────────────────────────────────────

const ZONE: &str = "enrich-zone";

fn signing_key() -> SigningKey {
    SigningKey::from_bytes([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
        0x1D, 0x1E, 0x1F, 0x20,
    ])
}

fn alt_signing_key() -> SigningKey {
    SigningKey::from_bytes([
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE,
        0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC,
        0xBD, 0xBE, 0xBF, 0xC0,
    ])
}

fn make_revocation(
    target_type: RevocationTargetType,
    reason: RevocationReason,
    target_bytes: [u8; 32],
) -> Revocation {
    let sk = alt_signing_key();
    let principal = PrincipalId::from_verification_key(&sk.verification_key());
    let target_id = EngineObjectId(target_bytes);
    let revocation_id = engine_object_id::derive_id(
        ObjectDomain::Revocation,
        ZONE,
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
        zone: ZONE.to_string(),
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };

    let preimage = rev.preimage_bytes();
    let sig = sign_preimage(&sk, &preimage).unwrap();
    rev.signature = sig;
    rev
}

fn append_revocation(
    chain: &mut RevocationChain,
    target_type: RevocationTargetType,
    target_bytes: [u8; 32],
) -> u64 {
    let rev = make_revocation(target_type, RevocationReason::Compromised, target_bytes);
    chain.append(rev, &signing_key(), "t-enrich").unwrap()
}

// ---------------------------------------------------------------------------
// RevocationTargetType
// ---------------------------------------------------------------------------

#[test]
fn enrich_target_type_display_all() {
    assert_eq!(RevocationTargetType::Key.to_string(), "key");
    assert_eq!(RevocationTargetType::Token.to_string(), "token");
    assert_eq!(RevocationTargetType::Attestation.to_string(), "attestation");
    assert_eq!(RevocationTargetType::Extension.to_string(), "extension");
    assert_eq!(RevocationTargetType::Checkpoint.to_string(), "checkpoint");
}

#[test]
fn enrich_target_type_serde_all() {
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
fn enrich_target_type_ord() {
    assert!(RevocationTargetType::Key < RevocationTargetType::Token);
    assert!(RevocationTargetType::Token < RevocationTargetType::Attestation);
}

// ---------------------------------------------------------------------------
// RevocationReason
// ---------------------------------------------------------------------------

#[test]
fn enrich_reason_display_all() {
    assert_eq!(RevocationReason::Compromised.to_string(), "compromised");
    assert_eq!(RevocationReason::Expired.to_string(), "expired");
    assert_eq!(RevocationReason::Superseded.to_string(), "superseded");
    assert_eq!(RevocationReason::PolicyViolation.to_string(), "policy_violation");
    assert_eq!(RevocationReason::Administrative.to_string(), "administrative");
}

#[test]
fn enrich_reason_serde_all() {
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

// ---------------------------------------------------------------------------
// Schema functions
// ---------------------------------------------------------------------------

#[test]
fn enrich_schema_functions_deterministic() {
    let s1 = revocation_schema();
    let s2 = revocation_schema();
    assert_eq!(s1, s2);

    let e1 = revocation_event_schema();
    let e2 = revocation_event_schema();
    assert_eq!(e1, e2);

    let h1 = revocation_head_schema();
    let h2 = revocation_head_schema();
    assert_eq!(h1, h2);
}

#[test]
fn enrich_schema_id_functions_deterministic() {
    let s1 = revocation_schema_id();
    let s2 = revocation_schema_id();
    assert_eq!(s1, s2);

    let e1 = revocation_event_schema_id();
    let e2 = revocation_event_schema_id();
    assert_eq!(e1, e2);

    let h1 = revocation_head_schema_id();
    let h2 = revocation_head_schema_id();
    assert_eq!(h1, h2);
}

#[test]
fn enrich_schemas_all_different() {
    let s = revocation_schema();
    let e = revocation_event_schema();
    let h = revocation_head_schema();
    assert_ne!(s, e);
    assert_ne!(e, h);
    assert_ne!(s, h);
}

// ---------------------------------------------------------------------------
// RevocationChain: basic operations
// ---------------------------------------------------------------------------

#[test]
fn enrich_chain_new_empty() {
    let chain = RevocationChain::new(ZONE);
    assert!(chain.is_empty());
    assert_eq!(chain.len(), 0);
    assert_eq!(chain.zone(), ZONE);
    assert!(chain.head().is_none());
    assert!(chain.head_seq().is_none());
}

#[test]
fn enrich_chain_genesis_hash_not_zero() {
    let chain = RevocationChain::new(ZONE);
    assert_ne!(chain.chain_hash(), &ContentHash::compute(&[0u8; 32]));
}

#[test]
fn enrich_chain_single_append() {
    let mut chain = RevocationChain::new(ZONE);
    let seq = append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    assert_eq!(seq, 0);
    assert_eq!(chain.len(), 1);
    assert!(!chain.is_empty());
    assert_eq!(chain.head_seq(), Some(0));
}

#[test]
fn enrich_chain_three_appends() {
    let mut chain = RevocationChain::new(ZONE);
    for i in 0u8..3 {
        let seq = append_revocation(&mut chain, RevocationTargetType::Key, [i + 10; 32]);
        assert_eq!(seq, i as u64);
    }
    assert_eq!(chain.len(), 3);
    assert_eq!(chain.head_seq(), Some(2));
}

#[test]
fn enrich_chain_is_revoked_true() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [42; 32]);
    assert!(chain.is_revoked(&EngineObjectId([42; 32])));
}

#[test]
fn enrich_chain_is_revoked_false() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [42; 32]);
    assert!(!chain.is_revoked(&EngineObjectId([99; 32])));
}

#[test]
fn enrich_chain_lookup_revocation() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Extension, [50; 32]);
    let rev = chain.lookup_revocation(&EngineObjectId([50; 32])).unwrap();
    assert_eq!(rev.target_type, RevocationTargetType::Extension);
    assert_eq!(rev.reason, RevocationReason::Compromised);
}

#[test]
fn enrich_chain_lookup_revocation_not_found() {
    let chain = RevocationChain::new(ZONE);
    assert!(chain.lookup_revocation(&EngineObjectId([1; 32])).is_none());
}

#[test]
fn enrich_chain_get_event() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    let event = chain.get_event(0).unwrap();
    assert_eq!(event.event_seq, 0);
    assert!(event.prev_event.is_none());
}

#[test]
fn enrich_chain_get_event_out_of_range() {
    let chain = RevocationChain::new(ZONE);
    assert!(chain.get_event(0).is_none());
}

#[test]
fn enrich_chain_events_slice() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Key, [1; 32]);
    append_revocation(&mut chain, RevocationTargetType::Token, [2; 32]);
    assert_eq!(chain.events().len(), 2);
}

// ---------------------------------------------------------------------------
// Chain: duplicate target rejection
// ---------------------------------------------------------------------------

#[test]
fn enrich_chain_duplicate_target_rejected() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [5; 32]);
    let rev = make_revocation(RevocationTargetType::Token, RevocationReason::Expired, [5; 32]);
    let err = chain.append(rev, &signing_key(), "t-dup").unwrap_err();
    assert!(matches!(err, ChainError::DuplicateTarget { .. }));
}

// ---------------------------------------------------------------------------
// Chain: zone mismatch rejection
// ---------------------------------------------------------------------------

#[test]
fn enrich_chain_zone_mismatch_rejected() {
    let mut chain = RevocationChain::new(ZONE);
    let sk = alt_signing_key();
    let principal = PrincipalId::from_verification_key(&sk.verification_key());
    let target_bytes = [99u8; 32];
    let target_id = EngineObjectId(target_bytes);
    let revocation_id = engine_object_id::derive_id(
        ObjectDomain::Revocation,
        "wrong-zone",
        &revocation_schema_id(),
        target_bytes.as_slice(),
    )
    .unwrap();

    let mut rev = Revocation {
        revocation_id,
        target_type: RevocationTargetType::Token,
        target_id,
        reason: RevocationReason::Compromised,
        issued_by: principal,
        issued_at: DeterministicTimestamp(1000),
        zone: "wrong-zone".to_string(),
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };
    let preimage = rev.preimage_bytes();
    let sig = sign_preimage(&sk, &preimage).unwrap();
    rev.signature = sig;

    let err = chain.append(rev, &signing_key(), "t-zone").unwrap_err();
    assert!(matches!(err, ChainError::ChainIntegrity { .. }));
}

// ---------------------------------------------------------------------------
// Chain: hash linking integrity
// ---------------------------------------------------------------------------

#[test]
fn enrich_chain_hash_link_second_event_references_first() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    append_revocation(&mut chain, RevocationTargetType::Key, [2; 32]);
    let event0 = chain.get_event(0).unwrap();
    let event1 = chain.get_event(1).unwrap();
    assert!(event0.prev_event.is_none());
    assert_eq!(event1.prev_event, Some(event0.event_id.clone()));
}

#[test]
fn enrich_chain_rolling_hash_changes_on_append() {
    let mut chain = RevocationChain::new(ZONE);
    let h0 = *chain.chain_hash();
    append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    let h1 = *chain.chain_hash();
    assert_ne!(h0, h1);
    append_revocation(&mut chain, RevocationTargetType::Key, [2; 32]);
    let h2 = *chain.chain_hash();
    assert_ne!(h1, h2);
}

// ---------------------------------------------------------------------------
// Chain: verification
// ---------------------------------------------------------------------------

#[test]
fn enrich_chain_verify_empty_ok() {
    let chain = RevocationChain::new(ZONE);
    assert!(chain.verify_chain("t-verify").is_ok());
}

#[test]
fn enrich_chain_verify_single_ok() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    assert!(chain.verify_chain("t-verify").is_ok());
}

#[test]
fn enrich_chain_verify_five_events_ok() {
    let mut chain = RevocationChain::new(ZONE);
    for i in 0u8..5 {
        append_revocation(&mut chain, RevocationTargetType::Key, [i + 100; 32]);
    }
    assert!(chain.verify_chain("t-verify").is_ok());
}

#[test]
fn enrich_chain_verify_mut_emits_audit() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    chain.drain_events();
    chain.verify_chain_mut("t-vmut").unwrap();
    let events = chain.drain_events();
    assert!(events.iter().any(|e| matches!(e.event_type, ChainEventType::ChainVerified { .. })));
}

// ---------------------------------------------------------------------------
// Chain: head signature verification
// ---------------------------------------------------------------------------

#[test]
fn enrich_chain_head_sig_verified() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    assert!(chain.verify_head_signature(&signing_key().verification_key()).is_ok());
}

#[test]
fn enrich_chain_head_sig_wrong_key_fails() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    let wrong = VerificationKey::from_bytes([0xFF; 32]);
    assert!(chain.verify_head_signature(&wrong).is_err());
}

#[test]
fn enrich_chain_head_sig_empty_chain_fails() {
    let chain = RevocationChain::new(ZONE);
    assert!(matches!(
        chain.verify_head_signature(&signing_key().verification_key()),
        Err(ChainError::EmptyChain)
    ));
}

// ---------------------------------------------------------------------------
// Chain: audit events
// ---------------------------------------------------------------------------

#[test]
fn enrich_chain_audit_events_on_append() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    let events = chain.drain_events();
    assert!(!events.is_empty());
    assert!(events.iter().any(|e| matches!(&e.event_type, ChainEventType::RevocationAppended { .. })));
}

#[test]
fn enrich_chain_drain_events_clears() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    let e1 = chain.drain_events();
    assert!(!e1.is_empty());
    let e2 = chain.drain_events();
    assert!(e2.is_empty());
}

// ---------------------------------------------------------------------------
// ChainError display
// ---------------------------------------------------------------------------

#[test]
fn enrich_error_display_all_variants() {
    let errors: Vec<ChainError> = vec![
        ChainError::HeadSequenceRegression { current_seq: 5, attempted_seq: 3 },
        ChainError::HashLinkMismatch {
            event_seq: 2,
            expected_prev: None,
            actual_prev: Some(EngineObjectId([1; 32])),
        },
        ChainError::SequenceDiscontinuity { expected_seq: 3, actual_seq: 5 },
        ChainError::InvalidGenesis { detail: "bad".to_string() },
        ChainError::ChainIntegrity { detail: "broken".to_string() },
        ChainError::SignatureInvalid { detail: "sig fail".to_string() },
        ChainError::DuplicateTarget { target_id: EngineObjectId([1; 32]) },
        ChainError::MutationRejected { event_seq: 0 },
        ChainError::EmptyChain,
    ];
    for e in &errors {
        let msg = e.to_string();
        assert!(!msg.is_empty());
    }
}

#[test]
fn enrich_error_serde_all_variants() {
    let errors: Vec<ChainError> = vec![
        ChainError::HeadSequenceRegression { current_seq: 5, attempted_seq: 3 },
        ChainError::SequenceDiscontinuity { expected_seq: 3, actual_seq: 5 },
        ChainError::InvalidGenesis { detail: "bad".to_string() },
        ChainError::ChainIntegrity { detail: "broken".to_string() },
        ChainError::SignatureInvalid { detail: "sig fail".to_string() },
        ChainError::DuplicateTarget { target_id: EngineObjectId([1; 32]) },
        ChainError::MutationRejected { event_seq: 0 },
        ChainError::EmptyChain,
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: ChainError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ---------------------------------------------------------------------------
// Revocation: all reason types
// ---------------------------------------------------------------------------

#[test]
fn enrich_revocation_all_reasons() {
    let mut chain = RevocationChain::new(ZONE);
    for (i, reason) in [
        RevocationReason::Compromised,
        RevocationReason::Expired,
        RevocationReason::Superseded,
        RevocationReason::PolicyViolation,
        RevocationReason::Administrative,
    ].iter().enumerate() {
        let rev = make_revocation(RevocationTargetType::Token, *reason, [i as u8 + 200; 32]);
        chain.append(rev, &signing_key(), "t-reason").unwrap();
    }
    assert_eq!(chain.len(), 5);
    assert!(chain.verify_chain("t-verify").is_ok());
}

// ---------------------------------------------------------------------------
// Revocation: all target types
// ---------------------------------------------------------------------------

#[test]
fn enrich_revocation_all_target_types() {
    let mut chain = RevocationChain::new(ZONE);
    for (i, tt) in [
        RevocationTargetType::Key,
        RevocationTargetType::Token,
        RevocationTargetType::Attestation,
        RevocationTargetType::Extension,
        RevocationTargetType::Checkpoint,
    ].iter().enumerate() {
        let rev = make_revocation(*tt, RevocationReason::Administrative, [i as u8 + 210; 32]);
        chain.append(rev, &signing_key(), "t-type").unwrap();
    }
    assert_eq!(chain.len(), 5);
    assert!(chain.verify_chain("t-verify").is_ok());
}

// ---------------------------------------------------------------------------
// RevocationEvent content_hash determinism
// ---------------------------------------------------------------------------

#[test]
fn enrich_event_content_hash_deterministic() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    let event = chain.get_event(0).unwrap();
    let h1 = event.content_hash();
    let h2 = event.content_hash();
    assert_eq!(h1, h2);
}

// ---------------------------------------------------------------------------
// ChainEventType serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_chain_event_type_serde() {
    let event = ChainEvent {
        event_type: ChainEventType::RevocationAppended {
            event_seq: 0,
            target_id: EngineObjectId([1; 32]),
            target_type: RevocationTargetType::Token,
        },
        zone: ZONE.to_string(),
        trace_id: "t-1".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ChainEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}
