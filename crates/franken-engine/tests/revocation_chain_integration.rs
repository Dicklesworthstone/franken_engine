use frankenengine_engine::capability_token::PrincipalId;
use frankenengine_engine::engine_object_id::{self, EngineObjectId, ObjectDomain};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::revocation_chain::*;
use frankenengine_engine::signature_preimage::{
    SIGNATURE_SENTINEL, Signature, SignaturePreimage, SigningKey, VerificationKey, sign_preimage,
};

// ── Test helpers ─────────────────────────────────────────────────────────

const ZONE: &str = "test-zone";
const ALT_ZONE: &str = "alt-zone";

fn signing_key() -> SigningKey {
    SigningKey::from_bytes([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ])
}

fn alt_signing_key() -> SigningKey {
    SigningKey::from_bytes([
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE,
        0xBF, 0xC0,
    ])
}

fn make_target_id(seed: u8) -> EngineObjectId {
    EngineObjectId([seed; 32])
}

fn make_revocation(
    target_type: RevocationTargetType,
    reason: RevocationReason,
    target_bytes: [u8; 32],
    zone: &str,
) -> Revocation {
    let sk = alt_signing_key();
    let principal = PrincipalId::from_verification_key(&sk.verification_key());
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
        issued_at: DeterministicTimestamp(1000),
        zone: zone.to_string(),
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
    let rev = make_revocation(
        target_type,
        RevocationReason::Compromised,
        target_bytes,
        ZONE,
    );
    let sk = signing_key();
    chain.append(rev, &sk, "trace-test").unwrap()
}

// ── Schema helpers ────────────────────────────────────────────────────────

#[test]
fn revocation_schema_is_deterministic() {
    let s1 = revocation_schema();
    let s2 = revocation_schema();
    assert_eq!(s1.as_bytes(), s2.as_bytes());
}

#[test]
fn revocation_event_schema_is_deterministic() {
    let s1 = revocation_event_schema();
    let s2 = revocation_event_schema();
    assert_eq!(s1.as_bytes(), s2.as_bytes());
}

#[test]
fn revocation_head_schema_is_deterministic() {
    let s1 = revocation_head_schema();
    let s2 = revocation_head_schema();
    assert_eq!(s1.as_bytes(), s2.as_bytes());
}

#[test]
fn revocation_schema_id_is_deterministic() {
    let id1 = revocation_schema_id();
    let id2 = revocation_schema_id();
    assert_eq!(id1, id2);
}

// ── RevocationTargetType display ──────────────────────────────────────────

#[test]
fn target_type_display_key() {
    assert_eq!(RevocationTargetType::Key.to_string(), "key");
}

#[test]
fn target_type_display_token() {
    assert_eq!(RevocationTargetType::Token.to_string(), "token");
}

#[test]
fn target_type_display_attestation() {
    assert_eq!(RevocationTargetType::Attestation.to_string(), "attestation");
}

#[test]
fn target_type_display_extension() {
    assert_eq!(RevocationTargetType::Extension.to_string(), "extension");
}

#[test]
fn target_type_display_checkpoint() {
    assert_eq!(RevocationTargetType::Checkpoint.to_string(), "checkpoint");
}

// ── RevocationReason display ──────────────────────────────────────────────

#[test]
fn reason_display_compromised() {
    assert_eq!(RevocationReason::Compromised.to_string(), "compromised");
}

#[test]
fn reason_display_expired() {
    assert_eq!(RevocationReason::Expired.to_string(), "expired");
}

#[test]
fn reason_display_superseded() {
    assert_eq!(RevocationReason::Superseded.to_string(), "superseded");
}

#[test]
fn reason_display_policy_violation() {
    assert_eq!(
        RevocationReason::PolicyViolation.to_string(),
        "policy_violation"
    );
}

#[test]
fn reason_display_administrative() {
    assert_eq!(
        RevocationReason::Administrative.to_string(),
        "administrative"
    );
}

// ── ChainError display ─────────────────────────────────────────────────────

#[test]
fn chain_error_display_empty_chain() {
    let e = ChainError::EmptyChain;
    assert!(e.to_string().contains("empty"));
}

#[test]
fn chain_error_display_head_sequence_regression() {
    let e = ChainError::HeadSequenceRegression {
        current_seq: 5,
        attempted_seq: 3,
    };
    let s = e.to_string();
    assert!(s.contains("5"));
    assert!(s.contains("3"));
}

#[test]
fn chain_error_display_sequence_discontinuity() {
    let e = ChainError::SequenceDiscontinuity {
        expected_seq: 2,
        actual_seq: 5,
    };
    let s = e.to_string();
    assert!(s.contains("2"));
    assert!(s.contains("5"));
}

#[test]
fn chain_error_display_invalid_genesis() {
    let e = ChainError::InvalidGenesis {
        detail: "bad genesis".to_string(),
    };
    assert!(e.to_string().contains("bad genesis"));
}

#[test]
fn chain_error_display_chain_integrity() {
    let e = ChainError::ChainIntegrity {
        detail: "integrity failed".to_string(),
    };
    assert!(e.to_string().contains("integrity failed"));
}

#[test]
fn chain_error_display_signature_invalid() {
    let e = ChainError::SignatureInvalid {
        detail: "bad sig".to_string(),
    };
    assert!(e.to_string().contains("bad sig"));
}

#[test]
fn chain_error_display_duplicate_target() {
    let target_id = make_target_id(1);
    let e = ChainError::DuplicateTarget {
        target_id: target_id.clone(),
    };
    let s = e.to_string();
    assert!(s.contains("duplicate"));
}

#[test]
fn chain_error_display_mutation_rejected() {
    let e = ChainError::MutationRejected { event_seq: 7 };
    let s = e.to_string();
    assert!(s.contains("7"));
}

// ── RevocationChain: creation and empty state ──────────────────────────────

#[test]
fn new_chain_is_empty() {
    let chain = RevocationChain::new(ZONE);
    assert!(chain.is_empty());
    assert_eq!(chain.len(), 0);
    assert!(chain.head().is_none());
    assert!(chain.head_seq().is_none());
}

#[test]
fn new_chain_has_correct_zone() {
    let chain = RevocationChain::new(ZONE);
    assert_eq!(chain.zone(), ZONE);
}

#[test]
fn new_chain_events_empty() {
    let chain = RevocationChain::new(ZONE);
    assert!(chain.events().is_empty());
}

// ── RevocationChain: verify_chain on empty ──────────────────────────────────

#[test]
fn verify_chain_empty_is_ok() {
    let chain = RevocationChain::new(ZONE);
    assert!(chain.verify_chain("trace-1").is_ok());
}

// ── RevocationChain: append ────────────────────────────────────────────────

#[test]
fn append_first_revocation_returns_seq_zero() {
    let mut chain = RevocationChain::new(ZONE);
    let seq = append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    assert_eq!(seq, 0);
}

#[test]
fn append_second_revocation_returns_seq_one() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    let seq = append_revocation(&mut chain, RevocationTargetType::Token, [2; 32]);
    assert_eq!(seq, 1);
}

#[test]
fn append_updates_chain_length() {
    let mut chain = RevocationChain::new(ZONE);
    assert_eq!(chain.len(), 0);
    append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    assert_eq!(chain.len(), 1);
    append_revocation(&mut chain, RevocationTargetType::Key, [2; 32]);
    assert_eq!(chain.len(), 2);
}

#[test]
fn append_updates_head() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    let head = chain.head().unwrap();
    assert_eq!(head.head_seq, 0);
    assert_eq!(head.zone, ZONE);
}

#[test]
fn append_updates_head_seq_monotonically() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    append_revocation(&mut chain, RevocationTargetType::Token, [2; 32]);
    assert_eq!(chain.head_seq(), Some(1));
}

#[test]
fn append_rejects_zone_mismatch() {
    let mut chain = RevocationChain::new(ZONE);
    let rev = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Compromised,
        [5; 32],
        ALT_ZONE,
    );
    let sk = signing_key();
    let err = chain.append(rev, &sk, "trace").unwrap_err();
    assert!(matches!(err, ChainError::ChainIntegrity { .. }));
}

#[test]
fn append_rejects_duplicate_target() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [7; 32]);
    let rev2 = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Administrative,
        [7; 32],
        ZONE,
    );
    let sk = signing_key();
    let err = chain.append(rev2, &sk, "trace").unwrap_err();
    assert!(matches!(err, ChainError::DuplicateTarget { .. }));
}

// ── RevocationChain: is_revoked ──────────────────────────────────────────

#[test]
fn is_revoked_false_for_unknown_target() {
    let chain = RevocationChain::new(ZONE);
    let target = make_target_id(99);
    assert!(!chain.is_revoked(&target));
}

#[test]
fn is_revoked_true_after_append() {
    let mut chain = RevocationChain::new(ZONE);
    let target = [42; 32];
    append_revocation(&mut chain, RevocationTargetType::Key, target);
    assert!(chain.is_revoked(&EngineObjectId(target)));
}

#[test]
fn lookup_revocation_none_for_unknown() {
    let chain = RevocationChain::new(ZONE);
    let target = make_target_id(1);
    assert!(chain.lookup_revocation(&target).is_none());
}

#[test]
fn lookup_revocation_returns_revocation_after_append() {
    let mut chain = RevocationChain::new(ZONE);
    let target = [10; 32];
    append_revocation(&mut chain, RevocationTargetType::Token, target);
    let rev = chain.lookup_revocation(&EngineObjectId(target)).unwrap();
    assert_eq!(rev.target_id, EngineObjectId(target));
}

// ── RevocationChain: get_event ────────────────────────────────────────────

#[test]
fn get_event_returns_none_for_empty_chain() {
    let chain = RevocationChain::new(ZONE);
    assert!(chain.get_event(0).is_none());
}

#[test]
fn get_event_returns_event_at_seq() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    let event = chain.get_event(0).unwrap();
    assert_eq!(event.event_seq, 0);
    assert!(event.prev_event.is_none()); // genesis
}

#[test]
fn get_event_links_to_previous() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    append_revocation(&mut chain, RevocationTargetType::Token, [2; 32]);
    let event0 = chain.get_event(0).unwrap();
    let event1 = chain.get_event(1).unwrap();
    assert_eq!(event1.prev_event.as_ref(), Some(&event0.event_id));
}

// ── RevocationChain: verify_chain ────────────────────────────────────────

#[test]
fn verify_chain_passes_with_one_event() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    assert!(chain.verify_chain("trace").is_ok());
}

#[test]
fn verify_chain_passes_with_multiple_events() {
    let mut chain = RevocationChain::new(ZONE);
    for i in 0u8..5 {
        append_revocation(&mut chain, RevocationTargetType::Token, [i; 32]);
    }
    assert!(chain.verify_chain("trace").is_ok());
}

#[test]
fn verify_chain_mut_emits_audit_event() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    chain.drain_events(); // clear prior events
    chain.verify_chain_mut("trace").unwrap();
    let events = chain.drain_events();
    assert!(!events.is_empty());
    assert!(
        events
            .iter()
            .any(|e| matches!(e.event_type, ChainEventType::ChainVerified { .. }))
    );
}

// ── RevocationChain: verify_head_signature ────────────────────────────────

#[test]
fn verify_head_signature_fails_on_empty_chain() {
    let chain = RevocationChain::new(ZONE);
    let vk = VerificationKey::from_bytes([1; 32]);
    let err = chain.verify_head_signature(&vk).unwrap_err();
    assert!(matches!(err, ChainError::EmptyChain));
}

#[test]
fn verify_head_signature_passes_with_correct_key() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    let sk = signing_key();
    let vk = sk.verification_key();
    assert!(chain.verify_head_signature(&vk).is_ok());
}

#[test]
fn verify_head_signature_fails_with_wrong_key() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    let wrong_vk = VerificationKey::from_bytes([0xFF; 32]);
    let err = chain.verify_head_signature(&wrong_vk).unwrap_err();
    assert!(matches!(err, ChainError::SignatureInvalid { .. }));
}

// ── RevocationChain: verify_append ───────────────────────────────────────

#[test]
fn verify_append_rejects_wrong_sequence() {
    let chain = RevocationChain::new(ZONE);
    // chain is empty, so expected_seq = 0
    // create a fake event with seq=1
    let fake_event = RevocationEvent {
        event_id: EngineObjectId([0; 32]),
        revocation: make_revocation(
            RevocationTargetType::Token,
            RevocationReason::Compromised,
            [1; 32],
            ZONE,
        ),
        prev_event: None,
        event_seq: 1, // wrong
    };
    let err = chain.verify_append(&fake_event).unwrap_err();
    assert!(matches!(err, ChainError::SequenceDiscontinuity { .. }));
}

// ── RevocationChain: is_revoked_audited ──────────────────────────────────

#[test]
fn is_revoked_audited_emits_lookup_event() {
    let mut chain = RevocationChain::new(ZONE);
    let target = make_target_id(5);
    chain.drain_events();
    let result = chain.is_revoked_audited(&target, "trace-audit");
    assert!(!result);
    let events = chain.drain_events();
    assert!(
        events
            .iter()
            .any(|e| matches!(e.event_type, ChainEventType::RevocationLookup { .. }))
    );
}

// ── RevocationChain: drain_events ────────────────────────────────────────

#[test]
fn drain_events_clears_audit_log() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    let events = chain.drain_events();
    assert!(!events.is_empty());
    let events2 = chain.drain_events();
    assert!(events2.is_empty());
}

// ── RevocationChain: chain_hash changes after append ─────────────────────

#[test]
fn chain_hash_changes_after_each_append() {
    let mut chain = RevocationChain::new(ZONE);
    let h0 = *chain.chain_hash();
    append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    let h1 = *chain.chain_hash();
    append_revocation(&mut chain, RevocationTargetType::Token, [2; 32]);
    let h2 = *chain.chain_hash();
    assert_ne!(h0.as_bytes(), h1.as_bytes());
    assert_ne!(h1.as_bytes(), h2.as_bytes());
}

// ── RevocationChain: rebuild_from_events ─────────────────────────────────

#[test]
fn rebuild_from_empty_events_succeeds() {
    let chain = RevocationChain::rebuild_from_events(ZONE, vec![], None).unwrap();
    assert!(chain.is_empty());
}

#[test]
fn rebuild_from_empty_events_with_head_fails() {
    let fake_head = RevocationHead {
        head_id: EngineObjectId([0; 32]),
        latest_event: EngineObjectId([0; 32]),
        head_seq: 0,
        chain_hash: ContentHash::compute(b"bad"),
        zone: ZONE.to_string(),
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };
    let err = RevocationChain::rebuild_from_events(ZONE, vec![], Some(fake_head)).unwrap_err();
    assert!(matches!(err, ChainError::ChainIntegrity { .. }));
}

#[test]
fn rebuild_from_wrong_sequence_fails() {
    let fake_event = RevocationEvent {
        event_id: EngineObjectId([0; 32]),
        revocation: make_revocation(
            RevocationTargetType::Token,
            RevocationReason::Compromised,
            [1; 32],
            ZONE,
        ),
        prev_event: None,
        event_seq: 5, // wrong
    };
    let err = RevocationChain::rebuild_from_events(ZONE, vec![fake_event], None).unwrap_err();
    assert!(matches!(err, ChainError::SequenceDiscontinuity { .. }));
}

// ── RevocationEvent canonical_bytes and content_hash ─────────────────────

#[test]
fn revocation_event_canonical_bytes_is_deterministic() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    let event = chain.get_event(0).unwrap();
    let bytes1 = event.canonical_bytes();
    let bytes2 = event.canonical_bytes();
    assert_eq!(bytes1, bytes2);
}

#[test]
fn revocation_event_content_hash_is_deterministic() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    let event = chain.get_event(0).unwrap();
    let h1 = event.content_hash();
    let h2 = event.content_hash();
    assert_eq!(h1.as_bytes(), h2.as_bytes());
}

// ── Serde roundtrip ────────────────────────────────────────────────────────

#[test]
fn revocation_target_type_serde_roundtrip() {
    for t in [
        RevocationTargetType::Key,
        RevocationTargetType::Token,
        RevocationTargetType::Attestation,
        RevocationTargetType::Extension,
        RevocationTargetType::Checkpoint,
    ] {
        let json = serde_json::to_string(&t).unwrap();
        let decoded: RevocationTargetType = serde_json::from_str(&json).unwrap();
        assert_eq!(t, decoded);
    }
}

#[test]
fn revocation_reason_serde_roundtrip() {
    for r in [
        RevocationReason::Compromised,
        RevocationReason::Expired,
        RevocationReason::Superseded,
        RevocationReason::PolicyViolation,
        RevocationReason::Administrative,
    ] {
        let json = serde_json::to_string(&r).unwrap();
        let decoded: RevocationReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, decoded);
    }
}

#[test]
fn chain_error_serde_roundtrip() {
    let e = ChainError::EmptyChain;
    let json = serde_json::to_string(&e).unwrap();
    let decoded: ChainError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, decoded);
}

// ── Multi-type revocations ────────────────────────────────────────────────

#[test]
fn can_revoke_different_target_types() {
    let mut chain = RevocationChain::new(ZONE);
    for (i, tt) in [
        RevocationTargetType::Key,
        RevocationTargetType::Token,
        RevocationTargetType::Attestation,
        RevocationTargetType::Extension,
        RevocationTargetType::Checkpoint,
    ]
    .into_iter()
    .enumerate()
    {
        let target = [i as u8; 32];
        append_revocation(&mut chain, tt, target);
        assert!(chain.is_revoked(&EngineObjectId(target)));
    }
    assert_eq!(chain.len(), 5);
    assert!(chain.verify_chain("trace").is_ok());
}

// ── Audit trail for appends ────────────────────────────────────────────────

#[test]
fn append_emits_revocation_appended_event() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    let events = chain.drain_events();
    assert!(
        events
            .iter()
            .any(|e| matches!(e.event_type, ChainEventType::RevocationAppended { .. }))
    );
}

#[test]
fn second_append_emits_head_advanced_event() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    chain.drain_events();
    append_revocation(&mut chain, RevocationTargetType::Token, [2; 32]);
    let events = chain.drain_events();
    assert!(
        events
            .iter()
            .any(|e| matches!(e.event_type, ChainEventType::HeadAdvanced { .. }))
    );
}

#[test]
fn zone_mismatch_emits_append_rejected_event() {
    let mut chain = RevocationChain::new(ZONE);
    chain.drain_events();
    let rev = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Compromised,
        [5; 32],
        ALT_ZONE,
    );
    let sk = signing_key();
    let _ = chain.append(rev, &sk, "trace");
    let events = chain.drain_events();
    assert!(
        events
            .iter()
            .any(|e| matches!(e.event_type, ChainEventType::AppendRejected { .. }))
    );
}

// ===========================================================================
// Enrichment: ChainError Display — HashLinkMismatch
// ===========================================================================

#[test]
fn chain_error_display_hash_link_mismatch_none_expected() {
    let e = ChainError::HashLinkMismatch {
        event_seq: 0,
        expected_prev: None,
        actual_prev: Some(EngineObjectId([0xAA; 32])),
    };
    let s = e.to_string();
    assert!(s.contains("0"), "{s}");
    assert!(s.contains("None"), "{s}");
}

#[test]
fn chain_error_display_hash_link_mismatch_both_some() {
    let e = ChainError::HashLinkMismatch {
        event_seq: 3,
        expected_prev: Some(EngineObjectId([0x11; 32])),
        actual_prev: Some(EngineObjectId([0x22; 32])),
    };
    let s = e.to_string();
    assert!(s.contains("3"), "{s}");
}

// ===========================================================================
// Enrichment: ChainError serde roundtrip — all variants
// ===========================================================================

#[test]
fn chain_error_serde_head_sequence_regression() {
    let e = ChainError::HeadSequenceRegression {
        current_seq: 10,
        attempted_seq: 5,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: ChainError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn chain_error_serde_hash_link_mismatch() {
    let e = ChainError::HashLinkMismatch {
        event_seq: 4,
        expected_prev: Some(EngineObjectId([0x11; 32])),
        actual_prev: None,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: ChainError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn chain_error_serde_sequence_discontinuity() {
    let e = ChainError::SequenceDiscontinuity {
        expected_seq: 3,
        actual_seq: 7,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: ChainError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn chain_error_serde_invalid_genesis() {
    let e = ChainError::InvalidGenesis {
        detail: "bad".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: ChainError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn chain_error_serde_chain_integrity() {
    let e = ChainError::ChainIntegrity {
        detail: "corrupt".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: ChainError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn chain_error_serde_signature_invalid() {
    let e = ChainError::SignatureInvalid {
        detail: "wrong key".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: ChainError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn chain_error_serde_duplicate_target() {
    let e = ChainError::DuplicateTarget {
        target_id: EngineObjectId([0xBB; 32]),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: ChainError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn chain_error_serde_mutation_rejected() {
    let e = ChainError::MutationRejected { event_seq: 9 };
    let json = serde_json::to_string(&e).unwrap();
    let back: ChainError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ===========================================================================
// Enrichment: ChainError std::error::Error impl
// ===========================================================================

#[test]
fn chain_error_implements_std_error() {
    let e: Box<dyn std::error::Error> = Box::new(ChainError::EmptyChain);
    assert!(!e.to_string().is_empty());
}

#[test]
fn chain_error_std_error_chain_integrity() {
    let e: Box<dyn std::error::Error> = Box::new(ChainError::ChainIntegrity {
        detail: "test".to_string(),
    });
    assert!(e.to_string().contains("test"));
}

// ===========================================================================
// Enrichment: ChainEventType serde roundtrips
// ===========================================================================

#[test]
fn chain_event_type_serde_revocation_appended() {
    let t = ChainEventType::RevocationAppended {
        event_seq: 3,
        target_id: EngineObjectId([0x10; 32]),
        target_type: RevocationTargetType::Key,
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: ChainEventType = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn chain_event_type_serde_head_advanced() {
    let t = ChainEventType::HeadAdvanced {
        old_seq: 1,
        new_seq: 2,
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: ChainEventType = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn chain_event_type_serde_chain_verified() {
    let t = ChainEventType::ChainVerified { chain_length: 42 };
    let json = serde_json::to_string(&t).unwrap();
    let back: ChainEventType = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn chain_event_type_serde_revocation_lookup() {
    let t = ChainEventType::RevocationLookup {
        target_id: EngineObjectId([0x20; 32]),
        is_revoked: true,
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: ChainEventType = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn chain_event_type_serde_append_rejected() {
    let t = ChainEventType::AppendRejected {
        reason: "zone mismatch".to_string(),
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: ChainEventType = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

// ===========================================================================
// Enrichment: ChainEvent serde roundtrip
// ===========================================================================

#[test]
fn chain_event_serde_roundtrip() {
    let evt = ChainEvent {
        event_type: ChainEventType::ChainVerified { chain_length: 10 },
        zone: "zone-a".to_string(),
        trace_id: "trace-1".to_string(),
    };
    let json = serde_json::to_string(&evt).unwrap();
    let back: ChainEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(evt, back);
}

#[test]
fn chain_event_serde_with_append_rejected() {
    let evt = ChainEvent {
        event_type: ChainEventType::AppendRejected {
            reason: "dup target".to_string(),
        },
        zone: ZONE.to_string(),
        trace_id: "trace-rej".to_string(),
    };
    let json = serde_json::to_string(&evt).unwrap();
    let back: ChainEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(evt, back);
}

// ===========================================================================
// Enrichment: Revocation struct serde roundtrip
// ===========================================================================

#[test]
fn revocation_struct_serde_roundtrip() {
    let rev = make_revocation(
        RevocationTargetType::Extension,
        RevocationReason::PolicyViolation,
        [0xCC; 32],
        ZONE,
    );
    let json = serde_json::to_string(&rev).unwrap();
    let back: Revocation = serde_json::from_str(&json).unwrap();
    assert_eq!(rev, back);
}

#[test]
fn revocation_struct_serde_all_reason_variants() {
    for reason in [
        RevocationReason::Compromised,
        RevocationReason::Expired,
        RevocationReason::Superseded,
        RevocationReason::PolicyViolation,
        RevocationReason::Administrative,
    ] {
        let rev = make_revocation(RevocationTargetType::Key, reason, [0xDD; 32], ZONE);
        let json = serde_json::to_string(&rev).unwrap();
        let back: Revocation = serde_json::from_str(&json).unwrap();
        assert_eq!(rev.reason, back.reason);
    }
}

// ===========================================================================
// Enrichment: RevocationEvent serde roundtrip
// ===========================================================================

#[test]
fn revocation_event_serde_roundtrip() {
    let rev = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Expired,
        [0xEE; 32],
        ZONE,
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
fn revocation_event_serde_with_prev_event() {
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [0xFF; 32],
        ZONE,
    );
    let event = RevocationEvent {
        event_id: EngineObjectId([0xBB; 32]),
        revocation: rev,
        prev_event: Some(EngineObjectId([0xAA; 32])),
        event_seq: 1,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: RevocationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ===========================================================================
// Enrichment: RevocationHead serde roundtrip
// ===========================================================================

#[test]
fn revocation_head_serde_roundtrip() {
    let head = RevocationHead {
        head_id: EngineObjectId([0x11; 32]),
        latest_event: EngineObjectId([0x22; 32]),
        head_seq: 5,
        chain_hash: ContentHash::compute(b"test-hash"),
        zone: ZONE.to_string(),
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };
    let json = serde_json::to_string(&head).unwrap();
    let back: RevocationHead = serde_json::from_str(&json).unwrap();
    assert_eq!(head, back);
}

// ===========================================================================
// Enrichment: Schema uniqueness
// ===========================================================================

#[test]
fn schema_ids_are_all_distinct() {
    let r = revocation_schema_id();
    let e = revocation_event_schema_id();
    let h = revocation_head_schema_id();
    assert_ne!(r, e);
    assert_ne!(r, h);
    assert_ne!(e, h);
}

#[test]
fn schema_hashes_are_all_distinct() {
    let r = revocation_schema();
    let e = revocation_event_schema();
    let h = revocation_head_schema();
    assert_ne!(r.as_bytes(), e.as_bytes());
    assert_ne!(r.as_bytes(), h.as_bytes());
    assert_ne!(e.as_bytes(), h.as_bytes());
}

#[test]
fn revocation_event_schema_id_is_deterministic() {
    let id1 = revocation_event_schema_id();
    let id2 = revocation_event_schema_id();
    assert_eq!(id1, id2);
}

#[test]
fn revocation_head_schema_id_is_deterministic() {
    let id1 = revocation_head_schema_id();
    let id2 = revocation_head_schema_id();
    assert_eq!(id1, id2);
}

// ===========================================================================
// Enrichment: RevocationTargetType ordering and clone
// ===========================================================================

#[test]
fn target_type_ordering_all_variants() {
    assert!(RevocationTargetType::Key < RevocationTargetType::Token);
    assert!(RevocationTargetType::Token < RevocationTargetType::Attestation);
    assert!(RevocationTargetType::Attestation < RevocationTargetType::Extension);
    assert!(RevocationTargetType::Extension < RevocationTargetType::Checkpoint);
}

#[test]
fn target_type_clone_equals_original() {
    let t = RevocationTargetType::Attestation;
    let cloned = t;
    assert_eq!(t, cloned);
}

#[test]
fn target_type_debug_contains_variant_name() {
    let s = format!("{:?}", RevocationTargetType::Key);
    assert!(s.contains("Key"), "{s}");
}

// ===========================================================================
// Enrichment: RevocationReason ordering and clone
// ===========================================================================

#[test]
fn reason_ordering_all_variants() {
    assert!(RevocationReason::Compromised < RevocationReason::Expired);
    assert!(RevocationReason::Expired < RevocationReason::Superseded);
    assert!(RevocationReason::Superseded < RevocationReason::PolicyViolation);
    assert!(RevocationReason::PolicyViolation < RevocationReason::Administrative);
}

#[test]
fn reason_clone_equals_original() {
    let r = RevocationReason::Superseded;
    let cloned = r;
    assert_eq!(r, cloned);
}

#[test]
fn reason_debug_contains_variant_name() {
    let s = format!("{:?}", RevocationReason::PolicyViolation);
    assert!(s.contains("PolicyViolation"), "{s}");
}

// ===========================================================================
// Enrichment: RevocationEvent content_hash changes with different fields
// ===========================================================================

#[test]
fn event_content_hash_changes_with_event_id() {
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [0x10; 32],
        ZONE,
    );
    let e1 = RevocationEvent {
        event_id: EngineObjectId([0xAA; 32]),
        revocation: rev.clone(),
        prev_event: None,
        event_seq: 0,
    };
    let e2 = RevocationEvent {
        event_id: EngineObjectId([0xBB; 32]),
        revocation: rev,
        prev_event: None,
        event_seq: 0,
    };
    assert_ne!(e1.content_hash(), e2.content_hash());
}

#[test]
fn event_content_hash_changes_with_seq() {
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [0x11; 32],
        ZONE,
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
fn event_content_hash_changes_with_prev_event() {
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [0x12; 32],
        ZONE,
    );
    let e1 = RevocationEvent {
        event_id: EngineObjectId([0xDD; 32]),
        revocation: rev.clone(),
        prev_event: None,
        event_seq: 0,
    };
    let e2 = RevocationEvent {
        event_id: EngineObjectId([0xDD; 32]),
        revocation: rev,
        prev_event: Some(EngineObjectId([0xFF; 32])),
        event_seq: 0,
    };
    assert_ne!(e1.content_hash(), e2.content_hash());
}

// ===========================================================================
// Enrichment: Revocation preimage_bytes determinism
// ===========================================================================

#[test]
fn revocation_preimage_bytes_deterministic() {
    let rev = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Expired,
        [0x30; 32],
        ZONE,
    );
    let p1 = rev.preimage_bytes();
    let p2 = rev.preimage_bytes();
    assert_eq!(p1, p2);
}

#[test]
fn revocation_preimage_bytes_differ_by_target() {
    let r1 = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Expired,
        [0x31; 32],
        ZONE,
    );
    let r2 = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Expired,
        [0x32; 32],
        ZONE,
    );
    assert_ne!(r1.preimage_bytes(), r2.preimage_bytes());
}

#[test]
fn revocation_signature_domain_is_revocation() {
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [0x33; 32],
        ZONE,
    );
    assert_eq!(rev.signature_domain(), ObjectDomain::Revocation);
}

// ===========================================================================
// Enrichment: RevocationHead SignaturePreimage
// ===========================================================================

#[test]
fn revocation_head_preimage_bytes_deterministic() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [0x40; 32]);
    let head = chain.head().unwrap();
    let p1 = head.preimage_bytes();
    let p2 = head.preimage_bytes();
    assert_eq!(p1, p2);
}

#[test]
fn revocation_head_signature_domain_is_revocation() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [0x41; 32]);
    let head = chain.head().unwrap();
    assert_eq!(head.signature_domain(), ObjectDomain::Revocation);
}

// ===========================================================================
// Enrichment: verify_append — additional scenarios
// ===========================================================================

#[test]
fn verify_append_accepts_valid_genesis_on_empty_chain() {
    let chain = RevocationChain::new(ZONE);
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [0x50; 32],
        ZONE,
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
fn verify_append_rejects_genesis_with_prev_link() {
    let chain = RevocationChain::new(ZONE);
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [0x51; 32],
        ZONE,
    );
    let bad_genesis = RevocationEvent {
        event_id: EngineObjectId([0xBB; 32]),
        revocation: rev,
        prev_event: Some(EngineObjectId([0xFF; 32])),
        event_seq: 0,
    };
    let err = chain.verify_append(&bad_genesis).unwrap_err();
    assert!(
        matches!(err, ChainError::HashLinkMismatch { .. })
            || matches!(err, ChainError::InvalidGenesis { .. })
    );
}

#[test]
fn verify_append_accepts_correct_next_event() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [0x52; 32]);
    let prev_id = chain.events().last().unwrap().event_id.clone();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Expired,
        [0x53; 32],
        ZONE,
    );
    let next = RevocationEvent {
        event_id: EngineObjectId([0xCC; 32]),
        revocation: rev,
        prev_event: Some(prev_id),
        event_seq: 1,
    };
    assert!(chain.verify_append(&next).is_ok());
}

#[test]
fn verify_append_rejects_wrong_prev_link() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [0x54; 32]);
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Expired,
        [0x55; 32],
        ZONE,
    );
    let next = RevocationEvent {
        event_id: EngineObjectId([0xDD; 32]),
        revocation: rev,
        prev_event: Some(EngineObjectId([0xFF; 32])),
        event_seq: 1,
    };
    let err = chain.verify_append(&next).unwrap_err();
    assert!(matches!(err, ChainError::HashLinkMismatch { .. }));
}

// ===========================================================================
// Enrichment: rebuild_from_events — additional scenarios
// ===========================================================================

#[test]
fn rebuild_from_valid_events_with_head_succeeds() {
    let mut chain = RevocationChain::new(ZONE);
    let sk = signing_key();
    for i in 0..5u8 {
        let rev = make_revocation(
            RevocationTargetType::Token,
            RevocationReason::Superseded,
            [i + 0x60; 32],
            ZONE,
        );
        chain.append(rev, &sk, &format!("t-{i}")).unwrap();
    }
    let events = chain.events().to_vec();
    let head = chain.head().cloned();
    let rebuilt = RevocationChain::rebuild_from_events(ZONE, events, head).unwrap();
    assert_eq!(rebuilt.len(), 5);
    assert_eq!(rebuilt.head_seq(), Some(4));
    assert_eq!(rebuilt.chain_hash(), chain.chain_hash());
}

#[test]
fn rebuild_detects_tampered_hash_link() {
    let mut chain = RevocationChain::new(ZONE);
    let sk = signing_key();
    for i in 0..3u8 {
        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [i + 0x70; 32],
            ZONE,
        );
        chain.append(rev, &sk, &format!("t-{i}")).unwrap();
    }
    let mut events = chain.events().to_vec();
    events[1].prev_event = Some(EngineObjectId([0xFF; 32]));
    let err = RevocationChain::rebuild_from_events(ZONE, events, None).unwrap_err();
    assert!(matches!(err, ChainError::HashLinkMismatch { .. }));
}

#[test]
fn rebuild_detects_genesis_with_prev_event() {
    let mut chain = RevocationChain::new(ZONE);
    let sk = signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [0x80; 32],
        ZONE,
    );
    chain.append(rev, &sk, "t").unwrap();
    let mut events = chain.events().to_vec();
    events[0].prev_event = Some(EngineObjectId([0xAA; 32]));
    let err = RevocationChain::rebuild_from_events(ZONE, events, None).unwrap_err();
    assert!(matches!(err, ChainError::InvalidGenesis { .. }));
}

#[test]
fn rebuild_detects_head_seq_mismatch() {
    let mut chain = RevocationChain::new(ZONE);
    let sk = signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [0x81; 32],
        ZONE,
    );
    chain.append(rev, &sk, "t").unwrap();
    let events = chain.events().to_vec();
    let mut head = chain.head().cloned().unwrap();
    head.head_seq = 99;
    let err = RevocationChain::rebuild_from_events(ZONE, events, Some(head)).unwrap_err();
    assert!(matches!(err, ChainError::ChainIntegrity { .. }));
}

#[test]
fn rebuild_detects_head_chain_hash_mismatch() {
    let mut chain = RevocationChain::new(ZONE);
    let sk = signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [0x82; 32],
        ZONE,
    );
    chain.append(rev, &sk, "t").unwrap();
    let events = chain.events().to_vec();
    let mut head = chain.head().cloned().unwrap();
    head.chain_hash = ContentHash::compute(b"tampered-hash");
    let err = RevocationChain::rebuild_from_events(ZONE, events, Some(head)).unwrap_err();
    assert!(matches!(err, ChainError::ChainIntegrity { .. }));
}

#[test]
fn rebuild_detects_duplicate_target_in_events() {
    let mut chain = RevocationChain::new(ZONE);
    let sk = signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [0x83; 32],
        ZONE,
    );
    chain.append(rev, &sk, "t").unwrap();
    let mut events = chain.events().to_vec();
    let mut dup = events[0].clone();
    dup.event_seq = 1;
    dup.prev_event = Some(events[0].event_id.clone());
    events.push(dup);
    let err = RevocationChain::rebuild_from_events(ZONE, events, None).unwrap_err();
    assert!(matches!(err, ChainError::DuplicateTarget { .. }));
}

// ===========================================================================
// Enrichment: event_counts
// ===========================================================================

#[test]
fn event_counts_empty_chain() {
    let chain = RevocationChain::new(ZONE);
    let counts = chain.event_counts();
    assert!(counts.is_empty());
}

#[test]
fn event_counts_after_appends() {
    let mut chain = RevocationChain::new(ZONE);
    let sk = signing_key();
    let rev1 = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [0x90; 32],
        ZONE,
    );
    chain.append(rev1, &sk, "t-1").unwrap();
    let rev2 = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Expired,
        [0x91; 32],
        ZONE,
    );
    chain.append(rev2, &sk, "t-2").unwrap();

    let counts = chain.event_counts();
    assert_eq!(counts.get("revocation_appended"), Some(&2));
    assert_eq!(counts.get("head_advanced"), Some(&1)); // only 2nd append emits this
}

#[test]
fn event_counts_with_lookup() {
    let mut chain = RevocationChain::new(ZONE);
    chain.is_revoked_audited(&EngineObjectId([0x99; 32]), "t-l1");
    chain.is_revoked_audited(&EngineObjectId([0x98; 32]), "t-l2");
    let counts = chain.event_counts();
    assert_eq!(counts.get("revocation_lookup"), Some(&2));
}

#[test]
fn event_counts_with_rejection() {
    let mut chain = RevocationChain::new(ZONE);
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [0x97; 32],
        ALT_ZONE,
    );
    let sk = signing_key();
    let _ = chain.append(rev, &sk, "t");
    let counts = chain.event_counts();
    assert_eq!(counts.get("append_rejected"), Some(&1));
}

#[test]
fn event_counts_with_verify_chain_mut() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [0x96; 32]);
    chain.drain_events();
    chain.verify_chain_mut("t-verify").unwrap();
    let counts = chain.event_counts();
    assert_eq!(counts.get("chain_verified"), Some(&1));
}

// ===========================================================================
// Enrichment: Genesis append does NOT emit HeadAdvanced
// ===========================================================================

#[test]
fn genesis_append_does_not_emit_head_advanced() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Key, [0xA0; 32]);
    let events = chain.drain_events();
    assert!(events.iter().any(|e| matches!(
        e.event_type,
        ChainEventType::RevocationAppended { event_seq: 0, .. }
    )));
    assert!(
        !events
            .iter()
            .any(|e| matches!(e.event_type, ChainEventType::HeadAdvanced { .. }))
    );
}

// ===========================================================================
// Enrichment: Audit events carry correct zone and trace_id
// ===========================================================================

#[test]
fn audit_events_carry_correct_zone_and_trace_id() {
    let mut chain = RevocationChain::new(ZONE);
    let sk = signing_key();
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [0xA1; 32],
        ZONE,
    );
    chain.append(rev, &sk, "trace-xyz").unwrap();
    let events = chain.drain_events();
    for evt in &events {
        assert_eq!(evt.zone, ZONE);
        assert_eq!(evt.trace_id, "trace-xyz");
    }
}

// ===========================================================================
// Enrichment: head_id changes with each append
// ===========================================================================

#[test]
fn head_id_changes_per_append() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Key, [0xB0; 32]);
    let id1 = chain.head().unwrap().head_id.clone();
    append_revocation(&mut chain, RevocationTargetType::Token, [0xB1; 32]);
    let id2 = chain.head().unwrap().head_id.clone();
    assert_ne!(id1, id2);
}

// ===========================================================================
// Enrichment: Chain hash determinism (same appends produce same hash)
// ===========================================================================

#[test]
fn chain_hash_deterministic_for_same_sequence() {
    let build = || {
        let mut chain = RevocationChain::new(ZONE);
        let sk = signing_key();
        for i in 0..3u8 {
            let rev = make_revocation(
                RevocationTargetType::Key,
                RevocationReason::Compromised,
                [i + 0xC0; 32],
                ZONE,
            );
            chain.append(rev, &sk, &format!("t-{i}")).unwrap();
        }
        *chain.chain_hash()
    };
    assert_eq!(build(), build());
}

// ===========================================================================
// Enrichment: Different targets produce different chain hashes
// ===========================================================================

#[test]
fn different_targets_produce_different_chain_hashes() {
    let sk = signing_key();

    let mut chain_a = RevocationChain::new(ZONE);
    let rev_a = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [0xD0; 32],
        ZONE,
    );
    chain_a.append(rev_a, &sk, "t").unwrap();

    let mut chain_b = RevocationChain::new(ZONE);
    let rev_b = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [0xD1; 32],
        ZONE,
    );
    chain_b.append(rev_b, &sk, "t").unwrap();

    assert_ne!(chain_a.chain_hash(), chain_b.chain_hash());
}

// ===========================================================================
// Enrichment: Large chain verify
// ===========================================================================

#[test]
fn large_chain_50_events_verifies() {
    let mut chain = RevocationChain::new(ZONE);
    let sk = signing_key();
    for i in 0..50u16 {
        let mut target = [0u8; 32];
        target[0] = (i & 0xFF) as u8;
        target[1] = (i >> 8) as u8;
        target[2] = 0xE0; // namespace to avoid collisions
        let rev = make_revocation(
            RevocationTargetType::Token,
            RevocationReason::Expired,
            target,
            ZONE,
        );
        chain.append(rev, &sk, &format!("t-{i}")).unwrap();
    }
    assert_eq!(chain.len(), 50);
    assert!(chain.verify_chain("t-large").is_ok());
    let vk = sk.verification_key();
    assert!(chain.verify_head_signature(&vk).is_ok());
}

// ===========================================================================
// Enrichment: Full pipeline — append, verify, lookup, rebuild
// ===========================================================================

#[test]
fn full_pipeline_append_verify_lookup_rebuild() {
    let mut chain = RevocationChain::new(ZONE);
    let sk = signing_key();
    let vk = sk.verification_key();

    for i in 0..5u8 {
        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [i + 0xF0; 32],
            ZONE,
        );
        chain.append(rev, &sk, &format!("t-{i}")).unwrap();
    }

    assert!(chain.verify_chain("t-verify").is_ok());
    assert!(chain.verify_head_signature(&vk).is_ok());

    for i in 0..5u8 {
        assert!(chain.is_revoked(&EngineObjectId([i + 0xF0; 32])));
        let rev = chain
            .lookup_revocation(&EngineObjectId([i + 0xF0; 32]))
            .unwrap();
        assert_eq!(rev.target_type, RevocationTargetType::Key);
        assert_eq!(rev.reason, RevocationReason::Compromised);
    }

    let events = chain.events().to_vec();
    let head = chain.head().cloned();
    let rebuilt = RevocationChain::rebuild_from_events(ZONE, events, head).unwrap();
    assert_eq!(rebuilt.len(), chain.len());
    assert_eq!(rebuilt.chain_hash(), chain.chain_hash());
}

// ===========================================================================
// Enrichment: Rebuilt chain lookups match original
// ===========================================================================

#[test]
fn rebuilt_chain_lookups_match_original() {
    let mut chain = RevocationChain::new(ZONE);
    let sk = signing_key();
    let targets: Vec<[u8; 32]> = (0..8u8)
        .map(|i| {
            let mut t = [0u8; 32];
            t[0] = i;
            t[1] = 0xFA;
            t
        })
        .collect();
    for t in &targets {
        let rev = make_revocation(
            RevocationTargetType::Extension,
            RevocationReason::Superseded,
            *t,
            ZONE,
        );
        chain.append(rev, &sk, "t").unwrap();
    }

    let events = chain.events().to_vec();
    let head = chain.head().cloned();
    let rebuilt = RevocationChain::rebuild_from_events(ZONE, events, head).unwrap();

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

// ===========================================================================
// Enrichment: Duplicate target emits AppendRejected audit event
// ===========================================================================

#[test]
fn duplicate_target_emits_append_rejected() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [0xFA; 32]);
    chain.drain_events();
    let rev2 = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Administrative,
        [0xFA; 32],
        ZONE,
    );
    let sk = signing_key();
    let _ = chain.append(rev2, &sk, "trace-dup");
    let events = chain.drain_events();
    assert!(
        events
            .iter()
            .any(|e| matches!(e.event_type, ChainEventType::AppendRejected { .. }))
    );
}

// ===========================================================================
// Enrichment: is_revoked_audited records correct result for revoked target
// ===========================================================================

#[test]
fn is_revoked_audited_records_true_for_revoked_target() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Key, [0xFB; 32]);
    chain.drain_events();
    let result = chain.is_revoked_audited(&EngineObjectId([0xFB; 32]), "t-audit");
    assert!(result);
    let events = chain.drain_events();
    assert_eq!(events.len(), 1);
    match &events[0].event_type {
        ChainEventType::RevocationLookup {
            target_id,
            is_revoked,
        } => {
            assert_eq!(*target_id, EngineObjectId([0xFB; 32]));
            assert!(*is_revoked);
        }
        other => panic!("expected RevocationLookup, got {other:?}"),
    }
}

// ===========================================================================
// Enrichment: get_event returns None for out-of-range
// ===========================================================================

#[test]
fn get_event_returns_none_for_out_of_range() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [0xFC; 32]);
    assert!(chain.get_event(0).is_some());
    assert!(chain.get_event(1).is_none());
    assert!(chain.get_event(u64::MAX).is_none());
}

// ===========================================================================
// Enrichment: verify_chain_mut on empty chain still emits audit
// ===========================================================================

#[test]
fn verify_chain_mut_empty_emits_chain_verified() {
    let mut chain = RevocationChain::new(ZONE);
    chain.verify_chain_mut("t-empty-verify").unwrap();
    let events = chain.drain_events();
    assert!(events.iter().any(|e| matches!(
        e.event_type,
        ChainEventType::ChainVerified { chain_length: 0 }
    )));
}

// ===========================================================================
// Enrichment: Multiple drains are idempotent
// ===========================================================================

#[test]
fn multiple_drains_idempotent() {
    let mut chain = RevocationChain::new(ZONE);
    append_revocation(&mut chain, RevocationTargetType::Token, [0xFD; 32]);
    let first = chain.drain_events();
    assert!(!first.is_empty());
    let second = chain.drain_events();
    assert!(second.is_empty());
    let third = chain.drain_events();
    assert!(third.is_empty());
}

// ===========================================================================
// Enrichment: Chain with all reasons preserves each reason in lookup
// ===========================================================================

#[test]
fn all_reasons_preserved_in_lookup() {
    let mut chain = RevocationChain::new(ZONE);
    let sk = signing_key();
    let reasons = [
        RevocationReason::Compromised,
        RevocationReason::Expired,
        RevocationReason::Superseded,
        RevocationReason::PolicyViolation,
        RevocationReason::Administrative,
    ];
    for (i, reason) in reasons.iter().enumerate() {
        let mut target = [0u8; 32];
        target[0] = i as u8;
        target[1] = 0xFE;
        let rev = make_revocation(RevocationTargetType::Key, *reason, target, ZONE);
        chain.append(rev, &sk, &format!("t-{i}")).unwrap();
    }
    for (i, reason) in reasons.iter().enumerate() {
        let mut target = [0u8; 32];
        target[0] = i as u8;
        target[1] = 0xFE;
        let found = chain.lookup_revocation(&EngineObjectId(target)).unwrap();
        assert_eq!(found.reason, *reason);
    }
}

// ===========================================================================
// Enrichment: Revocation clone and Debug
// ===========================================================================

#[test]
fn revocation_clone_equals_original() {
    let rev = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Superseded,
        [0xE0; 32],
        ZONE,
    );
    let cloned = rev.clone();
    assert_eq!(rev, cloned);
}

#[test]
fn revocation_debug_is_nonempty() {
    let rev = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Superseded,
        [0xE1; 32],
        ZONE,
    );
    let s = format!("{:?}", rev);
    assert!(!s.is_empty());
    assert!(s.contains("Revocation"), "{s}");
}

// ===========================================================================
// Enrichment: RevocationEvent clone and Debug
// ===========================================================================

#[test]
fn revocation_event_clone_equals_original() {
    let rev = make_revocation(
        RevocationTargetType::Key,
        RevocationReason::Compromised,
        [0xE2; 32],
        ZONE,
    );
    let event = RevocationEvent {
        event_id: EngineObjectId([0xE3; 32]),
        revocation: rev,
        prev_event: None,
        event_seq: 0,
    };
    let cloned = event.clone();
    assert_eq!(event, cloned);
}

// ===========================================================================
// Enrichment: RevocationHead clone and Debug
// ===========================================================================

#[test]
fn revocation_head_clone_equals_original() {
    let head = RevocationHead {
        head_id: EngineObjectId([0xE4; 32]),
        latest_event: EngineObjectId([0xE5; 32]),
        head_seq: 10,
        chain_hash: ContentHash::compute(b"clone-test"),
        zone: ZONE.to_string(),
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };
    let cloned = head.clone();
    assert_eq!(head, cloned);
}

#[test]
fn revocation_head_debug_is_nonempty() {
    let head = RevocationHead {
        head_id: EngineObjectId([0xE6; 32]),
        latest_event: EngineObjectId([0xE7; 32]),
        head_seq: 0,
        chain_hash: ContentHash::compute(b"debug-test"),
        zone: ZONE.to_string(),
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };
    let s = format!("{:?}", head);
    assert!(!s.is_empty());
    assert!(s.contains("RevocationHead"), "{s}");
}

// ===========================================================================
// Enrichment: verify_head_signature after multiple appends
// ===========================================================================

#[test]
fn verify_head_signature_valid_after_multiple_appends() {
    let mut chain = RevocationChain::new(ZONE);
    let sk = signing_key();
    let vk = sk.verification_key();
    for i in 0..10u8 {
        let mut target = [0u8; 32];
        target[0] = i;
        target[1] = 0xE8;
        let rev = make_revocation(
            RevocationTargetType::Attestation,
            RevocationReason::Administrative,
            target,
            ZONE,
        );
        chain.append(rev, &sk, &format!("t-{i}")).unwrap();
    }
    assert!(chain.verify_head_signature(&vk).is_ok());
}

// ===========================================================================
// Enrichment: head latest_event matches last event's id
// ===========================================================================

#[test]
fn head_latest_event_matches_last_event_id() {
    let mut chain = RevocationChain::new(ZONE);
    for i in 0..3u8 {
        let mut target = [0u8; 32];
        target[0] = i;
        target[1] = 0xE9;
        append_revocation(&mut chain, RevocationTargetType::Checkpoint, target);
    }
    let head = chain.head().unwrap();
    let last_event = chain.events().last().unwrap();
    assert_eq!(head.latest_event, last_event.event_id);
    assert_eq!(head.head_seq, last_event.event_seq);
}
