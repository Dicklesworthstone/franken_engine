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
    let h0 = chain.chain_hash().clone();
    append_revocation(&mut chain, RevocationTargetType::Token, [1; 32]);
    let h1 = chain.chain_hash().clone();
    append_revocation(&mut chain, RevocationTargetType::Token, [2; 32]);
    let h2 = chain.chain_hash().clone();
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
