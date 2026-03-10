//! Comprehensive conformance test suite for security-critical primitives.
//!
//! This is a mandatory release blocker: no release ships without 100% pass.
//!
//! Covers: canonical serialization, ID derivation, signatures, multi-signature
//! ordering, revocation chain integrity, revocation freshness, epoch ordering,
//! trust zones, hash tiers, evidence ledger, and audit chain integrity.
//!
//! Plan references: Section 10.10 item 25, 9E.10.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::canonical_encoding::CanonicalGuard;
use frankenengine_engine::deterministic_serde::{self, CanonicalValue, SchemaHash, SchemaRegistry};
use frankenengine_engine::engine_object_id::{
    EngineObjectId, IdError, ObjectDomain, SchemaId, derive_id, verify_id,
};
use frankenengine_engine::evidence_ledger::{
    ChosenAction, DecisionType, EvidenceEmitter, EvidenceEntryBuilder, InMemoryLedger,
    SchemaVersionExt,
};
use frankenengine_engine::fork_detection::ForkDetector;
use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash, IntegrityHash};
use frankenengine_engine::revocation_chain::{
    ChainError, Revocation, RevocationChain, RevocationReason, RevocationTargetType,
};
use frankenengine_engine::revocation_freshness::{
    FreshnessConfig, FreshnessState, OperationType, RevocationFreshnessController,
};
use frankenengine_engine::security_epoch::{
    EpochMetadata, EpochTracker, EpochValidationError, SecurityEpoch, TransitionReason,
};
use frankenengine_engine::signature_preimage::{
    SIGNATURE_LEN, SIGNATURE_SENTINEL, Signature, SignatureError, SignaturePreimage, SigningKey,
    VerificationKey, sign_preimage, verify_signature,
};
use frankenengine_engine::sorted_multisig::{MultiSigError, SignerSignature, SortedSignatureArray};
use frankenengine_engine::trust_zone::{TrustZoneClass, ZoneCreateRequest, ZoneHierarchy};

// =========================================================================
// 1. Canonical Serialization Conformance
// =========================================================================

#[test]
fn conformance_canonical_round_trip_deterministic() {
    let value = CanonicalValue::Map({
        let mut m = BTreeMap::new();
        m.insert("alpha".to_string(), CanonicalValue::U64(42));
        m.insert("beta".to_string(), CanonicalValue::String("hello".into()));
        m.insert("gamma".to_string(), CanonicalValue::Bytes(vec![1, 2, 3, 4]));
        m
    });
    let encoded = deterministic_serde::encode_value(&value);
    let decoded = deterministic_serde::decode_value(&encoded).expect("decode");
    let re_encoded = deterministic_serde::encode_value(&decoded);
    assert_eq!(encoded, re_encoded, "round-trip must be byte-identical");
}

#[test]
fn conformance_canonical_guard_registered_class_validates() {
    let mut guard = CanonicalGuard::new();
    let schema = guard.register_class(
        ObjectDomain::PolicyObject,
        "TestObject",
        1,
        b"test-object-schema",
    );
    assert!(guard.is_class_registered(&ObjectDomain::PolicyObject));

    let value = CanonicalValue::Map({
        let mut m = BTreeMap::new();
        m.insert("field_a".to_string(), CanonicalValue::U64(100));
        m
    });
    let bytes = deterministic_serde::serialize_with_schema(&schema, &value);
    let result = guard.validate(ObjectDomain::PolicyObject, &bytes, "trace-001");
    assert!(result.is_ok(), "canonical bytes should pass validation");
    assert!(guard.acceptance_count() > 0);
}

#[test]
fn conformance_canonical_guard_rejects_unregistered_class() {
    let mut guard = CanonicalGuard::new();
    let bytes = vec![1, 2, 3];
    let result = guard.validate(ObjectDomain::EvidenceRecord, &bytes, "trace-002");
    assert!(result.is_err(), "unregistered class should be rejected");
}

#[test]
fn conformance_canonical_schema_hash_prefix_deterministic() {
    let h1 = SchemaHash::from_definition(b"TestSchema.v1");
    let h2 = SchemaHash::from_definition(b"TestSchema.v1");
    assert_eq!(h1, h2);

    let h3 = SchemaHash::from_definition(b"TestSchema.v2");
    assert_ne!(h1, h3);
}

#[test]
fn conformance_canonical_lexicographic_key_ordering() {
    let value = CanonicalValue::Map({
        let mut m = BTreeMap::new();
        m.insert("z_last".to_string(), CanonicalValue::U64(1));
        m.insert("a_first".to_string(), CanonicalValue::U64(2));
        m
    });
    let encoded = deterministic_serde::encode_value(&value);
    let decoded = deterministic_serde::decode_value(&encoded).expect("decode");
    if let CanonicalValue::Map(map) = decoded {
        let keys: Vec<_> = map.keys().collect();
        assert_eq!(keys, vec!["a_first", "z_last"]);
    } else {
        panic!("expected map");
    }
}

#[test]
fn conformance_canonical_null_and_bool_encode_stably() {
    let null_bytes = deterministic_serde::encode_value(&CanonicalValue::Null);
    let true_bytes = deterministic_serde::encode_value(&CanonicalValue::Bool(true));
    let false_bytes = deterministic_serde::encode_value(&CanonicalValue::Bool(false));

    assert_ne!(null_bytes, true_bytes);
    assert_ne!(true_bytes, false_bytes);

    assert_eq!(
        deterministic_serde::decode_value(&null_bytes).unwrap(),
        CanonicalValue::Null
    );
    assert_eq!(
        deterministic_serde::decode_value(&true_bytes).unwrap(),
        CanonicalValue::Bool(true)
    );
}

// =========================================================================
// 2. ID Derivation Conformance
// =========================================================================

#[test]
fn conformance_id_derivation_deterministic() {
    let schema = SchemaId::from_definition(b"test.schema.v1");
    let id1 = derive_id(ObjectDomain::PolicyObject, "zone-a", &schema, b"payload").expect("derive");
    let id2 = derive_id(ObjectDomain::PolicyObject, "zone-a", &schema, b"payload").expect("derive");
    assert_eq!(id1, id2, "same inputs must produce same ID");
}

#[test]
fn conformance_id_derivation_domain_separation() {
    let schema = SchemaId::from_definition(b"test.schema.v1");
    let id_policy =
        derive_id(ObjectDomain::PolicyObject, "zone", &schema, b"data").expect("derive");
    let id_evidence =
        derive_id(ObjectDomain::EvidenceRecord, "zone", &schema, b"data").expect("derive");
    assert_ne!(
        id_policy, id_evidence,
        "different domains must produce different IDs"
    );
}

#[test]
fn conformance_id_derivation_zone_separation() {
    let schema = SchemaId::from_definition(b"test.schema.v1");
    let id_a = derive_id(ObjectDomain::PolicyObject, "zone-a", &schema, b"data").expect("derive");
    let id_b = derive_id(ObjectDomain::PolicyObject, "zone-b", &schema, b"data").expect("derive");
    assert_ne!(id_a, id_b, "different zones must produce different IDs");
}

#[test]
fn conformance_id_derivation_schema_separation() {
    let schema_a = SchemaId::from_definition(b"schema.a.v1");
    let schema_b = SchemaId::from_definition(b"schema.b.v1");
    let id_a = derive_id(ObjectDomain::PolicyObject, "zone", &schema_a, b"data").expect("derive");
    let id_b = derive_id(ObjectDomain::PolicyObject, "zone", &schema_b, b"data").expect("derive");
    assert_ne!(id_a, id_b, "different schemas must produce different IDs");
}

#[test]
fn conformance_id_derivation_rejects_empty_canonical_bytes() {
    let schema = SchemaId::from_definition(b"test.schema.v1");
    let result = derive_id(ObjectDomain::PolicyObject, "zone", &schema, b"");
    assert_eq!(
        result.unwrap_err(),
        IdError::EmptyCanonicalBytes,
        "empty canonical bytes must be rejected"
    );
}

#[test]
fn conformance_id_verify_matches_derive() {
    let schema = SchemaId::from_definition(b"test.schema.v1");
    let id = derive_id(ObjectDomain::Revocation, "zone", &schema, b"payload").expect("derive");
    verify_id(&id, ObjectDomain::Revocation, "zone", &schema, b"payload")
        .expect("verify must pass for matching inputs");
}

#[test]
fn conformance_id_verify_rejects_tampered() {
    let schema = SchemaId::from_definition(b"test.schema.v1");
    let id = derive_id(ObjectDomain::Revocation, "zone", &schema, b"payload").expect("derive");
    let result = verify_id(&id, ObjectDomain::Revocation, "zone", &schema, b"tampered");
    assert!(
        matches!(result, Err(IdError::IdMismatch { .. })),
        "tampered payload must be rejected"
    );
}

#[test]
fn conformance_id_hex_round_trip() {
    let schema = SchemaId::from_definition(b"test.schema.v1");
    let id = derive_id(ObjectDomain::PolicyObject, "zone", &schema, b"data").expect("derive");
    let hex = id.to_hex();
    let restored = EngineObjectId::from_hex(&hex).expect("from_hex");
    assert_eq!(id, restored, "hex round-trip must be lossless");
}

#[test]
fn conformance_id_all_domains_produce_distinct_tags() {
    let tags: BTreeSet<Vec<u8>> = ObjectDomain::ALL.iter().map(|d| d.tag().to_vec()).collect();
    assert_eq!(
        tags.len(),
        ObjectDomain::ALL.len(),
        "every domain must have a unique tag"
    );
}

// =========================================================================
// 3. Signature Verification Conformance
// =========================================================================

fn test_signing_key(seed: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    bytes[31] = seed.wrapping_add(1);
    SigningKey::from_bytes(bytes)
}

#[test]
fn conformance_signature_sign_verify_round_trip() {
    let sk = test_signing_key(1);
    let vk = sk.verification_key();
    let message = b"conformance-test-message";

    let sig = sign_preimage(&sk, message).expect("sign");
    verify_signature(&vk, message, &sig).expect("verify must pass");
}

#[test]
fn conformance_signature_rejects_wrong_key() {
    let sk1 = test_signing_key(1);
    let sk2 = test_signing_key(2);
    let vk2 = sk2.verification_key();
    let message = b"conformance-test-message";

    let sig = sign_preimage(&sk1, message).expect("sign");
    let result = verify_signature(&vk2, message, &sig);
    assert!(result.is_err(), "wrong key must fail verification");
}

#[test]
fn conformance_signature_rejects_tampered_message() {
    let sk = test_signing_key(3);
    let vk = sk.verification_key();
    let message = b"original-message";

    let sig = sign_preimage(&sk, message).expect("sign");
    let result = verify_signature(&vk, b"tampered-message", &sig);
    assert!(result.is_err(), "tampered message must fail verification");
}

#[test]
fn conformance_signature_sentinel_is_all_zeros() {
    assert_eq!(
        SIGNATURE_SENTINEL, [0u8; SIGNATURE_LEN],
        "sentinel must be 64 zero bytes"
    );
    let sig = Signature::from_bytes(SIGNATURE_SENTINEL);
    assert!(sig.is_sentinel(), "sentinel signature must be detected");
}

#[test]
fn conformance_signature_non_sentinel_detected() {
    let mut bytes = [0u8; SIGNATURE_LEN];
    bytes[0] = 1;
    let sig = Signature::from_bytes(bytes);
    assert!(!sig.is_sentinel(), "non-zero sig must not be sentinel");
}

#[test]
fn conformance_signing_key_derives_deterministic_vk() {
    let sk = test_signing_key(5);
    let vk1 = sk.verification_key();
    let vk2 = sk.verification_key();
    assert_eq!(vk1, vk2, "same SK must always derive same VK");
}

#[test]
fn conformance_different_signing_keys_produce_different_vks() {
    let sk1 = test_signing_key(10);
    let sk2 = test_signing_key(20);
    assert_ne!(
        sk1.verification_key(),
        sk2.verification_key(),
        "distinct SKs must produce distinct VKs"
    );
}

#[test]
fn conformance_signature_bytes_round_trip() {
    let sk = test_signing_key(6);
    let sig = sign_preimage(&sk, b"round-trip").expect("sign");
    let bytes = sig.to_bytes();
    let restored = Signature::from_bytes(bytes);
    assert_eq!(sig, restored, "signature bytes round-trip must be lossless");
}

// =========================================================================
// 4. Multi-Signature Ordering Conformance
// =========================================================================

fn make_signer_sig(seed: u8, message: &[u8]) -> SignerSignature {
    let sk = test_signing_key(seed);
    let vk = sk.verification_key();
    let sig = sign_preimage(&sk, message).expect("sign");
    SignerSignature::new(vk, sig)
}

#[test]
fn conformance_sorted_multisig_maintains_order() {
    let msg = b"multisig-conformance";
    let s1 = make_signer_sig(10, msg);
    let s2 = make_signer_sig(20, msg);
    let s3 = make_signer_sig(30, msg);

    let arr = SortedSignatureArray::from_unsorted(vec![s3, s1, s2]).expect("sort");
    let keys: Vec<_> = arr.entries().iter().map(|e| e.signer.clone()).collect();
    for w in keys.windows(2) {
        assert!(w[0] <= w[1], "array must be sorted by verification key");
    }
}

#[test]
fn conformance_sorted_multisig_rejects_duplicate_signer() {
    let msg = b"dup-test";
    let s1 = make_signer_sig(10, msg);
    let s2 = make_signer_sig(10, msg);

    let result = SortedSignatureArray::from_unsorted(vec![s1, s2]);
    assert!(
        matches!(result, Err(MultiSigError::DuplicateSignerKey { .. })),
        "duplicate signer must be rejected"
    );
}

#[test]
fn conformance_sorted_multisig_rejects_empty_array() {
    let result = SortedSignatureArray::from_unsorted(vec![]);
    assert!(
        matches!(result, Err(MultiSigError::EmptyArray)),
        "empty array must be rejected"
    );
}

#[test]
fn conformance_sorted_multisig_quorum_verification() {
    let msg = b"quorum-test";
    let sk1 = test_signing_key(40);
    let sk2 = test_signing_key(50);
    let sk3 = test_signing_key(60);

    let s1 = make_signer_sig(40, msg);
    let s2 = make_signer_sig(50, msg);
    let s3 = make_signer_sig(60, msg);

    let authorized: Vec<VerificationKey> = vec![
        sk1.verification_key(),
        sk2.verification_key(),
        sk3.verification_key(),
    ];

    let arr = SortedSignatureArray::from_unsorted(vec![s1, s2, s3]).expect("sort");
    let result = arr
        .verify_quorum(2, &authorized, |vk, sig| verify_signature(vk, msg, sig))
        .expect("quorum");
    assert!(result.valid_count >= 2, "quorum of 2 must be met");
}

#[test]
fn conformance_sorted_multisig_quorum_not_met() {
    let msg = b"quorum-fail-test";
    let sk = test_signing_key(70);
    let vk = sk.verification_key();
    let sig = sign_preimage(&sk, b"wrong-message").expect("sign");
    let s1 = SignerSignature::new(vk.clone(), sig);

    let authorized = vec![vk];
    let arr = SortedSignatureArray::from_unsorted(vec![s1]).expect("sort");
    let result = arr.verify_quorum(1, &authorized, |vk, sig| verify_signature(vk, msg, sig));
    assert!(
        matches!(result, Err(MultiSigError::QuorumNotMet { .. })),
        "bad signatures must not meet quorum"
    );
}

#[test]
fn conformance_sorted_multisig_contains_signer() {
    let msg = b"contains-test";
    let s1 = make_signer_sig(40, msg);
    let s2 = make_signer_sig(50, msg);
    let vk1 = s1.signer.clone();
    let vk_missing = test_signing_key(99).verification_key();

    let arr = SortedSignatureArray::from_unsorted(vec![s1, s2]).expect("sort");
    assert!(arr.contains_signer(&vk1));
    assert!(!arr.contains_signer(&vk_missing));
}

// =========================================================================
// 5. Revocation Chain Conformance
// =========================================================================

use frankenengine_engine::capability_token::PrincipalId;
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;

fn make_revocation(target_seed: u8, zone: &str, sk: &SigningKey) -> Revocation {
    let schema = SchemaId::from_definition(b"test.revocation.v1");
    let target_id = derive_id(ObjectDomain::CapabilityToken, zone, &schema, &[target_seed])
        .expect("derive target id");

    let rev_id = derive_id(
        ObjectDomain::Revocation,
        zone,
        &schema,
        &[target_seed, 0xFF],
    )
    .expect("derive revocation id");

    let vk = sk.verification_key();
    let principal = PrincipalId::from_verification_key(&vk);

    let mut rev = Revocation {
        revocation_id: rev_id,
        target_type: RevocationTargetType::Token,
        target_id,
        reason: RevocationReason::Compromised,
        issued_by: principal,
        issued_at: DeterministicTimestamp(1000),
        zone: zone.to_string(),
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };

    let preimage = rev.preimage_bytes();
    rev.signature = sign_preimage(sk, &preimage).expect("sign revocation");
    rev
}

#[test]
fn conformance_revocation_chain_append_only() {
    let sk = test_signing_key(80);
    let mut chain = RevocationChain::new("test-zone");

    let rev = make_revocation(1, "test-zone", &sk);
    let seq = chain.append(rev, &sk, "trace-001").expect("append");
    assert_eq!(seq, 0, "first event must be seq 0");
    assert_eq!(chain.len(), 1);
}

#[test]
fn conformance_revocation_chain_monotonic_head() {
    let sk = test_signing_key(81);
    let mut chain = RevocationChain::new("test-zone");

    chain
        .append(make_revocation(1, "test-zone", &sk), &sk, "t1")
        .expect("append 1");
    chain
        .append(make_revocation(2, "test-zone", &sk), &sk, "t2")
        .expect("append 2");
    chain
        .append(make_revocation(3, "test-zone", &sk), &sk, "t3")
        .expect("append 3");

    assert_eq!(chain.head_seq(), Some(2));
    let events = chain.events();
    for (i, ev) in events.iter().enumerate() {
        assert_eq!(ev.event_seq, i as u64);
    }
}

#[test]
fn conformance_revocation_chain_is_revoked_lookup() {
    let sk = test_signing_key(82);
    let mut chain = RevocationChain::new("test-zone");

    let rev = make_revocation(10, "test-zone", &sk);
    let target_id = rev.target_id.clone();
    chain.append(rev, &sk, "t1").expect("append");

    assert!(chain.is_revoked(&target_id), "revoked target must be found");

    let schema = SchemaId::from_definition(b"test.revocation.v1");
    let not_revoked =
        derive_id(ObjectDomain::CapabilityToken, "test-zone", &schema, &[99]).expect("derive");
    assert!(
        !chain.is_revoked(&not_revoked),
        "non-revoked target must not be found"
    );
}

#[test]
fn conformance_revocation_chain_rejects_duplicate_target() {
    let sk = test_signing_key(83);
    let mut chain = RevocationChain::new("test-zone");

    let rev = make_revocation(20, "test-zone", &sk);
    chain.append(rev.clone(), &sk, "t1").expect("append");

    let schema = SchemaId::from_definition(b"test.revocation.v1");
    let rev_id2 =
        derive_id(ObjectDomain::Revocation, "test-zone", &schema, &[20, 0xFE]).expect("derive");

    let mut rev2 = rev;
    rev2.revocation_id = rev_id2;
    rev2.signature = Signature::from_bytes(SIGNATURE_SENTINEL);
    let preimage = rev2.preimage_bytes();
    rev2.signature = sign_preimage(&sk, &preimage).expect("sign");

    let result = chain.append(rev2, &sk, "t2");
    assert!(
        matches!(result, Err(ChainError::DuplicateTarget { .. })),
        "duplicate target must be rejected"
    );
}

#[test]
fn conformance_revocation_chain_hash_linking() {
    let sk = test_signing_key(84);
    let mut chain = RevocationChain::new("test-zone");

    chain
        .append(make_revocation(30, "test-zone", &sk), &sk, "t1")
        .expect("append 1");
    let hash_after_1 = chain.chain_hash().clone();

    chain
        .append(make_revocation(31, "test-zone", &sk), &sk, "t2")
        .expect("append 2");
    let hash_after_2 = chain.chain_hash().clone();

    assert_ne!(
        hash_after_1, hash_after_2,
        "chain hash must change after append"
    );

    let events = chain.events();
    assert!(events[0].prev_event.is_none(), "genesis has no prev");
    assert_eq!(
        events[1].prev_event.as_ref(),
        Some(&events[0].event_id),
        "second event must link to first"
    );
}

#[test]
fn conformance_revocation_chain_zone_mismatch_rejected() {
    let sk = test_signing_key(85);
    let mut chain = RevocationChain::new("zone-a");

    let rev = make_revocation(40, "zone-b", &sk);
    let result = chain.append(rev, &sk, "t1");
    assert!(
        matches!(result, Err(ChainError::ChainIntegrity { .. })),
        "zone mismatch must be rejected"
    );
}

#[test]
fn conformance_revocation_chain_lookup_returns_revocation() {
    let sk = test_signing_key(86);
    let mut chain = RevocationChain::new("test-zone");

    let rev = make_revocation(50, "test-zone", &sk);
    let target_id = rev.target_id.clone();
    chain.append(rev, &sk, "t1").expect("append");

    let looked_up = chain.lookup_revocation(&target_id);
    assert!(looked_up.is_some(), "must find the revocation");
    assert_eq!(looked_up.unwrap().reason, RevocationReason::Compromised);
}

// =========================================================================
// 6. Revocation Freshness Conformance
// =========================================================================

#[test]
fn conformance_freshness_initial_state_is_fresh() {
    let config = FreshnessConfig {
        staleness_threshold: 5,
        holdoff_ticks: 3,
        override_eligible: BTreeSet::from([OperationType::TokenAcceptance]),
        authorized_operators: BTreeSet::new(),
    };
    let ctrl = RevocationFreshnessController::new(config, "zone");
    assert_eq!(ctrl.state(), FreshnessState::Fresh);
}

#[test]
fn conformance_freshness_staleness_detection() {
    let config = FreshnessConfig {
        staleness_threshold: 5,
        holdoff_ticks: 1,
        override_eligible: BTreeSet::new(),
        authorized_operators: BTreeSet::new(),
    };
    let mut ctrl = RevocationFreshnessController::new(config, "zone");

    // Gap=3 within threshold=5: Fresh → Stale
    ctrl.update_expected_head(3, "trace-1");
    let state = ctrl.check_freshness("trace-2");
    assert_eq!(
        state,
        FreshnessState::Stale,
        "0 < gap <= threshold => Stale"
    );
}

#[test]
fn conformance_freshness_safe_ops_evaluated() {
    let config = FreshnessConfig {
        staleness_threshold: 2,
        holdoff_ticks: 1,
        override_eligible: BTreeSet::new(),
        authorized_operators: BTreeSet::new(),
    };
    let mut ctrl = RevocationFreshnessController::new(config, "zone");

    ctrl.update_expected_head(5, "t1");
    ctrl.check_freshness("t2");

    let decision = ctrl.evaluate(OperationType::SafeOperation, "t3");
    assert!(decision.is_ok(), "safe ops must succeed");
}

#[test]
fn conformance_freshness_recovery_after_catchup() {
    let config = FreshnessConfig {
        staleness_threshold: 2,
        holdoff_ticks: 1,
        override_eligible: BTreeSet::new(),
        authorized_operators: BTreeSet::new(),
    };
    let mut ctrl = RevocationFreshnessController::new(config, "zone");

    // Gap=5 > threshold=2: Fresh → Degraded
    ctrl.update_expected_head(5, "t1");
    ctrl.check_freshness("t2");
    assert_eq!(ctrl.state(), FreshnessState::Degraded);

    // Catch up: gap=0 <= threshold → Degraded → Recovering
    ctrl.update_local_head(5, "t3");
    let state = ctrl.check_freshness("t4");
    assert_ne!(
        state,
        FreshnessState::Degraded,
        "catching up must exit Degraded"
    );
}

#[test]
fn conformance_freshness_is_fresh_and_is_degraded() {
    let config = FreshnessConfig {
        staleness_threshold: 2,
        holdoff_ticks: 1,
        override_eligible: BTreeSet::new(),
        authorized_operators: BTreeSet::new(),
    };
    let ctrl = RevocationFreshnessController::new(config, "zone");
    assert!(ctrl.is_fresh(), "initial state must be fresh");
    assert!(!ctrl.is_degraded(), "initial state must not be degraded");
}

#[test]
fn conformance_freshness_staleness_gap_tracks_difference() {
    let config = FreshnessConfig {
        staleness_threshold: 5,
        holdoff_ticks: 1,
        override_eligible: BTreeSet::new(),
        authorized_operators: BTreeSet::new(),
    };
    let mut ctrl = RevocationFreshnessController::new(config, "zone");
    assert_eq!(ctrl.staleness_gap(), 0);

    ctrl.update_expected_head(10, "t1");
    assert_eq!(ctrl.staleness_gap(), 10);

    ctrl.update_local_head(7, "t2");
    assert_eq!(ctrl.staleness_gap(), 3);
}

// =========================================================================
// 7. Epoch Ordering Conformance
// =========================================================================

#[test]
fn conformance_epoch_genesis_is_zero() {
    assert_eq!(SecurityEpoch::GENESIS.as_u64(), 0);
}

#[test]
fn conformance_epoch_monotonic_advance() {
    let mut tracker = EpochTracker::new();
    assert_eq!(tracker.current(), SecurityEpoch::GENESIS);

    let e1 = tracker
        .advance(TransitionReason::PolicyKeyRotation, "t1")
        .expect("advance");
    assert_eq!(e1.as_u64(), 1);

    let e2 = tracker
        .advance(TransitionReason::RevocationFrontierAdvance, "t2")
        .expect("advance");
    assert_eq!(e2.as_u64(), 2);

    assert!(e2 > e1, "epochs must be strictly monotonic");
}

#[test]
fn conformance_epoch_validates_current_artifact() {
    let mut tracker = EpochTracker::new();
    tracker
        .advance(TransitionReason::PolicyKeyRotation, "t1")
        .expect("advance");

    let meta = EpochMetadata::open_ended(SecurityEpoch::from_raw(1));
    tracker
        .validate_artifact(&meta)
        .expect("current-epoch artifact must be valid");
}

#[test]
fn conformance_epoch_rejects_future_artifact() {
    let tracker = EpochTracker::new();

    let meta = EpochMetadata::open_ended(SecurityEpoch::from_raw(5));
    let errs = tracker.validate_artifact(&meta).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| matches!(e, EpochValidationError::FutureArtifact { .. })),
        "future artifact must be rejected"
    );
}

#[test]
fn conformance_epoch_rejects_expired_artifact() {
    let mut tracker = EpochTracker::new();
    for _ in 0..5 {
        tracker
            .advance(TransitionReason::GuardrailConfigChange, "t")
            .expect("advance");
    }

    let meta = EpochMetadata::windowed(
        SecurityEpoch::from_raw(1),
        SecurityEpoch::from_raw(1),
        SecurityEpoch::from_raw(3),
    );
    let errs = tracker.validate_artifact(&meta).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| matches!(e, EpochValidationError::Expired { .. })),
        "expired artifact must be rejected"
    );
}

#[test]
fn conformance_epoch_rejects_not_yet_valid() {
    let tracker = EpochTracker::new();

    let meta = EpochMetadata::windowed(
        SecurityEpoch::from_raw(0),
        SecurityEpoch::from_raw(3),
        SecurityEpoch::from_raw(10),
    );
    let errs = tracker.validate_artifact(&meta).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| matches!(e, EpochValidationError::NotYetValid { .. })),
        "not-yet-valid artifact must be rejected"
    );
}

#[test]
fn conformance_epoch_rejects_inverted_window() {
    let mut tracker = EpochTracker::new();
    tracker
        .advance(TransitionReason::PolicyKeyRotation, "t1")
        .expect("advance");

    let meta = EpochMetadata::windowed(
        SecurityEpoch::from_raw(1),
        SecurityEpoch::from_raw(5),
        SecurityEpoch::from_raw(2),
    );
    let errs = tracker.validate_artifact(&meta).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| matches!(e, EpochValidationError::InvertedWindow { .. })),
        "inverted window must be rejected"
    );
}

#[test]
fn conformance_epoch_verify_persisted_accepts_higher() {
    let mut tracker = EpochTracker::new();
    tracker
        .verify_persisted(SecurityEpoch::from_raw(10))
        .expect("higher persisted epoch must be accepted");
    assert_eq!(tracker.current(), SecurityEpoch::from_raw(10));
}

#[test]
fn conformance_epoch_verify_persisted_rejects_lower() {
    let mut tracker = EpochTracker::new();
    tracker
        .advance(TransitionReason::PolicyKeyRotation, "t1")
        .expect("advance");

    let result = tracker.verify_persisted(SecurityEpoch::GENESIS);
    assert!(
        result.is_err(),
        "lower persisted epoch must be rejected as monotonicity violation"
    );
}

#[test]
fn conformance_epoch_transition_records_auditable() {
    let mut tracker = EpochTracker::new();
    tracker
        .advance(TransitionReason::PolicyKeyRotation, "trace-1")
        .expect("advance");
    tracker
        .advance(TransitionReason::LossMatrixUpdate, "trace-2")
        .expect("advance");

    let transitions = tracker.transitions();
    assert_eq!(transitions.len(), 2, "all transitions must be recorded");
    assert_eq!(transitions[0].trace_id, "trace-1");
    assert_eq!(transitions[0].reason, TransitionReason::PolicyKeyRotation);
    assert_eq!(transitions[1].trace_id, "trace-2");
}

#[test]
fn conformance_epoch_transition_count() {
    let mut tracker = EpochTracker::new();
    assert_eq!(tracker.transition_count(), 0);

    tracker
        .advance(TransitionReason::PolicyKeyRotation, "t1")
        .expect("advance");
    assert_eq!(tracker.transition_count(), 1);

    tracker
        .advance(TransitionReason::OperatorManualBump, "t2")
        .expect("advance");
    assert_eq!(tracker.transition_count(), 2);
}

#[test]
fn conformance_epoch_next_saturates() {
    let max_epoch = SecurityEpoch::from_raw(u64::MAX);
    let next = max_epoch.next();
    assert_eq!(next, max_epoch, "next() at MAX must saturate, not wrap");
}

// =========================================================================
// 8. Trust Zone Conformance
// =========================================================================

#[test]
fn conformance_trust_zone_class_ordering() {
    assert!(TrustZoneClass::Owner < TrustZoneClass::Private);
    assert!(TrustZoneClass::Private < TrustZoneClass::Team);
    assert!(TrustZoneClass::Team < TrustZoneClass::Community);
}

#[test]
fn conformance_trust_zone_ceiling_deterministic() {
    let ceiling1 = TrustZoneClass::Team.default_ceiling();
    let ceiling2 = TrustZoneClass::Team.default_ceiling();
    assert_eq!(
        ceiling1, ceiling2,
        "same zone class must produce same ceiling"
    );
}

#[test]
fn conformance_trust_zone_owner_superset() {
    let owner_ceiling = TrustZoneClass::Owner.default_ceiling();
    let team_ceiling = TrustZoneClass::Team.default_ceiling();
    assert!(
        team_ceiling.is_subset(&owner_ceiling),
        "team ceiling must be subset of owner ceiling"
    );
}

#[test]
fn conformance_trust_zone_community_most_restricted() {
    let community_ceiling = TrustZoneClass::Community.default_ceiling();
    for class in [
        TrustZoneClass::Owner,
        TrustZoneClass::Private,
        TrustZoneClass::Team,
    ] {
        let other = class.default_ceiling();
        assert!(
            community_ceiling.is_subset(&other),
            "community must be subset of {class:?}"
        );
    }
}

#[test]
fn conformance_trust_zone_hierarchy_add_zone() {
    let mut hierarchy = ZoneHierarchy::new("default");
    let req = ZoneCreateRequest::new("test-zone", TrustZoneClass::Owner, 1, "operator");
    let result = hierarchy.add_zone(req);
    assert!(result.is_ok(), "zone creation must succeed");
}

#[test]
fn conformance_trust_zone_hierarchy_standard_creates_four_zones() {
    let hierarchy = ZoneHierarchy::standard("operator", 1).expect("standard");
    for class in TrustZoneClass::ORDERED {
        let zone = hierarchy.zone(class.as_str());
        assert!(
            zone.is_some(),
            "standard hierarchy must include zone for {class:?}"
        );
    }
}

// =========================================================================
// 9. Hash Tiers Conformance
// =========================================================================

#[test]
fn conformance_hash_tiers_content_hash_deterministic() {
    let h1 = ContentHash::compute(b"deterministic data");
    let h2 = ContentHash::compute(b"deterministic data");
    assert_eq!(h1, h2, "same data must produce same content hash");
}

#[test]
fn conformance_hash_tiers_content_hash_collision_resistance() {
    let h1 = ContentHash::compute(b"data-a");
    let h2 = ContentHash::compute(b"data-b");
    assert_ne!(h1, h2, "different data must produce different hashes");
}

#[test]
fn conformance_hash_tiers_integrity_hash_deterministic() {
    let h1 = IntegrityHash::compute(b"integrity test");
    let h2 = IntegrityHash::compute(b"integrity test");
    assert_eq!(h1, h2);
}

#[test]
fn conformance_hash_tiers_authenticity_hash_keyed() {
    let h1 = AuthenticityHash::compute_keyed(b"key-a", b"data");
    let h2 = AuthenticityHash::compute_keyed(b"key-b", b"data");
    assert_ne!(
        h1, h2,
        "different keys must produce different authenticity hashes"
    );
}

#[test]
fn conformance_hash_tiers_content_hash_32_bytes() {
    let h = ContentHash::compute(b"test");
    assert_eq!(h.as_bytes().len(), 32, "content hash must be 32 bytes");
}

#[test]
fn conformance_hash_tiers_content_hash_hex_round_trip() {
    let h = ContentHash::compute(b"hex-test");
    let hex = h.to_hex();
    assert_eq!(hex.len(), 64, "hex must be 64 chars");
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
}

// =========================================================================
// 10. Evidence Ledger (Audit Chain) Conformance
// =========================================================================

#[test]
fn conformance_evidence_ledger_build_entry() {
    let entry = EvidenceEntryBuilder::new(
        "trace-001",
        "decision-1",
        "policy-1",
        SecurityEpoch::from_raw(1),
        DecisionType::SecurityAction,
    )
    .chosen(ChosenAction {
        action_name: "accept".to_string(),
        expected_loss_millionths: 0,
        rationale: "conformance test".to_string(),
    })
    .build()
    .expect("build");

    assert_eq!(entry.decision_id, "decision-1");
    assert_eq!(entry.decision_type, DecisionType::SecurityAction);
    assert_eq!(
        entry.schema_version,
        frankenengine_engine::evidence_ledger::current_schema_version()
    );
}

#[test]
fn conformance_evidence_ledger_in_memory_emit_and_query() {
    let mut ledger = InMemoryLedger::new();
    assert!(ledger.is_empty());

    let entry = EvidenceEntryBuilder::new(
        "trace-002",
        "decision-2",
        "policy-2",
        SecurityEpoch::from_raw(1),
        DecisionType::PolicyUpdate,
    )
    .chosen(ChosenAction {
        action_name: "update".to_string(),
        expected_loss_millionths: 100,
        rationale: "conformance test".to_string(),
    })
    .build()
    .expect("build");

    ledger.emit(entry).expect("emit");
    assert_eq!(ledger.len(), 1);

    let by_type = ledger.by_decision_type(DecisionType::PolicyUpdate);
    assert_eq!(by_type.len(), 1);
}

#[test]
fn conformance_evidence_ledger_schema_version_current() {
    let v = frankenengine_engine::evidence_ledger::current_schema_version();
    assert_eq!(v.major, 1, "current schema must be major version 1");
    assert!(v.is_compatible_with(&v), "version must be self-compatible");
}

// =========================================================================
// 11. Deterministic Serde Conformance
// =========================================================================

#[test]
fn conformance_deterministic_serde_value_types_round_trip() {
    let values = vec![
        CanonicalValue::Null,
        CanonicalValue::Bool(true),
        CanonicalValue::Bool(false),
        CanonicalValue::U64(0),
        CanonicalValue::U64(u64::MAX),
        CanonicalValue::I64(-1),
        CanonicalValue::I64(i64::MIN),
        CanonicalValue::String("hello world".to_string()),
        CanonicalValue::String(String::new()),
        CanonicalValue::Bytes(vec![0, 1, 2, 255]),
        CanonicalValue::Bytes(vec![]),
        CanonicalValue::Array(vec![
            CanonicalValue::U64(1),
            CanonicalValue::String("two".to_string()),
        ]),
    ];

    for (i, val) in values.iter().enumerate() {
        let encoded = deterministic_serde::encode_value(val);
        let decoded = deterministic_serde::decode_value(&encoded)
            .unwrap_or_else(|e| panic!("decode failed for value {i}: {e:?}"));
        assert_eq!(&decoded, val, "round-trip failed for value {i}: {val:?}");
    }
}

#[test]
fn conformance_deterministic_serde_nested_maps() {
    let inner = {
        let mut m = BTreeMap::new();
        m.insert("inner_key".to_string(), CanonicalValue::U64(42));
        m
    };
    let outer = {
        let mut m = BTreeMap::new();
        m.insert("nested".to_string(), CanonicalValue::Map(inner));
        m.insert("top_level".to_string(), CanonicalValue::Bool(true));
        m
    };
    let val = CanonicalValue::Map(outer);
    let encoded = deterministic_serde::encode_value(&val);
    let decoded = deterministic_serde::decode_value(&encoded).expect("decode nested");
    assert_eq!(decoded, val);
}

#[test]
fn conformance_deterministic_serde_schema_registry() {
    let mut registry = SchemaRegistry::new();
    let hash = registry.register("TestType", 1, b"test.v1");
    assert!(registry.is_known(&hash));
    let def = registry.lookup(&hash);
    assert!(def.is_some());
    assert_eq!(def.unwrap().name, "TestType");

    let unknown = SchemaHash::from_definition(b"unknown");
    assert!(registry.lookup(&unknown).is_none());
}

// =========================================================================
// 12. Fork Detection Conformance
// =========================================================================

use frankenengine_engine::fork_detection::RecordCheckpointInput;
use frankenengine_engine::policy_checkpoint::{CheckpointBuilder, PolicyHead, PolicyType};

fn make_policy_head(policy_type: PolicyType, version: u64) -> PolicyHead {
    PolicyHead {
        policy_type,
        policy_hash: ContentHash::compute(format!("policy-v{version}").as_bytes()),
        policy_version: version,
    }
}

fn build_genesis_checkpoint(
    sk: &SigningKey,
    zone: &str,
    epoch: SecurityEpoch,
) -> frankenengine_engine::policy_checkpoint::PolicyCheckpoint {
    CheckpointBuilder::genesis(epoch, DeterministicTimestamp(0), zone)
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(std::slice::from_ref(sk))
        .expect("genesis should build")
}

fn build_next_checkpoint(
    prev: &frankenengine_engine::policy_checkpoint::PolicyCheckpoint,
    seq: u64,
    sk: &SigningKey,
    zone: &str,
    epoch: SecurityEpoch,
) -> frankenengine_engine::policy_checkpoint::PolicyCheckpoint {
    CheckpointBuilder::after(prev, seq, epoch, DeterministicTimestamp(seq * 100), zone)
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, seq))
        .build(std::slice::from_ref(sk))
        .expect("checkpoint should build")
}

#[test]
fn conformance_fork_detection_new_detector_no_zones() {
    let detector = ForkDetector::new(100);
    assert!(detector.zones().is_empty(), "new detector has no zones");
}

#[test]
fn conformance_fork_detection_with_defaults() {
    let detector = ForkDetector::with_defaults();
    assert!(detector.zones().is_empty(), "default detector has no zones");
}

#[test]
fn conformance_fork_detection_safe_mode_initially_false() {
    let detector = ForkDetector::new(100);
    assert!(
        !detector.is_safe_mode("zone-1"),
        "no zone recorded => not in safe mode"
    );
}

#[test]
fn conformance_fork_detection_divergent_checkpoint_triggers_fork() {
    let sk = test_signing_key(90);
    let mut detector = ForkDetector::with_defaults();
    let zone = "fork-zone";

    let genesis = build_genesis_checkpoint(&sk, zone, SecurityEpoch::GENESIS);
    let _ = detector.record_checkpoint(&RecordCheckpointInput {
        zone,
        checkpoint: &genesis,
        accepted: true,
        frontier_seq: 0,
        frontier_epoch: SecurityEpoch::GENESIS,
        tick: 1,
        trace_id: "t1",
    });

    // Divergent genesis: same seq=0 but different policy head → different ID.
    let divergent =
        CheckpointBuilder::genesis(SecurityEpoch::GENESIS, DeterministicTimestamp(0), zone)
            .add_policy_head(make_policy_head(PolicyType::CapabilityLattice, 99))
            .build(std::slice::from_ref(&sk))
            .unwrap();

    let result = detector.record_checkpoint(&RecordCheckpointInput {
        zone,
        checkpoint: &divergent,
        accepted: false,
        frontier_seq: 0,
        frontier_epoch: SecurityEpoch::GENESIS,
        tick: 2,
        trace_id: "t2",
    });
    assert!(result.is_err(), "divergent checkpoint must trigger fork");
    assert!(detector.is_safe_mode(zone), "safe mode must be active");
}

#[test]
fn conformance_fork_detection_safe_mode_sticky_until_ack() {
    let sk = test_signing_key(91);
    let mut detector = ForkDetector::with_defaults();
    let zone = "sticky-zone";

    let genesis = build_genesis_checkpoint(&sk, zone, SecurityEpoch::GENESIS);
    let _ = detector.record_checkpoint(&RecordCheckpointInput {
        zone,
        checkpoint: &genesis,
        accepted: true,
        frontier_seq: 0,
        frontier_epoch: SecurityEpoch::GENESIS,
        tick: 1,
        trace_id: "t1",
    });

    let divergent =
        CheckpointBuilder::genesis(SecurityEpoch::GENESIS, DeterministicTimestamp(0), zone)
            .add_policy_head(make_policy_head(PolicyType::CapabilityLattice, 99))
            .build(std::slice::from_ref(&sk))
            .unwrap();

    let _ = detector.record_checkpoint(&RecordCheckpointInput {
        zone,
        checkpoint: &divergent,
        accepted: false,
        frontier_seq: 0,
        frontier_epoch: SecurityEpoch::GENESIS,
        tick: 2,
        trace_id: "t2",
    });

    // Cannot exit without acknowledgment.
    let exit_result = detector.exit_safe_mode(zone, "t3");
    assert!(exit_result.is_err(), "exit without ack must fail");

    // Acknowledge all incidents and exit.
    let incidents = detector.incidents(zone).to_vec();
    for inc in &incidents {
        assert!(detector.acknowledge_incident(zone, &inc.incident_id));
    }
    let exit_result = detector.exit_safe_mode(zone, "t4");
    assert!(exit_result.is_ok());
    assert!(!detector.is_safe_mode(zone));
}

#[test]
fn conformance_fork_detection_zone_isolation() {
    let sk = test_signing_key(92);
    let mut detector = ForkDetector::with_defaults();

    let genesis_a = build_genesis_checkpoint(&sk, "zone-a", SecurityEpoch::GENESIS);
    let _ = detector.record_checkpoint(&RecordCheckpointInput {
        zone: "zone-a",
        checkpoint: &genesis_a,
        accepted: true,
        frontier_seq: 0,
        frontier_epoch: SecurityEpoch::GENESIS,
        tick: 1,
        trace_id: "t1",
    });

    let divergent_a =
        CheckpointBuilder::genesis(SecurityEpoch::GENESIS, DeterministicTimestamp(0), "zone-a")
            .add_policy_head(make_policy_head(PolicyType::CapabilityLattice, 99))
            .build(std::slice::from_ref(&sk))
            .unwrap();

    let _ = detector.record_checkpoint(&RecordCheckpointInput {
        zone: "zone-a",
        checkpoint: &divergent_a,
        accepted: false,
        frontier_seq: 0,
        frontier_epoch: SecurityEpoch::GENESIS,
        tick: 2,
        trace_id: "t2",
    });

    assert!(detector.is_safe_mode("zone-a"));
    assert!(
        !detector.is_safe_mode("zone-b"),
        "zone-b must not be affected"
    );
}

#[test]
fn conformance_fork_detection_state_persistence() {
    let sk = test_signing_key(93);
    let mut detector = ForkDetector::with_defaults();

    let genesis = build_genesis_checkpoint(&sk, "zone-p", SecurityEpoch::GENESIS);
    let _ = detector.record_checkpoint(&RecordCheckpointInput {
        zone: "zone-p",
        checkpoint: &genesis,
        accepted: true,
        frontier_seq: 0,
        frontier_epoch: SecurityEpoch::GENESIS,
        tick: 1,
        trace_id: "t1",
    });

    let state = detector.export_state();
    assert!(!state.is_empty(), "exported state must not be empty");
    let original_keys: Vec<_> = state.keys().cloned().collect();

    let mut detector2 = ForkDetector::with_defaults();
    detector2.import_state(state.clone());
    let reimported_keys: Vec<_> = detector2.export_state().keys().cloned().collect();
    assert_eq!(
        original_keys, reimported_keys,
        "import/export must preserve zone keys"
    );
}

// =========================================================================
// 13. Checkpoint Chain Conformance
// =========================================================================

use frankenengine_engine::policy_checkpoint::CheckpointError;

#[test]
fn conformance_checkpoint_genesis_has_seq_zero() {
    let sk = test_signing_key(100);
    let cp = build_genesis_checkpoint(&sk, "cp-zone", SecurityEpoch::GENESIS);
    assert_eq!(cp.checkpoint_seq, 0);
    assert!(cp.prev_checkpoint.is_none());
}

#[test]
fn conformance_checkpoint_genesis_has_policy_heads() {
    let sk = test_signing_key(101);
    let cp = build_genesis_checkpoint(&sk, "cp-zone", SecurityEpoch::GENESIS);
    assert!(
        !cp.policy_heads.is_empty(),
        "genesis must have policy heads"
    );
}

#[test]
fn conformance_checkpoint_chain_linkage() {
    let sk = test_signing_key(102);
    let genesis = build_genesis_checkpoint(&sk, "cp-zone", SecurityEpoch::GENESIS);
    let cp1 = build_next_checkpoint(&genesis, 1, &sk, "cp-zone", SecurityEpoch::GENESIS);
    assert_eq!(cp1.checkpoint_seq, 1);
    assert_eq!(
        cp1.prev_checkpoint.as_ref(),
        Some(&genesis.checkpoint_id),
        "cp1 must link to genesis"
    );

    let cp2 = build_next_checkpoint(&cp1, 2, &sk, "cp-zone", SecurityEpoch::GENESIS);
    assert_eq!(cp2.checkpoint_seq, 2);
    assert_eq!(
        cp2.prev_checkpoint.as_ref(),
        Some(&cp1.checkpoint_id),
        "cp2 must link to cp1"
    );
}

#[test]
fn conformance_checkpoint_distinct_ids() {
    let sk = test_signing_key(103);
    let genesis = build_genesis_checkpoint(&sk, "cp-zone", SecurityEpoch::GENESIS);
    let cp1 = build_next_checkpoint(&genesis, 1, &sk, "cp-zone", SecurityEpoch::GENESIS);
    assert_ne!(
        genesis.checkpoint_id, cp1.checkpoint_id,
        "distinct checkpoints must have distinct IDs"
    );
}

#[test]
fn conformance_checkpoint_epoch_non_regression() {
    let sk = test_signing_key(104);
    let genesis = build_genesis_checkpoint(&sk, "cp-zone", SecurityEpoch::from_raw(2));
    let cp1 = build_next_checkpoint(&genesis, 1, &sk, "cp-zone", SecurityEpoch::from_raw(2));
    assert_eq!(cp1.epoch_id, SecurityEpoch::from_raw(2));

    let cp2 = build_next_checkpoint(&cp1, 2, &sk, "cp-zone", SecurityEpoch::from_raw(3));
    assert_eq!(cp2.epoch_id, SecurityEpoch::from_raw(3));
}

#[test]
fn conformance_checkpoint_empty_policy_heads_rejected() {
    let sk = test_signing_key(105);
    let result =
        CheckpointBuilder::genesis(SecurityEpoch::GENESIS, DeterministicTimestamp(0), "zone")
            .build(&[sk]);
    assert!(
        matches!(result, Err(CheckpointError::EmptyPolicyHeads)),
        "checkpoint without policy heads must be rejected"
    );
}

#[test]
fn conformance_checkpoint_serde_round_trip() {
    let sk = test_signing_key(106);
    let cp = build_genesis_checkpoint(&sk, "serde-zone", SecurityEpoch::GENESIS);
    let json = serde_json::to_string(&cp).expect("serialize checkpoint");
    let restored: frankenengine_engine::policy_checkpoint::PolicyCheckpoint =
        serde_json::from_str(&json).expect("deserialize checkpoint");
    assert_eq!(cp.checkpoint_id, restored.checkpoint_id);
    assert_eq!(cp.checkpoint_seq, restored.checkpoint_seq);
}

// =========================================================================
// 14. Capability Token Conformance
// =========================================================================

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::capability_token::{
    CheckpointRef, RevocationFreshnessRef, TokenBuilder, TokenError, VerificationContext,
    verify_token,
};

fn build_test_token(
    sk: &SigningKey,
    zone: &str,
    caps: &[RuntimeCapability],
    audience: Option<&PrincipalId>,
) -> frankenengine_engine::capability_token::CapabilityToken {
    let mut builder = TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(0),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        zone,
    );
    for cap in caps {
        builder = builder.add_capability(*cap);
    }
    if let Some(p) = audience {
        builder = builder.add_audience(p.clone());
    }
    builder.build().expect("token build")
}

#[test]
fn conformance_token_build_and_verify() {
    let sk = test_signing_key(110);
    let vk = sk.verification_key();
    let presenter = PrincipalId::from_verification_key(&vk);

    let token = build_test_token(
        &sk,
        "token-zone",
        &[RuntimeCapability::PolicyRead],
        Some(&presenter),
    );

    let ctx = VerificationContext {
        current_tick: 500,
        verifier_checkpoint_seq: 0,
        verifier_revocation_seq: 0,
    };
    verify_token(&token, &presenter, &ctx).expect("token must verify");
}

#[test]
fn conformance_token_rejects_wrong_audience() {
    let sk = test_signing_key(111);
    let vk = sk.verification_key();
    let real_audience = PrincipalId::from_verification_key(&vk);

    let token = build_test_token(
        &sk,
        "token-zone",
        &[RuntimeCapability::PolicyRead],
        Some(&real_audience),
    );

    let fake_presenter = PrincipalId::from_bytes([99u8; 32]);
    let ctx = VerificationContext {
        current_tick: 500,
        verifier_checkpoint_seq: 0,
        verifier_revocation_seq: 0,
    };
    let result = verify_token(&token, &fake_presenter, &ctx);
    assert!(
        matches!(result, Err(TokenError::AudienceRejected { .. })),
        "wrong audience must be rejected"
    );
}

#[test]
fn conformance_token_rejects_expired() {
    let sk = test_signing_key(112);
    let vk = sk.verification_key();
    let presenter = PrincipalId::from_verification_key(&vk);

    let token = build_test_token(
        &sk,
        "token-zone",
        &[RuntimeCapability::PolicyRead],
        Some(&presenter),
    );

    let ctx = VerificationContext {
        current_tick: 2000, // past expiry of 1000
        verifier_checkpoint_seq: 0,
        verifier_revocation_seq: 0,
    };
    let result = verify_token(&token, &presenter, &ctx);
    assert!(
        matches!(result, Err(TokenError::Expired { .. })),
        "expired token must be rejected"
    );
}

#[test]
fn conformance_token_rejects_not_yet_valid() {
    let sk = test_signing_key(113);
    let vk = sk.verification_key();
    let presenter = PrincipalId::from_verification_key(&vk);

    let token = TokenBuilder::new(
        sk,
        DeterministicTimestamp(100),
        DeterministicTimestamp(500),
        SecurityEpoch::GENESIS,
        "zone",
    )
    .add_capability(RuntimeCapability::PolicyRead)
    .add_audience(presenter.clone())
    .build()
    .expect("build");

    let ctx = VerificationContext {
        current_tick: 50, // before nbf of 100
        verifier_checkpoint_seq: 0,
        verifier_revocation_seq: 0,
    };
    let result = verify_token(&token, &presenter, &ctx);
    assert!(
        matches!(result, Err(TokenError::NotYetValid { .. })),
        "not-yet-valid token must be rejected"
    );
}

#[test]
fn conformance_token_rejects_empty_capabilities() {
    let sk = test_signing_key(114);
    let result = TokenBuilder::new(
        sk,
        DeterministicTimestamp(0),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone",
    )
    .build();
    assert!(
        matches!(result, Err(TokenError::EmptyCapabilities)),
        "token with no capabilities must be rejected"
    );
}

#[test]
fn conformance_token_rejects_inverted_temporal_window() {
    let sk = test_signing_key(115);
    let result = TokenBuilder::new(
        sk,
        DeterministicTimestamp(500), // nbf > expiry
        DeterministicTimestamp(100),
        SecurityEpoch::GENESIS,
        "zone",
    )
    .add_capability(RuntimeCapability::VmDispatch)
    .build();
    assert!(
        matches!(result, Err(TokenError::InvertedTemporalWindow { .. })),
        "inverted temporal window must be rejected"
    );
}

#[test]
fn conformance_token_checkpoint_binding_verified() {
    let sk = test_signing_key(116);
    let vk = sk.verification_key();
    let presenter = PrincipalId::from_verification_key(&vk);

    let schema = SchemaId::from_definition(b"test.cp.v1");
    let cp_id =
        derive_id(ObjectDomain::CheckpointArtifact, "zone", &schema, b"cp1").expect("derive");

    let token = TokenBuilder::new(
        sk,
        DeterministicTimestamp(0),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone",
    )
    .add_capability(RuntimeCapability::PolicyRead)
    .add_audience(presenter.clone())
    .bind_checkpoint(CheckpointRef {
        min_checkpoint_seq: 5,
        checkpoint_id: cp_id,
    })
    .build()
    .expect("build");

    // Verifier with seq < 5 must fail.
    let ctx_stale = VerificationContext {
        current_tick: 500,
        verifier_checkpoint_seq: 3,
        verifier_revocation_seq: 0,
    };
    let result = verify_token(&token, &presenter, &ctx_stale);
    assert!(
        matches!(result, Err(TokenError::CheckpointBindingFailed { .. })),
        "stale checkpoint must fail binding"
    );

    // Verifier with seq >= 5 must pass.
    let ctx_ok = VerificationContext {
        current_tick: 500,
        verifier_checkpoint_seq: 5,
        verifier_revocation_seq: 0,
    };
    verify_token(&token, &presenter, &ctx_ok).expect("checkpoint binding must pass");
}

#[test]
fn conformance_token_revocation_freshness_binding_verified() {
    let sk = test_signing_key(117);
    let vk = sk.verification_key();
    let presenter = PrincipalId::from_verification_key(&vk);

    let token = TokenBuilder::new(
        sk,
        DeterministicTimestamp(0),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone",
    )
    .add_capability(RuntimeCapability::EvidenceEmit)
    .add_audience(presenter.clone())
    .bind_revocation_freshness(RevocationFreshnessRef {
        min_revocation_seq: 10,
        revocation_head_hash: ContentHash::compute(b"rev-head"),
    })
    .build()
    .expect("build");

    // Verifier with seq < 10 must fail.
    let ctx_stale = VerificationContext {
        current_tick: 500,
        verifier_checkpoint_seq: 0,
        verifier_revocation_seq: 5,
    };
    let result = verify_token(&token, &presenter, &ctx_stale);
    assert!(
        matches!(result, Err(TokenError::RevocationFreshnessStale { .. })),
        "stale revocation head must fail"
    );

    // Verifier with seq >= 10 must pass.
    let ctx_ok = VerificationContext {
        current_tick: 500,
        verifier_checkpoint_seq: 0,
        verifier_revocation_seq: 10,
    };
    verify_token(&token, &presenter, &ctx_ok).expect("revocation freshness must pass");
}

#[test]
fn conformance_token_multiple_capabilities() {
    let sk = test_signing_key(118);
    let vk = sk.verification_key();
    let presenter = PrincipalId::from_verification_key(&vk);

    let token = TokenBuilder::new(
        sk,
        DeterministicTimestamp(0),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone",
    )
    .add_capability(RuntimeCapability::PolicyRead)
    .add_capability(RuntimeCapability::PolicyWrite)
    .add_capability(RuntimeCapability::EvidenceEmit)
    .add_audience(presenter.clone())
    .build()
    .expect("build");

    assert_eq!(token.capabilities.len(), 3);
    let ctx = VerificationContext {
        current_tick: 500,
        verifier_checkpoint_seq: 0,
        verifier_revocation_seq: 0,
    };
    verify_token(&token, &presenter, &ctx).expect("multi-cap token must verify");
}

#[test]
fn conformance_token_jti_deterministic() {
    let sk = test_signing_key(119);
    let t1 = build_test_token(&sk, "zone", &[RuntimeCapability::VmDispatch], None);
    let t2 = build_test_token(&sk, "zone", &[RuntimeCapability::VmDispatch], None);
    assert_eq!(t1.jti, t2.jti, "same inputs must produce same jti");
}

// =========================================================================
// 15. Delegation Chain Conformance
// =========================================================================

use frankenengine_engine::delegation_chain::{
    ChainError as DelegationChainError, DelegationChain, DelegationVerificationContext,
    NoRevocationOracle,
};

#[test]
fn conformance_delegation_empty_chain_rejected() {
    let chain = DelegationChain::new(vec![]);
    let sk = test_signing_key(120);
    let vk = sk.verification_key();
    let ctx = DelegationVerificationContext::with_authorized_root(vk.clone());
    let presenter = PrincipalId::from_verification_key(&vk);
    let result = chain.verify(
        RuntimeCapability::PolicyRead,
        &presenter,
        &ctx,
        &NoRevocationOracle,
    );
    assert!(
        matches!(result, Err(DelegationChainError::EmptyChain)),
        "empty chain must be rejected"
    );
}

#[test]
fn conformance_delegation_single_link_valid() {
    let root_sk = test_signing_key(121);
    let root_vk = root_sk.verification_key();
    let leaf_sk = test_signing_key(122);
    let leaf_vk = leaf_sk.verification_key();
    let leaf_principal = PrincipalId::from_verification_key(&leaf_vk);

    let schema = SchemaId::from_definition(b"test.deleg.v1");
    let cp_id =
        derive_id(ObjectDomain::CheckpointArtifact, "zone", &schema, b"cp").expect("derive");

    let token = TokenBuilder::new(
        root_sk,
        DeterministicTimestamp(0),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone",
    )
    .add_capability(RuntimeCapability::PolicyRead)
    .add_audience(leaf_principal.clone())
    .bind_checkpoint(CheckpointRef {
        min_checkpoint_seq: 0,
        checkpoint_id: cp_id,
    })
    .bind_revocation_freshness(RevocationFreshnessRef {
        min_revocation_seq: 0,
        revocation_head_hash: ContentHash::compute(b"rev"),
    })
    .build()
    .expect("build token");

    let chain = DelegationChain::new(vec![token]);
    let ctx = DelegationVerificationContext::with_authorized_root(root_vk);
    let proof = chain
        .verify(
            RuntimeCapability::PolicyRead,
            &leaf_principal,
            &ctx,
            &NoRevocationOracle,
        )
        .expect("single-link chain must verify");
    assert_eq!(proof.authorized_capability, RuntimeCapability::PolicyRead);
}

#[test]
fn conformance_delegation_unauthorized_root_rejected() {
    let root_sk = test_signing_key(123);
    let other_sk = test_signing_key(124);
    let other_vk = other_sk.verification_key();
    let leaf_sk = test_signing_key(125);
    let leaf_vk = leaf_sk.verification_key();
    let leaf_principal = PrincipalId::from_verification_key(&leaf_vk);

    let schema = SchemaId::from_definition(b"test.deleg.v1");
    let cp_id =
        derive_id(ObjectDomain::CheckpointArtifact, "zone", &schema, b"cp").expect("derive");

    let token = TokenBuilder::new(
        root_sk,
        DeterministicTimestamp(0),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone",
    )
    .add_capability(RuntimeCapability::PolicyRead)
    .add_audience(leaf_principal.clone())
    .bind_checkpoint(CheckpointRef {
        min_checkpoint_seq: 0,
        checkpoint_id: cp_id,
    })
    .bind_revocation_freshness(RevocationFreshnessRef {
        min_revocation_seq: 0,
        revocation_head_hash: ContentHash::compute(b"rev"),
    })
    .build()
    .expect("build");

    let chain = DelegationChain::new(vec![token]);
    let ctx = DelegationVerificationContext::with_authorized_root(other_vk);
    let result = chain.verify(
        RuntimeCapability::PolicyRead,
        &leaf_principal,
        &ctx,
        &NoRevocationOracle,
    );
    assert!(
        matches!(result, Err(DelegationChainError::UnauthorizedRoot { .. })),
        "unauthorized root must be rejected"
    );
}

#[test]
fn conformance_delegation_depth_exceeded_rejected() {
    let sk = test_signing_key(126);
    let vk = sk.verification_key();
    let presenter = PrincipalId::from_verification_key(&vk);

    let schema = SchemaId::from_definition(b"test.deleg.v1");
    let cp_id =
        derive_id(ObjectDomain::CheckpointArtifact, "zone", &schema, b"cp").expect("derive");

    let token = TokenBuilder::new(
        sk,
        DeterministicTimestamp(0),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone",
    )
    .add_capability(RuntimeCapability::PolicyRead)
    .add_audience(presenter.clone())
    .bind_checkpoint(CheckpointRef {
        min_checkpoint_seq: 0,
        checkpoint_id: cp_id,
    })
    .bind_revocation_freshness(RevocationFreshnessRef {
        min_revocation_seq: 0,
        revocation_head_hash: ContentHash::compute(b"rev"),
    })
    .build()
    .expect("build");

    let chain = DelegationChain::new(vec![token]);
    let mut ctx = DelegationVerificationContext::with_authorized_root(vk);
    ctx.max_chain_depth = 0;
    let result = chain.verify(
        RuntimeCapability::PolicyRead,
        &presenter,
        &ctx,
        &NoRevocationOracle,
    );
    assert!(
        matches!(result, Err(DelegationChainError::DepthExceeded { .. })),
        "depth exceeded must be rejected"
    );
}

#[test]
fn conformance_delegation_missing_capability_at_leaf() {
    let root_sk = test_signing_key(127);
    let root_vk = root_sk.verification_key();
    let leaf_sk = test_signing_key(128);
    let leaf_vk = leaf_sk.verification_key();
    let leaf_principal = PrincipalId::from_verification_key(&leaf_vk);

    let schema = SchemaId::from_definition(b"test.deleg.v1");
    let cp_id =
        derive_id(ObjectDomain::CheckpointArtifact, "zone", &schema, b"cp").expect("derive");

    let token = TokenBuilder::new(
        root_sk,
        DeterministicTimestamp(0),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone",
    )
    .add_capability(RuntimeCapability::PolicyRead)
    .add_audience(leaf_principal.clone())
    .bind_checkpoint(CheckpointRef {
        min_checkpoint_seq: 0,
        checkpoint_id: cp_id,
    })
    .bind_revocation_freshness(RevocationFreshnessRef {
        min_revocation_seq: 0,
        revocation_head_hash: ContentHash::compute(b"rev"),
    })
    .build()
    .expect("build");

    let chain = DelegationChain::new(vec![token]);
    let ctx = DelegationVerificationContext::with_authorized_root(root_vk);
    let result = chain.verify(
        RuntimeCapability::PolicyWrite,
        &leaf_principal,
        &ctx,
        &NoRevocationOracle,
    );
    assert!(
        matches!(
            result,
            Err(DelegationChainError::MissingCapabilityAtLeaf { .. })
        ),
        "missing capability must be rejected"
    );
}

// =========================================================================
// 16. Cross-Module Integration Conformance
// =========================================================================

#[test]
fn conformance_integration_checkpoint_to_token_binding() {
    let sk = test_signing_key(130);
    let vk = sk.verification_key();
    let presenter = PrincipalId::from_verification_key(&vk);

    let cp = build_genesis_checkpoint(&sk, "int-zone", SecurityEpoch::GENESIS);

    let token = TokenBuilder::new(
        sk,
        DeterministicTimestamp(0),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "int-zone",
    )
    .add_capability(RuntimeCapability::PolicyRead)
    .add_audience(presenter.clone())
    .bind_checkpoint(CheckpointRef {
        min_checkpoint_seq: cp.checkpoint_seq,
        checkpoint_id: cp.checkpoint_id.clone(),
    })
    .build()
    .expect("build");

    let ctx = VerificationContext {
        current_tick: 500,
        verifier_checkpoint_seq: cp.checkpoint_seq,
        verifier_revocation_seq: 0,
    };
    verify_token(&token, &presenter, &ctx).expect("checkpoint-bound token must verify");
}

#[test]
fn conformance_integration_revocation_chain_plus_freshness() {
    let sk = test_signing_key(131);
    let mut chain = RevocationChain::new("int-zone");
    let rev = make_revocation(60, "int-zone", &sk);
    let target_id = rev.target_id.clone();
    chain.append(rev, &sk, "t1").expect("append");

    assert!(chain.is_revoked(&target_id));

    let config = FreshnessConfig {
        staleness_threshold: 10,
        holdoff_ticks: 1,
        override_eligible: BTreeSet::new(),
        authorized_operators: BTreeSet::new(),
    };
    let mut ctrl = RevocationFreshnessController::new(config, "int-zone");
    ctrl.update_expected_head(chain.head_seq().unwrap_or(0), "t2");
    ctrl.update_local_head(chain.head_seq().unwrap_or(0), "t3");
    assert!(ctrl.is_fresh(), "synced revocation head must be fresh");
}

// =========================================================================
// 17. Cross-Cutting Conformance Meta-Tests
// =========================================================================

#[test]
fn conformance_meta_all_object_domains_have_tags() {
    for domain in ObjectDomain::ALL {
        let tag = domain.tag();
        assert!(!tag.is_empty(), "domain {domain:?} must have non-empty tag");
        assert!(
            tag.starts_with(b"FrankenEngine."),
            "domain {domain:?} tag must start with FrankenEngine."
        );
    }
}

#[test]
fn conformance_meta_all_domain_tags_unique() {
    let tags: BTreeSet<Vec<u8>> = ObjectDomain::ALL.iter().map(|d| d.tag().to_vec()).collect();
    assert_eq!(
        tags.len(),
        ObjectDomain::ALL.len(),
        "all domain tags must be unique"
    );
}

#[test]
fn conformance_meta_schema_id_derivation_stable() {
    let s1 = SchemaId::from_definition(b"FrankenEngine.Meta.v1");
    let s2 = SchemaId::from_definition(b"FrankenEngine.Meta.v1");
    assert_eq!(s1, s2);

    let s3 = SchemaId::from_definition(b"FrankenEngine.Meta.v2");
    assert_ne!(
        s1, s3,
        "different definitions must produce different schema IDs"
    );
}

#[test]
fn conformance_meta_signing_key_zero_rejected() {
    let zero_sk = SigningKey::from_bytes([0u8; 32]);
    let result = sign_preimage(&zero_sk, b"test");
    assert!(
        matches!(result, Err(SignatureError::InvalidSigningKey)),
        "all-zero signing key must be rejected"
    );
}

#[test]
fn conformance_meta_verification_key_zero_rejected() {
    let sk = test_signing_key(99);
    let sig = sign_preimage(&sk, b"test").expect("sign");
    let zero_vk = VerificationKey::from_bytes([0u8; 32]);
    let result = verify_signature(&zero_vk, b"test", &sig);
    assert!(
        matches!(result, Err(SignatureError::InvalidVerificationKey)),
        "all-zero verification key must be rejected"
    );
}

#[test]
fn conformance_meta_id_from_hex_rejects_wrong_length() {
    let result = EngineObjectId::from_hex("abcdef");
    assert!(
        matches!(result, Err(IdError::InvalidHexLength { .. })),
        "wrong hex length must be rejected"
    );
}

#[test]
fn conformance_meta_id_from_hex_rejects_invalid_chars() {
    let result = EngineObjectId::from_hex(
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
    );
    assert!(
        matches!(result, Err(IdError::InvalidHexChar { .. })),
        "invalid hex chars must be rejected"
    );
}

// =========================================================================
// 18. Serialization Conformance for All Security Types
// =========================================================================

#[test]
fn conformance_serde_security_epoch_round_trip() {
    let epoch = SecurityEpoch::from_raw(42);
    let json = serde_json::to_string(&epoch).expect("serialize");
    let restored: SecurityEpoch = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(epoch, restored);
}

#[test]
fn conformance_serde_epoch_metadata_round_trip() {
    let meta = EpochMetadata::windowed(
        SecurityEpoch::from_raw(1),
        SecurityEpoch::from_raw(1),
        SecurityEpoch::from_raw(10),
    );
    let json = serde_json::to_string(&meta).expect("serialize");
    let restored: EpochMetadata = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(meta, restored);
}

#[test]
fn conformance_serde_engine_object_id_round_trip() {
    let schema = SchemaId::from_definition(b"serde.test.v1");
    let id = derive_id(ObjectDomain::PolicyObject, "zone", &schema, b"data").expect("derive");
    let json = serde_json::to_string(&id).expect("serialize");
    let restored: EngineObjectId = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(id, restored);
}

#[test]
fn conformance_serde_verification_key_round_trip() {
    let sk = test_signing_key(50);
    let vk = sk.verification_key();
    let json = serde_json::to_string(&vk).expect("serialize");
    let restored: VerificationKey = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(vk, restored);
}

#[test]
fn conformance_serde_signature_round_trip() {
    let sk = test_signing_key(51);
    let sig = sign_preimage(&sk, b"serde-test").expect("sign");
    let json = serde_json::to_string(&sig).expect("serialize");
    let restored: Signature = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(sig, restored);
}

#[test]
fn conformance_serde_freshness_state_round_trip() {
    for state in [
        FreshnessState::Fresh,
        FreshnessState::Stale,
        FreshnessState::Degraded,
        FreshnessState::Recovering,
    ] {
        let json = serde_json::to_string(&state).expect("serialize");
        let restored: FreshnessState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(state, restored);
    }
}

#[test]
fn conformance_serde_revocation_reason_round_trip() {
    for reason in [
        RevocationReason::Compromised,
        RevocationReason::Expired,
        RevocationReason::Superseded,
        RevocationReason::PolicyViolation,
        RevocationReason::Administrative,
    ] {
        let json = serde_json::to_string(&reason).expect("serialize");
        let restored: RevocationReason = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(reason, restored);
    }
}

#[test]
fn conformance_serde_trust_zone_class_round_trip() {
    for class in TrustZoneClass::ORDERED {
        let json = serde_json::to_string(&class).expect("serialize");
        let restored: TrustZoneClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(class, restored);
    }
}

#[test]
fn conformance_serde_transition_reason_round_trip() {
    let reasons = vec![
        TransitionReason::PolicyKeyRotation,
        TransitionReason::RevocationFrontierAdvance,
        TransitionReason::GuardrailConfigChange,
        TransitionReason::LossMatrixUpdate,
        TransitionReason::RemoteTrustConfigChange,
        TransitionReason::OperatorManualBump,
    ];
    for reason in reasons {
        let json = serde_json::to_string(&reason).expect("serialize");
        let restored: TransitionReason = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(reason, restored);
    }
}

#[test]
fn conformance_serde_content_hash_round_trip() {
    let h = ContentHash::compute(b"serde-hash-test");
    let json = serde_json::to_string(&h).expect("serialize");
    let restored: ContentHash = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(h, restored);
}

#[test]
fn conformance_serde_schema_id_round_trip() {
    let s = SchemaId::from_definition(b"serde-schema-test");
    let json = serde_json::to_string(&s).expect("serialize");
    let restored: SchemaId = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(s, restored);
}
