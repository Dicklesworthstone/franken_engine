//! Edge-case tests for `threshold_signing` module.

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

use std::collections::BTreeSet;
use std::hash::{DefaultHasher, Hash, Hasher};

use frankenengine_engine::capability_token::PrincipalId;
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{SigningKey, VerificationKey};
use frankenengine_engine::threshold_signing::{
    CreateThresholdPolicyInput, PartialSignature, ShareHolderId, ShareRefreshResult,
    ThresholdCeremony, ThresholdError, ThresholdEventType, ThresholdResult, ThresholdScope,
    ThresholdSigningPolicy, refresh_shares, threshold_ceremony_schema_id, threshold_policy_schema,
    threshold_policy_schema_id,
};

// =========================================================================
// Helpers
// =========================================================================

const TEST_ZONE: &str = "edge-case-zone";
const TEST_PREIMAGE: &[u8] = b"edge-case-test-preimage-data";

fn hash_of<T: Hash>(val: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    val.hash(&mut hasher);
    hasher.finish()
}

fn make_keys(count: usize) -> Vec<SigningKey> {
    (0..count)
        .map(|i| SigningKey::from_bytes([(i + 10) as u8; 32]))
        .collect()
}

fn make_holder_ids(keys: &[SigningKey]) -> BTreeSet<ShareHolderId> {
    keys.iter()
        .map(|sk| ShareHolderId::from_verification_key(&sk.verification_key()))
        .collect()
}

fn make_scopes_all() -> BTreeSet<ThresholdScope> {
    ThresholdScope::ALL.iter().copied().collect()
}

fn make_scopes_single(scope: ThresholdScope) -> BTreeSet<ThresholdScope> {
    let mut s = BTreeSet::new();
    s.insert(scope);
    s
}

fn test_principal() -> PrincipalId {
    PrincipalId::from_bytes([0xAA; 32])
}

fn create_policy(
    k: u32,
    keys: &[SigningKey],
    scopes: BTreeSet<ThresholdScope>,
) -> ThresholdSigningPolicy {
    ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
        principal_id: test_principal(),
        threshold_k: k,
        authorized_shares: make_holder_ids(keys),
        scoped_operations: scopes,
        epoch: SecurityEpoch::from_raw(1),
        zone: TEST_ZONE,
    })
    .expect("create policy")
}

fn run_ceremony(
    policy: &ThresholdSigningPolicy,
    scope: ThresholdScope,
    keys_to_sign: &[&SigningKey],
    preimage: &[u8],
) -> ThresholdResult {
    let mut ceremony =
        ThresholdCeremony::new(policy, scope, preimage, DeterministicTimestamp(1000))
            .expect("new ceremony");
    for (i, key) in keys_to_sign.iter().enumerate() {
        ceremony
            .submit_partial(key, preimage, DeterministicTimestamp(1001 + i as u64))
            .expect("submit partial");
    }
    ceremony.finalize(preimage).expect("finalize")
}

// =========================================================================
// ThresholdScope
// =========================================================================

#[test]
fn scope_copy_semantics() {
    let a = ThresholdScope::EmergencyRevocation;
    let b = a; // Copy
    assert_eq!(a, b);
}

#[test]
fn scope_hash_all_four_distinct() {
    let hashes: BTreeSet<u64> = ThresholdScope::ALL.iter().map(hash_of).collect();
    assert_eq!(
        hashes.len(),
        4,
        "all 4 ThresholdScope variants must hash distinctly"
    );
}

#[test]
fn scope_serde_all_four_roundtrip() {
    for scope in ThresholdScope::ALL {
        let json = serde_json::to_string(scope).unwrap();
        let restored: ThresholdScope = serde_json::from_str(&json).unwrap();
        assert_eq!(*scope, restored);
    }
}

#[test]
fn scope_serde_stable_strings() {
    assert_eq!(
        serde_json::to_string(&ThresholdScope::EmergencyRevocation).unwrap(),
        "\"EmergencyRevocation\""
    );
    assert_eq!(
        serde_json::to_string(&ThresholdScope::KeyRotation).unwrap(),
        "\"KeyRotation\""
    );
    assert_eq!(
        serde_json::to_string(&ThresholdScope::AuthoritySetChange).unwrap(),
        "\"AuthoritySetChange\""
    );
    assert_eq!(
        serde_json::to_string(&ThresholdScope::PolicyCheckpoint).unwrap(),
        "\"PolicyCheckpoint\""
    );
}

#[test]
fn scope_display_all_four() {
    assert_eq!(
        ThresholdScope::EmergencyRevocation.to_string(),
        "emergency_revocation"
    );
    assert_eq!(ThresholdScope::KeyRotation.to_string(), "key_rotation");
    assert_eq!(
        ThresholdScope::AuthoritySetChange.to_string(),
        "authority_set_change"
    );
    assert_eq!(
        ThresholdScope::PolicyCheckpoint.to_string(),
        "policy_checkpoint"
    );
}

#[test]
fn scope_ordering_exhaustive() {
    let ordered = [
        ThresholdScope::EmergencyRevocation,
        ThresholdScope::KeyRotation,
        ThresholdScope::AuthoritySetChange,
        ThresholdScope::PolicyCheckpoint,
    ];
    for i in 0..ordered.len() {
        for j in (i + 1)..ordered.len() {
            assert!(
                ordered[i] < ordered[j],
                "{:?} should be < {:?}",
                ordered[i],
                ordered[j]
            );
        }
    }
}

#[test]
fn scope_all_has_four_variants() {
    assert_eq!(ThresholdScope::ALL.len(), 4);
}

// =========================================================================
// ShareHolderId
// =========================================================================

#[test]
fn share_holder_id_from_verification_key_deterministic() {
    let sk = SigningKey::from_bytes([0x42; 32]);
    let vk = sk.verification_key();
    let id1 = ShareHolderId::from_verification_key(&vk);
    let id2 = ShareHolderId::from_verification_key(&vk);
    assert_eq!(id1, id2);
}

#[test]
fn share_holder_id_different_keys_different_ids() {
    let sk1 = SigningKey::from_bytes([0x01; 32]);
    let sk2 = SigningKey::from_bytes([0x02; 32]);
    let id1 = ShareHolderId::from_verification_key(&sk1.verification_key());
    let id2 = ShareHolderId::from_verification_key(&sk2.verification_key());
    assert_ne!(id1, id2);
}

#[test]
fn share_holder_id_as_bytes_32() {
    let sk = SigningKey::from_bytes([0x42; 32]);
    let id = ShareHolderId::from_verification_key(&sk.verification_key());
    assert_eq!(id.as_bytes().len(), 32);
}

#[test]
fn share_holder_id_to_hex_64_chars() {
    let sk = SigningKey::from_bytes([0x42; 32]);
    let id = ShareHolderId::from_verification_key(&sk.verification_key());
    let hex = id.to_hex();
    assert_eq!(hex.len(), 64); // 32 bytes * 2 hex chars
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn share_holder_id_display_starts_with_share() {
    let sk = SigningKey::from_bytes([0x42; 32]);
    let id = ShareHolderId::from_verification_key(&sk.verification_key());
    let display = id.to_string();
    assert!(display.starts_with("share:"));
    // Display uses first 16 chars of hex
    assert_eq!(display.len(), 6 + 16); // "share:" + 16 hex chars
}

#[test]
fn share_holder_id_hash_distinct_for_different_keys() {
    let ids: Vec<ShareHolderId> = (0..5)
        .map(|i| {
            let sk = SigningKey::from_bytes([(i + 1) as u8; 32]);
            ShareHolderId::from_verification_key(&sk.verification_key())
        })
        .collect();
    let hashes: BTreeSet<u64> = ids.iter().map(hash_of).collect();
    assert_eq!(hashes.len(), 5);
}

#[test]
fn share_holder_id_serde_roundtrip() {
    let sk = SigningKey::from_bytes([0x42; 32]);
    let id = ShareHolderId::from_verification_key(&sk.verification_key());
    let json = serde_json::to_string(&id).unwrap();
    let restored: ShareHolderId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, restored);
}

#[test]
fn share_holder_id_ordering() {
    let id1 = ShareHolderId([0x00; 32]);
    let id2 = ShareHolderId([0xFF; 32]);
    assert!(id1 < id2);
}

// =========================================================================
// ThresholdSigningPolicy — creation edge cases
// =========================================================================

#[test]
fn policy_create_minimum_valid_2_of_2() {
    let keys = make_keys(2);
    let policy = create_policy(
        2,
        &keys,
        make_scopes_single(ThresholdScope::EmergencyRevocation),
    );
    assert_eq!(policy.threshold_k, 2);
    assert_eq!(policy.total_n, 2);
}

#[test]
fn policy_create_1_of_2_valid() {
    let keys = make_keys(2);
    let policy = create_policy(
        1,
        &keys,
        make_scopes_single(ThresholdScope::EmergencyRevocation),
    );
    assert_eq!(policy.threshold_k, 1);
    assert_eq!(policy.total_n, 2);
}

#[test]
fn policy_create_k_0_rejected() {
    let keys = make_keys(3);
    let result = ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
        principal_id: test_principal(),
        threshold_k: 0,
        authorized_shares: make_holder_ids(&keys),
        scoped_operations: make_scopes_all(),
        epoch: SecurityEpoch::from_raw(1),
        zone: TEST_ZONE,
    });
    match result {
        Err(ThresholdError::InvalidThreshold { k, n: _, detail }) => {
            assert_eq!(k, 0);
            assert!(detail.contains("must be > 0"));
        }
        other => panic!("expected InvalidThreshold, got: {:?}", other),
    }
}

#[test]
fn policy_create_k_exceeds_n_rejected() {
    let keys = make_keys(3);
    let result = ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
        principal_id: test_principal(),
        threshold_k: 4,
        authorized_shares: make_holder_ids(&keys),
        scoped_operations: make_scopes_all(),
        epoch: SecurityEpoch::from_raw(1),
        zone: TEST_ZONE,
    });
    match result {
        Err(ThresholdError::InvalidThreshold { k, n, detail }) => {
            assert_eq!(k, 4);
            assert_eq!(n, 3);
            assert!(detail.contains("must be <= n"));
        }
        other => panic!("expected InvalidThreshold, got: {:?}", other),
    }
}

#[test]
fn policy_create_single_share_rejected() {
    let keys = make_keys(1);
    let result = ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
        principal_id: test_principal(),
        threshold_k: 1,
        authorized_shares: make_holder_ids(&keys),
        scoped_operations: make_scopes_all(),
        epoch: SecurityEpoch::from_raw(1),
        zone: TEST_ZONE,
    });
    match result {
        Err(ThresholdError::InvalidThreshold { n, detail, .. }) => {
            assert_eq!(n, 1);
            assert!(detail.contains("at least 2"));
        }
        other => panic!("expected InvalidThreshold, got: {:?}", other),
    }
}

#[test]
fn policy_create_empty_scopes_rejected() {
    let keys = make_keys(3);
    let result = ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
        principal_id: test_principal(),
        threshold_k: 2,
        authorized_shares: make_holder_ids(&keys),
        scoped_operations: BTreeSet::new(),
        epoch: SecurityEpoch::from_raw(1),
        zone: TEST_ZONE,
    });
    assert!(matches!(result, Err(ThresholdError::NoScopedOperations)));
}

#[test]
fn policy_requires_threshold_checks_scoped() {
    let keys = make_keys(3);
    let policy = create_policy(
        2,
        &keys,
        make_scopes_single(ThresholdScope::PolicyCheckpoint),
    );
    assert!(policy.requires_threshold(ThresholdScope::PolicyCheckpoint));
    assert!(!policy.requires_threshold(ThresholdScope::EmergencyRevocation));
    assert!(!policy.requires_threshold(ThresholdScope::KeyRotation));
    assert!(!policy.requires_threshold(ThresholdScope::AuthoritySetChange));
}

#[test]
fn policy_is_authorized_correct() {
    let keys = make_keys(3);
    let policy = create_policy(2, &keys, make_scopes_all());
    for k in &keys {
        let id = ShareHolderId::from_verification_key(&k.verification_key());
        assert!(policy.is_authorized(&id));
    }
    let rogue = ShareHolderId([0xFF; 32]);
    assert!(!policy.is_authorized(&rogue));
}

#[test]
fn policy_deterministic_id() {
    let keys = make_keys(3);
    let p1 = create_policy(2, &keys, make_scopes_all());
    let p2 = create_policy(2, &keys, make_scopes_all());
    assert_eq!(p1.policy_id, p2.policy_id);
}

#[test]
fn policy_display_contains_k_of_n() {
    let keys = make_keys(5);
    let policy = create_policy(3, &keys, make_scopes_all());
    let display = policy.to_string();
    assert!(display.contains("3-of-5"));
}

#[test]
fn policy_serde_roundtrip() {
    let keys = make_keys(4);
    let policy = create_policy(3, &keys, make_scopes_all());
    let json = serde_json::to_string(&policy).unwrap();
    let restored: ThresholdSigningPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, restored);
}

// =========================================================================
// ThresholdCeremony — edge cases
// =========================================================================

#[test]
fn ceremony_scope_not_thresholded_rejected() {
    let keys = make_keys(3);
    let policy = create_policy(
        2,
        &keys,
        make_scopes_single(ThresholdScope::EmergencyRevocation),
    );
    let result = ThresholdCeremony::new(
        &policy,
        ThresholdScope::KeyRotation, // Not in scoped_operations
        TEST_PREIMAGE,
        DeterministicTimestamp(1000),
    );
    assert!(
        matches!(result, Err(ThresholdError::ScopeNotThresholded { scope }) if scope == ThresholdScope::KeyRotation)
    );
}

#[test]
fn ceremony_preimage_mismatch_rejected() {
    let keys = make_keys(3);
    let policy = create_policy(2, &keys, make_scopes_all());
    let mut ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        TEST_PREIMAGE,
        DeterministicTimestamp(1000),
    )
    .unwrap();
    let result = ceremony.submit_partial(&keys[0], b"wrong-preimage", DeterministicTimestamp(1001));
    assert!(matches!(result, Err(ThresholdError::PreimageMismatch)));
}

#[test]
fn ceremony_unauthorized_holder_rejected() {
    let keys = make_keys(3);
    let policy = create_policy(2, &keys, make_scopes_all());
    let mut ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        TEST_PREIMAGE,
        DeterministicTimestamp(1000),
    )
    .unwrap();
    let rogue = SigningKey::from_bytes([0xFF; 32]);
    let result = ceremony.submit_partial(&rogue, TEST_PREIMAGE, DeterministicTimestamp(1001));
    assert!(matches!(
        result,
        Err(ThresholdError::UnauthorizedShareHolder { .. })
    ));
}

#[test]
fn ceremony_duplicate_submission_rejected() {
    let keys = make_keys(3);
    let policy = create_policy(2, &keys, make_scopes_all());
    let mut ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        TEST_PREIMAGE,
        DeterministicTimestamp(1000),
    )
    .unwrap();
    ceremony
        .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
        .unwrap();
    let result = ceremony.submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1002));
    assert!(matches!(
        result,
        Err(ThresholdError::DuplicateSubmission { .. })
    ));
}

#[test]
fn ceremony_finalize_without_threshold_rejected() {
    let keys = make_keys(3);
    let policy = create_policy(2, &keys, make_scopes_all());
    let mut ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        TEST_PREIMAGE,
        DeterministicTimestamp(1000),
    )
    .unwrap();
    ceremony
        .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
        .unwrap();
    let result = ceremony.finalize(TEST_PREIMAGE);
    assert!(matches!(
        result,
        Err(ThresholdError::InsufficientThresholdShares {
            collected: 1,
            required: 2
        })
    ));
}

#[test]
fn ceremony_finalize_twice_rejected() {
    let keys = make_keys(3);
    let policy = create_policy(2, &keys, make_scopes_all());
    let mut ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        TEST_PREIMAGE,
        DeterministicTimestamp(1000),
    )
    .unwrap();
    ceremony
        .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
        .unwrap();
    ceremony
        .submit_partial(&keys[1], TEST_PREIMAGE, DeterministicTimestamp(1002))
        .unwrap();
    ceremony.finalize(TEST_PREIMAGE).unwrap();
    let result = ceremony.finalize(TEST_PREIMAGE);
    assert!(matches!(
        result,
        Err(ThresholdError::CeremonyAlreadyFinalized)
    ));
}

#[test]
fn ceremony_submit_after_finalize_rejected() {
    let keys = make_keys(3);
    let policy = create_policy(2, &keys, make_scopes_all());
    let mut ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        TEST_PREIMAGE,
        DeterministicTimestamp(1000),
    )
    .unwrap();
    ceremony
        .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
        .unwrap();
    ceremony
        .submit_partial(&keys[1], TEST_PREIMAGE, DeterministicTimestamp(1002))
        .unwrap();
    ceremony.finalize(TEST_PREIMAGE).unwrap();
    let result = ceremony.submit_partial(&keys[2], TEST_PREIMAGE, DeterministicTimestamp(1003));
    assert!(matches!(
        result,
        Err(ThresholdError::CeremonyAlreadyFinalized)
    ));
}

#[test]
fn ceremony_participants_empty_before_submissions() {
    let keys = make_keys(3);
    let policy = create_policy(2, &keys, make_scopes_all());
    let ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        TEST_PREIMAGE,
        DeterministicTimestamp(1000),
    )
    .unwrap();
    assert!(ceremony.participants().is_empty());
    assert_eq!(ceremony.signatures_collected(), 0);
    assert!(!ceremony.is_threshold_met());
}

#[test]
fn ceremony_signatures_collected_increments() {
    let keys = make_keys(4);
    let policy = create_policy(3, &keys, make_scopes_all());
    let mut ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        TEST_PREIMAGE,
        DeterministicTimestamp(1000),
    )
    .unwrap();
    assert_eq!(ceremony.signatures_collected(), 0);
    ceremony
        .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
        .unwrap();
    assert_eq!(ceremony.signatures_collected(), 1);
    ceremony
        .submit_partial(&keys[1], TEST_PREIMAGE, DeterministicTimestamp(1002))
        .unwrap();
    assert_eq!(ceremony.signatures_collected(), 2);
    ceremony
        .submit_partial(&keys[2], TEST_PREIMAGE, DeterministicTimestamp(1003))
        .unwrap();
    assert_eq!(ceremony.signatures_collected(), 3);
}

#[test]
fn ceremony_all_n_shares_submit_and_finalize() {
    let keys = make_keys(5);
    let policy = create_policy(3, &keys, make_scopes_all());
    let key_refs: Vec<&SigningKey> = keys.iter().collect();
    let result = run_ceremony(
        &policy,
        ThresholdScope::EmergencyRevocation,
        &key_refs,
        TEST_PREIMAGE,
    );
    assert_eq!(result.signatures.len(), 5);
    assert_eq!(result.participating_shares.len(), 5);
    result.verify(TEST_PREIMAGE).expect("verify all shares");
}

#[test]
fn ceremony_exact_threshold_submits() {
    let keys = make_keys(5);
    let policy = create_policy(3, &keys, make_scopes_all());
    let key_refs: Vec<&SigningKey> = keys.iter().take(3).collect();
    let result = run_ceremony(
        &policy,
        ThresholdScope::EmergencyRevocation,
        &key_refs,
        TEST_PREIMAGE,
    );
    assert_eq!(result.signatures.len(), 3);
    assert_eq!(result.threshold_k, 3);
    result
        .verify(TEST_PREIMAGE)
        .expect("verify exact threshold");
}

// =========================================================================
// ThresholdResult — verification edge cases
// =========================================================================

#[test]
fn result_verify_wrong_preimage_fails() {
    let keys = make_keys(3);
    let policy = create_policy(2, &keys, make_scopes_all());
    let key_refs: Vec<&SigningKey> = keys.iter().take(2).collect();
    let result = run_ceremony(
        &policy,
        ThresholdScope::EmergencyRevocation,
        &key_refs,
        TEST_PREIMAGE,
    );
    let verify_result = result.verify(b"wrong-preimage");
    assert!(matches!(
        verify_result,
        Err(ThresholdError::PreimageMismatch)
    ));
}

#[test]
fn result_serde_roundtrip() {
    let keys = make_keys(3);
    let policy = create_policy(2, &keys, make_scopes_all());
    let key_refs: Vec<&SigningKey> = keys.iter().take(2).collect();
    let result = run_ceremony(
        &policy,
        ThresholdScope::EmergencyRevocation,
        &key_refs,
        TEST_PREIMAGE,
    );
    let json = serde_json::to_string(&result).unwrap();
    let restored: ThresholdResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

// =========================================================================
// ShareRefreshResult / refresh_shares
// =========================================================================

#[test]
fn refresh_shares_produces_new_policy_and_result() {
    let keys = make_keys(3);
    let policy = create_policy(2, &keys, make_scopes_all());
    let new_keys: Vec<SigningKey> = (0..3)
        .map(|i| SigningKey::from_bytes([(i + 50) as u8; 32]))
        .collect();
    let new_vks: Vec<VerificationKey> = new_keys.iter().map(|sk| sk.verification_key()).collect();
    let (new_policy, refresh_result) =
        refresh_shares(&policy, &new_vks, SecurityEpoch::from_raw(2)).unwrap();
    assert_eq!(new_policy.threshold_k, 2);
    assert_eq!(new_policy.total_n, 3);
    assert_ne!(new_policy.policy_id, policy.policy_id);
    assert_eq!(new_policy.epoch, SecurityEpoch::from_raw(2));
    assert_eq!(refresh_result.old_shares.len(), 3);
    assert_eq!(refresh_result.new_shares.len(), 3);
    assert_eq!(refresh_result.refresh_epoch, SecurityEpoch::from_raw(2));
}

#[test]
fn refresh_shares_wrong_count_rejected() {
    let keys = make_keys(3);
    let policy = create_policy(2, &keys, make_scopes_all());
    let new_vks: Vec<VerificationKey> = make_keys(4)
        .iter()
        .map(|sk| sk.verification_key())
        .collect();
    let result = refresh_shares(&policy, &new_vks, SecurityEpoch::from_raw(2));
    assert!(matches!(
        result,
        Err(ThresholdError::InvalidThreshold { .. })
    ));
}

#[test]
fn refresh_shares_duplicate_new_keys_rejected() {
    let keys = make_keys(3);
    let policy = create_policy(2, &keys, make_scopes_all());
    // Same key 3 times
    let same_key = SigningKey::from_bytes([0x50; 32]);
    let new_vks = vec![
        same_key.verification_key(),
        same_key.verification_key(),
        same_key.verification_key(),
    ];
    let result = refresh_shares(&policy, &new_vks, SecurityEpoch::from_raw(2));
    assert!(matches!(result, Err(ThresholdError::DuplicateShareHolder)));
}

#[test]
fn refresh_shares_new_keys_can_sign() {
    let keys = make_keys(3);
    let policy = create_policy(2, &keys, make_scopes_all());
    let new_keys: Vec<SigningKey> = (0..3)
        .map(|i| SigningKey::from_bytes([(i + 50) as u8; 32]))
        .collect();
    let new_vks: Vec<VerificationKey> = new_keys.iter().map(|sk| sk.verification_key()).collect();
    let (new_policy, _) = refresh_shares(&policy, &new_vks, SecurityEpoch::from_raw(2)).unwrap();
    let key_refs: Vec<&SigningKey> = new_keys.iter().take(2).collect();
    let result = run_ceremony(
        &new_policy,
        ThresholdScope::EmergencyRevocation,
        &key_refs,
        TEST_PREIMAGE,
    );
    result.verify(TEST_PREIMAGE).expect("verify with new keys");
}

#[test]
fn refresh_shares_old_keys_rejected_in_new_policy() {
    let keys = make_keys(3);
    let policy = create_policy(2, &keys, make_scopes_all());
    let new_keys: Vec<SigningKey> = (0..3)
        .map(|i| SigningKey::from_bytes([(i + 50) as u8; 32]))
        .collect();
    let new_vks: Vec<VerificationKey> = new_keys.iter().map(|sk| sk.verification_key()).collect();
    let (new_policy, _) = refresh_shares(&policy, &new_vks, SecurityEpoch::from_raw(2)).unwrap();
    let mut ceremony = ThresholdCeremony::new(
        &new_policy,
        ThresholdScope::EmergencyRevocation,
        TEST_PREIMAGE,
        DeterministicTimestamp(3000),
    )
    .unwrap();
    let result = ceremony.submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(3001));
    assert!(matches!(
        result,
        Err(ThresholdError::UnauthorizedShareHolder { .. })
    ));
}

#[test]
fn share_refresh_result_serde_roundtrip() {
    let keys = make_keys(3);
    let policy = create_policy(2, &keys, make_scopes_all());
    let new_keys: Vec<SigningKey> = (0..3)
        .map(|i| SigningKey::from_bytes([(i + 50) as u8; 32]))
        .collect();
    let new_vks: Vec<VerificationKey> = new_keys.iter().map(|sk| sk.verification_key()).collect();
    let (_, refresh_result) =
        refresh_shares(&policy, &new_vks, SecurityEpoch::from_raw(2)).unwrap();
    let json = serde_json::to_string(&refresh_result).unwrap();
    let restored: ShareRefreshResult = serde_json::from_str(&json).unwrap();
    assert_eq!(refresh_result, restored);
}

// =========================================================================
// ThresholdError
// =========================================================================

#[test]
fn error_serde_all_variants_roundtrip() {
    let holder = ShareHolderId([0x42; 32]);
    let errors = [
        ThresholdError::InvalidThreshold {
            k: 0,
            n: 3,
            detail: "test".to_string(),
        },
        ThresholdError::InsufficientThresholdShares {
            collected: 1,
            required: 3,
        },
        ThresholdError::UnauthorizedShareHolder {
            holder: holder.clone(),
        },
        ThresholdError::DuplicateSubmission {
            holder: holder.clone(),
        },
        ThresholdError::DuplicateShareHolder,
        ThresholdError::PartialSignatureInvalid { holder },
        ThresholdError::SigningFailed {
            detail: "oops".to_string(),
        },
        ThresholdError::IdDerivationFailed {
            detail: "bad".to_string(),
        },
        ThresholdError::CeremonyAlreadyFinalized,
        ThresholdError::PreimageMismatch,
        ThresholdError::ScopeNotThresholded {
            scope: ThresholdScope::KeyRotation,
        },
        ThresholdError::NoScopedOperations,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: ThresholdError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored, "serde roundtrip failed for: {:?}", err);
    }
}

#[test]
fn error_display_all_non_empty() {
    let holder = ShareHolderId([0x42; 32]);
    let errors: Vec<ThresholdError> = vec![
        ThresholdError::InvalidThreshold {
            k: 0,
            n: 3,
            detail: "test".to_string(),
        },
        ThresholdError::InsufficientThresholdShares {
            collected: 1,
            required: 3,
        },
        ThresholdError::UnauthorizedShareHolder {
            holder: holder.clone(),
        },
        ThresholdError::DuplicateSubmission {
            holder: holder.clone(),
        },
        ThresholdError::DuplicateShareHolder,
        ThresholdError::PartialSignatureInvalid { holder },
        ThresholdError::SigningFailed {
            detail: "oops".to_string(),
        },
        ThresholdError::IdDerivationFailed {
            detail: "bad".to_string(),
        },
        ThresholdError::CeremonyAlreadyFinalized,
        ThresholdError::PreimageMismatch,
        ThresholdError::ScopeNotThresholded {
            scope: ThresholdScope::KeyRotation,
        },
        ThresholdError::NoScopedOperations,
    ];
    for err in &errors {
        assert!(!err.to_string().is_empty(), "empty display for {:?}", err);
    }
}

#[test]
fn error_display_contains_expected_substrings() {
    let err = ThresholdError::InvalidThreshold {
        k: 5,
        n: 3,
        detail: "too many".to_string(),
    };
    assert!(err.to_string().contains("5"));
    assert!(err.to_string().contains("3"));
    assert!(err.to_string().contains("too many"));

    let err = ThresholdError::InsufficientThresholdShares {
        collected: 1,
        required: 3,
    };
    assert!(err.to_string().contains("1/3"));

    let err = ThresholdError::CeremonyAlreadyFinalized;
    assert!(err.to_string().contains("finalized"));

    let err = ThresholdError::PreimageMismatch;
    assert!(err.to_string().contains("preimage"));
}

#[test]
fn error_implements_std_error() {
    let err = ThresholdError::PreimageMismatch;
    let _: &dyn std::error::Error = &err;
}

// =========================================================================
// ThresholdEventType / ThresholdEvent
// =========================================================================

#[test]
fn event_type_serde_all_variants() {
    let holder = ShareHolderId([0x42; 32]);
    let event_types = [
        ThresholdEventType::CeremonyInitiated {
            scope: ThresholdScope::EmergencyRevocation,
            threshold_k: 2,
            total_authorized: 3,
        },
        ThresholdEventType::PartialSignatureSubmitted {
            signer: holder.clone(),
            signatures_collected: 1,
            threshold_k: 2,
        },
        ThresholdEventType::UnauthorizedSubmission {
            signer: holder.clone(),
        },
        ThresholdEventType::CeremonyFinalized {
            participants: vec![holder],
        },
    ];
    for et in &event_types {
        let json = serde_json::to_string(et).unwrap();
        let restored: ThresholdEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*et, restored);
    }
}

#[test]
fn ceremony_drain_events_clears() {
    let keys = make_keys(3);
    let policy = create_policy(2, &keys, make_scopes_all());
    let mut ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        TEST_PREIMAGE,
        DeterministicTimestamp(1000),
    )
    .unwrap();
    ceremony
        .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
        .unwrap();
    let events = ceremony.drain_events();
    assert!(!events.is_empty());
    // Second drain should be empty
    let events2 = ceremony.drain_events();
    assert!(events2.is_empty());
}

#[test]
fn ceremony_events_include_unauthorized() {
    let keys = make_keys(3);
    let policy = create_policy(2, &keys, make_scopes_all());
    let mut ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        TEST_PREIMAGE,
        DeterministicTimestamp(1000),
    )
    .unwrap();
    let rogue = SigningKey::from_bytes([0xFF; 32]);
    let _ = ceremony.submit_partial(&rogue, TEST_PREIMAGE, DeterministicTimestamp(1001));
    let events = ceremony.drain_events();
    assert!(events.iter().any(|e| matches!(
        e.event_type,
        ThresholdEventType::UnauthorizedSubmission { .. }
    )));
}

// =========================================================================
// PartialSignature
// =========================================================================

#[test]
fn partial_signature_serde_roundtrip() {
    let keys = make_keys(3);
    let policy = create_policy(2, &keys, make_scopes_all());
    let mut ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        TEST_PREIMAGE,
        DeterministicTimestamp(1000),
    )
    .unwrap();
    ceremony
        .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
        .unwrap();
    ceremony
        .submit_partial(&keys[1], TEST_PREIMAGE, DeterministicTimestamp(1002))
        .unwrap();
    let result = ceremony.finalize(TEST_PREIMAGE).unwrap();
    for sig in &result.signatures {
        let json = serde_json::to_string(sig).unwrap();
        let restored: PartialSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(*sig, restored);
    }
}

// =========================================================================
// Schema constants
// =========================================================================

#[test]
fn schema_functions_deterministic() {
    let s1 = threshold_policy_schema();
    let s2 = threshold_policy_schema();
    assert_eq!(s1, s2);

    let id1 = threshold_policy_schema_id();
    let id2 = threshold_policy_schema_id();
    assert_eq!(id1, id2);

    let cid1 = threshold_ceremony_schema_id();
    let cid2 = threshold_ceremony_schema_id();
    assert_eq!(cid1, cid2);
}

#[test]
fn schema_ids_distinct() {
    let policy_id = threshold_policy_schema_id();
    let ceremony_id = threshold_ceremony_schema_id();
    assert_ne!(policy_id, ceremony_id);
}

// =========================================================================
// Determinism
// =========================================================================

#[test]
fn ceremony_deterministic_100_iterations() {
    let keys = make_keys(3);
    let policy = create_policy(2, &keys, make_scopes_all());
    let key_refs: Vec<&SigningKey> = keys.iter().take(2).collect();

    let baseline = run_ceremony(
        &policy,
        ThresholdScope::EmergencyRevocation,
        &key_refs,
        TEST_PREIMAGE,
    );
    for _ in 0..100 {
        let run = run_ceremony(
            &policy,
            ThresholdScope::EmergencyRevocation,
            &key_refs,
            TEST_PREIMAGE,
        );
        assert_eq!(baseline.ceremony_id, run.ceremony_id);
        assert_eq!(baseline.signatures.len(), run.signatures.len());
        for (s1, s2) in baseline.signatures.iter().zip(run.signatures.iter()) {
            assert_eq!(s1.signature, s2.signature);
            assert_eq!(s1.signer, s2.signer);
        }
    }
}

// =========================================================================
// Integration
// =========================================================================

#[test]
fn integration_full_lifecycle_with_refresh() {
    // Create initial policy
    let keys = make_keys(4);
    let policy = create_policy(2, &keys, make_scopes_all());

    // Run ceremony with initial keys
    let key_refs: Vec<&SigningKey> = keys.iter().take(2).collect();
    let result1 = run_ceremony(
        &policy,
        ThresholdScope::EmergencyRevocation,
        &key_refs,
        TEST_PREIMAGE,
    );
    result1.verify(TEST_PREIMAGE).expect("verify initial");

    // Refresh shares
    let new_keys: Vec<SigningKey> = (0..4)
        .map(|i| SigningKey::from_bytes([(i + 80) as u8; 32]))
        .collect();
    let new_vks: Vec<VerificationKey> = new_keys.iter().map(|sk| sk.verification_key()).collect();
    let (new_policy, _refresh) =
        refresh_shares(&policy, &new_vks, SecurityEpoch::from_raw(2)).unwrap();

    // Run ceremony with new keys
    let new_key_refs: Vec<&SigningKey> = new_keys.iter().take(2).collect();
    let result2 = run_ceremony(
        &new_policy,
        ThresholdScope::EmergencyRevocation,
        &new_key_refs,
        TEST_PREIMAGE,
    );
    result2.verify(TEST_PREIMAGE).expect("verify after refresh");

    // Old keys can't sign under new policy
    let mut ceremony = ThresholdCeremony::new(
        &new_policy,
        ThresholdScope::EmergencyRevocation,
        TEST_PREIMAGE,
        DeterministicTimestamp(5000),
    )
    .unwrap();
    assert!(
        ceremony
            .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(5001))
            .is_err()
    );
}

#[test]
fn integration_different_subsets_both_valid() {
    let keys = make_keys(5);
    let policy = create_policy(2, &keys, make_scopes_all());

    // Subset A: keys 0,1
    let refs_a: Vec<&SigningKey> = vec![&keys[0], &keys[1]];
    let result_a = run_ceremony(
        &policy,
        ThresholdScope::EmergencyRevocation,
        &refs_a,
        TEST_PREIMAGE,
    );
    result_a.verify(TEST_PREIMAGE).expect("verify A");

    // Subset B: keys 3,4
    let refs_b: Vec<&SigningKey> = vec![&keys[3], &keys[4]];
    let result_b = run_ceremony(
        &policy,
        ThresholdScope::EmergencyRevocation,
        &refs_b,
        TEST_PREIMAGE,
    );
    result_b.verify(TEST_PREIMAGE).expect("verify B");

    // Different ceremony IDs (different timestamps in run_ceremony)
    assert_ne!(result_a.participating_shares, result_b.participating_shares);
}

#[test]
fn integration_all_scope_types_work() {
    let keys = make_keys(3);
    let policy = create_policy(2, &keys, make_scopes_all());
    let key_refs: Vec<&SigningKey> = keys.iter().take(2).collect();

    for scope in ThresholdScope::ALL {
        let result = run_ceremony(&policy, *scope, &key_refs, TEST_PREIMAGE);
        result.verify(TEST_PREIMAGE).unwrap_or_else(|e| {
            panic!("verify failed for scope {:?}: {}", scope, e);
        });
        assert_eq!(result.scope, *scope);
    }
}
