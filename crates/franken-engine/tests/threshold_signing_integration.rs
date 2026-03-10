#![forbid(unsafe_code)]
//! Integration tests for the `threshold_signing` module.
//!
//! Covers: ThresholdScope, ShareHolderId, ThresholdSigningPolicy,
//! CreateThresholdPolicyInput, ThresholdCeremony, PartialSignature,
//! ThresholdResult, ShareRefreshResult, ThresholdError, ThresholdEventType,
//! ThresholdEvent, refresh_shares, threshold_policy_schema,
//! threshold_policy_schema_id, threshold_ceremony_schema_id.

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

use frankenengine_engine::capability_token::PrincipalId;
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{SigningKey, VerificationKey};
use frankenengine_engine::threshold_signing::{
    CreateThresholdPolicyInput, ShareHolderId, ShareRefreshResult, ThresholdCeremony,
    ThresholdError, ThresholdEvent, ThresholdEventType, ThresholdResult, ThresholdScope,
    ThresholdSigningPolicy, refresh_shares, threshold_ceremony_schema_id, threshold_policy_schema,
    threshold_policy_schema_id,
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const TEST_ZONE: &str = "integration-zone";
const TEST_PREIMAGE: &[u8] = b"emergency-revocation-preimage-integration-v1";

fn make_share_keys(count: usize) -> Vec<SigningKey> {
    (0..count)
        .map(|i| SigningKey::from_bytes([(i + 10) as u8; 32]))
        .collect()
}

fn make_share_holder_ids(keys: &[SigningKey]) -> BTreeSet<ShareHolderId> {
    keys.iter()
        .map(|sk| ShareHolderId::from_verification_key(&sk.verification_key()))
        .collect()
}

fn make_scopes() -> BTreeSet<ThresholdScope> {
    let mut scopes = BTreeSet::new();
    scopes.insert(ThresholdScope::EmergencyRevocation);
    scopes.insert(ThresholdScope::KeyRotation);
    scopes
}

fn all_scopes() -> BTreeSet<ThresholdScope> {
    ThresholdScope::ALL.iter().copied().collect()
}

fn test_principal() -> PrincipalId {
    PrincipalId::from_bytes([0x42; 32])
}

fn create_test_policy(k: u32, keys: &[SigningKey]) -> ThresholdSigningPolicy {
    ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
        principal_id: test_principal(),
        threshold_k: k,
        authorized_shares: make_share_holder_ids(keys),
        scoped_operations: make_scopes(),
        epoch: SecurityEpoch::from_raw(1),
        zone: TEST_ZONE,
    })
    .expect("create policy")
}

fn create_test_policy_with_scopes(
    k: u32,
    keys: &[SigningKey],
    scopes: BTreeSet<ThresholdScope>,
) -> ThresholdSigningPolicy {
    ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
        principal_id: test_principal(),
        threshold_k: k,
        authorized_shares: make_share_holder_ids(keys),
        scoped_operations: scopes,
        epoch: SecurityEpoch::from_raw(1),
        zone: TEST_ZONE,
    })
    .expect("create policy with scopes")
}

// =========================================================================
// Section 1: Display impls
// =========================================================================

#[test]
fn threshold_scope_display_all_variants() {
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
fn share_holder_id_display_starts_with_share_prefix() {
    let sk = SigningKey::from_bytes([0x42; 32]);
    let holder = ShareHolderId::from_verification_key(&sk.verification_key());
    let display = holder.to_string();
    assert!(
        display.starts_with("share:"),
        "display must start with 'share:', got: {display}"
    );
    // The hex portion after "share:" should be 16 characters.
    let hex_part = &display["share:".len()..];
    assert_eq!(hex_part.len(), 16);
}

#[test]
fn share_holder_id_to_hex_is_64_chars() {
    let sk = SigningKey::from_bytes([0xAA; 32]);
    let holder = ShareHolderId::from_verification_key(&sk.verification_key());
    let hex = holder.to_hex();
    assert_eq!(hex.len(), 64, "hex representation must be 64 characters");
}

#[test]
fn policy_display_contains_threshold_ratio() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
    let display = policy.to_string();
    assert!(
        display.contains("2-of-3"),
        "display must contain threshold ratio, got: {display}"
    );
    assert!(
        display.contains("ThresholdPolicy"),
        "display must contain type name, got: {display}"
    );
}

#[test]
fn threshold_error_display_variants() {
    let err1 = ThresholdError::InvalidThreshold {
        k: 5,
        n: 3,
        detail: "k exceeds n".into(),
    };
    assert!(err1.to_string().contains("5-of-3"));
    assert!(err1.to_string().contains("k exceeds n"));

    let err2 = ThresholdError::InsufficientThresholdShares {
        collected: 1,
        required: 3,
    };
    assert!(err2.to_string().contains("1/3"));

    let err3 = ThresholdError::CeremonyAlreadyFinalized;
    assert!(err3.to_string().contains("already finalized"));

    let err4 = ThresholdError::PreimageMismatch;
    assert!(err4.to_string().contains("preimage"));

    let err5 = ThresholdError::NoScopedOperations;
    assert!(err5.to_string().contains("no scoped operations"));

    let err6 = ThresholdError::DuplicateShareHolder;
    assert!(err6.to_string().contains("duplicate share holder"));

    let sk = SigningKey::from_bytes([0xFF; 32]);
    let holder = ShareHolderId::from_verification_key(&sk.verification_key());

    let err7 = ThresholdError::UnauthorizedShareHolder {
        holder: holder.clone(),
    };
    assert!(err7.to_string().contains("unauthorized"));

    let err8 = ThresholdError::DuplicateSubmission {
        holder: holder.clone(),
    };
    assert!(err8.to_string().contains("duplicate submission"));

    let err9 = ThresholdError::PartialSignatureInvalid {
        holder: holder.clone(),
    };
    assert!(err9.to_string().contains("invalid"));

    let err10 = ThresholdError::SigningFailed {
        detail: "key error".into(),
    };
    assert!(err10.to_string().contains("key error"));

    let err11 = ThresholdError::IdDerivationFailed {
        detail: "id error".into(),
    };
    assert!(err11.to_string().contains("id error"));

    let err12 = ThresholdError::ScopeNotThresholded {
        scope: ThresholdScope::PolicyCheckpoint,
    };
    assert!(err12.to_string().contains("policy_checkpoint"));
}

// =========================================================================
// Section 2: Construction / Defaults
// =========================================================================

#[test]
fn threshold_scope_all_has_four_variants() {
    assert_eq!(ThresholdScope::ALL.len(), 4);
    let unique: BTreeSet<ThresholdScope> = ThresholdScope::ALL.iter().copied().collect();
    assert_eq!(unique.len(), 4);
}

#[test]
fn share_holder_id_from_verification_key() {
    let sk = SigningKey::from_bytes([0x10; 32]);
    let vk = sk.verification_key();
    let holder = ShareHolderId::from_verification_key(&vk);
    assert_eq!(holder.as_bytes().len(), 32);
}

#[test]
fn share_holder_id_deterministic() {
    let sk = SigningKey::from_bytes([0x20; 32]);
    let vk = sk.verification_key();
    let h1 = ShareHolderId::from_verification_key(&vk);
    let h2 = ShareHolderId::from_verification_key(&vk);
    assert_eq!(h1, h2);
}

#[test]
fn share_holder_id_different_keys_produce_different_ids() {
    let sk1 = SigningKey::from_bytes([0x10; 32]);
    let sk2 = SigningKey::from_bytes([0x20; 32]);
    let h1 = ShareHolderId::from_verification_key(&sk1.verification_key());
    let h2 = ShareHolderId::from_verification_key(&sk2.verification_key());
    assert_ne!(h1, h2);
}

#[test]
fn schema_functions_return_valid_values() {
    let policy_schema = threshold_policy_schema();
    let policy_schema_id = threshold_policy_schema_id();
    let ceremony_schema_id = threshold_ceremony_schema_id();

    // Schemas should be deterministic.
    assert_eq!(policy_schema, threshold_policy_schema());
    assert_eq!(policy_schema_id, threshold_policy_schema_id());
    assert_eq!(ceremony_schema_id, threshold_ceremony_schema_id());
}

// =========================================================================
// Section 3: Policy creation
// =========================================================================

#[test]
fn create_policy_2_of_3() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
    assert_eq!(policy.threshold_k, 2);
    assert_eq!(policy.total_n, 3);
    assert_eq!(policy.authorized_shares.len(), 3);
    assert_eq!(policy.principal_id, test_principal());
    assert_eq!(policy.epoch, SecurityEpoch::from_raw(1));
    assert_eq!(policy.zone, TEST_ZONE);
}

#[test]
fn create_policy_3_of_5() {
    let keys = make_share_keys(5);
    let policy = create_test_policy(3, &keys);
    assert_eq!(policy.threshold_k, 3);
    assert_eq!(policy.total_n, 5);
}

#[test]
fn create_policy_k_equals_n() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(3, &keys);
    assert_eq!(policy.threshold_k, 3);
    assert_eq!(policy.total_n, 3);
}

#[test]
fn create_policy_2_of_2_minimum() {
    let keys = make_share_keys(2);
    let policy = create_test_policy(2, &keys);
    assert_eq!(policy.threshold_k, 2);
    assert_eq!(policy.total_n, 2);
}

#[test]
fn create_policy_with_all_scopes() {
    let keys = make_share_keys(3);
    let policy = create_test_policy_with_scopes(2, &keys, all_scopes());
    assert_eq!(policy.scoped_operations.len(), 4);
    for scope in ThresholdScope::ALL {
        assert!(policy.requires_threshold(*scope));
    }
}

#[test]
fn create_policy_deterministic_id() {
    let keys = make_share_keys(3);
    let p1 = create_test_policy(2, &keys);
    let p2 = create_test_policy(2, &keys);
    assert_eq!(p1.policy_id, p2.policy_id);
}

#[test]
fn create_policy_different_keys_different_id() {
    let keys1 = make_share_keys(3);
    let keys2: Vec<SigningKey> = (0..3)
        .map(|i| SigningKey::from_bytes([(i + 50) as u8; 32]))
        .collect();
    let p1 = create_test_policy(2, &keys1);
    let p2 = create_test_policy(2, &keys2);
    assert_ne!(p1.policy_id, p2.policy_id);
}

// =========================================================================
// Section 4: Policy creation — error conditions
// =========================================================================

#[test]
fn create_policy_zero_threshold_rejected() {
    let keys = make_share_keys(3);
    let result = ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
        principal_id: test_principal(),
        threshold_k: 0,
        authorized_shares: make_share_holder_ids(&keys),
        scoped_operations: make_scopes(),
        epoch: SecurityEpoch::from_raw(1),
        zone: TEST_ZONE,
    });
    assert!(matches!(
        result,
        Err(ThresholdError::InvalidThreshold { k: 0, .. })
    ));
}

#[test]
fn create_policy_k_exceeds_n_rejected() {
    let keys = make_share_keys(3);
    let result = ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
        principal_id: test_principal(),
        threshold_k: 4,
        authorized_shares: make_share_holder_ids(&keys),
        scoped_operations: make_scopes(),
        epoch: SecurityEpoch::from_raw(1),
        zone: TEST_ZONE,
    });
    assert!(matches!(
        result,
        Err(ThresholdError::InvalidThreshold { k: 4, n: 3, .. })
    ));
}

#[test]
fn create_policy_single_share_rejected() {
    let keys = make_share_keys(1);
    let result = ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
        principal_id: test_principal(),
        threshold_k: 1,
        authorized_shares: make_share_holder_ids(&keys),
        scoped_operations: make_scopes(),
        epoch: SecurityEpoch::from_raw(1),
        zone: TEST_ZONE,
    });
    assert!(matches!(
        result,
        Err(ThresholdError::InvalidThreshold { n: 1, .. })
    ));
}

#[test]
fn create_policy_no_scopes_rejected() {
    let keys = make_share_keys(3);
    let result = ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
        principal_id: test_principal(),
        threshold_k: 2,
        authorized_shares: make_share_holder_ids(&keys),
        scoped_operations: BTreeSet::new(),
        epoch: SecurityEpoch::from_raw(1),
        zone: TEST_ZONE,
    });
    assert!(matches!(result, Err(ThresholdError::NoScopedOperations)));
}

// =========================================================================
// Section 5: Policy authorization checks
// =========================================================================

#[test]
fn policy_requires_threshold_for_scoped_operations() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
    assert!(policy.requires_threshold(ThresholdScope::EmergencyRevocation));
    assert!(policy.requires_threshold(ThresholdScope::KeyRotation));
    assert!(!policy.requires_threshold(ThresholdScope::AuthoritySetChange));
    assert!(!policy.requires_threshold(ThresholdScope::PolicyCheckpoint));
}

#[test]
fn policy_is_authorized_for_known_holders() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
    for key in &keys {
        let holder = ShareHolderId::from_verification_key(&key.verification_key());
        assert!(policy.is_authorized(&holder));
    }
}

#[test]
fn policy_is_not_authorized_for_unknown_holder() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
    let rogue = ShareHolderId(*VerificationKey::from_bytes([0xFF; 32]).as_bytes());
    assert!(!policy.is_authorized(&rogue));
}

// =========================================================================
// Section 6: Ceremony — basic flow
// =========================================================================

#[test]
fn ceremony_2_of_3_succeeds() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
    let mut ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        TEST_PREIMAGE,
        DeterministicTimestamp(1000),
    )
    .expect("new ceremony");

    assert!(!ceremony.is_threshold_met());
    assert_eq!(ceremony.signatures_collected(), 0);
    assert_eq!(ceremony.scope, ThresholdScope::EmergencyRevocation);
    assert_eq!(ceremony.threshold_k, 2);
    assert_eq!(ceremony.policy_id, policy.policy_id);

    ceremony
        .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
        .expect("partial 0");
    assert!(!ceremony.is_threshold_met());
    assert_eq!(ceremony.signatures_collected(), 1);

    ceremony
        .submit_partial(&keys[1], TEST_PREIMAGE, DeterministicTimestamp(1002))
        .expect("partial 1");
    assert!(ceremony.is_threshold_met());
    assert_eq!(ceremony.signatures_collected(), 2);

    let result = ceremony.finalize(TEST_PREIMAGE).expect("finalize");
    assert_eq!(result.threshold_k, 2);
    assert_eq!(result.signatures.len(), 2);
    assert_eq!(result.scope, ThresholdScope::EmergencyRevocation);
}

#[test]
fn ceremony_3_of_5_succeeds() {
    let keys = make_share_keys(5);
    let policy = create_test_policy(3, &keys);
    let mut ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::KeyRotation,
        TEST_PREIMAGE,
        DeterministicTimestamp(1000),
    )
    .expect("new ceremony");

    for (i, key) in keys.iter().take(3).enumerate() {
        ceremony
            .submit_partial(key, TEST_PREIMAGE, DeterministicTimestamp(1000 + i as u64))
            .expect("partial");
    }
    assert!(ceremony.is_threshold_met());

    let result = ceremony.finalize(TEST_PREIMAGE).expect("finalize");
    assert_eq!(result.signatures.len(), 3);
    assert_eq!(result.participating_shares.len(), 3);
}

#[test]
fn ceremony_all_shares_submitting() {
    let keys = make_share_keys(5);
    let policy = create_test_policy(3, &keys);
    let mut ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        TEST_PREIMAGE,
        DeterministicTimestamp(1000),
    )
    .unwrap();

    for (i, key) in keys.iter().enumerate() {
        ceremony
            .submit_partial(key, TEST_PREIMAGE, DeterministicTimestamp(1000 + i as u64))
            .unwrap();
    }
    assert_eq!(ceremony.signatures_collected(), 5);
    let result = ceremony.finalize(TEST_PREIMAGE).unwrap();
    assert_eq!(result.signatures.len(), 5);
    result.verify(TEST_PREIMAGE).expect("verify all");
}

#[test]
fn ceremony_different_subsets_both_valid() {
    let keys = make_share_keys(4);
    let policy = create_test_policy(2, &keys);

    // Subset A: keys[0] and keys[1]
    let mut ceremony_a = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        TEST_PREIMAGE,
        DeterministicTimestamp(1000),
    )
    .unwrap();
    ceremony_a
        .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
        .unwrap();
    ceremony_a
        .submit_partial(&keys[1], TEST_PREIMAGE, DeterministicTimestamp(1002))
        .unwrap();
    let result_a = ceremony_a.finalize(TEST_PREIMAGE).unwrap();

    // Subset B: keys[2] and keys[3]
    let mut ceremony_b = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        TEST_PREIMAGE,
        DeterministicTimestamp(2000),
    )
    .unwrap();
    ceremony_b
        .submit_partial(&keys[2], TEST_PREIMAGE, DeterministicTimestamp(2001))
        .unwrap();
    ceremony_b
        .submit_partial(&keys[3], TEST_PREIMAGE, DeterministicTimestamp(2002))
        .unwrap();
    let result_b = ceremony_b.finalize(TEST_PREIMAGE).unwrap();

    // Both should verify independently.
    result_a.verify(TEST_PREIMAGE).expect("verify subset A");
    result_b.verify(TEST_PREIMAGE).expect("verify subset B");
}

#[test]
fn ceremony_participants_list() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
    let mut ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        TEST_PREIMAGE,
        DeterministicTimestamp(1000),
    )
    .unwrap();

    assert!(ceremony.participants().is_empty());

    ceremony
        .submit_partial(&keys[2], TEST_PREIMAGE, DeterministicTimestamp(1001))
        .unwrap();
    let participants = ceremony.participants();
    assert_eq!(participants.len(), 1);
    assert_eq!(
        *participants[0],
        ShareHolderId::from_verification_key(&keys[2].verification_key())
    );

    ceremony
        .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1002))
        .unwrap();
    assert_eq!(ceremony.participants().len(), 2);
}

// =========================================================================
// Section 7: Ceremony — error conditions
// =========================================================================

#[test]
fn ceremony_insufficient_shares_on_finalize() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
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
            required: 2,
        })
    ));
}

#[test]
fn ceremony_unauthorized_holder_rejected() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
    let mut ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        TEST_PREIMAGE,
        DeterministicTimestamp(1000),
    )
    .unwrap();

    let rogue_key = SigningKey::from_bytes([0xFF; 32]);
    let result = ceremony.submit_partial(&rogue_key, TEST_PREIMAGE, DeterministicTimestamp(1001));
    assert!(matches!(
        result,
        Err(ThresholdError::UnauthorizedShareHolder { .. })
    ));
}

#[test]
fn ceremony_duplicate_submission_rejected() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
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
fn ceremony_wrong_preimage_rejected() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
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
fn ceremony_non_threshold_scope_rejected() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
    let result = ThresholdCeremony::new(
        &policy,
        ThresholdScope::AuthoritySetChange,
        TEST_PREIMAGE,
        DeterministicTimestamp(1000),
    );
    assert!(matches!(
        result,
        Err(ThresholdError::ScopeNotThresholded { .. })
    ));
}

#[test]
fn ceremony_finalize_twice_rejected() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
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

    ceremony.finalize(TEST_PREIMAGE).expect("first finalize");
    let result = ceremony.finalize(TEST_PREIMAGE);
    assert!(matches!(
        result,
        Err(ThresholdError::CeremonyAlreadyFinalized)
    ));
}

#[test]
fn ceremony_submit_after_finalize_rejected() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
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
fn ceremony_zero_shares_finalize_rejected() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
    let mut ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        TEST_PREIMAGE,
        DeterministicTimestamp(1000),
    )
    .unwrap();

    let result = ceremony.finalize(TEST_PREIMAGE);
    assert!(matches!(
        result,
        Err(ThresholdError::InsufficientThresholdShares {
            collected: 0,
            required: 2,
        })
    ));
}

// =========================================================================
// Section 8: Result verification
// =========================================================================

#[test]
fn result_verify_succeeds() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
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
    result.verify(TEST_PREIMAGE).expect("verify");
}

#[test]
fn result_verify_wrong_preimage_fails() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
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
    let verify_result = result.verify(b"wrong-preimage");
    assert!(matches!(
        verify_result,
        Err(ThresholdError::PreimageMismatch)
    ));
}

#[test]
fn result_fields_populated() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
    let mut ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::KeyRotation,
        TEST_PREIMAGE,
        DeterministicTimestamp(1000),
    )
    .unwrap();

    ceremony
        .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
        .unwrap();
    ceremony
        .submit_partial(&keys[2], TEST_PREIMAGE, DeterministicTimestamp(1002))
        .unwrap();

    let result = ceremony.finalize(TEST_PREIMAGE).unwrap();
    assert_eq!(result.policy_id, policy.policy_id);
    assert_eq!(result.scope, ThresholdScope::KeyRotation);
    assert_eq!(result.threshold_k, 2);
    assert_eq!(result.signatures.len(), 2);
    assert_eq!(result.participating_shares.len(), 2);
    // Preimage hash should be populated.
    assert_ne!(result.preimage_hash, [0u8; 32]);
}

// =========================================================================
// Section 9: Share refresh
// =========================================================================

#[test]
fn share_refresh_produces_new_policy() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
    let new_keys: Vec<SigningKey> = (0..3)
        .map(|i| SigningKey::from_bytes([(i + 50) as u8; 32]))
        .collect();
    let new_vks: Vec<VerificationKey> = new_keys.iter().map(|sk| sk.verification_key()).collect();

    let (new_policy, refresh_result) =
        refresh_shares(&policy, &new_vks, SecurityEpoch::from_raw(2)).expect("refresh");

    assert_eq!(new_policy.threshold_k, 2);
    assert_eq!(new_policy.total_n, 3);
    assert_ne!(new_policy.policy_id, policy.policy_id);
    assert_eq!(new_policy.epoch, SecurityEpoch::from_raw(2));
    assert_eq!(new_policy.principal_id, policy.principal_id);
    assert_eq!(new_policy.scoped_operations, policy.scoped_operations);
    assert_eq!(refresh_result.old_shares.len(), 3);
    assert_eq!(refresh_result.new_shares.len(), 3);
    assert_eq!(refresh_result.policy_id, policy.policy_id);
    assert_eq!(refresh_result.refresh_epoch, SecurityEpoch::from_raw(2));
}

#[test]
fn share_refresh_new_keys_work_in_ceremony() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
    let new_keys: Vec<SigningKey> = (0..3)
        .map(|i| SigningKey::from_bytes([(i + 50) as u8; 32]))
        .collect();
    let new_vks: Vec<VerificationKey> = new_keys.iter().map(|sk| sk.verification_key()).collect();

    let (new_policy, _) = refresh_shares(&policy, &new_vks, SecurityEpoch::from_raw(2)).unwrap();

    let mut ceremony = ThresholdCeremony::new(
        &new_policy,
        ThresholdScope::EmergencyRevocation,
        TEST_PREIMAGE,
        DeterministicTimestamp(2000),
    )
    .unwrap();

    ceremony
        .submit_partial(&new_keys[0], TEST_PREIMAGE, DeterministicTimestamp(2001))
        .unwrap();
    ceremony
        .submit_partial(&new_keys[1], TEST_PREIMAGE, DeterministicTimestamp(2002))
        .unwrap();
    let result = ceremony.finalize(TEST_PREIMAGE).unwrap();
    result.verify(TEST_PREIMAGE).expect("verify with new keys");
}

#[test]
fn share_refresh_old_keys_rejected_in_new_policy() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
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
fn share_refresh_wrong_count_rejected() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
    let new_vks: Vec<VerificationKey> = make_share_keys(2)
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
fn share_refresh_duplicate_keys_rejected() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
    // Three keys but two are the same.
    let dup_key = SigningKey::from_bytes([0x99; 32]);
    let unique_key = SigningKey::from_bytes([0xAA; 32]);
    let new_vks = vec![
        dup_key.verification_key(),
        dup_key.verification_key(),
        unique_key.verification_key(),
    ];
    let result = refresh_shares(&policy, &new_vks, SecurityEpoch::from_raw(2));
    assert!(matches!(result, Err(ThresholdError::DuplicateShareHolder)));
}

// =========================================================================
// Section 10: Audit events
// =========================================================================

#[test]
fn audit_events_ceremony_lifecycle() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
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

    let events = ceremony.drain_events();
    assert_eq!(events.len(), 4); // init + 2 partials + finalize

    assert!(matches!(
        events[0].event_type,
        ThresholdEventType::CeremonyInitiated { .. }
    ));
    assert!(matches!(
        events[1].event_type,
        ThresholdEventType::PartialSignatureSubmitted { .. }
    ));
    assert!(matches!(
        events[2].event_type,
        ThresholdEventType::PartialSignatureSubmitted { .. }
    ));
    assert!(matches!(
        events[3].event_type,
        ThresholdEventType::CeremonyFinalized { .. }
    ));

    for event in &events {
        assert_eq!(event.ceremony_id, ceremony.ceremony_id);
        assert_eq!(event.zone, TEST_ZONE);
    }
}

#[test]
fn audit_event_on_unauthorized_attempt() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
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
    assert_eq!(events.len(), 2); // init + unauthorized
    assert!(matches!(
        events[1].event_type,
        ThresholdEventType::UnauthorizedSubmission { .. }
    ));
}

#[test]
fn audit_event_finalized_includes_participants() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
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
        .submit_partial(&keys[2], TEST_PREIMAGE, DeterministicTimestamp(1002))
        .unwrap();
    ceremony.finalize(TEST_PREIMAGE).unwrap();

    let events = ceremony.drain_events();
    if let ThresholdEventType::CeremonyFinalized { participants } =
        &events.last().unwrap().event_type
    {
        assert_eq!(participants.len(), 2);
    } else {
        panic!("expected CeremonyFinalized event");
    }
}

#[test]
fn audit_event_initiated_contains_details() {
    let keys = make_share_keys(5);
    let policy = create_test_policy(3, &keys);
    let mut ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::KeyRotation,
        TEST_PREIMAGE,
        DeterministicTimestamp(1000),
    )
    .unwrap();

    let events = ceremony.drain_events();
    assert_eq!(events.len(), 1);
    if let ThresholdEventType::CeremonyInitiated {
        scope,
        threshold_k,
        total_authorized,
    } = &events[0].event_type
    {
        assert_eq!(*scope, ThresholdScope::KeyRotation);
        assert_eq!(*threshold_k, 3);
        assert_eq!(*total_authorized, 5);
    } else {
        panic!("expected CeremonyInitiated event");
    }
}

#[test]
fn drain_events_clears_buffer() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
    let mut ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        TEST_PREIMAGE,
        DeterministicTimestamp(1000),
    )
    .unwrap();

    let events_first = ceremony.drain_events();
    assert_eq!(events_first.len(), 1); // Just init event

    let events_second = ceremony.drain_events();
    assert!(events_second.is_empty(), "drain should clear the buffer");

    ceremony
        .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
        .unwrap();

    let events_third = ceremony.drain_events();
    assert_eq!(events_third.len(), 1); // Just the partial event
}

// =========================================================================
// Section 11: Serde roundtrips
// =========================================================================

#[test]
fn threshold_scope_serde_roundtrip() {
    for scope in ThresholdScope::ALL {
        let json = serde_json::to_string(scope).expect("serialize");
        let restored: ThresholdScope = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*scope, restored);
    }
}

#[test]
fn share_holder_id_serde_roundtrip() {
    let sk = SigningKey::from_bytes([0x42; 32]);
    let holder = ShareHolderId::from_verification_key(&sk.verification_key());
    let json = serde_json::to_string(&holder).expect("serialize");
    let restored: ShareHolderId = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(holder, restored);
}

#[test]
fn policy_serde_roundtrip() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
    let json = serde_json::to_string(&policy).expect("serialize");
    let restored: ThresholdSigningPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(policy, restored);
}

#[test]
fn result_serde_roundtrip() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
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

    let json = serde_json::to_string(&result).expect("serialize");
    let restored: ThresholdResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(result, restored);
}

#[test]
fn ceremony_serde_roundtrip_empty() {
    // ThresholdCeremony has BTreeMap<ShareHolderId, _> which fails JSON serde
    // ("key must be a string"). Test with empty partial_signatures to confirm
    // the struct itself is serde-capable before partial submissions trigger
    // the BTreeMap key issue.
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
    let ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        TEST_PREIMAGE,
        DeterministicTimestamp(1000),
    )
    .unwrap();

    let json = serde_json::to_string(&ceremony).expect("serialize empty ceremony");
    let restored: ThresholdCeremony = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ceremony.ceremony_id, restored.ceremony_id);
    assert_eq!(
        ceremony.signatures_collected(),
        restored.signatures_collected()
    );
    assert_eq!(ceremony.threshold_k, restored.threshold_k);
}

#[test]
fn ceremony_with_partials_json_serde_fails_gracefully() {
    // Demonstrates the known limitation: BTreeMap<ShareHolderId, _>
    // cannot be serialized to JSON. This is a documented constraint.
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
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

    // JSON serialization should fail because the BTreeMap key is not a string.
    let result = serde_json::to_string(&ceremony);
    assert!(
        result.is_err(),
        "BTreeMap<ShareHolderId, _> cannot serialize to JSON"
    );
}

#[test]
fn error_serde_roundtrip() {
    let sk = SigningKey::from_bytes([0xAA; 32]);
    let holder = ShareHolderId::from_verification_key(&sk.verification_key());

    let errors: Vec<ThresholdError> = vec![
        ThresholdError::InvalidThreshold {
            k: 5,
            n: 3,
            detail: "k > n".into(),
        },
        ThresholdError::InsufficientThresholdShares {
            collected: 1,
            required: 2,
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
            detail: "sign error".into(),
        },
        ThresholdError::IdDerivationFailed {
            detail: "id error".into(),
        },
        ThresholdError::CeremonyAlreadyFinalized,
        ThresholdError::PreimageMismatch,
        ThresholdError::ScopeNotThresholded {
            scope: ThresholdScope::PolicyCheckpoint,
        },
        ThresholdError::NoScopedOperations,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let restored: ThresholdError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, restored);
    }
}

#[test]
fn threshold_event_serde_roundtrip() {
    let sk = SigningKey::from_bytes([0x10; 32]);
    let holder = ShareHolderId::from_verification_key(&sk.verification_key());
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);

    let events = vec![
        ThresholdEvent {
            event_type: ThresholdEventType::CeremonyInitiated {
                scope: ThresholdScope::EmergencyRevocation,
                threshold_k: 2,
                total_authorized: 3,
            },
            ceremony_id: policy.policy_id.clone(),
            zone: TEST_ZONE.into(),
        },
        ThresholdEvent {
            event_type: ThresholdEventType::PartialSignatureSubmitted {
                signer: holder.clone(),
                signatures_collected: 1,
                threshold_k: 2,
            },
            ceremony_id: policy.policy_id.clone(),
            zone: TEST_ZONE.into(),
        },
        ThresholdEvent {
            event_type: ThresholdEventType::UnauthorizedSubmission {
                signer: holder.clone(),
            },
            ceremony_id: policy.policy_id.clone(),
            zone: TEST_ZONE.into(),
        },
        ThresholdEvent {
            event_type: ThresholdEventType::CeremonyFinalized {
                participants: vec![holder],
            },
            ceremony_id: policy.policy_id.clone(),
            zone: TEST_ZONE.into(),
        },
    ];

    for event in &events {
        let json = serde_json::to_string(event).expect("serialize");
        let restored: ThresholdEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*event, restored);
    }
}

#[test]
fn share_refresh_result_serde_roundtrip() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
    let new_keys: Vec<SigningKey> = (0..3)
        .map(|i| SigningKey::from_bytes([(i + 50) as u8; 32]))
        .collect();
    let new_vks: Vec<VerificationKey> = new_keys.iter().map(|sk| sk.verification_key()).collect();

    let (_, refresh_result) =
        refresh_shares(&policy, &new_vks, SecurityEpoch::from_raw(2)).unwrap();

    let json = serde_json::to_string(&refresh_result).expect("serialize");
    let restored: ShareRefreshResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(refresh_result, restored);
}

// =========================================================================
// Section 12: Deterministic replay
// =========================================================================

#[test]
fn ceremony_deterministic_replay() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);

    let run = || {
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
        ceremony.finalize(TEST_PREIMAGE).unwrap()
    };

    let r1 = run();
    let r2 = run();
    assert_eq!(r1.ceremony_id, r2.ceremony_id);
    assert_eq!(r1.signatures.len(), r2.signatures.len());
    for (s1, s2) in r1.signatures.iter().zip(r2.signatures.iter()) {
        assert_eq!(s1.signature, s2.signature);
        assert_eq!(s1.signer, s2.signer);
    }
    assert_eq!(
        serde_json::to_string(&r1).unwrap(),
        serde_json::to_string(&r2).unwrap()
    );
}

#[test]
fn policy_creation_deterministic() {
    let keys = make_share_keys(5);
    let p1 = create_test_policy(3, &keys);
    let p2 = create_test_policy(3, &keys);
    assert_eq!(
        serde_json::to_string(&p1).unwrap(),
        serde_json::to_string(&p2).unwrap()
    );
}

// =========================================================================
// Section 13: Error trait implementation
// =========================================================================

#[test]
fn threshold_error_implements_error_trait() {
    let err = ThresholdError::PreimageMismatch;
    let _: &dyn std::error::Error = &err;
}

#[test]
fn threshold_error_debug_format() {
    let err = ThresholdError::CeremonyAlreadyFinalized;
    let debug = format!("{err:?}");
    assert!(debug.contains("CeremonyAlreadyFinalized"));
}

// =========================================================================
// Section 14: State transitions — complex scenarios
// =========================================================================

#[test]
fn ceremony_with_key_rotation_scope() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
    let preimage = b"key-rotation-payload-v2";

    let mut ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::KeyRotation,
        preimage,
        DeterministicTimestamp(5000),
    )
    .unwrap();

    ceremony
        .submit_partial(&keys[1], preimage, DeterministicTimestamp(5001))
        .unwrap();
    ceremony
        .submit_partial(&keys[2], preimage, DeterministicTimestamp(5002))
        .unwrap();

    let result = ceremony.finalize(preimage).unwrap();
    result.verify(preimage).expect("verify key rotation result");
}

#[test]
fn multiple_ceremonies_same_policy_different_preimages() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);

    let preimage_a = b"operation-alpha";
    let preimage_b = b"operation-beta";

    let mut ceremony_a = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        preimage_a,
        DeterministicTimestamp(1000),
    )
    .unwrap();
    ceremony_a
        .submit_partial(&keys[0], preimage_a, DeterministicTimestamp(1001))
        .unwrap();
    ceremony_a
        .submit_partial(&keys[1], preimage_a, DeterministicTimestamp(1002))
        .unwrap();
    let result_a = ceremony_a.finalize(preimage_a).unwrap();

    let mut ceremony_b = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        preimage_b,
        DeterministicTimestamp(2000),
    )
    .unwrap();
    ceremony_b
        .submit_partial(&keys[0], preimage_b, DeterministicTimestamp(2001))
        .unwrap();
    ceremony_b
        .submit_partial(&keys[1], preimage_b, DeterministicTimestamp(2002))
        .unwrap();
    let result_b = ceremony_b.finalize(preimage_b).unwrap();

    // Different preimages produce different ceremony IDs.
    assert_ne!(result_a.ceremony_id, result_b.ceremony_id);

    // Each result verifies against its own preimage.
    result_a.verify(preimage_a).expect("verify A");
    result_b.verify(preimage_b).expect("verify B");

    // Cross-verification should fail.
    assert!(matches!(
        result_a.verify(preimage_b),
        Err(ThresholdError::PreimageMismatch)
    ));
}

#[test]
fn refresh_then_full_ceremony() {
    let original_keys = make_share_keys(4);
    let policy = create_test_policy_with_scopes(3, &original_keys, all_scopes());

    // Refresh shares.
    let new_keys: Vec<SigningKey> = (0..4)
        .map(|i| SigningKey::from_bytes([(i + 80) as u8; 32]))
        .collect();
    let new_vks: Vec<VerificationKey> = new_keys.iter().map(|sk| sk.verification_key()).collect();
    let (new_policy, _) = refresh_shares(&policy, &new_vks, SecurityEpoch::from_raw(3)).unwrap();

    // Run ceremony with new keys on a scope that wasn't in the original test helper.
    let preimage = b"authority-set-change-payload";
    let mut ceremony = ThresholdCeremony::new(
        &new_policy,
        ThresholdScope::AuthoritySetChange,
        preimage,
        DeterministicTimestamp(5000),
    )
    .unwrap();

    for (i, key) in new_keys.iter().take(3).enumerate() {
        ceremony
            .submit_partial(key, preimage, DeterministicTimestamp(5001 + i as u64))
            .unwrap();
    }

    let result = ceremony.finalize(preimage).unwrap();
    result.verify(preimage).expect("verify after refresh");
}

#[test]
fn ceremony_preimage_hash_stored_correctly() {
    let keys = make_share_keys(3);
    let policy = create_test_policy(2, &keys);
    let ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        TEST_PREIMAGE,
        DeterministicTimestamp(1000),
    )
    .unwrap();

    // Preimage hash should be the content hash of the preimage.
    assert_ne!(ceremony.preimage_hash, [0u8; 32]);
    // Same preimage should produce same hash.
    let ceremony2 = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        TEST_PREIMAGE,
        DeterministicTimestamp(1000),
    )
    .unwrap();
    assert_eq!(ceremony.preimage_hash, ceremony2.preimage_hash);
}

#[test]
fn policy_with_single_scope() {
    let keys = make_share_keys(3);
    let mut scopes = BTreeSet::new();
    scopes.insert(ThresholdScope::PolicyCheckpoint);
    let policy = create_test_policy_with_scopes(2, &keys, scopes);

    assert!(policy.requires_threshold(ThresholdScope::PolicyCheckpoint));
    assert!(!policy.requires_threshold(ThresholdScope::EmergencyRevocation));
    assert!(!policy.requires_threshold(ThresholdScope::KeyRotation));
    assert!(!policy.requires_threshold(ThresholdScope::AuthoritySetChange));
}

#[test]
fn policy_different_principals_different_ids() {
    let keys = make_share_keys(3);
    let shares = make_share_holder_ids(&keys);

    let p1 = ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
        principal_id: PrincipalId::from_bytes([0x01; 32]),
        threshold_k: 2,
        authorized_shares: shares.clone(),
        scoped_operations: make_scopes(),
        epoch: SecurityEpoch::from_raw(1),
        zone: TEST_ZONE,
    })
    .unwrap();

    let p2 = ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
        principal_id: PrincipalId::from_bytes([0x02; 32]),
        threshold_k: 2,
        authorized_shares: shares,
        scoped_operations: make_scopes(),
        epoch: SecurityEpoch::from_raw(1),
        zone: TEST_ZONE,
    })
    .unwrap();

    assert_ne!(p1.policy_id, p2.policy_id);
}

#[test]
fn policy_different_epochs_different_ids() {
    let keys = make_share_keys(3);
    let shares = make_share_holder_ids(&keys);

    let p1 = ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
        principal_id: test_principal(),
        threshold_k: 2,
        authorized_shares: shares.clone(),
        scoped_operations: make_scopes(),
        epoch: SecurityEpoch::from_raw(1),
        zone: TEST_ZONE,
    })
    .unwrap();

    let p2 = ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
        principal_id: test_principal(),
        threshold_k: 2,
        authorized_shares: shares,
        scoped_operations: make_scopes(),
        epoch: SecurityEpoch::from_raw(2),
        zone: TEST_ZONE,
    })
    .unwrap();

    assert_ne!(p1.policy_id, p2.policy_id);
}
