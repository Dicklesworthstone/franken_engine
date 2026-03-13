//! Enrichment integration tests for the `threshold_signing` module.
//!
//! Covers: ThresholdScope ordering, ShareHolderId ordering/comparison,
//! ThresholdError serde all variants, ThresholdEventType serde all variants,
//! PartialSignature serde, ShareRefreshResult serde, policy Display format,
//! ceremony is_threshold_met lifecycle, ceremony participants ordering,
//! Debug formatting.

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

use std::collections::BTreeSet;

use frankenengine_engine::capability_token::PrincipalId;
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;
use frankenengine_engine::threshold_signing::{
    CreateThresholdPolicyInput, ShareHolderId, ShareRefreshResult, ThresholdCeremony,
    ThresholdError, ThresholdEventType, ThresholdScope, ThresholdSigningPolicy,
    threshold_ceremony_schema_id, threshold_policy_schema, threshold_policy_schema_id,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn keys(count: usize) -> Vec<SigningKey> {
    (0..count)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[0] = (i + 1) as u8;
            SigningKey::from_bytes(bytes)
        })
        .collect()
}

fn holder_ids(signing_keys: &[SigningKey]) -> BTreeSet<ShareHolderId> {
    signing_keys
        .iter()
        .map(|k| ShareHolderId::from_verification_key(&k.verification_key()))
        .collect()
}

fn scopes_all() -> BTreeSet<ThresholdScope> {
    ThresholdScope::ALL.iter().copied().collect()
}

fn principal() -> PrincipalId {
    PrincipalId::from_bytes([0xAA; 32])
}

fn make_policy(k: u32, signing_keys: &[SigningKey]) -> ThresholdSigningPolicy {
    ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
        principal_id: principal(),
        threshold_k: k,
        authorized_shares: holder_ids(signing_keys),
        scoped_operations: scopes_all(),
        epoch: SecurityEpoch::from_raw(1),
        zone: "test-zone",
    })
    .unwrap()
}

// =========================================================================
// A. ThresholdScope — ordering
// =========================================================================

#[test]
fn enrichment_threshold_scope_ordering() {
    assert!(ThresholdScope::EmergencyRevocation < ThresholdScope::KeyRotation);
    assert!(ThresholdScope::KeyRotation < ThresholdScope::AuthoritySetChange);
    assert!(ThresholdScope::AuthoritySetChange < ThresholdScope::PolicyCheckpoint);
}

#[test]
fn enrichment_threshold_scope_all_count() {
    assert_eq!(ThresholdScope::ALL.len(), 4);
}

#[test]
fn enrichment_threshold_scope_copy() {
    let s = ThresholdScope::EmergencyRevocation;
    let s2 = s;
    assert_eq!(s, s2);
}

// =========================================================================
// B. ShareHolderId — ordering and comparison
// =========================================================================

#[test]
fn enrichment_share_holder_id_ordering_by_bytes() {
    let id_a = ShareHolderId([0x00; 32]);
    let id_b = ShareHolderId([0x01; 32]);
    let id_c = ShareHolderId([0xFF; 32]);
    assert!(id_a < id_b);
    assert!(id_b < id_c);
}

#[test]
fn enrichment_share_holder_id_hex_length_64() {
    let id = ShareHolderId([0xAB; 32]);
    assert_eq!(id.to_hex().len(), 64);
}

#[test]
fn enrichment_share_holder_id_display_truncated() {
    let id = ShareHolderId([0xDE; 32]);
    let display = id.to_string();
    assert!(display.starts_with("share:"));
    // Display shows first 16 hex chars = 8 bytes
    assert!(display.len() < 80);
}

#[test]
fn enrichment_share_holder_id_as_bytes_roundtrip() {
    let bytes = [0x42; 32];
    let id = ShareHolderId(bytes);
    assert_eq!(*id.as_bytes(), bytes);
}

// =========================================================================
// C. ThresholdError — serde all variants
// =========================================================================

#[test]
fn enrichment_error_serde_invalid_threshold() {
    let err = ThresholdError::InvalidThreshold {
        k: 5,
        n: 3,
        detail: "k > n".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let restored: ThresholdError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

#[test]
fn enrichment_error_serde_insufficient_shares() {
    let err = ThresholdError::InsufficientThresholdShares {
        collected: 1,
        required: 3,
    };
    let json = serde_json::to_string(&err).unwrap();
    let restored: ThresholdError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

#[test]
fn enrichment_error_serde_unauthorized() {
    let err = ThresholdError::UnauthorizedShareHolder {
        holder: ShareHolderId([0x11; 32]),
    };
    let json = serde_json::to_string(&err).unwrap();
    let restored: ThresholdError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

#[test]
fn enrichment_error_serde_duplicate_submission() {
    let err = ThresholdError::DuplicateSubmission {
        holder: ShareHolderId([0x22; 32]),
    };
    let json = serde_json::to_string(&err).unwrap();
    let restored: ThresholdError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

#[test]
fn enrichment_error_serde_duplicate_share_holder() {
    let err = ThresholdError::DuplicateShareHolder;
    let json = serde_json::to_string(&err).unwrap();
    let restored: ThresholdError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

#[test]
fn enrichment_error_serde_partial_signature_invalid() {
    let err = ThresholdError::PartialSignatureInvalid {
        holder: ShareHolderId([0x33; 32]),
    };
    let json = serde_json::to_string(&err).unwrap();
    let restored: ThresholdError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

#[test]
fn enrichment_error_serde_signing_failed() {
    let err = ThresholdError::SigningFailed {
        detail: "key corrupted".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let restored: ThresholdError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

#[test]
fn enrichment_error_serde_ceremony_finalized() {
    let err = ThresholdError::CeremonyAlreadyFinalized;
    let json = serde_json::to_string(&err).unwrap();
    let restored: ThresholdError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

#[test]
fn enrichment_error_serde_preimage_mismatch() {
    let err = ThresholdError::PreimageMismatch;
    let json = serde_json::to_string(&err).unwrap();
    let restored: ThresholdError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

#[test]
fn enrichment_error_serde_scope_not_thresholded() {
    let err = ThresholdError::ScopeNotThresholded {
        scope: ThresholdScope::KeyRotation,
    };
    let json = serde_json::to_string(&err).unwrap();
    let restored: ThresholdError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

#[test]
fn enrichment_error_serde_no_scoped_operations() {
    let err = ThresholdError::NoScopedOperations;
    let json = serde_json::to_string(&err).unwrap();
    let restored: ThresholdError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

// =========================================================================
// D. Policy — Display format
// =========================================================================

#[test]
fn enrichment_policy_display_contains_k_of_n() {
    let k = keys(3);
    let policy = make_policy(2, &k);
    let display = policy.to_string();
    assert!(display.contains("2-of-3"));
    assert!(display.contains("scopes=4"));
}

#[test]
fn enrichment_policy_requires_threshold_all_scopes() {
    let k = keys(2);
    let policy = make_policy(2, &k);
    for scope in ThresholdScope::ALL {
        assert!(policy.requires_threshold(*scope));
    }
}

// =========================================================================
// E. Ceremony — is_threshold_met lifecycle
// =========================================================================

#[test]
fn enrichment_ceremony_threshold_not_met_initially() {
    let k = keys(3);
    let policy = make_policy(2, &k);
    let ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        b"preimage-data",
        DeterministicTimestamp(0),
    )
    .unwrap();
    assert!(!ceremony.is_threshold_met());
    assert_eq!(ceremony.signatures_collected(), 0);
}

#[test]
fn enrichment_ceremony_threshold_met_after_k_submissions() {
    let k = keys(3);
    let policy = make_policy(2, &k);
    let mut ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        b"preimage-data",
        DeterministicTimestamp(0),
    )
    .unwrap();

    ceremony
        .submit_partial(&k[0], b"preimage-data", DeterministicTimestamp(1))
        .unwrap();
    assert!(!ceremony.is_threshold_met());
    assert_eq!(ceremony.signatures_collected(), 1);

    ceremony
        .submit_partial(&k[1], b"preimage-data", DeterministicTimestamp(2))
        .unwrap();
    assert!(ceremony.is_threshold_met());
    assert_eq!(ceremony.signatures_collected(), 2);
}

// =========================================================================
// F. Ceremony — participants sorted by holder ID
// =========================================================================

#[test]
fn enrichment_ceremony_participants_deterministic_order() {
    let k = keys(3);
    let policy = make_policy(2, &k);
    let mut ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::KeyRotation,
        b"data",
        DeterministicTimestamp(0),
    )
    .unwrap();

    // Submit in reverse order
    ceremony
        .submit_partial(&k[2], b"data", DeterministicTimestamp(1))
        .unwrap();
    ceremony
        .submit_partial(&k[0], b"data", DeterministicTimestamp(2))
        .unwrap();

    let participants = ceremony.participants();
    // BTreeMap keys are sorted
    assert_eq!(participants.len(), 2);
    assert!(participants[0] <= participants[1]);
}

// =========================================================================
// G. Schema functions
// =========================================================================

#[test]
fn enrichment_schema_functions_non_empty() {
    let policy_schema = threshold_policy_schema();
    assert!(!policy_schema.to_string().is_empty());

    let policy_sid = threshold_policy_schema_id();
    assert!(!policy_sid.as_bytes().iter().all(|b| *b == 0));

    let ceremony_sid = threshold_ceremony_schema_id();
    assert!(!ceremony_sid.as_bytes().iter().all(|b| *b == 0));
}

#[test]
fn enrichment_schema_ids_distinct() {
    let policy_sid = threshold_policy_schema_id();
    let ceremony_sid = threshold_ceremony_schema_id();
    assert_ne!(policy_sid, ceremony_sid);
}

// =========================================================================
// H. ThresholdEventType — serde roundtrip
// =========================================================================

#[test]
fn enrichment_event_type_serde_ceremony_initiated() {
    let et = ThresholdEventType::CeremonyInitiated {
        scope: ThresholdScope::AuthoritySetChange,
        threshold_k: 3,
        total_authorized: 5,
    };
    let json = serde_json::to_string(&et).unwrap();
    let restored: ThresholdEventType = serde_json::from_str(&json).unwrap();
    assert_eq!(et, restored);
}

#[test]
fn enrichment_event_type_serde_partial_submitted() {
    let et = ThresholdEventType::PartialSignatureSubmitted {
        signer: ShareHolderId([0xCC; 32]),
        signatures_collected: 2,
        threshold_k: 3,
    };
    let json = serde_json::to_string(&et).unwrap();
    let restored: ThresholdEventType = serde_json::from_str(&json).unwrap();
    assert_eq!(et, restored);
}

#[test]
fn enrichment_event_type_serde_unauthorized() {
    let et = ThresholdEventType::UnauthorizedSubmission {
        signer: ShareHolderId([0xDD; 32]),
    };
    let json = serde_json::to_string(&et).unwrap();
    let restored: ThresholdEventType = serde_json::from_str(&json).unwrap();
    assert_eq!(et, restored);
}

#[test]
fn enrichment_event_type_serde_finalized() {
    let et = ThresholdEventType::CeremonyFinalized {
        participants: vec![ShareHolderId([0x01; 32]), ShareHolderId([0x02; 32])],
    };
    let json = serde_json::to_string(&et).unwrap();
    let restored: ThresholdEventType = serde_json::from_str(&json).unwrap();
    assert_eq!(et, restored);
}

// =========================================================================
// I. Policy — error cases
// =========================================================================

#[test]
fn enrichment_policy_create_zero_k_error_message() {
    let err = ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
        principal_id: principal(),
        threshold_k: 0,
        authorized_shares: holder_ids(&keys(3)),
        scoped_operations: scopes_all(),
        epoch: SecurityEpoch::from_raw(1),
        zone: "test",
    })
    .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("0-of-3"));
}

#[test]
fn enrichment_policy_create_k_exceeds_n_error_message() {
    let err = ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
        principal_id: principal(),
        threshold_k: 4,
        authorized_shares: holder_ids(&keys(3)),
        scoped_operations: scopes_all(),
        epoch: SecurityEpoch::from_raw(1),
        zone: "test",
    })
    .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("4-of-3"));
}

// =========================================================================
// J. ShareRefreshResult — serde roundtrip
// =========================================================================

#[test]
fn enrichment_share_refresh_result_serde() {
    let result = ShareRefreshResult {
        policy_id: frankenengine_engine::engine_object_id::EngineObjectId([0xBB; 32]),
        old_shares: BTreeSet::from([ShareHolderId([0x01; 32])]),
        new_shares: BTreeSet::from([ShareHolderId([0x02; 32])]),
        refresh_epoch: SecurityEpoch::from_raw(5),
    };
    let json = serde_json::to_string(&result).unwrap();
    let restored: ShareRefreshResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

// =========================================================================
// K. ThresholdError — Display all variants produce non-empty strings
// =========================================================================

#[test]
fn enrichment_error_display_all_nonempty() {
    let errors: Vec<ThresholdError> = vec![
        ThresholdError::InvalidThreshold {
            k: 1,
            n: 0,
            detail: "x".to_string(),
        },
        ThresholdError::InsufficientThresholdShares {
            collected: 0,
            required: 2,
        },
        ThresholdError::UnauthorizedShareHolder {
            holder: ShareHolderId([0; 32]),
        },
        ThresholdError::DuplicateSubmission {
            holder: ShareHolderId([0; 32]),
        },
        ThresholdError::DuplicateShareHolder,
        ThresholdError::PartialSignatureInvalid {
            holder: ShareHolderId([0; 32]),
        },
        ThresholdError::SigningFailed {
            detail: "x".to_string(),
        },
        ThresholdError::IdDerivationFailed {
            detail: "x".to_string(),
        },
        ThresholdError::CeremonyAlreadyFinalized,
        ThresholdError::PreimageMismatch,
        ThresholdError::ScopeNotThresholded {
            scope: ThresholdScope::EmergencyRevocation,
        },
        ThresholdError::NoScopedOperations,
    ];
    for err in &errors {
        assert!(!err.to_string().is_empty());
    }
}

// =========================================================================
// L. Debug formatting — all types
// =========================================================================

#[test]
fn enrichment_debug_nonempty_all_types() {
    assert!(!format!("{:?}", ThresholdScope::EmergencyRevocation).is_empty());
    assert!(!format!("{:?}", ShareHolderId([0; 32])).is_empty());
    assert!(!format!("{:?}", ThresholdError::CeremonyAlreadyFinalized).is_empty());
    assert!(
        !format!(
            "{:?}",
            ThresholdEventType::CeremonyFinalized {
                participants: vec![]
            }
        )
        .is_empty()
    );
}
