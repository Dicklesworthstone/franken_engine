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
use frankenengine_engine::signature_preimage::VerificationKey;
use frankenengine_engine::threshold_signing::{
    CreateThresholdPolicyInput, ShareHolderId, ShareRefreshResult, ThresholdCeremony,
    ThresholdError, ThresholdEvent, ThresholdEventType, ThresholdResult, ThresholdScope,
    ThresholdSigningPolicy, refresh_shares, threshold_ceremony_schema_id, threshold_policy_schema,
    threshold_policy_schema_id,
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

// =========================================================================
// M. ThresholdSigningPolicy — serde roundtrip
// =========================================================================

#[test]
fn enrichment_policy_serde_roundtrip() {
    let k = keys(3);
    let policy = make_policy(2, &k);
    let json = serde_json::to_string(&policy).unwrap();
    let restored: ThresholdSigningPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy.policy_id, restored.policy_id);
    assert_eq!(policy.principal_id, restored.principal_id);
    assert_eq!(policy.threshold_k, restored.threshold_k);
    assert_eq!(policy.total_n, restored.total_n);
    assert_eq!(policy.authorized_shares, restored.authorized_shares);
    assert_eq!(policy.scoped_operations, restored.scoped_operations);
    assert_eq!(policy.epoch, restored.epoch);
    assert_eq!(policy.zone, restored.zone);
}

// =========================================================================
// N. ThresholdSigningPolicy — clone independence
// =========================================================================

#[test]
fn enrichment_policy_clone_independence() {
    let k = keys(3);
    let policy = make_policy(2, &k);
    let cloned = policy.clone();
    // Mutating the clone's public fields should not affect the original.
    // We verify deep equality first, then confirm they are independent objects.
    assert_eq!(policy.policy_id, cloned.policy_id);
    assert_eq!(policy.zone, cloned.zone);
    // Drop clone; original still accessible.
    drop(cloned);
    assert_eq!(policy.threshold_k, 2);
}

// =========================================================================
// O. ThresholdCeremony — serde roundtrip (before any submissions)
// =========================================================================

#[test]
fn enrichment_ceremony_serde_roundtrip_empty() {
    let k = keys(3);
    let policy = make_policy(2, &k);
    let ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        b"preimage-serde",
        DeterministicTimestamp(100),
    )
    .unwrap();
    let json = serde_json::to_string(&ceremony).unwrap();
    let restored: ThresholdCeremony = serde_json::from_str(&json).unwrap();
    assert_eq!(ceremony.ceremony_id, restored.ceremony_id);
    assert_eq!(ceremony.scope, restored.scope);
    assert_eq!(ceremony.threshold_k, restored.threshold_k);
    assert_eq!(ceremony.preimage_hash, restored.preimage_hash);
    assert_eq!(
        ceremony.signatures_collected(),
        restored.signatures_collected()
    );
}

// =========================================================================
// P. ThresholdCeremony — clone independence after submissions
// =========================================================================

#[test]
fn enrichment_ceremony_clone_independence_after_submit() {
    let k = keys(3);
    let policy = make_policy(2, &k);
    let mut ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        b"clone-test",
        DeterministicTimestamp(200),
    )
    .unwrap();
    ceremony
        .submit_partial(&k[0], b"clone-test", DeterministicTimestamp(201))
        .unwrap();

    let cloned = ceremony.clone();
    assert_eq!(cloned.signatures_collected(), 1);
    assert_eq!(ceremony.ceremony_id, cloned.ceremony_id);

    // Mutate original further; clone is unaffected.
    ceremony
        .submit_partial(&k[1], b"clone-test", DeterministicTimestamp(202))
        .unwrap();
    assert_eq!(ceremony.signatures_collected(), 2);
    assert_eq!(cloned.signatures_collected(), 1);
}

// =========================================================================
// Q. Schema idempotency — same call twice yields identical results
// =========================================================================

#[test]
fn enrichment_schema_idempotent_across_calls() {
    let s1 = threshold_policy_schema();
    let s2 = threshold_policy_schema();
    assert_eq!(s1, s2);

    let sid1 = threshold_policy_schema_id();
    let sid2 = threshold_policy_schema_id();
    assert_eq!(sid1, sid2);

    let csid1 = threshold_ceremony_schema_id();
    let csid2 = threshold_ceremony_schema_id();
    assert_eq!(csid1, csid2);
}

// =========================================================================
// R. ThresholdScope — serde roundtrip all variants
// =========================================================================

#[test]
fn enrichment_threshold_scope_serde_all_variants() {
    for scope in ThresholdScope::ALL {
        let json = serde_json::to_string(scope).unwrap();
        let restored: ThresholdScope = serde_json::from_str(&json).unwrap();
        assert_eq!(*scope, restored);
    }
}

// =========================================================================
// S. ThresholdScope — Display produces expected strings
// =========================================================================

#[test]
fn enrichment_threshold_scope_display_strings() {
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

// =========================================================================
// T. Policy — is_authorized for all holders and a rogue
// =========================================================================

#[test]
fn enrichment_policy_is_authorized_checks() {
    let k = keys(4);
    let policy = make_policy(2, &k);
    // All four holders should be authorized.
    for key in &k {
        let holder = ShareHolderId::from_verification_key(&key.verification_key());
        assert!(policy.is_authorized(&holder));
    }
    // A rogue holder should not be authorized.
    let rogue = ShareHolderId([0xFF; 32]);
    assert!(!policy.is_authorized(&rogue));
}

// =========================================================================
// U. Policy — field validation after construction
// =========================================================================

#[test]
fn enrichment_policy_fields_after_creation() {
    let k = keys(5);
    let policy = make_policy(3, &k);
    assert_eq!(policy.threshold_k, 3);
    assert_eq!(policy.total_n, 5);
    assert_eq!(policy.authorized_shares.len(), 5);
    assert_eq!(policy.scoped_operations.len(), 4);
    assert_eq!(policy.epoch, SecurityEpoch::from_raw(1));
    assert_eq!(policy.zone, "test-zone");
    assert_eq!(policy.principal_id, principal());
    // policy_id should be non-zero
    assert!(!policy.policy_id.as_bytes().iter().all(|b| *b == 0));
}

// =========================================================================
// V. Ceremony — over-threshold (all n submit, more than k)
// =========================================================================

#[test]
fn enrichment_ceremony_over_threshold_all_submit() {
    let k = keys(4);
    let policy = make_policy(2, &k);
    let mut ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        b"over-threshold",
        DeterministicTimestamp(0),
    )
    .unwrap();

    // Submit all 4 of 4 (threshold is 2).
    for (i, key) in k.iter().enumerate() {
        ceremony
            .submit_partial(key, b"over-threshold", DeterministicTimestamp(i as u64 + 1))
            .unwrap();
    }
    assert!(ceremony.is_threshold_met());
    assert_eq!(ceremony.signatures_collected(), 4);

    let result = ceremony.finalize(b"over-threshold").unwrap();
    assert_eq!(result.signatures.len(), 4);
    result.verify(b"over-threshold").unwrap();
}

// =========================================================================
// W. Ceremony — drain_events captures ceremony lifecycle
// =========================================================================

#[test]
fn enrichment_ceremony_drain_events_lifecycle() {
    let k = keys(3);
    let policy = make_policy(2, &k);
    let mut ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        b"events-data",
        DeterministicTimestamp(0),
    )
    .unwrap();

    // After creation, there should be exactly one CeremonyInitiated event.
    let events = ceremony.drain_events();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        &events[0].event_type,
        ThresholdEventType::CeremonyInitiated { .. }
    ));

    // After drain, events should be empty.
    let empty = ceremony.drain_events();
    assert!(empty.is_empty());

    // Submit a partial and drain again.
    ceremony
        .submit_partial(&k[0], b"events-data", DeterministicTimestamp(1))
        .unwrap();
    let events2 = ceremony.drain_events();
    assert_eq!(events2.len(), 1);
    assert!(matches!(
        &events2[0].event_type,
        ThresholdEventType::PartialSignatureSubmitted { .. }
    ));

    // Submit second partial and finalize — both generate events.
    ceremony
        .submit_partial(&k[1], b"events-data", DeterministicTimestamp(2))
        .unwrap();
    ceremony.finalize(b"events-data").unwrap();
    let events3 = ceremony.drain_events();
    assert_eq!(events3.len(), 2); // PartialSignatureSubmitted + CeremonyFinalized
    assert!(matches!(
        &events3[1].event_type,
        ThresholdEventType::CeremonyFinalized { .. }
    ));
}

// =========================================================================
// X. ThresholdEvent — serde roundtrip
// =========================================================================

#[test]
fn enrichment_threshold_event_serde_roundtrip() {
    let event = ThresholdEvent {
        event_type: ThresholdEventType::CeremonyInitiated {
            scope: ThresholdScope::PolicyCheckpoint,
            threshold_k: 3,
            total_authorized: 5,
        },
        ceremony_id: frankenengine_engine::engine_object_id::EngineObjectId([0xCC; 32]),
        zone: "serde-zone".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: ThresholdEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

// =========================================================================
// Y. ThresholdResult — serde roundtrip and verify
// =========================================================================

#[test]
fn enrichment_threshold_result_serde_roundtrip() {
    let k = keys(3);
    let policy = make_policy(2, &k);
    let mut ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        b"result-serde",
        DeterministicTimestamp(0),
    )
    .unwrap();
    ceremony
        .submit_partial(&k[0], b"result-serde", DeterministicTimestamp(1))
        .unwrap();
    ceremony
        .submit_partial(&k[1], b"result-serde", DeterministicTimestamp(2))
        .unwrap();
    let result = ceremony.finalize(b"result-serde").unwrap();

    let json = serde_json::to_string(&result).unwrap();
    let restored: ThresholdResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
    // Restored result should also verify correctly.
    restored.verify(b"result-serde").unwrap();
}

// =========================================================================
// Z. refresh_shares — integration roundtrip
// =========================================================================

#[test]
fn enrichment_refresh_shares_integration() {
    let k = keys(3);
    let policy = make_policy(2, &k);
    let new_keys = (0..3)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[0] = (i + 100) as u8;
            SigningKey::from_bytes(bytes)
        })
        .collect::<Vec<_>>();
    let new_vks: Vec<VerificationKey> = new_keys.iter().map(|sk| sk.verification_key()).collect();

    let (new_policy, refresh_result) =
        refresh_shares(&policy, &new_vks, SecurityEpoch::from_raw(10)).unwrap();
    assert_eq!(new_policy.threshold_k, 2);
    assert_eq!(new_policy.total_n, 3);
    assert_ne!(new_policy.policy_id, policy.policy_id);
    assert_eq!(new_policy.epoch, SecurityEpoch::from_raw(10));
    assert_eq!(refresh_result.old_shares.len(), 3);
    assert_eq!(refresh_result.new_shares.len(), 3);

    // Old holders should not be in new policy.
    for key in &k {
        let holder = ShareHolderId::from_verification_key(&key.verification_key());
        assert!(!new_policy.is_authorized(&holder));
    }
    // New holders should be authorized.
    for key in &new_keys {
        let holder = ShareHolderId::from_verification_key(&key.verification_key());
        assert!(new_policy.is_authorized(&holder));
    }
}

// =========================================================================
// AA. Policy determinism — same inputs yield same policy_id
// =========================================================================

#[test]
fn enrichment_policy_deterministic_id() {
    let k = keys(4);
    let p1 = make_policy(3, &k);
    let p2 = make_policy(3, &k);
    assert_eq!(p1.policy_id, p2.policy_id);
    assert_eq!(p1.authorized_shares, p2.authorized_shares);
}

// =========================================================================
// AB. Ceremony — unauthorized submission emits event
// =========================================================================

#[test]
fn enrichment_ceremony_unauthorized_emits_event() {
    let k = keys(3);
    let policy = make_policy(2, &k);
    let mut ceremony = ThresholdCeremony::new(
        &policy,
        ThresholdScope::EmergencyRevocation,
        b"unauthorized-test",
        DeterministicTimestamp(0),
    )
    .unwrap();

    // Drain init event.
    let _ = ceremony.drain_events();

    let rogue_key = SigningKey::from_bytes([0xFF; 32]);
    let result =
        ceremony.submit_partial(&rogue_key, b"unauthorized-test", DeterministicTimestamp(1));
    assert!(result.is_err());

    let events = ceremony.drain_events();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        &events[0].event_type,
        ThresholdEventType::UnauthorizedSubmission { .. }
    ));
}
