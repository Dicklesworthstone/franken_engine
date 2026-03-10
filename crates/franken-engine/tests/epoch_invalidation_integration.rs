//! Integration tests for `epoch_invalidation` — epoch-bound specialization
//! invalidation, deterministic fallback, churn dampening, and audit trail.

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

use frankenengine_engine::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use frankenengine_engine::epoch_invalidation::{
    ChurnConfig, EpochBoundSpecialization, EpochInvalidationEngine, FallbackState,
    InvalidationConfig, InvalidationError, InvalidationEvent, InvalidationEventType,
    InvalidationReason, InvalidationReceipt, SpecializationInput, create_specialization,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::proof_schema::OptimizationClass;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// Helpers
// ===========================================================================

fn test_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(11).wrapping_add(5);
    }
    key
}

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn default_config() -> InvalidationConfig {
    InvalidationConfig {
        signing_key: test_key(),
        churn: ChurnConfig::default(),
    }
}

fn churn_config(threshold: u64, window_ns: u64) -> InvalidationConfig {
    InvalidationConfig {
        signing_key: test_key(),
        churn: ChurnConfig {
            threshold,
            window_ns,
            ..ChurnConfig::default()
        },
    }
}

fn new_engine() -> EpochInvalidationEngine {
    EpochInvalidationEngine::new(epoch(100), default_config())
}

fn proof_id(suffix: &str) -> EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::PolicyObject,
        "test",
        &SchemaId::from_definition(b"test-proof"),
        suffix.as_bytes(),
    )
    .unwrap()
}

fn make_spec(
    class: OptimizationClass,
    from: u64,
    until: u64,
    policy: &str,
    suffix: &str,
) -> EpochBoundSpecialization {
    let mut proofs = BTreeSet::new();
    proofs.insert(proof_id(suffix));
    create_specialization(SpecializationInput {
        optimization_class: class,
        valid_from_epoch: epoch(from),
        valid_until_epoch: epoch(until),
        source_proof_ids: proofs,
        linked_policy_id: policy.to_string(),
        rollback_token_hash: ContentHash::compute(format!("rollback-{suffix}").as_bytes()),
        baseline_ir_hash: ContentHash::compute(format!("baseline-{suffix}").as_bytes()),
        activated_epoch: epoch(from),
        activated_at_ns: 1000,
    })
    .expect("create_specialization should succeed")
}

fn default_spec() -> EpochBoundSpecialization {
    make_spec(
        OptimizationClass::TraceSpecialization,
        90,
        110,
        "policy-001",
        "default",
    )
}

/// Build a spec with explicit proof IDs.
fn spec_with_proofs(
    class: OptimizationClass,
    from: u64,
    until: u64,
    policy: &str,
    proof_ids: BTreeSet<EngineObjectId>,
    suffix: &str,
) -> EpochBoundSpecialization {
    create_specialization(SpecializationInput {
        optimization_class: class,
        valid_from_epoch: epoch(from),
        valid_until_epoch: epoch(until),
        source_proof_ids: proof_ids,
        linked_policy_id: policy.to_string(),
        rollback_token_hash: ContentHash::compute(format!("rollback-{suffix}").as_bytes()),
        baseline_ir_hash: ContentHash::compute(format!("baseline-{suffix}").as_bytes()),
        activated_epoch: epoch(from),
        activated_at_ns: 1000,
    })
    .unwrap()
}

fn event_tags(engine: &EpochInvalidationEngine) -> Vec<&'static str> {
    engine
        .events()
        .iter()
        .map(|e| match &e.event_type {
            InvalidationEventType::SpecializationRegistered { .. } => "registered",
            InvalidationEventType::EpochTransitionTriggered { .. } => "epoch-transition",
            InvalidationEventType::SpecializationInvalidated { .. } => "invalidated",
            InvalidationEventType::BaselineFallbackCompleted { .. } => "fallback",
            InvalidationEventType::BulkInvalidationCompleted { .. } => "bulk-complete",
            InvalidationEventType::InvalidationReceiptEmitted { .. } => "receipt",
            InvalidationEventType::ReSpecializationStarted { .. } => "respec-start",
            InvalidationEventType::ChurnDampeningActivated { .. } => "churn-on",
            InvalidationEventType::ChurnDampeningDeactivated => "churn-off",
        })
        .collect()
}

// ===========================================================================
// 1. Construction and basic accessors
// ===========================================================================

#[test]
fn new_engine_starts_empty() {
    let engine = new_engine();
    assert_eq!(engine.current_epoch(), epoch(100));
    assert!(engine.specializations().is_empty());
    assert!(engine.receipts().is_empty());
    assert!(engine.events().is_empty());
    assert_eq!(engine.active_count(), 0);
    assert_eq!(engine.fallback_count(), 0);
    assert_eq!(engine.total_invalidations(), 0);
    assert!(!engine.is_conservative_mode());
    assert!(!engine.requires_extended_canary());
    assert_eq!(engine.canary_multiplier(), 1_000_000);
}

#[test]
fn engine_with_custom_config() {
    let cfg = churn_config(5, 500_000);
    let engine = EpochInvalidationEngine::new(epoch(42), cfg);
    assert_eq!(engine.current_epoch(), epoch(42));
    assert_eq!(engine.canary_multiplier(), 1_000_000);
}

// ===========================================================================
// 2. Specialization registration
// ===========================================================================

#[test]
fn register_single_specialization() {
    let mut engine = new_engine();
    let spec = default_spec();
    let id = spec.specialization_id.clone();
    engine.register_specialization(spec, 1000).unwrap();

    assert_eq!(engine.specializations().len(), 1);
    assert_eq!(engine.active_count(), 1);
    assert!(engine.get_specialization(&id).is_some());
}

#[test]
fn register_multiple_specializations() {
    let mut engine = new_engine();
    for i in 0..10 {
        let spec = make_spec(
            OptimizationClass::TraceSpecialization,
            90,
            110,
            "policy-001",
            &format!("multi-{i}"),
        );
        engine.register_specialization(spec, 1000 + i).unwrap();
    }
    assert_eq!(engine.specializations().len(), 10);
    assert_eq!(engine.active_count(), 10);
}

#[test]
fn register_duplicate_fails() {
    let mut engine = new_engine();
    let spec = default_spec();
    engine.register_specialization(spec.clone(), 1000).unwrap();
    let err = engine.register_specialization(spec, 2000).unwrap_err();
    assert!(matches!(
        err,
        InvalidationError::DuplicateSpecialization { .. }
    ));
}

#[test]
fn register_inverted_epoch_range_fails() {
    let mut engine = new_engine();
    let spec = make_spec(
        OptimizationClass::Superinstruction,
        110,
        90, // inverted
        "policy-001",
        "inverted",
    );
    let err = engine.register_specialization(spec, 1000).unwrap_err();
    assert!(matches!(err, InvalidationError::InvalidEpochRange { .. }));
}

#[test]
fn register_emits_event() {
    let mut engine = new_engine();
    let spec = default_spec();
    engine.register_specialization(spec, 1000).unwrap();
    assert_eq!(engine.events().len(), 1);
    assert!(matches!(
        engine.events()[0].event_type,
        InvalidationEventType::SpecializationRegistered { .. }
    ));
}

// ===========================================================================
// 3. EpochBoundSpecialization — validity and canonical bytes
// ===========================================================================

#[test]
fn is_valid_at_boundary_epochs() {
    let spec = make_spec(
        OptimizationClass::TraceSpecialization,
        50,
        60,
        "p",
        "bounds",
    );
    assert!(!spec.is_valid_at(epoch(49)));
    assert!(spec.is_valid_at(epoch(50)));
    assert!(spec.is_valid_at(epoch(55)));
    assert!(spec.is_valid_at(epoch(60)));
    assert!(!spec.is_valid_at(epoch(61)));
}

#[test]
fn is_valid_at_single_epoch_range() {
    let spec = make_spec(OptimizationClass::Superinstruction, 42, 42, "p", "single");
    assert!(spec.is_valid_at(epoch(42)));
    assert!(!spec.is_valid_at(epoch(41)));
    assert!(!spec.is_valid_at(epoch(43)));
}

#[test]
fn canonical_bytes_deterministic() {
    let s1 = default_spec();
    let s2 = default_spec();
    assert_eq!(s1.canonical_bytes(), s2.canonical_bytes());
}

#[test]
fn canonical_bytes_differ_for_different_specs() {
    let s1 = make_spec(OptimizationClass::TraceSpecialization, 90, 110, "p", "a");
    let s2 = make_spec(OptimizationClass::TraceSpecialization, 90, 111, "p", "b");
    assert_ne!(s1.canonical_bytes(), s2.canonical_bytes());
}

// ===========================================================================
// 4. Epoch advance and bulk invalidation
// ===========================================================================

#[test]
fn advance_epoch_preserves_valid_specs() {
    let mut engine = new_engine();
    engine
        .register_specialization(default_spec(), 1000)
        .unwrap(); // valid 90..=110
    let count = engine.advance_epoch(epoch(105), 2000);
    assert_eq!(count, 0);
    assert_eq!(engine.active_count(), 1);
    assert_eq!(engine.fallback_count(), 0);
}

#[test]
fn advance_epoch_invalidates_expired_specs() {
    let mut engine = new_engine();
    engine
        .register_specialization(default_spec(), 1000)
        .unwrap();
    let count = engine.advance_epoch(epoch(111), 2000);
    assert_eq!(count, 1);
    assert_eq!(engine.active_count(), 0);
    assert_eq!(engine.fallback_count(), 1);
    assert_eq!(engine.current_epoch(), epoch(111));
}

#[test]
fn advance_epoch_updates_current_epoch() {
    let mut engine = new_engine();
    engine.advance_epoch(epoch(200), 1000);
    assert_eq!(engine.current_epoch(), epoch(200));
}

#[test]
fn advance_epoch_mixed_validity() {
    let mut engine = new_engine();
    let short = make_spec(
        OptimizationClass::TraceSpecialization,
        90,
        105,
        "p",
        "short",
    );
    let long = make_spec(OptimizationClass::Superinstruction, 90, 120, "p", "long");
    engine.register_specialization(short, 1000).unwrap();
    engine.register_specialization(long, 1000).unwrap();

    let count = engine.advance_epoch(epoch(110), 2000);
    assert_eq!(count, 1);
    assert_eq!(engine.active_count(), 1);
    assert_eq!(engine.fallback_count(), 1);
}

#[test]
fn advance_epoch_all_expire() {
    let mut engine = new_engine();
    for i in 0..5 {
        let spec = make_spec(
            OptimizationClass::TraceSpecialization,
            90,
            100,
            "p",
            &format!("all-{i}"),
        );
        engine.register_specialization(spec, 1000).unwrap();
    }
    let count = engine.advance_epoch(epoch(101), 2000);
    assert_eq!(count, 5);
    assert_eq!(engine.active_count(), 0);
    assert_eq!(engine.fallback_count(), 5);
}

#[test]
fn advance_epoch_none_expire() {
    let mut engine = new_engine();
    for i in 0..3 {
        let spec = make_spec(
            OptimizationClass::TraceSpecialization,
            90,
            200,
            "p",
            &format!("none-{i}"),
        );
        engine.register_specialization(spec, 1000).unwrap();
    }
    let count = engine.advance_epoch(epoch(150), 2000);
    assert_eq!(count, 0);
    assert_eq!(engine.active_count(), 3);
}

#[test]
fn advance_epoch_deterministic_invalidation_order() {
    let mut engine = new_engine();
    for i in 0..5 {
        let spec = make_spec(
            OptimizationClass::TraceSpecialization,
            90,
            100,
            "p",
            &format!("order-{i}"),
        );
        engine.register_specialization(spec, 1000).unwrap();
    }
    engine.advance_epoch(epoch(101), 2000);

    let receipt_spec_ids: Vec<_> = engine
        .receipts()
        .iter()
        .map(|r| r.specialization_id.clone())
        .collect();
    let mut sorted = receipt_spec_ids.clone();
    sorted.sort();
    assert_eq!(
        receipt_spec_ids, sorted,
        "invalidation order must be deterministic"
    );
}

#[test]
fn advance_epoch_skips_already_fallback_specs() {
    let mut engine = new_engine();
    let spec = default_spec();
    let id = spec.specialization_id.clone();
    engine.register_specialization(spec, 1000).unwrap();

    // Manually invalidate first.
    engine
        .invalidate_specialization(
            &id,
            InvalidationReason::OperatorInvalidation {
                reason: "manual".into(),
            },
            1500,
        )
        .unwrap();
    assert_eq!(engine.fallback_count(), 1);

    // Epoch advance should not re-invalidate the already-fallback spec.
    let count = engine.advance_epoch(epoch(111), 2000);
    assert_eq!(count, 0);
}

#[test]
fn advance_epoch_emits_bulk_event_only_when_invalidations_occur() {
    let mut engine = new_engine();
    engine
        .register_specialization(default_spec(), 1000)
        .unwrap();

    // No invalidation.
    engine.advance_epoch(epoch(105), 2000);
    let tags = event_tags(&engine);
    assert!(!tags.contains(&"bulk-complete"));

    // Now invalidate.
    engine.advance_epoch(epoch(111), 3000);
    let tags = event_tags(&engine);
    assert!(tags.contains(&"bulk-complete"));
}

// ===========================================================================
// 5. Individual invalidation
// ===========================================================================

#[test]
fn invalidate_specific_specialization() {
    let mut engine = new_engine();
    let spec = default_spec();
    let id = spec.specialization_id.clone();
    engine.register_specialization(spec, 1000).unwrap();

    let receipt = engine
        .invalidate_specialization(
            &id,
            InvalidationReason::OperatorInvalidation {
                reason: "manual".into(),
            },
            2000,
        )
        .unwrap();

    assert_eq!(receipt.specialization_id, id);
    assert!(!receipt.signature.is_empty());
    assert_eq!(engine.active_count(), 0);
    assert_eq!(engine.fallback_count(), 1);
    assert_eq!(engine.total_invalidations(), 1);
}

#[test]
fn invalidate_nonexistent_returns_error() {
    let mut engine = new_engine();
    let fake = proof_id("fake");
    let err = engine
        .invalidate_specialization(
            &fake,
            InvalidationReason::OperatorInvalidation {
                reason: "test".into(),
            },
            1000,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        InvalidationError::SpecializationNotFound { .. }
    ));
}

#[test]
fn double_invalidation_returns_already_in_fallback() {
    let mut engine = new_engine();
    let spec = default_spec();
    let id = spec.specialization_id.clone();
    engine.register_specialization(spec, 1000).unwrap();

    engine
        .invalidate_specialization(
            &id,
            InvalidationReason::OperatorInvalidation {
                reason: "first".into(),
            },
            2000,
        )
        .unwrap();

    let err = engine
        .invalidate_specialization(
            &id,
            InvalidationReason::OperatorInvalidation {
                reason: "second".into(),
            },
            3000,
        )
        .unwrap_err();
    assert!(matches!(err, InvalidationError::AlreadyInFallback { .. }));
}

#[test]
fn invalidate_with_key_rotation_reason() {
    let mut engine = new_engine();
    let spec = default_spec();
    let id = spec.specialization_id.clone();
    engine.register_specialization(spec, 1000).unwrap();

    let receipt = engine
        .invalidate_specialization(
            &id,
            InvalidationReason::KeyRotation {
                key_id: "key-42".into(),
            },
            2000,
        )
        .unwrap();

    assert!(matches!(
        receipt.reason,
        InvalidationReason::KeyRotation { ref key_id } if key_id == "key-42"
    ));
}

#[test]
fn invalidate_with_capability_revocation_reason() {
    let mut engine = new_engine();
    let spec = default_spec();
    let id = spec.specialization_id.clone();
    engine.register_specialization(spec, 1000).unwrap();

    let receipt = engine
        .invalidate_specialization(
            &id,
            InvalidationReason::CapabilityRevocation {
                capability_id: "cap-99".into(),
            },
            2000,
        )
        .unwrap();

    assert!(matches!(
        receipt.reason,
        InvalidationReason::CapabilityRevocation { ref capability_id } if capability_id == "cap-99"
    ));
}

// ===========================================================================
// 6. Proof-based invalidation
// ===========================================================================

#[test]
fn invalidate_by_proof_hits_linked_specs() {
    let mut engine = new_engine();
    let shared_proof = proof_id("shared-proof");
    let mut proofs = BTreeSet::new();
    proofs.insert(shared_proof.clone());

    let s1 = spec_with_proofs(
        OptimizationClass::LayoutSpecialization,
        90,
        110,
        "p",
        proofs.clone(),
        "proof-linked-1",
    );
    let s2 = spec_with_proofs(
        OptimizationClass::Superinstruction,
        90,
        110,
        "p",
        proofs.clone(),
        "proof-linked-2",
    );
    engine.register_specialization(s1, 1000).unwrap();
    engine.register_specialization(s2, 1000).unwrap();

    let count = engine.invalidate_by_proof(&shared_proof, 2000);
    assert_eq!(count, 2);
    assert_eq!(engine.fallback_count(), 2);
    assert_eq!(engine.active_count(), 0);
}

#[test]
fn invalidate_by_proof_misses_unlinked_specs() {
    let mut engine = new_engine();
    let spec = default_spec(); // has its own proof
    engine.register_specialization(spec, 1000).unwrap();

    let unrelated = proof_id("unrelated-proof");
    let count = engine.invalidate_by_proof(&unrelated, 2000);
    assert_eq!(count, 0);
    assert_eq!(engine.active_count(), 1);
}

#[test]
fn invalidate_by_proof_skips_already_fallback() {
    let mut engine = new_engine();
    let shared_proof = proof_id("shared");
    let mut proofs = BTreeSet::new();
    proofs.insert(shared_proof.clone());

    let s1 = spec_with_proofs(
        OptimizationClass::TraceSpecialization,
        90,
        110,
        "p",
        proofs.clone(),
        "proof-fb-1",
    );
    let id1 = s1.specialization_id.clone();
    engine.register_specialization(s1, 1000).unwrap();

    // Manually invalidate first.
    engine
        .invalidate_specialization(
            &id1,
            InvalidationReason::OperatorInvalidation {
                reason: "pre".into(),
            },
            1500,
        )
        .unwrap();

    // invalidate_by_proof should skip already-fallback.
    let count = engine.invalidate_by_proof(&shared_proof, 2000);
    assert_eq!(count, 0);
}

// ===========================================================================
// 7. Policy-based invalidation
// ===========================================================================

#[test]
fn invalidate_by_policy_hits_matching_specs() {
    let mut engine = new_engine();
    let s1 = make_spec(
        OptimizationClass::TraceSpecialization,
        90,
        110,
        "policy-A",
        "pa1",
    );
    let s2 = make_spec(
        OptimizationClass::Superinstruction,
        90,
        110,
        "policy-A",
        "pa2",
    );
    let s3 = make_spec(
        OptimizationClass::LayoutSpecialization,
        90,
        110,
        "policy-B",
        "pb1",
    );
    engine.register_specialization(s1, 1000).unwrap();
    engine.register_specialization(s2, 1000).unwrap();
    engine.register_specialization(s3, 1000).unwrap();

    let count = engine.invalidate_by_policy("policy-A", 2000);
    assert_eq!(count, 2);
    assert_eq!(engine.active_count(), 1); // policy-B survives
}

#[test]
fn invalidate_by_policy_no_match() {
    let mut engine = new_engine();
    engine
        .register_specialization(default_spec(), 1000)
        .unwrap();
    let count = engine.invalidate_by_policy("nonexistent-policy", 2000);
    assert_eq!(count, 0);
    assert_eq!(engine.active_count(), 1);
}

// ===========================================================================
// 8. Re-specialization lifecycle
// ===========================================================================

#[test]
fn respecialization_full_cycle() {
    let mut engine = new_engine();
    let spec = default_spec();
    let id = spec.specialization_id.clone();
    engine.register_specialization(spec, 1000).unwrap();

    // Invalidate via epoch advance.
    engine.advance_epoch(epoch(111), 2000);
    assert_eq!(engine.fallback_count(), 1);

    // Begin re-specialization.
    engine.begin_respecialization(&id, 3000).unwrap();
    let s = engine.get_specialization(&id).unwrap();
    assert_eq!(s.state, FallbackState::ReSpecializing);

    // Complete re-specialization with new bounds.
    let new_proofs = {
        let mut s = BTreeSet::new();
        s.insert(proof_id("new-proof"));
        s
    };
    engine
        .complete_respecialization(&id, epoch(111), epoch(130), new_proofs, 4000)
        .unwrap();

    let s = engine.get_specialization(&id).unwrap();
    assert_eq!(s.state, FallbackState::Active);
    assert_eq!(s.valid_from_epoch, epoch(111));
    assert_eq!(s.valid_until_epoch, epoch(130));
    assert_eq!(s.activated_epoch, engine.current_epoch());
    assert_eq!(s.activated_at_ns, 4000);
}

#[test]
fn begin_respecialization_requires_baseline_fallback_state() {
    let mut engine = new_engine();
    let spec = default_spec();
    let id = spec.specialization_id.clone();
    engine.register_specialization(spec, 1000).unwrap();

    // Active state — should fail.
    let err = engine.begin_respecialization(&id, 2000).unwrap_err();
    assert!(matches!(err, InvalidationError::InvalidState { .. }));
}

#[test]
fn complete_respecialization_requires_respecializing_state() {
    let mut engine = new_engine();
    let spec = default_spec();
    let id = spec.specialization_id.clone();
    engine.register_specialization(spec, 1000).unwrap();

    // Invalidate but don't begin re-specialization.
    engine.advance_epoch(epoch(111), 2000);

    let err = engine
        .complete_respecialization(&id, epoch(111), epoch(130), BTreeSet::new(), 3000)
        .unwrap_err();
    assert!(matches!(err, InvalidationError::InvalidState { .. }));
}

#[test]
fn complete_respecialization_rejects_inverted_epoch_range() {
    let mut engine = new_engine();
    let spec = default_spec();
    let id = spec.specialization_id.clone();
    engine.register_specialization(spec, 1000).unwrap();

    engine.advance_epoch(epoch(111), 2000);
    engine.begin_respecialization(&id, 3000).unwrap();

    let err = engine
        .complete_respecialization(&id, epoch(130), epoch(111), BTreeSet::new(), 4000)
        .unwrap_err();
    assert!(matches!(err, InvalidationError::InvalidEpochRange { .. }));
}

#[test]
fn begin_respecialization_nonexistent_fails() {
    let mut engine = new_engine();
    let fake = proof_id("nonexistent");
    let err = engine.begin_respecialization(&fake, 1000).unwrap_err();
    assert!(matches!(
        err,
        InvalidationError::SpecializationNotFound { .. }
    ));
}

#[test]
fn complete_respecialization_nonexistent_fails() {
    let mut engine = new_engine();
    let fake = proof_id("nonexistent");
    let err = engine
        .complete_respecialization(&fake, epoch(100), epoch(200), BTreeSet::new(), 1000)
        .unwrap_err();
    assert!(matches!(
        err,
        InvalidationError::SpecializationNotFound { .. }
    ));
}

#[test]
fn respecialized_spec_survives_new_epoch_within_range() {
    let mut engine = new_engine();
    let spec = default_spec();
    let id = spec.specialization_id.clone();
    engine.register_specialization(spec, 1000).unwrap();

    // Invalidate, re-specialize.
    engine.advance_epoch(epoch(111), 2000);
    engine.begin_respecialization(&id, 3000).unwrap();
    engine
        .complete_respecialization(
            &id,
            epoch(111),
            epoch(200),
            {
                let mut s = BTreeSet::new();
                s.insert(proof_id("new"));
                s
            },
            4000,
        )
        .unwrap();

    // Advance within new range.
    let count = engine.advance_epoch(epoch(150), 5000);
    assert_eq!(count, 0);
    assert_eq!(engine.active_count(), 1);
}

#[test]
fn respecialized_spec_invalidated_on_expire() {
    let mut engine = new_engine();
    let spec = default_spec();
    let id = spec.specialization_id.clone();
    engine.register_specialization(spec, 1000).unwrap();

    engine.advance_epoch(epoch(111), 2000);
    engine.begin_respecialization(&id, 3000).unwrap();
    engine
        .complete_respecialization(
            &id,
            epoch(111),
            epoch(120),
            {
                let mut s = BTreeSet::new();
                s.insert(proof_id("new"));
                s
            },
            4000,
        )
        .unwrap();

    // Advance past new valid_until.
    let count = engine.advance_epoch(epoch(121), 5000);
    assert_eq!(count, 1);
    assert_eq!(engine.fallback_count(), 1);
}

#[test]
fn begin_respecialization_emits_event() {
    let mut engine = new_engine();
    let spec = default_spec();
    let id = spec.specialization_id.clone();
    engine.register_specialization(spec, 1000).unwrap();
    engine.advance_epoch(epoch(111), 2000);

    engine.begin_respecialization(&id, 3000).unwrap();
    let tags = event_tags(&engine);
    assert!(tags.contains(&"respec-start"));
}

// ===========================================================================
// 9. Churn dampening
// ===========================================================================

#[test]
fn churn_activates_on_rapid_invalidations() {
    let cfg = churn_config(3, 10_000);
    let mut engine = EpochInvalidationEngine::new(epoch(100), cfg);

    for i in 0..3 {
        let spec = make_spec(
            OptimizationClass::TraceSpecialization,
            90,
            110,
            "p",
            &format!("churn-{i}"),
        );
        let id = spec.specialization_id.clone();
        engine
            .register_specialization(spec, 1000 + i * 100)
            .unwrap();
        engine
            .invalidate_specialization(
                &id,
                InvalidationReason::OperatorInvalidation {
                    reason: "churn".into(),
                },
                1050 + i * 100,
            )
            .unwrap();
    }

    assert!(engine.is_conservative_mode());
    assert!(engine.requires_extended_canary());
    assert_eq!(engine.canary_multiplier(), 2_000_000);
}

#[test]
fn churn_deactivates_after_window_expires() {
    let cfg = churn_config(2, 1000);
    let mut engine = EpochInvalidationEngine::new(epoch(100), cfg);

    // Two rapid invalidations.
    for i in 0..2 {
        let spec = make_spec(
            OptimizationClass::TraceSpecialization,
            90,
            110,
            "p",
            &format!("churn-deact-{i}"),
        );
        let id = spec.specialization_id.clone();
        engine.register_specialization(spec, 100 + i * 100).unwrap();
        engine
            .invalidate_specialization(
                &id,
                InvalidationReason::OperatorInvalidation { reason: "t".into() },
                200 + i * 100,
            )
            .unwrap();
    }
    assert!(engine.is_conservative_mode());

    // Invalidation outside the window.
    let spec = make_spec(
        OptimizationClass::LayoutSpecialization,
        90,
        110,
        "p",
        "churn-deact-late",
    );
    let id = spec.specialization_id.clone();
    engine.register_specialization(spec, 5000).unwrap();
    engine
        .invalidate_specialization(
            &id,
            InvalidationReason::OperatorInvalidation { reason: "t".into() },
            5100,
        )
        .unwrap();

    assert!(!engine.is_conservative_mode());
    assert_eq!(engine.canary_multiplier(), 1_000_000);
}

#[test]
fn churn_events_emitted() {
    let cfg = churn_config(2, 10_000);
    let mut engine = EpochInvalidationEngine::new(epoch(100), cfg);

    for i in 0..2 {
        let spec = make_spec(
            OptimizationClass::TraceSpecialization,
            90,
            110,
            "p",
            &format!("churn-evt-{i}"),
        );
        let id = spec.specialization_id.clone();
        engine.register_specialization(spec, 100 + i * 100).unwrap();
        engine
            .invalidate_specialization(
                &id,
                InvalidationReason::OperatorInvalidation { reason: "t".into() },
                200 + i * 100,
            )
            .unwrap();
    }

    let tags = event_tags(&engine);
    assert!(tags.contains(&"churn-on"));
}

#[test]
fn churn_deactivation_emits_event() {
    let cfg = churn_config(2, 1000);
    let mut engine = EpochInvalidationEngine::new(epoch(100), cfg);

    // Two rapid invalidations to activate churn (threshold=2).
    for i in 0..2 {
        let s = make_spec(
            OptimizationClass::TraceSpecialization,
            90,
            110,
            "p",
            &format!("cd-{i}"),
        );
        let id = s.specialization_id.clone();
        engine.register_specialization(s, 100 + i * 100).unwrap();
        engine
            .invalidate_specialization(
                &id,
                InvalidationReason::OperatorInvalidation { reason: "t".into() },
                200 + i * 100,
            )
            .unwrap();
    }
    assert!(engine.is_conservative_mode());

    // Invalidation well outside window (1000ns). Old timestamps at 200/300 are pruned.
    // Only the new timestamp at 10_100 remains — below threshold of 2.
    let s3 = make_spec(OptimizationClass::Superinstruction, 90, 110, "p", "cd-late");
    let id3 = s3.specialization_id.clone();
    engine.register_specialization(s3, 10_000).unwrap();
    engine
        .invalidate_specialization(
            &id3,
            InvalidationReason::OperatorInvalidation { reason: "t".into() },
            10_100,
        )
        .unwrap();

    assert!(!engine.is_conservative_mode());
    let tags = event_tags(&engine);
    assert!(tags.contains(&"churn-off"));
}

#[test]
fn canary_multiplier_returns_base_when_not_conservative() {
    let engine = new_engine();
    assert_eq!(engine.canary_multiplier(), 1_000_000);
}

#[test]
fn canary_multiplier_returns_extended_when_conservative() {
    let mut cfg = default_config();
    cfg.churn.threshold = 1;
    cfg.churn.window_ns = 1_000_000;
    cfg.churn.extended_canary_multiplier = 3_000_000;
    let mut engine = EpochInvalidationEngine::new(epoch(100), cfg);

    let spec = make_spec(OptimizationClass::TraceSpecialization, 90, 110, "p", "cm");
    let id = spec.specialization_id.clone();
    engine.register_specialization(spec, 100).unwrap();
    engine
        .invalidate_specialization(
            &id,
            InvalidationReason::OperatorInvalidation { reason: "t".into() },
            200,
        )
        .unwrap();

    assert!(engine.is_conservative_mode());
    assert_eq!(engine.canary_multiplier(), 3_000_000);
}

#[test]
fn bulk_policy_invalidation_triggers_churn() {
    let cfg = churn_config(2, 10_000);
    let mut engine = EpochInvalidationEngine::new(epoch(100), cfg);

    for i in 0..3 {
        let spec = make_spec(
            OptimizationClass::TraceSpecialization,
            90,
            200,
            "hot-policy",
            &format!("bulk-churn-{i}"),
        );
        engine.register_specialization(spec, 1000).unwrap();
    }

    engine.invalidate_by_policy("hot-policy", 5000);
    assert!(engine.is_conservative_mode());
}

#[test]
fn epoch_advance_bulk_can_trigger_churn() {
    let cfg = churn_config(3, 50_000);
    let mut engine = EpochInvalidationEngine::new(epoch(100), cfg);

    for i in 0..4 {
        let spec = make_spec(
            OptimizationClass::Superinstruction,
            90,
            100,
            "p",
            &format!("epoch-churn-{i}"),
        );
        engine.register_specialization(spec, 500).unwrap();
    }

    let count = engine.advance_epoch(epoch(101), 10_000);
    assert_eq!(count, 4);
    assert!(engine.is_conservative_mode());
}

// ===========================================================================
// 10. Receipts
// ===========================================================================

#[test]
fn receipt_has_correct_fields() {
    let mut engine = new_engine();
    let spec = default_spec();
    let id = spec.specialization_id.clone();
    let expected_rollback = spec.rollback_token_hash.clone();
    let expected_baseline = spec.baseline_ir_hash.clone();
    engine.register_specialization(spec, 1000).unwrap();

    let receipt = engine
        .invalidate_specialization(
            &id,
            InvalidationReason::PolicyRotation {
                policy_id: "policy-X".into(),
            },
            2000,
        )
        .unwrap();

    assert_eq!(receipt.specialization_id, id);
    assert_eq!(receipt.rollback_token_hash, expected_rollback);
    assert_eq!(receipt.baseline_restoration_hash, expected_baseline);
    assert_eq!(receipt.invalidated_at_ns, 2000);
    assert!(!receipt.signature.is_empty());
    assert!(matches!(
        receipt.reason,
        InvalidationReason::PolicyRotation { ref policy_id } if policy_id == "policy-X"
    ));
}

#[test]
fn receipts_accumulate() {
    let mut engine = new_engine();
    for i in 0..3 {
        let spec = make_spec(
            OptimizationClass::TraceSpecialization,
            90,
            100,
            "p",
            &format!("rcpt-{i}"),
        );
        engine.register_specialization(spec, 1000).unwrap();
    }
    engine.advance_epoch(epoch(101), 2000);
    assert_eq!(engine.receipts().len(), 3);
}

#[test]
fn receipt_signature_is_deterministic() {
    let make_engine_and_receipt = || {
        let mut engine = new_engine();
        let spec = default_spec();
        let id = spec.specialization_id.clone();
        engine.register_specialization(spec, 1000).unwrap();
        engine
            .invalidate_specialization(
                &id,
                InvalidationReason::OperatorInvalidation {
                    reason: "det".into(),
                },
                2000,
            )
            .unwrap()
    };

    let r1 = make_engine_and_receipt();
    let r2 = make_engine_and_receipt();
    assert_eq!(r1.signature, r2.signature);
    assert_eq!(r1.receipt_id, r2.receipt_id);
}

#[test]
fn different_signing_keys_produce_different_signatures() {
    let make_receipt = |key_seed: u8| {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(key_seed);
        }
        let cfg = InvalidationConfig {
            signing_key: key,
            churn: ChurnConfig::default(),
        };
        let mut engine = EpochInvalidationEngine::new(epoch(100), cfg);
        let spec = default_spec();
        let id = spec.specialization_id.clone();
        engine.register_specialization(spec, 1000).unwrap();
        engine
            .invalidate_specialization(
                &id,
                InvalidationReason::OperatorInvalidation {
                    reason: "det".into(),
                },
                2000,
            )
            .unwrap()
    };

    let r1 = make_receipt(0);
    let r2 = make_receipt(1);
    assert_ne!(r1.signature, r2.signature);
}

// ===========================================================================
// 11. Audit event log
// ===========================================================================

#[test]
fn events_have_monotonic_sequence_numbers() {
    let mut engine = new_engine();
    let spec = default_spec();
    engine.register_specialization(spec, 1000).unwrap();
    engine.advance_epoch(epoch(111), 2000);

    for (i, event) in engine.events().iter().enumerate() {
        assert_eq!(event.seq, i as u64);
    }
}

#[test]
fn epoch_transition_event_sequence() {
    let mut engine = new_engine();
    engine
        .register_specialization(default_spec(), 1000)
        .unwrap();
    engine.advance_epoch(epoch(111), 2000);

    let tags = event_tags(&engine);
    assert_eq!(tags[0], "registered");
    assert_eq!(tags[1], "epoch-transition");
    assert_eq!(tags[2], "invalidated");
    assert_eq!(tags[3], "fallback");
    assert_eq!(tags[4], "receipt");
    assert_eq!(tags[5], "bulk-complete");
}

#[test]
fn events_carry_correct_epoch() {
    let mut engine = new_engine();
    engine
        .register_specialization(default_spec(), 1000)
        .unwrap();

    // Registration event at epoch 100.
    assert_eq!(engine.events()[0].epoch, epoch(100));

    // Advance to 111.
    engine.advance_epoch(epoch(111), 2000);

    // All subsequent events at epoch 111.
    for event in &engine.events()[1..] {
        assert_eq!(event.epoch, epoch(111));
    }
}

#[test]
fn events_carry_correct_timestamps() {
    let mut engine = new_engine();
    engine
        .register_specialization(default_spec(), 1000)
        .unwrap();
    assert_eq!(engine.events()[0].timestamp_ns, 1000);

    engine.advance_epoch(epoch(111), 2000);
    for event in &engine.events()[1..] {
        assert_eq!(event.timestamp_ns, 2000);
    }
}

// ===========================================================================
// 12. Query methods
// ===========================================================================

#[test]
fn specializations_by_class() {
    let mut engine = new_engine();
    engine
        .register_specialization(
            make_spec(
                OptimizationClass::TraceSpecialization,
                90,
                110,
                "p",
                "cls-ts",
            ),
            1000,
        )
        .unwrap();
    engine
        .register_specialization(
            make_spec(OptimizationClass::Superinstruction, 90, 110, "p", "cls-si"),
            1000,
        )
        .unwrap();
    engine
        .register_specialization(
            make_spec(
                OptimizationClass::LayoutSpecialization,
                90,
                110,
                "p",
                "cls-ls",
            ),
            1000,
        )
        .unwrap();

    assert_eq!(
        engine
            .specializations_by_class(&OptimizationClass::TraceSpecialization)
            .len(),
        1
    );
    assert_eq!(
        engine
            .specializations_by_class(&OptimizationClass::Superinstruction)
            .len(),
        1
    );
    assert_eq!(
        engine
            .specializations_by_class(&OptimizationClass::LayoutSpecialization)
            .len(),
        1
    );
}

#[test]
fn specializations_by_state() {
    let mut engine = new_engine();
    let short = make_spec(
        OptimizationClass::TraceSpecialization,
        90,
        100,
        "p",
        "st-short",
    );
    let long = make_spec(OptimizationClass::Superinstruction, 90, 120, "p", "st-long");
    engine.register_specialization(short, 1000).unwrap();
    engine.register_specialization(long, 1000).unwrap();

    engine.advance_epoch(epoch(105), 2000);

    assert_eq!(
        engine.specializations_by_state(FallbackState::Active).len(),
        1
    );
    assert_eq!(
        engine
            .specializations_by_state(FallbackState::BaselineFallback)
            .len(),
        1
    );
    assert_eq!(
        engine
            .specializations_by_state(FallbackState::ReSpecializing)
            .len(),
        0
    );
}

#[test]
fn get_specialization_returns_none_for_missing() {
    let engine = new_engine();
    let fake = proof_id("missing");
    assert!(engine.get_specialization(&fake).is_none());
}

// ===========================================================================
// 13. Display implementations
// ===========================================================================

#[test]
fn invalidation_reason_display_all_variants() {
    let reasons = [
        InvalidationReason::EpochTransition {
            old_epoch: epoch(1),
            new_epoch: epoch(2),
        },
        InvalidationReason::PolicyRotation {
            policy_id: "p1".into(),
        },
        InvalidationReason::KeyRotation {
            key_id: "k1".into(),
        },
        InvalidationReason::CapabilityRevocation {
            capability_id: "c1".into(),
        },
        InvalidationReason::ProofUpdate {
            proof_id: proof_id("test"),
        },
        InvalidationReason::OperatorInvalidation {
            reason: "manual".into(),
        },
    ];

    for r in &reasons {
        let s = r.to_string();
        assert!(!s.is_empty(), "display should not be empty for {r:?}");
    }
}

#[test]
fn invalidation_reason_display_contains_expected_text() {
    let r = InvalidationReason::EpochTransition {
        old_epoch: epoch(10),
        new_epoch: epoch(20),
    };
    let s = r.to_string();
    assert!(s.contains("epoch-transition"));
}

#[test]
fn fallback_state_display() {
    assert_eq!(FallbackState::Active.to_string(), "active");
    assert_eq!(FallbackState::Invalidating.to_string(), "invalidating");
    assert_eq!(
        FallbackState::BaselineFallback.to_string(),
        "baseline-fallback"
    );
    assert_eq!(FallbackState::ReSpecializing.to_string(), "re-specializing");
}

#[test]
fn invalidation_error_display_all_variants() {
    let errors = [
        InvalidationError::SpecializationNotFound {
            id: proof_id("test"),
        },
        InvalidationError::AlreadyInFallback {
            id: proof_id("test"),
        },
        InvalidationError::InvalidEpochRange {
            valid_from: epoch(10),
            valid_until: epoch(5),
        },
        InvalidationError::IdDerivation("test error".into()),
        InvalidationError::ChurnDampeningActive {
            invalidation_count: 5,
            window_ns: 1000,
        },
        InvalidationError::DuplicateSpecialization {
            id: proof_id("test"),
        },
    ];

    for e in &errors {
        let s = e.to_string();
        assert!(!s.is_empty(), "display should not be empty for {e:?}");
    }
}

#[test]
fn invalidation_error_is_std_error() {
    let e = InvalidationError::IdDerivation("test".into());
    let _: &dyn std::error::Error = &e;
}

// ===========================================================================
// 14. Serde roundtrips
// ===========================================================================

#[test]
fn specialization_serde_roundtrip() {
    let spec = default_spec();
    let json = serde_json::to_string(&spec).unwrap();
    let restored: EpochBoundSpecialization = serde_json::from_str(&json).unwrap();
    assert_eq!(spec, restored);
}

#[test]
fn invalidation_receipt_serde_roundtrip() {
    let mut engine = new_engine();
    let spec = default_spec();
    let id = spec.specialization_id.clone();
    engine.register_specialization(spec, 1000).unwrap();
    let receipt = engine
        .invalidate_specialization(
            &id,
            InvalidationReason::PolicyRotation {
                policy_id: "test".into(),
            },
            2000,
        )
        .unwrap();

    let json = serde_json::to_string(&receipt).unwrap();
    let restored: InvalidationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, restored);
}

#[test]
fn invalidation_event_serde_roundtrip() {
    let mut engine = new_engine();
    engine
        .register_specialization(default_spec(), 1000)
        .unwrap();
    let event = engine.events()[0].clone();
    let json = serde_json::to_string(&event).unwrap();
    let restored: InvalidationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn engine_serde_roundtrip() {
    let mut engine = new_engine();
    for i in 0..3 {
        let spec = make_spec(
            OptimizationClass::TraceSpecialization,
            90,
            100,
            "p",
            &format!("serde-{i}"),
        );
        engine.register_specialization(spec, 1000).unwrap();
    }
    engine.advance_epoch(epoch(101), 2000);

    let json = serde_json::to_string(&engine).unwrap();
    let restored: EpochInvalidationEngine = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.current_epoch(), engine.current_epoch());
    assert_eq!(
        restored.specializations().len(),
        engine.specializations().len()
    );
    assert_eq!(restored.events().len(), engine.events().len());
    assert_eq!(restored.receipts().len(), engine.receipts().len());
    assert_eq!(restored.total_invalidations(), engine.total_invalidations());
    assert_eq!(
        restored.is_conservative_mode(),
        engine.is_conservative_mode()
    );
}

#[test]
fn invalidation_reason_serde_all_variants() {
    let reasons = [
        InvalidationReason::EpochTransition {
            old_epoch: epoch(1),
            new_epoch: epoch(2),
        },
        InvalidationReason::PolicyRotation {
            policy_id: "p1".into(),
        },
        InvalidationReason::KeyRotation {
            key_id: "k1".into(),
        },
        InvalidationReason::CapabilityRevocation {
            capability_id: "c1".into(),
        },
        InvalidationReason::ProofUpdate {
            proof_id: proof_id("pf"),
        },
        InvalidationReason::OperatorInvalidation {
            reason: "manual".into(),
        },
    ];

    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let restored: InvalidationReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, restored);
    }
}

#[test]
fn fallback_state_serde_roundtrip() {
    let states = [
        FallbackState::Active,
        FallbackState::Invalidating,
        FallbackState::BaselineFallback,
        FallbackState::ReSpecializing,
    ];
    for s in &states {
        let json = serde_json::to_string(s).unwrap();
        let restored: FallbackState = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, restored);
    }
}

#[test]
fn invalidation_error_serde_roundtrip() {
    let errors = [
        InvalidationError::SpecializationNotFound {
            id: proof_id("test"),
        },
        InvalidationError::AlreadyInFallback {
            id: proof_id("test"),
        },
        InvalidationError::InvalidEpochRange {
            valid_from: epoch(10),
            valid_until: epoch(5),
        },
        InvalidationError::IdDerivation("test".into()),
        InvalidationError::ChurnDampeningActive {
            invalidation_count: 5,
            window_ns: 1000,
        },
        InvalidationError::DuplicateSpecialization {
            id: proof_id("test"),
        },
    ];

    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let restored: InvalidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, restored);
    }
}

// ===========================================================================
// 15. Fallback state persists across serde (simulated crash)
// ===========================================================================

#[test]
fn fallback_state_survives_serde_crash_restart() {
    let mut engine = new_engine();
    let spec = default_spec();
    let id = spec.specialization_id.clone();
    engine.register_specialization(spec, 1000).unwrap();
    engine.advance_epoch(epoch(111), 2000);

    let json = serde_json::to_string(&engine).unwrap();
    let restored: EpochInvalidationEngine = serde_json::from_str(&json).unwrap();

    let s = restored.get_specialization(&id).unwrap();
    assert_eq!(s.state, FallbackState::BaselineFallback);
    assert_eq!(restored.fallback_count(), 1);
    assert_eq!(restored.active_count(), 0);
}

#[test]
fn respecializing_state_survives_serde() {
    let mut engine = new_engine();
    let spec = default_spec();
    let id = spec.specialization_id.clone();
    engine.register_specialization(spec, 1000).unwrap();
    engine.advance_epoch(epoch(111), 2000);
    engine.begin_respecialization(&id, 3000).unwrap();

    let json = serde_json::to_string(&engine).unwrap();
    let restored: EpochInvalidationEngine = serde_json::from_str(&json).unwrap();

    let s = restored.get_specialization(&id).unwrap();
    assert_eq!(s.state, FallbackState::ReSpecializing);
}

// ===========================================================================
// 16. create_specialization helper
// ===========================================================================

#[test]
fn create_specialization_deterministic_id() {
    let s1 = default_spec();
    let s2 = default_spec();
    assert_eq!(s1.specialization_id, s2.specialization_id);
}

#[test]
fn different_inputs_yield_different_ids() {
    let s1 = make_spec(OptimizationClass::TraceSpecialization, 90, 110, "p", "a");
    let s2 = make_spec(OptimizationClass::TraceSpecialization, 90, 110, "p", "b");
    assert_ne!(s1.specialization_id, s2.specialization_id);
}

#[test]
fn create_specialization_sets_active_state() {
    let spec = default_spec();
    assert_eq!(spec.state, FallbackState::Active);
}

#[test]
fn create_specialization_preserves_all_fields() {
    let spec = create_specialization(SpecializationInput {
        optimization_class: OptimizationClass::Superinstruction,
        valid_from_epoch: epoch(10),
        valid_until_epoch: epoch(20),
        source_proof_ids: {
            let mut s = BTreeSet::new();
            s.insert(proof_id("preserve-proof"));
            s
        },
        linked_policy_id: "my-policy".into(),
        rollback_token_hash: ContentHash::compute(b"rollback-preserve"),
        baseline_ir_hash: ContentHash::compute(b"baseline-preserve"),
        activated_epoch: epoch(10),
        activated_at_ns: 42_000,
    })
    .unwrap();

    assert_eq!(spec.optimization_class, OptimizationClass::Superinstruction);
    assert_eq!(spec.valid_from_epoch, epoch(10));
    assert_eq!(spec.valid_until_epoch, epoch(20));
    assert_eq!(spec.linked_policy_id, "my-policy");
    assert_eq!(
        spec.rollback_token_hash,
        ContentHash::compute(b"rollback-preserve")
    );
    assert_eq!(
        spec.baseline_ir_hash,
        ContentHash::compute(b"baseline-preserve")
    );
    assert_eq!(spec.activated_epoch, epoch(10));
    assert_eq!(spec.activated_at_ns, 42_000);
    assert_eq!(spec.state, FallbackState::Active);
    assert_eq!(spec.source_proof_ids.len(), 1);
}

// ===========================================================================
// 17. ChurnConfig defaults
// ===========================================================================

#[test]
fn churn_config_defaults() {
    let cfg = ChurnConfig::default();
    assert_eq!(cfg.threshold, 10);
    assert_eq!(cfg.window_ns, 60_000_000_000);
    assert_eq!(cfg.extended_canary_multiplier, 2_000_000);
    assert_eq!(cfg.cooldown_ns, 30_000_000_000);
}

// ===========================================================================
// 18. Counters and stats
// ===========================================================================

#[test]
fn total_invalidations_increments_correctly() {
    let mut engine = new_engine();
    for i in 0..5 {
        let spec = make_spec(
            OptimizationClass::TraceSpecialization,
            90,
            100,
            "p",
            &format!("count-{i}"),
        );
        engine.register_specialization(spec, 1000).unwrap();
    }
    engine.advance_epoch(epoch(101), 2000);
    assert_eq!(engine.total_invalidations(), 5);
}

#[test]
fn active_and_fallback_counts_consistent() {
    let mut engine = new_engine();
    for i in 0..4 {
        let until = if i < 2 { 105 } else { 120 };
        let spec = make_spec(
            OptimizationClass::TraceSpecialization,
            90,
            until,
            "p",
            &format!("consist-{i}"),
        );
        engine.register_specialization(spec, 1000).unwrap();
    }

    engine.advance_epoch(epoch(110), 2000);
    assert_eq!(engine.active_count(), 2);
    assert_eq!(engine.fallback_count(), 2);
    assert_eq!(engine.specializations().len(), 4);
}

// ===========================================================================
// 19. Edge cases
// ===========================================================================

#[test]
fn advance_epoch_with_no_specializations() {
    let mut engine = new_engine();
    let count = engine.advance_epoch(epoch(200), 1000);
    assert_eq!(count, 0);
    assert_eq!(engine.current_epoch(), epoch(200));
}

#[test]
fn advance_epoch_to_same_epoch() {
    let mut engine = new_engine();
    engine
        .register_specialization(default_spec(), 1000)
        .unwrap();
    let count = engine.advance_epoch(epoch(100), 2000);
    assert_eq!(count, 0);
    assert_eq!(engine.active_count(), 1);
}

#[test]
fn advance_epoch_to_lower_epoch() {
    let mut engine = new_engine();
    engine
        .register_specialization(default_spec(), 1000)
        .unwrap();
    let count = engine.advance_epoch(epoch(50), 2000);
    // spec valid 90..=110, epoch 50 is below valid_from so is_valid_at returns false.
    assert_eq!(count, 1);
    assert_eq!(engine.current_epoch(), epoch(50));
}

#[test]
fn multiple_epoch_advances() {
    let mut engine = new_engine();
    let spec = make_spec(
        OptimizationClass::TraceSpecialization,
        90,
        200,
        "p",
        "multi-adv",
    );
    engine.register_specialization(spec, 1000).unwrap();

    for e in [110, 120, 130, 140, 150] {
        let count = engine.advance_epoch(epoch(e), 1000 + e);
        assert_eq!(count, 0);
    }
    assert_eq!(engine.active_count(), 1);

    // Now expire.
    let count = engine.advance_epoch(epoch(201), 2000);
    assert_eq!(count, 1);
}

#[test]
fn invalidate_by_proof_empty_engine() {
    let mut engine = new_engine();
    let count = engine.invalidate_by_proof(&proof_id("any"), 1000);
    assert_eq!(count, 0);
}

#[test]
fn invalidate_by_policy_empty_engine() {
    let mut engine = new_engine();
    let count = engine.invalidate_by_policy("any", 1000);
    assert_eq!(count, 0);
}

// ===========================================================================
// 20. Complex multi-operation scenarios
// ===========================================================================

#[test]
fn full_lifecycle_register_invalidate_respec_reinvalidate() {
    let mut engine = new_engine();
    let spec = make_spec(
        OptimizationClass::TraceSpecialization,
        90,
        110,
        "p",
        "lifecycle",
    );
    let id = spec.specialization_id.clone();
    engine.register_specialization(spec, 1000).unwrap();
    assert_eq!(engine.active_count(), 1);

    // Invalidate via epoch.
    engine.advance_epoch(epoch(111), 2000);
    assert_eq!(engine.fallback_count(), 1);
    assert_eq!(engine.total_invalidations(), 1);

    // Re-specialize.
    engine.begin_respecialization(&id, 3000).unwrap();
    engine
        .complete_respecialization(
            &id,
            epoch(111),
            epoch(130),
            {
                let mut s = BTreeSet::new();
                s.insert(proof_id("new"));
                s
            },
            4000,
        )
        .unwrap();
    assert_eq!(engine.active_count(), 1);

    // Second invalidation via operator.
    engine
        .invalidate_specialization(
            &id,
            InvalidationReason::OperatorInvalidation {
                reason: "security".into(),
            },
            5000,
        )
        .unwrap();
    assert_eq!(engine.fallback_count(), 1);
    assert_eq!(engine.total_invalidations(), 2);
    assert_eq!(engine.receipts().len(), 2);
}

#[test]
fn mixed_invalidation_methods() {
    let mut engine = new_engine();
    let shared_proof = proof_id("shared");
    let mut proofs = BTreeSet::new();
    proofs.insert(shared_proof.clone());

    let s1 = spec_with_proofs(
        OptimizationClass::TraceSpecialization,
        90,
        110,
        "policy-A",
        proofs.clone(),
        "mix-1",
    );
    let s2 = spec_with_proofs(
        OptimizationClass::Superinstruction,
        90,
        110,
        "policy-B",
        proofs.clone(),
        "mix-2",
    );
    let s3 = make_spec(
        OptimizationClass::LayoutSpecialization,
        90,
        110,
        "policy-A",
        "mix-3",
    );

    engine.register_specialization(s1, 1000).unwrap();
    engine.register_specialization(s2, 1000).unwrap();
    engine.register_specialization(s3, 1000).unwrap();
    assert_eq!(engine.active_count(), 3);

    // Invalidate by proof — hits s1, s2.
    let count = engine.invalidate_by_proof(&shared_proof, 2000);
    assert_eq!(count, 2);
    assert_eq!(engine.active_count(), 1);

    // Invalidate by policy — s3 is still active on policy-A.
    let count = engine.invalidate_by_policy("policy-A", 3000);
    assert_eq!(count, 1);
    assert_eq!(engine.active_count(), 0);
    assert_eq!(engine.total_invalidations(), 3);
}

#[test]
fn many_specs_stress_test() {
    let mut engine = new_engine();
    for i in 0u64..100 {
        let spec = make_spec(
            OptimizationClass::TraceSpecialization,
            90,
            100 + (i % 20),
            "p",
            &format!("stress-{i}"),
        );
        engine.register_specialization(spec, 1000).unwrap();
    }
    assert_eq!(engine.specializations().len(), 100);

    // Advance to epoch 110 — specs with valid_until < 110 get invalidated.
    // valid_until = 100 + i%20. Expired when valid_until < 110 means i%20 < 10.
    // That's i%20 in 0..9 → 50 specs.
    let count = engine.advance_epoch(epoch(110), 2000);
    assert_eq!(count, 50);
    assert_eq!(engine.active_count(), 50);
    assert_eq!(engine.fallback_count(), 50);
}
