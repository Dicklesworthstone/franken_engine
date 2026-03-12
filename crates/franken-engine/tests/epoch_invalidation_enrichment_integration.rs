//! Enrichment integration tests for `epoch_invalidation` module.
//!
//! Covers: InvalidationReason, FallbackState, EpochBoundSpecialization,
//! InvalidationReceipt, InvalidationEvent/EventType, InvalidationError,
//! ChurnConfig, InvalidationConfig, EpochInvalidationEngine,
//! SpecializationInput, create_specialization — serde roundtrips,
//! Display uniqueness, deterministic ID derivation, lifecycle state machine,
//! churn dampening edge cases, proof/policy bulk invalidation, canonical bytes.

use std::collections::BTreeSet;

use frankenengine_engine::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use frankenengine_engine::epoch_invalidation::*;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::proof_schema::OptimizationClass;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ── helpers ──────────────────────────────────────────────────────────────

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn signing_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(3);
    }
    key
}

fn cfg() -> InvalidationConfig {
    InvalidationConfig {
        signing_key: signing_key(),
        churn: ChurnConfig::default(),
    }
}

fn engine_at(e: u64) -> EpochInvalidationEngine {
    EpochInvalidationEngine::new(epoch(e), cfg())
}

fn proof_id(suffix: &str) -> EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::PolicyObject,
        "enrichment-test",
        &SchemaId::from_definition(b"enrichment-proof"),
        suffix.as_bytes(),
    )
    .unwrap()
}

fn spec(class: OptimizationClass, from: u64, until: u64, policy: &str, tag: &str) -> EpochBoundSpecialization {
    let mut proofs = BTreeSet::new();
    proofs.insert(proof_id(tag));
    create_specialization(SpecializationInput {
        optimization_class: class,
        valid_from_epoch: epoch(from),
        valid_until_epoch: epoch(until),
        source_proof_ids: proofs,
        linked_policy_id: policy.to_string(),
        rollback_token_hash: ContentHash::compute(format!("rb-{tag}").as_bytes()),
        baseline_ir_hash: ContentHash::compute(format!("bl-{tag}").as_bytes()),
        activated_epoch: epoch(from),
        activated_at_ns: 1000,
    })
    .expect("create spec")
}

fn default_spec() -> EpochBoundSpecialization {
    spec(OptimizationClass::TraceSpecialization, 90, 110, "pol-1", "default")
}

// ── InvalidationReason Display uniqueness ────────────────────────────────

#[test]
fn enrichment_invalidation_reason_display_unique() {
    let reasons = [
        InvalidationReason::EpochTransition { old_epoch: epoch(1), new_epoch: epoch(2) },
        InvalidationReason::PolicyRotation { policy_id: "p".into() },
        InvalidationReason::KeyRotation { key_id: "k".into() },
        InvalidationReason::CapabilityRevocation { capability_id: "c".into() },
        InvalidationReason::ProofUpdate { proof_id: proof_id("x") },
        InvalidationReason::OperatorInvalidation { reason: "op".into() },
    ];
    let displays: BTreeSet<String> = reasons.iter().map(|r| r.to_string()).collect();
    assert_eq!(displays.len(), reasons.len());
}

// ── InvalidationReason serde ─────────────────────────────────────────────

#[test]
fn enrichment_invalidation_reason_serde_epoch_transition() {
    let r = InvalidationReason::EpochTransition { old_epoch: epoch(5), new_epoch: epoch(10) };
    let json = serde_json::to_string(&r).unwrap();
    let back: InvalidationReason = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_invalidation_reason_serde_policy_rotation() {
    let r = InvalidationReason::PolicyRotation { policy_id: "pol-42".into() };
    let json = serde_json::to_string(&r).unwrap();
    let back: InvalidationReason = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_invalidation_reason_serde_key_rotation() {
    let r = InvalidationReason::KeyRotation { key_id: "key-99".into() };
    let json = serde_json::to_string(&r).unwrap();
    let back: InvalidationReason = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_invalidation_reason_serde_capability_revocation() {
    let r = InvalidationReason::CapabilityRevocation { capability_id: "cap-1".into() };
    let json = serde_json::to_string(&r).unwrap();
    let back: InvalidationReason = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_invalidation_reason_serde_proof_update() {
    let r = InvalidationReason::ProofUpdate { proof_id: proof_id("pu") };
    let json = serde_json::to_string(&r).unwrap();
    let back: InvalidationReason = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_invalidation_reason_serde_operator_invalidation() {
    let r = InvalidationReason::OperatorInvalidation { reason: "manual teardown".into() };
    let json = serde_json::to_string(&r).unwrap();
    let back: InvalidationReason = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ── FallbackState Display uniqueness ─────────────────────────────────────

#[test]
fn enrichment_fallback_state_display_unique() {
    let states = [
        FallbackState::Active,
        FallbackState::Invalidating,
        FallbackState::BaselineFallback,
        FallbackState::ReSpecializing,
    ];
    let displays: BTreeSet<String> = states.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_fallback_state_serde_all() {
    for state in [
        FallbackState::Active,
        FallbackState::Invalidating,
        FallbackState::BaselineFallback,
        FallbackState::ReSpecializing,
    ] {
        let json = serde_json::to_string(&state).unwrap();
        let back: FallbackState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }
}

// ── EpochBoundSpecialization ─────────────────────────────────────────────

#[test]
fn enrichment_specialization_is_valid_at_inclusive_bounds() {
    let s = spec(OptimizationClass::Superinstruction, 50, 60, "p", "bounds");
    assert!(s.is_valid_at(epoch(50)));
    assert!(s.is_valid_at(epoch(55)));
    assert!(s.is_valid_at(epoch(60)));
    assert!(!s.is_valid_at(epoch(49)));
    assert!(!s.is_valid_at(epoch(61)));
}

#[test]
fn enrichment_specialization_canonical_bytes_deterministic() {
    let s1 = default_spec();
    let s2 = default_spec();
    assert_eq!(s1.canonical_bytes(), s2.canonical_bytes());
}

#[test]
fn enrichment_specialization_canonical_bytes_differ_on_different_input() {
    let s1 = spec(OptimizationClass::TraceSpecialization, 90, 110, "p", "a");
    let s2 = spec(OptimizationClass::TraceSpecialization, 90, 110, "p", "b");
    assert_ne!(s1.canonical_bytes(), s2.canonical_bytes());
}

#[test]
fn enrichment_specialization_serde_roundtrip() {
    let s = default_spec();
    let json = serde_json::to_string(&s).unwrap();
    let back: EpochBoundSpecialization = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn enrichment_specialization_starts_active() {
    let s = default_spec();
    assert_eq!(s.state, FallbackState::Active);
}

// ── InvalidationError Display uniqueness ─────────────────────────────────

#[test]
fn enrichment_invalidation_error_display_unique() {
    let errors: Vec<InvalidationError> = vec![
        InvalidationError::SpecializationNotFound { id: proof_id("x") },
        InvalidationError::AlreadyInFallback { id: proof_id("x") },
        InvalidationError::InvalidEpochRange { valid_from: epoch(10), valid_until: epoch(5) },
        InvalidationError::IdDerivation("msg".into()),
        InvalidationError::ChurnDampeningActive { invalidation_count: 5, window_ns: 1000 },
        InvalidationError::DuplicateSpecialization { id: proof_id("x") },
        InvalidationError::InvalidState { id: proof_id("x"), expected: "a".into(), actual: "b".into() },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), errors.len());
}

#[test]
fn enrichment_invalidation_error_is_std_error() {
    let e = InvalidationError::IdDerivation("test".into());
    let _: &dyn std::error::Error = &e;
}

#[test]
fn enrichment_invalidation_error_serde_all_variants() {
    let errors: Vec<InvalidationError> = vec![
        InvalidationError::SpecializationNotFound { id: proof_id("a") },
        InvalidationError::AlreadyInFallback { id: proof_id("b") },
        InvalidationError::InvalidEpochRange { valid_from: epoch(10), valid_until: epoch(5) },
        InvalidationError::IdDerivation("msg".into()),
        InvalidationError::ChurnDampeningActive { invalidation_count: 3, window_ns: 500 },
        InvalidationError::DuplicateSpecialization { id: proof_id("c") },
        InvalidationError::InvalidState { id: proof_id("d"), expected: "a".into(), actual: "b".into() },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: InvalidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ── ChurnConfig defaults ────────────────────────────────────────────────

#[test]
fn enrichment_churn_config_defaults() {
    let c = ChurnConfig::default();
    assert_eq!(c.threshold, 10);
    assert_eq!(c.window_ns, 60_000_000_000);
    assert_eq!(c.extended_canary_multiplier, 2_000_000);
    assert_eq!(c.cooldown_ns, 30_000_000_000);
}

#[test]
fn enrichment_churn_config_serde_roundtrip() {
    let c = ChurnConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: ChurnConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ── InvalidationConfig ──────────────────────────────────────────────────

#[test]
fn enrichment_invalidation_config_serde_roundtrip() {
    let c = cfg();
    let json = serde_json::to_string(&c).unwrap();
    let back: InvalidationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ── Engine construction ─────────────────────────────────────────────────

#[test]
fn enrichment_engine_new_empty() {
    let e = engine_at(100);
    assert_eq!(e.current_epoch(), epoch(100));
    assert!(e.specializations().is_empty());
    assert!(e.receipts().is_empty());
    assert!(e.events().is_empty());
    assert!(!e.is_conservative_mode());
    assert_eq!(e.total_invalidations(), 0);
    assert_eq!(e.active_count(), 0);
    assert_eq!(e.fallback_count(), 0);
}

#[test]
fn enrichment_engine_canary_multiplier_default() {
    let e = engine_at(100);
    assert_eq!(e.canary_multiplier(), 1_000_000);
}

// ── Registration edge cases ─────────────────────────────────────────────

#[test]
fn enrichment_register_multiple_classes() {
    let mut e = engine_at(100);
    e.register_specialization(
        spec(OptimizationClass::TraceSpecialization, 90, 110, "p", "ts"),
        1000,
    ).unwrap();
    e.register_specialization(
        spec(OptimizationClass::Superinstruction, 90, 110, "p", "si"),
        1000,
    ).unwrap();
    e.register_specialization(
        spec(OptimizationClass::LayoutSpecialization, 90, 110, "p", "ls"),
        1000,
    ).unwrap();
    assert_eq!(e.active_count(), 3);
    assert_eq!(e.specializations().len(), 3);
}

#[test]
fn enrichment_register_emits_event() {
    let mut e = engine_at(100);
    e.register_specialization(default_spec(), 1000).unwrap();
    assert_eq!(e.events().len(), 1);
    assert!(matches!(
        e.events()[0].event_type,
        InvalidationEventType::SpecializationRegistered { .. }
    ));
}

// ── Epoch advance ───────────────────────────────────────────────────────

#[test]
fn enrichment_advance_epoch_no_specs_zero_invalidations() {
    let mut e = engine_at(100);
    let count = e.advance_epoch(epoch(200), 1000);
    assert_eq!(count, 0);
    assert_eq!(e.current_epoch(), epoch(200));
}

#[test]
fn enrichment_advance_epoch_updates_current_epoch() {
    let mut e = engine_at(100);
    e.advance_epoch(epoch(150), 1000);
    assert_eq!(e.current_epoch(), epoch(150));
}

#[test]
fn enrichment_advance_epoch_all_expired() {
    let mut e = engine_at(100);
    for i in 0..4 {
        e.register_specialization(
            spec(OptimizationClass::TraceSpecialization, 90, 100, "p", &format!("all-{i}")),
            1000,
        ).unwrap();
    }
    let count = e.advance_epoch(epoch(101), 2000);
    assert_eq!(count, 4);
    assert_eq!(e.active_count(), 0);
    assert_eq!(e.fallback_count(), 4);
}

#[test]
fn enrichment_advance_epoch_generates_receipts() {
    let mut e = engine_at(100);
    e.register_specialization(default_spec(), 1000).unwrap();
    e.advance_epoch(epoch(111), 2000);
    assert_eq!(e.receipts().len(), 1);
    let r = &e.receipts()[0];
    assert!(!r.signature.is_empty());
    assert_eq!(r.new_epoch, epoch(111));
}

// ── Individual invalidation ─────────────────────────────────────────────

#[test]
fn enrichment_invalidate_specific_preserves_others() {
    let mut e = engine_at(100);
    let s1 = spec(OptimizationClass::TraceSpecialization, 90, 110, "p", "keep");
    let s2 = spec(OptimizationClass::Superinstruction, 90, 110, "p", "remove");
    let s2_id = s2.specialization_id.clone();
    e.register_specialization(s1, 1000).unwrap();
    e.register_specialization(s2, 1000).unwrap();

    e.invalidate_specialization(
        &s2_id,
        InvalidationReason::KeyRotation { key_id: "k1".into() },
        2000,
    ).unwrap();

    assert_eq!(e.active_count(), 1);
    assert_eq!(e.fallback_count(), 1);
}

#[test]
fn enrichment_invalidate_already_fallback_errors() {
    let mut e = engine_at(100);
    let s = default_spec();
    let sid = s.specialization_id.clone();
    e.register_specialization(s, 1000).unwrap();
    e.advance_epoch(epoch(111), 2000);

    let err = e.invalidate_specialization(
        &sid,
        InvalidationReason::OperatorInvalidation { reason: "dup".into() },
        3000,
    ).unwrap_err();
    assert!(matches!(err, InvalidationError::AlreadyInFallback { .. }));
}

// ── Proof-based invalidation ────────────────────────────────────────────

#[test]
fn enrichment_invalidate_by_proof_targets_matching() {
    let mut e = engine_at(100);
    let pid = proof_id("shared");
    let mut proofs = BTreeSet::new();
    proofs.insert(pid.clone());

    let s = create_specialization(SpecializationInput {
        optimization_class: OptimizationClass::LayoutSpecialization,
        valid_from_epoch: epoch(90),
        valid_until_epoch: epoch(110),
        source_proof_ids: proofs,
        linked_policy_id: "p".into(),
        rollback_token_hash: ContentHash::compute(b"rb"),
        baseline_ir_hash: ContentHash::compute(b"bl"),
        activated_epoch: epoch(90),
        activated_at_ns: 1000,
    }).unwrap();
    e.register_specialization(s, 1000).unwrap();

    // Also register one with a different proof
    e.register_specialization(
        spec(OptimizationClass::TraceSpecialization, 90, 110, "p", "other"),
        1000,
    ).unwrap();

    let count = e.invalidate_by_proof(&pid, 2000);
    assert_eq!(count, 1);
    assert_eq!(e.active_count(), 1);
}

#[test]
fn enrichment_invalidate_by_proof_no_match() {
    let mut e = engine_at(100);
    e.register_specialization(default_spec(), 1000).unwrap();
    let count = e.invalidate_by_proof(&proof_id("nonexistent"), 2000);
    assert_eq!(count, 0);
    assert_eq!(e.active_count(), 1);
}

// ── Policy-based invalidation ───────────────────────────────────────────

#[test]
fn enrichment_invalidate_by_policy_targets_matching() {
    let mut e = engine_at(100);
    e.register_specialization(
        spec(OptimizationClass::TraceSpecialization, 90, 110, "pol-A", "pa1"),
        1000,
    ).unwrap();
    e.register_specialization(
        spec(OptimizationClass::Superinstruction, 90, 110, "pol-A", "pa2"),
        1000,
    ).unwrap();
    e.register_specialization(
        spec(OptimizationClass::LayoutSpecialization, 90, 110, "pol-B", "pb1"),
        1000,
    ).unwrap();

    let count = e.invalidate_by_policy("pol-A", 2000);
    assert_eq!(count, 2);
    assert_eq!(e.active_count(), 1);
}

#[test]
fn enrichment_invalidate_by_policy_no_match() {
    let mut e = engine_at(100);
    e.register_specialization(default_spec(), 1000).unwrap();
    let count = e.invalidate_by_policy("nonexistent", 2000);
    assert_eq!(count, 0);
}

// ── Re-specialization lifecycle ─────────────────────────────────────────

#[test]
fn enrichment_respecialization_full_lifecycle() {
    let mut e = engine_at(100);
    let s = default_spec();
    let sid = s.specialization_id.clone();
    e.register_specialization(s, 1000).unwrap();

    // Invalidate
    e.advance_epoch(epoch(111), 2000);
    assert_eq!(e.get_specialization(&sid).unwrap().state, FallbackState::BaselineFallback);

    // Begin respecialization
    e.begin_respecialization(&sid, 3000).unwrap();
    assert_eq!(e.get_specialization(&sid).unwrap().state, FallbackState::ReSpecializing);

    // Complete respecialization
    let new_proofs = {
        let mut s = BTreeSet::new();
        s.insert(proof_id("new"));
        s
    };
    e.complete_respecialization(&sid, epoch(111), epoch(130), new_proofs, 4000).unwrap();

    let restored = e.get_specialization(&sid).unwrap();
    assert_eq!(restored.state, FallbackState::Active);
    assert_eq!(restored.valid_from_epoch, epoch(111));
    assert_eq!(restored.valid_until_epoch, epoch(130));
}

#[test]
fn enrichment_begin_respecialization_requires_baseline_fallback() {
    let mut e = engine_at(100);
    let s = default_spec();
    let sid = s.specialization_id.clone();
    e.register_specialization(s, 1000).unwrap();

    let err = e.begin_respecialization(&sid, 2000).unwrap_err();
    assert!(matches!(err, InvalidationError::InvalidState { .. }));
}

#[test]
fn enrichment_complete_respecialization_requires_respecializing_state() {
    let mut e = engine_at(100);
    let s = default_spec();
    let sid = s.specialization_id.clone();
    e.register_specialization(s, 1000).unwrap();
    e.advance_epoch(epoch(111), 2000);

    let err = e.complete_respecialization(
        &sid, epoch(111), epoch(130), BTreeSet::new(), 3000,
    ).unwrap_err();
    assert!(matches!(err, InvalidationError::InvalidState { .. }));
}

#[test]
fn enrichment_complete_respecialization_invalid_epoch_range() {
    let mut e = engine_at(100);
    let s = default_spec();
    let sid = s.specialization_id.clone();
    e.register_specialization(s, 1000).unwrap();
    e.advance_epoch(epoch(111), 2000);
    e.begin_respecialization(&sid, 3000).unwrap();

    let err = e.complete_respecialization(
        &sid, epoch(130), epoch(111), BTreeSet::new(), 4000,
    ).unwrap_err();
    assert!(matches!(err, InvalidationError::InvalidEpochRange { .. }));
}

// ── Churn dampening ─────────────────────────────────────────────────────

#[test]
fn enrichment_churn_dampening_activates_at_threshold() {
    let mut c = cfg();
    c.churn.threshold = 2;
    c.churn.window_ns = 10_000;
    let mut e = EpochInvalidationEngine::new(epoch(100), c);

    for i in 0..2 {
        let s = spec(OptimizationClass::TraceSpecialization, 90, 110, "p", &format!("ch-{i}"));
        let sid = s.specialization_id.clone();
        e.register_specialization(s, 1000 + i * 100).unwrap();
        e.invalidate_specialization(
            &sid,
            InvalidationReason::OperatorInvalidation { reason: "t".into() },
            1050 + i * 100,
        ).unwrap();
    }

    assert!(e.is_conservative_mode());
    assert!(e.requires_extended_canary());
}

#[test]
fn enrichment_churn_canary_multiplier_when_active() {
    let mut c = cfg();
    c.churn.threshold = 1;
    c.churn.extended_canary_multiplier = 3_000_000;
    let mut e = EpochInvalidationEngine::new(epoch(100), c);

    let s = default_spec();
    let sid = s.specialization_id.clone();
    e.register_specialization(s, 1000).unwrap();
    e.invalidate_specialization(
        &sid,
        InvalidationReason::OperatorInvalidation { reason: "t".into() },
        1050,
    ).unwrap();

    assert_eq!(e.canary_multiplier(), 3_000_000);
}

#[test]
fn enrichment_churn_deactivates_when_window_expires() {
    let mut c = cfg();
    c.churn.threshold = 2;
    c.churn.window_ns = 500;
    let mut e = EpochInvalidationEngine::new(epoch(100), c);

    // Two rapid invalidations within window to activate conservative mode
    let s1 = spec(OptimizationClass::TraceSpecialization, 90, 110, "p", "cd1");
    let s1_id = s1.specialization_id.clone();
    e.register_specialization(s1, 100).unwrap();
    e.invalidate_specialization(
        &s1_id,
        InvalidationReason::OperatorInvalidation { reason: "t".into() },
        200,
    ).unwrap();

    let s1b = spec(OptimizationClass::LayoutSpecialization, 90, 110, "p", "cd1b");
    let s1b_id = s1b.specialization_id.clone();
    e.register_specialization(s1b, 250).unwrap();
    e.invalidate_specialization(
        &s1b_id,
        InvalidationReason::OperatorInvalidation { reason: "t".into() },
        300,
    ).unwrap();
    assert!(e.is_conservative_mode());

    // New invalidation far outside window — only 1 timestamp remains < threshold of 2
    let s2 = spec(OptimizationClass::Superinstruction, 90, 110, "p", "cd2");
    let s2_id = s2.specialization_id.clone();
    e.register_specialization(s2, 5000).unwrap();
    e.invalidate_specialization(
        &s2_id,
        InvalidationReason::OperatorInvalidation { reason: "t".into() },
        5100,
    ).unwrap();
    assert!(!e.is_conservative_mode());
    assert_eq!(e.canary_multiplier(), 1_000_000);
}

// ── Query methods ───────────────────────────────────────────────────────

#[test]
fn enrichment_specializations_by_class_filters() {
    let mut e = engine_at(100);
    e.register_specialization(
        spec(OptimizationClass::TraceSpecialization, 90, 110, "p", "qc1"),
        1000,
    ).unwrap();
    e.register_specialization(
        spec(OptimizationClass::Superinstruction, 90, 110, "p", "qc2"),
        1000,
    ).unwrap();

    assert_eq!(e.specializations_by_class(&OptimizationClass::TraceSpecialization).len(), 1);
    assert_eq!(e.specializations_by_class(&OptimizationClass::Superinstruction).len(), 1);
    assert_eq!(e.specializations_by_class(&OptimizationClass::LayoutSpecialization).len(), 0);
}

#[test]
fn enrichment_specializations_by_state_filters() {
    let mut e = engine_at(100);
    let s1 = spec(OptimizationClass::TraceSpecialization, 90, 100, "p", "qs1");
    let s2 = spec(OptimizationClass::Superinstruction, 90, 120, "p", "qs2");
    e.register_specialization(s1, 1000).unwrap();
    e.register_specialization(s2, 1000).unwrap();

    e.advance_epoch(epoch(105), 2000);

    assert_eq!(e.specializations_by_state(FallbackState::Active).len(), 1);
    assert_eq!(e.specializations_by_state(FallbackState::BaselineFallback).len(), 1);
    assert_eq!(e.specializations_by_state(FallbackState::ReSpecializing).len(), 0);
}

// ── Receipt structure ───────────────────────────────────────────────────

#[test]
fn enrichment_receipt_contains_correct_hashes() {
    let mut e = engine_at(100);
    let s = default_spec();
    let expected_rb = s.rollback_token_hash;
    let expected_bl = s.baseline_ir_hash;
    e.register_specialization(s, 1000).unwrap();

    e.advance_epoch(epoch(111), 2000);
    let r = &e.receipts()[0];
    assert_eq!(r.rollback_token_hash, expected_rb);
    assert_eq!(r.baseline_restoration_hash, expected_bl);
}

#[test]
fn enrichment_receipt_serde_roundtrip() {
    let mut e = engine_at(100);
    let s = default_spec();
    let sid = s.specialization_id.clone();
    e.register_specialization(s, 1000).unwrap();

    let receipt = e.invalidate_specialization(
        &sid,
        InvalidationReason::PolicyRotation { policy_id: "pol-X".into() },
        2000,
    ).unwrap();

    let json = serde_json::to_string(&receipt).unwrap();
    let back: InvalidationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

// ── Event log ───────────────────────────────────────────────────────────

#[test]
fn enrichment_events_monotonic_seq() {
    let mut e = engine_at(100);
    e.register_specialization(default_spec(), 1000).unwrap();
    e.advance_epoch(epoch(111), 2000);

    for (i, ev) in e.events().iter().enumerate() {
        assert_eq!(ev.seq, i as u64);
    }
}

#[test]
fn enrichment_events_epoch_matches_current() {
    let mut e = engine_at(100);
    e.register_specialization(default_spec(), 1000).unwrap();
    // All events before advance are at epoch 100
    for ev in e.events() {
        assert_eq!(ev.epoch, epoch(100));
    }

    e.advance_epoch(epoch(111), 2000);
    // Events after advance are at epoch 111
    for ev in e.events().iter().skip(1) {
        assert_eq!(ev.epoch, epoch(111));
    }
}

#[test]
fn enrichment_event_type_serde_all_variants() {
    let sid = proof_id("ev");
    let events = vec![
        InvalidationEventType::SpecializationRegistered {
            specialization_id: sid.clone(),
            optimization_class: OptimizationClass::TraceSpecialization,
        },
        InvalidationEventType::EpochTransitionTriggered {
            old_epoch: epoch(1),
            new_epoch: epoch(2),
        },
        InvalidationEventType::SpecializationInvalidated {
            specialization_id: sid.clone(),
            reason: InvalidationReason::OperatorInvalidation { reason: "t".into() },
        },
        InvalidationEventType::BaselineFallbackCompleted {
            specialization_id: sid.clone(),
        },
        InvalidationEventType::ReSpecializationStarted {
            specialization_id: sid.clone(),
        },
        InvalidationEventType::ChurnDampeningActivated {
            invalidation_count: 5,
            window_ns: 1000,
        },
        InvalidationEventType::ChurnDampeningDeactivated,
        InvalidationEventType::BulkInvalidationCompleted {
            count: 3,
            epoch: epoch(10),
        },
        InvalidationEventType::InvalidationReceiptEmitted {
            receipt_id: sid.clone(),
            specialization_id: sid.clone(),
        },
    ];

    for et in &events {
        let wrapped = InvalidationEvent {
            seq: 0,
            timestamp_ns: 1000,
            event_type: et.clone(),
            epoch: epoch(1),
        };
        let json = serde_json::to_string(&wrapped).unwrap();
        let back: InvalidationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(wrapped, back);
    }
}

// ── Engine serde ────────────────────────────────────────────────────────

#[test]
fn enrichment_engine_serde_roundtrip_with_state() {
    let mut e = engine_at(100);
    let s = default_spec();
    let sid = s.specialization_id.clone();
    e.register_specialization(s, 1000).unwrap();
    e.advance_epoch(epoch(111), 2000);
    e.begin_respecialization(&sid, 3000).unwrap();

    let json = serde_json::to_string(&e).unwrap();
    let back: EpochInvalidationEngine = serde_json::from_str(&json).unwrap();
    assert_eq!(back.current_epoch(), epoch(111));
    assert_eq!(back.specializations().len(), 1);
    assert_eq!(back.get_specialization(&sid).unwrap().state, FallbackState::ReSpecializing);
    assert_eq!(back.total_invalidations(), 1);
    assert!(!back.receipts().is_empty());
}

// ── create_specialization ───────────────────────────────────────────────

#[test]
fn enrichment_create_specialization_deterministic_id() {
    let s1 = default_spec();
    let s2 = default_spec();
    assert_eq!(s1.specialization_id, s2.specialization_id);
}

#[test]
fn enrichment_create_specialization_different_class_different_id() {
    let s1 = spec(OptimizationClass::TraceSpecialization, 90, 110, "p", "same");
    let s2 = spec(OptimizationClass::Superinstruction, 90, 110, "p", "same");
    assert_ne!(s1.specialization_id, s2.specialization_id);
}

#[test]
fn enrichment_create_specialization_different_policy_different_id() {
    let s1 = spec(OptimizationClass::TraceSpecialization, 90, 110, "pol-A", "same");
    let s2 = spec(OptimizationClass::TraceSpecialization, 90, 110, "pol-B", "same");
    assert_ne!(s1.specialization_id, s2.specialization_id);
}

#[test]
fn enrichment_create_specialization_different_epochs_different_id() {
    let s1 = spec(OptimizationClass::TraceSpecialization, 90, 110, "p", "same");
    let s2 = spec(OptimizationClass::TraceSpecialization, 91, 110, "p", "same");
    assert_ne!(s1.specialization_id, s2.specialization_id);
}

// ── SpecializationInput serde ───────────────────────────────────────────

#[test]
fn enrichment_specialization_input_serde_roundtrip() {
    let input = SpecializationInput {
        optimization_class: OptimizationClass::TraceSpecialization,
        valid_from_epoch: epoch(90),
        valid_until_epoch: epoch(110),
        source_proof_ids: {
            let mut s = BTreeSet::new();
            s.insert(proof_id("inp"));
            s
        },
        linked_policy_id: "pol-X".into(),
        rollback_token_hash: ContentHash::compute(b"rb"),
        baseline_ir_hash: ContentHash::compute(b"bl"),
        activated_epoch: epoch(90),
        activated_at_ns: 1000,
    };
    let json = serde_json::to_string(&input).unwrap();
    let back: SpecializationInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input.optimization_class, back.optimization_class);
    assert_eq!(input.valid_from_epoch, back.valid_from_epoch);
    assert_eq!(input.linked_policy_id, back.linked_policy_id);
}

// ── Total invalidations counter ─────────────────────────────────────────

#[test]
fn enrichment_total_invalidations_increments() {
    let mut e = engine_at(100);
    for i in 0..5 {
        e.register_specialization(
            spec(OptimizationClass::TraceSpecialization, 90, 100, "p", &format!("ti-{i}")),
            1000,
        ).unwrap();
    }
    e.advance_epoch(epoch(101), 2000);
    assert_eq!(e.total_invalidations(), 5);
}

// ── Deterministic receipt ordering ──────────────────────────────────────

#[test]
fn enrichment_bulk_invalidation_receipt_order_deterministic() {
    let mut e = engine_at(100);
    for i in 0..8 {
        e.register_specialization(
            spec(OptimizationClass::TraceSpecialization, 90, 100, "p", &format!("det-{i}")),
            1000,
        ).unwrap();
    }
    e.advance_epoch(epoch(101), 2000);

    let ids: Vec<_> = e.receipts().iter().map(|r| r.specialization_id.clone()).collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted);
}

// ── Fallback persists across serde ──────────────────────────────────────

#[test]
fn enrichment_fallback_persists_across_serde() {
    let mut e = engine_at(100);
    let s = default_spec();
    let sid = s.specialization_id.clone();
    e.register_specialization(s, 1000).unwrap();
    e.advance_epoch(epoch(111), 2000);

    let json = serde_json::to_string(&e).unwrap();
    let restored: EpochInvalidationEngine = serde_json::from_str(&json).unwrap();
    assert_eq!(
        restored.get_specialization(&sid).unwrap().state,
        FallbackState::BaselineFallback,
    );
}

// ── InvalidationReason Display content ──────────────────────────────────

#[test]
fn enrichment_reason_display_epoch_transition_format() {
    let r = InvalidationReason::EpochTransition { old_epoch: epoch(5), new_epoch: epoch(10) };
    let s = r.to_string();
    assert!(s.contains("epoch-transition"));
}

#[test]
fn enrichment_reason_display_policy_rotation_format() {
    let r = InvalidationReason::PolicyRotation { policy_id: "pol-XYZ".into() };
    let s = r.to_string();
    assert!(s.contains("policy-rotation"));
    assert!(s.contains("pol-XYZ"));
}

#[test]
fn enrichment_reason_display_capability_revocation_format() {
    let r = InvalidationReason::CapabilityRevocation { capability_id: "cap-99".into() };
    let s = r.to_string();
    assert!(s.contains("capability-revocation"));
    assert!(s.contains("cap-99"));
}

// ── Edge cases ──────────────────────────────────────────────────────────

#[test]
fn enrichment_epoch_advance_same_epoch_no_invalidation() {
    let mut e = engine_at(100);
    e.register_specialization(default_spec(), 1000).unwrap();
    let count = e.advance_epoch(epoch(100), 2000);
    assert_eq!(count, 0);
    assert_eq!(e.active_count(), 1);
}

#[test]
fn enrichment_get_specialization_not_found() {
    let e = engine_at(100);
    assert!(e.get_specialization(&proof_id("nope")).is_none());
}

#[test]
fn enrichment_invalidate_nonexistent_errors() {
    let mut e = engine_at(100);
    let err = e.invalidate_specialization(
        &proof_id("nope"),
        InvalidationReason::OperatorInvalidation { reason: "t".into() },
        1000,
    ).unwrap_err();
    assert!(matches!(err, InvalidationError::SpecializationNotFound { .. }));
}

#[test]
fn enrichment_begin_respecialization_nonexistent_errors() {
    let mut e = engine_at(100);
    let err = e.begin_respecialization(&proof_id("nope"), 1000).unwrap_err();
    assert!(matches!(err, InvalidationError::SpecializationNotFound { .. }));
}

#[test]
fn enrichment_complete_respecialization_nonexistent_errors() {
    let mut e = engine_at(100);
    let err = e.complete_respecialization(
        &proof_id("nope"),
        epoch(100),
        epoch(200),
        BTreeSet::new(),
        1000,
    ).unwrap_err();
    assert!(matches!(err, InvalidationError::SpecializationNotFound { .. }));
}
