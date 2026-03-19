//! Enrichment integration tests for the `revocation_enforcement` module.
//!
//! Covers additional edge cases for enforcement points, denial scenarios,
//! batch operations, statistics, audit events, and serde round-trips.

#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use frankenengine_engine::capability_token::PrincipalId;
use frankenengine_engine::engine_object_id::{self, EngineObjectId, ObjectDomain};
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::revocation_chain::{
    Revocation, RevocationChain, RevocationReason, RevocationTargetType, revocation_schema_id,
};
use frankenengine_engine::revocation_enforcement::*;
use frankenengine_engine::signature_preimage::{
    SIGNATURE_SENTINEL, Signature, SignaturePreimage, SigningKey, VerificationKey, sign_preimage,
};

// ── Helpers ───────────────────────────────────────────────────────────────

const ZONE: &str = "enrich-zone";

fn head_signing_key() -> SigningKey {
    SigningKey::from_bytes([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ])
}

fn rev_signing_key() -> SigningKey {
    SigningKey::from_bytes([
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE,
        0xBF, 0xC0,
    ])
}

fn make_revocation(target_type: RevocationTargetType, target_bytes: [u8; 32]) -> Revocation {
    let sk = rev_signing_key();
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
        reason: RevocationReason::Compromised,
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

fn make_enforcer() -> RevocationEnforcer {
    let chain = RevocationChain::new(ZONE);
    RevocationEnforcer::new(chain, 5000)
}

fn revoke_target(
    enforcer: &mut RevocationEnforcer,
    target_type: RevocationTargetType,
    target_bytes: [u8; 32],
) {
    let rev = make_revocation(target_type, target_bytes);
    let sk = head_signing_key();
    enforcer.chain_mut().append(rev, &sk, "t-revoke").unwrap();
}

// ---------------------------------------------------------------------------
// EnforcementPoint: display, serde, clone, ord
// ---------------------------------------------------------------------------

#[test]
fn enrich_enforcement_point_display_all() {
    assert_eq!(
        EnforcementPoint::TokenAcceptance.to_string(),
        "token_acceptance"
    );
    assert_eq!(
        EnforcementPoint::HighRiskOperation.to_string(),
        "high_risk_operation"
    );
    assert_eq!(
        EnforcementPoint::ExtensionActivation.to_string(),
        "extension_activation"
    );
}

#[test]
fn enrich_enforcement_point_clone_eq() {
    let a = EnforcementPoint::HighRiskOperation;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrich_enforcement_point_all_ne() {
    let pts = [
        EnforcementPoint::TokenAcceptance,
        EnforcementPoint::HighRiskOperation,
        EnforcementPoint::ExtensionActivation,
    ];
    for i in 0..pts.len() {
        for j in (i + 1)..pts.len() {
            assert_ne!(pts[i], pts[j]);
        }
    }
}

// ---------------------------------------------------------------------------
// HighRiskCategory: display, serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_high_risk_category_display_all() {
    assert_eq!(HighRiskCategory::PolicyChange.to_string(), "policy_change");
    assert_eq!(HighRiskCategory::KeyOperation.to_string(), "key_operation");
    assert_eq!(HighRiskCategory::DataExport.to_string(), "data_export");
    assert_eq!(
        HighRiskCategory::CrossZoneAction.to_string(),
        "cross_zone_action"
    );
    assert_eq!(
        HighRiskCategory::ExtensionLifecycleChange.to_string(),
        "extension_lifecycle_change"
    );
}

#[test]
fn enrich_high_risk_category_serde_all() {
    for cat in [
        HighRiskCategory::PolicyChange,
        HighRiskCategory::KeyOperation,
        HighRiskCategory::DataExport,
        HighRiskCategory::CrossZoneAction,
        HighRiskCategory::ExtensionLifecycleChange,
    ] {
        let json = serde_json::to_string(&cat).unwrap();
        let back: HighRiskCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(cat, back);
    }
}

// ---------------------------------------------------------------------------
// key_id_from_verification_key
// ---------------------------------------------------------------------------

#[test]
fn enrich_key_id_deterministic() {
    let vk = VerificationKey::from_bytes([42; 32]);
    let id1 = key_id_from_verification_key(&vk);
    let id2 = key_id_from_verification_key(&vk);
    assert_eq!(id1, id2);
}

#[test]
fn enrich_key_id_different_keys() {
    let vk1 = VerificationKey::from_bytes([1; 32]);
    let vk2 = VerificationKey::from_bytes([2; 32]);
    assert_ne!(
        key_id_from_verification_key(&vk1),
        key_id_from_verification_key(&vk2)
    );
}

#[test]
fn enrich_key_id_all_zeros() {
    let vk = VerificationKey::from_bytes([0; 32]);
    let id = key_id_from_verification_key(&vk);
    assert_eq!(id.as_bytes().len(), 32);
}

// ---------------------------------------------------------------------------
// EnforcementResult
// ---------------------------------------------------------------------------

#[test]
fn enrich_cleared_is_cleared() {
    let r = EnforcementResult::Cleared {
        enforcement_point: EnforcementPoint::HighRiskOperation,
        checks_performed: 2,
    };
    assert!(r.is_cleared());
    assert!(r.into_result().is_ok());
}

#[test]
fn enrich_denied_is_not_cleared() {
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Extension,
        target_id: EngineObjectId([5; 32]),
        transitive: false,
        transitive_root: None,
        enforcement_point: EnforcementPoint::ExtensionActivation,
    };
    let r = EnforcementResult::Denied(denial.clone());
    assert!(!r.is_cleared());
    let err = r.into_result().unwrap_err();
    assert_eq!(err, denial);
}

#[test]
fn enrich_enforcement_result_serde() {
    let cleared = EnforcementResult::Cleared {
        enforcement_point: EnforcementPoint::TokenAcceptance,
        checks_performed: 2,
    };
    let json = serde_json::to_string(&cleared).unwrap();
    let back: EnforcementResult = serde_json::from_str(&json).unwrap();
    assert_eq!(cleared, back);
}

// ---------------------------------------------------------------------------
// RevocationDenial display
// ---------------------------------------------------------------------------

#[test]
fn enrich_denial_display_direct() {
    let d = RevocationDenial {
        target_type: RevocationTargetType::Attestation,
        target_id: EngineObjectId([3; 32]),
        transitive: false,
        transitive_root: None,
        enforcement_point: EnforcementPoint::HighRiskOperation,
    };
    let s = d.to_string();
    assert!(s.contains("directly revoked"));
    assert!(s.contains("high_risk_operation"));
}

#[test]
fn enrich_denial_display_transitive_with_root() {
    let d = RevocationDenial {
        target_type: RevocationTargetType::Token,
        target_id: EngineObjectId([1; 32]),
        transitive: true,
        transitive_root: Some(EngineObjectId([2; 32])),
        enforcement_point: EnforcementPoint::TokenAcceptance,
    };
    let s = d.to_string();
    assert!(s.contains("transitively revoked"));
}

#[test]
fn enrich_denial_serde_roundtrip() {
    let d = RevocationDenial {
        target_type: RevocationTargetType::Extension,
        target_id: EngineObjectId([6; 32]),
        transitive: true,
        transitive_root: Some(EngineObjectId([7; 32])),
        enforcement_point: EnforcementPoint::ExtensionActivation,
    };
    let json = serde_json::to_string(&d).unwrap();
    let back: RevocationDenial = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

// ---------------------------------------------------------------------------
// Token acceptance: additional scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrich_token_cleared_two_checks_performed() {
    let mut enforcer = make_enforcer();
    let result = enforcer.check_token_acceptance(
        &EngineObjectId([1; 32]),
        &VerificationKey::from_bytes([2; 32]),
        "t-1",
    );
    match result {
        EnforcementResult::Cleared {
            checks_performed, ..
        } => {
            assert_eq!(checks_performed, 2);
        }
        _ => panic!("expected cleared"),
    }
}

#[test]
fn enrich_token_denial_direct_stops_early() {
    let mut enforcer = make_enforcer();
    revoke_target(&mut enforcer, RevocationTargetType::Token, [10; 32]);
    enforcer.drain_audit_log();
    let result = enforcer.check_token_acceptance(
        &EngineObjectId([10; 32]),
        &VerificationKey::from_bytes([2; 32]),
        "t-early",
    );
    assert!(!result.is_cleared());
    // Direct denial emits only 1 audit event (stops before transitive check)
    let events = enforcer.drain_audit_log();
    assert_eq!(events.len(), 1);
    assert!(!events[0].transitive);
}

#[test]
fn enrich_token_transitive_denial_emits_two_events() {
    let mut enforcer = make_enforcer();
    let issuer_key = VerificationKey::from_bytes([20; 32]);
    let key_id = key_id_from_verification_key(&issuer_key);
    revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());
    enforcer.drain_audit_log();

    enforcer.check_token_acceptance(&EngineObjectId([5; 32]), &issuer_key, "t-trans");
    let events = enforcer.drain_audit_log();
    assert_eq!(events.len(), 2);
    assert!(!events[0].is_revoked); // direct check passes
    assert!(events[1].is_revoked); // transitive check fails
    assert!(events[1].transitive);
}

// ---------------------------------------------------------------------------
// High-risk operation: additional scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrich_high_risk_all_categories_cleared() {
    let mut enforcer = make_enforcer();
    for cat in [
        HighRiskCategory::PolicyChange,
        HighRiskCategory::KeyOperation,
        HighRiskCategory::DataExport,
        HighRiskCategory::CrossZoneAction,
        HighRiskCategory::ExtensionLifecycleChange,
    ] {
        let result = enforcer.check_high_risk_operation(
            &EngineObjectId([30; 32]),
            &VerificationKey::from_bytes([31; 32]),
            cat,
            "t-all-cat",
        );
        assert!(result.is_cleared(), "category {cat} should be cleared");
    }
}

#[test]
fn enrich_high_risk_attestation_revoked_direct() {
    let mut enforcer = make_enforcer();
    revoke_target(&mut enforcer, RevocationTargetType::Attestation, [40; 32]);
    let result = enforcer.check_high_risk_operation(
        &EngineObjectId([40; 32]),
        &VerificationKey::from_bytes([41; 32]),
        HighRiskCategory::PolicyChange,
        "t-hr-deny",
    );
    match result {
        EnforcementResult::Denied(d) => {
            assert_eq!(d.target_type, RevocationTargetType::Attestation);
            assert!(!d.transitive);
            assert_eq!(d.enforcement_point, EnforcementPoint::HighRiskOperation);
        }
        _ => panic!("expected denial"),
    }
}

#[test]
fn enrich_high_risk_key_revoked_transitive() {
    let mut enforcer = make_enforcer();
    let key = VerificationKey::from_bytes([50; 32]);
    let key_id = key_id_from_verification_key(&key);
    revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());
    let result = enforcer.check_high_risk_operation(
        &EngineObjectId([51; 32]),
        &key,
        HighRiskCategory::DataExport,
        "t-hr-trans",
    );
    match result {
        EnforcementResult::Denied(d) => {
            assert!(d.transitive);
            assert!(d.transitive_root.is_some());
        }
        _ => panic!("expected transitive denial"),
    }
}

// ---------------------------------------------------------------------------
// Extension activation: additional scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrich_extension_cleared() {
    let mut enforcer = make_enforcer();
    let result = enforcer.check_extension_activation(
        &EngineObjectId([60; 32]),
        &VerificationKey::from_bytes([61; 32]),
        "t-ext-ok",
    );
    assert!(result.is_cleared());
}

#[test]
fn enrich_extension_revoked_direct() {
    let mut enforcer = make_enforcer();
    revoke_target(&mut enforcer, RevocationTargetType::Extension, [70; 32]);
    let result = enforcer.check_extension_activation(
        &EngineObjectId([70; 32]),
        &VerificationKey::from_bytes([71; 32]),
        "t-ext-deny",
    );
    match result {
        EnforcementResult::Denied(d) => {
            assert_eq!(d.target_type, RevocationTargetType::Extension);
            assert!(!d.transitive);
        }
        _ => panic!("expected denial"),
    }
}

#[test]
fn enrich_extension_signing_key_revoked_transitive() {
    let mut enforcer = make_enforcer();
    let key = VerificationKey::from_bytes([80; 32]);
    let key_id = key_id_from_verification_key(&key);
    revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());
    let result =
        enforcer.check_extension_activation(&EngineObjectId([81; 32]), &key, "t-ext-trans");
    match result {
        EnforcementResult::Denied(d) => {
            assert!(d.transitive);
            assert_eq!(d.target_type, RevocationTargetType::Extension);
        }
        _ => panic!("expected transitive denial"),
    }
}

// ---------------------------------------------------------------------------
// Batch token check
// ---------------------------------------------------------------------------

#[test]
fn enrich_batch_empty_cleared() {
    let mut enforcer = make_enforcer();
    let result = enforcer.check_token_batch(&[], "t-batch");
    assert!(result.is_cleared());
}

#[test]
fn enrich_batch_all_valid() {
    let mut enforcer = make_enforcer();
    let tokens = vec![
        (
            EngineObjectId([1; 32]),
            VerificationKey::from_bytes([2; 32]),
        ),
        (
            EngineObjectId([3; 32]),
            VerificationKey::from_bytes([4; 32]),
        ),
        (
            EngineObjectId([5; 32]),
            VerificationKey::from_bytes([6; 32]),
        ),
    ];
    let result = enforcer.check_token_batch(&tokens, "t-batch-ok");
    assert!(result.is_cleared());
}

#[test]
fn enrich_batch_first_revoked() {
    let mut enforcer = make_enforcer();
    revoke_target(&mut enforcer, RevocationTargetType::Token, [1; 32]);
    let tokens = vec![
        (
            EngineObjectId([1; 32]),
            VerificationKey::from_bytes([2; 32]),
        ),
        (
            EngineObjectId([3; 32]),
            VerificationKey::from_bytes([4; 32]),
        ),
    ];
    let result = enforcer.check_token_batch(&tokens, "t-batch-deny");
    assert!(!result.is_cleared());
}

#[test]
fn enrich_batch_last_revoked() {
    let mut enforcer = make_enforcer();
    revoke_target(&mut enforcer, RevocationTargetType::Token, [3; 32]);
    let tokens = vec![
        (
            EngineObjectId([1; 32]),
            VerificationKey::from_bytes([2; 32]),
        ),
        (
            EngineObjectId([3; 32]),
            VerificationKey::from_bytes([4; 32]),
        ),
    ];
    let result = enforcer.check_token_batch(&tokens, "t-batch-deny-last");
    assert!(!result.is_cleared());
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

#[test]
fn enrich_stats_empty_initially() {
    let enforcer = make_enforcer();
    assert!(enforcer.stats().is_empty());
}

#[test]
fn enrich_stats_cleared_increments() {
    let mut enforcer = make_enforcer();
    enforcer.check_token_acceptance(
        &EngineObjectId([1; 32]),
        &VerificationKey::from_bytes([2; 32]),
        "t-1",
    );
    enforcer.check_token_acceptance(
        &EngineObjectId([3; 32]),
        &VerificationKey::from_bytes([4; 32]),
        "t-2",
    );
    let s = enforcer
        .stats()
        .get(&EnforcementPoint::TokenAcceptance)
        .unwrap();
    assert_eq!(s.cleared, 2);
    assert_eq!(s.denied, 0);
    assert_eq!(s.checks, 2);
}

#[test]
fn enrich_stats_denied_increments() {
    let mut enforcer = make_enforcer();
    revoke_target(&mut enforcer, RevocationTargetType::Token, [10; 32]);
    enforcer.check_token_acceptance(
        &EngineObjectId([10; 32]),
        &VerificationKey::from_bytes([2; 32]),
        "t-deny",
    );
    let s = enforcer
        .stats()
        .get(&EnforcementPoint::TokenAcceptance)
        .unwrap();
    assert_eq!(s.denied, 1);
    assert_eq!(s.cleared, 0);
}

#[test]
fn enrich_stats_multiple_enforcement_points() {
    let mut enforcer = make_enforcer();
    enforcer.check_token_acceptance(
        &EngineObjectId([1; 32]),
        &VerificationKey::from_bytes([2; 32]),
        "t-1",
    );
    enforcer.check_high_risk_operation(
        &EngineObjectId([3; 32]),
        &VerificationKey::from_bytes([4; 32]),
        HighRiskCategory::PolicyChange,
        "t-2",
    );
    enforcer.check_extension_activation(
        &EngineObjectId([5; 32]),
        &VerificationKey::from_bytes([6; 32]),
        "t-3",
    );
    assert_eq!(enforcer.stats().len(), 3);
}

// ---------------------------------------------------------------------------
// set_tick
// ---------------------------------------------------------------------------

#[test]
fn enrich_set_tick_affects_audit_timestamp() {
    let mut enforcer = make_enforcer();
    enforcer.set_tick(12345);
    enforcer.check_token_acceptance(
        &EngineObjectId([1; 32]),
        &VerificationKey::from_bytes([2; 32]),
        "t-tick",
    );
    let events = enforcer.drain_audit_log();
    assert!(events.iter().all(|e| e.checked_at.0 == 12345));
}

// ---------------------------------------------------------------------------
// Drain audit log
// ---------------------------------------------------------------------------

#[test]
fn enrich_drain_clears_log() {
    let mut enforcer = make_enforcer();
    enforcer.check_token_acceptance(
        &EngineObjectId([1; 32]),
        &VerificationKey::from_bytes([2; 32]),
        "t-1",
    );
    let e1 = enforcer.drain_audit_log();
    assert!(!e1.is_empty());
    let e2 = enforcer.drain_audit_log();
    assert!(e2.is_empty());
}

// ---------------------------------------------------------------------------
// Chain access
// ---------------------------------------------------------------------------

#[test]
fn enrich_chain_ref_access() {
    let enforcer = make_enforcer();
    assert!(enforcer.chain().is_empty());
    assert_eq!(enforcer.chain().zone(), ZONE);
}

#[test]
fn enrich_chain_mut_access() {
    let mut enforcer = make_enforcer();
    let chain = enforcer.chain_mut();
    assert!(chain.is_empty());
}

// ---------------------------------------------------------------------------
// EnforcementStats serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_enforcement_stats_serde() {
    let s = EnforcementStats {
        checks: 100,
        cleared: 90,
        denied: 10,
        transitive_denials: 3,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: EnforcementStats = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn enrich_enforcement_stats_default() {
    let s = EnforcementStats::default();
    assert_eq!(s.checks, 0);
    assert_eq!(s.cleared, 0);
    assert_eq!(s.denied, 0);
    assert_eq!(s.transitive_denials, 0);
}

// ---------------------------------------------------------------------------
// RevocationCheckEvent serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_revocation_check_event_serde() {
    let event = RevocationCheckEvent {
        enforcement_point: EnforcementPoint::TokenAcceptance,
        target_id: EngineObjectId([1; 32]),
        target_type: RevocationTargetType::Token,
        is_revoked: false,
        transitive: false,
        trace_id: "t-serde".to_string(),
        checked_at: DeterministicTimestamp(5000),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: RevocationCheckEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ---------------------------------------------------------------------------
// Audit event trace_id and enforcement_point correctness
// ---------------------------------------------------------------------------

#[test]
fn enrich_audit_events_have_correct_trace_id() {
    let mut enforcer = make_enforcer();
    enforcer.check_extension_activation(
        &EngineObjectId([1; 32]),
        &VerificationKey::from_bytes([2; 32]),
        "my-trace-xyz",
    );
    let events = enforcer.drain_audit_log();
    assert!(events.iter().all(|e| e.trace_id == "my-trace-xyz"));
}

#[test]
fn enrich_audit_events_have_correct_enforcement_point() {
    let mut enforcer = make_enforcer();
    enforcer.check_high_risk_operation(
        &EngineObjectId([1; 32]),
        &VerificationKey::from_bytes([2; 32]),
        HighRiskCategory::KeyOperation,
        "t-pt",
    );
    let events = enforcer.drain_audit_log();
    assert!(
        events
            .iter()
            .all(|e| e.enforcement_point == EnforcementPoint::HighRiskOperation)
    );
}
