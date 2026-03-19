//! Enrichment integration tests (batch 2) for the `revocation_enforcement` module.
//!
//! Covers enforcement lifecycle, transitive denial semantics, batch operations,
//! audit event ordering, statistics accumulation, and serde round-trips.

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
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::capability_token::PrincipalId;
use frankenengine_engine::engine_object_id::{self, EngineObjectId, ObjectDomain};
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::revocation_chain::{
    Revocation, RevocationChain, RevocationReason, RevocationTargetType, revocation_schema_id,
};
use frankenengine_engine::revocation_enforcement::{
    EnforcementPoint, EnforcementResult, EnforcementStats, HighRiskCategory, RevocationCheckEvent,
    RevocationDenial, RevocationEnforcer, key_id_from_verification_key,
};
use frankenengine_engine::signature_preimage::{
    SIGNATURE_SENTINEL, Signature, SignaturePreimage, SigningKey, VerificationKey, sign_preimage,
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const TEST_ZONE: &str = "enforcement2-zone";

fn head_signing_key() -> SigningKey {
    SigningKey::from_bytes([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    ])
}

fn revocation_key() -> SigningKey {
    SigningKey::from_bytes([
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8,
        0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
        0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8,
        0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0,
    ])
}

fn make_revocation(
    target_type: RevocationTargetType,
    reason: RevocationReason,
    target_bytes: [u8; 32],
) -> Revocation {
    let sk = revocation_key();
    let principal = PrincipalId::from_verification_key(&sk.verification_key());
    let target_id = EngineObjectId(target_bytes);
    let revocation_id = engine_object_id::derive_id(
        ObjectDomain::Revocation,
        TEST_ZONE,
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
        zone: TEST_ZONE.to_string(),
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };
    let preimage = rev.preimage_bytes();
    let sig = sign_preimage(&sk, &preimage).unwrap();
    rev.signature = sig;
    rev
}

fn make_enforcer() -> RevocationEnforcer {
    let chain = RevocationChain::new(TEST_ZONE);
    RevocationEnforcer::new(chain, 5000)
}

fn revoke_target(
    enforcer: &mut RevocationEnforcer,
    target_type: RevocationTargetType,
    target_bytes: [u8; 32],
) {
    let rev = make_revocation(target_type, RevocationReason::Compromised, target_bytes);
    let sk = head_signing_key();
    enforcer.chain_mut().append(rev, &sk, "t-revoke").unwrap();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_new_enforcer_empty_chain() {
    let enforcer = make_enforcer();
    assert!(enforcer.chain().is_empty());
    assert_eq!(enforcer.chain().zone(), TEST_ZONE);
    assert!(enforcer.stats().is_empty());
}

#[test]
fn enrichment_token_acceptance_cleared_for_valid() {
    let mut enforcer = make_enforcer();
    let result = enforcer.check_token_acceptance(
        &EngineObjectId([1; 32]),
        &VerificationKey::from_bytes([2; 32]),
        "t-clear",
    );
    assert!(result.is_cleared());
}

#[test]
fn enrichment_token_acceptance_emits_two_audit_events() {
    let mut enforcer = make_enforcer();
    enforcer.check_token_acceptance(
        &EngineObjectId([1; 32]),
        &VerificationKey::from_bytes([2; 32]),
        "t-audit",
    );
    let events = enforcer.drain_audit_log();
    assert_eq!(events.len(), 2);
    assert!(!events[0].is_revoked);
    assert!(!events[1].is_revoked);
}

#[test]
fn enrichment_token_direct_denial() {
    let mut enforcer = make_enforcer();
    revoke_target(&mut enforcer, RevocationTargetType::Token, [10; 32]);
    let result = enforcer.check_token_acceptance(
        &EngineObjectId([10; 32]),
        &VerificationKey::from_bytes([2; 32]),
        "t-deny",
    );
    match result {
        EnforcementResult::Denied(denial) => {
            assert!(!denial.transitive);
            assert_eq!(denial.target_type, RevocationTargetType::Token);
            assert_eq!(denial.enforcement_point, EnforcementPoint::TokenAcceptance);
        }
        _ => panic!("expected denial"),
    }
}

#[test]
fn enrichment_token_transitive_issuer_key_denial() {
    let mut enforcer = make_enforcer();
    let issuer_key = VerificationKey::from_bytes([20; 32]);
    let key_id = key_id_from_verification_key(&issuer_key);
    revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());
    enforcer.drain_audit_log();

    let result = enforcer.check_token_acceptance(
        &EngineObjectId([30; 32]),
        &issuer_key,
        "t-transitive",
    );
    match result {
        EnforcementResult::Denied(denial) => {
            assert!(denial.transitive);
            assert_eq!(denial.transitive_root, Some(key_id));
        }
        _ => panic!("expected transitive denial"),
    }
}

#[test]
fn enrichment_high_risk_cleared_for_valid() {
    let mut enforcer = make_enforcer();
    let result = enforcer.check_high_risk_operation(
        &EngineObjectId([40; 32]),
        &VerificationKey::from_bytes([41; 32]),
        HighRiskCategory::PolicyChange,
        "t-hr-ok",
    );
    assert!(result.is_cleared());
}

#[test]
fn enrichment_high_risk_denied_attestation_revoked() {
    let mut enforcer = make_enforcer();
    revoke_target(&mut enforcer, RevocationTargetType::Attestation, [50; 32]);
    let result = enforcer.check_high_risk_operation(
        &EngineObjectId([50; 32]),
        &VerificationKey::from_bytes([51; 32]),
        HighRiskCategory::KeyOperation,
        "t-hr-deny",
    );
    match result {
        EnforcementResult::Denied(denial) => {
            assert!(!denial.transitive);
            assert_eq!(denial.target_type, RevocationTargetType::Attestation);
        }
        _ => panic!("expected denial"),
    }
}

#[test]
fn enrichment_high_risk_transitive_key_denial() {
    let mut enforcer = make_enforcer();
    let principal_key = VerificationKey::from_bytes([60; 32]);
    let key_id = key_id_from_verification_key(&principal_key);
    revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());

    let result = enforcer.check_high_risk_operation(
        &EngineObjectId([61; 32]),
        &principal_key,
        HighRiskCategory::DataExport,
        "t-hr-trans",
    );
    match result {
        EnforcementResult::Denied(denial) => {
            assert!(denial.transitive);
            assert_eq!(denial.transitive_root, Some(key_id));
        }
        _ => panic!("expected transitive denial"),
    }
}

#[test]
fn enrichment_extension_cleared_for_valid() {
    let mut enforcer = make_enforcer();
    let result = enforcer.check_extension_activation(
        &EngineObjectId([70; 32]),
        &VerificationKey::from_bytes([71; 32]),
        "t-ext-ok",
    );
    assert!(result.is_cleared());
}

#[test]
fn enrichment_extension_direct_denial() {
    let mut enforcer = make_enforcer();
    revoke_target(&mut enforcer, RevocationTargetType::Extension, [80; 32]);
    let result = enforcer.check_extension_activation(
        &EngineObjectId([80; 32]),
        &VerificationKey::from_bytes([81; 32]),
        "t-ext-deny",
    );
    match result {
        EnforcementResult::Denied(denial) => {
            assert!(!denial.transitive);
            assert_eq!(denial.target_type, RevocationTargetType::Extension);
        }
        _ => panic!("expected denial"),
    }
}

#[test]
fn enrichment_extension_transitive_key_denial() {
    let mut enforcer = make_enforcer();
    let signing_key = VerificationKey::from_bytes([90; 32]);
    let key_id = key_id_from_verification_key(&signing_key);
    revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());

    let result = enforcer.check_extension_activation(
        &EngineObjectId([91; 32]),
        &signing_key,
        "t-ext-trans",
    );
    match result {
        EnforcementResult::Denied(denial) => {
            assert!(denial.transitive);
            assert_eq!(denial.transitive_root, Some(key_id));
        }
        _ => panic!("expected transitive denial"),
    }
}

#[test]
fn enrichment_into_result_cleared() {
    let result = EnforcementResult::Cleared {
        enforcement_point: EnforcementPoint::TokenAcceptance,
        checks_performed: 2,
    };
    assert!(result.into_result().is_ok());
}

#[test]
fn enrichment_into_result_denied() {
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Token,
        target_id: EngineObjectId([1; 32]),
        transitive: false,
        transitive_root: None,
        enforcement_point: EnforcementPoint::TokenAcceptance,
    };
    let result = EnforcementResult::Denied(denial.clone());
    assert_eq!(result.into_result().unwrap_err(), denial);
}

#[test]
fn enrichment_batch_all_valid() {
    let mut enforcer = make_enforcer();
    let tokens = vec![
        (EngineObjectId([1; 32]), VerificationKey::from_bytes([2; 32])),
        (EngineObjectId([3; 32]), VerificationKey::from_bytes([4; 32])),
    ];
    let result = enforcer.check_token_batch(&tokens, "t-batch");
    assert!(result.is_cleared());
    if let EnforcementResult::Cleared { checks_performed, .. } = result {
        assert_eq!(checks_performed, 4);
    }
}

#[test]
fn enrichment_batch_stops_at_first_denial() {
    let mut enforcer = make_enforcer();
    revoke_target(&mut enforcer, RevocationTargetType::Token, [3; 32]);
    let tokens = vec![
        (EngineObjectId([1; 32]), VerificationKey::from_bytes([2; 32])),
        (EngineObjectId([3; 32]), VerificationKey::from_bytes([4; 32])),
        (EngineObjectId([5; 32]), VerificationKey::from_bytes([6; 32])),
    ];
    let result = enforcer.check_token_batch(&tokens, "t-batch-deny");
    assert!(matches!(result, EnforcementResult::Denied(ref d) if d.target_id == EngineObjectId([3; 32])));
}

#[test]
fn enrichment_batch_empty_clears() {
    let mut enforcer = make_enforcer();
    let result = enforcer.check_token_batch(&[], "t-empty");
    assert!(result.is_cleared());
    if let EnforcementResult::Cleared { checks_performed, .. } = result {
        assert_eq!(checks_performed, 0);
    }
}

#[test]
fn enrichment_key_id_deterministic() {
    let vk = VerificationKey::from_bytes([42; 32]);
    assert_eq!(
        key_id_from_verification_key(&vk),
        key_id_from_verification_key(&vk)
    );
}

#[test]
fn enrichment_different_keys_different_ids() {
    let vk1 = VerificationKey::from_bytes([1; 32]);
    let vk2 = VerificationKey::from_bytes([2; 32]);
    assert_ne!(
        key_id_from_verification_key(&vk1),
        key_id_from_verification_key(&vk2)
    );
}

#[test]
fn enrichment_enforcement_point_display() {
    assert_eq!(EnforcementPoint::TokenAcceptance.to_string(), "token_acceptance");
    assert_eq!(EnforcementPoint::HighRiskOperation.to_string(), "high_risk_operation");
    assert_eq!(EnforcementPoint::ExtensionActivation.to_string(), "extension_activation");
}

#[test]
fn enrichment_enforcement_point_display_unique() {
    let displays: BTreeSet<String> = [
        EnforcementPoint::TokenAcceptance,
        EnforcementPoint::HighRiskOperation,
        EnforcementPoint::ExtensionActivation,
    ].iter().map(|p| p.to_string()).collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_high_risk_category_display() {
    let displays: BTreeSet<String> = [
        HighRiskCategory::PolicyChange,
        HighRiskCategory::KeyOperation,
        HighRiskCategory::DataExport,
        HighRiskCategory::CrossZoneAction,
        HighRiskCategory::ExtensionLifecycleChange,
    ].iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_denial_display_direct() {
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Token,
        target_id: EngineObjectId([1; 32]),
        transitive: false,
        transitive_root: None,
        enforcement_point: EnforcementPoint::TokenAcceptance,
    };
    let display = denial.to_string();
    assert!(display.contains("directly revoked"));
    assert!(display.contains("token_acceptance"));
}

#[test]
fn enrichment_denial_display_transitive() {
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Extension,
        target_id: EngineObjectId([2; 32]),
        transitive: true,
        transitive_root: Some(EngineObjectId([3; 32])),
        enforcement_point: EnforcementPoint::ExtensionActivation,
    };
    let display = denial.to_string();
    assert!(display.contains("transitively revoked"));
}

#[test]
fn enrichment_denial_display_transitive_without_root() {
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Key,
        target_id: EngineObjectId([12; 32]),
        transitive: true,
        transitive_root: None,
        enforcement_point: EnforcementPoint::HighRiskOperation,
    };
    assert!(denial.to_string().contains("transitively revoked via unknown"));
}

#[test]
fn enrichment_enforcement_point_serde_all() {
    for p in [EnforcementPoint::TokenAcceptance, EnforcementPoint::HighRiskOperation, EnforcementPoint::ExtensionActivation] {
        let json = serde_json::to_string(&p).unwrap();
        let back: EnforcementPoint = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }
}

#[test]
fn enrichment_high_risk_category_serde_all() {
    for c in [HighRiskCategory::PolicyChange, HighRiskCategory::KeyOperation, HighRiskCategory::DataExport, HighRiskCategory::CrossZoneAction, HighRiskCategory::ExtensionLifecycleChange] {
        let json = serde_json::to_string(&c).unwrap();
        let back: HighRiskCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }
}

#[test]
fn enrichment_denial_serde_round_trip() {
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Token,
        target_id: EngineObjectId([1; 32]),
        transitive: true,
        transitive_root: Some(EngineObjectId([2; 32])),
        enforcement_point: EnforcementPoint::TokenAcceptance,
    };
    let json = serde_json::to_string(&denial).unwrap();
    let back: RevocationDenial = serde_json::from_str(&json).unwrap();
    assert_eq!(denial, back);
}

#[test]
fn enrichment_enforcement_result_serde() {
    let cleared = EnforcementResult::Cleared {
        enforcement_point: EnforcementPoint::TokenAcceptance,
        checks_performed: 2,
    };
    let json = serde_json::to_string(&cleared).unwrap();
    let back: EnforcementResult = serde_json::from_str(&json).unwrap();
    assert_eq!(cleared, back);
}

#[test]
fn enrichment_check_event_serde() {
    let event = RevocationCheckEvent {
        enforcement_point: EnforcementPoint::HighRiskOperation,
        target_id: EngineObjectId([5; 32]),
        target_type: RevocationTargetType::Attestation,
        is_revoked: true,
        transitive: false,
        trace_id: "t-ser".to_string(),
        checked_at: DeterministicTimestamp(5000),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: RevocationCheckEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn enrichment_stats_serde() {
    let stats = EnforcementStats {
        checks: 10,
        cleared: 8,
        denied: 2,
        transitive_denials: 1,
    };
    let json = serde_json::to_string(&stats).unwrap();
    let back: EnforcementStats = serde_json::from_str(&json).unwrap();
    assert_eq!(stats, back);
}

#[test]
fn enrichment_stats_default() {
    let stats = EnforcementStats::default();
    assert_eq!(stats.checks, 0);
    assert_eq!(stats.cleared, 0);
    assert_eq!(stats.denied, 0);
    assert_eq!(stats.transitive_denials, 0);
}

#[test]
fn enrichment_stats_across_all_points() {
    let mut enforcer = make_enforcer();
    enforcer.check_token_acceptance(&EngineObjectId([1; 32]), &VerificationKey::from_bytes([2; 32]), "t1");
    enforcer.check_high_risk_operation(&EngineObjectId([3; 32]), &VerificationKey::from_bytes([4; 32]), HighRiskCategory::PolicyChange, "t2");
    enforcer.check_extension_activation(&EngineObjectId([5; 32]), &VerificationKey::from_bytes([6; 32]), "t3");
    let stats = enforcer.stats();
    assert_eq!(stats.len(), 3);
    for s in stats.values() {
        assert_eq!(s.checks, 1);
        assert_eq!(s.cleared, 1);
    }
}

#[test]
fn enrichment_set_tick_updates_timestamps() {
    let mut enforcer = make_enforcer();
    enforcer.set_tick(1000);
    enforcer.check_token_acceptance(&EngineObjectId([1; 32]), &VerificationKey::from_bytes([2; 32]), "t1");
    enforcer.set_tick(2000);
    enforcer.check_token_acceptance(&EngineObjectId([3; 32]), &VerificationKey::from_bytes([4; 32]), "t2");
    let events = enforcer.drain_audit_log();
    assert_eq!(events[0].checked_at, DeterministicTimestamp(1000));
    assert_eq!(events[2].checked_at, DeterministicTimestamp(2000));
}

#[test]
fn enrichment_drain_audit_log_idempotent() {
    let mut enforcer = make_enforcer();
    enforcer.check_token_acceptance(&EngineObjectId([1; 32]), &VerificationKey::from_bytes([2; 32]), "t");
    assert!(!enforcer.drain_audit_log().is_empty());
    assert!(enforcer.drain_audit_log().is_empty());
    assert!(enforcer.drain_audit_log().is_empty());
}

#[test]
fn enrichment_audit_ordering_matches_call_order() {
    let mut enforcer = make_enforcer();
    enforcer.check_token_acceptance(&EngineObjectId([1; 32]), &VerificationKey::from_bytes([2; 32]), "trace-A");
    enforcer.check_high_risk_operation(&EngineObjectId([3; 32]), &VerificationKey::from_bytes([4; 32]), HighRiskCategory::PolicyChange, "trace-B");
    let events = enforcer.drain_audit_log();
    assert_eq!(events[0].trace_id, "trace-A");
    assert_eq!(events[1].trace_id, "trace-A");
    assert_eq!(events[2].trace_id, "trace-B");
    assert_eq!(events[3].trace_id, "trace-B");
}

#[test]
fn enrichment_direct_beats_transitive_when_both_revoked() {
    let mut enforcer = make_enforcer();
    let issuer_key = VerificationKey::from_bytes([20; 32]);
    let key_id = key_id_from_verification_key(&issuer_key);
    revoke_target(&mut enforcer, RevocationTargetType::Token, [10; 32]);
    revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());
    enforcer.drain_audit_log();

    let result = enforcer.check_token_acceptance(&EngineObjectId([10; 32]), &issuer_key, "t");
    match result {
        EnforcementResult::Denied(denial) => {
            assert!(!denial.transitive);
        }
        _ => panic!("expected direct denial"),
    }
}

#[test]
fn enrichment_all_high_risk_categories_accepted() {
    let mut enforcer = make_enforcer();
    for (i, cat) in [
        HighRiskCategory::PolicyChange, HighRiskCategory::KeyOperation,
        HighRiskCategory::DataExport, HighRiskCategory::CrossZoneAction,
        HighRiskCategory::ExtensionLifecycleChange,
    ].iter().enumerate() {
        let result = enforcer.check_high_risk_operation(
            &EngineObjectId([(i as u8) + 100; 32]),
            &VerificationKey::from_bytes([(i as u8) + 200; 32]),
            *cat,
            &format!("t-{i}"),
        );
        assert!(result.is_cleared());
    }
}

#[test]
fn enrichment_denial_implements_error_trait() {
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Token,
        target_id: EngineObjectId([1; 32]),
        transitive: false,
        transitive_root: None,
        enforcement_point: EnforcementPoint::TokenAcceptance,
    };
    let err: &dyn std::error::Error = &denial;
    assert!(err.source().is_none());
    assert!(err.to_string().contains("directly revoked"));
}

#[test]
fn enrichment_enforcement_is_deterministic() {
    let run = || {
        let mut enforcer = make_enforcer();
        revoke_target(&mut enforcer, RevocationTargetType::Token, [10; 32]);
        enforcer.drain_audit_log();
        let r1 = enforcer.check_token_acceptance(
            &EngineObjectId([10; 32]),
            &VerificationKey::from_bytes([11; 32]),
            "t",
        );
        let r2 = enforcer.check_token_acceptance(
            &EngineObjectId([20; 32]),
            &VerificationKey::from_bytes([21; 32]),
            "t",
        );
        let events = enforcer.drain_audit_log();
        (r1, r2, events)
    };
    let (r1a, r2a, e_a) = run();
    let (r1b, r2b, e_b) = run();
    assert_eq!(r1a, r1b);
    assert_eq!(r2a, r2b);
    assert_eq!(e_a, e_b);
}

#[test]
fn enrichment_key_id_from_all_zeros() {
    let vk = VerificationKey::from_bytes([0; 32]);
    let id = key_id_from_verification_key(&vk);
    assert_eq!(id.as_bytes().len(), 32);
    assert_eq!(id, key_id_from_verification_key(&vk));
}

#[test]
fn enrichment_cleared_checks_performed_is_two() {
    let mut enforcer = make_enforcer();
    let r1 = enforcer.check_token_acceptance(&EngineObjectId([1; 32]), &VerificationKey::from_bytes([2; 32]), "t1");
    let r2 = enforcer.check_high_risk_operation(&EngineObjectId([3; 32]), &VerificationKey::from_bytes([4; 32]), HighRiskCategory::PolicyChange, "t2");
    let r3 = enforcer.check_extension_activation(&EngineObjectId([5; 32]), &VerificationKey::from_bytes([6; 32]), "t3");
    for r in [r1, r2, r3] {
        if let EnforcementResult::Cleared { checks_performed, .. } = r {
            assert_eq!(checks_performed, 2);
        } else {
            panic!("expected cleared");
        }
    }
}
