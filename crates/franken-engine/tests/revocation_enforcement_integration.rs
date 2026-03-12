#![allow(
    clippy::too_many_arguments,
    clippy::clone_on_copy,
    clippy::len_zero,
    clippy::identity_op
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

const ZONE: &str = "test-zone";

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

// ── EnforcementPoint display ─────────────────────────────────────────────

#[test]
fn enforcement_point_display_token_acceptance() {
    assert_eq!(
        EnforcementPoint::TokenAcceptance.to_string(),
        "token_acceptance"
    );
}

#[test]
fn enforcement_point_display_high_risk_operation() {
    assert_eq!(
        EnforcementPoint::HighRiskOperation.to_string(),
        "high_risk_operation"
    );
}

#[test]
fn enforcement_point_display_extension_activation() {
    assert_eq!(
        EnforcementPoint::ExtensionActivation.to_string(),
        "extension_activation"
    );
}

// ── HighRiskCategory display ─────────────────────────────────────────────

#[test]
fn high_risk_category_display_policy_change() {
    assert_eq!(HighRiskCategory::PolicyChange.to_string(), "policy_change");
}

#[test]
fn high_risk_category_display_key_operation() {
    assert_eq!(HighRiskCategory::KeyOperation.to_string(), "key_operation");
}

#[test]
fn high_risk_category_display_data_export() {
    assert_eq!(HighRiskCategory::DataExport.to_string(), "data_export");
}

#[test]
fn high_risk_category_display_cross_zone_action() {
    assert_eq!(
        HighRiskCategory::CrossZoneAction.to_string(),
        "cross_zone_action"
    );
}

#[test]
fn high_risk_category_display_extension_lifecycle() {
    assert_eq!(
        HighRiskCategory::ExtensionLifecycleChange.to_string(),
        "extension_lifecycle_change"
    );
}

// ── key_id_from_verification_key ─────────────────────────────────────────

#[test]
fn key_id_is_deterministic() {
    let vk = VerificationKey::from_bytes([5; 32]);
    let id1 = key_id_from_verification_key(&vk);
    let id2 = key_id_from_verification_key(&vk);
    assert_eq!(id1, id2);
}

#[test]
fn key_id_differs_for_different_keys() {
    let vk1 = VerificationKey::from_bytes([1; 32]);
    let vk2 = VerificationKey::from_bytes([2; 32]);
    let id1 = key_id_from_verification_key(&vk1);
    let id2 = key_id_from_verification_key(&vk2);
    assert_ne!(id1, id2);
}

// ── EnforcementResult ─────────────────────────────────────────────────────

#[test]
fn cleared_result_is_cleared() {
    let r = EnforcementResult::Cleared {
        enforcement_point: EnforcementPoint::TokenAcceptance,
        checks_performed: 2,
    };
    assert!(r.is_cleared());
}

#[test]
fn denied_result_is_not_cleared() {
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Token,
        target_id: EngineObjectId([1; 32]),
        transitive: false,
        transitive_root: None,
        enforcement_point: EnforcementPoint::TokenAcceptance,
    };
    let r = EnforcementResult::Denied(denial);
    assert!(!r.is_cleared());
}

#[test]
fn cleared_into_result_is_ok() {
    let r = EnforcementResult::Cleared {
        enforcement_point: EnforcementPoint::TokenAcceptance,
        checks_performed: 1,
    };
    assert!(r.into_result().is_ok());
}

#[test]
fn denied_into_result_is_err() {
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Token,
        target_id: EngineObjectId([1; 32]),
        transitive: false,
        transitive_root: None,
        enforcement_point: EnforcementPoint::TokenAcceptance,
    };
    let r = EnforcementResult::Denied(denial);
    assert!(r.into_result().is_err());
}

// ── RevocationDenial display ──────────────────────────────────────────────

#[test]
fn revocation_denial_display_direct() {
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Token,
        target_id: EngineObjectId([1; 32]),
        transitive: false,
        transitive_root: None,
        enforcement_point: EnforcementPoint::TokenAcceptance,
    };
    let s = denial.to_string();
    assert!(s.contains("token_acceptance"));
    assert!(s.contains("directly revoked"));
}

#[test]
fn revocation_denial_display_transitive() {
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Token,
        target_id: EngineObjectId([1; 32]),
        transitive: true,
        transitive_root: Some(EngineObjectId([2; 32])),
        enforcement_point: EnforcementPoint::TokenAcceptance,
    };
    let s = denial.to_string();
    assert!(s.contains("transitively revoked"));
}

#[test]
fn revocation_denial_display_transitive_no_root() {
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Token,
        target_id: EngineObjectId([1; 32]),
        transitive: true,
        transitive_root: None,
        enforcement_point: EnforcementPoint::TokenAcceptance,
    };
    let s = denial.to_string();
    assert!(s.contains("unknown"));
}

// ── Token acceptance checks ───────────────────────────────────────────────

#[test]
fn token_acceptance_cleared_for_valid_token() {
    let mut enforcer = make_enforcer();
    let token_jti = EngineObjectId([1; 32]);
    let issuer_key = VerificationKey::from_bytes([2; 32]);
    let result = enforcer.check_token_acceptance(&token_jti, &issuer_key, "t-1");
    assert!(result.is_cleared());
}

#[test]
fn token_acceptance_emits_two_audit_events_on_clear() {
    let mut enforcer = make_enforcer();
    let token_jti = EngineObjectId([1; 32]);
    let issuer_key = VerificationKey::from_bytes([2; 32]);
    enforcer.check_token_acceptance(&token_jti, &issuer_key, "t-1");
    let events = enforcer.drain_audit_log();
    assert_eq!(events.len(), 2);
}

#[test]
fn token_acceptance_denied_for_revoked_token() {
    let mut enforcer = make_enforcer();
    let token_jti = EngineObjectId([10; 32]);
    revoke_target(&mut enforcer, RevocationTargetType::Token, [10; 32]);
    let issuer_key = VerificationKey::from_bytes([2; 32]);
    let result = enforcer.check_token_acceptance(&token_jti, &issuer_key, "t-deny");
    assert!(!result.is_cleared());
}

#[test]
fn token_acceptance_denial_is_direct_for_revoked_token() {
    let mut enforcer = make_enforcer();
    let token_jti = EngineObjectId([10; 32]);
    revoke_target(&mut enforcer, RevocationTargetType::Token, [10; 32]);
    let issuer_key = VerificationKey::from_bytes([2; 32]);
    match enforcer.check_token_acceptance(&token_jti, &issuer_key, "t-deny") {
        EnforcementResult::Denied(d) => {
            assert!(!d.transitive);
            assert!(d.transitive_root.is_none());
            assert_eq!(d.target_type, RevocationTargetType::Token);
            assert_eq!(d.enforcement_point, EnforcementPoint::TokenAcceptance);
        }
        _ => panic!("expected denial"),
    }
}

#[test]
fn token_acceptance_denied_emits_one_audit_event() {
    let mut enforcer = make_enforcer();
    let token_jti = EngineObjectId([10; 32]);
    revoke_target(&mut enforcer, RevocationTargetType::Token, [10; 32]);
    enforcer.drain_audit_log();
    let issuer_key = VerificationKey::from_bytes([2; 32]);
    enforcer.check_token_acceptance(&token_jti, &issuer_key, "t-deny");
    let events = enforcer.drain_audit_log();
    assert_eq!(events.len(), 1);
    assert!(events[0].is_revoked);
}

#[test]
fn token_acceptance_transitive_denial_for_revoked_issuer_key() {
    let mut enforcer = make_enforcer();
    let issuer_key = VerificationKey::from_bytes([20; 32]);
    let issuer_key_id = key_id_from_verification_key(&issuer_key);
    revoke_target(
        &mut enforcer,
        RevocationTargetType::Key,
        *issuer_key_id.as_bytes(),
    );
    let token_jti = EngineObjectId([5; 32]);
    match enforcer.check_token_acceptance(&token_jti, &issuer_key, "t-transitive") {
        EnforcementResult::Denied(d) => {
            assert!(d.transitive);
            assert!(d.transitive_root.is_some());
            assert_eq!(d.transitive_root.unwrap(), issuer_key_id);
        }
        _ => panic!("expected transitive denial"),
    }
}

// ── High-risk operation checks ────────────────────────────────────────────

#[test]
fn high_risk_operation_cleared_for_valid_attestation() {
    let mut enforcer = make_enforcer();
    let attestation_id = EngineObjectId([3; 32]);
    let principal_key = VerificationKey::from_bytes([4; 32]);
    let result = enforcer.check_high_risk_operation(
        &attestation_id,
        &principal_key,
        HighRiskCategory::PolicyChange,
        "t-hr",
    );
    assert!(result.is_cleared());
}

#[test]
fn high_risk_operation_denied_for_revoked_attestation() {
    let mut enforcer = make_enforcer();
    let attestation_id = EngineObjectId([3; 32]);
    revoke_target(&mut enforcer, RevocationTargetType::Attestation, [3; 32]);
    let principal_key = VerificationKey::from_bytes([4; 32]);
    let result = enforcer.check_high_risk_operation(
        &attestation_id,
        &principal_key,
        HighRiskCategory::KeyOperation,
        "t-hr-deny",
    );
    assert!(!result.is_cleared());
}

#[test]
fn high_risk_operation_denial_is_attestation_type() {
    let mut enforcer = make_enforcer();
    let attestation_id = EngineObjectId([3; 32]);
    revoke_target(&mut enforcer, RevocationTargetType::Attestation, [3; 32]);
    let principal_key = VerificationKey::from_bytes([4; 32]);
    match enforcer.check_high_risk_operation(
        &attestation_id,
        &principal_key,
        HighRiskCategory::DataExport,
        "t-hr-deny",
    ) {
        EnforcementResult::Denied(d) => {
            assert_eq!(d.target_type, RevocationTargetType::Attestation);
            assert_eq!(d.enforcement_point, EnforcementPoint::HighRiskOperation);
            assert!(!d.transitive);
        }
        _ => panic!("expected denial"),
    }
}

#[test]
fn high_risk_operation_transitive_denial_for_revoked_key() {
    let mut enforcer = make_enforcer();
    let principal_key = VerificationKey::from_bytes([4; 32]);
    let key_id = key_id_from_verification_key(&principal_key);
    revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());
    let attestation_id = EngineObjectId([9; 32]);
    match enforcer.check_high_risk_operation(
        &attestation_id,
        &principal_key,
        HighRiskCategory::CrossZoneAction,
        "t-transitive-hr",
    ) {
        EnforcementResult::Denied(d) => {
            assert!(d.transitive);
            assert!(d.transitive_root.is_some());
        }
        _ => panic!("expected transitive denial"),
    }
}

// ── Extension activation checks ───────────────────────────────────────────

#[test]
fn extension_activation_cleared_for_valid_extension() {
    let mut enforcer = make_enforcer();
    let ext_id = EngineObjectId([6; 32]);
    let signing_key = VerificationKey::from_bytes([7; 32]);
    let result = enforcer.check_extension_activation(&ext_id, &signing_key, "t-ext");
    assert!(result.is_cleared());
}

#[test]
fn extension_activation_denied_for_revoked_extension() {
    let mut enforcer = make_enforcer();
    let ext_id = EngineObjectId([6; 32]);
    revoke_target(&mut enforcer, RevocationTargetType::Extension, [6; 32]);
    let signing_key = VerificationKey::from_bytes([7; 32]);
    let result = enforcer.check_extension_activation(&ext_id, &signing_key, "t-ext-deny");
    assert!(!result.is_cleared());
}

#[test]
fn extension_activation_denial_is_extension_type() {
    let mut enforcer = make_enforcer();
    let ext_id = EngineObjectId([6; 32]);
    revoke_target(&mut enforcer, RevocationTargetType::Extension, [6; 32]);
    let signing_key = VerificationKey::from_bytes([7; 32]);
    match enforcer.check_extension_activation(&ext_id, &signing_key, "t-ext-deny") {
        EnforcementResult::Denied(d) => {
            assert_eq!(d.target_type, RevocationTargetType::Extension);
            assert_eq!(d.enforcement_point, EnforcementPoint::ExtensionActivation);
            assert!(!d.transitive);
        }
        _ => panic!("expected denial"),
    }
}

#[test]
fn extension_activation_transitive_denial_for_revoked_signing_key() {
    let mut enforcer = make_enforcer();
    let signing_key = VerificationKey::from_bytes([7; 32]);
    let key_id = key_id_from_verification_key(&signing_key);
    revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());
    let ext_id = EngineObjectId([8; 32]);
    match enforcer.check_extension_activation(&ext_id, &signing_key, "t-ext-transitive") {
        EnforcementResult::Denied(d) => {
            assert!(d.transitive);
            assert_eq!(d.target_type, RevocationTargetType::Extension);
        }
        _ => panic!("expected transitive denial"),
    }
}

// ── Batch token check ─────────────────────────────────────────────────────

#[test]
fn batch_token_check_cleared_for_empty_batch() {
    let mut enforcer = make_enforcer();
    let result = enforcer.check_token_batch(&[], "t-batch");
    assert!(result.is_cleared());
}

#[test]
fn batch_token_check_cleared_for_valid_tokens() {
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
    ];
    let result = enforcer.check_token_batch(&tokens, "t-batch");
    assert!(result.is_cleared());
}

#[test]
fn batch_token_check_denied_if_any_revoked() {
    let mut enforcer = make_enforcer();
    revoke_target(&mut enforcer, RevocationTargetType::Token, [5; 32]);
    let tokens = vec![
        (
            EngineObjectId([1; 32]),
            VerificationKey::from_bytes([2; 32]),
        ),
        (
            EngineObjectId([5; 32]),
            VerificationKey::from_bytes([4; 32]),
        ),
    ];
    let result = enforcer.check_token_batch(&tokens, "t-batch-deny");
    assert!(!result.is_cleared());
}

// ── Statistics ────────────────────────────────────────────────────────────

#[test]
fn stats_initially_empty() {
    let enforcer = make_enforcer();
    assert!(enforcer.stats().is_empty());
}

#[test]
fn stats_incremented_on_token_acceptance_clear() {
    let mut enforcer = make_enforcer();
    let token_jti = EngineObjectId([1; 32]);
    let issuer_key = VerificationKey::from_bytes([2; 32]);
    enforcer.check_token_acceptance(&token_jti, &issuer_key, "t-1");
    let stats = enforcer.stats();
    let s = stats.get(&EnforcementPoint::TokenAcceptance).unwrap();
    assert_eq!(s.cleared, 1);
    assert_eq!(s.denied, 0);
}

#[test]
fn stats_incremented_on_token_acceptance_denial() {
    let mut enforcer = make_enforcer();
    let token_jti = EngineObjectId([10; 32]);
    revoke_target(&mut enforcer, RevocationTargetType::Token, [10; 32]);
    let issuer_key = VerificationKey::from_bytes([2; 32]);
    enforcer.check_token_acceptance(&token_jti, &issuer_key, "t-deny");
    let stats = enforcer.stats();
    let s = stats.get(&EnforcementPoint::TokenAcceptance).unwrap();
    assert_eq!(s.denied, 1);
    assert_eq!(s.cleared, 0);
}

#[test]
fn stats_transitive_denial_counted() {
    let mut enforcer = make_enforcer();
    let issuer_key = VerificationKey::from_bytes([20; 32]);
    let issuer_key_id = key_id_from_verification_key(&issuer_key);
    revoke_target(
        &mut enforcer,
        RevocationTargetType::Key,
        *issuer_key_id.as_bytes(),
    );
    let token_jti = EngineObjectId([5; 32]);
    enforcer.check_token_acceptance(&token_jti, &issuer_key, "t-transitive");
    let stats = enforcer.stats();
    let s = stats.get(&EnforcementPoint::TokenAcceptance).unwrap();
    assert_eq!(s.transitive_denials, 1);
}

// ── set_tick ──────────────────────────────────────────────────────────────

#[test]
fn set_tick_updates_tick() {
    let mut enforcer = make_enforcer();
    enforcer.set_tick(9999);
    // tick is used internally in audit events; just check it doesn't panic
    let token_jti = EngineObjectId([1; 32]);
    let issuer_key = VerificationKey::from_bytes([2; 32]);
    enforcer.check_token_acceptance(&token_jti, &issuer_key, "t-tick");
    let events = enforcer.drain_audit_log();
    assert!(!events.is_empty());
    assert_eq!(events[0].checked_at.0, 9999);
}

// ── drain_audit_log clears ────────────────────────────────────────────────

#[test]
fn drain_audit_log_clears_after_drain() {
    let mut enforcer = make_enforcer();
    let token_jti = EngineObjectId([1; 32]);
    let issuer_key = VerificationKey::from_bytes([2; 32]);
    enforcer.check_token_acceptance(&token_jti, &issuer_key, "t-1");
    let events = enforcer.drain_audit_log();
    assert!(!events.is_empty());
    let events2 = enforcer.drain_audit_log();
    assert!(events2.is_empty());
}

// ── chain access ──────────────────────────────────────────────────────────

#[test]
fn enforcer_chain_access_works() {
    let enforcer = make_enforcer();
    assert!(enforcer.chain().is_empty());
    assert_eq!(enforcer.chain().zone(), ZONE);
}

// ── Serde roundtrip ───────────────────────────────────────────────────────

#[test]
fn enforcement_point_serde_roundtrip() {
    for ep in [
        EnforcementPoint::TokenAcceptance,
        EnforcementPoint::HighRiskOperation,
        EnforcementPoint::ExtensionActivation,
    ] {
        let json = serde_json::to_string(&ep).unwrap();
        let decoded: EnforcementPoint = serde_json::from_str(&json).unwrap();
        assert_eq!(ep, decoded);
    }
}

#[test]
fn high_risk_category_serde_roundtrip() {
    for cat in [
        HighRiskCategory::PolicyChange,
        HighRiskCategory::KeyOperation,
        HighRiskCategory::DataExport,
        HighRiskCategory::CrossZoneAction,
        HighRiskCategory::ExtensionLifecycleChange,
    ] {
        let json = serde_json::to_string(&cat).unwrap();
        let decoded: HighRiskCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(cat, decoded);
    }
}

#[test]
fn enforcement_stats_default() {
    let s = EnforcementStats::default();
    assert_eq!(s.checks, 0);
    assert_eq!(s.cleared, 0);
    assert_eq!(s.denied, 0);
    assert_eq!(s.transitive_denials, 0);
}

#[test]
fn enforcement_stats_serde_roundtrip() {
    let s = EnforcementStats {
        checks: 10,
        cleared: 8,
        denied: 2,
        transitive_denials: 1,
    };
    let json = serde_json::to_string(&s).unwrap();
    let decoded: EnforcementStats = serde_json::from_str(&json).unwrap();
    assert_eq!(s, decoded);
}

// ── RevocationCheckEvent ──────────────────────────────────────────────────

#[test]
fn audit_events_contain_correct_trace_id() {
    let mut enforcer = make_enforcer();
    let token_jti = EngineObjectId([1; 32]);
    let issuer_key = VerificationKey::from_bytes([2; 32]);
    enforcer.check_token_acceptance(&token_jti, &issuer_key, "trace-abc");
    let events = enforcer.drain_audit_log();
    assert!(events.iter().all(|e| e.trace_id == "trace-abc"));
}

#[test]
fn audit_events_contain_correct_enforcement_point() {
    let mut enforcer = make_enforcer();
    let ext_id = EngineObjectId([6; 32]);
    let signing_key = VerificationKey::from_bytes([7; 32]);
    enforcer.check_extension_activation(&ext_id, &signing_key, "trace-ext");
    let events = enforcer.drain_audit_log();
    assert!(
        events
            .iter()
            .all(|e| e.enforcement_point == EnforcementPoint::ExtensionActivation)
    );
}

#[test]
fn multiple_checks_accumulate_audit_events() {
    let mut enforcer = make_enforcer();
    let vk = VerificationKey::from_bytes([2; 32]);
    enforcer.check_token_acceptance(&EngineObjectId([1; 32]), &vk, "t1");
    enforcer.check_token_acceptance(&EngineObjectId([2; 32]), &vk, "t2");
    let events = enforcer.drain_audit_log();
    assert_eq!(events.len(), 4); // 2 checks per call
}

// ============================================================================
// Enrichment tests — ~90 new tests
// ============================================================================

// ── EnforcementPoint: Debug, Clone, PartialEq, serde ────────────────────

#[test]
fn enrichment_enforcement_point_debug_token_acceptance() {
    let ep = EnforcementPoint::TokenAcceptance;
    let dbg = format!("{:?}", ep);
    assert_eq!(dbg, "TokenAcceptance");
}

#[test]
fn enrichment_enforcement_point_debug_high_risk_operation() {
    let ep = EnforcementPoint::HighRiskOperation;
    let dbg = format!("{:?}", ep);
    assert_eq!(dbg, "HighRiskOperation");
}

#[test]
fn enrichment_enforcement_point_debug_extension_activation() {
    let ep = EnforcementPoint::ExtensionActivation;
    let dbg = format!("{:?}", ep);
    assert_eq!(dbg, "ExtensionActivation");
}

#[test]
fn enrichment_enforcement_point_clone_eq() {
    let ep = EnforcementPoint::HighRiskOperation;
    let cloned = ep.clone();
    assert_eq!(ep, cloned);
}

#[test]
fn enrichment_enforcement_point_ne_variants() {
    assert_ne!(
        EnforcementPoint::TokenAcceptance,
        EnforcementPoint::HighRiskOperation
    );
    assert_ne!(
        EnforcementPoint::HighRiskOperation,
        EnforcementPoint::ExtensionActivation
    );
    assert_ne!(
        EnforcementPoint::TokenAcceptance,
        EnforcementPoint::ExtensionActivation
    );
}

#[test]
fn enrichment_enforcement_point_json_field_stability() {
    let ep = EnforcementPoint::TokenAcceptance;
    let json = serde_json::to_string(&ep).unwrap();
    // Serde enum representation is a string literal
    assert!(json.contains("TokenAcceptance") || json.contains("token_acceptance"));
    // Roundtrip is stable
    let decoded: EnforcementPoint = serde_json::from_str(&json).unwrap();
    assert_eq!(ep, decoded);
}

#[test]
fn enrichment_enforcement_point_ord_total() {
    let mut variants = vec![
        EnforcementPoint::ExtensionActivation,
        EnforcementPoint::TokenAcceptance,
        EnforcementPoint::HighRiskOperation,
    ];
    variants.sort();
    assert_eq!(variants[0], EnforcementPoint::TokenAcceptance);
    assert_eq!(variants[1], EnforcementPoint::HighRiskOperation);
    assert_eq!(variants[2], EnforcementPoint::ExtensionActivation);
}

// ── HighRiskCategory: Debug, Clone, PartialEq, serde ────────────────────

#[test]
fn enrichment_high_risk_category_debug_all() {
    assert_eq!(
        format!("{:?}", HighRiskCategory::PolicyChange),
        "PolicyChange"
    );
    assert_eq!(
        format!("{:?}", HighRiskCategory::KeyOperation),
        "KeyOperation"
    );
    assert_eq!(format!("{:?}", HighRiskCategory::DataExport), "DataExport");
    assert_eq!(
        format!("{:?}", HighRiskCategory::CrossZoneAction),
        "CrossZoneAction"
    );
    assert_eq!(
        format!("{:?}", HighRiskCategory::ExtensionLifecycleChange),
        "ExtensionLifecycleChange"
    );
}

#[test]
fn enrichment_high_risk_category_clone_eq() {
    let cat = HighRiskCategory::DataExport;
    let cloned = cat.clone();
    assert_eq!(cat, cloned);
}

#[test]
fn enrichment_high_risk_category_ne_all_pairs() {
    let all = [
        HighRiskCategory::PolicyChange,
        HighRiskCategory::KeyOperation,
        HighRiskCategory::DataExport,
        HighRiskCategory::CrossZoneAction,
        HighRiskCategory::ExtensionLifecycleChange,
    ];
    for i in 0..all.len() {
        for j in (i + 1)..all.len() {
            assert_ne!(all[i], all[j], "variants {i} and {j} should differ");
        }
    }
}

#[test]
fn enrichment_high_risk_category_ord_total() {
    let mut variants = vec![
        HighRiskCategory::ExtensionLifecycleChange,
        HighRiskCategory::PolicyChange,
        HighRiskCategory::CrossZoneAction,
        HighRiskCategory::DataExport,
        HighRiskCategory::KeyOperation,
    ];
    variants.sort();
    assert_eq!(variants[0], HighRiskCategory::PolicyChange);
    assert_eq!(variants[4], HighRiskCategory::ExtensionLifecycleChange);
}

#[test]
fn enrichment_high_risk_category_json_roundtrip_all() {
    let all = [
        HighRiskCategory::PolicyChange,
        HighRiskCategory::KeyOperation,
        HighRiskCategory::DataExport,
        HighRiskCategory::CrossZoneAction,
        HighRiskCategory::ExtensionLifecycleChange,
    ];
    for cat in &all {
        let json = serde_json::to_string(cat).unwrap();
        let decoded: HighRiskCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*cat, decoded);
    }
}

// ── RevocationDenial: Debug, Clone, PartialEq, serde ────────────────────

#[test]
fn enrichment_revocation_denial_debug_format() {
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Token,
        target_id: EngineObjectId([1; 32]),
        transitive: false,
        transitive_root: None,
        enforcement_point: EnforcementPoint::TokenAcceptance,
    };
    let dbg = format!("{:?}", denial);
    assert!(dbg.contains("RevocationDenial"));
    assert!(dbg.contains("Token"));
}

#[test]
fn enrichment_revocation_denial_clone_eq() {
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Attestation,
        target_id: EngineObjectId([5; 32]),
        transitive: true,
        transitive_root: Some(EngineObjectId([6; 32])),
        enforcement_point: EnforcementPoint::HighRiskOperation,
    };
    let cloned = denial.clone();
    assert_eq!(denial, cloned);
}

#[test]
fn enrichment_revocation_denial_ne_different_target_type() {
    let d1 = RevocationDenial {
        target_type: RevocationTargetType::Token,
        target_id: EngineObjectId([1; 32]),
        transitive: false,
        transitive_root: None,
        enforcement_point: EnforcementPoint::TokenAcceptance,
    };
    let d2 = RevocationDenial {
        target_type: RevocationTargetType::Extension,
        target_id: EngineObjectId([1; 32]),
        transitive: false,
        transitive_root: None,
        enforcement_point: EnforcementPoint::TokenAcceptance,
    };
    assert_ne!(d1, d2);
}

#[test]
fn enrichment_revocation_denial_ne_different_transitive() {
    let d1 = RevocationDenial {
        target_type: RevocationTargetType::Token,
        target_id: EngineObjectId([1; 32]),
        transitive: false,
        transitive_root: None,
        enforcement_point: EnforcementPoint::TokenAcceptance,
    };
    let d2 = RevocationDenial {
        target_type: RevocationTargetType::Token,
        target_id: EngineObjectId([1; 32]),
        transitive: true,
        transitive_root: None,
        enforcement_point: EnforcementPoint::TokenAcceptance,
    };
    assert_ne!(d1, d2);
}

#[test]
fn enrichment_revocation_denial_serde_roundtrip_direct() {
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Token,
        target_id: EngineObjectId([7; 32]),
        transitive: false,
        transitive_root: None,
        enforcement_point: EnforcementPoint::TokenAcceptance,
    };
    let json = serde_json::to_string(&denial).unwrap();
    let decoded: RevocationDenial = serde_json::from_str(&json).unwrap();
    assert_eq!(denial, decoded);
}

#[test]
fn enrichment_revocation_denial_serde_roundtrip_transitive() {
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Extension,
        target_id: EngineObjectId([8; 32]),
        transitive: true,
        transitive_root: Some(EngineObjectId([9; 32])),
        enforcement_point: EnforcementPoint::ExtensionActivation,
    };
    let json = serde_json::to_string(&denial).unwrap();
    let decoded: RevocationDenial = serde_json::from_str(&json).unwrap();
    assert_eq!(denial, decoded);
}

#[test]
fn enrichment_revocation_denial_json_field_names_stable() {
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Token,
        target_id: EngineObjectId([1; 32]),
        transitive: false,
        transitive_root: None,
        enforcement_point: EnforcementPoint::TokenAcceptance,
    };
    let json = serde_json::to_string(&denial).unwrap();
    assert!(json.contains("\"target_type\""));
    assert!(json.contains("\"target_id\""));
    assert!(json.contains("\"transitive\""));
    assert!(json.contains("\"transitive_root\""));
    assert!(json.contains("\"enforcement_point\""));
}

#[test]
fn enrichment_revocation_denial_display_contains_target_type() {
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Extension,
        target_id: EngineObjectId([1; 32]),
        transitive: false,
        transitive_root: None,
        enforcement_point: EnforcementPoint::ExtensionActivation,
    };
    let s = denial.to_string();
    assert!(s.contains("extension"));
    assert!(s.contains("extension_activation"));
    assert!(s.contains("directly revoked"));
}

#[test]
fn enrichment_revocation_denial_display_transitive_with_root_shows_root() {
    let root_id = EngineObjectId([0xAB; 32]);
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Attestation,
        target_id: EngineObjectId([1; 32]),
        transitive: true,
        transitive_root: Some(root_id.clone()),
        enforcement_point: EnforcementPoint::HighRiskOperation,
    };
    let s = denial.to_string();
    assert!(s.contains("transitively revoked"));
    // The root ID should appear somewhere in the string
    let root_str = root_id.to_string();
    assert!(s.contains(&root_str));
}

#[test]
fn enrichment_revocation_denial_is_error() {
    // RevocationDenial implements std::error::Error
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Token,
        target_id: EngineObjectId([1; 32]),
        transitive: false,
        transitive_root: None,
        enforcement_point: EnforcementPoint::TokenAcceptance,
    };
    let err: &dyn std::error::Error = &denial;
    let display = err.to_string();
    assert!(display.contains("directly revoked"));
}

// ── EnforcementResult: Debug, Clone, PartialEq, serde ───────────────────

#[test]
fn enrichment_enforcement_result_debug_cleared() {
    let r = EnforcementResult::Cleared {
        enforcement_point: EnforcementPoint::TokenAcceptance,
        checks_performed: 2,
    };
    let dbg = format!("{:?}", r);
    assert!(dbg.contains("Cleared"));
}

#[test]
fn enrichment_enforcement_result_debug_denied() {
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Token,
        target_id: EngineObjectId([1; 32]),
        transitive: false,
        transitive_root: None,
        enforcement_point: EnforcementPoint::TokenAcceptance,
    };
    let r = EnforcementResult::Denied(denial);
    let dbg = format!("{:?}", r);
    assert!(dbg.contains("Denied"));
}

#[test]
fn enrichment_enforcement_result_clone_cleared() {
    let r = EnforcementResult::Cleared {
        enforcement_point: EnforcementPoint::HighRiskOperation,
        checks_performed: 5,
    };
    let cloned = r.clone();
    assert_eq!(r, cloned);
}

#[test]
fn enrichment_enforcement_result_clone_denied() {
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Extension,
        target_id: EngineObjectId([3; 32]),
        transitive: true,
        transitive_root: Some(EngineObjectId([4; 32])),
        enforcement_point: EnforcementPoint::ExtensionActivation,
    };
    let r = EnforcementResult::Denied(denial);
    let cloned = r.clone();
    assert_eq!(r, cloned);
}

#[test]
fn enrichment_enforcement_result_ne_cleared_vs_denied() {
    let cleared = EnforcementResult::Cleared {
        enforcement_point: EnforcementPoint::TokenAcceptance,
        checks_performed: 2,
    };
    let denied = EnforcementResult::Denied(RevocationDenial {
        target_type: RevocationTargetType::Token,
        target_id: EngineObjectId([1; 32]),
        transitive: false,
        transitive_root: None,
        enforcement_point: EnforcementPoint::TokenAcceptance,
    });
    assert_ne!(cleared, denied);
}

#[test]
fn enrichment_enforcement_result_serde_cleared() {
    let r = EnforcementResult::Cleared {
        enforcement_point: EnforcementPoint::ExtensionActivation,
        checks_performed: 3,
    };
    let json = serde_json::to_string(&r).unwrap();
    let decoded: EnforcementResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, decoded);
}

#[test]
fn enrichment_enforcement_result_serde_denied() {
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Attestation,
        target_id: EngineObjectId([11; 32]),
        transitive: true,
        transitive_root: Some(EngineObjectId([12; 32])),
        enforcement_point: EnforcementPoint::HighRiskOperation,
    };
    let r = EnforcementResult::Denied(denial);
    let json = serde_json::to_string(&r).unwrap();
    let decoded: EnforcementResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, decoded);
}

#[test]
fn enrichment_enforcement_result_into_result_denied_content() {
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Extension,
        target_id: EngineObjectId([99; 32]),
        transitive: false,
        transitive_root: None,
        enforcement_point: EnforcementPoint::ExtensionActivation,
    };
    let r = EnforcementResult::Denied(denial.clone());
    let err = r.into_result().unwrap_err();
    assert_eq!(err, denial);
}

#[test]
fn enrichment_enforcement_result_cleared_checks_performed_zero() {
    let r = EnforcementResult::Cleared {
        enforcement_point: EnforcementPoint::TokenAcceptance,
        checks_performed: 0,
    };
    assert!(r.is_cleared());
}

// ── RevocationCheckEvent: Debug, Clone, PartialEq, serde ────────────────

#[test]
fn enrichment_check_event_debug() {
    let event = RevocationCheckEvent {
        enforcement_point: EnforcementPoint::TokenAcceptance,
        target_id: EngineObjectId([1; 32]),
        target_type: RevocationTargetType::Token,
        is_revoked: false,
        transitive: false,
        trace_id: "trace-dbg".to_string(),
        checked_at: DeterministicTimestamp(1000),
    };
    let dbg = format!("{:?}", event);
    assert!(dbg.contains("RevocationCheckEvent"));
}

#[test]
fn enrichment_check_event_clone_eq() {
    let event = RevocationCheckEvent {
        enforcement_point: EnforcementPoint::HighRiskOperation,
        target_id: EngineObjectId([5; 32]),
        target_type: RevocationTargetType::Attestation,
        is_revoked: true,
        transitive: true,
        trace_id: "trace-clone".to_string(),
        checked_at: DeterministicTimestamp(2000),
    };
    let cloned = event.clone();
    assert_eq!(event, cloned);
}

#[test]
fn enrichment_check_event_ne_different_revoked() {
    let e1 = RevocationCheckEvent {
        enforcement_point: EnforcementPoint::TokenAcceptance,
        target_id: EngineObjectId([1; 32]),
        target_type: RevocationTargetType::Token,
        is_revoked: false,
        transitive: false,
        trace_id: "t".to_string(),
        checked_at: DeterministicTimestamp(100),
    };
    let e2 = RevocationCheckEvent {
        enforcement_point: EnforcementPoint::TokenAcceptance,
        target_id: EngineObjectId([1; 32]),
        target_type: RevocationTargetType::Token,
        is_revoked: true,
        transitive: false,
        trace_id: "t".to_string(),
        checked_at: DeterministicTimestamp(100),
    };
    assert_ne!(e1, e2);
}

#[test]
fn enrichment_check_event_serde_roundtrip() {
    let event = RevocationCheckEvent {
        enforcement_point: EnforcementPoint::ExtensionActivation,
        target_id: EngineObjectId([15; 32]),
        target_type: RevocationTargetType::Extension,
        is_revoked: false,
        transitive: true,
        trace_id: "trace-serde".to_string(),
        checked_at: DeterministicTimestamp(9999),
    };
    let json = serde_json::to_string(&event).unwrap();
    let decoded: RevocationCheckEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, decoded);
}

#[test]
fn enrichment_check_event_json_field_names_stable() {
    let event = RevocationCheckEvent {
        enforcement_point: EnforcementPoint::TokenAcceptance,
        target_id: EngineObjectId([1; 32]),
        target_type: RevocationTargetType::Token,
        is_revoked: false,
        transitive: false,
        trace_id: "t-fields".to_string(),
        checked_at: DeterministicTimestamp(100),
    };
    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("\"enforcement_point\""));
    assert!(json.contains("\"target_id\""));
    assert!(json.contains("\"target_type\""));
    assert!(json.contains("\"is_revoked\""));
    assert!(json.contains("\"transitive\""));
    assert!(json.contains("\"trace_id\""));
    assert!(json.contains("\"checked_at\""));
}

// ── EnforcementStats: Debug, Clone, Default, PartialEq, serde ──────────

#[test]
fn enrichment_enforcement_stats_debug() {
    let s = EnforcementStats {
        checks: 42,
        cleared: 30,
        denied: 12,
        transitive_denials: 3,
    };
    let dbg = format!("{:?}", s);
    assert!(dbg.contains("EnforcementStats"));
    assert!(dbg.contains("42"));
}

#[test]
fn enrichment_enforcement_stats_clone_eq() {
    let s = EnforcementStats {
        checks: 5,
        cleared: 4,
        denied: 1,
        transitive_denials: 0,
    };
    let cloned = s.clone();
    assert_eq!(s, cloned);
}

#[test]
fn enrichment_enforcement_stats_ne_different_checks() {
    let s1 = EnforcementStats {
        checks: 10,
        cleared: 8,
        denied: 2,
        transitive_denials: 0,
    };
    let s2 = EnforcementStats {
        checks: 11,
        cleared: 8,
        denied: 2,
        transitive_denials: 0,
    };
    assert_ne!(s1, s2);
}

#[test]
fn enrichment_enforcement_stats_default_all_zero() {
    let s = EnforcementStats::default();
    assert_eq!(s.checks, 0);
    assert_eq!(s.cleared, 0);
    assert_eq!(s.denied, 0);
    assert_eq!(s.transitive_denials, 0);
}

#[test]
fn enrichment_enforcement_stats_json_field_names() {
    let s = EnforcementStats {
        checks: 1,
        cleared: 1,
        denied: 0,
        transitive_denials: 0,
    };
    let json = serde_json::to_string(&s).unwrap();
    assert!(json.contains("\"checks\""));
    assert!(json.contains("\"cleared\""));
    assert!(json.contains("\"denied\""));
    assert!(json.contains("\"transitive_denials\""));
}

#[test]
fn enrichment_enforcement_stats_serde_roundtrip_large_values() {
    let s = EnforcementStats {
        checks: u64::MAX,
        cleared: u64::MAX - 1,
        denied: 1,
        transitive_denials: 0,
    };
    let json = serde_json::to_string(&s).unwrap();
    let decoded: EnforcementStats = serde_json::from_str(&json).unwrap();
    assert_eq!(s, decoded);
}

// ── key_id_from_verification_key: edge cases & determinism ──────────────

#[test]
fn enrichment_key_id_all_zeros() {
    let vk = VerificationKey::from_bytes([0; 32]);
    let id = key_id_from_verification_key(&vk);
    // Should produce a valid, non-zero EngineObjectId from hashing
    let id2 = key_id_from_verification_key(&vk);
    assert_eq!(id, id2);
}

#[test]
fn enrichment_key_id_all_ff() {
    let vk = VerificationKey::from_bytes([0xFF; 32]);
    let id = key_id_from_verification_key(&vk);
    let id2 = key_id_from_verification_key(&vk);
    assert_eq!(id, id2);
}

#[test]
fn enrichment_key_id_single_bit_difference() {
    let bytes1 = [0u8; 32];
    let mut bytes2 = [0u8; 32];
    bytes2[0] = 1;
    let vk1 = VerificationKey::from_bytes(bytes1);
    let vk2 = VerificationKey::from_bytes(bytes2);
    assert_ne!(
        key_id_from_verification_key(&vk1),
        key_id_from_verification_key(&vk2),
    );
}

#[test]
fn enrichment_key_id_last_byte_difference() {
    let bytes1 = [0xAAu8; 32];
    let mut bytes2 = [0xAAu8; 32];
    bytes2[31] = 0xAB;
    let vk1 = VerificationKey::from_bytes(bytes1);
    let vk2 = VerificationKey::from_bytes(bytes2);
    assert_ne!(
        key_id_from_verification_key(&vk1),
        key_id_from_verification_key(&vk2),
    );
}

#[test]
fn enrichment_key_id_determinism_ten_runs() {
    let vk = VerificationKey::from_bytes([77; 32]);
    let reference = key_id_from_verification_key(&vk);
    for _ in 0..10 {
        assert_eq!(key_id_from_verification_key(&vk), reference);
    }
}

// ── RevocationEnforcer: constructor & accessors ─────────────────────────

#[test]
fn enrichment_enforcer_new_empty_chain() {
    let chain = RevocationChain::new("zone-1");
    let enforcer = RevocationEnforcer::new(chain, 0);
    assert!(enforcer.chain().is_empty());
    assert_eq!(enforcer.chain().zone(), "zone-1");
}

#[test]
fn enrichment_enforcer_stats_initially_empty_btreemap() {
    let enforcer = make_enforcer();
    assert!(enforcer.stats().is_empty());
    assert_eq!(enforcer.stats().len(), 0);
}

#[test]
fn enrichment_enforcer_debug() {
    let enforcer = make_enforcer();
    let dbg = format!("{:?}", enforcer);
    assert!(dbg.contains("RevocationEnforcer"));
}

#[test]
fn enrichment_set_tick_zero() {
    let mut enforcer = make_enforcer();
    enforcer.set_tick(0);
    let vk = VerificationKey::from_bytes([2; 32]);
    enforcer.check_token_acceptance(&EngineObjectId([1; 32]), &vk, "t-tick-0");
    let events = enforcer.drain_audit_log();
    assert_eq!(events[0].checked_at.0, 0);
}

#[test]
fn enrichment_set_tick_max_u64() {
    let mut enforcer = make_enforcer();
    enforcer.set_tick(u64::MAX);
    let vk = VerificationKey::from_bytes([2; 32]);
    enforcer.check_token_acceptance(&EngineObjectId([1; 32]), &vk, "t-tick-max");
    let events = enforcer.drain_audit_log();
    assert_eq!(events[0].checked_at.0, u64::MAX);
}

#[test]
fn enrichment_drain_audit_log_idempotent_empty() {
    let mut enforcer = make_enforcer();
    let e1 = enforcer.drain_audit_log();
    let e2 = enforcer.drain_audit_log();
    assert!(e1.is_empty());
    assert!(e2.is_empty());
}

// ── Token acceptance: edge cases ─────────────────────────────────────────

#[test]
fn enrichment_token_acceptance_same_jti_different_key_cleared() {
    let mut enforcer = make_enforcer();
    let jti = EngineObjectId([50; 32]);
    let r1 = enforcer.check_token_acceptance(&jti, &VerificationKey::from_bytes([1; 32]), "t-a");
    let r2 = enforcer.check_token_acceptance(&jti, &VerificationKey::from_bytes([2; 32]), "t-b");
    assert!(r1.is_cleared());
    assert!(r2.is_cleared());
}

#[test]
fn enrichment_token_acceptance_cleared_checks_performed_is_two() {
    let mut enforcer = make_enforcer();
    let jti = EngineObjectId([50; 32]);
    let vk = VerificationKey::from_bytes([51; 32]);
    match enforcer.check_token_acceptance(&jti, &vk, "t-cp") {
        EnforcementResult::Cleared {
            checks_performed,
            enforcement_point,
        } => {
            assert_eq!(checks_performed, 2);
            assert_eq!(enforcement_point, EnforcementPoint::TokenAcceptance);
        }
        _ => panic!("expected cleared"),
    }
}

#[test]
fn enrichment_token_acceptance_direct_denial_stops_before_key_check() {
    let mut enforcer = make_enforcer();
    let jti = EngineObjectId([50; 32]);
    revoke_target(&mut enforcer, RevocationTargetType::Token, [50; 32]);
    enforcer.drain_audit_log();
    let vk = VerificationKey::from_bytes([51; 32]);
    enforcer.check_token_acceptance(&jti, &vk, "t-early-stop");
    let events = enforcer.drain_audit_log();
    // Only 1 audit event: the direct token check (does not proceed to key check)
    assert_eq!(events.len(), 1);
    assert!(events[0].is_revoked);
    assert!(!events[0].transitive);
}

#[test]
fn enrichment_token_acceptance_both_token_and_key_revoked_prefers_direct() {
    let mut enforcer = make_enforcer();
    let jti = EngineObjectId([60; 32]);
    let vk = VerificationKey::from_bytes([61; 32]);
    let key_id = key_id_from_verification_key(&vk);
    // Revoke both the token and the issuer key
    revoke_target(&mut enforcer, RevocationTargetType::Token, [60; 32]);
    revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());
    enforcer.drain_audit_log();
    match enforcer.check_token_acceptance(&jti, &vk, "t-both-revoked") {
        EnforcementResult::Denied(d) => {
            // Direct denial takes priority over transitive
            assert!(!d.transitive);
            assert!(d.transitive_root.is_none());
            assert_eq!(d.target_type, RevocationTargetType::Token);
        }
        _ => panic!("expected denial"),
    }
}

// ── High-risk operation: edge cases ──────────────────────────────────────

#[test]
fn enrichment_high_risk_cleared_checks_performed_is_two() {
    let mut enforcer = make_enforcer();
    let att_id = EngineObjectId([70; 32]);
    let pk = VerificationKey::from_bytes([71; 32]);
    match enforcer.check_high_risk_operation(
        &att_id,
        &pk,
        HighRiskCategory::PolicyChange,
        "t-hr-cp",
    ) {
        EnforcementResult::Cleared {
            checks_performed,
            enforcement_point,
        } => {
            assert_eq!(checks_performed, 2);
            assert_eq!(enforcement_point, EnforcementPoint::HighRiskOperation);
        }
        _ => panic!("expected cleared"),
    }
}

#[test]
fn enrichment_high_risk_both_attestation_and_key_revoked_prefers_direct() {
    let mut enforcer = make_enforcer();
    let att_id = EngineObjectId([72; 32]);
    let pk = VerificationKey::from_bytes([73; 32]);
    let key_id = key_id_from_verification_key(&pk);
    revoke_target(&mut enforcer, RevocationTargetType::Attestation, [72; 32]);
    revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());
    enforcer.drain_audit_log();
    match enforcer.check_high_risk_operation(
        &att_id,
        &pk,
        HighRiskCategory::DataExport,
        "t-hr-both",
    ) {
        EnforcementResult::Denied(d) => {
            assert!(!d.transitive);
            assert_eq!(d.target_type, RevocationTargetType::Attestation);
        }
        _ => panic!("expected denial"),
    }
}

#[test]
fn enrichment_high_risk_denied_attestation_emits_one_audit_event() {
    let mut enforcer = make_enforcer();
    revoke_target(&mut enforcer, RevocationTargetType::Attestation, [75; 32]);
    enforcer.drain_audit_log();
    let pk = VerificationKey::from_bytes([76; 32]);
    enforcer.check_high_risk_operation(
        &EngineObjectId([75; 32]),
        &pk,
        HighRiskCategory::CrossZoneAction,
        "t-hr-1evt",
    );
    let events = enforcer.drain_audit_log();
    assert_eq!(events.len(), 1);
    assert!(events[0].is_revoked);
}

#[test]
fn enrichment_high_risk_transitive_emits_two_audit_events() {
    let mut enforcer = make_enforcer();
    let pk = VerificationKey::from_bytes([78; 32]);
    let key_id = key_id_from_verification_key(&pk);
    revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());
    enforcer.drain_audit_log();
    enforcer.check_high_risk_operation(
        &EngineObjectId([77; 32]),
        &pk,
        HighRiskCategory::ExtensionLifecycleChange,
        "t-hr-2evt",
    );
    let events = enforcer.drain_audit_log();
    assert_eq!(events.len(), 2);
    assert!(!events[0].is_revoked); // attestation pass
    assert!(events[1].is_revoked); // key fail
    assert!(events[1].transitive);
}

#[test]
fn enrichment_high_risk_all_categories_with_revoked_attestation() {
    let categories = [
        HighRiskCategory::PolicyChange,
        HighRiskCategory::KeyOperation,
        HighRiskCategory::DataExport,
        HighRiskCategory::CrossZoneAction,
        HighRiskCategory::ExtensionLifecycleChange,
    ];
    for (i, cat) in categories.iter().enumerate() {
        let mut enforcer = make_enforcer();
        let bytes = [(i as u8) + 80; 32];
        revoke_target(&mut enforcer, RevocationTargetType::Attestation, bytes);
        let pk = VerificationKey::from_bytes([(i as u8) + 180; 32]);
        let result = enforcer.check_high_risk_operation(
            &EngineObjectId(bytes),
            &pk,
            *cat,
            &format!("t-cat-deny-{i}"),
        );
        assert!(!result.is_cleared(), "category {:?} should be denied", cat);
    }
}

// ── Extension activation: edge cases ─────────────────────────────────────

#[test]
fn enrichment_extension_activation_cleared_checks_performed_is_two() {
    let mut enforcer = make_enforcer();
    let ext_id = EngineObjectId([90; 32]);
    let sk = VerificationKey::from_bytes([91; 32]);
    match enforcer.check_extension_activation(&ext_id, &sk, "t-ext-cp") {
        EnforcementResult::Cleared {
            checks_performed,
            enforcement_point,
        } => {
            assert_eq!(checks_performed, 2);
            assert_eq!(enforcement_point, EnforcementPoint::ExtensionActivation);
        }
        _ => panic!("expected cleared"),
    }
}

#[test]
fn enrichment_extension_both_ext_and_key_revoked_prefers_direct() {
    let mut enforcer = make_enforcer();
    let ext_id = EngineObjectId([92; 32]);
    let sk = VerificationKey::from_bytes([93; 32]);
    let key_id = key_id_from_verification_key(&sk);
    revoke_target(&mut enforcer, RevocationTargetType::Extension, [92; 32]);
    revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());
    enforcer.drain_audit_log();
    match enforcer.check_extension_activation(&ext_id, &sk, "t-ext-both") {
        EnforcementResult::Denied(d) => {
            assert!(!d.transitive);
            assert_eq!(d.target_type, RevocationTargetType::Extension);
            assert_eq!(d.target_id, ext_id);
        }
        _ => panic!("expected denial"),
    }
}

#[test]
fn enrichment_extension_denied_ext_emits_one_audit_event() {
    let mut enforcer = make_enforcer();
    revoke_target(&mut enforcer, RevocationTargetType::Extension, [94; 32]);
    enforcer.drain_audit_log();
    let sk = VerificationKey::from_bytes([95; 32]);
    enforcer.check_extension_activation(&EngineObjectId([94; 32]), &sk, "t-ext-1evt");
    let events = enforcer.drain_audit_log();
    assert_eq!(events.len(), 1);
    assert!(events[0].is_revoked);
    assert!(!events[0].transitive);
}

#[test]
fn enrichment_extension_transitive_emits_two_audit_events() {
    let mut enforcer = make_enforcer();
    let sk = VerificationKey::from_bytes([97; 32]);
    let key_id = key_id_from_verification_key(&sk);
    revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());
    enforcer.drain_audit_log();
    enforcer.check_extension_activation(&EngineObjectId([96; 32]), &sk, "t-ext-2evt");
    let events = enforcer.drain_audit_log();
    assert_eq!(events.len(), 2);
    assert!(!events[0].is_revoked); // extension pass
    assert!(events[1].is_revoked); // key fail
    assert!(events[1].transitive);
}

// ── Batch token check: edge cases ────────────────────────────────────────

#[test]
fn enrichment_batch_single_token_cleared() {
    let mut enforcer = make_enforcer();
    let tokens = vec![(
        EngineObjectId([1; 32]),
        VerificationKey::from_bytes([2; 32]),
    )];
    let result = enforcer.check_token_batch(&tokens, "t-batch-single");
    assert!(result.is_cleared());
    if let EnforcementResult::Cleared {
        checks_performed, ..
    } = result
    {
        assert_eq!(checks_performed, 2);
    }
}

#[test]
fn enrichment_batch_first_token_revoked() {
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
    let result = enforcer.check_token_batch(&tokens, "t-batch-first");
    match result {
        EnforcementResult::Denied(d) => {
            assert_eq!(d.target_id, EngineObjectId([1; 32]));
        }
        _ => panic!("expected denial"),
    }
}

#[test]
fn enrichment_batch_last_token_revoked() {
    let mut enforcer = make_enforcer();
    revoke_target(&mut enforcer, RevocationTargetType::Token, [5; 32]);
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
    let result = enforcer.check_token_batch(&tokens, "t-batch-last");
    match result {
        EnforcementResult::Denied(d) => {
            assert_eq!(d.target_id, EngineObjectId([5; 32]));
        }
        _ => panic!("expected denial"),
    }
}

#[test]
fn enrichment_batch_transitive_denial_via_issuer_key() {
    let mut enforcer = make_enforcer();
    let shared_key = VerificationKey::from_bytes([50; 32]);
    let key_id = key_id_from_verification_key(&shared_key);
    revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());
    let tokens = vec![
        (EngineObjectId([1; 32]), shared_key.clone()),
        (
            EngineObjectId([2; 32]),
            VerificationKey::from_bytes([99; 32]),
        ),
    ];
    let result = enforcer.check_token_batch(&tokens, "t-batch-trans");
    match result {
        EnforcementResult::Denied(d) => {
            assert!(d.transitive);
            assert_eq!(d.target_id, EngineObjectId([1; 32]));
        }
        _ => panic!("expected transitive denial"),
    }
}

#[test]
fn enrichment_batch_multiple_revoked_returns_first() {
    let mut enforcer = make_enforcer();
    revoke_target(&mut enforcer, RevocationTargetType::Token, [10; 32]);
    revoke_target(&mut enforcer, RevocationTargetType::Token, [20; 32]);
    let tokens = vec![
        (
            EngineObjectId([10; 32]),
            VerificationKey::from_bytes([11; 32]),
        ),
        (
            EngineObjectId([20; 32]),
            VerificationKey::from_bytes([21; 32]),
        ),
    ];
    let result = enforcer.check_token_batch(&tokens, "t-batch-multi");
    match result {
        EnforcementResult::Denied(d) => {
            assert_eq!(d.target_id, EngineObjectId([10; 32]));
        }
        _ => panic!("expected denial"),
    }
}

#[test]
fn enrichment_batch_checks_performed_count() {
    let mut enforcer = make_enforcer();
    let tokens: Vec<_> = (0..5u8)
        .map(|i| {
            (
                EngineObjectId([i; 32]),
                VerificationKey::from_bytes([i + 100; 32]),
            )
        })
        .collect();
    match enforcer.check_token_batch(&tokens, "t-batch-count") {
        EnforcementResult::Cleared {
            checks_performed, ..
        } => {
            assert_eq!(checks_performed, 10); // 5 * 2
        }
        _ => panic!("expected cleared"),
    }
}

// ── Stats: comprehensive tracking ────────────────────────────────────────

#[test]
fn enrichment_stats_separate_per_enforcement_point() {
    let mut enforcer = make_enforcer();
    let vk = VerificationKey::from_bytes([2; 32]);
    enforcer.check_token_acceptance(&EngineObjectId([1; 32]), &vk, "t-s");
    enforcer.check_high_risk_operation(
        &EngineObjectId([2; 32]),
        &vk,
        HighRiskCategory::PolicyChange,
        "t-s",
    );
    enforcer.check_extension_activation(&EngineObjectId([3; 32]), &vk, "t-s");
    let stats = enforcer.stats();
    assert_eq!(stats.len(), 3);
    assert!(stats.contains_key(&EnforcementPoint::TokenAcceptance));
    assert!(stats.contains_key(&EnforcementPoint::HighRiskOperation));
    assert!(stats.contains_key(&EnforcementPoint::ExtensionActivation));
}

#[test]
fn enrichment_stats_multiple_clears_accumulate() {
    let mut enforcer = make_enforcer();
    for i in 0..10u8 {
        let vk = VerificationKey::from_bytes([i + 100; 32]);
        enforcer.check_token_acceptance(&EngineObjectId([i; 32]), &vk, &format!("t-{i}"));
    }
    let stats = enforcer.stats();
    let s = stats.get(&EnforcementPoint::TokenAcceptance).unwrap();
    assert_eq!(s.checks, 10);
    assert_eq!(s.cleared, 10);
    assert_eq!(s.denied, 0);
}

#[test]
fn enrichment_stats_mixed_clears_and_denials() {
    let mut enforcer = make_enforcer();
    // 3 cleared
    for i in 0..3u8 {
        let vk = VerificationKey::from_bytes([i + 100; 32]);
        enforcer.check_token_acceptance(&EngineObjectId([i; 32]), &vk, "t-mix");
    }
    // 2 direct denials
    for i in 10..12u8 {
        revoke_target(&mut enforcer, RevocationTargetType::Token, [i; 32]);
        let vk = VerificationKey::from_bytes([i + 100; 32]);
        enforcer.check_token_acceptance(&EngineObjectId([i; 32]), &vk, "t-mix");
    }
    let stats = enforcer.stats();
    let s = stats.get(&EnforcementPoint::TokenAcceptance).unwrap();
    assert_eq!(s.checks, 5);
    assert_eq!(s.cleared, 3);
    assert_eq!(s.denied, 2);
    assert_eq!(s.transitive_denials, 0);
}

#[test]
fn enrichment_stats_transitive_denials_counted_separately() {
    let mut enforcer = make_enforcer();
    let vk = VerificationKey::from_bytes([42; 32]);
    let key_id = key_id_from_verification_key(&vk);
    revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());
    // 3 transitive denials
    for i in 0..3u8 {
        enforcer.check_token_acceptance(&EngineObjectId([i; 32]), &vk, &format!("t-td-{i}"));
    }
    let stats = enforcer.stats();
    let s = stats.get(&EnforcementPoint::TokenAcceptance).unwrap();
    assert_eq!(s.denied, 3);
    assert_eq!(s.transitive_denials, 3);
    assert_eq!(s.cleared, 0);
}

// ── Audit event ordering ─────────────────────────────────────────────────

#[test]
fn enrichment_audit_events_ordered_chronologically() {
    let mut enforcer = make_enforcer();
    enforcer.set_tick(100);
    let vk = VerificationKey::from_bytes([2; 32]);
    enforcer.check_token_acceptance(&EngineObjectId([1; 32]), &vk, "t-ord-1");
    enforcer.set_tick(200);
    enforcer.check_token_acceptance(&EngineObjectId([2; 32]), &vk, "t-ord-2");
    enforcer.set_tick(300);
    enforcer.check_token_acceptance(&EngineObjectId([3; 32]), &vk, "t-ord-3");
    let events = enforcer.drain_audit_log();
    assert_eq!(events.len(), 6);
    // Events within a single check have same timestamp
    assert_eq!(events[0].checked_at.0, 100);
    assert_eq!(events[1].checked_at.0, 100);
    assert_eq!(events[2].checked_at.0, 200);
    assert_eq!(events[3].checked_at.0, 200);
    assert_eq!(events[4].checked_at.0, 300);
    assert_eq!(events[5].checked_at.0, 300);
}

#[test]
fn enrichment_audit_event_trace_ids_preserved() {
    let mut enforcer = make_enforcer();
    let vk = VerificationKey::from_bytes([2; 32]);
    enforcer.check_token_acceptance(&EngineObjectId([1; 32]), &vk, "alpha");
    enforcer.check_token_acceptance(&EngineObjectId([2; 32]), &vk, "beta");
    let events = enforcer.drain_audit_log();
    assert!(events[0].trace_id == "alpha");
    assert!(events[1].trace_id == "alpha");
    assert!(events[2].trace_id == "beta");
    assert!(events[3].trace_id == "beta");
}

// ── Determinism: multiple runs produce identical results ─────────────────

#[test]
fn enrichment_determinism_extension_activation() {
    let run = || {
        let mut enforcer = make_enforcer();
        let sk = VerificationKey::from_bytes([7; 32]);
        let key_id = key_id_from_verification_key(&sk);
        revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());
        enforcer.drain_audit_log();
        let r = enforcer.check_extension_activation(&EngineObjectId([8; 32]), &sk, "t-det-ext");
        let events = enforcer.drain_audit_log();
        (r, events)
    };
    let (r1, e1) = run();
    let (r2, e2) = run();
    assert_eq!(r1, r2);
    assert_eq!(e1, e2);
}

#[test]
fn enrichment_determinism_high_risk_operation() {
    let run = || {
        let mut enforcer = make_enforcer();
        revoke_target(&mut enforcer, RevocationTargetType::Attestation, [50; 32]);
        enforcer.drain_audit_log();
        let pk = VerificationKey::from_bytes([51; 32]);
        let r = enforcer.check_high_risk_operation(
            &EngineObjectId([50; 32]),
            &pk,
            HighRiskCategory::KeyOperation,
            "t-det-hr",
        );
        let events = enforcer.drain_audit_log();
        (r, events)
    };
    let (r1, e1) = run();
    let (r2, e2) = run();
    assert_eq!(r1, r2);
    assert_eq!(e1, e2);
}

#[test]
fn enrichment_determinism_batch_check() {
    let run = || {
        let mut enforcer = make_enforcer();
        revoke_target(&mut enforcer, RevocationTargetType::Token, [3; 32]);
        enforcer.drain_audit_log();
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
        let r = enforcer.check_token_batch(&tokens, "t-det-batch");
        let events = enforcer.drain_audit_log();
        (r, events)
    };
    let (r1, e1) = run();
    let (r2, e2) = run();
    assert_eq!(r1, r2);
    assert_eq!(e1, e2);
}

// ── Cross-enforcement isolation ──────────────────────────────────────────

#[test]
fn enrichment_revocation_by_id_is_type_agnostic() {
    // RevocationChain.is_revoked checks by EngineObjectId alone,
    // so revoking a Token ID also blocks Extension checks with the same ID.
    let mut enforcer = make_enforcer();
    revoke_target(&mut enforcer, RevocationTargetType::Token, [10; 32]);
    // Extension with the same ID bytes is also treated as revoked
    let ext_id = EngineObjectId([10; 32]);
    let sk = VerificationKey::from_bytes([11; 32]);
    let result = enforcer.check_extension_activation(&ext_id, &sk, "t-agnostic");
    assert!(!result.is_cleared());
}

#[test]
fn enrichment_extension_revocation_blocks_same_id_token_check() {
    // Revoking an extension ID also blocks a token with the same ID bytes.
    let mut enforcer = make_enforcer();
    revoke_target(&mut enforcer, RevocationTargetType::Extension, [20; 32]);
    let jti = EngineObjectId([20; 32]);
    let vk = VerificationKey::from_bytes([21; 32]);
    let result = enforcer.check_token_acceptance(&jti, &vk, "t-cross-ext");
    assert!(!result.is_cleared());
}

#[test]
fn enrichment_attestation_revocation_blocks_same_id_token_check() {
    // Revoking an attestation ID also blocks a token with the same ID bytes.
    let mut enforcer = make_enforcer();
    revoke_target(&mut enforcer, RevocationTargetType::Attestation, [30; 32]);
    let jti = EngineObjectId([30; 32]);
    let vk = VerificationKey::from_bytes([31; 32]);
    let result = enforcer.check_token_acceptance(&jti, &vk, "t-cross-att");
    assert!(!result.is_cleared());
}

// ── Chain mutations via chain_mut ────────────────────────────────────────

#[test]
fn enrichment_chain_mut_revocation_reflected_in_checks() {
    let mut enforcer = make_enforcer();
    // Initially cleared
    let jti = EngineObjectId([40; 32]);
    let vk = VerificationKey::from_bytes([41; 32]);
    assert!(
        enforcer
            .check_token_acceptance(&jti, &vk, "t-pre")
            .is_cleared()
    );
    // Revoke via chain_mut
    revoke_target(&mut enforcer, RevocationTargetType::Token, [40; 32]);
    // Now denied
    assert!(
        !enforcer
            .check_token_acceptance(&jti, &vk, "t-post")
            .is_cleared()
    );
}

#[test]
fn enrichment_chain_len_increases_on_append() {
    let mut enforcer = make_enforcer();
    assert_eq!(enforcer.chain().len(), 0);
    revoke_target(&mut enforcer, RevocationTargetType::Token, [1; 32]);
    assert_eq!(enforcer.chain().len(), 1);
    revoke_target(&mut enforcer, RevocationTargetType::Extension, [2; 32]);
    assert_eq!(enforcer.chain().len(), 2);
}

// ── Serde roundtrip: complex scenarios ───────────────────────────────────

#[test]
fn enrichment_revocation_denial_all_target_types_serde() {
    let target_types = [
        RevocationTargetType::Key,
        RevocationTargetType::Token,
        RevocationTargetType::Attestation,
        RevocationTargetType::Extension,
        RevocationTargetType::Checkpoint,
    ];
    for tt in &target_types {
        let denial = RevocationDenial {
            target_type: *tt,
            target_id: EngineObjectId([33; 32]),
            transitive: false,
            transitive_root: None,
            enforcement_point: EnforcementPoint::TokenAcceptance,
        };
        let json = serde_json::to_string(&denial).unwrap();
        let decoded: RevocationDenial = serde_json::from_str(&json).unwrap();
        assert_eq!(denial, decoded);
    }
}

#[test]
fn enrichment_enforcement_result_cleared_all_points_serde() {
    for ep in [
        EnforcementPoint::TokenAcceptance,
        EnforcementPoint::HighRiskOperation,
        EnforcementPoint::ExtensionActivation,
    ] {
        let r = EnforcementResult::Cleared {
            enforcement_point: ep,
            checks_performed: 7,
        };
        let json = serde_json::to_string(&r).unwrap();
        let decoded: EnforcementResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, decoded);
    }
}

// ── Stats in BTreeMap ────────────────────────────────────────────────────

#[test]
fn enrichment_stats_btreemap_ordering() {
    let mut enforcer = make_enforcer();
    let vk = VerificationKey::from_bytes([2; 32]);
    // Perform checks in reverse order of EnforcementPoint
    enforcer.check_extension_activation(&EngineObjectId([3; 32]), &vk, "t-o");
    enforcer.check_high_risk_operation(
        &EngineObjectId([2; 32]),
        &vk,
        HighRiskCategory::PolicyChange,
        "t-o",
    );
    enforcer.check_token_acceptance(&EngineObjectId([1; 32]), &vk, "t-o");
    let stats = enforcer.stats();
    let keys: Vec<_> = stats.keys().collect();
    // BTreeMap maintains sorted order per Ord on EnforcementPoint
    assert!(keys[0] <= keys[1]);
    assert!(keys[1] <= keys[2]);
}

// ── Stress: many revocations and checks ──────────────────────────────────

#[test]
fn enrichment_stress_many_distinct_revocations() {
    let mut enforcer = make_enforcer();
    // Revoke 30 distinct tokens
    for i in 0..30u8 {
        revoke_target(&mut enforcer, RevocationTargetType::Token, [i; 32]);
    }
    // All should be denied
    for i in 0..30u8 {
        let result = enforcer.check_token_acceptance(
            &EngineObjectId([i; 32]),
            &VerificationKey::from_bytes([i + 100; 32]),
            &format!("t-stress-{i}"),
        );
        assert!(!result.is_cleared(), "token {i} should be denied");
    }
    // Unrevoked token should still clear
    let result = enforcer.check_token_acceptance(
        &EngineObjectId([200; 32]),
        &VerificationKey::from_bytes([201; 32]),
        "t-stress-clear",
    );
    assert!(result.is_cleared());
}

#[test]
fn enrichment_stress_interleaved_enforcement_points() {
    let mut enforcer = make_enforcer();
    let vk = VerificationKey::from_bytes([2; 32]);
    for i in 0..20u8 {
        enforcer.check_token_acceptance(&EngineObjectId([i; 32]), &vk, &format!("t-il-{i}"));
        enforcer.check_high_risk_operation(
            &EngineObjectId([i + 50; 32]),
            &vk,
            HighRiskCategory::PolicyChange,
            &format!("t-il-{i}"),
        );
        enforcer.check_extension_activation(
            &EngineObjectId([i + 100; 32]),
            &vk,
            &format!("t-il-{i}"),
        );
    }
    let stats = enforcer.stats();
    assert_eq!(stats[&EnforcementPoint::TokenAcceptance].checks, 20);
    assert_eq!(stats[&EnforcementPoint::HighRiskOperation].checks, 20);
    assert_eq!(stats[&EnforcementPoint::ExtensionActivation].checks, 20);
}

// ── Drain and re-check ──────────────────────────────────────────────────

#[test]
fn enrichment_drain_does_not_affect_stats() {
    let mut enforcer = make_enforcer();
    let vk = VerificationKey::from_bytes([2; 32]);
    enforcer.check_token_acceptance(&EngineObjectId([1; 32]), &vk, "t-drain");
    let _events = enforcer.drain_audit_log();
    // Stats remain after drain
    let stats = enforcer.stats();
    assert_eq!(stats[&EnforcementPoint::TokenAcceptance].checks, 1);
}

#[test]
fn enrichment_drain_then_check_produces_fresh_events() {
    let mut enforcer = make_enforcer();
    let vk = VerificationKey::from_bytes([2; 32]);
    enforcer.check_token_acceptance(&EngineObjectId([1; 32]), &vk, "t-first");
    let _ = enforcer.drain_audit_log();
    enforcer.check_token_acceptance(&EngineObjectId([2; 32]), &vk, "t-second");
    let events = enforcer.drain_audit_log();
    assert_eq!(events.len(), 2);
    assert!(events.iter().all(|e| e.trace_id == "t-second"));
}

// ── Property: if cleared then not denied, if denied then not cleared ────

#[test]
fn enrichment_property_cleared_implies_not_denied() {
    let mut enforcer = make_enforcer();
    let vk = VerificationKey::from_bytes([2; 32]);
    let result = enforcer.check_token_acceptance(&EngineObjectId([1; 32]), &vk, "t-prop");
    if result.is_cleared() {
        assert!(result.into_result().is_ok());
    }
}

#[test]
fn enrichment_property_denied_implies_not_cleared() {
    let mut enforcer = make_enforcer();
    revoke_target(&mut enforcer, RevocationTargetType::Token, [1; 32]);
    let vk = VerificationKey::from_bytes([2; 32]);
    let result = enforcer.check_token_acceptance(&EngineObjectId([1; 32]), &vk, "t-prop");
    if !result.is_cleared() {
        assert!(result.into_result().is_err());
    }
}

// ── Audit event target types ─────────────────────────────────────────────

#[test]
fn enrichment_token_check_audit_events_have_correct_target_types() {
    let mut enforcer = make_enforcer();
    let vk = VerificationKey::from_bytes([2; 32]);
    enforcer.check_token_acceptance(&EngineObjectId([1; 32]), &vk, "t-tt");
    let events = enforcer.drain_audit_log();
    assert_eq!(events[0].target_type, RevocationTargetType::Token);
    assert_eq!(events[1].target_type, RevocationTargetType::Key);
}

#[test]
fn enrichment_high_risk_check_audit_events_have_correct_target_types() {
    let mut enforcer = make_enforcer();
    let vk = VerificationKey::from_bytes([2; 32]);
    enforcer.check_high_risk_operation(
        &EngineObjectId([1; 32]),
        &vk,
        HighRiskCategory::DataExport,
        "t-tt",
    );
    let events = enforcer.drain_audit_log();
    assert_eq!(events[0].target_type, RevocationTargetType::Attestation);
    assert_eq!(events[1].target_type, RevocationTargetType::Key);
}

#[test]
fn enrichment_extension_check_audit_events_have_correct_target_types() {
    let mut enforcer = make_enforcer();
    let vk = VerificationKey::from_bytes([2; 32]);
    enforcer.check_extension_activation(&EngineObjectId([1; 32]), &vk, "t-tt");
    let events = enforcer.drain_audit_log();
    assert_eq!(events[0].target_type, RevocationTargetType::Extension);
    assert_eq!(events[1].target_type, RevocationTargetType::Key);
}

// ── Audit event transitive flag ──────────────────────────────────────────

#[test]
fn enrichment_cleared_token_audit_first_event_not_transitive() {
    let mut enforcer = make_enforcer();
    let vk = VerificationKey::from_bytes([2; 32]);
    enforcer.check_token_acceptance(&EngineObjectId([1; 32]), &vk, "t-tf");
    let events = enforcer.drain_audit_log();
    assert!(!events[0].transitive);
    assert!(events[1].transitive);
}

#[test]
fn enrichment_cleared_high_risk_audit_first_event_not_transitive() {
    let mut enforcer = make_enforcer();
    let vk = VerificationKey::from_bytes([2; 32]);
    enforcer.check_high_risk_operation(
        &EngineObjectId([1; 32]),
        &vk,
        HighRiskCategory::PolicyChange,
        "t-tf",
    );
    let events = enforcer.drain_audit_log();
    assert!(!events[0].transitive);
    assert!(events[1].transitive);
}

#[test]
fn enrichment_cleared_extension_audit_first_event_not_transitive() {
    let mut enforcer = make_enforcer();
    let vk = VerificationKey::from_bytes([2; 32]);
    enforcer.check_extension_activation(&EngineObjectId([1; 32]), &vk, "t-tf");
    let events = enforcer.drain_audit_log();
    assert!(!events[0].transitive);
    assert!(events[1].transitive);
}

// ── Empty trace IDs ──────────────────────────────────────────────────────

#[test]
fn enrichment_empty_trace_id_accepted() {
    let mut enforcer = make_enforcer();
    let vk = VerificationKey::from_bytes([2; 32]);
    let result = enforcer.check_token_acceptance(&EngineObjectId([1; 32]), &vk, "");
    assert!(result.is_cleared());
    let events = enforcer.drain_audit_log();
    assert!(events.iter().all(|e| e.trace_id.is_empty()));
}

// ── RevocationDenial with all enforcement points ─────────────────────────

#[test]
fn enrichment_denial_display_all_enforcement_points() {
    for ep in [
        EnforcementPoint::TokenAcceptance,
        EnforcementPoint::HighRiskOperation,
        EnforcementPoint::ExtensionActivation,
    ] {
        let denial = RevocationDenial {
            target_type: RevocationTargetType::Token,
            target_id: EngineObjectId([1; 32]),
            transitive: false,
            transitive_root: None,
            enforcement_point: ep,
        };
        let s = denial.to_string();
        assert!(s.contains(&ep.to_string()));
        assert!(s.contains("directly revoked"));
    }
}

// ── Tick monotonicity in events ──────────────────────────────────────────

#[test]
fn enrichment_tick_monotonicity_across_checks() {
    let mut enforcer = make_enforcer();
    let vk = VerificationKey::from_bytes([2; 32]);
    for tick in [10, 20, 30, 40, 50] {
        enforcer.set_tick(tick);
        enforcer.check_token_acceptance(
            &EngineObjectId([(tick as u8); 32]),
            &vk,
            &format!("t-mono-{tick}"),
        );
    }
    let events = enforcer.drain_audit_log();
    for window in events.windows(2) {
        assert!(window[0].checked_at.0 <= window[1].checked_at.0);
    }
}
