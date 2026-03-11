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
