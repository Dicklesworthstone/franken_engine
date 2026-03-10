#![forbid(unsafe_code)]

//! Integration tests for the `revocation_enforcement` module.
//!
//! Covers all three enforcement points (token acceptance, high-risk operation,
//! extension activation), batch checks, statistics tracking, audit log,
//! key ID derivation, EnforcementResult conversions, Display impls, serde
//! round-trips, and determinism guarantees.

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

const TEST_ZONE: &str = "test-zone";

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ])
}

fn revocation_key() -> SigningKey {
    SigningKey::from_bytes([
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE,
        0xBF, 0xC0,
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
    RevocationEnforcer::new(RevocationChain::new(TEST_ZONE), 5000)
}

fn revoke_target(
    enforcer: &mut RevocationEnforcer,
    target_type: RevocationTargetType,
    target_bytes: [u8; 32],
) {
    let rev = make_revocation(target_type, RevocationReason::Compromised, target_bytes);
    let sk = test_signing_key();
    enforcer.chain_mut().append(rev, &sk, "t-revoke").unwrap();
}

// ---------------------------------------------------------------------------
// 1. Token acceptance enforcement (8+ tests)
// ---------------------------------------------------------------------------

#[test]
fn token_acceptance_cleared_for_valid_token() {
    let mut enforcer = make_enforcer();
    let token_jti = EngineObjectId([0x01; 32]);
    let issuer_key = VerificationKey::from_bytes([0x02; 32]);

    let result = enforcer.check_token_acceptance(&token_jti, &issuer_key, "t-tok-1");
    assert!(result.is_cleared());
    if let EnforcementResult::Cleared {
        checks_performed,
        enforcement_point,
    } = result
    {
        assert_eq!(checks_performed, 2);
        assert_eq!(enforcement_point, EnforcementPoint::TokenAcceptance);
    } else {
        panic!("expected Cleared");
    }
}

#[test]
fn token_acceptance_denied_for_revoked_jti() {
    let mut enforcer = make_enforcer();
    let target_bytes = [0x10; 32];
    revoke_target(&mut enforcer, RevocationTargetType::Token, target_bytes);

    let token_jti = EngineObjectId(target_bytes);
    let issuer_key = VerificationKey::from_bytes([0x11; 32]);
    let result = enforcer.check_token_acceptance(&token_jti, &issuer_key, "t-tok-2");

    match result {
        EnforcementResult::Denied(denial) => {
            assert_eq!(denial.target_type, RevocationTargetType::Token);
            assert_eq!(denial.target_id, token_jti);
            assert!(!denial.transitive);
            assert!(denial.transitive_root.is_none());
            assert_eq!(denial.enforcement_point, EnforcementPoint::TokenAcceptance);
        }
        _ => panic!("expected Denied"),
    }
}

#[test]
fn token_acceptance_denied_for_revoked_issuer_key() {
    let mut enforcer = make_enforcer();
    let issuer_key = VerificationKey::from_bytes([0x20; 32]);
    let issuer_key_id = key_id_from_verification_key(&issuer_key);

    revoke_target(
        &mut enforcer,
        RevocationTargetType::Key,
        *issuer_key_id.as_bytes(),
    );

    let token_jti = EngineObjectId([0x21; 32]);
    let result = enforcer.check_token_acceptance(&token_jti, &issuer_key, "t-tok-3");

    match result {
        EnforcementResult::Denied(denial) => {
            assert!(denial.transitive);
            assert_eq!(denial.transitive_root, Some(issuer_key_id));
            assert_eq!(denial.target_type, RevocationTargetType::Token);
            assert_eq!(denial.target_id, token_jti);
            assert_eq!(denial.enforcement_point, EnforcementPoint::TokenAcceptance);
        }
        _ => panic!("expected transitive Denied"),
    }
}

#[test]
fn token_acceptance_cleared_emits_two_audit_events() {
    let mut enforcer = make_enforcer();
    let token_jti = EngineObjectId([0x30; 32]);
    let issuer_key = VerificationKey::from_bytes([0x31; 32]);

    enforcer.check_token_acceptance(&token_jti, &issuer_key, "t-tok-4");
    let events = enforcer.drain_audit_log();
    assert_eq!(events.len(), 2);
    assert!(!events[0].is_revoked);
    assert!(!events[1].is_revoked);
    assert!(!events[0].transitive);
    assert!(events[1].transitive);
}

#[test]
fn token_acceptance_direct_denial_emits_one_audit_event() {
    let mut enforcer = make_enforcer();
    let target_bytes = [0x32; 32];
    revoke_target(&mut enforcer, RevocationTargetType::Token, target_bytes);
    enforcer.drain_audit_log(); // clear append events

    let token_jti = EngineObjectId(target_bytes);
    let issuer_key = VerificationKey::from_bytes([0x33; 32]);
    enforcer.check_token_acceptance(&token_jti, &issuer_key, "t-tok-5");
    let events = enforcer.drain_audit_log();
    assert_eq!(events.len(), 1);
    assert!(events[0].is_revoked);
    assert!(!events[0].transitive);
}

#[test]
fn token_acceptance_transitive_denial_emits_two_audit_events() {
    let mut enforcer = make_enforcer();
    let issuer_key = VerificationKey::from_bytes([0x34; 32]);
    let issuer_key_id = key_id_from_verification_key(&issuer_key);
    revoke_target(
        &mut enforcer,
        RevocationTargetType::Key,
        *issuer_key_id.as_bytes(),
    );
    enforcer.drain_audit_log();

    let token_jti = EngineObjectId([0x35; 32]);
    enforcer.check_token_acceptance(&token_jti, &issuer_key, "t-tok-6");
    let events = enforcer.drain_audit_log();
    assert_eq!(events.len(), 2);
    assert!(!events[0].is_revoked); // direct token check passes
    assert!(events[1].is_revoked); // transitive key check fails
    assert!(events[1].transitive);
}

#[test]
fn token_acceptance_denial_fields_complete() {
    let mut enforcer = make_enforcer();
    let target_bytes = [0x36; 32];
    revoke_target(&mut enforcer, RevocationTargetType::Token, target_bytes);

    let token_jti = EngineObjectId(target_bytes);
    let issuer_key = VerificationKey::from_bytes([0x37; 32]);
    let result = enforcer.check_token_acceptance(&token_jti, &issuer_key, "t-tok-7");

    if let EnforcementResult::Denied(denial) = result {
        assert_eq!(denial.target_type, RevocationTargetType::Token);
        assert_eq!(denial.target_id.0, target_bytes);
        assert!(!denial.transitive);
        assert!(denial.transitive_root.is_none());
        assert_eq!(denial.enforcement_point, EnforcementPoint::TokenAcceptance);
    } else {
        panic!("expected Denied");
    }
}

#[test]
fn token_acceptance_transitive_denial_root_is_key_id() {
    let mut enforcer = make_enforcer();
    let issuer_key = VerificationKey::from_bytes([0x38; 32]);
    let expected_root = key_id_from_verification_key(&issuer_key);
    revoke_target(
        &mut enforcer,
        RevocationTargetType::Key,
        *expected_root.as_bytes(),
    );

    let token_jti = EngineObjectId([0x39; 32]);
    let result = enforcer.check_token_acceptance(&token_jti, &issuer_key, "t-tok-8");

    if let EnforcementResult::Denied(denial) = result {
        assert!(denial.transitive);
        assert_eq!(denial.transitive_root.unwrap(), expected_root);
    } else {
        panic!("expected transitive Denied");
    }
}

// ---------------------------------------------------------------------------
// 2. High-risk operation enforcement (6+ tests)
// ---------------------------------------------------------------------------

#[test]
fn high_risk_cleared_for_valid_attestation() {
    let mut enforcer = make_enforcer();
    let attestation_id = EngineObjectId([0x40; 32]);
    let principal_key = VerificationKey::from_bytes([0x41; 32]);

    let result = enforcer.check_high_risk_operation(
        &attestation_id,
        &principal_key,
        HighRiskCategory::PolicyChange,
        "t-hr-1",
    );
    assert!(result.is_cleared());
    if let EnforcementResult::Cleared {
        checks_performed,
        enforcement_point,
    } = result
    {
        assert_eq!(checks_performed, 2);
        assert_eq!(enforcement_point, EnforcementPoint::HighRiskOperation);
    }
}

#[test]
fn high_risk_denied_for_revoked_attestation() {
    let mut enforcer = make_enforcer();
    let target_bytes = [0x42; 32];
    revoke_target(
        &mut enforcer,
        RevocationTargetType::Attestation,
        target_bytes,
    );

    let attestation_id = EngineObjectId(target_bytes);
    let principal_key = VerificationKey::from_bytes([0x43; 32]);
    let result = enforcer.check_high_risk_operation(
        &attestation_id,
        &principal_key,
        HighRiskCategory::KeyOperation,
        "t-hr-2",
    );

    match result {
        EnforcementResult::Denied(denial) => {
            assert_eq!(denial.target_type, RevocationTargetType::Attestation);
            assert_eq!(denial.target_id, attestation_id);
            assert!(!denial.transitive);
            assert!(denial.transitive_root.is_none());
            assert_eq!(
                denial.enforcement_point,
                EnforcementPoint::HighRiskOperation
            );
        }
        _ => panic!("expected Denied"),
    }
}

#[test]
fn high_risk_denied_for_revoked_principal_key() {
    let mut enforcer = make_enforcer();
    let principal_key = VerificationKey::from_bytes([0x44; 32]);
    let key_id = key_id_from_verification_key(&principal_key);
    revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());

    let attestation_id = EngineObjectId([0x45; 32]);
    let result = enforcer.check_high_risk_operation(
        &attestation_id,
        &principal_key,
        HighRiskCategory::DataExport,
        "t-hr-3",
    );

    match result {
        EnforcementResult::Denied(denial) => {
            assert!(denial.transitive);
            assert_eq!(denial.transitive_root, Some(key_id));
            assert_eq!(denial.target_type, RevocationTargetType::Attestation);
        }
        _ => panic!("expected transitive Denied"),
    }
}

#[test]
fn high_risk_all_categories_accepted_when_not_revoked() {
    let categories = [
        HighRiskCategory::PolicyChange,
        HighRiskCategory::KeyOperation,
        HighRiskCategory::DataExport,
        HighRiskCategory::CrossZoneAction,
        HighRiskCategory::ExtensionLifecycleChange,
    ];
    for (idx, category) in categories.iter().enumerate() {
        let mut enforcer = make_enforcer();
        let attestation_id = EngineObjectId([0x50 + idx as u8; 32]);
        let principal_key = VerificationKey::from_bytes([0x60 + idx as u8; 32]);
        let result = enforcer.check_high_risk_operation(
            &attestation_id,
            &principal_key,
            *category,
            "t-hr-cat",
        );
        assert!(result.is_cleared(), "category {category} should be cleared");
    }
}

#[test]
fn high_risk_audit_events_emitted_correctly() {
    let mut enforcer = make_enforcer();
    let attestation_id = EngineObjectId([0x46; 32]);
    let principal_key = VerificationKey::from_bytes([0x47; 32]);
    enforcer.check_high_risk_operation(
        &attestation_id,
        &principal_key,
        HighRiskCategory::CrossZoneAction,
        "t-hr-audit",
    );
    let events = enforcer.drain_audit_log();
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[0].enforcement_point,
        EnforcementPoint::HighRiskOperation
    );
    assert_eq!(
        events[1].enforcement_point,
        EnforcementPoint::HighRiskOperation
    );
    assert!(!events[0].transitive);
    assert!(events[1].transitive);
}

#[test]
fn high_risk_denied_attestation_emits_one_event() {
    let mut enforcer = make_enforcer();
    let target_bytes = [0x48; 32];
    revoke_target(
        &mut enforcer,
        RevocationTargetType::Attestation,
        target_bytes,
    );
    enforcer.drain_audit_log();

    let attestation_id = EngineObjectId(target_bytes);
    let principal_key = VerificationKey::from_bytes([0x49; 32]);
    enforcer.check_high_risk_operation(
        &attestation_id,
        &principal_key,
        HighRiskCategory::ExtensionLifecycleChange,
        "t-hr-6",
    );
    let events = enforcer.drain_audit_log();
    assert_eq!(events.len(), 1);
    assert!(events[0].is_revoked);
}

// ---------------------------------------------------------------------------
// 3. Extension activation enforcement (6+ tests)
// ---------------------------------------------------------------------------

#[test]
fn extension_activation_cleared_for_valid_extension() {
    let mut enforcer = make_enforcer();
    let ext_id = EngineObjectId([0x70; 32]);
    let signing_key = VerificationKey::from_bytes([0x71; 32]);

    let result = enforcer.check_extension_activation(&ext_id, &signing_key, "t-ext-1");
    assert!(result.is_cleared());
    if let EnforcementResult::Cleared {
        checks_performed,
        enforcement_point,
    } = result
    {
        assert_eq!(checks_performed, 2);
        assert_eq!(enforcement_point, EnforcementPoint::ExtensionActivation);
    }
}

#[test]
fn extension_activation_denied_for_revoked_extension() {
    let mut enforcer = make_enforcer();
    let target_bytes = [0x72; 32];
    revoke_target(&mut enforcer, RevocationTargetType::Extension, target_bytes);

    let ext_id = EngineObjectId(target_bytes);
    let signing_key = VerificationKey::from_bytes([0x73; 32]);
    let result = enforcer.check_extension_activation(&ext_id, &signing_key, "t-ext-2");

    match result {
        EnforcementResult::Denied(denial) => {
            assert_eq!(denial.target_type, RevocationTargetType::Extension);
            assert_eq!(denial.target_id, ext_id);
            assert!(!denial.transitive);
            assert!(denial.transitive_root.is_none());
            assert_eq!(
                denial.enforcement_point,
                EnforcementPoint::ExtensionActivation
            );
        }
        _ => panic!("expected Denied"),
    }
}

#[test]
fn extension_activation_denied_for_revoked_signing_key() {
    let mut enforcer = make_enforcer();
    let signing_key = VerificationKey::from_bytes([0x74; 32]);
    let key_id = key_id_from_verification_key(&signing_key);
    revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());

    let ext_id = EngineObjectId([0x75; 32]);
    let result = enforcer.check_extension_activation(&ext_id, &signing_key, "t-ext-3");

    match result {
        EnforcementResult::Denied(denial) => {
            assert!(denial.transitive);
            assert_eq!(denial.transitive_root, Some(key_id));
            assert_eq!(denial.target_type, RevocationTargetType::Extension);
            assert_eq!(denial.target_id, ext_id);
        }
        _ => panic!("expected transitive Denied"),
    }
}

#[test]
fn extension_activation_denial_fields_correct() {
    let mut enforcer = make_enforcer();
    let target_bytes = [0x76; 32];
    revoke_target(&mut enforcer, RevocationTargetType::Extension, target_bytes);

    let ext_id = EngineObjectId(target_bytes);
    let signing_key = VerificationKey::from_bytes([0x77; 32]);
    let result = enforcer.check_extension_activation(&ext_id, &signing_key, "t-ext-4");

    if let EnforcementResult::Denied(denial) = result {
        assert_eq!(denial.target_type, RevocationTargetType::Extension);
        assert_eq!(denial.target_id.0, target_bytes);
        assert!(!denial.transitive);
        assert!(denial.transitive_root.is_none());
        assert_eq!(
            denial.enforcement_point,
            EnforcementPoint::ExtensionActivation
        );
    } else {
        panic!("expected Denied");
    }
}

#[test]
fn extension_activation_cleared_emits_two_audit_events() {
    let mut enforcer = make_enforcer();
    let ext_id = EngineObjectId([0x78; 32]);
    let signing_key = VerificationKey::from_bytes([0x79; 32]);
    enforcer.check_extension_activation(&ext_id, &signing_key, "t-ext-5");
    let events = enforcer.drain_audit_log();
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[0].enforcement_point,
        EnforcementPoint::ExtensionActivation
    );
    assert_eq!(
        events[1].enforcement_point,
        EnforcementPoint::ExtensionActivation
    );
    assert!(!events[0].is_revoked);
    assert!(!events[1].is_revoked);
}

#[test]
fn extension_activation_transitive_denial_emits_two_events() {
    let mut enforcer = make_enforcer();
    let signing_key = VerificationKey::from_bytes([0x7A; 32]);
    let key_id = key_id_from_verification_key(&signing_key);
    revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());
    enforcer.drain_audit_log();

    let ext_id = EngineObjectId([0x7B; 32]);
    enforcer.check_extension_activation(&ext_id, &signing_key, "t-ext-6");
    let events = enforcer.drain_audit_log();
    assert_eq!(events.len(), 2);
    assert!(!events[0].is_revoked); // direct ext check passes
    assert!(events[1].is_revoked); // transitive key check fails
}

// ---------------------------------------------------------------------------
// 4. Batch token check (5+ tests)
// ---------------------------------------------------------------------------

#[test]
fn batch_all_valid_cleared_with_correct_checks() {
    let mut enforcer = make_enforcer();
    let tokens = vec![
        (
            EngineObjectId([0x80; 32]),
            VerificationKey::from_bytes([0x81; 32]),
        ),
        (
            EngineObjectId([0x82; 32]),
            VerificationKey::from_bytes([0x83; 32]),
        ),
        (
            EngineObjectId([0x84; 32]),
            VerificationKey::from_bytes([0x85; 32]),
        ),
    ];

    let result = enforcer.check_token_batch(&tokens, "t-batch-1");
    assert!(result.is_cleared());
    if let EnforcementResult::Cleared {
        checks_performed, ..
    } = result
    {
        assert_eq!(checks_performed, 6); // 3 tokens * 2 checks each
    }
}

#[test]
fn batch_second_token_revoked_denied() {
    let mut enforcer = make_enforcer();
    let revoked_bytes = [0x87; 32];
    revoke_target(&mut enforcer, RevocationTargetType::Token, revoked_bytes);

    let tokens = vec![
        (
            EngineObjectId([0x86; 32]),
            VerificationKey::from_bytes([0x88; 32]),
        ),
        (
            EngineObjectId(revoked_bytes),
            VerificationKey::from_bytes([0x89; 32]),
        ),
        (
            EngineObjectId([0x8A; 32]),
            VerificationKey::from_bytes([0x8B; 32]),
        ),
    ];

    let result = enforcer.check_token_batch(&tokens, "t-batch-2");
    match result {
        EnforcementResult::Denied(denial) => {
            assert_eq!(denial.target_id, EngineObjectId(revoked_bytes));
        }
        _ => panic!("expected Denied"),
    }

    // First token was checked (2 events), second token stopped at denial (1 event)
    let events = enforcer.drain_audit_log();
    // chain append events + first token (2) + second token (1) = 3 check events (ignoring chain events)
    let check_events: Vec<_> = events
        .iter()
        .filter(|e| e.enforcement_point == EnforcementPoint::TokenAcceptance)
        .collect();
    assert_eq!(check_events.len(), 3); // 2 for first valid + 1 for denied
}

#[test]
fn batch_empty_cleared_with_zero_checks() {
    let mut enforcer = make_enforcer();
    let tokens: Vec<(EngineObjectId, VerificationKey)> = vec![];

    let result = enforcer.check_token_batch(&tokens, "t-batch-3");
    assert!(result.is_cleared());
    if let EnforcementResult::Cleared {
        checks_performed, ..
    } = result
    {
        assert_eq!(checks_performed, 0);
    }
}

#[test]
fn batch_single_token_valid() {
    let mut enforcer = make_enforcer();
    let tokens = vec![(
        EngineObjectId([0x8C; 32]),
        VerificationKey::from_bytes([0x8D; 32]),
    )];

    let result = enforcer.check_token_batch(&tokens, "t-batch-4");
    assert!(result.is_cleared());
    if let EnforcementResult::Cleared {
        checks_performed, ..
    } = result
    {
        assert_eq!(checks_performed, 2);
    }
}

#[test]
fn batch_many_tokens_one_key_revoked_all_denied_transitively() {
    let mut enforcer = make_enforcer();
    let shared_key = VerificationKey::from_bytes([0x8E; 32]);
    let key_id = key_id_from_verification_key(&shared_key);
    revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());

    // All tokens share the same revoked issuer key
    let tokens = vec![
        (EngineObjectId([0x90; 32]), shared_key.clone()),
        (EngineObjectId([0x91; 32]), shared_key.clone()),
        (EngineObjectId([0x92; 32]), shared_key.clone()),
    ];

    let result = enforcer.check_token_batch(&tokens, "t-batch-5");
    match result {
        EnforcementResult::Denied(denial) => {
            assert!(denial.transitive);
            assert_eq!(denial.target_id, EngineObjectId([0x90; 32])); // first token
        }
        _ => panic!("expected transitive Denied"),
    }
}

// ---------------------------------------------------------------------------
// 5. Statistics tracking (5+ tests)
// ---------------------------------------------------------------------------

#[test]
fn stats_cleared_and_denied_accumulate() {
    let mut enforcer = make_enforcer();

    // Two cleared
    enforcer.check_token_acceptance(
        &EngineObjectId([0xA0; 32]),
        &VerificationKey::from_bytes([0xA1; 32]),
        "t-stat-1",
    );
    enforcer.check_token_acceptance(
        &EngineObjectId([0xA2; 32]),
        &VerificationKey::from_bytes([0xA3; 32]),
        "t-stat-2",
    );

    // One denied (direct)
    revoke_target(&mut enforcer, RevocationTargetType::Token, [0xA4; 32]);
    enforcer.check_token_acceptance(
        &EngineObjectId([0xA4; 32]),
        &VerificationKey::from_bytes([0xA5; 32]),
        "t-stat-3",
    );

    let stats = enforcer.stats();
    let token_stats = &stats[&EnforcementPoint::TokenAcceptance];
    assert_eq!(token_stats.checks, 3);
    assert_eq!(token_stats.cleared, 2);
    assert_eq!(token_stats.denied, 1);
}

#[test]
fn stats_transitive_denials_tracked_separately() {
    let mut enforcer = make_enforcer();
    let issuer_key = VerificationKey::from_bytes([0xA6; 32]);
    let key_id = key_id_from_verification_key(&issuer_key);
    revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());

    enforcer.check_token_acceptance(&EngineObjectId([0xA7; 32]), &issuer_key, "t-stat-trans");

    let stats = enforcer.stats();
    let token_stats = &stats[&EnforcementPoint::TokenAcceptance];
    assert_eq!(token_stats.denied, 1);
    assert_eq!(token_stats.transitive_denials, 1);
}

#[test]
fn stats_per_enforcement_point() {
    let mut enforcer = make_enforcer();

    enforcer.check_token_acceptance(
        &EngineObjectId([0xB0; 32]),
        &VerificationKey::from_bytes([0xB1; 32]),
        "t-stat-ep-1",
    );
    enforcer.check_high_risk_operation(
        &EngineObjectId([0xB2; 32]),
        &VerificationKey::from_bytes([0xB3; 32]),
        HighRiskCategory::PolicyChange,
        "t-stat-ep-2",
    );
    enforcer.check_extension_activation(
        &EngineObjectId([0xB4; 32]),
        &VerificationKey::from_bytes([0xB5; 32]),
        "t-stat-ep-3",
    );

    let stats = enforcer.stats();
    assert_eq!(stats[&EnforcementPoint::TokenAcceptance].cleared, 1);
    assert_eq!(stats[&EnforcementPoint::HighRiskOperation].cleared, 1);
    assert_eq!(stats[&EnforcementPoint::ExtensionActivation].cleared, 1);
}

#[test]
fn stats_multiple_enforcement_points_tracked_independently() {
    let mut enforcer = make_enforcer();

    // Token: 1 cleared
    enforcer.check_token_acceptance(
        &EngineObjectId([0xB6; 32]),
        &VerificationKey::from_bytes([0xB7; 32]),
        "t-stat-ind-1",
    );

    // High-risk: 1 denied (direct attestation revoked)
    revoke_target(&mut enforcer, RevocationTargetType::Attestation, [0xB8; 32]);
    enforcer.check_high_risk_operation(
        &EngineObjectId([0xB8; 32]),
        &VerificationKey::from_bytes([0xB9; 32]),
        HighRiskCategory::DataExport,
        "t-stat-ind-2",
    );

    let stats = enforcer.stats();
    let token_stats = &stats[&EnforcementPoint::TokenAcceptance];
    let hr_stats = &stats[&EnforcementPoint::HighRiskOperation];

    assert_eq!(token_stats.cleared, 1);
    assert_eq!(token_stats.denied, 0);
    assert_eq!(hr_stats.cleared, 0);
    assert_eq!(hr_stats.denied, 1);
}

#[test]
fn stats_default_are_all_zeros() {
    let stats = EnforcementStats::default();
    assert_eq!(stats.checks, 0);
    assert_eq!(stats.cleared, 0);
    assert_eq!(stats.denied, 0);
    assert_eq!(stats.transitive_denials, 0);
}

// ---------------------------------------------------------------------------
// 6. Audit log (5+ tests)
// ---------------------------------------------------------------------------

#[test]
fn drain_audit_log_clears_and_returns_events() {
    let mut enforcer = make_enforcer();
    enforcer.check_token_acceptance(
        &EngineObjectId([0xC0; 32]),
        &VerificationKey::from_bytes([0xC1; 32]),
        "t-audit-drain",
    );
    let events1 = enforcer.drain_audit_log();
    assert_eq!(events1.len(), 2);

    let events2 = enforcer.drain_audit_log();
    assert!(events2.is_empty());
}

#[test]
fn audit_events_contain_correct_trace_id() {
    let mut enforcer = make_enforcer();
    enforcer.check_token_acceptance(
        &EngineObjectId([0xC2; 32]),
        &VerificationKey::from_bytes([0xC3; 32]),
        "unique-trace-42",
    );
    let events = enforcer.drain_audit_log();
    for event in &events {
        assert_eq!(event.trace_id, "unique-trace-42");
    }
}

#[test]
fn audit_events_contain_correct_timestamp() {
    let mut enforcer = make_enforcer(); // tick = 5000
    enforcer.check_token_acceptance(
        &EngineObjectId([0xC4; 32]),
        &VerificationKey::from_bytes([0xC5; 32]),
        "t-ts",
    );
    let events = enforcer.drain_audit_log();
    for event in &events {
        assert_eq!(event.checked_at, DeterministicTimestamp(5000));
    }
}

#[test]
fn set_tick_updates_timestamps() {
    let mut enforcer = make_enforcer(); // tick = 5000
    enforcer.set_tick(9999);

    enforcer.check_extension_activation(
        &EngineObjectId([0xC6; 32]),
        &VerificationKey::from_bytes([0xC7; 32]),
        "t-new-tick",
    );
    let events = enforcer.drain_audit_log();
    for event in &events {
        assert_eq!(event.checked_at, DeterministicTimestamp(9999));
    }
}

#[test]
fn audit_events_from_all_enforcement_points() {
    let mut enforcer = make_enforcer();

    enforcer.check_token_acceptance(
        &EngineObjectId([0xD0; 32]),
        &VerificationKey::from_bytes([0xD1; 32]),
        "t-all-1",
    );
    enforcer.check_high_risk_operation(
        &EngineObjectId([0xD2; 32]),
        &VerificationKey::from_bytes([0xD3; 32]),
        HighRiskCategory::PolicyChange,
        "t-all-2",
    );
    enforcer.check_extension_activation(
        &EngineObjectId([0xD4; 32]),
        &VerificationKey::from_bytes([0xD5; 32]),
        "t-all-3",
    );

    let events = enforcer.drain_audit_log();
    assert_eq!(events.len(), 6);

    let token_count = events
        .iter()
        .filter(|e| e.enforcement_point == EnforcementPoint::TokenAcceptance)
        .count();
    let hr_count = events
        .iter()
        .filter(|e| e.enforcement_point == EnforcementPoint::HighRiskOperation)
        .count();
    let ext_count = events
        .iter()
        .filter(|e| e.enforcement_point == EnforcementPoint::ExtensionActivation)
        .count();

    assert_eq!(token_count, 2);
    assert_eq!(hr_count, 2);
    assert_eq!(ext_count, 2);
}

// ---------------------------------------------------------------------------
// 7. key_id_from_verification_key (3+ tests)
// ---------------------------------------------------------------------------

#[test]
fn key_id_deterministic() {
    let vk = VerificationKey::from_bytes([0xE0; 32]);
    let id1 = key_id_from_verification_key(&vk);
    let id2 = key_id_from_verification_key(&vk);
    assert_eq!(id1, id2);
}

#[test]
fn key_id_different_keys_produce_different_ids() {
    let vk1 = VerificationKey::from_bytes([0xE1; 32]);
    let vk2 = VerificationKey::from_bytes([0xE2; 32]);
    assert_ne!(
        key_id_from_verification_key(&vk1),
        key_id_from_verification_key(&vk2),
    );
}

#[test]
fn key_id_returns_engine_object_id() {
    let vk = VerificationKey::from_bytes([0xE3; 32]);
    let id = key_id_from_verification_key(&vk);
    // EngineObjectId is a 32-byte array wrapper; confirm it's non-zero
    assert_ne!(id.0, [0u8; 32]);
}

// ---------------------------------------------------------------------------
// 8. EnforcementResult (4+ tests)
// ---------------------------------------------------------------------------

#[test]
fn enforcement_result_into_result_cleared_is_ok() {
    let result = EnforcementResult::Cleared {
        enforcement_point: EnforcementPoint::TokenAcceptance,
        checks_performed: 2,
    };
    assert!(result.into_result().is_ok());
}

#[test]
fn enforcement_result_into_result_denied_is_err() {
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Token,
        target_id: EngineObjectId([0xF0; 32]),
        transitive: false,
        transitive_root: None,
        enforcement_point: EnforcementPoint::TokenAcceptance,
    };
    let result = EnforcementResult::Denied(denial.clone());
    let err = result.into_result().unwrap_err();
    assert_eq!(err, denial);
}

#[test]
fn enforcement_result_is_cleared_true_for_cleared() {
    let result = EnforcementResult::Cleared {
        enforcement_point: EnforcementPoint::HighRiskOperation,
        checks_performed: 2,
    };
    assert!(result.is_cleared());
}

#[test]
fn enforcement_result_is_cleared_false_for_denied() {
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Extension,
        target_id: EngineObjectId([0xF1; 32]),
        transitive: true,
        transitive_root: Some(EngineObjectId([0xF2; 32])),
        enforcement_point: EnforcementPoint::ExtensionActivation,
    };
    let result = EnforcementResult::Denied(denial);
    assert!(!result.is_cleared());
}

// ---------------------------------------------------------------------------
// 9. Display traits (4+ tests)
// ---------------------------------------------------------------------------

#[test]
fn enforcement_point_display_all_variants() {
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
fn high_risk_category_display_all_variants() {
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
fn revocation_denial_display_direct() {
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Token,
        target_id: EngineObjectId([0x01; 32]),
        transitive: false,
        transitive_root: None,
        enforcement_point: EnforcementPoint::TokenAcceptance,
    };
    let display = denial.to_string();
    assert!(display.contains("directly revoked"));
    assert!(display.contains("token_acceptance"));
    assert!(display.contains("token"));
}

#[test]
fn revocation_denial_display_transitive() {
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Extension,
        target_id: EngineObjectId([0x02; 32]),
        transitive: true,
        transitive_root: Some(EngineObjectId([0x03; 32])),
        enforcement_point: EnforcementPoint::ExtensionActivation,
    };
    let display = denial.to_string();
    assert!(display.contains("transitively revoked"));
    assert!(display.contains("extension_activation"));
}

// ---------------------------------------------------------------------------
// 10. Serde roundtrips (6+ tests)
// ---------------------------------------------------------------------------

#[test]
fn serde_enforcement_point_all_variants() {
    let points = [
        EnforcementPoint::TokenAcceptance,
        EnforcementPoint::HighRiskOperation,
        EnforcementPoint::ExtensionActivation,
    ];
    for point in &points {
        let json = serde_json::to_string(point).unwrap();
        let restored: EnforcementPoint = serde_json::from_str(&json).unwrap();
        assert_eq!(*point, restored);
    }
}

#[test]
fn serde_high_risk_category_all_variants() {
    let categories = [
        HighRiskCategory::PolicyChange,
        HighRiskCategory::KeyOperation,
        HighRiskCategory::DataExport,
        HighRiskCategory::CrossZoneAction,
        HighRiskCategory::ExtensionLifecycleChange,
    ];
    for category in &categories {
        let json = serde_json::to_string(category).unwrap();
        let restored: HighRiskCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*category, restored);
    }
}

#[test]
fn serde_revocation_denial_roundtrip() {
    let denial = RevocationDenial {
        target_type: RevocationTargetType::Token,
        target_id: EngineObjectId([0xAA; 32]),
        transitive: true,
        transitive_root: Some(EngineObjectId([0xBB; 32])),
        enforcement_point: EnforcementPoint::TokenAcceptance,
    };
    let json = serde_json::to_string(&denial).unwrap();
    let restored: RevocationDenial = serde_json::from_str(&json).unwrap();
    assert_eq!(denial, restored);
}

#[test]
fn serde_revocation_check_event_roundtrip() {
    let event = RevocationCheckEvent {
        enforcement_point: EnforcementPoint::HighRiskOperation,
        target_id: EngineObjectId([0xCC; 32]),
        target_type: RevocationTargetType::Attestation,
        is_revoked: true,
        transitive: false,
        trace_id: "t-serde-event".to_string(),
        checked_at: DeterministicTimestamp(12345),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: RevocationCheckEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn serde_enforcement_stats_roundtrip() {
    let stats = EnforcementStats {
        checks: 100,
        cleared: 85,
        denied: 15,
        transitive_denials: 7,
    };
    let json = serde_json::to_string(&stats).unwrap();
    let restored: EnforcementStats = serde_json::from_str(&json).unwrap();
    assert_eq!(stats, restored);
}

#[test]
fn serde_enforcement_result_cleared_roundtrip() {
    let cleared = EnforcementResult::Cleared {
        enforcement_point: EnforcementPoint::ExtensionActivation,
        checks_performed: 2,
    };
    let json = serde_json::to_string(&cleared).unwrap();
    let restored: EnforcementResult = serde_json::from_str(&json).unwrap();
    assert_eq!(cleared, restored);
}

#[test]
fn serde_enforcement_result_denied_roundtrip() {
    let denied = EnforcementResult::Denied(RevocationDenial {
        target_type: RevocationTargetType::Extension,
        target_id: EngineObjectId([0xDD; 32]),
        transitive: false,
        transitive_root: None,
        enforcement_point: EnforcementPoint::ExtensionActivation,
    });
    let json = serde_json::to_string(&denied).unwrap();
    let restored: EnforcementResult = serde_json::from_str(&json).unwrap();
    assert_eq!(denied, restored);
}

// ---------------------------------------------------------------------------
// 11. Determinism and multi-step (3+ tests)
// ---------------------------------------------------------------------------

#[test]
fn same_inputs_identical_results() {
    let mut enforcer1 = make_enforcer();
    let mut enforcer2 = make_enforcer();

    let token_jti = EngineObjectId([0xF3; 32]);
    let issuer_key = VerificationKey::from_bytes([0xF4; 32]);

    let r1 = enforcer1.check_token_acceptance(&token_jti, &issuer_key, "t-det-1");
    let r2 = enforcer2.check_token_acceptance(&token_jti, &issuer_key, "t-det-1");
    assert_eq!(r1, r2);

    let events1 = enforcer1.drain_audit_log();
    let events2 = enforcer2.drain_audit_log();
    assert_eq!(events1, events2);
}

#[test]
fn multiple_revocations_all_enforced() {
    let mut enforcer = make_enforcer();

    revoke_target(&mut enforcer, RevocationTargetType::Token, [0xF5; 32]);
    revoke_target(&mut enforcer, RevocationTargetType::Attestation, [0xF6; 32]);
    revoke_target(&mut enforcer, RevocationTargetType::Extension, [0xF7; 32]);

    let r1 = enforcer.check_token_acceptance(
        &EngineObjectId([0xF5; 32]),
        &VerificationKey::from_bytes([0xF8; 32]),
        "t-multi-tok",
    );
    assert!(!r1.is_cleared());

    let r2 = enforcer.check_high_risk_operation(
        &EngineObjectId([0xF6; 32]),
        &VerificationKey::from_bytes([0xF9; 32]),
        HighRiskCategory::PolicyChange,
        "t-multi-hr",
    );
    assert!(!r2.is_cleared());

    let r3 = enforcer.check_extension_activation(
        &EngineObjectId([0xF7; 32]),
        &VerificationKey::from_bytes([0xFA; 32]),
        "t-multi-ext",
    );
    assert!(!r3.is_cleared());
}

#[test]
fn chain_access_through_enforcer() {
    let mut enforcer = make_enforcer();

    // chain() returns immutable reference
    assert_eq!(enforcer.chain().zone(), TEST_ZONE);

    // chain_mut() allows appending
    let rev = make_revocation(
        RevocationTargetType::Token,
        RevocationReason::Compromised,
        [0xFB; 32],
    );
    let sk = test_signing_key();
    enforcer
        .chain_mut()
        .append(rev, &sk, "t-chain-mut")
        .unwrap();

    // Verify the revocation was added
    assert!(enforcer.chain().is_revoked(&EngineObjectId([0xFB; 32])));
}
