#![forbid(unsafe_code)]

//! Enrichment integration tests for capability_token.

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

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::capability_token::*;
use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;

// ── Helpers ──────────────────────────────────────────────────────────────

fn make_sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes([seed; 32])
}

fn make_principal(seed: u8) -> PrincipalId {
    PrincipalId::from_bytes([seed; 32])
}

fn make_checkpoint_ref(seq: u64) -> CheckpointRef {
    CheckpointRef {
        min_checkpoint_seq: seq,
        checkpoint_id: EngineObjectId([seq as u8; 32]),
    }
}

fn make_revocation_ref(seq: u64) -> RevocationFreshnessRef {
    RevocationFreshnessRef {
        min_revocation_seq: seq,
        revocation_head_hash: ContentHash::compute(&seq.to_be_bytes()),
    }
}

fn build_basic_token(sk: &SigningKey) -> CapabilityToken {
    TokenBuilder::new(
        sk.clone(),
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-enrich",
    )
    .add_audience(make_principal(10))
    .add_capability(RuntimeCapability::VmDispatch)
    .build()
    .unwrap()
}

fn basic_ctx() -> VerificationContext {
    VerificationContext {
        current_tick: 500,
        verifier_checkpoint_seq: 10,
        verifier_revocation_seq: 5,
    }
}

// ===========================================================================
// 1. PrincipalId — Clone independence, Display, serde
// ===========================================================================

#[test]
fn enrichment_principal_id_clone_independence() {
    let original = make_principal(42);
    let cloned = original.clone();
    assert_eq!(original, cloned);
    assert_eq!(original.as_bytes(), cloned.as_bytes());
}

#[test]
fn enrichment_principal_id_display_format() {
    let p = make_principal(0xAB);
    let display = p.to_string();
    assert!(
        display.starts_with("principal:"),
        "expected 'principal:' prefix, got {display}"
    );
}

#[test]
fn enrichment_principal_id_hex_length() {
    let p = make_principal(1);
    let hex = p.to_hex();
    assert_eq!(hex.len(), 64, "hex should be 64 chars for 32 bytes");
}

#[test]
fn enrichment_principal_id_from_verification_key_deterministic() {
    let sk = make_sk(99);
    let vk = sk.verification_key();
    let p1 = PrincipalId::from_verification_key(&vk);
    let p2 = PrincipalId::from_verification_key(&vk);
    assert_eq!(p1, p2);
}

#[test]
fn enrichment_principal_id_different_keys_different_ids() {
    let vk1 = make_sk(1).verification_key();
    let vk2 = make_sk(2).verification_key();
    let p1 = PrincipalId::from_verification_key(&vk1);
    let p2 = PrincipalId::from_verification_key(&vk2);
    assert_ne!(p1, p2);
}

#[test]
fn enrichment_principal_id_serde_roundtrip() {
    let p = make_principal(77);
    let json = serde_json::to_string(&p).unwrap();
    let restored: PrincipalId = serde_json::from_str(&json).unwrap();
    assert_eq!(p, restored);
}

// ===========================================================================
// 2. TokenVersion — Copy, Display, serde
// ===========================================================================

#[test]
fn enrichment_token_version_copy_semantics() {
    let a = TokenVersion::V2;
    let b = a;
    let c = a;
    assert_eq!(b, c);
}

#[test]
fn enrichment_token_version_display() {
    assert_eq!(TokenVersion::V2.to_string(), "v2");
}

#[test]
fn enrichment_token_version_serde_roundtrip() {
    let v = TokenVersion::V2;
    let json = serde_json::to_string(&v).unwrap();
    let restored: TokenVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, restored);
}

// ===========================================================================
// 3. TokenError — Display uniqueness, std::error::Error, Clone, serde
// ===========================================================================

#[test]
fn enrichment_token_error_display_all_unique() {
    let variants: Vec<TokenError> = vec![
        TokenError::SignatureInvalid {
            detail: "d".to_string(),
        },
        TokenError::NonCanonical {
            detail: "d".to_string(),
        },
        TokenError::AudienceRejected {
            presenter: make_principal(1),
            audience_size: 5,
        },
        TokenError::NotYetValid {
            current_tick: 1,
            not_before: 10,
        },
        TokenError::Expired {
            current_tick: 100,
            expiry: 50,
        },
        TokenError::CheckpointBindingFailed {
            required_seq: 5,
            verifier_seq: 3,
        },
        TokenError::RevocationFreshnessStale {
            required_seq: 5,
            verifier_seq: 3,
        },
        TokenError::UnsupportedVersion {
            version: "v99".to_string(),
        },
        TokenError::IdDerivationFailed {
            detail: "d".to_string(),
        },
        TokenError::InvertedTemporalWindow {
            not_before: 100,
            expiry: 50,
        },
        TokenError::EmptyCapabilities,
    ];
    let displays: BTreeSet<String> = variants.iter().map(|e| e.to_string()).collect();
    assert_eq!(
        displays.len(),
        variants.len(),
        "some Display outputs collide"
    );
}

#[test]
fn enrichment_token_error_debug_all_unique() {
    let variants: Vec<TokenError> = vec![
        TokenError::SignatureInvalid {
            detail: "d".to_string(),
        },
        TokenError::NonCanonical {
            detail: "d".to_string(),
        },
        TokenError::AudienceRejected {
            presenter: make_principal(1),
            audience_size: 5,
        },
        TokenError::NotYetValid {
            current_tick: 1,
            not_before: 10,
        },
        TokenError::Expired {
            current_tick: 100,
            expiry: 50,
        },
        TokenError::CheckpointBindingFailed {
            required_seq: 5,
            verifier_seq: 3,
        },
        TokenError::RevocationFreshnessStale {
            required_seq: 5,
            verifier_seq: 3,
        },
        TokenError::UnsupportedVersion {
            version: "v99".to_string(),
        },
        TokenError::IdDerivationFailed {
            detail: "d".to_string(),
        },
        TokenError::InvertedTemporalWindow {
            not_before: 100,
            expiry: 50,
        },
        TokenError::EmptyCapabilities,
    ];
    let debugs: BTreeSet<String> = variants.iter().map(|e| format!("{e:?}")).collect();
    assert_eq!(debugs.len(), variants.len());
}

#[test]
fn enrichment_token_error_is_std_error() {
    let err = TokenError::EmptyCapabilities;
    // std::error::Error is implemented
    let _: &dyn std::error::Error = &err;
}

#[test]
fn enrichment_token_error_clone_independence() {
    let original = TokenError::SignatureInvalid {
        detail: "original".to_string(),
    };
    let mut cloned = original.clone();
    if let TokenError::SignatureInvalid { ref mut detail } = cloned {
        *detail = "mutated".to_string();
    }
    if let TokenError::SignatureInvalid { detail } = &original {
        assert_eq!(detail, "original");
    }
}

#[test]
fn enrichment_token_error_serde_all_variants() {
    let variants: Vec<TokenError> = vec![
        TokenError::SignatureInvalid {
            detail: "d".to_string(),
        },
        TokenError::NonCanonical {
            detail: "d".to_string(),
        },
        TokenError::AudienceRejected {
            presenter: make_principal(1),
            audience_size: 5,
        },
        TokenError::NotYetValid {
            current_tick: 1,
            not_before: 10,
        },
        TokenError::Expired {
            current_tick: 100,
            expiry: 50,
        },
        TokenError::CheckpointBindingFailed {
            required_seq: 5,
            verifier_seq: 3,
        },
        TokenError::RevocationFreshnessStale {
            required_seq: 5,
            verifier_seq: 3,
        },
        TokenError::UnsupportedVersion {
            version: "v99".to_string(),
        },
        TokenError::IdDerivationFailed {
            detail: "d".to_string(),
        },
        TokenError::InvertedTemporalWindow {
            not_before: 100,
            expiry: 50,
        },
        TokenError::EmptyCapabilities,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: TokenError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

// ===========================================================================
// 4. CheckpointRef — Clone independence, serde
// ===========================================================================

#[test]
fn enrichment_checkpoint_ref_clone_independence() {
    let original = make_checkpoint_ref(42);
    let cloned = original.clone();
    assert_eq!(original, cloned);
    assert_eq!(original.min_checkpoint_seq, cloned.min_checkpoint_seq);
}

#[test]
fn enrichment_checkpoint_ref_serde_roundtrip() {
    let cr = make_checkpoint_ref(100);
    let json = serde_json::to_string(&cr).unwrap();
    let restored: CheckpointRef = serde_json::from_str(&json).unwrap();
    assert_eq!(cr, restored);
}

#[test]
fn enrichment_checkpoint_ref_json_field_names() {
    let cr = make_checkpoint_ref(5);
    let json = serde_json::to_string(&cr).unwrap();
    assert!(json.contains("\"min_checkpoint_seq\""));
    assert!(json.contains("\"checkpoint_id\""));
}

// ===========================================================================
// 5. RevocationFreshnessRef — Clone independence, serde
// ===========================================================================

#[test]
fn enrichment_revocation_freshness_ref_clone_independence() {
    let original = make_revocation_ref(10);
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_revocation_freshness_ref_serde_roundtrip() {
    let rf = make_revocation_ref(77);
    let json = serde_json::to_string(&rf).unwrap();
    let restored: RevocationFreshnessRef = serde_json::from_str(&json).unwrap();
    assert_eq!(rf, restored);
}

#[test]
fn enrichment_revocation_freshness_ref_json_field_names() {
    let rf = make_revocation_ref(5);
    let json = serde_json::to_string(&rf).unwrap();
    assert!(json.contains("\"min_revocation_seq\""));
    assert!(json.contains("\"revocation_head_hash\""));
}

// ===========================================================================
// 6. CapabilityToken — Clone independence, serde, determinism
// ===========================================================================

#[test]
fn enrichment_capability_token_clone_independence() {
    let sk = make_sk(1);
    let original = build_basic_token(&sk);
    let mut cloned = original.clone();
    cloned.zone = "mutated-zone".to_string();
    assert_eq!(original.zone, "zone-enrich");
    assert_eq!(cloned.zone, "mutated-zone");
}

#[test]
fn enrichment_capability_token_serde_roundtrip() {
    let sk = make_sk(1);
    let token = build_basic_token(&sk);
    let json = serde_json::to_string(&token).unwrap();
    let restored: CapabilityToken = serde_json::from_str(&json).unwrap();
    assert_eq!(token, restored);
}

#[test]
fn enrichment_capability_token_determinism_five_builds() {
    let sk = make_sk(1);
    let baseline = build_basic_token(&sk);
    for run in 1..=5 {
        let token = build_basic_token(&sk);
        assert_eq!(baseline.jti, token.jti, "jti diverged on run {run}");
        assert_eq!(
            baseline.signature, token.signature,
            "sig diverged on run {run}"
        );
    }
}

#[test]
fn enrichment_capability_token_json_field_names() {
    let sk = make_sk(1);
    let token = build_basic_token(&sk);
    let json = serde_json::to_string(&token).unwrap();
    assert!(json.contains("\"version\""));
    assert!(json.contains("\"jti\""));
    assert!(json.contains("\"issuer\""));
    assert!(json.contains("\"audience\""));
    assert!(json.contains("\"capabilities\""));
    assert!(json.contains("\"nbf\""));
    assert!(json.contains("\"expiry\""));
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"signature\""));
    assert!(json.contains("\"zone\""));
}

#[test]
fn enrichment_capability_token_debug_nonempty() {
    let sk = make_sk(1);
    let token = build_basic_token(&sk);
    let dbg = format!("{token:?}");
    assert!(dbg.contains("CapabilityToken"));
}

// ===========================================================================
// 7. TokenBuilder — validation edge cases
// ===========================================================================

#[test]
fn enrichment_builder_empty_capabilities_error() {
    let sk = make_sk(1);
    let result = TokenBuilder::new(
        sk,
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone",
    )
    .add_audience(make_principal(10))
    .build();
    assert!(result.is_err());
    if let Err(TokenError::EmptyCapabilities) = result {
        // expected
    } else {
        panic!("expected EmptyCapabilities error");
    }
}

#[test]
fn enrichment_builder_inverted_window_error() {
    let sk = make_sk(1);
    let result = TokenBuilder::new(
        sk,
        DeterministicTimestamp(1000), // nbf > expiry
        DeterministicTimestamp(100),
        SecurityEpoch::GENESIS,
        "zone",
    )
    .add_audience(make_principal(10))
    .add_capability(RuntimeCapability::VmDispatch)
    .build();
    assert!(result.is_err());
    if let Err(TokenError::InvertedTemporalWindow { not_before, expiry }) = result {
        assert_eq!(not_before, 1000);
        assert_eq!(expiry, 100);
    } else {
        panic!("expected InvertedTemporalWindow error");
    }
}

#[test]
fn enrichment_builder_equal_nbf_expiry_ok() {
    let sk = make_sk(1);
    let result = TokenBuilder::new(
        sk,
        DeterministicTimestamp(500),
        DeterministicTimestamp(500), // nbf == expiry is ok
        SecurityEpoch::GENESIS,
        "zone",
    )
    .add_audience(make_principal(10))
    .add_capability(RuntimeCapability::VmDispatch)
    .build();
    assert!(result.is_ok());
}

#[test]
fn enrichment_builder_multiple_audience_members() {
    let sk = make_sk(1);
    let token = TokenBuilder::new(
        sk,
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-multi-aud",
    )
    .add_audience(make_principal(10))
    .add_audience(make_principal(20))
    .add_audience(make_principal(30))
    .add_capability(RuntimeCapability::VmDispatch)
    .build()
    .unwrap();
    assert_eq!(token.audience.len(), 3);
}

#[test]
fn enrichment_builder_duplicate_audience_deduped() {
    let sk = make_sk(1);
    let token = TokenBuilder::new(
        sk,
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-dedup",
    )
    .add_audience(make_principal(10))
    .add_audience(make_principal(10)) // duplicate
    .add_capability(RuntimeCapability::VmDispatch)
    .build()
    .unwrap();
    assert_eq!(token.audience.len(), 1);
}

// ===========================================================================
// 8. verify_token — verification order and boundary checks
// ===========================================================================

#[test]
fn enrichment_verify_token_happy_path() {
    let sk = make_sk(1);
    let token = build_basic_token(&sk);
    let presenter = make_principal(10);
    let ctx = basic_ctx();
    assert!(verify_token(&token, &presenter, &ctx).is_ok());
}

#[test]
fn enrichment_verify_token_wrong_audience() {
    let sk = make_sk(1);
    let token = build_basic_token(&sk);
    let wrong_presenter = make_principal(99);
    let ctx = basic_ctx();
    let err = verify_token(&token, &wrong_presenter, &ctx).unwrap_err();
    assert!(matches!(err, TokenError::AudienceRejected { .. }));
}

#[test]
fn enrichment_verify_token_not_yet_valid() {
    let sk = make_sk(1);
    let token = build_basic_token(&sk);
    let presenter = make_principal(10);
    let ctx = VerificationContext {
        current_tick: 50, // Before nbf=100
        verifier_checkpoint_seq: 10,
        verifier_revocation_seq: 5,
    };
    let err = verify_token(&token, &presenter, &ctx).unwrap_err();
    assert!(matches!(err, TokenError::NotYetValid { .. }));
}

#[test]
fn enrichment_verify_token_expired() {
    let sk = make_sk(1);
    let token = build_basic_token(&sk);
    let presenter = make_principal(10);
    let ctx = VerificationContext {
        current_tick: 1001, // After expiry=1000
        verifier_checkpoint_seq: 10,
        verifier_revocation_seq: 5,
    };
    let err = verify_token(&token, &presenter, &ctx).unwrap_err();
    assert!(matches!(err, TokenError::Expired { .. }));
}

#[test]
fn enrichment_verify_token_at_exact_nbf() {
    let sk = make_sk(1);
    let token = build_basic_token(&sk);
    let presenter = make_principal(10);
    let ctx = VerificationContext {
        current_tick: 100, // exactly at nbf
        verifier_checkpoint_seq: 10,
        verifier_revocation_seq: 5,
    };
    assert!(verify_token(&token, &presenter, &ctx).is_ok());
}

#[test]
fn enrichment_verify_token_at_exact_expiry() {
    let sk = make_sk(1);
    let token = build_basic_token(&sk);
    let presenter = make_principal(10);
    let ctx = VerificationContext {
        current_tick: 1000, // exactly at expiry
        verifier_checkpoint_seq: 10,
        verifier_revocation_seq: 5,
    };
    assert!(verify_token(&token, &presenter, &ctx).is_ok());
}

#[test]
fn enrichment_verify_token_checkpoint_binding_failed() {
    let sk = make_sk(1);
    let token = TokenBuilder::new(
        sk,
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-ckpt",
    )
    .add_audience(make_principal(10))
    .add_capability(RuntimeCapability::VmDispatch)
    .bind_checkpoint(make_checkpoint_ref(20))
    .build()
    .unwrap();
    let presenter = make_principal(10);
    let ctx = VerificationContext {
        current_tick: 500,
        verifier_checkpoint_seq: 10, // Below required 20
        verifier_revocation_seq: 5,
    };
    let err = verify_token(&token, &presenter, &ctx).unwrap_err();
    assert!(matches!(err, TokenError::CheckpointBindingFailed { .. }));
}

#[test]
fn enrichment_verify_token_revocation_freshness_stale() {
    let sk = make_sk(1);
    let token = TokenBuilder::new(
        sk,
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-rev",
    )
    .add_audience(make_principal(10))
    .add_capability(RuntimeCapability::VmDispatch)
    .bind_revocation_freshness(make_revocation_ref(10))
    .build()
    .unwrap();
    let presenter = make_principal(10);
    let ctx = VerificationContext {
        current_tick: 500,
        verifier_checkpoint_seq: 10,
        verifier_revocation_seq: 5, // Below required 10
    };
    let err = verify_token(&token, &presenter, &ctx).unwrap_err();
    assert!(matches!(err, TokenError::RevocationFreshnessStale { .. }));
}

// ===========================================================================
// 9. TokenEventType — Display uniqueness, serde, Clone
// ===========================================================================

#[test]
fn enrichment_token_event_type_display_all_unique() {
    let jti = EngineObjectId([1; 32]);
    let variants = [
        TokenEventType::TokenIssued { jti: jti.clone() },
        TokenEventType::TokenVerified { jti: jti.clone() },
        TokenEventType::TokenRejected {
            jti,
            reason: "r".to_string(),
        },
    ];
    let displays: BTreeSet<String> = variants.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_token_event_type_serde_all_variants() {
    let jti = EngineObjectId([2; 32]);
    let variants = [
        TokenEventType::TokenIssued { jti: jti.clone() },
        TokenEventType::TokenVerified { jti: jti.clone() },
        TokenEventType::TokenRejected {
            jti,
            reason: "err".to_string(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: TokenEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

// ===========================================================================
// 10. TokenEvent — serde, Clone
// ===========================================================================

#[test]
fn enrichment_token_event_serde_roundtrip() {
    let event = TokenEvent {
        event_type: TokenEventType::TokenIssued {
            jti: EngineObjectId([3; 32]),
        },
        trace_id: "trace-001".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: TokenEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn enrichment_token_event_clone_independence() {
    let original = TokenEvent {
        event_type: TokenEventType::TokenIssued {
            jti: EngineObjectId([4; 32]),
        },
        trace_id: "trace-original".to_string(),
    };
    let mut cloned = original.clone();
    cloned.trace_id = "mutated".to_string();
    assert_eq!(original.trace_id, "trace-original");
    assert_eq!(cloned.trace_id, "mutated");
}

// ===========================================================================
// 11. Schema functions — stability
// ===========================================================================

#[test]
fn enrichment_token_schema_deterministic() {
    let s1 = token_schema();
    let s2 = token_schema();
    assert_eq!(s1, s2);
}

#[test]
fn enrichment_token_schema_id_deterministic() {
    let s1 = token_schema_id();
    let s2 = token_schema_id();
    assert_eq!(s1, s2);
}

// ===========================================================================
// 12. Different keys produce different tokens
// ===========================================================================

#[test]
fn enrichment_different_issuers_different_jti() {
    let t1 = build_basic_token(&make_sk(1));
    let t2 = build_basic_token(&make_sk(2));
    assert_ne!(t1.jti, t2.jti);
    assert_ne!(t1.signature, t2.signature);
}

// ===========================================================================
// 13. Full token with all bindings serde roundtrip
// ===========================================================================

#[test]
fn enrichment_full_token_all_bindings_serde_roundtrip() {
    let sk = make_sk(1);
    let token = TokenBuilder::new(
        sk,
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "zone-full",
    )
    .add_audience(make_principal(10))
    .add_audience(make_principal(20))
    .add_capability(RuntimeCapability::VmDispatch)
    .add_capability(RuntimeCapability::GcInvoke)
    .bind_checkpoint(make_checkpoint_ref(5))
    .bind_revocation_freshness(make_revocation_ref(3))
    .build()
    .unwrap();
    let json = serde_json::to_string(&token).unwrap();
    let restored: CapabilityToken = serde_json::from_str(&json).unwrap();
    assert_eq!(token, restored);
}
