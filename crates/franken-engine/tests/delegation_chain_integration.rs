#![forbid(unsafe_code)]

//! Integration tests for the `delegation_chain` module.
//!
//! Covers: DelegationChain, DelegationVerificationContext, ChainError,
//! RevocationOracle, NoRevocationOracle, DelegationLinkSummary,
//! AuthorizationProof, verify_chain, principal_id_from_verification_key,
//! DEFAULT_MAX_CHAIN_DEPTH, Display impls, serde round-trips,
//! state transitions, error conditions.

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
use frankenengine_engine::capability_token::{
    CapabilityToken, CheckpointRef, PrincipalId, RevocationFreshnessRef, TokenBuilder, TokenError,
    TokenId,
};
use frankenengine_engine::delegation_chain::{
    AuthorizationProof, ChainError, DEFAULT_MAX_CHAIN_DEPTH, DelegationChain,
    DelegationLinkSummary, DelegationVerificationContext, NoRevocationOracle, RevocationOracle,
    principal_id_from_verification_key, verify_chain,
};
use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{Signature, SigningKey, VerificationKey};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes([seed; 32])
}

fn make_principal(seed: u8) -> PrincipalId {
    PrincipalId::from_bytes([seed; 32])
}

fn make_bound_token(
    issuer_sk: &SigningKey,
    delegate: PrincipalId,
    caps: &[RuntimeCapability],
) -> CapabilityToken {
    let mut builder = TokenBuilder::new(
        issuer_sk.clone(),
        DeterministicTimestamp(100),
        DeterministicTimestamp(1_000),
        SecurityEpoch::GENESIS,
        "zone-a",
    )
    .add_audience(delegate)
    .bind_checkpoint(CheckpointRef {
        min_checkpoint_seq: 5,
        checkpoint_id: EngineObjectId([7; 32]),
    })
    .bind_revocation_freshness(RevocationFreshnessRef {
        min_revocation_seq: 3,
        revocation_head_hash: ContentHash::compute(b"rev-head"),
    });

    for cap in caps {
        builder = builder.add_capability(*cap);
    }
    builder.build().expect("token should build")
}

fn make_bound_token_in_zone(
    issuer_sk: &SigningKey,
    delegate: PrincipalId,
    caps: &[RuntimeCapability],
    zone: &str,
) -> CapabilityToken {
    let mut builder = TokenBuilder::new(
        issuer_sk.clone(),
        DeterministicTimestamp(100),
        DeterministicTimestamp(1_000),
        SecurityEpoch::GENESIS,
        zone,
    )
    .add_audience(delegate)
    .bind_checkpoint(CheckpointRef {
        min_checkpoint_seq: 5,
        checkpoint_id: EngineObjectId([7; 32]),
    })
    .bind_revocation_freshness(RevocationFreshnessRef {
        min_revocation_seq: 3,
        revocation_head_hash: ContentHash::compute(b"rev-head"),
    });

    for cap in caps {
        builder = builder.add_capability(*cap);
    }
    builder.build().expect("token should build")
}

fn valid_chain_fixture() -> (DelegationChain, SigningKey, PrincipalId) {
    let root_sk = make_sk(1);
    let issuer_sk = make_sk(2);
    let delegate_sk = make_sk(3);
    let leaf_delegate = make_principal(99);

    let link0 = make_bound_token(
        &root_sk,
        principal_id_from_verification_key(&issuer_sk.verification_key()),
        &[
            RuntimeCapability::VmDispatch,
            RuntimeCapability::NetworkEgress,
        ],
    );
    let link1 = make_bound_token(
        &issuer_sk,
        principal_id_from_verification_key(&delegate_sk.verification_key()),
        &[RuntimeCapability::VmDispatch],
    );
    let link2 = make_bound_token(
        &delegate_sk,
        leaf_delegate.clone(),
        &[RuntimeCapability::VmDispatch],
    );

    (
        DelegationChain::new(vec![link0, link1, link2]),
        root_sk,
        leaf_delegate,
    )
}

fn make_ctx(root_sk: &SigningKey) -> DelegationVerificationContext {
    let mut roots = BTreeSet::new();
    roots.insert(root_sk.verification_key());
    DelegationVerificationContext {
        current_tick: 500,
        verifier_checkpoint_seq: 10,
        verifier_revocation_seq: 10,
        max_chain_depth: DEFAULT_MAX_CHAIN_DEPTH,
        authorized_roots: roots,
        required_zone: Some("zone-a".to_string()),
    }
}

struct SetRevocationOracle {
    revoked: BTreeSet<TokenId>,
}

impl RevocationOracle for SetRevocationOracle {
    fn is_revoked(&self, token_id: &TokenId) -> bool {
        self.revoked.contains(token_id)
    }
}

// =========================================================================
// Section 1: DEFAULT_MAX_CHAIN_DEPTH
// =========================================================================

#[test]
fn default_max_chain_depth_value() {
    assert_eq!(DEFAULT_MAX_CHAIN_DEPTH, 8);
}

// =========================================================================
// Section 2: DelegationChain — construction, len, is_empty
// =========================================================================

#[test]
fn delegation_chain_new_empty() {
    let chain = DelegationChain::new(Vec::new());
    assert!(chain.is_empty());
    assert_eq!(chain.len(), 0);
}

#[test]
fn delegation_chain_new_with_links() {
    let (chain, _, _) = valid_chain_fixture();
    assert!(!chain.is_empty());
    assert_eq!(chain.len(), 3);
}

#[test]
fn delegation_chain_clone_equality() {
    let (chain, _, _) = valid_chain_fixture();
    let chain2 = chain.clone();
    assert_eq!(chain, chain2);
}

#[test]
fn delegation_chain_serde_round_trip() {
    let (chain, _, _) = valid_chain_fixture();
    let json = serde_json::to_string(&chain).expect("serialize");
    let restored: DelegationChain = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(chain, restored);
}

// =========================================================================
// Section 3: DelegationVerificationContext — construction, defaults
// =========================================================================

#[test]
fn verification_context_default_values() {
    let ctx = DelegationVerificationContext::default();
    assert_eq!(ctx.current_tick, 0);
    assert_eq!(ctx.verifier_checkpoint_seq, 0);
    assert_eq!(ctx.verifier_revocation_seq, 0);
    assert_eq!(ctx.max_chain_depth, DEFAULT_MAX_CHAIN_DEPTH);
    assert!(ctx.authorized_roots.is_empty());
    assert!(ctx.required_zone.is_none());
}

#[test]
fn verification_context_with_authorized_root() {
    let root_sk = make_sk(1);
    let ctx = DelegationVerificationContext::with_authorized_root(root_sk.verification_key());
    assert!(ctx.authorized_roots.contains(&root_sk.verification_key()));
    assert_eq!(ctx.authorized_roots.len(), 1);
    assert_eq!(ctx.max_chain_depth, DEFAULT_MAX_CHAIN_DEPTH);
}

#[test]
fn verification_context_serde_round_trip() {
    let root_sk = make_sk(1);
    let ctx = make_ctx(&root_sk);
    let json = serde_json::to_string(&ctx).expect("serialize");
    let restored: DelegationVerificationContext = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ctx, restored);
}

// =========================================================================
// Section 4: NoRevocationOracle
// =========================================================================

#[test]
fn no_revocation_oracle_never_revoked() {
    let oracle = NoRevocationOracle;
    let token_id = EngineObjectId([42; 32]);
    assert!(!oracle.is_revoked(&token_id));
}

#[test]
fn no_revocation_oracle_default() {
    let oracle = NoRevocationOracle;
    let token_id = EngineObjectId([0; 32]);
    assert!(!oracle.is_revoked(&token_id));
}

// =========================================================================
// Section 5: principal_id_from_verification_key
// =========================================================================

#[test]
fn principal_id_deterministic_from_key() {
    let sk = make_sk(42);
    let vk = sk.verification_key();
    let p1 = principal_id_from_verification_key(&vk);
    let p2 = principal_id_from_verification_key(&vk);
    assert_eq!(p1, p2);
}

#[test]
fn principal_id_different_keys_produce_different_principals() {
    let sk1 = make_sk(1);
    let sk2 = make_sk(2);
    let p1 = principal_id_from_verification_key(&sk1.verification_key());
    let p2 = principal_id_from_verification_key(&sk2.verification_key());
    assert_ne!(p1, p2);
}

// =========================================================================
// Section 6: ChainError — Display impls
// =========================================================================

#[test]
fn chain_error_display_empty_chain() {
    let err = ChainError::EmptyChain;
    let s = err.to_string();
    assert!(s.contains("empty"));
    assert!(s.contains("no ambient authority"));
}

#[test]
fn chain_error_display_depth_exceeded() {
    let err = ChainError::DepthExceeded {
        max_depth: 8,
        actual_depth: 12,
    };
    let s = err.to_string();
    assert!(s.contains("depth exceeded"));
    assert!(s.contains("8"));
    assert!(s.contains("12"));
}

#[test]
fn chain_error_display_unauthorized_root() {
    let vk = VerificationKey::from_bytes([0xAB; 32]);
    let err = ChainError::UnauthorizedRoot { root_issuer: vk };
    let s = err.to_string();
    assert!(s.contains("unauthorized root"));
}

#[test]
fn chain_error_display_missing_checkpoint_binding() {
    let err = ChainError::MissingCheckpointBinding { index: 2 };
    let s = err.to_string();
    assert!(s.contains("checkpoint binding"));
    assert!(s.contains("2"));
}

#[test]
fn chain_error_display_missing_revocation_freshness_binding() {
    let err = ChainError::MissingRevocationFreshnessBinding { index: 3 };
    let s = err.to_string();
    assert!(s.contains("revocation freshness"));
    assert!(s.contains("3"));
}

#[test]
fn chain_error_display_token_verification_failed() {
    let err = ChainError::TokenVerificationFailed {
        index: 1,
        error: TokenError::SignatureInvalid {
            detail: "test-issuer".to_string(),
        },
    };
    let s = err.to_string();
    assert!(s.contains("verification failed"));
    assert!(s.contains("1"));
}

#[test]
fn chain_error_display_attenuation_violation() {
    let mut amplified = BTreeSet::new();
    amplified.insert(RuntimeCapability::NetworkEgress);
    let err = ChainError::AttenuationViolation {
        index: 2,
        parent_capability_count: 1,
        child_capability_count: 3,
        amplified_capabilities: amplified,
    };
    let s = err.to_string();
    assert!(s.contains("attenuation"));
    assert!(s.contains("2"));
}

#[test]
fn chain_error_display_zone_mismatch() {
    let err = ChainError::ZoneMismatch {
        index: 1,
        expected_zone: "zone-a".to_string(),
        actual_zone: "zone-b".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("zone mismatch"));
    assert!(s.contains("zone-a"));
    assert!(s.contains("zone-b"));
}

#[test]
fn chain_error_display_revoked_link() {
    let token_id = EngineObjectId([0xDE; 32]);
    let err = ChainError::RevokedLink { index: 0, token_id };
    let s = err.to_string();
    assert!(s.contains("revoked"));
    assert!(s.contains("0"));
}

#[test]
fn chain_error_display_missing_capability_at_leaf() {
    let mut leaf_caps = BTreeSet::new();
    leaf_caps.insert(RuntimeCapability::GcInvoke);
    let err = ChainError::MissingCapabilityAtLeaf {
        required: RuntimeCapability::VmDispatch,
        leaf_capabilities: leaf_caps,
    };
    let s = err.to_string();
    assert!(s.contains("missing required capability"));
    assert!(s.contains("vm_dispatch"));
}

#[test]
fn chain_error_is_std_error() {
    let err = ChainError::EmptyChain;
    let _: &dyn std::error::Error = &err;
}

// =========================================================================
// Section 7: ChainError — serde round-trips
// =========================================================================

#[test]
fn chain_error_serde_round_trip_empty_chain() {
    let err = ChainError::EmptyChain;
    let json = serde_json::to_string(&err).expect("serialize");
    let restored: ChainError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, restored);
}

#[test]
fn chain_error_serde_round_trip_depth_exceeded() {
    let err = ChainError::DepthExceeded {
        max_depth: 8,
        actual_depth: 12,
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let restored: ChainError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, restored);
}

#[test]
fn chain_error_serde_round_trip_attenuation_violation() {
    let mut amplified = BTreeSet::new();
    amplified.insert(RuntimeCapability::NetworkEgress);
    amplified.insert(RuntimeCapability::FsWrite);
    let err = ChainError::AttenuationViolation {
        index: 2,
        parent_capability_count: 1,
        child_capability_count: 3,
        amplified_capabilities: amplified,
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let restored: ChainError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, restored);
}

// =========================================================================
// Section 8: verify_chain — valid chain
// =========================================================================

#[test]
fn valid_three_link_chain_verifies() {
    let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);
    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("chain should verify");

    assert_eq!(proof.authorized_capability, RuntimeCapability::VmDispatch);
    assert_eq!(proof.chain_summary.len(), 3);
    assert_eq!(proof.leaf_delegate, leaf_delegate);
    assert_eq!(proof.verified_at_tick, 500);
}

#[test]
fn chain_verify_method_delegates_correctly() {
    let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);
    let proof = chain
        .verify(
            RuntimeCapability::VmDispatch,
            &leaf_delegate,
            &ctx,
            &NoRevocationOracle,
        )
        .expect("chain.verify() should work");
    assert_eq!(proof.authorized_capability, RuntimeCapability::VmDispatch);
}

// =========================================================================
// Section 9: verify_chain — error conditions
// =========================================================================

#[test]
fn rejects_empty_chain() {
    let empty = DelegationChain::new(Vec::new());
    let root_sk = make_sk(1);
    let ctx = make_ctx(&root_sk);
    let leaf_delegate = make_principal(9);

    let err = verify_chain(
        &empty,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("empty chain should fail");

    assert_eq!(err, ChainError::EmptyChain);
}

#[test]
fn rejects_chain_depth_exceeded() {
    let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
    let mut ctx = make_ctx(&root_sk);
    ctx.max_chain_depth = 2;

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("depth overflow must fail");

    assert_eq!(
        err,
        ChainError::DepthExceeded {
            max_depth: 2,
            actual_depth: 3,
        }
    );
}

#[test]
fn rejects_unauthorized_root() {
    let (chain, _root_sk, leaf_delegate) = valid_chain_fixture();
    let wrong_root = make_sk(77);
    let ctx = make_ctx(&wrong_root);

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("unauthorized root must fail");

    assert!(matches!(err, ChainError::UnauthorizedRoot { .. }));
}

#[test]
fn rejects_missing_checkpoint_binding() {
    let (mut chain, root_sk, leaf_delegate) = valid_chain_fixture();
    chain.links[0].checkpoint_binding = None;
    let ctx = make_ctx(&root_sk);

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("missing checkpoint binding should fail");

    assert_eq!(err, ChainError::MissingCheckpointBinding { index: 0 });
}

#[test]
fn rejects_missing_revocation_freshness_binding() {
    let (mut chain, root_sk, leaf_delegate) = valid_chain_fixture();
    chain.links[1].revocation_freshness = None;
    let ctx = make_ctx(&root_sk);

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("missing revocation freshness should fail");

    assert_eq!(
        err,
        ChainError::MissingRevocationFreshnessBinding { index: 1 }
    );
}

#[test]
fn rejects_invalid_signature() {
    let (mut chain, root_sk, leaf_delegate) = valid_chain_fixture();
    chain.links[1].signature = Signature::from_bytes([0xAB; 64]);
    let ctx = make_ctx(&root_sk);

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("invalid signature should fail");

    match err {
        ChainError::TokenVerificationFailed { index, error } => {
            assert_eq!(index, 1);
            assert!(matches!(error, TokenError::SignatureInvalid { .. }));
        }
        other => panic!("expected token verification failure, got {other:?}"),
    }
}

#[test]
fn rejects_attenuation_violation() {
    let root_sk = make_sk(1);
    let issuer_sk = make_sk(2);
    let delegate_sk = make_sk(3);
    let leaf_delegate = make_principal(99);

    let link0 = make_bound_token(
        &root_sk,
        principal_id_from_verification_key(&issuer_sk.verification_key()),
        &[RuntimeCapability::VmDispatch],
    );
    // link1 adds NetworkEgress which was NOT in link0: attenuation violation
    let link1 = make_bound_token(
        &issuer_sk,
        principal_id_from_verification_key(&delegate_sk.verification_key()),
        &[
            RuntimeCapability::VmDispatch,
            RuntimeCapability::NetworkEgress,
        ],
    );
    let link2 = make_bound_token(
        &delegate_sk,
        leaf_delegate.clone(),
        &[RuntimeCapability::VmDispatch],
    );
    let chain = DelegationChain::new(vec![link0, link1, link2]);
    let ctx = make_ctx(&root_sk);

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("attenuation amplification must fail");

    match err {
        ChainError::AttenuationViolation {
            index,
            amplified_capabilities,
            ..
        } => {
            assert_eq!(index, 1);
            assert!(amplified_capabilities.contains(&RuntimeCapability::NetworkEgress));
        }
        other => panic!("expected attenuation violation, got {other:?}"),
    }
}

#[test]
fn rejects_revoked_link() {
    let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);
    let mut revoked = BTreeSet::new();
    revoked.insert(chain.links[1].jti.clone());
    let oracle = SetRevocationOracle { revoked };

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &oracle,
    )
    .expect_err("revoked link must fail");

    match err {
        ChainError::RevokedLink { index, token_id } => {
            assert_eq!(index, 1);
            assert_eq!(token_id, chain.links[1].jti);
        }
        other => panic!("expected revoked-link error, got {other:?}"),
    }
}

#[test]
fn rejects_revoked_root_link() {
    let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);
    let mut revoked = BTreeSet::new();
    revoked.insert(chain.links[0].jti.clone());
    let oracle = SetRevocationOracle { revoked };

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &oracle,
    )
    .expect_err("revoked root must fail");

    match err {
        ChainError::RevokedLink { index, .. } => assert_eq!(index, 0),
        other => panic!("expected revoked-link at index 0, got {other:?}"),
    }
}

#[test]
fn rejects_revoked_leaf_link() {
    let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);
    let mut revoked = BTreeSet::new();
    revoked.insert(chain.links[2].jti.clone());
    let oracle = SetRevocationOracle { revoked };

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &oracle,
    )
    .expect_err("revoked leaf must fail");

    match err {
        ChainError::RevokedLink { index, .. } => assert_eq!(index, 2),
        other => panic!("expected revoked-link at index 2, got {other:?}"),
    }
}

#[test]
fn rejects_missing_capability_at_leaf() {
    let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);

    // Request a capability that is NOT in the leaf token
    let err = verify_chain(
        &chain,
        RuntimeCapability::NetworkEgress,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("missing leaf capability should fail");

    match err {
        ChainError::MissingCapabilityAtLeaf {
            required,
            leaf_capabilities,
        } => {
            assert_eq!(required, RuntimeCapability::NetworkEgress);
            assert!(leaf_capabilities.contains(&RuntimeCapability::VmDispatch));
            assert!(!leaf_capabilities.contains(&RuntimeCapability::NetworkEgress));
        }
        other => panic!("expected missing capability at leaf, got {other:?}"),
    }
}

#[test]
fn rejects_zone_mismatch() {
    let root_sk = make_sk(1);
    let issuer_sk = make_sk(2);
    let leaf_delegate = make_principal(99);

    let link0 = make_bound_token_in_zone(
        &root_sk,
        principal_id_from_verification_key(&issuer_sk.verification_key()),
        &[RuntimeCapability::VmDispatch],
        "zone-a",
    );
    let link1 = make_bound_token_in_zone(
        &issuer_sk,
        leaf_delegate.clone(),
        &[RuntimeCapability::VmDispatch],
        "zone-b", // MISMATCH
    );
    let chain = DelegationChain::new(vec![link0, link1]);

    let mut ctx = make_ctx(&root_sk);
    ctx.required_zone = Some("zone-a".to_string());

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("zone mismatch should fail");

    match err {
        ChainError::ZoneMismatch {
            index,
            expected_zone,
            actual_zone,
        } => {
            assert_eq!(index, 1);
            assert_eq!(expected_zone, "zone-a");
            assert_eq!(actual_zone, "zone-b");
        }
        other => panic!("expected zone mismatch, got {other:?}"),
    }
}

// =========================================================================
// Section 10: AuthorizationProof — structure and serde
// =========================================================================

#[test]
fn authorization_proof_contains_chain_summary() {
    let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);
    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("chain should verify");

    assert_eq!(proof.chain_summary.len(), 3);
    assert_eq!(proof.chain_summary[0].index, 0);
    assert_eq!(proof.chain_summary[1].index, 1);
    assert_eq!(proof.chain_summary[2].index, 2);
}

#[test]
fn authorization_proof_root_issuer_correct() {
    let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);
    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();

    let expected_root = principal_id_from_verification_key(&root_sk.verification_key());
    assert_eq!(proof.root_issuer, expected_root);
}

#[test]
fn authorization_proof_leaf_delegate_correct() {
    let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);
    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();
    assert_eq!(proof.leaf_delegate, leaf_delegate);
}

#[test]
fn authorization_proof_chain_hash_deterministic() {
    let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);
    let proof1 = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();
    let proof2 = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();
    assert_eq!(proof1.chain_hash, proof2.chain_hash);
}

#[test]
fn authorization_proof_serde_round_trip() {
    let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);
    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();

    let json = serde_json::to_string(&proof).expect("serialize");
    let restored: AuthorizationProof = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(proof, restored);
}

// =========================================================================
// Section 11: DelegationLinkSummary — structure validation
// =========================================================================

#[test]
fn link_summary_delegate_chain_matches() {
    let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);
    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();

    // Link 0's delegate should be link 1's issuer principal
    assert_eq!(
        proof.chain_summary[0].delegate,
        principal_id_from_verification_key(&chain.links[1].issuer)
    );
    // Link 1's delegate should be link 2's issuer principal
    assert_eq!(
        proof.chain_summary[1].delegate,
        principal_id_from_verification_key(&chain.links[2].issuer)
    );
    // Link 2 (leaf) delegate should be the provided leaf_delegate
    assert_eq!(proof.chain_summary[2].delegate, leaf_delegate);
}

#[test]
fn link_summary_token_ids_match() {
    let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);
    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();

    for (i, summary) in proof.chain_summary.iter().enumerate() {
        assert_eq!(summary.token_id, chain.links[i].jti);
    }
}

#[test]
fn link_summary_zones_match() {
    let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);
    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();

    for summary in &proof.chain_summary {
        assert_eq!(summary.zone, "zone-a");
    }
}

#[test]
fn link_summary_capability_counts() {
    let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);
    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();

    // Link 0 has VmDispatch + NetworkEgress = 2
    assert_eq!(proof.chain_summary[0].capability_count, 2);
    // Link 1 has VmDispatch only = 1
    assert_eq!(proof.chain_summary[1].capability_count, 1);
    // Link 2 has VmDispatch only = 1
    assert_eq!(proof.chain_summary[2].capability_count, 1);
}

#[test]
fn link_summary_serde_round_trip() {
    let summary = DelegationLinkSummary {
        index: 0,
        token_id: EngineObjectId([0xAB; 32]),
        issuer: make_principal(1),
        delegate: make_principal(2),
        capability_count: 3,
        zone: "zone-x".to_string(),
        not_before_tick: 100,
        expiry_tick: 1000,
    };
    let json = serde_json::to_string(&summary).expect("serialize");
    let restored: DelegationLinkSummary = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(summary, restored);
}

// =========================================================================
// Section 12: Single-link chain (root == leaf)
// =========================================================================

#[test]
fn single_link_chain_verifies() {
    let root_sk = make_sk(1);
    let leaf_delegate = make_principal(99);

    let link = make_bound_token(
        &root_sk,
        leaf_delegate.clone(),
        &[RuntimeCapability::VmDispatch],
    );
    let chain = DelegationChain::new(vec![link]);
    let ctx = make_ctx(&root_sk);

    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("single-link chain should verify");

    assert_eq!(proof.chain_summary.len(), 1);
    assert_eq!(proof.leaf_delegate, leaf_delegate);
    assert_eq!(proof.authorized_capability, RuntimeCapability::VmDispatch);
}

// =========================================================================
// Section 13: Max-depth chain (exactly at limit)
// =========================================================================

#[test]
fn chain_at_exact_depth_limit_succeeds() {
    let root_sk = make_sk(1);
    let leaf_delegate = make_principal(99);

    // Build a single-link chain; depth = 1, set limit to 1
    let link = make_bound_token(
        &root_sk,
        leaf_delegate.clone(),
        &[RuntimeCapability::VmDispatch],
    );
    let chain = DelegationChain::new(vec![link]);

    let mut ctx = make_ctx(&root_sk);
    ctx.max_chain_depth = 1;

    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("chain at exact limit should pass");
    assert_eq!(proof.chain_summary.len(), 1);
}

#[test]
fn chain_one_over_depth_limit_fails() {
    let root_sk = make_sk(1);
    let issuer_sk = make_sk(2);
    let leaf_delegate = make_principal(99);

    let link0 = make_bound_token(
        &root_sk,
        principal_id_from_verification_key(&issuer_sk.verification_key()),
        &[RuntimeCapability::VmDispatch],
    );
    let link1 = make_bound_token(
        &issuer_sk,
        leaf_delegate.clone(),
        &[RuntimeCapability::VmDispatch],
    );
    let chain = DelegationChain::new(vec![link0, link1]);

    let mut ctx = make_ctx(&root_sk);
    ctx.max_chain_depth = 1; // chain len=2 > 1

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("chain over limit must fail");

    assert_eq!(
        err,
        ChainError::DepthExceeded {
            max_depth: 1,
            actual_depth: 2,
        }
    );
}

// =========================================================================
// Section 14: Zone inference (required_zone = None)
// =========================================================================

#[test]
fn zone_inferred_from_root_when_required_zone_is_none() {
    let root_sk = make_sk(1);
    let leaf_delegate = make_principal(99);

    let link = make_bound_token_in_zone(
        &root_sk,
        leaf_delegate.clone(),
        &[RuntimeCapability::VmDispatch],
        "zone-inferred",
    );
    let chain = DelegationChain::new(vec![link]);

    let mut ctx = make_ctx(&root_sk);
    ctx.required_zone = None; // will infer from root link

    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("should infer zone from root");

    assert_eq!(proof.chain_summary[0].zone, "zone-inferred");
}

// =========================================================================
// Section 15: Multiple authorized roots
// =========================================================================

#[test]
fn multiple_authorized_roots_accepts_any() {
    let root_sk_1 = make_sk(1);
    let root_sk_2 = make_sk(2);
    let leaf_delegate = make_principal(99);

    let link = make_bound_token(
        &root_sk_2,
        leaf_delegate.clone(),
        &[RuntimeCapability::VmDispatch],
    );
    let chain = DelegationChain::new(vec![link]);

    let mut roots = BTreeSet::new();
    roots.insert(root_sk_1.verification_key());
    roots.insert(root_sk_2.verification_key());
    let ctx = DelegationVerificationContext {
        current_tick: 500,
        verifier_checkpoint_seq: 10,
        verifier_revocation_seq: 10,
        max_chain_depth: DEFAULT_MAX_CHAIN_DEPTH,
        authorized_roots: roots,
        required_zone: Some("zone-a".to_string()),
    };

    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("should accept any authorized root");
    assert_eq!(proof.chain_summary.len(), 1);
}

// =========================================================================
// Section 16: Custom RevocationOracle
// =========================================================================

#[test]
fn set_revocation_oracle_selectively_revokes() {
    let id1 = EngineObjectId([1; 32]);
    let id2 = EngineObjectId([2; 32]);
    let id3 = EngineObjectId([3; 32]);

    let mut revoked = BTreeSet::new();
    revoked.insert(id2.clone());
    let oracle = SetRevocationOracle { revoked };

    assert!(!oracle.is_revoked(&id1));
    assert!(oracle.is_revoked(&id2));
    assert!(!oracle.is_revoked(&id3));
}

// =========================================================================
// Section 17: Proper attenuation (strict subset) verification
// =========================================================================

#[test]
fn proper_attenuation_subset_passes() {
    let root_sk = make_sk(1);
    let issuer_sk = make_sk(2);
    let leaf_delegate = make_principal(99);

    let link0 = make_bound_token(
        &root_sk,
        principal_id_from_verification_key(&issuer_sk.verification_key()),
        &[
            RuntimeCapability::VmDispatch,
            RuntimeCapability::NetworkEgress,
            RuntimeCapability::GcInvoke,
        ],
    );
    // Properly attenuated: subset of parent capabilities
    let link1 = make_bound_token(
        &issuer_sk,
        leaf_delegate.clone(),
        &[RuntimeCapability::VmDispatch],
    );
    let chain = DelegationChain::new(vec![link0, link1]);
    let ctx = make_ctx(&root_sk);

    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("properly attenuated chain should pass");
    assert_eq!(proof.chain_summary.len(), 2);
}

#[test]
fn equal_capabilities_is_valid_attenuation() {
    let root_sk = make_sk(1);
    let issuer_sk = make_sk(2);
    let leaf_delegate = make_principal(99);

    let caps = &[RuntimeCapability::VmDispatch, RuntimeCapability::GcInvoke];
    let link0 = make_bound_token(
        &root_sk,
        principal_id_from_verification_key(&issuer_sk.verification_key()),
        caps,
    );
    // Same capabilities as parent: is_subset returns true
    let link1 = make_bound_token(&issuer_sk, leaf_delegate.clone(), caps);
    let chain = DelegationChain::new(vec![link0, link1]);
    let ctx = make_ctx(&root_sk);

    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("equal capability set is valid attenuation");
    assert_eq!(proof.chain_summary.len(), 2);
}

// =========================================================================
// Section 18: Deterministic replay
// =========================================================================

#[test]
fn deterministic_chain_verification() {
    let run = || {
        let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
        let ctx = make_ctx(&root_sk);
        verify_chain(
            &chain,
            RuntimeCapability::VmDispatch,
            &leaf_delegate,
            &ctx,
            &NoRevocationOracle,
        )
        .unwrap()
    };

    let r1 = run();
    let r2 = run();
    assert_eq!(r1.chain_hash, r2.chain_hash);
    assert_eq!(r1.authorized_capability, r2.authorized_capability);
    assert_eq!(r1.root_issuer, r2.root_issuer);
    assert_eq!(r1.leaf_delegate, r2.leaf_delegate);
    assert_eq!(r1.chain_summary, r2.chain_summary);
}

// =========================================================================
// Section 19: Chain hash depends on content
// =========================================================================

#[test]
fn different_leaf_delegates_produce_different_chain_hashes() {
    let root_sk = make_sk(1);
    let leaf_a = make_principal(10);
    let leaf_b = make_principal(20);

    let link_a = make_bound_token(&root_sk, leaf_a.clone(), &[RuntimeCapability::VmDispatch]);
    let link_b = make_bound_token(&root_sk, leaf_b.clone(), &[RuntimeCapability::VmDispatch]);

    let chain_a = DelegationChain::new(vec![link_a]);
    let chain_b = DelegationChain::new(vec![link_b]);

    let ctx = make_ctx(&root_sk);
    let proof_a = verify_chain(
        &chain_a,
        RuntimeCapability::VmDispatch,
        &leaf_a,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();
    let proof_b = verify_chain(
        &chain_b,
        RuntimeCapability::VmDispatch,
        &leaf_b,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();

    assert_ne!(proof_a.chain_hash, proof_b.chain_hash);
}

// =========================================================================
// Section 20: Edge cases
// =========================================================================

#[test]
fn missing_checkpoint_binding_at_middle_link() {
    let (mut chain, root_sk, leaf_delegate) = valid_chain_fixture();
    chain.links[1].checkpoint_binding = None;
    let ctx = make_ctx(&root_sk);

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("missing checkpoint at middle link should fail");

    assert_eq!(err, ChainError::MissingCheckpointBinding { index: 1 });
}

#[test]
fn missing_revocation_freshness_at_leaf() {
    let (mut chain, root_sk, leaf_delegate) = valid_chain_fixture();
    chain.links[2].revocation_freshness = None;
    let ctx = make_ctx(&root_sk);

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("missing revocation freshness at leaf should fail");

    assert_eq!(
        err,
        ChainError::MissingRevocationFreshnessBinding { index: 2 }
    );
}

#[test]
fn all_links_revoked_first_is_reported() {
    let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);
    let mut revoked = BTreeSet::new();
    for link in &chain.links {
        revoked.insert(link.jti.clone());
    }
    let oracle = SetRevocationOracle { revoked };

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &oracle,
    )
    .expect_err("all revoked should fail");

    // Should fail on the FIRST revoked link (index 0)
    match err {
        ChainError::RevokedLink { index, .. } => assert_eq!(index, 0),
        other => panic!("expected revoked link error, got {other:?}"),
    }
}

#[test]
fn chain_error_variants_are_distinguishable() {
    // Ensure different error variants produce different Debug strings
    let errors: Vec<ChainError> = vec![
        ChainError::EmptyChain,
        ChainError::DepthExceeded {
            max_depth: 8,
            actual_depth: 10,
        },
        ChainError::UnauthorizedRoot {
            root_issuer: VerificationKey::from_bytes([0; 32]),
        },
        ChainError::MissingCheckpointBinding { index: 0 },
        ChainError::MissingRevocationFreshnessBinding { index: 0 },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(
        displays.len(),
        errors.len(),
        "all error messages must be unique"
    );
}

#[test]
fn verification_context_clone_is_independent() {
    let root_sk = make_sk(1);
    let ctx = make_ctx(&root_sk);
    let mut ctx2 = ctx.clone();
    ctx2.current_tick = 999;
    assert_ne!(ctx.current_tick, ctx2.current_tick);
    assert_eq!(ctx.authorized_roots, ctx2.authorized_roots);
}
