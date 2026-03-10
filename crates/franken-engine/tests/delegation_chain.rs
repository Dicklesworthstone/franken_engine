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
    CheckpointRef, PrincipalId, RevocationFreshnessRef, TokenBuilder, TokenError, TokenId,
};
use frankenengine_engine::delegation_chain::{
    ChainError, DelegationChain, DelegationVerificationContext, NoRevocationOracle,
    RevocationOracle, principal_id_from_verification_key, verify_chain,
};
use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;

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
) -> frankenengine_engine::capability_token::CapabilityToken {
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

fn make_ctx(root_sk: &SigningKey) -> DelegationVerificationContext {
    let mut roots = BTreeSet::new();
    roots.insert(root_sk.verification_key());
    DelegationVerificationContext {
        current_tick: 500,
        verifier_checkpoint_seq: 10,
        verifier_revocation_seq: 10,
        max_chain_depth: 8,
        authorized_roots: roots,
        required_zone: Some("zone-a".to_string()),
    }
}

#[test]
fn end_to_end_owner_issuer_delegate_chain_authorizes_leaf_action() {
    let root_sk = make_sk(1);
    let issuer_sk = make_sk(2);
    let delegate_sk = make_sk(3);
    let leaf_delegate = make_principal(42);

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

    let chain = DelegationChain::new(vec![link0, link1, link2]);
    let ctx = make_ctx(&root_sk);
    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("chain should authorize action");

    assert_eq!(proof.leaf_delegate, leaf_delegate);
    assert_eq!(proof.chain_summary.len(), 3);
    assert_eq!(proof.authorized_capability, RuntimeCapability::VmDispatch);
}

struct SetRevocationOracle {
    revoked: BTreeSet<TokenId>,
}

impl RevocationOracle for SetRevocationOracle {
    fn is_revoked(&self, token_id: &TokenId) -> bool {
        self.revoked.contains(token_id)
    }
}

#[test]
fn revoking_middle_link_invalidates_downstream_authorization() {
    let root_sk = make_sk(1);
    let issuer_sk = make_sk(2);
    let delegate_sk = make_sk(3);
    let leaf_delegate = make_principal(55);

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

    let chain = DelegationChain::new(vec![link0, link1, link2]);
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
    .expect_err("revoked middle link must invalidate authorization");

    assert!(matches!(err, ChainError::RevokedLink { index: 1, .. }));
}

// ────────────────────────────────────────────────────────────
// Enrichment: error paths, edge cases, serde, Display
// ────────────────────────────────────────────────────────────

#[test]
fn empty_chain_is_rejected() {
    let root_sk = make_sk(1);
    let chain = DelegationChain::new(vec![]);
    let ctx = make_ctx(&root_sk);
    let leaf = make_principal(99);

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("empty chain must fail");

    assert!(matches!(err, ChainError::EmptyChain));
    assert!(err.to_string().contains("empty"));
}

#[test]
fn depth_exceeded_is_rejected() {
    let root_sk = make_sk(1);
    let issuer_sk = make_sk(2);
    let delegate_sk = make_sk(3);
    let leaf_delegate = make_principal(42);

    let link0 = make_bound_token(
        &root_sk,
        principal_id_from_verification_key(&issuer_sk.verification_key()),
        &[RuntimeCapability::VmDispatch],
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

    let chain = DelegationChain::new(vec![link0, link1, link2]);
    let mut ctx = make_ctx(&root_sk);
    ctx.max_chain_depth = 2; // 3 links exceeds depth=2

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("depth exceeded must fail");

    assert!(matches!(
        err,
        ChainError::DepthExceeded {
            max_depth: 2,
            actual_depth: 3
        }
    ));
    assert!(err.to_string().contains("depth exceeded"));
}

#[test]
fn unauthorized_root_issuer_is_rejected() {
    let root_sk = make_sk(1);
    let unauthorized_sk = make_sk(99);
    let leaf = make_principal(10);

    let link0 = make_bound_token(
        &unauthorized_sk,
        leaf.clone(),
        &[RuntimeCapability::VmDispatch],
    );

    let chain = DelegationChain::new(vec![link0]);
    let ctx = make_ctx(&root_sk); // root_sk != unauthorized_sk

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("unauthorized root must fail");

    assert!(matches!(err, ChainError::UnauthorizedRoot { .. }));
    assert!(err.to_string().contains("unauthorized root"));
}

#[test]
fn single_link_chain_authorizes_direct_grant() {
    let root_sk = make_sk(1);
    let leaf = make_principal(50);

    let link0 = make_bound_token(
        &root_sk,
        leaf.clone(),
        &[
            RuntimeCapability::VmDispatch,
            RuntimeCapability::NetworkEgress,
        ],
    );

    let chain = DelegationChain::new(vec![link0]);
    let ctx = make_ctx(&root_sk);

    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("single-link chain should succeed");

    assert_eq!(proof.chain_summary.len(), 1);
    assert_eq!(proof.authorized_capability, RuntimeCapability::VmDispatch);
    assert_eq!(proof.leaf_delegate, leaf);
}

#[test]
fn missing_capability_at_leaf_is_rejected() {
    let root_sk = make_sk(1);
    let leaf = make_principal(60);

    let link0 = make_bound_token(
        &root_sk,
        leaf.clone(),
        &[RuntimeCapability::NetworkEgress], // does not include VmDispatch
    );

    let chain = DelegationChain::new(vec![link0]);
    let ctx = make_ctx(&root_sk);

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch, // request capability not in leaf
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("missing capability at leaf must fail");

    assert!(matches!(err, ChainError::MissingCapabilityAtLeaf { .. }));
    assert!(err.to_string().contains("capability"));
}

#[test]
fn zone_mismatch_is_rejected() {
    let root_sk = make_sk(1);
    let delegate_sk = make_sk(2);
    let leaf = make_principal(70);

    let link0 = make_bound_token(
        &root_sk,
        principal_id_from_verification_key(&delegate_sk.verification_key()),
        &[RuntimeCapability::VmDispatch],
    );
    // Build a token in a different zone
    let link1 = {
        let builder = TokenBuilder::new(
            delegate_sk.clone(),
            DeterministicTimestamp(100),
            DeterministicTimestamp(1_000),
            SecurityEpoch::GENESIS,
            "zone-b", // different from "zone-a" in make_ctx
        )
        .add_audience(leaf.clone())
        .bind_checkpoint(CheckpointRef {
            min_checkpoint_seq: 5,
            checkpoint_id: EngineObjectId([7; 32]),
        })
        .bind_revocation_freshness(RevocationFreshnessRef {
            min_revocation_seq: 3,
            revocation_head_hash: ContentHash::compute(b"rev-head"),
        })
        .add_capability(RuntimeCapability::VmDispatch);
        builder.build().expect("token should build")
    };

    let chain = DelegationChain::new(vec![link0, link1]);
    let ctx = make_ctx(&root_sk);

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("zone mismatch must fail");

    assert!(matches!(err, ChainError::ZoneMismatch { index: 1, .. }));
    assert!(err.to_string().contains("zone"));
}

#[test]
fn attenuation_violation_is_detected_when_child_amplifies_capabilities() {
    let root_sk = make_sk(1);
    let issuer_sk = make_sk(2);
    let leaf = make_principal(80);

    // Root grants only VmDispatch
    let link0 = make_bound_token(
        &root_sk,
        principal_id_from_verification_key(&issuer_sk.verification_key()),
        &[RuntimeCapability::VmDispatch],
    );
    // Child attempts VmDispatch + NetworkEgress (amplification)
    let link1 = make_bound_token(
        &issuer_sk,
        leaf.clone(),
        &[
            RuntimeCapability::VmDispatch,
            RuntimeCapability::NetworkEgress,
        ],
    );

    let chain = DelegationChain::new(vec![link0, link1]);
    let ctx = make_ctx(&root_sk);

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("attenuation violation must fail");

    assert!(matches!(
        err,
        ChainError::AttenuationViolation { index: 1, .. }
    ));
    assert!(err.to_string().contains("amplif"));
}

#[test]
fn revoking_root_link_invalidates_chain() {
    let root_sk = make_sk(1);
    let leaf = make_principal(90);

    let link0 = make_bound_token(&root_sk, leaf.clone(), &[RuntimeCapability::VmDispatch]);

    let chain = DelegationChain::new(vec![link0]);
    let ctx = make_ctx(&root_sk);
    let mut revoked = BTreeSet::new();
    revoked.insert(chain.links[0].jti.clone());
    let oracle = SetRevocationOracle { revoked };

    let err = verify_chain(&chain, RuntimeCapability::VmDispatch, &leaf, &ctx, &oracle)
        .expect_err("revoked root link must invalidate chain");

    assert!(matches!(err, ChainError::RevokedLink { index: 0, .. }));
}

#[test]
fn chain_hash_is_deterministic() {
    let root_sk = make_sk(1);
    let leaf = make_principal(40);

    let link0 = make_bound_token(&root_sk, leaf.clone(), &[RuntimeCapability::VmDispatch]);

    let chain = DelegationChain::new(vec![link0]);
    let ctx = make_ctx(&root_sk);

    let proof1 = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("first verify");

    let proof2 = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("second verify");

    assert_eq!(proof1.chain_hash, proof2.chain_hash);
}

#[test]
fn authorization_proof_serde_round_trip() {
    let root_sk = make_sk(1);
    let leaf = make_principal(55);

    let link0 = make_bound_token(&root_sk, leaf.clone(), &[RuntimeCapability::VmDispatch]);

    let chain = DelegationChain::new(vec![link0]);
    let ctx = make_ctx(&root_sk);

    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("verify should succeed");

    let json = serde_json::to_string(&proof).expect("serialize proof");
    let recovered: frankenengine_engine::delegation_chain::AuthorizationProof =
        serde_json::from_str(&json).expect("deserialize proof");

    assert_eq!(proof.chain_hash, recovered.chain_hash);
    assert_eq!(proof.authorized_capability, recovered.authorized_capability);
    assert_eq!(proof.leaf_delegate, recovered.leaf_delegate);
    assert_eq!(proof.root_issuer, recovered.root_issuer);
    assert_eq!(proof.chain_summary.len(), recovered.chain_summary.len());
}

#[test]
fn delegation_chain_serde_round_trip() {
    let root_sk = make_sk(1);
    let leaf = make_principal(65);

    let link0 = make_bound_token(&root_sk, leaf.clone(), &[RuntimeCapability::VmDispatch]);

    let chain = DelegationChain::new(vec![link0]);
    let json = serde_json::to_string(&chain).expect("serialize chain");
    let recovered: DelegationChain = serde_json::from_str(&json).expect("deserialize chain");

    assert_eq!(chain.links.len(), recovered.links.len());
    assert_eq!(chain.links[0].jti, recovered.links[0].jti);
    assert_eq!(chain.links[0].zone, recovered.links[0].zone);
}

#[test]
fn chain_error_display_covers_all_variants() {
    // Exhaustive display test for ChainError
    let errors: Vec<ChainError> = vec![
        ChainError::EmptyChain,
        ChainError::DepthExceeded {
            max_depth: 5,
            actual_depth: 10,
        },
        ChainError::UnauthorizedRoot {
            root_issuer: make_sk(1).verification_key(),
        },
        ChainError::MissingCheckpointBinding { index: 2 },
        ChainError::MissingRevocationFreshnessBinding { index: 3 },
        ChainError::TokenVerificationFailed {
            index: 0,
            error: TokenError::Expired {
                current_tick: 2000,
                expiry: 1000,
            },
        },
        ChainError::AttenuationViolation {
            index: 1,
            parent_capability_count: 1,
            child_capability_count: 2,
            amplified_capabilities: BTreeSet::from([RuntimeCapability::NetworkEgress]),
        },
        ChainError::ZoneMismatch {
            index: 1,
            expected_zone: "zone-a".to_string(),
            actual_zone: "zone-b".to_string(),
        },
        ChainError::RevokedLink {
            index: 0,
            token_id: EngineObjectId([1; 32]),
        },
        ChainError::MissingCapabilityAtLeaf {
            required: RuntimeCapability::VmDispatch,
            leaf_capabilities: BTreeSet::new(),
        },
    ];

    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.is_empty(), "Display for {err:?} must not be empty");
    }
}

#[test]
fn no_revocation_oracle_never_revokes() {
    let oracle = NoRevocationOracle;
    let token_id = EngineObjectId([42; 32]);
    assert!(!oracle.is_revoked(&token_id));
}

#[test]
fn set_revocation_oracle_revokes_only_registered_tokens() {
    let revoked_id = EngineObjectId([10; 32]);
    let clean_id = EngineObjectId([20; 32]);
    let mut revoked = BTreeSet::new();
    revoked.insert(revoked_id.clone());
    let oracle = SetRevocationOracle { revoked };

    assert!(oracle.is_revoked(&revoked_id));
    assert!(!oracle.is_revoked(&clean_id));
}

#[test]
fn delegation_link_summary_contains_expected_fields() {
    let root_sk = make_sk(1);
    let issuer_sk = make_sk(2);
    let leaf = make_principal(33);

    let link0 = make_bound_token(
        &root_sk,
        principal_id_from_verification_key(&issuer_sk.verification_key()),
        &[
            RuntimeCapability::VmDispatch,
            RuntimeCapability::NetworkEgress,
        ],
    );
    let link1 = make_bound_token(&issuer_sk, leaf.clone(), &[RuntimeCapability::VmDispatch]);

    let chain = DelegationChain::new(vec![link0, link1]);
    let ctx = make_ctx(&root_sk);

    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("verify chain");

    assert_eq!(proof.chain_summary.len(), 2);
    assert_eq!(proof.chain_summary[0].index, 0);
    assert_eq!(proof.chain_summary[0].capability_count, 2);
    assert_eq!(proof.chain_summary[0].zone, "zone-a");
    assert_eq!(proof.chain_summary[1].index, 1);
    assert_eq!(proof.chain_summary[1].capability_count, 1);
    assert_eq!(proof.chain_summary[1].delegate, leaf);
}

#[test]
fn principal_id_from_verification_key_is_deterministic() {
    let sk = make_sk(42);
    let vk = sk.verification_key();
    let p1 = principal_id_from_verification_key(&vk);
    let p2 = principal_id_from_verification_key(&vk);
    assert_eq!(p1, p2);
}

#[test]
fn verified_at_tick_matches_context_current_tick() {
    let root_sk = make_sk(1);
    let leaf = make_principal(77);

    let link0 = make_bound_token(&root_sk, leaf.clone(), &[RuntimeCapability::VmDispatch]);

    let chain = DelegationChain::new(vec![link0]);
    let ctx = make_ctx(&root_sk);

    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("verify chain");

    assert_eq!(proof.verified_at_tick, ctx.current_tick);
}

#[test]
fn attenuation_preserving_subset_passes() {
    let root_sk = make_sk(1);
    let issuer_sk = make_sk(2);
    let leaf = make_principal(85);

    // Root grants VmDispatch + NetworkEgress
    let link0 = make_bound_token(
        &root_sk,
        principal_id_from_verification_key(&issuer_sk.verification_key()),
        &[
            RuntimeCapability::VmDispatch,
            RuntimeCapability::NetworkEgress,
        ],
    );
    // Child grants only VmDispatch (strict subset, OK)
    let link1 = make_bound_token(&issuer_sk, leaf.clone(), &[RuntimeCapability::VmDispatch]);

    let chain = DelegationChain::new(vec![link0, link1]);
    let ctx = make_ctx(&root_sk);

    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("attenuation-preserving subset should pass");

    assert_eq!(proof.authorized_capability, RuntimeCapability::VmDispatch);
}

#[test]
fn chain_error_attenuation_violation_lists_amplified_capabilities() {
    let root_sk = make_sk(1);
    let issuer_sk = make_sk(2);
    let leaf = make_principal(90);

    let link0 = make_bound_token(
        &root_sk,
        principal_id_from_verification_key(&issuer_sk.verification_key()),
        &[RuntimeCapability::VmDispatch],
    );
    let link1 = make_bound_token(
        &issuer_sk,
        leaf.clone(),
        &[
            RuntimeCapability::VmDispatch,
            RuntimeCapability::NetworkEgress,
            RuntimeCapability::GcInvoke,
        ],
    );

    let chain = DelegationChain::new(vec![link0, link1]);
    let ctx = make_ctx(&root_sk);

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("amplification must fail");

    if let ChainError::AttenuationViolation {
        amplified_capabilities,
        ..
    } = &err
    {
        assert!(amplified_capabilities.contains(&RuntimeCapability::NetworkEgress));
        assert!(amplified_capabilities.contains(&RuntimeCapability::GcInvoke));
        assert!(!amplified_capabilities.contains(&RuntimeCapability::VmDispatch));
    } else {
        panic!("expected AttenuationViolation, got {err:?}");
    }
}

// ────────────────────────────────────────────────────────────
// Additional enrichment: chain methods, error serde, context
// ────────────────────────────────────────────────────────────

#[test]
fn delegation_chain_len_and_is_empty() {
    let empty = DelegationChain::new(vec![]);
    assert_eq!(empty.len(), 0);
    assert!(empty.is_empty());

    let root_sk = make_sk(1);
    let leaf = make_principal(10);
    let link0 = make_bound_token(&root_sk, leaf, &[RuntimeCapability::VmDispatch]);
    let chain = DelegationChain::new(vec![link0]);
    assert_eq!(chain.len(), 1);
    assert!(!chain.is_empty());
}

#[test]
fn chain_error_serde_round_trip() {
    let errors = vec![
        ChainError::EmptyChain,
        ChainError::DepthExceeded {
            max_depth: 8,
            actual_depth: 10,
        },
        ChainError::MissingCheckpointBinding { index: 2 },
        ChainError::MissingRevocationFreshnessBinding { index: 3 },
        ChainError::MissingCapabilityAtLeaf {
            required: RuntimeCapability::VmDispatch,
            leaf_capabilities: BTreeSet::from([RuntimeCapability::NetworkEgress]),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let recovered: ChainError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, recovered);
    }
}

#[test]
fn chain_error_display_all_unique() {
    let errors: Vec<String> = vec![
        ChainError::EmptyChain.to_string(),
        ChainError::DepthExceeded {
            max_depth: 5,
            actual_depth: 10,
        }
        .to_string(),
        ChainError::UnauthorizedRoot {
            root_issuer: make_sk(1).verification_key(),
        }
        .to_string(),
        ChainError::MissingCheckpointBinding { index: 0 }.to_string(),
        ChainError::MissingRevocationFreshnessBinding { index: 0 }.to_string(),
        ChainError::MissingCapabilityAtLeaf {
            required: RuntimeCapability::VmDispatch,
            leaf_capabilities: BTreeSet::new(),
        }
        .to_string(),
    ];
    let unique: BTreeSet<_> = errors.iter().collect();
    assert_eq!(unique.len(), errors.len());
}

#[test]
fn chain_error_is_std_error() {
    let err = ChainError::EmptyChain;
    let _: &dyn std::error::Error = &err;
}

#[test]
fn delegation_verification_context_with_authorized_root() {
    let sk = make_sk(42);
    let ctx = DelegationVerificationContext::with_authorized_root(sk.verification_key());
    assert!(ctx.authorized_roots.contains(&sk.verification_key()));
    assert_eq!(ctx.authorized_roots.len(), 1);
}

#[test]
fn delegation_verification_context_default() {
    let ctx = DelegationVerificationContext::default();
    assert!(ctx.authorized_roots.is_empty());
    assert!(ctx.required_zone.is_none());
}

#[test]
fn delegation_link_summary_serde_round_trip() {
    use frankenengine_engine::delegation_chain::DelegationLinkSummary;

    let summary = DelegationLinkSummary {
        index: 0,
        token_id: EngineObjectId([1; 32]),
        issuer: make_principal(10),
        delegate: make_principal(20),
        capability_count: 2,
        zone: "zone-a".to_string(),
        not_before_tick: 100,
        expiry_tick: 1000,
    };
    let json = serde_json::to_string(&summary).expect("serialize");
    let recovered: DelegationLinkSummary = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(summary, recovered);
}

#[test]
fn principal_id_from_different_keys_yields_different_ids() {
    let sk1 = make_sk(1);
    let sk2 = make_sk(2);
    let p1 = principal_id_from_verification_key(&sk1.verification_key());
    let p2 = principal_id_from_verification_key(&sk2.verification_key());
    assert_ne!(p1, p2);
}

#[test]
fn chain_verify_method_matches_free_function() {
    let root_sk = make_sk(1);
    let leaf = make_principal(55);
    let link0 = make_bound_token(&root_sk, leaf.clone(), &[RuntimeCapability::VmDispatch]);
    let chain = DelegationChain::new(vec![link0]);
    let ctx = make_ctx(&root_sk);

    let proof_method = chain
        .verify(
            RuntimeCapability::VmDispatch,
            &leaf,
            &ctx,
            &NoRevocationOracle,
        )
        .expect("method verify");

    let proof_fn = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("function verify");

    assert_eq!(proof_method.chain_hash, proof_fn.chain_hash);
    assert_eq!(
        proof_method.authorized_capability,
        proof_fn.authorized_capability
    );
}

#[test]
fn chain_error_debug_is_nonempty() {
    let err = ChainError::EmptyChain;
    assert!(!format!("{err:?}").is_empty());
}

#[test]
fn no_revocation_oracle_debug_is_nonempty() {
    let oracle = NoRevocationOracle;
    assert!(!format!("{oracle:?}").is_empty());
}

#[test]
fn delegation_verification_context_debug_is_nonempty() {
    let ctx = DelegationVerificationContext::default();
    assert!(!format!("{ctx:?}").is_empty());
}
