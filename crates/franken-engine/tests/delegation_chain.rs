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

// ────────────────────────────────────────────────────────────
// Enrichment batch: ~80 new tests covering delegation chain
// construction, traversal, integrity, edge cases, permission
// delegation, restriction, and serialization round-trips.
// ────────────────────────────────────────────────────────────

fn make_bound_token_in_zone(
    issuer_sk: &SigningKey,
    delegate: PrincipalId,
    caps: &[RuntimeCapability],
    zone: &str,
) -> frankenengine_engine::capability_token::CapabilityToken {
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

fn make_bound_token_timed(
    issuer_sk: &SigningKey,
    delegate: PrincipalId,
    caps: &[RuntimeCapability],
    nbf: u64,
    expiry: u64,
) -> frankenengine_engine::capability_token::CapabilityToken {
    let mut builder = TokenBuilder::new(
        issuer_sk.clone(),
        DeterministicTimestamp(nbf),
        DeterministicTimestamp(expiry),
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

// --- 1. Chain construction ---

#[test]
fn enrichment_chain_new_preserves_link_order() {
    let root_sk = make_sk(1);
    let issuer_sk = make_sk(2);
    let leaf = make_principal(50);

    let link0 = make_bound_token(
        &root_sk,
        principal_id_from_verification_key(&issuer_sk.verification_key()),
        &[RuntimeCapability::VmDispatch],
    );
    let link1 = make_bound_token(&issuer_sk, leaf.clone(), &[RuntimeCapability::VmDispatch]);

    let jti0 = link0.jti.clone();
    let jti1 = link1.jti.clone();
    let chain = DelegationChain::new(vec![link0, link1]);
    assert_eq!(chain.links[0].jti, jti0);
    assert_eq!(chain.links[1].jti, jti1);
}

#[test]
fn enrichment_chain_new_single_link() {
    let root_sk = make_sk(1);
    let leaf = make_principal(50);
    let link = make_bound_token(&root_sk, leaf, &[RuntimeCapability::VmDispatch]);
    let chain = DelegationChain::new(vec![link]);
    assert_eq!(chain.len(), 1);
    assert!(!chain.is_empty());
}

#[test]
fn enrichment_chain_new_empty() {
    let chain = DelegationChain::new(vec![]);
    assert_eq!(chain.len(), 0);
    assert!(chain.is_empty());
}

#[test]
fn enrichment_chain_links_field_accessible() {
    let root_sk = make_sk(1);
    let leaf = make_principal(50);
    let link = make_bound_token(&root_sk, leaf.clone(), &[RuntimeCapability::VmDispatch]);
    let chain = DelegationChain::new(vec![link]);
    assert_eq!(chain.links.len(), 1);
    assert!(
        chain.links[0]
            .capabilities
            .contains(&RuntimeCapability::VmDispatch)
    );
}

// --- 2. Chain traversal ---

#[test]
fn enrichment_chain_summary_indices_sequential() {
    let (chain, root_sk, leaf) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);
    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("verify");
    for (i, summary) in proof.chain_summary.iter().enumerate() {
        assert_eq!(summary.index, i);
    }
}

#[test]
fn enrichment_chain_summary_issuer_delegate_threading() {
    let (chain, root_sk, leaf) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);
    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("verify");

    // Each link's delegate is the next link's issuer
    for i in 0..proof.chain_summary.len() - 1 {
        assert_eq!(
            proof.chain_summary[i].delegate,
            proof.chain_summary[i + 1].issuer,
        );
    }
}

#[test]
fn enrichment_chain_summary_last_delegate_is_leaf() {
    let (chain, root_sk, leaf) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);
    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("verify");
    assert_eq!(proof.chain_summary.last().unwrap().delegate, leaf);
}

#[test]
fn enrichment_chain_summary_first_issuer_is_root() {
    let (chain, root_sk, leaf) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);
    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("verify");

    let expected_root = principal_id_from_verification_key(&root_sk.verification_key());
    assert_eq!(proof.chain_summary[0].issuer, expected_root);
}

// --- 3. Chain integrity and validation ---

#[test]
fn enrichment_chain_hash_changes_with_different_leaf() {
    let root_sk = make_sk(1);
    let leaf_a = make_principal(10);
    let leaf_b = make_principal(20);

    let link_a = make_bound_token(&root_sk, leaf_a.clone(), &[RuntimeCapability::VmDispatch]);
    let link_b = make_bound_token(&root_sk, leaf_b.clone(), &[RuntimeCapability::VmDispatch]);

    let ctx = make_ctx(&root_sk);
    let proof_a = verify_chain(
        &DelegationChain::new(vec![link_a]),
        RuntimeCapability::VmDispatch,
        &leaf_a,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();
    let proof_b = verify_chain(
        &DelegationChain::new(vec![link_b]),
        RuntimeCapability::VmDispatch,
        &leaf_b,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();

    assert_ne!(proof_a.chain_hash, proof_b.chain_hash);
}

#[test]
fn enrichment_chain_hash_changes_with_different_root() {
    let root_a = make_sk(1);
    let root_b = make_sk(2);
    let leaf = make_principal(50);

    let link_a = make_bound_token(&root_a, leaf.clone(), &[RuntimeCapability::VmDispatch]);
    let link_b = make_bound_token(&root_b, leaf.clone(), &[RuntimeCapability::VmDispatch]);

    let mut roots = BTreeSet::new();
    roots.insert(root_a.verification_key());
    roots.insert(root_b.verification_key());
    let ctx = DelegationVerificationContext {
        current_tick: 500,
        verifier_checkpoint_seq: 10,
        verifier_revocation_seq: 10,
        max_chain_depth: 8,
        authorized_roots: roots,
        required_zone: Some("zone-a".to_string()),
    };

    let proof_a = verify_chain(
        &DelegationChain::new(vec![link_a]),
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();
    let proof_b = verify_chain(
        &DelegationChain::new(vec![link_b]),
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();

    assert_ne!(proof_a.chain_hash, proof_b.chain_hash);
}

#[test]
fn enrichment_proof_verified_at_tick_reflects_context() {
    let root_sk = make_sk(1);
    let leaf = make_principal(50);
    let link = make_bound_token(&root_sk, leaf.clone(), &[RuntimeCapability::VmDispatch]);
    let chain = DelegationChain::new(vec![link]);
    let mut ctx = make_ctx(&root_sk);
    ctx.current_tick = 777;

    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();
    assert_eq!(proof.verified_at_tick, 777);
}

// --- 4. Edge cases ---

#[test]
fn enrichment_depth_limit_zero_rejects_any_chain() {
    let root_sk = make_sk(1);
    let leaf = make_principal(50);
    let link = make_bound_token(&root_sk, leaf.clone(), &[RuntimeCapability::VmDispatch]);
    let chain = DelegationChain::new(vec![link]);
    let mut ctx = make_ctx(&root_sk);
    ctx.max_chain_depth = 0;

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("depth 0 must reject everything");
    assert!(matches!(
        err,
        ChainError::DepthExceeded {
            max_depth: 0,
            actual_depth: 1,
        }
    ));
}

#[test]
fn enrichment_chain_exactly_at_default_depth() {
    // Build a chain of exactly DEFAULT_MAX_CHAIN_DEPTH links
    let depth = frankenengine_engine::delegation_chain::DEFAULT_MAX_CHAIN_DEPTH;
    let mut sks = Vec::new();
    for i in 0..depth {
        sks.push(make_sk((i + 1) as u8));
    }
    let leaf = make_principal(200);

    let mut links = Vec::new();
    for i in 0..depth {
        let delegate = if i + 1 < depth {
            principal_id_from_verification_key(&sks[i + 1].verification_key())
        } else {
            leaf.clone()
        };
        // Only root has the full cap set; others attenuate to VmDispatch
        let caps = &[RuntimeCapability::VmDispatch];
        links.push(make_bound_token(&sks[i], delegate, caps));
    }

    let chain = DelegationChain::new(links);
    let ctx = make_ctx(&sks[0]);

    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("chain at default depth limit should succeed");
    assert_eq!(proof.chain_summary.len(), depth);
}

#[test]
fn enrichment_chain_one_over_default_depth_fails() {
    let depth = frankenengine_engine::delegation_chain::DEFAULT_MAX_CHAIN_DEPTH + 1;
    let mut sks = Vec::new();
    for i in 0..depth {
        sks.push(make_sk((i + 1) as u8));
    }
    let leaf = make_principal(200);

    let mut links = Vec::new();
    for i in 0..depth {
        let delegate = if i + 1 < depth {
            principal_id_from_verification_key(&sks[i + 1].verification_key())
        } else {
            leaf.clone()
        };
        links.push(make_bound_token(
            &sks[i],
            delegate,
            &[RuntimeCapability::VmDispatch],
        ));
    }

    let chain = DelegationChain::new(links);
    let ctx = make_ctx(&sks[0]);

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("one over default depth must fail");
    assert!(matches!(err, ChainError::DepthExceeded { .. }));
}

#[test]
fn enrichment_missing_checkpoint_at_root() {
    let root_sk = make_sk(1);
    let leaf = make_principal(50);
    let mut link = make_bound_token(&root_sk, leaf.clone(), &[RuntimeCapability::VmDispatch]);
    link.checkpoint_binding = None;

    let chain = DelegationChain::new(vec![link]);
    let ctx = make_ctx(&root_sk);

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("missing checkpoint at root");
    assert_eq!(err, ChainError::MissingCheckpointBinding { index: 0 });
}

#[test]
fn enrichment_missing_revocation_freshness_at_root() {
    let root_sk = make_sk(1);
    let leaf = make_principal(50);
    let mut link = make_bound_token(&root_sk, leaf.clone(), &[RuntimeCapability::VmDispatch]);
    link.revocation_freshness = None;

    let chain = DelegationChain::new(vec![link]);
    let ctx = make_ctx(&root_sk);

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("missing revocation freshness at root");
    assert_eq!(
        err,
        ChainError::MissingRevocationFreshnessBinding { index: 0 }
    );
}

#[test]
fn enrichment_missing_checkpoint_at_leaf_in_long_chain() {
    let (mut chain, root_sk, leaf) = valid_chain_fixture();
    chain.links[2].checkpoint_binding = None;
    let ctx = make_ctx(&root_sk);

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("missing checkpoint at leaf");
    assert_eq!(err, ChainError::MissingCheckpointBinding { index: 2 });
}

// --- 5. Permission delegation and restriction ---

#[test]
fn enrichment_attenuation_drops_two_capabilities() {
    let root_sk = make_sk(1);
    let issuer_sk = make_sk(2);
    let leaf = make_principal(50);

    let link0 = make_bound_token(
        &root_sk,
        principal_id_from_verification_key(&issuer_sk.verification_key()),
        &[
            RuntimeCapability::VmDispatch,
            RuntimeCapability::NetworkEgress,
            RuntimeCapability::GcInvoke,
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
    .expect("strict attenuation should pass");
    assert_eq!(proof.chain_summary[0].capability_count, 3);
    assert_eq!(proof.chain_summary[1].capability_count, 1);
}

#[test]
fn enrichment_attenuation_same_caps_is_valid() {
    let root_sk = make_sk(1);
    let issuer_sk = make_sk(2);
    let leaf = make_principal(50);

    let caps = &[RuntimeCapability::VmDispatch, RuntimeCapability::GcInvoke];
    let link0 = make_bound_token(
        &root_sk,
        principal_id_from_verification_key(&issuer_sk.verification_key()),
        caps,
    );
    let link1 = make_bound_token(&issuer_sk, leaf.clone(), caps);

    let chain = DelegationChain::new(vec![link0, link1]);
    let ctx = make_ctx(&root_sk);

    verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("same-set attenuation is valid");
}

#[test]
fn enrichment_attenuation_disjoint_capabilities_rejected() {
    let root_sk = make_sk(1);
    let issuer_sk = make_sk(2);
    let leaf = make_principal(50);

    let link0 = make_bound_token(
        &root_sk,
        principal_id_from_verification_key(&issuer_sk.verification_key()),
        &[RuntimeCapability::VmDispatch],
    );
    // Completely disjoint set
    let link1 = make_bound_token(&issuer_sk, leaf.clone(), &[RuntimeCapability::GcInvoke]);

    let chain = DelegationChain::new(vec![link0, link1]);
    let ctx = make_ctx(&root_sk);

    let err = verify_chain(
        &chain,
        RuntimeCapability::GcInvoke,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("disjoint caps must fail attenuation");
    assert!(matches!(
        err,
        ChainError::AttenuationViolation { index: 1, .. }
    ));
}

#[test]
fn enrichment_attenuation_partial_overlap_rejected() {
    let root_sk = make_sk(1);
    let issuer_sk = make_sk(2);
    let leaf = make_principal(50);

    let link0 = make_bound_token(
        &root_sk,
        principal_id_from_verification_key(&issuer_sk.verification_key()),
        &[RuntimeCapability::VmDispatch, RuntimeCapability::GcInvoke],
    );
    // Overlaps on VmDispatch but adds NetworkEgress
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
    .expect_err("partial overlap with amplification must fail");
    if let ChainError::AttenuationViolation {
        amplified_capabilities,
        ..
    } = &err
    {
        assert!(amplified_capabilities.contains(&RuntimeCapability::NetworkEgress));
        assert!(!amplified_capabilities.contains(&RuntimeCapability::VmDispatch));
    } else {
        panic!("expected AttenuationViolation, got {err:?}");
    }
}

#[test]
fn enrichment_multiple_attenuation_steps() {
    let root_sk = make_sk(1);
    let sk2 = make_sk(2);
    let sk3 = make_sk(3);
    let leaf = make_principal(50);

    let link0 = make_bound_token(
        &root_sk,
        principal_id_from_verification_key(&sk2.verification_key()),
        &[
            RuntimeCapability::VmDispatch,
            RuntimeCapability::NetworkEgress,
            RuntimeCapability::GcInvoke,
        ],
    );
    let link1 = make_bound_token(
        &sk2,
        principal_id_from_verification_key(&sk3.verification_key()),
        &[RuntimeCapability::VmDispatch, RuntimeCapability::GcInvoke],
    );
    let link2 = make_bound_token(&sk3, leaf.clone(), &[RuntimeCapability::VmDispatch]);

    let chain = DelegationChain::new(vec![link0, link1, link2]);
    let ctx = make_ctx(&root_sk);

    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("progressive attenuation should pass");
    assert_eq!(proof.chain_summary[0].capability_count, 3);
    assert_eq!(proof.chain_summary[1].capability_count, 2);
    assert_eq!(proof.chain_summary[2].capability_count, 1);
}

#[test]
fn enrichment_request_capability_not_in_leaf_but_in_parents() {
    let root_sk = make_sk(1);
    let issuer_sk = make_sk(2);
    let leaf = make_principal(50);

    let link0 = make_bound_token(
        &root_sk,
        principal_id_from_verification_key(&issuer_sk.verification_key()),
        &[RuntimeCapability::VmDispatch, RuntimeCapability::GcInvoke],
    );
    let link1 = make_bound_token(
        &issuer_sk,
        leaf.clone(),
        &[RuntimeCapability::VmDispatch], // dropped GcInvoke
    );

    let chain = DelegationChain::new(vec![link0, link1]);
    let ctx = make_ctx(&root_sk);

    let err = verify_chain(
        &chain,
        RuntimeCapability::GcInvoke, // request attenuated-away cap
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("requesting attenuated-away cap must fail");
    assert!(matches!(err, ChainError::MissingCapabilityAtLeaf { .. }));
}

// --- 6. Serialization round-trips ---

#[test]
fn enrichment_chain_serde_preserves_link_count() {
    let (chain, _, _) = valid_chain_fixture();
    let json = serde_json::to_string(&chain).expect("serialize");
    let recovered: DelegationChain = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(chain.links.len(), recovered.links.len());
}

#[test]
fn enrichment_chain_serde_preserves_all_jtis() {
    let (chain, _, _) = valid_chain_fixture();
    let json = serde_json::to_string(&chain).expect("serialize");
    let recovered: DelegationChain = serde_json::from_str(&json).expect("deserialize");
    for (a, b) in chain.links.iter().zip(recovered.links.iter()) {
        assert_eq!(a.jti, b.jti);
    }
}

#[test]
fn enrichment_chain_serde_preserves_zones() {
    let (chain, _, _) = valid_chain_fixture();
    let json = serde_json::to_string(&chain).expect("serialize");
    let recovered: DelegationChain = serde_json::from_str(&json).expect("deserialize");
    for (a, b) in chain.links.iter().zip(recovered.links.iter()) {
        assert_eq!(a.zone, b.zone);
    }
}

#[test]
fn enrichment_chain_serde_preserves_capabilities() {
    let (chain, _, _) = valid_chain_fixture();
    let json = serde_json::to_string(&chain).expect("serialize");
    let recovered: DelegationChain = serde_json::from_str(&json).expect("deserialize");
    for (a, b) in chain.links.iter().zip(recovered.links.iter()) {
        assert_eq!(a.capabilities, b.capabilities);
    }
}

#[test]
fn enrichment_empty_chain_serde_round_trip() {
    let chain = DelegationChain::new(vec![]);
    let json = serde_json::to_string(&chain).expect("serialize");
    let recovered: DelegationChain = serde_json::from_str(&json).expect("deserialize");
    assert!(recovered.is_empty());
}

#[test]
fn enrichment_chain_error_empty_chain_serde() {
    let err = ChainError::EmptyChain;
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: ChainError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, recovered);
}

#[test]
fn enrichment_chain_error_depth_exceeded_serde() {
    let err = ChainError::DepthExceeded {
        max_depth: 3,
        actual_depth: 7,
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: ChainError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, recovered);
}

#[test]
fn enrichment_chain_error_missing_checkpoint_serde() {
    let err = ChainError::MissingCheckpointBinding { index: 5 };
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: ChainError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, recovered);
}

#[test]
fn enrichment_chain_error_missing_revocation_serde() {
    let err = ChainError::MissingRevocationFreshnessBinding { index: 4 };
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: ChainError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, recovered);
}

#[test]
fn enrichment_chain_error_zone_mismatch_serde() {
    let err = ChainError::ZoneMismatch {
        index: 2,
        expected_zone: "alpha".to_string(),
        actual_zone: "beta".to_string(),
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: ChainError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, recovered);
}

#[test]
fn enrichment_chain_error_revoked_link_serde() {
    let err = ChainError::RevokedLink {
        index: 1,
        token_id: EngineObjectId([0xAA; 32]),
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: ChainError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, recovered);
}

#[test]
fn enrichment_chain_error_missing_capability_serde() {
    let err = ChainError::MissingCapabilityAtLeaf {
        required: RuntimeCapability::FsWrite,
        leaf_capabilities: BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::GcInvoke,
        ]),
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: ChainError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, recovered);
}

#[test]
fn enrichment_chain_error_attenuation_serde() {
    let err = ChainError::AttenuationViolation {
        index: 3,
        parent_capability_count: 2,
        child_capability_count: 5,
        amplified_capabilities: BTreeSet::from([
            RuntimeCapability::FsRead,
            RuntimeCapability::FsWrite,
            RuntimeCapability::ProcessSpawn,
        ]),
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: ChainError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, recovered);
}

#[test]
fn enrichment_delegation_verification_context_serde() {
    let root_sk = make_sk(42);
    let ctx = make_ctx(&root_sk);
    let json = serde_json::to_string(&ctx).expect("serialize");
    let recovered: DelegationVerificationContext =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ctx, recovered);
}

#[test]
fn enrichment_authorization_proof_serde_preserves_all_fields() {
    let (chain, root_sk, leaf) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);
    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();

    let json = serde_json::to_string(&proof).expect("serialize");
    let recovered: frankenengine_engine::delegation_chain::AuthorizationProof =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(proof, recovered);
}

#[test]
fn enrichment_delegation_link_summary_serde_all_fields() {
    let summary = frankenengine_engine::delegation_chain::DelegationLinkSummary {
        index: 7,
        token_id: EngineObjectId([0xCC; 32]),
        issuer: make_principal(1),
        delegate: make_principal(2),
        capability_count: 5,
        zone: "zone-test".to_string(),
        not_before_tick: 50,
        expiry_tick: 999,
    };
    let json = serde_json::to_string(&summary).expect("serialize");
    let recovered: frankenengine_engine::delegation_chain::DelegationLinkSummary =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(summary, recovered);
}

// --- 7. Zone enforcement ---

#[test]
fn enrichment_zone_mismatch_first_link_rejected() {
    let root_sk = make_sk(1);
    let leaf = make_principal(50);

    let link = make_bound_token_in_zone(
        &root_sk,
        leaf.clone(),
        &[RuntimeCapability::VmDispatch],
        "zone-wrong",
    );
    let chain = DelegationChain::new(vec![link]);

    let mut ctx = make_ctx(&root_sk);
    ctx.required_zone = Some("zone-required".to_string());

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("zone mismatch at root must fail");
    assert!(matches!(err, ChainError::ZoneMismatch { index: 0, .. }));
}

#[test]
fn enrichment_zone_mismatch_middle_link_rejected() {
    let root_sk = make_sk(1);
    let issuer_sk = make_sk(2);
    let delegate_sk = make_sk(3);
    let leaf = make_principal(50);

    let link0 = make_bound_token_in_zone(
        &root_sk,
        principal_id_from_verification_key(&issuer_sk.verification_key()),
        &[RuntimeCapability::VmDispatch],
        "zone-a",
    );
    let link1 = make_bound_token_in_zone(
        &issuer_sk,
        principal_id_from_verification_key(&delegate_sk.verification_key()),
        &[RuntimeCapability::VmDispatch],
        "zone-b", // mismatch
    );
    let link2 = make_bound_token_in_zone(
        &delegate_sk,
        leaf.clone(),
        &[RuntimeCapability::VmDispatch],
        "zone-a",
    );

    let chain = DelegationChain::new(vec![link0, link1, link2]);
    let ctx = make_ctx(&root_sk);

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("zone mismatch at middle link");
    assert!(matches!(err, ChainError::ZoneMismatch { index: 1, .. }));
}

#[test]
fn enrichment_zone_inferred_from_root_when_none_required() {
    let root_sk = make_sk(1);
    let leaf = make_principal(50);

    let link = make_bound_token_in_zone(
        &root_sk,
        leaf.clone(),
        &[RuntimeCapability::VmDispatch],
        "inferred-zone",
    );
    let chain = DelegationChain::new(vec![link]);

    let mut ctx = make_ctx(&root_sk);
    ctx.required_zone = None;

    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("zone inferred from root should pass");
    assert_eq!(proof.chain_summary[0].zone, "inferred-zone");
}

#[test]
fn enrichment_all_links_same_zone_passes() {
    let root_sk = make_sk(1);
    let issuer_sk = make_sk(2);
    let leaf = make_principal(50);

    let link0 = make_bound_token_in_zone(
        &root_sk,
        principal_id_from_verification_key(&issuer_sk.verification_key()),
        &[RuntimeCapability::VmDispatch],
        "zone-unified",
    );
    let link1 = make_bound_token_in_zone(
        &issuer_sk,
        leaf.clone(),
        &[RuntimeCapability::VmDispatch],
        "zone-unified",
    );

    let chain = DelegationChain::new(vec![link0, link1]);
    let mut ctx = make_ctx(&root_sk);
    ctx.required_zone = Some("zone-unified".to_string());

    verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("all same zone should pass");
}

// --- 8. Revocation oracle variants ---

#[test]
fn enrichment_revoke_last_link_only() {
    let (chain, root_sk, leaf) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);
    let mut revoked = BTreeSet::new();
    revoked.insert(chain.links[2].jti.clone());
    let oracle = SetRevocationOracle { revoked };

    let err = verify_chain(&chain, RuntimeCapability::VmDispatch, &leaf, &ctx, &oracle)
        .expect_err("revoking leaf must fail");
    assert!(matches!(err, ChainError::RevokedLink { index: 2, .. }));
}

#[test]
fn enrichment_revoke_all_links_reports_first() {
    let (chain, root_sk, leaf) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);
    let mut revoked = BTreeSet::new();
    for link in &chain.links {
        revoked.insert(link.jti.clone());
    }
    let oracle = SetRevocationOracle { revoked };

    let err = verify_chain(&chain, RuntimeCapability::VmDispatch, &leaf, &ctx, &oracle)
        .expect_err("all revoked must fail");
    assert!(matches!(err, ChainError::RevokedLink { index: 0, .. }));
}

#[test]
fn enrichment_no_revocation_oracle_allows_any_token() {
    let oracle = NoRevocationOracle;
    for i in 0..=255u8 {
        assert!(!oracle.is_revoked(&EngineObjectId([i; 32])));
    }
}

#[test]
fn enrichment_set_revocation_oracle_empty_revokes_nothing() {
    let oracle = SetRevocationOracle {
        revoked: BTreeSet::new(),
    };
    assert!(!oracle.is_revoked(&EngineObjectId([1; 32])));
    assert!(!oracle.is_revoked(&EngineObjectId([255; 32])));
}

#[test]
fn enrichment_set_revocation_oracle_multiple_tokens() {
    let mut revoked = BTreeSet::new();
    revoked.insert(EngineObjectId([1; 32]));
    revoked.insert(EngineObjectId([2; 32]));
    revoked.insert(EngineObjectId([3; 32]));
    let oracle = SetRevocationOracle { revoked };

    assert!(oracle.is_revoked(&EngineObjectId([1; 32])));
    assert!(oracle.is_revoked(&EngineObjectId([2; 32])));
    assert!(oracle.is_revoked(&EngineObjectId([3; 32])));
    assert!(!oracle.is_revoked(&EngineObjectId([4; 32])));
}

// --- 9. Multiple authorized roots ---

#[test]
fn enrichment_multiple_roots_accept_first() {
    let root_sk_1 = make_sk(1);
    let root_sk_2 = make_sk(2);
    let leaf = make_principal(50);

    let link = make_bound_token(&root_sk_1, leaf.clone(), &[RuntimeCapability::VmDispatch]);
    let chain = DelegationChain::new(vec![link]);

    let mut roots = BTreeSet::new();
    roots.insert(root_sk_1.verification_key());
    roots.insert(root_sk_2.verification_key());
    let ctx = DelegationVerificationContext {
        current_tick: 500,
        verifier_checkpoint_seq: 10,
        verifier_revocation_seq: 10,
        max_chain_depth: 8,
        authorized_roots: roots,
        required_zone: Some("zone-a".to_string()),
    };

    verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("first of multiple roots should be accepted");
}

#[test]
fn enrichment_multiple_roots_accept_second() {
    let root_sk_1 = make_sk(1);
    let root_sk_2 = make_sk(2);
    let leaf = make_principal(50);

    let link = make_bound_token(&root_sk_2, leaf.clone(), &[RuntimeCapability::VmDispatch]);
    let chain = DelegationChain::new(vec![link]);

    let mut roots = BTreeSet::new();
    roots.insert(root_sk_1.verification_key());
    roots.insert(root_sk_2.verification_key());
    let ctx = DelegationVerificationContext {
        current_tick: 500,
        verifier_checkpoint_seq: 10,
        verifier_revocation_seq: 10,
        max_chain_depth: 8,
        authorized_roots: roots,
        required_zone: Some("zone-a".to_string()),
    };

    verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("second of multiple roots should be accepted");
}

#[test]
fn enrichment_no_authorized_roots_rejects_everything() {
    let root_sk = make_sk(1);
    let leaf = make_principal(50);
    let link = make_bound_token(&root_sk, leaf.clone(), &[RuntimeCapability::VmDispatch]);
    let chain = DelegationChain::new(vec![link]);

    let ctx = DelegationVerificationContext {
        current_tick: 500,
        verifier_checkpoint_seq: 10,
        verifier_revocation_seq: 10,
        max_chain_depth: 8,
        authorized_roots: BTreeSet::new(),
        required_zone: Some("zone-a".to_string()),
    };

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("no authorized roots must reject");
    assert!(matches!(err, ChainError::UnauthorizedRoot { .. }));
}

// --- 10. Display format content checks ---

#[test]
fn enrichment_display_empty_chain_contains_no_ambient() {
    let msg = ChainError::EmptyChain.to_string();
    assert!(msg.contains("no ambient authority"));
}

#[test]
fn enrichment_display_depth_exceeded_contains_counts() {
    let msg = ChainError::DepthExceeded {
        max_depth: 4,
        actual_depth: 9,
    }
    .to_string();
    assert!(msg.contains("4"));
    assert!(msg.contains("9"));
}

#[test]
fn enrichment_display_unauthorized_root_contains_issuer() {
    let vk = make_sk(42).verification_key();
    let msg = ChainError::UnauthorizedRoot {
        root_issuer: vk.clone(),
    }
    .to_string();
    assert!(msg.contains("unauthorized root"));
}

#[test]
fn enrichment_display_missing_checkpoint_binding_contains_index() {
    let msg = ChainError::MissingCheckpointBinding { index: 7 }.to_string();
    assert!(msg.contains("7"));
    assert!(msg.contains("checkpoint"));
}

#[test]
fn enrichment_display_missing_revocation_contains_index() {
    let msg = ChainError::MissingRevocationFreshnessBinding { index: 4 }.to_string();
    assert!(msg.contains("4"));
    assert!(msg.contains("revocation"));
}

#[test]
fn enrichment_display_attenuation_contains_index_and_counts() {
    let msg = ChainError::AttenuationViolation {
        index: 2,
        parent_capability_count: 1,
        child_capability_count: 4,
        amplified_capabilities: BTreeSet::from([RuntimeCapability::NetworkEgress]),
    }
    .to_string();
    assert!(msg.contains("2"));
    assert!(msg.contains("attenuation"));
}

#[test]
fn enrichment_display_zone_mismatch_contains_zones() {
    let msg = ChainError::ZoneMismatch {
        index: 0,
        expected_zone: "zone-x".to_string(),
        actual_zone: "zone-y".to_string(),
    }
    .to_string();
    assert!(msg.contains("zone-x"));
    assert!(msg.contains("zone-y"));
}

#[test]
fn enrichment_display_revoked_link_contains_index() {
    let msg = ChainError::RevokedLink {
        index: 3,
        token_id: EngineObjectId([0xFF; 32]),
    }
    .to_string();
    assert!(msg.contains("3"));
    assert!(msg.contains("revoked"));
}

#[test]
fn enrichment_display_missing_capability_at_leaf_contains_cap() {
    let msg = ChainError::MissingCapabilityAtLeaf {
        required: RuntimeCapability::FsRead,
        leaf_capabilities: BTreeSet::from([RuntimeCapability::VmDispatch]),
    }
    .to_string();
    assert!(msg.contains("fs_read"));
}

// --- 11. Context construction ---

#[test]
fn enrichment_context_with_authorized_root_has_default_depth() {
    let sk = make_sk(1);
    let ctx = DelegationVerificationContext::with_authorized_root(sk.verification_key());
    assert_eq!(
        ctx.max_chain_depth,
        frankenengine_engine::delegation_chain::DEFAULT_MAX_CHAIN_DEPTH
    );
}

#[test]
fn enrichment_context_default_has_no_zone() {
    let ctx = DelegationVerificationContext::default();
    assert!(ctx.required_zone.is_none());
}

#[test]
fn enrichment_context_default_has_zero_tick() {
    let ctx = DelegationVerificationContext::default();
    assert_eq!(ctx.current_tick, 0);
    assert_eq!(ctx.verifier_checkpoint_seq, 0);
    assert_eq!(ctx.verifier_revocation_seq, 0);
}

#[test]
fn enrichment_context_clone_independence() {
    let root_sk = make_sk(1);
    let ctx = make_ctx(&root_sk);
    let mut ctx2 = ctx.clone();
    ctx2.max_chain_depth = 100;
    ctx2.current_tick = 999;
    assert_ne!(ctx.max_chain_depth, ctx2.max_chain_depth);
    assert_ne!(ctx.current_tick, ctx2.current_tick);
    assert_eq!(ctx.authorized_roots, ctx2.authorized_roots);
}

// --- 12. principal_id_from_verification_key ---

#[test]
fn enrichment_principal_id_from_vk_is_pure_function() {
    let sk = make_sk(100);
    let vk = sk.verification_key();
    let results: Vec<_> = (0..10)
        .map(|_| principal_id_from_verification_key(&vk))
        .collect();
    for r in &results {
        assert_eq!(*r, results[0]);
    }
}

#[test]
fn enrichment_principal_id_different_for_each_seed() {
    let ids: BTreeSet<_> = (1..=20u8)
        .map(|seed| {
            let sk = make_sk(seed);
            principal_id_from_verification_key(&sk.verification_key())
        })
        .collect();
    assert_eq!(
        ids.len(),
        20,
        "all 20 seeds must produce distinct principals"
    );
}

// --- 13. Chain verify method vs free function ---

#[test]
fn enrichment_verify_method_error_matches_free_function() {
    let chain = DelegationChain::new(vec![]);
    let root_sk = make_sk(1);
    let leaf = make_principal(50);
    let ctx = make_ctx(&root_sk);

    let err_method = chain
        .verify(
            RuntimeCapability::VmDispatch,
            &leaf,
            &ctx,
            &NoRevocationOracle,
        )
        .expect_err("method");
    let err_fn = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("function");

    assert_eq!(err_method, err_fn);
}

#[test]
fn enrichment_verify_method_proof_hash_matches_free_function() {
    let root_sk = make_sk(1);
    let leaf = make_principal(50);
    let link = make_bound_token(&root_sk, leaf.clone(), &[RuntimeCapability::VmDispatch]);
    let chain = DelegationChain::new(vec![link]);
    let ctx = make_ctx(&root_sk);

    let p1 = chain
        .verify(
            RuntimeCapability::VmDispatch,
            &leaf,
            &ctx,
            &NoRevocationOracle,
        )
        .unwrap();
    let p2 = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();

    assert_eq!(p1.chain_hash, p2.chain_hash);
    assert_eq!(p1.root_issuer, p2.root_issuer);
    assert_eq!(p1.leaf_delegate, p2.leaf_delegate);
    assert_eq!(p1.chain_summary, p2.chain_summary);
}

// --- 14. DelegationChain Debug/Clone/PartialEq ---

#[test]
fn enrichment_chain_debug_nonempty() {
    let (chain, _, _) = valid_chain_fixture();
    let debug = format!("{chain:?}");
    assert!(!debug.is_empty());
    assert!(debug.contains("DelegationChain"));
}

#[test]
fn enrichment_chain_clone_equals_original() {
    let (chain, _, _) = valid_chain_fixture();
    let cloned = chain.clone();
    assert_eq!(chain, cloned);
}

#[test]
fn enrichment_chain_clone_independence() {
    let (chain, _, _) = valid_chain_fixture();
    let mut cloned = chain.clone();
    cloned.links.pop();
    assert_ne!(chain.links.len(), cloned.links.len());
}

#[test]
fn enrichment_chain_partial_eq_different_chains() {
    let root_sk = make_sk(1);
    let leaf_a = make_principal(10);
    let leaf_b = make_principal(20);

    let chain_a = DelegationChain::new(vec![make_bound_token(
        &root_sk,
        leaf_a,
        &[RuntimeCapability::VmDispatch],
    )]);
    let chain_b = DelegationChain::new(vec![make_bound_token(
        &root_sk,
        leaf_b,
        &[RuntimeCapability::VmDispatch],
    )]);
    assert_ne!(chain_a, chain_b);
}

// --- 15. Proof structure ---

#[test]
fn enrichment_proof_root_issuer_matches_chain_root() {
    let (chain, root_sk, leaf) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);
    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();

    let expected = principal_id_from_verification_key(&root_sk.verification_key());
    assert_eq!(proof.root_issuer, expected);
}

#[test]
fn enrichment_proof_capability_matches_request() {
    let root_sk = make_sk(1);
    let leaf = make_principal(50);
    let link = make_bound_token(
        &root_sk,
        leaf.clone(),
        &[RuntimeCapability::VmDispatch, RuntimeCapability::GcInvoke],
    );
    let chain = DelegationChain::new(vec![link]);
    let ctx = make_ctx(&root_sk);

    let proof_vm = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();
    assert_eq!(
        proof_vm.authorized_capability,
        RuntimeCapability::VmDispatch
    );

    let proof_gc = verify_chain(
        &chain,
        RuntimeCapability::GcInvoke,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();
    assert_eq!(proof_gc.authorized_capability, RuntimeCapability::GcInvoke);
}

#[test]
fn enrichment_proof_chain_hash_differs_for_different_capabilities() {
    let root_sk = make_sk(1);
    let leaf = make_principal(50);
    let link = make_bound_token(
        &root_sk,
        leaf.clone(),
        &[RuntimeCapability::VmDispatch, RuntimeCapability::GcInvoke],
    );
    let chain = DelegationChain::new(vec![link]);
    let ctx = make_ctx(&root_sk);

    let proof_vm = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();
    let proof_gc = verify_chain(
        &chain,
        RuntimeCapability::GcInvoke,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();

    // The chain hash is computed from link data and leaf delegate, NOT from
    // the requested capability, so both hashes should be equal.
    assert_eq!(proof_vm.chain_hash, proof_gc.chain_hash);
}

// --- 16. Link summary temporal fields ---

#[test]
fn enrichment_link_summary_temporal_fields() {
    let root_sk = make_sk(1);
    let leaf = make_principal(50);
    let link = make_bound_token_timed(
        &root_sk,
        leaf.clone(),
        &[RuntimeCapability::VmDispatch],
        200,
        2000,
    );
    let chain = DelegationChain::new(vec![link]);
    let mut ctx = make_ctx(&root_sk);
    ctx.current_tick = 500;

    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();
    assert_eq!(proof.chain_summary[0].not_before_tick, 200);
    assert_eq!(proof.chain_summary[0].expiry_tick, 2000);
}

// --- 17. Error variant matching exhaustiveness ---

#[test]
fn enrichment_all_chain_error_variants_have_distinct_debug() {
    let errors: Vec<ChainError> = vec![
        ChainError::EmptyChain,
        ChainError::DepthExceeded {
            max_depth: 1,
            actual_depth: 2,
        },
        ChainError::UnauthorizedRoot {
            root_issuer: make_sk(1).verification_key(),
        },
        ChainError::MissingCheckpointBinding { index: 0 },
        ChainError::MissingRevocationFreshnessBinding { index: 0 },
        ChainError::TokenVerificationFailed {
            index: 0,
            error: TokenError::Expired {
                current_tick: 999,
                expiry: 100,
            },
        },
        ChainError::AttenuationViolation {
            index: 0,
            parent_capability_count: 1,
            child_capability_count: 2,
            amplified_capabilities: BTreeSet::new(),
        },
        ChainError::ZoneMismatch {
            index: 0,
            expected_zone: "a".to_string(),
            actual_zone: "b".to_string(),
        },
        ChainError::RevokedLink {
            index: 0,
            token_id: EngineObjectId([0; 32]),
        },
        ChainError::MissingCapabilityAtLeaf {
            required: RuntimeCapability::VmDispatch,
            leaf_capabilities: BTreeSet::new(),
        },
    ];

    let debugs: BTreeSet<String> = errors.iter().map(|e| format!("{e:?}")).collect();
    assert_eq!(
        debugs.len(),
        errors.len(),
        "all error Debug must be distinct"
    );
}

// --- 18. Deterministic replay ---

#[test]
fn enrichment_deterministic_replay_ten_times() {
    let run = || {
        let (chain, root_sk, leaf) = valid_chain_fixture();
        let ctx = make_ctx(&root_sk);
        verify_chain(
            &chain,
            RuntimeCapability::VmDispatch,
            &leaf,
            &ctx,
            &NoRevocationOracle,
        )
        .unwrap()
    };

    let baseline = run();
    for _ in 0..10 {
        let r = run();
        assert_eq!(baseline.chain_hash, r.chain_hash);
        assert_eq!(baseline.root_issuer, r.root_issuer);
        assert_eq!(baseline.leaf_delegate, r.leaf_delegate);
        assert_eq!(baseline.chain_summary, r.chain_summary);
    }
}

// --- 19. Token ID propagation ---

#[test]
fn enrichment_proof_summary_token_ids_match_chain_links() {
    let (chain, root_sk, leaf) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);
    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();

    for (i, summary) in proof.chain_summary.iter().enumerate() {
        assert_eq!(summary.token_id, chain.links[i].jti);
    }
}

// --- 20. All capabilities through attenuation ---

#[test]
fn enrichment_all_runtime_capabilities_can_be_granted() {
    let all_caps = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::GcInvoke,
        RuntimeCapability::IrLowering,
        RuntimeCapability::PolicyRead,
        RuntimeCapability::PolicyWrite,
        RuntimeCapability::EvidenceEmit,
        RuntimeCapability::DecisionInvoke,
        RuntimeCapability::NetworkEgress,
        RuntimeCapability::LeaseManagement,
        RuntimeCapability::IdempotencyDerive,
        RuntimeCapability::ExtensionLifecycle,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::EnvRead,
        RuntimeCapability::ProcessSpawn,
        RuntimeCapability::FsRead,
        RuntimeCapability::FsWrite,
    ];

    let root_sk = make_sk(1);
    let leaf = make_principal(50);

    for cap in &all_caps {
        let link = make_bound_token(&root_sk, leaf.clone(), &[*cap]);
        let chain = DelegationChain::new(vec![link]);
        let ctx = make_ctx(&root_sk);
        let proof = verify_chain(&chain, *cap, &leaf, &ctx, &NoRevocationOracle)
            .unwrap_or_else(|e| panic!("capability {cap:?} should be grantable: {e}"));
        assert_eq!(proof.authorized_capability, *cap);
    }
}

#[test]
fn enrichment_all_runtime_capabilities_through_attenuation() {
    let all_caps = vec![
        RuntimeCapability::VmDispatch,
        RuntimeCapability::GcInvoke,
        RuntimeCapability::IrLowering,
        RuntimeCapability::PolicyRead,
        RuntimeCapability::PolicyWrite,
        RuntimeCapability::EvidenceEmit,
        RuntimeCapability::DecisionInvoke,
        RuntimeCapability::NetworkEgress,
        RuntimeCapability::LeaseManagement,
        RuntimeCapability::IdempotencyDerive,
        RuntimeCapability::ExtensionLifecycle,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::EnvRead,
        RuntimeCapability::ProcessSpawn,
        RuntimeCapability::FsRead,
        RuntimeCapability::FsWrite,
    ];

    let root_sk = make_sk(1);
    let issuer_sk = make_sk(2);
    let leaf = make_principal(50);

    // Root grants all caps; child attenuates to each single one
    for cap in &all_caps {
        let link0 = make_bound_token(
            &root_sk,
            principal_id_from_verification_key(&issuer_sk.verification_key()),
            &all_caps,
        );
        let link1 = make_bound_token(&issuer_sk, leaf.clone(), &[*cap]);
        let chain = DelegationChain::new(vec![link0, link1]);
        let ctx = make_ctx(&root_sk);
        let proof = verify_chain(&chain, *cap, &leaf, &ctx, &NoRevocationOracle)
            .unwrap_or_else(|e| panic!("attenuation to {cap:?} should pass: {e}"));
        assert_eq!(proof.authorized_capability, *cap);
        assert_eq!(proof.chain_summary[1].capability_count, 1);
    }
}

// --- 21. DEFAULT_MAX_CHAIN_DEPTH constant ---

#[test]
fn enrichment_default_max_chain_depth_is_eight() {
    assert_eq!(
        frankenengine_engine::delegation_chain::DEFAULT_MAX_CHAIN_DEPTH,
        8
    );
}

// --- 22. Error equality ---

#[test]
fn enrichment_chain_error_eq_same_variant() {
    let a = ChainError::EmptyChain;
    let b = ChainError::EmptyChain;
    assert_eq!(a, b);
}

#[test]
fn enrichment_chain_error_ne_different_variant() {
    let a = ChainError::EmptyChain;
    let b = ChainError::DepthExceeded {
        max_depth: 1,
        actual_depth: 2,
    };
    assert_ne!(a, b);
}

#[test]
fn enrichment_chain_error_ne_same_variant_different_fields() {
    let a = ChainError::DepthExceeded {
        max_depth: 1,
        actual_depth: 2,
    };
    let b = ChainError::DepthExceeded {
        max_depth: 3,
        actual_depth: 4,
    };
    assert_ne!(a, b);
}

// --- 23. Proof equality ---

#[test]
fn enrichment_proof_eq_identical_chains() {
    let (chain, root_sk, leaf) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);
    let p1 = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();
    let p2 = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();
    assert_eq!(p1, p2);
}

// --- 24. Chain with many capabilities ---

#[test]
fn enrichment_chain_with_full_capability_set() {
    let all_caps = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::GcInvoke,
        RuntimeCapability::IrLowering,
        RuntimeCapability::PolicyRead,
        RuntimeCapability::PolicyWrite,
        RuntimeCapability::EvidenceEmit,
        RuntimeCapability::DecisionInvoke,
        RuntimeCapability::NetworkEgress,
        RuntimeCapability::LeaseManagement,
        RuntimeCapability::IdempotencyDerive,
        RuntimeCapability::ExtensionLifecycle,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::EnvRead,
        RuntimeCapability::ProcessSpawn,
        RuntimeCapability::FsRead,
        RuntimeCapability::FsWrite,
    ];

    let root_sk = make_sk(1);
    let leaf = make_principal(50);
    let link = make_bound_token(&root_sk, leaf.clone(), &all_caps);
    let chain = DelegationChain::new(vec![link]);
    let ctx = make_ctx(&root_sk);

    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();
    assert_eq!(proof.chain_summary[0].capability_count, all_caps.len());
}

// --- 25. Expired token in chain ---

#[test]
fn enrichment_expired_token_in_chain_rejected() {
    let root_sk = make_sk(1);
    let leaf = make_principal(50);
    let link = make_bound_token_timed(
        &root_sk,
        leaf.clone(),
        &[RuntimeCapability::VmDispatch],
        100,
        200, // expires at 200
    );
    let chain = DelegationChain::new(vec![link]);
    let mut ctx = make_ctx(&root_sk);
    ctx.current_tick = 300; // past expiry

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("expired token must fail");
    assert!(matches!(
        err,
        ChainError::TokenVerificationFailed { index: 0, .. }
    ));
}

#[test]
fn enrichment_token_not_yet_valid_rejected() {
    let root_sk = make_sk(1);
    let leaf = make_principal(50);
    let link = make_bound_token_timed(
        &root_sk,
        leaf.clone(),
        &[RuntimeCapability::VmDispatch],
        500,
        1000,
    );
    let chain = DelegationChain::new(vec![link]);
    let mut ctx = make_ctx(&root_sk);
    ctx.current_tick = 100; // before nbf

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf,
        &ctx,
        &NoRevocationOracle,
    )
    .expect_err("not-yet-valid token must fail");
    assert!(matches!(
        err,
        ChainError::TokenVerificationFailed { index: 0, .. }
    ));
}

// --- 26. DelegationLinkSummary equality ---

#[test]
fn enrichment_link_summary_ne_different_index() {
    let a = frankenengine_engine::delegation_chain::DelegationLinkSummary {
        index: 0,
        token_id: EngineObjectId([1; 32]),
        issuer: make_principal(1),
        delegate: make_principal(2),
        capability_count: 1,
        zone: "z".to_string(),
        not_before_tick: 0,
        expiry_tick: 100,
    };
    let mut b = a.clone();
    b.index = 1;
    assert_ne!(a, b);
}

#[test]
fn enrichment_link_summary_eq_identical() {
    let a = frankenengine_engine::delegation_chain::DelegationLinkSummary {
        index: 0,
        token_id: EngineObjectId([1; 32]),
        issuer: make_principal(1),
        delegate: make_principal(2),
        capability_count: 1,
        zone: "z".to_string(),
        not_before_tick: 0,
        expiry_tick: 100,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

// --- 27. NoRevocationOracle traits ---

#[test]
fn enrichment_no_revocation_oracle_is_copy() {
    let a = NoRevocationOracle;
    let b = a;
    let _c = a; // would fail if not Copy
    assert!(!b.is_revoked(&EngineObjectId([0; 32])));
}

#[test]
fn enrichment_no_revocation_oracle_default() {
    let oracle: NoRevocationOracle = Default::default();
    assert!(!oracle.is_revoked(&EngineObjectId([42; 32])));
}
