#![forbid(unsafe_code)]

//! Enrichment integration tests for the `delegation_chain` module.
//!
//! Covers: Clone independence, Debug/Display uniqueness, serde JSON field-name
//! stability, BTreeSet ordering for authorized roots, determinism N-run proofs,
//! boundary conditions, std::error::Error trait, and cross-property invariants.

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
    ChainError, DEFAULT_MAX_CHAIN_DEPTH, DelegationChain, DelegationLinkSummary,
    DelegationVerificationContext, NoRevocationOracle, RevocationOracle,
    principal_id_from_verification_key, verify_chain,
};
use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{SigningKey, VerificationKey};

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

// ===========================================================================
// 1. DelegationChain — Clone independence, Debug
// ===========================================================================

#[test]
fn enrichment_delegation_chain_clone_independence() {
    let (original, _, _) = valid_chain_fixture();
    let cloned = original.clone();
    // Both should be equal
    assert_eq!(original, cloned);
    // They are independent (mutating cloned won't affect original — but since
    // DelegationChain fields are pub, we verify via separate identity)
    assert_eq!(original.len(), cloned.len());
    assert_eq!(original.links.len(), cloned.links.len());
}

#[test]
fn enrichment_delegation_chain_debug_nonempty() {
    let (chain, _, _) = valid_chain_fixture();
    let dbg = format!("{chain:?}");
    assert!(!dbg.is_empty());
    assert!(
        dbg.contains("DelegationChain"),
        "Debug should contain type name"
    );
}

#[test]
fn enrichment_delegation_chain_debug_empty() {
    let chain = DelegationChain::new(Vec::new());
    let dbg = format!("{chain:?}");
    assert!(dbg.contains("DelegationChain"));
}

// ===========================================================================
// 2. DelegationVerificationContext — Clone independence, Debug, BTreeSet
// ===========================================================================

#[test]
fn enrichment_verification_context_clone_independence() {
    let root_sk = make_sk(1);
    let original = make_ctx(&root_sk);
    let mut cloned = original.clone();
    cloned.current_tick = 9999;
    cloned.max_chain_depth = 1;
    cloned.required_zone = Some("zone-x".to_string());
    // Original should be unchanged
    assert_eq!(original.current_tick, 500);
    assert_eq!(original.max_chain_depth, DEFAULT_MAX_CHAIN_DEPTH);
    assert_eq!(original.required_zone, Some("zone-a".to_string()));
}

#[test]
fn enrichment_verification_context_debug_includes_fields() {
    let root_sk = make_sk(1);
    let ctx = make_ctx(&root_sk);
    let dbg = format!("{ctx:?}");
    assert!(dbg.contains("current_tick"), "Debug missing current_tick");
    assert!(
        dbg.contains("max_chain_depth"),
        "Debug missing max_chain_depth"
    );
    assert!(
        dbg.contains("authorized_roots"),
        "Debug missing authorized_roots"
    );
}

#[test]
fn enrichment_verification_context_authorized_roots_btreeset_dedup() {
    let root_sk = make_sk(1);
    let vk = root_sk.verification_key();
    let mut roots = BTreeSet::new();
    roots.insert(vk.clone());
    roots.insert(vk.clone()); // duplicate
    roots.insert(vk); // triple
    assert_eq!(roots.len(), 1);
}

#[test]
fn enrichment_verification_context_authorized_roots_btreeset_ordering_stable() {
    let vk1 = make_sk(1).verification_key();
    let vk2 = make_sk(2).verification_key();
    let vk3 = make_sk(3).verification_key();
    let mut roots = BTreeSet::new();
    roots.insert(vk3.clone());
    roots.insert(vk1.clone());
    roots.insert(vk2.clone());
    // BTreeSet should produce deterministic ordering
    let order1: Vec<_> = roots.iter().collect();
    let order2: Vec<_> = roots.iter().collect();
    assert_eq!(order1, order2);
    assert_eq!(roots.len(), 3);
}

#[test]
fn enrichment_verification_context_json_field_names_stable() {
    let root_sk = make_sk(1);
    let ctx = make_ctx(&root_sk);
    let json = serde_json::to_string(&ctx).unwrap();
    for field in &[
        "current_tick",
        "verifier_checkpoint_seq",
        "verifier_revocation_seq",
        "max_chain_depth",
        "authorized_roots",
        "required_zone",
    ] {
        assert!(json.contains(field), "missing JSON field: {field}");
    }
}

// ===========================================================================
// 3. ChainError — Display uniqueness, Debug distinctness, serde stability
// ===========================================================================

#[test]
fn enrichment_chain_error_display_all_variants_unique() {
    let variants: Vec<ChainError> = vec![
        ChainError::EmptyChain,
        ChainError::DepthExceeded {
            max_depth: 8,
            actual_depth: 12,
        },
        ChainError::UnauthorizedRoot {
            root_issuer: VerificationKey::from_bytes([0xAB; 32]),
        },
        ChainError::MissingCheckpointBinding { index: 0 },
        ChainError::MissingRevocationFreshnessBinding { index: 1 },
        ChainError::TokenVerificationFailed {
            index: 2,
            error: TokenError::SignatureInvalid {
                detail: "bad".to_string(),
            },
        },
        ChainError::AttenuationViolation {
            index: 3,
            parent_capability_count: 2,
            child_capability_count: 4,
            amplified_capabilities: {
                let mut s = BTreeSet::new();
                s.insert(RuntimeCapability::NetworkEgress);
                s
            },
        },
        ChainError::ZoneMismatch {
            index: 4,
            expected_zone: "zone-a".to_string(),
            actual_zone: "zone-b".to_string(),
        },
        ChainError::RevokedLink {
            index: 5,
            token_id: EngineObjectId([0xDE; 32]),
        },
        ChainError::MissingCapabilityAtLeaf {
            required: RuntimeCapability::VmDispatch,
            leaf_capabilities: {
                let mut s = BTreeSet::new();
                s.insert(RuntimeCapability::GcInvoke);
                s
            },
        },
    ];
    let displays: BTreeSet<String> = variants.iter().map(|e| e.to_string()).collect();
    assert_eq!(
        displays.len(),
        variants.len(),
        "all ChainError Display strings should be unique"
    );
}

#[test]
fn enrichment_chain_error_debug_all_variants_unique() {
    let variants: Vec<ChainError> = vec![
        ChainError::EmptyChain,
        ChainError::DepthExceeded {
            max_depth: 8,
            actual_depth: 12,
        },
        ChainError::UnauthorizedRoot {
            root_issuer: VerificationKey::from_bytes([0xAB; 32]),
        },
        ChainError::MissingCheckpointBinding { index: 0 },
        ChainError::MissingRevocationFreshnessBinding { index: 1 },
        ChainError::TokenVerificationFailed {
            index: 2,
            error: TokenError::SignatureInvalid {
                detail: "bad".to_string(),
            },
        },
        ChainError::AttenuationViolation {
            index: 3,
            parent_capability_count: 2,
            child_capability_count: 4,
            amplified_capabilities: BTreeSet::new(),
        },
        ChainError::ZoneMismatch {
            index: 4,
            expected_zone: "a".to_string(),
            actual_zone: "b".to_string(),
        },
        ChainError::RevokedLink {
            index: 5,
            token_id: EngineObjectId([0xDE; 32]),
        },
        ChainError::MissingCapabilityAtLeaf {
            required: RuntimeCapability::VmDispatch,
            leaf_capabilities: BTreeSet::new(),
        },
    ];
    let debugs: BTreeSet<String> = variants.iter().map(|e| format!("{e:?}")).collect();
    assert_eq!(
        debugs.len(),
        variants.len(),
        "all ChainError Debug representations should be unique"
    );
}

#[test]
fn enrichment_chain_error_std_error_trait() {
    let err: Box<dyn std::error::Error> = Box::new(ChainError::EmptyChain);
    assert!(!err.to_string().is_empty());
    // Also test a variant with data
    let err2: Box<dyn std::error::Error> = Box::new(ChainError::DepthExceeded {
        max_depth: 4,
        actual_depth: 10,
    });
    assert!(err2.to_string().contains("4"));
}

#[test]
fn enrichment_chain_error_serde_all_variants() {
    let variants: Vec<ChainError> = vec![
        ChainError::EmptyChain,
        ChainError::DepthExceeded {
            max_depth: 8,
            actual_depth: 12,
        },
        ChainError::UnauthorizedRoot {
            root_issuer: VerificationKey::from_bytes([0xAB; 32]),
        },
        ChainError::MissingCheckpointBinding { index: 0 },
        ChainError::MissingRevocationFreshnessBinding { index: 1 },
        ChainError::ZoneMismatch {
            index: 4,
            expected_zone: "a".to_string(),
            actual_zone: "b".to_string(),
        },
        ChainError::RevokedLink {
            index: 5,
            token_id: EngineObjectId([0xDE; 32]),
        },
        ChainError::MissingCapabilityAtLeaf {
            required: RuntimeCapability::VmDispatch,
            leaf_capabilities: {
                let mut s = BTreeSet::new();
                s.insert(RuntimeCapability::GcInvoke);
                s
            },
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: ChainError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored, "serde roundtrip failed for: {v:?}");
    }
}

#[test]
fn enrichment_chain_error_clone_independence() {
    let original = ChainError::DepthExceeded {
        max_depth: 8,
        actual_depth: 12,
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
    // Both should produce the same Display
    assert_eq!(original.to_string(), cloned.to_string());
}

// ===========================================================================
// 4. NoRevocationOracle — Copy, Debug, Default
// ===========================================================================

#[test]
fn enrichment_no_revocation_oracle_copy_semantics() {
    let oracle = NoRevocationOracle;
    let copy = oracle;
    // Both usable (Copy)
    assert!(!oracle.is_revoked(&EngineObjectId([0; 32])));
    assert!(!copy.is_revoked(&EngineObjectId([1; 32])));
}

#[test]
fn enrichment_no_revocation_oracle_debug() {
    let oracle = NoRevocationOracle;
    let dbg = format!("{oracle:?}");
    assert!(dbg.contains("NoRevocationOracle"));
}

#[test]
fn enrichment_no_revocation_oracle_default() {
    let oracle = NoRevocationOracle;
    assert!(!oracle.is_revoked(&EngineObjectId([42; 32])));
}

// ===========================================================================
// 5. DelegationLinkSummary — Clone, Debug, serde, JSON field names
// ===========================================================================

#[test]
fn enrichment_link_summary_clone_independence() {
    let original = DelegationLinkSummary {
        index: 0,
        token_id: EngineObjectId([0xAB; 32]),
        issuer: make_principal(1),
        delegate: make_principal(2),
        capability_count: 3,
        zone: "zone-x".to_string(),
        not_before_tick: 100,
        expiry_tick: 1000,
    };
    let mut cloned = original.clone();
    cloned.index = 99;
    cloned.capability_count = 0;
    cloned.zone = "zone-mutated".to_string();
    assert_eq!(original.index, 0);
    assert_eq!(original.capability_count, 3);
    assert_eq!(original.zone, "zone-x");
}

#[test]
fn enrichment_link_summary_debug() {
    let summary = DelegationLinkSummary {
        index: 0,
        token_id: EngineObjectId([0xAB; 32]),
        issuer: make_principal(1),
        delegate: make_principal(2),
        capability_count: 3,
        zone: "zone-a".to_string(),
        not_before_tick: 100,
        expiry_tick: 1000,
    };
    let dbg = format!("{summary:?}");
    assert!(dbg.contains("DelegationLinkSummary"));
    assert!(dbg.contains("zone-a"));
}

#[test]
fn enrichment_link_summary_json_field_names_stable() {
    let summary = DelegationLinkSummary {
        index: 0,
        token_id: EngineObjectId([0xAB; 32]),
        issuer: make_principal(1),
        delegate: make_principal(2),
        capability_count: 3,
        zone: "zone-a".to_string(),
        not_before_tick: 100,
        expiry_tick: 1000,
    };
    let json = serde_json::to_string(&summary).unwrap();
    for field in &[
        "index",
        "token_id",
        "issuer",
        "delegate",
        "capability_count",
        "zone",
        "not_before_tick",
        "expiry_tick",
    ] {
        assert!(json.contains(field), "missing JSON field: {field}");
    }
}

// ===========================================================================
// 6. AuthorizationProof — Clone, Debug, serde, JSON field names
// ===========================================================================

#[test]
fn enrichment_authorization_proof_clone_independence() {
    let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);
    let original = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();
    let cloned = original.clone();
    assert_eq!(original, cloned);
    assert_eq!(original.chain_hash, cloned.chain_hash);
    assert_eq!(original.authorized_capability, cloned.authorized_capability);
}

#[test]
fn enrichment_authorization_proof_debug() {
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
    let dbg = format!("{proof:?}");
    assert!(dbg.contains("AuthorizationProof"));
    assert!(dbg.contains("chain_hash"));
    assert!(dbg.contains("authorized_capability"));
}

#[test]
fn enrichment_authorization_proof_json_field_names_stable() {
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
    let json = serde_json::to_string(&proof).unwrap();
    for field in &[
        "chain_hash",
        "authorized_capability",
        "root_issuer",
        "leaf_delegate",
        "verified_at_tick",
        "chain_summary",
    ] {
        assert!(json.contains(field), "missing JSON field: {field}");
    }
}

// ===========================================================================
// 7. Determinism — N-run proofs
// ===========================================================================

#[test]
fn enrichment_determinism_five_run_proof() {
    let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);
    let reference = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();

    for run in 1..5 {
        let trial = verify_chain(
            &chain,
            RuntimeCapability::VmDispatch,
            &leaf_delegate,
            &ctx,
            &NoRevocationOracle,
        )
        .unwrap();
        assert_eq!(
            reference.chain_hash, trial.chain_hash,
            "chain_hash mismatch on run {run}"
        );
        assert_eq!(
            reference.authorized_capability, trial.authorized_capability,
            "authorized_capability mismatch on run {run}"
        );
        assert_eq!(
            reference.root_issuer, trial.root_issuer,
            "root_issuer mismatch on run {run}"
        );
        assert_eq!(
            reference.chain_summary, trial.chain_summary,
            "chain_summary mismatch on run {run}"
        );
    }
}

// ===========================================================================
// 8. principal_id_from_verification_key — deep properties
// ===========================================================================

#[test]
fn enrichment_principal_id_deterministic_across_calls() {
    let vk = make_sk(42).verification_key();
    let p1 = principal_id_from_verification_key(&vk);
    let p2 = principal_id_from_verification_key(&vk);
    let p3 = principal_id_from_verification_key(&vk);
    assert_eq!(p1, p2);
    assert_eq!(p2, p3);
}

#[test]
fn enrichment_principal_id_all_different_seeds_unique() {
    let mut principals = BTreeSet::new();
    for seed in 0u8..20 {
        let vk = make_sk(seed).verification_key();
        let p = principal_id_from_verification_key(&vk);
        principals.insert(p);
    }
    assert_eq!(
        principals.len(),
        20,
        "all 20 seeds should produce unique principals"
    );
}

// ===========================================================================
// 9. DelegationChain — serde JSON field names, Debug
// ===========================================================================

#[test]
fn enrichment_delegation_chain_json_field_names_stable() {
    let (chain, _, _) = valid_chain_fixture();
    let json = serde_json::to_string(&chain).unwrap();
    assert!(json.contains("\"links\""), "missing JSON field: links");
}

#[test]
fn enrichment_delegation_chain_serde_empty_roundtrip() {
    let chain = DelegationChain::new(Vec::new());
    let json = serde_json::to_string(&chain).unwrap();
    let restored: DelegationChain = serde_json::from_str(&json).unwrap();
    assert_eq!(chain, restored);
    assert!(restored.is_empty());
}

// ===========================================================================
// 10. DEFAULT_MAX_CHAIN_DEPTH constant
// ===========================================================================

#[test]
fn enrichment_default_max_chain_depth_reasonable() {
    assert!(
        DEFAULT_MAX_CHAIN_DEPTH >= 2,
        "must allow at least 2-link chains"
    );
    assert!(
        DEFAULT_MAX_CHAIN_DEPTH <= 256,
        "should not allow absurd depth"
    );
}

// ===========================================================================
// 11. verify_chain — boundary and cross-cutting invariants
// ===========================================================================

#[test]
fn enrichment_verify_chain_proof_verified_at_tick_matches_context() {
    let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
    let mut ctx = make_ctx(&root_sk);
    ctx.current_tick = 777;
    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();
    assert_eq!(proof.verified_at_tick, 777);
}

#[test]
fn enrichment_verify_chain_summary_indices_sequential() {
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
        assert_eq!(summary.index, i, "summary index should be sequential");
    }
}

#[test]
fn enrichment_verify_chain_summary_len_matches_chain_len() {
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
    assert_eq!(proof.chain_summary.len(), chain.len());
}

#[test]
fn enrichment_verify_chain_all_summaries_same_zone() {
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
        assert_eq!(
            summary.zone, "zone-a",
            "all links should be in the required zone"
        );
    }
}

#[test]
fn enrichment_verify_chain_root_summary_issuer_matches_proof_root_issuer() {
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
    assert_eq!(
        proof.chain_summary[0].issuer, proof.root_issuer,
        "root summary issuer should match proof root_issuer"
    );
}

#[test]
fn enrichment_verify_chain_leaf_summary_delegate_matches_proof_leaf_delegate() {
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
    let last_summary = proof.chain_summary.last().unwrap();
    assert_eq!(
        last_summary.delegate, proof.leaf_delegate,
        "last summary delegate should match proof leaf_delegate"
    );
}

#[test]
fn enrichment_verify_chain_capability_attenuation_monotonic() {
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
    // Capability counts should be monotonically non-increasing
    for i in 1..proof.chain_summary.len() {
        assert!(
            proof.chain_summary[i].capability_count <= proof.chain_summary[i - 1].capability_count,
            "capability count should be non-increasing along the chain"
        );
    }
}

// ===========================================================================
// 12. Error paths — boundary conditions
// ===========================================================================

#[test]
fn enrichment_empty_chain_error_is_deterministic() {
    let empty = DelegationChain::new(Vec::new());
    let ctx = make_ctx(&make_sk(1));
    let leaf = make_principal(99);
    for _ in 0..5 {
        let err = verify_chain(
            &empty,
            RuntimeCapability::VmDispatch,
            &leaf,
            &ctx,
            &NoRevocationOracle,
        )
        .unwrap_err();
        assert_eq!(err, ChainError::EmptyChain);
    }
}

#[test]
fn enrichment_depth_exceeded_boundary() {
    // Exactly at max_chain_depth should succeed
    let root_sk = make_sk(1);
    let leaf_delegate = make_principal(99);
    let link = make_bound_token(
        &root_sk,
        leaf_delegate.clone(),
        &[RuntimeCapability::VmDispatch],
    );
    let chain = DelegationChain::new(vec![link]);
    let mut ctx = make_ctx(&root_sk);
    ctx.max_chain_depth = 1; // exact match
    assert!(
        verify_chain(
            &chain,
            RuntimeCapability::VmDispatch,
            &leaf_delegate,
            &ctx,
            &NoRevocationOracle,
        )
        .is_ok()
    );

    // One over should fail
    ctx.max_chain_depth = 0;
    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap_err();
    assert!(matches!(err, ChainError::DepthExceeded { .. }));
}

#[test]
fn enrichment_revocation_oracle_custom_all_revoked() {
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
    .unwrap_err();
    // Should fail at the first link (index 0)
    match err {
        ChainError::RevokedLink { index, .. } => assert_eq!(index, 0),
        other => panic!("expected RevokedLink at 0, got {other:?}"),
    }
}

// ===========================================================================
// 13. DelegationChain.verify method
// ===========================================================================

#[test]
fn enrichment_chain_verify_method_returns_same_as_free_function() {
    let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
    let ctx = make_ctx(&root_sk);

    let proof_method = chain
        .verify(
            RuntimeCapability::VmDispatch,
            &leaf_delegate,
            &ctx,
            &NoRevocationOracle,
        )
        .unwrap();
    let proof_free = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .unwrap();

    assert_eq!(proof_method.chain_hash, proof_free.chain_hash);
    assert_eq!(
        proof_method.authorized_capability,
        proof_free.authorized_capability
    );
    assert_eq!(proof_method.root_issuer, proof_free.root_issuer);
    assert_eq!(proof_method.leaf_delegate, proof_free.leaf_delegate);
    assert_eq!(proof_method.chain_summary, proof_free.chain_summary);
}

// ===========================================================================
// 14. Chain hash properties
// ===========================================================================

#[test]
fn enrichment_chain_hash_depends_on_leaf_delegate() {
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
    assert_ne!(
        proof_a.chain_hash, proof_b.chain_hash,
        "different delegates should produce different hashes"
    );
}
