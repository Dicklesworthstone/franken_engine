//! Delegated capability attenuation-chain verification.
//!
//! This module enforces explicit, non-ambient authority delegation:
//! - every link is a signed capability token
//! - every link is verified against audience/temporal/checkpoint/revocation
//!   freshness bindings
//! - every child link must attenuate (subset) parent capabilities
//! - root issuer must be an authorized root authority
//! - chain depth is bounded
//! - any revoked link invalidates the chain tail
//!
//! Plan references: Section 10.10 item 10, 9E.4.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::capability::RuntimeCapability;
use crate::capability_token::{
    CapabilityToken, PrincipalId, TokenError, TokenId,
    VerificationContext as TokenVerificationContext, verify_token,
};
use crate::hash_tiers::ContentHash;
use crate::signature_preimage::VerificationKey;

/// Default maximum delegation-chain depth.
pub const DEFAULT_MAX_CHAIN_DEPTH: usize = 8;

/// Ordered delegation chain from root grant to leaf token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationChain {
    pub links: Vec<CapabilityToken>,
}

impl DelegationChain {
    pub fn new(links: Vec<CapabilityToken>) -> Self {
        Self { links }
    }

    pub fn len(&self) -> usize {
        self.links.len()
    }

    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }

    pub fn verify<R: RevocationOracle>(
        &self,
        required_capability: RuntimeCapability,
        leaf_delegate: &PrincipalId,
        context: &DelegationVerificationContext,
        revocation_oracle: &R,
    ) -> Result<AuthorizationProof, ChainError> {
        verify_chain(
            self,
            required_capability,
            leaf_delegate,
            context,
            revocation_oracle,
        )
    }
}

/// Context for delegation-chain verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationVerificationContext {
    pub current_tick: u64,
    pub verifier_checkpoint_seq: u64,
    pub verifier_revocation_seq: u64,
    pub max_chain_depth: usize,
    pub authorized_roots: BTreeSet<VerificationKey>,
    pub required_zone: Option<String>,
}

impl Default for DelegationVerificationContext {
    fn default() -> Self {
        Self {
            current_tick: 0,
            verifier_checkpoint_seq: 0,
            verifier_revocation_seq: 0,
            max_chain_depth: DEFAULT_MAX_CHAIN_DEPTH,
            authorized_roots: BTreeSet::new(),
            required_zone: None,
        }
    }
}

impl DelegationVerificationContext {
    pub fn with_authorized_root(root: VerificationKey) -> Self {
        let mut roots = BTreeSet::new();
        roots.insert(root);
        Self {
            authorized_roots: roots,
            ..Self::default()
        }
    }

    fn as_token_context(&self) -> TokenVerificationContext {
        TokenVerificationContext {
            current_tick: self.current_tick,
            verifier_checkpoint_seq: self.verifier_checkpoint_seq,
            verifier_revocation_seq: self.verifier_revocation_seq,
        }
    }
}

/// Chain verification error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainError {
    /// No chain means no authority: explicit no-ambient-authority invariant.
    EmptyChain,
    /// Chain exceeds configured depth limit.
    DepthExceeded {
        max_depth: usize,
        actual_depth: usize,
    },
    /// Root grant is not signed by an authorized root.
    UnauthorizedRoot { root_issuer: VerificationKey },
    /// Token missing mandatory checkpoint binding.
    MissingCheckpointBinding { index: usize },
    /// Token missing mandatory revocation-freshness binding.
    MissingRevocationFreshnessBinding { index: usize },
    /// Token-level verification failure.
    TokenVerificationFailed { index: usize, error: TokenError },
    /// Chain amplification detected.
    AttenuationViolation {
        index: usize,
        parent_capability_count: usize,
        child_capability_count: usize,
        amplified_capabilities: BTreeSet<RuntimeCapability>,
    },
    /// Zone mismatch across links or against required zone.
    ZoneMismatch {
        index: usize,
        expected_zone: String,
        actual_zone: String,
    },
    /// Revoked link invalidates the chain tail.
    RevokedLink { index: usize, token_id: TokenId },
    /// Required capability is not present on the leaf grant.
    MissingCapabilityAtLeaf {
        required: RuntimeCapability,
        leaf_capabilities: BTreeSet<RuntimeCapability>,
    },
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyChain => write!(f, "delegation chain is empty (no ambient authority)"),
            Self::DepthExceeded {
                max_depth,
                actual_depth,
            } => write!(
                f,
                "delegation chain depth exceeded: max={max_depth}, actual={actual_depth}"
            ),
            Self::UnauthorizedRoot { root_issuer } => {
                write!(f, "unauthorized root issuer: {root_issuer}")
            }
            Self::MissingCheckpointBinding { index } => {
                write!(f, "delegation link {index} missing checkpoint binding")
            }
            Self::MissingRevocationFreshnessBinding { index } => write!(
                f,
                "delegation link {index} missing revocation freshness binding"
            ),
            Self::TokenVerificationFailed { index, error } => {
                write!(f, "delegation link {index} verification failed: {error}")
            }
            Self::AttenuationViolation {
                index,
                parent_capability_count,
                child_capability_count,
                amplified_capabilities,
            } => write!(
                f,
                "delegation attenuation violation at link {index}: parent caps={}, \
                 child caps={}, amplified={:?}",
                parent_capability_count, child_capability_count, amplified_capabilities
            ),
            Self::ZoneMismatch {
                index,
                expected_zone,
                actual_zone,
            } => write!(
                f,
                "delegation link {index} zone mismatch: expected `{expected_zone}`, got `{actual_zone}`"
            ),
            Self::RevokedLink { index, token_id } => write!(
                f,
                "delegation link {index} revoked: token_id={}",
                token_id.to_hex()
            ),
            Self::MissingCapabilityAtLeaf {
                required,
                leaf_capabilities,
            } => write!(
                f,
                "leaf token missing required capability `{required}` (leaf caps={leaf_capabilities:?})"
            ),
        }
    }
}

impl std::error::Error for ChainError {}

/// Lightweight revocation lookup for delegation links.
pub trait RevocationOracle {
    fn is_revoked(&self, token_id: &TokenId) -> bool;
}

/// Default oracle that treats all links as not revoked.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRevocationOracle;

impl RevocationOracle for NoRevocationOracle {
    fn is_revoked(&self, _token_id: &TokenId) -> bool {
        false
    }
}

/// One verified delegation link summary in authorization proof material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationLinkSummary {
    pub index: usize,
    pub token_id: TokenId,
    pub issuer: PrincipalId,
    pub delegate: PrincipalId,
    pub capability_count: usize,
    pub zone: String,
    pub not_before_tick: u64,
    pub expiry_tick: u64,
}

/// Verifiable proof returned after successful chain verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationProof {
    pub chain_hash: ContentHash,
    pub authorized_capability: RuntimeCapability,
    pub root_issuer: PrincipalId,
    pub leaf_delegate: PrincipalId,
    pub verified_at_tick: u64,
    pub chain_summary: Vec<DelegationLinkSummary>,
}

/// Deterministically derive principal identity from a verification key.
pub fn principal_id_from_verification_key(vk: &VerificationKey) -> PrincipalId {
    PrincipalId::from_verification_key(vk)
}

/// Verify a delegated capability chain for a specific action capability.
pub fn verify_chain<R: RevocationOracle>(
    chain: &DelegationChain,
    required_capability: RuntimeCapability,
    leaf_delegate: &PrincipalId,
    context: &DelegationVerificationContext,
    revocation_oracle: &R,
) -> Result<AuthorizationProof, ChainError> {
    if chain.is_empty() {
        return Err(ChainError::EmptyChain);
    }

    if chain.len() > context.max_chain_depth {
        return Err(ChainError::DepthExceeded {
            max_depth: context.max_chain_depth,
            actual_depth: chain.len(),
        });
    }

    let root_issuer = chain.links[0].issuer.clone();
    if !context.authorized_roots.contains(&root_issuer) {
        return Err(ChainError::UnauthorizedRoot { root_issuer });
    }

    let expected_zone = context
        .required_zone
        .as_deref()
        .unwrap_or(&chain.links[0].zone)
        .to_string();

    let mut summary = Vec::with_capacity(chain.len());
    let token_ctx = context.as_token_context();

    for (index, token) in chain.links.iter().enumerate() {
        if token.zone != expected_zone {
            return Err(ChainError::ZoneMismatch {
                index,
                expected_zone: expected_zone.clone(),
                actual_zone: token.zone.clone(),
            });
        }

        if token.checkpoint_binding.is_none() {
            return Err(ChainError::MissingCheckpointBinding { index });
        }
        if token.revocation_freshness.is_none() {
            return Err(ChainError::MissingRevocationFreshnessBinding { index });
        }
        if revocation_oracle.is_revoked(&token.jti) {
            return Err(ChainError::RevokedLink {
                index,
                token_id: token.jti.clone(),
            });
        }

        let delegate = if index + 1 < chain.len() {
            principal_id_from_verification_key(&chain.links[index + 1].issuer)
        } else {
            leaf_delegate.clone()
        };

        verify_token(token, &delegate, &token_ctx)
            .map_err(|error| ChainError::TokenVerificationFailed { index, error })?;

        if index + 1 < chain.len() {
            let child = &chain.links[index + 1];
            if !child.capabilities.is_subset(&token.capabilities) {
                let amplified = child
                    .capabilities
                    .difference(&token.capabilities)
                    .copied()
                    .collect::<BTreeSet<_>>();
                return Err(ChainError::AttenuationViolation {
                    index: index + 1,
                    parent_capability_count: token.capabilities.len(),
                    child_capability_count: child.capabilities.len(),
                    amplified_capabilities: amplified,
                });
            }
        }

        summary.push(DelegationLinkSummary {
            index,
            token_id: token.jti.clone(),
            issuer: principal_id_from_verification_key(&token.issuer),
            delegate,
            capability_count: token.capabilities.len(),
            zone: token.zone.clone(),
            not_before_tick: token.nbf.0,
            expiry_tick: token.expiry.0,
        });
    }

    let leaf = chain
        .links
        .last()
        .expect("non-empty delegation chain must have leaf");
    if !leaf.capabilities.contains(&required_capability) {
        return Err(ChainError::MissingCapabilityAtLeaf {
            required: required_capability,
            leaf_capabilities: leaf.capabilities.clone(),
        });
    }

    Ok(AuthorizationProof {
        chain_hash: chain_hash(&chain.links, leaf_delegate),
        authorized_capability: required_capability,
        root_issuer: principal_id_from_verification_key(&chain.links[0].issuer),
        leaf_delegate: leaf_delegate.clone(),
        verified_at_tick: context.current_tick,
        chain_summary: summary,
    })
}

fn chain_hash(links: &[CapabilityToken], leaf_delegate: &PrincipalId) -> ContentHash {
    let mut material = Vec::new();
    for token in links {
        material.extend_from_slice(token.jti.as_bytes());
        material.extend_from_slice(token.issuer.as_bytes());
        material.extend_from_slice(token.zone.as_bytes());
        material.push(0xff);
        for cap in &token.capabilities {
            material.extend_from_slice(cap.to_string().as_bytes());
            material.push(0x1f);
        }
    }
    material.extend_from_slice(leaf_delegate.as_bytes());
    ContentHash::compute(&material)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::capability_token::{CheckpointRef, RevocationFreshnessRef, TokenBuilder};
    use crate::engine_object_id::EngineObjectId;
    use crate::policy_checkpoint::DeterministicTimestamp;
    use crate::security_epoch::SecurityEpoch;
    use crate::signature_preimage::{Signature, SigningKey};

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
    fn rejects_invalid_middle_signature() {
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
    fn revoked_middle_link_invalidates_chain() {
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
    fn root_must_be_authorized() {
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
    fn proof_contains_complete_chain_summary() {
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
        assert_eq!(
            proof.chain_summary[0].delegate,
            principal_id_from_verification_key(&chain.links[1].issuer)
        );
        assert_eq!(proof.chain_summary[2].delegate, leaf_delegate);
    }

    #[test]
    fn no_ambient_authority_empty_chain_is_rejected() {
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
    fn missing_checkpoint_binding_is_rejected() {
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

    // -- Missing revocation freshness binding --

    #[test]
    fn missing_revocation_freshness_binding_is_rejected() {
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

    // -- Zone mismatch --

    #[test]
    fn zone_mismatch_is_rejected() {
        let root_sk = make_sk(1);
        let issuer_sk = make_sk(2);
        let leaf_delegate = make_principal(99);

        let link0 = make_bound_token(
            &root_sk,
            principal_id_from_verification_key(&issuer_sk.verification_key()),
            &[RuntimeCapability::VmDispatch],
        );

        // Build link1 in a different zone.
        let builder = crate::capability_token::TokenBuilder::new(
            issuer_sk.clone(),
            DeterministicTimestamp(100),
            DeterministicTimestamp(1_000),
            SecurityEpoch::GENESIS,
            "zone-evil",
        )
        .add_audience(leaf_delegate.clone())
        .bind_checkpoint(crate::capability_token::CheckpointRef {
            min_checkpoint_seq: 5,
            checkpoint_id: EngineObjectId([7; 32]),
        })
        .bind_revocation_freshness(crate::capability_token::RevocationFreshnessRef {
            min_revocation_seq: 3,
            revocation_head_hash: ContentHash::compute(b"rev-head"),
        })
        .add_capability(RuntimeCapability::VmDispatch);
        let link1 = builder.build().expect("token should build");

        let chain = DelegationChain::new(vec![link0, link1]);
        let ctx = make_ctx(&root_sk);

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
                assert_eq!(actual_zone, "zone-evil");
            }
            other => panic!("expected zone mismatch, got {other:?}"),
        }
    }

    // -- Missing capability at leaf --

    #[test]
    fn missing_capability_at_leaf_is_rejected() {
        let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
        let ctx = make_ctx(&root_sk);

        // Leaf only has VmDispatch, not NetworkEgress.
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

    // -- Single-link chain --

    #[test]
    fn single_link_chain_verifies() {
        let root_sk = make_sk(1);
        let leaf_delegate = make_principal(99);

        let link0 = make_bound_token(
            &root_sk,
            leaf_delegate.clone(),
            &[RuntimeCapability::VmDispatch],
        );
        let chain = DelegationChain::new(vec![link0]);
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
        assert_eq!(proof.chain_summary[0].index, 0);
        assert_eq!(proof.chain_summary[0].delegate, leaf_delegate);
    }

    // -- Revocation of first/last link --

    #[test]
    fn revoked_root_link_invalidates_chain() {
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
        .expect_err("revoked root should fail");

        match err {
            ChainError::RevokedLink { index, .. } => assert_eq!(index, 0),
            other => panic!("expected revoked link, got {other:?}"),
        }
    }

    #[test]
    fn revoked_leaf_link_invalidates_chain() {
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
        .expect_err("revoked leaf should fail");

        match err {
            ChainError::RevokedLink { index, .. } => assert_eq!(index, 2),
            other => panic!("expected revoked link, got {other:?}"),
        }
    }

    // -- DelegationChain basic methods --

    #[test]
    fn delegation_chain_len_and_is_empty() {
        let empty = DelegationChain::new(Vec::new());
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let (chain, _, _) = valid_chain_fixture();
        assert!(!chain.is_empty());
        assert_eq!(chain.len(), 3);
    }

    // -- DelegationVerificationContext defaults --

    #[test]
    fn delegation_context_default_values() {
        let ctx = DelegationVerificationContext::default();
        assert_eq!(ctx.current_tick, 0);
        assert_eq!(ctx.verifier_checkpoint_seq, 0);
        assert_eq!(ctx.verifier_revocation_seq, 0);
        assert_eq!(ctx.max_chain_depth, DEFAULT_MAX_CHAIN_DEPTH);
        assert!(ctx.authorized_roots.is_empty());
        assert!(ctx.required_zone.is_none());
    }

    #[test]
    fn delegation_context_with_authorized_root() {
        let sk = make_sk(1);
        let ctx = DelegationVerificationContext::with_authorized_root(sk.verification_key());
        assert_eq!(ctx.authorized_roots.len(), 1);
        assert!(ctx.authorized_roots.contains(&sk.verification_key()));
        assert_eq!(ctx.max_chain_depth, DEFAULT_MAX_CHAIN_DEPTH);
    }

    // -- NoRevocationOracle --

    #[test]
    fn no_revocation_oracle_never_revokes() {
        let oracle = NoRevocationOracle;
        let token_id = EngineObjectId([0xAA; 32]);
        assert!(!oracle.is_revoked(&token_id));
    }

    // -- chain_hash determinism --

    #[test]
    fn chain_hash_is_deterministic() {
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
    fn chain_hash_changes_with_different_delegate() {
        let root_sk = make_sk(1);
        let leaf_a = make_principal(99);
        let leaf_b = make_principal(88);

        let link0_a = make_bound_token(&root_sk, leaf_a.clone(), &[RuntimeCapability::VmDispatch]);
        let link0_b = make_bound_token(&root_sk, leaf_b.clone(), &[RuntimeCapability::VmDispatch]);

        let ctx = make_ctx(&root_sk);
        let proof_a = verify_chain(
            &DelegationChain::new(vec![link0_a]),
            RuntimeCapability::VmDispatch,
            &leaf_a,
            &ctx,
            &NoRevocationOracle,
        )
        .unwrap();
        let proof_b = verify_chain(
            &DelegationChain::new(vec![link0_b]),
            RuntimeCapability::VmDispatch,
            &leaf_b,
            &ctx,
            &NoRevocationOracle,
        )
        .unwrap();

        assert_ne!(proof_a.chain_hash, proof_b.chain_hash);
    }

    // -- AuthorizationProof fields --

    #[test]
    fn proof_verified_at_tick_matches_context() {
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

        assert_eq!(proof.verified_at_tick, 500);
        assert_eq!(proof.authorized_capability, RuntimeCapability::VmDispatch);
        assert_eq!(
            proof.root_issuer,
            principal_id_from_verification_key(&root_sk.verification_key())
        );
    }

    // -- DelegationChain::verify convenience method --

    #[test]
    fn delegation_chain_verify_method() {
        let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
        let ctx = make_ctx(&root_sk);

        let proof = chain
            .verify(
                RuntimeCapability::VmDispatch,
                &leaf_delegate,
                &ctx,
                &NoRevocationOracle,
            )
            .expect("verify method should delegate correctly");

        assert_eq!(proof.chain_summary.len(), 3);
    }

    // -- principal_id_from_verification_key --

    #[test]
    fn principal_id_from_vk_is_deterministic() {
        let sk = make_sk(42);
        let p1 = principal_id_from_verification_key(&sk.verification_key());
        let p2 = principal_id_from_verification_key(&sk.verification_key());
        assert_eq!(p1, p2);
    }

    #[test]
    fn principal_id_differs_for_different_keys() {
        let p1 = principal_id_from_verification_key(&make_sk(1).verification_key());
        let p2 = principal_id_from_verification_key(&make_sk(2).verification_key());
        assert_ne!(p1, p2);
    }

    // -- ChainError Display --

    #[test]
    fn chain_error_display_empty_chain() {
        let err = ChainError::EmptyChain;
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn chain_error_display_depth_exceeded() {
        let err = ChainError::DepthExceeded {
            max_depth: 5,
            actual_depth: 10,
        };
        let s = err.to_string();
        assert!(s.contains("5"));
        assert!(s.contains("10"));
    }

    #[test]
    fn chain_error_display_unauthorized_root() {
        let err = ChainError::UnauthorizedRoot {
            root_issuer: make_sk(1).verification_key(),
        };
        assert!(err.to_string().contains("unauthorized root"));
    }

    #[test]
    fn chain_error_display_missing_checkpoint() {
        let err = ChainError::MissingCheckpointBinding { index: 3 };
        let s = err.to_string();
        assert!(s.contains("3"));
        assert!(s.contains("checkpoint"));
    }

    #[test]
    fn chain_error_display_missing_revocation_freshness() {
        let err = ChainError::MissingRevocationFreshnessBinding { index: 2 };
        let s = err.to_string();
        assert!(s.contains("2"));
        assert!(s.contains("revocation freshness"));
    }

    #[test]
    fn chain_error_display_token_verification_failed() {
        let err = ChainError::TokenVerificationFailed {
            index: 1,
            error: TokenError::SignatureInvalid {
                detail: "bad sig".to_string(),
            },
        };
        let s = err.to_string();
        assert!(s.contains("1"));
        assert!(s.contains("bad sig"));
    }

    #[test]
    fn chain_error_display_attenuation_violation() {
        let mut amplified = BTreeSet::new();
        amplified.insert(RuntimeCapability::FsWrite);
        let err = ChainError::AttenuationViolation {
            index: 2,
            parent_capability_count: 1,
            child_capability_count: 2,
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
        assert!(s.contains("zone-a"));
        assert!(s.contains("zone-b"));
    }

    #[test]
    fn chain_error_display_revoked_link() {
        let err = ChainError::RevokedLink {
            index: 0,
            token_id: EngineObjectId([0xAA; 32]),
        };
        let s = err.to_string();
        assert!(s.contains("revoked"));
        assert!(s.contains("0"));
    }

    #[test]
    fn chain_error_display_missing_capability_at_leaf() {
        let mut caps = BTreeSet::new();
        caps.insert(RuntimeCapability::VmDispatch);
        let err = ChainError::MissingCapabilityAtLeaf {
            required: RuntimeCapability::NetworkEgress,
            leaf_capabilities: caps,
        };
        let s = err.to_string();
        assert!(s.contains("network_egress"));
    }

    // -- Serde roundtrips --

    #[test]
    fn chain_error_serde_roundtrip() {
        let errors = vec![
            ChainError::EmptyChain,
            ChainError::DepthExceeded {
                max_depth: 8,
                actual_depth: 12,
            },
            ChainError::UnauthorizedRoot {
                root_issuer: make_sk(1).verification_key(),
            },
            ChainError::MissingCheckpointBinding { index: 0 },
            ChainError::MissingRevocationFreshnessBinding { index: 1 },
            ChainError::TokenVerificationFailed {
                index: 2,
                error: TokenError::EmptyCapabilities,
            },
            ChainError::AttenuationViolation {
                index: 1,
                parent_capability_count: 2,
                child_capability_count: 3,
                amplified_capabilities: {
                    let mut s = BTreeSet::new();
                    s.insert(RuntimeCapability::FsWrite);
                    s
                },
            },
            ChainError::ZoneMismatch {
                index: 0,
                expected_zone: "a".to_string(),
                actual_zone: "b".to_string(),
            },
            ChainError::RevokedLink {
                index: 1,
                token_id: EngineObjectId([1; 32]),
            },
            ChainError::MissingCapabilityAtLeaf {
                required: RuntimeCapability::VmDispatch,
                leaf_capabilities: BTreeSet::new(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap_or_default();
            let restored: ChainError = serde_json::from_str(&json).unwrap_or_default();
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn delegation_chain_serde_roundtrip() {
        let (chain, _, _) = valid_chain_fixture();
        let json = serde_json::to_string(&chain).unwrap_or_default();
        let restored: DelegationChain = serde_json::from_str(&json).unwrap_or_default();
        assert_eq!(chain, restored);
    }

    #[test]
    fn authorization_proof_serde_roundtrip() {
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

        let json = serde_json::to_string(&proof).unwrap_or_default();
        let restored: AuthorizationProof = serde_json::from_str(&json).unwrap_or_default();
        assert_eq!(proof, restored);
    }

    #[test]
    fn delegation_link_summary_serde_roundtrip() {
        let summary = DelegationLinkSummary {
            index: 0,
            token_id: EngineObjectId([1; 32]),
            issuer: make_principal(1),
            delegate: make_principal(2),
            capability_count: 3,
            zone: "zone-a".to_string(),
            not_before_tick: 100,
            expiry_tick: 1000,
        };
        let json = serde_json::to_string(&summary).unwrap_or_default();
        let restored: DelegationLinkSummary = serde_json::from_str(&json).unwrap_or_default();
        assert_eq!(summary, restored);
    }

    #[test]
    fn delegation_context_serde_roundtrip() {
        let ctx = DelegationVerificationContext {
            current_tick: 500,
            verifier_checkpoint_seq: 10,
            verifier_revocation_seq: 5,
            max_chain_depth: 4,
            authorized_roots: {
                let mut s = BTreeSet::new();
                s.insert(make_sk(1).verification_key());
                s
            },
            required_zone: Some("zone-a".to_string()),
        };
        let json = serde_json::to_string(&ctx).unwrap_or_default();
        let restored: DelegationVerificationContext =
            serde_json::from_str(&json).unwrap_or_default();
        assert_eq!(ctx, restored);
    }

    // -- DEFAULT_MAX_CHAIN_DEPTH constant --

    #[test]
    fn default_max_chain_depth_constant() {
        assert_eq!(DEFAULT_MAX_CHAIN_DEPTH, 8);
    }

    // -- Zone inferred from root when required_zone is None --

    #[test]
    fn zone_inferred_from_root_link_when_required_zone_is_none() {
        let root_sk = make_sk(1);
        let leaf_delegate = make_principal(99);

        let link0 = make_bound_token(
            &root_sk,
            leaf_delegate.clone(),
            &[RuntimeCapability::VmDispatch],
        );
        let chain = DelegationChain::new(vec![link0]);

        let mut ctx = make_ctx(&root_sk);
        ctx.required_zone = None; // Zone inferred from root link.

        let proof = verify_chain(
            &chain,
            RuntimeCapability::VmDispatch,
            &leaf_delegate,
            &ctx,
            &NoRevocationOracle,
        )
        .expect("should verify when zone inferred from root");

        assert_eq!(proof.chain_summary.len(), 1);
    }

    // -- Chain summary link fields --

    #[test]
    fn chain_summary_includes_temporal_and_zone_info() {
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

        for (i, link_summary) in proof.chain_summary.iter().enumerate() {
            assert_eq!(link_summary.index, i);
            assert_eq!(link_summary.zone, "zone-a");
            assert_eq!(link_summary.not_before_tick, 100);
            assert_eq!(link_summary.expiry_tick, 1_000);
            assert!(link_summary.capability_count > 0);
            assert_eq!(link_summary.token_id, chain.links[i].jti);
        }
    }

    // -- Max depth boundary --

    // -- Enrichment: std::error --

    #[test]
    fn chain_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(ChainError::EmptyChain),
            Box::new(ChainError::DepthExceeded {
                max_depth: 5,
                actual_depth: 8,
            }),
            Box::new(ChainError::MissingCheckpointBinding { index: 2 }),
            Box::new(ChainError::MissingRevocationFreshnessBinding { index: 1 }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            4,
            "all 4 variants produce distinct messages"
        );
    }

    #[test]
    fn chain_at_exact_max_depth_passes() {
        let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
        let mut ctx = make_ctx(&root_sk);
        ctx.max_chain_depth = 3; // chain has exactly 3 links

        let proof = verify_chain(
            &chain,
            RuntimeCapability::VmDispatch,
            &leaf_delegate,
            &ctx,
            &NoRevocationOracle,
        )
        .expect("chain at exact max depth should pass");

        assert_eq!(proof.chain_summary.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Enrichment: Display uniqueness for ChainError via BTreeSet
    // -----------------------------------------------------------------------

    #[test]
    fn chain_error_display_all_variants_unique() {
        let mut amplified = BTreeSet::new();
        amplified.insert(RuntimeCapability::FsWrite);
        let variants: Vec<ChainError> = vec![
            ChainError::EmptyChain,
            ChainError::DepthExceeded {
                max_depth: 5,
                actual_depth: 10,
            },
            ChainError::UnauthorizedRoot {
                root_issuer: make_sk(1).verification_key(),
            },
            ChainError::MissingCheckpointBinding { index: 0 },
            ChainError::MissingRevocationFreshnessBinding { index: 1 },
            ChainError::TokenVerificationFailed {
                index: 2,
                error: TokenError::EmptyCapabilities,
            },
            ChainError::AttenuationViolation {
                index: 1,
                parent_capability_count: 1,
                child_capability_count: 2,
                amplified_capabilities: amplified,
            },
            ChainError::ZoneMismatch {
                index: 0,
                expected_zone: "a".to_string(),
                actual_zone: "b".to_string(),
            },
            ChainError::RevokedLink {
                index: 0,
                token_id: EngineObjectId([0xBB; 32]),
            },
            ChainError::MissingCapabilityAtLeaf {
                required: RuntimeCapability::NetworkEgress,
                leaf_capabilities: BTreeSet::new(),
            },
        ];
        let mut displays = BTreeSet::new();
        for v in &variants {
            displays.insert(v.to_string());
        }
        assert_eq!(
            displays.len(),
            variants.len(),
            "all ChainError variants produce distinct Display"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: DelegationChain serde empty
    // -----------------------------------------------------------------------

    #[test]
    fn delegation_chain_empty_serde_roundtrip() {
        let empty = DelegationChain::new(Vec::new());
        let json = serde_json::to_string(&empty).unwrap_or_default();
        let restored: DelegationChain = serde_json::from_str(&json).unwrap_or_default();
        assert_eq!(empty, restored);
        assert!(restored.is_empty());
    }

    // -----------------------------------------------------------------------
    // Enrichment: chain_hash differs for different capabilities
    // -----------------------------------------------------------------------

    #[test]
    fn chain_hash_differs_for_different_capabilities() {
        let root_sk = make_sk(1);
        let leaf_a = make_principal(99);
        let ctx = make_ctx(&root_sk);

        let link_vm = make_bound_token(&root_sk, leaf_a.clone(), &[RuntimeCapability::VmDispatch]);
        let link_both = make_bound_token(
            &root_sk,
            leaf_a.clone(),
            &[
                RuntimeCapability::VmDispatch,
                RuntimeCapability::NetworkEgress,
            ],
        );

        let proof_vm = verify_chain(
            &DelegationChain::new(vec![link_vm]),
            RuntimeCapability::VmDispatch,
            &leaf_a,
            &ctx,
            &NoRevocationOracle,
        )
        .unwrap();
        let proof_both = verify_chain(
            &DelegationChain::new(vec![link_both]),
            RuntimeCapability::VmDispatch,
            &leaf_a,
            &ctx,
            &NoRevocationOracle,
        )
        .unwrap();

        assert_ne!(proof_vm.chain_hash, proof_both.chain_hash);
    }

    // -----------------------------------------------------------------------
    // Enrichment: SetRevocationOracle — non-revoked tokens pass
    // -----------------------------------------------------------------------

    #[test]
    fn set_revocation_oracle_non_revoked_passes() {
        let mut revoked = BTreeSet::new();
        revoked.insert(EngineObjectId([0xAA; 32]));
        let oracle = SetRevocationOracle { revoked };
        assert!(!oracle.is_revoked(&EngineObjectId([0xBB; 32])));
        assert!(oracle.is_revoked(&EngineObjectId([0xAA; 32])));
    }

    // -----------------------------------------------------------------------
    // Enrichment: DelegationVerificationContext serde with multiple roots
    // -----------------------------------------------------------------------

    #[test]
    fn delegation_context_serde_with_multiple_roots() {
        let mut roots = BTreeSet::new();
        roots.insert(make_sk(1).verification_key());
        roots.insert(make_sk(2).verification_key());
        roots.insert(make_sk(3).verification_key());
        let ctx = DelegationVerificationContext {
            current_tick: 1000,
            verifier_checkpoint_seq: 50,
            verifier_revocation_seq: 25,
            max_chain_depth: 4,
            authorized_roots: roots,
            required_zone: None,
        };
        let json = serde_json::to_string(&ctx).unwrap_or_default();
        let restored: DelegationVerificationContext =
            serde_json::from_str(&json).unwrap_or_default();
        assert_eq!(ctx, restored);
        assert_eq!(restored.authorized_roots.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Enrichment: proof root_issuer matches first link
    // -----------------------------------------------------------------------

    #[test]
    fn proof_root_issuer_matches_root_link() {
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
        .unwrap();

        assert_eq!(
            proof.root_issuer,
            principal_id_from_verification_key(&root_sk.verification_key())
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: DelegationLinkSummary Display-like fields
    // -----------------------------------------------------------------------

    #[test]
    fn delegation_link_summary_fields_are_correct() {
        let summary = DelegationLinkSummary {
            index: 2,
            token_id: EngineObjectId([0x42; 32]),
            issuer: make_principal(10),
            delegate: make_principal(20),
            capability_count: 5,
            zone: "zone-prod".to_string(),
            not_before_tick: 500,
            expiry_tick: 5000,
        };
        assert_eq!(summary.index, 2);
        assert_eq!(summary.capability_count, 5);
        assert_eq!(summary.zone, "zone-prod");
        assert!(summary.not_before_tick < summary.expiry_tick);
    }

    // -- Enrichment: PearlTower 2026-02-27 --

    #[test]
    fn chain_hash_deterministic_same_inputs() {
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
    fn chain_hash_differs_for_different_leaf_delegate() {
        let root_sk = make_sk(1);
        let ctx = make_ctx(&root_sk);
        let leaf_a = make_principal(99);
        let leaf_b = make_principal(88);

        let link_a = make_bound_token(&root_sk, leaf_a.clone(), &[RuntimeCapability::VmDispatch]);
        let link_b = make_bound_token(&root_sk, leaf_b.clone(), &[RuntimeCapability::VmDispatch]);

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
    fn proof_verified_at_tick_reflects_context_tick() {
        let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
        let mut ctx = make_ctx(&root_sk);
        ctx.current_tick = 777;
        let proof = chain
            .verify(
                RuntimeCapability::VmDispatch,
                &leaf_delegate,
                &ctx,
                &NoRevocationOracle,
            )
            .unwrap();
        assert_eq!(proof.verified_at_tick, 777);
    }

    #[test]
    fn proof_chain_summary_length_matches_chain() {
        let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
        let ctx = make_ctx(&root_sk);
        let proof = chain
            .verify(
                RuntimeCapability::VmDispatch,
                &leaf_delegate,
                &ctx,
                &NoRevocationOracle,
            )
            .unwrap();
        assert_eq!(proof.chain_summary.len(), chain.len());
    }

    #[test]
    fn authorization_proof_three_link_serde_roundtrip() {
        let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
        let ctx = make_ctx(&root_sk);
        let proof = chain
            .verify(
                RuntimeCapability::VmDispatch,
                &leaf_delegate,
                &ctx,
                &NoRevocationOracle,
            )
            .unwrap();
        let json = serde_json::to_string(&proof).unwrap_or_default();
        let restored: AuthorizationProof = serde_json::from_str(&json).unwrap_or_default();
        assert_eq!(proof, restored);
    }

    #[test]
    fn principal_id_same_key_yields_same_id() {
        let sk = make_sk(42);
        let vk = sk.verification_key();
        let p1 = principal_id_from_verification_key(&vk);
        let p2 = principal_id_from_verification_key(&vk);
        assert_eq!(p1, p2);
    }

    #[test]
    fn principal_id_from_different_keys_differ() {
        let vk1 = make_sk(1).verification_key();
        let vk2 = make_sk(2).verification_key();
        let p1 = principal_id_from_verification_key(&vk1);
        let p2 = principal_id_from_verification_key(&vk2);
        assert_ne!(p1, p2);
    }

    #[test]
    fn chain_error_is_std_error() {
        let e: &dyn std::error::Error = &ChainError::EmptyChain;
        assert!(e.source().is_none());
    }

    #[test]
    fn revoking_first_link_fails_chain() {
        let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
        let ctx = make_ctx(&root_sk);
        let mut revoked = BTreeSet::new();
        revoked.insert(chain.links[0].jti.clone());
        let oracle = SetRevocationOracle { revoked };
        let err = chain
            .verify(RuntimeCapability::VmDispatch, &leaf_delegate, &ctx, &oracle)
            .unwrap_err();
        match err {
            ChainError::RevokedLink { index, .. } => assert_eq!(index, 0),
            other => panic!("expected RevokedLink, got {other}"),
        }
    }

    #[test]
    fn revoking_last_link_fails_chain() {
        let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
        let ctx = make_ctx(&root_sk);
        let mut revoked = BTreeSet::new();
        revoked.insert(chain.links[2].jti.clone());
        let oracle = SetRevocationOracle { revoked };
        let err = chain
            .verify(RuntimeCapability::VmDispatch, &leaf_delegate, &ctx, &oracle)
            .unwrap_err();
        match err {
            ChainError::RevokedLink { index, .. } => assert_eq!(index, 2),
            other => panic!("expected RevokedLink, got {other}"),
        }
    }

    #[test]
    fn depth_exceeded_reports_correct_values() {
        let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
        let mut ctx = make_ctx(&root_sk);
        ctx.max_chain_depth = 2; // chain has 3 links
        let err = chain
            .verify(
                RuntimeCapability::VmDispatch,
                &leaf_delegate,
                &ctx,
                &NoRevocationOracle,
            )
            .unwrap_err();
        match err {
            ChainError::DepthExceeded {
                max_depth,
                actual_depth,
            } => {
                assert_eq!(max_depth, 2);
                assert_eq!(actual_depth, 3);
            }
            other => panic!("expected DepthExceeded, got {other}"),
        }
    }

    #[test]
    fn chain_summary_indices_are_sequential() {
        let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
        let ctx = make_ctx(&root_sk);
        let proof = chain
            .verify(
                RuntimeCapability::VmDispatch,
                &leaf_delegate,
                &ctx,
                &NoRevocationOracle,
            )
            .unwrap();
        for (i, summary) in proof.chain_summary.iter().enumerate() {
            assert_eq!(summary.index, i);
        }
    }

    #[test]
    fn chain_summary_leaf_delegate_matches() {
        let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
        let ctx = make_ctx(&root_sk);
        let proof = chain
            .verify(
                RuntimeCapability::VmDispatch,
                &leaf_delegate,
                &ctx,
                &NoRevocationOracle,
            )
            .unwrap();
        let last = proof.chain_summary.last().unwrap();
        assert_eq!(last.delegate, leaf_delegate);
    }

    #[test]
    fn verify_method_delegates_to_verify_chain() {
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
        let proof_fn = verify_chain(
            &chain,
            RuntimeCapability::VmDispatch,
            &leaf_delegate,
            &ctx,
            &NoRevocationOracle,
        )
        .unwrap();
        assert_eq!(proof_method.chain_hash, proof_fn.chain_hash);
        assert_eq!(
            proof_method.authorized_capability,
            proof_fn.authorized_capability
        );
    }

    #[test]
    fn chain_error_serde_all_variants() {
        let mut amplified = BTreeSet::new();
        amplified.insert(RuntimeCapability::NetworkEgress);
        let variants = vec![
            ChainError::EmptyChain,
            ChainError::DepthExceeded {
                max_depth: 3,
                actual_depth: 5,
            },
            ChainError::UnauthorizedRoot {
                root_issuer: make_sk(1).verification_key(),
            },
            ChainError::MissingCheckpointBinding { index: 0 },
            ChainError::MissingRevocationFreshnessBinding { index: 1 },
            ChainError::TokenVerificationFailed {
                index: 2,
                error: TokenError::EmptyCapabilities,
            },
            ChainError::AttenuationViolation {
                index: 1,
                parent_capability_count: 1,
                child_capability_count: 2,
                amplified_capabilities: amplified,
            },
            ChainError::ZoneMismatch {
                index: 0,
                expected_zone: "a".into(),
                actual_zone: "b".into(),
            },
            ChainError::RevokedLink {
                index: 0,
                token_id: EngineObjectId([0xBB; 32]),
            },
            ChainError::MissingCapabilityAtLeaf {
                required: RuntimeCapability::NetworkEgress,
                leaf_capabilities: BTreeSet::new(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap_or_default();
            let restored: ChainError = serde_json::from_str(&json).unwrap_or_default();
            assert_eq!(*v, restored);
        }
    }

    #[test]
    fn chain_link_summary_zones_all_match() {
        let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
        let ctx = make_ctx(&root_sk);
        let proof = chain
            .verify(
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
    fn delegation_link_summary_alternate_serde() {
        let summary = DelegationLinkSummary {
            index: 0,
            token_id: EngineObjectId([0x42; 32]),
            issuer: make_principal(10),
            delegate: make_principal(20),
            capability_count: 3,
            zone: "z".into(),
            not_before_tick: 100,
            expiry_tick: 900,
        };
        let json = serde_json::to_string(&summary).unwrap_or_default();
        let restored: DelegationLinkSummary = serde_json::from_str(&json).unwrap_or_default();
        assert_eq!(summary, restored);
    }

    // -- Enrichment: clone equality --

    #[test]
    fn delegation_chain_clone_equality() {
        let (chain, _, _) = valid_chain_fixture();
        let cloned = chain.clone();
        assert_eq!(chain, cloned);
    }

    #[test]
    fn delegation_verification_context_clone_equality() {
        let root_sk = make_sk(1);
        let ctx = make_ctx(&root_sk);
        let cloned = ctx.clone();
        assert_eq!(ctx, cloned);
    }

    #[test]
    fn delegation_link_summary_clone_equality() {
        let summary = DelegationLinkSummary {
            index: 5,
            token_id: EngineObjectId([0xCC; 32]),
            issuer: make_principal(30),
            delegate: make_principal(40),
            capability_count: 7,
            zone: "zone-staging".to_string(),
            not_before_tick: 200,
            expiry_tick: 2000,
        };
        let cloned = summary.clone();
        assert_eq!(summary, cloned);
    }

    #[test]
    fn authorization_proof_clone_equality() {
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
        let cloned = proof.clone();
        assert_eq!(proof, cloned);
    }

    #[test]
    fn chain_error_clone_equality() {
        let err = ChainError::AttenuationViolation {
            index: 3,
            parent_capability_count: 2,
            child_capability_count: 4,
            amplified_capabilities: {
                let mut s = BTreeSet::new();
                s.insert(RuntimeCapability::FsRead);
                s.insert(RuntimeCapability::FsWrite);
                s
            },
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    // -- Enrichment: JSON field presence --

    #[test]
    fn delegation_link_summary_json_field_presence() {
        let summary = DelegationLinkSummary {
            index: 1,
            token_id: EngineObjectId([0x11; 32]),
            issuer: make_principal(5),
            delegate: make_principal(6),
            capability_count: 2,
            zone: "zone-x".to_string(),
            not_before_tick: 50,
            expiry_tick: 500,
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"index\""));
        assert!(json.contains("\"token_id\""));
        assert!(json.contains("\"capability_count\""));
        assert!(json.contains("\"zone\""));
        assert!(json.contains("\"not_before_tick\""));
        assert!(json.contains("\"expiry_tick\""));
    }

    #[test]
    fn authorization_proof_json_field_presence() {
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
        assert!(json.contains("\"chain_hash\""));
        assert!(json.contains("\"authorized_capability\""));
        assert!(json.contains("\"root_issuer\""));
        assert!(json.contains("\"leaf_delegate\""));
        assert!(json.contains("\"verified_at_tick\""));
        assert!(json.contains("\"chain_summary\""));
    }

    #[test]
    fn delegation_context_json_field_presence() {
        let root_sk = make_sk(1);
        let ctx = make_ctx(&root_sk);
        let json = serde_json::to_string(&ctx).unwrap();
        assert!(json.contains("\"current_tick\""));
        assert!(json.contains("\"verifier_checkpoint_seq\""));
        assert!(json.contains("\"verifier_revocation_seq\""));
        assert!(json.contains("\"max_chain_depth\""));
        assert!(json.contains("\"authorized_roots\""));
        assert!(json.contains("\"required_zone\""));
    }

    // -- Enrichment: error source --

    #[test]
    fn chain_error_source_is_none_for_all_variants() {
        let variants: Vec<ChainError> = vec![
            ChainError::EmptyChain,
            ChainError::DepthExceeded {
                max_depth: 4,
                actual_depth: 6,
            },
            ChainError::UnauthorizedRoot {
                root_issuer: make_sk(9).verification_key(),
            },
            ChainError::MissingCheckpointBinding { index: 0 },
            ChainError::MissingRevocationFreshnessBinding { index: 1 },
            ChainError::TokenVerificationFailed {
                index: 0,
                error: TokenError::EmptyCapabilities,
            },
            ChainError::AttenuationViolation {
                index: 1,
                parent_capability_count: 1,
                child_capability_count: 3,
                amplified_capabilities: BTreeSet::new(),
            },
            ChainError::ZoneMismatch {
                index: 0,
                expected_zone: "a".into(),
                actual_zone: "b".into(),
            },
            ChainError::RevokedLink {
                index: 0,
                token_id: EngineObjectId([0xFF; 32]),
            },
            ChainError::MissingCapabilityAtLeaf {
                required: RuntimeCapability::GcInvoke,
                leaf_capabilities: BTreeSet::new(),
            },
        ];
        for v in &variants {
            let e: &dyn std::error::Error = v;
            assert!(
                e.source().is_none(),
                "ChainError variant should have no source: {v}"
            );
        }
    }

    // -- Enrichment: boundary conditions --

    #[test]
    fn max_depth_zero_rejects_single_link() {
        let root_sk = make_sk(1);
        let leaf_delegate = make_principal(99);
        let link = make_bound_token(
            &root_sk,
            leaf_delegate.clone(),
            &[RuntimeCapability::VmDispatch],
        );
        let chain = DelegationChain::new(vec![link]);
        let mut ctx = make_ctx(&root_sk);
        ctx.max_chain_depth = 0;

        let err = verify_chain(
            &chain,
            RuntimeCapability::VmDispatch,
            &leaf_delegate,
            &ctx,
            &NoRevocationOracle,
        )
        .expect_err("max_depth=0 should reject any chain");

        assert_eq!(
            err,
            ChainError::DepthExceeded {
                max_depth: 0,
                actual_depth: 1,
            }
        );
    }

    #[test]
    fn max_depth_one_accepts_single_link() {
        let root_sk = make_sk(1);
        let leaf_delegate = make_principal(99);
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
        .expect("max_depth=1 should accept single-link chain");

        assert_eq!(proof.chain_summary.len(), 1);
    }

    // -- Enrichment: Display uniqueness for same variant with different indices --

    #[test]
    fn chain_error_display_differs_by_index() {
        let err_a = ChainError::MissingCheckpointBinding { index: 0 };
        let err_b = ChainError::MissingCheckpointBinding { index: 7 };
        assert_ne!(err_a.to_string(), err_b.to_string());

        let err_c = ChainError::MissingRevocationFreshnessBinding { index: 0 };
        let err_d = ChainError::MissingRevocationFreshnessBinding { index: 5 };
        assert_ne!(err_c.to_string(), err_d.to_string());
    }
}
