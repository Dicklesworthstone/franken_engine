use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::capability::RuntimeCapability;
use crate::capability_token::{
    verify_versioned_token, PrincipalId, VersionedCapabilityToken, VersionedTokenError,
    VersionedVerificationContext,
};
use crate::engine_object_id::PersistedEngineObjectId;
use crate::hash_tiers::ContentHash;
use crate::revocation_chain::RevocationChainV2;
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::VerificationKey;

use super::compat::DEFAULT_MAX_CHAIN_DEPTH;

/// Ordered delegation chain from root v2 grant to leaf v2 grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedDelegationChain {
    pub links: Vec<VersionedCapabilityToken>,
}

impl VersionedDelegationChain {
    pub fn new(links: Vec<VersionedCapabilityToken>) -> Self {
        Self { links }
    }

    pub fn len(&self) -> usize {
        self.links.len()
    }

    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }

    pub fn verify<R: VersionedRevocationOracle>(
        &self,
        required_capability: RuntimeCapability,
        leaf_delegate: &PrincipalId,
        context: &VersionedDelegationVerificationContext,
        revocation_oracle: &R,
    ) -> Result<VersionedAuthorizationProof, VersionedChainError> {
        verify_versioned_chain(
            self,
            required_capability,
            leaf_delegate,
            context,
            revocation_oracle,
        )
    }
}

/// Fully versioned context for delegated authority verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedDelegationVerificationContext {
    pub current_tick: u64,
    pub current_epoch: SecurityEpoch,
    pub verifier_checkpoint_seq: u64,
    pub verifier_revocation_seq: u64,
    #[serde(default)]
    pub accepted_checkpoint_ids: BTreeSet<PersistedEngineObjectId>,
    #[serde(default)]
    pub accepted_revocation_head_hashes: BTreeSet<ContentHash>,
    pub max_chain_depth: usize,
    pub authorized_roots: BTreeSet<VerificationKey>,
    pub required_zone: Option<String>,
}

impl Default for VersionedDelegationVerificationContext {
    fn default() -> Self {
        Self {
            current_tick: 0,
            current_epoch: SecurityEpoch::GENESIS,
            verifier_checkpoint_seq: 0,
            verifier_revocation_seq: 0,
            accepted_checkpoint_ids: BTreeSet::new(),
            accepted_revocation_head_hashes: BTreeSet::new(),
            max_chain_depth: DEFAULT_MAX_CHAIN_DEPTH,
            authorized_roots: BTreeSet::new(),
            required_zone: None,
        }
    }
}

impl VersionedDelegationVerificationContext {
    pub fn with_authorized_root(root: VerificationKey) -> Self {
        let mut roots = BTreeSet::new();
        roots.insert(root);
        Self {
            authorized_roots: roots,
            ..Self::default()
        }
    }

    pub fn with_checkpoint_id(mut self, checkpoint_id: PersistedEngineObjectId) -> Self {
        self.accepted_checkpoint_ids.insert(checkpoint_id);
        self
    }

    pub fn with_revocation_head_hash(mut self, revocation_head_hash: ContentHash) -> Self {
        self.accepted_revocation_head_hashes
            .insert(revocation_head_hash);
        self
    }

    pub fn with_current_epoch(mut self, epoch: SecurityEpoch) -> Self {
        self.current_epoch = epoch;
        self
    }

    pub fn with_required_zone(mut self, zone: impl Into<String>) -> Self {
        self.required_zone = Some(zone.into());
        self
    }

    fn as_token_context(&self) -> VersionedVerificationContext {
        let mut context = VersionedVerificationContext::new(
            self.current_tick,
            self.verifier_checkpoint_seq,
            self.verifier_revocation_seq,
        )
        .with_current_epoch(self.current_epoch);
        for checkpoint_id in &self.accepted_checkpoint_ids {
            context = context.with_checkpoint_id(checkpoint_id.clone());
        }
        for revocation_head_hash in &self.accepted_revocation_head_hashes {
            context = context.with_revocation_head_hash(*revocation_head_hash);
        }
        context
    }
}

/// Exact-ID revocation lookup for v2 delegation links.
pub trait VersionedRevocationOracle {
    fn is_revoked(&self, token_id: &PersistedEngineObjectId) -> bool;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NoVersionedRevocationOracle;

impl VersionedRevocationOracle for NoVersionedRevocationOracle {
    fn is_revoked(&self, _token_id: &PersistedEngineObjectId) -> bool {
        false
    }
}

impl VersionedRevocationOracle for RevocationChainV2 {
    fn is_revoked(&self, token_id: &PersistedEngineObjectId) -> bool {
        RevocationChainV2::is_revoked(self, token_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionedChainError {
    EmptyChain,
    DepthExceeded {
        max_depth: usize,
        actual_depth: usize,
    },
    UnauthorizedRoot {
        root_issuer: VerificationKey,
    },
    TokenIdentityFailed {
        index: usize,
        error: VersionedTokenError,
    },
    MissingCheckpointBinding {
        index: usize,
    },
    MissingRevocationFreshnessBinding {
        index: usize,
    },
    RevokedLink {
        index: usize,
        token_id: PersistedEngineObjectId,
    },
    TokenVerificationFailed {
        index: usize,
        error: VersionedTokenError,
    },
    AttenuationViolation {
        index: usize,
        parent_capability_count: usize,
        child_capability_count: usize,
        amplified_capabilities: BTreeSet<RuntimeCapability>,
    },
    ZoneMismatch {
        index: usize,
        expected_zone: String,
        actual_zone: String,
    },
    MissingCapabilityAtLeaf {
        required: RuntimeCapability,
        leaf_capabilities: BTreeSet<RuntimeCapability>,
    },
}

impl std::fmt::Display for VersionedChainError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyChain => formatter.write_str("delegation chain is empty (no ambient authority)"),
            Self::DepthExceeded {
                max_depth,
                actual_depth,
            } => write!(
                formatter,
                "delegation chain depth exceeded: max={max_depth}, actual={actual_depth}"
            ),
            Self::UnauthorizedRoot { root_issuer } => {
                write!(formatter, "unauthorized root issuer: {root_issuer}")
            }
            Self::TokenIdentityFailed { index, error } => {
                write!(formatter, "delegation link {index} identity failed: {error}")
            }
            Self::MissingCheckpointBinding { index } => {
                write!(formatter, "delegation link {index} missing checkpoint binding")
            }
            Self::MissingRevocationFreshnessBinding { index } => write!(
                formatter,
                "delegation link {index} missing revocation freshness binding"
            ),
            Self::RevokedLink { index, token_id } => write!(
                formatter,
                "delegation link {index} revoked: token_id={}:{}",
                token_id.derivation_version,
                token_id.to_hex()
            ),
            Self::TokenVerificationFailed { index, error } => {
                write!(formatter, "delegation link {index} verification failed: {error}")
            }
            Self::AttenuationViolation {
                index,
                parent_capability_count,
                child_capability_count,
                amplified_capabilities,
            } => write!(
                formatter,
                "delegation attenuation violation at link {index}: parent caps={parent_capability_count}, child caps={child_capability_count}, amplified={amplified_capabilities:?}"
            ),
            Self::ZoneMismatch {
                index,
                expected_zone,
                actual_zone,
            } => write!(
                formatter,
                "delegation link {index} zone mismatch: expected {expected_zone:?}, got {actual_zone:?}"
            ),
            Self::MissingCapabilityAtLeaf {
                required,
                leaf_capabilities,
            } => write!(
                formatter,
                "leaf token missing required capability {required:?} (leaf caps={leaf_capabilities:?})"
            ),
        }
    }
}

impl std::error::Error for VersionedChainError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedDelegationLinkSummary {
    pub index: usize,
    pub token_id: PersistedEngineObjectId,
    pub issuer: PrincipalId,
    pub delegate: PrincipalId,
    pub capability_count: usize,
    pub zone: String,
    pub not_before_tick: u64,
    pub expiry_tick: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedAuthorizationProof {
    pub chain_hash: ContentHash,
    pub authorized_capability: RuntimeCapability,
    pub root_issuer: PrincipalId,
    pub leaf_delegate: PrincipalId,
    pub verified_at_tick: u64,
    pub verified_epoch: SecurityEpoch,
    pub chain_summary: Vec<VersionedDelegationLinkSummary>,
}

pub fn verify_versioned_chain<R: VersionedRevocationOracle>(
    chain: &VersionedDelegationChain,
    required_capability: RuntimeCapability,
    leaf_delegate: &PrincipalId,
    context: &VersionedDelegationVerificationContext,
    revocation_oracle: &R,
) -> Result<VersionedAuthorizationProof, VersionedChainError> {
    if chain.is_empty() {
        return Err(VersionedChainError::EmptyChain);
    }
    if chain.len() > context.max_chain_depth {
        return Err(VersionedChainError::DepthExceeded {
            max_depth: context.max_chain_depth,
            actual_depth: chain.len(),
        });
    }

    let root_issuer = chain.links[0].issuer.clone();
    if !context.authorized_roots.contains(&root_issuer) {
        return Err(VersionedChainError::UnauthorizedRoot { root_issuer });
    }
    let expected_zone = context
        .required_zone
        .as_deref()
        .unwrap_or(&chain.links[0].zone)
        .to_string();
    let token_context = context.as_token_context();
    let mut summary = Vec::with_capacity(chain.len());

    for (index, token) in chain.links.iter().enumerate() {
        token
            .validate_identity()
            .map_err(|error| VersionedChainError::TokenIdentityFailed { index, error })?;
        if token.zone != expected_zone {
            return Err(VersionedChainError::ZoneMismatch {
                index,
                expected_zone: expected_zone.clone(),
                actual_zone: token.zone.clone(),
            });
        }
        if token.checkpoint_binding.is_none() {
            return Err(VersionedChainError::MissingCheckpointBinding { index });
        }
        if token.revocation_freshness.is_none() {
            return Err(VersionedChainError::MissingRevocationFreshnessBinding { index });
        }
        if revocation_oracle.is_revoked(&token.jti) {
            return Err(VersionedChainError::RevokedLink {
                index,
                token_id: token.jti.clone(),
            });
        }

        let delegate = if index + 1 < chain.len() {
            PrincipalId::from_verification_key(&chain.links[index + 1].issuer)
        } else {
            leaf_delegate.clone()
        };
        verify_versioned_token(token, &delegate, &token_context).map_err(|error| {
            VersionedChainError::TokenVerificationFailed { index, error }
        })?;

        if index + 1 < chain.len() {
            let child = &chain.links[index + 1];
            if !child.capabilities.is_subset(&token.capabilities) {
                let amplified_capabilities = child
                    .capabilities
                    .difference(&token.capabilities)
                    .copied()
                    .collect::<BTreeSet<_>>();
                return Err(VersionedChainError::AttenuationViolation {
                    index: index + 1,
                    parent_capability_count: token.capabilities.len(),
                    child_capability_count: child.capabilities.len(),
                    amplified_capabilities,
                });
            }
        }

        summary.push(VersionedDelegationLinkSummary {
            index,
            token_id: token.jti.clone(),
            issuer: PrincipalId::from_verification_key(&token.issuer),
            delegate,
            capability_count: token.capabilities.len(),
            zone: token.zone.clone(),
            not_before_tick: token.nbf.0,
            expiry_tick: token.expiry.0,
        });
    }

    let leaf = chain.links.last().expect("non-empty chain has a leaf");
    if !leaf.capabilities.contains(&required_capability) {
        return Err(VersionedChainError::MissingCapabilityAtLeaf {
            required: required_capability,
            leaf_capabilities: leaf.capabilities.clone(),
        });
    }

    Ok(VersionedAuthorizationProof {
        chain_hash: versioned_chain_hash(&chain.links, leaf_delegate),
        authorized_capability: required_capability,
        root_issuer: PrincipalId::from_verification_key(&chain.links[0].issuer),
        leaf_delegate: leaf_delegate.clone(),
        verified_at_tick: context.current_tick,
        verified_epoch: context.current_epoch,
        chain_summary: summary,
    })
}

fn versioned_chain_hash(
    links: &[VersionedCapabilityToken],
    leaf_delegate: &PrincipalId,
) -> ContentHash {
    let mut material = Vec::new();
    for token in links {
        append_tagged_id(&mut material, &token.jti);
        material.extend_from_slice(token.issuer.as_bytes());
        material.extend_from_slice(token.zone.as_bytes());
        material.push(0xff);
        for capability in &token.capabilities {
            material.extend_from_slice(capability.to_string().as_bytes());
            material.push(0x1f);
        }
    }
    material.extend_from_slice(leaf_delegate.as_bytes());
    ContentHash::compute(&material)
}

fn append_tagged_id(material: &mut Vec<u8>, id: &PersistedEngineObjectId) {
    let version = id.derivation_version.as_str().as_bytes();
    material.extend_from_slice(&(version.len() as u64).to_be_bytes());
    material.extend_from_slice(version);
    material.extend_from_slice(id.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_token::{
        RevocationFreshnessRef, VersionedCheckpointRef, VersionedTokenBuilder,
    };
    use crate::engine_object_id::{
        derive_versioned_id, derive_versioned_schema_id, ObjectDomain, ObjectIdDerivationVersion,
    };
    use crate::policy_checkpoint::DeterministicTimestamp;
    use crate::signature_preimage::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes([seed; 32]).expect("valid test key")
    }

    fn principal(seed: u8) -> PrincipalId {
        PrincipalId::from_bytes([seed; 32])
    }

    fn checkpoint() -> VersionedCheckpointRef {
        let schema = derive_versioned_schema_id(
            ObjectIdDerivationVersion::Sha256V2,
            b"delegation-checkpoint-v2",
        )
        .expect("schema");
        VersionedCheckpointRef::new(
            5,
            PersistedEngineObjectId::from_versioned(
                derive_versioned_id(
                    ObjectDomain::CheckpointArtifact,
                    "zone-a",
                    &schema,
                    b"checkpoint",
                )
                .expect("checkpoint id"),
            ),
        )
    }

    fn freshness() -> crate::capability_token::RevocationFreshnessRef {
        RevocationFreshnessRef {
            min_revocation_seq: 3,
            revocation_head_hash: ContentHash::compute(b"rev-head"),
        }
    }

    fn token(
        issuer: &SigningKey,
        delegate: PrincipalId,
        capabilities: &[RuntimeCapability],
    ) -> VersionedCapabilityToken {
        let mut builder = VersionedTokenBuilder::new(
            issuer.clone(),
            DeterministicTimestamp(100),
            DeterministicTimestamp(1_000),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(delegate)
        .bind_checkpoint(checkpoint())
        .bind_revocation_freshness(freshness());
        for capability in capabilities {
            builder = builder.add_capability(*capability);
        }
        builder.build().expect("token")
    }

    fn fixture() -> (
        VersionedDelegationChain,
        SigningKey,
        PrincipalId,
        VersionedDelegationVerificationContext,
    ) {
        let root = key(1);
        let middle = key(2);
        let leaf_issuer = key(3);
        let leaf_delegate = principal(99);
        let links = vec![
            token(
                &root,
                PrincipalId::from_verification_key(&middle.verification_key()),
                &[RuntimeCapability::VmDispatch, RuntimeCapability::NetworkEgress],
            ),
            token(
                &middle,
                PrincipalId::from_verification_key(&leaf_issuer.verification_key()),
                &[RuntimeCapability::VmDispatch],
            ),
            token(
                &leaf_issuer,
                leaf_delegate.clone(),
                &[RuntimeCapability::VmDispatch],
            ),
        ];
        let checkpoint = checkpoint();
        let freshness = freshness();
        let mut context = VersionedDelegationVerificationContext::with_authorized_root(
            root.verification_key(),
        )
        .with_checkpoint_id(checkpoint.checkpoint_id)
        .with_revocation_head_hash(freshness.revocation_head_hash)
        .with_required_zone("zone-a");
        context.current_tick = 500;
        context.verifier_checkpoint_seq = checkpoint.min_checkpoint_seq;
        context.verifier_revocation_seq = freshness.min_revocation_seq;
        let chain = VersionedDelegationChain::new(links);
        chain
            .verify(
                RuntimeCapability::VmDispatch,
                &leaf_delegate,
                &context,
                &NoVersionedRevocationOracle,
            )
            .expect("fixture must authorize before testing an isolated rejection");
        (chain, root, leaf_delegate, context)
    }

    #[test]
    fn valid_v2_chain_verifies_end_to_end() {
        let (chain, _, leaf_delegate, mut context) = fixture();
        for tick in [100, 500, 1_000] {
            context.current_tick = tick;
            let proof = chain
                .verify(
                    RuntimeCapability::VmDispatch,
                    &leaf_delegate,
                    &context,
                    &NoVersionedRevocationOracle,
                )
                .expect("chain verification at both inclusive time boundaries and inside");
            assert_eq!(proof.chain_summary.len(), 3);
            assert_eq!(proof.verified_epoch, SecurityEpoch::GENESIS);
            assert_eq!(proof.verified_at_tick, tick);
            assert_eq!(proof.leaf_delegate, leaf_delegate);
            for (summary, token) in proof.chain_summary.iter().zip(&chain.links) {
                assert_eq!(summary.token_id, token.jti);
            }
        }
    }

    #[test]
    fn checkpoint_algorithm_mismatch_fails_before_authorization() {
        let (mut chain, _, leaf_delegate, context) = fixture();
        chain.links[0]
            .checkpoint_binding
            .as_mut()
            .expect("checkpoint")
            .checkpoint_id
            .derivation_version = ObjectIdDerivationVersion::LegacyV1;
        assert!(matches!(
            chain.verify(
                RuntimeCapability::VmDispatch,
                &leaf_delegate,
                &context,
                &NoVersionedRevocationOracle,
            ),
            Err(VersionedChainError::TokenIdentityFailed { index: 0, .. })
        ));
    }

    #[test]
    fn revocation_oracle_receives_verified_tagged_token_id() {
        #[derive(Default)]
        struct Oracle(BTreeSet<PersistedEngineObjectId>);
        impl VersionedRevocationOracle for Oracle {
            fn is_revoked(&self, token_id: &PersistedEngineObjectId) -> bool {
                self.0.contains(token_id)
            }
        }

        let (chain, _, leaf_delegate, context) = fixture();
        let revoked = chain.links[1].jti.clone();
        let oracle = Oracle(BTreeSet::from([revoked.clone()]));
        assert!(matches!(
            chain.verify(
                RuntimeCapability::VmDispatch,
                &leaf_delegate,
                &context,
                &oracle,
            ),
            Err(VersionedChainError::RevokedLink { index: 1, token_id }) if token_id == revoked
        ));
    }

    #[test]
    fn attenuation_amplification_is_rejected() {
        let (mut chain, _, leaf_delegate, context) = fixture();
        chain.links[2] = token(
            &key(3),
            leaf_delegate.clone(),
            &[RuntimeCapability::VmDispatch, RuntimeCapability::NetworkEgress],
        );
        chain.links[2]
            .verify_signature()
            .expect("amplifying child has a valid identity and issuer signature");
        assert_eq!(
            chain.verify(
                RuntimeCapability::VmDispatch,
                &leaf_delegate,
                &context,
                &NoVersionedRevocationOracle,
            ),
            Err(VersionedChainError::AttenuationViolation {
                index: 2,
                parent_capability_count: 1,
                child_capability_count: 2,
                amplified_capabilities: BTreeSet::from([RuntimeCapability::NetworkEgress]),
            })
        );
    }

    #[test]
    fn identity_tampering_is_rejected_before_revocation_lookup() {
        struct PanicOracle;
        impl VersionedRevocationOracle for PanicOracle {
            fn is_revoked(&self, _token_id: &PersistedEngineObjectId) -> bool {
                panic!("revocation oracle must not see an unverified token id")
            }
        }

        let (mut chain, _, leaf_delegate, context) = fixture();
        chain.links[0].jti.object_id.0[0] ^= 1;
        assert!(matches!(
            chain.verify(
                RuntimeCapability::VmDispatch,
                &leaf_delegate,
                &context,
                &PanicOracle,
            ),
            Err(VersionedChainError::TokenIdentityFailed { index: 0, .. })
        ));
    }

    #[test]
    fn time_and_freshness_failures_keep_their_exact_causes() {
        let (chain, _, leaf_delegate, mut context) = fixture();
        let cases = [
            (
                99,
                5,
                3,
                VersionedTokenError::NotYetValid {
                    current_tick: 99,
                    not_before: 100,
                },
            ),
            (
                1_001,
                5,
                3,
                VersionedTokenError::Expired {
                    current_tick: 1_001,
                    expiry: 1_000,
                },
            ),
            (
                500,
                4,
                3,
                VersionedTokenError::CheckpointBindingFailed {
                    required_seq: 5,
                    verifier_seq: 4,
                },
            ),
            (
                500,
                5,
                2,
                VersionedTokenError::RevocationFreshnessStale {
                    required_seq: 3,
                    verifier_seq: 2,
                },
            ),
        ];
        for (tick, checkpoint_seq, revocation_seq, error) in cases {
            context.current_tick = tick;
            context.verifier_checkpoint_seq = checkpoint_seq;
            context.verifier_revocation_seq = revocation_seq;
            assert_eq!(
                chain.verify(
                    RuntimeCapability::VmDispatch,
                    &leaf_delegate,
                    &context,
                    &NoVersionedRevocationOracle,
                ),
                Err(VersionedChainError::TokenVerificationFailed { index: 0, error })
            );
        }
    }

    #[test]
    fn accepted_checkpoint_cannot_change_only_its_algorithm_tag() {
        let (chain, _, leaf_delegate, mut context) = fixture();
        let checkpoint_id = checkpoint().checkpoint_id;
        let mut wrong_algorithm = checkpoint_id.clone();
        wrong_algorithm.derivation_version = ObjectIdDerivationVersion::LegacyV1;
        context.accepted_checkpoint_ids = BTreeSet::from([wrong_algorithm]);
        assert_eq!(
            chain.verify(
                RuntimeCapability::VmDispatch,
                &leaf_delegate,
                &context,
                &NoVersionedRevocationOracle,
            ),
            Err(VersionedChainError::TokenVerificationFailed {
                index: 0,
                error: VersionedTokenError::CheckpointIdentityMismatch { checkpoint_id },
            })
        );
    }

    #[test]
    fn leaf_cannot_recover_an_attenuated_capability() {
        let (chain, _, leaf_delegate, context) = fixture();
        assert_eq!(
            chain.verify(
                RuntimeCapability::NetworkEgress,
                &leaf_delegate,
                &context,
                &NoVersionedRevocationOracle,
            ),
            Err(VersionedChainError::MissingCapabilityAtLeaf {
                required: RuntimeCapability::NetworkEgress,
                leaf_capabilities: BTreeSet::from([RuntimeCapability::VmDispatch]),
            })
        );
    }

    #[test]
    fn leaf_presenter_must_match_the_signed_audience() {
        let (chain, _, _, context) = fixture();
        let wrong_presenter = principal(100);
        assert_eq!(
            chain.verify(
                RuntimeCapability::VmDispatch,
                &wrong_presenter,
                &context,
                &NoVersionedRevocationOracle,
            ),
            Err(VersionedChainError::TokenVerificationFailed {
                index: 2,
                error: VersionedTokenError::AudienceRejected {
                    presenter: wrong_presenter,
                    audience_size: 1,
                },
            })
        );
    }

    #[test]
    fn chain_hash_changes_when_only_id_algorithm_changes() {
        let (chain, _, leaf_delegate, _) = fixture();
        let original = versioned_chain_hash(&chain.links, &leaf_delegate);
        let mut modified = chain.links.clone();
        modified[0].jti.derivation_version = ObjectIdDerivationVersion::LegacyV1;
        assert_ne!(original, versioned_chain_hash(&modified, &leaf_delegate));
    }
}
