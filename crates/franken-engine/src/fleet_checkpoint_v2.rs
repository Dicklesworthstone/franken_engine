//! Authenticated fleet checkpoints with a non-consuming draft phase.
//!
//! The operator supplies the electorate independently of network messages.
//! Every co-signer checks the same evidence and containment view, and a strict
//! majority of that electorate must sign before pending intents are consumed.
//! This is an opt-in v2 API, not a migration of the legacy fleet wire protocol.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::fleet_immune_protocol::FLEET_V2_MAX_DYNAMIC_BYTES;
use crate::fleet_immune_protocol::{
    AuthenticatedFleetProtocolStateV2, DeterministicPrecedence, DurableFleetVerificationRegistry,
    FLEET_V2_MAX_COLLECTION_ITEMS, FLEET_V2_MAX_IDENTIFIER_BYTES, FleetAuthorityId,
    FleetIdentityError, FleetRegistryAnchorAuthority, FleetSignaturePreimageV2, FleetSignatureV2,
    FleetSigner, NodeId, ProtocolVersion, QuorumCheckpoint, ResolvedContainmentDecision,
};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

const ELECTORATE_EXTENSION: &str = "fleet.checkpoint-v2.electorate_hash";
const QUORUM_EXTENSION: &str = "fleet.checkpoint-v2.quorum_millionths";
const EVIDENCE_EXTENSION: &str = "fleet.checkpoint-v2.evidence_hash";
const INTENTS_EXTENSION: &str = "fleet.checkpoint-v2.intents_hash";

/// Independently provisioned checkpoint voters and quorum policy.
///
/// There is deliberately no deserializer: callers must validate operator
/// configuration through [`Self::new`], never adopt a received voter set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetCheckpointQuorumV2 {
    electorate: BTreeSet<NodeId>,
    threshold_millionths: u64,
    required: usize,
    electorate_hash: ContentHash,
}

impl FleetCheckpointQuorumV2 {
    pub fn new(
        electorate: BTreeSet<NodeId>,
        threshold_millionths: u64,
    ) -> Result<Self, FleetCheckpointV2Error> {
        if electorate.is_empty() || electorate.len() > FLEET_V2_MAX_COLLECTION_ITEMS {
            return Err(FleetCheckpointV2Error::InvalidQuorum {
                detail: "electorate must contain between 1 and 256 distinct nodes".to_string(),
            });
        }
        if !(500_000..=1_000_000).contains(&threshold_millionths) {
            return Err(FleetCheckpointV2Error::InvalidQuorum {
                detail: "quorum fraction must be between 500000 and 1000000 millionths".to_string(),
            });
        }
        // Reuse the protocol's canonical identity and collection validators.
        let shape = QuorumCheckpoint {
            checkpoint_seq: 1,
            epoch: SecurityEpoch::GENESIS,
            participating_nodes: electorate.clone(),
            evidence_summary_hash: ContentHash::default(),
            containment_decisions: Vec::new(),
            quorum_signatures: BTreeMap::new(),
            timestamp_ns: 0,
            protocol_version: ProtocolVersion::V2,
            extensions: BTreeMap::new(),
        };
        shape.validate_fleet_ingress_limits()?;
        shape.validate_fleet_structure()?;
        if electorate
            .iter()
            .map(|node| node.as_str().len())
            .sum::<usize>()
            > FLEET_V2_MAX_DYNAMIC_BYTES / 2
        {
            return Err(FleetCheckpointV2Error::InvalidQuorum {
                detail: "electorate identities exceed the reserved checkpoint byte budget"
                    .to_string(),
            });
        }
        let electorate_hash =
            hash_serializable(&("frankenengine.fleet-checkpoint-electorate.v2", &electorate))?;
        let fractional = (u128::from(threshold_millionths) * electorate.len() as u128)
            .div_ceil(1_000_000) as usize;
        // 50% means a majority, including for an even-sized electorate.
        let required = fractional.max(electorate.len() / 2 + 1);
        Ok(Self {
            electorate,
            threshold_millionths,
            required,
            electorate_hash,
        })
    }

    pub fn electorate(&self) -> &BTreeSet<NodeId> {
        &self.electorate
    }

    pub fn required_signatures(&self) -> usize {
        self.required
    }

    fn extensions(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                ELECTORATE_EXTENSION.to_string(),
                self.electorate_hash.to_hex(),
            ),
            (
                QUORUM_EXTENSION.to_string(),
                self.threshold_millionths.to_string(),
            ),
        ])
    }

    fn validate_checkpoint(
        &self,
        checkpoint: &QuorumCheckpoint,
    ) -> Result<(), FleetCheckpointV2Error> {
        checkpoint.validate_fleet_ingress_limits()?;
        checkpoint.validate_fleet_structure()?;
        if checkpoint.checkpoint_seq == 0
            || !checkpoint.quorum_signatures.is_empty()
            || checkpoint.extensions.len() != 4
            || self
                .extensions()
                .iter()
                .any(|(key, value)| checkpoint.extensions.get(key) != Some(value))
            || [EVIDENCE_EXTENSION, INTENTS_EXTENSION].iter().any(|key| {
                checkpoint.extensions.get(*key).is_none_or(|value| {
                    value.len() != 64
                        || !value
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
            })
            || !checkpoint.participating_nodes.is_subset(&self.electorate)
        {
            return Err(FleetCheckpointV2Error::CheckpointMismatch);
        }
        require_quorum(self.required, checkpoint.participating_nodes.len())
    }
}

/// A draft owns an immutable payload and collects independently verified votes.
/// Creating or signing a draft never consumes pending intents or advances the
/// checkpoint sequence. Signing reserves the node's vote for this round.
#[derive(Debug, Clone)]
pub struct FleetCheckpointDraftV2 {
    fleet_authority_id: FleetAuthorityId,
    quorum: FleetCheckpointQuorumV2,
    checkpoint: QuorumCheckpoint,
    intent_commitments: BTreeMap<String, ContentHash>,
    signatures: BTreeMap<NodeId, FleetSignatureV2>,
}

impl FleetCheckpointDraftV2 {
    pub fn checkpoint(&self) -> &QuorumCheckpoint {
        &self.checkpoint
    }

    pub fn signatures(&self) -> &BTreeMap<NodeId, FleetSignatureV2> {
        &self.signatures
    }

    pub fn add_signature<A: FleetRegistryAnchorAuthority>(
        &mut self,
        signature: FleetSignatureV2,
        registry: &DurableFleetVerificationRegistry,
        authority: &A,
    ) -> Result<(), FleetCheckpointV2Error> {
        validate_authority(self.fleet_authority_id, registry)?;
        self.quorum.validate_checkpoint(&self.checkpoint)?;
        if self.signatures.contains_key(&signature.signer) {
            return Err(FleetCheckpointV2Error::DuplicateSigner {
                node_id: signature.signer,
            });
        }
        registry.verify_live_detached_message_v2(
            &self.checkpoint,
            &signature,
            self.checkpoint.epoch,
            authority,
        )?;
        // A rotation during verification cannot publish a stale vote.
        registry.active_identity(&signature.signer, authority)?;
        self.signatures.insert(signature.signer.clone(), signature);
        Ok(())
    }
}

/// A checkpoint payload and its real, detached Ed25519 quorum signatures.
///
/// Deserialization does not confer trust. Call [`Self::verify`] with an
/// independently configured electorate and current durable authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedFleetCheckpointV2 {
    pub checkpoint: QuorumCheckpoint,
    pub signatures: BTreeMap<NodeId, FleetSignatureV2>,
}

impl SignedFleetCheckpointV2 {
    pub fn verify<A: FleetRegistryAnchorAuthority>(
        &self,
        quorum: &FleetCheckpointQuorumV2,
        registry: &DurableFleetVerificationRegistry,
        trusted_epoch: SecurityEpoch,
        authority: &A,
    ) -> Result<(), FleetCheckpointV2Error> {
        quorum.validate_checkpoint(&self.checkpoint)?;
        if self.signatures.len() > self.checkpoint.participating_nodes.len() {
            return Err(FleetCheckpointV2Error::CheckpointMismatch);
        }
        require_quorum(quorum.required, self.signatures.len())?;
        for (node_id, signature) in &self.signatures {
            if node_id.as_str().len() > FLEET_V2_MAX_IDENTIFIER_BYTES
                || signature.signer.as_str().len() > FLEET_V2_MAX_IDENTIFIER_BYTES
                || node_id != &signature.signer
            {
                return Err(FleetCheckpointV2Error::CheckpointMismatch);
            }
            registry.verify_live_detached_message_v2(
                &self.checkpoint,
                signature,
                trusted_epoch,
                authority,
            )?;
        }
        // Verify freshness again after the whole batch, not only before each
        // individual signature. The first voter exists because quorum > 0.
        let voter =
            self.signatures
                .keys()
                .next()
                .ok_or(FleetCheckpointV2Error::InsufficientQuorum {
                    required: quorum.required,
                    actual: 0,
                })?;
        registry.active_identity(voter, authority)?;
        Ok(())
    }
}

impl AuthenticatedFleetProtocolStateV2 {
    pub fn draft_checkpoint_v2(
        &self,
        timestamp_ns: u64,
        quorum: &FleetCheckpointQuorumV2,
    ) -> Result<FleetCheckpointDraftV2, FleetCheckpointV2Error> {
        let checkpoint = self.checkpoint_payload_v2(timestamp_ns, quorum)?;
        Ok(FleetCheckpointDraftV2 {
            fleet_authority_id: self.fleet_authority_id(),
            quorum: quorum.clone(),
            checkpoint,
            intent_commitments: self.pending_intent_commitments.clone(),
            signatures: BTreeMap::new(),
        })
    }

    /// Co-sign only a payload that agrees with this node's authenticated view.
    pub fn sign_checkpoint_v2<A: FleetRegistryAnchorAuthority>(
        &mut self,
        draft: &FleetCheckpointDraftV2,
        quorum: &FleetCheckpointQuorumV2,
        signer: &FleetSigner,
        registry: &DurableFleetVerificationRegistry,
        authority: &A,
    ) -> Result<FleetSignatureV2, FleetCheckpointV2Error> {
        validate_authority(self.fleet_authority_id(), registry)?;
        let vote_hash =
            hash_serializable(&("frankenengine.fleet-checkpoint-vote.v2", &draft.checkpoint))?;
        let voted_for_draft = self.checkpoint_vote
            == Some((
                draft.checkpoint.epoch,
                draft.checkpoint.checkpoint_seq,
                vote_hash,
            ));
        if draft.fleet_authority_id != self.fleet_authority_id()
            || &draft.quorum != quorum
            || signer.identity().signer != self.state.local_node_id
            || self.state.current_epoch != draft.checkpoint.epoch
            || self.state.last_checkpoint_seq.checked_add(1)
                != Some(draft.checkpoint.checkpoint_seq)
            || (!voted_for_draft
                && self.checkpoint_payload_v2(draft.checkpoint.timestamp_ns, quorum)?
                    != draft.checkpoint)
        {
            return Err(FleetCheckpointV2Error::CheckpointMismatch);
        }
        self.validate_checkpoint_vote_v2(&draft.checkpoint, vote_hash)?;
        let signature = signer.sign_detached_message_v2(&draft.checkpoint)?;
        registry.verify_live_detached_message_v2(
            &draft.checkpoint,
            &signature,
            self.state.current_epoch,
            authority,
        )?;
        registry.active_identity(&signature.signer, authority)?;
        // Reserve this round before releasing the signature. Repeating the
        // same vote is idempotent; signing a different view requires a later
        // checkpoint or policy epoch. This reservation is process-local.
        self.checkpoint_vote = Some((
            draft.checkpoint.epoch,
            draft.checkpoint.checkpoint_seq,
            vote_hash,
        ));
        Ok(signature)
    }

    /// Publish a fully verified quorum, consuming only the intents in its draft.
    /// A node that already voted for this view may receive more input while
    /// signatures are collected; that input remains available for the next round.
    pub fn finalize_checkpoint_v2<A: FleetRegistryAnchorAuthority>(
        &mut self,
        draft: &FleetCheckpointDraftV2,
        quorum: &FleetCheckpointQuorumV2,
        current_time_ns: u64,
        registry: &DurableFleetVerificationRegistry,
        authority: &A,
    ) -> Result<SignedFleetCheckpointV2, FleetCheckpointV2Error> {
        validate_authority(self.fleet_authority_id(), registry)?;
        let vote_hash =
            hash_serializable(&("frankenengine.fleet-checkpoint-vote.v2", &draft.checkpoint))?;
        let voted_for_draft = self.checkpoint_vote
            == Some((
                draft.checkpoint.epoch,
                draft.checkpoint.checkpoint_seq,
                vote_hash,
            ));
        if draft.fleet_authority_id != self.fleet_authority_id()
            || &draft.quorum != quorum
            || self.state.current_epoch != draft.checkpoint.epoch
            || self.state.last_checkpoint_seq.checked_add(1)
                != Some(draft.checkpoint.checkpoint_seq)
            || self.state.config.quorum_threshold_millionths != quorum.threshold_millionths
            || !quorum.electorate.contains(&self.state.local_node_id)
            || draft
                .intent_commitments
                .iter()
                .any(|(id, commitment)| self.pending_intent_commitments.get(id) != Some(commitment))
            || (!voted_for_draft
                && self.checkpoint_payload_v2(draft.checkpoint.timestamp_ns, quorum)?
                    != draft.checkpoint)
        {
            return Err(FleetCheckpointV2Error::StaleDraft);
        }
        if current_time_ns < draft.checkpoint.timestamp_ns {
            return Err(FleetCheckpointV2Error::InvalidTime);
        }
        let healthy = self
            .state
            .health
            .healthy_nodes(current_time_ns, self.state.config.partition_timeout_ns);
        if !draft.signatures.keys().all(|node| {
            healthy.contains(node)
                && self
                    .state
                    .health
                    .last_heartbeat_ns(node)
                    .is_some_and(|last| last <= current_time_ns)
        }) {
            return Err(FleetCheckpointV2Error::ExpiredParticipant);
        }
        let signed = SignedFleetCheckpointV2 {
            checkpoint: draft.checkpoint.clone(),
            signatures: draft.signatures.clone(),
        };
        self.validate_checkpoint_vote_v2(&signed.checkpoint, vote_hash)?;
        signed.verify(quorum, registry, self.state.current_epoch, authority)?;
        // No fallible work or external callbacks after the final trust check.
        self.state.last_checkpoint_seq = signed.checkpoint.checkpoint_seq;
        self.state.pending_intents.retain(|_, intents| {
            intents.retain(|intent| !draft.intent_commitments.contains_key(&intent.intent_id));
            !intents.is_empty()
        });
        for id in draft.intent_commitments.keys() {
            self.pending_intent_commitments.remove(id);
        }
        self.pending_intent_bytes = self
            .state
            .pending_intents
            .iter()
            .map(|(extension, intents)| {
                extension.len()
                    + intents
                        .iter()
                        .map(|intent| intent.intent_id.len())
                        .sum::<usize>()
            })
            .sum();
        self.checkpoint_vote = None;
        Ok(signed)
    }

    fn validate_checkpoint_vote_v2(
        &self,
        checkpoint: &QuorumCheckpoint,
        vote_hash: ContentHash,
    ) -> Result<(), FleetCheckpointV2Error> {
        if let Some((epoch, sequence, prior_hash)) = self.checkpoint_vote
            && epoch == checkpoint.epoch
            && sequence == checkpoint.checkpoint_seq
            && prior_hash != vote_hash
        {
            return Err(FleetCheckpointV2Error::ConflictingVote { epoch, sequence });
        }
        Ok(())
    }

    fn checkpoint_payload_v2(
        &self,
        timestamp_ns: u64,
        quorum: &FleetCheckpointQuorumV2,
    ) -> Result<QuorumCheckpoint, FleetCheckpointV2Error> {
        if self.state.protocol_version != ProtocolVersion::V2
            || self.state.config.quorum_threshold_millionths != quorum.threshold_millionths
            || !quorum.electorate.contains(&self.state.local_node_id)
        {
            return Err(FleetCheckpointV2Error::CheckpointMismatch);
        }
        let healthy = self
            .state
            .health
            .healthy_nodes(timestamp_ns, self.state.config.partition_timeout_ns);
        // A faulty member cannot veto a healthy majority by advertising a
        // heartbeat from the future. Exclude it without shrinking the electorate.
        let participating_nodes: BTreeSet<_> = healthy
            .intersection(&quorum.electorate)
            .filter(|node| {
                self.state
                    .health
                    .last_heartbeat_ns(node)
                    .is_some_and(|last| last <= timestamp_ns)
            })
            .cloned()
            .collect();
        require_quorum(quorum.required, participating_nodes.len())?;
        let mut decisions = Vec::new();
        let mut seen_intent_ids = BTreeSet::new();
        let mut canonical_intents = BTreeMap::new();
        for (extension_id, intents) in &self.state.pending_intents {
            let Some(winner) = DeterministicPrecedence::resolve_all(intents) else {
                continue;
            };
            let mut contributing_intent_ids = Vec::with_capacity(intents.len());
            for intent in intents {
                if intent.epoch != self.state.current_epoch {
                    return Err(FleetCheckpointV2Error::StaleIntent {
                        intent_id: intent.intent_id.clone(),
                    });
                }
                if !seen_intent_ids.insert(&intent.intent_id) {
                    return Err(FleetCheckpointV2Error::DuplicateIntent {
                        intent_id: intent.intent_id.clone(),
                    });
                }
                canonical_intents.insert(&intent.intent_id, intent);
                contributing_intent_ids.push(intent.intent_id.clone());
            }
            contributing_intent_ids.sort();
            decisions.push(ResolvedContainmentDecision {
                extension_id: extension_id.clone(),
                resolved_action: winner.proposed_action,
                contributing_intent_ids,
                epoch: self.state.current_epoch,
            });
        }
        let mut extensions = quorum.extensions();
        extensions.insert(
            EVIDENCE_EXTENSION.to_string(),
            hash_serializable(&(
                "frankenengine.fleet-checkpoint-evidence.v2",
                &self.evidence_commitments,
            ))?
            .to_hex(),
        );
        extensions.insert(
            INTENTS_EXTENSION.to_string(),
            hash_serializable(&(
                "frankenengine.fleet-checkpoint-intents.v2",
                canonical_intents,
                &self.pending_intent_commitments,
            ))?
            .to_hex(),
        );
        let checkpoint = QuorumCheckpoint {
            checkpoint_seq: self
                .state
                .last_checkpoint_seq
                .checked_add(1)
                .ok_or(FleetCheckpointV2Error::SequenceExhausted)?,
            epoch: self.state.current_epoch,
            participating_nodes,
            evidence_summary_hash: self.state.evidence.summary_hash(),
            containment_decisions: decisions,
            quorum_signatures: BTreeMap::new(),
            timestamp_ns,
            protocol_version: ProtocolVersion::V2,
            extensions,
        };
        quorum.validate_checkpoint(&checkpoint)?;
        Ok(checkpoint)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FleetCheckpointV2Error {
    #[error("fleet checkpoint identity verification failed: {0}")]
    Identity(#[from] FleetIdentityError),
    #[error("invalid fleet checkpoint quorum: {detail}")]
    InvalidQuorum { detail: String },
    #[error("fleet checkpoint quorum requires {required} distinct voters, got {actual}")]
    InsufficientQuorum { required: usize, actual: usize },
    #[error("checkpoint payload, electorate, or signer does not match the trusted local view")]
    CheckpointMismatch,
    #[error("checkpoint draft no longer matches this node's epoch or admitted view")]
    StaleDraft,
    #[error("checkpoint signer {node_id} has already voted")]
    DuplicateSigner { node_id: NodeId },
    #[error("already voted for a different checkpoint at epoch {epoch}, sequence {sequence}")]
    ConflictingVote { epoch: SecurityEpoch, sequence: u64 },
    #[error("checkpoint contains duplicate intent {intent_id}")]
    DuplicateIntent { intent_id: String },
    #[error("checkpoint contains intent {intent_id} from an earlier epoch")]
    StaleIntent { intent_id: String },
    #[error("checkpoint sequence counter is exhausted")]
    SequenceExhausted,
    #[error("checkpoint finalization time precedes its draft")]
    InvalidTime,
    #[error("a checkpoint signer is no longer healthy")]
    ExpiredParticipant,
    #[error("checkpoint state serialization failed: {detail}")]
    Serialization { detail: String },
}

fn validate_authority(
    expected: FleetAuthorityId,
    registry: &DurableFleetVerificationRegistry,
) -> Result<(), FleetCheckpointV2Error> {
    if expected != registry.fleet_authority_id() {
        return Err(FleetIdentityError::FleetAuthorityMismatch {
            boundary: "fleet checkpoint v2".to_string(),
            expected,
            actual: registry.fleet_authority_id(),
        }
        .into());
    }
    Ok(())
}

fn hash_serializable(value: &impl Serialize) -> Result<ContentHash, FleetCheckpointV2Error> {
    serde_json::to_vec(value)
        .map(|bytes| ContentHash::compute(&bytes))
        .map_err(|error| FleetCheckpointV2Error::Serialization {
            detail: error.to_string(),
        })
}

fn require_quorum(required: usize, actual: usize) -> Result<(), FleetCheckpointV2Error> {
    if actual < required {
        Err(FleetCheckpointV2Error::InsufficientQuorum { required, actual })
    } else {
        Ok(())
    }
}
