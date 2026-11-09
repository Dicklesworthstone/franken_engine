//! Bounded, explicitly opted-in protocol-V2 fleet transport.
//!
//! Frames contain semantic payloads and detached Ed25519 signatures. Legacy
//! public-node-ID tags are absent from this schema. Decoding establishes shape,
//! never trust: admission reuses the current externally anchored registry and
//! authenticated state APIs. The caller supplies the electorate and current time.
//! This module does not change `ProtocolVersion::CURRENT` or persist vote state.

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::fleet_checkpoint_v2::{
    FleetCheckpointDraftV2, FleetCheckpointQuorumV2, FleetCheckpointV2Error,
    SignedFleetCheckpointV2,
};
use crate::fleet_immune_protocol::{
    AuthenticatedFleetProtocolStateV2, ContainmentAction, ContainmentIntent,
    DurableFleetVerificationRegistry, EvidencePacket, FLEET_V2_MAX_COLLECTION_ITEMS,
    FLEET_V2_MAX_IDENTIFIER_BYTES, FLEET_V2_MAX_VALUE_BYTES, FleetAuthorityId, FleetIdentityError,
    FleetIngressV2Error, FleetKeyId, FleetRegistryAnchorAuthority, FleetSignaturePreimageV2,
    FleetSignatureV2, HeartbeatLiveness, MessageSignature, NodeId, ProtocolVersion,
    QuorumCheckpoint, ResolvedContainmentDecision, validate_fleet_v2_frame_len,
};
use crate::hash_tiers::{AuthenticityHash, ContentHash};
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::Signature;

/// Fixed schema discriminator. Other versions and legacy envelopes are rejected.
pub const FLEET_TRANSPORT_SCHEMA: &str = "frankenengine.fleet-transport.v2";
/// Maximum JSON nesting before allocating a typed message.
pub const FLEET_TRANSPORT_MAX_DEPTH: usize = 16;
const MAX_JSON_NODES: usize = 16_384;
const MAX_JSON_CONTAINER_ITEMS: usize = 1024;

/// A decoded but unauthenticated message. Use `process_frame_v2` for admission.
///
/// Outbound callers may construct these from existing signed protocol values;
/// `encode` strips legacy tags and rejects non-V2 semantic payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FleetTransportMessage {
    Evidence {
        message: EvidencePacket,
        signature: FleetSignatureV2,
    },
    Intent {
        message: ContainmentIntent,
        signature: FleetSignatureV2,
    },
    Heartbeat {
        message: HeartbeatLiveness,
        signature: FleetSignatureV2,
    },
    CheckpointProposal {
        checkpoint: QuorumCheckpoint,
        signature: FleetSignatureV2,
    },
    CheckpointVote {
        checkpoint: QuorumCheckpoint,
        signature: FleetSignatureV2,
    },
    CheckpointFinalized(SignedFleetCheckpointV2),
}

impl FleetTransportMessage {
    /// Encode one bounded V2 frame. This does not authenticate supplied signatures.
    pub fn encode(&self) -> Result<Vec<u8>, FleetTransportError> {
        self.validate_shape()?;
        let envelope = WireEnvelope {
            schema: FLEET_TRANSPORT_SCHEMA.to_string(),
            message: WireMessage::from_message(self),
        };
        let frame = serde_json::to_vec(&envelope).map_err(malformed)?;
        validate_fleet_v2_frame_len(frame.len())?;
        Ok(frame)
    }

    /// Reject excessive raw size, nesting, duplicate keys, trailing data, and
    /// unknown fields before constructing protocol payloads. Signatures remain
    /// untrusted until admitted against the externally supplied authority.
    pub fn decode(frame: &[u8]) -> Result<Self, FleetTransportError> {
        validate_fleet_v2_frame_len(frame.len())?;
        let mut remaining = MAX_JSON_NODES;
        let mut deserializer = serde_json::Deserializer::from_slice(frame);
        let value = BoundedValue {
            depth: 0,
            remaining: &mut remaining,
        }
        .deserialize(&mut deserializer)
        .map_err(malformed)?;
        deserializer.end().map_err(malformed)?;
        let envelope: WireEnvelope = serde_json::from_value(value).map_err(malformed)?;
        if envelope.schema != FLEET_TRANSPORT_SCHEMA {
            return Err(FleetTransportError::UnsupportedSchema {
                schema: envelope.schema,
            });
        }
        let message = envelope.message.into_message()?;
        message.validate_shape()?;
        Ok(message)
    }

    fn validate_shape(&self) -> Result<(), FleetTransportError> {
        match self {
            Self::Evidence { message, signature } => validate_signed_shape(message, signature),
            Self::Intent { message, signature } => validate_signed_shape(message, signature),
            Self::Heartbeat { message, signature } => validate_signed_shape(message, signature),
            Self::CheckpointProposal {
                checkpoint,
                signature,
            }
            | Self::CheckpointVote {
                checkpoint,
                signature,
            } => {
                validate_checkpoint_shape(checkpoint)?;
                validate_signed_shape(checkpoint, signature)
            }
            Self::CheckpointFinalized(signed) => {
                validate_checkpoint_shape(&signed.checkpoint)?;
                if signed.signatures.is_empty()
                    || signed.signatures.len() > FLEET_V2_MAX_COLLECTION_ITEMS
                {
                    return Err(invalid("checkpoint signature count is outside 1..=256"));
                }
                for (node, signature) in &signed.signatures {
                    if node != &signature.signer {
                        return Err(invalid(
                            "checkpoint signature map key does not match signer",
                        ));
                    }
                    validate_signed_shape(&signed.checkpoint, signature)?;
                }
                Ok(())
            }
        }
    }
}

/// Independently trusted admission inputs; none are read from the wire.
pub struct FleetTransportContext<'a, A: FleetRegistryAnchorAuthority> {
    pub quorum: &'a FleetCheckpointQuorumV2,
    pub registry: &'a DurableFleetVerificationRegistry,
    pub authority: &'a A,
    pub current_time_ns: u64,
}

/// A successful state change or authenticated checkpoint proposal.
#[derive(Debug)]
pub enum FleetTransportOutcome {
    EvidenceAccepted { node_id: NodeId, sequence: u64 },
    IntentAccepted { node_id: NodeId, sequence: u64 },
    HeartbeatAccepted { node_id: NodeId, sequence: u64 },
    CheckpointProposed(FleetCheckpointDraftV2),
    CheckpointVoteAdded { signer: NodeId, checkpoint_seq: u64 },
    CheckpointFinalized(SignedFleetCheckpointV2),
}

impl AuthenticatedFleetProtocolStateV2 {
    /// Admit exactly one network frame through the authenticated mutation paths.
    ///
    /// A checkpoint vote requires the caller's pending draft and must match its
    /// entire body. A proposal returns a checked draft with its proposer's vote;
    /// the caller may co-sign it with `sign_checkpoint_v2`. A finalized frame
    /// uses the same consuming checks as local checkpoint completion.
    pub fn process_frame_v2<A: FleetRegistryAnchorAuthority>(
        &mut self,
        frame: &[u8],
        context: &FleetTransportContext<'_, A>,
        pending_checkpoint: Option<&mut FleetCheckpointDraftV2>,
    ) -> Result<FleetTransportOutcome, FleetTransportError> {
        let message = FleetTransportMessage::decode(frame)?;
        if self.fleet_authority_id() != context.registry.fleet_authority_id() {
            return Err(FleetIdentityError::FleetAuthorityMismatch {
                boundary: "fleet transport".to_string(),
                expected: self.fleet_authority_id(),
                actual: context.registry.fleet_authority_id(),
            }
            .into());
        }
        match message {
            FleetTransportMessage::Evidence { message, signature } => {
                self.process_evidence(&message, &signature, context.registry, context.authority)?;
                Ok(FleetTransportOutcome::EvidenceAccepted {
                    node_id: message.node_id,
                    sequence: message.sequence,
                })
            }
            FleetTransportMessage::Intent { message, signature } => {
                self.process_intent(&message, &signature, context.registry, context.authority)?;
                Ok(FleetTransportOutcome::IntentAccepted {
                    node_id: message.node_id,
                    sequence: message.sequence,
                })
            }
            FleetTransportMessage::Heartbeat { message, signature } => {
                self.process_heartbeat(&message, &signature, context.registry, context.authority)?;
                Ok(FleetTransportOutcome::HeartbeatAccepted {
                    node_id: message.node_id,
                    sequence: message.sequence,
                })
            }
            FleetTransportMessage::CheckpointProposal {
                checkpoint,
                signature,
            } => {
                context.registry.verify_live_detached_message_v2(
                    &checkpoint,
                    &signature,
                    self.state().current_epoch,
                    context.authority,
                )?;
                let mut draft = self.import_checkpoint_proposal_v2(&checkpoint, context.quorum)?;
                draft.add_signature(signature, context.registry, context.authority)?;
                Ok(FleetTransportOutcome::CheckpointProposed(draft))
            }
            FleetTransportMessage::CheckpointVote {
                checkpoint,
                signature,
            } => {
                let draft =
                    pending_checkpoint.ok_or(FleetTransportError::MissingCheckpointDraft)?;
                if draft.checkpoint() != &checkpoint {
                    return Err(FleetTransportError::CheckpointVoteMismatch);
                }
                context.registry.verify_live_detached_message_v2(
                    &checkpoint,
                    &signature,
                    self.state().current_epoch,
                    context.authority,
                )?;
                self.import_checkpoint_proposal_v2(&checkpoint, context.quorum)?;
                let signer = signature.signer.clone();
                let checkpoint_seq = checkpoint.checkpoint_seq;
                draft.add_signature(signature, context.registry, context.authority)?;
                Ok(FleetTransportOutcome::CheckpointVoteAdded {
                    signer,
                    checkpoint_seq,
                })
            }
            FleetTransportMessage::CheckpointFinalized(signed) => {
                let accepted = self.accept_checkpoint_v2(
                    &signed,
                    context.quorum,
                    context.current_time_ns,
                    context.registry,
                    context.authority,
                )?;
                Ok(FleetTransportOutcome::CheckpointFinalized(accepted))
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FleetTransportError {
    #[error("invalid fleet transport frame: {detail}")]
    MalformedFrame { detail: String },
    #[error("unsupported fleet transport schema: {schema}")]
    UnsupportedSchema { schema: String },
    #[error("fleet transport identity validation failed: {0}")]
    Identity(#[from] FleetIdentityError),
    #[error("fleet transport admission failed: {0}")]
    Ingress(#[from] FleetIngressV2Error),
    #[error("fleet transport checkpoint validation failed: {0}")]
    Checkpoint(#[from] FleetCheckpointV2Error),
    #[error("a checkpoint vote requires its pending local draft")]
    MissingCheckpointDraft,
    #[error("checkpoint vote does not match the pending local draft")]
    CheckpointVoteMismatch,
}

fn malformed(error: impl fmt::Display) -> FleetTransportError {
    invalid(&error.to_string())
}

fn invalid(detail: &str) -> FleetTransportError {
    FleetTransportError::MalformedFrame {
        detail: detail.to_string(),
    }
}

fn validate_signed_shape<T: FleetSignaturePreimageV2>(
    message: &T,
    signature: &FleetSignatureV2,
) -> Result<(), FleetTransportError> {
    message.validate_fleet_ingress_limits()?;
    message.validate_fleet_structure()?;
    message.validate_fleet_signer(&signature.signer)?;
    // Reuse the canonical identity budget, including bounded signer metadata.
    message.fleet_signature_preimage_v2(&signature.identity())?;
    Ok(())
}

fn validate_checkpoint_shape(checkpoint: &QuorumCheckpoint) -> Result<(), FleetTransportError> {
    checkpoint.validate_fleet_ingress_limits()?;
    checkpoint.validate_fleet_structure()?;
    if !checkpoint.quorum_signatures.is_empty() {
        return Err(invalid(
            "legacy checkpoint signature carriers are forbidden",
        ));
    }
    Ok(())
}

fn legacy_marker(node_id: NodeId) -> MessageSignature {
    MessageSignature {
        signer: node_id,
        hash: AuthenticityHash([0; 32]),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEnvelope {
    schema: String,
    message: WireMessage,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum WireMessage {
    Evidence {
        payload: EvidencePayload,
        signature: SignaturePayload,
    },
    Intent {
        payload: IntentPayload,
        signature: SignaturePayload,
    },
    Heartbeat {
        payload: HeartbeatPayload,
        signature: SignaturePayload,
    },
    CheckpointProposal {
        payload: CheckpointPayload,
        signature: SignaturePayload,
    },
    CheckpointVote {
        payload: CheckpointPayload,
        signature: SignaturePayload,
    },
    CheckpointFinalized {
        payload: CheckpointPayload,
        signatures: Vec<SignaturePayload>,
    },
}

impl WireMessage {
    fn from_message(message: &FleetTransportMessage) -> Self {
        match message {
            FleetTransportMessage::Evidence { message, signature } => Self::Evidence {
                payload: message.clone().into(),
                signature: signature.clone().into(),
            },
            FleetTransportMessage::Intent { message, signature } => Self::Intent {
                payload: message.clone().into(),
                signature: signature.clone().into(),
            },
            FleetTransportMessage::Heartbeat { message, signature } => Self::Heartbeat {
                payload: message.clone().into(),
                signature: signature.clone().into(),
            },
            FleetTransportMessage::CheckpointProposal {
                checkpoint,
                signature,
            } => Self::CheckpointProposal {
                payload: checkpoint.clone().into(),
                signature: signature.clone().into(),
            },
            FleetTransportMessage::CheckpointVote {
                checkpoint,
                signature,
            } => Self::CheckpointVote {
                payload: checkpoint.clone().into(),
                signature: signature.clone().into(),
            },
            FleetTransportMessage::CheckpointFinalized(signed) => Self::CheckpointFinalized {
                payload: signed.checkpoint.clone().into(),
                signatures: signed
                    .signatures
                    .values()
                    .cloned()
                    .map(Into::into)
                    .collect(),
            },
        }
    }

    fn into_message(self) -> Result<FleetTransportMessage, FleetTransportError> {
        Ok(match self {
            Self::Evidence { payload, signature } => FleetTransportMessage::Evidence {
                message: payload.into(),
                signature: signature.into(),
            },
            Self::Intent { payload, signature } => FleetTransportMessage::Intent {
                message: payload.into(),
                signature: signature.into(),
            },
            Self::Heartbeat { payload, signature } => FleetTransportMessage::Heartbeat {
                message: payload.into(),
                signature: signature.into(),
            },
            Self::CheckpointProposal { payload, signature } => {
                FleetTransportMessage::CheckpointProposal {
                    checkpoint: payload.try_into()?,
                    signature: signature.into(),
                }
            }
            Self::CheckpointVote { payload, signature } => FleetTransportMessage::CheckpointVote {
                checkpoint: payload.try_into()?,
                signature: signature.into(),
            },
            Self::CheckpointFinalized {
                payload,
                signatures,
            } => {
                if signatures.len() > FLEET_V2_MAX_COLLECTION_ITEMS
                    || !signatures
                        .windows(2)
                        .all(|pair| pair[0].signer < pair[1].signer)
                {
                    return Err(invalid(
                        "checkpoint signatures must be bounded, sorted, and distinct",
                    ));
                }
                FleetTransportMessage::CheckpointFinalized(SignedFleetCheckpointV2 {
                    checkpoint: payload.try_into()?,
                    signatures: signatures
                        .into_iter()
                        .map(|signature| (signature.signer.clone(), signature.into()))
                        .collect(),
                })
            }
        })
    }
}

macro_rules! semantic_payload {
    ($wire:ident, $protocol:ident, { $($field:ident: $ty:ty),* $(,)? }) => {
        #[derive(Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct $wire { $( $field: $ty, )* }

        impl From<$protocol> for $wire {
            fn from(message: $protocol) -> Self { Self { $( $field: message.$field, )* } }
        }

        impl From<$wire> for $protocol {
            fn from(message: $wire) -> Self {
                let signature = legacy_marker(message.node_id.clone());
                Self { $( $field: message.$field, )* signature, protocol_version: ProtocolVersion::V2 }
            }
        }
    };
}

semantic_payload!(EvidencePayload, EvidencePacket, {
    trace_id: String,
    extension_id: String,
    evidence_hash: ContentHash,
    posterior_delta_millionths: i64,
    policy_version: u64,
    epoch: SecurityEpoch,
    node_id: NodeId,
    sequence: u64,
    timestamp_ns: u64,
    extensions: BTreeMap<String, String>,
});

semantic_payload!(IntentPayload, ContainmentIntent, {
    intent_id: String,
    extension_id: String,
    proposed_action: ContainmentAction,
    confidence_millionths: u64,
    supporting_evidence_ids: Vec<String>,
    policy_version: u64,
    epoch: SecurityEpoch,
    node_id: NodeId,
    sequence: u64,
    timestamp_ns: u64,
    extensions: BTreeMap<String, String>,
});

semantic_payload!(HeartbeatPayload, HeartbeatLiveness, {
    node_id: NodeId,
    policy_version: u64,
    evidence_frontier_hash: ContentHash,
    local_health: BTreeMap<String, String>,
    epoch: SecurityEpoch,
    sequence: u64,
    timestamp_ns: u64,
    extensions: BTreeMap<String, String>,
});

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointPayload {
    checkpoint_seq: u64,
    epoch: SecurityEpoch,
    participating_nodes: Vec<NodeId>,
    evidence_summary_hash: ContentHash,
    containment_decisions: Vec<DecisionPayload>,
    timestamp_ns: u64,
    extensions: BTreeMap<String, String>,
}

impl From<QuorumCheckpoint> for CheckpointPayload {
    fn from(checkpoint: QuorumCheckpoint) -> Self {
        Self {
            checkpoint_seq: checkpoint.checkpoint_seq,
            epoch: checkpoint.epoch,
            participating_nodes: checkpoint.participating_nodes.into_iter().collect(),
            evidence_summary_hash: checkpoint.evidence_summary_hash,
            containment_decisions: checkpoint
                .containment_decisions
                .into_iter()
                .map(Into::into)
                .collect(),
            timestamp_ns: checkpoint.timestamp_ns,
            extensions: checkpoint.extensions,
        }
    }
}

impl TryFrom<CheckpointPayload> for QuorumCheckpoint {
    type Error = FleetTransportError;

    fn try_from(checkpoint: CheckpointPayload) -> Result<Self, Self::Error> {
        if !checkpoint
            .participating_nodes
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        {
            return Err(invalid(
                "checkpoint participants must be strictly sorted and distinct",
            ));
        }
        Ok(Self {
            checkpoint_seq: checkpoint.checkpoint_seq,
            epoch: checkpoint.epoch,
            participating_nodes: checkpoint.participating_nodes.into_iter().collect(),
            evidence_summary_hash: checkpoint.evidence_summary_hash,
            containment_decisions: checkpoint
                .containment_decisions
                .into_iter()
                .map(Into::into)
                .collect(),
            quorum_signatures: BTreeMap::new(),
            timestamp_ns: checkpoint.timestamp_ns,
            protocol_version: ProtocolVersion::V2,
            extensions: checkpoint.extensions,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionPayload {
    extension_id: String,
    resolved_action: ContainmentAction,
    contributing_intent_ids: Vec<String>,
    epoch: SecurityEpoch,
}

impl From<ResolvedContainmentDecision> for DecisionPayload {
    fn from(value: ResolvedContainmentDecision) -> Self {
        Self {
            extension_id: value.extension_id,
            resolved_action: value.resolved_action,
            contributing_intent_ids: value.contributing_intent_ids,
            epoch: value.epoch,
        }
    }
}

impl From<DecisionPayload> for ResolvedContainmentDecision {
    fn from(value: DecisionPayload) -> Self {
        Self {
            extension_id: value.extension_id,
            resolved_action: value.resolved_action,
            contributing_intent_ids: value.contributing_intent_ids,
            epoch: value.epoch,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignaturePayload {
    fleet_authority_id: FleetAuthorityId,
    signer: NodeId,
    key_id: FleetKeyId,
    key_sequence: u64,
    signature: HexSignature,
}

impl From<FleetSignatureV2> for SignaturePayload {
    fn from(value: FleetSignatureV2) -> Self {
        Self {
            fleet_authority_id: value.fleet_authority_id,
            signer: value.signer,
            key_id: value.key_id,
            key_sequence: value.key_sequence,
            signature: HexSignature(value.signature.to_bytes()),
        }
    }
}

impl From<SignaturePayload> for FleetSignatureV2 {
    fn from(value: SignaturePayload) -> Self {
        Self {
            fleet_authority_id: value.fleet_authority_id,
            signer: value.signer,
            key_id: value.key_id,
            key_sequence: value.key_sequence,
            signature: Signature::from_bytes(value.signature.0),
        }
    }
}

struct HexSignature([u8; 64]);

impl Serialize for HexSignature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for HexSignature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.len() != 128
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(serde::de::Error::custom(
                "signature must be 128 lowercase hexadecimal digits",
            ));
        }
        let mut bytes = [0; 64];
        hex::decode_to_slice(&value, &mut bytes).map_err(serde::de::Error::custom)?;
        Ok(Self(bytes))
    }
}

/// This first pass keeps duplicate keys visible. Parsing through ordinary
/// `Value` or `BTreeMap` deserialization first would silently overwrite them.
struct BoundedValue<'a> {
    depth: usize,
    remaining: &'a mut usize,
}

impl<'de> DeserializeSeed<'de> for BoundedValue<'_> {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        if self.depth > FLEET_TRANSPORT_MAX_DEPTH {
            return Err(serde::de::Error::custom(
                "fleet frame nesting limit exceeded",
            ));
        }
        if *self.remaining == 0 {
            return Err(serde::de::Error::custom("fleet frame value count exceeded"));
        }
        *self.remaining -= 1;
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for BoundedValue<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded fleet JSON with unique object keys and integer numbers")
    }

    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Value, E> {
        if value.len() > FLEET_V2_MAX_VALUE_BYTES {
            return Err(E::custom("fleet JSON string exceeds its byte limit"));
        }
        Ok(Value::String(value.to_string()))
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Value, E> {
        if value.len() > FLEET_V2_MAX_VALUE_BYTES {
            return Err(E::custom("fleet JSON string exceeds its byte limit"));
        }
        Ok(Value::String(value))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<S: SeqAccess<'de>>(self, mut sequence: S) -> Result<Value, S::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(BoundedValue {
            depth: self.depth + 1,
            remaining: self.remaining,
        })? {
            if values.len() == MAX_JSON_CONTAINER_ITEMS {
                return Err(serde::de::Error::custom(
                    "fleet JSON array item limit exceeded",
                ));
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Value, M::Error> {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > FLEET_V2_MAX_IDENTIFIER_BYTES {
                return Err(serde::de::Error::custom(
                    "fleet JSON key exceeds its byte limit",
                ));
            }
            if values.len() == MAX_JSON_CONTAINER_ITEMS {
                return Err(serde::de::Error::custom(
                    "fleet JSON object item limit exceeded",
                ));
            }
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom("duplicate fleet JSON object key"));
            }
            let value = map.next_value_seed(BoundedValue {
                depth: self.depth + 1,
                remaining: self.remaining,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
