//! Fleet immune-system message protocol.
//!
//! Defines the wire protocol and message schema for fleet-wide collective
//! defense: nodes exchange signed evidence atoms, local posterior risk deltas,
//! and containment intent signals.  Gossip dissemination, quorum checkpoints,
//! and deterministic precedence ensure that fleet-scale containment decisions
//! converge predictably even under partitions.
//!
//! Fixed-point millionths (1_000_000 = 1.0) are used for all fractional values
//! to guarantee deterministic arithmetic across platforms.
//!
//! All collections use `BTreeMap`/`BTreeSet` for deterministic iteration.
//!
//! Plan references: Section 10.12 item 5, 9H.2, 9F.2.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{CanonicalValue, SchemaHash};
use crate::engine_object_id::ObjectDomain;
use crate::hash_tiers::{AuthenticityHash, ContentHash};
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    SIGNATURE_SENTINEL, Signature, SignatureError, SigningKey, VerificationKey, build_preimage,
    sign_preimage, verify_signature,
};

// ---------------------------------------------------------------------------
// ContainmentAction — severity-ordered containment actions
// ---------------------------------------------------------------------------

/// Containment action with deterministic severity ordering.
///
/// Under conflict, higher-severity actions take precedence regardless
/// of causal order.  This eliminates TOCTOU attacks exploiting clock
/// disagreements between nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ContainmentAction {
    /// Continue normal execution.
    Allow = 0,
    /// Sandbox with restricted capabilities.
    Sandbox = 1,
    /// Suspend execution pending review.
    Suspend = 2,
    /// Terminate execution immediately.
    Terminate = 3,
    /// Full quarantine with fleet-wide propagation.
    Quarantine = 4,
}

impl ContainmentAction {
    /// Return the severity rank (higher = more severe).
    pub fn severity(self) -> u8 {
        self as u8
    }

    /// True if `self` is at least as severe as `other`.
    pub fn at_least_as_severe_as(self, other: Self) -> bool {
        self.severity() >= other.severity()
    }
}

impl fmt::Display for ContainmentAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Sandbox => write!(f, "sandbox"),
            Self::Suspend => write!(f, "suspend"),
            Self::Terminate => write!(f, "terminate"),
            Self::Quarantine => write!(f, "quarantine"),
        }
    }
}

// ---------------------------------------------------------------------------
// ProtocolVersion — versioned handshake negotiation
// ---------------------------------------------------------------------------

/// Protocol version for forward-compatible negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub major: u32,
    pub minor: u32,
}

impl ProtocolVersion {
    pub const V1: Self = Self { major: 1, minor: 0 };
    pub const V2: Self = Self { major: 2, minor: 0 };
    pub const CURRENT: Self = Self::V1;

    /// Two versions are compatible if they share the same major version
    /// and the reader's minor version is >= the writer's.
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major && self.minor >= other.minor
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

// ---------------------------------------------------------------------------
// NodeId — deterministic fleet node identity
// ---------------------------------------------------------------------------

/// Unique identifier for a fleet node.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeId(pub String);

impl NodeId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// MessageSignature — per-message cryptographic signature
// ---------------------------------------------------------------------------

/// Cryptographic signature on a fleet protocol message.
///
/// Wraps an `AuthenticityHash` produced by the node's signing key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageSignature {
    /// The signing node.
    pub signer: NodeId,
    /// Keyed hash of the canonical message bytes.
    pub hash: AuthenticityHash,
}

// ---------------------------------------------------------------------------
// Fleet protocol v2 signing foundation
// ---------------------------------------------------------------------------

/// Hard ceiling for one serialized fleet-v2 transport frame.
///
/// Transport code must apply this limit to the raw frame before deserializing
/// it. The typed signing and verification paths additionally enforce the
/// structural budgets below before allocation proportional to attacker input
/// or construction of a canonical tree.
pub const FLEET_V2_MAX_FRAME_BYTES: usize = 64 * 1024;

/// Maximum aggregate UTF-8 bytes across dynamic fields in one v2 message.
pub const FLEET_V2_MAX_DYNAMIC_BYTES: usize = 32 * 1024;

/// Maximum UTF-8 byte length of an identifier or map key.
pub const FLEET_V2_MAX_IDENTIFIER_BYTES: usize = 256;

/// Maximum UTF-8 byte length of an extension or health-map value.
pub const FLEET_V2_MAX_VALUE_BYTES: usize = 4 * 1024;

/// Maximum elements in any single array or set carried by a v2 message.
pub const FLEET_V2_MAX_COLLECTION_ITEMS: usize = 256;

/// Maximum entries in any string or legacy-signature map.
pub const FLEET_V2_MAX_MAP_ENTRIES: usize = 64;

/// Maximum aggregate collection elements across a nested v2 message.
pub const FLEET_V2_MAX_TOTAL_COLLECTION_ITEMS: usize = 1024;

/// Maximum inclusive reconciliation range accepted from one peer.
pub const FLEET_V2_MAX_SEQUENCE_RANGE_LEN: u64 = 65_536;

/// Stable identifier for a fleet verification key.
///
/// The identifier is derived from the verification-key bytes rather than
/// supplied by an untrusted message, so a key cannot be rebound under a
/// convenient alias.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FleetKeyId(ContentHash);

impl FleetKeyId {
    pub fn from_verification_key(key: &VerificationKey) -> Self {
        Self(ContentHash::compute(key.as_bytes()))
    }

    pub fn as_content_hash(&self) -> &ContentHash {
        &self.0
    }
}

impl fmt::Display for FleetKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fleet-key:{}", self.0.to_hex())
    }
}

/// Public identity metadata bound into every fleet protocol v2 signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetSigningIdentity {
    pub signer: NodeId,
    pub key_id: FleetKeyId,
    pub key_sequence: u64,
}

/// Detached Ed25519 signature for a fleet protocol v2 message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetSignatureV2 {
    pub signer: NodeId,
    pub key_id: FleetKeyId,
    pub key_sequence: u64,
    pub signature: Signature,
}

impl FleetSignatureV2 {
    pub fn identity(&self) -> FleetSigningIdentity {
        FleetSigningIdentity {
            signer: self.signer.clone(),
            key_id: self.key_id,
            key_sequence: self.key_sequence,
        }
    }
}

/// Secret signing authority for one fleet node.
///
/// This type intentionally implements neither `Serialize` nor `Deserialize`.
/// It must be provisioned separately from persisted protocol state.
pub struct FleetSigner {
    identity: FleetSigningIdentity,
    signing_key: SigningKey,
    verification_key: VerificationKey,
}

impl fmt::Debug for FleetSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FleetSigner")
            .field("identity", &self.identity)
            .field("signing_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl FleetSigner {
    pub fn new(
        node_id: NodeId,
        key_sequence: u64,
        signing_key: SigningKey,
    ) -> Result<Self, FleetIdentityError> {
        validate_fleet_node_id(&node_id)?;
        validate_key_sequence(key_sequence)?;

        // `SigningKey` currently has a serde representation. Reconstructing
        // through the validating constructor prevents an all-zero key smuggled
        // through that representation from entering fleet authority.
        let signing_key = SigningKey::from_bytes(*signing_key.as_bytes())
            .map_err(FleetIdentityError::from_signature_error)?;
        let verification_key = signing_key.verification_key();
        let identity = FleetSigningIdentity {
            signer: node_id,
            key_id: FleetKeyId::from_verification_key(&verification_key),
            key_sequence,
        };
        Ok(Self {
            identity,
            signing_key,
            verification_key,
        })
    }

    pub fn identity(&self) -> &FleetSigningIdentity {
        &self.identity
    }

    pub fn verification_key(&self) -> &VerificationKey {
        &self.verification_key
    }

    fn sign_preimage(&self, preimage: &[u8]) -> Result<FleetSignatureV2, FleetIdentityError> {
        let signature = sign_preimage(&self.signing_key, preimage)
            .map_err(FleetIdentityError::from_signature_error)?;
        Ok(FleetSignatureV2 {
            signer: self.identity.signer.clone(),
            key_id: self.identity.key_id,
            key_sequence: self.identity.key_sequence,
            signature,
        })
    }

    /// Sign the additive v2 unsigned projection of a legacy message struct.
    ///
    /// Embedded v1 signature carriers are deliberately excluded. This stages
    /// canonical v2 bytes; it does not make the entire serialized legacy
    /// struct authenticated before the parent migration cuts over the wire.
    pub fn sign_detached_message_v2<T: FleetSignaturePreimageV2>(
        &self,
        message: &T,
    ) -> Result<FleetSignatureV2, FleetIdentityError> {
        message.validate_fleet_ingress_limits()?;
        message.validate_fleet_structure()?;
        message.validate_fleet_signer(&self.identity.signer)?;
        self.sign_preimage(&message.fleet_signature_preimage_v2(&self.identity)?)
    }
}

/// Lifecycle state of a key retained by the trusted fleet registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FleetVerificationKeyStatus {
    Active,
    Rotated,
    Revoked,
}

#[derive(Debug, Clone)]
struct TrustedFleetVerificationKey {
    identity: FleetSigningIdentity,
    key: VerificationKey,
    status: FleetVerificationKeyStatus,
}

/// Separately provisioned trust roots for fleet message verification.
///
/// The registry intentionally has no serde implementation. Restored protocol
/// state therefore starts with an empty registry and fails closed until an
/// operator reprovisions trusted keys. That authority must enforce durable
/// sequence floors and revocation freshness so a restart cannot roll trust
/// back to an older key.
#[derive(Debug, Default)]
pub struct FleetVerificationRegistry {
    keys: BTreeMap<(NodeId, u64), TrustedFleetVerificationKey>,
    active_sequences: BTreeMap<NodeId, u64>,
    key_owners: BTreeMap<FleetKeyId, (NodeId, u64)>,
    node_history: BTreeSet<NodeId>,
}

impl FleetVerificationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_signer(&mut self, signer: &FleetSigner) -> Result<(), FleetIdentityError> {
        self.register(
            signer.identity.signer.clone(),
            signer.identity.key_sequence,
            signer.verification_key.clone(),
        )
    }

    pub fn register(
        &mut self,
        node_id: NodeId,
        key_sequence: u64,
        verification_key: VerificationKey,
    ) -> Result<(), FleetIdentityError> {
        validate_fleet_node_id(&node_id)?;
        validate_key_sequence(key_sequence)?;
        let verification_key = revalidate_verification_key(&verification_key)?;
        let key_id = FleetKeyId::from_verification_key(&verification_key);

        if self.node_history.contains(&node_id) {
            return Err(FleetIdentityError::NodeAlreadyRegistered { node_id });
        }
        self.ensure_unbound_key(key_id, &node_id, key_sequence)?;

        let identity = FleetSigningIdentity {
            signer: node_id.clone(),
            key_id,
            key_sequence,
        };
        self.keys.insert(
            (node_id.clone(), key_sequence),
            TrustedFleetVerificationKey {
                identity,
                key: verification_key,
                status: FleetVerificationKeyStatus::Active,
            },
        );
        self.active_sequences.insert(node_id.clone(), key_sequence);
        self.node_history.insert(node_id.clone());
        self.key_owners.insert(key_id, (node_id, key_sequence));
        Ok(())
    }

    pub fn rotate(
        &mut self,
        node_id: &NodeId,
        expected_active_sequence: u64,
        new_sequence: u64,
        verification_key: VerificationKey,
    ) -> Result<(), FleetIdentityError> {
        validate_fleet_node_id(node_id)?;
        validate_key_sequence(new_sequence)?;
        let verification_key = revalidate_verification_key(&verification_key)?;
        let current_sequence = self
            .active_sequences
            .get(node_id)
            .copied()
            .ok_or_else(|| self.missing_active_key_error(node_id))?;
        if current_sequence != expected_active_sequence {
            return Err(FleetIdentityError::UnexpectedActiveSequence {
                node_id: node_id.clone(),
                expected: expected_active_sequence,
                actual: current_sequence,
            });
        }
        if new_sequence <= current_sequence {
            return Err(FleetIdentityError::SequenceRegression {
                node_id: node_id.clone(),
                existing: current_sequence,
                attempted: new_sequence,
            });
        }

        let new_key_id = FleetKeyId::from_verification_key(&verification_key);
        self.ensure_unbound_key(new_key_id, node_id, new_sequence)?;
        if self.keys.contains_key(&(node_id.clone(), new_sequence)) {
            return Err(FleetIdentityError::DuplicateKeySequence {
                node_id: node_id.clone(),
                key_sequence: new_sequence,
            });
        }

        // All fallible validation is complete before the old key is changed.
        let current = self
            .keys
            .get_mut(&(node_id.clone(), current_sequence))
            .ok_or_else(|| FleetIdentityError::UnknownKey {
                node_id: node_id.clone(),
                key_sequence: current_sequence,
            })?;
        if current.status != FleetVerificationKeyStatus::Active {
            return Err(status_error(current));
        }
        current.status = FleetVerificationKeyStatus::Rotated;

        let identity = FleetSigningIdentity {
            signer: node_id.clone(),
            key_id: new_key_id,
            key_sequence: new_sequence,
        };
        self.keys.insert(
            (node_id.clone(), new_sequence),
            TrustedFleetVerificationKey {
                identity,
                key: verification_key,
                status: FleetVerificationKeyStatus::Active,
            },
        );
        self.active_sequences.insert(node_id.clone(), new_sequence);
        self.key_owners
            .insert(new_key_id, (node_id.clone(), new_sequence));
        Ok(())
    }

    pub fn revoke(
        &mut self,
        node_id: &NodeId,
        key_sequence: u64,
    ) -> Result<(), FleetIdentityError> {
        if !self.keys.contains_key(&(node_id.clone(), key_sequence)) {
            return Err(self.missing_key_error(node_id, key_sequence));
        }
        let entry = self
            .keys
            .get_mut(&(node_id.clone(), key_sequence))
            .expect("key existence checked immediately above");
        match entry.status {
            FleetVerificationKeyStatus::Active => {
                entry.status = FleetVerificationKeyStatus::Revoked;
                if self.active_sequences.get(node_id) == Some(&key_sequence) {
                    self.active_sequences.remove(node_id);
                }
                Ok(())
            }
            FleetVerificationKeyStatus::Rotated => {
                entry.status = FleetVerificationKeyStatus::Revoked;
                Ok(())
            }
            FleetVerificationKeyStatus::Revoked => Err(FleetIdentityError::RevokedKey {
                identity: entry.identity.clone(),
            }),
        }
    }

    pub fn active_identity(
        &self,
        node_id: &NodeId,
    ) -> Result<&FleetSigningIdentity, FleetIdentityError> {
        let sequence = self
            .active_sequences
            .get(node_id)
            .copied()
            .ok_or_else(|| self.missing_active_key_error(node_id))?;
        let entry = self.resolve_entry(node_id, sequence, None)?;
        Ok(&entry.identity)
    }

    /// Verify a detached v2 signature against the currently active key.
    ///
    /// This additive migration API authenticates the v2 unsigned projection,
    /// not the serialized legacy `MessageSignature` or checkpoint signature
    /// map. It is not a complete ingress-authentication API until the parent
    /// migration replaces those v1 carriers atomically.
    pub fn verify_live_detached_message_v2<T: FleetSignaturePreimageV2>(
        &self,
        message: &T,
        signature: &FleetSignatureV2,
    ) -> Result<(), FleetIdentityError> {
        validate_ingress_limit(
            "fleet-detached-signature-v2",
            "signer",
            signature.signer.as_str().len(),
            FLEET_V2_MAX_IDENTIFIER_BYTES,
        )?;
        validate_fleet_node_id(&signature.signer)?;
        // Resolve the separately bounded signer first so unknown, rotated, or
        // revoked keys fail without traversing an attacker-controlled payload.
        // Registry lookup is bounded and read-only; canonical-tree allocation
        // and cryptographic verification remain behind the message budget.
        let entry = self.resolve_entry(
            &signature.signer,
            signature.key_sequence,
            Some(signature.key_id),
        )?;
        message.validate_fleet_ingress_limits()?;
        message.validate_fleet_structure()?;
        message.validate_fleet_signer(&signature.signer)?;
        let identity = signature.identity();
        let preimage = message.fleet_signature_preimage_v2(&identity)?;
        verify_signature(&entry.key, &preimage, &signature.signature)
            .map_err(FleetIdentityError::from_signature_error)
    }

    /// Number of nodes that currently have an active verification key.
    ///
    /// Revoked node histories remain tombstoned in the registry but are not
    /// included in this count.
    pub fn active_node_count(&self) -> usize {
        self.active_sequences.len()
    }

    fn ensure_unbound_key(
        &self,
        key_id: FleetKeyId,
        node_id: &NodeId,
        key_sequence: u64,
    ) -> Result<(), FleetIdentityError> {
        if let Some((existing_node, existing_sequence)) = self.key_owners.get(&key_id) {
            return Err(FleetIdentityError::KeyAlreadyBound {
                key_id,
                existing_node: existing_node.clone(),
                existing_sequence: *existing_sequence,
                attempted_node: node_id.clone(),
                attempted_sequence: key_sequence,
            });
        }
        Ok(())
    }

    fn resolve_entry(
        &self,
        node_id: &NodeId,
        key_sequence: u64,
        key_id: Option<FleetKeyId>,
    ) -> Result<&TrustedFleetVerificationKey, FleetIdentityError> {
        let entry = self
            .keys
            .get(&(node_id.clone(), key_sequence))
            .ok_or_else(|| self.missing_key_error(node_id, key_sequence))?;
        if key_id.is_some_and(|candidate| candidate != entry.identity.key_id) {
            return Err(FleetIdentityError::UnknownKey {
                node_id: node_id.clone(),
                key_sequence,
            });
        }
        match entry.status {
            FleetVerificationKeyStatus::Active => Ok(entry),
            FleetVerificationKeyStatus::Rotated => Err(FleetIdentityError::RotatedKey {
                identity: entry.identity.clone(),
            }),
            FleetVerificationKeyStatus::Revoked => Err(FleetIdentityError::RevokedKey {
                identity: entry.identity.clone(),
            }),
        }
    }

    fn missing_key_error(&self, node_id: &NodeId, key_sequence: u64) -> FleetIdentityError {
        if self.node_history.contains(node_id) {
            FleetIdentityError::UnknownKey {
                node_id: node_id.clone(),
                key_sequence,
            }
        } else {
            FleetIdentityError::UnknownNode {
                node_id: node_id.clone(),
            }
        }
    }

    fn missing_active_key_error(&self, node_id: &NodeId) -> FleetIdentityError {
        if self.node_history.contains(node_id) {
            FleetIdentityError::NoActiveKey {
                node_id: node_id.clone(),
            }
        } else {
            FleetIdentityError::UnknownNode {
                node_id: node_id.clone(),
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FleetIdentityError {
    InvalidNodeId {
        node_id: NodeId,
        reason: String,
    },
    InvalidKeySequence {
        key_sequence: u64,
    },
    NodeAlreadyRegistered {
        node_id: NodeId,
    },
    KeyAlreadyBound {
        key_id: FleetKeyId,
        existing_node: NodeId,
        existing_sequence: u64,
        attempted_node: NodeId,
        attempted_sequence: u64,
    },
    DuplicateKeySequence {
        node_id: NodeId,
        key_sequence: u64,
    },
    SequenceRegression {
        node_id: NodeId,
        existing: u64,
        attempted: u64,
    },
    UnexpectedActiveSequence {
        node_id: NodeId,
        expected: u64,
        actual: u64,
    },
    UnknownNode {
        node_id: NodeId,
    },
    NoActiveKey {
        node_id: NodeId,
    },
    UnknownKey {
        node_id: NodeId,
        key_sequence: u64,
    },
    RotatedKey {
        identity: FleetSigningIdentity,
    },
    RevokedKey {
        identity: FleetSigningIdentity,
    },
    SignerMismatch {
        message_type: String,
        expected: String,
        actual: NodeId,
    },
    NonCanonicalMessage {
        message_type: String,
        detail: String,
    },
    CryptographicFailure {
        detail: String,
    },
}

impl FleetIdentityError {
    fn from_signature_error(error: SignatureError) -> Self {
        Self::CryptographicFailure {
            detail: error.to_string(),
        }
    }
}

impl fmt::Display for FleetIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNodeId { node_id, reason } => {
                write!(f, "invalid fleet node id {node_id:?}: {reason}")
            }
            Self::InvalidKeySequence { key_sequence } => {
                write!(f, "fleet key sequence must be non-zero, got {key_sequence}")
            }
            Self::NodeAlreadyRegistered { node_id } => {
                write!(f, "fleet node {node_id} already has key history")
            }
            Self::KeyAlreadyBound {
                key_id,
                existing_node,
                existing_sequence,
                attempted_node,
                attempted_sequence,
            } => write!(
                f,
                "fleet key {key_id} is already bound to {existing_node}@{existing_sequence}, not {attempted_node}@{attempted_sequence}"
            ),
            Self::DuplicateKeySequence {
                node_id,
                key_sequence,
            } => write!(f, "duplicate fleet key sequence {node_id}@{key_sequence}"),
            Self::SequenceRegression {
                node_id,
                existing,
                attempted,
            } => write!(
                f,
                "fleet key sequence regression for {node_id}: existing={existing}, attempted={attempted}"
            ),
            Self::UnexpectedActiveSequence {
                node_id,
                expected,
                actual,
            } => write!(
                f,
                "unexpected active fleet key for {node_id}: expected={expected}, actual={actual}"
            ),
            Self::UnknownNode { node_id } => write!(f, "unknown fleet node {node_id}"),
            Self::NoActiveKey { node_id } => {
                write!(f, "fleet node {node_id} has no active key")
            }
            Self::UnknownKey {
                node_id,
                key_sequence,
            } => write!(f, "unknown fleet key {node_id}@{key_sequence}"),
            Self::RotatedKey { identity } => write!(
                f,
                "rotated fleet key {}@{}",
                identity.signer, identity.key_sequence
            ),
            Self::RevokedKey { identity } => write!(
                f,
                "revoked fleet key {}@{}",
                identity.signer, identity.key_sequence
            ),
            Self::SignerMismatch {
                message_type,
                expected,
                actual,
            } => write!(
                f,
                "fleet signer mismatch for {message_type}: expected {expected}, got {actual}"
            ),
            Self::NonCanonicalMessage {
                message_type,
                detail,
            } => write!(f, "non-canonical fleet {message_type}: {detail}"),
            Self::CryptographicFailure { detail } => {
                write!(f, "fleet cryptographic failure: {detail}")
            }
        }
    }
}

impl std::error::Error for FleetIdentityError {}

/// Validate a supplied raw fleet-v2 frame length before deserialization.
///
/// The atomic ingress cutover owns the actual decoder. Keeping this byte gate
/// separate lets that boundary reject `len > max` before it materializes a
/// message while the typed APIs below independently bound canonicalization.
pub fn validate_fleet_v2_frame_len(frame_len: usize) -> Result<(), FleetIdentityError> {
    validate_ingress_limit(
        "fleet-v2-frame",
        "frame_bytes",
        frame_len,
        FLEET_V2_MAX_FRAME_BYTES,
    )
}

#[derive(Debug, Default)]
struct FleetV2IngressBudget {
    dynamic_bytes: usize,
    collection_items: usize,
}

impl FleetV2IngressBudget {
    fn charge_identifier(
        &mut self,
        message_type: &str,
        field: &str,
        value: &str,
    ) -> Result<(), FleetIdentityError> {
        validate_ingress_limit(
            message_type,
            field,
            value.len(),
            FLEET_V2_MAX_IDENTIFIER_BYTES,
        )?;
        self.charge_dynamic_bytes(message_type, field, value.len())
    }

    fn charge_value(
        &mut self,
        message_type: &str,
        field: &str,
        value: &str,
    ) -> Result<(), FleetIdentityError> {
        validate_ingress_limit(message_type, field, value.len(), FLEET_V2_MAX_VALUE_BYTES)?;
        self.charge_dynamic_bytes(message_type, field, value.len())
    }

    fn charge_node_id(
        &mut self,
        message_type: &str,
        field: &str,
        node_id: &NodeId,
    ) -> Result<(), FleetIdentityError> {
        self.charge_identifier(message_type, field, node_id.as_str())
    }

    fn charge_collection(
        &mut self,
        message_type: &str,
        field: &str,
        item_count: usize,
        per_collection_limit: usize,
    ) -> Result<(), FleetIdentityError> {
        validate_ingress_limit(message_type, field, item_count, per_collection_limit)?;
        let next = self
            .collection_items
            .checked_add(item_count)
            .ok_or_else(|| {
                ingress_limit_error(
                    message_type,
                    field,
                    usize::MAX,
                    FLEET_V2_MAX_TOTAL_COLLECTION_ITEMS,
                )
            })?;
        validate_ingress_limit(
            message_type,
            "aggregate_collection_items",
            next,
            FLEET_V2_MAX_TOTAL_COLLECTION_ITEMS,
        )?;
        self.collection_items = next;
        Ok(())
    }

    fn charge_string_array(
        &mut self,
        message_type: &str,
        field: &str,
        values: &[String],
    ) -> Result<(), FleetIdentityError> {
        self.charge_collection(
            message_type,
            field,
            values.len(),
            FLEET_V2_MAX_COLLECTION_ITEMS,
        )?;
        for value in values {
            self.charge_identifier(message_type, field, value)?;
        }
        Ok(())
    }

    fn charge_string_map(
        &mut self,
        message_type: &str,
        field: &str,
        values: &BTreeMap<String, String>,
    ) -> Result<(), FleetIdentityError> {
        self.charge_collection(message_type, field, values.len(), FLEET_V2_MAX_MAP_ENTRIES)?;
        for (key, value) in values {
            self.charge_identifier(message_type, field, key)?;
            self.charge_value(message_type, field, value)?;
        }
        Ok(())
    }

    fn charge_legacy_signature(
        &mut self,
        message_type: &str,
        field: &str,
        signature: &MessageSignature,
    ) -> Result<(), FleetIdentityError> {
        self.charge_node_id(message_type, field, &signature.signer)
    }

    fn charge_dynamic_bytes(
        &mut self,
        message_type: &str,
        field: &str,
        bytes: usize,
    ) -> Result<(), FleetIdentityError> {
        let next = self.dynamic_bytes.checked_add(bytes).ok_or_else(|| {
            ingress_limit_error(message_type, field, usize::MAX, FLEET_V2_MAX_DYNAMIC_BYTES)
        })?;
        validate_ingress_limit(
            message_type,
            "aggregate_dynamic_bytes",
            next,
            FLEET_V2_MAX_DYNAMIC_BYTES,
        )?;
        self.dynamic_bytes = next;
        Ok(())
    }
}

fn validate_ingress_limit(
    message_type: &str,
    field: &str,
    actual: usize,
    limit: usize,
) -> Result<(), FleetIdentityError> {
    if actual <= limit {
        Ok(())
    } else {
        Err(ingress_limit_error(message_type, field, actual, limit))
    }
}

fn validate_ingress_limit_u64(
    message_type: &str,
    field: &str,
    actual: u64,
    limit: u64,
) -> Result<(), FleetIdentityError> {
    if actual <= limit {
        Ok(())
    } else {
        Err(ingress_limit_error_u64(message_type, field, actual, limit))
    }
}

fn ingress_limit_error(
    message_type: &str,
    field: &str,
    actual: usize,
    limit: usize,
) -> FleetIdentityError {
    FleetIdentityError::NonCanonicalMessage {
        message_type: message_type.to_string(),
        detail: format!("ingress limit exceeded for {field}: {actual} > {limit}"),
    }
}

fn ingress_limit_error_u64(
    message_type: &str,
    field: &str,
    actual: u64,
    limit: u64,
) -> FleetIdentityError {
    FleetIdentityError::NonCanonicalMessage {
        message_type: message_type.to_string(),
        detail: format!("ingress limit exceeded for {field}: {actual} > {limit}"),
    }
}

fn validate_fleet_signing_identity_ingress(
    identity: &FleetSigningIdentity,
) -> Result<(), FleetIdentityError> {
    let mut budget = FleetV2IngressBudget::default();
    budget.charge_node_id("fleet-signing-identity", "signer", &identity.signer)?;
    validate_fleet_node_id(&identity.signer)?;
    validate_key_sequence(identity.key_sequence)
}

fn validate_fleet_node_id(node_id: &NodeId) -> Result<(), FleetIdentityError> {
    let value = node_id.as_str();
    let reason = if value.is_empty() {
        Some("identity is empty")
    } else if value.len() > FLEET_V2_MAX_IDENTIFIER_BYTES {
        Some("identity exceeds 256 UTF-8 bytes")
    } else if value.trim() != value {
        Some("identity has leading or trailing whitespace")
    } else if value == "__checkpoint__" {
        Some("identity is reserved for collective checkpoint routing")
    } else {
        None
    };
    if let Some(reason) = reason {
        return Err(FleetIdentityError::InvalidNodeId {
            node_id: node_id.clone(),
            reason: reason.to_string(),
        });
    }
    Ok(())
}

fn validate_key_sequence(key_sequence: u64) -> Result<(), FleetIdentityError> {
    if key_sequence == 0 {
        Err(FleetIdentityError::InvalidKeySequence { key_sequence })
    } else {
        Ok(())
    }
}

fn revalidate_verification_key(
    verification_key: &VerificationKey,
) -> Result<VerificationKey, FleetIdentityError> {
    VerificationKey::from_bytes(*verification_key.as_bytes())
        .map_err(FleetIdentityError::from_signature_error)
}

fn status_error(entry: &TrustedFleetVerificationKey) -> FleetIdentityError {
    match entry.status {
        FleetVerificationKeyStatus::Active => unreachable!("active key has no status error"),
        FleetVerificationKeyStatus::Rotated => FleetIdentityError::RotatedKey {
            identity: entry.identity.clone(),
        },
        FleetVerificationKeyStatus::Revoked => FleetIdentityError::RevokedKey {
            identity: entry.identity.clone(),
        },
    }
}

// ---------------------------------------------------------------------------
// EvidencePacket — individual evidence atom from a single node
// ---------------------------------------------------------------------------

/// A single evidence observation from one node about one extension.
///
/// Evidence packets propagate via gossip and accumulate additively in
/// log-likelihood space across the fleet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidencePacket {
    /// Unique trace identifier for the observation.
    pub trace_id: String,
    /// Extension under observation.
    pub extension_id: String,
    /// Content hash of the evidence data.
    pub evidence_hash: ContentHash,
    /// Posterior risk delta in fixed-point millionths (log-likelihood
    /// contribution).  Positive values increase suspicion; negative
    /// values decrease it.
    pub posterior_delta_millionths: i64,
    /// Policy version under which evidence was generated.
    pub policy_version: u64,
    /// Security epoch of the observation.
    pub epoch: SecurityEpoch,
    /// Originating node.
    pub node_id: NodeId,
    /// Monotonic per-node sequence number for replay protection.
    pub sequence: u64,
    /// Timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Cryptographic signature.
    pub signature: MessageSignature,
    /// Protocol version.
    pub protocol_version: ProtocolVersion,
    /// Forward-compatible extension fields (preserved during forwarding).
    pub extensions: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// ContainmentIntent — node's proposed containment action
// ---------------------------------------------------------------------------

/// A node's recommendation for collective containment action.
///
/// Intents propagate via gossip and are resolved by deterministic
/// precedence: higher severity wins, then higher epoch, then node-id
/// tiebreaker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentIntent {
    /// Unique intent identifier.
    pub intent_id: String,
    /// Target extension.
    pub extension_id: String,
    /// Proposed containment action.
    pub proposed_action: ContainmentAction,
    /// Confidence in the recommendation (fixed-point millionths).
    pub confidence_millionths: u64,
    /// Evidence hashes supporting this intent.
    pub supporting_evidence_ids: Vec<String>,
    /// Policy version authorising the intent.
    pub policy_version: u64,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Originating node.
    pub node_id: NodeId,
    /// Monotonic per-node sequence number.
    pub sequence: u64,
    /// Timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Cryptographic signature.
    pub signature: MessageSignature,
    /// Protocol version.
    pub protocol_version: ProtocolVersion,
    /// Forward-compatible extension fields.
    pub extensions: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// QuorumCheckpoint — fleet-level consensus marker
// ---------------------------------------------------------------------------

/// Periodic aggregation of fleet evidence state.
///
/// A quorum checkpoint records participating nodes, aggregated evidence
/// summaries, and resolved containment decisions at a point in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumCheckpoint {
    /// Monotonically increasing checkpoint sequence number.
    pub checkpoint_seq: u64,
    /// Security epoch of the checkpoint.
    pub epoch: SecurityEpoch,
    /// Nodes that contributed to this checkpoint (sorted for determinism).
    pub participating_nodes: BTreeSet<NodeId>,
    /// Content hash summarising accumulated evidence across participants.
    pub evidence_summary_hash: ContentHash,
    /// Resolved containment decisions included in this checkpoint.
    pub containment_decisions: Vec<ResolvedContainmentDecision>,
    /// Quorum signatures (sorted by signer node-id for determinism).
    pub quorum_signatures: BTreeMap<NodeId, MessageSignature>,
    /// Timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Protocol version.
    pub protocol_version: ProtocolVersion,
    /// Forward-compatible extension fields.
    pub extensions: BTreeMap<String, String>,
}

/// A containment decision resolved by deterministic precedence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedContainmentDecision {
    /// Target extension.
    pub extension_id: String,
    /// Resolved action (highest severity among competing intents).
    pub resolved_action: ContainmentAction,
    /// Intent IDs that contributed to this resolution.
    pub contributing_intent_ids: Vec<String>,
    /// Epoch of the resolution.
    pub epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// HeartbeatLiveness — periodic health probe
// ---------------------------------------------------------------------------

/// Periodic liveness signal for partition detection.
///
/// Heartbeat absence beyond a configurable timeout triggers
/// degraded-mode containment on the detecting node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatLiveness {
    /// Originating node.
    pub node_id: NodeId,
    /// Current policy version on this node.
    pub policy_version: u64,
    /// Content hash of the node's evidence frontier.
    pub evidence_frontier_hash: ContentHash,
    /// Local health summary (structured key-value pairs).
    pub local_health: BTreeMap<String, String>,
    /// Current epoch.
    pub epoch: SecurityEpoch,
    /// Monotonic per-node sequence number.
    pub sequence: u64,
    /// Timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Cryptographic signature.
    pub signature: MessageSignature,
    /// Protocol version.
    pub protocol_version: ProtocolVersion,
    /// Forward-compatible extension fields.
    pub extensions: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// ReconciliationRequest — anti-entropy gap repair
// ---------------------------------------------------------------------------

/// Request for evidence gaps after partition heal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciliationRequest {
    /// Requesting node.
    pub node_id: NodeId,
    /// The node's current evidence frontier hash.
    pub known_frontier_hash: ContentHash,
    /// Requested sequence range (per originating node).
    pub requested_ranges: BTreeMap<NodeId, SequenceRange>,
    /// Current epoch.
    pub epoch: SecurityEpoch,
    /// Monotonic per-node sequence number.
    pub sequence: u64,
    /// Timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Cryptographic signature.
    pub signature: MessageSignature,
    /// Protocol version.
    pub protocol_version: ProtocolVersion,
}

/// Inclusive range of sequence numbers for reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequenceRange {
    pub start: u64,
    pub end: u64,
}

impl SequenceRange {
    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    pub fn len(&self) -> u64 {
        if self.is_empty() {
            0
        } else {
            // The inclusive full range contains 2^64 values, which cannot be
            // represented by `u64`; report the largest representable bound.
            self.end.saturating_sub(self.start).saturating_add(1)
        }
    }

    pub fn is_empty(&self) -> bool {
        self.start > self.end
    }
}

// ---------------------------------------------------------------------------
// Canonical fleet protocol v2 signature preimages
// ---------------------------------------------------------------------------

const EVIDENCE_SIGNATURE_SCHEMA_V2: &[u8] = b"FrankenEngine.FleetEvidencePacket.v2|trace_id:string|extension_id:string|evidence_hash:bytes32|posterior_delta_millionths:i64|policy_version:u64|epoch:u64|node_id:string|sequence:u64|timestamp_ns:u64|signature:{signer:string,key_id:bytes32,key_sequence:u64,signature:bytes64-sentinel}|protocol_version:{major:u64,minor:u64}|extensions:map<string,string>";
const INTENT_SIGNATURE_SCHEMA_V2: &[u8] = b"FrankenEngine.FleetContainmentIntent.v2|intent_id:string|extension_id:string|proposed_action:u64|confidence_millionths:u64|supporting_evidence_ids:array<string>|policy_version:u64|epoch:u64|node_id:string|sequence:u64|timestamp_ns:u64|signature:{signer:string,key_id:bytes32,key_sequence:u64,signature:bytes64-sentinel}|protocol_version:{major:u64,minor:u64}|extensions:map<string,string>";
const HEARTBEAT_SIGNATURE_SCHEMA_V2: &[u8] = b"FrankenEngine.FleetHeartbeatLiveness.v2|node_id:string|policy_version:u64|evidence_frontier_hash:bytes32|local_health:map<string,string>|epoch:u64|sequence:u64|timestamp_ns:u64|signature:{signer:string,key_id:bytes32,key_sequence:u64,signature:bytes64-sentinel}|protocol_version:{major:u64,minor:u64}|extensions:map<string,string>";
const RECONCILIATION_SIGNATURE_SCHEMA_V2: &[u8] = b"FrankenEngine.FleetReconciliationRequest.v2|node_id:string|known_frontier_hash:bytes32|requested_ranges:array<{node_id:string,start:u64,end:u64}>|epoch:u64|sequence:u64|timestamp_ns:u64|signature:{signer:string,key_id:bytes32,key_sequence:u64,signature:bytes64-sentinel}|protocol_version:{major:u64,minor:u64}";
const CHECKPOINT_SIGNATURE_SCHEMA_V2: &[u8] = b"FrankenEngine.FleetQuorumCheckpoint.v2|checkpoint_seq:u64|epoch:u64|participating_nodes:array<string>|evidence_summary_hash:bytes32|containment_decisions:array<{extension_id:string,resolved_action:u64,contributing_intent_ids:array<string>,epoch:u64}>|quorum_signatures:bytes64-sentinel|signature_identity:{signer:string,key_id:bytes32,key_sequence:u64,signature:bytes64-sentinel}|timestamp_ns:u64|protocol_version:{major:u64,minor:u64}|extensions:map<string,string>";

static EVIDENCE_SIGNATURE_SCHEMA_HASH_V2: LazyLock<SchemaHash> =
    LazyLock::new(|| SchemaHash::from_definition(EVIDENCE_SIGNATURE_SCHEMA_V2));
static INTENT_SIGNATURE_SCHEMA_HASH_V2: LazyLock<SchemaHash> =
    LazyLock::new(|| SchemaHash::from_definition(INTENT_SIGNATURE_SCHEMA_V2));
static HEARTBEAT_SIGNATURE_SCHEMA_HASH_V2: LazyLock<SchemaHash> =
    LazyLock::new(|| SchemaHash::from_definition(HEARTBEAT_SIGNATURE_SCHEMA_V2));
static RECONCILIATION_SIGNATURE_SCHEMA_HASH_V2: LazyLock<SchemaHash> =
    LazyLock::new(|| SchemaHash::from_definition(RECONCILIATION_SIGNATURE_SCHEMA_V2));
static CHECKPOINT_SIGNATURE_SCHEMA_HASH_V2: LazyLock<SchemaHash> =
    LazyLock::new(|| SchemaHash::from_definition(CHECKPOINT_SIGNATURE_SCHEMA_V2));

/// Canonical unsigned-view contract for the protocol-v2 fleet migration.
///
/// The existing v1 `MessageSignature` remains on the wire until the parent
/// migration atomically changes every constructor and ingress path. These
/// methods already encode the target v2 signer metadata and Ed25519 sentinel,
/// so callers can stage and verify the exact future preimage without relying
/// on the forgeable v1 field.
mod fleet_signature_preimage_v2_sealed {
    pub trait Sealed {}
}

pub trait FleetSignaturePreimageV2: fleet_signature_preimage_v2_sealed::Sealed {
    fn fleet_signature_domain(&self) -> ObjectDomain;

    fn fleet_signature_schema_v2(&self) -> &SchemaHash;

    fn fleet_unsigned_view_v2(
        &self,
        identity: &FleetSigningIdentity,
    ) -> Result<CanonicalValue, FleetIdentityError>;

    fn fleet_message_type(&self) -> &'static str;

    /// Bound every attacker-controlled dynamic field before canonical-tree allocation.
    fn validate_fleet_ingress_limits(&self) -> Result<(), FleetIdentityError>;

    fn validate_fleet_structure(&self) -> Result<(), FleetIdentityError> {
        Ok(())
    }

    fn validate_fleet_signer(&self, signer: &NodeId) -> Result<(), FleetIdentityError>;

    fn fleet_signature_preimage_v2(
        &self,
        identity: &FleetSigningIdentity,
    ) -> Result<Vec<u8>, FleetIdentityError> {
        let unsigned_view = self.fleet_unsigned_view_v2(identity)?;
        Ok(build_preimage(
            self.fleet_signature_domain(),
            self.fleet_signature_schema_v2(),
            &unsigned_view,
        ))
    }
}

impl fleet_signature_preimage_v2_sealed::Sealed for EvidencePacket {}

impl FleetSignaturePreimageV2 for EvidencePacket {
    fn fleet_signature_domain(&self) -> ObjectDomain {
        ObjectDomain::EvidenceRecord
    }

    fn fleet_signature_schema_v2(&self) -> &SchemaHash {
        &EVIDENCE_SIGNATURE_SCHEMA_HASH_V2
    }

    fn fleet_unsigned_view_v2(
        &self,
        identity: &FleetSigningIdentity,
    ) -> Result<CanonicalValue, FleetIdentityError> {
        self.validate_fleet_ingress_limits()?;
        validate_fleet_signing_identity_ingress(identity)?;
        Ok(CanonicalValue::Map(BTreeMap::from([
            (
                "epoch".to_string(),
                CanonicalValue::U64(self.epoch.as_u64()),
            ),
            (
                "evidence_hash".to_string(),
                canonical_content_hash(self.evidence_hash),
            ),
            (
                "extension_id".to_string(),
                CanonicalValue::String(self.extension_id.clone()),
            ),
            (
                "extensions".to_string(),
                canonical_string_map(&self.extensions),
            ),
            (
                "node_id".to_string(),
                CanonicalValue::String(self.node_id.as_str().to_string()),
            ),
            (
                "policy_version".to_string(),
                CanonicalValue::U64(self.policy_version),
            ),
            (
                "posterior_delta_millionths".to_string(),
                CanonicalValue::I64(self.posterior_delta_millionths),
            ),
            (
                "protocol_version".to_string(),
                canonical_protocol_version(self.protocol_version),
            ),
            ("sequence".to_string(), CanonicalValue::U64(self.sequence)),
            (
                "signature".to_string(),
                canonical_signature_identity(identity),
            ),
            (
                "timestamp_ns".to_string(),
                CanonicalValue::U64(self.timestamp_ns),
            ),
            (
                "trace_id".to_string(),
                CanonicalValue::String(self.trace_id.clone()),
            ),
        ])))
    }

    fn fleet_message_type(&self) -> &'static str {
        "evidence"
    }

    fn validate_fleet_ingress_limits(&self) -> Result<(), FleetIdentityError> {
        let message_type = self.fleet_message_type();
        let mut budget = FleetV2IngressBudget::default();
        budget.charge_identifier(message_type, "trace_id", &self.trace_id)?;
        budget.charge_identifier(message_type, "extension_id", &self.extension_id)?;
        budget.charge_node_id(message_type, "node_id", &self.node_id)?;
        budget.charge_legacy_signature(message_type, "signature.signer", &self.signature)?;
        budget.charge_string_map(message_type, "extensions", &self.extensions)
    }

    fn validate_fleet_structure(&self) -> Result<(), FleetIdentityError> {
        validate_fleet_node_id(&self.node_id)?;
        validate_protocol_v2(self.fleet_message_type(), self.protocol_version)
    }

    fn validate_fleet_signer(&self, signer: &NodeId) -> Result<(), FleetIdentityError> {
        validate_exact_message_signer(self.fleet_message_type(), &self.node_id, signer)
    }
}

impl fleet_signature_preimage_v2_sealed::Sealed for ContainmentIntent {}

impl FleetSignaturePreimageV2 for ContainmentIntent {
    fn fleet_signature_domain(&self) -> ObjectDomain {
        ObjectDomain::EvidenceRecord
    }

    fn fleet_signature_schema_v2(&self) -> &SchemaHash {
        &INTENT_SIGNATURE_SCHEMA_HASH_V2
    }

    fn fleet_unsigned_view_v2(
        &self,
        identity: &FleetSigningIdentity,
    ) -> Result<CanonicalValue, FleetIdentityError> {
        self.validate_fleet_ingress_limits()?;
        validate_fleet_signing_identity_ingress(identity)?;
        Ok(CanonicalValue::Map(BTreeMap::from([
            (
                "confidence_millionths".to_string(),
                CanonicalValue::U64(self.confidence_millionths),
            ),
            (
                "epoch".to_string(),
                CanonicalValue::U64(self.epoch.as_u64()),
            ),
            (
                "extension_id".to_string(),
                CanonicalValue::String(self.extension_id.clone()),
            ),
            (
                "extensions".to_string(),
                canonical_string_map(&self.extensions),
            ),
            (
                "intent_id".to_string(),
                CanonicalValue::String(self.intent_id.clone()),
            ),
            (
                "node_id".to_string(),
                CanonicalValue::String(self.node_id.as_str().to_string()),
            ),
            (
                "policy_version".to_string(),
                CanonicalValue::U64(self.policy_version),
            ),
            (
                "proposed_action".to_string(),
                CanonicalValue::U64(u64::from(self.proposed_action.severity())),
            ),
            (
                "protocol_version".to_string(),
                canonical_protocol_version(self.protocol_version),
            ),
            ("sequence".to_string(), CanonicalValue::U64(self.sequence)),
            (
                "signature".to_string(),
                canonical_signature_identity(identity),
            ),
            (
                "supporting_evidence_ids".to_string(),
                canonical_string_array(&self.supporting_evidence_ids),
            ),
            (
                "timestamp_ns".to_string(),
                CanonicalValue::U64(self.timestamp_ns),
            ),
        ])))
    }

    fn fleet_message_type(&self) -> &'static str {
        "containment-intent"
    }

    fn validate_fleet_ingress_limits(&self) -> Result<(), FleetIdentityError> {
        let message_type = self.fleet_message_type();
        let mut budget = FleetV2IngressBudget::default();
        budget.charge_identifier(message_type, "intent_id", &self.intent_id)?;
        budget.charge_identifier(message_type, "extension_id", &self.extension_id)?;
        budget.charge_string_array(
            message_type,
            "supporting_evidence_ids",
            &self.supporting_evidence_ids,
        )?;
        budget.charge_node_id(message_type, "node_id", &self.node_id)?;
        budget.charge_legacy_signature(message_type, "signature.signer", &self.signature)?;
        budget.charge_string_map(message_type, "extensions", &self.extensions)
    }

    fn validate_fleet_structure(&self) -> Result<(), FleetIdentityError> {
        validate_fleet_node_id(&self.node_id)?;
        validate_protocol_v2(self.fleet_message_type(), self.protocol_version)?;
        if self.confidence_millionths > 1_000_000 {
            return Err(FleetIdentityError::NonCanonicalMessage {
                message_type: self.fleet_message_type().to_string(),
                detail: "confidence_millionths exceeds 1_000_000".to_string(),
            });
        }
        validate_sorted_unique(
            self.fleet_message_type(),
            "supporting_evidence_ids",
            &self.supporting_evidence_ids,
        )
    }

    fn validate_fleet_signer(&self, signer: &NodeId) -> Result<(), FleetIdentityError> {
        validate_exact_message_signer(self.fleet_message_type(), &self.node_id, signer)
    }
}

impl fleet_signature_preimage_v2_sealed::Sealed for HeartbeatLiveness {}

impl FleetSignaturePreimageV2 for HeartbeatLiveness {
    fn fleet_signature_domain(&self) -> ObjectDomain {
        ObjectDomain::EvidenceRecord
    }

    fn fleet_signature_schema_v2(&self) -> &SchemaHash {
        &HEARTBEAT_SIGNATURE_SCHEMA_HASH_V2
    }

    fn fleet_unsigned_view_v2(
        &self,
        identity: &FleetSigningIdentity,
    ) -> Result<CanonicalValue, FleetIdentityError> {
        self.validate_fleet_ingress_limits()?;
        validate_fleet_signing_identity_ingress(identity)?;
        Ok(CanonicalValue::Map(BTreeMap::from([
            (
                "epoch".to_string(),
                CanonicalValue::U64(self.epoch.as_u64()),
            ),
            (
                "evidence_frontier_hash".to_string(),
                canonical_content_hash(self.evidence_frontier_hash),
            ),
            (
                "extensions".to_string(),
                canonical_string_map(&self.extensions),
            ),
            (
                "local_health".to_string(),
                canonical_string_map(&self.local_health),
            ),
            (
                "node_id".to_string(),
                CanonicalValue::String(self.node_id.as_str().to_string()),
            ),
            (
                "policy_version".to_string(),
                CanonicalValue::U64(self.policy_version),
            ),
            (
                "protocol_version".to_string(),
                canonical_protocol_version(self.protocol_version),
            ),
            ("sequence".to_string(), CanonicalValue::U64(self.sequence)),
            (
                "signature".to_string(),
                canonical_signature_identity(identity),
            ),
            (
                "timestamp_ns".to_string(),
                CanonicalValue::U64(self.timestamp_ns),
            ),
        ])))
    }

    fn fleet_message_type(&self) -> &'static str {
        "heartbeat"
    }

    fn validate_fleet_ingress_limits(&self) -> Result<(), FleetIdentityError> {
        let message_type = self.fleet_message_type();
        let mut budget = FleetV2IngressBudget::default();
        budget.charge_node_id(message_type, "node_id", &self.node_id)?;
        budget.charge_string_map(message_type, "local_health", &self.local_health)?;
        budget.charge_legacy_signature(message_type, "signature.signer", &self.signature)?;
        budget.charge_string_map(message_type, "extensions", &self.extensions)
    }

    fn validate_fleet_structure(&self) -> Result<(), FleetIdentityError> {
        validate_fleet_node_id(&self.node_id)?;
        validate_protocol_v2(self.fleet_message_type(), self.protocol_version)
    }

    fn validate_fleet_signer(&self, signer: &NodeId) -> Result<(), FleetIdentityError> {
        validate_exact_message_signer(self.fleet_message_type(), &self.node_id, signer)
    }
}

impl fleet_signature_preimage_v2_sealed::Sealed for ReconciliationRequest {}

impl FleetSignaturePreimageV2 for ReconciliationRequest {
    fn fleet_signature_domain(&self) -> ObjectDomain {
        ObjectDomain::EvidenceRecord
    }

    fn fleet_signature_schema_v2(&self) -> &SchemaHash {
        &RECONCILIATION_SIGNATURE_SCHEMA_HASH_V2
    }

    fn fleet_unsigned_view_v2(
        &self,
        identity: &FleetSigningIdentity,
    ) -> Result<CanonicalValue, FleetIdentityError> {
        self.validate_fleet_ingress_limits()?;
        validate_fleet_signing_identity_ingress(identity)?;
        let requested_ranges = CanonicalValue::Array(
            self.requested_ranges
                .iter()
                .map(|(node_id, range)| {
                    CanonicalValue::Map(BTreeMap::from([
                        ("end".to_string(), CanonicalValue::U64(range.end)),
                        (
                            "node_id".to_string(),
                            CanonicalValue::String(node_id.as_str().to_string()),
                        ),
                        ("start".to_string(), CanonicalValue::U64(range.start)),
                    ]))
                })
                .collect(),
        );
        Ok(CanonicalValue::Map(BTreeMap::from([
            (
                "epoch".to_string(),
                CanonicalValue::U64(self.epoch.as_u64()),
            ),
            (
                "known_frontier_hash".to_string(),
                canonical_content_hash(self.known_frontier_hash),
            ),
            (
                "node_id".to_string(),
                CanonicalValue::String(self.node_id.as_str().to_string()),
            ),
            (
                "protocol_version".to_string(),
                canonical_protocol_version(self.protocol_version),
            ),
            ("requested_ranges".to_string(), requested_ranges),
            ("sequence".to_string(), CanonicalValue::U64(self.sequence)),
            (
                "signature".to_string(),
                canonical_signature_identity(identity),
            ),
            (
                "timestamp_ns".to_string(),
                CanonicalValue::U64(self.timestamp_ns),
            ),
        ])))
    }

    fn fleet_message_type(&self) -> &'static str {
        "reconciliation-request"
    }

    fn validate_fleet_ingress_limits(&self) -> Result<(), FleetIdentityError> {
        let message_type = self.fleet_message_type();
        let mut budget = FleetV2IngressBudget::default();
        budget.charge_node_id(message_type, "node_id", &self.node_id)?;
        budget.charge_collection(
            message_type,
            "requested_ranges",
            self.requested_ranges.len(),
            FLEET_V2_MAX_COLLECTION_ITEMS,
        )?;
        let mut total_span = 0u64;
        for (requested_node, range) in &self.requested_ranges {
            budget.charge_node_id(message_type, "requested_ranges.node_id", requested_node)?;
            let span = range.len();
            validate_ingress_limit_u64(
                message_type,
                "requested_ranges.span",
                span,
                FLEET_V2_MAX_SEQUENCE_RANGE_LEN,
            )?;
            total_span = total_span.checked_add(span).ok_or_else(|| {
                ingress_limit_error_u64(
                    message_type,
                    "requested_ranges.aggregate_span",
                    u64::MAX,
                    FLEET_V2_MAX_SEQUENCE_RANGE_LEN,
                )
            })?;
            validate_ingress_limit_u64(
                message_type,
                "requested_ranges.aggregate_span",
                total_span,
                FLEET_V2_MAX_SEQUENCE_RANGE_LEN,
            )?;
        }
        budget.charge_legacy_signature(message_type, "signature.signer", &self.signature)
    }

    fn validate_fleet_structure(&self) -> Result<(), FleetIdentityError> {
        validate_fleet_node_id(&self.node_id)?;
        validate_protocol_v2(self.fleet_message_type(), self.protocol_version)?;
        for (requested_node, range) in &self.requested_ranges {
            validate_fleet_node_id(requested_node)?;
            if range.start > range.end {
                return Err(FleetIdentityError::NonCanonicalMessage {
                    message_type: self.fleet_message_type().to_string(),
                    detail: format!("empty sequence range for {requested_node}"),
                });
            }
        }
        Ok(())
    }

    fn validate_fleet_signer(&self, signer: &NodeId) -> Result<(), FleetIdentityError> {
        validate_exact_message_signer(self.fleet_message_type(), &self.node_id, signer)
    }
}

impl fleet_signature_preimage_v2_sealed::Sealed for QuorumCheckpoint {}

impl FleetSignaturePreimageV2 for QuorumCheckpoint {
    fn fleet_signature_domain(&self) -> ObjectDomain {
        ObjectDomain::CheckpointArtifact
    }

    fn fleet_signature_schema_v2(&self) -> &SchemaHash {
        &CHECKPOINT_SIGNATURE_SCHEMA_HASH_V2
    }

    fn fleet_unsigned_view_v2(
        &self,
        identity: &FleetSigningIdentity,
    ) -> Result<CanonicalValue, FleetIdentityError> {
        self.validate_fleet_ingress_limits()?;
        validate_fleet_signing_identity_ingress(identity)?;
        let decisions = CanonicalValue::Array(
            self.containment_decisions
                .iter()
                .map(canonical_containment_decision)
                .collect(),
        );
        let participating_nodes = CanonicalValue::Array(
            self.participating_nodes
                .iter()
                .map(|node_id| CanonicalValue::String(node_id.as_str().to_string()))
                .collect(),
        );
        Ok(CanonicalValue::Map(BTreeMap::from([
            (
                "checkpoint_seq".to_string(),
                CanonicalValue::U64(self.checkpoint_seq),
            ),
            ("containment_decisions".to_string(), decisions),
            (
                "epoch".to_string(),
                CanonicalValue::U64(self.epoch.as_u64()),
            ),
            (
                "evidence_summary_hash".to_string(),
                canonical_content_hash(self.evidence_summary_hash),
            ),
            (
                "extensions".to_string(),
                canonical_string_map(&self.extensions),
            ),
            ("participating_nodes".to_string(), participating_nodes),
            (
                "protocol_version".to_string(),
                canonical_protocol_version(self.protocol_version),
            ),
            (
                "quorum_signatures".to_string(),
                CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
            ),
            (
                "signature_identity".to_string(),
                canonical_signature_identity(identity),
            ),
            (
                "timestamp_ns".to_string(),
                CanonicalValue::U64(self.timestamp_ns),
            ),
        ])))
    }

    fn fleet_message_type(&self) -> &'static str {
        "quorum-checkpoint"
    }

    fn validate_fleet_ingress_limits(&self) -> Result<(), FleetIdentityError> {
        let message_type = self.fleet_message_type();
        let mut budget = FleetV2IngressBudget::default();
        budget.charge_collection(
            message_type,
            "participating_nodes",
            self.participating_nodes.len(),
            FLEET_V2_MAX_COLLECTION_ITEMS,
        )?;
        for participant in &self.participating_nodes {
            budget.charge_node_id(message_type, "participating_nodes", participant)?;
        }

        budget.charge_collection(
            message_type,
            "containment_decisions",
            self.containment_decisions.len(),
            FLEET_V2_MAX_COLLECTION_ITEMS,
        )?;
        for decision in &self.containment_decisions {
            budget.charge_identifier(
                message_type,
                "containment_decisions.extension_id",
                &decision.extension_id,
            )?;
            budget.charge_string_array(
                message_type,
                "containment_decisions.contributing_intent_ids",
                &decision.contributing_intent_ids,
            )?;
        }

        budget.charge_collection(
            message_type,
            "quorum_signatures",
            self.quorum_signatures.len(),
            FLEET_V2_MAX_MAP_ENTRIES,
        )?;
        for (node_id, signature) in &self.quorum_signatures {
            budget.charge_node_id(message_type, "quorum_signatures.node_id", node_id)?;
            budget.charge_legacy_signature(
                message_type,
                "quorum_signatures.signature.signer",
                signature,
            )?;
        }
        budget.charge_string_map(message_type, "extensions", &self.extensions)
    }

    fn validate_fleet_structure(&self) -> Result<(), FleetIdentityError> {
        validate_protocol_v2(self.fleet_message_type(), self.protocol_version)?;
        if self.participating_nodes.is_empty() {
            return Err(FleetIdentityError::NonCanonicalMessage {
                message_type: self.fleet_message_type().to_string(),
                detail: "participant set is empty".to_string(),
            });
        }
        for participant in &self.participating_nodes {
            validate_fleet_node_id(participant)?;
        }
        if !self
            .containment_decisions
            .windows(2)
            .all(|pair| pair[0].extension_id.as_str() < pair[1].extension_id.as_str())
        {
            return Err(FleetIdentityError::NonCanonicalMessage {
                message_type: self.fleet_message_type().to_string(),
                detail:
                    "containment_decisions.extension_id must be strictly sorted and duplicate-free"
                        .to_string(),
            });
        }
        for decision in &self.containment_decisions {
            if decision.epoch != self.epoch {
                return Err(FleetIdentityError::NonCanonicalMessage {
                    message_type: self.fleet_message_type().to_string(),
                    detail: format!(
                        "decision epoch {} does not match checkpoint epoch {}",
                        decision.epoch.as_u64(),
                        self.epoch.as_u64()
                    ),
                });
            }
            validate_sorted_unique(
                self.fleet_message_type(),
                "contributing_intent_ids",
                &decision.contributing_intent_ids,
            )?;
        }
        Ok(())
    }

    fn validate_fleet_signer(&self, signer: &NodeId) -> Result<(), FleetIdentityError> {
        if self.participating_nodes.contains(signer) {
            Ok(())
        } else {
            Err(FleetIdentityError::SignerMismatch {
                message_type: self.fleet_message_type().to_string(),
                expected: "a participating node".to_string(),
                actual: signer.clone(),
            })
        }
    }
}

fn canonical_content_hash(hash: ContentHash) -> CanonicalValue {
    CanonicalValue::Bytes(hash.as_bytes().to_vec())
}

fn canonical_protocol_version(version: ProtocolVersion) -> CanonicalValue {
    CanonicalValue::Map(BTreeMap::from([
        (
            "major".to_string(),
            CanonicalValue::U64(u64::from(version.major)),
        ),
        (
            "minor".to_string(),
            CanonicalValue::U64(u64::from(version.minor)),
        ),
    ]))
}

fn canonical_string_map(values: &BTreeMap<String, String>) -> CanonicalValue {
    CanonicalValue::Map(
        values
            .iter()
            .map(|(key, value)| (key.clone(), CanonicalValue::String(value.clone())))
            .collect(),
    )
}

fn canonical_string_array(values: &[String]) -> CanonicalValue {
    CanonicalValue::Array(
        values
            .iter()
            .map(|value| CanonicalValue::String(value.clone()))
            .collect(),
    )
}

fn canonical_signature_identity(identity: &FleetSigningIdentity) -> CanonicalValue {
    CanonicalValue::Map(BTreeMap::from([
        (
            "key_id".to_string(),
            CanonicalValue::Bytes(identity.key_id.as_content_hash().as_bytes().to_vec()),
        ),
        (
            "key_sequence".to_string(),
            CanonicalValue::U64(identity.key_sequence),
        ),
        (
            "signature".to_string(),
            CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
        ),
        (
            "signer".to_string(),
            CanonicalValue::String(identity.signer.as_str().to_string()),
        ),
    ]))
}

fn canonical_containment_decision(decision: &ResolvedContainmentDecision) -> CanonicalValue {
    CanonicalValue::Map(BTreeMap::from([
        (
            "contributing_intent_ids".to_string(),
            canonical_string_array(&decision.contributing_intent_ids),
        ),
        (
            "epoch".to_string(),
            CanonicalValue::U64(decision.epoch.as_u64()),
        ),
        (
            "extension_id".to_string(),
            CanonicalValue::String(decision.extension_id.clone()),
        ),
        (
            "resolved_action".to_string(),
            CanonicalValue::U64(u64::from(decision.resolved_action.severity())),
        ),
    ]))
}

fn validate_exact_message_signer(
    message_type: &str,
    expected: &NodeId,
    actual: &NodeId,
) -> Result<(), FleetIdentityError> {
    if expected == actual {
        Ok(())
    } else {
        Err(FleetIdentityError::SignerMismatch {
            message_type: message_type.to_string(),
            expected: expected.as_str().to_string(),
            actual: actual.clone(),
        })
    }
}

fn validate_sorted_unique(
    message_type: &str,
    field: &str,
    values: &[String],
) -> Result<(), FleetIdentityError> {
    if values.windows(2).all(|pair| pair[0] < pair[1]) {
        Ok(())
    } else {
        Err(FleetIdentityError::NonCanonicalMessage {
            message_type: message_type.to_string(),
            detail: format!("{field} must be strictly sorted and duplicate-free"),
        })
    }
}

fn validate_protocol_v2(
    message_type: &str,
    version: ProtocolVersion,
) -> Result<(), FleetIdentityError> {
    if version == ProtocolVersion::V2 {
        Ok(())
    } else {
        Err(FleetIdentityError::NonCanonicalMessage {
            message_type: message_type.to_string(),
            detail: format!(
                "detached v2 authentication requires protocol {}, got {version}",
                ProtocolVersion::V2
            ),
        })
    }
}

// ---------------------------------------------------------------------------
// FleetMessage — unified envelope for all protocol messages
// ---------------------------------------------------------------------------

/// Unified message envelope for fleet protocol traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FleetMessage {
    Evidence(EvidencePacket),
    Intent(ContainmentIntent),
    Checkpoint(QuorumCheckpoint),
    Heartbeat(HeartbeatLiveness),
    Reconciliation(ReconciliationRequest),
}

impl FleetMessage {
    /// Extract the originating node from any message variant.
    pub fn node_id(&self) -> &NodeId {
        match self {
            Self::Evidence(p) => &p.node_id,
            Self::Intent(i) => &i.node_id,
            Self::Checkpoint(c) => {
                // Checkpoints are collective; return the first participating
                // node (BTreeSet is sorted) as a deterministic fallback.
                static EMPTY_NODE: std::sync::LazyLock<NodeId> =
                    std::sync::LazyLock::new(|| NodeId::new("__checkpoint__"));
                c.participating_nodes.iter().next().unwrap_or(&EMPTY_NODE)
            }
            Self::Heartbeat(h) => &h.node_id,
            Self::Reconciliation(r) => &r.node_id,
        }
    }

    /// Extract the sequence number (for replay protection).
    pub fn sequence(&self) -> Option<u64> {
        match self {
            Self::Evidence(p) => Some(p.sequence),
            Self::Intent(i) => Some(i.sequence),
            Self::Checkpoint(_) => None,
            Self::Heartbeat(h) => Some(h.sequence),
            Self::Reconciliation(r) => Some(r.sequence),
        }
    }
}

// ---------------------------------------------------------------------------
// GossipConfig — configurable gossip parameters
// ---------------------------------------------------------------------------

/// Configuration for gossip dissemination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipConfig {
    /// Number of peers to forward each message to.
    pub fanout: u32,
    /// Maximum number of hops before a message is dropped.
    pub max_ttl: u32,
    /// Heartbeat interval in nanoseconds (default: 5 seconds).
    pub heartbeat_interval_ns: u64,
    /// Heartbeat absence timeout before declaring partition (nanoseconds).
    pub partition_timeout_ns: u64,
    /// Maximum bandwidth per node in bytes/second.
    pub bandwidth_ceiling_bytes_per_sec: u64,
    /// Quorum checkpoint interval in nanoseconds (default: 10 seconds).
    pub checkpoint_interval_ns: u64,
    /// Quorum threshold as fraction of healthy nodes (millionths).
    /// 500_000 = 50% = simple majority.
    pub quorum_threshold_millionths: u64,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            fanout: 3,
            max_ttl: 10,
            heartbeat_interval_ns: 5_000_000_000,       // 5s
            partition_timeout_ns: 15_000_000_000,       // 15s (3x heartbeat)
            bandwidth_ceiling_bytes_per_sec: 1_048_576, // 1 MB/s
            checkpoint_interval_ns: 10_000_000_000,     // 10s
            quorum_threshold_millionths: 500_000,       // simple majority
        }
    }
}

// ---------------------------------------------------------------------------
// DeterministicPrecedence — conflict resolution
// ---------------------------------------------------------------------------

/// Deterministic precedence resolver for conflicting containment intents.
///
/// Resolution order:
/// 1. Higher severity containment action wins.
/// 2. Higher security epoch wins (tie on severity).
/// 3. Lexicographically smaller node-id wins (tie on epoch).
///
/// This is fully deterministic and independent of message arrival order
/// or wall-clock time.
pub struct DeterministicPrecedence;

impl DeterministicPrecedence {
    /// Compare two containment intents and return the winner.
    ///
    /// Returns the intent with higher precedence.  When intents are
    /// identical in all precedence dimensions, the first argument wins
    /// (stable tiebreak).
    pub fn resolve<'a>(
        a: &'a ContainmentIntent,
        b: &'a ContainmentIntent,
    ) -> &'a ContainmentIntent {
        // 1. Higher severity wins.
        match a
            .proposed_action
            .severity()
            .cmp(&b.proposed_action.severity())
        {
            std::cmp::Ordering::Greater => return a,
            std::cmp::Ordering::Less => return b,
            std::cmp::Ordering::Equal => {}
        }

        // 2. Higher epoch wins.
        match a.epoch.as_u64().cmp(&b.epoch.as_u64()) {
            std::cmp::Ordering::Greater => return a,
            std::cmp::Ordering::Less => return b,
            std::cmp::Ordering::Equal => {}
        }

        // 3. Lexicographically smaller node-id wins (deterministic tiebreak).
        if a.node_id <= b.node_id { a } else { b }
    }

    /// Resolve a collection of intents for the same extension, returning
    /// the winning intent.  Returns `None` if the slice is empty.
    pub fn resolve_all(intents: &[ContainmentIntent]) -> Option<&ContainmentIntent> {
        intents
            .iter()
            .reduce(|winner, candidate| Self::resolve(winner, candidate))
    }
}

// ---------------------------------------------------------------------------
// NodeSequenceTracker — replay protection
// ---------------------------------------------------------------------------

/// Tracks per-node sequence numbers for replay protection.
///
/// Each node maintains a monotonically increasing sequence counter.
/// Messages with sequence numbers <= the last accepted value for that
/// node are rejected as replays.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeSequenceTracker {
    /// Last accepted sequence number per node.
    last_accepted: BTreeMap<NodeId, u64>,
}

impl NodeSequenceTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept a message's sequence number if it is strictly greater
    /// than the last accepted sequence for that node.
    ///
    /// Returns `Ok(())` if accepted, `Err` if the sequence is a replay
    /// or out-of-order.
    pub fn accept(&mut self, node_id: &NodeId, sequence: u64) -> Result<(), ProtocolError> {
        let last = self.last_accepted.get(node_id).copied().unwrap_or(0);
        if sequence <= last {
            return Err(ProtocolError::ReplayDetected {
                node_id: node_id.clone(),
                received_seq: sequence,
                last_accepted_seq: last,
            });
        }
        self.last_accepted.insert(node_id.clone(), sequence);
        Ok(())
    }

    /// Return the last accepted sequence for a node, or 0 if unseen.
    pub fn last_sequence(&self, node_id: &NodeId) -> u64 {
        self.last_accepted.get(node_id).copied().unwrap_or(0)
    }

    /// Return the set of known nodes.
    pub fn known_nodes(&self) -> BTreeSet<NodeId> {
        self.last_accepted.keys().cloned().collect()
    }
}

// ---------------------------------------------------------------------------
// EvidenceAccumulator — fleet-wide posterior aggregation
// ---------------------------------------------------------------------------

/// Accumulates evidence posterior deltas across nodes per extension.
///
/// Posterior deltas combine additively in log-likelihood space.  The
/// fleet-wide posterior for an extension is the sum of all received
/// evidence deltas (in fixed-point millionths).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvidenceAccumulator {
    /// Accumulated posterior delta per extension (millionths).
    accumulated: BTreeMap<String, i64>,
    /// Evidence count per extension.
    evidence_count: BTreeMap<String, u64>,
    /// Per-extension, per-node last-seen evidence hash for dedup.
    seen_evidence: BTreeMap<String, BTreeSet<String>>,
}

impl EvidenceAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest an evidence packet, accumulating its posterior delta.
    ///
    /// Returns `Err` if the evidence was already seen (deduplicated by
    /// `trace_id`).
    pub fn ingest(&mut self, packet: &EvidencePacket) -> Result<(), ProtocolError> {
        let ext_evidence = self
            .seen_evidence
            .entry(packet.extension_id.clone())
            .or_default();

        if !ext_evidence.insert(packet.trace_id.clone()) {
            return Err(ProtocolError::DuplicateEvidence {
                trace_id: packet.trace_id.clone(),
                extension_id: packet.extension_id.clone(),
            });
        }

        let acc = self
            .accumulated
            .entry(packet.extension_id.clone())
            .or_insert(0);
        *acc = acc.saturating_add(packet.posterior_delta_millionths);

        let count = self
            .evidence_count
            .entry(packet.extension_id.clone())
            .or_insert(0);
        *count = count.saturating_add(1);

        Ok(())
    }

    /// Return the accumulated posterior delta for an extension (millionths).
    pub fn posterior_delta(&self, extension_id: &str) -> i64 {
        self.accumulated.get(extension_id).copied().unwrap_or(0)
    }

    /// Return the number of evidence packets ingested for an extension.
    pub fn evidence_count(&self, extension_id: &str) -> u64 {
        self.evidence_count.get(extension_id).copied().unwrap_or(0)
    }

    /// Return all extension IDs with accumulated evidence.
    pub fn extensions(&self) -> BTreeSet<String> {
        self.accumulated.keys().cloned().collect()
    }

    /// Compute the evidence summary hash over all accumulated state.
    ///
    /// The hash is computed over a deterministic canonical representation:
    /// extensions are iterated in sorted order, and each entry contributes
    /// `extension_id || accumulated_delta || evidence_count`.
    pub fn summary_hash(&self) -> ContentHash {
        let mut canonical = Vec::new();
        for (ext_id, delta) in &self.accumulated {
            canonical.extend_from_slice(&(ext_id.len() as u32).to_le_bytes());
            canonical.extend_from_slice(ext_id.as_bytes());
            canonical.extend_from_slice(&delta.to_le_bytes());
            let count = self.evidence_count.get(ext_id).copied().unwrap_or(0);
            canonical.extend_from_slice(&count.to_le_bytes());
        }
        ContentHash::compute(&canonical)
    }
}

// ---------------------------------------------------------------------------
// NodeHealthTracker — partition detection
// ---------------------------------------------------------------------------

/// Tracks node liveness for partition detection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeHealthTracker {
    /// Last heartbeat timestamp per node (nanoseconds).
    last_heartbeat_ns: BTreeMap<NodeId, u64>,
    /// Last known policy version per node.
    last_policy_version: BTreeMap<NodeId, u64>,
    /// Last known evidence frontier hash per node.
    last_frontier_hash: BTreeMap<NodeId, ContentHash>,
}

impl NodeHealthTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a heartbeat from a node.
    pub fn record_heartbeat(&mut self, heartbeat: &HeartbeatLiveness) {
        self.last_heartbeat_ns
            .insert(heartbeat.node_id.clone(), heartbeat.timestamp_ns);
        self.last_policy_version
            .insert(heartbeat.node_id.clone(), heartbeat.policy_version);
        self.last_frontier_hash
            .insert(heartbeat.node_id.clone(), heartbeat.evidence_frontier_hash);
    }

    /// Return nodes that have not sent a heartbeat within the timeout.
    pub fn suspected_partitioned(&self, current_time_ns: u64, timeout_ns: u64) -> BTreeSet<NodeId> {
        let mut partitioned = BTreeSet::new();
        for (node_id, last_ns) in &self.last_heartbeat_ns {
            if current_time_ns.saturating_sub(*last_ns) > timeout_ns {
                partitioned.insert(node_id.clone());
            }
        }
        partitioned
    }

    /// Return all healthy (non-partitioned) nodes.
    pub fn healthy_nodes(&self, current_time_ns: u64, timeout_ns: u64) -> BTreeSet<NodeId> {
        let partitioned = self.suspected_partitioned(current_time_ns, timeout_ns);
        self.last_heartbeat_ns
            .keys()
            .filter(|n| !partitioned.contains(*n))
            .cloned()
            .collect()
    }

    /// Return the number of known nodes.
    pub fn known_node_count(&self) -> usize {
        self.last_heartbeat_ns.len()
    }

    /// Return the last heartbeat timestamp for a node.
    pub fn last_heartbeat_ns(&self, node_id: &NodeId) -> Option<u64> {
        self.last_heartbeat_ns.get(node_id).copied()
    }
}

// ---------------------------------------------------------------------------
// ProtocolError — protocol-level errors
// ---------------------------------------------------------------------------

/// Errors arising from fleet protocol operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolError {
    /// Message sequence number indicates replay or out-of-order delivery.
    ReplayDetected {
        node_id: NodeId,
        received_seq: u64,
        last_accepted_seq: u64,
    },
    /// Evidence with this trace_id was already ingested for this extension.
    DuplicateEvidence {
        trace_id: String,
        extension_id: String,
    },
    /// Two pending intents for one extension reused the same intent ID.
    DuplicateIntentId {
        intent_id: String,
        extension_id: String,
    },
    /// Protocol version mismatch.
    IncompatibleVersion {
        local: ProtocolVersion,
        remote: ProtocolVersion,
    },
    /// Signature verification failed.
    InvalidSignature {
        node_id: NodeId,
        message_type: String,
    },
    /// Quorum was not reached (insufficient participating nodes).
    QuorumNotReached { required: usize, actual: usize },
    /// Message from a node suspected of being partitioned.
    PartitionedNode { node_id: NodeId },
    /// Empty intents list in precedence resolution.
    EmptyIntents,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReplayDetected {
                node_id,
                received_seq,
                last_accepted_seq,
            } => write!(
                f,
                "replay detected from {node_id}: seq {received_seq} <= last accepted {last_accepted_seq}"
            ),
            Self::DuplicateEvidence {
                trace_id,
                extension_id,
            } => write!(
                f,
                "duplicate evidence {trace_id} for extension {extension_id}"
            ),
            Self::DuplicateIntentId {
                intent_id,
                extension_id,
            } => write!(
                f,
                "duplicate intent ID {intent_id} for extension {extension_id}"
            ),
            Self::IncompatibleVersion { local, remote } => {
                write!(
                    f,
                    "incompatible protocol version: local={local}, remote={remote}"
                )
            }
            Self::InvalidSignature {
                node_id,
                message_type,
            } => write!(f, "invalid signature from {node_id} on {message_type}"),
            Self::QuorumNotReached { required, actual } => {
                write!(f, "quorum not reached: need {required}, have {actual}")
            }
            Self::PartitionedNode { node_id } => {
                write!(f, "message from partitioned node {node_id}")
            }
            Self::EmptyIntents => write!(f, "no intents to resolve"),
        }
    }
}

impl std::error::Error for ProtocolError {}

// ---------------------------------------------------------------------------
// FleetProtocolState — aggregate protocol state
// ---------------------------------------------------------------------------

/// Aggregate state for a node's view of the fleet protocol.
///
/// Combines sequence tracking, evidence accumulation, health monitoring,
/// and containment intent resolution into a single coherent state machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetProtocolState {
    /// This node's identity.
    pub local_node_id: NodeId,
    /// Gossip configuration.
    pub config: GossipConfig,
    /// Current protocol version.
    pub protocol_version: ProtocolVersion,
    /// Current security epoch.
    pub current_epoch: SecurityEpoch,
    /// Replay protection tracker.
    pub sequence_tracker: NodeSequenceTracker,
    /// Evidence accumulator.
    pub evidence: EvidenceAccumulator,
    /// Node health tracker.
    pub health: NodeHealthTracker,
    /// Pending containment intents (per extension, all received).
    pub pending_intents: BTreeMap<String, Vec<ContainmentIntent>>,
    /// Last checkpoint sequence number.
    pub last_checkpoint_seq: u64,
    /// Local monotonic sequence counter for outgoing messages.
    pub local_sequence: u64,
}

impl FleetProtocolState {
    /// Create a new fleet protocol state for the given node.
    pub fn new(node_id: NodeId, config: GossipConfig) -> Self {
        Self {
            local_node_id: node_id,
            config,
            protocol_version: ProtocolVersion::CURRENT,
            current_epoch: SecurityEpoch::GENESIS,
            sequence_tracker: NodeSequenceTracker::new(),
            evidence: EvidenceAccumulator::new(),
            health: NodeHealthTracker::new(),
            pending_intents: BTreeMap::new(),
            last_checkpoint_seq: 0,
            local_sequence: 0,
        }
    }

    /// Advance the local sequence counter and return the new value.
    pub fn next_sequence(&mut self) -> u64 {
        self.local_sequence = self.local_sequence.saturating_add(1);
        self.local_sequence
    }

    /// Process an incoming evidence packet.
    ///
    /// Validates replay protection and accumulates the evidence delta.
    pub fn process_evidence(&mut self, packet: &EvidencePacket) -> Result<(), ProtocolError> {
        // Version check.
        if !self
            .protocol_version
            .is_compatible_with(&packet.protocol_version)
        {
            return Err(ProtocolError::IncompatibleVersion {
                local: self.protocol_version,
                remote: packet.protocol_version,
            });
        }

        // Replay protection.
        self.sequence_tracker
            .accept(&packet.node_id, packet.sequence)?;

        // Accumulate evidence.
        self.evidence.ingest(packet)?;

        Ok(())
    }

    /// Process an incoming containment intent.
    ///
    /// Validates replay protection and adds to pending intents.
    pub fn process_intent(&mut self, intent: &ContainmentIntent) -> Result<(), ProtocolError> {
        // Version check.
        if !self
            .protocol_version
            .is_compatible_with(&intent.protocol_version)
        {
            return Err(ProtocolError::IncompatibleVersion {
                local: self.protocol_version,
                remote: intent.protocol_version,
            });
        }

        // Replay protection.
        self.sequence_tracker
            .accept(&intent.node_id, intent.sequence)?;

        // Store the intent.
        self.pending_intents
            .entry(intent.extension_id.clone())
            .or_default()
            .push(intent.clone());

        Ok(())
    }

    /// Process an incoming heartbeat.
    pub fn process_heartbeat(
        &mut self,
        heartbeat: &HeartbeatLiveness,
    ) -> Result<(), ProtocolError> {
        // Version check.
        if !self
            .protocol_version
            .is_compatible_with(&heartbeat.protocol_version)
        {
            return Err(ProtocolError::IncompatibleVersion {
                local: self.protocol_version,
                remote: heartbeat.protocol_version,
            });
        }

        // Replay protection.
        self.sequence_tracker
            .accept(&heartbeat.node_id, heartbeat.sequence)?;

        // Update health.
        self.health.record_heartbeat(heartbeat);

        Ok(())
    }

    /// Resolve all pending intents for a given extension using
    /// deterministic precedence.
    pub fn resolve_intents(&self, extension_id: &str) -> Option<&ContainmentIntent> {
        self.pending_intents
            .get(extension_id)
            .and_then(|intents| DeterministicPrecedence::resolve_all(intents))
    }

    /// Build a quorum checkpoint from current state.
    ///
    /// Returns `Err` if insufficient healthy nodes for quorum or if a v2
    /// checkpoint would contain colliding intent IDs.
    pub fn build_checkpoint(
        &mut self,
        current_time_ns: u64,
        local_signature: MessageSignature,
    ) -> Result<QuorumCheckpoint, ProtocolError> {
        let healthy = self
            .health
            .healthy_nodes(current_time_ns, self.config.partition_timeout_ns);

        let total_known = self.health.known_node_count();
        let required = if total_known == 0 {
            1
        } else {
            // quorum_threshold_millionths / 1_000_000 * total_known, rounded up.
            let threshold = self.config.quorum_threshold_millionths;
            (threshold as u128 * total_known as u128).div_ceil(1_000_000) as usize
        };

        if healthy.len() < required {
            return Err(ProtocolError::QuorumNotReached {
                required,
                actual: healthy.len(),
            });
        }

        // Resolve containment decisions for all extensions with pending intents.
        let mut decisions = Vec::new();
        for (ext_id, intents) in &self.pending_intents {
            if let Some(winner) = DeterministicPrecedence::resolve_all(intents) {
                let mut contributing_intent_ids = intents
                    .iter()
                    .map(|intent| intent.intent_id.clone())
                    .collect::<Vec<_>>();
                if self.protocol_version == ProtocolVersion::V2 {
                    contributing_intent_ids.sort();
                    if let Some(duplicate) = contributing_intent_ids
                        .windows(2)
                        .find(|pair| pair[0] == pair[1])
                    {
                        return Err(ProtocolError::DuplicateIntentId {
                            intent_id: duplicate[0].clone(),
                            extension_id: ext_id.clone(),
                        });
                    }
                }
                decisions.push(ResolvedContainmentDecision {
                    extension_id: ext_id.clone(),
                    resolved_action: winner.proposed_action,
                    contributing_intent_ids,
                    epoch: self.current_epoch,
                });
            }
        }

        // All fallible V2 canonicalization is complete before protocol state
        // advances or pending inputs are consumed.
        self.last_checkpoint_seq = self.last_checkpoint_seq.saturating_add(1);

        let mut quorum_sigs = BTreeMap::new();
        quorum_sigs.insert(self.local_node_id.clone(), local_signature);

        // Clear resolved pending intents to prevent duplicate containment
        // decisions in subsequent checkpoints.
        self.pending_intents.clear();

        Ok(QuorumCheckpoint {
            checkpoint_seq: self.last_checkpoint_seq,
            epoch: self.current_epoch,
            participating_nodes: healthy,
            evidence_summary_hash: self.evidence.summary_hash(),
            containment_decisions: decisions,
            quorum_signatures: quorum_sigs,
            timestamp_ns: current_time_ns,
            protocol_version: self.protocol_version,
            extensions: BTreeMap::new(),
        })
    }

    /// Return currently suspected-partitioned nodes.
    pub fn partitioned_nodes(&self, current_time_ns: u64) -> BTreeSet<NodeId> {
        self.health
            .suspected_partitioned(current_time_ns, self.config.partition_timeout_ns)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helpers --

    fn test_signature(node: &str) -> MessageSignature {
        MessageSignature {
            signer: NodeId::new(node),
            hash: AuthenticityHash::compute_keyed(node.as_bytes(), b"test-message"),
        }
    }

    fn test_evidence(node: &str, ext: &str, seq: u64, delta: i64) -> EvidencePacket {
        EvidencePacket {
            trace_id: format!("trace-{node}-{ext}-{seq}"),
            extension_id: ext.to_string(),
            evidence_hash: ContentHash::compute(format!("evidence-{node}-{ext}-{seq}").as_bytes()),
            posterior_delta_millionths: delta,
            policy_version: 1,
            epoch: SecurityEpoch::from_raw(1),
            node_id: NodeId::new(node),
            sequence: seq,
            timestamp_ns: 1_000_000_000 * seq,
            signature: test_signature(node),
            protocol_version: ProtocolVersion::CURRENT,
            extensions: BTreeMap::new(),
        }
    }

    fn test_intent(
        node: &str,
        ext: &str,
        action: ContainmentAction,
        seq: u64,
        epoch: u64,
    ) -> ContainmentIntent {
        ContainmentIntent {
            intent_id: format!("intent-{node}-{ext}-{seq}"),
            extension_id: ext.to_string(),
            proposed_action: action,
            confidence_millionths: 900_000,
            supporting_evidence_ids: vec![format!("trace-{node}-{ext}-1")],
            policy_version: 1,
            epoch: SecurityEpoch::from_raw(epoch),
            node_id: NodeId::new(node),
            sequence: seq,
            timestamp_ns: 1_000_000_000 * seq,
            signature: test_signature(node),
            protocol_version: ProtocolVersion::CURRENT,
            extensions: BTreeMap::new(),
        }
    }

    fn test_heartbeat(node: &str, seq: u64, ts_ns: u64) -> HeartbeatLiveness {
        HeartbeatLiveness {
            node_id: NodeId::new(node),
            policy_version: 1,
            evidence_frontier_hash: ContentHash::compute(
                format!("frontier-{node}-{seq}").as_bytes(),
            ),
            local_health: BTreeMap::new(),
            epoch: SecurityEpoch::from_raw(1),
            sequence: seq,
            timestamp_ns: ts_ns,
            signature: test_signature(node),
            protocol_version: ProtocolVersion::CURRENT,
            extensions: BTreeMap::new(),
        }
    }

    // -- ContainmentAction tests --

    #[test]
    fn containment_action_severity_ordering() {
        assert!(ContainmentAction::Allow.severity() < ContainmentAction::Sandbox.severity());
        assert!(ContainmentAction::Sandbox.severity() < ContainmentAction::Suspend.severity());
        assert!(ContainmentAction::Suspend.severity() < ContainmentAction::Terminate.severity());
        assert!(ContainmentAction::Terminate.severity() < ContainmentAction::Quarantine.severity());
    }

    #[test]
    fn containment_action_at_least_as_severe() {
        assert!(ContainmentAction::Quarantine.at_least_as_severe_as(ContainmentAction::Allow));
        assert!(ContainmentAction::Suspend.at_least_as_severe_as(ContainmentAction::Suspend));
        assert!(!ContainmentAction::Allow.at_least_as_severe_as(ContainmentAction::Sandbox));
    }

    #[test]
    fn containment_action_display() {
        assert_eq!(ContainmentAction::Allow.to_string(), "allow");
        assert_eq!(ContainmentAction::Quarantine.to_string(), "quarantine");
    }

    // -- ProtocolVersion tests --

    #[test]
    fn protocol_version_compatibility() {
        let v1_0 = ProtocolVersion { major: 1, minor: 0 };
        let v1_1 = ProtocolVersion { major: 1, minor: 1 };
        let v2_0 = ProtocolVersion { major: 2, minor: 0 };

        assert!(v1_0.is_compatible_with(&v1_0));
        assert!(v1_1.is_compatible_with(&v1_0)); // reader minor >= writer minor
        assert!(!v1_0.is_compatible_with(&v1_1)); // reader minor < writer minor
        assert!(!v1_0.is_compatible_with(&v2_0)); // different major
    }

    #[test]
    fn protocol_version_display() {
        assert_eq!(ProtocolVersion::CURRENT.to_string(), "1.0");
    }

    // -- SequenceRange tests --

    #[test]
    fn sequence_range_length() {
        assert_eq!(SequenceRange::new(1, 5).len(), 5);
        assert_eq!(SequenceRange::new(3, 3).len(), 1);
        assert_eq!(SequenceRange::new(5, 3).len(), 0); // inverted
    }

    #[test]
    fn sequence_range_empty() {
        assert!(!SequenceRange::new(1, 5).is_empty());
        assert!(SequenceRange::new(5, 3).is_empty());
    }

    // -- NodeSequenceTracker tests --

    #[test]
    fn sequence_tracker_accepts_monotonic() {
        let mut tracker = NodeSequenceTracker::new();
        let node = NodeId::new("node-1");

        assert!(tracker.accept(&node, 1).is_ok());
        assert!(tracker.accept(&node, 2).is_ok());
        assert!(tracker.accept(&node, 5).is_ok()); // gaps allowed
        assert_eq!(tracker.last_sequence(&node), 5);
    }

    #[test]
    fn sequence_tracker_rejects_replay() {
        let mut tracker = NodeSequenceTracker::new();
        let node = NodeId::new("node-1");

        tracker.accept(&node, 3).unwrap();
        let err = tracker.accept(&node, 2).unwrap_err();
        assert!(matches!(err, ProtocolError::ReplayDetected { .. }));
    }

    #[test]
    fn sequence_tracker_rejects_duplicate() {
        let mut tracker = NodeSequenceTracker::new();
        let node = NodeId::new("node-1");

        tracker.accept(&node, 1).unwrap();
        let err = tracker.accept(&node, 1).unwrap_err();
        assert!(matches!(err, ProtocolError::ReplayDetected { .. }));
    }

    #[test]
    fn sequence_tracker_independent_per_node() {
        let mut tracker = NodeSequenceTracker::new();
        let a = NodeId::new("node-a");
        let b = NodeId::new("node-b");

        tracker.accept(&a, 5).unwrap();
        tracker.accept(&b, 1).unwrap(); // independent
        assert_eq!(tracker.last_sequence(&a), 5);
        assert_eq!(tracker.last_sequence(&b), 1);
    }

    #[test]
    fn sequence_tracker_known_nodes() {
        let mut tracker = NodeSequenceTracker::new();
        tracker.accept(&NodeId::new("a"), 1).unwrap();
        tracker.accept(&NodeId::new("b"), 1).unwrap();
        let nodes = tracker.known_nodes();
        assert_eq!(nodes.len(), 2);
        assert!(nodes.contains(&NodeId::new("a")));
        assert!(nodes.contains(&NodeId::new("b")));
    }

    // -- DeterministicPrecedence tests --

    #[test]
    fn precedence_higher_severity_wins() {
        let sandbox = test_intent("node-a", "ext-1", ContainmentAction::Sandbox, 1, 1);
        let terminate = test_intent("node-b", "ext-1", ContainmentAction::Terminate, 1, 1);

        let winner = DeterministicPrecedence::resolve(&sandbox, &terminate);
        assert_eq!(winner.proposed_action, ContainmentAction::Terminate);
    }

    #[test]
    fn precedence_higher_epoch_wins_on_tie() {
        let old = test_intent("node-a", "ext-1", ContainmentAction::Suspend, 1, 1);
        let new = test_intent("node-b", "ext-1", ContainmentAction::Suspend, 1, 2);

        let winner = DeterministicPrecedence::resolve(&old, &new);
        assert_eq!(winner.epoch, SecurityEpoch::from_raw(2));
    }

    #[test]
    fn precedence_smaller_node_id_wins_on_full_tie() {
        let a = test_intent("node-a", "ext-1", ContainmentAction::Suspend, 1, 1);
        let b = test_intent("node-b", "ext-1", ContainmentAction::Suspend, 1, 1);

        let winner = DeterministicPrecedence::resolve(&a, &b);
        assert_eq!(winner.node_id, NodeId::new("node-a"));
    }

    #[test]
    fn precedence_resolve_all_empty() {
        let result = DeterministicPrecedence::resolve_all(&[]);
        assert!(result.is_none());
    }

    #[test]
    fn precedence_resolve_all_multiple() {
        let intents = vec![
            test_intent("node-a", "ext-1", ContainmentAction::Sandbox, 1, 1),
            test_intent("node-b", "ext-1", ContainmentAction::Quarantine, 1, 1),
            test_intent("node-c", "ext-1", ContainmentAction::Suspend, 1, 1),
        ];

        let winner = DeterministicPrecedence::resolve_all(&intents).unwrap();
        assert_eq!(winner.proposed_action, ContainmentAction::Quarantine);
    }

    #[test]
    fn precedence_deterministic_regardless_of_order() {
        let a = test_intent("node-a", "ext-1", ContainmentAction::Suspend, 1, 1);
        let b = test_intent("node-b", "ext-1", ContainmentAction::Suspend, 1, 1);

        let ab = DeterministicPrecedence::resolve(&a, &b);
        let ba = DeterministicPrecedence::resolve(&b, &a);
        assert_eq!(ab.node_id, ba.node_id);
    }

    // -- EvidenceAccumulator tests --

    #[test]
    fn accumulator_ingests_evidence() {
        let mut acc = EvidenceAccumulator::new();
        let packet = test_evidence("node-1", "ext-1", 1, 500_000);

        acc.ingest(&packet).unwrap();
        assert_eq!(acc.posterior_delta("ext-1"), 500_000);
        assert_eq!(acc.evidence_count("ext-1"), 1);
    }

    #[test]
    fn accumulator_additive_deltas() {
        let mut acc = EvidenceAccumulator::new();

        acc.ingest(&test_evidence("node-1", "ext-1", 1, 300_000))
            .unwrap();
        acc.ingest(&test_evidence("node-2", "ext-1", 1, 200_000))
            .unwrap();

        assert_eq!(acc.posterior_delta("ext-1"), 500_000);
        assert_eq!(acc.evidence_count("ext-1"), 2);
    }

    #[test]
    fn accumulator_negative_deltas() {
        let mut acc = EvidenceAccumulator::new();

        acc.ingest(&test_evidence("node-1", "ext-1", 1, 500_000))
            .unwrap();
        acc.ingest(&test_evidence("node-2", "ext-1", 1, -200_000))
            .unwrap();

        assert_eq!(acc.posterior_delta("ext-1"), 300_000);
    }

    #[test]
    fn accumulator_deduplicates_by_trace_id() {
        let mut acc = EvidenceAccumulator::new();
        let packet = test_evidence("node-1", "ext-1", 1, 500_000);

        acc.ingest(&packet).unwrap();
        let err = acc.ingest(&packet).unwrap_err();
        assert!(matches!(err, ProtocolError::DuplicateEvidence { .. }));
        assert_eq!(acc.posterior_delta("ext-1"), 500_000); // not doubled
    }

    #[test]
    fn accumulator_per_extension_isolation() {
        let mut acc = EvidenceAccumulator::new();

        acc.ingest(&test_evidence("node-1", "ext-1", 1, 300_000))
            .unwrap();
        acc.ingest(&test_evidence("node-1", "ext-2", 2, 700_000))
            .unwrap();

        assert_eq!(acc.posterior_delta("ext-1"), 300_000);
        assert_eq!(acc.posterior_delta("ext-2"), 700_000);
    }

    #[test]
    fn accumulator_summary_hash_deterministic() {
        let mut acc1 = EvidenceAccumulator::new();
        let mut acc2 = EvidenceAccumulator::new();

        // Same evidence in same order.
        for acc in [&mut acc1, &mut acc2] {
            acc.ingest(&test_evidence("node-1", "ext-1", 1, 300_000))
                .unwrap();
            acc.ingest(&test_evidence("node-2", "ext-1", 1, 200_000))
                .unwrap();
        }

        assert_eq!(acc1.summary_hash(), acc2.summary_hash());
    }

    #[test]
    fn accumulator_extensions_returns_all() {
        let mut acc = EvidenceAccumulator::new();
        acc.ingest(&test_evidence("node-1", "ext-a", 1, 100))
            .unwrap();
        acc.ingest(&test_evidence("node-1", "ext-b", 2, 200))
            .unwrap();

        let exts = acc.extensions();
        assert!(exts.contains("ext-a"));
        assert!(exts.contains("ext-b"));
        assert_eq!(exts.len(), 2);
    }

    #[test]
    fn accumulator_unknown_extension_zero() {
        let acc = EvidenceAccumulator::new();
        assert_eq!(acc.posterior_delta("nonexistent"), 0);
        assert_eq!(acc.evidence_count("nonexistent"), 0);
    }

    // -- NodeHealthTracker tests --

    #[test]
    fn health_tracker_records_heartbeat() {
        let mut tracker = NodeHealthTracker::new();
        let hb = test_heartbeat("node-1", 1, 5_000_000_000);

        tracker.record_heartbeat(&hb);
        assert_eq!(
            tracker.last_heartbeat_ns(&NodeId::new("node-1")),
            Some(5_000_000_000)
        );
        assert_eq!(tracker.known_node_count(), 1);
    }

    #[test]
    fn health_tracker_partition_detection() {
        let mut tracker = NodeHealthTracker::new();
        tracker.record_heartbeat(&test_heartbeat("node-1", 1, 1_000_000_000));
        tracker.record_heartbeat(&test_heartbeat("node-2", 1, 1_000_000_000));

        // At time 20s, with 15s timeout, both are partitioned.
        let partitioned = tracker.suspected_partitioned(20_000_000_000, 15_000_000_000);
        assert_eq!(partitioned.len(), 2);

        // At time 10s, with 15s timeout, neither is partitioned.
        let partitioned = tracker.suspected_partitioned(10_000_000_000, 15_000_000_000);
        assert!(partitioned.is_empty());
    }

    #[test]
    fn health_tracker_healthy_nodes() {
        let mut tracker = NodeHealthTracker::new();
        tracker.record_heartbeat(&test_heartbeat("node-1", 1, 10_000_000_000));
        tracker.record_heartbeat(&test_heartbeat("node-2", 1, 1_000_000_000));

        // At time 12s, with 5s timeout: node-1 healthy, node-2 partitioned.
        let healthy = tracker.healthy_nodes(12_000_000_000, 5_000_000_000);
        assert!(healthy.contains(&NodeId::new("node-1")));
        assert!(!healthy.contains(&NodeId::new("node-2")));
    }

    // -- FleetProtocolState tests --

    #[test]
    fn state_process_evidence_success() {
        let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
        let packet = test_evidence("remote-1", "ext-1", 1, 500_000);

        state.process_evidence(&packet).unwrap();
        assert_eq!(state.evidence.posterior_delta("ext-1"), 500_000);
    }

    #[test]
    fn state_process_evidence_replay_rejected() {
        let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());

        let p1 = test_evidence("remote-1", "ext-1", 1, 500_000);
        state.process_evidence(&p1).unwrap();

        // Same node, lower sequence → replay.
        let p2 = test_evidence("remote-1", "ext-2", 1, 100_000);
        let err = state.process_evidence(&p2).unwrap_err();
        assert!(matches!(err, ProtocolError::ReplayDetected { .. }));
    }

    #[test]
    fn state_process_intent_success() {
        let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
        let intent = test_intent("remote-1", "ext-1", ContainmentAction::Sandbox, 1, 1);

        state.process_intent(&intent).unwrap();
        assert_eq!(state.pending_intents.len(), 1);
    }

    #[test]
    fn state_resolve_intents() {
        let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());

        state
            .process_intent(&test_intent(
                "node-a",
                "ext-1",
                ContainmentAction::Sandbox,
                1,
                1,
            ))
            .unwrap();
        state
            .process_intent(&test_intent(
                "node-b",
                "ext-1",
                ContainmentAction::Terminate,
                1,
                1,
            ))
            .unwrap();

        let winner = state.resolve_intents("ext-1").unwrap();
        assert_eq!(winner.proposed_action, ContainmentAction::Terminate);
    }

    #[test]
    fn state_process_heartbeat() {
        let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
        let hb = test_heartbeat("remote-1", 1, 5_000_000_000);

        state.process_heartbeat(&hb).unwrap();
        assert_eq!(state.health.known_node_count(), 1);
    }

    #[test]
    fn state_incompatible_version_rejected() {
        let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());

        let mut packet = test_evidence("remote-1", "ext-1", 1, 500_000);
        packet.protocol_version = ProtocolVersion { major: 2, minor: 0 };

        let err = state.process_evidence(&packet).unwrap_err();
        assert!(matches!(err, ProtocolError::IncompatibleVersion { .. }));
    }

    #[test]
    fn state_next_sequence_monotonic() {
        let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());

        let s1 = state.next_sequence();
        let s2 = state.next_sequence();
        let s3 = state.next_sequence();
        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
        assert_eq!(s3, 3);
    }

    #[test]
    fn state_partitioned_nodes() {
        let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());

        state
            .process_heartbeat(&test_heartbeat("node-1", 1, 1_000_000_000))
            .unwrap();

        // At time 20s with default 15s timeout → node-1 partitioned.
        let partitioned = state.partitioned_nodes(20_000_000_000);
        assert!(partitioned.contains(&NodeId::new("node-1")));
    }

    // -- Serialization round-trip tests --

    #[test]
    fn evidence_packet_serde_round_trip() {
        let packet = test_evidence("node-1", "ext-1", 1, 500_000);
        let json = serde_json::to_string(&packet).unwrap();
        let decoded: EvidencePacket = serde_json::from_str(&json).unwrap();
        assert_eq!(packet, decoded);
    }

    #[test]
    fn containment_intent_serde_round_trip() {
        let intent = test_intent("node-1", "ext-1", ContainmentAction::Quarantine, 1, 1);
        let json = serde_json::to_string(&intent).unwrap();
        let decoded: ContainmentIntent = serde_json::from_str(&json).unwrap();
        assert_eq!(intent, decoded);
    }

    #[test]
    fn gossip_config_default_values() {
        let config = GossipConfig::default();
        assert_eq!(config.fanout, 3);
        assert_eq!(config.max_ttl, 10);
        assert_eq!(config.bandwidth_ceiling_bytes_per_sec, 1_048_576);
        assert_eq!(config.quorum_threshold_millionths, 500_000);
    }

    #[test]
    fn gossip_config_serde_round_trip() {
        let config = GossipConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let decoded: GossipConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, decoded);
    }

    #[test]
    fn fleet_message_envelope_evidence() {
        let packet = test_evidence("node-1", "ext-1", 1, 500_000);
        let msg = FleetMessage::Evidence(packet.clone());

        assert_eq!(msg.node_id(), &NodeId::new("node-1"));
        assert_eq!(msg.sequence(), Some(1));

        let json = serde_json::to_string(&msg).unwrap();
        let decoded: FleetMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn fleet_message_envelope_intent() {
        let intent = test_intent("node-1", "ext-1", ContainmentAction::Suspend, 1, 1);
        let msg = FleetMessage::Intent(intent);

        assert_eq!(msg.node_id(), &NodeId::new("node-1"));
        assert_eq!(msg.sequence(), Some(1));
    }

    #[test]
    fn fleet_message_envelope_heartbeat() {
        let hb = test_heartbeat("node-1", 1, 5_000_000_000);
        let msg = FleetMessage::Heartbeat(hb);

        assert_eq!(msg.node_id(), &NodeId::new("node-1"));
        assert_eq!(msg.sequence(), Some(1));
    }

    #[test]
    fn resolved_decision_serde_round_trip() {
        let decision = ResolvedContainmentDecision {
            extension_id: "ext-1".into(),
            resolved_action: ContainmentAction::Terminate,
            contributing_intent_ids: vec!["intent-1".into(), "intent-2".into()],
            epoch: SecurityEpoch::from_raw(3),
        };
        let json = serde_json::to_string(&decision).unwrap();
        let decoded: ResolvedContainmentDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, decoded);
    }

    #[test]
    fn protocol_error_display() {
        let err = ProtocolError::ReplayDetected {
            node_id: NodeId::new("node-1"),
            received_seq: 3,
            last_accepted_seq: 5,
        };
        let msg = err.to_string();
        assert!(msg.contains("replay detected"));
        assert!(msg.contains("node-1"));
    }

    #[test]
    fn protocol_error_serde_round_trip() {
        let err = ProtocolError::QuorumNotReached {
            required: 3,
            actual: 1,
        };
        let json = serde_json::to_string(&err).unwrap();
        let decoded: ProtocolError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, decoded);
    }

    #[test]
    fn state_serde_round_trip() {
        let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
        state
            .process_evidence(&test_evidence("remote-1", "ext-1", 1, 500_000))
            .unwrap();
        state
            .process_heartbeat(&test_heartbeat("remote-2", 1, 5_000_000_000))
            .unwrap();

        let json = serde_json::to_string(&state).unwrap();
        let decoded: FleetProtocolState = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.evidence.posterior_delta("ext-1"), 500_000);
    }

    #[test]
    fn deterministic_serialization_evidence_accumulator() {
        let mut acc1 = EvidenceAccumulator::new();
        let mut acc2 = EvidenceAccumulator::new();

        // Ingest same evidence in same order.
        for acc in [&mut acc1, &mut acc2] {
            acc.ingest(&test_evidence("node-1", "ext-b", 1, 100))
                .unwrap();
            acc.ingest(&test_evidence("node-1", "ext-a", 2, 200))
                .unwrap();
        }

        let json1 = serde_json::to_string(&acc1).unwrap();
        let json2 = serde_json::to_string(&acc2).unwrap();
        assert_eq!(json1, json2);
    }

    #[test]
    fn accumulator_saturating_add_no_overflow() {
        let mut acc = EvidenceAccumulator::new();
        acc.ingest(&test_evidence("node-1", "ext-1", 1, i64::MAX))
            .unwrap();
        acc.ingest(&test_evidence("node-2", "ext-1", 1, 1_000_000))
            .unwrap();

        // Should saturate at i64::MAX, not overflow.
        assert_eq!(acc.posterior_delta("ext-1"), i64::MAX);
    }

    #[test]
    fn reconciliation_request_serde_round_trip() {
        let mut ranges = BTreeMap::new();
        ranges.insert(NodeId::new("node-1"), SequenceRange::new(5, 10));
        let req = ReconciliationRequest {
            node_id: NodeId::new("local"),
            known_frontier_hash: ContentHash::compute(b"frontier"),
            requested_ranges: ranges,
            epoch: SecurityEpoch::from_raw(2),
            sequence: 1,
            timestamp_ns: 10_000_000_000,
            signature: test_signature("local"),
            protocol_version: ProtocolVersion::CURRENT,
        };

        let json = serde_json::to_string(&req).unwrap();
        let decoded: ReconciliationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn node_id_display_and_ordering() {
        let a = NodeId::new("alpha");
        let b = NodeId::new("beta");
        assert!(a < b); // lexicographic
        assert_eq!(a.to_string(), "alpha");
    }

    #[test]
    fn quorum_checkpoint_serde_round_trip() {
        let mut nodes = BTreeSet::new();
        nodes.insert(NodeId::new("node-1"));
        nodes.insert(NodeId::new("node-2"));

        let mut sigs = BTreeMap::new();
        sigs.insert(NodeId::new("node-1"), test_signature("node-1"));
        sigs.insert(NodeId::new("node-2"), test_signature("node-2"));

        let checkpoint = QuorumCheckpoint {
            checkpoint_seq: 1,
            epoch: SecurityEpoch::from_raw(1),
            participating_nodes: nodes,
            evidence_summary_hash: ContentHash::compute(b"summary"),
            containment_decisions: vec![ResolvedContainmentDecision {
                extension_id: "ext-1".into(),
                resolved_action: ContainmentAction::Suspend,
                contributing_intent_ids: vec!["intent-1".into()],
                epoch: SecurityEpoch::from_raw(1),
            }],
            quorum_signatures: sigs,
            timestamp_ns: 10_000_000_000,
            protocol_version: ProtocolVersion::CURRENT,
            extensions: BTreeMap::new(),
        };

        let json = serde_json::to_string(&checkpoint).unwrap();
        let decoded: QuorumCheckpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(checkpoint, decoded);
    }

    // -- Enrichment: std::error --

    #[test]
    fn protocol_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(ProtocolError::ReplayDetected {
                node_id: NodeId("n-1".into()),
                received_seq: 3,
                last_accepted_seq: 5,
            }),
            Box::new(ProtocolError::DuplicateEvidence {
                trace_id: "t-1".into(),
                extension_id: "ext-1".into(),
            }),
            Box::new(ProtocolError::DuplicateIntentId {
                intent_id: "i-1".into(),
                extension_id: "ext-1".into(),
            }),
            Box::new(ProtocolError::IncompatibleVersion {
                local: ProtocolVersion { major: 1, minor: 0 },
                remote: ProtocolVersion { major: 2, minor: 0 },
            }),
            Box::new(ProtocolError::InvalidSignature {
                node_id: NodeId("n-3".into()),
                message_type: "intent".into(),
            }),
            Box::new(ProtocolError::QuorumNotReached {
                required: 3,
                actual: 1,
            }),
            Box::new(ProtocolError::PartitionedNode {
                node_id: NodeId("n-4".into()),
            }),
            Box::new(ProtocolError::EmptyIntents),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            variants.len(),
            "all protocol error variants produce distinct messages"
        );
    }

    // -- Enrichment: Display uniqueness, ordering, determinism, edge cases --

    #[test]
    fn containment_action_display_all_unique() {
        let mut displays = std::collections::BTreeSet::new();
        for action in [
            ContainmentAction::Allow,
            ContainmentAction::Sandbox,
            ContainmentAction::Suspend,
            ContainmentAction::Terminate,
            ContainmentAction::Quarantine,
        ] {
            displays.insert(action.to_string());
        }
        assert_eq!(
            displays.len(),
            5,
            "all ContainmentAction variants have unique Display"
        );
    }

    #[test]
    fn containment_action_ordering_monotonic() {
        assert!(ContainmentAction::Allow < ContainmentAction::Sandbox);
        assert!(ContainmentAction::Sandbox < ContainmentAction::Suspend);
        assert!(ContainmentAction::Suspend < ContainmentAction::Terminate);
        assert!(ContainmentAction::Terminate < ContainmentAction::Quarantine);
    }

    #[test]
    fn node_id_serde_roundtrip() {
        let node = NodeId::new("test-node-42");
        let json = serde_json::to_string(&node).unwrap();
        let back: NodeId = serde_json::from_str(&json).unwrap();
        assert_eq!(node, back);
    }

    #[test]
    fn sequence_range_serde_roundtrip() {
        let range = SequenceRange::new(5, 15);
        let json = serde_json::to_string(&range).unwrap();
        let back: SequenceRange = serde_json::from_str(&json).unwrap();
        assert_eq!(range, back);
    }

    #[test]
    fn health_tracker_empty_returns_none() {
        let tracker = NodeHealthTracker::new();
        assert!(
            tracker
                .last_heartbeat_ns(&NodeId::new("nonexistent"))
                .is_none()
        );
        assert_eq!(tracker.known_node_count(), 0);
    }

    #[test]
    fn state_resolve_intents_no_intents_returns_none() {
        let state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
        assert!(state.resolve_intents("ext-unknown").is_none());
    }

    #[test]
    fn accumulator_new_is_empty() {
        let acc = EvidenceAccumulator::new();
        assert!(acc.extensions().is_empty());
        assert_eq!(acc.posterior_delta("anything"), 0);
        assert_eq!(acc.evidence_count("anything"), 0);
    }

    #[test]
    fn heartbeat_liveness_serde_roundtrip() {
        let hb = test_heartbeat("node-1", 1, 5_000_000_000);
        let json = serde_json::to_string(&hb).unwrap();
        let back: HeartbeatLiveness = serde_json::from_str(&json).unwrap();
        assert_eq!(hb, back);
    }

    // ── Enrichment: MessageSignature serde ─────────────────────────

    #[test]
    fn message_signature_serde_roundtrip() {
        let sig = test_signature("node-sig");
        let json = serde_json::to_string(&sig).unwrap();
        let back: MessageSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig, back);
    }

    // ── Enrichment: ProtocolVersion ────────────────────────────────

    #[test]
    fn protocol_version_current_is_1_0() {
        assert_eq!(ProtocolVersion::CURRENT.major, 1);
        assert_eq!(ProtocolVersion::CURRENT.minor, 0);
    }

    #[test]
    fn protocol_version_serde_roundtrip() {
        let v = ProtocolVersion { major: 3, minor: 7 };
        let json = serde_json::to_string(&v).unwrap();
        let back: ProtocolVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn protocol_version_ordering() {
        let v1_0 = ProtocolVersion { major: 1, minor: 0 };
        let v1_1 = ProtocolVersion { major: 1, minor: 1 };
        let v2_0 = ProtocolVersion { major: 2, minor: 0 };
        assert!(v1_0 < v1_1);
        assert!(v1_1 < v2_0);
    }

    #[test]
    fn protocol_version_display_non_current() {
        let v = ProtocolVersion {
            major: 5,
            minor: 12,
        };
        assert_eq!(v.to_string(), "5.12");
    }

    #[test]
    fn protocol_version_compatibility_same_major_higher_minor_reader() {
        let reader = ProtocolVersion { major: 1, minor: 3 };
        let writer = ProtocolVersion { major: 1, minor: 1 };
        assert!(reader.is_compatible_with(&writer));
    }

    #[test]
    fn protocol_version_compatibility_same_major_lower_minor_reader_fails() {
        let reader = ProtocolVersion { major: 1, minor: 0 };
        let writer = ProtocolVersion { major: 1, minor: 2 };
        assert!(!reader.is_compatible_with(&writer));
    }

    // ── Enrichment: ContainmentAction serde all variants ──────────

    #[test]
    fn containment_action_serde_all_variants() {
        for action in [
            ContainmentAction::Allow,
            ContainmentAction::Sandbox,
            ContainmentAction::Suspend,
            ContainmentAction::Terminate,
            ContainmentAction::Quarantine,
        ] {
            let json = serde_json::to_string(&action).unwrap();
            let back: ContainmentAction = serde_json::from_str(&json).unwrap();
            assert_eq!(action, back, "roundtrip failed for {action}");
        }
    }

    #[test]
    fn containment_action_severity_values() {
        assert_eq!(ContainmentAction::Allow.severity(), 0);
        assert_eq!(ContainmentAction::Sandbox.severity(), 1);
        assert_eq!(ContainmentAction::Suspend.severity(), 2);
        assert_eq!(ContainmentAction::Terminate.severity(), 3);
        assert_eq!(ContainmentAction::Quarantine.severity(), 4);
    }

    #[test]
    fn containment_action_at_least_as_severe_reflexive() {
        for action in [
            ContainmentAction::Allow,
            ContainmentAction::Sandbox,
            ContainmentAction::Suspend,
            ContainmentAction::Terminate,
            ContainmentAction::Quarantine,
        ] {
            assert!(
                action.at_least_as_severe_as(action),
                "{action} should be at least as severe as itself"
            );
        }
    }

    // ── Enrichment: NodeId ─────────────────────────────────────────

    #[test]
    fn node_id_as_str() {
        let node = NodeId::new("fleet-node-42");
        assert_eq!(node.as_str(), "fleet-node-42");
    }

    #[test]
    fn node_id_empty_string() {
        let node = NodeId::new("");
        assert_eq!(node.as_str(), "");
        assert_eq!(node.to_string(), "");
    }

    // ── Enrichment: SequenceRange edge cases ──────────────────────

    #[test]
    fn sequence_range_zero_to_zero_is_single() {
        let r = SequenceRange::new(0, 0);
        assert_eq!(r.len(), 1);
        assert!(!r.is_empty());
    }

    #[test]
    fn sequence_range_u64_max() {
        let r = SequenceRange::new(u64::MAX, u64::MAX);
        assert_eq!(r.len(), 1);
        let full = SequenceRange::new(0, u64::MAX);
        assert_eq!(full.len(), u64::MAX);
        assert!(!full.is_empty());
    }

    // ── Enrichment: ProtocolError Display all variants ─────────────

    #[test]
    fn protocol_error_display_duplicate_evidence() {
        let err = ProtocolError::DuplicateEvidence {
            trace_id: "trace-42".into(),
            extension_id: "ext-bad".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("duplicate evidence"));
        assert!(msg.contains("trace-42"));
        assert!(msg.contains("ext-bad"));
    }

    #[test]
    fn protocol_error_display_incompatible_version() {
        let err = ProtocolError::IncompatibleVersion {
            local: ProtocolVersion { major: 1, minor: 0 },
            remote: ProtocolVersion { major: 2, minor: 0 },
        };
        let msg = err.to_string();
        assert!(msg.contains("incompatible"));
        assert!(msg.contains("1.0"));
        assert!(msg.contains("2.0"));
    }

    #[test]
    fn protocol_error_display_invalid_signature() {
        let err = ProtocolError::InvalidSignature {
            node_id: NodeId::new("rogue-node"),
            message_type: "evidence".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("invalid signature"));
        assert!(msg.contains("rogue-node"));
        assert!(msg.contains("evidence"));
    }

    #[test]
    fn protocol_error_display_quorum_not_reached() {
        let err = ProtocolError::QuorumNotReached {
            required: 5,
            actual: 2,
        };
        let msg = err.to_string();
        assert!(msg.contains("quorum"));
        assert!(msg.contains("5"));
        assert!(msg.contains("2"));
    }

    #[test]
    fn protocol_error_display_partitioned_node() {
        let err = ProtocolError::PartitionedNode {
            node_id: NodeId::new("isolated-1"),
        };
        let msg = err.to_string();
        assert!(msg.contains("partitioned"));
        assert!(msg.contains("isolated-1"));
    }

    #[test]
    fn protocol_error_display_empty_intents() {
        let err = ProtocolError::EmptyIntents;
        assert_eq!(err.to_string(), "no intents to resolve");
    }

    // ── Enrichment: ProtocolError serde all variants ──────────────

    #[test]
    fn protocol_error_serde_all_variants() {
        let variants = vec![
            ProtocolError::ReplayDetected {
                node_id: NodeId::new("n"),
                received_seq: 1,
                last_accepted_seq: 5,
            },
            ProtocolError::DuplicateEvidence {
                trace_id: "t".into(),
                extension_id: "e".into(),
            },
            ProtocolError::DuplicateIntentId {
                intent_id: "i".into(),
                extension_id: "e".into(),
            },
            ProtocolError::IncompatibleVersion {
                local: ProtocolVersion::CURRENT,
                remote: ProtocolVersion { major: 2, minor: 0 },
            },
            ProtocolError::InvalidSignature {
                node_id: NodeId::new("n"),
                message_type: "intent".into(),
            },
            ProtocolError::QuorumNotReached {
                required: 3,
                actual: 1,
            },
            ProtocolError::PartitionedNode {
                node_id: NodeId::new("n"),
            },
            ProtocolError::EmptyIntents,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ProtocolError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // ── Enrichment: FleetMessage edge cases ────────────────────────

    #[test]
    fn fleet_message_checkpoint_sequence_is_none() {
        let checkpoint = QuorumCheckpoint {
            checkpoint_seq: 1,
            epoch: SecurityEpoch::from_raw(1),
            participating_nodes: BTreeSet::new(),
            evidence_summary_hash: ContentHash::compute(b"summary"),
            containment_decisions: vec![],
            quorum_signatures: BTreeMap::new(),
            timestamp_ns: 1_000_000_000,
            protocol_version: ProtocolVersion::CURRENT,
            extensions: BTreeMap::new(),
        };
        let msg = FleetMessage::Checkpoint(checkpoint);
        assert_eq!(msg.sequence(), None);
    }

    #[test]
    fn fleet_message_reconciliation_serde_roundtrip() {
        let req = ReconciliationRequest {
            node_id: NodeId::new("local"),
            known_frontier_hash: ContentHash::compute(b"frontier"),
            requested_ranges: BTreeMap::new(),
            epoch: SecurityEpoch::from_raw(1),
            sequence: 5,
            timestamp_ns: 5_000_000_000,
            signature: test_signature("local"),
            protocol_version: ProtocolVersion::CURRENT,
        };
        let msg = FleetMessage::Reconciliation(req);
        let json = serde_json::to_string(&msg).unwrap();
        let back: FleetMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, back);
        assert_eq!(msg.sequence(), Some(5));
    }

    // ── Enrichment: build_checkpoint ───────────────────────────────

    #[test]
    fn build_checkpoint_success_with_healthy_nodes() {
        let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());

        // Register some healthy nodes via heartbeats
        let now = 10_000_000_000u64;
        state
            .process_heartbeat(&test_heartbeat("node-1", 1, now))
            .unwrap();
        state
            .process_heartbeat(&test_heartbeat("node-2", 1, now))
            .unwrap();

        // Add an intent so there's something to resolve
        state
            .process_intent(&test_intent(
                "node-1",
                "ext-1",
                ContainmentAction::Sandbox,
                2,
                1,
            ))
            .unwrap();

        let sig = test_signature("local");
        let checkpoint = state.build_checkpoint(now + 1_000_000_000, sig).unwrap();

        assert_eq!(checkpoint.checkpoint_seq, 1);
        assert_eq!(checkpoint.participating_nodes.len(), 2);
        assert!(!checkpoint.containment_decisions.is_empty());
        assert_eq!(
            checkpoint.containment_decisions[0].resolved_action,
            ContainmentAction::Sandbox
        );
    }

    #[test]
    fn build_checkpoint_v2_rejects_colliding_intent_ids_atomically_without_changing_v1() {
        let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
        let now = 10_000_000_000u64;
        state
            .process_heartbeat(&test_heartbeat("node-1", 1, now))
            .expect("record healthy node");
        state.protocol_version = ProtocolVersion::V2;

        let mut intent_z = test_intent("node-1", "ext-1", ContainmentAction::Sandbox, 2, 1);
        intent_z.intent_id = "intent-z".to_string();
        let mut intent_a = test_intent("node-2", "ext-1", ContainmentAction::Sandbox, 1, 1);
        intent_a.intent_id = "intent-a".to_string();
        let mut colliding_intent_a =
            test_intent("node-3", "ext-1", ContainmentAction::Suspend, 1, 1);
        colliding_intent_a.intent_id = "intent-a".to_string();
        state.pending_intents.insert(
            "ext-1".to_string(),
            vec![intent_z, intent_a, colliding_intent_a],
        );

        let pending_before = state.pending_intents.clone();
        let checkpoint_seq_before = state.last_checkpoint_seq;
        let error = state
            .build_checkpoint(now, test_signature("local"))
            .expect_err("v2 contributor collisions must fail closed");
        assert_eq!(
            error,
            ProtocolError::DuplicateIntentId {
                intent_id: "intent-a".to_string(),
                extension_id: "ext-1".to_string(),
            }
        );
        assert_eq!(state.last_checkpoint_seq, checkpoint_seq_before);
        assert_eq!(state.pending_intents, pending_before);

        state.protocol_version = ProtocolVersion::V1;
        let checkpoint = state
            .build_checkpoint(now, test_signature("local"))
            .expect("v1 preserves legacy contributor ordering and collisions");
        assert_eq!(
            checkpoint.containment_decisions[0].contributing_intent_ids,
            vec![
                "intent-z".to_string(),
                "intent-a".to_string(),
                "intent-a".to_string(),
            ]
        );

        let mut unique_intent_z = test_intent("node-1", "ext-1", ContainmentAction::Sandbox, 3, 1);
        unique_intent_z.intent_id = "intent-z".to_string();
        let mut unique_intent_a = test_intent("node-2", "ext-1", ContainmentAction::Sandbox, 2, 1);
        unique_intent_a.intent_id = "intent-a".to_string();
        state.protocol_version = ProtocolVersion::V2;
        state
            .pending_intents
            .insert("ext-1".to_string(), vec![unique_intent_z, unique_intent_a]);
        let checkpoint = state
            .build_checkpoint(now, test_signature("local"))
            .expect("v2 sorts unique contributor IDs");
        assert_eq!(
            checkpoint.containment_decisions[0].contributing_intent_ids,
            vec!["intent-a".to_string(), "intent-z".to_string()]
        );
    }

    #[test]
    fn build_checkpoint_quorum_not_reached() {
        let config = GossipConfig {
            quorum_threshold_millionths: 750_000, // 75%
            ..GossipConfig::default()
        };
        let mut state = FleetProtocolState::new(NodeId::new("local"), config);

        // Register 4 nodes but only 1 is healthy
        let old = 1_000_000_000u64;
        let now = 20_000_000_000u64; // 20s later

        state
            .process_heartbeat(&test_heartbeat("node-1", 1, old))
            .unwrap();
        state
            .process_heartbeat(&test_heartbeat("node-2", 1, old))
            .unwrap();
        state
            .process_heartbeat(&test_heartbeat("node-3", 1, old))
            .unwrap();
        state
            .process_heartbeat(&test_heartbeat("node-4", 1, now))
            .unwrap();

        let sig = test_signature("local");
        let err = state.build_checkpoint(now, sig).unwrap_err();
        assert!(matches!(err, ProtocolError::QuorumNotReached { .. }));
    }

    #[test]
    fn build_checkpoint_increments_sequence() {
        let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
        let now = 10_000_000_000u64;
        state
            .process_heartbeat(&test_heartbeat("node-1", 1, now))
            .unwrap();

        let cp1 = state
            .build_checkpoint(now + 1_000_000, test_signature("local"))
            .unwrap();
        let cp2 = state
            .build_checkpoint(now + 2_000_000, test_signature("local"))
            .unwrap();

        assert_eq!(cp1.checkpoint_seq, 1);
        assert_eq!(cp2.checkpoint_seq, 2);
    }

    // ── Enrichment: process_intent version rejection ──────────────

    #[test]
    fn state_process_intent_incompatible_version() {
        let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
        let mut intent = test_intent("node-a", "ext-1", ContainmentAction::Sandbox, 1, 1);
        intent.protocol_version = ProtocolVersion { major: 3, minor: 0 };

        let err = state.process_intent(&intent).unwrap_err();
        assert!(matches!(err, ProtocolError::IncompatibleVersion { .. }));
    }

    #[test]
    fn state_process_intent_replay_rejected() {
        let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
        state
            .process_intent(&test_intent(
                "node-a",
                "ext-1",
                ContainmentAction::Sandbox,
                5,
                1,
            ))
            .unwrap();

        let err = state
            .process_intent(&test_intent(
                "node-a",
                "ext-2",
                ContainmentAction::Terminate,
                3,
                1,
            ))
            .unwrap_err();
        assert!(matches!(err, ProtocolError::ReplayDetected { .. }));
    }

    // ── Enrichment: process_heartbeat version rejection ───────────

    #[test]
    fn state_process_heartbeat_incompatible_version() {
        let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
        let mut hb = test_heartbeat("node-1", 1, 5_000_000_000);
        hb.protocol_version = ProtocolVersion { major: 2, minor: 0 };

        let err = state.process_heartbeat(&hb).unwrap_err();
        assert!(matches!(err, ProtocolError::IncompatibleVersion { .. }));
    }

    #[test]
    fn state_process_heartbeat_replay_rejected() {
        let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
        state
            .process_heartbeat(&test_heartbeat("node-1", 5, 5_000_000_000))
            .unwrap();

        let err = state
            .process_heartbeat(&test_heartbeat("node-1", 3, 6_000_000_000))
            .unwrap_err();
        assert!(matches!(err, ProtocolError::ReplayDetected { .. }));
    }

    // ── Enrichment: NodeSequenceTracker edge cases ─────────────────

    #[test]
    fn sequence_tracker_last_sequence_unknown_node() {
        let tracker = NodeSequenceTracker::new();
        assert_eq!(tracker.last_sequence(&NodeId::new("unknown")), 0);
    }

    #[test]
    fn sequence_tracker_serde_roundtrip() {
        let mut tracker = NodeSequenceTracker::new();
        tracker.accept(&NodeId::new("a"), 10).unwrap();
        tracker.accept(&NodeId::new("b"), 20).unwrap();

        let json = serde_json::to_string(&tracker).unwrap();
        let back: NodeSequenceTracker = serde_json::from_str(&json).unwrap();
        assert_eq!(back.last_sequence(&NodeId::new("a")), 10);
        assert_eq!(back.last_sequence(&NodeId::new("b")), 20);
    }

    // ── Enrichment: NodeHealthTracker ──────────────────────────────

    #[test]
    fn health_tracker_healthy_and_partitioned_mutual_exclusion() {
        let mut tracker = NodeHealthTracker::new();
        tracker.record_heartbeat(&test_heartbeat("healthy", 1, 10_000_000_000));
        tracker.record_heartbeat(&test_heartbeat("stale", 1, 1_000_000_000));

        let now = 12_000_000_000;
        let timeout = 5_000_000_000;

        let healthy = tracker.healthy_nodes(now, timeout);
        let partitioned = tracker.suspected_partitioned(now, timeout);

        // They should not overlap
        for node in &healthy {
            assert!(!partitioned.contains(node));
        }
        for node in &partitioned {
            assert!(!healthy.contains(node));
        }
        // Together they should cover all known nodes
        assert_eq!(
            healthy.len() + partitioned.len(),
            tracker.known_node_count()
        );
    }

    #[test]
    fn health_tracker_serde_roundtrip() {
        let mut tracker = NodeHealthTracker::new();
        tracker.record_heartbeat(&test_heartbeat("node-1", 1, 5_000_000_000));

        let json = serde_json::to_string(&tracker).unwrap();
        let back: NodeHealthTracker = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.last_heartbeat_ns(&NodeId::new("node-1")),
            Some(5_000_000_000)
        );
    }

    #[test]
    fn health_tracker_heartbeat_updates_timestamp() {
        let mut tracker = NodeHealthTracker::new();
        tracker.record_heartbeat(&test_heartbeat("node-1", 1, 5_000_000_000));
        assert_eq!(
            tracker.last_heartbeat_ns(&NodeId::new("node-1")),
            Some(5_000_000_000)
        );

        tracker.record_heartbeat(&test_heartbeat("node-1", 2, 10_000_000_000));
        assert_eq!(
            tracker.last_heartbeat_ns(&NodeId::new("node-1")),
            Some(10_000_000_000)
        );
    }

    // ── Enrichment: EvidenceAccumulator ────────────────────────────

    #[test]
    fn accumulator_summary_hash_differs_with_different_evidence() {
        let mut acc1 = EvidenceAccumulator::new();
        acc1.ingest(&test_evidence("node-1", "ext-1", 1, 100_000))
            .unwrap();

        let mut acc2 = EvidenceAccumulator::new();
        acc2.ingest(&test_evidence("node-1", "ext-1", 1, 200_000))
            .unwrap();

        assert_ne!(acc1.summary_hash(), acc2.summary_hash());
    }

    #[test]
    fn accumulator_empty_summary_hash_deterministic() {
        let acc1 = EvidenceAccumulator::new();
        let acc2 = EvidenceAccumulator::new();
        assert_eq!(acc1.summary_hash(), acc2.summary_hash());
    }

    // ── Enrichment: GossipConfig ───────────────────────────────────

    #[test]
    fn gossip_config_default_heartbeat_values() {
        let config = GossipConfig::default();
        assert_eq!(config.heartbeat_interval_ns, 5_000_000_000);
        assert_eq!(config.partition_timeout_ns, 15_000_000_000);
        assert_eq!(config.checkpoint_interval_ns, 10_000_000_000);
    }

    // ── Enrichment: DeterministicPrecedence ────────────────────────

    #[test]
    fn precedence_resolve_all_single_intent() {
        let intents = vec![test_intent(
            "node-a",
            "ext-1",
            ContainmentAction::Terminate,
            1,
            1,
        )];
        let winner = DeterministicPrecedence::resolve_all(&intents).unwrap();
        assert_eq!(winner.proposed_action, ContainmentAction::Terminate);
        assert_eq!(winner.node_id, NodeId::new("node-a"));
    }

    #[test]
    fn precedence_epoch_tiebreak_lower_node_id() {
        // Same action, same epoch → smaller node-id wins
        let a = test_intent("aaa", "ext-1", ContainmentAction::Quarantine, 1, 5);
        let z = test_intent("zzz", "ext-1", ContainmentAction::Quarantine, 1, 5);
        let winner = DeterministicPrecedence::resolve(&a, &z);
        assert_eq!(winner.node_id, NodeId::new("aaa"));
    }

    // ── Enrichment: FleetProtocolState ─────────────────────────────

    #[test]
    fn state_new_defaults() {
        let state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
        assert_eq!(state.local_node_id, NodeId::new("local"));
        assert_eq!(state.protocol_version, ProtocolVersion::CURRENT);
        assert_eq!(state.current_epoch, SecurityEpoch::GENESIS);
        assert_eq!(state.last_checkpoint_seq, 0);
        assert_eq!(state.local_sequence, 0);
        assert!(state.pending_intents.is_empty());
    }

    #[test]
    fn state_multiple_extensions_intent_resolution() {
        let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());

        state
            .process_intent(&test_intent(
                "node-a",
                "ext-1",
                ContainmentAction::Sandbox,
                1,
                1,
            ))
            .unwrap();
        state
            .process_intent(&test_intent(
                "node-b",
                "ext-2",
                ContainmentAction::Quarantine,
                1,
                1,
            ))
            .unwrap();

        let w1 = state.resolve_intents("ext-1").unwrap();
        assert_eq!(w1.proposed_action, ContainmentAction::Sandbox);

        let w2 = state.resolve_intents("ext-2").unwrap();
        assert_eq!(w2.proposed_action, ContainmentAction::Quarantine);

        assert!(state.resolve_intents("ext-unknown").is_none());
    }

    #[test]
    fn state_evidence_and_intent_separate_sequence_spaces() {
        let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());

        // node-a sends evidence seq=1, then intent seq=2
        state
            .process_evidence(&test_evidence("node-a", "ext-1", 1, 100_000))
            .unwrap();
        state
            .process_intent(&test_intent(
                "node-a",
                "ext-1",
                ContainmentAction::Sandbox,
                2,
                1,
            ))
            .unwrap();

        // Verify both accumulated
        assert_eq!(state.evidence.posterior_delta("ext-1"), 100_000);
        assert_eq!(state.pending_intents["ext-1"].len(), 1);
    }

    fn v2_test_signer(node_id: &str, key_sequence: u64, seed: u8) -> FleetSigner {
        FleetSigner::new(
            NodeId::new(node_id),
            key_sequence,
            SigningKey::from_bytes([seed; 32]).expect("non-zero deterministic test key"),
        )
        .expect("valid fleet signer")
    }

    fn v2_test_reconciliation(node_id: &str) -> ReconciliationRequest {
        ReconciliationRequest {
            node_id: NodeId::new(node_id),
            known_frontier_hash: ContentHash::compute(b"frontier"),
            requested_ranges: BTreeMap::from([
                (NodeId::new("node-b"), SequenceRange::new(2, 4)),
                (NodeId::new("node-c"), SequenceRange::new(7, 9)),
            ]),
            epoch: SecurityEpoch::from_raw(3),
            sequence: 11,
            timestamp_ns: 12_345,
            signature: test_signature(node_id),
            protocol_version: ProtocolVersion::V2,
        }
    }

    fn v2_test_checkpoint(node_id: &str) -> QuorumCheckpoint {
        QuorumCheckpoint {
            checkpoint_seq: 4,
            epoch: SecurityEpoch::from_raw(3),
            participating_nodes: BTreeSet::from([NodeId::new(node_id), NodeId::new("node-b")]),
            evidence_summary_hash: ContentHash::compute(b"summary"),
            containment_decisions: vec![ResolvedContainmentDecision {
                extension_id: "ext-a".to_string(),
                resolved_action: ContainmentAction::Quarantine,
                contributing_intent_ids: vec!["intent-a".to_string(), "intent-b".to_string()],
                epoch: SecurityEpoch::from_raw(3),
            }],
            quorum_signatures: BTreeMap::new(),
            timestamp_ns: 99_000,
            protocol_version: ProtocolVersion::V2,
            extensions: BTreeMap::from([("checkpoint-note".to_string(), "bound".to_string())]),
        }
    }

    fn assert_v2_signature_roundtrip<T: FleetSignaturePreimageV2>(
        signer: &FleetSigner,
        registry: &FleetVerificationRegistry,
        message: &T,
    ) {
        let signature = signer
            .sign_detached_message_v2(message)
            .expect("sign v2 message");
        registry
            .verify_live_detached_message_v2(message, &signature)
            .expect("verify v2 message");
    }

    fn assert_v2_tamper_rejected<T: FleetSignaturePreimageV2>(
        signer: &FleetSigner,
        registry: &FleetVerificationRegistry,
        original: &T,
        tampered: &T,
    ) {
        let signature = signer
            .sign_detached_message_v2(original)
            .expect("sign original v2 message");
        assert!(matches!(
            registry.verify_live_detached_message_v2(tampered, &signature),
            Err(FleetIdentityError::CryptographicFailure { .. })
        ));
    }

    fn assert_v2_legacy_carrier_excluded<T: FleetSignaturePreimageV2>(
        signer: &FleetSigner,
        registry: &FleetVerificationRegistry,
        original: &T,
        legacy_carrier_changed: &T,
    ) {
        let signature = signer
            .sign_detached_message_v2(original)
            .expect("sign original v2 projection");
        registry
            .verify_live_detached_message_v2(legacy_carrier_changed, &signature)
            .expect("legacy carrier is outside the staged v2 projection");
    }

    fn assert_v2_ingress_limit(error: FleetIdentityError, field: &str) {
        match error {
            FleetIdentityError::NonCanonicalMessage { detail, .. } => {
                assert!(detail.contains("ingress limit exceeded"), "{detail}");
                assert!(detail.contains(field), "{detail}");
            }
            other => panic!("expected ingress limit error for {field}, got {other:?}"),
        }
    }

    fn v2_numbered_ids(prefix: &str, count: usize) -> Vec<String> {
        (0..count)
            .map(|index| format!("{prefix}-{index:03}"))
            .collect()
    }

    #[test]
    fn v2_ingress_scalar_map_and_frame_boundaries_fail_closed() {
        assert!(validate_fleet_v2_frame_len(FLEET_V2_MAX_FRAME_BYTES).is_ok());
        assert_v2_ingress_limit(
            validate_fleet_v2_frame_len(FLEET_V2_MAX_FRAME_BYTES + 1).unwrap_err(),
            "frame_bytes",
        );

        let signer = v2_test_signer("node-a", 1, 31);
        let mut evidence = test_evidence("node-a", "ext-a", 1, 100_000);
        evidence.protocol_version = ProtocolVersion::V2;

        evidence.trace_id = "é".repeat(FLEET_V2_MAX_IDENTIFIER_BYTES / 2);
        signer
            .sign_detached_message_v2(&evidence)
            .expect("exact UTF-8 byte identifier limit is accepted");
        evidence.trace_id.push('é');
        assert_v2_ingress_limit(
            signer.sign_detached_message_v2(&evidence).unwrap_err(),
            "trace_id",
        );

        evidence = test_evidence("node-a", "ext-a", 1, 100_000);
        evidence.protocol_version = ProtocolVersion::V2;
        evidence.extensions = (0..FLEET_V2_MAX_MAP_ENTRIES)
            .map(|index| (format!("key-{index:03}"), "v".to_string()))
            .collect();
        signer
            .sign_detached_message_v2(&evidence)
            .expect("exact map-entry limit is accepted");
        evidence
            .extensions
            .insert("key-over".to_string(), "v".to_string());
        assert_v2_ingress_limit(
            signer.sign_detached_message_v2(&evidence).unwrap_err(),
            "extensions",
        );

        evidence.extensions =
            BTreeMap::from([("value".to_string(), "v".repeat(FLEET_V2_MAX_VALUE_BYTES))]);
        signer
            .sign_detached_message_v2(&evidence)
            .expect("exact map-value byte limit is accepted");
        evidence
            .extensions
            .get_mut("value")
            .expect("value exists")
            .push('v');
        assert_v2_ingress_limit(
            signer.sign_detached_message_v2(&evidence).unwrap_err(),
            "extensions",
        );

        evidence.extensions = (0..8)
            .map(|index| {
                (
                    format!("aggregate-{index}"),
                    "v".repeat(FLEET_V2_MAX_VALUE_BYTES),
                )
            })
            .collect();
        assert_v2_ingress_limit(
            signer.sign_detached_message_v2(&evidence).unwrap_err(),
            "aggregate_dynamic_bytes",
        );

        evidence.extensions.clear();
        evidence.signature.signer = NodeId::new("s".repeat(FLEET_V2_MAX_IDENTIFIER_BYTES + 1));
        assert_v2_ingress_limit(
            signer.sign_detached_message_v2(&evidence).unwrap_err(),
            "signature.signer",
        );
    }

    #[test]
    fn v2_ingress_collection_range_and_nested_limits_cover_all_families() {
        let signer = v2_test_signer("node-a", 1, 32);

        let mut intent = test_intent("node-a", "ext-a", ContainmentAction::Suspend, 2, 1);
        intent.protocol_version = ProtocolVersion::V2;
        intent.supporting_evidence_ids = v2_numbered_ids("trace", FLEET_V2_MAX_COLLECTION_ITEMS);
        signer
            .sign_detached_message_v2(&intent)
            .expect("exact array-item limit is accepted");
        intent
            .supporting_evidence_ids
            .push("trace-over".to_string());
        assert_v2_ingress_limit(
            signer.sign_detached_message_v2(&intent).unwrap_err(),
            "supporting_evidence_ids",
        );

        let mut heartbeat = test_heartbeat("node-a", 3, 30_000);
        heartbeat.protocol_version = ProtocolVersion::V2;
        heartbeat.local_health = (0..=FLEET_V2_MAX_MAP_ENTRIES)
            .map(|index| (format!("health-{index:03}"), "ok".to_string()))
            .collect();
        assert_v2_ingress_limit(
            signer.sign_detached_message_v2(&heartbeat).unwrap_err(),
            "local_health",
        );

        let mut reconciliation = v2_test_reconciliation("node-a");
        reconciliation.requested_ranges = BTreeMap::from([(
            NodeId::new("node-b"),
            SequenceRange::new(0, FLEET_V2_MAX_SEQUENCE_RANGE_LEN - 1),
        )]);
        signer
            .sign_detached_message_v2(&reconciliation)
            .expect("exact sequence-range limit is accepted");
        reconciliation.requested_ranges.insert(
            NodeId::new("node-b"),
            SequenceRange::new(0, FLEET_V2_MAX_SEQUENCE_RANGE_LEN),
        );
        assert_v2_ingress_limit(
            signer
                .sign_detached_message_v2(&reconciliation)
                .unwrap_err(),
            "requested_ranges.span",
        );

        reconciliation.requested_ranges = BTreeMap::from([
            (NodeId::new("node-b"), SequenceRange::new(0, 32_768)),
            (NodeId::new("node-c"), SequenceRange::new(0, 32_768)),
        ]);
        assert_v2_ingress_limit(
            signer
                .sign_detached_message_v2(&reconciliation)
                .unwrap_err(),
            "requested_ranges.aggregate_span",
        );

        reconciliation.requested_ranges = (0..=FLEET_V2_MAX_COLLECTION_ITEMS)
            .map(|index| {
                (
                    NodeId::new(format!("node-{index:03}")),
                    SequenceRange::new(1, 1),
                )
            })
            .collect();
        assert_v2_ingress_limit(
            signer
                .sign_detached_message_v2(&reconciliation)
                .unwrap_err(),
            "requested_ranges",
        );

        let mut checkpoint = v2_test_checkpoint("node-a");
        checkpoint.participating_nodes = (0..=FLEET_V2_MAX_COLLECTION_ITEMS)
            .map(|index| NodeId::new(format!("node-{index:03}")))
            .collect();
        assert_v2_ingress_limit(
            signer.sign_detached_message_v2(&checkpoint).unwrap_err(),
            "participating_nodes",
        );

        checkpoint = v2_test_checkpoint("node-a");
        let checkpoint_epoch = checkpoint.epoch;
        checkpoint.containment_decisions = (0..=FLEET_V2_MAX_COLLECTION_ITEMS)
            .map(|index| ResolvedContainmentDecision {
                extension_id: format!("ext-{index:03}"),
                resolved_action: ContainmentAction::Quarantine,
                contributing_intent_ids: Vec::new(),
                epoch: checkpoint_epoch,
            })
            .collect();
        assert_v2_ingress_limit(
            signer.sign_detached_message_v2(&checkpoint).unwrap_err(),
            "containment_decisions",
        );

        checkpoint = v2_test_checkpoint("node-a");
        checkpoint.containment_decisions[0].contributing_intent_ids =
            v2_numbered_ids("intent", FLEET_V2_MAX_COLLECTION_ITEMS + 1);
        assert_v2_ingress_limit(
            signer.sign_detached_message_v2(&checkpoint).unwrap_err(),
            "containment_decisions.contributing_intent_ids",
        );

        checkpoint = v2_test_checkpoint("node-a");
        let checkpoint_epoch = checkpoint.epoch;
        checkpoint.containment_decisions = (0..4)
            .map(|index| ResolvedContainmentDecision {
                extension_id: format!("ext-{index:03}"),
                resolved_action: ContainmentAction::Quarantine,
                contributing_intent_ids: v2_numbered_ids("intent", FLEET_V2_MAX_COLLECTION_ITEMS),
                epoch: checkpoint_epoch,
            })
            .collect();
        assert_v2_ingress_limit(
            signer.sign_detached_message_v2(&checkpoint).unwrap_err(),
            "aggregate_collection_items",
        );

        checkpoint = v2_test_checkpoint("node-a");
        checkpoint.quorum_signatures = (0..=FLEET_V2_MAX_MAP_ENTRIES)
            .map(|index| {
                let node_id = format!("node-{index:03}");
                (NodeId::new(node_id.as_str()), test_signature(&node_id))
            })
            .collect();
        assert_v2_ingress_limit(
            signer.sign_detached_message_v2(&checkpoint).unwrap_err(),
            "quorum_signatures",
        );
    }

    #[test]
    fn v2_oversized_tamper_fails_before_crypto_without_registry_mutation() {
        let signer = v2_test_signer("node-a", 1, 33);
        let mut registry = FleetVerificationRegistry::new();
        registry.register_signer(&signer).expect("register signer");
        let mut evidence = test_evidence("node-a", "ext-a", 1, 100_000);
        evidence.protocol_version = ProtocolVersion::V2;
        let signature = signer
            .sign_detached_message_v2(&evidence)
            .expect("sign bounded evidence");

        evidence.extensions.insert(
            "oversized".to_string(),
            "v".repeat(FLEET_V2_MAX_VALUE_BYTES + 1),
        );
        assert_v2_ingress_limit(
            registry
                .verify_live_detached_message_v2(&evidence, &signature)
                .unwrap_err(),
            "extensions",
        );
        assert_v2_ingress_limit(
            evidence
                .fleet_signature_preimage_v2(signer.identity())
                .unwrap_err(),
            "extensions",
        );
        assert_v2_ingress_limit(
            evidence
                .fleet_unsigned_view_v2(signer.identity())
                .unwrap_err(),
            "extensions",
        );
        assert_eq!(registry.active_node_count(), 1);
        assert_eq!(
            registry
                .active_identity(&NodeId::new("node-a"))
                .expect("registry authority remains intact"),
            signer.identity()
        );

        let mut oversized_identity = signature;
        oversized_identity.signer = NodeId::new("s".repeat(FLEET_V2_MAX_IDENTIFIER_BYTES + 1));
        assert_v2_ingress_limit(
            registry
                .verify_live_detached_message_v2(&evidence, &oversized_identity)
                .unwrap_err(),
            "signer",
        );
    }

    #[test]
    fn v2_ingress_budget_checked_accounting_is_atomic() {
        let mut exact = FleetV2IngressBudget::default();
        exact
            .charge_dynamic_bytes("test", "payload", FLEET_V2_MAX_DYNAMIC_BYTES)
            .expect("exact dynamic budget is accepted");
        let before = exact.dynamic_bytes;
        assert_v2_ingress_limit(
            exact
                .charge_dynamic_bytes("test", "payload", 1)
                .unwrap_err(),
            "aggregate_dynamic_bytes",
        );
        assert_eq!(exact.dynamic_bytes, before);

        let mut overflow = FleetV2IngressBudget {
            dynamic_bytes: usize::MAX,
            collection_items: 0,
        };
        assert_v2_ingress_limit(
            overflow
                .charge_dynamic_bytes("test", "payload", 1)
                .unwrap_err(),
            "payload",
        );
        assert_eq!(overflow.dynamic_bytes, usize::MAX);
    }

    #[test]
    fn v2_registry_signs_and_verifies_every_common_message_family() {
        let signer = v2_test_signer("node-a", 1, 11);
        let mut registry = FleetVerificationRegistry::new();
        registry.register_signer(&signer).expect("register signer");

        let mut evidence = test_evidence("node-a", "ext-a", 1, 125_000);
        evidence.protocol_version = ProtocolVersion::V2;
        evidence
            .extensions
            .insert("evidence-note".to_string(), "bound".to_string());
        let mut intent = test_intent("node-a", "ext-a", ContainmentAction::Suspend, 2, 3);
        intent.protocol_version = ProtocolVersion::V2;
        intent
            .extensions
            .insert("intent-note".to_string(), "bound".to_string());
        let mut heartbeat = test_heartbeat("node-a", 3, 30_000);
        heartbeat.protocol_version = ProtocolVersion::V2;
        heartbeat
            .local_health
            .insert("queue".to_string(), "healthy".to_string());
        heartbeat
            .extensions
            .insert("heartbeat-note".to_string(), "bound".to_string());

        assert_v2_signature_roundtrip(&signer, &registry, &evidence);
        assert_v2_signature_roundtrip(&signer, &registry, &intent);
        assert_v2_signature_roundtrip(&signer, &registry, &heartbeat);
        assert_v2_signature_roundtrip(&signer, &registry, &v2_test_reconciliation("node-a"));
        assert_v2_signature_roundtrip(&signer, &registry, &v2_test_checkpoint("node-a"));
    }

    #[test]
    fn v2_registry_rejects_unknown_wrong_and_tampered_signatures() {
        let signer = v2_test_signer("node-a", 1, 12);
        let wrong_signer = v2_test_signer("node-b", 1, 13);
        let mut evidence = test_evidence("node-a", "ext-a", 1, 100_000);
        evidence.protocol_version = ProtocolVersion::V2;
        let signature = signer
            .sign_detached_message_v2(&evidence)
            .expect("sign evidence");

        let empty_registry = FleetVerificationRegistry::new();
        assert!(matches!(
            empty_registry.verify_live_detached_message_v2(&evidence, &signature),
            Err(FleetIdentityError::UnknownNode { .. })
        ));

        let mut registry = FleetVerificationRegistry::new();
        registry.register_signer(&signer).expect("register signer");
        registry
            .register_signer(&wrong_signer)
            .expect("register wrong signer independently");

        let forged_preimage = evidence
            .fleet_signature_preimage_v2(wrong_signer.identity())
            .expect("bounded wrong-identity preimage");
        let forged_identity_signature = wrong_signer
            .sign_preimage(&forged_preimage)
            .expect("sign deliberately wrong identity preimage");
        assert!(matches!(
            registry.verify_live_detached_message_v2(&evidence, &forged_identity_signature),
            Err(FleetIdentityError::SignerMismatch { .. })
        ));

        let mut tampered = evidence.clone();
        tampered.posterior_delta_millionths += 1;
        assert!(matches!(
            registry.verify_live_detached_message_v2(&tampered, &signature),
            Err(FleetIdentityError::CryptographicFailure { .. })
        ));

        let mut intent = test_intent("node-a", "ext-a", ContainmentAction::Suspend, 2, 1);
        intent.protocol_version = ProtocolVersion::V2;
        assert!(matches!(
            registry.verify_live_detached_message_v2(&intent, &signature),
            Err(FleetIdentityError::CryptographicFailure { .. })
        ));
    }

    #[test]
    fn v2_registry_rejects_unknown_keys_and_spoofed_registered_metadata() {
        let signer = v2_test_signer("node-a", 1, 19);
        let unknown_sequence = v2_test_signer("node-a", 2, 20);
        let spoofed_key = v2_test_signer("node-a", 1, 21);
        let mut evidence = test_evidence("node-a", "ext-a", 1, 100_000);
        evidence.protocol_version = ProtocolVersion::V2;

        let mut registry = FleetVerificationRegistry::new();
        registry.register_signer(&signer).expect("register signer");

        let unknown_signature = unknown_sequence
            .sign_detached_message_v2(&evidence)
            .expect("sign with unregistered sequence");
        assert!(matches!(
            registry.verify_live_detached_message_v2(&evidence, &unknown_signature),
            Err(FleetIdentityError::UnknownKey { .. })
        ));

        let mut wrong_key_id = signer
            .sign_detached_message_v2(&evidence)
            .expect("sign with registered key");
        wrong_key_id.key_id = unknown_sequence.identity().key_id;
        assert!(matches!(
            registry.verify_live_detached_message_v2(&evidence, &wrong_key_id),
            Err(FleetIdentityError::UnknownKey { .. })
        ));

        let mut spoofed_signature = spoofed_key
            .sign_detached_message_v2(&evidence)
            .expect("sign with spoofed key");
        spoofed_signature.key_id = signer.identity().key_id;
        assert!(matches!(
            registry.verify_live_detached_message_v2(&evidence, &spoofed_signature),
            Err(FleetIdentityError::CryptographicFailure { .. })
        ));
    }

    #[test]
    fn v2_registry_binds_every_common_message_family() {
        let signer = v2_test_signer("node-a", 1, 22);
        let mut registry = FleetVerificationRegistry::new();
        registry.register_signer(&signer).expect("register signer");

        let mut evidence = test_evidence("node-a", "ext-a", 1, 100_000);
        evidence.protocol_version = ProtocolVersion::V2;
        let mut tampered_evidence = evidence.clone();
        tampered_evidence.trace_id.push_str("-tampered");
        assert_v2_tamper_rejected(&signer, &registry, &evidence, &tampered_evidence);

        let mut intent = test_intent("node-a", "ext-a", ContainmentAction::Suspend, 2, 1);
        intent.protocol_version = ProtocolVersion::V2;
        let mut tampered_intent = intent.clone();
        tampered_intent.confidence_millionths -= 1;
        assert_v2_tamper_rejected(&signer, &registry, &intent, &tampered_intent);

        let mut heartbeat = test_heartbeat("node-a", 3, 30_000);
        heartbeat.protocol_version = ProtocolVersion::V2;
        let mut tampered_heartbeat = heartbeat.clone();
        tampered_heartbeat.policy_version += 1;
        assert_v2_tamper_rejected(&signer, &registry, &heartbeat, &tampered_heartbeat);

        let reconciliation = v2_test_reconciliation("node-a");
        let mut tampered_reconciliation = reconciliation.clone();
        tampered_reconciliation.timestamp_ns += 1;
        assert_v2_tamper_rejected(
            &signer,
            &registry,
            &reconciliation,
            &tampered_reconciliation,
        );

        let checkpoint = v2_test_checkpoint("node-a");
        let mut tampered_checkpoint = checkpoint.clone();
        tampered_checkpoint.evidence_summary_hash = ContentHash::compute(b"other-summary");
        assert_v2_tamper_rejected(&signer, &registry, &checkpoint, &tampered_checkpoint);
    }

    #[test]
    fn v2_detached_foundation_explicitly_excludes_legacy_signature_carriers() {
        let signer = v2_test_signer("node-a", 1, 24);
        let mut registry = FleetVerificationRegistry::new();
        registry.register_signer(&signer).expect("register signer");

        let mut evidence = test_evidence("node-a", "ext-a", 1, 100_000);
        evidence.protocol_version = ProtocolVersion::V2;
        let mut changed_evidence = evidence.clone();
        changed_evidence.signature = test_signature("legacy-mutated");
        assert_v2_legacy_carrier_excluded(&signer, &registry, &evidence, &changed_evidence);

        let mut intent = test_intent("node-a", "ext-a", ContainmentAction::Suspend, 2, 1);
        intent.protocol_version = ProtocolVersion::V2;
        let mut changed_intent = intent.clone();
        changed_intent.signature = test_signature("legacy-mutated");
        assert_v2_legacy_carrier_excluded(&signer, &registry, &intent, &changed_intent);

        let mut heartbeat = test_heartbeat("node-a", 3, 30_000);
        heartbeat.protocol_version = ProtocolVersion::V2;
        let mut changed_heartbeat = heartbeat.clone();
        changed_heartbeat.signature = test_signature("legacy-mutated");
        assert_v2_legacy_carrier_excluded(&signer, &registry, &heartbeat, &changed_heartbeat);

        let reconciliation = v2_test_reconciliation("node-a");
        let mut changed_reconciliation = reconciliation.clone();
        changed_reconciliation.signature = test_signature("legacy-mutated");
        assert_v2_legacy_carrier_excluded(
            &signer,
            &registry,
            &reconciliation,
            &changed_reconciliation,
        );

        let checkpoint = v2_test_checkpoint("node-a");
        let mut changed_checkpoint = checkpoint.clone();
        changed_checkpoint
            .quorum_signatures
            .insert(NodeId::new("node-a"), test_signature("legacy-mutated"));
        assert_v2_legacy_carrier_excluded(&signer, &registry, &checkpoint, &changed_checkpoint);
    }

    #[test]
    fn v2_signing_rejects_v1_and_noncanonical_structures() {
        let signer = v2_test_signer("node-a", 1, 23);

        let v1_evidence = test_evidence("node-a", "ext-a", 1, 100_000);
        assert!(matches!(
            signer.sign_detached_message_v2(&v1_evidence),
            Err(FleetIdentityError::NonCanonicalMessage { .. })
        ));

        let mut intent = test_intent("node-a", "ext-a", ContainmentAction::Suspend, 2, 1);
        intent.protocol_version = ProtocolVersion::V2;
        intent.supporting_evidence_ids = vec!["trace-z".to_string(), "trace-a".to_string()];
        assert!(matches!(
            signer.sign_detached_message_v2(&intent),
            Err(FleetIdentityError::NonCanonicalMessage { .. })
        ));
        intent.supporting_evidence_ids = vec!["trace-a".to_string()];
        intent.confidence_millionths = 1_000_001;
        assert!(matches!(
            signer.sign_detached_message_v2(&intent),
            Err(FleetIdentityError::NonCanonicalMessage { .. })
        ));

        let mut reconciliation = v2_test_reconciliation("node-a");
        reconciliation
            .requested_ranges
            .insert(NodeId::new("node-b"), SequenceRange::new(5, 4));
        assert!(matches!(
            signer.sign_detached_message_v2(&reconciliation),
            Err(FleetIdentityError::NonCanonicalMessage { .. })
        ));

        let mut checkpoint = v2_test_checkpoint("node-a");
        checkpoint.containment_decisions[0].epoch = SecurityEpoch::from_raw(4);
        assert!(matches!(
            signer.sign_detached_message_v2(&checkpoint),
            Err(FleetIdentityError::NonCanonicalMessage { .. })
        ));
        checkpoint.containment_decisions[0].epoch = checkpoint.epoch;
        checkpoint.containment_decisions[0].contributing_intent_ids =
            vec!["intent-a".to_string(), "intent-a".to_string()];
        assert!(matches!(
            signer.sign_detached_message_v2(&checkpoint),
            Err(FleetIdentityError::NonCanonicalMessage { .. })
        ));
        checkpoint.containment_decisions[0].contributing_intent_ids = vec!["intent-a".to_string()];
        checkpoint.participating_nodes.clear();
        assert!(matches!(
            signer.sign_detached_message_v2(&checkpoint),
            Err(FleetIdentityError::NonCanonicalMessage { .. })
        ));
    }

    #[test]
    fn v2_registry_rotation_and_revocation_fail_closed_atomically() {
        let old_signer = v2_test_signer("node-a", 1, 14);
        let new_signer = v2_test_signer("node-a", 2, 15);
        let mut evidence = test_evidence("node-a", "ext-a", 1, 100_000);
        evidence.protocol_version = ProtocolVersion::V2;
        let old_signature = old_signer
            .sign_detached_message_v2(&evidence)
            .expect("sign with old key");
        let mut registry = FleetVerificationRegistry::new();
        assert!(matches!(
            registry.active_identity(&NodeId::new("never-registered")),
            Err(FleetIdentityError::UnknownNode { .. })
        ));
        registry
            .register_signer(&old_signer)
            .expect("register old key");

        assert!(matches!(
            registry.rotate(
                &NodeId::new("node-a"),
                9,
                2,
                new_signer.verification_key().clone(),
            ),
            Err(FleetIdentityError::UnexpectedActiveSequence { .. })
        ));
        registry
            .verify_live_detached_message_v2(&evidence, &old_signature)
            .expect("failed rotation leaves old key active");
        assert_eq!(
            registry
                .active_identity(&NodeId::new("node-a"))
                .expect("old key remains active"),
            old_signer.identity()
        );
        assert_eq!(registry.active_node_count(), 1);
        let not_yet_registered = new_signer
            .sign_detached_message_v2(&evidence)
            .expect("sign with prospective key");
        assert!(matches!(
            registry.verify_live_detached_message_v2(&evidence, &not_yet_registered),
            Err(FleetIdentityError::UnknownKey { .. })
        ));

        assert!(matches!(
            registry.rotate(
                &NodeId::new("node-a"),
                1,
                2,
                old_signer.verification_key().clone(),
            ),
            Err(FleetIdentityError::KeyAlreadyBound { .. })
        ));
        registry
            .verify_live_detached_message_v2(&evidence, &old_signature)
            .expect("key-reuse rejection leaves old key active");

        registry
            .rotate(
                &NodeId::new("node-a"),
                1,
                2,
                new_signer.verification_key().clone(),
            )
            .expect("rotate to new key");
        assert!(matches!(
            registry.verify_live_detached_message_v2(&evidence, &old_signature),
            Err(FleetIdentityError::RotatedKey { .. })
        ));

        let new_signature = new_signer
            .sign_detached_message_v2(&evidence)
            .expect("sign with new key");
        registry
            .verify_live_detached_message_v2(&evidence, &new_signature)
            .expect("new key verifies");
        registry
            .revoke(&NodeId::new("node-a"), 2)
            .expect("revoke active key");
        assert!(matches!(
            registry.verify_live_detached_message_v2(&evidence, &new_signature),
            Err(FleetIdentityError::RevokedKey { .. })
        ));
        assert!(matches!(
            registry.active_identity(&NodeId::new("node-a")),
            Err(FleetIdentityError::NoActiveKey { .. })
        ));
        assert!(matches!(
            registry.rotate(
                &NodeId::new("node-a"),
                2,
                3,
                v2_test_signer("node-a", 3, 16).verification_key().clone(),
            ),
            Err(FleetIdentityError::NoActiveKey { .. })
        ));
        assert!(matches!(
            registry.register_signer(&v2_test_signer("node-a", 3, 16)),
            Err(FleetIdentityError::NodeAlreadyRegistered { .. })
        ));
        assert_eq!(registry.active_node_count(), 0);
    }

    #[test]
    fn v2_registry_rejects_invalid_identities_and_key_rebinding() {
        for invalid in ["", " node-a", "node-a ", "__checkpoint__"] {
            assert!(matches!(
                FleetSigner::new(
                    NodeId::new(invalid),
                    1,
                    SigningKey::from_bytes([16; 32]).expect("test key"),
                ),
                Err(FleetIdentityError::InvalidNodeId { .. })
            ));
        }
        assert!(matches!(
            FleetSigner::new(
                NodeId::new("x".repeat(FLEET_V2_MAX_IDENTIFIER_BYTES + 1)),
                1,
                SigningKey::from_bytes([16; 32]).expect("test key"),
            ),
            Err(FleetIdentityError::InvalidNodeId { .. })
        ));
        assert!(matches!(
            FleetSigner::new(
                NodeId::new("node-a"),
                0,
                SigningKey::from_bytes([16; 32]).expect("test key"),
            ),
            Err(FleetIdentityError::InvalidKeySequence { .. })
        ));

        let signer = v2_test_signer("node-a", 1, 17);
        let mut registry = FleetVerificationRegistry::new();
        registry.register_signer(&signer).expect("register signer");
        assert!(matches!(
            registry.register(NodeId::new("node-b"), 1, signer.verification_key().clone(),),
            Err(FleetIdentityError::KeyAlreadyBound { .. })
        ));
        assert!(matches!(
            registry.register(
                NodeId::new("node-a"),
                2,
                v2_test_signer("node-a", 2, 18).verification_key().clone(),
            ),
            Err(FleetIdentityError::NodeAlreadyRegistered { .. })
        ));
        assert_eq!(registry.active_node_count(), 1);
    }
}
