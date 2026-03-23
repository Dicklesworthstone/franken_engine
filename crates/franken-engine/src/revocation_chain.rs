//! Revocation object chain: append-only, hash-linked, monotonic-head
//! revocation history.
//!
//! Three object types form the chain:
//! - **`Revocation`**: an individual revocation decision (who revoked what,
//!   why, signed proof).
//! - **`RevocationEvent`**: a timestamped wrapper that hash-links each
//!   revocation into a sequential chain.
//! - **`RevocationHead`**: the current head pointer with monotonic sequence
//!   and a rolling chain hash for efficient integrity verification.
//!
//! The chain is append-only: events cannot be modified or removed after
//! insertion. Any hash-chain break or sequence regression is detectable
//! and rejected.
//!
//! Plan references: Section 10.10 item 17, 9E.7 (revocation-head freshness
//! semantics and degraded-mode policy).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::capability_token::PrincipalId;
use crate::deterministic_serde::{self, CanonicalValue, SchemaHash};
use crate::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use crate::hash_tiers::ContentHash;
use crate::policy_checkpoint::DeterministicTimestamp;
use crate::signature_preimage::{
    SIGNATURE_SENTINEL, Signature, SignaturePreimage, SigningKey, VerificationKey, sign_preimage,
    verify_signature,
};

// ---------------------------------------------------------------------------
// Schema definitions
// ---------------------------------------------------------------------------

const REVOCATION_SCHEMA_DEF: &[u8] = b"FrankenEngine.Revocation.v1";
const REVOCATION_EVENT_SCHEMA_DEF: &[u8] = b"FrankenEngine.RevocationEvent.v1";
const REVOCATION_HEAD_SCHEMA_DEF: &[u8] = b"FrankenEngine.RevocationHead.v1";

pub fn revocation_schema() -> SchemaHash {
    SchemaHash::from_definition(REVOCATION_SCHEMA_DEF)
}

pub fn revocation_schema_id() -> SchemaId {
    SchemaId::from_definition(REVOCATION_SCHEMA_DEF)
}

pub fn revocation_event_schema() -> SchemaHash {
    SchemaHash::from_definition(REVOCATION_EVENT_SCHEMA_DEF)
}

pub fn revocation_event_schema_id() -> SchemaId {
    SchemaId::from_definition(REVOCATION_EVENT_SCHEMA_DEF)
}

pub fn revocation_head_schema() -> SchemaHash {
    SchemaHash::from_definition(REVOCATION_HEAD_SCHEMA_DEF)
}

pub fn revocation_head_schema_id() -> SchemaId {
    SchemaId::from_definition(REVOCATION_HEAD_SCHEMA_DEF)
}

// ---------------------------------------------------------------------------
// RevocationTargetType
// ---------------------------------------------------------------------------

/// The class of object being revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RevocationTargetType {
    Key,
    Token,
    Attestation,
    Extension,
    Checkpoint,
}

impl fmt::Display for RevocationTargetType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key => write!(f, "key"),
            Self::Token => write!(f, "token"),
            Self::Attestation => write!(f, "attestation"),
            Self::Extension => write!(f, "extension"),
            Self::Checkpoint => write!(f, "checkpoint"),
        }
    }
}

// ---------------------------------------------------------------------------
// RevocationReason
// ---------------------------------------------------------------------------

/// Why the object was revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RevocationReason {
    Compromised,
    Expired,
    Superseded,
    PolicyViolation,
    Administrative,
}

impl fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compromised => write!(f, "compromised"),
            Self::Expired => write!(f, "expired"),
            Self::Superseded => write!(f, "superseded"),
            Self::PolicyViolation => write!(f, "policy_violation"),
            Self::Administrative => write!(f, "administrative"),
        }
    }
}

// ---------------------------------------------------------------------------
// Revocation — individual revocation decision
// ---------------------------------------------------------------------------

/// An individual revocation decision.
///
/// Identifies what was revoked, why, and by whom. The revocation is signed
/// by the issuing principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    pub revocation_id: EngineObjectId,
    pub target_type: RevocationTargetType,
    pub target_id: EngineObjectId,
    pub reason: RevocationReason,
    pub issued_by: PrincipalId,
    pub issued_at: DeterministicTimestamp,
    pub zone: String,
    pub signature: Signature,
}

impl Revocation {
    /// Build the canonical unsigned view for signature computation.
    fn build_unsigned_view(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "issued_at".to_string(),
            CanonicalValue::U64(self.issued_at.0),
        );
        map.insert(
            "issued_by".to_string(),
            CanonicalValue::Bytes(self.issued_by.as_bytes().to_vec()),
        );
        map.insert(
            "reason".to_string(),
            CanonicalValue::String(self.reason.to_string()),
        );
        map.insert(
            "revocation_id".to_string(),
            CanonicalValue::Bytes(self.revocation_id.as_bytes().to_vec()),
        );
        map.insert(
            "signature".to_string(),
            CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
        );
        map.insert(
            "target_id".to_string(),
            CanonicalValue::Bytes(self.target_id.as_bytes().to_vec()),
        );
        map.insert(
            "target_type".to_string(),
            CanonicalValue::String(self.target_type.to_string()),
        );
        map.insert(
            "zone".to_string(),
            CanonicalValue::String(self.zone.clone()),
        );
        CanonicalValue::Map(map)
    }
}

impl SignaturePreimage for Revocation {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::Revocation
    }

    fn signature_schema(&self) -> &SchemaHash {
        unreachable!("use preimage_bytes() directly")
    }

    fn unsigned_view(&self) -> CanonicalValue {
        self.build_unsigned_view()
    }

    fn preimage_bytes(&self) -> Vec<u8> {
        let domain_tag = self.signature_domain().tag();
        let schema = revocation_schema();
        let unsigned = self.unsigned_view();
        let value_bytes = deterministic_serde::encode_value(&unsigned);

        let mut preimage = Vec::with_capacity(domain_tag.len() + 32 + value_bytes.len());
        preimage.extend_from_slice(domain_tag);
        preimage.extend_from_slice(schema.as_bytes());
        preimage.extend_from_slice(&value_bytes);
        preimage
    }
}

// Schema hashes are computed on-demand in preimage_bytes() overrides,
// avoiding the need for lazy_static or static references.

// ---------------------------------------------------------------------------
// RevocationEvent — hash-linked chain entry
// ---------------------------------------------------------------------------

/// A timestamped event wrapping a revocation action and linking it into
/// the append-only chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationEvent {
    pub event_id: EngineObjectId,
    pub revocation: Revocation,
    /// Hash link to previous event. `None` for the genesis event.
    pub prev_event: Option<EngineObjectId>,
    /// Monotonic sequence within the chain (0-based).
    pub event_seq: u64,
}

impl RevocationEvent {
    /// Compute the canonical bytes for this event (used for hash linking).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut map = BTreeMap::new();
        map.insert(
            "event_id".to_string(),
            CanonicalValue::Bytes(self.event_id.as_bytes().to_vec()),
        );
        map.insert("event_seq".to_string(), CanonicalValue::U64(self.event_seq));
        map.insert(
            "prev_event".to_string(),
            match &self.prev_event {
                Some(id) => CanonicalValue::Bytes(id.as_bytes().to_vec()),
                None => CanonicalValue::Null,
            },
        );
        // Include full revocation content for tamper detection.
        let rev = &self.revocation;
        map.insert(
            "revocation_id".to_string(),
            CanonicalValue::Bytes(rev.revocation_id.as_bytes().to_vec()),
        );
        map.insert(
            "target_type".to_string(),
            CanonicalValue::String(rev.target_type.to_string()),
        );
        map.insert(
            "target_id".to_string(),
            CanonicalValue::Bytes(rev.target_id.as_bytes().to_vec()),
        );
        map.insert(
            "reason".to_string(),
            CanonicalValue::String(rev.reason.to_string()),
        );
        map.insert(
            "issued_by".to_string(),
            CanonicalValue::Bytes(rev.issued_by.as_bytes().to_vec()),
        );
        map.insert(
            "issued_at".to_string(),
            CanonicalValue::U64(rev.issued_at.0),
        );
        map.insert("zone".to_string(), CanonicalValue::String(rev.zone.clone()));
        let mut sig_bytes = Vec::with_capacity(64);
        sig_bytes.extend_from_slice(&rev.signature.lower);
        sig_bytes.extend_from_slice(&rev.signature.upper);
        map.insert("signature".to_string(), CanonicalValue::Bytes(sig_bytes));
        deterministic_serde::encode_value(&CanonicalValue::Map(map))
    }

    /// Compute the content hash of this event for chain linking.
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::compute(&self.canonical_bytes())
    }
}

// ---------------------------------------------------------------------------
// RevocationHead — current chain head
// ---------------------------------------------------------------------------

/// The current head of the revocation chain.
///
/// Provides a single point of reference for chain freshness verification:
/// the head sequence is monotonic, and the chain hash is a rolling hash
/// of the entire chain for integrity verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationHead {
    pub head_id: EngineObjectId,
    /// Points to the most recent RevocationEvent.
    pub latest_event: EngineObjectId,
    /// Monotonic sequence (equals the latest event's seq).
    pub head_seq: u64,
    /// Rolling hash of the entire chain for integrity verification.
    pub chain_hash: ContentHash,
    pub zone: String,
    pub signature: Signature,
}

impl RevocationHead {
    fn build_unsigned_view(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "chain_hash".to_string(),
            CanonicalValue::Bytes(self.chain_hash.as_bytes().to_vec()),
        );
        map.insert(
            "head_id".to_string(),
            CanonicalValue::Bytes(self.head_id.as_bytes().to_vec()),
        );
        map.insert("head_seq".to_string(), CanonicalValue::U64(self.head_seq));
        map.insert(
            "latest_event".to_string(),
            CanonicalValue::Bytes(self.latest_event.as_bytes().to_vec()),
        );
        map.insert(
            "signature".to_string(),
            CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
        );
        map.insert(
            "zone".to_string(),
            CanonicalValue::String(self.zone.clone()),
        );
        CanonicalValue::Map(map)
    }
}

impl SignaturePreimage for RevocationHead {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::Revocation
    }

    fn signature_schema(&self) -> &SchemaHash {
        // Overridden in preimage_bytes; this is never called.
        unreachable!("use preimage_bytes directly")
    }

    fn unsigned_view(&self) -> CanonicalValue {
        self.build_unsigned_view()
    }

    fn preimage_bytes(&self) -> Vec<u8> {
        let domain_tag = self.signature_domain().tag();
        let schema = revocation_head_schema();
        let unsigned = self.unsigned_view();
        let value_bytes = deterministic_serde::encode_value(&unsigned);

        let mut preimage = Vec::with_capacity(domain_tag.len() + 32 + value_bytes.len());
        preimage.extend_from_slice(domain_tag);
        preimage.extend_from_slice(schema.as_bytes());
        preimage.extend_from_slice(&value_bytes);
        preimage
    }
}

// ---------------------------------------------------------------------------
// ChainError
// ---------------------------------------------------------------------------

/// Errors from revocation chain operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainError {
    /// Head sequence regression: new_seq <= current_seq.
    HeadSequenceRegression {
        current_seq: u64,
        attempted_seq: u64,
    },
    /// Hash link mismatch: event's prev_event does not match expected.
    HashLinkMismatch {
        event_seq: u64,
        expected_prev: Option<EngineObjectId>,
        actual_prev: Option<EngineObjectId>,
    },
    /// Event sequence gap or regression in the chain.
    SequenceDiscontinuity { expected_seq: u64, actual_seq: u64 },
    /// Genesis event must have prev_event = None and seq = 0.
    InvalidGenesis { detail: String },
    /// Chain integrity verification failed.
    ChainIntegrity { detail: String },
    /// Signature verification failed on a revocation or head.
    SignatureInvalid { detail: String },
    /// Duplicate revocation for the same target.
    DuplicateTarget { target_id: EngineObjectId },
    /// Attempted mutation of an existing event.
    MutationRejected { event_seq: u64 },
    /// Chain is empty (no events appended yet).
    EmptyChain,
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeadSequenceRegression {
                current_seq,
                attempted_seq,
            } => write!(
                f,
                "head sequence regression: current={current_seq}, attempted={attempted_seq}"
            ),
            Self::HashLinkMismatch {
                event_seq,
                expected_prev,
                actual_prev,
            } => write!(
                f,
                "hash link mismatch at seq {event_seq}: expected {expected_prev:?}, got {actual_prev:?}"
            ),
            Self::SequenceDiscontinuity {
                expected_seq,
                actual_seq,
            } => write!(
                f,
                "sequence discontinuity: expected {expected_seq}, got {actual_seq}"
            ),
            Self::InvalidGenesis { detail } => write!(f, "invalid genesis: {detail}"),
            Self::ChainIntegrity { detail } => write!(f, "chain integrity: {detail}"),
            Self::SignatureInvalid { detail } => write!(f, "signature invalid: {detail}"),
            Self::DuplicateTarget { target_id } => {
                write!(f, "duplicate target: {target_id}")
            }
            Self::MutationRejected { event_seq } => {
                write!(f, "mutation rejected at seq {event_seq}")
            }
            Self::EmptyChain => write!(f, "chain is empty"),
        }
    }
}

impl std::error::Error for ChainError {}

// ---------------------------------------------------------------------------
// Audit events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainEventType {
    RevocationAppended {
        event_seq: u64,
        target_id: EngineObjectId,
        target_type: RevocationTargetType,
    },
    HeadAdvanced {
        old_seq: u64,
        new_seq: u64,
    },
    ChainVerified {
        chain_length: u64,
    },
    RevocationLookup {
        target_id: EngineObjectId,
        is_revoked: bool,
    },
    AppendRejected {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainEvent {
    pub event_type: ChainEventType,
    pub zone: String,
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// RevocationChain — the chain manager
// ---------------------------------------------------------------------------

/// Manages an append-only revocation chain with O(1) revocation lookup.
#[derive(Debug)]
pub struct RevocationChain {
    zone: String,
    /// Events in order (index = event_seq).
    events: Vec<RevocationEvent>,
    /// Current head (None if chain is empty).
    head: Option<RevocationHead>,
    /// O(1) revocation lookup: target_id -> event_seq.
    revocation_index: BTreeMap<EngineObjectId, u64>,
    /// Rolling chain hash.
    chain_hash: ContentHash,
    /// Audit events.
    audit_events: Vec<ChainEvent>,
}

impl RevocationChain {
    /// Create a new empty revocation chain for the given zone.
    pub fn new(zone: &str) -> Self {
        Self {
            zone: zone.to_string(),
            events: Vec::new(),
            head: None,
            revocation_index: BTreeMap::new(),
            chain_hash: ContentHash::compute(b"revocation-chain-genesis"),
            audit_events: Vec::new(),
        }
    }

    /// The zone this chain manages.
    pub fn zone(&self) -> &str {
        &self.zone
    }

    /// Number of events in the chain.
    pub fn len(&self) -> u64 {
        self.events.len() as u64
    }

    /// Whether the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Current head sequence, or None if chain is empty.
    pub fn head_seq(&self) -> Option<u64> {
        self.head.as_ref().map(|h| h.head_seq)
    }

    /// Current head reference.
    pub fn head(&self) -> Option<&RevocationHead> {
        self.head.as_ref()
    }

    /// Current rolling chain hash.
    pub fn chain_hash(&self) -> &ContentHash {
        &self.chain_hash
    }

    /// O(1) revocation lookup: check if a target has been revoked.
    pub fn is_revoked(&self, target_id: &EngineObjectId) -> bool {
        self.revocation_index.contains_key(target_id)
    }

    /// Look up the revocation event for a target, if revoked.
    pub fn lookup_revocation(&self, target_id: &EngineObjectId) -> Option<&Revocation> {
        self.revocation_index
            .get(target_id)
            .and_then(|&seq| self.events.get(seq as usize))
            .map(|event| &event.revocation)
    }

    /// Get an event by sequence number.
    pub fn get_event(&self, seq: u64) -> Option<&RevocationEvent> {
        self.events.get(seq as usize)
    }

    /// All events in chain order.
    pub fn events(&self) -> &[RevocationEvent] {
        &self.events
    }

    /// Append a revocation to the chain and advance the head.
    ///
    /// The caller provides a signed `Revocation` and a signing key for
    /// the new head. The method constructs the `RevocationEvent` and
    /// updated `RevocationHead` internally.
    pub fn append(
        &mut self,
        revocation: Revocation,
        head_signing_key: &SigningKey,
        trace_id: &str,
    ) -> Result<u64, ChainError> {
        // Validate zone matches.
        if revocation.zone != self.zone {
            self.emit_reject(
                trace_id,
                format!(
                    "zone mismatch: chain={}, revocation={}",
                    self.zone, revocation.zone
                ),
            );
            return Err(ChainError::ChainIntegrity {
                detail: format!(
                    "zone mismatch: chain={}, revocation={}",
                    self.zone, revocation.zone
                ),
            });
        }

        // Check for duplicate target revocation.
        if self.revocation_index.contains_key(&revocation.target_id) {
            self.emit_reject(
                trace_id,
                format!("duplicate target: {}", revocation.target_id),
            );
            return Err(ChainError::DuplicateTarget {
                target_id: revocation.target_id.clone(),
            });
        }

        let event_seq = self.events.len() as u64;
        let prev_event = self.events.last().map(|e| e.event_id.clone());

        // Derive event ID from canonical content.
        let event_id = self.derive_event_id(&revocation, event_seq, &prev_event);

        let event = RevocationEvent {
            event_id: event_id.clone(),
            revocation: revocation.clone(),
            prev_event,
            event_seq,
        };

        // Update rolling chain hash.
        let event_hash = event.content_hash();
        let mut hash_input = Vec::with_capacity(64);
        hash_input.extend_from_slice(self.chain_hash.as_bytes());
        hash_input.extend_from_slice(event_hash.as_bytes());
        self.chain_hash = ContentHash::compute(&hash_input);

        // Build and sign the new head.
        let head_id = self.derive_head_id(event_seq, &event_id);
        let mut new_head = RevocationHead {
            head_id,
            latest_event: event_id,
            head_seq: event_seq,
            chain_hash: self.chain_hash,
            zone: self.zone.clone(),
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };

        let preimage = new_head.preimage_bytes();
        let sig = sign_preimage(head_signing_key, &preimage).map_err(|e| {
            ChainError::SignatureInvalid {
                detail: e.to_string(),
            }
        })?;
        new_head.signature = sig;

        // Update index and store.
        self.revocation_index
            .insert(revocation.target_id.clone(), event_seq);
        let target_id = revocation.target_id.clone();
        let target_type = revocation.target_type;
        self.events.push(event);
        self.head = Some(new_head);

        self.audit_events.push(ChainEvent {
            event_type: ChainEventType::RevocationAppended {
                event_seq,
                target_id,
                target_type,
            },
            zone: self.zone.clone(),
            trace_id: trace_id.to_string(),
        });

        if event_seq > 0 {
            self.audit_events.push(ChainEvent {
                event_type: ChainEventType::HeadAdvanced {
                    old_seq: event_seq - 1,
                    new_seq: event_seq,
                },
                zone: self.zone.clone(),
                trace_id: trace_id.to_string(),
            });
        }

        Ok(event_seq)
    }

    /// Verify incremental append: validate that a new event correctly
    /// links to the current head.
    pub fn verify_append(&self, event: &RevocationEvent) -> Result<(), ChainError> {
        let expected_seq = self.events.len() as u64;

        // Verify sequence continuity.
        if event.event_seq != expected_seq {
            return Err(ChainError::SequenceDiscontinuity {
                expected_seq,
                actual_seq: event.event_seq,
            });
        }

        // Verify hash link.
        let expected_prev = self.events.last().map(|e| e.event_id.clone());
        if event.prev_event != expected_prev {
            return Err(ChainError::HashLinkMismatch {
                event_seq: event.event_seq,
                expected_prev,
                actual_prev: event.prev_event.clone(),
            });
        }

        // Genesis validation.
        if event.event_seq == 0 && event.prev_event.is_some() {
            return Err(ChainError::InvalidGenesis {
                detail: "genesis event must have prev_event = None".to_string(),
            });
        }

        Ok(())
    }

    /// Verify the entire chain from genesis to the current head.
    pub fn verify_chain(&self, _trace_id: &str) -> Result<(), ChainError> {
        if self.events.is_empty() {
            if self.head.is_some() {
                return Err(ChainError::ChainIntegrity {
                    detail: "empty chain must not have a head".to_string(),
                });
            }
            return Ok(());
        }

        // Verify genesis.
        let genesis = &self.events[0];
        if genesis.event_seq != 0 {
            return Err(ChainError::InvalidGenesis {
                detail: format!("genesis seq must be 0, got {}", genesis.event_seq),
            });
        }
        if genesis.prev_event.is_some() {
            return Err(ChainError::InvalidGenesis {
                detail: "genesis must have prev_event = None".to_string(),
            });
        }

        // Walk the chain, verifying hash links and sequence monotonicity.
        let mut rolling_hash = ContentHash::compute(b"revocation-chain-genesis");

        for (i, event) in self.events.iter().enumerate() {
            let expected_seq = i as u64;
            if event.event_seq != expected_seq {
                return Err(ChainError::SequenceDiscontinuity {
                    expected_seq,
                    actual_seq: event.event_seq,
                });
            }

            // Verify hash link to previous event.
            if i == 0 {
                if event.prev_event.is_some() {
                    return Err(ChainError::HashLinkMismatch {
                        event_seq: 0,
                        expected_prev: None,
                        actual_prev: event.prev_event.clone(),
                    });
                }
            } else {
                let expected_prev = Some(self.events[i - 1].event_id.clone());
                if event.prev_event != expected_prev {
                    return Err(ChainError::HashLinkMismatch {
                        event_seq: expected_seq,
                        expected_prev,
                        actual_prev: event.prev_event.clone(),
                    });
                }
            }

            // Update rolling hash.
            let event_hash = event.content_hash();
            let mut hash_input = Vec::with_capacity(64);
            hash_input.extend_from_slice(rolling_hash.as_bytes());
            hash_input.extend_from_slice(event_hash.as_bytes());
            rolling_hash = ContentHash::compute(&hash_input);
        }

        // Verify rolling hash matches head.
        if let Some(head) = &self.head {
            if rolling_hash != head.chain_hash {
                return Err(ChainError::ChainIntegrity {
                    detail: "rolling chain hash does not match head".to_string(),
                });
            }
            // Verify head seq matches last event.
            let last_seq = (self.events.len() as u64).saturating_sub(1);
            if head.head_seq != last_seq {
                return Err(ChainError::ChainIntegrity {
                    detail: format!(
                        "head seq {} does not match last event seq {}",
                        head.head_seq, last_seq
                    ),
                });
            }
        }

        Ok(())
    }

    /// Verify the entire chain and emit an audit event (mutable version).
    pub fn verify_chain_mut(&mut self, trace_id: &str) -> Result<(), ChainError> {
        // Delegate to immutable verify_chain for the actual logic.
        let result = self.verify_chain(trace_id);

        if result.is_ok() {
            self.audit_events.push(ChainEvent {
                event_type: ChainEventType::ChainVerified {
                    chain_length: self.events.len() as u64,
                },
                zone: self.zone.clone(),
                trace_id: trace_id.to_string(),
            });
        }

        result
    }

    /// Verify the head signature.
    pub fn verify_head_signature(
        &self,
        verification_key: &VerificationKey,
    ) -> Result<(), ChainError> {
        let head = self.head.as_ref().ok_or(ChainError::EmptyChain)?;
        let preimage = head.preimage_bytes();
        verify_signature(verification_key, &preimage, &head.signature).map_err(|e| {
            ChainError::SignatureInvalid {
                detail: e.to_string(),
            }
        })
    }

    /// Drain accumulated audit events.
    pub fn drain_events(&mut self) -> Vec<ChainEvent> {
        std::mem::take(&mut self.audit_events)
    }

    /// Event counts by type.
    pub fn event_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for event in &self.audit_events {
            let key = match &event.event_type {
                ChainEventType::RevocationAppended { .. } => "revocation_appended",
                ChainEventType::HeadAdvanced { .. } => "head_advanced",
                ChainEventType::ChainVerified { .. } => "chain_verified",
                ChainEventType::RevocationLookup { .. } => "revocation_lookup",
                ChainEventType::AppendRejected { .. } => "append_rejected",
            };
            *counts.entry(key.to_string()).or_insert(0) += 1;
        }
        counts
    }

    /// Lookup with audit trail.
    pub fn is_revoked_audited(&mut self, target_id: &EngineObjectId, trace_id: &str) -> bool {
        let result = self.revocation_index.contains_key(target_id);
        self.audit_events.push(ChainEvent {
            event_type: ChainEventType::RevocationLookup {
                target_id: target_id.clone(),
                is_revoked: result,
            },
            zone: self.zone.clone(),
            trace_id: trace_id.to_string(),
        });
        result
    }

    /// Rebuild the chain from a list of events (e.g. after loading from
    /// storage). Validates the chain during reconstruction.
    pub fn rebuild_from_events(
        zone: &str,
        events: Vec<RevocationEvent>,
        head: Option<RevocationHead>,
    ) -> Result<Self, ChainError> {
        let mut chain = Self::new(zone);

        for (i, event) in events.iter().enumerate() {
            // Verify sequence.
            if event.event_seq != i as u64 {
                return Err(ChainError::SequenceDiscontinuity {
                    expected_seq: i as u64,
                    actual_seq: event.event_seq,
                });
            }

            // Verify hash link.
            if i == 0 {
                if event.prev_event.is_some() {
                    return Err(ChainError::InvalidGenesis {
                        detail: "genesis must have prev_event = None".to_string(),
                    });
                }
            } else {
                let expected_prev = Some(events[i - 1].event_id.clone());
                if event.prev_event != expected_prev {
                    return Err(ChainError::HashLinkMismatch {
                        event_seq: event.event_seq,
                        expected_prev,
                        actual_prev: event.prev_event.clone(),
                    });
                }
            }

            // Check for duplicate target.
            if chain
                .revocation_index
                .contains_key(&event.revocation.target_id)
            {
                return Err(ChainError::DuplicateTarget {
                    target_id: event.revocation.target_id.clone(),
                });
            }

            // Update rolling hash.
            let event_hash = event.content_hash();
            let mut hash_input = Vec::with_capacity(64);
            hash_input.extend_from_slice(chain.chain_hash.as_bytes());
            hash_input.extend_from_slice(event_hash.as_bytes());
            chain.chain_hash = ContentHash::compute(&hash_input);

            // Update index.
            chain
                .revocation_index
                .insert(event.revocation.target_id.clone(), event.event_seq);
        }

        // Verify head matches chain if provided.
        if let Some(ref h) = head {
            if events.is_empty() {
                return Err(ChainError::ChainIntegrity {
                    detail: "empty chain must not have a head".to_string(),
                });
            }
            let last_seq = (events.len() as u64).saturating_sub(1);
            if h.head_seq != last_seq {
                return Err(ChainError::ChainIntegrity {
                    detail: format!(
                        "head seq {} does not match last event seq {}",
                        h.head_seq, last_seq
                    ),
                });
            }
            if h.chain_hash != chain.chain_hash {
                return Err(ChainError::ChainIntegrity {
                    detail: "head chain_hash does not match computed hash".to_string(),
                });
            }
        }

        chain.events = events;
        chain.head = head;
        Ok(chain)
    }

    // -- Internal helpers --

    fn derive_event_id(
        &self,
        revocation: &Revocation,
        event_seq: u64,
        prev_event: &Option<EngineObjectId>,
    ) -> EngineObjectId {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(revocation.revocation_id.as_bytes());
        canonical.extend_from_slice(&event_seq.to_be_bytes());
        if let Some(prev) = prev_event {
            canonical.extend_from_slice(prev.as_bytes());
        }
        engine_object_id::derive_id(
            ObjectDomain::Revocation,
            &self.zone,
            &revocation_event_schema_id(),
            &canonical,
        )
        .expect("canonical bytes are non-empty")
    }

    fn derive_head_id(&self, head_seq: u64, latest_event: &EngineObjectId) -> EngineObjectId {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(&head_seq.to_be_bytes());
        canonical.extend_from_slice(latest_event.as_bytes());
        canonical.extend_from_slice(self.chain_hash.as_bytes());
        engine_object_id::derive_id(
            ObjectDomain::Revocation,
            &self.zone,
            &revocation_head_schema_id(),
            &canonical,
        )
        .expect("canonical bytes are non-empty")
    }

    fn emit_reject(&mut self, trace_id: &str, reason: String) {
        self.audit_events.push(ChainEvent {
            event_type: ChainEventType::AppendRejected { reason },
            zone: self.zone.clone(),
            trace_id: trace_id.to_string(),
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature_preimage::SigningKey;

    const TEST_ZONE: &str = "test-zone";

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ])
    }

    fn test_revocation_key() -> SigningKey {
        SigningKey::from_bytes([
            0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE,
            0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC,
            0xBD, 0xBE, 0xBF, 0xC0,
        ])
    }

    fn make_revocation(
        target_type: RevocationTargetType,
        reason: RevocationReason,
        target_bytes: [u8; 32],
        signing_key: &SigningKey,
    ) -> Revocation {
        let principal = PrincipalId::from_verification_key(&signing_key.verification_key());
        let target_id = EngineObjectId(target_bytes);

        // Derive revocation_id from target.
        let revocation_id = engine_object_id::derive_id(
            ObjectDomain::Revocation,
            TEST_ZONE,
            &revocation_schema_id(),
            target_bytes.as_slice(),
        )
        .unwrap();

        let mut rev = Revocation {
            revocation_id,
            target_type,
            target_id,
            reason,
            issued_by: principal,
            issued_at: DeterministicTimestamp(1000),
            zone: TEST_ZONE.to_string(),
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };

        // Sign the revocation.
        let preimage = rev.preimage_bytes();
        let sig = sign_preimage(signing_key, &preimage).unwrap();
        rev.signature = sig;
        rev
    }

    // -- Genesis and basic append --

    #[test]
    fn new_chain_is_empty() {
        let chain = RevocationChain::new(TEST_ZONE);
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
        assert!(chain.head().is_none());
        assert_eq!(chain.head_seq(), None);
    }

    #[test]
    fn append_genesis_event() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();
        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [1; 32],
            &test_revocation_key(),
        );

        let seq = chain.append(rev, &sk, "t-genesis").unwrap();
        assert_eq!(seq, 0);
        assert_eq!(chain.len(), 1);
        assert!(!chain.is_empty());
        assert_eq!(chain.head_seq(), Some(0));

        // Genesis event should have prev_event = None.
        let event = chain.get_event(0).unwrap();
        assert!(event.prev_event.is_none());
        assert_eq!(event.event_seq, 0);
    }

    #[test]
    fn append_multiple_events() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();

        for i in 0..5u8 {
            let rev = make_revocation(
                RevocationTargetType::Token,
                RevocationReason::Expired,
                [i + 10; 32],
                &test_revocation_key(),
            );
            let seq = chain.append(rev, &sk, &format!("t-{i}")).unwrap();
            assert_eq!(seq, i as u64);
        }

        assert_eq!(chain.len(), 5);
        assert_eq!(chain.head_seq(), Some(4));

        // Verify hash linking.
        for i in 1..5 {
            let event = chain.get_event(i).unwrap();
            let prev = chain.get_event(i - 1).unwrap();
            assert_eq!(event.prev_event, Some(prev.event_id.clone()));
        }
    }

    // -- Revocation lookup --

    #[test]
    fn is_revoked_returns_true_for_revoked_target() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();
        let target = EngineObjectId([42; 32]);

        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [42; 32],
            &test_revocation_key(),
        );
        chain.append(rev, &sk, "t-lookup").unwrap();

        assert!(chain.is_revoked(&target));
    }

    #[test]
    fn is_revoked_returns_false_for_non_revoked_target() {
        let chain = RevocationChain::new(TEST_ZONE);
        let target = EngineObjectId([99; 32]);
        assert!(!chain.is_revoked(&target));
    }

    #[test]
    fn lookup_revocation_returns_details() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();

        let rev = make_revocation(
            RevocationTargetType::Extension,
            RevocationReason::PolicyViolation,
            [55; 32],
            &test_revocation_key(),
        );
        chain.append(rev, &sk, "t-detail").unwrap();

        let found = chain.lookup_revocation(&EngineObjectId([55; 32])).unwrap();
        assert_eq!(found.target_type, RevocationTargetType::Extension);
        assert_eq!(found.reason, RevocationReason::PolicyViolation);
    }

    // -- Duplicate target rejection --

    #[test]
    fn duplicate_target_rejected() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();

        let rev1 = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [1; 32],
            &test_revocation_key(),
        );
        chain.append(rev1, &sk, "t-dup-1").unwrap();

        let rev2 = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Administrative,
            [1; 32], // same target
            &test_revocation_key(),
        );
        let err = chain.append(rev2, &sk, "t-dup-2").unwrap_err();
        assert!(matches!(err, ChainError::DuplicateTarget { .. }));
    }

    // -- Chain verification --

    #[test]
    fn verify_chain_empty_succeeds() {
        let chain = RevocationChain::new(TEST_ZONE);
        assert!(chain.verify_chain("t-empty").is_ok());
    }

    #[test]
    fn verify_chain_after_appends() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();

        for i in 0..10u8 {
            let rev = make_revocation(
                RevocationTargetType::Token,
                RevocationReason::Superseded,
                [i + 100; 32],
                &test_revocation_key(),
            );
            chain.append(rev, &sk, &format!("t-v{i}")).unwrap();
        }

        assert!(chain.verify_chain("t-verify").is_ok());
    }

    #[test]
    fn verify_chain_detects_tampered_event() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();

        for i in 0..3u8 {
            let rev = make_revocation(
                RevocationTargetType::Key,
                RevocationReason::Compromised,
                [i + 200; 32],
                &test_revocation_key(),
            );
            chain.append(rev, &sk, &format!("t-t{i}")).unwrap();
        }

        // Tamper with the middle event's prev_event link.
        chain.events[1].prev_event = Some(EngineObjectId([0xFF; 32]));

        let err = chain.verify_chain("t-tamper").unwrap_err();
        assert!(matches!(err, ChainError::HashLinkMismatch { .. }));
    }

    #[test]
    fn verify_chain_detects_sequence_discontinuity() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();

        for i in 0..3u8 {
            let rev = make_revocation(
                RevocationTargetType::Key,
                RevocationReason::Compromised,
                [i + 210; 32],
                &test_revocation_key(),
            );
            chain.append(rev, &sk, &format!("t-s{i}")).unwrap();
        }

        // Tamper with event sequence.
        chain.events[2].event_seq = 99;

        let err = chain.verify_chain("t-seq").unwrap_err();
        assert!(matches!(err, ChainError::SequenceDiscontinuity { .. }));
    }

    // -- Head signature verification --

    #[test]
    fn verify_head_signature_succeeds() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();
        let vk = sk.verification_key();

        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [1; 32],
            &test_revocation_key(),
        );
        chain.append(rev, &sk, "t-sig").unwrap();

        assert!(chain.verify_head_signature(&vk).is_ok());
    }

    #[test]
    fn verify_head_signature_fails_with_wrong_key() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();

        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [1; 32],
            &test_revocation_key(),
        );
        chain.append(rev, &sk, "t-wrong").unwrap();

        let wrong_vk = VerificationKey::from_bytes([0xFF; 32]);
        let err = chain.verify_head_signature(&wrong_vk).unwrap_err();
        assert!(matches!(err, ChainError::SignatureInvalid { .. }));
    }

    #[test]
    fn verify_head_on_empty_chain_returns_error() {
        let chain = RevocationChain::new(TEST_ZONE);
        let vk = test_signing_key().verification_key();
        let err = chain.verify_head_signature(&vk).unwrap_err();
        assert!(matches!(err, ChainError::EmptyChain));
    }

    // -- Monotonic head sequence --

    #[test]
    fn head_seq_increases_monotonically() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();

        let mut prev_seq = None;
        for i in 0..5u8 {
            let rev = make_revocation(
                RevocationTargetType::Token,
                RevocationReason::Expired,
                [i + 50; 32],
                &test_revocation_key(),
            );
            chain.append(rev, &sk, &format!("t-mono-{i}")).unwrap();
            let current = chain.head_seq().unwrap();
            if let Some(prev) = prev_seq {
                assert!(current > prev, "head seq must be monotonically increasing");
            }
            prev_seq = Some(current);
        }
    }

    // -- All target types --

    #[test]
    fn all_target_types_can_be_revoked() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();

        let types = [
            RevocationTargetType::Key,
            RevocationTargetType::Token,
            RevocationTargetType::Attestation,
            RevocationTargetType::Extension,
            RevocationTargetType::Checkpoint,
        ];

        for (i, target_type) in types.iter().enumerate() {
            let rev = make_revocation(
                *target_type,
                RevocationReason::Administrative,
                [(i as u8) + 30; 32],
                &test_revocation_key(),
            );
            chain.append(rev, &sk, &format!("t-type-{i}")).unwrap();
        }

        assert_eq!(chain.len(), 5);
        for (i, _) in types.iter().enumerate() {
            assert!(chain.is_revoked(&EngineObjectId([(i as u8) + 30; 32])));
        }
    }

    // -- All revocation reasons --

    #[test]
    fn all_revocation_reasons_accepted() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();

        let reasons = [
            RevocationReason::Compromised,
            RevocationReason::Expired,
            RevocationReason::Superseded,
            RevocationReason::PolicyViolation,
            RevocationReason::Administrative,
        ];

        for (i, reason) in reasons.iter().enumerate() {
            let rev = make_revocation(
                RevocationTargetType::Key,
                *reason,
                [(i as u8) + 60; 32],
                &test_revocation_key(),
            );
            chain.append(rev, &sk, &format!("t-reason-{i}")).unwrap();
        }

        assert_eq!(chain.len(), 5);
    }

    // -- Incremental verify --

    #[test]
    fn verify_append_accepts_valid_next_event() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();

        // Append genesis.
        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [1; 32],
            &test_revocation_key(),
        );
        chain.append(rev, &sk, "t-inc-0").unwrap();

        // Build what the next event would look like.
        let rev2 = make_revocation(
            RevocationTargetType::Token,
            RevocationReason::Expired,
            [2; 32],
            &test_revocation_key(),
        );

        let prev_id = chain.events.last().unwrap().event_id.clone();
        let next_event = RevocationEvent {
            event_id: EngineObjectId([0xAA; 32]), // doesn't matter for verify
            revocation: rev2,
            prev_event: Some(prev_id),
            event_seq: 1,
        };

        assert!(chain.verify_append(&next_event).is_ok());
    }

    #[test]
    fn verify_append_rejects_wrong_seq() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();

        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [1; 32],
            &test_revocation_key(),
        );
        chain.append(rev, &sk, "t-seq-bad").unwrap();

        let rev2 = make_revocation(
            RevocationTargetType::Token,
            RevocationReason::Expired,
            [2; 32],
            &test_revocation_key(),
        );
        let next_event = RevocationEvent {
            event_id: EngineObjectId([0xBB; 32]),
            revocation: rev2,
            prev_event: Some(chain.events.last().unwrap().event_id.clone()),
            event_seq: 99, // wrong
        };

        let err = chain.verify_append(&next_event).unwrap_err();
        assert!(matches!(err, ChainError::SequenceDiscontinuity { .. }));
    }

    #[test]
    fn verify_append_rejects_wrong_prev_link() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();

        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [1; 32],
            &test_revocation_key(),
        );
        chain.append(rev, &sk, "t-link-bad").unwrap();

        let rev2 = make_revocation(
            RevocationTargetType::Token,
            RevocationReason::Expired,
            [2; 32],
            &test_revocation_key(),
        );
        let next_event = RevocationEvent {
            event_id: EngineObjectId([0xCC; 32]),
            revocation: rev2,
            prev_event: Some(EngineObjectId([0xFF; 32])), // wrong link
            event_seq: 1,
        };

        let err = chain.verify_append(&next_event).unwrap_err();
        assert!(matches!(err, ChainError::HashLinkMismatch { .. }));
    }

    // -- Rebuild from events --

    #[test]
    fn rebuild_from_events_succeeds() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();

        for i in 0..5u8 {
            let rev = make_revocation(
                RevocationTargetType::Token,
                RevocationReason::Superseded,
                [i + 70; 32],
                &test_revocation_key(),
            );
            chain.append(rev, &sk, &format!("t-rb-{i}")).unwrap();
        }

        let events = chain.events().to_vec();
        let head = chain.head().cloned();

        let rebuilt = RevocationChain::rebuild_from_events(TEST_ZONE, events, head).unwrap();
        assert_eq!(rebuilt.len(), 5);
        assert_eq!(rebuilt.head_seq(), Some(4));
        assert_eq!(rebuilt.chain_hash(), chain.chain_hash());

        for i in 0..5u8 {
            assert!(rebuilt.is_revoked(&EngineObjectId([i + 70; 32])));
        }
    }

    #[test]
    fn rebuild_detects_tampered_chain() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();

        for i in 0..3u8 {
            let rev = make_revocation(
                RevocationTargetType::Key,
                RevocationReason::Compromised,
                [i + 80; 32],
                &test_revocation_key(),
            );
            chain.append(rev, &sk, &format!("t-rt-{i}")).unwrap();
        }

        let mut events = chain.events().to_vec();
        // Tamper: break hash link.
        events[1].prev_event = Some(EngineObjectId([0xFF; 32]));

        let err = RevocationChain::rebuild_from_events(TEST_ZONE, events, None).unwrap_err();
        assert!(matches!(err, ChainError::HashLinkMismatch { .. }));
    }

    #[test]
    fn rebuild_detects_head_mismatch() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();

        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [90; 32],
            &test_revocation_key(),
        );
        chain.append(rev, &sk, "t-hm").unwrap();

        let events = chain.events().to_vec();
        let mut head = chain.head().cloned().unwrap();
        head.head_seq = 99; // tamper

        let err = RevocationChain::rebuild_from_events(TEST_ZONE, events, Some(head)).unwrap_err();
        assert!(matches!(err, ChainError::ChainIntegrity { .. }));
    }

    // -- Zone mismatch rejection --

    #[test]
    fn zone_mismatch_rejected() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();

        let mut rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [1; 32],
            &test_revocation_key(),
        );
        rev.zone = "wrong-zone".to_string();

        let err = chain.append(rev, &sk, "t-zone").unwrap_err();
        assert!(matches!(err, ChainError::ChainIntegrity { .. }));
    }

    // -- Audit events --

    #[test]
    fn audit_events_emitted_on_append() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();

        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [1; 32],
            &test_revocation_key(),
        );
        chain.append(rev, &sk, "t-audit").unwrap();

        let events = chain.drain_events();
        assert!(
            events
                .iter()
                .any(|e| matches!(e.event_type, ChainEventType::RevocationAppended { .. }))
        );
    }

    #[test]
    fn audit_events_emitted_on_rejection() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();

        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [1; 32],
            &test_revocation_key(),
        );
        chain.append(rev, &sk, "t-r1").unwrap();

        // Duplicate.
        let rev2 = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Administrative,
            [1; 32],
            &test_revocation_key(),
        );
        let _ = chain.append(rev2, &sk, "t-r2");

        let counts = chain.event_counts();
        assert_eq!(counts.get("append_rejected"), Some(&1));
    }

    #[test]
    fn audited_lookup_emits_event() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let target = EngineObjectId([99; 32]);

        chain.is_revoked_audited(&target, "t-look");

        let counts = chain.event_counts();
        assert_eq!(counts.get("revocation_lookup"), Some(&1));
    }

    #[test]
    fn drain_events_clears() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();

        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [1; 32],
            &test_revocation_key(),
        );
        chain.append(rev, &sk, "t-drain").unwrap();

        assert!(!chain.drain_events().is_empty());
        assert!(chain.drain_events().is_empty());
    }

    // -- Serialization round-trips --

    #[test]
    fn revocation_target_type_serialization() {
        let types = [
            RevocationTargetType::Key,
            RevocationTargetType::Token,
            RevocationTargetType::Attestation,
            RevocationTargetType::Extension,
            RevocationTargetType::Checkpoint,
        ];
        for t in &types {
            let json = serde_json::to_string(t).unwrap();
            let restored: RevocationTargetType = serde_json::from_str(&json).unwrap();
            assert_eq!(*t, restored);
        }
    }

    #[test]
    fn revocation_reason_serialization() {
        let reasons = [
            RevocationReason::Compromised,
            RevocationReason::Expired,
            RevocationReason::Superseded,
            RevocationReason::PolicyViolation,
            RevocationReason::Administrative,
        ];
        for r in &reasons {
            let json = serde_json::to_string(r).unwrap();
            let restored: RevocationReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*r, restored);
        }
    }

    #[test]
    fn revocation_serialization_round_trip() {
        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [1; 32],
            &test_revocation_key(),
        );
        let json = serde_json::to_string(&rev).unwrap();
        let restored: Revocation = serde_json::from_str(&json).unwrap();
        assert_eq!(rev, restored);
    }

    #[test]
    fn chain_error_serialization() {
        let errors: Vec<ChainError> = vec![
            ChainError::HeadSequenceRegression {
                current_seq: 5,
                attempted_seq: 3,
            },
            ChainError::EmptyChain,
            ChainError::MutationRejected { event_seq: 2 },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let restored: ChainError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, restored);
        }
    }

    // -- Display --

    #[test]
    fn target_type_display() {
        assert_eq!(RevocationTargetType::Key.to_string(), "key");
        assert_eq!(RevocationTargetType::Token.to_string(), "token");
        assert_eq!(RevocationTargetType::Attestation.to_string(), "attestation");
        assert_eq!(RevocationTargetType::Extension.to_string(), "extension");
        assert_eq!(RevocationTargetType::Checkpoint.to_string(), "checkpoint");
    }

    #[test]
    fn reason_display() {
        assert_eq!(RevocationReason::Compromised.to_string(), "compromised");
        assert_eq!(RevocationReason::Expired.to_string(), "expired");
        assert_eq!(RevocationReason::Superseded.to_string(), "superseded");
        assert_eq!(
            RevocationReason::PolicyViolation.to_string(),
            "policy_violation"
        );
        assert_eq!(
            RevocationReason::Administrative.to_string(),
            "administrative"
        );
    }

    #[test]
    fn chain_error_display() {
        let err = ChainError::HeadSequenceRegression {
            current_seq: 5,
            attempted_seq: 3,
        };
        let display = err.to_string();
        assert!(display.contains("5"));
        assert!(display.contains("3"));
    }

    // -- Verify chain with 100+ events --

    #[test]
    fn large_chain_verification() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();

        for i in 0..120u16 {
            let mut target = [0u8; 32];
            target[0] = (i & 0xFF) as u8;
            target[1] = (i >> 8) as u8;

            let rev = make_revocation(
                RevocationTargetType::Token,
                RevocationReason::Expired,
                target,
                &test_revocation_key(),
            );
            chain.append(rev, &sk, &format!("t-large-{i}")).unwrap();
        }

        assert_eq!(chain.len(), 120);
        assert!(chain.verify_chain("t-large-verify").is_ok());

        // Spot-check lookups.
        let mut target_first = [0u8; 32];
        target_first[0] = 0;
        target_first[1] = 0;
        assert!(chain.is_revoked(&EngineObjectId(target_first)));

        let mut target_last = [0u8; 32];
        target_last[0] = 119;
        target_last[1] = 0;
        assert!(chain.is_revoked(&EngineObjectId(target_last)));
    }

    // -- Chain hash determinism --

    #[test]
    fn chain_hash_is_deterministic() {
        let build_chain = || {
            let mut chain = RevocationChain::new(TEST_ZONE);
            let sk = test_signing_key();

            for i in 0..3u8 {
                let rev = make_revocation(
                    RevocationTargetType::Key,
                    RevocationReason::Compromised,
                    [i + 150; 32],
                    &test_revocation_key(),
                );
                chain.append(rev, &sk, &format!("t-det-{i}")).unwrap();
            }
            *chain.chain_hash()
        };

        let hash1 = build_chain();
        let hash2 = build_chain();
        assert_eq!(hash1, hash2);
    }

    // -- Verify chain_mut emits audit --

    #[test]
    fn verify_chain_mut_emits_audit() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();

        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [1; 32],
            &test_revocation_key(),
        );
        chain.append(rev, &sk, "t-vm").unwrap();
        chain.drain_events(); // clear append events

        chain.verify_chain_mut("t-vcm").unwrap();
        let counts = chain.event_counts();
        assert_eq!(counts.get("chain_verified"), Some(&1));
    }

    // -- Enrichment: remaining serde roundtrips --

    #[test]
    fn chain_error_serde_remaining_variants() {
        let errors: Vec<ChainError> = vec![
            ChainError::HashLinkMismatch {
                event_seq: 3,
                expected_prev: Some(EngineObjectId([1; 32])),
                actual_prev: Some(EngineObjectId([2; 32])),
            },
            ChainError::SequenceDiscontinuity {
                expected_seq: 5,
                actual_seq: 8,
            },
            ChainError::InvalidGenesis {
                detail: "bad genesis".to_string(),
            },
            ChainError::ChainIntegrity {
                detail: "hash mismatch".to_string(),
            },
            ChainError::SignatureInvalid {
                detail: "invalid sig".to_string(),
            },
            ChainError::DuplicateTarget {
                target_id: EngineObjectId([42; 32]),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: ChainError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn chain_error_display_remaining_variants() {
        let s = ChainError::HashLinkMismatch {
            event_seq: 3,
            expected_prev: None,
            actual_prev: Some(EngineObjectId([2; 32])),
        }
        .to_string();
        assert!(s.contains("hash link mismatch"));
        assert!(s.contains("3"));

        let s = ChainError::SequenceDiscontinuity {
            expected_seq: 5,
            actual_seq: 8,
        }
        .to_string();
        assert!(s.contains("5"));
        assert!(s.contains("8"));

        let s = ChainError::InvalidGenesis {
            detail: "oops".to_string(),
        }
        .to_string();
        assert!(s.contains("oops"));

        let s = ChainError::ChainIntegrity {
            detail: "corrupt".to_string(),
        }
        .to_string();
        assert!(s.contains("corrupt"));

        let s = ChainError::SignatureInvalid {
            detail: "bad".to_string(),
        }
        .to_string();
        assert!(s.contains("bad"));

        let s = ChainError::DuplicateTarget {
            target_id: EngineObjectId([42; 32]),
        }
        .to_string();
        assert!(s.contains("duplicate"));

        let s = ChainError::MutationRejected { event_seq: 7 }.to_string();
        assert!(s.contains("7"));

        assert_eq!(ChainError::EmptyChain.to_string(), "chain is empty");
    }

    #[test]
    fn revocation_event_serde_roundtrip() {
        let rev = make_revocation(
            RevocationTargetType::Token,
            RevocationReason::Expired,
            [44; 32],
            &test_revocation_key(),
        );
        let event = RevocationEvent {
            event_id: EngineObjectId([11; 32]),
            revocation: rev,
            prev_event: Some(EngineObjectId([10; 32])),
            event_seq: 5,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: RevocationEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    #[test]
    fn revocation_head_serde_roundtrip() {
        let head = RevocationHead {
            head_id: EngineObjectId([20; 32]),
            latest_event: EngineObjectId([19; 32]),
            head_seq: 10,
            chain_hash: ContentHash::compute(b"test-chain-hash"),
            zone: TEST_ZONE.to_string(),
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };
        let json = serde_json::to_string(&head).expect("serialize");
        let restored: RevocationHead = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(head, restored);
    }

    #[test]
    fn chain_event_type_serde_roundtrip() {
        let variants: Vec<ChainEventType> = vec![
            ChainEventType::RevocationAppended {
                event_seq: 3,
                target_id: EngineObjectId([1; 32]),
                target_type: RevocationTargetType::Key,
            },
            ChainEventType::HeadAdvanced {
                old_seq: 2,
                new_seq: 3,
            },
            ChainEventType::ChainVerified { chain_length: 10 },
            ChainEventType::RevocationLookup {
                target_id: EngineObjectId([2; 32]),
                is_revoked: true,
            },
            ChainEventType::AppendRejected {
                reason: "dup".to_string(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialize");
            let restored: ChainEventType = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*v, restored);
        }
    }

    #[test]
    fn chain_event_serde_roundtrip() {
        let event = ChainEvent {
            event_type: ChainEventType::HeadAdvanced {
                old_seq: 0,
                new_seq: 1,
            },
            zone: TEST_ZONE.to_string(),
            trace_id: "t-serde".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: ChainEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    #[test]
    fn revocation_event_content_hash_deterministic() {
        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [77; 32],
            &test_revocation_key(),
        );
        let event = RevocationEvent {
            event_id: EngineObjectId([11; 32]),
            revocation: rev,
            prev_event: None,
            event_seq: 0,
        };
        let h1 = event.content_hash();
        let h2 = event.content_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn revocation_target_type_ordering() {
        assert!(RevocationTargetType::Key < RevocationTargetType::Token);
        assert!(RevocationTargetType::Token < RevocationTargetType::Attestation);
    }

    #[test]
    fn revocation_reason_ordering() {
        assert!(RevocationReason::Compromised < RevocationReason::Expired);
        assert!(RevocationReason::Expired < RevocationReason::Superseded);
    }

    #[test]
    fn head_advanced_event_emitted_on_second_append() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();

        let rev1 = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [1; 32],
            &test_revocation_key(),
        );
        chain.append(rev1, &sk, "t-h1").unwrap();
        chain.drain_events();

        let rev2 = make_revocation(
            RevocationTargetType::Token,
            RevocationReason::Expired,
            [2; 32],
            &test_revocation_key(),
        );
        chain.append(rev2, &sk, "t-h2").unwrap();

        let events = chain.drain_events();
        assert!(events.iter().any(|e| matches!(
            &e.event_type,
            ChainEventType::HeadAdvanced {
                old_seq: 0,
                new_seq: 1,
            }
        )));
    }

    // -----------------------------------------------------------------------
    // Enrichment batch — PearlTower 2026-02-25
    // -----------------------------------------------------------------------

    #[test]
    fn revocation_target_type_display_uniqueness_btreeset() {
        let types = [
            RevocationTargetType::Key,
            RevocationTargetType::Token,
            RevocationTargetType::Attestation,
            RevocationTargetType::Extension,
            RevocationTargetType::Checkpoint,
        ];
        let mut displays = std::collections::BTreeSet::new();
        for t in &types {
            displays.insert(t.to_string());
        }
        assert_eq!(
            displays.len(),
            5,
            "all RevocationTargetType variants produce distinct Display strings"
        );
    }

    #[test]
    fn revocation_reason_display_uniqueness_btreeset() {
        let reasons = [
            RevocationReason::Compromised,
            RevocationReason::Expired,
            RevocationReason::Superseded,
            RevocationReason::PolicyViolation,
            RevocationReason::Administrative,
        ];
        let mut displays = std::collections::BTreeSet::new();
        for r in &reasons {
            displays.insert(r.to_string());
        }
        assert_eq!(
            displays.len(),
            5,
            "all RevocationReason variants produce distinct Display strings"
        );
    }

    #[test]
    fn revocation_serde_roundtrip() {
        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [1; 32],
            &test_revocation_key(),
        );
        let json = serde_json::to_string(&rev).unwrap();
        let back: Revocation = serde_json::from_str(&json).unwrap();
        assert_eq!(rev, back);
    }

    #[test]
    fn chain_hash_changes_on_second_append() {
        let sk = test_signing_key();
        let mut chain = RevocationChain::new(TEST_ZONE);

        let rev1 = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [1; 32],
            &test_revocation_key(),
        );
        chain.append(rev1, &sk, "trace-1").unwrap();
        let hash_after_first = chain.head().unwrap().chain_hash;

        let rev2 = make_revocation(
            RevocationTargetType::Token,
            RevocationReason::Expired,
            [3; 32],
            &test_revocation_key(),
        );
        chain.append(rev2, &sk, "trace-2").unwrap();
        let hash_after_second = chain.head().unwrap().chain_hash;

        assert_ne!(
            hash_after_first, hash_after_second,
            "chain_hash must change after appending a revocation"
        );
    }

    #[test]
    fn schema_functions_are_deterministic() {
        let s1 = revocation_schema();
        let s2 = revocation_schema();
        assert_eq!(s1, s2);

        let es1 = revocation_event_schema();
        let es2 = revocation_event_schema();
        assert_eq!(es1, es2);

        let hs1 = revocation_head_schema();
        let hs2 = revocation_head_schema();
        assert_eq!(hs1, hs2);
    }

    #[test]
    fn revocation_target_type_serde_roundtrip() {
        for t in [
            RevocationTargetType::Key,
            RevocationTargetType::Token,
            RevocationTargetType::Attestation,
            RevocationTargetType::Extension,
            RevocationTargetType::Checkpoint,
        ] {
            let json = serde_json::to_string(&t).unwrap();
            let back: RevocationTargetType = serde_json::from_str(&json).unwrap();
            assert_eq!(t, back);
        }
    }

    #[test]
    fn revocation_reason_serde_roundtrip() {
        for r in [
            RevocationReason::Compromised,
            RevocationReason::Expired,
            RevocationReason::Superseded,
            RevocationReason::PolicyViolation,
            RevocationReason::Administrative,
        ] {
            let json = serde_json::to_string(&r).unwrap();
            let back: RevocationReason = serde_json::from_str(&json).unwrap();
            assert_eq!(r, back);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: PearlTower 2026-02-26
    // -----------------------------------------------------------------------

    #[test]
    fn zone_accessor_returns_constructor_zone() {
        let chain = RevocationChain::new("my-zone");
        assert_eq!(chain.zone(), "my-zone");
    }

    #[test]
    fn chain_hash_accessor_matches_head_chain_hash() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();
        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [77; 32],
            &test_revocation_key(),
        );
        chain.append(rev, &sk, "t-hash").unwrap();
        assert_eq!(chain.chain_hash(), &chain.head().unwrap().chain_hash);
    }

    #[test]
    fn event_counts_tracks_all_types() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();

        // Append two events — should produce: 2 appended, 1 head_advanced
        let rev1 = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [1; 32],
            &test_revocation_key(),
        );
        chain.append(rev1, &sk, "t-1").unwrap();

        let rev2 = make_revocation(
            RevocationTargetType::Token,
            RevocationReason::Expired,
            [2; 32],
            &test_revocation_key(),
        );
        chain.append(rev2, &sk, "t-2").unwrap();

        // Trigger a rejection with a duplicate
        let rev_dup = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Administrative,
            [1; 32],
            &test_revocation_key(),
        );
        let _ = chain.append(rev_dup, &sk, "t-dup");

        // Audited lookup
        chain.is_revoked_audited(&EngineObjectId([1; 32]), "t-lk");

        // Verify chain
        chain.verify_chain_mut("t-verify").unwrap();

        let counts = chain.event_counts();
        assert_eq!(counts.get("revocation_appended"), Some(&2));
        assert_eq!(counts.get("head_advanced"), Some(&1));
        assert_eq!(counts.get("append_rejected"), Some(&1));
        assert_eq!(counts.get("revocation_lookup"), Some(&1));
        assert_eq!(counts.get("chain_verified"), Some(&1));
    }

    #[test]
    fn get_event_out_of_range_returns_none() {
        let chain = RevocationChain::new(TEST_ZONE);
        assert!(chain.get_event(0).is_none());
        assert!(chain.get_event(999).is_none());
    }

    #[test]
    fn lookup_revocation_returns_none_for_non_revoked() {
        let chain = RevocationChain::new(TEST_ZONE);
        assert!(chain.lookup_revocation(&EngineObjectId([88; 32])).is_none());
    }

    #[test]
    fn chain_error_implements_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(ChainError::EmptyChain);
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn events_accessor_returns_all_events() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();

        for i in 0..3u8 {
            let rev = make_revocation(
                RevocationTargetType::Token,
                RevocationReason::Expired,
                [i + 50; 32],
                &test_revocation_key(),
            );
            chain.append(rev, &sk, &format!("t-{i}")).unwrap();
        }

        let events = chain.events();
        assert_eq!(events.len(), 3);
        for (i, event) in events.iter().enumerate() {
            assert_eq!(event.event_seq, i as u64);
        }
    }

    #[test]
    fn rebuild_detects_duplicate_target_in_events() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();

        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [1; 32],
            &test_revocation_key(),
        );
        chain.append(rev, &sk, "t-1").unwrap();

        // Tamper: create a second event with same target_id
        let mut events = chain.events().to_vec();
        let mut dup_event = events[0].clone();
        dup_event.event_seq = 1;
        dup_event.prev_event = Some(events[0].event_id.clone());
        events.push(dup_event);

        let err = RevocationChain::rebuild_from_events(TEST_ZONE, events, None).unwrap_err();
        assert!(matches!(err, ChainError::DuplicateTarget { .. }));
    }

    #[test]
    fn schema_ids_are_deterministic() {
        let s1 = revocation_schema_id();
        let s2 = revocation_schema_id();
        assert_eq!(s1, s2);

        let es1 = revocation_event_schema_id();
        let es2 = revocation_event_schema_id();
        assert_eq!(es1, es2);

        let hs1 = revocation_head_schema_id();
        let hs2 = revocation_head_schema_id();
        assert_eq!(hs1, hs2);
    }

    #[test]
    fn revocation_event_canonical_bytes_differ_for_different_events() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();

        let rev1 = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [1; 32],
            &test_revocation_key(),
        );
        chain.append(rev1, &sk, "t-1").unwrap();

        let rev2 = make_revocation(
            RevocationTargetType::Token,
            RevocationReason::Expired,
            [2; 32],
            &test_revocation_key(),
        );
        chain.append(rev2, &sk, "t-2").unwrap();

        let b1 = chain.get_event(0).unwrap().canonical_bytes();
        let b2 = chain.get_event(1).unwrap().canonical_bytes();
        assert_ne!(b1, b2);
    }

    #[test]
    fn revocation_ordering_all_variants() {
        let variants = [
            RevocationTargetType::Key,
            RevocationTargetType::Token,
            RevocationTargetType::Attestation,
            RevocationTargetType::Extension,
            RevocationTargetType::Checkpoint,
        ];
        // Verify Ord is implemented and is consistent
        let mut sorted = variants;
        sorted.sort();
        assert_eq!(sorted.len(), 5);
    }

    // -- Enrichment: PearlTower 2026-02-26 session 3 --

    #[test]
    fn schema_hashes_are_all_distinct() {
        let s1 = revocation_schema();
        let s2 = revocation_event_schema();
        let s3 = revocation_head_schema();
        assert_ne!(s1, s2);
        assert_ne!(s2, s3);
        assert_ne!(s1, s3);
    }

    #[test]
    fn schema_ids_are_all_distinct() {
        let s1 = revocation_schema_id();
        let s2 = revocation_event_schema_id();
        let s3 = revocation_head_schema_id();
        assert_ne!(s1, s2);
        assert_ne!(s2, s3);
        assert_ne!(s1, s3);
    }

    #[test]
    fn rebuild_from_empty_events_no_head_succeeds() {
        let chain = RevocationChain::rebuild_from_events(TEST_ZONE, vec![], None).unwrap();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
        assert!(chain.head().is_none());
    }

    #[test]
    fn rebuild_from_empty_events_with_head_fails() {
        let head = RevocationHead {
            head_id: EngineObjectId([20; 32]),
            latest_event: EngineObjectId([19; 32]),
            head_seq: 0,
            chain_hash: ContentHash::compute(b"x"),
            zone: TEST_ZONE.to_string(),
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };
        let err = RevocationChain::rebuild_from_events(TEST_ZONE, vec![], Some(head)).unwrap_err();
        assert!(matches!(err, ChainError::ChainIntegrity { .. }));
        assert!(err.to_string().contains("empty chain must not have a head"));
    }

    #[test]
    fn verify_append_genesis_with_prev_event_fails_hash_link() {
        // On an empty chain, expected_prev = None. Providing prev_event = Some
        // triggers HashLinkMismatch because the hash link check precedes genesis
        // validation.
        let chain = RevocationChain::new(TEST_ZONE);
        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [1; 32],
            &test_revocation_key(),
        );
        let event = RevocationEvent {
            event_id: EngineObjectId([0xAA; 32]),
            revocation: rev,
            prev_event: Some(EngineObjectId([0xFF; 32])),
            event_seq: 0,
        };
        let err = chain.verify_append(&event).unwrap_err();
        assert!(matches!(err, ChainError::HashLinkMismatch { .. }));
    }

    #[test]
    fn chain_error_head_regression_display_content() {
        let err = ChainError::HeadSequenceRegression {
            current_seq: 10,
            attempted_seq: 5,
        };
        let s = err.to_string();
        assert!(s.contains("head sequence regression"));
        assert!(s.contains("current=10"));
        assert!(s.contains("attempted=5"));
    }

    #[test]
    fn revocation_preimage_bytes_deterministic() {
        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [1; 32],
            &test_revocation_key(),
        );
        let p1 = rev.preimage_bytes();
        let p2 = rev.preimage_bytes();
        assert_eq!(p1, p2);
        assert!(!p1.is_empty());
    }

    #[test]
    fn revocation_head_preimage_bytes_deterministic() {
        let head = RevocationHead {
            head_id: EngineObjectId([20; 32]),
            latest_event: EngineObjectId([19; 32]),
            head_seq: 5,
            chain_hash: ContentHash::compute(b"test"),
            zone: TEST_ZONE.to_string(),
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };
        let p1 = head.preimage_bytes();
        let p2 = head.preimage_bytes();
        assert_eq!(p1, p2);
        assert!(!p1.is_empty());
    }

    #[test]
    fn rebuild_from_events_detects_genesis_seq_mismatch() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();
        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [1; 32],
            &test_revocation_key(),
        );
        chain.append(rev, &sk, "t").unwrap();

        let mut events = chain.events().to_vec();
        events[0].event_seq = 5; // should be 0

        let err = RevocationChain::rebuild_from_events(TEST_ZONE, events, None).unwrap_err();
        assert!(matches!(err, ChainError::SequenceDiscontinuity { .. }));
    }

    #[test]
    fn empty_chain_hash_is_genesis_sentinel() {
        let chain = RevocationChain::new(TEST_ZONE);
        let expected = ContentHash::compute(b"revocation-chain-genesis");
        assert_eq!(*chain.chain_hash(), expected);
    }

    #[test]
    fn rebuild_from_events_detects_chain_hash_mismatch() {
        let mut chain = RevocationChain::new(TEST_ZONE);
        let sk = test_signing_key();
        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [1; 32],
            &test_revocation_key(),
        );
        chain.append(rev, &sk, "t").unwrap();

        let events = chain.events().to_vec();
        let mut head = chain.head().cloned().unwrap();
        head.chain_hash = ContentHash::compute(b"tampered"); // wrong hash

        let err = RevocationChain::rebuild_from_events(TEST_ZONE, events, Some(head)).unwrap_err();
        assert!(matches!(err, ChainError::ChainIntegrity { .. }));
        assert!(err.to_string().contains("chain_hash"));
    }

    #[test]
    fn revocation_signature_domain_is_revocation() {
        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [1; 32],
            &test_revocation_key(),
        );
        assert_eq!(rev.signature_domain(), ObjectDomain::Revocation);
    }

    #[test]
    fn revocation_head_signature_domain_is_revocation() {
        let head = RevocationHead {
            head_id: EngineObjectId([20; 32]),
            latest_event: EngineObjectId([19; 32]),
            head_seq: 0,
            chain_hash: ContentHash::compute(b"x"),
            zone: TEST_ZONE.to_string(),
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };
        assert_eq!(head.signature_domain(), ObjectDomain::Revocation);
    }
}
