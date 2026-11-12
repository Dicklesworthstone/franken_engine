//! Legacy-v1.0 reconstruction receipts for erasure-coded fleet gossip.
//!
//! Track II (`bd-cixqu.35.2`) — when a fleet node reconstructs an original
//! payload from a `k`-of-`n` erasure shard set (see
//! [`crate::fleet_immune_protocol`]'s erasure-coded gossip lane), it must be
//! able to emit a self-consistency record of *what it reconstructed and from
//! which shards*. That record is a [`ReconstructionReceipt`]:
//!
//! - **Commitment to the contributing shards.** The receipt binds the shard
//!   indices, roles, per-shard content hashes, and origin identities that
//!   materially fed the reconstruction, plus the coding parameters used.
//! - **Legacy-v1.0 authentication carrier.** The receipt carries the same
//!   NodeId-keyed tag used by legacy fleet messages over a length-prefixed
//!   canonical commitment. Because NodeId bytes are public, this detects
//!   accidental corruption but does **not** establish signer authority or
//!   non-repudiation. Trusted Ed25519 admission is part of `bd-q8x8x.6`.
//! - **Verification data usable without the original payload.**
//!   [`ReconstructionReceipt::verify`] validates the receipt's internal
//!   cryptographic and structural consistency with *no* access to the
//!   original data and without performing reconstruction; a party that also
//!   holds the shards can escalate to
//!   [`ReconstructionReceipt::verify_against_shards`], which re-derives the
//!   shard commitments (and optionally re-runs reconstruction) from the raw
//!   fragments.
//!
//! ## Honest coding-scheme labeling
//!
//! The gossip erasure lane in [`crate::fleet_immune_protocol`] is a systematic
//! **XOR single-parity** code (one parity shard recovers at most one missing
//! data shard), not a full Reed–Solomon code over GF(2^8). Receipts record the
//! *actual* scheme identifier ([`XOR_SINGLE_PARITY_SCHEME`]) and the real
//! `(k, n)` plan; they never fabricate Reed–Solomon polynomial coefficients
//! that the implementation does not compute. If the erasure lane is later
//! upgraded to a wider code, a new scheme identifier and receipt schema
//! version are introduced rather than back-dating this one.
//!
//! ## Determinism discipline
//!
//! Every variable-length field mixed into the receipt commitment is
//! length-prefixed (`u64` big-endian length, then bytes) before hashing, and
//! contributing shards are emitted in a canonical shard-index order. This
//! mirrors `compute_erasure_shard_hash` in the fleet protocol so two honest
//! implementations agree byte-for-byte on the commitment. Fixed-width scalars
//! are big-endian; the `Option<u16>` recovery slot carries an explicit tag
//! byte so `None` cannot collide with `Some(0)`.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{CanonicalValue, SchemaHash};
use crate::engine_object_id::ObjectDomain;
use crate::fleet_immune_protocol::{
    DurableFleetVerificationRegistry, ErasureCodingPlan, ErasureShard, ErasureShardRole,
    FLEET_V2_MAX_ERASURE_SHARDS, FleetErasureV2Error, FleetHistoricalAcceptanceContext,
    FleetIdentityError, FleetRegistryAnchorAuthority, FleetSignaturePreimageV2, FleetSignatureV2,
    FleetSigner, FleetSigningIdentity, FleetV2IngressBudget, MessageSignature, NodeId,
    ProtocolError, ProtocolVersion, SignedErasureShardV2, canonical_content_hash,
    canonical_protocol_version, canonical_signature_identity, canonical_string_map,
    fleet_signature_preimage_v2_sealed, reconstruct_erasure_payload, validate_exact_message_signer,
    validate_fleet_node_id, validate_fleet_signing_identity_ingress, validate_fleet_v2_frame_len,
    validate_legacy_erasure_shard_set, validate_protocol_v2,
};
use crate::hash_tiers::{AuthenticityHash, ContentHash};
use crate::security_epoch::SecurityEpoch;

/// Schema identifier stamped into every legacy-v1 receipt for drift detection.
pub const RECONSTRUCTION_RECEIPT_SCHEMA_ID: &str = "franken-engine.reconstruction-receipt.v1";

/// Schema identifier stamped into every protocol-v2 detached-signed receipt.
pub const RECONSTRUCTION_RECEIPT_SCHEMA_ID_V2: &str = "franken-engine.reconstruction-receipt.v2";

/// Schema identifier stamped into persisted protocol-v2 verified receipt ledgers.
pub const TRUSTED_RECONSTRUCTION_RECEIPT_LEDGER_SCHEMA_ID_V2: &str =
    "franken-engine.trusted-reconstruction-receipt-ledger.v2";

const RECONSTRUCTION_RECEIPT_SIGNATURE_SCHEMA_V2: &[u8] = b"FrankenEngine.FleetReconstructionReceipt.v2|schema_id:string|epoch:u64|shard_set_id:string|payload_hash:bytes32|payload_len:u64|coding_scheme:string|plan:{data_shards:u64,total_shards:u64}|contributing_shards:array<{origin_node:string,role:u64,sequence:u64,shard_hash:bytes32,shard_index:u64}>|recovered_shard_index:{present:bool,index:u64}|reconstructing_node:string|reconstruction_timestamp_ns:u64|receipt_commitment:bytes32|signature:{fleet_authority_id:bytes32,signer:string,key_id:bytes32,key_sequence:u64,signature:bytes64-sentinel}|protocol_version:{major:u64,minor:u64}|extensions:map<string,string>";

static RECONSTRUCTION_RECEIPT_SIGNATURE_SCHEMA_HASH_V2: LazyLock<SchemaHash> =
    LazyLock::new(|| SchemaHash::from_definition(RECONSTRUCTION_RECEIPT_SIGNATURE_SCHEMA_V2));

/// Identifier for the erasure coding scheme the gossip lane actually uses.
///
/// The lane is systematic XOR single-parity — deliberately *not* claimed to be
/// Reed–Solomon (see the module docs).
pub const XOR_SINGLE_PARITY_SCHEME: &str = "xor-single-parity-v1";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors arising from reconstruction-receipt generation or verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiptError {
    /// No shards were supplied to reconstruct.
    EmptyShardSet,
    /// The underlying erasure reconstruction failed.
    ReconstructionFailed {
        shard_set_id: String,
        reason: String,
    },
    /// The receipt's `schema_id` is not the expected identifier.
    UnknownSchema { found: String },
    /// The receipt's coding scheme is not one this verifier understands.
    UnknownScheme { found: String },
    /// The receipt's structural invariants are internally inconsistent.
    InconsistentStructure { reason: String },
    /// The recomputed commitment does not match the stored commitment.
    CommitmentMismatch,
    /// The signer identity does not match the reconstructing node.
    SignerMismatch,
    /// The legacy self-consistency tag does not match the commitment.
    InvalidSignature,
    /// A contributing shard was absent from the supplied verification set.
    MissingShardForVerification { shard_index: u16 },
    /// A supplied shard's recomputed commitment disagrees with the receipt.
    ShardCommitmentMismatch { shard_index: u16 },
    /// A persisted ledger contained the same receipt commitment more than once.
    DuplicateReceiptCommitment { commitment: ContentHash },
}

impl fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyShardSet => write!(f, "no shards supplied for reconstruction receipt"),
            Self::ReconstructionFailed {
                shard_set_id,
                reason,
            } => write!(f, "reconstruction failed for {shard_set_id}: {reason}"),
            Self::UnknownSchema { found } => {
                write!(f, "unexpected receipt schema id: {found}")
            }
            Self::UnknownScheme { found } => {
                write!(f, "unsupported coding scheme: {found}")
            }
            Self::InconsistentStructure { reason } => {
                write!(f, "inconsistent receipt structure: {reason}")
            }
            Self::CommitmentMismatch => write!(f, "receipt commitment mismatch"),
            Self::SignerMismatch => write!(f, "receipt signer is not the reconstructing node"),
            Self::InvalidSignature => write!(f, "receipt signature verification failed"),
            Self::MissingShardForVerification { shard_index } => {
                write!(f, "shard {shard_index} missing from verification set")
            }
            Self::ShardCommitmentMismatch { shard_index } => {
                write!(f, "shard {shard_index} commitment mismatch")
            }
            Self::DuplicateReceiptCommitment { commitment } => {
                write!(
                    f,
                    "duplicate reconstruction receipt commitment {commitment}"
                )
            }
        }
    }
}

impl std::error::Error for ReceiptError {}

// ---------------------------------------------------------------------------
// ShardCommitment
// ---------------------------------------------------------------------------

/// A cryptographic commitment to one shard that contributed to a
/// reconstruction.
///
/// The commitment is intentionally the shard's *hash and identity*, not its
/// payload bytes, so a receipt can be verified without leaking or transmitting
/// the erasure fragments themselves.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShardCommitment {
    /// Index of the shard within its set.
    pub shard_index: u16,
    /// Whether the shard is a systematic data shard or an XOR parity shard.
    pub role: ErasureShardRole,
    /// The shard's canonical content hash (as recorded on the `ErasureShard`).
    pub shard_hash: ContentHash,
    /// The node that originally encoded the shard.
    pub origin_node: NodeId,
    /// The shard's per-origin sequence number.
    pub sequence: u64,
}

impl ShardCommitment {
    fn from_shard(shard: &ErasureShard) -> Self {
        Self {
            shard_index: shard.shard_index,
            role: shard.role,
            shard_hash: shard.shard_hash,
            origin_node: shard.origin_node.clone(),
            sequence: shard.sequence,
        }
    }
}

// ---------------------------------------------------------------------------
// ReconstructionReceipt
// ---------------------------------------------------------------------------

/// A legacy-v1.0 self-consistency record for a payload reconstruction from a
/// specific set of erasure shards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconstructionReceipt {
    /// Schema identifier for drift detection.
    pub schema_id: String,
    /// Stable identifier shared by all shards of the reconstructed set.
    pub shard_set_id: String,
    /// Content hash of the reconstructed original payload.
    pub payload_hash: ContentHash,
    /// Length in bytes of the reconstructed original payload.
    pub payload_len: u64,
    /// Identifier of the erasure coding scheme actually used.
    pub coding_scheme: String,
    /// The `(k, n)` coding plan the shard set was produced under.
    pub plan: ErasureCodingPlan,
    /// Canonically-ordered commitments to the shards that materially fed the
    /// reconstruction (present data shards plus the parity shard iff a data
    /// shard was recovered).
    pub contributing_shards: Vec<ShardCommitment>,
    /// The data-shard index recovered from parity, if any (`None` when every
    /// data shard was directly present).
    pub recovered_shard_index: Option<u16>,
    /// Claimed identity of the node that performed the reconstruction.
    pub reconstructing_node: NodeId,
    /// Reconstruction timestamp in nanoseconds.
    pub reconstruction_timestamp_ns: u64,
    /// Content hash over the length-prefixed canonical receipt preimage.
    pub receipt_commitment: ContentHash,
    /// Legacy public-NodeId keyed tag over the commitment, attributed to the
    /// reconstructing node but not proof of its authority.
    pub signature: MessageSignature,
    /// Protocol version.
    pub protocol_version: ProtocolVersion,
    /// Forward-compatible extension fields.
    pub extensions: BTreeMap<String, String>,
}

impl ReconstructionReceipt {
    /// Recompute the receipt commitment from the receipt's own fields.
    ///
    /// This excludes `receipt_commitment` and `signature` (which are derived
    /// from it), so it is the canonical preimage a verifier recomputes.
    pub fn compute_commitment(&self) -> ContentHash {
        let mut buf = Vec::new();
        append_bytes(&mut buf, self.schema_id.as_bytes());
        append_bytes(&mut buf, self.shard_set_id.as_bytes());
        buf.extend_from_slice(self.payload_hash.as_bytes());
        buf.extend_from_slice(&self.payload_len.to_be_bytes());
        append_bytes(&mut buf, self.coding_scheme.as_bytes());
        buf.extend_from_slice(&self.plan.data_shards.to_be_bytes());
        buf.extend_from_slice(&self.plan.total_shards.to_be_bytes());
        buf.extend_from_slice(&(self.contributing_shards.len() as u64).to_be_bytes());
        for shard in &self.contributing_shards {
            buf.extend_from_slice(&shard.shard_index.to_be_bytes());
            buf.push(role_tag(shard.role));
            buf.extend_from_slice(shard.shard_hash.as_bytes());
            append_bytes(&mut buf, shard.origin_node.as_str().as_bytes());
            buf.extend_from_slice(&shard.sequence.to_be_bytes());
        }
        match self.recovered_shard_index {
            None => buf.push(0),
            Some(index) => {
                buf.push(1);
                buf.extend_from_slice(&index.to_be_bytes());
            }
        }
        append_bytes(&mut buf, self.reconstructing_node.as_str().as_bytes());
        buf.extend_from_slice(&self.reconstruction_timestamp_ns.to_be_bytes());
        buf.extend_from_slice(&self.protocol_version.major.to_be_bytes());
        buf.extend_from_slice(&self.protocol_version.minor.to_be_bytes());
        buf.extend_from_slice(&(self.extensions.len() as u64).to_be_bytes());
        for (key, value) in &self.extensions {
            append_bytes(&mut buf, key.as_bytes());
            append_bytes(&mut buf, value.as_bytes());
        }
        ContentHash::compute(&buf)
    }

    /// Recompute the signature tag the reconstructing node would produce over a
    /// given commitment.
    fn expected_signature_tag(&self, commitment: &ContentHash) -> AuthenticityHash {
        AuthenticityHash::compute_keyed(
            self.reconstructing_node.as_str().as_bytes(),
            commitment.as_bytes(),
        )
    }

    /// Verify the receipt's internal cryptographic and structural consistency.
    ///
    /// Requires neither the original payload nor the erasure shards: this is
    /// the "validate without performing reconstruction" path other fleet nodes
    /// use. It confirms the schema and scheme, that the structural invariants
    /// hold, that the stored commitment matches the fields, and that the
    /// legacy tag is self-consistent with the reconstructing-node metadata.
    /// This method does not consult trusted verification authority.
    pub fn verify(&self) -> Result<(), ReceiptError> {
        if self.schema_id != RECONSTRUCTION_RECEIPT_SCHEMA_ID {
            return Err(ReceiptError::UnknownSchema {
                found: self.schema_id.clone(),
            });
        }
        if self.coding_scheme != XOR_SINGLE_PARITY_SCHEME {
            return Err(ReceiptError::UnknownScheme {
                found: self.coding_scheme.clone(),
            });
        }
        self.check_structure()?;
        if self.signature.signer != self.reconstructing_node {
            return Err(ReceiptError::SignerMismatch);
        }
        let recomputed = self.compute_commitment();
        if !recomputed.constant_time_eq(&self.receipt_commitment) {
            return Err(ReceiptError::CommitmentMismatch);
        }
        let expected_tag = self.expected_signature_tag(&self.receipt_commitment);
        if !expected_tag.constant_time_eq(&self.signature.hash) {
            return Err(ReceiptError::InvalidSignature);
        }
        Ok(())
    }

    /// Validate the structural invariants that must hold regardless of any
    /// external data.
    fn check_structure(&self) -> Result<(), ReceiptError> {
        if self.protocol_version != ProtocolVersion::V1 {
            return Err(ReceiptError::InconsistentStructure {
                reason: "legacy receipt requires exact protocol version 1.0".to_string(),
            });
        }

        // Coding plan must be well-formed.
        if self.plan.data_shards == 0
            || self.plan.total_shards == 0
            || self.plan.data_shards > self.plan.total_shards
        {
            return Err(ReceiptError::InconsistentStructure {
                reason: "invalid coding plan".to_string(),
            });
        }

        // Contributing shards must be in canonical (strictly increasing index)
        // order and role-consistent with their index.
        let mut previous: Option<u16> = None;
        let mut data_indices: BTreeSet<u16> = BTreeSet::new();
        let mut parity_count = 0usize;
        for shard in &self.contributing_shards {
            if let Some(prev) = previous
                && shard.shard_index <= prev
            {
                return Err(ReceiptError::InconsistentStructure {
                    reason: "contributing shards not in canonical order".to_string(),
                });
            }
            previous = Some(shard.shard_index);

            match shard.role {
                ErasureShardRole::Data => {
                    if shard.shard_index >= self.plan.data_shards {
                        return Err(ReceiptError::InconsistentStructure {
                            reason: "data shard index outside data range".to_string(),
                        });
                    }
                    data_indices.insert(shard.shard_index);
                }
                ErasureShardRole::Parity => {
                    if shard.shard_index < self.plan.data_shards {
                        return Err(ReceiptError::InconsistentStructure {
                            reason: "parity shard index overlaps data range".to_string(),
                        });
                    }
                    if shard.shard_index >= self.plan.total_shards {
                        return Err(ReceiptError::InconsistentStructure {
                            reason: "parity shard index outside total shard range".to_string(),
                        });
                    }
                    parity_count += 1;
                }
            }
        }

        // Recovery consistency: a recovered index must be a real data slot that
        // is *not* directly present, and recovery requires a parity shard.
        match self.recovered_shard_index {
            Some(index) => {
                if index >= self.plan.data_shards {
                    return Err(ReceiptError::InconsistentStructure {
                        reason: "recovered index outside data range".to_string(),
                    });
                }
                if data_indices.contains(&index) {
                    return Err(ReceiptError::InconsistentStructure {
                        reason: "recovered index also present as a data shard".to_string(),
                    });
                }
                if parity_count != 1 {
                    return Err(ReceiptError::InconsistentStructure {
                        reason: "recovery requires exactly one parity shard".to_string(),
                    });
                }
                if data_indices.len() != usize::from(self.plan.data_shards) - 1 {
                    return Err(ReceiptError::InconsistentStructure {
                        reason: "recovery requires exactly one missing data shard".to_string(),
                    });
                }
            }
            None => {
                if parity_count != 0 {
                    return Err(ReceiptError::InconsistentStructure {
                        reason: "parity shard committed without recovery".to_string(),
                    });
                }
                if data_indices.len() != usize::from(self.plan.data_shards) {
                    return Err(ReceiptError::InconsistentStructure {
                        reason: "no recovery claimed but data shards incomplete".to_string(),
                    });
                }
            }
        }

        if self.contributing_shards.len() != usize::from(self.plan.data_shards) {
            return Err(ReceiptError::InconsistentStructure {
                reason: "receipt must commit to exactly data_shards contributors".to_string(),
            });
        }

        // Reconstruction admits one origin and one sequence/index base for
        // the entire shard set, including the parity shard used for recovery.
        // These fields are present in every commitment, so intrinsic receipt
        // validation and ledger restoration must reject impossible provenance
        // even when a caller has recomputed the legacy commitment and tag.
        // The nonzero plan and exact cardinality above ensure a first shard.
        let first = &self.contributing_shards[0];
        let sequence_base = first
            .sequence
            .checked_sub(u64::from(first.shard_index))
            .ok_or_else(|| ReceiptError::InconsistentStructure {
                reason: "contributing shard sequence precedes its index".to_string(),
            })?;
        for shard in &self.contributing_shards {
            if shard.origin_node != first.origin_node
                || shard.sequence.checked_sub(u64::from(shard.shard_index)) != Some(sequence_base)
            {
                return Err(ReceiptError::InconsistentStructure {
                    reason: "contributing shards have inconsistent origin or sequence base"
                        .to_string(),
                });
            }
        }

        Ok(())
    }

    /// Verify the receipt *and* cross-check every committed shard against a
    /// supplied shard set, optionally re-running reconstruction.
    ///
    /// This is the stronger verification a party performs when it holds the
    /// erasure shards (but not necessarily the original payload): it confirms
    /// each committed shard hash matches a real shard and — when
    /// `reconstruct` is set — that reconstructing from the contributing shards
    /// reproduces the committed payload hash.
    pub fn verify_against_shards(
        &self,
        shards: &[ErasureShard],
        reconstruct: bool,
    ) -> Result<(), ReceiptError> {
        self.verify()?;

        let payload_len =
            usize::try_from(self.payload_len).map_err(|_| ReceiptError::InconsistentStructure {
                reason: "receipt payload length does not fit usize".to_string(),
            })?;
        let expected_shard_payload_len = if payload_len == 0 {
            0
        } else {
            payload_len.div_ceil(usize::from(self.plan.data_shards))
        };

        let mut by_index: BTreeMap<u16, &ErasureShard> = BTreeMap::new();
        for shard in shards {
            // Validate every supplied candidate before duplicate collapse so
            // an invalid exact-index duplicate cannot be hidden behind the
            // first representative in input order.
            validate_legacy_erasure_shard_set(std::slice::from_ref(shard)).map_err(|_| {
                ReceiptError::ShardCommitmentMismatch {
                    shard_index: shard.shard_index,
                }
            })?;
            match by_index.entry(shard.shard_index) {
                Entry::Occupied(entry) => {
                    let existing = *entry.get();
                    if existing.shard_hash != shard.shard_hash
                        || existing.recompute_shard_hash() != shard.recompute_shard_hash()
                        || ShardCommitment::from_shard(existing)
                            != ShardCommitment::from_shard(shard)
                    {
                        return Err(ReceiptError::ShardCommitmentMismatch {
                            shard_index: shard.shard_index,
                        });
                    }
                }
                Entry::Vacant(entry) => {
                    entry.insert(shard);
                }
            }
        }

        for commitment in &self.contributing_shards {
            let shard = by_index.get(&commitment.shard_index).ok_or(
                ReceiptError::MissingShardForVerification {
                    shard_index: commitment.shard_index,
                },
            )?;
            let recomputed = shard.recompute_shard_hash();
            if shard.role != commitment.role
                || shard.origin_node != commitment.origin_node
                || shard.sequence != commitment.sequence
                || !recomputed.constant_time_eq(&commitment.shard_hash)
                || !recomputed.constant_time_eq(&shard.shard_hash)
                || shard.shard_set_id != self.shard_set_id
                || shard.plan != self.plan
                || shard.payload_len != self.payload_len
                || !shard.payload_hash.constant_time_eq(&self.payload_hash)
                || shard.protocol_version != self.protocol_version
                || shard.shard_payload.len() != expected_shard_payload_len
            {
                return Err(ReceiptError::ShardCommitmentMismatch {
                    shard_index: commitment.shard_index,
                });
            }
        }

        let contributing: Vec<ErasureShard> = self
            .contributing_shards
            .iter()
            .filter_map(|commitment| {
                by_index
                    .get(&commitment.shard_index)
                    .map(|shard| (**shard).clone())
            })
            .collect();
        validate_legacy_erasure_shard_set(&contributing).map_err(|error| {
            ReceiptError::ReconstructionFailed {
                shard_set_id: self.shard_set_id.clone(),
                reason: error.to_string(),
            }
        })?;

        if reconstruct {
            let payload = reconstruct_erasure_payload(&contributing).map_err(|err| {
                ReceiptError::ReconstructionFailed {
                    shard_set_id: self.shard_set_id.clone(),
                    reason: err.to_string(),
                }
            })?;
            if !ContentHash::compute(&payload).constant_time_eq(&self.payload_hash) {
                return Err(ReceiptError::CommitmentMismatch);
            }
            let payload_len =
                u64::try_from(payload.len()).map_err(|_| ReceiptError::InconsistentStructure {
                    reason: "reconstructed payload length does not fit u64".to_string(),
                })?;
            if payload_len != self.payload_len {
                return Err(ReceiptError::InconsistentStructure {
                    reason: "reconstructed payload length does not match receipt".to_string(),
                });
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/// Reconstruct a payload from an erasure shard set and emit an intrinsic
/// legacy-v1.0 receipt attributed to `reconstructing_node`.
///
/// Returns the reconstructed payload alongside its receipt. The reconstruction
/// itself is performed by [`reconstruct_erasure_payload`], so the receipt is
/// only produced when reconstruction genuinely succeeds (the payload hash is
/// verified against the shard set's committed `payload_hash` inside that call).
pub fn reconstruct_with_receipt(
    shards: &[ErasureShard],
    reconstructing_node: NodeId,
    reconstruction_timestamp_ns: u64,
) -> Result<(Vec<u8>, ReconstructionReceipt), ReceiptError> {
    let first = shards.first().ok_or(ReceiptError::EmptyShardSet)?;

    let payload = reconstruct_erasure_payload(shards).map_err(|err| match err {
        ProtocolError::ErasureDecodeFailed {
            shard_set_id,
            reason,
        } => ReceiptError::ReconstructionFailed {
            shard_set_id,
            reason,
        },
        other => ReceiptError::ReconstructionFailed {
            shard_set_id: first.shard_set_id.clone(),
            reason: other.to_string(),
        },
    })?;

    let (contributing_shards, recovered_shard_index) = derive_contributing_shards(shards)?;

    let mut receipt = ReconstructionReceipt {
        schema_id: RECONSTRUCTION_RECEIPT_SCHEMA_ID.to_string(),
        shard_set_id: first.shard_set_id.clone(),
        payload_hash: first.payload_hash,
        payload_len: first.payload_len,
        coding_scheme: XOR_SINGLE_PARITY_SCHEME.to_string(),
        plan: first.plan,
        contributing_shards,
        recovered_shard_index,
        reconstructing_node: reconstructing_node.clone(),
        reconstruction_timestamp_ns,
        receipt_commitment: ContentHash::from_bytes([0u8; 32]),
        signature: MessageSignature {
            signer: reconstructing_node.clone(),
            hash: AuthenticityHash::compute_keyed(b"", b""),
        },
        protocol_version: first.protocol_version,
        extensions: BTreeMap::new(),
    };

    let commitment = receipt.compute_commitment();
    let signature_tag = AuthenticityHash::compute_keyed(
        reconstructing_node.as_str().as_bytes(),
        commitment.as_bytes(),
    );
    receipt.receipt_commitment = commitment;
    receipt.signature = MessageSignature {
        signer: reconstructing_node,
        hash: signature_tag,
    };

    Ok((payload, receipt))
}

/// Derive the canonical set of contributing shard commitments and the recovered
/// data-shard index (if any) from a successfully-reconstructed shard set.
///
/// Preconditions: `shards` is non-empty and has already been accepted by
/// [`reconstruct_erasure_payload`], so its metadata is internally consistent.
fn derive_contributing_shards(
    shards: &[ErasureShard],
) -> Result<(Vec<ShardCommitment>, Option<u16>), ReceiptError> {
    let first = shards.first().ok_or(ReceiptError::EmptyShardSet)?;
    let plan = first.plan;

    let mut data_shards: BTreeMap<u16, &ErasureShard> = BTreeMap::new();
    let mut parity_shards: BTreeMap<u16, &ErasureShard> = BTreeMap::new();
    for shard in shards {
        match shard.role {
            ErasureShardRole::Data if shard.shard_index < plan.data_shards => {
                match data_shards.entry(shard.shard_index) {
                    Entry::Occupied(entry) => {
                        if entry.get().shard_hash != shard.shard_hash {
                            return Err(ReceiptError::InconsistentStructure {
                                reason: format!(
                                    "conflicting duplicate data shard {}",
                                    shard.shard_index
                                ),
                            });
                        }
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(shard);
                    }
                }
            }
            ErasureShardRole::Parity if shard.shard_index >= plan.data_shards => {
                match parity_shards.entry(shard.shard_index) {
                    Entry::Occupied(entry) => {
                        if entry.get().shard_hash != shard.shard_hash {
                            return Err(ReceiptError::InconsistentStructure {
                                reason: format!(
                                    "conflicting duplicate parity shard {}",
                                    shard.shard_index
                                ),
                            });
                        }
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(shard);
                    }
                }
            }
            // Out-of-range shards would already have been rejected by
            // reconstruction; ignore defensively.
            _ => {}
        }
    }

    let missing: Vec<u16> = (0..plan.data_shards)
        .filter(|index| !data_shards.contains_key(index))
        .collect();
    let recovered_shard_index = missing.first().copied();

    // Canonical order is ascending shard index; BTreeMap already yields that
    // for data shards, and the parity (if used) has the largest index.
    let mut contributing: Vec<ShardCommitment> = data_shards
        .values()
        .map(|shard| ShardCommitment::from_shard(shard))
        .collect();
    if recovered_shard_index.is_some() {
        // The erasure lane emits identical parity for every parity slot when
        // `n - k > 1`; BTreeMap order deterministically selects the lowest.
        let parity =
            parity_shards
                .values()
                .next()
                .copied()
                .ok_or(ReceiptError::InconsistentStructure {
                    reason: "reconstruction recovered a shard without parity".to_string(),
                })?;
        contributing.push(ShardCommitment::from_shard(parity));
    }
    contributing.sort();

    Ok((contributing, recovered_shard_index))
}

// ---------------------------------------------------------------------------
// Audit ledger
// ---------------------------------------------------------------------------

/// An append-only, dedup-keyed audit ledger of reconstruction receipts.
///
/// Every appended receipt is verified before admission, so a ledger only ever
/// holds receipts that passed [`ReconstructionReceipt::verify`]. Deduplication
/// is keyed on the receipt commitment, so an idempotent re-reconstruction of
/// the same shard set by the same node at the same instant does not double-log.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ReconstructionReceiptLedger {
    receipts: Vec<ReconstructionReceipt>,
    #[serde(skip)]
    seen: BTreeSet<[u8; 32]>,
}

impl<'de> Deserialize<'de> for ReconstructionReceiptLedger {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename = "ReconstructionReceiptLedger")]
        struct WireLedger {
            receipts: Vec<ReconstructionReceipt>,
        }

        let wire = WireLedger::deserialize(deserializer)?;
        let seen = Self::validated_seen(&wire.receipts).map_err(serde::de::Error::custom)?;
        Ok(Self {
            receipts: wire.receipts,
            seen,
        })
    }
}

impl ReconstructionReceiptLedger {
    /// Create an empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify every receipt and build a duplicate-free commitment index.
    ///
    /// This validates the current receipt schema's self-contained structural,
    /// commitment, and legacy-tag consistency contract. Trusted-key
    /// authorization is context supplied by the protocol-v2 receipt cutover,
    /// not by Serde.
    fn validated_seen(
        receipts: &[ReconstructionReceipt],
    ) -> Result<BTreeSet<[u8; 32]>, ReceiptError> {
        let mut seen = BTreeSet::new();
        for receipt in receipts {
            receipt.verify()?;
            let key = *receipt.receipt_commitment.as_bytes();
            if !seen.insert(key) {
                return Err(ReceiptError::DuplicateReceiptCommitment {
                    commitment: receipt.receipt_commitment,
                });
            }
        }
        Ok(seen)
    }

    /// Verify and record a receipt.
    ///
    /// Returns `Ok(true)` if the receipt was newly recorded, `Ok(false)` if an
    /// identical receipt (by commitment) was already present, and `Err` if the
    /// receipt fails verification (in which case it is never admitted).
    pub fn record(&mut self, receipt: ReconstructionReceipt) -> Result<bool, ReceiptError> {
        receipt.verify()?;
        let key = *receipt.receipt_commitment.as_bytes();
        if self.seen.contains(&key) {
            return Ok(false);
        }
        self.seen.insert(key);
        self.receipts.push(receipt);
        Ok(true)
    }

    /// Whether a receipt with the given commitment is present.
    pub fn contains(&self, commitment: &ContentHash) -> bool {
        self.seen.contains(commitment.as_bytes())
    }

    /// Number of receipts recorded.
    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    /// Whether the ledger is empty.
    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    /// The recorded receipts in insertion order.
    pub fn receipts(&self) -> &[ReconstructionReceipt] {
        &self.receipts
    }

    /// A deterministic summary hash binding every recorded receipt in insertion
    /// order (length-prefixed), suitable as an audit-chain digest.
    pub fn summary_hash(&self) -> ContentHash {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(self.receipts.len() as u64).to_be_bytes());
        for receipt in &self.receipts {
            buf.extend_from_slice(receipt.receipt_commitment.as_bytes());
        }
        ContentHash::compute(&buf)
    }

    /// Re-verify all receipts and atomically rebuild the dedup index.
    ///
    /// Deserialization already performs this validation. This method remains
    /// available for callers that mutate a ledger through an older persistence
    /// adapter before handing it to the current API.
    pub fn reindex(&mut self) -> Result<(), ReceiptError> {
        let seen = Self::validated_seen(&self.receipts)?;
        self.seen = seen;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Protocol-v2 Ed25519-authenticated reconstruction receipts & verified ledger
// ---------------------------------------------------------------------------

/// Errors arising from protocol-v2 authenticated receipt generation, verification,
/// or trusted ledger restoration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptV2Error {
    /// Intrinsic receipt structure or shard cross-check failure.
    Receipt(ReceiptError),
    /// Detached Ed25519 identity, ingress bound, or anchor verification failure.
    Identity(FleetIdentityError),
    /// Authenticated erasure shard-set verification or decode failure.
    Erasure(FleetErasureV2Error),
    /// Malformed or schema-mismatched persisted ledger JSON.
    InvalidPersistedLedger { detail: String },
    /// Persisted ledger contained duplicate receipt commitments.
    DuplicateReceiptCommitment { commitment: ContentHash },
}

impl From<ReceiptError> for ReceiptV2Error {
    fn from(error: ReceiptError) -> Self {
        Self::Receipt(error)
    }
}

impl From<FleetIdentityError> for ReceiptV2Error {
    fn from(error: FleetIdentityError) -> Self {
        Self::Identity(error)
    }
}

impl From<FleetErasureV2Error> for ReceiptV2Error {
    fn from(error: FleetErasureV2Error) -> Self {
        Self::Erasure(error)
    }
}

impl fmt::Display for ReceiptV2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Receipt(error) => write!(f, "{error}"),
            Self::Identity(error) => write!(f, "{error}"),
            Self::Erasure(error) => write!(f, "{error}"),
            Self::InvalidPersistedLedger { detail } => {
                write!(f, "invalid persisted trusted receipt ledger: {detail}")
            }
            Self::DuplicateReceiptCommitment { commitment } => {
                write!(
                    f,
                    "duplicate trusted reconstruction receipt commitment {commitment}"
                )
            }
        }
    }
}

impl std::error::Error for ReceiptV2Error {}

/// Protocol-v2 reconstruction receipt with no forgeable public-NodeId tag.
///
/// Authority is carried exclusively by [`SignedReconstructionReceiptV2`]'s
/// detached Ed25519 [`FleetSignatureV2`], verified against a trusted
/// [`DurableFleetVerificationRegistry`] and [`FleetRegistryAnchorAuthority`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconstructionReceiptV2 {
    /// Schema identifier (`franken-engine.reconstruction-receipt.v2`).
    pub schema_id: String,
    /// Security epoch binding key validity andshard-set epoch.
    pub epoch: SecurityEpoch,
    /// Stable identifier shared by all shards of the reconstructed set.
    pub shard_set_id: String,
    /// Content hash of the reconstructed original payload.
    pub payload_hash: ContentHash,
    /// Length in bytes of the reconstructed original payload.
    pub payload_len: u64,
    /// Identifier of the erasure coding scheme actually used.
    pub coding_scheme: String,
    /// The `(k, n)` coding plan the shard set was produced under.
    pub plan: ErasureCodingPlan,
    /// Canonically-ordered commitments to the shards that materially fed the
    /// reconstruction (present data shards plus the parity shard iff a data
    /// shard was recovered).
    pub contributing_shards: Vec<ShardCommitment>,
    /// The data-shard index recovered from parity, if any (`None` when every
    /// data shard was directly present).
    pub recovered_shard_index: Option<u16>,
    /// Node identity of the reconstructing signer.
    pub reconstructing_node: NodeId,
    /// Reconstruction timestamp in nanoseconds.
    pub reconstruction_timestamp_ns: u64,
    /// Content hash over the length-prefixed canonical v2 receipt preimage.
    pub receipt_commitment: ContentHash,
    /// Exact protocol version (`2.0`).
    pub protocol_version: ProtocolVersion,
    /// Bounded extension metadata.
    pub extensions: BTreeMap<String, String>,
}

impl ReconstructionReceiptV2 {
    /// Recompute the length-prefixed canonical v2 receipt commitment.
    pub fn compute_commitment(&self) -> ContentHash {
        let mut buf = Vec::new();
        append_bytes(&mut buf, self.schema_id.as_bytes());
        buf.extend_from_slice(&self.epoch.as_u64().to_be_bytes());
        append_bytes(&mut buf, self.shard_set_id.as_bytes());
        buf.extend_from_slice(self.payload_hash.as_bytes());
        buf.extend_from_slice(&self.payload_len.to_be_bytes());
        append_bytes(&mut buf, self.coding_scheme.as_bytes());
        buf.extend_from_slice(&self.plan.data_shards.to_be_bytes());
        buf.extend_from_slice(&self.plan.total_shards.to_be_bytes());
        buf.extend_from_slice(&(self.contributing_shards.len() as u64).to_be_bytes());
        for shard in &self.contributing_shards {
            buf.extend_from_slice(&shard.shard_index.to_be_bytes());
            buf.push(role_tag(shard.role));
            buf.extend_from_slice(shard.shard_hash.as_bytes());
            append_bytes(&mut buf, shard.origin_node.as_str().as_bytes());
            buf.extend_from_slice(&shard.sequence.to_be_bytes());
        }
        match self.recovered_shard_index {
            None => buf.push(0),
            Some(index) => {
                buf.push(1);
                buf.extend_from_slice(&index.to_be_bytes());
            }
        }
        append_bytes(&mut buf, self.reconstructing_node.as_str().as_bytes());
        buf.extend_from_slice(&self.reconstruction_timestamp_ns.to_be_bytes());
        buf.extend_from_slice(&self.protocol_version.major.to_be_bytes());
        buf.extend_from_slice(&self.protocol_version.minor.to_be_bytes());
        buf.extend_from_slice(&(self.extensions.len() as u64).to_be_bytes());
        for (key, value) in &self.extensions {
            append_bytes(&mut buf, key.as_bytes());
            append_bytes(&mut buf, value.as_bytes());
        }
        ContentHash::compute(&buf)
    }

    /// Validate intrinsic schema, coding scheme, protocol-v2 version, shard
    /// cardinality/range/provenance invariants, and commitment integrity.
    ///
    /// Intrinsic validation never establishes signer authority; callers must
    /// verify [`SignedReconstructionReceiptV2`] against trusted fleet keys.
    pub fn check_intrinsic(&self) -> Result<(), ReceiptError> {
        if self.schema_id != RECONSTRUCTION_RECEIPT_SCHEMA_ID_V2 {
            return Err(ReceiptError::UnknownSchema {
                found: self.schema_id.clone(),
            });
        }
        if self.coding_scheme != XOR_SINGLE_PARITY_SCHEME {
            return Err(ReceiptError::UnknownScheme {
                found: self.coding_scheme.clone(),
            });
        }
        if self.protocol_version != ProtocolVersion::V2 {
            return Err(ReceiptError::InconsistentStructure {
                reason: "protocol-v2 receipt requires exact protocol version 2.0".to_string(),
            });
        }
        if self.shard_set_id.trim().is_empty() {
            return Err(ReceiptError::InconsistentStructure {
                reason: "shard_set_id must be non-empty".to_string(),
            });
        }
        validate_fleet_node_id(&self.reconstructing_node).map_err(|error| {
            ReceiptError::InconsistentStructure {
                reason: error.to_string(),
            }
        })?;

        if self.plan.data_shards == 0
            || self.plan.total_shards == 0
            || self.plan.data_shards > self.plan.total_shards
        {
            return Err(ReceiptError::InconsistentStructure {
                reason: "invalid coding plan".to_string(),
            });
        }
        if usize::from(self.plan.total_shards) > FLEET_V2_MAX_ERASURE_SHARDS {
            return Err(ReceiptError::InconsistentStructure {
                reason: format!(
                    "protocol-v2 erasure plan exceeds the {FLEET_V2_MAX_ERASURE_SHARDS}-shard limit"
                ),
            });
        }

        let mut previous: Option<u16> = None;
        let mut data_indices: BTreeSet<u16> = BTreeSet::new();
        let mut parity_count = 0usize;
        for shard in &self.contributing_shards {
            if let Some(prev) = previous
                && shard.shard_index <= prev
            {
                return Err(ReceiptError::InconsistentStructure {
                    reason: "contributing shards not in canonical order".to_string(),
                });
            }
            previous = Some(shard.shard_index);
            validate_fleet_node_id(&shard.origin_node).map_err(|error| {
                ReceiptError::InconsistentStructure {
                    reason: error.to_string(),
                }
            })?;

            match shard.role {
                ErasureShardRole::Data => {
                    if shard.shard_index >= self.plan.data_shards {
                        return Err(ReceiptError::InconsistentStructure {
                            reason: "data shard index outside data range".to_string(),
                        });
                    }
                    data_indices.insert(shard.shard_index);
                }
                ErasureShardRole::Parity => {
                    if shard.shard_index < self.plan.data_shards {
                        return Err(ReceiptError::InconsistentStructure {
                            reason: "parity shard index overlaps data range".to_string(),
                        });
                    }
                    if shard.shard_index >= self.plan.total_shards {
                        return Err(ReceiptError::InconsistentStructure {
                            reason: "parity shard index outside total shard range".to_string(),
                        });
                    }
                    parity_count += 1;
                }
            }
        }

        match self.recovered_shard_index {
            Some(index) => {
                if index >= self.plan.data_shards {
                    return Err(ReceiptError::InconsistentStructure {
                        reason: "recovered index outside data range".to_string(),
                    });
                }
                if data_indices.contains(&index) {
                    return Err(ReceiptError::InconsistentStructure {
                        reason: "recovered index also present as a data shard".to_string(),
                    });
                }
                if parity_count != 1 {
                    return Err(ReceiptError::InconsistentStructure {
                        reason: "recovery requires exactly one parity shard".to_string(),
                    });
                }
                if data_indices.len() != usize::from(self.plan.data_shards) - 1 {
                    return Err(ReceiptError::InconsistentStructure {
                        reason: "recovery requires exactly one missing data shard".to_string(),
                    });
                }
            }
            None => {
                if parity_count != 0 {
                    return Err(ReceiptError::InconsistentStructure {
                        reason: "parity shard committed without recovery".to_string(),
                    });
                }
                if data_indices.len() != usize::from(self.plan.data_shards) {
                    return Err(ReceiptError::InconsistentStructure {
                        reason: "no recovery claimed but data shards incomplete".to_string(),
                    });
                }
            }
        }

        if self.contributing_shards.len() != usize::from(self.plan.data_shards) {
            return Err(ReceiptError::InconsistentStructure {
                reason: "receipt must commit to exactly data_shards contributors".to_string(),
            });
        }

        let first = &self.contributing_shards[0];
        let sequence_base = first
            .sequence
            .checked_sub(u64::from(first.shard_index))
            .ok_or_else(|| ReceiptError::InconsistentStructure {
                reason: "contributing shard sequence precedes its index".to_string(),
            })?;
        for shard in &self.contributing_shards {
            if shard.origin_node != first.origin_node
                || shard.sequence.checked_sub(u64::from(shard.shard_index)) != Some(sequence_base)
            {
                return Err(ReceiptError::InconsistentStructure {
                    reason: "contributing shards have inconsistent origin or sequence base"
                        .to_string(),
                });
            }
        }

        let recomputed = self.compute_commitment();
        if !recomputed.constant_time_eq(&self.receipt_commitment) {
            return Err(ReceiptError::CommitmentMismatch);
        }
        Ok(())
    }
}

impl fleet_signature_preimage_v2_sealed::Sealed for ReconstructionReceiptV2 {}

impl FleetSignaturePreimageV2 for ReconstructionReceiptV2 {
    fn fleet_signature_domain(&self) -> ObjectDomain {
        ObjectDomain::EvidenceRecord
    }

    fn fleet_signature_schema_v2(&self) -> &SchemaHash {
        &RECONSTRUCTION_RECEIPT_SIGNATURE_SCHEMA_HASH_V2
    }

    fn fleet_security_epoch(&self) -> SecurityEpoch {
        self.epoch
    }

    fn fleet_message_type(&self) -> &'static str {
        "reconstruction-receipt"
    }

    fn validate_fleet_ingress_limits(&self) -> Result<(), FleetIdentityError> {
        let message_type = self.fleet_message_type();
        let mut budget = FleetV2IngressBudget::default();
        budget.charge_identifier(message_type, "schema_id", &self.schema_id)?;
        budget.charge_identifier(message_type, "shard_set_id", &self.shard_set_id)?;
        budget.charge_identifier(message_type, "coding_scheme", &self.coding_scheme)?;
        budget.charge_node_id(
            message_type,
            "reconstructing_node",
            &self.reconstructing_node,
        )?;
        budget.charge_collection(
            message_type,
            "contributing_shards",
            self.contributing_shards.len(),
            FLEET_V2_MAX_ERASURE_SHARDS,
        )?;
        for shard in &self.contributing_shards {
            budget.charge_node_id(
                message_type,
                "contributing_shards.origin_node",
                &shard.origin_node,
            )?;
        }
        budget.charge_string_map(message_type, "extensions", &self.extensions)
    }

    fn validate_fleet_structure(&self) -> Result<(), FleetIdentityError> {
        validate_protocol_v2(self.fleet_message_type(), self.protocol_version)?;
        validate_fleet_node_id(&self.reconstructing_node)?;
        self.check_intrinsic()
            .map_err(|error| FleetIdentityError::NonCanonicalMessage {
                message_type: self.fleet_message_type().to_string(),
                detail: error.to_string(),
            })
    }

    fn validate_fleet_signer(&self, signer: &NodeId) -> Result<(), FleetIdentityError> {
        validate_exact_message_signer(self.fleet_message_type(), &self.reconstructing_node, signer)
    }

    fn fleet_unsigned_view_v2(
        &self,
        identity: &FleetSigningIdentity,
    ) -> Result<CanonicalValue, FleetIdentityError> {
        self.validate_fleet_ingress_limits()?;
        validate_fleet_signing_identity_ingress(identity)?;
        let contributors = self
            .contributing_shards
            .iter()
            .map(|shard| {
                CanonicalValue::Map(BTreeMap::from([
                    (
                        "origin_node".to_string(),
                        CanonicalValue::String(shard.origin_node.as_str().to_string()),
                    ),
                    (
                        "role".to_string(),
                        CanonicalValue::U64(u64::from(role_tag(shard.role))),
                    ),
                    ("sequence".to_string(), CanonicalValue::U64(shard.sequence)),
                    (
                        "shard_hash".to_string(),
                        canonical_content_hash(shard.shard_hash),
                    ),
                    (
                        "shard_index".to_string(),
                        CanonicalValue::U64(u64::from(shard.shard_index)),
                    ),
                ]))
            })
            .collect();
        let recovered = match self.recovered_shard_index {
            None => CanonicalValue::Map(BTreeMap::from([
                ("index".to_string(), CanonicalValue::U64(0)),
                ("present".to_string(), CanonicalValue::Bool(false)),
            ])),
            Some(index) => CanonicalValue::Map(BTreeMap::from([
                ("index".to_string(), CanonicalValue::U64(u64::from(index))),
                ("present".to_string(), CanonicalValue::Bool(true)),
            ])),
        };
        Ok(CanonicalValue::Map(BTreeMap::from([
            (
                "coding_scheme".to_string(),
                CanonicalValue::String(self.coding_scheme.clone()),
            ),
            (
                "contributing_shards".to_string(),
                CanonicalValue::Array(contributors),
            ),
            (
                "epoch".to_string(),
                CanonicalValue::U64(self.epoch.as_u64()),
            ),
            (
                "extensions".to_string(),
                canonical_string_map(&self.extensions),
            ),
            (
                "payload_hash".to_string(),
                canonical_content_hash(self.payload_hash),
            ),
            (
                "payload_len".to_string(),
                CanonicalValue::U64(self.payload_len),
            ),
            (
                "plan".to_string(),
                CanonicalValue::Map(BTreeMap::from([
                    (
                        "data_shards".to_string(),
                        CanonicalValue::U64(u64::from(self.plan.data_shards)),
                    ),
                    (
                        "total_shards".to_string(),
                        CanonicalValue::U64(u64::from(self.plan.total_shards)),
                    ),
                ])),
            ),
            (
                "protocol_version".to_string(),
                canonical_protocol_version(self.protocol_version),
            ),
            (
                "receipt_commitment".to_string(),
                canonical_content_hash(self.receipt_commitment),
            ),
            (
                "reconstructing_node".to_string(),
                CanonicalValue::String(self.reconstructing_node.as_str().to_string()),
            ),
            (
                "reconstruction_timestamp_ns".to_string(),
                CanonicalValue::U64(self.reconstruction_timestamp_ns),
            ),
            ("recovered_shard_index".to_string(), recovered),
            (
                "schema_id".to_string(),
                CanonicalValue::String(self.schema_id.clone()),
            ),
            (
                "shard_set_id".to_string(),
                CanonicalValue::String(self.shard_set_id.clone()),
            ),
            (
                "signature".to_string(),
                canonical_signature_identity(identity),
            ),
        ])))
    }
}

/// Detached Ed25519-signed protocol-v2 reconstruction receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReconstructionReceiptV2 {
    pub receipt: ReconstructionReceiptV2,
    pub signature: FleetSignatureV2,
}

impl SignedReconstructionReceiptV2 {
    /// Verify detached Ed25519 signature, ingress bounds, and receipt invariants
    /// against the current live fleet trust registry.
    pub fn verify_live<A: FleetRegistryAnchorAuthority>(
        &self,
        registry: &DurableFleetVerificationRegistry,
        trusted_epoch: SecurityEpoch,
        authority: &A,
    ) -> Result<(), ReceiptV2Error> {
        registry.verify_live_detached_message_v2(
            &self.receipt,
            &self.signature,
            trusted_epoch,
            authority,
        )?;
        Ok(())
    }

    /// Verify historical receipt evidence under a retired key backed by an
    /// authenticated preimage acceptance context.
    pub fn verify_historical<A: FleetRegistryAnchorAuthority>(
        &self,
        registry: &DurableFleetVerificationRegistry,
        acceptance: &FleetHistoricalAcceptanceContext,
        authority: &A,
    ) -> Result<(), ReceiptV2Error> {
        registry.verify_historical_detached_message_v2(
            &self.receipt,
            &self.signature,
            acceptance,
            authority,
        )?;
        Ok(())
    }

    /// Verify both the signed receipt and a signed protocol-v2 shard set under
    /// trusted keys, cross-checking every shard commitment and optionally
    /// re-running payload reconstruction.
    pub fn verify_live_against_signed_shards<A: FleetRegistryAnchorAuthority>(
        &self,
        signed_shards: &[SignedErasureShardV2],
        reconstruct: bool,
        registry: &DurableFleetVerificationRegistry,
        trusted_epoch: SecurityEpoch,
        authority: &A,
    ) -> Result<(), ReceiptV2Error> {
        self.verify_live(registry, trusted_epoch, authority)?;
        if signed_shards.is_empty() {
            return Err(ReceiptError::EmptyShardSet.into());
        }
        let shard_epoch = signed_shards[0].message.epoch;
        if shard_epoch != self.receipt.epoch {
            return Err(ReceiptError::InconsistentStructure {
                reason: "receipt epoch does not match signed shard set epoch".to_string(),
            }
            .into());
        }
        let verified_shards =
            registry.verify_live_erasure_shard_set_v2(signed_shards, trusted_epoch, authority)?;
        let payload_len = usize::try_from(self.receipt.payload_len).map_err(|_| {
            ReceiptError::InconsistentStructure {
                reason: "receipt payload length does not fit usize".to_string(),
            }
        })?;
        let expected_shard_payload_len = if payload_len == 0 {
            0
        } else {
            payload_len.div_ceil(usize::from(self.receipt.plan.data_shards))
        };

        let mut by_index: BTreeMap<u16, &ErasureShard> = BTreeMap::new();
        for shard in verified_shards.shards() {
            by_index.insert(shard.shard_index, shard);
        }

        for commitment in &self.receipt.contributing_shards {
            let shard = by_index.get(&commitment.shard_index).ok_or(
                ReceiptError::MissingShardForVerification {
                    shard_index: commitment.shard_index,
                },
            )?;
            let recomputed = shard.recompute_shard_hash();
            if shard.role != commitment.role
                || shard.origin_node != commitment.origin_node
                || shard.sequence != commitment.sequence
                || !recomputed.constant_time_eq(&commitment.shard_hash)
                || !recomputed.constant_time_eq(&shard.shard_hash)
                || shard.shard_set_id != self.receipt.shard_set_id
                || shard.plan != self.receipt.plan
                || shard.payload_len != self.receipt.payload_len
                || !shard
                    .payload_hash
                    .constant_time_eq(&self.receipt.payload_hash)
                || shard.protocol_version != ProtocolVersion::V2
                || shard.protocol_version != self.receipt.protocol_version
                || shard.shard_payload.len() != expected_shard_payload_len
            {
                return Err(ReceiptError::ShardCommitmentMismatch {
                    shard_index: commitment.shard_index,
                }
                .into());
            }
        }

        if reconstruct {
            let contributing_signed: Vec<SignedErasureShardV2> = self
                .receipt
                .contributing_shards
                .iter()
                .map(|commitment| {
                    signed_shards
                        .iter()
                        .find(|candidate| {
                            candidate.message.shard.shard_index == commitment.shard_index
                        })
                        .cloned()
                        .ok_or(ReceiptError::MissingShardForVerification {
                            shard_index: commitment.shard_index,
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let payload = registry
                .verify_live_erasure_shard_set_v2(&contributing_signed, trusted_epoch, authority)?
                .reconstruct()
                .map_err(|error| ReceiptError::ReconstructionFailed {
                    shard_set_id: self.receipt.shard_set_id.clone(),
                    reason: error.to_string(),
                })?;
            registry.ensure_current(authority)?;
            if !ContentHash::compute(&payload).constant_time_eq(&self.receipt.payload_hash) {
                return Err(ReceiptError::CommitmentMismatch.into());
            }
            let reconstructed_len =
                u64::try_from(payload.len()).map_err(|_| ReceiptError::InconsistentStructure {
                    reason: "reconstructed payload length does not fit u64".to_string(),
                })?;
            if reconstructed_len != self.receipt.payload_len {
                return Err(ReceiptError::InconsistentStructure {
                    reason: "reconstructed payload length does not match receipt".to_string(),
                }
                .into());
            }
        }
        Ok(())
    }
}

/// Reconstruct an authenticated protocol-v2 erasure shard set and emit a
/// detached Ed25519-signed [`SignedReconstructionReceiptV2`].
pub fn reconstruct_live_with_receipt_v2<A: FleetRegistryAnchorAuthority>(
    signed_shards: &[SignedErasureShardV2],
    signer: &FleetSigner,
    reconstruction_timestamp_ns: u64,
    registry: &DurableFleetVerificationRegistry,
    trusted_epoch: SecurityEpoch,
    authority: &A,
) -> Result<(Vec<u8>, SignedReconstructionReceiptV2), ReceiptV2Error> {
    if signed_shards.is_empty() {
        return Err(ReceiptError::EmptyShardSet.into());
    }
    let verified =
        registry.verify_live_erasure_shard_set_v2(signed_shards, trusted_epoch, authority)?;
    let shards_snapshot = verified.shards().to_vec();
    let first = shards_snapshot.first().ok_or(ReceiptError::EmptyShardSet)?;
    let (contributing_shards, recovered_shard_index) =
        derive_contributing_shards(&shards_snapshot)?;
    let payload = verified
        .reconstruct()
        .map_err(|error| ReceiptError::ReconstructionFailed {
            shard_set_id: first.shard_set_id.clone(),
            reason: error.to_string(),
        })?;
    registry.ensure_current(authority)?;

    let reconstructing_node = signer.identity().signer.clone();
    let mut receipt = ReconstructionReceiptV2 {
        schema_id: RECONSTRUCTION_RECEIPT_SCHEMA_ID_V2.to_string(),
        epoch: signed_shards[0].message.epoch,
        shard_set_id: first.shard_set_id.clone(),
        payload_hash: first.payload_hash,
        payload_len: first.payload_len,
        coding_scheme: XOR_SINGLE_PARITY_SCHEME.to_string(),
        plan: first.plan,
        contributing_shards,
        recovered_shard_index,
        reconstructing_node,
        reconstruction_timestamp_ns,
        receipt_commitment: ContentHash::from_bytes([0u8; 32]),
        protocol_version: ProtocolVersion::V2,
        extensions: BTreeMap::new(),
    };
    receipt.receipt_commitment = receipt.compute_commitment();
    let signature = signer.sign_detached_message_v2(&receipt)?;
    let signed = SignedReconstructionReceiptV2 { receipt, signature };
    signed.verify_live(registry, trusted_epoch, authority)?;
    Ok((payload, signed))
}

/// Append-only, dedup-keyed ledger of Ed25519-verified protocol-v2 receipts.
///
/// This type intentionally omits `serde::Deserialize` so untrusted JSON can
/// never be materialized into a live ledger without supplying trusted
/// [`DurableFleetVerificationRegistry`] and [`FleetRegistryAnchorAuthority`]
/// context via [`Self::restore_live_verified`] or
/// [`Self::restore_historical_verified`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedReconstructionReceiptLedger {
    receipts: Vec<SignedReconstructionReceiptV2>,
    seen: BTreeSet<[u8; 32]>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireTrustedReconstructionReceiptLedger {
    schema_id: String,
    receipts: Vec<SignedReconstructionReceiptV2>,
}

impl Serialize for TrustedReconstructionReceiptLedger {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct BorrowedWireLedger<'a> {
            schema_id: &'static str,
            receipts: &'a [SignedReconstructionReceiptV2],
        }

        BorrowedWireLedger {
            schema_id: TRUSTED_RECONSTRUCTION_RECEIPT_LEDGER_SCHEMA_ID_V2,
            receipts: &self.receipts,
        }
        .serialize(serializer)
    }
}

impl TrustedReconstructionReceiptLedger {
    /// Create an empty trusted receipt ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify `signed` against live trusted fleet keys and record if new.
    pub fn record_live<A: FleetRegistryAnchorAuthority>(
        &mut self,
        signed: SignedReconstructionReceiptV2,
        registry: &DurableFleetVerificationRegistry,
        trusted_epoch: SecurityEpoch,
        authority: &A,
    ) -> Result<bool, ReceiptV2Error> {
        signed.verify_live(registry, trusted_epoch, authority)?;
        let key = *signed.receipt.receipt_commitment.as_bytes();
        if self.seen.contains(&key) {
            return Ok(false);
        }
        self.seen.insert(key);
        self.receipts.push(signed);
        Ok(true)
    }

    /// Restore a persisted ledger from JSON bytes, verifying every receipt
    /// under current live trusted keys and atomically rebuilding the dedup index.
    pub fn restore_live_verified<A: FleetRegistryAnchorAuthority>(
        json_bytes: &[u8],
        registry: &DurableFleetVerificationRegistry,
        trusted_epoch: SecurityEpoch,
        authority: &A,
    ) -> Result<Self, ReceiptV2Error> {
        validate_fleet_v2_frame_len(json_bytes.len())?;
        let wire: WireTrustedReconstructionReceiptLedger = serde_json::from_slice(json_bytes)
            .map_err(|error| ReceiptV2Error::InvalidPersistedLedger {
                detail: error.to_string(),
            })?;
        if wire.schema_id != TRUSTED_RECONSTRUCTION_RECEIPT_LEDGER_SCHEMA_ID_V2 {
            return Err(ReceiptV2Error::InvalidPersistedLedger {
                detail: format!("unexpected ledger schema_id `{}`", wire.schema_id),
            });
        }
        let seen = Self::validated_live_seen(&wire.receipts, registry, trusted_epoch, authority)?;
        Ok(Self {
            receipts: wire.receipts,
            seen,
        })
    }

    /// Restore a persisted historical ledger from JSON bytes, verifying every
    /// receipt under the historical acceptance context (including rotated keys
    /// whose preimage digest was finalized pre-cutover) and atomically
    /// rebuilding the dedup index.
    pub fn restore_historical_verified<A: FleetRegistryAnchorAuthority>(
        json_bytes: &[u8],
        registry: &DurableFleetVerificationRegistry,
        acceptance: &FleetHistoricalAcceptanceContext,
        authority: &A,
    ) -> Result<Self, ReceiptV2Error> {
        validate_fleet_v2_frame_len(json_bytes.len())?;
        let wire: WireTrustedReconstructionReceiptLedger = serde_json::from_slice(json_bytes)
            .map_err(|error| ReceiptV2Error::InvalidPersistedLedger {
                detail: error.to_string(),
            })?;
        if wire.schema_id != TRUSTED_RECONSTRUCTION_RECEIPT_LEDGER_SCHEMA_ID_V2 {
            return Err(ReceiptV2Error::InvalidPersistedLedger {
                detail: format!("unexpected ledger schema_id `{}`", wire.schema_id),
            });
        }
        let mut seen = BTreeSet::new();
        for signed in &wire.receipts {
            signed.verify_historical(registry, acceptance, authority)?;
            let key = *signed.receipt.receipt_commitment.as_bytes();
            if !seen.insert(key) {
                return Err(ReceiptV2Error::DuplicateReceiptCommitment {
                    commitment: signed.receipt.receipt_commitment,
                });
            }
        }
        Ok(Self {
            receipts: wire.receipts,
            seen,
        })
    }

    /// Re-verify every stored receipt under current live keys and atomically
    /// replace the dedup index on success.
    pub fn reindex_live_verified<A: FleetRegistryAnchorAuthority>(
        &mut self,
        registry: &DurableFleetVerificationRegistry,
        trusted_epoch: SecurityEpoch,
        authority: &A,
    ) -> Result<(), ReceiptV2Error> {
        let seen = Self::validated_live_seen(&self.receipts, registry, trusted_epoch, authority)?;
        self.seen = seen;
        Ok(())
    }

    fn validated_live_seen<A: FleetRegistryAnchorAuthority>(
        receipts: &[SignedReconstructionReceiptV2],
        registry: &DurableFleetVerificationRegistry,
        trusted_epoch: SecurityEpoch,
        authority: &A,
    ) -> Result<BTreeSet<[u8; 32]>, ReceiptV2Error> {
        let mut seen = BTreeSet::new();
        for signed in receipts {
            signed.verify_live(registry, trusted_epoch, authority)?;
            let key = *signed.receipt.receipt_commitment.as_bytes();
            if !seen.insert(key) {
                return Err(ReceiptV2Error::DuplicateReceiptCommitment {
                    commitment: signed.receipt.receipt_commitment,
                });
            }
        }
        Ok(seen)
    }

    pub fn contains(&self, commitment: &ContentHash) -> bool {
        self.seen.contains(commitment.as_bytes())
    }

    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    pub fn receipts(&self) -> &[SignedReconstructionReceiptV2] {
        &self.receipts
    }

    pub fn summary_hash(&self) -> ContentHash {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(self.receipts.len() as u64).to_be_bytes());
        for signed in &self.receipts {
            buf.extend_from_slice(signed.receipt.receipt_commitment.as_bytes());
        }
        ContentHash::compute(&buf)
    }
}

// ---------------------------------------------------------------------------
// Canonical encoding helpers
// ---------------------------------------------------------------------------

fn append_bytes(buf: &mut Vec<u8>, value: &[u8]) {
    buf.extend_from_slice(&(value.len() as u64).to_be_bytes());
    buf.extend_from_slice(value);
}

fn role_tag(role: ErasureShardRole) -> u8 {
    match role {
        ErasureShardRole::Data => 0,
        ErasureShardRole::Parity => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet_immune_protocol::encode_erasure_shards;

    fn node(id: &str) -> NodeId {
        NodeId::new(id)
    }

    /// Encode `payload` into a `(k, n)` shard set from `origin`.
    fn shards_for(payload: &[u8], data_shards: u16, total_shards: u16) -> Vec<ErasureShard> {
        let plan = ErasureCodingPlan::new(data_shards, total_shards).unwrap();
        encode_erasure_shards("set-A", node("origin-1"), 100, 1_000, payload, plan).unwrap()
    }

    fn all_data(shards: &[ErasureShard]) -> Vec<ErasureShard> {
        shards.iter().filter(|s| s.is_data()).cloned().collect()
    }

    fn reauthenticate_legacy_receipt(receipt: &mut ReconstructionReceipt) {
        let commitment = receipt.compute_commitment();
        receipt.receipt_commitment = commitment;
        receipt.signature.signer = receipt.reconstructing_node.clone();
        receipt.signature.hash = receipt.expected_signature_tag(&commitment);
    }

    fn reauthenticate_legacy_shard(shard: &mut ErasureShard) {
        shard.shard_hash = shard.recompute_shard_hash();
        shard.signature.signer = shard.origin_node.clone();
        shard.signature.hash = AuthenticityHash::compute_keyed(
            shard.origin_node.as_str().as_bytes(),
            shard.shard_hash.as_bytes(),
        );
    }

    #[test]
    fn receipt_generation_happy_path_all_data_shards() {
        let payload = b"the quick brown fox jumps over the lazy dog";
        let shards = shards_for(payload, 3, 4);
        let (recovered_payload, receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-1"), 2_000).unwrap();
        assert_eq!(recovered_payload, payload);
        assert_eq!(receipt.schema_id, RECONSTRUCTION_RECEIPT_SCHEMA_ID);
        assert_eq!(receipt.coding_scheme, XOR_SINGLE_PARITY_SCHEME);
        assert_eq!(receipt.recovered_shard_index, None);
        assert_eq!(receipt.contributing_shards.len(), 3);
        assert_eq!(receipt.reconstructing_node, node("recon-1"));
        receipt.verify().unwrap();
    }

    #[test]
    fn receipt_generation_recovers_missing_data_shard_via_parity() {
        let payload = b"payload requiring parity recovery to reconstruct";
        let shards = shards_for(payload, 3, 4);
        // Drop data shard index 1; keep 0, 2 and the parity (index 3).
        let available: Vec<ErasureShard> = shards
            .iter()
            .filter(|s| s.shard_index != 1)
            .cloned()
            .collect();
        let (recovered_payload, receipt) =
            reconstruct_with_receipt(&available, node("recon-2"), 3_000).unwrap();
        assert_eq!(recovered_payload, payload);
        assert_eq!(receipt.recovered_shard_index, Some(1));
        // Contributing = data 0, data 2, parity 3.
        assert_eq!(receipt.contributing_shards.len(), 3);
        assert!(
            receipt
                .contributing_shards
                .iter()
                .any(|c| c.is_parity_role())
        );
        receipt.verify().unwrap();
    }

    #[test]
    fn receipt_contributing_shards_are_canonically_ordered() {
        let payload = b"ordering check payload for contributing shards";
        let shards = shards_for(payload, 4, 5);
        let (_p, receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-3"), 4_000).unwrap();
        let indices: Vec<u16> = receipt
            .contributing_shards
            .iter()
            .map(|c| c.shard_index)
            .collect();
        let mut sorted = indices.clone();
        sorted.sort_unstable();
        assert_eq!(indices, sorted);
        receipt.verify().unwrap();
    }

    #[test]
    fn receipt_verify_passes_without_original_data() {
        let payload = b"verification needs neither payload nor shards";
        let shards = shards_for(payload, 2, 3);
        let (_p, receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-4"), 5_000).unwrap();
        // Only the receipt itself is required.
        assert!(receipt.verify().is_ok());
    }

    #[test]
    fn receipt_rejects_impossible_provenance_at_all_admission_boundaries() {
        let shards = shards_for(b"one origin and sequence base per reconstruction", 3, 4);
        let (_, receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon"), 5_000).unwrap();
        let recovery_shards: Vec<_> = shards
            .iter()
            .filter(|shard| shard.shard_index != 1)
            .cloned()
            .collect();
        let (_, recovery) =
            reconstruct_with_receipt(&recovery_shards, node("recon"), 5_001).unwrap();

        let mut invalid_receipts = vec![receipt.clone(); 3];
        invalid_receipts[0].contributing_shards[1].origin_node = node("foreign-origin");
        invalid_receipts[1].contributing_shards[1].sequence += 1;
        invalid_receipts[2].contributing_shards[1].sequence = 0;
        let mut foreign_parity = recovery.clone();
        foreign_parity.contributing_shards[2].origin_node = node("foreign-parity-origin");
        invalid_receipts.push(foreign_parity);
        let mut displaced_parity = recovery;
        displaced_parity.contributing_shards[2].sequence += 1;
        invalid_receipts.push(displaced_parity);

        for mut invalid in invalid_receipts {
            // A fresh commitment/tag cannot turn provenance that the actual
            // reconstruction rejects into a structurally possible receipt.
            reauthenticate_legacy_receipt(&mut invalid);
            assert!(matches!(
                invalid.verify(),
                Err(ReceiptError::InconsistentStructure { .. })
            ));

            let mut ledger = ReconstructionReceiptLedger::new();
            ledger.record(receipt.clone()).unwrap();
            let before = ledger.clone();
            assert!(ledger.record(invalid.clone()).is_err());
            assert_eq!(ledger, before);

            // The legacy reindex entry point must also refuse these receipts
            // without publishing a partially rebuilt dedup index.
            let mut invalid_ledger = ledger;
            invalid_ledger.receipts.push(invalid.clone());
            assert!(invalid_ledger.reindex().is_err());
            assert!(invalid_ledger.contains(&receipt.receipt_commitment));
            assert!(!invalid_ledger.contains(&invalid.receipt_commitment));

            let wire = serde_json::json!({ "receipts": [receipt.clone(), invalid] });
            assert!(serde_json::from_value::<ReconstructionReceiptLedger>(wire).is_err());
        }
    }

    #[test]
    fn receipt_accepts_consistent_provenance_near_sequence_limit() {
        let payload = b"nonzero sequence bases and parity recovery remain valid";
        let shards = encode_erasure_shards(
            "sequence-limit",
            node("origin"),
            u64::MAX - 3,
            1_000,
            payload,
            ErasureCodingPlan::new(3, 4).unwrap(),
        )
        .unwrap();
        let recovery_shards: Vec<_> = shards
            .iter()
            .filter(|shard| shard.shard_index != 1)
            .cloned()
            .collect();
        for available in [all_data(&shards), recovery_shards] {
            let (reconstructed, receipt) =
                reconstruct_with_receipt(&available, node("recon"), 2_000).unwrap();
            assert_eq!(reconstructed, payload);
            receipt.verify().unwrap();
            receipt.verify_against_shards(&available, true).unwrap();
            let mut ledger = ReconstructionReceiptLedger::new();
            ledger.record(receipt).unwrap();
            let restored: ReconstructionReceiptLedger =
                serde_json::from_value(serde_json::to_value(&ledger).unwrap()).unwrap();
            assert_eq!(restored, ledger);
        }
    }

    #[test]
    fn receipt_verify_against_shards_passes_with_reconstruction() {
        let payload = b"cross-check against the raw shard set";
        let shards = shards_for(payload, 3, 4);
        let (_p, receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-5"), 6_000).unwrap();
        receipt.verify_against_shards(&shards, true).unwrap();
    }

    #[test]
    fn receipt_verify_against_shards_passes_for_recovery_case() {
        let payload = b"recovery cross-check payload contents here";
        let shards = shards_for(payload, 3, 4);
        let available: Vec<ErasureShard> = shards
            .iter()
            .filter(|s| s.shard_index != 2)
            .cloned()
            .collect();
        let (_p, receipt) = reconstruct_with_receipt(&available, node("recon-6"), 7_000).unwrap();
        receipt.verify_against_shards(&available, true).unwrap();
    }

    #[test]
    fn verify_against_shards_rejects_receipt_payload_len_mismatch() {
        let shards = shards_for(b"payload length cross-check", 2, 3);
        let (_payload, mut receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-len"), 7_100).unwrap();
        receipt.payload_len = receipt.payload_len.saturating_add(1);
        reauthenticate_legacy_receipt(&mut receipt);
        receipt
            .verify()
            .expect("mutation is internally self-consistent");
        assert!(matches!(
            receipt.verify_against_shards(&shards, false),
            Err(ReceiptError::ShardCommitmentMismatch { .. })
        ));
        assert!(matches!(
            receipt.verify_against_shards(&shards, true),
            Err(ReceiptError::ShardCommitmentMismatch { .. })
        ));
    }

    #[test]
    fn legacy_receipt_verification_rejects_v2_retag_before_shard_comparison() {
        let shards = shards_for(b"protocol version cross-check", 2, 3);
        let (_payload, mut receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-version"), 7_200).unwrap();
        receipt.protocol_version = ProtocolVersion::V2;
        reauthenticate_legacy_receipt(&mut receipt);
        assert!(matches!(
            receipt.verify(),
            Err(ReceiptError::InconsistentStructure { ref reason })
                if reason.contains("exact protocol version 1.0")
        ));
        assert!(matches!(
            receipt.verify_against_shards(&shards, false),
            Err(ReceiptError::InconsistentStructure { ref reason })
                if reason.contains("exact protocol version 1.0")
        ));
        assert!(matches!(
            receipt.verify_against_shards(&shards, true),
            Err(ReceiptError::InconsistentStructure { ref reason })
                if reason.contains("exact protocol version 1.0")
        ));
    }

    #[test]
    fn legacy_receipt_generation_rejects_v2_shards_without_registry_verification() {
        let mut shards = shards_for(b"version propagation", 2, 3);
        for shard in &mut shards {
            shard.protocol_version = ProtocolVersion::V2;
            shard.shard_hash = shard.recompute_shard_hash();
            shard.signature.hash = AuthenticityHash::compute_keyed(
                shard.origin_node.as_str().as_bytes(),
                shard.shard_hash.as_bytes(),
            );
        }
        assert!(matches!(
            reconstruct_with_receipt(&all_data(&shards), node("recon-versioned"), 7_300),
            Err(ReceiptError::ReconstructionFailed { ref reason, .. })
                if reason.contains("trusted registry verification")
        ));
    }

    #[test]
    fn empty_shard_set_is_rejected() {
        let err = reconstruct_with_receipt(&[], node("recon-7"), 8_000).unwrap_err();
        assert_eq!(err, ReceiptError::EmptyShardSet);
    }

    #[test]
    fn reconstruction_failure_maps_to_receipt_error() {
        // Two missing data shards cannot be recovered by single parity.
        let payload = b"two missing data shards is unrecoverable here";
        let shards = shards_for(payload, 4, 5);
        let available: Vec<ErasureShard> = shards
            .iter()
            .filter(|s| s.shard_index != 0 && s.shard_index != 1)
            .cloned()
            .collect();
        let err = reconstruct_with_receipt(&available, node("recon-8"), 9_000).unwrap_err();
        match err {
            ReceiptError::ReconstructionFailed { .. } => {}
            other => panic!("expected ReconstructionFailed, got {other:?}"),
        }
    }

    #[test]
    fn tampering_commitment_is_detected() {
        let payload = b"tamper the stored commitment";
        let shards = shards_for(payload, 2, 3);
        let (_p, mut receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-9"), 10_000).unwrap();
        receipt.receipt_commitment = ContentHash::from_bytes([9u8; 32]);
        assert_eq!(
            receipt.verify().unwrap_err(),
            ReceiptError::CommitmentMismatch
        );
    }

    #[test]
    fn tampering_field_without_recommitting_is_detected() {
        let payload = b"tamper a committed field but keep old commitment";
        let shards = shards_for(payload, 2, 3);
        let (_p, mut receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-10"), 11_000).unwrap();
        receipt.payload_len += 1;
        assert_eq!(
            receipt.verify().unwrap_err(),
            ReceiptError::CommitmentMismatch
        );
    }

    #[test]
    fn tampering_signature_is_detected() {
        let payload = b"tamper the signature tag";
        let shards = shards_for(payload, 2, 3);
        let (_p, mut receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-11"), 12_000).unwrap();
        receipt.signature.hash = AuthenticityHash::compute_keyed(b"attacker", b"forged");
        assert_eq!(
            receipt.verify().unwrap_err(),
            ReceiptError::InvalidSignature
        );
    }

    #[test]
    fn signer_mismatch_is_detected() {
        let payload = b"signer disagreeing with reconstructing node";
        let shards = shards_for(payload, 2, 3);
        let (_p, mut receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-12"), 13_000).unwrap();
        receipt.signature.signer = node("someone-else");
        assert_eq!(receipt.verify().unwrap_err(), ReceiptError::SignerMismatch);
    }

    #[test]
    fn unknown_schema_is_rejected() {
        let payload = b"unknown schema id";
        let shards = shards_for(payload, 2, 3);
        let (_p, mut receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-13"), 14_000).unwrap();
        receipt.schema_id = "franken-engine.reconstruction-receipt.v2".to_string();
        match receipt.verify().unwrap_err() {
            ReceiptError::UnknownSchema { .. } => {}
            other => panic!("expected UnknownSchema, got {other:?}"),
        }
    }

    #[test]
    fn unknown_scheme_is_rejected() {
        let payload = b"unknown coding scheme";
        let shards = shards_for(payload, 2, 3);
        let (_p, mut receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-14"), 15_000).unwrap();
        receipt.coding_scheme = "reed-solomon-gf256".to_string();
        match receipt.verify().unwrap_err() {
            ReceiptError::UnknownScheme { .. } => {}
            other => panic!("expected UnknownScheme, got {other:?}"),
        }
    }

    #[test]
    fn serde_round_trip_preserves_and_reverifies() {
        let payload = b"serde round trip stability";
        let shards = shards_for(payload, 3, 4);
        let (_p, receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-15"), 16_000).unwrap();
        let json = serde_json::to_string(&receipt).unwrap();
        let restored: ReconstructionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, receipt);
        restored.verify().unwrap();
    }

    #[test]
    fn receipt_commitment_is_deterministic_across_regeneration() {
        let payload = b"deterministic commitment across runs";
        let shards = shards_for(payload, 3, 4);
        let (_p1, receipt_a) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-16"), 17_000).unwrap();
        let (_p2, receipt_b) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-16"), 17_000).unwrap();
        assert!(
            receipt_a
                .receipt_commitment
                .constant_time_eq(&receipt_b.receipt_commitment)
        );
        assert_eq!(receipt_a.signature.hash, receipt_b.signature.hash);
    }

    #[test]
    fn different_timestamp_changes_commitment() {
        let payload = b"timestamp is bound into the commitment";
        let shards = shards_for(payload, 2, 3);
        let (_p1, receipt_a) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-17"), 18_000).unwrap();
        let (_p2, receipt_b) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-17"), 19_000).unwrap();
        assert_ne!(receipt_a.receipt_commitment, receipt_b.receipt_commitment);
    }

    #[test]
    fn ledger_records_and_dedups() {
        let payload = b"ledger dedup by commitment";
        let shards = shards_for(payload, 2, 3);
        let (_p, receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-18"), 20_000).unwrap();
        let mut ledger = ReconstructionReceiptLedger::new();
        assert!(ledger.is_empty());
        assert!(ledger.record(receipt.clone()).unwrap());
        assert_eq!(ledger.len(), 1);
        assert!(ledger.contains(&receipt.receipt_commitment));
        // Idempotent re-record is a no-op.
        assert!(!ledger.record(receipt).unwrap());
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn ledger_rejects_tampered_receipt() {
        let payload = b"ledger refuses an unverifiable receipt";
        let shards = shards_for(payload, 2, 3);
        let (_p, mut receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-19"), 21_000).unwrap();
        receipt.receipt_commitment = ContentHash::from_bytes([1u8; 32]);
        let mut ledger = ReconstructionReceiptLedger::new();
        assert!(ledger.record(receipt).is_err());
        assert!(ledger.is_empty());
    }

    #[test]
    fn ledger_summary_hash_changes_as_receipts_accrue() {
        let mut ledger = ReconstructionReceiptLedger::new();
        let empty_hash = ledger.summary_hash();
        for (i, payload) in [b"first".as_slice(), b"second".as_slice()]
            .iter()
            .enumerate()
        {
            let shards = shards_for(payload, 2, 3);
            let (_p, receipt) =
                reconstruct_with_receipt(&all_data(&shards), node("recon-20"), 22_000 + i as u64)
                    .unwrap();
            ledger.record(receipt).unwrap();
        }
        assert_ne!(empty_hash, ledger.summary_hash());
        // Summary hash is stable for a fixed ledger state.
        assert_eq!(ledger.summary_hash(), ledger.summary_hash());
    }

    #[test]
    fn ledger_deserialization_restores_dedup_immediately() {
        let payload = b"reindex restores dedup semantics";
        let shards = shards_for(payload, 2, 3);
        let (_p, receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-21"), 23_000).unwrap();
        let mut ledger = ReconstructionReceiptLedger::new();
        ledger.record(receipt.clone()).unwrap();
        let json = serde_json::to_string(&ledger).unwrap();
        let mut restored: ReconstructionReceiptLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.len(), 1);
        assert!(!restored.record(receipt).unwrap());
        assert_eq!(restored.len(), 1);
    }

    #[test]
    fn ledger_deserialization_rejects_tampered_receipt() {
        let shards = shards_for(b"tampered persisted receipt", 2, 3);
        let (_payload, receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-tampered"), 23_100).unwrap();
        let mut ledger = ReconstructionReceiptLedger::new();
        ledger.record(receipt).unwrap();
        let mut value = serde_json::to_value(&ledger).unwrap();
        value["receipts"][0]["payload_len"] = serde_json::Value::from(9_999u64);
        assert!(serde_json::from_value::<ReconstructionReceiptLedger>(value).is_err());
    }

    #[test]
    fn ledger_deserialization_rejects_duplicate_commitments() {
        let shards = shards_for(b"duplicate persisted receipt", 2, 3);
        let (_payload, receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-duplicate"), 23_200).unwrap();
        let mut ledger = ReconstructionReceiptLedger::new();
        ledger.record(receipt).unwrap();
        let mut value = serde_json::to_value(&ledger).unwrap();
        let duplicate = value["receipts"][0].clone();
        value["receipts"]
            .as_array_mut()
            .expect("receipts is an array")
            .push(duplicate);
        let error = serde_json::from_value::<ReconstructionReceiptLedger>(value).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("duplicate reconstruction receipt")
        );
    }

    #[test]
    fn ledger_reindex_is_atomic_on_verification_failure() {
        let shards = shards_for(b"atomic reindex", 2, 3);
        let (_payload, receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-atomic"), 23_300).unwrap();
        let mut ledger = ReconstructionReceiptLedger::new();
        ledger.record(receipt.clone()).unwrap();
        let seen_before = ledger.seen.clone();
        ledger.receipts[0].payload_len = ledger.receipts[0].payload_len.saturating_add(1);
        assert!(ledger.reindex().is_err());
        assert_eq!(ledger.seen, seen_before);
        assert!(ledger.contains(&receipt.receipt_commitment));
    }

    #[test]
    fn verify_against_shards_detects_missing_shard() {
        let payload = b"missing shard in verification set";
        let shards = shards_for(payload, 3, 4);
        let (_p, receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-22"), 24_000).unwrap();
        // Provide only a subset that omits a committed shard.
        let subset: Vec<ErasureShard> = shards
            .iter()
            .filter(|s| s.shard_index == 0)
            .cloned()
            .collect();
        match receipt.verify_against_shards(&subset, false).unwrap_err() {
            ReceiptError::MissingShardForVerification { .. } => {}
            other => panic!("expected MissingShardForVerification, got {other:?}"),
        }
    }

    #[test]
    fn verify_against_shards_detects_mutated_shard() {
        let payload = b"mutated shard payload in verification set";
        let shards = shards_for(payload, 3, 4);
        let (_p, receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-23"), 25_000).unwrap();
        let mut mutated = shards.clone();
        // Corrupt a data shard's payload bytes without recomputing its hash.
        if let Some(byte) = mutated[0].shard_payload.first_mut() {
            *byte ^= 0xFF;
        }
        match receipt.verify_against_shards(&mutated, false).unwrap_err() {
            ReceiptError::ShardCommitmentMismatch { .. } => {}
            other => panic!("expected ShardCommitmentMismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_against_shards_rejects_conflicting_duplicate_provenance_in_any_order() {
        let shards = shards_for(b"conflicting duplicate provenance", 2, 3);
        let data = all_data(&shards);
        let (_payload, receipt) =
            reconstruct_with_receipt(&data, node("recon-provenance"), 25_100).unwrap();
        let mut conflict = data[0].clone();
        conflict.origin_node = node("other-origin");
        conflict.shard_hash = conflict.recompute_shard_hash();
        reauthenticate_legacy_shard(&mut conflict);

        let mut conflict_last = data.clone();
        conflict_last.push(conflict.clone());
        assert!(matches!(
            receipt.verify_against_shards(&conflict_last, false),
            Err(ReceiptError::ShardCommitmentMismatch { .. })
        ));

        let mut conflict_first = vec![conflict];
        conflict_first.extend(data);
        assert!(matches!(
            receipt.verify_against_shards(&conflict_first, false),
            Err(ReceiptError::ShardCommitmentMismatch { .. })
        ));
    }

    #[test]
    fn verify_against_shards_rejects_inconsistent_shard_payload_length_without_reconstruction() {
        let shards = shards_for(b"fragment length must match the coding plan", 2, 3);
        let mut data = all_data(&shards);
        let (_payload, mut receipt) =
            reconstruct_with_receipt(&data, node("recon-fragment-len"), 25_150).unwrap();
        assert!(data[0].shard_payload.pop().is_some());
        data[0].shard_hash = data[0].recompute_shard_hash();
        let commitment = receipt
            .contributing_shards
            .iter_mut()
            .find(|commitment| commitment.shard_index == data[0].shard_index)
            .expect("receipt commits the mutated shard");
        commitment.shard_hash = data[0].shard_hash;
        reauthenticate_legacy_receipt(&mut receipt);
        assert!(matches!(
            receipt.verify_against_shards(&data, false),
            Err(ReceiptError::ShardCommitmentMismatch { .. })
        ));
    }

    #[test]
    fn receipt_generation_rejects_conflicting_duplicate_provenance() {
        let shards = shards_for(b"generation duplicate provenance", 2, 3);
        let mut data = all_data(&shards);
        let mut conflict = data[0].clone();
        conflict.origin_node = node("other-origin");
        conflict.shard_hash = conflict.recompute_shard_hash();
        reauthenticate_legacy_shard(&mut conflict);
        data.push(conflict);
        assert!(matches!(
            reconstruct_with_receipt(&data, node("recon-provenance"), 25_200),
            Err(ReceiptError::ReconstructionFailed { ref reason, .. })
                if reason.contains("mixed shard set provenance")
        ));
    }

    #[test]
    fn verify_against_shards_without_reconstruction_enforces_canonical_provenance() {
        let shards = shards_for(b"false-mode provenance validation", 2, 3);
        let mut bad_tag = all_data(&shards);
        let (_payload, receipt) =
            reconstruct_with_receipt(&bad_tag, node("recon-false-tag"), 25_300).unwrap();
        bad_tag[0].signature.hash =
            AuthenticityHash::compute_keyed(b"wrong-legacy-key", bad_tag[0].shard_hash.as_bytes());
        for candidates in [
            bad_tag.clone(),
            vec![shards[0].clone(), bad_tag[0].clone(), shards[1].clone()],
            vec![bad_tag[0].clone(), shards[0].clone(), shards[1].clone()],
        ] {
            assert!(matches!(
                receipt.verify_against_shards(&candidates, false),
                Err(ReceiptError::ShardCommitmentMismatch { .. })
            ));
        }

        for mutation in ["sequence", "timestamp"] {
            let mut data = all_data(&shards);
            let (_payload, mut receipt) =
                reconstruct_with_receipt(&data, node("recon-false-provenance"), 25_400).unwrap();
            match mutation {
                "sequence" => data[1].sequence += 1,
                "timestamp" => data[1].timestamp_ns += 1,
                _ => unreachable!(),
            }
            reauthenticate_legacy_shard(&mut data[1]);
            let commitment = receipt
                .contributing_shards
                .iter_mut()
                .find(|commitment| commitment.shard_index == data[1].shard_index)
                .expect("receipt commits the mutated shard");
            commitment.sequence = data[1].sequence;
            commitment.shard_hash = data[1].shard_hash;
            reauthenticate_legacy_receipt(&mut receipt);
            if mutation == "sequence" {
                // Sequence/index provenance is present in the receipt itself,
                // so both admission paths reject it before inspecting shards.
                assert!(matches!(
                    receipt.verify(),
                    Err(ReceiptError::InconsistentStructure { ref reason })
                        if reason.contains("sequence base")
                ));
                assert!(matches!(
                    receipt.verify_against_shards(&data, false),
                    Err(ReceiptError::InconsistentStructure { ref reason })
                        if reason.contains("sequence base")
                ));
            } else {
                // Individual shard timestamps are available only in the shard
                // set; they still require the stronger cross-shard check.
                receipt.verify().expect("receipt omits shard timestamps");
                assert!(matches!(
                    receipt.verify_against_shards(&data, false),
                    Err(ReceiptError::ReconstructionFailed { ref reason, .. })
                        if reason.contains("mixed shard set provenance")
                ));
            }
        }
    }

    #[test]
    fn boundary_single_data_shard_plus_parity() {
        let payload = b"k=1 n=2 boundary";
        let shards = shards_for(payload, 1, 2);
        let (recovered, receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-24"), 26_000).unwrap();
        assert_eq!(recovered, payload);
        assert_eq!(receipt.contributing_shards.len(), 1);
        receipt.verify().unwrap();
    }

    #[test]
    fn boundary_no_parity_plan() {
        // k == n: no parity shards exist; all data must be present.
        let payload = b"k equals n no parity";
        let shards = shards_for(payload, 3, 3);
        assert!(shards.iter().all(|s| s.is_data()));
        let (recovered, receipt) =
            reconstruct_with_receipt(&shards, node("recon-25"), 27_000).unwrap();
        assert_eq!(recovered, payload);
        assert_eq!(receipt.recovered_shard_index, None);
        receipt.verify().unwrap();
    }

    #[test]
    fn structural_check_rejects_recovery_without_parity() {
        let payload = b"structural: recovery flag but no parity commitment";
        let shards = shards_for(payload, 3, 4);
        let (_p, mut receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-26"), 28_000).unwrap();
        // Claim a recovery that the contributing set cannot support.
        receipt.recovered_shard_index = Some(0);
        // Recompute commitment + signature so only the structural rule fires.
        let commitment = receipt.compute_commitment();
        receipt.receipt_commitment = commitment;
        receipt.signature.hash = AuthenticityHash::compute_keyed(
            receipt.reconstructing_node.as_str().as_bytes(),
            commitment.as_bytes(),
        );
        match receipt.verify().unwrap_err() {
            ReceiptError::InconsistentStructure { .. } => {}
            other => panic!("expected InconsistentStructure, got {other:?}"),
        }
    }

    #[test]
    fn structural_check_rejects_unordered_contributions() {
        let payload = b"structural: contributions out of order";
        let shards = shards_for(payload, 3, 4);
        let (_p, mut receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-27"), 29_000).unwrap();
        receipt.contributing_shards.reverse();
        let commitment = receipt.compute_commitment();
        receipt.receipt_commitment = commitment;
        receipt.signature.hash = AuthenticityHash::compute_keyed(
            receipt.reconstructing_node.as_str().as_bytes(),
            commitment.as_bytes(),
        );
        match receipt.verify().unwrap_err() {
            ReceiptError::InconsistentStructure { .. } => {}
            other => panic!("expected InconsistentStructure, got {other:?}"),
        }
    }

    #[test]
    fn structural_check_rejects_parity_index_outside_total_range() {
        let shards = shards_for(b"parity index range", 2, 3);
        let available: Vec<ErasureShard> = shards
            .iter()
            .filter(|shard| shard.shard_index != 0)
            .cloned()
            .collect();
        let (_payload, mut receipt) =
            reconstruct_with_receipt(&available, node("recon-parity-range"), 29_100).unwrap();
        let total_shards = receipt.plan.total_shards;
        let parity = receipt
            .contributing_shards
            .iter_mut()
            .find(|commitment| commitment.role == ErasureShardRole::Parity)
            .expect("recovery receipt contains parity");
        parity.shard_index = total_shards;
        reauthenticate_legacy_receipt(&mut receipt);
        assert!(matches!(
            receipt.verify(),
            Err(ReceiptError::InconsistentStructure { .. })
        ));
    }

    #[test]
    fn structural_check_rejects_parity_without_recovery() {
        let shards = shards_for(b"superfluous parity", 2, 4);
        let (_payload, mut receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-extra-parity"), 29_200)
                .unwrap();
        receipt
            .contributing_shards
            .push(ShardCommitment::from_shard(&shards[2]));
        receipt.contributing_shards.sort();
        reauthenticate_legacy_receipt(&mut receipt);
        assert!(matches!(
            receipt.verify(),
            Err(ReceiptError::InconsistentStructure { .. })
        ));
    }

    #[test]
    fn structural_check_rejects_multiple_parity_contributors() {
        let shards = shards_for(b"multiple parity contributors", 2, 4);
        let available: Vec<ErasureShard> = shards
            .iter()
            .filter(|shard| shard.shard_index != 0)
            .cloned()
            .collect();
        let (_payload, mut receipt) =
            reconstruct_with_receipt(&available, node("recon-multi-parity"), 29_300).unwrap();
        receipt
            .contributing_shards
            .push(ShardCommitment::from_shard(&shards[3]));
        receipt.contributing_shards.sort();
        reauthenticate_legacy_receipt(&mut receipt);
        assert!(matches!(
            receipt.verify(),
            Err(ReceiptError::InconsistentStructure { .. })
        ));
    }

    #[test]
    fn empty_payload_receipt_round_trips() {
        let payload: &[u8] = b"";
        let shards = shards_for(payload, 2, 3);
        let (recovered, receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-28"), 30_000).unwrap();
        assert_eq!(recovered, payload);
        assert_eq!(receipt.payload_len, 0);
        receipt.verify().unwrap();
    }

    #[test]
    fn shard_commitment_records_origin_and_sequence() {
        let payload = b"commitment binds origin + sequence";
        let shards = shards_for(payload, 2, 3);
        let (_p, receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-29"), 31_000).unwrap();
        for commitment in &receipt.contributing_shards {
            assert_eq!(commitment.origin_node, node("origin-1"));
            assert!(commitment.sequence >= 100);
        }
    }

    #[test]
    fn extensions_are_bound_into_commitment() {
        let payload = b"extensions participate in the commitment";
        let shards = shards_for(payload, 2, 3);
        let (_p, mut receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-30"), 32_000).unwrap();
        let base = receipt.receipt_commitment;
        receipt
            .extensions
            .insert("audit_note".to_string(), "manual".to_string());
        let with_ext = receipt.compute_commitment();
        assert_ne!(base, with_ext);
    }

    #[test]
    fn parity_selection_is_deterministic_across_shard_order() {
        // (2, 4): two data shards plus two identical parity shards (indices 2,
        // 3). Recovering a missing data shard must commit to the same (lowest
        // index) parity regardless of the order shards are supplied in.
        let payload = b"multi-parity determinism across orderings";
        let shards = shards_for(payload, 2, 4);
        let available: Vec<ErasureShard> = shards
            .iter()
            .filter(|s| s.shard_index != 0)
            .cloned()
            .collect();
        let (_p1, forward) =
            reconstruct_with_receipt(&available, node("recon-mp"), 40_000).unwrap();
        let mut reversed = available.clone();
        reversed.reverse();
        let (_p2, backward) =
            reconstruct_with_receipt(&reversed, node("recon-mp"), 40_000).unwrap();
        assert_eq!(forward.receipt_commitment, backward.receipt_commitment);
        let parity_indices: Vec<u16> = forward
            .contributing_shards
            .iter()
            .filter(|c| c.is_parity_role())
            .map(|c| c.shard_index)
            .collect();
        assert_eq!(parity_indices, vec![2]);
        forward.verify().unwrap();
    }

    // Small helper used by the recovery tests.
    impl ShardCommitment {
        fn is_parity_role(&self) -> bool {
            matches!(self.role, ErasureShardRole::Parity)
        }
    }

    mod v2_tests {
        use std::cell::RefCell;

        use super::*;
        use crate::fleet_immune_protocol::{
            FLEET_V2_MAX_FRAME_BYTES, FLEET_V2_MAX_IDENTIFIER_BYTES, FLEET_V2_MAX_MAP_ENTRIES,
            FleetAuthorityId, FleetRegistrySnapshotAnchorClaim,
            FleetVerificationRegistryPersistence, encode_erasure_shards_v2,
        };
        use crate::signature_preimage::SigningKey;
        use crate::storage_adapter::{EventContext, InMemoryStorageAdapter};

        type Claim = FleetRegistrySnapshotAnchorClaim;

        #[derive(Default)]
        struct AnchorState {
            current: Option<Claim>,
            permits: BTreeMap<Vec<u8>, (Option<Claim>, Claim)>,
            next_permit: u64,
        }

        struct TestAuthority {
            id: FleetAuthorityId,
            state: RefCell<AnchorState>,
        }

        impl FleetRegistryAnchorAuthority for TestAuthority {
            fn fleet_authority_id(&self) -> FleetAuthorityId {
                self.id
            }

            fn authenticate_current_registry_anchor(
                &self,
                claim: &Claim,
            ) -> Result<String, FleetIdentityError> {
                if self.state.borrow().current.as_ref() != Some(claim) {
                    return Err(FleetIdentityError::UnverifiedRegistryAnchor {
                        detail: "anchor no longer current".to_string(),
                    });
                }
                Ok(format!("current-{}", claim.generation))
            }

            fn prepare_registry_anchor_advance(
                &self,
                expected: Option<&Claim>,
                next: &Claim,
            ) -> Result<Vec<u8>, FleetIdentityError> {
                let mut state = self.state.borrow_mut();
                if state.current.as_ref() != expected || next.fleet_authority_id != self.id {
                    return Err(FleetIdentityError::UnverifiedRegistryAnchor {
                        detail: "prepare cas refused".to_string(),
                    });
                }
                state.next_permit += 1;
                let permit = state.next_permit.to_be_bytes().to_vec();
                state
                    .permits
                    .insert(permit.clone(), (expected.cloned(), next.clone()));
                Ok(permit)
            }

            fn finalize_registry_anchor_advance(
                &self,
                permit: &[u8],
                next: &Claim,
            ) -> Result<String, FleetIdentityError> {
                let mut state = self.state.borrow_mut();
                let Some((expected, authorized)) = state.permits.get(permit).cloned() else {
                    return Err(FleetIdentityError::UnverifiedRegistryAnchor {
                        detail: "unknown permit".to_string(),
                    });
                };
                if authorized != *next
                    || (state.current != expected && state.current.as_ref() != Some(next))
                {
                    return Err(FleetIdentityError::UnverifiedRegistryAnchor {
                        detail: "permit transition mismatch".to_string(),
                    });
                }
                state.current = Some(next.clone());
                Ok(format!("finalized-{}", next.generation))
            }
        }

        struct ReceiptFixture {
            authority: TestAuthority,
            storage: InMemoryStorageAdapter,
            event: EventContext,
            registry: DurableFleetVerificationRegistry,
            origin_signer: FleetSigner,
            recon_signer: FleetSigner,
            other_signer: FleetSigner,
            epoch: SecurityEpoch,
        }

        impl ReceiptFixture {
            fn new() -> Self {
                let id = FleetAuthorityId::from_provisioned_bytes([0x5a; 32]).unwrap();
                let authority = TestAuthority {
                    id,
                    state: RefCell::new(AnchorState::default()),
                };
                let epoch = SecurityEpoch::from_raw(3);
                let origin_signer = FleetSigner::new(
                    id,
                    node("origin-v2"),
                    1,
                    SigningKey::from_bytes([0x11; 32]).unwrap(),
                )
                .unwrap();
                let recon_signer = FleetSigner::new(
                    id,
                    node("recon-v2"),
                    1,
                    SigningKey::from_bytes([0x22; 32]).unwrap(),
                )
                .unwrap();
                let other_signer = FleetSigner::new(
                    id,
                    node("other-v2"),
                    1,
                    SigningKey::from_bytes([0x33; 32]).unwrap(),
                )
                .unwrap();
                let mut storage = InMemoryStorageAdapter::new();
                let event = EventContext::new(
                    "receipt-v2-trace",
                    "receipt-v2-decision",
                    "receipt-v2-policy",
                )
                .unwrap();
                let mut registry = FleetVerificationRegistryPersistence::new(&mut storage, &event)
                    .prepare_initial_registration(
                        origin_signer.identity().signer.clone(),
                        1,
                        origin_signer.verification_key().clone(),
                        epoch,
                        &authority,
                    )
                    .unwrap()
                    .finalize_and_publish(&authority)
                    .unwrap();
                for signer in [&recon_signer, &other_signer] {
                    registry = FleetVerificationRegistryPersistence::new(&mut storage, &event)
                        .prepare_register_node(
                            &registry,
                            signer.identity().signer.clone(),
                            1,
                            signer.verification_key().clone(),
                            epoch,
                            &authority,
                        )
                        .unwrap()
                        .finalize_and_publish(&authority)
                        .unwrap();
                }
                Self {
                    authority,
                    storage,
                    event,
                    registry,
                    origin_signer,
                    recon_signer,
                    other_signer,
                    epoch,
                }
            }

            fn encode_signed_shards(
                &self,
                set_id: &str,
                payload: &[u8],
                data_shards: u16,
                total_shards: u16,
            ) -> Vec<SignedErasureShardV2> {
                let plan = ErasureCodingPlan::new(data_shards, total_shards).unwrap();
                encode_erasure_shards_v2(
                    set_id,
                    self.origin_signer.identity().signer.clone(),
                    500,
                    10_000,
                    self.epoch,
                    payload,
                    plan,
                )
                .unwrap()
                .into_iter()
                .map(|shard| {
                    self.origin_signer
                        .sign_erasure_shard_v2(shard)
                        .expect("sign erasure shard v2")
                })
                .collect()
            }
        }

        #[test]
        fn v2_signed_receipt_reconstructs_verifies_and_handles_parity_recovery() {
            let fx = ReceiptFixture::new();
            let payload = b"authenticated protocol-v2 erasure reconstruction payload";
            let shards = fx.encode_signed_shards("set-v2-1", payload, 3, 4);
            let recovery: Vec<_> = shards
                .iter()
                .filter(|shard| shard.message.shard.shard_index != 1)
                .cloned()
                .collect();

            let (recovered, signed) = reconstruct_live_with_receipt_v2(
                &recovery,
                &fx.recon_signer,
                20_000,
                &fx.registry,
                fx.epoch,
                &fx.authority,
            )
            .unwrap();
            assert_eq!(recovered, payload);
            assert_eq!(
                signed.receipt.schema_id,
                RECONSTRUCTION_RECEIPT_SCHEMA_ID_V2
            );
            assert_eq!(signed.receipt.protocol_version, ProtocolVersion::V2);
            assert_eq!(signed.receipt.recovered_shard_index, Some(1));
            signed
                .verify_live(&fx.registry, fx.epoch, &fx.authority)
                .unwrap();
            signed
                .verify_live_against_signed_shards(
                    &recovery,
                    true,
                    &fx.registry,
                    fx.epoch,
                    &fx.authority,
                )
                .unwrap();
        }

        #[test]
        fn v2_receipt_enforces_ingress_caps_before_canonicalization() {
            let fx = ReceiptFixture::new();
            let shards = fx.encode_signed_shards("set-v2-bounds", b"bounded", 2, 3);
            let (_payload, signed) = reconstruct_live_with_receipt_v2(
                &shards[..2],
                &fx.recon_signer,
                21_000,
                &fx.registry,
                fx.epoch,
                &fx.authority,
            )
            .unwrap();

            let mut exact = signed.receipt.clone();
            exact.shard_set_id = "s".repeat(FLEET_V2_MAX_IDENTIFIER_BYTES);
            exact.receipt_commitment = exact.compute_commitment();
            assert!(exact.validate_fleet_ingress_limits().is_ok());

            let mut oversized_id = exact.clone();
            oversized_id.shard_set_id.push('x');
            assert!(matches!(
                oversized_id.fleet_unsigned_view_v2(fx.recon_signer.identity()),
                Err(FleetIdentityError::NonCanonicalMessage { ref detail, .. })
                    if detail.contains("ingress limit exceeded")
            ));

            let mut oversized_map = signed.receipt.clone();
            for idx in 0..=FLEET_V2_MAX_MAP_ENTRIES {
                oversized_map
                    .extensions
                    .insert(format!("k-{idx}"), "v".to_string());
            }
            assert!(matches!(
                oversized_map.validate_fleet_ingress_limits(),
                Err(FleetIdentityError::NonCanonicalMessage { ref detail, .. })
                    if detail.contains("ingress limit exceeded")
            ));

            let mut oversized_contributors = signed.receipt;
            let sample = oversized_contributors.contributing_shards[0].clone();
            oversized_contributors.contributing_shards =
                vec![sample; FLEET_V2_MAX_ERASURE_SHARDS + 1];
            assert!(matches!(
                oversized_contributors.validate_fleet_ingress_limits(),
                Err(FleetIdentityError::NonCanonicalMessage { ref detail, .. })
                    if detail.contains("contributing_shards")
            ));
        }

        #[test]
        fn v2_receipt_rejects_false_length_version_parity_and_forged_signers() {
            let fx = ReceiptFixture::new();
            let shards = fx.encode_signed_shards("set-v2-neg", b"shard-bound invariants", 2, 4);
            let (_payload, signed) = reconstruct_live_with_receipt_v2(
                &shards[..2],
                &fx.recon_signer,
                22_000,
                &fx.registry,
                fx.epoch,
                &fx.authority,
            )
            .unwrap();

            // Wrong/forged signer key cannot sign or verify another node's receipt.
            assert!(matches!(
                fx.other_signer.sign_detached_message_v2(&signed.receipt),
                Err(FleetIdentityError::SignerMismatch { .. })
            ));
            let forged_sig = SignedReconstructionReceiptV2 {
                receipt: signed.receipt.clone(),
                signature: FleetSignatureV2 {
                    fleet_authority_id: fx.authority.id,
                    signer: fx.other_signer.identity().signer.clone(),
                    key_id: fx.other_signer.identity().key_id,
                    key_sequence: 1,
                    signature: signed.signature.signature.clone(),
                },
            };
            assert!(
                forged_sig
                    .verify_live(&fx.registry, fx.epoch, &fx.authority)
                    .is_err()
            );

            // Re-signed false payload_len passes detached receipt signature alone
            // (without shards), but MUST fail verify_live_against_signed_shards.
            let mut false_len = signed.receipt.clone();
            false_len.payload_len += 1;
            false_len.receipt_commitment = false_len.compute_commitment();
            let false_len_signed = SignedReconstructionReceiptV2 {
                signature: fx
                    .recon_signer
                    .sign_detached_message_v2(&false_len)
                    .unwrap(),
                receipt: false_len,
            };
            assert!(matches!(
                false_len_signed.verify_live_against_signed_shards(
                    &shards,
                    false,
                    &fx.registry,
                    fx.epoch,
                    &fx.authority,
                ),
                Err(ReceiptV2Error::Receipt(
                    ReceiptError::ShardCommitmentMismatch { .. }
                ))
            ));

            // False protocol version, superfluous parity, multiple parity, and
            // out-of-range parity are rejected before signing/verification.
            let mut false_version = signed.receipt.clone();
            false_version.protocol_version = ProtocolVersion::V1;
            false_version.receipt_commitment = false_version.compute_commitment();
            assert!(
                fx.recon_signer
                    .sign_detached_message_v2(&false_version)
                    .is_err()
            );

            let mut superfluous_parity = signed.receipt.clone();
            superfluous_parity
                .contributing_shards
                .push(ShardCommitment::from_shard(&shards[2].message.shard));
            superfluous_parity.receipt_commitment = superfluous_parity.compute_commitment();
            assert!(
                fx.recon_signer
                    .sign_detached_message_v2(&superfluous_parity)
                    .is_err()
            );

            let recovery: Vec<_> = shards
                .iter()
                .filter(|shard| shard.message.shard.shard_index != 0)
                .cloned()
                .collect();
            let (_p, recovery_signed) = reconstruct_live_with_receipt_v2(
                &recovery,
                &fx.recon_signer,
                22_500,
                &fx.registry,
                fx.epoch,
                &fx.authority,
            )
            .unwrap();

            let mut out_of_range = recovery_signed.receipt.clone();
            out_of_range
                .contributing_shards
                .iter_mut()
                .find(|c| c.role == ErasureShardRole::Parity)
                .unwrap()
                .shard_index = out_of_range.plan.total_shards;
            out_of_range.receipt_commitment = out_of_range.compute_commitment();
            assert!(
                fx.recon_signer
                    .sign_detached_message_v2(&out_of_range)
                    .is_err()
            );

            let mut multi_parity = recovery_signed.receipt;
            multi_parity
                .contributing_shards
                .push(ShardCommitment::from_shard(&shards[3].message.shard));
            multi_parity.contributing_shards.sort();
            multi_parity.receipt_commitment = multi_parity.compute_commitment();
            assert!(
                fx.recon_signer
                    .sign_detached_message_v2(&multi_parity)
                    .is_err()
            );
        }

        #[test]
        fn trusted_ledger_restores_live_and_historical_rotated_keys_and_rejects_tampering() {
            let mut fx = ReceiptFixture::new();
            let shards = fx.encode_signed_shards("set-v2-ledger", b"persisted ledger", 2, 3);
            let (_payload, signed) = reconstruct_live_with_receipt_v2(
                &shards[..2],
                &fx.recon_signer,
                23_000,
                &fx.registry,
                fx.epoch,
                &fx.authority,
            )
            .unwrap();

            let mut ledger = TrustedReconstructionReceiptLedger::new();
            assert!(
                ledger
                    .record_live(signed.clone(), &fx.registry, fx.epoch, &fx.authority)
                    .unwrap()
            );
            assert!(
                !ledger
                    .record_live(signed.clone(), &fx.registry, fx.epoch, &fx.authority)
                    .unwrap()
            );

            let bytes = serde_json::to_vec(&ledger).unwrap();
            let mut restored = TrustedReconstructionReceiptLedger::restore_live_verified(
                &bytes,
                &fx.registry,
                fx.epoch,
                &fx.authority,
            )
            .unwrap();
            assert_eq!(restored.len(), 1);
            // Immediate post-roundtrip dedup index is active.
            assert!(
                !restored
                    .record_live(signed.clone(), &fx.registry, fx.epoch, &fx.authority)
                    .unwrap()
            );

            // Tampered JSON is rejected.
            let mut tampered: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            tampered["receipts"][0]["receipt"]["payload_len"] = serde_json::Value::from(999u64);
            assert!(
                TrustedReconstructionReceiptLedger::restore_live_verified(
                    &serde_json::to_vec(&tampered).unwrap(),
                    &fx.registry,
                    fx.epoch,
                    &fx.authority,
                )
                .is_err()
            );

            // Duplicate JSON commitment is rejected.
            let mut dup_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let first = dup_json["receipts"][0].clone();
            dup_json["receipts"].as_array_mut().unwrap().push(first);
            assert!(matches!(
                TrustedReconstructionReceiptLedger::restore_live_verified(
                    &serde_json::to_vec(&dup_json).unwrap(),
                    &fx.registry,
                    fx.epoch,
                    &fx.authority,
                ),
                Err(ReceiptV2Error::DuplicateReceiptCommitment { .. })
            ));

            // Oversized frame is rejected before JSON parsing.
            let oversized = vec![b' '; FLEET_V2_MAX_FRAME_BYTES + 1];
            assert!(
                TrustedReconstructionReceiptLedger::restore_live_verified(
                    &oversized,
                    &fx.registry,
                    fx.epoch,
                    &fx.authority,
                )
                .is_err()
            );

            // Rotate recon_signer to key_sequence=2 at epoch 4: live restore rejects
            // the retired key, whereas historical restore with finalized preimage
            // acceptance succeeds and rebuilds dedup atomically.
            let rotated_signer = FleetSigner::new(
                fx.authority.id,
                node("recon-v2"),
                2,
                SigningKey::from_bytes([0x44; 32]).unwrap(),
            )
            .unwrap();
            let pre_rotation_gen = fx.registry.generation();
            let cutover = SecurityEpoch::from_raw(4);
            fx.registry = FleetVerificationRegistryPersistence::new(&mut fx.storage, &fx.event)
                .prepare_rotation(
                    &fx.registry,
                    node("recon-v2"),
                    1,
                    2,
                    rotated_signer.verification_key().clone(),
                    cutover,
                    &fx.authority,
                )
                .unwrap()
                .finalize_and_publish(&fx.authority)
                .unwrap();

            assert!(matches!(
                TrustedReconstructionReceiptLedger::restore_live_verified(
                    &bytes,
                    &fx.registry,
                    fx.epoch,
                    &fx.authority,
                ),
                Err(ReceiptV2Error::Identity(
                    FleetIdentityError::RotatedKey { .. }
                ))
            ));
            assert!(matches!(
                TrustedReconstructionReceiptLedger::restore_live_verified(
                    &bytes,
                    &fx.registry,
                    cutover,
                    &fx.authority,
                ),
                Err(ReceiptV2Error::Identity(
                    FleetIdentityError::UntrustedMessageEpoch { .. }
                ))
            ));

            let preimage_hash = ContentHash::compute(
                &signed
                    .receipt
                    .fleet_signature_preimage_v2(fx.recon_signer.identity())
                    .unwrap(),
            );
            let post_rotation_acceptance = FleetHistoricalAcceptanceContext::for_authority(
                fx.authority.id,
                fx.registry.generation(),
                fx.registry
                    .authority_head_at(fx.registry.generation())
                    .unwrap(),
            )
            .with_accepted_preimage_hash(preimage_hash);
            assert!(matches!(
                TrustedReconstructionReceiptLedger::restore_historical_verified(
                    &bytes,
                    &fx.registry,
                    &post_rotation_acceptance,
                    &fx.authority,
                ),
                Err(ReceiptV2Error::Identity(
                    FleetIdentityError::HistoricalGenerationOutsideKeyWindow { .. }
                ))
            ));

            let acceptance = FleetHistoricalAcceptanceContext::for_authority(
                fx.authority.id,
                pre_rotation_gen,
                fx.registry.authority_head_at(pre_rotation_gen).unwrap(),
            )
            .with_accepted_preimage_hash(preimage_hash);
            let hist_restored = TrustedReconstructionReceiptLedger::restore_historical_verified(
                &bytes,
                &fx.registry,
                &acceptance,
                &fx.authority,
            )
            .unwrap();
            assert_eq!(hist_restored.len(), 1);
            assert!(hist_restored.contains(&signed.receipt.receipt_commitment));
        }
    }
}
