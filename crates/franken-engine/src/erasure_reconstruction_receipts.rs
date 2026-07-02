//! Reconstruction-proof signed receipts for erasure-coded fleet gossip.
//!
//! Track II (`bd-cixqu.35.2`) — when a fleet node reconstructs an original
//! payload from a `k`-of-`n` erasure shard set (see
//! [`crate::fleet_immune_protocol`]'s erasure-coded gossip lane), it must be
//! able to emit a tamper-evident proof of *what it reconstructed and from
//! which shards*. That proof is a [`ReconstructionReceipt`]:
//!
//! - **Commitment to the contributing shards.** The receipt binds the shard
//!   indices, roles, per-shard content hashes, and origin identities that
//!   materially fed the reconstruction, plus the coding parameters used.
//! - **Signed attestation of correct reconstruction.** The receipt carries a
//!   keyed-authenticity signature (the same primitive every other fleet
//!   message is signed with — [`AuthenticityHash::compute_keyed`]) over a
//!   length-prefixed canonical commitment, attributed to the reconstructing
//!   node for non-repudiation.
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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::fleet_immune_protocol::{
    ErasureCodingPlan, ErasureShard, ErasureShardRole, MessageSignature, NodeId, ProtocolError,
    ProtocolVersion, reconstruct_erasure_payload,
};
use crate::hash_tiers::{AuthenticityHash, ContentHash};

/// Schema identifier stamped into every receipt for drift detection.
pub const RECONSTRUCTION_RECEIPT_SCHEMA_ID: &str = "franken-engine.reconstruction-receipt.v1";

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
    /// The signature does not authenticate the commitment.
    InvalidSignature,
    /// A contributing shard was absent from the supplied verification set.
    MissingShardForVerification { shard_index: u16 },
    /// A supplied shard's recomputed commitment disagrees with the receipt.
    ShardCommitmentMismatch { shard_index: u16 },
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

/// A tamper-evident, signed proof that a node reconstructed a payload from a
/// specific set of erasure shards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Identity of the node that performed the reconstruction.
    pub reconstructing_node: NodeId,
    /// Reconstruction timestamp in nanoseconds.
    pub reconstruction_timestamp_ns: u64,
    /// Content hash over the length-prefixed canonical receipt preimage.
    pub receipt_commitment: ContentHash,
    /// Keyed-authenticity signature over the commitment, by the reconstructing
    /// node.
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
    /// signature authenticates the commitment under the reconstructing node's
    /// identity.
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
        let mut parity_present = false;
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
                    parity_present = true;
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
                if !parity_present {
                    return Err(ReceiptError::InconsistentStructure {
                        reason: "recovery claimed without a parity shard".to_string(),
                    });
                }
                if data_indices.len() != usize::from(self.plan.data_shards) - 1 {
                    return Err(ReceiptError::InconsistentStructure {
                        reason: "recovery requires exactly one missing data shard".to_string(),
                    });
                }
            }
            None => {
                if data_indices.len() != usize::from(self.plan.data_shards) {
                    return Err(ReceiptError::InconsistentStructure {
                        reason: "no recovery claimed but data shards incomplete".to_string(),
                    });
                }
            }
        }

        // The reconstructed payload length must be consistent with the plan.
        if self.payload_len == 0 && self.plan.data_shards == 0 {
            return Err(ReceiptError::InconsistentStructure {
                reason: "zero data shards".to_string(),
            });
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

        let mut by_index: BTreeMap<u16, &ErasureShard> = BTreeMap::new();
        for shard in shards {
            by_index.entry(shard.shard_index).or_insert(shard);
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
                || !shard.payload_hash.constant_time_eq(&self.payload_hash)
            {
                return Err(ReceiptError::ShardCommitmentMismatch {
                    shard_index: commitment.shard_index,
                });
            }
        }

        if reconstruct {
            let contributing: Vec<ErasureShard> = self
                .contributing_shards
                .iter()
                .filter_map(|commitment| {
                    by_index.get(&commitment.shard_index).map(|s| (**s).clone())
                })
                .collect();
            let payload = reconstruct_erasure_payload(&contributing).map_err(|err| {
                ReceiptError::ReconstructionFailed {
                    shard_set_id: self.shard_set_id.clone(),
                    reason: err.to_string(),
                }
            })?;
            if !ContentHash::compute(&payload).constant_time_eq(&self.payload_hash) {
                return Err(ReceiptError::CommitmentMismatch);
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/// Reconstruct a payload from an erasure shard set and emit a signed
/// reconstruction-proof receipt attributed to `reconstructing_node`.
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
        protocol_version: ProtocolVersion::CURRENT,
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
    let mut parity_shard: Option<&ErasureShard> = None;
    for shard in shards {
        match shard.role {
            ErasureShardRole::Data if shard.shard_index < plan.data_shards => {
                data_shards.entry(shard.shard_index).or_insert(shard);
            }
            ErasureShardRole::Parity if shard.shard_index >= plan.data_shards => {
                // Deterministically keep the lowest-index parity shard: the
                // erasure lane emits identical parity for every parity slot when
                // `n - k > 1`, so committing to the smallest index makes the
                // receipt independent of input shard ordering.
                let replace =
                    parity_shard.is_none_or(|existing| shard.shard_index < existing.shard_index);
                if replace {
                    parity_shard = Some(shard);
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
        let parity = parity_shard.ok_or(ReceiptError::InconsistentStructure {
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconstructionReceiptLedger {
    receipts: Vec<ReconstructionReceipt>,
    #[serde(skip)]
    seen: BTreeSet<[u8; 32]>,
}

impl ReconstructionReceiptLedger {
    /// Create an empty ledger.
    pub fn new() -> Self {
        Self::default()
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

    /// Rebuild the in-memory dedup index after deserialization.
    ///
    /// `seen` is `#[serde(skip)]`, so a ledger loaded from disk must call this
    /// once before further `record` calls to restore dedup semantics.
    pub fn reindex(&mut self) {
        self.seen = self
            .receipts
            .iter()
            .map(|receipt| *receipt.receipt_commitment.as_bytes())
            .collect();
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
    fn ledger_reindex_restores_dedup_after_deserialization() {
        let payload = b"reindex restores dedup semantics";
        let shards = shards_for(payload, 2, 3);
        let (_p, receipt) =
            reconstruct_with_receipt(&all_data(&shards), node("recon-21"), 23_000).unwrap();
        let mut ledger = ReconstructionReceiptLedger::new();
        ledger.record(receipt.clone()).unwrap();
        let json = serde_json::to_string(&ledger).unwrap();
        let mut restored: ReconstructionReceiptLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.len(), 1);
        // Before reindex the skip-serialized dedup set is empty.
        restored.reindex();
        assert!(!restored.record(receipt).unwrap());
        assert_eq!(restored.len(), 1);
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
}
