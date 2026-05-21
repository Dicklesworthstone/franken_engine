//! Append-only Merkle transparency log of decision-receipt hashes.
//!
//! Implements an RFC 9162-shaped surface (append, inclusion proof,
//! consistency proof, signed head) on top of the existing Merkle-Mountain-
//! Range (see [`crate::mmr_proof`]) so an external auditor can:
//!
//! 1. Re-verify that a receipt was published in the log at index `i`
//!    without trusting FrankenEngine source code or runtime state.
//! 2. Re-verify that the log's current head is an append-only extension
//!    of any earlier head it once trusted.
//! 3. Re-verify that the head itself was issued by the authorised log
//!    operator (Ed25519 signature over a domain-tagged preimage).
//!
//! Why MMR rather than a hand-rolled CT-style log: bd-cixqu.1.2's
//! acceptance criteria explicitly direct us to reuse the existing
//! [`crate::hash_tiers::AuthenticityHash`] / length-prefixed canonical
//! encoding and BTreeMap-only auxiliary structures. The MMR already
//! ships those primitives, has matching `verify_inclusion` /
//! `verify_consistency` helpers the receipt verifier
//! (`receipt_verifier_pipeline.rs:540-600`) already speaks, and lives
//! under `#![forbid(unsafe_code)]`. Building a parallel CT-shape on top
//! would duplicate the same algebra without earning a new property.
//!
//! Scope (bd-cixqu.1.2):
//! - Producer side: [`TransparencyLog::append_receipt`],
//!   [`TransparencyLog::inclusion_proof_for`],
//!   [`TransparencyLog::consistency_proof_between`],
//!   [`TransparencyLog::sign_head`].
//! - Verifier side: [`verify_receipt_inclusion`],
//!   [`verify_log_consistency_between`], [`verify_signed_head`].
//! - Tree-index arithmetic is saturating per the bead's
//!   "Implementation pointers" — `u64::MAX` is a permanently-error
//!   terminal state rather than a panicking overflow.
//!
//! Out of scope here and tracked as follow-ups under bd-cixqu.1.2's
//! parent epic:
//! - frankensqlite-backed persistence of the leaf table (bead requires
//!   sibling-reuse via [`crate::storage_adapter::StorageAdapter`] — the
//!   adapter contract is in place, an implementation that wires this
//!   log to it lands separately).
//! - Threshold signing of heads (the head is signed with a single
//!   Ed25519 key here; the threshold-signing module already exists and
//!   can wrap [`SignedLogHead::sign`] in a coordinator-style ceremony
//!   without changing the verifier API).
//! - `frankenctl verify receipt --check-transparency` wiring (the
//!   verifier pipeline already accepts an `inclusion_proof` +
//!   `consistency_proofs` shape — this module produces those proofs).
//! - `run_manifest.json` head publication.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{self, CanonicalValue, SchemaHash};
use crate::engine_object_id::ObjectDomain;
use crate::hash_tiers::ContentHash;
use crate::mmr_proof::{
    MerkleMountainRange, MmrProof, ProofError, ProofType, verify_consistency, verify_inclusion,
};
use crate::signature_preimage::{
    SIGNATURE_SENTINEL, Signature, SignatureError, SignaturePreimage, SigningKey, VerificationKey,
    sign_preimage, verify_signature,
};

// ---------------------------------------------------------------------------
// Schema hashes
// ---------------------------------------------------------------------------

const HEAD_SCHEMA_DEFINITION: &[u8] = b"franken-engine.transparency_log.head.v1";
const ENTRY_SCHEMA_DEFINITION: &[u8] = b"franken-engine.transparency_log.entry.v1";

fn head_schema() -> SchemaHash {
    SchemaHash::from_definition(HEAD_SCHEMA_DEFINITION)
}

fn entry_schema() -> SchemaHash {
    SchemaHash::from_definition(ENTRY_SCHEMA_DEFINITION)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Stable error taxonomy for transparency-log operations.
///
/// All variants carry the data needed to produce structured evidence
/// without re-querying the producer; mirrors the
/// [`crate::storage_adapter::StorageError`] / [`SignatureError`] style.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransparencyLogError {
    /// The log has no entries yet, so the requested operation is
    /// undefined (`root_hash`, `sign_head`, etc.).
    Empty,
    /// The requested leaf index does not exist in this log.
    LeafIndexOutOfRange { index: u64, length: u64 },
    /// Underlying MMR proof operation failed.
    Proof { detail: String },
    /// Signing or verification failed.
    Signature { detail: String },
    /// The proof's stream length does not match the head's tree length;
    /// inclusion is only meaningful when proven against the head it was
    /// generated for.
    InclusionLengthMismatch { proof_length: u64, head_length: u64 },
    /// The proof's root hash does not match the head's root hash; the
    /// proof was generated for a different MMR state than the head
    /// represents.
    RootMismatch {
        proof_root: ContentHash,
        head_root: ContentHash,
    },
    /// The leaf index for which the proof was generated does not match
    /// the receipt the verifier is checking.
    ReceiptIndexMismatch {
        proof_index: u64,
        receipt_index: u64,
    },
    /// The supplied proof type does not match the verification
    /// operation (e.g. handing a consistency proof to inclusion
    /// verification).
    WrongProofType { expected: ProofType, got: ProofType },
    /// The tree-index counter has saturated at `u64::MAX`; this log
    /// instance can no longer accept appends. Reject rather than
    /// silently wrap, per the determinism rule.
    CounterExhausted,
    /// The log id encoded into the signed head does not match the log
    /// id the verifier expected (cross-log replay defence).
    LogIdMismatch { expected: String, found: String },
}

impl TransparencyLogError {
    /// Stable machine-readable error code, suitable for structured logs.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Empty => "FE-TLOG-0001",
            Self::LeafIndexOutOfRange { .. } => "FE-TLOG-0002",
            Self::Proof { .. } => "FE-TLOG-0003",
            Self::Signature { .. } => "FE-TLOG-0004",
            Self::InclusionLengthMismatch { .. } => "FE-TLOG-0005",
            Self::RootMismatch { .. } => "FE-TLOG-0006",
            Self::ReceiptIndexMismatch { .. } => "FE-TLOG-0007",
            Self::WrongProofType { .. } => "FE-TLOG-0008",
            Self::CounterExhausted => "FE-TLOG-0009",
            Self::LogIdMismatch { .. } => "FE-TLOG-0010",
        }
    }
}

impl fmt::Display for TransparencyLogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "transparency log is empty"),
            Self::LeafIndexOutOfRange { index, length } => {
                write!(f, "leaf index {index} out of range (length {length})")
            }
            Self::Proof { detail } => write!(f, "merkle proof error: {detail}"),
            Self::Signature { detail } => write!(f, "signature error: {detail}"),
            Self::InclusionLengthMismatch {
                proof_length,
                head_length,
            } => write!(
                f,
                "inclusion proof length {proof_length} != head tree length {head_length}"
            ),
            Self::RootMismatch {
                proof_root,
                head_root,
            } => write!(
                f,
                "proof root {} != head root {}",
                proof_root.to_hex(),
                head_root.to_hex()
            ),
            Self::ReceiptIndexMismatch {
                proof_index,
                receipt_index,
            } => write!(
                f,
                "proof leaf index {proof_index} != receipt index {receipt_index}"
            ),
            Self::WrongProofType { expected, got } => {
                write!(f, "expected {expected:?} proof, got {got:?}")
            }
            Self::CounterExhausted => write!(f, "tree-index counter saturated at u64::MAX"),
            Self::LogIdMismatch { expected, found } => {
                write!(f, "log id mismatch: expected `{expected}`, found `{found}`")
            }
        }
    }
}

impl std::error::Error for TransparencyLogError {}

impl From<ProofError> for TransparencyLogError {
    fn from(err: ProofError) -> Self {
        Self::Proof {
            detail: err.to_string(),
        }
    }
}

impl From<SignatureError> for TransparencyLogError {
    fn from(err: SignatureError) -> Self {
        Self::Signature {
            detail: err.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

/// A single appended leaf: the receipt hash plus its assigned leaf
/// index and an append timestamp. Carries enough metadata that a
/// persistence layer (e.g. frankensqlite) can store it as one row and
/// the producer can reconstruct the in-memory MMR by replaying entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparencyLogEntry {
    /// 0-based leaf index in the log's MMR.
    pub leaf_index: u64,
    /// The receipt hash that was appended at this index.
    pub receipt_hash: ContentHash,
    /// Wall-clock nanoseconds at append time, supplied by the caller so
    /// the log itself stays deterministic / replayable.
    pub appended_at_ns: u64,
    /// The log this entry belongs to (binds the entry to a log id at
    /// rest so a stale entry from another log can't be replayed into
    /// this one).
    pub log_id: String,
}

impl TransparencyLogEntry {
    /// Canonical schema hash for entry serde.
    pub fn schema_hash() -> SchemaHash {
        entry_schema()
    }

    /// Canonical-value view used by the schema-hash bookkeeping. Not
    /// signed directly (the log signs *heads*, not individual entries)
    /// but exposed so persistence layers can derive a content hash for
    /// row-level identity.
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "leaf_index".to_string(),
            CanonicalValue::U64(self.leaf_index),
        );
        map.insert(
            "receipt_hash".to_string(),
            CanonicalValue::Bytes(self.receipt_hash.as_bytes().to_vec()),
        );
        map.insert(
            "appended_at_ns".to_string(),
            CanonicalValue::U64(self.appended_at_ns),
        );
        map.insert(
            "log_id".to_string(),
            CanonicalValue::String(self.log_id.clone()),
        );
        CanonicalValue::Map(map)
    }
}

// ---------------------------------------------------------------------------
// SignedLogHead
// ---------------------------------------------------------------------------

/// A signed snapshot of the log's state at a moment in time. This is
/// the publishable witness an external auditor needs in order to
/// verify subsequent inclusion / consistency proofs.
///
/// The signature is over a domain-tagged preimage that binds:
/// - the log id,
/// - the tree length (number of leaves),
/// - the root hash,
/// - the signing timestamp,
/// - the signer key id.
///
/// Tampering with any of those fields invalidates the signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedLogHead {
    /// Stable identifier for the log instance (e.g.
    /// `"franken-engine.receipts.prod"`).
    pub log_id: String,
    /// Number of leaves the log has when this head was produced.
    pub tree_length: u64,
    /// Root hash of the MMR at this head.
    pub root_hash: ContentHash,
    /// Wall-clock nanoseconds at signing time (caller-supplied so the
    /// head stays deterministic / replayable).
    pub signed_at_ns: u64,
    /// Identifier of the key that produced the signature (operator
    /// rotation evidence; not used for verification — the verifier
    /// supplies the [`VerificationKey`] separately).
    pub signer_key_id: String,
    /// Ed25519 signature over the head's preimage.
    pub signature: Signature,
}

impl SignedLogHead {
    /// Canonical schema hash for head serde.
    pub fn schema_hash() -> SchemaHash {
        head_schema()
    }

    /// Build an unsigned-view canonical value (signature field replaced
    /// by [`SIGNATURE_SENTINEL`]). Used both for signing and verifying.
    fn unsigned_view_inner(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "log_id".to_string(),
            CanonicalValue::String(self.log_id.clone()),
        );
        map.insert(
            "tree_length".to_string(),
            CanonicalValue::U64(self.tree_length),
        );
        map.insert(
            "root_hash".to_string(),
            CanonicalValue::Bytes(self.root_hash.as_bytes().to_vec()),
        );
        map.insert(
            "signed_at_ns".to_string(),
            CanonicalValue::U64(self.signed_at_ns),
        );
        map.insert(
            "signer_key_id".to_string(),
            CanonicalValue::String(self.signer_key_id.clone()),
        );
        map.insert(
            "signature".to_string(),
            CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
        );
        CanonicalValue::Map(map)
    }
}

impl SignaturePreimage for SignedLogHead {
    fn signature_domain(&self) -> ObjectDomain {
        // A log head is functionally a checkpoint of the log's state.
        ObjectDomain::CheckpointArtifact
    }

    fn signature_schema(&self) -> &SchemaHash {
        // The trait wants a `&SchemaHash`; use the inline override so
        // we can return a computed value without leaking a static.
        // Mirrors the pattern in `capability_token.rs:323`.
        unreachable!("use preimage_bytes() directly")
    }

    fn unsigned_view(&self) -> CanonicalValue {
        self.unsigned_view_inner()
    }

    fn preimage_bytes(&self) -> Vec<u8> {
        let schema = head_schema();
        let domain_tag = ObjectDomain::CheckpointArtifact.tag();
        let value_bytes = deterministic_serde::encode_value(&self.unsigned_view_inner());

        let mut preimage = Vec::with_capacity(domain_tag.len() + 32 + value_bytes.len());
        preimage.extend_from_slice(domain_tag);
        preimage.extend_from_slice(schema.as_bytes());
        preimage.extend_from_slice(&value_bytes);
        preimage
    }
}

// ---------------------------------------------------------------------------
// TransparencyLog
// ---------------------------------------------------------------------------

/// Append-only Merkle log of receipt hashes.
///
/// Holds the MMR in memory plus the ordered list of appended entries.
/// Re-hydration from persistence is supported via
/// [`TransparencyLog::replay_from_entries`].
#[derive(Debug)]
pub struct TransparencyLog {
    log_id: String,
    mmr: MerkleMountainRange,
    /// Ordered by [`TransparencyLogEntry::leaf_index`]; the index into
    /// this vector is the leaf index.
    entries: Vec<TransparencyLogEntry>,
    /// Saturating tree-index counter. When the next append would exceed
    /// `u64::MAX`, [`Self::append_receipt`] returns
    /// [`TransparencyLogError::CounterExhausted`] rather than wrapping
    /// or panicking. (bd-cixqu.1.2 "Implementation pointers".)
    next_index: u64,
}

impl TransparencyLog {
    /// Create a new empty transparency log under a stable id.
    pub fn new(log_id: impl Into<String>) -> Self {
        Self {
            log_id: log_id.into(),
            mmr: MerkleMountainRange::new(0),
            entries: Vec::new(),
            next_index: 0,
        }
    }

    /// Create a new transparency log at a given security epoch (forwarded
    /// to the underlying MMR's `epoch_id`). Useful when the receipt
    /// stream's proofs need to carry epoch metadata.
    pub fn new_at_epoch(log_id: impl Into<String>, epoch_id: u64) -> Self {
        Self {
            log_id: log_id.into(),
            mmr: MerkleMountainRange::new(epoch_id),
            entries: Vec::new(),
            next_index: 0,
        }
    }

    /// Replay a previously persisted entry list and rebuild the MMR.
    /// Fails closed if the entry sequence is not strictly contiguous
    /// starting at 0 or carries mismatched log ids.
    pub fn replay_from_entries(
        log_id: impl Into<String>,
        epoch_id: u64,
        entries: Vec<TransparencyLogEntry>,
    ) -> Result<Self, TransparencyLogError> {
        let log_id = log_id.into();
        let mut log = Self::new_at_epoch(log_id.clone(), epoch_id);
        for (expected_index, entry) in entries.into_iter().enumerate() {
            let expected = expected_index as u64;
            if entry.leaf_index != expected {
                return Err(TransparencyLogError::LeafIndexOutOfRange {
                    index: entry.leaf_index,
                    length: expected,
                });
            }
            if entry.log_id != log_id {
                return Err(TransparencyLogError::LogIdMismatch {
                    expected: log_id.clone(),
                    found: entry.log_id,
                });
            }
            log.append_receipt(entry.receipt_hash, entry.appended_at_ns)?;
        }
        Ok(log)
    }

    /// Stable id of this log instance.
    pub fn log_id(&self) -> &str {
        &self.log_id
    }

    /// Number of leaves currently in the log.
    pub fn tree_length(&self) -> u64 {
        self.mmr.num_leaves()
    }

    /// Whether the log has any entries.
    pub fn is_empty(&self) -> bool {
        self.mmr.is_empty()
    }

    /// All entries in append order. Index of the slice equals the
    /// leaf's `leaf_index`.
    pub fn entries(&self) -> &[TransparencyLogEntry] {
        &self.entries
    }

    /// Entry at a specific leaf index.
    pub fn entry_at(&self, leaf_index: u64) -> Option<&TransparencyLogEntry> {
        self.entries.get(leaf_index as usize)
    }

    /// Current root hash. Returns `Empty` when no entries have been
    /// appended yet.
    pub fn current_root(&self) -> Result<ContentHash, TransparencyLogError> {
        if self.mmr.is_empty() {
            return Err(TransparencyLogError::Empty);
        }
        self.mmr.root_hash().map_err(TransparencyLogError::from)
    }

    /// Append a receipt hash, returning the assigned leaf index.
    ///
    /// Uses saturating arithmetic on the index counter so that once the
    /// log reaches `u64::MAX` leaves it permanently refuses further
    /// appends rather than wrapping (which would silently re-issue a
    /// leaf index that any external auditor already trusts).
    pub fn append_receipt(
        &mut self,
        receipt_hash: ContentHash,
        appended_at_ns: u64,
    ) -> Result<u64, TransparencyLogError> {
        if self.next_index == u64::MAX {
            return Err(TransparencyLogError::CounterExhausted);
        }
        let leaf_index = self.next_index;
        self.mmr.append(receipt_hash);
        self.entries.push(TransparencyLogEntry {
            leaf_index,
            receipt_hash,
            appended_at_ns,
            log_id: self.log_id.clone(),
        });
        // Saturating add: next_index reaches u64::MAX exactly when the
        // last legal append happens; the next call returns
        // CounterExhausted on the early check above.
        self.next_index = self.next_index.saturating_add(1);
        Ok(leaf_index)
    }

    /// Build an inclusion proof for the leaf at `leaf_index`.
    pub fn inclusion_proof_for(&self, leaf_index: u64) -> Result<MmrProof, TransparencyLogError> {
        if leaf_index >= self.mmr.num_leaves() {
            return Err(TransparencyLogError::LeafIndexOutOfRange {
                index: leaf_index,
                length: self.mmr.num_leaves(),
            });
        }
        self.mmr
            .inclusion_proof(leaf_index)
            .map_err(TransparencyLogError::from)
    }

    /// Build a consistency proof from `old_length` (which must be
    /// `>= 1` and `<=` the current tree length) to the current head.
    /// The underlying MMR rejects `old_length == 0` as `EmptyStream`,
    /// so it surfaces here as [`TransparencyLogError::Proof`]; callers
    /// that never trusted any earlier head don't need a consistency
    /// proof to begin with — they bind directly to the current
    /// [`SignedLogHead`] via inclusion.
    pub fn consistency_proof_between(
        &self,
        old_length: u64,
    ) -> Result<MmrProof, TransparencyLogError> {
        self.mmr
            .consistency_proof(old_length)
            .map_err(TransparencyLogError::from)
    }

    /// Produce a signed head at the current tree state.
    pub fn sign_head(
        &self,
        signing_key: &SigningKey,
        signer_key_id: impl Into<String>,
        signed_at_ns: u64,
    ) -> Result<SignedLogHead, TransparencyLogError> {
        let root_hash = self.current_root()?;
        let mut head = SignedLogHead {
            log_id: self.log_id.clone(),
            tree_length: self.mmr.num_leaves(),
            root_hash,
            signed_at_ns,
            signer_key_id: signer_key_id.into(),
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };
        let preimage = head.preimage_bytes();
        let signature = sign_preimage(signing_key, &preimage)?;
        head.signature = signature;
        Ok(head)
    }
}

// ---------------------------------------------------------------------------
// External verifier API
// ---------------------------------------------------------------------------

/// Verify that `head` was signed by the supplied verification key.
///
/// This is the prerequisite for any other verification: an unsigned
/// head proves nothing.
pub fn verify_signed_head(
    head: &SignedLogHead,
    verification_key: &VerificationKey,
) -> Result<(), TransparencyLogError> {
    let preimage = head.preimage_bytes();
    verify_signature(verification_key, &preimage, &head.signature)
        .map_err(TransparencyLogError::from)
}

/// Verify that `receipt_hash` was appended at `proof.marker_index` in a
/// log whose head is `head` and whose head was signed by
/// `head_verification_key`.
///
/// Fails closed on:
/// - bad head signature,
/// - wrong proof type,
/// - proof / head length mismatch,
/// - proof / head root mismatch,
/// - inclusion proof failure (tampered receipt, sibling, or index).
pub fn verify_receipt_inclusion(
    receipt_hash: &ContentHash,
    proof: &MmrProof,
    head: &SignedLogHead,
    head_verification_key: &VerificationKey,
) -> Result<(), TransparencyLogError> {
    verify_signed_head(head, head_verification_key)?;
    if proof.proof_type != ProofType::Inclusion {
        return Err(TransparencyLogError::WrongProofType {
            expected: ProofType::Inclusion,
            got: proof.proof_type.clone(),
        });
    }
    if proof.stream_length != head.tree_length {
        return Err(TransparencyLogError::InclusionLengthMismatch {
            proof_length: proof.stream_length,
            head_length: head.tree_length,
        });
    }
    if proof.root_hash != head.root_hash {
        return Err(TransparencyLogError::RootMismatch {
            proof_root: proof.root_hash,
            head_root: head.root_hash,
        });
    }
    verify_inclusion(receipt_hash, proof).map_err(TransparencyLogError::from)
}

/// Verify that a consistency proof links a trusted-earlier `old_root`
/// to a freshly-signed `new_head`. The new head's signature is checked
/// first so a forged head cannot induce belief in the consistency
/// relation.
pub fn verify_log_consistency_between(
    old_root: &ContentHash,
    new_head: &SignedLogHead,
    proof: &MmrProof,
    head_verification_key: &VerificationKey,
) -> Result<(), TransparencyLogError> {
    verify_signed_head(new_head, head_verification_key)?;
    if proof.proof_type != ProofType::Consistency {
        return Err(TransparencyLogError::WrongProofType {
            expected: ProofType::Consistency,
            got: proof.proof_type.clone(),
        });
    }
    if proof.root_hash != new_head.root_hash {
        return Err(TransparencyLogError::RootMismatch {
            proof_root: proof.root_hash,
            head_root: new_head.root_hash,
        });
    }
    verify_consistency(old_root, proof).map_err(TransparencyLogError::from)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature_preimage::generate_keypair_from_seed;

    fn leaf(value: u8) -> ContentHash {
        ContentHash::compute(&[value])
    }

    fn fresh_log() -> TransparencyLog {
        TransparencyLog::new("test-log")
    }

    fn fresh_keypair() -> (SigningKey, VerificationKey) {
        generate_keypair_from_seed(&[7u8; 32])
    }

    // -- Construction / state --

    #[test]
    fn new_log_is_empty() {
        let log = fresh_log();
        assert!(log.is_empty());
        assert_eq!(log.tree_length(), 0);
        assert!(log.entries().is_empty());
        assert_eq!(log.log_id(), "test-log");
    }

    #[test]
    fn new_log_root_errors() {
        let log = fresh_log();
        assert!(matches!(
            log.current_root(),
            Err(TransparencyLogError::Empty)
        ));
    }

    // -- Append --

    #[test]
    fn append_assigns_sequential_leaf_indices() {
        let mut log = fresh_log();
        for i in 0..10u8 {
            let idx = log.append_receipt(leaf(i), 1_000 + i as u64).expect("ok");
            assert_eq!(idx, i as u64);
        }
        assert_eq!(log.tree_length(), 10);
        for (i, entry) in log.entries().iter().enumerate() {
            assert_eq!(entry.leaf_index, i as u64);
            assert_eq!(entry.receipt_hash, leaf(i as u8));
            assert_eq!(entry.appended_at_ns, 1_000 + i as u64);
            assert_eq!(entry.log_id, "test-log");
        }
    }

    #[test]
    fn append_changes_root() {
        let mut log = fresh_log();
        log.append_receipt(leaf(0), 1).unwrap();
        let root_a = log.current_root().unwrap();
        log.append_receipt(leaf(1), 2).unwrap();
        let root_b = log.current_root().unwrap();
        assert_ne!(root_a, root_b);
    }

    #[test]
    fn append_is_deterministic_for_same_inputs() {
        let mut a = fresh_log();
        let mut b = fresh_log();
        for i in 0..16u8 {
            a.append_receipt(leaf(i), 100).unwrap();
            b.append_receipt(leaf(i), 100).unwrap();
        }
        assert_eq!(a.current_root().unwrap(), b.current_root().unwrap());
        assert_eq!(a.tree_length(), b.tree_length());
    }

    #[test]
    fn counter_exhausted_blocks_further_appends() {
        // Construct an artificially-saturated log by writing
        // `next_index` directly (test-only access via Self fields is
        // not permitted, so we model exhaustion by populating the
        // first slot then mutating).
        let mut log = fresh_log();
        log.append_receipt(leaf(0), 1).unwrap();
        // Force the counter to its terminal state.
        log.next_index = u64::MAX;
        match log.append_receipt(leaf(1), 2) {
            Err(TransparencyLogError::CounterExhausted) => {}
            other => panic!("expected CounterExhausted, got {other:?}"),
        }
        // The exhausted state's error code is stable.
        assert_eq!(
            TransparencyLogError::CounterExhausted.code(),
            "FE-TLOG-0009"
        );
    }

    // -- Inclusion proof --

    #[test]
    fn inclusion_proof_succeeds_for_every_index() {
        let mut log = fresh_log();
        for i in 0..32u8 {
            log.append_receipt(leaf(i), i as u64).unwrap();
        }
        for i in 0..32u64 {
            let proof = log.inclusion_proof_for(i).expect("proof");
            verify_inclusion(&leaf(i as u8), &proof).expect("verify");
            assert_eq!(proof.marker_index, i);
            assert_eq!(proof.stream_length, 32);
            assert_eq!(proof.proof_type, ProofType::Inclusion);
        }
    }

    #[test]
    fn inclusion_proof_out_of_range_errs() {
        let mut log = fresh_log();
        log.append_receipt(leaf(0), 1).unwrap();
        match log.inclusion_proof_for(5) {
            Err(TransparencyLogError::LeafIndexOutOfRange { index, length }) => {
                assert_eq!(index, 5);
                assert_eq!(length, 1);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // -- Consistency proof --

    #[test]
    fn consistency_proof_old_length_zero_is_rejected_by_underlying_mmr() {
        // The MMR's `consistency_proof` treats `old_length == 0` as
        // `EmptyStream`, which surfaces through our wrapper as the
        // `Proof` variant. This pins that contract so a future MMR
        // change that "succeeds" silently is caught by this test.
        let mut log = fresh_log();
        for i in 0..4u8 {
            log.append_receipt(leaf(i), 1).unwrap();
        }
        let err = log
            .consistency_proof_between(0)
            .expect_err("zero old_length is rejected by MMR");
        assert!(matches!(err, TransparencyLogError::Proof { .. }));
    }

    #[test]
    fn consistency_proof_succeeds_between_real_heads() {
        let mut log = fresh_log();
        for i in 0..4u8 {
            log.append_receipt(leaf(i), 1).unwrap();
        }
        let old_root = log.current_root().unwrap();
        for i in 4..10u8 {
            log.append_receipt(leaf(i), 2).unwrap();
        }
        let proof = log.consistency_proof_between(4).expect("proof");
        verify_consistency(&old_root, &proof).expect("verify");
    }

    #[test]
    fn consistency_proof_old_length_too_large_errs() {
        let mut log = fresh_log();
        log.append_receipt(leaf(0), 1).unwrap();
        let err = log
            .consistency_proof_between(10)
            .expect_err("must err for too-large old length");
        assert!(matches!(err, TransparencyLogError::Proof { .. }));
    }

    // -- Signed head --

    #[test]
    fn sign_head_produces_verifiable_signature() {
        let (sk, vk) = fresh_keypair();
        let mut log = fresh_log();
        log.append_receipt(leaf(0), 1).unwrap();
        log.append_receipt(leaf(1), 2).unwrap();
        let head = log
            .sign_head(&sk, "op-key-001", 1_000_000)
            .expect("sign head");
        verify_signed_head(&head, &vk).expect("verify head");
        assert_eq!(head.tree_length, 2);
        assert_eq!(head.signed_at_ns, 1_000_000);
        assert_eq!(head.signer_key_id, "op-key-001");
        assert_eq!(head.log_id, "test-log");
    }

    #[test]
    fn sign_head_errs_on_empty_log() {
        let (sk, _vk) = fresh_keypair();
        let log = fresh_log();
        assert!(matches!(
            log.sign_head(&sk, "k", 1),
            Err(TransparencyLogError::Empty)
        ));
    }

    #[test]
    fn signed_head_preimage_binds_log_id() {
        let (sk, vk) = fresh_keypair();
        let mut log = fresh_log();
        log.append_receipt(leaf(0), 1).unwrap();
        let mut head = log.sign_head(&sk, "k", 100).unwrap();
        head.log_id = "different-log".to_string();
        assert!(matches!(
            verify_signed_head(&head, &vk),
            Err(TransparencyLogError::Signature { .. })
        ));
    }

    #[test]
    fn signed_head_preimage_binds_tree_length() {
        let (sk, vk) = fresh_keypair();
        let mut log = fresh_log();
        log.append_receipt(leaf(0), 1).unwrap();
        let mut head = log.sign_head(&sk, "k", 100).unwrap();
        head.tree_length = head.tree_length.wrapping_add(1);
        assert!(matches!(
            verify_signed_head(&head, &vk),
            Err(TransparencyLogError::Signature { .. })
        ));
    }

    #[test]
    fn signed_head_preimage_binds_root_hash() {
        let (sk, vk) = fresh_keypair();
        let mut log = fresh_log();
        log.append_receipt(leaf(0), 1).unwrap();
        let mut head = log.sign_head(&sk, "k", 100).unwrap();
        head.root_hash = ContentHash::compute(b"forged");
        assert!(matches!(
            verify_signed_head(&head, &vk),
            Err(TransparencyLogError::Signature { .. })
        ));
    }

    #[test]
    fn signed_head_preimage_binds_signed_at_ns() {
        let (sk, vk) = fresh_keypair();
        let mut log = fresh_log();
        log.append_receipt(leaf(0), 1).unwrap();
        let mut head = log.sign_head(&sk, "k", 100).unwrap();
        head.signed_at_ns = head.signed_at_ns.wrapping_add(1);
        assert!(matches!(
            verify_signed_head(&head, &vk),
            Err(TransparencyLogError::Signature { .. })
        ));
    }

    #[test]
    fn signed_head_preimage_binds_signer_key_id() {
        let (sk, vk) = fresh_keypair();
        let mut log = fresh_log();
        log.append_receipt(leaf(0), 1).unwrap();
        let mut head = log.sign_head(&sk, "k", 100).unwrap();
        head.signer_key_id = "rotated-key".to_string();
        assert!(matches!(
            verify_signed_head(&head, &vk),
            Err(TransparencyLogError::Signature { .. })
        ));
    }

    #[test]
    fn signed_head_serde_round_trips() {
        let (sk, _vk) = fresh_keypair();
        let mut log = fresh_log();
        for i in 0..4u8 {
            log.append_receipt(leaf(i), i as u64).unwrap();
        }
        let head = log.sign_head(&sk, "k", 999).unwrap();
        let json = serde_json::to_string(&head).expect("ser");
        let round: SignedLogHead = serde_json::from_str(&json).expect("de");
        assert_eq!(head, round);
    }

    #[test]
    fn entry_serde_round_trips() {
        let entry = TransparencyLogEntry {
            leaf_index: 7,
            receipt_hash: leaf(42),
            appended_at_ns: 12345,
            log_id: "x".to_string(),
        };
        let json = serde_json::to_string(&entry).expect("ser");
        let round: TransparencyLogEntry = serde_json::from_str(&json).expect("de");
        assert_eq!(entry, round);
    }

    // -- verify_receipt_inclusion --

    #[test]
    fn verify_receipt_inclusion_succeeds_for_real_proof() {
        let (sk, vk) = fresh_keypair();
        let mut log = fresh_log();
        for i in 0..8u8 {
            log.append_receipt(leaf(i), 1).unwrap();
        }
        let head = log.sign_head(&sk, "k", 1).unwrap();
        for i in 0..8u64 {
            let proof = log.inclusion_proof_for(i).unwrap();
            verify_receipt_inclusion(&leaf(i as u8), &proof, &head, &vk).expect("ok");
        }
    }

    #[test]
    fn verify_receipt_inclusion_fails_on_tampered_receipt() {
        let (sk, vk) = fresh_keypair();
        let mut log = fresh_log();
        for i in 0..4u8 {
            log.append_receipt(leaf(i), 1).unwrap();
        }
        let head = log.sign_head(&sk, "k", 1).unwrap();
        let proof = log.inclusion_proof_for(2).unwrap();
        let err = verify_receipt_inclusion(&leaf(99), &proof, &head, &vk).unwrap_err();
        assert!(matches!(err, TransparencyLogError::Proof { .. }));
    }

    #[test]
    fn verify_receipt_inclusion_fails_on_forged_head_signature() {
        let (sk, vk) = fresh_keypair();
        let mut log = fresh_log();
        log.append_receipt(leaf(0), 1).unwrap();
        let mut head = log.sign_head(&sk, "k", 1).unwrap();
        let mut bad_bytes = head.signature.to_bytes();
        bad_bytes[0] ^= 0x01;
        head.signature = Signature::from_bytes(bad_bytes);
        let proof = log.inclusion_proof_for(0).unwrap();
        let err = verify_receipt_inclusion(&leaf(0), &proof, &head, &vk).unwrap_err();
        assert!(matches!(err, TransparencyLogError::Signature { .. }));
    }

    #[test]
    fn verify_receipt_inclusion_fails_on_wrong_vk() {
        let (sk, _vk) = fresh_keypair();
        let (_sk2, vk2) = generate_keypair_from_seed(&[9u8; 32]);
        let mut log = fresh_log();
        log.append_receipt(leaf(0), 1).unwrap();
        let head = log.sign_head(&sk, "k", 1).unwrap();
        let proof = log.inclusion_proof_for(0).unwrap();
        let err = verify_receipt_inclusion(&leaf(0), &proof, &head, &vk2).unwrap_err();
        assert!(matches!(err, TransparencyLogError::Signature { .. }));
    }

    #[test]
    fn verify_receipt_inclusion_fails_on_length_mismatch() {
        let (sk, vk) = fresh_keypair();
        let mut log = fresh_log();
        log.append_receipt(leaf(0), 1).unwrap();
        log.append_receipt(leaf(1), 2).unwrap();
        let head = log.sign_head(&sk, "k", 1).unwrap();
        let mut proof = log.inclusion_proof_for(0).unwrap();
        proof.stream_length = 99;
        let err = verify_receipt_inclusion(&leaf(0), &proof, &head, &vk).unwrap_err();
        match err {
            TransparencyLogError::InclusionLengthMismatch {
                proof_length,
                head_length,
            } => {
                assert_eq!(proof_length, 99);
                assert_eq!(head_length, 2);
            }
            other => panic!("expected length mismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_receipt_inclusion_fails_on_root_mismatch() {
        let (sk, vk) = fresh_keypair();
        let mut log = fresh_log();
        log.append_receipt(leaf(0), 1).unwrap();
        let head = log.sign_head(&sk, "k", 1).unwrap();
        let mut proof = log.inclusion_proof_for(0).unwrap();
        proof.root_hash = ContentHash::compute(b"fake");
        let err = verify_receipt_inclusion(&leaf(0), &proof, &head, &vk).unwrap_err();
        assert!(matches!(err, TransparencyLogError::RootMismatch { .. }));
    }

    #[test]
    fn verify_receipt_inclusion_fails_when_given_consistency_proof() {
        let (sk, vk) = fresh_keypair();
        let mut log = fresh_log();
        for i in 0..4u8 {
            log.append_receipt(leaf(i), 1).unwrap();
        }
        let head = log.sign_head(&sk, "k", 1).unwrap();
        let cp = log.consistency_proof_between(2).unwrap();
        let err = verify_receipt_inclusion(&leaf(0), &cp, &head, &vk).unwrap_err();
        assert!(matches!(err, TransparencyLogError::WrongProofType { .. }));
    }

    // -- verify_log_consistency_between --

    #[test]
    fn verify_log_consistency_between_succeeds() {
        let (sk, vk) = fresh_keypair();
        let mut log = fresh_log();
        for i in 0..4u8 {
            log.append_receipt(leaf(i), 1).unwrap();
        }
        let old_root = log.current_root().unwrap();
        for i in 4..8u8 {
            log.append_receipt(leaf(i), 1).unwrap();
        }
        let new_head = log.sign_head(&sk, "k", 1).unwrap();
        let cp = log.consistency_proof_between(4).unwrap();
        verify_log_consistency_between(&old_root, &new_head, &cp, &vk).expect("ok");
    }

    #[test]
    fn verify_log_consistency_fails_on_forged_old_root() {
        let (sk, vk) = fresh_keypair();
        let mut log = fresh_log();
        for i in 0..4u8 {
            log.append_receipt(leaf(i), 1).unwrap();
        }
        for i in 4..8u8 {
            log.append_receipt(leaf(i), 1).unwrap();
        }
        let new_head = log.sign_head(&sk, "k", 1).unwrap();
        let cp = log.consistency_proof_between(4).unwrap();
        let bogus = ContentHash::compute(b"not-the-old-root");
        let err = verify_log_consistency_between(&bogus, &new_head, &cp, &vk).unwrap_err();
        assert!(matches!(err, TransparencyLogError::Proof { .. }));
    }

    #[test]
    fn verify_log_consistency_fails_when_given_inclusion_proof() {
        let (sk, vk) = fresh_keypair();
        let mut log = fresh_log();
        for i in 0..4u8 {
            log.append_receipt(leaf(i), 1).unwrap();
        }
        let head = log.sign_head(&sk, "k", 1).unwrap();
        let ip = log.inclusion_proof_for(0).unwrap();
        let old_root = log.current_root().unwrap();
        let err = verify_log_consistency_between(&old_root, &head, &ip, &vk).unwrap_err();
        assert!(matches!(err, TransparencyLogError::WrongProofType { .. }));
    }

    // -- Replay --

    #[test]
    fn replay_from_entries_rebuilds_same_root() {
        let mut original = fresh_log();
        for i in 0..7u8 {
            original.append_receipt(leaf(i), i as u64).unwrap();
        }
        let snapshot: Vec<TransparencyLogEntry> = original.entries().to_vec();
        let rebuilt = TransparencyLog::replay_from_entries("test-log", 0, snapshot).expect("ok");
        assert_eq!(rebuilt.tree_length(), original.tree_length());
        assert_eq!(
            rebuilt.current_root().unwrap(),
            original.current_root().unwrap()
        );
    }

    #[test]
    fn replay_rejects_non_contiguous_indices() {
        let bad = vec![
            TransparencyLogEntry {
                leaf_index: 0,
                receipt_hash: leaf(0),
                appended_at_ns: 0,
                log_id: "L".to_string(),
            },
            TransparencyLogEntry {
                leaf_index: 5, // gap
                receipt_hash: leaf(1),
                appended_at_ns: 0,
                log_id: "L".to_string(),
            },
        ];
        let err = TransparencyLog::replay_from_entries("L", 0, bad).unwrap_err();
        assert!(matches!(
            err,
            TransparencyLogError::LeafIndexOutOfRange { .. }
        ));
    }

    #[test]
    fn replay_rejects_log_id_mismatch() {
        let bad = vec![TransparencyLogEntry {
            leaf_index: 0,
            receipt_hash: leaf(0),
            appended_at_ns: 0,
            log_id: "OTHER".to_string(),
        }];
        let err = TransparencyLog::replay_from_entries("L", 0, bad).unwrap_err();
        assert!(matches!(err, TransparencyLogError::LogIdMismatch { .. }));
    }

    // -- Error codes are stable / Display formats --

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(TransparencyLogError::Empty.code(), "FE-TLOG-0001");
        assert_eq!(
            TransparencyLogError::LeafIndexOutOfRange {
                index: 0,
                length: 0
            }
            .code(),
            "FE-TLOG-0002"
        );
        assert_eq!(
            TransparencyLogError::Proof {
                detail: "x".to_string()
            }
            .code(),
            "FE-TLOG-0003"
        );
        assert_eq!(
            TransparencyLogError::Signature {
                detail: "x".to_string()
            }
            .code(),
            "FE-TLOG-0004"
        );
        assert_eq!(
            TransparencyLogError::InclusionLengthMismatch {
                proof_length: 0,
                head_length: 0
            }
            .code(),
            "FE-TLOG-0005"
        );
        assert_eq!(
            TransparencyLogError::RootMismatch {
                proof_root: leaf(0),
                head_root: leaf(0)
            }
            .code(),
            "FE-TLOG-0006"
        );
        assert_eq!(
            TransparencyLogError::ReceiptIndexMismatch {
                proof_index: 0,
                receipt_index: 0
            }
            .code(),
            "FE-TLOG-0007"
        );
        assert_eq!(
            TransparencyLogError::WrongProofType {
                expected: ProofType::Inclusion,
                got: ProofType::Consistency
            }
            .code(),
            "FE-TLOG-0008"
        );
        assert_eq!(
            TransparencyLogError::CounterExhausted.code(),
            "FE-TLOG-0009"
        );
        assert_eq!(
            TransparencyLogError::LogIdMismatch {
                expected: "a".to_string(),
                found: "b".to_string()
            }
            .code(),
            "FE-TLOG-0010"
        );
    }

    #[test]
    fn error_display_includes_diagnostic_data() {
        let e = TransparencyLogError::LeafIndexOutOfRange {
            index: 9,
            length: 4,
        };
        assert!(e.to_string().contains("9"));
        assert!(e.to_string().contains("4"));

        let e2 = TransparencyLogError::LogIdMismatch {
            expected: "A".to_string(),
            found: "B".to_string(),
        };
        assert!(e2.to_string().contains("A"));
        assert!(e2.to_string().contains("B"));
    }

    // -- Schema hash is stable across calls --

    #[test]
    fn schema_hashes_are_stable() {
        assert_eq!(SignedLogHead::schema_hash(), head_schema());
        assert_eq!(TransparencyLogEntry::schema_hash(), entry_schema());
        // Different schemas: head vs entry must not collide.
        assert_ne!(head_schema(), entry_schema());
    }

    #[test]
    fn entry_canonical_value_round_trips_through_encode() {
        let entry = TransparencyLogEntry {
            leaf_index: 1,
            receipt_hash: leaf(2),
            appended_at_ns: 3,
            log_id: "L".to_string(),
        };
        let cv = entry.canonical_value();
        // Round-trip through the canonical encoder to confirm we
        // produce a valid CanonicalValue::Map (not a NaN-poisoned
        // float etc.).
        let bytes = deterministic_serde::encode_value(&cv);
        assert!(!bytes.is_empty());
    }
}
