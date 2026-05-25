//! Merkle-batched session signing for the evidence ledger (PERF-ALIEN-1.2).
//!
//! The evidence ledger normally signs one ed25519 signature per entry — one
//! curve operation per entry. [`SessionSigningBatch`] accumulates N entries,
//! builds an RFC 6962 Merkle tree over their canonical hashes, and signs the
//! **root once**. Each entry is then emitted as a [`MerkleSignedEnvelope`]
//! carrying an O(log N) inclusion proof, so it remains independently verifiable
//! against the single signed root with no per-entry curve work.
//!
//! Byte-level shapes are pinned by `docs/PERF_ALIEN1_MERKLE_BATCH_SIGNING_DESIGN.md`
//! (bd-o4cbn.9.1). Three disjoint hash domains are used:
//!
//! | Domain   | Prefix | Hashed structure                                            |
//! |----------|--------|-------------------------------------------------------------|
//! | Leaf     | `0x00` | `0x00 \|\| u32_be(len) \|\| canonical_bytes(entry)`         |
//! | Internal | `0x01` | `0x01 \|\| left_hash \|\| right_hash`                       |
//! | Root sig | `0x02` | `0x02 \|\| schema_id \|\| batch_id \|\| root \|\| u64_be(ts)`|
//!
//! Tree construction is RFC 6962's asymmetric power-of-two split (Laurie,
//! Langley, Kasper, *Certificate Transparency*, RFC 6962, §2.1). It performs
//! **no leaf duplication** (the Bitcoin-style scheme that is vulnerable to
//! CVE-2012-2459) and needs no sentinel padding.
//!
//! ## Canonicalization note
//!
//! The leaf input uses `serde_json::to_vec(entry)`, the same canonicalization
//! `evidence_ledger`'s own per-entry signature path uses
//! (`EvidenceEntry::unsigned_signature_preimage`). It is deterministic because
//! every map field of [`EvidenceEntry`] is a `BTreeMap`. The design doc names
//! `deterministic_serde::encode_value`; we deliberately match the ledger's
//! existing JSON canonicalization instead so a batched and an unbatched
//! signature attest byte-identical preimages for the same entry.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::evidence_ledger::EvidenceEntry;
use crate::hash_tiers::ContentHash;
use crate::signature_preimage::{
    Signature, SignatureError, SigningKey, VerificationKey, sign_preimage, verify_signature,
};

/// Leaf domain-separation byte (RFC 6962 §2.1).
const LEAF_DOMAIN: u8 = 0x00;
/// Internal-node domain-separation byte (RFC 6962 §2.1).
const INTERNAL_DOMAIN: u8 = 0x01;
/// Root-signature domain-separation byte (project extension, design §5).
const ROOT_SIG_DOMAIN: u8 = 0x02;

// ---------------------------------------------------------------------------
// BatchId — 16-byte session/batch identifier
// ---------------------------------------------------------------------------

/// Session/batch identifier, serialized as a fixed 16-byte big-endian value in
/// the root-signature preimage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BatchId(u128);

impl BatchId {
    /// Construct a batch id from a raw `u128`.
    pub fn new(value: u128) -> Self {
        Self(value)
    }

    /// The raw `u128` value.
    pub fn as_u128(self) -> u128 {
        self.0
    }

    /// Fixed-width big-endian encoding used in the signing preimage.
    pub fn to_be_bytes(self) -> [u8; 16] {
        self.0.to_be_bytes()
    }
}

// ---------------------------------------------------------------------------
// Inclusion proof shapes
// ---------------------------------------------------------------------------

/// Which side a sibling hash sits on within an inclusion-proof step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SiblingSide {
    /// Sibling is the left child: `parent = H(0x01 || sibling || acc)`.
    Left,
    /// Sibling is the right child: `parent = H(0x01 || acc || sibling)`.
    Right,
}

/// One step of an audit path: the sibling hash needed to reconstruct the parent
/// at this level, tagged with the side the sibling is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofStep {
    /// Side of the sibling hash relative to the running accumulator.
    pub direction: SiblingSide,
    /// The 32-byte sibling hash.
    pub hash: ContentHash,
}

/// Audit path proving a leaf's membership in a signed root, ordered leaf -> root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Index of the proven leaf within the batch.
    pub leaf_index: u64,
    /// Number of leaves in the batch (pins the proof to one tree shape).
    pub tree_size: u64,
    /// Sibling hashes from leaf to root.
    pub path: Vec<ProofStep>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from batch construction or envelope verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchError {
    /// `finalize` was called with no entries (nothing to attest).
    EmptyBatch,
    /// An entry could not be canonicalized for hashing.
    CanonicalizationFailed {
        /// Underlying serialization error description.
        reason: String,
    },
    /// Signing the Merkle root failed.
    Signing(SignatureError),
    /// The proof's `leaf_index` is not within `tree_size`.
    LeafIndexOutOfRange {
        /// The offending leaf index.
        index: u64,
        /// The declared tree size.
        tree_size: u64,
    },
    /// The inclusion proof did not reconstruct the signed root.
    RootMismatch,
    /// The root signature did not verify under the envelope's key.
    SignatureInvalid(SignatureError),
    /// The envelope's producer key differed from the expected key.
    KeyMismatch,
}

impl fmt::Display for BatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BatchError::EmptyBatch => write!(f, "cannot finalize an empty signing batch"),
            BatchError::CanonicalizationFailed { reason } => {
                write!(f, "entry canonicalization failed: {reason}")
            }
            BatchError::Signing(e) => write!(f, "merkle root signing failed: {e}"),
            BatchError::LeafIndexOutOfRange { index, tree_size } => {
                write!(f, "leaf index {index} out of range for tree size {tree_size}")
            }
            BatchError::RootMismatch => {
                write!(f, "inclusion proof did not reconstruct the signed merkle root")
            }
            BatchError::SignatureInvalid(e) => write!(f, "root signature verification failed: {e}"),
            BatchError::KeyMismatch => write!(f, "envelope producer key did not match expected key"),
        }
    }
}

impl std::error::Error for BatchError {}

// ---------------------------------------------------------------------------
// Hashing primitives (design §1-§3, §5)
// ---------------------------------------------------------------------------

/// Canonical bytes of an entry, matching `evidence_ledger`'s JSON preimage.
fn canonical_entry_bytes(entry: &EvidenceEntry) -> Result<Vec<u8>, BatchError> {
    serde_json::to_vec(entry).map_err(|e| BatchError::CanonicalizationFailed {
        reason: e.to_string(),
    })
}

/// `leaf_hash = SHA256(0x00 || u32_be(len) || canonical)` (design §1).
fn leaf_hash_from_canonical(canonical: &[u8]) -> ContentHash {
    let len = u32::try_from(canonical.len()).unwrap_or(u32::MAX);
    let mut buf = Vec::with_capacity(1 + 4 + canonical.len());
    buf.push(LEAF_DOMAIN);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(canonical);
    ContentHash::compute(&buf)
}

/// `internal_hash = SHA256(0x01 || left || right)` (design §2).
fn internal_hash(left: &ContentHash, right: &ContentHash) -> ContentHash {
    let mut buf = [0u8; 1 + 32 + 32];
    buf[0] = INTERNAL_DOMAIN;
    buf[1..33].copy_from_slice(left.as_bytes());
    buf[33..].copy_from_slice(right.as_bytes());
    ContentHash::compute(&buf)
}

/// Largest power of two strictly less than `n` (requires `n >= 2`).
fn split_point(n: usize) -> usize {
    debug_assert!(n >= 2, "split_point requires n >= 2");
    let mut k = 1usize;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// RFC 6962 Merkle Tree Hash over the ordered leaf hashes (design §3).
fn merkle_root(leaves: &[ContentHash]) -> ContentHash {
    match leaves.len() {
        0 => ContentHash::compute(&[]),
        1 => leaves[0],
        n => {
            let k = split_point(n);
            internal_hash(&merkle_root(&leaves[..k]), &merkle_root(&leaves[k..]))
        }
    }
}

/// RFC 6962 audit path for `index` within `leaves`, ordered leaf -> root.
fn inclusion_path(index: usize, leaves: &[ContentHash]) -> Vec<ProofStep> {
    let n = leaves.len();
    if n <= 1 {
        return Vec::new();
    }
    let k = split_point(n);
    if index < k {
        // Leaf is in the left subtree; its sibling is the right subtree root.
        let mut path = inclusion_path(index, &leaves[..k]);
        path.push(ProofStep {
            direction: SiblingSide::Right,
            hash: merkle_root(&leaves[k..]),
        });
        path
    } else {
        // Leaf is in the right subtree; its sibling is the left subtree root.
        let mut path = inclusion_path(index - k, &leaves[k..]);
        path.push(ProofStep {
            direction: SiblingSide::Left,
            hash: merkle_root(&leaves[..k]),
        });
        path
    }
}

/// `sig_preimage = SHA256(0x02 || schema_id || batch_id || root || u64_be(ts))` (design §5).
fn root_sig_preimage(
    schema_id: &ContentHash,
    batch_id: BatchId,
    root: &ContentHash,
    timestamp_ns: u64,
) -> ContentHash {
    let mut buf = Vec::with_capacity(1 + 32 + 16 + 32 + 8);
    buf.push(ROOT_SIG_DOMAIN);
    buf.extend_from_slice(schema_id.as_bytes());
    buf.extend_from_slice(&batch_id.to_be_bytes());
    buf.extend_from_slice(root.as_bytes());
    buf.extend_from_slice(&timestamp_ns.to_be_bytes());
    ContentHash::compute(&buf)
}

// ---------------------------------------------------------------------------
// SessionSigningBatch
// ---------------------------------------------------------------------------

/// Accumulates evidence entries and signs their Merkle root exactly once.
#[derive(Debug, Clone)]
pub struct SessionSigningBatch {
    entries: Vec<EvidenceEntry>,
    batch_id: BatchId,
    schema_id: ContentHash,
    timestamp_ns: u64,
    producer_id: String,
    producer_key: SigningKey,
}

impl SessionSigningBatch {
    /// Open a new batch.
    ///
    /// `schema_id` is the 32-byte schema hash the batch's entries conform to;
    /// `timestamp_ns` is the session signing time bound into the root signature.
    pub fn new(
        producer_id: impl Into<String>,
        producer_key: SigningKey,
        batch_id: BatchId,
        schema_id: ContentHash,
        timestamp_ns: u64,
    ) -> Self {
        Self {
            entries: Vec::new(),
            batch_id,
            schema_id,
            timestamp_ns,
            producer_id: producer_id.into(),
            producer_key,
        }
    }

    /// Append an evidence entry to the batch.
    pub fn add_entry(&mut self, entry: EvidenceEntry) {
        self.entries.push(entry);
    }

    /// Number of entries accumulated so far.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the batch has no entries yet.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Build the Merkle tree, sign the root once, and emit one envelope per
    /// entry carrying its inclusion proof and the shared root signature.
    pub fn finalize(self) -> Result<Vec<MerkleSignedEnvelope>, BatchError> {
        if self.entries.is_empty() {
            return Err(BatchError::EmptyBatch);
        }

        let mut leaves = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            leaves.push(leaf_hash_from_canonical(&canonical_entry_bytes(entry)?));
        }

        let root = merkle_root(&leaves);
        let preimage = root_sig_preimage(&self.schema_id, self.batch_id, &root, self.timestamp_ns);
        let signature =
            sign_preimage(&self.producer_key, preimage.as_bytes()).map_err(BatchError::Signing)?;
        let verification_key = self.producer_key.verification_key();
        let tree_size = leaves.len() as u64;

        let mut envelopes = Vec::with_capacity(self.entries.len());
        for (index, entry) in self.entries.into_iter().enumerate() {
            envelopes.push(MerkleSignedEnvelope {
                entry,
                producer_id: self.producer_id.clone(),
                verification_key: verification_key.clone(),
                schema_id: self.schema_id,
                batch_id: self.batch_id,
                timestamp_ns: self.timestamp_ns,
                merkle_root: root,
                root_signature: signature.clone(),
                inclusion_proof: InclusionProof {
                    leaf_index: index as u64,
                    tree_size,
                    path: inclusion_path(index, &leaves),
                },
            });
        }
        Ok(envelopes)
    }
}

// ---------------------------------------------------------------------------
// MerkleSignedEnvelope
// ---------------------------------------------------------------------------

/// A single evidence entry plus the inclusion proof and shared root signature
/// that make it independently verifiable against the batch's signed root.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MerkleSignedEnvelope {
    /// The attested evidence entry.
    pub entry: EvidenceEntry,
    /// Registered producer identity.
    pub producer_id: String,
    /// Public verification key for the producer.
    pub verification_key: VerificationKey,
    /// Schema hash bound into the root signature.
    pub schema_id: ContentHash,
    /// Batch identifier bound into the root signature.
    pub batch_id: BatchId,
    /// Session signing time (ns) bound into the root signature.
    pub timestamp_ns: u64,
    /// The signed RFC 6962 root over the whole batch.
    pub merkle_root: ContentHash,
    /// The single ed25519 signature over the root preimage, shared by the batch.
    pub root_signature: Signature,
    /// This entry's audit path to the root.
    pub inclusion_proof: InclusionProof,
}

impl MerkleSignedEnvelope {
    /// Verify this envelope: re-derive the leaf, walk the inclusion proof to a
    /// root, check it equals the signed root, then verify the single root
    /// signature under the envelope's producer key. No per-entry curve work.
    pub fn verify(&self) -> Result<(), BatchError> {
        if self.inclusion_proof.leaf_index >= self.inclusion_proof.tree_size {
            return Err(BatchError::LeafIndexOutOfRange {
                index: self.inclusion_proof.leaf_index,
                tree_size: self.inclusion_proof.tree_size,
            });
        }

        let mut acc = leaf_hash_from_canonical(&canonical_entry_bytes(&self.entry)?);
        for step in &self.inclusion_proof.path {
            acc = match step.direction {
                SiblingSide::Left => internal_hash(&step.hash, &acc),
                SiblingSide::Right => internal_hash(&acc, &step.hash),
            };
        }
        if acc != self.merkle_root {
            return Err(BatchError::RootMismatch);
        }

        let preimage = root_sig_preimage(
            &self.schema_id,
            self.batch_id,
            &self.merkle_root,
            self.timestamp_ns,
        );
        verify_signature(&self.verification_key, preimage.as_bytes(), &self.root_signature)
            .map_err(BatchError::SignatureInvalid)
    }

    /// As [`verify`](Self::verify), but also pin the producer key to an expected
    /// value (defends against a swapped-key envelope carrying a valid self-signature).
    pub fn verify_with_key(&self, expected: &VerificationKey) -> Result<(), BatchError> {
        if &self.verification_key != expected {
            return Err(BatchError::KeyMismatch);
        }
        self.verify()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence_ledger::{ChosenAction, DecisionType, EvidenceEntryBuilder};
    use crate::security_epoch::SecurityEpoch;

    fn test_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes([seed; 32]).expect("non-zero signing key")
    }

    fn entry(n: u64) -> EvidenceEntry {
        EvidenceEntryBuilder::new(
            format!("trace-{n}"),
            format!("dec-{n}"),
            "policy-test",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .timestamp_ns(1_000 + n)
        .chosen(ChosenAction {
            action_name: format!("act-{n}"),
            expected_loss_millionths: n as i64,
            rationale: "test".to_string(),
        })
        .build()
        .expect("entry builds")
    }

    fn batch_of(count: u64) -> SessionSigningBatch {
        let mut b = SessionSigningBatch::new(
            "producer-1",
            test_key(0x11),
            BatchId::new(42),
            ContentHash::compute(b"test-schema"),
            1_700_000_000,
        );
        for i in 0..count {
            b.add_entry(entry(i));
        }
        b
    }

    #[test]
    fn split_point_matches_rfc6962() {
        assert_eq!(split_point(2), 1);
        assert_eq!(split_point(3), 2);
        assert_eq!(split_point(4), 2);
        assert_eq!(split_point(5), 4);
        assert_eq!(split_point(7), 4);
        assert_eq!(split_point(8), 4);
        assert_eq!(split_point(9), 8);
    }

    #[test]
    fn empty_tree_root_is_hash_of_empty_string() {
        assert_eq!(merkle_root(&[]), ContentHash::compute(&[]));
    }

    #[test]
    fn single_leaf_root_is_the_leaf_hash() {
        let leaf = leaf_hash_from_canonical(b"abc");
        assert_eq!(merkle_root(&[leaf]), leaf);
    }

    #[test]
    fn two_leaf_root_matches_manual_internal_hash() {
        let a = leaf_hash_from_canonical(b"a");
        let b = leaf_hash_from_canonical(b"b");
        assert_eq!(merkle_root(&[a, b]), internal_hash(&a, &b));
    }

    #[test]
    fn three_leaf_root_matches_rfc6962_split() {
        let a = leaf_hash_from_canonical(b"a");
        let b = leaf_hash_from_canonical(b"b");
        let c = leaf_hash_from_canonical(b"c");
        // k = 2: H(H(a,b), c-as-singleton-root=c)
        let expected = internal_hash(&internal_hash(&a, &b), &c);
        assert_eq!(merkle_root(&[a, b, c]), expected);
    }

    #[test]
    fn leaf_and_internal_domains_are_separated() {
        // A leaf preimage and an internal preimage of the same 32-byte payloads
        // must not collide because of the 0x00 / 0x01 prefix bytes.
        let h = ContentHash::compute(b"x");
        let as_leaf = leaf_hash_from_canonical(h.as_bytes());
        let as_internal = internal_hash(&h, &h);
        assert_ne!(as_leaf, as_internal);
    }

    #[test]
    fn finalize_empty_batch_is_rejected() {
        let b = batch_of(0);
        assert_eq!(b.finalize(), Err(BatchError::EmptyBatch));
    }

    #[test]
    fn single_entry_envelope_verifies() {
        let envs = batch_of(1).finalize().expect("finalize");
        assert_eq!(envs.len(), 1);
        assert!(envs[0].inclusion_proof.path.is_empty());
        assert_eq!(envs[0].inclusion_proof.tree_size, 1);
        envs[0].verify().expect("verify ok");
    }

    #[test]
    fn all_envelopes_verify_for_various_sizes() {
        for count in [1u64, 2, 3, 4, 5, 6, 7, 8, 13] {
            let envs = batch_of(count).finalize().expect("finalize");
            assert_eq!(envs.len() as u64, count);
            for (i, env) in envs.iter().enumerate() {
                assert_eq!(env.inclusion_proof.leaf_index, i as u64);
                assert_eq!(env.inclusion_proof.tree_size, count);
                env.verify()
                    .unwrap_or_else(|e| panic!("count={count} index={i} should verify: {e}"));
            }
        }
    }

    #[test]
    fn all_envelopes_share_one_root_and_signature() {
        let envs = batch_of(6).finalize().expect("finalize");
        let root = envs[0].merkle_root;
        let sig = envs[0].root_signature.clone();
        for env in &envs {
            assert_eq!(env.merkle_root, root);
            assert_eq!(env.root_signature, sig);
        }
    }

    #[test]
    fn proof_path_length_is_logarithmic() {
        let envs = batch_of(8).finalize().expect("finalize");
        // Perfect binary tree of 8 leaves => every audit path has length 3.
        for env in &envs {
            assert_eq!(env.inclusion_proof.path.len(), 3);
        }
    }

    #[test]
    fn tampered_entry_fails_root_check() {
        let mut envs = batch_of(5).finalize().expect("finalize");
        envs[2].entry.policy_id.push_str("-tampered");
        assert_eq!(envs[2].verify(), Err(BatchError::RootMismatch));
    }

    #[test]
    fn tampered_proof_step_fails() {
        let mut envs = batch_of(5).finalize().expect("finalize");
        let step = &mut envs[1].inclusion_proof.path[0];
        step.hash = ContentHash::compute(b"not-the-real-sibling");
        assert_eq!(envs[1].verify(), Err(BatchError::RootMismatch));
    }

    #[test]
    fn swapped_proof_direction_fails() {
        let mut envs = batch_of(4).finalize().expect("finalize");
        let step = &mut envs[0].inclusion_proof.path[0];
        step.direction = match step.direction {
            SiblingSide::Left => SiblingSide::Right,
            SiblingSide::Right => SiblingSide::Left,
        };
        assert_eq!(envs[0].verify(), Err(BatchError::RootMismatch));
    }

    #[test]
    fn cross_entry_proof_does_not_verify() {
        let envs = batch_of(4).finalize().expect("finalize");
        // Attach entry 0 to entry 1's proof: the leaf no longer matches the path.
        let mut forged = envs[1].clone();
        forged.entry = envs[0].entry.clone();
        assert_eq!(forged.verify(), Err(BatchError::RootMismatch));
    }

    #[test]
    fn wrong_key_signature_is_rejected() {
        let mut envs = batch_of(3).finalize().expect("finalize");
        // Replace the stored key with a different valid key: the shared root
        // signature was made by 0x11, so verification under 0x22 must fail.
        envs[0].verification_key = test_key(0x22).verification_key();
        match envs[0].verify() {
            Err(BatchError::SignatureInvalid(_)) => {}
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn verify_with_key_pins_producer() {
        let envs = batch_of(2).finalize().expect("finalize");
        let right = test_key(0x11).verification_key();
        let wrong = test_key(0x33).verification_key();
        envs[0].verify_with_key(&right).expect("matching key verifies");
        assert_eq!(envs[0].verify_with_key(&wrong), Err(BatchError::KeyMismatch));
    }

    #[test]
    fn out_of_range_leaf_index_is_rejected() {
        let mut envs = batch_of(2).finalize().expect("finalize");
        envs[0].inclusion_proof.leaf_index = 9;
        assert_eq!(
            envs[0].verify(),
            Err(BatchError::LeafIndexOutOfRange {
                index: 9,
                tree_size: 2
            })
        );
    }

    #[test]
    fn root_is_deterministic_across_builds() {
        let r1 = batch_of(7).finalize().expect("finalize")[0].merkle_root;
        let r2 = batch_of(7).finalize().expect("finalize")[0].merkle_root;
        assert_eq!(r1, r2);
    }

    #[test]
    fn distinct_entry_sets_produce_distinct_roots() {
        let r_small = batch_of(3).finalize().expect("finalize")[0].merkle_root;
        let r_big = batch_of(4).finalize().expect("finalize")[0].merkle_root;
        assert_ne!(r_small, r_big);
    }

    #[test]
    fn batch_id_round_trips_through_be_bytes() {
        let id = BatchId::new(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10);
        assert_eq!(u128::from_be_bytes(id.to_be_bytes()), id.as_u128());
    }

    #[test]
    fn envelope_serde_round_trips_and_still_verifies() {
        let envs = batch_of(5).finalize().expect("finalize");
        let json = serde_json::to_string(&envs[3]).expect("serialize envelope");
        let back: MerkleSignedEnvelope = serde_json::from_str(&json).expect("deserialize envelope");
        assert_eq!(back, envs[3]);
        back.verify().expect("deserialized envelope verifies");
    }

    #[test]
    fn batch_len_and_is_empty_track_entries() {
        let mut b = SessionSigningBatch::new(
            "p",
            test_key(0x11),
            BatchId::new(1),
            ContentHash::compute(b"s"),
            0,
        );
        assert!(b.is_empty());
        b.add_entry(entry(0));
        b.add_entry(entry(1));
        assert_eq!(b.len(), 2);
        assert!(!b.is_empty());
    }

    #[test]
    fn changing_schema_id_changes_signature_domain() {
        // Same entries + batch_id + ts but different schema_id => different signed
        // preimage, so an envelope's signature must not verify if schema_id is altered.
        let mut envs = batch_of(2).finalize().expect("finalize");
        envs[0].schema_id = ContentHash::compute(b"a-different-schema");
        match envs[0].verify() {
            Err(BatchError::SignatureInvalid(_)) => {}
            other => panic!("expected SignatureInvalid after schema_id change, got {other:?}"),
        }
    }
}
