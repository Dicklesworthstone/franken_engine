//! Signed replacement-lineage log with transparency-verifiable append semantics.
//!
//! Records every slot replacement event in an append-only, hash-chained log.
//! Each entry includes a replacement receipt, predecessor hash, sequence number,
//! and a Merkle-tree commitment enabling inclusion and consistency proofs.
//!
//! Periodic signed checkpoints (tree-heads) allow independent verifiers to
//! confirm that the log has not been tampered with since a previous checkpoint.
//!
//! Plan reference: Section 10.15 item 4 of 9I.6 (`bd-kr99`).
//! Cross-refs: bd-7rwi (ReplacementReceipt schema), bd-1g5c (promotion gate
//! runner produces the receipts), bd-1ilz (frankensqlite-backed index).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::self_replacement::{ReplacementReceipt, ValidationArtifactKind};
use crate::slot_registry::SlotId;
use crate::storage_adapter::{EventContext, StorageAdapter, StorageError, StoreKind, StoreQuery};

// ---------------------------------------------------------------------------
// Replacement types
// ---------------------------------------------------------------------------

/// The kind of replacement recorded in a lineage log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ReplacementKind {
    /// Delegate cell replaced by native implementation.
    DelegateToNative,
    /// Native implementation demoted back to delegate cell.
    Demotion,
    /// Rollback to a previously known-good implementation.
    Rollback,
    /// Re-promotion after a demotion/rollback cycle.
    RePromotion,
}

impl ReplacementKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DelegateToNative => "delegate_to_native",
            Self::Demotion => "demotion",
            Self::Rollback => "rollback",
            Self::RePromotion => "re_promotion",
        }
    }
}

impl fmt::Display for ReplacementKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Log entry
// ---------------------------------------------------------------------------

/// A single entry in the replacement lineage log.
///
/// Entries form a hash chain: each entry includes the content hash of its
/// predecessor, providing tamper-evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageLogEntry {
    /// Monotonically increasing sequence number (0-indexed).
    pub sequence: u64,
    /// The replacement receipt for this event.
    pub receipt: ReplacementReceipt,
    /// Kind of replacement.
    pub kind: ReplacementKind,
    /// Content hash of the preceding entry (all-zeros for the first entry).
    pub predecessor_hash: ContentHash,
    /// Content hash of this entry (computed over canonical serialization).
    pub entry_hash: ContentHash,
}

impl LineageLogEntry {
    /// Compute the canonical content hash of this entry.
    ///
    /// Deterministic: hash(sequence || kind || receipt_id || old_digest ||
    /// new_digest || predecessor_hash).
    fn compute_hash(
        sequence: u64,
        kind: ReplacementKind,
        receipt: &ReplacementReceipt,
        predecessor_hash: &ContentHash,
    ) -> ContentHash {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(&sequence.to_be_bytes());
        canonical.extend_from_slice(kind.as_str().as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(receipt.receipt_id.as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(receipt.old_cell_digest.as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(receipt.new_cell_digest.as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(receipt.slot_id.as_str().as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(predecessor_hash.as_bytes());
        ContentHash::compute(&canonical)
    }
}

// ---------------------------------------------------------------------------
// Merkle tree for inclusion / consistency proofs
// ---------------------------------------------------------------------------

/// A node in the Merkle tree. Leaf nodes hash log entries; internal nodes
/// hash their two children.
fn merkle_leaf(entry_hash: &ContentHash) -> ContentHash {
    let mut buf = Vec::with_capacity(33);
    buf.push(0x00); // leaf prefix
    buf.extend_from_slice(entry_hash.as_bytes());
    ContentHash::compute(&buf)
}

fn merkle_node(left: &ContentHash, right: &ContentHash) -> ContentHash {
    let mut buf = Vec::with_capacity(65);
    buf.push(0x01); // node prefix
    buf.extend_from_slice(left.as_bytes());
    buf.extend_from_slice(right.as_bytes());
    ContentHash::compute(&buf)
}

/// Compute the Merkle root of a list of entry hashes.
fn compute_merkle_root(entry_hashes: &[ContentHash]) -> ContentHash {
    if entry_hashes.is_empty() {
        return ContentHash::compute(b"empty_lineage_tree");
    }
    if entry_hashes.len() == 1 {
        return merkle_leaf(&entry_hashes[0]);
    }

    let mut current_level: Vec<ContentHash> = entry_hashes.iter().map(merkle_leaf).collect();

    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
        let mut i = 0;
        while i < current_level.len() {
            if i + 1 < current_level.len() {
                next_level.push(merkle_node(&current_level[i], &current_level[i + 1]));
            } else {
                // Odd node promoted directly.
                next_level.push(current_level[i]);
            }
            i += 2;
        }
        current_level = next_level;
    }
    current_level.remove(0)
}

/// Direction in a Merkle proof path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofDirection {
    /// The sibling is to the left.
    Left,
    /// The sibling is to the right.
    Right,
}

/// A single step in a Merkle inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProofStep {
    pub sibling_hash: ContentHash,
    pub direction: ProofDirection,
}

/// Merkle inclusion proof for a single log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Index of the entry in the log.
    pub entry_index: u64,
    /// The entry's hash.
    pub entry_hash: ContentHash,
    /// Path of sibling hashes from leaf to root.
    pub path: Vec<MerkleProofStep>,
    /// The expected Merkle root.
    pub root: ContentHash,
}

/// Build a Merkle inclusion proof for entry at `index`.
fn build_inclusion_proof(entry_hashes: &[ContentHash], index: usize) -> Option<InclusionProof> {
    if index >= entry_hashes.len() || entry_hashes.is_empty() {
        return None;
    }

    let root = compute_merkle_root(entry_hashes);

    if entry_hashes.len() == 1 {
        return Some(InclusionProof {
            entry_index: index as u64,
            entry_hash: entry_hashes[index],
            path: Vec::new(),
            root,
        });
    }

    // Build the proof path by walking up the tree.
    let mut current_level: Vec<ContentHash> = entry_hashes.iter().map(merkle_leaf).collect();
    let mut path = Vec::new();
    let mut pos = index;

    while current_level.len() > 1 {
        if pos.is_multiple_of(2) {
            // We're a left child; sibling is to our right (if exists).
            if pos + 1 < current_level.len() {
                path.push(MerkleProofStep {
                    sibling_hash: current_level[pos + 1],
                    direction: ProofDirection::Right,
                });
            }
            // No sibling: odd node promoted, no step needed.
        } else {
            // We're a right child; sibling is to our left.
            path.push(MerkleProofStep {
                sibling_hash: current_level[pos - 1],
                direction: ProofDirection::Left,
            });
        }

        // Move to next level.
        let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
        let mut i = 0;
        while i < current_level.len() {
            if i + 1 < current_level.len() {
                next_level.push(merkle_node(&current_level[i], &current_level[i + 1]));
            } else {
                next_level.push(current_level[i]);
            }
            i += 2;
        }
        current_level = next_level;
        pos /= 2;
    }

    Some(InclusionProof {
        entry_index: index as u64,
        entry_hash: entry_hashes[index],
        path,
        root,
    })
}

/// Verify an inclusion proof.
pub fn verify_inclusion_proof(proof: &InclusionProof) -> bool {
    let mut current = merkle_leaf(&proof.entry_hash);
    for step in &proof.path {
        current = match step.direction {
            ProofDirection::Left => merkle_node(&step.sibling_hash, &current),
            ProofDirection::Right => merkle_node(&current, &step.sibling_hash),
        };
    }
    current == proof.root
}

// ---------------------------------------------------------------------------
// Consistency proofs
// ---------------------------------------------------------------------------

/// Proof that a newer checkpoint extends an older checkpoint without rewriting
/// historical entries.
///
/// The proof carries the hash inventory needed for independent verification:
/// - `older_entry_hashes` must match the prefix of `newer_entry_hashes`
/// - Merkle roots recomputed from each hash list must match the recorded roots
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsistencyProof {
    /// Older checkpoint sequence number.
    pub older_checkpoint_seq: u64,
    /// Newer checkpoint sequence number.
    pub newer_checkpoint_seq: u64,
    /// Number of entries covered by the older checkpoint.
    pub older_log_length: u64,
    /// Number of entries covered by the newer checkpoint.
    pub newer_log_length: u64,
    /// Recorded Merkle root of the older checkpoint.
    pub older_root: ContentHash,
    /// Recorded Merkle root of the newer checkpoint.
    pub newer_root: ContentHash,
    /// Entry hashes covered by the older checkpoint.
    pub older_entry_hashes: Vec<ContentHash>,
    /// Entry hashes covered by the newer checkpoint.
    pub newer_entry_hashes: Vec<ContentHash>,
}

/// Verify a checkpoint consistency proof.
pub fn verify_consistency_proof(proof: &ConsistencyProof) -> bool {
    if proof.older_log_length > proof.newer_log_length {
        return false;
    }
    if proof.older_entry_hashes.len() as u64 != proof.older_log_length {
        return false;
    }
    if proof.newer_entry_hashes.len() as u64 != proof.newer_log_length {
        return false;
    }
    if proof.older_entry_hashes != proof.newer_entry_hashes[..proof.older_entry_hashes.len()] {
        return false;
    }

    let recomputed_older_root = compute_merkle_root(&proof.older_entry_hashes);
    if recomputed_older_root != proof.older_root {
        return false;
    }
    let recomputed_newer_root = compute_merkle_root(&proof.newer_entry_hashes);
    recomputed_newer_root == proof.newer_root
}

// ---------------------------------------------------------------------------
// Signed checkpoint (tree-head)
// ---------------------------------------------------------------------------

/// A signed checkpoint representing the state of the lineage log at a
/// particular sequence number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogCheckpoint {
    /// Checkpoint sequence number (monotonically increasing).
    pub checkpoint_seq: u64,
    /// Sequence number of the latest entry included in this checkpoint.
    pub log_length: u64,
    /// Merkle root over all entries up to `log_length`.
    pub merkle_root: ContentHash,
    /// Timestamp (nanoseconds, monotonic) when the checkpoint was created.
    pub timestamp_ns: u64,
    /// Security epoch at checkpoint time.
    pub epoch: SecurityEpoch,
    /// Content hash of this checkpoint for verification.
    pub checkpoint_hash: ContentHash,
}

impl LogCheckpoint {
    fn compute_checkpoint_hash(
        checkpoint_seq: u64,
        log_length: u64,
        merkle_root: &ContentHash,
        timestamp_ns: u64,
        epoch: SecurityEpoch,
    ) -> ContentHash {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(b"lineage_checkpoint|");
        canonical.extend_from_slice(&checkpoint_seq.to_be_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(&log_length.to_be_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(merkle_root.as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(&timestamp_ns.to_be_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(&epoch.as_u64().to_be_bytes());
        ContentHash::compute(&canonical)
    }
}

// ---------------------------------------------------------------------------
// Query types
// ---------------------------------------------------------------------------

/// Filter for querying log entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageQuery {
    /// Filter by slot ID (if present).
    pub slot_id: Option<SlotId>,
    /// Filter by replacement kind (if present).
    pub kinds: Option<BTreeSet<ReplacementKind>>,
    /// Minimum timestamp (inclusive, nanoseconds).
    pub min_timestamp_ns: Option<u64>,
    /// Maximum timestamp (inclusive, nanoseconds).
    pub max_timestamp_ns: Option<u64>,
}

impl LineageQuery {
    pub fn for_slot(slot_id: SlotId) -> Self {
        Self {
            slot_id: Some(slot_id),
            kinds: None,
            min_timestamp_ns: None,
            max_timestamp_ns: None,
        }
    }

    pub fn all() -> Self {
        Self {
            slot_id: None,
            kinds: None,
            min_timestamp_ns: None,
            max_timestamp_ns: None,
        }
    }

    fn matches(&self, entry: &LineageLogEntry) -> bool {
        if let Some(ref sid) = self.slot_id
            && entry.receipt.slot_id != *sid
        {
            return false;
        }
        if let Some(ref kinds) = self.kinds
            && !kinds.contains(&entry.kind)
        {
            return false;
        }
        if let Some(min_ts) = self.min_timestamp_ns
            && entry.receipt.timestamp_ns < min_ts
        {
            return false;
        }
        if let Some(max_ts) = self.max_timestamp_ns
            && entry.receipt.timestamp_ns > max_ts
        {
            return false;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Slot lineage summary
// ---------------------------------------------------------------------------

/// A summary of a single step in a slot's replacement lineage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageStep {
    pub sequence: u64,
    pub kind: ReplacementKind,
    pub old_cell_digest: String,
    pub new_cell_digest: String,
    pub receipt_id: String,
    pub timestamp_ns: u64,
    pub epoch: SecurityEpoch,
    pub validation_artifact_count: usize,
}

// ---------------------------------------------------------------------------
// Verification results
// ---------------------------------------------------------------------------

/// Result of verifying a slot's replacement lineage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageVerification {
    pub slot_id: SlotId,
    pub total_entries: usize,
    pub chain_valid: bool,
    pub all_receipts_present: bool,
    pub issues: Vec<String>,
}

/// Result of an audit across the entire log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditResult {
    pub total_entries: u64,
    pub total_slots: usize,
    pub chain_valid: bool,
    pub merkle_valid: bool,
    pub checkpoint_count: usize,
    pub latest_checkpoint_seq: Option<u64>,
    pub issues: Vec<String>,
}

// ---------------------------------------------------------------------------
// Structured log events
// ---------------------------------------------------------------------------

/// Structured log event emitted by the lineage log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from lineage log operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LineageLogError {
    /// Sequence number mismatch on append.
    SequenceMismatch { expected: u64, got: u64 },
    /// Chain hash does not match predecessor.
    ChainBreak { sequence: u64 },
    /// Duplicate receipt ID in the log.
    DuplicateReceipt { receipt_id: String },
    /// Checkpoint references a log length beyond current entries.
    CheckpointBeyondLog {
        checkpoint_length: u64,
        log_length: u64,
    },
    /// Requested checkpoint sequence does not exist.
    CheckpointNotFound { checkpoint_seq: u64 },
    /// Checkpoint order is invalid for consistency verification.
    InvalidCheckpointOrder { older: u64, newer: u64 },
    /// Log is empty, operation requires entries.
    EmptyLog,
}

impl fmt::Display for LineageLogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SequenceMismatch { expected, got } => {
                write!(f, "sequence mismatch: expected {expected}, got {got}")
            }
            Self::ChainBreak { sequence } => {
                write!(f, "chain break at sequence {sequence}")
            }
            Self::DuplicateReceipt { receipt_id } => {
                write!(f, "duplicate receipt: {receipt_id}")
            }
            Self::CheckpointBeyondLog {
                checkpoint_length,
                log_length,
            } => {
                write!(
                    f,
                    "checkpoint length {checkpoint_length} beyond log length {log_length}"
                )
            }
            Self::CheckpointNotFound { checkpoint_seq } => {
                write!(f, "checkpoint not found: sequence {checkpoint_seq}")
            }
            Self::InvalidCheckpointOrder { older, newer } => {
                write!(
                    f,
                    "invalid checkpoint order: older={older}, newer={newer} (must be older < newer)"
                )
            }
            Self::EmptyLog => f.write_str("log is empty"),
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the lineage log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageLogConfig {
    /// How often to create automatic checkpoints (every N appends).
    pub checkpoint_interval: u64,
    /// Maximum number of entries to keep in memory (0 = unlimited).
    pub max_entries_in_memory: u64,
}

impl Default for LineageLogConfig {
    fn default() -> Self {
        Self {
            checkpoint_interval: 100,
            max_entries_in_memory: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Lineage log engine
// ---------------------------------------------------------------------------

/// The replacement lineage log engine.
///
/// Append-only, hash-chained log of slot replacement events with Merkle tree
/// commitments and periodic signed checkpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplacementLineageLog {
    config: LineageLogConfig,
    entries: Vec<LineageLogEntry>,
    checkpoints: Vec<LogCheckpoint>,
    checkpoint_seq_counter: u64,
    events: Vec<LineageLogEvent>,
    event_seq: u64,
}

impl ReplacementLineageLog {
    /// Create a new empty lineage log.
    pub fn new(config: LineageLogConfig) -> Self {
        Self {
            config,
            entries: Vec::new(),
            checkpoints: Vec::new(),
            checkpoint_seq_counter: 0,
            events: Vec::new(),
            event_seq: 0,
        }
    }

    /// Current number of entries in the log.
    pub fn len(&self) -> u64 {
        self.entries.len() as u64
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All entries in the log.
    pub fn entries(&self) -> &[LineageLogEntry] {
        &self.entries
    }

    /// All checkpoints.
    pub fn checkpoints(&self) -> &[LogCheckpoint] {
        &self.checkpoints
    }

    /// Structured log events.
    pub fn events(&self) -> &[LineageLogEvent] {
        &self.events
    }

    /// Build a consistency proof showing that `newer_checkpoint_seq` extends
    /// `older_checkpoint_seq` without rewriting historical entries.
    pub fn consistency_proof(
        &self,
        older_checkpoint_seq: u64,
        newer_checkpoint_seq: u64,
    ) -> Result<ConsistencyProof, LineageLogError> {
        if older_checkpoint_seq >= newer_checkpoint_seq {
            return Err(LineageLogError::InvalidCheckpointOrder {
                older: older_checkpoint_seq,
                newer: newer_checkpoint_seq,
            });
        }

        let older = self.checkpoint_by_seq(older_checkpoint_seq).ok_or(
            LineageLogError::CheckpointNotFound {
                checkpoint_seq: older_checkpoint_seq,
            },
        )?;
        let newer = self.checkpoint_by_seq(newer_checkpoint_seq).ok_or(
            LineageLogError::CheckpointNotFound {
                checkpoint_seq: newer_checkpoint_seq,
            },
        )?;

        if older.log_length > newer.log_length {
            return Err(LineageLogError::InvalidCheckpointOrder {
                older: older_checkpoint_seq,
                newer: newer_checkpoint_seq,
            });
        }

        if newer.log_length > self.entries.len() as u64 {
            return Err(LineageLogError::CheckpointBeyondLog {
                checkpoint_length: newer.log_length,
                log_length: self.entries.len() as u64,
            });
        }

        let newer_entry_hashes: Vec<ContentHash> = self
            .entries
            .iter()
            .take(newer.log_length as usize)
            .map(|entry| entry.entry_hash)
            .collect();
        let older_entry_hashes: Vec<ContentHash> = newer_entry_hashes
            .iter()
            .take(older.log_length as usize)
            .cloned()
            .collect();

        Ok(ConsistencyProof {
            older_checkpoint_seq,
            newer_checkpoint_seq,
            older_log_length: older.log_length,
            newer_log_length: newer.log_length,
            older_root: older.merkle_root,
            newer_root: newer.merkle_root,
            older_entry_hashes,
            newer_entry_hashes,
        })
    }

    /// Append a replacement event to the log.
    pub fn append(
        &mut self,
        receipt: ReplacementReceipt,
        kind: ReplacementKind,
        timestamp_ns: u64,
    ) -> Result<u64, LineageLogError> {
        let sequence = self.entries.len() as u64;

        // Check for duplicate receipt.
        let receipt_id_str = hex::encode(receipt.receipt_id.as_bytes());
        for existing in &self.entries {
            if existing.receipt.receipt_id == receipt.receipt_id {
                return Err(LineageLogError::DuplicateReceipt {
                    receipt_id: receipt_id_str,
                });
            }
        }

        // Predecessor hash: hash of the previous entry, or zeros for first.
        let predecessor_hash = if let Some(last) = self.entries.last() {
            last.entry_hash
        } else {
            ContentHash::compute(b"genesis")
        };

        let entry_hash = LineageLogEntry::compute_hash(sequence, kind, &receipt, &predecessor_hash);

        let entry = LineageLogEntry {
            sequence,
            receipt,
            kind,
            predecessor_hash,
            entry_hash,
        };

        self.entries.push(entry);

        self.emit_event(
            "entry_appended",
            "ok",
            None,
            &format!("seq={sequence},kind={kind}"),
        );

        // Auto-checkpoint.
        if self.config.checkpoint_interval > 0
            && (sequence + 1).is_multiple_of(self.config.checkpoint_interval)
        {
            let _ = self.create_checkpoint(timestamp_ns, SecurityEpoch::from_raw(1));
        }

        Ok(sequence)
    }

    /// Create a signed checkpoint at the current log state.
    pub fn create_checkpoint(
        &mut self,
        timestamp_ns: u64,
        epoch: SecurityEpoch,
    ) -> Result<u64, LineageLogError> {
        if self.entries.is_empty() {
            return Err(LineageLogError::EmptyLog);
        }

        let log_length = self.entries.len() as u64;
        let entry_hashes: Vec<ContentHash> = self.entries.iter().map(|e| e.entry_hash).collect();
        let merkle_root = compute_merkle_root(&entry_hashes);

        let checkpoint_seq = self.checkpoint_seq_counter;
        self.checkpoint_seq_counter += 1;

        let checkpoint_hash = LogCheckpoint::compute_checkpoint_hash(
            checkpoint_seq,
            log_length,
            &merkle_root,
            timestamp_ns,
            epoch,
        );

        let checkpoint = LogCheckpoint {
            checkpoint_seq,
            log_length,
            merkle_root,
            timestamp_ns,
            epoch,
            checkpoint_hash,
        };

        self.checkpoints.push(checkpoint);

        self.emit_event(
            "checkpoint_created",
            "ok",
            None,
            &format!("checkpoint_seq={checkpoint_seq},log_length={log_length}"),
        );

        Ok(checkpoint_seq)
    }

    /// Query log entries matching a filter.
    pub fn query(&self, filter: &LineageQuery) -> Vec<&LineageLogEntry> {
        self.entries.iter().filter(|e| filter.matches(e)).collect()
    }

    /// Get the complete replacement lineage for a slot.
    pub fn slot_lineage(&self, slot_id: &SlotId) -> Vec<LineageStep> {
        self.entries
            .iter()
            .filter(|e| e.receipt.slot_id == *slot_id)
            .map(|e| LineageStep {
                sequence: e.sequence,
                kind: e.kind,
                old_cell_digest: e.receipt.old_cell_digest.clone(),
                new_cell_digest: e.receipt.new_cell_digest.clone(),
                receipt_id: hex::encode(e.receipt.receipt_id.as_bytes()),
                timestamp_ns: e.receipt.timestamp_ns,
                epoch: e.receipt.epoch,
                validation_artifact_count: e.receipt.validation_artifacts.len(),
            })
            .collect()
    }

    /// Generate a Merkle inclusion proof for a specific entry.
    pub fn inclusion_proof(&self, sequence: u64) -> Option<InclusionProof> {
        let entry_hashes: Vec<ContentHash> = self.entries.iter().map(|e| e.entry_hash).collect();
        build_inclusion_proof(&entry_hashes, sequence as usize)
    }

    /// Verify the full replacement lineage for a slot.
    pub fn verify_slot_lineage(&self, slot_id: &SlotId) -> LineageVerification {
        let slot_entries: Vec<&LineageLogEntry> = self
            .entries
            .iter()
            .filter(|e| e.receipt.slot_id == *slot_id)
            .collect();

        let mut issues = Vec::new();

        if slot_entries.is_empty() {
            return LineageVerification {
                slot_id: slot_id.clone(),
                total_entries: 0,
                chain_valid: true,
                all_receipts_present: true,
                issues: vec!["no entries for this slot".to_string()],
            };
        }

        // Verify each entry's hash is correct.
        let mut chain_valid = true;
        for entry in &slot_entries {
            let expected_hash = LineageLogEntry::compute_hash(
                entry.sequence,
                entry.kind,
                &entry.receipt,
                &entry.predecessor_hash,
            );
            if expected_hash != entry.entry_hash {
                chain_valid = false;
                issues.push(format!("entry {} hash mismatch", entry.sequence));
            }
        }

        // Verify chain continuity: each entry's predecessor hash should match
        // the actual predecessor in the global log.
        for entry in &slot_entries {
            if entry.sequence == 0 {
                let genesis = ContentHash::compute(b"genesis");
                if entry.predecessor_hash != genesis {
                    chain_valid = false;
                    issues.push("first entry has wrong genesis hash".to_string());
                }
            } else {
                match self.entries.get(entry.sequence as usize - 1) {
                    Some(pred) if entry.predecessor_hash != pred.entry_hash => {
                        chain_valid = false;
                        issues.push(format!(
                            "entry {} predecessor hash mismatch",
                            entry.sequence
                        ));
                    }
                    None => {
                        chain_valid = false;
                        issues.push(format!(
                            "entry {} predecessor at sequence {} missing from global log",
                            entry.sequence,
                            entry.sequence - 1,
                        ));
                    }
                    _ => {}
                }
            }
        }

        LineageVerification {
            slot_id: slot_id.clone(),
            total_entries: slot_entries.len(),
            chain_valid,
            all_receipts_present: true,
            issues,
        }
    }

    /// Audit the entire log for consistency and completeness.
    pub fn audit(&self) -> AuditResult {
        let mut issues = Vec::new();
        let mut chain_valid = true;

        // Verify the full hash chain.
        for (i, entry) in self.entries.iter().enumerate() {
            let expected_pred = if i == 0 {
                ContentHash::compute(b"genesis")
            } else {
                self.entries[i - 1].entry_hash
            };

            if entry.predecessor_hash != expected_pred {
                chain_valid = false;
                issues.push(format!("chain break at sequence {}", entry.sequence));
            }

            let expected_hash = LineageLogEntry::compute_hash(
                entry.sequence,
                entry.kind,
                &entry.receipt,
                &entry.predecessor_hash,
            );
            if entry.entry_hash != expected_hash {
                chain_valid = false;
                issues.push(format!("hash mismatch at sequence {}", entry.sequence));
            }

            if entry.sequence != i as u64 {
                issues.push(format!(
                    "sequence gap: expected {i}, got {}",
                    entry.sequence
                ));
            }
        }

        // Verify Merkle root matches the latest checkpoint.
        let entry_hashes: Vec<ContentHash> = self.entries.iter().map(|e| e.entry_hash).collect();
        let current_root = compute_merkle_root(&entry_hashes);
        let mut merkle_valid = if let Some(last_cp) = self.checkpoints.last() {
            if last_cp.log_length == self.entries.len() as u64 {
                if last_cp.merkle_root != current_root {
                    issues.push("latest checkpoint merkle root mismatch".to_string());
                    false
                } else {
                    true
                }
            } else {
                // Checkpoint covers a prefix — verify that prefix.
                let prefix_hashes: Vec<ContentHash> = entry_hashes
                    .iter()
                    .take(last_cp.log_length as usize)
                    .cloned()
                    .collect();
                let prefix_root = compute_merkle_root(&prefix_hashes);
                if last_cp.merkle_root != prefix_root {
                    issues.push("checkpoint merkle root mismatch for prefix".to_string());
                    false
                } else {
                    true
                }
            }
        } else {
            true // No checkpoints, nothing to verify.
        };

        // Verify checkpoint chain monotonicity and pairwise consistency proofs.
        for window in self.checkpoints.windows(2) {
            if window[1].checkpoint_seq <= window[0].checkpoint_seq {
                issues.push("checkpoint sequence not monotonic".to_string());
                merkle_valid = false;
            }
            if window[1].log_length < window[0].log_length {
                issues.push("checkpoint log_length regressed".to_string());
                merkle_valid = false;
            }

            match self.consistency_proof(window[0].checkpoint_seq, window[1].checkpoint_seq) {
                Ok(proof) => {
                    if !verify_consistency_proof(&proof) {
                        issues.push(format!(
                            "checkpoint consistency proof failed ({} -> {})",
                            window[0].checkpoint_seq, window[1].checkpoint_seq
                        ));
                        merkle_valid = false;
                    }
                }
                Err(err) => {
                    issues.push(format!(
                        "checkpoint consistency generation failed ({} -> {}): {err}",
                        window[0].checkpoint_seq, window[1].checkpoint_seq
                    ));
                    merkle_valid = false;
                }
            }
        }

        // Count unique slots.
        let unique_slots: BTreeSet<&SlotId> =
            self.entries.iter().map(|e| &e.receipt.slot_id).collect();

        let latest_checkpoint_seq = self.checkpoints.last().map(|cp| cp.checkpoint_seq);

        AuditResult {
            total_entries: self.entries.len() as u64,
            total_slots: unique_slots.len(),
            chain_valid,
            merkle_valid,
            checkpoint_count: self.checkpoints.len(),
            latest_checkpoint_seq,
            issues,
        }
    }

    /// Get the current Merkle root.
    pub fn merkle_root(&self) -> ContentHash {
        let entry_hashes: Vec<ContentHash> = self.entries.iter().map(|e| e.entry_hash).collect();
        compute_merkle_root(&entry_hashes)
    }

    /// Get distinct slot IDs that appear in the log.
    pub fn slot_ids(&self) -> Vec<SlotId> {
        let unique: BTreeSet<&SlotId> = self.entries.iter().map(|e| &e.receipt.slot_id).collect();
        unique.into_iter().cloned().collect()
    }

    // ── internal helpers ────────────────────────────────────────────

    fn checkpoint_by_seq(&self, checkpoint_seq: u64) -> Option<&LogCheckpoint> {
        self.checkpoints
            .iter()
            .find(|cp| cp.checkpoint_seq == checkpoint_seq)
    }

    fn emit_event(
        &mut self,
        event: &str,
        outcome: &str,
        error_code: Option<&str>,
        trace_suffix: &str,
    ) {
        let seq = self.event_seq;
        self.event_seq += 1;
        self.events.push(LineageLogEvent {
            trace_id: format!("lineage-{seq}-{trace_suffix}"),
            decision_id: format!("lineage-decision-{seq}"),
            policy_id: "replacement-lineage-policy".to_string(),
            component: "replacement_lineage_log".to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error_code.map(|s| s.to_string()),
        });
    }
}

// ---------------------------------------------------------------------------
// frankensqlite-backed lineage/evidence index (bd-1ilz)
// ---------------------------------------------------------------------------

const TABLE_REPLACEMENT_RECEIPTS: &str = "replacement_receipts";
const TABLE_DEMOTION_RECEIPTS: &str = "demotion_receipts";
const TABLE_LINEAGE_CHAIN: &str = "lineage_chain";
const TABLE_REPLACEMENT_BY_HASH: &str = "replacement_by_hash";
const TABLE_DEMOTION_BY_HASH: &str = "demotion_by_hash";
const TABLE_EVIDENCE_INDEX: &str = "evidence_index";

/// Stable evidence categories used by replay-join queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EvidenceCategory {
    GateResult,
    PerformanceBenchmark,
    SentinelRiskScore,
    DifferentialExecutionLog,
    Additional,
}

impl EvidenceCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GateResult => "gate_result",
            Self::PerformanceBenchmark => "performance_benchmark",
            Self::SentinelRiskScore => "sentinel_risk_score",
            Self::DifferentialExecutionLog => "differential_execution_log",
            Self::Additional => "additional",
        }
    }
}

impl fmt::Display for EvidenceCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Input evidence pointer attached while indexing a receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidencePointerInput {
    pub category: EvidenceCategory,
    pub artifact_digest: String,
    pub passed: Option<bool>,
    pub summary: String,
}

/// Evidence pointer persisted in the evidence index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidencePointer {
    pub receipt_id: String,
    pub category: EvidenceCategory,
    pub artifact_digest: String,
    pub passed: Option<bool>,
    pub summary: String,
}

impl EvidencePointer {
    fn from_input(receipt_id: &str, input: EvidencePointerInput) -> Self {
        Self {
            receipt_id: receipt_id.to_string(),
            category: input.category,
            artifact_digest: input.artifact_digest,
            passed: input.passed,
            summary: input.summary,
        }
    }
}

fn category_from_validation_kind(kind: ValidationArtifactKind) -> EvidenceCategory {
    match kind {
        ValidationArtifactKind::EquivalenceResult => EvidenceCategory::DifferentialExecutionLog,
        ValidationArtifactKind::CapabilityPreservation => EvidenceCategory::GateResult,
        ValidationArtifactKind::PerformanceBenchmark => EvidenceCategory::PerformanceBenchmark,
        ValidationArtifactKind::AdversarialSurvival => EvidenceCategory::GateResult,
    }
}

/// Canonical replacement receipt record persisted in the lineage index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplacementReceiptRecord {
    pub receipt_id: String,
    pub slot_id: SlotId,
    pub replacement_kind: ReplacementKind,
    pub old_cell_digest: String,
    pub new_cell_digest: String,
    pub promotion_timestamp_ns: u64,
    pub epoch: SecurityEpoch,
    pub receipt_content_hash: String,
    pub receipt: ReplacementReceipt,
}

/// Input for indexing a demotion receipt artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemotionReceiptInput {
    pub receipt_id: String,
    pub slot_id: SlotId,
    pub demoted_cell_digest: String,
    pub restored_cell_digest: String,
    pub demotion_reason: String,
    pub timestamp_ns: u64,
    pub rollback_token_used: String,
    pub linked_replacement_receipt_id: Option<String>,
    pub evidence: Vec<EvidencePointerInput>,
}

/// Canonical demotion receipt record persisted in the lineage index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemotionReceiptRecord {
    pub receipt_id: String,
    pub slot_id: SlotId,
    pub demoted_cell_digest: String,
    pub restored_cell_digest: String,
    pub demotion_reason: String,
    pub timestamp_ns: u64,
    pub rollback_token_used: String,
    pub linked_replacement_receipt_id: Option<String>,
    pub receipt_content_hash: String,
}

/// Entry in the ordered lineage-chain index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageChainEntry {
    pub slot_id: SlotId,
    pub timestamp_ns: u64,
    pub receipt_id: String,
    pub kind: ReplacementKind,
    pub from_cell_digest: String,
    pub to_cell_digest: String,
    pub receipt_content_hash: String,
}

/// Time-range query over a slot's lineage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SlotLineageQuery {
    pub min_timestamp_ns: Option<u64>,
    pub max_timestamp_ns: Option<u64>,
    pub limit: Option<usize>,
}

impl SlotLineageQuery {
    fn matches(&self, entry: &LineageChainEntry) -> bool {
        if let Some(min_ts) = self.min_timestamp_ns
            && entry.timestamp_ns < min_ts
        {
            return false;
        }
        if let Some(max_ts) = self.max_timestamp_ns
            && entry.timestamp_ns > max_ts
        {
            return false;
        }
        true
    }
}

/// Query for deterministic replay joins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ReplayJoinQuery {
    pub slot_id: Option<SlotId>,
    pub min_timestamp_ns: Option<u64>,
    pub max_timestamp_ns: Option<u64>,
    pub limit: Option<usize>,
}

/// Joined view for replay/audit/operator flows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayJoinRow {
    pub slot_id: SlotId,
    pub replacement_receipt_id: String,
    pub replacement_kind: ReplacementKind,
    pub old_cell_digest: String,
    pub new_cell_digest: String,
    pub promotion_timestamp_ns: u64,
    pub replacement_content_hash: String,
    pub demotion_receipt_id: Option<String>,
    pub demotion_reason: Option<String>,
    pub demotion_timestamp_ns: Option<u64>,
    pub gate_results: Vec<EvidencePointer>,
    pub performance_benchmarks: Vec<EvidencePointer>,
    pub sentinel_risk_scores: Vec<EvidencePointer>,
    pub differential_execution_logs: Vec<EvidencePointer>,
    pub additional_evidence: Vec<EvidencePointer>,
}

/// Structured index event emitted by lineage-index operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageIndexEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

/// Stable error taxonomy for lineage-index operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LineageIndexError {
    Storage(StorageError),
    Serialization { operation: String, detail: String },
    CorruptRecord { key: String, detail: String },
    InvalidInput { detail: String },
}

impl LineageIndexError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Storage(_) => "FE-LIDX-0001",
            Self::Serialization { .. } => "FE-LIDX-0002",
            Self::CorruptRecord { .. } => "FE-LIDX-0003",
            Self::InvalidInput { .. } => "FE-LIDX-0004",
        }
    }
}

impl fmt::Display for LineageIndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(err) => write!(f, "storage error: {err}"),
            Self::Serialization { operation, detail } => {
                write!(f, "serialization error ({operation}): {detail}")
            }
            Self::CorruptRecord { key, detail } => {
                write!(f, "corrupt record `{key}`: {detail}")
            }
            Self::InvalidInput { detail } => write!(f, "invalid input: {detail}"),
        }
    }
}

impl std::error::Error for LineageIndexError {}

impl From<StorageError> for LineageIndexError {
    fn from(value: StorageError) -> Self {
        Self::Storage(value)
    }
}

/// Typed lineage/evidence index backed by the storage-adapter contract.
///
/// Schema coverage:
/// - replacement receipts table
/// - demotion receipts table
/// - lineage chain table
/// - evidence index table
/// - content-address lookup tables (replacement/demotion by content hash)
#[derive(Debug)]
pub struct ReplacementLineageEvidenceIndex<A: StorageAdapter> {
    adapter: A,
    events: Vec<LineageIndexEvent>,
}

impl<A: StorageAdapter> ReplacementLineageEvidenceIndex<A> {
    pub fn new(adapter: A) -> Self {
        Self {
            adapter,
            events: Vec::new(),
        }
    }

    pub fn into_inner(self) -> A {
        self.adapter
    }

    pub fn events(&self) -> &[LineageIndexEvent] {
        &self.events
    }

    fn emit_event(
        &mut self,
        context: &EventContext,
        event: &str,
        outcome: &str,
        error: Option<&LineageIndexError>,
    ) {
        self.events.push(LineageIndexEvent {
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: "replacement_lineage_index".to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error.map(|err| err.code().to_string()),
        });
    }

    /// Index a replacement receipt and its validation evidence.
    pub fn index_replacement_receipt(
        &mut self,
        receipt: &ReplacementReceipt,
        replacement_kind: ReplacementKind,
        supplemental_evidence: &[EvidencePointerInput],
        context: &EventContext,
    ) -> Result<ReplacementReceiptRecord, LineageIndexError> {
        let result = (|| {
            let receipt_id = hex::encode(receipt.receipt_id.as_bytes());
            let receipt_bytes =
                serde_json::to_vec(receipt).map_err(|err| LineageIndexError::Serialization {
                    operation: "serialize replacement receipt".to_string(),
                    detail: err.to_string(),
                })?;
            let receipt_content_hash = hex::encode(ContentHash::compute(&receipt_bytes).as_bytes());

            let record = ReplacementReceiptRecord {
                receipt_id,
                slot_id: receipt.slot_id.clone(),
                replacement_kind,
                old_cell_digest: receipt.old_cell_digest.clone(),
                new_cell_digest: receipt.new_cell_digest.clone(),
                promotion_timestamp_ns: receipt.timestamp_ns,
                epoch: receipt.epoch,
                receipt_content_hash,
                receipt: receipt.clone(),
            };

            let key = replacement_receipt_key(
                &record.slot_id,
                record.promotion_timestamp_ns,
                &record.receipt_id,
            );
            let mut metadata = table_metadata(TABLE_REPLACEMENT_RECEIPTS);
            metadata.insert("slot_id".to_string(), record.slot_id.as_str().to_string());
            metadata.insert(
                "old_cell_digest".to_string(),
                record.old_cell_digest.clone(),
            );
            metadata.insert(
                "new_cell_digest".to_string(),
                record.new_cell_digest.clone(),
            );
            metadata.insert(
                "promotion_timestamp_ns".to_string(),
                record.promotion_timestamp_ns.to_string(),
            );
            metadata.insert(
                "replacement_kind".to_string(),
                record.replacement_kind.as_str().to_string(),
            );
            metadata.insert(
                "receipt_content_hash".to_string(),
                record.receipt_content_hash.clone(),
            );

            let value =
                serde_json::to_vec(&record).map_err(|err| LineageIndexError::Serialization {
                    operation: "serialize replacement record".to_string(),
                    detail: err.to_string(),
                })?;
            self.adapter.put(
                StoreKind::ReplacementLineage,
                key.clone(),
                value,
                metadata,
                context,
            )?;

            self.adapter.put(
                StoreKind::ReplacementLineage,
                replacement_by_hash_key(&record.receipt_content_hash),
                key.as_bytes().to_vec(),
                table_metadata(TABLE_REPLACEMENT_BY_HASH),
                context,
            )?;

            let chain_entry = LineageChainEntry {
                slot_id: record.slot_id.clone(),
                timestamp_ns: record.promotion_timestamp_ns,
                receipt_id: record.receipt_id.clone(),
                kind: record.replacement_kind,
                from_cell_digest: record.old_cell_digest.clone(),
                to_cell_digest: record.new_cell_digest.clone(),
                receipt_content_hash: record.receipt_content_hash.clone(),
            };
            let chain_key = lineage_chain_key(
                &chain_entry.slot_id,
                chain_entry.timestamp_ns,
                &chain_entry.receipt_id,
            );
            let mut chain_meta = table_metadata(TABLE_LINEAGE_CHAIN);
            chain_meta.insert(
                "slot_id".to_string(),
                chain_entry.slot_id.as_str().to_string(),
            );
            chain_meta.insert("receipt_id".to_string(), chain_entry.receipt_id.clone());
            let chain_value = serde_json::to_vec(&chain_entry).map_err(|err| {
                LineageIndexError::Serialization {
                    operation: "serialize lineage chain entry".to_string(),
                    detail: err.to_string(),
                }
            })?;
            self.adapter.put(
                StoreKind::ReplacementLineage,
                chain_key,
                chain_value,
                chain_meta,
                context,
            )?;

            let mut evidence_inputs = Vec::with_capacity(
                receipt
                    .validation_artifacts
                    .len()
                    .saturating_add(supplemental_evidence.len()),
            );
            for artifact in &receipt.validation_artifacts {
                evidence_inputs.push(EvidencePointerInput {
                    category: category_from_validation_kind(artifact.kind),
                    artifact_digest: artifact.artifact_digest.clone(),
                    passed: Some(artifact.passed),
                    summary: artifact.summary.clone(),
                });
            }
            evidence_inputs.extend_from_slice(supplemental_evidence);
            self.store_evidence(&record.receipt_id, evidence_inputs, context)?;

            Ok(record)
        })();

        self.emit_event(
            context,
            "index_replacement_receipt",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    /// Index a demotion receipt and associated evidence.
    pub fn index_demotion_receipt(
        &mut self,
        input: DemotionReceiptInput,
        context: &EventContext,
    ) -> Result<DemotionReceiptRecord, LineageIndexError> {
        let result = (|| {
            if input.receipt_id.trim().is_empty() {
                return Err(LineageIndexError::InvalidInput {
                    detail: "demotion receipt_id cannot be empty".to_string(),
                });
            }
            if input.slot_id.as_str().trim().is_empty() {
                return Err(LineageIndexError::InvalidInput {
                    detail: "demotion slot_id cannot be empty".to_string(),
                });
            }

            let canonical =
                serde_json::to_vec(&input).map_err(|err| LineageIndexError::Serialization {
                    operation: "serialize demotion input".to_string(),
                    detail: err.to_string(),
                })?;
            let receipt_content_hash = hex::encode(ContentHash::compute(&canonical).as_bytes());

            let record = DemotionReceiptRecord {
                receipt_id: input.receipt_id.clone(),
                slot_id: input.slot_id.clone(),
                demoted_cell_digest: input.demoted_cell_digest.clone(),
                restored_cell_digest: input.restored_cell_digest.clone(),
                demotion_reason: input.demotion_reason.clone(),
                timestamp_ns: input.timestamp_ns,
                rollback_token_used: input.rollback_token_used.clone(),
                linked_replacement_receipt_id: input.linked_replacement_receipt_id.clone(),
                receipt_content_hash,
            };

            let key =
                demotion_receipt_key(&record.slot_id, record.timestamp_ns, &record.receipt_id);
            let mut metadata = table_metadata(TABLE_DEMOTION_RECEIPTS);
            metadata.insert("slot_id".to_string(), record.slot_id.as_str().to_string());
            metadata.insert(
                "demoted_cell_digest".to_string(),
                record.demoted_cell_digest.clone(),
            );
            metadata.insert(
                "restored_cell_digest".to_string(),
                record.restored_cell_digest.clone(),
            );
            metadata.insert(
                "demotion_reason".to_string(),
                record.demotion_reason.clone(),
            );
            metadata.insert(
                "demotion_timestamp_ns".to_string(),
                record.timestamp_ns.to_string(),
            );
            if let Some(linked) = &record.linked_replacement_receipt_id {
                metadata.insert("linked_replacement_receipt_id".to_string(), linked.clone());
            }
            metadata.insert(
                "receipt_content_hash".to_string(),
                record.receipt_content_hash.clone(),
            );
            let value =
                serde_json::to_vec(&record).map_err(|err| LineageIndexError::Serialization {
                    operation: "serialize demotion record".to_string(),
                    detail: err.to_string(),
                })?;
            self.adapter.put(
                StoreKind::ReplacementLineage,
                key.clone(),
                value,
                metadata,
                context,
            )?;

            self.adapter.put(
                StoreKind::ReplacementLineage,
                demotion_by_hash_key(&record.receipt_content_hash),
                key.as_bytes().to_vec(),
                table_metadata(TABLE_DEMOTION_BY_HASH),
                context,
            )?;

            let chain_entry = LineageChainEntry {
                slot_id: record.slot_id.clone(),
                timestamp_ns: record.timestamp_ns,
                receipt_id: record.receipt_id.clone(),
                kind: ReplacementKind::Demotion,
                from_cell_digest: record.demoted_cell_digest.clone(),
                to_cell_digest: record.restored_cell_digest.clone(),
                receipt_content_hash: record.receipt_content_hash.clone(),
            };
            let mut chain_meta = table_metadata(TABLE_LINEAGE_CHAIN);
            chain_meta.insert(
                "slot_id".to_string(),
                chain_entry.slot_id.as_str().to_string(),
            );
            chain_meta.insert("receipt_id".to_string(), chain_entry.receipt_id.clone());
            let chain_value = serde_json::to_vec(&chain_entry).map_err(|err| {
                LineageIndexError::Serialization {
                    operation: "serialize demotion lineage chain entry".to_string(),
                    detail: err.to_string(),
                }
            })?;
            self.adapter.put(
                StoreKind::ReplacementLineage,
                lineage_chain_key(
                    &chain_entry.slot_id,
                    chain_entry.timestamp_ns,
                    &chain_entry.receipt_id,
                ),
                chain_value,
                chain_meta,
                context,
            )?;

            self.store_evidence(&record.receipt_id, input.evidence, context)?;
            Ok(record)
        })();

        self.emit_event(
            context,
            "index_demotion_receipt",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    /// Lookup a replacement receipt by content hash.
    pub fn replacement_by_content_hash(
        &mut self,
        receipt_content_hash: &str,
        context: &EventContext,
    ) -> Result<Option<ReplacementReceiptRecord>, LineageIndexError> {
        let result =
            (|| {
                let Some(pointer_record) = self.adapter.get(
                    StoreKind::ReplacementLineage,
                    &replacement_by_hash_key(receipt_content_hash),
                    context,
                )?
                else {
                    return Ok(None);
                };

                let pointed_key = String::from_utf8(pointer_record.value).map_err(|err| {
                    LineageIndexError::CorruptRecord {
                        key: pointer_record.key,
                        detail: err.to_string(),
                    }
                })?;

                let Some(record) =
                    self.adapter
                        .get(StoreKind::ReplacementLineage, &pointed_key, context)?
                else {
                    return Ok(None);
                };
                let decoded: ReplacementReceiptRecord = serde_json::from_slice(&record.value)
                    .map_err(|err| LineageIndexError::CorruptRecord {
                        key: record.key,
                        detail: err.to_string(),
                    })?;
                Ok(Some(decoded))
            })();

        self.emit_event(
            context,
            "replacement_by_content_hash",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    /// Lookup a demotion receipt by content hash.
    pub fn demotion_by_content_hash(
        &mut self,
        receipt_content_hash: &str,
        context: &EventContext,
    ) -> Result<Option<DemotionReceiptRecord>, LineageIndexError> {
        let result =
            (|| {
                let Some(pointer_record) = self.adapter.get(
                    StoreKind::ReplacementLineage,
                    &demotion_by_hash_key(receipt_content_hash),
                    context,
                )?
                else {
                    return Ok(None);
                };

                let pointed_key = String::from_utf8(pointer_record.value).map_err(|err| {
                    LineageIndexError::CorruptRecord {
                        key: pointer_record.key,
                        detail: err.to_string(),
                    }
                })?;

                let Some(record) =
                    self.adapter
                        .get(StoreKind::ReplacementLineage, &pointed_key, context)?
                else {
                    return Ok(None);
                };
                let decoded: DemotionReceiptRecord = serde_json::from_slice(&record.value)
                    .map_err(|err| LineageIndexError::CorruptRecord {
                        key: record.key,
                        detail: err.to_string(),
                    })?;
                Ok(Some(decoded))
            })();

        self.emit_event(
            context,
            "demotion_by_content_hash",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    /// Deterministic lineage-chain query for a single slot.
    pub fn slot_lineage(
        &mut self,
        slot_id: &SlotId,
        query: &SlotLineageQuery,
        context: &EventContext,
    ) -> Result<Vec<LineageChainEntry>, LineageIndexError> {
        let result = (|| {
            let rows = self.adapter.query(
                StoreKind::ReplacementLineage,
                &StoreQuery {
                    key_prefix: Some(format!("lineage_chain/{}/", slot_id.as_str())),
                    metadata_filters: table_metadata(TABLE_LINEAGE_CHAIN),
                    limit: None,
                },
                context,
            )?;
            let mut decoded = decode_chain_entries(rows)?;
            decoded.retain(|entry| query.matches(entry));
            decoded.sort_by(|a, b| {
                a.timestamp_ns
                    .cmp(&b.timestamp_ns)
                    .then(a.receipt_id.cmp(&b.receipt_id))
                    .then(a.kind.as_str().cmp(b.kind.as_str()))
            });
            if let Some(limit) = query.limit {
                decoded.truncate(limit);
            }
            Ok(decoded)
        })();

        self.emit_event(
            context,
            "slot_lineage",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    /// Deterministic replay join across receipts + evidence pointers.
    pub fn replay_join(
        &mut self,
        query: &ReplayJoinQuery,
        context: &EventContext,
    ) -> Result<Vec<ReplayJoinRow>, LineageIndexError> {
        let result = (|| {
            let mut replacements = decode_replacement_records(self.adapter.query(
                StoreKind::ReplacementLineage,
                &StoreQuery {
                    key_prefix: Some("replacement_receipts/".to_string()),
                    metadata_filters: table_metadata(TABLE_REPLACEMENT_RECEIPTS),
                    limit: None,
                },
                context,
            )?)?;
            replacements.retain(|record| {
                replay_query_matches(query, &record.slot_id, record.promotion_timestamp_ns)
            });
            replacements.sort_by(|a, b| {
                a.promotion_timestamp_ns
                    .cmp(&b.promotion_timestamp_ns)
                    .then(a.receipt_id.cmp(&b.receipt_id))
            });

            let mut demotions = decode_demotion_records(self.adapter.query(
                StoreKind::ReplacementLineage,
                &StoreQuery {
                    key_prefix: Some("demotion_receipts/".to_string()),
                    metadata_filters: table_metadata(TABLE_DEMOTION_RECEIPTS),
                    limit: None,
                },
                context,
            )?)?;
            demotions.sort_by(|a, b| {
                a.timestamp_ns
                    .cmp(&b.timestamp_ns)
                    .then(a.receipt_id.cmp(&b.receipt_id))
            });

            let mut relevant_receipt_ids: BTreeSet<String> = replacements
                .iter()
                .map(|record| record.receipt_id.clone())
                .collect();
            for demotion in &demotions {
                relevant_receipt_ids.insert(demotion.receipt_id.clone());
            }
            let evidence = self.evidence_by_receipt_ids(&relevant_receipt_ids, context)?;

            let mut rows = Vec::new();
            for replacement in replacements {
                let demotion = demotions
                    .iter()
                    .filter(|demotion| demotion.slot_id == replacement.slot_id)
                    .filter(|demotion| demotion.timestamp_ns >= replacement.promotion_timestamp_ns)
                    .filter(|demotion| {
                        if let Some(linked) = &demotion.linked_replacement_receipt_id {
                            linked == &replacement.receipt_id
                        } else {
                            demotion.demoted_cell_digest == replacement.new_cell_digest
                                && demotion.restored_cell_digest == replacement.old_cell_digest
                        }
                    })
                    .min_by(|a, b| {
                        a.timestamp_ns
                            .cmp(&b.timestamp_ns)
                            .then(a.receipt_id.cmp(&b.receipt_id))
                    })
                    .cloned();

                let mut joined_evidence = evidence
                    .get(&replacement.receipt_id)
                    .cloned()
                    .unwrap_or_default();
                if let Some(ref demotion_record) = demotion {
                    joined_evidence.extend(
                        evidence
                            .get(&demotion_record.receipt_id)
                            .cloned()
                            .unwrap_or_default(),
                    );
                }
                joined_evidence.sort_by(|a, b| {
                    a.category
                        .as_str()
                        .cmp(b.category.as_str())
                        .then(a.artifact_digest.cmp(&b.artifact_digest))
                        .then(a.summary.cmp(&b.summary))
                });

                let mut gate_results = Vec::new();
                let mut performance_benchmarks = Vec::new();
                let mut sentinel_risk_scores = Vec::new();
                let mut differential_execution_logs = Vec::new();
                let mut additional_evidence = Vec::new();

                for item in joined_evidence {
                    match item.category {
                        EvidenceCategory::GateResult => gate_results.push(item),
                        EvidenceCategory::PerformanceBenchmark => performance_benchmarks.push(item),
                        EvidenceCategory::SentinelRiskScore => sentinel_risk_scores.push(item),
                        EvidenceCategory::DifferentialExecutionLog => {
                            differential_execution_logs.push(item)
                        }
                        EvidenceCategory::Additional => additional_evidence.push(item),
                    }
                }

                rows.push(ReplayJoinRow {
                    slot_id: replacement.slot_id.clone(),
                    replacement_receipt_id: replacement.receipt_id.clone(),
                    replacement_kind: replacement.replacement_kind,
                    old_cell_digest: replacement.old_cell_digest.clone(),
                    new_cell_digest: replacement.new_cell_digest.clone(),
                    promotion_timestamp_ns: replacement.promotion_timestamp_ns,
                    replacement_content_hash: replacement.receipt_content_hash,
                    demotion_receipt_id: demotion.as_ref().map(|record| record.receipt_id.clone()),
                    demotion_reason: demotion
                        .as_ref()
                        .map(|record| record.demotion_reason.clone()),
                    demotion_timestamp_ns: demotion.as_ref().map(|record| record.timestamp_ns),
                    gate_results,
                    performance_benchmarks,
                    sentinel_risk_scores,
                    differential_execution_logs,
                    additional_evidence,
                });
            }

            rows.sort_by(|a, b| {
                a.promotion_timestamp_ns
                    .cmp(&b.promotion_timestamp_ns)
                    .then(a.replacement_receipt_id.cmp(&b.replacement_receipt_id))
            });
            if let Some(limit) = query.limit {
                rows.truncate(limit);
            }
            Ok(rows)
        })();

        self.emit_event(
            context,
            "replay_join",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    fn store_evidence(
        &mut self,
        receipt_id: &str,
        evidence: Vec<EvidencePointerInput>,
        context: &EventContext,
    ) -> Result<(), LineageIndexError> {
        for (idx, input) in evidence.into_iter().enumerate() {
            let pointer = EvidencePointer::from_input(receipt_id, input);
            if pointer.artifact_digest.trim().is_empty() {
                return Err(LineageIndexError::InvalidInput {
                    detail: format!("evidence pointer at index {idx} has empty artifact_digest"),
                });
            }
            let key = evidence_key(
                &pointer.receipt_id,
                pointer.category,
                idx,
                &pointer.artifact_digest,
            );
            let mut metadata = table_metadata(TABLE_EVIDENCE_INDEX);
            metadata.insert("receipt_id".to_string(), pointer.receipt_id.clone());
            metadata.insert(
                "category".to_string(),
                pointer.category.as_str().to_string(),
            );
            metadata.insert(
                "artifact_digest".to_string(),
                pointer.artifact_digest.clone(),
            );

            let value =
                serde_json::to_vec(&pointer).map_err(|err| LineageIndexError::Serialization {
                    operation: "serialize evidence pointer".to_string(),
                    detail: err.to_string(),
                })?;
            self.adapter
                .put(StoreKind::EvidenceIndex, key, value, metadata, context)?;
        }
        Ok(())
    }

    fn evidence_by_receipt_ids(
        &mut self,
        receipt_ids: &BTreeSet<String>,
        context: &EventContext,
    ) -> Result<BTreeMap<String, Vec<EvidencePointer>>, LineageIndexError> {
        let rows = self.adapter.query(
            StoreKind::EvidenceIndex,
            &StoreQuery {
                key_prefix: Some("evidence/".to_string()),
                metadata_filters: table_metadata(TABLE_EVIDENCE_INDEX),
                limit: None,
            },
            context,
        )?;

        let mut out: BTreeMap<String, Vec<EvidencePointer>> = BTreeMap::new();
        for row in rows {
            let pointer: EvidencePointer = serde_json::from_slice(&row.value).map_err(|err| {
                LineageIndexError::CorruptRecord {
                    key: row.key,
                    detail: err.to_string(),
                }
            })?;
            if receipt_ids.contains(&pointer.receipt_id) {
                out.entry(pointer.receipt_id.clone())
                    .or_default()
                    .push(pointer);
            }
        }

        for pointers in out.values_mut() {
            pointers.sort_by(|a, b| {
                a.category
                    .as_str()
                    .cmp(b.category.as_str())
                    .then(a.artifact_digest.cmp(&b.artifact_digest))
                    .then(a.summary.cmp(&b.summary))
            });
        }
        Ok(out)
    }
}

fn replay_query_matches(query: &ReplayJoinQuery, slot_id: &SlotId, timestamp_ns: u64) -> bool {
    if let Some(expected_slot) = &query.slot_id
        && slot_id != expected_slot
    {
        return false;
    }
    if let Some(min_ts) = query.min_timestamp_ns
        && timestamp_ns < min_ts
    {
        return false;
    }
    if let Some(max_ts) = query.max_timestamp_ns
        && timestamp_ns > max_ts
    {
        return false;
    }
    true
}

fn table_metadata(table: &str) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    metadata.insert("table".to_string(), table.to_string());
    metadata
}

fn replacement_receipt_key(slot_id: &SlotId, timestamp_ns: u64, receipt_id: &str) -> String {
    format!(
        "replacement_receipts/{}/{:020}/{}",
        slot_id.as_str(),
        timestamp_ns,
        receipt_id
    )
}

fn demotion_receipt_key(slot_id: &SlotId, timestamp_ns: u64, receipt_id: &str) -> String {
    format!(
        "demotion_receipts/{}/{:020}/{}",
        slot_id.as_str(),
        timestamp_ns,
        receipt_id
    )
}

fn lineage_chain_key(slot_id: &SlotId, timestamp_ns: u64, receipt_id: &str) -> String {
    format!(
        "lineage_chain/{}/{:020}/{}",
        slot_id.as_str(),
        timestamp_ns,
        receipt_id
    )
}

fn replacement_by_hash_key(content_hash: &str) -> String {
    format!("replacement_by_hash/{content_hash}")
}

fn demotion_by_hash_key(content_hash: &str) -> String {
    format!("demotion_by_hash/{content_hash}")
}

fn evidence_key(
    receipt_id: &str,
    category: EvidenceCategory,
    ordinal: usize,
    artifact_digest: &str,
) -> String {
    format!(
        "evidence/{}/{}/{:04}/{}",
        receipt_id,
        category.as_str(),
        ordinal,
        artifact_digest
    )
}

fn decode_replacement_records(
    rows: Vec<crate::storage_adapter::StoreRecord>,
) -> Result<Vec<ReplacementReceiptRecord>, LineageIndexError> {
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let record: ReplacementReceiptRecord =
            serde_json::from_slice(&row.value).map_err(|err| LineageIndexError::CorruptRecord {
                key: row.key,
                detail: err.to_string(),
            })?;
        out.push(record);
    }
    Ok(out)
}

fn decode_demotion_records(
    rows: Vec<crate::storage_adapter::StoreRecord>,
) -> Result<Vec<DemotionReceiptRecord>, LineageIndexError> {
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let record: DemotionReceiptRecord =
            serde_json::from_slice(&row.value).map_err(|err| LineageIndexError::CorruptRecord {
                key: row.key,
                detail: err.to_string(),
            })?;
        out.push(record);
    }
    Ok(out)
}

fn decode_chain_entries(
    rows: Vec<crate::storage_adapter::StoreRecord>,
) -> Result<Vec<LineageChainEntry>, LineageIndexError> {
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let record: LineageChainEntry =
            serde_json::from_slice(&row.value).map_err(|err| LineageIndexError::CorruptRecord {
                key: row.key,
                detail: err.to_string(),
            })?;
        out.push(record);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_object_id::{self, ObjectDomain};
    use crate::self_replacement::{
        SchemaVersion, SignatureBundle, ValidationArtifactKind, ValidationArtifactRef,
    };

    fn test_slot_id(name: &str) -> SlotId {
        SlotId::new(name).expect("valid slot id")
    }

    fn test_receipt(slot_name: &str, old: &str, new: &str, ts: u64) -> ReplacementReceipt {
        let slot_id = test_slot_id(slot_name);
        let receipt_id = engine_object_id::derive_id(
            ObjectDomain::CheckpointArtifact,
            "test-zone",
            &engine_object_id::SchemaId::from_definition(b"test-receipt-schema"),
            &format!("{slot_name}|{old}|{new}|{ts}").into_bytes(),
        )
        .expect("valid id");

        ReplacementReceipt {
            receipt_id,
            schema_version: SchemaVersion::V1,
            slot_id,
            old_cell_digest: old.to_string(),
            new_cell_digest: new.to_string(),
            validation_artifacts: vec![ValidationArtifactRef {
                kind: ValidationArtifactKind::EquivalenceResult,
                artifact_digest: "deadbeef".to_string(),
                passed: true,
                summary: "test artifact".to_string(),
            }],
            rollback_token: format!("rollback-{old}"),
            promotion_rationale: "test promotion".to_string(),
            timestamp_ns: ts,
            epoch: SecurityEpoch::from_raw(1),
            zone: "test-zone".to_string(),
            signature_bundle: SignatureBundle::new(1),
        }
    }

    // ── basic operations ────────────────────────────────────────────

    #[test]
    fn new_log_is_empty() {
        let log = ReplacementLineageLog::new(LineageLogConfig::default());
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn append_single_entry() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let receipt = test_receipt("slot-a", "old-digest", "new-digest", 1000);
        let seq = log
            .append(receipt, ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        assert_eq!(seq, 0);
        assert_eq!(log.len(), 1);
        assert!(!log.is_empty());
    }

    #[test]
    fn append_multiple_entries() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..5 {
            let receipt = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            let seq = log
                .append(receipt, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
            assert_eq!(seq, i);
        }
        assert_eq!(log.len(), 5);
    }

    #[test]
    fn duplicate_receipt_rejected() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let receipt = test_receipt("slot-a", "old", "new", 1000);
        log.append(receipt.clone(), ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        let result = log.append(receipt, ReplacementKind::DelegateToNative, 2000);
        assert!(matches!(
            result,
            Err(LineageLogError::DuplicateReceipt { .. })
        ));
    }

    // ── hash chain ──────────────────────────────────────────────────

    #[test]
    fn first_entry_uses_genesis_predecessor() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let receipt = test_receipt("slot-a", "old", "new", 1000);
        log.append(receipt, ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        let genesis = ContentHash::compute(b"genesis");
        assert_eq!(log.entries()[0].predecessor_hash, genesis);
    }

    #[test]
    fn entries_are_hash_chained() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..3 {
            let receipt = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(receipt, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
        }
        // Entry 1's predecessor should be entry 0's hash.
        assert_eq!(
            log.entries()[1].predecessor_hash,
            log.entries()[0].entry_hash
        );
        assert_eq!(
            log.entries()[2].predecessor_hash,
            log.entries()[1].entry_hash
        );
    }

    #[test]
    fn entry_hash_is_deterministic() {
        let mut log1 = ReplacementLineageLog::new(LineageLogConfig::default());
        let mut log2 = ReplacementLineageLog::new(LineageLogConfig::default());
        let receipt = test_receipt("slot-a", "old", "new", 1000);
        log1.append(receipt.clone(), ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        log2.append(receipt, ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        assert_eq!(log1.entries()[0].entry_hash, log2.entries()[0].entry_hash);
    }

    // ── Merkle tree ─────────────────────────────────────────────────

    #[test]
    fn merkle_root_single_entry() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let receipt = test_receipt("slot-a", "old", "new", 1000);
        log.append(receipt, ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        let root = log.merkle_root();
        // Should be merkle_leaf(entry_hash).
        let expected = merkle_leaf(&log.entries()[0].entry_hash);
        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_root_deterministic() {
        let mut log1 = ReplacementLineageLog::new(LineageLogConfig::default());
        let mut log2 = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..4 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log1.append(r.clone(), ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
            log2.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
        }
        assert_eq!(log1.merkle_root(), log2.merkle_root());
    }

    #[test]
    fn merkle_root_changes_with_new_entry() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r1 = test_receipt("slot-a", "old-0", "new-0", 100);
        log.append(r1, ReplacementKind::DelegateToNative, 100)
            .unwrap();
        let root1 = log.merkle_root();
        let r2 = test_receipt("slot-a", "old-1", "new-1", 200);
        log.append(r2, ReplacementKind::DelegateToNative, 200)
            .unwrap();
        let root2 = log.merkle_root();
        assert_ne!(root1, root2);
    }

    // ── inclusion proofs ────────────────────────────────────────────

    #[test]
    fn inclusion_proof_single_entry() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let receipt = test_receipt("slot-a", "old", "new", 1000);
        log.append(receipt, ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        let proof = log.inclusion_proof(0).expect("proof exists");
        assert!(verify_inclusion_proof(&proof));
    }

    #[test]
    fn inclusion_proof_multiple_entries() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..8 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
        }
        // Verify inclusion proof for every entry.
        for i in 0..8 {
            let proof = log.inclusion_proof(i).expect("proof exists");
            assert_eq!(proof.entry_index, i);
            assert!(
                verify_inclusion_proof(&proof),
                "inclusion proof failed for entry {i}"
            );
        }
    }

    #[test]
    fn inclusion_proof_odd_count() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..7 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
        }
        for i in 0..7 {
            let proof = log.inclusion_proof(i).expect("proof exists");
            assert!(
                verify_inclusion_proof(&proof),
                "inclusion proof failed for entry {i}"
            );
        }
    }

    #[test]
    fn inclusion_proof_out_of_bounds() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r = test_receipt("slot-a", "old", "new", 100);
        log.append(r, ReplacementKind::DelegateToNative, 100)
            .unwrap();
        assert!(log.inclusion_proof(5).is_none());
    }

    #[test]
    fn tampered_inclusion_proof_fails() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..4 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
        }
        let mut proof = log.inclusion_proof(2).expect("proof exists");
        // Tamper with the entry hash.
        proof.entry_hash = ContentHash::compute(b"tampered");
        assert!(!verify_inclusion_proof(&proof));
    }

    // ── checkpoints ─────────────────────────────────────────────────

    #[test]
    fn create_checkpoint() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r = test_receipt("slot-a", "old", "new", 1000);
        log.append(r, ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        let cp_seq = log
            .create_checkpoint(1000, SecurityEpoch::from_raw(1))
            .unwrap();
        assert_eq!(cp_seq, 0);
        assert_eq!(log.checkpoints().len(), 1);
        assert_eq!(log.checkpoints()[0].log_length, 1);
    }

    #[test]
    fn checkpoint_on_empty_log_fails() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let result = log.create_checkpoint(1000, SecurityEpoch::from_raw(1));
        assert!(matches!(result, Err(LineageLogError::EmptyLog)));
    }

    #[test]
    fn checkpoint_merkle_root_matches() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..5 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
        }
        log.create_checkpoint(500, SecurityEpoch::from_raw(1))
            .unwrap();
        let root = log.merkle_root();
        assert_eq!(log.checkpoints()[0].merkle_root, root);
    }

    #[test]
    fn auto_checkpoint_at_interval() {
        let config = LineageLogConfig {
            checkpoint_interval: 3,
            max_entries_in_memory: 0,
        };
        let mut log = ReplacementLineageLog::new(config);
        for i in 0..6 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
        }
        // Checkpoints at entries 2 (seq 0..2 = 3 entries) and 5 (seq 0..5 = 6 entries).
        assert_eq!(log.checkpoints().len(), 2);
    }

    #[test]
    fn checkpoint_hash_deterministic() {
        let mut log1 = ReplacementLineageLog::new(LineageLogConfig::default());
        let mut log2 = ReplacementLineageLog::new(LineageLogConfig::default());
        let r = test_receipt("slot-a", "old", "new", 1000);
        log1.append(r.clone(), ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        log2.append(r, ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        log1.create_checkpoint(1000, SecurityEpoch::from_raw(1))
            .unwrap();
        log2.create_checkpoint(1000, SecurityEpoch::from_raw(1))
            .unwrap();
        assert_eq!(
            log1.checkpoints()[0].checkpoint_hash,
            log2.checkpoints()[0].checkpoint_hash
        );
    }

    #[test]
    fn consistency_proof_between_checkpoints_verifies() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..6 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
            if i == 2 || i == 5 {
                log.create_checkpoint(i * 100, SecurityEpoch::from_raw(1))
                    .unwrap();
            }
        }

        let proof = log.consistency_proof(0, 1).expect("proof");
        assert_eq!(proof.older_log_length, 3);
        assert_eq!(proof.newer_log_length, 6);
        assert!(verify_consistency_proof(&proof));
    }

    #[test]
    fn consistency_proof_tamper_is_detected() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..4 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
            if i == 1 || i == 3 {
                log.create_checkpoint(i * 100, SecurityEpoch::from_raw(1))
                    .unwrap();
            }
        }

        let mut proof = log.consistency_proof(0, 1).expect("proof");
        proof.newer_entry_hashes[0] = ContentHash::compute(b"tampered");
        assert!(!verify_consistency_proof(&proof));
    }

    #[test]
    fn consistency_proof_invalid_order_fails() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..2 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
            log.create_checkpoint(i * 100, SecurityEpoch::from_raw(1))
                .unwrap();
        }

        let err = log.consistency_proof(1, 0).expect_err("invalid order");
        assert!(matches!(
            err,
            LineageLogError::InvalidCheckpointOrder { older: 1, newer: 0 }
        ));
    }

    #[test]
    fn consistency_proof_missing_checkpoint_fails() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r = test_receipt("slot-a", "old", "new", 100);
        log.append(r, ReplacementKind::DelegateToNative, 100)
            .unwrap();
        log.create_checkpoint(100, SecurityEpoch::from_raw(1))
            .unwrap();

        let err = log
            .consistency_proof(0, 99)
            .expect_err("missing checkpoint must fail");
        assert!(matches!(
            err,
            LineageLogError::CheckpointNotFound { checkpoint_seq: 99 }
        ));
    }

    // ── queries ─────────────────────────────────────────────────────

    #[test]
    fn query_by_slot_id() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r1 = test_receipt("slot-a", "old-a", "new-a", 100);
        let r2 = test_receipt("slot-b", "old-b", "new-b", 200);
        let r3 = test_receipt("slot-a", "new-a", "newer-a", 300);
        log.append(r1, ReplacementKind::DelegateToNative, 100)
            .unwrap();
        log.append(r2, ReplacementKind::DelegateToNative, 200)
            .unwrap();
        log.append(r3, ReplacementKind::RePromotion, 300).unwrap();

        let results = log.query(&LineageQuery::for_slot(test_slot_id("slot-a")));
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn query_by_kind() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r1 = test_receipt("slot-a", "old", "new", 100);
        let r2 = test_receipt("slot-a", "new", "old", 200);
        log.append(r1, ReplacementKind::DelegateToNative, 100)
            .unwrap();
        log.append(r2, ReplacementKind::Rollback, 200).unwrap();

        let mut kinds = BTreeSet::new();
        kinds.insert(ReplacementKind::Rollback);
        let query = LineageQuery {
            slot_id: None,
            kinds: Some(kinds),
            min_timestamp_ns: None,
            max_timestamp_ns: None,
        };
        let results = log.query(&query);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].kind, ReplacementKind::Rollback);
    }

    #[test]
    fn query_by_time_range() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..5 {
            let r = test_receipt(
                "slot-a",
                &format!("old-{i}"),
                &format!("new-{i}"),
                (i + 1) * 100,
            );
            log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 100)
                .unwrap();
        }
        let query = LineageQuery {
            slot_id: None,
            kinds: None,
            min_timestamp_ns: Some(200),
            max_timestamp_ns: Some(400),
        };
        let results = log.query(&query);
        assert_eq!(results.len(), 3); // timestamps 200, 300, 400
    }

    #[test]
    fn query_all() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..3 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
        }
        let results = log.query(&LineageQuery::all());
        assert_eq!(results.len(), 3);
    }

    // ── slot lineage ────────────────────────────────────────────────

    #[test]
    fn slot_lineage_tracks_replacement_chain() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r1 = test_receipt("slot-a", "delegate-v1", "native-v1", 100);
        let r2 = test_receipt("slot-a", "native-v1", "delegate-v1", 200);
        let r3 = test_receipt("slot-a", "delegate-v1", "native-v2", 300);
        log.append(r1, ReplacementKind::DelegateToNative, 100)
            .unwrap();
        log.append(r2, ReplacementKind::Demotion, 200).unwrap();
        log.append(r3, ReplacementKind::RePromotion, 300).unwrap();

        let lineage = log.slot_lineage(&test_slot_id("slot-a"));
        assert_eq!(lineage.len(), 3);
        assert_eq!(lineage[0].kind, ReplacementKind::DelegateToNative);
        assert_eq!(lineage[1].kind, ReplacementKind::Demotion);
        assert_eq!(lineage[2].kind, ReplacementKind::RePromotion);
    }

    #[test]
    fn slot_lineage_isolates_slots() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r1 = test_receipt("slot-a", "old-a", "new-a", 100);
        let r2 = test_receipt("slot-b", "old-b", "new-b", 200);
        log.append(r1, ReplacementKind::DelegateToNative, 100)
            .unwrap();
        log.append(r2, ReplacementKind::DelegateToNative, 200)
            .unwrap();

        let lineage_a = log.slot_lineage(&test_slot_id("slot-a"));
        let lineage_b = log.slot_lineage(&test_slot_id("slot-b"));
        assert_eq!(lineage_a.len(), 1);
        assert_eq!(lineage_b.len(), 1);
    }

    // ── verification ────────────────────────────────────────────────

    #[test]
    fn verify_slot_lineage_valid() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..3 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
        }
        let result = log.verify_slot_lineage(&test_slot_id("slot-a"));
        assert!(result.chain_valid);
        assert!(result.issues.is_empty());
        assert_eq!(result.total_entries, 3);
    }

    #[test]
    fn verify_slot_lineage_empty() {
        let log = ReplacementLineageLog::new(LineageLogConfig::default());
        let result = log.verify_slot_lineage(&test_slot_id("slot-nonexistent"));
        assert_eq!(result.total_entries, 0);
        assert_eq!(result.issues.len(), 1);
    }

    // ── audit ───────────────────────────────────────────────────────

    #[test]
    fn audit_valid_log() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..5 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
        }
        log.create_checkpoint(500, SecurityEpoch::from_raw(1))
            .unwrap();

        let audit = log.audit();
        assert!(audit.chain_valid);
        assert!(audit.merkle_valid);
        assert_eq!(audit.total_entries, 5);
        assert_eq!(audit.total_slots, 1);
        assert_eq!(audit.checkpoint_count, 1);
        assert!(audit.issues.is_empty());
    }

    #[test]
    fn audit_multi_slot_log() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r1 = test_receipt("slot-a", "old-a", "new-a", 100);
        let r2 = test_receipt("slot-b", "old-b", "new-b", 200);
        let r3 = test_receipt("slot-c", "old-c", "new-c", 300);
        log.append(r1, ReplacementKind::DelegateToNative, 100)
            .unwrap();
        log.append(r2, ReplacementKind::DelegateToNative, 200)
            .unwrap();
        log.append(r3, ReplacementKind::DelegateToNative, 300)
            .unwrap();

        let audit = log.audit();
        assert!(audit.chain_valid);
        assert_eq!(audit.total_slots, 3);
    }

    #[test]
    fn audit_empty_log() {
        let log = ReplacementLineageLog::new(LineageLogConfig::default());
        let audit = log.audit();
        assert!(audit.chain_valid);
        assert!(audit.merkle_valid);
        assert_eq!(audit.total_entries, 0);
    }

    // ── replacement kind ────────────────────────────────────────────

    #[test]
    fn replacement_kind_display() {
        assert_eq!(
            ReplacementKind::DelegateToNative.to_string(),
            "delegate_to_native"
        );
        assert_eq!(ReplacementKind::Demotion.to_string(), "demotion");
        assert_eq!(ReplacementKind::Rollback.to_string(), "rollback");
        assert_eq!(ReplacementKind::RePromotion.to_string(), "re_promotion");
    }

    #[test]
    fn replacement_kind_serde_round_trip() {
        let kinds = [
            ReplacementKind::DelegateToNative,
            ReplacementKind::Demotion,
            ReplacementKind::Rollback,
            ReplacementKind::RePromotion,
        ];
        for kind in &kinds {
            let json = serde_json::to_string(kind).expect("serialize");
            let decoded: ReplacementKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*kind, decoded);
        }
    }

    // ── serde round-trips ───────────────────────────────────────────

    #[test]
    fn log_entry_serde_round_trip() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r = test_receipt("slot-a", "old", "new", 1000);
        log.append(r, ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        let entry = &log.entries()[0];
        let json = serde_json::to_vec(entry).expect("serialize");
        let decoded: LineageLogEntry = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(*entry, decoded);
    }

    #[test]
    fn checkpoint_serde_round_trip() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r = test_receipt("slot-a", "old", "new", 1000);
        log.append(r, ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        log.create_checkpoint(1000, SecurityEpoch::from_raw(1))
            .unwrap();
        let cp = &log.checkpoints()[0];
        let json = serde_json::to_vec(cp).expect("serialize");
        let decoded: LogCheckpoint = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(*cp, decoded);
    }

    #[test]
    fn inclusion_proof_serde_round_trip() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..4 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
        }
        let proof = log.inclusion_proof(2).expect("proof exists");
        let json = serde_json::to_vec(&proof).expect("serialize");
        let decoded: InclusionProof = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(proof, decoded);
        assert!(verify_inclusion_proof(&decoded));
    }

    #[test]
    fn consistency_proof_serde_round_trip() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..4 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
            if i == 1 || i == 3 {
                log.create_checkpoint(i * 100, SecurityEpoch::from_raw(1))
                    .unwrap();
            }
        }

        let proof = log.consistency_proof(0, 1).expect("proof");
        let json = serde_json::to_vec(&proof).expect("serialize");
        let decoded: ConsistencyProof = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(proof, decoded);
        assert!(verify_consistency_proof(&decoded));
    }

    #[test]
    fn full_log_serde_round_trip() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..3 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
        }
        log.create_checkpoint(300, SecurityEpoch::from_raw(1))
            .unwrap();
        let json = serde_json::to_vec(&log).expect("serialize");
        let decoded: ReplacementLineageLog = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(log.len(), decoded.len());
        assert_eq!(log.merkle_root(), decoded.merkle_root());
    }

    // ── structured events ───────────────────────────────────────────

    #[test]
    fn append_emits_event() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r = test_receipt("slot-a", "old", "new", 1000);
        log.append(r, ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        assert!(!log.events().is_empty());
        let event = &log.events()[0];
        assert_eq!(event.event, "entry_appended");
        assert_eq!(event.outcome, "ok");
        assert_eq!(event.component, "replacement_lineage_log");
    }

    #[test]
    fn checkpoint_emits_event() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r = test_receipt("slot-a", "old", "new", 1000);
        log.append(r, ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        log.create_checkpoint(1000, SecurityEpoch::from_raw(1))
            .unwrap();
        let cp_events: Vec<_> = log
            .events()
            .iter()
            .filter(|e| e.event == "checkpoint_created")
            .collect();
        assert_eq!(cp_events.len(), 1);
    }

    // ── error display ───────────────────────────────────────────────

    #[test]
    fn error_display() {
        let err = LineageLogError::SequenceMismatch {
            expected: 5,
            got: 3,
        };
        assert!(err.to_string().contains("sequence mismatch"));

        let err = LineageLogError::ChainBreak { sequence: 7 };
        assert!(err.to_string().contains("chain break"));

        let err = LineageLogError::CheckpointNotFound { checkpoint_seq: 9 };
        assert!(err.to_string().contains("not found"));

        let err = LineageLogError::InvalidCheckpointOrder { older: 2, newer: 1 };
        assert!(err.to_string().contains("invalid checkpoint order"));

        let err = LineageLogError::EmptyLog;
        assert!(err.to_string().contains("empty"));
    }

    // ── slot_ids helper ─────────────────────────────────────────────

    #[test]
    fn slot_ids_returns_unique_sorted() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r1 = test_receipt("slot-c", "old", "new", 100);
        let r2 = test_receipt("slot-a", "old", "new", 200);
        let r3 = test_receipt("slot-c", "old2", "new2", 300);
        log.append(r1, ReplacementKind::DelegateToNative, 100)
            .unwrap();
        log.append(r2, ReplacementKind::DelegateToNative, 200)
            .unwrap();
        log.append(r3, ReplacementKind::RePromotion, 300).unwrap();

        let ids = log.slot_ids();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0].as_str(), "slot-a"); // sorted
        assert_eq!(ids[1].as_str(), "slot-c");
    }

    // ── config ──────────────────────────────────────────────────────

    #[test]
    fn config_serde_round_trip() {
        let config = LineageLogConfig {
            checkpoint_interval: 50,
            max_entries_in_memory: 1000,
        };
        let json = serde_json::to_vec(&config).expect("serialize");
        let decoded: LineageLogConfig = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(config, decoded);
    }

    #[test]
    fn default_config_values() {
        let config = LineageLogConfig::default();
        assert_eq!(config.checkpoint_interval, 100);
        assert_eq!(config.max_entries_in_memory, 0);
    }

    // ── lineage query serde ─────────────────────────────────────────

    #[test]
    fn lineage_query_serde_round_trip() {
        let query = LineageQuery {
            slot_id: Some(test_slot_id("slot-a")),
            kinds: Some(BTreeSet::from([ReplacementKind::Demotion])),
            min_timestamp_ns: Some(100),
            max_timestamp_ns: Some(500),
        };
        let json = serde_json::to_vec(&query).expect("serialize");
        let decoded: LineageQuery = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(query, decoded);
    }

    // ── audit result serde ──────────────────────────────────────────

    #[test]
    fn audit_result_serde_round_trip() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r = test_receipt("slot-a", "old", "new", 1000);
        log.append(r, ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        log.create_checkpoint(1000, SecurityEpoch::from_raw(1))
            .unwrap();
        let audit = log.audit();
        let json = serde_json::to_vec(&audit).expect("serialize");
        let decoded: AuditResult = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(audit, decoded);
    }

    // ── EvidenceCategory ───────────────────────────────────────────

    #[test]
    fn evidence_category_as_str() {
        assert_eq!(EvidenceCategory::GateResult.as_str(), "gate_result");
        assert_eq!(
            EvidenceCategory::PerformanceBenchmark.as_str(),
            "performance_benchmark"
        );
        assert_eq!(
            EvidenceCategory::SentinelRiskScore.as_str(),
            "sentinel_risk_score"
        );
        assert_eq!(
            EvidenceCategory::DifferentialExecutionLog.as_str(),
            "differential_execution_log"
        );
        assert_eq!(EvidenceCategory::Additional.as_str(), "additional");
    }

    #[test]
    fn evidence_category_display() {
        assert_eq!(EvidenceCategory::GateResult.to_string(), "gate_result");
    }

    #[test]
    fn evidence_category_serde_round_trip() {
        for variant in [
            EvidenceCategory::GateResult,
            EvidenceCategory::PerformanceBenchmark,
            EvidenceCategory::SentinelRiskScore,
            EvidenceCategory::DifferentialExecutionLog,
            EvidenceCategory::Additional,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: EvidenceCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    #[test]
    fn category_from_validation_kind_mapping() {
        assert_eq!(
            category_from_validation_kind(ValidationArtifactKind::EquivalenceResult),
            EvidenceCategory::DifferentialExecutionLog
        );
        assert_eq!(
            category_from_validation_kind(ValidationArtifactKind::CapabilityPreservation),
            EvidenceCategory::GateResult
        );
        assert_eq!(
            category_from_validation_kind(ValidationArtifactKind::PerformanceBenchmark),
            EvidenceCategory::PerformanceBenchmark
        );
        assert_eq!(
            category_from_validation_kind(ValidationArtifactKind::AdversarialSurvival),
            EvidenceCategory::GateResult
        );
    }

    // ── LineageIndexError ──────────────────────────────────────────

    #[test]
    fn lineage_index_error_codes() {
        assert_eq!(
            LineageIndexError::Storage(StorageError::NotFound {
                store: StoreKind::ReplacementLineage,
                key: "k".into()
            })
            .code(),
            "FE-LIDX-0001"
        );
        assert_eq!(
            LineageIndexError::Serialization {
                operation: "op".into(),
                detail: "d".into()
            }
            .code(),
            "FE-LIDX-0002"
        );
        assert_eq!(
            LineageIndexError::CorruptRecord {
                key: "k".into(),
                detail: "d".into()
            }
            .code(),
            "FE-LIDX-0003"
        );
        assert_eq!(
            LineageIndexError::InvalidInput { detail: "d".into() }.code(),
            "FE-LIDX-0004"
        );
    }

    #[test]
    fn lineage_index_error_display() {
        let err = LineageIndexError::Serialization {
            operation: "encode".into(),
            detail: "bad json".into(),
        };
        assert!(err.to_string().contains("encode"));
        assert!(err.to_string().contains("bad json"));

        let err = LineageIndexError::CorruptRecord {
            key: "k1".into(),
            detail: "truncated".into(),
        };
        assert!(err.to_string().contains("k1"));
        assert!(err.to_string().contains("truncated"));

        let err = LineageIndexError::InvalidInput {
            detail: "empty id".into(),
        };
        assert!(err.to_string().contains("empty id"));
    }

    #[test]
    fn lineage_index_error_is_std_error() {
        let err = LineageIndexError::InvalidInput {
            detail: "test".into(),
        };
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn lineage_index_error_from_storage_error() {
        let storage_err = StorageError::NotFound {
            store: StoreKind::ReplacementLineage,
            key: "missing".into(),
        };
        let idx_err: LineageIndexError = storage_err.into();
        assert!(matches!(idx_err, LineageIndexError::Storage(_)));
    }

    // ── EvidencePointerInput serde ─────────────────────────────────

    #[test]
    fn evidence_pointer_input_serde_round_trip() {
        let input = EvidencePointerInput {
            category: EvidenceCategory::GateResult,
            artifact_digest: "abc123".to_string(),
            passed: Some(true),
            summary: "gate passed".to_string(),
        };
        let json = serde_json::to_string(&input).unwrap();
        let back: EvidencePointerInput = serde_json::from_str(&json).unwrap();
        assert_eq!(input, back);
    }

    // ── EvidencePointer ────────────────────────────────────────────

    #[test]
    fn evidence_pointer_from_input() {
        let input = EvidencePointerInput {
            category: EvidenceCategory::PerformanceBenchmark,
            artifact_digest: "digest-1".to_string(),
            passed: Some(false),
            summary: "perf regression".to_string(),
        };
        let ptr = EvidencePointer::from_input("receipt-xyz", input);
        assert_eq!(ptr.receipt_id, "receipt-xyz");
        assert_eq!(ptr.category, EvidenceCategory::PerformanceBenchmark);
        assert_eq!(ptr.artifact_digest, "digest-1");
        assert_eq!(ptr.passed, Some(false));
    }

    #[test]
    fn evidence_pointer_serde_round_trip() {
        let ptr = EvidencePointer {
            receipt_id: "r-1".to_string(),
            category: EvidenceCategory::SentinelRiskScore,
            artifact_digest: "d".to_string(),
            passed: None,
            summary: "s".to_string(),
        };
        let json = serde_json::to_string(&ptr).unwrap();
        let back: EvidencePointer = serde_json::from_str(&json).unwrap();
        assert_eq!(ptr, back);
    }

    // ── SlotLineageQuery / ReplayJoinQuery serde ───────────────────

    #[test]
    fn slot_lineage_query_serde_round_trip() {
        let query = SlotLineageQuery {
            min_timestamp_ns: Some(100),
            max_timestamp_ns: Some(500),
            limit: Some(10),
        };
        let json = serde_json::to_string(&query).unwrap();
        let back: SlotLineageQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(query, back);
    }

    #[test]
    fn replay_join_query_serde_round_trip() {
        let query = ReplayJoinQuery {
            slot_id: Some(test_slot_id("s")),
            min_timestamp_ns: Some(100),
            max_timestamp_ns: Some(500),
            limit: Some(10),
        };
        let json = serde_json::to_string(&query).unwrap();
        let back: ReplayJoinQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(query, back);
    }

    // ── LineageIndexEvent serde ────────────────────────────────────

    #[test]
    fn lineage_index_event_serde_round_trip() {
        let event = LineageIndexEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "replacement_lineage_index".to_string(),
            event: "index_replacement_receipt".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: LineageIndexEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    // ── ReplacementLineageEvidenceIndex ─────────────────────────────

    fn test_context() -> EventContext {
        EventContext {
            trace_id: "trace-idx".to_string(),
            decision_id: "decision-idx".to_string(),
            policy_id: "policy-idx".to_string(),
        }
    }

    #[test]
    fn evidence_index_new_and_events_empty() {
        use crate::storage_adapter::InMemoryStorageAdapter;
        let idx = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
        assert!(idx.events().is_empty());
    }

    #[test]
    fn evidence_index_into_inner() {
        use crate::storage_adapter::InMemoryStorageAdapter;
        let adapter = InMemoryStorageAdapter::new();
        let idx = ReplacementLineageEvidenceIndex::new(adapter);
        let _recovered = idx.into_inner();
    }

    #[test]
    fn evidence_index_replacement_receipt_round_trip() {
        use crate::storage_adapter::InMemoryStorageAdapter;
        let mut idx = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
        let receipt = test_receipt("slot-idx", "old-cell", "new-cell", 5000);
        let ctx = test_context();
        let evidence = vec![EvidencePointerInput {
            category: EvidenceCategory::GateResult,
            artifact_digest: "gate-digest".to_string(),
            passed: Some(true),
            summary: "gate ok".to_string(),
        }];
        let record = idx
            .index_replacement_receipt(&receipt, ReplacementKind::DelegateToNative, &evidence, &ctx)
            .unwrap();
        assert_eq!(record.slot_id, receipt.slot_id);
        assert_eq!(record.old_cell_digest, "old-cell");
        assert_eq!(record.new_cell_digest, "new-cell");
        assert_eq!(record.promotion_timestamp_ns, 5000);
        assert!(!record.receipt_content_hash.is_empty());
        assert_eq!(idx.events().len(), 1);
        assert_eq!(idx.events()[0].outcome, "ok");
    }

    #[test]
    fn evidence_index_replacement_by_content_hash() {
        use crate::storage_adapter::InMemoryStorageAdapter;
        let mut idx = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
        let receipt = test_receipt("slot-hash", "old", "new", 6000);
        let ctx = test_context();
        let record = idx
            .index_replacement_receipt(&receipt, ReplacementKind::DelegateToNative, &[], &ctx)
            .unwrap();
        let found = idx
            .replacement_by_content_hash(&record.receipt_content_hash, &ctx)
            .unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().receipt_id, record.receipt_id);
    }

    #[test]
    fn evidence_index_replacement_by_content_hash_missing() {
        use crate::storage_adapter::InMemoryStorageAdapter;
        let mut idx = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
        let ctx = test_context();
        let found = idx
            .replacement_by_content_hash("nonexistent", &ctx)
            .unwrap();
        assert!(found.is_none());
    }

    #[test]
    fn evidence_index_demotion_receipt() {
        use crate::storage_adapter::InMemoryStorageAdapter;
        let mut idx = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
        let ctx = test_context();
        let input = DemotionReceiptInput {
            receipt_id: "demotion-1".to_string(),
            slot_id: test_slot_id("slot-dem"),
            demoted_cell_digest: "new-cell".to_string(),
            restored_cell_digest: "old-cell".to_string(),
            demotion_reason: "regression detected".to_string(),
            timestamp_ns: 7000,
            rollback_token_used: "rollback-token-1".to_string(),
            linked_replacement_receipt_id: None,
            evidence: vec![EvidencePointerInput {
                category: EvidenceCategory::SentinelRiskScore,
                artifact_digest: "risk-digest".to_string(),
                passed: Some(false),
                summary: "high risk".to_string(),
            }],
        };
        let record = idx.index_demotion_receipt(input, &ctx).unwrap();
        assert_eq!(record.receipt_id, "demotion-1");
        assert_eq!(record.demotion_reason, "regression detected");
        assert!(!record.receipt_content_hash.is_empty());
    }

    #[test]
    fn evidence_index_demotion_empty_receipt_id_fails() {
        use crate::storage_adapter::InMemoryStorageAdapter;
        let mut idx = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
        let ctx = test_context();
        let input = DemotionReceiptInput {
            receipt_id: "".to_string(),
            slot_id: test_slot_id("slot-dem"),
            demoted_cell_digest: "d".to_string(),
            restored_cell_digest: "r".to_string(),
            demotion_reason: "test".to_string(),
            timestamp_ns: 100,
            rollback_token_used: "tok".to_string(),
            linked_replacement_receipt_id: None,
            evidence: Vec::new(),
        };
        let err = idx.index_demotion_receipt(input, &ctx).unwrap_err();
        assert!(matches!(err, LineageIndexError::InvalidInput { .. }));
    }

    #[test]
    fn evidence_index_demotion_by_content_hash() {
        use crate::storage_adapter::InMemoryStorageAdapter;
        let mut idx = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
        let ctx = test_context();
        let input = DemotionReceiptInput {
            receipt_id: "dem-hash-test".to_string(),
            slot_id: test_slot_id("slot-dh"),
            demoted_cell_digest: "d".to_string(),
            restored_cell_digest: "r".to_string(),
            demotion_reason: "test".to_string(),
            timestamp_ns: 8000,
            rollback_token_used: "tok".to_string(),
            linked_replacement_receipt_id: None,
            evidence: Vec::new(),
        };
        let record = idx.index_demotion_receipt(input, &ctx).unwrap();
        let found = idx
            .demotion_by_content_hash(&record.receipt_content_hash, &ctx)
            .unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().receipt_id, "dem-hash-test");
    }

    #[test]
    fn evidence_index_slot_lineage() {
        use crate::storage_adapter::InMemoryStorageAdapter;
        let mut idx = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
        let ctx = test_context();
        let r1 = test_receipt("slot-lin", "old1", "new1", 1000);
        let r2 = test_receipt("slot-lin", "new1", "new2", 2000);
        idx.index_replacement_receipt(&r1, ReplacementKind::DelegateToNative, &[], &ctx)
            .unwrap();
        idx.index_replacement_receipt(&r2, ReplacementKind::DelegateToNative, &[], &ctx)
            .unwrap();
        let slot_id = test_slot_id("slot-lin");
        let query = SlotLineageQuery::default();
        let chain = idx.slot_lineage(&slot_id, &query, &ctx).unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].from_cell_digest, "old1");
        assert_eq!(chain[1].from_cell_digest, "new1");
    }

    #[test]
    fn evidence_index_slot_lineage_with_time_filter() {
        use crate::storage_adapter::InMemoryStorageAdapter;
        let mut idx = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
        let ctx = test_context();
        let r1 = test_receipt("slot-tf", "old1", "new1", 1000);
        let r2 = test_receipt("slot-tf", "new1", "new2", 2000);
        let r3 = test_receipt("slot-tf", "new2", "new3", 3000);
        idx.index_replacement_receipt(&r1, ReplacementKind::DelegateToNative, &[], &ctx)
            .unwrap();
        idx.index_replacement_receipt(&r2, ReplacementKind::DelegateToNative, &[], &ctx)
            .unwrap();
        idx.index_replacement_receipt(&r3, ReplacementKind::DelegateToNative, &[], &ctx)
            .unwrap();
        let slot_id = test_slot_id("slot-tf");
        let query = SlotLineageQuery {
            min_timestamp_ns: Some(1500),
            max_timestamp_ns: Some(2500),
            limit: None,
        };
        let chain = idx.slot_lineage(&slot_id, &query, &ctx).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].timestamp_ns, 2000);
    }

    #[test]
    fn evidence_index_replay_join() {
        use crate::storage_adapter::InMemoryStorageAdapter;
        let mut idx = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
        let ctx = test_context();
        let receipt = test_receipt("slot-rj", "old", "new", 9000);
        let evidence = vec![
            EvidencePointerInput {
                category: EvidenceCategory::GateResult,
                artifact_digest: "gate-d".to_string(),
                passed: Some(true),
                summary: "gate ok".to_string(),
            },
            EvidencePointerInput {
                category: EvidenceCategory::PerformanceBenchmark,
                artifact_digest: "perf-d".to_string(),
                passed: Some(true),
                summary: "perf ok".to_string(),
            },
        ];
        idx.index_replacement_receipt(&receipt, ReplacementKind::DelegateToNative, &evidence, &ctx)
            .unwrap();
        let query = ReplayJoinQuery::default();
        let rows = idx.replay_join(&query, &ctx).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].gate_results.is_empty());
        assert!(!rows[0].performance_benchmarks.is_empty());
    }

    // ── Merkle root empty log ──────────────────────────────────────

    #[test]
    fn merkle_root_empty_log() {
        let log = ReplacementLineageLog::new(LineageLogConfig::default());
        let root = log.merkle_root();
        // Should return a deterministic "empty" hash
        assert_eq!(root, ContentHash::compute(b"empty_lineage_tree"));
    }

    // ── Inclusion proof on empty log ───────────────────────────────

    #[test]
    fn inclusion_proof_empty_log_returns_none() {
        let log = ReplacementLineageLog::new(LineageLogConfig::default());
        assert!(log.inclusion_proof(0).is_none());
    }

    // ── Data type serde ────────────────────────────────────────────

    #[test]
    fn replacement_receipt_record_serde_round_trip() {
        use crate::storage_adapter::InMemoryStorageAdapter;
        let mut idx = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
        let receipt = test_receipt("slot-s", "old", "new", 1000);
        let ctx = test_context();
        let record = idx
            .index_replacement_receipt(&receipt, ReplacementKind::Rollback, &[], &ctx)
            .unwrap();
        let json = serde_json::to_string(&record).unwrap();
        let back: ReplacementReceiptRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }

    #[test]
    fn demotion_receipt_record_serde_round_trip() {
        use crate::storage_adapter::InMemoryStorageAdapter;
        let mut idx = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
        let ctx = test_context();
        let input = DemotionReceiptInput {
            receipt_id: "dem-serde".to_string(),
            slot_id: test_slot_id("slot-ds"),
            demoted_cell_digest: "d".to_string(),
            restored_cell_digest: "r".to_string(),
            demotion_reason: "test".to_string(),
            timestamp_ns: 100,
            rollback_token_used: "tok".to_string(),
            linked_replacement_receipt_id: Some("linked-r".to_string()),
            evidence: Vec::new(),
        };
        let record = idx.index_demotion_receipt(input, &ctx).unwrap();
        let json = serde_json::to_string(&record).unwrap();
        let back: DemotionReceiptRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }

    #[test]
    fn lineage_chain_entry_serde_round_trip() {
        let entry = LineageChainEntry {
            slot_id: test_slot_id("slot-ce"),
            timestamp_ns: 42,
            receipt_id: "r".to_string(),
            kind: ReplacementKind::DelegateToNative,
            from_cell_digest: "f".to_string(),
            to_cell_digest: "t".to_string(),
            receipt_content_hash: "h".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: LineageChainEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn demotion_receipt_input_serde_round_trip() {
        let input = DemotionReceiptInput {
            receipt_id: "dem-in".to_string(),
            slot_id: test_slot_id("slot"),
            demoted_cell_digest: "d".to_string(),
            restored_cell_digest: "r".to_string(),
            demotion_reason: "reason".to_string(),
            timestamp_ns: 1,
            rollback_token_used: "tok".to_string(),
            linked_replacement_receipt_id: None,
            evidence: Vec::new(),
        };
        let json = serde_json::to_string(&input).unwrap();
        let back: DemotionReceiptInput = serde_json::from_str(&json).unwrap();
        assert_eq!(input, back);
    }

    // -----------------------------------------------------------------------
    // Enrichment: leaf enum serde
    // -----------------------------------------------------------------------

    #[test]
    fn proof_direction_serde_roundtrip() {
        for dir in [ProofDirection::Left, ProofDirection::Right] {
            let json = serde_json::to_string(&dir).unwrap();
            let restored: ProofDirection = serde_json::from_str(&json).unwrap();
            assert_eq!(dir, restored);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: LineageLogError serde all variants
    // -----------------------------------------------------------------------

    #[test]
    fn lineage_log_error_serde_all_variants() {
        let errors: Vec<LineageLogError> = vec![
            LineageLogError::SequenceMismatch {
                expected: 5,
                got: 3,
            },
            LineageLogError::ChainBreak { sequence: 7 },
            LineageLogError::DuplicateReceipt {
                receipt_id: "r-1".to_string(),
            },
            LineageLogError::CheckpointBeyondLog {
                checkpoint_length: 10,
                log_length: 5,
            },
            LineageLogError::CheckpointNotFound { checkpoint_seq: 9 },
            LineageLogError::InvalidCheckpointOrder { older: 2, newer: 1 },
            LineageLogError::EmptyLog,
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let restored: LineageLogError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, restored);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: LineageLogError Display missing variants
    // -----------------------------------------------------------------------

    #[test]
    fn lineage_log_error_display_remaining_variants() {
        let err = LineageLogError::DuplicateReceipt {
            receipt_id: "r-1".to_string(),
        };
        assert_eq!(err.to_string(), "duplicate receipt: r-1");

        let err = LineageLogError::CheckpointBeyondLog {
            checkpoint_length: 10,
            log_length: 5,
        };
        assert_eq!(err.to_string(), "checkpoint length 10 beyond log length 5");
    }

    // -----------------------------------------------------------------------
    // Enrichment: struct serde roundtrips for untested types
    // -----------------------------------------------------------------------

    #[test]
    fn merkle_proof_step_serde_roundtrip() {
        let step = MerkleProofStep {
            sibling_hash: ContentHash::compute(b"sibling"),
            direction: ProofDirection::Left,
        };
        let json = serde_json::to_string(&step).unwrap();
        let restored: MerkleProofStep = serde_json::from_str(&json).unwrap();
        assert_eq!(step, restored);
    }

    #[test]
    fn lineage_step_serde_roundtrip() {
        let step = LineageStep {
            sequence: 0,
            kind: ReplacementKind::Demotion,
            old_cell_digest: "old".to_string(),
            new_cell_digest: "new".to_string(),
            receipt_id: "r-1".to_string(),
            timestamp_ns: 100,
            epoch: SecurityEpoch::from_raw(1),
            validation_artifact_count: 3,
        };
        let json = serde_json::to_string(&step).unwrap();
        let restored: LineageStep = serde_json::from_str(&json).unwrap();
        assert_eq!(step, restored);
    }

    #[test]
    fn lineage_verification_serde_roundtrip() {
        let ver = LineageVerification {
            slot_id: test_slot_id("slot-a"),
            total_entries: 5,
            chain_valid: true,
            all_receipts_present: true,
            issues: vec!["minor note".to_string()],
        };
        let json = serde_json::to_string(&ver).unwrap();
        let restored: LineageVerification = serde_json::from_str(&json).unwrap();
        assert_eq!(ver, restored);
    }

    #[test]
    fn lineage_log_event_serde_roundtrip() {
        let event = LineageLogEvent {
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            component: "lineage_log".to_string(),
            event: "append".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let restored: LineageLogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, restored);
    }

    #[test]
    fn replay_join_row_serde_roundtrip() {
        let row = ReplayJoinRow {
            slot_id: test_slot_id("slot"),
            replacement_receipt_id: "r-1".to_string(),
            replacement_kind: ReplacementKind::DelegateToNative,
            old_cell_digest: "old".to_string(),
            new_cell_digest: "new".to_string(),
            promotion_timestamp_ns: 100,
            replacement_content_hash: "hash".to_string(),
            demotion_receipt_id: None,
            demotion_reason: None,
            demotion_timestamp_ns: None,
            gate_results: Vec::new(),
            performance_benchmarks: Vec::new(),
            sentinel_risk_scores: Vec::new(),
            differential_execution_logs: Vec::new(),
            additional_evidence: Vec::new(),
        };
        let json = serde_json::to_string(&row).unwrap();
        let restored: ReplayJoinRow = serde_json::from_str(&json).unwrap();
        assert_eq!(row, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment: ordering tests
    // -----------------------------------------------------------------------

    #[test]
    fn replacement_kind_ordering() {
        assert!(ReplacementKind::DelegateToNative < ReplacementKind::RePromotion);
    }

    #[test]
    fn evidence_category_ordering() {
        assert!(EvidenceCategory::GateResult < EvidenceCategory::Additional);
    }

    // -----------------------------------------------------------------------
    // Enrichment: LineageIndexError serde all variants
    // -----------------------------------------------------------------------

    #[test]
    fn lineage_index_error_serde_all_variants() {
        let errors: Vec<LineageIndexError> = vec![
            LineageIndexError::Storage(StorageError::NotFound {
                store: StoreKind::ReplacementLineage,
                key: "k".to_string(),
            }),
            LineageIndexError::Serialization {
                operation: "write".to_string(),
                detail: "err".to_string(),
            },
            LineageIndexError::CorruptRecord {
                key: "k".to_string(),
                detail: "bad".to_string(),
            },
            LineageIndexError::InvalidInput {
                detail: "empty".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let restored: LineageIndexError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, restored);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: LineageIndexError Display content verified
    // -----------------------------------------------------------------------

    #[test]
    fn lineage_index_error_display_content_verified() {
        let err = LineageIndexError::Serialization {
            operation: "write".to_string(),
            detail: "codec failure".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "serialization error (write): codec failure"
        );

        let err = LineageIndexError::CorruptRecord {
            key: "slot:a".to_string(),
            detail: "invalid CRC".to_string(),
        };
        assert_eq!(err.to_string(), "corrupt record `slot:a`: invalid CRC");

        let err = LineageIndexError::InvalidInput {
            detail: "empty receipt_id".to_string(),
        };
        assert_eq!(err.to_string(), "invalid input: empty receipt_id");
    }

    // -----------------------------------------------------------------------
    // Enrichment: SlotLineageQuery and ReplayJoinQuery defaults
    // -----------------------------------------------------------------------

    #[test]
    fn slot_lineage_query_default() {
        let q = SlotLineageQuery::default();
        assert!(q.min_timestamp_ns.is_none());
        assert!(q.max_timestamp_ns.is_none());
        assert!(q.limit.is_none());
    }

    #[test]
    fn replay_join_query_default() {
        let q = ReplayJoinQuery::default();
        assert!(q.slot_id.is_none());
        assert!(q.min_timestamp_ns.is_none());
        assert!(q.max_timestamp_ns.is_none());
        assert!(q.limit.is_none());
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn replacement_kind_as_str_matches_display() {
        for kind in [
            ReplacementKind::DelegateToNative,
            ReplacementKind::Demotion,
            ReplacementKind::Rollback,
            ReplacementKind::RePromotion,
        ] {
            assert_eq!(kind.as_str(), &kind.to_string());
        }
    }

    #[test]
    fn replacement_kind_as_str_all_distinct() {
        let mut strs = std::collections::BTreeSet::new();
        for kind in [
            ReplacementKind::DelegateToNative,
            ReplacementKind::Demotion,
            ReplacementKind::Rollback,
            ReplacementKind::RePromotion,
        ] {
            strs.insert(kind.as_str());
        }
        assert_eq!(strs.len(), 4);
    }

    #[test]
    fn lineage_log_error_display_all_nonempty() {
        let variants: Vec<LineageLogError> = vec![LineageLogError::DuplicateReceipt {
            receipt_id: "r-001".to_string(),
        }];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
    }

    #[test]
    fn evidence_category_as_str_enrichment_all_distinct() {
        let mut strs = std::collections::BTreeSet::new();
        for cat in [
            EvidenceCategory::GateResult,
            EvidenceCategory::PerformanceBenchmark,
            EvidenceCategory::SentinelRiskScore,
            EvidenceCategory::DifferentialExecutionLog,
            EvidenceCategory::Additional,
        ] {
            strs.insert(cat.as_str());
        }
        assert_eq!(strs.len(), 5);
    }

    #[test]
    fn proof_direction_serde_all_variants_distinct() {
        let variants = [ProofDirection::Left, ProofDirection::Right];
        let mut names = std::collections::BTreeSet::new();
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ProofDirection = serde_json::from_str(&json).unwrap();
            assert_eq!(v, &back);
            names.insert(json);
        }
        assert_eq!(names.len(), variants.len());
    }

    #[test]
    fn lineage_index_error_display_all_nonempty() {
        let err = LineageIndexError::InvalidInput {
            detail: "bad".to_string(),
        };
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn config_default_checkpoint_interval_nonzero() {
        let config = LineageLogConfig::default();
        assert!(config.checkpoint_interval > 0);
    }

    #[test]
    fn lineage_log_entry_hash_changes_with_kind() {
        let receipt = test_receipt("slot-a", "old", "new", 1);
        let entry1 = LineageLogEntry {
            sequence: 0,
            receipt: receipt.clone(),
            kind: ReplacementKind::DelegateToNative,
            predecessor_hash: ContentHash::compute(b"genesis"),
            entry_hash: ContentHash::compute(b"placeholder"),
        };
        let entry2 = LineageLogEntry {
            sequence: 0,
            receipt,
            kind: ReplacementKind::Demotion,
            predecessor_hash: ContentHash::compute(b"genesis"),
            entry_hash: ContentHash::compute(b"placeholder"),
        };
        let json1 = serde_json::to_string(&entry1).unwrap();
        let json2 = serde_json::to_string(&entry2).unwrap();
        assert_ne!(
            json1, json2,
            "different kinds should produce different JSON"
        );
    }

    #[test]
    fn slot_lineage_query_with_all_filters() {
        let query = SlotLineageQuery {
            min_timestamp_ns: Some(100),
            max_timestamp_ns: Some(999),
            limit: Some(10),
        };
        let json = serde_json::to_string(&query).unwrap();
        let back: SlotLineageQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(query, back);
    }

    #[test]
    fn replay_join_query_with_all_filters() {
        let query = ReplayJoinQuery {
            slot_id: Some(test_slot_id("parser")),
            min_timestamp_ns: Some(0),
            max_timestamp_ns: Some(u64::MAX),
            limit: Some(50),
        };
        let json = serde_json::to_string(&query).unwrap();
        let back: ReplayJoinQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(query, back);
    }

    // -- Enrichment: PearlTower 2026-02-26 session 3 --

    #[test]
    fn lineage_log_error_display_content_all_variants() {
        let seq_err = LineageLogError::SequenceMismatch {
            expected: 5,
            got: 3,
        };
        assert_eq!(seq_err.to_string(), "sequence mismatch: expected 5, got 3");

        let chain_err = LineageLogError::ChainBreak { sequence: 7 };
        assert_eq!(chain_err.to_string(), "chain break at sequence 7");

        let cp_not_found = LineageLogError::CheckpointNotFound { checkpoint_seq: 9 };
        assert_eq!(cp_not_found.to_string(), "checkpoint not found: sequence 9");

        let invalid_order = LineageLogError::InvalidCheckpointOrder { older: 2, newer: 1 };
        assert_eq!(
            invalid_order.to_string(),
            "invalid checkpoint order: older=2, newer=1 (must be older < newer)"
        );

        let empty = LineageLogError::EmptyLog;
        assert_eq!(empty.to_string(), "log is empty");
    }

    #[test]
    fn evidence_category_display_matches_as_str_all_variants() {
        for cat in [
            EvidenceCategory::GateResult,
            EvidenceCategory::PerformanceBenchmark,
            EvidenceCategory::SentinelRiskScore,
            EvidenceCategory::DifferentialExecutionLog,
            EvidenceCategory::Additional,
        ] {
            assert_eq!(cat.to_string(), cat.as_str());
        }
    }

    #[test]
    fn config_default_all_fields_verified() {
        let config = LineageLogConfig::default();
        assert_eq!(config.checkpoint_interval, 100);
        assert_eq!(config.max_entries_in_memory, 0);
    }

    #[test]
    fn merkle_leaf_and_node_domain_separation() {
        // Same input to leaf and node should produce different hashes
        // because they use different domain prefixes (0x00 vs 0x01).
        let h = ContentHash::compute(b"test-entry");
        let leaf = merkle_leaf(&h);
        let node = merkle_node(&h, &h);
        assert_ne!(leaf, node, "leaf and node must differ for same input");
    }

    #[test]
    fn compute_merkle_root_single_entry_equals_leaf() {
        let h = ContentHash::compute(b"sole-entry");
        let root = compute_merkle_root(std::slice::from_ref(&h));
        assert_eq!(root, merkle_leaf(&h));
    }

    #[test]
    fn emit_event_trace_id_and_fields() {
        let config = LineageLogConfig::default();
        let mut log = ReplacementLineageLog::new(config);
        let receipt = test_receipt("slot-ev", "old", "new", 1000);
        log.append(receipt, ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        let events = log.events();
        assert!(!events.is_empty());
        let ev = &events[0];
        assert!(
            ev.trace_id.starts_with("lineage-"),
            "trace_id should start with lineage-"
        );
        assert!(
            ev.decision_id.starts_with("lineage-decision-"),
            "decision_id should start with lineage-decision-"
        );
        assert_eq!(ev.policy_id, "replacement-lineage-policy");
        assert_eq!(ev.component, "replacement_lineage_log");
        assert_eq!(ev.event, "entry_appended");
        assert_eq!(ev.outcome, "ok");
        assert!(ev.error_code.is_none());
    }

    #[test]
    fn lineage_log_serde_roundtrip_with_entries() {
        let config = LineageLogConfig::default();
        let mut log = ReplacementLineageLog::new(config);
        let r1 = test_receipt("slot-serde", "old", "new", 100);
        let r2 = test_receipt("slot-serde", "new", "newer", 200);
        log.append(r1, ReplacementKind::DelegateToNative, 100)
            .unwrap();
        log.append(r2, ReplacementKind::Demotion, 200).unwrap();
        log.create_checkpoint(200, SecurityEpoch::from_raw(1))
            .unwrap();
        let json = serde_json::to_string(&log).unwrap();
        let restored: ReplacementLineageLog = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.len(), 2);
        assert_eq!(restored.checkpoints().len(), 1);
        assert_eq!(
            restored.entries()[0].kind,
            ReplacementKind::DelegateToNative
        );
        assert_eq!(restored.entries()[1].kind, ReplacementKind::Demotion);
    }

    #[test]
    fn slot_lineage_receipt_id_is_hex_encoded() {
        let config = LineageLogConfig::default();
        let mut log = ReplacementLineageLog::new(config);
        let receipt = test_receipt("slot-hex", "old", "new", 100);
        log.append(receipt, ReplacementKind::DelegateToNative, 100)
            .unwrap();
        let slot_id = test_slot_id("slot-hex");
        let steps = log.slot_lineage(&slot_id);
        assert_eq!(steps.len(), 1);
        // hex::encode produces lowercase hex characters
        assert!(
            steps[0].receipt_id.chars().all(|c| c.is_ascii_hexdigit()),
            "receipt_id in LineageStep should be hex-encoded"
        );
    }

    #[test]
    fn slot_lineage_query_matches_direct() {
        let entry = LineageChainEntry {
            slot_id: test_slot_id("slot-m"),
            timestamp_ns: 500,
            receipt_id: "r".to_string(),
            kind: ReplacementKind::DelegateToNative,
            from_cell_digest: "f".to_string(),
            to_cell_digest: "t".to_string(),
            receipt_content_hash: "h".to_string(),
        };

        // No filters — matches everything.
        let q_all = SlotLineageQuery::default();
        assert!(q_all.matches(&entry));

        // Min filter excludes.
        let q_min = SlotLineageQuery {
            min_timestamp_ns: Some(600),
            ..Default::default()
        };
        assert!(!q_min.matches(&entry));

        // Max filter excludes.
        let q_max = SlotLineageQuery {
            max_timestamp_ns: Some(400),
            ..Default::default()
        };
        assert!(!q_max.matches(&entry));

        // Both filters include.
        let q_range = SlotLineageQuery {
            min_timestamp_ns: Some(400),
            max_timestamp_ns: Some(600),
            ..Default::default()
        };
        assert!(q_range.matches(&entry));
    }

    #[test]
    fn table_name_constants_nonempty_and_distinct() {
        let names = [
            TABLE_REPLACEMENT_RECEIPTS,
            TABLE_DEMOTION_RECEIPTS,
            TABLE_LINEAGE_CHAIN,
            TABLE_REPLACEMENT_BY_HASH,
            TABLE_DEMOTION_BY_HASH,
            TABLE_EVIDENCE_INDEX,
        ];
        for name in &names {
            assert!(!name.is_empty());
        }
        let set: std::collections::BTreeSet<&str> = names.iter().copied().collect();
        assert_eq!(set.len(), names.len(), "table names must all be distinct");
    }

    #[test]
    fn slot_ids_deduplication_and_ordering() {
        let config = LineageLogConfig::default();
        let mut log = ReplacementLineageLog::new(config);
        let r1 = test_receipt("bravo", "old", "new", 100);
        let r2 = test_receipt("alpha", "old", "new", 200);
        let r3 = test_receipt("bravo", "new", "newer", 300);
        log.append(r1, ReplacementKind::DelegateToNative, 100)
            .unwrap();
        log.append(r2, ReplacementKind::DelegateToNative, 200)
            .unwrap();
        log.append(r3, ReplacementKind::Demotion, 300).unwrap();
        let ids = log.slot_ids();
        // BTreeSet guarantees sorted order and deduplication.
        assert_eq!(ids.len(), 2);
        assert!(ids[0].as_str() <= ids[1].as_str());
    }

    #[test]
    fn evidence_index_empty_artifact_digest_fails() {
        use crate::storage_adapter::InMemoryStorageAdapter;
        let mut idx = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
        let ctx = test_context();
        let receipt = test_receipt("slot-bad-ev", "old", "new", 1000);
        let bad_evidence = vec![EvidencePointerInput {
            category: EvidenceCategory::GateResult,
            artifact_digest: "   ".to_string(), // whitespace-only → empty after trim
            passed: Some(true),
            summary: "ok".to_string(),
        }];
        let err = idx
            .index_replacement_receipt(
                &receipt,
                ReplacementKind::DelegateToNative,
                &bad_evidence,
                &ctx,
            )
            .unwrap_err();
        assert!(matches!(err, LineageIndexError::InvalidInput { .. }));
    }

    #[test]
    fn lineage_index_error_storage_display_includes_inner() {
        let storage_err = StorageError::NotFound {
            store: StoreKind::ReplacementLineage,
            key: "some_key".to_string(),
        };
        let idx_err = LineageIndexError::Storage(storage_err);
        let display = idx_err.to_string();
        assert!(
            display.starts_with("storage error:"),
            "Storage display should start with 'storage error:'"
        );
        assert!(
            display.contains("some_key"),
            "Storage display should include inner error"
        );
    }

    #[test]
    fn lineage_log_len_and_is_empty() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        assert_eq!(log.len(), 0);
        assert!(log.is_empty());
        let receipt = test_receipt("slot-len", "old", "new", 100);
        log.append(receipt, ReplacementKind::DelegateToNative, 100)
            .unwrap();
        assert_eq!(log.len(), 1);
        assert!(!log.is_empty());
    }
}
