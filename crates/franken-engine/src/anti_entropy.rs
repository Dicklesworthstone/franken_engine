//! O(Delta) anti-entropy reconciliation for distributed object sets
//! using Invertible Bloom Lookup Tables (IBLT).
//!
//! Nodes exchange compact IBLT sketches to efficiently identify
//! discrepancies proportional to the actual difference (O(|Delta|)),
//! not the full set size. Supports revocation events, checkpoint
//! markers, and evidence entries.
//!
//! When the IBLT cannot peel (too many differences), the protocol
//! falls back to a deterministic full-state reconciliation.
//!
//! Plan references: Section 10.11 item 30, 9G.10 (anti-entropy +
//! proof-carrying recovery), Top-10 #5, #10.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

/// Symmetric difference: `(local_only, remote_only)` keyed by 32-byte content hash.
pub type SymmetricDiff = (Vec<[u8; 32]>, Vec<[u8; 32]>);

// ---------------------------------------------------------------------------
// ObjectType — types of reconciled objects
// ---------------------------------------------------------------------------

/// Types of objects subject to anti-entropy reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ReconcileObjectType {
    /// Revocation issuance and propagation records.
    RevocationEvent,
    /// Policy checkpoint and decision markers.
    CheckpointMarker,
    /// Evidence-ledger entries.
    EvidenceEntry,
}

impl fmt::Display for ReconcileObjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RevocationEvent => f.write_str("revocation_event"),
            Self::CheckpointMarker => f.write_str("checkpoint_marker"),
            Self::EvidenceEntry => f.write_str("evidence_entry"),
        }
    }
}

// ---------------------------------------------------------------------------
// ObjectId — content-addressed identity for reconciled objects
// ---------------------------------------------------------------------------

/// Content-addressed identity for a reconciled object.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObjectId {
    /// Content hash (Tier 2) of the object.
    pub content_hash: ContentHash,
    /// Object type.
    pub object_type: ReconcileObjectType,
    /// Epoch in which the object was created.
    pub epoch: SecurityEpoch,
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}@{}",
            self.object_type, self.content_hash, self.epoch
        )
    }
}

// ---------------------------------------------------------------------------
// IBLT — Invertible Bloom Lookup Table
// ---------------------------------------------------------------------------

/// A single IBLT cell.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IbltCell {
    /// Count of items hashing to this cell.
    pub count: i64,
    /// XOR of all key hashes.
    pub key_hash_xor: [u8; 32],
    /// XOR of all key checksums (for verification).
    pub checksum_xor: u32,
}

impl IbltCell {
    fn is_zero(&self) -> bool {
        self.count == 0 && self.key_hash_xor == [0u8; 32] && self.checksum_xor == 0
    }
}

/// Invertible Bloom Lookup Table for set-difference computation.
///
/// Uses `k` hash functions to map each element to `k` cells.
/// Two IBLTs can be subtracted to find the symmetric difference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Iblt {
    /// Cells of the IBLT.
    pub cells: Vec<IbltCell>,
    /// Number of hash functions.
    pub num_hashes: usize,
}

impl Iblt {
    /// Create a new IBLT with the given number of cells and hash functions.
    ///
    /// Rule of thumb: cells ~= 1.5 * expected_difference_size.
    pub fn new(num_cells: usize, num_hashes: usize) -> Self {
        Self {
            cells: (0..num_cells).map(|_| IbltCell::default()).collect(),
            num_hashes,
        }
    }

    /// Number of cells.
    pub fn num_cells(&self) -> usize {
        self.cells.len()
    }

    /// Insert an element (identified by its 32-byte content hash).
    pub fn insert(&mut self, key_hash: &[u8; 32]) {
        let checksum = compute_checksum(key_hash);
        for i in 0..self.num_hashes {
            let idx = hash_to_index(key_hash, i, self.cells.len());
            self.cells[idx].count += 1;
            xor_into(&mut self.cells[idx].key_hash_xor, key_hash);
            self.cells[idx].checksum_xor ^= checksum;
        }
    }

    /// Remove an element (inverse of insert).
    pub fn remove(&mut self, key_hash: &[u8; 32]) {
        let checksum = compute_checksum(key_hash);
        for i in 0..self.num_hashes {
            let idx = hash_to_index(key_hash, i, self.cells.len());
            self.cells[idx].count -= 1;
            xor_into(&mut self.cells[idx].key_hash_xor, key_hash);
            self.cells[idx].checksum_xor ^= checksum;
        }
    }

    /// Subtract another IBLT from this one (compute difference).
    pub fn subtract(&self, other: &Iblt) -> Result<Iblt, ReconcileError> {
        if self.cells.len() != other.cells.len() || self.num_hashes != other.num_hashes {
            return Err(ReconcileError::IbltSizeMismatch {
                local_cells: self.cells.len(),
                remote_cells: other.cells.len(),
            });
        }
        let mut result = self.clone();
        for (i, other_cell) in other.cells.iter().enumerate() {
            result.cells[i].count -= other_cell.count;
            xor_into(&mut result.cells[i].key_hash_xor, &other_cell.key_hash_xor);
            result.cells[i].checksum_xor ^= other_cell.checksum_xor;
        }
        Ok(result)
    }

    /// Peel the IBLT to extract the symmetric difference.
    ///
    /// Returns `(positive, negative)` where positive are elements in self
    /// but not other, and negative are elements in other but not self.
    /// Returns Err if the IBLT cannot be fully peeled.
    pub fn peel(&self) -> Result<SymmetricDiff, ReconcileError> {
        let mut work = self.clone();
        let mut positive = Vec::new();
        let mut negative = Vec::new();

        let mut changed = true;
        while changed {
            changed = false;
            for i in 0..work.cells.len() {
                let cell_count = work.cells[i].count;
                if cell_count == 1 || cell_count == -1 {
                    let key = work.cells[i].key_hash_xor;
                    let checksum = compute_checksum(&key);
                    if checksum == work.cells[i].checksum_xor {
                        if cell_count == 1 {
                            positive.push(key);
                        } else {
                            negative.push(key);
                        }
                        // Remove this element from the working IBLT.
                        for j in 0..work.num_hashes {
                            let idx = hash_to_index(&key, j, work.cells.len());
                            work.cells[idx].count -= cell_count;
                            xor_into(&mut work.cells[idx].key_hash_xor, &key);
                            work.cells[idx].checksum_xor ^= checksum;
                        }
                        changed = true;
                    }
                }
            }
        }

        // Verify all cells are empty.
        let all_empty = work.cells.iter().all(IbltCell::is_zero);
        if all_empty {
            positive.sort();
            negative.sort();
            Ok((positive, negative))
        } else {
            Err(ReconcileError::PeelFailed {
                remaining_cells: work.cells.iter().filter(|c| !c.is_zero()).count(),
            })
        }
    }
}

/// Compute a simple checksum for verification.
fn compute_checksum(key: &[u8; 32]) -> u32 {
    let mut csum: u32 = 0;
    for chunk in key.chunks(4) {
        let mut bytes = [0u8; 4];
        bytes[..chunk.len()].copy_from_slice(chunk);
        csum ^= u32::from_le_bytes(bytes);
    }
    csum
}

/// Hash a key to a cell index using the hash function index.
fn hash_to_index(key: &[u8; 32], hash_idx: usize, num_cells: usize) -> usize {
    // Use different 4-byte windows of the key for different hash functions.
    let offset = (hash_idx * 4) % 32;
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&key[offset..offset + 4]);
    let raw = u32::from_le_bytes(bytes);
    // Mix in hash_idx to reduce correlation.
    let mixed = raw.wrapping_add(hash_idx as u32).wrapping_mul(0x9E3779B9);
    (mixed as usize) % num_cells
}

/// XOR `src` into `dst`.
fn xor_into(dst: &mut [u8; 32], src: &[u8; 32]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

// ---------------------------------------------------------------------------
// ReconcileResult — outcome of reconciliation
// ---------------------------------------------------------------------------

/// Outcome of a reconciliation session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcileResult {
    /// Objects we need to fetch from the peer.
    pub objects_to_fetch: Vec<[u8; 32]>,
    /// Objects the peer needs to fetch from us.
    pub objects_to_send: Vec<[u8; 32]>,
    /// Whether fallback was triggered.
    pub fallback_triggered: bool,
}

// ---------------------------------------------------------------------------
// ReconcileEvent — structured audit event
// ---------------------------------------------------------------------------

/// Structured event emitted for reconciliation sessions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcileEvent {
    /// Unique reconciliation session identifier.
    pub reconciliation_id: String,
    /// Peer node identifier.
    pub peer: String,
    /// Number of objects sent to peer.
    pub objects_sent: usize,
    /// Number of objects received from peer.
    pub objects_received: usize,
    /// Number of conflicting objects.
    pub objects_conflicting: usize,
    /// Epoch at time of reconciliation.
    pub epoch_id: u64,
    /// Trace identifier.
    pub trace_id: String,
    /// Event type.
    pub event: String,
    /// Whether fallback was triggered.
    pub fallback_triggered: bool,
}

// ---------------------------------------------------------------------------
// ReconcileError — typed errors
// ---------------------------------------------------------------------------

/// Errors from reconciliation operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReconcileError {
    /// IBLT sizes do not match.
    IbltSizeMismatch {
        local_cells: usize,
        remote_cells: usize,
    },
    /// IBLT could not be peeled (too many differences).
    PeelFailed { remaining_cells: usize },
    /// Epoch mismatch between local and remote.
    EpochMismatch {
        local_epoch: SecurityEpoch,
        remote_epoch: SecurityEpoch,
    },
    /// Object verification failed.
    VerificationFailed { object_hash: String, reason: String },
    /// Empty object set.
    EmptyObjectSet,
}

impl fmt::Display for ReconcileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IbltSizeMismatch {
                local_cells,
                remote_cells,
            } => {
                write!(
                    f,
                    "IBLT size mismatch: local {local_cells} cells, remote {remote_cells} cells"
                )
            }
            Self::PeelFailed { remaining_cells } => {
                write!(
                    f,
                    "IBLT peel failed: {remaining_cells} non-empty cells remaining"
                )
            }
            Self::EpochMismatch {
                local_epoch,
                remote_epoch,
            } => {
                write!(
                    f,
                    "epoch mismatch: local {local_epoch}, remote {remote_epoch}"
                )
            }
            Self::VerificationFailed {
                object_hash,
                reason,
            } => {
                write!(f, "verification failed for {object_hash}: {reason}")
            }
            Self::EmptyObjectSet => f.write_str("object set is empty"),
        }
    }
}

impl std::error::Error for ReconcileError {}

// ---------------------------------------------------------------------------
// ReconcileConfig — configurable parameters
// ---------------------------------------------------------------------------

/// Configuration for reconciliation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcileConfig {
    /// Number of IBLT cells (rule of thumb: 1.5 * expected difference).
    pub iblt_cells: usize,
    /// Number of IBLT hash functions.
    pub iblt_hashes: usize,
    /// Maximum retries before fallback.
    pub max_retries: u32,
    /// Scale factor for retry (multiply cells by this on retry).
    pub retry_scale_factor: usize,
}

impl Default for ReconcileConfig {
    fn default() -> Self {
        Self {
            iblt_cells: 256,
            iblt_hashes: 3,
            max_retries: 2,
            retry_scale_factor: 2,
        }
    }
}

// ---------------------------------------------------------------------------
// ReconcileSession — orchestrates a reconciliation round
// ---------------------------------------------------------------------------

/// A reconciliation session between two nodes.
#[derive(Debug)]
pub struct ReconcileSession {
    /// Current epoch.
    current_epoch: SecurityEpoch,
    /// Configuration.
    config: ReconcileConfig,
    /// Accumulated events.
    events: Vec<ReconcileEvent>,
    /// Event counters.
    event_counts: BTreeMap<String, u64>,
}

impl ReconcileSession {
    /// Create a new reconciliation session.
    pub fn new(epoch: SecurityEpoch, config: ReconcileConfig) -> Self {
        Self {
            current_epoch: epoch,
            config,
            events: Vec::new(),
            event_counts: BTreeMap::new(),
        }
    }

    /// Build an IBLT from a set of object hashes.
    pub fn build_iblt(&self, object_hashes: &BTreeSet<[u8; 32]>) -> Iblt {
        let mut iblt = Iblt::new(self.config.iblt_cells, self.config.iblt_hashes);
        for hash in object_hashes {
            iblt.insert(hash);
        }
        iblt
    }

    /// Reconcile local and remote object sets using IBLT exchange.
    ///
    /// Returns the reconciliation result with objects to fetch/send.
    /// On peel failure, retries with larger IBLT before triggering fallback.
    pub fn reconcile(
        &mut self,
        local_objects: &BTreeSet<[u8; 32]>,
        remote_iblt: &Iblt,
        peer: &str,
        trace_id: &str,
    ) -> Result<ReconcileResult, ReconcileError> {
        let local_iblt = self.build_iblt(local_objects);

        // Try with current IBLT size, then retry with scaled size.
        let mut attempt = 0;
        let mut current_cells = self.config.iblt_cells;

        loop {
            let local_sketch = if current_cells == self.config.iblt_cells {
                local_iblt.clone()
            } else {
                // Rebuild with larger size.
                let mut larger = Iblt::new(current_cells, self.config.iblt_hashes);
                for hash in local_objects {
                    larger.insert(hash);
                }
                larger
            };

            // Can only subtract if sizes match — in a real protocol,
            // both sides would agree on size. For mismatched retry sizes,
            // we'd need to re-request from the peer. Here we detect and
            // handle the mismatch.
            if local_sketch.num_cells() != remote_iblt.num_cells() {
                attempt += 1;
                if attempt > self.config.max_retries {
                    return self.fallback_result(local_objects, peer, trace_id);
                }
                current_cells *= self.config.retry_scale_factor;
                continue;
            }

            let diff = local_sketch.subtract(remote_iblt)?;

            match diff.peel() {
                Ok((to_send, to_fetch)) => {
                    self.emit_event(ReconcileEvent {
                        reconciliation_id: format!("{trace_id}:{peer}"),
                        peer: peer.to_string(),
                        objects_sent: to_send.len(),
                        objects_received: to_fetch.len(),
                        objects_conflicting: 0,
                        epoch_id: self.current_epoch.as_u64(),
                        trace_id: trace_id.to_string(),
                        event: "reconcile_success".to_string(),
                        fallback_triggered: false,
                    });
                    self.record_count("reconcile_success");

                    return Ok(ReconcileResult {
                        objects_to_fetch: to_fetch,
                        objects_to_send: to_send,
                        fallback_triggered: false,
                    });
                }
                Err(ReconcileError::PeelFailed { .. }) => {
                    attempt += 1;
                    if attempt > self.config.max_retries {
                        return self.fallback_result(local_objects, peer, trace_id);
                    }
                    current_cells *= self.config.retry_scale_factor;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Full-state fallback: compute difference by brute force.
    fn fallback_result(
        &mut self,
        local_objects: &BTreeSet<[u8; 32]>,
        peer: &str,
        trace_id: &str,
    ) -> Result<ReconcileResult, ReconcileError> {
        // In fallback mode, we don't have the peer's full set,
        // so we signal that fallback was triggered. The caller
        // must use a different protocol to resolve.
        self.emit_event(ReconcileEvent {
            reconciliation_id: format!("{trace_id}:{peer}"),
            peer: peer.to_string(),
            objects_sent: 0,
            objects_received: 0,
            objects_conflicting: local_objects.len(),
            epoch_id: self.current_epoch.as_u64(),
            trace_id: trace_id.to_string(),
            event: "reconcile_fallback".to_string(),
            fallback_triggered: true,
        });
        self.record_count("reconcile_fallback");

        Ok(ReconcileResult {
            objects_to_fetch: Vec::new(),
            objects_to_send: Vec::new(),
            fallback_triggered: true,
        })
    }

    /// Compute the exact set difference between two known sets.
    /// Used for testing and as the fallback protocol.
    pub fn exact_difference(
        local: &BTreeSet<[u8; 32]>,
        remote: &BTreeSet<[u8; 32]>,
    ) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
        let local_only: Vec<[u8; 32]> = local.difference(remote).copied().collect();
        let remote_only: Vec<[u8; 32]> = remote.difference(local).copied().collect();
        (local_only, remote_only)
    }

    /// Current epoch.
    pub fn epoch(&self) -> SecurityEpoch {
        self.current_epoch
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<ReconcileEvent> {
        std::mem::take(&mut self.events)
    }

    /// Event counters.
    pub fn event_counts(&self) -> &BTreeMap<String, u64> {
        &self.event_counts
    }

    // -- Internal --

    fn emit_event(&mut self, event: ReconcileEvent) {
        self.events.push(event);
    }

    fn record_count(&mut self, event_type: &str) {
        *self.event_counts.entry(event_type.to_string()).or_insert(0) += 1;
    }
}

// ---------------------------------------------------------------------------
// FallbackTrigger — why the deterministic fallback was activated
// ---------------------------------------------------------------------------

/// Reason the deterministic fallback protocol was activated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FallbackTrigger {
    /// IBLT peel failed (too many differences for the table size).
    PeelFailed { remaining_cells: usize },
    /// Decoded objects failed hash verification.
    VerificationFailed { object_hash: String, reason: String },
    /// Reconciliation exceeded convergence SLO.
    Timeout { elapsed_ms: u64, slo_ms: u64 },
    /// MMR consistency proof failure (stream divergence).
    MmrConsistencyFailure { details: String },
}

impl fmt::Display for FallbackTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeelFailed { remaining_cells } => {
                write!(f, "peel_failed({remaining_cells} remaining)")
            }
            Self::VerificationFailed {
                object_hash,
                reason,
            } => {
                write!(f, "verification_failed({object_hash}: {reason})")
            }
            Self::Timeout { elapsed_ms, slo_ms } => {
                write!(f, "timeout({elapsed_ms}ms > {slo_ms}ms SLO)")
            }
            Self::MmrConsistencyFailure { details } => {
                write!(f, "mmr_consistency({details})")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FallbackEvidence — structured evidence entry per fallback activation
// ---------------------------------------------------------------------------

/// Structured evidence emitted for every fallback activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackEvidence {
    /// Unique fallback identifier.
    pub fallback_id: String,
    /// Why fallback was triggered.
    pub trigger: FallbackTrigger,
    /// Original reconciliation session ID.
    pub original_reconciliation_id: String,
    /// Number of objects in the reconciliation scope.
    pub scope_size: usize,
    /// Number of differences found.
    pub differences_found: usize,
    /// Number of objects transferred.
    pub objects_transferred: usize,
    /// Simulated duration in milliseconds (deterministic; real wall-clock not used).
    pub duration_ms: u64,
    /// Epoch at time of fallback.
    pub epoch_id: u64,
    /// Trace identifier.
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// FallbackResult — outcome of fallback execution
// ---------------------------------------------------------------------------

/// Outcome of the deterministic fallback protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackResult {
    /// Objects we need to fetch from the peer.
    pub objects_to_fetch: Vec<[u8; 32]>,
    /// Objects the peer needs to fetch from us.
    pub objects_to_send: Vec<[u8; 32]>,
    /// Evidence record for this fallback.
    pub evidence: FallbackEvidence,
}

// ---------------------------------------------------------------------------
// FallbackConfig — configurable parameters
// ---------------------------------------------------------------------------

/// Configuration for fallback protocol and rate monitoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackConfig {
    /// Maximum allowed fallback rate (percentage of reconciliation attempts).
    /// If exceeded, a `FallbackRateExceeded` alert is emitted.
    pub max_fallback_rate_pct: u32,
    /// Sliding window size for fallback rate calculation.
    pub monitoring_window: usize,
}

impl Default for FallbackConfig {
    fn default() -> Self {
        Self {
            max_fallback_rate_pct: 5,
            monitoring_window: 100,
        }
    }
}

// ---------------------------------------------------------------------------
// FallbackRequest — parameters for a single fallback execution
// ---------------------------------------------------------------------------

/// Parameters for a fallback execution.
pub struct FallbackRequest<'a> {
    /// Local node's sorted hash set.
    pub local_hashes: &'a BTreeSet<[u8; 32]>,
    /// Remote node's sorted hash set.
    pub remote_hashes: &'a BTreeSet<[u8; 32]>,
    /// Why the fallback was triggered.
    pub trigger: FallbackTrigger,
    /// Original reconciliation session ID.
    pub reconciliation_id: &'a str,
    /// Peer node identifier.
    pub peer: &'a str,
    /// Trace identifier.
    pub trace_id: &'a str,
}

// ---------------------------------------------------------------------------
// FallbackProtocol — deterministic hash-list reconciliation
// ---------------------------------------------------------------------------

/// Deterministic fallback protocol for anti-entropy reconciliation.
///
/// When the IBLT-based path fails, both nodes exchange sorted hash lists
/// and compute the set difference via a merge-join (O(n) on sorted input).
/// This guarantees convergence at the cost of higher communication overhead.
#[derive(Debug)]
pub struct FallbackProtocol {
    current_epoch: SecurityEpoch,
    events: Vec<FallbackEvidence>,
    event_counts: BTreeMap<String, u64>,
    fallback_seq: u64,
}

impl FallbackProtocol {
    /// Create a new fallback protocol instance.
    pub fn new(epoch: SecurityEpoch) -> Self {
        Self {
            current_epoch: epoch,
            events: Vec::new(),
            event_counts: BTreeMap::new(),
            fallback_seq: 0,
        }
    }

    /// Execute the deterministic fallback: sorted-list merge-join.
    ///
    /// Both `local_hashes` and `remote_hashes` are the full sorted hash sets
    /// for the reconciliation scope. The difference is computed via
    /// `BTreeSet::difference` (O(n) merge on sorted iterators).
    ///
    /// Returns the same information as the IBLT path: objects to send/fetch.
    pub fn execute(&mut self, req: FallbackRequest<'_>) -> FallbackResult {
        self.fallback_seq += 1;
        let fallback_id = format!("fb-{}-{}", req.trace_id, self.fallback_seq);

        // Merge-join difference on sorted sets.
        let objects_to_send: Vec<[u8; 32]> = req
            .local_hashes
            .difference(req.remote_hashes)
            .copied()
            .collect();
        let objects_to_fetch: Vec<[u8; 32]> = req
            .remote_hashes
            .difference(req.local_hashes)
            .copied()
            .collect();

        let differences_found = objects_to_send.len() + objects_to_fetch.len();
        let scope_size = req.local_hashes.len().max(req.remote_hashes.len());

        let evidence = FallbackEvidence {
            fallback_id,
            trigger: req.trigger,
            original_reconciliation_id: format!("{}:{}", req.reconciliation_id, req.peer),
            scope_size,
            differences_found,
            objects_transferred: differences_found,
            duration_ms: 0, // deterministic: caller provides real timing
            epoch_id: self.current_epoch.as_u64(),
            trace_id: req.trace_id.to_string(),
        };

        self.events.push(evidence.clone());
        *self
            .event_counts
            .entry("fallback_executed".to_string())
            .or_insert(0) += 1;

        FallbackResult {
            objects_to_fetch,
            objects_to_send,
            evidence,
        }
    }

    /// Execute fallback with incremental range narrowing.
    ///
    /// Splits the hash space into `num_ranges` sub-ranges and processes
    /// each independently, allowing early termination when ranges match.
    pub fn execute_incremental(
        &mut self,
        req: FallbackRequest<'_>,
        num_ranges: u8,
    ) -> FallbackResult {
        if num_ranges <= 1 {
            return self.execute(req);
        }

        self.fallback_seq += 1;
        let fallback_id = format!("fb-{}-{}", req.trace_id, self.fallback_seq);

        let mut all_to_send: Vec<[u8; 32]> = Vec::new();
        let mut all_to_fetch: Vec<[u8; 32]> = Vec::new();
        let mut ranges_skipped: usize = 0;

        // Split the 256-value first-byte space into num_ranges buckets.
        let range_size = 256usize / (num_ranges as usize);
        for r in 0..num_ranges {
            let lo = (r as usize) * range_size;
            let hi = if r == num_ranges - 1 {
                256
            } else {
                lo + range_size
            };

            let local_range: BTreeSet<[u8; 32]> = req
                .local_hashes
                .iter()
                .filter(|h| {
                    let b = h[0] as usize;
                    b >= lo && b < hi
                })
                .copied()
                .collect();

            let remote_range: BTreeSet<[u8; 32]> = req
                .remote_hashes
                .iter()
                .filter(|h| {
                    let b = h[0] as usize;
                    b >= lo && b < hi
                })
                .copied()
                .collect();

            // Skip ranges that are identical (count + total check).
            if local_range == remote_range {
                ranges_skipped += 1;
                continue;
            }

            all_to_send.extend(local_range.difference(&remote_range));
            all_to_fetch.extend(remote_range.difference(&local_range));
        }

        all_to_send.sort();
        all_to_fetch.sort();

        let differences_found = all_to_send.len() + all_to_fetch.len();
        let scope_size = req.local_hashes.len().max(req.remote_hashes.len());

        let evidence = FallbackEvidence {
            fallback_id,
            trigger: req.trigger,
            original_reconciliation_id: format!("{}:{}", req.reconciliation_id, req.peer),
            scope_size,
            differences_found,
            objects_transferred: differences_found,
            duration_ms: 0,
            epoch_id: self.current_epoch.as_u64(),
            trace_id: req.trace_id.to_string(),
        };

        // Track skipped ranges as a metric.
        *self
            .event_counts
            .entry("fallback_ranges_skipped".to_string())
            .or_insert(0) += ranges_skipped as u64;
        self.events.push(evidence.clone());
        *self
            .event_counts
            .entry("fallback_executed".to_string())
            .or_insert(0) += 1;

        FallbackResult {
            objects_to_fetch: all_to_fetch,
            objects_to_send: all_to_send,
            evidence,
        }
    }

    /// Current epoch.
    pub fn epoch(&self) -> SecurityEpoch {
        self.current_epoch
    }

    /// Drain accumulated evidence entries.
    pub fn drain_events(&mut self) -> Vec<FallbackEvidence> {
        std::mem::take(&mut self.events)
    }

    /// Event counters.
    pub fn event_counts(&self) -> &BTreeMap<String, u64> {
        &self.event_counts
    }
}

// ---------------------------------------------------------------------------
// FallbackRateMonitor — tracks fallback frequency and emits alerts
// ---------------------------------------------------------------------------

/// Alert emitted when fallback rate exceeds the configured threshold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackRateAlert {
    /// Current fallback rate as a percentage.
    pub rate_pct: u32,
    /// Configured threshold.
    pub threshold_pct: u32,
    /// Number of fallbacks in the window.
    pub fallbacks_in_window: u32,
    /// Total reconciliations in the window.
    pub total_in_window: u32,
    /// Epoch at time of alert.
    pub epoch_id: u64,
}

/// Monitors fallback frequency over a sliding window.
#[derive(Debug)]
pub struct FallbackRateMonitor {
    config: FallbackConfig,
    current_epoch: SecurityEpoch,
    /// Ring buffer of recent reconciliation outcomes (true = fallback).
    outcomes: Vec<bool>,
    /// Write cursor into the ring buffer.
    cursor: usize,
    /// Total recorded so far (may be less than window size).
    total_recorded: usize,
    /// Accumulated alerts.
    alerts: Vec<FallbackRateAlert>,
}

impl FallbackRateMonitor {
    /// Create a new rate monitor.
    pub fn new(epoch: SecurityEpoch, config: FallbackConfig) -> Self {
        let window = config.monitoring_window.max(1);
        Self {
            config: FallbackConfig {
                monitoring_window: window,
                ..config
            },
            current_epoch: epoch,
            outcomes: vec![false; window],
            cursor: 0,
            total_recorded: 0,
            alerts: Vec::new(),
        }
    }

    /// Record a reconciliation outcome.
    ///
    /// `was_fallback` is true if the reconciliation triggered fallback.
    /// Returns `Some(alert)` if the fallback rate now exceeds the threshold.
    pub fn record(&mut self, was_fallback: bool) -> Option<FallbackRateAlert> {
        self.outcomes[self.cursor] = was_fallback;
        self.cursor = (self.cursor + 1) % self.config.monitoring_window;
        self.total_recorded += 1;

        let window_size = self.total_recorded.min(self.config.monitoring_window);
        let fallback_count = self.outcomes[..window_size].iter().filter(|&&b| b).count() as u32;

        let total = window_size as u32;
        if total == 0 {
            return None;
        }

        let rate_pct = (fallback_count * 100) / total;

        if rate_pct > self.config.max_fallback_rate_pct {
            let alert = FallbackRateAlert {
                rate_pct,
                threshold_pct: self.config.max_fallback_rate_pct,
                fallbacks_in_window: fallback_count,
                total_in_window: total,
                epoch_id: self.current_epoch.as_u64(),
            };
            self.alerts.push(alert.clone());
            Some(alert)
        } else {
            None
        }
    }

    /// Current fallback rate as a percentage (0-100).
    pub fn current_rate_pct(&self) -> u32 {
        let window_size = self.total_recorded.min(self.config.monitoring_window);
        if window_size == 0 {
            return 0;
        }
        let fallback_count = self.outcomes[..window_size].iter().filter(|&&b| b).count() as u32;
        // Only count up to the window.
        let effective = fallback_count.min(window_size as u32);
        (effective * 100) / (window_size as u32)
    }

    /// Whether the current rate exceeds the threshold.
    pub fn is_rate_exceeded(&self) -> bool {
        self.current_rate_pct() > self.config.max_fallback_rate_pct
    }

    /// Drain accumulated alerts.
    pub fn drain_alerts(&mut self) -> Vec<FallbackRateAlert> {
        std::mem::take(&mut self.alerts)
    }

    /// Number of reconciliations recorded.
    pub fn total_recorded(&self) -> usize {
        self.total_recorded
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    fn make_hash(seed: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        // Fill with a deterministic pattern.
        for (i, byte) in h.iter_mut().enumerate() {
            *byte = seed.wrapping_add(i as u8).wrapping_mul(37);
        }
        h
    }

    /// Hash from u16, with a marker byte to distinguish sets.
    fn make_wide_hash(val: u16, marker: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        let bytes = val.to_le_bytes();
        h[0] = bytes[0];
        h[1] = bytes[1];
        h[2] = marker;
        // Spread entropy across the key so different hash functions see variation.
        for i in 3..32 {
            h[i] = h[i - 1].wrapping_mul(37).wrapping_add(marker);
        }
        h
    }

    // -- ObjectType --

    #[test]
    fn object_type_display() {
        assert_eq!(
            ReconcileObjectType::RevocationEvent.to_string(),
            "revocation_event"
        );
        assert_eq!(
            ReconcileObjectType::CheckpointMarker.to_string(),
            "checkpoint_marker"
        );
        assert_eq!(
            ReconcileObjectType::EvidenceEntry.to_string(),
            "evidence_entry"
        );
    }

    // -- IBLT basics --

    #[test]
    fn iblt_insert_and_peel_single() {
        let mut iblt = Iblt::new(64, 3);
        let h = make_hash(1);
        iblt.insert(&h);

        // Create an empty IBLT and subtract.
        let empty = Iblt::new(64, 3);
        let diff = iblt.subtract(&empty).unwrap();
        let (pos, neg) = diff.peel().unwrap();
        assert_eq!(pos.len(), 1);
        assert_eq!(pos[0], h);
        assert!(neg.is_empty());
    }

    #[test]
    fn iblt_symmetric_difference() {
        let mut iblt_a = Iblt::new(128, 3);
        let mut iblt_b = Iblt::new(128, 3);

        let shared: Vec<[u8; 32]> = (0..10).map(make_hash).collect();
        let a_only: Vec<[u8; 32]> = (10..13).map(make_hash).collect();
        let b_only: Vec<[u8; 32]> = (13..15).map(make_hash).collect();

        for h in &shared {
            iblt_a.insert(h);
            iblt_b.insert(h);
        }
        for h in &a_only {
            iblt_a.insert(h);
        }
        for h in &b_only {
            iblt_b.insert(h);
        }

        let diff = iblt_a.subtract(&iblt_b).unwrap();
        let (pos, neg) = diff.peel().unwrap();

        // pos = elements in A but not B (a_only).
        // neg = elements in B but not A (b_only).
        assert_eq!(pos.len(), a_only.len());
        assert_eq!(neg.len(), b_only.len());

        let pos_set: BTreeSet<[u8; 32]> = pos.into_iter().collect();
        let neg_set: BTreeSet<[u8; 32]> = neg.into_iter().collect();
        let a_only_set: BTreeSet<[u8; 32]> = a_only.into_iter().collect();
        let b_only_set: BTreeSet<[u8; 32]> = b_only.into_iter().collect();

        assert_eq!(pos_set, a_only_set);
        assert_eq!(neg_set, b_only_set);
    }

    #[test]
    fn iblt_identical_sets_produce_empty_diff() {
        let mut iblt_a = Iblt::new(64, 3);
        let mut iblt_b = Iblt::new(64, 3);

        for i in 0..20 {
            let h = make_hash(i);
            iblt_a.insert(&h);
            iblt_b.insert(&h);
        }

        let diff = iblt_a.subtract(&iblt_b).unwrap();
        let (pos, neg) = diff.peel().unwrap();
        assert!(pos.is_empty());
        assert!(neg.is_empty());
    }

    #[test]
    fn iblt_peel_fails_for_large_difference_small_table() {
        // 4 cells with 3 hash functions and 400 distinct elements:
        // each element touches 3 of 4 cells, making isolation impossible.
        let mut iblt_a = Iblt::new(4, 3);
        let mut iblt_b = Iblt::new(4, 3);

        for i in 0u16..200 {
            iblt_a.insert(&make_wide_hash(i, 0xAA));
        }
        for i in 200u16..400 {
            iblt_b.insert(&make_wide_hash(i, 0xBB));
        }

        let diff = iblt_a.subtract(&iblt_b).unwrap();
        assert!(diff.peel().is_err());
    }

    #[test]
    fn iblt_subtract_size_mismatch() {
        let iblt_a = Iblt::new(64, 3);
        let iblt_b = Iblt::new(128, 3);
        assert!(matches!(
            iblt_a.subtract(&iblt_b),
            Err(ReconcileError::IbltSizeMismatch { .. })
        ));
    }

    #[test]
    fn iblt_insert_remove_cancels() {
        let mut iblt = Iblt::new(64, 3);
        let h = make_hash(42);
        iblt.insert(&h);
        iblt.remove(&h);

        // Should be equivalent to an empty IBLT.
        let empty = Iblt::new(64, 3);
        assert_eq!(iblt, empty);
    }

    // -- ReconcileSession --

    #[test]
    fn reconcile_success() {
        let config = ReconcileConfig {
            iblt_cells: 128,
            iblt_hashes: 3,
            max_retries: 2,
            retry_scale_factor: 2,
        };
        let mut session = ReconcileSession::new(test_epoch(), config);

        let mut local: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut remote: BTreeSet<[u8; 32]> = BTreeSet::new();

        // Shared objects.
        for i in 0..20 {
            let h = make_hash(i);
            local.insert(h);
            remote.insert(h);
        }
        // Local-only.
        let local_only_hash = make_hash(100);
        local.insert(local_only_hash);
        // Remote-only.
        let remote_only_hash = make_hash(200);
        remote.insert(remote_only_hash);

        let remote_iblt = session.build_iblt(&remote);
        let result = session
            .reconcile(&local, &remote_iblt, "peer-1", "t1")
            .unwrap();

        assert!(!result.fallback_triggered);
        assert_eq!(result.objects_to_send.len(), 1);
        assert_eq!(result.objects_to_fetch.len(), 1);
        assert!(result.objects_to_send.contains(&local_only_hash));
        assert!(result.objects_to_fetch.contains(&remote_only_hash));
    }

    #[test]
    fn reconcile_identical_sets() {
        let config = ReconcileConfig::default();
        let mut session = ReconcileSession::new(test_epoch(), config);

        let mut objects: BTreeSet<[u8; 32]> = BTreeSet::new();
        for i in 0..30 {
            objects.insert(make_hash(i));
        }

        let remote_iblt = session.build_iblt(&objects);
        let result = session
            .reconcile(&objects, &remote_iblt, "peer-1", "t1")
            .unwrap();

        assert!(!result.fallback_triggered);
        assert!(result.objects_to_send.is_empty());
        assert!(result.objects_to_fetch.is_empty());
    }

    #[test]
    fn reconcile_fallback_on_large_difference() {
        let config = ReconcileConfig {
            iblt_cells: 4, // tiny — will fail to peel
            iblt_hashes: 3,
            max_retries: 0, // no retries → immediate fallback
            retry_scale_factor: 2,
        };
        let mut session = ReconcileSession::new(test_epoch(), config);

        let local: BTreeSet<[u8; 32]> = (0u16..200).map(|i| make_wide_hash(i, 0xAA)).collect();
        let remote: BTreeSet<[u8; 32]> = (200u16..400).map(|i| make_wide_hash(i, 0xBB)).collect();

        let remote_iblt = session.build_iblt(&remote);
        let result = session
            .reconcile(&local, &remote_iblt, "peer-1", "t1")
            .unwrap();
        assert!(result.fallback_triggered);
    }

    // -- Exact difference --

    #[test]
    fn exact_difference_computes_correctly() {
        let mut local: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut remote: BTreeSet<[u8; 32]> = BTreeSet::new();

        for i in 0..5 {
            let h = make_hash(i);
            local.insert(h);
            remote.insert(h);
        }
        let l_only = make_hash(100);
        local.insert(l_only);
        let r_only = make_hash(200);
        remote.insert(r_only);

        let (local_only, remote_only) = ReconcileSession::exact_difference(&local, &remote);
        assert_eq!(local_only.len(), 1);
        assert_eq!(remote_only.len(), 1);
        assert_eq!(local_only[0], l_only);
        assert_eq!(remote_only[0], r_only);
    }

    // -- Audit events --

    #[test]
    fn reconcile_emits_success_event() {
        let config = ReconcileConfig {
            iblt_cells: 128,
            iblt_hashes: 3,
            max_retries: 2,
            retry_scale_factor: 2,
        };
        let mut session = ReconcileSession::new(test_epoch(), config);

        let objects: BTreeSet<[u8; 32]> = (0..10).map(make_hash).collect();
        let remote_iblt = session.build_iblt(&objects);
        session
            .reconcile(&objects, &remote_iblt, "peer-1", "t1")
            .unwrap();

        let events = session.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "reconcile_success");
        assert_eq!(events[0].peer, "peer-1");
        assert!(!events[0].fallback_triggered);
    }

    #[test]
    fn fallback_emits_event() {
        let config = ReconcileConfig {
            iblt_cells: 4,
            iblt_hashes: 3,
            max_retries: 0,
            retry_scale_factor: 2,
        };
        let mut session = ReconcileSession::new(test_epoch(), config);

        let local: BTreeSet<[u8; 32]> = (0u16..200).map(|i| make_wide_hash(i, 0xAA)).collect();
        let remote: BTreeSet<[u8; 32]> = (200u16..400).map(|i| make_wide_hash(i, 0xBB)).collect();
        let remote_iblt = session.build_iblt(&remote);
        session
            .reconcile(&local, &remote_iblt, "peer-1", "t1")
            .unwrap();

        let events = session.drain_events();
        assert!(!events.is_empty());
        let fallback = events.iter().find(|e| e.event == "reconcile_fallback");
        assert!(fallback.is_some());
        assert!(fallback.unwrap().fallback_triggered);
    }

    #[test]
    fn event_counts_track() {
        let config = ReconcileConfig {
            iblt_cells: 128,
            iblt_hashes: 3,
            max_retries: 2,
            retry_scale_factor: 2,
        };
        let mut session = ReconcileSession::new(test_epoch(), config);

        let objects: BTreeSet<[u8; 32]> = (0..5).map(make_hash).collect();
        let remote_iblt = session.build_iblt(&objects);
        session
            .reconcile(&objects, &remote_iblt, "peer-1", "t1")
            .unwrap();

        assert_eq!(session.event_counts().get("reconcile_success"), Some(&1));
    }

    // -- Serialization round-trips --

    #[test]
    fn object_id_serialization_round_trip() {
        let id = ObjectId {
            content_hash: ContentHash::compute(b"test"),
            object_type: ReconcileObjectType::RevocationEvent,
            epoch: test_epoch(),
        };
        let json = serde_json::to_string(&id).expect("serialize");
        let restored: ObjectId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, restored);
    }

    #[test]
    fn reconcile_event_serialization_round_trip() {
        let event = ReconcileEvent {
            reconciliation_id: "r1".to_string(),
            peer: "peer-1".to_string(),
            objects_sent: 5,
            objects_received: 3,
            objects_conflicting: 0,
            epoch_id: 1,
            trace_id: "t1".to_string(),
            event: "reconcile_success".to_string(),
            fallback_triggered: false,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: ReconcileEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    #[test]
    fn reconcile_error_serialization_round_trip() {
        let errors = vec![
            ReconcileError::IbltSizeMismatch {
                local_cells: 64,
                remote_cells: 128,
            },
            ReconcileError::PeelFailed {
                remaining_cells: 10,
            },
            ReconcileError::EmptyObjectSet,
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: ReconcileError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn iblt_serialization_round_trip() {
        let mut iblt = Iblt::new(16, 3);
        iblt.insert(&make_hash(1));
        iblt.insert(&make_hash(2));

        let json = serde_json::to_string(&iblt).expect("serialize");
        let restored: Iblt = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(iblt, restored);
    }

    #[test]
    fn reconcile_config_serialization_round_trip() {
        let config = ReconcileConfig::default();
        let json = serde_json::to_string(&config).expect("serialize");
        let restored: ReconcileConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, restored);
    }

    // -- Error display --

    #[test]
    fn error_display() {
        assert!(
            ReconcileError::PeelFailed {
                remaining_cells: 10
            }
            .to_string()
            .contains("10")
        );
        assert!(ReconcileError::EmptyObjectSet.to_string().contains("empty"));
        assert!(
            ReconcileError::IbltSizeMismatch {
                local_cells: 64,
                remote_cells: 128,
            }
            .to_string()
            .contains("mismatch")
        );
    }

    // -- Deterministic replay --

    #[test]
    fn deterministic_reconciliation() {
        let run = || -> ReconcileResult {
            let config = ReconcileConfig {
                iblt_cells: 128,
                iblt_hashes: 3,
                max_retries: 2,
                retry_scale_factor: 2,
            };
            let mut session = ReconcileSession::new(SecurityEpoch::from_raw(1), config);

            let mut local: BTreeSet<[u8; 32]> = BTreeSet::new();
            let mut remote: BTreeSet<[u8; 32]> = BTreeSet::new();
            for i in 0..20 {
                let h = make_hash(i);
                local.insert(h);
                remote.insert(h);
            }
            local.insert(make_hash(100));
            remote.insert(make_hash(200));

            let remote_iblt = session.build_iblt(&remote);
            session
                .reconcile(&local, &remote_iblt, "peer-1", "t1")
                .unwrap()
        };

        let r1 = run();
        let r2 = run();
        assert_eq!(r1, r2);
    }

    // -- Checksum --

    #[test]
    fn checksum_deterministic() {
        let h = make_hash(42);
        assert_eq!(compute_checksum(&h), compute_checksum(&h));
    }

    // -- Hash function coverage --

    #[test]
    fn different_hash_functions_produce_different_indices() {
        let h = make_hash(1);
        let idx0 = hash_to_index(&h, 0, 256);
        let idx1 = hash_to_index(&h, 1, 256);
        let idx2 = hash_to_index(&h, 2, 256);
        // Not guaranteed to be different, but with 256 cells
        // and mixing, very likely.
        assert!(idx0 != idx1 || idx1 != idx2);
    }

    // -- FallbackProtocol --

    #[test]
    fn fallback_computes_correct_difference() {
        let mut fb = FallbackProtocol::new(test_epoch());
        let mut local: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut remote: BTreeSet<[u8; 32]> = BTreeSet::new();

        for i in 0..20 {
            let h = make_hash(i);
            local.insert(h);
            remote.insert(h);
        }
        let l_only = make_hash(100);
        local.insert(l_only);
        let r_only = make_hash(200);
        remote.insert(r_only);

        let result = fb.execute(FallbackRequest {
            local_hashes: &local,
            remote_hashes: &remote,
            trigger: FallbackTrigger::PeelFailed { remaining_cells: 5 },
            reconciliation_id: "recon-1",
            peer: "peer-1",
            trace_id: "t1",
        });

        assert_eq!(result.objects_to_send.len(), 1);
        assert_eq!(result.objects_to_fetch.len(), 1);
        assert!(result.objects_to_send.contains(&l_only));
        assert!(result.objects_to_fetch.contains(&r_only));
        assert_eq!(result.evidence.differences_found, 2);
        assert_eq!(result.evidence.scope_size, 21);
    }

    #[test]
    fn fallback_identical_sets_no_difference() {
        let mut fb = FallbackProtocol::new(test_epoch());
        let objects: BTreeSet<[u8; 32]> = (0..30).map(make_hash).collect();

        let result = fb.execute(FallbackRequest {
            local_hashes: &objects,
            remote_hashes: &objects,
            trigger: FallbackTrigger::Timeout {
                elapsed_ms: 5000,
                slo_ms: 3000,
            },
            reconciliation_id: "recon-2",
            peer: "peer-1",
            trace_id: "t1",
        });

        assert!(result.objects_to_send.is_empty());
        assert!(result.objects_to_fetch.is_empty());
        assert_eq!(result.evidence.differences_found, 0);
    }

    #[test]
    fn fallback_deterministic_both_perspectives() {
        let local: BTreeSet<[u8; 32]> = (0..15).map(make_hash).collect();
        let remote: BTreeSet<[u8; 32]> = (10..25).map(make_hash).collect();

        let mut fb_a = FallbackProtocol::new(test_epoch());
        let result_a = fb_a.execute(FallbackRequest {
            local_hashes: &local,
            remote_hashes: &remote,
            trigger: FallbackTrigger::PeelFailed { remaining_cells: 3 },
            reconciliation_id: "r1",
            peer: "peer-b",
            trace_id: "t1",
        });

        let mut fb_b = FallbackProtocol::new(test_epoch());
        let result_b = fb_b.execute(FallbackRequest {
            local_hashes: &remote,
            remote_hashes: &local,
            trigger: FallbackTrigger::PeelFailed { remaining_cells: 3 },
            reconciliation_id: "r1",
            peer: "peer-a",
            trace_id: "t1",
        });

        // A's to_send should equal B's to_fetch and vice versa.
        assert_eq!(result_a.objects_to_send, result_b.objects_to_fetch);
        assert_eq!(result_a.objects_to_fetch, result_b.objects_to_send);
    }

    #[test]
    fn fallback_emits_evidence() {
        let mut fb = FallbackProtocol::new(test_epoch());
        let local: BTreeSet<[u8; 32]> = (0..5).map(make_hash).collect();
        let remote: BTreeSet<[u8; 32]> = (3..8).map(make_hash).collect();

        fb.execute(FallbackRequest {
            local_hashes: &local,
            remote_hashes: &remote,
            trigger: FallbackTrigger::MmrConsistencyFailure {
                details: "root mismatch".to_string(),
            },
            reconciliation_id: "r1",
            peer: "peer-1",
            trace_id: "t1",
        });

        let events = fb.drain_events();
        assert_eq!(events.len(), 1);
        assert!(events[0].fallback_id.starts_with("fb-"));
        assert_eq!(events[0].epoch_id, 1);
        assert_eq!(fb.event_counts().get("fallback_executed"), Some(&1));
    }

    #[test]
    fn fallback_agrees_with_iblt_for_small_diff() {
        let config = ReconcileConfig {
            iblt_cells: 128,
            iblt_hashes: 3,
            max_retries: 2,
            retry_scale_factor: 2,
        };
        let mut session = ReconcileSession::new(test_epoch(), config);
        let mut fb = FallbackProtocol::new(test_epoch());

        let mut local: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut remote: BTreeSet<[u8; 32]> = BTreeSet::new();
        for i in 0..20 {
            let h = make_hash(i);
            local.insert(h);
            remote.insert(h);
        }
        local.insert(make_hash(100));
        remote.insert(make_hash(200));

        let remote_iblt = session.build_iblt(&remote);
        let iblt_result = session
            .reconcile(&local, &remote_iblt, "peer-1", "t1")
            .unwrap();

        let fb_result = fb.execute(FallbackRequest {
            local_hashes: &local,
            remote_hashes: &remote,
            trigger: FallbackTrigger::PeelFailed { remaining_cells: 0 },
            reconciliation_id: "r1",
            peer: "peer-1",
            trace_id: "t1",
        });

        // Both should find the same differences.
        let iblt_send: BTreeSet<_> = iblt_result.objects_to_send.into_iter().collect();
        let iblt_fetch: BTreeSet<_> = iblt_result.objects_to_fetch.into_iter().collect();
        let fb_send: BTreeSet<_> = fb_result.objects_to_send.into_iter().collect();
        let fb_fetch: BTreeSet<_> = fb_result.objects_to_fetch.into_iter().collect();

        assert_eq!(iblt_send, fb_send);
        assert_eq!(iblt_fetch, fb_fetch);
    }

    // -- Incremental fallback --

    #[test]
    fn incremental_fallback_matches_full() {
        let mut fb = FallbackProtocol::new(test_epoch());
        let local: BTreeSet<[u8; 32]> = (0..50).map(make_hash).collect();
        let remote: BTreeSet<[u8; 32]> = (25..75).map(make_hash).collect();

        let full = fb.execute(FallbackRequest {
            local_hashes: &local,
            remote_hashes: &remote,
            trigger: FallbackTrigger::PeelFailed { remaining_cells: 3 },
            reconciliation_id: "r1",
            peer: "peer-1",
            trace_id: "t1",
        });

        let mut fb2 = FallbackProtocol::new(test_epoch());
        let incr = fb2.execute_incremental(
            FallbackRequest {
                local_hashes: &local,
                remote_hashes: &remote,
                trigger: FallbackTrigger::PeelFailed { remaining_cells: 3 },
                reconciliation_id: "r1",
                peer: "peer-1",
                trace_id: "t1",
            },
            4,
        );

        // Incremental and full must produce the same result sets.
        assert_eq!(
            full.objects_to_send.iter().collect::<BTreeSet<_>>(),
            incr.objects_to_send.iter().collect::<BTreeSet<_>>()
        );
        assert_eq!(
            full.objects_to_fetch.iter().collect::<BTreeSet<_>>(),
            incr.objects_to_fetch.iter().collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn incremental_fallback_skips_matching_ranges() {
        let mut fb = FallbackProtocol::new(test_epoch());
        let objects: BTreeSet<[u8; 32]> = (0..30).map(make_hash).collect();

        fb.execute_incremental(
            FallbackRequest {
                local_hashes: &objects,
                remote_hashes: &objects,
                trigger: FallbackTrigger::Timeout {
                    elapsed_ms: 5000,
                    slo_ms: 3000,
                },
                reconciliation_id: "r1",
                peer: "peer-1",
                trace_id: "t1",
            },
            4,
        );

        // All ranges should have been skipped.
        let skipped = fb
            .event_counts()
            .get("fallback_ranges_skipped")
            .copied()
            .unwrap_or(0);
        assert!(skipped > 0);
    }

    // -- FallbackRateMonitor --

    #[test]
    fn rate_monitor_no_alert_under_threshold() {
        let config = FallbackConfig {
            max_fallback_rate_pct: 10,
            monitoring_window: 20,
        };
        let mut monitor = FallbackRateMonitor::new(test_epoch(), config);

        // Record 20 successes, 1 fallback = 5% < 10%.
        for _ in 0..19 {
            assert!(monitor.record(false).is_none());
        }
        assert!(monitor.record(true).is_none());
        assert!(!monitor.is_rate_exceeded());
    }

    #[test]
    fn rate_monitor_alerts_over_threshold() {
        let config = FallbackConfig {
            max_fallback_rate_pct: 5,
            monitoring_window: 10,
        };
        let mut monitor = FallbackRateMonitor::new(test_epoch(), config);

        // Record 9 successes, then 1 fallback = 10% > 5%.
        for _ in 0..9 {
            monitor.record(false);
        }
        let alert = monitor.record(true);
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.threshold_pct, 5);
        assert!(alert.rate_pct > 5);
        assert!(monitor.is_rate_exceeded());
    }

    #[test]
    fn rate_monitor_sliding_window_evicts() {
        let config = FallbackConfig {
            max_fallback_rate_pct: 5,
            monitoring_window: 10,
        };
        let mut monitor = FallbackRateMonitor::new(test_epoch(), config);

        // Fill window with 1 fallback + 9 successes (10%).
        monitor.record(true);
        for _ in 0..9 {
            monitor.record(false);
        }
        assert!(monitor.is_rate_exceeded());

        // Overwrite the fallback slot with a success.
        monitor.record(false);
        // Now the window should contain 0 fallbacks.
        assert!(!monitor.is_rate_exceeded());
    }

    #[test]
    fn rate_monitor_empty_window_zero_rate() {
        let config = FallbackConfig::default();
        let monitor = FallbackRateMonitor::new(test_epoch(), config);
        assert_eq!(monitor.current_rate_pct(), 0);
        assert!(!monitor.is_rate_exceeded());
    }

    #[test]
    fn rate_monitor_drain_alerts() {
        let config = FallbackConfig {
            max_fallback_rate_pct: 0, // any fallback exceeds
            monitoring_window: 5,
        };
        let mut monitor = FallbackRateMonitor::new(test_epoch(), config);
        monitor.record(true);
        monitor.record(true);

        let alerts = monitor.drain_alerts();
        assert_eq!(alerts.len(), 2);
        assert!(monitor.drain_alerts().is_empty());
    }

    // -- Serialization round-trips for new types --

    #[test]
    fn fallback_trigger_serialization_round_trip() {
        let triggers = vec![
            FallbackTrigger::PeelFailed { remaining_cells: 5 },
            FallbackTrigger::VerificationFailed {
                object_hash: "abc123".to_string(),
                reason: "hash mismatch".to_string(),
            },
            FallbackTrigger::Timeout {
                elapsed_ms: 5000,
                slo_ms: 3000,
            },
            FallbackTrigger::MmrConsistencyFailure {
                details: "root divergence".to_string(),
            },
        ];
        for t in &triggers {
            let json = serde_json::to_string(t).expect("serialize");
            let restored: FallbackTrigger = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*t, restored);
        }
    }

    #[test]
    fn fallback_evidence_serialization_round_trip() {
        let ev = FallbackEvidence {
            fallback_id: "fb-1".to_string(),
            trigger: FallbackTrigger::PeelFailed { remaining_cells: 3 },
            original_reconciliation_id: "r1:peer-1".to_string(),
            scope_size: 100,
            differences_found: 10,
            objects_transferred: 10,
            duration_ms: 42,
            epoch_id: 1,
            trace_id: "t1".to_string(),
        };
        let json = serde_json::to_string(&ev).expect("serialize");
        let restored: FallbackEvidence = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ev, restored);
    }

    #[test]
    fn fallback_rate_alert_serialization_round_trip() {
        let alert = FallbackRateAlert {
            rate_pct: 12,
            threshold_pct: 5,
            fallbacks_in_window: 6,
            total_in_window: 50,
            epoch_id: 1,
        };
        let json = serde_json::to_string(&alert).expect("serialize");
        let restored: FallbackRateAlert = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(alert, restored);
    }

    #[test]
    fn fallback_config_serialization_round_trip() {
        let config = FallbackConfig::default();
        let json = serde_json::to_string(&config).expect("serialize");
        let restored: FallbackConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, restored);
    }

    // -- FallbackTrigger Display --

    #[test]
    fn fallback_trigger_display() {
        assert!(
            FallbackTrigger::PeelFailed { remaining_cells: 5 }
                .to_string()
                .contains("peel_failed")
        );
        assert!(
            FallbackTrigger::Timeout {
                elapsed_ms: 5000,
                slo_ms: 3000
            }
            .to_string()
            .contains("timeout")
        );
        assert!(
            FallbackTrigger::MmrConsistencyFailure {
                details: "test".to_string()
            }
            .to_string()
            .contains("mmr_consistency")
        );
    }

    // -- Enrichment: remaining serde/display gaps --

    #[test]
    fn reconcile_error_serde_remaining_variants() {
        let errors = vec![
            ReconcileError::EpochMismatch {
                local_epoch: SecurityEpoch::from_raw(1),
                remote_epoch: SecurityEpoch::from_raw(2),
            },
            ReconcileError::VerificationFailed {
                object_hash: "abc".to_string(),
                reason: "mismatch".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: ReconcileError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn reconcile_error_display_remaining_variants() {
        let s = ReconcileError::EpochMismatch {
            local_epoch: SecurityEpoch::from_raw(1),
            remote_epoch: SecurityEpoch::from_raw(2),
        }
        .to_string();
        assert!(s.contains("epoch"));
        assert!(s.contains("mismatch"));

        let s = ReconcileError::VerificationFailed {
            object_hash: "abc".to_string(),
            reason: "hash mismatch".to_string(),
        }
        .to_string();
        assert!(s.contains("abc"));
        assert!(s.contains("hash mismatch"));
    }

    #[test]
    fn reconcile_object_type_serde_roundtrip() {
        let variants = [
            ReconcileObjectType::RevocationEvent,
            ReconcileObjectType::CheckpointMarker,
            ReconcileObjectType::EvidenceEntry,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialize");
            let restored: ReconcileObjectType = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*v, restored);
        }
    }

    #[test]
    fn reconcile_result_serde_roundtrip() {
        let result = ReconcileResult {
            objects_to_fetch: vec![make_hash(1), make_hash(2)],
            objects_to_send: vec![make_hash(3)],
            fallback_triggered: false,
        };
        let json = serde_json::to_string(&result).expect("serialize");
        let restored: ReconcileResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(result, restored);
    }

    #[test]
    fn fallback_result_serde_roundtrip() {
        let result = FallbackResult {
            objects_to_fetch: vec![make_hash(1)],
            objects_to_send: vec![make_hash(2)],
            evidence: FallbackEvidence {
                fallback_id: "fb-1".to_string(),
                trigger: FallbackTrigger::PeelFailed { remaining_cells: 3 },
                original_reconciliation_id: "r1:p1".to_string(),
                scope_size: 50,
                differences_found: 2,
                objects_transferred: 2,
                duration_ms: 0,
                epoch_id: 1,
                trace_id: "t1".to_string(),
            },
        };
        let json = serde_json::to_string(&result).expect("serialize");
        let restored: FallbackResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(result, restored);
    }

    #[test]
    fn reconcile_config_default_values() {
        let config = ReconcileConfig::default();
        assert_eq!(config.iblt_cells, 256);
        assert_eq!(config.iblt_hashes, 3);
        assert_eq!(config.max_retries, 2);
        assert_eq!(config.retry_scale_factor, 2);
    }

    #[test]
    fn fallback_config_default_values() {
        let config = FallbackConfig::default();
        assert_eq!(config.max_fallback_rate_pct, 5);
        assert_eq!(config.monitoring_window, 100);
    }

    #[test]
    fn object_id_display_content() {
        let id = ObjectId {
            content_hash: ContentHash::compute(b"test"),
            object_type: ReconcileObjectType::RevocationEvent,
            epoch: test_epoch(),
        };
        let s = id.to_string();
        assert!(s.contains("revocation_event"));
    }

    #[test]
    fn fallback_trigger_display_verification_failed() {
        let s = FallbackTrigger::VerificationFailed {
            object_hash: "abc".to_string(),
            reason: "bad".to_string(),
        }
        .to_string();
        assert!(s.contains("verification_failed"));
        assert!(s.contains("abc"));
    }

    // -- Enrichment: std::error --

    #[test]
    fn reconcile_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(ReconcileError::IbltSizeMismatch {
                local_cells: 100,
                remote_cells: 200,
            }),
            Box::new(ReconcileError::PeelFailed { remaining_cells: 5 }),
            Box::new(ReconcileError::EpochMismatch {
                local_epoch: SecurityEpoch::from_raw(1),
                remote_epoch: SecurityEpoch::from_raw(3),
            }),
            Box::new(ReconcileError::VerificationFailed {
                object_hash: "aabb".into(),
                reason: "mismatch".into(),
            }),
            Box::new(ReconcileError::EmptyObjectSet),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            5,
            "all 5 variants produce distinct messages"
        );
    }

    #[test]
    fn reconcile_object_type_ordering() {
        assert!(ReconcileObjectType::RevocationEvent < ReconcileObjectType::CheckpointMarker);
        assert!(ReconcileObjectType::CheckpointMarker < ReconcileObjectType::EvidenceEntry);
    }

    // -- Enrichment: Display uniqueness, edge cases, defaults --

    #[test]
    fn reconcile_object_type_display_uniqueness() {
        let variants = [
            ReconcileObjectType::RevocationEvent,
            ReconcileObjectType::CheckpointMarker,
            ReconcileObjectType::EvidenceEntry,
        ];
        let displays: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
        assert_eq!(
            displays.len(),
            3,
            "all 3 variants produce distinct display strings"
        );
    }

    #[test]
    fn fallback_trigger_display_uniqueness() {
        let triggers = [
            FallbackTrigger::PeelFailed { remaining_cells: 1 },
            FallbackTrigger::VerificationFailed {
                object_hash: "h".into(),
                reason: "r".into(),
            },
            FallbackTrigger::Timeout {
                elapsed_ms: 1,
                slo_ms: 1,
            },
            FallbackTrigger::MmrConsistencyFailure {
                details: "d".into(),
            },
        ];
        let displays: BTreeSet<String> = triggers.iter().map(|t| t.to_string()).collect();
        assert_eq!(
            displays.len(),
            4,
            "all 4 trigger variants produce distinct display strings"
        );
    }

    #[test]
    fn reconcile_config_default_has_expected_hash_count() {
        let config = ReconcileConfig::default();
        assert_eq!(config.iblt_hashes, 3, "default uses 3 hash functions");
    }

    #[test]
    fn iblt_cell_default_is_zero() {
        let cell = IbltCell::default();
        assert_eq!(cell.count, 0);
        assert_eq!(cell.checksum_xor, 0);
        assert_eq!(cell.key_hash_xor, [0u8; 32]);
    }

    #[test]
    fn iblt_num_cells_accessor_matches_construction() {
        let iblt = Iblt::new(42, 3);
        assert_eq!(iblt.num_cells(), 42);
    }

    #[test]
    fn iblt_double_insert_remove_cancels() {
        let mut iblt = Iblt::new(64, 3);
        let h1 = make_hash(10);
        let h2 = make_hash(20);
        iblt.insert(&h1);
        iblt.insert(&h2);
        iblt.remove(&h1);
        iblt.remove(&h2);
        let empty = Iblt::new(64, 3);
        assert_eq!(iblt, empty);
    }

    #[test]
    fn object_id_display_contains_epoch() {
        let id = ObjectId {
            content_hash: ContentHash::compute(b"epoch-test"),
            object_type: ReconcileObjectType::EvidenceEntry,
            epoch: SecurityEpoch::from_raw(42),
        };
        let s = id.to_string();
        assert!(
            s.contains("evidence_entry"),
            "display must include object type"
        );
        assert!(s.contains("42"), "display must include epoch");
    }

    #[test]
    fn iblt_cell_serde_roundtrip() {
        let cell = IbltCell {
            count: -3,
            key_hash_xor: make_hash(77),
            checksum_xor: 0xDEAD_BEEF,
        };
        let json = serde_json::to_string(&cell).expect("serialize");
        let restored: IbltCell = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cell, restored);
    }

    // ── Enrichment: serde roundtrip tests ────────────────────────────

    #[test]
    fn object_id_serde_roundtrip() {
        let id = ObjectId {
            content_hash: ContentHash::compute(b"test-obj"),
            object_type: ReconcileObjectType::RevocationEvent,
            epoch: test_epoch(),
        };
        let json = serde_json::to_string(&id).unwrap();
        let back: ObjectId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn object_id_serde_all_object_types() {
        for otype in [
            ReconcileObjectType::RevocationEvent,
            ReconcileObjectType::CheckpointMarker,
            ReconcileObjectType::EvidenceEntry,
        ] {
            let id = ObjectId {
                content_hash: ContentHash::compute(b"variant"),
                object_type: otype,
                epoch: test_epoch(),
            };
            let json = serde_json::to_string(&id).unwrap();
            let back: ObjectId = serde_json::from_str(&json).unwrap();
            assert_eq!(back, id);
        }
    }

    #[test]
    fn fallback_trigger_serde_roundtrip_all_variants() {
        let variants = [
            FallbackTrigger::PeelFailed {
                remaining_cells: 42,
            },
            FallbackTrigger::VerificationFailed {
                object_hash: "abc123".to_string(),
                reason: "mismatch".to_string(),
            },
            FallbackTrigger::Timeout {
                elapsed_ms: 5000,
                slo_ms: 3000,
            },
            FallbackTrigger::MmrConsistencyFailure {
                details: "root diverged".to_string(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: FallbackTrigger = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn reconcile_config_serde_roundtrip() {
        let cfg = ReconcileConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: ReconcileConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn reconcile_config_serde_roundtrip_custom() {
        let cfg = ReconcileConfig {
            iblt_cells: 512,
            iblt_hashes: 5,
            max_retries: 4,
            retry_scale_factor: 3,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: ReconcileConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn fallback_config_serde_roundtrip() {
        let cfg = FallbackConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: FallbackConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn fallback_config_serde_roundtrip_custom() {
        let cfg = FallbackConfig {
            max_fallback_rate_pct: 10,
            monitoring_window: 200,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: FallbackConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn iblt_serde_roundtrip() {
        let iblt = Iblt::new(8, 3);
        let json = serde_json::to_string(&iblt).unwrap();
        let back: Iblt = serde_json::from_str(&json).unwrap();
        assert_eq!(back, iblt);
    }

    #[test]
    fn iblt_serde_roundtrip_with_inserts() {
        let mut iblt = Iblt::new(16, 3);
        iblt.insert(&make_hash(1));
        iblt.insert(&make_hash(2));
        let json = serde_json::to_string(&iblt).unwrap();
        let back: Iblt = serde_json::from_str(&json).unwrap();
        assert_eq!(back, iblt);
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn session_epoch_accessor() {
        let session =
            ReconcileSession::new(SecurityEpoch::from_raw(42), ReconcileConfig::default());
        assert_eq!(session.epoch(), SecurityEpoch::from_raw(42));
    }

    #[test]
    fn session_drain_events_empties() {
        let config = ReconcileConfig {
            iblt_cells: 128,
            iblt_hashes: 3,
            max_retries: 2,
            retry_scale_factor: 2,
        };
        let mut session = ReconcileSession::new(test_epoch(), config);
        let objects: BTreeSet<[u8; 32]> = (0..5).map(make_hash).collect();
        let remote_iblt = session.build_iblt(&objects);
        session
            .reconcile(&objects, &remote_iblt, "peer", "t1")
            .unwrap();
        assert!(!session.drain_events().is_empty());
        assert!(session.drain_events().is_empty());
    }

    #[test]
    fn exact_difference_identical_sets_empty() {
        let objects: BTreeSet<[u8; 32]> = (0..10).map(make_hash).collect();
        let (lo, ro) = ReconcileSession::exact_difference(&objects, &objects);
        assert!(lo.is_empty());
        assert!(ro.is_empty());
    }

    #[test]
    fn exact_difference_disjoint_sets() {
        let local: BTreeSet<[u8; 32]> = (0..5).map(make_hash).collect();
        let remote: BTreeSet<[u8; 32]> = (5..10).map(make_hash).collect();
        let (lo, ro) = ReconcileSession::exact_difference(&local, &remote);
        assert_eq!(lo.len(), 5);
        assert_eq!(ro.len(), 5);
    }

    #[test]
    fn fallback_protocol_epoch_accessor() {
        let fb = FallbackProtocol::new(SecurityEpoch::from_raw(7));
        assert_eq!(fb.epoch(), SecurityEpoch::from_raw(7));
    }

    #[test]
    fn rate_monitor_total_recorded_tracks() {
        let mut monitor = FallbackRateMonitor::new(test_epoch(), FallbackConfig::default());
        assert_eq!(monitor.total_recorded(), 0);
        monitor.record(false);
        monitor.record(true);
        monitor.record(false);
        assert_eq!(monitor.total_recorded(), 3);
    }

    #[test]
    fn iblt_subtract_hash_count_mismatch() {
        let a = Iblt::new(64, 3);
        let b = Iblt::new(64, 4); // different num_hashes
        assert!(matches!(
            a.subtract(&b),
            Err(ReconcileError::IbltSizeMismatch { .. })
        ));
    }

    #[test]
    fn incremental_fallback_with_one_range_matches_full() {
        let mut fb = FallbackProtocol::new(test_epoch());
        let local: BTreeSet<[u8; 32]> = (0..10).map(make_hash).collect();
        let remote: BTreeSet<[u8; 32]> = (5..15).map(make_hash).collect();

        let full = fb.execute(FallbackRequest {
            local_hashes: &local,
            remote_hashes: &remote,
            trigger: FallbackTrigger::PeelFailed { remaining_cells: 1 },
            reconciliation_id: "r1",
            peer: "p1",
            trace_id: "t1",
        });

        let mut fb2 = FallbackProtocol::new(test_epoch());
        let incr = fb2.execute_incremental(
            FallbackRequest {
                local_hashes: &local,
                remote_hashes: &remote,
                trigger: FallbackTrigger::PeelFailed { remaining_cells: 1 },
                reconciliation_id: "r1",
                peer: "p1",
                trace_id: "t1",
            },
            1, // num_ranges=1 delegates to execute()
        );

        assert_eq!(
            full.objects_to_send.iter().collect::<BTreeSet<_>>(),
            incr.objects_to_send.iter().collect::<BTreeSet<_>>()
        );
        assert_eq!(
            full.objects_to_fetch.iter().collect::<BTreeSet<_>>(),
            incr.objects_to_fetch.iter().collect::<BTreeSet<_>>()
        );
    }
}
